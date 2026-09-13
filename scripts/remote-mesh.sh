#!/usr/bin/env bash
#
# Dispatches a mesh of runner peers and collects the pairwise matrix.
#
#   scripts/remote-mesh.sh up [-n 10] [-s 420] [-t 45] [-o ubuntu-latest]
#   scripts/remote-mesh.sh collect <run-id> [-n 10]
#   scripts/remote-mesh.sh local [-n 4]
#
# Uses the same two secrets as scripts/remote-peer.sh; run that script's `secret`
# subcommand first. Members dial each higher index once, so a mesh of n reports
# n(n-1)/2 links.
#
# Members derive every member key from the shared run secret, so they need no
# directory to find each other. The collector's key is not in that set: it comes
# from a secret that stays on this machine, and members are given only its public
# key, as the coordinator_key dispatch input, so no member can pose as the
# collector and read the matrix.

set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"
workflow=remote-mesh.yml
node_bin="${NODE:-node}"
# Both secrets, their paths, and the pin derivation. Shared with remote-peer.sh and
# live-route.sh so one file decides how credentials are read.
# shellcheck source=scripts/remote-peer-credentials.sh
. "$(dirname "${BASH_SOURCE[0]}")/remote-peer-credentials.sh"

members=10
seconds=420
settle=45
os=ubuntu-latest

# The docker credential and endpoint dance is only needed by the container gates,
# not here: this script talks to gh and to the DHT, nothing else.
parse_flags() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -n | --members)
        members="$2"
        shift 2
        ;;
      -s | --seconds)
        seconds="$2"
        shift 2
        ;;
      -t | --settle)
        settle="$2"
        shift 2
        ;;
      -o | --os)
        os="$2"
        shift 2
        ;;
      *)
        echo "unknown flag: $1" >&2
        exit 64
        ;;
    esac
  done
  if ! [ "$members" -ge 2 ] 2>/dev/null || [ "$members" -gt 12 ]; then
    echo "members must be 2 to 12, got: $members" >&2
    exit 64
  fi
  for value in "$seconds" "$settle"; do
    case "$value" in
      '' | *[!0-9]*)
        echo "seconds and settle must be whole numbers" >&2
        exit 64
        ;;
    esac
  done
  if [ "$seconds" -lt 60 ] || [ "$seconds" -gt 1500 ]; then
    echo "seconds must be 60 to 1500, got: $seconds" >&2
    exit 64
  fi
  if [ "$settle" -lt 5 ] || [ "$settle" -ge "$seconds" ]; then
    echo "settle must be 5 or more and below seconds" >&2
    exit 64
  fi
  case "$os" in
    ubuntu-latest | macos-latest) ;;
    *)
      echo "os must be ubuntu-latest or macos-latest, got: $os" >&2
      exit 64
      ;;
  esac
}

newest_run_id() {
  local before="$1"
  local deadline=$((SECONDS + 90))
  while [ "$SECONDS" -lt "$deadline" ]; do
    local candidate
    candidate="$(gh run list --workflow "$workflow" --limit 1 --json databaseId \
      --jq '.[0].databaseId' 2>/dev/null || true)"
    if [ -n "$candidate" ] && [ "$candidate" != "$before" ]; then
      echo "$candidate"
      return 0
    fi
    sleep 3
  done
  return 1
}

collect() {
  local run_id="$1"
  local secret coordinator_secret
  # Read into locals first: a missing secret must stop the run here, with the
  # message the reader prints, not inside brittle with an empty environment.
  secret="$(read_secret)"
  coordinator_secret="$(read_coordinator_secret)"
  # Members dial only after the settle window, so the collector must outlast
  # queueing plus install plus settle plus the dial sweep.
  REMOTE_PEER_SECRET="$secret" \
    REMOTE_PEER_COORDINATOR_SECRET="$coordinator_secret" \
    REMOTE_PEER_RUN_ID="$run_id" \
    REMOTE_PEER_COUNT="$members" \
    REMOTE_PEER_WAIT_SECONDS="$((seconds + 300))" \
    "$repo/node_modules/.bin/brittle-node" test/remote-peer/mesh-probe.js
}

case "${1:-}" in
  up)
    shift
    parse_flags "$@"
    before="$(gh run list --workflow "$workflow" --limit 1 --json databaseId \
      --jq '.[0].databaseId' 2>/dev/null || true)"
    # Members pin this key and refuse everyone else, so a dispatch without it
    # would hold a mesh open that no collector can read.
    gh workflow run "$workflow" -f "members=$members" -f "seconds=$seconds" \
      -f "settle=$settle" -f "os=$os" \
      -f "coordinator_key=$(derive_coordinator_key "$(read_coordinator_secret)")"
    run_id="$(newest_run_id "$before")" || {
      echo "dispatched, but the run id never appeared; find it with: gh run list" >&2
      exit 75
    }
    echo "run $run_id: $members member(s) on $os for ${seconds}s, settle ${settle}s"
    echo "log: $(gh run view "$run_id" --json url --jq .url)"
    # Members hold still during settle; collecting earlier just burns attempts.
    sleep "$settle"
    collect "$run_id"
    ;;
  collect)
    shift
    run_id="$1"
    shift || true
    parse_flags "$@"
    collect "$run_id"
    ;;
  local)
    shift
    settle=5
    seconds=180
    parse_flags "$@"
    secret="$(read_secret)"
    # Both sides run here, so this shell holds both secrets; the members it starts
    # still receive only the public key, exactly as a runner does.
    coordinator_secret="$(read_coordinator_secret)"
    coordinator_key="$(derive_coordinator_key "$coordinator_secret")"
    run_id="mesh-local-$(date +%s)"
    testnet_log="$(mktemp)"
    "$node_bin" test/remote-peer/local-testnet.js --size 8 >"$testnet_log" 2>&1 &
    testnet_pid=$!
    member_pids=()
    cleanup() {
      for pid in ${member_pids+"${member_pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
      kill "$testnet_pid" 2>/dev/null || true
      rm -f "$testnet_log"
    }
    trap cleanup EXIT
    bootstrap=""
    deadline=$((SECONDS + 30))
    while [ "$SECONDS" -lt "$deadline" ]; do
      bootstrap="$("$node_bin" -e '
        const fs = require("fs")
        for (const line of fs.readFileSync(process.argv[1], "utf8").split("\n")) {
          if (!line.startsWith("{")) continue
          const parsed = JSON.parse(line)
          if (parsed.event === "testnet") { process.stdout.write(parsed.bootstrap); break }
        }
      ' "$testnet_log")"
      [ -n "$bootstrap" ] && break
      sleep 1
    done
    if [ -z "$bootstrap" ]; then
      echo "local testnet never reported a bootstrap: $(cat "$testnet_log")" >&2
      exit 70
    fi
    for index in $(seq 1 "$members"); do
      REMOTE_PEER_SECRET="$secret" REMOTE_PEER_RUN_ID="$run_id" \
        REMOTE_PEER_COORDINATOR_KEY="$coordinator_key" \
        "$node_bin" test/remote-peer/mesh.js --index "$index" --count "$members" \
        --seconds "$seconds" --settle "$settle" --bootstrap "$bootstrap" >/dev/null 2>&1 &
      member_pids+=($!)
    done
    sleep $((settle + 8))
    REMOTE_PEER_SECRET="$secret" \
      REMOTE_PEER_COORDINATOR_SECRET="$coordinator_secret" \
      REMOTE_PEER_RUN_ID="$run_id" \
      REMOTE_PEER_COUNT="$members" \
      REMOTE_PEER_WAIT_SECONDS=120 \
      REMOTE_PEER_BOOTSTRAP="$bootstrap" \
      "$repo/node_modules/.bin/brittle-node" test/remote-peer/mesh-probe.js
    ;;
  *)
    sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 64
    ;;
esac
