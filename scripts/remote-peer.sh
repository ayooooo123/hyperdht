#!/usr/bin/env bash
#
# Drives the Remote Peer workflow and times this machine against the peers it
# holds open.
#
#   scripts/remote-peer.sh secret            # create the local secret, push it to the repo
#   scripts/remote-peer.sh up [-p 3] [-s 300] [-o ubuntu-latest]
#   scripts/remote-peer.sh probe <run-id> [-p 3]
#   scripts/remote-peer.sh local [-p 2]      # same harness on a local testnet, no CI
#
# The secret lives in $XDG_CONFIG_HOME/hyperdht-remote-peer/secret and in the
# REMOTE_PEER_SECRET repository secret. It is never a workflow input: dispatch
# inputs are readable by anyone who can read the repository, and the secret is
# what stops a stranger from connecting to a peer.

set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# brittle resolves test paths as globs relative to the working directory, so the
# whole script runs from the repository root.
cd "$repo"
secret_dir="${XDG_CONFIG_HOME:-$HOME/.config}/hyperdht-remote-peer"
secret_file="$secret_dir/secret"
workflow=remote-peer.yml
node_bin="${NODE:-node}"

peers=2
seconds=300
os=ubuntu-latest

read_secret() {
  if [ ! -s "$secret_file" ]; then
    echo "no local secret; run: scripts/remote-peer.sh secret" >&2
    exit 69
  fi
  tr -d '[:space:]' <"$secret_file"
}

ensure_secret() {
  mkdir -p "$secret_dir"
  if [ ! -s "$secret_file" ]; then
    "$node_bin" -e 'process.stdout.write(require("crypto").randomBytes(32).toString("hex"))' \
      >"$secret_file"
    chmod 600 "$secret_file"
    echo "wrote a new secret to $secret_file"
  else
    echo "keeping the existing secret in $secret_file"
  fi
  # Writing a repository secret changes repository settings, so it only happens
  # when asked for. The local file alone is enough for the `local` harness.
  if [ "${1:-}" = "--push" ]; then
    gh secret set REMOTE_PEER_SECRET --body "$(read_secret)"
    echo "pushed it to the REMOTE_PEER_SECRET repository secret"
  else
    echo "not pushed; run with --push to set the REMOTE_PEER_SECRET repository secret"
  fi
}

parse_flags() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -p | --peers)
        peers="$2"
        shift 2
        ;;
      -s | --seconds)
        seconds="$2"
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
  # The workflow has five peer slots and a 30 minute job timeout. Rejecting bad
  # values here costs a second; a bad dispatch costs the whole timeout.
  case "$peers" in
    1 | 2 | 3 | 4 | 5) ;;
    *)
      echo "peers must be 1 to 5, got: $peers" >&2
      exit 64
      ;;
  esac
  case "$seconds" in
    '' | *[!0-9]*)
      echo "seconds must be a whole number, got: $seconds" >&2
      exit 64
      ;;
  esac
  if [ "$seconds" -lt 30 ] || [ "$seconds" -gt 1500 ]; then
    echo "seconds must be 30 to 1500, got: $seconds" >&2
    exit 64
  fi
  case "$os" in
    ubuntu-latest | macos-latest | windows-latest) ;;
    *)
      echo "os must be ubuntu-latest, macos-latest or windows-latest, got: $os" >&2
      exit 64
      ;;
  esac
}

# gh run list is the only way back to the run id after a dispatch, and the run
# takes a moment to appear.
newest_run_id() {
  local before="$1"
  local deadline=$((SECONDS + 60))
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

probe() {
  local run_id="$1"
  # The wait window covers runner queueing plus npm install before a peer
  # listens, so it is deliberately larger than the peer lifetime.
  REMOTE_PEER_SECRET="$(read_secret)" \
    REMOTE_PEER_RUN_ID="$run_id" \
    REMOTE_PEER_COUNT="$peers" \
    REMOTE_PEER_WAIT_SECONDS="$((seconds + 240))" \
    "$repo/node_modules/.bin/brittle-node" test/remote-peer/probe.js
}

case "${1:-}" in
  secret)
    shift
    ensure_secret "${1:-}"
    ;;
  up)
    shift
    parse_flags "$@"
    before="$(gh run list --workflow "$workflow" --limit 1 --json databaseId \
      --jq '.[0].databaseId' 2>/dev/null || true)"
    gh workflow run "$workflow" -f "peers=$peers" -f "seconds=$seconds" -f "os=$os"
    run_id="$(newest_run_id "$before")" || {
      echo "dispatched, but the run id never appeared; find it with: gh run list" >&2
      exit 75
    }
    echo "run $run_id: $peers peer(s) on $os for ${seconds}s"
    echo "log: $(gh run view "$run_id" --json url --jq .url)"
    probe "$run_id"
    ;;
  probe)
    shift
    run_id="$1"
    shift || true
    parse_flags "$@"
    probe "$run_id"
    ;;
  local)
    shift
    parse_flags "$@"
    secret="$(read_secret)"
    run_id="local-$(date +%s)"
    testnet_log="$(mktemp)"
    "$node_bin" "$repo/test/remote-peer/local-testnet.js" --size 8 >"$testnet_log" 2>&1 &
    testnet_pid=$!
    peer_pids=()
    cleanup() {
      for pid in ${peer_pids+"${peer_pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
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
    for index in $(seq 1 "$peers"); do
      REMOTE_PEER_SECRET="$secret" REMOTE_PEER_RUN_ID="$run_id" \
        "$node_bin" "$repo/test/remote-peer/serve.js" --index "$index" --seconds "$seconds" \
        --bootstrap "$bootstrap" --host 127.0.0.1 >/dev/null 2>&1 &
      peer_pids+=($!)
    done
    sleep 2
    REMOTE_PEER_SECRET="$secret" \
      REMOTE_PEER_RUN_ID="$run_id" \
      REMOTE_PEER_COUNT="$peers" \
      REMOTE_PEER_WAIT_SECONDS=60 \
      REMOTE_PEER_BOOTSTRAP="$bootstrap" \
      "$repo/node_modules/.bin/brittle-node" test/remote-peer/probe.js
    ;;
  *)
    sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 64
    ;;
esac
