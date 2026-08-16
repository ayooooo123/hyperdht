#!/usr/bin/env bash
#
# Dispatches role bridges to runners and drives the eleven-role live route from
# this machine.
#
#   scripts/live-route.sh up [-s 900] [-w 600] [-l 1,9,10,11]
#   scripts/live-route.sh drive <run-id> [-w 600] [-l 1,9,10,11]
#
# Needs both local secrets; run scripts/remote-peer.sh secret --push once. Nothing
# else has to be set up, and no repository secret beyond REMOTE_PEER_SECRET is ever
# needed: the coordinator runs here, so its secret stays in ~/.config and a run
# carries only the matching public key, as the coordinator_key input.
#
# A ROLE DOES NOT KNOW WHERE IT IS. role-bridge.js binds 0.0.0.0 and learns the
# address peers dial from two reflectors, so a role on an Azure runner and a role on
# this laptop are the same program with the same arguments, both behind some NAT.
# -l names the indices to run here; everything else is dispatched. The coordinator
# discovers all eleven over the DHT and cannot tell them apart. Default is all
# eleven remote.
#
# WHICH PLACEMENTS ARE SAFE, because two roles here share one reachable address:
#
#   1  endpoint      free
#   2  guard         diversity-constrained
#   3  lookup-middle-a  \
#   4  lookup-exit-a     |  the six relay candidates the guard chooses from,
#   5  lookup-middle-b   |  topology-fixture.js:938 lists them as [2,3,6,7,4,5]
#   6  lookup-exit-b     |  in ROLES order
#   7  announce-middle   |
#   8  announce-exit    /
#   9  dht-seed      free
#   10 dht-referral  free
#   11 dht-value     free
#
# validatePathDiversity (lib/private/branch-path-authority.js:159) rejects a path
# whose guard and four branch positions share a /24, and recordsDiverse
# (relay-candidate-directory.js:355) applies the same rule when candidates are
# chosen. Roles 2 to 8 are exactly the set that rule sees, so AT MOST ONE OF THEM
# MAY RUN HERE; roles 1, 9, 10 and 11 are never compared by subnet and any number
# of them can be local. So the largest safe local set is five: 1, 9, 10, 11 and one
# of 2 to 8. This script refuses anything else before dispatching, because the
# failure it would cause is ERR_INCOMPATIBLE_RELAY eleven steps later with nothing
# naming the addresses.
#
# ONE THING THIS CANNOT CHECK: whether this machine's NAT lets a runner reach a
# local role at all. Roles send to each other's reflected addresses directly, with
# no punching, so a NAT that filters by source address will drop a runner's first
# packet to a local role even though the mapping exists. That shows up as links
# that never open, not as a diversity error. It is also precisely what a mixed
# dispatch tests; if it fails that way, all eleven remote is the fallback.

set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# brittle resolves test paths as globs relative to the working directory, so the
# whole script runs from the repository root.
cd "$repo"
workflow=live-route.yml
node_bin="${NODE:-node}"
# Both secrets, their paths, and the pin derivation. Shared with remote-peer.sh and
# remote-mesh.sh so one file decides how credentials are read.
# shellcheck source=scripts/remote-peer-credentials.sh
. "$(dirname "${BASH_SOURCE[0]}")/remote-peer-credentials.sh"

roles=11
seconds=900
wait_seconds=600
local_roles=""
# The guard plus the six relay candidates: the roles validatePathDiversity compares
# by subnet. Padded with spaces so a membership test cannot match a substring.
diverse_roles=" 2 3 4 5 6 7 8 "

parse_flags() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -s | --seconds)
        seconds="$2"
        shift 2
        ;;
      -w | --wait)
        wait_seconds="$2"
        shift 2
        ;;
      -l | --local)
        local_roles="$2"
        shift 2
        ;;
      *)
        echo "unknown flag: $1" >&2
        exit 64
        ;;
    esac
  done
  for value in "$seconds" "$wait_seconds"; do
    case "$value" in
      '' | *[!0-9]*)
        echo "seconds and wait must be whole numbers" >&2
        exit 64
        ;;
    esac
  done
  # The same bounds the workflow enforces, checked here so a bad number costs
  # nothing instead of failing eleven jobs after dispatch.
  if [ "$seconds" -lt 300 ] || [ "$seconds" -gt 1500 ]; then
    echo "seconds must be 300 to 1500, got: $seconds" >&2
    exit 64
  fi
  if [ "$wait_seconds" -lt 60 ] || [ "$wait_seconds" -gt 1200 ]; then
    echo "wait must be 60 to 1200, got: $wait_seconds" >&2
    exit 64
  fi
  if [ "$seconds" -le "$((wait_seconds + 120))" ]; then
    echo "seconds must exceed wait by at least 120, got: $seconds and $wait_seconds" >&2
    exit 64
  fi
  case "$local_roles" in
    '' | *[0-9]) ;;
    *)
      echo "local roles must be a comma-separated list of indices, got: $local_roles" >&2
      exit 64
      ;;
  esac
}

# Splits -l into a validated, space-padded list, and refuses a placement the
# diversity rule would reject. Sets local_list and remote_list.
plan_placement() {
  local value diverse_count=0
  local_list=" "
  diverse_count=0
  if [ -n "$local_roles" ]; then
    for value in ${local_roles//,/ }; do
      case "$value" in
        '' | *[!0-9]*)
          echo "local roles must be whole numbers, got: $value" >&2
          exit 64
          ;;
      esac
      if [ "$value" -lt 1 ] || [ "$value" -gt "$roles" ]; then
        echo "local roles must be 1 to $roles, got: $value" >&2
        exit 64
      fi
      case "$local_list" in
        *" $value "*)
          echo "local roles must be unique, got $value twice" >&2
          exit 64
          ;;
      esac
      local_list="$local_list$value "
      case "$diverse_roles" in
        *" $value "*) diverse_count=$((diverse_count + 1)) ;;
      esac
    done
  fi
  # Every role here shares one reachable address, so a second diversity-constrained
  # role on this machine makes the path unbuildable. Named now, from the placement
  # itself, rather than as ERR_INCOMPATIBLE_RELAY during route construction.
  if [ "$diverse_count" -gt 1 ]; then
    echo "path diversity refuses roles sharing a subnet (KI-5): $diverse_count of" >&2
    echo "roles 2-8 are local and they would share this machine's one address." >&2
    echo "The guard and the four branch positions must differ by /24, so keep at" >&2
    echo "most one of 2,3,4,5,6,7,8 here; 1,9,10,11 are unconstrained." >&2
    exit 64
  fi
  remote_list=""
  for value in $(seq 1 "$roles"); do
    case "$local_list" in
      *" $value "*) continue ;;
    esac
    remote_list="${remote_list:+$remote_list,}$value"
  done
  if [ -z "$remote_list" ]; then
    echo "at least one role must be dispatched; this workflow hosts roles" >&2
    exit 64
  fi
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

bridge_pids=()
bridge_logs=""
cleanup() {
  for pid in ${bridge_pids+"${bridge_pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
}

# The roles that run here, started exactly as the workflow starts a remote one: no
# --bind-host, no --reachable-host, no --cell-port, so the address they publish is
# the one two reflectors saw.
start_local_bridges() {
  local secret="$1" coordinator_key="$2" run_id="$3" value
  # An `&&` here would return non-zero under set -e when every role is remote.
  if [ "$local_list" = " " ]; then
    return 0
  fi
  bridge_logs="$(mktemp -d)"
  for value in $local_list; do
    # A role host never holds the coordinator secret - that is the whole point of the
    # split, and it has to hold for a role hosted HERE too. These children inherit
    # this shell, which is the one place in a run where that secret is legitimately
    # present, so strip it explicitly rather than relying on role-bridge.js not
    # reading it.
    env -u REMOTE_PEER_COORDINATOR_SECRET \
      REMOTE_PEER_SECRET="$secret" \
      REMOTE_PEER_RUN_ID="$run_id" \
      REMOTE_PEER_COORDINATOR_KEY="$coordinator_key" \
      "$node_bin" test/remote-peer/role-bridge.js \
      --index "$value" \
      --seconds "$seconds" \
      >"$bridge_logs/role-$value.log" 2>&1 &
    bridge_pids+=($!)
  done
  echo "hosting roles$local_list here, logs in $bridge_logs"
}

# The version every role must match. role-runner.js compares its own runtime version
# against the coordinator's and refuses to configure if they differ, which is a
# deliberate fail-closed check that all twelve processes are the same build - so the
# runners have to install this exact patch version rather than whatever lts/* means
# today.
coordinator_node_version() {
  "$node_bin" -p 'process.version.slice(1)'
}

# Reads back the pin the run was dispatched with. The workflow puts it in the run
# name, which is public material by construction, so a run driven by the wrong
# coordinator secret is named in seconds rather than appearing as eleven roles that
# never answered.
check_pin() {
  local run_id="$1" coordinator_key="$2" title
  title="$(gh run view "$run_id" --json displayTitle --jq .displayTitle 2>/dev/null || true)"
  if [ -z "$title" ]; then
    echo "could not read run $run_id's name, so the pin is unverified; continuing" >&2
    return 0
  fi
  case "$title" in
    *"$coordinator_key"*) ;;
    *)
      echo "run $run_id was dispatched with a different coordinator key" >&2
      echo "  this machine derives: $coordinator_key" >&2
      echo "  the run is named:     $title" >&2
      echo "Its roles pin the other key and will refuse this coordinator." >&2
      exit 69
      ;;
  esac
}

drive() {
  local run_id="$1" secret coordinator_secret
  # Read into locals first: a missing secret must stop here, with the message the
  # reader prints, rather than inside brittle with an empty environment.
  secret="$(read_secret)"
  coordinator_secret="$(read_coordinator_secret)"
  trap cleanup EXIT
  start_local_bridges "$secret" "$(derive_coordinator_key "$coordinator_secret")" "$run_id"
  REMOTE_PEER_SECRET="$secret" \
    REMOTE_PEER_COORDINATOR_SECRET="$coordinator_secret" \
    REMOTE_PEER_RUN_ID="$run_id" \
    REMOTE_PEER_WAIT_SECONDS="$wait_seconds" \
    "$repo/node_modules/.bin/brittle-node" test/remote-peer/live-route.js
}

case "${1:-}" in
  up)
    shift
    parse_flags "$@"
    plan_placement
    coordinator_key="$(derive_coordinator_key "$(read_coordinator_secret)")"
    before="$(gh run list --workflow "$workflow" --limit 1 --json databaseId \
      --jq '.[0].databaseId' 2>/dev/null || true)"
    # Roles pin this key and refuse everyone else, so a dispatch without it would
    # hold bridges open that no coordinator can drive.
    gh workflow run "$workflow" -f "seconds=$seconds" -f "wait=$wait_seconds" \
      -f "remote_roles=$remote_list" -f "coordinator_key=$coordinator_key" \
      -f "node_version=$(coordinator_node_version)"
    run_id="$(newest_run_id "$before")" || {
      echo "dispatched, but the run id never appeared; find it with: gh run list" >&2
      exit 75
    }
    echo "run $run_id: roles $remote_list on runners for ${seconds}s"
    echo "log: $(gh run view "$run_id" --json url --jq .url)"
    # Discovery retries every 5s until the wait window ends, so the coordinator can
    # start before the runners have installed; it just spends attempts.
    drive "$run_id"
    ;;
  drive)
    shift
    run_id="${1:-}"
    if [ -z "$run_id" ]; then
      echo "usage: scripts/live-route.sh drive <run-id> [-w 600] [-l 1,9,10,11]" >&2
      exit 64
    fi
    shift
    parse_flags "$@"
    plan_placement
    check_pin "$run_id" "$(derive_coordinator_key "$(read_coordinator_secret)")"
    drive "$run_id"
    ;;
  *)
    sed -n '2,50p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 64
    ;;
esac
