#!/usr/bin/env bash
#
# Rehearses the distributed route on one machine: a throwaway DHT, eleven role
# bridges, and the same scenario the runners will execute.
#
#   scripts/live-route-rehearsal.sh [seconds]
#
# Every part of the distributed path is exercised except distance: addresses are
# asked for over the DHT, the topology is minted from the answers, and the roles
# are driven through DHT streams. Reachable addresses are stated as loopback here
# because one host has no translation to discover.

set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"
secret_file="${XDG_CONFIG_HOME:-$HOME/.config}/hyperdht-remote-peer/secret"
seconds="${1:-300}"

if [ ! -s "$secret_file" ]; then
  echo "no local secret; run: scripts/remote-peer.sh secret" >&2
  exit 69
fi
secret="$(tr -d '[:space:]' <"$secret_file")"
run_id="rehearsal-$(date +%s)"

testnet_log="$(mktemp)"
node test/remote-peer/local-testnet.js --size 8 >"$testnet_log" 2>&1 &
testnet_pid=$!
bridge_pids=()
cleanup() {
  for pid in ${bridge_pids+"${bridge_pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  kill "$testnet_pid" 2>/dev/null || true
  rm -f "$testnet_log"
}
trap cleanup EXIT

bootstrap=""
deadline=$((SECONDS + 30))
while [ "$SECONDS" -lt "$deadline" ]; do
  bootstrap="$(node -e '
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
echo "testnet at $bootstrap, run $run_id"

# One address per role when the host allows it, because the diversity rule rejects a
# set of relays that share a /24 (KI-5). Linux serves every 127/8 address, macOS does
# not, so a rehearsal there shares 127.0.0.1 and stops at that rule.
for index in $(seq 1 11); do
  if [ -n "${REHEARSAL_HOST_PREFIX:-}" ]; then
    host_flags=(
      --reachable-host "$REHEARSAL_HOST_PREFIX.$index.1"
      --bind-host "$REHEARSAL_HOST_PREFIX.$index.1"
    )
  else
    host_flags=(--reachable-host 127.0.0.1)
  fi
  REMOTE_PEER_SECRET="$secret" REMOTE_PEER_RUN_ID="$run_id" \
    node test/remote-peer/role-bridge.js \
    --index "$index" \
    --seconds "$seconds" \
    --cell-port "$((42000 + index))" \
    "${host_flags[@]}" \
    --bootstrap "$bootstrap" \
    >"/tmp/rehearsal-bridge-$index.log" 2>&1 &
  bridge_pids+=($!)
done

# Bridges bind, reflect and announce before they can answer.
sleep 8

REMOTE_PEER_SECRET="$secret" \
  REMOTE_PEER_RUN_ID="$run_id" \
  REMOTE_PEER_WAIT_SECONDS=120 \
  REMOTE_PEER_BOOTSTRAP="$bootstrap" \
  "${BRITTLE_NODE:-$repo/node_modules/.bin/brittle-node}" test/remote-peer/live-route.js
