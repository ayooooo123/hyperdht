#!/usr/bin/env bash
#
# Rehearses the distributed route on one machine: a throwaway DHT, eleven role
# bridges, and the same scenario the runners will execute.
#
#   scripts/live-route-rehearsal.sh [seconds]
#   REHEARSAL_ADDRESSES=divergent scripts/live-route-rehearsal.sh [seconds]
#
# Every part of the distributed path is exercised except distance. Addresses are
# asked for over the DHT, the topology is minted from the answers, and the roles
# are driven through DHT streams.
#
# REHEARSAL_ADDRESSES selects what a role's bound address has to do with the
# address its peers dial. This is the flag that decides what the rehearsal is
# able to catch, so read both modes before trusting a green run.
#
#   identical   (default) Bind and reachable are the same address. Needs no
#               iptables, so this is the mode for macOS and for any host without
#               the nat table. It CANNOT catch anything that confuses a bound
#               address with an advertised one, because the two are the same
#               string: a green run here is not evidence about that class. Three
#               separate faults of exactly that class passed this mode at
#               125/125 before the divergent mode existed to expose them —
#               role-runner's endpoint bootstrap authority, the exits' DHT-exit
#               reservation, and the learned-closer digest in
#               live-process-suite.js. See KI-8 in docs/private-routing-migration.md.
#   divergent   Role `i` binds REHEARSAL_BIND_PREFIX.i.1 and is reached at
#               REHEARSAL_ADVERTISED_PREFIX.i.1, with iptables translating both
#               directions, which is what a runner behind a NAT has. This is the
#               only mode that exercises the bind-versus-advertised class. Needs
#               Linux, --privileged, and every 127/8 address. It is not the
#               default because it currently stops at one assertion in the guard
#               rebuild, 6 runs in 33 getting past it (KI-8). That is an open
#               fault it found, not a reason to distrust the mode: rerunning
#               until green is exactly how such a fault disappears from view.
#
# A divergent run that cannot install its rules stops with EX_UNAVAILABLE rather
# than silently rehearsing the weaker mode.

set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"
secret_dir="${XDG_CONFIG_HOME:-$HOME/.config}/hyperdht-remote-peer"
secret_file="$secret_dir/secret"
coordinator_secret_file="$secret_dir/coordinator-secret"
seconds="${1:-300}"
roles=11

addresses="${REHEARSAL_ADDRESSES:-identical}"
# REHEARSAL_HOST_PREFIX named the one prefix the older single-mode script used, so
# it stays the way a caller overrides the bind prefix.
bind_prefix="${REHEARSAL_BIND_PREFIX:-${REHEARSAL_HOST_PREFIX:-}}"
advertised_prefix="${REHEARSAL_ADVERTISED_PREFIX:-127.65}"
case "$addresses" in
  divergent)
    # A divergent run needs one bind address per role, so it cannot fall back to
    # the shared 127.0.0.1 that a host without 127/8 forces.
    [ -n "$bind_prefix" ] || bind_prefix=127.64
    bash scripts/live-route-nat.sh check
    ;;
  identical) ;;
  *)
    echo "REHEARSAL_ADDRESSES must be divergent or identical, got $addresses" >&2
    exit 64
    ;;
esac

if [ ! -s "$secret_file" ]; then
  echo "no local secret; run: scripts/remote-peer.sh secret" >&2
  exit 69
fi
secret="$(tr -d '[:space:]' <"$secret_file")"

# The coordinator's own secret, which the roles never get. They pin only its public
# key, and that pin is the only thing stopping one role host from driving another.
# Passing it in the environment is for the container rehearsal, which has no second
# file; there is deliberately no fall back to deriving it from "$secret".
coordinator_secret="${REMOTE_PEER_COORDINATOR_SECRET:-}"
if [ -z "$coordinator_secret" ] && [ -s "$coordinator_secret_file" ]; then
  coordinator_secret="$(tr -d '[:space:]' <"$coordinator_secret_file")"
fi
if [ -z "$coordinator_secret" ]; then
  echo "no coordinator secret; run: scripts/remote-peer.sh secret, or set" >&2
  echo "REMOTE_PEER_COORDINATOR_SECRET for a container rehearsal" >&2
  exit 69
fi
coordinator_key="$(REMOTE_PEER_COORDINATOR_SECRET="$coordinator_secret" \
  node test/remote-peer/identity.js)"
run_id="rehearsal-$(date +%s)"

if [ "$addresses" = divergent ]; then
  echo "addresses: roles bind $bind_prefix.<index>.1, reached at $advertised_prefix.<index>.1"
  bash scripts/live-route-nat.sh up "$bind_prefix" "$advertised_prefix" "$roles"
else
  echo "addresses: identical, bind-versus-advertised divergence is not exercised"
fi

testnet_log="$(mktemp)"
node test/remote-peer/local-testnet.js --size 8 >"$testnet_log" 2>&1 &
testnet_pid=$!
bridge_pids=()
cleanup() {
  for pid in ${bridge_pids+"${bridge_pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  kill "$testnet_pid" 2>/dev/null || true
  rm -f "$testnet_log"
  # Unconditional: the rules outlive this shell otherwise, and `down` is a no-op
  # when nothing was installed.
  if [ "$addresses" = divergent ]; then bash scripts/live-route-nat.sh down || true; fi
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

# One reachable address per role when the host allows it, because the diversity rule
# rejects a set of relays that share a /24 (KI-5). Linux serves every 127/8 address,
# macOS does not, so an identical-mode rehearsal there shares 127.0.0.1 and stops at
# that rule.
for index in $(seq 1 "$roles"); do
  if [ "$addresses" = divergent ]; then
    host_flags=(
      --bind-host "$bind_prefix.$index.1"
      --reachable-host "$advertised_prefix.$index.1"
    )
  elif [ -n "$bind_prefix" ]; then
    host_flags=(
      --bind-host "$bind_prefix.$index.1"
      --reachable-host "$bind_prefix.$index.1"
    )
  else
    host_flags=(--reachable-host 127.0.0.1)
  fi
  REMOTE_PEER_SECRET="$secret" REMOTE_PEER_RUN_ID="$run_id" \
    REMOTE_PEER_COORDINATOR_KEY="$coordinator_key" \
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
  REMOTE_PEER_COORDINATOR_SECRET="$coordinator_secret" \
  REMOTE_PEER_RUN_ID="$run_id" \
  REMOTE_PEER_WAIT_SECONDS=120 \
  REMOTE_PEER_BOOTSTRAP="$bootstrap" \
  "${BRITTLE_NODE:-$repo/node_modules/.bin/brittle-node}" test/remote-peer/live-route.js
