#!/usr/bin/env bash
#
# Rehearses the distributed route on one machine: a throwaway DHT, eleven role
# bridges, and the same scenario the runners will execute.
#
#   scripts/live-route-rehearsal.sh [seconds]
#   REHEARSAL_ADDRESSES=divergent scripts/live-route-rehearsal.sh [seconds]
#   REHEARSAL_ADDRESSES=unmapped scripts/live-route-rehearsal.sh [seconds]
#
# Every part of the distributed path is exercised except distance. Addresses are
# asked for over the DHT, the topology is minted from the answers, and the roles
# are driven through DHT streams.
#
# REHEARSAL_ADDRESSES selects what a role's bound address has to do with the
# address its peers dial. This is the flag that decides what the rehearsal is
# able to catch, so read all three modes before trusting a green run.
#
#               NOTE none of the three modes runs on a macOS host: all eleven roles
#               there report 127.0.0.1 and the path-diversity rule rejects them
#               (KI-5). Every mode needs the Linux container; the modes differ only
#               in what they need INSIDE it.
#   identical   (default, for portability only - NOT the mode to trust) Bind and
#               reachable are the same address. The only mode needing neither the
#               nat table nor --privileged, which is the whole reason it is the
#               default. It CANNOT catch anything that confuses a bound
#               address with an advertised one, because the two are the same
#               string: a green run here is not evidence about that class. Three
#               separate faults of exactly that class passed this mode at
#               125/125 before the divergent mode existed to expose them —
#               role-runner's endpoint bootstrap authority, the exits' DHT-exit
#               reservation, and the learned-closer digest in
#               live-process-suite.js. It is also the FASTEST mode, which is a
#               second blind spot: KI-8 is a race that identical wins purely by
#               being loopback-fast. See KI-8 and KI-10 in
#               docs/private-routing-migration.md.
#   divergent   Role `i` binds REHEARSAL_BIND_PREFIX.i.1 and is reached at
#               REHEARSAL_ADVERTISED_PREFIX.i.1, with iptables translating both
#               directions, which is what a runner behind a NAT has. This is the
#               mode that exercises the bind-versus-advertised class the way a
#               runner does. Needs Linux, --privileged, and every 127/8 address,
#               which is the only reason it is not the default: `identical` is
#               what runs on a host without the nat table. THIS IS THE MODE CI
#               SHOULD RUN. It found the three bind-versus-advertised faults
#               above, and separately exposed KI-8 - which is NOT an addressing
#               fault at all, but a timing-sensitive race that only appears once
#               the rehearsal stops being unrealistically fast. That is the mode's
#               second and less obvious value: every mode here is sub-millisecond
#               loopback, so a real deployment loses that race more often than our
#               worst mode does. Before KI-8 was fixed no divergent run reached the
#               teardown at all; after it, divergent reaches 125/125. Deliberately
#               no pass RATE is quoted here: the pre-fix counts were taken with
#               instrumentation whose synchronous writes biased them, so they and
#               the post-fix counts come from different trees and are not a
#               before/after pair. See KI-8.
#   unmapped    Role `i` binds the WILDCARD and is reached at
#               REHEARSAL_ADVERTISED_PREFIX.i.1, with NO packet translation
#               anywhere: the published address is a real address on `lo`, so
#               delivery is ordinary local delivery, and each role's egress
#               source address is chosen by a routing rule keyed on its own
#               source port. Bound and published differ - 0.0.0.0 against
#               127.65.i.1 - so this mode exercises the bind-versus-advertised
#               class exactly as divergent does, but a stall under it cannot be
#               blamed on the harness's NAT because there is no NAT. That is what
#               it is for: it is the control that says whether a divergent
#               failure is the protocol's or the rehearsal's. Needs Linux,
#               --privileged, and an iproute2 that can select a routing rule on
#               sport.
#
# A divergent or unmapped run that cannot install its plumbing stops with
# EX_UNAVAILABLE rather than silently rehearsing the weaker mode.

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
  unmapped)
    # Nothing is bound per-role here: every role binds the wildcard, so a bind
    # prefix is not merely unnecessary, it would contradict the mode.
    bind_prefix=''
    bash scripts/live-route-nat.sh alias-check
    ;;
  identical) ;;
  *)
    echo "REHEARSAL_ADDRESSES must be identical, divergent or unmapped," >&2
    echo "got $addresses" >&2
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

case "$addresses" in
  divergent)
    echo "addresses: roles bind $bind_prefix.<index>.1, reached at $advertised_prefix.<index>.1"
    bash scripts/live-route-nat.sh up "$bind_prefix" "$advertised_prefix" "$roles"
    ;;
  unmapped)
    echo "addresses: roles bind 0.0.0.0, reached at $advertised_prefix.<index>.1, untranslated"
    bash scripts/live-route-nat.sh alias-up "$advertised_prefix" "$roles"
    ;;
  *)
    echo "addresses: identical, bind-versus-advertised divergence is not exercised"
    ;;
esac

testnet_log="$(mktemp)"
node test/remote-peer/local-testnet.js --size 8 >"$testnet_log" 2>&1 &
testnet_pid=$!
bridge_pids=()
cleanup() {
  for pid in ${bridge_pids+"${bridge_pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  kill "$testnet_pid" 2>/dev/null || true
  rm -f "$testnet_log"
  # Unconditional for any mode that installed plumbing: it outlives this shell
  # otherwise, and `down` is a no-op when nothing was installed.
  case "$addresses" in
    divergent | unmapped) bash scripts/live-route-nat.sh down || true ;;
  esac
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
  elif [ "$addresses" = unmapped ]; then
    # The wildcard is the point: the socket accepts the published address without
    # anything rewriting the destination, and 0.0.0.0 is the most obviously wrong
    # answer any code could give if it reached for the bound address by mistake.
    host_flags=(
      --bind-host 0.0.0.0
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
