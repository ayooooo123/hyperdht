#!/usr/bin/env bash
# Packet-level per-link delay. Every datagram traverses namespace-owned lo once;
# both data and transport ACKs are delayed, so link RTT adds 2 * delay_ms.
# No host interface, qdisc, route or named namespace is modified.
set -euo pipefail

if [[ "$(uname -s)" != Linux ]]; then
  echo 'netem benchmark requires Linux with CAP_SYS_ADMIN and CAP_NET_ADMIN' >&2
  exit 1
fi
for tool in unshare readlink ip tc node; do
  command -v "$tool" >/dev/null
done

delay_ms="${PR_NETEM_DELAY_MS:-5}"
limit="${PR_NETEM_LIMIT:-100000}"
if [[ ! "$delay_ms" =~ ^[0-9]+([.][0-9]+)?$ || ! "$limit" =~ ^[1-9][0-9]*$ ]]; then
  echo 'invalid PR_NETEM_DELAY_MS or PR_NETEM_LIMIT' >&2
  exit 64
fi
export PR_BENCH_PARENT_NETNS="$(readlink /proc/self/ns/net)"
runner="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/index.js"

# unshare fails closed if namespace creation is unavailable. exec keeps signal
# delivery and the benchmark's worker shutdown lifecycle intact. The anonymous
# namespace (and its qdisc) disappears after its last process/socket exits.
exec unshare --net -- bash -euo pipefail -c '
  if [[ "$(readlink /proc/self/ns/net)" == "$PR_BENCH_PARENT_NETNS" ]]; then
    echo "refusing to configure netem outside a dedicated network namespace" >&2
    exit 1
  fi
  delay_ms="$1"
  limit="$2"
  runner="$3"
  shift 3
  delay_ms="$(node -p "Number(process.argv[1])" "$delay_ms")"
  ip link set dev lo up
  tc qdisc add dev lo root netem delay "${delay_ms}ms" limit "$limit"
  tc -s qdisc show dev lo >&2
  export PR_BENCH_NETEM_ACTIVE="$delay_ms/$limit"
  exec node "$runner" "$@" --method=netem --netem="$delay_ms" --netemlimit="$limit" --delays=0
' netem "$delay_ms" "$limit" "$runner" "$@"
