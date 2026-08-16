#!/usr/bin/env bash
#
# Installs the address translation that lets a one-machine rehearsal exercise the
# thing a real distributed run has and a rehearsal otherwise cannot: a role binds
# one address and is reached at a different one.
#
#   scripts/live-route-nat.sh up <bind-prefix> <advertised-prefix> <role-count>
#   scripts/live-route-nat.sh down
#   scripts/live-route-nat.sh check
#
# Role `i` binds <bind-prefix>.i.1 and is reached at <advertised-prefix>.i.1, on
# the same port. Two rules per role make that true, and both halves are needed:
#
#   DNAT   in nat OUTPUT, so a packet addressed to the advertised address is
#          delivered to the socket bound at the bind address.
#   SNAT   in nat POSTROUTING, so a packet leaving that socket is observed by its
#          peer as coming from the advertised address.
#
# The SNAT half is not decoration. A peer's observed source address is load
# bearing in this protocol: a cell endpoint refuses a link handle whose local
# address is not its advertised pair (lib/private/udx-cell-endpoint.js:1606), and
# the DHT-setup audit rejects a packet whose source is not a permitted reachable
# tuple (test/private/process/dht-setup-audit-udx.js:277). Translating only the
# destination would exercise half a NAT and fail for the wrong reason.
#
# Everything lives in two named chains, so teardown is exact: nothing this script
# adds is identified by rule number or by matching against the ambient rule set.

set -euo pipefail

DNAT_CHAIN=PR_REHEARSAL_DNAT
SNAT_CHAIN=PR_REHEARSAL_SNAT

# A role's cell endpoint sits at CELL_PORT_BASE + roleIndex. An exit owns a
# second socket for reaching DHT nodes at EXIT_DHT_PORT_BASE + roleIndex, bound to
# the same local host (test/private/process/role-runner.js:410), so it needs its
# own DNAT rule.
CELL_PORT_BASE=42000
EXIT_DHT_PORT_BASE=43000
EXIT_ROLE_INDEXES=(4 6 8)

usage() {
  echo "usage: $0 up <bind-prefix> <advertised-prefix> <role-count> | down | check" >&2
  exit 64
}

# EX_UNAVAILABLE. A caller that asked for divergent addresses and cannot have
# them must stop, not quietly fall back to the mode that hides the bug.
unavailable() {
  echo "live-route-nat: $1" >&2
  exit 69
}

require_iptables() {
  command -v iptables >/dev/null 2>&1 || unavailable "iptables is not installed"
  iptables -t nat -L -n >/dev/null 2>&1 ||
    unavailable "cannot read the nat table; the container needs --privileged"
}

# Two octets, each a plain decimal number: the third and fourth are the role index
# and a literal 1, and the /16 the SNAT rule matches on is derived from the first
# two.
check_prefix() {
  case "$2" in
    [0-9] | [0-9][0-9] | [0-9][0-9][0-9]) ;;
    *) unavailable "bad $1 prefix: $2" ;;
  esac
}

parse_prefix() {
  local label="$1" prefix="$2"
  case "$prefix" in
    *.*.*) unavailable "$label prefix must be two octets, got $prefix" ;;
    *.*) ;;
    *) unavailable "$label prefix must be two octets, got $prefix" ;;
  esac
  check_prefix "$label" "${prefix%%.*}"
  check_prefix "$label" "${prefix##*.}"
}

remove_chains() {
  # Idempotent, and safe to call when `up` failed halfway: every step is allowed
  # to find nothing.
  while iptables -t nat -C OUTPUT -j "$DNAT_CHAIN" 2>/dev/null; do
    iptables -t nat -D OUTPUT -j "$DNAT_CHAIN"
  done
  while iptables -t nat -C POSTROUTING -j "$SNAT_CHAIN" 2>/dev/null; do
    iptables -t nat -D POSTROUTING -j "$SNAT_CHAIN"
  done
  for chain in "$DNAT_CHAIN" "$SNAT_CHAIN"; do
    iptables -t nat -F "$chain" 2>/dev/null || true
    iptables -t nat -X "$chain" 2>/dev/null || true
  done
  # A translated flow outlives the rule that created it: conntrack keeps the
  # mapping for the UDP timeout, so a later run in the same container would still
  # be translated by a rule set that no longer exists. Best effort, because the
  # tool is not part of the protocol.
  if command -v conntrack >/dev/null 2>&1; then
    conntrack -F >/dev/null 2>&1 || true
  fi
}

# One socket, one port: reached at the advertised address, delivered to the bound
# one. The port is the same on both sides, because a rehearsal diverges the host
# only — the bridge publishes the port it actually claimed.
forward() {
  iptables -t nat -A "$DNAT_CHAIN" \
    -p udp -d "$2.$3.1" --dport "$4" \
    -j DNAT --to-destination "$1.$3.1:$4"
}

install_chains() {
  local bind_prefix="$1" advertised_prefix="$2" count="$3"
  local network="${bind_prefix%%.*}.${bind_prefix##*.}.0.0/16"

  iptables -t nat -N "$DNAT_CHAIN"
  iptables -t nat -N "$SNAT_CHAIN"
  iptables -t nat -A OUTPUT -j "$DNAT_CHAIN"
  iptables -t nat -A POSTROUTING -j "$SNAT_CHAIN"

  local index
  for index in $(seq 1 "$count"); do
    forward "$bind_prefix" "$advertised_prefix" "$index" "$((CELL_PORT_BASE + index))"
    case " ${EXIT_ROLE_INDEXES[*]} " in
      *" $index "*)
        forward "$bind_prefix" "$advertised_prefix" "$index" "$((EXIT_DHT_PORT_BASE + index))"
        ;;
    esac

    # Scoped to the bind network so only role-to-role traffic is translated. By
    # POSTROUTING the destination has already been rewritten by the DNAT above,
    # which is why this matches the bind prefix and not the advertised one. A
    # role's traffic to the throwaway testnet on 127.0.0.1 is left alone.
    iptables -t nat -A "$SNAT_CHAIN" \
      -p udp -s "$bind_prefix.$index.1" -d "$network" \
      -j SNAT --to-source "$advertised_prefix.$index.1"
  done
}

case "${1:-}" in
  up)
    [ "$#" -eq 4 ] || usage
    require_iptables
    parse_prefix bind "$2"
    parse_prefix advertised "$3"
    case "$4" in
      '' | *[!0-9]*) unavailable "bad role count: $4" ;;
    esac
    [ "$2" != "$3" ] || unavailable "bind and advertised prefixes must differ"
    remove_chains
    install_chains "$2" "$3" "$4"
    iptables -t nat -S "$DNAT_CHAIN"
    iptables -t nat -S "$SNAT_CHAIN"
    ;;
  down)
    [ "$#" -eq 1 ] || usage
    command -v iptables >/dev/null 2>&1 || exit 0
    remove_chains
    ;;
  check)
    [ "$#" -eq 1 ] || usage
    require_iptables
    ;;
  *) usage ;;
esac
