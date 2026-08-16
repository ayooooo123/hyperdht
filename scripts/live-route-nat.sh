#!/usr/bin/env bash
#
# Installs the address plumbing that lets a one-machine rehearsal exercise the
# thing a real distributed run has and a rehearsal otherwise cannot: a role binds
# one address and is reached at a different one.
#
#   scripts/live-route-nat.sh up <bind-prefix> <advertised-prefix> <role-count>
#   scripts/live-route-nat.sh alias-up <advertised-prefix> <role-count>
#   scripts/live-route-nat.sh down
#   scripts/live-route-nat.sh check
#   scripts/live-route-nat.sh alias-check
#   scripts/live-route-nat.sh counters
#
# There are two ways to make bound and advertised differ, and the difference
# between them is the whole reason both exist.
#
# `up` TRANSLATES. Role `i` binds <bind-prefix>.i.1 and is reached at
# <advertised-prefix>.i.1, on the same port, and netfilter rewrites addresses in
# flight. Two rules per role make that true, and both halves are needed:
#
#   DNAT   in nat OUTPUT, so a packet addressed to the advertised address is
#          delivered to the socket bound at the bind address.
#   SNAT   in nat POSTROUTING, so a packet leaving that socket is observed by its
#          peer as coming from the advertised address.
#
# The SNAT half is not decoration. A peer's observed source address is load
# bearing in this protocol: the cell endpoint compares the source of every
# inbound packet against the address it believes its peer to be at and throws
# UNAUTHORIZED on a mismatch (lib/private/udx-cell-endpoint.js:748), an endpoint
# refuses a link handle whose local address is not its advertised pair
# (lib/private/udx-cell-endpoint.js:1607), and the DHT-setup audit rejects a
# packet whose source is not a permitted reachable tuple
# (test/private/process/dht-setup-audit-udx.js:277). Translating only the
# destination would exercise half a NAT and fail for the wrong reason.
#
# `alias-up` DOES NOT TRANSLATE, and that is its entire point. It reaches the
# same divergence with no packet ever rewritten, so a stall observed under it
# cannot be blamed on this script. See ALIAS MODE below.
#
# The DNAT rule matches an ADDRESS AND NOTHING ELSE. An earlier version of this
# script enumerated the ports it expected the protocol to use and wrote one rule
# per port, which encoded an assumption the protocol never promised to honour: a
# host behind a translated address is reachable on all of its ports, not on a
# list someone wrote down in advance. `--to-destination <addr>` with no port
# preserves the port by definition, so one rule per role now covers every port
# the protocol might ever choose, including one chosen at runtime. The port
# constants below survive only because the observation chains and alias mode
# genuinely need to know them.
#
# Everything lives in named chains, named routing tables and a fixed rule
# priority band, so teardown is exact: nothing this script adds is identified by
# rule number or by matching against the ambient rule set.
#
# KNOWN FAITHFULNESS GAP, recorded rather than fixed, because closing it would
# change what the mode measures. The SNAT rule is scoped to the bind network, so a
# role's traffic to the throwaway testnet on 127.0.0.1 is NOT translated: a DHT
# node observes an exit's DHT-exit socket at its BOUND address while the topology
# publishes its ADVERTISED one. A real NAT translates all egress, not just egress
# to peers. This has not been observed to break anything - the routed immutable
# get through exit A succeeds - but it is a difference from a real runner and it
# belongs in the record.

set -euo pipefail

DNAT_CHAIN=PR_REHEARSAL_DNAT
SNAT_CHAIN=PR_REHEARSAL_SNAT
# Observation only. Every rule in these two chains ends in RETURN and they live in
# tables that do no translation, so installing them cannot change what a packet is
# or where it goes; the packet and byte counters are the entire product. Opt in
# with PR_REHEARSAL_OBSERVE=1, so a mode whose claim is "no netfilter" can be run
# with genuinely no netfilter.
SEEN_OUT_CHAIN=PR_REHEARSAL_SEEN_OUT
SEEN_IN_CHAIN=PR_REHEARSAL_SEEN_IN

# A role's cell endpoint sits at CELL_PORT_BASE + roleIndex. An exit owns a
# second socket for reaching DHT nodes at EXIT_DHT_PORT_BASE + roleIndex, bound to
# the same local host (test/private/process/role-runner.js:420). Those are the
# only two sockets a role ever binds, both at prepare, for its whole life.
CELL_PORT_BASE=42000
EXIT_DHT_PORT_BASE=43000
EXIT_ROLE_INDEXES=(4 6 8)

# Alias mode's routing tables and rule priorities: a fixed band, so `down` removes
# exactly what was added and nothing else.
ALIAS_TABLE_BASE=6400
ALIAS_RULE_PREF_BASE=6400
ALIAS_RULE_PREF_LIMIT=6600
# Where the kernel's own local table gets moved to. It normally sits at priority
# 0, ahead of everything, which is precisely the problem alias mode has to solve.
ALIAS_LOCAL_PREF=32000

usage() {
  echo "usage: $0 up <bind-prefix> <advertised-prefix> <role-count>" >&2
  echo "       $0 alias-up <advertised-prefix> <role-count>" >&2
  echo "       $0 down | check | alias-check | counters" >&2
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

# Alias mode needs no netfilter at all. It needs iproute2 new enough to select a
# routing rule on the source port of a packet, which is what makes per-role source
# selection possible without rewriting anything.
require_iproute2() {
  command -v ip >/dev/null 2>&1 || unavailable "iproute2 is not installed"
  ip rule show >/dev/null 2>&1 ||
    unavailable "cannot read routing rules; the container needs --privileged"
  ip rule add pref "$ALIAS_RULE_PREF_LIMIT" ipproto udp sport 65000 lookup main 2>/dev/null ||
    unavailable "this iproute2/kernel cannot select a routing rule on sport"
  ip rule del pref "$ALIAS_RULE_PREF_LIMIT" 2>/dev/null || true
}

# Two octets, each a plain decimal number: the third and fourth are the role index
# and a literal 1, and the /16 the rules match on is derived from the first two.
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

check_count() {
  case "$1" in
    '' | *[!0-9]*) unavailable "bad role count: $1" ;;
  esac
  [ "$1" -ge 1 ] || unavailable "bad role count: $1"
}

network_of() {
  echo "${1%%.*}.${1##*.}.0.0/16"
}

is_exit_index() {
  case " ${EXIT_ROLE_INDEXES[*]} " in
    *" $1 "*) return 0 ;;
  esac
  return 1
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
  while iptables -t mangle -C OUTPUT -j "$SEEN_OUT_CHAIN" 2>/dev/null; do
    iptables -t mangle -D OUTPUT -j "$SEEN_OUT_CHAIN"
  done
  while iptables -t filter -C INPUT -j "$SEEN_IN_CHAIN" 2>/dev/null; do
    iptables -t filter -D INPUT -j "$SEEN_IN_CHAIN"
  done
  for chain in "$DNAT_CHAIN" "$SNAT_CHAIN"; do
    iptables -t nat -F "$chain" 2>/dev/null || true
    iptables -t nat -X "$chain" 2>/dev/null || true
  done
  iptables -t mangle -F "$SEEN_OUT_CHAIN" 2>/dev/null || true
  iptables -t mangle -X "$SEEN_OUT_CHAIN" 2>/dev/null || true
  iptables -t filter -F "$SEEN_IN_CHAIN" 2>/dev/null || true
  iptables -t filter -X "$SEEN_IN_CHAIN" 2>/dev/null || true
  # A translated flow outlives the rule that created it: conntrack keeps the
  # mapping for the UDP timeout, so a later run in the same container would still
  # be translated by a rule set that no longer exists. Best effort, because the
  # tool is not part of the protocol - and in this image it is absent, which is
  # why `counters` says so out loud rather than guessing.
  if command -v conntrack >/dev/null 2>&1; then
    conntrack -F >/dev/null 2>&1 || true
  fi
}

# One socket, one port: reached at the advertised address, delivered to the bound
# one. No port clause on either side, so every port the role might use is covered
# and the port is preserved by definition.
forward() {
  iptables -t nat -A "$DNAT_CHAIN" \
    -p udp -d "$2.$3.1" \
    -j DNAT --to-destination "$1.$3.1"
}

# Counters, not policy. The out chain answers "did anything address a role at a
# port the old per-port rule set was not written for". The in chain answers the
# sharper question: of the role-to-role packets that actually arrived, how many
# carried a translated source and how many escaped SNAT. A packet that escapes
# SNAT is dropped by its peer at udx-cell-endpoint.js:748 with no frame and no
# log, so a non-zero untranslated count is a silent-drop mechanism rather than a
# curiosity.
install_observation() {
  local bind_prefix="$1" advertised_prefix="$2" count="$3"
  local bind_network advertised_network index
  bind_network="$(network_of "$bind_prefix")"
  advertised_network="$(network_of "$advertised_prefix")"

  iptables -t mangle -N "$SEEN_OUT_CHAIN"
  iptables -t mangle -A OUTPUT -j "$SEEN_OUT_CHAIN"
  for index in $(seq 1 "$count"); do
    iptables -t mangle -A "$SEEN_OUT_CHAIN" \
      -p udp -d "$advertised_prefix.$index.1" --dport "$((CELL_PORT_BASE + index))" -j RETURN
    if is_exit_index "$index"; then
      iptables -t mangle -A "$SEEN_OUT_CHAIN" \
        -p udp -d "$advertised_prefix.$index.1" --dport "$((EXIT_DHT_PORT_BASE + index))" -j RETURN
    fi
  done
  # Anything reaching this rule addressed a role at a port the old rule set did
  # not enumerate. Its counter is the fresh-port question, answered.
  iptables -t mangle -A "$SEEN_OUT_CHAIN" -p udp -d "$advertised_network" -j RETURN

  # filter INPUT sees a packet after nat OUTPUT and nat POSTROUTING have both run,
  # so it is the only place the final source address can be observed.
  iptables -t filter -N "$SEEN_IN_CHAIN"
  iptables -t filter -A INPUT -j "$SEEN_IN_CHAIN"
  iptables -t filter -A "$SEEN_IN_CHAIN" \
    -p udp -s "$advertised_network" -d "$bind_network" -j RETURN
  iptables -t filter -A "$SEEN_IN_CHAIN" \
    -p udp -s "$bind_network" -d "$bind_network" -j RETURN
}

install_chains() {
  local bind_prefix="$1" advertised_prefix="$2" count="$3"
  local network
  network="$(network_of "$bind_prefix")"

  iptables -t nat -N "$DNAT_CHAIN"
  iptables -t nat -N "$SNAT_CHAIN"
  iptables -t nat -A OUTPUT -j "$DNAT_CHAIN"
  iptables -t nat -A POSTROUTING -j "$SNAT_CHAIN"

  local index
  for index in $(seq 1 "$count"); do
    forward "$bind_prefix" "$advertised_prefix" "$index"

    # Scoped to the bind network so only role-to-role traffic is translated. By
    # POSTROUTING the destination has already been rewritten by the DNAT above,
    # which is why this matches the bind prefix and not the advertised one. See
    # the faithfulness gap noted at the top of this file.
    iptables -t nat -A "$SNAT_CHAIN" \
      -p udp -s "$bind_prefix.$index.1" -d "$network" \
      -j SNAT --to-source "$advertised_prefix.$index.1"
  done

  if [ "${PR_REHEARSAL_OBSERVE:-}" = 1 ]; then
    install_observation "$bind_prefix" "$advertised_prefix" "$count"
  fi
}

# ALIAS MODE
#
# The question translation cannot answer about itself: when a divergent run
# stalls, is the protocol wrong or is this script? Alias mode answers it by
# reaching the same divergence with nothing rewritten.
#
# A role binds the WILDCARD and publishes <advertised-prefix>.i.1. Two facts make
# that a real divergence rather than a relabelling:
#
#   Delivery. The published address is added to `lo`, so a packet addressed to it
#   is delivered, by ordinary local delivery, to the wildcard socket holding that
#   port. Nothing rewrites the destination, because the destination was already
#   right.
#
#   Source. A wildcard socket does not fix its own source address; the kernel
#   picks one per destination, and for anything in 127/8 it would pick the same
#   address for every role alike. That is not good enough here, because a peer
#   compares the source of an inbound packet against the address it believes we
#   are at (udx-cell-endpoint.js:748) and rejects a mismatch silently. So each
#   role gets a routing table whose route carries `src <its own advertised
#   address>`, and a routing rule selects that table on the role's own source
#   port. Source SELECTION is not translation: it decides which address a packet
#   is born with, it keeps no per-flow state, it has no timeout, and there is no
#   conntrack entry anywhere in it to expire, collide or be reaped.
#
# The kernel's local table normally resolves 127/8 at priority 0, ahead of any
# rule that could be added, which would defeat the src hint. So the local lookup
# is moved to ALIAS_LOCAL_PREF and the per-role rules sit ahead of it. A
# destination no per-role table covers falls through to the moved local table and
# behaves exactly as before, which is what keeps the throwaway testnet on
# 127.0.0.1 working.
#
# What this buys: bound is 0.0.0.0 and published is <advertised>.i.1, which are
# not only different strings but maximally different ones. Any code reaching for
# the bound address where the published one belongs yields 0.0.0.0 and fails at
# once, rather than producing a plausible wrong answer. And because no packet is
# translated, a stall under this mode is not this script's doing.
alias_local_rule_moved() {
  ip rule show | grep -q "^$ALIAS_LOCAL_PREF:.*lookup local"
}

remove_alias() {
  local pref table addr
  # Only the fixed band belongs to this script.
  for pref in $(
    ip rule show 2>/dev/null | sed -n 's/^\([0-9][0-9]*\):.*/\1/p' | sort -un
  ); do
    if [ "$pref" -ge "$ALIAS_RULE_PREF_BASE" ] && [ "$pref" -le "$ALIAS_RULE_PREF_LIMIT" ]; then
      while ip rule del pref "$pref" 2>/dev/null; do :; done
    fi
  done
  for table in $(seq "$((ALIAS_TABLE_BASE + 1))" "$((ALIAS_TABLE_BASE + 32))"); do
    ip route flush table "$table" 2>/dev/null || true
  done
  # Put the kernel's local lookup back at priority 0 before dropping the copy, so
  # there is never an instant with no local table in the chain.
  if alias_local_rule_moved; then
    ip rule add pref 0 lookup local 2>/dev/null || true
    ip rule del pref "$ALIAS_LOCAL_PREF" lookup local 2>/dev/null || true
  fi
  # Published addresses are the /32s this script put on lo. The kernel's own
  # 127.0.0.1/8 is not a /32 and is not matched.
  for addr in $(
    ip -4 -o addr show dev lo 2>/dev/null | sed -n 's#.*inet \([0-9.]*\)/32 .*#\1#p'
  ); do
    ip addr del "$addr/32" dev lo 2>/dev/null || true
  done
}

install_alias() {
  local advertised_prefix="$1" count="$2"
  local advertised_network index table pref
  advertised_network="$(network_of "$advertised_prefix")"

  for index in $(seq 1 "$count"); do
    ip addr add "$advertised_prefix.$index.1/32" dev lo ||
      unavailable "cannot add $advertised_prefix.$index.1 to lo"
  done

  # Order matters: add the copy first, then drop priority 0.
  ip rule add pref "$ALIAS_LOCAL_PREF" lookup local ||
    unavailable "cannot move the local routing table"
  ip rule del pref 0 lookup local 2>/dev/null || true

  for index in $(seq 1 "$count"); do
    table="$((ALIAS_TABLE_BASE + index))"
    pref="$((ALIAS_RULE_PREF_BASE + index))"
    ip route add table "$table" \
      local "$advertised_network" dev lo src "$advertised_prefix.$index.1" ||
      unavailable "cannot install the source route for role $index"
    ip rule add pref "$pref" ipproto udp sport "$((CELL_PORT_BASE + index))" lookup "$table" ||
      unavailable "cannot install the source rule for role $index"
    if is_exit_index "$index"; then
      ip rule add pref "$((pref + 100))" \
        ipproto udp sport "$((EXIT_DHT_PORT_BASE + index))" lookup "$table" ||
        unavailable "cannot install the exit source rule for role $index"
    fi
  done
}

# What a run can actually be asked about afterwards. Stated, not guessed: this
# image has no `conntrack` binary and no /proc/net/nf_conntrack, so per-flow
# conntrack state cannot be listed here and this function does not pretend it can.
# The aggregate count and the timeouts are readable, and the rule counters are the
# real evidence.
report_counters() {
  echo "--- nat rule counters ---"
  iptables -t nat -L "$DNAT_CHAIN" -n -v -x 2>/dev/null || echo "(no $DNAT_CHAIN)"
  iptables -t nat -L "$SNAT_CHAIN" -n -v -x 2>/dev/null || echo "(no $SNAT_CHAIN)"
  echo "--- observation counters ---"
  iptables -t mangle -L "$SEEN_OUT_CHAIN" -n -v -x 2>/dev/null || echo "(no $SEEN_OUT_CHAIN)"
  iptables -t filter -L "$SEEN_IN_CHAIN" -n -v -x 2>/dev/null || echo "(no $SEEN_IN_CHAIN)"
  echo "--- conntrack ---"
  if command -v conntrack >/dev/null 2>&1; then
    conntrack -L 2>/dev/null || true
  else
    echo "conntrack(8): ABSENT from this image"
  fi
  if [ -r /proc/net/nf_conntrack ]; then
    echo "per-flow table:"
    cat /proc/net/nf_conntrack
  else
    echo "/proc/net/nf_conntrack: ABSENT (CONFIG_NF_CONNTRACK_PROCFS off)"
  fi
  for f in nf_conntrack_count nf_conntrack_max nf_conntrack_udp_timeout \
    nf_conntrack_udp_timeout_stream; do
    printf '%s %s\n' "$f" "$(cat "/proc/sys/net/netfilter/$f" 2>/dev/null || echo '?')"
  done
  echo "--- bound udp sockets ---"
  ss -uan 2>/dev/null || echo "(ss unavailable)"
  echo "--- routing rules ---"
  ip rule show 2>/dev/null || true
}

case "${1:-}" in
  up)
    [ "$#" -eq 4 ] || usage
    require_iptables
    parse_prefix bind "$2"
    parse_prefix advertised "$3"
    check_count "$4"
    [ "$2" != "$3" ] || unavailable "bind and advertised prefixes must differ"
    remove_chains
    if command -v ip >/dev/null 2>&1; then remove_alias; fi
    install_chains "$2" "$3" "$4"
    iptables -t nat -S "$DNAT_CHAIN"
    iptables -t nat -S "$SNAT_CHAIN"
    ;;
  alias-up)
    [ "$#" -eq 3 ] || usage
    require_iproute2
    parse_prefix advertised "$2"
    check_count "$3"
    # Alias mode installs no netfilter rule of any kind, so a leftover rule set
    # from a translated run would silently make it a translated run.
    if command -v iptables >/dev/null 2>&1 && iptables -t nat -L -n >/dev/null 2>&1; then
      remove_chains
    fi
    remove_alias
    install_alias "$2" "$3"
    ip rule show
    ip -4 -o addr show dev lo
    ;;
  down)
    [ "$#" -eq 1 ] || usage
    if command -v iptables >/dev/null 2>&1; then remove_chains; fi
    if command -v ip >/dev/null 2>&1; then remove_alias; fi
    ;;
  check)
    [ "$#" -eq 1 ] || usage
    require_iptables
    ;;
  alias-check)
    [ "$#" -eq 1 ] || usage
    require_iproute2
    ;;
  counters)
    [ "$#" -eq 1 ] || usage
    report_counters
    ;;
  *) usage ;;
esac
