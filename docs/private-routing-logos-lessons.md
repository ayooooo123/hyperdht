# Private Routing: Lessons from the Logos Networking Stack

**Status:** research rationale with current gate status; C/D are implemented experimentally, A is dropped, B is deferred; external cryptographic review remains open
**Date:** 2026-08-10
**Relates to:** [`private-routing-v1.md`](./private-routing-v1.md), specifically its
`Security Contract → Out of scope for v1` and `Active-relay adversary` sections.

## Framing

Our v1 is a low-latency onion-**circuit** design in the Tor family: pinned guard,
3-hop path (guard → safety relay → DHT exit), fixed 1,200-byte padded cells,
XChaCha20-Poly1305 with independent keys per direction/class/circuit/generation,
signed relay-capability advertisements, and a package-private fail-closed routing
mode. Fixed-size cells, source-to-exit inner AEAD, and route-key separation are
implemented. Peer streams and legacy-peer egress remain unimplemented design
targets, not properties established by these research notes.

What v1 deliberately puts **out of scope** is almost exactly the problem the Logos
networking stack (Waku-lineage libp2p mixnet + RLN) exists to solve:

- global passive observer;
- timing correlation by colluding guard + exit;
- complete Sybil resistance / relay incentives;
- constant-rate cover traffic (esp. mobile);
- query privacy from DHT exits.

Logos is therefore the most relevant prior art for the properties we chose to defer.
The Logos stack itself is pre-testnet, so these are design borrows, not code to lift.
Reference implementations for the mix ideas: `logos-co/nim-libp2p-mix` (Sphinx mixnet).
Nym/Loopix and Tor v3 onion services are the upstream academic sources. Note:
`vacp2p/zerokit` / `logos-co/mix-rln-spam-protection-plugin` (RLN) are **not** used — see
Gate A below for why RLN is rejected.

The original value-to-disruption ordering is superseded. **A is dropped**;
**C and D are implemented experimentally**; **B remains deferred**. The bounded
DHT request-exit role exists, but it is not a generic VPN or legacy-peer egress.
See [current implementation and open gates](private-routing-migration.md#current-implementation).

---

## A. Anonymous admission — DROPPED (not this protocol)

Superseded by the decision record:
[`superpowers/specs/2026-08-10-private-routing-admission-analysis-note.md`](./superpowers/specs/2026-08-10-private-routing-admission-analysis-note.md).

No RLN or VOPRF admission mechanism is added. The implemented slice has bounded
DHT request-exit operations, not arbitrary third-party proxying. Relay resource
use is bounded by circuit and queue quotas; those limits do not eliminate Sybil
churn or denial of service. The rejected admission proposals and their dependency
costs remain recorded in the linked decision. Gate A is not a prerequisite for
the deferred mixing research.

---

## B. Loopix/Nym mixing + cover traffic — scoped to cell class, not global

**Gap.** Timing correlation by colluding guard+exit and the global passive observer are
out of scope. A pure low-latency circuit cannot close these.

**Borrow.** Loopix-style Poisson mix delays + cover traffic — but applied **only** to
the `CONTROL` and `DATAGRAM` cell classes, never `STREAM`. We already separate these
contexts, so the structure exists. This begins eroding guard↔exit timing correlation
without touching stream latency or forcing constant-rate cover on mobile (which v1
explicitly refuses).

**Possible future integration.** A separately reviewed per-class scheduling and
cover-traffic policy. Current Gate C replies use the existing reverse relays
and route/query deadlines; SURBs alone do not provide independent routing,
timing decoupling, or a mixing scheduler.

**Risk.** This is the expensive, research-grade property. Treat as a later gate; do not
let it bleed into the STREAM fast path. Note the CDN corollary: bulk data must never ride
the mix — mix the signaling, not the payload.

---

## C. SURBs (single-use reply blocks) — receiver-anonymous replies for DATAGRAM

**Implemented scope.** Gate C provides single-use replies for the package-private
DHT get/put path, including Gate D publication and revocation. The initiator
supplies a bounded SURB batch in an authenticated V2 request; each reply fragment
uses a different SURB. Relays peel locally, and physical carriage remains
link-sealed in fixed-size cells.

The default reply path remains correlated. Explicit `SURB_REQUIRED` is gated by
`experimentalSurbReplies: true` and never falls back to correlated replies.
Current SURBs reuse the route's reverse relays and shared operation lifetime;
they do not survive arbitrary forward-route teardown, add cover traffic, or
prove general receiver anonymity. Private-peer DATAGRAMs and peer streams still
need their own reviewed implementation.

**Risk.** SURB key/epoch management; replay window interaction with the existing bounded
64-counter DATAGRAM window. Keep SURBs single-use and epoch-bound to match current
teardown semantics.

---

## D. Tor-v3 blinded, epoch-rotating descriptor keys — enumeration resistance

**Implemented scope.** `lib/private/blinded-presence.js` supplies per-period key
derivation, blinded signing, encrypted fixed-size records, and tombstones;
`lib/private/presence-client.js` publishes, resolves, and revokes them through
mutable DHT records. Native scalar multiplication is supplied by the pinned
sodium-native fork, not JavaScript arithmetic.

**Borrow.** Tor v3-style blinded public keys avoid publishing the stable identity
as the storage identifier. A separate reader credential protects the descriptor
body. A party that already knows the stable identity can derive its period keys;
blinding does not hide timing, volume, or that known-identity linkage.

**Verification and risk.** Required-mode publication and revocation are proven
on the live gate, including resolution to authenticated absence after a newer
tombstone. External cryptographic review remains open. The
[presence note](superpowers/specs/2026-08-10-private-routing-blinded-presence-keys-note.md)
distinguishes the original derivation sketch from the accepted record transcript.

---

## Explicitly NOT borrowed from Logos

- Blockchain / consensus / token layer — irrelevant; our DHT-exit + relay-directory model
  is the right substrate.
- Mix-everything-by-default — kills streams and mobile; our cell-class split already
  avoids it.
- libp2p / nim-libp2p transport — we build native on UDX / dht-rpc.

## Suggested sequencing

1. **C and D:** implemented experimentally; preserve their external cryptographic
   review and public-mode gates rather than reimplementing the old candidates.
2. **Peer streams and consumer integration:** separately reviewed designs and
   end-to-end evidence are still required.
3. **B (scoped mixing + cover):** deferred research; not enabled by C/D alone and
   never part of the STREAM fast path.

**A remains dropped.** It is not a step in the current sequence.
