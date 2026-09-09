# Private Routing: Anonymity Roadmap — Index

**Date:** 2026-08-10
**Source analysis:** [`../../private-routing-logos-lessons.md`](../../private-routing-logos-lessons.md)
**Current status:** [implementation and open gates](../../private-routing-migration.md#current-implementation),
at published `cae9721` (2026-09-09). Historical design targets are not public APIs.

**Target:** low-latency private routing inside HyperDHT, with bounded DHT
request-exit roles but no implemented generic VPN or legacy-peer egress. The
Veilid comparison is architectural, not an equivalence or anonymity proof.
Timing/volume correlation remains outside the current guarantees; mixing/cover
traffic (Gate B) is deferred research.

## Implemented core and remaining gates

Guard-pinned three-position routes, fixed 1,200-byte cells, and authenticated
per-link/per-generation state are implemented package-private. Opaque DHT
destination references and tail-extension proofs are not a completed
private-peer rendezvous or stream API. Gate C/D implementation does not close
the external cryptographic review or public-mode gates.

| Gate  | Property                                              | Status vs target                                                                                                             | Doc                                                                                                                                              |
| ----- | ----------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| **C** | Single-use DATAGRAM replies                           | **IMPLEMENTED, experimental** — reverse-relay return; external review open                                                   | [datagram-surb](./2026-08-10-private-routing-datagram-surb-design.md) + [construction](./2026-08-10-private-routing-surb-construction-design.md) |
| **D** | Blinded, epoch-rotating published-route/presence keys | **IMPLEMENTED (experimental wire; external review OPEN)** — mutable-command presence, native `scalar_mul` binding            | [blinded-presence-keys](./2026-08-10-private-routing-blinded-presence-keys-note.md)                                                              |
| **B** | Scoped mixing + cover traffic                         | **DEFERRED — opt-in high-anonymity mode** (only path to Nym/mixnet-class; latency cost; independent of dropped Gate A / RLN) | [scoped-mixing](./2026-08-10-private-routing-scoped-mixing-note.md)                                                                              |
| **A** | Anonymous admission                                   | **DROPPED — not this protocol**                                                                                              | [admission decision](./2026-08-10-private-routing-admission-analysis-note.md)                                                                    |

## Current status & sequencing

1. **C (SURBs / private routes)** — **Implemented (experimental wire).** Owner-approved
   experimental Gate C wire (`ROUTED_REQUEST_V2` `0x0103`) and live link-sealed relay-local
   peel implemented; tested live for immutable/mutable get/put and presence publish/revoke.
   Current SURBs return via the route's own reverse relays and share the route/query deadline;
   they are not independently routed or mixed and do not claim general timing anonymity.
   External cryptographic review and public required-mode exposure remain open.
2. **D (blinded route keys)** — **Implemented (experimental wire).** Implemented as Gate D
   blinded presence over DHT mutable commands, with publish/resolve/revoke
   threading configured `replyMode`. The live scenario checks publication and
   authenticated absence after a period-scoped tombstone at a higher revision.
   Native scalar multiplication is pinned; there is no JavaScript substitute. External
   cryptographic review and public mode remain open.
3. **B (mixing + cover)** — **Deferred.** Opt-in high-anonymity mode (CONTROL/DATAGRAM only,
   never STREAM). Independent of dropped Gate A (RLN is not a prerequisite).
4. **A (admission)** — **Dropped.** Recorded as an architectural decision; no admission
   machinery ships.

## Cryptographic dependencies

Gate C uses the existing X25519, BLAKE2b, and XChaCha20-Poly1305 primitives.
Gate D required a native `crypto_core_ed25519_scalar_mul` binding, now supplied
by the pinned sodium-native fork. The old “no dependency change” claim does not
apply to that pin. No zk/SNARK, libp2p, or blockchain stack was added.

**Cryptographic bindings & review status:**

- **Historical note (2026-08-10):** At initial draft, `crypto_core_ed25519_scalar_mul` was
  missing in the baseline package; the original Gate C sketch selected per-hop X25519 DH.
- **Current status:** Gate D private-key blinding is backed by a pinned native `scalar_mul`
  dependency binding; there is no JavaScript scalar arithmetic.
- Gate C wire is owner-approved as experimental; external cryptographic review and public
  required-mode exposure remain **OPEN**. Wire formats remain experimental until external
  review passes.
