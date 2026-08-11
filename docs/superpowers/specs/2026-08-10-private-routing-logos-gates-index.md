# Private Routing: Logos-Lessons Gate Set — Index

**Date:** 2026-08-10
**Source analysis:** [`../../private-routing-logos-lessons.md`](../../private-routing-logos-lessons.md)

Four candidate hardening gates derived from the Logos/Nym/Loopix/Tor-v3 prior art, mapped
onto v1's `Out of scope` list. None is owner-approved; all are gated behind the existing
testnet + external-review bar. Sequencing: **A → C → D → B**.

| Gate | Property | Status | Host code exists? | Spec |
|---|---|---|---|---|
| **A** | RLN anonymous admission (Sybil/abuse without deanonymization) | DRAFT, review-ready | Yes — `relay-service.js`, `dht-exit-reservation.js` | [rln-admission](./2026-08-10-private-routing-rln-admission-design.md) |
| **C** | DATAGRAM SURB reply path (connectionless / timing-decoupled / receiver-anon request-response) | DRAFT, review-ready | Partial — DATAGRAM class, `fragments.js`, exit reply path | [datagram-surb](./2026-08-10-private-routing-datagram-surb-design.md) |
| **D** | Blinded, epoch-rotating presence-record keys (enumeration resistance) | FORWARD NOTE — requirement | No — presence records unbuilt at Gate 3B1 | [blinded-presence-keys](./2026-08-10-private-routing-blinded-presence-keys-note.md) |
| **B** | Scoped mixing + cover traffic (timing-correlation / passive-observer resistance) | FORWARD NOTE — research-grade | No — no mix scheduler | [scoped-mixing](./2026-08-10-private-routing-scoped-mixing-note.md) |

## Reading order

1. **A** and **C** are the near-term, review-ready designs with real integration points
   in existing modules. A closes an abuse hole that bites the moment relays are public; C
   completes receiver/reply-path privacy where the circuit model does not already cover it
   (note: initiator-hiding for exit ops already exists via correlated-reply).
2. **D** is a captured requirement for the future private-presence/`announce` gate — must
   be folded into that gate's spec, not implemented standalone.
3. **B** is the hard, research-grade property; it depends on A (relays not an open proxy)
   and C (decoupled replies) and must stay off the STREAM fast path.

## Cross-gate contracts

- **Wire budget:** A's RLN proof and C's SURB header both compete for space in the fixed
  1,200-byte outer cell; their combined footprint on a single request must be designed
  together (both specs flag this).
- **Epochs:** A's external-nullifier epoch and B's mix epoch must compose (A open Q).
- **Additivity:** A (`rlnVerifier: null`) and C (no SURB) both default to exact current
  behavior — the seams are opt-in.

## Not borrowed from Logos

Blockchain / consensus / token layer; mix-everything-by-default; libp2p/nim-libp2p
transport. hyperdht stays native on UDX/dht-rpc.
