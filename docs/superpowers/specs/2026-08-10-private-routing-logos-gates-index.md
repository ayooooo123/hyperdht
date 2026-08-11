# Private Routing: Anonymity Roadmap — Index

**Date:** 2026-08-10
**Source analysis:** [`../../private-routing-logos-lessons.md`](../../private-routing-logos-lessons.md)

**Target (decided):** **Veilid-class anonymity inside hyperdht** — low-latency onion
routing, everything in-network, **no exit** (a clearnet/VPN exit would be a separate
protocol). Tor/Veilid-class, *not* a Nym/Logos mixnet: resists local and single-relay
adversaries, not a global passive observer / traffic correlation. Mixnet-class resistance
(Gate B) is deferred as an opt-in high-anonymity mode; always-on mixing would make
interactive hyperdht use painful.

## The core is already Veilid-class

The existing design — guard-pinned 3-hop circuits, fixed 1,200-byte padded cells,
per-direction/class/circuit AEAD, private route descriptors (`opaque-destination` /
`destination-ref` / `redacted-responder-proof`) — is architecturally a Veilid-style overlay:
circuits ≈ Veilid **safety routes** (sender anonymity), descriptors ≈ Veilid **private
routes** (receiver anonymity). The floor is built. The gates below finish the receiver half
and metadata hardening.

| Gate | Property | Status vs target | Doc |
|---|---|---|---|
| **C** | SURB reply path = Veilid "private routes" done right | **NEAR-TERM — completes receiver anonymity** | [datagram-surb](./2026-08-10-private-routing-datagram-surb-design.md) + [construction](./2026-08-10-private-routing-surb-construction-design.md) |
| **D** | Blinded, epoch-rotating published-route/presence keys | **REQUIRED for the receiver side** — fold into the presence/route-record gate | [blinded-presence-keys](./2026-08-10-private-routing-blinded-presence-keys-note.md) |
| **B** | Scoped mixing + cover traffic | **DEFERRED — opt-in high-anonymity mode** (only path to Nym/mixnet-class; latency cost) | [scoped-mixing](./2026-08-10-private-routing-scoped-mixing-note.md) |
| **A** | Anonymous admission | **DROPPED — not this protocol** | [admission decision](./2026-08-10-private-routing-admission-analysis-note.md) |

## Sequencing for the Veilid-class target

1. **C (SURBs / private routes)** — near-term. Sender anonymity (safety routes) already
   exists via circuits; C completes *receiver* anonymity for connectionless and private-peer
   request/response, and makes routes mixable later. Additive alongside existing
   correlated-reply / STREAM reply.
2. **D (blinded route keys)** — a required property to design into the presence/route-record
   gate whenever address-free `announce`/`lookup` records are built.
3. **B (mixing + cover)** — later, opt-in, CONTROL/DATAGRAM only, never STREAM.
4. **A** — not planned; recorded as a decision only.

## No new dependencies

Everything hand-rolled builds on primitives the pinned deps already expose — **verified
2026-08-10** (`sodium-universal@5.0.1` / `sodium-native@5.1.0`): X25519 `crypto_scalarmult`
(+`_base`), `crypto_box_seal`, BLAKE2b (`crypto_generichash`), XChaCha20-Poly1305. No
zk/SNARK, no libp2p, no chain. **ristretto255 is NOT available and
`crypto_core_ed25519_scalar_mul` is missing**, so: **C** uses per-hop X25519 DH (no scalar
arithmetic — clean fit); **D**'s private-key blinding (`a' = h·a mod L`) needs scalar×scalar
and must supply a vetted mod-`L` multiply (or a newer sodium) when built. Wire formats are
not stable until fixed test vectors + external cryptographic review.
