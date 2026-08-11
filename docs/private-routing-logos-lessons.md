# Private Routing: Lessons from the Logos Networking Stack

**Status:** research notes / candidate gate items (not owner-approved)
**Date:** 2026-08-10
**Relates to:** [`private-routing-v1.md`](./private-routing-v1.md), specifically its
`Security Contract → Out of scope for v1` and `Active-relay adversary` sections.

## Framing

Our v1 is a low-latency onion-**circuit** design in the Tor family: pinned guard,
3-hop path (guard → safety relay → DHT exit), fixed 1,200-byte padded cells,
XChaCha20-Poly1305 with independent keys per direction/class/circuit/generation,
signed relay-capability advertisements, legacy-egress exits, and a fail-closed
`required` mode. Several mixnet lessons are **already absorbed**: fixed-size padded
cells, layered inner AEAD (source→exit and source→destination) so no intermediate
sees non-terminal plaintext, and route-identity/route-key separation from the stable
Noise identity.

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

The items below kept their original value-to-disruption ordering, but that ordering was
**revised once the deployment was pinned** as a closed hyperdht peer network with no exit
(see each gate's status): **A is dropped**, **C is optional**, **D** and **B** remain
forward-looking.

---

## A. Anonymous admission — DROPPED (not this protocol)

Superseded by the decision record:
[`superpowers/specs/2026-08-10-private-routing-admission-analysis-note.md`](./superpowers/specs/2026-08-10-private-routing-admission-analysis-note.md).

Short version: this protocol keeps everything inside the hyperdht peer network — there is
no exit (that would be a separate VPN-service protocol). Admission control protects an
exit; with none, the only abuse is volunteer-relay resource exhaustion, already bounded by
`relay-service.js` quotas (global `MAX_RELAY_CIRCUITS`, per-neighbor cap, queue bytes;
Sybil churn cycles slots but cannot exceed the ceiling). RLN was rejected regardless — it
needs a zk-SNARK dependency (cannot be hand-rolled safely) and a replicated all-member
Merkle tree (Autobase scales badly for many writers). VOPRF tokens were the no-dependency
fallback but only protect an exit, so they are unnecessary here.

---

## B. Loopix/Nym mixing + cover traffic — scoped to cell class, not global

**Gap.** Timing correlation by colluding guard+exit and the global passive observer are
out of scope. A pure low-latency circuit cannot close these.

**Borrow.** Loopix-style Poisson mix delays + cover traffic — but applied **only** to
the `CONTROL` and `DATAGRAM` cell classes, never `STREAM`. We already separate these
contexts, so the structure exists. This begins eroding guard↔exit timing correlation
without touching stream latency or forcing constant-rate cover on mobile (which v1
explicitly refuses).

**Where it lands.** Per-class scheduling policy in the cell scheduler; cover-traffic
generation as a relay/endpoint policy knob defaulted off on mobile. Pairs naturally with
**C** (SURBs make DATAGRAM responses timing-decoupled, which is what mixing needs).

**Risk.** This is the expensive, research-grade property. Treat as a later gate; do not
let it bleed into the STREAM fast path. Note the CDN corollary: bulk data must never ride
the mix — mix the signaling, not the payload.

---

## C. SURBs (single-use reply blocks) — receiver-anonymous replies for DATAGRAM

**Gap / clarification.** Connection-oriented receiver privacy is **already largely
handled**: the bidirectional STREAM circuit carries replies back down the established
route (per-direction keys), and `opaque-destination.js` / `destination-ref.js` /
`redacted-responder-proof.js` / the private-responder tail-extension keep `connect` from
leaking the destination's network address. That is a sound rendezvous-style design for
streams. The residual reply-path gap is the **`DATAGRAM`** class — one-shot DHT-exit
responses that have no standing circuit.

**Borrow.** Nym/Sphinx **single-use reply blocks**: the responder attaches a SURB so a
reply can be routed back without either side learning the other's location and without
holding a circuit open. This decouples request/response timing (enabling **B**) and gives
true receiver-anonymous one-shot responses.

**Where it lands.** DATAGRAM reply path alongside `dht-exit-io.js` /
`dht-exit-destination-table.js`; SURB construction bound into the existing
source→destination inner AEAD context so a relay still cannot read or substitute it.

**Risk.** SURB key/epoch management; replay window interaction with the existing bounded
64-counter DATAGRAM window. Keep SURBs single-use and epoch-bound to match current
teardown semantics.

---

## D. Tor-v3 blinded, epoch-rotating descriptor keys — enumeration resistance

**Gap (forward-looking).** v1 admits "DHT storage nodes see stored record keys and
bounded descriptor bytes." Route material rotates by `epoch` throughout the code, but a
grep of `lib/private` for `blind` returns **zero hits** — there is no key-*blinding*
primitive, only rotation. Private presence records are also not implemented at the
current gate (Gate 3B1 is route construction), so this is guidance for when the
`lookup`/`announce` private-presence path lands, not a present defect.

**Borrow.** Tor v3 onion-service **blinded public keys**: per-time-period key derivation
so the storage node can hold and serve a descriptor it cannot enumerate or link across
epochs or back to a stable identity. Rotation alone is insufficient — without blinding, a
storage node can still correlate successive records of the same private service.

**Where it lands.** Presence-record key derivation when that gate is designed; extend the
existing `crypto_generichash` domain-separated derivation with a per-epoch blinding factor
over the destination's stable key. Verify against the presence-record gate before
treating this as a required item.

**Risk.** Low now (component unbuilt); design it in rather than retrofit.

---

## Explicitly NOT borrowed from Logos

- Blockchain / consensus / token layer — irrelevant; our DHT-exit + relay-directory model
  is the right substrate.
- Mix-everything-by-default — kills streams and mobile; our cell-class split already
  avoids it.
- libp2p / nim-libp2p transport — we build native on UDX / dht-rpc.

## Suggested sequencing

1. **A (RLN admission)** — closes a real abuse hole that bites the moment relays are
   public; scoped, additive to existing advertisements/quotas.
2. **C (DATAGRAM SURBs)** — completes receiver/reply-path privacy where the circuit model
   doesn't already cover it.
3. **D (blinded descriptors)** — fold into the presence-record gate design.
4. **B (scoped mixing + cover)** — later gate; the hard, research-grade property, kept off
   the STREAM fast path.
