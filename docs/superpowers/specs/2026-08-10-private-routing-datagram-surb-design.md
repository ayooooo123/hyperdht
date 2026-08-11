# Private Routing: DATAGRAM SURB Reply Path (Candidate Gate C)

**Status:** NEAR-TERM for the Veilid-class target — completes receiver anonymity (Veilid
"private routes"). Design not owner-approved; no wire bytes/API frozen. Concrete
construction in [`2026-08-10-private-routing-surb-construction-design.md`](./2026-08-10-private-routing-surb-construction-design.md).
**Date:** 2026-08-10
**Relates to:** [`private-routing-v1.md`](../../private-routing-v1.md) (the mixnet
"carries both fire-and-forget messages and request-response interactions"; `Out of
scope` cover traffic / timing) and
[`private-routing-logos-lessons.md`](../../private-routing-logos-lessons.md) item **C**.
**Prior art:** Sphinx single-use reply blocks (SURBs); Nym / Loopix reply mechanics.

## Summary

A SURB (single-use reply block) is a layered, pre-addressed reply header the initiator
builds and hands to a responder, so the responder can send exactly one reply back
through a chosen relay path **without learning the initiator's address or the return
route**, and without a standing circuit held open for the round trip.

This gate adds a SURB-based reply path for the `DATAGRAM` cell class
(`CELL_CLASS.DATAGRAM = 2`, `lib/private/protocol.js:136`). It is **complementary**, not
a replacement, to the two reply mechanisms that already exist.

## What already exists (do not re-solve)

Accurate statement of the current reply paths, from source:

- **STREAM replies** ride the established bidirectional circuit (per-direction keys).
  Receiver/initiator address-hiding for connection-oriented traffic is already handled;
  `privateConnect` does not leak the initiator's address to the destination.
- **DHT-exit replies** are **circuit-correlated**:
  `createDhtExitCorrelatedReplyAuthorityForIO`
  (`lib/private/dht-exit-reservation.js:394`) binds a reply to the exact request `tid`
  and remote/local tuples and returns it along the established route
  (`transferState.channel`). The queried DHT node sees the exit, never the initiator.

So initiator-hiding for one-shot exit ops is **already provided**. This gate does not
claim to fix a leak there. What SURBs add:

1. **Connectionless replies** — no need to pin the full forward circuit/transfer for the
   whole RTT; the reply can be emitted after the forward request has torn down.
2. **Timing decoupling** — the reply leg is no longer bound to the forward
   request/response deadline, which is the prerequisite for applying Gate B (Loopix mix
   delays / cover traffic) to replies without stalling the forward path.
3. **Receiver-anonymous request/response to private-peer destinations** — a lightweight
   DATAGRAM request/response between two private peers that does not require standing up
   a full STREAM circuit, while still hiding both endpoints' addresses.

## SURB mechanics (target)

- The **initiator** selects a return path (relays) and builds a SURB: a Sphinx-style
  layered header addressed hop-by-hop back to itself, plus a set of per-layer secrets it
  retains locally to decrypt the eventual reply. The initiator's address appears only in
  the innermost layer, encrypted to the initiator.
- The SURB travels inside the forward request's inner (source-to-destination) AEAD
  context, so no relay or exit on the forward path can read it — reuse the existing
  `crypto-suite` source-to-destination context and domain separation.
- The **responder/exit** attaches its reply payload to the SURB and forwards it to the
  SURB's first return hop. It learns only that first hop, never the initiator's address
  or the full return path.
- Each return relay peels one layer (fresh per-layer key) and forwards to the next,
  identically to the forward mix/relay peel, terminating at the initiator, which unwraps
  using its retained secrets.
- **Single-use.** Every SURB carries fresh keys and a one-shot nullifier bound to the
  route epoch. A SURB MUST NOT be reused: reuse is a linkability vector and a replay.
  One request → one SURB (or a small pre-issued batch, each single-use) → at most one
  reply.

## Enforcement / integration points

- **New module** `lib/private/surb.js`: `buildSurb({ returnPath, epoch, ... })` →
  `{ surb, openSecrets }` (initiator side); `useSurb(surb, replyPayload)` → return-path
  cell (responder side); `openSurbReply(cell, openSecrets)` → plaintext (initiator side).
  Fixed-size SURB header consistent with the 1,200-byte outer cell discipline.
- **DATAGRAM carriage**: replies fragment/reassemble through the existing
  `lib/private/fragments.js` path (bounded 64-counter replay window, `epochExpiresAt`),
  under the `TAIL_FINALIZE_DATAGRAM` / `FINAL_EXIT_FINALIZE_DATAGRAM` contexts
  (`protocol.js` `CONTEXT_CLASS`).
- **Exit path**: add a SURB-based reply authority alongside
  `createDhtExitCorrelatedReplyAuthorityForIO` — the request may carry an optional SURB;
  when present, the exit replies via the SURB instead of the correlated live channel.
  Absent → current correlated-reply behavior is unchanged (additive seam).
- **Private-peer path**: a routed DATAGRAM request between private peers may carry a SURB
  so the responder can answer without a STREAM circuit.

## Security invariants (must hold)

1. A SURB is single-use: a second use of the same SURB nullifier within its epoch is
   rejected as replay; the reply is delivered at most once.
2. The responder/exit learns only the SURB's first return hop — never the initiator's
   address, the full return path, or the number of return hops beyond what fixed-size
   padding reveals.
3. Each return relay learns only its own next hop (same guarantee as the forward path);
   no relay can read the reply payload (inner AEAD to the initiator).
4. SURB per-layer secrets and the initiator's `openSecrets` are fresh per request, bound
   to the route epoch, and erased on reply receipt, expiry, or teardown.
5. The SURB is unreadable to every forward-path hop (carried in the source-to-destination
   inner context); a forward relay cannot substitute, forge, or correlate it across
   circuits, directions, or epochs.
6. `required` mode: if a reply requires a SURB and none is present or it is invalid/expired,
   the reply is dropped — never a fallback that reveals the initiator, never a downgrade
   of the pinned guard.
7. Omitting the SURB restores exact current behavior (STREAM circuit / correlated exit
   reply) — the seam is additive.

## Open questions (resolve before implementation)

- **SURB wire budget.** A multi-hop Sphinx SURB header is large; confirm it fits the
  request cell alongside the payload (and, under Gate A, an RLN proof) without breaking
  the fixed 1,200-byte cell. May force a dedicated request layout or a shorter default
  return-path length.
- **Large replies.** `immutableGet`/`mutableGet` values can exceed one cell. Decide:
  one SURB keying a fragmented reply stream, vs. a small batch of single-use SURBs (one
  per fragment). Fragmentation MUST stay within `fragments.js` bounds.
- **Coexistence with correlated-reply.** Keep the synchronous correlated-reply path for
  the common low-latency exit case; use SURBs for async / connectionless / private-peer
  replies. Define selection rules so both cannot apply to one request.
- **Return-path selection & diversity.** Reuse forward path-selection/diversity rules for
  the return path; decide whether return relays may equal forward relays (topology rules
  currently forbid one identity in multiple positions of a route — does the return leg
  count as the same route?).
- **Gate B interaction.** SURB replies are the intended surface for mix delay / cover
  traffic; epoch and nullifier choices must compose with that, not fight it.

## Non-goals

No change to STREAM circuit replies or the existing correlated exit-reply wire. No
economic layer. No change to guard pinning or forward path selection. No claim of
production anonymity; gated behind the same testnet + external-review bar as the rest of
v1. Does not, by itself, defeat a global passive observer or guard+exit timing
correlation (that is Gate B).
