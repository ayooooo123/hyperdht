# Private Routing: RLN Anonymous Admission Gate (Candidate Gate A)

**Status:** DRAFT — proposed design, NOT owner-approved. No wire bytes or public
API are frozen by this document.
**Date:** 2026-08-10
**Relates to:** [`private-routing-v1.md`](../../private-routing-v1.md) (Security
Contract → `Out of scope for v1`; `Active-relay adversary`) and
[`private-routing-logos-lessons.md`](../../private-routing-logos-lessons.md) item **A**.
**External crypto dependency:** RLN (Rate-Limiting Nullifier) via `vacp2p/zerokit`;
prior art `logos-co/mix-rln-spam-protection-plugin`.

## Summary

v1 lists "complete Sybil resistance or relay incentives" as out of scope, and the
active-relay section concedes that "one operator obtaining multiple path positions
through distinct identities" remains open. The relay admission path enforces only
*per-neighbor* quotas — `RelayService.reserveCircuit` rejects on
`peer.size >= limits.maxCircuitsPerNeighbor` (`lib/private/relay-service.js:333`),
keyed on the caller's `peerId`. Identity churn trivially defeats that: a caller who
mints fresh peer identities gets fresh circuit budget each time. Because the design's
whole point is that a relay does **not** learn who the route initiator is, the relay
cannot rate-limit an abuser by identity without breaking anonymity.

This gate adds an **RLN admission proof**: a zero-knowledge proof, presented by the
route initiator to each relay/exit at reservation time, that the initiator is a member
of an authorized group and is within its per-epoch message rate. Honest members stay
anonymous. A member who exceeds the rate in one epoch produces two proofs sharing a
nullifier; the relay combines the secret shares, recovers that member's identity
commitment, and evicts/slashes it. DoS resistance without deanonymizing well-behaved
initiators.

This narrows — does not close — the Sybil gap: it bounds the *rate* an anonymous
member can consume, and makes sustained abuse self-identifying. It does not by itself
stop a funded adversary from enrolling many distinct memberships; that is the group
governance / cost-of-membership problem (see Open questions). Topology rules continue
to prohibit one *known* identity occupying multiple positions in a single route.

## Scope change vs v1

Brings **partial** Sybil/abuse resistance in scope. Explicitly still out of scope:
economic incentives, global passive observer, guard+exit timing correlation, and
complete Sybil resistance. `required` mode remains fail-closed: a missing or invalid
admission proof refuses the reservation and never triggers a direct fallback.

## Enforcement points

The proof is presented by the **initiator** (route builder) and verified by the
**relay/exit** before any circuit or exit state is created — mirroring the v1 invariant
"authentication before any counter, replay, route, or application state changes."

1. **Circuit-relay admission** — `lib/private/relay-service.js`,
   `RelayService.reserveCircuit()`. New check inserted after the existing quota checks
   (`:332`–`:333`) and before record construction (`:335`): verify the RLN proof and
   register its nullifier for the current relay epoch. Rejection raises a new
   `ERR_RLN_ADMISSION` (or reuses `ERR_QUOTA_EXCEEDED` for the over-rate case). The
   per-membership rate becomes the primary cap; `maxCircuitsPerNeighbor` remains as a
   coarse secondary bound.
2. **DHT-exit admission** — `lib/private/dht-exit-reservation.js`, at
   `createDhtExitPacketReservation` / `consumeOpenAuthority`. Same proof shape, a
   distinct external-nullifier domain so exit-op rate is metered separately from
   circuit-open rate.

The proof travels in the route-construction control message that requests the
reservation (the M3 link-setup / EXTEND request for circuits; the exit open-authority
request for exits). It does **not** go in the relay's signed capability advertisement
(`relay-capability.js`) — that structure advertises the *relay's* offer, whereas RLN
proves the *initiator's* membership. The relay is the RLN verifier; the group is the
set of authorized initiators.

## RLN mechanics (target)

- **Group** = Merkle tree of member identity commitments (Poseidon), maintained off the
  hot path (see Membership).
- **Proof** binds: the membership Merkle root, an `external_nullifier =
  H(relay_identity, epoch, domain)` (domain distinguishes circuit-open from exit-op),
  a per-epoch `message_limit`, and the message index within the epoch.
- **Rate enforcement:** each in-epoch reservation consumes one message slot and emits a
  `(nullifier, share)` pair. The relay stores at most `message_limit` shares per
  `external_nullifier`. The `message_limit + 1`-th share for the same nullifier lets the
  relay reconstruct the member's secret (Shamir recovery), recover the identity
  commitment, and publish a slashing proof so the group can evict it.
- **Epoch:** relay-local wall epoch (reuse the existing wall-clock discipline in
  `crypto-suite`/verifier state); external nullifier rotates per epoch so the rate is
  per-relay-per-epoch, not global.

## Membership (off hyperdht)

The RLN group tree is **not** a blockchain and **not** owned by hyperdht. Proposed:
an Autobase/Hyperbee-backed membership log in a companion module. Members append a
commitment; the log's deterministic view yields the current Merkle root; relays verify
proofs against a recent root they replicate. hyperdht only receives `{ root,
verifyingKey }` and the proof, and returns accept/reject.

- Autobase `apply` MUST be pure/deterministic (registration ops → tree state); no
  wall-clock or randomness in `apply` (v1/Autobase rule).
- Root freshness/rotation, revocation propagation, and root-disagreement handling are
  open (below).

## Module ownership (proposed)

- New `lib/private/rln-admission.js` — a thin verifier wrapper over the zerokit RLN
  verifier: `verifyAdmission({ proof, root, externalNullifier, verifyingKey, now })`
  → `{ ok, nullifier, share }`; plus per-nullifier share accounting with a bounded
  per-epoch table and eviction-proof emission. No key material for honest members ever
  leaves the initiator; the relay holds only public verifying key + roots.
- Integration hooks (call sites only) in `relay-service.js` (`reserveCircuit`) and
  `dht-exit-reservation.js`. These modules gain a constructor option
  (`rlnVerifier`/`admission`) defaulting to `null` → gate disabled (backward
  compatible; no behavior change when absent).
- Membership log lives in a separate package/module; hyperdht depends only on the
  verifying key + root interface, never on the tree implementation.

## Security invariants (must hold)

1. The admission proof is verified before any circuit/exit record, counter, or replay
   state is created or mutated.
2. A valid under-rate proof reveals nothing about the initiator beyond group
   membership; the relay learns no network address (unchanged from v1) and no stable
   identity.
3. Exceeding `message_limit` for an `external_nullifier` reveals only the offending
   member's identity commitment — never any circuit/application plaintext.
4. Nullifier accounting is bounded per epoch and discard-safe; epoch rollover clears
   prior-epoch nullifier state; counter/epoch wrap is forbidden.
5. A malicious relay may refuse service (DoS) but, absent the member's secret, cannot
   forge a valid membership proof, cannot deanonymize an under-rate member, and cannot
   fabricate a slashing proof against an honest member (soundness of RLN).
6. `required` mode: no proof / invalid proof / stale root → reservation refused; never a
   direct fallback and never a downgrade of the pinned guard.
7. Disabling the gate (`rlnVerifier: null`) restores exact current behavior — the seam
   is additive.

## Open questions (resolve before implementation)

- **Wire budget.** A Groth16 RLN proof + public signals is on the order of a few hundred
  bytes. Confirm it fits the reservation control message without breaking the fixed
  1,200-byte outer cell discipline; a dedicated control message type is likely, not an
  extension of the 188-byte fixed advertisement body (`CAPABILITY_ADVERTISEMENT_FIXED_BODY`).
- **Proving cost on mobile.** RLN proof generation per reservation may be too slow on
  low-end/mobile initiators; measure, and mitigate by **precomputing a batch of fresh
  per-message proofs** ahead of time (each with a distinct in-epoch message index /
  nullifier slot) and/or batch proving to amortize cost. NEVER reuse a proof: every
  reservation MUST carry a fresh proof at its own message index — reusing one replays a
  nullifier slot and collapses the rate guarantee (it is indistinguishable from, or
  worse than, an over-rate event). A lighter membership scheme is an alternative only if
  it preserves one-proof-per-message.
- **Root distribution & freshness.** How relays obtain and agree on a recent membership
  root; tolerance window for root skew; behavior on root disagreement.
- **Revocation / slashing propagation.** How an eviction proof reaches the group and how
  quickly a slashed member is refused network-wide.
- **Group governance / cost of membership.** RLN bounds rate per membership but not the
  number of memberships; the anti-Sybil strength ultimately rests on how costly/gated
  enrolment is. Out of scope for this gate; must be named as a dependency.
- **Interaction with Gate B (mixing).** External-nullifier epoching should be chosen so
  it composes with future cover-traffic/mix delays rather than fighting them.

## Non-goals

No economic/token layer. No change to the E2E Noise/SecretStream guarantee. No change to
guard pinning, path selection, or the existing capability-advertisement wire. No claim
of production anonymity; RLN admission is one hardening layer, gated behind the same
testnet + external-review bar as the rest of v1.
