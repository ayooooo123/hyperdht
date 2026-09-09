# Private Routing: Anonymous Admission — Analysis & Decision (was Candidate Gate A)

**Status:** DROPPED — not part of this protocol. Retained only as a decision record so the
reasoning is not re-litigated.
**Date:** 2026-08-10 (supersedes the earlier RLN-admission draft of the same date)
**Relates to:** [`private-routing-v1.md`](../../private-routing-v1.md),
[`private-routing-logos-lessons.md`](../../private-routing-logos-lessons.md) item **A**.

## Decision

**No anonymous-admission mechanism (RLN, VOPRF tokens, or otherwise) is added.**

The implemented slice has bounded DHT request-exit roles, but no generic VPN,
clearnet, or legacy-peer egress. A third-party proxy service would need its own
threat model and approval. The decision not to add anonymous admission remains
in force; it must not be justified by claiming that the DHT exit role is absent.

## Existing resource controls and their limits

The current resource controls include:

- **Volunteer-relay resource exhaustion.** A middle/guard relay spends memory, bandwidth,
  and per-cell crypto forwarding for strangers. Already bounded in
  `lib/private/relay-service.js`: `MAX_RELAY_CIRCUITS` (128 global), per-neighbor cap
  (`maxCircuitsPerNeighbor` 32), and per-circuit/global queue-byte caps. Sybil identity
  churn lets an attacker _cycle_ slots faster but **cannot exceed** the ceiling — the relay
  refuses circuit 129. An admission token would add a per-circuit cost without lowering
  that ceiling. Marginal value, real complexity → not worth it.

These ceilings bound allocated relay state; they do not establish complete abuse,
Sybil, or denial-of-service resistance. Typed DHT-exit command policies separately
bound destinations, request/reply bytes, costs, and outstanding operations.

## Why the imported mechanisms were rejected (record)

- **RLN (Waku/Logos):** rejected on two independent grounds even before scope narrowed it
  out. (1) It needs a zk-SNARK proving system — a dependency we will not add, and a SNARK
  cannot be hand-rolled safely. (2) It needs a Merkle membership tree of **all** members
  replicated to every verifier — exactly the large shared-writer set Autobase scales badly
  for (Autobase is for small per-room/org/doc writer sets).
- **VOPRF anonymous tokens (Privacy-Pass style):** considered as an alternative
  to replicated membership machinery, but not selected. No issuer, token flow,
  or admission protocol is implemented or approved by this note.

## Correction of an earlier factual error

The earlier “no exit at all” wording conflated a DHT request-exit with generic
egress. The fork implements the former. `DHT_EXIT_ORIGIN_SERVICE_POLICY` in
`lib/private/exit-policy.js` permits the four immutable/mutable get/put commands
(`0x0120–0x0123`), not arbitrary proxying or public announce/lookup.
Gate D presence uses mutable records. The old `PRIVATE_ANNOUNCE` overlay and
storage-session IDs remain reserved/rejected for presence under D10; they are
not an implemented announce-flooding surface. See
[current implementation and open gates](../../private-routing-migration.md#current-implementation).

## If a separate VPN/exit service is ever built

A generic proxy service would be separate reviewed work with external
attribution and third-party abuse risks. Whether anonymous admission belongs
there would require a new decision; this historical discussion neither approves
a VOPRF implementation nor reintroduces dropped RLN/Autobase membership.

## Non-goals

No anonymous-admission machinery, generic VPN/legacy-peer egress, chain, token
economics, or deanonymization mechanism is added. This decision does not claim
production anonymity or replace external review of the implemented routing,
SURB, and presence paths.
