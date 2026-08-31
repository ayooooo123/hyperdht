# Private Routing: Anonymous Admission — Analysis & Decision (was Candidate Gate A)

**Status:** DROPPED — not part of this protocol. Retained only as a decision record so the
reasoning is not re-litigated.
**Date:** 2026-08-10 (supersedes the earlier RLN-admission draft of the same date)
**Relates to:** [`private-routing-v1.md`](../../private-routing-v1.md),
[`private-routing-logos-lessons.md`](../../private-routing-logos-lessons.md) item **A**.

## Decision

**No anonymous-admission mechanism (RLN, VOPRF tokens, or otherwise) is added.**

This protocol keeps **everything inside the hyperdht peer network**. There is no exit from
the DHT network — no bridge to the clearnet or to non-participating services. Such a bridge
would be an **entirely separate VPN-service protocol** with its own threat model, and is
explicitly not what is being built here. Absent any exit, anonymous admission solves a
problem this system does not have.

## Why (the only real abuse surface, and it's already handled)

With all traffic internal to the peer network, the abuse surface reduces to **one** thing:

- **Volunteer-relay resource exhaustion.** A middle/guard relay spends memory, bandwidth,
  and per-cell crypto forwarding for strangers. Already bounded in
  `lib/private/relay-service.js`: `MAX_RELAY_CIRCUITS` (128 global), per-neighbor cap
  (`maxCircuitsPerNeighbor` 32), and per-circuit/global queue-byte caps. Sybil identity
  churn lets an attacker _cycle_ slots faster but **cannot exceed** the ceiling — the relay
  refuses circuit 129. An admission token would add a per-circuit cost without lowering
  that ceiling. Marginal value, real complexity → not worth it.

Same class of resource problem vanilla Hyperswarm already lives with, handled the same way
(quotas + the commons model).

## Why the imported mechanisms were rejected (record)

- **RLN (Waku/Logos):** rejected on two independent grounds even before scope narrowed it
  out. (1) It needs a zk-SNARK proving system — a dependency we will not add, and a SNARK
  cannot be hand-rolled safely. (2) It needs a Merkle membership tree of **all** members
  replicated to every verifier — exactly the large shared-writer set Autobase scales badly
  for (Autobase is for small per-room/org/doc writer sets).
- **VOPRF anonymous tokens (Privacy-Pass style):** the hand-rollable, no-dependency
  alternative (issuer public key + relay-local per-epoch ephemeral nullifier set; no
  Autobase, no replicated membership, no chain). Sound, but it only protects an **exit** —
  which this protocol does not have.

## Correction of an earlier factual error

An earlier draft described DHT-exit abuse as "announce flooding." Wrong on two counts.
First, this protocol has no exit at all. Second, even the fork's internal DHT-request
handling is typed and bounded: `DHT_EXIT_ORIGIN_SERVICE_POLICY` is the first four entries
of `EXIT_ORIGIN_SERVICE_POLICY` (`lib/private/exit-policy.js`) — **immutable/mutable
get/put only** (`M3_MESSAGE_ID.IMMUTABLE_GET_V1 0x0120 … MUTABLE_PUT_V1 0x0123`).
`announce` is a separate `PRIVATE_ANNOUNCE`/private-records capability, not part of that
policy. (A private endpoint using the DHT via a route is using the DHT _itself_, staying
inside the network — not exiting it.)

## If a separate VPN/exit service is ever built

That would be a **different protocol**, not an extension of this one. It would introduce
external attribution (the exit's address answering for others' traffic) and anonymous
proxying to third parties — and _there_ anonymous admission earns its keep, via VOPRF
tokens on the exit reservation path (issuer-key + relay-local nullifiers), never on plain
circuit relay, and never RLN/Autobase-membership. Out of scope here; recorded so the
analysis is not lost.

## Non-goals

No admission machinery ships. No exit/egress. No chain, no token economics, no
deanonymization mechanism. Core private routing (guards, circuits, cells) already provides
the privacy for a closed peer network; admission was an imported anonymity-network add-on
this protocol does not warrant.
