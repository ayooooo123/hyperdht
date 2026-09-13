# Private Routing: Scoped Mixing + Cover Traffic (Candidate Gate B — forward note)

**Status:** DEFERRED — opt-in high-anonymity ("mixnet") mode **beyond** the current
low-latency routing target. Not scheduled. Current Gate C supplies single-use
replies, not independently timed/mixed routes; B requires a separate reviewed
scheduling and lifetime design and must never touch the STREAM fast path.
**Date:** 2026-08-10
**Relates to:** [`private-routing-v1.md`](../../private-routing-v1.md) (`Out of scope for
v1`: global passive observer, guard+exit timing correlation, constant-rate cover traffic
esp. mobile) and [`private-routing-logos-lessons.md`](../../private-routing-logos-lessons.md) item **B**.
**Prior art:** Loopix / Nym (Poisson mix delays, loop + drop cover traffic).

## The property this buys (and its cost)

v1 is a low-latency onion-circuit design; it explicitly excludes resistance to a global
passive observer and to guard+exit timing correlation. No amount of the current design
closes those — they require **mixing**: relays delaying and reordering traffic plus cover
traffic to keep the plausible-sender set large. This is the expensive, research-grade
property, and it trades latency and bandwidth for unlinkability. It must never be applied
to latency-sensitive bulk flows (the CDN corollary: mix the signaling, not the payload).

## Grounding

- Cell classes already separate concerns: `CELL_CLASS = { CONTROL: 0, STREAM: 1,
DATAGRAM: 2 }` (`lib/private/protocol.js:133`). This split is the lever.
- The relay forwarding scheduler is `RelayService` (`lib/private/relay-service.js`):
  `trySend` queues per circuit, `state.fair` is a FIFO fair-queue across circuits. Any
  mix delay/reorder would attach here, at the relay's dequeue step — not in the crypto or
  the initiator.

## The constraint (for the future gate)

- Apply Poisson mix delay + cover traffic **only to `CONTROL` and `DATAGRAM`** classes.
  **Never `STREAM`** — stream latency must stay intact.
- Cover traffic (Loopix loop + drop messages) defaulted **off on mobile** (v1 refuses
  constant-rate cover there); a policy knob per node class.
- Compose with Gate C's single-use replies without assuming they are independent
  of the live route or query deadline. The current return path reuses the route's
  own reverse relays; safe delay/reorder requires a separately reviewed lifetime
  and capacity contract.
- Gate A is dropped. RLN proofs, admission nullifiers, and membership epochs are
  not dependencies of this research.

## Why not now

No mixing scheduler or cover-traffic policy exists. Gate C/D implementation does
not close B's timing/volume threat model, scheduling, or latency questions.
Gate A is not a prerequisite. See the
[current implementation and open gates](../../private-routing-migration.md#current-implementation)
instead of the superseded A → C → D → B sequence.

## Acceptance (for the future gate)

- Mix delay/reorder + cover apply to CONTROL/DATAGRAM only; STREAM latency is unchanged
  and measured to prove it.
- A passive observer at a single relay cannot pair CONTROL/DATAGRAM senders with receivers
  by timing/volume within the mixed set.
- Cover traffic is a per-node-class policy, off by default on mobile.
- No change to the E2E guarantee or guard pinning; a reviewed design must compose
  with route lifetimes and Gate C's one-use SURBs.

## Non-goals

Does not defeat an adversary who controls the entire path (guard+exit collusion remains
out of scope even with mixing at scale limits). No economic layer. Not required for the
experimental C/D implementation to ship.
