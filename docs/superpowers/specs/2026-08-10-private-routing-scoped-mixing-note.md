# Private Routing: Scoped Mixing + Cover Traffic (Candidate Gate B — forward note)

**Status:** FORWARD-LOOKING / RESEARCH-GRADE — not a spec for current code, and the last
of the four gates by priority. Captured so the design constraints are on record; depends
on Gate C (decoupled DATAGRAM replies) and composes with, does not precede, A and C.
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
- Requires Gate C first: SURB-based DATAGRAM replies are timing-decoupled from the forward
  request, which is what makes delaying the reply leg possible without stalling the
  forward path. Mixing a reply that is bound to a live correlated-reply deadline is not
  possible.
- External-nullifier / epoch choices in Gate A must compose with mix epochs (named in the
  A spec's open questions), so RLN admission and mix delay do not fight over timing.

## Why not now

No mixing scheduler exists, and the property is only meaningful once A (so the mix relays
are not an open abuse proxy) and C (so replies are decoupled) are in place. Sequencing is
A → C → D → B. This note records the constraints so B is designed compatibly rather than
retrofitted.

## Acceptance (for the future gate)

- Mix delay/reorder + cover apply to CONTROL/DATAGRAM only; STREAM latency is unchanged
  and measured to prove it.
- A passive observer at a single relay cannot pair CONTROL/DATAGRAM senders with receivers
  by timing/volume within the mixed set.
- Cover traffic is a per-node-class policy, off by default on mobile.
- No change to the E2E guarantee, guard pinning, or path selection; composes with A's
  epochs and C's SURBs.

## Non-goals

Does not defeat an adversary who controls the entire path (guard+exit collusion remains
out of scope even with mixing at scale limits). No economic layer. Not required for the
A/C hardening to ship.
