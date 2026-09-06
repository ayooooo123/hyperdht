# Branch liveness: design for KI-10's second half

**Status: historical proposal; its lease-only premise is superseded.** Written
against 919f822, with the KI-10 pump-halt fix already present. L0 landed; L1/L2
were not ratified and are not authorized by this document.

The accepted native blackhole gate now identifies an existing
`LinkControlSession`: authenticated hop-local PING/PONG every 500ms and closure
after 1,500ms without accepted activity. `UdxCellEndpoint.installLinkControl`
already installs it on live adjacencies. The eleven-process scenario exercises
the native socket → M3 → controller → RouteManager loss path without calling a
synthetic destroy. Both healthy branches survive application silence; a
blackholed lookup branch is replaced while its healthy sibling is preserved.
See [current KI-10 status](private-routing-migration.md#ki-10-native-blackhole-detection-and-refused-loss-redelivery).

The measurements and proposed alternatives below remain historical evidence,
not a current implementation plan. In particular, the missing-trigger claim in
§1 and the missing-blackhole-harness claim in §6 are no longer true. A new
keepalive would duplicate existing traffic rather than fill an absent detector.
Changing that traffic or adding wire-level reliable branch-loss delivery still
requires its own protocol and privacy review. KI-10 now retains already-received
local loss reports on their published branch generation and redelivers them
after rotation. That local recovery adds no protocol traffic or heartbeat.

## 1. A premise in the brief is false, and it removes the "free half"

The brief for this design says endpoints already observe UDX stream close and error
events on the physical channel and do not use them, so wiring them would be a free fix
covering process death. That came from a scout map. I tried to confirm it and it does not
hold. Three measurements:

- **There is no per-peer stream.** Cells ride one UDX **datagram socket** per endpoint:
  `udx.createSocket()` at `udx-cell-endpoint.js:1428`, sends are
  `socket.send(packet, port, host)` at `:950` and `:2177`, and the only listeners are
  `socket.on('message', ...)` and `socket.on('error', ...)` at `:1520-1521`. A datagram
  socket has no per-peer connection state, so there is no per-peer close event to wire.
- **`socket.on('error')` is endpoint-wide, not peer-scoped.** Its handler is
  `state.onError = () => { void this.close() }` at `:1517-1519`: it closes the whole
  endpoint and every route on it. It cannot attribute a failure to one adjacency, so
  trusting it would turn any transient socket error into a total teardown.
- **`UDX_LINK_CLOSE` is not an event.** It is a bare `Symbol` (`udx-adapter.js:10`)
  invoked as a local method call from `udx-cell-endpoint.js:562` and
  `link-bootstrap-session.js:206`. `udx-adapter.js` exposes no emitter surface at all.

The physical-loss chain itself is real and **already fully wired**, which is the part the
scout got right in spirit and wrong in mechanism: `udx-cell-endpoint.js:672` fires the
sink registered at `m3-adjacency-runtime.js:2678`, which reaches the controller sink at
`private-routing-controller.js:519`, which calls `issueRouteManagerBranchPhysicalLoss`
and lands on `reportRouteManagerBranchLoss` (`route-manager.js:1263`). Nothing is unused.
What is missing is a **trigger**: I audited every `invalidateRecord` call site
(`udx-cell-endpoint.js:665, 899, 1618, 1652, 1655, 1668, 1818, 1843, 1911, 3296, 3602`)
and every `closeRecord` call site in `topology-grant.js`, and all of them are local —
grant `'expired'` (`:667, 687, 691, 843, 1022`), `'revoked'` (`:928`), local setup throw,
or owner-initiated close. **Not one is driven by a peer's state or by an inbound packet.**

Two consequences that shape everything below:

1. The gap is narrower than "notifications are lossy" but wider than "one signal is
   unwired". On silent death **no node anywhere forms the intent to notify**:
   `stopAfterFailure` (`m3-adjacency-runtime.js:1916`) is reached only from a thrown
   error in the relay loop (`:1993-1995`), and a dead neighbour makes
   `await source.physicalChannel.receive()` at `:1942` never settle. So
   `emitBranchDestroyUpstream` (`:1906`) is never called. Retransmitting a notification
   nobody generates fixes nothing.
2. **Process kill is not free either.** With a datagram socket, a killed peer yields at
   best an ICMP that this stack cannot attribute to an adjacency and whose only handler
   closes the endpoint. Graceful close is already covered — that is exactly what the
   existing local chain does. So the free/expensive split the brief asks for is real and
   worth keeping, but the free half is **not** a stream event. It is §2.

## 2. FREE HALF — enforce the deadline that is already on the wire (L0)

**Status: ratified and landed in this pass, with tests.** The rest of this file is design.

**Amendment, after KI-15.** The field this section calls `absoluteDeadlineMs` no longer
exists. The wire now carries `operationBudgetMs`, a relative duration, and each host
derives its own absolute deadline from its own clock; the endpoint's local deadline travels
as the `operationDeadlineMs` request option and is never encoded. L0 as landed is unchanged
in behaviour - the endpoint still arms and enforces its own deadline - but read every
`absoluteDeadlineMs` below as the endpoint-local deadline derived from that budget.

Every routed request already carries `absoluteDeadlineMs`. The **exit** enforces it
(`dht-exit-io.js:519-521`). The endpoint only _validates_ it once at admission,
`live-route-authority.js:668`, captures `started` at `:672`, and then waits forever: the
receive loop at `:715-721` awaits `receiveReservedM3RouteFrame` with no deadline. The
endpoint sets a deadline, tells the exit about it, and does not hold itself to it.

The recovery path is also already there and already wired to the adjacent failure mode:
`reportOwnedRouteFailure` (`:624`) calls `reportRouteManagerBranchLoss`, and it is
invoked from both throw sites, `:705` (send) and `:723` (receive). Only the timeout arm
is missing.

**Change:** add the deadline as a third racer to the existing
`Promise.race([run, cancellation])` at `:798`, using the already-injected
`state.monotonicNow()`; on expiry call the existing `operation.cancel(...)` (`:811`) and
`reportOwnedRouteFailure(state, BRANCH_CLASS.LOOKUP)`. Needs `schedule`/`cancelScheduled`
injected into this module the way the M3 authority already takes them
(`m3-adjacency-runtime.js:1426`). Lands in `lib/private/live-route-authority.js`, which
no one in this batch owns.

- **What detects:** an operation that outlives its own already-negotiated deadline.
- **Who detects, who acts:** the endpoint does both. Item 3 of the brief — getting news
  past a dead hop — **does not arise**, because the detector is the party that must act.
- **Traffic added: none. New timing signal: none.** The deadline was already on the wire
  and already enforced by the exit, so a KI-1 observer learns nothing new. Zero privacy
  cost, and this is the only layer I would land without a sub-gate.
- **False positive:** a slow-but-alive route is declared lost at its own stated deadline.
  Cost is one rotation. `reportRouteManagerBranchLoss` is idempotent — it returns false on
  an already-lost or non-`READY` branch (`route-manager.js:1266-1269`).
- **Limit, stated plainly:** L0 detects a dead hop only while an operation is
  outstanding. It does not detect death of an idle branch. That is deliberate: KI-10's
  harm is "routing into a black hole", and an idle branch has no traffic to lose, so the
  cost of not knowing while idle is latency on next use. L0 converts an unbounded hang
  into a bounded failure plus immediate rotation, for free.

## 3. EXPENSIVE HALF — silent death of an idle branch (L1), and it needs a protocol change

`idleTimeoutMs` is **already negotiated and signed** at every layer: the relay's signed
advertisement (`relay-capability.js:72`), admitted limits (`guard-link.js:507-563`,
clamped `Math.min(decoded.idleTimeoutMs, 5_000)` at `guard-lease.js:474`), tail-control
requested/advertised limits (`tail-control.js:300-342, 761`), default `5_000`
(`route-extension.js:22`), and the payload-parameter allowlist (`link-parameters.js:203`).
Every one of ~40 references is encode, decode, validate, negotiate, or compare.
**Nothing schedules anything off it.** Both sides agree an idle timeout and both ignore it.

It was rational to leave it unenforced, and this is the crux: with nothing to reset the
timer, enforcing a 5s idle timeout would destroy every healthy idle branch within 5s. The
timeout and a keepalive have to land together or not at all.

**Change:** each adjacent pair — and only adjacent pairs — enforces its own negotiated
`idleTimeoutMs`, reset by **any** cell in either direction. On expiry the local side
enters the existing `stopAfterFailure(err, downstreamFailure)` path
(`m3-adjacency-runtime.js:1916`), which for a relay whose downstream died already emits
`BRANCH_DESTROY` upstream (`:1906-1913, :1926`). No new recovery code. Resetting the timer
without application traffic requires **one new frame**: a hop-local keepalive on
`CELL_CLASS.CONTROL`, sent only when the adjacency is idle, consumed by the neighbour and
**never forwarded**.

- **Who detects:** each adjacent pair, independently. **Who acts:** the endpoint, reached
  by the existing hop-by-hop `BRANCH_DESTROY` relay (`:1970-1988`), which now works
  because only the far side is dead and the pump halt is fixed.
- **Why `CONTROL`:** it is already adjacency-scoped, not route-scoped — `CONTROL` carries
  generation `0` while other classes carry the route generation
  (`udx-cell-endpoint.js:441, 453-454`). A `CONTROL` keepalive is structurally hop-local.
- **Why it must be consumed, not forwarded:** the relay loop currently forwards `CONTROL`
  (`:1947, :1991`), so this needs a decode-and-consume arm beside `decodeBranchDestroy` at
  `:1970`. Forwarded end-to-end it would create a phase relationship between the two edges
  of one route — precisely a new KI-1 correlator.
- **Traffic:** at most one 1200-byte cell per direction per idle interval per adjacency,
  and **zero on a busy adjacency**, since real cells reset the timer. Size is not a
  correlator — `CELL_SIZE` is fixed at 1200 (`cell-codec.js:11`) — but the payload sizes
  are allowlisted to `[1200, 1146, 1101, 1100, 1073, 64]` (`link-parameters.js:207`), so
  the keepalive **must reuse an existing exact size**; a new size class would be a fresh
  fingerprint.
- **Privacy cost against KI-1, honestly:** today an idle route emits nothing, so a
  two-edge observer has nothing to correlate while idle. L1 gives a _single_-edge observer
  a persistent "this adjacency exists and is being kept alive" signal and makes route
  lifetime observable. That is **strictly more than KI-1 accepts**. Two mandatory
  mitigations: (a) period drawn per-adjacency from the injected `randomBytes`, e.g. uniform
  in `[0.5, 0.9] × idleTimeoutMs`, redrawn every interval — a fixed period is a
  fingerprint; (b) strictly hop-local, so the two edges of one route are independent random
  processes with no phase relation. **Residual exposure remains** and needs owner
  acceptance, not my assertion.
- **False-positive bound:** one lost UDP datagram must not tear down a route. Require
  **N=3 consecutive missed intervals** with period ≤ T/3. Cost when wrong is one early
  rotation — the same operation the lease performs on every branch roughly every 10s
  (`MAX_ROUTE_LIFETIME_MS = 15_000n`, `route-extension.js:16`, minus
  `BRANCH_ROTATION_LEAD_MS = 5_000n`, `route-manager.js:36`; that is also the arithmetic
  behind the measured 9656ms — a fault ~344ms into a branch's life). The real cost of a
  false positive is not the rotation but the **fresh relay draw**, since new hops mean new
  exposure.
- **Adversarial adjacent peer:** an adjacent relay **already** has an unbounded teardown
  primitive — it can call `emitBranchDestroyUpstream` at will (`:1906-1913`). L1 grants no
  new capability; it only lets a peer achieve the same by _omission_ (silence) as well as
  by action. So this is not a new DoS surface, but it does make the existing one cheaper to
  use deniably. Bounding it properly requires that a relay which repeatedly kills routes
  becomes less likely to be redrawn; whether `relay-candidate-directory.js` can express
  that is a question for **HopSelection**, not something I should assert.
  **That mitigation is currently blocked, and worse than blocked.** There is no fault-based
  exclusion in the directory at all — every `quarantine.set` is at seal time and
  equivocation-only — so a relay rotated off one branch is not merely still eligible for the
  sibling: in the eleven-role shape the exclusion set exhausts the pool and it is the only
  qualifying pair, so it is certain. Randomising selection does not touch this, because the
  question is not which qualifying hop is chosen but whether a just-failed hop is still
  qualifying. So for L1 the adversarial case is not "cheaper and deniable" but **rewarded**: a
  relay that wants to observe more of a route can get there by failing. L1 MUST NOT land
  before fault-based exclusion exists, and a loss signal has to carry a reason for that
  exclusion to be possible at all.
- **Plumbing cost, honestly:** the adjacency runtime does not carry the negotiated limits
  today — neither the runtime state (`m3-adjacency-runtime.js:1689-1707`) nor the install
  plan (`:2201-2210`) has a `limits` field. The signed value must be threaded in from
  `relay-capability`/`guard-link`. Real work, but threading an already-signed, already-agreed
  number, not negotiating a new one.

**L2, required with L1:** `emitBranchDestroyUpstream` sends **one** unacknowledged
datagram (`:1906-1913`) and each upstream relay forwards exactly one (`:1982`). One drop
loses the whole notification. Send k=3 jittered copies — which requires relays to tolerate
duplicates, because today a second copy hits `branchDestroyForwarded` at `:1975` and calls
`invalid()`, i.e. a duplicate is currently a protocol violation that kills the adjacency.

## 4. Verdict: L0 is an implementation fix; L1+L2 need a scoped sub-gate

L1 adds a frame type and L2 changes what a relay accepts on the wire. Both are
wire-observable changes to a signed, version-negotiated protocol, and L1 adds an exposure
KI-1 does not currently accept. **Recommendation: land L0 alone, now. Record L1+L2 as
sub-gate "branch liveness", gated on a protocol version bump and an explicit owner
acceptance of the idle-adjacency signal.** Do not smuggle L1 in as an implementation
detail, and do not bundle it with L0 — bundled, the free fix gets deferred with it.

## 5. Interaction with ExpirySignal's seam — a hazard my detector must not walk into

ExpirySignal is making refused **expiry** delivery renewable and leaving **loss** delivery
untouched: a loss refused while the other class rotates is dropped and never redelivered.
That means a detector that fires loss into a one-shot sink can have its output **silently
discarded**, recreating KI-10 one layer up. So any liveness detector needs the loss fact to
be **durable** — a flag on the branch or connection record, re-examined when the controller
returns to `READY` — reusing ExpirySignal's renew-at-refusal precedent. That is a design
call, and it is a prerequisite for L1, not an afterthought. L0 is less exposed but not
immune, and it must also tolerate **repeat deliveries**, since after ExpirySignal's change
one condition can produce more than one delivery attempt; `reportRouteManagerBranchLoss`
is already idempotent (`route-manager.js:1268`), which is what makes this safe.

## 6. Test strategy — nothing waits out a lease

Three tiers that answer different questions and do not substitute for one another.

1. **Unit, host aggregate.** The adjacency layer takes injected `wallNow`, `monotonicNow`,
   `schedule` and `cancelScheduled`, asserted as four separate capabilities by the existing
   test at `test/private/m3-adjacency-runtime.js:442-448`. The existing `fakeClock`
   (`:48-105`) has `fireNext()`, `setMonotonic()`, `pending()` and records every delay in
   `clock.delays`. So the idle timer fires instantly with no wall-clock wait, and the
   **privacy property is directly assertable**: arm the keepalive many times and assert the
   delays are not all equal and all lie in the intended range. A fixed period then fails a
   test instead of surviving review. Same harness covers the N-miss bound and that any
   inbound cell resets the timer.
2. **L0 unit.** Deadline expiry must produce both a cancelled operation **and** a
   `BranchLoss` sink event. Assert both; the second is the whole point.
3. **Container process gates (`process:node`, `process:bare`) — required.** The host
   aggregate does not contain the eleven-role scenarios at all, so a live-path change is
   unverified until these run — however green the aggregate is. Stated as a property on
   purpose: a total pinned here would rot on any sibling slice's edit, with nothing about
   this file to prompt re-checking it.

**Blocking gap for tier 3: the rehearsal cannot currently produce silent death.** Both
fault verbs are _local_ destroys — `faultIncomingPhysicalLink` destroys the local incoming
channel and `faultOutgoingPhysicalLink` closes the local link session, whose own comment
says it "makes this relay emit BRANCH_DESTROY" (`test/private/process/wire-services.js:773-791`),
reached through the single `rotate` verb (`role-runner.js:946-961`). Both produce exactly
the clean notification this design exists to survive the absence of.

Required addition: a **`blackhole`** verb that drops route cells in both directions while
leaving every local object alive and every socket bound — **not** a `destroy()` or
`faultLink()`. Measured obstacle, which rules out the obvious implementation: a drop flag on
the pre-install physical channel CANNOT work, because the M3 install replaces the taken
issuer with its own transfer object. That is the same reason destroying the issuer is a no-op
in `faultOutgoingPhysicalLink`, as its own comment records. Silent death therefore has to be
injected below that, at the UDX layer via `TEST_ONLY_UDX_ADAPTER_ISSUER`
(`udx-cell-endpoint.js:122`), installed from role start so the flag is consultable per packet
when the verb arrives later. This is a follow-up, not a one-line addition. Falsification test: with
`blackhole` on `lookup-middle-a` and this design reverted, the endpoint must learn nothing
until the lease (~10s, reproducing the 9656ms); with it applied, the endpoint must report
`BranchLoss` within the negotiated idle bound. **If the first half does not reproduce, the
verb is not producing silent death and the test is worthless.** `wire-services.js` and
`role-runner.js` are unowned; the suite that would drive the verb is
`live-process-suite.js`, owned by TeardownRace, so that hand-off needs coordinating.
