# Private Routing Gate 3A / Gate 3B1 Migration Record

## Status and scope

This record describes the experimental, internal Gate 3A substrate and the owner-approved Gate 3B1 implementation through Task 17 in this fork. It is not a public API or a production anonymity surface. Gate 3A combines the generic DHT-RPC request-transport seam established in Gate 2 with deterministic protocol primitives, an address-free internal adapter, and an in-process fake topology. Gate 3B1 adds production-code native routing owners behind package-private capabilities.

Direct mode remains the only public behavior. Gate 3B1 Task 15 has a package-private required-mode controller, authenticated native route authority, routed immutable-get request/reply path, rotation, suspension, and teardown; Tasks 16 and 17 add test-only process isolation and prove that path live across eleven separate Node or Bare role processes over native UDX, and, on Linux, with every role in its own network namespace under packet capture. The root package still exposes no private-routing constructor or user-selectable required mode. A post-readiness packet-capture proof now exists for the specific properties tabulated in [Task 17 wire-level privacy evidence](#gate-3b1-task-17-wire-level-privacy-evidence). It is not a general anonymity claim: a global passive observer and timing correlation by colluding guards and exits are out of scope for v1, no cover traffic exists, and these tests do not establish suitability for protecting users.

The canonical design remains [Private Routing Protocol v1](private-routing-v1.md).
Accepted limitations that are not scheduled for repair are tracked under
[Known issues](#known-issues); the load-bearing one is
[KI-1: routes are correlatable by timing and volume](#ki-1-routes-are-correlatable-by-timing-and-volume).

The owner-approved Gate 3B1 Task 5 authenticated-M3 transport, Task 6
tail-control lifetime/ownership amendment, and Tasks 7–17 live-route lifecycle
are incorporated into the canonical design documents and implemented
internally in this fork. This remains a package-private compatibility slice: it
adds no root public constructor, export, user-selectable required mode, or
anonymity claim, although its internal path uses the production UDX, relay,
final-exit, and DHT-exit owners rather than a structural or fake transport.

### Continuation checkpoint — 2026-09-05

Reviewed the accepted branch through `6468028`, the current live owners, gate
scripts, and prior review records. The next completed work is verification
hardening, not a new public routing feature:

- The local `all` runner now includes normal and reversed candidate order under
  both Node and Bare role runtimes, like CI.
  Each process gate explicitly sets its order. Running all four process gates
  with the caller exporting either `normal` or `reverse` produced
  `normal, normal, reverse, reverse`; all eight runs passed 136 assertions each.
- The blackhole scenario uses monotonic elapsed time and checks both healthy
  idle generations plus preservation of the announce generation during lookup
  replacement.
- An isolated mutation that suppresses `runLiveness` timeout closure, while
  leaving PING scheduling intact, fails the native scenario with
  `PROCESS_COMMAND_DEADLINE` after the blackhole is armed. The unmodified
  scenario passes. Lease-only recovery cannot substitute for the native detector.
- KI-10 and the historical branch-liveness proposal now name the existing
  detector. KI-14's headline now reflects preferred-tier selection on all three
  construction paths, without implying hard exclusion in small pools.
- Fork CI exposed a guard authentication failure at resume. Preserved source
  stacks and deterministic signed-message regressions identified a clock-skew
  rejection in both handshake completion paths. KI-4 below records the fix:
  order peer timestamps against signed bounds, not another host's wall clock.

KI-10 refused-loss redelivery is now implemented: loss stays on its published
branch, physical and live-IO reports carry that generation, and a refused
controller wakeup is restored for delivery after the active rotation completes.
The focused regression proves both refusal paths without advancing the lease
clock, plus rejection of retired registrations and retiring-branch safety.

The active, experimental SURB reference now has wire-compatible key cleanup,
payload bounds, canonical X25519 public-key validation, and aggregate test
registration. A direct probe reproduced high-bit encoding malleability before
the fix and rejects it afterward. A four-hop fault probe also checks key
erasure across 115 injected native-hash failures. The deterministic fixture
still passes. This hardening does not activate Gate C: one-use ownership,
authenticated epoch and reply-mode binding, and production DATAGRAM integration
remain separate design/review work. See the
[reference hardening record](superpowers/specs/2026-08-10-private-routing-surb-construction-design.md#reference-hardening--2026-09-05).

After the advisory fixes and approved teardown classification, all eight local
Linux gates pass. Node passes **975 tests / 19,051 assertions**; Bare passes
**932 / 18,923**. All four normal/reverse process legs pass 136 assertions;
namespace projection passes 27; live namespace capture passes 146 with raw
DROP zero and classified ICMP zero. A delayed-close probe passes with three
raw drops and three classified replies. An injected ICMP echo fails as required.
See [KI-16](#ki-16-ordered-udp-shutdown-can-produce-kernel-icmp-drops).
These local container results do not replace fork-native CI or real NAT-host
evidence.

Remaining work, in dependency order:

1. **KI-13 production NAT traversal:** design and review the production owner
   path for same-socket reflection, signed plan creation/distribution, topology
   and run binding, replay limits, and mapping lifetime. Then prove authenticated
   route startup across real NAT'd hosts without harness pre-punching. The
   isolated NAT branch's positive worker report is not acceptance evidence.
2. **Gate C and private-presence/Gate D:** meet their protocol and cryptographic
   review gates, then integrate the actual reply and record paths. The reverted
   and rejected branches are not completed implementations. Gate D still needs
   a vetted native scalar multiplication path for full blinded-key signing.
3. **Complete Gate 3B:** remaining DHT commands, private presence, and peer
   streams need reviewed end-to-end implementations. Public required mode must
   remain disabled until all aggregate criteria below pass together in CI.
4. **Consumer integration:** Hyperswarm, mobile, and PearTube follow the public
   controller gate. Real-device and real-network evidence cannot be replaced by
   the local container gates.

KI-1 timing/volume correlation and KI-5 operator diversity remain explicit
limits. This checkpoint adds no production constructor, protocol, or anonymity
claim. Current local measurements are in the Task 17 table below.

### Continuation checkpoint — 2026-09-06

Two internal architecture reviews (KI-13 production NAT ownership; Gate C SURB
lifecycle) and one dependency build were completed, and the two reviewed
experimental slices were implemented. Neither review is external
cryptographic review, and nothing here enables public required mode.

**KI-13 production NAT ownership.** The review found that active production
code creates no topology grants (`signTopologyGrant` is only called by the
process fixture), that the archived `924fd55` proposal inherits a test trust
root and reflects through a raw socket that is closed and rebound, and that a
general plan signer accepting caller tuples would be a UDP redirection
service. Seat decisions, recorded here for owner review: (D1) a plan is signed
by both adjacent identities over one canonical body, with no central signer;
(D2) plans travel only over an existing authenticated pre-link control path,
otherwise the adjacency fails closed; (D3) IPv4 and IPv6 through the topology
address codec; (D4) a successful punch never authorizes a link or readiness;
(D5) plan validity is bounded by the link deadline and both reflection claims,
at most 15 s; (D6) test topology grants stay test-only. Implemented:
`lib/private/nat-reflect.js` (probe/observation codec and endpoint-bound
reflection claims; two distinct identity-pinned reflectors must agree; never
holds a socket), `lib/private/nat-punch-plan.js` (canonical plan codec,
bilateral sign/verify, fixed punch-profile registry), a shared strict parser
in `dht-exit-wire.js`, and package-private
`createNatTraversalAuthority`/`reflectNatEndpoint`/`armNatPunch` on
`UdxCellEndpoint`. `armNatPunch` compares the plan against the live link
handle (grant digest, epoch, run, identities, roles, both tuples, expiry), the
live reflection claim for this socket generation, and a plan-ID tombstone
before charging or allocating a packet. Punch bytes are demultiplexed before
bootstrap parsing and never reach `BootstrapRequestTable`. Guard pinning and
endpoint close destroy all NAT state. `LinkBootstrapSession` consumes one
opaque attempt, arms its deadline first, starts LINK CREATE after the first
owned send, and cancels the attempt on OPEN, failure, close, and invalidation.
Focused tests: `nat-reflect` 9/17, `nat-punch-plan` 7/25, `nat-traversal`
6/33; the owned-file suites are unchanged. Review scenarios 19 and 27–29 need
live processes and are not covered locally. Not implemented: the production
plan producer/distributor over a pre-link channel, and the real-NAT run with
the harness punch disabled. KI-13 therefore remains open.

**Gate C SURB amendment.** Implemented in `lib/private/surb.js` as recorded in
the [design spec](superpowers/specs/2026-08-10-private-routing-surb-construction-design.md#ownership-amendment--2026-09-06):
per-hop context-bound key schedule with no context bytes on the wire, owned
one-use authorities, atomic in-hop replay admission, and an authenticated inner
reply envelope. 31 tests / 115 assertions. Reply-mode selection in the routed
request, batch framing, the 492-byte fragment profile, and exit/initiator
integration remain unimplemented and human-gated.

**Gate D dependency.** `crypto_core_ed25519_scalar_mul` was added to a local
checkout of `holepunchto/sodium-native` at `f566427` (npm 5.1.0) as a direct
libsodium binding with the upstream wrapper conventions (local commit
`5c10460`, patch at `/tmp/hyperdht-sodium-scalar-mul.patch`). Built with
`bare-make` for darwin-arm64; the full upstream suite passes under Node
(6,292 assertions) and Bare (6,282), plus independent checks
$(L-1)^2 \equiv 1$ and $(L-1)\cdot 2 \equiv L-2 \pmod L$. Not yet done: a
fork commit or release, prebuilds for the Linux gate image, the
`sodium-universal` override, and the record-transcript approval that the
design handoff below still requires. No JavaScript scalar arithmetic was
introduced.

**Routed immutable-put and mutable get/put (Gate 3B criterion 4, partial).**
An internal review (`glm-5.3`, full text at
`/tmp/hyperdht-routed-dht-commands-review.md`) confirmed that the frozen
`COMMANDS` ranges in `routed-dht.js` fit only fixed-width bodies:
`MUTABLE_GET_V1` is `target[32] || seq u64`; `IMMUTABLE_PUT_V1` is
`token[32] || target[32] || version u8 || len u16 || value[0..1023]`;
`MUTABLE_PUT_V1` adds `publicKey[32] || seq u64` before the value and a
64-byte signature after it, so the required-mode mutable value cap is
**895 bytes** (direct mode allows more; this asymmetry is now the contract).
Seat decisions taken as the review defaults: put replies are bare one-byte
acks with no token or closer nodes (209-byte reply, amplification 0); the exit
maps upstream `SEQ_REUSED`/`SEQ_TOO_LOW` to `ROUTED_ERROR.RECORD_CONFLICT` and
the controller surfaces `ERR_RECORD_CONFLICT`; no exit-side token state or
hash checks (the upstream node verifies signatures and hashes); a
refresh-capable `mutableGet` queries on the announce branch so its commit token
comes from the exit that will send the put; pure reads stay on the lookup
branch. Implemented across `dht-command-policy.js`, `query-context.js`,
`routed-dht.js` (per-command reply profiles and `targetOf`),
`opaque-destination.js` (announce referrals), `routed-dht-io.js`,
`live-route-authority.js`, `dht-exit-wire.js`, `dht-exit-destination-table.js`,
`dht-exit-io.js`, and `PrivateRoutingController.immutablePut/mutableGet/
mutablePut` with generation pinning and one restart on rotation. `findPeer`,
`lookup`, `announce`, `unannounce`, and raw `query` still fail closed. New
suites: `dht-exit-put` 3/24, `dht-exit-mutable-get` 3/18,
`live-mutable-and-put` 3/16. Not covered: a live announce-branch put end to
end (the in-process harness does not deliver announce seed frames), and the
lying-exit limitation stays a documented v1 limit.

After formatting, the eight local Linux gates were run on the combined tree.
Node aggregate passes **1,019 tests / 19,244 assertions**; Bare passes
**976 / 19,116**. Process legs pass 136 assertions each; namespace projection
27; live namespace capture 146 with raw DROP zero. One earlier
`process:bare:reverse` run failed with `ERR_PRIVATE_GUARD_UNAVAILABLE` from
the bootstrap deadline at 6.1 s while the container was also finishing the
aggregate; five immediate reruns of that gate, one of `process:bare`, and the
final full pass all succeeded. The no-punch bootstrap path is unchanged by
this checkpoint, so the failure is recorded as a load-related deadline expiry,
not explained. It should be watched in fork CI.

Remaining work is unchanged in shape: KI-13 plan distribution and real-NAT
proof; Gate C integration and human review; Gate D transcript approval,
dependency pin, and implementation; remaining DHT commands, presence, peer
streams; consumer integration.

### Continuation checkpoint — 2026-09-06, KI-13 plan distribution

The production plan producer and distributor were implemented after mapping the
real link lifecycle rather than the review packet's assumed one. Three facts
decided the shape. Topology grants are minted only by the process fixture and
reach roles over the coordinator control channel; no production owner mints
them yet. The endpoint opens its guard link inside `bootstrap-io.js` only after
a direct CAPS_QUERY / ACTIVE_CHALLENGE exchange with the guard, so any punch
for that edge must precede the FIRST bootstrap contact, not LINK CREATE.
Guard→middle and middle→exit links are dialed cold from
`wire-services.dial()` at route build and at every rotation, and a plan is
valid for at most 15 s, so no pre-negotiated plan can serve them.

Seat decisions, recorded for owner review beside D1–D6:

- **D7.** Endpoint↔guard is the only production-punched edge. Its plan
  travels over the topology owner's channel, the same authenticated channel
  that carries the topology grant; in the harness that is the coordinator,
  which relays opaque bytes and never signs. Relay↔relay cold dials have no
  pre-link channel, so under D2 a NAT'd middle or exit stays unsupported and
  fails closed. The harness keeps its own pre-punch for relay pairs and labels
  it test topology plumbing.
- **D8.** The endpoint's punch precedes its first bootstrap contact. The
  attempt is armed against a link handle the role authorizes from the same
  grant in its own `LinkDirectory`, runs standalone, and the controller starts
  only after the first owned punch send. OPEN transfers nothing from the punch.
- **D9.** Four-step bilateral exchange: `offerNatPunch` (initiator: header,
  its side, responder claim digest and nonce zero) → `counterNatPunch`
  (responder fills its claim digest and nonce, may only LOWER `expiresAt`,
  signs) → `completeNatPunch` (initiator checks the counter differs from its
  offer in exactly those fields, verifies the responder signature, signs, arms
  through `armNatPunch`) → `acceptNatPunch` (responder checks the plan's
  unsigned bytes and its own signature byte-for-byte, arms through
  `armNatPunch`, which verifies the initiator signature and every binding).

Implemented in `lib/private`: strict offer/counter codecs and the
allowed-difference comparator in `nat-punch-plan.js`; the four functions above
plus single-use pending tokens (bounded by `DEFAULT_MAX_NAT_PLANS`, expiring at
the offer window, revoked on guard pin, endpoint close, authority destroy and
link-handle close) in `udx-cell-endpoint.js`; the NAT authority now retains an
owned copy of the identity secret key and clears it on every revocation path;
`bindReflectedEndpointClaim` requires explicit reflectors (the hard-coded
`203.0.113.x` defaults were a production bypass and are gone); and
`prepareEndpointNatTraversal` in `endpoint-bootstrap-authority.js`, which binds
the endpoint's own socket before the controller starts, creates the NAT
authority on it from a second identity secret capability, and reflects.

Harness: optional `natTraversal.reflectors` projection field, guard
`endpointGrant`, control-channel commands `nat-reflect|offer|counter|plan|arm|start`
and events `nat-reflected|offer|counter|plan|armed|started`, coordinator
helpers, role-runner handlers, and the suite sequence guard reflect → endpoint
reflect → offer → counter → plan → arm → guard start → endpoint start →
endpoint activate. `nat-reflected` carries one `observed` string because the
leak oracle refuses any event field named `host` or `port`. `scripts/live-route.sh -p`
(`REMOTE_PEER_PRODUCTION_ENDPOINT_PUNCH=1`) removes the endpoint from the
harness punch cross-product and passes the two public bootstrap reflectors,
labelled by `hash(host:port)`. New local gates `process:node:punch` and
`process:bare:punch` run the portable loopback scenario with dht-seed and
dht-value as reflectors. Default runs send no NAT command and mint no NAT
projection field.

Evidence: `nat-negotiation` 11/19, `nat-traversal` 6/33, `process-codec`
21/416, `nat-control-messages` 2/49. `process:node:punch` passes 141/141: both
production reflections equal the minted tuples, the whole exchange took 33.7 ms
on loopback, both sides report a first owned punch send, at least one direction
crossed, and the endpoint then bootstrapped and completed the full lifecycle.
Loopback proves the frame path only.

First real-NAT dispatch, run
[34059354417](https://github.com/ayooooo123/hyperdht/actions/runs/34059354417),
all eleven roles on runners, `-p`: the harness punch matrix arrived on 96 of
117 directed pairs and every one of the 21 silent pairs involved
lookup-middle-b, which heard nothing from any role. Production reflection on
the final socket equalled the minted tuple on both NAT'd hosts (endpoint
`74.235.70.229:23569`, guard `135.119.236.51:32793`), so the close-and-rebind
hop preserved both mappings on those runners. The four-step exchange took
799.6 ms over the DHT control streams; both sides reported a first owned punch
send; the endpoint then bootstrapped to the guard, pinned it, and the first
routed immutable get was exact — with no harness punch on the endpoint's edge.
Two assertions failed. The crossing check read the counters immediately after
the first send, before the peer's packets could have crossed a real NAT; it now
reads them at the scenario tail. The blackhole rotation then missed the process
deadline; the only replacement middle was the role whose NAT admitted nobody,
which is consistent with the punch matrix but was not proven to be the cause.
The first `-p` drive also exposed a `live-route.sh` bug: an expanded word is
never an assignment prefix, so the flag is now exported.

Second dispatch, run
[34059905384](https://github.com/ayooooo123/hyperdht/actions/runs/34059905384),
on the corrected tree: this time the guard's runner and lookup-middle-b's
runner admitted nobody (punch matrix 77/117, every silent pair involving role 2
or role 5). The endpoint's production reflection again equalled its minted
tuple (`52.161.51.65:20489`), but the guard's did not: the probe socket had
been reflected at `48.217.251.100:10265` and the final socket, bound to the
same local port, was reflected at `:10267`. That is the close-and-rebind hop
the harness could never measure, measured: on that runner's NAT the mapping
did not survive the rebind, or the NAT allocates per socket. Production
behaved as designed — the guard's claim did not match its grant tuple, no plan
was offered, no punch byte was sent, and the run stopped at the reflection
assertion. Third dispatch, run
[34060254019](https://github.com/ayooooo123/hyperdht/actions/runs/34060254019):
the harness punch matrix arrived on 8 of 117 pairs and the run died in DHT
setup, before any production step. Three runs, three different outcomes from
runner placement alone; which runner draws a NAT that admits unsolicited peers
is not under the harness's control. The owner approved placing the guard on
the operator's machine (`-l 2`) on condition that its address never enters
this repository; the records below therefore name that host only as "the
operator host".

Fourth dispatch, run
[34061028552](https://github.com/ayooooo123/hyperdht/actions/runs/34061028552),
ten roles on runners and the guard on the operator host: harness punch matrix
117/117; production reflection equalled the minted tuple on the endpoint's
runner and on the operator host; the four-step exchange took 738.1 ms; both
sides made a first owned punch send; the endpoint bootstrapped through the
production-punched pair, pinned the guard, and the first routed immutable get
was exact; the initial routes, cancel, and healthy-silence checks all passed.
**That is the KI-13 real-NAT proof for the endpoint↔guard edge: bind once,
reflect the same socket, bilateral plan, punch from that socket, authenticated
link, no harness punch on that edge and no close-and-rebind after reflection.**
The run then failed at the blackhole rotation with `PROCESS_COMMAND_DEADLINE`,
as the first dispatch had. That was first read as loopback-tuned deadlines; the
later KI-17 diagnosis gives the likelier cause: the harness link service killed
every pre-armed standby accept five seconds after activation, and on runners
the punch exchange and real latency pushed the rotation past that. Fixed under
KI-17; not yet re-run remotely. A fifth
run with the coordinator's documented diagnostic overrides
(`PR_COMMAND_TIMEOUT_MS=20000`, `PR_SCENARIO_TIMEOUT_MS=120000`), run
[34061182110](https://github.com/ayooooo123/hyperdht/actions/runs/34061182110),
never reached the production steps: the runners' harness punch matrix arrived
on 10 of 117 pairs, as in the third run, and DHT setup failed. The remote
lifecycle after readiness — rotation under a blackhole across runners — is
therefore still unmeasured with the punched edge; it is a harness-deadline
question, not a NAT one. Dispatching stopped after the fifth run.

Two contract notes. The reflectors observe the endpoint's socket before guard
pinning; that is within the pre-guard exposure the security contract allows
for configured bootstrap contacts, but those sends bypass the bootstrap
exposure accounting, so the readiness report does not yet list them. The
reflector `identity32` is a label bound into the claim, not an authenticated
identity: dht-rpc pings are unauthenticated, and the claim's authority comes
from the socket owner observing agreement between two reflectors.

### Subagent design handoff — 2026-09-05

These are review requirements, not accepted replacement protocols:

- **Gate C:** make initiator ownership one-use and expiry-bound. Relay replay
  admission must be atomic, after header authentication and before wrapping.
  Remove manual replay-cache reset from the production contract. A local
  `{run, epoch}` label alone is not cryptographic binding: an old header must
  also fail under a new run or epoch. Bind that context through the accepted
  key/header contract; do not call a cache-only change sufficient.
- Authenticate the reply mode inside the inner request AEAD. A required SURB
  reply must never fall back to the correlated path. Each reply fragment needs
  an independent SURB; counter-based reuse is not the single-use construction.
  At the current 512-byte reference cap, a 20-byte fragment header leaves
  492 data bytes. The existing fragment encoder uses 1,053 data bytes, so it
  cannot be reused unchanged. A three-SURB request also needs a reviewed batch
  format and multi-cell carriage. Full-header reply overhead is 468 bytes;
  the 1,073-byte route payload leaves 605 bytes before any new envelope fields.
  This arithmetic does not approve a production cap.
- **Gate D:** the current native dependency lacks
  `crypto_core_ed25519_scalar_mul`. The
  [current npm release](https://registry.npmjs.org/sodium-native/latest) is
  `sodium-native@5.1.0`, which supports Node and Bare. The proposed dependency
  path is an upstream native binding to libsodium's scalar multiply, followed
  by a released version or approved commit and an explicit dependency pin.
  No JavaScript scalar arithmetic, substitute signer, codec shell, or
  permanently disabled implementation is an accepted substitute.
- Before Gate D implementation, approve the complete signed record transcript:
  version, type, epoch, revision, descriptor length, and tombstone scope/target.
  Verification must use the caller-derived expected blinded key, epoch, and
  storage key, not authority taken from the record itself. Overlap and rollback
  rules must be executable. The advisor's proposed schema and hash choices are
  not ratified, and external cryptographic review remains a human gate.

### Single-branch work collection — 2026-09-05

All related work is centralized on `private-routing-v1` in
`ayooooo123/hyperdht`. The accepted runtime remains active. Rejected and
unaccepted implementations are preserved under `research/private-routing/`,
not merged into `lib/private`. Preservation does not close their review gates.
The complete inventory covers all 33 local branch refs found at collection
time, both detached experiments, external handoff/workflow notes, and the
legacy Tor-transport history from the separate `source-hyperdht` checkout.
Original worktree commits are also retained as parents of an explicitly
archive-only merge. That merge keeps the accepted tree unchanged: it preserves
Git history without installing rejected implementations. Thus the one pushed
branch contains both the original commits and the reconstructable research
copies; separate remote feature branches are not required.

| Archive directory        | Preserved work                                              | Acceptance status                                                                                        |
| ------------------------ | ----------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `ki10-blackhole-history` | Original `5a53851` / `7aeee57` history                      | Tip tree equals accepted `6468028`; no second runtime merge is needed                                    |
| `pr50-history`           | Original six-commit PR #50 history through `ba1f87e`        | Tip tree equals accepted `c035cf8`; no second runtime merge is needed                                    |
| `production-nat`         | `924fd55` NAT work and preservation status                  | Unaccepted; production ownership and real NAT evidence remain required                                   |
| `presence-gate-d`        | `5c77a50` / `2ac6b64` presence work and rejection status    | Rejected: record-type authentication, trailing-zero handling, overlap, and integration remain unresolved |
| `gate-c-surb`            | SURB rewrite and `check_vectors.js`                         | Incomplete; checker needs absent `/tmp/surb_vectors.txt` and undefined relay `sec` fields                |
| `blackhole-isolation`    | Detached `ab818f9` blackhole/demotion source and tests      | Historical research only; generated `choose.log` and `hook.log` are excluded                             |
| `baseline`               | Detached `ab818f9` baseline demotion and diagnostic changes | Historical comparison only; not a merge candidate                                                        |
| `handoff`                | External handoff and two Task 6 workflow briefs             | Historical instructions, not current authority                                                           |

Each archive has a `manifest.json` with its exact base/head, status, changed
paths, and SHA-256 file hashes. `history.patch`, when present, preserves the
original commits in `git am` format. `working.patch`, when present, preserves
the pending tracked and approved untracked files. Neither patch changes the
active runtime merely by being stored here.

To continue an experiment, create a separate worktree at its manifest's
`base_commit`, apply `history.patch` with `git am`, then apply `working.patch`
with `git apply --index`. Skip whichever patch the manifest marks `null`.
For example, from the canonical checkout:

```sh
ARCHIVE="$PWD/research/private-routing/production-nat"
git worktree add --detach ../hyperdht-nat-study 6c307fa8edbd380be4ff9a6a1bce0c1fd926e903
git -C ../hyperdht-nat-study am "$ARCHIVE/history.patch"
git -C ../hyperdht-nat-study apply --index "$ARCHIVE/working.patch"
```

Verification reconstructed all eight archives in temporary worktrees. Every
original committed tree matched exactly, and all 55 final changed files
matched their SHA-256 records; live source files were also compared directly.
This proves preservation, not correctness of the rejected implementations.
The temporary verification worktrees were removed.

`research/private-routing/inventory.json` records every original local ref and
its location on the fork or in these archives. Other local routing branches
already match their fork refs. The second `projects/Hyperdht-private-routing`
checkout has no unique edits or commits. The clean `source-hyperdht` reference
tip `b329b8b` was already on the fork, but its four Tor-transport commits were
not reachable from the collected branch. A further archive-only merge retains
that tip without installing its files. The source checkout's disabled push
configuration is unchanged. This history is listed in `external_histories` in
the inventory and can be inspected directly with `git worktree add --detach`
at `b329b8b`; no duplicate patch archive is needed. The clean DHT-RPC dependency
tip `fe04496` is already on its own `ayooooo123/dht-rpc` fork and is not copied here.
The stale `/private/tmp` baseline worktree entry points to a missing directory;
the live detached experiments are preserved without pruning that entry.

## Known issues

### KI-1: routes are correlatable by timing and volume

**Status: accepted for v1. Not fixed, not scheduled in this gate.**

Every route cell is the same 1,200 bytes on every hop, so cell length is not a
correlator. Nothing else about the traffic shape is concealed: an observer of
two edges sees when each datagram was sent and how many there were, and the
route relays each cell promptly. An adversary who can watch both the
endpoint-to-guard edge and an exit-to-DHT edge can therefore link them by timing
and volume alone, without breaking any cryptography and without any protocol
error.

This is a property of the v1 design, not a defect in its implementation. v1
deliberately excludes
[a global passive observer, timing correlation by colluding guards and exits,
and constant-rate cover traffic](private-routing-v1.md#out-of-scope-for-v1),
because the padding, batching, or cover traffic that would address it costs
bandwidth and battery that v1 is not willing to spend, especially on mobile.

The
[Task 17 wire-level privacy evidence](#gate-3b1-task-17-wire-level-privacy-evidence)
is scoped accordingly: it proves what crossed which edge, never that two edges
cannot be linked. Any future claim of resistance to a two-edge observer requires
a wire-format change and its own sub-gate, and must not be inferred from the
current test results.

### KI-2: the eleven-role live scenarios only run on Linux

macOS and Windows refuse to bind the `127.64.x.1` role tuples without
per-address configuration, so the scenarios stop at the first bind with
`PROCESS_BIND_UNAVAILABLE` there.

They are therefore kept out of `test/private-routing.js`, which `test/all.js`
and `npm test` run on every platform, and are invoked from
`npm run test:private:process:node` and `npm run test:private:process:bare` in
the Linux CI job instead. Anything that binds a role tuple belongs in a
platform-gated script, never in the portable aggregate; putting it there turns
a known platform limit into a red build on macOS and Windows.

### KI-3: the namespace gates need privileged Linux

`npm run test:private:namespace` and `npm run test:private:namespace:live`
create network namespaces, veth pairs and iptables rules, and capture with
`tcpdump`. They require Linux with non-interactive root and skip elsewhere with
a stated reason. They are not part of the portable aggregate suite.

Both limits are limits of the host kernel, not of the gates, so a Linux
container satisfies them. `npm run test:private:linux-gates -- <gate ...>`
builds `docker/linux-gates.Dockerfile` and runs any of `aggregate:node`,
`aggregate:bare`, `process:node`, `process:bare`, `process:node:reverse`,
`process:bare:reverse`, `namespace`, `namespace:live`, or `all` in a privileged
container with the working tree bind-mounted. `all` includes both candidate
orders for both role runtimes, matching the Linux CI matrix. Explicit reverse
gates set their own candidate order even when the caller exports `normal`.
Dependencies live at `/node_modules` inside the image and a tmpfs shadows
`/app/node_modules`, so a host build for another platform is never loaded.
This gives a macOS or Windows workstation the same eight gates as Linux CI.
It does not replace that job: the
container shares the host kernel and its clock, so it is local evidence only,
and KI-4 timing behaviour still has to be judged on the runner.

Observed locally on macOS 25.5.0 arm64 with Docker 29.5.2 over Colima
(`linux/aarch64`), Node v22.23.2 in the image:

- `aggregate:node`: 876/876 tests, 18,106/18,106 assertions.
- `aggregate:bare`: 855/855 tests, 18,047/18,047 assertions.
- `process:node`: 1/1 test, 125/125 assertions.
- `process:bare`: 1/1 test, 125/125 assertions.
- `namespace`: 1/1 test, 27/27 assertions.
- `namespace:live`: 1/1 test, 135/135 assertions, marker datagrams 0,
  undecodable frames 0.

### KI-17: a routed get fails after a short idle following readiness

**Status: FIXED, two causes — one production, one harness. Found on the
unmodified scenario while placing the punch counters; not caused by NAT work.
The eleven-process gates now idle two seconds between readiness and the first
routed get, so the fix is defended by every process leg.**

Symptom. On the portable loopback `process:node` gate, a coordinator wait
between the endpoint's `ready` and the first `immutable-get` changed the
result: 1,000 ms passed; 2,000 ms failed the first get with
`ERR_PRIVACY_UNAVAILABLE`, meaning the routed query returned no value. A
pause of about 2.5 s after that get instead failed the blackhole rotation.

Production cause. `buildDhtExitOpenAuthorityMaterial` in
`final-exit-activation.js` set the DHT-exit open authority's
`absoluteDeadline` to `min(graceDeadline, localDeadline)`. The grace deadline
is OPEN + `FINALIZATION_TIMEOUT_MS` (5 s): it bounds finalization
retransmits, not the open route. That value flowed through
`dht-exit-reservation.js` into the exit's destination table, where every
admitted destination expires at `min(now + 300 s, expiresAt,
absoluteDeadline)` and `verifyDhtExitRoutedDestination` refuses a request
whose deadline exceeds the entry's expiry. A routed get carries a 3 s budget,
so any request issued more than about 2 s after OPEN was refused by the exit
and the endpoint's query drained empty. The same class of fault as the
extension-budget shortening recorded under the KI-4 history: an operation
budget carried as a route lifetime. Fix: the open authority is bounded by the
route's `localDeadline` only. Both the exit-side and endpoint-side authorities
come from the same builder, so both are corrected.

Harness cause. `test/private/process/wire-services.js` gave every
`LinkBootstrapSession` `absoluteDeadline = now + LINK_DEADLINE_MS` (5 s).
That is right for an initiate, which starts now, and wrong for a pre-armed
accept, which waits for a peer that dials whenever the route owner decides.
`receive()` computes `min(start + 5 s, absoluteDeadline, signedExpiry)` when
the first LINK CREATE arrives and fails closed when that is already past, so
every standby middle and exit arm died five seconds after activation. The
scenario's blackhole rotation normally lands at about 3.7 s and passed; two
seconds later it dialed dead arms and the endpoint reported `unavailable`.
Fix: accept-mode sessions are bounded by the grant's remaining lifetime
projected onto the monotonic clock; initiates keep the operation budget.
Production relays do not use this test link service, so this half is
harness-only, but the consumer integration that replaces it must not repeat
it.

Evidence. With the 2 s idle in place: unfixed tree fails assertion 35
(`ERR_PRIVACY_UNAVAILABLE`); production fix alone reaches assertion 48 and
fails the rotation (`unavailable`, generation 1, instead of `rotated`); both
fixes pass 136/136. Debug instrumentation used to identify the rejected event
was removed.

### KI-16: ordered UDP shutdown can produce kernel ICMP drops

**Status: classification approved, implemented, and verified on native Linux.**

The 2026-09-05 advisory verification passed seven Linux gates. The live
namespace gate reported one firewall drop, despite passing every UDP graph,
marker, and payload oracle. The original UDP-only capture could not identify
the dropped packet.

The capture now includes IPv4 traffic, and an audit with drops prints non-UDP
frames as well as the unchanged raw counter. A throwaway 750 ms pause
after the guard's stop command reproduced five dropped ICMP destination/port
unreachable replies. They quoted 1,200-byte route datagrams sent on allowed
adjacencies after the receiving endpoint or guard socket had closed. The
coordinator stops roles in sequence while later roles can still send link
heartbeats. This explains a real failure mechanism; the uncaptured packet in
the first run cannot be identified retroactively.

Six instrumented reruns and one ordinary run passed 146/146 without a drop.
Those passes do not resolve the shutdown race. A separate six-container
concurrency experiment hit command deadlines before its first lifecycle
assertion; it is not evidence about the original dropped packet.

No firewall exception, counter reset, skipped UDP assertion, delayed production
close, or packet-suppressing adapter was added. JD approved a narrow teardown
classification instead of a new acknowledged shutdown protocol.

The two read-only reviews found no existing peer-acknowledged shutdown barrier.
`LinkControlSession.destroy()` waits for local send completion, not peer
receipt; the receiver closes without an acknowledgement. A bounded delay
cannot prove that all peer datagrams have stopped.

Main rejected the first ICMP classification proposal: these kernel replies
contain only a prefix of the original datagram, so a full-cell comparison
cannot succeed. The original one-drop failure remains unattributed.

The replacement audit reads all eleven role captures and both marker captures.
It requires complete, checksummed, unfragmented IPv4; marker non-UDP traffic
never qualifies. Only ICMP type 3/code 3 with zero reserved bytes, a valid
checksum, and an exact quoted-prefix match to earlier allowed UDP traffic on
the same destination root-veth can qualify. The outer addresses must reverse
that exact firewall tuple. Duplicate records, missing provenance, other
protocols, malformed packets, and unmatched counters fail the gate.

Namespace-only instrumentation observes each real native UDP socket's close
call and successful completion without changing its returned promise or
shutdown order. Sidecars identify the exact host and port. Eligibility starts
three milliseconds after the sampled close-call time: one millisecond for
resolution plus two for observed clock uncertainty. This is a close-call
bound, not an exact kernel-unbind timestamp. Packets near that boundary remain
unmatched; uncertainty never backdates eligibility. Completion must precede
the audit, and observed realtime/monotonic drift over two milliseconds fails.
Coordinator receipt of the later `closed` event is not used as a close time.

The raw DROP counter is printed and checked before and after capture stops.
It must exactly equal the independently classified ICMP count in both
directions. No counter is decremented and ICMP remains blocked by the firewall.
Every existing UDP privacy assertion still runs over the full capture.

One follow-up run failed a new file-order assertion with raw DROP zero.
[Libpcap documents that packet queues can produce non-increasing timestamps](https://www.tcpdump.org/manpages/pcap-tstamp.7.html).
The audit no longer assumes global timestamp order. Quote proof still needs
both an earlier file record and an earlier timestamp. A later matching UDP
record cannot supply missing earlier evidence. Duplicate detection covers
records separated by different timestamps.

The native-close observer also had an error path that could throw before
calling native close. It now records the audit error and still closes the
socket. A real-socket regression injects a clock error, rebinds the same port,
and requires the audit to refuse the bad clock. Restoring the throw makes
that regression fail. Restoring the global file-order assertion fails the
valid reordered-traffic case; removing the file-index check fails the later
matching-record refusal case. The final focused checks pass 31 tests and
79 assertions.

The final full Linux matrix passes all eight gates: Node 975 tests / 19,051
assertions; Bare 932 / 18,923; four process legs at 136 assertions each;
namespace projection 27; live namespace 146 with raw DROP zero and classified
ICMP zero. On the same source, a throwaway 750 ms guard-stop pause produces
three raw drops and three classified replies, with all 146 assertions passing.
A separate injected ICMP echo produces one raw drop and fails assertion 146
with `ERR_TEARDOWN_ICMP: unmatched non-UDP packet`, as required. The native
firewall remains strict; the original uncaptured packet remains unattributed.

### Remote peer timing harness

Every gate above runs on one machine, so nothing measures this fork against a
host on another network. `.github/workflows/remote-peer.yml` holds up to five
peers open on runners for a chosen span, and `scripts/remote-peer.sh` times a
workstation against them:

- `scripts/remote-peer.sh secret --push` mints a 32-byte secret, keeps it in
  `$XDG_CONFIG_HOME/hyperdht-remote-peer/secret`, and sets the
  `REMOTE_PEER_SECRET` repository secret. Without `--push` nothing leaves the
  machine.
- `scripts/remote-peer.sh up -p 3 -s 300` dispatches three peers for five
  minutes, then measures all three at once.
- `scripts/remote-peer.sh local -p 3` runs the same harness against a local
  testnet, with no CI and no public network.

Peer and prober keys are derived from that secret plus the run id, so the DHT is
the only rendezvous: no key is a workflow input, none has to be scraped from a
runner log, and none is usable without the secret. Each peer pins its firewall to
the derived prober key. Per peer the probe reports connect time and attempts,
round-trip min/p50/p95 over 64 samples, and 1 MiB echo throughput; peers are
always measured concurrently, which is what exposes shared-socket and holepunch
contention that one peer at a time hides. Every read phase is bounded, so a peer
that accepts and then stalls fails in seconds naming the phase.

Observed against GitHub `ubuntu-latest` runners, run 31909702808, two peers for
300s, prober on a workstation behind a home NAT:

- Peer 1: connect 761ms on the 4th attempt, round trip min 31.7ms p50 36.1ms
  p95 115.7ms, echo 28.0 Mbit/s, remote 52.186.175.102:11265.
- Peer 2: connect 966ms on the 5th attempt, round trip min 31.9ms p50 36.0ms
  p95 111.8ms, echo 25.2 Mbit/s, remote 40.76.238.180:2049.
- Both runners reported `firewalled true`, `accepted 1`, and
  `echoed 1049088` bytes, which is exactly 64 pings of 8 bytes plus 1 MiB.
- Peer 1 also reported `rejected 1`: the stranger-key test was refused by a real
  remote peer, not only locally.
- Neither side counted a relay or a punch (`relaying.attempts 0`, `punches` all
  zero), and the prober's stream reported the runner's public address with a port
  that differs from the runner's local port. Which mechanism carried the
  connection is not established by these counters alone.

A second dispatch, run 31910008193, held five peers for 300s and all five
answered: connect 525..1,695ms, round trip p50 39.5..92.1ms, echo 3.1..21.6
Mbit/s, across five distinct runner addresses, 12/12 assertions. The spread is
the point of measuring peers concurrently: a single peer would have reported one
region's latency as though it were the number.

#### Runner-to-runner links

A single prober only proves workstation-to-peer reachability, which is not what a
private route needs: a guard must reach a middle and a middle an exit.
`.github/workflows/remote-mesh.yml` and `scripts/remote-mesh.sh` hold a mesh of
up to twelve runner members open. Every member derives every other member's key,
dials each higher index once, and answers a report request, so one collector
assembles the whole matrix. Success is a required link ratio plus a minimum
per-member degree, both defaulting to a full mesh, so a mostly-broken mesh cannot
pass.

Run 31910815472, ten `ubuntu-latest` members, 600s, 60s settle: 45/45 pairs
formed, every one on the first attempt, every member holding degree 9, 94/94
assertions. Connect p50 759ms, round trip p50 31.7ms, reconnect p50 276ms with a
worst case of 1,406ms. Reconnect is measured per pair because route rotation
depends on a link returning after a drop.

Cell-socket reachability was measured next, because a DHT link is not what
carries route cells. Each member binds a second UDX socket of the kind
`lib/private/udx-cell-endpoint.js:1401` binds, learns what address the world sees
for that socket, and punches every peer at once from the collector's plan.

Learning that address does not need an external STUN service. Every dht-rpc reply
carries a `to` field with the responder's view of the sender, which is how
dht-rpc fills its own `NatSampler` (`node_modules/dht-rpc/index.js:885`) and how
`dht.host`, `dht.port` and `remoteAddress()` are populated. That covers the socket
the DHT owns, and a NAT mapping belongs to a socket, so the cell socket is
reflected off two DHT bootstrap nodes with a PING built by this repository's own
client codec in `lib/private/dht-exit-wire.js`.

Run 31913403231 and run 31914488659, ten `ubuntu-latest` members each:

- 10/10 members reported the same mapped address from two different bootstrap
  nodes, so the mapping does not depend on the destination and one value per role
  is publishable to every peer.
- Mapped ports differ from local ports on every runner, for example local 40881
  mapped to 20.189.188.0:43970, so a local port would have been the wrong value to
  publish. An earlier attempt that published local ports recorded 0/90 arrivals.
- 90/90 directed cell-socket pairs arrived once the mapped address was used, with
  the source port intact on all 90.
- 10/10 members kept their mapping after closing a socket and binding a new one on
  the same local port, which is the order a distributed run needs: discover the
  endpoint, mint it into the signed capability, then let the endpoint bind.

Note for the private stack itself: `decodeDhtExitReply`
(`lib/private/dht-exit-wire.js:164`) rejects a reply whose `to` differs from the
local tuple, so the audited codec cannot be used unchanged for discovery behind a
NAT.

Two facts follow. Peer-to-peer links between NAT'd runners are reliable enough to
carry a distributed route topology, and a runner mesh can supply the two endpoint
peers plus eight or more route candidates that route choice needs. What it does
not yet do is carry private-route cells: `lib/private/udx-cell-endpoint.js:1398`
binds its own UDX socket with no injection point, and `lib/private/guard-link.js`
dials the endpoint bound into a signed relay capability, checked at line 627. A
distributed route run therefore needs each role's reachable endpoint discovered
first and minted into its capability, which is the next piece of work.

Observed locally, for comparison:

- Three peers on a local testnet: connect 18..19ms, round trip p50 0.4..0.5ms,
  echo 78..127 Mbit/s, 8/8 assertions.
- One peer over the public DHT on the same LAN as the prober: connect 1,328ms,
  round trip p50 0.4ms, echo 173 Mbit/s. This measures the LAN shortcut, not a
  cross-network path, so it is not evidence of remote reachability.
- A peer that accepts and never echoes failed in 15s with
  `ping 0 timed out after 15000ms` rather than hanging.

A peer inside the Colima VM is not reachable from the host prober. What the
diagnostics show: every prober attempt fails with `PEER_NOT_FOUND`, the peer
reports `firewalled true` and never accepts, and the only punch either side
counts is one random punch. So the peer is not discoverable through the DHT from
the host, and the cause has not been isolated further than that. Either way, a
remote peer belongs on a runner; the container stays for the kernel-dependent
gates above.

#### A route across separate hosts

`PROCESS_PLANS.DHT_MESH` builds the eleven-role topology from addresses discovered
at runtime instead of deriving `127.64.x.1`. Each role supplies two tuples,
because they are not the same address: a role binds a socket it owns, and
publishes the address peers must dial. Reachable values drive everything published
(advertisements, adjacency contacts, link specs, DHT peer lists, the firewall map,
the leak oracle's endpoint address); the bind tuple is used only where a socket is
bound, including a DHT role's own host and port.

`test/remote-peer/role-bridge.js` hosts one role on another machine. One byte
decides what a coordinator connection is for: ask for the role's addresses, or
attach and become the role's control stream. The role process itself is
`test/private/process/role-runner.js`, unmodified, so a distributed run executes
the same program the local gates do.
`test/remote-peer/role-channels.js` presents those streams to
`test/private/process/coordinator.js` as child processes, and
`test/remote-peer/live-route.js` supplies both halves to the existing scenario
through a `prepare` hook.

`scripts/live-route-rehearsal.sh` runs the whole path on one machine against a
throwaway DHT: eleven bridges answer with their addresses, the topology is minted
from those answers, eleven control channels open, and the scenario runs.

**Status: passing.** The rehearsal completes the whole scenario across eleven
separately hosted roles: 1/1 test, 132/132 assertions. Roles activate, the route
builds, traffic flows, every role stops on command and exits zero. Earlier 125-count
measurements below are retained as historical snapshots of their respective trees.

The last failure was in the transport, not the protocol. `live-process-suite.js:415`
ends the scenario by calling `expectExit` for every role, sending `stop`, and
asserting each exit code is zero, so a role exiting cleanly is the expected outcome.
`RemoteChild` listened only for the stream's `close` event, and a hyperdht stream
that the far side half-closes with `end()` need never reach `close` while this side
stays open, so no exit was ever reported and the coordinator burned its thirty
second scenario deadline. A remote `end` is now the role finishing: it settles an
exit with code zero and ends this side too.

Two further places where a stream-backed role differed from a spawned one were
measured and closed, both of which could have let a green run hide a fault.
`kill()` reported a zero exit, making a role that was cut down indistinguishable
from one that finished; it now reports no code and the signal, as a killed child
does. And the coordinator stops a role by ending its stdin
(`coordinator.js:549`), which a spawned role sees as EOF; the channel now
half-closes the stream and the bridge passes the EOF on, so a role waiting for it
is not left running.

`test/remote-peer/role-channel-lifecycle.js` holds those semantics with eleven
assertions over a real stream and no role process: byte fidelity in both directions
across many packets, a silent stderr, a graceful end producing exactly one exit with
code zero before the stream closes, a destroyed stream producing one failure exit
with and without an error listener, kill closing the stream, and a write after the
far side is gone reporting to its caller. The graceful-end assertion was checked
against the pre-fix channel and fails there, so it guards the bug rather than
describing it.

Setting `PR_BRIDGE_TRACE` to a path makes both halves of the transport write one
JSON object per line for every control frame, stream event and role exit, which is
how the teardown sequence above was read back. It is off unless the variable is
set.

A rehearsal needs one address per role, because the diversity rule rejects a set of
relays sharing a /24 (KI-5). Linux serves every 127/8 address, so the rehearsal runs
in the container from `docker/linux-gates.Dockerfile` with
`REHEARSAL_HOST_PREFIX=127.64`; on macOS the roles share 127.0.0.1 and the run stops
at that rule.

Getting that far drove out three layers that each treated a role's local address
and its published address as one value. They are equal only when nothing translates
in between, which is what a run across hosts breaks:

- `topology-fixture.js` now carries a bind tuple and a reachable tuple per role,
  and an exit also publishes the address of the second socket it binds at
  `role-runner.js:360` for reaching DHT nodes. No role can derive a peer's address
  under this plan, so they travel with the projection as `meshPeers`.
- `audit-event.js:373` built a record's addresses from the plan name. Under the
  discovered plan the two addresses a record binds are stated instead, encoded to
  the same nineteen bytes the derived plans produce.
- `dht-setup-audit-udx.js` compared one address against both the socket's own bind
  and the address a peer reports back. Those are now separate: the bind check uses
  the local address, the reply checks and the record use the observed one.

No transport question remains open, since 90/90 directed cell-socket pairs already
reach each other between runners.

### KI-7: a cell endpoint must be bound to the address it advertises

**Status: fixed. Found by running the topology across hosts, not by review.**

`lib/private/udx-cell-endpoint.js:1561` rejects a link whose handle carries a local
address different from the address the endpoint bound:

```
if (link.localAddress.host !== state.host || link.localAddress.port !== state.port) {
  throw PrivateRouteError.UNAUTHORIZED()
}
```

The check is sound as an ownership test, and it holds trivially in both derived
plans, where a role binds the same `127.64.x.1` or `10.203.x.2` address it
advertises. It cannot hold behind a NAT. A role there binds a private address or
`0.0.0.0` and is reachable at a translated one, so the address in its signed
capability is never the address it bound, and every `openLink` fails
`UNAUTHORIZED`.

This is what stops the distributed rehearsal after the DHT phases: `announce-exit`
rejects its incoming extension with `UNAUTHORIZED` from `openLink`. It is not a
harness problem. Any deployment where a relay or exit sits behind a NAT hits it,
which is most of them.

`UdxCellEndpoint` now takes an optional `advertisedHost` and `advertisedPort`.
Absent, they are the bound address, so every existing caller is unchanged. Stated,
they must be stated as a pair and are validated like any other address, and the
ownership check at `openLink` compares against them. The test is unchanged in
substance: the advertised pair is fixed when the endpoint is constructed and is
never taken from the handle. `endpoint-bootstrap-authority.js` passes the pair
through when given it, so the endpoint role's bootstrap path publishes the same
address as everything else; stating one field without the other is refused there
too. `test/private/udx-cell-endpoint-advertised.js` covers the pair rule, each
rejection, and the behaviour itself: a handle naming the advertised address passes
the ownership check while a handle naming the bound address is refused
`UNAUTHORIZED`. hyperdht keeps the same distinction for its own
socket through dht-rpc's NatSampler.

Three further plan-name whitelists surfaced behind it, each rejecting an unknown
plan: `role-runner.js` derived peer addresses from the plan, `audit-event.js:373`
derived an audit record's addresses, and `control-channel.js:993` accepted only the
two derived plans on the isolated-grant command. All three now handle the discovered
plan.

### KI-8: a branch loss is never delivered when a stale frame is queued unread

**Status: FIXED. The fault was in the routing code, not in the rehearsal. Diagnosis and
evidence are kept below because the mechanism is worth understanding and because three
earlier hypotheses were wrong.**

This entry was originally titled as an addressing fault and it is not one. Nothing in it
confuses a bound address with an advertised one. The rehearsal's divergent mode exposed it
by adding LATENCY, not by diverging addresses: the deciding variable is a 3.4ms window
between a cancel and a reply, which is why the untranslated mode reproduces it with no
translation anywhere and why identical addressing wins the race purely by being
loopback-fast. That matters for what the mode is worth. Its obvious value is catching
bind-versus-advertised confusion, and it caught three such faults; its second and less
obvious value is being the only mode with remotely realistic timing. Every mode here is
sub-millisecond loopback, so a real deployment loses this race MORE often than our worst
mode does.

The fix is recorded under KI-10, whose first half is the same fault: a live route
transport now drains its physical channel for as long as it is live, so an in-band
`BRANCH_DESTROY` is consumed on arrival whether or not the application is reading.

Proof, on a tree carrying the fix, read by rotation trigger rather than by assertion
number because both candidate faults failed the same assertion:

| mode      | runs | after the fix | rotation trigger     |
| --------- | ---- | ------------- | -------------------- |
| unmapped  | 5    | 5 of 5        | loss, +4.4 to +9.5ms |
| divergent | 5    | 5 of 5        | loss, +4.4 to +9.5ms |

The pre-fix counts are deliberately NOT tabulated beside those, because they come from a
different tree and are contaminated in the direction that would flatter the fix. The
pre-fix rates of 0 in 11 unmapped and 0 in 12 divergent were measured with instrumentation
active, and that instrumentation wrote with `appendFileSync` - synchronously, on the
calling thread - with one probe firing inside the very window that decides the race. Extra
latency there makes failure MORE likely, so those counts are a lower bound on the true
pre-fix pass rate rather than an estimate of it. No pre-fix rate on a clean tree exists and
none can be taken now without un-applying the fix.

So the claim here is deliberately not "it went from zero to green". It is that the
mechanism is fixed, proven by a probe-free before-and-after against committed exports
extracted from the pre-fix commit - a destroy behind one unread frame is not consumed at
queue depth 1 before, and is consumed at depth 0 after - and that the fixed tree is green
on the tree that ships. Attribution is unaffected by probe cost, since the comparison that
established it varied only translation while holding instrumentation constant across all
three modes, and its packet-level half rested on netfilter counters and a capture, which no
JavaScript timing can influence.

`lookupBranchExpiry`, which was the only trigger that ever fired before, is never the
trigger in any of the ten runs. The rebuild now starts on the loss it is supposed to start
on, claims at +15 to +23ms and emits `rotated` at +122 to +215ms.

FAULT B WAS NOT INDEPENDENT. The replacement middle extension - which took 4965ms and died
on its deadline in the one disturbed run where it was ever reached, and was null in all 21
pre-fix failures - completes in 98 to 175ms in all five divergent runs once Fault A is
fixed. It needed no fix. It was a single observation of Fault A's downstream consequence: a
rotation starting 9.7s late against a topology that had been idle for ten seconds. The
caution three reviewers insisted on, against writing it up as a second independent fault,
was correct.

`scripts/live-route-rehearsal.sh` gained a second addressing mode because a
rehearsal where every role binds the address it publishes cannot catch anything that
confuses the two. That mode found three faults which had all passed the same
scenario at 125/125:

- `role-runner.js` built the endpoint role's bootstrap authority without the
  advertised pair, so it alone published its bound address. Fixed; note that the
  KI-7 entry above already claimed this path published the same address as
  everything else, which was true of `endpoint-bootstrap-authority.js` and not of
  its caller.
- `wire-services.js` used one tuple both to bind an exit's DHT-exit socket and as
  the reservation's `local`, which is the address a peer's reply must echo
  (`lib/private/dht-exit-reservation.js:403`, `lib/private/dht-exit-wire.js:164`).
  Fixed by taking an optional advertised pair; the socket still binds the local one.
- `live-process-suite.js` recomputed the learned-closer isolated-address digest from
  a candidate's bound address, while `topology-fixture.js:1030` mints those grant
  pools from the reachable one. Fixed. This one was silent: a digest keyed on the
  wrong address throws nothing and logs nothing, the responder simply never matches,
  so no stack exists anywhere for it.

What remains open is a fourth observation, and instrumented traces have now disproved
this entry's original description of it. It is not that the rebuild fails. The rebuild
never starts, and a second unrelated fault then breaks the rotation that eventually does
start. Two runs, one per mode, instrumented identically, with times relative to the
injected fault:

| step                                       | identical | divergent |
| ------------------------------------------ | --------- | --------- |
| `fault-outgoing-physical-link` on middle-a | +0.0ms    | +0.0ms    |
| endpoint consumes `BRANCH_DESTROY`         | +2.8ms    | never     |
| `branch-physical-loss` at the endpoint     | +4.7ms    | never     |
| signal that starts the rotation            | +5.8ms    | +9656.0ms |
| kind of that signal                        | loss      | expiry    |
| replacement middle extension completes     | +65.7ms   | never     |
| `emit-rotated`                             | +142.0ms  | never     |

So there are two faults, and both are a packet that does not arrive. They are not yet
known to be independent: Fault A is measured in both modes and is solid, while Fault B
has been observed exactly once, in a run whose rotation had already been started 9.7s
late by Fault A, so its 5s build deadline was competing with a topology that had been
idle for ten seconds. Until Fault B is reproduced in a rotation that started on time, it
may be a consequence of A rather than a second fault.

Fault A. The `BRANCH_DESTROY` that middle-a emits toward the guard is never consumed by
the endpoint's route transport: `consumeM3RouteBranchDestroy`,
`lib/private/m3-adjacency-runtime.js:842`, never runs, so
`takeM3RuntimePhysicalLossState` at `:847` never runs and the loss sink registered by
`commitBranchConnection`, `private-routing-controller.js:519`, never fires. There is no
pending promise anywhere: the rebuild is not stalled mid-flight, it is never entered,
which is why raising the coordinator's command timeout twelvefold changes nothing. What
does eventually rotate the branch is `BRANCH_ROTATION_LEAD_MS`, `route-manager.js:36`,
a scheduled timer that fires 5s before the branch material expires and would have fired
at the same moment if nothing had been faulted at all. Because the shipped command
timeout is 5s and the earliest possible rotation is 9.7s away, Fault A alone is fatal:
a divergent run that passes is one where the `BRANCH_DESTROY` did arrive, so delivery of
that one control message is at least the dominant variable. Whether anything else also
varies is open until Fault B's status is settled.

Fault B, provisional on the caveat above. Once a rotation does start, the replacement
middle extension to lookup-middle-b
gets no response and dies exactly on `REPLACEMENT_BRANCH_DEADLINE_MS`,
`route-manager.js:38`, measured at 4965.6ms against a 5000ms budget. Identical mode
completes the same extension in 39.5ms. This is the first packet ever sent on the
guard-to-middle-b path, so nothing about it is a stale-state problem. The deadline fires
correctly and the failure is clean: `enterUnavailable` runs, the controller reaches
UNAVAILABLE, and the role emits `unavailable`. That is why a run with a raised command
timeout fails as `PROCESS_PHASE_MISMATCH` rather than a deadline.

Attribution: the rehearsal's NAT is exonerated, and Fault A is in the routing code. A
third addressing mode, `REHEARSAL_ADDRESSES=unmapped`, makes bound and published
addresses differ with no packet translation at all - roles bind `0.0.0.0` and are reached
at `127.65.<index>.1` via `ip addr add` plus a per-role route carrying
`src 127.65.<index>.1`, selected by an `ip rule` on source port, with all four netfilter
tables verified bare. Fault A reproduces there, and in both runs the trace shows the
`BRANCH_DESTROY` handed to the wire 2.3ms BEFORE the harness's link rearm dropped any
link, and never consumed:

| event                        | run 1     | run 2     |
| ---------------------------- | --------- | --------- |
| destroy emit begins          | fault+2.6 | fault+2.4 |
| destroy handed to the wire   | fault+3.4 | fault+3.2 |
| harness rearm drops links    | fault+5.7 | fault+5.5 |
| destroy consumed by endpoint | never     | never     |

So the message is sent, untranslated, and not consumed. That falsifies two earlier
hypotheses outright: translation loss, and a race in which the harness's rearm tears down
the link before the destroy is emitted.

The mechanism is KI-10's head-of-line blocking, recorded below, and the full chain is now
measured at a real fault rather than assembled from parts. Two unmapped runs, times
relative to the injected fault, agreeing to within a millisecond:

| event                                          | run 1  | run 2  |
| ---------------------------------------------- | ------ | ------ |
| the scenario cancels operation 2               | -5.1ms | -4.9ms |
| the in-flight reply arrives with no reader     | -1.7ms | -1.4ms |
| the pump declines to read and does not restart | -1.3ms | -0.9ms |
| the link is faulted                            | 0.0ms  | 0.0ms  |
| middle-a hands `BRANCH_DESTROY` to the wire    | +3.2ms | +3.3ms |
| the harness's link rearm drops links           | +5.1ms | +5.2ms |
| the endpoint consumes the destroy              | never  | never  |

So: the cancel removes the reader; the reply to the cancelled operation lands about 3.4ms
later with no waiter and is queued; the pump refuses to read while a frame is queued and
does not restart; the link is faulted 1.4ms after that; middle-a emits the
`BRANCH_DESTROY` and it reaches the wire; nobody ever reads it; the branch loss is never
delivered; the rotation never starts; assertion 41 fails. The window that decides a run
is the interval between the cancel and the reply's arrival, 3.4ms and 3.5ms in these two
runs. Identical addressing wins that race and the translated and untranslated divergent
modes lose it, which is why the same code passes 28 of 28 one way and fails the other.

The comparison is symmetric and the separation is total. Twenty-seven instrumented runs
across all three addressing modes, classified by one binary feature with no exceptions.
Every run of every mode queues exactly two route frames with no reader; the modes differ
only in when the second one lands:

| mode      | runs | outcome | second queue event | destroy consumed | rotation      |
| --------- | ---- | ------- | ------------------ | ---------------- | ------------- |
| identical | 6    | pass    | +542 to +618ms     | +3.85 to +4.37ms | loss-driven   |
| divergent | 12   | fail    | -1.3 to -3.1ms     | never            | never started |
| unmapped  | 9    | fail    | -0.5 to -2.4ms     | never            | never started |

The first queue event is common to all twenty-seven runs, at -160 to -262ms, and is always
drained by a later reader. The second decides the run: in all twenty-one failures it lands
inside the last 3.1ms before the fault, so the pump is already wedged when the destroy
reaches the wire 3-6ms later; in all six passes it lands more than half a second after the
fault, long after the destroy was consumed and the branch rotated. The clusters are
separated by more than 540ms with no overlap.

That yields the sharpest statement of the fault, and it is not the obvious one: a queued
frame is not the fault. Frames queue with no reader twice per run, in healthy runs, in
every mode, and are drained harmlessly. The fault is a frame queued in the roughly three
milliseconds before a branch dies. Any fix or test that keys on "a frame was queued" will
look correct and prove nothing.

The trace-based finding is corroborated at packet level by an independent instrument. A
divergent run that reached `not ok 41` was observed with pure-counter netfilter chains and
`tcpdump` on `lo`, 272 packets captured across 17 samples:

- The DNAT and SNAT rules for roles 5 and 6 - `lookup-middle-b` and `lookup-exit-b`, the
  replacement pair - counted ZERO for the entire run, and no packet to either appears
  anywhere in the capture. The guard never dialled either one. Fault A stops the rebuild
  before a single replacement packet reaches the wire.
- No rule stopped matching: counters are monotonic across all 17 samples. No UDP mapping
  can expire, since the scenario is 6.8s end to end against a 30s unreplied timeout, and
  `conntrack_count` rose monotonically to 436 against a maximum of 262144.
- The uncovered-port catch-all counted zero packets, and every one of the 272 captured
  destinations falls inside the covered set. The earlier hypothesis that a rebuild might
  use a port the rules did not cover is dead by measurement rather than by reading.
- Zero packets escaped SNAT: 250 translated, 0 untranslated, measured in `filter INPUT`
  after both nat hooks. So nothing was silently discarded by a peer's source check.

Two tooling limits are worth stating rather than leaving implicit: `conntrack(8)` is absent
from the image and `/proc/net/nf_conntrack` does not exist, so per-flow listing was
impossible and only aggregate counters were available.

A limit on every load figure in this document, and on every timing number that depends on
one. The container VM has four vCPUs, not the host's ten, and three unrelated long-lived
containers share it - a relay and two Postgres instances, up four and seven days. They were
idle when measured, but idle-when-measured is not idle-at-the-time, and no run here was
taken with them stopped. So every recorded load average has an unmeasured floor under it.
This does not undermine the findings, because the load-bearing evidence is mechanism-level
and comparative rather than rate-level - a before-and-after on committed exports, and
comparisons that hold instrumentation and machine constant while varying one thing - but any
absolute rate in this document should be read as an observation under uncontrolled load
rather than as a measurement of the code alone.

Worse, every load figure recorded here is the macOS HOST one-minute average sampled before
the run, and no harness ever sampled inside the guest. That number is nearly blind to what
the container's four vCPUs were actually doing: the whole VM is one host process, so even a
fully saturated guest contributes only about four to six to the host figure. A host average
materially above that implies work outside the VM entirely - which, during this batch, means
the agents' own tooling, since a lease that disciplined containers never covered anyone's
`node`, `git` and `python` on the host. Two instruments that look like the answer are not. Guest `/proc/loadavg` reads 0.14-0.47
while the host is at 12-14, because host oversubscription DESCHEDULES the guest's vCPU
threads rather than lengthening the guest's runqueue - the guest runs slower in wall-clock
without its runqueue growing, so guest loadavg would read the same whether the hypervisor
gets full time or a third of it. Steal time, the normal metric for exactly that, is flat
zero in `/proc/stat` because colima on Virtualization.framework does not report it to the
guest. So neither reveals host starvation from inside a container on this setup.

What does work is timing a fixed amount of work inside the guest, and the harness already
records one: the scenario's own duration. Runs cluster tightly at 2775-3157ms across two
harnesses and three modes, so a run well outside that band had its vCPUs descheduled
whatever loadavg said. That is a zero-cost instrument, already present in every log.

One indirect guest-side measure does exist, and it is the only one in this document. The
trace intervals above are measured between lines inside a single container, so unlike a host
average they stretch under guest contention. Across the twenty-seven classified runs the
destroy was consumed at +2.8 to +4.4ms in six identical runs - a 0.5ms spread - with
emit-sent at +3.0 to +6.0ms and the deciding queue event at -0.5 to -3.1ms across
twenty-one failures in two modes. A guest under real contention does not hold a 0.5ms spread
on a millisecond-scale interval six times running, so the corpus behind this diagnosis was
taken on a guest that was not meaningfully contended - inferred from the intervals
themselves rather than from a figure nobody sampled. Note also what this does NOT cover: the
separation between clusters is 540ms, three orders of magnitude beyond any scheduling jitter
that could survive in intervals this tight, so contention cannot flip a classification
either way.

That inference is scoped to that corpus and must not be read as a claim about the session.
At a coarser grain the same guest was NOT stable: gate scenario wall times moved -1.3%,
+6.3%, +26.3% and -39.9% between two runs of the same four gates, with identical assertion
counts in every pair. Millisecond intervals inside one container over twelve minutes were
tight; multi-second scenario times across forty minutes swung by up to 40%. Both are true and
they measure different windows at different resolutions. Whether that swing is guest
contention, Bare runtime startup variance, or a real timing cost of the pump reading more is
unresolved - what it is not is a change in work, since every assertion count in those pairs
is identical.

Fault B is unreachable before Fault A is fixed, and that is measured rather than assumed:
`middleExtensionOpen` is null in all twelve divergent and all nine unmapped runs, so the
rebuild is stopped before the replacement middle extension is ever attempted, twenty-one
times out of twenty-one. No pre-fix capture in any mode can settle whether Fault B is
independent. Only post-fix runs can, read by rotation trigger rather than by assertion
number, since both faults fail the same assertion.

One measurement note that supersedes the rate table below for divergent. A later batch ran
twelve divergent rehearsals with the tree state and host load recorded for the first time
and found zero passes. Under the earlier 22% estimate twelve consecutive failures has
probability 5.4%, so this does not falsify the older figure, but the older figure was
measured under unknown load against an unrecorded tree and this one was not. Do not quote
22% as a post-fix baseline without that caveat.

Measured across two independent batches on the same image, counting runs that
reached 125/125. The second batch was run by a different party against the same tree
precisely because the first batch's stronger claim, that the failure had become
consistent, did not survive checking:

| batch  | mode      | runs | reached 125/125 |
| ------ | --------- | ---- | --------------- |
| first  | divergent | 33   | 6               |
| second | divergent | 12   | 4               |
| first  | identical | 15   | 15              |
| second | identical | 7    | 7               |

So it is intermittent, roughly one run in four passing, and not a failure that has
settled into always happening: an earlier draft of this entry claimed twenty-one
consecutive divergent failures, and twelve consecutive runs then produced four
passes. What is consistent is where it stops. Every one of the twenty divergent
failures across both batches stopped at the same place, assertion 41,
`PROCESS_COMMAND_DEADLINE`, with 40 of 41 assertions passing. Identical addressing
has never failed in 22 runs.

Because of this, divergent is not the default: a mode that passes 10 runs in 45 would
either be muted or be rerun until green, and rerunning until green is how the fault
it exposes disappears from view. Reproduce it with the documented container rehearsal
plus `--privileged` and the mode flag:

```
DOCKER_CONFIG=/tmp/hyperdht-private-routing-linux-gates-docker \
DOCKER_HOST=unix:///Users/jd/.colima/default/docker.sock \
docker run --rm --privileged --mount type=bind,source=$PWD,target=/app \
  --mount type=tmpfs,destination=/app/node_modules \
  --mount type=tmpfs,destination=/root/.config \
  -e REHEARSAL_ADDRESSES=divergent -e REHEARSAL_HOST_PREFIX=127.64 \
  -e XDG_CONFIG_HOME=/root/.config \
  -e BRITTLE_NODE=/node_modules/.bin/brittle-node \
  -e REMOTE_PEER_COORDINATOR_SECRET=<64 hex> \
  -w /app hyperdht-private-routing/linux-gates:ffd5f7f04db9 \
  bash -c 'mkdir -p /root/.config/hyperdht-remote-peer && printf "%s" "<64 hex>" \
    > /root/.config/hyperdht-remote-peer/secret && bash scripts/live-route-rehearsal.sh 240'
```

### KI-9: an expiry signal arriving during a rotation is lost permanently

**Status: FIXED. A production fault, not a harness artifact. Found by instrumenting a
rehearsal, not by review. The diagnosis below is kept because the mechanism is the
reason the fix is level-triggered rather than a queue.**

A branch expiry signal that arrives while the controller is `ROTATING` is dropped, and
the state needed to reissue it is destroyed at the same moment, so that branch never
rotates again for the life of the controller. `private-routing-controller.js:272`
refuses any signal delivered in a state other than `READY`, which alone would only
delay it. What makes the loss permanent:

- `route-manager.js:274-281`, `issueBranchSink` nulls `state.lifecycleSinks[key]`
  before issuing, and the signal is one-shot: it is consumed and added to
  `SPENT_SIGNALS` at `private-routing-controller.js:321-325`.
- `route-manager.js:314` deletes the handle from `state.branchExpiryTimers` before
  issuing, and `armBranchExpiry` is re-entered at `:322-324` only when the expiry has
  moved further out, which on this path it has not.
- `registerReplacementLifecycle`, `private-routing-controller.js:461-472`, recreates
  expiry sinks only for the branch class being rotated, never the other one.

So after the drop there is no sink and no timer for that branch class. The two branches
expire on independent clocks and a rotation takes seconds, so a lookup rotation that
overlaps the announce branch's expiry silently retires the announce branch's only
rotation trigger.

Observed in an instrumented divergent rehearsal: an `announceBranchExpiry` signal
arrived 11072.4ms into the run with the controller in `ROTATING`, 130ms after a lookup
rotation began, and was discarded with nothing rearming it.

This is independent of KI-8. KI-8 is about which signal starts a rebuild, and whether
the message that should start it arrives at all. This is about a signal that does
arrive, at a moment the controller cannot accept it, and is then unrecoverable.

The fix keeps the condition standing rather than queueing the event. A refused
`lookupBranchExpiry` or `announceBranchExpiry` delivery makes the controller mint a
replacement sink for the emptied slot, `private-routing-controller.js:298-302`, and
`renewRouteManagerBranchExpiry`, `route-manager.js:1235-1250`, re-arms the manager's
own clock at `BRANCH_EXPIRY_RETRY_MS` of 250ms - well inside
`BRANCH_ROTATION_LEAD_MS` - so redelivery does not depend on the controller reaching
any particular state. Only an empty slot can be filled, so a live sink is never
displaced. KI-10 now retains a refused branch loss separately on the published
branch and redelivers it after READY; expiry is no longer its recovery backstop.
Regression coverage for expiry remains
`test/private/branch-expiry-rotation.js:271`, which refuses an announce expiry during a
lookup rotation and asserts the redelivered signal rotates the announce branch.

### KI-10: native blackhole detection and refused-loss redelivery

**Status: native blackhole detection and refused-loss redelivery fixed.**
Loss reports now name the generation owned by the physical registration or live
route IO owner. RouteManager rejects a retired generation before changing
capabilities or recording fault demotion. A matching loss received during either
branch's rotation remains on the current published branch object.

The controller treats a loss signal as a wakeup, not as authority to lose an
arbitrary current branch. It checks the current manager-owned loss, restores a
refused one-shot sink, and redelivers standing losses in the `pairReady`
handler after `await installReadyGeneration(state)` completes, including old
transport teardown. No additional `dht.ready()` wait changes controller startup.
Replacement discards the old branch's lost flag; loss during that branch's own
build does not spend the replacement's lifecycle sink. Teardown destroys the
pending branch state. No loss retry queue, retry timer, or direct fallback is added.

`test/private/branch-expiry-rotation.js` reproduces both refusal windows: two
reports queued before the first controller transition, and a sibling report
issued after RouteManager enters ROTATING. Recovery completes with the lease
clock unchanged. It also checks delayed retired registrations and loss of a
branch already being replaced.
The retiring-branch regression also faults its replacement to prove that the
new loss sink remains usable. A network change with pending sibling loss
removes request authority and prevents recovery from restoring it. The shared
test harness now encodes its complete deterministic counter instead of
wrapping a byte-fill sequence into an invalid all-zero route identifier.
Failed replacement publication also requires the old branch to be both unexpired
and not lost before READY can be restored. A same-branch-loss regression fails
when `!current.lost` is removed: the old code reports ready and returns the
rotating error instead of `ERR_PRIVACY_UNAVAILABLE`.

This is separate from the verified silent-link detector. The head-of-line
blocking fault was closed with KI-8. Commits `d00ecef` and `6468028` added an
eleven-process proof of the existing detector; they did not introduce a new
heartbeat protocol.

`installLinkControl` in `lib/private/udx-cell-endpoint.js` installs a production
`LinkControlSession` on each authenticated adjacency. Its `runLiveness` sends
PING at `LINK_PING_AFTER` (500ms) and closes an adjacency after
`LINK_UNRESPONSIVE_AFTER` (1,500ms) without accepted activity. `closeState`
notifies circuit ownership and closes the physical link. M3 propagates that
loss to the controller and RouteManager. This is application link control
carried by UDX datagrams, not a native UDX per-peer close event.

`test/private/live-process-suite.js` leaves both healthy branches without
application traffic for two seconds, then blackholes the selected lookup
middle's route cells in both directions. The middle's process, bound socket,
bootstrap traffic, and test control stream remain alive. The scenario requires
a fresh lookup generation within five seconds, an unchanged healthy announce
generation, an exact immutable get through the replacement, and successful
suspend/resume and teardown. Elapsed detection time uses a monotonic clock.
Every selectable middle can receive the fault, including `announce-middle`;
role labels do not determine which branch uses a relay.

Scope: this proves complete bidirectional route-cell silence in the local
eleven-role topology. It does not prove loss tolerance under arbitrary delay,
a remote-network latency bound, or detection of a malicious relay that answers
heartbeats while discarding application cells. L0 still bounds an outstanding
operation. The existing heartbeat also reveals idle adjacency activity; fixed
cell size is not traffic-analysis resistance.

#### Historical diagnosis — before 2026-08-30, superseded

The original pump fault stopped `pumpM3RouteTransport` whenever
`record.received` held an unread frame. A `BRANCH_DESTROY` behind that frame was
never consumed because neither recursion nor the re-pump path restarted the
reader. The original measurement compared two cases:

| Historical case                        | Destroy consumed | Channel depth |
| -------------------------------------- | ---------------- | ------------- |
| Branch destroy alone                   | true             | 0             |
| Branch destroy behind one unread frame | false            | 1             |

Cancelled operations could leave a late reply without a reader. The same pump
served endpoint requests, DHT exits, and final-exit activation, so the KI-8 pump
fix addressed all three consumers. This table records the pre-fix failure, not
current behavior.

An early rehearsal reported a route change only after 9,656ms, at lease
rotation. The original diagnosis incorrectly concluded that no keepalive or
adjacency timeout existed. A later blackhole probe contradicted that premise:
it observed detection in about 1.48–1.52 seconds while idle and 1.30–1.34 seconds
with a get outstanding, versus about 14.7 seconds of no-fault silence.
Disabling the L0 operation deadline did not materially change those results.
At that point the detector had not been identified.

Commits `d00ecef` and `6468028` replaced that uncertainty with the production
`LinkControlSession` path and the native eleven-process blackhole gate described
above. The earlier claims of lease-only discovery, an unknown detector, and
unfixed idle pump blocking are withdrawn. They must not be used as reasons to
implement the unratified L1/L2 proposal.

The historical KI-8 field attribution remained uncertain: the proposed stale
frame had to arrive before the destroy, while one identical-addressing run
consumed the destroy after 2.8ms and took about 70ms for a routed get. That
uncertainty concerns the cause of a past field occurrence, not the current
native detector or the fixed pump.

### KI-11: a teardown phase mismatch, window found and closed

**Status: the window is CLOSED in the harness and the closure is confirmed by a
deliberate provocation that reproduces the exact failure on demand in 0.11s. What is
still open is attribution: the provocation proves the mechanism exists and that the fix
removes it, NOT that this mechanism is what produced the one field occurrence. That run
remains unmeasurable after the fact.**

One divergent rehearsal on the fixed tree failed at
`not ok 71 - PROCESS_PHASE_MISMATCH (lookup-exit-a/CONTROL)`, 70 of 71 assertions, where
assertion 71 is the first of the teardown loop, `t.is(snapshot.state, 'CLOSED')` at
`live-process-suite.js:499`. The run passed the rotate at 41, suspend and resume at 55-66
and network-change at 69-70, so it is a different phase and a different failure mode from
KI-8, which always failed at 41 with `PROCESS_COMMAND_DEADLINE`. A phase mismatch fires
when a role's phase sequence has advanced past what the suite believes, so it needs ONE
unexpected event from one role, not a slow run.

An interleaved A/B in identical mode - the only mode reaching teardown on both trees,
since every pre-fix divergent run stops at 41 - found nothing: eight runs with the KI-10
fix reverted and eight with it present, alternating on one machine, zero occurrences of
assertion 71 in either arm. At a 1-in-31 rate that is an underpowered null and not
evidence of absence. It was run with the guest effectively idle (VM load 0.39 while the
host read 11-13), so it is not an under-load result. Its one useful incidental: the two
arms' scenario bands overlap and the fixed arm's is slightly tighter, which is mild
matched evidence that the KI-10 fix costs no measurable wall time.

A second-order effect of the KI-10 fix was the original suspicion and remains DISFAVOURED
BY SOURCE, on two counts. First, a retired exit's route transport is DESTROYED rather than
wedged: retirement awaits `finalExitService.destroy()`, which reaches
`destroyDhtExitRouteTransportForIO` via `closeState`, `dht-exit-io.js:887-892`. A destroyed
transport cannot be wedged or drained, and teardown is 2.8s later. Second, and decisively,
the premise was wrong: LOOKUP-EXIT-A IS NOT RETIRED AT TEARDOWN. `retainForSuspend()`
clears `state.committed`, and `resume()` at `relay-candidate-directory.js:892` then calls
`choosePairs(state, now)` with NO exclusions, which returns the first diverse quad in
record order - and that order is the guard's fixed projection array, so resume re-selects
`lookup-middle-a` with `lookup-exit-a`. The suspend and resume at assertions 55-66 put
exit-a back in the live path before teardown. "The failing role is the retired exit", the
detail that made the fix look implicated, is simply false.

#### The mechanism, now measured rather than inferred

The harness's own control protocol had a race, independent of route transports and
therefore of the KI-10 fix. It is no longer an inference. Each of its three steps is in
source and the whole is reproducible:

1. Every event is validated against a single scalar, and by EXACT EQUALITY:
   `baseMessage` rejects the message unless `context.phaseSequence === phaseSequence`,
   `control-channel.js:964`. There is no tolerance for the immediately preceding phase.
2. `dispatch` maps any validation throw to one code:
   `PROCESS_PHASE_MISMATCH`, `coordinator.js:343-348`, which is also the catch-all for
   every other event validation failure.
3. The coordinator's expected phase for a role is advanced BEFORE the command that carries
   the new phase is written, because `send` validates the outgoing command against
   `record.phaseSequence`, `coordinator.js:481`. Advance-then-send is structural, not a
   choice the suite makes.

So for any role that speaks unprompted, every phase advance opens a window: an event
already emitted and not yet read carries the OLD phase, and is refused. By teardown
exactly one role class still speaks unprompted. Every `emit` site in `role-runner.js` is
either a direct answer to a command or one of `isolated-grant-request` (the three exits,
raised whenever the exit's own discovery finds an isolated candidate) and the endpoint's
`rotated` and `unavailable`, which are gated on `state === 'READY'`,
`role-runner.js:920-934`, and the terminal network-change immediately before teardown
leaves the endpoint UNAVAILABLE. The window is therefore an `isolated-grant-request`
overtaking the teardown loop, which accounts for the role identity, the phase, and why the
failure has never appeared at any other assertion.

#### The obvious fix is not the fix

The earlier proposal, and the one this batch was briefed with, was to stop the
learned-grant responders BEFORE the teardown loop instead of in its `finally`. That cannot
close this window, and the reason is worth stating plainly because it is easy to
re-derive wrongly: THE REQUEST IS EMITTED BY THE ROLE, NOT SOLICITED BY THE COORDINATOR.
The responders are coordinator-side standing waiters. Stopping one cannot unsend a frame
already in the pipe. The provocation confirms this directly rather than by argument: the
`stale` arm below never answers a single grant - it is run with granting already stopped -
and it still reproduces the mismatch.

Stopping the responders early is kept anyway, as hygiene, for two reasons that are its own
and not the window's:

- A grant answered after the advance is refused by
  `observed.phaseSequence !== record.phaseSequence`, `coordinator.js:516`, and
  `respondIsolatedGrant` throws SYNCHRONOUSLY there. The suite's
  `await control.respondIsolatedGrant(...).catch(noop)` cannot catch a synchronous throw,
  and `.then(onFulfilled, noop)` handles the SOURCE promise's rejection rather than its own
  handler's, so the throw escaped as an unhandled rejection - which takes the entire run
  down, not one assertion. Reachable today: a request dispatched at the correct phase
  resolves the waiter, the loop advances that role's phase at the next `await`, and the
  queued handler then calls into `respondIsolatedGrant`. The handler is now wrapped, so a
  future ordering cannot be fatal either.
- An exit handed a grant mid-teardown admits the closer and restarts the very discovery
  that emits the next request. Unanswered, it cannot: `requestIsolatedGrant` throws while
  one request is pending, `role-runner.js:335-342`, so at most one request per exit exists
  during teardown.

Withholding the grant is safe on the role side, which was checked before relying on it:
`stopOwners` rejects a pending isolated grant with `PROCESS_CANCELLED` before destroying
the exit service, `role-runner.js:816-821`, so an unanswered request cannot wedge the
`stop`. `stopGranting()` deliberately does NOT disarm the standing waiter - only `stop()`
does, in the `finally` - because a request that still arrives must be tolerated rather than
become `PROCESS_UNEXPECTED_EVENT`.

#### The fix

A round trip at the phase already in force, per role, immediately before that role's phase
is advanced: `live-process-suite.js:486`, ahead of the advance at `:487-489`. A role's
events reach the coordinator as one FIFO stream decoded in order, so once this snapshot has
been dispatched, every frame that role emitted earlier has been dispatched too, under the
phase it was emitted with. That is an ordering proof rather than a delay.

Three properties made this cheap. Re-sending at the current phase is legal because the
runner adopts whatever phase a command carries, `role-runner.js:968`, and it is already an
established pattern in this suite - both `immutable-get`s in the resume path reuse
`phases.get('endpoint')`. A `snapshot` command is pure, `role-runner.js:1050-1052`. And the
extra snapshots are audit-neutral: `validatePostSetupState` returns early for snapshots,
and for DHT roles every field `validateDhtSnapshot` constrains is structurally fixed,
because `snapshotFields` derives them from controller, wire and exit snapshots that are all
null for those roles, `role-runner.js:740-772`.

Rejected shapes, with reasons, so they are not retried:

- Sending `stop` at the current phase with no advance at all. This closes the window
  completely and was rejected anyway: it would let a stale event from the network-change
  step be accepted during teardown, which is a real loss of the phase separation the
  equality check exists to provide. Not a check worth weakening for a 1-in-64 event.
- Draining by yielding the event loop. Timing-shaped, no ordering guarantee, and it would
  read as a fix while proving nothing.
- Reordering the loop to stop the DHT roles first, starving the exits of referrals. Too
  clever, and it perturbs the wire record the namespace oracles read.

#### The provocation

`test/private/process/teardown-phase-window-probe.js`, standalone and deliberately NOT
registered in `test/private-routing.js` so its assertions cannot move the aggregate's
counts. Run it with `node test/private/process/teardown-phase-window-probe.js`; set
`PR_BRIDGE_TRACE` to also append the trace, in the same JSON-per-line shape the bridge's
own sniffer uses, `frameSniffer` in `role-bridge.js`. It drives the REAL coordinator with a synthetic role
that is a pair of streams, and models exactly one thing explicitly: `outbound`, the bytes
that have left the role and that the coordinator has not read yet. A frame's phase is
stamped when the role emits it, which is what makes a delayed frame stale; whether the byte
landed a microsecond before or after the advance is invisible to the coordinator.

Three arms, differing only in where the coordinator's read falls relative to the advance.
0.11s for all three:

| arm       | order                                                 | result                                           |
| --------- | ----------------------------------------------------- | ------------------------------------------------ |
| `control` | advance with NO frame in flight                       | no failure - the advance alone is harmless       |
| `stale`   | advance, then read (shipped order, no grant answered) | `PROCESS_PHASE_MISMATCH (lookup-exit-a/CONTROL)` |
| `drained` | read at the current phase, then advance (fixed order) | no failure; the request is accepted at phase 5   |

The stale frame, named by the trace:

```
{"t":1786915234793.8203,"side":"probe","pid":69822,"event":"frame","direction":"role->coordinator","type":"isolated-grant-request","generation":"7","phaseSequence":"5","queued":true}
```

`phaseSequence: "5"` is the phase in force when the exit emitted it; the coordinator
advanced to 6 before reading it. The `control` arm is what makes this attribution rather
than coincidence: the same advance with no frame in flight is clean, so the frame is the
cause and not the advance. The same run also confirms the second hazard directly - a grant
answered after the advance returns `PROCESS_CONTROL_INVALID` from `coordinator.js:516`,
observed in the `drained` arm.

What this establishes and what it does not. It establishes that the window is real, that
the shipped teardown order reproduces the exact recorded failure signature on demand, that
stopping the responders alone does not prevent it, and that reading before advancing does.
It does NOT establish that this is what happened in the one field occurrence. That would
need the failing run instrumented, and it was not.

#### What is left

- A residual window remains, one round trip wide instead of the whole loop wide: an exit
  can emit between answering the drain snapshot and receiving its `stop`. It cannot emit
  twice, because granting has stopped. A COMPLETE closure is not reachable from the suite:
  it needs either events validated against the phase in force at EMISSION rather than at
  read, or the `phase-pending`/`phase-ack` pair - which is fully defined and validated in
  `control-channel.js:1023-1026` and `:1130-1137`, exercised only by the codec tests, and
  wired to nothing. That pair looks like exactly this drain barrier, designed and never
  connected.
- The same advance-while-armed shape still exists, narrower, at the exit snapshot step,
  `live-process-suite.js:391-394`: it advances all three exits' phases while the responders
  are necessarily still granting, because the resumes ahead of it need grants. Not closed by
  this change and never observed; recorded so it is not rediscovered as new.
- Whether guest starvation occurred in the field run - fixed-work timing inside the guest,
  since the four instruments below cannot see it.

#### Why the field run cannot be re-read

The load explanation for that one run is neither confirmed nor excluded. It recorded a host
load of 15.31 against 2.39-3.73 for the five runs before it, with a decaying tail across
four subsequent runs that all passed. Four instruments were considered and each is blind to
what matters:

| instrument               | why it cannot answer                                                                  |
| ------------------------ | ------------------------------------------------------------------------------------- |
| host load average        | the whole VM is one host process, so it is nearly blind to guest saturation           |
| guest `/proc/loadavg`    | host oversubscription deschedules vCPU threads without lengthening the guest runqueue |
| steal time, `/proc/stat` | flat zero; colima on Virtualization.framework does not report it                      |
| scenario wall time       | a 3s aggregate; a 20ms stall moves it 0.7% and vanishes in the 2775-3157ms band       |

A fifth does work: timestamped trace intervals inside the run, which sample at millisecond
scale and show a transient stall directly, because a descheduling in the wrong place
stretches one interval while leaving the total untouched. That run carried none, correctly,
since it was measuring the shipping tree. Any future hunt for a millisecond-scale race here
must instrument the run itself; nothing outside it can see in.

One process note, and it is NOT "read the code first", because that rule would have failed
the KI-8 investigation. Ask whether the question is STRUCTURAL or EMPIRICAL before choosing
the instrument. Structural questions ask whether something can happen, whether a path
exists, whether a state is reachable. Empirical questions ask whether it does happen, how
often, under what conditions. Nothing that cracked KI-8 was answerable from source, and
every expensive detour there was a structural question attacked empirically. This entry is
the same lesson from the other side: "can a stale frame fail the phase gate" is structural,
and a 0.11s rig answered it and the fix's adequacy together, where sixteen interleaved
three-second runs had answered neither.

#### Verification of the fix

- `process:node` 125/125 three times, 3675ms cold then 2816ms and 2819ms, both inside the
  documented 2775-3157ms band, so eleven extra round trips cost nothing measurable.
- `process:bare` 125/125.
- Host aggregate 882 tests and 18138 asserts, which was the baseline at the moment this was
  measured and is not quoted here as the standing one - other slices in the same batch
  registered tests after it. The durable claim is the delta: this change adds no test and no
  assertion, so it moves the aggregate by zero whatever the baseline is. Note also that a
  host aggregate is NOT evidence about the eleven-role scenario, which it does not contain,
  by KI-2.
- Assertion counts are unchanged everywhere because the drain adds round trips and no
  assertions. The 44 successful drain round trips across those four runs are themselves the
  evidence that a command re-sent at the phase already in force is accepted: each is awaited
  under the 5s command deadline, so a refusal would have failed the run.

### KI-12: what the first real eleven-runner dispatches found

**Status: three findings, two closed and one open. All of them are conditions no
local rehearsal can produce, which is the argument for dispatching at all.**

The rehearsal simulates distance with loopback and iptables. A dispatch has eleven
roles on separate Azure hosts with real public addresses, real NAT in front of each,
and tens of milliseconds of RTT, driven by a coordinator on a laptop behind a
domestic NAT. Three things failed in that environment that are structurally
unreachable in any local mode.

FIRST, the runtime attestation could never have passed. `role-runner.js:876-884`
refuses to configure unless a role's own runtime version equals the version the
coordinator attests. That is a deliberate fail-closed check that every process in a
run is the same build, and on one machine it is trivially true because both sides
read the same `process.version`. The workflow installed `node-version: lts/*`, which
resolves to whatever the current LTS patch happens to be, so the check could only
have passed by coincidence. FIXED by making the coordinator's exact version a
dispatch input, like the coordinator pin before it. The check itself was not
touched; relaxing it to a major version would have hidden the class of thing it
exists to catch.

SECOND, eleven concurrent role jobs exceed what the account will schedule.
Observed: nine jobs started within 25 seconds and two stayed queued past a
ten-minute discovery window, so the run failed as `role 9 never reported:
PEER_NOT_FOUND` with nothing wrong in any role. Not a code fault and not fixable in
code. Either wait longer than the queue, or host some roles where the coordinator
runs - which is supported, and is the reason placement is a dispatch input.

THIRD, AND OPEN: a role hosted behind this domestic NAT is not reachable from a
runner, even though its address is correct and stable. With the endpoint and the
three DHT roles local, every role reported an address, all eleven attested and all
eleven bound, and then the ordered DHT setup timed out at the first role. With only
the endpoint local, the same run passed DHT setup and got four assertions further.

The distinction that explains it is worth stating precisely, because the local
evidence looks reassuring and is not sufficient. Each local bridge reported
`endpointStable: true` with two independent reflectors observing the same host and
port, which establishes that the NAT's MAPPING is endpoint-independent. It says
nothing about FILTERING. These roles dial each other directly at published
addresses with no hole punching, so a NAT that only admits inbound datagrams from
addresses the host has already written to will drop a runner's first packet to a
local role while every reflector still agrees on the address. That is exactly what
was observed, and it is why an endpoint can be local but a DHT role cannot: the
endpoint initiates.

FOURTH, NOW EXPLAINED: nothing in the eleven-role plan punches, so no role-to-role
datagram has ever been delivered in a dispatch. Established by source reading:

- `role-runner.js:638-657` issues three raw `dht.request(..., tupleForRole(11),
{ retry: false })` straight to a literal address, with no `connect()` and no punch.
- `role-runner.js:166-169` resolves that to dht-value's REFLECTED public address.
- `retry: false` sets `req.retries = 0`, so dht-rpc destroys the request at
  `io.js:601` after ONE unanswered datagram - the exact frame in the stack recovered
  from the runner.
- `topology-fixture.js:1073`, `:1080`, `:1087` wire every DHT edge one way, seed to
  referral to value, with nothing pointing back. dht-value therefore never sends to
  dht-referral, its NAT holds no mapping for it, and dht-referral's first packet
  inbound is dropped. No reply is possible, and raising any timeout cannot help
  because the packet is never delivered at all.
- `grep -c punch` is zero in role-bridge.js, role-runner.js, topology-fixture.js and
  across all of lib/private.

The source read also predicts the observed boundary, which is the strongest available
consistency check: assertions 1 to 10 are all satisfiable on a completely deaf
network, and the run dies at the 11th emission.

One precision about that emission, because it is the kind of line a later reader
re-derives wrongly. The eleventh assertion RESULT is the catch-block `t.fail` at
`live-process-suite.js:509-510`, reporting the role's REQUEST_TIMEOUT thrown out of the
`Promise.all` at `:168`. The eleventh assertion in SOURCE ORDER, the audit-open class
check at `:169`, was never reached. Both statements are true of different things, and
the distinction points at opposite halves of the system: had `:169` run and failed, the
diagnosis would be that three audit opens arrived with the wrong classes, a codec or
audit-arming fault, and a reader would search `AUDIT_CLASSES` and `armSetupDhtAudit` and
find nothing wrong. The events never arrived at all. Note also that once the store
completes, `:169` WILL execute, and "assertion 11" will then mean the audit-open check
rather than a caught role failure.

This repository already solved the same problem in a sibling harness.
`test/remote-peer/mesh.js` punches at ten sites, and states the principle at
`:294-297`: every member punches the moment the plan lands so the sends cross in
flight, because that is the only way two NAT'd hosts open a path neither can open
alone. The measured result is recorded earlier in this document: 90 of 90 directed
cell-socket pairs arrived between ten runners once every member punched
simultaneously, source port intact on all 90. So the mechanism is proven here; the
eleven-role plan simply never adopted it.

FIFTH, AND ITS OWN FAULT: the DHT-setup assertions cannot fail when the DHT is deaf,
so they are not gates. `live-process-suite.js:142-145` asserts
`t.is(ready.state, 'DHT_SETUP')` per DHT role and the suite reads it as evidence that
setup worked. It is evidence that a local variable changed. `role-runner.js:600-606`
awaits `dht.ready()` and then sets that state unconditionally, and a dht-rpc query
treats a request timeout as an error it counts and continues past, with
`_bootstrapping` additionally `.catch(noop)`. So `dht.ready()` resolves on a network
where nothing was ever answered. Three green assertions covered exactly that
condition, and the first assertion with teeth was eight later. This would be worth
fixing even if reachability were perfect: an assertion that cannot fail when the
subject is dead is not a gate. The fix is for it to require an ANSWERED request -
a success count from the bootstrap query, or one round trip - rather than a state
transition.

That fix is cheap but NOT free, and the reason is worth recording because the obvious
version does not work. Event shapes are strictly validated: `control-channel.js` builds
`EVENT_FIELDS` and then calls `exactObject`, which enforces an EXACT field list rather
than a minimum, so simply attaching an answered-request count to the `ready` event throws
at validation. It takes three edits: read `dht.stats.requests.responses` after
`await dht.ready()` in `role-runner.js` `activate()` and pass it to the `ready` emit; add
the field name to `EVENT_FIELDS.ready`, which is the shared control codec at
`control-channel.js:809`; and assert it is above zero for the two roles that must have
been answered. Routing it through the `snapshot` event instead is strictly worse, since
that path needs both a digest and the same field-list change. A corollary for anyone
wanting one value out of a role quickly: anything structured must pass `exactObject`, so
an unstructured diagnostic log is the only genuinely zero-cost probe in this harness.

Kept for the record, since it was the observable symptom: the setup store does not
complete over a real network. With the
command deadline raised and EVERY role on a runner, so nothing depends on the
laptop's NAT, the run reaches 10 of 11 assertions and then dies with
`PROCESS_ROLE_FAILURE (dht-referral/CONTROL)`. The role's own stack, recovered from
the runner, is `DHTError: REQUEST_TIMEOUT` raised inside `dht-rpc/lib/io.js:601` -
dht-rpc's own request timeout, not a harness deadline and not a check failing. Some
DHT request the referral role makes is never answered. Cause not established, and I
am not going to guess it: it reproduces with all eleven roles remote, so the laptop
is excluded, and it survives a ninefold increase in the coordinator's command
budget, so it is not the harness being impatient.

One asymmetry found while looking, worth recording because it is cheap to fix and
could contribute. The cell socket's address is reflected off TWO reflectors and the
bridge reports `endpointStable` only when both agree, which is what establishes that
the NAT's mapping is endpoint-independent. The exits' second socket, the DHT socket
at `43000 + index`, is reflected off reflectors in a loop that BREAKS on the first
success, so its mapping is confirmed once and never cross-checked. If a NAT were
endpoint-dependent for that socket, the published address would be the mapping for
that one reflector rather than the one other roles will see, and requests to it
would time out exactly as observed. That hypothesis is now ELIMINATED rather than open. The DHT
socket was given the same two-reflector agreement check as the cell socket, and the
coordinator names any disagreement before minting: on a further all-remote dispatch
no exit reported a disagreement and assertion 11 failed identically. So the exits'
DHT mappings are stable, cross-checked, and not the cause. The check stays because
it turns an address nobody verified into one that is verified, but it bought a
negative result rather than a fix.

The order these were found matters for anyone repeating the exercise, because each
one hid the next: runtime attestation, runner scheduling, laptop NAT filtering,
retransmission classification, setup-store timeout, and finally the cross-host
monotonic deadline. PR #45 removed that last protocol fault.

The next reviewed dispatches crossed every boundary the earlier runs could not:
140/140 directed punch pairs, answered DHT setup, immutable store/readback, every
role READY, guard-only endpoint authority, no retained bootstrap socket, and the
first exact routed immutable get across eleven Azure hosts. That closes KI-15
end-to-end for the exercised request.

The run then exposed a harness assumption: it awaited
`isolated-grant-request` from `lookup-exit-a` as mandatory, but real DHT ordering
returned the value directly without discovering a learned closer. The local
deterministic topology always takes the referral path, so it had hidden the hang.
Role snapshots now report `isolatedGrantRequestCount`; learned-closer events remain
served when present, but scenario progress and accounting accept both valid paths.

Further dispatches separated protocol from runner/NAT allocation:

- eleven remote jobs can leave one queued beyond the workflow's maximum discovery
  window, even though the eventual Actions jobs all pass;
- one allocation opened only 2/140 punch pairs, while another opened 140/140;
- co-located roles on this workstation cannot hairpin through their shared
  reflected public address;
- two Azure relay candidates can land in the same /24, which the privacy diversity
  rule correctly rejects during activation.

These are named environmental outcomes, not reasons to relax the route. A standing
remote gate needs placement/allocation control before a green 132/132 run is
repeatable; good allocations have exercised the complete lifecycle through
teardown, and the reviewed protocol remains fail-closed on bad ones.

### KI-15: an absolute deadline is built on a host-local monotonic clock

**Status: FIXED, including a real eleven-host routed immutable get.** The wire
now carries a RELATIVE budget and each host derives its own absolute deadline from
its own clock, so no clock value is compared across hosts. This entry originally
recorded the wrong cause - that the 3000ms budget was too small - and that diagnosis
is retracted below because the way it was wrong is instructive. Full remote
132/132 remains an infrastructure-allocation gate, not an open KI-15 claim.

#### The fix

`absoluteDeadlineMs` is gone. The uint64 at request body offset 39 is now
`operationBudgetMs`, a DURATION in milliseconds. The layout is bit-identical - the fixed
body is still 221 bytes and an encoded immutable-get is still 261 - so this is a semantic
change to one field, not a wire-format change.

- The endpoint mints the budget it already derived (`routed-dht-io.js`, `ROUTE_HOPS` x
  `PER_HOP_ONE_WAY_MS` x 2 + `EXIT_DHT_REFERRAL_MS`, clamped to the exit's advertised
  ceiling) and puts THAT on the wire. Its own absolute deadline stays local and is passed
  to `live-route-authority.js` as the `operationDeadlineMs` request option. It is never
  encoded.
- The exit admits on a duration-vs-duration comparison,
  `operationBudgetMs === 0n || operationBudgetMs > policy.timeoutMs`, which needs no clock
  agreement of any kind, then derives its OWN deadline as `exitNow + operationBudgetMs` for
  the ordinary DHT reservation and the referral probe cap.
- `dht-exit-destination-table.js` likewise derives before comparing, so the checks against
  `state.absoluteDeadline` and `entry.expiresAt` are exit-domain on both sides.
- `opaque-destination.js` is untouched. Its `deadline` is minted AND verified on the
  endpoint - `createRoutedReplyReferralAuthority` and
  `createAuthenticatedRoutedReplyAuthority` are both endpoint-side - so it was never a
  cross-host comparison and stays a local monotonic absolute.

Why a relative budget and not the alternatives the earlier entry listed: a wall-clock
domain would import skew and a time-sync dependency into an admission check; an exit-minted
deadline echoed back would move who is trusted to bound the operation. The objection to a
relative TTL was that decrementing per hop leaks or bounds path length - which does not
apply here, because relays never read this field. The routed request is encrypted
end-to-end between endpoint and exit, so there is nothing to decrement and no hop count to
leak: exactly two parties read the number, and each reads it in its own domain.

The endpoint holds itself to the same bound it advertises. `requestProduction` samples its
clock once and refuses a zero budget, a budget above the exit's ceiling, and a local
deadline that either lies in the past or outlasts the advertised budget. The ceiling is
read from `EXIT_ORIGIN_SERVICE_POLICY` - the same table the exit enforces - rather than
restated as a constant, since two constants agreeing by coincidence is how this fault was
built in the first place.

What pins it: `test/private/routed-dht.js` admits ONE encoded request at exit clocks `0n`
and `10_000_000n` and refuses `0n` and `3_001n` budgets at both, and reverting the
admission check makes the far-clock arm throw `ERR_AUTHENTICATION` - the KI-15 failure
reproduced on demand. `test/private/routed-dht-io.js` mints from clocks with unrelated
origins and asserts the budget BYTES are identical while the local deadlines differ, so a
frozen clock cannot satisfy it vacuously. `test/private/live-route-authority.js` proves the
endpoint still arms a real timer off its own absolute deadline and still reports the branch
lost when it fires; feeding the wire budget to that timer instead fails the test.

Gates after the change, and after the three audit fixes it prompted, all at `e3cf206`: the
aggregate is 902/902 tests and 18326/18326 asserts under Node and 881/881 and 18267/18267
under Bare, measured in the Linux container and again on the macOS host with both agreeing
exactly; and in the container only, because they cannot run anywhere else, eleven-role live
127/127 under both runtimes, namespace 27/27, and namespace-live 137/137.

#### The fault, as it stood before the fix

`absoluteDeadlineMs` is minted from the endpoint's `monotonicNow` and compared against the
EXIT's clock in production code: `dht-exit-io.js:519` evaluates
`current + 1_000n < request.absoluteDeadlineMs`, where `current` is the exit's own sample.
So two peers' monotonic clock values are compared directly.

A monotonic clock is host-local by definition, and the harness supplies exactly that,
correctly: `test/private/process/runtime-clock.js` builds it from `process.hrtime.bigint()`
and its own comment says the clock must keep hrtime's machine-wide scale rather than
restarting per process. That is right for a monotonic clock and it is not the bug. The bug
is that the protocol compares two of them. On one host both sides share an origin, which is
why every container rehearsal and every gate passes.

Across two hosts the origins are unrelated, and admission requires
`endpointNow - exitNow` to fall inside a bounded window, so the comparison is against an
arbitrary boot-time delta. The exit therefore refuses the request outright and the
endpoint waits out its full budget.

That made this a design fault rather than a tuning error: an ABSOLUTE deadline expressed in
a RELATIVE clock domain. The three candidate domains were a wall clock, a relative TTL, and
an exit-minted deadline echoed back; the fix above takes the relative one and records why.

RETRACTED DIAGNOSIS, kept because the error is worth more than the conclusion. This entry
first read the observed 3.048 seconds as evidence that a four-hop route needs more than
3000ms. It is not: it is the signature of the endpoint's own deadline firing after the
exit rejected the request. Two checks would have caught it and neither was done before
writing it down:

- The endpoint's 3000ms is not an independent constant. It is exactly the exit's policy
  ceiling for IMMUTABLE_GET_V1, and the admitted window measures as exactly
  `[exitNow, exitNow+3000]`, with a 3001ms budget rejected as `ERR_AUTHENTICATION`. So
  raising it - which the retracted entry implied - would have reddened `process:node` and
  `process:bare` immediately while doing nothing for the dispatch.
- The measurements already in this document refute the premise. Single-link p95 round trip
  is 115.7ms, so eight transits plus the exit's 1000ms referral round is roughly two
  seconds, comfortably inside 3000.

The general lesson, since it has now cost an hour of wrong record: A TIMEOUT IS NOT
EVIDENCE OF SLOWNESS. It is evidence that something did not arrive, and a rejected request
looks exactly like a slow one from the waiting end.

One change did land from this, and it is worth keeping on its own terms: the endpoint's
budget is now derived and clamped to the exit's advertised ceiling rather than being a
second constant that must agree with the first by coincidence. It evaluates to the same
value today, so nothing on the wire or in the live path changes.

### KI-13: the punch that makes a dispatch work is in the harness, not in production

**Status: endpoint↔guard edge proven on real NAT (fourth `-p` dispatch,
run 34061028552: same-socket reflection, bilateral plan over the topology
owner's channel, punch from the production socket, authenticated bootstrap and
an exact routed get with no harness punch on that edge). Open residuals: the
remote lifecycle after readiness is unmeasured with the punched edge because
the scenario's 5 s command and rotation deadlines are loopback constants;
relay pairs still depend on the harness pre-punch; the second dispatch measured
a runner NAT that did not preserve the mapping across close-and-rebind
(production failed closed). NAT'd middles and exits remain unsupported by
decision D7: they are dialed cold at rotation time and have no pre-link
channel, so the harness pre-punch below still opens those pairs and is test
topology plumbing, not production. The paragraphs below describe the harness
and remain accurate for the relay pairs.**

The eleven-role dispatch now opens role-to-role NAT mappings before any role starts:
the coordinator distributes all eleven addresses over a fourth bridge mode byte, and
every role punches simultaneously from probes bound to the exact ports it will later
own, following the mechanism `test/remote-peer/mesh.js` already proved here.

Stated as plainly as it can be, because a green run will otherwise be read as more than
it is:

> The punch is in the harness, not in production. `lib/private` contains zero punching.
> A green eleven-role dispatch proves the SCENARIO can run across NAT'd hosts because
> `test/remote-peer/role-bridge.js` opens the mappings before any role is attached. It
> does not prove two NAT'd relays can join a route in production. The rehearsal cannot
> narrow this: identical mode passes `--reachable-host`, and the bridge's
> `if (options.reachableHost !== null)` branches skip reflection entirely when that is
> set - `role-bridge.js:452-454` for the exit's DHT socket and `:475` for the cell
> endpoint - so no local mode reflects or translates
> and 140/140 on loopback is the floor, not evidence. A rehearsal proves the frame path,
> the one-tick plan distribution and that the probes release the role's ports. Only a
> dispatch tests traversal.

When this was written, `udx-cell-endpoint.js` owned its socket with no injection
point. That seam now exists for the endpoint↔guard edge only:
`prepareEndpointNatTraversal` and `armNatPunch` punch from the production socket.

Three limits belong beside it, and together they mean a green store assertion says the
pair was open at that moment rather than that the topology is durably connected:

- Nothing refreshes a mapping for the length of a 900-second run.
- The punch sits at the earliest point in the run, so the gap to the store is the
  largest possible, and it grows with RTT while the NAT's idle timeout does not.
- `retry: false` at `role-runner.js:641`, `:649` and `:656` means one lost datagram
  still fails the store with a perfect mapping.
- The three DHT roles hold the LONGEST unbound window of any role, and they are exactly
  the ones the store depends on. `role-runner.js:532-537` has `prepare()` for a DHT role
  set `PREPARED` and bind nothing; its socket is bound only later at activate, via
  `createDhtOwner` and `dht.ready()` at `:595-597` and `:600-606`. Every other role binds
  its cell endpoint during its own prepare at `:538-539`. So for dht-seed, dht-referral
  and dht-value the port is unbound from probe-release until activate, spanning role spawn
  plus eleven configures plus eleven prepares - and the mapping-survival measurement above
  covers a QUICK rebind, not that.

AND ONE HOP NOBODY HAS MEASURED, which is precisely the seam this design rests on. Two
measurements exist and neither covers it: the record above shows a MAPPING survives
close-and-rebind, and the 90-of-90 result never rebinds at all, because `mesh.js`
punches and receives on one live socket. So nothing measures whether a NAT still ADMITS
a previously punched peer after the local socket has been closed and rebound. If a
dispatch reports a partial punch matrix, that is the first place to look.

### KI-14: a rotation re-qualifies the hop it just rotated away from

**Status: preferred-tier fault demotion is implemented for initial, reconnect,
and replacement selection.** The all-candidate tier remains available when no
preferred combination is possible; demotion is not hard exclusion. A minimal
three-plus-three pool can still require a previously faulted pair. KI-6 now
selects uniformly within the chosen tier and its harness coupling is fixed.
The rotation-only scope and harness blocker described below are historical;
the small-pool exposure remains current.

The honest cost first, because it is the part a later reader most needs and least wants.
At three middles and three exits, `reserveReplacement` already excludes the live opposite
pair and the pair being replaced — two of three middles and two of three exits — so the
only qualifying pair IS the one just vacated. The preferred tier therefore comes back
empty, the fallback admits the vacated pair, and the selection is byte-for-byte what it
was before this fix. That is not an oversight: it is the property that keeps a legitimate
rotation from failing closed, and it is why the process gates cannot go red. The fix
helps a deployment with a genuinely larger relay pool and does nothing for the minimal
one. Both halves are pinned by tests, so neither can change unnoticed.

#### The design question came first: was a reason available at all?

A rotation fires for at least two unrelated reasons. Material expiry is routine and
implies nothing about the hop. Failure or suspected misbehaviour does. The directory could
not tell them apart, so the first question was whether the signal reaching it carried a
reason, and if not, where one would have to come from.

It did carry one, and no protocol change or new signal was needed. Both triggers converge
on `issueBranchSink(state, branchClass, suffix)` in `route-manager.js` with the suffix
`'BranchLoss'` or `'BranchExpiry'`, so the four controller signal kinds —
`lookupBranchLoss`, `announceBranchLoss`, `lookupBranchExpiry`, `announceBranchExpiry` —
already encode expiry-versus-fault. The reason was discarded at exactly one place: the
four-kind case arm in `private-routing-controller.js` reads `signal.kind` only to derive a
`branchClass` and then calls `routeManager.rotate(branchClass)`. Nothing below that hop
ever saw a reason: `rotate` to `createRotationDraft` to `createReplacementBranchDraft` to
`reserveReplacement({ branchClass, generation })`.

Two seams were possible. Threading a reason down all four files would have widened two
`exactObject`-pinned lists, `REPLACEMENT_FIELDS` and `REPLACEMENT_BRANCH_FIELDS`, to carry
information the controller already had. The controller was also the wrong place to tell
the directory directly, for a reason worth recording: **the controller holds no live
directory handle.** `state.suspendedDirectory` is null except across suspend and resume,
because the directory is owned by the route manager. Hooking there would have meant adding
a handle to controller state and keeping it coherent across suspend, resume and
unavailable.

The seam used is one hop upstream, where the handle is already in hand:
`reportRouteManagerBranchLoss`. It is the manager's **exclusive** fault path — expiry
reaches `issueBranchSink` from `armBranchExpiry` under the other suffix and never passes
through it — it is where `branch.lost` is set, so it is the authoritative statement that
this branch failed for cause, and every fault source funnels through it, including the
physical-loss registration and L0's owned-route failure. The change there is one advisory
call, deliberately wrapped so a directory that cannot record the demotion still cannot
stop the branch being reported lost.

#### Demotion, not exclusion, and why hard exclusion would have been worse

Hard exclusion is the obvious reading of "fault-based exclusion" and it is wrong here.
Because the exclusion set already leaves exactly one qualifying pair at three-plus-three,
removing the just-failed pair makes the sibling rotation throw `ERR_INCOMPATIBLE_RELAY` —
so **any relay could deny the endpoint a route by failing.** That trades rewarded
observation for rewarded denial, which is a strictly worse bargain: the first costs
privacy against one adversary, the second costs availability to anyone.

Instead a faulted record is **demoted**: still eligible, but only after every unfaulted
combination has been tried. Availability is bit-for-bit unchanged, and the pool can never
be exhausted by exclusion. What the fix removes is not the suspect's eligibility but the
_reward_ — failing can no longer be a way to get selected sooner.

**This is expressed as a PARTITION, not as a position in a list, and that matters for
KI-6.** `validCandidates` returns `{ preferred, all }`, and a selection exhausts
`preferred` before admitting anything from `all`. Had the demotion been implemented as
"move faulted records to the back", a future KI-6 fix that randomises selection would have
silently disabled it. As a tier, a randomised selector may randomise _within_ a tier and
the property survives; only a selector that draws from `all` directly discards it. That
constraint is written into `relay-candidate-directory.js` as a comment on
`validCandidates`, where a KI-6 fix will trip over it, rather than only here.

One consequence recorded plainly: **candidate order — specifically the ordering between
the two tiers — is now load-bearing for a security property.** Before this fix, order was
merely an arbitrary artefact, which is what KI-6 exists to complain about.

#### The two-pair build is deliberately NOT tiered, and the reason is a measured coupling

The demotion applies to `chooseReplacementPair`, the rotation path, and NOT to
`choosePairs`, which builds both branches at once — the initial route and the bootstrap
pair after a reconnect. Two reasons, one principled and one measured.

The principled one: KI-14's harm is a rotation handing the SIBLING branch the hop it just
rotated away from, so the relay gains a second view of one live route. A build from
scratch has no sibling to protect; there is no live branch for a demoted hop to see more
of.

The measured one is the finding worth keeping. Tiering `choosePairs` turns the
eleven-role gate red: `process:node` fails at the assertion after the suspend step, with
the guard's dial rejecting — `ROUTE_UNAVAILABLE` thrown at `guard-link.js:199` from the
dial-rejected arm, reached through `openTailAdjacentLink`. **That failure is not caused by
this fix.** On pristine HEAD, with no demotion anywhere, reversing the candidate order in
`validCandidates` — one line, no faults involved — ALSO fails the gate, deadlocking at the
first routed get without ever reaching the rotation. Three runs, isolation trees from the
same commit:

| tree                                          | process:node        |
| --------------------------------------------- | ------------------- |
| pristine HEAD                                 | pass, 125/125       |
| HEAD + this fix, demotion on all paths        | FAIL at the suspend |
| HEAD + this fix, demotion on rotations only   | pass, 125/125       |
| pristine HEAD + candidate order reversed only | FAIL, deadlock      |

So the eleven-role fixture cannot tolerate ANY change to which pair first-match returns.
Tiering does not fail closed there — it succeeds and returns a different, equally valid
pair, which the fixture then cannot service.

**This is a hard blocker for KI-6 and is larger than this entry.** Randomising hop
selection would not merely weaken this demotion; it would break the eleven-role gate
outright, because the scenario depends on first-match's exact assignment of the six relay
roles to branch positions. KI-6 cannot land until that coupling is fixed, and the coupling
lives in the harness — `live-process-suite.js`, `role-runner.js`, `wire-services.js` — not
in the directory.

**What is NOT given up.** The demotion is not forgotten across a reconnect. It survives in
the directory and still binds every later rotation, so a reconnect buys a faulted relay
ONE bootstrap selection rather than a reset. That residual is asserted, with a control, by
'a demotion survives a reconnect and still binds a later rotation'.

#### The bound, and why this is not `quarantine`

The demotion lasts until the LATER of the record's own `expiresAt` and
`FAULT_DEMOTION_MS` — 60s, minted in `relay-candidate-directory.js` — from the moment of
the fault.

The floor was added after a fresh-context security review of this entry. The original
bound was the record's own `expiresAt` and nothing else, which is **a number the demoted
relay signs for itself**: the only checks on it are `expiresAt > now` at admission and
`MAX_CAPABILITY_LIFETIME` (30 minutes) as a ceiling in `relay-capability.js`, and there is
no minimum anywhere. Because a branch fault demotes BOTH hops of the failed pair, that is
an asymmetry an attacker can exercise: a malicious middle advertises a two-second
capability, blackholes the branch it is carrying, serves a two-second penalty and
re-advertises, while the honest exit it dragged down — whose expiry it does not control —
serves up to the full thirty minutes. Repeated across partners it drains honest hops out
of `preferred` while the attacker cycles back in, biasing `chooseReplacementPair` toward
attacker-controlled hops. For a heuristic penalty the duration IS the entire penalty, so
an attacker-chosen duration removes the penalty for the attacker alone. Quarantine's bound
did not carry over the way the original reasoning assumed: quarantine acts on proof of
equivocation, where the identity is already forfeit and a self-chosen duration costs
nothing. A heuristic demotion is not that.

**The invariant traded away, stated plainly.** A demotion previously could not outlive the
record it applied to, because `pruneInvalidRecords` dropped the record and the demotion on
one sweep. Under the floor it can, and that is the point: shedding a penalty by
advertising a short-lived capability and re-advertising is precisely the move being closed,
so the penalty has to be able to outlive the advertisement it was earned on. What survives
is the part that was load-bearing. The entry is still swept on `expiresAt <= now`, so a
demotion stays temporary and never becomes a bar; and the map is still bounded by
`MAX_IDENTITIES`, because only an identity already in `state.records` is ever inserted and
that set is fixed at seal and only shrinks. The floor is computed from the same wall
sample the sweep compares against, so a floored entry expires on the clock that prunes it.

60s is minted locally rather than derived: four `MAX_ROUTE_LIFETIME_MS` route lifetimes and
twelve `BRANCH_ROTATION_LEAD_MS` rotation leads, so a demotion binds several consecutive
rotations instead of lapsing inside the one that earned it, and a thirtieth of the
capability ceiling, so it stays far below the longest demotion an honest long-lived
advertisement already accepts. Deriving it from either constant would tie this module to
the route manager's and the extension's clocks for no gain, and both remain rejected as
the bound itself: a demotion shorter than the record's selectable life reopens the window
at the next rotation.

The two mechanisms are kept **separate**, and conflating them would be unsafe in both
directions. Quarantine answers a question about _identity_: one key advertising two digests
at one epoch is proof of equivocation, so a hard bar there has no false positives. A fault
is a _heuristic_ about _behaviour_ — a timeout or a physical loss can be the network, the
local host, or an unlucky but honest relay, and attribution to the hop is unproven. This
fix therefore never writes `quarantine`, and a test asserts `quarantineCount` stays zero
across a reported fault. Attribution is also to the **branch**, not to a hop: nothing in a
physical loss or an elapsed deadline says whether the middle or the exit failed, so both
hops of the failed branch are demoted.

#### What is proven, and by which test

- **A faulted hop is not handed to the sibling, measured at four-plus-four** — the shape
  where KI-14 measured reuse six times out of six. The test runs both arms over the same
  pool, and the **control is the load-bearing half**: with no fault reported the vacated
  middle and exit ARE reused, reproducing the original finding; with the fault reported
  neither is. Without that control the test would only show that some pair was selected.
- **A rotation never fails closed at three-plus-three**, on both the expiry-driven and the
  fault-driven arm, and the demoted pair is confirmed to be the one selected — pinning the
  no-effect caveat above as an assertion rather than a claim. Hard exclusion would throw on
  both arms.
- **A demotion survives a reconnect and still binds a later rotation**, with the same
  control shape: without the fault report the demoted pair IS reused one reconnect later.
  This is the property that makes scoping the fix to rotations defensible rather than a
  quiet retreat.
- **The bound is the later of the record's expiry and the 60s floor**, proven from both
  sides. A middle that signs itself a two-second capability still carries its demotion ten
  seconds later, when its own record has already been swept out of the candidate set; and a
  record advertising two minutes carries its demotion for exactly those two minutes and not
  a sweep longer. Three mutations were confirmed to bite: dropping the floor, replacing the
  record's expiry with the floor, and adding the two rather than comparing them.
- **Suspend/resume does not launder a demotion** — `retainForSuspend` clears the committed
  pairs, so without this a reconnect would be a free pardon.

#### Residual exposure, stated rather than implied

Demoting on a heuristic creates an inverse move: an adversary who can induce false
positives on honest relays shrinks the preferred tier toward itself. This is strictly
weaker than the fault it replaces — that one required only failing once — and it degrades
gracefully, because once every candidate is demoted the tier collapses and selection is
identical to today's. So an adversary gains nothing by demoting everyone; it would have to
demote exactly everyone else.

#### Effect on the branch-liveness sub-gate

`docs/private-routing-branch-liveness-design.md` records that L1's keepalive-driven
teardown must not land before fault-based exclusion exists, or failing becomes a rewarded
strategy. That precondition is now met **only for pools larger than three-plus-three**. In
the minimal shape a relay that fails is still handed the sibling branch, so L1 remains
blocked there, and the blocker is pool size rather than a missing mechanism.

#### Generation binding after refused-loss redelivery

Before redelivery, the no-yield publish/swap/revoke sequence prevented an old
physical registration from reaching a new pair through native I/O interleaving.
That argument depended on refusing and spending every report during ROTATING.
It is not sufficient once losses can survive a rotation.

`createRouteManagerBranchLossRegistration` now captures the published material's
generation. Live route IO passes its owner generation through the same
`reportRouteManagerBranchLoss` boundary. A mismatched generation is rejected
before marking the branch lost or demoting its selected pair.

Pending loss belongs to the published branch object, not to a branch-class-only
event queue. Publishing its replacement removes that standing loss. A queued
controller wakeup must still find a current manager-owned loss to start rotation.
The regression deliberately retains a physical registration across publication
and proves that issuing it cannot lose the replacement.

### KI-4: intermittent wall-clock deadline rejections on CI

**Status: the earlier two causes and the reproduced signed clock-skew rejection
are fixed. Signature, local expiry, and replay checks remain enforced.**

On 2026-09-05, collection commit `efb5051` produced:

```
not ok 73 - PROCESS_FAILURE (guard/CONTROL): ERR_AUTHENTICATION
```

The [push run](https://github.com/ayooooo123/hyperdht/actions/runs/33992418356)
passed both deterministic jobs but failed the Node process scenario immediately
after `suspend has no send-capable guard edge`. The
[companion run](https://github.com/ayooooo123/hyperdht/actions/runs/33992419663)
passed all three private-routing jobs on the same commit; the
[build matrix](https://github.com/ayooooo123/hyperdht/actions/runs/33992419669)
also passed on Linux, macOS, and Windows. These results do not clear the failure.

The first recorded stack started at `actorFailure` in `role-runner.js`, which
replaced the original error before logging it. It therefore did not identify
the originating authentication check. At that checkpoint, the cause was not
established and no runtime fix was claimed.

An isolated copy retained the original actor error stack for diagnosis and ran
eight Node plus eight Bare live process scenarios in the local Linux container.
All 16 passed 136 assertions each; the CI failure did not recur. This is a
non-reproduction, not a fix. The diagnostic copy was removed. The same
one-line stack-preservation change is now retained in the role harness:
actual `Error` objects reach the existing opt-in fatal log unchanged; a
non-Error value still gets a normalized fallback error. The control channel
still sends only `sanitizeCode(err)`. That diagnostic commit did not change
protocol acceptance and did not itself fix the authentication rejection.

A deterministic fault-path smoke injected a marked authentication error in a
temporary relay actor. Before the fix, Node logged a replacement stack and
Bare wrote no diagnostic file: the shared `require('fs')` lacked a Bare module
mapping. The package now maps `fs` to the pinned `bare-fs` development dependency
under Bare, following the existing cross-runtime import pattern.
After the fix, both runtimes logged the original marker and `Object.serve`
source stack; both control failures still contained only
`PROCESS_FAILURE (guard/CONTROL): ERR_AUTHENTICATION`. The injected fault and
temporary worktree were removed. This proves diagnostic preservation, not a
fix for the intermittent CI rejection.

#### Signed clock-skew rejection reproduced and fixed

The [next failing Bare CI run](https://github.com/ayooooo123/hyperdht/actions/runs/33993769484)
on `3c8e48f` preserved the originating stack at `completeExtensionLink`'s
ACCEPT validation. A deterministic valid signed reply with the responder
1 ms ahead of the initiator failed at `acceptedAtMs > current`.
The equivalent index-zero case failed too. An independent clock experiment
also showed how the role clock's fractional start phase can produce a signed
timestamp of `1600000001002` followed by a receiver reading `1600000001001`.
Separate real hosts can have clock skew as well; synchronizing the fixture
would hide rather than fix that protocol assumption.

Both completion paths now require the authenticated ordering
`acceptedAtMs < admittedLimits.expiresAtMs`, while retaining
`acceptedAtMs <= offerDeadlineMs`. They no longer compare the peer's accepted
time with the receiver's current time. The receiver still rejects completion
at or after its offered deadline and rejects already expired admitted limits.
Signatures, exact offer/identity bindings, nonces, one-shot pending ownership,
and proof verification are unchanged.

For extension links, admitted expiry must also remain at or before the
offered deadline. Index-zero link lifetime remains bounded by its authenticated
requested/admitted limits; the handshake deadline does not shorten that lifetime.
No clock-skew allowance constant, retry, or shared-clock fixture was added.

Both positive-skew regressions fail before the fix. After it, the focused
guard-link suite passes 51 tests and 1,059 assertions, including both skew
directions, a signed accepted time at admitted expiry, a signed time beyond
the offered window, forged signatures, late completion, cross-offer
substitution, and replay rejection. The extension cases use native UDX
ownership and production responder proofs.
The index-zero inclusive boundary is also pinned: a signed accepted timestamp
equal to the offered deadline can complete before that deadline while retaining
the longer authenticated link lifetime. Changing the rejection from `>` to
`>=` in an isolated module-loading mutation makes that regression fail.

Historical evidence for the two established causes follows.

Three fail-closed rejections on the GitHub `ubuntu-latest` runner, in three of
the twelve `live-linux` executions observed before the fix below, all tied to a
wall-clock boundary and none reproducible on the local arm64 Linux VM.

Signature A, in the eleven-role scenario around the suspend step, seen in both
the Node-roles and Bare-roles variant:

```
not ok 62 - PROCESS_FAILURE (announce-middle/CONTROL): ERR_AUTHENTICATION
```

Signature B, in the Bare aggregate during the initial branch build:

```
ERR_PRIVACY_UNAVAILABLE
    at sealTailExtend (lib/private/tail-control.js:892)
    at RouteExtensionSession.open (lib/private/route-extension.js:418)
    at openInitialBranch (lib/private/private-routing-controller.js:586)
```

Signature C, in the Bare aggregate at adjacent-link setup, and the one that
carried enough stack to be actionable:

```
ERR_AUTHENTICATION
    at createExtensionLinkOffer (lib/private/guard-link.js:2199)
    at openTailAdjacentLink (lib/private/tail-control.js:3050)
    at Object.serve (test/private/hosted-tail-fixture.js:220)
```

**C is fixed, and it was a harness defect.** `createExtensionLinkOffer` converts
a wall duration into the monotonic domain and rejects a derived deadline above
the one it was handed. Four test sites supplied `wallNow` and `monotonicNow` as
two independent `() => BigInt(Date.now())` calls, so a millisecond boundary
falling between the samples inflated the derived deadline by exactly one
millisecond. `test/private/coherent-clock.js` now derives both from a single
cached sample, the same guarantee `runtime-clock.js` already gave the role
runtimes. Signature A plausibly shared this cause, since the eleven-role fixture
was one of the four sites, though that is not proven.

Eight consecutive `live-linux` runs passed after the fix, against roughly one
failure in four before it. That is evidence, not proof: at the earlier rate,
eight clean runs would happen by chance about one time in eight.

**B is now fixed.** The deterministic characterization is now the regression
`TailControl keeps committed limits valid when only the operation deadline shortens`:
limits whose expiry equals the authenticated route lifetime seal both with the full
operation window and with that operation window shortened by one millisecond.

The fault was a two-bound model representing three different facts. The replacement
deadline snapshot keeps:

- `wireExpiresAt`, the immutable authenticated wall-clock route lifetime;
- `routeLocalDeadline`, its coherent monotonic projection, sampled once and retained;
- `operationDeadline`, a separately mutable local timeout for the current operation.

An operation may shorten only `operationDeadline`. An authenticated earlier proof/request
wall expiry is always projected from the retained `(wireExpiresAt, routeLocalDeadline)`
anchor, never from the mutable operation deadline and never from fresh clock samples.
TailControl carries the final M3 monotonic high-water across ownership, rejects rollback,
reserves one-shot transitions before every injected clock call, and rechecks the operation
deadline after the clock-bearing final route take before publishing its transport.

No protocol frame, transcript, admitted-material key, or final-handoff key changed. The
fix separates actor-local scheduling from the route lifetime the peer authenticated.

#### Pre-fix diagnosis retained

The shortening was not exotic. `createTailControlSession` shortened whenever the
`absoluteDeadline` it was handed was below the tail's local projection, and the old
`shortenM3TailLifetime` moved `wireExpiresAt` down by the same delta. But the value
`RouteExtensionSession` handed it was an _operation_ budget, bounded by
`MAX_EXTENSION_MS`, not a statement about how long the route should live. Narrowing one
extension window therefore shortened the route's wire lifetime and made limits committed
against the longer lifetime unpresentable.

Choosing a remedy has an overhead dimension, so the shortening was measured
across one aggregate run. It fires 48 times: 28 from `createTailControlSession`
and 20 from the rearm path. Twenty-four of those lose 13,000 ms of wire lifetime
each, and the granted lifetime at seal clusters at 4,000 ms where a shortening
happened against roughly 14,990 ms on the one real-clock path where none did.
Those absolute numbers are fixture-scale rather than production, but the ratio
is the mechanism: narrowing the operation window shortens the route's wire
lifetime one for one.

That reverses the earlier preference order. Adding headroom at negotiation buys
robustness by making every route permanently shorter, which raises the rotation
rate and therefore the branch-build cost, the most expensive operation in the
system. Decoupling instead is free and cuts overhead: how long a handshake may
take and how long a route may live are different quantities, and only the first
should be bounded by `MAX_EXTENSION_MS`. It also removes the shortening that
invalidates committed limits, so the performance choice and the correctness
choice coincide.

The implementation cost of decoupling was retaining the authenticated wall/local route
pair while carrying the operation deadline independently through TailControl. A rejected
one-line attempt preserved `wireExpiresAt` but projected later proof expiries from the
already-shortened operation deadline; it mapped `(wire, routeLocal)=(20,000,29,000)`,
operation `16,000`, proof `4,500` to `500` instead of `13,500` and broke normal tail
completion. That failure is why all three bounds are explicit.

Instrumenting every `sealTailExtend` in the private aggregate and recording the
distance from the requested wire expiry to each bound gives, identically under
Node and Bare, over 44 seals:

| `tailWireExpiresAt - requested` | seals                                                                |
| ------------------------------- | -------------------------------------------------------------------- |
| -1 ms                           | 1, from a deliberate negative test in `test/private/tail-control.js` |
| 0 ms                            | 21                                                                   |
| 2,000 ms                        | 20                                                                   |
| 4,000 ms                        | 1                                                                    |
| 5,499 ms                        | 1                                                                    |

Both real seals in `test/private/route-extension.js` sit at exactly 0. The
advertisement is never the binding bound: its slack on the real-clock paths is
about 45,000 ms.

So the protocol routinely asks for precisely the tail's wire deadline, and
passes only because the comparisons are strict `>`. Three sites share the shape,
all against `state.deadline.wireExpiresAt`:

- `sealTailExtend`, throwing `ERR_PRIVACY_UNAVAILABLE`, which is signature B;
- `clampTailControlProofDeadline`, whose next line treats `===` as the normal
  path and whose `>` calls `authentication()`, which is signature A;
- the responder mirror in the extend-admission path.

A single millisecond of divergence between the two independently derived wall
values therefore turns a normal operation into a fail-closed rejection. That is
the same hazard already recorded for the role clocks further down this document,
where independent `Date.now()` and `hrtime` samples straddling a millisecond
boundary produced exactly this rejection and were fixed by deriving both from
one cached sample. The production path still has the hazard between the extend
requester and the tail state.

Both rejections are fail-closed. The route build aborts rather than continuing
with an expiry the relay never authorised, so this is an availability defect
under load, not a privacy one. It must not be retried away: zero margin means
the next perturbation reproduces it.

The obvious remedy does not work, and the reason narrows the fix usefully.
Having the requester ask for slightly less than the bound was tried and
reverted: `expiresAtMs` is not the requester's to choose. It is proposed by the
peer in `LINK_ACCEPT`, hashed by `digestAdmittedLimits(accept.admittedLimits)`
into `admittedLimitsDigest`, and bound into the M3 transcript, so
`authenticateRequestedLimitsDigest` rejects any request that does not present
exactly the accepted bytes. Lowering the value client-side fails authentication,
correctly. That also explains why the zero margin is so consistent: the request
is stable across derivations precisely because the deadline term binds it, which
is load-bearing rather than accidental.

The alternatives remain rejected. Negotiation headroom permanently shortens every route
to buy transient operation slack; comparison tolerance relaxes an authentication bound;
and fresh reprojection loses the one coherent wall/monotonic anchor. The shipped model
instead removes the second derivation: authenticated route values remain stable while the
local operation expires independently.

The two bounds in `sealTailExtend` are now thrown separately so a stack
attributes a future rejection to the one that fired. Same error, same
fail-closed behaviour, no wire or semantic change.

Instrumentation is in place for the next occurrence. Setting `PR_ROLE_FATAL_LOG`
makes each role append its stack to that file, the coordinator forwards that one
variable into the otherwise empty role environment, and the Linux CI job prints
the file whenever a scenario step fails. The control channel still carries only
a strict error code, so no diagnostic text reaches the wire.

### KI-5: subnet diversity is a weak proxy for operator diversity

`validatePathDiversity` requires the guard and all four branch positions to
differ by identity and by endpoint subnet, /24 for IPv4 and /48 for IPv6. That
stops the naive case of several hops behind one address block, and it fails
closed rather than relaxing.

It does not stop an adversary who rents addresses across many blocks, which is
cheap. Real diversity would key on autonomous system, hosting provider, or a
declared operator family, none of which the advertisement carries today. Veilid
uses the same IP-block proxy and additionally relaxes it away on small networks,
so this is a shared limitation of the approach rather than something to copy
from elsewhere.

Until relay identity has a cost, path diversity constrains the shape of an
attack without bounding the attacker's share of the candidate set.

### KI-6: hop selection is first-match, not random — FIXED

**Status: FIXED.** Initial, reconnect, and replacement selection now draw
uniformly over the valid diverse ordered combinations in one chosen demotion
tier. The preferred tier is counted and exhausted first; the all-candidate tier
is considered only when the preferred count is zero. Candidate order is now only
the enumeration order behind the random index.

Selection is allocation-flat in the size of the combination space: one pass
counts valid combinations, rejection sampling draws an unbiased index, and a
second pass walks to that index. No combination array is materialized. A
three-middle/three-exit directory has exactly 36 valid ordered quads. Fixed draws
0 through 35 select all 36 in enumeration order; draw 0 selects
`middle-1/exit-0, middle-2/exit-1`, and draw 35 selects
`middle-3/exit-2, middle-2/exit-1`. The four valid replacement pairs after a
four-plus-four fixture's initial two pairs are likewise reached by draws 0
through 3.

Counts up to 256 use one random byte; larger bounded counts use two. The
eight-plus-eight maximum-shape fixture has 3,136 valid ordered quads and requests
two bytes. A singleton spends no entropy. For the 36-combination case, byte 252
is rejected and byte 35 selects index 35 rather than introducing modulo bias.
Repeated rejection is capped at 128 draws and invalidates the directory, so a
hostile entropy callback cannot retain ownership or loop forever.

The sink's exact source contract now owns `randomBytes` beside both clocks and
threads it through the sealed token into the directory. The initial endpoint
passes its already-injected capability; reconnect uses the existing
`cryptoSuite.randomBytes` capability already passed to bootstrap IO at that
construction seam. Every constructor validates own data exactly. Throwing,
malformed, endlessly rejecting, reentrant, and destroy-during-draw callbacks
clear candidate ownership, retain no callback, and publish no reservation.

The original blocker was the eleven-role fixture, not the directory. It minted only
three matched middle-to-exit grants (`3-4`, `5-6`, `7-8`), while a directory of
three middles and three exits has 36 ordered diverse quads and only six use those
matched pairs. Uniform selection therefore produced a harness-servicable topology
only one time in six.

The fixture now models the production contract:

1. `ALLOW_EDGES` and signed topology grants contain the full 3x3 middle/exit
   bipartite matrix.
2. Every middle receives all three exit contacts/grants and resolves the
   authenticated selected identity and endpoint dynamically.
3. Every exit atomically pre-arms all three possible predecessor grants. The
   endpoint-selected opaque source handle is preserved through the role callback;
   a boolean-only TEST_ONLY matcher dispatches the datagram only to the exact
   session that owns that live source relation. No tuple, identity, or handle is
   exposed.
4. Winner/loser cleanup is one ownership transaction. A teardown lock and shared
   completion promise prevent new acquisition or overlapping fault/destroy from
   missing held sessions; cross-arm packets consume no grant.
5. Snapshots expose only nullable reciprocal role indexes. The coordinator derives
   active lookup, announce, standby, rotation, and the physical-fault target from
   those relationships and observed counters rather than role labels.

Before production randomness was enabled, the corrected harness proved both
candidate orders with different fixed first-match paths and a state-derived fault
target. Restoring the fixed `lookup-middle-a` target made the reverse run fail at
assertion 45, proving the mutation reached the formerly coupled path. That was
the structural prerequisite; selection is no longer pinned to either recorded
pairing.

One shortcut is worth ruling out explicitly, because it looks cheap. Pinning the
draw inside the harness so the first combination always wins would keep the gates
green without generalising anything. It does not work. The harness passes the real
`cryptoSuite.randomBytes` into `createEndpointBootstrapAuthority` at
`role-runner.js:234`, and that same capability supplies bootstrap nonces, so it
cannot be pinned in isolation. Pinning only the draw means a second,
selection-only entropy capability whose only caller is the harness, and it would
make middle i with exit i a permanent fixture assumption, which is the coincidence
the `exitPairs` correction below removed. It buys green gates by having them prove
something production would not do.

The production draw exposed a real reconnect race, not a harness race: the
preferred tier can legitimately redraw a pair that was live immediately before
suspend, while its remote circuit still owns the link grants. Waiting on the
1.5-second link-liveness bound does not release it because the old middle and exit
continue heartbeating each other.

Suspend now performs an authenticated end-to-end teardown before publishing
reconnect authority. `BRANCH_TEARDOWN_V1` (`0x0027`) travels endpoint → guard →
middle → exit and `BRANCH_TEARDOWN_ACK_V1` (`0x0028`) returns only after each
downstream actor has drained operations and joined its link/grant release. Both
carry the exact branch class, branch ID, circuit ID, generation, intentional
suspend reason, and a nonzero 16-byte teardown ID in one 58-byte M3 datagram body.
Same-ID retries are idempotent, completed exits can resend a bounded cached ACK,
and a different ID is replay-fatal.

The endpoint retries at the existing 500ms link-ping cadence under the existing
5s circuit-teardown deadline. Timeout, malformed ACK, release failure, network
change, or destroy cancels both branch transactions and enters `UNAVAILABLE`;
release is never inferred. Success ordering is exact: stop applications, settle
both exit releases, settle middle then guard downstream releases, receive both
ACKs, destroy both branch materials, retain the directory, suspend the guard
lease, then publish reconnect authority. The eleven-role test still calls
suspend → resume directly; there is no coordinator-only prepare command or
pre-resume barrier.

Final Linux process gates pass through teardown in all four required modes:
normal Node 132/132, normal Bare 132/132, reversed Node 132/132, and reversed
Bare 132/132. Host-only aggregation remains insufficient evidence because the
eleven-role scenarios are excluded from `test/private-routing.js`.

Focused teardown proofs pass: M3 48/48 tests (373 assertions), DHT exit 8/8
(52), route manager 19/19 (280), controller 8/8 (77), protocol 14/14 (755),
live authority 11/11 (63), and process services 4/4 (46).

Mutation proofs are load-bearing. Replacing the unbiased draw with fixed index
zero makes the directory suite fail 27/31 tests with only one of 36 combinations
reachable. Drawing reconnect bootstrap pairs directly from `all` makes the KI-14
test fail both assertions that the faulted middle and exit are not redrawn.
Removing teardown send, acknowledging before downstream release, accepting a
different teardown ID, disabling retry, treating timeout as success, or
publishing reconnect after only one ACK each fails its focused ordering gate.

## Comparison with Veilid

Reviewed `veilid-core/src/routing_table/route_spec_store` on `main`, since Veilid
solves a closely related problem on a permissionless P2P network.

Veilid composes a route from a sender-allocated safety route and a
destination-published private route, one hop each by default. Allocation tries
progressively looser passes, `UniqueIpblockDiverse` then `Unique` then
`AllowDuplicateHops`, crossed with a relay-capability preference of all hops,
last hop only, then none, over a high-pass-filtered slice of the routing table.
Selection sorts candidate routes by whether they need testing, then stability,
then latency, and round-robins among the top tier with an atomic counter.
Allocated routes are persisted and reused, and a caller may pin a preferred one.

Three things were checked against that design:

- **Nodes learned through a route.** Veilid had to isolate nodes discovered only
  via a private route so the general routing table does not ping them, which
  would correlate a route participant with an IP. That exposure does not exist
  here. `relay-candidate-directory.js` performs no network I/O at all, and after
  readiness the endpoint holds no direct send authority, which the namespace
  oracle already proves by observing that its only edge is its guard.
- **Hop diversity.** Present, and stricter. Ours applies across the guard and
  both branches at once and fails closed; Veilid's equivalent is dropped on
  small networks.
- **Exclusion when rebuilding.** Present. `chooseReplacementPair` takes an
  exclusion set and diversity is revalidated at commit.
- **Which qualifying hops get chosen.** A genuine gap, open, recorded as
  [KI-6](#ki-6-hop-selection-is-first-match-not-random). Veilid round-robins
  among its top tier, which distributes load but stays predictable. We take the
  first match, which is worse: it is fixed rather than merely predictable.

Two of Veilid's choices are deliberately not adopted. Latency-ranked selection
prefers well-resourced relays, which is exactly what a funded adversary can most
cheaply supply. Silent relaxation of diversity trades a privacy property for
availability without telling anyone; for this system "no route" is a better
failure than "worse route".

Two real differences remain in Veilid's favour or as future work. Veilid hides
the destination as well as the sender, whereas here the exit performs an ordinary
DHT operation and the capture shows the retrieved value plainly on that edge.
Veilid also maintains a pool of routes and distributes across it, where this fork
builds one set per generation; a pool would be the prerequisite for choosing
among qualifying routes at all.

## Reviewed prototype source

Every migrated module below came from the reviewed private-routes prototype at exact commit `0305df915b6a767093f9e75e6c06bc0a35da6169`. The migration changed ESM imports and exports to HyperDHT's CommonJS module style, changed local import paths, and retained the listed focused/vector coverage. Subsequent fork review added defensive ownership, hostile-shape handling, intrinsic capture, bounded allocation, and clearing checks without intentionally changing the listed normative protocol bytes.

| Migrated private file                      | Exact prototype source and commit                                                                                                                                                                                    | CommonJS adaptation and retained focused/vector coverage                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `lib/private/errors.js`                    | `packages/private-routes/lib/errors.js` at `0305df915b6a767093f9e75e6c06bc0a35da6169`                                                                                                                                | ESM exports became a CommonJS object containing frozen error-code registries and the error class. `test/private/protocol.js` retains the error assertions adapted from prototype `test/protocol.test.js` and `test/m3-protocol.test.js`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `lib/private/protocol.js`                  | `packages/private-routes/lib/protocol.js` at `0305df915b6a767093f9e75e6c06bc0a35da6169`                                                                                                                              | ESM imports/exports became local `require()` calls and a CommonJS object containing frozen registries, maps, and values plus codec helpers. `test/private/protocol.js` retains the protocol, message-ID, domain, role, strict-shape, and hostile-buffer vectors adapted from prototype `test/protocol.test.js` and `test/m3-protocol.test.js`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `lib/private/crypto-suite.js`              | `packages/private-routes/lib/crypto-suite.js` at `0305df915b6a767093f9e75e6c06bc0a35da6169`                                                                                                                          | ESM imports/exports became CommonJS using HyperDHT's existing `sodium-universal`, `hypercore-crypto`, and `b4a` dependencies. `test/private/crypto-suite.js` retains generic transcript/KDF, X25519, nonce, substitution, and clearing vectors adapted from prototype `test/crypto-suite.test.js` and relevant `test/adversarial.test.js` cases. Exact M3 transcript construction is intentionally absent.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `lib/private/counters.js`                  | `packages/private-routes/lib/counters.js` at `0305df915b6a767093f9e75e6c06bc0a35da6169`                                                                                                                              | ESM exports became CommonJS; counter semantics and bounds remain covered by `test/private/counters.js`, adapted from prototype `test/counters.test.js` and the counter cases in `test/adversarial.test.js`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `lib/private/cell-codec.js`                | `packages/private-routes/lib/cell-codec.js` at `0305df915b6a767093f9e75e6c06bc0a35da6169`                                                                                                                            | ESM imports/exports became CommonJS with local private-module paths. `test/private/cell-codec.js` retains exact layout/hash, padding, authentication, substitution, allocation, hostile-buffer, and clearing coverage adapted from prototype `test/cell-codec.test.js`, `test/property.test.js`, and `test/adversarial.test.js`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `lib/private/route-payload.js`             | `packages/private-routes/lib/route-payload.js` at `0305df915b6a767093f9e75e6c06bc0a35da6169`                                                                                                                         | ESM imports/exports became CommonJS with local private-module paths. `test/private/route-payload.js` retains exact payload, direction/class/generation substitution, replay, ownership, nonce, and clearing coverage adapted from prototype `test/route-payload.test.js`, `test/property.test.js`, and `test/adversarial.test.js`. Gate 3A retains a fail-closed process-local ceiling of 4,096 nonce-domain claims; durable generation ownership is deferred.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `lib/private/fragments.js`                 | `packages/private-routes/lib/fragments.js` at `0305df915b6a767093f9e75e6c06bc0a35da6169`                                                                                                                             | ESM imports/exports became CommonJS and the reviewed Gate 3A resource ceilings were reduced and made explicit. `test/private/fragments.js` retains and extends prototype `test/fragments.test.js` and fragmentation cases from `test/property.test.js`, including ceilings, expiry, allocation order, conflict handling, ownership, and clearing.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `lib/private/exit-policy.js`               | `policyEntry`, the nine `EXIT_ORIGIN_SERVICE_POLICY` entries, and policy encode/decode/digest pieces from `packages/private-routes/lib/final-exit.js` at `0305df915b6a767093f9e75e6c06bc0a35da6169`                  | Only the immutable policy pieces were extracted into CommonJS; live exit state, socket ownership, and activation were not migrated. `test/private/exit-policy.js` retains the exact policy bytes/digest and immutability assertions adapted from prototype `test/final-exit-activation.test.js`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `lib/private/routed-dht.js`                | `packages/private-routes/lib/routed-dht.js` at `0305df915b6a767093f9e75e6c06bc0a35da6169`                                                                                                                            | ESM imports/exports became CommonJS and the policy import points to the extracted local module. `test/private/routed-dht.js` retains exact destination/request bytes, policy equality, branch, deadline, size, hostile-shape, and clearing coverage adapted from prototype `test/routed-dht.test.js` and the policy assertions in `test/final-exit-activation.test.js`. The prototype supplies no routed-reply wire codec, so none is claimed here.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `lib/private/relay-capability.js`          | `packages/private-routes/lib/relay-capability.js` at `0305df915b6a767093f9e75e6c06bc0a35da6169`                                                                                                                      | Gate 3B1 retains the exact advertisement, endpoint, DHT-node-ID, provider-policy, CAPS-cookie, active-challenge, response, signature, and digest bytes covered by prototype `test/relay-capability.test.js`. The CommonJS migration narrows accepted capability masks to circuit-only safety relays (`1`) and circuit-plus-DHT private exits (`3`), adds strict own-data validation and defensive ownership, and replaces the prototype directory state machine with the internal `RelayCapabilityVerifier` epoch, quarantine, active-proof, clock-rollback, expiry, and erasure owner tested by `test/private/relay-capability.js`. It exposes no public discovery or dialing API.                                                                                                                                                                                                                                                                                                                                                                                          |
| `lib/private/link-setup.js`                | `packages/private-routes/lib/link-setup.js` at `0305df915b6a767093f9e75e6c06bc0a35da6169`                                                                                                                            | CommonJS port retaining exact LINK CREATE/CREATED vectors, one-shot ticket ownership, replay bounds, timer behavior, hostile crypto adapters, and deep zeroization from prototype `test/link-setup.test.js`, now in `test/private/link-setup.js`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `lib/private/topology-grant.js`            | `packages/private-routes/lib/topology-grant.js` at `0305df915b6a767093f9e75e6c06bc0a35da6169`                                                                                                                        | CommonJS port retaining the exact signed-grant bytes, adjacency/role checks, bounded grant and link-handle tables, replay tombstones, long-horizon timers, reentrant callback cleanup, and destroy behavior from prototype `test/topology-grant.test.js`, now in `test/private/topology-grant.js`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `lib/private/link-parameters.js`           | Pure admitted-limit functions from `packages/private-routes/lib/tail-control.js` and pure payload-parameter functions from `packages/private-routes/lib/final-exit.js` at `0305df915b6a767093f9e75e6c06bc0a35da6169` | One CommonJS owner freezes the exact 26-byte admitted-limit and 20-byte payload-parameter formats and their registry digests. No tail or final-exit state was imported.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `lib/private/guard-link.js`                | Index-zero portions of `packages/private-routes/lib/guard-link.js` at `0305df915b6a767093f9e75e6c06bc0a35da6169`                                                                                                     | Intentionally partial CommonJS port exposing only index-zero offer/responder/complete/abort and established-link ownership. `test/private/guard-link.js` retains the exact fixed messages, transcript digest, mutual contexts, substitution/replay/reentry cases, and destruction checks. Tail extension, redacted responder proof, adjacency adoption, and final-exit paths remain deferred to Gate 3B1 Chunk 2 tasks.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `lib/private/bootstrap-envelope.js`        | `packages/private-routes/lib/bootstrap-envelope.js` at `0305df915b6a767093f9e75e6c06bc0a35da6169`                                                                                                                    | CommonJS port retaining the exact 1,200-byte envelope, 150-byte header, signature domain, request/body bindings, bilateral link ownership, five-second deadline, pending/cache/tombstone bounds, replay handling, allocation order, and reentrant adapter cleanup from prototype `test/bootstrap-envelope.test.js`, now in `test/private/bootstrap-envelope.js`. The source tuple remains out-of-band and no wire field was added.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `lib/private/bootstrap-io.js`              | Cold-start authority narrowed from `packages/private-routes/lib/bootstrap-io.js` at `0305df915b6a767093f9e75e6c06bc0a35da6169`                                                                                       | Gate 3B1-only owner for one to three numeric configured endpoints, at most sixteen signed candidates, sequential prospective-guard challenges, one ten-second budget, redacted exposure, exact index-zero establishment, Task 3 directory sealing, generic-send revocation-before-resolution, and atomic one-shot guard-pin transfer. Task 5 replaces the old fake M3 handoff with one opaque reservation, opens the shared LINK CREATE/CREATED session under the absolute operation and signed-advertisement deadlines, awaits establishment, and pins that exact token. The Task 4 fake-datagram boundary implements the same nonforgeable open/pin contract. It has no public state callback, DNS, referral, fallback, middle, or exit contact surface.                                                                                                                                                                                                                                                                                                                   |
| `lib/private/guard-reconnect-authority.js` | Adapted from `packages/private-routes/lib/guard-revalidation-io.js` at `0305df915b6a767093f9e75e6c06bc0a35da6169`                                                                                                    | Replaced the broad revalidation IO with one zero-argument WeakMap capability permanently bound to the pinned identity, canonical tuple, advertisement digest/epoch/expiry, local identity, and a single five-second operation. Task 5 permits the transport to be obtained only through a zero-argument one-shot exact-tuple factory after the authority becomes spent; the previous direct fake transport remains solely for focused compatibility tests. It performs only self-CAPS, active challenge, and index-zero guard link setup; revoke before/during IO is terminal.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `lib/private/m3-context.js`                | `packages/private-routes/lib/m3-context.js` at `0305df915b6a767093f9e75e6c06bc0a35da6169`                                                                                                                            | CommonJS port retaining the exact 54-byte associated-data layout and fixed 1,101-byte context envelope from prototype `test/m3-vectors.test.js` and `test/m3-adjacency-runtime.test.js`. `test/private/m3-context.js` freezes the byte vector and rejects field, direction, version, width, authentication-tag, nonce-counter, and trailing-byte substitution.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `lib/private/link-bootstrap-session.js`    | `packages/private-routes/lib/link-bootstrap-session.js` at `0305df915b6a767093f9e75e6c06bc0a35da6169`                                                                                                                | CommonJS port of the exact LINK CREATE/CREATED adjacent bootstrap lifecycle. Gate 3B1 additionally requires inherited `absoluteDeadline` and `signedExpiry`; the session can use only `min(start + 5,000, absoluteDeadline, signedExpiry)`. Focused Node/Bare tests cover identical retry bytes, one-shot establishment, opaque link ownership, delayed route-extension budget, rejection, and deterministic close.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `lib/private/link-control-session.js`      | Adjacent-link portions of `packages/private-routes/lib/link-control-session.js` at `0305df915b6a767093f9e75e6c06bc0a35da6169`                                                                                        | Narrow CommonJS port retaining fixed link-control wire bytes, CONTROL/STREAM ordering, DATAGRAM replay delivery decisions, bounded ACK state, 500 ms ping, 1,500 ms unresponsive close, five-second ACK/circuit teardown, counter exhaustion, opaque direction capabilities, and clearing. Prototype remote-actor and async route-control integrations are deliberately absent from this Task 5 owner.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `lib/private/udx-adapter.js`               | `packages/private-routes/lib/udx-adapter.js` at `0305df915b6a767093f9e75e6c06bc0a35da6169`                                                                                                                           | CommonJS adapter pinned to direct runtime dependency `udx-native@1.20.7`; it owns the reviewed internal symbol registry and platform-specific numeric loopback selection without adding any public dial API.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `lib/private/udx-cell-endpoint.js`         | Adjacent socket-owner portions of `packages/private-routes/lib/udx-cell-endpoint.js` at `0305df915b6a767093f9e75e6c06bc0a35da6169`                                                                                   | Sole native UDX instance/socket owner for one role process, with exact tuple/identity/generation reservations, PENDING/OPEN demultiplexing, 64-packet and 76,800-byte global queue bounds, per-peer inbound bounds, atomic reservation before packet copying, listener/native-send/socket close ordering, opaque local-secret/bootstrap authorities, pin-time direct-send revocation, and shared `GuardLeaseMaterial`. Established ownership binds and consumes an opaque internal token rather than exposing endpoint/session reservations. Lease destruction closes the original established owner exactly once. The zero-argument reconnect factory starts and awaits that same close before creating and binding a fresh socket owner, remains exact-tuple and one-shot, and closes the fresh owner on setup failure or revocation. Fake adapters are reachable only through the symbol-keyed one-shot test issuer; production Node/Bare loopback tests use the default native adapter. Prototype actor-control paths are excluded with the narrowed link-control owner. |

### Gate 3B1 authenticated M3 transport and tail ownership amendment

The exact Task 5 production contract now lives in the Gate 3B1 design's
[`AdjacentLink`](superpowers/specs/2026-07-18-private-routing-gate-3b1-live-immutable-get-design.md#adjacentlink)
section. The exact Task 6 stable owner, logical lifetime, authenticated
transport borrower, responder stages, forwarding, final-exit, and destruction
contracts live in the
[Task 6 responder-authority design](superpowers/specs/2026-07-19-private-routing-task6-private-responder-authority-design.md).
Those sections, not provisional structural objects, are the migration
boundary.

Migration must preserve these compatibility rules:

1. `udx-cell-endpoint.js` remains the sole UDX socket and established-record
   owner. An OPEN record first issues a slot-reserving one-shot
   `M3CellLinkTransferIssuer`; lexical `guard-link.js` authentication
   separately issues the exact `M3AuthenticatedBranchBinding`.
   `registerM3CellLinkTransfer(issuer, binding)` consumes and joins both,
   compares endpoint/link/setup, tuple/peer, link provenance, M3
   branch/circuit/generation/cell directions, and record-owned physical policy,
   then issues `M3CellLinkTransfer`. Revoke/failure removes tentative
   registration/charges and releases the slot exactly once. No production or
   test migration may replace either proof with a structural channel or fake
   issuer.
2. Existing 64-packet/76,800-byte global and 8-packet/9,600-byte per-peer UDX
   bounds remain exact. Record-bound `{ epoch, circuitId, direction }` M3
   dispatch uses the M3 branch/runtime generation as offset-4 `epoch`; the
   established LinkControlSession epoch is separate provenance checked during
   issuer registration, transfer take, and adoption. The specified
   four/shared or one/non-shared borrower limits, two initiator or one
   responder receive reservations, and full 1,200-byte receipt/envelope
   charges are additive. Logical release returns every charge/registration
   without closing a shared GuardLease physical link.
3. Non-shared relay M3 runtime ownership moves only the exact opaque
   `physicalOwner`; shared pinned-guard runtimes never gain physical close
   authority. `extension-setup-channel.js`, `guard-link.js`, and
   `M3AdjacencyAuthority.adopt` move the issuer, authenticated binding, and
   registered transfer instead of reading `physicalChannel.destroy`.
4. Task 6 takes the authenticated borrower into one stable `TailControlOwner`
   and independently timed `M3TailLifetime`. Client completion, both successor
   sessions, RouteExtension transfer, final-exit handoff, and Task 7/Task 9
   same-runtime activation move that same state; none creates a replacement
   deadline, timer, transport, lifetime, or borrower.
5. Clean cutover removes structural `tailControlTransportFactory` input and a
   consumer `.destroy()` method. The session remains exactly five methods;
   destruction and borrowing use package-private `destroyTailControlSession`
   and `borrowTailControlTransport`.
6. Responder forwarding carries the stable owner through a one-shot
   `TailForwardingTransfer`. `completeTailExtend` emits the exact frozen
   `{ transfer, publicationClaim }` runtime-event payload, and the registry
   presents that object-identical claim when taking the transfer synchronously.
   Its exact M3 lease owns lifetime/callback and both borrower identities; the
   taken value carries opaque owner, lease, claim, and forwarding facade. The
   registry publishes both runtime records before an exact receipt permits
   logical lifetime/transport release. Clock/deadline mismatch fails
   publication; every rollback destroys the pair and releases both slots. No
   facade-only transfer or hidden-claim lookup is compatible.
7. `final-exit-activation.js` alone issues
   `FinalExitActivationClaim`/`FinalExitActivationOwner` and exposes the exact
   `claimFinalExitActivation` operation. Its fixed prepare/commit/revoke bridge
   keeps `TAIL_CONTROL_OWNERS` lexical, verifies the live handoff,
   lifetime/callback/clocks/deadline/generation, and routes cleanup from either
   module without accepting an arbitrary destructor.
8. Task 7 ports the terminal DHT-exit ACTIVATE/READY/ACK/OPEN codec and
   derivation layer, binds READY signing to a relay-identity-owned
   `DHT_EXIT_READY` one-shot signer, and keeps endpoint actors on claimed
   activation owners instead of raw identity secrets, raw handoff material, or
   arbitrary callbacks. `final-exit-activation.js` lexically issues the
   terminal `OpenRouteHandoff` only after authenticated OPEN; the deep import
   exposes only consume/revoke/destroy, and unconsumed handoffs are revoked by
   activation-owner destruction.

Task 6 changes no existing wire byte, message order, public HyperDHT API,
direct-mode behavior, or address-authority boundary. One 1,101-byte M3 context
envelope still produces one 1,200-byte CONTROL cell. The implementation depends
on Task 5 production OPEN-record issuers, record-bound demultiplexing, and
reservation accounting; fake issuers, raw sockets, arbitrary callbacks,
physical destructors, and direct dial authority remain incompatible
substitutes.

Local Task 6 verification used Node v22.19.0, npm 11.10.0, and the exact Bare
v1.30.3 runtime restored into `/tmp/hyperdht-bare-v1.30.3` outside the
repository:

- Focused Task 6 suite
  (`test/private/route-extension.js`, `test/private/guard-link.js`,
  `test/private/udx-cell-endpoint.js`, `test/private/m3-adjacency-runtime.js`,
  `test/private/tail-control.js`, `test/private/tail-extension-committer.js`,
  `test/private/final-exit-handoff.js`, and
  `test/private/final-exit-activation.js`) passed independently in Node and
  Bare with 135/135 tests and 1,660/1,660 assertions.
- Complete private aggregate `test/private-routing.js` passed independently in
  Node and Bare with 662/662 tests and 14,937/14,937 assertions.
- `npm test` passed its repository-wide Prettier check, then reproduced the
  documented local host-topology exception in direct-mode
  `createServer + connect - same-LAN explicit keypair opens server`: Node
  observed `HOLEPUNCH_ABORTED` in top-level test 18 and timed out without a
  final TAP summary. This local full-suite run is not reported as green.
- Exact Bare v1.30.3 direct full-suite verification reached 749 top-level
  tests and 15,264 assertions, failing only the same direct-mode same-LAN
  explicit-keypair case with `ETIMEDOUT`; final TAP was 748/749 tests and
  15,263/15,264 assertions. This local full-suite run is not reported as
  green.

Local Task 7 verification used Node v22.19.0, npm 11.10.0, and Bare v1.30.3:

- Focused Task 7 suite
  (`test/private/final-exit.js`, `test/private/final-exit-activation.js`,
  `test/private/final-exit-handoff.js`, `test/private/open-route-handoff.js`,
  and `test/private/relay-identity-signer.js`) passed independently in Node
  and Bare with 27/27 tests and 273/273 assertions.
- Complete private aggregate `test/private-routing.js` passed independently in
  Node and Bare with 675/675 tests and 15,054/15,054 assertions.

Local Task 8 verification used Node v22.19.0, npm 11.10.0, and Bare v1.30.3:

- `lib/private/relay-service.js` ports bounded opaque relay forwarding from
  the reviewed prototype, retaining the canonical 128 global circuits, 32
  circuits per observed neighbor, 256 KiB per-circuit queue, 8 MiB global
  queue, five-second relay deadlines, replay tombstones, downward-only
  negotiated limits, and `ERR_BUSY`/`ERR_QUOTA_EXCEEDED` failure split.
- The relay service stores only opaque previous-hop and next-hop capabilities
  plus local circuit/generation/accounting state. Queue accounting is reserved
  before payload copies; allocation/callback failures roll back queue bytes and
  replay counters, with the admission-boundary callback rollback covered
  explicitly. Destroy tombstones routing state before closing adjacent
  capabilities so reentrant callbacks see destroyed state.
- Focused Task 8 suite (`test/private/relay-service.js`) passed independently
  in Node and Bare with 12/12 tests and 73/73 assertions.
- Complete private aggregate `test/private-routing.js` passed independently in
  Node and Bare with 689/689 tests and 15,147/15,147 assertions.

Local Task 9 Step 1 verification used Node v22.19.0, npm 11.10.0, and Bare
v1.30.3:

- `lib/private/guard-lease.js` adds the opaque GuardLease owner for a pinned
  SHARED_GUARD bootstrap material record. Lease creation consumes the
  `GuardLeaseMaterial`, binds the separately returned pinned guard identity and
  endpoint tuple, and retains physical close authority without exposing raw
  endpoint, established-link, or secret material.
- `lib/private/udx-cell-endpoint.js` brands the OPEN record only during
  bootstrap pinning, rejects preexisting generic M3 transfer ownership before
  branding, and permits at most four live shared-guard M3 transfer issuer/
  transfer slots. Destroying a shared logical transfer releases only its slot;
  GuardLease destroy revokes every shared slot before closing the physical
  owner once.
- Focused Task 9 Step 1 suite (`test/private/guard-lease.js`,
  `test/private/udx-cell-endpoint.js`, `test/private/guard-link.js`,
  `test/private/m3-adjacency-runtime.js`) passed independently in Node with
  102/102 tests and 1,419/1,419 assertions.
- Complete private aggregate `test/private-routing.js` passed independently in
  Node and Bare with 693/693 tests and 15,170/15,170 assertions.

Local Task 9 Step 2 verification used Node v22.19.0, npm 11.10.0, and Bare
v1.30.3:

- `lib/private/branch-path-authority.js` builds an atomic initial lookup/
  announce draft from one relay-directory transaction. It consumes exactly four
  selected evidence objects, binds the directory scope to the pinned
  `GuardLease`, rejects guard/candidate identity and subnet collisions, reserves
  four shared-guard M3 slots, and aborts without committing on destroy or
  failure.
- `lib/private/route-extension.js` and `lib/private/final-exit-activation.js`
  own the empty opaque route-extension/final-exit factory capabilities. The
  wrappers `openRouteExtension(factory, exactOptions)` and
  `openFinalExit(factory, exactOptions)` inject only the factory-owned wall
  clock, monotonic clock, random source, scheduler, and cancellation function;
  final-exit retry and retired/replayed OPEN helpers also reject caller RNG.
  `lib/private/route-manager.js` validates those same factory capabilities and
  still exposes only the initial `buildInitialPair()`, `branchCapability()`, and
  `destroy()` manager surface until terminal OPEN publication lands.
- Focused Task 9 Step 2 suite (`test/private/branch-path-authority.js`,
  `test/private/route-manager.js`, `test/private/guard-lease.js`,
  `test/private/udx-cell-endpoint.js`) passed independently in Node with 27/27
  tests and 228/228 assertions. The new branch/manager tests also passed
  independently in Bare with 8/8 tests and 95/95 assertions.
- Focused Task 9 Step 3 suite (`test/private/route-manager.js`,
  `test/private/route-extension-session.js`,
  `test/private/final-exit-activation-session.js`,
  `test/private/final-exit-activation.js`) passed in Node with 19/19 tests and
  157/157 assertions. The final-exit facade proof now consumes the authenticated
  responder OPEN handoff and proves replay/revoke/destruction semantics.
- Focused Task 9 Step 4/5/6 suite (`test/private/route-manager.js`,
  `test/private/guard-lease.js`, `test/private/branch-path-authority.js`,
  `test/private/route-extension-session.js`,
  `test/private/final-exit-activation.js`, and
  `test/private/udx-cell-endpoint.js`) passed in Node and Bare with 42/42
  tests and 354/354 assertions. The route manager now publishes the initial
  lookup/announce OPEN pair transactionally, exposes only branch-local empty
  capabilities after publication, rotates one branch make-before-break while
  preserving the opposite branch capability, clamps replacement construction to
  the directory guard/selected relay signed expiries, rolls failed rotation
  attempts back without leaking consumed OPEN material, and suspends by revoking
  manager operations, branch material, guard issuers, and the live socket while
  retaining only a one-shot reconnect authority and sealed directory.
- `lib/private/dht-exit-seeds.js` freezes the DHT-only exit seed set as
  signed `DHT_EXIT_DHT_SEEDS_V1` bytes. `test/private/dht-exit-seeds.js`
  proves exact one- and three-reference encodings, strict 1..3 count
  bounds, canonical set-digest input, canonical destination ordering,
  branch/exit binding, clocked expiry rejection, hostile descriptor
  rejection, signature verification, and zeroization.
- `lib/private/dht-exit-destination-table.js` admits only live,
  ping-correlated configured bootstrap references, sorts seed refs by
  canonical decoded id/handle order before signing, and exposes seed delivery
  only through a revocable one-shot authority. Destroying the table revokes
  unconsumed seed-delivery authorities.
- `lib/private/dht-exit-wire.js` owns the client-only DHT-RPC packet subset
  adapted from dht-rpc commit `fe04496196ea2ce42d1de27b0f770b02d2a87cd5`
  under MIT provenance: `Request._encodeRequest`, `decodeReply`,
  `validateId`, and the IPv4 peer codec only. `test/private/dht-exit-wire.js`
  freezes command-0 PING and HyperDHT command-9 IMMUTABLE_GET request bytes,
  response byte `0x13`, u16 transaction byte order, destination tuples,
  empty/error/full reply flag mixes, invalid IDs, trailing bytes, and
  request-packet rejection in Node and Bare.
- `lib/private/dht-exit-reservation.js` and `lib/private/dht-exit-io.js`
  add the exit-side one-socket reservation boundary. The endpoint OPEN
  authority is a distinct handoff-carried capability, not accepted by the
  exit reservation channel.
- `requestDhtExitImmutableGet` accepts one validated routed immutable-get request,
  reserves its ordinary UDP operation before send, and emits one normalized
  `ROUTED_REPLY_V1`. Referral tuples are reply-correlated, bounded, probed before
  admission, deduplicated against live destination IDs, and sorted by unsigned
  XOR distance. The operation owns every pending TID and settlement authority;
  cancellation, socket close, deadline expiry, table destruction, and
  synchronous callback failure revoke all remaining authority without emitting
  a duplicate reply. Raw immutable values remain bounded to 1,023 bytes before
  any referral can be admitted.
- Focused DHT-exit Task 13 suite (`test/private/dht-exit-wire.js`,
  `test/private/dht-exit-destination-table.js`, `test/private/dht-exit-io.js`,
  and `test/private/dht-exit-immutable-get.js`) passed in Node and Bare with
  27/27 tests and 248/248 assertions.
- Focused DHT-exit Task 12 suite (`test/private/dht-exit-seeds.js`,
  `test/private/dht-exit-destination-table.js`,
  `test/private/dht-exit-test-topology-grant.js`,
  `test/private/dht-exit-wire.js`, `test/private/dht-exit-reservation.js`,
  and `test/private/dht-exit-io.js`) passed in Node and Bare with 22/22 tests
  and 240/240 assertions.

### Gate 3B1 Task 15 live controller and lifecycle checkpoint

Task 15 connects the previously reviewed package-private owners into one
production-code, in-process lifecycle without changing HyperDHT's root public
surface:

- `lib/private/private-routing-controller.js` owns the exact `OFF`,
  `BOOTSTRAPPING`, `GUARD_PINNED`, `BUILDING`, `READY`, `ROTATING`,
  `SUSPENDED`, `UNAVAILABLE`, and `DESTROYED` state machine. Its frozen
  capability exposes only `start`, `snapshot`, `immutableGet`, `suspend`,
  `resume`, `networkChanged`, and `destroy`.
- `lib/private/live-route-authority.js` and
  `lib/private/opaque-destination.js` retain each branch's moved OPEN
  route transport and payload codec, admit signed exit seeds, publish
  generation-bound address-free destinations, and carry only the reviewed
  immutable-get command. Failed live send/receive operations issue an exact
  branch-loss signal; cancellation and intentional teardown do not.
- The controller's `start` method consumes only `EndpointBootstrapAuthority`, then
  drives production `BootstrapIO`, `GuardLease`, lookup/announce branch
  construction, authenticated tail extension, final-exit
  ACTIVATE/READY/ACK/OPEN, signed DHT-exit seed delivery, route admission, and
  immutable lookup. No test-only controller issuer, raw socket, endpoint,
  identity secret, or structural route authority participates in the hosted
  success path.
- Rotation is make-before-break and branch-local. Natural expiry, rejected
  route IO, or authenticated `BRANCH_DESTROY_V1` propagation replaces only the
  affected branch, advances its generation, preserves the other branch and
  shared physical guard, and releases every retired logical M3 forwarding
  owner. Candidate exhaustion or replacement failure closes owned resources and
  enters `UNAVAILABLE`.
- Suspend synchronously installs one shared in-flight result, revokes both live
  branches and routed destinations, closes native route ownership, and retains
  only the sealed directory plus one-shot guard reconnect capability. Resume
  consumes that capability and builds fresh generations. Network change,
  wall-clock rollback, guard loss, partial initial construction, and teardown
  fail closed with deterministic ownership cleanup and key zeroization.
- `test/private/live-immutable-get.js` exercises a fully hosted native
  endpoint/guard/middle/exit/DHT-exit topology: READY, exact immutable value,
  natural lookup rotation, idle downstream lookup replacement, idle announce
  loss fail-closed behavior, shared-guard loss, suspend/resume, network change,
  and negative absent-service startup. The relay actors are hosted in-process;
  Task 16 process isolation remains required before the multi-process criterion
  is complete.
- Final Task 15 verification ran `test/private-routing.js` independently under
  Node v22.19.0 and Bare v1.30.3: both passed 798/798 tests and
  16,124/16,124 assertions. Focused native hosted lifecycle coverage passed
  13/13 tests and 119/119 assertions under each runtime.

### Gate 3B1 Task 17 live eleven-process scenario status

`test/private/live-process-suite.js` drives eleven separate role processes over
native UDX loopback. It is test infrastructure, not a public API, and carries no
anonymity claim.

On Linux the scenario passes all 136 assertions with both Node
and Bare role children. It proves,
live and cross-process: ordered DHT role bind and the audited setup store;
endpoint bootstrap, guard pinning, and separate lookup/announce branches built
through authenticated adjacent links; an exact immutable get retrieved through
the three-position route either directly from the configured DHT path or after
the exit admits an isolated learned closer under a signed Task 12 grant;
delayed-lookup cancellation; a silent native lookup-middle route-cell blackhole
that triggers link-loss propagation and rotates the endpoint onto a fresh pair,
followed by a second exact immutable get; exit accounting for referral probes and
ordinary requests; endpoint suspend and resume, including a third exact immutable
get over the rebuilt route; a terminal network change that leaves no endpoint
socket and installs no fallback edge; and ordered teardown with zero residual
operations, resources, and queued bytes in
every role.

Reaching resume, rotation, and network-change required four fixture
and owner corrections, each of which is now part of the proof:

- The fixture issues a per-generation pool of one-shot topology grants
  (`LEARNED_GRANT_USES` referral, value, and seed grants per adjacency and
  generation) because `LinkDirectory` keeps one link handle per grant and
  `UdxCellEndpoint.openLink` refuses a consumed handle, so every rebuilt branch
  must re-probe its learned closers with fresh grants.
- Guard bootstrap acceptance and relay accept sessions are re-armable, so a
  rebuilt branch can re-enter the same guard.
- Exit grant requests are serialized: exits allow one outstanding isolated grant
  request per exit and answer `COUNTER_EXHAUSTED` for a concurrent second, which
  the DHT retries against later candidates.
- `DHTExitIO` seeds its request TID from a random 16-bit counter rather than zero,
  so a socket rebuilt on a reused host/port after suspend does not collide with
  the TIDs of the pre-suspend session and have its replies dropped as duplicates.

The eleven-role scenarios are not part of the portable aggregate. They bind the
`127.64.x.1` role tuples, which macOS and Windows refuse without per-address
configuration (KI-2), so they run from their own scripts under the Linux CI job
while `test/private-routing.js` stays green everywhere:

Counts below are a MEASUREMENT taken at one commit, not a contract. Every added test
moves them, and a stale total quoted as current has already caused four false findings
in this document's history - so re-measure rather than cite, and if you change a suite,
change this table in the same pass. Measured on 2026-09-05 after the native
blackhole, local-matrix, signed clock-skew, generation-bound refused-loss, and
SURB advisory corrections. The namespace row records the failed full run,
not a later passing rerun. Darwin aggregates and remote dispatches were not
re-measured in this checkpoint.

| Suite                              | Command                                            | Result                                            |
| ---------------------------------- | -------------------------------------------------- | ------------------------------------------------- |
| Private aggregate, Node            | `npx brittle-node test/private-routing.js`         | 975/975 tests, 19,051/19,051 assertions, Linux    |
| Private aggregate, Bare            | `bare test/private-routing.js`                     | 932/932 tests, 18,923/18,923 assertions, Linux    |
| Eleven-role scenario, Node roles   | `npm run test:private:process:node`                | 136/136 assertions, Linux                         |
| Eleven-role scenario, Bare roles   | `npm run test:private:process:bare`                | 136/136 assertions, Linux                         |
| Eleven-role scenario, reverse Node | `bash scripts/linux-gates.sh process:node:reverse` | 136/136 assertions, Linux                         |
| Eleven-role scenario, reverse Bare | `bash scripts/linux-gates.sh process:bare:reverse` | 136/136 assertions, Linux                         |
| Namespace projection enforcement   | `npm run test:private:namespace`                   | 27/27 assertions, privileged Linux                |
| Namespace live route and oracles   | `npm run test:private:namespace:live`              | 146/146 assertions; raw DROP 0, classified ICMP 0 |

### Gate 3B1 Task 17 wire-level privacy evidence

`test/private/live-namespace-node.js` runs the same eleven-process scenario with
every role in its own Linux network namespace, captures IPv4 traffic on every
veth, and checks the captured UDP bytes plus the independent kernel-drop
counter. The final full run passes `146/146` with raw DROP zero. KI-16 records
the approved narrow teardown classification, its three-drop native positive
probe, and the injected ICMP echo that the gate rejects. Every UDP-specific
assertion still covers the full capture.

Isolation is structural, not asserted. Each role holds routes only to the peers
named by `ALLOW_EDGES`, and the root namespace forwards under a dedicated
iptables chain that ends in DROP for those devices. The endpoint's routing table
contains exactly one destination, its guard, and no default route, so a datagram
addressed anywhere else has no path rather than an unenforced prohibition.

The scenario is the full lifecycle, including the failure paths: bootstrap,
guard pinning, two branches, three exact immutable gets, a silent route-cell
blackhole with lookup rotation, suspend and resume, a terminal network change,
and ordered teardown. What the capture shows across all of it:

| Observed on the wire                                                      | Assertion                                                         |
| ------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| No datagram crossed a pair the topology forbids                           | `no datagram crosses a pair the topology forbids`                 |
| The kernel refused nothing, so no role even addressed a forbidden pair    | `the kernel refused no packet between roles`                      |
| The endpoint's only destination, for the entire run, is its guard         | `the endpoint only ever sends to its guard`                       |
| The endpoint's encoded address never appears inside a cell past its guard | `the endpoint address never travels inside a cell past its guard` |
| No identity key, route key, MAC key or sentinel appears in any payload    | `no leak marker appears on any edge that carries route cells`     |
| No cell payload repeats on a second hop, so each hop re-encrypts          | `no cell payload is relayed unchanged across two hops`            |
| Every route cell is 1,200 bytes on every hop, on every edge               | `every route cell is the same size on every hop`                  |

The leak search is checked against itself. The retrieved value is deliberately
visible where the design says it must be, between an exit and a DHT node, and
`the value search is not vacuous` fails if the same search stops finding it. The
auditor/decoy namespace pair plays the same role for the capture harness in
`test/private/namespace-projection.js`: a capture that observes nothing there is
a broken harness, not a private route.

This supports a scoped claim and nothing wider. Under the
[v1 active-relay adversary](private-routing-v1.md#active-relay-adversary), where
any single guard, middle, exit or storage node may be malicious, these
[protected properties](private-routing-v1.md#protected-properties) now have
packet-level evidence: the endpoint has no direct send authority after
readiness, no failure path produces direct fallback, and private-capable peers
do not learn one another's addresses. The remaining protected properties are
semantic and stay covered by the deterministic suites, not by capture.

What this is still not. Every v1
[out-of-scope](private-routing-v1.md#out-of-scope-for-v1) item is untouched: a
global passive observer, timing correlation by colluding guards and exits, Sybil
resistance, and query privacy from exits. Uniform cell size removes length as a
correlator, but the capture records timing and packet counts per edge, and
nothing in this gate pads, batches, or adds cover traffic. An adversary watching
two edges can still correlate them. That is tracked as
[KI-1](#ki-1-routes-are-correlatable-by-timing-and-volume): a v1 design boundary
accepted on purpose, not a test gap, and the reason this remains an
experimental, package-private slice with no anonymity claim beyond the table
above.

Role clocks are supplied by `test/private/process/runtime-clock.js`. Wall and
monotonic time are derived from one cached sample of a single counter because the
route protocol carries a wall expiry into a monotonic deadline and rejects any hop
whose derived deadline exceeds the one it was handed; independent `Date.now()` and
`hrtime` samples straddling a millisecond boundary produced exactly that rejection.

### Gate 3A resource bounds

Fragmentation is limited to eight fragments, eight concurrent messages, eight buffered fragments, and a five-second message deadline. Eight full fragments carry at most 8,424 bytes of application data. Including the twenty-byte header in each of eight route payloads produces at most 8,584 encoded bytes; 8,584 is not an application-data limit. Public duplex segmentation across multiple internal messages is intentionally absent.

The route-payload nonce-domain registry is also deliberately process-local and capped at 4,096 claims. It never evicts an activated claim and fails closed at capacity. It is deterministic Gate 3A scaffolding, not the durable circuit/generation freshness mechanism required for live or mobile routing.

## Newly authored Gate 3A modules

The following files were authored in this fork and were not migrated from the prototype commit:

- `lib/private/dht-command-policy.js` defines the fail-closed immutable-get-only command mapping. `test/private/dht-command-policy.js` proves exact request encoding and rejection of every unsupported command before authority IO.
- `lib/private/query-context.js` creates per-instance, unforgeable lookup/announce capabilities for that one command. Its focused coverage is in `test/private/dht-command-policy.js`.
- `lib/private/opaque-destination.js` owns address-free, branch-bound destination capabilities for one adapter instance. Its focused coverage is in `test/private/routed-dht-io.js`.
- `lib/private/routed-dht-io.js` implements the internal nine-method DHT-RPC request-transport contract against a trusted in-process authority. It supports only the reviewed immutable-get request body and normalizes a trusted logical response; it is not a live or remote authority interface. Its focused coverage is in `test/private/routed-dht-io.js`.

`test/private/fake-route-authority.js` and `test/private/routed-dht-traversal.js` are also newly authored, test-only conformance scaffolding. They exercise deterministic five-node lookup and announce traversal through base DHT-RPC without hosts, ports, sockets, UDX, or network traffic. They do not model a live three-position route and are not an anonymity test.

## Gate 3A-only and deferred scope

The Gate 3A fake authority and traversal modules remain deterministic
conformance scaffolding and are not authorized as substitutes for the
package-private Gate 3B1 live owners. Gate 3B1 through Task 17 now includes M3
context derivation, authenticated adjacent links, tail/final-exit state,
guard pinning, separate lookup/announce routes, quotas, branch rotation,
teardown, immutable-get request/reply encoding, provenance-qualified DHT-exit
destinations, generation invalidation, and native DHT-exit socket ownership.

The remaining deferred scope is explicit:

- traffic-analysis defences: padding to a constant rate, batching, and cover
  traffic, tracked as
  [KI-1](#ki-1-routes-are-correlatable-by-timing-and-volume);
- root public required-mode integration, Hyperswarm, mobile, and PearTube
  integration.

The Task 15 controller remains package-private. It carries no anonymity claim
beyond the properties tabulated in
[Task 17 wire-level privacy evidence](#gate-3b1-task-17-wire-level-privacy-evidence),
which hold only under the v1 active-relay adversary.

## Gate 3B entry criteria

Gate 3B is an aggregate delivery gate, not a requirement that one implementation
plan change every private-routing subsystem at once. It may be completed through
numbered, separately designed and reviewed vertical sub-gates such as Gate 3B1,
3B2, and later slices. Each sub-gate must state exactly which criteria it
advances, keep incomplete criteria fail-closed and non-public, and preserve the
experimental/no-anonymity boundary. No sub-gate may expose public required mode
or claim Delivery Gate 3 complete until all ten aggregate criteria below pass
together in fork-native CI.

The complete Gate 3B series must implement and verify all of the following:

1. Signed relay advertisements and numeric-only bounded bootstrap.
2. Stable guard pinning and separate lookup/announce middle/exit branches.
3. Adjacent authenticated links, three-position live routes, quotas, rotation, and teardown.
4. Exact reviewed request and reply body codecs, encoded-byte amplification accounting, and adversarial vectors for private presence, mutable/immutable get/put, and exit referrals.
5. Exact v1 role/branch/circuit/generation transcript constructors and the deferred M3 derivation vectors.
6. Provenance-qualified DHT exit destination tables and live allowlisted UDP operations.
7. Trusted route-generation expiry and rotation invalidation for every issued destination capability.
8. A public required-mode controller only after direct authority is removed at readiness.
9. Multi-process Node/Bare integration.
10. Privileged Linux namespace capture plus a semantic leak oracle proving endpoint-to-guard-only traffic after readiness.

Delivery Gate 3 remains open until every one of these ten items passes fork-native CI. Gate 3A completion alone does not authorize a public private-routing mode or an anonymity claim.

[Gate 3B1](superpowers/specs/2026-07-18-private-routing-gate-3b1-live-immutable-get-design.md)
is authorized as the first live vertical slice. It covers signed relay
advertisements, bounded numeric bootstrap, stable guard pinning, separate live
lookup/announce branches, adjacent authenticated links, endpoint-to-exit
authentication, immutable-get request/reply codecs, provenance-qualified DHT
destinations, generation invalidation, Node/Bare multi-process integration, and
the privileged packet/semantic leak oracles. The announce branch is constructed
but carries no DHT mutation in that slice. Remaining DHT commands, private
presence, public required mode, peer streams, Hyperswarm, and mobile device
evidence remain disabled for later separately reviewed sub-gates.
