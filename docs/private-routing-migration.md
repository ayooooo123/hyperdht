# Private Routing Gate 3A / Gate 3B1 Migration Record

## Status and scope

This record describes the experimental, internal Gate 3A substrate and the owner-approved Gate 3B1 implementation through Task 17 in this fork. It is not a public API or a production anonymity surface. Gate 3A combines the generic DHT-RPC request-transport seam established in Gate 2 with deterministic protocol primitives, an address-free internal adapter, and an in-process fake topology. Gate 3B1 adds production-code native routing owners behind package-private capabilities.

Direct mode remains the only public behavior. Gate 3B1 Task 15 has a package-private required-mode controller, authenticated native route authority, routed immutable-get request/reply path, rotation, suspension, and teardown; Tasks 16 and 17 add test-only process isolation and prove that path live across eleven separate Node or Bare role processes over native UDX, and, on Linux, with every role in its own network namespace under packet capture. The root package still exposes no private-routing constructor or user-selectable required mode. A post-readiness packet-capture proof now exists for the specific properties tabulated in [Task 17 wire-level privacy evidence](#gate-3b1-task-17-wire-level-privacy-evidence). It is not a general anonymity claim: a global passive observer and timing correlation by colluding guards and exits are out of scope for v1, no cover traffic exists, and these tests do not establish suitability for protecting users.

The canonical design remains [Private Routing Protocol v1](private-routing-v1.md).

The owner-approved Gate 3B1 Task 5 authenticated-M3 transport, Task 6
tail-control lifetime/ownership amendment, and Tasks 7–17 live-route lifecycle
are incorporated into the canonical design documents and implemented
internally in this fork. This remains a package-private compatibility slice: it
adds no root public constructor, export, user-selectable required mode, or
anonymity claim, although its internal path uses the production UDX, relay,
final-exit, and DHT-exit owners rather than a structural or fake transport.

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

On Linux (Ubuntu 24.04 under Colima, Node v22.19.0) the scenario passes all 125
assertions deterministically with both Node and Bare role children. It proves,
live and cross-process: ordered DHT role bind and the audited setup store;
endpoint bootstrap, guard pinning, and separate lookup/announce branches built
through authenticated adjacent links; an exact immutable get retrieved through
the three-position route after the exit admits an isolated learned closer under a
signed Task 12 grant; delayed-lookup cancellation; a physical lookup-A link fault
that propagates `BRANCH_DESTROY` upstream and rotates the endpoint onto lookup B,
followed by a second exact immutable get; exit accounting for referral probes and
ordinary requests; endpoint suspend and resume, including a third exact immutable
get over the rebuilt route; a terminal network change that leaves no endpoint
socket and installs no fallback edge; an acknowledged guard physical link fault;
and ordered teardown with zero residual operations, resources, and queued bytes in
every role.

Reaching resume, rotation, network-change, and guard-loss required four fixture
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

One environment boundary remains: macOS cannot bind the `127.64.x.1` role tuples,
so both portable live suites stop at the first bind with
`PROCESS_BIND_UNAVAILABLE` there (`866/868` tests, `18,096/18,098` assertions
under Node on Darwin). Every other private suite is green on Darwin, and
`test/private-routing.js` is fully green under both runtimes on Linux
(`868/868` Node, `854/854` Bare).

### Gate 3B1 Task 17 wire-level privacy evidence

`test/private/live-namespace-node.js` runs the same eleven-process scenario with
every role in its own Linux network namespace, captures every packet on every
veth, and decides the result from the captured bytes rather than from the
implementation's own accounting. It passes `135/135` assertions on Linux.

Isolation is structural, not asserted. Each role holds routes only to the peers
named by `ALLOW_EDGES`, and the root namespace forwards under a dedicated
iptables chain that ends in DROP for those devices. The endpoint's routing table
contains exactly one destination, its guard, and no default route, so a datagram
addressed anywhere else has no path rather than an unenforced prohibition.

The scenario is the full lifecycle, including the failure paths: bootstrap,
guard pinning, two branches, three exact immutable gets, a physical link fault
with rotation, suspend and resume, a terminal network change, a guard fault, and
ordered teardown. What the capture shows across all of it:

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
two edges can still correlate them. That is a v1 design boundary, not a test
gap, and it is the reason this remains an experimental, package-private slice
with no anonymity claim beyond the table above.

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

- private presence and the mutable get/put command bodies and live operations;
- public duplex/peer-stream segmentation and stream backpressure;
- traffic-analysis defences: padding to a constant rate, batching, and cover
  traffic. Cell size is already uniform, but per-edge timing and packet counts
  are observable and nothing conceals them, so correlation by an adversary
  watching two edges remains possible and out of scope;
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
