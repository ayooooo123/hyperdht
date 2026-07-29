# Gate 3B1 Task 6: Private Tail Responder Authority

**Status:** Owner-approved on 2026-07-29 after independent design review

**Date:** 2026-07-29

**Amends:** [Gate 3B1 implementation plan](../../superpowers/plans/2026-07-18-private-routing-gate-3b1.md), Task 6 only

**Byte-level source:** reviewed private-routes prototype commit `0305df915b6a767093f9e75e6c06bc0a35da6169`

## Summary

Gate 3B1 Task 6 extends an authenticated private route from its current tail to
one already-selected relay without performing discovery after guard pinning.
The endpoint sends the complete signed relay advertisement inside
`EXTEND_REQUEST_V1`; the current tail verifies it and uses relay-owned adjacent
link authority to contact exactly that advertised endpoint. The endpoint never
receives a socket, a decoded endpoint tuple, a dial callback, or authority to
select a different peer.

The reviewed prototype correctly defines the extension wire bytes,
cryptographic transcript, redacted responder proof, and one-shot link
capabilities, but its `TailControlSession` admits an extension through a
discovery cache and reserves it through the future `BranchPathAuthority`.
Neither dependency exists at Task 6's boundary. This amendment replaces those
two ownership dependencies with a package-private, WeakMap-backed responder
authority. It does not change the adopted wire protocol or public package API.

## Decision

Keep the Task 6 `TailControlSession` consumer surface exactly as planned:

```js
session.sealExtend(options)
session.openExtended(envelope)
session.completeClientExtension(completion, readyEnvelope)
session.abortClientExtension(completion)
session.takeFinalExitHandoff()
takeAdmittedExtendRequest(capability)
completeClientTailExtension(completion, readyEnvelope)
abortClientTailExtension(completion)
readTailControlDeadline(session)
```

Pure codec, digest, and test-vector exports named by Task 6 remain available.
No responder receive, dial, or completion method is added to the session
object. Responder transitions are co-located with the `SESSIONS` WeakMap in
`tail-control.js`; moving them to another module would require exporting raw
session-state mutation. They are package-private CommonJS functions and are
never re-exported from HyperDHT's package entry point.

The authority is an empty frozen capability backed by a `WeakMap`. It is issued
only when `createTailControlResponderAuthority` consumes a one-shot
`TailResponderToken` capability issued by `m3-adjacency-runtime.js` alongside
an authenticated responder tail. The token is cryptographically bound to the
same tail transcript and local relay identity. The relay runtime separately
borrows its relay-owned M3 responder adopter and supplies a one-shot
tail-extension committer,
adjacent-link factory, TAIL_READY signer, local clocks, and randomness owner.
Endpoint-side M3 tail adoption does not mint a responder token, so an initiator
session cannot request, synthesize, or receive the authority. Deep-importing
the private factory without that unforgeable paired token grants nothing.

## Security invariants

The implementation must preserve all of these invariants:

1. After guard pinning, an endpoint can emit route-construction traffic only on
   its authenticated current-tail transport.
2. Only the current relay tail can turn an authenticated `EXTEND_REQUEST_V1`
   into adjacent-link work.
3. The adjacent link may target only the canonical endpoint encoded in the
   complete, verified advertisement carried by that request.
4. The endpoint receives neither the canonical tuple nor any socket, bind,
   `trySend`, DNS, connect, or arbitrary-dial authority.
5. Relay selection is completed before `sealExtend`; no discovery request,
   discovery response, candidate enumeration, or random discovery target is
   accepted by this flow.
6. Each admission, link-completion, adjacency adoption, ready completion, and
   final-exit handoff is one-shot and WeakMap-backed.
7. A new tail is not endpoint-usable and its directory reservation is not
   committed until a valid `TAIL_READY_V1` is opened.
8. No timer, retry, callback, or nested session can extend an actor's local
   monotonic deadline or an authenticated wire wall-clock expiry.
9. Authentication, replay, expiry, cancellation, reentrancy, or setup failure
   destroys locally owned new adjacency and pending-tail state immediately.
   Already-installed remote relay state is destroyed on authenticated transport
   close or its bounded local expiry. No failure creates direct fallback or
   replaces the already-pinned guard.
10. Extension index 1 must select a safety relay; extension index 2 must select
    a DHT exit. No third extension is valid.

## Capability and module ownership

`tail-control.js` owns the exact EXTEND/EXTENDED/TAIL_READY codecs, ordered
control AEAD, transcript derivation, initiator state, and final-exit handoff.
Its session object exposes only the consumer methods listed above.

`tail-control.js` also owns these package-private responder transition
functions because they must mutate its ordered AEAD counters and transcript
state atomically:

```js
createTailControlResponderAuthority(session, responderToken, options)
admitTailExtend(authority, envelope)
openTailAdjacentLink(authority, admitted)
completeTailExtend(authority, completion)
abortTailExtend(authority)
sealTailReady(authority)
destroyTailControlResponderAuthority(authority)
```

These names are an internal contract and not public package exports. Tests may
require the private file directly. `createTailControlResponderAuthority`
atomically consumes `responderToken`; the token's hidden binding must equal the
responder session's tail binding. Mismatch destroys both inputs and every
capability supplied in `options`.

`m3-adjacency-runtime.js` owns the token and provides only
`consumeTailResponderToken`, `revokeTailResponderToken`, and its internal
issuer. Responder adoption returns an opaque bundle containing `{ runtime,
tail, responderToken }`; initiator adoption returns no token. Authority options
are exact own data. Every index requires `tailReadySigner`, `wallNow`,
`monotonicNow`, and `randomBytes`. Indices 0 and 1 additionally require
`adjacencyAdopter`, `extensionCommitter`, and `adjacentLinkFactory`. At terminal
index 2 those extension keys are forbidden and EXTEND admission is invalid.

```js
// Transcript indices 0 and 1
const extensionResponderOptions = {
  adjacencyAdopter,
  extensionCommitter,
  adjacentLinkFactory,
  tailReadySigner,
  wallNow,
  monotonicNow,
  randomBytes,
  schedule,
  cancelScheduled
}

// Terminal transcript index 2
const terminalResponderOptions = {
  tailReadySigner,
  wallNow,
  monotonicNow,
  randomBytes,
  schedule,
  cancelScheduled
}
```

The responder option clock functions must be the same function identities
already stored by its session; alternate clocks are rejected before any
capability is retained.

Authority construction arms one opaque handle at the session's already
projected `localDeadline` before returning the authority. Synchronous firing,
throwing scheduling, or reentrant cancellation fails construction and destroys
all transferred options. Authority destroy cancels the recorded handle before
destroying protocol state. Successful forwarding installation cancels the old
authority handle only after the independently armed M3 runtime handles own both
installed contexts; a successor authority and terminal index-2 authority keep
their own handles until destroy or expiry.

The runtime stores one internal frozen binding object in both WeakMap records.
It binds the exact tail transcript digest, local relay identity, role, and wire
expiry. `takeM3TailCapability` moves that object into the responder session
state without exporting it; consuming the token succeeds only on object
identity and repeated field validation. The token is one-shot and revocation or
session destruction clears its copied binding bytes.

`guard-link.js` owns `ExtensionAdjacentLinkFactory` through this exact internal
surface:

```js
createExtensionAdjacentLinkFactory(options)
openExtensionAdjacentLink(factory, admitted) // Promise<ExtensionLinkCompletion>
abortExtensionAdjacentLink(factory)
destroyExtensionAdjacentLinkFactory(factory)
```

The factory options are exact own data with no accessors or extra keys:

```js
const adjacentLinkFactoryOptions = {
  dialAuthority,
  linkOfferSigner,
  wallNow,
  monotonicNow,
  randomBytes,
  schedule,
  cancelScheduled,
  destroy
}
```

They are relay-owned capabilities: a domain-limited LINK_OFFER signer, a
request-bound-on-first-use dial authority, separate wall and monotonic clocks,
randomness, scheduler/canceller, and destroy owner. `open` permits one
live operation, consumes `admitted` through `takeAdmittedExtendRequest`, decodes
the canonical endpoint internally, and asks the dial authority to contact only
that endpoint. It owns LINK_OFFER/LINK_ACCEPT/proof exchange and resolves only
an `ExtensionLinkCompletion`; no tuple, socket, physical channel, or raw key is
returned. `abort` cancels the live operation even after admission has moved.

`guard-link.js` also owns the relay-only dial authority:

```js
createRelayAdjacentDialAuthority({ socketOwner, allowedRole, dial, destroy })
dialRelayAdvertisement(authority, options)
destroyRelayAdjacentDialAuthority(authority)
```

`dialRelayAdvertisement` accepts this exact own-data options object with no
accessors or extra keys:

```js
const dialOptions = {
  advertisement,
  advertisementDigest,
  requiredRole,
  wireExpiresAt,
  localDeadline
}
```

The dial callback contract is exact:

```js
dial(socketOwner, canonicalEndpoint) // Promise<ExtensionResponseReceiver>
destroy() // synchronous, no arguments
```

`dial` must return a genuine Promise. A synchronous throw is a dial failure. A
synchronous non-Promise return is a contract violation. If that direct return is
a live capability recognized by `isExtensionResponseReceiver`, it is first
consumed with `destroyExtensionResponseReceiver`; no property or method is read
from any other malformed return. Cleanup precedes the `INVALID_ROUTE` result.
The Promise may fulfill only with the existing opaque
`ExtensionResponseReceiver`; this design introduces no setup-transport
interface.

Authority construction creates one internal linear `SocketOwnerLease`
containing `{ socketOwner, onceDestroy }`. `onceDestroy` is the sole owner of
the supplied no-argument `destroy` callback, suppresses its exception, and can
be spent only once. The lease is never exported. Receiver and physical-channel
cleanup remains separate channel cleanup and neither spends nor replaces this
lease.

During `DIALING`, the callback receives a temporary non-owning reference to the
lease's `socketOwner`, retained by the pending attempt only until settlement,
and may initiate exactly one connection. After valid installation, a non-owning
operational reference may remain only inside the returned receiver/physical-
channel graph, and only while that graph is co-owned and atomically
co-transferred with the same `SocketOwnerLease`. The graph may neither invoke
nor own `onceDestroy`, nor export, use, or retain the reference after the lease
is spent. Every failure drops the graph before spending the lease. The separate
lease remains the sole destruction owner through factory, completion, and
runtime ownership.

The operation owns one fresh 19-byte canonical-endpoint copy decoded from the
verified advertisement. `dial` receives a read-only loan of that exact buffer
until its Promise settles and may contact only that endpoint: no DNS lookup,
fallback, alternate candidate, discovery request, or retry target. It may not
retain the loan after settlement. Abort, destroy, or pre-install deadline
failure while the Promise is unsettled moves buffer-cleanup ownership into the
attached endpoint settlement capsule; pending callback code never observes the
buffer cleared or mutated. The fulfillment/rejection handler clears it exactly
once.

The callback contract requires settlement no later than the retained local
deadline and requires socket-owner destruction to drive cancellation
settlement. Correctness does not trust either promise. If the callback remains
unsettled after abort or destroy, its capsule retains the same globally counted
pending-offer lease until settlement. A never-settling Promise therefore
occupies one bounded global slot rather than creating unbounded uncounted
buffers or handlers; new attempts fail closed at `MAX_PENDING_OFFERS`.

The adjacent factory creates its operation synchronously and privately binds
the dial authority to that operation's exact wall-clock identity,
monotonic-clock identity, and retained local deadline. On the first
`dialRelayAdvertisement` call, the authority changes `UNUSED -> DIALING` and
permanently tombstones reuse before option inspection, verification, either
clock, scheduling, or `dial`. That operation acquires one process-global
pending-offer lease before any external or cryptographic operation. A malformed
first call, synchronous throw, rejection, invalid fulfillment, expiry, abort,
or destroy spends the authority.

Before calling `dial`, the authority re-verifies the canonical advertisement,
digest, required role, wire expiry, exact retained local deadline, and both
clock identities. It creates the endpoint copy only after those checks. It
rechecks generation identity, liveness, and both deadlines after every external
or reentrant operation.

Before a genuine dial Promise exists with settlement handlers attached, a
dedicated pre-Promise terminal/failure owner detaches and tombstones the
operation and cancels any armed timer. Once any synchronous endpoint/socket-
owner loan has ended, that owner destroys any live direct-return receiver,
spends `SocketOwnerLease`, clears the endpoint copy, and releases any acquired
pending-offer lease, in that order. It returns the applicable normalized error
only after that cleanup. It cannot create a quarantine record without a genuine
Promise and an attached settlement handler. If a reentrant terminal transition
occurs while `dial` is on the stack and `dial` then returns a genuine Promise,
its handler is attached and the unsettled-Promise quarantine rule below applies
before any loan-coupled owner is released.

The pending-offer lease has one ownership path:

1. While dialing, the authority record owns `{ pendingOfferLease,
   socketOwnerLease, endpointSettlementCapsule }`.
2. Promise settlement alone is not a commit. Its handler first validates
   `isExtensionResponseReceiver`, rechecks the still-`DIALING`
   authority/factory generation and both deadlines, and performs no external
   callback between the final state check and commit.
3. Valid fulfillment commits only by atomically moving `{ receiver,
   pendingOfferLease, socketOwnerLease }` into the still-live bound factory
   operation and marking the authority `TRANSFERRED`/spent. Only this install
   commit wins over a later abort.
4. Abort or destroy that commits first, including after underlying Promise
   settlement but before the fulfillment handler's install commit, wins. The
   uninstalled receiver is destroyed and late settlement cannot mutate factory
   state.
5. A settled genuine-Promise pre-install failure—rejection, invalid
   fulfillment, or failed fulfillment-handler validation—first detaches and
   tombstones, then destroys any live receiver, spends `socketOwnerLease`,
   clears the endpoint copy, and releases the pending-offer lease, all once and
   with callback exceptions suppressed. Synchronous throw/non-Promise follows
   the pre-Promise owner above instead.
6. Abort, destroy, or pre-install deadline failure while the genuine dial
   Promise is unsettled detaches and tombstones the factory operation, then
   atomically moves `{ pendingOfferLease, endpointSettlementCapsule }` into a
   globally counted late-settlement quarantine record. It immediately spends
   `socketOwnerLease` and rejects the outer operation, but does not release the
   pending-offer lease or clear the endpoint while callback code may still run.
   Eventual fulfillment/rejection destroys any live receiver, clears the
   endpoint, releases the lease, and deletes the record. A record that never
   settles permanently occupies one `MAX_PENDING_OFFERS` slot.
7. During LINK_OFFER/LINK_ACCEPT/proof exchange after a valid install, the
   factory operation owns `{ receiver, pendingOfferLease, socketOwnerLease }`.
   Abort, factory destroy, expiry, or exchange failure first detaches and
   tombstones the operation and releases the pending-offer lease, then destroys
   the receiver or already-moved physical channel, and finally spends
   `socketOwnerLease`.
8. A terminal completion attempt atomically detaches the pending operation,
   moving `{ receiver, socketOwnerLease }` into the terminal-attempt owner, and
   releases the pending-offer lease before validating completion options or
   invoking `takeExtensionResponse`, matching `completeExtensionLink`'s
   existing boundary.
9. The terminal attempt uses `finally` on every pre-transfer failure to destroy
   whichever of the receiver or taken physical channel it then owns and only
   afterward spends `socketOwnerLease`. Successful `takeExtensionResponse`
   atomically replaces the terminal owner's receiver with `{ physicalChannel,
   socketOwnerLease }` in a factory-local post-take owner. Every subsequent
   validation, proof, derivation, or establishment failure destroys the
   physical channel or derived/established link and then spends the lease. Only
   after the established link and every retained proof/binding are valid does
   `createExtensionLinkCompletion` atomically move `{ establishedLinkMaterial,
   socketOwnerLease }` into the completion destruction state. Completion
   destruction destroys the established link and then spends the lease once.
10. Successful responder completion/adoption moves `socketOwnerLease` with the
    established adjacency into the M3 runtime registry's existing destroy owner
    before clearing completion material. Registry removal, link close, or
    projected expiry destroys physical-channel/runtime state and then spends
    the lease. No success path drops the lease or invokes its destructor early.

The first committed terminal transition wins, not Promise settlement time.
Every pre-install terminal transition uses the same settled-versus-unsettled
ownership rule. Before the valid fulfillment install commit, abort/destroy
marks `ABORTED`/spent and detaches the operation before callbacks, performs the
cleanup or quarantine transfer above, destroys any operation-owned channel,
spends the socket-owner lease once, and rejects `openExtensionAdjacentLink`
with `ERR_DESTROYED`; pre-install expiry uses the existing normal expiry error.
Only quarantined settlement handlers remain. A later rejection is consumed; a
later live receiver is destroyed and never installed. Settlement clears the
endpoint and releases the quarantined lease once, without mutating factory
state or reacquiring a released lease. Reentrant abort/destroy observes the
tombstone and is an idempotent no-op. After install commits, abort follows the
normal factory-operation cleanup path.

Post-invocation non-destroy dial failures are cleaned up before normalization to
`ERR_ROUTE_UNAVAILABLE`; caller-shape violations remain `INVALID_ROUTE`. No
arbitrary callback exception escapes.

Before this factory consumes a receiver, `takeExtensionResponse` must be
corrected through TDD. Store `takePhysicalChannel()` in a temporary candidate
and assign it to the owned `physicalChannel` local only after it passes the
existing nominal channel check. A malformed truthy candidate therefore leaves
`physicalChannel` null and runs the receiver's registered destructor. A valid
candidate is destroyed on every later non-transfer path. This changes no wire
bytes or API.

Only the already-bound adjacent factory may invoke the authority.
`dialRelayAdvertisement` resolves its opaque result to factory code only after
the valid fulfillment install commit. Endpoint code receives no tuple,
endpoint bytes, socket owner, owner lease, dial function, receiver, physical
channel, DNS/bind/`trySend`/connect capability, or alternate-dial authority.
The factory resolves only `ExtensionLinkCompletion`.

Task 6 implementation keeps its existing numbering but executes this dependency
order without a test-only admission issuer: Step 5a corrects
`takeExtensionResponse` and implements the relay dial authority plus exact
adjacent-factory construction/lifecycle; Step 8a implements real token-gated
responder-authority construction and authenticated `admitTailExtend`, publishes
the ordinary `AdmittedExtendRequest`, and adds its one-shot
`takeAdmittedExtendRequest` consumer; Step 5b consumes that honest admitted
capability synchronously before the factory's first await and performs the
exact link exchange; Step 8b implements `openTailAdjacentLink`, completion,
abort, TAIL_READY, and remaining responder transitions, including transfer of
the socket-owner lease into the M3 runtime destroy owner. The deferred initiator
LINK_OFFER signer migration finishes only after the production admission path
can exercise it behaviorally.

On the successor side, `takeExtensionResponderAdjacency` is narrowed to return
an opaque accepted-adjacency transfer. The private transfer/cache-owner surface
is:

```js
takeAcceptedExtensionAdjacencyTransfer(transfer)
revokeAcceptedExtensionAdjacencyTransfer(transfer)
answerAcceptedExtensionReplay(owner, offerReceiver)
destroyAcceptedExtensionAdjacencyOwner(owner)
```

The taken material is exactly frozen `{ adjacency, replayOwner }`; both move
atomically. Before take, revoke destroys both. After take, a failure before
successor runtime-registry publication destroys the adjacency and replay owner
in `finally`; publication is the ownership boundary.

The exact successor extension-responder factory replaces `now` with `wallNow`
and adds `monotonicNow`, `schedule`, and `cancelScheduled` alongside its
advertisement, adopter, extension-responder signer, responder route-encryption
secret, offer receiver, and randomness inputs. These clock and scheduler
identities must match the successor M3 runtime owner.

```js
const successorResponderOptions = {
  advertisement,
  adjacencyAdopter,
  extensionResponderSigner,
  responderRouteEncryptionSecretKey,
  wallNow,
  monotonicNow,
  schedule,
  cancelScheduled,
  offerReceiver,
  randomBytes
}
```

`answerAcceptedExtensionReplay` accepts only an authenticated duplicate of the
exact retained offer digest and nonces, writes cached LINK_ACCEPT/proof bytes to
the supplied one-shot response channel, and never adopts again. The successor
runtime registry consumes both transferred objects atomically; rollback
destroys both. The owner's proactive local expiry timer is armed before this
transfer is published.

`relay-identity-signer.js` owns separate empty, WeakMap-backed LINK_OFFER and
TAIL_READY signer capabilities. Its private issuer receives the relay identity
owner; consumers accept only the exact registered message ID, signature domain,
body length, and expected public identity. A signer can be consumed for its one
semantic message or destroyed, and no operation returns the secret key.

```js
createRelayIdentitySigningAuthority({ identitySecretKey })
createLinkOfferSigner(identityOwner)
signLinkOffer(signer, body, expectedIdentity)
destroyLinkOfferSigner(signer)
createExtensionResponderSigner(identityOwner)
signLinkAccept(signer, body, expectedIdentity)
signRedactedResponderProof(signer, body, expectedIdentity)
destroyExtensionResponderSigner(signer)
createTailReadySigner(identityOwner)
signTailReady(signer, body, expectedIdentity)
destroyTailReadySigner(signer)
destroyRelayIdentitySigningAuthority(identityOwner)
```

The owner copies and validates the secret key once during relay startup, derives
its public identity internally, and zeroizes the copy on destroy. Child signers
are bound to that identity and message domain; no child can mint another child.
Each signing function returns one owned 64-byte signature only after verifying
it against the bound identity. The LINK_OFFER and TAIL_READY signers are spent
after one semantic object. The extension-responder signer has an exact
LINK_ACCEPT-then-redacted-proof two-phase lifecycle and is spent after the
second signature. Signing retries reuse cached semantic objects; they do not
spend a second signer.
`guard-link.js` is refactored so neither `createExtensionLinkOffer` nor the
extension responder receives `initiatorIdentitySecretKey` or
`responderIdentitySecretKey`; both receive domain-limited identity signers. The
responder route-encryption secret remains relay-owned inside its existing
one-shot responder factory and is never returned or passed to an endpoint.

`extension-setup-channel.js` remains the owner of LINK_OFFER/LINK_ACCEPT and
the physical setup channel. `extension-link-completion.js` remains the owner of
the completed link plus redacted proof. `m3-adjacency-adopter.js` adopts that
link through `adoptM3ResponderLink`; `tail-control.js` never calls the
`M3AdjacencyAuthority.adopt` method directly. On the current tail's initiating
side, `takeM3ResponderLink` transfers `{ runtime, tail }`; the local initiator
tail capability is revoked after its material has been staged because the
endpoint derives its matching next-tail session from `EXTENDED_V1`. On the
successor relay's independently accepted side, adoption transfers `{ runtime,
tail, responderToken }`; that relay consumes the tail and paired token to build
the responder session/authority that seals `TAIL_READY_V1`.
`tail-extension-committer.js` stages `EXTENDED_V1` and installs the next relay
runtime. It also owns an opaque `TailForwardingTransfer`:

```js
takeTailForwardingTransfer(transfer)
revokeTailForwardingTransfer(transfer)
```

The taken value is the existing frozen `{ diagnostics, destroy }` forwarding
facade returned by `TailExtensionCommitter.install()`, not the separate empty
`M3ForwardingOwner` used internally by `m3-adjacency-runtime.js`. The facade
owns that internal M3 owner; its `destroy` consumes it and tears down both
installed runtime sides. A failed or abandoned transfer invokes the same
destroy path. None of these modules learns the full route.

The private responder authority stores no endpoint-provided callback. Its
clocks, randomness, signer, dialer, scheduler, and cleanup owners arrive only
through the paired responder token plus exact relay-owned options. It enters a non-reentrant mutation phase
before invoking them and tombstones or advances its generation before any
destruction, transport, or installation callback so reentry cannot publish
state.

`M3AdjacencyAuthority` replaces its ambiguous `now` option with `wallNow` and
adds exact `monotonicNow`, `schedule`, and `cancelScheduled` constructor
capabilities. Every adopted runtime arms one
proactive expiry handle before the runtime or tail capability is published.
The timer record is stored in the runtime reservation. Before installation its
callback tombstones and destroys that runtime; after `commitM3Install` both
installed records point to the internal `M3ForwardingOwner`, so the first
expiry consumes that owner and cancels both handles before closing contexts.
The successor relay has its own independently armed runtime timer. No packet,
diagnostic call, or later allocation is required to trigger expiry cleanup.
Synchronous firing, throwing schedules, reentrant cancellation, and failure to
record a handle all destroy the unpublished runtime.

## Construction and deadline

`createTailControlSession(capability, options)` consumes one M3 tail capability.
Its exact common options are `wallNow`, `monotonicNow`, and optional `crypto`
for deterministic vectors. An initiator additionally requires the
RouteManager-owned `absoluteDeadline`, expressed only in that endpoint
process's monotonic clock. A responder does not receive or compare that value;
every M3 tail capability carries an already-owned `{ wireExpiresAt,
localDeadline, clockIdentity }`, and its paired responder token supplies only
the authority binding.

Wall-clock expiries appear in signed advertisements, requested limits, link
offers/proofs, tail capabilities, and other wire transcripts. Monotonic
deadlines are process-local scheduling values and are never encoded, signed,
or compared across machines. At each actor, a positive wall-clock interval is
projected into that actor's monotonic clock exactly once:

```text
remaining(wireExpiresAt) = max(0, wireExpiresAt - wallNow())
projected = monotonicNow() + remaining(wireExpiresAt)
```

Overflow, backward wall time, non-monotonic `monotonicNow`, or a non-positive
interval fails closed. `M3AdjacencyAuthority.adopt` performs the tail wire-expiry
projection exactly once before publishing the runtime, tail capability, or
responder token. `createTailControlSession` verifies the supplied clock
functions against `clockIdentity` and moves `wireExpiresAt` and `localDeadline`
without projecting again. On an initiator it further clamps, but never resets,
the moved deadline to the RouteManager `absoluteDeadline`. Every later bound is
calculated as `min(previousLocalDeadline, newlyProjectedShorterBounds)`. The
endpoint initiator's local extension deadline is:

```text
min(
  RouteManager absoluteDeadline,
  initiatorSession.localDeadline,
  extensionStartMonotonic + 5,000 ms,
  project(manager signedExpiry),
  project(selected advertisement expiry)
)
```

`signedExpiry` is the manager-owned authenticated current-branch wall-clock
upper bound already present in the Task 6 request. It is not returned by Task 3
and is not treated as selected-evidence metadata. `RouteExtensionSession`
permits it only to shorten the tail capability's authenticated wire expiry;
`sealExtend` rejects requested limits later than either bound.

The initiator encodes `requestedLimits.expiresAtMs` as a wall-clock value no
later than the minimum authenticated wire expiry and no later than the wall
time corresponding to its remaining local budget. On receipt, the responder
computes its own local deadline:

```text
min(
  responderSession.localDeadline,
  responderStartMonotonic + 5,000 ms,
  project(selected advertisement expiry),
  project(requestedLimits.expiresAtMs)
)
```

The responder never reconstructs or compares the endpoint's monotonic epoch.
Each nested link offer, accept, proof, retry, timer, and completion carries the
minimum wall-clock wire expiry and is scheduled against only the current
actor's projected local monotonic deadline. Both values are checked before and
after external or reentrant operations. A later session, retry, duplicate, or
callback may only preserve or reduce them.

`readTailControlDeadline(session)` returns only that session's local monotonic
deadline. It never returns a wire expiry or a value meaningful in another
process. RouteExtension compares it only with its endpoint-local
`monotonicNow()` and stored RouteManager deadline.

## Initiator flow

`RouteExtensionSession` first consumes Task 3 selected evidence using the exact
transaction, branch class, position, generation, and extension-index bindings.
The resulting owned material contains the complete canonical advertisement,
its digest, role/index metadata, and no independent expiry field. The signed
advertisement itself contains the selected peer's authenticated wall-clock
expiry. The evidence contains no dial authority.

It calls `session.sealExtend(options)` with exact own data:

```js
const sealExtendOptions = {
  advertisement,
  advertisementDigest,
  extensionIndex,
  requestedLimits,
  absoluteDeadline,
  randomBytes
}
```

Branch class, position, and generation are not caller-repeatable inputs here:
`RouteExtensionSession` already consumed them from the Task 3 selection and
the session owns branch, circuit, generation, current-tail identity, and
current-tail advertisement digest in its authenticated transcript. The session
verifies those owned bindings, next index, required role, advertisement
signature, advertisement digest, payload parameters, and both clock-domain
bounds. The repeated `absoluteDeadline` must equal the session's already-owned
endpoint-local deadline; it cannot replace or extend it. The session then generates
fresh client-tail ephemeral and extension nonces, stores one pending client
extension, encodes the prototype-exact `EXTEND_REQUEST_V1`, and seals it in the
forward ordered tail-control AEAD. A second pending request is rejected.

The complete advertisement is deliberately present in the authenticated
request. This reveals the selected next-hop identity and address to the current
tail, which must contact that peer, but does not reveal it to unrelated DHT
peers and does not grant the endpoint direct-send authority.

After receiving `EXTENDED_V1`, `openExtended(envelope)` verifies the exact
prototype transcript, advertisement digest, extension nonce, responder
identity, redacted proof, ephemeral keys, limits, branch/circuit/generation,
authenticated wire expiry, and local monotonic deadline before deriving the next tail. It returns one opaque
client completion. It does not publish or commit the next tail yet.

`completeClientExtension(completion, readyEnvelope)` opens and authenticates
`TAIL_READY_V1` and returns the next `TailControlSession` atomically. It does
not commit the Task 3 directory transaction: Task 9 commits the complete branch
pair only after both branches are ready. On failure it destroys the uncommitted
next session and zeroizes its retained material. The enclosing
`RouteExtensionSession` catches that failure, consumes the manager cancellation
capability, and the Task 9 transaction owner then aborts the path reservation.
`abortClientExtension` has the same local cleanup without activation.

## Responder flow

The current relay's authenticated transport delivers the sealed control frame
to `admitTailExtend(authority, envelope)`. The function opens ordered tail AEAD
and accepts only `EXTEND_REQUEST_V1`. It verifies:

- exact current branch, circuit, generation, current tail, and next extension
  index;
- the complete advertisement's canonical encoding, signature, digest, route
  key, required role, canonical endpoint, and signed expiry;
- payload-parameter digest and requested limits;
- nonzero fresh client and extension nonces;
- the inherited effective deadline; and
- absence of a live, spent, duplicate, or conflicting extension.

Unlike the prototype, admission does not consult a relay discovery cache.
Successful admission publishes one `AdmittedExtendRequest` capability and
stores `state.liveAdmission = capability` together with its exact current-tail
binding and effective deadline. The ordinary
consumer `takeAdmittedExtendRequest(capability)` transfers the complete owned
request, current-tail identity, current-tail advertisement digest, and deadline
once. It does not separately return a host or port.

Only the relay-owned adjacent-link factory may consume the admitted capability.
`openTailAdjacentLink(authority, admitted)` transfers it into the authority's
bound factory. It first requires object identity with `state.liveAdmission`,
clears that field, and changes phase to `LINK_OPENING` before invoking a clock,
randomness source, scheduler, signer, factory, or dialer. The factory
synchronously calls `takeAdmittedExtendRequest` before its first await. On
resolution the authority stores the exact returned object as
`state.liveCompletion` and then resolves the same
`ExtensionLinkCompletion`. The factory decodes the canonical
endpoint internally from the verified signed advertisement and opens
LINK_OFFER/LINK_ACCEPT against exactly that endpoint. It may neither enumerate
alternatives nor retry a different tuple.

Taking the admitted request moves its full owned request bytes to the adjacent
link owner but leaves only digests, nonces, indices, and the effective deadline
inside the responder authority for later correlation. `completeTailExtend`
therefore accepts the authority and one `ExtensionLinkCompletion`; it cannot
consume or inspect the already-spent admission capability a second time.

`completeTailExtend(authority, completion)` consumes that one-shot completion,
first requires object identity with `state.liveCompletion`, clears that field,
and advances phase before calling `takeExtensionLinkCompletion`. It then
verifies the redacted responder proof and all retained expected bindings,
adopts the established M3 adjacency, seals prototype-exact
`EXTENDED_V1`, and passes the envelope plus staged next runtime to the
`TailExtensionCommitter`. The committer makes the current relay a forwarder
between its predecessor and new successor. Relay-owned link, forwarding, and
tail-control contexts must exist at this point so `TAIL_READY_V1` can traverse
the new adjacency, but they are staged for control traffic only. No endpoint
next-tail session, endpoint application-send authority, final-exit activation,
or directory commit exists yet.

Before invoking the committer's external installation owner, completion changes
the old responder session and authority to an irreversible `INSTALLING`
generation so reentry cannot admit, abort, or publish again. Success tombstones
the old session/authority. `TailExtensionCommitter.install()` obtains the
existing frozen forwarding facade and wraps it in exactly one opaque
`TailForwardingTransfer`; `completeTailExtend` returns that transfer. The relay
runtime registry calls `takeTailForwardingTransfer` before the event handler
returns. Before take, cancellation or abandonment calls
`revokeTailForwardingTransfer`. After take but before registry publication, the
handler owns the facade in a tracked local and calls `facade.destroy()` in
`finally` on every failure. Registry publication is the failure-atomic
ownership boundary; afterward registry removal calls the same destroy method.
Destroying the facade tears down both sides of the installed pair. The separate
internal `M3ForwardingOwner` never leaves `m3-adjacency-runtime.js`.

The new tail relay calls `sealTailReady` only after it owns the adopted link and
is ready to process authenticated tail control. The responder authority uses
its bound signing capability and randomness source; the responder session does
not expose `sealReady` or raw secret-key input. `sealTailReady(authority)`
returns one owned exact M3 context envelope, consumes the signer for that
semantic message, and advances the authority from `WAITING_READY` to `ACTIVE`.
At indices 0 and 1 the active authority may later admit exactly one extension;
at index 2 it may only create the final-exit handoff. The endpoint initiator
validates the envelope inside `completeClientExtension`. The exact reverse direction,
counter-zero rule, signature input, and transcript digest remain those of the
prototype. This amendment changes ownership, not message ordering or bytes:

```text
EXTEND_REQUEST_V1 -> LINK_OFFER/LINK_ACCEPT -> EXTENDED_V1 -> TAIL_READY_V1
```

## Final-exit handoff

After extension index 2 reaches valid `TAIL_READY_V1`, no further EXTEND is
accepted. `session.takeFinalExitHandoff()` returns one opaque handoff containing
the tail-control owner, exact 290-byte tail-control transcript, shared secret,
finalize keys and nonce prefixes, initiator flag, authenticated
`wireExpiresAt`, process-local `localDeadline`, and the clock-identity token for
the exact `wallNow`/`monotonicNow` functions that projected it.
`consumeFinalExitHandoff` transfers it once into Task 7. Revocation, session
destroy, or expiry erases every field.

Task 7 consumes the handoff in the same runtime and must present the same clock
identity; it reuses `localDeadline` without projection or reset and uses
`wireExpiresAt` only in authenticated transcript comparisons. A handoff cannot
cross processes. The remote exit independently owns its own handoff and local
projection. No local monotonic value is ever encoded or compared by another
actor.

The handoff exposes no destination table, DHT socket, endpoint tuple, or final
payload key bytes to intermediate relays.

## Failure, replay, and cleanup rules

All public and private transition functions reject accessor-backed or
extra-keyed option objects before retaining data. Owned buffers are copied on
admission and cleared on transfer, abort, or destroy. A capability is removed
from its live WeakMap and added to its spent set before any external operation.

Tail-control replay and link-setup retransmission are distinct:

- replaying the same sealed ordered-tail frame reuses its counter and is
  rejected before allocation; the fail-closed session is destroyed as in the
  reviewed prototype;
- a freshly sealed second EXTEND with the same semantic nonce is rejected as a
  replay because one live extension already exists; it is not answered from a
  cache by the retired current-tail session;
- conflicting reuse of an extension or client nonce is an authentication
  failure; and
- only the lower link-setup owners may resend already-authorized semantic bytes
  under fresh datagram counters. The current tail's adjacent factory owns only
  outbound LINK_OFFER retry state and destroys it when its operation settles.
  The successor relay owns cached LINK_ACCEPT/proof bytes; successful responder
  admission transfers that cache into a successor-local
  `AcceptedExtensionAdjacencyOwner` paired with its responder token and runtime.
  That owner answers only the exact offer digest/nonce, rejects conflicts,
  cancels its own retry timer on destroy, and expires at the successor's local
  projected deadline. No cache crosses machines or enters the current tail's
  forwarding owner, and no replay allocates a second adjacency.

Cleanup is actor-local because the fixed four-message protocol has no final
ACK or authenticated remote cancel. The design therefore does not claim
synchronous remote erasure after an endpoint rejects `TAIL_READY_V1`.

Endpoint-local cancellation or failure performs this order:

1. tombstone the RouteExtension/session mutation and consume manager cancel;
2. cancel every endpoint-local opaque timer;
3. abort the client completion and destroy an uncommitted next-tail session;
4. revoke the failed branch's logical tail transport without closing the
   shared pinned-guard physical link; an observable context/transport close may
   trigger relay cleanup, but the design does not require such a signal;
5. leave Task 9's transaction owner to abort the path reservation; and
6. zeroize endpoint-owned nonces, secrets, transcript copies, advertisements,
   proofs, and semantic bytes.

Relay-local failure before forwarding installation performs this order:

1. tombstone the responder authority and abort its one live adjacent factory;
2. cancel relay-local timers;
3. revoke admission, completion, committer, signer, and responder-token state,
   and abort any live one-shot adoption; the borrowed `M3ResponderAdopter`
   remains owned by its `M3AdjacencyAuthority` and is not destroyed here;
4. destroy the half-built runtime, physical channel, and adjacent socket owner;
   and
5. zeroize relay-owned request, proof, transcript, and cache bytes.

After forwarding installation, an observed predecessor context or transport
close destroys the taken forwarding facade, both installed relay contexts, and
the successor link. If no such signal exists, or it is lost or delayed, each
relay independently destroys the same state no later than its projected local
monotonic deadline derived from the authenticated wire expiry. Tests require
immediate local cleanup and bounded eventual remote cleanup by that deadline,
not impossible cross-machine synchronous cleanup.

The already-established predecessor link remains owned by its relay until its
local close/expiry rule fires. At the endpoint, failure leaves only the pinned
guard link and no application-usable next tail; it does not bootstrap,
discover, or dial another peer.

## Verification contract

Task 6 is not complete until Node and Bare tests prove:

- exact known-answer vectors and mutation rejection for
  `EXTEND_REQUEST_V1`, `EXTENDED_V1`, `TAIL_READY_V1`, the 290-byte transcript,
  KDF labels, and redacted responder proof;
- initiator sessions cannot obtain or invoke responder authority, and responder
  sessions do not expose responder methods;
- the authority, admission, link completion, one-shot adoption, committer, client
  completion, and final-exit handoff are opaque and one-shot;
- a real in-memory guard -> middle -> DHT-exit trace emits only the four
  specified semantic control stages after pinning;
- the current tail contacts exactly the tuple inside the authenticated selected
  advertisement, while an endpoint direct-send trap remains untouched;
- a semantic trap rejects `RELAY_DISCOVER_V1`,
  `RELAY_DISCOVER_RESPONSE_V1`, random discovery targets, DNS, arbitrary
  enumeration, and Task 9 `BranchPathAuthority` dependencies;
- before valid `TAIL_READY_V1`, relay-owned link/forwarding contexts may be
  staged solely to carry tail-control traffic, but no endpoint next-tail
  session, endpoint application-send authority, final-exit activation, or
  directory commit is published;
- same-counter tail replay, semantic EXTEND replay, lower-link duplicate cached
  responses, conflicts, wrong bindings, wrong roles, malicious
  proofs, expired advertisements, deadline races, a dropped setup packet,
  cancellation, quota rejection, throwing/reentrant clocks and schedulers, and
  half-built second extensions fail closed; and
- every failure leaves zero locally owned uncommitted timer, callback,
  capability, transport, semantic cache, or secret immediately; installed
  remote forwarding/adjacency state is then destroyed on observed transport
  close and in all cases by its authenticated expiry, while the endpoint
  preserves only the already pinned guard where the Task 6 plan requires it.

The aggregate discovery-edge scan must find no discovery symbols or imports in
`route-extension.js`, `tail-control.js`, or `guard-link.js`. The
focused tests must be registered in `test/private-routing.js`, generated into
`test/all.js`, and pass independently under `brittle-node` and Bare.

## Non-goals

This amendment does not add public private-routing options, Hyperswarm or
PearTube integration, peer streams, announce traffic, mobile lifecycle work,
cover traffic, relay registries, direct fallback, guard replacement, route
rotation, or Task 9 branch management. It does not claim Tor-equivalent
anonymity. It only closes Task 6's responder ownership gap while preserving the
approved Gate 3B1 boundary.

## Plan effect

Task 6 Step 8a adds the package-private responder authority and replaces
prototype discovery-cache and `BranchPathAuthority` admission with the
selected-evidence flow above. The Task 6 file list additionally creates
`lib/private/relay-identity-signer.js` and
`test/private/relay-identity-signer.js`; responder transitions remain in
`tail-control.js` beside its private session state. Task 6 also modifies
`m3-adjacency-runtime.js` to mint/revoke the paired `TailResponderToken`,
refactors `guard-link.js` around the exact adjacent-link factory and signing
capabilities above, and replaces RouteExtension's single `now` dependency with
separate `wallNow` and `monotonicNow` functions. Task 3 evidence is unchanged,
and no `selectedEvidenceExpiry` field is added.

Step 5 is split in place: 5a applies the `takeExtensionResponse` ownership
correction and implements dial/factory construction through counted
late-settlement quarantine; after Step 8a produces the real authenticated
admission capability, 5b consumes it and performs the link exchange. Step 8
then resumes as 8b for completion, abort, TAIL_READY, and transfer of the
socket-owner lease into the M3 runtime destroy owner. The initiator LINK_OFFER
signer caller migration is deferred until that honest admission path exists.
The pending-offer reservation transfers to the live factory operation or
globally counted quarantine, releases directly through the pre-Promise owner
when no settlement handler exists, or releases after genuine-Promise
settlement. It is never unconditionally released while callback code remains
unsettled. All unchanged
requirements in Steps 1-7 remain in force. No later task is renumbered or
broadened. No wire bytes, public or package-private APIs, discovery/direct-
authority boundaries, or exact clock requirements change.
