# Gate 3B1 Task 6: Private Tail Responder Authority

**Status:** The responder-authority design and tail-control lifetime/authenticated-UDX transport amendment are owner-approved as of 2026-07-29. This written repository incorporation awaits owner review.

**Date:** 2026-07-29

**Plan reference:** [Gate 3B1 implementation plan](../../superpowers/plans/2026-07-18-private-routing-gate-3b1.md); required post-review Task 5/6/7/9 reconciliation is listed under Plan effect, and the plan is not modified by this revision

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

This revision also closes two ownership gaps exposed by the provisional Task 6
shape. A spent M3 tail capability cannot remain the sole cleanup path after its
material moves into a session, and the physical adjacency timer cannot enforce
a shorter logical-tail deadline because its expiry closes the physical link.
Likewise, structural `physicalChannel` and transport-factory objects cannot
prove the authenticated UDX established record or logical-only release. The
stable owner/lifetime below preserves cleanup across every transfer, and Task
5's UDX-issued `M3CellLinkTransfer` supplies the authenticated transport
prerequisite without changing bytes or public authority.

## Decision

Adopt one stable package-private `TailControlOwner` paired with one opaque
package-private `M3TailLifetime`. The lifetime owns a logical-tail timer
separate from the physical M3 adjacency-runtime timer. The stable owner moves
through current session, waiting-ready completion, successor session,
responder forwarding, and final-exit handoff/activation, and is the sole owner
of the logical tail-control transport destructor.

The `TailControlSession` object exposes exactly these five consumer methods:

```js
session.sealExtend(options)
session.openExtended(envelope)
session.completeClientExtension(completion, readyEnvelope)
session.abortClientExtension(completion)
session.takeFinalExitHandoff()
```

The original direct session-adjacent consumers remain package-private
functions, not session methods:

```js
takeAdmittedExtendRequest(capability)
completeClientTailExtension(completion, readyEnvelope)
abortClientTailExtension(completion)
readTailControlDeadline(session)
destroyTailControlSession(session)
borrowTailControlTransport(session)
```

The forwarding and final-activation package-private bridges are specified with
their owning modules below; they are likewise not session methods or entry-point
exports.

Pure codec, digest, and test-vector exports named by Task 6 remain available.
No responder receive, dial, completion, or `.destroy()` method is added to the
session object. The functions above and the responder transitions are
co-located with the `SESSIONS` and `TAIL_CONTROL_OWNERS` WeakMaps in
`tail-control.js`; moving them elsewhere would require exporting raw
session-state mutation. None is re-exported from HyperDHT's package entry
point.

The responder authority is an empty frozen capability backed by a `WeakMap`.
It is issued only when `createTailControlResponderAuthority` consumes a
one-shot `TailResponderToken` issued by `m3-adjacency-runtime.js` alongside an
authenticated responder tail. The token is cryptographically bound to the
same tail transcript, logical lifetime, and local relay identity. The relay
runtime separately borrows its relay-owned M3 responder adopter and supplies a
one-shot tail-extension committer, adjacent-link factory, TAIL_READY signer,
local clocks, and randomness owner. Endpoint-side M3 tail adoption does not
mint a responder token, so an initiator session cannot request, synthesize, or
receive the authority. Deep-importing the private factory without that
unforgeable paired token grants nothing.

No public HyperDHT API or wire byte changes. No endpoint socket, tuple, DNS,
bind, connect, `trySend`, arbitrary callback, raw key, endpoint-supplied
scheduler, dial authority, physical destructor, or test issuer is added.

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
atomically consumes `responderToken`; the token's hidden tail binding,
deadline object, and lifetime must equal the responder session's exact hidden
state. Mismatch destroys session, lifetime, token/binding, and every capability
supplied in `options`.

`m3-adjacency-runtime.js` owns the token; its token-specific surface is only
`consumeTailResponderToken`, `revokeTailResponderToken`, and the internal
issuer. Responder adoption returns an opaque bundle containing `{ runtime,
tail, responderToken }`; initiator adoption returns no token. Authority options
are exact own data. Every index requires `tailReadySigner`, `wallNow`,
`monotonicNow`, `randomBytes`, `schedule`, and `cancelScheduled`. Indices 0
and 1 additionally require `adjacencyAdopter`, `extensionCommitter`, and
`adjacentLinkFactory`. At terminal
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

Authority construction arms one opaque subordinate handle at the session's
already projected `localDeadline` before returning the authority. This handle
does not replace either the logical-lifetime timer or the physical-runtime
timer. Synchronous firing, throwing scheduling, or reentrant cancellation
fails construction and destroys all transferred options. Authority destroy
cancels its recorded handle before destroying protocol state. Successful
forwarding installation cancels that old authority handle only after the
independently armed M3 runtime handles own both contexts; a successor authority
and terminal index-2 authority keep their handles until destroy or expiry.

At responder adoption the runtime stores one internal frozen tail-binding
object in both the PENDING tail-capability and responder-token WeakMap records.
It binds the exact tail transcript digest, local relay identity, role, and wire
expiry. During `takeM3TailCapability`, the runtime creates the deadline object
and `M3TailLifetime`, atomically binds both records to that lifetime and the
stable owner callback, and moves the binding into responder session state
without exporting it. Token consumption requires binding-object identity,
deadline-object identity, lifetime identity, owner callback identity, and
repeated field validation. The token is one-shot; revocation or session,
lifetime, or runtime destruction clears its copied binding bytes.

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
   the receiver or endpoint-owned established-link ownership, and finally
   spends `socketOwnerLease`.
8. A terminal completion attempt atomically detaches the pending operation,
   moving `{ receiver, socketOwnerLease }` into the terminal-attempt owner, and
   releases the pending-offer lease before validating completion options or
   invoking `takeExtensionResponse`, matching `completeExtensionLink`'s
   existing boundary.
9. The terminal attempt uses `finally` on every pre-transfer failure to destroy
   whichever receiver or endpoint-owned established-link ownership it then
   owns and only afterward spends `socketOwnerLease`. Successful
   `takeExtensionResponse` atomically replaces the terminal owner's receiver
   with `{ establishedLinkOwnership, m3CellLinkTransferIssuer,
   socketOwnerLease }` in a factory-local post-take owner. After every proof
   and transcript binding is valid, lexical guard-link code creates the exact
   `M3AuthenticatedBranchBinding` and joins it with that issuer through
   `registerM3CellLinkTransfer`. Any validation/registration failure revokes
   issuer, binding, and unpublished transfer before destroying established
   ownership and spending the lease.
10. `createExtensionLinkCompletion` atomically moves
    `{ establishedLinkMaterial, m3CellLinkTransfer, socketOwnerLease }` into
    completion destruction state. Successful responder completion/adoption
    consumes the registered transfer into the M3 runtime and moves the
    `socketOwnerLease` with the exact non-shared physical owner before clearing
    completion material. Registry removal, link close, or projected expiry
    destroys runtime/established ownership and then spends the lease. No
    success path drops the lease or invokes its destructor early.

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

Before the Task 5 cutover wraps the receiver's channel in endpoint-owned
established-link ownership, the approved `takeExtensionResponse` correction
still applies at the current source boundary: hold `takePhysicalChannel()` in a
temporary, assign it only after the nominal channel check, and use the
receiver's registered destructor for a malformed truthy candidate. Immediately
after that check, `extension-setup-channel.js` moves the candidate behind the
opaque established-link/issuer path above; no downstream module reads
`.destroy`. Every later non-transfer path uses the fixed package-private
revoke/destroy operations. This changes no wire bytes or public API.

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
`tail-extension-committer.js` stages `EXTENDED_V1` and prepares, but does not
publish, the previous/next runtime pair. After `beginM3Install` and
`validateM3Install` have reserved and validated both exact runtime records,
`m3-adjacency-runtime.js` issues one frozen empty
`M3ForwardingPublicationClaim`. Its WeakMap record binds the install plan,
previous/next runtimes and reservations, both runtime borrowers and physical
policies, clock identities/deadlines, pending internal `M3ForwardingOwner`, and
the existing frozen `{ diagnostics, destroy }` forwarding facade. The
committer moves the claim and facade to `tail-control.js` in an opaque one-shot
install result; neither is published to a registry consumer yet.

While the stable owner is `RESPONDER_INSTALLING`, `tail-control.js` invokes:

```js
createM3TailForwardingLease(
  transportOwner,
  lifetime,
  ownerDestroy,
  publicationClaim
)
```

This M3-owned operation verifies the exact live transport owner, lifetime,
callback identity, and install claim. It tombstones every send/receive borrow
facade and moves the predecessor M3 cell borrower out of
`M3TailControlTransportOwner` into one frozen empty `M3TailForwardingLease`;
it does not unregister that borrower or disarm/release the logical lifetime.
The lease's WeakMap record carries the lifetime and `ownerDestroy` identities,
logical-transport owner, moved predecessor borrower, next-runtime borrower,
both runtime reservation/generation identities, clock identity/deadline, and
publication claim. Failure restores nothing: it revokes the unpublished
install and destroys the stable logical owner.

Because only `tail-control.js` can move `TAIL_CONTROL_OWNERS`, it—not the
committer—owns `TailForwardingTransfer`. Its hidden record is exactly the
stable owner identity and generation, `RESPONDER_FORWARDING_TRANSFER` stage,
the lifetime and callback identities, the `M3TailForwardingLease`, exact
publication claim, forwarding facade, and rollback-owned responder/session
fields.

`completeTailExtend` returns one exact frozen package-private runtime-event
payload:

```js
{
  transfer,
  publicationClaim
}
```

Those are the object-identical empty capabilities already paired in the hidden
transfer record; there are no extra keys, accessors, or structural authority.
The relay runtime-registry handler receives this payload directly, copies both
references into tracked locals, and calls
`takeTailForwardingTransfer(transfer, publicationClaim)` synchronously before
the event handler returns. It never discovers or extracts a claim from the
transfer. Failure before take calls `revokeTailForwardingTransfer(transfer)`,
which also revokes the paired claim/lease; a retained payload cannot replay
either capability.

The exact package-private transfer surface is:

```js
takeTailForwardingTransfer(transfer, publicationClaim)
revokeTailForwardingTransfer(transfer)
commitTailForwardingTransfer(taken, publication)
destroyTakenTailForwardingTransfer(taken)
```

Take requires the object-identical claim, tombstones the transfer, advances
the stable owner generation before callbacks, and returns this frozen
package-private own-data value:

```js
{
  tailControlOwner,
  m3ForwardingLease,
  publicationClaim,
  forwarding
}
```

`tailControlOwner`, `m3ForwardingLease`, and `publicationClaim` are empty
opaque capabilities. `forwarding` is the exact frozen
`{ diagnostics, destroy }` facade; it owns no tail lifetime or UDX borrower.
The stable owner remains interpretable only through lexical
`TAIL_CONTROL_OWNERS`.

The runtime-registry handler then uses only these M3-owned operations:

```js
publishM3TailForwarding(publicationClaim, m3ForwardingLease, forwarding)
takeM3TailForwardingPublication(publication, m3ForwardingLease, publicationClaim)
revokeM3TailForwardingLease(m3ForwardingLease)
destroyM3TailForwardingPublication(publication)
```

`publishM3TailForwarding` verifies that the claim, lease, facade, still-pending
runtime records, lifetime, callback identity, and both exact borrowers all
match. It requires both records to point to the same pending forwarding owner,
requires
`previous.clockIdentity === next.clockIdentity === logicalLifetime.clockIdentity`,
and then proves
`min(previous.localDeadline, next.localDeadline) <= logicalLifetime.localDeadline`.
Clock mismatch or an unprovable deadline fails publication; this design does
not use the optional successful-retention branch. No runtime timer is
shortened.

After the final checks, with no allocation, clock, crypto, or external callback
remaining, publication atomically points both runtime records and their exact
borrowers/physical owners at the pending `M3ForwardingOwner`. Only then does it
return an opaque publication receipt. Until
`commitTailForwardingTransfer(taken, publication)` succeeds, the stable owner
remains in `RESPONDER_FORWARDING_TRANSFER`; logical-lifetime expiry or runtime
teardown reaches that record and destroys the publication, both runtimes, and
both borrowers.

Commit tombstones the taken record and advances the owner generation before
calling `takeM3TailForwardingPublication` with the exact lease and claim.
Successful receipt consumption proves the runtime publication already owns
both borrowers. Commit then terminally calls `releaseM3TailLifetime` and clears
`M3TailControlTransportOwner` without calling `releaseM3CellBorrower`, because
that borrower has moved to `M3ForwardingOwner`; it clears remaining
tail-control/responder state and marks the stable owner `DESTROYED`. The
registry may publish/retain the forwarding facade only after commit returns.

Revoke before take destroys the lease/facade and stable owner. Any take,
publication, receipt, or commit failure runs
`destroyTakenTailForwardingTransfer` in `finally`; it tombstones the stable
owner first, calls the fixed M3 revoke/destroy operations, releases each
borrower/slot exactly once, destroys both unpublished or published runtime
sides, cancels the logical lifetime, and zeroizes rollback state. Registry
removal or either runtime expiry later consumes the internal
`M3ForwardingOwner`, destroys both sides, and releases both borrowers. The
internal owner never leaves `m3-adjacency-runtime.js`, and no module learns the
full route.

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

## Stable logical lifetime and session ownership

`m3-adjacency-runtime.js` owns a frozen empty `M3TailLifetime` capability
backed by `M3_TAIL_LIFETIMES`. It is never exported from HyperDHT's package
entry point and is returned only inside owned material consumed by
`tail-control.js`. Its exact package-private operations are:

```js
takeM3TailCapability(capability, { wallNow, monotonicNow }, ownerDestroy)
shortenM3TailLifetime(lifetime, ownerDestroy, {
  wireExpiresAt,
  localDeadline
})
releaseM3TailLifetime(lifetime, ownerDestroy)
```

`ownerDestroy` is one stable function created lexically inside
`tail-control.js` and closing over an empty `TailControlOwner`. It is never
accepted from TailControlSession or RouteExtension options, endpoint code, or
a public caller. On a successful capability take the M3 runtime atomically:

1. validates and spends the exact tail capability and matching clock
   identities;
2. creates and registers one lifetime against the exact runtime state and
   reservation;
3. records the stable `ownerDestroy` identity, moved `{ wireExpiresAt,
   localDeadline, clockIdentity }`, generation, and phase;
4. arms the lifetime's own timer at `localDeadline` with the same
   M3-authority scheduler/canceller identities; and
5. returns the owned tail material and opaque lifetime only after the timer is
   valid and live.

The M3 adjacency-runtime timer remains independently armed at the adjacency
deadline. A logical-tail bound never cancels, replaces, or shortens it.
Runtime/context teardown tombstones the lifetime and advances its generation,
detaches and cancels the lifetime timer, clears/revokes the paired responder
binding and token, invokes `ownerDestroy` once with exceptions suppressed, and
only then continues physical runtime/context cleanup. Logical lifetime expiry
performs only the logical steps and never destroys the M3 runtime or physical
channel.

`shortenM3TailLifetime` requires the same lifetime and exact `ownerDestroy`
identity. Both wire and local bounds must be non-increasing, and
`monotonicNow() < localDeadline` must still hold. The operation never projects
a wall expiry and never replaces the retained clock identity. It advances the
generation before scheduler/canceller callbacks and arms a replacement timer
before canceling the previous logical timer. Synchronous timer firing,
scheduler throw, an invalid handle, reentry, post-schedule expiry, or failure
to retain the new handle tombstones and destroys the logical lifetime instead
of publishing partially shortened state. The physical runtime timer is
untouched.

`releaseM3TailLifetime` is terminal-only: explicit logical-tail destruction, or
an exact responder-forwarding publication where already-armed runtime owners
have atomically assumed equivalent cleanup. Endpoint RouteExtension transfer,
client completion, final-exit handoff, and Task 7/Task 9 same-runtime
activation retain the same registered lifetime and armed timer while moving
only the stable owner's stage. Release verifies the callback identity,
tombstones the lifetime, cancels its logical timer, unlinks it from the
runtime, and clears responder binding/token state without closing the physical
runtime. Repeated release, expiry, runtime teardown, token revoke, callback
reentry, and owner destruction are idempotent after the first tombstone.

The paired `TailResponderToken` record carries the same tail binding, deadline
object, and lifetime identity. `createTailControlResponderAuthority` consumes
it only against the responder session's exact lifetime. Mismatch destroys the
session, lifetime, token/binding, and every supplied authority option. Success
registers the exact responder authority as one subordinate slot of the stable
owner. Lifetime teardown first tombstones that authority, advances its
generation, cancels its handle, aborts live admission/open/completion, and
revokes transferred signer/factory/committer state; it then clears the token
binding and session stage. Every responder entry point requires the same live
lifetime, owner generation, and subordinate-authority identity.

`tail-control.js` stores empty stable owners in `TAIL_CONTROL_OWNERS`. The
callback registered with `M3TailLifetime` resolves only the current owner
stage:

```text
UNBOUND
CONSTRUCTING_SESSION
ACTIVE_SESSION
WAITING_READY_SESSION
CLIENT_WAITING_READY
RESPONDER_INSTALLING
RESPONDER_FORWARDING_TRANSFER
FINAL_EXIT_HANDOFF
FINAL_EXIT_ACTIVATION
DESTROYING
DESTROYED
```

Every external callback and crypto/scheduler action is preceded by a
tombstone or owner-generation advance. No stage has two live consumers.
Immediately after capability take, every moved field and the lifetime are
stored under `CONSTRUCTING_SESSION` before any further clock, crypto,
validation, or callback. Runtime/lifetime teardown can therefore erase all
unpublished construction material. Publication rechecks lifetime identity,
owner generation, and deadline, then atomically enters `ACTIVE_SESSION` or
`WAITING_READY_SESSION`.

`createTailControlSession(capability, options)` remains the sole externally
callable package-private constructor that consumes an M3 tail capability. Its
options remain separate `wallNow`, `monotonicNow`, optional deterministic
`crypto`, and initiator-only `absoluteDeadline`; scheduler functions are not
added. Phase provenance is exact:

- authenticated index-0 initiator and responder M3 capabilities construct
  `ACTIVE` sessions;
- an index-0 initiator has no responder token;
- an index-0 responder authority consumes only its exact paired token and
  begins `ACTIVE`;
- an independently adopted successor relay responder at index 1 or 2
  constructs `WAITING_READY` and can become `ACTIVE` only through valid
  `sealTailReady` after runtime installation;
- an index-1/2 initiator capability on the relay forwarding side is
  staged/revoked by the committer and cannot construct an endpoint session;
  and
- the endpoint's index-1/2 successor is constructed only by lexical,
  non-exported `createTailControlSessionFromOwnedMaterial` after authenticated
  `TAIL_READY_V1`.

`destroyTailControlSession(session)` is package-private and idempotent. It
tombstones session and owner before callbacks, cancels the logical lifetime,
aborts a pending client completion, revokes the logical transport, and
zeroizes owned transcript, secret, key, nonce, counter, proof, and
advertisement state. It returns `false` after the first destruction and never
closes the shared physical M3 link.

## Authenticated tail-control transport ownership

Task 6 depends on the UDX-issued `M3CellLinkTransfer`, exact established-record
demultiplexing, reservation accounting, and physical-owner split defined by
Task 5 in the Gate 3B1 design's [`AdjacentLink`](2026-07-18-private-routing-gate-3b1-live-immutable-get-design.md#adjacentlink)
contract. The prior structural `physicalChannel` and
`tailControlTransportFactory` shapes cannot authenticate a UDX record/runtime
binding or prove logical-only teardown and are not accepted.

At M3 adoption, `m3-adjacency-runtime.js` creates a frozen empty PENDING
`TailControlTransportTransfer` bound to the exact runtime, tail capability, M3
cell borrower, branch/circuit/generation/extension index, local and peer M3
cell IDs, initiator direction, clock identity, and moved wire/local deadlines.
It is not bound to a logical lifetime until capability take. The transfer is
stored only inside the tail-capability record before publication. During
`takeM3TailCapability`, the runtime creates and arms the lifetime, atomically
binds the pending transport transfer and paired responder token to that exact
lifetime and owner callback, consumes the transfer internally, and returns
tail material containing an opaque `M3TailControlTransportOwner`. No
intermediate unbound transfer is returned. Failure destroys the unpublished
lifetime, transport owner/borrower, token/binding, and moved tail material.

`createTailControlSession` consumes the `M3TailControlTransportOwner` into the
stable `TailControlOwner`. The exact package-private M3 transport surface is:

```js
sendM3TailControl(owner, envelope1101)
receiveM3TailControl(owner)
takeM3ReceivedEnvelope(owner, envelope)
releaseM3ReceivedEnvelope(owner, envelope)
releaseM3TailControlTransport(owner)
```

`borrowTailControlTransport(session)` returns a frozen send/receive-only facade
backed by a private borrow record and those operations. Every call verifies
the exact live owner/lifetime/runtime generation and deadline before producer
entry and again after settlement. Destruction tombstones the borrow record
before logical unregister, so later calls fail without entering UDX/M3 code.
The same object-identical borrower moves through client completion, the
index-1 successor, the index-2 successor, and final handoff.

Before `sealTail` advances an ordered semantic counter, send acquires an
existing bounded UDX reservation with `reserveM3CellSend`. It then invokes
`M3AdjacencyRuntime.sealTail({ class: CELL_CLASS.CONTROL, payload: envelope })`
and commits the exact 1,200-byte cell. Seal failure aborts the unused
reservation. Post-seal commit failure spends the semantic counter and destroys
the logical owner; it never retries different bytes. Concurrent sends fail
busy.

RouteExtension creates both `EXTENDED_V1` and `TAIL_READY_V1` receive Promises
before sending `EXTEND_REQUEST_V1`, then awaits them in protocol order. A
responder keeps one reserved EXTEND receive and renews it only after the prior
request settles. The Task 5 UDX owner drops a packet lacking the exact
reservation before copy.

After M3 `openTail`, `receiveM3TailControl` atomically moves the complete
1,200-byte charge from the UDX receipt to the exact owned 1,101-byte envelope
in `M3_RECEIVED_ENVELOPES` before releasing the receipt. Its private record
binds the transport owner, runtime/lifetime/owner generations, deadline, and
charge; resolving the receive Promise does not release the charge. At the
start of `openExtended`, `completeClientExtension`, or responder admission,
tail control must consume that exact registered envelope with
`takeM3ReceivedEnvelope`; a structurally identical buffer is rejected. A
`finally` calls `releaseM3ReceivedEnvelope` after copy/decode and releases the
charge. Owner destruction clears every untaken or taken envelope and receipt.
Threshold-plus-one clears the incoming packet and fails only the logical
route.

Every asynchronous settlement rechecks its reservation, receipt/envelope,
owner/lifetime/runtime generation, and deadline. The inherited UDX bounds stay
at 64 packets/76,800 bytes globally and 8 packets/9,600 bytes per peer. The
additional bounds are four logical borrowers on a shared guard, one on a
non-shared adjacency, two receive reservations per initiator extension, one
per responder, and one full-cell charge for every retained receipt/envelope.
No byte or registration is unaccounted.

This transport changes no bytes: one exact 1,101-byte M3 context envelope fits
the existing 1,146-byte cell payload and produces one 1,200-byte CONTROL cell.
Reverse `EXTENDED_V1` and `TAIL_READY_V1` use the same borrower in the opposite
authenticated direction. Intermediate forwarding opens only M3 cells and
never tail-control AEAD.

`route-extension.js` removes `tailControlTransportFactory` from the exact
request shape and accepts no raw transport, endpoint, callback, destroy method,
or test issuer. It obtains the already-bound borrower only through
`borrowTailControlTransport(session)`. Failure to provide Task 5's genuine
UDX-issued, record-bound transport keeps Task 6 blocked; a structural object,
arbitrary callback, raw socket, physical destructor, direct dial, or test-only
issuer is not a substitute.

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
responder token. `createTailControlSession` passes the exact functions to
`takeM3TailCapability`, verifies them against the retained `clockIdentity`,
and moves `wireExpiresAt` and `localDeadline` without projecting again. Before
publishing an initiator session, it calls `shortenM3TailLifetime` to clamp, but
never reset, the moved local deadline to RouteManager's `absoluteDeadline`
while preserving the non-increasing wire bound and clock identity. Every later
bound is `min(previousLocalDeadline, newlyProjectedShorterBounds)` and is
committed only by the same shortening operation.
The endpoint initiator's local extension deadline is:

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
`RouteExtensionSession` already consumed them from Task 3 selection, and the
session owns branch, circuit, generation, current-tail identity, and
current-tail advertisement digest in its authenticated transcript. The
session verifies those bindings, next index, required role, advertisement
signature/digest, payload parameters, and both clock-domain bounds. The
repeated `absoluteDeadline` must equal the already-owned endpoint-local
deadline and cannot replace or extend it.

Before publishing `EXTEND_REQUEST_V1`, `sealExtend` validates the exact own
options and successfully shortens the stable lifetime to the effective
endpoint wire/local deadline. It then generates fresh client-tail ephemeral
and extension nonces, stores one pending client extension, encodes the
prototype-exact request, and seals it in forward ordered tail-control AEAD. A
second pending request is rejected. RouteExtension obtains the already-bound
facade only through `borrowTailControlTransport(session)`, reserves both
ordered reverse receives, and then sends the request. The index-1 successor
reuses the same borrower for the second extension without a new factory,
claim, context, counter, or deadline. Every await rechecks borrower identity,
owner/session generation, and the local monotonic deadline.

The complete advertisement is deliberately present in the authenticated
request. This reveals the selected next-hop identity and address to the
current tail, which must contact that peer, but not to unrelated DHT peers and
does not grant endpoint direct-send authority.

`openExtended(envelope)` first takes the exact registered `EXTENDED_V1`
envelope and verifies the prototype transcript, advertisement digest,
extension nonce, responder identity, redacted proof, ephemeral keys, limits,
branch/circuit/generation, authenticated wire expiry, and local deadline. It
then derives and owns successor material, spends/tombstones the old session,
and moves the stable owner to `CLIENT_WAITING_READY`. It does not construct or
publish a successor session. Before returning one opaque completion it
successfully shortens the lifetime to every newly authenticated non-increasing
wire/local bound. Any failure destroys the staged material and owner.

`completeClientExtension(completion, readyEnvelope)` spends the exact
completion before decode or crypto, takes the exact registered ready envelope,
and authenticates counter-zero reverse-direction `TAIL_READY_V1`. Only then
does it invoke lexical `createTailControlSessionFromOwnedMaterial`. Success
atomically moves the same owner, lifetime, deadline, clock identity, claimed
transport borrower, transcript/digest, shared secret, control/finalize keys,
nonce prefixes, and counters into one index-1/2 initiator `ACTIVE` session. It
does not commit Task 3 directory state; Task 9 commits the complete branch pair
only after both branches are ready. Failure destroys and zeroizes the complete
stage and returns no session. The enclosing RouteExtension consumes manager
cancellation and leaves Task 9's transaction owner to abort the path
reservation. `abortClientExtension` performs the same stage destruction
without activation.

## RouteExtension ownership transfer

`route-extension.js` imports `destroyTailControlSession` and
`borrowTailControlTransport`. `validTailControl` requires exactly the five
approved session methods, including `takeFinalExitHandoff`, and never requires
or invokes `.destroy`. Successor validation uses the same predicate.

The one-shot RouteExtension transfer contains the `ACTIVE` successor session
and its send/receive-only logical transport borrower. The same borrower is
reused for the second extension. The stable lifetime timer remains armed
across `takeRouteExtensionTransfer`; there is no timer-disarm/publication gap.
RouteManager takes both synchronously into an already-created local owner and
calls `destroyTailControlSession` in `finally` on every pre-publication
failure. Task 9 cannot synthesize a fresh deadline, timer, transport, tail
lifetime, or second transport binding.


## Responder flow

The current relay's authenticated transport delivers one exact registered
control envelope to `admitTailExtend(authority, envelope)`. The function first
takes that envelope through `takeM3ReceivedEnvelope`, opens ordered tail AEAD,
and accepts only `EXTEND_REQUEST_V1`. It verifies:

- exact current branch, circuit, generation, current tail, and next extension
  index;
- the complete advertisement's canonical encoding, signature, digest, route
  key, required role, canonical endpoint, and signed expiry;
- payload-parameter digest and requested limits;
- nonzero fresh client and extension nonces;
- the inherited effective deadline; and
- absence of a live, spent, duplicate, or conflicting extension.

The responder authority stores the exact stable owner/lifetime binding as a
subordinate of that owner. Admission does not consult a relay discovery cache.
It computes the actor-local effective wire/local bound and successfully calls
`shortenM3TailLifetime` before publishing one `AdmittedExtendRequest`.
Authority/session/token mismatch or timer failure destroys every transferred
state. Success stores `state.liveAdmission = capability` with the exact
current-tail binding and effective deadline.
`takeAdmittedExtendRequest(capability)` then transfers the complete owned
request, current-tail identity, current-tail advertisement digest, and deadline
once; it never separately returns a host or port.

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

`completeTailExtend(authority, completion)` consumes the one-shot completion,
requires object identity with `state.liveCompletion`, clears that field, and
moves the stable owner plus every rollback-owned field to
`RESPONDER_INSTALLING` before invoking the committer. It then takes the
`ExtensionLinkCompletion`, verifies the redacted responder proof and all
retained bindings, adopts the established M3 adjacency, seals prototype-exact
`EXTENDED_V1`, and passes the envelope plus staged runtime to
`TailExtensionCommitter`. The committer makes the current relay a forwarder
between predecessor and successor. Relay-owned link, forwarding, and control
contexts are staged only to carry `TAIL_READY_V1`; no endpoint next-tail
session, application-send authority, final-exit activation, or directory
commit exists.

Successful issuance creates the exact M3 lease described under Capability and
module ownership, then moves the stable owner, lease, publication claim,
forwarding facade, and rollback state into one `TailForwardingTransfer` at
`RESPONDER_FORWARDING_TRANSFER`. `completeTailExtend` emits the exact frozen
`{ transfer, publicationClaim }` runtime-event payload. Cancellation or
failure before the registry's synchronous take invokes
`revokeTailForwardingTransfer`, which owns claim/lease cleanup.

The relay registry copies both payload fields into tracked locals, presents the
object-identical claim when taking the transfer before its handler returns,
owns the exact frozen taken value, and runs
`destroyTakenTailForwardingTransfer` in `finally` until commit succeeds.
`publishM3TailForwarding` validates the stable lease's lifetime/callback and
both borrower identities, atomically publishes both runtime records under one
internal `M3ForwardingOwner`, and returns the exact receipt. It fails on clock
identity mismatch or an unprovable deadline invariant; there is no successful
fallback that leaves ownership ambiguous.

Only `commitTailForwardingTransfer` may consume that receipt, release the
logical lifetime/transport wrapper without unregistering the moved borrower,
and permit the registry to retain the facade. Runtime removal or either
runtime expiry later consumes the internal owner and both borrowers. Any
earlier failure destroys the publication, lease, facade, runtime pair, stable
owner, and all rollback state once.

At successor indices 1 and 2, `sealTailReady` is the only
`WAITING_READY -> ACTIVE` transition. The new tail first proves adopted-runtime
ownership and enters an irreversible sealing generation before signer or
randomness callbacks. After sealing it rechecks that generation, the live
lifetime/deadline, and adopted-runtime ownership, then atomically moves the
responder session and subordinate authority to `ACTIVE` before returning the
detached exact M3 context envelope. Any failure before that boundary destroys
both records and the envelope. ACTIVE indices 0 and 1 may admit one extension;
ACTIVE index 2 rejects EXTEND and may create only the final-exit handoff. The
endpoint authenticates the envelope in `completeClientExtension`; reverse
direction, counter zero, signature input, transcript digest, message ordering,
and bytes remain prototype-exact:

```text
EXTEND_REQUEST_V1 -> LINK_OFFER/LINK_ACCEPT -> EXTENDED_V1 -> TAIL_READY_V1
```

## Final-exit handoff

After valid index-2 readiness, no further EXTEND is accepted.
`takeFinalExitHandoff` tombstones the session and moves the same stable
owner/lifetime to `FINAL_EXIT_HANDOFF` with one opaque handoff containing
exactly:

```text
tail-control owner
290-byte transcript
shared secret
finalize keys and nonce prefixes
initiator flag
wireExpiresAt
localDeadline
clockIdentity
```

The logical M3 borrower/release authority stays inside the stable owner; the
handoff exposes neither raw transport nor a physical destructor.
Revocation/material destruction invokes the same logical release path. Taking
or consuming a final-exit handoff never releases `M3TailLifetime`.

`final-exit-activation.js` is the sole issuer and owner of activation claims
and activation owners. Its exact package-private surface is:

```js
createFinalExitActivationClaim(handoff)
claimFinalExitActivation(handoff, claim)
revokeFinalExitActivationClaim(claim)
destroyFinalExitActivationOwner(owner)
reserveFinalExitActivationOwner(owner)
consumeFinalExitActivationOwnerReservation(reservation, owner)
revokeFinalExitActivationOwnerReservation(reservation)
```

`createFinalExitActivationClaim(handoff)` accepts exactly one opaque handoff and
does not inspect its fields. It permits only one live claim for that object
identity, then creates one frozen empty `FinalExitActivationClaim` and one
paired frozen empty `FinalExitActivationOwner`, backed by module-local WeakMap
records. The claim is one-shot, records the exact handoff identity, and begins
`UNBOUND`; neither capability exposes a destructor, callback, handoff field,
clock, key, or transport. Neither is re-exported from HyperDHT's entry point.

Because `TAIL_CONTROL_OWNERS` remains lexical to `tail-control.js`,
`claimFinalExitActivation` coordinates through this exact fixed
package-private bridge, never a caller-supplied callback:

```js
prepareTailControlFinalExitActivation(handoff, activationOwner)
commitTailControlFinalExitActivation(transfer, activationOwner)
revokeTailControlFinalExitActivation(transfer)
destroyTailControlFinalExitActivation(tailControlOwner, activationOwner)
```

The claim operation validates its exact two arguments and requires the claim's
recorded handoff identity to equal the supplied handoff. It then
tombstones/spends the claim and detaches its paired activation owner before
invoking the fixed tail-control bridge. The three reservation operations above
are
cross-module support used only by `tail-control.js`: reserve atomically changes
the exact module-issued owner from `UNBOUND` to `RESERVED` and returns a frozen
empty reservation; consume proves object identity and changes it to `ACTIVE`;
revoke tombstones the reservation and destroys an otherwise-unbound owner.

Prepare verifies the object-identical live handoff recorded by the stable
owner, stage `FINAL_EXIT_HANDOFF`, exact owner generation, same live
`M3TailLifetime` and `ownerDestroy`, same `wireExpiresAt`, `localDeadline`, and
`clockIdentity`, and `monotonicNow() < localDeadline`. It rejects a
consumed/revoked handoff, alternate clock, or replacement deadline.

Before consuming the handoff or calling back into either package-private
module, prepare removes the handoff from the live owner slot, advances the
owner generation, sets a non-reentrant claiming flag in the
`FINAL_EXIT_HANDOFF` record, and tombstones all prior session/handoff
consumers. It then calls `reserveFinalExitActivationOwner` with the exact
module-issued owner, consumes `final-exit-handoff.js`'s one-shot handoff, and
returns only this frozen package-private result:

```js
{
  transfer,
  material
}
```

`transfer` is an empty `TailControlFinalExitActivationTransfer` backed by
`tail-control.js`; its hidden record binds the stable owner, new generation,
lifetime/callback identity, activation-owner identity, exact module-issued
owner reservation, claimed handoff, and rollback state. `material` is the
exact owned final-exit material already listed above; no new key, deadline,
transport, or destructor is added.

`claimFinalExitActivation` installs that material into the still-live paired
`FinalExitActivationOwner` and then calls
`commitTailControlFinalExitActivation(transfer, activationOwner)`. Commit
revalidates transfer/owner object identity, owner generation, live lifetime,
clock identity, and deadline; atomically consumes the hidden reservation
through `consumeFinalExitActivationOwnerReservation`; removes the claiming
record before any callback; and changes the stable stage to
`FINAL_EXIT_ACTIVATION` with that exact activation owner as its only consumer.
The claim operation returns only
the opaque activation owner. Task 7 keeps the existing lifetime timer armed,
reuses `localDeadline` without projection/reset, and uses `wireExpiresAt` only
for authenticated transcript comparison.

Claim revoke before take tombstones the claim and destroys its unbound
activation owner. Any failure after claim take runs
`revokeTailControlFinalExitActivation(transfer)`, which consumes
`revokeFinalExitActivationOwnerReservation` if still reserved, and then
`destroyFinalExitActivationOwner(owner)` in `finally`. Both registrations are
tombstoned before cross-module calls; handoff/material and stable owner are
destroyed through the universal order, and all buffers are zeroized. If
lifetime/runtime teardown wins during prepare or after commit, the stable
`ownerDestroy` resolves the claiming transfer or exact activation owner and
calls the fixed module destructor once. Conversely,
`destroyFinalExitActivationOwner` calls
`destroyTailControlFinalExitActivation` with the exact paired identities before
zeroizing activation state. Revoke, expiry, destroy, commit failure, and
reentry are idempotent after the first tombstone; no path leaves an activation
owner live without the stable owner or accepts an arbitrary destructor.

A handoff cannot cross processes. The remote exit has its own handoff and
actor-local projection; no monotonic value is encoded or compared by another
actor. The handoff exposes no destination table, DHT socket, endpoint tuple, or
final payload key bytes to intermediate relays.

## Failure, replay, and cleanup rules

All public and private transition functions reject accessor-backed or
extra-keyed option objects before retaining data. Owned buffers are copied on
admission and cleared on transfer, abort, or destroy. A capability is removed
from its live WeakMap and added to its spent set before any external operation.

Every destructive transition follows this universal order:

1. delete live WeakMap registrations, add spent/destroyed tombstones, advance
   generation, and mark the stable owner `DESTROYING`;
2. tombstone any transport-borrow record, forwarding transfer/taken/publication
   record, final-activation claim/transfer/owner binding, and
   responder-authority subordinate; then capture and clear timer handles,
   logical M3 borrower/release capability, pending completion, and
   secret-bearing fields from reachable owner state;
3. cancel the logical lifetime and responder-authority timers;
4. abort/tombstone pending client or responder completion/admission;
5. invoke either the captured package-private logical M3 release or the exact
   M3 forwarding revoke/publication-destroy path once with exceptions
   suppressed; neither can reach shared physical close authority;
6. clear the paired responder token/binding, signer, factory, committer,
   activation claim/transfer, and other one-shot capabilities; and
7. zeroize detached cells, envelopes, nonces, advertisements/proofs,
   transcripts/digests, shared/control/finalize keys, nonce prefixes, and
   counters before marking `DESTROYED`.

Canceller and release callbacks may throw or synchronously reenter session,
runtime, token, transport, authority, handoff, or activation cleanup. Because
registrations and capability slots are tombstoned first, recursive cleanup is
a no-op and outer cleanup continues. Borrower sends/receives verify the exact
live owner/lifetime/runtime generation and deadline before producer entry and
after settlement; destruction rejects pending operations, and later calls fail
without entering UDX/M3 code.

The frozen forwarding event payload is not a third owner. Before registry
take, the live `TailForwardingTransfer` record owns both payload capabilities,
the lease, and rollback. A handler throw, cancellation, malformed payload, or
failure to take synchronously calls `revokeTailForwardingTransfer` and clears
the paired claim. After take, the tracked `taken` record owns all cleanup and
the payload is inert. Missing, swapped, foreign, or replayed transfer/claim
pairs fail object-identity validation and cannot acquire a lease or facade.

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

Endpoint-local cancellation or failure first tombstones RouteExtension/session
mutation and consumes manager cancellation, then destroys the stable logical
owner through the universal order above. A pending client completion is
aborted; no successor session exists before valid READY. The logical borrower
is released without closing the shared pinned-guard physical link. Task 9's
transaction owner aborts the path reservation. Endpoint-owned nonces, secrets,
transcript copies, advertisements, proofs, and semantic bytes are zeroized.
An observable context/transport close may trigger relay cleanup, but the
protocol does not require such a signal.

Relay-local failure before forwarding publication destroys the stable owner
through the same order: it tombstones the subordinate responder authority,
aborts its one live adjacent factory, cancels local timers, revokes admission,
completion, committer, signer, responder-token state, and any live one-shot
adoption, then destroys the half-built next runtime, physical channel, and
adjacent socket owner and zeroizes request, proof, transcript, and cache bytes.
The borrowed `M3ResponderAdopter` remains owned by its
`M3AdjacencyAuthority`; the already-established predecessor link and any
shared guard physical owner are not reachable through logical-tail release.

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
  half-built second extensions fail closed;
- real Node and Bare UDX loopback issuance, registration, take, send, receive,
  and logical release use only Task 5's OPEN-record issuer plus lexical
  authenticated branch binding; wrong issuer/binding, endpoint/link/setup,
  tuple/peer, link-epoch provenance, M3 generation/circuit/direction, physical
  policy, and replay fail before authority transfer;
- existing UDX packet/byte ceilings, per-receipt and per-envelope full-cell
  accounting, shared/non-shared borrower limits, exact release accounting, and
  physical-link preservation after logical release hold at every failure
  boundary;
- capability take followed by M3 runtime destroy/context close clears the
  registered lifetime, owner, responder binding/token, borrower, envelopes,
  and secrets once;
- adjacency-runtime and logical-tail timers remain independent; local-only and
  wire/local shortening are non-increasing, and synchronous firing,
  scheduler throw, invalid handles, reentry, post-schedule expiry, and
  cancellation cannot publish partial lifetime state;
- responder-token mismatch and revoke before/after consume, every exact phase
  provenance case, owner-generation mismatch, and subordinate-authority
  mismatch fail closed;
- current session -> staged client completion -> successor session preserves
  one stable owner/lifetime and the object-identical borrower through both
  extensions; abort and invalid READY zeroize the complete stage;
- explicit destroy, double destroy, runtime teardown, token revoke, callback
  reentry, and logical release obey the universal tombstone-first order;
- RouteExtension transfer has no timer-disarm gap; forwarding tests freeze and
  exact-shape-check `{ transfer, publicationClaim }`, reject missing/extra/
  accessor fields and swapped/foreign/replayed pairs, prove synchronous take
  before handler return, and cover handler throw/cancel before take;
- forwarding tests also cover wrong/replayed lease, exact taken-value
  ownership, moved-borrower non-release, callback/lifetime mismatch, both
  dual-runtime clock/deadline comparisons, failure before/after runtime
  publication, receipt/commit failure, and exact pair/slot rollback before a
  facade is retained;
- final-exit tests exercise claim create/revoke/replay, foreign handoff or
  activation owner, lifetime/callback/clock/deadline mismatch, reentrant
  prepare, expiry between prepare/commit, commit failure, owner destruction
  from either module, handoff revoke, and Task 7/Task 9 movement of the same
  owner, lifetime, clock identity, deadline, and borrower rather than new
  state;
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
anonymity. It closes Task 6's responder, logical-lifetime, and authenticated
transport ownership gaps while preserving the approved Gate 3B1 boundary.

## Plan effect

This repository-spec incorporation intentionally does not edit the
implementation plan while the written revision awaits owner review. Once that
review passes, the plan must be reconciled in place without renumbering tasks:
Task 5 Step 6; Task 6 Steps 2, 7, 8a/8b, 9, 10, 11, and 12; Task 7 Steps
3-5; and Task 9 Steps 1 and 3-4. Task 5's UDX-issued transfer and record-bound
dispatch are prerequisites; Task 6 implementation cannot resume by substituting a
structural or test-only transport.

The earlier responder-authority dependency order remains in force. Task 6 Step
5 stays split into 5a for `takeExtensionResponse` ownership correction and
counted late-settlement quarantine, then 5b for the honest admitted link
exchange after Step 8a creates token-gated authenticated admission. Step 8b
owns completion, abort, TAIL_READY, and socket-owner-lease movement into M3.
Responder transitions remain in `tail-control.js`; relay signing remains in
`relay-identity-signer.js`; Task 3 evidence remains unchanged and no
`selectedEvidenceExpiry` field is added. Pending-offer reservations still move
to the live operation or counted quarantine and are never released while
callback code remains unsettled.

The owner-approved lifetime/transport amendment affects only the following
private implementation and focused-test owners when implementation resumes:

```text
lib/private/udx-cell-endpoint.js
test/private/udx-cell-endpoint.js
lib/private/extension-setup-channel.js
test/private/extension-setup-channel.js
lib/private/guard-link.js
test/private/guard-link.js
lib/private/m3-adjacency-runtime.js
test/private/m3-adjacency-runtime.js
lib/private/tail-control.js
test/private/tail-control.js
lib/private/route-extension.js
test/private/route-extension-session.js
lib/private/final-exit-handoff.js
test/private/final-exit-handoff.js
lib/private/final-exit-activation.js
test/private/final-exit-activation.js
lib/private/tail-extension-committer.js
test/private/tail-extension-committer.js
```

Later Task 7/Task 9 integration must prove transfer of the same stable owner,
lifetime, authenticated borrower, clocks, and deadlines rather than create new
state. The amendment adds only the exact package-private capabilities and
operations specified above. It changes no wire bytes, public API, discovery
boundary, direct-authority boundary, or cross-clock rule.
