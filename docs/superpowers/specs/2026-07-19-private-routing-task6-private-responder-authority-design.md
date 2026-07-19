# Gate 3B1 Task 6: Private Tail Responder Authority

**Status:** Approved design amendment pending document review

**Date:** 2026-07-19

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
object. Responder operations live behind a package-private authority in a
separate `tail-control-responder.js` module. That module is internal to
`lib/private/`, is not re-exported from HyperDHT, and cannot be reached through
a public constructor.

The authority is an empty frozen capability backed by a `WeakMap`. It is issued
only while the relay role constructs its authenticated tail runtime. The
issuer binds it to exactly one responder `TailControlSession`, its current
adjacent-link owner, its `M3AdjacencyAuthority`, its
`TailExtensionCommitter`, and its inherited deadline. Endpoint-side session
construction cannot request, synthesize, or receive this authority.

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
8. No timer, retry, callback, or nested session can extend the inherited
   absolute deadline.
9. Authentication, replay, expiry, cancellation, reentrancy, or setup failure
   destroys all new adjacency and pending-tail state. It does not create a
   direct fallback and does not replace the already-pinned guard.
10. Extension index 1 must select a safety relay; extension index 2 must select
    a DHT exit. No third extension is valid.

## Capability and module ownership

`tail-control.js` owns the exact EXTEND/EXTENDED/TAIL_READY codecs, ordered
control AEAD, transcript derivation, initiator state, and final-exit handoff.
Its session object exposes only the consumer methods listed above.

`tail-control-responder.js` owns the package-private responder authority and
the responder state transition functions:

```js
createTailControlResponderAuthority(session, options)
admitTailExtend(authority, envelope)
completeTailExtend(authority, completion)
abortTailExtend(authority)
sealTailReady(authority)
destroyTailControlResponderAuthority(authority)
```

These names are an internal contract, not package exports. Tests may require
the private file directly. `createTailControlResponderAuthority` is callable
only by the relay-role setup owner and accepts exact own data:

```js
{
  adjacencyAuthority,
  extensionCommitter,
  adjacentLinkFactory,
  tailReadySigner,
  absoluteDeadline,
  now,
  randomBytes
}
```

`tailReadySigner`, `absoluteDeadline`, `now`, and `randomBytes` are mandatory
for every responder index. For current-tail indices 0 and 1, the three
extension resources are mandatory as well. At terminal index 2 those three
keys are forbidden because that role can become a final exit but cannot extend
again. Construction validates the variant against the consumed tail transcript
before retaining any capability.

`tailReadySigner` and `adjacentLinkFactory` are empty, WeakMap-backed relay
capabilities. The signer accepts only the exact TAIL_READY signature input for
the bound local relay identity; it never returns or transfers the identity
secret key.

`adjacentLinkFactory` is itself an empty, WeakMap-backed relay capability. It
does not expose a callback property. Its private consumer accepts one admitted
request capability and internally decodes the already-verified advertisement
to create exactly one adjacent link. Its result is an
`ExtensionLinkCompletion`; it never returns a socket or tuple.

`extension-setup-channel.js` remains the owner of LINK_OFFER/LINK_ACCEPT and
the physical setup channel. `extension-link-completion.js` remains the owner of
the completed link plus redacted proof. `m3-adjacency-adopter.js` adopts that
link. `tail-extension-committer.js` stages `EXTENDED_V1` and the next relay
runtime. None of these modules learns the full route.

The private responder authority may invoke imported module functions, but it
must not store endpoint-provided callbacks. Its clock and randomness functions
are supplied by the relay runtime owner and use the same hardened contracts as
the adjacent setup modules. It must remove
its live WeakMap state before invoking destruction or transport operations so
reentrant calls see a tombstone.

## Construction and deadline

`createTailControlSession(capability, options)` consumes one M3 tail capability.
Its exact common options are `absoluteDeadline`, `now`, and optional `crypto`
for deterministic vectors. `absoluteDeadline` is a `u64` monotonic deadline
inherited from the `GUARD_PINNED` route construction attempt; it is mandatory
for both roles.

The effective session deadline is:

```text
min(tail capability expiry, absoluteDeadline)
```

The effective initiator deadline for one selected extension is:

```text
min(
  session effective deadline,
  extension start + 5,000 ms,
  signed advertisement expiry,
  requested-limits expiry,
  selected-evidence expiry
)
```

The responder cannot independently observe the endpoint's selection lifetime.
The initiator therefore clamps `requested-limits expiry` to the selected
evidence and signed expiry before encoding the request. The responder's
effective deadline is `min(session effective deadline, start + 5,000 ms,
signed advertisement expiry, requested-limits expiry)`.

Every nested link offer, accept, proof, retry, timer, and completion receives
that same effective deadline. The deadline is checked before and after every
external or reentrant operation. A later session, retry, duplicate, or callback
may only preserve or reduce it.

## Initiator flow

`RouteExtensionSession` first consumes Task 3 selected evidence using the exact
transaction, branch class, position, generation, and extension-index bindings.
The resulting owned material contains the complete canonical advertisement,
its digest, role/index metadata, and selection expiry. It contains no dial
authority.

It calls `session.sealExtend(options)` with exact own data:

```js
{
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
signature, advertisement digest, payload parameters, and all expiries. It then generates
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
and effective expiry before deriving the next tail. It returns one opaque
client completion. It does not publish or commit the next tail yet.

`completeClientExtension(completion, readyEnvelope)` opens and authenticates
`TAIL_READY_V1` and returns the next `TailControlSession` atomically. It does
not commit the Task 3 directory transaction: Task 9 commits the complete branch
pair only after both branches are ready. On failure it destroys the uncommitted
next session, consumes the manager cancellation capability, and zeroizes
retained material; the transaction owner then aborts the path reservation.
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
records its exact current-tail binding and effective deadline. The ordinary
consumer `takeAdmittedExtendRequest(capability)` transfers the complete owned
request, current-tail identity, current-tail advertisement digest, and deadline
once. It does not separately return a host or port.

Only the relay-owned adjacent-link factory may consume the admitted capability.
It decodes the canonical endpoint internally from the verified signed
advertisement, opens LINK_OFFER/LINK_ACCEPT against exactly that endpoint, and
produces one `ExtensionLinkCompletion`. It may neither enumerate alternatives
nor retry a different tuple.

Taking the admitted request moves its full owned request bytes to the adjacent
link owner but leaves only digests, nonces, indices, and the effective deadline
inside the responder authority for later correlation. `completeTailExtend`
therefore accepts the authority and one `ExtensionLinkCompletion`; it cannot
consume or inspect the already-spent admission capability a second time.

`completeTailExtend(authority, completion)` consumes that one-shot completion,
verifies the redacted responder proof and all retained expected bindings,
adopts the established M3 adjacency, seals prototype-exact
`EXTENDED_V1`, and passes the envelope plus staged next runtime to the
`TailExtensionCommitter`. The committer makes the current relay a forwarder
between its predecessor and new successor, but keeps the new tail context
unavailable to endpoint application traffic until the authenticated
`TAIL_READY_V1` transition completes.

The new tail relay calls `sealTailReady` only after it owns the adopted link and
is ready to process authenticated tail control. The responder authority uses
its bound signing capability and randomness source; the responder session does
not expose `sealReady` or raw secret-key input. The endpoint initiator validates
the result inside `completeClientExtension`. The exact reverse direction,
counter-zero rule, signature input, and transcript digest remain those of the
prototype. This amendment changes ownership, not message ordering or bytes:

```text
EXTEND_REQUEST_V1 -> LINK_OFFER/LINK_ACCEPT -> EXTENDED_V1 -> TAIL_READY_V1
```

## Final-exit handoff

After extension index 2 reaches valid `TAIL_READY_V1`, no further EXTEND is
accepted. `session.takeFinalExitHandoff()` returns one opaque handoff containing
the tail-control owner, exact 290-byte tail-control transcript, shared secret,
finalize keys and nonce prefixes, initiator flag, and effective expiry.
`consumeFinalExitHandoff` transfers it once into Task 7. Revocation, session
destroy, or expiry erases every field.

The handoff exposes no destination table, DHT socket, endpoint tuple, or final
payload key bytes to intermediate relays.

## Failure, replay, and cleanup rules

All public and private transition functions reject accessor-backed or
extra-keyed option objects before retaining data. Owned buffers are copied on
admission and cleared on transfer, abort, or destroy. A capability is removed
from its live WeakMap and added to its spent set before any external operation.

Duplicate authenticated datagrams may receive only the already-authorized
cached semantic response under a fresh datagram counter. Conflicting duplicates
are authentication failures. They never allocate a second adjacency, advance a
counter twice, extend a timer, or revive a capability.

On cancellation or failure, teardown order is:

1. tombstone the session/authority mutation and consume manager cancellation;
2. cancel every opaque timer handle and prohibit later callbacks;
3. revoke pending admission, completion, adopter, and committer capabilities;
4. destroy the half-built next runtime, physical setup channel, and adjacent
   socket owner;
5. abort the selected-evidence reservation; and
6. zeroize nonces, shared secrets, transcript copies, advertisements, proofs,
   and cached semantic bytes.

The already-established predecessor link remains owned by its relay. At the
endpoint, failure of either extension leaves only the pinned guard link; it
does not bootstrap, discover, or dial another peer.

## Verification contract

Task 6 is not complete until Node and Bare tests prove:

- exact known-answer vectors and mutation rejection for
  `EXTEND_REQUEST_V1`, `EXTENDED_V1`, `TAIL_READY_V1`, the 290-byte transcript,
  KDF labels, and redacted responder proof;
- initiator sessions cannot obtain or invoke responder authority, and responder
  sessions do not expose responder methods;
- the authority, admission, link completion, adopter, committer, client
  completion, and final-exit handoff are opaque and one-shot;
- a real in-memory guard -> middle -> DHT-exit trace emits only the four
  specified semantic control stages after pinning;
- the current tail contacts exactly the tuple inside the authenticated selected
  advertisement, while an endpoint direct-send trap remains untouched;
- a semantic trap rejects `RELAY_DISCOVER_V1`,
  `RELAY_DISCOVER_RESPONSE_V1`, random discovery targets, DNS, arbitrary
  enumeration, and Task 9 `BranchPathAuthority` dependencies;
- no next context or directory reservation is active before valid
  `TAIL_READY_V1`;
- duplicate cached responses, conflicts, wrong bindings, wrong roles, malicious
  proofs, expired advertisements, deadline races, a dropped setup packet,
  cancellation, quota rejection, throwing/reentrant clocks and schedulers, and
  half-built second extensions fail closed; and
- every failure leaves zero new live adjacency, timer, callback, capability,
  transport, semantic cache, or secret, while preserving only the already
  pinned guard where the Task 6 plan requires it.

The aggregate discovery-edge scan must find no discovery symbols or imports in
`route-extension.js`, `tail-control.js`, or `tail-control-responder.js`. The
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

Task 6 Step 4 is amended to add the package-private responder authority and to
replace prototype discovery-cache and `BranchPathAuthority` admission with the
selected-evidence flow above. Steps 1-3 and 5-7 remain in force. The Task 6
implementation plan must add `lib/private/tail-control-responder.js` and its
focused test before implementation resumes. No later task is otherwise
renumbered or broadened.
