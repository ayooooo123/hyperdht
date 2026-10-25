# Relay Capability Quality Hardening Design

## Scope

This design closes the seven Task 2 code-quality findings in
`lib/private/relay-capability.js` without exposing a public discovery or dialing API.
The existing advertisement wire format, CAPS transcripts, active-challenge vectors,
and future Task 3 candidate-directory contract remain unchanged.

## Consumer and Task 3 compatibility

Current consumers use one flow:

1. `RelayCapabilityVerifier.accept()` returns a frozen defensive projection.
2. `createActiveChallengeSendAuthority()` binds a CAPS query to that exact live
   projection.
3. `RelayCapabilityVerifier.beginChallenge()` consumes the authority and returns a
   new verified defensive projection.

Task 3 accepts defensive advertisement evidence and does not require stable projection
object identity, indefinite projection retention, or a projection-release API. The
bounded lifecycle therefore remains internal and does not expand the reviewed Task 2
surface.

## Projection leases

Each accepted record retains at most `MAX_CAPABILITY_ADVERTISEMENTS` (eight) live
projections. Publishing a ninth projection evicts the oldest projection for that record
before publishing the new one. Eviction:

- removes only that projection from the record, verifier, and owner registries;
- clears all five owned byte buffers;
- revokes only send authorities explicitly bound to the evicted projection;
- does not affect projections or authorities belonging to another record; and
- leaves the newest projection usable.

FIFO eviction preserves distinct defensive copies and avoids a new release API. Record
replacement, quarantine, expiry, invalidation, and destroy continue to revoke every
projection belonging to the affected record.

## Active-challenge completion and replay tombstones

After signature verification, key agreement, and proof construction, completion samples
both clocks again. Before recording replay state or publishing a projection it requires:

- the monotonic deadline has not elapsed or moved backwards;
- wall time remains before the challenge deadline and signed advertisement expiry;
- the source projection still selects the same live record; and
- the verifier still owns that record.

Failure returns the existing normalized private-route error and publishes no projection
from cleared record bytes.

Replay tombstones become a bounded insertion-ordered map from response digest to expiry.
Entries expire at the challenge deadline, are pruned lazily on verifier operations, and
new completion fails closed with `ERR_BUSY` when all 4,096 retained entries are still
live. No unexpired replay claim is evicted. Expiry and record cleanup make capacity
available for later sequential challenges, preventing permanent exhaustion while
retaining replay rejection throughout each response's challenge lifetime. Invalidation
and destroy clear the map.

## Responder authority state and rotation

All `ActiveChallengeResponderAuthority` secrets, maps, hooks, timers, and lifecycle flags
move into a module-local `WeakMap`. The returned authority is frozen and exposes only its
prototype methods. A deep-imported test-only observer function provides narrow access to
post-detachment, post-zeroization events and non-authorizing metadata needed for cleanup
assertions; it never receives a mutable reference to a live secret, binding, timer, map,
hook, or authority state. It is absent from the documented package entry point.

Rotation stages every required timer before publishing a new current/prior secret set.
Synchronous timer callbacks during installation are detected. A throwing, synchronous,
or reentrant scheduler cannot leave a published secret without its required schedule:
the operation either publishes the complete staged rotation or destroys and clears the
authority. Staged handles and secrets are cleared on failure, including when timer cleanup
throws.

## CAPS mask binding and history ownership

`admitCapsRetry()` requires the signed advertisement capability mask to equal the
cookie-authenticated `requestedCapabilityMask`. A correctly issued cookie for a mismatched
query and advertisement is rejected before binding publication or response cryptography.

The unread `history.encoded` copy is removed. History retains only the digest, epoch,
expiry, bounded route-key set, and poison flag used by current decisions.

## Test strategy and commits

Implementation follows strict red/green TDD in five scoped commits:

1. Post-crypto deadline/liveness checks and bounded expiring replay tombstones.
2. Eight-projection FIFO leases with projection-bound authority revocation.
3. WeakMap responder state and atomic staged timer rotation.
4. Exact CAPS requested-mask binding.
5. Removal of the unread history encoding copy.

Each commit runs the focused relay-capability test under Node and Bare. The final state
also runs the full private-routing suite under both runtimes, runner generation, scoped
Prettier, and `git diff --check`. Repository-wide `test/all.js` is intentionally excluded.
