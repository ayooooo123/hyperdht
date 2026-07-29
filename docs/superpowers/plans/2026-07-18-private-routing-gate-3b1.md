# Private Routing Gate 3B1 Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents are available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Gate 3A's trusted logical route authority with signed relay discovery, a pinned guard, two authenticated live three-position branches, and one fail-closed immutable DHT get whose endpoint emits packets only to its guard after pinning.

**Architecture:** Migrate the reviewed live-route kernel from prototype commit `0305df915b6a767093f9e75e6c06bc0a35da6169` into focused CommonJS modules under `lib/private/`, then reconcile it with Gate 3A's hardened codecs and DHT-RPC request-transport seam. A private controller owns the only state transition function; bootstrap authority is revoked atomically at guard pinning, route construction can consume signed candidate evidence only through the guard, and a terminally authenticated DHT exit owns the only ordinary DHT socket and destination table. The public HyperDHT constructor and direct wire behavior remain unchanged.

**Tech Stack:** CommonJS JavaScript, Node.js, Bare, `brittle`, `b4a`, `hypercore-crypto`, `sodium-universal`, `udx-native` through the pinned DHT-RPC/HyperDHT runtime, DHT-RPC request-transport mode, Linux network namespaces, `tcpdump`, GitHub Actions.

---

## Scope, sources, and execution rules

Run implementation commands from:

```text
/Users/jd/Documents/Codex/2026-07-10/task-extract-three-packages-into-standalone/hyperdht-private-routing
```

Canonical approved design:

```text
docs/superpowers/specs/2026-07-18-private-routing-gate-3b1-live-immutable-get-design.md
```

Canonical protocol and migration record:

```text
docs/private-routing-v1.md
docs/private-routing-migration.md
```

Read-only migration source:

```text
repository: /Users/jd/.config/superpowers/worktrees/peartube/private-routing
commit: 0305df915b6a767093f9e75e6c06bc0a35da6169
source root: packages/private-routes
wire registry: docs/superpowers/specs/2026-07-14-native-dht-private-routing-m3-wire-registry.md
```

Every migrated file must include this provenance comment before its first exported symbol:

```js
// Ported from the reviewed private-routes prototype at commit
// 0305df915b6a767093f9e75e6c06bc0a35da6169 and narrowed to Gate 3B1.
```

Use `git show 0305df915b6a767093f9e75e6c06bc0a35da6169:packages/private-routes/<relative-file>` to read prototype bytes. Never modify the prototype worktree. Convert ESM imports/exports to CommonJS, preserve Holepunch no-semicolon style, use `b4a` instead of `Buffer`, retain `Cargo.lock`-style reproducibility discipline for exact dependency SHAs, and do not add a public private-routing export.

For each created `test/private/<name>.js`, add `require('./private/<name>')` to `test/private-routing.js` in the same red-test step. After changing that aggregator, run `npm run test:generate` and inspect the generated `test/all.js`; a focused pass is insufficient if the aggregate runner omits the test.

Use test-driven development for every task: write one bounded failing behavior, run it and observe the intended failure, implement only that behavior, rerun Node and Bare focused suites, then commit. Do not migrate unused prototype modules or enable commands beyond immutable get.

## Completion boundary

This plan completes only Gate 3B1. It must not:

- add `privateRouting`, `privacy`, or required-mode options to public constructors;
- add Hyperswarm, peer-stream, PearTube, iOS, Android, mobile background, or app UI behavior;
- route announce application traffic or support immutable put, mutable operations, private presence, or peer descriptors;
- enable DNS, TCP, direct DHT fallback, hole punching, direct races, guard replacement, or post-pin relay discovery;
- claim production anonymity or close aggregate Delivery Gate 3.

The implementation is accepted only when the exact twelve-item completion contract in the approved design passes fork-native CI at the recorded head SHA.

## File and responsibility map

Existing Gate 3A modules remain focused:

- `lib/private/protocol.js`: frozen numeric registries, M3 object envelope, domains, role derivation.
- `lib/private/destination-ref.js`: exact destination-reference codec shared
  without a CommonJS dependency cycle.
- `lib/private/routed-dht.js`: routed-request and new routed-reply wire ownership;
  it re-exports the destination codec for Gate 3A compatibility.
- `lib/private/routed-dht-io.js`: address-free DHT-RPC adapter; logical fake responses are replaced by authenticated encoded replies.
- `lib/private/cell-codec.js`, `route-payload.js`, `fragments.js`, `counters.js`, `crypto-suite.js`: unchanged fixed-cell transport primitives.

New production units have one owner each:

- `relay-capability.js`: signed relay advertisement and active challenge codecs/verification.
- `relay-candidate-directory.js`: sealed, bounded, non-dialing advertisement evidence.
- `bootstrap-envelope.js`: exact 1,200-byte signed adjacent bootstrap envelope.
- `bootstrap-io.js`: sole bounded pre-guard direct authority and exposure report.
- `link-setup.js`, `topology-grant.js`: exact adjacent setup tickets and
  one-shot topology/link handles required by the bootstrap envelope.
- `link-parameters.js`: one exact owner for admitted-limit and payload-parameter
  bytes/digests shared by guard, tail, and final-exit handshakes.
- `guard-link.js`: authenticated index-zero links plus the relay-owned,
  request-bound extension adjacent-link factory, dial authority, accepted
  adjacency/replay transfer, and no endpoint-visible tuple or raw identity key.
- `relay-identity-signer.js`: empty WeakMap-backed, relay-identity-owned,
  domain-limited LINK_OFFER, LINK_ACCEPT/redacted-proof, and TAIL_READY signers.
- `guard-reconnect-authority.js`: single-use, exact-tuple suspend/resume authority.
- `m3-context.js`: M3 inner associated-data and fixed envelope codecs.
- `m3-adjacency-adopter.js`, `m3-adjacency-runtime.js`: one-shot link adoption,
  paired responder-tail/token ownership, actor-local wire-expiry projection,
  proactive runtime timers, and installed forwarding ownership.
- `link-bootstrap-session.js`, `link-control-session.js`, `udx-adapter.js`, `udx-cell-endpoint.js`: live adjacent UDX lifecycle, liveness, queue bounds, direct-authority audit points, and cell delivery.
- `tail-control.js`: authenticated in-route `EXTEND_REQUEST`/`EXTENDED`/
  `TAIL_READY`, initiator state, co-located token-gated responder transitions,
  ordered AEAD counters, and terminal handoff.
- `extension-setup-channel.js`, `extension-link-completion.js`: physical
  LINK_OFFER/LINK_ACCEPT/proof exchange and one-shot completed-link ownership.
- `route-extension.js`: endpoint-local selected-evidence initiator orchestration
  with separate wall/monotonic clocks and no discovery or dialing surface.
- `tail-extension-committer.js`: staged `EXTENDED` installation and
  failure-atomic opaque forwarding-facade transfer.
- `final-exit-handoff.js`: one-shot same-runtime terminal handoff carrying
  authenticated wire expiry, projected local deadline, and clock identity.
- `final-exit.js`, `final-exit-activation.js`: terminal ACTIVATE/READY/ACK/OPEN transcript and inner AEAD.
- `branch-path-authority.js`, `route-manager.js`: later Task 9-only branch
  publication, global deadline, rotation, and generation ownership; Task 6 has
  no `BranchPathAuthority` dependency.
- `relay-service.js`: relay circuit quotas, fairness, expiry, cancellation, and tombstones.
- `dht-exit-seeds.js`: new `0x0045` DHT-only seed object.
- `dht-exit-test-topology-grant.js`: test-issuer-only verification of exact, signed, one-shot isolated-address grants; it is not exported by the package.
- `dht-exit-destination-table.js`: provenance-qualified destination admission, opaque references, probes, and generation invalidation.
- `dht-exit-wire.js`: exact DHT-RPC client packet and immutable-response codec ownership.
- `dht-exit-reservation.js`: terminal-OPEN paired destination-table/socket reservation channel.
- `dht-exit-audit-events.js`: non-authorizing, test-issuer-only audit channel consumed by the real table and exit IO owners.
- `dht-exit-io.js`: immutable-get-only ordinary DHT request/reply correlation at the exit, with paired send and settlement authorities.
- `live-route-authority.js`: seven-method live branch authority behind the existing nine-method `RoutedDHTIO` adapter.
- `endpoint-bootstrap-authority.js`: aggregate endpoint bootstrap capability and its explicit signal transitions.
- `private-routing-controller.js`: sole internal state transition function, private DHT instance, and lifecycle ownership.

Test-only units remain outside the package API:

- `test/private/live-topology-fixture.js`: deterministic in-process roles, clocks, and authority traps.
- `test/private/direct-authority-audit.js`: empty-by-default, test-issued observation cap for real production create/bind/trySend authority use; it cannot inject an adapter or authorize a send.
- `test/private/process/*`: role-scoped Node/Bare process coordinator and runners.
- `test/private/namespace/*`: Linux namespace topology, capture parser, packet oracle, and negative controls.

## Chunk 1: Frozen wire, relay evidence, and bounded guard bootstrap

### Task 1: Freeze the Gate 3B1 registry, errors, and routed reply

**Files:**

- Modify: `lib/private/protocol.js`
- Modify: `lib/private/errors.js`
- Create: `lib/private/destination-ref.js`
- Modify: `lib/private/routed-dht.js`
- Modify: `lib/private/opaque-destination.js`
- Modify: `test/private/protocol.js`
- Modify: `test/private/routed-dht.js`
- Modify: `test/private/routed-dht-io.js`

- [ ] **Step 1: Add failing registry and error assertions**

Add tests proving:

```js
t.is(M3_MESSAGE_ID.DHT_EXIT_SEEDS_V1, 0x0044)
t.is(M3_MESSAGE_ID.DHT_EXIT_DHT_SEEDS_V1, 0x0045)
t.is(M3_ID_REGISTRY.filter((id) => id === 0x0045).length, 1)
t.is(PrivateRouteError.ERR_PRIVATE_GUARD_UNAVAILABLE().code, 'ERR_PRIVATE_GUARD_UNAVAILABLE')
```

Also assert the registry contains 59 unique IDs, the new M3 object layout is
exactly `[0x0045, [310, 654, 64]]`, minimum framing is 382 bytes, maximum
framing is 726 bytes, and the new error message is exactly
`Private guard is unavailable` with no endpoint data. Assert the existing
`0x0044` ID and `[905, 4265, 64]` layout remain unchanged; its domains are
owned by the future full-seed codec, not current Gate 3A `protocol.js`, so do
not invent or relocate them in this task.

Run:

```bash
npx brittle-node test/private/protocol.js
```

Expected: FAIL because `DHT_EXIT_DHT_SEEDS_V1` and `ERR_PRIVATE_GUARD_UNAVAILABLE` do not exist.

- [ ] **Step 2: Add the sole new ID and error without renumbering anything**

In `protocol.js`, insert only the new ID:

```js
DHT_EXIT_DHT_SEEDS_V1: 0x0045,
```

Add the two frozen UTF-8 domains from the design to the domain registry:

```text
hyperdht-private-routes/m3/dht-exit-dht-seeds/v1
hyperdht-private-routes/m3/dht-exit-dht-seeds/set/v1
```

In `errors.js`, add `ERR_PRIVATE_GUARD_UNAVAILABLE` to `M3_ERROR_CODES`, `MESSAGES`, and `PrivateRouteError`. Do not add aliases or change any pre-existing error text.

Register the new object in the existing private `M3_OBJECT_LAYOUT` map:

```js
[0x0045, [310, 654, 64]],
```

Update the exact object-layout fixture and registry-count assertion from 58 to 59. Do not export the mutable layout map.

- [ ] **Step 3: Add failing exact `ROUTED_REPLY_V1` vectors**

In `test/private/routed-dht.js`, freeze one minimum successful reply, one maximum Gate 3B1 immutable-get reply, and one error reply. The exact body is:

```text
16B requestId | u16 commandId | u16 commandVersion | u8 operationClass |
172B from | u16 errorCode | u16 tokenLength | token | u8 closerCount |
172B * closerCount | u16 responseLength | response
```

Assert fixed body 200, wire base 208, maximum complete bytes 4,706, maximum
amplification 4,445, immutable-get encoded response at most 1,026 bytes, exact
request/from equality, token length only 0 or 32, at most 20 unique closer
references sorted by unsigned XOR distance from the immutable target and then
destination ID, no trailing bytes, and the known error set `0x0180..0x018e`.
Success uses error `0`; every nonzero error requires empty token, closer list,
and encoded response. Mutation tests must reject unknown error IDs, an error
carrying data, wrong request/command/version/class/from, duplicate or unsorted
referrals, wrong destination class/generation, and accessor-backed hostile
shapes before returning or staging owned data.

Run:

```bash
npx brittle-node test/private/routed-dht.js
```

Expected: FAIL because routed-reply exports do not exist.

- [ ] **Step 4: Break the destination-codec dependency before adding admission**

Move only `DESTINATION_REF_SIZE`, `encodeDestinationRef`, and
`decodeDestinationRef` from `routed-dht.js` into `destination-ref.js` without
changing bytes or validation. Import them into both `routed-dht.js` and
`opaque-destination.js`; re-export them from `routed-dht.js` so every Gate 3A
caller remains compatible. Run the pre-existing destination and adapter tests
before proceeding. The dependency direction must now be:

```text
routed-dht -> opaque-destination -> destination-ref
          \-----------------------> destination-ref
```

`opaque-destination.js` must not import `routed-dht.js`, eliminating the
CommonJS cycle before routed-reply admission is added.

- [ ] **Step 5: Implement owned routed-reply codecs and the exact live-table owner**

Add focused exports to `routed-dht.js`:

```js
const ROUTED_REPLY_FIXED_BODY_SIZE = 200
const MAX_ROUTED_REPLY_BYTES = 4706

function encodeRoutedReply(value) {}
function decodeRoutedReply(encoded) {}
function validateRoutedReplyForRequest(encoded, options) {}
function clearRoutedReply(reply) {}
function commitRoutedReplyAdmission(admission) {}
function abortRoutedReplyAdmission(admission) {}
```

`options` is exact own data with no accessors or extra keys:

```js
const options = {
  encodedRequest, // complete ROUTED_REQUEST_V1 bytes
  target, // exact 32-byte immutable target
  branch, // BRANCH_CLASS.LOOKUP
  circuitId, // 16 bytes
  generation, // u64
  now, // wall-clock u64 milliseconds
  referralAuthority // unforgeable capability from opaque-destination.js
}
```

Extend `opaque-destination.js` with a separate WeakMap-backed live owner; leave
the existing `createOpaqueDestinations()` Gate 3A factory behavior unchanged:

```js
const owner = createLiveOpaqueDestinations({
  branch,
  circuitId,
  generation,
  expiresAt,
  wallNow
})
const seed = issueLiveOpaqueDestination(owner, { id, destinationRef })
const authority = createRoutedReplyReferralAuthority(owner, {
  from: seed,
  target,
  requestId,
  deadline
})
stageRoutedReplyReferral(authority, { encoded, decoded })
const admission = sealRoutedReplyAdmission(authority)
commitRoutedReplyAdmission(admission)
abortRoutedReplyAdmission(admission)
revokeRoutedReplyReferralAuthority(authority)
destroyLiveOpaqueDestinations(owner)
```

Here `owner` is the endpoint-side table for exactly one terminally authenticated
exit branch/circuit/generation; it is not the exit's secret destination table.
All owner, authority, and admission objects are frozen empty capabilities whose
state lives only in WeakMaps. `issueLiveOpaqueDestination` is called only for
authenticated `0x0045` seeds or a committed routed admission and returns the
same address-free capability shape expected by `RoutedDHTIO`.

`routed-dht.js` imports stage/seal functions from `opaque-destination.js`. They
(1) prove `from` is an active record in `owner` and its complete bytes equal the
request destination, (2) require the authority to be bound to an authenticated
reply from that exact terminal DHT-exit session, then label each canonical
closer as `DHT_NODE_HANDLE` in endpoint table metadata owned by the same
branch/circuit/generation with expiry no later than the owner, (3) reject
duplicate destination IDs already live or staged, and (4) create an
all-or-nothing staged set. `DESTINATION_REF_V1` keeps its 130-byte handle opaque;
the client does not invent a parser for exit-secret handle internals. The
required order is: decode outer framing; bind request ID/command/version/class
and full `from`; validate error/data and complete-byte budgets; validate and
sort every closer; stage all closer records without publishing them; validate
the 1,026-byte immutable response bound; then return `{ reply, admission }`.
Nothing is retained yet. `RoutedDHTIO`, which created the authority from its
private owner and exact opaque `to` capability, decodes and hash-checks the command
response, calls `commitRoutedReplyAdmission(admission)` only after that check,
and calls `abortRoutedReplyAdmission(admission)` on every error/cancel/destroy
path. Commit publishes the entire staged set atomically; it cannot partially
import referrals or be called twice.

Follow the exact Section 10.3 registry layout. Reuse hardened intrinsic
capture, strict own-data validation, bounded allocation, destination decoding,
and clearing patterns. Return defensive owned copies only.

- [ ] **Step 6: Run Node/Bare vectors and commit**

```bash
npx brittle-node test/private/protocol.js test/private/routed-dht.js test/private/routed-dht-io.js
bare node_modules/brittle/cmd.js test/private/protocol.js test/private/routed-dht.js test/private/routed-dht-io.js
npm run test:generate
git diff --check
git add lib/private/protocol.js lib/private/errors.js lib/private/destination-ref.js lib/private/routed-dht.js lib/private/opaque-destination.js test/private/protocol.js test/private/routed-dht.js test/private/routed-dht-io.js test/all.js
git commit -m "feat: freeze Gate 3B1 routed reply wire"
```

Expected: both runtimes pass exact vectors and all owned buffers are cleared by the existing clearing assertions.

### Task 2: Migrate signed relay advertisements and active challenge

**Files:**

- Create: `lib/private/relay-capability.js`
- Create: `test/private/relay-capability.js`
- Modify: `test/private-routing.js`
- Regenerate: `test/all.js`
- Modify: `docs/private-routing-migration.md`

- [ ] **Step 1: Add failing pure advertisement codec/signature vectors**

Adapt the exact prototype `test/relay-capability.test.js` cases named
`M3 relay advertisement is canonical, signed, exact-sized, and defensively copied`,
`M3 DHT node identity uses IPv4 octets and little-endian port exactly`,
`provider policy is the exact capability-derived 0/4/5/9 tuple set`, and the
related validation/digest/hostile-object tests. Freeze exact vectors for
canonical 19-byte numeric IPv4 endpoints, the signed advertisement, and its
digest. Do not cite `test/m3-vectors.test.js` for these bytes. Assert:

- safety relay mask `1`, derived `SAFETY` role, zero policy entries;
- DHT exit mask `3`, derived `PRIVATE` role, exactly four immutable-order DHT policies;
- body offsets 0..188 plus `32 * policyCount` and 64-byte Ed25519 suffix;
- maximum 1,800,000 ms lifetime and 30,000 ms future skew;
- IPv6, hostnames, unknown/accessor/inherited fields, bad role/capability/policy,
  invalid intervals, bad signatures, expiry, and input aliasing fail before
  candidate allocation/contact.

Run:

```bash
npx brittle-node test/private/relay-capability.js
```

Expected: FAIL because the module does not exist.

- [ ] **Step 2: Port only adopted advertisement wire bytes, then harden the API**

Port prototype `packages/private-routes/lib/relay-capability.js` byte-for-byte
only for the adopted field layouts, domains, signatures, and known vectors.
Do not claim its ordinary-property reads, IPv6 acceptance, capability masks up
to 7, clock ownership, or state-machine behavior are adopted. Convert to
CommonJS and expose these pure functions:

```js
encodeCanonicalEndpoint
decodeCanonicalEndpoint
deriveM3DhtNodeId
providerServicePolicyForCapabilities
signRelayCapabilityAdvertisement
encodeRelayCapabilityAdvertisement
decodeRelayCapabilityAdvertisement
digestRelayCapabilityAdvertisement
```

Every input uses strict exact own-data descriptors, captured intrinsics, bounded
allocation, defensive copies, and deterministic clearing. Gate 3B1 validation
rejects masks other than `1` for guard/middle or `3` for DHT exits and rejects
IPv6 before any IO. Do not expose a public discovery API.

- [ ] **Step 3: Add failing epoch/quarantine owner tests**

Define a CommonJS-internal `RelayCapabilityVerifier` with exact constructor
options and methods:

```js
new RelayCapabilityVerifier({ wallNow, monotonicNow, setTimer, clearTimer, onInvalidated })
verifier.accept(encoded, { expectedRole, expectedCapabilityMask })
verifier.beginChallenge(advertisement, sendChallenge)
verifier.destroy()
```

`accept` returns an owned frozen projection containing canonical bytes, digest,
identity, canonical endpoint bytes, route public key, role, capability mask,
epoch, issuedAt, and expiresAt. Add red tests for lower-epoch replay,
byte-identical current-epoch idempotence, different-digest same-epoch
equivocation quarantine, 16 distinct route-key history, seventeenth-key poison,
and complete erasure on destroy.

- [ ] **Step 4: Implement epoch/quarantine ownership**

Use one WeakMap state per verifier. Per identity retain only the highest accepted
nonzero epoch plus up to sixteen distinct route keys needed by the approved
history/quarantine rule. A quarantined identity cannot be selected until the
later conflicting expiry. `accept` performs canonical decode/signature/time and
role/capability checks before mutating history. On failure, clear all temporary
owned bytes.

- [ ] **Step 5: Add failing CAPS and active-challenge tests, then port them**

Adapt the exact CAPS cookie/query/response and `ACTIVE_CHALLENGE_V1` /
`ACTIVE_CHALLENGE_RESPONSE_V1` vectors from prototype
`test/relay-capability.test.js`. Prove cookie binding, route-X25519 possession,
all-zero shared-secret rejection, 5,000 ms monotonic deadline, single
completion, replay rejection, and clearing. Then port the adopted CAPS and
challenge codec/domain functions plus `createActiveChallengeResponderAuthority`.
`beginChallenge` may call only its injected role-scoped `sendChallenge`
capability and never resolves an advertisement endpoint itself.

- [ ] **Step 6: Add clock rollback and ownership adversaries**

The verifier owns `lastAcceptedWallNow`. Before each accept, selection handoff,
challenge completion, or expiry timer callback it samples `wallNow()`. If the
sample is more than 30,000 ms below the last accepted sample, it atomically
clears all advertisement/history/quarantine state and calls `onInvalidated()`
once. A forward jump immediately expires records; no timer may extend signed
expiry. Monotonic time owns only elapsed challenge/deadline checks. Prove
outputs do not alias inputs and invalidation exposes no raw endpoint or key.

- [ ] **Step 7: Record provenance, run both runtimes, and commit**

Add a Gate 3B1 migration row naming the exact prototype file and retained tests. Then run:

```bash
npx brittle-node test/private/relay-capability.js
bare node_modules/brittle/cmd.js test/private/relay-capability.js
npm run test:generate
git diff --check
git add lib/private/relay-capability.js test/private/relay-capability.js test/private-routing.js test/all.js docs/private-routing-migration.md
git commit -m "feat: verify signed private relay advertisements"
```

### Task 3: Seal a bounded, non-dialing candidate directory

**Files:**

- Create: `lib/private/relay-candidate-directory.js`
- Create: `test/private/relay-candidate-directory.js`
- Modify: `test/private-routing.js`
- Regenerate: `test/all.js`

- [ ] **Step 1: Write failing authority-separation tests**

Construct verified canonical advertisement bytes and assert the directory:

- accepts at most 16 unique identities and copies bytes/digests;
- exposes only the opaque reservation flow defined below plus
  `retainForSuspend()`, zero-argument `resume()`, and `destroy()`;
- never returns a raw host/port, send callback, socket, enumerator, refresh method, or advertisement-to-address converter;
- consumes each candidate at most once per branch generation;
- enforces guard/middle/exit role, capability, expiry, pairwise diversity, and lookup/announce cross-branch diversity;
- retains a sealed non-dialing snapshot across ordinary suspend, revalidates signature/epoch/capability/expiry on resume, and retains no send authority;
- clears on guard loss, network change, destroy, or wall-clock rollback;
- returns `ERR_INCOMPATIBLE_RELAY` for initial or resumed diversity failure;
  the controller, in a later task, maps that failure to state `UNAVAILABLE`
  without invoking discovery.

Install hostile getters named `host`, `port`, `send`, `socket`, and `discover`; assert none are read.

Run:

```bash
npx brittle-node test/private/relay-candidate-directory.js
```

Expected: FAIL because the directory does not exist.

- [ ] **Step 2: Freeze the one-shot BootstrapIO transfer contract**

Export only these module-internal construction functions in addition to the
directory class used by the controller:

```js
const sink = createRelayCandidateDirectorySink({
  wallNow,
  monotonicNow
})
sealRelayCandidateDirectorySink(sink, records, scope)
revokeRelayCandidateDirectorySink(sink)
```

`sink` is a frozen empty WeakMap-authenticated object, not a function. It is
passed to `BootstrapIO` before start and has no inspectable fields. Only the
module-internal `sealRelayCandidateDirectorySink` operation may consume it,
exactly once, with owned canonical record bytes/digests and this exact scope:

```js
const scope = {
  guardIdentity,
  guardEndpoint, // canonical 19-byte bytes, never a send function
  guardAdvertisementDigest,
  guardEpoch,
  guardExpiresAt
}
```

Sealing copies all bytes before returning a second opaque sealed token, then the
bootstrap owner clears its copies. That sealed token is never returned to the
controller or caller; BootstrapIO stores it only inside the final guard-pin
capability described in Task 4. The internal
`consumeSealedRelayCandidateDirectory(token)` installs directory ownership
before clearing transfer state, and `destroySealedRelayCandidateDirectory`
clears an unconsumed token. Only `consumeBootstrapGuardPin` can reach either
operation in production. Expiry, failure, or replay clears the sink/token and
returns `ERR_REPLAY`. Tests use this same issuer path; no test-only array
constructor bypasses it and no callback can reenter sealing.

- [ ] **Step 3: Implement the capability-free directory and exact reservation API**

Use a `WeakMap` for private state and frozen defensive projections. Store no UDX
instance or callable network object. Guard scope is immutable directory state,
the current committed lookup/announce selections are directory state, and all
expiry decisions sample the injected `wallNow()` internally. Callers may not
supply guard, paired-path, or time predicates. The only selection APIs are:

```js
const initial = directory.reserveInitialPair({
  lookupGeneration,
  announceGeneration
})
const replacement = directory.reserveReplacement({
  branchClass,
  generation
})
const transaction = takeRelayPathReservation(initialOrReplacement)
const selections = splitRelayPathReservation(transaction)
const evidence = consumeSelectedRelayEvidence(selection, {
  transaction,
  branchClass,
  position,
  generation
})
commitRelayPathReservation(transaction)
abortRelayPathReservation(transaction)
```

Generations are nonzero u64 values. `reserveInitialPair` atomically chooses both
middle/exit pairs, excludes the sealed guard identity/endpoint, and enforces all
within- and cross-branch identity+endpoint diversity before returning one
reservation. `reserveReplacement` reads the directory-owned committed opposite
branch and excludes it while replacing only the selected branch. Both sample
the verifier/directory clock, revalidate signatures/epochs/capabilities/expiry,
and record pending once-per-branch-generation claims before returning.
`takeRelayPathReservation` consumes the reservation and returns one frozen empty
transaction capability. `splitRelayPathReservation` may run once and returns
frozen empty selection capabilities shaped as
`{ lookup: { middle, exit }, announce: { middle, exit } }` for an initial pair
or `{ branchClass, middle, exit }` for replacement. Each selection remains
WeakMap-bound to its transaction, exact branch/position/generation, and selected
directory record. `consumeSelectedRelayEvidence` requires all four expected
predicates to equal that stored binding, consumes one selection once, and
returns owned complete advertisement bytes/digest/role/position metadata for
authenticated `EXTEND_REQUEST_V1`; it returns no separately dialable tuple or
send closure. Task 6 uses this exact consumer, so it needs no later path-authority
module to preserve provenance. Commit is permitted only after all expected
selections were consumed and atomically installs the initial pair or one
replacement. Abort clears all unconsumed/consumed evidence and releases only
pending claims. Repeating a committed branch/generation fails `ERR_REPLAY`.

- [ ] **Step 4: Prove suspend/resume and destruction semantics**

Add fake-clock boundary tests at exact expiry, epoch replacement, rollback, and insufficient resume candidates. After destroy, inspect through a test-only symbol and require zero identities, bytes, digests, timers, callbacks, and generation-consumption records.

- [ ] **Step 5: Run focused tests and commit**

```bash
npx brittle-node test/private/relay-candidate-directory.js
bare node_modules/brittle/cmd.js test/private/relay-candidate-directory.js
npm run test:generate
git diff --check
git add lib/private/relay-candidate-directory.js test/private/relay-candidate-directory.js test/private-routing.js test/all.js
git commit -m "feat: seal private relay candidate evidence"
```

### Task 4: Migrate the bootstrap envelope and bounded pre-guard IO

**Files:**

- Create: `lib/private/bootstrap-envelope.js`
- Create: `lib/private/bootstrap-io.js`
- Create: `lib/private/link-setup.js`
- Create: `lib/private/topology-grant.js`
- Create: `lib/private/link-parameters.js`
- Create: `lib/private/guard-link.js`
- Create: `lib/private/guard-reconnect-authority.js`
- Create: `test/private/bootstrap-envelope.js`
- Create: `test/private/bootstrap-io.js`
- Create: `test/private/link-setup.js`
- Create: `test/private/topology-grant.js`
- Create: `test/private/link-parameters.js`
- Create: `test/private/guard-link.js`
- Create: `test/private/guard-reconnect-authority.js`
- Modify: `test/private-routing.js`
- Regenerate: `test/all.js`
- Modify: `docs/private-routing-migration.md`

- [ ] **Step 1: Stage the compilation-safe link prerequisites with failing vectors**

Before importing `bootstrap-envelope.js`, adapt exact vectors from prototype
`test/link-setup.test.js`, `test/topology-grant.test.js`, and the index-zero
cases in `test/guard-link.test.js`. Add `link-parameters.js` for only the exact
pure admitted-limit and payload-parameter encode/decode/digest helpers currently
embedded in prototype `tail-control.js` and `final-exit.js`; freeze their known
bytes now so later route modules import one owner.

Port `link-setup.js` and `topology-grant.js` to CommonJS with their bounds,
one-shot ticket/handle ownership, replay tables, timers, and clearing. Create a
compilation-safe, intentionally partial `guard-link.js` containing only these
index-zero exports from the prototype source:

```js
createIndexZeroGuardLinkOffer
createIndexZeroGuardLinkResponder
completeIndexZeroGuardLink
abortIndexZeroGuardLink
readM3EstablishedLink
takeM3EstablishedLink
destroyM3EstablishedLink
destroyTakenM3EstablishedLink
```

Preserve exact `LINK_OFFER_V1`/`LINK_ACCEPT_V1` layouts/domains and cell-context
derivation. Do not import or stub tail extension, redacted proof, adjacency
adopter, or final-exit session modules yet. Chunk 2 extends this same file only
after those dependencies exist.

Run:

```bash
npx brittle-node test/private/link-setup.js test/private/topology-grant.js test/private/link-parameters.js test/private/guard-link.js
bare node_modules/brittle/cmd.js test/private/link-setup.js test/private/topology-grant.js test/private/link-parameters.js test/private/guard-link.js
```

Expected: initial red tests fail for missing modules; after the narrow ports,
all exact prerequisite vectors pass with no unresolved import.

- [ ] **Step 2: Add failing exact bootstrap-envelope vectors**

Port the exact known vectors and adversaries from prototype `test/bootstrap-envelope.test.js`, `test/bootstrap-io-authority.test.js`, and `test/guard-link.test.js`. Assert every datagram is exactly 1,200 bytes, signed under `hyperdht-private-routes/udx-bootstrap/v0`, bound to sender/recipient identity, numeric tuple, epoch, request ID, type, and body digest, and rejected for replay, mismatch, trailing data, oversize, or allocation before verification.

The adopted envelope does **not** add a tuple field. The numeric source tuple is
received out of band from the datagram transport and is bound to the verified
request-table/link state before the body is accepted. Tests must mutate that
out-of-band source tuple separately; never change the 1,200-byte layout.

Run:

```bash
npx brittle-node test/private/bootstrap-envelope.js
```

Expected: FAIL because the codec does not exist.

- [ ] **Step 3: Port the exact bootstrap codec and bounded request table**

Port prototype `lib/bootstrap-envelope.js` to CommonJS, retaining `BootstrapEnvelopeCodec`, `BootstrapRequestTable`, exact constants, pending/per-peer/cache/tombstone bounds, five-second request deadlines, clearing, and the test-only table observer. Remove no validation and add no new wire fields.

- [ ] **Step 4: Add failing cold-start authority tests**

Using an injected fake datagram transport, assert `BootstrapIO`:

- accepts 1..3 deduplicated numeric configured endpoints only;
- contacts configured bootstraps sequentially and actively challenges at most three distinct prospective guards, one at a time;
- uses one ten-second monotonic deadline for cookies, advertisement verification, challenges, and the first link;
- retains at most sixteen verified candidates and never contacts a middle or exit;
- emits an exposure report with at most six keyed/redacted entries and no raw endpoint, key, topic, descriptor, or stable cross-generation identifier;
- seals owned candidate evidence into the injected one-shot directory sink and
  publishes one opaque guard-pin transfer only after every generic direct-send
  closure is destroyed; state `GUARD_PINNED` remains controller-owned and is
  not observable from `BootstrapIO`;
- maps exhaustion to `ERR_PRIVATE_GUARD_UNAVAILABLE` and creates no fallback or DNS traffic.

Use an authority trap whose generic `send(host, port)` throws after pinning. A
promise continuation attached to `start()` must observe that the trap is
already revoked; `BootstrapIO` has no state-transition callback.

- [ ] **Step 5: Implement the narrowed `BootstrapIO` and exposure report**

Port only the cold-start pieces of prototype `lib/bootstrap-io.js`. Constructor input is exact own data:

```js
const options = {
  endpoints,
  localIdentity,
  localSecretKey,
  datagrams,
  wallNow,
  monotonicNow,
  randomBytes,
  candidateDirectorySink
}
```

Provide only `start()`, `cancel()`, `destroy()`, and a test-only redacted
snapshot. `start()` resolves an opaque WeakMap-backed guard-pin transfer. Export
only these module-internal consumers:

```js
consumeBootstrapGuardPin(transfer)
revokeBootstrapGuardPin(transfer)
```

Success ordering is exact: verify and own all candidate bytes; establish the
guard; call module-internal `sealRelayCandidateDirectorySink` on the opaque
sink and store its opaque sealed token; revoke and destroy the generic
datagram/direct-send authority; clear BootstrapIO candidate copies; create one
guard-pin transfer whose WeakMap state owns both an opaque `GuardLeaseMaterial`
and sealed directory token; then resolve `start()`. In Chunk 1 the fake material
wraps the established guard link; Task 5 replaces it with the production
socket-owner/reconnect material under the same consumer contract. There is no caller callback during
sealing. Consuming the transfer once atomically removes its state, consumes both
owned tokens, and returns
`{ guardLeaseMaterial, candidateDirectory, pinnedGuard, exposureReport }`, where
`pinnedGuard` contains defensive identity/canonical endpoint bytes,
advertisement digest/epoch/expiry for equality checks but no send function.
If either consume fails, `consumeBootstrapGuardPin` destroys the other resource
and returns no partial value. The controller installs both returned resources,
destroys BootstrapIO, and only then commits `GUARD_PINNED`. Failure or explicit
revocation at any point destroys the sink/sealed token, lease material, and IO and
publishes neither resource. The transfer never contains advertisements, issuer
functions, externally inspectable sockets/callbacks, or caller-controlled send data.

- [ ] **Step 6: Add and implement the one-shot reconnect authority**

Adapt prototype `guard-revalidation-io.js` into
`guard-reconnect-authority.js`. Create it only through:

```js
createGuardReconnectAuthority({
  guardIdentity,
  guardEndpoint,
  advertisement,
  advertisementDigest,
  epoch,
  expiresAt,
  localIdentity,
  localSecretKey,
  reconnectDatagrams,
  wallNow,
  monotonicNow,
  setTimer,
  clearTimer
})
revokeGuardReconnectAuthority(authority, reason)
```

The capability's sole public method is zero-argument `reconnect()`. Its WeakMap
state owns the expiry timer and an abort controller. `reconnect()` atomically
changes `READY -> SPENT` before first IO, copies its exact bound tuple into an
in-flight private record, and returns one operation promise. The spent public
object can never start another operation, while the private record may perform
only CAPS self-query, active challenge, and guard LINK OFFER/ACCEPT to that
tuple under one 5,000 ms deadline. Module-private revoke aborts and clears a
pending or in-flight record and is called for expiry, network change,
substitution, controller destroy, or failure. No path restores `READY`.
Tests prove no arguments, referral, DHT request, or generic send can alter the
tuple and that revoke-before-call and revoke-during-flight emit no later packet.

- [ ] **Step 7: Run both runtimes, update migration provenance, and commit**

```bash
npx brittle-node test/private/link-setup.js test/private/topology-grant.js test/private/link-parameters.js test/private/guard-link.js test/private/bootstrap-envelope.js test/private/bootstrap-io.js test/private/guard-reconnect-authority.js
bare node_modules/brittle/cmd.js test/private/link-setup.js test/private/topology-grant.js test/private/link-parameters.js test/private/guard-link.js test/private/bootstrap-envelope.js test/private/bootstrap-io.js test/private/guard-reconnect-authority.js
npm run test:generate
git diff --check
git add lib/private/link-setup.js lib/private/topology-grant.js lib/private/link-parameters.js lib/private/guard-link.js lib/private/bootstrap-envelope.js lib/private/bootstrap-io.js lib/private/guard-reconnect-authority.js test/private/link-setup.js test/private/topology-grant.js test/private/link-parameters.js test/private/guard-link.js test/private/bootstrap-envelope.js test/private/bootstrap-io.js test/private/guard-reconnect-authority.js test/private-routing.js test/all.js docs/private-routing-migration.md
git commit -m "feat: pin a bounded authenticated private guard"
```

### Chunk 1 checkpoint

- [ ] Run all private deterministic tests in Node and Bare:

```bash
npx brittle-node test/private/*.js
bare node_modules/brittle/cmd.js test/private/*.js
```

- [ ] Confirm `rg -n "privateRouting|privacy" index.js lib --glob '*.js'` finds no public option or export.
- [ ] Confirm the post-pin authority trap is armed before `GUARD_PINNED` callbacks.
- [ ] Confirm `git diff --check` is clean and all four task commits are present.

## Chunk 2: Authenticated adjacent links and two live terminal branches

### Task 5: Migrate fixed M3 contexts and live adjacent UDX sessions

**Files:**

- Create: `lib/private/m3-context.js`
- Create: `lib/private/link-bootstrap-session.js`
- Create: `lib/private/link-control-session.js`
- Create: `lib/private/udx-adapter.js`
- Create: `lib/private/udx-cell-endpoint.js`
- Modify: `lib/private/bootstrap-io.js`
- Modify: `lib/private/guard-link.js`
- Modify: `lib/private/guard-reconnect-authority.js`
- Create: `test/private/m3-context.js`
- Create: `test/private/link-bootstrap-session.js`
- Create: `test/private/link-control-session.js`
- Create: `test/private/udx-loopback.js`
- Create: `test/private/udx-cell-endpoint.js`
- Modify: `package.json`
- Modify: `test/private-routing.js`
- Regenerate: `test/all.js`
- Modify: `docs/private-routing-migration.md`

- [ ] **Step 1: Add failing M3 context vectors**

Adapt exact cases from prototype `test/m3-vectors.test.js` and
`test/m3-adjacency-runtime.test.js` for the contexts Gate 3B1 uses. Freeze the
54-byte associated-data layout and 1,101-byte M3 context envelope. Assert
branch, link, circuit, generation, context class, direction, counter, nonce,
body length, authentication tag, padding, and trailing-byte substitution all
fail closed.

Run:

```bash
npx brittle-node test/private/m3-context.js
```

Expected: FAIL because `m3-context.js` does not exist.

- [ ] **Step 2: Port the exact context codec**

Port prototype `lib/m3-context.js` to CommonJS. Reuse Gate 3A owned-buffer,
captured-intrinsic, counter, and zeroization patterns. Export only
`encodeM3ContextAD`, `decodeM3ContextAD`, `encodeM3ContextEnvelope`, and
`decodeM3ContextEnvelope` plus exact constants. Do not add variable-size frames.

- [ ] **Step 3: Add failing link bootstrap lifecycle tests**

Adapt the Gate 3B1 cases from prototype `test/link-bootstrap-session.test.js`
and `test/link-control-session.test.js`. Use fake clocks and an exact-tuple send
handle. Prove:

- LINK CREATE/CREATED retries use identical semantic bytes, fixed retry times,
  and one-shot ticket installation;
- bootstrap and established cells cannot decode as each other;
- duplicate success returns only the cached response; conflicting reuse closes;
- destroy/cancel clears timers, counters, tickets, sends, receives, callbacks,
  queues, and secrets exactly once.

Every `LinkBootstrapSession` constructor receives `absoluteDeadline` and
`signedExpiry`; it computes only
`min(start + 5_000, absoluteDeadline, signedExpiry)`. Test a route extension
whose LINK CREATE starts after 3,500 ms of the branch budget and therefore has
at most 1,500 ms remaining. The initial guard link receives BootstrapIO's
ten-second absolute deadline instead of a branch deadline.

- [ ] **Step 4: Port and verify the bootstrap session**

Port prototype `lib/link-bootstrap-session.js` to CommonJS, importing the Chunk
1 codecs and requiring the inherited absolute deadline. Keep opaque
established-link WeakMaps. The constructor receives a pending link reservation
from the socket owner defined below; no method accepts a host or port.

- [ ] **Step 5: Add failing established control-session tests, then port them**

Add the CONTROL/STREAM ordering, DATAGRAM replay window, ACK bounds, liveness at
500 ms, unresponsive close at 1,500 ms, counter exhaustion, five-second circuit
teardown, and clearing tests from prototype `test/link-control-session.test.js`.
Then port `lib/link-control-session.js` with its opaque direction capabilities.
It receives an already-established reservation from the same socket owner.

- [ ] **Step 6: Add one exact Node/Bare UDX socket owner**

Add direct runtime dependency `"udx-native": "1.20.7"`, matching the exact
reviewed prototype/runtime version. Port prototype `lib/udx-adapter.js` and
`lib/udx-cell-endpoint.js` to CommonJS. `UdxCellEndpoint` is the sole socket
owner for one role process: it creates the UDX instance/socket through
`UdxAdapter`, binds it, attaches one message/error demultiplexer, owns all
pending and established reservations, and closes both socket and adapter-owned
UDX references.

Run `npm pkg set dependencies.udx-native=1.20.7 && npm install`, verify
`require('udx-native/package.json').version === '1.20.7'`, and confirm the
ignored `package-lock.json` is not staged.

Its exact constructor is:

```js
new UdxCellEndpoint({
  host,
  port,
  onBootstrap,
  onCell,
  onLinkFailure,
  maxQueuedPackets,
  maxQueuedBytes,
  maxInboundPackets,
  maxInboundBytes,
  maxInboundPacketsPerPeer,
  maxInboundBytesPerPeer
})
```

`openLink(linkHandle, sessionOptions)` consumes a topology-grant link handle,
binds one peer identity+numeric tuple, installs a PENDING record, and returns a
`LinkBootstrapSession`. On valid CREATED, that exact record atomically changes
to OPEN, installs cell codec/control state, and returns role-scoped send/control
capabilities. Receive demux accepts the reserved bootstrap class only for
PENDING and established cells only for OPEN; source tuple/identity mismatch is
dropped before callbacks. `close()` first marks closing, revokes all send
handles, rejects queues, removes listeners, closes pending/control sessions,
waits native sends, closes the socket, then clears the adapter-owned UDX
reference; it does not call an undocumented UDX destroy method. It is
idempotent and no caller may close the inner socket directly.

The production constructor never accepts an adapter. Queue/allocation tests use
only this separate test boundary:

```js
const adapterAuthority = createTestUdxAdapterAuthority(fakeFactory)
const endpoint = createUdxCellEndpointForTest(options, adapterAuthority)
```

Both functions are exported only under `TEST_ONLY_UDX_ADAPTER_ISSUER`; the
authority is frozen, WeakMap-backed, one-shot, and cannot be passed to the
production constructor. Production tests assert the default constructor reaches
`UdxAdapter`/`udx-native` by observing real loopback packets.

Before guard pinning, create one opaque authority through:

```js
const localSecretCapability = createLocalIdentitySecretCapability({
  localIdentity,
  localSecretKey
})
const bootstrapUdxAuthority = createBootstrapUdxAuthority({
  endpoint,
  configuredEndpoints,
  localSecretCapability,
  maxProspectiveGuards: 3,
  monotonicDeadline
})
```

Creation consumes the local-secret capability into authority state; failure
clears it. BootstrapIO can consume the authority only through module-internal operations
`sendConfigured(index, packet)` and `sendProspectiveGuard(admission, packet)`;
neither accepts a tuple. Candidate admission binds one of at most three verified
guard identities/tuples and returns an opaque token. On successful guard LINK
ACCEPT, `pinBootstrapUdxGuard(authority, admission, establishedLink)` atomically
revokes every configured/candidate handle, changes receive demux to the exact
guard only, and returns one opaque `GuardLeaseMaterial`. That material owns the
established guard-link capability, socket-owner capability, local identity
secret capability, and a zero-argument exact-tuple reconnect transport factory;
none is inspectable or separately consumable. BootstrapIO stores this material
inside the final guard-pin transfer instead of a raw link. Task 4 fake transports
must implement this same capability contract.

- [ ] **Step 7: Add failing fake and real UDX endpoint tests**

Adapt prototype `test/udx-cell-endpoint.test.js` and `test/udx-loopback.test.js`.
Use an injected fake adapter only for queue/allocation adversaries. The real
loopback tests must use the default production `UdxAdapter` and assert its
native socket sends/receives bootstrap and established cells. Prove every link reservation binds one verified
numeric tuple, identity, direction, and link generation; spoofed tuples,
unreserved packets, address changes, queue overflow, late receives, and
post-destroy sends fail. Freeze 64-packet and 76,800-byte default inbound/outbound
bounds and verify atomic reservation before allocation.

- [ ] **Step 8: Run focused fake and native tests in both runtimes**

Run:

```bash
npx brittle-node test/private/m3-context.js test/private/link-bootstrap-session.js test/private/link-control-session.js test/private/udx-cell-endpoint.js test/private/udx-loopback.js
bare node_modules/brittle/cmd.js test/private/m3-context.js test/private/link-bootstrap-session.js test/private/link-control-session.js test/private/udx-cell-endpoint.js test/private/udx-loopback.js
npm run test:generate
git diff --check
git add package.json lib/private/m3-context.js lib/private/link-bootstrap-session.js lib/private/link-control-session.js lib/private/udx-adapter.js lib/private/udx-cell-endpoint.js lib/private/bootstrap-io.js lib/private/guard-link.js lib/private/guard-reconnect-authority.js test/private/m3-context.js test/private/link-bootstrap-session.js test/private/link-control-session.js test/private/udx-cell-endpoint.js test/private/udx-loopback.js test/private-routing.js test/all.js docs/private-routing-migration.md
git commit -m "feat: run authenticated private UDX links"
```

### Task 6: Migrate authenticated in-route extension without discovery

Task 6 follows the independently reviewed responder-authority amendment in
`docs/superpowers/specs/2026-07-19-private-routing-task6-private-responder-authority-design.md`.
The reviewed prototype at commit
`0305df915b6a767093f9e75e6c06bc0a35da6169` remains the byte-level source for
`EXTEND_REQUEST_V1 -> LINK_OFFER/LINK_ACCEPT -> EXTENDED_V1 -> TAIL_READY_V1`.
The amendment changes ownership, clocks, and publication boundaries, not those
wire bytes or the public package API.

**Files:**

- Create: `lib/private/redacted-responder-proof.js`
- Create: `lib/private/m3-adjacency-adopter.js`
- Create: `lib/private/m3-adjacency-runtime.js`
- Create: `lib/private/extension-setup-channel.js`
- Create: `lib/private/extension-link-completion.js`
- Create: `lib/private/relay-identity-signer.js`
- Create: `lib/private/route-extension.js`
- Create: `lib/private/tail-extension-committer.js`
- Create: `lib/private/final-exit-handoff.js`
- Create: `lib/private/tail-control.js`
- Modify: `lib/private/guard-link.js`
- Create: `test/private/redacted-responder-proof.js`
- Create: `test/private/m3-adjacency-runtime.js`
- Create: `test/private/extension-setup-channel.js`
- Create: `test/private/extension-link-completion.js`
- Create: `test/private/relay-identity-signer.js`
- Create: `test/private/route-extension-session.js`
- Create: `test/private/tail-extension-committer.js`
- Create: `test/private/final-exit-handoff.js`
- Create: `test/private/tail-control.js`
- Create: `test/private/route-extension.js`
- Modify: `test/private/guard-link.js`
- Modify: `test/private-routing.js`
- Regenerate: `test/all.js`
- Modify after implementation passes: `docs/private-routing-migration.md`

Use:

```bash
NODE=/Users/jd/.nvm/versions/node/v22.19.0/bin/node
```

Focused Node tests run as
`$NODE node_modules/brittle/bin/node.js <test-files>`. Before Task 6
implementation verification, restore the inherited exact Bare v1.30.3 runtime
into a temporary prefix outside the repository, set `$BARE` to that prefix's
executable, and record `$BARE --version`; do not add it to this package or use a
floating global install. Focused Bare tests run as
`$BARE node_modules/brittle/bin/bare.js <test-files>`. If the exact runtime
cannot be restored, stop before the implementation commit rather than
substituting Node or an unversioned CI install.

For every test file created or modified in Steps 1-12, add its require to
`test/private-routing.js` and run `npm run test:generate` in that same RED
step. The focused test must fail for the expected missing behavior and the
generated aggregate must reach that failure before implementation begins.

- [ ] **Step 1: Freeze the exact extension vectors before changing ownership**

Adapt the exact cases from prototype
`test/redacted-responder-proof.test.js`, `test/extension-setup-channel.test.js`,
`test/extension-link-completion.test.js`, `test/tail-control-session.test.js`,
and `test/route-extension-adversarial.test.js`. Preserve provenance comments
naming the exact prototype path and commit. Freeze:

```text
EXTEND_REQUEST_V1  body 458..746, wire 466..754
EXTENDED_V1        body 486,      wire 494
TAIL_READY_V1      body 210+64,   wire 282
TAIL_TRANSCRIPT    290 bytes
```

Also freeze the exact M3 contexts, KDF labels, redacted responder proof, ordered
forward/reverse counter behavior, and signature inputs already reviewed in the
prototype. Mutate every identity, route key, branch, circuit, generation,
extension index, advertisement/digest, nonce, limit, expiry, proof, context, and
direction field. Each mutation must fail authentication before publishing or
retaining new state.

Run the focused vector tests first. Expected RED: missing Task 6 CommonJS
modules/exports or mismatched exact vectors, never a syntax or fixture error.
Port only the pure codecs/proofs required to make those vectors green. Do not
invent bytes or change an adopted vector to match provisional code.

- [ ] **Step 2: Add dual-clock M3 adoption and proactive runtime expiry**

In `test/private/m3-adjacency-runtime.js`, add one bounded failing test at a
time for:

1. projecting `wireExpiresAt` into the adopting actor's monotonic clock exactly
   once as
   `monotonicNow() + max(0, wireExpiresAt - wallNow())`;
2. moving frozen `{ wireExpiresAt, localDeadline, clockIdentity }` through the
   opaque tail capability without a second projection;
3. rejecting overflow, non-positive intervals, backward wall time,
   non-monotonic `monotonicNow`, and alternate clock function identities;
4. arming one proactive expiry handle before publishing a runtime, tail, or
   responder token;
5. destroying unpublished state on synchronous firing, throwing scheduling,
   failure to record a handle, or reentrant cancellation; and
6. after `commitM3Install`, letting the first of the two installed handles
   consume the internal `M3ForwardingOwner`, cancel both handles, and close both
   contexts exactly once.

Expected RED: the provisional authority accepts one `now` function, lacks the
projected dual-clock record, or publishes runtime state without an owned timer.
Replace the ambiguous `now` option in `M3AdjacencyAuthority` with exact
`wallNow`, `monotonicNow`, `schedule`, and `cancelScheduled` capabilities.
The successor relay projects independently in its own process. Never encode or
compare a local monotonic value across actors.

Run:

```bash
$NODE node_modules/brittle/bin/node.js test/private/m3-adjacency-runtime.js
```

- [ ] **Step 3: Pair each authenticated responder tail with one token**

Extend the same test file with RED cases proving initiator adoption returns no
token and responder adoption returns one opaque bundle containing
`{ runtime, tail, responderToken }`. `m3-adjacency-runtime.js` owns the internal
issuer and exports only:

```js
consumeTailResponderToken(token)
revokeTailResponderToken(token)
```

Store one internal frozen binding object in both WeakMap records. Bind exact
tail transcript digest, local relay identity, role, and wire expiry. Make token
consumption one-shot; require object identity plus repeated field validation.
Revocation, session destruction, mismatch, expiry, and transfer failure must
clear copied binding bytes. `takeM3TailCapability` moves the same binding into
the responder session without exporting it.

Expected RED: initiator can observe a token, token reuse succeeds, or a token
from another transcript/relay can be paired. Implement only enough issuer,
consume, revoke, and cleanup behavior to make each case green.

- [ ] **Step 4: Replace raw identity keys with domain-limited signer capabilities**

Create `test/private/relay-identity-signer.js`. First prove all returned
capabilities are empty, frozen, WeakMap-backed, one-shot in their semantic
domain, and reveal no secret key. Then create
`lib/private/relay-identity-signer.js` with the exact private surface:

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

The owner copies and validates the secret once, derives the public identity
internally, and zeroizes its copy on destroy. Consumers accept only the exact
registered message ID, signature domain, body length, and expected identity,
then verify the produced 64-byte signature before returning it. LINK_OFFER and
TAIL_READY signers are spent after one semantic object. The extension responder
signer follows exactly LINK_ACCEPT then redacted proof and is spent after the
second signature. Retries reuse cached semantic bytes and do not spend another
signer.

Expected RED: raw secret-key options are still required, the wrong domain/body
signs, or a signer is reusable. Refactor `guard-link.js` only after these signer
tests fail correctly. Neither `createExtensionLinkOffer` nor the extension
responder may receive `initiatorIdentitySecretKey` or
`responderIdentitySecretKey`.

Run:

```bash
$NODE node_modules/brittle/bin/node.js test/private/relay-identity-signer.js
```

- [ ] **Step 5: Add the request-bound relay dial and adjacent-link factory**

In `test/private/guard-link.js`, add failing tests for the relay-only dial
surface:

```js
createRelayAdjacentDialAuthority({ socketOwner, allowedRole, dial, destroy })
dialRelayAdvertisement(authority, {
  advertisement,
  advertisementDigest,
  requiredRole,
  wireExpiresAt,
  localDeadline
})
destroyRelayAdjacentDialAuthority(authority)
```

All inputs are exact own data with no accessors or extra keys. Because the dial
authority and factory are co-located in `guard-link.js`, the factory's first
operation privately binds the authority's WeakMap record to its exact
`wallNow`/`monotonicNow` identities and already-retained `localDeadline`
without adding an external API. Before invoking verification, either clock, or
`dial`, move `UNUSED -> DIALING`, tombstone reusable state, and reserve one
process-global pending-offer slot. Preserve the reviewed
`MAX_PENDING_OFFERS = 4096` ceiling and reserve before verification, crypto,
dial, or scheduling callbacks. Re-verify the canonical signed advertisement,
expected digest, required role,
`wallNow() < wireExpiresAt <= advertisement.expiresAtMs`, exact equality
between the supplied and factory-retained `localDeadline`, and
`localDeadline > monotonicNow()`. Add a RED substitution using a later but
still-future deadline and alternate clock identities. Decode the tuple
internally, permit one live dial, and return only an opaque setup transport.
Transfer or destroy that transport and release the reservation before returning
even under throw/reentry.

Then add RED tests for:

```js
createExtensionAdjacentLinkFactory({
  dialAuthority,
  linkOfferSigner,
  wallNow,
  monotonicNow,
  randomBytes,
  schedule,
  cancelScheduled,
  destroy
})
openExtensionAdjacentLink(factory, admitted)
abortExtensionAdjacentLink(factory)
destroyExtensionAdjacentLinkFactory(factory)
```

`open` permits one live operation, synchronously consumes `admitted` through
`takeAdmittedExtendRequest` before its first await, and owns the exact
LINK_OFFER/LINK_ACCEPT/redacted-proof exchange. Every offer, accept, proof,
retry, timer, and completion carries the minimum authenticated `wireExpiresAt`
and current actor's retained `localDeadline`; check both before and after every
external or reentrant operation, and allow later work only to preserve or
shorten them. Add separate RED cases for expiry at each nested stage and for a
retry/completion that attempts to extend either bound. The factory resolves
only an `ExtensionLinkCompletion`; no tuple, socket, physical channel, raw key,
DNS, bind, `trySend`, connect, candidate enumeration, or alternate dial
authority escapes. `abort` cancels the live operation after admission has moved
and releases its pending-offer reservation.

Expected RED: the endpoint can observe a tuple/dialer, a second tuple can be
dialed, admission is taken after an await, a later deadline is substituted, a
nested stage survives either expiry, or abort leaks the live transport.

Run:

```bash
$NODE node_modules/brittle/bin/node.js test/private/guard-link.js test/private/extension-setup-channel.js test/private/extension-link-completion.js
```

- [ ] **Step 6: Transfer accepted successor adjacency and replay ownership atomically**

Add RED cases in `test/private/guard-link.js` for this private surface:

```js
takeAcceptedExtensionAdjacencyTransfer(transfer)
revokeAcceptedExtensionAdjacencyTransfer(transfer)
answerAcceptedExtensionReplay(owner, offerReceiver)
destroyAcceptedExtensionAdjacencyOwner(owner)
```

`takeExtensionResponderAdjacency` returns only an opaque transfer whose taken
material is frozen `{ adjacency, replayOwner }`. Before take, revoke destroys
both. `m3-adjacency-runtime.js`'s existing authority/runtime records are the
concrete successor runtime registry owner; its package-private accepted-link
event handler takes both values atomically. After take, any failure before that
registry publication destroys both in `finally`; publication is the ownership
boundary, and registry removal destroys both through the same path.
The successor factory uses exact:

```js
{
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

Those clock/scheduler identities must match the successor M3 runtime owner.
Arm the successor-local proactive expiry timer before publishing the transfer
and pair the replay owner with that exact runtime and responder token.
`answerAcceptedExtensionReplay` accepts one one-shot response channel, answers
only an authenticated duplicate of the exact retained offer digest and nonces
with cached LINK_ACCEPT/proof bytes, rejects conflicts, and never adopts twice.
Preserve the reviewed process-global `MAX_RESPONDER_REPLAYS = 4096` ceiling:
reserve before verification, crypto, response, or scheduling callbacks and
release on failure, cancellation, destroy, or expiry. Owner destruction cancels
its retry handle before clearing cached semantic bytes. Runtime/token teardown
destroys the paired replay owner. No replay cache crosses machines or enters
the current tail's forwarding owner.

Expected RED: transfer returns adjacency directly, rollback leaks one owner, a
response channel is reused, destroy leaves a retry armed, runtime/token teardown
retains cached bytes, threshold-plus-one allocates, a conflicting replay is
answered, or a duplicate allocates another adjacency.

- [ ] **Step 7: Narrow the initiator `TailControlSession` and dual-clock deadline**

In `test/private/tail-control.js`, first keep the exact pure codec/vector RED
cases from Step 1. Construct sessions only by consuming an M3 tail capability.
`createTailControlSession(capability, options)` accepts common `wallNow`,
`monotonicNow`, and optional deterministic `crypto`; an initiator also requires
the RouteManager-owned monotonic `absoluteDeadline`.

The session object exposes only:

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

It moves `{ wireExpiresAt, localDeadline, clockIdentity }`, verifies exact clock
function identities, never projects again, and clamps initiator
`localDeadline` to `absoluteDeadline`. `readTailControlDeadline` returns only
that process-local monotonic deadline.

Add one RED case per `sealExtend` requirement using exact own data:

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

The session owns branch/circuit/generation/current-tail bindings. Verify the
next index, required role, canonical advertisement/signature/digest, payload
parameters, authenticated wire expiry, and local bound before allocation.
Generate fresh client-tail ephemeral and extension nonces, retain one pending
extension, and seal prototype-exact `EXTEND_REQUEST_V1`. The effective endpoint
deadline is the minimum of RouteManager absolute deadline, moved session
deadline, start plus 5,000 ms, and separately projected signed-manager and
advertisement wall expiries. Encode only a wall-clock requested expiry no later
than every authenticated bound or the wall time corresponding to remaining
local budget. No `selectedEvidenceExpiry` field exists.

Expected RED: provisional single-`now` behavior reprojects/resets a deadline,
accepts alternate clock identity, allows a second pending request, or accepts
an extension later than either authenticated bound.

- [ ] **Step 8: Co-locate token-gated responder transitions with session state**

Keep responder mutation beside `SESSIONS` in `tail-control.js`; do not add
responder methods to the session object or re-export them from HyperDHT's entry
point. Add RED tests for the exact package-private surface:

```js
createTailControlResponderAuthority(session, responderToken, options)
admitTailExtend(authority, envelope)
openTailAdjacentLink(authority, admitted)
completeTailExtend(authority, completion)
abortTailExtend(authority)
sealTailReady(authority)
destroyTailControlResponderAuthority(authority)
```

At transcript indices 0 and 1, exact authority options are:

```js
{
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
```

At terminal index 2, forbid the first three extension keys and accept only:

```js
{
  tailReadySigner,
  wallNow,
  monotonicNow,
  randomBytes,
  schedule,
  cancelScheduled
}
```

Authority construction atomically consumes the paired token, requires its
hidden binding object to equal the responder session binding, validates exact
own-data options and identical clocks, and arms one authority expiry handle
before return. Mismatch, synchronous firing, schedule throw, reentrant cancel,
or failure to retain a handle destroys session, token, and every transferred
owned option. `adjacencyAdopter` is borrowed from its
`M3AdjacencyAuthority`: abort any live one-shot adoption, but never destroy the
borrowed adopter owner during authority cleanup. Add mismatch, abort, and
reentrant RED cases proving that distinction.

`destroyTailControlResponderAuthority` cancels the recorded handle before
destroying protocol state. The old authority retains its handle until both
installed M3 handles own cleanup; only then may forwarding installation cancel
it. Successor and terminal-index-2 authorities retain their own handles until
explicit destroy or expiry. Add RED cases for each normal lifetime boundary,
not only construction failure.

`admitTailExtend` must open ordered tail AEAD and verify exact current bindings,
next index/role, complete canonical advertisement/signature/digest/route key/
endpoint/expiry, payload parameters, requested limits, fresh nonces, and local
deadline without a discovery cache. It stores one live admission capability.
The responder independently clamps to its moved session deadline, start plus
5,000 ms, projected advertisement expiry, and projected requested wall expiry.

`openTailAdjacentLink` verifies object identity, clears `liveAdmission`, enters
`LINK_OPENING` before external code, and hands the capability to its bound
factory. It records the exact returned completion. `completeTailExtend` clears
and spends that exact completion before taking it, verifies the proof and all
retained digests/nonces/limits, adopts only through `adoptM3ResponderLink`,
seals exact `EXTENDED_V1`, and invokes the committer from an irreversible
`INSTALLING` generation. Reentry must never admit, abort, or publish twice.

Expected RED: an initiator can obtain authority; a deep import works without
the paired token; a terminal session admits EXTEND; alternate clocks/options
are accepted; or any external callback observes reusable pre-transition state.

Run:

```bash
$NODE node_modules/brittle/bin/node.js test/private/tail-control.js
```

- [ ] **Step 9: Make forwarding installation a failure-atomic transfer**

In `test/private/tail-extension-committer.js`, add RED cases for:

```js
takeTailForwardingTransfer(transfer)
revokeTailForwardingTransfer(transfer)
```

`TailExtensionCommitter.install()` stages `EXTENDED_V1` and the next runtime,
obtains the existing frozen `{ diagnostics, destroy }` forwarding facade, and
wraps that facade in one opaque `TailForwardingTransfer`. It never exports the
separate empty internal `M3ForwardingOwner`. Before take, revocation destroys
the facade. `m3-adjacency-runtime.js`'s existing authority/runtime records are
the concrete forwarding registry owner; its package-private forwarding event
handler takes the facade, calls `commitM3Install`, and publishes both installed
records atomically. After take and before publication, the handler holds the
facade in a tracked local and calls `facade.destroy()` in `finally` on every
failure. Publication is the ownership boundary; registry removal uses the same
destroy path. Test take-through-publication, throw/reentry rollback, and
registry removal through the production event path without adding a public
registry API.

Successful forwarding cancels the old responder-authority handle only after
the independently armed M3 runtime handles own both installed contexts.
Context/link close or proactive local expiry consumes the facade and destroys
both installed sides. Do not claim synchronous cleanup on another machine.

Expected RED: install returns the facade directly, abandonment leaks it,
publication failure skips destroy, or an old timer is cancelled before the new
runtime timers own cleanup.

Run:

```bash
$NODE node_modules/brittle/bin/node.js test/private/tail-extension-committer.js test/private/m3-adjacency-runtime.js
```

- [ ] **Step 10: Reconcile `RouteExtensionSession` with selected evidence only**

In `test/private/route-extension-session.js`, add RED tests around the existing
Task 3 evidence transaction. Preserve the exact own-data factory surface while
replacing only `now` with separate clocks:

```js
const request = createRouteExtensionSessionRequest({
  transaction,
  selection,
  branchClass,
  position,
  generation,
  extensionIndex,
  limits,
  absoluteDeadline,
  signedExpiry,
  wallNow,
  monotonicNow,
  randomBytes,
  schedule,
  cancelScheduled,
  cancel,
  tailControl,
  tailControlTransportFactory
})
const session = new RouteExtensionSession(request)
const transfer = await session.open()
const next = takeRouteExtensionTransfer(transfer)
```

Reject accessors, inherited properties, omitted fields, and extra keys before
retaining any input.

The constructor consumes exactly:

```js
consumeSelectedRelayEvidence(selection, {
  transaction,
  branchClass,
  position,
  generation
})
```

It receives complete owned canonical advertisement bytes/digest and role/index
metadata, with no independent evidence-expiry field and no dial authority.
Extension index 1 selects a safety relay; index 2 selects a DHT exit; no third
extension is valid. `signedExpiry` is manager-owned current-branch wire expiry
and may only shorten the tail capability's authenticated wire expiry.

The endpoint sequence is: seal one `EXTEND_REQUEST_V1` containing the complete
advertisement; send it only on authenticated current-tail transport; open and
verify exact `EXTENDED_V1`; retain an opaque client completion without
publishing the next tail; receive valid `TAIL_READY_V1`; atomically complete
and publish the next `TailControlSession`. Task 9, not Task 6, commits the
complete branch-pair directory transaction.

Destroy, abort, expiry, authentication failure, or TAIL_READY rejection must:
tombstone and consume manager cancellation; cancel endpoint-local timers;
abort completion and destroy uncommitted next-tail state; revoke only the
failed logical tail transport without closing the shared pinned-guard physical
link; leave Task 9's transaction owner to abort reservation; then zeroize
owned nonces, secrets, transcripts, advertisements, proofs, and semantic
bytes.

Expected RED: provisional code accepts `now`, discovery service/query state,
`selectedEvidenceExpiry`, endpoint dialing, or publishes a next tail before
TAIL_READY.

Run:

```bash
$NODE node_modules/brittle/bin/node.js test/private/route-extension-session.js
```

- [ ] **Step 11: Gate TAIL_READY publication and the final-exit handoff**

In `test/private/tail-control.js` and `test/private/final-exit-handoff.js`, add
RED cases proving the successor calls `sealTailReady(authority)` only after it
owns the adopted adjacency and can process authenticated control. The authority
uses only its bound `tailReadySigner` and randomness, returns one owned exact M3
context envelope, and moves `WAITING_READY -> ACTIVE`. Indices 0/1 may then
admit one extension; index 2 may only create the terminal handoff.

Only valid `TAIL_READY_V1` lets `completeClientExtension` return the next
initiator `TailControlSession`. Before it, no endpoint application-send
authority, final-exit activation, or directory commit exists.

After index 2 readiness, `session.takeFinalExitHandoff()` returns one opaque
same-runtime handoff containing the tail-control owner, exact 290-byte
transcript, shared secret, finalize keys and nonce prefixes, initiator flag,
authenticated `wireExpiresAt`, process-local `localDeadline`, and clock
identity. `consumeFinalExitHandoff` moves it once into Task 7. Task 7 must
present the same clock identity and reuse the moved deadline without projection
or reset. Revoke, destroy, or expiry erases every field. The handoff cannot
cross processes and exposes no destination table, DHT socket, endpoint tuple,
or payload key bytes to intermediate relays.

Expected RED: provisional handoff carries only one ambiguous expiry, crosses a
clock identity, activates before ready, or is reusable.

Run:

```bash
$NODE node_modules/brittle/bin/node.js test/private/tail-control.js test/private/final-exit-handoff.js
```

- [ ] **Step 12: Prove guard → middle → DHT-exit routing and actor-local cleanup**

Create the real in-memory integration in `test/private/route-extension.js`.
Feed Task 3 selected advertisement evidence into the endpoint's current tail.
Assert the only post-pin semantic stages are:

```text
EXTEND_REQUEST_V1 -> LINK_OFFER/LINK_ACCEPT -> EXTENDED_V1 -> TAIL_READY_V1
```

The current tail contacts exactly the tuple inside the authenticated
advertisement. Keep an endpoint direct-send trap untouched. Add a semantic scan
and runtime traps rejecting `RELAY_DISCOVER_V1`,
`RELAY_DISCOVER_RESPONSE_V1`, random discovery targets, DNS, arbitrary
enumeration, and any Task 9 `BranchPathAuthority` dependency in
`route-extension.js`, `tail-control.js`, or `guard-link.js`.

Build guard→middle and then middle→DHT-exit with independent actor clocks and
fresh one-shot nonces. Before valid TAIL_READY, relay contexts may carry only
authenticated control; assert no endpoint next-tail/application-send
authority, final-exit activation, or directory commit. Exercise same-counter
tail replay, semantic EXTEND replay, exact lower-link cached duplicate,
conflicting duplicate, wrong bindings/roles, malicious proof, expired
advertisement, deadline races, dropped setup packet, cancellation, quota
rejection, throwing/reentrant clocks and schedulers, observed transport close,
and half-built second extension.

Every pre-install failure leaves zero locally owned uncommitted timer, callback,
capability, transport, replay cache, or secret immediately. Already-installed
remote forwarding/adjacency state closes on observed transport/context close
and in all cases by that actor's authenticated projected expiry. The endpoint
retains only its pinned guard physical link where the Gate 3B1 design requires
it; no failure bootstraps, discovers, dials, or races a fallback peer.

Expected RED: any forbidden semantic trap fires, publication occurs before
TAIL_READY, replay allocates a second adjacency, or a manual-clock advance past
expiry leaves installed actor-local state.

Run:

```bash
$NODE node_modules/brittle/bin/node.js test/private/route-extension.js test/private/guard-link.js test/private/tail-control.js
```

- [ ] **Step 13: Audit registration and generate the final aggregate runner**

Steps 1-12 register and generate each test during its own RED phase. As a final
reachability audit, run:

```bash
$NODE node_modules/brittle/bin/node.js test/private-routing.js
npm run test:generate
```

Inspect generated `test/all.js` and require every new Task 6 test file to be
reachable. Focused success is insufficient when generation omits a file. Run
`git diff --check` after generation. Do not manually edit generated omissions.

- [ ] **Step 14: Run the complete Node/Bare and direct-compatibility matrix**

Run focused Task 6 Node and exact-runtime Bare suites, then the complete private
aggregate under both runtimes. Run the native UDX Node/Bare tests that carried
Task 5 evidence. Run the repository's full direct-mode Node and Bare suites,
`npm run test:generate`, Prettier check, and `git diff --check`. Record exact
test/assertion counts and runtime versions for every command.

Do not mark Bare green from the Node result, a floating global install, or an
unversioned CI job. Exact local Bare v1.30.3 evidence is required before
proceeding to reviews and the implementation commit. If that runtime cannot be
restored outside the repository, record the blocker and stop; do not create or
push a candidate commit that cannot satisfy this gate.

- [ ] **Step 15: Obtain independent reviews in strict order**

Dispatch a fresh spec-compliance reviewer against the approved amendment,
canonical Gate 3B1 documents, exact prototype commit, implementation diff, and
test evidence. The Task 6 implementer fixes every substantiated finding with a
new failing regression test first; the same reviewer re-checks until approved.

Only after spec approval, dispatch a separate security/code-quality reviewer.
Review capability reachability, exact option shapes, identity-key confinement,
actor/clock ownership, replay ownership, deadline non-extension, scheduling
reentry, failure-atomic transfers, teardown/zeroization, allocation bounds,
public exports, direct-mode compatibility, and missing adversarial tests. The
same implementer fixes findings test-first; the reviewer re-checks until
approved.

- [ ] **Step 16: Update migration evidence and commit complete Task 6 once**

After all tests and both reviews pass, update
`docs/private-routing-migration.md` with exact Task 6 scope, prototype
provenance, local Node/Bare counts, native UDX/direct compatibility, review
verdicts, and remaining non-goals. Stage only reviewed Task 6 source, tests,
generated runner, and migration evidence. Create one complete implementation
commit:

```bash
git commit -m "feat: extend private routes through pinned guards"
```

Do not commit a half-built slice. Do not add a public private-routing
constructor or package export. Do not push without the separate owner
authorization gate.

### Task 7: Authenticate the endpoint directly to each selected DHT exit

**Files:**

- Create: `lib/private/final-exit.js`
- Create: `lib/private/final-exit-activation.js`
- Create: `test/private/final-exit.js`
- Create: `test/private/final-exit-activation.js`
- Modify: `test/private-routing.js`
- Regenerate: `test/all.js`
- Modify: `docs/private-routing-migration.md`

- [ ] **Step 1: Add failing exact terminal codec and KDF vectors**

Adapt exact cases from prototype `test/final-exit-activation.test.js` and the
final-exit rows in `test/m3-vectors.test.js`. Freeze:

```text
DHT_EXIT_ACTIVATE_V1   body 96,      wire 104
DHT_EXIT_READY_V1      body 233+64,  wire 305
DHT_EXIT_READY_ACK_V1  body 105,     wire 113
DHT_EXIT_OPEN_V1       body 169,     wire 177
FINAL_EXIT_TRANSCRIPT  287 bytes
```

Assert all twelve exact `FINAL_LABELS` strings and their forward/reverse
payload/control/finalize key/nonce vectors. Require exact branch ID, circuit ID,
generation, tail transcript digest, selected advertisement digest/identity/
route key, activation nonce, four-entry policy digest, and payload-parameter
digest bindings.

- [ ] **Step 2: Port pure final-exit codecs and derivation**

Port prototype `lib/final-exit.js` to CommonJS, replacing its duplicate
admitted/payload parameter helpers with imports from `link-parameters.js` while
proving the bytes remain identical. Keep all codecs strict, owned, bounded, and
cleared. No seed or routed-DHT logic belongs in this file.

- [ ] **Step 3: Add failing ACTIVATE/READY transition tests**

Construct `FinalExitActivationSession` only from
`consumeFinalExitHandoff(handoff)` plus exact own options:

```js
new FinalExitActivationSession(handoff, {
  branchId,
  circuitId,
  generation,
  selectedExitAdvertisement,
  absoluteDeadline,
  signedExpiry,
  now,
  randomBytes,
  schedule,
  cancelScheduled
})
```

`schedule(delay, callback)` returns one opaque timer handle and
`cancelScheduled(handle)` consumes it once while guaranteeing the callback
cannot run afterward. The session records every handle before leaving its
scheduling mutation and cancels all handles before clearing protocol state.

Test ACTIVATE→READY first with the endpoint's fresh X25519 ephemeral secret and
the selected exit advertisement's route public key. Assert READY signature
verification and every transcript equality check precedes availability of ACK.
Substitute every identity/key/digest/nonce/branch/circuit/generation field and
assert `ERR_AUTHENTICATION` with handoff material erased.

- [ ] **Step 4: Add failing ACK/OPEN publication and retry tests**

Continue READY→ACK→OPEN. The exit enters OPEN only after ACK, and the endpoint
publishes no terminal binding before valid OPEN. Local finalization expiry is
`min(initialActivate + 5_000, absoluteDeadline, signedExpiry, handoffExpiry)`.
Exact semantic send offsets from initial ACTIVATE are 0, 250, 750, 1,750, and
3,750 ms, but sends after the effective inherited deadline are forbidden. Add
the critical late-start case: ACTIVATE begins 3,500 ms after `GUARD_PINNED`, so
the session gets only the remaining 1,500 ms rather than a fresh five seconds.
Retries reuse semantic bytes under fresh datagram counters; duplicates receive
only cached next responses; conflicts or expiry destroy. After OPEN, cached OPEN
and receive-only tombstones live exactly 5,000 ms, capped by branch/session
expiry, then retired contexts, keys, and semantic caches are erased.

Add revoke-during-retry, destroy-before-next-offset, suspend at 749 ms, and
deadline-races-scheduled-callback tests. Each must show zero later send,
callback, timer handle, or retained semantic bytes.

- [ ] **Step 5: Port `FinalExitActivationSession` and prove inner AEAD**

Port prototype `lib/final-exit-activation.js`. Add a test that seals one routed
payload with the derived terminal payload key, forwards it unchanged through
guard/middle fixtures, and opens it only at the selected exit. Adjacent relays
must fail to decrypt or substitute it. Session success returns one opaque
terminal binding containing branch/circuit/generation/exit identity/expiry and
role-scoped inner payload/control capabilities; it returns no key bytes.

- [ ] **Step 6: Run both runtimes and commit**

```bash
npx brittle-node test/private/final-exit.js test/private/final-exit-activation.js
bare node_modules/brittle/cmd.js test/private/final-exit.js test/private/final-exit-activation.js
npm run test:generate
git diff --check
git add lib/private/final-exit.js lib/private/final-exit-activation.js test/private/final-exit.js test/private/final-exit-activation.js test/private-routing.js test/all.js docs/private-routing-migration.md
git commit -m "feat: authenticate private DHT exits end to end"
```

### Task 8: Migrate bounded relay forwarding and teardown

**Files:**

- Create: `lib/private/relay-service.js`
- Create: `test/private/relay-service.js`
- Modify: `test/private-routing.js`
- Regenerate: `test/all.js`
- Modify: `docs/private-routing-migration.md`

- [ ] **Step 1: Add failing quota, fairness, and teardown tests**

Adapt Gate 3B1 cases from prototype `test/relay-service.test.js` and
`test/adversarial.test.js`. Freeze defaults: 128 circuits globally, 32 per
observed neighbor, 256 KiB queued per circuit, 8 MiB globally, five-second
half-open/reassembly deadlines, bounded replay/tombstones, and atomic queue
admission. Assert negotiated limits may decrease but never increase them.

Prove a relay stores only opaque previous-hop/next-hop capabilities plus local
circuit/generation state, cannot enumerate a path, and cannot open the terminal
routed body. Exercise round-robin fairness, queue pressure, half-open expiry,
cancel, duplicate destroy, link loss, generation expiry, recursive callbacks,
and allocation failure. Temporary capacity returns bounded `ERR_BUSY`; hard
quota returns `ERR_QUOTA_EXCEEDED`; neither creates direct fallback.

- [ ] **Step 2: Port `RelayService` narrowly**

Port prototype `lib/relay-service.js` to CommonJS and bind it to Chunk 2 link
direction capabilities. Keep the exact destroy payload and test observer. All
queue/accounting reservations occur before copying a cell or invoking a
callback. Destroy removes routing state before closing adjacent capabilities so
reentrancy sees a tombstone.

- [ ] **Step 3: Run both runtimes and commit**

```bash
npx brittle-node test/private/relay-service.js
bare node_modules/brittle/cmd.js test/private/relay-service.js
npm run test:generate
git diff --check
git add lib/private/relay-service.js test/private/relay-service.js test/private-routing.js test/all.js docs/private-routing-migration.md
git commit -m "feat: bound private relay forwarding"
```

### Task 9: Build, rotate, and revoke the two branch generations

**Files:**

- Create: `lib/private/guard-lease.js`
- Create: `lib/private/branch-path-authority.js`
- Create: `lib/private/route-manager.js`
- Modify: `lib/private/guard-reconnect-authority.js`
- Modify: `lib/private/route-extension.js`
- Modify: `lib/private/final-exit-activation.js`
- Create: `test/private/guard-lease.js`
- Create: `test/private/branch-path-authority.js`
- Create: `test/private/route-manager.js`
- Create: `test/private/live-topology-fixture.js`
- Modify: `test/private-routing.js`
- Regenerate: `test/all.js`
- Modify: `docs/private-routing-migration.md`

- [ ] **Step 1: Add failing guard-lease ownership tests**

Construct a lease only through:

```js
const lease = createGuardLease({
  guardLeaseMaterial,
  pinnedGuard,
  wallNow,
  monotonicNow,
  setTimer,
  clearTimer,
  guardLossSink
})
```

`guardLossSink` is a frozen empty capability created by the future controller;
an imported internal publisher records one sanitized event after lease state is
already tombstoned and never invokes caller code synchronously.

`guardLeaseMaterial` is the one-shot Task 5 object returned by
`consumeBootstrapGuardPin`; `createGuardLease` atomically consumes it and binds
its exact guard identity/tuple, advertisement digest/epoch/expiry, established
adjacent link, socket owner, local-secret capability, and exact-tuple reconnect
factory to the separately returned `pinnedGuard`. Any mismatch destroys both
inputs. When `RouteManager` later receives the lease and candidate directory,
it uses an imported internal equality check to require the directory's sealed
guard scope to equal the lease; the lease does not own or enumerate directory
records. The lease exposes only opaque manager
capabilities consumed through module-internal `sendToGuard`,
`suspendGuardLease`, and `destroyGuardLease`; it has no property methods
returning material.

`suspendGuardLease` first creates one `GuardReconnectAuthority` by moving the
local-secret capability and zero-argument reconnect factory into it, then
revokes the live guard send capability, closes the established link and socket
owner, and returns the reconnect capability only after zero live socket/send
state is confirmed. The candidate directory remains controller-owned and is
sealed separately; it never enters the reconnect object. Reconnect success
creates a fresh socket owner/link and resolves one fresh `GuardLeaseMaterial`
for the exact same identity/tuple/digest/epoch/expiry. Failure destroys the
fresh socket and returns no material. Test expiry, link loss, replacement
attempt, network change, duplicate destroy, and zero state; guard substitution
always returns `ERR_PRIVATE_GUARD_UNAVAILABLE` and never bootstraps another guard.

- [ ] **Step 2: Add failing initial-pair construction tests**

Using `live-topology-fixture.js`, reserve the directory's atomic initial pair,
create fresh branch IDs/circuit IDs/generations/keys/counters, and build lookup
and announce branches concurrently. Both share only the pinned guard; all four
middle/exit identities, endpoints, IPv4 `/24` groups (or normalized IPv6 `/48`
groups in future-capable pure tests), and local-quarantine groups are distinct.
There is no diversity relaxation. Add explicit negative cases for every
guard↔middle and guard↔exit identity, canonical endpoint, IPv4 `/24`, normalized
IPv4-mapped group, loop, and local-quarantine collision as well as collisions
among the four middle/exit positions.

Start one absolute 5,000 ms monotonic deadline at the `GUARD_PINNED` timestamp.
Candidate selection, both extensions, terminal authentication, and later seed
validation receive that same deadline and may not reset it. Readiness is false
until both branches reach terminal OPEN. Half-success destroys both branches
and commits no directory reservation.

- [ ] **Step 3: Freeze RouteManager's dependency capabilities**

Create module-private factories before constructing the manager:

```js
const extensionFactory = createRouteExtensionFactory({
  now,
  randomBytes,
  schedule,
  cancelScheduled
})
const terminalFactory = createFinalExitActivationFactory({
  now,
  randomBytes,
  schedule,
  cancelScheduled
})
const manager = createRouteManager({
  guardLease,
  candidateDirectory,
  extensionFactory,
  terminalFactory,
  monotonicNow,
  randomBytes
})
```

Both factories are frozen empty WeakMap capabilities. `route-manager.js` calls
only imported internal `openRouteExtension(factory, exactOptions)` and
`openFinalExit(factory, exactOptions)`; callers cannot inject callbacks or
replace protocol steps. The extension factory may create only exact selected
in-route requests through the manager-owned current tail transport; the remote
relay's own role socket owner creates the next adjacency. The terminal factory consumes only
the second-tail `FinalExitHandoff` and inherited deadline.

- [ ] **Step 4: Port path authority and implement transactional pair publication**

Port the narrowed selection/reservation pieces of prototype
`lib/branch-path-authority.js` and `lib/route-manager.js`; do not port the
compiled simulator or discovery path. Implement exact internal methods:

```js
manager.buildInitialPair()
manager.rotate(branchClass)
manager.branchCapability(branchClass)
manager.destroy()
```

The manager reads the guard lease's owned guard-pinned monotonic timestamp;
callers cannot supply or choose a later start. Initial publication is one
synchronous mutation: reserve the directory's atomic pair; consume its selected
evidence into two unobservable draft branches; build both extensions and
terminal sessions concurrently under the same deadline; verify both OPEN;
commit the directory reservation; install both branch slots; mark the pair
ready; only then permit branch-capability issuance. Before commit, any failure
aborts the directory reservation and destroys both drafts. After directory
commit, any impossible publication failure destroys both committed generations
and enters unavailable; it never retries that generation.

Capabilities are frozen empty objects backed by WeakMaps and expose no path
array or address. `branchCapability` becomes issuable only after adjacent links
and terminal OPEN are complete. Module-internal consumers return only route
payload/control send authority and owned branch/circuit/generation/expiry/exit
identity metadata. Revocation removes the capability from its WeakMap before
closing transport so reentrant sends fail.

- [ ] **Step 5: Add failing make-before-break rotation tests**

Lose one middle or exit and reserve one replacement path against the committed
opposite branch. New operations are blocked on the old generation with
`ERR_PRIVATE_BRANCH_ROTATING`; already bounded work may drain. One replacement
attempt uses one absolute deadline computed once at rotation start as
`min(start + 5_000, guard expiry, selected signed expiries)`; every link and
terminal constructor inherits it and cannot reset it. On success,
publish the new generation before destroying the drained old route. On failure,
keep a still-live old generation only until signed expiry; otherwise enter
`UNAVAILABLE`. Repeated attempts cannot overlap, extend expiry, reuse a
candidate generation, or retain failed state.

- [ ] **Step 6: Prove suspend and complete teardown**

Ordinary suspend is controller-owned: it first prevents new manager operations,
cancels pending operations/timers, destroys both branch generations, calls
`suspendGuardLease`, retains only its returned reconnect authority plus the
sealed non-dialing directory, and verifies no other send capability remains.
Manager resume itself does not exist and cannot do IO; a later controller task
consumes reconnect, validates the returned fresh lease material, revalidates the
directory, creates a new GuardLease, and calls `buildInitialPair` with fresh
generations. Destroy order is
routed work → branches → relay circuits → adjacent links → guard lease → socket
→ secrets/tombstones. Test-only snapshots must show zero callbacks, queues,
timers, capabilities, links, routes, and secret buffers.

- [ ] **Step 7: Run both runtimes and commit**

```bash
npx brittle-node test/private/guard-lease.js test/private/branch-path-authority.js test/private/route-manager.js
bare node_modules/brittle/cmd.js test/private/guard-lease.js test/private/branch-path-authority.js test/private/route-manager.js
npm run test:generate
git diff --check
git add lib/private/guard-lease.js lib/private/branch-path-authority.js lib/private/route-manager.js lib/private/guard-reconnect-authority.js lib/private/route-extension.js lib/private/final-exit-activation.js test/private/guard-lease.js test/private/branch-path-authority.js test/private/route-manager.js test/private/live-topology-fixture.js test/private-routing.js test/all.js docs/private-routing-migration.md
git commit -m "feat: manage two private route generations"
```

### Chunk 2 checkpoint

- [ ] Run all private deterministic tests in Node and Bare.
- [ ] Inspect semantic packet-edge records: after guard pinning, endpoint edges
      are guard-only and no `RELAY_DISCOVER_V1` edge exists.
- [ ] Verify both branches are terminally authenticated and pairwise diverse,
      rotation invalidates old generation authority, and teardown leaves zero
      owned state.
- [ ] Confirm `git diff --check` is clean and Tasks 5–9 are separate commits.

## Chunk 3: Provenance-qualified DHT exit and live immutable traversal

### Task 10: Freeze the DHT-only seed object without admitting it

**Files:**

- Create: `lib/private/dht-exit-seeds.js`
- Create: `test/private/dht-exit-seeds.js`
- Modify: `lib/private/protocol.js`
- Modify: `test/private/protocol.js`
- Modify: `test/private-routing.js`
- Regenerate: `test/all.js`

- [ ] **Step 1: Add failing minimum/maximum `0x0045` vectors**

Freeze one one-reference and one three-reference vector using the exact body:

```text
u8 branchClass | 16B branchId | 16B circuitId | u64 generation |
32B exitIdentity | 32B seedSetNonce | u8 count |
count * 172B DESTINATION_REF_V1 | 32B seedSetDigest | 64B signature
```

Assert fixed body 138, body size `138 + 172 * count`, M3 body range 310..654,
complete wire 382..726, count 1..3, unique references sorted by destination ID
then complete handle bytes, exact digest/signature domains, and exact exit
Ed25519 verification. Require branch/circuit/generation/exit equality and
defensive ownership before returning decoded bytes. Prove the existing `0x0044`
decoder rejects `0x0045` and its ID/layout remain unchanged.

Run:

```bash
npx brittle-node test/private/dht-exit-seeds.js
```

Expected: FAIL because the codec does not exist.

- [ ] **Step 2: Implement strict seed sign/encode/decode/verify**

Create exact exports:

```js
signDhtExitSeeds(value, exitSecretKey)
encodeDhtExitSeeds(value)
decodeDhtExitSeeds(encoded)
verifyDhtExitSeeds(encoded, expected)
clearDhtExitSeeds(value)
```

`expected` is exact own data containing branch class/ID, circuit ID, generation,
exit identity, and terminal expiry. Verification performs only canonical,
digest, signature, transcript, class, order, and expiry checks and returns owned
decoded bytes. It does not accept a destination table, endpoint owner, terminal
session, socket, or tuple; assign `CONFIGURED_BOOTSTRAP`; mint a handle; publish
a destination; or claim server-table liveness. Correctly signed seed bytes are
inert until Task 12 consumes them through a terminal-bound admission authority.

- [ ] **Step 3: Prove the codec alone cannot publish authority**

Assert none of the exports can mutate Task 1's live endpoint owner. Mutation,
hostile accessors, allocation failure, wrong key/branch/generation, and trailing
data clear every owned copy and leave zero records. Task 12 adds the only
production signing/delivery and atomic admission path after the exit table
exists.

- [ ] **Step 4: Run both runtimes and commit**

```bash
npx brittle-node test/private/dht-exit-seeds.js test/private/protocol.js
bare node_modules/brittle/cmd.js test/private/dht-exit-seeds.js test/private/protocol.js
npm run test:generate
git diff --check
git add lib/private/dht-exit-seeds.js lib/private/protocol.js test/private/dht-exit-seeds.js test/private/protocol.js test/private-routing.js test/all.js
git commit -m "feat: freeze private DHT exit seeds"
```

### Task 11: Own one client-only ordinary DHT socket and exact packet codec

**Files:**

- Create: `lib/private/dht-exit-wire.js`
- Create: `lib/private/dht-exit-reservation.js`
- Create: `lib/private/dht-exit-io.js`
- Modify: `lib/private/final-exit.js`
- Modify: `lib/private/final-exit-activation.js`
- Create: `test/private/dht-exit-wire.js`
- Create: `test/private/dht-exit-reservation.js`
- Create: `test/private/dht-exit-io.js`
- Modify: `test/private-routing.js`
- Regenerate: `test/all.js`
- Modify: `docs/private-routing-migration.md`

- [ ] **Step 1: Extract a client-only DHT-RPC packet codec with exact vectors**

Adapt only `Request._encodeRequest`, `decodeReply`, `validateId`, and the IPv4
peer codec from pinned DHT-RPC commit
`fe04496196ea2ce42d1de27b0f770b02d2a87cd5`; record those symbols and MIT
provenance in the migration record. Freeze command-0 PING and HyperDHT command-9
IMMUTABLE_GET request/reply bytes in Node and Bare.

The package-private encoder receives an opaque IO reservation plus exact own
data `{ tid, token, internal, command, target, value }`. The reservation, never
the caller, supplies the canonical destination tuple and bound local socket
tuple. PING requires `internal=true`, no token/target/value, and command 0.
Immutable get requires `internal=false`, token null or 32 bytes, command 9,
32-byte target, and null value. Freeze request byte `0x03`, response byte
`0x13`, every permitted flag combination, the encoded destination tuple, and
u16 transaction byte order.

The decoder receives that reservation, the out-of-band source tuple, and the
complete packet. It returns owned `{ tid, from, to, token, closerNodes, error,
valuePresent, value }` only when type/version, allowed flags, transaction, exact source tuple,
encoded `to` equality with the bound local tuple, optional node ID/address-ID
equality, lengths, and complete consumption pass. Reject request packets,
unknown flags/framing, invalid IDs, trailing bytes, and oversize. The codec has
no socket, retry, timer, or table logic.

- [ ] **Step 2: Add failing single-socket correlation tests**

After READY_ACK/OPEN verification, `final-exit-activation.js` creates exactly
two empty WeakMap capabilities from the same finalized transcript:

```js
const exitOpenAuthority = takeDhtExitOpenAuthority(exitSession)
const endpointOpenAuthority = takeEndpointDhtExitOpenAuthority(endpointSession)
```

Each binds branch class/ID, circuit, generation, exit identity, transcript
digest, expiry, absolute deadline, and its direction-specific terminal control
keys. It is issued once only after the local session has committed OPEN,
removed finalization send authority, and installed the 5,000 ms retired-context
tombstone. Cross-side, duplicate, pre-ACK, conflicting-transcript, and expired
takes fail and destroy the narrow session. Tests derive both from one live
transcript and prove every field substitution prevents later seed acceptance.

Create a reservation channel only by consuming the exit-side authority:

```js
const { tableIssuer, ioConsumer } = createDhtExitReservationChannel(openAuthority)
const io = createDhtExitIO(ioConsumer, options)
```

Both halves are frozen empty, WeakMap-backed, generation-bound, and one-shot to
install. `tableIssuer` can be installed only into Task 12's exact table and
`ioConsumer` only into this IO; neither exposes fields or methods. The
reservation module owns the only unwrap operation, verifies both halves came
from the same channel, and transfers reservation bytes directly from table
state to IO state without returning a tuple. Abort/destroy revokes both halves.
The channel retains the exit-side reverse seed-control capability inside
`tableIssuer`; it cannot be supplied again by a caller. Task 11 uses a separate
test-only OPEN issuer to compile and exercise this channel before the production
table exists.

`DHTExitIO` creates exactly one `udx-native` client socket, binds once, and
installs one receive callback. It does not instantiate full DHT-RPC, create a
routing table, open a server socket, watch interfaces, rotate cookies, run
maintenance, or answer inbound requests. Production accepts only exact
host/port and bounded clock/scheduler inputs; it internally constructs
`UdxAdapter`/`udx-native` and never accepts an adapter, socket, UDX instance, or
send callback.

Fake tests use only this separate one-shot boundary:

```js
const authority = createTestDhtExitSocketAuthority(fakeFactory)
const io = createDhtExitIOForTest(options, authority)
```

Both test functions exist only under `TEST_ONLY_DHT_EXIT_SOCKET_ISSUER`; the
frozen empty WeakMap capability is consumed once and rejected by production.
Real Node/Bare loopback tests prove the default reaches `udx-native`.

The only send entry is `sendReservedExitDhtPacket(io, reservation)`. Only the
Task 12 table that consumed this IO's matching `tableIssuer` may issue a
reservation. Its private state supplies exact tuple,
derived ID, branch/circuit/generation, audit class, command/payload, deadline,
and precharged slot. IO allocates a collision-free u16 TID shared by probes and
ordinary requests, writes it into the already-reserved audit record, registers
`(tid, source tuple, local binding, authority, deadline)` before send, and emits
one packet. Exhausting 65,536 IDs fails without send. Wrong source/TID/encoded
destination, late, duplicate, malformed, unsolicited, and request-type packets
are dropped.

Cancel tombstones and removes correlation/timer before table notification and
touches no socket if send has not started. Close tombstones all records, revokes
completion capabilities, cancels scheduled handles, removes the listener,
waits native sends, closes the socket, and clears codec state.

- [ ] **Step 3: Run fake/native packet tests and commit**

```bash
npx brittle-node test/private/dht-exit-wire.js test/private/dht-exit-reservation.js test/private/dht-exit-io.js
bare node_modules/brittle/cmd.js test/private/dht-exit-wire.js test/private/dht-exit-reservation.js test/private/dht-exit-io.js
npm run test:generate
git diff --check
git add lib/private/dht-exit-wire.js lib/private/dht-exit-reservation.js lib/private/dht-exit-io.js lib/private/final-exit.js lib/private/final-exit-activation.js test/private/dht-exit-wire.js test/private/dht-exit-reservation.js test/private/dht-exit-io.js test/private-routing.js test/all.js docs/private-routing-migration.md
git commit -m "feat: own private DHT exit packet IO"
```

### Task 12: Qualify destinations, mint seeds, and publish branch readiness

**Files:**

- Create: `lib/private/dht-exit-destination-table.js`
- Create: `lib/private/dht-exit-test-topology-grant.js`
- Create: `test/private/dht-exit-destination-table.js`
- Create: `test/private/dht-exit-test-topology-grant.js`
- Modify: `lib/private/dht-exit-seeds.js`
- Modify: `lib/private/opaque-destination.js`
- Modify: `lib/private/final-exit.js`
- Modify: `lib/private/final-exit-activation.js`
- Modify: `lib/private/branch-path-authority.js`
- Modify: `lib/private/route-manager.js`
- Modify: `test/private/dht-exit-seeds.js`
- Modify: `test/private/route-manager.js`
- Modify: `test/private-routing.js`
- Regenerate: `test/all.js`

- [ ] **Step 1: Implement and test the opaque 130-byte handle**

In `dht-exit-destination-table.js`, freeze this exact handle prefix/tag layout:

```text
u8 version=1 | u8 class=DHT_NODE_HANDLE | u64 expiresAt |
32B exitIdentity | 16B branchId | 16B circuitId | u64 generation |
32B nonce | 16B authTag
```

Create the 32-byte handle secret and empty table only after terminal OPEN. Bind
the tag and mandatory table entry to complete prefix, destination ID, canonical
tuple, derived DHT ID, exit-owned provenance class/digest, immutable-get command
bit, and zero capability digest under the adopted server-binding/handle-auth
domains.
A valid tag without a live entry fails. Mint expiry is
`min(now + 300_000, branch expiry, circuit expiry, generation expiry, exit advertisement expiry)`.
Rotation/suspend/network change/guard loss/destroy first revoke every request
authority, then clear table entries and secret.

- [ ] **Step 2: Add exact one-shot table authority APIs**

Create a table only by consuming Task 11's matching `tableIssuer`, which already
owns the consumed authenticated terminal OPEN binding:

```js
const table = createDhtExitDestinationTable(tableIssuer, options)
const { sendAuthority, settlementAuthority } = reserveConfiguredBootstrapProbe(
  table,
  index,
  absoluteDeadline
)
const referral = reserveReferralProbe(table, referralReplyAuthority, candidate, absoluteDeadline)
const ordinary = reserveOrdinaryDhtRequest(table, destinationRef, requestSpec, absoluteDeadline)
const completion = settleExitDhtReservation(settlementAuthority, correlatedReplyAuthority)
abortExitDhtReservation(settlementAuthority, reason)
destroyDhtExitDestinationTable(table)
```

All authorities are frozen empty WeakMap keys. Reservation atomically checks
branch/circuit/generation, tuple, derived ID, provenance source, command bit,
rate/concurrency/table bounds, and deadline; charges the slot; installs the
audit record; and only then returns paired send/settlement capabilities. Task
11 consumes `sendAuthority`; the table retains its pending record behind
`settlementAuthority`.

After exact reply correlation, DHTExitIO first removes its TID/source/timer
record and tombstones the send operation, then creates one channel-bound
`correlatedReplyAuthority` containing the matching reservation ID, branch/
generation, transaction, source/local tuples, reply digest, deadline, and owned
decoded reply. It returns no tuple or decoded object to its caller. Only the
matching table can consume both settlement and reply capabilities. Settlement
tombstones table-pending state first. For a successful PING it performs the
single atomic probe-to-live-entry transition and returns the new 172-byte
reference; there is no separate `commitValidatedDestination`. Failure removes
the record without minting. `ORDINARY_DHT_REQUEST` can be
issued only by a live admitted entry, never by a probe or a valid handle lacking
its server entry. Task 11 alone assigns the shared transaction ID and writes it
into the already-reserved audit record before send.

Settling a correlated ordinary reply yields one
`createReferralReplyAuthority(completion)` capability bound to the admitted
issuer entry, exact source, branch/circuit/generation, response digest,
deadline, and an eight-probe budget. `reserveReferralProbe` consumes one budget
unit from only that object; no caller-supplied tuple or reply can establish
`VALIDATED_PROTOCOL_REFERRAL` provenance.

- [ ] **Step 3: Add failing configured-bootstrap and referral-probe tests**

After OPEN, accept 1..3 immutable configured numeric DHT tuples. Validate each with
exactly one command-0 PING, retry false, and 1,000 ms monotonic deadline. For a
protocol referral, require a correlated immutable-get response from an already
admitted reference, exact source tuple, canonical globally routable candidate,
and proposed ID equal to the address-derived ID before allocating a probe.

Before the ping, install one `EXIT_VALIDATION_PROBE` record containing exact
branch/circuit/generation, issuer digest/bootstrap index, candidate tuple/ID,
transaction correlation, deadline, and charged slot. It authorizes that ping
and reply only; it cannot authorize immutable get or mint a ref. Remove it on
reply/timeout/cancel/rotation/teardown.

Freeze bounds: eight candidate probes per upstream reply, three concurrent,
eight per issuing destination per 60 monotonic seconds, 32 per generation, 64
live entries. Duplicates consume no slot and never refresh expiry; excess is
omitted. Reject special-use/private/loopback/link-local/multicast/documentation/
benchmark/CGNAT/invalid-mapped ranges before crypto/allocation/IO. A test-only
topology bypass exists only behind `TEST_ONLY_DHT_EXIT_TOPOLOGY_ISSUER`. Unit
tests may issue the original frozen, one-shot WeakMap authority from an exact
tuple set. Cross-process tests instead issue a frozen verifier from a 32-byte
Ed25519 public key, 16-byte run nonce, exact exit role, and generation; no
signing key or permitted contact enters the child projection. The coordinator
signs this canonical grant only after the exit reports the digest of a tuple it
learned from an authenticated DHT reply:

```text
domain "hyperdht-private-routes/test/isolated-address-grant/v1" |
16B runNonce | u8 exitRole | u64 generation | u64 grantSequence |
u64 expiresAt | 32B tupleDigest | 64B Ed25519 signature
```

`tupleDigest` is a 32-byte hash under the separate
`.../isolated-address-tuple/v1` domain over canonical numeric tuple bytes,
derived DHT ID, exit role, and generation. The child control event carries only
that digest. The coordinator compares it against its eleven-role oracle,
returns only the opaque signed grant, and never returns a tuple. The verifier
recomputes the digest from the already-discovered candidate, verifies exact
run/role/generation/expiry/signature, and consumes the sequence once before the
table can reserve a probe. The initial configured seed may receive one grant in
its projection because that exact tuple is already projected; no referral or
value contact is pre-granted. Production constructors reject both test forms,
and no prefix/range/wildcard or digest-only admission is valid.

Freeze and vector-test `encodeTestIsolatedAddressGrant`,
`decodeTestIsolatedAddressGrant`, and detached Ed25519 sign/verify over every
pre-signature byte above. A cross-process test table is constructed by
consuming `createTestDhtExitTopologyVerifier(testIssuer, publicProjection,
initialSeedGrant)`; it retains only verifier state and the consumed exact seed
grant. After discovery, the only later-grant consumer is:

```js
const testCandidateAuthority = acceptTestIsolatedReferralGrant(
  table,
  referralReplyAuthority,
  candidate,
  grantBytes,
  absoluteDeadline
)
const referral = reserveReferralProbe(
  table,
  referralReplyAuthority,
  candidate,
  absoluteDeadline,
  testCandidateAuthority
)
```

Acceptance verifies the authenticated upstream reply capability first, then
the signed grant, and returns a frozen empty WeakMap authority bound to that
table/candidate/reply/generation/deadline. Reservation consumes it once. A
normal globally routable candidate must omit it; a special-use candidate must
provide it. Grant parsing/signature failure, late arrival, replay, a second
candidate, or a second table fails before allocation/IO. Focused tests create a
table first and admit a signed referral later, proving that the grant is not
merely constructor-time configuration.

- [ ] **Step 4: Deliver seeds through one terminal-bound transaction**

After one or more configured probes succeed, the exit creates
`createDhtSeedDeliveryAuthority(table)`. Creation checks
1..3 live `CONFIGURED_BOOTSTRAP` entries and binds their exact references,
branch/circuit/generation/exit, terminal reverse-control keys, and the original
branch absolute deadline inherited from the consumed `tableIssuer` channel.
No separately supplied terminal session is accepted. Encoding/signing consumes
it once. The exit sends one
`DHT_EXIT_DHT_SEEDS_V1`; byte-identical retries receive only cached success and
conflicting bytes destroy terminal state.

At the endpoint,
`createDhtSeedAdmissionAuthority(owner, endpointOpenAuthority)` consumes the
paired endpoint-side OPEN capability from Task 11 and creates a one-shot exact
binding. Add these transactions to
`opaque-destination.js`:

```js
stageDhtSeedAdmission(authority, verifiedSeeds)
sealDhtSeedAdmission(authority)
commitDhtSeedAdmission(admission)
abortDhtSeedAdmission(admission)
revokeDhtSeedAdmissionAuthority(authority)
```

Stage verifies every signed reference first and labels endpoint metadata only
as `EXIT_ISSUED_DHT_SEED` plus `DHT_NODE_HANDLE`; the endpoint never claims it
observed `CONFIGURED_BOOTSTRAP`. Commit publishes all records atomically.
Allocation failure, timeout, cancel, duplicate ID, or conflict publishes none
and clears every copy.

Modify Task 9's RouteManager so terminal OPEN remains internal as
`OPEN_PENDING_SEEDS`. Each committed seed transaction yields one branch-bound
`BranchSeedReady` capability. Publish the pair only by atomically consuming both
lookup and announce capabilities and rechecking diversity, generation, expiry,
and the original shared 5,000 ms deadline. RouteManager/controller cannot
report READY at OPEN. Seed-before-OPEN or seed after the deadline aborts both
drafts.

- [ ] **Step 5: Run both runtimes and commit**

```bash
npx brittle-node test/private/dht-exit-destination-table.js test/private/dht-exit-test-topology-grant.js test/private/dht-exit-seeds.js test/private/route-manager.js
bare node_modules/brittle/cmd.js test/private/dht-exit-destination-table.js test/private/dht-exit-test-topology-grant.js test/private/dht-exit-seeds.js test/private/route-manager.js
npm run test:generate
git diff --check
git add lib/private/dht-exit-destination-table.js lib/private/dht-exit-test-topology-grant.js lib/private/dht-exit-seeds.js lib/private/opaque-destination.js lib/private/final-exit.js lib/private/final-exit-activation.js lib/private/branch-path-authority.js lib/private/route-manager.js test/private/dht-exit-destination-table.js test/private/dht-exit-test-topology-grant.js test/private/dht-exit-seeds.js test/private/route-manager.js test/private-routing.js test/all.js
git commit -m "feat: admit private DHT exit seeds"
```

### Task 13: Normalize one immutable-get request and qualified reply

**Files:**

- Modify: `lib/private/dht-exit-io.js`
- Modify: `lib/private/dht-exit-wire.js`
- Modify: `lib/private/dht-exit-destination-table.js`
- Create: `test/private/dht-exit-immutable-get.js`
- Modify: `test/private/dht-exit-io.js`
- Modify: `test/private/process/dht-setup-audit-udx.js`
- Modify: `test/private/dht-setup-audit-udx.js`
- Modify: `test/private/dht-exit-wire.js`
- Modify: `test/private-routing.js`
- Regenerate: `test/all.js`
- Modify: `docs/private-routing-migration.md`

- [ ] **Step 1: Add failing immutable-get authority tests**

`DHTExitIO` accepts only a validated `ROUTED_REQUEST_V1` whose live table handle,
branch/circuit/generation, immutable-get policy tuple, 32-byte target, complete
byte budgets, and deadline match. It creates one `ORDINARY_DHT_REQUEST` audit
record before Task 11 sends command 9 with retry false. Require exact
transaction/source/encoded-destination correlation.

Add `encodeImmutableGetResponse`/`decodeImmutableGetResponse` to
`dht-exit-wire.js` by adapting the exact DHT-RPC response value flag and its
`compact-encoding.buffer` field from pinned `lib/io.js`. The routed wire form is
exact: a DHT reply with value flag clear produces zero `encodedResponse` bytes;
with the flag set it contains the complete canonical `c.buffer` encoding,
including one byte for a present empty value. Gate 3B1 therefore permits raw
immutable values of 0..1,023 bytes and encoded present bodies of 1..1,026 bytes.
Freeze absent, present-empty, one-byte, and 1,023-byte vectors plus trailing and
1,024-byte rejection. The outer `encodedResponseByteLength` distinguishes
absence; no JavaScript sentinel or alternate encoding enters the wire.

For each closer tuple, prove it came from this correlated reply to the admitted
`from`, reserve at most the bounded Task 12 probes, and wait only within the
inherited request/branch deadline. Include only successfully admitted live
references sorted by unsigned XOR distance then destination ID. Encode one
exact `ROUTED_REPLY_V1`; charge complete DHT datagram, routed, fragment, cell,
and reverse-reply bytes before send. Late/cancelled replies or probes mutate no
token, entry, counter, cache, or output.

Task 14 requires RoutedDHTIO to decode this exact body with
`decodeImmutableGetResponse` before the local hash check. An absent body yields
no query value; a present empty buffer remains present and is hash-checked.

- [ ] **Step 2: Prove reservation-before-send and negative authority cases**

Authority traps reject an unrecorded PING, immutable get to a probe-only tuple,
valid-tag/missing-entry handle, wrong provenance/generation, expired reference,
transaction exhaustion/collision, and post-cancel request before socket send.
Reentrant rotation after DHT reply correlation but before referral commit aborts
all staged references and emits no routed reply.

- [ ] **Step 3: Run focused tests and commit**

```bash
npx brittle-node test/private/dht-exit-wire.js test/private/dht-exit-io.js test/private/dht-exit-immutable-get.js
bare node_modules/brittle/cmd.js test/private/dht-exit-wire.js test/private/dht-exit-io.js test/private/dht-exit-immutable-get.js
npm run test:generate
git diff --check
git add lib/private/dht-exit-wire.js lib/private/dht-exit-io.js lib/private/dht-exit-destination-table.js test/private/dht-exit-wire.js test/private/dht-exit-io.js test/private/dht-exit-immutable-get.js test/private-routing.js test/all.js docs/private-routing-migration.md
git commit -m "feat: normalize private immutable exit IO"
```

### Task 14: Replace the fake authority with authenticated live branches

**Files:**

- Create: `lib/private/live-route-authority.js`
- Modify: `lib/private/opaque-destination.js`
- Modify: `lib/private/routed-dht.js`
- Create: `test/private/live-route-authority.js`
- Modify: `lib/private/routed-dht-io.js`
- Modify: `test/private/routed-dht-io.js`
- Modify: `test/private/routed-dht-traversal.js`
- Modify: `test/private-routing.js`
- Regenerate: `test/all.js`

- [ ] **Step 1: Separate the nine-method adapter from the seven-method authority**

Freeze `RoutedDHTIO`'s nine adapter methods as `ready`, `suspend`, `resume`,
`destroy`, `bootstrap`, `closest`, `key`, `id`, and `request`. Separately freeze
`LiveRouteAuthority`'s seven methods as `ready`, `suspend`, `resume`, `destroy`,
`bootstrap`, `closest`, and `request`. Authority `request()` returns exact own
data `{ promise, cancel }`; `promise` resolves exact own data
`{ encodedReply, authenticatedReplyAuthority, rtt }`. Reject extras, accessors,
hostile thenables, raw addresses, sockets, paths, or send callbacks.

Create the live authority only from RouteManager's atomically published pair.
Lookup `bootstrap`/`closest` return address-free `{ id, destinationRef }`
snapshots from the live endpoint owner. ANNOUNCE `bootstrap`/`closest` return a
frozen empty array and `request` throws `ERR_PRIVATE_COMMAND_UNSUPPORTED` before
fragment/cell IO; that branch remains live only for the readiness invariant.

- [ ] **Step 2: Send one encoded request through fixed route cells**

For `request`, snapshot exact branch capability, destination capability,
generation, request bytes, attempt, and cancellation state. Encode immutable
target in `ROUTED_REQUEST_V1`, fragment through Gate 3A limits, seal terminal
inner AEAD, frame fixed route payload/cells, and send only through the lookup
branch's pinned-guard capability. Guard/middle relay fixtures forward opaque
cells; only the terminal exit opens and passes the request to `DHTExitIO`.

Reverse the exact encoded reply through the same branch and authenticate/
reassemble without decoding. `LiveRouteAuthority` returns owned bytes plus one
single-use `authenticatedReplyAuthority` bound to terminal session,
branch/circuit/generation, request ID, exact `from`, and reply-byte digest.

`RoutedDHTIO` is the sole reply-validation owner. It consumes that capability
by calling:

```js
const bound = bindAuthenticatedRoutedReply(
  routedReplyReferralAuthority,
  authenticatedReplyAuthority,
  encodedReply
)
```

The first input is the Task 1 capability RoutedDHTIO created before send from
its exact endpoint owner/from/target/request ID/deadline. The second comes only
from the terminal inner-AEAD receive above. The one-shot bind proves both refer
to the same live owner, terminal transcript, branch/circuit/generation, request
ID, exact complete `from`, deadline, and reply-byte digest; consumes both; and
returns one empty staged-admission authority. Cross-request, cross-owner,
cross-generation, wrong digest, late, duplicate, or already-cancelled binds
abort both inputs and publish nothing.

RoutedDHTIO passes only `bound` to Task 1's
`validateRoutedReplyForRequest`, decodes Task 13's exact immutable response,
hash-checks a present value locally, and only then calls
`commitRoutedReplyAdmission`. Every error/cancel/destroy aborts admission and
revokes terminal authority. Neither LiveRouteAuthority nor DHTExitIO publishes
endpoint referrals. Complete logical and encoded-byte costs are charged once.

- [ ] **Step 3: Propagate cancellation and generation revocation**

`cancel(reason)` first tombstones the operation and releases local capacity,
then drops queued route fragments. It sends no network CANCEL. Late complete
replies are discarded before decode/admission. Rotation, suspend, branch expiry,
network change, or destroy revoke all matching operations and opaque
destinations before closing transport. Error mapping must exactly follow the
approved table; errors/logs contain no address, advertisement, key, or path.

- [ ] **Step 4: Replace logical-response handling in `RoutedDHTIO`**

Keep the nine-method DHT-RPC adapter and query-context APIs unchanged. Add only
the exact live-result path above and remove trusted logical responses from
production. Keep `FakeRouteAuthority` only in explicit Gate 3A conformance
tests behind a test-only constructor issuer, so it cannot satisfy the live
constructor. Unsupported commands and ANNOUNCE application calls fail at the
specified boundary without reaching a socket.

- [ ] **Step 5: Run a deterministic two-branch traversal over live routes**

Replace the fake topology in one traversal test with endpoint, shared guard,
diverse lookup middle/exit, diverse announce middle/exit, and enough ordinary
DHT fixtures to force at least one referral. Pre-store one immutable value,
admit seeds on both branches, traverse the lookup referral, and assert exact
value bytes/hash at the endpoint. Verify endpoint edges are guard-only after
pinning, announce remains unused, and ordinary DHT edges originate only at the
lookup exit.

- [ ] **Step 6: Run both runtimes and commit**

```bash
npx brittle-node test/private/live-route-authority.js test/private/routed-dht-io.js test/private/routed-dht-traversal.js
bare node_modules/brittle/cmd.js test/private/live-route-authority.js test/private/routed-dht-io.js test/private/routed-dht-traversal.js
npm run test:generate
git diff --check
git add lib/private/live-route-authority.js lib/private/opaque-destination.js lib/private/routed-dht.js lib/private/routed-dht-io.js test/private/live-route-authority.js test/private/routed-dht-io.js test/private/routed-dht-traversal.js test/private-routing.js test/all.js
git commit -m "feat: traverse DHT over live private routes"
```

### Task 15: Own the internal fail-closed lifecycle controller

**Files:**

- Create: `lib/private/private-routing-controller.js`
- Create: `lib/private/endpoint-bootstrap-authority.js`
- Create: `test/private/private-routing-controller.js`
- Create: `test/private/endpoint-bootstrap-authority.js`
- Create: `test/private/live-immutable-get.js`
- Modify: `lib/private/bootstrap-io.js`
- Modify: `lib/private/guard-lease.js`
- Modify: `lib/private/route-manager.js`
- Modify: `lib/private/relay-capability.js`
- Modify: `lib/private/opaque-destination.js`
- Modify: `lib/private/live-route-authority.js`
- Modify: `test/private/guard-lease.js`
- Modify: `test/private/route-manager.js`
- Modify: `test/private/relay-capability.js`
- Modify: `test/private-routing.js`
- Regenerate: `test/all.js`
- Modify: `docs/private-routing-migration.md`

- [ ] **Step 1: Add failing exact state, signal, and authority-edge tests**

Freeze states `OFF`, `BOOTSTRAPPING`, `GUARD_PINNED`, `BUILDING`, `READY`,
`ROTATING`, `SUSPENDED`, `UNAVAILABLE`, `DESTROYED`. One private transition
function is the sole writer. Before every side effect it checks current state,
owned capabilities, generation, reentrancy token, and destruction status.
Callbacks/events are queued only after a complete state commit; no callback can
observe partial readiness.

For every state, assert the exact endpoint authority/packet-edge table in the
design. From committed `GUARD_PINNED` onward the only permitted endpoint tuple
is the pinned guard. `UNAVAILABLE` and `SUSPENDED` emit nothing. Teardown permits
only one authenticated guard destroy sequence before silence.

Create module-private frozen sinks for guard loss, branch loss/rotation, branch
expiry, wall-clock rollback, seed-ready, and network change. GuardLease,
RouteManager, relay-capability clock validation, and seed admission receive only
their matching sink. Each producer tombstones its affected authority before
issuing one WeakMap event capability; the sink only queues the sole controller
transition. It accepts no tuple, socket, path, generic data, or callback. Test
stale, duplicate, cross-controller, and reentrant signals.

- [ ] **Step 2: Implement cold start through pair readiness**

Create an internal-only factory; do not export from `index.js`. Replace the
unconstrained runtime placeholder with one pre-created endpoint capability:

```js
createPrivateRoutingController({
  endpointBootstrapAuthority
})
```

Create that object through the new internal aggregate issuer:

```js
const endpointBootstrapAuthority = createEndpointBootstrapAuthority({
  bootstrapEndpoints,
  localIdentity,
  localSecretKey,
  host,
  port,
  wallNow,
  monotonicNow,
  schedule,
  cancelScheduled,
  randomBytes
})
```

The issuer immediately creates the Task 3 sealed-directory sink, Task 5 local
identity secret capability/UDX endpoint/bootstrap UDX authority, and Task 4
BootstrapIO, then clears caller-owned secret copies. It returns one frozen empty
WeakMap object. Only
`consumeEndpointBootstrapAuthority(authority, controllerRegistration)` may move
those exact resources plus their guarded clocks, scheduler, and entropy source
into the matching new controller, once; mismatch/failure destroys every
resource. The controller cannot inspect or replace configured
endpoints, identity/secret, candidate sink, or endpoint socket. Remote
guard/middle/exit/DHT services are independently hosted and never injected into
or destroyed by this endpoint controller.

The result exposes internal methods `start`, `immutableGet`, `suspend`,
`resume`, `networkChanged`, `snapshot`, and `destroy`; `snapshot` is test-only,
redacted, and absent from `index.js`. `start()` performs Task 4 bootstrap,
commits `GUARD_PINNED`, builds both branches under the inherited deadline,
waits for both terminal OPEN sessions, then both atomic seed admissions. Its
sole READY predicate is:

```text
live guard lease AND published diverse lookup/announce generation pair AND
both seed-ready capabilities consumed before the shared deadline AND
LiveRouteAuthority/RoutedDHTIO installed for that exact lookup generation
```

Only then does it commit `READY`. Failure destroys both drafts, endpoint
destination state, guard resources, and timers before `UNAVAILABLE`; it never
calls direct DHT or fallback.

- [ ] **Step 3: Implement every capability-driven failure transition**

Install the Step 1 sinks while constructing their listed owners and add one
red-green test for each exact transition:

- guard loss/expiry: the lease tombstones first; controller cancels the
  transport DHT, revokes both branches/destinations, and enters `UNAVAILABLE`
  without replacement;
- middle/exit loss or branch expiry: RouteManager tombstones new-work authority,
  controller commits `ROTATING`, invokes exactly one `rotate(branchClass)`, and
  returns `ERR_PRIVATE_BRANCH_ROTATING` for new work; a replacement reaches
  READY only after terminal OPEN plus its new seed-ready capability, while
  failure preserves an eligible draining old generation only to signed expiry
  or enters `UNAVAILABLE`;
- seed-ready: BUILDING consumes both exact-generation caps atomically; ROTATING
  consumes only the expected replacement cap; stale/cross-branch caps are
  destroyed before transition;
- wall-clock rollback beyond 30 seconds: relay validation tombstones directory
  evidence first, then controller revokes reconnect/routes/destinations and
  enters `UNAVAILABLE` without discovery;
- network change: `networkChanged()` first revokes reconnect, directory, branch,
  destination, socket, and IO owners, then commits `UNAVAILABLE` with no packet.

Every sink handler verifies controller registration/state/generation and calls
only the sole queued transition function. No producer calls `rotate`, creates a
socket, or runs controller code synchronously.

- [ ] **Step 4: Add internal immutable-get and exact DHT-RPC ownership tests**

`immutableGet(target)` exists only on the internal controller and is accepted in
`READY`. After exact route readiness, the controller creates and owns one
`dht-rpc` instance with only:

```js
new DHT({
  outboundPolicy: 'transport-only',
  requestTransport: routedDHTIO,
  requestTimeout: 3000,
  concurrency: 1
})
```

It supplies no `udx`, socket factory, bootstrap, nodes, host/port, or direct
option. The DHT instance owns the RoutedDHTIO adapter lifecycle. Suspend,
failure, and destroy first stop active queries and await
`transportDHT.destroy()`, which destroys the adapter exactly once, before route
teardown. During make-before-break rotation the old instance rejects new work
but may drain only its already bounded operations; the replacement generation
gets a fresh adapter/DHT, is swapped atomically after seed readiness, and the
old DHT is destroyed at drain completion or its fixed deadline. Resume likewise
creates a fresh adapter and transport-only DHT for the fresh lookup generation.

`immutableGet` uses this transport-only traversal,
returns only a locally hash-verified value, and maps exact sanitized errors.
Exercise request timeout, branch rotating, malicious exit, bad hash, quota,
guard loss, link loss, wall-clock rollback, and reentrant destroy. Guard loss
destroys both branches/destinations and enters unavailable without replacement.

- [ ] **Step 5: Implement suspend/resume and network-change semantics**

Suspend blocks new operations, cancels routed work, destroys endpoint-owned
branch handles, calls
`suspendGuardLease`, confirms no live socket/send authority, retains only the
one-shot reconnect capability plus sealed directory, then commits `SUSPENDED`.
Resume atomically consumes reconnect while entering `BUILDING`, contacts only
the exact guard, revalidates directory evidence, creates a fresh GuardLease and
branch generations, validates new seeds, reinstalls live authority, and commits
`READY`. Failure enters unavailable. Network change revokes reconnect,
directory, branches, destinations, socket, and all IO; no resume/discovery/fallback.

- [ ] **Step 6: Prove ordered idempotent endpoint destruction and zero state**

Destroy order is active queries → transport-only DHT (which closes
RoutedDHTIO) → endpoint branch/circuit handles → endpoint
adjacent links → guard lease/reconnect → endpoint socket owner → endpoint
candidate/destination tables → timers/callback queues → endpoint secrets and
tombstones. Remove capabilities from WeakMaps before closing. Repeated destroy
resolves once. In-process snapshots require zero endpoint sockets, handles,
queues, tables, callbacks, timers, or nonzero secret buffers. Chunk 4's
coordinator separately proves teardown of independently hosted relay, exit, and
DHT processes; this controller neither owns nor claims to destroy them.

- [ ] **Step 7: Run deterministic Node/Bare integration and commit**

```bash
npx brittle-node test/private/endpoint-bootstrap-authority.js test/private/private-routing-controller.js test/private/live-immutable-get.js test/private/guard-lease.js test/private/route-manager.js test/private/relay-capability.js
bare node_modules/brittle/cmd.js test/private/endpoint-bootstrap-authority.js test/private/private-routing-controller.js test/private/live-immutable-get.js test/private/guard-lease.js test/private/route-manager.js test/private/relay-capability.js
npm run test:generate
git diff --check
git add lib/private/private-routing-controller.js lib/private/endpoint-bootstrap-authority.js lib/private/bootstrap-io.js lib/private/guard-lease.js lib/private/route-manager.js lib/private/relay-capability.js lib/private/opaque-destination.js lib/private/live-route-authority.js test/private/endpoint-bootstrap-authority.js test/private/private-routing-controller.js test/private/live-immutable-get.js test/private/guard-lease.js test/private/route-manager.js test/private/relay-capability.js test/private-routing.js test/all.js docs/private-routing-migration.md
git commit -m "feat: control live private immutable gets"
```

### Chunk 3 checkpoint

- [ ] Run all private deterministic Node/Bare tests.
- [ ] Confirm one configured seed and at least one qualified referral traverse
      the live lookup branch; announce remains ready but unused.
- [ ] Confirm the exit owns one client-only ordinary DHT socket and every probe/
      request edge has a live audit record.
- [ ] Confirm public `index.js` and constructor behavior are unchanged.
- [ ] Confirm `git diff --check` is clean and Tasks 10–15 are separate commits.

## Chunk 4: Isolated processes, packet/leak oracles, and fork-native CI

### Task 16: Freeze the eleven-role topology and audited process protocol

**Files:**

- Create: `test/private/process/control-channel.js`
- Create: `test/private/process/config-auditor.js`
- Create: `test/private/process/topology-fixture.js`
- Create: `test/private/process/codec-vectors.js`
- Create: `test/private/process/audit-event.js`
- Create: `test/private/process-codec.js`
- Create: `test/private/process-audit-event.js`
- Create: `test/private/process-config-auditor.js`
- Modify: `test/private-routing.js`
- Regenerate: `test/all.js`

- [ ] **Step 1: Add failing canonical control-frame vectors**

Adapt the bounded canonical control codec from prototype
`test/process/control-channel.js` to CommonJS. Freeze a u32be length-prefixed,
maximum-65,536-byte frame whose canonical body supports only null, booleans,
safe integers, bounded strings, arrays, exact plain objects, BigInt u64 strings,
and owned byte arrays. Reject duplicate/forbidden keys (`__proto__`,
`constructor`, `prototype`), accessors, cycles, sparse arrays, noncanonical key
order, overlong UTF-8, trailing bytes, partial-prefix overflow, and more than
131,072 buffered undecoded bytes. The decoder clears each complete backing
buffer after dispatch and `destroy()` clears partial data.

Freeze commands `configure`, `prepare`, `isolated-grant`, `store-immutable`, `activate`,
`immutable-get`, `cancel`, `rotate`, `suspend`, `resume`, `network-change`,
`guard-loss`, test-only `phase-ack`, `snapshot`, and `stop`; events are
`configured`, `prepared`, test-only `isolated-grant-request`, `stored`, `phase`, test-only `phase-pending`,
`audit-open`, `audit-close`, `ready`, `value`,
`cancelled`, `rotated`, `suspended`, `resumed`, `unavailable`, `snapshot`,
`closed`, and sanitized `error`. Every command/event has exact keys, role,
generation, phase, and bounded payload rules. No event may carry a tuple,
advertisement, secret, route key, raw table, or generic log string.

`audit-open`/`audit-close` use the exact sanitized fields defined in Task 19;
`process/audit-event.js` implements Task 19's exact record-digest and event-MAC
bytes now, and `process-audit-event.js` freezes open/close vectors, sequence/
nonce uniqueness, reply-digest correlation, and key clearing before either live
process task consumes them. The codec freezes them even though portable runs
only validate/store them.
`phase-ack`/`phase-pending` are accepted only when the role projection contains
Task 19's one-shot phase-gate capability; production/portable projections
reject them.

`isolated-grant-request` is exit-only and carries exact run/role/generation,
one 32-byte tuple digest, and a request sequence—never a tuple.
`isolated-grant` is coordinator-only, may answer only a pending matching digest,
and carries the bounded signed Task 12 grant bytes. It is accepted once and
only in the Linux-namespace or portable-loopback test projection.

Run:

```bash
npx brittle-node test/private/process-codec.js test/private/process-audit-event.js
```

Expected: FAIL because the process codec does not exist.

- [ ] **Step 2: Build one deterministic eleven-role topology fixture**

Freeze these process roles:

```text
endpoint
guard
lookup-middle-a       lookup-exit-a
lookup-middle-b       lookup-exit-b
announce-middle       announce-exit
dht-seed              dht-referral              dht-value
```

The guard also serves the configured pre-pin CAPS/bootstrap endpoint. Lookup A
is selected initially; lookup B is valid standby evidence used for one
make-before-break rotation. Announce remains independently ready. `dht-seed`
is the exit's configured bootstrap and its ordinary routing table contains at
least `dht-referral`; `dht-referral` also knows `dht-value`. The coordinator
orders `dht-referral` to obtain an ordinary DHT token from the exact
`dht-value` tuple and send one ordinary command-8 IMMUTABLE_PUT there, then
clears its transient value bytes. Thus `dht-seed` does not store the value and
its command-9 reply must contain at least one closer tuple, forcing a
correlated referral PING before retrieval. Tests assert the observed referral
path rather than trusting fixture labels.

`createLiveProcessTopology({ plan, clocks, entropy })` accepts only these two
frozen plans:

```text
portable-loopback: 127.64.<roleIndex>.1, UDP 42000 + roleIndex
linux-namespace:   10.203.<roleIndex>.2/24, UDP 42000 + roleIndex
```

Role indexes are 1..11 in the exact order above. Portable addresses use
distinct loopback `/24`s available on Linux/macOS/Windows and never require an
interface alias or default route. Namespace peers use a matching root-side
`.1/24` veth gateway but install no default route. For every exact permitted
role edge, install a destination `/32` route through that namespace's `.1`
gateway. Enable root IPv4 forwarding only for the test bridge and install a
default-deny forward policy whose bidirectional allow rules match the fixture's
exact source/destination IPv4 addresses, UDP ports, and ingress/egress veths.
The frozen allow graph contains only endpoint↔guard, guard↔its three middles,
each middle↔its exit, each exit↔the three ordinary DHT roles, seed↔referral,
referral↔value, and auditor↔decoy; response directions are explicit rather than
ambient conntrack authority. Teardown removes rules/routes and restores the
prior forwarding setting. Unit tests reject a missing gateway `/32`, a broad
subnet/default route, a cross-role edge, and marker traffic outside the
auditor↔decoy pair. The test-only topology authority signs and permits exactly
the selected plan's eleven tuples; no caller-supplied address, port, prefix,
hostname, wildcard, or fallback is accepted.

The fixture creates
all identities, signed advertisements, exact policy/parameter digests,
configured numeric endpoints, expected link grants, DHT IDs, target hash, and a
distinctive endpoint address plus 32-byte leak sentinel. It returns eleven
role-scoped projections and a coordinator-only oracle record. Entropy is
deterministic only in tests; no fixture key enters production defaults.

- [ ] **Step 3: Reject ambient authority in every role projection**

Port and narrow prototype `test/process/config-auditor.js`. Exact policies are:

- endpoint knows its local secret, one numeric guard bootstrap, target hash,
  and no DHT/exit/middle tuple or immutable value;
- guard owns its Ed25519 identity secret, route-encryption secret, advertisement
  signing state, Task 5 UDX bind tuple, bounded candidate advertisements it
  serves, and selected/standby middle adjacencies; it learns the endpoint tuple
  only from authenticated bootstrap/link traffic and never receives endpoint
  application bytes;
- each middle owns its Ed25519 identity secret, route-encryption secret,
  advertisement, one UDX bind tuple, and only its guard/exit adjacent
  identities/tuples;
- each exit owns its Ed25519 identity and route-encryption secrets,
  advertisement, adjacent UDX tuple, terminal policy/keys, and
  `dht-seed`; only lookup exits receive immutable-get authority. Test
  projections additionally contain only the Task 12 isolated-grant verifier
  public key/run binding and one initial grant for the already-projected seed;
  no referral/value tuple or signing authority is projected;
- each ordinary DHT role owns exact `{ host, port, ephemeral: false,
firewalled: false, anyPort: false, bootstrap: [], nodes }` construction authority, where
  `dht-value.nodes=[]`, `dht-referral.nodes=[dht-value]`, and
  `dht-seed.nodes=[dht-referral]`; none receives a socket/adapter callback or
  another role's bind capability;
- ordinary DHT roles otherwise know only their DHT neighbors; `dht-referral` may receive
  value bytes only in the one audited `store-immutable` command and must clear
  them after command-8 succeeds, `dht-value` retains the stored value, and none
  receives endpoint identity/tuple/sentinel.

Every role projection owns one independent 32-byte control/audit MAC key; the
coordinator-only oracle record owns the matching copies. Keys authenticate
events but authorize no network edge and are cleared on child/coordinator stop.
Namespace-only auditor/decoy marker keys are never projected into the eleven
route roles.

The auditor checks canonical config bytes before spawn and every event after
spawn, traversing Maps/arrays/objects without invoking accessors. It rejects a
forbidden role, extra contact, raw path, broad subnet, hostname, DNS setting,
TCP setting, endpoint sentinel/address outside the endpoint projection and
guard's documented adjacent binding, or a secret in any event. Add one
mutation case for every role/contact edge.

- [ ] **Step 4: Run Node/Bare codec/config tests and commit**

```bash
npx brittle-node test/private/process-codec.js test/private/process-audit-event.js test/private/process-config-auditor.js
bare node_modules/brittle/cmd.js test/private/process-codec.js test/private/process-audit-event.js test/private/process-config-auditor.js
npm run test:generate
git diff --check
git add test/private/process/control-channel.js test/private/process/config-auditor.js test/private/process/topology-fixture.js test/private/process/codec-vectors.js test/private/process/audit-event.js test/private/process-codec.js test/private/process-audit-event.js test/private/process-config-auditor.js test/private-routing.js test/all.js
git commit -m "test: freeze private route process topology"
```

### Task 17: Run the live value flow in separate Node and Bare processes

**Files:**

- Create: `test/private/process/runtime-node.js`
- Create: `test/private/process/runtime-bare.js`
- Create: `test/private/process/role-runner.js`
- Create: `test/private/process/coordinator.js`
- Create: `test/private/process/dht-setup-audit-udx.js`
- Create: `test/private/live-process-suite.js`
- Create: `test/private/live-process-node.js`
- Create: `test/private/live-process-bare.js`
- Create: `test/private/process-control.js`
- Create: `test/private/dht-setup-audit-udx.js`
- Modify: `lib/private/dht-exit-destination-table.js`
- Modify: `lib/private/dht-exit-test-topology-grant.js`
- Modify: `test/private/dht-exit-test-topology-grant.js`
- Modify: `package.json`
- Modify: `test/private-routing.js`
- Regenerate: `test/all.js`

- [ ] **Step 1: Add failing spawn, framing, deadline, and cleanup tests**

Adapt prototype process coordinator/control-lifecycle cases. The coordinator is
always a Node test process; each role child is either Node or Bare. Add exact
5,000 ms per-command and 30,000 ms whole-scenario deadlines, stderr maximum
4,096 bytes, one waiter per expected `(role,event,generation)`, and no implicit
retry. A child error, malformed frame, unexpected phase, stderr output, early
exit, deadline, or coordinator cancel first closes stdin, sends SIGTERM once,
waits 2,000 ms, sends the platform hard-kill only if still live, awaits all
exits, destroys decoders/auditor, and reports only sanitized role/phase/code.

Test partial frames, stdout flooding, duplicate events, child crash during
prepare, cancel during activation, stop while a DHT request is pending, and
cleanup after a Bare child fails before importing UDX.

- [ ] **Step 2: Add exact runtime adapters and pinned Bare dev tools**

Add exact dev dependencies:

```json
"bare-process": "4.5.1",
"bare-runtime": "1.30.3"
```

Add package import `#private-route-process` with `bare` and `default` mappings
to the two runtime files. The adapters expose only stdin/stdout/stderr,
runtime/version, monotonic/wall clocks, and `exit(code)`. Role code uses no
Node-only import. The coordinator resolves Bare through
`require('bare-runtime')('bare')`; it never downloads a runtime during a test.
Freeze identical codec-vector digests and `udx-native` version `1.20.7` from
every child before activation.

- [ ] **Step 3: Host each real protocol role behind its projection**

`role-runner.js` constructs only the service owned by its role:

- endpoint: Task 15 aggregate/controller and transport-only DHT;
- guard/middles: one `UdxCellEndpoint`, authenticated link sessions, and bounded
  `RelayService` circuits for permitted adjacencies;
- exits: adjacent/terminal sessions, one Task 11 ordinary DHT socket, one Task
  12 table, and no full DHT-RPC node;
- DHT roles: ordinary direct HyperDHT/DHT-RPC nodes bound to their one numeric
  test address, with only `dht-value` storing the known immutable value.

Before implementing the setup store, add a failing
`dht-setup-audit-udx.js` test proving direct `dht.request()` otherwise hides its
assigned TID/encoded packet until native send. Then create a test-issuer-only,
non-authorizing observing UDX wrapper inside the `dht-referral` role runner—not
in its projection and not in DHT-RPC production code. It wraps the runner's real
`udx-native` instance and delegates `watchNetworkInterfaces()` unchanged; each
`createSocket()` returns a proxy that forwards bind/address/close/event methods
and the exact original buffer/host/port/TTL to the real socket once.

`armSetupDhtAudit(controller, spec)` accepts only the next coordinator-ordered
setup class, exact command/target/value digest, `dht-value` destination, and
DHT_SETUP phase. The proxy decodes every bounded DHT-RPC datagram into exactly
one of these non-overlapping classes:

- an outbound non-internal command 8/9 to the exact bound `dht-value` tuple is
  setup-eligible and must match/consume the next arm before native send;
- an outbound internal command `0..3` to an exact projected `nodes` tuple is
  constructor bootstrap/maintenance, passes unarmed byte-identically, and adds
  one bounded response correlation;
- an inbound response passes byte-identically only when source/TID match an
  outstanding setup or internal request; setup correlation queues its close;
- an inbound canonical request from an exact topology-permitted DHT/exit tuple
  passes and creates one bounded server-reply correlation; the outbound response
  passes unarmed only when destination/TID consume that correlation.

No other outbound non-internal request, unmatched response, or unclassified
packet passes. Thus constructor bootstrap, permitted maintenance, correlated
inbound replies, and real server responses need no setup arm, while an unarmed
or mismatched setup-store request fails before native send.

For a setup-eligible real proxy `trySend`, the wrapper obtains the actual TID
and bound source, verifies the armed spec, queues the Task 16 `audit-open`
synchronously, and only then forwards the unaltered call. It cannot create a
socket, packet, address, retry, or send of its own. Its wrapped `message`
listener observes the real response before forwarding the unchanged event to
DHT-RPC, requires swapped tuple/TID, queues the correlated `audit-close`, and
consumes the arm. Promise rejection closes only the matching armed/open record
with the bounded outcome. One controller allows exactly the three ordered
token/put/readback arms, 64 internal/server correlations, a 16-record event
queue, and a drain-only cap; expiries are monotonic and never authorize a send.
Destroy clears arms, correlations, records, queue, wrapper references, and MAC
key. Tests prove unarmed bootstrap/maintenance, correlated inbound replies, and
server responses pass unchanged. They reject an unarmed/mismatched/retried
setup request, non-internal traffic to another tuple, a forged response, packet
mutation, socket-method expansion, cross-role use, overflow, and post-destroy
traffic, while proving the real socket receives byte-identical arguments
exactly once.

For endpoint/relay/exit roles, prepare binds only the sockets whose production
owners are explicitly idle until activation and installs receive authority
without sending. For all three ordinary DHT roles, prepare performs canonical
config/audit checks only: it must not construct DHT-RPC because its constructor
schedules `_bootstrap()` on the next tick. Ordered activation constructs
`dht-value` first with no known node, then `dht-referral` with only
`dht-value`, then `dht-seed` with only `dht-referral`, always with
`anyPort:false`. Each role waits for `listening`/ready, obtains the actual local
address from the live IO owner, and requires byte-for-byte equality with its
projected host/port before emitting readiness or permitting the next role to
construct. Bind fallback, an early packet during prepare, or a different actual
tuple fails and destroys the scenario. Before proceeding, exact
test-only routing snapshots must show: seed has referral and no stored value;
referral has value-node reachability; value has no immutable record. The
coordinator then performs the setup-only store below, freezes those three
initial-contact projections, activates relays/exits, and finally activates
endpoint bootstrap. Later ordinary DHT learning is allowed and audited; the
acceptance invariant is that the configured seed lacks the value and therefore
returns at least one closer that the exit must qualify before retrieval—not
that a particular intermediate hop remains hidden. Deep
snapshots are test-only counts/digests: state, generation, open sockets/links/
routes, queued bytes, active operations/probes/table entries/timers, and
nonzero-secret count. They contain no tuple, key, advertisement, handle, or
payload.

- [ ] **Step 4: Prove a live immutable get and lifecycle failures in Node roles**

Before endpoint activation, the coordinator sends the single setup-only,
audited `store-immutable` command carrying the known value to `dht-referral`.
That process performs one direct ordinary `dht.request` command 9 to the exact
`dht-value` tuple with retry false, consumes the returned token, then performs
one direct command 8 to that same tuple with retry false. It does not call
`immutablePut()` or start an iterative query, so no other node receives/stores
the value. The `stored` event is accepted only after a command-9/8 TID/source
pair correlates, a command-9 readback from `dht-value` returns the exact hash/
bytes, `dht-seed` reports no local record, and the writer has zero transient
value bytes. The DHT_SETUP audit contract in Task 19 opens and closes one exact
record for each token request, put, and readback; `stored` carries their three
ordered audit sequences and record digests plus the value digest, never a tuple
or payload. No setup-store operation is valid after endpoint bootstrap begins.

At endpoint activation the seed snapshot contains at least `dht-referral` and
no value. Its command-9 reply must therefore carry one or more closer tuples.
For an isolated test address, the exit hashes the already-decoded candidate and
emits `isolated-grant-request`. The coordinator matches only that digest
against its oracle, returns the signed Task 12 grant, and the exit verifies and
consumes it before the normal referral-probe reservation. A grant request for
an undiscovered digest, a replay, or a grant for another role/generation fails
before PING. No contact is projected by this exchange.
The exit must open a referral audit record, PING, and admit at least one returned
closer before the endpoint can request that new reference; the closer may be
`dht-referral` or a legitimately learned `dht-value`. Either is a protocol
referral under the spec, and the test fails if the endpoint receives a value
without traversing one admitted referral. It then waits for both private branches and both
seeds, orders one immutable get, and accepts `value` only when endpoint reports
exact target hash and bytes.
Assert at least one referral probe and two ordinary exit requests occurred,
endpoint semantic edges are guard-only after pin, and announce transported no
application request.

Then run bounded subscenarios: cancel a delayed lookup; fault lookup A and wait
for lookup B rotation/seed readiness before a second successful get; suspend
and require zero endpoint socket/send state; resume only the exact guard and get
through fresh generations; network-change to unavailable with no fallback; and
separately guard-loss to unavailable without replacement. Stop all eleven
roles and require exit code 0 plus zero-state snapshots.

Run:

```bash
npx brittle-node test/private/dht-setup-audit-udx.js test/private/process-control.js test/private/live-process-node.js
```

Expected before implementation: FAIL on the first missing runner/coordinator.

- [ ] **Step 5: Run the identical scenario with Bare role children**

`live-process-suite.js` owns the assertions and receives only the runtime launch
record. Node and Bare tests may not fork scenario logic. Bare child success
proves runtime/process compatibility only—not mobile backgrounding, app-private
storage, radio changes, or anonymity.

```bash
npx brittle-node test/private/live-process-bare.js
```

Expected after implementation: all eleven children report runtime `bare`,
version `v1.30.3`, identical codec digests, the exact value, and clean closure.

- [ ] **Step 6: Add scripts, run both suites, and commit**

Add:

```json
"test:private:process:node": "brittle-node test/private/live-process-node.js",
"test:private:process:bare": "brittle-node test/private/live-process-bare.js"
```

Then run:

```bash
npm install
npx brittle-node test/private/dht-exit-test-topology-grant.js test/private/dht-exit-destination-table.js
npx brittle-node test/private/dht-setup-audit-udx.js test/private/process-control.js
npm run test:private:process:node
npm run test:private:process:bare
npm run test:generate
git diff --check
git add package.json lib/private/dht-exit-destination-table.js lib/private/dht-exit-test-topology-grant.js test/private/dht-exit-test-topology-grant.js test/private/process/runtime-node.js test/private/process/runtime-bare.js test/private/process/role-runner.js test/private/process/coordinator.js test/private/process/dht-setup-audit-udx.js test/private/dht-setup-audit-udx.js test/private/live-process-suite.js test/private/live-process-node.js test/private/live-process-bare.js test/private/process-control.js test/private-routing.js test/all.js
git commit -m "test: run live private routes across processes"
```

Confirm ignored `package-lock.json` and all temporary role directories remain
unstaged.

### Task 18: Enforce the semantic leak and direct-authority oracles

**Files:**

- Create: `test/private/semantic-leak-oracle.js`
- Create: `test/private/direct-authority-trap.js`
- Create: `test/private/leak-oracle.js`
- Create: `lib/private/direct-authority-audit.js`
- Modify: `lib/private/udx-adapter.js`
- Modify: `lib/private/udx-cell-endpoint.js`
- Modify: `lib/private/endpoint-bootstrap-authority.js`
- Modify: `lib/private/bootstrap-io.js`
- Modify: `test/private/process/config-auditor.js`
- Modify: `test/private/process/coordinator.js`
- Modify: `test/private/process/role-runner.js`
- Modify: `test/private/live-process-suite.js`
- Modify: `test/private-routing.js`
- Regenerate: `test/all.js`

- [ ] **Step 1: Add failing recursive leak-oracle tests**

Create one iterative, cycle-safe oracle that inspects owned bytes and exact data
properties in: role projections/control frames, decoded M3/routed/DHT messages,
relay advertisements, test-only candidate/destination/probe/audit snapshots,
errors, metrics, event frames, stderr, process exit records, and teardown
snapshots. It never invokes accessors, coercion, iterators supplied by tested
objects, `toJSON`, or custom inspection.

Outside the documented pre-guard exposure report and the guard's authenticated
adjacent record, fail on the endpoint's numeric address bytes/string, 32-byte
sentinel, local secret/public identity where not explicitly allowed, a public
dial field, a raw 19-byte endpoint, or a route path. Scan complete captured
datagram payloads for the same address/sentinel and allow only encrypted/random
coincidence handling through exact phase/type provenance—not substring
whitelists. Mutation tests hide each value in arrays, Maps, Sets, errors,
symbols, typed-array views, backing buffers, and hostile prototypes.

- [ ] **Step 2: Arm a process-local direct-authority trap at guard pin**

Add a non-authorizing module-internal audit channel:

```js
const audit = createTestEndpointAuthorityAudit(testIssuer, exposurePlan)
const endpoint = createEndpointBootstrapAuthorityForTest(options, audit)
commitEndpointAuditGuardPin(audit, guardPinCapability)
```

Only `TEST_ONLY_ENDPOINT_AUTHORITY_AUDIT_ISSUER` can create it, production
aggregate construction rejects it, and it exposes no UDX/socket/create/send
method. `endpoint-bootstrap-authority.js` consumes the empty WeakMap sink into
the real `UdxAdapter`; adapter/socket-owner code calls imported
`auditCreateSocket`, `auditBind`, and `auditTrySend` synchronously immediately
before each native operation. The audit module derives permitted tuples only
from the consumed configured/prospective-guard admission capabilities. At guard
pin, BootstrapIO passes its one-shot guard-pin capability to the audit module,
which atomically revokes pre-pin entries and permits the exact guard only. No
caller tuple, adapter injection, or policy callback is accepted.

A forbidden create/bind/send records a sanitized violation and throws before
native IO even if a namespace/firewall would drop the packet. The adapter's
existing production constructor still rejects adapter/socket injection, and a
test proves the audited path uses the same production `udx-native` methods.

Exercise endpoint→exit, endpoint→DHT, DNS, TCP, hole-punch, post-pin bootstrap,
post-pin RELAY_DISCOVER, suspended send, unavailable send, and late teardown
send. Also prove permitted bootstrap/prospective-guard and pinned-guard packets
do not trip it.

- [ ] **Step 3: Audit the live Node/Bare lifecycle and commit**

Feed every config/event/snapshot and role stderr chunk through the oracle before
retention. After each live suite, combine coordinator records with the
endpoint/guard exposure report and require zero violations plus zero direct
trap calls. Negative unit fixtures must fail with stable reason codes and no
sensitive bytes in the thrown error.

```bash
npx brittle-node test/private/leak-oracle.js
bare node_modules/brittle/cmd.js test/private/leak-oracle.js
npm run test:private:process:node
npm run test:private:process:bare
npm run test:generate
git diff --check
git add lib/private/direct-authority-audit.js lib/private/udx-adapter.js lib/private/udx-cell-endpoint.js lib/private/endpoint-bootstrap-authority.js lib/private/bootstrap-io.js test/private/semantic-leak-oracle.js test/private/direct-authority-trap.js test/private/leak-oracle.js test/private/process/config-auditor.js test/private/process/coordinator.js test/private/process/role-runner.js test/private/live-process-suite.js test/private-routing.js test/all.js
git commit -m "test: reject private route authority leaks"
```

### Task 19: Prove phase-aware packet edges in Linux namespaces

**Files:**

- Create: `test/private/namespace/layout.js`
- Create: `test/private/namespace/manager.js`
- Create: `test/private/namespace/pcap.js`
- Create: `test/private/namespace/capture-oracle.js`
- Create: `test/private/namespace/phase-marker.js`
- Create: `test/private/namespace/negative-control.js`
- Create: `test/private/namespace/diagnostic-sanitizer.js`
- Create: `test/private/namespace/run.js`
- Create: `test/private/namespace-unit.js`
- Create: `lib/private/dht-exit-audit-events.js`
- Modify: `lib/private/dht-exit-destination-table.js`
- Modify: `lib/private/dht-exit-io.js`
- Create: `test/private/dht-exit-audit-events.js`
- Modify: `test/private/dht-exit-destination-table.js`
- Modify: `test/private/dht-exit-io.js`
- Modify: `test/private/process/coordinator.js`
- Modify: `test/private/process/control-channel.js`
- Modify: `test/private/process/config-auditor.js`
- Modify: `test/private/process/role-runner.js`
- Modify: `lib/private/private-routing-controller.js`
- Modify: `package.json`
- Modify: `.gitignore`
- Modify: `test/private-routing.js`
- Regenerate: `test/all.js`

- [ ] **Step 1: Add failing namespace-layout and PCAP parser tests**

Adapt prototype namespace layout/parser to CommonJS and eleven route roles plus
isolated `auditor` and `decoy` namespaces. Allocate unique RFC1918 synthetic
IPv4 addresses only inside the test topology, ports 42,000+, one veth per role,
and a root bridge. Disable IPv6/router advertisements and bring up only loopback
plus `eth0`; install no default internet route. Materialize Task 16's exact
per-edge `/32` gateway routes, root bridge addresses, IPv4 forwarding, and
default-deny ingress/egress-veth-qualified UDP forward rules before any child
starts. Root forwarding has no route to the host uplink, and cleanup restores
the prior forwarding/firewall state even after partial setup. Names and ports include a
validated random run suffix and cleanup actions are registered immediately
after every resource creation.

Parse classic PCAP little/big endian for Ethernet and Linux cooked v2. Retain
SLL2 packet type and interface index. Reject PCAPNG, truncated records, snaplen
truncation, unknown link types, malformed
VLAN/IP/UDP, fragments, TCP, IPv6, bad lengths, duplicate/missing phase
sentinels, and packets whose ingress interface contradicts the claimed source.
Return owned timestamp, SLL2 packet type/interface, source/destination,
protocol, ports, and payload. Ethernet remains unit-parser coverage only.

The authoritative launch is exactly:

```text
tcpdump -i any -Q in -y LINUX_SLL2 -U -s 0 -w <0600-temporary-path>
```

Require SLL2 plus inbound `PACKET_HOST` records. `-Q in` retains the packet as
it enters the root bridge on the source role's veth and excludes the forwarded
outbound copy. Infer source role from SLL2 interface index, then require its
source IP/port; exact duplicate records fail rather than being silently
deduplicated.

- [ ] **Step 2: Build a phase-aware packet/audit oracle**

First add focused failing tests for the real exit audit seam:

```bash
npx brittle-node test/private/dht-exit-audit-events.js test/private/dht-exit-destination-table.js test/private/dht-exit-io.js
```

Expected: FAIL because the test audit channel and constructor sink halves do
not exist. Implement the channel only after observing that failure.

Install a test-only, non-authorizing controller phase gate through
`TEST_ONLY_CONTROLLER_PHASE_GATE_ISSUER`. After the sole transition function
commits a state but before starting any new-state network side effect, the gate
emits an out-of-band `phase-pending` control event and blocks only the test
runner. The coordinator orders the auditor namespace to send one phase marker,
waits for the decoy's correlated reply, then sends `phase-ack`; only then may the
controller continue. Production construction rejects the gate, and it cannot
choose a state, tuple, or send.

Marker payload is exact canonical bytes:

```text
domain "hyperdht-private-routes/test/capture-phase/v1" | u8 direction |
u64 sequence | u8 phase | u64 generation | 16B nonce |
[32B requestDigest on reply only] | 32B HMAC
```

The HMAC is exactly `sodium-universal` `crypto_auth` (32-byte
HMAC-SHA-512/256 output, 32-byte key) over all preceding marker bytes, including
the fixed domain with no terminator or length prefix. Request and reply use
distinct one-byte direction values `0` and `1` immediately after the domain;
the reply also appends the 32-byte request digest before its HMAC. All integers
are big-endian. Reusing a sequence/nonce in either direction fails.

Only coordinator/auditor/decoy own the per-run key. Freeze marker IDs in this
order: `0x00 CAPTURE_START`, `0x01 DHT_SETUP`, `0x02 BOOTSTRAPPING`,
`0x03 GUARD_PINNED`, `0x04 BUILDING`, `0x05 READY`, `0x06 ROTATING`,
`0x07 SUSPENDED`, `0x08 RESUME_BUILDING`, `0x09 UNAVAILABLE`,
`0x0a TEARDOWN`, `0x0b DESTROYED`, and `0x0c CAPTURE_STOP`.
Each request/reply pair is unique and ordered; the reply echoes digest/sequence.
The marker reply is the attribution boundary: packets captured before it belong
to the previous phase, and packets after it belong to the newly committed
phase. The controller gate blocks every new endpoint side effect during this
pending interval, and the packet oracle proves the endpoint emits nothing
between `phase-pending` and the matching marker reply. Relay liveness,
maintenance, and replies may continue only under the previous phase's exact
edge rules until that boundary; they are not falsely claimed to be globally
fenced. Missing, duplicate, misordered, bad-MAC, or unacknowledged markers fail.

CAPTURE_START/STOP and DHT_SETUP are coordinator capture boundaries. DHT_SETUP
begins before the first ordinary DHT constructor is called and ends before
endpoint BOOTSTRAPPING. TEARDOWN is a
coordinator command boundary emitted/acknowledged before invoking controller
destroy, not an added controller state. All other markers come from the exact
post-commit controller phase gate; DESTROYED is emitted after its state commit.

Enforce the design's exact edges during DHT_SETUP, before pin, and in GUARD_PINNED, BUILDING,
READY, ROTATING (old/new bounded routes), SUSPENDED, resume BUILDING,
UNAVAILABLE, and teardown. From guard pin onward endpoint packets are only the
pinned guard. During DHT_SETUP, allow DHT-RPC's constructor-scheduled bootstrap
traffic only between each role and its exact projected `nodes` contact, and
only from that role's construction until its verified ready event. Every
explicit setup-store token request (command 9), put (command 8), and readback
(command 9) must instead match its own live setup audit record and must occur
after all three DHT roles are ready but before BOOTSTRAPPING. Decode
exit-generated ordinary DHT headers and require every PING or command 9
packet/TID/tuple/time to equal a live exported audit-record digest interval;
probe-only records cannot authorize command 9. Reject DNS, TCP, unexpected
IPv6, a non-role interface, endpoint→exit/DHT, post-close packets, or a packet
outside its phase.

Cross-check the Task 18 semantic oracle against every packet payload and the
role-event/config corpus. Require at least one role packet in every exercised
networked phase, one admitted configured PING, one referral PING, two ordinary
immutable requests, a lookup A→B rotation, suspend silence, exact-guard resume,
and the authenticated endpoint→guard teardown sequence.

Add the only real-exit audit seam as a non-authorizing test channel:

```js
const { tableAuditSink, ioAuditSink, drainAuthority } = createTestDhtExitAuditChannel(
  TEST_ONLY_DHT_EXIT_AUDIT_ISSUER,
  {
    roleIndex,
    auditMacKey,
    maximumRecords: 256
  }
)
```

All three values are frozen empty WeakMap capabilities. The Task 11 IO
constructor and Task 12 table constructor accept their matching half only when
it was issued by the module-private test issuer; ordinary production
construction and cross-channel halves fail. The
channel exposes no tuple, socket, adapter, packet mutation, callback, or send
method and therefore can deny on overflow but cannot authorize or redirect IO.
The role runner owns only `drainAuthority`, which drains bounded owned
sanitized events in sequence for its control channel.

The table sink stages class/generation/reservation identity when the real table
charges a reservation. Immediately after Task 11 assigns the final TID and
encodes the complete packet, but synchronously before its real native
`trySend`, the IO sink joins that opaque reservation, freezes the packet digest,
and queues `audit-open`. It cannot manufacture a reservation. After exact
reply/source/TID correlation, the IO puts only the reply digest into
`correlatedReplyAuthority`; the matching real table queues `audit-close` only
while consuming settlement, or queues the bounded timeout/cancel/error close
while aborting. Both owners tombstone their audit state with the network
authority. Focused tests prove a real configured probe, referral probe, and
ordinary request produce the exact events, while a fake sink, sink swap,
post-close drain, or sink-created send is impossible.

Freeze these one-byte audit classes in Task 16's codec:

```text
0x01 EXIT_VALIDATION_PROBE
0x02 ORDINARY_DHT_REQUEST
0x03 SETUP_STORE_TOKEN
0x04 SETUP_STORE_PUT
0x05 SETUP_STORE_READBACK
```

The three setup classes are valid only for `dht-referral`→`dht-value` in
DHT_SETUP and exact commands 9, 8, 9 respectively. `stored` carries ordered
`setupAuditSequences[3]`, `setupAuditDigests[3]`, and `valueDigest`; the
coordinator accepts it only after the three matching successful closes and
captured request/reply correlations. Reuse, reordering, another tuple/command,
or any setup class after BOOTSTRAPPING fails. These events come only from Task
17's observing wrapper around the real `dht-referral` UDX socket; the
coordinator and role runner may not synthesize them from the Promise result.

Every audit record owns a monotonically increasing nonzero u64
`recordSequence` and fresh 16-byte `recordNonce`. Its 32-byte `recordDigest` is
the unkeyed BLAKE2b-256 hash of the exact fixed domain
`hyperdht-private-routes/test/dht-audit-record/v1`, followed by u64 record
sequence, nonce, u8 class, u16 TID, u64 generation, canonical 19-byte source and
destination numeric tuples, u16 command, u64 opening phase sequence, and the
32-byte BLAKE2b-256 digest of the complete outbound UDP payload. Integers are
big-endian and fixed domains have no terminator or variable-length prefix.

`audit-open` carries only role index, class, TID, generation, opening phase
sequence, record sequence/nonce/digest, and event MAC. `audit-close` repeats
those fields and adds closing phase sequence, one-byte outcome, 32-byte complete
reply-payload digest, and event MAC. Outcome IDs are `0 SUCCESS`, `1 TIMEOUT`,
`2 CANCELLED`, and `3 ERROR`; open uses the reserved outcome byte `0xff` in its
MAC input. Events expose no tuple or packet bytes.

The event MAC is exactly keyed BLAKE2b-256 (`sodium-universal`
`crypto_generichash`, 32-byte output and 32-byte per-role key) over fixed domain
`hyperdht-private-routes/test/dht-audit-event/v1`, then u8 discriminator
`0 OPEN`/`1 CLOSE`, u64 record sequence, 16-byte nonce, u8 role index, u8 class,
u16 TID, u64 generation, u64 opening phase sequence, u64 closing phase sequence
(`0` for open), u8 outcome, 32-byte record digest, and 32-byte reply digest
(all zero for open). The coordinator-only oracle supplies known role tuples,
recomputes the record digest from each captured request, verifies the exact
event MAC/lifetime, and correlates the reverse reply by swapped tuple plus TID
and complete reply digest before accepting close. A reused sequence/nonce/TID
combination, unmatched event, or unmatched packet fails.

- [ ] **Step 3: Calibrate three isolated negative controls**

Before the authoritative run, capture one decoy forbidden edge and prove the
packet oracle rejects it. In two separate fresh captures, a test-only bypass
emits (a) a PING without `EXIT_VALIDATION_PROBE` and (b) command 9 to a
probed-but-unadmitted tuple; both must be captured and rejected for the missing
audit authority. The production table/IO authority trap independently attempts
the same operations and must reject them before send. Delete successful
calibration captures. A failing local authoritative PCAP is kept mode 0600 only
when `PRIVATE_ROUTE_KEEP_RAW_CAPTURE=1`; CI never sets it.

- [ ] **Step 4: Run namespace unit tests and the privileged gate**

Add scripts:

```json
"test:private:namespace:unit": "brittle-node test/private/namespace-unit.js",
"test:private:namespace": "node test/private/namespace/run.js"
```

Run locally only when Linux/root/tools are available:

```bash
npx brittle-node test/private/dht-exit-audit-events.js test/private/dht-exit-destination-table.js test/private/dht-exit-io.js
bare node_modules/brittle/cmd.js test/private/dht-exit-audit-events.js test/private/dht-exit-destination-table.js test/private/dht-exit-io.js
npm run test:private:namespace:unit
sudo env "PATH=$PATH" npm run test:private:namespace
```

Before cleanup, `diagnostic-sanitizer.js` converts failures to bounded JSON
containing only workflow/run IDs, parser reason code, phase, role names, packet
header fields, audit digests, and SHA-256 payload digests. Unit fixtures prove
the JSON contains no raw payload/value, endpoint sentinel/address, key, handle,
config, or PCAP bytes. CI deletes raw captures before artifact upload even if
sanitization fails.

Expected authoritative summary contains exact role/phase/packet/audit counts,
zero forbidden/leak records, and `cleanup: true`. On every success/failure,
stop capture, children, listeners, veths/bridge/namespaces in reverse order and
verify `ip netns list` contains no run suffix. Add `artifacts/` to `.gitignore`.

- [ ] **Step 5: Commit the namespace oracle**

```bash
npm run test:private:namespace:unit
npm run test:generate
git diff --check
git add .gitignore package.json lib/private/dht-exit-audit-events.js lib/private/dht-exit-destination-table.js lib/private/dht-exit-io.js lib/private/private-routing-controller.js test/private/dht-exit-audit-events.js test/private/dht-exit-destination-table.js test/private/dht-exit-io.js test/private/namespace/layout.js test/private/namespace/manager.js test/private/namespace/pcap.js test/private/namespace/capture-oracle.js test/private/namespace/phase-marker.js test/private/namespace/negative-control.js test/private/namespace/diagnostic-sanitizer.js test/private/namespace/run.js test/private/namespace-unit.js test/private/process/dht-setup-audit-udx.js test/private/dht-setup-audit-udx.js test/private/process/coordinator.js test/private/process/control-channel.js test/private/process/config-auditor.js test/private/process/role-runner.js test/private-routing.js test/all.js
git commit -m "test: enforce private route packet edges"
```

### Task 20: Add GitHub-native gates and record exact-head evidence

**Files:**

- Create: `.github/workflows/private-routing-gate-3b1.yml`
- Modify: `package.json`
- Create: `test/private/public-api-audit.js`
- Modify: `test/private-routing.js`
- Regenerate: `test/all.js`
- Modify: `docs/private-routing-migration.md`
- Modify: `docs/private-routing-baseline.md`

- [ ] **Step 1: Add failing public/direct compatibility audits**

Snapshot enumerable exports, `HyperDHT.DEFAULTS`, direct constructor option
handling, direct DHT-RPC/HyperDHT wire vectors, and package `files`. Assert no
`privateRouting`, `privacy`, controller, route authority, test issuer, process
harness, or new constructor option is public from `index.js`, `browser.js`, or
package exports. Compare direct-mode vector fixtures to Gate 3A bytes. The
installed dependency intentionally omits its tests, so the exact DHT-RPC fork
suite is owned by the secondary-checkout CI job below rather than this audit.

Add aggregate scripts without changing `npm test`/`test:bare` semantics:

```json
"test:private:node": "brittle-node test/private-routing.js",
"test:private:bare": "node node_modules/bare-runtime/bin/bare node_modules/brittle/cmd.js test/private-routing.js",
"test:private:portable": "npm run test:private:process:node && npm run test:private:process:bare"
```

- [ ] **Step 2: Add one pinned GitHub-native workflow**

Create a workflow with `permissions: contents: read`, concurrency cancellation,
20-minute job timeouts, no repository/secrets write, no caches containing role
state, and only full action SHAs:

```text
actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5
actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020
actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
```

Jobs:

1. `pinned-dht-rpc`: Linux/macOS/Windows matrix. Use a second pinned checkout
   step with `repository: ayooooo123/dht-rpc`,
   `ref: fe04496196ea2ce42d1de27b0f770b02d2a87cd5`,
   `path: exact-dht-rpc`, and `persist-credentials: false`; verify
   `git rev-parse HEAD`, install independently, force/verify UDX 1.20.7 and Bare
   1.30.3 for the test environment, then run its `npm run lint`,
   `npm run test:node`, and `npm run test:bare`. Never substitute the packaged
   dependency for this source checkout.
2. `deterministic`: Linux/macOS/Windows matrix; Node 22; `npm install`; verify
   DHT-RPC dependency string contains the exact SHA, installed DHT-RPC is
   6.27.0, UDX is 1.20.7, Bare is 1.30.3; run Prettier, the private Node/Bare
   suites, public API audit, `npm test`, `npm run integration`, and
   `npm run test:bare`. This duplicates the complete direct matrix on
   `private-routing-v1`, so exact-head evidence does not depend on the existing
   main/PR-only workflow trigger.
3. `portable`: Linux/macOS/Windows × Node/Bare-child matrix after deterministic;
   run the matching eleven-process suite with no privileges or internet
   topology dependency.
4. `namespace`: Ubuntu after all portable jobs; install only `iproute2`,
   `iptables`, and `tcpdump`; prove `ip netns` capability; run namespace unit
   tests, then the authoritative root gate with a bounded artifact directory.
   On failure run the tested sanitizer, then an `if: always()` deletion step for
   every `.pcap`; upload only `artifacts/diagnostics/*.json` for three days.
   Never upload raw captures, control frames, configs, keys, values, or
   successful artifacts.

The workflow triggers for `private-routing-v1`, main, and PRs when private code/tests,
package metadata, migration/baseline docs, or the workflow changes. Existing
`test-node.yml` remains unchanged and must pass whenever a PR/main event triggers
it; the new workflow's duplicated direct matrix is the branch-push evidence.

- [ ] **Step 3: Run the complete local nonprivileged regression**

```bash
npm install
npm run format
npm run test:generate
npm run test:private:node
npm run test:private:bare
npm run test:private:portable
npm test
npm run integration
npm run test:bare
git diff --check
git status --short
```

Expected: every deterministic/private/process/direct suite passes in Node and
Bare; repository-wide tests pass or any known host-topology exception is
reported without calling it green. Confirm `node_modules`, ignored lockfile,
artifacts, captures, role data, and debug logs are unstaged.

- [ ] **Step 4: Commit and obtain implementation-head workflow evidence**

```bash
git add .github/workflows/private-routing-gate-3b1.yml package.json test/private/public-api-audit.js test/private-routing.js test/all.js docs/private-routing-migration.md
git commit -m "ci: gate live private immutable routing"
git push origin private-routing-v1
gh run list --branch private-routing-v1 --limit 10
```

Wait for every new Gate 3B1 job, including its duplicated full direct matrix and
secondary DHT-RPC checkout, at that exact implementation SHA. If a PR is open,
the existing workflow must also pass, but branch-push evidence never depends on
that trigger. Do not rerun a different SHA and call it evidence. Inspect every
job and download only sanitized JSON failure artifacts; fix in a new task commit
and repeat until the exact implementation head is green.

- [ ] **Step 5: Record evidence without overstating the milestone**

Update baseline/migration docs with the exact implementation SHA, workflow run
URLs, per-job results, Node/Bare test/assertion counts, packet/audit/phase counts,
negative-control results, pinned dependency/runtime versions, and any local
host-topology exception. State explicitly that Gate 3B1 proves this live
immutable-get slice and its observed packet/leak invariants only. It does not
claim production anonymity, traffic-analysis resistance, public mode,
Hyperswarm/peer streams, PearTube, or mobile readiness.

```bash
git add docs/private-routing-baseline.md docs/private-routing-migration.md
git commit -m "docs: record Gate 3B1 verification"
git push origin private-routing-v1
```

Wait for the documentation head's path-triggered workflows too. Report both the
recorded implementation run and final documentation-head runs; the former is
the canonical code evidence and the latter proves the committed evidence did
not regress formatting/tests.

### Chunk 4 checkpoint

- [ ] Node and Bare deterministic suites pass with identical protocol vectors.
- [ ] Eleven-process Node and Bare suites retrieve and locally verify the value,
      rotate lookup A→B, suspend/resume exact guard, and fail closed on network/
      guard loss with zero child state.
- [ ] Semantic and direct-authority oracles report zero violations; every
      negative fixture is detected.
- [ ] Privileged namespace CI proves phase-aware endpoint→guard-only traffic,
      correlated exit probe/request edges, suspend silence, and cleanup.
- [ ] Existing direct-mode HyperDHT plus exact pinned DHT-RPC remain green.
- [ ] No public private mode, unsupported DHT command, Hyperswarm/PearTube/mobile
      behavior, or production anonymity claim exists.
- [ ] Tasks 16–20 are separate commits, `git diff --check` is clean, and exact
      implementation/documentation workflow evidence is recorded.
