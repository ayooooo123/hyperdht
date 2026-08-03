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
- `guard-link.js`: authenticated index-zero links; the relay-owned,
  request-bound extension adjacent-link factory and dial authority; accepted
  adjacency/replay transfer; and the lexical issuer for an empty
  `M3AuthenticatedBranchBinding`. It joins that binding only with the exact
  `M3CellLinkTransferIssuer` that moved with the authenticated established
  link; no endpoint-visible tuple, raw identity key, structural channel, or
  test issuer exists.
- `relay-identity-signer.js`: empty WeakMap-backed, relay-identity-owned,
  domain-limited LINK_OFFER, LINK_ACCEPT/redacted-proof, TAIL_READY, and
  DHT_EXIT_READY signers.
- `guard-reconnect-authority.js`: single-use, exact-tuple suspend/resume authority.
- `m3-context.js`: M3 inner associated-data and fixed envelope codecs.
- `m3-adjacency-adopter.js`, `m3-adjacency-runtime.js`: registered
  `M3CellLinkTransfer` adoption; paired responder-tail/token ownership; separate
  proactive physical-runtime and logical `M3TailLifetime` timers; the
  `M3TailControlTransportOwner`; and exact forwarding claim/lease/publication/
  receipt ownership.
- `link-bootstrap-session.js`, `link-control-session.js`, `udx-adapter.js`:
  adjacent bootstrap/control wire state and the native adapter boundary.
- `udx-cell-endpoint.js`: sole live UDX socket/established-record owner,
  record-owned `SHARED_GUARD`/`NON_SHARED_RELAY` policy, slot-reserving
  `M3CellLinkTransferIssuer`, two-capability registration, private
  `{ M3 generation, circuitId, direction }` dispatch, send/receive reservation
  and full-cell accounting, and the physical-owner split.
- `guard-lease.js`: sole holder and closer of already pin-branded
  `SHARED_GUARD` established ownership, with up to four logical branch/
  replacement slots; logical M3 release never closes it. Non-shared runtime
  teardown instead consumes only its exact moved physical owner.
- `tail-control.js`: exact authenticated `EXTEND_REQUEST`/`EXTENDED`/
  `TAIL_READY` bytes; one stable `TailControlOwner`; the sole logical transport
  destructor; send/receive-only borrower; co-located token-gated responder
  transitions; exact forwarding transfer; ordered AEAD counters; and the
  prepare/commit/revoke final-exit bridge.
- `extension-setup-channel.js`, `extension-link-completion.js`: physical
  LINK_OFFER/LINK_ACCEPT/proof exchange and linear movement of authenticated
  established ownership, the UDX-issued transfer issuer/registered transfer,
  socket-owner lease, and one-shot completion.
- `route-extension.js`: endpoint-local selected-evidence initiator orchestration
  that moves the same stable owner, armed lifetime, authenticated borrower,
  clocks, and deadlines; it has no discovery, dialing, structural transport,
  or replacement-timer surface.
- `tail-extension-committer.js`: staged `EXTENDED` installation and movement of
  the exact M3 forwarding publication claim/facade into tail-control ownership;
  it does not publish a facade by itself.
- `final-exit-handoff.js`: one-shot same-runtime terminal handoff carrying the
  stable owner, armed lifetime, authenticated borrower, wire expiry, projected
  local deadline, and clock identity.
- `final-exit.js`: exact terminal ACTIVATE/READY/ACK/OPEN codecs, transcript,
  derivation, and inner AEAD.
- `final-exit-activation.js`: sole issuer of
  `FinalExitActivationClaim`/`FinalExitActivationOwner`, exact claim operation,
  activation state, responder-only DHT_EXIT_READY signer consumption, the fixed
  cross-module cleanup bridge, and lexical `OpenRouteHandoff` issuance only
  after authenticated OPEN.
- `open-route-handoff.js`: consumer/revoke/destroy boundary for the one-shot
  terminal OPEN capability already issued by `final-exit-activation.js`; it
  accepts no arbitrary owner/material issuer and moves the exact activation/
  stable owner, borrower accounting, and route material into Task 9 without
  exposing keys, transport, deadline owners, or destructors.
- `branch-path-authority.js`, `route-manager.js`: later Task 9-only branch
  publication, global deadline, rotation, generation ownership, and movement
  of the same TailControl owner/lifetime/borrower through extension and
  final-exit activation; Task 6 has no `BranchPathAuthority` dependency.
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

- [ ] **Step 6: Add the exact Node/Bare UDX owner and authenticated M3 transfer**

- [ ] **Step 6a: Write the failing OPEN-record transfer, dispatch, and accounting tests**

In `test/private/udx-cell-endpoint.js` and `test/private/guard-link.js`, use the
real loopback owner—not a structural channel or test-issued M3 transport—to
prove that one OPEN established record can issue an M3 transfer only by joining
two independent one-shot capabilities:

1. `takeM3CellLinkTransferIssuer(establishedLink)` reserves a logical slot and
   tentative registration charge from the exact live OPEN UDX record; and
2. lexical authenticated `guard-link.js` code issues one empty
   `M3AuthenticatedBranchBinding` only after LINK_OFFER/LINK_ACCEPT,
   advertisement, proof, transcript, peer, and cell-context authentication.

Add RED cases for swapped, foreign, replayed, or revoked issuer/binding pairs;
wrong endpoint/send/topology/setup identity, tuple/peer, link-control
epoch/circuit provenance, authenticated identities/digests, M3
branch/circuit/generation/extension index/cell IDs/directions, physical policy,
duplicate dispatch key, and use of the LinkControlSession circuit as an M3 key.
Also freeze four simultaneous shared-guard logical slots and one non-shared
slot; issuer-take-through-revoke/release charging; two ordered initiator
receive reservations and one responder reservation; full 1,200-byte
receipt/envelope accounting; unknown-key drop before copy; and exact rollback
without physical close.

Run:

```bash
npx brittle-node test/private/udx-cell-endpoint.js test/private/guard-link.js
bare node_modules/brittle/cmd.js test/private/udx-cell-endpoint.js test/private/guard-link.js
```

Expected RED: missing `takeM3CellLinkTransferIssuer`,
`registerM3CellLinkTransfer`, record-bound dispatch/reservation operations, or
the lexical authenticated-binding issuer. A fake issuer, raw socket, arbitrary
callback, or structural `{ send, receive, destroy }` object is an invalid RED
fixture.

- [ ] **Step 6b: Port the sole native UDX owner and preserve bootstrap authority**

Add direct runtime dependency `"udx-native": "1.20.7"`, matching the reviewed
prototype/runtime exactly. Run
`npm pkg set dependencies.udx-native=1.20.7 && npm install`, verify
`require('udx-native/package.json').version === '1.20.7'`, and confirm the
ignored `package-lock.json` is not staged. Port prototype `lib/udx-adapter.js`
and `lib/udx-cell-endpoint.js` to CommonJS.

`UdxCellEndpoint` remains the sole socket owner for one role process. Its
production constructor still accepts only:

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
binds one peer identity and numeric tuple, installs a PENDING record, and
returns a `LinkBootstrapSession`. Valid CREATED atomically changes that record
to OPEN and installs cell codec/control state. PENDING accepts only bootstrap;
OPEN accepts only established traffic; tuple/identity mismatch drops before
callback. `close()` tombstones first, revokes send handles, rejects queues,
removes listeners, closes pending/control sessions, waits native sends, closes
the socket, and clears adapter-owned UDX state without an undocumented destroy.

The production constructor never accepts an adapter. Existing queue/allocation
tests retain only the frozen, one-shot `TEST_ONLY_UDX_ADAPTER_ISSUER` boundary;
production loopback tests must observe the default `UdxAdapter`/`udx-native`.
Keep the exact pre-pin `createLocalIdentitySecretCapability`,
`createBootstrapUdxAuthority`, `sendConfigured`,
`sendProspectiveGuard`, and `pinBootstrapUdxGuard` flow. Successful pinning
consumes the exact hidden GuardLease ownership token, brands that OPEN record
`SHARED_GUARD` before any M3 issuer can be taken, revokes every generic handle,
and returns opaque `GuardLeaseMaterial` carrying the already-branded
established ownership plus exact socket/local-secret/reconnect ownership.

- [ ] **Step 6c: Implement the two-capability registration and private dispatch**

An OPEN record records immutable physical policy only from hidden ownership:
bootstrap pinning consumes the exact GuardLease ownership token and brands
`SHARED_GUARD`; the one-shot extension setup owner brands
`NON_SHARED_RELAY`. No later GuardLease constructor, M3 caller, or policy enum
can choose, defer, or mutate that value.

Implement this exact package-private UDX surface:

```js
takeM3CellLinkTransferIssuer(establishedLink)
registerM3CellLinkTransfer(transferIssuer, authenticatedBinding)
revokeM3CellLinkTransferIssuer(transferIssuer)
takeM3CellLinkTransfer(transfer)
revokeM3CellLinkTransfer(transfer)
reserveM3CellSend(borrower)
commitM3CellSend(reservation, cell1200)
abortM3CellSend(reservation)
reserveM3CellReceive(borrower)
takeM3CellReceipt(borrower, receipt)
releaseM3CellReceipt(borrower, receipt)
releaseM3CellBorrower(borrower)
destroyM3PhysicalLinkOwner(owner)
```

The issuer is frozen and empty. Its WeakMap record binds the OPEN endpoint
record, established send/topology handles, peer identity/canonical tuple,
current link-control epoch/circuit, hidden physical policy, reserved slot, and
issuer generation. `guard-link.js` exposes only
`takeM3AuthenticatedBranchBinding(binding, transferIssuer)` and
`revokeM3AuthenticatedBranchBinding(binding)` as package-private consumers.
Registration tombstones both inputs before callbacks, compares every hidden
record and authenticated M3 field, rejects the link-control circuit and a
duplicate pending/active M3 dispatch key, then replaces the tentative charge
with one empty `M3CellLinkTransfer`.

Each OPEN record owns a dispatch map keyed exactly by
`{ epoch, circuitId, direction }`, where `epoch` is M3 generation from the u64
at offset 4 and `circuitId` is the M3 value at offset 12. The established
LinkControlSession epoch remains separate record provenance and is rechecked at
registration, transfer take, and M3 adoption. Parse only the fixed 36-byte
clear header before any decoder/allocation. Link-control circuit traffic stays
on its existing path; an exact M3 key consumes one queued opaque reservation;
unknown/malformed/conflicting keys clear and drop without closing the physical
link.

Taking a non-shared transfer moves one opaque `physicalOwner`; taking a shared
guard transfer returns only the logical borrower because physical ownership
remains in `GuardLease`. Logical release tombstones reservations/receipts,
rejects pending work, releases every slot/packet/byte charge once, and never
emits close or spends shared physical ownership. GuardLease close first
invalidates every issuer/transfer/borrower and then closes once. Every
registration/revoke/reentry failure clears copied identities, tentative
dispatch, slot, and accounting before returning and never permits a callback
before rollback.

- [ ] **Step 6d: Make the authenticated transport prerequisite GREEN**

Run:

```bash
npx brittle-node test/private/udx-cell-endpoint.js test/private/guard-link.js test/private/udx-loopback.js
bare node_modules/brittle/cmd.js test/private/udx-cell-endpoint.js test/private/guard-link.js test/private/udx-loopback.js
```

Expected GREEN: real Node and Bare UDX loopback issue both capabilities,
register and take one transfer, send/receive one exact 1,200-byte M3 cell,
release logical ownership with exact zero accounting, preserve shared guard
physical ownership, and reject every mismatch/replay before authority moves.
Only after this step and Task 5 Steps 7-8 are GREEN and committed may Task 6
resume; Task 6 must not substitute provisional structural or test-only
transport.

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
- Create: `lib/private/final-exit-activation.js`
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
- Create: `test/private/final-exit-activation.js`
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

- [ ] **Step 2: Add authenticated-transfer M3 adoption and independent runtime/lifetime clocks**

- [ ] **Step 2a: Write the failing registered-transfer and timer tests**

In `test/private/m3-adjacency-runtime.js`, build adoption from Task 5's real
loopback path: OPEN record issuer + lexical guard-link binding -> registered
`M3CellLinkTransfer`. Add no structural `physicalChannel`, fake transport
issuer, or arbitrary destructor. Add one bounded RED case at a time proving:

1. `M3AdjacencyAuthority.adopt` consumes the registered transfer and rechecks
   its exact endpoint/link/setup identities, canonical tuple/peer, separate
   established-link epoch provenance, M3 branch/circuit/generation/cell
   IDs/directions, and hidden physical policy;
2. a shared guard adoption receives only the logical borrower, while a
   non-shared relay adoption moves exactly one opaque `physicalOwner`;
3. `wireExpiresAt` projects once into the adopting actor's monotonic clock as
   `monotonicNow() + max(0, wireExpiresAt - wallNow())`, and the frozen
   `{ wireExpiresAt, localDeadline, clockIdentity }` moves without reprojection;
4. overflow, non-positive intervals, backward wall time, non-monotonic
   `monotonicNow`, alternate clock identities, transfer replay, and any joined
   record mismatch fail before publishing runtime/tail state;
5. one physical-runtime expiry handle is armed before runtime, tail, responder
   token, or pending tail transport can publish; synchronous firing, scheduler
   throw, invalid handle, reentrant cancellation, or failure to retain the
   handle destroys unpublished state; and
6. after exact forwarding installation, the first installed runtime expiry
   consumes the internal `M3ForwardingOwner`, cancels both runtime handles, and
   closes both contexts/borrowers/eligible non-shared physical owners once.

Run:

```bash
$NODE node_modules/brittle/bin/node.js test/private/m3-adjacency-runtime.js test/private/udx-cell-endpoint.js
```

Expected RED: adoption still accepts structural channel material or ambiguous
`now`, cannot consume `M3CellLinkTransfer`, confuses M3 generation with the
established-link epoch, leaks shared physical close authority, or publishes
without an owned timer.

- [ ] **Step 2b: Implement the exact adoption and separate lifetime owner**

Replace `M3AdjacencyAuthority`'s ambiguous `now` with exact `wallNow`,
`monotonicNow`, `schedule`, and `cancelScheduled`. Adoption consumes only the
registered transfer, rechecks the complete joined record, and creates a frozen
empty pending `TailControlTransportTransfer` bound to the exact runtime, tail,
M3 borrower, branch/circuit/generation/extension index, local/peer cell IDs,
initiator direction, clock identity, and moved deadlines. Store it only inside
the tail-capability record; never return an unbound transfer.

Implement the M3-owned logical-lifetime surface:

```js
takeM3TailCapability(capability, { wallNow, monotonicNow }, ownerDestroy)
shortenM3TailLifetime(lifetime, ownerDestroy, {
  wireExpiresAt,
  localDeadline
})
releaseM3TailLifetime(lifetime, ownerDestroy)
```

Capability take validates and spends the exact tail capability and clock
identities, creates one empty `M3TailLifetime`, records the stable
`ownerDestroy`, runtime reservation/generation, binding, and moved bounds,
arms the lifetime's own timer at `localDeadline`, then atomically consumes the
pending transport transfer into an opaque `M3TailControlTransportOwner`.
Responder token and tail binding attach to that same lifetime/callback before
publication. Any failure destroys the unpublished lifetime, borrower,
transport owner, token/binding, and moved material.

The logical timer is independent of the physical runtime timer. Logical expiry
invokes stable-owner cleanup and releases only logical M3 ownership; it never
closes a runtime or physical link. Runtime/context teardown first tombstones
the lifetime, cancels its timer, clears token/binding, invokes `ownerDestroy`
once with exceptions suppressed, and only then performs eligible physical
cleanup. `shortenM3TailLifetime` accepts only non-increasing wire/local bounds
and the identical callback/clock, arms the replacement before canceling the
old logical timer, and fail-closes on every synchronous/reentrant scheduling
boundary. `releaseM3TailLifetime` is terminal-only and never closes physical
state.

- [ ] **Step 2c: Run the focused GREEN proof**

```bash
$NODE node_modules/brittle/bin/node.js test/private/m3-adjacency-runtime.js test/private/udx-cell-endpoint.js
```

Expected GREEN: the real registered transfer is consumed once; runtime and
logical timers stay independently armed; shared and non-shared physical
ownership remain distinct; every mismatch/expiry releases exact borrower,
slot, receipt/envelope, timer, and copied binding state once.

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
createFinalExitReadySigner(identityOwner)
signFinalExitReady(signer, body, expectedIdentity)
destroyFinalExitReadySigner(signer)
destroyRelayIdentitySigningAuthority(identityOwner)
```

The owner copies and validates the secret once, derives the public identity
internally, and zeroizes its copy on destroy. Consumers accept only the exact
registered message ID, signature domain, body length, and expected identity,
then verify the produced 64-byte signature before returning it. LINK_OFFER,
TAIL_READY, and DHT_EXIT_READY signers are spent after one semantic object. The
extension responder signer follows exactly LINK_ACCEPT then redacted proof and
is spent after the second signature. Retries reuse cached semantic bytes and do
not spend another signer.

Expected RED: raw secret-key options are still required, the wrong domain/body
signs, or a signer is reusable. Implement the signer module only after these
tests fail correctly. Defer the initiator LINK_OFFER caller migration in
`guard-link.js` until Step 8a supplies an honest production admission; finish
and exercise that migration in Step 5b. The extension-responder caller migrates
in Step 8a. The final-exit READY caller migrates in Task 7 Step 3. At
completion, neither `createExtensionLinkOffer`, the extension responder, nor
final-exit activation may receive raw identity secret keys.

Run:

```bash
$NODE node_modules/brittle/bin/node.js test/private/relay-identity-signer.js
```

- [ ] **Step 5: Add the request-bound relay dial and adjacent-link factory**

**Step 5a — correct receiver cleanup and implement dial/factory lifecycle**

Begin in `test/private/extension-setup-channel.js` with a focused RED case for
the existing `takeExtensionResponse` ownership bug: a truthy malformed result
from `takePhysicalChannel()` must leave the owned `physicalChannel` local null
and run the receiver's registered destructor. A valid candidate must be
destroyed on every later non-transfer path. Make it GREEN by storing the return
in a temporary candidate and assigning the owned local only after the existing
nominal channel check. This is a prerequisite to the factory cleanup contract
and changes no wire bytes or API.

In `test/private/guard-link.js`, add failing tests for the unchanged relay-only
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

The callback contract is exactly
`dial(socketOwner, canonicalEndpoint) // Promise<ExtensionResponseReceiver>`;
`destroy()` is synchronous and takes no arguments. Require a genuine Promise.
A synchronous throw is a dial failure. Any synchronous non-Promise is a
contract violation; if it is a live `ExtensionResponseReceiver`, consume it
with `destroyExtensionResponseReceiver`, and do not read any property or method
from any other malformed return. The Promise may fulfill only with the existing
opaque receiver. Add no setup-transport interface.

Construction creates one private linear `SocketOwnerLease` containing
`{ socketOwner, onceDestroy }`. `onceDestroy` solely owns the supplied
destructor, suppresses its exception, and is spent once. Receiver and physical-
channel cleanup is separate. During `DIALING`, pass only a temporary non-owning
`socketOwner` reference, retained until settlement; that loan may initiate
exactly one connection. After install, the reference may remain only in the
receiver/channel graph while the graph is co-owned and atomically
co-transferred with the lease. The graph never owns or invokes `onceDestroy`,
and every failure destroys the graph before spending the lease.

All inputs remain exact own data with no accessors or extra keys. The factory
creates its operation synchronously and privately binds the authority to that
operation's exact `wallNow`/`monotonicNow` identities and retained
`localDeadline`. On the first call, move `UNUSED -> DIALING` and permanently
tombstone reuse before option inspection, verification, either clock,
scheduling, or `dial`. Reserve one process-global pending-offer lease before
external or cryptographic work; preserve `MAX_PENDING_OFFERS = 4096`.
Re-verify the canonical signed advertisement, digest, required role,
`wallNow() < wireExpiresAt <= advertisement.expiresAtMs`, exact retained
deadline, clock identities, and `localDeadline > monotonicNow()`. Recheck
generation identity, liveness, and both deadlines after every external or
reentrant operation.

Only after those checks, decode one fresh 19-byte canonical-endpoint copy.
`dial` receives a read-only loan of that exact buffer until Promise settlement
and may contact only it—no DNS, fallback, alternate candidate, discovery, or
retry target. The callback may not retain it after settlement. Its settlement
capsule clears it exactly once. The callback must settle by the retained local
deadline and socket-owner destruction must drive cancellation settlement, but
cleanup must remain bounded and correct when it does neither.

Before a genuine Promise exists with settlement handlers attached, the
pre-Promise terminal/failure owner must detach and tombstone the operation and
cancel any armed timer. Once any synchronous endpoint/socket-owner loan has
ended, destroy any live direct-return receiver, spend `SocketOwnerLease`, clear
the endpoint, and release the acquired pending-offer lease, in that order.
Return the applicable normalized error only after cleanup. Do not create
quarantine without a genuine Promise and attached settlement handler. If
reentrant termination occurs while `dial` is on the stack and it then returns a
genuine Promise, attach the handler and apply the unsettled-Promise quarantine
rule before releasing any loan-coupled owner. Add RED cases for synchronous
throw/non-Promise, a live direct-return receiver, terminal reentry from `dial`,
timer cancellation, ordered cleanup after both loans end, direct slot release,
destructor throw/reentry, and the absence of an unhandled settlement or
quarantine record.

Add separate RED cases proving:

1. the first call spends authority even when malformed, throwing, rejected,
   invalidly fulfilled, expired, aborted, or destroyed, and reservation occurs
   before verification, crypto, dial, or scheduling callbacks;
2. a later-but-still-future deadline or alternate clock identity fails, no
   endpoint copy exists before all checks pass, and only the exact endpoint loan
   reaches `dial`;
3. Promise settlement alone does not commit: the handler validates the receiver
   and still-`DIALING` generation/deadlines, invokes no external callback
   between final check and the atomic install of `{ receiver,
pendingOfferLease, socketOwnerLease }`, then marks the authority
   `TRANSFERRED`;
4. abort, destroy, or local/wire expiry while a genuine dial Promise is
   unsettled wins by detaching and tombstoning first, moving
   `{ pendingOfferLease, endpointSettlementCapsule }` to globally counted
   late-settlement quarantine, spending `socketOwnerLease`, and rejecting the
   outer open with `ERR_DESTROYED` for abort/destroy or the existing expiry
   error;
5. abort, destroy, or local/wire expiry after underlying settlement but before
   the fulfillment handler's install commit also wins and destroys the
   uninstalled receiver, while those transitions after install use normal
   factory-operation cleanup;
6. settled genuine-Promise rejection/invalid fulfillment or failed handler
   validation detaches first, destroys any live receiver, spends the
   socket-owner lease, clears the endpoint, and releases the pending-offer
   lease exactly once; synchronous throw/non-Promise instead uses the
   pre-Promise owner above;
7. a quarantined late rejection is consumed; a late valid receiver is destroyed
   and never installed; either settlement clears the endpoint, releases the
   counted lease, deletes the quarantine record, and cannot mutate factory
   state;
8. a never-settling callback permanently occupies one counted
   `MAX_PENDING_OFFERS` slot so threshold-plus-one fails closed without
   uncounted buffers or handlers;
9. destructor throw and reentry are suppressed, tombstones make repeated
   abort/destroy no-ops, and all failure paths destroy receiver/channel state
   before spending `SocketOwnerLease`; and
10. post-invocation non-destroy failures normalize to `ERR_ROUTE_UNAVAILABLE`
    only after cleanup, while caller-shape violations remain `INVALID_ROUTE`.

Successful install transfers the still-counted pending-offer lease to the live
factory. A pre-Promise failure releases it directly through the pre-Promise
owner after the synchronous endpoint loan ends. A settled genuine-Promise
failure releases it during settlement cleanup; an unsettled genuine Promise
transfers it with the endpoint capsule into counted quarantine. Never
unconditionally release the reservation while callback code may still run.

Construct the adjacent factory in this substep, but do not invent a test-only
admission issuer. A terminal-completion attempt atomically detaches the pending
operation, moving `{ receiver, socketOwnerLease }` into its terminal-attempt
owner, and releases the pending-offer lease before validating completion
options or calling `takeExtensionResponse`, matching `completeExtensionLink`.
On every pre-transfer failure, `finally` destroys whichever receiver or taken
physical channel that owner holds and only then spends the lease. Successful
take atomically replaces the receiver with `{ physicalChannel,
socketOwnerLease }` in a factory-local post-take owner. Later
validation/proof/derivation/establishment failure destroys the channel or
derived/established link before spending the lease. Only fully validated
established material moves with the lease into `createExtensionLinkCompletion`;
completion destruction destroys the link and then spends the lease once.

Only the already-bound factory may invoke the dial authority, and
`dialRelayAdvertisement` resolves to factory code only after the install
commit. Endpoint code receives no tuple, endpoint bytes, socket owner, owner
lease, dial function, receiver, physical channel, DNS/bind/`trySend`/connect
capability, or alternate-dial authority. The factory resolves only
`ExtensionLinkCompletion`.

Pause Step 5 after 5a, implement Step 8a's real authenticated admission producer
and one-shot consumer, then resume here. This split does not renumber Task 6.

**Step 5b — consume honest admission and run the exact link exchange**

Add RED tests for the unchanged factory surface:

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

`open` permits one live operation and synchronously consumes the ordinary
`AdmittedExtendRequest` through `takeAdmittedExtendRequest` before its first
await. Exercise the real Step 8a admission path; do not add a test-only issuer.
Finish the deferred initiator LINK_OFFER signer migration here, then perform the
exact LINK_OFFER/LINK_ACCEPT/redacted-proof exchange. Every offer, accept,
proof, retry, timer, and completion carries the minimum authenticated
`wireExpiresAt` and current actor's retained `localDeadline`; check both before
and after every external or reentrant operation, and only preserve or shorten
them. Add RED cases for expiry at every nested stage and for retry/completion
attempts to extend either bound.

During the exchange, the operation owns `{ receiver, pendingOfferLease,
socketOwnerLease }`. Abort, destroy, expiry, or exchange failure first detaches
and releases the pending-offer lease, then destroys the receiver or already-
moved channel, and finally spends the socket-owner lease. The factory exposes
none of the authority listed above.

Expected RED across 5a/5b: early channel assignment leaks receiver ownership;
the callback accepts a direct receiver/non-Promise; settlement is mistaken for
install commit; abort or expiry releases an unsettled reservation; late
settlement mutates factory state; never-settling callbacks accumulate outside
the global bound; endpoint code observes dial authority; admission is taken
after an await; a later deadline is substituted; a nested stage survives
expiry; or post-take failure drops either owner.

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
  ;(advertisement,
    adjacencyAdopter,
    extensionResponderSigner,
    responderRouteEncryptionSecretKey,
    wallNow,
    monotonicNow,
    schedule,
    cancelScheduled,
    offerReceiver,
    randomBytes)
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

- [ ] **Step 7: Build the stable TailControl owner, lifetime, and authenticated borrower**

- [ ] **Step 7a: Write the failing lifetime/transport/session authority tests**

In `test/private/tail-control.js` and
`test/private/m3-adjacency-runtime.js`, retain Step 1's exact codec/vector
cases, then construct a session only by consuming a Task 5-registered M3 tail
capability. Add RED cases proving one empty `TailControlOwner` and the
object-identical `M3TailLifetime`/M3 borrower survive current session ->
client-waiting-ready -> successor session through both extensions.

The session object exposes exactly five methods:

```js
session.sealExtend(options)
session.openExtended(envelope)
session.completeClientExtension(completion, readyEnvelope)
session.abortClientExtension(completion)
session.takeFinalExitHandoff()
```

The package-private direct consumers are functions, never session methods:

```js
takeAdmittedExtendRequest(capability)
completeClientTailExtension(completion, readyEnvelope)
abortClientTailExtension(completion)
readTailControlDeadline(session)
destroyTailControlSession(session)
borrowTailControlTransport(session)
```

Reject `.destroy()`, responder methods, structural
`tailControlTransportFactory`, a raw transport, alternate `ownerDestroy`,
replacement lifetime/borrower, and deadline/timer reset. In Step 7, exercise
only the stable owner stages reachable before responder installation,
forwarding, and final-exit activation:

```text
UNBOUND
CONSTRUCTING_SESSION
ACTIVE_SESSION
WAITING_READY_SESSION
CLIENT_WAITING_READY
DESTROYING
DESTROYED
```

Move the stage-specific RED cases for `RESPONDER_INSTALLING` to Step 8b,
`RESPONDER_FORWARDING_TRANSFER` to Step 9, and `FINAL_EXIT_HANDOFF`/
`FINAL_EXIT_ACTIVATION` to Step 11.

Run:

```bash
$NODE node_modules/brittle/bin/node.js test/private/tail-control.js test/private/m3-adjacency-runtime.js
```

Expected RED: session construction can use structural transport, the spent tail
capability is the only cleanup path, logical expiry closes the physical link,
the five-method shape is not exact, or transfer creates a new owner/lifetime/
borrower/deadline.

- [ ] **Step 7b: Implement stable ownership and authenticated tail transport**

`tail-control.js` creates one lexical stable `ownerDestroy` closing over the
empty `TailControlOwner`; no caller supplies it. Immediately after
`takeM3TailCapability`, store every moved field, the `M3TailLifetime`, and the
opaque `M3TailControlTransportOwner` under `CONSTRUCTING_SESSION` before any
further clock, crypto, validation, or callback. Publication rechecks lifetime,
owner generation, and deadline before entering ACTIVE or WAITING_READY.

`createTailControlSession(capability, options)` accepts common `wallNow`,
`monotonicNow`, and optional deterministic `crypto`; an initiator additionally
requires RouteManager's `absoluteDeadline`. It verifies the retained clock
identities, never projects again, and calls `shortenM3TailLifetime` to clamp
both moved wire/local bounds without replacing the timer owner.
`readTailControlDeadline` returns only the actor-local monotonic deadline.

Use only the M3-owned transport operations:

```js
sendM3TailControl(owner, envelope1101)
receiveM3TailControl(owner)
takeM3ReceivedEnvelope(owner, envelope)
releaseM3ReceivedEnvelope(owner, envelope)
releaseM3TailControlTransport(owner)
```

`borrowTailControlTransport(session)` returns a frozen send/receive-only facade.
Every call checks owner/lifetime/runtime generation and deadline before producer
entry and after settlement. Send reserves one Task 5 cell before advancing the
semantic counter, seals one exact 1,101-byte envelope, and commits one
1,200-byte CONTROL cell; seal failure aborts reservation, while post-seal
commit failure spends the counter and destroys the logical owner. Receive uses
the exact record dispatch reservation. After M3 open, move the full-cell charge
into an opaque `M3ReceivedEnvelope`; decoding paths must take that exact object
and release it in `finally`. A structurally equal buffer is invalid.

Initiators reserve both ordered `EXTENDED_V1` and `TAIL_READY_V1` receives
before sending `EXTEND_REQUEST_V1`; responders keep exactly one EXTEND receive
and renew only after settlement. Preserve Task 5's four/shared and
one/non-shared borrower limits, two/one receive limits, and full-cell receipt/
envelope accounting. Logical release rejects pending work and returns every
charge/slot without closing the shared guard physical link.

- [ ] **Step 7c: Implement exact initiator sealing and prove GREEN**

Add one RED-then-GREEN case per exact `sealExtend` own-data field:

```js
{
  ;(advertisement,
    advertisementDigest,
    extensionIndex,
    requestedLimits,
    absoluteDeadline,
    randomBytes)
}
```

The session owns branch/circuit/generation/current-tail bindings. Verify next
index/role, canonical advertisement/signature/digest, payload parameters,
wire expiry, and local bound before allocation. Generate fresh client-tail
ephemeral and extension nonces, retain one pending extension, and seal the
prototype-exact request. The endpoint deadline is the minimum of RouteManager
absolute deadline, moved session deadline, start + 5,000 ms, manager signed
expiry, and selected-advertisement expiry projected once in this actor.
Requested wire expiry cannot exceed any authenticated or local-budget bound.
Task 3 evidence gains no `selectedEvidenceExpiry`.

Run:

```bash
$NODE node_modules/brittle/bin/node.js test/private/tail-control.js test/private/m3-adjacency-runtime.js test/private/udx-cell-endpoint.js
```

Expected GREEN: exact vectors remain unchanged; the stable owner/lifetime/
borrower and independent logical timer move without a gap; exact UDX
reservation and accounting paths are used; destroy/expiry/reentry tombstone
first, release logical ownership once, and leave no physical-close authority
on shared guard sessions.

- [ ] **Step 8: Co-locate token-gated responder transitions with stable session ownership**

Keep responder mutation beside `SESSIONS` and `TAIL_CONTROL_OWNERS` in
`tail-control.js`; add no responder method to the five-method session and
re-export nothing from HyperDHT's entry point. Preserve this package-private
surface:

```js
createTailControlResponderAuthority(session, responderToken, options)
admitTailExtend(authority, envelope)
openTailAdjacentLink(authority, admitted)
completeTailExtend(authority, completion)
abortTailExtend(authority)
sealTailReady(authority)
destroyTailControlResponderAuthority(authority)
```

At indices 0/1 the exact own-data options are
`{ adjacencyAdopter, extensionCommitter, adjacentLinkFactory, tailReadySigner,
wallNow, monotonicNow, randomBytes, schedule, cancelScheduled }`. At terminal
index 2 the first three extension keys are forbidden; only the signer, clocks,
randomness, scheduler, and canceller remain.

Execute Step 8 around Step 5b in this exact order: 8a RED/GREEN -> 5b
RED/GREEN -> 8b RED/GREEN. Do not renumber and do not create a test admission
issuer.

- [ ] **Step 8a: Construct the real authority and publish authenticated admission**

First add RED cases in `test/private/tail-control.js` proving authority
construction atomically consumes the responder token and requires object
identity for its hidden tail binding, deadline object, `M3TailLifetime`,
stable `ownerDestroy`, responder session, and local relay. It must validate
exact options/clock identities and arm one subordinate authority timer at the
already-projected local deadline before return. Initiator adoption has no
token. A deep import without the exact token grants nothing.

Mismatch, synchronous timer firing, schedule throw, invalid handle, reentrant
cancellation, expiry, or failure to retain the handle destroys session,
lifetime, token/binding, transport owner/borrower, signer/factory/committer
options, and copied bytes once. `adjacencyAdopter` remains borrowed from its
`M3AdjacencyAuthority`: abort its live one-shot adoption but never destroy that
borrowed owner.

`admitTailExtend` first consumes the exact registered `M3ReceivedEnvelope`,
opens ordered tail AEAD, and verifies current branch/circuit/generation/tail,
next index/role, complete canonical advertisement/signature/digest/route
key/endpoint/expiry, payload parameters, requested limits, fresh nonces, and
deadline without discovery. It projects selected/requested wall expiries once
in this responder and must successfully call `shortenM3TailLifetime` before
publishing one opaque `AdmittedExtendRequest`. Store that exact object as the
sole live admission; `takeAdmittedExtendRequest` transfers request bytes,
current-tail identity/digest, and effective deadline once without separately
returning a tuple.

Run:

```bash
$NODE node_modules/brittle/bin/node.js test/private/tail-control.js test/private/m3-adjacency-runtime.js
```

Expected RED: token/session/lifetime mismatch survives, the authority accepts
alternate clocks, a raw buffer can replace the registered envelope, admission
uses discovery or is reusable, the lifetime is not shortened first, or cleanup
reaches shared physical close. Implement only the production token-gated
authority/admission path until this command is GREEN, then return to Step 5b.

- [x] **Step 8b: Finish responder transitions and move authenticated runtime ownership**

Resume only after Step 5b consumes the honest admission synchronously before
its first await and passes. Add RED cases for `RESPONDER_INSTALLING` and each
remaining responder transition reachable in this step. `openTailAdjacentLink`
requires object identity with `liveAdmission`, clears it, advances to
`LINK_OPENING` before external code, and records the exact
`ExtensionLinkCompletion`. The factory internally consumes the advertisement,
contacts only its canonical tuple, and linearly moves established ownership
plus Task 5's `M3CellLinkTransferIssuer`; no downstream module reads
`.destroy`.

`completeTailExtend` clears/spends the exact completion before take, moves the
stable owner and rollback fields to `RESPONDER_INSTALLING`, verifies the
redacted proof and every retained binding, then lets lexical guard-link code
issue `M3AuthenticatedBranchBinding` and call
`registerM3CellLinkTransfer`. Any proof/registration failure revokes binding,
issuer, and unpublished transfer before established-owner destruction. Adopt
the registered transfer only through `adoptM3ResponderLink`, seal the exact
prototype `EXTENDED_V1`, and invoke the committer from an irreversible
installation generation. No callback may re-admit, abort, or publish twice.

Successful non-shared adoption atomically moves the factory's
`SocketOwnerLease` with the exact opaque M3 `physicalOwner` into runtime
destruction ownership before clearing completion material. Shared guard
adoption has no movable physical owner. Registry removal, link close, or
projected physical-runtime expiry destroys runtime/eligible established state
and then spends the lease once. Every pre-publication failure revokes logical
transfer/borrower/slot state, destroys derived/established ownership, and only
then spends the lease; no success path drops or invokes it early.

Implement `abortTailExtend`, `sealTailReady`, and remaining responder
transitions. Authority destroy cancels its subordinate timer before protocol
state. The old authority keeps that timer until the independently armed M3
runtimes own both contexts; successor and terminal authorities keep theirs
until destroy/expiry. Lifetime teardown first tombstones the subordinate,
aborts live admission/open/completion, and then clears token/signer/factory/
committer state.

Run:

```bash
$NODE node_modules/brittle/bin/node.js test/private/tail-control.js test/private/guard-link.js test/private/extension-setup-channel.js test/private/extension-link-completion.js test/private/m3-adjacency-runtime.js
```

Expected GREEN: only the token-bound relay can admit; exact Task 5 issuer +
lexical binding registration precedes adoption; abort/reentry/expiry releases
every logical slot/charge and socket-owner lease once; shared physical
ownership remains in GuardLease; and exact EXTENDED/TAIL_READY vectors and
ordering are unchanged.

- [ ] **Step 9: Publish forwarding through the exact transfer/claim/lease/receipt chain**

- [ ] **Step 9a: Write the failing paired-capability and rollback tests**

In `test/private/tail-extension-committer.js`,
`test/private/tail-control.js`, and
`test/private/m3-adjacency-runtime.js`, first add RED cases for the exact
tail-control transfer surface:

```js
takeTailForwardingTransfer(transfer, publicationClaim)
revokeTailForwardingTransfer(transfer)
commitTailForwardingTransfer(taken, publication)
destroyTakenTailForwardingTransfer(taken)
```

`completeTailExtend` must emit one exact frozen own-data event payload:

```js
{
  ;(transfer, publicationClaim)
}
```

Require the object-identical pair, no extra keys/accessors, and synchronous
registry take before the event handler returns. Reject missing, swapped,
foreign, replayed, or retained pair members. Cover handler throw/cancel before
take; wrong/replayed lease; lifetime/callback/borrower/clock/deadline mismatch;
failure before and after runtime publication; publication-receipt or commit
failure; expiry/reentry at each boundary; and exact two-runtime/two-slot
rollback before a facade is retained.

Run:

```bash
$NODE node_modules/brittle/bin/node.js test/private/tail-extension-committer.js test/private/tail-control.js test/private/m3-adjacency-runtime.js
```

Expected RED: the provisional facade-only transfer has no publication claim,
lease, pair identity, receipt, moved-borrower ownership, or failure-atomic
rollback.

- [ ] **Step 9b: Implement exact forwarding ownership and publication**

Add the stage-specific RED case for `RESPONDER_FORWARDING_TRANSFER` here: no
earlier step may create or test this stage before the committer and forwarding
lease exist.

`TailExtensionCommitter.install()` stages exact `EXTENDED_V1`, calls
`beginM3Install`/`validateM3Install`, and receives one empty
`M3ForwardingPublicationClaim` plus the existing frozen
`{ diagnostics, destroy }` facade. The claim binds the install plan,
previous/next runtimes and reservations, both exact borrowers/physical
policies, clocks/deadlines, pending internal `M3ForwardingOwner`, and facade.
The committer moves claim/facade into `tail-control.js`; it publishes neither.

While the stable owner is `RESPONDER_INSTALLING`, `tail-control.js` invokes:

```js
createM3TailForwardingLease(transportOwner, lifetime, ownerDestroy, publicationClaim)
```

This atomically tombstones send/receive borrow facades and moves the predecessor
borrower out of `M3TailControlTransportOwner` into one empty
`M3TailForwardingLease` without unregistering it or disarming/releasing the
logical lifetime. The lease binds lifetime/callback, transport owner, moved
predecessor borrower, next-runtime borrower, both runtime reservation/
generation identities, clock/deadline, and claim. Failure restores nothing:
revoke the unpublished install and destroy the stable owner.

Only `tail-control.js` creates `TailForwardingTransfer`, binding stable owner/
generation, `RESPONDER_FORWARDING_TRANSFER`, lifetime/callback, lease, exact
claim, facade, and rollback state. Take tombstones transfer, advances owner
generation, and returns exactly:

```js
{
  ;(tailControlOwner, m3ForwardingLease, publicationClaim, forwarding)
}
```

The first three values are empty opaque capabilities; `forwarding` is only the
exact facade and owns neither lifetime nor borrower.

The runtime registry then uses only:

```js
publishM3TailForwarding(publicationClaim, m3ForwardingLease, forwarding)
takeM3TailForwardingPublication(publication, m3ForwardingLease, publicationClaim)
revokeM3TailForwardingLease(m3ForwardingLease)
destroyM3TailForwardingPublication(publication)
```

Publication verifies claim/lease/facade, pending runtime records,
lifetime/callback, and both borrowers. Require
`previous.clockIdentity === next.clockIdentity === lifetime.clockIdentity` and
prove
`min(previous.localDeadline, next.localDeadline) <= lifetime.localDeadline`;
clock mismatch or an unprovable bound fails—no optional retention fallback.
With no allocation, clock, crypto, or callback remaining, atomically point both
runtimes and borrowers/physical owners at the pending `M3ForwardingOwner`, then
return one opaque publication receipt.

`commitTailForwardingTransfer(taken, publication)` tombstones the taken record
and advances owner generation before consuming that receipt with the exact
lease/claim. Only after the M3 owner holds both borrowers does commit call
`releaseM3TailLifetime` and clear `M3TailControlTransportOwner` without
`releaseM3CellBorrower`; the predecessor borrower already moved. The registry
may retain/publish the facade only after commit returns.

- [ ] **Step 9c: Prove terminal ownership and every rollback GREEN**

Revoke before take destroys claim/lease/facade and stable owner. Any take,
publish, receipt, or commit failure runs
`destroyTakenTailForwardingTransfer` in `finally`: tombstone stable owner first,
destroy unpublished/published runtime pair, release both borrower slots once,
cancel logical lifetime, clear pair records, and zeroize rollback state.
Registry removal or either physical-runtime expiry consumes the internal owner,
cancels both handles, destroys both sides, and releases both borrowers. Never
export the internal owner or claim synchronous cleanup on another machine.

Run:

```bash
$NODE node_modules/brittle/bin/node.js test/private/tail-extension-committer.js test/private/tail-control.js test/private/m3-adjacency-runtime.js
```

Expected GREEN: exact pair is taken synchronously, publication owns both
registered borrowers before the receipt commits stable-owner release, no moved
borrower is released early, every failure returns both slots/charges exactly
once, and facade publication occurs only after commit.

- [ ] **Step 10: Move RouteExtension through selected evidence and the existing borrower**

- [ ] **Step 10a: Write the failing clean-cutover request-shape tests**

In `test/private/route-extension-session.js`, add RED cases around the existing
Task 3 evidence transaction. The exact own-data request is:

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
  tailControl
})
const session = new RouteExtensionSession(request)
const transfer = await session.open()
const next = takeRouteExtensionTransfer(transfer)
```

Reject accessors, inherited/omitted/extra fields, legacy `now`,
`tailControlTransportFactory`, raw transport, endpoint/dial callbacks,
`.destroy()`, a test issuer, discovery service/query state, and
`selectedEvidenceExpiry` before retaining input.

Run:

```bash
$NODE node_modules/brittle/bin/node.js test/private/route-extension-session.js test/private/tail-control.js
```

Expected RED: the provisional request still requires a transport factory or
structural transport, can replace the stable borrower/deadline, or publishes a
successor before authenticated READY.

- [ ] **Step 10b: Implement selected-evidence initiation without new ownership**

Consume only:

```js
consumeSelectedRelayEvidence(selection, {
  transaction,
  branchClass,
  position,
  generation
})
```

This returns complete owned advertisement bytes/digest and role/index metadata,
with no independent evidence expiry or dial authority. Index 1 requires a
safety relay; index 2 requires a DHT exit; no third extension exists.
`signedExpiry` is manager-owned current-branch wire expiry and may only shorten
the authenticated tail lifetime.

Obtain the already-bound transport only through
`borrowTailControlTransport(tailControl)`. Reserve the two ordered reverse
receives before sending prototype-exact `EXTEND_REQUEST_V1`, then await/open
`EXTENDED_V1` and retain one opaque client completion without publishing a
successor. Only exact registered `TAIL_READY_V1` may atomically call lexical
`createTailControlSessionFromOwnedMaterial`.

The one-shot RouteExtension transfer moves the ACTIVE successor session and
its object-identical send/receive borrower. It must also move, not recreate,
the same stable owner, armed `M3TailLifetime`, clock identity, wire/local
deadlines, transcript, keys/nonces, and counters. The lifetime timer stays
armed across `takeRouteExtensionTransfer`; no transfer/publication gap exists.
Task 9 synchronously takes the transfer into its pre-created draft owner and
calls `destroyTailControlSession` in `finally` on every pre-publication failure.

Destroy, abort, expiry, authentication failure, or READY rejection tombstones
session/manager cancellation first, aborts client completion, destroys staged
successor state, releases only the failed logical borrower/slot/charges, leaves
the shared pinned-guard physical link open, leaves Task 9's transaction owner
to abort directory reservation, and zeroizes all owned semantic/secret bytes.

- [ ] **Step 10c: Run the focused GREEN proof**

```bash
$NODE node_modules/brittle/bin/node.js test/private/route-extension-session.js test/private/tail-control.js test/private/udx-cell-endpoint.js
```

Expected GREEN: selected evidence drives only authenticated current-tail IO,
both receive reservations precede send, valid READY moves the original owner/
lifetime/borrower without reset, invalid READY returns exact zero logical
accounting, and no structural/dial/discovery authority is reachable.

- [ ] **Step 11: Gate TAIL_READY and bridge the same owner into final-exit activation**

- [ ] **Step 11a: Write the failing READY, handoff, claim, and cleanup tests**

In `test/private/tail-control.js`,
`test/private/final-exit-handoff.js`, and
`test/private/final-exit-activation.js`, first add RED cases proving
`sealTailReady(authority)` succeeds only after the successor owns the adopted
runtime and can process authenticated control. It uses only its bound
TAIL_READY signer/randomness, returns one owned exact M3 envelope, and moves
`WAITING_READY -> ACTIVE`. Indices 0/1 may admit one extension; index 2 may
only create final handoff. Before valid READY, no endpoint successor,
application-send authority, activation owner, or directory commit exists.

After index-2 readiness, `session.takeFinalExitHandoff()` must tombstone the
session and move the same stable owner/lifetime to `FINAL_EXIT_HANDOFF`.
The opaque one-shot handoff owns the exact 290-byte transcript, shared secret,
finalize keys/nonces, initiator flag, wire expiry, local deadline, and clock
identity; the M3 borrower/destructor remains inside the stable owner. It cannot
cross processes or expose raw transport/physical destructor.

Add claim create/revoke/replay, foreign handoff/owner, lifetime/callback/clock/
deadline/generation mismatch, reentrant prepare, expiry between prepare and
commit, commit failure, handoff revoke, and destruction initiated from either
module. Every case must prove the same owner, lifetime, clock, deadline, and
borrower move—never replacement state.

Run:

```bash
$NODE node_modules/brittle/bin/node.js test/private/tail-control.js test/private/final-exit-handoff.js test/private/final-exit-activation.js
```

Expected RED: handoff consumption bypasses an activation claim, resets the
lifetime/deadline, exposes transport/destructor, or either module can remain
live after the other is destroyed.

- [ ] **Step 11b: Implement the fixed final-activation ownership bridge**

`final-exit-activation.js` alone issues activation capabilities:

```js
createFinalExitActivationClaim(handoff)
claimFinalExitActivation(handoff, claim)
revokeFinalExitActivationClaim(claim)
destroyFinalExitActivationOwner(owner)
reserveFinalExitActivationOwner(owner)
consumeFinalExitActivationOwnerReservation(reservation, owner)
revokeFinalExitActivationOwnerReservation(reservation)
```

Creation accepts only the opaque handoff identity, permits one live claim, and
creates paired empty `FinalExitActivationClaim`/
`FinalExitActivationOwner` WeakMap records. The claim starts UNBOUND and is
one-shot. Neither capability contains a destructor, callback, handoff field,
clock, key, or transport; neither is a package-entry export.

Because `TAIL_CONTROL_OWNERS` remains lexical, claiming coordinates only
through this fixed tail-control bridge:

```js
prepareTailControlFinalExitActivation(handoff, activationOwner)
commitTailControlFinalExitActivation(transfer, activationOwner)
revokeTailControlFinalExitActivation(transfer)
destroyTailControlFinalExitActivation(tailControlOwner, activationOwner)
```

`claimFinalExitActivation` validates exact handoff/claim identity, spends the
claim, detaches its paired owner, and calls prepare. Prepare requires the live
handoff, `FINAL_EXIT_HANDOFF`, owner generation, object-identical lifetime and
`ownerDestroy`, wire/local bounds, clock identity, and
`monotonicNow() < localDeadline`. Before cross-module calls it removes the
handoff slot, advances owner generation, sets a non-reentrant claiming flag,
tombstones old consumers, and reserves the exact module-issued activation
owner.

Prepare consumes the one-shot handoff and returns only frozen
`{ transfer, material }`. The empty transfer binds stable owner/generation,
lifetime/callback, activation owner/reservation, claimed handoff, and rollback;
material is the already-owned final-exit material, with no new timer,
deadline, transport, key, or destructor.

Claim installs material into its still-live paired owner, then commit rechecks
all identities/deadline, consumes the reservation, removes claiming state, and
moves the stable stage to `FINAL_EXIT_ACTIVATION` with that exact owner as sole
consumer. Claim returns only the activation owner. Keep the existing lifetime
timer armed; Task 7 reuses `localDeadline` and uses `wireExpiresAt` only for
authenticated transcript comparison.

- [ ] **Step 11c: Prove bidirectional destruction and READY vectors GREEN**

Claim revoke destroys the unbound paired owner. Any post-take failure revokes
the tail transfer/reservation and destroys the activation owner in `finally`.
Both modules tombstone before cross-module cleanup. Lifetime/runtime teardown
resolves only the current claim transfer or exact activation owner; activation
destroy calls the fixed tail-control destructor with paired identities. Every
path releases logical borrower/slot/charges once without shared physical close
and zeroizes handoff/material.

Run:

```bash
$NODE node_modules/brittle/bin/node.js test/private/tail-control.js test/private/final-exit-handoff.js test/private/final-exit-activation.js test/private/m3-adjacency-runtime.js
```

Expected GREEN: exact TAIL_READY bytes/order remain frozen; only READY creates
handoff; prepare/claim/commit move the original stable state with no timer gap;
expiry/revoke/failure/reentry from either module leaves zero claim, transfer,
owner, borrower charge, timer, or secret state.

- [ ] **Step 12: Prove the full guard -> middle -> DHT-exit authority chain and cleanup**

- [ ] **Step 12a: Write the failing real-transport integration**

Create `test/private/route-extension.js` from the production owners. Feed Task
3 selected evidence into the endpoint's authenticated current tail, and create
every adjacency through real Task 5 OPEN-record issuer + lexical guard-link
binding + registration + M3 adoption. No fake issuer, structural channel,
transport factory, raw socket, or arbitrary destructor is allowed.

Build guard -> middle, then middle -> DHT exit under independent actor clocks
and fresh nonces. Assert the only post-pin semantic stages remain:

```text
EXTEND_REQUEST_V1 -> LINK_OFFER/LINK_ACCEPT -> EXTENDED_V1 -> TAIL_READY_V1
```

The current tail contacts exactly the tuple in the authenticated advertisement;
the endpoint direct-send trap remains untouched. Scan and trap
`RELAY_DISCOVER_V1`, `RELAY_DISCOVER_RESPONSE_V1`, random targets, DNS,
enumeration, and any Task 9 `BranchPathAuthority` dependency in
`route-extension.js`, `tail-control.js`, or `guard-link.js`.

Before valid READY, staged relay contexts may carry only tail-control cells:
assert no endpoint successor/application authority, activation owner, or
directory commit. Then prove the same stable owner/lifetime/authenticated
borrower survives both client extensions and the final-exit claim bridge, while
relay forwarding publishes only through exact
`{ transfer, publicationClaim }` -> lease -> publication receipt -> commit.

Run:

```bash
$NODE node_modules/brittle/bin/node.js test/private/route-extension.js test/private/guard-link.js test/private/udx-cell-endpoint.js test/private/m3-adjacency-runtime.js test/private/tail-control.js test/private/final-exit-activation.js
```

Expected RED: any production edge still accepts a structural/test transport,
the two capability proofs are not joined, a deadline/timer/borrower is replaced,
publication precedes READY/forwarding receipt/final claim commit, or a
forbidden semantic trap fires.

- [ ] **Step 12b: Add adversarial lifetime, accounting, and rollback coverage**

Exercise wrong issuer/binding/record/tuple/peer/link epoch/M3 generation/
circuit/direction/physical policy; same-counter tail replay; semantic EXTEND
replay; exact lower-link cached duplicate and conflict; wrong roles/proofs;
expired advertisement; dropped setup; cancellation; quota exhaustion;
throwing/reentrant clocks, schedulers, cancellers, destructors, and runtime
registry callbacks; never-settling dial quarantine; observed transport close;
forwarding pair/lease/receipt failure; final-activation prepare/commit races;
and a half-built second extension.

At every boundary assert the universal local destruction order: tombstone live
WeakMaps/owner generation first; tombstone transport/forwarding/final-activation
records; capture and clear timers/borrower/secrets; cancel logical and
subordinate timers; abort admission/completion; call only the package-private
logical release or exact forwarding rollback; clear token/signer/factory/
committer/claim state; then zeroize cells/envelopes/nonces/proofs/transcripts/
keys/counters before `DESTROYED`.

Assert Task 5's 64-packet/76,800-byte global and 8-packet/9,600-byte per-peer
bounds, four/shared and one/non-shared borrower limits, two/one receive
reservations, and every 1,200-byte receipt/envelope charge at every failure.
Logical release preserves the shared pinned-guard physical link; GuardLease
physical close invalidates every attached issuer/transfer/borrower before one
close; non-shared teardown consumes only its moved physical owner.

Installed remote forwarding/adjacency state closes on observed authenticated
transport/context close and in all cases by that actor's projected expiry; do
not claim impossible synchronous remote erasure. Endpoint failure retains only
the pinned guard where specified and never bootstraps/discovers/dials/races a
fallback.

- [ ] **Step 12c: Run the focused integration GREEN**

```bash
$NODE node_modules/brittle/bin/node.js test/private/route-extension.js test/private/guard-link.js test/private/udx-cell-endpoint.js test/private/m3-adjacency-runtime.js test/private/tail-control.js test/private/tail-extension-committer.js test/private/final-exit-handoff.js test/private/final-exit-activation.js
```

Expected GREEN: the real registered UDX/M3 path carries the unchanged four
semantic stages, record dispatch/accounting is exact, stable owner/lifetime/
borrower transfer has no gap, forwarding and final activation commit through
their paired capabilities, and every local failure leaves zero uncommitted
timer/callback/capability/transport/cache/charge/secret immediately.

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
- Modify: `lib/private/final-exit-activation.js`
- Create: `lib/private/open-route-handoff.js`
- Modify: `lib/private/relay-identity-signer.js`
- Create: `test/private/final-exit.js`
- Modify: `test/private/final-exit-activation.js`
- Create: `test/private/open-route-handoff.js`
- Modify: `test/private/relay-identity-signer.js`
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

- [ ] **Step 3: Add failing claim-owned ACTIVATE/READY transition tests**

Task 6 Step 11 must already have created the reviewed
final-activation claim/owner bridge and its tests; if
`lib/private/final-exit-activation.js` or
`test/private/final-exit-activation.js` is absent, resume Task 6 at the stable
TailControl owner/session prerequisite instead of starting Task 7. In
`test/private/final-exit-activation.js`, obtain each actor's session only from
its own claimed activation owner. Freeze two distinct exact own-data shapes.
The endpoint initiator forbids a READY signer:

```js
const initiatorClaim = createFinalExitActivationClaim(initiatorHandoff)
const initiatorOwner = claimFinalExitActivation(initiatorHandoff, initiatorClaim)
const initiatorSession = new FinalExitActivationSession(initiatorOwner, {
  branchId,
  circuitId,
  generation,
  selectedExitAdvertisement,
  wallNow,
  monotonicNow,
  randomBytes,
  schedule,
  cancelScheduled
})
```

The responder DHT exit requires its relay-identity-owned, domain-limited
READY signer:

```js
const responderClaim = createFinalExitActivationClaim(responderHandoff)
const responderOwner = claimFinalExitActivation(responderHandoff, responderClaim)
const responderSession = new FinalExitActivationSession(responderOwner, {
  branchId,
  circuitId,
  generation,
  selectedExitAdvertisement,
  readySigner,
  wallNow,
  monotonicNow,
  randomBytes,
  schedule,
  cancelScheduled
})
```

Each activation owner already owns that actor's same TailControl owner,
`M3TailLifetime`, authenticated borrower, `wireExpiresAt`, `localDeadline`, and
clock identity. The responder-only `readySigner` is one-shot and bound by the
relay identity owner to the exact exit identity, DHT_EXIT_READY message/domain,
and 233-byte READY body. The responder activation owner owns signer cleanup on
success, failure, expiry, and destroy. Neither actor receives a raw identity
secret or arbitrary signing callback.

Reject `readySigner` as an extra key for the initiator; reject an omitted,
foreign, replayed, spent, wrong-identity/domain/body signer for the responder.
For both shapes reject direct `consumeFinalExitHandoff`, `absoluteDeadline`,
`signedExpiry`, ambiguous `now`, alternate clocks, replacement timers/
borrowers, raw handoff material, arbitrary destructors, and raw identity keys.

`schedule(callback, delay)` returns one opaque handle and
`cancelScheduled(handle)` consumes it once while preventing later callback.
Protocol retry handles are subordinate to the activation owner; the existing
M3 logical-lifetime timer remains armed and is never replaced or released.

Test ACTIVATE -> READY between the two actor-specific sessions using the
endpoint's fresh X25519 secret, selected exit advertisement route key, and only
the responder's domain-limited READY signer. READY signing/verification and
every transcript equality must precede ACK availability; signer cleanup must
follow the responder activation owner's tombstone-first path. Substitute each
identity/key/digest/nonce/branch/circuit/generation/owner/lifetime/deadline
binding and assert `ERR_AUTHENTICATION` after both actor-local activation/
stable-owner cleanups and zeroization.

Run:

```bash
npx brittle-node test/private/final-exit.js test/private/final-exit-activation.js test/private/final-exit-handoff.js
```

Expected RED: the provisional constructor has one shared option shape, accepts
`readySigner` on the initiator, accepts a responder without the exact signer,
accepts handoff material directly, reprojects expiry, resets the monotonic
budget, or is not bound to the exact actor-local activation/stable owner pair.

- [ ] **Step 4: Add failing ACK/OPEN, retry, expiry, and owner-race tests**

Continue READY -> ACK -> OPEN. The exit enters OPEN only after ACK; the endpoint
publishes no terminal binding before valid OPEN. The finalization operation may
use only `min(initialActivate + 5_000, moved localDeadline)` in this actor;
`wireExpiresAt` is authenticated transcript comparison, not permission to
project/reset the lifetime. Exact semantic offsets remain 0, 250, 750, 1,750,
and 3,750 ms, but no send may cross the moved deadline.

Add the late-start case: ACTIVATE at 3,500 ms after `GUARD_PINNED` retains only
the 1,500 ms remaining in the already-armed branch lifetime. Retries reuse
semantic bytes under fresh datagram counters; duplicates get only cached next
responses; conflicts/expiry destroy. Cached OPEN and receive-only tombstones
survive at most 5,000 ms after OPEN, capped by moved lifetime/wire bounds, then
retired contexts, keys, and semantic caches erase.

Add expiry before/after claim, between Task 6 prepare/commit, during each
ACTIVATE/READY/ACK/OPEN stage, owner destroy from either module,
revoke-during-retry, destroy-before-offset, suspend at 749 ms, synchronous
timer firing, scheduling throw, cancel reentry, and deadline callback races.
Each must leave zero later send, callback, activation claim/transfer/owner,
borrower charge, timer handle, or secret; shared physical guard ownership stays
outside this cleanup.

Run:

```bash
npx brittle-node test/private/final-exit-activation.js test/private/tail-control.js test/private/m3-adjacency-runtime.js
```

Expected RED: any race publishes terminal state, disarms/replaces the stable
lifetime timer, leaves either module live alone, or releases/closes the moved
borrower/physical link incorrectly.

- [ ] **Step 5: Implement activation on the moved owner and prove inner AEAD GREEN**

Complete the prototype `FinalExitActivationSession` state machine in the Task
6-owned `lib/private/final-exit-activation.js`; do not recreate its claim/
owner bridge. Consume only the exact module-issued activation owner and
revalidate its stable owner generation, lifetime/callback, clock identity, and
deadline before/after each crypto, clock, scheduler, or send operation.

Add `lib/private/open-route-handoff.js` as the package-private consumer,
revocation, and destruction boundary for one terminal OPEN capability. Its
Task 9-facing surface is exactly:

```js
consumeOpenRouteHandoff(handoff)
revokeOpenRouteHandoff(handoff)
destroyOpenRouteMaterial(material)
```

It exports no create/issue operation and accepts no activation owner plus
arbitrary material. `final-exit-activation.js` lexically owns handoff issuance:
only its authenticated OPEN transition may create/register one frozen empty
`OpenRouteHandoff`, after all OPEN authentication, transcript equality,
actor-role, activation/stable-owner, lifetime, borrower, clock, and deadline
checks succeed. `FinalExitActivationSession.takeOpenHandoff()` may consume that
already-proven OPEN state once and return the issued capability; no caller
supplies material, owner, claim, callback, or destructor, and repeated take is
tombstoned.

The hidden handoff record binds the object-identical activation/stable owner,
lifetime/callback, authenticated borrower, clocks/deadlines, branch/circuit/
generation, exit identity, role-scoped inner payload/control material, the
one-shot endpoint OPEN authority transfer slot, and rollback/expiry cleanup.
`consumeOpenRouteHandoff` spends it once and returns only the exact terminal
material, still-charged borrower/slot accounting, endpoint OPEN authority
transfer, and an empty activation-owner transfer for Task 9's pre-created
draft. Revoke takes the exact handoff—not an owner—and Task 9 may only consume,
revoke, or destroy. Revoke, destroy, and failed consume tombstone before
callbacks and release logical borrower/slot/charges once without shared
physical close; successful consume transfers the live charge into the draft.

Add RED cases proving no handoff exists before authenticated OPEN; invalid,
substituted, expired, or wrong-role OPEN cannot issue; deep-imported
`open-route-handoff.js` has no issuer; caller-provided owner/material is
rejected; replayed take/consume/revoke is inert; and activation destruction
reaches any issued-but-unconsumed handoff exactly once.

Add a test that seals one routed payload with the derived terminal payload key,
forwards it unchanged through guard/middle fixtures, and opens it only at the
selected exit. Adjacent relays cannot decrypt/substitute it. Success publishes
only the opaque terminal OPEN handoff; no key bytes, transport borrower,
deadline owner, or destructor is returned to endpoint code.

Run:

```bash
npx brittle-node test/private/final-exit.js test/private/final-exit-activation.js test/private/final-exit-handoff.js test/private/open-route-handoff.js test/private/relay-identity-signer.js test/private/tail-control.js
```

Expected GREEN: exact Task 7 vectors/KDFs/message order remain unchanged;
claim-owned activation reuses the armed lifetime and borrower; valid OPEN alone
creates the one-shot terminal OPEN handoff; every substitution/race cleans both
modules and leaves zero logical accounting.

- [ ] **Step 6: Run both runtimes and commit**

```bash
npx brittle-node test/private/final-exit.js test/private/final-exit-activation.js test/private/final-exit-handoff.js test/private/open-route-handoff.js test/private/relay-identity-signer.js
bare node_modules/brittle/cmd.js test/private/final-exit.js test/private/final-exit-activation.js test/private/final-exit-handoff.js test/private/open-route-handoff.js test/private/relay-identity-signer.js
npm run test:generate
git diff --check
git add lib/private/final-exit.js lib/private/final-exit-activation.js lib/private/open-route-handoff.js lib/private/relay-identity-signer.js test/private/final-exit.js test/private/final-exit-activation.js test/private/open-route-handoff.js test/private/relay-identity-signer.js test/private-routing.js test/all.js docs/private-routing-migration.md
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

- [ ] **Step 1: Prove GuardLease is the sole shared physical owner**

- [ ] **Step 1a: Write the failing shared-link ownership and borrower-limit tests**

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

Use Task 5's real loopback-established `guardLeaseMaterial`. Add RED cases
proving bootstrap pinning already consumed the hidden ownership token and
branded the OPEN record `SHARED_GUARD` before returning that material.
`createGuardLease` consumes and retains the already-branded established
ownership but never brands, chooses, or mutates its policy; it becomes the only
physical close owner.
Each active lookup/announce build, and at most
one unpublished replacement for each, obtains a distinct slot-reserving
`M3CellLinkTransferIssuer` from that same OPEN record. A fifth issuer fails
before allocation/callback.

Take each issuer through the lexical authenticated binding and registered
transfer path. Shared M3 adoption must receive a logical borrower but no
`physicalOwner`. Releasing one/all logical borrowers returns dispatch, receipt/
envelope, packet/byte, and slot charges without emitting link close. Lease
destroy/link loss first invalidates every issuer, unpublished transfer,
reservation, receipt, and active branch borrower, then closes the physical
record/socket exactly once.

Run:

```bash
npx brittle-node test/private/guard-lease.js test/private/udx-cell-endpoint.js test/private/guard-link.js
```

Expected RED: GuardLeaseMaterial has no hidden shared brand, M3 receives shared
physical close authority, more than four slots issue, logical release closes
the guard, or physical close leaves a usable issuer/borrower.

- [ ] **Step 1b: Implement exact pin, scope, suspend, and reconnect ownership**

`guardLossSink` remains an empty controller-issued capability; its internal
publisher records one sanitized event only after lease tombstone and never
invokes caller code synchronously.

Atomically consume `guardLeaseMaterial` and bind exact guard identity/tuple,
advertisement digest/epoch/expiry, SHARED_GUARD established ownership, socket
owner, local-secret capability, reconnect factory, and the separately returned
`pinnedGuard`; mismatch destroys both. RouteManager later uses the imported
internal equality check to match sealed directory scope. The lease neither owns
nor enumerates directory records and exposes only opaque manager capabilities
consumed through package-private `sendToGuard`, `suspendGuardLease`, and
`destroyGuardLease`; no property returns material.

The existing branch-build path asks the live lease to obtain the Task 5 issuer
from its retained OPEN record for each exact active/replacement slot. Slot
identity is tied to branch class/generation inside the issuer/authenticated
binding join; callers never receive established ownership, tuple, policy, or
physical close authority.

`suspendGuardLease` first creates one `GuardReconnectAuthority` by moving the
local-secret capability and zero-argument reconnect factory, then revokes every
issuer/borrower/send capability, closes the shared established link/socket, and
returns reconnect only after zero live UDX/M3 registration or charge remains.
The sealed directory stays controller-owned. Reconnect success creates a fresh
socket/OPEN shared record and one fresh `GuardLeaseMaterial` for the exact same
identity/tuple/digest/epoch/expiry; failure destroys it. Expiry, link loss,
replacement attempt, network change, duplicate destroy, and guard substitution
fail closed without bootstrapping another guard.

- [ ] **Step 1c: Run the focused GREEN proof**

```bash
npx brittle-node test/private/guard-lease.js test/private/udx-cell-endpoint.js test/private/guard-link.js test/private/m3-adjacency-runtime.js
```

Expected GREEN: GuardLease alone retains shared physical ownership; exactly four
logical slots cover active/replacement branches; logical cleanup is accounting-
exact and non-closing; suspend/destroy invalidates every registration before one
physical close and leaves zero socket/send/borrower/timer/secret state.

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

- [ ] **Step 3: Freeze dual-clock factories that move existing tail ownership**

- [ ] **Step 3a: Write the failing dependency-shape and ownership tests**

In `test/private/route-manager.js`, freeze these module-private factories:

```js
const extensionFactory = createRouteExtensionFactory({
  wallNow,
  monotonicNow,
  randomBytes,
  schedule,
  cancelScheduled
})
const terminalFactory = createFinalExitActivationFactory({
  wallNow,
  monotonicNow,
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

Both factories are empty frozen WeakMap capabilities and retain the exact same
clock, callback-first scheduler, and canceller identities used by the
GuardLease/current tail. Reject legacy `now`, alternate clocks, alternate
scheduler/canceller pairs, structural transport/factory objects, caller
callbacks, physical destructors, direct dial authority, and replacement owner/
lifetime/borrower/deadline state.

`route-manager.js` may call only imported package-private
`openRouteExtension(factory, exactOptions)` and
`openFinalExit(factory, exactOptions)`. Extension opens an already-selected
in-route request through the manager's current authenticated tail; remote relay
ownership creates the next adjacency. Terminal open consumes the exact opaque
index-2 `FinalExitHandoff`, internally creates and claims Task 6's
final-activation owner, and drives Task 7 ACTIVATE/READY/ACK/OPEN under the
same deadline/scheduler graph. Only `final-exit-activation.js` may lexically
issue `OpenRouteHandoff` after authenticated OPEN; the manager receives that
capability and may only synchronously consume it into the pre-created draft or
revoke/destroy it. It never issues a handoff, supplies owner/material to an
issuer, consumes raw handoff material/keys, or projects a fresh deadline.

Run:

```bash
npx brittle-node test/private/route-manager.js test/private/route-extension-session.js test/private/final-exit-activation.js
```

Expected RED: factories still accept ambiguous `now`, alternate schedulers, a
structural transport/factory object, raw handoff material, or create a new
timer/lifetime/borrower instead of moving Task 6 state.

- [ ] **Step 3b: Implement the exact private factories and prove GREEN**

Bind factory operations to the manager-owned branch draft, selected evidence,
GuardLease branch slot, absolute construction deadline, exact stable
TailControl owner/lifetime/borrower/clock identities, and object-identical
callback-first scheduler/canceller pair. RouteExtension transfer is taken
synchronously into the draft. Final activation consumes the exact index-2
`FinalExitHandoff`; after authenticated OPEN,
`final-exit-activation.js` lexically issues the terminal handoff and the manager
synchronously consumes it into the draft. Factory cleanup is limited to
`destroyTailControlSession`, `revokeOpenRouteHandoff`,
`destroyOpenRouteMaterial`, or the exact final-activation owner destructor; it
cannot create an OPEN handoff or close shared physical ownership.

Run:

```bash
npx brittle-node test/private/route-manager.js test/private/route-extension-session.js test/private/final-exit-activation.js
```

Expected GREEN: both empty factories accept only the exact dual-clock graph,
perform no discovery/dialing, and carry one stable owner/lifetime/borrower from
the shared guard current tail through extension and terminal activation.

- [x] **Step 4: Port path selection and publish both complete ownership graphs transactionally**

- [x] **Step 4a: Write the failing pair-publication and rollback tests**

Before implementation, add RED cases in `test/private/route-manager.js` and
`test/private/guard-lease.js` around the exact internal methods:

```js
manager.buildInitialPair()
manager.rotate(branchClass)
manager.branchCapability(branchClass)
manager.destroy()
```

For each lookup/announce draft, prove the manager synchronously takes every
RouteExtension transfer and consumes the terminal `OpenRouteHandoff` that
`final-exit-activation.js` issued only after authenticated OPEN. The
object-identical stable owner, armed lifetime, authenticated borrower, clock
identity, and non-increasing deadlines survive both extensions and OPEN.
No draft may issue/synthesize an OPEN handoff, transport, timer, lifetime,
borrower, final claim, arbitrary owner/material pair, or physical owner. Before
consume it may only revoke the exact handoff; after consume it may only destroy
the returned material. Assert shared GuardLease slots remain charged from Task
5 issuer through draft rollback or final branch destruction.

Run:

```bash
npx brittle-node test/private/route-manager.js test/private/guard-lease.js test/private/route-extension-session.js test/private/final-exit-activation.js
```

Expected RED: a draft publishes after structural readiness, resets state between
extension/final activation, commits one branch alone, releases the shared slot
early, or leaks one owner on pair failure.

- [x] **Step 4b: Implement one synchronous pair publication boundary**

Port only narrowed selection/reservation from prototype
`branch-path-authority.js`/`route-manager.js`; exclude simulator/discovery.
Read the guard-pinned timestamp from GuardLease—callers cannot choose a later
start. Reserve the atomic directory pair; consume selected evidence into two
unobservable drafts; obtain exact shared-guard issuers/registered borrowers;
build both extensions and final activations concurrently under the same
deadline; verify both terminal OPEN; then in one synchronous mutation commit
directory reservation, install both fully owned branch slots, and mark ready.
Only afterward may `branchCapability` issue.

Before commit, any failure aborts the directory transaction and destroys both
draft activation/session owners in `finally`, causing each stable owner to
release its logical borrower/dispatch/slot/charges once without closing the
shared guard. After directory commit, impossible publication failure destroys
both committed generations and enters unavailable; never retry that generation
or leave one branch published.

Branch capabilities are empty WeakMap objects exposing no path, address,
borrower, lifetime, timer, or physical close authority. Internal consumers get
only route payload/control authority and owned branch/circuit/generation/
expiry/exit metadata. Revocation tombstones capability and stable branch owner
before transport callbacks, then releases logical borrower accounting.

- [x] **Step 4c: Run the focused transactional GREEN proof**

```bash
npx brittle-node test/private/route-manager.js test/private/guard-lease.js test/private/branch-path-authority.js test/private/route-extension-session.js test/private/final-exit-activation.js test/private/udx-cell-endpoint.js
```

Expected GREEN: pair publication occurs only after both exact ownership graphs
reach OPEN; no owner/lifetime/borrower/clock/deadline is recreated; half-success
returns both branch-build logical slots/charges while preserving the guard
physical link; committed revocation tombstones before callback and leaves no
usable branch authority.

- [x] **Step 5: Add failing make-before-break rotation tests**

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

- [x] **Step 6: Prove suspend and complete teardown**

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

- [x] **Step 7: Run both runtimes and commit**

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

- [x] **Step 1: Add failing minimum/maximum `0x0045` vectors**

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

- [x] **Step 2: Implement strict seed sign/encode/decode/verify**

Create exact exports:

```js
signDhtExitSeeds(value, exitSecretKey)
encodeDhtExitSeeds(value)
decodeDhtExitSeeds(encoded)
verifyDhtExitSeeds(encoded, expected, now)
clearDhtExitSeeds(value)
```

`expected` is exact own data containing branch class/ID, circuit ID, generation,
exit identity, and terminal expiry. Verification performs only canonical,
digest, signature, transcript, class, order, and expiry checks and returns owned
decoded bytes. It does not accept a destination table, endpoint owner, terminal
session, socket, or tuple; assign `CONFIGURED_BOOTSTRAP`; mint a handle; publish
a destination; or claim server-table liveness. Correctly signed seed bytes are
inert until Task 12 consumes them through a terminal-bound admission authority.

- [x] **Step 3: Prove the codec alone cannot publish authority**

Assert none of the exports can mutate Task 1's live endpoint owner. Mutation,
hostile accessors, allocation failure, wrong key/branch/generation, and trailing
data clear every owned copy and leave zero records. Task 12 adds the only
production signing/delivery and atomic admission path after the exit table
exists.

- [x] **Step 4: Run both runtimes and commit**

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
- Modify: `lib/private/open-route-handoff.js`
- Create: `test/private/dht-exit-wire.js`
- Create: `test/private/dht-exit-reservation.js`
- Create: `test/private/dht-exit-io.js`
- Modify: `test/private/open-route-handoff.js`
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
Production never exposes the endpoint session or a direct take path: Task 9's
terminal factory receives the endpoint-side capability only as the opaque
endpoint OPEN authority transfer moved through `OpenRouteHandoff` into the
branch draft. This step updates `open-route-handoff.js` and its tests so
successful handoff consume preserves that one-shot authority while revoke,
destroy, failed consume, or draft rollback spends it before callbacks.

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
npx brittle-node test/private/dht-exit-wire.js test/private/dht-exit-reservation.js test/private/dht-exit-io.js test/private/open-route-handoff.js
bare node_modules/brittle/cmd.js test/private/dht-exit-wire.js test/private/dht-exit-reservation.js test/private/dht-exit-io.js test/private/open-route-handoff.js
npm run test:generate
git diff --check
git add lib/private/dht-exit-wire.js lib/private/dht-exit-reservation.js lib/private/dht-exit-io.js lib/private/final-exit.js lib/private/final-exit-activation.js lib/private/open-route-handoff.js test/private/dht-exit-wire.js test/private/dht-exit-reservation.js test/private/dht-exit-io.js test/private/open-route-handoff.js test/private-routing.js test/all.js docs/private-routing-migration.md
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

- [x] **Step 1: Add failing immutable-get authority tests**

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

- [x] **Step 2: Prove reservation-before-send and negative authority cases**

Authority traps reject an unrecorded PING, immutable get to a probe-only tuple,
valid-tag/missing-entry handle, wrong provenance/generation, expired reference,
transaction exhaustion/collision, and post-cancel request before socket send.
Reentrant rotation after DHT reply correlation but before referral commit aborts
all staged references and emits no routed reply.

- [x] **Step 3: Run focused tests and commit**

```bash
npx brittle-node test/private/dht-exit-wire.js test/private/dht-exit-destination-table.js test/private/dht-exit-io.js test/private/dht-exit-immutable-get.js
bare node_modules/brittle/cmd.js test/private/dht-exit-wire.js test/private/dht-exit-destination-table.js test/private/dht-exit-io.js test/private/dht-exit-immutable-get.js
npm run test:generate
git diff --check
git add lib/private/dht-exit-wire.js lib/private/dht-exit-io.js lib/private/dht-exit-destination-table.js test/private/dht-exit-wire.js test/private/dht-exit-destination-table.js test/private/dht-exit-io.js test/private/dht-exit-immutable-get.js test/private-routing.js test/all.js docs/private-routing-migration.md
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
