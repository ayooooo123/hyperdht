# Private Routing Gate 3A Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents are available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate the verified fixed-cell and typed routed-DHT substrate into the HyperDHT fork and prove an internal `RoutedDHTIO` adapter can drive DHT-RPC's transport-only traversal without creating direct network authority.

**Architecture:** A small, generic DHT-RPC refinement carries one opaque transport context through candidate discovery, requests, retries, and auto-commit. HyperDHT then owns private protocol constants, key derivation, counters, cells, fragmentation, exit policy, routed-DHT codecs, and an internal adapter. The adapter recognizes only module-private query capabilities that bind both the route branch and approved command policy, wraps destination references in unforgeable JavaScript objects, and delegates delivery to an injected route authority. Deterministic tests use a fake authority; no public `privateRouting` option is exposed and no live anonymity claim is made in this slice.

**Tech Stack:** CommonJS JavaScript, Node.js, Bare, `brittle`, `b4a`, `compact-encoding`, `hypercore-crypto`, `sodium-universal`, DHT-RPC transport-only mode, GitHub Actions.

---

## Scope and execution roots

Run commands from:

```text
/Users/jd/Documents/Codex/2026-07-10/task-extract-three-packages-into-standalone
```

Repositories modified by this plan:

```text
dht-rpc-private-routing
hyperdht-private-routing
```

Canonical specification:

```text
hyperdht-private-routing/docs/private-routing-v1.md
```

Verified implementation source, read only:

```text
repository: /Users/jd/.config/superpowers/worktrees/peartube/private-routing
ref: feature/hyperswarm-private-routing-implementation
commit: 0305df915b6a767093f9e75e6c06bc0a35da6169
source root: packages/private-routes
```

The prototype is implementation evidence, not the package boundary. Preserve its MIT authorship through a migration note and file-level source comments. Convert ESM imports/exports to the HyperDHT fork's CommonJS style, retain no-semicolon Holepunch formatting, and use `b4a` for byte buffers.

Whenever a task creates `test/private/name.js`, append exactly `require('./private/name')` to `test/private-routing.js` in the same red-test step, then run both the focused file and the aggregate runner. A focused pass does not count if the aggregate runner omits the file.

This plan is **Gate 3A**, a testable prerequisite to Delivery Gate 3. It does not complete the live three-position route, DHT exit networking, namespace packet oracle, public `privateRouting: { mode: 'required' }` controller, Hyperswarm integration, mobile integration, or PearTube integration. Gate 3B must supply those pieces and prove the post-readiness address-separation guarantee.

## Completion contract

- DHT-RPC direct mode and wire behavior remain unchanged.
- One opaque `transportContext` reference is snapshotted per transport-only query and is delivered unchanged to `closest`, `bootstrap`, every request retry, and auto-commit.
- HyperDHT pins the exact reviewed DHT-RPC fork commit produced by this plan; it does not use a floating branch.
- Fixed-cell dimensions are exactly 1,200-byte cell, 36-byte header, 1,148-byte encrypted body, 16-byte tag, and 1,146-byte outer payload.
- End-to-end route payload is at most 1,073 bytes per cell; a message is at most eight fragments and 8,584 bytes.
- CONTROL and STREAM counters are strictly ordered. DATAGRAM uses a 64-counter replay window. Counter exhaustion fails closed.
- X25519 rejects an all-zero shared secret. The migrated generic KDF separates direction, purpose, transcript bytes, keys, and nonce prefixes. Exact role/branch/circuit/generation transcript construction remains Gate 3B work because its prototype helpers live in route-state modules outside this slice.
- Gate 3A `RoutedDHTIO` encodes only the fully specified immutable-get request body and uses only opaque destination references. Its test authority returns a trusted in-process logical response for structural conformance; no command, including immutable get, is live-wire capable until Gate 3B adds reviewed reply codecs. Every other request command fails closed. No hostname, host, port, socket, or raw address is accepted anywhere in `RoutedDHTIO`.
- The fake authority proves lookup and announce branches remain distinct, unsupported commands fail before candidate discovery, and cancellation reaches the active route operation.
- All migrated known vectors match in Node and Bare.
- Existing HyperDHT Node, Bare, integration, macOS, Linux, and Windows CI remains green.

## Chunk 1: Generic context and verified route core

### Task 1: Carry opaque query context through DHT-RPC

**Files:**

- Modify: `dht-rpc-private-routing/lib/query.js`
- Modify: `dht-rpc-private-routing/lib/request-transport.js`
- Modify: `dht-rpc-private-routing/index.js`
- Modify: `dht-rpc-private-routing/test/request-transport.js`
- Regenerate: `dht-rpc-private-routing/test/all.js`

- [ ] **Step 1: Add failing context-propagation tests**

Append focused tests to `test/request-transport.js` using the existing fake transport helpers. Use two frozen sentinel objects, one per query, and assert:

1. `closest({ target, limit, context })` receives the query's exact sentinel reference.
2. `bootstrap({ target, limit, context })` receives the same reference when closest candidates are insufficient.
3. `request({ ..., context, attempt })` receives the same reference on the first attempt and every retry.
4. auto-commit receives the same reference as the query request.
5. concurrent queries with different sentinels never exchange them.
6. one hostile `transportContext` getter is read exactly once when each transport-only query or standalone request starts.
7. the stored value, not the getter, is reused by discovery, traversal, retries, auto-commit, and auto-commit retries.
8. direct mode does not inspect an accessor named `transportContext` and its existing request encoding is unchanged.

Run:

```bash
cd dht-rpc-private-routing
npx brittle-node test/request-transport.js
```

Expected: the new transport-only assertions fail because context is absent; all pre-existing assertions still pass until the first intended failure.

- [ ] **Step 2: Snapshot context once in `Query`**

In `lib/query.js`, read `opts.transportContext` once during transport-only construction, default it to `null`, and store it as `this.transportContext`. Direct-mode construction stores `null` without reading the property. Do not clone, enumerate, stringify, call, or re-read the object. Pass the explicit stored reference into:

```js
this.dht._closestQueryNodes(..., this.transportContext)
this.dht._resolveQueryBootstrap(..., this.transportContext)
this.dht._request(..., candidate, this.transportContext)
```

In `autoCommit`, pass `query.transportContext` as an explicit final argument to `_queryCandidateRequest`; do not put it back onto an options object.

- [ ] **Step 3: Thread context through transport-only DHT-RPC helpers**

In `index.js`:

- extend `_closestQueryNodes` and `_resolveQueryBootstrap` with a final `context` argument;
- pass `{ target, limit, context }` to the adapter only in transport-only mode;
- read `opts.transportContext` exactly once at the public transport-only `request` entry point, then pass that explicit value through `_transportRequestToPromise`;
- make `_transportRequestToPromise`, `_queryCandidateRequest`, and the transport-only `_request` branch accept an explicit final `context` value and never read it from `opts`;
- pass `Query.transportContext` explicitly through `_visit` and auto-commit, including every retry;
- update every other `RequestTransport.createRequest` caller to pass explicit `null` when no query context exists;
- leave every direct-mode call and direct IO message unchanged.

Do not interpret the context in DHT-RPC. It is an opaque capability owned by the injected adapter.

- [ ] **Step 4: Preserve context across retries and cancellation**

In `lib/request-transport.js`, extend `RequestTransport.createRequest(to, token, internal, command, target, value, session, candidate, context)` and pass the explicit value into a new `TransportRequest` constructor field. Include that stored field in every adapter request:

```js
operation = this._io.adapter.request({
  to: this.to,
  token: this.token,
  internal: this.internal,
  command: this.command,
  target: this.target,
  value: this.value,
  context: this.context,
  attempt
})
```

Do not let retry logic replace or derive the reference. Existing request timeout, response validation, and `cancel(reason)` ownership stay in DHT-RPC.

- [ ] **Step 5: Run focused and full DHT-RPC verification**

```bash
cd dht-rpc-private-routing
npx brittle-node test/request-transport.js
npm run test:generate
npm run lint
npm test
git diff --check
```

Expected: focused tests, formatting, Node tests, and Bare tests pass. If local UDX binding is denied by the Codex sandbox, record the exact `EPERM`, run every non-network focused test locally, and require the fork-native GitHub matrix before proceeding.

- [ ] **Step 6: Commit, push, and verify the fork-native matrix**

```bash
cd dht-rpc-private-routing
git add index.js lib/query.js lib/request-transport.js test/request-transport.js test/all.js
git commit -m "feat: propagate request transport context"
git push origin private-routing-v1
gh run list --repo ayooooo123/dht-rpc --branch private-routing-v1 --limit 5
```

Watch the matching head SHA. Expected: lint and Linux, macOS, and Windows test jobs pass. Record the full commit SHA and workflow URLs in `hyperdht-private-routing/docs/private-routing-baseline.md`.

### Task 2: Pin DHT-RPC and establish the private test runner

**Files:**

- Modify: `hyperdht-private-routing/package.json`
- Create: `hyperdht-private-routing/test/private-routing.js`
- Create: `hyperdht-private-routing/test/private/transport-seam.js`
- Regenerate: `hyperdht-private-routing/test/all.js`
- Modify: `hyperdht-private-routing/docs/private-routing-baseline.md`

- [ ] **Step 1: Add a failing installed-seam test**

Create `test/private-routing.js` as the only root-level aggregator:

```js
require('./private/transport-seam')
```

Create `test/private/transport-seam.js`. Construct base `dht-rpc` in transport-only mode with a complete inert adapter and a frozen context. Assert that `closest`, `bootstrap`, and `request` see the exact reference and that destroy delegates once. Also construct ordinary HyperDHT with its existing direct options and assert `outboundPolicy === 'direct'`.

Run:

```bash
cd hyperdht-private-routing
npx brittle-node test/private/transport-seam.js
```

Expected: fail against the currently installed published `dht-rpc` because the context is absent.

- [ ] **Step 2: Pin the exact green DHT-RPC commit**

Replace only the `dht-rpc` dependency with the full SHA from Task 1:

```bash
cd hyperdht-private-routing
DHT_RPC_SHA=$(git -C ../dht-rpc-private-routing rev-parse HEAD)
test ${#DHT_RPC_SHA} -eq 40
npm pkg set "dependencies.dht-rpc=github:ayooooo123/dht-rpc#$DHT_RPC_SHA"
npm install
```

Inspect `package.json` and confirm it contains the actual 40-character SHA, never a branch name. The repository ignores `package-lock.json`, so do not add it.

- [ ] **Step 3: Generate and run the aggregate tests**

```bash
cd hyperdht-private-routing
npm run test:generate
npx brittle-node test/private/transport-seam.js
node test/all.js
bare test/all.js
git diff --check
```

Expected: the seam test passes in Node and the generated `test/all.js` imports `./private-routing.js`. The unchanged suite remains green subject only to a documented local UDX sandbox restriction.

- [ ] **Step 4: Record the exact dependency evidence**

Add a Gate 3A subsection to `docs/private-routing-baseline.md` containing the DHT-RPC SHA, its green workflow URLs, and the exact GitHub dependency string. Do not describe Gate 3 or anonymity as complete.

### Task 3: Migrate protocol constants and stable errors

**Files:**

- Create: `hyperdht-private-routing/lib/private/errors.js`
- Create: `hyperdht-private-routing/lib/private/protocol.js`
- Create: `hyperdht-private-routing/test/private/protocol.js`
- Modify: `hyperdht-private-routing/test/private-routing.js`

- [ ] **Step 1: Add failing protocol-vector and error tests**

Adapt the assertions from prototype files `test/protocol.test.js` and `test/m3-protocol.test.js`. Cover exact cell enums, branch classes, direction values, protocol versions, message IDs, domain strings, strict object lengths, hostile typed-array accessors, and stable error codes required by the canonical spec.

Run:

```bash
cd hyperdht-private-routing
npx brittle-node test/private/protocol.js
```

Expected: fail because `lib/private/protocol.js` and `lib/private/errors.js` do not exist.

- [ ] **Step 2: Port the reviewed protocol subset exactly**

Port from commit `0305df915b6a767093f9e75e6c06bc0a35da6169`:

```text
packages/private-routes/lib/errors.js
packages/private-routes/lib/protocol.js
```

Retain the following normative values without renumbering:

- `PROTOCOL_VERSION = 0`, `M3_PROTOCOL_VERSION = 1`;
- branch classes `LOOKUP = 0`, `ANNOUNCE = 1`;
- cell classes `CONTROL = 0`, `STREAM = 1`, `DATAGRAM = 2`;
- directions `FORWARD = 0`, `REVERSE = 1`;
- destination, routed request/reply, immutable/mutable, private find-node, and private presence message IDs used by later tasks;
- role domain `hyperdht-private-routes/role/v0` and all KDF domains consumed by this slice.

Convert exports to CommonJS. Keep strict defensive buffer handling and stable error constructors. Add a source comment naming the exact prototype commit.

- [ ] **Step 3: Verify in both runtimes**

```bash
cd hyperdht-private-routing
npx brittle-node test/private/protocol.js
bare test/private/protocol.js
npx prettier --check lib/private/errors.js lib/private/protocol.js test/private/protocol.js
```

Expected: identical vectors and error codes pass in Node and Bare.

### Task 4: Migrate crypto derivation and replay counters

**Files:**

- Create: `hyperdht-private-routing/lib/private/crypto-suite.js`
- Create: `hyperdht-private-routing/lib/private/counters.js`
- Create: `hyperdht-private-routing/test/private/crypto-suite.js`
- Create: `hyperdht-private-routing/test/private/counters.js`
- Modify: `hyperdht-private-routing/test/private-routing.js`

- [ ] **Step 1: Add failing known-vector and adversarial tests**

Adapt all security-relevant assertions from prototype `test/crypto-suite.test.js`, `test/counters.test.js`, and the counter cases in `test/adversarial.test.js`. Do not claim or copy `test/m3-vectors.test.js`: those vectors depend on transcript constructors in `m3-context.js`, `tail-control.js`, and `final-exit.js`, which are deliberately outside Gate 3A. Tests in this task cover:

- deterministic generic transcript-byte and KDF vectors already exposed by `crypto-suite.js`;
- X25519 all-zero shared-secret rejection;
- distinct keys and 16-byte nonce prefixes when direction, purpose label, or caller-supplied transcript bytes change;
- 24-byte nonce construction from prefix plus unsigned 64-bit big-endian counter;
- CONTROL/STREAM exact-next semantics;
- DATAGRAM duplicate, stale, reordering, and 64-counter-window boundaries;
- wrap rejection and owned-secret clearing on teardown.

Run both files and confirm missing-module failures.

- [ ] **Step 2: Port crypto with the existing HyperDHT dependencies**

Port the complete reviewed implementations from:

```text
packages/private-routes/lib/crypto-suite.js
packages/private-routes/lib/counters.js
```

Use `sodium-universal`, `hypercore-crypto`, and `b4a` already present in HyperDHT. Do not add a second crypto library. Convert modules to CommonJS without changing caller-supplied transcript byte order, KDF labels, allocation checks, intrinsic-method defenses, or zeroization behavior. Add a module comment stating that exact v1 role/branch/circuit/generation transcript construction is not yet provided by this generic primitive.

- [ ] **Step 3: Run vectors and substitution checks in Node and Bare**

```bash
cd hyperdht-private-routing
npx brittle-node test/private/crypto-suite.js test/private/counters.js
bare test/private/crypto-suite.js
bare test/private/counters.js
npx prettier --check lib/private/crypto-suite.js lib/private/counters.js test/private/crypto-suite.js test/private/counters.js
```

Expected: all vectors inherited from `crypto-suite.test.js` and `counters.test.js` match byte-for-byte in both runtimes. The migration record lists the deferred M3 transcript modules and vectors as Gate 3B requirements.

### Task 5: Migrate fixed cells and end-to-end route payloads

**Files:**

- Create: `hyperdht-private-routing/lib/private/cell-codec.js`
- Create: `hyperdht-private-routing/lib/private/route-payload.js`
- Create: `hyperdht-private-routing/test/private/cell-codec.js`
- Create: `hyperdht-private-routing/test/private/route-payload.js`
- Modify: `hyperdht-private-routing/test/private-routing.js`

- [ ] **Step 1: Add failing layout, vector, and tampering tests**

Adapt prototype `test/cell-codec.test.js`, `test/route-payload.test.js`, relevant `test/property.test.js`, and substitution cases from `test/adversarial.test.js`. Include this exact regression vector:

```text
header hex: 000100000000000000000008111111111111111111111111111111110000000000000003
complete cell BLAKE2b-256: 85cef0e1ccb809ab4a305568aa6a7ee9cd570289353be0a6f554de4287857e27
```

Assert exact dimensions, random padding coverage, short/oversized rejection, header authentication, cross-circuit/direction/class/generation substitution rejection, no state advance on failed authentication, hostile-buffer safety, and clearing of temporary plaintext.

- [ ] **Step 2: Port the complete reviewed codecs**

Port from:

```text
packages/private-routes/lib/cell-codec.js
packages/private-routes/lib/route-payload.js
```

Keep the exact 1,200/36/1,148/16/1,146 layout and 1,073-byte route-payload maximum. Preserve XChaCha20-Poly1305 nonce/counter semantics and authentication order. Convert only module syntax and local import paths.

- [ ] **Step 3: Verify both runtimes and the known hash**

```bash
cd hyperdht-private-routing
npx brittle-node test/private/cell-codec.js test/private/route-payload.js
bare test/private/cell-codec.js
bare test/private/route-payload.js
npx prettier --check lib/private/cell-codec.js lib/private/route-payload.js test/private/cell-codec.js test/private/route-payload.js
```

Expected: exact known hash and all tampering cases pass in Node and Bare.

### Task 6: Migrate bounded fragmentation and reassembly

**Files:**

- Create: `hyperdht-private-routing/lib/private/fragments.js`
- Create: `hyperdht-private-routing/test/private/fragments.js`
- Modify: `hyperdht-private-routing/test/private-routing.js`

- [ ] **Step 1: Add failing ceiling and lifecycle tests**

Adapt prototype `test/fragments.test.js` and fragmentation cases from `test/property.test.js`. Cover one through eight fragments, exactly 8,584 bytes, all over-limit boundaries, duplicate/conflicting fragments, out-of-order fragments, five-second expiry, allocation-before-validation traps, reassembly cleanup, and output/temporary-buffer clearing.

- [ ] **Step 2: Port the bounded fragment implementation**

Port `packages/private-routes/lib/fragments.js` completely. Retain maximum eight fragments, maximum 8,584-byte internal message, per-message deadline, strict integer checks, and bounded allocation order. Do not implement public duplex segmentation in this task; that belongs to the later routed-stream gate.

- [ ] **Step 3: Run focused and aggregate core tests**

```bash
cd hyperdht-private-routing
npx brittle-node test/private/fragments.js
bare test/private/fragments.js
node test/all.js
bare test/all.js
git diff --check
```

Expected: all migrated route-core tests and unchanged aggregate tests pass, subject only to a documented local UDX bind restriction.

- [ ] **Step 4: Commit the verified route core**

```bash
cd hyperdht-private-routing
git add package.json lib/private test/private test/private-routing.js test/all.js docs/private-routing-baseline.md
git commit -m "feat: migrate private route cell core"
git push origin private-routing-v1
```

Expected: the commit contains no `node_modules`, package lock, capture, build, or generated binary artifacts.

- [ ] **Step 5: Require fork-native CI before starting Chunk 2**

```bash
cd hyperdht-private-routing
CORE_SHA=$(git rev-parse HEAD)
gh run list --repo ayooooo123/hyperdht --branch private-routing-v1 --limit 10
```

Watch only the workflow whose `headSha` equals `CORE_SHA`. Require Ubuntu, macOS, and Windows to pass `npm test`, `npm run integration`, and `npm run test:bare`. Record the exact run and job URLs in `docs/private-routing-baseline.md`, commit and push that evidence, and confirm the evidence-only follow-up run is also green. Do not start Chunk 2 while any core-SHA job is missing, queued indefinitely, cancelled, or red.

## Chunk 2: Typed DHT policy and internal adapter

### Task 7: Extract the immutable exit policy and routed-DHT codecs

**Files:**

- Create: `hyperdht-private-routing/lib/private/exit-policy.js`
- Create: `hyperdht-private-routing/lib/private/routed-dht.js`
- Create: `hyperdht-private-routing/test/private/exit-policy.js`
- Create: `hyperdht-private-routing/test/private/routed-dht.js`
- Modify: `hyperdht-private-routing/test/private-routing.js`

- [ ] **Step 1: Add failing policy and codec tests**

Adapt prototype `test/routed-dht.test.js` plus the policy encode/digest assertions from `test/final-exit-activation.test.js`. Assert:

- `DESTINATION_REF_SIZE === 172` and `ROUTED_REQUEST_FIXED_BODY_SIZE === 221`;
- a destination contains exactly a 32-byte node ID and 130-byte opaque handle;
- request ID is 16 bytes and deadline is unsigned 64-bit;
- command, version, mutation flag, destination-validation class, request/response limits, amplification limits, and costs exactly match the immutable policy;
- lookup versus announce branch permissions match the approved command table;
- wrong branch, stale deadline, forged handle, changed policy field, changed command, truncated body, oversized body, and hostile accessors fail before route IO;
- decoding and failure paths clear owned copies.

The verified prototype does not contain a routed-reply wire codec or the complete per-command request-body codecs. Do not invent either in this task. Gate 3A uses only the exact 32-byte immutable-get request body that the prototype specifies; the internal fake authority returns a logical response object that is validated and wrapped by the adapter.

- [ ] **Step 2: Extract only the policy table from the prototype final exit**

Create `exit-policy.js` from the following reviewed pieces of `packages/private-routes/lib/final-exit.js`:

- `policyEntry`;
- `EXIT_ORIGIN_SERVICE_POLICY` entries for immutable get/put, mutable get/put, private find-node, private lookup, private prepare, private announce, and private unannounce;
- exact policy encode, decode, and digest functions used to bind negotiation.

Do not port socket opening, live exit state, or activation state into this single-responsibility file. Freeze every entry and the table. Preserve every numeric bound from the prototype commit.

- [ ] **Step 3: Port the routed-DHT codec completely**

Port `packages/private-routes/lib/routed-dht.js`, changing only ESM/CommonJS syntax and the policy import path. Preserve defensive copies, intrinsic method use, exact binary layout, policy equality checks, deadline validation, response bounds, and clear helpers.

- [ ] **Step 4: Verify deterministic bytes in Node and Bare**

```bash
cd hyperdht-private-routing
npx brittle-node test/private/exit-policy.js test/private/routed-dht.js
bare test/private/exit-policy.js
bare test/private/routed-dht.js
npx prettier --check lib/private/exit-policy.js lib/private/routed-dht.js test/private/exit-policy.js test/private/routed-dht.js
```

Expected: exact policy digests, destination references, and routed request vectors match the prototype in both runtimes.

### Task 8: Define private query capabilities and command mapping

**Files:**

- Create: `hyperdht-private-routing/lib/private/query-context.js`
- Create: `hyperdht-private-routing/lib/private/dht-command-policy.js`
- Create: `hyperdht-private-routing/test/private/dht-command-policy.js`
- Modify: `hyperdht-private-routing/test/private-routing.js`

- [ ] **Step 1: Add failing capability and mapping tests**

Tests must prove:

- only module-created immutable-get lookup and announce capability objects are accepted;
- strings, symbols, cloned objects, proxy objects, `null`, and a capability from another policy instance are rejected;
- each capability binds `IMMUTABLE_GET`, `IMMUTABLE_GET_V1`, and exactly one branch before `closest` or `bootstrap` authority IO;
- HyperDHT `IMMUTABLE_GET` encodes exactly the 32-byte target on either branch;
- immutable get rejects a token, non-null value, missing target, or target of any size other than 32 bytes;
- `LOOKUP`, `ANNOUNCE`, `UNANNOUNCE`, mutable get/put, immutable put, private find-node, peer handshake, hole punch, plugin, raw internal DHT commands, and unknown integers return `ERR_PRIVATE_COMMAND_UNSUPPORTED` before any route authority method executes because Gate 3A has no reviewed complete body/reply codecs for them.

- [ ] **Step 2: Implement unforgeable query contexts**

`query-context.js` owns one private per-instance `WeakMap` and exports only:

```js
createQueryContexts() // returns frozen { immutableGet: { lookup, announce }, classify(value) }
```

Each returned capability is a frozen empty object registered in the private `WeakMap` with one frozen policy descriptor containing its normative branch class, HyperDHT command, and v1 typed command ID. `classify` returns that descriptor or throws the stable unsupported/authentication error. Never export the registry or a constructor that accepts caller-selected branch or command data. `RoutedDHTIO.closest` and `RoutedDHTIO.bootstrap` classify the context before calling authority, so unsupported or forged queries cannot perform candidate-discovery IO.

- [ ] **Step 3: Implement one immutable command table**

`dht-command-policy.js` creates the two frozen immutable-get descriptors consumed by `createQueryContexts`, permits the appropriate private branch on each, and exposes an encoder that returns a defensive copy of the exact 32-byte target only when token and value are absent. The module returns frozen descriptors, never mutable table entries. Every other command uses one stable unsupported error. Add a comment explaining that expansion requires a reviewed exact request-body and routed-reply codec, exit implementation, and adversarial vectors.

- [ ] **Step 4: Verify fail-closed mapping**

```bash
cd hyperdht-private-routing
npx brittle-node test/private/dht-command-policy.js
bare test/private/dht-command-policy.js
```

Expected: every unsupported or forged input fails before the test authority call counter changes.

### Task 9: Implement opaque destinations and `RoutedDHTIO`

**Files:**

- Create: `hyperdht-private-routing/lib/private/opaque-destination.js`
- Create: `hyperdht-private-routing/lib/private/routed-dht-io.js`
- Create: `hyperdht-private-routing/test/private/fake-route-authority.js`
- Create: `hyperdht-private-routing/test/private/routed-dht-io.js`
- Modify: `hyperdht-private-routing/test/private-routing.js`

- [ ] **Step 1: Add failing adapter contract tests**

The test fake implements this exact internal authority contract. This illustrative class is valid JavaScript; tests instantiate a concrete subclass or equivalent object:

```js
class RouteAuthority {
  ready() {}
  suspend() {}
  resume() {}
  destroy() {}
  bootstrap({ target, limit, branch }) {}
  closest({ target, limit, branch }) {}
  request({ branch, destinationRef, encodedRequest, attempt }) {
    return { promise: Promise.resolve(), cancel(reason) {} }
  }
}
```

`bootstrap` and `closest` return bounded records shaped as `{ id, destinationRef }`, where `id` is 32 bytes and `destinationRef` is an exact encoded `DESTINATION_REF_V1`. The fake stores separate lookup and announce tables and never exposes host/port data.

`request` must synchronously copy the `encodedRequest` bytes it needs before returning its operation and must never retain the caller's buffer. Once `request` returns, buffer ownership remains exclusively with `RoutedDHTIO`, which clears it immediately. The returned operation owns only its copied authority state; `cancel(reason)` synchronously revokes that state and prevents later authority reads or delivery.

The operation promise returns an internal logical response:

```js
{
  rtt,
  from: { id, destinationRef },
  to: null,
  token: null,
  closerNodes: [{ id, destinationRef }],
  error,
  value
}
```

This object is not a wire format. The adapter validates it and wraps every destination before returning the ordinary DHT-RPC logical reply. A reviewed routed-reply wire codec remains a Gate 3B prerequisite.

This logical response contract is for deterministic structural conformance only. Production code must not connect Gate 3A `RoutedDHTIO` to an untrusted, remote, or live route authority.

Test all nine DHT-RPC adapter methods: `ready`, `suspend`, `resume`, `destroy`, `bootstrap`, `closest`, `key`, `id`, and `request`. Also assert:

- output destinations are frozen, have no enumerable fields, and cannot be caller-constructed;
- `key(destination)` is stable for the same issued capability and distinct across independently issued branch references;
- `id(destination)` returns a defensive 32-byte copy;
- changed or cleared IDs/refs, forged objects, cross-adapter destinations, raw `{host, port}`, and destinations invalidated by suspend/destroy reject before authority IO;
- route request bytes decode to immutable-get v1 with the exact branch, 32-byte target body, request ID, and deadline;
- normalized replies contain only `{ rtt, from, to, token, closerNodes, error, value }` and all destinations are newly validated opaque capabilities;
- route rejection, malformed logical response, stale request deadline, and cancellation fail closed;
- `cancel(reason)` reaches the currently active route operation exactly once;
- every authority request copies its input synchronously, after which the adapter clears its encoded request buffer; successful resolution, rejection, timeout cancellation, explicit cancellation, suspend, and destroy all remove active bookkeeping and clear the remaining adapter-owned request ID exactly once;
- synchronous authority throws and malformed returned operations clear the encoded request, request ID, and active bookkeeping exactly once before the stable failure is propagated;
- suspend cancels active work, resume does not construct direct state, and destroy is idempotent.

Do not claim exact routed-response bytes or amplification accounting in Gate 3A. The prototype has no response wire codec, so those assertions are impossible against this logical internal object. Task 11 records them as mandatory Gate 3B work before any live authority is accepted.

- [ ] **Step 2: Implement opaque destination ownership**

`opaque-destination.js` uses a per-adapter `WeakMap` and exposes a factory with `issue`, `snapshot`, `key`, `id`, and `clear`. `issue` validates and copies the 32-byte ID and 172-byte destination reference before returning a frozen empty object. The key is derived from the authenticated destination reference and branch with a domain-separated BLAKE2b digest, not from host/port. `snapshot` recognizes only objects issued by that factory. `clear` zeroes owned copies during suspend or destroy. Live generation expiry and rotation invalidation are deferred until Gate 3B supplies trusted route-generation metadata.

- [ ] **Step 3: Implement `RoutedDHTIO` as an internal adapter**

The constructor accepts only `{ authority, contexts, now, randomBytes }`; validate all methods before storing authority. Its DHT-RPC methods behave as follows:

- lifecycle methods delegate in order and clear destination/request state on suspend and destroy;
- `bootstrap` and `closest` classify the query capability before authority IO, pass only `{ target, limit, branch }`, bound results by `limit`, validate each encoded reference, and issue opaque destination objects;
- `request` classifies the same query capability, requires `message.command` to equal its bound HyperDHT command before reading destination authority, snapshots the issued destination, creates a 16-byte request ID and bounded absolute deadline, encodes one typed routed request, and delegates to authority;
- the returned operation owns a promise that validates one internal logical authority response, bounds its closer-node count, defensively copies byte values, wraps every destination record, and then produces the DHT-RPC logical reply;
- call `authority.request` inside `try`/`finally`, clearing the adapter-owned encoded request whether authority returns or throws; validate the returned `{ promise, cancel }` operation before registering it as active;
- if authority throws synchronously or returns a malformed operation, remove any provisional active state, clear the request ID exactly once, and propagate the stable routed-transport failure without invoking authority again;
- `cancel(reason)` is idempotent, delegates exactly once, and then clears active state and the adapter-owned request ID under the contract that authority cancellation synchronously revokes its copied state;
- promise settlement uses a `finally` cleanup path that removes active bookkeeping and zeroes the adapter-owned request ID exactly once on either resolution or rejection;
- no code path imports `udx-native`, `dgram`, `net`, DNS, or accepts address-shaped authority.

Use dependency injection only for deterministic clock/random tests. `now()` must return a nonnegative safe-integer millisecond value or unsigned 64-bit `BigInt`; normalize safe integers to `BigInt` and reject everything else. `randomBytes(buffer)` must synchronously fill the supplied `b4a` buffer and return `undefined`; after it returns, verify the buffer still has the requested byte length. Production defaults are `Date.now` and a wrapper around `sodium.randombytes_buf(buffer)`, never `Math.random`.

- [ ] **Step 4: Verify adapter behavior in Node and Bare**

```bash
cd hyperdht-private-routing
npx brittle-node test/private/routed-dht-io.js
bare test/private/routed-dht-io.js
npx prettier --check lib/private/opaque-destination.js lib/private/routed-dht-io.js test/private/fake-route-authority.js test/private/routed-dht-io.js
```

Expected: all contract, authority, hostile-input, cancellation, and lifecycle tests pass in both runtimes.

### Task 10: Prove iterative traversal through the adapter

**Files:**

- Create: `hyperdht-private-routing/test/private/routed-dht-traversal.js`
- Modify: `hyperdht-private-routing/test/private/fake-route-authority.js`
- Modify: `hyperdht-private-routing/test/private-routing.js`

- [ ] **Step 1: Add a deterministic multi-node fake topology**

Build five logical DHT nodes with fixed 32-byte IDs. The fake lookup and announce authorities each issue independent destination references for those IDs. Each internal logical reply returns only normalized values and authoritative closer-node records that the adapter wraps. Record every semantic edge as `{ branch, fromId, toId, commandId, attempt }`.

- [ ] **Step 2: Run base DHT-RPC in transport-only mode**

Construct:

```js
const dht = new DHT({
  outboundPolicy: 'transport-only',
  requestTransport: routedDHTIO,
  requestTimeout: 1000
})
```

Exercise client-controlled iterative traversal for:

- lookup-branch immutable get;
- announce-branch immutable get using its independent destination table;
- cancellation during traversal;
- one retry that retains the same context and destination capability.

Assert the closest node set is correct, no edge crosses branch tables, every destination is opaque, and the fake has no field containing a host or port. Add negative cases showing a forged or missing query capability fails before `closest` or `bootstrap`, and a command that does not equal the capability's bound immutable-get command fails before the fake sees a request. Immutable put, mutable operations, private presence operations, peer operations, and plugin commands have no module-created query capability in Gate 3A.

- [ ] **Step 3: Add negative direct-authority traps**

Install getters that throw for direct-network `udx`, `socket`, `host`, `port`, `bootstrap`, and `nodes` only on DHT constructor options, query options, destination inputs, and logical response records. Do not replace the routed authority's required callable `bootstrap()` method. Assert successful deterministic traversal never reads any direct-network getter. Also assert missing/forged context fails with `ERR_PRIVATE_COMMAND_UNSUPPORTED` before routed authority `bootstrap` or `closest` calls.

- [ ] **Step 4: Verify traversal in Node and Bare**

```bash
cd hyperdht-private-routing
npx brittle-node test/private/routed-dht-traversal.js
bare test/private/routed-dht-traversal.js
node test/all.js
bare test/all.js
git diff --check
```

Expected: both runtimes complete logical traversal entirely through the fake routed authority. This is semantic conformance only, not a network anonymity test.

### Task 11: Document provenance, limitations, and the Gate 3B boundary

**Files:**

- Create: `hyperdht-private-routing/docs/private-routing-migration.md`
- Modify: `hyperdht-private-routing/README.md`
- Modify: `hyperdht-private-routing/docs/private-routing-baseline.md`

- [ ] **Step 1: Write the migration record**

Document each migrated file's prototype source path, exact source commit, CommonJS adaptation, retained vector tests, and any intentionally deferred module. State explicitly that the implementation is experimental, internal, and not a production anonymity surface.

- [ ] **Step 2: Add a concise README experimental note**

Link to `docs/private-routing-v1.md` and `docs/private-routing-migration.md`. Say the fork currently contains the Gate 2 seam and Gate 3A deterministic route substrate; direct mode remains the only public behavior. Do not document a `privateRouting` constructor option until Gate 3B implements it fail-closed.

- [ ] **Step 3: Specify Gate 3B entry criteria**

The migration document must require the next reviewed plan to implement:

1. signed relay advertisements and numeric-only bounded bootstrap;
2. stable guard pinning and separate lookup/announce middle/exit branches;
3. adjacent authenticated links, three-position live routes, quotas, rotation, and teardown;
4. exact reviewed request and reply body codecs, encoded-byte amplification accounting, and adversarial vectors for private presence, mutable/immutable get/put, and exit referrals;
5. exact v1 role/branch/circuit/generation transcript constructors and the deferred M3 derivation vectors;
6. provenance-qualified DHT exit destination tables and live allowlisted UDP operations;
7. trusted route-generation expiry and rotation invalidation for every issued destination capability;
8. a public required-mode controller only after direct authority is removed at readiness;
9. multi-process Node/Bare integration;
10. privileged Linux namespace capture plus semantic leak oracle proving endpoint-to-guard-only traffic after readiness.

The document must say Delivery Gate 3 remains open until all ten items pass in fork-native CI.

### Task 12: Run full verification and publish the reviewed branch state

**Files:**

- Verify: all files changed by Chunk 2
- Modify after results: `hyperdht-private-routing/docs/private-routing-baseline.md`

- [ ] **Step 1: Run all local checks**

```bash
cd hyperdht-private-routing
npm test
npm run integration
npm run test:bare
npx prettier --check lib/private test/private docs README.md package.json
git diff --check
git status --short
```

Expected: all deterministic private tests and formatting pass. Existing UDX-backed commands pass when the host permits binding; otherwise preserve the exact local `EPERM` evidence and do not claim those checks green until GitHub Actions passes.

- [ ] **Step 2: Audit artifact and dependency hygiene**

```bash
cd hyperdht-private-routing
if git ls-files | rg '(^|/)(node_modules|build|target|coverage)(/|$)'; then exit 1; fi
git diff -- package.json
npm ls dht-rpc --depth=0
```

Expected: no build/dependency artifacts are tracked and `npm ls` resolves the exact DHT-RPC Git commit pin.

- [ ] **Step 3: Commit and push Gate 3A**

```bash
cd hyperdht-private-routing
git add package.json lib/private test/private test/private-routing.js test/all.js README.md docs
git commit -m "feat: add routed DHT protocol substrate"
git push origin private-routing-v1
gh run list --repo ayooooo123/hyperdht --branch private-routing-v1 --limit 10
```

- [ ] **Step 4: Require fork-native CI before marking Gate 3A complete**

Watch the workflow for the exact pushed head SHA. Required green jobs:

- Ubuntu: `npm test`, `npm run integration`, `npm run test:bare`;
- macOS: the same three commands;
- Windows: the same three commands;
- every existing lint/format check.

Record exact workflow URLs and job results in `docs/private-routing-baseline.md`, commit that evidence, push it, and confirm the evidence-only follow-up workflow also remains green.

- [ ] **Step 5: Final scope audit**

Confirm all of the following before handoff:

```text
public privateRouting option absent
public privacy option absent
no Hyperswarm or PearTube files changed
no direct fallback path added
no host/port accepted by RoutedDHTIO
no production anonymity claim
Gate 3 still documented as open
```

Only then report Gate 3A complete and start a separately reviewed Gate 3B plan.
