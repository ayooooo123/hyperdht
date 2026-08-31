# Relay Capability Quality Hardening Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close all seven Task 2 code-quality findings while preserving the reviewed wire formats and internal consumer contract.

**Architecture:** Keep all changes inside the existing relay-capability module and focused tests. Add bounded internal leases and replay claims, move responder ownership into a WeakMap with fail-closed staged timers, enforce the authenticated CAPS mask, and remove unread history ownership.

**Tech Stack:** CommonJS JavaScript, Brittle, Node.js, Bare, `b4a`, `sodium-universal`, `hypercore-crypto`.

---

## Chunk 1: Verifier completion and bounded state

### Task 1: Recheck challenge liveness after crypto

**Files:**

- Modify: `lib/private/relay-capability.js:2027-2200`
- Test: `test/private/relay-capability.js`

- [ ] **Step 1: Write the failing late-expiry hook test**

Fresh-load the module with a crypto `verify` or `keyAgreement` wrapper that advances
wall and monotonic time after the existing completion checks. Assert
`beginChallenge()` returns `ERR_INCOMPATIBLE_RELAY`, publishes no projection, leaves
no timer, and clears the prior projection and challenge-owned bytes. Add an independent
valid-clock hook that reentrantly replaces or revokes the source record and proves the
stale challenge completion publishes nothing.

- [ ] **Step 2: Run the focused Node test and verify RED**

Run:

```bash
/Users/jd/.nvm/versions/node/v22.19.0/bin/node test/private/relay-capability.js
```

Expected: the hook test observes a returned projection containing cleared bytes.

- [ ] **Step 3: Add the final completion gate**

After response signature/proof crypto, sample both clocks and require the original
projection and record to remain live before replay or projection publication:

```js
const wallVerified = sampleWall(state)
const monoVerified = sampleMonotonic(state)
if (
  monoVerified < monoStart ||
  monoVerified - monoStart >= wallDeadline - wallStart ||
  wallVerified >= wallDeadline ||
  record.advertisement.expiresAtMs <= wallVerified ||
  state.projections.get(advertisement) !== record
)
  incompatible()
```

Use an internal record-ownership check rather than caller-controlled identity data.

- [ ] **Step 4: Run focused Node and Bare tests and verify GREEN**

### Task 2: Bound and expire replay tombstones

**Files:**

- Modify: `lib/private/relay-capability.js:1800-2210`
- Test: `test/private/relay-capability.js`

- [ ] **Step 1: Write failing replay lifecycle tests**

Generate valid sequential active challenges. Prove a completed response replays as
`ERR_REPLAY` before its challenge deadline, expired tombstones are pruned, more than
4,096 sequential challenges remain possible when time advances through cleanup,
exactly 4,096 simultaneously live claims succeed, the 4,097th completion returns
`ERR_BUSY` without a projection, and the oldest live claim remains replay-rejected.

- [ ] **Step 2: Run focused Node and verify RED**

- [ ] **Step 3: Replace the permanent Set with an expiry Map**

Store `digest -> expiresAt`, prune entries with `expiresAt <= now`, fail `ERR_BUSY`
when 4,096 entries remain live, and clear the map on invalidation/destroy. Add no
per-entry timers.

- [ ] **Step 4: Run focused Node and Bare and verify GREEN**

- [ ] **Step 5: Commit**

```bash
git add lib/private/relay-capability.js test/private/relay-capability.js
git commit -m "fix: harden relay challenge completion"
```

### Task 3: Bound projection leases

**Files:**

- Modify: `lib/private/relay-capability.js:1470-1795`
- Test: `test/private/relay-capability.js`

- [ ] **Step 1: Write the failing projection ceiling test**

Accept the same canonical advertisement at least nine times. Assert only the newest
eight projections remain live, the oldest projection's five buffers are zero, authority
creation and challenge use from it fail before IO, and projections for another record
remain independent. After the ninth publication, prove the newest projection still
creates an authority and completes an active challenge successfully.

- [ ] **Step 2: Run focused Node and verify RED**

- [ ] **Step 3: Implement FIFO projection eviction**

Before publishing a projection at the cap, remove the oldest projection from all three
registries, clear it, and revoke only authority states whose new `projection` field
matches it. Keep authority identity checks exact so stale projection eviction cannot
revoke a newer authority.

- [ ] **Step 4: Run focused Node and Bare and verify GREEN**

- [ ] **Step 5: Commit**

```bash
git add lib/private/relay-capability.js test/private/relay-capability.js
git commit -m "fix: bound relay projection leases"
```

## Chunk 2: Responder ownership and timer atomicity

### Task 4: Move responder state into a WeakMap and stage rotation timers

**Files:**

- Modify: `lib/private/relay-capability.js:1030-1470`
- Test: `test/private/relay-capability.js`

- [ ] **Step 1: Write failing hostile-surface and timer-injection tests**

Assert the authority is frozen with no own secret/map/timer/hook fields and hostile
property writes cannot affect cookies or response behavior. Inject throwing,
synchronously firing, and reentrant `setTimeout`/`clearTimeout` behavior for both next
rotation and prior-secret erasure. Each failure must either publish a fully scheduled
rotation or destroy and clear the authority with no live timer.

- [ ] **Step 2: Run focused Node and verify RED**

- [ ] **Step 3: Introduce responder WeakMap state**

Add `responderStates`, retrieve state inside every method, freeze the returned authority,
and remove all `this._...` fields. Replace direct test access with a deep-imported
test-only observer that receives only post-detachment/post-zeroization events and
non-authorizing metadata.

- [ ] **Step 4: Stage rotation publication**

Install prior-erasure and next-rotation timers under synchronous-installation guards
before publishing the new secret set. On a throw, synchronous callback, or reentrant
lifecycle change, cancel staged handles best-effort and destroy/clear the authority.

- [ ] **Step 5: Run focused Node and Bare and verify GREEN**

- [ ] **Step 6: Commit**

```bash
git add lib/private/relay-capability.js test/private/relay-capability.js
git commit -m "fix: make CAPS responder state atomic"
```

## Chunk 3: Binding and ownership cleanup

### Task 5: Bind CAPS mask exactly

**Files:**

- Modify: `lib/private/relay-capability.js:1288-1338`
- Test: `test/private/relay-capability.js`

- [ ] **Step 1: Write a failing correctly-authenticated mismatch test**

Issue a valid cookie for a mask-3 query and submit a valid signed mask-1 advertisement.
Assert `admitCapsRetry()` rejects with `ERR_AUTHENTICATION` before binding publication;
response crypto hooks remain uncalled and caller bytes remain unchanged.

- [ ] **Step 2: Run focused Node and verify RED**

- [ ] **Step 3: Enforce exact equality after signed decode**

Compare `advertisement.capabilityMask` to `query.requestedCapabilityMask` before clearing
the decoded advertisement or publishing a binding.

- [ ] **Step 4: Run focused Node and Bare and verify GREEN**

- [ ] **Step 5: Commit**

```bash
git add lib/private/relay-capability.js test/private/relay-capability.js
git commit -m "fix: bind CAPS query capability mask"
```

### Task 6: Remove unread history encoding ownership

**Files:**

- Modify: `lib/private/relay-capability.js:1565-1990`
- Test: `test/private/relay-capability.js`

- [ ] **Step 1: Write the failing allocation/ownership test**

Profile first acceptance and assert no second retained canonical advertisement copy is
allocated for history. Existing replacement, quarantine, poison, and destroy clearing
tests remain the behavioral contract.

- [ ] **Step 2: Run focused Node and verify RED**

- [ ] **Step 3: Remove `history.encoded`**

Delete its initialization, copy, and clearing. Retain digest, epoch, expiry, route keys,
and poison state only.

- [ ] **Step 4: Run focused Node and Bare and verify GREEN**

- [ ] **Step 5: Commit**

```bash
git add lib/private/relay-capability.js test/private/relay-capability.js
git commit -m "refactor: remove unused relay history bytes"
```

## Chunk 4: Final verification

### Task 7: Run the bounded matrix

**Files:**

- Regenerate: `test/all.js` only if generation changes it

- [ ] **Step 1: Run focused Node and Bare**

- [ ] **Step 2: Run full private-routing Node and Bare**

- [ ] **Step 3: Regenerate the Brittle runner**

```bash
/Users/jd/.nvm/versions/node/v22.19.0/bin/node node_modules/brittle/bin/node.js -r test/all.js test/*.js
```

- [ ] **Step 4: Run scoped Prettier and diff checks**

```bash
/Users/jd/.nvm/versions/node/v22.19.0/bin/node node_modules/prettier/bin/prettier.cjs --check lib/private/relay-capability.js test/private/relay-capability.js
git diff --check
git status --short
```

- [ ] **Step 5: Report every commit SHA and exact test/assertion totals**

Do not push and do not run repository-wide `test/all.js`.
