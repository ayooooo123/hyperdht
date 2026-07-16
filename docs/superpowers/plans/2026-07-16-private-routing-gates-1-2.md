# Native Private Routing Gates 1–2 Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish reproducible private-routing fork baselines and add the generic, fail-closed request-transport seam to DHT-RPC without changing direct-mode behavior.

**Architecture:** The four forks remain drop-in compatible. Gate 1 pins and verifies clean upstream-derived baselines. Gate 2 adds two explicit DHT-RPC outbound policies: the existing `direct` path and a `transport-only` path whose injected adapter owns request delivery, opaque destination identity, cancellation, retry, bootstrap, and lifecycle. No onion protocol or privacy policy is implemented in DHT-RPC; HyperDHT will implement the routed adapter in the next plan.

**Tech Stack:** CommonJS JavaScript, Node.js, Bare, `brittle`, `streamx`, `udx-native`, GitHub Actions, GitHub CLI.

---

## Execution roots

Run commands from:

```text
/Users/jd/Documents/Codex/2026-07-10/task-extract-three-packages-into-standalone
```

Repository directories:

```text
dht-rpc-private-routing
hyperdht-private-routing
hyperswarm-private-routing
hyperswarm-testnet-private-routing
```

The canonical protocol specification is:

```text
hyperdht-private-routing/docs/private-routing-v1.md
```

Do not modify the frozen PearTube prototype or the three earlier Tor package repositories while executing this plan.

## Chunk 1: Gate 1 — Fork baselines

### Task 1: Establish all four GitHub forks and branch roots

**Files:**

- Verify: each repository's `.git/config`
- Verify: each repository's `package.json`
- Create remotely: `ayooooo123/hyperswarm-testnet`

- [ ] **Step 1: Confirm GitHub identity and current repository state**

```bash
set -e
gh auth status
test "$(gh api user --jq .login)" = "ayooooo123"
for repo in dht-rpc-private-routing hyperdht-private-routing hyperswarm-private-routing hyperswarm-testnet-private-routing; do git -C "$repo" status --short; git -C "$repo" remote -v; git -C "$repo" branch --show-current; done
```

Expected: GitHub is authenticated as `ayooooo123`; all worktrees are clean. Stop and resolve any unexpected local changes before continuing.

- [ ] **Step 2: Create the missing public testnet fork without generating files**

```bash
set -e
gh repo view ayooooo123/hyperswarm-testnet || gh repo fork holepunchto/hyperswarm-testnet --clone=false
for repo in dht-rpc hyperdht hyperswarm hyperswarm-testnet; do gh repo view "ayooooo123/$repo" --json visibility,isFork,parent; done
```

Expected: each repository reports `PUBLIC`, `isFork: true`, and its matching `holepunchto/<repo>` parent. `https://github.com/ayooooo123/hyperswarm-testnet` exists without generated files.

- [ ] **Step 3: Normalize `origin` and `upstream` remotes**

```bash
set -e
git -C dht-rpc-private-routing remote set-url origin https://github.com/ayooooo123/dht-rpc.git
git -C dht-rpc-private-routing remote remove upstream 2>/dev/null || true
git -C dht-rpc-private-routing remote add upstream https://github.com/holepunchto/dht-rpc.git
git -C hyperdht-private-routing remote set-url origin https://github.com/ayooooo123/hyperdht.git
git -C hyperdht-private-routing remote remove upstream 2>/dev/null || true
git -C hyperdht-private-routing remote add upstream https://github.com/holepunchto/hyperdht.git
git -C hyperswarm-private-routing remote set-url origin https://github.com/ayooooo123/hyperswarm.git
git -C hyperswarm-private-routing remote remove upstream 2>/dev/null || true
git -C hyperswarm-private-routing remote add upstream https://github.com/holepunchto/hyperswarm.git
git -C hyperswarm-testnet-private-routing remote set-url origin https://github.com/ayooooo123/hyperswarm-testnet.git
git -C hyperswarm-testnet-private-routing remote remove upstream 2>/dev/null || true
git -C hyperswarm-testnet-private-routing remote add upstream https://github.com/holepunchto/hyperswarm-testnet.git
```

Expected: `origin` is the writable fork and `upstream` is Holepunch in every repository.

- [ ] **Step 4: Fetch upstream and record exact baseline SHAs**

```bash
set -e
for repo in dht-rpc-private-routing hyperdht-private-routing hyperswarm-private-routing hyperswarm-testnet-private-routing; do git -C "$repo" fetch upstream --tags; done
for repo in dht-rpc-private-routing hyperdht-private-routing hyperswarm-private-routing hyperswarm-testnet-private-routing; do printf '%s ' "$repo"; git -C "$repo" rev-parse upstream/main; done
```

Expected: four full SHAs. Preserve them for the baseline record.

- [ ] **Step 5: Create or verify the `private-routing-v1` branches**

For DHT-RPC, Hyperswarm, and Hyperswarm Testnet, create `private-routing-v1` from the recorded `upstream/main` only if the branch does not exist. If it exists locally or remotely, verify ancestry and stop on divergence; never reset it. HyperDHT already contains the approved specification and must not be reset.

```bash
set -e
for repo in dht-rpc-private-routing hyperswarm-private-routing hyperswarm-testnet-private-routing; do
  git -C "$repo" fetch origin private-routing-v1 2>/dev/null || true
  if git -C "$repo" show-ref --verify --quiet refs/heads/private-routing-v1; then
    git -C "$repo" merge-base --is-ancestor upstream/main private-routing-v1
    git -C "$repo" switch private-routing-v1
    if git -C "$repo" show-ref --verify --quiet refs/remotes/origin/private-routing-v1; then
      if git -C "$repo" merge-base --is-ancestor private-routing-v1 origin/private-routing-v1; then
        git -C "$repo" merge --ff-only origin/private-routing-v1
      elif ! git -C "$repo" merge-base --is-ancestor origin/private-routing-v1 private-routing-v1; then
        echo "$repo: local and origin/private-routing-v1 have diverged" >&2
        exit 1
      fi
    fi
  elif git -C "$repo" show-ref --verify --quiet refs/remotes/origin/private-routing-v1; then
    git -C "$repo" merge-base --is-ancestor upstream/main origin/private-routing-v1
    git -C "$repo" switch --track -c private-routing-v1 origin/private-routing-v1
  else
    git -C "$repo" switch -c private-routing-v1 upstream/main
  fi
done
git -C hyperdht-private-routing switch private-routing-v1
git -C hyperdht-private-routing merge-base --is-ancestor upstream/main private-routing-v1
test -f hyperdht-private-routing/docs/private-routing-v1.md
test "$(sed -n '3p' hyperdht-private-routing/docs/private-routing-v1.md)" = "**Status:** owner-approved experimental design  "
```

Expected: every repository is on `private-routing-v1`; only HyperDHT is ahead of upstream before implementation.

- [ ] **Step 6: Push branch roots**

```bash
set -e
git -C dht-rpc-private-routing push -u origin private-routing-v1
git -C hyperdht-private-routing push -u origin private-routing-v1
git -C hyperswarm-private-routing push -u origin private-routing-v1
git -C hyperswarm-testnet-private-routing push -u origin private-routing-v1
```

Expected: all four experimental branches are visible on GitHub.

### Task 2: Verify and document independent baselines

**Files:**

- Create: `hyperdht-private-routing/docs/private-routing-baseline.md`
- Modify only if required to restore an upstream baseline: package lockfiles generated by the package manager already used by that repository

- [ ] **Step 1: Install the same Bare runtime used by upstream CI and record it**

```bash
set -e
npm install --global bare-runtime
bare --version
```

Expected: the `bare` executable is available before any package's combined Node/Bare test script runs.

- [ ] **Step 2: Install and verify DHT-RPC**

```bash
set -e
cd dht-rpc-private-routing
npm install
npm run lint
npm test
cd ..
```

Expected: formatting/lunte, Node tests, and Bare tests pass.

- [ ] **Step 3: Install and verify HyperDHT**

```bash
set -e
cd hyperdht-private-routing
npm install
npm test
npm run integration
npm run test:bare
cd ..
```

Expected: the three existing upstream test commands pass. HyperDHT does not define a `lint` script at this baseline.

- [ ] **Step 4: Install and verify Hyperswarm**

```bash
set -e
cd hyperswarm-private-routing
npm install
npm run lint
npm test
cd ..
```

Expected: upstream Node/Bare coverage remains green.

- [ ] **Step 5: Install and verify Hyperswarm Testnet**

```bash
set -e
cd hyperswarm-testnet-private-routing
npm install
npm run lint
npm test
cd ..
```

Expected: upstream lint and tests pass.

- [ ] **Step 6: Collect exact provenance values**

```bash
set -e
node --version
npm --version
bare --version
uname -a
node -p "process.platform + ' ' + process.arch"
for repo in dht-rpc-private-routing hyperdht-private-routing hyperswarm-private-routing hyperswarm-testnet-private-routing; do printf '%s upstream=' "$repo"; git -C "$repo" rev-parse upstream/main; printf '%s branch=' "$repo"; git -C "$repo" rev-parse private-routing-v1; done
printf 'hyperdht merge-base='; git -C hyperdht-private-routing merge-base upstream/main private-routing-v1
date -u +%Y-%m-%dT%H:%M:%SZ
```

Expected: exact runtime, operating-system, architecture, repository, and timestamp values suitable for copying into the baseline record.

- [ ] **Step 7: Create the reproducibility record**

Create `hyperdht-private-routing/docs/private-routing-baseline.md` with this shape, replacing placeholders with exact UTC timestamps, SHAs, runtime versions, and results:

```markdown
# Private Routing Fork Baselines

The private-routing experiment starts from these independently verified roots.

| Repository         | Upstream SHA | Private branch root | Node        | Bare        | Commands                                               | Result |
| ------------------ | ------------ | ------------------- | ----------- | ----------- | ------------------------------------------------------ | ------ |
| dht-rpc            | `<sha>`      | `<sha>`             | `<version>` | `<version>` | `npm run lint`; `npm test`                             | pass   |
| hyperdht           | `<sha>`      | `<sha>`             | `<version>` | `<version>` | `npm test`; `npm run integration`; `npm run test:bare` | pass   |
| hyperswarm         | `<sha>`      | `<sha>`             | `<version>` | `<version>` | `npm run lint`; `npm test`                             | pass   |
| hyperswarm-testnet | `<sha>`      | `<sha>`             | `<version>` | `<version>` | `npm run lint`; `npm test`                             | pass   |

Verified at `<ISO-8601 UTC>` on `<OS and architecture>`.
```

- [ ] **Step 8: Ensure generated artifacts are not tracked**

```bash
set -e
for repo in dht-rpc-private-routing hyperdht-private-routing hyperswarm-private-routing hyperswarm-testnet-private-routing; do
  git -C "$repo" status --short
  if git -C "$repo" ls-files | rg '(^|/)(node_modules|build|target)(/|$)'; then exit 1; fi
done
```

Expected: no dependency or build directories are tracked. Review any lockfile change according to that repository's existing convention.

- [ ] **Step 9: Format, commit, and push the baseline record**

```bash
set -e
cd hyperdht-private-routing
npx prettier --write docs/private-routing-baseline.md docs/superpowers/plans/2026-07-16-private-routing-gates-1-2.md
git diff --check
git add docs/private-routing-baseline.md docs/superpowers/plans/2026-07-16-private-routing-gates-1-2.md
git commit -m "docs: record private routing baselines"
git push origin private-routing-v1
cd ..
```

Expected: a small documentation-only commit, with no generated dependencies.

### Gate 1 completion criteria

- [ ] All four public forks exist under `ayooooo123`.
- [ ] All four `private-routing-v1` branches are pushed.
- [ ] Clean upstream behavior passes independently on Node and Bare wherever upstream supports each runtime.
- [ ] Exact roots, tool versions, commands, and results are recorded in the canonical HyperDHT repository.
- [ ] PearTube and the earlier Tor repositories remain untouched.

## Chunk 2: Gate 2 — Generic DHT-RPC request transport

### Gate 2 contract

The new constructor options are exact and intentionally low-level:

```js
new DHT({
  outboundPolicy: 'transport-only',
  requestTransport
})
```

`outboundPolicy` accepts only:

- `direct` — the default; construct and run the existing `lib/io.js` path unchanged.
- `transport-only` — require `requestTransport`; do not construct UDX, bind UDP sockets, watch interfaces, run NAT sampling, or create direct background traffic.

The injected adapter contract is:

```js
{
  ;(ready(),
    suspend(),
    resume(),
    destroy(),
    bootstrap({ target, limit }),
    closest({ target, limit }),
    key(destination),
    id(destination),
    request({ to, token, internal, command, target, value, attempt }))
}
```

Lifecycle methods may return promises. `bootstrap()` returns a promise or async iterable of destinations; `closest()` returns an iterable of locally known destinations. `key(destination)` returns a stable string scoped to this adapter. `id(destination)` returns a 32-byte `b4a`-compatible identifier. A destination is opaque to DHT-RPC and may be `{ id, ref }`; `host` and `port` are never required in transport-only mode.

Each adapter `request()` call is one attempt and returns:

```js
{
  ;(promise, cancel(reason))
}
```

`promise` resolves to the existing logical reply shape:

```js
{
  ;(rtt, from, to, token, closerNodes, error, value)
}
```

The wrapper validates that `from` and every `closerNodes` entry have a valid adapter key and 32-byte ID before query state changes. It normalizes omitted nullable fields to `null`, requires a non-negative integer `error`, and rejects malformed responses with `TRANSPORT_INVALID_RESPONSE`. The wrapper, not the adapter, owns DHT-RPC retry counts, timeout cycles, stats, session attachment, and exactly-once terminal callbacks. Canceling or destroying a request must invoke the active attempt's `cancel()` exactly once and ignore late settlement.

Every admitted destination becomes an internal immutable candidate:

```js
{
  ;(destination, // retained opaque adapter value; never cloned or mutated
    key, // string copied from adapter.key(destination)
    id) // copied 32-byte buffer from adapter.id(destination)
}
```

Each active Query owns a key-to-ID registry, capped by `opts.maxTransportCandidates` (default `256`, valid range `20..4096`). Caller seeds, adapter `closest()`, adapter `bootstrap()`, reply `from`, and reply `closerNodes` all consume the same query-local capacity. Reusing one key with different ID bytes is `TRANSPORT_INVALID_RESPONSE`; capacity overflow also fails the query with `TRANSPORT_INVALID_RESPONSE` rather than evicting or accepting unchecked data. Query teardown clears the registry. A standalone `request()` retains one registry entry for `to`; each response is then validated atomically in a temporary response-local registry capped at `21` entries (one `from` plus the DHT maximum of 20 `closerNodes`) and discarded on settlement. More than 20 closer nodes, collisions within the response, or a response identity conflicting with `to` fail with `TRANSPORT_INVALID_RESPONSE`. No registry is process-global or retained across completed operations. Query ordering, `_seen`, DOWN/DONE state, closest replies, and retries use candidates, never `destination.id`, `host`, or `port`. Public results unwrap and return the retained opaque `destination`; copied IDs are used only for Kademlia comparison and validation.

Transport-only request timing is explicit: `opts.requestTimeout` is a positive integer in milliseconds and defaults to `1000`, matching direct IO's fallback. An internal `opts.requestTimer` seam has `{ set(fn, ms), clear(handle) }`; production defaults to global `setTimeout`/`clearTimeout`, while tests use a manual clock and advance cycles synchronously. The timer seam never leaves DHT-RPC or becomes part of the adapter protocol.

Stable configuration/lifecycle error codes:

```text
DIRECT_IO_FORBIDDEN
TRANSPORT_INVALID
TRANSPORT_UNAVAILABLE
TRANSPORT_INVALID_RESPONSE
```

No onion routing, route cryptography, DHT exit behavior, or downgrade policy belongs in this repository.

### Complete transport-only DHT state

Do not invent placeholder UDP objects. The `transport-only` constructor state is exact:

- `this.io` is `RequestTransport`; it owns `inflight`, request stats, command tx/rx stats, and lifecycle, but has no congestion window, sockets, token generator, decoder, or network-interface watcher.
- `this.table`, `this.udx`, `this.health`, and `this._nat` are `null`; Query uses `this._queryId` (fresh random 32 bytes), `this._queryK = 20`, and transport candidates instead. Add a direct-mode regression assertion that the pinned `kademlia-routing-table` dependency still reports `table.k === 20`; update both paths together if that upstream constant ever changes.
- `this.firewalled` and `this.ephemeral` are `true`; `id`, `host`, `port`, `socket`, `address()`, `localAddress()`, and `remoteAddress()` return `null`.
- No `_tickInterval`, table row handler, NAT sampler, interface listener, reping, refresh, stability, or DOWN_HINT state is created. Transport requests still increment the existing public `stats.queries`, `stats.requests`, and `stats.commands` shapes.
- `config` returns `{ concurrency, maxPingDelay, outboundPolicy, requestTimeout, maxTransportCandidates }` in transport-only mode; direct mode keeps its current object exactly.
- `toArray()` returns `[]`; opaque route candidates are not exported as direct node-cache entries.
- Direct `opts.bootstrap`, `opts.nodes`, `opts.udx`, `opts.port`, `opts.host`, `opts.firewalled`, `opts.anyPort`, `opts.ephemeral`, `opts.socket`, and IP TTL authority are rejected with `DIRECT_IO_FORBIDDEN` when combined with `transport-only`. Route bootstrap/configuration belongs inside the adapter.

Adapter failures map exactly:

- Missing methods or invalid constructor configuration: `TRANSPORT_INVALID`.
- A user-supplied request destination whose `key()`/`id()` throws or returns invalid data: `TRANSPORT_INVALID` before adapter activity.
- Adapter-produced bootstrap, closest, `from`, or `closerNodes` data with invalid/colliding keys or IDs, and malformed logical replies: `TRANSPORT_INVALID_RESPONSE` before query mutation.
- Synchronous throws or rejections from `ready`, `suspend`, `resume`, `destroy`, `bootstrap`, `closest`, or a well-formed request operation: wrap as `TRANSPORT_UNAVAILABLE` with `cause`.
- A synchronous `request()` throw or operation `promise` rejection is an unavailable attempt and follows the request retry budget; after exhaustion it rejects `TRANSPORT_UNAVAILABLE`. Wrapper-owned timer exhaustion remains `REQUEST_TIMEOUT`.
- A runtime `request()` result lacking a thenable `promise` or callable `cancel` is `TRANSPORT_INVALID`; it is terminal and is not retried.
- If `cancel()` throws, emit `transport-error` with a wrapped `TRANSPORT_UNAVAILABLE`, but preserve the original timeout/destroy/suspend terminal result and exactly-once accounting.
- Once wrapper teardown begins, its existing lifecycle code (`REQUEST_DESTROYED` or `IO_SUSPENDED`) wins over late adapter resolution/rejection.

### Task 3: Lock the constructor and adapter contract with failing tests

**Files:**

- Create: `dht-rpc-private-routing/test/request-transport.js`
- Modify: `dht-rpc-private-routing/test.js`
- Modify: `dht-rpc-private-routing/lib/errors.js`
- Create: `dht-rpc-private-routing/lib/request-transport.js`
- Modify: `dht-rpc-private-routing/index.js`

- [ ] **Step 1: Add the transport test harness**

At the end of `test.js`, load the focused tests:

```js
require('./test/request-transport')
```

In `test/request-transport.js`, define `createTransport(overrides = {})` with every required method, deterministic 32-byte IDs, opaque refs, call logs, and deferred request promises. Do not open sockets in the fake.

- [ ] **Step 2: Write failing constructor tests**

Cover these cases:

```js
test('direct remains the default', async (t) => {
  const dht = new DHT({ bootstrap: false })
  t.is(dht.outboundPolicy, 'direct')
  t.ok(dht.io)
  await dht.destroy()
})

test('transport-only requires a complete adapter', (t) => {
  t.exception(
    () => new DHT({ outboundPolicy: 'transport-only' }),
    (err) => err.code === 'TRANSPORT_INVALID'
  )
})
```

Also reject unknown `outboundPolicy` values, incomplete methods, `requestTransport` supplied without `transport-only`, invalid `maxTransportCandidates`, and every direct-only constructor option listed in the complete-state section. Assert their stable error codes rather than messages. Do not call `key()` or `id()` during construction because no destination has been admitted yet.

- [ ] **Step 3: Run the focused test and observe failure**

```bash
set -e
cd dht-rpc-private-routing
npx brittle test/request-transport.js
```

Expected: FAIL because `outboundPolicy` and the transport wrapper do not exist.

- [ ] **Step 4: Add stable errors and a strict adapter validator**

In `lib/errors.js`, add named factories following the existing `DHTError` pattern. In `lib/request-transport.js`, export a `RequestTransport` class and a `validateTransport()` helper. Validate all required methods before retaining the adapter. Never coerce destinations, keys, IDs, responses, counters, or error codes.

- [ ] **Step 5: Select IO only after validating policy**

At the start of the `DHT` constructor in `index.js`:

1. Validate `opts.outboundPolicy` before constructing `UDX` or `IO`.
2. Set `this.outboundPolicy` to `direct` by default.
3. Preserve existing direct initialization behavior; the only permitted refactor is replacing `new UDX()` with `(opts.udxFactory || defaultUDXFactory)()` while retaining `opts.udx` precedence.
4. Construct `RequestTransport` in the transport-only branch.
5. Keep `this.io` as the selected IO-like request owner so public request/query call sites remain narrow.
6. Initialize every transport-only field exactly as listed under `Complete transport-only DHT state`; do not leave code paths to infer state from missing IO properties.

Do not instantiate `new UDX()`, `NatSampler`, or an interface watcher in the transport-only branch.

- [ ] **Step 6: Make the focused constructor tests pass**

```bash
set -e
cd dht-rpc-private-routing
npx brittle test/request-transport.js
npm run format
npm run lint
```

Expected: the constructor cases pass; formatting and lint pass.

- [ ] **Step 7: Commit the contract slice**

```bash
set -e
cd dht-rpc-private-routing
git add index.js lib/errors.js lib/request-transport.js test.js test/request-transport.js
git commit -m "feat: define routed request transport"
```

### Task 4: Implement request, retry, cancellation, and lifecycle parity

**Files:**

- Modify: `dht-rpc-private-routing/index.js`
- Modify: `dht-rpc-private-routing/lib/request-transport.js`
- Modify: `dht-rpc-private-routing/lib/session.js`
- Modify: `dht-rpc-private-routing/test/request-transport.js`

- [ ] **Step 1: Write failing one-attempt and normalization tests**

Test that `dht.request(message, opaqueDestination)`:

- passes `to`, `token`, `internal`, `command`, `target`, `value`, and `attempt: 1` without adding a host, port, socket, or IP TTL;
- resolves one validated reply and updates `active`, `total`, and `responses` once;
- normalizes absent `to`, `token`, `closerNodes`, and `value` to `null`;
- rejects a malformed ID/key/reply with `TRANSPORT_INVALID_RESPONSE` before exposing it to the caller;
- preserves the adapter's opaque `from` object in the validated result.

For a caller-supplied standalone destination, invalid/throwing `key()` or `id()` must reject `TRANSPORT_INVALID` before `adapter.request()`. Prove atomic validation of `from` plus up to 20 `closerNodes`, collision/overflow rejection, disposal of the temporary response registry, and clearing of the retained `to` entry after resolve, rejection, timeout, or destroy.

- [ ] **Step 2: Write failing deterministic timeout/retry tests**

Construct DHT with `requestTimeout: 1000` and a manual `requestTimer`. Advance the manual timer without sleeping. Assert:

- attempt numbers increment monotonically;
- `req.oncycle` runs before retry;
- `opts.retry === false` performs one attempt;
- exhausting retries rejects with existing `REQUEST_TIMEOUT`;
- the superseded attempt is canceled once before the next attempt starts;
- stats count retries and timeouts exactly once.

Use fake/deferred promises, not wall-clock one-second sleeps.

- [ ] **Step 3: Write failing session and teardown tests**

Assert that `session.destroy(customError)`, `dht.suspend()`, and `dht.destroy()` each:

- cancel every active adapter attempt once;
- detach the request from its session;
- decrement active stats once;
- reject with the appropriate existing lifecycle error;
- ignore a late resolve/reject from the adapter;
- call adapter lifecycle methods in order and make repeated lifecycle calls idempotent.

Also assert lifecycle method throws/rejections follow the exact error map, and a throwing `cancel()` emits `transport-error` without replacing the original terminal error.

Add a synchronous-throw regression: `adapter.request()` throws immediately, but the caller still receives one asynchronous `TRANSPORT_UNAVAILABLE` through the installed callback/promise; query-specific retries and `oncycle` are honored, and no default/no-op callback consumes the error.

- [ ] **Step 4: Run the focused tests and observe failure**

```bash
set -e
cd dht-rpc-private-routing
npx brittle test/request-transport.js
```

Expected: FAIL on unimplemented request and lifecycle behavior.

- [ ] **Step 5: Implement `TransportRequest`**

Inside `lib/request-transport.js`, add a private request class matching the subset Query and Session use:

```js
{
  ;(to,
    token,
    internal,
    command,
    target,
    value,
    session,
    index,
    sent,
    retries,
    destroyed,
    timeout,
    oncycle,
    onresponse,
    onerror,
    send(force),
    destroy(error))
}
```

Implement exactly-once `_settle`, `_cancelAttempt`, timeout-cycle, retry, stats, and session attach/detach behavior. Add an internal generation number so late completion from an older attempt cannot settle a newer attempt. Invoke `adapter.request()` behind a promise/microtask boundary so adapter throws and already-settled promises never call user/query callbacks in the `send()` stack. Erase owned value/token references on terminal teardown where doing so does not mutate caller-owned buffers.

Refactor `_request()`/`Query._visit()` so `onresponse`, `onerror`, `oncycle`, `retries`, and `force` are all assigned before the first `send()` in both direct and transport modes. Preserve direct retry counts and callback ordering with regression tests; do not rely only on microtask timing for correctness.

- [ ] **Step 6: Implement transport-only public request and lifecycle branches**

In `index.js`:

- change `request(message, destination, opts)`, `ping(destination, opts)`, and `delayedPing(destination, delay, opts)` to pass the destination intact; direct mode validates/destructures host/port at its existing IO boundary, while transport-only validates an opaque candidate;
- allow ordinary query/find-node operations to use adapter candidates;
- reject `opts.socket`, IP `ttl`, relay/raw-packet methods, and other direct authority with `DIRECT_IO_FORBIDDEN` before adapter calls;
- make transport-only `_bootstrap()` wait one tick, await `requestTransport.ready()`, set `bootstrapped`, and emit `ready` but never `listening`;
- make `suspend()`, `resume()`, and `destroy()` delegate exactly once to RequestTransport and avoid tick/socket/interface work;
- expose the exact null getters and transport-only config/state defined earlier.

- [ ] **Step 7: Remove Session's direct-congestion assumption**

In `lib/session.js`, change `destroy()` to call `req.destroy(err)` only. Direct IO's own `Request.destroy()` already decrements congestion; the current extra `this.dht.io.congestion.recv()` double-owns that concern and prevents generic request owners. Add a direct-mode regression test proving congestion counts do not underflow or stall after session destruction.

- [ ] **Step 8: Make focused and direct regression tests pass**

```bash
set -e
cd dht-rpc-private-routing
npx brittle test/request-transport.js
npm run test:node
npm run test:bare
```

Expected: both transport-only tests and the unchanged direct suite pass on Node and Bare.

- [ ] **Step 9: Commit request lifecycle support**

```bash
set -e
cd dht-rpc-private-routing
git add index.js lib/request-transport.js lib/session.js test/request-transport.js test.js
git commit -m "feat: run requests through injected transports"
```

### Task 5: Make iterative queries destination-opaque

**Files:**

- Modify: `dht-rpc-private-routing/index.js`
- Modify: `dht-rpc-private-routing/lib/query.js`
- Modify: `dht-rpc-private-routing/lib/session.js`
- Modify: `dht-rpc-private-routing/test/request-transport.js`

- [ ] **Step 1: Write a failing three-hop opaque traversal test**

The fake transport should bootstrap with `{ id: idA, ref: 'a' }`, return B from A's `closerNodes`, then return C from B. Assert:

- Query visits A, B, and C without `host` or `port`.
- Deduplication uses adapter `key()`.
- Kademlia ordering uses adapter `id()`.
- No `peer.id(host, port)` call or `host + ':' + port` key is required.
- Replies and `closestNodes` preserve opaque destinations.
- Internal state contains frozen `{ destination, key, id }` candidates with copied IDs, and never adds `.id` to the opaque destination.
- Reusing a key with different ID bytes fails before visiting that candidate.

- [ ] **Step 2: Write failing local-seed and bootstrap tests**

Cover adapter `closest({ target, limit })`, async `bootstrap({ target, limit })`, `opts.nodes`, and `opts.replies`. Reject duplicate keys with conflicting IDs and invalid bootstrap entries before a request is attempted.

Set `maxTransportCandidates` to a small test value and prove that caller, closest, bootstrap, `from`, and `closerNodes` admissions share the same query-local count; overflow fails closed, and query teardown clears every registry entry.

- [ ] **Step 3: Write failing auto-commit/session propagation test**

For `{ commit: true }`, assert the commit request uses the same transport-only session, opaque destination, and outbound policy. Destroying the query must cancel both traversal and commit work. This prevents the commit helper from escaping through a newly created default request path.

- [ ] **Step 4: Run focused tests and observe failure**

```bash
set -e
cd dht-rpc-private-routing
npx brittle test/request-transport.js
```

Expected: FAIL on direct-address assumptions in `lib/query.js`.

- [ ] **Step 5: Centralize destination operations on DHT**

Add internal helpers in `index.js`:

```js
_nodeKey(node)
_nodeId(node)
_closestQueryNodes(target, limit)
_resolveQueryBootstrap(target, limit)
```

Direct mode delegates to the existing host/port/table behavior. Transport-only delegates to the validated adapter. Return copied/validated node descriptors so adapter mutation cannot rewrite `_seen` or ordering state after admission.

For transport-only, these helpers return or consume the internal candidate form defined by the contract. `_nodeKey()` reads `candidate.key`; `_nodeId()` reads the copied `candidate.id`; bootstrap/closest wrap opaque destinations exactly once through RequestTransport's key-to-ID registry. Direct mode may construct the same internal candidate shape around its existing `{ id, host, port }` node so Query has one representation without changing public direct results.

- [ ] **Step 6: Replace address assumptions in Query**

In `lib/query.js`:

- use `_nodeKey()` for `_seen`, DONE, and DOWN state;
- use `_nodeId()` for distance comparisons;
- use `_closestQueryNodes()` and `_resolveQueryBootstrap()` for initial candidates;
- validate and wrap `m.from` and `m.closerNodes` through the same candidate registry before `_isCloser`, `_pushClosest`, `_seen`, or callbacks;
- retain the direct-mode peer-ID derivation only inside the direct helper;
- disable encoded IPv4 DOWN_HINT generation in transport-only mode; adapter retries/errors remain local and must not synthesize a direct packet;
- pass `query._session` into `autoCommit()`.

When exposing `reply.from`, `reply.closerNodes`, `closestReplies`, or `closestNodes`, unwrap `candidate.destination`. Never expose the internal candidate wrapper or copied ID as dial authority.

Update `Session.request()` and `Session.ping()` to pass destinations through rather than destructuring `{ host, port }`.

- [ ] **Step 7: Make all query tests pass**

```bash
set -e
cd dht-rpc-private-routing
npx brittle test/request-transport.js
npm run test:node
npm run test:bare
npm run lint
```

Expected: opaque iterative traversal passes, and all direct lookup/announce behavior is unchanged.

- [ ] **Step 8: Commit opaque traversal support**

```bash
set -e
cd dht-rpc-private-routing
git add index.js lib/query.js lib/session.js test/request-transport.js
git commit -m "feat: traverse opaque transport destinations"
```

### Task 6: Prove transport-only is fail-closed

**Files:**

- Modify: `dht-rpc-private-routing/index.js`
- Modify: `dht-rpc-private-routing/lib/request-transport.js`
- Modify: `dht-rpc-private-routing/test/request-transport.js`

- [ ] **Step 1: Add a portable UDX construction trap**

Add a narrow `opts.udxFactory` seam whose production default is `() => new UDX()` and which is consulted only in the direct branch when `opts.udx` is absent. In both Node and Bare tests, pass `udxFactory() { throw DIRECT_IO_FORBIDDEN() }`, then construct and exercise a transport-only DHT. Assert readiness, query, suspend/resume, and destroy succeed without calling the factory.

The portable guarantee is: `udx-native` may be imported by the CommonJS module, but transport-only never constructs UDX, creates/binds a socket, or registers a network-interface watcher. An additional Node subprocess/module-stub test may strengthen this but cannot replace the shared Node/Bare factory test.

- [ ] **Step 2: Add forbidden direct-API tests**

In transport-only mode, assert these operations throw or reject `DIRECT_IO_FORBIDDEN` without adapter activity:

- `bind()`, `onmessage()`, `addNode({ host, port })`, direct bootstrapper construction, and APIs that explicitly accept a UDX socket;
- any direct-address persistence/import path;
- any inbound DHT request-serving path not supplied by the transport adapter.

Read-only address getters must return `null`; `toArray()` must return only adapter-safe opaque entries or an empty array, never a dial address.

- [ ] **Step 3: Add background-traffic assertions**

After `ready()` and multiple synthetic ticks/network-change opportunities, assert the fake adapter log contains no implicit ping, NAT test, DOWN_HINT, refresh, direct retry, or socket bind. Only calls explicitly required by adapter readiness/bootstrap and the test's query may occur.

- [ ] **Step 4: Run focused tests and observe failure**

```bash
set -e
cd dht-rpc-private-routing
npx brittle test/request-transport.js
```

Expected: FAIL wherever direct lifecycle code is still unconditional.

- [ ] **Step 5: Remove remaining unconditional direct lifecycle state**

Audit every read of `io.stats.commands`, `io.inflight`, `io.congestion`, `io.networkInterfaces`, client/server sockets, `firewalled`, `_nat`, `table`, and tick/refresh state. Route valid transport-only reads to the exact state defined in the contract, and guard direct-only reads at their public entry with `DIRECT_IO_FORBIDDEN`. Task 4 already owns bootstrap/suspend/resume/destroy behavior; this step removes any missed unconditional direct state rather than introducing lifecycle semantics late.

- [ ] **Step 6: Make the leak-oracle tests pass on Node and Bare**

```bash
set -e
cd dht-rpc-private-routing
npx brittle test/request-transport.js
npm run test:node
npm run test:bare
npm run lint
```

Expected: transport-only cannot construct or reach UDX, and the full direct suite remains green.

- [ ] **Step 7: Commit the fail-closed slice**

```bash
set -e
cd dht-rpc-private-routing
git add index.js lib/request-transport.js test/request-transport.js
git commit -m "feat: forbid direct io for routed transports"
```

### Task 7: Document the experimental hook and make GitHub CI authoritative

**Files:**

- Modify: `dht-rpc-private-routing/README.md`
- Modify: `dht-rpc-private-routing/.github/workflows/ci.yml`
- Modify: `hyperdht-private-routing/docs/private-routing-baseline.md`

- [ ] **Step 1: Document only the generic seam**

Add an `Experimental request transports` section to the DHT-RPC README containing:

- the exact constructor and adapter contract from this plan;
- the `direct` default and `transport-only` fail-closed guarantee;
- cancellation, retry, opaque-destination, and response-validation rules;
- a warning that this hook alone does not provide anonymity;
- a link to `https://github.com/ayooooo123/hyperdht/blob/private-routing-v1/docs/private-routing-v1.md`;
- local fork development using the Git branch, without changing the npm package name.

- [ ] **Step 2: Run CI for the experimental branch without changing release behavior**

Change workflow branch filters to:

```yaml
push:
  tags:
    - '*'
  branches: [main, private-routing-v1]
pull_request:
  branches: [main, private-routing-v1]
```

Keep the existing Linux/macOS/Windows matrix and Node/Bare test command. Keep tag-only canary/release behavior unchanged. Do not add publish permissions or npm tokens.

- [ ] **Step 3: Run final local verification**

```bash
set -e
cd dht-rpc-private-routing
npm run format
npm run lint
npm test
git diff --check
git status --short
cd ..
```

Expected: formatting, lint, Node, Bare, and whitespace checks pass; only intentional files are modified.

- [ ] **Step 4: Commit and push docs/CI**

```bash
set -e
cd dht-rpc-private-routing
git add README.md .github/workflows/ci.yml
git commit -m "ci: verify private routing transport hook"
git push origin private-routing-v1
cd ..
```

- [ ] **Step 5: Open a fork-local review PR**

```bash
gh pr create --repo ayooooo123/dht-rpc --base main --head private-routing-v1 --title "Experimental fail-closed request transport" --body "Implements Gate 2 of the owner-approved native private routing design. Direct mode remains the default and retains its existing tests. This PR does not claim production anonymity."
```

Expected: a PR in the fork, not against Holepunch upstream.

- [ ] **Step 6: Wait for and record GitHub-native CI**

```bash
set -e
PR_URL=$(gh pr view private-routing-v1 --repo ayooooo123/dht-rpc --json url --jq .url)
gh pr checks "$PR_URL" --repo ayooooo123/dht-rpc --watch
gh run list --repo ayooooo123/dht-rpc --branch private-routing-v1 --limit 5
git -C dht-rpc-private-routing rev-parse HEAD
```

Record the final DHT-RPC SHA, PR URL, and each GitHub Actions job result in `hyperdht-private-routing/docs/private-routing-baseline.md`. Commit and push that documentation update on HyperDHT's `private-routing-v1` branch.

### Gate 2 completion criteria

- [ ] Unconfigured DHT-RPC direct mode has no API, wire, test, or performance-path regression.
- [ ] `transport-only` requires a validated adapter and never constructs/binds UDX or starts direct background activity.
- [ ] Request delivery, retry, timeout, cancellation, session teardown, and stats have Node/Bare coverage.
- [ ] Iterative queries traverse opaque `{ id, ref }` destinations without host/port assumptions.
- [ ] Invalid adapter data fails before query state changes.
- [ ] Direct-only APIs fail with stable errors instead of falling back.
- [ ] Linux, macOS, and Windows GitHub Actions jobs are green on `private-routing-v1`.
- [ ] The fork-local PR, final SHA, and CI results are recorded in the canonical HyperDHT repository.

## Next plan boundary

After Gate 2 passes, write a separate reviewed plan for Gate 3 in `hyperdht-private-routing`. That plan will implement the fixed-cell cryptographic prototype and a `RoutedDHTIO` adapter against this seam. Do not begin Hyperswarm or PearTube integration during this plan.
