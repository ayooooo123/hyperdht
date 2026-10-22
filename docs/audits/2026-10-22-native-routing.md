**HyperDHT fork audit — 22 October 2026**

Repository: [ayooooo123/hyperdht](https://github.com/ayooooo123/hyperdht). Audited default branch: `implement-private-peer-v2`, pinned to [3ea467edfe338a29e0e48bd1b7a15668eef9dc2c](https://github.com/ayooooo123/hyperdht/commit/3ea467edfe338a29e0e48bd1b7a15668eef9dc2c).

The main problems are distribution and recovery: the native feature fails when installed into a separate application, guard discovery cannot recover from a stale initial result without resetting the subsystem, and an ordinary registration refresh breaks the first reconnect from a client with cached presence. The general CI matrix is also blocked before tests begin. These are confirmed observations, separate from the architecture recommendations below.

This review focused on the public facade, native controller and runtime, guard discovery, presence publication and caching, stream adapter and endpoint lifecycle, package installation, workflows, and current documentation. It is a targeted source and behavior audit, not an exhaustive review of every protocol implementation or a cryptographic certification. The two additional network reproductions use a local loopback testnet. No production traffic capture, external relay deployment, or Linux namespace test was performed. Runtime sources were left unchanged by this audit; the accompanying changes contain documentation and reproduction scripts.

**Confirmed findings**

| Priority | Finding                                                                    | Evidence                                                                                                                                     |
| -------- | -------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| High     | Native routing fails in a consumer installation                            | Packed the checkout and installed it in a separate empty application; the controller throws because its required sodium primitive is absent. |
| Medium   | Stale guard discovery persists across connection retries                   | Two failed attempts reused the same initial directory result; explicit suspend/resume refreshed discovery and succeeded.                     |
| Medium   | Server refresh breaks the first cached reconnect                           | First reconnect returned `ERR_REPLAY`; the next attempt succeeded.                                                                           |
| Medium   | General CI cannot install the dependencies                                 | The audited commit's Ubuntu build failed with `EALLOWGIT`, before tests.                                                                     |
| Medium   | Public status values differ by profile and violate the documented contract | Native returns lowercase internal states; the other public profiles return the documented uppercase states.                                  |

**Native routing fails when installed as a dependency**

The required sodium fork is specified only in [`package.json`'s overrides](https://github.com/ayooooo123/hyperdht/blob/3ea467edfe338a29e0e48bd1b7a15668eef9dc2c/package.json#L65-L78). npm ignores overrides belonging to installed dependencies; it applies the consuming application's root overrides. This is documented in [npm's package manifest reference](https://docs.npmjs.com/cli/configuring-npm/package-json/#overrides).

The checkout resolved the fork reporting `sodium-native` version `5.1.0`, with `crypto_core_ed25519_scalar_mul` available. The separate consumer resolved upstream `sodium-native@5.2.0`, where that function was undefined. Loading the native controller failed at the explicit capability check in [`blinded-presence.js:35–39`](https://github.com/ayooooo123/hyperdht/blob/3ea467edfe338a29e0e48bd1b7a15668eef9dc2c/lib/private/blinded-presence.js#L35-L39):

```text
Gate D requires sodium.crypto_core_ed25519_scalar_mul (native scalar×scalar); no fallback
```

Both installations used `--ignore-scripts`; the native libraries loaded from their supplied prebuilds. The failure is the missing exported primitive, not a failed native build.

Repair: make the necessary implementation part of the package's actual runtime dependency graph, ideally through a dedicated crypto adapter and a published, versioned dependency exposing the primitive. Merely adding another top-level copy is insufficient unless the adapter demonstrably resolves that copy. Add a release check that runs `npm pack`, installs the tarball into an empty consumer with no overrides, then initializes and exercises native routing on Node and Bare.

Minimal package reproduction, run from an installed checkout:

```sh
npm pack --ignore-scripts --pack-destination ..
mkdir ../consumer
npm install --prefix ../consumer --ignore-scripts --no-audit --no-fund ../hyperdht-6.34.1.tgz
node -e "require('../consumer/node_modules/hyperdht/lib/private/private-native-controller')"
```

**Stale initial guard discovery cannot recover through normal retries**

[`NativeController.start()`](https://github.com/ayooooo123/hyperdht/blob/3ea467edfe338a29e0e48bd1b7a15668eef9dc2c/lib/private/private-native-controller.js#L461-L487) discovers guard locators once and constructs the runtime from at most three candidates. [`ready()`](https://github.com/ayooooo123/hyperdht/blob/3ea467edfe338a29e0e48bd1b7a15668eef9dc2c/lib/private/private-native-controller.js#L433-L453) retains its fulfilled startup promise. Each subsequent pin attempt copies the same [`state.config.source.guards`](https://github.com/ayooooo123/hyperdht/blob/3ea467edfe338a29e0e48bd1b7a15668eef9dc2c/lib/private/peer-native-runtime.js#L1025-L1077), with no directory refresh after exhaustion.

The reproduction injects one stale locator in the initial DHT lookup: a real loopback DHT node that does not serve private guards. It then restores the healthy, real directory and uses the production runtime and transport for all connection attempts. This models a stale advertisement without requiring an external network.

```text
directory now healthy: discoveryCalls=1, status=ready
attempt 1: opened=false, ERR_PRIVATE_GUARD_UNAVAILABLE, discoveryCalls=1
attempt 2: opened=false, ERR_PRIVATE_GUARD_UNAVAILABLE, discoveryCalls=1
after explicit suspend/resume: opened=true, discoveryCalls=2
```

Impact: a long-lived application can remain unable to connect after its initial candidate set goes stale, even when healthy relays are discoverable. Calling `ready()` again does not repair it, and status still reports ready.

Repair: give guard discovery an explicit lifetime and a bounded refresh path after candidate exhaustion or relevant network changes. Preserve pinning and exposure limits, and distinguish discovery readiness from a currently usable route. Regress with stale initial candidates, healthy replacement advertisements, and a reconnect on the same public object.

Reproduction: `node scripts/audit/native-guard-discovery.cjs .` from the checkout root.

**Normal server refresh breaks the first reconnect from a cached client**

The client returns a cached descriptor for up to 30 seconds in [`resolve()`](https://github.com/ayooooo123/hyperdht/blob/3ea467edfe338a29e0e48bd1b7a15668eef9dc2c/lib/private/private-native-controller.js#L1190-L1250). On successful refresh, the server publishes a replacement and immediately retires the old registration when it has no applications ([refresh and retirement](https://github.com/ayooooo123/hyperdht/blob/3ea467edfe338a29e0e48bd1b7a15668eef9dc2c/lib/private/private-native-controller.js#L1574-L1589)). This invalidates a still-cached route. The client catches the failed activation and evicts its cache, but [returns the failure without retrying discovery](https://github.com/ayooooo123/hyperdht/blob/3ea467edfe338a29e0e48bd1b7a15668eef9dc2c/lib/private/private-native-controller.js#L1396-L1410).

Reproduction used a real local native topology: connect successfully; close that stream; await `server.refresh()`; reconnect with the same client before the cache expires. The refresh completed in 10,585 ms and the server remained listening.

```text
initial connection opened true
first reconnect: opened=false, error=ERR_REPLAY, incoming=0
second reconnect: opened=true, error=null, incoming=1
```

Impact: normal route maintenance produces a user-visible failed connection. The existing refresh regression uses a fresh second client, so it misses this cache interaction ([test](https://github.com/ayooooo123/hyperdht/blob/3ea467edfe338a29e0e48bd1b7a15668eef9dc2c/test/private/private-native-controller.js#L279-L300)).

Repair: perform one bounded fresh-presence retry when activation of a cached descriptor fails before application data is released. Keep signature, rollback, and route verification intact. Alternatively, define and enforce a registration grace period consistent with the published cache lifetime. Test with the same client on both sides of the refresh, and with concurrent queued connects.

Reproduction: `node scripts/audit/native-route-refresh.cjs .` from the checkout root.

**General CI is blocked during installation**

The audited commit's [Build Status run](https://github.com/ayooooo123/hyperdht/actions/runs/39825029207) failed in the setup action, before `npm test`, integration tests, or Bare tests. The Ubuntu job log shows:

```text
npm install --ignore-scripts --foreground-scripts --allow-git=none
npm error code EALLOWGIT
npm error Fetching packages of type "git" have been disabled
```

The refused dependency was the pinned `ayooooo123/dht-rpc` Git dependency. [`test-node.yml:21`](https://github.com/ayooooo123/hyperdht/blob/3ea467edfe338a29e0e48bd1b7a15668eef9dc2c/.github/workflows/test-node.yml#L21-L24) uses `holepunchto/actions/bare-base@v1` without configuring its `allow-git` input. The [action defaults that input to `none`](https://github.com/holepunchto/actions/blob/v1/bare-base/action.yml).

The separate [Private Routing run](https://github.com/ayooooo123/hyperdht/actions/runs/39825029062) succeeded at the same commit. That success does not provide the missing general build and integration results.

Repair: align dependency distribution with the installation policy. Prefer versioned registry releases for runtime forks; if Git dependencies remain intentional, explicitly configure the supported action input and pin the action revision. Ensure the default development branch runs the general compatibility matrix as well as the private aggregate; the current general workflow's push filter names only `main`.

**Public status contract differs across profiles**

The [README](https://github.com/ayooooo123/hyperdht/blob/3ea467edfe338a29e0e48bd1b7a15668eef9dc2c/README.md#L185-L198) documents `BOOTSTRAPPING`, `READY`, `SUSPENDED`, and `DESTROYED`. The public facade [returns the controller state unchanged](https://github.com/ayooooo123/hyperdht/blob/3ea467edfe338a29e0e48bd1b7a15668eef9dc2c/index.js#L95-L102), while the native controller uses lowercase states and additional intermediate values.

Local public-API observation:

```text
native-v2: initial idle; after destroy destroyed
standard:  initial BOOTSTRAPPING; after destroy DESTROYED
spliced:   initial BOOTSTRAPPING; after destroy DESTROYED
```

Native live reproductions also returned `ready`. A caller waiting for the documented `READY`, or testing for `DESTROYED`, will not match it on native routing.

Repair: define one stable public state enumeration and map each controller's internal lifecycle into it. Keep richer internal state in a separately documented diagnostic field. Add a public-facade contract test across every supported profile.

**Architecture improvements, in recommended order**

1. **Separate installation correctness from checkout correctness.** The missing sodium primitive is a concrete example of why the release artifact must be tested as an installed dependency. Use one explicit crypto adapter, document its required native exports, and validate them before allocating network resources. Keep a deterministic development dependency graph and test supported Node/Bare versions with the packed artifact.

2. **Give discovery, registration, and connection setup separate owners.** The native controller is 1,991 lines and owns startup, directory queries, slots, caches, route construction, publication, server refresh, legacy egress, and teardown. The native runtime adds 1,749 lines; semantic services add 2,968. Extract a guard-directory owner with refresh policy, a presence-cache owner with generation-aware invalidation, a registration owner, and a connection-attempt owner with bounded retry and cancellation. These boundaries directly address the two reproduced recovery failures rather than merely relocating code.

3. **Unify lifecycle and time contracts.** Keep public readiness/status behavior common across profiles, and thread cancellation through bootstrap, lookup, route build, publication, and teardown. Reuse the native runtime's clock abstraction in the controller, which currently calls `Date.now()` and global timers directly. Then test expiry, cached descriptors, relay renewal, and suspension with a scoped clock instead of long real-time waits.

4. **Make observations distinguishable from declarations.** [`exposureReport()`](https://github.com/ayooooo123/hyperdht/blob/3ea467edfe338a29e0e48bd1b7a15668eef9dc2c/lib/private/private-native-controller.js#L1823-L1843) returns a literal `directDestinationSends: 0`. It is not a measured send counter. Replace that with a clearly named policy statement, or connect it to actual transport observations. Add safe counters for discovery refreshes, cache-hit activation failures, guard exhaustion, renewal failures, and slot wait time, without exposing route identities or addresses.

5. **Separate current supported behavior from historical protocol stacks.** The repository exposes `standard`, `spliced`, and `native-v2` through different controllers while also retaining the older routed-DHT controller. Establish an explicit support/deprecation matrix and keep each protocol version's tests and documentation attributable to it. Generate public option/state tables from a single contract. Preserve historical design material, but do not use it as the entry point for current integration.

6. **Add a small failure-oriented release suite.** Include the packed-consumer startup, same-client reconnect after refresh, stale-directory recovery, public status transitions, and actual default-branch CI installation. Run these before the large aggregate. The existing test volume is substantial; these missing combinations matter more than adding more isolated happy-path assertions.

**Documentation improvements**

| Problem                                                                                                                                                                                                                   | Concrete revision                                                                                                                                                                                                                                                               |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The first install command is `npm install hyperdht`, with upstream metadata and documentation links.                                                                                                                      | Identify this fork and its supported release/commit installation procedure prominently. Explain the dependency requirements; the current consumer installation bug must be fixed before presenting it as working.                                                               |
| The relay example in README lines 98–106 is missing the closing brace for `privateRouting`.                                                                                                                               | Add the brace and execute fenced examples in CI. Parsing the current example produced `SyntaxError: Unexpected token ')'`.                                                                                                                                                      |
| README says only `native-v2` is accepted and `standard` is rejected, but both `standard` and `spliced` were accepted in the public API. Nearby prose also describes the older four-relay design and flow-control windows. | Provide a profile support table and separate, clearly labeled examples. State the current native path, limits, role restrictions, and compatibility explicitly.                                                                                                                 |
| `status()` documents values the native controller does not return.                                                                                                                                                        | Fix the facade contract and generate the reference from the same enumeration.                                                                                                                                                                                                   |
| `relayConfig` is introduced without a complete runnable provisioning example.                                                                                                                                             | Add a small local topology tutorial covering relay identities, authority keys, bilateral grants, expiry, endpoint binding, JSON encoding, startup order, and shutdown. Show the minimum topology needed to build a route.                                                       |
| Reader-secret wording says it restricts presence lookup.                                                                                                                                                                  | State precisely that it protects descriptor decryption. The storage address is derived from the stable public key and period; possession of the public key permits deriving that address. The code already explains this boundary in `blinded-presence.js:3–19`.                |
| The migration record is 6,007 lines; its opening “current implementation” still describes `standard` and says native services are not publicly wired.                                                                     | Move dated evidence into an archive and write a short current architecture/status page. Link evidence by profile, commit, platform, command, result, and known limitation. Replace session-specific gate/task labels in user-facing docs with descriptive names.                |
| Operational failure behavior is spread across implementation notes.                                                                                                                                                       | Add an integration guide for queue limits, lifetime budgets, expiry/renewal, reader credentials, firewall timing, retryable errors, half-close behavior, suspension, and shutdown. Explain what the private context anonymizes and which ordinary DHT operations remain direct. |

**Validation record**

- Host: macOS, Node `v26.12.1`, npm `11.20.0`.
- Source checkout installed with `npm install --ignore-scripts --no-audit --no-fund`; supplied native prebuilds loaded successfully.
- `prettier --check .`: passed.
- `node test/all.js`: passed, 1,556/1,556 reported tests and 26,709/26,709 assertions, exit code 0; duration approximately 8 minutes 24 seconds. The aggregate retains its existing skipped cases.
- Packed consumer test: confirmed missing required sodium export and native-controller load failure.
- Same-client refresh reproduction: confirmed failed first reconnect followed by successful retry.
- Stale-directory reproduction: confirmed two failures without a second lookup, then recovery after suspend/resume.
- Public profile/status probe: confirmed all three profiles are accepted and native status differs.
- README relay example syntax check: failed as described.
- `git diff --exit-code` and `git status --porcelain`: clean before adding this report and its reproduction scripts.
- Hosted evidence inspected: private-routing CI success and general build setup failure at the exact audited commit. Linux capture and Bare success in hosted CI were not independently rerun locally.

The two scripts under `scripts/audit/` take a path to the installed, pinned checkout. They reuse the fixture preamble from `test/private/private-native-controller.js`, run on loopback, and leave production source files unchanged. Their watchdogs end a run if cleanup or networking fails to settle.
