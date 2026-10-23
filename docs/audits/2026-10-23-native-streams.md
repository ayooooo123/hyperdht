**HyperDHT native stream audit — 23 October 2026**

Repository: [ayooooo123/hyperdht](https://github.com/ayooooo123/hyperdht). Audited default branch: `implement-private-peer-v2`, at [3ea467edfe338a29e0e48bd1b7a15668eef9dc2c](https://github.com/ayooooo123/hyperdht/commit/3ea467edfe338a29e0e48bd1b7a15668eef9dc2c).

The default branch has not changed since the [first audit, PR #58](https://github.com/ayooooo123/hyperdht/pull/58), which was still open when this pass began. This report adds two distinct, reproduced findings: cancelled connections retain admission while startup is blocked, and the documented string write fails on an authenticated native stream. It does not recount the first audit's findings as new discoveries.

This pass reviewed the public facade, connection admission and cancellation, endpoint authentication and shutdown, record ownership and fragmentation, semantic session quotas and deadlines, registration replacement, native guard pinning, and relay renewal. It is a targeted behavior and source audit. Both reproductions use the public `dht.privateRouting` API on loopback; the cancellation probe deliberately holds one node's bootstrap promise to make the lifecycle ordering deterministic. No production network, Linux capture, Bare runtime, or cryptographic certification is claimed.

**Confirmed findings**

| Priority | Finding                                                                                        | Observed result                                                                                                                           |
| -------- | ---------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Medium   | Cancelling connections after startup begins does not release admission until bootstrap settles | All 32 cancelled streams remained unclosed; a replacement connect threw `ROUTE_UNAVAILABLE`. Releasing bootstrap allowed all 32 to close. |
| Medium   | Native streams reject the README's string payload                                              | An authenticated stream emitted `INVALID_ROUTE` and delivered no payload. The same payload as a Buffer succeeded.                         |

**Cancelled streams remain tied to shared bootstrap**

The facade obtains readiness from the underlying DHT's bootstrap promise ([index.js:680–686](https://github.com/ayooooo123/hyperdht/blob/3ea467edfe338a29e0e48bd1b7a15668eef9dc2c/index.js#L680-L686)). Once the connecting facade's opening callback has started, it awaits `this.ready()` before checking cancellation again ([private-native-controller.js:1340–1348](https://github.com/ayooooo123/hyperdht/blob/3ea467edfe338a29e0e48bd1b7a15668eef9dc2c/lib/private/private-native-controller.js#L1340-L1348)).

Destroying that stream cancels its operation, but calls `erase()` immediately only if opening has not started ([1415–1423](https://github.com/ayooooo123/hyperdht/blob/3ea467edfe338a29e0e48bd1b7a15668eef9dc2c/lib/private/private-native-controller.js#L1415-L1423)). Once opening has started, the `connecting` admission counter is decremented only when the async opening job reaches its `finally` block ([1327–1335](https://github.com/ayooooo123/hyperdht/blob/3ea467edfe338a29e0e48bd1b7a15668eef9dc2c/lib/private/private-native-controller.js#L1327-L1335), [1406–1410](https://github.com/ayooooo123/hyperdht/blob/3ea467edfe338a29e0e48bd1b7a15668eef9dc2c/lib/private/private-native-controller.js#L1406-L1410)). The stream adapter also waits for that opening job before completing `_open()` ([peer-record-adapter.js:859–873](https://github.com/ayooooo123/hyperdht/blob/3ea467edfe338a29e0e48bd1b7a15668eef9dc2c/lib/private/peer-record-adapter.js#L859-L873)).

The probe lets the real local DHT bootstrap, holds that instance's `_bootstrapping` promise, and waits until private startup is awaiting it. It opens and then destroys 32 connection attempts, observes them for 150 ms while the gate remains held, and tries one replacement. It then releases bootstrap and joins teardown. The per-instance gate is fault injection; the public facade, operation, stream, and admission implementation run unchanged.

```json
{"bootstrapEntered":true,"cancelled":32,"closedBeforeBootstrapRelease":0,"replacementError":"ROUTE_UNAVAILABLE","status":"starting"}
{"closedAfterBootstrapRelease":32,"status":"destroyed"}
```

Impact: an application that cancels and retries while bootstrap is slow can exhaust the entire pre-admission allowance using already-cancelled work. `opened` can resolve `false` while `close` and admission release still wait on unrelated shared startup. The wait follows the bootstrap promise rather than an independent cancellation completion path. This experiment demonstrates that dependency; it does not claim a particular real-world bootstrap delay.

The existing [pending cancellation test](https://github.com/ayooooo123/hyperdht/blob/3ea467edfe338a29e0e48bd1b7a15668eef9dc2c/test/private/private-native-controller.js#L417-L448) destroys the stream immediately after `connect()`, before yielding to the opening callback. It covers the earlier ordering, where `opening` is still false. The pre-admission queue test uses the same ordering.

Repair: let per-connection cancellation settle the opening facade and release its admission independently of shared readiness. Keep the shared startup job observed, and preserve generation checks and cleanup for any material it produces later. Apply the same reasoning to waiting for slots, serialized presence lookups, and route construction; do not release actual native resource reservations until their work has joined. Regress both cancellation orderings and assert that a replacement connection is admitted before the held bootstrap gate is released.

Run from an installed checkout:

```sh
node scripts/audit/native-startup-cancellation.cjs .
```

**The documented string write fails after authentication**

The audited [README example](https://github.com/ayooooo123/hyperdht/blob/3ea467edfe338a29e0e48bd1b7a15668eef9dc2c/README.md#L83-L90) calls `socket.write('private peer payload')`. `PeerPlaintextDuplex` constructs its stream without a writable string mapping ([peer-record-adapter.js:803–808](https://github.com/ayooooo123/hyperdht/blob/3ea467edfe338a29e0e48bd1b7a15668eef9dc2c/lib/private/peer-record-adapter.js#L803-L808)). Its `_write()` immediately rejects non-buffer input with `INVALID_ROUTE` ([899–904](https://github.com/ayooooo123/hyperdht/blob/3ea467edfe338a29e0e48bd1b7a15668eef9dc2c/lib/private/peer-record-adapter.js#L899-L904)). The pinned SecretStream dependency's own constructor supplies `mapWritable: toBuffer`, which converts strings using `b4a.from`; the facade loses that behavior before input reaches SecretStream.

The reproduction creates real private source and destination contexts on the existing loopback native topology. It authenticates two connections to the same server and writes the same text, first as a Buffer, then as a string:

```json
{"inputType":"object","opened":true,"error":null,"received":"private peer payload"}
{"inputType":"string","opened":true,"error":"INVALID_ROUTE","received":""}
```

Impact: copying the documented application payload call terminates a working connection. This is an input compatibility failure after successful authentication, not a route-discovery or cryptographic-handshake failure.

Repair: give the public writable facade an explicit string-to-byte conversion matching the supported SecretStream contract, while retaining byte validation, quota checks, and record-size limits. Test `write(string)`, `end(string)`, early writes before authentication, and multi-byte UTF-8 near fragmentation boundaries, with Buffer controls. The accompanying README change uses `Buffer.from(...)` as a working example with the current implementation; runtime string support remains follow-up work.

```sh
node scripts/audit/native-string-write.cjs .
```

The script reuses the topology helper preamble from the pinned controller test file without registering that file's tests. It asserts both the Buffer success and the string failure. Both audit scripts have watchdogs and are historical reproductions: a fix should make their expected-bug assertions fail, then be covered by a normal regression test asserting the repaired behavior.

**Architecture improvements supported by this pass**

1. **Separate caller cancellation from shared startup ownership.** A connection should own an abortable wait for readiness, not the readiness job itself. Give admission release, public stream closure, and native cleanup separate, explicit completion conditions. This addresses the reproduced cancellation failure without cancelling startup needed by other callers or freeing resources prematurely.

2. **Specify the stream boundary in one place.** The facade correctly handles many difficult record-ownership and shutdown cases, but omits the dependency's simple string normalization. Define supported input types, encodings, `opened`, `flush`, EOF, and half-close behavior at the facade boundary, then run a shared contract suite against native and ordinary streams. Keep the native quotas and fragmentation policy explicit where they differ.

3. **Extract reusable topology fixtures from test registration.** The existing topology and endpoint helpers are embedded above the first `test()` call. Audit probes must currently compile those preambles to reuse the real setup. Move reusable factories into ordinary helper modules, parameterize lifecycle gates, and have tests and diagnostic scripts import them. This avoids fragile source markers and makes cancellation tests at specific asynchronous boundaries straightforward.

4. **Document and evaluate relay renewal interruption.** [Relay renewal](https://github.com/ayooooo123/hyperdht/blob/3ea467edfe338a29e0e48bd1b7a15668eef9dc2c/lib/private/peer-native-runtime.js#L1424-L1457) explicitly tears down the old generation, including hosted tails and links, before provisioning its replacement. This is an intentional implementation constraint, not a newly reproduced defect. Define the application-visible interruption policy and consider whether socket dispatch can support bounded generation overlap. Any overlap must preserve unique authority, grant expiry, and joined teardown; changing those invariants is a protocol/lifecycle design task.

**Documentation improvements**

- Keep the native quick-start executable against the current implementation. This PR changes the string payload to a Buffer; add a loopback example check so valid syntax alone cannot miss this class of failure.
- State accepted write types, byte-based fragmentation limits, and the encoding of strings if support is added. Separate connection authentication (`opened`) from application policy acceptance and eventual stream closure.
- Describe cancellation during startup, queueing, discovery, and authentication. Until the cancellation issue is fixed, explain that cancelled startup attempts can retain admission until bootstrap settles; avoid promising immediate release.
- Describe idle timeout, total route lifetime, and relay renewal as separate limits. Include which events can terminate an established application stream and the safe reconnect behavior after each.
- Publish a testing table that distinguishes endpoint fixtures, record-adapter tests, controller loopback tests, packed-consumer checks, Bare, and Linux capture. Record partial runs and intermittent failures rather than treating a passing lower-level suite as end-to-end evidence.

**Validation record**

- Host: macOS, Node `v26.12.1`, npm `11.20.0`; dependencies from the audited checkout with the sodium override already installed.
- Public startup-cancellation reproduction: observed the retained admission and delayed close; cleanup completed after gate release.
- Public loopback string-write reproduction: Buffer delivered the payload; string emitted `INVALID_ROUTE` and delivered none.
- `node test/private/peer-endpoint-controller.js`: 29/29 tests, 196/196 assertions, exit 0.
- `node test/private/peer-record-adapter.js`: 30/30 tests, 504/504 assertions, exit 0.
- First `node test/private/private-native-controller.js` run: exited 1 after three completed tests, when the next test's connection did not authenticate. It ran concurrently with other checks. This observation has not been attributed to a confirmed root cause.
- Controller-suite rerun: 11/11 tests, 92/92 assertions, exit 0, approximately 3 minutes 47 seconds. The initial authentication failure did not recur; its cause remains unresolved.
- Total across the three passing focused suites: 70 tests and 792 assertions.
- Both final reproduction scripts completed with exit 0, meaning their assertions confirmed the documented failures and the Buffer control.
- `prettier --check .` passed; both reproduction scripts passed `node --check`.

The full aggregate's 1,556-test result in PR #58 belongs to the first audit; it was not rerun for this pass. The runtime implementation is unchanged by this PR. The two confirmed defects remain explicit follow-up work.
