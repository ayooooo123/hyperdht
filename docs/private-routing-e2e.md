# Private-routing C1 evidence

This is the portable alpha (`profile: 'standard'`) evidence suite. It does not
claim native-v2 completion, independent packet capture, multi-host anonymity, or
external cryptographic review. External human review remains deferred.

## Commands

```sh
npm run test:e2e
npm run test:e2e:bare
npm run test:e2e:b1
npm run test:e2e:b1:bare
npm run bench:private-routing -- --out=/tmp/private-routing-benchmark.jsonl
```

`test:e2e` and `test:e2e:bare` execute the same baseline-compatible scenario files.
Regenerate their aggregate with `npm run test:e2e:generate`. This is a new local
suite, not a rename of the existing public-bootstrap `end-to-end` command.

The `b1` commands are explicit, non-skipped intended-contract tests. They are
expected to fail on the pre-hardening baseline. They must pass after the B1
controller changes merge; their assertions are not weakened to accommodate the
baseline. They are separate from the baseline-compatible aggregate so a passing
smoke cannot be mistaken for passing the hardening gates.

| B1 scenario                                    | Required behavior / baseline defect                                                                                                                                                                                                                                                                                                                 |
| ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `private-streams.js`                           | Exact 16 MiB transfers in both directions with unequal reverse traffic, and four concurrent 4 MiB duplex streams. Baseline bounded cell queues can destroy bulk transfers.                                                                                                                                                                          |
| `multiplex-budget.js`                          | Seventy sequential sessions retain a live sibling and never recycle stream IDs. Baseline treats 64 admitted streams as a lifetime limit.                                                                                                                                                                                                            |
| `slow-consumer.js`                             | A paused 1 MiB reader exposes backpressure without blocking a live sibling, then delivers every byte after resumption. This probes runtime-sensitive queue exhaustion; it passed the focused baseline Node run but failed the initial Bare run.                                                                                                     |
| `refresh-without-drop.js`                      | New descriptor generations preserve admitted streams. Baseline refresh destroys the old destination circuit.                                                                                                                                                                                                                                        |
| `half-close.js` and `reset-propagation.js`, R5 | One source `end()` delivers one FIN while the reverse direction remains writable; one `destroy()` delivers one RESET, retires the peer stream, and preserves siblings even with late frames. FIN fails on the baseline. The bounded, backpressured RESET case passes on both runtimes and remains a regression guard, not a claimed production fix. |
| `crypto-views.js`, E1                          | No stable destination key in relay control reads/writes or opened plaintext over twenty connects and five refreshes. Baseline resolver and destination admission disclose it.                                                                                                                                                                       |
| `crypto-views.js`, E3                          | Independent header epochs and counter origins for matching forwarded frames; fixed 1200-byte cells. Baseline exposes wall-clock epochs and aligned counters.                                                                                                                                                                                        |
| `descriptor-periods.js`, E4                    | An advancing scoped clock crosses a real presence-period boundary, storage revisions do not form a seq-plus-one link, and a live stream survives. Baseline lacks the scoped clock seam and fails explicitly, without replacing `Date.now`.                                                                                                          |
| `client-identity.js`, E5                       | Fresh authenticated application identities by default, explicit identity override, and an explicit listener key. Baseline uses the node default identity implicitly.                                                                                                                                                                                |
| `guard-pinning.js`, E6                         | Ten refreshes retain healthy source/destination guards; guard loss republishes immediately using the previously pinned alternate. Baseline shuffles guards and lacks the alternate snapshot.                                                                                                                                                        |
| `directory-sampling.js`, E7 sampling           | A real storage node returns a biased set of real relay keys, while the client samples more than one directory target. Baseline samples one constant target. This is not a path-diversity proof.                                                                                                                                                     |

## Harness and no-direct oracle

The harness uses this repository's `testnet.js`, eight local storage peers, six
real relay nodes, and ephemeral, non-storage application endpoints. The first
bootstrap receives `bootstrap: []`; every later node uses only that local numeric
bootstrap. Storage peers run the production descriptor service, avoiding silent
unsupported-plugin timeouts. Ports come from bound sockets, never a free-port
probe. Cleanup joins application streams, listeners, and all DHT nodes.

Helpers directly import only brittle, b4a, compact-encoding, Protomux, udx-native,
the library under test, and platform modules mapped to bare-* in `package.json`.
They do not import `test/helpers/index.js`, streamx, or other non-holepunchto test
utilities. Protomux frames carry independent payloads, explicit sequence numbers,
exact byte comparisons, and a final frame in each direction. Runtime/transitive
library dependencies are not reclassified as test helpers.

The UDP oracle is installed before the first testnet socket. It observes:

- every UDX socket `send` and `trySend`, including replacement sockets;
- native-stream `connect`, `changeRemote`, `relayTo`, datagram sends, write batches,
  and finalization;
- destination-owned bound tuples and socket generations, with IPv4-mapped IPv6
  normalization;
- attempted operations before native completion, including failed attempts.

The strict assertion covers setup, data, refresh, route loss, explicit retry,
suspension, resumption, and final teardown. No alleged maintenance packets are
subtracted. Both mandatory negative controls execute the same detector: a real
explicit UDP datagram, and an ordinary HyperDHT connection carrying verified data.
Ordinary direct APIs remain direct; the optional context does not anonymize DHT
maintenance or unrelated direct connections.

These JavaScript/native-association observations are not independent interface
capture. Native retransmissions are covered by their established association,
not counted as individually captured packets. Capture attribution and its
missing/duplicate-owner controls belong to C2.

## Test-only B1 observation interface

`test/e2e/support/private-peer.js` binds to B1's
`test/private/helpers/private-peer.js`. It uses scoped controller creation,
read-only relay events, the advancing per-controller clock, and copied guard
snapshots. Until that entry point lands, test-owned baseline capture observes
actual relay stream reads/writes and authenticated cell openers. No production
source is patched and no observer supplies candidate selection, forwarding
credits, route authority, or a successful fallback. E4 reports the missing clock
seam as a failure rather than pretending a global clock substitution is valid.

The provisional contract was supplied by the slice-B owner for C1. Post-merge
execution is required to verify the implemented B1 event and guard interfaces.

## Diversity boundary and open C2 gate

Diversity uses established raw-stream remote tuples, never advertised directory
addresses. For a loopback-bound node, its diversity key is the actual
(address, port); for real networks it is the IPv4 /24 or IPv6 /48 prefix. The
property is no repeated diversity key among accepted path positions, not a bound
on how many relays one operator controls.

The supported API has one private relay identity per DHT node. A synthetic
multi-controller/plugin-overwrite fixture is not used. C1 therefore tests biased
storage and multi-target sampling separately, relying on B1 address-policy unit
tests for prefix and loopback policy. The end-to-end equal-prefix rejection gate
is an open C2 Linux multi-subnet scenario owned by the coordinator. A source
cannot independently certify a downstream relay's reported tuple observation;
that remains a stated limitation.

## Observed C1 correctness results

The production base is `6053ee8`; C1 changes only test, benchmark, package and
documentation files. This pre-B1 checkout was exercised on macOS arm64 with Node
v22.19.0 and Bare v1.30.3. The existing private-routing aggregate was run once at
the milestone.

| Command                                                                      | Observed result                                                                                                                                                            |
| ---------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `npm run test:e2e`                                                           | Exit 0; 14/14 scenarios, 69/69 assertions; 152.30 s.                                                                                                                       |
| `npm run test:e2e:bare`                                                      | Exit 0; 14/14 scenarios, 69/69 assertions; 158.74 s.                                                                                                                       |
| `node test/private-routing.js`                                               | Exit 0; 1323/1323 tests, 23319/23319 assertions; 122.49 s.                                                                                                                 |
| `npm run test:e2e:b1`                                                        | Exit 1; the intended bulk, lifetime-budget, refresh, E1/E3/E4/E5/E6/E7 and FIN gates fail. The paused-reader and idle-reset cases passed in this aggregate run.            |
| `npm run test:e2e:b1:bare`                                                   | Exit 1; the same hardening gates fail. The initial E7 fixture failure was corrected and rerun below; the initial paused-reader and unjoined-close reset cases also failed. |
| `npx brittle test/e2e/b1/directory-sampling.js test/e2e/b1/slow-consumer.js` | Exit 1; real biased reply observed, multiple-directory-target assertion fails; paused-reader case passes (1/2 scenarios, 5/6 assertions).                                  |
| `npx brittle-bare test/e2e/b1/directory-sampling.js`                         | Exit 1; real biased reply observed, multiple-directory-target assertion fails (1/2 assertions).                                                                            |
| `npx brittle test/e2e/b1/reset-propagation.js`                               | Exit 0; final backpressured 64 KiB RESET case, 8/8 assertions.                                                                                                             |
| `npx brittle-bare test/e2e/b1/reset-propagation.js`                          | Exit 0; the same final RESET case, 8/8 assertions.                                                                                                                         |

E1 observed 26 stable-key disclosures during twenty connects and five refreshes.
E3 observed aligned counters on three links, aligned initial counters across ten
directions, and wall-clock-derived epochs. Healthy guards changed across ten
refreshes. E4 cannot execute its period transition until B1 supplies the agreed
advancing-clock seam; it reports that missing prerequisite explicitly.

An initial Bare aggregate failure came from destroying application streams while
Protomux close writes remained queued. The harness now joins those writes using
`SecretStream.flush()`. A subsequent explicit DATA/backpressure RESET scenario
passes on both runtimes; the earlier reset timeout is not evidence that RESET
universally fails. FIN still reaches the 20-second deadline without peer EOF.

## Benchmark interpretation

`bench:private-routing` runs direct and alpha against equivalent local swarms,
with six relay processes and separate source/destination processes. It defaults
to three repetitions per direction and alternates mode order. Each trial publishes
a new service identity and verifies deterministic payload bytes at the receiver.
A bounded explicit finish frame and a verification receipt delimit the trial;
transport teardown is joined separately, not charged to payload throughput.

The printed comparison includes build time, first byte, 64-byte ping, 1/16 MiB,
four concurrent 4 MiB streams, summed relay CPU per MiB, and a 5 ms per-hop
UDX-write-delay condition. `--out` exclusively creates raw JSONL evidence; omit
it for console-only reporting. Available selectors are shown by
`npm run bench:private-routing -- --help`.

- Build is `connect()` to Noise `opened`, excluding publication and readiness
  framing. First byte starts on an already opened stream.
- Throughput spans the earliest sender timestamp to the latest verified payload
  receipt across all streams. Timestamps use the same host's monotonic clock.
- Relay CPU includes background work and measurement IPC. Direct relay CPU is
  idle/background cost, not direct forwarding. No background subtraction is made.
- Failed or partial transfers retain failure details and verified byte counts but
  receive no throughput or CPU/MiB value. The command exits nonzero on failed
  attempts or failed cleanup; this is expected for baseline bulk failures.
- Delay is bounded application-send/UDX-write latency at each hop, not WAN/netem.
  UDP discovery, native ACKs, and retransmissions are not delayed. Original UDX
  write backpressure is preserved; queues are capped at 2 MiB / 256 writes per
  process. It is a stated emulation model, not an Internet performance claim.

Compare pre/post changes on the same machine and topology. Successful local runs
alone do not establish a general anonymity advantage over another implementation.

## C1 pre-B1 benchmark

Exact command:

```sh
npm run bench:private-routing -- --out=/tmp/hyperdht-council/vega/baseline-c1.jsonl
```

This run exited 1 in 42.86 s because alpha transfers failed, not because failed
transfers were normalized into successful throughput. Node v22.19.0, macOS arm64,
10 logical CPUs, three repetitions per condition and direction. Direct completed
42/42 attempts; alpha completed 28/42. All sixteen worker processes exited 0
without forced termination.

The table gives medians as **up / down**. Direct values use 3/3 successful
attempts in each direction. Alpha uses 3/3 except the 1 MiB rows (2/3 in each
direction) and the 16 MiB / four-stream rows (0/3 in each direction). A dash
means no completed transfer, not zero cost. The raw JSONL retains partial byte
counts and each failure.

| Metric                                     | Direct, up / down | Alpha, up / down |
| ------------------------------------------ | ----------------: | ---------------: |
| Build, ms                                  |       3.05 / 2.56 |    35.63 / 24.06 |
| First byte, 64 B, ms                       |       0.24 / 0.26 |      3.44 / 2.02 |
| 64-byte ping, ms                           |       0.53 / 0.27 |      5.07 / 4.03 |
| 1 MiB, MiB/s                               |     32.58 / 31.93 |      6.17 / 6.17 |
| 1 MiB relay CPU, ms/MiB                    |       0.68 / 0.66 |  649.63 / 558.04 |
| 16 MiB, MiB/s                              |     31.17 / 29.61 |            — / — |
| 16 MiB relay CPU, ms/MiB                   |       0.06 / 0.08 |            — / — |
| Four concurrent 4 MiB streams, MiB/s       |     32.02 / 32.45 |            — / — |
| Four-stream relay CPU, ms/MiB              |       0.09 / 0.08 |            — / — |
| 64-byte ping with 5 ms UDX-write delay, ms |     15.76 / 17.84 |    69.35 / 65.91 |
| 4 MiB with 5 ms UDX-write delay, MiB/s     |     11.04 / 11.30 |      1.45 / 1.46 |
| Delayed 4 MiB relay CPU, ms/MiB            |       0.50 / 0.24 |  504.73 / 443.88 |

Alpha's fourteen failed attempts were two 1 MiB transfers, six 16 MiB transfers,
and six four-stream transfers. They reported `ECONNRESET` and/or
`ERR_PRIVACY_UNAVAILABLE`. Failure before one full MiB is therefore possible on
this baseline. The delayed condition's successes do not repair that defect:
the write-delay model also changes pacing.

Before collecting this table, a real direct-stream verifier smoke accepted a
valid transfer and rejected a corrupt payload, excess payload, and a missing
finish frame. The small benchmark smoke completed all twelve direct/alpha
probe, ping, and 1 MiB attempts with one repetition per direction.
