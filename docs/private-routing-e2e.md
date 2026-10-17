# Private-routing C1 and C2 evidence

C1 is the portable alpha (`profile: 'standard'`) evidence suite. It does not
claim native-runtime completion, independent packet capture, multi-host anonymity, or
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
| `guard-pinning.js`, E6                         | Ten refreshes and role collisions preserve pinned policy order. Each circuit uses the first compatible pinned guard and four distinct relay roles; only real primary loss promotes an alternate. A separate destination-loss scenario requires automatic publication through the previously pinned alternate within twenty real seconds.            |
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
tests for prefix and loopback policy. The C2 Linux multi-subnet scenario below
adds an executable equal-prefix rejection gate; its privileged run remains
coordinator-owned. A source cannot independently certify a downstream relay's
reported tuple observation; that remains a stated limitation.

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
- Application/UDX delay uses immediate admission callbacks after copying the
  caller's bytes into an owned delay line. It does not serialize admissions
  behind a delay timer. The process-wide bound is **64 MiB / 16,384 writes**,
  including delayed and native-retained copies; overflow rejects the new write
  and fails that stream. Native drain orders submission, and FIN/flush cannot
  overtake delayed writes. Zero injection delay is native passthrough.
- This in-process method does not delay UDP discovery, native ACKs, or
  retransmissions. It is not a WAN RTT measurement. Every JSONL row identifies
  `application-udx-delay-line-v2` and its explicit delay/bound parameters.
- The opt-in `packet-tc-netem-v1` variant delays every loopback egress datagram,
  including discovery, transport ACKs, and retransmissions, in an anonymous
  Linux network namespace. The configured per-link RTT addition is twice the
  one-way delay. The qdisc never touches the host's network namespace.
- Native-completion counters include cancellation because this udx-native
  version discards the native completion status. Only verified receiver bytes
  and finish receipts establish successful delivery.

Run the packet-level variant through the privileged container, outside `all`:

```sh
PR_NETEM_DELAY_MS=5 PR_BENCH_OUT=/app/private-routing-netem-5ms.jsonl \
  bash scripts/linux-gates.sh bench:netem
```

`PR_NETEM_LIMIT` defaults to 100,000 packets. The gate also accepts
`PR_BENCH_REPS` and `PR_BENCH_CASES`; `PR_NETEM_DELAY_MS=0` provides the packet
method's zero-delay control. Output paths must not already exist, and `/app`
paths persist through the repository bind mount. Inside an existing privileged
container, `bash bench/private-routing/netem.sh --out=/app/results.jsonl` invokes
the same isolated setup.

Summaries group by the complete method and parameter tuple. Legacy callback-held
or unlabelled rows are kept separate. Before/after comparisons require the same
corrected method, parameters, machine, and topology, including a fresh baseline;
old delayed rows must not be compared against the corrected delay line.

The method correction was exercised with four real-native UDX regressions
(34/34 assertions): immediate multiple admissions, owned-buffer lifetime,
FIFO/flush/FIN ordering, byte/write bounds including unacknowledged native
buffers, and exact-once cleanup. Shell parsing and CLI help were checked.
Those method checks alone do not establish throughput. The matched corrected
application-delay runs below now provide before/after measurements; no
privileged Linux netem run is claimed here.

Compare pre/post changes on the same machine and topology. Successful local runs
alone do not establish a general anonymity advantage over another implementation.

## Matched corrected-method benchmark: targets remain unmet

Astra reran both sides with `application-udx-delay-line-v2`; **legacy
callback-held delay rows are not used in this comparison**.

- **Before:** isolated checkout `51da9f7`, retaining production base `6053ee8`,
  with only `bench/private-routing` overlaid from Vega `069e0dd`.
- **After:** measured implementation
  `1e9dfb281f1f540d27ae9ea5ff881ed54fbcd3fa`, containing descriptor `a9213ca`,
  controls `4b308f4`, retired-ID fixture `876e4fd` and F03/F15 `fcda109`, with
  local merges of Vega `40570ab` and `069e0dd`.
- Both use the same installed `node_modules`, through a symlink in the isolated
  baseline checkout. The precise summary records
  `sameEnvironmentAndOptionsExceptOutput: true`. The JSONL metadata records
  Node v22.19.0, macOS arm64, ten logical CPUs, six relay processes, three
  repetitions per direction, 64 KiB chunks, and 0/5 ms application-delay
  conditions. The delay line retains the same 64 MiB / 16,384-write bounds.
- Both fixtures explicitly enable the production privateRouting service on
  three non-relay bootstrap/storage nodes. This controlled storage setup does
  not establish general F07 storage availability.

Commands were run in their corresponding checkouts, with no additional selectors:

```sh
npm run bench:private-routing -- --out=/tmp/hyperdht-council/astra/baseline-corrected-v2.jsonl
npm run bench:private-routing -- --out=/tmp/hyperdht-council/astra/after-b1-corrected-v2.jsonl
```

| Outcome                           | Corrected baseline | Measured B1 |
| --------------------------------- | -----------------: | ----------: |
| Direct attempts completed         |              42/42 |       42/42 |
| Alpha attempts completed          |              27/42 |       42/42 |
| Transfer failures                 |                 15 |           0 |
| Workers completing clean teardown |              16/16 |       16/16 |
| Whole-run wall time               |            23.39 s |     64.35 s |
| Exit code                         |                  1 |           0 |

The reliability improvement is real, but **the M1 performance targets are not
met**. Whole-run time is not a throughput comparison: failed baseline trials
transfer less data than successful B1 trials.

Astra's reported alpha measurements, using the same corrected method:

| Metric                                | Corrected baseline | Measured B1 | M1 requirement         |
| ------------------------------------- | -----------------: | ----------: | ---------------------- |
| 1 MiB upload, MiB/s                   |               6.22 |        5.82 | At least 2× baseline   |
| 1 MiB upload relay CPU, ms/MiB        |             579.99 |      563.13 | At most 0.5× baseline  |
| 5 ms delay, 4 MiB upload, MiB/s       |               4.62 |        3.19 | At least 3× baseline   |
| 5 ms delay, 4 MiB download, MiB/s     |               4.74 |        5.21 | At least 3× baseline   |
| 5 ms delay, 64-byte ping upload, ms   |              70.46 |      110.99 | No worse than baseline |
| 5 ms delay, 64-byte ping download, ms |              68.61 |      113.05 | No worse than baseline |

Baseline 1 MiB download completed **0/3** attempts. The failed 1 MiB download,
16 MiB and concurrent-bulk baseline groups provide no valid throughput or
relay-CPU ratio. Missing successful baseline measurements are not
zero-throughput values and must not be turned into an infinite improvement.
The modest CPU and delayed-download gains do not meet their required factors;
the reported upload throughput and delayed ping values worsen. Performance
work remains necessary, without weakening fixed 1200-byte cells, per-hop
authentication, bounded buffering or end-to-end Noise.

The two JSONL files above are the raw evidence. Exact measurements, ratios and
revision/environment provenance are recorded in
`/tmp/hyperdht-council/astra/benchmark-corrected-v2-summary.json`, which explicitly
records `performanceTargetsMet: false` and clean workers on both sides.
These are Astra's supplied runs, not a new Vega benchmark execution. Transfer
completion does not close the performance gate or substitute for the merged
M1 correctness gates.

### F17 send-observer boundary: read-only inspection

Source inspection found **no send observer attached by the throughput harness**.
All files under `bench/private-routing` and `testnet.js` were byte-identical
between the isolated baseline, Astra and Vega checkouts. Neither benchmark
checkout nor either existing JSONL artifact was changed for this inspection.

The exact throughput path is:

- `bench/private-routing/index.js:82-87` forks fresh workers with `execArgv: []`.
  Its bootstrap/storage setup at `:343-379` uses ordinary public DHT construction,
  not a test scope or a native send-observer registration.
- `bench/private-routing/worker.js:142-159` constructs the alpha DHT without an
  observer. `index.js:655-668` likewise passes no observer to the controller.
  At the measured implementation `1e9dfb2`, `private-peer-controller.js:2206`
  defaults it to null, and `:293-306` returns before snapshot copying/freezing
  when no observer exists. The baseline's separate test-observer default is
  also null; the benchmark never invokes its setter.
- No `observeSendAttempts` or `scope.create` attachment occurs from worker
  startup through `worker.js:253-260` joined stream/server/node teardown.
  Thus the harness's send-observer attachment lifetime is **none**, not an
  observer removed only after timing.
- The nonzero-delay hook is different: `worker.js:17` installs it before DHT
  construction; `worker.js:259` closes it after node destruction.
  `delay.js:22-28,237-278` wraps UDX write/ACK/final/flush handling and restores
  the original methods on close. Zero delay returns native passthrough at
  `delay.js:56-57`. This bounded delay/counter machinery does not hash packets
  or freeze send-observation records. The payload seed hash in
  `protocol.js:48-53` runs during preparation, before relay CPU timing and
  transfer timestamps, and is not a per-send observer.

The native warning applies to an explicitly observed native runtime, a separate
path inspected in Opus's checkout. In `lib/private/peer-native-runtime.js`,
`:1521-1523` initializes the listener to null; `observeSendAttempts` at
`:1601-1618` attaches to an existing lease or records the listener for
`leaseCurrentSocket` at `:401-410`, and returns `stopObservingSends` to detach.
Suspend removes the lease attachment during `stopRuntime` at `:1479-1499`;
an undisposed listener is retained for resume. Joined destroy detaches through
that shutdown path, not synchronously at the initial `destroy()` call.
`lib/private/udx-cell-endpoint.js:4214-4244` checks for a lease observer before
the packet hash and attempt-record freezes; `:4368-4403` also guards send and
completion observation. No attachment means no hashing/freezing from that
observation facility, not absence of normal protocol cryptography or funding.

Capture/privacy remains separate. The alpha capture path attaches through
`test/private/live-peer-capture-node.js:199-210` →
`test/private/helpers/private-peer.js:34-85` during scoped node construction,
before readiness. Controller destruction clears its observer; after joined
node teardown, capture calls `scope.close()` at `:345-348`, which clears any
remaining scoped callbacks (`helpers/private-peer.js:109-115`). These capture
paths are not imported by the throughput harness.

No observer-driven harness correction is indicated by this source inspection;
it is not a new runtime or performance result. If an active observer is later
introduced, both benchmark checkouts must receive the identical corrected
harness before a new paired comparison, with prior artifacts retained as a
separate evidence group. Neither one-sided removal nor subtracting an estimated
observer cost is a valid correction.

The coordinator accepted this as read-only evidence under R42, not a performance
pass. Preserve the matched harness and artifacts: **no observer-driven rebaseline
or lazy-digest work is authorized**.

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
this baseline. These historical delayed rows used the callback-held method
identified in F-17: their throughput ceiling could be imposed by batch size
divided by the artificial delay. They are retained as historical evidence, not
as protocol-throughput measurements or a comparable corrected-method baseline.

Before collecting this table, a real direct-stream verifier smoke accepted a
valid transfer and rejected a corrupt payload, excess payload, and a missing
finish frame. The small benchmark smoke completed all twelve direct/alpha
probe, ping, and 1 MiB attempts with one repetition per direction.

## Settled B1 e2e observation adapter

The e2e adapter requires Astra's `aaf9761` scoped helper directly. The pre-B1
fallback observer, stream taps, and global `CellCodec.open` wrapper are removed.
E1 inspects bytes on every relay-emitted control read/write and authenticated
opened cell. Inner source-cell opcodes 1/2 are not interpreted as outer setup
opcodes 3–7; attempted writes are not represented as downstream reads.

E3 groups opener views by relay identity, settled link label, header circuit ID,
and direction. E4 correlates `descriptor-published.wire` with each listener it
created and compares independently inspected storage records across a real
advancing-clock period crossing.

E6 uses the R12 contract: `guards().source.current` is the pinned policy primary,
not the last guard used. Actual circuit usage comes from
`source-route-selected.firstSafetyRelayPublicKey` and is compared with the
authenticated first adjacency. A real published entry collision must use the
first compatible pinned alternate without promoting it or reordering the policy.
Restoring a compatible destination tail must use the primary again; actual
primary failure must promote the next pinned alternate. Every observed circuit
must have four distinct relay roles. Ten healthy descriptor refreshes preserve
the pinned policy, but independently changing destination tails need not keep a
fixed first adjacency.

Destination guard loss is isolated in a separate fixture so a preceding source
failure cannot invalidate its pinned alternate. It must automatically republish
through the previously pinned alternate within twenty real seconds, then admit
a working circuit through that guard. Its source makes no connection before
the destination failure: the post-publication exchange is a fresh-caller proof,
not a promise that an earlier caller's pins remain usable. The test does not
manually republish, lengthen the deadline, or treat a pinned snapshot as a
liveness claim.

Listener recovery does not override source pinning. For example, the pinned
set `[new destination guard, new entry, failed old guard]` has no legal first
safety relay. That caller must fail closed with `ERR_PRIVACY_UNAVAILABLE` while
retaining its healthy policy primary; a role collision is not a reason to
promote it. R12 and the three-build cap remain unchanged. Astra owns the
separate deterministic exhausted-pin/healthy-primary-retention regression.

Astra's completed lifecycle proof, recorded below, now covers the unchanged
twenty-second publication deadline on both Node and Bare. An earlier added
same-source reconnect assertion failed once without a root trace; eleven
instrumented repetitions passed. The deterministic real-network exhausted-pin
fixture establishes that this reconnect assertion is invalid in general. It
does **not** identify the cause of the original untraced failure. These reported
results are separate from Vega's merged Node/Bare E6 gate, which has not been
rerun during the runtime hold.

E4 and E6 explicitly share one advancing protocol clock across their private
controllers and descriptor-storage validators. Descriptor lifetimes, periods,
refresh, and guard rotation use that clock. Harness deadlines remain real
`setTimeout` deadlines; the adapter does not replace global time or shrink
transport, control-I/O, or ordered-cell gap deadlines.

### Control-version-7 flow observations

The e2e observers bind to Astra's dual-credit contract in `5ed8449`. The shared
logical decoder recognizes DATA/OPEN/FIN/RESET plus `CREDIT=4`, `DEMAND=5`, and
`RELEASE=6`. Flow-control bodies contain exactly one two-byte unsigned big-endian
count. CREDIT and RELEASE require positive counts. CREDIT is at most 512 for a
stream or 2048 for a circuit; DEMAND and RELEASE are circuit-only and at most 2048. Stream ID `0xffffffff` denotes circuit scope and cannot carry a stream
operation. Other IDs denote stream scope.

DEMAND zero withdraws outstanding demand and receives an ordered zero
acknowledgement after all earlier grants. Those grants remain valid until the
acknowledgement arrives. RELEASE returns unspent granted cells, not consumed
DATA. Unknown flags, wrong lengths, invalid scopes, oversized counts and illegal
zero counts remain test errors rather than disappearing when production ignores
observer exceptions. Inner source controls retain their separate opcode namespace.

#### Raw-reader credits and bounded ownership

Under Astra's R16 contract, credits return when SecretStream consumes raw
encrypted bytes through the LogicalRouteStream reader, not on relay receipt or
public plaintext reads. Stream returns are batched at 128 cells and circuit
returns at 32 cells, with partial circuit batches flushed after 50 ms. No
Noise-aware fragmentation adapter is added to alpha: ordinary SecretStream
atomic records up to 16,777,215 bytes and application plaintext buffers remain
outside the additional private-routing window bound.

DATA requires both stream and circuit credit. Entry allocates the shared forward
pool before independent sources transmit; the destination allocates the reverse
pool across its logical writers. Each pool conserves
`available + sum(unused grants) + inFlight === 2048`, regardless of source count.
Queued demanders receive rotating max-min shares; a sole demander can reserve
the entire available pool. A source-side circuit CREDIT grants demand, whereas
a destination-side circuit CREDIT returns consumed cells.

The wire observer maintains separate directional stream balances and sums DATA
on the shared destination circuit. Bulk, multiplex-budget and paused-reader
scenarios assert at most **512 in-flight cells per stream** and **2048 per
shared circuit**, with control progress while DATA is outstanding. The paused
reader reaches its actual raw stream window before the sibling exchange begins.
E3 classifies flow-control types/scopes and correlates forwarded DATA separately.

Each link has **2048 pending DATA slots**, **256 independent control slots**,
**64-cell write batches**, and at most **two in-flight transport batches**.
These queue/transport bounds are separate from wire balances. The e2e observer
does not reconstruct the pool's unused grants or measure those internal queue
and batch counts; Astra's flow regressions inspect them directly. Transport
failure/stop settles pending promises exactly once, and RESET waits for its
queued write before source close destroys the physical link.

Honest writers release unused grants after 50 ms idle or immediately when stream
credit is exhausted. Entry independently closes a leg holding unused grants
without DATA progress for five seconds; voluntary RELEASE is not its only
defense. Close, RESET and teardown reclaim unused grants, while transmitted
cells remain charged until consumed or discarded. The late/retired-cell fixture
therefore reserves one sender-pool debit per injected DATA cell in each direction;
RESET does not consume DATA credit. Retirement is checked using
`firstId <= route.lastStreamId && !route.streams.has(firstId)`, without depending
on a retained-ID set.

#### Bounded demand accounting

Duplicate outstanding demand, malformed or unsolicited credit, grant underflow
or overflow, and excessive no-DATA demand/release cycles are rejected. Per-leg
earned progress is capped at 64 DATA cells, enough for two 32-cell renewals.
An accepted request subtracts 32 with a zero floor rather than clearing all
accumulated progress. This preserves legitimate renewal when partial circuit
grants cross an independent stream-credit boundary. The 50 ms idle-demand
interval, duplicate-request rejection, circuit capacity and protocol deadlines
are unchanged; demand accounting is not an unbounded token accumulator.

#### Evidence and remaining gates

Astra's recorded final `test/private/alpha-flow-control.js` runs on `5ed8449`
pass **4/4 tests and 79/79 assertions on each runtime**, serially: Node 176.96 s
and Bare 188.96 s. The supplied evidence is
`/tmp/hyperdht-council/astra/dual-credit-final.log`, with contract and
before/after details in `TEST-SEAM.md`. It covers paused-reader resume, sibling
FIN, 16 MiB each way, four concurrent 4 MiB duplex streams, 64 source legs,
pool conservation, malformed and repeated-demand isolation, idle reclamation,
and misaligned credit boundaries. The last regression fails before correction
at **2/4 assertions** on both runtimes and passes afterward at **4/4**, without
changing the 50 ms interval or protocol deadlines.

Vega's earlier decoder/accounting preparation passed **15/15 tests and 318/318
assertions on Node and Bare** before the final scope/count-limit binding. The
final binding and watermark migration were reviewed against the committed
contract but were not rerun: Astra held the heavy slot at that stage and
explicitly requested no tests, builds or benchmarks. Neither those earlier
unit checks nor Astra's focused regressions replace the merged M1 aggregates,
Vega's explicit Bare slow-consumer gate, the bidirectional late-cell fixture,
or the merged active-session/refresh-generation lifecycle gates.

### Shared-link funding and scheduling proof (F03/F15)

The supplied `shared-links-after.json` records the original complete
`alpha-shared-links.js` suite passing **3/3 tests and 35/35 assertions** on
Node (146.801 s) and Bare (150.883 s). The F03/F15 shared-funding and pre-seal
DRR implementation is committed as **`fcda109`**, following the previously
recorded lifecycle and ownership work.

Five sequential 16 MiB bidirectional sessions carry **80 MiB in each direction
on one published route**, followed by another useful sibling. Four concurrent
4 MiB bulk writers remain byte-exact in each scheduling direction. Interactive
DATA has **11 forward / 12 reverse bulk cells ahead on Node**, and **16 forward /
0 reverse on Bare**, against the bound of **16 newly transmitted bulk cells
after actual interactive enqueue**. Both echoes finish within two seconds.
These are controlled scheduling regressions, not matched throughput benchmarks
or a general end-to-end latency guarantee.

Shared funding is earned only by fresh, monotonically increasing even OPEN IDs.
The available allowance is capped at **64 per-stream allocations plus the
control reserve**; replayed OPEN, ordinary DATA and stream closure cannot refill
it. Individual source ledgers remain finite. This funding is distinct from the
2048-cell receive-credit pool and the listener's 64 concurrent admission slots.

The strengthened funding case pre-spends an **already-existing source before
the new admission**, using real ledger charges rather than claiming multi-GiB
wire traffic. Against the exact `ecc3748` controller it fails **3/6 assertions**
on both runtimes. After correction it passes **9/9 assertions** on both, with
the other two tests explicitly skipped in those focused repeats. The new
admission preserves the shared route and old source; the old source subsequently
exhausts its unchanged finite allowance and closes alone while the newcomer
remains usable. The earlier 35-assertion aggregate is not presented as a rerun
of this strengthened fixture.

Scheduling uses per-stream deficit round robin (DRR), with **four fixed
1200-byte cells per visit**. Selection happens **before sealing and counter
allocation**, not by reordering sealed cells. Pending DATA/control bounds and
the two 64-cell transport batches remain independent of stream count.
The initial one-bulk fixture that did not form the intended backlog is excluded
from the proof. Evidence: `/tmp/hyperdht-council/astra/shared-links-after.json`
and `/tmp/hyperdht-council/astra/TEST-SEAM.md`.

The latest integrated serial `alpha-flow-control.js` repeat passes **4/4 tests
and 79/79 assertions on each runtime**: Node 209.906100083 s and Bare 210.189 s
(Astra artifact 234). This is the integrated data-plane repeat, distinct from
the earlier `5ed8449` run recorded above. It does not substitute for the merged
M1 aggregates or establish the still-unmet benchmark performance targets.

### Control sessions and descriptor cancellation (F09)

Descriptor-operation ownership is committed as `a9213ca`; relay control-session
ownership and the actual owner-integration test are committed as `4b308f4`.

The original full `alpha-control-sessions.js` suite passes **7/7 tests and
35/35 assertions on each runtime**, serially: Node 210.997 s and Bare 218.099 s.
It covers the two-second partial-opcode deadline, five-second silent setup reads,
ten-second whole-session bound, eight unfinished sessions per authenticated key
and observed diversity bucket, 64 global unfinished sessions, cancellation of
real stalled outgoing handshakes, and established/paused application traffic
surviving the setup deadlines. The public /24 or /48 diversity rule and locally
bound loopback host+port exception apply; an observed IP is not an authenticated
identity. Setup ownership ends at successful bridge/entry handoff, so those
deadlines do not own established application streams. These setup admission
limits are separate from application-session quotas.

The descriptor service's real cancellation cases now pass **5/5 tests and
44/44 assertions** on Node (0.233 s) and Bare (0.239 s). The unchanged service's
Node before run fails **0/5, 22/44** (5.291 s), exposing leaked native requests,
late success and continued PUT/readback after cancellation, and suspend/destroy
that do not join owned operations.

Operation ownership now cancels and joins real queries, borrowed sessions and
native requests before releasing ownership. Delayed valid replies cannot
produce success, and cancellation prevents later publication phases through
reusable root sessions. The existing C7 final-closest/disjoint-vantage and
wrong-target tests pass **2/2, 7/7 on both runtimes**. The selected public-api
exact-readback case also passes **8/8 assertions on each runtime**, with 48 other
cases explicitly skipped on each. This is not a full public-api suite pass.
Routing, retry policy, quorum selection, encoding and directory sampling are
unchanged by this ownership work.

The read-only review found no demonstrated production defect, but identified
missing coverage connecting an actual ControlSession to descriptor cancellation
and admission-slot reuse. The added real second-safety fixture sends an
authenticated encrypted resolve cell while seven other unfinished setups
saturate its peer cap. Valid descriptor responders defer actual RPC replies;
the transports and descriptor responses are not mocked.

The focused before runs keep the current control implementation active and load
only the exact **`ecc3748` descriptor service**. Both Node and Bare fail the
selected case with **7/11 assertions passing**: seven native requests survive
cancellation and the admission slot remains occupied. After operation ownership,
the selected case passes **11/11 assertions on both runtimes**: Node 21.148 s
and Bare 21.155 s. Requests drain before a replacement setup is admitted, late
replies cannot advance the cancelled resolver, and an independent application
authenticates and echoes.

**Seven other cases were explicitly skipped in each focused before/after run.**
The earlier full seven-case results remain 7/7, 35/35 per runtime; no full
eight-case run is claimed. The first draft's unsupported Node-style write
callback on streamx was corrected to `Writable.drained` before accepted proof.
That draft timeout is not production failing-before evidence.

Evidence: `/tmp/hyperdht-council/astra/control-sessions-after.json`,
`/tmp/hyperdht-council/astra/descriptor-cancellation-after.json`,
`/tmp/hyperdht-council/astra/ownership-integration-after.json`, and the descriptor
and relay-owner sections of `TEST-SEAM.md`. F07 storage availability and merged
M1 acceptance/performance gates remain separate requirements.

### F07 storage choice and remaining availability work

Vega retains docs/e2e ownership. The explicit F07 decision remains **RETAIN
PLUGIN STORAGE** for alpha. Astra owns bounded capability bootstrap/referrals
using ordinary announce and capability-only transport queries. Storage must
not be restricted to a C6-only relay universe. The index API remains unchanged,
and there is no mutable migration. This design and ownership ruling is not
completed implementation or availability proof. C7 closest-set/wrong-target results,
exact-readback checks and benchmarks with deliberately capable storage nodes
must not be represented as proof that the remaining F07 availability path is
complete.

### F10 ownership and serialized verification

Opus has released F10 cell-codec, minimal crypto-suite and focused-test
ownership to Astra, with Opus cross-review. Changes must remain additive and
preserve the old API until the native A4 cutover. Implementation is underway;
no completed F10 validation or performance result is claimed here.

The coordinator's current heavy-slot order is **Astra's finite iteration,
then explicit handoff to Opus** for M3b/A3/native16/funding proof. **Vega remains
no-heavy**: no suites, builds or benchmarks without an assigned slot. This
ownership order does not complete any outstanding merged M1 or native gate.
Vega's runtime work remains deferred pending Opus's verification window.

### Stream-ownership recheck and late-frame fixture

The initial `alpha-stream-lifecycle.js` compatibility repeat passed **4/4 tests,
52/52 assertions on Node**, but **3/4 tests, 51/52 assertions on Bare**.
Astra traced the Bare failure to fixture behavior, not a demonstrated scheduler
defect: the test forcibly released a sibling's 2047 unused grants ten milliseconds
after demand, then immediately echoed. The next demand had only one DATA cell
of progress and sixteen milliseconds elapsed, so `INVALID_ROUTE` was correct
under the unchanged **32-DATA / 50 ms** demand-rate rule. Both circuit pools
remained conserved at 2048, late DATA credit returned, and a later stream worked.

The test-only correction is **`876e4fd`**. It waits for actually available pool
capacity, debits every injected DATA cell, retains the immediate sibling echo
and all four authenticated late frames, and checks in-flight reclamation plus
conservation in both directions. No production rate, deadline, credit or
scheduling policy changes.

The full corrected suite passes **4/4 tests and 54/54 assertions on both
runtimes**: Node 109.647 s and Bare 109.579 s, including the R11 queued-send
process-event guarantee. This is Astra's existing ownership suite, not a rerun
of Vega's e2e fixture below. Results are recorded in
`/tmp/hyperdht-council/astra/ownership-integration-after.json`. The first external
Bare diagnostic failed to load `fs` before any test; that runner failure is
excluded and is not an application R11 rejection.

Vega's `reset-propagation.js` did not force `_releaseCircuit()`, but its immediate
no-capacity error could reject a temporarily fully granted pool. It now waits
for genuinely unallocated credit with a bounded real-time fixture wait, without
releasing a sibling's grant. Each injected DATA cell receives one atomic
`available--` / `inFlight++` debit; RESET is not charged. The immediate sibling
exchange remains, followed by conservation assertions for both sender pools.
This owned fixture still has not been rerun; Vega remains no-heavy under the
coordinator's Astra-then-Opus execution order.

### Completed lifecycle proof and integration boundary

Astra's lifecycle implementation is `ecc3748`, following the dual-credit
implementation `5ed8449`. The complete after-correction run was serial:

```sh
node test/private/alpha-route-lifecycle.js && bare test/private/alpha-route-lifecycle.js
```

- **Node:** 4/4 tests, 45/45 assertions, 142.929 s.
- **Bare:** 4/4 tests, 45/45 assertions, 147.973 s.
- **Clean before-correction runs:** both runtimes fail all four tests, with
  21/33 assertions passing: Node 147.655 s and Bare 140.558 s. The before branch
  reaches fewer downstream edge assertions, so its denominator must not be
  presented as an identical assertion-by-assertion comparison with the
  45-assertion after run.
- **First after run:** Node passed 3/4 tests and 41/43 assertions in 144.614 s,
  then the chained command stopped before Bare started. The failed additional
  unconditional same-source reconnect and the later eleven passing instrumented
  repetitions are the untraced investigation described above, not the clean
  final proof or an identified root cause.

The four cases establish:

1. **Refresh without dropping admitted streams.** Refresh crosses a blinded
   presence-period boundary while a backpressured 1 MiB transfer and an old
   echo stream remain alive beyond the old admission expiry. A new caller uses
   the refreshed registration, and the old route is reclaimed after its final
   admitted stream closes.
2. **Sequential admission and finite IDs.** Seventy sequential sessions
   complete rather than consuming a 64-session lifetime allowance. The final
   even uint32 stream ID (`0xfffffffe`) is admitted, followed by exhaustion
   without wrapping or reusing an earlier ID. Only the newcomer is refused;
   both existing siblings remain usable.
3. **Concurrent reservations across generations.** One listener shares the
   64-reservation bound across its old and new generations. A 65th reservation
   is refused without resetting an admitted sibling; closing an old-generation
   reservation makes its slot available on the new route.
4. **Guard-loss recovery and exhausted pins.** Actual guard loss causes fresh
   publication within the unchanged twenty-second deadline. A fresh caller
   works after the failed node withdraws. Separately, explicitly exhausted
   source pins fail closed while retaining their healthy policy primary.
   Production R12 guard selection and the three-build cap are unchanged: no
   role-collision promotion, guard resampling or deadline increase is introduced.

These are Astra's supplied runtime results, not new Vega runs. The handoff is
`/tmp/hyperdht-council/astra/lifecycle-results.json`; the complete qualification
is in `/tmp/hyperdht-council/astra/TEST-SEAM.md`, under "Route lifecycle and
admission evidence". Listener recovery and universal availability for an
exhausted caller remain distinct claims.

Vega's owned E4, refresh, quota and E6 fixtures remain unchanged. The merged M1
Node/Bare baseline, B1 aggregates and performance gates still require their
coordinated runs. No tests, builds or benchmarks were launched for this
documentation update.

## Corrected native C2 acceptance plan

This is a planning contract, not native implementation or runtime proof. The
coordinator's corrected profile supersedes the earlier R33/R34 arithmetic and
pool figures.

- **Purpose 2 source:** M=1, W=24, Q=111,852 frames per signed direction.
- **Purpose 3 registration:** M=17, with actual W=1 per application under one
  shared **24-frame / 23,448-byte** window, not sixteen independent windows.
  Aggregate Q is **111,791 per direction**. The first OPEN ceiling is
  **96,431** after reserving **15 × 1,024** for the remaining applications.
  Admission grants are nonrefundable; use the actual accepted grant rather
  than treating every application as independently entitled to the aggregate.
- Each signed direction has **maxCells=3,579,138** and
  **maxBytes=4,294,965,600**.
- Production **maxConcurrentCircuits=24**, not eight. A common entry must fund
  the registration plus sixteen clients; distributing those clients among
  source nodes does not remove that shared-entry requirement.
- After the native16 amendment, **sourcePool=37,457,344 B**,
  **mask9pool=768,704 B**, **mask11pool=56,848,040 B**, and
  **maxQueued=2,336,639** for private-purpose sizing. The interim four-slot
  source pool is **9,364,336 B**.
  Do not substitute the profile's `maxQueued` for the controller connect-FIFO
  limit; that limit and its deadline require the actual controller contract.

One pin's sixteen slots count **all CIRCUITS**, including local registrations
and presence work. They do not promise sixteen application streams in addition
to those other purposes.

The native acceptance plan retains:

1. **Four sources, sixteen applications:** four streams per source to one
   destination registration, all held open before exact small duplex transfers.
   Keep this topology after the native16 amendment; it is not replaced by the
   single-source boundary case.
2. **The actual source-slot boundary:** derive the limit from the integrated
   contract—four before amendment, sixteen afterward. Occupy all slots, then
   submit the next connect. It waits for joined native circuit-slot release
   through the bounded queue, or fails closed on queue/deadline exhaustion.
   No early application acceptance, alpha/direct fallback, or late opening of
   cancelled requests is permitted.
3. **Additional native16 single-source coverage:** hold sixteen application
   streams only with no simultaneous source registration/presence circuit.
   Use a warm verified cache or explicitly sequence lookup and join its circuit
   release before the hold. A seventeenth connect exercises the boundary; this
   is not a generic sixteen-application guarantee when other purposes use slots.
4. **Shared-entry funding:** exercise production capacity for registration plus
   sixteen clients at one common entry under the 24-circuit profile, without
   synthetic funding or increased test-only limits.

Large duplex transfers, private-record fragmentation, lifetime admission
exhaustion, refresh with retained old streams, nonrefundable budgets and clean
finite-budget termination remain separate required scenarios. The detailed plan
is `/tmp/hyperdht-council/vega/C2-PREPARATION.md`. Acceptance still needs the
committed native integration/amendment and real directional funding, their
joined-release/queue evidence, and explicit runtime authorization.

## Planned explicit legacy egress — after native M5b

This section records **PLAN R40 as amended by R41 and documentation ledger 27**.
R41 supersedes R40's terminal-free call shape. These are C2 planning requirements,
not a claim that M5c is implemented, exercised or operational.

The explicit public request is:

```js
connect(publicKey, {
  legacy: true,
  terminal: { advertisement260 }
})
```

`keyPair` is optional. Preserve fresh application identities and expected
destination Noise-key checking. With no legacy flag, the request remains private
rendezvous; a present flag must be exactly `true`. **Private mode rejects
`terminal`; legacy mode rejects `readerSecret`.**

The required terminal is an exact-own-data supplied object. Copy its signed
260-byte advertisement and authenticate it through the existing admission,
grant-derived mask-11, epoch, expiry and capacity checks, using existing
**supplied-terminal mode 2**. There is no random directory selection, blind retry,
`policyCount` reinterpretation or new wire flag. Advertisements do not disclose
legacy service opt-in; a refusing or unavailable selected terminal fails closed,
without choosing a replacement or falling back to private/direct transport.

Terminal service is separately opt-in through optional
`relayConfig.legacyEgress`: an exact-own-data boolean, default `false`, with
`true` permitted only on a grant-derived mask-11 terminal. Opus normalizes it
through `readNativeConfig`; B2 consumes the normalized value and mask. CLI input
uses the same validator. Disabled terminals must refuse purpose 1 **before
remote destination contact**.

The legacy allowance is finite: **purpose 1, M=1, Q=20,000, W=24**, permitting
**19,540,000 raw bytes per direction** with unchanged legacy record limits—not
that many plaintext application bytes or unlimited streaming. At most **one
concurrent legacy application per source and per opted-in terminal** shares the
existing circuit and memory limits. The source **37,457,344 B** and terminal
**56,848,040 B** pools remain shared ceilings, not additional legacy pools.
Mixed work may wait or refuse rather than over-admit. The opted-in terminal's
`maxQueued` must cover helper-derived legacy acceptance; the private-purpose
2,336,639 figure is not a sufficient legacy acceptance bound. Private
cell/byte maxima remain the larger directional ceilings.

The terminal necessarily learns and contacts the destination; the unchanged
destination sees the egress transport endpoint. Do not describe this as native
private-rendezvous destination hiding. No source-side native/direct upgrade
toward that destination is permitted.

Orion owns M5c implementation. Opus cross-reviews authority, semantic command
costs and event ordering, including ACCEPT-before-pair. Both pair-before-ACCEPT
and ACCEPT-before-pair must work: encrypted IK2 forwarding cannot require a
premature remote UDX ID, while the authenticated ACCEPT/pair join must validate
identity before native connect/open. Use production accounting helpers rather
than duplicating their equations.

### Planned C2 legacy acceptance cases

Only after native M5b, actual M5c integration and explicit runtime authorization:

1. **Unchanged remote server:** use an ordinary HyperDHT server with no native
   private-routing adaptation. Require exact independent duplex payloads and
   explicit receipts, in both source-first and destination-first FIN orders;
   half-closing one direction must not truncate the other.
2. **Both ACCEPT/pair orders:** exercise each real ordering, preserving encrypted
   IK2 forwarding and the authenticated identity join. No invented remote UDX ID,
   premature native connect/open or source direct upgrade may make a case pass.
3. **Opt-out and incompatible inputs:** prove refusal before terminal-to-remote
   contact for disabled service, not merely absence of application delivery.
   Reject missing/invalid supplied terminals, non-true legacy flags, private
   calls with `terminal`, legacy calls with `readerSecret`, and invalid opt-in
   configuration. Invalid signatures, epochs, expiry, derived masks and capacity
   cannot authorize egress.
4. **No implicit fallback:** private failure never becomes legacy/direct; an
   explicit legacy refusal never becomes private, source-direct or a randomly
   selected alternate terminal. The selected terminal's intended ordinary
   egress connection is not a source fallback.
5. **Finite budget and shared capacity:** count actual raw frames/records and
   helper-derived command costs, not just plaintext bytes. Require clean,
   fail-closed exhaustion without hidden refill or silent truncation; exercise
   per-source/per-terminal one-legacy limits and mixed private/legacy pool and
   circuit exhaustion. Queued work may proceed only after real joined release.

Record independent remote-contact, transport/identity, admitted-funding and
joined-release evidence through the actual implementation's supported seams.
No M5c implementation, interoperability result or legacy public-path completion
is claimed by this plan.

## Scoped private-peer packet capture

`npm run test:private:peer:capture` uses the scoped helper introduced by Astra's
`aaf9761`, not production `TEST_ONLY` symbols or a process-global observer.
Private nodes are constructed synchronously through `scope.create`; all nodes
are destroyed and joined before `scope.close`.

The collector consumes read-only `route-cell-opened`, `route-transform`, and
`route-cell-sealed` events from the settled seven-event contract. Views are
grouped by relay identity, link label, header circuit ID, and direction.
Forwarding joins require a unique matching authenticated plaintext at the same
relay; ambiguous observations fail rather than borrowing another circuit's cell.
Observers never gate forwarding, publication, or commit.

The test explicitly skips outside Linux. A macOS skip and parse/load check do
not prove packet capture or forwarding; the coordinator runs the real privileged
Linux capture gate at M1.

## C2 send-owner reconciliation

```sh
npm run test:e2e:c2:capture
npm run test:e2e:c2:capture:bare
npm run analyze:private-sends -- /path/to/normalized-evidence.json
```

The analyzer consumes the fourteen-kind A2 `observeSendAttempts` schema published
in `A2-CONTRACTS.md` §4.1–§4.4 by `c437804`, including the coordinator's ratification
of uncharged stateless phase-zero bootstrap replies.
Tests use synthetic events and independent UDP payload bytes, not a fabricated
runtime or native capture claim.
All five required negative controls execute the real analyzer: missing owner,
duplicate owner, miscategorized discovery, uncharged retry, and charge after send.
`fixture.js` exports a complete input for CLI experiments.

Native private transport legs target **wire version 3**. The explicitly selected
M5c legacy destination retains ordinary HyperDHT; that is not a source downgrade.
The analysis document's `version: 2` is a JSON schema version, not a wire version.
The pre-contract SHA-256/invented-event input has been removed, without a
compatibility adapter.

### Unmodified runtime events

An attempt has exactly the contract's semantic fields: `kind: 'attempt'`,
`attemptId`, `socketGeneration`, `local`, `remote`, `bytes`, `digest`, `owner`,
and `obligation`. Tuples contain numeric `host` and `port`; the digest is hex
**BLAKE2b-256 of the complete UDP payload**. An owner contains `kind`, `class`,
`category`, `charged`, `ledger`, `ordinal`, and `governor`. The kind fixes class
and category; only circuit, neighbor and guard-bootstrap classes are charged.
Missing or conflicting classes fail, as does changing class within one owner.

- Charged circuit kinds: `circuit`, `closure`, `circuit-discovery`.
- Charged service kinds: `neighbor-service`, `neighbor-close`,
  `neighbor-discovery`.
- Charged bootstrap kinds: `bootstrap-request`, `link-setup`, `link-control`,
  class `guard-bootstrap`, sharing a source pin's ledger or a guard's accepted-link
  reservation.
- Governed service kind: `discovery-response`, class `responder-cache`.
- Governed bootstrap kind: `bootstrap-response`, class `responder-cache`.
- Governed v1-routed kind: `routed-branch`, class `v1-routed-branch`.
- Governed traversal kinds: `nat-reflection`, `nat-punch`, class `nat-traversal`.

Charged events require a positive opaque ledger, an ordinal at least 1, and a
null governor. Governed events require null ledger/ordinal and a positive opaque
governor. A governor is not silently promoted to a charged ledger. Undocumented
kinds, missing governors, or a charged kind without its charge fail explicitly.
The retired generic `direct` and `direct-response` names are not aliases.

Every charged attempt debits **one cell and 1,200 ledger bytes**, even when its
actual UDP payload is shorter. `chargedCells` and `chargedBytes` track that debit
separately from attempted/observed wire bytes. Charged byte allowances constrain
the debit, not the shorter wire length; native failures never refund it.
Pre-boundary funding refusals have no charged attempt or socket send and cannot
be fabricated as governed attempts.

For a 30-minute lifetime, the synthetic fixture's source pin has **7,285 cells /
8,742,000 bytes**; an accepted guard link has **7,232 cells / 8,678,400 bytes**.
Bootstrap command budget is zero. These are independent sizing inputs, not new
event fields; the guard generation pool also covers eight accepts in progress.

Completion events use the published §4.2 fields: `kind: 'completion'`,
`attemptId`, and `outcome` (`sent`, `refused`, or `failed`). They remain unmodified;
the collector envelope supplies their lease identity. Missing completion is
reported as analyzer-level `unresolved`, never fabricated as a runtime outcome.
`obligation` is the supplied opaque retry identity or null; there is no invented
`retryOf`, command counter, route ID, or runtime timestamp.

### Analysis input, version 2

The top level contains `version: 2`, `maxCaptureDelayMicros`, and:

- `leases`: `{ node, runtime, lease, socketGeneration, local, start, end }`.
  These are independently recorded test fixture/socket lifetimes. Generation is
  positive and unique within a runtime; endpoints use actual numeric addresses.
- `events`: `{ node, runtime, lease, at, event }`, wrapping the unchanged native
  event. Record `at` synchronously in the observer using the calibrated capture
  clock, not later when a coordinator receives a message.
- `captures`: `{ node, runtime, lease, id, tap, at, local, remote, payload,
duplicateOf }`. `payload` is lowercase hex of the complete independently
  captured UDP payload, including private protocol overhead but excluding IP/UDP
  headers. The analyzer computes its length and BLAKE2b-256 itself.
- `captureLosses`: `{ node, runtime, lease, attemptId, reason, evidence }`.
  Each declaration explains one successful-but-unobserved attempt with specific
  independent loss evidence. Unknown, refused/failed, or captured attempts cannot
  be excused this way.
- Optional `allowances`: `{ node, runtime, lease, ledger, governor, kinds,
datagrams, bytes, sizes }`. Exactly one of ledger/governor is a positive
  reference and the other is null. These are independent fixture expectations,
  not A2 event fields. Use compiled or scenario-authorized limits, never totals
  derived from the observed sends. All kinds sharing a real owner share its one
  allowance. `completeAllowanceCoverage` is false for owners without supplied
  limits; the analyzer does not invent limits absent from the runtime event.
- Optional `links`: `{ node, runtime, lease, local, remote, start, end, class,
requiresCharge }`. These are independent directional topology/lifetime windows.
  `circuit` and `neighbor` require charging even when `requiresCharge` says false.
  Native `guard-bootstrap` traffic also requires charging, but §4.4 expressly
  permits governed `v1-routed-branch` sends over a shared A0 link. That exception
  does not reclassify bootstrap control or override an explicit `requiresCharge`.
  The remaining classes are `responder-cache`, `v1-routed-branch`, and
  `nat-traversal`. Reports retain both the independent link class and native
  owner class. Uncharged attempts in required windows fail `UNCHARGED_REQUIRED_LINK`.
  Overlapping matching windows fail `AMBIGUOUS_LINK_CLASS`.

Times are safe integer microseconds on one calibrated clock; intervals are
`[start, end)`. Native attempt IDs must be unique and strictly increasing across
all leases of a runtime. Event/capture association is scoped by node, runtime,
socket generation and attempt ID. Charged ordinals begin at 1 and remain
consecutive within the complete recorded ledger lifetime. Attach observation
before sends and analyze complete generations; partial traces need explicit
provenance, not a guessed counter reset.

Opaque owner IDs are reported by lease/generation rather than merged across
reconnects. The analyzer does not reconstruct secret path identities. IPv4,
IPv4-mapped IPv6 and equivalent IPv6 spellings normalize without DNS.

### Join, bounds, and evidence limits

Prefer one egress tap per sender namespace. Additional taps need an explicit
`duplicateOf` primary observation with the same exact tuple, generation, bytes,
digest and timestamp, but a different tap. Only one copy per additional tap is
accepted. The capture normalizer must establish that relation independently;
similar bytes or nearby times never automatically collapse retransmissions.

Within each tuple/generation/length/digest bucket, attempts retain timestamp and
attempt-ID order. A packet follows its owner's notification and falls within
`maxCaptureDelayMicros`. Each packet consumes one attempt, never two competing
owners. Identical same-time packets preserve multiplicity. Every private capture
must have an owner; unmatched traffic is not relabeled ordinary DHT. A future
capture normalizer must distinguish ordinary DHT independently, not by discarding
packets that fail to match the event log.

Refused/failed native attempts remain in attempted totals without demanding false
packet equality. Successful attempts missing capture require explicit loss
evidence. Unresolved completions, unexplained capture absence, and clock/order
assumptions stay visible. This preparation does not supply the real PCAP/clock
collector or claim a live native capture run.

The report includes **circuit, service, bootstrap, traversal, v1-routed, and sum**,
every kind's subtotal, charged and uncharged totals, each node and lease, charged
subtotals per `ledgers` entry, and governed subtotals per `governors` entry.
It retains joins, attempted/observed/unobserved UDP bytes and datagrams, retries,
native outcomes, declared losses, and link-policy evidence. `completeCapture`,
`completeCompletions`, `completeAllowanceCoverage`, and
`completeLinkClassification` are separate statements. CLI exit 0 alone is not
native privacy, complete capture, or M4 compliance.

Governor identity/counts do not prove the governor's internal bounds. In
particular, a 64-packet **in-flight** cap is not a 64-send lifetime cap. Cache
capacity, session deadlines, retransmission schedules, and admission policy
require their own native evidence; the analyzer never manufactures these from a
governor number.

Ratified `bootstrap-response` governors can answer unknown phase-zero sources
with stateless cookies exactly the request size; later phases require cookie
proof. Live bindings are capped at 4,096 and ACTIVE requires a fundable link.
An observer's opaque governor ID cannot prove those state/anti-amplification
bounds. Synthetic per-governor allowances are scenario limits, not invented
lifetime packet caps or charges against the bootstrap ledger.

### M4 charging cross-review

The ratified packet at
`docs/superpowers/specs/2026-09-09-private-routing-peer-stream-design-packet.md`
§8.1 requires a directional cell charge before each physical attempt, including
failed/uncertain attempts. §3.4 includes neighbor setup, cancellation, PING/PONG,
renewal, reconnection and teardown. §8.3 also describes native guard bootstrap
and neighbor maintenance as independently **bounded and charged**.

The reviewed pre-R10 A2 pump charged attached circuit/closure or neighbor funding,
but chose an uncharged fallback when funding was absent rather than enforcing
an A0-only class. No funded-neighbor or native circuit bypass was established.
The coordinator resolved the normative question in R10: A0 bootstrap must charge
a finite source-pin ledger or accepted-guard-link reservation; circuit, neighbor
and guard-bootstrap owners without funding must be refused before the socket.
Only responder-cache, v1-routed-branch and nat-traversal may use bounded uncharged
governors. The analyzer enforces those class/category/charge rules and independent
link windows without treating legitimate shared-A0 v1 traffic as native funding.

Opus's `c437804` supplies the exact immutable `owner.class` field. The analyzer
requires it and records it in owner, join and link evidence. Synthetic rejection
of invalid claims is not a substitute for Opus's real zero-socket/zero-charge
funding-refusal tests or a future complete native capture run.

Do not classify a physical link from `owner.kind`, `owner.category`, or a shared
guard flag. Direct discovery replies may share a peer tuple with an established
neighbor link. Supply independently established windows and retain ambiguity
rather than silently exempting a reply. Missing classification is reported, not
treated as an M4 pass. The analyzer rejects uncharged setup, control, routed
branches, or any other kind whenever independent policy requires charging.

Native runtime scenarios remain dependent on integrated A2/B2 implementations.
They will construct `createPeerNativeRuntime({ dht, config })`, observe before
`ready()`, drive source `buildTail` and terminal `onIncomingFinal`, consume each
`FinalTailLease` once with the specified purpose-owner fields, and exercise joined
suspend/resume/destroy. A published interface contract is not evidence that these
source-runtime paths have already executed.

## C2 Linux E7 path diversity

```sh
# Inspection only, including on macOS; not a network pass:
npm run test:e2e:c2:diversity -- --describe
# Coordinator-owned privileged container run:
bash scripts/linux-gates.sh peer:diversity
# Inside an already provisioned privileged Linux environment:
npm run test:e2e:c2:diversity
```

The explicit gate is excluded from `linux-gates.sh all` while the C6 production
dependency is pending. It is brittle-driven and registers an explicit skip
outside Linux. On Linux, missing root, CAP_NET_ADMIN, or iproute2 fails the test.
It never starts Docker/Colima from the scenario. The existing runner provisions
the privileged container when the coordinator requests it. No A2 native runtime
or control-wire imitation is used. Random interface names use `hypercore-crypto`;
IPv4 evidence uses strict canonical dotted-quad parsing. Privileged `ip` commands
use the unprefixed `child_process` mapping used by the namespace provisioner.

Each scenario creates owned dummy interfaces in an unused private /16 and binds
real, non-loopback DHT sockets to them. Six storage nodes run production descriptor
services. All bootstrap tuples come from fixture sockets; all UDP ports are
kernel allocated. Before either private assertion, ordinary direct handshakes
authenticate every relay key and an ordinary direct duplex transfer verifies
payload bytes. This liveness traffic is reported separately from private proof.

The positive topology has eight relays over five /24s: four distinct live keys
share one /24 and four more occupy separate prefixes. Exactly one actual
persistent storage response is biased toward the first four keys. Read-only
async-iterator instrumentation requires production private discovery to consume
that exact responder/target/key-list response. Three private duplex transfers
must succeed with exact bytes. Every accepted path is joined to authenticated
`_connectRelay` raw-stream tuples for source→first safety, first→second safety,
second→entry, destination→guard, and guard→entry. The four relay positions must
have distinct actual /24s; directory advertisements do not supply that authority.

The negative topology has eight authenticated, actually announced relay keys in
one /24. Publication may reject insufficient diversity. The private connection
must fail with `ERR_PRIVACY_UNAVAILABLE`, never open, and never reach a private
application accept. Tentative selection events are reported but are not confused
with accepted paths. No optional/direct fallback is used to make the gate pass.

Cleanup joins application/relay streams, listeners, and nodes; restores scoped
observers and lookup patches; and deletes only interfaces this invocation created.
The scenario is IPv4-only; IPv6 /48 remains separate policy coverage. Dummy
interfaces are not independent hosts/operators, and downstream tuple observations
are local test evidence, not independent source certification or operator honesty.
The privileged end-to-end run remains required after C6 integration.

## Native v2 (`profile: 'native-v2'`) and temporary Cloudflare Worker e2e evidence

```sh
npm run test:e2e:c2:native
npm run test:e2e:c2:native:bare
npm run test:e2e:c2:cloudflare
```

The integrated branch completes the `native-v2` public controller
(`lib/private/private-native-controller.js`), config/CLI validation
(`lib/private/peer-native-config.js`, `bin.js`), directional purpose ledger
funding and authenticated operation command admission
(`lib/private/peer-purpose-owner.js`, `lib/private/peer-semantic-services.js`),
64 KiB private record fragmentation (`lib/private/peer-record-adapter.js`), and
explicit legacy egress (R40/R41).

Exercised native and e2e verification on `darwin 25.5.0` (`arm64`, Node
`v24.18.0`, Bare `1.30.3`):

- `npx brittle test/private/peer-native-config.js` and `npx brittle-bare`: pass
  on both runtimes.
- `npx brittle test/private/peer-native-cli.js` and `npx brittle-bare`: 4/4
  tests, 28/28 assertions on both runtimes, including live CLI relay startup
  and `HyperDHT` `profile: 'native-v2'` controller selection.
- `npx brittle test/private/peer-native-purpose.js` and `npx brittle-bare`: 5/5
  tests, 470/470 assertions on both runtimes, proving three-relay production
  `purpose 2` and `purpose 3` first-OFFER admission, all 16 `OPEN` +
  `PRIVATE_ACTIVATE` pairs spending 32 source allocation commands, funded
  stream and route tombstones, and disjoint native physical closure partitions.
- `npx brittle test/private/private-native-controller.js` and
  `npx brittle-bare`: 11/11 tests, 92/92 assertions on both runtimes, including
  guard locator publication, reader-policy cache separation, firewall
  enforcement, make-before-break registration replacement, suspend/resume
  joins, shared 16-slot ceiling, and explicit legacy egress (`pair-before-ACCEPT`
  and `ACCEPT-before-pair`, `>64 KiB` records, and opt-out terminal refusal
  before remote contact).
- `npm run test:e2e:b1`: 16/16 tests, 186/186 assertions passing.
- `npm run test:e2e:c2:capture` and `npm run test:e2e:c2:capture:bare`: 32/32
  tests, 113/113 assertions passing on both runtimes.
- `npm run test:e2e:c2:native`: 4/4 tests passing (16 MiB byte-exact native
  private duplex transfer, 16 concurrent streams across 4 source nodes with
  make-before-break registration refresh, live native send-owner capture
  reconciliation with zero differences across circuit/service/bootstrap
  categories, and explicit legacy egress with opt-out terminal refusal).
- `npm run test:e2e:c2:cloudflare`: 1/1 test, 20/20 assertions passing. Deploys
  5 temporary Cloudflare Workers (`source`, `guard`, `safety`, `terminal`,
  `dest`) to `*.workers.dev`, routes a live 5-node `native-v2` private routing
  topology through the temporary Cloudflare Workers (verified at Cloudflare
  edge colo `MAD`, 159 private UDP datagrams and 97 fixed 1,200-byte cells
  audited on the edge with HMAC-SHA256 transit receipts, zero destination key
  or plaintext leaks on any relay Worker, and zero identical 1,101-byte
  envelopes across `guard -> safety` vs `safety -> terminal` proving N-1
  LIONESS per-hop transformation), and deletes all 5 temporary Workers on
  teardown.
