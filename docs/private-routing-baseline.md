# Private Routing Fork Baselines

This record pins the upstream-derived roots used for the private-routing experiment and reports the baseline checks that were run before transport implementation. It records compatibility evidence only. It does not establish anonymity, resistance to traffic analysis, production readiness, or suitability for protecting users.

| Repository         | Upstream SHA                               | Private branch root                        | Node     | Bare    | Commands                                               | Result                                                                                                                                                                                                                                                                                                                                                |
| ------------------ | ------------------------------------------ | ------------------------------------------ | -------- | ------- | ------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| dht-rpc            | `a079674d7185ece6fe310974ef8cabc5bc59d4e2` | `a079674d7185ece6fe310974ef8cabc5bc59d4e2` | v22.19.0 | v1.30.3 | `npm run lint`; `npm test`                             | PASS: lint completed with 10 pre-existing `require-await` warnings; Node 52/52 tests and 215/215 assertions; Bare 52/52 tests and 215/215 assertions.                                                                                                                                                                                                 |
| hyperdht           | `ac6eaa5def633ccdd0b1c733f14b63036dbe4d33` | `0ba10b089df5b01c55e154a3ccf4e2d0843deb95` | v22.19.0 | v1.30.3 | `npm test`; `npm run integration`; `npm run test:bare` | HOST EXCEPTION: formatter passed. Node and Bare each reached 90/91 tests and 362/363 assertions; each failed only the same-LAN explicit-keypair case. Integration hung in its separate-process connection path and was terminated. Fork-native CI was activated but failed externally before package steps. See below.                                |
| hyperswarm         | `48d4241f69f848bb4c9dccb65b6fce5a9f40009d` | `64ebdd47369f685766fcc16fe7cf49b5072e58f3` | v22.19.0 | v1.30.3 | `npm run lint`; `npm test`                             | HOST EXCEPTION: lint passed with 8 pre-existing warnings. Node and Bare both reproduced a chaos connection-count/startup failure on the local multi-interface host; Node later timed out in peer-join and Bare was stopped after the chaos failure was confirmed. Fork-native CI was activated but failed externally before package steps. See below. |
| hyperswarm-testnet | `c301fb808735caeebf711c0bc6de79b7c1036bfa` | `c301fb808735caeebf711c0bc6de79b7c1036bfa` | v22.19.0 | v1.30.3 | `npm run lint`; `npm test`                             | PASS: lint; Node 2/2 tests and 3/3 assertions; Bare 2/2 tests and 3/3 assertions.                                                                                                                                                                                                                                                                     |

## Recorded environment

- Verification timestamp: `2026-07-16T22:47:24Z`
- Node: `v22.19.0`
- npm: `11.10.0`
- Bare / `bare-runtime`: `v1.30.3`
- Node platform and architecture: `darwin arm64`
- Host: `Darwin jds-Laptop.local 25.5.0 Darwin Kernel Version 25.5.0: Tue Jun 9 22:18:58 PDT 2026; root:xnu-12377.121.10~1/RELEASE_ARM64_T6000 arm64`
- HyperDHT upstream/private branch merge-base: `ac6eaa5def633ccdd0b1c733f14b63036dbe4d33`

The branch roots above were collected with `git rev-parse private-routing-v1`; upstream roots were collected with `git rev-parse upstream/main`. The HyperDHT branch root contains only the owner-approved private-routing design documentation and the upstream merge at this checkpoint. The Hyperswarm branch root adds reviewed test-only lint repair commit `64ebdd47369f685766fcc16fe7cf49b5072e58f3`.

## Local host exceptions

The local host exposes both the physical `192.168.8.50` interface and the `100.84.6.2` tunnel interface. That topology affects upstream same-LAN and chaos tests that discover or count physical network paths.

### HyperDHT

Both runtimes failed only `createServer + connect - same-LAN explicit keypair opens server`: Node completed 90/91 tests with 362/363 assertions, and Bare completed 90/91 tests with 362/363 assertions. A temporary A/B run reproduced the failure with the default physical interfaces and passed with an explicit `127.0.0.1` interface, opening both client and server. `npm run integration` hung in its separate-process connection path on this host and was terminated rather than reported as passing.

### Hyperswarm

Both runtimes reproduced the upstream chaos connection-count/startup failure on the same multi-interface host. The Node run later timed out in peer-join. The Bare run was stopped after the equivalent chaos failure was confirmed. These local runs are not reported as green. Commit `64ebdd47369f685766fcc16fe7cf49b5072e58f3` is a one-line, test-only lint repair and is available for review in [draft PR #1](https://github.com/ayooooo123/hyperswarm/pull/1).

## GitHub CI evidence

### Gate 3A DHT-RPC opaque-context compatibility

HyperDHT Gate 3A pins the reviewed DHT-RPC commit `fe04496196ea2ce42d1de27b0f770b02d2a87cd5` with the exact dependency string `github:ayooooo123/dht-rpc#fe04496196ea2ce42d1de27b0f770b02d2a87cd5`. The implementation is available for review in [fork-local PR #1](https://github.com/ayooooo123/dht-rpc/pull/1). Its exact-head branch-push [run 29646677295](https://github.com/ayooooo123/dht-rpc/actions/runs/29646677295) and pull-request [run 29646678762](https://github.com/ayooooo123/dht-rpc/actions/runs/29646678762) both completed with the same results:

- `Lint`: PASS
- `Test / linux`: PASS
- `Test / darwin`: PASS
- `Test / win32`: PASS
- `trigger_canary`: SKIPPED as expected because these were not tag builds

Each operating-system test job ran the repository's complete `npm test` command, covering both Node and Bare. This evidence proves only generic opaque-context propagation through the DHT-RPC request-transport seam and compatibility with its direct mode. It does not establish anonymity or demonstrate live private routing.

Historical intermediate evidence: DHT-RPC commit `42f954661994811ad9c187ace8e173e9146fc1ef` previously passed exact-head branch-push [run 29627693418](https://github.com/ayooooo123/dht-rpc/actions/runs/29627693418) and pull-request [run 29627694591](https://github.com/ayooooo123/dht-rpc/actions/runs/29627694591). That commit was the approved opaque-context pin before later traversal-query seam hardening produced the current `fe04496196ea2ce42d1de27b0f770b02d2a87cd5` pin. It is retained here only as historical compatibility evidence, not as the current dependency.

HyperDHT [run 29625809850](https://github.com/ayooooo123/hyperdht/actions/runs/29625809850) caught a direct-root `Session.destroy()` compatibility regression in an earlier DHT-RPC pin. Intermediate commit `8eea32f93fd83eb8de6bbddf9bb263720decb4af` restored reusable cancellation for legacy direct-root sessions while keeping child and transport-only sessions terminal.

HyperDHT [run 29627213694](https://github.com/ayooooo123/hyperdht/actions/runs/29627213694) then passed the forced-holepunch regression but caught direct caller-owned queries being converted into terminal child sessions during the reusable-socket test. Commit `42f954661994811ad9c187ace8e173e9146fc1ef` restores legacy caller-session borrowing for direct queries, while transport-only queries retain scoped terminal child sessions. These compatibility corrections do not add anonymity or demonstrate a live private route.

Final HyperDHT commit `5753a5b98a1e3dd5caabfcbd682df26b1111266f` completed [exact-head workflow run 29628278979](https://github.com/ayooooo123/hyperdht/actions/runs/29628278979) successfully. macOS, Ubuntu, and Windows each passed `npm install`, `npm test`, `npm run integration`, Bare installation, and `npm run test:bare`; the tag-only canary was skipped as expected. This is compatibility and regression evidence only. It does not establish anonymity or demonstrate a live private route.

### Gate 3A deterministic private-route cell core

The reviewed deterministic route-core head is `85d7b574496b7a6fda4b23290dd375ee4f0a1a43`. Its [exact-head workflow run 29635463646](https://github.com/ayooooo123/hyperdht/actions/runs/29635463646) completed successfully:

- [Ubuntu job 88056910166](https://github.com/ayooooo123/hyperdht/actions/runs/29635463646/job/88056910166): PASS for `npm test`, `npm run integration`, and `npm run test:bare`
- [macOS job 88056910151](https://github.com/ayooooo123/hyperdht/actions/runs/29635463646/job/88056910151): PASS for `npm test`, `npm run integration`, and `npm run test:bare`
- [Windows job 88056910117](https://github.com/ayooooo123/hyperdht/actions/runs/29635463646/job/88056910117): PASS for `npm test`, `npm run integration`, and `npm run test:bare`
- `trigger_canary`: SKIPPED as expected because this was not a tag build

The focused fragmentation suite passed 43/43 tests and 2,843/2,843 assertions independently in Node and Bare. The aggregate deterministic private-routing suite passed 175/175 tests and 5,620/5,620 assertions independently in Node and Bare. The reviewed core includes protocol errors and constants, cryptographic vectors and counters, fixed cells and authenticated route payloads, and bounded fragmentation/reassembly. This is deterministic protocol-core, resource-bound, compatibility, and regression evidence only. It does not establish a live route, anonymity, resistance to traffic analysis, or production readiness.

### Gate 3A deterministic DHT adapter and traversal

The reviewed deterministic adapter/traversal head is `e2da3a9c867eb4e077e7977330fa066a8ce2d4d6`. Its [exact-head workflow run 29646997859](https://github.com/ayooooo123/hyperdht/actions/runs/29646997859) completed successfully:

- [Ubuntu job 88086804697](https://github.com/ayooooo123/hyperdht/actions/runs/29646997859/job/88086804697): PASS for `npm test`, `npm run integration`, and `npm run test:bare`
- [macOS job 88086804707](https://github.com/ayooooo123/hyperdht/actions/runs/29646997859/job/88086804707): PASS for `npm test`, `npm run integration`, and `npm run test:bare`
- [Windows job 88086804718](https://github.com/ayooooo123/hyperdht/actions/runs/29646997859/job/88086804718): PASS for `npm test`, `npm run integration`, and `npm run test:bare`
- `trigger_canary`: SKIPPED as expected because this was not a tag build

The focused `RoutedDHTIO` and deterministic traversal suites passed 42/42 tests and 377/377 assertions independently in Node and Bare. The aggregate deterministic private-routing suite passed 247/247 tests and 7,219/7,219 assertions independently in Node and Bare. The reviewed substrate proves immutable-get command binding, unforgeable query contexts, opaque branch-bound destinations, fail-closed adapter lifecycle and ownership, and iterative traversal over a trusted in-process five-node fake topology.

This evidence is semantic-only compatibility and regression evidence. The fake topology sends no packets and contains no live authority, adjacent links, three-position route, routed-reply wire codec, DHT exit, or packet-capture oracle. It does not establish anonymity, traffic-analysis resistance, a live private route, or production readiness.

### Final Gate 3A verification

Final verification started from reviewed documentation head `68bd32a1d10ccd103a2ae27bb75e3846d90a5ab5`, with the branch and `origin/private-routing-v1` at that exact commit. Its [exact-head workflow run 29647577235](https://github.com/ayooooo123/hyperdht/actions/runs/29647577235) completed successfully:

- [macOS job 88088283556](https://github.com/ayooooo123/hyperdht/actions/runs/29647577235/job/88088283556): PASS for `npm install`, `npm test`, `npm run integration`, Bare installation, and `npm run test:bare`
- [Ubuntu job 88088283625](https://github.com/ayooooo123/hyperdht/actions/runs/29647577235/job/88088283625): PASS for the same commands
- [Windows job 88088283578](https://github.com/ayooooo123/hyperdht/actions/runs/29647577235/job/88088283578): PASS for the same commands
- `trigger_canary`: SKIPPED as expected because this was not a tag build

Fresh local verification on Node v22.19.0, npm 11.10.0, and Bare v1.30.3 produced these results:

- The focused `RoutedDHTIO` and deterministic traversal suites passed 42/42 tests and 377/377 assertions independently in Node and Bare.
- The aggregate deterministic private-routing suite passed 247/247 tests and 7,219/7,219 assertions independently in Node and Bare.
- `npm run integration` passed 1/1 test and 6/6 assertions in its separate-process connection path.
- `npm test` passed its repository-wide Prettier check, then reproduced the documented local multi-interface exception in `createServer + connect - same-LAN explicit keypair opens server`: 17 top-level tests completed with all 67 of their assertions passing before test 18 emitted `client should not error: HOLEPUNCH_ABORTED` and the run timed out at 30 seconds without a final TAP summary. `npm run test:bare` reproduced the same exception after the same 17 completed tests and 67 passing assertions, then timed out. These two local full-suite runs are not reported as green; the exact-head clean-host matrix above is the authoritative full-suite evidence.
- `npx prettier --check lib/private test/private docs README.md package.json` and `git diff --check` passed.
- `npm ls dht-rpc --depth=0` resolved `dht-rpc@6.27.0` at exact approved commit `fe04496196ea2ce42d1de27b0f770b02d2a87cd5`. `package.json` had no verification-time diff, `package-lock.json` remained ignored and untracked, and no `node_modules`, `build`, `target`, or `coverage` artifact was tracked.
- The Task 11 local documentation links resolve, its recorded GitHub runs and jobs still match their documented exact heads and successful conclusions, and the DHT-RPC review link remains open at the approved dependency head.

The final scope audit found no public `privateRouting` or `privacy` option, no Hyperswarm or PearTube change, and no direct fallback or host/port input in `RoutedDHTIO`. This remains an internal, address-free deterministic substrate with no live route authority or production anonymity claim. Delivery Gate 3 remains open until all ten Gate 3B entry criteria pass fork-native CI.

### DHT-RPC Gate 2

DHT-RPC Gate 2 is pinned to commit `49fea12c6c7677e50b114de64226b1856e308f3c` and is available for review in [fork-local PR #1](https://github.com/ayooooo123/dht-rpc/pull/1). The authoritative pull-request workflow [run 29621682832](https://github.com/ayooooo123/dht-rpc/actions/runs/29621682832) completed successfully with these job results:

- `Lint`: PASS
- `Test / linux`: PASS
- `Test / darwin`: PASS
- `Test / win32`: PASS
- `trigger_canary`: SKIPPED as expected because this was not a tag build

The matching branch-push workflow [run 29621681121](https://github.com/ayooooo123/dht-rpc/actions/runs/29621681121) independently produced the same results at the same commit. Each platform test job ran the repository's complete `npm test` command, covering both Node and Bare. This validates the generic, fail-closed request-transport seam and preservation of the direct-mode suite; it does not by itself establish an anonymous routing protocol.

### Upstream and initial fork evidence

- HyperDHT upstream SHA `ac6eaa5def633ccdd0b1c733f14b63036dbe4d33` passed its official Node, integration, and Bare jobs on Ubuntu, macOS, and Windows in [upstream workflow run 28976031145](https://github.com/holepunchto/hyperdht/actions/runs/28976031145).
- Hyperswarm upstream SHA `48d4241f69f848bb4c9dccb65b6fce5a9f40009d` passed its official jobs on all configured CI platforms in [upstream workflow run 26114678837](https://github.com/holepunchto/hyperswarm/actions/runs/26114678837).

GitHub Actions was explicitly activated through the documented repository permissions toggle, and workflows are now active in all four forks. The first fork-native HyperDHT and Hyperswarm runs did not reach package installation or test execution:

- HyperDHT [PR #1](https://github.com/ayooooo123/hyperdht/pull/1), head `58ce078ac4d1cc93fd25667f291ece1262394c42`, ran twice in [workflow run 29540819520](https://github.com/ayooooo123/hyperdht/actions/runs/29540819520). Checkout passed on macOS and Linux, but `setup-node` with `lts/*` received GitHub Unicorn HTML on those platforms. Windows was canceled by fail-fast. Neither attempt reached `npm install` or a package test.
- Hyperswarm [PR #1](https://github.com/ayooooo123/hyperswarm/pull/1), head `64ebdd47369f685766fcc16fe7cf49b5072e58f3`, ran twice in [workflow run 29540825599](https://github.com/ayooooo123/hyperswarm/actions/runs/29540825599). The `node-base` and `bare-base` setup failed before lint or tests with `failed to check version latest` on Linux and macOS. Windows was canceled by fail-fast. Neither attempt reached a package lint or test step.

These attempts coincided with GitHub Actions/API HTTP 503 responses and TLS timeouts while retrieving Actions log blobs. They are recorded as external CI bootstrap failures: they are not green results, but they also did not execute enough repository code to be classified as package failures. No deterministic Node-version pin was applied.

The external bootstrap condition later cleared without a repository setup change. HyperDHT commit `5af769c8e4e2fb31f65c58b9725789d3e5714ed3` completed its full fork-native matrix in [workflow run 29621927205](https://github.com/ayooooo123/hyperdht/actions/runs/29621927205): Ubuntu, macOS, and Windows each passed `npm test`, `npm run integration`, and `npm run test:bare`; the tag-only canary was skipped as expected. This is the current fork-native HyperDHT baseline evidence.

Upstream CI supports the conclusion that the two local exceptions are host-topology-sensitive baseline behavior. It is not evidence that the future private-routing protocol is anonymous, secure, or production-ready; those properties require the later protocol, leak-oracle, adversarial, and mobile gates.
