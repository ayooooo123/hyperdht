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

These attempts coincided with GitHub Actions/API HTTP 503 responses and TLS timeouts while retrieving Actions log blobs. They are recorded as external CI bootstrap failures: they are not green results, but they also did not execute enough repository code to be classified as package failures. A deterministic Node-version pin has been proposed as a resilience improvement, but remains pending explicit approval and is not part of this baseline commit.

Upstream CI supports the conclusion that the two local exceptions are host-topology-sensitive baseline behavior. It is not evidence that the future private-routing protocol is anonymous, secure, or production-ready; those properties require the later protocol, leak-oracle, adversarial, and mobile gates.
