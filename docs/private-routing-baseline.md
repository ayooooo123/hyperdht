# Private Routing Fork Baselines

This record pins the upstream-derived roots used for the private-routing experiment and reports the baseline checks that were run before transport implementation. It records compatibility evidence only. It does not establish anonymity, resistance to traffic analysis, production readiness, or suitability for protecting users.

| Repository         | Upstream SHA                               | Private branch root                        | Node     | Bare    | Commands                                               | Result                                                                                                                                                                                                                                                                                           |
| ------------------ | ------------------------------------------ | ------------------------------------------ | -------- | ------- | ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| dht-rpc            | `a079674d7185ece6fe310974ef8cabc5bc59d4e2` | `a079674d7185ece6fe310974ef8cabc5bc59d4e2` | v22.19.0 | v1.30.3 | `npm run lint`; `npm test`                             | PASS: lint completed with 10 pre-existing `require-await` warnings; Node 52/52 tests and 215/215 assertions; Bare 52/52 tests and 215/215 assertions.                                                                                                                                            |
| hyperdht           | `ac6eaa5def633ccdd0b1c733f14b63036dbe4d33` | `0ba10b089df5b01c55e154a3ccf4e2d0843deb95` | v22.19.0 | v1.30.3 | `npm test`; `npm run integration`; `npm run test:bare` | HOST EXCEPTION: formatter passed. Node and Bare each reached 90/91 tests and 362/363 assertions; each failed only the same-LAN explicit-keypair case. Integration hung in its separate-process connection path and was terminated. See below.                                                    |
| hyperswarm         | `48d4241f69f848bb4c9dccb65b6fce5a9f40009d` | `64ebdd47369f685766fcc16fe7cf49b5072e58f3` | v22.19.0 | v1.30.3 | `npm run lint`; `npm test`                             | HOST EXCEPTION: lint passed with 8 pre-existing warnings. Node and Bare both reproduced a chaos connection-count/startup failure on the local multi-interface host; Node later timed out in peer-join and Bare was stopped after the chaos failure was confirmed. Fork CI is pending. See below. |
| hyperswarm-testnet | `c301fb808735caeebf711c0bc6de79b7c1036bfa` | `c301fb808735caeebf711c0bc6de79b7c1036bfa` | v22.19.0 | v1.30.3 | `npm run lint`; `npm test`                             | PASS: lint; Node 2/2 tests and 3/3 assertions; Bare 2/2 tests and 3/3 assertions.                                                                                                                                                                                                                |

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

- HyperDHT upstream SHA `ac6eaa5def633ccdd0b1c733f14b63036dbe4d33` passed its official Node, integration, and Bare jobs on Ubuntu, macOS, and Windows in [upstream workflow run 28976031145](https://github.com/holepunchto/hyperdht/actions/runs/28976031145).
- Hyperswarm upstream SHA `48d4241f69f848bb4c9dccb65b6fce5a9f40009d` passed its official jobs on all configured CI platforms in [upstream workflow run 26114678837](https://github.com/holepunchto/hyperswarm/actions/runs/26114678837).
- CI for the fresh Hyperswarm fork PR was pending when this baseline was recorded. It is intentionally not described as green.

Upstream CI supports the conclusion that the two local exceptions are host-topology-sensitive baseline behavior. It is not evidence that the future private-routing protocol is anonymous, secure, or production-ready; those properties require the later protocol, leak-oracle, adversarial, and mobile gates.
