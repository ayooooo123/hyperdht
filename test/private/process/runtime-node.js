'use strict'

const { createCoherentClock } = require('../../../lib/private/runtime-clock')

const baseMono = process.hrtime.bigint() / 1_000_000n
const baseWall = BigInt(Date.now())
const clock = createCoherentClock(
  () => process.hrtime.bigint(),
  () => baseWall + (process.hrtime.bigint() / 1_000_000n - baseMono)
)

module.exports = Object.freeze({
  // Diagnostic sink only; see traceFatal in role-runner.js.
  fatalLog: process.env.PR_ROLE_FATAL_LOG || null,
  socketCloseLog: process.env.PR_SOCKET_CLOSE_LOG || null,
  exit(code) {
    process.exit(code)
  },
  monotonicNow() {
    return clock.monotonicNow()
  },
  runtime: 'node',
  stderr: process.stderr,
  stdin: process.stdin,
  stdout: process.stdout,
  version: process.version,
  wallNow() {
    return clock.wallNow()
  }
})
