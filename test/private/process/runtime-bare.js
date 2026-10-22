'use strict'

const process = require('bare-process')
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
  exit(code) {
    process.exit(code)
  },
  monotonicNow() {
    return clock.monotonicNow()
  },
  runtime: 'bare',
  stderr: process.stderr,
  stdin: process.stdin,
  stdout: process.stdout,
  version: process.version,
  wallNow() {
    return clock.wallNow()
  }
})
