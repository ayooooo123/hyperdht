'use strict'

const { createCoherentClock } = require('./runtime-clock')

const clock = createCoherentClock(
  () => process.hrtime.bigint(),
  () => Date.now()
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
