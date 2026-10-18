'use strict'

const process = require('bare-process')
const { createCoherentClock } = require('../../../lib/private/runtime-clock')

let lastMono = null
let lastWall = null
const clock = createCoherentClock(
  () => process.hrtime.bigint(),
  () => {
    const mono = process.hrtime.bigint() / 1_000_000n
    let wall = BigInt(Date.now())
    if (lastMono !== null) {
      const expected = lastWall + (mono - lastMono)
      if (expected - wall === 1n) wall = expected
    }
    lastMono = mono
    lastWall = wall
    return wall
  }
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
