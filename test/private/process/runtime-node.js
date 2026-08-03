'use strict'

const { createCoherentClock } = require('./runtime-clock')

const clock = createCoherentClock(
  () => process.hrtime.bigint(),
  () => Date.now()
)

module.exports = Object.freeze({
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
