'use strict'

const { hrtime } = require('process')
const monotonicNow = hrtime.bigint.bind(hrtime)
const advancingClocks = new WeakSet()

function createAdvancingClock({ now = Date.now(), rate = 1 } = {}) {
  if (!Number.isSafeInteger(now) || now < 0 || !Number.isFinite(rate) || rate <= 0) {
    throw new TypeError('Invalid advancing-clock origin or rate')
  }
  const started = monotonicNow()
  const clock = Object.freeze({
    now() {
      const current = Math.floor(now + (Number(monotonicNow() - started) / 1e6) * rate)
      if (!Number.isSafeInteger(current)) throw new RangeError('Advancing clock exhausted')
      return current
    },
    setTimeout(callback, milliseconds) {
      if (typeof callback !== 'function' || !Number.isFinite(milliseconds) || milliseconds < 0) {
        throw new TypeError('Invalid advancing-clock timer')
      }
      return setTimeout(callback, Math.max(1, Math.ceil(milliseconds / rate)))
    },
    clearTimeout(timer) {
      clearTimeout(timer)
    }
  })
  advancingClocks.add(clock)
  return clock
}

function isAdvancingClock(clock) {
  return advancingClocks.has(clock)
}

module.exports = { createAdvancingClock, isAdvancingClock }
