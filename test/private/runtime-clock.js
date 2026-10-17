'use strict'

const test = require('brittle')
const { createCoherentClock } = require('../../lib/private/runtime-clock')

for (const firstRead of ['wallNow', 'monotonicNow']) {
  test(`paired clock keeps one sample when ${firstRead} is read first`, async (t) => {
    let monoNs = 0n
    let wallMs = 9000
    const clock = createCoherentClock(
      () => monoNs,
      () => wallMs
    )
    clock[firstRead]()
    wallMs = 9001
    monoNs = 1_000_000n
    t.is(clock.wallNow(), 9000n, 'a synchronous wall read retains the paired sample')
    t.is(clock.monotonicNow(), 0n, 'a synchronous monotonic read retains the paired sample')
    await Promise.resolve()
    t.is(clock.wallNow(), 9001n, 'the next turn observes the new wall sample')
    t.is(clock.monotonicNow(), 1n, 'the next turn observes the new monotonic sample')
  })
}
