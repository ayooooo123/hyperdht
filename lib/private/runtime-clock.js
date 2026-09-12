'use strict'

// Route deadlines combine a wall-clock expiry with the machine-wide monotonic
// clock. Adjacent reads must use one sample so millisecond-boundary skew cannot
// inflate a derived deadline. The wall side must still observe real clock jumps:
// forward jumps expire signed material, and rollbacks over the protocol limit
// revoke the owning route state.
const MAX_SAMPLE_SKEW_MS = 1n

function createCoherentClock(hrtimeBigint, dateNow) {
  let lastMonotonic = null
  let lastWall = null
  let sampledMonotonic = null
  let sampledWall = null

  function sample() {
    if (sampledMonotonic !== null) return
    const monotonic = hrtimeBigint() / 1_000_000n
    const wall = BigInt(dateNow())

    if (lastMonotonic === null) {
      sampledWall = wall
    } else {
      const expectedWall = lastWall + (monotonic - lastMonotonic)
      const drift = wall - expectedWall
      sampledWall = drift < -MAX_SAMPLE_SKEW_MS || drift > MAX_SAMPLE_SKEW_MS ? wall : expectedWall
    }

    sampledMonotonic = monotonic
    lastMonotonic = monotonic
    lastWall = sampledWall
    queueMicrotask(() => {
      sampledMonotonic = null
      sampledWall = null
    })
  }

  return {
    monotonicNow() {
      sample()
      return sampledMonotonic
    },
    wallNow() {
      sample()
      return sampledWall
    }
  }
}

module.exports = { createCoherentClock }
