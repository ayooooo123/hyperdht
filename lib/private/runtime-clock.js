'use strict'

// Adjacent wall/monotonic reads share one sample for deadline projection.
// Each new wall sample is raw: cross-sample smoothing biases strict wire expiry
// checks between runtimes. Wall jumps remain visible to the owning protocol;
// monotonic time is sampled independently and owns elapsed deadlines.

function createCoherentClock(hrtimeBigint, dateNow) {
  let sampledMonotonic = null
  let sampledWall = null

  function sample() {
    if (sampledMonotonic !== null) return
    const monotonic = hrtimeBigint() / 1_000_000n
    const wall = BigInt(dateNow())

    sampledMonotonic = monotonic
    sampledWall = wall
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
