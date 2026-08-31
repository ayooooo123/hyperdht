'use strict'

// The route protocol transfers a wall-clock expiry into a monotonic local deadline
// and then requires every downstream hop to stay within the deadline it was handed.
// That only holds when a role's wall and monotonic clocks advance by exactly the same
// amount: two independent samples (`Date.now()` and `hrtime`) can straddle a
// millisecond boundary and inflate the derived deadline by 1ms, which the peer rejects
// as unauthenticated. So both clocks read one cached sample of a single counter, and
// the cache is dropped on the next microtask: adjacent reads are always coherent and
// every advance is identical in both clocks.
function createCoherentClock(hrtimeBigint, dateNow) {
  const originMonotonic = hrtimeBigint()
  // Roles compare monotonic deadlines they received from other processes, so this
  // clock must keep `hrtime`'s machine-wide scale, not restart per process.
  const originMonotonicMs = originMonotonic / 1_000_000n
  const originWall = BigInt(dateNow())
  let elapsed = null

  function elapsedMs() {
    if (elapsed !== null) return elapsed
    elapsed = (hrtimeBigint() - originMonotonic) / 1_000_000n
    queueMicrotask(() => {
      elapsed = null
    })
    return elapsed
  }

  return {
    monotonicNow() {
      return originMonotonicMs + elapsedMs()
    },
    wallNow() {
      return originWall + elapsedMs()
    }
  }
}

module.exports = { createCoherentClock }
