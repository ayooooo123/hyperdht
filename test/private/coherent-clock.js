'use strict'

// Wall and monotonic readings a test hands to the route owners must agree.
//
// The protocol converts a wall duration into the monotonic domain and then
// rejects any hop whose derived deadline exceeds the one it was handed, for
// example in `createExtensionLinkOffer`:
//
//   const remaining = deadline - now                  // wall
//   const localDeadline = monotonicNow + remaining    // monotonic
//   if (localDeadline > material.localDeadline) authentication()
//
// Two independent `Date.now()` calls straddling a millisecond boundary make
// `monotonicNow` one millisecond later than `now`, which inflates the derived
// deadline past the bound and fails authentication. It is rare, load dependent,
// and it does not reproduce on a fast host.
//
// `test/private/process/runtime-clock.js` already solves this for the role
// runtimes by deriving both readings from a single cached sample. This is the
// same guarantee for in-process tests, and it stays in the `Date.now()` domain
// so it does not change any value a test observes.

function createCoherentTestClock() {
  let cached = null
  const sample = () => {
    if (cached === null) {
      cached = BigInt(Date.now())
      // Both readings within one turn see the same instant; the next turn
      // re-samples, so time still advances.
      queueMicrotask(() => {
        cached = null
      })
    }
    return cached
  }
  return Object.freeze({ monotonicNow: sample, wallNow: sample })
}

module.exports = Object.freeze({ createCoherentTestClock })
