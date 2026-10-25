'use strict'

const test = require('brittle')

// A baseline runtime rejection is a failed assertion, never an expected pass or
// skip. Continue to the other B1 cases so one known defect cannot hide another.
module.exports = function pending(name, run) {
  return test(name, async (t) => {
    try {
      await run(t)
    } catch (error) {
      t.fail(error.stack || error.message)
    }
  })
}
