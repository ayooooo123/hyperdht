'use strict'

const fs = require('fs')
const { hrtime } = require('process')

// Namespace-test instrumentation only. Observe the real native socket and return
// its original close promise. No send, bind, close ordering, or delay is changed.
module.exports = function observeSocketClosures(UDX, isStopping, file) {
  const createSocket = UDX.prototype.createSocket
  const records = []
  const wallStart = Date.now()
  const monotonicStart = hrtime.bigint()
  let failure = null

  function millis() {
    const wall = Date.now()
    const elapsed = Number(hrtime.bigint() - monotonicStart) / 1e6
    if (Math.abs(wall - wallStart - elapsed) > 2) {
      throw new Error('socket close observer realtime clock changed')
    }
    return wall
  }

  UDX.prototype.createSocket = function (...args) {
    const socket = createSocket.apply(this, args)
    const close = socket.close
    let observed = false
    socket.close = function (...closeArgs) {
      if (observed || !isStopping()) return close.apply(this, closeArgs)
      observed = true
      let record = null
      try {
        const address = socket.address()
        if (address) {
          record = {
            host: address.host,
            port: address.port,
            // Round forward with 2 ms clock uncertainty. Near-boundary packets
            // remain unmatched; never backdate eligibility to cover the race.
            startMicros: (millis() + 3) * 1000,
            endMicros: null
          }
          records.push(record)
        }
      } catch (err) {
        // An audit failure must not prevent the real socket from closing.
        failure = err
      }
      const result = close.apply(this, closeArgs)
      if (record === null) return result
      Promise.resolve(result).then(
        () => {
          try {
            record.endMicros = (millis() + 3) * 1000
          } catch (err) {
            failure = err
          }
        },
        (err) => {
          failure = err || new Error('native socket close failed')
        }
      )
      return result
    }
    return socket
  }

  return function finish() {
    UDX.prototype.createSocket = createSocket
    if (failure) throw failure
    if (records.some((record) => record.endMicros === null)) {
      throw new Error('native socket close interval is incomplete')
    }
    fs.writeFileSync(file, JSON.stringify(records))
  }
}
