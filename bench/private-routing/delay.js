'use strict'

// This is application-send/UDX-write latency, not WAN or packet-level netem.
// Native ACKs, retransmissions and UDP discovery are not delayed. Keeping the
// original callback pending preserves UDX backpressure instead of adding credit.
module.exports = function installDelay(delayMs) {
  const UDXStream = require('udx-native/lib/stream')
  const original = UDXStream.prototype._writev
  const capBytes = 2 * 1024 * 1024
  const capWrites = 256
  const pending = new Set()
  let queuedBytes = 0
  const stats = { delayMs, capBytes, capWrites, writes: 0, maxBytes: 0, rejected: 0 }

  if (delayMs > 0) {
    UDXStream.prototype._writev = function (buffers, callback) {
      const bytes = buffers.reduce((sum, buffer) => sum + buffer.byteLength, 0)
      if (queuedBytes + bytes > capBytes || pending.size >= capWrites) {
        stats.rejected++
        callback(new Error('benchmark UDX-write latency queue limit exceeded'))
        return
      }
      queuedBytes += bytes
      stats.writes++
      stats.maxBytes = Math.max(stats.maxBytes, queuedBytes)
      const entry = { timer: null, callback, bytes }
      pending.add(entry)
      entry.timer = setTimeout(() => {
        pending.delete(entry)
        queuedBytes -= bytes
        if (this.destroying || this.destroyed) {
          callback(new Error('stream closed during benchmark UDX-write latency'))
          return
        }
        try {
          original.call(this, buffers, callback)
        } catch (error) {
          callback(error)
        }
      }, delayMs)
    }
  }

  return {
    stats,
    close() {
      UDXStream.prototype._writev = original
      for (const entry of pending) {
        clearTimeout(entry.timer)
        entry.callback(new Error('benchmark UDX-write latency stopped'))
      }
      pending.clear()
      queuedBytes = 0
    }
  }
}
