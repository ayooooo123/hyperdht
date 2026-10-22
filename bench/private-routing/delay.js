'use strict'

const METHOD = 'application-udx-delay-line-v2'
const CAP_BYTES = 64 * 1024 * 1024
const CAP_WRITES = 16384
let installed = false

// Application/UDX injection only: discovery, transport ACKs and retransmits are
// untouched. Install before constructing UDX streams (native callbacks are bound
// at construction). Admission, not native drain, completes the caller's write.
module.exports = function installDelay(
  delayMs,
  { capBytes = CAP_BYTES, capWrites = CAP_WRITES } = {}
) {
  if (!Number.isFinite(delayMs) || delayMs < 0 || delayMs > 2147483647) {
    throw new Error('invalid benchmark injection delay')
  }
  if (![capBytes, capWrites].every((n) => Number.isSafeInteger(n) && n > 0)) {
    throw new Error('invalid benchmark delay line bound')
  }
  if (installed) throw new Error('benchmark delay line already installed')
  const prototype = require('udx-native/lib/stream').prototype
  const original = {
    _writev: prototype._writev,
    _final: prototype._final,
    _onack: prototype._onack,
    flush: prototype.flush
  }
  const states = new Map()
  const owners = new WeakMap()
  let stopped = false
  const stats = {
    method: METHOD,
    delayMs,
    capBytes,
    capWrites,
    writes: 0,
    acceptedBytes: 0,
    submitted: 0,
    submittedBytes: 0,
    nativeCompleted: 0,
    nativeCompletedBytes: 0,
    rejected: 0,
    errors: 0,
    discarded: 0,
    discardedBytes: 0,
    queuedBytes: 0,
    queuedWrites: 0,
    nativeBytes: 0,
    nativeWrites: 0,
    outstandingBytes: 0,
    outstandingWrites: 0,
    maxBytes: 0,
    maxWrites: 0
  }
  // Zero delay is the explicitly labelled native, uncopied control condition.
  if (delayMs === 0) return { stats, close() {} }
  installed = true

  function stateFor(stream) {
    let state = states.get(stream)
    if (state) return state
    state = {
      stream,
      queue: [],
      entries: new Set(),
      timer: null,
      blocked: false,
      pumping: false,
      failed: false,
      final: null,
      waiters: []
    }
    states.set(stream, state)
    stream.once('close', () => {
      cancel(state, new Error('stream closed during benchmark injection delay'))
      // Native owns copies until completion (ACK/cancel) or stream close, NOT
      // _writev's drain callback. close() keeps those bytes charged until then.
      for (const entry of state.entries) release(state, entry, false)
      states.delete(stream)
    })
    return state
  }

  function release(state, entry, completed) {
    if (!state.entries.delete(entry)) return
    const prefix = entry.native ? 'native' : 'queued'
    stats[prefix + 'Bytes'] -= entry.bytes
    stats[prefix + 'Writes']--
    stats.outstandingBytes -= entry.bytes
    stats.outstandingWrites--
    stats[completed ? 'nativeCompleted' : 'discarded']++
    stats[completed ? 'nativeCompletedBytes' : 'discardedBytes'] += entry.bytes
    owners.delete(entry.buffer)
    entry.buffer = null
  }

  function wake(state, ok) {
    for (const resolve of state.waiters.splice(0)) resolve(ok)
  }

  function cancel(state, error) {
    if (state.failed) return
    state.failed = true
    clearTimeout(state.timer)
    state.timer = null
    for (const entry of state.queue) release(state, entry, false)
    state.queue.length = 0
    wake(state, false)
    if (state.final) {
      const callback = state.final
      state.final = null
      callback(error)
    }
  }

  function fail(state, error) {
    if (state.failed) return
    stats.errors++
    cancel(state, error)
    state.stream.destroy(error)
  }

  function pump(state) {
    if (state.pumping || state.blocked || state.failed) return
    if (state.stream.destroying || state.stream.destroyed) {
      cancel(state, new Error('stream destroyed during benchmark injection delay'))
      return
    }
    state.pumping = true
    try {
      while (!state.blocked && !state.failed && state.queue.length) {
        const entry = state.queue[0]
        const remaining = entry.due - performance.now()
        if (remaining > 0) {
          if (state.timer === null)
            state.timer = setTimeout(() => {
              state.timer = null
              pump(state)
            }, Math.ceil(remaining))
          return
        }
        state.queue.shift()
        entry.native = true
        stats.queuedBytes -= entry.bytes
        stats.queuedWrites--
        stats.nativeBytes += entry.bytes
        stats.nativeWrites++
        stats.submitted++
        stats.submittedBytes += entry.bytes
        state.blocked = true
        let completed = false
        original._writev.call(state.stream, [entry.buffer], (error) => {
          if (completed) return
          completed = true
          state.blocked = false
          if (error) fail(state, error)
          else pump(state)
        })
      }
      if (!state.blocked && !state.failed && state.queue.length === 0) {
        wake(state, true)
        if (state.final) {
          const callback = state.final
          state.final = null
          let completed = false
          const finish = (error) => {
            if (completed) return
            completed = true
            callback(error)
          }
          try {
            original._final.call(state.stream, finish)
          } catch (error) {
            finish(error)
          }
        }
      }
    } catch (error) {
      fail(state, error)
    } finally {
      state.pumping = false
    }
  }

  prototype._writev = function (buffers, callback) {
    const state = stateFor(this)
    const bytes = buffers.reduce((sum, buffer) => sum + buffer.byteLength, 0)
    const closed = stopped || state.failed || this.destroying || this.destroyed
    if (
      closed ||
      stats.outstandingBytes + bytes > capBytes ||
      stats.outstandingWrites >= capWrites
    ) {
      stats.rejected++
      const error = new Error(
        closed
          ? 'benchmark injection delay is closed'
          : 'benchmark injection delay byte/write bound exceeded'
      )
      error.code = closed ? 'BENCH_DELAY_CLOSED' : 'BENCH_DELAY_OVERFLOW'
      callback(error)
      fail(state, error)
      return
    }
    let buffer
    try {
      // A standalone allocation makes the byte bound real, including small
      // writes; Buffer.from() could retain a much larger shared pool slab.
      buffer = Buffer.allocUnsafeSlow(bytes)
      let offset = 0
      for (const source of buffers) {
        buffer.set(source, offset)
        offset += source.byteLength
      }
    } catch (error) {
      callback(error)
      fail(state, error)
      return
    }
    const entry = { buffer, bytes, due: performance.now() + delayMs, native: false }
    state.entries.add(entry)
    state.queue.push(entry)
    owners.set(buffer, { state, entry })
    stats.writes++
    stats.acceptedBytes += bytes
    stats.queuedBytes += bytes
    stats.queuedWrites++
    stats.outstandingBytes += bytes
    stats.outstandingWrites++
    stats.maxBytes = Math.max(stats.maxBytes, stats.outstandingBytes)
    stats.maxWrites = Math.max(stats.maxWrites, stats.outstandingWrites)
    pump(state)
    callback(null)
  }

  prototype._onack = function (id) {
    // udx-native 1.20.7 drops native completion status, so this counter includes
    // cancellation. Only the benchmark's verified receipts prove delivery.
    const req = this._wreqs[id]
    const owner = req && req.buffer && owners.get(req.buffer)
    original._onack.call(this, id)
    if (owner) release(owner.state, owner.entry, true)
  }

  prototype._final = function (callback) {
    const state = stateFor(this)
    if (stopped || state.failed) return callback(new Error('benchmark injection delay closed'))
    state.final = callback
    pump(state)
  }

  prototype.flush = async function () {
    // streamx drain alone now means admission. Wait for delayed submission as
    // well, then use UDX's real ACK barrier, preserving SecretStream.flush().
    if ((await require('streamx').Writable.drained(this)) === false) return false
    const state = states.get(this)
    if (state) {
      if (state.failed) return false
      if (state.queue.length || state.blocked) {
        if (!(await new Promise((resolve) => state.waiters.push(resolve)))) return false
      }
    }
    return original.flush.call(this)
  }

  return {
    stats,
    close() {
      if (stopped) return
      stopped = true
      for (const state of states.values()) {
        cancel(state, new Error('benchmark injection delay stopped'))
        state.stream.destroy()
      }
      Object.assign(prototype, original)
      installed = false
    }
  }
}

module.exports.METHOD = METHOD
module.exports.CAP_BYTES = CAP_BYTES
module.exports.CAP_WRITES = CAP_WRITES
