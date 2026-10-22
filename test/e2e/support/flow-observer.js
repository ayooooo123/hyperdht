'use strict'

const b4a = require('b4a')
const frameObserver = require('./frame-observer')

const STREAM_WINDOW = 512
const CIRCUIT_WINDOW = 2048

module.exports = function observeFlow(h) {
  const decoder = frameObserver()
  const errors = new Set()
  const streams = new Map()
  const circuits = new Map()
  const demands = new Map()
  const peak = { stream: 0, circuit: 0 }
  const counts = {
    data: 0,
    streamCredit: 0,
    circuitCredit: 0,
    demand: 0,
    release: 0,
    withdrawals: 0,
    acknowledgements: 0,
    controlDuringData: 0,
    controlWhileSaturated: 0
  }
  let outstanding = 0
  let onSaturated = null
  let saturated = 0

  function account(rows, key, amount, scope) {
    const previous = rows.get(key) || 0
    const next = previous + amount
    rows.set(key, next)
    peak[scope] = Math.max(peak[scope], next)
    const limit = scope === 'stream' ? STREAM_WINDOW : CIRCUIT_WINDOW
    if (next < 0 || next > limit) errors.add(scope + ' credit balance outside 0..' + limit)
    if (scope === 'stream') {
      outstanding += amount
      saturated += Number(next >= STREAM_WINDOW) - Number(previous >= STREAM_WINDOW)
      if (saturated > 0 && onSaturated) {
        onSaturated()
        onSaturated = null
      }
    }
  }

  function sourceDemand(view, frame, sealed) {
    let state = demands.get(view)
    if (!state) {
      state = { wanted: 0, available: 0, withdrawing: false }
      demands.set(view, state)
    }
    if (frame.scope === 'stream') {
      if (sealed && frame.type === 'data') state.available--
    } else if (sealed && frame.type === 'demand') {
      if (frame.count === 0) {
        if (state.withdrawing || state.wanted === 0)
          errors.add('withdrawal without outstanding demand')
        state.withdrawing = true
        counts.withdrawals++
      } else {
        if (state.withdrawing || state.wanted !== 0)
          errors.add('new demand before previous demand settled')
        state.wanted = frame.count
      }
    } else if (!sealed && frame.type === 'demand') {
      if (frame.count !== 0 || !state.withdrawing) errors.add('unexpected demand acknowledgement')
      // Earlier ordered grants remain valid until this acknowledgement arrives.
      state.wanted = 0
      state.withdrawing = false
      counts.acknowledgements++
    } else if (!sealed && frame.type === 'credit') {
      state.wanted -= frame.count
      state.available += frame.count
    } else if (sealed && frame.type === 'release') {
      state.available -= frame.count
    }
    if (state.wanted < 0 || state.wanted > CIRCUIT_WINDOW)
      errors.add('circuit grant exceeds demand')
    if (state.available < 0 || state.available > CIRCUIT_WINDOW)
      errors.add('circuit grant overspent or oversized')
  }

  const stop = h.observe((event) => {
    const frame = decoder.observe(event)
    if (!frame || frame.type === 'source-control' || frame.type === 'invalid') return
    if (event.role !== 'endpoint') return
    if (event.label !== 'source-endpoint' && event.label !== 'destination-endpoint') return
    const sealed = event.type === 'route-cell-sealed'
    const view = event.label + ':' + b4a.toString(event.cell.subarray(12, 28), 'hex')
    const lane = sealed ? 'send' : 'receive'
    const returning = sealed ? 'receive' : 'send'
    const streamKey = view + ':' + frame.streamId + ':'

    if (!sealed && frame.flags >= 4) {
      if (outstanding > 0) counts.controlDuringData++
      if (saturated > 0) counts.controlWhileSaturated++
      if (frame.type === 'credit')
        counts[frame.scope === 'stream' ? 'streamCredit' : 'circuitCredit']++
    }
    if (sealed && (frame.type === 'demand' || frame.type === 'release')) {
      counts[frame.type]++
    }
    if (frame.type === 'data') {
      counts.data++
      account(streams, streamKey + lane, 1, 'stream')
      if (event.label === 'destination-endpoint') account(circuits, view + ':' + lane, 1, 'circuit')
    } else if (frame.type === 'credit' && frame.scope === 'stream') {
      account(streams, streamKey + returning, -frame.count, 'stream')
    } else if (frame.type === 'credit' && event.label === 'destination-endpoint') {
      // At the shared destination leg circuit CREDIT returns consumed cells.
      // At the source leg it grants demand instead; it is not a receive ACK.
      account(circuits, view + ':' + returning, -frame.count, 'circuit')
    }
    if (event.label === 'source-endpoint') sourceDemand(view, frame, sealed)
  })

  return {
    peak,
    counts,
    errors,
    close: stop,
    whenSaturated() {
      if (saturated > 0) return Promise.resolve()
      return new Promise((resolve) => {
        onSaturated = resolve
      })
    },
    assertBounds(t, { streamCredit = true } = {}) {
      t.alike(
        Array.from(decoder.errors),
        [],
        'all observed wire frames decode under control version 7'
      )
      t.alike(
        Array.from(errors),
        [],
        'credit returns and ordered demand acknowledgements preserve balances'
      )
      t.ok(
        peak.stream > 0 && peak.stream <= STREAM_WINDOW,
        'in-flight cells per stream never exceed 512'
      )
      t.ok(
        peak.circuit > 0 && peak.circuit <= CIRCUIT_WINDOW,
        'in-flight cells per circuit never exceed 2048'
      )
      t.ok(counts.controlDuringData > 0, 'flow-control frames progress while DATA is in flight')
      t.ok(counts.circuitCredit > 0, 'circuit grants or returns reach their endpoint')
      if (streamCredit)
        t.ok(counts.streamCredit > 0, 'raw-reader stream credit returns reach their endpoint')
    }
  }
}
