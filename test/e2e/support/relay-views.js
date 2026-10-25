'use strict'

const b4a = require('b4a')
const frameObserver = require('./frame-observer')

module.exports = function relayViews(h, destinationKey) {
  const decoder = frameObserver()
  const leaks = []
  const headers = []
  let reads = 0
  let writes = 0
  let plaintexts = 0

  const stop = h.observe((event) => {
    const frame = decoder.observe(event)
    if (event.role !== 'relay') return
    const relay = b4a.toString(event.relayPublicKey, 'hex')
    if (event.type === 'control-read' || event.type === 'control-write') {
      if (event.type === 'control-read') reads++
      else writes++
      // Inspect every complete field: inner source-cell opcodes 1/2 are not
      // outer setup opcodes 3..7, and neither labels nor write attempts prove a read.
      if (event.bytes.indexOf(destinationKey) !== -1) {
        leaks.push({ relay, direction: event.type, label: event.label, opcode: event.opcode })
      }
    }
    if (event.type !== 'route-cell-opened') return
    plaintexts++
    if (event.plaintext.indexOf(destinationKey) !== -1) {
      leaks.push({ relay, direction: 'cell-plaintext', label: event.label })
    }
    const circuitId = b4a.toString(event.cell.subarray(12, 28), 'hex')
    headers.push({
      view: [relay, event.label, circuitId, event.direction].join(':'),
      relay,
      label: event.label,
      circuitId,
      direction: event.direction,
      cellBytes: event.cell.byteLength,
      epoch: event.cell.readBigUInt64BE(4),
      counter: event.cell.readBigUInt64BE(28),
      type: frame.type,
      scope: frame.scope,
      count: frame.count,
      streamId: frame.streamId,
      payload: b4a.toString(frame.data, 'hex'),
      at: Date.now()
    })
  })

  return {
    leaks,
    errors: decoder.errors,
    headers,
    counts: () => ({ reads, writes, plaintexts }),
    close: stop
  }
}
