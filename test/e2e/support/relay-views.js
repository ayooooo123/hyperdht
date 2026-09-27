'use strict'

const b4a = require('b4a')
const { CellCodec } = require('../../../lib/private/cell-codec')

// Observe actual control reads/writes without adding a flowing data listener.
// The 31-byte suffix detects a key split across adjacent control chunks.
module.exports = function relayViews(h, destinationKey) {
  const restores = []
  const wrapped = new WeakSet()
  const leaks = []
  const headers = []
  let reads = 0
  let writes = 0
  let plaintexts = 0

  function opened(value, packet) {
    plaintexts++
    if (value.indexOf(destinationKey) !== -1) leaks.push({ direction: 'cell-plaintext' })
    headers.push({
      cellBytes: packet.length,
      epoch: packet.readBigUInt64BE(4),
      counter: packet.readBigUInt64BE(28),
      link: b4a.toString(packet.subarray(12, 28), 'hex'),
      direction: packet[2],
      payload: b4a.toString(value.subarray(5), 'hex'),
      at: Date.now()
    })
  }

  const result = {
    leaks,
    headers,
    counts: () => ({ reads, writes, plaintexts }),
    close() {
      for (const restore of restores.reverse()) restore()
    }
  }

  if (h.scope.hasSeam) {
    restores.push(
      h.observe((event) => {
        if (event.role !== 'relay') return
        if (event.type === 'control-read' || event.type === 'control-write') {
          if (event.type === 'control-read') reads++
          else writes++
          if (event.bytes.indexOf(destinationKey) !== -1) {
            leaks.push({ relay: b4a.toString(event.relayPublicKey, 'hex'), direction: event.type })
          }
        }
        if (event.type === 'route-cell-opened') opened(event.plaintext, event.cell)
      })
    )
    return result
  }

  function wrap(object, name, replacement) {
    const original = object[name]
    object[name] = replacement(original)
    restores.push(() => {
      object[name] = original
    })
  }

  function tap(stream, relay) {
    if (wrapped.has(stream)) return stream
    wrapped.add(stream)
    const tails = new Map()
    function inspect(value, direction) {
      if (!b4a.isBuffer(value)) return
      const previous = tails.get(direction)
      const bytes = previous ? b4a.concat([previous, value]) : value
      if (bytes.indexOf(destinationKey) !== -1) leaks.push({ relay, direction })
      tails.set(direction, b4a.from(bytes.subarray(Math.max(0, bytes.length - 31))))
      if (direction === 'read') reads++
      else writes++
    }
    wrap(
      stream,
      'read',
      (read) =>
        function (...args) {
          const value = read.apply(this, args)
          inspect(value, 'read')
          return value
        }
    )
    wrap(
      stream,
      'write',
      (write) =>
        function (value, ...args) {
          inspect(value, 'write')
          return write.call(this, value, ...args)
        }
    )
    return stream
  }

  for (const node of h.relays) {
    const controller = h.controller(node)
    const relay = b4a.toString(controller.relayKeyPair.publicKey, 'hex')
    wrap(
      controller,
      '_handleRelayConnection',
      (handle) =>
        function (stream) {
          return handle.call(this, tap(stream, relay))
        }
    )
    wrap(
      controller,
      '_connectRelay',
      (connect) =>
        async function (...args) {
          return tap(await connect.apply(this, args), relay)
        }
    )
  }

  wrap(
    CellCodec.prototype,
    'open',
    (open) =>
      function (options, packet) {
        const values = open.call(this, options, packet)
        for (const value of values) opened(value, packet)
        return values
      }
  )

  return result
}
