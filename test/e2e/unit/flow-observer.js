'use strict'

const test = require('brittle')
const b4a = require('b4a')
const observeFlow = require('../support/flow-observer')
const frameObserver = require('../support/frame-observer')
const { CIRCUIT_STREAM_ID } = require('../support/logical-frame')

function fixture(label = 'destination-endpoint') {
  let observer
  const flow = observeFlow({
    observe(fn) {
      observer = fn
      return () => {}
    }
  })
  const cell = b4a.alloc(1200)
  cell.fill(1, 12, 28)
  return {
    flow,
    send(type, streamId, flags, count = 1) {
      const plaintext = b4a.alloc(flags >= 4 ? 7 : flags === 0 ? 6 : 5)
      plaintext.writeUInt32BE(streamId, 0)
      plaintext[4] = flags
      if (flags >= 4) plaintext.writeUInt16BE(count, 5)
      observer({ type: 'route-cell-' + type, label, role: 'endpoint', cell, plaintext })
    }
  }
}

test('stream accounting accepts 512 cells and detects the next uncredited cell', async (t) => {
  const { flow, send } = fixture()
  const saturated = flow.whenSaturated()
  for (let i = 0; i < 512; i++) send('opened', 2, 0)
  await saturated
  t.is(flow.peak.stream, 512)
  t.alike(Array.from(flow.errors), [])
  send('opened', 2, 0)
  t.ok(flow.errors.has('stream credit balance outside 0..512'))
})

test('shared circuit accounting sums distinct streams independently of stream bounds', (t) => {
  const { flow, send } = fixture()
  for (const id of [2, 4, 6, 8]) {
    for (let i = 0; i < 512; i++) send('opened', id, 0)
  }
  t.is(flow.peak.circuit, 2048)
  t.alike(Array.from(flow.errors), [])
  send('opened', 10, 0)
  t.is(flow.peak.stream, 512)
  t.alike(Array.from(flow.errors), ['circuit credit balance outside 0..2048'])
})

test('raw-reader returns replenish their own stream and shared circuit balances', (t) => {
  const { flow, send } = fixture()
  for (let cycle = 0; cycle < 5; cycle++) {
    for (let i = 0; i < 128; i++) send('opened', 2, 0)
    send('sealed', 2, 4, 128)
    send('sealed', CIRCUIT_STREAM_ID, 4, 128)
  }
  t.is(flow.peak.stream, 128)
  t.is(flow.peak.circuit, 128)
  t.alike(Array.from(flow.errors), [])
  send('sealed', 2, 4, 1)
  t.ok(flow.errors.has('stream credit balance outside 0..512'))
})

test('source circuit grants fund DATA instead of acknowledging received DATA', (t) => {
  const { flow, send } = fixture('source-endpoint')
  send('sealed', CIRCUIT_STREAM_ID, 5, 512)
  send('opened', CIRCUIT_STREAM_ID, 4, 512)
  for (let i = 0; i < 512; i++) send('sealed', 0, 0)
  send('opened', 0, 4, 128)
  t.is(flow.peak.stream, 512)
  t.is(flow.counts.controlWhileSaturated, 1)
  t.alike(Array.from(flow.errors), [])
  send('sealed', 0, 0)
  t.ok(flow.errors.has('circuit grant overspent or oversized'))
})

test('withdrawal preserves earlier grants until its ordered zero acknowledgement', (t) => {
  const { flow, send } = fixture('source-endpoint')
  send('sealed', CIRCUIT_STREAM_ID, 5, 10)
  send('opened', CIRCUIT_STREAM_ID, 4, 4)
  send('sealed', CIRCUIT_STREAM_ID, 5, 0)
  send('opened', CIRCUIT_STREAM_ID, 4, 3)
  send('opened', CIRCUIT_STREAM_ID, 5, 0)
  send('sealed', CIRCUIT_STREAM_ID, 6, 7)
  t.alike(Array.from(flow.errors), [])
  t.is(flow.counts.withdrawals, 1)
  t.is(flow.counts.acknowledgements, 1)
  send('opened', CIRCUIT_STREAM_ID, 4, 1)
  t.ok(flow.errors.has('circuit grant exceeds demand'))
})

test('an unsolicited withdrawal acknowledgement is not accepted as a grant', (t) => {
  const { flow, send } = fixture('source-endpoint')
  send('opened', CIRCUIT_STREAM_ID, 5, 0)
  t.ok(flow.errors.has('unexpected demand acknowledgement'))
})

test('inner source controls retain their namespace and malformed logical frames retain errors', (t) => {
  const decoder = frameObserver()
  const bytes = b4a.alloc(41, 255)
  bytes[0] = 1
  decoder.observe({ type: 'control-write', label: 'source-resolve', bytes })
  const decoded = decoder.observe({
    type: 'route-cell-opened',
    label: 'source-safety-1-in',
    plaintext: bytes
  })
  t.is(decoded.type, 'source-control')
  t.alike(Array.from(decoder.errors), [])
  decoder.observe({ type: 'control-read', label: 'header', bytes: b4a.from([6, 3]) })
  t.ok(decoder.errors.has('Unsupported control version: 6'))
  const invalid = decoder.observe({
    type: 'route-cell-opened',
    label: 'destination-endpoint',
    plaintext: b4a.from('00000002040000', 'hex')
  })
  t.is(invalid.type, 'invalid')
  t.ok(
    Array.from(decoder.errors).some((message) => message.includes('credit count must be nonzero'))
  )
})
