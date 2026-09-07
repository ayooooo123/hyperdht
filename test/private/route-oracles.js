'use strict'

// Adversarial tests for the capture oracles themselves.
//
// The namespace gate asserts strong properties from `assertRouteCaptures`, so
// those assertions are only worth their wording if they actually fail when the
// property is violated. Every case here builds a synthetic capture that breaks
// exactly one property and proves the oracle rejects it, plus a clean capture
// that proves it accepts a well-formed run.
//
// Synthetic pcaps are used deliberately: a real run cannot be made to leak on
// demand, and an oracle that has only ever seen passing input is untested.

const test = require('brittle')
const b4a = require('b4a')
const fs = require('fs')
const os = require('os')
const path = require('path')

const { assertRouteCaptures, summarizeRouteCaptures } = require('./process/route-oracles')
const { ROLES } = require('./process/topology-fixture')

const CELL_SIZE = 1200
const ENDPOINT = 1
const GUARD = 2
const LOOKUP_MIDDLE_A = 3
const LOOKUP_EXIT_A = 4
const DHT_VALUE = 11

function tupleFor(roleIndex) {
  return { host: `10.203.${roleIndex}.2`, port: 42_000 + roleIndex }
}

// A stand-in for the topology oracle, carrying only what the capture oracles read.
function fakeOracle(overrides = {}) {
  return {
    eventForbiddenBytes: [b4a.alloc(32, 0xc1), b4a.alloc(32, 0xc2)],
    immutableValue: b4a.alloc(48, 0xa7),
    leakSentinel: b4a.alloc(32, 0x5e),
    targetHash: b4a.alloc(32, 0x7a),
    tuples: ROLES.map((role, index) => tupleFor(index + 1)),
    ...overrides
  }
}

function writeUdp(source, destination, payload) {
  const frame = b4a.alloc(14 + 20 + 8 + payload.byteLength)
  frame.writeUInt16BE(0x0800, 12)
  frame[14] = 0x45
  frame.writeUInt16BE(20 + 8 + payload.byteLength, 16)
  frame[14 + 9] = 17
  source.host.split('.').forEach((part, index) => {
    frame[14 + 12 + index] = Number(part)
  })
  destination.host.split('.').forEach((part, index) => {
    frame[14 + 16 + index] = Number(part)
  })
  frame.writeUInt16BE(source.port, 34)
  frame.writeUInt16BE(destination.port, 36)
  frame.writeUInt16BE(8 + payload.byteLength, 38)
  payload.copy(frame, 42)
  return frame
}

let captureSeq = 0

/** Write one synthetic savefile from `[source, destination, payload]` triples. */
function writeCapture(datagrams) {
  const header = b4a.alloc(24)
  header.writeUInt32BE(0xa1b2c3d4, 0)
  header.writeUInt16BE(2, 4)
  header.writeUInt16BE(4, 6)
  header.writeUInt32BE(65_535, 16)
  header.writeUInt32BE(1, 20)
  const parts = [header]
  let micros = 0
  for (const [source, destination, payload] of datagrams) {
    const frame = writeUdp(source, destination, payload)
    const record = b4a.alloc(16)
    record.writeUInt32BE(1, 0)
    record.writeUInt32BE(++micros, 4)
    record.writeUInt32BE(frame.byteLength, 8)
    record.writeUInt32BE(frame.byteLength, 12)
    parts.push(record, frame)
  }
  const file = path.join(os.tmpdir(), `pr-oracle-${process.pid}-${++captureSeq}.pcap`)
  fs.writeFileSync(file, b4a.concat(parts))
  return [{ file, key: 'synthetic' }]
}

function cell(fill) {
  return b4a.alloc(CELL_SIZE, fill)
}

/** A capture that satisfies every property the oracles check. */
function cleanRun(oracle) {
  return [
    [tupleFor(ENDPOINT), tupleFor(GUARD), cell(0x11)],
    [tupleFor(GUARD), tupleFor(ENDPOINT), cell(0x12)],
    [tupleFor(GUARD), tupleFor(LOOKUP_MIDDLE_A), cell(0x13)],
    [tupleFor(LOOKUP_MIDDLE_A), tupleFor(GUARD), cell(0x14)],
    [tupleFor(LOOKUP_MIDDLE_A), tupleFor(LOOKUP_EXIT_A), cell(0x15)],
    [tupleFor(LOOKUP_EXIT_A), tupleFor(LOOKUP_MIDDLE_A), cell(0x16)],
    // The exit performs the DHT operation in the clear, which is a stated
    // visible property and the positive control for the value search.
    [tupleFor(LOOKUP_EXIT_A), tupleFor(DHT_VALUE), b4a.alloc(64, 0x21)],
    [
      tupleFor(DHT_VALUE),
      tupleFor(LOOKUP_EXIT_A),
      b4a.concat([b4a.alloc(8, 0x22), oracle.immutableValue])
    ]
  ]
}

/** Records assertion outcomes so a test can require that an oracle failed. */
function recorder() {
  const failures = []
  const equal = (actual, expected) => JSON.stringify(actual) === JSON.stringify(expected)
  return {
    failures,
    t: {
      alike(actual, expected, message) {
        if (!equal(actual, expected)) failures.push(message || 'alike')
      },
      is(actual, expected, message) {
        if (actual !== expected) failures.push(message || 'is')
      },
      ok(value, message) {
        if (!value) failures.push(message || 'ok')
      },
      absent(value, message) {
        if (value) failures.push(message || 'absent')
      },
      comment() {}
    }
  }
}

/** Remove synthetic savefiles; a test that litters tmp is a test that misbehaves. */
function discard(captures) {
  for (const capture of captures) {
    try {
      fs.unlinkSync(capture.file)
    } catch {}
  }
}

function runOracles(datagrams, oracle = fakeOracle()) {
  const { failures, t } = recorder()
  const captures = writeCapture(datagrams)
  try {
    assertRouteCaptures(t, captures, oracle)
  } finally {
    discard(captures)
  }
  return failures
}

test('capture oracles accept a well-formed run', (t) => {
  const oracle = fakeOracle()
  t.alike(runOracles(cleanRun(oracle), oracle), [], 'a clean capture raises nothing')
})

test('capture oracles reject a datagram on a forbidden pair', (t) => {
  const oracle = fakeOracle()
  const failures = runOracles(
    [...cleanRun(oracle), [tupleFor(ENDPOINT), tupleFor(LOOKUP_EXIT_A), cell(0x31)]],
    oracle
  )
  t.ok(
    failures.some((message) => message.includes('forbids')),
    'endpoint talking straight to an exit is caught'
  )
})

test('capture oracles reject the endpoint sending anywhere but its guard', (t) => {
  const oracle = fakeOracle()
  // A pair that is allowed for other roles, so only the endpoint rule can catch it.
  const failures = runOracles(
    [...cleanRun(oracle), [tupleFor(ENDPOINT), tupleFor(GUARD), cell(0x32)]],
    oracle
  )
  t.alike(failures, [], 'endpoint to guard stays clean')

  const captures = writeCapture([
    [tupleFor(GUARD), tupleFor(LOOKUP_MIDDLE_A), cell(0x33)],
    [tupleFor(ENDPOINT), tupleFor(GUARD), cell(0x34)]
  ])
  try {
    const summary = summarizeRouteCaptures(captures, oracle)
    t.alike(Array.from(summary.endpointDestinations), [GUARD], 'only the guard is recorded')
  } finally {
    discard(captures)
  }
})

test('capture oracles reject a secret inside a route cell', (t) => {
  const oracle = fakeOracle()
  const leaked = cell(0x41)
  oracle.leakSentinel.copy(leaked, 100)
  const failures = runOracles(
    [
      ...cleanRun(oracle).slice(0, 6),
      ...cleanRun(oracle).slice(6),
      [tupleFor(GUARD), tupleFor(LOOKUP_MIDDLE_A), leaked]
    ],
    oracle
  )
  t.ok(
    failures.some((message) => message.includes('leak marker')),
    'a sentinel carried in a cell is caught'
  )
})

test('capture oracles reject plaintext SURB tags on route edges', (t) => {
  for (const tag of ['SURB-HOP-V1', 'SURB-TERM-V1']) {
    const oracle = fakeOracle()
    const leaked = cell(0x41)
    b4a.from(tag).copy(leaked, 100)
    const failures = runOracles(
      [...cleanRun(oracle), [tupleFor(LOOKUP_EXIT_A), tupleFor(LOOKUP_MIDDLE_A), leaked]],
      oracle
    )
    t.ok(
      failures.includes('no leak marker appears on any edge that carries route cells'),
      `${tag} in a 1200-byte physical-link cell is detected`
    )
  }
})

test('capture oracles reject the retrieved value inside a route cell', (t) => {
  const oracle = fakeOracle()
  const leaked = cell(0x42)
  oracle.immutableValue.copy(leaked, 300)
  const failures = runOracles(
    [...cleanRun(oracle), [tupleFor(ENDPOINT), tupleFor(GUARD), leaked]],
    oracle
  )
  t.ok(
    failures.some((message) => message.includes('leak marker')),
    'the value in plaintext on a cell edge is caught'
  )
})

test('capture oracles reject a cell payload relayed unchanged across two hops', (t) => {
  const oracle = fakeOracle()
  const relayed = cell(0x51)
  const failures = runOracles(
    [
      ...cleanRun(oracle),
      [tupleFor(ENDPOINT), tupleFor(GUARD), relayed],
      [tupleFor(GUARD), tupleFor(LOOKUP_MIDDLE_A), relayed]
    ],
    oracle
  )
  t.ok(
    failures.some((message) => message.includes('relayed unchanged')),
    'a hop forwarding the same bytes is caught'
  )
})

test('capture oracles reject a route cell of the wrong size', (t) => {
  const oracle = fakeOracle()
  const failures = runOracles(
    [...cleanRun(oracle), [tupleFor(GUARD), tupleFor(LOOKUP_MIDDLE_A), b4a.alloc(800, 0x61)]],
    oracle
  )
  t.ok(
    failures.some((message) => message.includes('same size')),
    'a short cell breaks length uniformity and is caught'
  )
})

test('capture oracles reject a run where the value search finds nothing', (t) => {
  const oracle = fakeOracle()
  // Every cell edge present, but the exit never shows the value to the DHT, so
  // the search that guards the leak check has nothing to confirm it works.
  const failures = runOracles(cleanRun(oracle).slice(0, 7), oracle)
  t.ok(
    failures.some((message) => message.includes('not vacuous')),
    'a leak check that cannot find a known plaintext is reported'
  )
})

test('capture oracles reject a run with no cell traffic at all', (t) => {
  const oracle = fakeOracle()
  const failures = runOracles(
    [[tupleFor(LOOKUP_EXIT_A), tupleFor(DHT_VALUE), b4a.alloc(64, 0x71)]],
    oracle
  )
  t.ok(
    failures.some((message) => message.includes('observed route cell traffic')),
    'an empty or non-route capture is not silently green'
  )
})
