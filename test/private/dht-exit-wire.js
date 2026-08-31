'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { PrivateRouteError } = require('../../lib/private/errors')
const {
  TEST_ONLY_DHT_EXIT_WIRE_RESERVATION,
  decodeDhtExitReply,
  decodeImmutableGetResponse,
  encodeDhtExitRequest,
  encodeImmutableGetResponse
} = require('../../lib/private/dht-exit-wire')

const REMOTE = Object.freeze({ host: '203.0.113.9', port: 49737 })
const LOCAL = Object.freeze({ host: '10.1.2.3', port: 41234 })
const PING = '03043412cb00710949c200'
const IMMUTABLE_GET =
  '03083412cb00710949c209aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
const IMMUTABLE_GET_WITH_TOKEN =
  '030a3412cb00710949c2bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb09aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
const REPLY =
  '131734120a01020312a1ebbd82e1821bd6b655180ad77d6770c263d7a70abaab1ff867c06203335b6ac2cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01c6336407419c0568656c6c6f'
const EMPTY_REPLY = '130034120a01020312a1'
const ERROR_REPLY = '130834120a01020312a105'

function expectCode(t, fn, code) {
  let error = null
  try {
    fn()
  } catch (err) {
    error = err
  }
  t.ok(error instanceof PrivateRouteError)
  t.is(error && error.code, code)
}

function reservation(overrides = {}) {
  return TEST_ONLY_DHT_EXIT_WIRE_RESERVATION.create({
    remote: REMOTE,
    local: LOCAL,
    tid: 0x1234,
    ...overrides
  })
}

test('DHT exit wire encodes exact client PING and immutable get packets', (t) => {
  const channel = reservation()
  const target = b4a.alloc(32, 0xaa)
  const token = b4a.alloc(32, 0xbb)

  t.alike(
    encodeDhtExitRequest(channel, {
      tid: 0x1234,
      token: null,
      internal: true,
      command: 0,
      target: null,
      value: null
    }),
    b4a.from(PING, 'hex')
  )
  t.alike(
    encodeDhtExitRequest(channel, {
      tid: 0x1234,
      token: null,
      internal: false,
      command: 9,
      target,
      value: null
    }),
    b4a.from(IMMUTABLE_GET, 'hex')
  )
  t.alike(
    encodeDhtExitRequest(channel, {
      tid: 0x1234,
      token,
      internal: false,
      command: 9,
      target,
      value: null
    }),
    b4a.from(IMMUTABLE_GET_WITH_TOKEN, 'hex')
  )
})

test('DHT exit wire rejects malformed outbound commands before allocation', (t) => {
  const channel = reservation()
  const target = b4a.alloc(32)

  for (const message of [
    {},
    { tid: 0x1234, token: null, internal: true, command: 0, target, value: null },
    { tid: 0x1234, token: b4a.alloc(32), internal: true, command: 0, target: null, value: null },
    { tid: 0x1234, token: null, internal: false, command: 9, target: b4a.alloc(31), value: null },
    { tid: 0x1234, token: b4a.alloc(31), internal: false, command: 9, target, value: null },
    { tid: 0x1234, token: null, internal: false, command: 8, target, value: null },
    { tid: 0x1234, token: null, internal: false, command: 9, target, value: b4a.alloc(1) },
    { tid: 0x1235, token: null, internal: false, command: 9, target, value: null }
  ]) {
    expectCode(t, () => encodeDhtExitRequest(channel, message), 'INVALID_ROUTE')
  }
})

test('DHT exit wire decodes exact replies and owns returned buffers', (t) => {
  const channel = reservation()
  const packet = b4a.from(REPLY, 'hex')
  const decoded = decodeDhtExitReply(channel, REMOTE, packet)

  t.is(decoded.tid, 0x1234)
  t.alike(decoded.from, REMOTE)
  t.alike(decoded.to, LOCAL)
  t.alike(decoded.token, b4a.alloc(32, 0xcc))
  t.alike(decoded.value, b4a.from('hello'))
  t.is(decoded.valuePresent, true)
  t.is(decoded.error, 0)
  t.is(decoded.closerNodes.length, 1)
  t.alike(decoded.closerNodes[0], { id: null, host: '198.51.100.7', port: 40001 })

  packet.fill(0)
  t.alike(decoded.value, b4a.from('hello'))
})

test('DHT exit wire accepts empty and error-only replies', (t) => {
  const channel = reservation()
  const empty = decodeDhtExitReply(channel, REMOTE, b4a.from(EMPTY_REPLY, 'hex'))
  const error = decodeDhtExitReply(channel, REMOTE, b4a.from(ERROR_REPLY, 'hex'))

  t.is(empty.tid, 0x1234)
  t.alike(empty.from, REMOTE)
  t.alike(empty.to, LOCAL)
  t.is(empty.token, null)
  t.alike(empty.closerNodes, [])
  t.is(empty.error, 0)
  t.is(empty.valuePresent, false)
  t.is(empty.value, null)

  t.is(error.tid, 0x1234)
  t.is(error.token, null)
  t.alike(error.closerNodes, [])
  t.is(error.error, 5)
  t.is(error.valuePresent, false)
  t.is(error.value, null)
})

test('DHT exit wire rejects oversized values before referral admission', (t) => {
  const packet = b4a.concat([b4a.from('131034120a01020312a1fd0004', 'hex'), b4a.alloc(1024)])
  expectCode(t, () => decodeDhtExitReply(reservation(), REMOTE, packet), 'INVALID_ROUTE')
})

test('immutable get response codec distinguishes absent empty and bounded values', (t) => {
  t.is(typeof encodeImmutableGetResponse, 'function')
  t.is(typeof decodeImmutableGetResponse, 'function')
  const vectors = [
    [{ valuePresent: false, value: null }, b4a.alloc(0)],
    [{ valuePresent: true, value: b4a.alloc(0) }, b4a.from([0])],
    [{ valuePresent: true, value: b4a.from([0xaa]) }, b4a.from([1, 0xaa])],
    [
      { valuePresent: true, value: b4a.alloc(1023, 0xbb) },
      b4a.concat([b4a.from('fdff03', 'hex'), b4a.alloc(1023, 0xbb)])
    ]
  ]
  for (const [logical, encoded] of vectors) {
    t.alike(encodeImmutableGetResponse(logical), encoded)
    const decoded = decodeImmutableGetResponse(encoded)
    t.is(decoded.valuePresent, logical.valuePresent)
    t.alike(decoded.value, logical.value)
  }
  expectCode(
    t,
    () => encodeImmutableGetResponse({ valuePresent: true, value: b4a.alloc(1024) }),
    'INVALID_ROUTE'
  )
  expectCode(
    t,
    () => encodeImmutableGetResponse({ valuePresent: false, value: b4a.alloc(0) }),
    'INVALID_ROUTE'
  )
  expectCode(
    t,
    () => encodeImmutableGetResponse({ valuePresent: true, value: null }),
    'INVALID_ROUTE'
  )
  expectCode(t, () => decodeImmutableGetResponse(b4a.from([0, 0])), 'INVALID_ROUTE')
  expectCode(
    t,
    () => decodeImmutableGetResponse(b4a.concat([b4a.from('fd0004', 'hex'), b4a.alloc(1024)])),
    'INVALID_ROUTE'
  )
})

test('DHT exit wire drops wrong source, framing, IDs, tuple, and tails', (t) => {
  const channel = reservation()
  const packet = b4a.from(REPLY, 'hex')

  expectCode(
    t,
    () => decodeDhtExitReply(channel, { host: '203.0.113.10', port: 49737 }, packet),
    'INVALID_ROUTE'
  )
  expectCode(t, () => decodeDhtExitReply(channel, REMOTE, b4a.from(PING, 'hex')), 'INVALID_ROUTE')

  const wrongTid = b4a.from(packet)
  wrongTid[2] ^= 1
  expectCode(t, () => decodeDhtExitReply(channel, REMOTE, wrongTid), 'INVALID_ROUTE')

  const wrongTo = b4a.from(packet)
  wrongTo[4] ^= 1
  expectCode(t, () => decodeDhtExitReply(channel, REMOTE, wrongTo), 'INVALID_ROUTE')

  const wrongId = b4a.from(packet)
  wrongId[10] ^= 1
  expectCode(t, () => decodeDhtExitReply(channel, REMOTE, wrongId), 'INVALID_ROUTE')

  const trailing = b4a.alloc(packet.byteLength + 1)
  trailing.set(packet)
  expectCode(t, () => decodeDhtExitReply(channel, REMOTE, trailing), 'INVALID_ROUTE')

  const unknownFlag = b4a.from(packet)
  unknownFlag[1] |= 0x20
  expectCode(t, () => decodeDhtExitReply(channel, REMOTE, unknownFlag), 'INVALID_ROUTE')
})
