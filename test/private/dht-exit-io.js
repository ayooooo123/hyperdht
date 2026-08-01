'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { PrivateRouteError } = require('../../lib/private/errors')
const {
  TEST_ONLY_DHT_EXIT_OPEN_ISSUER,
  consumeDhtExitCorrelatedReplyAuthority,
  consumeDhtExitReservationIOConsumer,
  consumeDhtExitReservationTableIssuer,
  createDhtExitPacketReservation,
  createDhtExitReservationChannel
} = require('../../lib/private/dht-exit-reservation')
const {
  TEST_ONLY_DHT_EXIT_SOCKET_ISSUER,
  TEST_ONLY_DHT_EXIT_IO_STATE,
  closeDhtExitIO,
  createDhtExitIO,
  createDhtExitIOForTest,
  sendReservedExitDhtPacket
} = require('../../lib/private/dht-exit-io')
const { BRANCH_CLASS } = require('../../lib/private/protocol')

function seed(byte, size = 32) {
  return b4a.alloc(size, byte)
}

function expectCode(t, operation, code, message) {
  let error = null
  try {
    operation()
  } catch (err) {
    error = err
  }
  t.ok(error instanceof PrivateRouteError, message)
  t.is(error && error.code, code, message)
}

class FakeSocket {
  constructor() {
    this.binds = []
    this.closed = false
    this.handlers = new Map()
    this.sends = []
  }

  bind(port, host) {
    this.binds.push({ host, port })
  }

  on(name, handler) {
    this.handlers.set(name, handler)
  }

  send(packet, port, host) {
    this.sends.push({ packet: b4a.from(packet), host, port })
    return true
  }

  close() {
    this.closed = true
  }

  message(packet, from) {
    this.handlers.get('message')(packet, from)
  }
}

function channel() {
  const authority = TEST_ONLY_DHT_EXIT_OPEN_ISSUER.create({
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: seed(0x11, 16),
    circuitId: seed(0x12, 16),
    generation: 7n,
    exitIdentity: seed(0x13),
    finalTranscriptDigest: seed(0x14),
    expiresAt: 20_000n,
    absoluteDeadline: 19_000n,
    controlKey: seed(0x15),
    controlNoncePrefix: seed(0x16, 16)
  })
  const pair = createDhtExitReservationChannel(authority)
  return {
    table: consumeDhtExitReservationTableIssuer(pair.tableIssuer),
    io: consumeDhtExitReservationIOConsumer(pair.ioConsumer)
  }
}

function packet(table, overrides = {}) {
  return createDhtExitPacketReservation(table, {
    remote: { host: '203.0.113.9', port: 49737 },
    local: { host: '10.1.2.3', port: 41234 },
    token: null,
    internal: false,
    command: 9,
    target: seed(0xaa),
    value: null,
    deadline: 18_000n,
    auditClass: 'immutable-get',
    ...overrides
  })
}

test('DHTExitIO binds one owned socket and allocates the request TID before send', (t) => {
  const fake = new FakeSocket()
  const replies = []
  const socketAuthority = TEST_ONLY_DHT_EXIT_SOCKET_ISSUER.create(() => fake)
  const installed = channel()
  const io = createDhtExitIOForTest(
    {
      host: '10.1.2.3',
      port: 41234,
      monotonicNow: () => 1_000n,
      schedule() {},
      cancelScheduled() {},
      onReply: (reply) => replies.push(reply)
    },
    socketAuthority,
    installed.io
  )

  t.alike(fake.binds, [{ host: '10.1.2.3', port: 41234 }])
  t.is(fake.handlers.has('message'), true)
  t.is(sendReservedExitDhtPacket(io, packet(installed.table)), true)
  t.is(fake.sends.length, 1)
  t.is(fake.sends[0].host, '203.0.113.9')
  t.is(fake.sends[0].port, 49737)
  t.alike(fake.sends[0].packet.subarray(0, 4), b4a.from('03080000', 'hex'))

  fake.message(b4a.from('130000000a01020312a1', 'hex'), {
    host: '203.0.113.9',
    port: 49737
  })
  t.is(replies.length, 1)
  t.is(consumeDhtExitCorrelatedReplyAuthority(replies[0]).reply.tid, 0)
  t.is(closeDhtExitIO(io), true)
  t.is(fake.closed, true)
})

test('DHTExitIO drops wrong source, duplicate, malformed, and unsolicited replies', (t) => {
  const fake = new FakeSocket()
  const scheduled = []
  const canceled = []
  let now = 1_000n
  const replies = []
  const socketAuthority = TEST_ONLY_DHT_EXIT_SOCKET_ISSUER.create(() => fake)
  const installed = channel()
  const io = createDhtExitIOForTest(
    {
      host: '10.1.2.3',
      port: 41234,
      monotonicNow: () => now,
      schedule(callback, delay) {
        const handle = Object.freeze({ callback, delay })
        scheduled.push(handle)
        return handle
      },
      cancelScheduled(handle) {
        canceled.push(handle)
      },
      onReply: (reply) => replies.push(reply)
    },
    socketAuthority,
    installed.io
  )

  t.is(sendReservedExitDhtPacket(io, packet(installed.table)), true)
  t.is(scheduled.length, 1)
  t.is(scheduled[0].delay, 17_000)
  fake.message(b4a.from('130000000a01020312a1', 'hex'), { host: '203.0.113.10', port: 49737 })
  fake.message(
    b4a.from(
      '03080000cb00710949c209aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      'hex'
    ),
    { host: '203.0.113.9', port: 49737 }
  )
  fake.message(b4a.from('130001000a01020312a1', 'hex'), { host: '203.0.113.9', port: 49737 })
  t.is(replies.length, 0)
  fake.message(b4a.from('130000000a01020312a1', 'hex'), { host: '203.0.113.9', port: 49737 })
  fake.message(b4a.from('130000000a01020312a1', 'hex'), { host: '203.0.113.9', port: 49737 })
  t.is(replies.length, 1)
  const late = packet(installed.table, { deadline: 18_500n })
  t.is(sendReservedExitDhtPacket(io, late), true)
  now = 18_500n
  scheduled[1].callback()
  fake.message(b4a.from('130001000a01020312a1', 'hex'), { host: '203.0.113.9', port: 49737 })
  t.is(replies.length, 1)
  t.ok(canceled.length >= 1)
  t.is(closeDhtExitIO(io), true)
})

test('DHTExitIO does not send after synchronous deadline expiry', (t) => {
  const fake = new FakeSocket()
  const socketAuthority = TEST_ONLY_DHT_EXIT_SOCKET_ISSUER.create(() => fake)
  const installed = channel()
  const io = createDhtExitIOForTest(
    {
      host: '10.1.2.3',
      port: 41234,
      monotonicNow: () => 1_000n,
      schedule(callback) {
        callback()
        return Object.freeze({})
      },
      cancelScheduled() {},
      onReply() {}
    },
    socketAuthority,
    installed.io
  )

  expectCode(
    t,
    () => sendReservedExitDhtPacket(io, packet(installed.table)),
    'ERR_PRIVACY_UNAVAILABLE'
  )
  t.is(fake.sends.length, 0)
  t.is(closeDhtExitIO(io), true)
})

test('DHTExitIO production constructor reaches udx-native loopback', async (t) => {
  const UDX = require('udx-native')
  const udx = new UDX()
  const server = udx.createSocket()
  const received = new Promise((resolve) => {
    server.on('message', (message, from) => resolve({ message: b4a.from(message), from }))
  })
  await server.bind(0, '127.0.0.1')
  const serverAddress = server.address()
  const installed = channel()
  const io = createDhtExitIO(installed.io, {
    host: '127.0.0.1',
    port: 0,
    monotonicNow: () => 1_000n,
    schedule() {},
    cancelScheduled() {},
    onReply() {}
  })
  const clientAddress = TEST_ONLY_DHT_EXIT_IO_STATE.address(io)
  t.is(
    sendReservedExitDhtPacket(
      io,
      packet(installed.table, {
        remote: { host: '127.0.0.1', port: serverAddress.port },
        local: { host: '127.0.0.1', port: clientAddress.port }
      })
    ),
    true
  )
  let timeout = null
  const result = await Promise.race([
    received,
    new Promise((resolve) => {
      timeout = setTimeout(() => resolve(null), 1000)
      if (typeof timeout.unref === 'function') timeout.unref()
    })
  ])
  clearTimeout(timeout)
  t.ok(result)
  t.alike(result.message.subarray(0, 4), b4a.from('03080000', 'hex'))
  t.is(closeDhtExitIO(io), true)
  server.close()
})

test('DHTExitIO closes before send and rejects stale reservations', (t) => {
  const fake = new FakeSocket()
  const socketAuthority = TEST_ONLY_DHT_EXIT_SOCKET_ISSUER.create(() => fake)
  const installed = channel()
  const io = createDhtExitIOForTest(
    {
      host: '10.1.2.3',
      port: 41234,
      monotonicNow: () => 1_000n,
      schedule() {},
      cancelScheduled() {},
      onReply() {}
    },
    socketAuthority,
    installed.io
  )
  t.is(closeDhtExitIO(io), true)
  expectCode(t, () => sendReservedExitDhtPacket(io, packet(installed.table)), 'ERR_DESTROYED')
  t.is(fake.sends.length, 0)
  expectCode(t, () => createDhtExitIOForTest({}, socketAuthority, installed.io), 'ERR_REPLAY')
})
