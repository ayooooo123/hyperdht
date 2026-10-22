'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { PrivateRouteError } = require('../../lib/private/errors')
const { BRANCH_CLASS, M3_MESSAGE_ID, ROUTED_ERROR } = require('../../lib/private/protocol')
const { decodeRoutedReply, encodeRoutedRequest } = require('../../lib/private/routed-dht')
const { decodeImmutableGetResponse } = require('../../lib/private/dht-exit-wire')
const {
  TEST_ONLY_DHT_EXIT_OPEN_ISSUER,
  consumeDhtExitReservationIOConsumer,
  createDhtExitReservationChannel
} = require('../../lib/private/dht-exit-reservation')
const {
  createDhtExitDestinationTable,
  destroyDhtExitDestinationTable,
  readDhtExitDestinationRef,
  reserveConfiguredBootstrapProbe,
  settleExitDhtReservation
} = require('../../lib/private/dht-exit-destination-table')
const {
  TEST_ONLY_DHT_EXIT_SOCKET_ISSUER,
  closeDhtExitIO,
  createDhtExitIOForTest,
  requestDhtExitImmutableGet,
  sendReservedExitDhtPacket
} = require('../../lib/private/dht-exit-io')

function seed(value, size = 32) {
  return b4a.alloc(size, value)
}

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

class FakeSocket {
  constructor() {
    this.sends = []
    this.handler = null
    this.closed = false
  }

  bind() {}

  on(name, handler) {
    if (name === 'message') this.handler = handler
  }

  send(packet, port, host) {
    this.sends.push({ packet: b4a.from(packet), port, host })
  }

  message(packet, from) {
    this.handler(packet, from)
  }

  close() {
    this.closed = true
  }
}

function responseFor(packet, flags, suffix = b4a.alloc(0)) {
  const response = b4a.alloc(10 + suffix.byteLength)
  response[0] = 0x13
  response[1] = flags
  response[2] = packet[2]
  response[3] = packet[3]
  response.set([10, 1, 2, 3, 0x12, 0xa1], 4)
  response.set(suffix, 10)
  return response
}

function fixture(options = {}) {
  const fake = new FakeSocket()
  const replies = []
  const routed = []
  const monotonicNow = options.monotonicNow || (() => 1_000n)
  const tableMonotonicNow = options.tableMonotonicNow || monotonicNow
  const ioMonotonicNow = options.ioMonotonicNow || monotonicNow
  const channel = createDhtExitReservationChannel(
    TEST_ONLY_DHT_EXIT_OPEN_ISSUER.create({
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
  )
  const table = createDhtExitDestinationTable(channel.tableIssuer, {
    local: { host: '10.1.2.3', port: 41234 },
    configuredBootstrap: [{ host: '8.8.8.8', port: 49737 }],
    monotonicNow: tableMonotonicNow,
    randomBytes: seed
  })
  const io = createDhtExitIOForTest(
    {
      host: '10.1.2.3',
      port: 41234,
      monotonicNow: ioMonotonicNow,
      schedule: options.schedule || (() => null),
      cancelScheduled: options.cancelScheduled || (() => {}),
      onReply: (authority) => replies.push(authority)
    },
    TEST_ONLY_DHT_EXIT_SOCKET_ISSUER.create(() => fake),
    consumeDhtExitReservationIOConsumer(channel.ioConsumer)
  )
  const probe = reserveConfiguredBootstrapProbe(table, 0, 2_000n)
  sendReservedExitDhtPacket(io, probe.sendAuthority)
  fake.message(responseFor(fake.sends[0].packet, 0), { host: '8.8.8.8', port: 49737 })
  const destinationRef = settleExitDhtReservation(probe.settlementAuthority, replies[0])
  const destination = readDhtExitDestinationRef(table, destinationRef)
  const encodedRequest = encodeRoutedRequest({
    requestId: seed(0x21, 16),
    operationClass: BRANCH_CLASS.LOOKUP,
    commandId: M3_MESSAGE_ID.IMMUTABLE_GET_V1,
    operationBudgetMs: 2_000n,
    destination: { id: destination.id, handle: destination.handle },
    encodedBody: seed(0x31)
  })
  return { fake, io, table, routed, encodedRequest }
}

test('DHT exit immutable get reserves before send and normalizes response bytes', (t) => {
  t.is(typeof requestDhtExitImmutableGet, 'function')
  const { fake, io, table, routed, encodedRequest } = fixture()
  const operation = requestDhtExitImmutableGet(io, table, encodedRequest, {
    onRoutedReply: (encoded) => routed.push(encoded)
  })

  t.alike(Object.keys(operation), ['cancel'])
  t.is(fake.sends.length, 2)
  t.is(fake.sends[1].packet[1] & 0x08, 0x08)
  fake.message(responseFor(fake.sends[1].packet, 0x10, b4a.from([1, 0xaa])), {
    host: '8.8.8.8',
    port: 49737
  })

  t.is(routed.length, 1)
  const reply = decodeRoutedReply(routed[0])
  t.alike(reply.requestId, seed(0x21, 16))
  t.is(reply.commandId, M3_MESSAGE_ID.IMMUTABLE_GET_V1)
  t.alike(decodeImmutableGetResponse(reply.encodedResponse), {
    valuePresent: true,
    value: b4a.from([0xaa])
  })
  t.is(operation.cancel(), false)
  t.is(destroyDhtExitDestinationTable(table), true)
  t.is(closeDhtExitIO(io), true)
})

test('DHT exit immutable get returns only successfully probed referral references', (t) => {
  const { fake, io, table, routed, encodedRequest } = fixture()
  requestDhtExitImmutableGet(io, table, encodedRequest, {
    onRoutedReply: (encoded) => routed.push(encoded)
  })
  const closer = b4a.from([1, 1, 1, 1, 1, 0x49, 0xc2])
  fake.message(responseFor(fake.sends[1].packet, 0x04, closer), {
    host: '8.8.8.8',
    port: 49737
  })
  t.is(routed.length, 0)
  t.is(fake.sends.length, 3)
  t.is(fake.sends[2].packet[1], 0x04)
  fake.message(responseFor(fake.sends[2].packet, 0), {
    host: '1.1.1.1',
    port: 49737
  })
  t.is(routed.length, 1)
  const reply = decodeRoutedReply(routed[0])
  t.is(reply.closerNodes.length, 1)
  t.alike(
    reply.closerNodes[0].id,
    b4a.from('669f5bbaa7e063dbc2983191bbf0de6688c4ea2e68b7d653c4349276dde4a929', 'hex')
  )
  t.is(destroyDhtExitDestinationTable(table), true)
  t.is(closeDhtExitIO(io), true)
})

test('DHT exit immutable get rejects invalid destination and cancel suppresses reply', (t) => {
  const first = fixture()
  const invalid = b4a.from(first.encodedRequest)
  invalid[8 + 47 + 42] ^= 1
  expectCode(
    t,
    () => requestDhtExitImmutableGet(first.io, first.table, invalid, { onRoutedReply() {} }),
    'INVALID_ROUTE'
  )
  t.is(first.fake.sends.length, 1)

  const operation = requestDhtExitImmutableGet(first.io, first.table, first.encodedRequest, {
    onRoutedReply() {}
  })
  t.is(operation.cancel(), true)
  first.fake.message(responseFor(first.fake.sends[1].packet, 0), {
    host: '8.8.8.8',
    port: 49737
  })
  t.is(operation.cancel(), false)
  t.is(destroyDhtExitDestinationTable(first.table), true)
  t.is(closeDhtExitIO(first.io), true)
})

test('DHT exit immutable get settles late replies and aborts on close', (t) => {
  let current = 1_000n
  const late = fixture({ monotonicNow: () => current })
  const lateOperation = requestDhtExitImmutableGet(late.io, late.table, late.encodedRequest, {
    onRoutedReply: (encoded) => late.routed.push(encoded)
  })
  // The request's 2000ms budget is added to the exit's own clock, so the operation's deadline
  // here is 3000n; a reply that lands on it is late.
  current = 3_000n
  late.fake.message(responseFor(late.fake.sends[1].packet, 0), {
    host: '8.8.8.8',
    port: 49737
  })
  t.is(late.routed.length, 1)
  t.is(decodeRoutedReply(late.routed[0]).errorCode, ROUTED_ERROR.UPSTREAM_TIMEOUT)
  t.is(lateOperation.cancel(), false)
  t.is(closeDhtExitIO(late.io), true)
  t.is(destroyDhtExitDestinationTable(late.table), true)

  const closing = fixture()
  const closingOperation = requestDhtExitImmutableGet(
    closing.io,
    closing.table,
    closing.encodedRequest,
    { onRoutedReply: (encoded) => closing.routed.push(encoded) }
  )
  t.is(closeDhtExitIO(closing.io), true)
  t.is(closingOperation.cancel(), false)
  t.is(closing.routed.length, 0)
  t.is(destroyDhtExitDestinationTable(closing.table), true)
})

test('DHT exit immutable get completes synchronous timer expiry exactly once', (t) => {
  let expireSynchronously = false
  const current = fixture({
    schedule(callback) {
      if (expireSynchronously) callback()
      return Object.freeze({})
    }
  })
  expireSynchronously = true
  const operation = requestDhtExitImmutableGet(current.io, current.table, current.encodedRequest, {
    onRoutedReply: (encoded) => current.routed.push(encoded)
  })
  t.is(current.fake.sends.length, 1)
  t.is(current.routed.length, 1)
  t.is(decodeRoutedReply(current.routed[0]).errorCode, ROUTED_ERROR.UPSTREAM_TIMEOUT)
  t.is(operation.cancel(), false)
  t.is(closeDhtExitIO(current.io), true)
  t.is(destroyDhtExitDestinationTable(current.table), true)
})

test('DHT exit immutable get emits nothing after reentrant table rotation', (t) => {
  let table = null
  let rotate = false
  const current = fixture({
    tableMonotonicNow() {
      if (rotate) destroyDhtExitDestinationTable(table)
      return 1_000n
    },
    ioMonotonicNow: () => 1_000n
  })
  table = current.table
  const operation = requestDhtExitImmutableGet(current.io, table, current.encodedRequest, {
    onRoutedReply: (encoded) => current.routed.push(encoded)
  })
  const closer = b4a.from([1, 1, 1, 1, 1, 0x49, 0xc2])
  current.fake.message(responseFor(current.fake.sends[1].packet, 0x04, closer), {
    host: '8.8.8.8',
    port: 49737
  })
  t.is(current.fake.sends.length, 3)
  rotate = true
  current.fake.message(responseFor(current.fake.sends[2].packet, 0), {
    host: '1.1.1.1',
    port: 49737
  })
  t.is(current.routed.length, 0)
  t.is(operation.cancel(), false)
  t.is(closeDhtExitIO(current.io), true)
  t.is(destroyDhtExitDestinationTable(table), false)
})

test('DHT exit immutable get rejects oversized values before probing referrals', (t) => {
  const current = fixture()
  const operation = requestDhtExitImmutableGet(current.io, current.table, current.encodedRequest, {
    onRoutedReply: (encoded) => current.routed.push(encoded)
  })
  const closer = b4a.from([1, 1, 1, 1, 1, 0x49, 0xc2])
  const oversized = b4a.concat([closer, b4a.from('fd0004', 'hex'), b4a.alloc(1024)])
  current.fake.message(responseFor(current.fake.sends[1].packet, 0x14, oversized), {
    host: '8.8.8.8',
    port: 49737
  })
  t.is(current.fake.sends.length, 2)
  t.is(current.routed.length, 0)
  t.is(operation.cancel(), true)
  t.is(closeDhtExitIO(current.io), true)
  t.is(destroyDhtExitDestinationTable(current.table), true)
})
