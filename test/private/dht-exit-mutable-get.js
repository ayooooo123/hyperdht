'use strict'

const test = require('brittle')
const b4a = require('b4a')
const c = require('compact-encoding')
const m = require('../../lib/messages')

const { PrivateRouteError } = require('../../lib/private/errors')
const { BRANCH_CLASS, M3_MESSAGE_ID, ROUTED_ERROR } = require('../../lib/private/protocol')
const { decodeRoutedReply, encodeRoutedRequest } = require('../../lib/private/routed-dht')
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
  requestDhtExitCommand,
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

  close() {}
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

function writeU64(target, value, offset) {
  let remaining = BigInt(value)
  for (let index = offset + 7; index >= offset; index--) {
    target[index] = Number(remaining & 0xffn)
    remaining >>= 8n
  }
}

function fixture(branchClass = BRANCH_CLASS.LOOKUP) {
  const fake = new FakeSocket()
  const replies = []
  const routed = []
  const channel = createDhtExitReservationChannel(
    TEST_ONLY_DHT_EXIT_OPEN_ISSUER.create({
      branchClass,
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
    monotonicNow: () => 1_000n,
    randomBytes: seed
  })
  const io = createDhtExitIOForTest(
    {
      host: '10.1.2.3',
      port: 41234,
      monotonicNow: () => 1_000n,
      schedule: () => null,
      cancelScheduled: () => {},
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
  return { fake, io, table, routed, destination, branchClass }
}

function mutableGetBody(seq = 0) {
  const body = b4a.alloc(40)
  body.set(seed(0x31), 0)
  writeU64(body, seq, 32)
  return body
}

test('DHT exit mutable get forwards raw response bytes and referrals', (t) => {
  const { fake, io, table, routed, destination, branchClass } = fixture()
  const payload = c.encode(m.mutableGetResponse, {
    seq: 3,
    value: b4a.from('hello'),
    signature: seed(0x71, 64)
  })
  const encodedRequest = encodeRoutedRequest({
    requestId: seed(0x21, 16),
    operationClass: branchClass,
    commandId: M3_MESSAGE_ID.MUTABLE_GET_V1,
    operationBudgetMs: 2_000n,
    destination: { id: destination.id, handle: destination.handle },
    encodedBody: mutableGetBody(0)
  })
  requestDhtExitCommand(io, table, encodedRequest, {
    onRoutedReply: (encoded) => routed.push(encoded)
  })
  t.is(fake.sends.length, 2)
  const valueFlag = fake.sends[1].packet[1] & 0x10
  t.is(valueFlag, 0x10)
  const valueWire = c.encode(c.buffer, payload)
  fake.message(responseFor(fake.sends[1].packet, 0x10, valueWire), {
    host: '8.8.8.8',
    port: 49737
  })
  t.is(routed.length, 1)
  const reply = decodeRoutedReply(routed[0])
  t.is(reply.commandId, M3_MESSAGE_ID.MUTABLE_GET_V1)
  t.alike(reply.encodedResponse, payload)
  t.is(destroyDhtExitDestinationTable(table), true)
  t.is(closeDhtExitIO(io), true)
})

test('DHT exit mutable get rejects wrong body length and oversized upstream value', (t) => {
  const current = fixture()
  const shortBody = b4a.alloc(39, 1)
  expectCode(
    t,
    () =>
      encodeRoutedRequest({
        requestId: seed(0x22, 16),
        operationClass: BRANCH_CLASS.LOOKUP,
        commandId: M3_MESSAGE_ID.MUTABLE_GET_V1,
        operationBudgetMs: 2_000n,
        destination: { id: current.destination.id, handle: current.destination.handle },
        encodedBody: shortBody
      }),
    'INVALID_ROUTE'
  )

  const encodedRequest = encodeRoutedRequest({
    requestId: seed(0x23, 16),
    operationClass: BRANCH_CLASS.LOOKUP,
    commandId: M3_MESSAGE_ID.MUTABLE_GET_V1,
    operationBudgetMs: 2_000n,
    destination: { id: current.destination.id, handle: current.destination.handle },
    encodedBody: mutableGetBody(1)
  })
  const operation = requestDhtExitCommand(current.io, current.table, encodedRequest, {
    onRoutedReply: (encoded) => current.routed.push(encoded)
  })
  const oversized = b4a.concat([b4a.from('fd0004', 'hex'), b4a.alloc(1024)])
  current.fake.message(responseFor(current.fake.sends[1].packet, 0x10, oversized), {
    host: '8.8.8.8',
    port: 49737
  })
  t.is(current.routed.length, 0)
  t.is(operation.cancel(), true)
  t.is(destroyDhtExitDestinationTable(current.table), true)
  t.is(closeDhtExitIO(current.io), true)
})

test('DHT exit mutable get works on announce branch for put prepare', (t) => {
  const { fake, io, table, routed, destination, branchClass } = fixture(BRANCH_CLASS.ANNOUNCE)
  t.is(branchClass, BRANCH_CLASS.ANNOUNCE)
  const encodedRequest = encodeRoutedRequest({
    requestId: seed(0x24, 16),
    operationClass: BRANCH_CLASS.ANNOUNCE,
    commandId: M3_MESSAGE_ID.MUTABLE_GET_V1,
    operationBudgetMs: 2_000n,
    destination: { id: destination.id, handle: destination.handle },
    encodedBody: mutableGetBody(0)
  })
  requestDhtExitCommand(io, table, encodedRequest, {
    onRoutedReply: (encoded) => routed.push(encoded)
  })
  fake.message(responseFor(fake.sends[1].packet, 0), { host: '8.8.8.8', port: 49737 })
  t.is(routed.length, 1)
  t.is(decodeRoutedReply(routed[0]).operationClass, BRANCH_CLASS.ANNOUNCE)
  t.is(destroyDhtExitDestinationTable(table), true)
  t.is(closeDhtExitIO(io), true)
})
