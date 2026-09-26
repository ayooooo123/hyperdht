'use strict'

const test = require('brittle')
const b4a = require('b4a')
const c = require('compact-encoding')
const m = require('../../lib/messages')
const sodium = require('sodium-universal')

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

function responseFor(packet, flags, suffix = b4a.alloc(0), error = 0) {
  const errorBytes = error ? c.encode(c.uint, error) : b4a.alloc(0)
  const response = b4a.alloc(10 + errorBytes.byteLength + suffix.byteLength)
  response[0] = 0x13
  response[1] = flags | (error ? 0x08 : 0)
  response[2] = packet[2]
  response[3] = packet[3]
  response.set([10, 1, 2, 3, 0x12, 0xa1], 4)
  let offset = 10
  if (error) {
    response.set(errorBytes, offset)
    offset += errorBytes.byteLength
  }
  response.set(suffix, offset)
  return response
}

function writeU16(target, value, offset) {
  target[offset] = value >>> 8
  target[offset + 1] = value
}

function writeU64(target, value, offset) {
  let remaining = BigInt(value)
  for (let index = offset + 7; index >= offset; index--) {
    target[index] = Number(remaining & 0xffn)
    remaining >>= 8n
  }
}

function fixture(options = {}) {
  const fake = new FakeSocket()
  const replies = []
  const routed = []
  const monotonicNow = options.monotonicNow || (() => 1_000n)
  const channel = createDhtExitReservationChannel(
    TEST_ONLY_DHT_EXIT_OPEN_ISSUER.create({
      branchClass: BRANCH_CLASS.ANNOUNCE,
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
    monotonicNow,
    randomBytes: seed
  })
  const io = createDhtExitIOForTest(
    {
      host: '10.1.2.3',
      port: 41234,
      monotonicNow,
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
  return { fake, io, table, routed, destination }
}

function immutablePutBody(value) {
  const token = seed(0x41)
  const target = seed(0x42)
  const body = b4a.alloc(67 + value.byteLength)
  body.set(token, 0)
  body.set(target, 32)
  body[64] = 1
  writeU16(body, value.byteLength, 65)
  body.set(value, 67)
  return body
}

function mutablePutBody(value, seq = 1) {
  const token = seed(0x41)
  const publicKey = seed(0x51)
  const target = b4a.alloc(32)
  sodium.crypto_generichash(target, publicKey)
  const signature = seed(0x61, 64)
  const body = b4a.alloc(171 + value.byteLength)
  body.set(token, 0)
  body.set(target, 32)
  body.set(publicKey, 64)
  writeU64(body, seq, 96)
  body[104] = 1
  writeU16(body, value.byteLength, 105)
  body.set(value, 107)
  body.set(signature, 107 + value.byteLength)
  return body
}

test('DHT exit immutable put acks with one zero byte and no closers', (t) => {
  const { fake, io, table, routed, destination } = fixture()
  const value = b4a.alloc(8, 0xcd)
  const encodedRequest = encodeRoutedRequest({
    requestId: seed(0x21, 16),
    operationClass: BRANCH_CLASS.ANNOUNCE,
    commandId: M3_MESSAGE_ID.IMMUTABLE_PUT_V1,
    operationBudgetMs: 2_000n,
    destination: { id: destination.id, handle: destination.handle },
    encodedBody: immutablePutBody(value)
  })
  requestDhtExitCommand(io, table, encodedRequest, {
    onRoutedReply: (encoded) => routed.push(encoded)
  })
  t.is(fake.sends.length, 2)
  t.is(fake.sends[1].packet[1] & 0x10, 0x10)
  fake.message(responseFor(fake.sends[1].packet, 0), { host: '8.8.8.8', port: 49737 })
  t.is(routed.length, 1)
  const reply = decodeRoutedReply(routed[0])
  t.is(reply.commandId, M3_MESSAGE_ID.IMMUTABLE_PUT_V1)
  t.is(reply.operationClass, BRANCH_CLASS.ANNOUNCE)
  t.is(reply.errorCode, 0)
  t.is(reply.token.byteLength, 0)
  t.is(reply.closerNodes.length, 0)
  t.alike(reply.encodedResponse, b4a.from([0x00]))
  t.is(destroyDhtExitDestinationTable(table), true)
  t.is(closeDhtExitIO(io), true)
})

test('DHT exit mutable put maps seq conflict to RECORD_CONFLICT', (t) => {
  const { fake, io, table, routed, destination } = fixture()
  const encodedRequest = encodeRoutedRequest({
    requestId: seed(0x22, 16),
    operationClass: BRANCH_CLASS.ANNOUNCE,
    commandId: M3_MESSAGE_ID.MUTABLE_PUT_V1,
    operationBudgetMs: 2_000n,
    destination: { id: destination.id, handle: destination.handle },
    encodedBody: mutablePutBody(b4a.from('v'))
  })
  requestDhtExitCommand(io, table, encodedRequest, {
    onRoutedReply: (encoded) => routed.push(encoded)
  })
  fake.message(responseFor(fake.sends[1].packet, 0, b4a.alloc(0), 16), {
    host: '8.8.8.8',
    port: 49737
  })
  t.is(routed.length, 1)
  const reply = decodeRoutedReply(routed[0])
  t.is(reply.errorCode, ROUTED_ERROR.RECORD_CONFLICT)
  t.is(reply.encodedResponse.byteLength, 0)
  t.is(destroyDhtExitDestinationTable(table), true)
  t.is(closeDhtExitIO(io), true)
})

test('DHT exit put rejects lookup operation class and trailing body bytes', (t) => {
  const current = fixture()
  const value = b4a.alloc(1, 1)
  const body = immutablePutBody(value)
  expectCode(
    t,
    () =>
      encodeRoutedRequest({
        requestId: seed(0x23, 16),
        operationClass: BRANCH_CLASS.LOOKUP,
        commandId: M3_MESSAGE_ID.IMMUTABLE_PUT_V1,
        operationBudgetMs: 2_000n,
        destination: { id: current.destination.id, handle: current.destination.handle },
        encodedBody: body
      }),
    'ERR_AUTHENTICATION'
  )

  const badLen = b4a.alloc(66, 1)
  expectCode(
    t,
    () =>
      encodeRoutedRequest({
        requestId: seed(0x24, 16),
        operationClass: BRANCH_CLASS.ANNOUNCE,
        commandId: M3_MESSAGE_ID.IMMUTABLE_PUT_V1,
        operationBudgetMs: 2_000n,
        destination: {
          id: current.destination.id,
          handle: current.destination.handle
        },
        encodedBody: badLen
      }),
    'INVALID_ROUTE'
  )

  // Length field must consume the body exactly at the exit.
  const trailing = immutablePutBody(value)
  trailing[65] = 0
  trailing[66] = 0 // claims valueLen 0 but body still has trailing value bytes
  const encoded = encodeRoutedRequest({
    requestId: seed(0x25, 16),
    operationClass: BRANCH_CLASS.ANNOUNCE,
    commandId: M3_MESSAGE_ID.IMMUTABLE_PUT_V1,
    operationBudgetMs: 2_000n,
    destination: { id: current.destination.id, handle: current.destination.handle },
    encodedBody: trailing
  })
  expectCode(
    t,
    () => requestDhtExitCommand(current.io, current.table, encoded, { onRoutedReply() {} }),
    'ERR_AUTHENTICATION'
  )
  t.is(destroyDhtExitDestinationTable(current.table), true)
  t.is(closeDhtExitIO(current.io), true)
})
