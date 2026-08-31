'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { PrivateRouteError } = require('../../lib/private/errors')
const {
  TEST_ONLY_DHT_EXIT_OPEN_ISSUER,
  consumeDhtExitReservationIOConsumer,
  encodeDhtExitPacketReservationTransfer,
  consumeDhtExitReservationTableIssuer,
  createDhtExitPacketReservation,
  createDhtExitReservationChannel,
  revokeDhtExitReservationChannel
} = require('../../lib/private/dht-exit-reservation')
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

function openMaterial(overrides = {}) {
  return {
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: seed(0x11, 16),
    circuitId: seed(0x12, 16),
    generation: 7n,
    exitIdentity: seed(0x13),
    finalTranscriptDigest: seed(0x14),
    expiresAt: 20_000n,
    absoluteDeadline: 19_000n,
    controlKey: seed(0x15),
    controlNoncePrefix: seed(0x16, 16),
    ...overrides
  }
}

function openAuthority(overrides) {
  return TEST_ONLY_DHT_EXIT_OPEN_ISSUER.create(openMaterial(overrides))
}

test('DHT exit reservation channel consumes one open authority into empty one-shot halves', (t) => {
  const authority = openAuthority()
  const channel = createDhtExitReservationChannel(authority)
  t.alike(Reflect.ownKeys(channel.tableIssuer), [])
  t.alike(Reflect.ownKeys(channel.ioConsumer), [])
  t.ok(Object.isFrozen(channel.tableIssuer))
  t.ok(Object.isFrozen(channel.ioConsumer))

  const table = consumeDhtExitReservationTableIssuer(channel.tableIssuer)
  const io = consumeDhtExitReservationIOConsumer(channel.ioConsumer)
  t.is(table.generation, 7n)
  t.is(io.generation, 7n)
  t.alike(table.branchId, seed(0x11, 16))
  t.alike(io.circuitId, seed(0x12, 16))

  expectCode(t, () => consumeDhtExitReservationTableIssuer(channel.tableIssuer), 'ERR_REPLAY')
  expectCode(t, () => consumeDhtExitReservationIOConsumer(channel.ioConsumer), 'ERR_REPLAY')
  expectCode(t, () => createDhtExitReservationChannel(authority), 'ERR_REPLAY')
})

test('DHT exit reservation channel rejects cross-channel packet reservations', (t) => {
  const first = createDhtExitReservationChannel(openAuthority({ generation: 8n }))
  const second = createDhtExitReservationChannel(openAuthority({ generation: 9n }))
  const firstTable = consumeDhtExitReservationTableIssuer(first.tableIssuer)
  const firstIo = consumeDhtExitReservationIOConsumer(first.ioConsumer)
  const secondIo = consumeDhtExitReservationIOConsumer(second.ioConsumer)
  const target = seed(0xaa)
  const packet = createDhtExitPacketReservation(firstTable, {
    remote: { host: '203.0.113.9', port: 49737 },
    local: { host: '10.1.2.3', port: 41234 },
    token: null,
    internal: false,
    command: 9,
    target,
    value: null,
    deadline: 18_000n,
    auditClass: 'immutable-get'
  })

  expectCode(
    t,
    () => consumeDhtExitPacketReservationForIO(secondIo, packet, 0x1234),
    'ERR_AUTHENTICATION'
  )
  const transfer = consumeDhtExitPacketReservationForIO(firstIo, packet, 0x1234)
  t.alike(
    encodeDhtExitPacketReservationTransfer(transfer).subarray(0, 10),
    b4a.from('03083412cb00710949c2', 'hex')
  )
  expectCode(t, () => consumeDhtExitPacketReservationForIO(firstIo, packet, 0x1234), 'ERR_REPLAY')
})

test('DHT exit reservation channel revokes unconsumed halves and open authority', (t) => {
  const authority = openAuthority()
  const channel = createDhtExitReservationChannel(authority)
  t.is(revokeDhtExitReservationChannel(channel.tableIssuer), true)
  expectCode(t, () => consumeDhtExitReservationTableIssuer(channel.tableIssuer), 'ERR_REPLAY')
  expectCode(t, () => consumeDhtExitReservationIOConsumer(channel.ioConsumer), 'ERR_REPLAY')
  t.is(revokeDhtExitReservationChannel(channel.ioConsumer), false)
  expectCode(t, () => createDhtExitReservationChannel(authority), 'ERR_REPLAY')
})

function consumeDhtExitPacketReservationForIO(io, packet, tid) {
  return require('../../lib/private/dht-exit-reservation').consumeDhtExitPacketReservationForIO(
    io,
    packet,
    tid
  )
}
