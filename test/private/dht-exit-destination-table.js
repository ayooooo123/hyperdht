'use strict'

const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-universal')
const { cryptoSuite } = require('../../lib/private/crypto-suite')

const { PrivateRouteError } = require('../../lib/private/errors')
const { BRANCH_CLASS } = require('../../lib/private/protocol')
const {
  TEST_ONLY_DHT_EXIT_OPEN_ISSUER,
  consumeDhtExitReservationIOConsumer,
  createDhtExitReservationChannel
} = require('../../lib/private/dht-exit-reservation')
const {
  closeDhtExitIO,
  createDhtExitIOForTest,
  sendReservedExitDhtPacket
} = require('../../lib/private/dht-exit-io')
const {
  signDhtExitSeedsFromAuthority,
  encodeDhtExitSeeds,
  createDhtExitSeedsDeliveryAuthority,
  verifyDhtExitSeeds
} = require('../../lib/private/dht-exit-seeds')
const {
  TEST_ONLY_DHT_EXIT_TOPOLOGY_ISSUER
} = require('../../lib/private/dht-exit-test-topology-grant')
const {
  DHT_NODE_HANDLE_SIZE,
  createDhtExitDestinationTable,
  createDhtExitDestinationTableForTest,
  createReferralReplyAuthority,
  destroyDhtExitDestinationTable,
  reserveConfiguredBootstrapProbe,
  reserveReferralProbe,
  reserveOrdinaryDhtRequest,
  settleExitDhtReservation,
  readDhtExitDestinationRef
} = require('../../lib/private/dht-exit-destination-table')

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

function seed(value, size = 32) {
  return b4a.alloc(size, value)
}

function material(overrides = {}) {
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

function tableFixture(overrides = {}) {
  const fake = new FakeSocket()
  const channel = createDhtExitReservationChannel(
    TEST_ONLY_DHT_EXIT_OPEN_ISSUER.create(material(overrides.material))
  )
  const table = createDhtExitDestinationTable(channel.tableIssuer, {
    local: { host: '10.1.2.3', port: 41234 },
    configuredBootstrap: overrides.configuredBootstrap || [{ host: '8.8.8.8', port: 49737 }],
    monotonicNow: overrides.monotonicNow || (() => 1_000n),
    randomBytes: seed
  })
  const io = createDhtExitIOForTest(
    {
      host: '10.1.2.3',
      port: 41234,
      monotonicNow: overrides.monotonicNow || (() => 1_000n),
      schedule: (callback) => callback,
      cancelScheduled() {},
      onReply: (replyAuthority) => fake.replies.push(replyAuthority)
    },
    TEST_ONLY_DHT_EXIT_SOCKET_ISSUER.create(() => fake),
    consumeDhtExitReservationIOConsumer(channel.ioConsumer)
  )
  return { fake, table, io }
}

class FakeSocket {
  constructor() {
    this.sends = []
    this.replies = []
    this.bound = null
    this.handler = null
    this.closed = false
  }

  bind(port, host) {
    this.bound = { port, host }
  }

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

const { TEST_ONLY_DHT_EXIT_SOCKET_ISSUER } = require('../../lib/private/dht-exit-io')

function emptyPingReply() {
  return b4a.from('130000000a01020312a1', 'hex')
}

function pingReplyFor(packet) {
  const reply = emptyPingReply()
  reply[2] = packet[2]
  reply[3] = packet[3]
  return reply
}

function closerReplyFor(packet, candidate) {
  const reply = b4a.alloc(17)
  reply[0] = 0x13
  reply[1] = 0x04
  reply[2] = packet[2]
  reply[3] = packet[3]
  reply.set([10, 1, 2, 3, 0x12, 0xa1], 4)
  reply[10] = 1
  const address = candidate.host.split('.').map((part) => Number(part))
  reply.set(address, 11)
  reply[15] = candidate.port
  reply[16] = candidate.port >> 8
  return reply
}

function peerId(host, port) {
  const out = b4a.allocUnsafeSlow(32)
  const address = host.split('.').map((part) => Number(part))
  out[0] = address[0]
  out[1] = address[1]
  out[2] = address[2]
  out[3] = address[3]
  out[4] = port
  out[5] = port >> 8
  sodium.crypto_generichash(out, out.subarray(0, 6))
  return out
}

test('DHT exit destination table admits one configured bootstrap after correlated ping', (t) => {
  const { fake, table, io } = tableFixture()
  const reservation = reserveConfiguredBootstrapProbe(table, 0, 2_000n)

  t.alike(Reflect.ownKeys(reservation.sendAuthority), [])
  t.alike(Reflect.ownKeys(reservation.settlementAuthority), [])
  t.is(sendReservedExitDhtPacket(io, reservation.sendAuthority), true)
  t.alike(fake.sends[0].packet.subarray(0, 4), b4a.from('03040000', 'hex'))

  fake.message(emptyPingReply(), { host: '8.8.8.8', port: 49737 })
  const destinationRef = settleExitDhtReservation(reservation.settlementAuthority, fake.replies[0])
  const decoded = readDhtExitDestinationRef(table, destinationRef)

  t.is(destinationRef.byteLength, 172)
  t.is(decoded.handle.byteLength, DHT_NODE_HANDLE_SIZE)
  t.alike(decoded.id, peerId('8.8.8.8', 49737))
  t.alike(
    decoded.id,
    b4a.from('4365a92a12b58b0c5f92f6f05272e583279395d8887bb549486c55469d431d37', 'hex')
  )
  t.alike(decoded.tuple, { host: '8.8.8.8', port: 49737 })
  expectCode(
    t,
    () => settleExitDhtReservation(reservation.settlementAuthority, fake.replies[0]),
    'ERR_REPLAY'
  )
  t.is(closeDhtExitIO(io), true)
  t.is(destroyDhtExitDestinationTable(table), true)
})

test('DHT exit destination table mints revocable canonical seed delivery authority', (t) => {
  const exit = cryptoSuite.keyPair(seed(0x77))
  const { fake, table, io } = tableFixture({
    material: { exitIdentity: exit.publicKey },
    configuredBootstrap: [
      { host: '1.1.1.1', port: 49737 },
      { host: '8.8.8.8', port: 49737 }
    ]
  })

  const second = reserveConfiguredBootstrapProbe(table, 1, 2_000n)
  t.is(sendReservedExitDhtPacket(io, second.sendAuthority), true)
  fake.message(pingReplyFor(fake.sends[0].packet), { host: '8.8.8.8', port: 49737 })
  settleExitDhtReservation(second.settlementAuthority, fake.replies[0])

  const first = reserveConfiguredBootstrapProbe(table, 0, 2_000n)
  t.is(sendReservedExitDhtPacket(io, first.sendAuthority), true)
  fake.message(pingReplyFor(fake.sends[1].packet), { host: '1.1.1.1', port: 49737 })
  settleExitDhtReservation(first.settlementAuthority, fake.replies[1])

  const authority = createDhtExitSeedsDeliveryAuthority(table)
  const signed = signDhtExitSeedsFromAuthority(
    authority,
    { seedSetNonce: seed(0x99) },
    exit.secretKey
  )
  const decoded = verifyDhtExitSeeds(
    encodeDhtExitSeeds(signed),
    {
      branchClass: BRANCH_CLASS.LOOKUP,
      branchId: seed(0x11, 16),
      circuitId: seed(0x12, 16),
      generation: 7n,
      exitIdentity: exit.publicKey,
      expiresAt: 20_000n
    },
    1_000n
  )
  t.is(decoded.destinationRefs.length, 2)
  t.alike(decoded.destinationRefs, signed.destinationRefs)
  expectCode(
    t,
    () => signDhtExitSeedsFromAuthority(authority, { seedSetNonce: seed(0x99) }, exit.secretKey),
    'ERR_REPLAY'
  )

  const expiredClock = { now: 1_000n }
  const expiredFixture = tableFixture({
    monotonicNow: () => expiredClock.now,
    material: { exitIdentity: exit.publicKey, expiresAt: 2_000n, absoluteDeadline: 2_000n }
  })
  const expiredProbe = reserveConfiguredBootstrapProbe(expiredFixture.table, 0, 1_500n)
  t.is(sendReservedExitDhtPacket(expiredFixture.io, expiredProbe.sendAuthority), true)
  expiredFixture.fake.message(pingReplyFor(expiredFixture.fake.sends[0].packet), {
    host: '8.8.8.8',
    port: 49737
  })
  settleExitDhtReservation(expiredProbe.settlementAuthority, expiredFixture.fake.replies[0])
  const expired = createDhtExitSeedsDeliveryAuthority(expiredFixture.table)
  expiredClock.now = 2_000n
  expectCode(
    t,
    () => signDhtExitSeedsFromAuthority(expired, { seedSetNonce: seed(0x99) }, exit.secretKey),
    'ERR_DESTROYED'
  )
  t.is(closeDhtExitIO(expiredFixture.io), true)

  const revoked = createDhtExitSeedsDeliveryAuthority(table)
  t.is(destroyDhtExitDestinationTable(table), true)
  expectCode(
    t,
    () => signDhtExitSeedsFromAuthority(revoked, { seedSetNonce: seed(0x99) }, exit.secretKey),
    'ERR_DESTROYED'
  )
  t.is(closeDhtExitIO(io), true)
})

test('DHT exit destination table gates ordinary requests on live admitted references', (t) => {
  const { fake, table, io } = tableFixture()
  const probe = reserveConfiguredBootstrapProbe(table, 0, 2_000n)
  t.is(sendReservedExitDhtPacket(io, probe.sendAuthority), true)
  fake.message(emptyPingReply(), { host: '8.8.8.8', port: 49737 })
  const destinationRef = settleExitDhtReservation(probe.settlementAuthority, fake.replies[0])

  const ordinary = reserveOrdinaryDhtRequest(
    table,
    destinationRef,
    { command: 9, target: seed(0xaa), token: null },
    2_000n
  )
  t.is(sendReservedExitDhtPacket(io, ordinary.sendAuthority), true)
  t.alike(fake.sends[1].packet.subarray(0, 4), b4a.from('03080100', 'hex'))

  t.is(destroyDhtExitDestinationTable(table), true)
  expectCode(
    t,
    () =>
      reserveOrdinaryDhtRequest(
        table,
        destinationRef,
        { command: 9, target: seed(0xaa), token: null },
        2_000n
      ),
    'ERR_DESTROYED'
  )
  t.is(closeDhtExitIO(io), true)
})

test('DHT exit destination table admits only reply-qualified referral probes', (t) => {
  t.is(typeof createReferralReplyAuthority, 'function')
  t.is(typeof reserveReferralProbe, 'function')
  const { fake, table, io } = tableFixture()
  const bootstrap = reserveConfiguredBootstrapProbe(table, 0, 2_000n)
  t.is(sendReservedExitDhtPacket(io, bootstrap.sendAuthority), true)
  fake.message(pingReplyFor(fake.sends[0].packet), { host: '8.8.8.8', port: 49737 })
  const bootstrapRef = settleExitDhtReservation(bootstrap.settlementAuthority, fake.replies[0])

  const ordinary = reserveOrdinaryDhtRequest(
    table,
    bootstrapRef,
    { command: 9, target: seed(0xaa), token: null },
    2_000n
  )
  t.is(sendReservedExitDhtPacket(io, ordinary.sendAuthority), true)
  const candidate = { id: peerId('1.1.1.1', 49737), host: '1.1.1.1', port: 49737 }
  fake.message(closerReplyFor(fake.sends[1].packet, candidate), {
    host: '8.8.8.8',
    port: 49737
  })
  const completion = settleExitDhtReservation(ordinary.settlementAuthority, fake.replies[1])
  const referralReply = createReferralReplyAuthority(completion)
  expectCode(
    t,
    () =>
      reserveReferralProbe(
        table,
        referralReply,
        { id: peerId('9.9.9.9', 49737), host: '9.9.9.9', port: 49737 },
        2_000n
      ),
    'ERR_AUTHENTICATION'
  )
  const referral = reserveReferralProbe(table, referralReply, candidate, 2_000n)
  const concurrentOrdinary = reserveOrdinaryDhtRequest(
    table,
    bootstrapRef,
    { command: 9, target: seed(0xab), token: null },
    2_000n
  )
  t.is(sendReservedExitDhtPacket(io, concurrentOrdinary.sendAuthority), true)
  fake.message(closerReplyFor(fake.sends[2].packet, candidate), {
    host: '8.8.8.8',
    port: 49737
  })
  const concurrentCompletion = settleExitDhtReservation(
    concurrentOrdinary.settlementAuthority,
    fake.replies[2]
  )
  const concurrentReply = createReferralReplyAuthority(concurrentCompletion)
  t.is(reserveReferralProbe(table, concurrentReply, candidate, 2_000n), null)
  t.is(fake.sends.length, 3)
  t.is(sendReservedExitDhtPacket(io, referral.sendAuthority), true)
  fake.message(pingReplyFor(fake.sends[3].packet), { host: '1.1.1.1', port: 49737 })
  const referralRef = settleExitDhtReservation(referral.settlementAuthority, fake.replies[3])
  t.alike(readDhtExitDestinationRef(table, referralRef).tuple, {
    host: '1.1.1.1',
    port: 49737
  })
  const repeatedOrdinary = reserveOrdinaryDhtRequest(
    table,
    bootstrapRef,
    { command: 9, target: seed(0xbb), token: null },
    2_000n
  )
  t.is(sendReservedExitDhtPacket(io, repeatedOrdinary.sendAuthority), true)
  fake.message(closerReplyFor(fake.sends[4].packet, candidate), {
    host: '8.8.8.8',
    port: 49737
  })
  const repeatedCompletion = settleExitDhtReservation(
    repeatedOrdinary.settlementAuthority,
    fake.replies[4]
  )
  const repeatedReply = createReferralReplyAuthority(repeatedCompletion)
  t.is(reserveReferralProbe(table, repeatedReply, candidate, 2_000n), null)
  t.is(fake.sends.length, 5)
  t.is(destroyDhtExitDestinationTable(table), true)
  t.is(closeDhtExitIO(io), true)
})

test('DHT exit authorities cannot outlive reentrant table destruction', (t) => {
  let table = null
  let destroyOnClock = false
  const current = tableFixture({
    monotonicNow() {
      if (destroyOnClock) destroyDhtExitDestinationTable(table)
      return 1_000n
    }
  })
  table = current.table
  const bootstrap = reserveConfiguredBootstrapProbe(table, 0, 2_000n)
  t.is(sendReservedExitDhtPacket(current.io, bootstrap.sendAuthority), true)
  current.fake.message(pingReplyFor(current.fake.sends[0].packet), {
    host: '8.8.8.8',
    port: 49737
  })
  const bootstrapRef = settleExitDhtReservation(
    bootstrap.settlementAuthority,
    current.fake.replies[0]
  )
  const ordinary = reserveOrdinaryDhtRequest(
    table,
    bootstrapRef,
    { command: 9, target: seed(0xcc), token: null },
    2_000n
  )
  t.is(sendReservedExitDhtPacket(current.io, ordinary.sendAuthority), true)
  current.fake.message(pingReplyFor(current.fake.sends[1].packet), {
    host: '8.8.8.8',
    port: 49737
  })
  const completion = settleExitDhtReservation(ordinary.settlementAuthority, current.fake.replies[1])
  destroyOnClock = true
  expectCode(t, () => createReferralReplyAuthority(completion), 'ERR_DESTROYED')
  t.is(closeDhtExitIO(current.io), true)
  let referralTable = null
  let destroyReferral = false
  const referralFixture = tableFixture({
    monotonicNow() {
      if (destroyReferral) destroyDhtExitDestinationTable(referralTable)
      return 1_000n
    }
  })
  referralTable = referralFixture.table
  const referralBootstrap = reserveConfiguredBootstrapProbe(referralTable, 0, 2_000n)
  t.is(sendReservedExitDhtPacket(referralFixture.io, referralBootstrap.sendAuthority), true)
  referralFixture.fake.message(pingReplyFor(referralFixture.fake.sends[0].packet), {
    host: '8.8.8.8',
    port: 49737
  })
  const referralBootstrapRef = settleExitDhtReservation(
    referralBootstrap.settlementAuthority,
    referralFixture.fake.replies[0]
  )
  const referralOrdinary = reserveOrdinaryDhtRequest(
    referralTable,
    referralBootstrapRef,
    { command: 9, target: seed(0xcd), token: null },
    2_000n
  )
  t.is(sendReservedExitDhtPacket(referralFixture.io, referralOrdinary.sendAuthority), true)
  const referralCandidate = {
    id: peerId('1.1.1.1', 49737),
    host: '1.1.1.1',
    port: 49737
  }
  referralFixture.fake.message(
    closerReplyFor(referralFixture.fake.sends[1].packet, referralCandidate),
    { host: '8.8.8.8', port: 49737 }
  )
  const referralCompletion = settleExitDhtReservation(
    referralOrdinary.settlementAuthority,
    referralFixture.fake.replies[1]
  )
  const referralAuthority = createReferralReplyAuthority(referralCompletion)
  destroyReferral = true
  expectCode(
    t,
    () => reserveReferralProbe(referralTable, referralAuthority, referralCandidate, 2_000n),
    'ERR_DESTROYED'
  )
  t.is(closeDhtExitIO(referralFixture.io), true)

  let admissionTable = null
  let destroyAdmission = false
  const admissionFixture = tableFixture({
    monotonicNow() {
      if (destroyAdmission) destroyDhtExitDestinationTable(admissionTable)
      return 1_000n
    }
  })
  admissionTable = admissionFixture.table
  const admission = reserveConfiguredBootstrapProbe(admissionTable, 0, 2_000n)
  t.is(sendReservedExitDhtPacket(admissionFixture.io, admission.sendAuthority), true)
  admissionFixture.fake.message(pingReplyFor(admissionFixture.fake.sends[0].packet), {
    host: '8.8.8.8',
    port: 49737
  })
  destroyAdmission = true
  expectCode(
    t,
    () => settleExitDhtReservation(admission.settlementAuthority, admissionFixture.fake.replies[0]),
    'ERR_DESTROYED'
  )
  t.is(closeDhtExitIO(admissionFixture.io), true)
})

test('DHT exit destination table revokes reserved sends on destroy', (t) => {
  const { table, io } = tableFixture()
  const reservation = reserveConfiguredBootstrapProbe(table, 0, 2_000n)
  t.is(destroyDhtExitDestinationTable(table), true)
  expectCode(t, () => sendReservedExitDhtPacket(io, reservation.sendAuthority), 'ERR_DESTROYED')
  expectCode(
    t,
    () => settleExitDhtReservation(reservation.settlementAuthority, Object.freeze({})),
    'ERR_REPLAY'
  )
  t.is(closeDhtExitIO(io), true)
})

test('DHT exit test topology authority admits only its exact isolated tuple set', (t) => {
  t.is(typeof createDhtExitDestinationTableForTest, 'function')
  t.ok(TEST_ONLY_DHT_EXIT_TOPOLOGY_ISSUER)
  const channel = createDhtExitReservationChannel(TEST_ONLY_DHT_EXIT_OPEN_ISSUER.create(material()))
  const topologyAuthority = TEST_ONLY_DHT_EXIT_TOPOLOGY_ISSUER.create([
    { host: '203.0.113.9', port: 49737 }
  ])
  const table = createDhtExitDestinationTableForTest(
    channel.tableIssuer,
    {
      local: { host: '10.1.2.3', port: 41234 },
      configuredBootstrap: [{ host: '203.0.113.9', port: 49737 }],
      monotonicNow: () => 1_000n,
      randomBytes: seed
    },
    topologyAuthority
  )
  t.is(destroyDhtExitDestinationTable(table), true)

  const replayChannel = createDhtExitReservationChannel(
    TEST_ONLY_DHT_EXIT_OPEN_ISSUER.create(material())
  )
  expectCode(
    t,
    () =>
      createDhtExitDestinationTableForTest(
        replayChannel.tableIssuer,
        {
          local: { host: '10.1.2.3', port: 41234 },
          configuredBootstrap: [{ host: '203.0.113.9', port: 49737 }],
          monotonicNow: () => 1_000n,
          randomBytes: seed
        },
        topologyAuthority
      ),
    'ERR_REPLAY'
  )
  const mismatchChannel = createDhtExitReservationChannel(
    TEST_ONLY_DHT_EXIT_OPEN_ISSUER.create(material())
  )
  const mismatchAuthority = TEST_ONLY_DHT_EXIT_TOPOLOGY_ISSUER.create([
    { host: '203.0.113.9', port: 49737 }
  ])
  expectCode(
    t,
    () =>
      createDhtExitDestinationTableForTest(
        mismatchChannel.tableIssuer,
        {
          local: { host: '10.1.2.3', port: 41234 },
          configuredBootstrap: [{ host: '203.0.113.10', port: 49737 }],
          monotonicNow: () => 1_000n,
          randomBytes: seed
        },
        mismatchAuthority
      ),
    'ERR_AUTHENTICATION'
  )
})

test('DHT exit destination table rejects only exact special-use IPv4 seed blocks', (t) => {
  const acceptedChannel = createDhtExitReservationChannel(
    TEST_ONLY_DHT_EXIT_OPEN_ISSUER.create(material())
  )
  const accepted = createDhtExitDestinationTable(acceptedChannel.tableIssuer, {
    local: { host: '10.1.2.3', port: 41234 },
    configuredBootstrap: [{ host: '198.51.101.7', port: 49737 }],
    monotonicNow: () => 1_000n,
    randomBytes: seed
  })
  t.is(destroyDhtExitDestinationTable(accepted), true)

  const rejectedChannel = createDhtExitReservationChannel(
    TEST_ONLY_DHT_EXIT_OPEN_ISSUER.create(material())
  )
  expectCode(
    t,
    () =>
      createDhtExitDestinationTable(rejectedChannel.tableIssuer, {
        local: { host: '10.1.2.3', port: 41234 },
        configuredBootstrap: [{ host: '198.51.100.7', port: 49737 }],
        monotonicNow: () => 1_000n,
        randomBytes: seed
      }),
    'INVALID_ROUTE'
  )
})
