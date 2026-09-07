'use strict'

const test = require('brittle')
const b4a = require('b4a')

const guardLinks = require('../../lib/private/guard-link')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  DatagramReplayWindow,
  OrderedReceiver,
  SenderCounter
} = require('../../lib/private/counters')
const { fragment, Reassembler } = require('../../lib/private/fragments')
const {
  M3AdjacencyAuthority,
  beginM3RouteTeardown,
  deriveM3CellIds,
  destroyM3RouteTransport,
  receiveM3RouteFrame,
  sendM3RouteFrame,
  takeM3RouteTransport,
  takeM3TailCapability
} = require('../../lib/private/m3-adjacency-runtime')
const {
  ROUTE_ENDPOINT,
  RoutePayloadCodec,
  mintCreatedRoutePayloadContext
} = require('../../lib/private/route-payload')
const { decodeImmutableGetResponse } = require('../../lib/private/dht-exit-wire')
const { decodeRoutedReply, encodeRoutedRequest } = require('../../lib/private/routed-dht')
const {
  createDhtExitDestinationTable,
  destroyDhtExitDestinationTable,
  readDhtExitDestinationRef,
  reserveConfiguredBootstrapProbe,
  settleExitDhtReservation
} = require('../../lib/private/dht-exit-destination-table')
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
  installDhtExitRoute,
  sendReservedExitDhtPacket
} = require('../../lib/private/dht-exit-io')
const { BRANCH_CLASS, CELL_CLASS, DIRECTION, M3_MESSAGE_ID } = require('../../lib/private/protocol')

function seed(byte, size = 32) {
  return b4a.alloc(size, byte)
}

const TEST_ONLY_M3_ESTABLISHED_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-m3-established-issuer'
)

function routeCellContexts(initiator) {
  const contexts = {}
  for (const cellClass of [CELL_CLASS.CONTROL, CELL_CLASS.STREAM, CELL_CLASS.DATAGRAM]) {
    const forwardKey = seed(0x31 + cellClass)
    const reverseKey = seed(0x41 + cellClass)
    const forwardNonce = seed(0x51 + cellClass, 16)
    const reverseNonce = seed(0x61 + cellClass, 16)
    contexts[cellClass] = {
      tx: {
        key: initiator ? forwardKey : reverseKey,
        noncePrefix: initiator ? forwardNonce : reverseNonce,
        counter: new SenderCounter()
      },
      rx: {
        key: initiator ? reverseKey : forwardKey,
        noncePrefix: initiator ? reverseNonce : forwardNonce,
        counter:
          cellClass === CELL_CLASS.DATAGRAM
            ? new DatagramReplayWindow({ window: 256 })
            : new OrderedReceiver({ window: 256, gapTimeout: 5_000, now: () => 1_000 })
      }
    }
  }
  return contexts
}

function routeTransportPair() {
  const queues = [[], []]
  const waiters = [[], []]
  const channels = [0, 1].map((side) => ({
    send(packet) {
      const peer = side ^ 1
      if (waiters[peer].length > 0) waiters[peer].shift()(b4a.from(packet))
      else queues[peer].push(b4a.from(packet))
      return true
    },
    receive() {
      if (queues[side].length > 0) return Promise.resolve(queues[side].shift())
      return new Promise((resolve) => waiters[side].push(resolve))
    },
    destroy() {}
  }))
  const wallNow = () => 1_000n
  const monotonicNow = () => 1_000n
  const digest = seed(0x71)
  const ids = deriveM3CellIds(digest, { crypto: cryptoSuite })
  const authority = new M3AdjacencyAuthority({
    wallNow,
    monotonicNow,
    schedule: () => Object.freeze({}),
    cancelScheduled() {},
    crypto: cryptoSuite
  })
  const adopted = [true, false].map((initiator, side) =>
    authority.adopt(
      guardLinks[TEST_ONLY_M3_ESTABLISHED_ISSUER].issue({
        initiator,
        completeOfferDigest: b4a.from(digest),
        localId: b4a.from(initiator ? ids.initiatorCellId : ids.responderCellId),
        peerLocalId: b4a.from(initiator ? ids.responderCellId : ids.initiatorCellId),
        branchClass: BRANCH_CLASS.LOOKUP,
        branchId: seed(0x11, 16),
        circuitId: seed(0x12, 16),
        generation: 7n,
        extensionIndex: 0,
        localIdentity: seed(initiator ? 0x72 : 0x73),
        peerIdentity: seed(initiator ? 0x73 : 0x72),
        expiresAt: 20_000n,
        contexts: routeCellContexts(initiator),
        physicalChannel: channels[side],
        clientTailEphemeralSecretKey: initiator ? seed(0x74) : null,
        tailControlTranscript: seed(0x75, 290)
      })
    )
  )
  const moved = adopted.map((entry) =>
    takeM3TailCapability(entry.tail, {
      wallNow,
      monotonicNow
    })
  )
  return {
    endpoint: takeM3RouteTransport(moved[0].transportOwner),
    exit: takeM3RouteTransport(moved[1].transportOwner)
  }
}

function routePayloadCodec(endpointRole, route) {
  return new RoutePayloadCodec({
    crypto: cryptoSuite,
    context: mintCreatedRoutePayloadContext({
      endpointRole,
      descriptorId: route.payloadDigest,
      circuitId: seed(0x12, 16),
      forwardKey: route.payloadForwardKey,
      forwardNoncePrefix: route.payloadForwardNoncePrefix,
      reverseKey: route.payloadReverseKey,
      reverseNoncePrefix: route.payloadReverseNoncePrefix
    }),
    window: 64,
    gapTimeout: 5_000,
    now: () => 1_000
  })
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

async function waitFor(check) {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (check()) return
    await Promise.resolve()
  }
  throw new Error('condition was not reached')
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
  t.alike(fake.sends[0].packet.subarray(0, 2), b4a.from('0308', 'hex'))

  fake.message(responseFor(fake.sends[0].packet, 0), {
    host: '203.0.113.9',
    port: 49737
  })
  t.is(replies.length, 1)
  t.is(
    consumeDhtExitCorrelatedReplyAuthority(replies[0]).reply.tid,
    fake.sends[0].packet[2] | (fake.sends[0].packet[3] << 8)
  )
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
  fake.message(responseFor(fake.sends[0].packet, 0), { host: '203.0.113.10', port: 49737 })
  fake.message(
    b4a.from(
      '03080000cb00710949c209aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      'hex'
    ),
    { host: '203.0.113.9', port: 49737 }
  )
  const unsolicited = responseFor(fake.sends[0].packet, 0)
  unsolicited[2] ^= 1
  fake.message(unsolicited, { host: '203.0.113.9', port: 49737 })
  fake.message(responseFor(fake.sends[0].packet, 0), { host: '203.0.113.9', port: 49737 })
  fake.message(responseFor(fake.sends[0].packet, 0), { host: '203.0.113.9', port: 49737 })
  t.is(replies.length, 1)
  const late = packet(installed.table, { deadline: 18_500n })
  t.is(sendReservedExitDhtPacket(io, late), true)
  now = 18_500n
  scheduled[1].callback()
  const lateUnsolicited = responseFor(fake.sends[0].packet, 0)
  lateUnsolicited[2] ^= 1
  fake.message(lateUnsolicited, { host: '203.0.113.9', port: 49737 })
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
  t.alike(result.message.subarray(0, 2), b4a.from('0308', 'hex'))
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

test('DHTExitIO terminal pump executes routed immutable get over owned M3 transport', async (t) => {
  const fake = new FakeSocket()
  const replies = []
  const pair = routeTransportPair()
  let incomingReleases = 0
  const route = {
    payloadDigest: seed(0x21),
    payloadForwardKey: seed(0x22),
    payloadReverseKey: seed(0x23),
    payloadForwardNoncePrefix: seed(0x24, 16),
    payloadReverseNoncePrefix: seed(0x25, 16)
  }
  const authority = TEST_ONLY_DHT_EXIT_OPEN_ISSUER.create(
    {
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
    },
    { transport: pair.exit, ...route }
  )
  const channel = createDhtExitReservationChannel(authority)
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
      schedule: () => Object.freeze({}),
      cancelScheduled() {},
      onReply(authority) {
        replies.push(authority)
      }
    },
    TEST_ONLY_DHT_EXIT_SOCKET_ISSUER.create(() => fake),
    consumeDhtExitReservationIOConsumer(channel.ioConsumer)
  )
  const probe = reserveConfiguredBootstrapProbe(table, 0, 2_000n)
  sendReservedExitDhtPacket(io, probe.sendAuthority)
  fake.message(responseFor(fake.sends[0].packet, 0), { host: '8.8.8.8', port: 49737 })
  const destinationRef = settleExitDhtReservation(probe.settlementAuthority, replies[0])
  const destination = readDhtExitDestinationRef(table, destinationRef)
  t.is(
    installDhtExitRoute(io, table, {
      async releaseIncoming() {
        incomingReleases++
      }
    }),
    true
  )

  const endpointCodec = routePayloadCodec(ROUTE_ENDPOINT.SOURCE, route)
  const replyReassembler = new Reassembler({
    now: () => 1_000,
    epochExpiresAt: 20_000
  })
  const malformed = endpointCodec.seal({
    direction: DIRECTION.FORWARD,
    class: CELL_CLASS.DATAGRAM,
    payload: b4a.alloc(1)
  })
  await sendM3RouteFrame(pair.endpoint, malformed)
  malformed.fill(0)

  const encodedRequest = encodeRoutedRequest({
    requestId: seed(0x31, 16),
    operationClass: BRANCH_CLASS.LOOKUP,
    commandId: M3_MESSAGE_ID.IMMUTABLE_GET_V1,
    operationBudgetMs: 2_000n,
    destination: { id: destination.id, handle: destination.handle },
    encodedBody: seed(0x32)
  })
  const payloads = fragment(encodedRequest, {
    randomBytes: (size) => seed(0x33, size)
  })
  for (const payload of payloads) {
    const frame = endpointCodec.seal({
      direction: DIRECTION.FORWARD,
      class: CELL_CLASS.DATAGRAM,
      payload
    })
    await sendM3RouteFrame(pair.endpoint, frame)
    frame.fill(0)
    payload.fill(0)
  }
  encodedRequest.fill(0)
  await waitFor(() => fake.sends.length === 2)
  fake.message(responseFor(fake.sends[1].packet, 0x10, b4a.from([1, 0xaa])), {
    host: '8.8.8.8',
    port: 49737
  })

  let encodedReply = null
  while (encodedReply === null) {
    const frame = await receiveM3RouteFrame(pair.endpoint)
    const opened = endpointCodec.open({ direction: DIRECTION.REVERSE }, frame)
    frame.fill(0)
    encodedReply = replyReassembler.pushAuthenticated(opened.payload)
    opened.payload.fill(0)
  }
  const reply = decodeRoutedReply(encodedReply)
  t.alike(reply.requestId, seed(0x31, 16))
  t.alike(decodeImmutableGetResponse(reply.encodedResponse), {
    valuePresent: true,
    value: b4a.from([0xaa])
  })
  expectCode(
    t,
    () => installDhtExitRoute(io, table, { releaseIncoming: async () => {} }),
    'ERR_AUTHENTICATION'
  )
  encodedReply.fill(0)
  replyReassembler.destroy()
  endpointCodec.destroy()
  closeDhtExitIO(io)
  await waitFor(() => incomingReleases === 1)
  t.is(incomingReleases, 1, 'ordinary close joins transferred incoming release exactly once')
  destroyDhtExitDestinationTable(table)
  destroyM3RouteTransport(pair.endpoint)
})

test('DHTExitIO derives the routed operation deadline once for admission and reservation', async (t) => {
  const fake = new FakeSocket()
  const replies = []
  const scheduled = []
  const pair = routeTransportPair()
  const route = {
    payloadDigest: seed(0x81),
    payloadForwardKey: seed(0x82),
    payloadReverseKey: seed(0x83),
    payloadForwardNoncePrefix: seed(0x84, 16),
    payloadReverseNoncePrefix: seed(0x85, 16)
  }
  // KI-15: the routed request carries a relative budget, so the exit derives the operation's
  // absolute deadline from its own clock, exactly once. Here the exit's clock steps forward the
  // moment the destination check runs, and the table's absolute deadline - which is also the
  // admitted entry's expiry - sits exactly on the deadline derived from the FIRST sample. A
  // second sample would derive 3_500n, exceed the cap the destination was admitted against, and
  // the reservation would be refused, silently dropping a live route's request.
  const budget = 2_000n
  const admissionNow = 1_000n
  const reservationNow = 1_500n
  const operationDeadline = admissionNow + budget
  let armed = false
  let checkedDestination = false
  const exitNow = () => (checkedDestination ? reservationNow : admissionNow)
  // The table's clock marks the boundary the exit's clock steps across. Once the request is
  // injected the exit consults the table twice: first for the route binding, before the request
  // is even decoded, and then from inside the destination check - which happens after the exit
  // has sampled its own clock for the admission deadline. Stepping on the second consult puts
  // the step strictly between the destination check and the reservation.
  let tableConsults = 0
  const tableNow = () => {
    if (armed && ++tableConsults > 1) checkedDestination = true
    return admissionNow
  }
  const authority = TEST_ONLY_DHT_EXIT_OPEN_ISSUER.create(
    {
      branchClass: BRANCH_CLASS.LOOKUP,
      branchId: seed(0x11, 16),
      circuitId: seed(0x12, 16),
      generation: 7n,
      exitIdentity: seed(0x13),
      finalTranscriptDigest: seed(0x14),
      expiresAt: 20_000n,
      absoluteDeadline: operationDeadline,
      controlKey: seed(0x15),
      controlNoncePrefix: seed(0x16, 16)
    },
    { transport: pair.exit, ...route }
  )
  const opened = createDhtExitReservationChannel(authority)
  const table = createDhtExitDestinationTable(opened.tableIssuer, {
    local: { host: '10.1.2.3', port: 41234 },
    configuredBootstrap: [{ host: '8.8.8.8', port: 49737 }],
    monotonicNow: tableNow,
    randomBytes: seed
  })
  const io = createDhtExitIOForTest(
    {
      host: '10.1.2.3',
      port: 41234,
      monotonicNow: exitNow,
      schedule(callback, delay) {
        const handle = Object.freeze({ callback, delay })
        scheduled.push(handle)
        return handle
      },
      cancelScheduled() {},
      onReply(replyAuthority) {
        replies.push(replyAuthority)
      }
    },
    TEST_ONLY_DHT_EXIT_SOCKET_ISSUER.create(() => fake),
    consumeDhtExitReservationIOConsumer(opened.ioConsumer)
  )
  const probe = reserveConfiguredBootstrapProbe(table, 0, 2_000n)
  sendReservedExitDhtPacket(io, probe.sendAuthority)
  fake.message(responseFor(fake.sends[0].packet, 0), { host: '8.8.8.8', port: 49737 })
  const destinationRef = settleExitDhtReservation(probe.settlementAuthority, replies[0])
  const destination = readDhtExitDestinationRef(table, destinationRef)
  t.is(destination.expiresAt, operationDeadline)
  t.is(installDhtExitRoute(io, table, { releaseIncoming: async () => {} }), true)

  const endpointCodec = routePayloadCodec(ROUTE_ENDPOINT.SOURCE, route)
  const replyReassembler = new Reassembler({
    now: () => 1_000,
    epochExpiresAt: 20_000
  })
  const encodedRequest = encodeRoutedRequest({
    requestId: seed(0x41, 16),
    operationClass: BRANCH_CLASS.LOOKUP,
    commandId: M3_MESSAGE_ID.IMMUTABLE_GET_V1,
    operationBudgetMs: budget,
    destination: { id: destination.id, handle: destination.handle },
    encodedBody: seed(0x42)
  })
  const payloads = fragment(encodedRequest, {
    randomBytes: (size) => seed(0x43, size)
  })
  armed = true
  for (const payload of payloads) {
    const frame = endpointCodec.seal({
      direction: DIRECTION.FORWARD,
      class: CELL_CLASS.DATAGRAM,
      payload
    })
    await sendM3RouteFrame(pair.endpoint, frame)
    frame.fill(0)
    payload.fill(0)
  }
  encodedRequest.fill(0)
  await waitFor(() => fake.sends.length === 2)
  t.is(checkedDestination, true)
  t.is(exitNow(), reservationNow)
  t.is(BigInt(scheduled[1].delay) + reservationNow, operationDeadline)
  fake.message(responseFor(fake.sends[1].packet, 0x10, b4a.from([1, 0xbb])), {
    host: '8.8.8.8',
    port: 49737
  })

  let encodedReply = null
  while (encodedReply === null) {
    const frame = await receiveM3RouteFrame(pair.endpoint)
    const cell = endpointCodec.open({ direction: DIRECTION.REVERSE }, frame)
    frame.fill(0)
    encodedReply = replyReassembler.pushAuthenticated(cell.payload)
    cell.payload.fill(0)
  }
  const reply = decodeRoutedReply(encodedReply)
  t.is(reply.errorCode, 0)
  t.alike(reply.requestId, seed(0x41, 16))
  t.alike(decodeImmutableGetResponse(reply.encodedResponse), {
    valuePresent: true,
    value: b4a.from([0xbb])
  })
  encodedReply.fill(0)
  replyReassembler.destroy()
  endpointCodec.destroy()
  closeDhtExitIO(io)
  destroyDhtExitDestinationTable(table)
  destroyM3RouteTransport(pair.endpoint)
})
test('DHTExitIO drains active route ownership and joins incoming release before ACK', async (t) => {
  const fake = new FakeSocket()
  const replies = []
  const pair = routeTransportPair()
  const route = {
    payloadDigest: seed(0xa1),
    payloadForwardKey: seed(0xa2),
    payloadReverseKey: seed(0xa3),
    payloadForwardNoncePrefix: seed(0xa4, 16),
    payloadReverseNoncePrefix: seed(0xa5, 16)
  }
  const authority = TEST_ONLY_DHT_EXIT_OPEN_ISSUER.create(
    {
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
    },
    { transport: pair.exit, ...route }
  )
  const channel = createDhtExitReservationChannel(authority)
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
      schedule: () => Object.freeze({}),
      cancelScheduled() {},
      onReply(replyAuthority) {
        replies.push(replyAuthority)
      }
    },
    TEST_ONLY_DHT_EXIT_SOCKET_ISSUER.create(() => fake),
    consumeDhtExitReservationIOConsumer(channel.ioConsumer)
  )
  const probe = reserveConfiguredBootstrapProbe(table, 0, 2_000n)
  sendReservedExitDhtPacket(io, probe.sendAuthority)
  fake.message(responseFor(fake.sends[0].packet, 0), { host: '8.8.8.8', port: 49737 })
  const destinationRef = settleExitDhtReservation(probe.settlementAuthority, replies.shift())
  const destination = readDhtExitDestinationRef(table, destinationRef)
  let releaseIncoming
  const releaseHeld = new Promise((resolve) => {
    releaseIncoming = resolve
  })
  let releases = 0
  t.is(
    installDhtExitRoute(io, table, {
      async releaseIncoming() {
        releases++
        t.is(
          TEST_ONLY_DHT_EXIT_IO_STATE.snapshot(io).activeOperations,
          0,
          'active operation is cancelled before incoming release begins'
        )
        await releaseHeld
      }
    }),
    true
  )
  const endpointCodec = routePayloadCodec(ROUTE_ENDPOINT.SOURCE, route)
  const encodedRequest = encodeRoutedRequest({
    requestId: seed(0x91, 16),
    operationClass: BRANCH_CLASS.LOOKUP,
    commandId: M3_MESSAGE_ID.IMMUTABLE_GET_V1,
    operationBudgetMs: 2_000n,
    destination: { id: destination.id, handle: destination.handle },
    encodedBody: seed(0x92)
  })
  for (const payload of fragment(encodedRequest, { randomBytes: (size) => seed(0x93, size) })) {
    const frame = endpointCodec.seal({
      direction: DIRECTION.FORWARD,
      class: CELL_CLASS.DATAGRAM,
      payload
    })
    await sendM3RouteFrame(pair.endpoint, frame)
    frame.fill(0)
    payload.fill(0)
  }
  encodedRequest.fill(0)
  await waitFor(() => fake.sends.length === 2)
  t.is(TEST_ONLY_DHT_EXIT_IO_STATE.snapshot(io).activeOperations, 1)

  let settled = false
  const teardown = beginM3RouteTeardown(pair.endpoint, seed(0x94, 16)).then(() => {
    settled = true
  })
  await waitFor(() => releases === 1)
  t.is(settled, false, 'endpoint observes no ACK while incoming close/grant release is held')
  t.is(TEST_ONLY_DHT_EXIT_IO_STATE.snapshot(io).pendingPackets, 0)
  releaseIncoming()
  await teardown
  t.is(settled, true, 'ACK follows the joined release')
  t.is(releases, 1, 'cleanup is one-shot')
  endpointCodec.destroy()
  closeDhtExitIO(io)
  destroyDhtExitDestinationTable(table)
  destroyM3RouteTransport(pair.endpoint)
  destroyM3RouteTransport(pair.exit)
})
