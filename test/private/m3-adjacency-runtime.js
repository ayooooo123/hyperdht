'use strict'

const test = require('brittle')
const b4a = require('b4a')

const {
  DatagramReplayWindow,
  OrderedReceiver,
  SenderCounter
} = require('../../lib/private/counters')
const { CellCodec } = require('../../lib/private/cell-codec')
const guardLinks = require('../../lib/private/guard-link')
const {
  BRANCH_CLASS,
  CELL_CLASS,
  DIRECTION,
  M3_MESSAGE_ID,
  encodeM3Object
} = require('../../lib/private/protocol')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  M3AdjacencyAuthority,
  TEST_ONLY_M3_ADJACENCY_OBSERVER,
  BRANCH_TEARDOWN_BODY_BYTES,
  beginM3RouteTeardown,
  abortM3Install,
  beginM3Install,
  commitM3Install,
  createM3RelayForwardingFacade,
  decodeBranchTeardown,
  destroyM3RouteTransport,
  encodeBranchTeardown,
  createM3ForwardingPublicationClaim,
  createM3TailForwardingLease,
  destroyM3TailForwardingPublication,
  publishM3TailForwarding,
  consumeTailResponderToken,
  deriveM3CellIds,
  readM3RouteTransportDiagnostics,
  registerM3RouteTeardownHandler,
  receiveM3RouteFrame,
  sendM3RouteFrame,
  takeM3RouteTransport,
  revokeM3TailCapability,
  revokeM3TailForwardingLease,
  revokeTailResponderToken,
  projectM3TailWireDeadline,
  shortenM3TailOperationDeadline,
  takeM3TailCapability,
  takeM3TailForwardingPublication,
  validateM3Install
} = require('../../lib/private/m3-adjacency-runtime')
const { MAX_FRAGMENTS } = require('../../lib/private/fragments')
function fakeClock({ wall = 1_000n, monotonic = 10_000n } = {}) {
  let currentWall = wall
  let currentMonotonic = monotonic
  let wallSamples = 0
  let monotonicSamples = 0
  let nextHandle = 0
  const delays = []
  const timers = new Map()
  const clock = {
    wallNow() {
      wallSamples++
      return currentWall
    },
    monotonicNow() {
      monotonicSamples++
      return currentMonotonic
    },
    schedule(callback, delay) {
      delays.push(delay)
      const handle = ++nextHandle
      timers.set(handle, { callback, at: currentMonotonic + BigInt(delay) })
      return handle
    },
    cancelScheduled(handle) {
      timers.delete(handle)
    },
    setWall(value) {
      currentWall = value
    },
    setMonotonic(value) {
      currentMonotonic = value
    },
    pending() {
      return timers.size
    },
    fireNext() {
      let selected = null
      for (const [handle, timer] of timers) {
        if (selected === null || timer.at < selected.timer.at) selected = { handle, timer }
      }
      if (selected === null) return false
      timers.delete(selected.handle)
      currentMonotonic = selected.timer.at
      selected.timer.callback()
      return true
    },
    get delays() {
      return delays
    },
    get wallSamples() {
      return wallSamples
    },
    get monotonicSamples() {
      return monotonicSamples
    }
  }
  return clock
}

function authority(clock, overrides = {}) {
  return new M3AdjacencyAuthority({
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled,
    crypto: cryptoSuite,
    ...overrides
  })
}
function relayOptions(clock, overrides = {}) {
  return {
    releaseDownstream: async () => {},
    releaseUpstream: async () => {},
    monotonicNow: clock.monotonicNow,
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled,
    ...overrides
  }
}

const TEST_ONLY_M3_ESTABLISHED_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-m3-established-issuer'
)
const OFFER_DIGEST = b4a.from(Array.from({ length: 32 }, (_, index) => index))

const MAX_TIMER_DELAY = 0x7fff_ffff
function channel() {
  let destroys = 0
  return {
    value: Object.freeze({
      destroy() {
        destroys++
      }
    }),
    get destroys() {
      return destroys
    }
  }
}

function forwardingFacade(destroy = () => {}) {
  return Object.freeze({
    diagnostics: () => Object.freeze({ state: 'FORWARDING' }),
    destroy
  })
}

function relayChannel({ holdSends = false } = {}) {
  const packets = []
  const inbound = []
  const waiters = []
  const sendWaiters = []
  let receiveError = null
  let sendError = null
  let destroys = 0
  const value = Object.freeze({
    send(packet) {
      packets.push(b4a.from(packet))
      if (sendError) {
        const error = sendError
        sendError = null
        return Promise.reject(error)
      }
      if (!holdSends) return true
      return new Promise((resolve) => sendWaiters.push(resolve))
    },
    receive() {
      if (receiveError) {
        const error = receiveError
        receiveError = null
        return Promise.reject(error)
      }
      if (inbound.length > 0) return Promise.resolve(inbound.shift())
      return new Promise((resolve, reject) => waiters.push({ resolve, reject }))
    },
    destroy() {
      destroys++
      for (const waiter of waiters.splice(0)) {
        waiter.reject(new Error('logical relay channel destroyed'))
      }
    }
  })
  return {
    value,
    packets,
    // `deliver` requires a pending receive on purpose: three tests rely on that
    // throw to prove the pump was reading when they delivered. A route transport
    // that has stopped reading is exactly the state KI-10 is about, so it needs a
    // delivery that does not assert a reader - the packet waits in the channel the
    // way a datagram waits in a link buffer.
    deliverUnread(packet) {
      const waiter = waiters.shift()
      if (waiter) waiter.resolve(b4a.from(packet))
      else inbound.push(b4a.from(packet))
    },
    deliver(packet) {
      const waiter = waiters.shift()
      if (waiter) waiter.resolve(b4a.from(packet))
      else throw new Error('relay receive is not pending')
    },
    fail(error) {
      const waiter = waiters.shift()
      if (waiter) waiter.reject(error)
      else receiveError = error
    },
    failSend(error) {
      sendError = error
    },
    releaseSend() {
      const resolve = sendWaiters.shift()
      if (!resolve) return false
      resolve(true)
      return true
    },
    get pendingSends() {
      return sendWaiters.length
    },
    get destroys() {
      return destroys
    }
  }
}

function writeU64(target, value, offset) {
  for (let index = 7; index >= 0; index--) {
    target[offset + index] = Number(value & 0xffn)
    value >>= 8n
  }
}

function branchDestroyPacket(state) {
  const body = b4a.alloc(42)
  body[0] = state.branchClass
  body.set(state.branchId, 1)
  body.set(state.circuitId, 17)
  writeU64(body, state.generation, 33)
  body[41] = 1
  const payload = encodeM3Object({
    messageId: M3_MESSAGE_ID.BRANCH_DESTROY_V1,
    body
  })
  const context = state.contexts[CELL_CLASS.DATAGRAM].rx
  const codec = new CellCodec({ crypto: cryptoSuite, cellSize: 1200 })
  const packet = codec.seal({
    key: context.key,
    noncePrefix: context.noncePrefix,
    senderCounter: new SenderCounter(),
    class: CELL_CLASS.DATAGRAM,
    direction: state.initiator ? DIRECTION.REVERSE : DIRECTION.FORWARD,
    epoch: state.generation,
    circuitId: state.localId,
    payload
  })
  body.fill(0)
  payload.fill(0)
  return packet
}

async function settleRelayLoss(previousChannel, nextChannel) {
  for (
    let attempt = 0;
    attempt < 20 && (previousChannel.destroys === 0 || nextChannel.destroys === 0);
    attempt++
  ) {
    await Promise.resolve()
  }
}

function contexts(initiator) {
  const values = {}
  for (const cellClass of [CELL_CLASS.CONTROL, CELL_CLASS.STREAM, CELL_CLASS.DATAGRAM]) {
    const forwardKey = b4a.alloc(32, 0x10 + cellClass)
    const reverseKey = b4a.alloc(32, 0x20 + cellClass)
    const forwardNonce = b4a.alloc(16, 0x30 + cellClass)
    const reverseNonce = b4a.alloc(16, 0x40 + cellClass)
    values[cellClass] = {
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
  return values
}

function syntheticLink(overrides = {}) {
  const initiator = overrides.initiator === undefined ? true : overrides.initiator
  const completeOfferDigest = b4a.from(overrides.completeOfferDigest || OFFER_DIGEST)
  const ids = deriveM3CellIds(completeOfferDigest, { crypto: cryptoSuite })
  const ownedChannel = overrides.channel || channel()
  const state = {
    initiator,
    completeOfferDigest,
    localId: initiator ? ids.initiatorCellId : ids.responderCellId,
    peerLocalId: initiator ? ids.responderCellId : ids.initiatorCellId,
    branchClass: overrides.branchClass === undefined ? BRANCH_CLASS.LOOKUP : overrides.branchClass,
    branchId: b4a.from(overrides.branchId || b4a.alloc(16, 0x41)),
    circuitId: b4a.from(overrides.circuitId || b4a.alloc(16, 0x42)),
    generation: overrides.generation === undefined ? 7n : overrides.generation,
    extensionIndex:
      overrides.extensionIndex === undefined ? (initiator ? 2 : 1) : overrides.extensionIndex,
    localIdentity: b4a.from(overrides.localIdentity || b4a.alloc(32, 0x51)),
    peerIdentity: b4a.from(overrides.peerIdentity || b4a.alloc(32, 0x52)),
    expiresAt: overrides.wireExpiresAt === undefined ? 10_000n : overrides.wireExpiresAt,
    contexts: contexts(initiator),
    physicalChannel: ownedChannel.value,
    clientTailEphemeralSecretKey: initiator ? b4a.alloc(32, 0x63) : null,
    tailControlTranscript: b4a.alloc(290, 0x64)
  }
  return {
    handle: guardLinks[TEST_ONLY_M3_ESTABLISHED_ISSUER].issue(state),
    channel: ownedChannel,
    state
  }
}

async function microtasks(turns = 40) {
  for (let turn = 0; turn < turns; turn++) await Promise.resolve()
}

// A datagram cell sealed the way the peer would send it: the local side's own rx
// context and cell id, with a caller-owned SenderCounter so several forged cells
// arrive as distinct in-order counters rather than as a replay of one.
function routeCell(state, counter, payload) {
  const codec = new CellCodec({ crypto: cryptoSuite, cellSize: 1200 })
  const context = state.contexts[CELL_CLASS.DATAGRAM].rx
  return codec.seal({
    key: context.key,
    noncePrefix: context.noncePrefix,
    senderCounter: counter,
    class: CELL_CLASS.DATAGRAM,
    direction: state.initiator ? DIRECTION.REVERSE : DIRECTION.FORWARD,
    epoch: state.generation,
    circuitId: state.localId,
    payload
  })
}

function branchDestroyBody(state) {
  const body = b4a.alloc(42)
  body[0] = state.branchClass
  body.set(state.branchId, 1)
  body.set(state.circuitId, 17)
  writeU64(body, state.generation, 33)
  body[41] = 1
  return encodeM3Object({ messageId: M3_MESSAGE_ID.BRANCH_DESTROY_V1, body })
}

async function routeTransportRig(overrides = {}, authorityOverrides = {}) {
  const clock = fakeClock()
  const link = syntheticLink({
    channel: relayChannel(),
    wireExpiresAt: 2_000n,
    ...overrides
  })
  const adopted = authority(clock, authorityOverrides).adopt(link.handle)
  const moved = takeM3TailCapability(adopted.tail, {
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow
  })
  const transport = takeM3RouteTransport(moved.transportOwner)
  // The pump arms its first receive on a microtask, so the channel holds no pending
  // reader until that has run.
  await microtasks(5)
  return { transport, link, clock, counter: new SenderCounter() }
}

function deferred() {
  let resolve
  let reject
  const promise = new Promise((onResolve, onReject) => {
    resolve = onResolve
    reject = onReject
  })
  return { promise, resolve, reject }
}

async function takeRouteTransport(owner, link, clock) {
  const adopted = owner.adopt(link.handle)
  const moved = takeM3TailCapability(adopted.tail, {
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow
  })
  const transport = takeM3RouteTransport(moved.transportOwner)
  await microtasks(5)
  return transport
}

async function transferPackets(source, target, cursor) {
  while (cursor.index < source.packets.length) {
    target.deliverUnread(source.packets[cursor.index++])
  }
  await microtasks()
}

test('a route transport delivers every frame that arrived while no reader was pending', async (t) => {
  const rig = await routeTransportRig()
  const first = b4a.alloc(1100, 0x5a)
  const second = b4a.alloc(1100, 0x5b)

  // Two frames of one reply, both arriving while the reader is between reservations:
  // live-route-authority's loop is inside codec.open and pushAuthenticated for the
  // fragment it just took, so it legitimately holds no waiter. Neither may be lost.
  rig.link.channel.deliverUnread(routeCell(rig.link.state, rig.counter, first))
  rig.link.channel.deliverUnread(routeCell(rig.link.state, rig.counter, second))
  await microtasks()

  t.alike(await receiveM3RouteFrame(rig.transport), first, 'the queued frame is delivered')
  t.alike(
    await receiveM3RouteFrame(rig.transport),
    second,
    'a frame behind it is delivered too: a fragmented reply loses nothing to a reader gap'
  )
})

test('a branch destroy behind an unread route frame is consumed', async (t) => {
  const rig = await routeTransportRig()

  // The measured sequence: an operation is cancelled, its in-flight reply lands with
  // no reader, and the branch dies about two milliseconds later. Before the fix that
  // one queued frame stopped the pump reading, so the destroy was never consumed and
  // the endpoint kept routing into a dead branch until its material expired.
  rig.link.channel.deliverUnread(routeCell(rig.link.state, rig.counter, b4a.alloc(1100, 0x5a)))
  await microtasks()
  t.is(
    readM3RouteTransportDiagnostics(rig.transport).received,
    1,
    'the orphaned frame is retained rather than dropped'
  )

  rig.link.channel.deliverUnread(
    routeCell(rig.link.state, rig.counter, branchDestroyBody(rig.link.state))
  )
  await microtasks()

  t.is(readM3RouteTransportDiagnostics(rig.transport), null, 'the transport is destroyed')
  t.exception(
    () => sendM3RouteFrame(rig.transport, b4a.alloc(1100, 0x01)),
    'the branch destroy queued behind an unread frame was consumed'
  )
})

test('a route transport caps residency and still consumes a destroy behind a full buffer', async (t) => {
  const rig = await routeTransportRig()
  for (let index = 0; index < MAX_FRAGMENTS; index++) {
    rig.link.channel.deliverUnread(
      routeCell(rig.link.state, rig.counter, b4a.alloc(1100, 0x60 + index))
    )
  }
  await microtasks()
  t.alike(
    readM3RouteTransportDiagnostics(rig.transport),
    {
      active: true,
      received: MAX_FRAGMENTS,
      waiters: 0,
      droppedFrames: 0,
      branchDestroyConsumed: false,
      endpointTeardown: null,
      exitTeardown: null,
      cachedTeardownAckBytes: 0,
      teardownTimer: false,
      teardownCallback: false
    },
    'residency is capped at the most route frames one reply can occupy'
  )

  rig.link.channel.deliverUnread(routeCell(rig.link.state, rig.counter, b4a.alloc(1100, 0x71)))
  await microtasks()
  t.is(
    readM3RouteTransportDiagnostics(rig.transport).droppedFrames,
    1,
    'a frame past the cap is discarded and counted rather than stopping the reader'
  )

  rig.link.channel.deliverUnread(
    routeCell(rig.link.state, rig.counter, branchDestroyBody(rig.link.state))
  )
  await microtasks()
  t.exception(
    () => sendM3RouteFrame(rig.transport, b4a.alloc(1100, 0x01)),
    'a destroy arriving behind a full buffer is still consumed'
  )
})
test('branch teardown codecs have fixed 58-byte vectors and reject malformed tuples', (t) => {
  const state = syntheticLink().state
  const teardownId = b4a.from(Array.from({ length: 16 }, (_, index) => 0xa0 + index))
  const encoded = encodeBranchTeardown(state, teardownId)
  const expected = b4a.alloc(8 + BRANCH_TEARDOWN_BODY_BYTES)
  expected.set([0, 0, 0, 1, 0, 0x27, 0, 58])
  expected[8] = state.branchClass
  expected.set(state.branchId, 9)
  expected.set(state.circuitId, 25)
  writeU64(expected, state.generation, 41)
  expected[49] = 2
  expected.set(teardownId, 50)
  t.alike(encoded, expected, 'request vector fixes header, offsets, u64 order, reason, and id')
  const ack = encodeBranchTeardown(state, teardownId, M3_MESSAGE_ID.BRANCH_TEARDOWN_ACK_V1)
  expected[5] = 0x28
  t.alike(ack, expected, 'ACK differs only by its fixed message id')
  const decoded = decodeBranchTeardown(ack, state, M3_MESSAGE_ID.BRANCH_TEARDOWN_ACK_V1)
  t.alike(decoded.body, expected.subarray(8))
  t.alike(decoded.teardownId, teardownId)
  decoded.body.fill(0)
  decoded.teardownId.fill(0)

  for (const [offset, name] of [
    [8, 'branch class'],
    [9, 'branch id'],
    [25, 'circuit id'],
    [41, 'generation'],
    [49, 'reason']
  ]) {
    const malformed = b4a.from(ack)
    malformed[offset] ^= 1
    let error = null
    try {
      decodeBranchTeardown(malformed, state, M3_MESSAGE_ID.BRANCH_TEARDOWN_ACK_V1)
    } catch (err) {
      error = err
    }
    t.is(error && error.code, 'ERR_AUTHENTICATION', `${name} fails authentication`)
    malformed.fill(0)
  }
  const truncated = ack.subarray(0, ack.byteLength - 1)
  t.is(
    decodeBranchTeardown(truncated, state, M3_MESSAGE_ID.BRANCH_TEARDOWN_ACK_V1),
    null,
    'non-exact body length is never decoded as teardown'
  )
  encoded.fill(0)
  ack.fill(0)
  expected.fill(0)
  teardownId.fill(0)
})

test('endpoint teardown retries one id, authenticates ACK, and times out fail closed', async (t) => {
  const rig = await routeTransportRig({ wireExpiresAt: 20_000n })
  const teardownId = b4a.alloc(16, 0x91)
  const pending = beginM3RouteTeardown(rig.transport, teardownId)
  await microtasks()
  t.is(rig.link.channel.packets.length, 1, 'first request is sent after operation publication')
  t.is(readM3RouteTransportDiagnostics(rig.transport).teardownTimer, true)
  rig.clock.fireNext()
  await microtasks()
  t.is(rig.link.channel.packets.length, 2, 'dropped request retries with a fresh M3 cell')

  const ack = encodeBranchTeardown(rig.link.state, teardownId, M3_MESSAGE_ID.BRANCH_TEARDOWN_ACK_V1)
  rig.link.channel.deliverUnread(routeCell(rig.link.state, rig.counter, ack))
  ack.fill(0)
  t.is(await pending, true)
  t.alike(
    {
      state: readM3RouteTransportDiagnostics(rig.transport).endpointTeardown,
      timer: readM3RouteTransportDiagnostics(rig.transport).teardownTimer
    },
    { state: 'ACKED', timer: false },
    'matching ACK settles exactly once and retires its retry timer'
  )
  const duplicate = encodeBranchTeardown(
    rig.link.state,
    teardownId,
    M3_MESSAGE_ID.BRANCH_TEARDOWN_ACK_V1
  )
  rig.link.channel.deliverUnread(routeCell(rig.link.state, rig.counter, duplicate))
  duplicate.fill(0)
  await microtasks()
  t.is(readM3RouteTransportDiagnostics(rig.transport), null, 'duplicate ACK is replay-fatal')

  const wrong = await routeTransportRig({ wireExpiresAt: 20_000n })
  const wrongPending = beginM3RouteTeardown(wrong.transport, teardownId)
  const wrongAck = encodeBranchTeardown(
    wrong.link.state,
    b4a.alloc(16, 0x92),
    M3_MESSAGE_ID.BRANCH_TEARDOWN_ACK_V1
  )
  wrong.link.channel.deliverUnread(routeCell(wrong.link.state, wrong.counter, wrongAck))
  wrongAck.fill(0)
  const wrongError = await wrongPending.then(
    () => null,
    (err) => err
  )
  t.is(wrongError.code, 'ERR_AUTHENTICATION', 'wrong teardown id closes without authority')
  t.is(readM3RouteTransportDiagnostics(wrong.transport), null)
  const wrongClass = await routeTransportRig({ wireExpiresAt: 20_000n })
  const classPending = beginM3RouteTeardown(wrongClass.transport, teardownId)
  const classAck = encodeBranchTeardown(
    wrongClass.link.state,
    teardownId,
    M3_MESSAGE_ID.BRANCH_TEARDOWN_ACK_V1
  )
  const streamContext = wrongClass.link.state.contexts[CELL_CLASS.STREAM].rx
  const streamPacket = new CellCodec({ crypto: cryptoSuite, cellSize: 1200 }).seal({
    key: streamContext.key,
    noncePrefix: streamContext.noncePrefix,
    senderCounter: new SenderCounter(),
    class: CELL_CLASS.STREAM,
    direction: DIRECTION.REVERSE,
    epoch: wrongClass.link.state.generation,
    circuitId: wrongClass.link.state.localId,
    payload: classAck
  })
  wrongClass.link.channel.deliverUnread(streamPacket)
  streamPacket.fill(0)
  classAck.fill(0)
  const classError = await classPending.then(
    () => null,
    (err) => err
  )
  t.is(classError.code, 'INVALID_ROUTE', 'fragmented or wrong-class control closes')
  t.is(readM3RouteTransportDiagnostics(wrongClass.transport), null)

  const wrongDirection = await routeTransportRig({ wireExpiresAt: 20_000n })
  const directionPending = beginM3RouteTeardown(wrongDirection.transport, teardownId)
  const directionAck = encodeBranchTeardown(
    wrongDirection.link.state,
    teardownId,
    M3_MESSAGE_ID.BRANCH_TEARDOWN_ACK_V1
  )
  const datagramContext = wrongDirection.link.state.contexts[CELL_CLASS.DATAGRAM].rx
  const directionPacket = new CellCodec({ crypto: cryptoSuite, cellSize: 1200 }).seal({
    key: datagramContext.key,
    noncePrefix: datagramContext.noncePrefix,
    senderCounter: new SenderCounter(),
    class: CELL_CLASS.DATAGRAM,
    direction: DIRECTION.FORWARD,
    epoch: wrongDirection.link.state.generation,
    circuitId: wrongDirection.link.state.localId,
    payload: directionAck
  })
  wrongDirection.link.channel.deliverUnread(directionPacket)
  directionPacket.fill(0)
  directionAck.fill(0)
  const directionError = await directionPending.then(
    () => null,
    (err) => err
  )
  t.ok(directionError, 'wrong AEAD direction closes fail closed')
  t.is(readM3RouteTransportDiagnostics(wrongDirection.transport), null)

  const timed = await routeTransportRig({ wireExpiresAt: 20_000n })
  const timedPending = beginM3RouteTeardown(timed.transport, b4a.alloc(16, 0x93))
  for (let retry = 0; retry < 10; retry++) {
    t.is(timed.clock.fireNext(), true)
    await microtasks()
  }
  const timedError = await timedPending.then(
    () => null,
    (err) => err
  )
  t.is(timedError.code, 'ERR_PRIVACY_UNAVAILABLE')
  t.is(readM3RouteTransportDiagnostics(timed.transport), null, 'timeout owns no transport')
  t.is(timed.clock.pending(), 0, 'timeout owns no retry or runtime timer')
})
test('endpoint teardown rejects synchronous retry timer fire without rearming', async (t) => {
  let synchronous = false
  const handles = new Set()
  const rig = await routeTransportRig(
    { wireExpiresAt: 20_000n },
    {
      schedule(callback) {
        if (synchronous) {
          callback()
          return Object.freeze({})
        }
        const handle = Object.freeze({})
        handles.add(handle)
        return handle
      },
      cancelScheduled(handle) {
        handles.delete(handle)
      }
    }
  )
  synchronous = true
  const pending = beginM3RouteTeardown(rig.transport, b4a.alloc(16, 0x95))
  const error = await pending.then(
    () => null,
    (err) => err
  )
  t.is(error.code, 'ERR_PRIVACY_UNAVAILABLE')
  t.is(readM3RouteTransportDiagnostics(rig.transport), null)
  t.is(handles.size, 0, 'synchronous fire leaves no runtime or retry handle')
})

test('exit teardown joins release before ACK and bounds duplicate replay state', async (t) => {
  const exitChannel = relayChannel({ holdSends: true })
  const rig = await routeTransportRig({
    initiator: false,
    wireExpiresAt: 20_000n,
    channel: exitChannel
  })
  const release = deferred()
  let cleanupCalls = 0
  registerM3RouteTeardownHandler(rig.transport, async () => {
    cleanupCalls++
    await release.promise
  })
  const teardownId = b4a.alloc(16, 0xa1)
  const request = encodeBranchTeardown(rig.link.state, teardownId)
  rig.link.channel.deliverUnread(routeCell(rig.link.state, rig.counter, request))
  request.fill(0)
  await microtasks()
  t.is(cleanupCalls, 1)
  t.is(rig.link.channel.packets.length, 0, 'ACK is not emitted before joined release')
  t.alike(
    {
      state: readM3RouteTransportDiagnostics(rig.transport).exitTeardown,
      callback: readM3RouteTransportDiagnostics(rig.transport).teardownCallback
    },
    { state: 'DRAINING', callback: false },
    'handler ownership moves before invocation'
  )
  release.resolve()
  await microtasks()
  t.is(rig.link.channel.packets.length, 1, 'ACK emits only after release resolves')
  t.is(
    readM3RouteTransportDiagnostics(rig.transport).cachedTeardownAckBytes,
    BRANCH_TEARDOWN_BODY_BYTES,
    'only one bounded ACK body is cached'
  )

  const duplicate = encodeBranchTeardown(rig.link.state, teardownId)
  rig.link.channel.deliverUnread(routeCell(rig.link.state, rig.counter, duplicate))
  duplicate.fill(0)
  await microtasks()
  t.is(cleanupCalls, 1, 'same-id duplicate cannot run cleanup twice')
  const duplicateWhileSending = encodeBranchTeardown(rig.link.state, teardownId)
  rig.link.channel.deliverUnread(routeCell(rig.link.state, rig.counter, duplicateWhileSending))
  duplicateWhileSending.fill(0)
  await microtasks()
  t.is(rig.link.channel.packets.length, 1, 'duplicate ACK sends coalesce while one is pending')
  t.is(rig.link.channel.pendingSends, 1)
  t.is(rig.link.channel.releaseSend(), true)
  await microtasks()
  t.is(rig.link.channel.packets.length, 2, 'coalesced retry emits once after pending send')
  t.is(rig.link.channel.pendingSends, 1)
  t.is(rig.link.channel.releaseSend(), true)
  await microtasks()
  t.is(rig.link.channel.packets.length, 2, 'same-id duplicate resends cached ACK')

  const replayed = encodeBranchTeardown(rig.link.state, b4a.alloc(16, 0xa2))
  rig.link.channel.deliverUnread(routeCell(rig.link.state, rig.counter, replayed))
  replayed.fill(0)
  await microtasks()
  t.is(readM3RouteTransportDiagnostics(rig.transport), null, 'different id closes fail closed')
  t.is(rig.clock.pending(), 0, 'replay clears ACK, callback, and timer ownership')
})

test('endpoint, guard, middle, and exit enforce joined reverse ACK ordering', async (t) => {
  const clock = fakeClock()
  const owner = authority(clock)
  const tuple = {
    branchId: b4a.alloc(16, 0xb1),
    circuitId: b4a.alloc(16, 0xb2),
    generation: 9n,
    wireExpiresAt: 100_000n
  }
  const endpointChannel = relayChannel()
  const guardPreviousChannel = relayChannel()
  const guardNextChannel = relayChannel()
  const middlePreviousChannel = relayChannel()
  const middleNextChannel = relayChannel()
  const exitChannel = relayChannel()
  const endpointLink = syntheticLink({
    ...tuple,
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0xc1),
    channel: endpointChannel
  })
  const guardPreviousLink = syntheticLink({
    ...tuple,
    initiator: false,
    completeOfferDigest: b4a.alloc(32, 0xc1),
    channel: guardPreviousChannel
  })
  const guardNextLink = syntheticLink({
    ...tuple,
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0xc2),
    channel: guardNextChannel
  })
  const middlePreviousLink = syntheticLink({
    ...tuple,
    initiator: false,
    completeOfferDigest: b4a.alloc(32, 0xc2),
    channel: middlePreviousChannel
  })
  const middleNextLink = syntheticLink({
    ...tuple,
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0xc3),
    channel: middleNextChannel
  })
  const exitLink = syntheticLink({
    ...tuple,
    initiator: false,
    completeOfferDigest: b4a.alloc(32, 0xc3),
    channel: exitChannel
  })
  const endpoint = await takeRouteTransport(owner, endpointLink, clock)
  const exit = await takeRouteTransport(owner, exitLink, clock)
  const guardPrevious = owner.adopt(guardPreviousLink.handle)
  const guardNext = owner.adopt(guardNextLink.handle)
  const middlePrevious = owner.adopt(middlePreviousLink.handle)
  const middleNext = owner.adopt(middleNextLink.handle)
  const trace = []
  const exitRelease = deferred()
  const middleRelease = deferred()
  const guardRelease = deferred()
  const guard = createM3RelayForwardingFacade(
    guardPrevious.runtime,
    guardNext.runtime,
    relayOptions(clock, {
      async releaseDownstream() {
        trace.push('guard')
        await guardRelease.promise
        guardNextChannel.fail(new Error('intentional guard downstream close'))
      }
    })
  )
  const middle = createM3RelayForwardingFacade(
    middlePrevious.runtime,
    middleNext.runtime,
    relayOptions(clock, {
      async releaseDownstream() {
        trace.push('middle')
        await middleRelease.promise
        middleNextChannel.fail(new Error('intentional middle downstream close'))
      }
    })
  )
  registerM3RouteTeardownHandler(exit, async () => {
    trace.push('exit')
    await exitRelease.promise
  })
  const cursors = Array.from({ length: 6 }, () => ({ index: 0 }))
  const teardownId = b4a.alloc(16, 0xd1)
  const pending = beginM3RouteTeardown(endpoint, teardownId)
  await transferPackets(endpointChannel, guardPreviousChannel, cursors[0])
  await transferPackets(guardNextChannel, middlePreviousChannel, cursors[1])
  await transferPackets(middleNextChannel, exitChannel, cursors[2])
  t.alike(trace, ['exit'])
  t.is(exitChannel.packets.length, 0, 'exit holds ACK until route/link/grant release')

  exitRelease.resolve()
  await microtasks()
  await transferPackets(exitChannel, middleNextChannel, cursors[3])
  t.alike(trace, ['exit', 'middle'])
  t.is(middlePreviousChannel.packets.length, 0, 'middle holds reverse ACK')
  t.is(clock.fireNext(), true, 'endpoint retry fires while middle release is held')
  await microtasks()
  await transferPackets(endpointChannel, guardPreviousChannel, cursors[0])
  await transferPackets(guardNextChannel, middlePreviousChannel, cursors[1])
  t.is(
    middleNextChannel.packets.length,
    1,
    'ACK-received middle suppresses retry instead of forwarding onto closing link'
  )

  middleRelease.resolve()
  await microtasks()
  t.is(middlePreviousChannel.packets.length, 1, 'first middle ACK is emitted')
  cursors[4].index = 1
  t.is(clock.fireNext(), true, 'endpoint retries after dropped middle ACK')
  await microtasks()
  await transferPackets(endpointChannel, guardPreviousChannel, cursors[0])
  await transferPackets(guardNextChannel, middlePreviousChannel, cursors[1])
  await transferPackets(middlePreviousChannel, guardNextChannel, cursors[4])
  t.is(middlePreviousChannel.packets.length, 2, 'middle cached ACK answers retry')
  t.alike(trace, ['exit', 'middle', 'guard'])
  t.is(guardPreviousChannel.packets.length, 0, 'guard holds reverse ACK')

  guardRelease.resolve()
  await microtasks()
  t.is(guardPreviousChannel.packets.length, 1, 'first guard ACK is emitted')
  cursors[5].index = 1
  t.is(clock.fireNext(), true, 'endpoint retries after dropped guard ACK')
  await microtasks()
  await transferPackets(endpointChannel, guardPreviousChannel, cursors[0])
  await transferPackets(guardPreviousChannel, endpointChannel, cursors[5])
  t.is(guardPreviousChannel.packets.length, 2, 'guard cached ACK answers retry')
  t.is(await pending, true)
  t.alike(trace, ['exit', 'middle', 'guard'], 'release order is exact and one-shot')
  destroyM3RouteTransport(endpoint)
  destroyM3RouteTransport(exit)
  guardPrevious.runtime.destroy()
  guardNext.runtime.destroy()
  middlePrevious.runtime.destroy()
  middleNext.runtime.destroy()
  guard.destroy()
  middle.destroy()
})

test('M3 authority requires separate wall, monotonic, scheduler, and canceller capabilities', (t) => {
  const clock = fakeClock()
  const owner = authority(clock)

  t.alike(owner.diagnostics(), { activeRuntimes: 0, maxRuntimes: 128 })
  t.is(clock.pending(), 0, 'construction does not arm a timer before a runtime exists')
  for (const name of ['wallNow', 'monotonicNow', 'schedule', 'cancelScheduled']) {
    t.exception(() => authority(clock, { [name]: null }), `${name} is exact and mandatory`)
  }
  t.exception(
    () => new M3AdjacencyAuthority({ now: clock.wallNow, crypto: cryptoSuite }),
    'the ambiguous single-clock option is rejected'
  )
})

test('adoption projects wire expiry once and moves one frozen actor-local deadline', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const transfer = syntheticLink({ wireExpiresAt: 1_250n })

  const adopted = owner.adopt(transfer.handle)
  t.is(clock.wallSamples, 1, 'wire expiry samples the adopting wall clock once')
  t.is(
    clock.monotonicSamples,
    2,
    'projection and publication liveness sample the monotonic clock once each'
  )
  t.alike(clock.delays, [250], 'the projected interval arms before adoption returns')
  t.is(clock.pending(), 1)

  const moved = takeM3TailCapability(adopted.tail, {
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow
  })
  t.ok(Object.isFrozen(moved.deadline))
  t.alike(Object.keys(moved.deadline).sort(), [
    'clockIdentity',
    'operationDeadline',
    'routeLocalDeadline',
    'wireExpiresAt'
  ])
  t.is(moved.deadline.wireExpiresAt, 1_250n)
  t.is(moved.deadline.routeLocalDeadline, 10_250n)
  t.is(moved.deadline.operationDeadline, 10_250n)
  t.is(moved.deadline.clockIdentity.wallNow, clock.wallNow)
  t.is(moved.deadline.clockIdentity.monotonicNow, clock.monotonicNow)
  t.is(clock.wallSamples, 1, 'moving the tail never reprojects wall expiry')
  t.is(clock.monotonicSamples, 2, 'moving the tail adds no monotonic sample')

  adopted.runtime.destroy()
  revokeM3TailCapability(adopted.tail)
})

test('anchored tail projection never reuses a shortened operation deadline', (t) => {
  const deadline = Object.freeze({
    wireExpiresAt: 20_000n,
    routeLocalDeadline: 29_000n,
    operationDeadline: 16_000n,
    clockIdentity: Object.freeze({
      wallNow() {
        throw new Error('anchored projection must not sample wall time')
      },
      monotonicNow() {
        throw new Error('anchored projection must not sample monotonic time')
      }
    })
  })

  t.is(projectM3TailWireDeadline(deadline, 4_500n), 13_500n)
  t.is(projectM3TailWireDeadline(deadline, 20_000n), 29_000n)
  t.is(
    projectM3TailWireDeadline(Object.freeze({ ...deadline, operationDeadline: 13_500n }), 4_000n),
    13_000n,
    'a sequential projection still uses the immutable route anchor'
  )
})

test('projection rejects invalid intervals, regressing clocks, and alternate identities', (t) => {
  for (const [name, clock, wireExpiresAt] of [
    ['non-positive interval', fakeClock(), 1_000n],
    ['local deadline overflow', fakeClock({ monotonic: 0xffff_ffff_ffff_ffffn }), 1_001n]
  ]) {
    const transfer = syntheticLink({ wireExpiresAt })
    t.exception(() => authority(clock).adopt(transfer.handle), name)
    t.is(transfer.channel.destroys, 1, `${name} destroys transferred state`)
    t.is(clock.pending(), 0, `${name} publishes no handle`)
  }

  const backwardWall = fakeClock()
  const wallOwner = authority(backwardWall)
  const firstWall = wallOwner.adopt(syntheticLink({ wireExpiresAt: 2_000n }).handle)
  firstWall.runtime.destroy()
  backwardWall.setWall(999n)
  const regressedWall = syntheticLink({ wireExpiresAt: 2_000n })
  t.exception(() => wallOwner.adopt(regressedWall.handle), 'backward wall time fails closed')
  t.is(regressedWall.channel.destroys, 1)

  const backwardMonotonic = fakeClock()
  const monotonicOwner = authority(backwardMonotonic)
  const firstMonotonic = monotonicOwner.adopt(syntheticLink({ wireExpiresAt: 2_000n }).handle)
  firstMonotonic.runtime.destroy()
  backwardMonotonic.setWall(1_001n)
  backwardMonotonic.setMonotonic(9_999n)
  const regressedMonotonic = syntheticLink({ wireExpiresAt: 2_000n })
  t.exception(
    () => monotonicOwner.adopt(regressedMonotonic.handle),
    'non-monotonic local time fails closed'
  )
  t.is(regressedMonotonic.channel.destroys, 1)

  for (const [name, clocks] of [
    [
      'an alternate wall clock identity is rejected',
      (clock) => ({ wallNow: () => 1_000n, monotonicNow: clock.monotonicNow })
    ],
    [
      'an alternate monotonic clock identity is rejected',
      (clock) => ({ wallNow: clock.wallNow, monotonicNow: () => 10_000n })
    ]
  ]) {
    const exactClock = fakeClock()
    const adopted = authority(exactClock).adopt(syntheticLink({ wireExpiresAt: 2_000n }).handle)
    t.exception(() => takeM3TailCapability(adopted.tail, clocks(exactClock)), name)
    t.exception(
      () =>
        takeM3TailCapability(adopted.tail, {
          wallNow: exactClock.wallNow,
          monotonicNow: exactClock.monotonicNow
        }),
      `${name} consumes the mismatched capability`
    )
    adopted.runtime.destroy()
  }

  const exactClock = fakeClock()
  const adopted = authority(exactClock).adopt(syntheticLink({ wireExpiresAt: 2_000n }).handle)
  let nestedTake = null
  const reentrantClocks = {
    get wallNow() {
      try {
        nestedTake = takeM3TailCapability(adopted.tail, {
          wallNow: exactClock.wallNow,
          monotonicNow: exactClock.monotonicNow
        })
      } catch {}
      return exactClock.wallNow
    },
    monotonicNow: exactClock.monotonicNow
  }
  t.exception(
    () => takeM3TailCapability(adopted.tail, reentrantClocks),
    'accessor-backed clocks fail closed'
  )
  t.is(nestedTake, null, 'clock accessors cannot reenter one-shot tail consumption')
  adopted.runtime.destroy()
})

test('installed pair expiry consumes forwarding owner once and cancels both handles', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const previousLink = syntheticLink({ initiator: false, wireExpiresAt: 2_000n })
  const nextLink = syntheticLink({
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0x77),
    peerIdentity: b4a.alloc(32, 0x78),
    wireExpiresAt: 2_000n
  })
  const previous = owner.adopt(previousLink.handle)
  const next = owner.adopt(nextLink.handle)
  let destroys = 0
  const forwarding = forwardingFacade(() => {
    destroys++
  })
  const plan = beginM3Install(previous.runtime, next.runtime)
  t.ok(Object.isFrozen(plan), 'the install plan is opaque and frozen')
  t.alike(Object.keys(plan), [], 'the install plan exposes no runtime records')
  validateM3Install(plan, previousLink.state.localIdentity, 128, 1_000n)
  const installed = commitM3Install(plan, 2_000n, forwarding)
  t.ok(Object.isFrozen(installed), 'the installed facade is frozen')
  t.alike(Object.keys(installed), ['diagnostics', 'destroy'])

  t.is(clock.pending(), 2, 'both actor-local handles own the installed pair')
  t.is(clock.fireNext(), true, 'the first projected expiry fires')
  t.is(destroys, 1, 'the forwarding owner is consumed once')
  t.is(clock.pending(), 0, 'the first expiry cancels the sibling handle')
  t.is(previousLink.channel.destroys, 1)
  t.is(nextLink.channel.destroys, 1)
  t.is(clock.fireNext(), false, 'the cancelled sibling callback cannot fire')
  t.is(destroys, 1, 'a cancelled sibling cannot consume the owner again')
})

test('terminal relay loss retires every installed logical pair after upstream destroy', async (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  for (let attempt = 0; attempt < 6; attempt++) {
    const previousChannel = relayChannel()
    const nextChannel = relayChannel()
    const previousLink = syntheticLink({
      initiator: false,
      completeOfferDigest: b4a.alloc(32, 0x80 + attempt * 2),
      channel: previousChannel,
      wireExpiresAt: 2_000n
    })
    const nextLink = syntheticLink({
      initiator: true,
      completeOfferDigest: b4a.alloc(32, 0x81 + attempt * 2),
      peerIdentity: b4a.alloc(32, 0x90 + attempt),
      channel: nextChannel,
      wireExpiresAt: 2_000n
    })
    const previous = owner.adopt(previousLink.handle)
    const next = owner.adopt(nextLink.handle)
    const forwarding = createM3RelayForwardingFacade(
      previous.runtime,
      next.runtime,
      relayOptions(clock)
    )
    const plan = beginM3Install(previous.runtime, next.runtime)
    validateM3Install(plan, previousLink.state.localIdentity, 128, 1_000n)
    const installed = commitM3Install(plan, 2_000n, forwarding)

    nextChannel.fail(new Error('downstream terminal loss'))
    await settleRelayLoss(previousChannel, nextChannel)

    t.is(previousChannel.packets.length, 1, `loss ${attempt} sends one upstream destroy`)
    t.is(previousChannel.destroys, 1, `loss ${attempt} releases upstream logical channel`)
    t.is(nextChannel.destroys, 1, `loss ${attempt} releases downstream logical channel`)
    t.exception(() => installed.diagnostics(), `loss ${attempt} retires the forwarding owner`)
  }
})

test('received BRANCH_DESTROY retires the installed logical pair without a cascade', async (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const previousChannel = relayChannel()
  const nextChannel = relayChannel()
  const previousLink = syntheticLink({
    initiator: false,
    completeOfferDigest: b4a.alloc(32, 0xb1),
    channel: previousChannel,
    wireExpiresAt: 2_000n
  })
  const nextLink = syntheticLink({
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0xb2),
    peerIdentity: b4a.alloc(32, 0xb3),
    channel: nextChannel,
    wireExpiresAt: 2_000n
  })
  const previous = owner.adopt(previousLink.handle)
  const next = owner.adopt(nextLink.handle)
  const forwarding = createM3RelayForwardingFacade(
    previous.runtime,
    next.runtime,
    relayOptions(clock)
  )
  const plan = beginM3Install(previous.runtime, next.runtime)
  validateM3Install(plan, previousLink.state.localIdentity, 128, 1_000n)
  const installed = commitM3Install(plan, 2_000n, forwarding)
  const packet = branchDestroyPacket(nextLink.state)

  nextChannel.deliver(packet)
  packet.fill(0)
  await settleRelayLoss(previousChannel, nextChannel)

  t.is(previousChannel.packets.length, 1, 'received destroy is forwarded upstream once')
  t.is(nextChannel.packets.length, 0, 'logical cleanup emits no downstream cascade')
  t.is(previousChannel.destroys, 1)
  t.is(nextChannel.destroys, 1)
  t.exception(() => installed.diagnostics(), 'received destroy retires forwarding owner')
})

test('received BRANCH_DESTROY rejection still retires the installed logical pair', async (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const previousChannel = relayChannel()
  const nextChannel = relayChannel()
  const previousLink = syntheticLink({
    initiator: false,
    completeOfferDigest: b4a.alloc(32, 0xc1),
    channel: previousChannel,
    wireExpiresAt: 2_000n
  })
  const nextLink = syntheticLink({
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0xc2),
    peerIdentity: b4a.alloc(32, 0xc3),
    channel: nextChannel,
    wireExpiresAt: 2_000n
  })
  const previous = owner.adopt(previousLink.handle)
  const next = owner.adopt(nextLink.handle)
  const forwarding = createM3RelayForwardingFacade(
    previous.runtime,
    next.runtime,
    relayOptions(clock)
  )
  const plan = beginM3Install(previous.runtime, next.runtime)
  validateM3Install(plan, previousLink.state.localIdentity, 128, 1_000n)
  const installed = commitM3Install(plan, 2_000n, forwarding)
  const packet = branchDestroyPacket(nextLink.state)
  previousChannel.failSend(new Error('upstream destroy propagation rejected'))

  nextChannel.deliver(packet)
  packet.fill(0)
  await settleRelayLoss(previousChannel, nextChannel)

  t.is(previousChannel.packets.length, 1, 'propagation is attempted exactly once')
  t.is(nextChannel.packets.length, 0, 'failed propagation emits no cascade')
  t.is(previousChannel.destroys, 1)
  t.is(nextChannel.destroys, 1)
  t.exception(() => installed.diagnostics(), 'rejected propagation retires forwarding owner')
})

test('forwarding publication claim and lease require object-identical synchronous take', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const previousLink = syntheticLink({ initiator: false, wireExpiresAt: 2_000n })
  const nextLink = syntheticLink({
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0x7b),
    peerIdentity: b4a.alloc(32, 0x7c),
    wireExpiresAt: 2_000n
  })
  const previous = owner.adopt(previousLink.handle)
  const next = owner.adopt(nextLink.handle)
  const previousTail = takeM3TailCapability(previous.tail, {
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow
  })
  let forwardingDestroys = 0
  let lifetimeDestroys = 0
  const forwarding = forwardingFacade(() => {
    forwardingDestroys++
  })
  const plan = beginM3Install(previous.runtime, next.runtime)
  validateM3Install(plan, previousLink.state.localIdentity, 128, 1_000n)
  const publicationClaim = createM3ForwardingPublicationClaim(plan, forwarding)
  t.ok(Object.isFrozen(publicationClaim), 'publication claim is opaque and frozen')
  t.alike(Object.keys(publicationClaim), [], 'publication claim exposes no state')
  t.exception(
    () =>
      createM3TailForwardingLease(
        previousTail.transportOwner,
        Object.freeze({}),
        () => {},
        publicationClaim
      ),
    'foreign lifetime cannot lease the forwarding claim'
  )
  const originalDeadline = previousTail.deadline
  const shortenedDeadline = shortenM3TailOperationDeadline(
    previousTail,
    previousTail.deadline.operationDeadline - 1n
  )
  t.is(shortenedDeadline, previousTail.deadline, 'shortening refreshes the exact lease snapshot')
  t.not(shortenedDeadline, originalDeadline)
  t.is(shortenedDeadline.wireExpiresAt, originalDeadline.wireExpiresAt)
  t.is(shortenedDeadline.routeLocalDeadline, originalDeadline.routeLocalDeadline)
  t.is(shortenedDeadline.operationDeadline, originalDeadline.operationDeadline - 1n)
  t.is(shortenedDeadline.clockIdentity, originalDeadline.clockIdentity)
  const m3ForwardingLease = createM3TailForwardingLease(
    previousTail.transportOwner,
    previousTail.deadline,
    () => {
      lifetimeDestroys++
    },
    publicationClaim
  )
  t.ok(Object.isFrozen(m3ForwardingLease), 'forwarding lease is opaque and frozen')
  t.alike(Object.keys(m3ForwardingLease), [], 'forwarding lease exposes no state')
  const publication = publishM3TailForwarding(publicationClaim, m3ForwardingLease, forwarding)
  t.alike(
    clock.delays,
    [1_000, 1_000],
    'operation shortening does not cap physical forwarding lifetime'
  )
  const taken = takeM3TailForwardingPublication(publication, m3ForwardingLease, publicationClaim)
  t.alike(Object.keys(taken), [
    'm3ForwardingOwner',
    'm3ForwardingLease',
    'publicationClaim',
    'forwarding'
  ])
  t.ok(
    Object.isFrozen(taken.m3ForwardingOwner),
    'taken publication carries an opaque forwarding owner'
  )
  t.is(taken.m3ForwardingLease, m3ForwardingLease)
  t.is(taken.publicationClaim, publicationClaim)
  t.is(typeof taken.forwarding.destroy, 'function')
  t.is(
    destroyM3TailForwardingPublication(publication),
    false,
    'publication handle is consumed by take'
  )
  t.is(
    destroyM3TailForwardingPublication(taken),
    true,
    'taken publication destroys forwarding owner'
  )
  t.is(lifetimeDestroys, 1, 'publication destroy spends forwarding lease lifetime once')
  t.is(forwardingDestroys, 1, 'publication destroy spends forwarding facade once')
  t.is(previousLink.channel.destroys, 1)
  t.is(nextLink.channel.destroys, 1)
})

test('aborting a leased forwarding claim spends the lease owner once', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const previousLink = syntheticLink({ initiator: false, wireExpiresAt: 2_000n })
  const nextLink = syntheticLink({
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0x8f),
    peerIdentity: b4a.alloc(32, 0x90),
    wireExpiresAt: 2_000n
  })
  const previous = owner.adopt(previousLink.handle)
  const next = owner.adopt(nextLink.handle)
  const previousTail = takeM3TailCapability(previous.tail, {
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow
  })
  let forwardingDestroys = 0
  let lifetimeDestroys = 0
  const forwarding = forwardingFacade(() => {
    forwardingDestroys++
  })
  const plan = beginM3Install(previous.runtime, next.runtime)
  validateM3Install(plan, previousLink.state.localIdentity, 128, 1_000n)
  const publicationClaim = createM3ForwardingPublicationClaim(plan, forwarding)
  const m3ForwardingLease = createM3TailForwardingLease(
    previousTail.transportOwner,
    previousTail.deadline,
    () => {
      lifetimeDestroys++
    },
    publicationClaim
  )

  t.is(abortM3Install(plan), true)
  t.is(revokeM3TailForwardingLease(m3ForwardingLease), false)
  t.is(lifetimeDestroys, 1, 'abort spends the forwarding lease owner')
  t.is(forwardingDestroys, 1, 'abort destroys the staged forwarding facade')
  previous.runtime.destroy()
  next.runtime.destroy()
})

test('staged forwarding destroy uses the validated descriptor value', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const previousLink = syntheticLink({ initiator: false, wireExpiresAt: 2_000n })
  const nextLink = syntheticLink({
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0x91),
    peerIdentity: b4a.alloc(32, 0x92),
    wireExpiresAt: 2_000n
  })
  const previous = owner.adopt(previousLink.handle)
  const next = owner.adopt(nextLink.handle)
  let destroys = 0
  const target = forwardingFacade(() => {
    destroys++
  })
  const forwarding = new Proxy(target, {
    get(value, property, receiver) {
      if (property === 'destroy') throw new Error('destroy getter trap')
      return Reflect.get(value, property, receiver)
    }
  })
  const plan = beginM3Install(previous.runtime, next.runtime)
  validateM3Install(plan, previousLink.state.localIdentity, 128, 1_000n)
  createM3ForwardingPublicationClaim(plan, forwarding)

  t.is(abortM3Install(plan), true)
  t.is(destroys, 1, 'abort invokes the accepted data descriptor destroy')
  previous.runtime.destroy()
  next.runtime.destroy()
})

test('publishing forwarding uses the staged descriptor without re-reflection', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const previousLink = syntheticLink({ initiator: false, wireExpiresAt: 2_000n })
  const nextLink = syntheticLink({
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0x95),
    peerIdentity: b4a.alloc(32, 0x96),
    wireExpiresAt: 2_000n
  })
  const previous = owner.adopt(previousLink.handle)
  const next = owner.adopt(nextLink.handle)
  const previousTail = takeM3TailCapability(previous.tail, {
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow
  })
  let publishing = false
  let forwardingDestroys = 0
  const target = forwardingFacade(() => {
    forwardingDestroys++
  })
  const forwarding = new Proxy(target, {
    getOwnPropertyDescriptor(value, property) {
      if (publishing && (property === 'diagnostics' || property === 'destroy')) {
        throw new Error('descriptor reflection repeated during publish')
      }
      return Reflect.getOwnPropertyDescriptor(value, property)
    }
  })
  const plan = beginM3Install(previous.runtime, next.runtime)
  validateM3Install(plan, previousLink.state.localIdentity, 128, 1_000n)
  const publicationClaim = createM3ForwardingPublicationClaim(plan, forwarding)
  const m3ForwardingLease = createM3TailForwardingLease(
    previousTail.transportOwner,
    previousTail.deadline,
    () => {},
    publicationClaim
  )

  publishing = true
  const publication = publishM3TailForwarding(publicationClaim, m3ForwardingLease, forwarding)
  const taken = takeM3TailForwardingPublication(publication, m3ForwardingLease, publicationClaim)
  t.is(destroyM3TailForwardingPublication(taken), true)
  t.is(forwardingDestroys, 1)
})

test('taken forwarding publication tombstones before lease reentry', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const previousLink = syntheticLink({ initiator: false, wireExpiresAt: 2_000n })
  const nextLink = syntheticLink({
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0x93),
    peerIdentity: b4a.alloc(32, 0x94),
    wireExpiresAt: 2_000n
  })
  const previous = owner.adopt(previousLink.handle)
  const next = owner.adopt(nextLink.handle)
  const previousTail = takeM3TailCapability(previous.tail, {
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow
  })
  let taken = null
  let nestedDestroy = null
  let lifetimeDestroys = 0
  let forwardingDestroys = 0
  const forwarding = forwardingFacade(() => {
    forwardingDestroys++
  })
  const plan = beginM3Install(previous.runtime, next.runtime)
  validateM3Install(plan, previousLink.state.localIdentity, 128, 1_000n)
  const publicationClaim = createM3ForwardingPublicationClaim(plan, forwarding)
  const m3ForwardingLease = createM3TailForwardingLease(
    previousTail.transportOwner,
    previousTail.deadline,
    () => {
      lifetimeDestroys++
      nestedDestroy = destroyM3TailForwardingPublication(taken)
    },
    publicationClaim
  )
  const publication = publishM3TailForwarding(publicationClaim, m3ForwardingLease, forwarding)
  taken = takeM3TailForwardingPublication(publication, m3ForwardingLease, publicationClaim)

  t.is(destroyM3TailForwardingPublication(taken), true)
  t.is(nestedDestroy, false, 'lease cleanup reentry observes a tombstoned receipt')
  t.is(lifetimeDestroys, 1)
  t.is(forwardingDestroys, 1)
})

test('taken forwarding publication retires owner before lease callback reentry', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const previousLink = syntheticLink({ initiator: false, wireExpiresAt: 2_000n })
  const nextLink = syntheticLink({
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0x97),
    peerIdentity: b4a.alloc(32, 0x98),
    wireExpiresAt: 2_000n
  })
  const previous = owner.adopt(previousLink.handle)
  const next = owner.adopt(nextLink.handle)
  const previousTail = takeM3TailCapability(previous.tail, {
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow
  })
  let taken = null
  let nestedForwardingDestroy = null
  let lifetimeDestroys = 0
  let forwardingDestroys = 0
  const forwarding = forwardingFacade(() => {
    forwardingDestroys++
  })
  const plan = beginM3Install(previous.runtime, next.runtime)
  validateM3Install(plan, previousLink.state.localIdentity, 128, 1_000n)
  const publicationClaim = createM3ForwardingPublicationClaim(plan, forwarding)
  const m3ForwardingLease = createM3TailForwardingLease(
    previousTail.transportOwner,
    previousTail.deadline,
    () => {
      lifetimeDestroys++
      nestedForwardingDestroy = taken.forwarding.destroy()
    },
    publicationClaim
  )
  const publication = publishM3TailForwarding(publicationClaim, m3ForwardingLease, forwarding)
  taken = takeM3TailForwardingPublication(publication, m3ForwardingLease, publicationClaim)

  t.is(destroyM3TailForwardingPublication(taken), true)
  t.is(nestedForwardingDestroy, false, 'lease callback sees a retired forwarding owner')
  t.is(lifetimeDestroys, 1)
  t.is(forwardingDestroys, 1)
})

test('forwarding publication expires with its installed owner before receipt take', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const previousLink = syntheticLink({ initiator: false, wireExpiresAt: 2_000n })
  const nextLink = syntheticLink({
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0x81),
    peerIdentity: b4a.alloc(32, 0x82),
    wireExpiresAt: 2_000n
  })
  const previous = owner.adopt(previousLink.handle)
  const next = owner.adopt(nextLink.handle)
  const previousTail = takeM3TailCapability(previous.tail, {
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow
  })
  let forwardingDestroys = 0
  let lifetimeDestroys = 0
  const forwarding = forwardingFacade(() => {
    forwardingDestroys++
  })
  const plan = beginM3Install(previous.runtime, next.runtime)
  validateM3Install(plan, previousLink.state.localIdentity, 128, 1_000n)
  const publicationClaim = createM3ForwardingPublicationClaim(plan, forwarding)
  const m3ForwardingLease = createM3TailForwardingLease(
    previousTail.transportOwner,
    previousTail.deadline,
    () => {
      lifetimeDestroys++
    },
    publicationClaim
  )
  const publication = publishM3TailForwarding(publicationClaim, m3ForwardingLease, forwarding)

  t.is(clock.fireNext(), true, 'runtime expiry reaches the forwarding owner')
  t.is(lifetimeDestroys, 1, 'owner expiry spends the forwarding lease owner')
  t.is(forwardingDestroys, 1, 'owner expiry destroys the forwarding facade')
  t.exception(
    () => takeM3TailForwardingPublication(publication, m3ForwardingLease, publicationClaim),
    'expired publication cannot be consumed'
  )
  t.is(destroyM3TailForwardingPublication(publication), false)
})

test('publish closes claim and lease before clock reentry can revoke them', (t) => {
  const baseClock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  let onWall = null
  const runtimeClock = {
    wallNow() {
      if (onWall) onWall()
      return baseClock.wallNow()
    },
    monotonicNow: baseClock.monotonicNow,
    schedule: baseClock.schedule,
    cancelScheduled: baseClock.cancelScheduled
  }
  const owner = authority(runtimeClock)
  const previousLink = syntheticLink({ initiator: false, wireExpiresAt: 2_000n })
  const nextLink = syntheticLink({
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0x86),
    peerIdentity: b4a.alloc(32, 0x87),
    wireExpiresAt: 2_000n
  })
  const previous = owner.adopt(previousLink.handle)
  const next = owner.adopt(nextLink.handle)
  const previousTail = takeM3TailCapability(previous.tail, {
    wallNow: runtimeClock.wallNow,
    monotonicNow: runtimeClock.monotonicNow
  })
  let forwardingDestroys = 0
  let lifetimeDestroys = 0
  let revoked = null
  const forwarding = forwardingFacade(() => {
    forwardingDestroys++
  })
  const plan = beginM3Install(previous.runtime, next.runtime)
  validateM3Install(plan, previousLink.state.localIdentity, 128, 1_000n)
  const publicationClaim = createM3ForwardingPublicationClaim(plan, forwarding)
  const m3ForwardingLease = createM3TailForwardingLease(
    previousTail.transportOwner,
    previousTail.deadline,
    () => {
      lifetimeDestroys++
    },
    publicationClaim
  )
  onWall = () => {
    onWall = null
    revoked = revokeM3TailForwardingLease(m3ForwardingLease)
  }
  const publication = publishM3TailForwarding(publicationClaim, m3ForwardingLease, forwarding)

  t.is(revoked, false, 'publish phase makes the forwarding lease non-revocable before callbacks')
  t.is(forwardingDestroys, 0)
  t.is(lifetimeDestroys, 0)
  t.is(destroyM3TailForwardingPublication(publication), true)
  t.is(forwardingDestroys, 1)
  t.is(lifetimeDestroys, 1)
})

test('forwarding claim creation rejects facade reflection reentry', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const previousLink = syntheticLink({ initiator: false, wireExpiresAt: 2_000n })
  const nextLink = syntheticLink({
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0x8b),
    peerIdentity: b4a.alloc(32, 0x8c),
    wireExpiresAt: 2_000n
  })
  const previous = owner.adopt(previousLink.handle)
  const next = owner.adopt(nextLink.handle)
  const plan = beginM3Install(previous.runtime, next.runtime)
  validateM3Install(plan, previousLink.state.localIdentity, 128, 1_000n)

  let reentered = false
  let reentryClaim = null
  let reentryError = null
  const target = forwardingFacade()
  const reflected = new Proxy(target, {
    ownKeys(value) {
      if (!reentered) {
        reentered = true
        try {
          reentryClaim = createM3ForwardingPublicationClaim(plan, forwardingFacade())
        } catch (err) {
          reentryError = err
        }
      }
      return Reflect.ownKeys(value)
    }
  })

  t.exception(
    () => createM3ForwardingPublicationClaim(plan, reflected),
    'facade reflection cannot reenter claim creation'
  )
  t.is(reentryClaim, null, 'reentrant claim is never published')
  t.ok(reentryError, 'reentrant creation attempt is rejected')
  t.is(abortM3Install(plan), true)
  previous.runtime.destroy()
  next.runtime.destroy()
})

test('aborting a claimed forwarding install rejects destroy reentry claims', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const previousLink = syntheticLink({ initiator: false, wireExpiresAt: 2_000n })
  const nextLink = syntheticLink({
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0x8d),
    peerIdentity: b4a.alloc(32, 0x8e),
    wireExpiresAt: 2_000n
  })
  const previous = owner.adopt(previousLink.handle)
  const next = owner.adopt(nextLink.handle)
  const plan = beginM3Install(previous.runtime, next.runtime)
  validateM3Install(plan, previousLink.state.localIdentity, 128, 1_000n)

  let reentryClaim = null
  let reentryError = null
  let destroys = 0
  const forwarding = forwardingFacade(() => {
    destroys++
    try {
      reentryClaim = createM3ForwardingPublicationClaim(plan, forwardingFacade())
    } catch (err) {
      reentryError = err
    }
  })
  createM3ForwardingPublicationClaim(plan, forwarding)

  t.is(abortM3Install(plan), true)
  t.is(destroys, 1, 'abort destroys the original staged forwarding facade once')
  t.is(reentryClaim, null, 'destroy reentry cannot claim the aborting install plan')
  t.ok(reentryError, 'destroy reentry observes a rejected install plan')
  previous.runtime.destroy()
  next.runtime.destroy()
})

test('revoking unpublished forwarding lease aborts install and destroys staged owners', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const previousLink = syntheticLink({ initiator: false, wireExpiresAt: 2_000n })
  const nextLink = syntheticLink({
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0x7d),
    peerIdentity: b4a.alloc(32, 0x7e),
    wireExpiresAt: 2_000n
  })
  const previous = owner.adopt(previousLink.handle)
  const next = owner.adopt(nextLink.handle)
  const previousTail = takeM3TailCapability(previous.tail, {
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow
  })
  let forwardingDestroys = 0
  let lifetimeDestroys = 0
  const forwarding = forwardingFacade(() => {
    forwardingDestroys++
  })
  const plan = beginM3Install(previous.runtime, next.runtime)
  validateM3Install(plan, previousLink.state.localIdentity, 128, 1_000n)
  const publicationClaim = createM3ForwardingPublicationClaim(plan, forwarding)
  const m3ForwardingLease = createM3TailForwardingLease(
    previousTail.transportOwner,
    previousTail.deadline,
    () => {
      lifetimeDestroys++
    },
    publicationClaim
  )

  t.is(revokeM3TailForwardingLease(m3ForwardingLease), true)
  t.is(revokeM3TailForwardingLease(m3ForwardingLease), false)
  t.is(lifetimeDestroys, 1, 'lease revocation spends forwarding lifetime once')
  t.is(forwardingDestroys, 1, 'lease revocation destroys unpublished facade once')
  previous.runtime.destroy()
  next.runtime.destroy()
})

test('aborting a claimed forwarding install destroys the staged facade once', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const previousLink = syntheticLink({ initiator: false, wireExpiresAt: 2_000n })
  const nextLink = syntheticLink({
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0x7f),
    peerIdentity: b4a.alloc(32, 0x80),
    wireExpiresAt: 2_000n
  })
  const previous = owner.adopt(previousLink.handle)
  const next = owner.adopt(nextLink.handle)
  let forwardingDestroys = 0
  const forwarding = forwardingFacade(() => {
    forwardingDestroys++
  })
  const plan = beginM3Install(previous.runtime, next.runtime)
  validateM3Install(plan, previousLink.state.localIdentity, 128, 1_000n)
  createM3ForwardingPublicationClaim(plan, forwarding)
  t.exception(
    () => createM3ForwardingPublicationClaim(plan, forwardingFacade()),
    'one claim per install plan'
  )
  const legacyPreviousLink = syntheticLink({
    initiator: false,
    completeOfferDigest: b4a.alloc(32, 0x88),
    peerIdentity: b4a.alloc(32, 0x89),
    wireExpiresAt: 2_000n
  })
  const legacyNextLink = syntheticLink({
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0x88),
    peerIdentity: b4a.alloc(32, 0x8a),
    wireExpiresAt: 2_000n
  })
  const legacyPrevious = owner.adopt(legacyPreviousLink.handle)
  const legacyNext = owner.adopt(legacyNextLink.handle)
  const legacyPlan = beginM3Install(legacyPrevious.runtime, legacyNext.runtime)
  validateM3Install(legacyPlan, legacyPreviousLink.state.localIdentity, 128, 1_000n)
  t.exception(
    () => commitM3Install(legacyPlan, 2_000n, forwarding),
    'legacy commit cannot take a facade staged for publication'
  )
  t.is(forwardingDestroys, 0, 'legacy commit rejection does not spend the staged facade')
  t.is(abortM3Install(plan), true)
  t.is(abortM3Install(plan), false)
  t.is(forwardingDestroys, 1, 'abort destroys the staged forwarding facade once')
  const retryPreviousLink = syntheticLink({
    initiator: false,
    completeOfferDigest: b4a.alloc(32, 0x83),
    peerIdentity: b4a.alloc(32, 0x84),
    wireExpiresAt: 2_000n
  })
  const retryNextLink = syntheticLink({
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0x83),
    peerIdentity: b4a.alloc(32, 0x85),
    wireExpiresAt: 2_000n
  })
  const retryPrevious = owner.adopt(retryPreviousLink.handle)
  const retryNext = owner.adopt(retryNextLink.handle)
  const retryPlan = beginM3Install(retryPrevious.runtime, retryNext.runtime)
  validateM3Install(retryPlan, retryPreviousLink.state.localIdentity, 128, 1_000n)
  t.exception(
    () => createM3ForwardingPublicationClaim(retryPlan, forwarding),
    'destroyed staged forwarding facade cannot be reused'
  )
  t.is(abortM3Install(retryPlan), true)
  retryPrevious.runtime.destroy()
  retryNext.runtime.destroy()
  previous.runtime.destroy()
  next.runtime.destroy()
})

test('M3 authority rejects extra and accessor-backed capabilities before retention', (t) => {
  const clock = fakeClock()
  const options = {
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled,
    crypto: cryptoSuite
  }

  t.exception(
    () => new M3AdjacencyAuthority({ ...options, extra: true }),
    'extra capabilities are rejected'
  )

  let reads = 0
  const accessorOptions = {
    monotonicNow: clock.monotonicNow,
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled,
    crypto: cryptoSuite
  }
  Object.defineProperty(accessorOptions, 'wallNow', {
    enumerable: true,
    get() {
      reads++
      return clock.wallNow
    }
  })
  t.exception(
    () => new M3AdjacencyAuthority(accessorOptions),
    'accessor-backed capabilities are rejected'
  )
  t.is(reads, 0, 'the rejected accessor is never invoked')
})

test('adoption fails closed when timer publication cannot complete', (t) => {
  for (const mode of ['throw', 'missing', 'synchronous', 'reentrant-cancel']) {
    const clock = fakeClock()
    const transfer = syntheticLink({ wireExpiresAt: 2_000n })
    const secret = transfer.state.clientTailEphemeralSecretKey
    const transcript = transfer.state.tailControlTranscript
    let callback = null
    const overrides = {
      schedule(onExpiry) {
        callback = onExpiry
        if (mode === 'throw') throw new Error('injected schedule failure')
        if (mode === 'missing') return null
        if (mode === 'synchronous' || mode === 'reentrant-cancel') onExpiry()
        return 1
      },
      cancelScheduled() {
        if (mode === 'reentrant-cancel') callback()
      }
    }

    t.exception(() => authority(clock, overrides).adopt(transfer.handle), mode)
    t.is(transfer.channel.destroys, 1, `${mode} destroys unpublished state`)
    t.ok(b4a.equals(secret, b4a.alloc(secret.byteLength)), `${mode} clears the tail secret`)
    t.ok(
      b4a.equals(transcript, b4a.alloc(transcript.byteLength)),
      `${mode} clears the tail transcript`
    )
  }
})

test('a proactive actor-local expiry destroys an unpublished runtime and tail', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const transfer = syntheticLink({ wireExpiresAt: 1_250n })
  const adopted = authority(clock).adopt(transfer.handle)

  t.is(clock.pending(), 1)
  t.is(clock.fireNext(), true)
  t.is(clock.pending(), 0)
  t.is(transfer.channel.destroys, 1)
  t.is(adopted.runtime.destroy(), false, 'the expired runtime is already destroyed')
  t.is(revokeM3TailCapability(adopted.tail), false, 'expiry revokes the paired tail')
})

test('committing a shorter authenticated expiry rearms both installed runtimes', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const previousLink = syntheticLink({ initiator: false, wireExpiresAt: 2_000n })
  const nextLink = syntheticLink({
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0x79),
    peerIdentity: b4a.alloc(32, 0x7a),
    wireExpiresAt: 2_000n
  })
  const previous = owner.adopt(previousLink.handle)
  const next = owner.adopt(nextLink.handle)
  const forwarding = forwardingFacade()
  const plan = beginM3Install(previous.runtime, next.runtime)
  validateM3Install(plan, previousLink.state.localIdentity, 128, 1_000n)
  const installed = commitM3Install(plan, 1_500n, forwarding)

  t.alike(clock.delays, [1_000, 1_000, 500, 500], 'the shorter bound rearms both handles')
  t.is(clock.pending(), 2)
  t.is(clock.fireNext(), true)
  t.is(clock.pending(), 0)
  t.is(previousLink.channel.destroys, 1)
  t.is(nextLink.channel.destroys, 1)
})

test('long projected expiries are armed in platform-safe chunks', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const interval = BigInt(MAX_TIMER_DELAY) + 10n
  const transfer = syntheticLink({ wireExpiresAt: 1_000n + interval })
  const adopted = authority(clock).adopt(transfer.handle)

  t.alike(clock.delays, [MAX_TIMER_DELAY])
  t.is(clock.fireNext(), true)
  t.is(transfer.channel.destroys, 0, 'the first chunk does not expire early')
  t.alike(clock.delays, [MAX_TIMER_DELAY, 10])
  t.is(clock.pending(), 1)
  t.is(clock.fireNext(), true)
  t.is(transfer.channel.destroys, 1)
  t.is(adopted.runtime.destroy(), false)

  const hugeClock = fakeClock({ wall: 0n, monotonic: 0n })
  const hugeInterval = BigInt(Number.MAX_SAFE_INTEGER) + 1n
  const hugeTransfer = syntheticLink({ wireExpiresAt: hugeInterval })
  const huge = authority(hugeClock).adopt(hugeTransfer.handle)
  t.is(hugeClock.delays[0], MAX_TIMER_DELAY, 'u64-safe intervals above MAX_SAFE are chunked')
  huge.runtime.destroy()
  revokeM3TailCapability(huge.tail)
})

test('install rejects later, invalid, and already-consumed forwarding bounds', (t) => {
  const forwarding = forwardingFacade()
  const cases = [
    ['later wire expiry', 2_001n],
    ['zero wire expiry', 0n],
    ['non-integer wire expiry', 1_500]
  ]

  for (let index = 0; index < cases.length; index++) {
    const [name, expiresAt] = cases[index]
    const clock = fakeClock()
    const owner = authority(clock)
    const previousLink = syntheticLink({
      initiator: false,
      completeOfferDigest: b4a.alloc(32, 0x80 + index * 2),
      peerIdentity: b4a.alloc(32, 0x90 + index * 2),
      wireExpiresAt: 2_000n
    })
    const nextLink = syntheticLink({
      initiator: true,
      completeOfferDigest: b4a.alloc(32, 0x81 + index * 2),
      peerIdentity: b4a.alloc(32, 0x91 + index * 2),
      wireExpiresAt: 2_000n
    })
    const previous = owner.adopt(previousLink.handle)
    const next = owner.adopt(nextLink.handle)
    const plan = beginM3Install(previous.runtime, next.runtime)
    validateM3Install(plan, previousLink.state.localIdentity, 128, 1_000n)

    t.exception(() => commitM3Install(plan, expiresAt, forwarding), name)
    abortM3Install(plan)
    previous.runtime.destroy()
    next.runtime.destroy()
  }

  const clock = fakeClock()
  const owner = authority(clock)
  const firstPreviousLink = syntheticLink({ initiator: false, wireExpiresAt: 2_000n })
  const firstNextLink = syntheticLink({
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0xa0),
    peerIdentity: b4a.alloc(32, 0xa1),
    wireExpiresAt: 2_000n
  })
  const firstPrevious = owner.adopt(firstPreviousLink.handle)
  const firstNext = owner.adopt(firstNextLink.handle)
  let destroys = 0
  const consumedForwarding = forwardingFacade(() => {
    destroys++
  })
  const firstPlan = beginM3Install(firstPrevious.runtime, firstNext.runtime)
  validateM3Install(firstPlan, firstPreviousLink.state.localIdentity, 128, 1_000n)
  commitM3Install(firstPlan, 2_000n, consumedForwarding)
  clock.fireNext()
  t.is(destroys, 1)

  const secondPreviousLink = syntheticLink({
    initiator: false,
    completeOfferDigest: b4a.alloc(32, 0xa2),
    peerIdentity: b4a.alloc(32, 0xa3),
    wireExpiresAt: 2_000n
  })
  const secondNextLink = syntheticLink({
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0xa4),
    peerIdentity: b4a.alloc(32, 0xa5),
    wireExpiresAt: 2_000n
  })
  const secondPrevious = owner.adopt(secondPreviousLink.handle)
  const secondNext = owner.adopt(secondNextLink.handle)
  const secondPlan = beginM3Install(secondPrevious.runtime, secondNext.runtime)
  validateM3Install(secondPlan, secondPreviousLink.state.localIdentity, 128, 1_000n)
  let reused = null
  try {
    reused = commitM3Install(secondPlan, 2_000n, consumedForwarding)
  } catch {}
  t.is(reused, null, 'a consumed forwarding owner cannot install another pair')
  if (reused) reused.destroy()
  else {
    abortM3Install(secondPlan)
    secondPrevious.runtime.destroy()
    secondNext.runtime.destroy()
  }
})

test('install reserves plan and forwarding ownership before reentrant clocks', (t) => {
  const clock = fakeClock()
  let reenter = null
  const wallNow = () => {
    if (reenter) {
      const callback = reenter
      reenter = null
      callback()
    }
    return clock.wallNow()
  }
  const owner = new M3AdjacencyAuthority({
    wallNow,
    monotonicNow: clock.monotonicNow,
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled,
    crypto: cryptoSuite
  })
  const links = [0xb0, 0xb4].map((base) => {
    const previousLink = syntheticLink({
      initiator: false,
      completeOfferDigest: b4a.alloc(32, base),
      peerIdentity: b4a.alloc(32, base + 1)
    })
    const nextLink = syntheticLink({
      initiator: true,
      completeOfferDigest: b4a.alloc(32, base + 2),
      peerIdentity: b4a.alloc(32, base + 3)
    })
    const previous = owner.adopt(previousLink.handle)
    const next = owner.adopt(nextLink.handle)
    const plan = beginM3Install(previous.runtime, next.runtime)
    validateM3Install(plan, previousLink.state.localIdentity, 128, 1_000n)
    return { previousLink, nextLink, previous, next, plan }
  })
  const forwarding = forwardingFacade()
  let nested = null
  reenter = () => {
    try {
      nested = commitM3Install(links[1].plan, 2_000n, forwarding)
    } catch {}
  }
  const installed = commitM3Install(links[0].plan, 2_000n, forwarding)

  t.is(nested, null, 'a reentrant clock cannot install the same forwarding facade twice')
  installed.destroy()
  abortM3Install(links[1].plan)
  links[1].previous.runtime.destroy()
  links[1].next.runtime.destroy()
})

test('throwing forwarding teardown cannot retain an expired installed pair', (t) => {
  const clock = fakeClock()
  const owner = authority(clock)
  const previousLink = syntheticLink({ initiator: false })
  const nextLink = syntheticLink({
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0xc0),
    peerIdentity: b4a.alloc(32, 0xc1)
  })
  const previous = owner.adopt(previousLink.handle)
  const next = owner.adopt(nextLink.handle)
  const plan = beginM3Install(previous.runtime, next.runtime)
  validateM3Install(plan, previousLink.state.localIdentity, 128, 1_000n)
  commitM3Install(
    plan,
    2_000n,
    forwardingFacade(() => {
      throw new Error('teardown failure')
    })
  )

  t.is(clock.fireNext(), true)
  t.is(clock.pending(), 0)
  t.is(previousLink.channel.destroys, 1)
  t.is(nextLink.channel.destroys, 1)
})

test('initiator adoption publishes no responder token', (t) => {
  const clock = fakeClock()
  const adopted = authority(clock).adopt(syntheticLink({ initiator: true }).handle)

  t.alike(Object.keys(adopted).sort(), ['runtime', 'tail'])
  t.absent(adopted.responderToken)
  adopted.runtime.destroy()
  revokeM3TailCapability(adopted.tail)
})

test('responder adoption publishes one opaque frozen token', (t) => {
  const clock = fakeClock()
  const adopted = authority(clock).adopt(syntheticLink({ initiator: false }).handle)

  t.alike(Object.keys(adopted).sort(), ['responderToken', 'runtime', 'tail'])
  t.ok(Object.isFrozen(adopted))
  t.ok(Object.isFrozen(adopted.responderToken))
  t.alike(Reflect.ownKeys(adopted.responderToken), [])
  adopted.runtime.destroy()
  revokeM3TailCapability(adopted.tail)
})

test('responder tail and token move the same opaque binding', (t) => {
  const clock = fakeClock()
  const adopted = authority(clock).adopt(syntheticLink({ initiator: false }).handle)
  const tailState = takeM3TailCapability(adopted.tail, {
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow
  })
  const tokenBinding = consumeTailResponderToken(adopted.responderToken)

  t.ok(Object.isFrozen(tokenBinding))
  t.alike(Reflect.ownKeys(tokenBinding), [])
  t.is(tailState.binding, tokenBinding)
  adopted.runtime.destroy()
})

test('responder binding owns the exact transcript, identity, role, and deadline fields', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const transfer = syntheticLink({
    initiator: false,
    localIdentity: b4a.alloc(32, 0x71),
    wireExpiresAt: 1_250n
  })
  const transcript = b4a.from(transfer.state.tailControlTranscript)
  const expectedDigest = cryptoSuite.hash([transcript])
  let observed = null
  const owner = authority(clock, {
    [TEST_ONLY_M3_ADJACENCY_OBSERVER](event) {
      if (event.type === 'responder-binding') observed = event
    }
  })

  const adopted = owner.adopt(transfer.handle)
  const fields = observed ? observed.bindingFields : {}
  const deadline = fields.deadline || { clockIdentity: {} }
  t.ok(observed, 'the owned test hook observes only non-secret binding copies')
  t.alike(Object.keys(fields).sort(), [
    'deadline',
    'initiator',
    'localIdentity',
    'transcriptDigest',
    'wireExpiresAt'
  ])
  t.alike(fields.transcriptDigest, expectedDigest)
  t.alike(fields.localIdentity, b4a.alloc(32, 0x71))
  t.is(fields.initiator, false)
  t.is(fields.wireExpiresAt, 1_250n)
  t.is(deadline.wireExpiresAt, 1_250n)
  t.is(deadline.routeLocalDeadline, 10_250n)
  t.is(deadline.operationDeadline, 10_250n)
  t.is(deadline.clockIdentity.wallNow, clock.wallNow)
  t.is(deadline.clockIdentity.monotonicNow, clock.monotonicNow)

  adopted.runtime.destroy()
  revokeM3TailCapability(adopted.tail)
  b4a.fill(transcript, 0)
  b4a.fill(expectedDigest, 0)
})

test('token consumption repeats every hidden binding-field validation', (t) => {
  for (const field of [
    'transcriptDigest',
    'localIdentity',
    'initiator',
    'wireExpiresAt',
    'deadline'
  ]) {
    const clock = fakeClock()
    let observed = null
    const owner = authority(clock, {
      [TEST_ONLY_M3_ADJACENCY_OBSERVER](event) {
        if (event.type === 'responder-binding') observed = event
      }
    })
    const adopted = owner.adopt(syntheticLink({ initiator: false }).handle)
    const bindingDigest = observed.bindingFields.transcriptDigest
    const bindingIdentity = observed.bindingFields.localIdentity
    const tokenDigest = observed.tokenFields.transcriptDigest
    const tokenIdentity = observed.tokenFields.localIdentity

    observed.corruptToken(field)
    t.exception(
      () => consumeTailResponderToken(adopted.responderToken),
      `${field} is revalidated at consumption`
    )
    t.absent(revokeM3TailCapability(adopted.tail), `${field} mismatch revokes the paired tail`)
    t.alike(bindingDigest, b4a.alloc(32), `${field} mismatch clears the binding digest`)
    t.alike(bindingIdentity, b4a.alloc(32), `${field} mismatch clears the binding identity`)
    t.alike(tokenDigest, b4a.alloc(32), `${field} mismatch clears the token digest`)
    t.alike(tokenIdentity, b4a.alloc(32), `${field} mismatch clears the token identity`)
    adopted.runtime.destroy()
  }
})

test('responder token is one-shot and bindings are unique per tail', (t) => {
  const clock = fakeClock()
  const owner = authority(clock)
  const first = owner.adopt(syntheticLink({ initiator: false }).handle)
  const second = owner.adopt(
    syntheticLink({
      initiator: false,
      completeOfferDigest: b4a.alloc(32, 0xd0),
      peerIdentity: b4a.alloc(32, 0xd1)
    }).handle
  )
  const firstBinding = consumeTailResponderToken(first.responderToken)
  const secondBinding = consumeTailResponderToken(second.responderToken)

  t.not(firstBinding, secondBinding, 'different authenticated tails never share a binding')
  t.exception(() => consumeTailResponderToken(first.responderToken), 'a consumed token is replay')
  t.is(
    revokeTailResponderToken(first.responderToken),
    true,
    'authority destroy can clear a consumed token binding'
  )
  t.is(revokeTailResponderToken(first.responderToken), false)
  first.runtime.destroy()
  second.runtime.destroy()
})

test('revoking a consumed token zeroizes its moved binding', (t) => {
  const clock = fakeClock()
  let observed = null
  const owner = authority(clock, {
    [TEST_ONLY_M3_ADJACENCY_OBSERVER](event) {
      if (event.type === 'responder-binding') observed = event
    }
  })
  const adopted = owner.adopt(syntheticLink({ initiator: false }).handle)
  const bindingDigest = observed.bindingFields.transcriptDigest
  const bindingIdentity = observed.bindingFields.localIdentity

  consumeTailResponderToken(adopted.responderToken)
  t.is(revokeTailResponderToken(adopted.responderToken), true)
  t.alike(bindingDigest, b4a.alloc(32))
  t.alike(bindingIdentity, b4a.alloc(32))
  t.absent(revokeM3TailCapability(adopted.tail))
  t.is(revokeTailResponderToken(adopted.responderToken), false)
  adopted.runtime.destroy()
})

test('token revocation clears both repeated records and revokes the paired tail', (t) => {
  const clock = fakeClock()
  let observed = null
  const owner = authority(clock, {
    [TEST_ONLY_M3_ADJACENCY_OBSERVER](event) {
      if (event.type === 'responder-binding') observed = event
    }
  })
  const adopted = owner.adopt(syntheticLink({ initiator: false }).handle)
  const bindingDigest = observed.bindingFields.transcriptDigest
  const bindingIdentity = observed.bindingFields.localIdentity
  const tokenDigest = observed.tokenFields.transcriptDigest
  const tokenIdentity = observed.tokenFields.localIdentity

  t.is(revokeTailResponderToken(adopted.responderToken), true)
  t.is(revokeTailResponderToken(adopted.responderToken), false, 'revocation is one-shot')
  t.is(revokeM3TailCapability(adopted.tail), false, 'revocation consumes the paired tail')
  t.alike(bindingDigest, b4a.alloc(32))
  t.alike(bindingIdentity, b4a.alloc(32))
  t.alike(tokenDigest, b4a.alloc(32))
  t.alike(tokenIdentity, b4a.alloc(32))
  adopted.runtime.destroy()
})

test('runtime expiry proactively revokes and clears its responder token', (t) => {
  const clock = fakeClock()
  let observed = null
  const owner = authority(clock, {
    [TEST_ONLY_M3_ADJACENCY_OBSERVER](event) {
      if (event.type === 'responder-binding') observed = event
    }
  })
  const adopted = owner.adopt(syntheticLink({ initiator: false, wireExpiresAt: 1_250n }).handle)
  const bindingDigest = observed.bindingFields.transcriptDigest
  const tokenDigest = observed.tokenFields.transcriptDigest

  t.is(clock.fireNext(), true)
  t.exception(() => consumeTailResponderToken(adopted.responderToken))
  t.is(revokeM3TailCapability(adopted.tail), false)
  t.alike(bindingDigest, b4a.alloc(32))
  t.alike(tokenDigest, b4a.alloc(32))
  t.is(adopted.runtime.destroy(), false)
})

test('tail-first and token-first transfer failures destroy the paired binding', (t) => {
  for (const order of ['tail-first', 'token-first']) {
    const clock = fakeClock()
    let observed = null
    const owner = authority(clock, {
      [TEST_ONLY_M3_ADJACENCY_OBSERVER](event) {
        if (event.type === 'responder-binding') observed = event
      }
    })
    const adopted = owner.adopt(
      syntheticLink({
        initiator: false,
        completeOfferDigest: b4a.alloc(32, order === 'tail-first' ? 0xe0 : 0xe2),
        peerIdentity: b4a.alloc(32, order === 'tail-first' ? 0xe1 : 0xe3)
      }).handle
    )
    const bindingDigest = observed.bindingFields.transcriptDigest
    const bindingIdentity = observed.bindingFields.localIdentity
    const tokenDigest = observed.tokenFields.transcriptDigest
    const tokenIdentity = observed.tokenFields.localIdentity

    if (order === 'token-first') consumeTailResponderToken(adopted.responderToken)
    t.exception(() =>
      takeM3TailCapability(adopted.tail, {
        wallNow: () => 1_000n,
        monotonicNow: clock.monotonicNow
      })
    )
    if (order === 'tail-first') {
      t.exception(() => consumeTailResponderToken(adopted.responderToken))
    }
    t.alike(bindingDigest, b4a.alloc(32), `${order} clears the binding digest`)
    t.alike(bindingIdentity, b4a.alloc(32), `${order} clears the binding identity`)
    t.alike(tokenDigest, b4a.alloc(32), `${order} clears the token digest`)
    t.alike(tokenIdentity, b4a.alloc(32), `${order} clears the token identity`)
    adopted.runtime.destroy()
  }
})

test('responder token hash reentry cannot publish an expired adoption', (t) => {
  const clock = fakeClock()
  const transfer = syntheticLink({ initiator: false, wireExpiresAt: 2_000n })
  let owner = null
  let reentered = false
  const crypto = Object.freeze({
    ...cryptoSuite,
    hash(inputs) {
      if (!reentered && inputs.length === 1 && inputs[0].byteLength === 290) {
        reentered = true
        clock.setMonotonic(11_000n)
        owner.diagnostics()
      }
      return cryptoSuite.hash(inputs)
    }
  })
  owner = authority(clock, { crypto })
  let adopted = null

  t.exception(() => {
    adopted = owner.adopt(transfer.handle)
  }, 'an expired unpublished runtime cannot be returned after hash reentry')
  t.is(transfer.channel.destroys, 1)
  t.is(clock.pending(), 0)
  t.alike(owner.diagnostics(), {
    activeRuntimes: 0,
    maxRuntimes: 128
  })
  if (adopted) {
    revokeTailResponderToken(adopted.responderToken)
    revokeM3TailCapability(adopted.tail)
    adopted.runtime.destroy()
  }
})

test('reserved-observer reentry cannot publish an expired initiator adoption', (t) => {
  const clock = fakeClock()
  const transfer = syntheticLink({ initiator: true, wireExpiresAt: 2_000n })
  const owner = authority(clock, {
    [TEST_ONLY_M3_ADJACENCY_OBSERVER](event) {
      if (event.type === 'reserved') clock.setMonotonic(11_000n)
    }
  })
  let adopted = null

  t.exception(() => {
    adopted = owner.adopt(transfer.handle)
  }, 'an expired initiator cannot be published after reserved-observer reentry')
  t.is(transfer.channel.destroys, 1)
  t.is(clock.pending(), 0)
  t.alike(owner.diagnostics(), {
    activeRuntimes: 0,
    maxRuntimes: 128
  })
  if (adopted) {
    revokeM3TailCapability(adopted.tail)
    adopted.runtime.destroy()
  }
})
