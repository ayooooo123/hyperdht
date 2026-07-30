const b4a = require('b4a')
const test = require('brittle')

const {
  DatagramReplayWindow,
  OrderedReceiver,
  SenderCounter
} = require('../../lib/private/counters')
const guardLinks = require('../../lib/private/guard-link')
const {
  M3AdjacencyAuthority,
  deriveM3CellIds,
  revokeM3TailCapability
} = require('../../lib/private/m3-adjacency-runtime')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { digestPayloadParameters } = require('../../lib/private/link-parameters')
const {
  BRANCH_CLASS,
  CAPACITY_CLASS,
  CELL_CLASS,
  CONTEXT_CLASS,
  M3_MESSAGE_ID,
  RELAY_CAPABILITY,
  ROLE,
  decodeM3Object,
  encodeM3Object,
  roleForIdentity
} = require('../../lib/private/protocol')
const {
  deriveM3DhtNodeId,
  digestRelayCapabilityAdvertisement,
  encodeCanonicalEndpoint,
  encodeRelayCapabilityAdvertisement,
  providerServicePolicyForCapabilities,
  signRelayCapabilityAdvertisement,
  decodeRelayCapabilityAdvertisement
} = require('../../lib/private/relay-capability')
const { encodeM3ContextEnvelope } = require('../../lib/private/m3-context')
const {
  EXTENDED_SIZE,
  EXTEND_REQUEST_MAX_SIZE,
  borrowTailControlTransport,
  EXTEND_REQUEST_MIN_SIZE,
  abortTailExtend,
  admitTailExtend,
  completeTailExtend,
  createTailControlResponderAuthority,
  createTailControlSession,
  decodeExtendRequest,
  decodeExtended,
  destroyTailControlResponderAuthority,
  destroyTailControlSession,
  digestAdmittedLimits,
  encodeExtendRequest,
  encodeExtended,
  encodeTailControlTranscript,
  openTailAdjacentLink,
  readTailControlDeadline,
  sealTailReady,
  takeAdmittedExtendRequest
} = require('../../lib/private/tail-control')

const TEST_ONLY_M3_ESTABLISHED_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-m3-established-issuer'
)
const OFFER_DIGEST = b4a.from(Array.from({ length: 32 }, (_, index) => index))
function seed(byte, size = 32) {
  return b4a.alloc(size, byte)
}

function fakeClock({ wall = 1_000n, monotonic = 10_000n } = {}) {
  let currentWall = wall
  let currentMonotonic = monotonic
  let nextHandle = 0
  const timers = new Map()
  return {
    wallNow() {
      return currentWall
    },
    monotonicNow() {
      return currentMonotonic
    },
    schedule(callback, delay) {
      const handle = ++nextHandle
      timers.set(handle, { callback, at: currentMonotonic + BigInt(delay), delay })
      return handle
    },
    advance(monotonic) {
      currentMonotonic = monotonic
    },
    cancelScheduled(handle) {
      timers.delete(handle)
    },
    pending() {
      return timers.size
    },
    delays() {
      return [...timers.values()].map((timer) => timer.delay)
    },
    fireDelay(delay) {
      for (const [handle, timer] of timers) {
        if (timer.delay !== delay) continue
        timers.delete(handle)
        timer.callback()
        return true
      }
      return false
    }
  }
}
function authority(clock) {
  return new M3AdjacencyAuthority({
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled,
    crypto: cryptoSuite
  })
}

function tailSessionOptions(clock, extra = {}) {
  const options = {
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled,
    absoluteDeadline: 10_250n
  }
  for (const key of Reflect.ownKeys(extra)) options[key] = extra[key]
  return options
}

function responderAuthorityOptions(clock, extra = {}) {
  const options = {
    adjacencyAdopter: Object.freeze({}),
    extensionCommitter: Object.freeze({}),
    adjacentLinkFactory: Object.freeze({}),
    tailReadySigner: Object.freeze({}),
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    randomBytes: () => seed(0xf0),
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled
  }
  for (const key of Reflect.ownKeys(extra)) options[key] = extra[key]
  return options
}

function channel() {
  return Object.freeze({ destroy() {} })
}

function channelPair() {
  const left = []
  const right = []
  const make = (inbox, outbox) => Object.freeze({
    send(packet) {
      outbox.push(b4a.from(packet))
      return true
    },
    receive() {
      if (inbox.length === 0) throw new Error('empty inbox')
      return inbox.shift()
    },
    destroy() {}
  })
  return [make(left, right), make(right, left)]
}

function contexts(initiator) {
  const values = {}
  for (const cellClass of [CELL_CLASS.CONTROL, CELL_CLASS.STREAM, CELL_CLASS.DATAGRAM]) {
    const forwardKey = seed(0x20 + cellClass)
    const reverseKey = seed(0x30 + cellClass)
    const forwardNonce = seed(0x40 + cellClass, 16)
    const reverseNonce = seed(0x50 + cellClass, 16)
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
  const state = {
    initiator,
    completeOfferDigest,
    localId: initiator ? ids.initiatorCellId : ids.responderCellId,
    peerLocalId: initiator ? ids.responderCellId : ids.initiatorCellId,
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: seed(0x41, 16),
    circuitId: seed(0x42, 16),
    generation: 7n,
    extensionIndex: overrides.extensionIndex === undefined ? (initiator ? 2 : 1) : overrides.extensionIndex,
    localIdentity: seed(0x51),
    peerIdentity: seed(0x52),
    expiresAt: overrides.wireExpiresAt === undefined ? 10_000n : overrides.wireExpiresAt,
    contexts: contexts(initiator),
    physicalChannel: overrides.physicalChannel || channel(),
    clientTailEphemeralSecretKey: initiator ? (overrides.clientTailEphemeralSecretKey || seed(0x63)) : null,
    tailControlTranscript: overrides.tailControlTranscript || seed(0x64, 290)
  }
  return guardLinks[TEST_ONLY_M3_ESTABLISHED_ISSUER].issue(state)
}

function initiatorSealLink(signedAdvertisement, requestedLimits, overrides = {}) {
  const currentAdvertisement = overrides.currentAdvertisement || signedAdvertisement
  const decoded = decodeRelayCapabilityAdvertisement(currentAdvertisement)
  const advertisementDigest = digestRelayCapabilityAdvertisement(currentAdvertisement)
  const admittedLimitsDigest = digestAdmittedLimits(requestedLimits)
  const currentTailPair = cryptoSuite.encryptionKeyPair(seed(0x61))
  try {
    return syntheticLink({
      ...overrides,
      initiator: true,
      extensionIndex: 1,
      clientTailEphemeralSecretKey: currentTailPair.secretKey,
      tailControlTranscript: encodeTailControlTranscript({
        branchClass: BRANCH_CLASS.LOOKUP,
        branchId: seed(0x41, 16),
        circuitId: seed(0x42, 16),
        generation: 7n,
        extensionIndex: 1,
        clientTailEphemeralPublicKey: currentTailPair.publicKey,
        advertisedTailRouteEncryptionPublicKey: decoded.routeEncryptionPublicKey,
        candidateAdvertisementDigest: advertisementDigest,
        clientNonce: seed(0x62),
        tailIdentity: decoded.relayIdentity,
        admittedLimitsDigest
      })
    })
  } finally {
    b4a.fill(advertisementDigest, 0)
    b4a.fill(admittedLimitsDigest, 0)
    b4a.fill(decoded.relayIdentity, 0)
    b4a.fill(decoded.routeEncryptionPublicKey, 0)
  }
}

function responderSealLink(signedAdvertisement, requestedLimits, overrides = {}) {
  const currentAdvertisement = overrides.currentAdvertisement || signedAdvertisement
  const decoded = decodeRelayCapabilityAdvertisement(currentAdvertisement)
  const advertisementDigest = digestRelayCapabilityAdvertisement(currentAdvertisement)
  const admittedLimitsDigest = digestAdmittedLimits(requestedLimits)
  const currentTailPair = cryptoSuite.encryptionKeyPair(seed(0x61))
  try {
    return syntheticLink({
      ...overrides,
      initiator: false,
      extensionIndex: 1,
      localIdentity: decoded.relayIdentity,
      clientTailEphemeralSecretKey: null,
      tailControlTranscript: encodeTailControlTranscript({
        branchClass: BRANCH_CLASS.LOOKUP,
        branchId: seed(0x41, 16),
        circuitId: seed(0x42, 16),
        generation: 7n,
        extensionIndex: 1,
        clientTailEphemeralPublicKey: currentTailPair.publicKey,
        advertisedTailRouteEncryptionPublicKey: decoded.routeEncryptionPublicKey,
        candidateAdvertisementDigest: advertisementDigest,
        clientNonce: seed(0x62),
        tailIdentity: decoded.relayIdentity,
        admittedLimitsDigest
      })
    })
  } finally {
    b4a.fill(advertisementDigest, 0)
    b4a.fill(admittedLimitsDigest, 0)
    b4a.fill(decoded.relayIdentity, 0)
    b4a.fill(decoded.routeEncryptionPublicKey, 0)
  }
}

function tailControlEnvelope(encoded) {
  const frame = b4a.alloc(1100)
  frame.set(encoded)
  return encodeM3ContextEnvelope({
    contextClass: CONTEXT_CLASS.TAIL_CONTROL_ORDERED,
    frame
  })
}

function advertisement(byte) {
  const identity = cryptoSuite.keyPair(seed(byte))
  const capabilityMask =
    roleForIdentity(identity.publicKey) === ROLE.PRIVATE
      ? RELAY_CAPABILITY.CIRCUIT_RELAY_V1 | RELAY_CAPABILITY.DHT_EXIT_V1
      : RELAY_CAPABILITY.CIRCUIT_RELAY_V1
  const endpoint = encodeCanonicalEndpoint({
    addressFamily: 4,
    addressBytes: b4a.from([192, 0, 2, byte]),
    port: 44_000 + byte
  })
  return encodeRelayCapabilityAdvertisement(
    signRelayCapabilityAdvertisement(
      {
        relayIdentity: identity.publicKey,
        currentDhtNodeId: deriveM3DhtNodeId(endpoint),
        reachableEndpoint: endpoint,
        routeEncryptionPublicKey: cryptoSuite.encryptionKeyPair(seed(byte + 1)).publicKey,
        capabilityMask,
        minimumProtocolVersion: 1,
        maximumProtocolVersion: 1,
        cellSize: 1200,
        maxCellPayload: 1146,
        contextEnvelopeSize: 1101,
        routeFrameSize: 1100,
        maxRoutePayload: 1073,
        datagramReplayWindow: 64,
        maxConcurrentCircuits: 8,
        capacityClass: CAPACITY_CLASS.SMALL,
        maxCellsPerCircuit: 100,
        maxBytesPerCircuit: 100_000,
        maxCommandsPerCircuit: 10,
        idleTimeoutMs: 30_000,
        maxQueuedBytes: 65_536,
        epoch: 1n,
        issuedAtMs: 1_000n,
        expiresAtMs: 20_000n,
        providerServicePolicyEntries: providerServicePolicyForCapabilities(capabilityMask)
      },
      identity.secretKey
    )
  )
}

function advertisementForRole(role, start = 0x50) {
  for (let byte = start; byte <= 0xff; byte++) {
    const encoded = advertisement(byte)
    const decoded = decodeRelayCapabilityAdvertisement(encoded)
    try {
      if (roleForIdentity(decoded.relayIdentity) === role) return encoded
    } finally {
      b4a.fill(decoded.relayIdentity, 0)
      b4a.fill(decoded.routeEncryptionPublicKey, 0)
    }
  }
  throw new Error('role advertisement unavailable')
}

test('TailControlSession consumes one M3 tail into a five-method stable owner', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const adopted = owner.adopt(syntheticLink({ wireExpiresAt: 1_250n }))

  const session = createTailControlSession(adopted.tail, tailSessionOptions(clock))

  t.alike(Object.keys(session).sort(), [
    'abortClientExtension',
    'completeClientExtension',
    'openExtended',
    'sealExtend',
    'takeFinalExitHandoff'
  ])
  t.is(readTailControlDeadline(session), 10_250n)
  const transport = borrowTailControlTransport(session)
  t.alike(Object.keys(transport).sort(), ['receive', 'send'])
  t.is(Object.isFrozen(transport), true)
  t.is(borrowTailControlTransport(session), transport)
  t.exception(() =>
    createTailControlSession(adopted.tail, tailSessionOptions(clock))
  )
  t.is(revokeM3TailCapability(adopted.tail), false)
  t.exception(() => borrowTailControlTransport(Object.freeze({})))
  t.is(clock.pending(), 2, 'TailControl arms one independent logical lifetime')
  t.is(destroyTailControlSession(session), true)
  t.is(destroyTailControlSession(session), false)
  t.is(clock.pending(), 1, 'destroy cancels only the TailControl lifetime')
})

test('TailControl exports the package-private responder authority surface', (t) => {
  t.is(typeof createTailControlResponderAuthority, 'function')
  t.is(typeof admitTailExtend, 'function')
  t.is(typeof openTailAdjacentLink, 'function')
  t.is(typeof completeTailExtend, 'function')
  t.is(typeof abortTailExtend, 'function')
  t.is(typeof sealTailReady, 'function')
  t.is(typeof destroyTailControlResponderAuthority, 'function')
})

test('TailControl responder authority consumes exact token and arms subordinate lifetime', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const adopted = owner.adopt(syntheticLink({ initiator: false, wireExpiresAt: 20_000n }))
  const session = createTailControlSession(adopted.tail, tailSessionOptions(clock))

  const responder = createTailControlResponderAuthority(
    session,
    adopted.responderToken,
    responderAuthorityOptions(clock)
  )

  t.alike(Object.keys(session).sort(), [
    'abortClientExtension',
    'completeClientExtension',
    'openExtended',
    'sealExtend',
    'takeFinalExitHandoff'
  ])
  t.alike(Reflect.ownKeys(responder), [])
  t.is(Object.isFrozen(responder), true)
  t.is(clock.pending(), 3, 'responder authority arms one subordinate logical lifetime')
  t.exception(() =>
    createTailControlResponderAuthority(session, adopted.responderToken, responderAuthorityOptions(clock))
  )
  t.is(destroyTailControlResponderAuthority(responder), true)
  t.is(destroyTailControlResponderAuthority(responder), false)
  t.is(clock.pending(), 2, 'authority destroy cancels only the subordinate lifetime')
  t.is(destroyTailControlSession(session), true)
})

test('TailControl responder authority rejects initiators, token substitutes, and alternate clocks', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const initiator = owner.adopt(syntheticLink({ initiator: true, wireExpiresAt: 20_000n }))
  const initiatorSession = createTailControlSession(initiator.tail, tailSessionOptions(clock, {
    absoluteDeadline: 16_000n
  }))
  t.exception(() =>
    createTailControlResponderAuthority(initiatorSession, Object.freeze({}), responderAuthorityOptions(clock))
  )
  t.is(destroyTailControlSession(initiatorSession), true)

  const substitute = owner.adopt(syntheticLink({
    initiator: false,
    completeOfferDigest: seed(0x81),
    wireExpiresAt: 20_000n
  }))
  const substituteSession = createTailControlSession(substitute.tail, tailSessionOptions(clock))
  t.exception(() =>
    createTailControlResponderAuthority(substituteSession, Object.freeze({}), responderAuthorityOptions(clock))
  )
  t.is(destroyTailControlSession(substituteSession), true)

  const alternate = owner.adopt(syntheticLink({
    initiator: false,
    completeOfferDigest: seed(0x82),
    wireExpiresAt: 20_000n
  }))
  const alternateSession = createTailControlSession(alternate.tail, tailSessionOptions(clock))
  t.exception(() =>
    createTailControlResponderAuthority(alternateSession, alternate.responderToken, responderAuthorityOptions(clock, {
      monotonicNow: () => 10_000n
    }))
  )
  t.is(destroyTailControlSession(alternateSession), true)
})

test('TailControl responder admission consumes one registered control envelope', async (t) => {
  const initiatorClock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const responderClock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const initiatorOwner = authority(initiatorClock)
  const responderOwner = authority(responderClock)
  const [initiatorChannel, responderChannel] = channelPair()
  const currentAdvertisement = advertisementForRole(ROLE.SAFETY)
  const signedAdvertisement = advertisementForRole(ROLE.PRIVATE)
  const requestedLimits = Object.freeze({
    cellSize: 1200,
    maxCells: 64,
    maxBytes: 65_536,
    maxCommands: 10,
    idleTimeoutMs: 5_000,
    expiresAtMs: 5_000n
  })
  const initiator = initiatorOwner.adopt(initiatorSealLink(signedAdvertisement, requestedLimits, {
    currentAdvertisement,
    physicalChannel: initiatorChannel,
    wireExpiresAt: 20_000n
  }))
  const responder = responderOwner.adopt(responderSealLink(signedAdvertisement, requestedLimits, {
    currentAdvertisement,
    physicalChannel: responderChannel,
    wireExpiresAt: 20_000n
  }))
  const initiatorSession = createTailControlSession(initiator.tail, tailSessionOptions(initiatorClock, {
    absoluteDeadline: 16_000n,
    crypto: cryptoSuite
  }))
  const responderSession = createTailControlSession(responder.tail, tailSessionOptions(responderClock))
  const responderAuthority = createTailControlResponderAuthority(
    responderSession,
    responder.responderToken,
    responderAuthorityOptions(responderClock)
  )
  const encoded = initiatorSession.sealExtend({
    advertisement: signedAdvertisement,
    advertisementDigest: digestRelayCapabilityAdvertisement(signedAdvertisement),
    extensionIndex: 2,
    requestedLimits,
    absoluteDeadline: 16_000n,
    randomBytes: (() => {
      const randomSeeds = [seed(0x70), seed(0x71), seed(0x72)]
      return (size) => {
        t.is(size, 32)
        return randomSeeds.shift()
      }
    })()
  })
  await borrowTailControlTransport(initiatorSession).send(tailControlEnvelope(encoded))
  const received = await borrowTailControlTransport(responderSession).receive()

  t.exception(() => admitTailExtend(responderAuthority, b4a.from(received)), 'a structural envelope copy is not registered')
  const admitted = admitTailExtend(responderAuthority, received)
  t.alike(Reflect.ownKeys(admitted), [])
  t.ok(Object.isFrozen(admitted))

  const taken = takeAdmittedExtendRequest(admitted)
  t.alike(Object.keys(taken).sort(), [
    'currentTailAdvertisementDigest',
    'currentTailIdentity',
    'deadline',
    'request'
  ])
  t.is(taken.deadline, 5_000n)
  t.alike(taken.request, decodeExtendRequest(encoded))
  const decodedNextAdvertisement = decodeRelayCapabilityAdvertisement(taken.request.advertisement)
  t.ok(!b4a.equals(taken.currentTailIdentity, decodedNextAdvertisement.relayIdentity))
  t.ok(!b4a.equals(
    taken.currentTailAdvertisementDigest,
    digestRelayCapabilityAdvertisement(taken.request.advertisement)
  ))
  t.exception(() => admitTailExtend(responderAuthority, received), 'registered envelope is one-use')
  t.exception(() => takeAdmittedExtendRequest(admitted), 'admission is one-use')
  await borrowTailControlTransport(initiatorSession).send(tailControlEnvelope(encoded))
  const retransmitted = await borrowTailControlTransport(responderSession).receive()
  let retransmitCode = null
  try {
    admitTailExtend(responderAuthority, retransmitted)
  } catch (err) {
    retransmitCode = err.code
  }
  t.is(retransmitCode, 'ERR_BUSY')
  t.is(readTailControlDeadline(responderSession), 14_000n)
  t.is(destroyTailControlResponderAuthority(responderAuthority), true)
  t.is(destroyTailControlSession(initiatorSession), true)
  t.is(destroyTailControlSession(responderSession), true)
  t.alike(retransmitted, b4a.alloc(1101), 'destroy clears rejected retransmission envelope')
})

test('TailControl responder admission rejects unbound and out-of-policy limits', async (t) => {
  const initiatorClock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const responderClock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const currentAdvertisement = advertisementForRole(ROLE.SAFETY)
  const signedAdvertisement = advertisementForRole(ROLE.PRIVATE)
  const transcriptLimits = Object.freeze({
    cellSize: 1200,
    maxCells: 64,
    maxBytes: 65_536,
    maxCommands: 10,
    idleTimeoutMs: 5_000,
    expiresAtMs: 5_000n
  })
  const withinAdvertisement = Object.freeze({ ...transcriptLimits, maxCells: 65 })
  const beyondAdvertisement = Object.freeze({ ...transcriptLimits, maxCells: 101 })
  const makeEncoded = (limits, nonce) => encodeExtendRequest({
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: seed(0x41, 16),
    circuitId: seed(0x42, 16),
    generation: 7n,
    extensionIndex: 2,
    advertisement: signedAdvertisement,
    clientTailEphemeralPublicKey: cryptoSuite.encryptionKeyPair(seed(0x70 + nonce)).publicKey,
    clientNonce: seed(0x80 + nonce),
    payloadParametersDigest: digestPayloadParameters(decodeRelayCapabilityAdvertisement(signedAdvertisement)),
    requestedLimits: limits,
    extensionNonce: seed(0x90 + nonce)
  })
  for (const [limits, transcriptAdmittedLimits, expectedCode] of [
    [withinAdvertisement, transcriptLimits, 'ERR_AUTHENTICATION'],
    [beyondAdvertisement, beyondAdvertisement, 'ERR_PRIVACY_UNAVAILABLE']
  ]) {
    const initiatorOwner = authority(initiatorClock)
    const responderOwner = authority(responderClock)
    const [initiatorChannel, responderChannel] = channelPair()
    const initiator = initiatorOwner.adopt(initiatorSealLink(signedAdvertisement, transcriptAdmittedLimits, {
      currentAdvertisement,
      physicalChannel: initiatorChannel,
      wireExpiresAt: 20_000n
    }))
    const responder = responderOwner.adopt(responderSealLink(signedAdvertisement, transcriptAdmittedLimits, {
      currentAdvertisement,
      physicalChannel: responderChannel,
      wireExpiresAt: 20_000n
    }))
    const initiatorSession = createTailControlSession(initiator.tail, tailSessionOptions(initiatorClock, {
      absoluteDeadline: 16_000n,
      crypto: cryptoSuite
    }))
    const responderSession = createTailControlSession(responder.tail, tailSessionOptions(responderClock))
    const responderAuthority = createTailControlResponderAuthority(
      responderSession,
      responder.responderToken,
      responderAuthorityOptions(responderClock)
    )
    await borrowTailControlTransport(initiatorSession).send(tailControlEnvelope(makeEncoded(limits, expectedCode.length)))
    const received = await borrowTailControlTransport(responderSession).receive()
    let code = null
    try {
      admitTailExtend(responderAuthority, received)
    } catch (err) {
      code = err.code
    }
    t.is(code, expectedCode)
    t.is(destroyTailControlResponderAuthority(responderAuthority), true)
    t.is(destroyTailControlSession(initiatorSession), true)
    t.is(destroyTailControlSession(responderSession), true)
  }
})

test('TailControl responder admission reserves before reentrant clocks', async (t) => {
  const initiatorClock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const responderClock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const currentAdvertisement = advertisementForRole(ROLE.SAFETY)
  const signedAdvertisement = advertisementForRole(ROLE.PRIVATE)
  const requestedLimits = Object.freeze({
    cellSize: 1200,
    maxCells: 64,
    maxBytes: 65_536,
    maxCommands: 10,
    idleTimeoutMs: 5_000,
    expiresAtMs: 5_000n
  })
  const initiatorOwner = authority(initiatorClock)
  let responderAuthority = null
  let nestedEnvelope = null
  let nestedCode = null
  let reentered = false
  const reentrantWallNow = () => {
    if (nestedEnvelope !== null && !reentered) {
      reentered = true
      try {
        admitTailExtend(responderAuthority, nestedEnvelope)
      } catch (err) {
        nestedCode = err.code
      }
    }
    return responderClock.wallNow()
  }
  const responderClockWithReentry = Object.freeze({
    wallNow: reentrantWallNow,
    monotonicNow: responderClock.monotonicNow,
    schedule: responderClock.schedule,
    cancelScheduled: responderClock.cancelScheduled
  })
  const responderOwner = authority(responderClockWithReentry)
  const [initiatorChannel, responderChannel] = channelPair()
  const initiator = initiatorOwner.adopt(initiatorSealLink(signedAdvertisement, requestedLimits, {
    currentAdvertisement,
    physicalChannel: initiatorChannel,
    wireExpiresAt: 20_000n
  }))
  const responder = responderOwner.adopt(responderSealLink(signedAdvertisement, requestedLimits, {
    currentAdvertisement,
    physicalChannel: responderChannel,
    wireExpiresAt: 20_000n
  }))
  const initiatorSession = createTailControlSession(initiator.tail, tailSessionOptions(initiatorClock, {
    absoluteDeadline: 16_000n,
    crypto: cryptoSuite
  }))
  const responderSession = createTailControlSession(responder.tail, tailSessionOptions(responderClockWithReentry))
  responderAuthority = createTailControlResponderAuthority(
    responderSession,
    responder.responderToken,
    responderAuthorityOptions(responderClockWithReentry)
  )
  const encoded = initiatorSession.sealExtend({
    advertisement: signedAdvertisement,
    advertisementDigest: digestRelayCapabilityAdvertisement(signedAdvertisement),
    extensionIndex: 2,
    requestedLimits,
    absoluteDeadline: 16_000n,
    randomBytes: (() => {
      const randomSeeds = [seed(0x70), seed(0x71), seed(0x72)]
      return () => randomSeeds.shift()
    })()
  })
  await borrowTailControlTransport(initiatorSession).send(tailControlEnvelope(encoded))
  await borrowTailControlTransport(initiatorSession).send(tailControlEnvelope(encoded))
  const firstEnvelope = await borrowTailControlTransport(responderSession).receive()
  nestedEnvelope = await borrowTailControlTransport(responderSession).receive()
  const admitted = admitTailExtend(responderAuthority, firstEnvelope)
  t.is(nestedCode, 'ERR_BUSY')
  t.alike(Reflect.ownKeys(admitted), [])
  t.is(destroyTailControlResponderAuthority(responderAuthority), true)
  t.is(destroyTailControlSession(initiatorSession), true)
  t.is(destroyTailControlSession(responderSession), true)
  t.alike(nestedEnvelope, b4a.alloc(1101), 'destroy clears reentrant rejected envelope')
})

test('TailControl responder admission clamps local projection to inherited deadline', async (t) => {
  const initiatorClock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const responderClock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const currentAdvertisement = advertisementForRole(ROLE.SAFETY)
  const signedAdvertisement = advertisementForRole(ROLE.PRIVATE)
  const requestedLimits = Object.freeze({
    cellSize: 1200,
    maxCells: 64,
    maxBytes: 65_536,
    maxCommands: 10,
    idleTimeoutMs: 5_000,
    expiresAtMs: 20_000n
  })
  const initiatorOwner = authority(initiatorClock)
  const responderOwner = authority(responderClock)
  const [initiatorChannel, responderChannel] = channelPair()
  const initiator = initiatorOwner.adopt(initiatorSealLink(signedAdvertisement, requestedLimits, {
    currentAdvertisement,
    physicalChannel: initiatorChannel,
    wireExpiresAt: 20_000n
  }))
  const responder = responderOwner.adopt(responderSealLink(signedAdvertisement, requestedLimits, {
    currentAdvertisement,
    physicalChannel: responderChannel,
    wireExpiresAt: 20_000n
  }))
  const initiatorSession = createTailControlSession(initiator.tail, tailSessionOptions(initiatorClock, {
    absoluteDeadline: 29_000n,
    crypto: cryptoSuite
  }))
  const responderSession = createTailControlSession(responder.tail, tailSessionOptions(responderClock))
  const responderAuthority = createTailControlResponderAuthority(
    responderSession,
    responder.responderToken,
    responderAuthorityOptions(responderClock)
  )
  const encoded = initiatorSession.sealExtend({
    advertisement: signedAdvertisement,
    advertisementDigest: digestRelayCapabilityAdvertisement(signedAdvertisement),
    extensionIndex: 2,
    requestedLimits,
    absoluteDeadline: 29_000n,
    randomBytes: (() => {
      const randomSeeds = [seed(0xa0), seed(0xa1), seed(0xa2)]
      return () => randomSeeds.shift()
    })()
  })
  responderClock.advance(10_001n)
  await borrowTailControlTransport(initiatorSession).send(tailControlEnvelope(encoded))
  const received = await borrowTailControlTransport(responderSession).receive()
  const admitted = admitTailExtend(responderAuthority, received)
  const taken = takeAdmittedExtendRequest(admitted)
  t.is(taken.deadline, 20_000n)
  t.is(readTailControlDeadline(responderSession), 29_000n)
  t.is(destroyTailControlResponderAuthority(responderAuthority), true)
  t.is(destroyTailControlSession(initiatorSession), true)
  t.is(destroyTailControlSession(responderSession), true)
})

test('TailControlSession rejects structural transport and alternate clocks', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const adopted = owner.adopt(syntheticLink({ wireExpiresAt: 1_250n }))

  t.exception(() =>
    createTailControlSession(adopted.tail, tailSessionOptions(clock, {
      wallNow: () => 1_000n
    }))
  )

  const missingDeadline = owner.adopt(syntheticLink({
    completeOfferDigest: seed(0x72),
    wireExpiresAt: 1_250n
  }))
  const noDeadline = {
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled
  }
  t.exception(() => createTailControlSession(missingDeadline.tail, noDeadline))

  const second = owner.adopt(syntheticLink({ completeOfferDigest: seed(0x71), wireExpiresAt: 1_250n }))
  t.exception(() =>
    createTailControlSession(second.tail, tailSessionOptions(clock, {
      destroy() {}
    }))
  )
})

test('TailControl transport sends and receives only through M3-owned control cells', async (t) => {
  const initiatorClock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const responderClock = fakeClock({ wall: 1_000n, monotonic: 20_000n })
  const initiatorOwner = authority(initiatorClock)
  const responderOwner = authority(responderClock)
  const [initiatorChannel, responderChannel] = channelPair()
  const initiator = initiatorOwner.adopt(syntheticLink({
    physicalChannel: initiatorChannel,
    wireExpiresAt: 1_250n
  }))
  const responder = responderOwner.adopt(syntheticLink({
    initiator: false,
    physicalChannel: responderChannel,
    wireExpiresAt: 1_250n
  }))
  const initiatorSession = createTailControlSession(
    initiator.tail,
    tailSessionOptions(initiatorClock)
  )
  const responderSession = createTailControlSession(responder.tail, {
    wallNow: responderClock.wallNow,
    monotonicNow: responderClock.monotonicNow,
    schedule: responderClock.schedule,
    cancelScheduled: responderClock.cancelScheduled
  })
  const sent = seed(0x90, 1101)

  await borrowTailControlTransport(initiatorSession).send(sent)
  const received = await borrowTailControlTransport(responderSession).receive()
  t.alike(received, sent)
  t.exception(() => borrowTailControlTransport(initiatorSession).send(seed(0x91, 1100)))
  t.is(destroyTailControlSession(initiatorSession), true)
  t.is(destroyTailControlSession(responderSession), true)
  t.alike(received, b4a.alloc(1101), 'destroy clears an unconsumed registered envelope')
})

test('TailControl logical expiry releases session without closing physical link', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  let destroys = 0
  const physicalChannel = Object.freeze({
    destroy() {
      destroys++
    }
  })
  const adopted = owner.adopt(syntheticLink({
    physicalChannel,
    wireExpiresAt: 1_250n
  }))
  const session = createTailControlSession(adopted.tail, tailSessionOptions(clock, {
    absoluteDeadline: 10_100n
  }))

  t.alike(clock.delays(), [250, 100])
  clock.advance(10_100n)
  t.is(clock.fireDelay(100), true)
  t.exception(() => readTailControlDeadline(session))
  t.is(destroys, 0)
  t.is(clock.pending(), 1)
})

test('TailControlSession rejects synchronous scheduler reentry before publication', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const adopted = owner.adopt(syntheticLink({ wireExpiresAt: 1_250n }))
  const cancelled = []
  const reentrantSchedule = (callback) => {
    callback()
    return 99
  }
  const cancelScheduled = (handle) => {
    cancelled.push(handle)
  }

  t.exception(() =>
    createTailControlSession(adopted.tail, tailSessionOptions(clock, {
      schedule: reentrantSchedule,
      cancelScheduled
    }))
  )
  t.alike(cancelled, [99])
  t.is(revokeM3TailCapability(adopted.tail), false)
})

test('TailControlSession arms far deadlines with platform-safe chunks', (t) => {
  const maxTimerDelay = 0x7fff_ffff
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const adopted = owner.adopt(syntheticLink({
    wireExpiresAt: 1_000n + BigInt(maxTimerDelay) + 5n
  }))
  const session = createTailControlSession(adopted.tail, tailSessionOptions(clock, {
    absoluteDeadline: 10_000n + BigInt(maxTimerDelay) + 5n
  }))

  t.alike(clock.delays(), [maxTimerDelay, maxTimerDelay])
  t.is(readTailControlDeadline(session), 10_000n + BigInt(maxTimerDelay) + 5n)
  t.is(destroyTailControlSession(session), true)
})

test('TailControl far-deadline rearm releases transport after synchronous destruction', (t) => {
  const {
    releaseM3TailControlTransport: releaseTransport
  } = require('../../lib/private/m3-adjacency-runtime')
  const runtime = require('../../lib/private/m3-adjacency-runtime')
  const maxTimerDelay = 0x7fff_ffff
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const adopted = owner.adopt(syntheticLink({
    wireExpiresAt: 1_000n + BigInt(maxTimerDelay) + 5n
  }))
  const cancelled = []
  let releases = 0
  let session = null
  let tailSchedules = 0
  const schedule = (callback, delay) => {
    tailSchedules++
    if (tailSchedules === 1) return clock.schedule(callback, delay)
    t.is(destroyTailControlSession(session), true)
    callback()
    return 99
  }
  const cancelScheduled = (handle) => {
    cancelled.push(handle)
    clock.cancelScheduled(handle)
  }
  runtime.releaseM3TailControlTransport = (transportOwner) => {
    releases++
    return releaseTransport(transportOwner)
  }
  try {
    session = createTailControlSession(adopted.tail, tailSessionOptions(clock, {
      absoluteDeadline: 10_000n + BigInt(maxTimerDelay) + 5n,
      schedule,
      cancelScheduled
    }))

    clock.advance(10_000n + BigInt(maxTimerDelay))
    t.is(clock.fireDelay(maxTimerDelay), true, 'runtime chunk fires first')
    t.is(clock.fireDelay(maxTimerDelay), true, 'tail chunk attempts rearm')
    t.alike(cancelled, [99])
    t.is(releases, 1)
    t.exception(() => readTailControlDeadline(session))
    t.exception(() => borrowTailControlTransport(session).send(seed(0x92, 1101)))
  } finally {
    runtime.releaseM3TailControlTransport = releaseTransport
  }
})

test('TailControl far-deadline rearm releases transport when scheduler destroys then throws', (t) => {
  const {
    releaseM3TailControlTransport: releaseTransport
  } = require('../../lib/private/m3-adjacency-runtime')
  const runtime = require('../../lib/private/m3-adjacency-runtime')
  const maxTimerDelay = 0x7fff_ffff
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const adopted = owner.adopt(syntheticLink({
    wireExpiresAt: 1_000n + BigInt(maxTimerDelay) + 5n
  }))
  let releases = 0
  let session = null
  let tailSchedules = 0
  const schedule = (callback, delay) => {
    tailSchedules++
    if (tailSchedules === 1) return clock.schedule(callback, delay)
    t.is(destroyTailControlSession(session), true)
    throw new Error('reentrant scheduler failure')
  }
  runtime.releaseM3TailControlTransport = (transportOwner) => {
    releases++
    return releaseTransport(transportOwner)
  }
  try {
    session = createTailControlSession(adopted.tail, tailSessionOptions(clock, {
      absoluteDeadline: 10_000n + BigInt(maxTimerDelay) + 5n,
      schedule
    }))

    clock.advance(10_000n + BigInt(maxTimerDelay))
    t.is(clock.fireDelay(maxTimerDelay), true, 'runtime chunk fires first')
    t.is(clock.fireDelay(maxTimerDelay), true, 'tail chunk attempts throwing rearm')
    t.is(releases, 1)
    t.exception(() => readTailControlDeadline(session))
    t.exception(() => borrowTailControlTransport(session).send(seed(0x93, 1101)))
  } finally {
    runtime.releaseM3TailControlTransport = releaseTransport
  }
})

test('TailControl initiator sealExtend owns exact request fields', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const currentAdvertisement = advertisementForRole(ROLE.SAFETY)
  const signedAdvertisement = advertisementForRole(ROLE.PRIVATE)
  const requestedLimits = Object.freeze({
    cellSize: 1200,
    maxCells: 64,
    maxBytes: 65_536,
    maxCommands: 10,
    idleTimeoutMs: 5_000,
    expiresAtMs: 5_000n
  })
  const owner = authority(clock)
  const adopted = owner.adopt(initiatorSealLink(signedAdvertisement, requestedLimits, {
    currentAdvertisement,
    wireExpiresAt: 20_000n
  }))
  const randomSeeds = [seed(0x70), seed(0x71), seed(0x72)]
  const randomBytes = (size) => {
    t.is(size, 32)
    return randomSeeds.shift()
  }
  const session = createTailControlSession(adopted.tail, tailSessionOptions(clock, {
    absoluteDeadline: 16_000n,
    crypto: cryptoSuite
  }))
  const encoded = session.sealExtend({
    advertisement: signedAdvertisement,
    advertisementDigest: digestRelayCapabilityAdvertisement(signedAdvertisement),
    extensionIndex: 2,
    requestedLimits,
    absoluteDeadline: 16_000n,
    randomBytes
  })
  const decoded = decodeExtendRequest(encoded)
  const decodedAdvertisement = decodeRelayCapabilityAdvertisement(signedAdvertisement)
  const ephemeral = cryptoSuite.encryptionKeyPair(seed(0x70))

  t.alike(decoded, {
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: seed(0x41, 16),
    circuitId: seed(0x42, 16),
    generation: 7n,
    extensionIndex: 2,
    advertisement: signedAdvertisement,
    clientTailEphemeralPublicKey: ephemeral.publicKey,
    clientNonce: seed(0x71),
    payloadParametersDigest: digestPayloadParameters(decodedAdvertisement),
    requestedLimits,
    extensionNonce: seed(0x72)
  })
  let busyCode = null
  try {
    session.sealExtend({
      advertisement: signedAdvertisement,
      advertisementDigest: digestRelayCapabilityAdvertisement(signedAdvertisement),
      extensionIndex: 2,
      requestedLimits,
      absoluteDeadline: 16_000n,
      randomBytes: () => seed(0x73)
    })
  } catch (err) {
    busyCode = err.code
  }
  t.is(busyCode, 'ERR_BUSY')
  t.is(randomSeeds.length, 0)
  t.is(destroyTailControlSession(session), true)
})

test('TailControl initiator sealExtend rejects requested wire expiry beyond local budget', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const currentAdvertisement = advertisementForRole(ROLE.SAFETY)
  const signedAdvertisement = advertisementForRole(ROLE.PRIVATE)
  const requestedLimits = Object.freeze({
    cellSize: 1200,
    maxCells: 64,
    maxBytes: 65_536,
    maxCommands: 10,
    idleTimeoutMs: 5_000,
    expiresAtMs: 7_001n
  })
  const owner = authority(clock)
  const adopted = owner.adopt(initiatorSealLink(signedAdvertisement, requestedLimits, {
    currentAdvertisement,
    wireExpiresAt: 20_000n
  }))
  const session = createTailControlSession(adopted.tail, tailSessionOptions(clock, {
    absoluteDeadline: 16_000n,
    crypto: cryptoSuite
  }))
  let code = null
  try {
    session.sealExtend({
      advertisement: signedAdvertisement,
      advertisementDigest: digestRelayCapabilityAdvertisement(signedAdvertisement),
      extensionIndex: 2,
      requestedLimits,
      absoluteDeadline: 16_000n,
      randomBytes: () => seed(0x80)
    })
  } catch (err) {
    code = err.code
  }
  t.is(code, 'ERR_PRIVACY_UNAVAILABLE')
  t.is(destroyTailControlSession(session), true)
})

test('EXTEND_REQUEST_V1 and EXTENDED_V1 retain exact canonical bytes', (t) => {
  const signedAdvertisement = advertisement(0x51)
  const requestedLimits = {
    cellSize: 1200,
    maxCells: 64,
    maxBytes: 65_536,
    maxCommands: 32,
    idleTimeoutMs: 5_000,
    expiresAtMs: 5_000n
  }
  const request = {
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: seed(0x11, 16),
    circuitId: seed(0x12, 16),
    generation: 7n,
    extensionIndex: 1,
    advertisement: signedAdvertisement,
    clientTailEphemeralPublicKey: seed(0x52),
    clientNonce: seed(0x53),
    payloadParametersDigest: seed(0x54),
    requestedLimits,
    extensionNonce: seed(0x55)
  }
  const encodedRequest = encodeExtendRequest(request)
  const requestObject = decodeM3Object(encodedRequest)
  t.is(encodedRequest.byteLength, 206 + signedAdvertisement.byteLength)
  t.ok(
    encodedRequest.byteLength >= EXTEND_REQUEST_MIN_SIZE &&
      encodedRequest.byteLength <= EXTEND_REQUEST_MAX_SIZE
  )
  t.is(requestObject.body.byteLength, 198 + signedAdvertisement.byteLength)
  t.alike(decodeExtendRequest(encodedRequest), request)

  const proof = encodeM3Object({
    messageId: M3_MESSAGE_ID.REDACTED_RESPONDER_PROOF_V1,
    body: seed(0x56, 306),
    authSuffix: seed(0x57, 64)
  })
  const extended = {
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: request.branchId,
    circuitId: request.circuitId,
    generation: 7n,
    extensionIndex: 1,
    responderAdvertisementDigest: seed(0x58),
    redactedProof: proof,
    extensionNonce: request.extensionNonce
  }
  const encodedExtended = encodeExtended(extended)
  t.is(encodedExtended.byteLength, EXTENDED_SIZE)
  t.is(decodeM3Object(encodedExtended).body.byteLength, 486)
  t.alike(decodeExtended(encodedExtended), extended)
  t.exception(() => decodeExtendRequest(encodedRequest.subarray(0, encodedRequest.byteLength - 1)))
  t.exception(() => decodeExtended(encodedExtended.subarray(0, EXTENDED_SIZE - 1)))
})
