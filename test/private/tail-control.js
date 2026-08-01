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
const { createExtensionLinkCompletion } = require('../../lib/private/extension-link-completion')
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
  decodeTailReady,
  destroyTailControlResponderAuthority,
  destroyTailControlSession,
  digestAdmittedLimits,
  deriveTailControlTestVector,
  encodeExtendRequest,
  encodeExtended,
  encodeTailControlTranscript,
  openTailAdjacentLink,
  readTailControlDeadline,
  sealTailReady,
  takeAdmittedExtendRequest
} = require('../../lib/private/tail-control')
const { signRedactedResponderProof } = require('../../lib/private/redacted-responder-proof')
const { consumeFinalExitHandoff } = require('../../lib/private/final-exit-handoff')
const {
  claimFinalExitActivation,
  createFinalExitActivationClaim,
  destroyFinalExitActivationOwner
} = require('../../lib/private/final-exit-activation')

const TEST_ONLY_M3_ESTABLISHED_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-m3-established-issuer'
)
const OFFER_DIGEST = b4a.from(Array.from({ length: 32 }, (_, index) => index))
function seed(byte, size = 32) {
  return b4a.alloc(size, byte)
}

function errorCode(operation) {
  try {
    operation()
  } catch (err) {
    return err && err.code
  }
  return null
}

function writeUint16(target, value, offset) {
  target[offset] = value >>> 8
  target[offset + 1] = value
}

function writeUint32(target, value, offset) {
  target[offset] = value >>> 24
  target[offset + 1] = value >>> 16
  target[offset + 2] = value >>> 8
  target[offset + 3] = value
}

function writeUint64(target, value, offset) {
  for (let index = 7; index >= 0; index--) {
    target[offset + index] = Number(value & 0xffn)
    value >>= 8n
  }
}

const TAIL_READY_DOMAIN = b4a.from('hyperdht-private-routes/m3/tail-ready/v1')
const TAIL_READY_TRANSCRIPT_DOMAIN = b4a.from(
  'hyperdht-private-routes/m3/tail-control/transcript-digest/v1'
)

function signatureInput(domain, messageId, body) {
  const input = b4a.alloc(10 + domain.byteLength + body.byteLength)
  writeUint16(input, domain.byteLength, 0)
  input.set(domain, 2)
  writeUint32(input, 1, 2 + domain.byteLength)
  writeUint16(input, messageId, 6 + domain.byteLength)
  writeUint16(input, body.byteLength, 8 + domain.byteLength)
  input.set(body, 10 + domain.byteLength)
  return input
}

function tailReadyTranscriptDigest(transcript) {
  return cryptoSuite.hash([TAIL_READY_TRANSCRIPT_DOMAIN, transcript])
}

function encodeTailReadyFor(extended, request, signer, overrides = {}) {
  const body = b4a.alloc(210)
  body[0] = extended.branchClass
  body.set(extended.branchId, 1)
  body.set(extended.circuitId, 17)
  writeUint64(body, extended.generation, 33)
  body[41] = extended.extensionIndex
  body.set(overrides.transcriptDigest, 42)
  body.set(signer.publicKey, 74)
  body.set(extended.responderAdvertisementDigest, 106)
  body.set(overrides.clientNonce || request.clientNonce, 138)
  body.set(overrides.readyNonce || seed(0xa3), 170)
  writeUint64(body, overrides.expiresAtMs, 202)
  const input = signatureInput(TAIL_READY_DOMAIN, M3_MESSAGE_ID.TAIL_READY_V1, body)
  return encodeM3Object({
    messageId: M3_MESSAGE_ID.TAIL_READY_V1,
    body,
    authSuffix: overrides.signature || cryptoSuite.sign(input, signer.secretKey)
  })
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
    advanceWall(wall) {
      currentWall = wall
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
  const make = (inbox, outbox) =>
    Object.freeze({
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
  const extensionIndex =
    overrides.extensionIndex === undefined ? (initiator ? 2 : 1) : overrides.extensionIndex
  const localIdentity = overrides.localIdentity || seed(0x51)
  const tailControlTranscript =
    overrides.tailControlTranscript ||
    (!initiator && extensionIndex === 2
      ? encodeTailControlTranscript({
          branchClass: BRANCH_CLASS.LOOKUP,
          branchId: seed(0x41, 16),
          circuitId: seed(0x42, 16),
          generation: 7n,
          extensionIndex,
          clientTailEphemeralPublicKey: seed(0x61),
          advertisedTailRouteEncryptionPublicKey: seed(0x62),
          candidateAdvertisementDigest: seed(0x63),
          clientNonce: seed(0x64),
          tailIdentity: localIdentity,
          admittedLimitsDigest: seed(0x65)
        })
      : seed(0x64, 290))
  const state = {
    initiator,
    completeOfferDigest,
    localId: initiator ? ids.initiatorCellId : ids.responderCellId,
    peerLocalId: initiator ? ids.responderCellId : ids.initiatorCellId,
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: seed(0x41, 16),
    circuitId: seed(0x42, 16),
    generation: 7n,
    extensionIndex,
    localIdentity,
    peerIdentity: seed(0x52),
    expiresAt: overrides.wireExpiresAt === undefined ? 10_000n : overrides.wireExpiresAt,
    contexts: contexts(initiator),
    physicalChannel: overrides.physicalChannel || channel(),
    clientTailEphemeralSecretKey: initiator
      ? overrides.clientTailEphemeralSecretKey || seed(0x63)
      : null,
    tailSharedSecret: initiator ? null : overrides.tailSharedSecret || seed(0x63),
    tailControlTranscript
  }
  return guardLinks[TEST_ONLY_M3_ESTABLISHED_ISSUER].issue(state)
}

function initiatorTailControlTranscript(
  currentAdvertisement,
  requestedLimits,
  currentTailPair = cryptoSuite.encryptionKeyPair(seed(0x61))
) {
  const decoded = decodeRelayCapabilityAdvertisement(currentAdvertisement)
  const advertisementDigest = digestRelayCapabilityAdvertisement(currentAdvertisement)
  const admittedLimitsDigest = digestAdmittedLimits(requestedLimits)
  try {
    return encodeTailControlTranscript({
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
  } finally {
    b4a.fill(advertisementDigest, 0)
    b4a.fill(admittedLimitsDigest, 0)
    b4a.fill(decoded.relayIdentity, 0)
    b4a.fill(decoded.routeEncryptionPublicKey, 0)
  }
}

function initiatorSealLink(signedAdvertisement, requestedLimits, overrides = {}) {
  const currentAdvertisement = overrides.currentAdvertisement || signedAdvertisement
  const currentTailPair = cryptoSuite.encryptionKeyPair(seed(0x61))
  return syntheticLink({
    ...overrides,
    initiator: true,
    extensionIndex: 1,
    clientTailEphemeralSecretKey: currentTailPair.secretKey,
    tailControlTranscript: initiatorTailControlTranscript(
      currentAdvertisement,
      requestedLimits,
      currentTailPair
    )
  })
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
  t.exception(() => createTailControlSession(adopted.tail, tailSessionOptions(clock)))
  t.is(revokeM3TailCapability(adopted.tail), false)
  t.exception(() => borrowTailControlTransport(Object.freeze({})))
  t.is(clock.pending(), 2, 'TailControl arms one independent logical lifetime')
  t.is(destroyTailControlSession(session), true)
  t.is(destroyTailControlSession(session), false)
  t.is(clock.pending(), 1, 'destroy cancels only the TailControl lifetime')
})

test('TailControl transport destroy rejects a pending registered M3 receive', async (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const physicalChannel = Object.freeze({
    send() {
      return true
    },
    receive() {
      return new Promise(() => {})
    },
    destroy() {}
  })
  const adopted = owner.adopt(syntheticLink({ physicalChannel, wireExpiresAt: 1_250n }))
  const session = createTailControlSession(adopted.tail, tailSessionOptions(clock))
  const pending = borrowTailControlTransport(session).receive()
  await Promise.resolve()
  t.is(destroyTailControlSession(session), true)
  let code = null
  try {
    await pending
  } catch (err) {
    code = err && err.code
  } finally {
    adopted.runtime.destroy()
  }
  t.is(code, 'ERR_DESTROYED', 'logical release rejects the pending receive waiter')
  t.is(clock.pending(), 0, 'runtime and TailControl timers are cleared')
})

test('TailControl receive resolves buffered ordered envelopes to existing waiters', async (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const outbound = []
  const inbound = []
  const initiatorChannel = Object.freeze({
    send(packet) {
      outbound.push(b4a.from(packet))
      return true
    },
    receive() {
      return new Promise(() => {})
    },
    destroy() {}
  })
  const responderChannel = Object.freeze({
    send() {
      return true
    },
    receive() {
      const next = inbound.shift()
      if (!next) throw new Error('missing physical receive slot')
      return next.promise
    },
    destroy() {}
  })
  const initiator = owner.adopt(
    syntheticLink({ initiator: true, physicalChannel: initiatorChannel, wireExpiresAt: 1_250n })
  )
  const responder = owner.adopt(
    syntheticLink({ initiator: false, physicalChannel: responderChannel, wireExpiresAt: 1_250n })
  )
  const initiatorSession = createTailControlSession(initiator.tail, tailSessionOptions(clock))
  const responderSession = createTailControlSession(responder.tail, tailSessionOptions(clock))
  try {
    await borrowTailControlTransport(initiatorSession).send(seed(0xa1, 1101))
    await borrowTailControlTransport(initiatorSession).send(seed(0xa2, 1101))
    t.is(outbound.length, 2, 'two physical packets are available for reordering')
    let firstPhysicalResolve = null
    let secondPhysicalResolve = null
    inbound.push({
      promise: new Promise((resolve) => {
        firstPhysicalResolve = resolve
      })
    })
    inbound.push({
      promise: new Promise((resolve) => {
        secondPhysicalResolve = resolve
      })
    })
    const first = borrowTailControlTransport(responderSession).receive()
    const second = borrowTailControlTransport(responderSession).receive()
    let firstValue = null
    let secondValue = null
    first.catch(() => {})
    second.catch(() => {})
    await Promise.resolve()
    firstPhysicalResolve(outbound[1])
    await Promise.resolve()
    secondPhysicalResolve(outbound[0])
    firstValue = await first
    secondValue = await second
    t.alike(firstValue, seed(0xa1, 1101), 'oldest waiter receives the first logical envelope')
    t.alike(secondValue, seed(0xa2, 1101), 'second waiter receives the buffered logical envelope')
  } finally {
    destroyTailControlSession(initiatorSession)
    destroyTailControlSession(responderSession)
    initiator.runtime.destroy()
    responder.runtime.destroy()
  }
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
    createTailControlResponderAuthority(
      session,
      adopted.responderToken,
      responderAuthorityOptions(clock)
    )
  )
  t.is(destroyTailControlResponderAuthority(responder), true)
  t.is(destroyTailControlResponderAuthority(responder), false)
  t.is(clock.pending(), 2, 'authority destroy cancels only the subordinate lifetime')
  t.is(destroyTailControlSession(session), true)
})

test('TailControl terminal responder authority requires only readiness capabilities', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const adopted = owner.adopt(
    syntheticLink({ initiator: false, extensionIndex: 2, wireExpiresAt: 20_000n })
  )
  const session = createTailControlSession(adopted.tail, tailSessionOptions(clock))
  const options = responderAuthorityOptions(clock)
  delete options.adjacencyAdopter
  delete options.extensionCommitter
  delete options.adjacentLinkFactory

  const responder = createTailControlResponderAuthority(session, adopted.responderToken, options)

  t.alike(Reflect.ownKeys(responder), [])
  t.is(Object.isFrozen(responder), true)
  t.is(clock.pending(), 3, 'terminal responder authority arms readiness lifetime')
  t.exception(() =>
    createTailControlResponderAuthority(
      session,
      adopted.responderToken,
      responderAuthorityOptions(clock)
    )
  )
  t.is(destroyTailControlResponderAuthority(responder), true)
  t.is(destroyTailControlSession(session), true)
})

test('TailControl responder authority rejects initiators, token substitutes, and alternate clocks', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const initiator = owner.adopt(syntheticLink({ initiator: true, wireExpiresAt: 20_000n }))
  const initiatorSession = createTailControlSession(
    initiator.tail,
    tailSessionOptions(clock, {
      absoluteDeadline: 16_000n
    })
  )
  t.exception(() =>
    createTailControlResponderAuthority(
      initiatorSession,
      Object.freeze({}),
      responderAuthorityOptions(clock)
    )
  )
  t.is(destroyTailControlSession(initiatorSession), true)

  const substitute = owner.adopt(
    syntheticLink({
      initiator: false,
      completeOfferDigest: seed(0x81),
      wireExpiresAt: 20_000n
    })
  )
  const substituteSession = createTailControlSession(substitute.tail, tailSessionOptions(clock))
  t.exception(() =>
    createTailControlResponderAuthority(
      substituteSession,
      Object.freeze({}),
      responderAuthorityOptions(clock)
    )
  )
  t.is(destroyTailControlSession(substituteSession), true)

  const alternate = owner.adopt(
    syntheticLink({
      initiator: false,
      completeOfferDigest: seed(0x82),
      wireExpiresAt: 20_000n
    })
  )
  const alternateSession = createTailControlSession(alternate.tail, tailSessionOptions(clock))
  t.exception(() =>
    createTailControlResponderAuthority(
      alternateSession,
      alternate.responderToken,
      responderAuthorityOptions(clock, {
        monotonicNow: () => 10_000n
      })
    )
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
  const initiator = initiatorOwner.adopt(
    initiatorSealLink(signedAdvertisement, requestedLimits, {
      currentAdvertisement,
      physicalChannel: initiatorChannel,
      wireExpiresAt: 20_000n
    })
  )
  const responder = responderOwner.adopt(
    responderSealLink(signedAdvertisement, requestedLimits, {
      currentAdvertisement,
      physicalChannel: responderChannel,
      wireExpiresAt: 20_000n
    })
  )
  const initiatorSession = createTailControlSession(
    initiator.tail,
    tailSessionOptions(initiatorClock, {
      absoluteDeadline: 16_000n,
      crypto: cryptoSuite
    })
  )
  const responderSession = createTailControlSession(
    responder.tail,
    tailSessionOptions(responderClock)
  )
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

  t.exception(
    () => admitTailExtend(responderAuthority, b4a.from(received)),
    'a structural envelope copy is not registered'
  )
  const admitted = admitTailExtend(responderAuthority, received)
  t.alike(Reflect.ownKeys(admitted), [])
  t.ok(Object.isFrozen(admitted))

  const taken = takeAdmittedExtendRequest(admitted)
  t.alike(Object.keys(taken).sort(), [
    'currentTailAdvertisementDigest',
    'currentTailIdentity',
    'localDeadline',
    'request',
    'wireExpiresAt'
  ])
  t.is(taken.wireExpiresAt, 5_000n)
  t.is(taken.localDeadline, readTailControlDeadline(responderSession))
  t.alike(taken.request, decodeExtendRequest(encoded))
  const decodedNextAdvertisement = decodeRelayCapabilityAdvertisement(taken.request.advertisement)
  t.ok(!b4a.equals(taken.currentTailIdentity, decodedNextAdvertisement.relayIdentity))
  t.ok(
    !b4a.equals(
      taken.currentTailAdvertisementDigest,
      digestRelayCapabilityAdvertisement(taken.request.advertisement)
    )
  )
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

test('TailControl responder opens, completes, and seals tail readiness from admitted ownership', async (t) => {
  const { createM3ResponderAdopter } = require('../../lib/private/m3-adjacency-adopter')
  const { createTailExtensionCommitter } = require('../../lib/private/tail-extension-committer')
  const relayIdentitySigner = require('../../lib/private/relay-identity-signer')
  const originalOpenExtensionAdjacentLink = guardLinks.openExtensionAdjacentLink
  const originalSignTailReady = relayIdentitySigner.signTailReady
  const initiatorClock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const responderClock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const initiatorOwner = authority(initiatorClock)
  const responderOwner = authority(responderClock)
  const [initiatorChannel, responderChannel] = channelPair()
  const currentAdvertisement = advertisementForRole(ROLE.SAFETY)
  const signedAdvertisement = advertisementForRole(ROLE.PRIVATE)
  const decodedAdvertisement = decodeRelayCapabilityAdvertisement(signedAdvertisement)
  const currentDecodedAdvertisement = decodeRelayCapabilityAdvertisement(currentAdvertisement)
  const requestedLimits = Object.freeze({
    cellSize: 1200,
    maxCells: 64,
    maxBytes: 65_536,
    maxCommands: 10,
    idleTimeoutMs: 5_000,
    expiresAtMs: 5_000n
  })
  const redactedProof = encodeM3Object({
    messageId: M3_MESSAGE_ID.REDACTED_RESPONDER_PROOF_V1,
    body: seed(0x91, 306),
    authSuffix: seed(0x92, 64)
  })
  let adopterEstablished = null
  let installedRuntime = null
  let enqueuedEnvelope = null
  let forwardingDestroyed = 0
  let completionDestroyed = 0
  let replayDuringOpen = null
  try {
    const initiator = initiatorOwner.adopt(
      initiatorSealLink(signedAdvertisement, requestedLimits, {
        currentAdvertisement,
        physicalChannel: initiatorChannel,
        wireExpiresAt: 20_000n
      })
    )
    const responder = responderOwner.adopt(
      responderSealLink(signedAdvertisement, requestedLimits, {
        currentAdvertisement,
        physicalChannel: responderChannel,
        wireExpiresAt: 20_000n
      })
    )
    const initiatorSession = createTailControlSession(
      initiator.tail,
      tailSessionOptions(initiatorClock, {
        absoluteDeadline: 16_000n,
        crypto: cryptoSuite
      })
    )
    const responderSession = createTailControlSession(
      responder.tail,
      tailSessionOptions(responderClock)
    )
    const adjacencyAdopter = createM3ResponderAdopter(
      (established) => {
        adopterEstablished = established
        return Object.freeze({ tag: 'next-runtime' })
      },
      () => {}
    )
    const extensionCommitter = createTailExtensionCommitter({
      enqueue(envelope) {
        enqueuedEnvelope = b4a.from(envelope)
      },
      install(runtime) {
        installedRuntime = runtime
        return Object.freeze({
          diagnostics() {
            return Object.freeze({})
          },
          destroy() {
            forwardingDestroyed++
          }
        })
      },
      destroy() {}
    })
    const adjacentLinkFactory = Object.freeze({})
    const tailReadySigner = Object.freeze({})
    const responderAuthority = createTailControlResponderAuthority(
      responderSession,
      responder.responderToken,
      responderAuthorityOptions(responderClock, {
        adjacencyAdopter,
        extensionCommitter,
        adjacentLinkFactory,
        tailReadySigner,
        randomBytes: (size) => {
          t.is(size, 32)
          return seed(0xf5)
        }
      })
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
    const request = decodeExtendRequest(encoded)
    const expectedProof = {
      responderAdvertisementDigest: digestRelayCapabilityAdvertisement(signedAdvertisement),
      initiatorIdentity: currentDecodedAdvertisement.relayIdentity,
      responderIdentity: decodedAdvertisement.relayIdentity,
      branchClass: request.branchClass,
      branchId: request.branchId,
      circuitId: request.circuitId,
      generation: request.generation,
      extensionIndex: request.extensionIndex,
      clientTailEphemeralPublicKey: request.clientTailEphemeralPublicKey,
      clientNonce: request.clientNonce,
      advertisedRouteEncryptionPublicKey: decodedAdvertisement.routeEncryptionPublicKey,
      admittedLimitsDigest: digestAdmittedLimits(requestedLimits),
      expiresAtMs: requestedLimits.expiresAtMs,
      responderProofNonce: seed(0x93)
    }
    const established = Object.freeze({ tag: 'established-link' })
    const completion = createExtensionLinkCompletion(
      {
        established,
        verifiedProof: Object.freeze({ tag: 'proof' }),
        proofConsumer: Object.freeze({ tag: 'consumer' }),
        expectedProof,
        redactedProof,
        extensionNonce: request.extensionNonce
      },
      () => {
        completionDestroyed++
      }
    )
    guardLinks.openExtensionAdjacentLink = (factory, admittedRequest) => {
      t.is(factory, adjacentLinkFactory)
      const taken = takeAdmittedExtendRequest(admittedRequest)
      t.alike(taken.request, request)
      replayDuringOpen = errorCode(() => takeAdmittedExtendRequest(admittedRequest))
      return Promise.resolve(completion)
    }
    relayIdentitySigner.signTailReady = (signer, body, expectedIdentity) => {
      t.is(signer, tailReadySigner)
      t.is(body.byteLength, 210)
      t.alike(expectedIdentity, decodedAdvertisement.relayIdentity)
      return seed(0xb7, 64)
    }
    await borrowTailControlTransport(initiatorSession).send(tailControlEnvelope(encoded))
    const received = await borrowTailControlTransport(responderSession).receive()
    const admitted = admitTailExtend(responderAuthority, received)
    const openedCompletion = await openTailAdjacentLink(responderAuthority, admitted)
    t.is(openedCompletion, completion)
    t.is(replayDuringOpen, 'INVALID_ROUTE')
    const extendedEnvelope = completeTailExtend(responderAuthority, openedCompletion)
    t.alike(enqueuedEnvelope, extendedEnvelope)
    t.is(adopterEstablished, established)
    t.alike(installedRuntime, Object.freeze({ tag: 'next-runtime' }))
    const extended = decodeExtended(extendedEnvelope.subarray(1, 1 + EXTENDED_SIZE))
    t.alike(extended.redactedProof, redactedProof)
    t.alike(extended.extensionNonce, request.extensionNonce)
    t.is(completionDestroyed, 1)
    const ready = decodeTailReady(sealTailReady(responderAuthority))
    t.alike(ready.tailIdentity, decodedAdvertisement.relayIdentity)
    t.alike(ready.tailAdvertisementDigest, expectedProof.responderAdvertisementDigest)
    t.alike(ready.clientNonce, request.clientNonce)
    t.alike(ready.signature, seed(0xb7, 64))
    t.is(destroyTailControlResponderAuthority(responderAuthority), true)
    t.is(forwardingDestroyed, 1)
    t.is(destroyTailControlSession(initiatorSession), true)
    t.is(destroyTailControlSession(responderSession), true)
  } finally {
    guardLinks.openExtensionAdjacentLink = originalOpenExtensionAdjacentLink
    relayIdentitySigner.signTailReady = originalSignTailReady
    b4a.fill(decodedAdvertisement.relayIdentity, 0)
    b4a.fill(decodedAdvertisement.routeEncryptionPublicKey, 0)
    b4a.fill(currentDecodedAdvertisement.relayIdentity, 0)
    b4a.fill(redactedProof, 0)
  }
})

test('TailControl complete rejects responder authority destroyed during install', async (t) => {
  const { createM3ResponderAdopter } = require('../../lib/private/m3-adjacency-adopter')
  const { createTailExtensionCommitter } = require('../../lib/private/tail-extension-committer')
  const originalOpenExtensionAdjacentLink = guardLinks.openExtensionAdjacentLink
  const initiatorClock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const responderClock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const initiatorOwner = authority(initiatorClock)
  const responderOwner = authority(responderClock)
  const [initiatorChannel, responderChannel] = channelPair()
  const currentAdvertisement = advertisementForRole(ROLE.SAFETY)
  const signedAdvertisement = advertisementForRole(ROLE.PRIVATE)
  const decodedAdvertisement = decodeRelayCapabilityAdvertisement(signedAdvertisement)
  const currentDecodedAdvertisement = decodeRelayCapabilityAdvertisement(currentAdvertisement)
  const requestedLimits = Object.freeze({
    cellSize: 1200,
    maxCells: 64,
    maxBytes: 65_536,
    maxCommands: 10,
    idleTimeoutMs: 5_000,
    expiresAtMs: 5_000n
  })
  const redactedProof = encodeM3Object({
    messageId: M3_MESSAGE_ID.REDACTED_RESPONDER_PROOF_V1,
    body: seed(0x91, 306),
    authSuffix: seed(0x92, 64)
  })
  let responderAuthority = null
  let forwardingDestroyed = 0
  let adoptedRuntimeDestroyed = 0
  let completionDestroyed = 0
  try {
    const initiator = initiatorOwner.adopt(
      initiatorSealLink(signedAdvertisement, requestedLimits, {
        currentAdvertisement,
        physicalChannel: initiatorChannel,
        wireExpiresAt: 20_000n
      })
    )
    const responder = responderOwner.adopt(
      responderSealLink(signedAdvertisement, requestedLimits, {
        currentAdvertisement,
        physicalChannel: responderChannel,
        wireExpiresAt: 20_000n
      })
    )
    const initiatorSession = createTailControlSession(
      initiator.tail,
      tailSessionOptions(initiatorClock, {
        absoluteDeadline: 16_000n,
        crypto: cryptoSuite
      })
    )
    const responderSession = createTailControlSession(
      responder.tail,
      tailSessionOptions(responderClock)
    )
    const adjacencyAdopter = createM3ResponderAdopter(
      () => Object.freeze({ tag: 'next-runtime' }),
      () => {
        adoptedRuntimeDestroyed++
      }
    )
    const extensionCommitter = createTailExtensionCommitter({
      enqueue() {},
      install() {
        destroyTailControlResponderAuthority(responderAuthority)
        return Object.freeze({
          diagnostics() {
            return Object.freeze({})
          },
          destroy() {
            forwardingDestroyed++
            adoptedRuntimeDestroyed++
          }
        })
      },
      destroy() {}
    })
    responderAuthority = createTailControlResponderAuthority(
      responderSession,
      responder.responderToken,
      responderAuthorityOptions(responderClock, {
        adjacencyAdopter,
        extensionCommitter,
        adjacentLinkFactory: Object.freeze({}),
        tailReadySigner: Object.freeze({})
      })
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
    const request = decodeExtendRequest(encoded)
    const expectedProof = {
      responderAdvertisementDigest: digestRelayCapabilityAdvertisement(signedAdvertisement),
      initiatorIdentity: currentDecodedAdvertisement.relayIdentity,
      responderIdentity: decodedAdvertisement.relayIdentity,
      branchClass: request.branchClass,
      branchId: request.branchId,
      circuitId: request.circuitId,
      generation: request.generation,
      extensionIndex: request.extensionIndex,
      clientTailEphemeralPublicKey: request.clientTailEphemeralPublicKey,
      clientNonce: request.clientNonce,
      advertisedRouteEncryptionPublicKey: decodedAdvertisement.routeEncryptionPublicKey,
      admittedLimitsDigest: digestAdmittedLimits(requestedLimits),
      expiresAtMs: requestedLimits.expiresAtMs,
      responderProofNonce: seed(0x93)
    }
    const completion = createExtensionLinkCompletion(
      {
        established: Object.freeze({ tag: 'established-link' }),
        verifiedProof: Object.freeze({ tag: 'proof' }),
        proofConsumer: Object.freeze({ tag: 'consumer' }),
        expectedProof,
        redactedProof,
        extensionNonce: request.extensionNonce
      },
      () => {
        completionDestroyed++
      }
    )
    guardLinks.openExtensionAdjacentLink = () => Promise.resolve(completion)
    await borrowTailControlTransport(initiatorSession).send(tailControlEnvelope(encoded))
    const received = await borrowTailControlTransport(responderSession).receive()
    const admitted = admitTailExtend(responderAuthority, received)
    const openedCompletion = await openTailAdjacentLink(responderAuthority, admitted)
    t.is(openedCompletion, completion)
    let code = null
    try {
      completeTailExtend(responderAuthority, openedCompletion)
    } catch (err) {
      code = err && err.code
    }
    t.is(code, 'ERR_DESTROYED', 'destroyed authority cannot publish EXTENDED')
    t.is(forwardingDestroyed, 1, 'forwarding returned by reentrant install is destroyed')
    t.is(adoptedRuntimeDestroyed, 1, 'adopted M3 responder runtime is destroyed')
    t.is(completionDestroyed, 1, 'completion ownership is consumed exactly once')
    t.is(destroyTailControlResponderAuthority(responderAuthority), false)
    t.is(destroyTailControlSession(initiatorSession), true)
    t.is(destroyTailControlSession(responderSession), true)
  } finally {
    guardLinks.openExtensionAdjacentLink = originalOpenExtensionAdjacentLink
    b4a.fill(decodedAdvertisement.relayIdentity, 0)
    b4a.fill(decodedAdvertisement.routeEncryptionPublicKey, 0)
    b4a.fill(currentDecodedAdvertisement.relayIdentity, 0)
    b4a.fill(redactedProof, 0)
  }
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
  const makeEncoded = (limits, nonce) =>
    encodeExtendRequest({
      branchClass: BRANCH_CLASS.LOOKUP,
      branchId: seed(0x41, 16),
      circuitId: seed(0x42, 16),
      generation: 7n,
      extensionIndex: 2,
      advertisement: signedAdvertisement,
      clientTailEphemeralPublicKey: cryptoSuite.encryptionKeyPair(seed(0x70 + nonce)).publicKey,
      clientNonce: seed(0x80 + nonce),
      payloadParametersDigest: digestPayloadParameters(
        decodeRelayCapabilityAdvertisement(signedAdvertisement)
      ),
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
    const initiator = initiatorOwner.adopt(
      initiatorSealLink(signedAdvertisement, transcriptAdmittedLimits, {
        currentAdvertisement,
        physicalChannel: initiatorChannel,
        wireExpiresAt: 20_000n
      })
    )
    const responder = responderOwner.adopt(
      responderSealLink(signedAdvertisement, transcriptAdmittedLimits, {
        currentAdvertisement,
        physicalChannel: responderChannel,
        wireExpiresAt: 20_000n
      })
    )
    const initiatorSession = createTailControlSession(
      initiator.tail,
      tailSessionOptions(initiatorClock, {
        absoluteDeadline: 16_000n,
        crypto: cryptoSuite
      })
    )
    const responderSession = createTailControlSession(
      responder.tail,
      tailSessionOptions(responderClock)
    )
    const responderAuthority = createTailControlResponderAuthority(
      responderSession,
      responder.responderToken,
      responderAuthorityOptions(responderClock)
    )
    await borrowTailControlTransport(initiatorSession).send(
      tailControlEnvelope(makeEncoded(limits, expectedCode.length))
    )
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
  const initiator = initiatorOwner.adopt(
    initiatorSealLink(signedAdvertisement, requestedLimits, {
      currentAdvertisement,
      physicalChannel: initiatorChannel,
      wireExpiresAt: 20_000n
    })
  )
  const responder = responderOwner.adopt(
    responderSealLink(signedAdvertisement, requestedLimits, {
      currentAdvertisement,
      physicalChannel: responderChannel,
      wireExpiresAt: 20_000n
    })
  )
  const initiatorSession = createTailControlSession(
    initiator.tail,
    tailSessionOptions(initiatorClock, {
      absoluteDeadline: 16_000n,
      crypto: cryptoSuite
    })
  )
  const responderSession = createTailControlSession(
    responder.tail,
    tailSessionOptions(responderClockWithReentry)
  )
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
  const initiator = initiatorOwner.adopt(
    initiatorSealLink(signedAdvertisement, requestedLimits, {
      currentAdvertisement,
      physicalChannel: initiatorChannel,
      wireExpiresAt: 20_000n
    })
  )
  const responder = responderOwner.adopt(
    responderSealLink(signedAdvertisement, requestedLimits, {
      currentAdvertisement,
      physicalChannel: responderChannel,
      wireExpiresAt: 20_000n
    })
  )
  const initiatorSession = createTailControlSession(
    initiator.tail,
    tailSessionOptions(initiatorClock, {
      absoluteDeadline: 29_000n,
      crypto: cryptoSuite
    })
  )
  const responderSession = createTailControlSession(
    responder.tail,
    tailSessionOptions(responderClock)
  )
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
  t.is(taken.wireExpiresAt, 20_000n)
  t.is(taken.localDeadline, 29_000n)
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
    createTailControlSession(
      adopted.tail,
      tailSessionOptions(clock, {
        wallNow: () => 1_000n
      })
    )
  )

  const missingDeadline = owner.adopt(
    syntheticLink({
      completeOfferDigest: seed(0x72),
      wireExpiresAt: 1_250n
    })
  )
  const noDeadline = {
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled
  }
  t.exception(() => createTailControlSession(missingDeadline.tail, noDeadline))

  const second = owner.adopt(
    syntheticLink({ completeOfferDigest: seed(0x71), wireExpiresAt: 1_250n })
  )
  t.exception(() =>
    createTailControlSession(
      second.tail,
      tailSessionOptions(clock, {
        destroy() {}
      })
    )
  )
})

test('TailControl transport sends and receives only through M3-owned control cells', async (t) => {
  const initiatorClock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const responderClock = fakeClock({ wall: 1_000n, monotonic: 20_000n })
  const initiatorOwner = authority(initiatorClock)
  const responderOwner = authority(responderClock)
  const [initiatorChannel, responderChannel] = channelPair()
  const initiator = initiatorOwner.adopt(
    syntheticLink({
      physicalChannel: initiatorChannel,
      wireExpiresAt: 1_250n
    })
  )
  const responder = responderOwner.adopt(
    syntheticLink({
      initiator: false,
      physicalChannel: responderChannel,
      wireExpiresAt: 1_250n
    })
  )
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
  const adopted = owner.adopt(
    syntheticLink({
      physicalChannel,
      wireExpiresAt: 1_250n
    })
  )
  const session = createTailControlSession(
    adopted.tail,
    tailSessionOptions(clock, {
      absoluteDeadline: 10_100n
    })
  )

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
    createTailControlSession(
      adopted.tail,
      tailSessionOptions(clock, {
        schedule: reentrantSchedule,
        cancelScheduled
      })
    )
  )
  t.alike(cancelled, [99])
  t.is(revokeM3TailCapability(adopted.tail), false)
})

test('TailControlSession arms far deadlines with platform-safe chunks', (t) => {
  const maxTimerDelay = 0x7fff_ffff
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const adopted = owner.adopt(
    syntheticLink({
      wireExpiresAt: 1_000n + BigInt(maxTimerDelay) + 5n
    })
  )
  const session = createTailControlSession(
    adopted.tail,
    tailSessionOptions(clock, {
      absoluteDeadline: 10_000n + BigInt(maxTimerDelay) + 5n
    })
  )

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
  const adopted = owner.adopt(
    syntheticLink({
      wireExpiresAt: 1_000n + BigInt(maxTimerDelay) + 5n
    })
  )
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
    session = createTailControlSession(
      adopted.tail,
      tailSessionOptions(clock, {
        absoluteDeadline: 10_000n + BigInt(maxTimerDelay) + 5n,
        schedule,
        cancelScheduled
      })
    )

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
  const adopted = owner.adopt(
    syntheticLink({
      wireExpiresAt: 1_000n + BigInt(maxTimerDelay) + 5n
    })
  )
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
    session = createTailControlSession(
      adopted.tail,
      tailSessionOptions(clock, {
        absoluteDeadline: 10_000n + BigInt(maxTimerDelay) + 5n,
        schedule
      })
    )

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
  const adopted = owner.adopt(
    initiatorSealLink(signedAdvertisement, requestedLimits, {
      currentAdvertisement,
      wireExpiresAt: 20_000n
    })
  )
  const randomSeeds = [seed(0x70), seed(0x71), seed(0x72)]
  const randomBytes = (size) => {
    t.is(size, 32)
    return randomSeeds.shift()
  }
  const session = createTailControlSession(
    adopted.tail,
    tailSessionOptions(clock, {
      absoluteDeadline: 16_000n,
      crypto: cryptoSuite
    })
  )
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

test('TailControl initiator keeps completion reusable after rejected ready', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const currentAdvertisement = advertisementForRole(ROLE.SAFETY)
  let responderSeed = null
  for (let byte = 0x50; byte <= 0xff; byte++) {
    const pair = cryptoSuite.keyPair(seed(byte))
    if (roleForIdentity(pair.publicKey) === ROLE.PRIVATE) {
      responderSeed = byte
      break
    }
  }
  const responder = cryptoSuite.keyPair(seed(responderSeed))
  const signedAdvertisement = advertisement(responderSeed)
  const decodedAdvertisement = decodeRelayCapabilityAdvertisement(signedAdvertisement)
  const currentDecodedAdvertisement = decodeRelayCapabilityAdvertisement(currentAdvertisement)
  const requestedLimits = Object.freeze({
    cellSize: 1200,
    maxCells: 64,
    maxBytes: 65_536,
    maxCommands: 10,
    idleTimeoutMs: 5_000,
    expiresAtMs: 5_000n
  })
  const admittedLimitsDigest = digestAdmittedLimits(requestedLimits)
  const transcriptDigest = tailReadyTranscriptDigest(
    initiatorTailControlTranscript(currentAdvertisement, requestedLimits)
  )
  const owner = authority(clock)
  const adopted = owner.adopt(
    initiatorSealLink(signedAdvertisement, requestedLimits, {
      currentAdvertisement,
      wireExpiresAt: 20_000n
    })
  )
  const session = createTailControlSession(
    adopted.tail,
    tailSessionOptions(clock, {
      absoluteDeadline: 16_000n,
      crypto: cryptoSuite
    })
  )
  const randomSeeds = [seed(0x90), seed(0x91), seed(0x92)]
  const encoded = session.sealExtend({
    advertisement: signedAdvertisement,
    advertisementDigest: digestRelayCapabilityAdvertisement(signedAdvertisement),
    extensionIndex: 2,
    requestedLimits,
    absoluteDeadline: 16_000n,
    randomBytes: (size) => {
      t.is(size, 32)
      return randomSeeds.shift()
    }
  })
  const request = decodeExtendRequest(encoded)
  const proofValue = {
    responderAdvertisementDigest: digestRelayCapabilityAdvertisement(signedAdvertisement),
    initiatorIdentity: currentDecodedAdvertisement.relayIdentity,
    responderIdentity: decodedAdvertisement.relayIdentity,
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: request.branchId,
    circuitId: request.circuitId,
    generation: request.generation,
    extensionIndex: request.extensionIndex,
    clientTailEphemeralPublicKey: request.clientTailEphemeralPublicKey,
    clientNonce: request.clientNonce,
    advertisedRouteEncryptionPublicKey: decodedAdvertisement.routeEncryptionPublicKey,
    admittedLimitsDigest,
    expiresAtMs: 4_500n,
    responderProofNonce: seed(0x93)
  }
  const redactedProof = signRedactedResponderProof(proofValue, responder.secretKey)
  const proofObject = decodeM3Object(redactedProof)
  const extended = {
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: request.branchId,
    circuitId: request.circuitId,
    generation: request.generation,
    extensionIndex: request.extensionIndex,
    responderAdvertisementDigest: proofValue.responderAdvertisementDigest,
    redactedProof,
    extensionNonce: request.extensionNonce
  }
  t.exception(
    () =>
      session.openExtended(
        encodeExtended({
          ...extended,
          redactedProof: encodeM3Object({
            messageId: M3_MESSAGE_ID.REDACTED_RESPONDER_PROOF_V1,
            body: proofObject.body,
            authSuffix: seed(0x94, 64)
          })
        })
      ),
    'a forged redacted responder proof is rejected'
  )
  const completion = session.openExtended(encodeExtended(extended))
  t.exception(
    () =>
      session.completeClientExtension(
        completion,
        encodeTailReadyFor(extended, request, responder, {
          transcriptDigest,
          expiresAtMs: proofValue.expiresAtMs,
          signature: seed(0xa4, 64)
        })
      ),
    'a forged TAIL_READY signature is rejected'
  )
  t.exception(
    () =>
      session.completeClientExtension(
        completion,
        encodeTailReadyFor(extended, request, responder, {
          transcriptDigest: seed(0xa5),
          expiresAtMs: proofValue.expiresAtMs
        })
      ),
    'a wrong TAIL_READY transcript digest is rejected'
  )
  t.exception(
    () =>
      session.completeClientExtension(
        completion,
        encodeTailReadyFor(extended, request, responder, {
          transcriptDigest,
          clientNonce: seed(0xff),
          expiresAtMs: proofValue.expiresAtMs
        })
      ),
    'a mismatched TAIL_READY client nonce is rejected'
  )
  const preFinalTransport = borrowTailControlTransport(session)
  t.is(
    session.completeClientExtension(
      completion,
      encodeTailReadyFor(extended, request, responder, {
        transcriptDigest,
        expiresAtMs: proofValue.expiresAtMs
      })
    ),
    session
  )
  t.exception(
    () => borrowTailControlTransport(session),
    'final-exit readiness closes tail transport'
  )
  t.exception(
    () => preFinalTransport.send(seed(0x74, 1101)),
    'final-exit readiness closes borrowed transport sends'
  )
  t.exception(
    () => preFinalTransport.receive(),
    'final-exit readiness closes borrowed transport receives'
  )
  t.exception(
    () =>
      session.sealExtend({
        advertisement: signedAdvertisement,
        advertisementDigest: digestRelayCapabilityAdvertisement(signedAdvertisement),
        extensionIndex: 2,
        requestedLimits,
        absoluteDeadline: 16_000n,
        randomBytes: () => seed(0x73)
      }),
    'final-exit readiness closes further extension'
  )
  const expiryClock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const expiryOwner = authority(expiryClock)
  const expiryAdopted = expiryOwner.adopt(
    initiatorSealLink(signedAdvertisement, requestedLimits, {
      currentAdvertisement,
      wireExpiresAt: 20_000n
    })
  )
  const expirySession = createTailControlSession(
    expiryAdopted.tail,
    tailSessionOptions(expiryClock, {
      absoluteDeadline: 16_000n,
      crypto: cryptoSuite
    })
  )
  const expiryRandomSeeds = [seed(0x90), seed(0x91), seed(0x92)]
  const expiryEncoded = expirySession.sealExtend({
    advertisement: signedAdvertisement,
    advertisementDigest: digestRelayCapabilityAdvertisement(signedAdvertisement),
    extensionIndex: 2,
    requestedLimits,
    absoluteDeadline: 16_000n,
    randomBytes: (size) => {
      t.is(size, 32)
      return expiryRandomSeeds.shift()
    }
  })
  const expiryRequest = decodeExtendRequest(expiryEncoded)
  const expiryProofValue = {
    responderAdvertisementDigest: digestRelayCapabilityAdvertisement(signedAdvertisement),
    initiatorIdentity: currentDecodedAdvertisement.relayIdentity,
    responderIdentity: decodedAdvertisement.relayIdentity,
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: expiryRequest.branchId,
    circuitId: expiryRequest.circuitId,
    generation: expiryRequest.generation,
    extensionIndex: expiryRequest.extensionIndex,
    clientTailEphemeralPublicKey: expiryRequest.clientTailEphemeralPublicKey,
    clientNonce: expiryRequest.clientNonce,
    advertisedRouteEncryptionPublicKey: decodedAdvertisement.routeEncryptionPublicKey,
    admittedLimitsDigest,
    expiresAtMs: 4_500n,
    responderProofNonce: seed(0x93)
  }
  const expiryExtended = {
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: expiryRequest.branchId,
    circuitId: expiryRequest.circuitId,
    generation: expiryRequest.generation,
    extensionIndex: expiryRequest.extensionIndex,
    responderAdvertisementDigest: expiryProofValue.responderAdvertisementDigest,
    redactedProof: signRedactedResponderProof(expiryProofValue, responder.secretKey),
    extensionNonce: expiryRequest.extensionNonce
  }
  const expiryCompletion = expirySession.openExtended(encodeExtended(expiryExtended))
  t.is(
    expirySession.completeClientExtension(
      expiryCompletion,
      encodeTailReadyFor(expiryExtended, expiryRequest, responder, {
        transcriptDigest,
        expiresAtMs: expiryProofValue.expiresAtMs
      })
    ),
    expirySession
  )
  const expiringHandoff = expirySession.takeFinalExitHandoff()
  expiryClock.advance(16_000n)
  t.is(expiryClock.fireDelay(3_500), true)
  t.exception(() => consumeFinalExitHandoff(expiringHandoff), 'expired handoff is revoked')
  const directClock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const directOwner = authority(directClock)
  const directAdopted = directOwner.adopt(
    initiatorSealLink(signedAdvertisement, requestedLimits, {
      currentAdvertisement,
      wireExpiresAt: 20_000n
    })
  )
  const directSession = createTailControlSession(
    directAdopted.tail,
    tailSessionOptions(directClock, {
      absoluteDeadline: 16_000n,
      crypto: cryptoSuite
    })
  )
  const directRandomSeeds = [seed(0x90), seed(0x91), seed(0x92)]
  const directEncoded = directSession.sealExtend({
    advertisement: signedAdvertisement,
    advertisementDigest: digestRelayCapabilityAdvertisement(signedAdvertisement),
    extensionIndex: 2,
    requestedLimits,
    absoluteDeadline: 16_000n,
    randomBytes: (size) => {
      t.is(size, 32)
      return directRandomSeeds.shift()
    }
  })
  const directRequest = decodeExtendRequest(directEncoded)
  const directProofValue = {
    responderAdvertisementDigest: digestRelayCapabilityAdvertisement(signedAdvertisement),
    initiatorIdentity: currentDecodedAdvertisement.relayIdentity,
    responderIdentity: decodedAdvertisement.relayIdentity,
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: directRequest.branchId,
    circuitId: directRequest.circuitId,
    generation: directRequest.generation,
    extensionIndex: directRequest.extensionIndex,
    clientTailEphemeralPublicKey: directRequest.clientTailEphemeralPublicKey,
    clientNonce: directRequest.clientNonce,
    advertisedRouteEncryptionPublicKey: decodedAdvertisement.routeEncryptionPublicKey,
    admittedLimitsDigest,
    expiresAtMs: 4_500n,
    responderProofNonce: seed(0x93)
  }
  const directExtended = {
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: directRequest.branchId,
    circuitId: directRequest.circuitId,
    generation: directRequest.generation,
    extensionIndex: directRequest.extensionIndex,
    responderAdvertisementDigest: directProofValue.responderAdvertisementDigest,
    redactedProof: signRedactedResponderProof(directProofValue, responder.secretKey),
    extensionNonce: directRequest.extensionNonce
  }
  const directCompletion = directSession.openExtended(encodeExtended(directExtended))
  t.is(
    directSession.completeClientExtension(
      directCompletion,
      encodeTailReadyFor(directExtended, directRequest, responder, {
        transcriptDigest,
        expiresAtMs: directProofValue.expiresAtMs
      })
    ),
    directSession
  )
  const directHandoff = directSession.takeFinalExitHandoff()
  t.exception(
    () => consumeFinalExitHandoff(directHandoff),
    'bridge handoff requires activation claim'
  )

  const handoff = session.takeFinalExitHandoff()
  const claim = createFinalExitActivationClaim(handoff)
  const activationOwner = claimFinalExitActivation(handoff, claim)
  t.alike(Reflect.ownKeys(activationOwner), [])
  t.exception(
    () =>
      session.completeClientExtension(
        completion,
        encodeTailReadyFor(extended, request, responder, {
          transcriptDigest,
          expiresAtMs: proofValue.expiresAtMs
        })
      ),
    'accepted completion becomes spent'
  )
  t.exception(() => session.takeFinalExitHandoff(), 'handoff is one-shot')
  t.exception(() => consumeFinalExitHandoff(handoff), 'claimed handoff is spent')
  t.is(destroyFinalExitActivationOwner(activationOwner), true)
  t.is(destroyFinalExitActivationOwner(activationOwner), false)
  t.is(destroyTailControlSession(session), false)
})

test('TailControl initiator rejects ready at authenticated proof expiry', (t) => {
  const proofExpiresAt = 4_500n
  const clock = fakeClock({ wall: proofExpiresAt - 1n, monotonic: 10_000n })
  const currentAdvertisement = advertisementForRole(ROLE.SAFETY)
  let responderSeed = null
  for (let byte = 0x50; byte <= 0xff; byte++) {
    const pair = cryptoSuite.keyPair(seed(byte))
    if (roleForIdentity(pair.publicKey) === ROLE.PRIVATE) {
      responderSeed = byte
      break
    }
  }
  const responder = cryptoSuite.keyPair(seed(responderSeed))
  const signedAdvertisement = advertisement(responderSeed)
  const decodedAdvertisement = decodeRelayCapabilityAdvertisement(signedAdvertisement)
  const currentDecodedAdvertisement = decodeRelayCapabilityAdvertisement(currentAdvertisement)
  const requestedLimits = Object.freeze({
    cellSize: 1200,
    maxCells: 64,
    maxBytes: 65_536,
    maxCommands: 10,
    idleTimeoutMs: 5_000,
    expiresAtMs: 5_000n
  })
  const admittedLimitsDigest = digestAdmittedLimits(requestedLimits)
  const owner = authority(clock)
  const adopted = owner.adopt(
    initiatorSealLink(signedAdvertisement, requestedLimits, {
      currentAdvertisement,
      wireExpiresAt: 20_000n
    })
  )
  const session = createTailControlSession(
    adopted.tail,
    tailSessionOptions(clock, {
      absoluteDeadline: 16_000n,
      crypto: cryptoSuite
    })
  )
  const randomSeeds = [seed(0x90), seed(0x91), seed(0x92)]
  const encoded = session.sealExtend({
    advertisement: signedAdvertisement,
    advertisementDigest: digestRelayCapabilityAdvertisement(signedAdvertisement),
    extensionIndex: 2,
    requestedLimits,
    absoluteDeadline: 16_000n,
    randomBytes: () => randomSeeds.shift()
  })
  const request = decodeExtendRequest(encoded)
  const transcriptDigest = tailReadyTranscriptDigest(
    initiatorTailControlTranscript(currentAdvertisement, requestedLimits)
  )
  const proofValue = {
    responderAdvertisementDigest: digestRelayCapabilityAdvertisement(signedAdvertisement),
    initiatorIdentity: currentDecodedAdvertisement.relayIdentity,
    responderIdentity: decodedAdvertisement.relayIdentity,
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: request.branchId,
    circuitId: request.circuitId,
    generation: request.generation,
    extensionIndex: request.extensionIndex,
    clientTailEphemeralPublicKey: request.clientTailEphemeralPublicKey,
    clientNonce: request.clientNonce,
    advertisedRouteEncryptionPublicKey: decodedAdvertisement.routeEncryptionPublicKey,
    admittedLimitsDigest,
    expiresAtMs: proofExpiresAt,
    responderProofNonce: seed(0x93)
  }
  const extended = {
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: request.branchId,
    circuitId: request.circuitId,
    generation: request.generation,
    extensionIndex: request.extensionIndex,
    responderAdvertisementDigest: proofValue.responderAdvertisementDigest,
    redactedProof: signRedactedResponderProof(proofValue, responder.secretKey),
    extensionNonce: request.extensionNonce
  }
  const completion = session.openExtended(encodeExtended(extended))
  clock.advance(15_500n)
  let code = null
  try {
    session.completeClientExtension(
      completion,
      encodeTailReadyFor(extended, request, responder, {
        transcriptDigest,
        expiresAtMs: proofExpiresAt
      })
    )
  } catch (err) {
    code = err && err.code
  }
  t.is(code, 'ERR_PRIVACY_UNAVAILABLE', 'elapsed projected proof deadline is expiry')
  t.exception(() => readTailControlDeadline(session), 'elapsed proof projection releases tail')
  t.is(destroyTailControlSession(session), false)

  const underflowLimits = Object.freeze({
    ...requestedLimits,
    expiresAtMs: 16_000n
  })
  const underflowAdmittedLimitsDigest = digestAdmittedLimits(underflowLimits)
  const underflowTranscriptDigest = tailReadyTranscriptDigest(
    initiatorTailControlTranscript(currentAdvertisement, underflowLimits)
  )
  const underflowClock = fakeClock({ wall: 10_000n, monotonic: 1n })
  const underflowOwner = authority(underflowClock)
  const underflowAdopted = underflowOwner.adopt(
    initiatorSealLink(signedAdvertisement, underflowLimits, {
      currentAdvertisement,
      wireExpiresAt: 20_000n
    })
  )
  const underflowSession = createTailControlSession(
    underflowAdopted.tail,
    tailSessionOptions(underflowClock, {
      absoluteDeadline: 10_001n,
      crypto: cryptoSuite
    })
  )
  const underflowRandomSeeds = [seed(0x90), seed(0x91), seed(0x92)]
  const underflowEncoded = underflowSession.sealExtend({
    advertisement: signedAdvertisement,
    advertisementDigest: digestRelayCapabilityAdvertisement(signedAdvertisement),
    extensionIndex: 2,
    requestedLimits: underflowLimits,
    absoluteDeadline: 10_001n,
    randomBytes: () => underflowRandomSeeds.shift()
  })
  const underflowRequest = decodeExtendRequest(underflowEncoded)
  const underflowProofExpiresAt = 500n
  const underflowProofValue = {
    responderAdvertisementDigest: digestRelayCapabilityAdvertisement(signedAdvertisement),
    initiatorIdentity: currentDecodedAdvertisement.relayIdentity,
    responderIdentity: decodedAdvertisement.relayIdentity,
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: underflowRequest.branchId,
    circuitId: underflowRequest.circuitId,
    generation: underflowRequest.generation,
    extensionIndex: underflowRequest.extensionIndex,
    clientTailEphemeralPublicKey: underflowRequest.clientTailEphemeralPublicKey,
    clientNonce: underflowRequest.clientNonce,
    advertisedRouteEncryptionPublicKey: decodedAdvertisement.routeEncryptionPublicKey,
    admittedLimitsDigest: underflowAdmittedLimitsDigest,
    expiresAtMs: underflowProofExpiresAt,
    responderProofNonce: seed(0x93)
  }
  const underflowExtended = {
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: underflowRequest.branchId,
    circuitId: underflowRequest.circuitId,
    generation: underflowRequest.generation,
    extensionIndex: underflowRequest.extensionIndex,
    responderAdvertisementDigest: underflowProofValue.responderAdvertisementDigest,
    redactedProof: signRedactedResponderProof(underflowProofValue, responder.secretKey),
    extensionNonce: underflowRequest.extensionNonce
  }
  underflowClock.advanceWall(1n)
  const underflowCompletion = underflowSession.openExtended(encodeExtended(underflowExtended))
  code = null
  try {
    underflowSession.completeClientExtension(
      underflowCompletion,
      encodeTailReadyFor(underflowExtended, underflowRequest, responder, {
        transcriptDigest: underflowTranscriptDigest,
        expiresAtMs: underflowProofExpiresAt
      })
    )
  } catch (err) {
    code = err && err.code
  }
  t.is(code, 'ERR_PRIVACY_UNAVAILABLE', 'underflowed projected proof deadline is expiry')
  t.exception(
    () => readTailControlDeadline(underflowSession),
    'underflowed proof projection releases tail'
  )
  t.is(destroyTailControlSession(underflowSession), false)
})

test('TailControl completion destroys session when deadline rearm throws', (t) => {
  const baseClock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  let failTailRearm = false
  const clock = {
    wallNow: baseClock.wallNow,
    monotonicNow: baseClock.monotonicNow,
    schedule(callback, delay) {
      if (failTailRearm) {
        failTailRearm = false
        throw new Error('injected rearm failure')
      }
      return baseClock.schedule(callback, delay)
    },
    cancelScheduled: baseClock.cancelScheduled,
    pending: baseClock.pending
  }
  const currentAdvertisement = advertisementForRole(ROLE.SAFETY)
  let responderSeed = null
  for (let byte = 0x50; byte <= 0xff; byte++) {
    const pair = cryptoSuite.keyPair(seed(byte))
    if (roleForIdentity(pair.publicKey) === ROLE.PRIVATE) {
      responderSeed = byte
      break
    }
  }
  const responder = cryptoSuite.keyPair(seed(responderSeed))
  const signedAdvertisement = advertisement(responderSeed)
  const decodedAdvertisement = decodeRelayCapabilityAdvertisement(signedAdvertisement)
  const currentDecodedAdvertisement = decodeRelayCapabilityAdvertisement(currentAdvertisement)
  const requestedLimits = Object.freeze({
    cellSize: 1200,
    maxCells: 64,
    maxBytes: 65_536,
    maxCommands: 10,
    idleTimeoutMs: 5_000,
    expiresAtMs: 7_000n
  })
  const admittedLimitsDigest = digestAdmittedLimits(requestedLimits)
  const transcriptDigest = tailReadyTranscriptDigest(
    initiatorTailControlTranscript(currentAdvertisement, requestedLimits)
  )
  const owner = authority(clock)
  const adopted = owner.adopt(
    initiatorSealLink(signedAdvertisement, requestedLimits, {
      currentAdvertisement,
      wireExpiresAt: 20_000n
    })
  )
  const session = createTailControlSession(
    adopted.tail,
    tailSessionOptions(clock, {
      absoluteDeadline: 16_000n,
      crypto: cryptoSuite
    })
  )
  const randomSeeds = [seed(0x90), seed(0x91), seed(0x92)]
  const encoded = session.sealExtend({
    advertisement: signedAdvertisement,
    advertisementDigest: digestRelayCapabilityAdvertisement(signedAdvertisement),
    extensionIndex: 2,
    requestedLimits,
    absoluteDeadline: 16_000n,
    randomBytes: () => randomSeeds.shift()
  })
  const request = decodeExtendRequest(encoded)
  const proofValue = {
    responderAdvertisementDigest: digestRelayCapabilityAdvertisement(signedAdvertisement),
    initiatorIdentity: currentDecodedAdvertisement.relayIdentity,
    responderIdentity: decodedAdvertisement.relayIdentity,
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: request.branchId,
    circuitId: request.circuitId,
    generation: request.generation,
    extensionIndex: request.extensionIndex,
    clientTailEphemeralPublicKey: request.clientTailEphemeralPublicKey,
    clientNonce: request.clientNonce,
    advertisedRouteEncryptionPublicKey: decodedAdvertisement.routeEncryptionPublicKey,
    admittedLimitsDigest,
    expiresAtMs: 6_500n,
    responderProofNonce: seed(0x93)
  }
  const extended = {
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: request.branchId,
    circuitId: request.circuitId,
    generation: request.generation,
    extensionIndex: request.extensionIndex,
    responderAdvertisementDigest: proofValue.responderAdvertisementDigest,
    redactedProof: signRedactedResponderProof(proofValue, responder.secretKey),
    extensionNonce: request.extensionNonce
  }
  const completion = session.openExtended(encodeExtended(extended))
  failTailRearm = true
  let message = null
  try {
    session.completeClientExtension(
      completion,
      encodeTailReadyFor(extended, request, responder, {
        transcriptDigest,
        expiresAtMs: proofValue.expiresAtMs
      })
    )
  } catch (err) {
    message = err && err.message
  }
  t.is(message, 'injected rearm failure')
  t.is(failTailRearm, false, 'completion attempts the shortened deadline rearm')
  t.exception(() => readTailControlDeadline(session), 'rearm failure destroys the client tail')
  t.is(destroyTailControlSession(session), false)
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
  const adopted = owner.adopt(
    initiatorSealLink(signedAdvertisement, requestedLimits, {
      currentAdvertisement,
      wireExpiresAt: 20_000n
    })
  )
  const session = createTailControlSession(
    adopted.tail,
    tailSessionOptions(clock, {
      absoluteDeadline: 16_000n,
      crypto: cryptoSuite
    })
  )
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
