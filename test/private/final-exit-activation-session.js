'use strict'

const b4a = require('b4a')
const test = require('brittle')

const guardLinks = require('../../lib/private/guard-link')
const { M3AdjacencyAuthority, deriveM3CellIds } = require('../../lib/private/m3-adjacency-runtime')
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
  DatagramReplayWindow,
  OrderedReceiver,
  SenderCounter
} = require('../../lib/private/counters')
const {
  createTailControlSession,
  createTailControlResponderAuthority,
  decodeExtendRequest,
  encodeExtended,
  encodeTailControlTranscript,
  digestAdmittedLimits
} = require('../../lib/private/tail-control')
const { signRedactedResponderProof } = require('../../lib/private/redacted-responder-proof')
const {
  claimFinalExitActivation,
  consumeOpenRouteHandoff,
  createFinalExitActivationClaim,
  createFinalExitActivationFactory,
  destroyFinalExitActivationOwner,
  destroyOpenRouteMaterial,
  openFinalExit,
  revokeOpenRouteHandoff
} = require('../../lib/private/final-exit-activation')
const {
  createDhtExitReadySigner,
  createTailReadySigner,
  createRelayIdentitySigningAuthority,
  destroyRelayIdentitySigningAuthority
} = require('../../lib/private/relay-identity-signer')

const TEST_ONLY_M3_ESTABLISHED_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-m3-established-issuer'
)
const OFFER_DIGEST = b4a.from(Array.from({ length: 32 }, (_, index) => index))
const PAYLOAD_PARAMETERS = Object.freeze({
  cellSize: 1200,
  maxCellPayload: 1146,
  contextEnvelopeSize: 1101,
  routeFrameSize: 1100,
  maxRoutePayload: 1073,
  datagramReplayWindow: 64,
  maxQueuedBytes: 65_536,
  idleTimeoutMs: 5_000
})

function seed(byte, size = 32) {
  return b4a.alloc(size, byte)
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

function expectCode(t, operation, code, message) {
  let error = null
  try {
    operation()
  } catch (err) {
    error = err
  }
  t.is(error && error.code, code, message)
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
    advance(monotonic) {
      currentMonotonic = monotonic
    },
    schedule(callback, delay) {
      const handle = Object.freeze({ id: ++nextHandle, delay })
      timers.set(handle, { callback, delay })
      return handle
    },
    cancelScheduled(handle) {
      timers.delete(handle)
    },
    pending() {
      return timers.size
    },
    delays() {
      return Array.from(timers.values(), (timer) => timer.delay)
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
    absoluteDeadline: 16_000n
  }
  for (const key of Reflect.ownKeys(extra)) options[key] = extra[key]
  return options
}

function channel() {
  return Object.freeze({ destroy() {} })
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

function initiatorTailControlTranscript(currentAdvertisement, requestedLimits, currentTailPair) {
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

function activationOwnerFixture(t) {
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
    initiatorTailControlTranscript(
      currentAdvertisement,
      requestedLimits,
      cryptoSuite.encryptionKeyPair(seed(0x61))
    )
  )
  const owner = authority(clock)
  const adopted = owner.adopt(
    initiatorSealLink(signedAdvertisement, requestedLimits, {
      currentAdvertisement,
      wireExpiresAt: 20_000n
    })
  )
  const tail = createTailControlSession(
    adopted.tail,
    tailSessionOptions(clock, { crypto: cryptoSuite })
  )
  const encoded = tail.sealExtend({
    advertisement: signedAdvertisement,
    advertisementDigest: digestRelayCapabilityAdvertisement(signedAdvertisement),
    extensionIndex: 2,
    requestedLimits,
    absoluteDeadline: 16_000n,
    randomBytes: () => seed(0x90)
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
  const finalTailPair = cryptoSuite.encryptionKeyPair(seed(0x90))
  const sharedSecret = cryptoSuite.keyAgreement(
    finalTailPair.secretKey,
    decodedAdvertisement.routeEncryptionPublicKey
  )
  const finalTailControlTranscript = encodeTailControlTranscript({
    branchClass: proofValue.branchClass,
    branchId: proofValue.branchId,
    circuitId: proofValue.circuitId,
    generation: proofValue.generation,
    extensionIndex: proofValue.extensionIndex,
    clientTailEphemeralPublicKey: proofValue.clientTailEphemeralPublicKey,
    advertisedTailRouteEncryptionPublicKey: proofValue.advertisedRouteEncryptionPublicKey,
    candidateAdvertisementDigest: proofValue.responderAdvertisementDigest,
    clientNonce: proofValue.clientNonce,
    tailIdentity: proofValue.responderIdentity,
    admittedLimitsDigest
  })
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
  const completion = tail.openExtended(encodeExtended(extended))
  t.is(
    tail.completeClientExtension(
      completion,
      encodeTailReadyFor(extended, request, responder, {
        transcriptDigest,
        expiresAtMs: proofValue.expiresAtMs
      })
    ),
    tail
  )
  const handoff = tail.takeFinalExitHandoff()
  const claim = createFinalExitActivationClaim(handoff)
  const activationOwner = claimFinalExitActivation(handoff, claim)
  return {
    activationOwner,
    clock,
    finalTailControlTranscript,
    responder,
    responderIdentity: decodedAdvertisement.relayIdentity,
    sharedSecret,
    tail
  }
}

function activationSession(t) {
  const fixture = activationOwnerFixture(t)
  const factory = createFinalExitActivationFactory({
    wallNow: fixture.clock.wallNow,
    monotonicNow: fixture.clock.monotonicNow,
    randomBytes: (size) => seed(0x22, size),
    schedule: fixture.clock.schedule,
    cancelScheduled: fixture.clock.cancelScheduled
  })
  const session = openFinalExit(factory, {
    handoff: fixture.activationOwner,
    crypto: cryptoSuite,
    payloadParameters: PAYLOAD_PARAMETERS,
    readySigner: undefined
  })
  return { ...fixture, session }
}

test('FinalExitActivationSession has no open handoff before authenticated OPEN', (t) => {
  const { session } = activationSession(t)
  expectCode(t, () => session.takeOpenHandoff(), 'ERR_AUTHENTICATION', 'OPEN gates handoff')
  t.alike(session.diagnostics(), { state: 'DESTROYED' })
})

test('FinalExitActivationSession initiator rejects wrong-role READY and activation expiry', (t) => {
  const wrongRole = activationSession(t)
  expectCode(
    t,
    () => wrongRole.session.sealReady(),
    'ERR_AUTHENTICATION',
    'initiator cannot seal READY'
  )
  t.alike(wrongRole.session.diagnostics(), { state: 'DESTROYED' })

  const expired = activationSession(t)
  expired.clock.advance(16_000n)
  expectCode(
    t,
    () => expired.session.sealActivate(),
    'ERR_PRIVACY_UNAVAILABLE',
    'activation cannot start after the moved monotonic final-exit deadline'
  )
  t.alike(expired.session.diagnostics(), { state: 'DESTROYED' })
})

test('FinalExitActivationSession retryActivate enforces frozen retry schedule', (t) => {
  const { clock, session } = activationSession(t)
  const basePending = clock.pending()
  session.sealActivate()
  t.is(clock.pending(), basePending + 1)
  t.ok(clock.delays().includes(250))
  expectCode(
    t,
    () => session.retryActivate(),
    'ERR_PRIVACY_UNAVAILABLE',
    'retry cannot emit before 250ms ordinal'
  )
  t.ok(clock.delays().includes(250))
  clock.advance(10_250n)
  session.retryActivate()
  t.ok(clock.delays().includes(500))
  t.is(clock.pending(), basePending + 1)
  t.is(session.destroy(), true)
  t.is(clock.delays().includes(500), false)
})

test('FinalExitActivationSession observes activation owner destruction after construction', (t) => {
  const { activationOwner, session } = activationSession(t)
  t.is(destroyFinalExitActivationOwner(activationOwner), true)
  expectCode(
    t,
    () => session.sealActivate(),
    'ERR_DESTROYED',
    'destroyed activation owner invalidates the live session'
  )
  t.alike(session.diagnostics(), { state: 'DESTROYED' })
})

test('FinalExitActivationSession completes ACTIVATE READY ACK OPEN with production responder owner', (t) => {
  const initiator = activationSession(t)
  const clock = initiator.clock
  const owner = authority(clock)
  const relayIdentity = createRelayIdentitySigningAuthority({
    identitySecretKey: initiator.responder.secretKey
  })
  const tailReadySigner = createTailReadySigner(relayIdentity)
  const dhtExitReadySigner = createDhtExitReadySigner(relayIdentity)
  const adopted = owner.adopt(
    syntheticLink({
      initiator: false,
      extensionIndex: 2,
      localIdentity: initiator.responderIdentity,
      tailSharedSecret: initiator.sharedSecret,
      tailControlTranscript: initiator.finalTailControlTranscript,
      wireExpiresAt: 20_000n
    })
  )
  const tail = createTailControlSession(adopted.tail, tailSessionOptions(clock))
  createTailControlResponderAuthority(tail, adopted.responderToken, {
    tailReadySigner,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    randomBytes: () => seed(0x73),
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled
  })
  const handoff = tail.takeFinalExitHandoff()
  const claim = createFinalExitActivationClaim(handoff)
  const activationOwner = claimFinalExitActivation(handoff, claim)
  const responderFactory = createFinalExitActivationFactory({
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    randomBytes: (size) => seed(0x74, size),
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled
  })
  const responder = openFinalExit(responderFactory, {
    handoff: activationOwner,
    crypto: cryptoSuite,
    payloadParameters: PAYLOAD_PARAMETERS,
    readySigner: dhtExitReadySigner
  })

  const activate = initiator.session.sealActivate()
  t.alike(responder.openActivate(activate).exitOriginCommandPolicyDigest.byteLength, 32)
  let ready = responder.sealReady()
  expectCode(
    t,
    () => responder.retryReady(),
    'ERR_PRIVACY_UNAVAILABLE',
    'READY retry cannot emit before 250ms ordinal'
  )
  t.is(clock.delays().filter((delay) => delay === 250).length, 2)
  clock.advance(10_250n)
  ready = responder.retryReady()
  t.alike(initiator.session.openReady(ready).exitIdentity, initiator.responderIdentity)
  expectCode(
    t,
    () => initiator.session.sealAck({ randomBytes: (n) => seed(0xa2, n) }),
    'INVALID_ROUTE',
    'final-exit facade rejects caller random bytes'
  )
  const ack = initiator.session.sealAck()
  expectCode(
    t,
    () => responder.openAck(ack, { randomBytes: (n) => seed(0xa3, n) }),
    'INVALID_ROUTE',
    'final-exit facade injects responder random bytes'
  )
  const openEnvelope = responder.openAck(ack)
  t.alike(initiator.session.openOpen(openEnvelope).payloadParametersDigest.byteLength, 32)
  t.alike(initiator.session.diagnostics(), { state: 'OPEN' })
  t.alike(responder.diagnostics(), { state: 'OPEN' })
  const openHandoff = responder.takeOpenHandoff()
  expectCode(t, () => responder.takeOpenHandoff(), 'ERR_REPLAY')
  const openMaterial = consumeOpenRouteHandoff(openHandoff)
  t.is(revokeOpenRouteHandoff(openHandoff), false)
  expectCode(t, () => consumeOpenRouteHandoff(openHandoff), 'ERR_REPLAY')
  t.is(openMaterial.initiator, false)
  t.is(openMaterial.branchClass, BRANCH_CLASS.LOOKUP)
  t.is(openMaterial.branchId.byteLength, 16)
  t.is(openMaterial.circuitId.byteLength, 16)
  t.is(openMaterial.exitIdentity.byteLength, 32)
  t.is(openMaterial.payloadForwardKey.byteLength, 32)
  t.is(destroyOpenRouteMaterial(openMaterial), true)
  t.is(destroyOpenRouteMaterial(openMaterial), false)
  t.is(responder.destroy(), true)
  t.is(destroyFinalExitActivationOwner(activationOwner), false)
  t.is(destroyRelayIdentitySigningAuthority(relayIdentity), true)
})
