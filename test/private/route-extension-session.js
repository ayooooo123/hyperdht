const b4a = require('b4a')
const test = require('brittle')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { M3AdjacencyAuthority, deriveM3CellIds } = require('../../lib/private/m3-adjacency-runtime')
const {
  consumeSealedRelayCandidateDirectory,
  createRelayCandidateDirectorySink,
  sealRelayCandidateDirectorySink,
  splitRelayPathReservation,
  takeRelayPathReservation
} = require('../../lib/private/relay-candidate-directory')
const {
  CAPACITY_CLASS,
  BRANCH_CLASS,
  RELAY_CAPABILITY,
  ROLE,
  CELL_CLASS,
  CONTEXT_CLASS,
  M3_MESSAGE_ID,
  encodeM3Object,
  roleForIdentity
} = require('../../lib/private/protocol')
const {
  decodeRelayCapabilityAdvertisement,
  deriveM3DhtNodeId,
  digestRelayCapabilityAdvertisement,
  encodeCanonicalEndpoint,
  encodeRelayCapabilityAdvertisement,
  providerServicePolicyForCapabilities,
  signRelayCapabilityAdvertisement
} = require('../../lib/private/relay-capability')
const guardLinks = require('../../lib/private/guard-link')
const {
  DatagramReplayWindow,
  OrderedReceiver,
  SenderCounter
} = require('../../lib/private/counters')
const {
  createTailControlSession,
  decodeExtendRequest,
  digestAdmittedLimits,
  encodeExtended,
  encodeTailControlTranscript
} = require('../../lib/private/tail-control')
const { signRedactedResponderProof } = require('../../lib/private/redacted-responder-proof')
const {
  RouteExtensionSession,
  createRouteExtensionLimits,
  createRouteExtensionSessionRequest,
  takeRouteExtensionTransfer
} = require('../../lib/private/route-extension')

const OFFER_DIGEST = b4a.from(Array.from({ length: 32 }, (_, index) => index))
const NOW = 1_000n
const TEST_ONLY_M3_ESTABLISHED_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-m3-established-issuer'
)

function routeClock() {
  return {
    wallNow: () => NOW,
    monotonicNow: () => 0n,
    schedule() {
      return Object.freeze({})
    },
    cancelScheduled() {}
  }
}

function routeAuthority(clock) {
  return new M3AdjacencyAuthority({
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled,
    crypto: cryptoSuite
  })
}

function routeContexts(initiator) {
  const values = {}
  for (const cellClass of [CELL_CLASS.CONTROL, CELL_CLASS.STREAM, CELL_CLASS.DATAGRAM]) {
    const forwardKey = b4a.alloc(32, 0x20 + cellClass)
    const reverseKey = b4a.alloc(32, 0x30 + cellClass)
    const forwardNonce = b4a.alloc(16, 0x40 + cellClass)
    const reverseNonce = b4a.alloc(16, 0x50 + cellClass)
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
            : new OrderedReceiver({ window: 256, gapTimeout: 5_000, now: () => Number(NOW) })
      }
    }
  }
  return values
}

function routeEstablishedLink(transcript, options = {}) {
  const ids = deriveM3CellIds(OFFER_DIGEST, { crypto: cryptoSuite })
  return guardLinks[TEST_ONLY_M3_ESTABLISHED_ISSUER].issue({
    initiator: true,
    completeOfferDigest: OFFER_DIGEST,
    localId: ids.initiatorCellId,
    peerLocalId: ids.responderCellId,
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: b4a.alloc(16, 0x41),
    circuitId: b4a.alloc(16, 0x42),
    generation: 7n,
    extensionIndex: 1,
    localIdentity: b4a.alloc(32, 0x51),
    peerIdentity: b4a.alloc(32, 0x52),
    expiresAt: 20_000n,
    contexts: routeContexts(true),
    physicalChannel: Object.freeze({ destroy() {} }),
    clientTailEphemeralSecretKey: options.clientTailEphemeralSecretKey,
    tailControlTranscript: transcript
  })
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

const ROUTE_TAIL_READY_DOMAIN = b4a.from('hyperdht-private-routes/m3/tail-ready/v1')
const ROUTE_TAIL_READY_TRANSCRIPT_DOMAIN = b4a.from(
  'hyperdht-private-routes/m3/tail-control/transcript-digest/v1'
)

function routeSignatureInput(domain, messageId, body) {
  const input = b4a.alloc(10 + domain.byteLength + body.byteLength)
  writeUint16(input, domain.byteLength, 0)
  input.set(domain, 2)
  writeUint32(input, 1, 2 + domain.byteLength)
  writeUint16(input, messageId, 6 + domain.byteLength)
  writeUint16(input, body.byteLength, 8 + domain.byteLength)
  input.set(body, 10 + domain.byteLength)
  return input
}

function routeTailReady(extended, request, signer, transcriptDigest, expiresAtMs) {
  const body = b4a.alloc(210)
  body[0] = extended.branchClass
  body.set(extended.branchId, 1)
  body.set(extended.circuitId, 17)
  writeUint64(body, extended.generation, 33)
  body[41] = extended.extensionIndex
  body.set(transcriptDigest, 42)
  body.set(signer.publicKey, 74)
  body.set(extended.responderAdvertisementDigest, 106)
  body.set(request.clientNonce, 138)
  body.set(b4a.alloc(32, 0xa3), 170)
  writeUint64(body, expiresAtMs, 202)
  return encodeM3Object({
    messageId: M3_MESSAGE_ID.TAIL_READY_V1,
    body,
    authSuffix: cryptoSuite.sign(
      routeSignatureInput(ROUTE_TAIL_READY_DOMAIN, M3_MESSAGE_ID.TAIL_READY_V1, body),
      signer.secretKey
    )
  })
}

function routeTailControlEnvelope(encoded) {
  const frame = b4a.alloc(1100)
  frame.set(encoded)
  return b4a.concat([b4a.from([CONTEXT_CLASS.TAIL_CONTROL_ORDERED]), frame])
}

function routeInnerM3Object(envelope) {
  const frame = envelope.subarray(1)
  const bodyLength = frame.readUInt16BE(6)
  return frame.subarray(0, 8 + bodyLength)
}

function identityFor(role, ordinal) {
  let found = -1
  for (let value = 1; value < 256; value++) {
    const pair = cryptoSuite.keyPair(b4a.alloc(32, value))
    if (roleForIdentity(pair.publicKey) !== role) continue
    found++
    if (found === ordinal) return pair
  }
  throw new Error('missing deterministic identity')
}

function identityForPublicKey(publicKey) {
  for (let value = 1; value < 256; value++) {
    const pair = cryptoSuite.keyPair(b4a.alloc(32, value))
    if (b4a.equals(pair.publicKey, publicKey)) return pair
  }
  throw new Error('missing deterministic identity secret')
}

function candidate(role, ordinal, index) {
  const identity = identityFor(role, ordinal)
  const route = cryptoSuite.encryptionKeyPair(b4a.alloc(32, 128 + index))
  const endpoint = encodeCanonicalEndpoint({
    addressFamily: 4,
    addressBytes: b4a.from([198, 18, index, 1]),
    port: 40_000 + index
  })
  const capabilityMask =
    role === ROLE.SAFETY
      ? RELAY_CAPABILITY.CIRCUIT_RELAY_V1
      : RELAY_CAPABILITY.CIRCUIT_RELAY_V1 | RELAY_CAPABILITY.DHT_EXIT_V1
  const signed = signRelayCapabilityAdvertisement(
    {
      relayIdentity: identity.publicKey,
      currentDhtNodeId: deriveM3DhtNodeId(endpoint),
      reachableEndpoint: endpoint,
      routeEncryptionPublicKey: route.publicKey,
      capabilityMask,
      minimumProtocolVersion: 1,
      maximumProtocolVersion: 1,
      cellSize: 1200,
      maxCellPayload: 1146,
      contextEnvelopeSize: 1101,
      routeFrameSize: 1100,
      maxRoutePayload: 1073,
      datagramReplayWindow: 64,
      maxConcurrentCircuits: 32,
      capacityClass: CAPACITY_CLASS.MEDIUM,
      maxCellsPerCircuit: 10_000,
      maxBytesPerCircuit: 10_000_000,
      maxCommandsPerCircuit: 256,
      idleTimeoutMs: 30_000,
      maxQueuedBytes: 262_144,
      epoch: 1n,
      issuedAtMs: NOW,
      expiresAtMs: NOW + 30_000n,
      providerServicePolicyEntries: providerServicePolicyForCapabilities(capabilityMask)
    },
    identity.secretKey
  )
  const canonicalBytes = encodeRelayCapabilityAdvertisement(signed)
  return {
    canonicalBytes,
    digest: digestRelayCapabilityAdvertisement(canonicalBytes, { now: NOW }),
    identity: b4a.from(identity.publicKey),
    canonicalEndpointBytes: b4a.from(endpoint),
    routePublicKey: b4a.from(route.publicKey),
    role,
    capabilityMask,
    epoch: 1n,
    issuedAt: NOW,
    expiresAt: NOW + 30_000n
  }
}

function selectedMiddle() {
  const guard = candidate(ROLE.SAFETY, 0, 1)
  const records = [
    candidate(ROLE.SAFETY, 1, 2),
    candidate(ROLE.SAFETY, 2, 3),
    candidate(ROLE.PRIVATE, 0, 40),
    candidate(ROLE.PRIVATE, 1, 41)
  ]
  const sink = createRelayCandidateDirectorySink({ wallNow: () => NOW, monotonicNow: () => 0n })
  const directory = consumeSealedRelayCandidateDirectory(
    sealRelayCandidateDirectorySink(sink, records, {
      guardIdentity: guard.identity,
      guardEndpoint: guard.canonicalEndpointBytes,
      guardAdvertisementDigest: guard.digest,
      guardEpoch: guard.epoch,
      guardExpiresAt: guard.expiresAt
    })
  )
  const transaction = takeRelayPathReservation(
    directory.reserveInitialPair({ lookupGeneration: 1n, announceGeneration: 1n })
  )
  const split = splitRelayPathReservation(transaction)
  return { transaction, selection: split.lookup.middle }
}

test('M3 adjacency runtime derives exact actor-local cell IDs', (t) => {
  const ids = deriveM3CellIds(OFFER_DIGEST, { crypto: cryptoSuite })
  t.alike(ids.initiatorCellId, b4a.from('c78d0f017fe9b907995002a35ff0d9ef', 'hex'))
  t.alike(ids.responderCellId, b4a.from('1b59923d31c99d089e85e64671f7ce71', 'hex'))

  t.exception(() => deriveM3CellIds(b4a.alloc(31), { crypto: cryptoSuite }))
  t.exception(() => deriveM3CellIds(OFFER_DIGEST, { crypto: { hash: () => b4a.alloc(32) } }))
  t.exception(() => deriveM3CellIds(OFFER_DIGEST, { crypto: { hash: () => b4a.alloc(32, 0x5a) } }))
})

test('route extension limits retain route lifetime beyond the operation deadline', (t) => {
  t.alike(
    createRouteExtensionLimits(Object.freeze({}), () => 1_000n, 9_000n),
    {
      cellSize: 1200,
      maxCells: 64,
      maxBytes: 65_536,
      maxCommands: 10,
      idleTimeoutMs: 5_000,
      expiresAtMs: 9_000n
    }
  )
  t.is(
    createRouteExtensionLimits(Object.freeze({ maxCommands: 2 }), () => 1_000n, 4_000n).expiresAtMs,
    4_000n
  )
  t.exception(() => createRouteExtensionLimits(Object.freeze({}), () => 1_000n, 1_000n))
})

function routeExtensionRequestOptions(overrides = {}) {
  const selected = selectedMiddle()
  const tailControl = Object.freeze({
    sealExtend() {
      return b4a.alloc(466, 0x11)
    },
    openExtended() {
      return Object.freeze({})
    },
    completeClientExtension() {
      return Object.freeze({})
    },
    abortClientExtension() {},
    takeFinalExitHandoff() {}
  })
  return {
    transaction: selected.transaction,
    selection: selected.selection,
    branchClass: BRANCH_CLASS.LOOKUP,
    position: 'middle',
    generation: 1n,
    extensionIndex: 1,
    limits: Object.freeze({}),
    absoluteDeadline: 9_000n,
    signedExpiry: 8_000n,
    wallNow: () => NOW,
    monotonicNow: () => 0n,
    randomBytes: (size) => b4a.alloc(size, 0x44),
    schedule() {
      return Object.freeze({})
    },
    cancelScheduled() {},
    cancel() {},
    tailControl,
    ...overrides
  }
}

test('route extension request consumes only selected-evidence borrower fields', (t) => {
  t.exception(
    () => createRouteExtensionSessionRequest(routeExtensionRequestOptions()),
    'structural tailControl borrowers are rejected'
  )

  t.exception(
    () =>
      createRouteExtensionSessionRequest(
        routeExtensionRequestOptions({
          now: () => NOW,
          tailControlTransportFactory() {
            return Object.freeze({})
          }
        })
      ),
    'legacy now and transport factory are rejected'
  )
  t.exception(
    () =>
      createRouteExtensionSessionRequest(
        routeExtensionRequestOptions({
          tailControl: Object.freeze({
            sealExtend() {},
            openExtended() {},
            completeClientExtension() {},
            abortClientExtension() {},
            takeFinalExitHandoff() {},
            destroy() {}
          })
        })
      ),
    'tailControl destroy authority is rejected'
  )
})

test('selected evidence cannot open through a structural transport trap', (t) => {
  const selected = selectedMiddle()
  const tailControl = Object.freeze({
    sealExtend() {},
    openExtended() {},
    completeClientExtension() {},
    abortClientExtension() {},
    takeFinalExitHandoff() {}
  })
  t.exception(
    () =>
      createRouteExtensionSessionRequest({
        transaction: selected.transaction,
        selection: selected.selection,
        branchClass: BRANCH_CLASS.LOOKUP,
        position: 'middle',
        generation: 1n,
        extensionIndex: 1,
        limits: Object.freeze({}),
        absoluteDeadline: 9_000n,
        signedExpiry: 8_000n,
        wallNow: () => NOW,
        monotonicNow: () => 0n,
        randomBytes: (size) => b4a.alloc(size, 0x44),
        schedule() {
          return Object.freeze({})
        },
        cancelScheduled() {},
        cancel() {},
        tailControl
      }),
    'structural transport trap is rejected before open'
  )
})

test('selected evidence opens through production TailControl client methods', async (t) => {
  const selected = selectedMiddle()
  const clock = routeClock()
  const currentTail = candidate(ROLE.SAFETY, 0, 1)
  const requestedLimits = createRouteExtensionLimits(Object.freeze({}), () => NOW, 8_000n)
  const currentTailPair = cryptoSuite.encryptionKeyPair(b4a.alloc(32, 0x61))
  const admittedLimitsDigest = digestAdmittedLimits(requestedLimits)
  const transcript = encodeTailControlTranscript({
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: b4a.alloc(16, 0x41),
    circuitId: b4a.alloc(16, 0x42),
    generation: 7n,
    extensionIndex: 0,
    clientTailEphemeralPublicKey: currentTailPair.publicKey,
    advertisedTailRouteEncryptionPublicKey: currentTail.routePublicKey,
    candidateAdvertisementDigest: currentTail.digest,
    clientNonce: b4a.alloc(32, 0x62),
    tailIdentity: currentTail.identity,
    admittedLimitsDigest
  })
  const tailControl = createTailControlSession(
    routeAuthority(clock).adopt(
      routeEstablishedLink(transcript, {
        clientTailEphemeralSecretKey: currentTailPair.secretKey
      })
    ).tail,
    {
      wallNow: clock.wallNow,
      monotonicNow: clock.monotonicNow,
      schedule: clock.schedule,
      cancelScheduled: clock.cancelScheduled,
      absoluteDeadline: 9_000n,
      crypto: cryptoSuite
    }
  )
  const waiters = []
  const trace = []
  const transport = Object.freeze({
    async send(envelope) {
      trace.push('send')
      t.is(envelope.byteLength, 1101)
      t.is(envelope[0], CONTEXT_CLASS.TAIL_CONTROL_ORDERED)
      const request = decodeExtendRequest(routeInnerM3Object(envelope))
      const responderAdvertisement = decodeRelayCapabilityAdvertisement(request.advertisement)
      const responder = identityForPublicKey(responderAdvertisement.relayIdentity)
      const responderAdvertisementDigest = digestRelayCapabilityAdvertisement(request.advertisement)
      const proofExpiresAt = 4_500n
      const proof = signRedactedResponderProof(
        {
          responderAdvertisementDigest,
          initiatorIdentity: currentTail.identity,
          responderIdentity: responderAdvertisement.relayIdentity,
          branchClass: request.branchClass,
          branchId: request.branchId,
          circuitId: request.circuitId,
          generation: request.generation,
          extensionIndex: request.extensionIndex,
          clientTailEphemeralPublicKey: request.clientTailEphemeralPublicKey,
          clientNonce: request.clientNonce,
          advertisedRouteEncryptionPublicKey: responderAdvertisement.routeEncryptionPublicKey,
          admittedLimitsDigest: digestAdmittedLimits(request.requestedLimits),
          expiresAtMs: proofExpiresAt,
          responderProofNonce: b4a.alloc(32, 0x93)
        },
        responder.secretKey
      )
      const extended = {
        branchClass: request.branchClass,
        branchId: request.branchId,
        circuitId: request.circuitId,
        generation: request.generation,
        extensionIndex: request.extensionIndex,
        responderAdvertisementDigest,
        redactedProof: proof,
        extensionNonce: request.extensionNonce
      }
      const frames = [
        routeTailControlEnvelope(encodeExtended(extended)),
        routeTailControlEnvelope(
          routeTailReady(
            extended,
            request,
            responder,
            cryptoSuite.hash([ROUTE_TAIL_READY_TRANSCRIPT_DOMAIN, transcript]),
            proofExpiresAt
          )
        )
      ]
      t.is(waiters.length, 2, 'EXTENDED and READY receives are reserved before send')
      for (const frame of frames) waiters.shift()(frame)
    },
    receive() {
      trace.push('receive')
      return new Promise((resolve) => waiters.push(resolve))
    },
    release(envelope) {
      trace.push('release')
      t.ok(envelope)
    }
  })
  const tailControlModule = require('../../lib/private/tail-control')
  const originalBorrow = tailControlModule.borrowTailControlTransport
  tailControlModule.borrowTailControlTransport = (session) => {
    t.is(session, tailControl)
    return transport
  }
  t.teardown(() => {
    tailControlModule.borrowTailControlTransport = originalBorrow
  })
  const request = createRouteExtensionSessionRequest({
    transaction: selected.transaction,
    selection: selected.selection,
    branchClass: BRANCH_CLASS.LOOKUP,
    position: 'middle',
    generation: 1n,
    extensionIndex: 1,
    limits: Object.freeze({}),
    absoluteDeadline: 9_000n,
    signedExpiry: 8_000n,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    randomBytes: (() => {
      const seeds = [b4a.alloc(32, 0x90), b4a.alloc(32, 0x91), b4a.alloc(32, 0x92)]
      return () => seeds.shift()
    })(),
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled,
    cancel() {},
    tailControl
  })
  const session = new RouteExtensionSession(request)
  const transfer = await session.open()
  t.alike(trace, ['receive', 'receive', 'send', 'release', 'release'])
  const moved = takeRouteExtensionTransfer(transfer)
  t.is(moved.tailControl, tailControl)
  t.is(moved.transport, transport)
})
