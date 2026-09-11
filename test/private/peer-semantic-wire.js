const test = require('brittle')
const b4a = require('b4a')

const { PrivateRouteError } = require('../../lib/private/errors')
const { PEER_MESSAGE_ID } = require('../../lib/private/peer-protocol')
const { decodePeerSemantic, encodePeerSemantic } = require('../../lib/private/peer-semantic-wire')

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

function readU16(buffer, offset) {
  return buffer[offset] * 0x100 + buffer[offset + 1]
}

function bytes(length, value) {
  return b4a.alloc(length, value)
}

function fixedFields() {
  return {
    sessionId: bytes(16, 1),
    activateCommitment: bytes(32, 2),
    readyMac: bytes(32, 3),
    ackMac: bytes(32, 4),
    bridgeId: bytes(16, 5),
    sourceGeneration: 6n,
    destinationGeneration: 7n,
    expiresAtUnixMs: 8n,
    maxFrames: 9,
    maxBytes: 10n,
    idleMs: 11,
    receiptNonce: bytes(16, 12),
    receiptMac: bytes(32, 13)
  }
}
function makeAdvertisement() {
  const { encodePeerTransport } = require('../../lib/private/peer-transport-wire')
  return encodePeerTransport(
    PEER_MESSAGE_ID.PEER_CAPABILITY_ADVERTISEMENT_V2,
    {
      relayIdentity: bytes(32, 1),
      currentDhtNodeId: bytes(32, 2),
      reachableEndpoint: bytes(19, 3),
      routeEncryptionPublicKey: bytes(32, 4),
      capabilityMask: 11,
      minimumVersion: 2,
      maximumVersion: 2,
      cellSize: 1200,
      maxCellPayload: 1146,
      contextEnvelopeSize: 1101,
      routeFrameSize: 1100,
      maxRoutePayload: 1073,
      datagramReplayWindow: 64,
      maxConcurrentCircuits: 1,
      capacityClass: 0,
      maxCells: 1,
      maxBytes: 1,
      maxCommands: 1,
      idleTimeoutMs: 1,
      maxQueuedBytes: 1,
      epoch: 1n,
      issuedAt: 1n,
      expiresAt: 2n,
      policyCount: 0
    },
    bytes(64, 5)
  )
}

test('semantic descriptor nesting validates the fixed advertisement and descriptor wires', (t) => {
  const advertisement = makeAdvertisement()
  const descriptor = encodePeerSemantic(PEER_MESSAGE_ID.PEER_DESCRIPTOR_V2, {
    kind: 1,
    expectedDestinationNoiseKey: bytes(32, 6),
    entryIdentity: bytes(32, 7),
    advertisementLength: 260,
    advertisement,
    destinationPurposeDigest: bytes(32, 8),
    destinationFinalTranscriptDigest: bytes(32, 9),
    destinationCircuitId: bytes(16, 10),
    destinationGeneration: 1n,
    entryEpoch: 1n,
    maxFrames: 1,
    maxBytes: 59n,
    idleTimeoutMs: 1,
    expiresAtUnixMs: 2n,
    admissionToken: bytes(32, 11),
    registrationCommitment: bytes(32, 12)
  })
  t.is(descriptor.byteLength, 519)

  const registered = encodePeerSemantic(PEER_MESSAGE_ID.ENTRY_REGISTER_V2, {
    destinationNoiseKey: bytes(32, 13),
    circuitId: bytes(16, 14),
    generation: 1n,
    purposeDigest: bytes(32, 15),
    finalTranscriptDigest: bytes(32, 16),
    entryEpoch: 1n,
    maxFrames: 1,
    maxBytes: 59n,
    idleMs: 1,
    expiresAtUnixMs: 2n,
    advertisementLength: 260,
    advertisement,
    registerNonce: bytes(32, 17),
    requestCommitment: bytes(32, 18)
  })
  t.is(registered.byteLength, 486)

  const activated = encodePeerSemantic(PEER_MESSAGE_ID.PRIVATE_ACTIVATE_V2, {
    sessionId: bytes(16, 19),
    sourceCircuitId: bytes(16, 20),
    sourceGeneration: 1n,
    sourceFinalTranscriptDigest: bytes(32, 21),
    sourcePurposeDigest: bytes(32, 22),
    sourceNonce: bytes(32, 23),
    descriptorLength: 519,
    completeDescriptor: descriptor,
    sourceMaxFrames: 1,
    sourceMaxBytes: 59n,
    sourceIdleMs: 1,
    expiresAtUnixMs: 2n,
    ik1Digest: bytes(32, 24),
    ik1Bytes: 101,
    activateCommitment: bytes(32, 25)
  })
  const decoded = decodePeerSemantic(activated)
  t.is(activated.byteLength, 757)
  t.alike(decoded.fields.completeDescriptor, descriptor)
})

test('semantic v2 fixed objects use exact envelope and body lengths', (t) => {
  const fixtures = [
    [
      PEER_MESSAGE_ID.LEGACY_RESOLVE_V2,
      {
        sessionId: bytes(16, 1),
        expectedNoiseKey: bytes(32, 2),
        clientNonce: bytes(32, 3),
        deadlineUnixMs: 4n,
        maxCandidates: 1,
        maxNoiseBytes: 4096,
        requestedFrames: 5,
        requestedBytes: 6n
      },
      104
    ],
    [
      PEER_MESSAGE_ID.LEGACY_RESOLVED_V2,
      {
        sessionId: bytes(16, 1),
        clientNonce: bytes(32, 2),
        egressRef: bytes(32, 3),
        candidateCount: 1,
        expiresAtUnixMs: 4n,
        reservationNonce: bytes(16, 5)
      },
      106
    ],
    [
      PEER_MESSAGE_ID.LEGACY_RESERVE_V2,
      {
        sessionId: bytes(16, 1),
        egressRef: bytes(32, 2),
        reservationNonce: bytes(16, 3),
        egressServiceIdentity: bytes(32, 4)
      },
      96
    ],
    [
      PEER_MESSAGE_ID.LEGACY_RESERVED_V2,
      {
        sessionId: bytes(16, 1),
        egressRef: bytes(32, 2),
        reservationNonce: bytes(16, 3),
        sessionCapability: bytes(32, 4),
        egressRawUdxId: 5,
        egressServiceIdentity: bytes(32, 6)
      },
      132
    ],
    [
      PEER_MESSAGE_ID.LEGACY_HANDSHAKE_ACCEPT_V2,
      {
        sessionId: bytes(16, 1),
        egressRef: bytes(32, 2),
        reservationNonce: bytes(16, 3),
        ik1Digest: bytes(32, 4),
        ik2Digest: bytes(32, 5),
        validatedResponderUdxId: 6
      },
      132
    ],
    [
      PEER_MESSAGE_ID.LEGACY_OPEN_V2,
      {
        sessionId: bytes(16, 1),
        egressRef: bytes(32, 2),
        reservationNonce: bytes(16, 3),
        pendingRemoteUdxId: 4,
        ik2Digest: bytes(32, 5)
      },
      100
    ],
    [
      PEER_MESSAGE_ID.ENTRY_REGISTERED_V2,
      {
        registerNonce: bytes(32, 1),
        token: bytes(32, 2),
        registrationCommitment: bytes(32, 3),
        circuitId: bytes(16, 4),
        generation: 5n,
        expiresAtUnixMs: 6n,
        entryEpoch: 7n
      },
      136
    ],
    [
      PEER_MESSAGE_ID.ENTRY_REVOKE_V2,
      {
        token: bytes(32, 1),
        registrationCommitment: bytes(32, 2),
        circuitId: bytes(16, 3),
        generation: 4n
      },
      88
    ],
    [PEER_MESSAGE_ID.PRIVATE_READY_V2, {
      sessionId: bytes(16, 1),
      activateCommitment: bytes(32, 2),
      destinationCircuitId: bytes(16, 3),
      destinationGeneration: 4n,
      destinationNonce: bytes(32, 5),
      ik1Digest: bytes(32, 6),
      ik2Digest: bytes(32, 7),
      expiresAtUnixMs: 8n,
      maxFrames: 9,
      maxBytes: 10n,
      readyMac: bytes(32, 11)
    }, 220],
    [PEER_MESSAGE_ID.PRIVATE_ACK_V2, {
      sessionId: bytes(16, 1),
      activateCommitment: bytes(32, 2),
      readyMac: bytes(32, 3),
      sourceCircuitId: bytes(16, 4),
      sourceGeneration: 5n,
      sourceNonce: bytes(32, 6),
      destinationNonce: bytes(32, 7),
      ik2Digest: bytes(32, 8),
      ackMac: bytes(32, 9)
    }, 232],
    [PEER_MESSAGE_ID.PRIVATE_ACCEPTED_V2, {
      sessionId: bytes(16, 1),
      activateCommitment: bytes(32, 2),
      readyMac: bytes(32, 3),
      ackMac: bytes(32, 4),
      destinationCircuitId: bytes(16, 5),
      destinationGeneration: 6n,
      acceptedMac: bytes(32, 7)
    }, 168],
    [PEER_MESSAGE_ID.PRIVATE_SOURCE_RECEIPT_V2, {
      sessionId: bytes(16, 1),
      acceptedMac: bytes(32, 2),
      sourceCircuitId: bytes(16, 3),
      sourceGeneration: 4n,
      receiptNonce: bytes(16, 5),
      receiptMac: bytes(32, 6)
    }, 120],
    [PEER_MESSAGE_ID.PRIVATE_OPEN_V2, fixedFields(), 216]
  ]

  for (const [messageId, fields, bodyBytes] of fixtures) {
    const encoded = encodePeerSemantic(messageId, fields)
    t.is(encoded.byteLength, 8 + bodyBytes)
    t.is(encoded[0], 0)
    t.is(encoded[3], 2)
    t.is(readU16(encoded, 4), messageId)
    t.is(readU16(encoded, 6), bodyBytes)

    const decoded = decodePeerSemantic(encoded)
    t.is(decoded.protocolVersion, 2)
    t.is(decoded.messageId, messageId)
    t.is(decoded.body.byteLength, bodyBytes)
    t.is(decoded.authSuffix.byteLength, 0)
    t.alike(decoded.fields, fields)
  }
})

test('semantic noise fragments enforce canonical 1,002-byte geometry and 4,096-byte cap', (t) => {
  const fragment = (totalCiphertextBytes, fragmentIndex, fragmentBytes) =>
    encodePeerSemantic(PEER_MESSAGE_ID.PEER_NOISE_FRAGMENT_V2, {
      sessionId: bytes(16, 1),
      flight: 1,
      wholeCiphertextCommitment: bytes(32, 2),
      totalCiphertextBytes,
      fragmentIndex,
      fragmentCount: Math.ceil(totalCiphertextBytes / 1002),
      ciphertextOffset: fragmentIndex * 1002,
      fragmentBytes,
      ciphertext: bytes(fragmentBytes, 3)
    })

  t.is(fragment(1, 0, 1).byteLength, 72)
  t.is(fragment(1002, 0, 1002).byteLength, 1073)
  t.is(fragment(4096, 4, 88).byteLength, 159)

  expectCode(
    t,
    () => fragment(4097, 0, 1002),
    'INVALID_ROUTE'
  )
  expectCode(
    t,
    () =>
      encodePeerSemantic(PEER_MESSAGE_ID.PEER_NOISE_FRAGMENT_V2, {
        sessionId: bytes(16, 1),
        flight: 1,
        wholeCiphertextCommitment: bytes(32, 2),
        totalCiphertextBytes: 1003,
        fragmentIndex: 0,
        fragmentCount: 2,
        ciphertextOffset: 1,
        fragmentBytes: 1002,
        ciphertext: bytes(1002, 3)
      }),
    'INVALID_ROUTE'
  )
})

test('semantic v2 rejects reserved IDs, v1 envelopes, trailing bytes, and non-data fields', (t) => {
  expectCode(t, () => encodePeerSemantic(0x0348, {}), 'INVALID_ROUTE')
  expectCode(t, () => encodePeerSemantic(0x0366, {}), 'INVALID_ROUTE')

  const valid = encodePeerSemantic(PEER_MESSAGE_ID.LEGACY_RESOLVE_V2, {
    sessionId: bytes(16, 1),
    expectedNoiseKey: bytes(32, 2),
    clientNonce: bytes(32, 3),
    deadlineUnixMs: 4n,
    maxCandidates: 1,
    maxNoiseBytes: 4096,
    requestedFrames: 5,
    requestedBytes: 6n
  })

  const wrongVersion = b4a.from(valid)
  wrongVersion[3] = 1
  expectCode(t, () => decodePeerSemantic(wrongVersion), 'INVALID_ROUTE')
  expectCode(t, () => decodePeerSemantic(b4a.concat([valid, bytes(1, 0)])), 'INVALID_ROUTE')

  let getterReads = 0
  const accessorFields = {
    expectedNoiseKey: bytes(32, 2),
    clientNonce: bytes(32, 3),
    deadlineUnixMs: 4n,
    maxCandidates: 1,
    maxNoiseBytes: 4096,
    requestedFrames: 5,
    requestedBytes: 6n
  }
  Object.defineProperty(accessorFields, 'sessionId', {
    get() {
      getterReads++
      return bytes(16, 1)
    }
  })
  expectCode(t, () => encodePeerSemantic(PEER_MESSAGE_ID.LEGACY_RESOLVE_V2, accessorFields), 'INVALID_ROUTE')
  t.is(getterReads, 0)
})

test('semantic encoding owns caller byte fields and rejects malformed nested lengths', (t) => {
  const sessionId = bytes(16, 7)
  const fields = {
    sessionId,
    expectedNoiseKey: bytes(32, 2),
    clientNonce: bytes(32, 3),
    deadlineUnixMs: 4n,
    maxCandidates: 1,
    maxNoiseBytes: 4096,
    requestedFrames: 5,
    requestedBytes: 6n
  }
  const encoded = encodePeerSemantic(PEER_MESSAGE_ID.LEGACY_RESOLVE_V2, fields)
  sessionId.fill(0)
  t.alike(decodePeerSemantic(encoded).fields.sessionId, bytes(16, 7))

  const descriptorFields = {
    kind: 1,
    expectedDestinationNoiseKey: bytes(32, 1),
    entryIdentity: bytes(32, 2),
    advertisementLength: 260,
    advertisement: bytes(259, 3),
    destinationPurposeDigest: bytes(32, 4),
    destinationFinalTranscriptDigest: bytes(32, 5),
    destinationCircuitId: bytes(16, 6),
    destinationGeneration: 7n,
    entryEpoch: 8n,
    maxFrames: 9,
    maxBytes: 10n,
    idleTimeoutMs: 11,
    expiresAtUnixMs: 12n,
    admissionToken: bytes(32, 13),
    registrationCommitment: bytes(32, 14)
  }
  expectCode(
    t,
    () => encodePeerSemantic(PEER_MESSAGE_ID.PEER_DESCRIPTOR_V2, descriptorFields),
    'INVALID_ROUTE'
  )
})
