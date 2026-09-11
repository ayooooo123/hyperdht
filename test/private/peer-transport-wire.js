'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { PrivateRouteError } = require('../../lib/private/errors')
const { PEER_MESSAGE_ID } = require('../../lib/private/peer-protocol')
const {
  encodePeerTransport,
  decodePeerTransport,
  encodePeerLinkReply,
  decodePeerLinkReply
} = require('../../lib/private/peer-transport-wire')

const MAX_U64 = 0xffff_ffff_ffff_ffffn

function expectInvalid(t, fn) {
  let error = null
  try {
    fn()
  } catch (err) {
    error = err
  }
  t.ok(error instanceof PrivateRouteError)
  t.is(error && error.code, 'INVALID_ROUTE')
}

function makeCommon(opts = {}) {
  return {
    routeId: opts.routeId ? b4a.from(opts.routeId) : b4a.alloc(16, 1),
    streamId: opts.streamId !== undefined ? opts.streamId : 1n,
    streamEpoch: opts.streamEpoch !== undefined ? opts.streamEpoch : 1,
    direction: opts.direction !== undefined ? opts.direction : 0,
    flags: opts.flags !== undefined ? opts.flags : 0,
    reserved: opts.reserved !== undefined ? opts.reserved : 0,
    position: opts.position !== undefined ? opts.position : 0n
  }
}

function makeLimits(opts = {}) {
  return {
    cellSize: 1200,
    maxCells: opts.maxCells || 100,
    maxBytes: opts.maxBytes || 100000,
    maxCommands: opts.maxCommands || 10,
    idleTimeoutMs: opts.idleTimeoutMs || 30000,
    expiresAt: opts.expiresAt || 1000000n
  }
}

function sampleCapability() {
  return {
    fields: {
      relayIdentity: b4a.alloc(32, 1),
      currentDhtNodeId: b4a.alloc(32, 2),
      reachableEndpoint: b4a.alloc(19, 3),
      routeEncryptionPublicKey: b4a.alloc(32, 4),
      capabilityMask: 9,
      minimumVersion: 2,
      maximumVersion: 2,
      cellSize: 1200,
      maxCellPayload: 1146,
      contextEnvelopeSize: 1101,
      routeFrameSize: 1100,
      maxRoutePayload: 1073,
      datagramReplayWindow: 64,
      maxConcurrentCircuits: 10,
      capacityClass: 0,
      maxCells: 100,
      maxBytes: 10000,
      maxCommands: 10,
      idleTimeoutMs: 30000,
      maxQueuedBytes: 50000,
      epoch: 1n,
      issuedAt: 100n,
      expiresAt: 200n,
      policyCount: 0
    },
    authSuffix: b4a.alloc(64, 5)
  }
}

function sampleRedactedProof() {
  return {
    fields: {
      responderAdvertisementDigest: b4a.alloc(32, 1),
      initiatorIdentity: b4a.alloc(32, 2),
      responderIdentity: b4a.alloc(32, 3),
      branchClass: 2,
      branchId: b4a.alloc(16, 4),
      circuitId: b4a.alloc(16, 5),
      generation: 1n,
      extensionIndex: 1,
      clientTailEphemeralPublicKey: b4a.alloc(32, 6),
      clientNonce: b4a.alloc(32, 7),
      advertisedRouteEncryptionPublicKey: b4a.alloc(32, 8),
      admittedLimitsDigest: b4a.alloc(32, 9),
      expiresAt: 1000n,
      responderProofNonce: b4a.alloc(32, 10)
    },
    authSuffix: b4a.alloc(64, 11)
  }
}

function sampleLinkReply(index) {
  const proof = sampleRedactedProof()
  proof.fields.extensionIndex = index
  const accept = encodePeerTransport(PEER_MESSAGE_ID.PEER_LINK_ACCEPT_V2, {
    offerDigest: b4a.alloc(32, 12),
    advertisementDigest: proof.fields.responderAdvertisementDigest,
    responderIdentity: proof.fields.responderIdentity,
    observedPredecessorEndpoint: b4a.alloc(19, 13),
    responderLinkEphemeralPublicKey: b4a.alloc(32, 14),
    admittedLimits: makeLimits({ expiresAt: proof.fields.expiresAt }),
    acceptedAt: 500n,
    acceptNonce: b4a.alloc(32, 15)
  }, b4a.alloc(64, 16))
  return {
    accept,
    proof,
    proofWire: encodePeerTransport(
      PEER_MESSAGE_ID.PEER_REDACTED_RESPONDER_PROOF_V2, proof.fields, proof.authSuffix
    )
  }
}

function sampleSemanticFirstHeader(id, bodyBytes) {
  const hdr = b4a.alloc(8)
  hdr[0] = 0; hdr[1] = 0; hdr[2] = 0; hdr[3] = 2 // version 2
  hdr[4] = id >>> 8; hdr[5] = id & 0xff
  hdr[6] = bodyBytes >>> 8; hdr[7] = bodyBytes & 0xff
  return hdr
}

test('roundtrip all 32 transport message types', (t) => {
  const capSample = sampleCapability()
  const capWire = encodePeerTransport(
    PEER_MESSAGE_ID.PEER_CAPABILITY_ADVERTISEMENT_V2,
    capSample.fields,
    capSample.authSuffix
  )

  const proofSample = sampleRedactedProof()
  const proofWire = encodePeerTransport(
    PEER_MESSAGE_ID.PEER_REDACTED_RESPONDER_PROOF_V2,
    proofSample.fields,
    proofSample.authSuffix
  )

  const openSample = {
    messageId: PEER_MESSAGE_ID.PEER_OPEN_V2,
    fields: {
      common: makeCommon({ routeId: b4a.alloc(16, 9) }),
      semanticFirstId: 0x0349,
      semanticClass: 1,
      reservedZero: 0,
      firstSemanticWireBytes: 486,
      requestedHandshakeFrames: 2,
      requestedHandshakeBytes: 582n,
      requestedDataFrames: 0,
      requestedDataBytes: 0n,
      openNonce: b4a.alloc(16, 8)
    }
  }
  const openWire = encodePeerTransport(openSample.messageId, openSample.fields)

  const hsHeader = sampleSemanticFirstHeader(0x0349, 478) // total wire 486 <= 981
  const hsPayload = b4a.concat([hsHeader, b4a.alloc(478, 1)])

  const testCases = [
    {
      messageId: PEER_MESSAGE_ID.PEER_CAPABILITY_ADVERTISEMENT_V2,
      fields: capSample.fields,
      authSuffix: capSample.authSuffix
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_CAPS_QUERY_V2,
      fields: {
        requestedMask: 9,
        randomTarget: b4a.alloc(32, 1),
        queryNonce: b4a.alloc(32, 2),
        maximumResults: 1,
        phase: 0,
        cookieExpiresAt: 0n,
        returnCookie: b4a.alloc(32, 0)
      }
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_CAPS_COOKIE_CHALLENGE_V2,
      fields: {
        queryNonce: b4a.alloc(32, 1),
        cookieExpiresAt: 100n,
        returnCookie: b4a.alloc(32, 2)
      }
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_CAPS_RESPONSE_V2,
      fields: {
        responderIdentity: b4a.alloc(32, 1),
        queryNonce: b4a.alloc(32, 2),
        responseTime: 50n,
        count: 1,
        advertisementLength: 260,
        completeAdvertisement: capWire
      },
      authSuffix: b4a.alloc(64, 3)
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_ACTIVE_CHALLENGE_V2,
      fields: {
        advertisementDigest: b4a.alloc(32, 1),
        responderIdentity: b4a.alloc(32, 2),
        requesterEphemeralX25519PublicKey: b4a.alloc(32, 3),
        challengeExpiresAt: 100n,
        queryNonce: b4a.alloc(32, 4),
        cookieExpiresAt: 200n,
        returnCookie: b4a.alloc(32, 5)
      }
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_ACTIVE_CHALLENGE_RESPONSE_V2,
      fields: {
        advertisementDigest: b4a.alloc(32, 1),
        responderIdentity: b4a.alloc(32, 2),
        requesterEphemeralPublicKey: b4a.alloc(32, 3),
        responderNonce: b4a.alloc(32, 4),
        challengeExpiresAt: 100n,
        queryNonce: b4a.alloc(32, 5),
        cookieExpiresAt: 200n,
        returnCookie: b4a.alloc(32, 6),
        routeKeyProof: b4a.alloc(32, 7)
      },
      authSuffix: b4a.alloc(64, 8)
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_DISCOVER_REQUEST_V2,
      fields: {
        requestNonce: b4a.alloc(32, 1),
        mode: 1,
        requestedMask: 9,
        randomTarget: b4a.alloc(32, 2),
        expiresAt: 500n,
        suppliedAdvertisementLength: 0,
        suppliedAdvertisement: b4a.alloc(0)
      }
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_DISCOVER_RESPONSE_V2,
      fields: {
        requestNonce: b4a.alloc(32, 1),
        currentTailIdentity: b4a.alloc(32, 2),
        completeAdvertisement: capWire,
        activeResponseDigest: b4a.alloc(32, 3),
        candidateAuthorityNonce: b4a.alloc(32, 4),
        verifiedAt: 10n,
        expiresAt: 1000n,
        candidateAuthorityCommitment: b4a.alloc(32, 5)
      }
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_LINK_OFFER_V2,
      fields: {
        advertisementDigest: b4a.alloc(32, 1),
        initiatorIdentity: b4a.alloc(32, 2),
        responderIdentity: b4a.alloc(32, 3),
        initiatorRole: 0,
        responderRole: 1,
        branchClass: 2,
        branchId: b4a.alloc(16, 4),
        circuitId: b4a.alloc(16, 5),
        generation: 1n,
        extensionIndex: 0,
        initiatorLinkEphemeralPublicKey: b4a.alloc(32, 6),
        clientTailEphemeralPublicKey: b4a.alloc(32, 7),
        clientNonce: b4a.alloc(32, 8),
        payloadParametersDigest: b4a.alloc(32, 9),
        requestedLimits: makeLimits(),
        offerDeadline: 1000n,
        initiatorForwardLimits: makeLimits(),
        candidateAuthorityCommitment: b4a.alloc(32, 0)
      },
      authSuffix: b4a.alloc(64, 10)
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_LINK_ACCEPT_V2,
      fields: {
        offerDigest: b4a.alloc(32, 1),
        advertisementDigest: b4a.alloc(32, 2),
        responderIdentity: b4a.alloc(32, 3),
        observedPredecessorEndpoint: b4a.alloc(19, 4),
        responderLinkEphemeralPublicKey: b4a.alloc(32, 5),
        admittedLimits: makeLimits(),
        acceptedAt: 500n,
        acceptNonce: b4a.alloc(32, 6)
      },
      authSuffix: b4a.alloc(64, 7)
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_REDACTED_RESPONDER_PROOF_V2,
      fields: proofSample.fields,
      authSuffix: proofSample.authSuffix
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_EXTENDED_V2,
      fields: {
        branchClass: 2,
        branchId: b4a.alloc(16, 1),
        circuitId: b4a.alloc(16, 2),
        generation: 1n,
        extensionIndex: 1,
        responderAdvertisementDigest: b4a.alloc(32, 3),
        proofLength: 378,
        completeProof: proofWire,
        extensionNonce: b4a.alloc(32, 4)
      }
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_TAIL_READY_V2,
      fields: {
        branchClass: 2,
        branchId: b4a.alloc(16, 1),
        circuitId: b4a.alloc(16, 2),
        generation: 1n,
        extensionIndex: 1,
        tailControlTranscriptDigest: b4a.alloc(32, 3),
        tailIdentity: b4a.alloc(32, 4),
        tailAdvertisementDigest: b4a.alloc(32, 5),
        clientNonce: b4a.alloc(32, 6),
        readyNonce: b4a.alloc(32, 7),
        expiresAt: 5000n
      },
      authSuffix: b4a.alloc(64, 8)
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_EXTEND_REQUEST_V2,
      fields: {
        branchClass: 2,
        branchId: b4a.alloc(16, 1),
        circuitId: b4a.alloc(16, 2),
        generation: 1n,
        extensionIndex: 0,
        advertisementLength: 260,
        advertisement: capWire,
        clientTailEphemeralPublicKey: b4a.alloc(32, 3),
        clientNonce: b4a.alloc(32, 4),
        payloadParametersDigest: b4a.alloc(32, 5),
        successorReverseLimits: makeLimits(),
        extensionNonce: b4a.alloc(32, 6),
        currentTailForwardLimits: makeLimits(),
        candidateAuthorityCommitment: b4a.alloc(32, 0)
      }
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_BRANCH_DESTROY_V2,
      fields: {
        branchClass: 2,
        branchId: b4a.alloc(16, 1),
        circuitId: b4a.alloc(16, 2),
        generation: 1n,
        reason: 1
      }
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_BRANCH_TEARDOWN_V2,
      fields: {
        branchClass: 2,
        branchId: b4a.alloc(16, 1),
        circuitId: b4a.alloc(16, 2),
        generation: 1n,
        reason: 2,
        teardownId: b4a.alloc(16, 3)
      }
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_BRANCH_TEARDOWN_ACK_V2,
      fields: {
        branchClass: 2,
        branchId: b4a.alloc(16, 1),
        circuitId: b4a.alloc(16, 2),
        generation: 1n,
        reason: 2,
        teardownId: b4a.alloc(16, 3)
      }
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_ROUTE_OFFER_V2,
      fields: {
        routeId: b4a.alloc(16, 1),
        circuitId: b4a.alloc(16, 2),
        generation: 1n,
        purpose: 2,
        sourceDirection: 0,
        flags: 0,
        expiresAt: 5000n,
        terminalAdvertisementDigest: b4a.alloc(32, 3),
        queryNonce: b4a.alloc(32, 4),
        clientEphemeralPublicKey: b4a.alloc(32, 5),
        forwardCells: 10,
        forwardBytes: 1000n,
        forwardCommands: 5,
        reverseCells: 10,
        reverseBytes: 1000n,
        reverseCommands: 5,
        maxStreams: 4,
        receiveFrames: 16,
        receiveBytes: 16000,
        semanticOwnedBytes: 8000,
        maxQueuedBytes: 20000,
        offerNonce: b4a.alloc(16, 6)
      },
      authSuffix: b4a.alloc(16, 7)
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_ROUTE_ACCEPT_V2,
      fields: {
        routeId: b4a.alloc(16, 1),
        circuitId: b4a.alloc(16, 2),
        generation: 1n,
        purpose: 2,
        sourceDirection: 0,
        flags: 0,
        expiresAt: 5000n,
        terminalAdvertisementDigest: b4a.alloc(32, 3),
        queryNonce: b4a.alloc(32, 4),
        clientEphemeralPublicKey: b4a.alloc(32, 5),
        offerDigest: b4a.alloc(32, 6),
        admittedForwardCells: 10,
        admittedForwardBytes: 1000n,
        admittedForwardCommands: 5,
        admittedReverseCells: 10,
        admittedReverseBytes: 1000n,
        admittedReverseCommands: 5,
        admittedMaxStreams: 4,
        admittedReceiveFrames: 16,
        admittedReceiveBytes: 16000,
        admittedSemanticOwnedBytes: 8000,
        admittedMaxQueuedBytes: 20000,
        offerNonce: b4a.alloc(16, 7),
        acceptNonce: b4a.alloc(16, 8)
      },
      authSuffix: b4a.alloc(16, 9)
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_ROUTE_REJECT_V2,
      fields: {
        routeId: b4a.alloc(16, 1),
        generation: 1n,
        purpose: 2,
        reserved3: b4a.alloc(3, 0),
        offerNonce: b4a.alloc(16, 2),
        reason: 1,
        reserved: 0,
        rejectNonce: b4a.alloc(16, 3)
      },
      authSuffix: b4a.alloc(16, 4)
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_RELIABLE_PACKET_V2,
      fields: {
        routeId: b4a.alloc(16, 9),
        laneSequence: 0n,
        nestedLength: openWire.byteLength,
        flags: 1,
        completeNestedObject: openWire
      }
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_RELIABLE_ACK_V2,
      fields: {
        routeId: b4a.alloc(16, 1),
        generation: 1n,
        dataCumulative: MAX_U64,
        dataBitmap: 0n,
        controlCumulative: 0n,
        controlBitmap: 0n,
        ackSnapshot: 1,
        reservedZero: 0
      }
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_OPEN_V2,
      fields: openSample.fields
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_OPENED_V2,
      fields: {
        common: makeCommon({ flags: 0 }),
        openNonce: b4a.alloc(16, 1),
        admittedDataFrames: 10,
        admittedDataBytes: 10000
      }
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_HANDSHAKE_V2,
      fields: {
        common: makeCommon(),
        semanticObjectOffset: 0,
        fragmentBytes: hsPayload.byteLength,
        fragmentFlags: 3,
        bytes: hsPayload
      }
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_DATA_V2,
      fields: {
        common: makeCommon(),
        dataBytes: 20,
        dataFlags: 0,
        bytes: b4a.alloc(20, 2)
      }
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_CREDIT_V2,
      fields: {
        common: makeCommon({ flags: 0 }),
        cumulativeGrantedFrames: 10n,
        cumulativeGrantedBytes: 10000n,
        creditEpoch: 1
      }
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_FIN_V2,
      fields: {
        common: makeCommon({ flags: 0 }),
        finalCiphertextOffset: 0n,
        finalDataSequence: MAX_U64
      }
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_CLOSE_V2,
      fields: {
        common: makeCommon({ flags: 0 }),
        finalCiphertextOffset: 100n,
        finalDataSequence: 5n
      }
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_RESET_V2,
      fields: {
        common: makeCommon({ flags: 0 }),
        finalCiphertextOffset: 100n,
        finalDataSequence: 5n,
        errorCode: 1,
        reserved: 0
      }
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_ROUTE_CLOSE_V2,
      fields: {
        routeId: b4a.alloc(16, 1),
        generation: 1n,
        closeNonce: b4a.alloc(16, 2)
      }
    },
    {
      messageId: PEER_MESSAGE_ID.PEER_ROUTE_CLOSE_ACK_V2,
      fields: {
        routeId: b4a.alloc(16, 1),
        generation: 1n,
        closeNonce: b4a.alloc(16, 2)
      }
    }
  ]

  for (const tc of testCases) {
    const wire = encodePeerTransport(tc.messageId, tc.fields, tc.authSuffix)
    t.ok(b4a.isBuffer(wire), `encoded message 0x${tc.messageId.toString(16)} to buffer`)

    const decoded = decodePeerTransport(wire)
    t.is(decoded.protocolVersion, 2)
    t.is(decoded.messageId, tc.messageId)
    t.ok(decoded.fields, `decoded fields for 0x${tc.messageId.toString(16)}`)
  }
})

test('reject invalid transport IDs', (t) => {
  const cap = sampleCapability()
  expectInvalid(t, () => encodePeerTransport(0x0320, cap.fields, cap.authSuffix))
  expectInvalid(t, () => encodePeerTransport(0x0340, cap.fields, cap.authSuffix))
})

test('reject scalar coercion and invalid fields', (t) => {
  const fields = {
    requestedMask: '9', // string coercion rejected
    randomTarget: b4a.alloc(32, 1),
    queryNonce: b4a.alloc(32, 2),
    maximumResults: 1,
    phase: 0,
    cookieExpiresAt: 0n,
    returnCookie: b4a.alloc(32, 0)
  }
  expectInvalid(t, () => encodePeerTransport(PEER_MESSAGE_ID.PEER_CAPS_QUERY_V2, fields))
})

test('reject nonzero generation violation', (t) => {
  const fields = {
    routeId: b4a.alloc(16, 1),
    generation: 0n, // nonzero required
    closeNonce: b4a.alloc(16, 2)
  }
  expectInvalid(t, () => encodePeerTransport(PEER_MESSAGE_ID.PEER_ROUTE_CLOSE_V2, fields))
})

test('reject candidateCommitment mismatch for linkOffer', (t) => {
  const baseFields = {
    advertisementDigest: b4a.alloc(32, 1),
    initiatorIdentity: b4a.alloc(32, 2),
    responderIdentity: b4a.alloc(32, 3),
    initiatorRole: 0,
    responderRole: 1,
    branchClass: 2,
    branchId: b4a.alloc(16, 4),
    circuitId: b4a.alloc(16, 5),
    generation: 1n,
    extensionIndex: 0,
    initiatorLinkEphemeralPublicKey: b4a.alloc(32, 6),
    clientTailEphemeralPublicKey: b4a.alloc(32, 7),
    clientNonce: b4a.alloc(32, 8),
    payloadParametersDigest: b4a.alloc(32, 9),
    requestedLimits: makeLimits(),
    offerDeadline: 1000n,
    initiatorForwardLimits: makeLimits(),
    candidateAuthorityCommitment: b4a.alloc(32, 1) // extensionIndex=0 requires zero commitment
  }
  expectInvalid(t, () =>
    encodePeerTransport(PEER_MESSAGE_ID.PEER_LINK_OFFER_V2, baseFields, b4a.alloc(64, 10))
  )
})

test('reject reliablePacket routeId mismatch', (t) => {
  const openSample = {
    messageId: PEER_MESSAGE_ID.PEER_OPEN_V2,
    fields: {
      common: makeCommon({ routeId: b4a.alloc(16, 9) }),
      semanticFirstId: 0x0349,
      semanticClass: 1,
      reservedZero: 0,
      firstSemanticWireBytes: 486,
      requestedHandshakeFrames: 2,
      requestedHandshakeBytes: 582n,
      requestedDataFrames: 0,
      requestedDataBytes: 0n,
      openNonce: b4a.alloc(16, 8)
    }
  }
  const openWire = encodePeerTransport(openSample.messageId, openSample.fields)

  const packetFields = {
    routeId: b4a.alloc(16, 1), // mismatch with nested open routeId (all 9s)
    laneSequence: 0n,
    nestedLength: openWire.byteLength,
    flags: 1,
    completeNestedObject: openWire
  }

  expectInvalid(t, () =>
    encodePeerTransport(PEER_MESSAGE_ID.PEER_RELIABLE_PACKET_V2, packetFields)
  )
})

test('reject reliablePacket lane flags mismatch for DATA', (t) => {
  const dataSample = {
    messageId: PEER_MESSAGE_ID.PEER_DATA_V2,
    fields: {
      common: makeCommon({ routeId: b4a.alloc(16, 5) }),
      dataBytes: 10,
      dataFlags: 0,
      bytes: b4a.alloc(10, 1)
    }
  }
  const dataWire = encodePeerTransport(dataSample.messageId, dataSample.fields)

  const packetFields = {
    routeId: b4a.alloc(16, 5),
    laneSequence: 0n,
    nestedLength: dataWire.byteLength,
    flags: 1, // CONTROL flag set for DATA packet (must be 0)
    completeNestedObject: dataWire
  }

  expectInvalid(t, () =>
    encodePeerTransport(PEER_MESSAGE_ID.PEER_RELIABLE_PACKET_V2, packetFields)
  )
})

test('reject FIN offset/seq zero vs MAX inconsistency', (t) => {
  const fields = {
    common: makeCommon(),
    finalCiphertextOffset: 0n,
    finalDataSequence: 5n // offset 0 requires finalDataSequence = MAX_U64
  }
  expectInvalid(t, () => encodePeerTransport(PEER_MESSAGE_ID.PEER_FIN_V2, fields))
})

test('reject invalid OPEN profile tuples and unregistered semantic ID gaps', (t) => {
  // Gap ID 0x0348
  const fieldsGap = {
    common: makeCommon({ routeId: b4a.alloc(16, 9) }),
    semanticFirstId: 0x0348, // unregistered gap ID
    semanticClass: 1,
    reservedZero: 0,
    firstSemanticWireBytes: 486,
    requestedHandshakeFrames: 2,
    requestedHandshakeBytes: 582n,
    requestedDataFrames: 0,
    requestedDataBytes: 0n,
    openNonce: b4a.alloc(16, 8)
  }
  expectInvalid(t, () => encodePeerTransport(PEER_MESSAGE_ID.PEER_OPEN_V2, fieldsGap))

  // Mismatched budget for 0x0349
  const fieldsBadBudget = {
    common: makeCommon({ routeId: b4a.alloc(16, 9) }),
    semanticFirstId: 0x0349,
    semanticClass: 1,
    reservedZero: 0,
    firstSemanticWireBytes: 500, // mismatch (should be 486)
    requestedHandshakeFrames: 2,
    requestedHandshakeBytes: 582n,
    requestedDataFrames: 0,
    requestedDataBytes: 0n,
    openNonce: b4a.alloc(16, 8)
  }
  expectInvalid(t, () => encodePeerTransport(PEER_MESSAGE_ID.PEER_OPEN_V2, fieldsBadBudget))
})

test('reject malformed HANDSHAKE FIRST and second fragments', (t) => {
  // FIRST fragment with less than 8 bytes
  const badShortPayload = {
    common: makeCommon(),
    semanticObjectOffset: 0,
    fragmentBytes: 4,
    fragmentFlags: 1,
    bytes: b4a.alloc(4, 0)
  }
  expectInvalid(t, () => encodePeerTransport(PEER_MESSAGE_ID.PEER_HANDSHAKE_V2, badShortPayload))

  // FIRST fragment with invalid version in header
  const badHeader = b4a.alloc(10, 0)
  badHeader[0] = 0; badHeader[1] = 0; badHeader[2] = 0; badHeader[3] = 1; // version 1
  const badHeaderPayload = {
    common: makeCommon(),
    semanticObjectOffset: 0,
    fragmentBytes: 10,
    fragmentFlags: 3,
    bytes: badHeader
  }
  expectInvalid(t, () => encodePeerTransport(PEER_MESSAGE_ID.PEER_HANDSHAKE_V2, badHeaderPayload))

  // Invalid fragment flags (> 3)
  const badFlagsPayload = {
    common: makeCommon(),
    semanticObjectOffset: 0,
    fragmentBytes: 10,
    fragmentFlags: 4,
    bytes: b4a.alloc(10, 0)
  }
  expectInvalid(t, () => encodePeerTransport(PEER_MESSAGE_ID.PEER_HANDSHAKE_V2, badFlagsPayload))
})

test('decoder returns owned views and isolates result buffers', (t) => {
  const sample = {
    requestedMask: 9,
    randomTarget: b4a.alloc(32, 1),
    queryNonce: b4a.alloc(32, 2),
    maximumResults: 1,
    phase: 0,
    cookieExpiresAt: 0n,
    returnCookie: b4a.alloc(32, 0)
  }
  const wire = encodePeerTransport(PEER_MESSAGE_ID.PEER_CAPS_QUERY_V2, sample)
  const decoded = decodePeerTransport(wire)

  t.ok(b4a.equals(decoded.fields.randomTarget, sample.randomTarget))
  // Modify decoded buffer
  decoded.fields.randomTarget.fill(0xff)
  t.not(b4a.equals(sample.randomTarget, decoded.fields.randomTarget))
})

test('link reply expectation fixes member count, order and extension index', (t) => {
  for (const index of [0, 1, 2]) {
    const sample = sampleLinkReply(index)
    const proof = index === 0 ? null : sample.proofWire
    const reply = encodePeerLinkReply(sample.accept, proof, index)
    const decoded = decodePeerLinkReply(reply, index)
    t.alike(decoded.accept285, sample.accept)
    t.alike(decoded.proof378, proof)
    for (const other of [0, 1, 2].filter((value) => value !== index)) {
      expectInvalid(t, () => decodePeerLinkReply(reply, other))
      expectInvalid(t, () => encodePeerLinkReply(sample.accept, proof, other))
    }
    expectInvalid(t, () => decodePeerLinkReply(reply.subarray(0, reply.length - 1), index))
    expectInvalid(t, () => decodePeerLinkReply(b4a.concat([reply, b4a.alloc(1)]), index))
    if (proof !== null) {
      expectInvalid(t, () => decodePeerLinkReply(b4a.concat([proof, sample.accept]), index))
      expectInvalid(t, () => decodePeerLinkReply(proof, index))
      expectInvalid(t, () => encodePeerLinkReply(sample.accept, null, index))
    } else {
      expectInvalid(t, () => encodePeerLinkReply(sample.accept, sample.proofWire))
      expectInvalid(t, () => encodePeerLinkReply(sample.accept, sample.proofWire, index))
    }
  }
})

test('link reply rejects spliced identity, advertisement and expiry before returning members', (t) => {
  const sample = sampleLinkReply(1)
  for (const replacement of [
    { responderIdentity: b4a.alloc(32, 99) },
    { responderAdvertisementDigest: b4a.alloc(32, 99) },
    { expiresAt: sample.proof.fields.expiresAt - 1n }
  ]) {
    const proof = encodePeerTransport(PEER_MESSAGE_ID.PEER_REDACTED_RESPONDER_PROOF_V2, {
      ...sample.proof.fields,
      ...replacement
    }, sample.proof.authSuffix)
    expectInvalid(t, () => encodePeerLinkReply(sample.accept, proof, 1))
    expectInvalid(t, () => decodePeerLinkReply(b4a.concat([sample.accept, proof]), 1))
  }
})

test('link reply member ownership survives caller and encoded packet erasure', (t) => {
  const sample = sampleLinkReply(2)
  const expectedAccept = b4a.from(sample.accept)
  const expectedProof = b4a.from(sample.proofWire)
  const wire = encodePeerLinkReply(sample.accept, sample.proofWire, 2)
  sample.accept.fill(0)
  sample.proofWire.fill(0)
  const decoded = decodePeerLinkReply(wire, 2)
  wire.fill(0)
  t.alike(decoded.accept285, expectedAccept)
  t.alike(decoded.proof378, expectedProof)
})
