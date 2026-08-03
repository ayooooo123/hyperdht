'use strict'

const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-universal')
const DHT = require('dht-rpc')

const { COMMANDS } = require('../../lib/constants')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  DatagramReplayWindow,
  OrderedReceiver,
  SenderCounter
} = require('../../lib/private/counters')
const { encodeDestinationRef } = require('../../lib/private/destination-ref')
const { encodeImmutableGetResponse } = require('../../lib/private/dht-exit-wire')
const {
  createDhtExitSeedsDeliveryAuthority,
  encodeDhtExitSeeds,
  signDhtExitSeeds
} = require('../../lib/private/dht-exit-seeds')
const {
  createDhtExitDestinationTable,
  destroyDhtExitDestinationTable,
  readDhtExitDestinationTableBinding,
  readDhtExitDestinationRef,
  reserveConfiguredBootstrapProbe,
  settleExitDhtReservation
} = require('../../lib/private/dht-exit-destination-table')
const {
  TEST_ONLY_DHT_EXIT_SOCKET_ISSUER,
  closeDhtExitIO,
  createDhtExitIOForTest,
  installDhtExitRoute,
  sendDhtExitSeeds,
  sendReservedExitDhtPacket
} = require('../../lib/private/dht-exit-io')
const {
  consumeDhtExitReservationIOConsumer,
  createDhtExitReservationChannel
} = require('../../lib/private/dht-exit-reservation')
const finalExitActivation = require('../../lib/private/final-exit-activation')
const {
  claimFinalExitActivation,
  createFinalExitActivationClaim,
  openFinalExit,
  takeDhtExitOpenAuthority,
  takeEndpointDhtExitOpenAuthority
} = finalExitActivation
const { fragment, Reassembler } = require('../../lib/private/fragments')
const guardLinks = require('../../lib/private/guard-link')
const {
  LiveRouteAuthority,
  bindOpenRouteTransport,
  issueLiveRouteDestination,
  receiveOpenRouteSeedPayload
} = require('../../lib/private/live-route-authority')
const {
  M3AdjacencyAuthority,
  deriveM3CellIds,
  destroyM3RouteTransport,
  receiveM3RouteFrame,
  sendM3RouteFrame,
  takeM3RouteTransport,
  takeM3TailCapability
} = require('../../lib/private/m3-adjacency-runtime')
const {
  consumeOpenRouteHandoff,
  destroyOpenRouteMaterial
} = require('../../lib/private/open-route-handoff')
const opaqueDestination = require('../../lib/private/opaque-destination')
const { signRedactedResponderProof } = require('../../lib/private/redacted-responder-proof')
const { BRANCH_CLASS, CELL_CLASS, DIRECTION, M3_MESSAGE_ID } = require('../../lib/private/protocol')
const { RELAY_CAPABILITY, ROLE, encodeM3Object } = require('../../lib/private/protocol')
const {
  decodeRelayCapabilityAdvertisement,
  digestRelayCapabilityAdvertisement
} = require('../../lib/private/relay-capability')
const {
  createDhtExitReadySigner,
  createRelayIdentitySigningAuthority,
  createTailReadySigner,
  destroyRelayIdentitySigningAuthority
} = require('../../lib/private/relay-identity-signer')
const { RelayService } = require('../../lib/private/relay-service')
const { createQueryContexts } = require('../../lib/private/query-context')
const {
  ROUTE_ENDPOINT,
  RoutePayloadCodec,
  mintCreatedRoutePayloadContext
} = require('../../lib/private/route-payload')
const {
  TEST_ONLY_ROUTE_MANAGER_OBSERVER,
  createFinalExitActivationFactory,
  createRouteExtensionFactory,
  createRouteManager
} = require('../../lib/private/route-manager')
const {
  clearRoutedRequest,
  decodeRoutedRequest,
  encodeRoutedReply
} = require('../../lib/private/routed-dht')
const { RoutedDHTIO } = require('../../lib/private/routed-dht-io')
const {
  createTailControlResponderAuthority,
  createTailControlSession,
  decodeExtendRequest,
  digestAdmittedLimits,
  encodeExtended,
  encodeTailControlTranscript
} = require('../../lib/private/tail-control')
const { NOW, identityFor, liveTopologyFixture } = require('./live-topology-fixture')

const TEST_ONLY_M3_ESTABLISHED_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-m3-established-issuer'
)
const TEST_ONLY_BRANCH_SEED_READY_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-branch-seed-ready-issuer'
)
const TEST_ONLY_ENDPOINT_DHT_EXIT_OPEN_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-endpoint-dht-exit-open-issuer'
)
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
const TAIL_READY_DOMAIN = b4a.from('hyperdht-private-routes/m3/tail-ready/v1')
const TAIL_READY_TRANSCRIPT_DOMAIN = b4a.from(
  'hyperdht-private-routes/m3/tail-control/transcript-digest/v1'
)

function seed(value, size = 32) {
  return b4a.alloc(size, value)
}

function sequenceBytes(first) {
  let value = first
  return (size) => b4a.alloc(size, value++)
}

function routeCellContexts(initiator) {
  const contexts = {}
  for (const cellClass of [CELL_CLASS.CONTROL, CELL_CLASS.STREAM, CELL_CLASS.DATAGRAM]) {
    const forwardKey = seed(0x10 + cellClass)
    const reverseKey = seed(0x20 + cellClass)
    const forwardNonce = seed(0x30 + cellClass, 16)
    const reverseNonce = seed(0x40 + cellClass, 16)
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
            : new OrderedReceiver({ window: 256, gapTimeout: 5_000, now: () => 10_000 })
      }
    }
  }
  return contexts
}

function channelPair(edges, branchClass, leftNode, rightNode) {
  const queues = [[], []]
  const waiters = [[], []]
  const live = [true, true]
  const nodes = [leftNode, rightNode]
  return [0, 1].map((side) => ({
    send(packet) {
      if (!live[side]) throw new Error('closed physical channel endpoint')
      const peer = side ^ 1
      if (!live[peer]) throw new Error('closed physical channel peer')
      edges.push(
        Object.freeze({
          branch: branchClass,
          from: nodes[side],
          to: nodes[peer]
        })
      )
      const owned = b4a.from(packet)
      if (waiters[peer].length > 0) waiters[peer].shift().resolve(owned)
      else queues[peer].push(owned)
      return true
    },
    receive() {
      if (!live[side]) return Promise.reject(new Error('closed physical channel endpoint'))
      if (queues[side].length > 0) return Promise.resolve(queues[side].shift())
      return new Promise((resolve, reject) => waiters[side].push({ resolve, reject }))
    },
    destroy() {
      if (!live[side]) return false
      live[side] = false
      for (const waiter of waiters[side].splice(0)) {
        waiter.reject(new Error('closed physical channel endpoint'))
      }
      for (const packet of queues[side].splice(0)) packet.fill(0)
      return true
    }
  }))
}

function routeTransportPair(branch, network, clock) {
  const digest = seed(0x71 + branch.branchClass)
  const ids = deriveM3CellIds(digest, { crypto: cryptoSuite })
  const authority = m3Authority(clock)
  const adopted = [true, false].map((initiator, side) =>
    authority.adopt(
      guardLinks[TEST_ONLY_M3_ESTABLISHED_ISSUER].issue({
        initiator,
        completeOfferDigest: b4a.from(digest),
        localId: b4a.from(initiator ? ids.initiatorCellId : ids.responderCellId),
        peerLocalId: b4a.from(initiator ? ids.responderCellId : ids.initiatorCellId),
        branchClass: branch.branchClass,
        branchId: b4a.from(branch.branchId),
        circuitId: b4a.from(branch.circuitId),
        generation: branch.generation,
        extensionIndex: 0,
        localIdentity: seed(initiator ? 0x72 : 0x73),
        peerIdentity: seed(initiator ? 0x73 : 0x72),
        expiresAt: network.expiresAt,
        contexts: routeCellContexts(initiator),
        physicalChannel: initiator ? network.endpointChannel : network.exitChannel,
        clientTailEphemeralSecretKey: initiator ? seed(0x74) : null,
        tailControlTranscript: seed(0x75, 290)
      })
    )
  )
  const moved = adopted.map((entry) =>
    takeM3TailCapability(entry.tail, {
      wallNow: clock.wallNow,
      monotonicNow: clock.monotonicNow
    })
  )
  return {
    endpoint: takeM3RouteTransport(moved[0].transportOwner),
    exit: takeM3RouteTransport(moved[1].transportOwner),
    forwarders: network.forwarders
  }
}

function forwardingHop(channel) {
  return Object.freeze({
    send(packet) {
      return channel.send(packet)
    },
    close() {}
  })
}

function installOpaqueForwarder(branch, options) {
  const relay = new RelayService({
    now: () => Number(options.clock.monotonicNow()),
    schedule: options.clock.schedule,
    cancel: options.clock.cancelScheduled
  })
  relay.reserveCircuit({
    peerId: options.previousIdentity,
    circuitId: branch.circuitId,
    generation: branch.generation,
    previousHop: forwardingHop(options.previousChannel),
    nextHop: forwardingHop(options.nextChannel)
  })
  let live = true
  const pump = (channel, direction) => {
    Promise.resolve()
      .then(async () => {
        while (live) {
          let packet = null
          try {
            packet = await channel.receive()
            if (!live) break
            relay.forward(branch.circuitId, direction, packet)
            relay.dispatch()
          } finally {
            if (packet) packet.fill(0)
          }
        }
      })
      .catch(() => {})
  }
  pump(options.previousChannel, DIRECTION.FORWARD)
  pump(options.nextChannel, DIRECTION.REVERSE)
  return Object.freeze({
    diagnostics: () => Object.freeze({ state: live ? 'FORWARDING' : 'DESTROYED' }),
    destroy() {
      if (!live) return false
      live = false
      relay.destroy()
      options.previousChannel.destroy()
      options.nextChannel.destroy()
      return true
    }
  })
}

function createBranchNetwork(branch, guardIdentity, clock, edges, digestSeed) {
  const expiresAt = NOW + 20_000n
  const branchName = branch.branchClass === BRANCH_CLASS.LOOKUP ? 'lookup' : 'announce'
  const endpointNode = `${branchName}:endpoint`
  const guardNode = 'shared:guard'
  const middleNode = `${branchName}:middle`
  const exitNode = `${branchName}:exit`
  const endpointGuard = channelPair(edges, branch.branchClass, endpointNode, guardNode)
  const guardMiddle = channelPair(edges, branch.branchClass, guardNode, middleNode)
  const middleExit = channelPair(edges, branch.branchClass, middleNode, exitNode)
  const endpointIdentity = seed(digestSeed + 10)
  const guard = installOpaqueForwarder(branch, {
    clock,
    digestSeed,
    expiresAt,
    previousExtensionIndex: 0,
    previousChannel: endpointGuard[1],
    nextChannel: guardMiddle[0],
    previousIdentity: endpointIdentity,
    localIdentity: guardIdentity,
    nextIdentity: branch.middle.identity
  })
  const middle = installOpaqueForwarder(branch, {
    clock,
    digestSeed: digestSeed + 20,
    expiresAt,
    previousExtensionIndex: 1,
    previousChannel: guardMiddle[1],
    nextChannel: middleExit[0],
    previousIdentity: guardIdentity,
    localIdentity: branch.middle.identity,
    nextIdentity: branch.exit.identity
  })
  return Object.freeze({
    endpointChannel: endpointGuard[0],
    exitChannel: middleExit[1],
    expiresAt,
    forwarders: Object.freeze([guard, middle])
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

function encodeTailReadyFor(extended, request, signer, transcriptDigest, expiresAtMs) {
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
  body.set(seed(0xa3), 170)
  writeUint64(body, expiresAtMs, 202)
  const input = signatureInput(TAIL_READY_DOMAIN, M3_MESSAGE_ID.TAIL_READY_V1, body)
  return encodeM3Object({
    messageId: M3_MESSAGE_ID.TAIL_READY_V1,
    body,
    authSuffix: cryptoSuite.sign(input, signer.secretKey)
  })
}

function m3Authority(clock) {
  return new M3AdjacencyAuthority({
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled,
    crypto: cryptoSuite
  })
}

function tailSessionOptions(clock, absoluteDeadline, crypto = undefined) {
  const options = {
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled,
    absoluteDeadline
  }
  if (crypto !== undefined) options.crypto = crypto
  return options
}

function syntheticLink(branch, options) {
  const ids = deriveM3CellIds(options.completeOfferDigest, { crypto: cryptoSuite })
  return guardLinks[TEST_ONLY_M3_ESTABLISHED_ISSUER].issue({
    initiator: options.initiator,
    completeOfferDigest: b4a.from(options.completeOfferDigest),
    localId: b4a.from(options.initiator ? ids.initiatorCellId : ids.responderCellId),
    peerLocalId: b4a.from(options.initiator ? ids.responderCellId : ids.initiatorCellId),
    branchClass: branch.branchClass,
    branchId: b4a.from(branch.branchId),
    circuitId: b4a.from(branch.circuitId),
    generation: branch.generation,
    extensionIndex: options.extensionIndex,
    localIdentity: b4a.from(options.localIdentity),
    peerIdentity: b4a.from(options.peerIdentity),
    expiresAt: options.expiresAt,
    contexts: routeCellContexts(options.initiator),
    physicalChannel: options.physicalChannel,
    clientTailEphemeralSecretKey: options.initiator
      ? b4a.from(options.clientTailEphemeralSecretKey)
      : null,
    tailSharedSecret: options.initiator ? null : b4a.from(options.tailSharedSecret),
    tailControlTranscript: b4a.from(options.tailControlTranscript)
  })
}

function privateIdentityPair(identity) {
  for (let ordinal = 0; ordinal < 32; ordinal++) {
    const pair = identityFor(ROLE.PRIVATE, ordinal)
    if (b4a.equals(pair.publicKey, identity)) return pair
  }
  throw new Error('missing private identity pair')
}

function initiatorTailTranscript(branch, currentAdvertisement, requestedLimits, currentTailPair) {
  const decoded = decodeRelayCapabilityAdvertisement(currentAdvertisement)
  const advertisementDigest = digestRelayCapabilityAdvertisement(currentAdvertisement)
  const admittedLimitsDigest = digestAdmittedLimits(requestedLimits)
  try {
    return encodeTailControlTranscript({
      branchClass: branch.branchClass,
      branchId: branch.branchId,
      circuitId: branch.circuitId,
      generation: branch.generation,
      extensionIndex: 1,
      clientTailEphemeralPublicKey: currentTailPair.publicKey,
      advertisedTailRouteEncryptionPublicKey: decoded.routeEncryptionPublicKey,
      candidateAdvertisementDigest: advertisementDigest,
      clientNonce: seed(0x62),
      tailIdentity: decoded.relayIdentity,
      admittedLimitsDigest
    })
  } finally {
    advertisementDigest.fill(0)
    admittedLimitsDigest.fill(0)
  }
}

function createFinalOpenPair(branch, exitRecord, currentAdvertisement, clock, network) {
  const signedAdvertisement = exitRecord.canonicalBytes
  const responderIdentity = privateIdentityPair(branch.exit.identity)
  const decodedAdvertisement = decodeRelayCapabilityAdvertisement(signedAdvertisement)
  const currentDecodedAdvertisement = decodeRelayCapabilityAdvertisement(currentAdvertisement)
  const requestedLimits = Object.freeze({
    cellSize: 1200,
    maxCells: 64,
    maxBytes: 65_536,
    maxCommands: 10,
    idleTimeoutMs: 5_000,
    expiresAtMs: NOW + 20_000n
  })
  const completeOfferDigest = seed(0xe1)
  const currentTailPair = cryptoSuite.encryptionKeyPair(seed(0xe2))
  const initialTranscript = initiatorTailTranscript(
    branch,
    currentAdvertisement,
    requestedLimits,
    currentTailPair
  )
  const endpointAdopted = m3Authority(clock).adopt(
    syntheticLink(branch, {
      initiator: true,
      completeOfferDigest,
      extensionIndex: 1,
      localIdentity: currentDecodedAdvertisement.relayIdentity,
      peerIdentity: responderIdentity.publicKey,
      expiresAt: NOW + 20_000n,
      physicalChannel: network.endpointChannel,
      clientTailEphemeralSecretKey: currentTailPair.secretKey,
      tailControlTranscript: initialTranscript
    })
  )
  const endpointTail = createTailControlSession(
    endpointAdopted.tail,
    tailSessionOptions(clock, branch.absoluteDeadline || 30_000n, cryptoSuite)
  )
  const encodedExtend = endpointTail.sealExtend({
    advertisement: signedAdvertisement,
    advertisementDigest: digestRelayCapabilityAdvertisement(signedAdvertisement),
    extensionIndex: 2,
    requestedLimits,
    absoluteDeadline: 30_000n,
    randomBytes: () => seed(0xe3)
  })
  const request = decodeExtendRequest(encodedExtend)
  const admittedLimitsDigest = digestAdmittedLimits(requestedLimits)
  const transcriptDigest = cryptoSuite.hash([TAIL_READY_TRANSCRIPT_DOMAIN, initialTranscript])
  const proofValue = {
    responderAdvertisementDigest: digestRelayCapabilityAdvertisement(signedAdvertisement),
    initiatorIdentity: currentDecodedAdvertisement.relayIdentity,
    responderIdentity: decodedAdvertisement.relayIdentity,
    branchClass: branch.branchClass,
    branchId: request.branchId,
    circuitId: request.circuitId,
    generation: request.generation,
    extensionIndex: request.extensionIndex,
    clientTailEphemeralPublicKey: request.clientTailEphemeralPublicKey,
    clientNonce: request.clientNonce,
    advertisedRouteEncryptionPublicKey: decodedAdvertisement.routeEncryptionPublicKey,
    admittedLimitsDigest,
    expiresAtMs: NOW + 20_000n,
    responderProofNonce: seed(0xe4)
  }
  const finalTailPair = cryptoSuite.encryptionKeyPair(seed(0xe3))
  const sharedSecret = cryptoSuite.keyAgreement(
    finalTailPair.secretKey,
    decodedAdvertisement.routeEncryptionPublicKey
  )
  const finalTranscript = encodeTailControlTranscript({
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
    branchClass: branch.branchClass,
    branchId: request.branchId,
    circuitId: request.circuitId,
    generation: request.generation,
    extensionIndex: request.extensionIndex,
    responderAdvertisementDigest: proofValue.responderAdvertisementDigest,
    redactedProof: signRedactedResponderProof(proofValue, responderIdentity.secretKey),
    extensionNonce: request.extensionNonce
  }
  const completion = endpointTail.openExtended(encodeExtended(extended))
  endpointTail.completeClientExtension(
    completion,
    encodeTailReadyFor(
      extended,
      request,
      responderIdentity,
      transcriptDigest,
      proofValue.expiresAtMs
    )
  )
  const endpointFinalHandoff = endpointTail.takeFinalExitHandoff()
  const endpointClaim = createFinalExitActivationClaim(endpointFinalHandoff)
  const endpointActivationOwner = claimFinalExitActivation(endpointFinalHandoff, endpointClaim)
  const endpointSession = openFinalExit(
    createFinalExitActivationFactory({
      wallNow: clock.wallNow,
      monotonicNow: clock.monotonicNow,
      randomBytes: (size) => seed(0xe5, size),
      schedule: clock.schedule,
      cancelScheduled: clock.cancelScheduled
    }),
    {
      handoff: endpointActivationOwner,
      crypto: cryptoSuite,
      payloadParameters: PAYLOAD_PARAMETERS,
      readySigner: undefined
    }
  )

  const relayIdentity = createRelayIdentitySigningAuthority({
    identitySecretKey: responderIdentity.secretKey
  })
  const tailReadySigner = createTailReadySigner(relayIdentity)
  const dhtExitReadySigner = createDhtExitReadySigner(relayIdentity)
  const exitAdopted = m3Authority(clock).adopt(
    syntheticLink(branch, {
      initiator: false,
      completeOfferDigest,
      extensionIndex: 2,
      localIdentity: responderIdentity.publicKey,
      peerIdentity: currentDecodedAdvertisement.relayIdentity,
      expiresAt: NOW + 20_000n,
      physicalChannel: network.exitChannel,
      tailSharedSecret: sharedSecret,
      tailControlTranscript: finalTranscript
    })
  )
  const exitTail = createTailControlSession(exitAdopted.tail, tailSessionOptions(clock, 15_000n))
  createTailControlResponderAuthority(exitTail, exitAdopted.responderToken, {
    tailReadySigner,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    randomBytes: () => seed(0xe6),
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled
  })
  const exitFinalHandoff = exitTail.takeFinalExitHandoff()
  const exitClaim = createFinalExitActivationClaim(exitFinalHandoff)
  const exitActivationOwner = claimFinalExitActivation(exitFinalHandoff, exitClaim)
  const exitSession = openFinalExit(
    createFinalExitActivationFactory({
      wallNow: clock.wallNow,
      monotonicNow: clock.monotonicNow,
      randomBytes: (size) => seed(0xe7, size),
      schedule: clock.schedule,
      cancelScheduled: clock.cancelScheduled
    }),
    {
      handoff: exitActivationOwner,
      crypto: cryptoSuite,
      payloadParameters: PAYLOAD_PARAMETERS,
      readySigner: dhtExitReadySigner
    }
  )

  const activate = endpointSession.sealActivate()
  exitSession.openActivate(activate)
  const ready = exitSession.sealReady()
  endpointSession.openReady(ready)
  const ack = endpointSession.sealAck()
  const open = exitSession.openAck(ack)
  endpointSession.openOpen(open)

  takeEndpointDhtExitOpenAuthority(endpointSession)
  return {
    endpointHandoff: endpointSession.takeOpenHandoff(),
    exitAuthority: takeDhtExitOpenAuthority(exitSession),
    expiresAt: proofValue.expiresAtMs,
    close() {
      endpointSession.destroy()
      exitSession.destroy()
      destroyRelayIdentitySigningAuthority(relayIdentity)
      for (const forwarder of network.forwarders) forwarder.destroy()
    }
  }
}

class FakeDhtSocket {
  constructor() {
    this.sends = []
    this.messageHandler = null
    this.closed = false
  }

  bind() {}

  on(name, handler) {
    if (name === 'message') this.messageHandler = handler
  }

  send(packet, port, host) {
    this.sends.push({ packet: b4a.from(packet), port, host })
    return true
  }

  message(packet, from) {
    this.messageHandler(packet, from)
  }

  close() {
    this.closed = true
  }
}

function dhtResponseFor(packet, flags, suffix = b4a.alloc(0)) {
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

function openMaterialFor(branch, value) {
  const finalTranscriptDigest = seed(value + 11)
  return {
    finalTranscriptDigest,
    material: {
      initiator: true,
      expiresAt: NOW + 20_000n,
      branchClass: branch.branchClass,
      branchId: b4a.from(branch.branchId),
      circuitId: b4a.from(branch.circuitId),
      generation: branch.generation,
      exitIdentity: b4a.from(branch.exit.identity),
      policyDigest: seed(value + 1),
      payloadDigest: seed(value + 2),
      payloadForwardKey: seed(value + 3),
      payloadReverseKey: seed(value + 4),
      payloadForwardNoncePrefix: seed(value + 5, 16),
      payloadReverseNoncePrefix: seed(value + 6, 16),
      controlForwardKey: seed(value + 7),
      controlReverseKey: seed(value + 8),
      controlForwardNoncePrefix: seed(value + 9, 16),
      controlReverseNoncePrefix: seed(value + 10, 16),
      endpointOpenAuthority: null
    }
  }
}

let externalHarnesses = 0

async function liveAuthorityHarness(configurePublications = null, existing = null) {
  const externalPublications = configurePublications !== null
  const externalIndex = existing === null && externalPublications ? externalHarnesses++ : 0
  const topology =
    existing === null
      ? await liveTopologyFixture(
          externalPublications ? 47641 + externalIndex * 20 : 47631,
          externalPublications ? 47642 + externalIndex * 20 : 47632
        )
      : existing.topology
  const randomBytes = sequenceBytes(externalPublications ? 0xe1 + externalIndex * 8 : 0xb1)
  const manager =
    existing === null
      ? createRouteManager({
          guardLease: topology.guardLease,
          candidateDirectory: topology.directory,
          extensionFactory: createRouteExtensionFactory({
            wallNow: topology.clock.wallNow,
            monotonicNow: topology.clock.monotonicNow,
            randomBytes,
            schedule: topology.clock.schedule,
            cancelScheduled: topology.clock.cancelScheduled
          }),
          terminalFactory: createFinalExitActivationFactory({
            wallNow: topology.clock.wallNow,
            monotonicNow: topology.clock.monotonicNow,
            randomBytes,
            schedule: topology.clock.schedule,
            cancelScheduled: topology.clock.cancelScheduled
          }),
          monotonicNow: topology.clock.monotonicNow,
          randomBytes
        })
      : existing.manager
  const publications =
    configurePublications === null ? manager : configurePublications(manager, topology)
  if (existing === null) manager.buildInitialPair()
  const draft = manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().draft
  const endpointEdges = []
  const lookupExitRecord = topology.records.find((record) =>
    b4a.equals(record.identity, draft.lookup.exit.identity)
  )
  const currentSafety = topology.records.find((record) => record.role === ROLE.SAFETY)
  const lookupNetwork = createBranchNetwork(
    draft.lookup,
    currentSafety.identity,
    topology.clock,
    endpointEdges,
    0xc1
  )
  const announceNetwork = createBranchNetwork(
    draft.announce,
    currentSafety.identity,
    topology.clock,
    endpointEdges,
    0xd1
  )
  const finalPair = createFinalOpenPair(
    draft.lookup,
    lookupExitRecord,
    currentSafety.canonicalBytes,
    topology.clock,
    lookupNetwork
  )

  const exitChannel = createDhtExitReservationChannel(finalPair.exitAuthority)
  const table = createDhtExitDestinationTable(exitChannel.tableIssuer, {
    local: { host: '10.1.2.3', port: 41234 },
    configuredBootstrap: [{ host: '8.8.8.8', port: 49737 }],
    monotonicNow: topology.clock.monotonicNow,
    randomBytes: (size) => seed(0xb5, size)
  })
  const fakeSocket = new FakeDhtSocket()
  const correlatedReplies = []
  const exitIO = createDhtExitIOForTest(
    {
      host: '10.1.2.3',
      port: 41234,
      monotonicNow: topology.clock.monotonicNow,
      schedule: topology.clock.schedule,
      cancelScheduled: topology.clock.cancelScheduled,
      onReply(authority) {
        correlatedReplies.push(authority)
      }
    },
    TEST_ONLY_DHT_EXIT_SOCKET_ISSUER.create(() => fakeSocket),
    consumeDhtExitReservationIOConsumer(exitChannel.ioConsumer)
  )
  const bootstrapProbe = reserveConfiguredBootstrapProbe(
    table,
    0,
    topology.clock.monotonicNow() + 1_000n
  )
  sendReservedExitDhtPacket(exitIO, bootstrapProbe.sendAuthority)
  fakeSocket.message(dhtResponseFor(fakeSocket.sends[0].packet, 0), {
    host: '8.8.8.8',
    port: 49737
  })
  const seedDestinationRef = settleExitDhtReservation(
    bootstrapProbe.settlementAuthority,
    correlatedReplies.shift()
  )
  const seedDestination = readDhtExitDestinationRef(table, seedDestinationRef)

  const announceCreated = openMaterialFor(draft.announce, 0xa1)
  const announcePair = routeTransportPair(draft.announce, announceNetwork, topology.clock)
  announceCreated.material.endpointOpenAuthority = finalExitActivation[
    TEST_ONLY_ENDPOINT_DHT_EXIT_OPEN_ISSUER
  ].create({
    branchClass: BRANCH_CLASS.ANNOUNCE,
    branchId: draft.announce.branchId,
    circuitId: draft.announce.circuitId,
    generation: draft.announce.generation,
    exitIdentity: draft.announce.exit.identity,
    finalTranscriptDigest: announceCreated.finalTranscriptDigest,
    expiresAt: announceCreated.material.expiresAt,
    absoluteDeadline: draft.absoluteDeadline,
    controlKey: seed(0xae),
    controlNoncePrefix: seed(0xaf, 16)
  })
  bindOpenRouteTransport(announceCreated.material, {
    transport: announcePair.endpoint,
    finalTranscriptDigest: announceCreated.finalTranscriptDigest
  })
  const announceHandoff = Object.freeze({})
  const openRouteHandoff = require('../../lib/private/open-route-handoff')
  const original = {
    consumeOpenRouteHandoff: openRouteHandoff.consumeOpenRouteHandoff,
    revokeOpenRouteHandoff: openRouteHandoff.revokeOpenRouteHandoff,
    destroyOpenRouteMaterial: openRouteHandoff.destroyOpenRouteMaterial
  }
  let announceMaterial = announceCreated.material
  Object.assign(openRouteHandoff, {
    consumeOpenRouteHandoff(handoff) {
      if (handoff !== announceHandoff) return original.consumeOpenRouteHandoff(handoff)
      if (announceMaterial === null) throw new Error('spent announce OPEN handoff')
      const material = announceMaterial
      announceMaterial = null
      return material
    },
    revokeOpenRouteHandoff(handoff) {
      if (handoff !== announceHandoff) return original.revokeOpenRouteHandoff(handoff)
      const live = announceMaterial !== null
      announceMaterial = null
      return live
    },
    destroyOpenRouteMaterial(material) {
      if (material !== announceCreated.material) return original.destroyOpenRouteMaterial(material)
      return true
    }
  })
  try {
    publications.publishInitialPair({
      lookup: finalPair.endpointHandoff,
      announce: announceHandoff
    })
  } finally {
    Object.assign(openRouteHandoff, original)
  }

  const lookupOwner = opaqueDestination.createLiveOpaqueDestinations({
    branch: BRANCH_CLASS.LOOKUP,
    circuitId: draft.lookup.circuitId,
    generation: draft.lookup.generation,
    expiresAt: finalPair.expiresAt,
    wallNow: topology.clock.wallNow,
    monotonicNow: topology.clock.monotonicNow
  })
  const lookupSeedAdmission = publications.createDhtSeedAdmission(BRANCH_CLASS.LOOKUP, lookupOwner)
  const signedLookupSeeds = encodeDhtExitSeeds(
    signDhtExitSeeds(
      {
        branchClass: draft.lookup.branchClass,
        branchId: draft.lookup.branchId,
        circuitId: draft.lookup.circuitId,
        generation: draft.lookup.generation,
        exitIdentity: draft.lookup.exit.identity,
        seedSetNonce: seed(0xb6),
        destinationRefs: [seedDestinationRef]
      },
      privateIdentityPair(draft.lookup.exit.identity).secretKey
    )
  )
  opaqueDestination.stageDhtSeedAdmission(lookupSeedAdmission, signedLookupSeeds)
  const lookupCommitted = opaqueDestination.commitDhtSeedAdmission(
    opaqueDestination.sealDhtSeedAdmission(lookupSeedAdmission)
  )

  const announceOwner = opaqueDestination.createLiveOpaqueDestinations({
    branch: BRANCH_CLASS.ANNOUNCE,
    circuitId: draft.announce.circuitId,
    generation: draft.announce.generation,
    expiresAt: announceCreated.material.expiresAt,
    wallNow: topology.clock.wallNow,
    monotonicNow: topology.clock.monotonicNow
  })
  publications.createDhtSeedAdmission(BRANCH_CLASS.ANNOUNCE, announceOwner)
  const announceReady = opaqueDestination[TEST_ONLY_BRANCH_SEED_READY_ISSUER].create({
    branchClass: BRANCH_CLASS.ANNOUNCE,
    branchId: draft.announce.branchId,
    circuitId: draft.announce.circuitId,
    generation: draft.announce.generation,
    exitIdentity: draft.announce.exit.identity,
    expiresAt: announceCreated.material.expiresAt
  })
  publications.publishInitialSeedPair({
    lookup: lookupCommitted.branchSeedReady,
    announce: announceReady
  })
  const authority =
    existing === null && configurePublications === null
      ? new LiveRouteAuthority({ routeManager: manager })
      : null
  installDhtExitRoute(exitIO, table)
  return {
    authority,
    endpointEdges,
    exitIO,
    fakeSocket,
    lookupCircuitId: b4a.from(draft.lookup.circuitId),
    finalPair,
    manager,
    announcePair,
    seedDestination,
    table,
    topology,
    ownsTopology: existing === null
  }
}

function queryOptions(context) {
  return {
    transportContext: context,
    concurrency: 1,
    retries: 1
  }
}

async function rejection(promise) {
  try {
    await promise
  } catch (error) {
    return error
  }
  return null
}

async function closeLiveAuthorityHarness(harness) {
  closeDhtExitIO(harness.exitIO)
  destroyDhtExitDestinationTable(harness.table)
  harness.finalPair.close()
  try {
    harness.manager.destroy()
  } catch {}
  try {
    destroyM3RouteTransport(harness.announcePair.exit)
  } catch {}
  for (const forwarder of harness.announcePair.forwarders) forwarder.destroy()
  if (harness.ownsTopology) await harness.topology.close()
}

test('iterative immutable get uses live DHT exit route, qualified referral, and exact value', async (t) => {
  const harness = await liveAuthorityHarness()
  const contexts = createQueryContexts()
  const value = b4a.from('live-routed-immutable-value')
  const target = b4a.alloc(32)
  sodium.crypto_generichash(target, value)
  const routed = new RoutedDHTIO({
    authority: harness.authority,
    contexts,
    now: () => Number(harness.topology.clock.monotonicNow()),
    randomBytes(buffer) {
      buffer.fill(0x44)
    }
  })
  const dht = new DHT({
    outboundPolicy: 'transport-only',
    requestTransport: routed,
    requestTimeout: 1_000,
    concurrency: 1
  })
  const upstream = (async () => {
    await waitFor(() => harness.fakeSocket.sends.length >= 2)
    const closer = b4a.from([1, 1, 1, 1, 1, 0x49, 0xc2])
    harness.fakeSocket.message(dhtResponseFor(harness.fakeSocket.sends[1].packet, 0x04, closer), {
      host: '8.8.8.8',
      port: 49737
    })
    await waitFor(() => harness.fakeSocket.sends.length >= 3)
    harness.fakeSocket.message(dhtResponseFor(harness.fakeSocket.sends[2].packet, 0), {
      host: '1.1.1.1',
      port: 49737
    })
    await waitFor(() => harness.fakeSocket.sends.length >= 4)
    harness.fakeSocket.message(
      dhtResponseFor(
        harness.fakeSocket.sends[3].packet,
        0x10,
        b4a.concat([b4a.from([value.byteLength]), value])
      ),
      { host: '1.1.1.1', port: 49737 }
    )
  })()

  const query = dht.query(
    { target, command: COMMANDS.IMMUTABLE_GET, value: null },
    queryOptions(contexts.immutableGet.lookup)
  )
  const replies = []
  for await (const reply of query) replies.push(reply)
  await upstream

  t.is(replies.length, 2)
  t.is(replies[0].value, null)
  t.alike(replies[1].value, value)
  const observedHash = b4a.alloc(32)
  sodium.crypto_generichash(observedHash, replies[1].value)
  t.alike(observedHash, target)
  const dhtSends = harness.fakeSocket.sends.slice(1)
  t.is(dhtSends.length, 3)
  t.alike(
    dhtSends.map(({ host }) => host),
    ['8.8.8.8', '1.1.1.1', '1.1.1.1']
  )
  const lookupEdges = harness.endpointEdges.filter((edge) => edge.branch === BRANCH_CLASS.LOOKUP)
  t.is(lookupEdges.length, 12)
  t.alike(Array.from(new Set(lookupEdges.map((edge) => `${edge.from}>${edge.to}`))).sort(), [
    'lookup:endpoint>shared:guard',
    'lookup:exit>lookup:middle',
    'lookup:middle>lookup:exit',
    'lookup:middle>shared:guard',
    'shared:guard>lookup:endpoint',
    'shared:guard>lookup:middle'
  ])
  const endpointPhysicalEdges = lookupEdges.filter(
    (edge) => edge.from === 'lookup:endpoint' || edge.to === 'lookup:endpoint'
  )
  t.ok(
    endpointPhysicalEdges.every(
      (edge) => edge.from === 'shared:guard' || edge.to === 'shared:guard'
    )
  )
  t.ok(lookupEdges.every((edge) => edge.from !== 'lookup:endpoint' || edge.to !== 'lookup:exit'))
  const exitBinding = readDhtExitDestinationTableBinding(harness.table)
  t.is(exitBinding.branchClass, BRANCH_CLASS.LOOKUP)
  t.alike(exitBinding.circuitId, harness.lookupCircuitId)
  t.is(harness.endpointEdges.filter((edge) => edge.branch === BRANCH_CLASS.ANNOUNCE).length, 0)

  const beforeEdges = harness.endpointEdges.length
  const beforeSends = harness.fakeSocket.sends.length
  const announceError = await rejection(
    Promise.resolve().then(() =>
      routed.request({
        context: contexts.immutableGet.announce,
        command: COMMANDS.IMMUTABLE_GET,
        to: Object.freeze({}),
        token: null,
        internal: false,
        target,
        value: null,
        attempt: 1
      })
    )
  )
  t.is(announceError && announceError.code, 'ERR_PRIVATE_COMMAND_UNSUPPORTED')
  t.is(harness.endpointEdges.length, beforeEdges)
  t.is(harness.fakeSocket.sends.length, beforeSends)

  await dht.destroy()
  await routed.destroy()
  closeDhtExitIO(harness.exitIO)
  destroyDhtExitDestinationTable(harness.table)
  harness.finalPair.close()
  try {
    harness.manager.destroy()
  } catch {}
  try {
    destroyM3RouteTransport(harness.announcePair.exit)
  } catch {}
  for (const forwarder of harness.announcePair.forwarders) forwarder.destroy()
  await harness.topology.close()
})

test('Gate 3A exposes immutable get query contexts only', (t) => {
  const contexts = createQueryContexts()
  t.alike(Object.keys(contexts), ['immutableGet', 'classify'])
  t.alike(Object.keys(contexts.immutableGet), ['lookup', 'announce'])
})

module.exports = {
  closeLiveAuthorityHarness,
  dhtResponseFor,
  liveAuthorityHarness,
  waitFor
}

test('production exit seed delivery crosses the moved OPEN route into endpoint admission', async (t) => {
  const topology = await liveTopologyFixture(47901, 47902)
  const randomBytes = sequenceBytes(0x71)
  const manager = createRouteManager({
    guardLease: topology.guardLease,
    candidateDirectory: topology.directory,
    extensionFactory: createRouteExtensionFactory({
      wallNow: topology.clock.wallNow,
      monotonicNow: topology.clock.monotonicNow,
      randomBytes,
      schedule: topology.clock.schedule,
      cancelScheduled: topology.clock.cancelScheduled
    }),
    terminalFactory: createFinalExitActivationFactory({
      wallNow: topology.clock.wallNow,
      monotonicNow: topology.clock.monotonicNow,
      randomBytes,
      schedule: topology.clock.schedule,
      cancelScheduled: topology.clock.cancelScheduled
    }),
    monotonicNow: topology.clock.monotonicNow,
    randomBytes
  })
  manager.buildInitialPair()
  const draft = manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().draft
  const exitRecord = topology.records.find((record) =>
    b4a.equals(record.identity, draft.lookup.exit.identity)
  )
  const safety = topology.records.find((record) => record.role === ROLE.SAFETY)
  const network = createBranchNetwork(draft.lookup, safety.identity, topology.clock, [], 0x72)
  const pair = createFinalOpenPair(
    draft.lookup,
    exitRecord,
    safety.canonicalBytes,
    topology.clock,
    network
  )
  const material = consumeOpenRouteHandoff(pair.endpointHandoff)
  const channel = createDhtExitReservationChannel(pair.exitAuthority)
  const table = createDhtExitDestinationTable(channel.tableIssuer, {
    local: { host: '10.1.2.3', port: 41234 },
    configuredBootstrap: [{ host: '8.8.8.8', port: 49737 }],
    monotonicNow: topology.clock.monotonicNow,
    randomBytes: (size) => seed(0xf3, size)
  })
  const socket = new FakeDhtSocket()
  const replies = []
  const io = createDhtExitIOForTest(
    {
      host: '10.1.2.3',
      port: 41234,
      monotonicNow: topology.clock.monotonicNow,
      schedule: topology.clock.schedule,
      cancelScheduled: topology.clock.cancelScheduled,
      onReply(authority) {
        replies.push(authority)
      }
    },
    TEST_ONLY_DHT_EXIT_SOCKET_ISSUER.create(() => socket),
    consumeDhtExitReservationIOConsumer(channel.ioConsumer)
  )
  try {
    const probe = reserveConfiguredBootstrapProbe(table, 0, topology.clock.monotonicNow() + 1_000n)
    sendReservedExitDhtPacket(io, probe.sendAuthority)
    socket.message(dhtResponseFor(socket.sends[0].packet, 0), {
      host: '8.8.8.8',
      port: 49737
    })
    await waitFor(() => replies.length === 1)
    settleExitDhtReservation(probe.settlementAuthority, replies.shift())
    installDhtExitRoute(io, table)
    const receiving = receiveOpenRouteSeedPayload(material, topology.clock.monotonicNow)
    const sent = sendDhtExitSeeds(
      io,
      createDhtExitSeedsDeliveryAuthority(table),
      seed(0xf4),
      privateIdentityPair(draft.lookup.exit.identity).secretKey
    )
    const encoded = await receiving
    await sent
    const owner = opaqueDestination.createLiveOpaqueDestinations({
      branch: BRANCH_CLASS.LOOKUP,
      circuitId: material.circuitId,
      generation: material.generation,
      expiresAt: material.expiresAt,
      wallNow: topology.clock.wallNow,
      monotonicNow: topology.clock.monotonicNow
    })
    const admission = opaqueDestination.createDhtSeedAdmissionAuthority(
      owner,
      material.endpointOpenAuthority
    )
    material.endpointOpenAuthority = null
    opaqueDestination.stageDhtSeedAdmission(admission, encoded)
    const committed = opaqueDestination.commitDhtSeedAdmission(
      opaqueDestination.sealDhtSeedAdmission(admission)
    )
    t.ok(Object.isFrozen(committed.branchSeedReady))
    t.is(committed.destinations.length, 1)
    encoded.fill(0)
    opaqueDestination.destroyLiveOpaqueDestinations(owner)
  } finally {
    closeDhtExitIO(io)
    destroyDhtExitDestinationTable(table)
    destroyOpenRouteMaterial(material)
    pair.close()
    manager.destroy()
    await topology.close()
  }
})
