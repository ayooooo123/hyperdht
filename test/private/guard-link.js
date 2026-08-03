'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { BootstrapEnvelopeCodec } = require('../../lib/private/bootstrap-envelope')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  DatagramReplayWindow,
  OrderedReceiver,
  SenderCounter
} = require('../../lib/private/counters')
const {
  digestAdmittedLimits,
  digestPayloadParameters
} = require('../../lib/private/link-parameters')
const {
  createExtensionOfferReceiver,
  createExtensionResponseReceiver,
  destroyExtensionOfferReceiver
} = require('../../lib/private/extension-setup-channel')
const { createLinkSetupAuthority } = require('../../lib/private/link-setup')
const { encodeM3ContextEnvelope } = require('../../lib/private/m3-context')
const {
  M3AdjacencyAuthority,
  beginM3Install,
  commitM3Install,
  createM3RelayForwardingFacade,
  deriveM3CellIds,
  validateM3Install
} = require('../../lib/private/m3-adjacency-runtime')
const { createM3ResponderAdopter } = require('../../lib/private/m3-adjacency-adopter')
const {
  decodeRelayCapabilityAdvertisement,
  deriveM3DhtNodeId,
  digestRelayCapabilityAdvertisement,
  encodeCanonicalEndpoint,
  encodeRelayCapabilityAdvertisement,
  providerServicePolicyForCapabilities,
  signRelayCapabilityAdvertisement
} = require('../../lib/private/relay-capability')
const {
  createRedactedResponderProofAuthority,
  decodeRedactedResponderProof,
  signRedactedResponderProof
} = require('../../lib/private/redacted-responder-proof')
const {
  BRANCH_CLASS,
  CAPACITY_CLASS,
  CELL_CLASS,
  CONTEXT_CLASS,
  DOMAIN,
  M3_LINK_ROLE,
  M3_MESSAGE_ID,
  RELAY_CAPABILITY,
  ROLE,
  LINK_OPERATION,
  PROTOCOL_VERSION,
  TOPOLOGY_ROLE,
  decodeM3Object,
  encodeM3Object,
  roleForIdentity
} = require('../../lib/private/protocol')
const {
  abortExtensionAdjacentLink,
  abortExtensionLinkCompletion,
  abortIndexZeroGuardLink,
  answerAcceptedExtensionReplay,
  completeIndexZeroGuardLink,
  createExtensionAdjacentLinkFactory,
  createExtensionLinkResponder,
  openExtensionAdjacentLink,
  createIndexZeroGuardLinkOffer,
  createIndexZeroGuardLinkResponder,
  createRelayAdjacentDialAuthority,
  destroyAcceptedExtensionAdjacencyOwner,
  destroyExtensionAdjacentLinkFactory,
  destroyM3EstablishedLink,
  destroyRelayAdjacentDialAuthority,
  dialRelayAdvertisement,
  readM3EstablishedLink,
  revokeAcceptedExtensionAdjacencyTransfer,
  takeAcceptedExtensionAdjacencyTransfer,
  takeExtensionResponderAdjacency
} = require('../../lib/private/guard-link')
const extensionGuardLinks = require('../../lib/private/guard-link')
const { LinkDirectory, signTopologyGrant } = require('../../lib/private/topology-grant')
const { selectUdxLoopbackHosts } = require('../../lib/private/udx-adapter')
const endpointModule = require('../../lib/private/udx-cell-endpoint')
const {
  createExtensionResponderSigner,
  createLinkOfferSigner,
  createRelayIdentitySigningAuthority,
  createTailReadySigner,
  destroyLinkOfferSigner,
  destroyRelayIdentitySigningAuthority,
  signLinkAccept
} = require('../../lib/private/relay-identity-signer')
const {
  admitTailExtend,
  borrowTailControlTransport,
  completeTailExtend,
  createTailControlResponderAuthority,
  createSuccessorTailReadyContext,
  createTailControlSession,
  destroyTailControlResponderAuthority,
  destroyTailControlSession,
  encodeTailControlTranscript,
  openTailAdjacentLink,
  sealTailReady,
  sealSuccessorTailReady,
  takeAdmittedExtendRequest
} = require('../../lib/private/tail-control')
const { createTailExtensionCommitter } = require('../../lib/private/tail-extension-committer')

const TEST_ONLY_COUNTER_FACTORY = Symbol.for('hyperdht-private-routes/test-only-counter-factory')
const TEST_ONLY_M3_ESTABLISHED_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-m3-established-issuer'
)
const TAKE_STAGED_RELAY_ADJACENT_OFFER = Symbol.for(
  'hyperdht-private-routes/relay-adjacent-staged-offer-taker'
)

const LINK_OFFER_SIZE = 374
const LINK_ACCEPT_SIZE = 285
const seed = (value) => b4a.alloc(32, value)

function errorCode(operation) {
  try {
    operation()
  } catch (err) {
    return err && err.code
  }
  return null
}

test('guard link exposes only opaque authenticated extension operations', (t) => {
  for (const name of [
    'abortExtensionAdjacentLink',
    'answerAcceptedExtensionReplay',
    'abortExtensionLinkCompletion',
    'abortExtensionLinkOffer',
    'completeExtensionLink',
    'createExtensionAdjacentLinkFactory',
    'createExtensionLinkOffer',
    'openExtensionAdjacentLink',
    'createExtensionLinkResponder',
    'createRelayAdjacentDialAuthority',
    'destroyAcceptedExtensionAdjacencyOwner',
    'destroyExtensionAdjacentLinkFactory',
    'destroyRelayAdjacentDialAuthority',
    'dialRelayAdvertisement',
    'revokeAcceptedExtensionAdjacencyTransfer',
    'takeAcceptedExtensionAdjacencyTransfer',
    'takeExtensionResponderAdjacency'
  ]) {
    t.is(typeof extensionGuardLinks[name], 'function', name)
  }
})

function withSlowAllocationProbe(operation, armAtSize, failAt = Infinity) {
  const originalAlloc = b4a.allocUnsafeSlow
  const allocations = []
  let armed = armAtSize === null
  let position = 0
  b4a.allocUnsafeSlow = (size) => {
    if (size === armAtSize) armed = true
    if (armed && (size === 16 || size === 32)) {
      if (++position === failAt) throw new Error('injected allocation failure')
      const output = originalAlloc(size)
      allocations.push(output)
      return output
    }
    return originalAlloc(size)
  }
  try {
    return { result: operation(), allocations, positions: position }
  } catch (err) {
    err.allocations = allocations
    err.positions = position
    throw err
  } finally {
    b4a.allocUnsafeSlow = originalAlloc
  }
}

function allZero(values) {
  return values.every((value) => value.every((byte) => byte === 0))
}

function testCounterFactory(failAt, counters) {
  let position = 0
  return (cellClass, sender, now) => {
    if (++position === failAt) throw new Error('injected counter construction failure')
    const counter = sender
      ? new SenderCounter()
      : cellClass === 2
        ? new DatagramReplayWindow({ window: 256 })
        : new OrderedReceiver({ window: 256, gapTimeout: 5000, now })
    counters.push(counter)
    return counter
  }
}

test('guard-link exposes only index-zero and authenticated extension ownership', (t) => {
  t.alike(Object.keys(require('../../lib/private/guard-link')).sort(), [
    'LINK_ACCEPT_SIZE',
    'LINK_OFFER_SIZE',
    'abortExtensionAdjacentLink',
    'abortExtensionLinkCompletion',
    'abortExtensionLinkOffer',
    'abortIndexZeroGuardLink',
    'answerAcceptedExtensionReplay',
    'completeExtensionLink',
    'completeIndexZeroGuardLink',
    'createExtensionAdjacentLinkFactory',
    'createExtensionLinkOffer',
    'createExtensionLinkResponder',
    'createIndexZeroGuardLinkOffer',
    'createIndexZeroGuardLinkResponder',
    'createRelayAdjacentDialAuthority',
    'destroyAcceptedExtensionAdjacencyOwner',
    'destroyExtensionAdjacentLinkFactory',
    'destroyM3AuthenticatedBranchBinding',
    'destroyM3EstablishedLink',
    'destroyRelayAdjacentDialAuthority',
    'destroyTakenM3EstablishedLink',
    'dialRelayAdvertisement',
    'openExtensionAdjacentLink',
    'readM3EstablishedLink',
    'revokeAcceptedExtensionAdjacencyTransfer',
    'takeAcceptedExtensionAdjacencyTransfer',
    'takeExtensionResponderAdjacency',
    'takeM3AuthenticatedBranchBinding',
    'takeM3EstablishedLink'
  ])
})

const NOW = 1_000n
const OFFER_DOMAIN = b4a.from('hyperdht-private-routes/m3/link-offer/v1')
const ACCEPT_DOMAIN = b4a.from('hyperdht-private-routes/m3/link-accept/v1')
const PAYLOAD_PARAMETERS = Object.freeze({
  cellSize: 1200,
  maxCellPayload: 1146,
  contextEnvelopeSize: 1101,
  routeFrameSize: 1100,
  maxRoutePayload: 1073,
  datagramReplayWindow: 64,
  maxQueuedBytes: 65_536,
  idleTimeoutMs: 30_000
})

function signatureInput(domain, messageId, body) {
  const output = b4a.allocUnsafe(2 + domain.byteLength + 8 + body.byteLength)
  output.writeUInt16BE(domain.byteLength, 0)
  domain.copy(output, 2)
  output.writeUInt32BE(1, 2 + domain.byteLength)
  output.writeUInt16BE(messageId, 6 + domain.byteLength)
  output.writeUInt16BE(body.byteLength, 8 + domain.byteLength)
  body.copy(output, 10 + domain.byteLength)
  return output
}

function resign(encoded, messageId, domain, secretKey, mutate) {
  const object = decodeM3Object(encoded)
  mutate(object.body)
  return encodeM3Object({
    messageId,
    body: object.body,
    authSuffix: cryptoSuite.sign(signatureInput(domain, messageId, object.body), secretKey)
  })
}

function identityForRole(role, start) {
  for (let value = start; value < 256; value++) {
    const pair = cryptoSuite.keyPair(seed(value))
    if (roleForIdentity(pair.publicKey) === role) return pair
  }
  throw new Error('missing deterministic role identity')
}

function fixture(guard = cryptoSuite.keyPair(seed(2))) {
  const route = cryptoSuite.encryptionKeyPair(seed(5))
  const endpoint = encodeCanonicalEndpoint({
    addressFamily: 4,
    addressBytes: b4a.from([192, 0, 2, 41]),
    port: 49737
  })
  const capabilityMask = RELAY_CAPABILITY.CIRCUIT_RELAY_V1
  const advertisement = encodeRelayCapabilityAdvertisement(
    signRelayCapabilityAdvertisement(
      {
        relayIdentity: guard.publicKey,
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
        maxConcurrentCircuits: 8,
        capacityClass: CAPACITY_CLASS.SMALL,
        maxCellsPerCircuit: 100,
        maxBytesPerCircuit: 100_000,
        maxCommandsPerCircuit: 10,
        idleTimeoutMs: 30_000,
        maxQueuedBytes: 65_536,
        epoch: 1n,
        issuedAtMs: NOW,
        expiresAtMs: 20_000n,
        providerServicePolicyEntries: providerServicePolicyForCapabilities(capabilityMask)
      },
      guard.secretKey
    )
  )
  return { advertisement, endpoint, guard, route }
}

function exactDialOptions(overrides = {}) {
  return {
    advertisement: b4a.alloc(1),
    advertisementDigest: b4a.alloc(32),
    requiredRole: ROLE.SAFETY,
    wireExpiresAt: 2_000n,
    localDeadline: 3_000n,
    ...overrides
  }
}

function exactFactoryOptions(dialAuthority, linkOfferSigner, destroy, callbacks = {}) {
  const proofAuthority =
    callbacks.proofAuthority ||
    createRedactedResponderProofAuthority({ now: callbacks.wallNow || (() => NOW) })
  return {
    dialAuthority,
    linkOfferSigner,
    proofVerifier: callbacks.proofVerifier || proofAuthority.verifier,
    proofConsumer: callbacks.proofConsumer || proofAuthority.consumer,
    wallNow: callbacks.wallNow || (() => NOW),
    monotonicNow: callbacks.monotonicNow || (() => NOW),
    randomBytes: callbacks.randomBytes || ((size) => b4a.alloc(size)),
    schedule: callbacks.schedule || (() => Object.freeze({})),
    cancelScheduled: callbacks.cancelScheduled || (() => {}),
    destroy
  }
}
let nativeAdjacentPort = 49300

async function nativeAdjacentPair(currentIdentity, nextIdentity) {
  const platform = global.Bare ? Bare.platform : process.platform
  const [leftHost, rightHost] = selectUdxLoopbackHosts({ platform })
  const leftPort = nativeAdjacentPort
  const rightPort = nativeAdjacentPort + 1
  nativeAdjacentPort += 2
  const grantAuthority = cryptoSuite.keyPair(seed(0xd1))
  const runId32 = seed(0xd2)
  const grant = signTopologyGrant(
    {
      version: PROTOCOL_VERSION,
      format: 0,
      grantId32: seed(0xd3),
      endpointA: {
        identity32: currentIdentity.publicKey,
        role: TOPOLOGY_ROLE.SAFETY_FINAL,
        host: leftHost,
        port: leftPort,
        operations: LINK_OPERATION.INITIATE
      },
      endpointB: {
        identity32: nextIdentity.publicKey,
        role: TOPOLOGY_ROLE.PRIVATE_ENTRY,
        host: rightHost,
        port: rightPort,
        operations: LINK_OPERATION.ACCEPT
      },
      epoch: 1n,
      notBefore: 0n,
      expiresAt: 60_000n,
      runId32
    },
    grantAuthority.secretKey
  )
  const makeHandle = (local, peer, localRole, peerRole, operation) => {
    const directory = new LinkDirectory({
      localIdentity32: local.publicKey,
      localRole,
      authorityPublicKey: grantAuthority.publicKey,
      epoch: 1n,
      runId32,
      now: () => 1n,
      schedule: setTimeout,
      cancel: clearTimeout,
      onClose() {}
    })
    const digest32 = directory.add(grant)
    return {
      directory,
      handle: directory.authorize({
        digest32,
        operation,
        localIdentity32: local.publicKey,
        localRole,
        peerIdentity32: peer.publicKey,
        peerRole,
        epoch: 1n,
        runId32
      })
    }
  }
  const leftHandle = makeHandle(
    currentIdentity,
    nextIdentity,
    TOPOLOGY_ROLE.SAFETY_FINAL,
    TOPOLOGY_ROLE.PRIVATE_ENTRY,
    LINK_OPERATION.INITIATE
  )
  const rightHandle = makeHandle(
    nextIdentity,
    currentIdentity,
    TOPOLOGY_ROLE.PRIVATE_ENTRY,
    TOPOLOGY_ROLE.SAFETY_FINAL,
    LINK_OPERATION.ACCEPT
  )
  let leftSession = null
  let rightSession = null
  const left = new endpointModule.UdxCellEndpoint({
    host: leftHost,
    port: leftPort,
    onBootstrap(packet) {
      if (leftSession) void leftSession.receive(packet)
    },
    onCell() {
      return true
    },
    onLinkFailure() {}
  })
  const right = new endpointModule.UdxCellEndpoint({
    host: rightHost,
    port: rightPort,
    onBootstrap(packet) {
      if (rightSession) void rightSession.receive(packet)
    },
    onCell() {
      return true
    },
    onLinkFailure() {}
  })
  await left.bind()
  await right.bind()
  const responderStatic = cryptoSuite.encryptionKeyPair(seed(0xd4))
  const started = Date.now()
  const now = () => Date.now() - started
  let random = 0xd5
  const randomBytes = (size) => b4a.alloc(size, random++)
  return {
    endpoint: encodeCanonicalEndpoint({
      addressFamily: rightHost.includes(':') ? 6 : 4,
      addressBytes: rightHost.includes(':')
        ? b4a.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        : b4a.from(rightHost.split('.').map(Number)),
      port: rightPort
    }),
    async open(branch) {
      const common = {
        circuitId: b4a.from(branch.circuitId),
        epoch: 1n,
        initiatorIdentity: currentIdentity.publicKey,
        responderIdentity: nextIdentity.publicKey,
        initiatorLocalId: b4a.alloc(16, 0xd6),
        responderLocalId: b4a.alloc(16, 0xd7),
        expiresAt: 60_000n
      }
      rightSession = right.openLink(rightHandle.handle, {
        mode: 'accept',
        codec: new BootstrapEnvelopeCodec({
          linkHandle: rightHandle.handle,
          localIdentitySecretKey: nextIdentity.secretKey,
          padding: randomBytes
        }),
        linkSetup: createLinkSetupAuthority({ now, randomBytes }),
        setup: {
          ...common,
          responderStaticSecretKey: responderStatic.secretKey,
          responderIdentitySecretKey: nextIdentity.secretKey
        },
        now,
        schedule: setTimeout,
        cancel: clearTimeout,
        randomBytes,
        absoluteDeadline: 10_000,
        signedExpiry: 60_000,
        authorizedExpiry: 60_000
      })
      leftSession = left.openLink(leftHandle.handle, {
        mode: 'initiate',
        codec: new BootstrapEnvelopeCodec({
          linkHandle: leftHandle.handle,
          localIdentitySecretKey: currentIdentity.secretKey,
          padding: randomBytes
        }),
        linkSetup: createLinkSetupAuthority({ now, randomBytes }),
        setup: {
          ...common,
          responderStaticKey: responderStatic.publicKey,
          initiatorIdentitySecretKey: currentIdentity.secretKey
        },
        now,
        schedule: setTimeout,
        cancel: clearTimeout,
        randomBytes,
        absoluteDeadline: 10_000,
        signedExpiry: 60_000,
        authorizedExpiry: 60_000
      })
      const leftEstablished = await leftSession.open()
      if (!rightSession.established) throw new Error('native adjacent responder did not establish')
      return {
        initiator: endpointModule.createM3CellLinkTransferIssuer(left, leftEstablished),
        responder: endpointModule.createM3CellLinkTransferIssuer(right, rightSession.established)
      }
    },
    async destroy() {
      if (leftSession) await leftSession.close().catch(() => {})
      if (rightSession) await rightSession.close().catch(() => {})
      await left.close().catch(() => {})
      await right.close().catch(() => {})
      leftHandle.directory.destroy()
      rightHandle.directory.destroy()
    }
  }
}

function tailClock({ wall = NOW, monotonic = 10_000n } = {}) {
  let currentWall = wall
  let currentMonotonic = monotonic
  let nextHandle = 0
  const timers = new Map()
  const cancelled = []
  return {
    wallNow() {
      return currentWall
    },
    monotonicNow() {
      return currentMonotonic
    },
    schedule(callback, delay) {
      const handle = ++nextHandle
      timers.set(handle, { callback, delay })
      return handle
    },
    cancelScheduled(handle) {
      cancelled.push(handle)
      timers.delete(handle)
    },
    fire(handle) {
      const timer = timers.get(handle)
      if (!timer) return false
      timers.delete(handle)
      timer.callback()
      return true
    },
    pending() {
      return timers.size
    },
    handles() {
      return [...timers.keys()]
    },
    setWall(value) {
      currentWall = value
    },
    setMonotonic(value) {
      currentMonotonic = value
    },
    cancelled
  }
}
function tailAuthority(clock) {
  return new M3AdjacencyAuthority({
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled,
    crypto: cryptoSuite
  })
}

function tailContexts(initiator) {
  const completeOfferDigest = b4a.from(Array.from({ length: 32 }, (_, index) => index))
  const ids = deriveM3CellIds(completeOfferDigest, { crypto: cryptoSuite })
  const forwardKey = b4a.alloc(32, 0x10)
  const reverseKey = b4a.alloc(32, 0x20)
  const forwardNonce = b4a.alloc(16, 0x30)
  const reverseNonce = b4a.alloc(16, 0x40)
  const values = {}
  for (const cellClass of [CELL_CLASS.CONTROL, CELL_CLASS.STREAM, CELL_CLASS.DATAGRAM]) {
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
  return { completeOfferDigest, ids, values }
}

function privateRouteAdvertisement(identity, route, endpoint, capabilityMask) {
  return encodeRelayCapabilityAdvertisement(
    signRelayCapabilityAdvertisement(
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
        maxConcurrentCircuits: 8,
        capacityClass: CAPACITY_CLASS.SMALL,
        maxCellsPerCircuit: 100,
        maxBytesPerCircuit: 100_000,
        maxCommandsPerCircuit: 10,
        idleTimeoutMs: 30_000,
        maxQueuedBytes: 65_536,
        epoch: 1n,
        issuedAtMs: NOW,
        expiresAtMs: 20_000n,
        providerServicePolicyEntries: providerServicePolicyForCapabilities(capabilityMask)
      },
      identity.secretKey
    )
  )
}

function tailChannelPair() {
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

function issueTailLink(advertisement, requestedLimits, overrides = {}) {
  const initiator = overrides.initiator !== false
  const decoded = decodeRelayCapabilityAdvertisement(advertisement)
  const advertisementDigest = digestRelayCapabilityAdvertisement(advertisement)
  const admittedLimitsDigest = digestAdmittedLimits(requestedLimits)
  const currentTailPair = cryptoSuite.encryptionKeyPair(seed(0x61))
  const context = tailContexts(initiator)
  try {
    return extensionGuardLinks[TEST_ONLY_M3_ESTABLISHED_ISSUER].issue({
      initiator,
      completeOfferDigest: context.completeOfferDigest,
      localId: initiator ? context.ids.initiatorCellId : context.ids.responderCellId,
      peerLocalId: initiator ? context.ids.responderCellId : context.ids.initiatorCellId,
      branchClass: BRANCH_CLASS.LOOKUP,
      branchId: b4a.alloc(16, 0x41),
      circuitId: b4a.alloc(16, 0x42),
      generation: 7n,
      extensionIndex: 1,
      localIdentity: initiator ? b4a.alloc(32, 0x51) : b4a.from(decoded.relayIdentity),
      peerIdentity: b4a.alloc(32, 0x52),
      expiresAt: 20_000n,
      contexts: context.values,
      physicalChannel: overrides.physicalChannel || Object.freeze({ destroy() {} }),
      clientTailEphemeralSecretKey: initiator ? currentTailPair.secretKey : null,
      tailControlTranscript: encodeTailControlTranscript({
        branchClass: BRANCH_CLASS.LOOKUP,
        branchId: b4a.alloc(16, 0x41),
        circuitId: b4a.alloc(16, 0x42),
        generation: 7n,
        extensionIndex: 1,
        clientTailEphemeralPublicKey: currentTailPair.publicKey,
        advertisedTailRouteEncryptionPublicKey: decoded.routeEncryptionPublicKey,
        candidateAdvertisementDigest: advertisementDigest,
        clientNonce: b4a.alloc(32, 0x62),
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

async function admittedExtensionFixture(options = {}) {
  const clock = tailClock()
  const currentIdentity = identityForRole(ROLE.SAFETY, 50)
  const nextIdentity = identityForRole(ROLE.PRIVATE, 80)
  const currentRoute = cryptoSuite.encryptionKeyPair(seed(0x91))
  const nextRoute = cryptoSuite.encryptionKeyPair(seed(0x92))
  const currentEndpoint = encodeCanonicalEndpoint({
    addressFamily: 4,
    addressBytes: b4a.from([192, 0, 2, 51]),
    port: 44_051
  })
  const nextEndpoint =
    options.nextEndpoint ||
    encodeCanonicalEndpoint({
      addressFamily: 4,
      addressBytes: b4a.from([192, 0, 2, 80]),
      port: 44_080
    })
  const currentAdvertisement = privateRouteAdvertisement(
    currentIdentity,
    currentRoute,
    currentEndpoint,
    RELAY_CAPABILITY.CIRCUIT_RELAY_V1
  )
  const nextAdvertisement = privateRouteAdvertisement(
    nextIdentity,
    nextRoute,
    nextEndpoint,
    RELAY_CAPABILITY.CIRCUIT_RELAY_V1 | RELAY_CAPABILITY.DHT_EXIT_V1
  )
  const requestedLimits = Object.freeze({
    cellSize: 1200,
    maxCells: 64,
    maxBytes: 65_536,
    maxCommands: 10,
    idleTimeoutMs: 5_000,
    expiresAtMs: 5_000n
  })
  const owner = tailAuthority(clock)
  const [initiatorChannel, responderChannel] = tailChannelPair()
  const initiator = owner.adopt(
    issueTailLink(currentAdvertisement, requestedLimits, {
      initiator: true,
      physicalChannel: initiatorChannel
    })
  )
  const responder = owner.adopt(
    issueTailLink(currentAdvertisement, requestedLimits, {
      initiator: false,
      physicalChannel: responderChannel
    })
  )
  const initiatorSession = createTailControlSession(initiator.tail, {
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    absoluteDeadline: 16_000n,
    crypto: cryptoSuite,
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled
  })
  const responderSession = createTailControlSession(responder.tail, {
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    crypto: cryptoSuite,
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled
  })
  const responderOptions =
    typeof options.createResponderOptions === 'function'
      ? options.createResponderOptions({ clock, owner, responder, responderSession })
      : {
          wallNow: clock.wallNow,
          monotonicNow: clock.monotonicNow,
          adjacencyAdopter: Object.freeze({}),
          extensionCommitter: Object.freeze({}),
          adjacentLinkFactory: Object.freeze({}),
          tailReadySigner: Object.freeze({}),
          randomBytes: () => b4a.alloc(32, 0x72),
          schedule: clock.schedule,
          cancelScheduled: clock.cancelScheduled
        }
  const authority = createTailControlResponderAuthority(
    responderSession,
    responder.responderToken,
    responderOptions
  )
  const encoded = initiatorSession.sealExtend({
    advertisement: nextAdvertisement,
    advertisementDigest: digestRelayCapabilityAdvertisement(nextAdvertisement),
    extensionIndex: 2,
    requestedLimits,
    absoluteDeadline: 16_000n,
    randomBytes: () => b4a.alloc(32, 0x73)
  })
  await borrowTailControlTransport(initiatorSession).send(tailControlEnvelope(encoded))
  const received = await borrowTailControlTransport(responderSession).receive()
  const admitted = admitTailExtend(authority, received)
  return {
    admitted,
    authority,
    responder,
    initiatorSession,
    responderSession,
    clock,
    currentIdentity,
    nextIdentity,
    nextRoute,
    nextAdvertisement,
    nextEndpoint,
    cleanup() {
      destroyTailControlResponderAuthority(authority)
      destroyTailControlSession(initiatorSession)
      destroyTailControlSession(responderSession)
    }
  }
}

test('relay adjacent dial authority constructor is exact, opaque, and linear', (t) => {
  const socketOwner = Object.freeze({})
  let destroyed = 0
  let reentered = null
  let authority = null
  authority = createRelayAdjacentDialAuthority({
    socketOwner,
    allowedRole: ROLE.SAFETY,
    dial: () => Promise.resolve(null),
    destroy(...args) {
      destroyed++
      t.is(args.length, 0, 'socket-owner destroy receives no arguments')
      t.is(this, undefined, 'socket-owner destroy receives no caller receiver')
      reentered = destroyRelayAdjacentDialAuthority(authority)
    }
  })

  t.ok(Object.isFrozen(authority), 'authority is frozen')
  t.alike(Reflect.ownKeys(authority), [], 'authority exposes no properties')
  t.is(destroyRelayAdjacentDialAuthority(authority), true, 'first destroy spends authority')
  t.is(reentered, false, 'destroy tombstones before invoking owner cleanup')
  t.is(destroyed, 1, 'socket-owner cleanup runs once')
  t.is(destroyRelayAdjacentDialAuthority(authority), false, 'repeated destroy is a no-op')
  t.is(
    errorCode(() => dialRelayAdvertisement(authority, new Proxy({}, { ownKeys: () => t.fail() }))),
    'ERR_DESTROYED',
    'destroyed authority rejects before inspecting dial options'
  )

  let throwingDestroyed = 0
  const throwing = createRelayAdjacentDialAuthority({
    socketOwner: Object.freeze({}),
    allowedRole: ROLE.PRIVATE,
    dial: () => Promise.resolve(null),
    destroy() {
      throwingDestroyed++
      throw new Error('owner cleanup failure')
    }
  })
  t.is(destroyRelayAdjacentDialAuthority(throwing), true, 'destructor exceptions are suppressed')
  t.is(throwingDestroyed, 1, 'throwing destructor is still one-shot')

  for (const [name, options, expectedDestroy] of [
    [
      'accessor',
      {
        socketOwner,
        allowedRole: ROLE.SAFETY,
        dial: () => Promise.resolve(null),
        get destroy() {
          t.fail('constructor accessor must not run')
        }
      },
      0
    ],
    [
      'extra own key',
      {
        socketOwner,
        allowedRole: ROLE.SAFETY,
        dial: () => Promise.resolve(null),
        destroy: () => {},
        extra: true
      },
      0
    ],
    [
      'invalid role',
      {
        socketOwner,
        allowedRole: -1,
        dial: () => Promise.resolve(null),
        destroy: () => destroyed++
      },
      1
    ]
  ]) {
    const before = destroyed
    t.is(
      errorCode(() => createRelayAdjacentDialAuthority(options)),
      'INVALID_ROUTE',
      `${name} rejects`
    )
    t.is(destroyed - before, expectedDestroy, `${name} cleanup follows ownership transfer`)
  }
})

test('relay dial first call tombstones before exact option inspection', (t) => {
  let destroyed = 0
  let nestedInspections = 0
  let nestedCode = null
  const authority = createRelayAdjacentDialAuthority({
    socketOwner: Object.freeze({}),
    allowedRole: ROLE.SAFETY,
    dial: () => {
      t.fail('dial is gated on honest admission')
    },
    destroy: () => destroyed++
  })
  const nestedOptions = new Proxy(
    {},
    {
      ownKeys() {
        nestedInspections++
        return []
      }
    }
  )
  const options = new Proxy(
    {},
    {
      ownKeys() {
        t.is(destroyed, 0, 'socket-owner lease remains live during option inspection')
        nestedCode = errorCode(() => dialRelayAdvertisement(authority, nestedOptions))
        return []
      }
    }
  )

  t.is(
    errorCode(() => dialRelayAdvertisement(authority, options)),
    'INVALID_ROUTE',
    'malformed first call rejects'
  )
  t.is(nestedCode, 'ERR_AUTHENTICATION', 'reentrant dial observes the first-call tombstone')
  t.is(nestedInspections, 0, 'reentrant dial does not inspect attacker options')
  t.is(destroyed, 1, 'failed first call spends the socket-owner lease')
  t.is(
    errorCode(() => dialRelayAdvertisement(authority, nestedOptions)),
    'ERR_AUTHENTICATION',
    'spent authority rejects reuse'
  )
  t.is(nestedInspections, 0, 'reuse still does not inspect options')
  t.is(
    destroyRelayAdjacentDialAuthority(authority),
    false,
    'spent authority cannot be destroyed twice'
  )
})

test('relay dial options require exact own data without caller property dispatch', (t) => {
  const cases = [
    [
      'accessor',
      () => {
        const options = exactDialOptions()
        Object.defineProperty(options, 'localDeadline', {
          enumerable: true,
          get() {
            t.fail('dial option accessor must not run')
          }
        })
        return options
      }
    ],
    ['extra key', () => exactDialOptions({ extra: true })],
    [
      'symbol key',
      () => {
        const options = exactDialOptions()
        options[Symbol('extra')] = true
        return options
      }
    ],
    [
      'inherited shape',
      () => Object.assign(Object.create({ inherited: true }), exactDialOptions())
    ],
    [
      'unstable prototype Proxy',
      () => {
        let reads = 0
        return new Proxy(exactDialOptions(), {
          getPrototypeOf() {
            return reads++ === 0 ? Object.freeze({}) : null
          }
        })
      }
    ],
    [
      'throwing Proxy',
      () =>
        new Proxy(exactDialOptions(), {
          ownKeys() {
            throw new Error('ownKeys trap')
          }
        })
    ]
  ]

  for (const [name, makeOptions] of cases) {
    let destroyed = 0
    let dialed = 0
    const authority = createRelayAdjacentDialAuthority({
      socketOwner: Object.freeze({}),
      allowedRole: ROLE.SAFETY,
      dial: () => {
        dialed++
      },
      destroy: () => destroyed++
    })
    t.is(
      errorCode(() => dialRelayAdvertisement(authority, makeOptions())),
      'INVALID_ROUTE',
      `${name} rejects`
    )
    t.is(dialed, 0, `${name} never reaches dial`)
    t.is(destroyed, 1, `${name} spends owner cleanup once`)
  }

  let exactDestroyed = 0
  let exactDialed = 0
  const unadmitted = createRelayAdjacentDialAuthority({
    socketOwner: Object.freeze({}),
    allowedRole: ROLE.SAFETY,
    dial: () => {
      exactDialed++
    },
    destroy: () => exactDestroyed++
  })
  t.is(
    errorCode(() => dialRelayAdvertisement(unadmitted, exactDialOptions())),
    'ERR_DESTROYED',
    'exact options cannot bypass the honest-admission operation gate'
  )
  t.is(exactDialed, 0, 'operation gate precedes dial invocation')
  t.is(exactDestroyed, 1, 'gated attempt spends the request-bound authority')
})

test('exact option snapshots never dispatch through Object.prototype', (t) => {
  const original = Object.getOwnPropertyDescriptor(Object.prototype, 'localDeadline')
  let dispatched = 0
  Object.defineProperty(Object.prototype, 'localDeadline', {
    configurable: true,
    set() {
      dispatched++
    }
  })
  try {
    const authority = createRelayAdjacentDialAuthority({
      socketOwner: Object.freeze({}),
      allowedRole: ROLE.SAFETY,
      dial: () => t.fail('admission gate must precede dial'),
      destroy: () => {}
    })
    t.is(
      errorCode(() => dialRelayAdvertisement(authority, exactDialOptions())),
      'ERR_DESTROYED',
      'exact dial reaches only the honest-admission gate'
    )
    t.is(dispatched, 0, 'snapshot writes invoke no inherited setter')
  } finally {
    if (original) Object.defineProperty(Object.prototype, 'localDeadline', original)
    else delete Object.prototype.localDeadline
  }
})

test('extension adjacent factory binds one authority and destroys transferred owners once', (t) => {
  const identityOwner = createRelayIdentitySigningAuthority({
    identitySecretKey: identityForRole(ROLE.SAFETY, 80).secretKey
  })
  const signer = createLinkOfferSigner(identityOwner)
  const order = []
  let callbacks = 0
  const authority = createRelayAdjacentDialAuthority({
    socketOwner: Object.freeze({}),
    allowedRole: ROLE.SAFETY,
    dial: () => Promise.resolve(null),
    destroy: () => order.push('socket')
  })
  let factory = null
  factory = createExtensionAdjacentLinkFactory(
    exactFactoryOptions(
      authority,
      signer,
      () => {
        order.push('factory')
        t.is(
          destroyExtensionAdjacentLinkFactory(factory),
          false,
          'factory tombstones before owner cleanup'
        )
      },
      {
        wallNow: () => {
          callbacks++
          return NOW
        },
        monotonicNow: () => {
          callbacks++
          return NOW
        },
        randomBytes: () => {
          callbacks++
          return b4a.alloc(32)
        },
        schedule: () => {
          callbacks++
          return Object.freeze({})
        },
        cancelScheduled: () => {
          callbacks++
        }
      }
    )
  )

  t.ok(Object.isFrozen(factory), 'factory is frozen')
  t.alike(Reflect.ownKeys(factory), [], 'factory exposes no bound capabilities')
  t.is(callbacks, 0, 'construction captures providers without invoking them')
  t.is(abortExtensionAdjacentLink(factory), false, 'idle factory has no operation to abort')

  const secondIdentityOwner = createRelayIdentitySigningAuthority({
    identitySecretKey: identityForRole(ROLE.SAFETY, 100).secretKey
  })
  const secondSigner = createLinkOfferSigner(secondIdentityOwner)
  let secondDestroyed = 0
  t.is(
    errorCode(() =>
      createExtensionAdjacentLinkFactory(
        exactFactoryOptions(authority, secondSigner, () => secondDestroyed++)
      )
    ),
    'ERR_AUTHENTICATION',
    'authority binds to exactly one factory'
  )
  t.is(destroyLinkOfferSigner(secondSigner), false, 'failed second factory destroys its signer')
  t.is(secondDestroyed, 1, 'failed second factory destroys its independent owner')

  t.is(destroyExtensionAdjacentLinkFactory(factory), true, 'factory destroy succeeds once')
  t.alike(order, ['factory', 'socket'], 'factory state is dropped before socket-owner lease')
  t.is(destroyLinkOfferSigner(signer), false, 'factory destroys its link-offer signer')
  t.is(destroyRelayAdjacentDialAuthority(authority), false, 'factory spends its dial authority')
  t.is(destroyExtensionAdjacentLinkFactory(factory), false, 'factory destroy is idempotent')
  t.is(callbacks, 0, 'idle destruction invokes no clock, randomness, or scheduler provider')
  destroyRelayIdentitySigningAuthority(identityOwner)
  destroyRelayIdentitySigningAuthority(secondIdentityOwner)
})

test('extension adjacent factory exact options clean transferred owners without accessors', (t) => {
  const cases = [
    [
      'accessor',
      (options) => {
        Object.defineProperty(options, 'randomBytes', {
          enumerable: true,
          get() {
            t.fail('factory option accessor must not run')
          }
        })
        return options
      }
    ],
    ['extra key', (options) => ({ ...options, extra: true })],
    [
      'symbol key',
      (options) => {
        options[Symbol('extra')] = true
        return options
      }
    ],
    [
      'inherited prototype',
      (options) => Object.assign(Object.create({ inherited: true }), options)
    ],
    [
      'unstable prototype Proxy',
      (options) => {
        let reads = 0
        return new Proxy(options, {
          getPrototypeOf() {
            return reads++ === 0 ? Object.freeze({}) : null
          }
        })
      }
    ],
    [
      'throwing Proxy',
      (options) =>
        new Proxy(options, {
          ownKeys() {
            throw new Error('ownKeys trap')
          }
        })
    ]
  ]

  for (const [name, mutate] of cases) {
    const identityOwner = createRelayIdentitySigningAuthority({
      identitySecretKey: identityForRole(ROLE.SAFETY, 120).secretKey
    })
    const signer = createLinkOfferSigner(identityOwner)
    let socketDestroyed = 0
    let factoryDestroyed = 0
    const authority = createRelayAdjacentDialAuthority({
      socketOwner: Object.freeze({}),
      allowedRole: ROLE.SAFETY,
      dial: () => Promise.resolve(null),
      destroy: () => socketDestroyed++
    })
    const options = exactFactoryOptions(authority, signer, () => factoryDestroyed++)
    t.is(
      errorCode(() => createExtensionAdjacentLinkFactory(mutate(options))),
      'INVALID_ROUTE',
      `${name} rejects`
    )
    t.is(destroyLinkOfferSigner(signer), false, `${name} destroys the transferred signer`)
    t.is(
      destroyRelayAdjacentDialAuthority(authority),
      false,
      `${name} destroys the transferred dial authority`
    )
    t.is(socketDestroyed, 1, `${name} spends socket-owner cleanup`)
    t.is(factoryDestroyed, 1, `${name} spends factory cleanup`)
    destroyRelayIdentitySigningAuthority(identityOwner)
  }
})

test('factory rollback cleans the captured snapshot without rereading caller options', (t) => {
  const originalIdentityOwner = createRelayIdentitySigningAuthority({
    identitySecretKey: identityForRole(ROLE.SAFETY, 140).secretKey
  })
  const alternateIdentityOwner = createRelayIdentitySigningAuthority({
    identitySecretKey: identityForRole(ROLE.SAFETY, 160).secretKey
  })
  const originalSigner = createLinkOfferSigner(originalIdentityOwner)
  const alternateSigner = createLinkOfferSigner(alternateIdentityOwner)
  let originalSocketDestroyed = 0
  let alternateSocketDestroyed = 0
  let originalFactoryDestroyed = 0
  let alternateFactoryDestroyed = 0
  const originalAuthority = createRelayAdjacentDialAuthority({
    socketOwner: Object.freeze({}),
    allowedRole: ROLE.SAFETY,
    dial: () => Promise.resolve(null),
    destroy: () => originalSocketDestroyed++
  })
  const alternateAuthority = createRelayAdjacentDialAuthority({
    socketOwner: Object.freeze({}),
    allowedRole: ROLE.SAFETY,
    dial: () => Promise.resolve(null),
    destroy: () => alternateSocketDestroyed++
  })
  const target = exactFactoryOptions(
    originalAuthority,
    originalSigner,
    () => originalFactoryDestroyed++
  )
  target.wallNow = null
  const reads = new Map()
  const options = new Proxy(target, {
    getOwnPropertyDescriptor(object, name) {
      const count = reads.get(name) || 0
      reads.set(name, count + 1)
      if (count === 0) return Reflect.getOwnPropertyDescriptor(object, name)
      if (name === 'dialAuthority') {
        return { configurable: true, enumerable: true, writable: true, value: alternateAuthority }
      }
      if (name === 'linkOfferSigner') {
        return { configurable: true, enumerable: true, writable: true, value: alternateSigner }
      }
      if (name === 'destroy') {
        return {
          configurable: true,
          enumerable: true,
          writable: true,
          value: () => alternateFactoryDestroyed++
        }
      }
      return Reflect.getOwnPropertyDescriptor(object, name)
    }
  })

  t.is(
    errorCode(() => createExtensionAdjacentLinkFactory(options)),
    'INVALID_ROUTE',
    'semantic validation rejects after a complete exact snapshot'
  )
  t.is(destroyLinkOfferSigner(originalSigner), false, 'rollback destroys captured signer')
  t.is(
    destroyRelayAdjacentDialAuthority(originalAuthority),
    false,
    'rollback destroys captured dial authority'
  )
  t.is(originalSocketDestroyed, 1, 'captured socket owner is spent')
  t.is(originalFactoryDestroyed, 1, 'captured factory owner is spent')
  t.is(destroyLinkOfferSigner(alternateSigner), true, 'later signer substitution is untouched')
  t.is(
    destroyRelayAdjacentDialAuthority(alternateAuthority),
    true,
    'later authority substitution is untouched'
  )
  t.is(alternateSocketDestroyed, 1, 'alternate owner is cleaned only by this test')
  t.is(alternateFactoryDestroyed, 0, 'later destroy substitution is never invoked')
  destroyRelayIdentitySigningAuthority(originalIdentityOwner)
  destroyRelayIdentitySigningAuthority(alternateIdentityOwner)
})

test('failed factory construction pins authority across reentrant owner cleanup', (t) => {
  const identityOwner = createRelayIdentitySigningAuthority({
    identitySecretKey: identityForRole(ROLE.SAFETY, 180).secretKey
  })
  const nestedIdentityOwner = createRelayIdentitySigningAuthority({
    identitySecretKey: identityForRole(ROLE.SAFETY, 200).secretKey
  })
  const signer = createLinkOfferSigner(identityOwner)
  const nestedSigner = createLinkOfferSigner(nestedIdentityOwner)
  let socketDestroyed = 0
  let outerDestroyed = 0
  let nestedDestroyed = 0
  let nestedCode = null
  let nestedFactory = null
  const authority = createRelayAdjacentDialAuthority({
    socketOwner: Object.freeze({}),
    allowedRole: ROLE.SAFETY,
    dial: () => Promise.resolve(null),
    destroy: () => socketDestroyed++
  })
  const outerOptions = exactFactoryOptions(authority, signer, () => {
    outerDestroyed++
    nestedCode = errorCode(() => {
      nestedFactory = createExtensionAdjacentLinkFactory(
        exactFactoryOptions(authority, nestedSigner, () => nestedDestroyed++)
      )
    })
  })
  outerOptions.wallNow = null

  t.is(
    errorCode(() => createExtensionAdjacentLinkFactory(outerOptions)),
    'INVALID_ROUTE',
    'outer semantic failure is preserved'
  )
  t.is(nestedCode, 'ERR_AUTHENTICATION', 'reentrant construction sees a pinned authority')
  t.is(nestedFactory, null, 'no nested factory is published')
  t.is(destroyLinkOfferSigner(signer), false, 'outer signer is consumed')
  t.is(destroyLinkOfferSigner(nestedSigner), false, 'nested rollback consumes its signer')
  t.is(nestedDestroyed, 1, 'nested rollback consumes its owner')
  t.is(outerDestroyed, 1, 'outer owner runs once')
  t.is(destroyRelayAdjacentDialAuthority(authority), false, 'outer rollback tombstones authority')
  t.is(socketDestroyed, 1, 'socket owner is spent after factory owners')
  if (nestedFactory) destroyExtensionAdjacentLinkFactory(nestedFactory)
  destroyRelayIdentitySigningAuthority(identityOwner)
  destroyRelayIdentitySigningAuthority(nestedIdentityOwner)
})

test('factory destruction keeps authority bound across reentrant owner cleanup', (t) => {
  const identityOwner = createRelayIdentitySigningAuthority({
    identitySecretKey: identityForRole(ROLE.SAFETY, 220).secretKey
  })
  const nestedIdentityOwner = createRelayIdentitySigningAuthority({
    identitySecretKey: identityForRole(ROLE.SAFETY, 240).secretKey
  })
  const signer = createLinkOfferSigner(identityOwner)
  const nestedSigner = createLinkOfferSigner(nestedIdentityOwner)
  const order = []
  let nestedDestroyed = 0
  let nestedCode = null
  let nestedFactory = null
  const authority = createRelayAdjacentDialAuthority({
    socketOwner: Object.freeze({}),
    allowedRole: ROLE.SAFETY,
    dial: () => Promise.resolve(null),
    destroy: () => order.push('socket')
  })
  const factory = createExtensionAdjacentLinkFactory(
    exactFactoryOptions(authority, signer, () => {
      order.push('factory')
      nestedCode = errorCode(() => {
        nestedFactory = createExtensionAdjacentLinkFactory(
          exactFactoryOptions(authority, nestedSigner, () => nestedDestroyed++)
        )
      })
      t.alike(order, ['factory'], 'socket owner remains live throughout reentrant cleanup')
    })
  )

  t.is(destroyExtensionAdjacentLinkFactory(factory), true, 'outer factory destruction succeeds')
  t.is(nestedCode, 'ERR_AUTHENTICATION', 'reentrant construction sees terminal binding')
  t.is(nestedFactory, null, 'destructor reentry publishes no nested factory')
  t.is(destroyLinkOfferSigner(nestedSigner), false, 'nested rollback consumes its signer')
  t.is(nestedDestroyed, 1, 'nested rollback consumes its owner')
  t.alike(order, ['factory', 'socket'], 'authority tombstones only after factory callbacks')
  t.is(destroyRelayAdjacentDialAuthority(authority), false, 'authority is already terminal')
  if (nestedFactory) destroyExtensionAdjacentLinkFactory(nestedFactory)
  destroyRelayIdentitySigningAuthority(identityOwner)
  destroyRelayIdentitySigningAuthority(nestedIdentityOwner)
})

test('extension adjacent open consumes honest admission before dialing canonical endpoint', async (t) => {
  const x = await admittedExtensionFixture()
  const identityOwner = createRelayIdentitySigningAuthority({
    identitySecretKey: x.currentIdentity.secretKey
  })
  const signer = createLinkOfferSigner(identityOwner)
  let socketDestroyed = 0
  let factoryDestroyed = 0
  let replayDuringDial = null
  let stagedOffer = null
  let stagedReplay = null
  let dialEndpoint = null
  const socketOwner = Object.freeze({ tag: 'socket-owner' })
  const authority = createRelayAdjacentDialAuthority({
    socketOwner,
    allowedRole: ROLE.PRIVATE,
    dial(owner, endpoint) {
      t.is(owner, socketOwner, 'dial receives only the retained socket owner')
      dialEndpoint = b4a.from(endpoint)
      stagedOffer = extensionGuardLinks[TAKE_STAGED_RELAY_ADJACENT_OFFER](owner, endpoint)
      stagedReplay = errorCode(() =>
        extensionGuardLinks[TAKE_STAGED_RELAY_ADJACENT_OFFER](owner, endpoint)
      )
      replayDuringDial = errorCode(() => takeAdmittedExtendRequest(x.admitted)) !== null
      return Promise.reject(new Error('synthetic dial failure'))
    },
    destroy: () => socketDestroyed++
  })
  const factory = createExtensionAdjacentLinkFactory(
    exactFactoryOptions(authority, signer, () => factoryDestroyed++, {
      wallNow: x.clock.wallNow,
      monotonicNow: x.clock.monotonicNow,
      randomBytes: (size) => b4a.alloc(size, 0x74),
      schedule: x.clock.schedule,
      cancelScheduled: x.clock.cancelScheduled
    })
  )

  let code = null
  try {
    await openExtensionAdjacentLink(factory, x.admitted)
  } catch (err) {
    code = err && err.code
  } finally {
    destroyExtensionAdjacentLinkFactory(factory)
    destroyRelayIdentitySigningAuthority(identityOwner)
    x.cleanup()
  }
  t.is(replayDuringDial, true, 'admission is consumed before the first external dial callback')
  t.alike(dialEndpoint, x.nextEndpoint, 'dial receives the advertisement canonical endpoint')
  t.is(decodeM3Object(stagedOffer).messageId, M3_MESSAGE_ID.LINK_OFFER_V1)
  t.is(stagedReplay, 'ERR_REPLAY', 'staged LINK_OFFER is exact-owner one-shot')
  t.is(code, 'ROUTE_UNAVAILABLE', 'post-invocation dial rejection is normalized')
  t.is(socketDestroyed, 1, 'dial failure spends the socket owner once')
  t.is(factoryDestroyed, 1, 'eventual factory destroy spends the factory owner once')
})

test('extension adjacent factory completes production responder proof over native UDX ownership', async (t) => {
  const currentIdentity = identityForRole(ROLE.SAFETY, 50)
  const nextIdentity = identityForRole(ROLE.PRIVATE, 80)
  const native = await nativeAdjacentPair(currentIdentity, nextIdentity)
  const x = await admittedExtensionFixture({ nextEndpoint: native.endpoint })
  const currentSignerOwner = createRelayIdentitySigningAuthority({
    identitySecretKey: x.currentIdentity.secretKey
  })
  const nextSignerOwner = createRelayIdentitySigningAuthority({
    identitySecretKey: x.nextIdentity.secretKey
  })
  const linkOfferSigner = createLinkOfferSigner(currentSignerOwner)
  const proofAuthority = createRedactedResponderProofAuthority({ now: x.clock.wallNow })
  const responderAuthority = tailAuthority(x.clock)
  let extensionResponder = null
  let dialFailure = null
  const socketOwner = Object.freeze({})
  const dialAuthority = createRelayAdjacentDialAuthority({
    socketOwner,
    allowedRole: ROLE.PRIVATE,
    async dial(owner, endpoint) {
      try {
        const offer = extensionGuardLinks[TAKE_STAGED_RELAY_ADJACENT_OFFER](owner, endpoint)
        const channels = await native.open({
          circuitId: b4a.alloc(16, 0x42),
          generation: 7n
        })
        const responses = []
        const inbound = [offer, null]
        const offerReceiver = createExtensionOfferReceiver({
          observedPredecessorEndpoint: encodeCanonicalEndpoint({
            addressFamily: 4,
            addressBytes: b4a.from([127, 0, 0, 1]),
            port: 49_299
          }),
          receiveObject: () => inbound.shift(),
          takePhysicalChannel: () => channels.responder,
          sendObject: (value) => responses.push(b4a.from(value)),
          finish: () => responses.push(null),
          destroy() {}
        })
        extensionResponder = createExtensionLinkResponder({
          advertisement: x.nextAdvertisement,
          adjacencyAdopter: responderAuthority.responderAdopter(),
          extensionResponderSigner: createExtensionResponderSigner(nextSignerOwner),
          responderRouteEncryptionSecretKey: x.nextRoute.secretKey,
          wallNow: x.clock.wallNow,
          monotonicNow: x.clock.monotonicNow,
          schedule: x.clock.schedule,
          cancelScheduled: x.clock.cancelScheduled,
          offerReceiver,
          randomBytes: (size) => b4a.alloc(size, 0xe1)
        })
        const accepted = extensionResponder.accept()
        t.ok(accepted.accepted, 'production responder adopts the native adjacent link')
        return createExtensionResponseReceiver({
          receiveObject: () => responses.shift(),
          takePhysicalChannel: () => channels.initiator,
          destroy() {}
        })
      } catch (err) {
        dialFailure = err
        throw err
      }
    },
    destroy() {}
  })
  const factory = createExtensionAdjacentLinkFactory({
    dialAuthority,
    linkOfferSigner,
    proofVerifier: proofAuthority.verifier,
    proofConsumer: proofAuthority.consumer,
    wallNow: x.clock.wallNow,
    monotonicNow: x.clock.monotonicNow,
    randomBytes: (size) => b4a.alloc(size, 0xe2),
    schedule: x.clock.schedule,
    cancelScheduled: x.clock.cancelScheduled,
    destroy() {}
  })
  try {
    let completion = null
    try {
      completion = await openExtensionAdjacentLink(factory, x.admitted)
    } catch (err) {
      throw dialFailure || err
    }
    t.is(abortExtensionLinkCompletion(completion), true, 'verified native completion is owned')
  } finally {
    destroyExtensionAdjacentLinkFactory(factory)
    if (extensionResponder) extensionResponder.destroy()
    destroyRelayIdentitySigningAuthority(currentSignerOwner)
    destroyRelayIdentitySigningAuthority(nextSignerOwner)
    x.cleanup()
    await native.destroy()
  }
})

test('TailControl responder installs a native next tail through production extension ownership', async (t) => {
  const currentIdentity = identityForRole(ROLE.SAFETY, 50)
  const nextIdentity = identityForRole(ROLE.PRIVATE, 80)
  const native = await nativeAdjacentPair(currentIdentity, nextIdentity)
  const currentSignerOwner = createRelayIdentitySigningAuthority({
    identitySecretKey: currentIdentity.secretKey
  })
  const nextSignerOwner = createRelayIdentitySigningAuthority({
    identitySecretKey: nextIdentity.secretKey
  })
  const proofAuthority = createRedactedResponderProofAuthority({ now: () => NOW })
  let targetAuthority = null
  let extensionResponder = null
  let targetAdjacency = null
  let replayOwner = null
  let responderTransport = null
  let successorAuthority = null
  let successorTail = null
  let successorTransport = null
  let installFailure = null
  const sends = []
  const x = await admittedExtensionFixture({
    nextEndpoint: native.endpoint,
    createResponderOptions({ clock, owner, responder, responderSession }) {
      targetAuthority = tailAuthority(clock)
      responderTransport = borrowTailControlTransport(responderSession)
      const socketOwner = Object.freeze({})
      const dialAuthority = createRelayAdjacentDialAuthority({
        socketOwner,
        allowedRole: ROLE.PRIVATE,
        async dial(socket, endpoint) {
          try {
            const offer = extensionGuardLinks[TAKE_STAGED_RELAY_ADJACENT_OFFER](socket, endpoint)
            const channels = await native.open({
              circuitId: b4a.alloc(16, 0x42),
              generation: 7n
            })
            const inbound = [offer, null]
            const responses = []
            const offerReceiver = createExtensionOfferReceiver({
              observedPredecessorEndpoint: encodeCanonicalEndpoint({
                addressFamily: 4,
                addressBytes: b4a.from([127, 0, 0, 1]),
                port: 49_298
              }),
              receiveObject: () => inbound.shift(),
              takePhysicalChannel: () => channels.responder,
              sendObject: (value) => responses.push(b4a.from(value)),
              finish: () => responses.push(null),
              destroy() {}
            })
            extensionResponder = createExtensionLinkResponder({
              advertisement: x.nextAdvertisement,
              adjacencyAdopter: targetAuthority.responderAdopter(),
              extensionResponderSigner: createExtensionResponderSigner(nextSignerOwner),
              responderRouteEncryptionSecretKey: x.nextRoute.secretKey,
              wallNow: clock.wallNow,
              monotonicNow: clock.monotonicNow,
              schedule: clock.schedule,
              cancelScheduled: clock.cancelScheduled,
              offerReceiver,
              randomBytes: (size) => b4a.alloc(size, 0xe3)
            })
            const accepted = extensionResponder.accept()
            const transfer = takeExtensionResponderAdjacency(extensionResponder, accepted.accepted)
            const moved = takeAcceptedExtensionAdjacencyTransfer(transfer)
            targetAdjacency = moved.adjacency
            replayOwner = moved.replayOwner
            successorTail = createTailControlSession(targetAdjacency.tail, {
              wallNow: clock.wallNow,
              monotonicNow: clock.monotonicNow,
              crypto: cryptoSuite,
              schedule: clock.schedule,
              cancelScheduled: clock.cancelScheduled
            })
            successorAuthority = createTailControlResponderAuthority(
              successorTail,
              targetAdjacency.responderToken,
              {
                tailReadySigner: createTailReadySigner(nextSignerOwner),
                wallNow: clock.wallNow,
                monotonicNow: clock.monotonicNow,
                randomBytes: (size) => b4a.alloc(size, 0xe6),
                schedule: clock.schedule,
                cancelScheduled: clock.cancelScheduled
              }
            )
            successorTransport = borrowTailControlTransport(successorTail)
            return createExtensionResponseReceiver({
              receiveObject: () => responses.shift(),
              takePhysicalChannel: () => channels.initiator,
              destroy() {}
            })
          } catch (err) {
            installFailure = err
            throw err
          }
        },
        destroy() {}
      })
      const adjacentLinkFactory = createExtensionAdjacentLinkFactory({
        dialAuthority,
        linkOfferSigner: createLinkOfferSigner(currentSignerOwner),
        proofVerifier: proofAuthority.verifier,
        proofConsumer: proofAuthority.consumer,
        wallNow: clock.wallNow,
        monotonicNow: clock.monotonicNow,
        randomBytes: (size) => b4a.alloc(size, 0xe4),
        schedule: clock.schedule,
        cancelScheduled: clock.cancelScheduled,
        destroy() {}
      })
      const extensionCommitter = createTailExtensionCommitter({
        enqueue(envelope) {
          sends.push(responderTransport.send(envelope))
        },
        install(nextRuntime) {
          try {
            const forwarding = createM3RelayForwardingFacade(responder.runtime, nextRuntime)
            const plan = beginM3Install(responder.runtime, nextRuntime)
            validateM3Install(plan, currentIdentity.publicKey, 128, clock.wallNow())
            return commitM3Install(plan, 4_500n, forwarding)
          } catch (err) {
            installFailure = err
            throw err
          }
        },
        destroy() {}
      })
      return {
        adjacencyAdopter: owner.responderAdopter(),
        extensionCommitter,
        adjacentLinkFactory,
        tailReadySigner: null,
        wallNow: clock.wallNow,
        monotonicNow: clock.monotonicNow,
        randomBytes: (size) => b4a.alloc(size, 0xe5),
        schedule: clock.schedule,
        cancelScheduled: clock.cancelScheduled
      }
    }
  })
  const successorReadyContext = createSuccessorTailReadyContext(x.authority, x.admitted)
  try {
    let completion = null
    try {
      completion = await openTailAdjacentLink(x.authority, x.admitted)
    } catch (err) {
      throw installFailure || err
    }
    let extended = null
    try {
      extended = completeTailExtend(x.authority, completion)
    } catch (err) {
      throw installFailure || err
    }
    t.alike(extended.byteLength, 1101)
    await Promise.all(sends)
    t.exception(
      () => sealTailReady(x.authority),
      'current relay cannot sign for the successor identity'
    )
    const ready = sealSuccessorTailReady(successorAuthority, successorReadyContext)
    t.is(ready.byteLength, 282)
    await successorTransport.send(tailControlEnvelope(ready))
    const forwardedReady = await borrowTailControlTransport(x.initiatorSession).receive()
    t.is(forwardedReady.byteLength, 1101, 'successor TAIL_READY traverses installed forwarding')
    t.ok(targetAdjacency && targetAdjacency.tail, 'next relay owns the installed TailControl')
    t.ok(targetAdjacency && targetAdjacency.runtime, 'next relay owns the installed runtime')
  } finally {
    x.cleanup()
    if (successorAuthority) destroyTailControlResponderAuthority(successorAuthority)
    if (successorTail) destroyTailControlSession(successorTail)
    if (extensionResponder) extensionResponder.destroy()
    destroyAcceptedExtensionAdjacencyOwner(replayOwner)
    if (targetAdjacency) {
      try {
        targetAdjacency.runtime.destroy()
      } catch {}
    }
    destroyRelayIdentitySigningAuthority(currentSignerOwner)
    destroyRelayIdentitySigningAuthority(nextSignerOwner)
    await native.destroy()
  }
})

test('extension adjacent abort finalizes an unsettled relay dial', async (t) => {
  const x = await admittedExtensionFixture()
  const identityOwner = createRelayIdentitySigningAuthority({
    identitySecretKey: x.currentIdentity.secretKey
  })
  const signer = createLinkOfferSigner(identityOwner)
  let socketDestroyed = 0
  let factoryDestroyed = 0
  let receiverDestroyed = 0
  let resolveDial = null
  const authority = createRelayAdjacentDialAuthority({
    socketOwner: Object.freeze({}),
    allowedRole: ROLE.PRIVATE,
    dial() {
      return new Promise((resolve) => {
        resolveDial = resolve
      })
    },
    destroy: () => socketDestroyed++
  })
  const beforePending = x.clock.pending()
  const beforeCancelled = x.clock.cancelled.length
  const factory = createExtensionAdjacentLinkFactory(
    exactFactoryOptions(authority, signer, () => factoryDestroyed++, {
      wallNow: x.clock.wallNow,
      monotonicNow: x.clock.monotonicNow,
      randomBytes: (size) => b4a.alloc(size, 0x75),
      schedule: x.clock.schedule,
      cancelScheduled: x.clock.cancelScheduled
    })
  )
  const promise = openExtensionAdjacentLink(factory, x.admitted)
  t.is(x.clock.pending(), beforePending + 1, 'dial path arms one local deadline timer')
  t.ok(abortExtensionAdjacentLink(factory), 'abort accepts the live adjacent operation')
  t.is(x.clock.pending(), beforePending, 'abort cancels the pending dial deadline')
  t.is(x.clock.cancelled.length, beforeCancelled + 1, 'abort invokes scheduler cancellation')
  t.is(destroyRelayAdjacentDialAuthority(authority), false, 'abort finalizes dial authority')
  t.is(socketDestroyed, 1, 'abort releases the retained socket owner')
  let code = null
  try {
    await promise
  } catch (err) {
    code = err && err.code
  }
  t.is(code, 'ROUTE_UNAVAILABLE', 'abort rejects the unsettled dial')
  resolveDial(
    createExtensionResponseReceiver({
      receiveObject: () => null,
      takePhysicalChannel: () => Object.freeze({ destroy() {} }),
      destroy: () => receiverDestroyed++
    })
  )
  await Promise.resolve()
  await Promise.resolve()
  try {
    destroyExtensionAdjacentLinkFactory(factory)
  } finally {
    destroyRelayIdentitySigningAuthority(identityOwner)
    x.cleanup()
  }
  t.is(receiverDestroyed, 1, 'late response receiver is destroyed after abort')
  t.is(factoryDestroyed, 1, 'factory owner still tears down once')
})

test('extension adjacent pending dial deadline finalizes blackholed dials', async (t) => {
  const x = await admittedExtensionFixture()
  const identityOwner = createRelayIdentitySigningAuthority({
    identitySecretKey: x.currentIdentity.secretKey
  })
  const signer = createLinkOfferSigner(identityOwner)
  let socketDestroyed = 0
  let factoryDestroyed = 0
  let receiverDestroyed = 0
  let resolveDial = null
  const authority = createRelayAdjacentDialAuthority({
    socketOwner: Object.freeze({}),
    allowedRole: ROLE.PRIVATE,
    dial() {
      return new Promise((resolve) => {
        resolveDial = resolve
      })
    },
    destroy: () => socketDestroyed++
  })
  const beforeHandles = new Set(x.clock.handles())
  const factory = createExtensionAdjacentLinkFactory(
    exactFactoryOptions(authority, signer, () => factoryDestroyed++, {
      wallNow: x.clock.wallNow,
      monotonicNow: x.clock.monotonicNow,
      randomBytes: (size) => b4a.alloc(size, 0x76),
      schedule: x.clock.schedule,
      cancelScheduled: x.clock.cancelScheduled
    })
  )
  const promise = openExtensionAdjacentLink(factory, x.admitted)
  const timer = x.clock.handles().find((handle) => !beforeHandles.has(handle))
  t.ok(timer, 'open arms a dedicated pending-dial timeout')
  x.clock.setMonotonic(14_000n)
  t.ok(x.clock.fire(timer), 'deadline callback is reachable')
  t.is(destroyRelayAdjacentDialAuthority(authority), false, 'timer finalizes dial authority')
  t.is(socketDestroyed, 1, 'timer releases the retained socket owner')
  t.absent(abortExtensionAdjacentLink(factory), 'expired operation is no longer abortable')
  let code = null
  try {
    await promise
  } catch (err) {
    code = err && err.code
  }
  t.is(code, 'ROUTE_UNAVAILABLE', 'timeout rejects the unsettled dial')
  resolveDial(
    createExtensionResponseReceiver({
      receiveObject: () => null,
      takePhysicalChannel: () => Object.freeze({ destroy() {} }),
      destroy: () => receiverDestroyed++
    })
  )
  await Promise.resolve()
  await Promise.resolve()
  try {
    destroyExtensionAdjacentLinkFactory(factory)
  } finally {
    destroyRelayIdentitySigningAuthority(identityOwner)
    x.cleanup()
  }
  t.is(receiverDestroyed, 1, 'late response receiver is destroyed after timeout')
  t.is(factoryDestroyed, 1, 'factory owner still tears down once')
})

function setup(value = {}) {
  return {
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: b4a.alloc(16, 0x11),
    circuitId: b4a.alloc(16, 0x22),
    generation: 1n,
    clientCircuitIdentity: cryptoSuite.keyPair(seed(3)),
    clientTailEphemeral: cryptoSuite.encryptionKeyPair(seed(4)),
    payloadParametersDigest: digestPayloadParameters(PAYLOAD_PARAMETERS),
    requestedLimits: {
      cellSize: 1200,
      maxCells: 100,
      maxBytes: 100_000,
      maxCommands: 10,
      idleTimeoutMs: 30_000,
      expiresAtMs: 5_000n
    },
    ...value
  }
}

function exchange(overrides = {}) {
  const f = fixture()
  const linkSetup = setup(overrides)
  const initiated = createIndexZeroGuardLinkOffer({
    advertisement: f.advertisement,
    now: NOW,
    randomBytes: (size) => b4a.alloc(size, 0x44),
    ...linkSetup
  })
  const observedPredecessorEndpoint = encodeCanonicalEndpoint({
    addressFamily: 4,
    addressBytes: b4a.from([198, 51, 100, 9]),
    port: 44000
  })
  const responderPhysical = Object.freeze({ destroy() {} })
  const responder = responderFor(f, () => ({
    offer: initiated.offer,
    observedPredecessorEndpoint,
    physicalChannel: responderPhysical
  }))
  const accepted = responder.accept()
  return { accepted, f, initiated, linkSetup, observedPredecessorEndpoint, responder }
}

function responderFor(f, receiveOffer, random = 0x55) {
  return createIndexZeroGuardLinkResponder({
    advertisement: f.advertisement,
    responderIdentitySecretKey: f.guard.secretKey,
    responderRouteEncryptionSecretKey: f.route.secretKey,
    now: () => NOW,
    receiveOffer,
    randomBytes: (size) => b4a.alloc(size, random)
  })
}

function extensionResponderClock({ wall = NOW, monotonic = 10_000n, synchronous = false } = {}) {
  let currentWall = wall
  let currentMonotonic = monotonic
  let nextHandle = 0
  const timers = new Map()
  const cancelled = []
  return {
    wallNow() {
      return currentWall
    },
    monotonicNow() {
      return currentMonotonic
    },
    schedule(callback, delay) {
      const handle = ++nextHandle
      timers.set(handle, { callback, delay })
      if (synchronous) callback()
      return handle
    },
    cancelScheduled(handle) {
      cancelled.push(handle)
      timers.delete(handle)
    },
    fire(handle) {
      const timer = timers.get(handle)
      if (!timer) return false
      timers.delete(handle)
      timer.callback()
      return true
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
    handles() {
      return [...timers.keys()]
    },
    cancelled
  }
}

function extensionResponderExchange({
  signerIdentity = null,
  clock = extensionResponderClock()
} = {}) {
  const responderIdentity = identityForRole(ROLE.SAFETY, 20)
  const initiatorIdentity = identityForRole(ROLE.SAFETY, 40)
  const f = fixture(responderIdentity)
  const initiated = createIndexZeroGuardLinkOffer({
    advertisement: f.advertisement,
    now: NOW,
    randomBytes: (size) => b4a.alloc(size, 0x44),
    ...setup({ clientCircuitIdentity: initiatorIdentity })
  })
  const object = decodeM3Object(initiated.offer)
  object.body[96] = M3_LINK_ROLE.SAFETY_RELAY
  object.body[139] = 1
  const offer = encodeM3Object({
    messageId: M3_MESSAGE_ID.LINK_OFFER_V1,
    body: object.body,
    authSuffix: cryptoSuite.sign(
      signatureInput(OFFER_DOMAIN, M3_MESSAGE_ID.LINK_OFFER_V1, object.body),
      initiatorIdentity.secretKey
    )
  })
  abortIndexZeroGuardLink(initiated.pending)

  const inbound = [offer, null]
  const outbound = []
  let finished = 0
  let transportDestroyed = 0
  let destroyedAdjacencies = 0
  const offerReceiver = createExtensionOfferReceiver({
    observedPredecessorEndpoint: f.endpoint,
    receiveObject: () => inbound.shift(),
    takePhysicalChannel: () =>
      Object.freeze({
        destroy() {
          transportDestroyed++
        }
      }),
    sendObject: (value) => outbound.push(value),
    finish: () => finished++,
    destroy: () => transportDestroyed++
  })
  const adoptedAdjacencies = []
  const adjacencyAdopter = createM3ResponderAdopter(
    (established) => {
      const adjacency = Object.freeze({ established })
      adoptedAdjacencies.push(adjacency)
      return adjacency
    },
    (value) => {
      destroyedAdjacencies++
      destroyM3EstablishedLink(value.established)
    }
  )
  const identity = signerIdentity || responderIdentity
  const identityOwner = createRelayIdentitySigningAuthority({
    identitySecretKey: identity.secretKey
  })
  const extensionResponderSigner = createExtensionResponderSigner(identityOwner)
  const options = {
    advertisement: f.advertisement,
    adjacencyAdopter,
    extensionResponderSigner,
    responderRouteEncryptionSecretKey: f.route.secretKey,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled,
    offerReceiver,
    randomBytes: (size) => b4a.alloc(size, 0x55)
  }
  return {
    adoptedAdjacencies,
    clock,
    extensionResponderSigner,
    f,
    destroyedAdjacencies: () => destroyedAdjacencies,
    finished: () => finished,
    identityOwner,
    initiatorIdentity,
    offerReceiver,
    offer,
    options,
    outbound,
    responderIdentity,
    transportDestroyed: () => transportDestroyed
  }
}

function extensionReplayReceiver(x, { offer = x.offer, sendObject = null } = {}) {
  const inbound = [offer, null]
  const outbound = []
  let finished = 0
  let destroyed = 0
  const receiver = createExtensionOfferReceiver({
    observedPredecessorEndpoint: x.f.endpoint,
    receiveObject: () => inbound.shift(),
    takePhysicalChannel: () =>
      Object.freeze({
        destroy() {
          destroyed++
        }
      }),
    sendObject(value) {
      outbound.push(value)
      if (sendObject) sendObject(value, outbound.length)
    },
    finish: () => finished++,
    destroy: () => destroyed++
  })
  return {
    receiver,
    outbound,
    finished: () => finished,
    destroyed: () => destroyed
  }
}

function takeAcceptedExtensionMaterial(x) {
  const responder = extensionGuardLinks.createExtensionLinkResponder(x.options)
  const { accepted } = responder.accept()
  const transfer = takeExtensionResponderAdjacency(responder, accepted)
  const material = takeAcceptedExtensionAdjacencyTransfer(transfer)
  return { material, responder }
}

function expectRouteCode(t, operation, code, message) {
  let error = null
  try {
    operation()
  } catch (err) {
    error = err
  }
  t.is(error && error.code, code, message)
}

test('extension responder signs exact ACCEPT then proof bytes without reading a raw identity key', (t) => {
  const x = extensionResponderExchange()
  const responder = extensionGuardLinks.createExtensionLinkResponder(x.options)
  responder.accept()

  t.is(x.outbound.length, 2)
  t.is(x.finished(), 1)
  t.is(x.outbound[0].byteLength, LINK_ACCEPT_SIZE)
  t.is(x.outbound[1].byteLength, 378)
  const accept = decodeM3Object(x.outbound[0])
  const proof = decodeM3Object(x.outbound[1])
  t.is(accept.body.byteLength, 213)
  t.is(proof.body.byteLength, 306)
  t.ok(
    cryptoSuite.verify(
      signatureInput(ACCEPT_DOMAIN, M3_MESSAGE_ID.LINK_ACCEPT_V1, accept.body),
      accept.authSuffix,
      x.responderIdentity.publicKey
    ),
    'LINK_ACCEPT is signed by the responder capability identity'
  )
  t.alike(
    accept.authSuffix,
    cryptoSuite.sign(
      signatureInput(ACCEPT_DOMAIN, M3_MESSAGE_ID.LINK_ACCEPT_V1, accept.body),
      x.responderIdentity.secretKey
    ),
    'signer-capability LINK_ACCEPT bytes equal the former raw-key signature'
  )
  const proofValue = decodeRedactedResponderProof(x.outbound[1])
  t.alike(
    x.outbound[1],
    signRedactedResponderProof(proofValue, x.responderIdentity.secretKey),
    'proof signer seam preserves every prototype wire byte'
  )

  t.ok(responder.destroy())
  t.is(x.transportDestroyed(), 1)
  expectRouteCode(
    t,
    () => signLinkAccept(x.extensionResponderSigner, accept.body, x.responderIdentity.publicKey),
    'ERR_DESTROYED',
    'responder destruction destroys the transferred signer'
  )
  t.ok(destroyRelayIdentitySigningAuthority(x.identityOwner))
})

test('extension responder has no raw-key fallback and destroys a wrong signer on failure', (t) => {
  const wrongIdentity = identityForRole(ROLE.SAFETY, 80)
  const x = extensionResponderExchange({ signerIdentity: wrongIdentity })
  const responder = extensionGuardLinks.createExtensionLinkResponder(x.options)

  expectRouteCode(
    t,
    () => responder.accept(),
    'ERR_AUTHENTICATION',
    'wrong signer identity cannot fall back to a raw identity key'
  )
  t.is(x.outbound.length, 0)
  t.is(x.transportDestroyed(), 1)
  expectRouteCode(
    t,
    () => signLinkAccept(x.extensionResponderSigner, b4a.alloc(213), wrongIdentity.publicKey),
    'ERR_DESTROYED',
    'operation failure destroys the transferred signer and its cached bytes'
  )
  t.ok(responder.destroy())
  t.ok(destroyRelayIdentitySigningAuthority(x.identityOwner))
})

test('extension responder constructor failure destroys the transferred signer', (t) => {
  const x = extensionResponderExchange()
  x.options.responderRouteEncryptionSecretKey = cryptoSuite.encryptionKeyPair(seed(99)).secretKey

  expectRouteCode(
    t,
    () => extensionGuardLinks.createExtensionLinkResponder(x.options),
    'ERR_AUTHENTICATION',
    'route-key mismatch fails construction'
  )
  t.is(x.transportDestroyed(), 1)
  expectRouteCode(
    t,
    () => signLinkAccept(x.extensionResponderSigner, b4a.alloc(213), x.responderIdentity.publicKey),
    'ERR_DESTROYED',
    'constructor rollback destroys the transferred signer'
  )
  t.ok(destroyRelayIdentitySigningAuthority(x.identityOwner))
})

test('extension responder basic-option failure destroys both transferred capabilities', (t) => {
  const x = extensionResponderExchange()
  const advertisement = b4a.from(x.options.advertisement)
  const routeSecretKey = b4a.from(x.options.responderRouteEncryptionSecretKey)
  x.options.wallNow = null

  expectRouteCode(
    t,
    () => extensionGuardLinks.createExtensionLinkResponder(x.options),
    'INVALID_ROUTE',
    'malformed basic options fail construction'
  )
  t.is(x.transportDestroyed(), 1, 'offer receiver ownership is destroyed exactly once')
  t.absent(
    destroyExtensionOfferReceiver(x.offerReceiver),
    'offer receiver cannot be destroyed a second time'
  )
  expectRouteCode(
    t,
    () => signLinkAccept(x.extensionResponderSigner, b4a.alloc(213), x.responderIdentity.publicKey),
    'ERR_DESTROYED',
    'malformed basic options destroy the transferred signer'
  )
  t.alike(x.options.advertisement, advertisement, 'caller advertisement remains unchanged')
  t.alike(
    x.options.responderRouteEncryptionSecretKey,
    routeSecretKey,
    'caller route secret remains unchanged'
  )
  t.ok(destroyRelayIdentitySigningAuthority(x.identityOwner))
})

test('invalid opaque responder signer destroys a valid offer receiver on first use', (t) => {
  const x = extensionResponderExchange()
  x.options.extensionResponderSigner = Object.freeze({})
  const responder = extensionGuardLinks.createExtensionLinkResponder(x.options)

  expectRouteCode(
    t,
    () => responder.accept(),
    'INVALID_ROUTE',
    'the opaque signer is validated by its first domain operation'
  )
  t.is(x.transportDestroyed(), 1, 'failed first use destroys receiver transport exactly once')
  t.absent(
    destroyExtensionOfferReceiver(x.offerReceiver),
    'consumed offer receiver cannot be destroyed a second time'
  )
  t.ok(responder.destroy())
  t.ok(destroyRelayIdentitySigningAuthority(x.identityOwner))
})

function rejectResponderOptions(t, mutate, label) {
  const x = extensionResponderExchange()
  const advertisement = b4a.from(x.options.advertisement)
  const routeSecretKey = b4a.from(x.options.responderRouteEncryptionSecretKey)
  const options = mutate(x.options) || x.options
  let responder = null
  let error = null
  try {
    responder = extensionGuardLinks.createExtensionLinkResponder(options)
  } catch (err) {
    error = err
  }
  if (responder) responder.destroy()

  t.is(error && error.code, 'INVALID_ROUTE', `${label} rejects exact options`)
  t.is(x.transportDestroyed(), 1, `${label} destroys receiver ownership exactly once`)
  t.absent(
    destroyExtensionOfferReceiver(x.offerReceiver),
    `${label} leaves no live receiver capability`
  )
  expectRouteCode(
    t,
    () => signLinkAccept(x.extensionResponderSigner, b4a.alloc(213), x.responderIdentity.publicKey),
    'ERR_DESTROYED',
    `${label} destroys signer ownership`
  )
  t.alike(options.advertisement, advertisement, `${label} preserves caller advertisement`)
  t.alike(
    options.responderRouteEncryptionSecretKey,
    routeSecretKey,
    `${label} preserves caller route secret`
  )
  t.ok(destroyRelayIdentitySigningAuthority(x.identityOwner), `${label} owner cleanup`)
}

test('extension responder exact options reject accessors without invoking them', (t) => {
  let throwingCalls = 0
  rejectResponderOptions(
    t,
    (options) => {
      Object.defineProperty(options, 'randomBytes', {
        enumerable: true,
        get() {
          throwingCalls++
          throw new Error('random getter invoked')
        }
      })
    },
    'throwing randomBytes accessor'
  )
  t.is(throwingCalls, 0, 'throwing randomBytes accessor is never invoked')

  let reentrantCalls = 0
  rejectResponderOptions(
    t,
    (options) => {
      Object.defineProperty(options, 'randomBytes', {
        enumerable: true,
        get() {
          reentrantCalls++
          try {
            extensionGuardLinks.createExtensionLinkResponder({})
          } catch {}
          return (size) => b4a.alloc(size, 0x55)
        }
      })
    },
    'reentrant randomBytes accessor'
  )
  t.is(reentrantCalls, 0, 'reentrant randomBytes accessor is never invoked')
})

test('extension responder requires an exact own randomBytes successor option', (t) => {
  rejectResponderOptions(
    t,
    (options) => {
      delete options.randomBytes
    },
    'missing randomBytes'
  )
})

test('extension responder exact options reject extras, inheritance, and Proxy traps', (t) => {
  let staleRawKeyCalls = 0
  rejectResponderOptions(
    t,
    (options) => {
      Object.defineProperty(options, 'responderIdentitySecretKey', {
        enumerable: true,
        get() {
          staleRawKeyCalls++
          throw new Error('stale raw key getter invoked')
        }
      })
    },
    'stale raw-key option'
  )
  t.is(staleRawKeyCalls, 0, 'stale raw-key accessor is never invoked')

  rejectResponderOptions(
    t,
    (options) => {
      options[Symbol('extra')] = true
    },
    'symbol extra'
  )

  rejectResponderOptions(
    t,
    (options) => {
      const inherited = Object.create({ wallNow: options.wallNow })
      for (const [key, value] of Object.entries(options)) {
        if (key !== 'wallNow') inherited[key] = value
      }
      return inherited
    },
    'inherited required option'
  )

  let ownKeysCalls = 0
  rejectResponderOptions(
    t,
    (options) =>
      new Proxy(options, {
        ownKeys() {
          ownKeysCalls++
          throw new Error('ownKeys trap invoked')
        }
      }),
    'throwing Proxy ownKeys trap'
  )
  t.is(ownKeysCalls, 1, 'Proxy ownKeys trap is contained')
})

test('extension responder option snapshots never dispatch through Object.prototype', (t) => {
  const x = extensionResponderExchange()
  const original = Object.getOwnPropertyDescriptor(Object.prototype, 'wallNow')
  let dispatched = 0
  let responder = null
  let error = null
  Object.defineProperty(Object.prototype, 'wallNow', {
    configurable: true,
    set() {
      dispatched++
    }
  })
  try {
    responder = extensionGuardLinks.createExtensionLinkResponder(x.options)
  } catch (err) {
    error = err
  } finally {
    if (original) Object.defineProperty(Object.prototype, 'wallNow', original)
    else delete Object.prototype.wallNow
  }
  t.absent(error, 'captured option snapshots ignore inherited setters')
  t.is(dispatched, 0, 'snapshot invokes no inherited setter')
  if (responder) t.ok(responder.destroy())
  t.ok(destroyRelayIdentitySigningAuthority(x.identityOwner))
})

test('accepted extension adjacency moves only as one opaque atomic transfer', (t) => {
  const x = extensionResponderExchange()
  const responder = extensionGuardLinks.createExtensionLinkResponder(x.options)
  const { accepted } = responder.accept()
  expectRouteCode(
    t,
    () => takeExtensionResponderAdjacency(Object.freeze({}), accepted),
    'ERR_AUTHENTICATION',
    'wrong responder cannot consume accepted ownership'
  )
  const transfer = takeExtensionResponderAdjacency(responder, accepted)

  t.ok(Object.isFrozen(transfer), 'transfer is frozen')
  t.alike(Object.keys(transfer), [], 'transfer exposes neither owner')
  t.not(transfer, x.adoptedAdjacencies[0], 'adjacency is not returned directly')

  const material = takeAcceptedExtensionAdjacencyTransfer(transfer)
  t.ok(Object.isFrozen(material), 'taken material is frozen')
  t.alike(Object.keys(material).sort(), ['adjacency', 'replayOwner'])
  t.is(material.adjacency, x.adoptedAdjacencies[0])
  t.ok(Object.isFrozen(material.replayOwner), 'replay owner is opaque and frozen')
  t.alike(Object.keys(material.replayOwner), [])
  expectRouteCode(
    t,
    () => takeAcceptedExtensionAdjacencyTransfer(transfer),
    'ERR_REPLAY',
    'transfer is one-shot'
  )
  t.absent(
    revokeAcceptedExtensionAdjacencyTransfer(transfer),
    'taken transfer cannot revoke moved ownership'
  )

  t.ok(
    destroyM3EstablishedLink(material.adjacency.established),
    'registry rollback destroys adjacency'
  )
  t.ok(
    destroyAcceptedExtensionAdjacencyOwner(material.replayOwner),
    'registry rollback destroys replay owner'
  )
  t.absent(
    destroyAcceptedExtensionAdjacencyOwner(material.replayOwner),
    'owner destroy is idempotent'
  )
  t.ok(responder.destroy())
  t.ok(destroyRelayIdentitySigningAuthority(x.identityOwner))
})

test('accepted extension transfer revoke atomically destroys adjacency and replay ownership', (t) => {
  const x = extensionResponderExchange()
  const responder = extensionGuardLinks.createExtensionLinkResponder(x.options)
  const { accepted } = responder.accept()
  const transfer = takeExtensionResponderAdjacency(responder, accepted)

  t.is(x.destroyedAdjacencies(), 0)
  t.is(x.clock.pending(), 1, 'accepted replay owner arms expiry before transfer publication')
  t.ok(revokeAcceptedExtensionAdjacencyTransfer(transfer))
  t.is(x.destroyedAdjacencies(), 1, 'revoke destroys adjacency')
  t.is(x.clock.pending(), 0, 'revoke cancels replay expiry')
  t.is(x.clock.cancelled.length, 1, 'one scheduled handle is cancelled')
  t.absent(revokeAcceptedExtensionAdjacencyTransfer(transfer), 'revoke is idempotent')
  expectRouteCode(
    t,
    () => takeAcceptedExtensionAdjacencyTransfer(transfer),
    'ERR_REPLAY',
    'revoked transfer is tombstoned'
  )

  t.ok(responder.destroy())
  t.is(x.destroyedAdjacencies(), 1, 'responder no longer owns transferred material')
  t.ok(destroyRelayIdentitySigningAuthority(x.identityOwner))
})

test('accepted replay answers only the exact duplicate with cached semantic bytes', (t) => {
  const x = extensionResponderExchange()
  const originalAccept = b4a.from(x.outbound[0] || b4a.alloc(0))
  const originalProof = b4a.from(x.outbound[1] || b4a.alloc(0))
  const { material, responder } = takeAcceptedExtensionMaterial(x)
  const cachedAccept = b4a.from(x.outbound[0])
  const cachedProof = b4a.from(x.outbound[1])
  const replayChannel = extensionReplayReceiver(x)

  expectRouteCode(
    t,
    () => answerAcceptedExtensionReplay(Object.freeze({}), replayChannel.receiver),
    'ERR_AUTHENTICATION',
    'foreign owner fails before taking caller response ownership'
  )
  t.ok(answerAcceptedExtensionReplay(material.replayOwner, replayChannel.receiver))
  t.alike(
    replayChannel.outbound,
    [cachedAccept, cachedProof],
    'replay writes cached semantic bytes'
  )
  t.is(replayChannel.finished(), 1)
  t.is(replayChannel.destroyed(), 1, 'duplicate channel is closed without becoming adjacency')
  t.is(x.adoptedAdjacencies.length, 1, 'duplicate allocates no second adjacency')
  t.alike(originalAccept, b4a.alloc(0), 'cache is created only by the accepted exchange')
  t.alike(originalProof, b4a.alloc(0), 'proof cache is created only by the accepted exchange')

  expectRouteCode(
    t,
    () => answerAcceptedExtensionReplay(material.replayOwner, replayChannel.receiver),
    'ERR_REPLAY',
    'one-shot response channel cannot be reused'
  )
  const secondChannel = extensionReplayReceiver(x)
  t.ok(answerAcceptedExtensionReplay(material.replayOwner, secondChannel.receiver))
  t.alike(secondChannel.outbound, [cachedAccept, cachedProof])
  t.is(x.adoptedAdjacencies.length, 1, 'a later exact duplicate still allocates no adjacency')

  t.ok(destroyM3EstablishedLink(material.adjacency.established))
  t.ok(destroyAcceptedExtensionAdjacencyOwner(material.replayOwner))
  t.ok(responder.destroy())
  t.ok(destroyRelayIdentitySigningAuthority(x.identityOwner))
})

test('accepted replay rechecks ownership after a reentrant monotonic clock callback', (t) => {
  const clock = extensionResponderClock()
  const x = extensionResponderExchange({ clock })
  const monotonicNow = clock.monotonicNow
  let calls = 0
  let material = null
  x.options.monotonicNow = () => {
    calls++
    if (calls === 2) destroyAcceptedExtensionAdjacencyOwner(material.replayOwner)
    return monotonicNow()
  }
  const taken = takeAcceptedExtensionMaterial(x)
  material = taken.material
  const replayChannel = extensionReplayReceiver(x)

  expectRouteCode(
    t,
    () => answerAcceptedExtensionReplay(material.replayOwner, replayChannel.receiver),
    'ERR_DESTROYED',
    'clock reentry tombstones before caller response ownership moves'
  )
  t.ok(
    destroyExtensionOfferReceiver(replayChannel.receiver),
    'post-clock owner recheck preserves caller response ownership'
  )
  t.alike(replayChannel.outbound, [], 'clock reentry publishes no response bytes')
  t.ok(destroyM3EstablishedLink(material.adjacency.established))
  t.ok(taken.responder.destroy())
  t.ok(destroyRelayIdentitySigningAuthority(x.identityOwner))
})

test('accepted replay rejects a conflicting authenticated offer without answering', (t) => {
  const x = extensionResponderExchange()
  const { material, responder } = takeAcceptedExtensionMaterial(x)
  const conflicting = resign(
    x.offer,
    M3_MESSAGE_ID.LINK_OFFER_V1,
    OFFER_DOMAIN,
    x.initiatorIdentity.secretKey,
    (body) => (body[204] ^= 1)
  )
  const conflictChannel = extensionReplayReceiver(x, { offer: conflicting })

  expectRouteCode(
    t,
    () => answerAcceptedExtensionReplay(material.replayOwner, conflictChannel.receiver),
    'ERR_AUTHENTICATION',
    'different authenticated nonce is not a duplicate'
  )
  t.alike(conflictChannel.outbound, [])
  t.is(conflictChannel.finished(), 0)
  t.is(conflictChannel.destroyed(), 1, 'conflicting channel ownership is destroyed')
  t.is(x.adoptedAdjacencies.length, 1)

  t.ok(destroyM3EstablishedLink(material.adjacency.established))
  t.ok(destroyAcceptedExtensionAdjacencyOwner(material.replayOwner))
  t.ok(responder.destroy())
  t.ok(destroyRelayIdentitySigningAuthority(x.identityOwner))
})

test('responder wall high-water rejects post-adoption regression before replay projection', (t) => {
  const clock = extensionResponderClock()
  const x = extensionResponderExchange({ clock })
  let postAdoptionSamples = 0
  x.options.wallNow = () => {
    if (x.adoptedAdjacencies.length === 0) return NOW
    postAdoptionSamples++
    return postAdoptionSamples === 1 ? NOW + 500n : NOW
  }
  const responder = extensionGuardLinks.createExtensionLinkResponder(x.options)

  expectRouteCode(
    t,
    () => responder.accept(),
    'ERR_AUTHENTICATION',
    'an earlier post-adoption wall high-water cannot regress before replay projection'
  )
  t.is(postAdoptionSamples, 2, 'the first regressing wall sample fails immediately')
  t.is(clock.pending(), 0, 'wall regression releases replay capacity without scheduling')
  t.alike(x.outbound, [], 'wall regression publishes no response')
  t.is(x.destroyedAdjacencies(), 1, 'wall regression destroys unpublished adjacency state')
  t.ok(responder.destroy())
  t.ok(destroyRelayIdentitySigningAuthority(x.identityOwner))
})

test('accepted replay projection rejects a backward responder wall sample', (t) => {
  const clock = extensionResponderClock()
  const x = extensionResponderExchange({ clock })
  let randomCalls = 0
  let proofWallSamples = 0
  x.options.randomBytes = (size) => {
    randomCalls++
    return b4a.alloc(size, 0x55)
  }
  x.options.wallNow = () => {
    if (randomCalls < 3) return NOW
    proofWallSamples++
    if (proofWallSamples === 1) return NOW + 500n
    if (proofWallSamples === 2) return NOW
    return NOW + 500n
  }
  const responder = extensionGuardLinks.createExtensionLinkResponder(x.options)

  expectRouteCode(
    t,
    () => responder.accept(),
    'ERR_AUTHENTICATION',
    'wall rollback cannot extend the replay owner beyond wire expiry'
  )
  t.is(proofWallSamples, 2, 'projection compares against the retained prior wall sample')
  t.is(clock.pending(), 0, 'rejected projection arms no extended local deadline')
  t.alike(x.outbound, [], 'rejected projection publishes no response')
  t.is(x.destroyedAdjacencies(), 1, 'rejected projection rolls adjacency back')
  t.ok(responder.destroy())
  t.ok(destroyRelayIdentitySigningAuthority(x.identityOwner))
})

test('accepted replay fails closed on monotonic rollback in answer and timer paths', (t) => {
  const x = extensionResponderExchange()
  const taken = takeAcceptedExtensionMaterial(x)
  const replayChannel = extensionReplayReceiver(x)
  x.clock.setMonotonic(9_999n)
  expectRouteCode(
    t,
    () => answerAcceptedExtensionReplay(taken.material.replayOwner, replayChannel.receiver),
    'ERR_DESTROYED',
    'answer-time monotonic rollback destroys replay ownership'
  )
  t.ok(
    destroyExtensionOfferReceiver(replayChannel.receiver),
    'answer-time rollback preserves caller response ownership'
  )
  t.alike(replayChannel.outbound, [], 'answer-time rollback publishes no bytes')
  t.is(x.clock.pending(), 0, 'answer-time rollback cancels replay expiry')
  destroyAcceptedExtensionAdjacencyOwner(taken.material.replayOwner)
  t.ok(destroyM3EstablishedLink(taken.material.adjacency.established))
  t.ok(taken.responder.destroy())
  t.ok(destroyRelayIdentitySigningAuthority(x.identityOwner))

  const y = extensionResponderExchange()
  const timerTaken = takeAcceptedExtensionMaterial(y)
  const [handle] = y.clock.handles()
  y.clock.setMonotonic(9_999n)
  t.ok(y.clock.fire(handle), 'rollback reaches the armed timer callback')
  t.is(y.clock.pending(), 0, 'timer rollback destroys instead of rearming')
  t.absent(y.clock.fire(handle), 'repeated rollback cannot refire the stale handle')
  const staleChannel = extensionReplayReceiver(y)
  expectRouteCode(
    t,
    () => answerAcceptedExtensionReplay(timerTaken.material.replayOwner, staleChannel.receiver),
    'ERR_DESTROYED',
    'timer rollback tombstones replay ownership'
  )
  t.ok(
    destroyExtensionOfferReceiver(staleChannel.receiver),
    'timer rollback preserves later caller response ownership'
  )
  destroyAcceptedExtensionAdjacencyOwner(timerTaken.material.replayOwner)
  t.ok(destroyM3EstablishedLink(timerTaken.material.adjacency.established))
  t.ok(timerTaken.responder.destroy())
  t.ok(destroyRelayIdentitySigningAuthority(y.identityOwner))
})

test('accepted replay expiry and scheduler reentry tear down before callbacks continue', (t) => {
  const x = extensionResponderExchange()
  const { material, responder } = takeAcceptedExtensionMaterial(x)
  const [handle] = x.clock.handles()
  x.clock.setMonotonic(14_000n)
  t.ok(x.clock.fire(handle))
  t.is(x.clock.pending(), 0)
  const expiredChannel = extensionReplayReceiver(x)
  expectRouteCode(
    t,
    () => answerAcceptedExtensionReplay(material.replayOwner, expiredChannel.receiver),
    'ERR_DESTROYED',
    'local expiry tombstones replay owner before taking a channel'
  )
  t.ok(
    destroyExtensionOfferReceiver(expiredChannel.receiver),
    'pre-take expiry preserves caller owner'
  )
  t.ok(
    destroyM3EstablishedLink(material.adjacency.established),
    'replay expiry does not destroy runtime'
  )
  t.ok(responder.destroy())
  t.ok(destroyRelayIdentitySigningAuthority(x.identityOwner))

  const reentrantClock = extensionResponderClock()
  const y = extensionResponderExchange({ clock: reentrantClock })
  const schedule = reentrantClock.schedule
  let reentrantResponder = null
  y.options.schedule = (callback, delay) => {
    const timer = schedule(callback, delay)
    reentrantResponder.destroy()
    return timer
  }
  reentrantResponder = extensionGuardLinks.createExtensionLinkResponder(y.options)
  expectRouteCode(
    t,
    () => reentrantResponder.accept(),
    'INVALID_ROUTE',
    'scheduler reentry destroys before response publication'
  )
  t.is(y.outbound.length, 0)
  t.is(y.destroyedAdjacencies(), 1, 'post-adoption reentry rolls adjacency back')
  t.is(reentrantClock.pending(), 0)
  t.is(reentrantClock.cancelled.length, 1, 'reentry cancels the armed handle')
  t.ok(destroyRelayIdentitySigningAuthority(y.identityOwner))
})

test('accepted replay cache construction zeroizes every partial semantic owner', (t) => {
  const attempt = (failure = Infinity) => {
    const x = extensionResponderExchange()
    const responder = extensionGuardLinks.createExtensionLinkResponder(x.options)
    let result = null
    let error = null
    try {
      result = withSlowAllocationProbe(() => responder.accept(), null, failure)
    } catch (err) {
      error = err
      result = { allocations: err.allocations, positions: err.positions }
    } finally {
      responder.destroy()
      destroyRelayIdentitySigningAuthority(x.identityOwner)
    }
    return { ...result, error }
  }

  const baseline = attempt().positions
  t.ok(baseline >= 4, 'accepted owner performs four final nonce/digest copies')
  for (let failure = baseline - 3; failure <= baseline; failure++) {
    const result = attempt(failure)
    t.ok(result.error, `cache copy ${failure - baseline + 4} fails`)
    t.ok(
      allZero(result.allocations),
      `cache copy ${failure - baseline + 4} clears every prior buffer`
    )
  }
})

test('responder replay owners reserve the exact process-global 4096 bound before callbacks', (t) => {
  const maximum = 4096
  const base = extensionResponderExchange()
  const clock = base.clock
  const responders = []
  let extraResponder = null
  const candidate = (calls = null) => {
    const inbound = [base.offer, null]
    const offerReceiver = createExtensionOfferReceiver({
      observedPredecessorEndpoint: base.f.endpoint,
      receiveObject() {
        if (calls) calls.receive++
        return inbound.shift()
      },
      takePhysicalChannel: () => Object.freeze({ destroy() {} }),
      sendObject() {
        if (calls) calls.send++
      },
      finish() {
        if (calls) calls.finish++
      },
      destroy() {}
    })
    const adjacencyAdopter = createM3ResponderAdopter(
      (established) => Object.freeze({ established }),
      (adjacency) => destroyM3EstablishedLink(adjacency.established)
    )
    const extensionResponderSigner = createExtensionResponderSigner(base.identityOwner)
    return extensionGuardLinks.createExtensionLinkResponder({
      advertisement: base.f.advertisement,
      adjacencyAdopter,
      extensionResponderSigner,
      responderRouteEncryptionSecretKey: base.f.route.secretKey,
      wallNow() {
        if (calls) calls.wall++
        return clock.wallNow()
      },
      monotonicNow() {
        if (calls) calls.monotonic++
        return clock.monotonicNow()
      },
      schedule(callback, delay) {
        if (calls) calls.schedule++
        return clock.schedule(callback, delay)
      },
      cancelScheduled: clock.cancelScheduled,
      offerReceiver,
      randomBytes(size) {
        if (calls) calls.random++
        return b4a.alloc(size, 0x55)
      }
    })
  }

  try {
    const first = extensionGuardLinks.createExtensionLinkResponder(base.options)
    first.accept()
    responders.push(first)
    for (let index = 1; index < maximum; index++) {
      const responder = candidate()
      responder.accept()
      responders.push(responder)
    }
    t.is(responders.length, maximum, 'exact threshold is admitted')

    const calls = {
      wall: 0,
      monotonic: 0,
      schedule: 0,
      receive: 0,
      send: 0,
      finish: 0,
      random: 0
    }
    extraResponder = candidate(calls)
    const constructorCalls = { ...calls }
    expectRouteCode(t, () => extraResponder.accept(), 'ERR_BUSY', 'threshold plus one is rejected')
    t.alike(calls, constructorCalls, 'capacity reservation precedes every external callback')

    const [rollbackHandle] = clock.handles()
    clock.setMonotonic(9_999n)
    t.ok(clock.fire(rollbackHandle), 'rollback reaches one threshold owner timer')
    t.is(clock.pending(), maximum - 1, 'rollback releases its timer and global reservation')
    t.absent(clock.fire(rollbackHandle), 'repeated rollback does not rearm the stale handle')
    let retryError = null
    try {
      extraResponder.accept()
    } catch (err) {
      retryError = err
    }
    t.absent(retryError, 'the same pre-take responder retries after rollback releases capacity')
    t.ok(calls.receive > 0, 'capacity release permits responder callbacks')
    t.is(clock.pending(), maximum, 'retry restores exactly the active threshold')
  } finally {
    if (extraResponder) extraResponder.destroy()
    for (const responder of responders) responder.destroy()
    destroyRelayIdentitySigningAuthority(base.identityOwner)
  }
  t.is(clock.pending(), 0, 'global threshold cleanup cancels every timer')
})

test('index-zero offer and accept are exact fixed signed messages with mutual link keys', (t) => {
  const x = exchange()
  t.is(x.initiated.offer.byteLength, LINK_OFFER_SIZE)
  t.is(x.accepted.accept.byteLength, LINK_ACCEPT_SIZE)
  t.alike(
    decodeM3Object(x.accepted.accept).body.subarray(0, 32),
    b4a.from('526fb31362c0c45224fd3d6b03c1f8c50e09684a2c5ac4fa556868e0568d7ee3', 'hex'),
    'LINK_OFFER transcript digest has the independent registry vector'
  )

  const physical = Object.freeze({ id: 'guard-physical-channel', destroy() {} })
  const established = completeIndexZeroGuardLink(x.initiated.pending, x.accepted.accept, {
    advertisement: x.f.advertisement,
    physicalChannel: physical,
    now: NOW
  })
  const left = readM3EstablishedLink(established)
  const right = readM3EstablishedLink(x.accepted.established)

  t.is(left.physicalChannel, physical)
  t.is(left.extensionIndex, 0)
  t.is(left.branchClass, BRANCH_CLASS.LOOKUP)
  t.alike(left.branchId, x.linkSetup.branchId)
  t.alike(left.circuitId, x.linkSetup.circuitId)
  t.is(left.generation, 1n)
  t.alike(
    left.responderAdvertisementDigest,
    digestRelayCapabilityAdvertisement(x.f.advertisement, { now: NOW })
  )
  t.alike(left.contexts[0].tx.key, right.contexts[0].rx.key)
  t.alike(left.contexts[0].rx.key, right.contexts[0].tx.key)

  t.alike(
    left.contexts[0].tx.key,
    b4a.from('79d446bc8e1dc435118fea8ebb98f51144ed99a98f78019868dfe858536522c9', 'hex'),
    'KDF context has the fixed length-prefixed OFFER and ACCEPT digest vector'
  )

  destroyM3EstablishedLink(established)
  destroyM3EstablishedLink(x.accepted.established)
  t.exception(() => readM3EstablishedLink(established))
})

test('index-zero accept rejects replay, late completion, and M2 handles', (t) => {
  const x = exchange()
  const complete = (pending = x.initiated.pending, accept = x.accepted.accept) =>
    completeIndexZeroGuardLink(pending, accept, {
      advertisement: x.f.advertisement,
      physicalChannel: Object.freeze({ destroy() {} }),
      now: NOW
    })

  const established = complete()
  t.exception(() => complete(), 'pending is one-time')
  t.exception(
    () =>
      completeIndexZeroGuardLink(Object.freeze({}), x.accepted.accept, {
        advertisement: x.f.advertisement,
        physicalChannel: Object.freeze({ destroy() {} }),
        now: NOW
      }),
    'foreign or M2 topology-grant handles are not pending M3 offers'
  )
  destroyM3EstablishedLink(established)

  const y = exchange({ branchClass: BRANCH_CLASS.ANNOUNCE })
  t.exception(() =>
    completeIndexZeroGuardLink(y.initiated.pending, y.accepted.accept, {
      advertisement: y.f.advertisement,
      physicalChannel: Object.freeze({ destroy() {} }),
      now: 5_000n
    })
  )
  destroyM3EstablishedLink(y.accepted.established)
})

test('responder rejects every invalid index-zero offer binding before installing a link', (t) => {
  const mutations = [
    ['advertisement digest', (body) => (body[0] ^= 1)],
    ['initiator identity/signature', (body) => (body[32] ^= 1)],
    ['responder identity', (body) => (body[64] ^= 1)],
    ['initiator role', (body) => (body[96] = 1)],
    ['responder role', (body) => (body[97] = 2)],
    ['branch class', (body) => (body[98] = 2)],
    ['zero branch id', (body) => body.fill(0, 99, 115)],
    ['zero circuit id', (body) => body.fill(0, 115, 131)],
    ['zero generation', (body) => body.fill(0, 131, 139)],
    ['wrong index', (body) => (body[139] = 1)],
    ['zero link key', (body) => body.fill(0, 140, 172)],
    ['zero tail key', (body) => body.fill(0, 172, 204)],
    ['zero client nonce', (body) => body.fill(0, 204, 236)],
    ['zero parameter digest', (body) => body.fill(0, 236, 268)],
    ['nonzero parameter mismatch', (body) => (body[236] ^= 1)],
    ['bad cell size', (body) => body.fill(0, 268, 270)],
    ['zero max cells', (body) => body.fill(0, 270, 274)],
    ['over-advertised max bytes', (body) => body.fill(0xff, 274, 278)],
    ['expired deadline', (body) => body.fill(0, 294, 302)],
    ['deadline over five seconds', (body) => body.fill(0xff, 294, 302)]
  ]
  for (const [name, mutate] of mutations) {
    const x = exchange()
    const offer = resign(
      x.initiated.offer,
      M3_MESSAGE_ID.LINK_OFFER_V1,
      OFFER_DOMAIN,
      x.linkSetup.clientCircuitIdentity.secretKey,
      mutate
    )
    const responder = responderFor(
      x.f,
      () => ({
        offer,
        observedPredecessorEndpoint: x.observedPredecessorEndpoint,
        physicalChannel: Object.freeze({ destroy() {} })
      }),
      0x56
    )
    t.exception(() => responder.accept(), name)
    responder.destroy()
    destroyM3EstablishedLink(x.accepted.established)
    x.responder.destroy()
  }
})

test('responder receive authority is construction-bound and destroys invalid receives', (t) => {
  const x = exchange()
  t.is(x.responder.accept.length, 0, 'accept has no caller-supplied receive parameters')

  let substitutedCloses = 0
  const substituted = responderFor(x.f, () => ({
    offer: x.initiated.offer,
    observedPredecessorEndpoint: x.observedPredecessorEndpoint,
    observedPredecessorEndpointOverride: encodeCanonicalEndpoint({
      addressFamily: 4,
      addressBytes: b4a.from([203, 0, 113, 9]),
      port: 44000
    }),
    physicalChannel: Object.freeze({
      destroy() {
        substitutedCloses++
      }
    })
  }))
  t.exception(() => substituted.accept(), 'receive tuple rejects endpoint substitution fields')
  t.is(substitutedCloses, 1)
  substituted.destroy()

  let closes = 0
  const lowOrder = resign(
    x.initiated.offer,
    M3_MESSAGE_ID.LINK_OFFER_V1,
    OFFER_DOMAIN,
    x.linkSetup.clientCircuitIdentity.secretKey,
    (body) => {
      body.fill(0, 140, 172)
      body[140] = 1
    }
  )
  const lowOrderResponder = responderFor(x.f, () => ({
    offer: lowOrder,
    observedPredecessorEndpoint: x.observedPredecessorEndpoint,
    physicalChannel: Object.freeze({
      destroy() {
        closes++
      }
    })
  }))
  t.exception(() => lowOrderResponder.accept())
  t.is(closes, 1)
  lowOrderResponder.destroy()

  let tailCloses = 0
  const lowOrderTail = resign(
    x.initiated.offer,
    M3_MESSAGE_ID.LINK_OFFER_V1,
    OFFER_DOMAIN,
    x.linkSetup.clientCircuitIdentity.secretKey,
    (body) => {
      body.fill(0, 172, 204)
      body[172] = 1
    }
  )
  const lowOrderTailResponder = responderFor(x.f, () => ({
    offer: lowOrderTail,
    observedPredecessorEndpoint: x.observedPredecessorEndpoint,
    physicalChannel: Object.freeze({
      destroy() {
        tailCloses++
      }
    })
  }))
  t.exception(() => lowOrderTailResponder.accept())
  t.is(tailCloses, 1)
  lowOrderTailResponder.destroy()
  destroyM3EstablishedLink(x.accepted.established)
  x.responder.destroy()
})

test('responder reserves OFFER replay authority before recursive random providers', (t) => {
  const f = fixture()
  const initiated = createIndexZeroGuardLinkOffer({
    advertisement: f.advertisement,
    now: NOW,
    randomBytes: (size) => b4a.alloc(size, 0x44),
    ...setup()
  })
  const observedPredecessorEndpoint = encodeCanonicalEndpoint({
    addressFamily: 4,
    addressBytes: b4a.from([198, 51, 100, 10]),
    port: 44000
  })
  let responder = null
  let reentered = false
  let recursiveCode = null
  let recursiveAccepted = null
  let receiveCount = 0
  const closes = []
  responder = createIndexZeroGuardLinkResponder({
    advertisement: f.advertisement,
    responderIdentitySecretKey: f.guard.secretKey,
    responderRouteEncryptionSecretKey: f.route.secretKey,
    now: () => NOW,
    receiveOffer() {
      const index = receiveCount++
      closes[index] = 0
      return {
        offer: initiated.offer,
        observedPredecessorEndpoint,
        physicalChannel: Object.freeze({
          destroy() {
            closes[index]++
          }
        })
      }
    },
    randomBytes(size) {
      if (!reentered) {
        reentered = true
        try {
          recursiveAccepted = responder.accept()
        } catch (err) {
          recursiveCode = err && err.code
        }
      }
      return b4a.alloc(size, 0x57)
    }
  })

  const accepted = responder.accept()
  t.is(recursiveCode, 'ERR_REPLAY')
  t.is(receiveCount, 2)
  t.alike(closes, [0, 1], 'only the losing recursive physical channel is destroyed')
  destroyM3EstablishedLink(accepted.established)
  t.alike(closes, [1, 1], 'the winning channel transfers into exactly one established link')
  if (recursiveAccepted) destroyM3EstablishedLink(recursiveAccepted.established)
  responder.destroy()
  abortIndexZeroGuardLink(initiated.pending)
})

test('responder destroy invalidates an in-flight OFFER reservation', (t) => {
  const f = fixture()
  const initiated = createIndexZeroGuardLinkOffer({
    advertisement: f.advertisement,
    now: NOW,
    randomBytes: (size) => b4a.alloc(size, 0x44),
    ...setup()
  })
  let responder = null
  let closes = 0
  const generated = []
  responder = createIndexZeroGuardLinkResponder({
    advertisement: f.advertisement,
    responderIdentitySecretKey: f.guard.secretKey,
    responderRouteEncryptionSecretKey: f.route.secretKey,
    now: () => NOW,
    receiveOffer: () => ({
      offer: initiated.offer,
      observedPredecessorEndpoint: f.endpoint,
      physicalChannel: Object.freeze({
        destroy() {
          closes++
        }
      })
    }),
    randomBytes(size) {
      const bytes = b4a.alloc(size, 0x58 + generated.length)
      generated.push(bytes)
      if (generated.length === 1) responder.destroy()
      return bytes
    }
  })

  let code = null
  try {
    responder.accept()
  } catch (err) {
    code = err && err.code
  }
  t.is(code, 'ERR_DESTROYED')
  t.is(closes, 1, 'destroyed in-flight accepts close physical ownership exactly once')
  for (const bytes of generated) t.alike(bytes, b4a.alloc(bytes.byteLength))
  abortIndexZeroGuardLink(initiated.pending)
})

test('responder rejects a secret key for another advertised identity and destroy is terminal', (t) => {
  const f = fixture()
  const other = cryptoSuite.keyPair(seed(91))
  t.exception(() =>
    createIndexZeroGuardLinkResponder({
      advertisement: f.advertisement,
      responderIdentitySecretKey: other.secretKey,
      responderRouteEncryptionSecretKey: f.route.secretKey,
      now: () => NOW,
      receiveOffer: () => null
    })
  )
  const otherRoute = cryptoSuite.encryptionKeyPair(seed(92))
  t.exception(() =>
    createIndexZeroGuardLinkResponder({
      advertisement: f.advertisement,
      responderIdentitySecretKey: f.guard.secretKey,
      responderRouteEncryptionSecretKey: otherRoute.secretKey,
      now: () => NOW,
      receiveOffer: () => null
    })
  )

  const initiated = createIndexZeroGuardLinkOffer({
    advertisement: f.advertisement,
    now: NOW,
    randomBytes: (size) => b4a.alloc(size, 0x44),
    ...setup()
  })
  const responder = responderFor(f, () => ({
    offer: initiated.offer,
    observedPredecessorEndpoint: f.endpoint,
    physicalChannel: Object.freeze({ destroy() {} })
  }))
  responder.destroy()
  responder.destroy()
  let first = null
  let second = null
  try {
    responder.accept()
  } catch (err) {
    first = err
  }
  try {
    responder.accept()
  } catch (err) {
    second = err
  }
  t.is(first.code, 'ERR_DESTROYED')
  t.is(second.code, 'ERR_DESTROYED')
  abortIndexZeroGuardLink(initiated.pending)
})

test('initiator rejects every invalid accept binding and cross-offer substitution', (t) => {
  const mutations = [
    ['offer digest', (body) => (body[0] ^= 1)],
    ['advertisement digest', (body) => (body[32] ^= 1)],
    ['responder identity', (body) => (body[64] ^= 1)],
    ['zero observed endpoint', (body) => body.fill(0, 96, 115)],
    ['zero responder key', (body) => body.fill(0, 115, 147)],
    [
      'nonzero low-order responder key',
      (body) => {
        body.fill(0, 115, 147)
        body[115] = 1
      }
    ],
    ['over-limit cells', (body) => body.fill(0xff, 149, 153)],
    ['late accepted time', (body) => body.fill(0xff, 173, 181)],
    ['zero accept nonce', (body) => body.fill(0, 181, 213)]
  ]
  for (const [name, mutate] of mutations) {
    const x = exchange()
    let closes = 0
    const accept = resign(
      x.accepted.accept,
      M3_MESSAGE_ID.LINK_ACCEPT_V1,
      ACCEPT_DOMAIN,
      x.f.guard.secretKey,
      mutate
    )
    t.exception(
      () =>
        completeIndexZeroGuardLink(x.initiated.pending, accept, {
          advertisement: x.f.advertisement,
          physicalChannel: Object.freeze({
            destroy() {
              closes++
            }
          }),
          now: NOW
        }),
      name
    )
    t.is(closes, 1, `${name} closes physical ownership`)
    destroyM3EstablishedLink(x.accepted.established)
    x.responder.destroy()
  }

  const left = exchange({ branchClass: BRANCH_CLASS.LOOKUP })
  const right = exchange({ branchClass: BRANCH_CLASS.ANNOUNCE })
  t.exception(() =>
    completeIndexZeroGuardLink(left.initiated.pending, right.accepted.accept, {
      advertisement: left.f.advertisement,
      physicalChannel: Object.freeze({ destroy() {} }),
      now: NOW
    })
  )
  destroyM3EstablishedLink(left.accepted.established)
  destroyM3EstablishedLink(right.accepted.established)
  left.responder.destroy()
  right.responder.destroy()
})

test('destroy erases M3 link contexts and tail secret and closes physical ownership', (t) => {
  const x = exchange()
  let closes = 0
  const established = completeIndexZeroGuardLink(x.initiated.pending, x.accepted.accept, {
    advertisement: x.f.advertisement,
    physicalChannel: Object.freeze({
      destroy() {
        closes++
      }
    }),
    now: NOW
  })
  const state = readM3EstablishedLink(established)
  const forwardKey = state.contexts[0].tx.key
  const tailSecret = state.tailSharedSecret
  const tailTranscript = state.tailControlTranscript
  t.ok(destroyM3EstablishedLink(established))
  t.alike(forwardKey, b4a.alloc(32))
  t.alike(tailSecret, b4a.alloc(32))
  t.alike(tailTranscript, b4a.alloc(290))
  t.is(closes, 1)
  t.absent(destroyM3EstablishedLink(established))
  destroyM3EstablishedLink(x.accepted.established)
  x.responder.destroy()
})

test('offer pending construction is atomic at every owned key copy', (t) => {
  const countFixture = fixture()
  const countSetup = setup()
  const counted = withSlowAllocationProbe(
    () =>
      createIndexZeroGuardLinkOffer({
        advertisement: countFixture.advertisement,
        now: NOW,
        randomBytes: (size) => b4a.alloc(size, 0x44),
        ...countSetup
      }),
    302
  )
  abortIndexZeroGuardLink(counted.result.pending)

  for (let failure = 1; failure <= counted.positions; failure++) {
    const f = fixture()
    const value = setup()
    const callerSecret = b4a.from(value.clientTailEphemeral.secretKey)
    let error = null
    let allocations = []
    try {
      withSlowAllocationProbe(
        () =>
          createIndexZeroGuardLinkOffer({
            advertisement: f.advertisement,
            now: NOW,
            randomBytes: (size) => b4a.alloc(size, 0x44),
            ...value
          }),
        302,
        failure
      )
    } catch (err) {
      error = err
      allocations = err.allocations
    }
    t.ok(error, `copy ${failure} fails`)
    t.ok(allZero(allocations), `copy ${failure} clears prior owned buffers`)
    t.alike(value.clientTailEphemeral.secretKey, callerSecret, `copy ${failure} preserves caller`)
  }
})

test('responder and completion counter failures erase prior TX/RX contexts before publication', (t) => {
  t.is(typeof TEST_ONLY_COUNTER_FACTORY, 'symbol')

  for (const side of ['responder', 'completion']) {
    for (let failure = 1; failure <= 6; failure++) {
      const f = fixture()
      const value = setup()
      const initiated = createIndexZeroGuardLinkOffer({
        advertisement: f.advertisement,
        now: NOW,
        randomBytes: (size) => b4a.alloc(size, 0x44),
        ...value
      })
      const offerSnapshot = b4a.from(initiated.offer)
      const endpoint = encodeCanonicalEndpoint({
        addressFamily: 4,
        addressBytes: b4a.from([198, 51, 100, 9]),
        port: 44000
      })
      let responderCloses = 0
      const counters = []
      const responder = createIndexZeroGuardLinkResponder({
        advertisement: f.advertisement,
        responderIdentitySecretKey: f.guard.secretKey,
        responderRouteEncryptionSecretKey: f.route.secretKey,
        now: () => NOW,
        receiveOffer: () => ({
          offer: initiated.offer,
          observedPredecessorEndpoint: endpoint,
          physicalChannel: Object.freeze({
            destroy() {
              responderCloses++
            }
          })
        }),
        randomBytes: (size) => b4a.alloc(size, 0x55),
        ...(side === 'responder'
          ? { [TEST_ONLY_COUNTER_FACTORY]: testCounterFactory(failure, counters) }
          : {})
      })

      if (side === 'responder') {
        t.exception(() => responder.accept(), `${side} counter ${failure} fails`)
        t.is(responderCloses, 1, `${side} counter ${failure} does not publish a link`)
        abortIndexZeroGuardLink(initiated.pending)
      } else {
        const accepted = responder.accept()
        let initiatorCloses = 0
        t.exception(
          () =>
            completeIndexZeroGuardLink(initiated.pending, accepted.accept, {
              advertisement: f.advertisement,
              physicalChannel: Object.freeze({
                destroy() {
                  initiatorCloses++
                }
              }),
              now: NOW,
              [TEST_ONLY_COUNTER_FACTORY]: testCounterFactory(failure, counters)
            }),
          `${side} counter ${failure} fails`
        )
        t.is(initiatorCloses, 1, `${side} counter ${failure} does not publish a link`)
        destroyM3EstablishedLink(accepted.established)
      }

      t.ok(
        counters.every((counter) => counter.closed),
        `${side} counter ${failure} destroys prior counters`
      )
      t.alike(initiated.offer, offerSnapshot, `${side} counter ${failure} preserves caller offer`)
      responder.destroy()
    }
  }
})

test('responder and completion secret copies are atomic at every allocation', (t) => {
  function responderAttempt(failure = Infinity) {
    const f = fixture()
    const value = setup()
    const initiated = createIndexZeroGuardLinkOffer({
      advertisement: f.advertisement,
      now: NOW,
      randomBytes: (size) => b4a.alloc(size, 0x44),
      ...value
    })
    const offer = b4a.from(initiated.offer)
    let closes = 0
    const responder = createIndexZeroGuardLinkResponder({
      advertisement: f.advertisement,
      responderIdentitySecretKey: f.guard.secretKey,
      responderRouteEncryptionSecretKey: f.route.secretKey,
      now: () => NOW,
      receiveOffer: () => ({
        offer: initiated.offer,
        observedPredecessorEndpoint: encodeCanonicalEndpoint({
          addressFamily: 4,
          addressBytes: b4a.from([198, 51, 100, 9]),
          port: 44000
        }),
        physicalChannel: Object.freeze({
          destroy() {
            closes++
          }
        })
      }),
      randomBytes: (size) => b4a.alloc(size, 0x55)
    })
    let attempt = null
    let error = null
    try {
      attempt = withSlowAllocationProbe(() => responder.accept(), 213, failure)
    } catch (err) {
      error = err
      attempt = { allocations: err.allocations, positions: err.positions, result: null }
    }
    if (attempt.result) destroyM3EstablishedLink(attempt.result.established)
    abortIndexZeroGuardLink(initiated.pending)
    responder.destroy()
    return { ...attempt, closes, error, caller: initiated.offer, offer }
  }

  const responderCount = responderAttempt().positions
  for (let failure = 1; failure <= responderCount; failure++) {
    const attempt = responderAttempt(failure)
    t.ok(attempt.error, `responder allocation ${failure} fails`)
    t.ok(allZero(attempt.allocations), `responder allocation ${failure} clears prior secrets`)
    t.is(attempt.closes, 1, `responder allocation ${failure} publishes no link`)
    t.alike(attempt.caller, attempt.offer, `responder allocation ${failure} preserves caller`)
  }

  function completionAttempt(failure = Infinity) {
    const x = exchange()
    const accept = b4a.from(x.accepted.accept)
    let closes = 0
    let attempt = null
    let error = null
    try {
      attempt = withSlowAllocationProbe(
        () =>
          completeIndexZeroGuardLink(x.initiated.pending, x.accepted.accept, {
            advertisement: x.f.advertisement,
            physicalChannel: Object.freeze({
              destroy() {
                closes++
              }
            }),
            now: NOW
          }),
        null,
        failure
      )
    } catch (err) {
      error = err
      attempt = { allocations: err.allocations, positions: err.positions, result: null }
    }
    if (attempt.result) destroyM3EstablishedLink(attempt.result)
    destroyM3EstablishedLink(x.accepted.established)
    x.responder.destroy()
    return { ...attempt, closes, error, caller: x.accepted.accept, accept }
  }

  const completionCount = completionAttempt().positions
  for (let failure = 1; failure <= completionCount; failure++) {
    const attempt = completionAttempt(failure)
    t.ok(attempt.error, `completion allocation ${failure} fails`)
    t.ok(allZero(attempt.allocations), `completion allocation ${failure} clears prior secrets`)
    t.is(attempt.closes, 1, `completion allocation ${failure} publishes no link`)
    t.alike(attempt.caller, attempt.accept, `completion allocation ${failure} preserves caller`)
  }
})

test('derived transcript is erased when key derivation allocation fails', (t) => {
  const f = fixture()
  const initiated = createIndexZeroGuardLinkOffer({
    advertisement: f.advertisement,
    now: NOW,
    randomBytes: (size) => b4a.alloc(size, 0x44),
    ...setup()
  })
  const originalConcat = b4a.concat
  const originalAlloc = b4a.allocUnsafeSlow
  let transcript = null
  let failNext = false
  b4a.concat = (parts, totalLength) => {
    const output = originalConcat(parts, totalLength)
    if (parts.length === 4 && b4a.equals(parts[0], DOMAIN.LINK_CREATED)) {
      transcript = output
      failNext = true
    }
    return output
  }
  b4a.allocUnsafeSlow = (size) => {
    if (failNext) {
      failNext = false
      throw new Error('injected derivation allocation failure')
    }
    return originalAlloc(size)
  }
  const responder = responderFor(f, () => ({
    offer: initiated.offer,
    observedPredecessorEndpoint: encodeCanonicalEndpoint({
      addressFamily: 4,
      addressBytes: b4a.from([198, 51, 100, 9]),
      port: 44000
    }),
    physicalChannel: Object.freeze({ destroy() {} })
  }))
  try {
    t.exception(() => responder.accept())
  } finally {
    b4a.concat = originalConcat
    b4a.allocUnsafeSlow = originalAlloc
    responder.destroy()
    abortIndexZeroGuardLink(initiated.pending)
  }
  t.ok(transcript)
  if (transcript) {
    t.ok(
      transcript.every((byte) => byte === 0),
      'failed derived transcript is zeroized'
    )
  }
})
