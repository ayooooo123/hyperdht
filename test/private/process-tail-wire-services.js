'use strict'

const test = require('brittle')
const b4a = require('b4a')
const UDX = require('udx-native')
const c = require('compact-encoding')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const guardLinks = require('../../lib/private/guard-link')
const {
  claimFinalExitActivation,
  createFinalExitActivationClaim,
  createFinalExitActivationFactory,
  driveEndpointFinalExit,
  openFinalExit
} = require('../../lib/private/final-exit-activation')
const { digestPayloadParameters } = require('../../lib/private/link-parameters')
const { M3AdjacencyAuthority } = require('../../lib/private/m3-adjacency-runtime')
const { decodeM3ContextEnvelope, encodeM3ContextEnvelope } = require('../../lib/private/m3-context')
const {
  BRANCH_CLASS,
  CAPACITY_CLASS,
  CONTEXT_CLASS,
  LINK_OPERATION,
  PROTOCOL_VERSION,
  RELAY_CAPABILITY,
  ROLE,
  TOPOLOGY_ROLE,
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
const { deriveDhtExitPeerId } = require('../../lib/private/dht-exit-destination-table')
const {
  digestTestIsolatedAddressTuple,
  encodeTestIsolatedAddressGrant
} = require('../../lib/private/dht-exit-test-topology-grant')
const {
  borrowTailControlTransport,
  EXTENDED_SIZE,
  TAIL_READY_SIZE,
  createTailControlSession,
  destroyTailControlSession
} = require('../../lib/private/tail-control')
const { signTopologyGrant } = require('../../lib/private/topology-grant')
const { UdxCellEndpoint } = require('../../lib/private/udx-cell-endpoint')
const {
  activateFinalExitActor,
  acceptProjectedExtension,
  createEndpointFinalRouteActor,
  createProjectedLinkService,
  createTailRelayActor
} = require('./process/wire-services')

const HOST = '127.0.0.1'
const NOW = 1_000n
let nextPort = 49_700

function identityFor(role, value) {
  for (let index = value; index < value + 512; index++) {
    const pair = cryptoSuite.keyPair(b4a.alloc(32, index & 0xff))
    if (roleForIdentity(pair.publicKey) === role) return pair
    pair.secretKey.fill(0)
    pair.publicKey.fill(0)
  }
  throw new Error('identity role unavailable')
}

function canonical(host, port) {
  return encodeCanonicalEndpoint({
    addressFamily: 4,
    addressBytes: b4a.from(host.split('.').map(Number)),
    port
  })
}

function advertisement(identity, route, host, port, capabilityMask) {
  const reachableEndpoint = canonical(host, port)
  const encoded = encodeRelayCapabilityAdvertisement(
    signRelayCapabilityAdvertisement(
      {
        relayIdentity: identity.publicKey,
        currentDhtNodeId: deriveM3DhtNodeId(reachableEndpoint),
        reachableEndpoint,
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
        expiresAtMs: 60_000n,
        providerServicePolicyEntries: providerServicePolicyForCapabilities(capabilityMask)
      },
      identity.secretKey
    )
  )
  return Object.freeze({
    bytes: encoded,
    digest: digestRelayCapabilityAdvertisement(encoded, { now: NOW }),
    endpoint: reachableEndpoint
  })
}

function clocks() {
  return {
    wallNow: () => NOW,
    monotonicNow: () => NOW,
    schedule(callback, delay) {
      const timer = setTimeout(callback, delay)
      if (typeof timer.unref === 'function') timer.unref()
      return timer
    },
    cancelScheduled: clearTimeout
  }
}

async function signedLink(leftIdentity, rightIdentity, rightRoute, leftRole, rightRole, seed) {
  const leftPort = nextPort++
  const rightPort = nextPort++
  const authority = cryptoSuite.keyPair(b4a.alloc(32, seed))
  const runId32 = b4a.alloc(32, seed + 1)
  const grant = signTopologyGrant(
    {
      version: PROTOCOL_VERSION,
      format: 0,
      grantId32: b4a.alloc(32, seed + 2),
      endpointA: {
        identity32: leftIdentity.publicKey,
        role: leftRole,
        host: HOST,
        port: leftPort,
        operations: LINK_OPERATION.KNOWN
      },
      endpointB: {
        identity32: rightIdentity.publicKey,
        role: rightRole,
        host: HOST,
        port: rightPort,
        operations: LINK_OPERATION.KNOWN
      },
      epoch: 1n,
      notBefore: 0n,
      expiresAt: 60_000n,
      runId32
    },
    authority.secretKey
  )
  const leftDispatch = {}
  const rightDispatch = {}
  const leftEndpoint = new UdxCellEndpoint({
    host: HOST,
    port: leftPort,
    onBootstrap: (packet, handle) => leftDispatch.bootstrap(packet, handle),
    onCell: (packet, handle, metadata) => leftDispatch.cell(packet, handle, metadata),
    onLinkFailure: (handle, direction, reason) => leftDispatch.failure(handle, direction, reason)
  })
  const rightEndpoint = new UdxCellEndpoint({
    host: HOST,
    port: rightPort,
    onBootstrap: (packet, handle) => rightDispatch.bootstrap(packet, handle),
    onCell: (packet, handle, metadata) => rightDispatch.cell(packet, handle, metadata),
    onLinkFailure: (handle, direction, reason) => rightDispatch.failure(handle, direction, reason)
  })
  const clock = clocks()
  const left = createProjectedLinkService({
    ...clock,
    endpoint: leftEndpoint,
    authorityPublicKey: authority.publicKey,
    epoch: 1n,
    localIdentity: leftIdentity.publicKey,
    localIdentitySecretKey: leftIdentity.secretKey,
    localRouteSecretKey: null,
    runId32
  })
  const right = createProjectedLinkService({
    ...clock,
    endpoint: rightEndpoint,
    authorityPublicKey: authority.publicKey,
    epoch: 1n,
    localIdentity: rightIdentity.publicKey,
    localIdentitySecretKey: rightIdentity.secretKey,
    localRouteSecretKey: rightRoute.secretKey,
    runId32
  })
  leftDispatch.bootstrap = left.receiveBootstrap
  leftDispatch.cell = left.receiveCell
  leftDispatch.failure = left.receiveLinkFailure
  rightDispatch.bootstrap = right.receiveBootstrap
  rightDispatch.cell = right.receiveCell
  rightDispatch.failure = right.receiveLinkFailure
  await Promise.all([leftEndpoint.bind(), rightEndpoint.bind()])
  const accepted = right.prearmAccept(grant)
  return Object.freeze({
    accepted,
    clock,
    grant,
    left,
    leftEndpoint,
    leftPort,
    right,
    rightEndpoint,
    rightPort,
    async destroy() {
      await Promise.allSettled([left.destroy(), right.destroy()])
      await Promise.allSettled([leftEndpoint.close(), rightEndpoint.close()])
    }
  })
}

function tailEnvelope(encoded) {
  const frame = b4a.alloc(1100)
  frame.set(encoded)
  return encodeM3ContextEnvelope({ contextClass: CONTEXT_CLASS.TAIL_CONTROL_ORDERED, frame })
}

test('TailControl actors exchange offer, proof and responder-owned READY over signed UDX links', async (t) => {
  const clientIdentity = identityFor(ROLE.SAFETY, 0x10)
  const guardIdentity = identityFor(ROLE.SAFETY, 0x40)
  const middleIdentity = identityFor(ROLE.SAFETY, 0x70)
  const exitIdentity = identityFor(ROLE.PRIVATE, 0xa0)
  const guardRoute = cryptoSuite.encryptionKeyPair(b4a.alloc(32, 0xd0))
  const middleRoute = cryptoSuite.encryptionKeyPair(b4a.alloc(32, 0xd1))
  const exitRoute = cryptoSuite.encryptionKeyPair(b4a.alloc(32, 0xd2))
  const initial = await signedLink(
    clientIdentity,
    guardIdentity,
    guardRoute,
    TOPOLOGY_ROLE.SOURCE,
    TOPOLOGY_ROLE.SAFETY_GUARD,
    0xe1
  )
  const guardToMiddle = await signedLink(
    guardIdentity,
    middleIdentity,
    middleRoute,
    TOPOLOGY_ROLE.SAFETY_GUARD,
    TOPOLOGY_ROLE.SAFETY_FINAL,
    0xe5
  )
  const middleToExit = await signedLink(
    middleIdentity,
    exitIdentity,
    exitRoute,
    TOPOLOGY_ROLE.SAFETY_FINAL,
    TOPOLOGY_ROLE.PRIVATE_ENTRY,
    0xe9
  )
  const guardAd = advertisement(
    guardIdentity,
    guardRoute,
    HOST,
    initial.rightPort,
    RELAY_CAPABILITY.CIRCUIT_RELAY_V1
  )
  const middleAd = advertisement(
    middleIdentity,
    middleRoute,
    HOST,
    guardToMiddle.rightPort,
    RELAY_CAPABILITY.CIRCUIT_RELAY_V1
  )
  const exitAd = advertisement(
    exitIdentity,
    exitRoute,
    HOST,
    middleToExit.rightPort,
    RELAY_CAPABILITY.CIRCUIT_RELAY_V1 | RELAY_CAPABILITY.DHT_EXIT_V1
  )
  let clientTail = null
  let nextTail = null
  let clientRuntime = null
  let guardActor = null
  let middleActor = null
  let exitActor = null
  let middlePromise = null
  let exitPromise = null
  let finalTail = null
  let finalService = null
  let seedSocket = null
  let referralSocket = null
  let endpointRouteActor = null
  const objectFromEnvelope = (envelope, size) => {
    const decoded = decodeM3ContextEnvelope(envelope)
    const encoded = b4a.from(decoded.frame.subarray(0, size))
    decoded.frame.fill(0)
    return encoded
  }
  try {
    const initialOpened = await initial.left.initiate(initial.grant, {
      circuitId: b4a.alloc(16, 0x21),
      generation: 1n,
      responderStaticKey: guardRoute.publicKey
    })
    const initialAccepted = await initial.accepted
    const clientPhysical = initial.left.takeChannel(initialOpened)
    const guardPhysical = initial.right.takeChannel(initialAccepted)
    const decodedGuard = decodeRelayCapabilityAdvertisement(guardAd.bytes)
    const parametersDigest = digestPayloadParameters(decodedGuard)
    const limits = (expiresAtMs) =>
      Object.freeze({
        cellSize: 1200,
        maxCells: 100,
        maxBytes: 100_000,
        maxCommands: 10,
        idleTimeoutMs: 30_000,
        expiresAtMs
      })
    const currentLimits = limits(16_000n)
    const linkSetup = {
      branchClass: BRANCH_CLASS.LOOKUP,
      branchId: b4a.alloc(16, 0x31),
      circuitId: b4a.alloc(16, 0x32),
      generation: 1n,
      clientCircuitIdentity: cryptoSuite.keyPair(b4a.alloc(32, 0x33)),
      clientTailEphemeral: cryptoSuite.encryptionKeyPair(b4a.alloc(32, 0x34)),
      payloadParametersDigest: parametersDigest,
      requestedLimits: currentLimits
    }
    const initiated = guardLinks.createIndexZeroGuardLinkOffer({
      advertisement: guardAd.bytes,
      now: NOW,
      randomBytes: cryptoSuite.randomBytes,
      ...linkSetup
    })
    const responder = guardLinks.createIndexZeroGuardLinkResponder({
      advertisement: guardAd.bytes,
      responderIdentitySecretKey: guardIdentity.secretKey,
      responderRouteEncryptionSecretKey: guardRoute.secretKey,
      now: () => NOW,
      receiveOffer: () => ({
        offer: initiated.offer,
        observedPredecessorEndpoint: canonical(HOST, initial.leftPort),
        physicalChannel: guardPhysical
      }),
      randomBytes: cryptoSuite.randomBytes
    })
    const acceptedM3 = responder.accept()
    const completedM3 = guardLinks.completeIndexZeroGuardLink(
      initiated.pending,
      acceptedM3.accept,
      {
        advertisement: guardAd.bytes,
        physicalChannel: clientPhysical,
        now: NOW
      }
    )
    const clientAuthority = new M3AdjacencyAuthority({ ...initial.clock, crypto: cryptoSuite })
    const guardAuthority = new M3AdjacencyAuthority({ ...initial.clock, crypto: cryptoSuite })
    const clientAdjacency = clientAuthority.adopt(completedM3)
    const guardAdjacency = guardAuthority.adopt(acceptedM3.established)
    clientRuntime = clientAdjacency.runtime
    clientTail = createTailControlSession(clientAdjacency.tail, {
      ...initial.clock,
      absoluteDeadline: 20_000n,
      crypto: cryptoSuite
    })
    guardActor = createTailRelayActor({
      adjacency: guardAdjacency,
      adjacencyAuthority: guardAuthority,
      advertisement: guardAd.bytes,
      identityPublicKey: guardIdentity.publicKey,
      identitySecretKey: guardIdentity.secretKey,
      clocks: initial.clock,
      outgoing: {
        advertisementDigest: middleAd.digest,
        allowedRole: ROLE.SAFETY,
        extensionIndex: 1,
        grant: guardToMiddle.grant,
        linkService: guardToMiddle.left,
        peerIdentity: middleIdentity.publicKey
      }
    })
    middlePromise = acceptProjectedExtension({
      accepted: guardToMiddle.accepted,
      advertisement: middleAd.bytes,
      clocks: guardToMiddle.clock,
      identityPublicKey: middleIdentity.publicKey,
      identitySecretKey: middleIdentity.secretKey,
      linkService: guardToMiddle.right,
      observedPredecessorEndpoint: canonical(HOST, guardToMiddle.leftPort),
      routeSecretKey: middleRoute.secretKey,
      outgoing: {
        advertisementDigest: exitAd.digest,
        allowedRole: ROLE.PRIVATE,
        extensionIndex: 2,
        grant: middleToExit.grant,
        linkService: middleToExit.left,
        peerIdentity: exitIdentity.publicKey
      }
    })
    void middlePromise.catch(() => {})
    const firstExtension = clientTail.sealExtend({
      advertisement: middleAd.bytes,
      advertisementDigest: middleAd.digest,
      extensionIndex: 1,
      requestedLimits: currentLimits,
      absoluteDeadline: 16_000n,
      randomBytes: cryptoSuite.randomBytes
    })
    await borrowTailControlTransport(clientTail).send(tailEnvelope(firstExtension))
    const firstResults = await Promise.all([guardActor.serve(), middlePromise])
    middleActor = firstResults[1]
    t.is(firstResults[0], true, 'guard completes authenticated first extension')
    t.ok(guardActor.forwarding, 'guard installs forwarding before first READY')
    const firstExtendedEnvelope = await borrowTailControlTransport(clientTail).receive()
    const firstReadyEnvelope = await borrowTailControlTransport(clientTail).receive()
    const firstExtended = objectFromEnvelope(firstExtendedEnvelope, EXTENDED_SIZE)
    const firstReady = objectFromEnvelope(firstReadyEnvelope, TAIL_READY_SIZE)
    borrowTailControlTransport(clientTail).release(firstExtendedEnvelope)
    borrowTailControlTransport(clientTail).release(firstReadyEnvelope)
    const firstCompletion = clientTail.openExtended(firstExtended)
    nextTail = clientTail.completeClientExtension(firstCompletion, firstReady)
    firstExtended.fill(0)
    firstReady.fill(0)

    exitPromise = acceptProjectedExtension({
      accepted: middleToExit.accepted,
      advertisement: exitAd.bytes,
      clocks: middleToExit.clock,
      identityPublicKey: exitIdentity.publicKey,
      identitySecretKey: exitIdentity.secretKey,
      linkService: middleToExit.right,
      observedPredecessorEndpoint: canonical(HOST, middleToExit.leftPort),
      routeSecretKey: exitRoute.secretKey
    })
    void exitPromise.catch(() => {})
    const secondExtension = nextTail.sealExtend({
      advertisement: exitAd.bytes,
      advertisementDigest: exitAd.digest,
      extensionIndex: 2,
      requestedLimits: currentLimits,
      absoluteDeadline: 16_000n,
      randomBytes: cryptoSuite.randomBytes
    })
    await borrowTailControlTransport(nextTail).send(tailEnvelope(secondExtension))
    const secondResults = await Promise.all([middleActor.serve(), exitPromise])
    exitActor = secondResults[1]
    t.is(secondResults[0], true, 'middle completes authenticated terminal extension')
    t.ok(middleActor.forwarding, 'middle installs forwarding before terminal READY')
    t.ok(exitActor, 'exit owns terminal TailControl responder')
    const secondExtended = await borrowTailControlTransport(nextTail).receive()
    const secondReady = await borrowTailControlTransport(nextTail).receive()
    t.is(secondExtended.byteLength, 1101, 'terminal EXTENDED crosses the routed UDX tail')
    t.is(secondReady.byteLength, 1101, 'successor-signed READY crosses installed forwarding')
    const finalExtended = objectFromEnvelope(secondExtended, EXTENDED_SIZE)
    const finalReady = objectFromEnvelope(secondReady, TAIL_READY_SIZE)
    borrowTailControlTransport(nextTail).release(secondExtended)
    borrowTailControlTransport(nextTail).release(secondReady)
    const finalCompletion = nextTail.openExtended(finalExtended)
    finalTail = nextTail.completeClientExtension(finalCompletion, finalReady)
    finalExtended.fill(0)
    finalReady.fill(0)

    const seedPort = nextPort++
    const referralPort = nextPort++
    const dhtLocalPort = nextPort++
    const immutableValue = b4a.from('production-routed-referral-value')
    const immutableTarget = cryptoSuite.hash([immutableValue])
    const responseFor = (packet, from, flags, suffix = b4a.alloc(0)) => {
      const response = b4a.alloc(10 + suffix.byteLength)
      response[0] = 0x13
      response[1] = flags
      response[2] = packet[2]
      response[3] = packet[3]
      response.set([...from.host.split('.').map(Number), from.port & 0xff, from.port >>> 8], 4)
      response.set(suffix, 10)
      return response
    }
    let seedPackets = 0
    let referralPackets = 0
    let resolveSeedPacket
    const seedPacket = new Promise((resolve) => {
      resolveSeedPacket = resolve
    })
    referralSocket = new UDX().createSocket()
    referralSocket.on('message', (packet, from) => {
      referralPackets++
      const suffix = referralPackets === 1 ? b4a.alloc(0) : c.encode(c.buffer, immutableValue)
      const response = responseFor(packet, from, referralPackets === 1 ? 0 : 0x10, suffix)
      void referralSocket.send(response, from.port, from.host)
    })
    await referralSocket.bind(referralPort, HOST)
    const referralTuple = { host: HOST, port: referralPort }
    seedSocket = new UDX().createSocket()
    seedSocket.on('message', (packet, from) => {
      seedPackets++
      resolveSeedPacket(true)
      const suffix =
        seedPackets === 1 ? b4a.alloc(0) : c.encode(c.array(c.ipv4Address), [referralTuple])
      const response = responseFor(packet, from, seedPackets === 1 ? 0 : 0x04, suffix)
      void seedSocket.send(response, from.port, from.host)
    })
    await seedSocket.bind(seedPort, HOST)
    const seedTuple = { host: HOST, port: seedPort }
    const seedId = b4a.alloc(32, 0xf1)
    const referralId = deriveDhtExitPeerId(referralTuple)
    const runNonce = b4a.alloc(16, 0xf2)
    const grantAuthority = cryptoSuite.keyPair(b4a.alloc(32, 0xf3))
    const tupleDigest = digestTestIsolatedAddressTuple({
      tuple: seedTuple,
      id: seedId,
      exitRole: 4,
      generation: 1n
    })
    const learnedTupleDigest = digestTestIsolatedAddressTuple({
      tuple: referralTuple,
      id: referralId,
      exitRole: 4,
      generation: 1n
    })
    const grantFor = (digest, sequence) =>
      encodeTestIsolatedAddressGrant(
        {
          runNonce,
          exitRole: 4,
          generation: 1n,
          grantSequence: sequence,
          expiresAt: 60_000n,
          tupleDigest: digest
        },
        grantAuthority.secretKey
      )
    const initialGrant = grantFor(tupleDigest, 1n)
    const learnedGrant = grantFor(learnedTupleDigest, 2n)
    let isolatedGrantRequests = 0
    const endpointHandoff = finalTail.takeFinalExitHandoff()
    const endpointClaim = createFinalExitActivationClaim(endpointHandoff)
    const endpointOwner = claimFinalExitActivation(endpointHandoff, endpointClaim)
    const endpointFactory = createFinalExitActivationFactory({
      wallNow: initial.clock.wallNow,
      monotonicNow: initial.clock.monotonicNow,
      randomBytes: cryptoSuite.randomBytes,
      schedule: initial.clock.schedule,
      cancelScheduled: initial.clock.cancelScheduled
    })
    const endpointFacade = openFinalExit(endpointFactory, {
      handoff: endpointOwner,
      crypto: cryptoSuite,
      payloadParameters: decodeRelayCapabilityAdvertisement(exitAd.bytes),
      readySigner: undefined
    })
    const finalServicePromise = activateFinalExitActor({
      actor: exitActor,
      advertisement: exitAd.bytes,
      identityPublicKey: exitIdentity.publicKey,
      identitySecretKey: exitIdentity.secretKey,
      clocks: middleToExit.clock,
      local: { host: HOST, port: dhtLocalPort },
      dhtSeed: seedTuple,
      dhtSeedId: seedId,
      exitRole: 4,
      generation: 1n,
      initialSeedGrant: initialGrant,
      isolatedGrantVerifier: { publicKey: grantAuthority.publicKey, run: runNonce },
      requestIsolatedGrant: async (digest) => {
        isolatedGrantRequests++
        t.is(referralPackets, 0, 'learned candidate PING is absent until grant')
        t.alike(digest, learnedTupleDigest, 'grant request binds the learned closer digest')
        t.absent(b4a.equals(digest, tupleDigest), 'learned grant never reuses configured seed')
        return b4a.from(learnedGrant)
      }
    })
    const endpointRouteHandoff = await driveEndpointFinalExit(endpointFacade)
    const endpointRouteActorPromise = createEndpointFinalRouteActor(endpointRouteHandoff, {
      wallNow: initial.clock.wallNow,
      monotonicNow: initial.clock.monotonicNow,
      randomBytes: cryptoSuite.randomBytes
    })
    t.ok(
      await Promise.race([seedPacket, new Promise((resolve) => setTimeout(resolve, 1_000, false))]),
      'production DhtExitIO reaches the real UDX seed'
    )
    const services = await Promise.all([endpointRouteActorPromise, finalServicePromise])
    endpointRouteActor = services[0]
    finalService = services[1]
    t.is(isolatedGrantRequests, 0, 'configured seed consumes its initial grant without callback')
    const result = await endpointRouteActor.immutableGet(immutableTarget)
    t.alike(result.value, immutableValue, 'endpoint actor receives the immutable value')
    t.is(isolatedGrantRequests, 1, 'one learned closer requests one isolated grant')
    t.ok(referralPackets >= 2, 'grant permits referral PING then immutable request')
    const metrics = finalService.snapshot()
    t.ok(metrics.referralProbeCount >= 1, 'production exit records the referral probe')
    t.ok(metrics.ordinaryRequestCount >= 2, 'production exit records seed and referral requests')
    t.ok(metrics.tableEntryCount >= 2, 'production table admits the learned referral')
    tupleDigest.fill(0)
    learnedTupleDigest.fill(0)
    referralId.fill(0)
    seedId.fill(0)
    runNonce.fill(0)
    initialGrant.fill(0)
    learnedGrant.fill(0)
    immutableTarget.fill(0)
  } finally {
    if (endpointRouteActor) await endpointRouteActor.destroy()
    if (finalService) await finalService.destroy()
    if (referralSocket) await referralSocket.close()
    if (seedSocket) await seedSocket.close()
    if (finalTail) destroyTailControlSession(finalTail)
    if (exitActor) exitActor.destroy()
    if (middleActor) middleActor.destroy()
    if (guardActor) guardActor.destroy()
    if (nextTail) destroyTailControlSession(nextTail)
    if (clientTail) destroyTailControlSession(clientTail)
    if (clientRuntime) clientRuntime.destroy()
    await Promise.allSettled([initial.destroy(), guardToMiddle.destroy(), middleToExit.destroy()])
  }
})
