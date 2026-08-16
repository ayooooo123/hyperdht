'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  createEndpointBootstrapAuthority
} = require('../../lib/private/endpoint-bootstrap-authority')
const controllerModule = require('../../lib/private/private-routing-controller')
const {
  createPrivateRoutingController,
  PRIVATE_ROUTING_STATE,
  TEST_ONLY_PRIVATE_ROUTING_CONTROLLER_ISSUER
} = controllerModule
const controllerIssuer = TEST_ONLY_PRIVATE_ROUTING_CONTROLLER_ISSUER
const { CapsResponder } = require('../../lib/private/caps-responder')
const { BootstrapEnvelopeCodec } = require('../../lib/private/bootstrap-envelope')
const {
  decodeRelayCapabilityAdvertisement,
  encodeCanonicalEndpoint
} = require('../../lib/private/relay-capability')
const { BRANCH_CLASS, decodeM3Object } = require('../../lib/private/protocol')
const { createLinkSetupAuthority } = require('../../lib/private/link-setup')
const { createIndexZeroGuardLinkResponder } = require('../../lib/private/guard-link')
const { M3AdjacencyAuthority } = require('../../lib/private/m3-adjacency-runtime')
const {
  admitTailExtend,
  borrowTailControlTransport,
  createTailControlResponderAuthority,
  createTailControlSession,
  destroyTailControlResponderAuthority,
  destroyTailControlSession,
  digestAdmittedLimits,
  encodeExtended,
  readTailControlTranscriptDigest,
  takeAdmittedExtendRequest
} = require('../../lib/private/tail-control')
const endpointModule = require('../../lib/private/udx-cell-endpoint')
const { candidate, identityFor, canonicalEndpointForHost } = require('./live-topology-fixture')
const { CONTEXT_CLASS, M3_MESSAGE_ID, ROLE, TOPOLOGY_ROLE } = require('../../lib/private/protocol')
const { digestRelayCapabilityAdvertisement } = require('../../lib/private/relay-capability')
const { signRedactedResponderProof } = require('../../lib/private/redacted-responder-proof')
const {
  createDhtExitReadySigner,
  createRelayIdentitySigningAuthority
} = require('../../lib/private/relay-identity-signer')
const { createHostedTailResponder } = require('./hosted-tail-fixture')
const { createCoherentTestClock } = require('./coherent-clock')
const { nativeAdjacentPair } = require('./native-adjacent-fixture')
const {
  claimFinalExitActivation,
  createFinalExitActivationClaim,
  createFinalExitActivationFactory,
  driveDhtExitFinalExit,
  openFinalExit
} = require('../../lib/private/final-exit-activation')
const {
  createDhtExitReservationChannel,
  consumeDhtExitReservationIOConsumer
} = require('../../lib/private/dht-exit-reservation')
const {
  createDhtExitDestinationTable,
  destroyDhtExitDestinationTable,
  reserveConfiguredBootstrapProbe,
  settleExitDhtReservation
} = require('../../lib/private/dht-exit-destination-table')
const { createDhtExitSeedsDeliveryAuthority } = require('../../lib/private/dht-exit-seeds')
const {
  TEST_ONLY_DHT_EXIT_SOCKET_ISSUER,
  closeDhtExitIO,
  createDhtExitIOForTest,
  installDhtExitRoute,
  sendDhtExitSeeds,
  sendReservedExitDhtPacket
} = require('../../lib/private/dht-exit-io')
const { encodeM3Object } = require('../../lib/private/protocol')
const sessionModule = require('../../lib/private/link-bootstrap-session')
const routeManagerModule = require('../../lib/private/route-manager')
const routeManagerFactoryIssuer = routeManagerModule.TEST_ONLY_ROUTE_MANAGER_FACTORY_ISSUER
const {
  closeLiveAuthorityHarness,
  dhtResponseFor,
  liveAuthorityHarness,
  waitFor
} = require('./routed-dht-traversal')

const seed = (value) => b4a.alloc(32, value)

function controller(value, port, clock = null) {
  const identity = cryptoSuite.keyPair(seed(value))
  return createPrivateRoutingController({
    endpointBootstrapAuthority: createEndpointBootstrapAuthority({
      bootstrapEndpoints: [{ host: '127.0.0.2', port: port + 1 }],
      localIdentity: identity.publicKey,
      localSecretKey: identity.secretKey,
      host: '127.0.0.1',
      port,
      wallNow: clock === null ? () => 1_000n : clock.wallNow,
      monotonicNow: clock === null ? () => 1_000n : clock.monotonicNow,
      schedule: setTimeout,
      cancelScheduled: clearTimeout,
      randomBytes: (size) => b4a.alloc(size, value + 1)
    })
  })
}

async function code(promise) {
  try {
    await promise
    return null
  } catch (err) {
    return err && err.code
  }
}
async function waitForReady(routing) {
  for (let attempt = 0; attempt < 100; attempt++) {
    const state = routing.snapshot().state
    if (state === PRIVATE_ROUTING_STATE.READY) return
    if (state === PRIVATE_ROUTING_STATE.UNAVAILABLE) {
      throw new Error('controller entered UNAVAILABLE before READY')
    }
    await new Promise((resolve) => setTimeout(resolve, 1))
  }
  throw new Error(`controller remained ${routing.snapshot().state}`)
}
async function waitForState(routing, wanted) {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (routing.snapshot().state === wanted) return
    await new Promise((resolve) => setTimeout(resolve, 1))
  }
  throw new Error(`controller did not enter ${wanted}`)
}

async function waitForIO(check) {
  for (let attempt = 0; attempt < 5_000; attempt++) {
    if (check()) return
    await new Promise((resolve) => setTimeout(resolve, 1))
  }
  throw new Error('IO condition was not reached')
}

async function pumpQuery(harness, value) {
  const base = harness.fakeSocket.sends.length
  await waitForIO(() => harness.fakeSocket.sends.length >= base + 1)
  const closer = b4a.from([1, 1, 1, 1, 1, 0x49, 0xc2])
  harness.fakeSocket.message(dhtResponseFor(harness.fakeSocket.sends[base].packet, 0x04, closer), {
    host: '8.8.8.8',
    port: 49737
  })
  await waitForIO(() => harness.fakeSocket.sends.length >= base + 2)
  harness.fakeSocket.message(dhtResponseFor(harness.fakeSocket.sends[base + 1].packet, 0), {
    host: '1.1.1.1',
    port: 49737
  })
  await waitForIO(() => harness.fakeSocket.sends.length >= base + 3)
  const suffix = value === null ? b4a.alloc(0) : b4a.concat([b4a.from([value.byteLength]), value])
  harness.fakeSocket.message(
    dhtResponseFor(harness.fakeSocket.sends[base + 2].packet, value === null ? 0 : 0x10, suffix),
    { host: '1.1.1.1', port: 49737 }
  )
}
async function pumpDirectValue(harness, value) {
  const base = harness.fakeSocket.sends.length
  await waitForIO(() => harness.fakeSocket.sends.length > base)
  const sent = harness.fakeSocket.sends[base]
  const suffix = b4a.concat([b4a.from([value.byteLength]), value])
  harness.fakeSocket.message(dhtResponseFor(sent.packet, 0x10, suffix), {
    host: sent.host,
    port: sent.port
  })
}

test('internal immutableGet emits no work before exact READY', async (t) => {
  const routing = controller(71, 48771)
  t.is(await code(routing.immutableGet(seed(1))), 'ERR_PRIVACY_UNAVAILABLE')
  t.alike(routing.snapshot().packetEdges, [])
  t.is(routing.snapshot().activeQueries, 0)
  await routing.destroy()
})

async function controlledHarness(value, port) {
  let routing = null
  const harness = await liveAuthorityHarness((manager, topology) => {
    routing = controller(value, port, topology.clock)
    const builder = controllerIssuer.registerManager(routing, manager)
    return {
      publishInitialPair: (handoffs) =>
        controllerIssuer.publishInitialPair(routing, builder, handoffs),
      createDhtSeedAdmission: (branchClass, owner) =>
        controllerIssuer.createDhtSeedAdmission(routing, builder, branchClass, owner),
      publishInitialSeedPair: (readiness) =>
        controllerIssuer.publishInitialSeedPair(routing, builder, readiness)
    }
  })
  await waitForReady(routing)
  return { harness, routing }
}

test('internal immutableGet rejects destroyed and malformed ownership states', async (t) => {
  const routing = controller(73, 48773)
  await routing.destroy()
  t.is(await code(routing.immutableGet(seed(2))), 'ERR_DESTROYED')
  t.is(routing.snapshot().activeQueries, 0)
  t.is(routing.snapshot().transportDHT, false)
  t.is(routing.snapshot().routedDHTIO, false)
})

test('controller reaches READY from genuine OPEN and seed publication and returns exact value', async (t) => {
  let routing = null
  const harness = await liveAuthorityHarness((manager, topology) => {
    routing = controller(79, 48779, topology.clock)
    const builder = controllerIssuer.registerManager(routing, manager)
    return {
      publishInitialPair: (handoffs) =>
        controllerIssuer.publishInitialPair(routing, builder, handoffs),
      createDhtSeedAdmission: (branchClass, owner) =>
        controllerIssuer.createDhtSeedAdmission(routing, builder, branchClass, owner),
      publishInitialSeedPair: (readiness) =>
        controllerIssuer.publishInitialSeedPair(routing, builder, readiness)
    }
  })
  try {
    await waitForReady(routing)
    t.is(routing.snapshot().state, PRIVATE_ROUTING_STATE.READY)
    const value = b4a.from('controller-live-routed-immutable-value')
    const target = cryptoSuite.hash([value])
    const upstream = pumpQuery(harness, value)
    const result = await routing.immutableGet(target)
    await upstream
    t.alike(result.value, value)
    const badValue = b4a.from('malicious-exit-value')
    const badTarget = cryptoSuite.hash([b4a.from('different-value')])
    const badUpstream = pumpDirectValue(harness, badValue)
    t.is(await code(routing.immutableGet(badTarget)), 'ERR_PRIVACY_UNAVAILABLE')
    await badUpstream
    t.is(routing.snapshot().activeQueries, 0)
    t.is(routing.snapshot().state, PRIVATE_ROUTING_STATE.READY)
  } finally {
    if (routing) await routing.destroy()
    await closeLiveAuthorityHarness(harness)
  }
})

test('network change cancels the generation-owned query and revokes transport', async (t) => {
  let routing = null
  const harness = await liveAuthorityHarness((manager, topology) => {
    routing = controller(83, 48803, topology.clock)
    const builder = controllerIssuer.registerManager(routing, manager)
    return {
      publishInitialPair: (handoffs) =>
        controllerIssuer.publishInitialPair(routing, builder, handoffs),
      createDhtSeedAdmission: (branchClass, owner) =>
        controllerIssuer.createDhtSeedAdmission(routing, builder, branchClass, owner),
      publishInitialSeedPair: (readiness) =>
        controllerIssuer.publishInitialSeedPair(routing, builder, readiness)
    }
  })
  try {
    await waitForReady(routing)
    const before = harness.fakeSocket.sends.length
    const cancelled = code(routing.immutableGet(seed(92)))
    await waitFor(() => harness.fakeSocket.sends.length > before)
    await routing.networkChanged()
    t.is(await cancelled, 'ERR_DESTROYED')
    t.is(routing.snapshot().state, PRIVATE_ROUTING_STATE.UNAVAILABLE)
    t.is(routing.snapshot().activeQueries, 0)
    t.is(routing.snapshot().transportDHT, false)
    t.is(routing.snapshot().routedDHTIO, false)
  } finally {
    if (routing) await routing.destroy()
    await closeLiveAuthorityHarness(harness)
  }
})

test('candidate-directory rollback tombstones evidence and revokes the live generation', async (t) => {
  const { harness, routing } = await controlledHarness(97, 48837)
  try {
    const before = harness.fakeSocket.sends.length
    harness.topology.clock.rollbackWall(30_001)
    t.exception(() =>
      harness.topology.directory.reserveReplacement({
        branchClass: BRANCH_CLASS.LOOKUP,
        generation: 2n
      })
    )
    await waitForState(routing, PRIVATE_ROUTING_STATE.UNAVAILABLE)
    t.is(routing.snapshot().activeQueries, 0)
    t.is(routing.snapshot().transportDHT, false)
    t.is(routing.snapshot().routedDHTIO, false)
    t.is(routing.snapshot().routeManager, false)
    t.is(routing.snapshot().guardLease, false)
    t.is(harness.fakeSocket.sends.length, before)
  } finally {
    await routing.destroy()
    await closeLiveAuthorityHarness(harness)
  }
})

test('suspend failure after transport teardown destroys partial ownership and becomes unavailable', async (t) => {
  const { harness, routing } = await controlledHarness(101, 48841)
  try {
    harness.topology.directory.destroy()
    t.is(await code(routing.suspend()), 'ERR_DESTROYED')
    t.is(routing.snapshot().state, PRIVATE_ROUTING_STATE.UNAVAILABLE)
    t.is(routing.snapshot().transportDHT, false)
    t.is(routing.snapshot().routedDHTIO, false)
    t.is(routing.snapshot().routeManager, false)
    t.is(routing.snapshot().guardLease, false)
    t.is(routing.snapshot().reconnect, false)
    t.alike(routing.snapshot().packetEdges, [])
  } finally {
    await routing.destroy()
    await closeLiveAuthorityHarness(harness)
  }
})

function installNativeReconnectResponder(harness) {
  const topology = harness.topology
  const fixture = topology.guardFixture
  const record = topology.guardRecord
  const route = cryptoSuite.encryptionKeyPair(seed(218))
  const caps = new CapsResponder({
    now: topology.clock.wallNow,
    advertisement: record.canonicalBytes,
    identitySecretKey: fixture.links.b.secretKey,
    routeEncryptionSecretKey: route.secretKey
  })
  const deadline = Number(topology.clock.monotonicNow() + 10_000n)
  const rightAuthority = endpointModule.createBootstrapUdxAuthority({
    endpoint: fixture.right,
    configuredEndpoints: [{ host: '127.0.0.1', port: fixture.rightPort - 1 }],
    localSecretCapability: endpointModule.createLocalIdentitySecretCapability({
      localIdentity: fixture.links.b.publicKey,
      localSecretKey: fixture.links.b.secretKey
    }),
    maxProspectiveGuards: 1,
    monotonicDeadline: deadline
  })
  endpointModule.bindBootstrapUdxOperation(rightAuthority, deadline, Object.freeze({}))
  const capsModule = require('../../lib/private/caps-responder')
  const takeAcceptAuthority =
    capsModule[Symbol.for('hyperdht-private-routes/bootstrap-accept-authority-taker')]
  const createAcceptHandle =
    endpointModule[Symbol.for('hyperdht-private-routes/bootstrap-accept-handle-factory')]
  const createDynamicSetup =
    sessionModule[Symbol.for('hyperdht-private-routes/dynamic-responder-setup-factory')]
  const sessions = []
  let random = 0x51
  fixture.setRightBootstrapHandler(async (packet) => {
    if (((packet[0] << 8) | packet[1]) === 0xd301) {
      const bytes = (packet[2] << 8) | packet[3]
      const id = decodeM3Object(packet.subarray(4, 4 + bytes)).messageId
      const source = encodeCanonicalEndpoint({
        addressFamily: 4,
        addressBytes: b4a.from([127, 0, 0, 1]),
        port: fixture.rightPort - 1
      })
      const responses = caps.receive(packet, source)
      if (id === 4) {
        const handle = createAcceptHandle(takeAcceptAuthority(caps))
        const now = Number(topology.clock.monotonicNow())
        const wall = Number(topology.clock.wallNow())
        const authorizedExpiry = Number(record.expiresAt)
        const session = fixture.right.openLink(handle, {
          mode: 'accept',
          codec: new BootstrapEnvelopeCodec({
            linkHandle: handle,
            localIdentitySecretKey: fixture.links.b.secretKey,
            padding: (size) => b4a.alloc(size, random++)
          }),
          linkSetup: createLinkSetupAuthority({
            now: () => Number(topology.clock.wallNow()),
            randomBytes: (size) => b4a.alloc(size, random++)
          }),
          setup: createDynamicSetup({
            responderStaticSecretKey: route.secretKey,
            responderIdentitySecretKey: fixture.links.b.secretKey
          }),
          now: () => Number(topology.clock.monotonicNow()),
          schedule: setTimeout,
          cancel: clearTimeout,
          randomBytes: (size) => b4a.alloc(size, random++),
          absoluteDeadline: now + 5_000,
          signedExpiry: now + authorizedExpiry - wall,
          authorizedExpiry
        })
        sessions.push(session)
      }
      for (const response of responses) {
        await endpointModule.sendConfigured(rightAuthority, 0, response)
      }
      return
    }
    const session = sessions[sessions.length - 1]
    if (session) await session.receive(packet)
  })
  return async function close() {
    caps.destroy()
    endpointModule.destroyBootstrapUdxAuthority(rightAuthority)
    for (const session of sessions) await session.close()
  }
}

test('controller resumes through a native reconnect into fresh READY generations', async (t) => {
  const { harness, routing } = await controlledHarness(103, 48881)
  const closeResponder = installNativeReconnectResponder(harness)
  const generationHarnesses = []
  const observedManagers = []
  const revokeObserver = routeManagerFactoryIssuer.observe((manager) => {
    if (manager !== harness.manager) observedManagers.push(manager)
  })
  try {
    const stale = controllerIssuer.sinks(routing).guardLoss
    let prior = routing.snapshot()
    for (let cycle = 0; cycle < 2; cycle++) {
      t.is(await routing.suspend(), true)
      t.is(routing.snapshot().state, PRIVATE_ROUTING_STATE.SUSPENDED)
      let resumeSettled = false
      const resumed = routing.resume().finally(() => {
        resumeSettled = true
      })
      void resumed.catch(() => {})
      for (let attempt = 0; observedManagers.length <= cycle && attempt < 5_000; attempt++) {
        await new Promise((resolve) => setTimeout(resolve, 1))
      }
      if (observedManagers.length <= cycle) {
        throw new Error(`resume remained ${routing.snapshot().state}`)
      }
      t.is(routing.snapshot().state, PRIVATE_ROUTING_STATE.BUILDING)
      await Promise.resolve()
      t.is(resumeSettled, false)
      const fresh = await liveAuthorityHarness(null, {
        manager: observedManagers[cycle],
        topology: harness.topology
      })
      generationHarnesses.push(fresh)
      t.is(await resumed, true)
      const current = routing.snapshot()
      t.is(current.state, PRIVATE_ROUTING_STATE.READY)
      t.ok(current.lookupGeneration > prior.lookupGeneration)
      t.ok(current.announceGeneration > prior.announceGeneration)
      t.is(current.transportDHT, true)
      t.is(current.routedDHTIO, true)
      prior = current
    }
    t.is(
      await code(Promise.resolve().then(() => controllerIssuer.issue(routing, stale))),
      'ERR_REPLAY'
    )
    const fresh = generationHarnesses[generationHarnesses.length - 1]
    const value = b4a.from('resumed-native-controller-value')
    const target = cryptoSuite.hash([value])
    const upstream = pumpDirectValue(fresh, value)
    const result = await routing.immutableGet(target)
    await upstream
    t.alike(result.value, value)
    const firstDestroy = routing.destroy()
    t.is(routing.destroy(), firstDestroy)
    await firstDestroy
    const zero = routing.snapshot()
    t.is(zero.state, PRIVATE_ROUTING_STATE.DESTROYED)
    t.is(zero.endpointSockets, 0)
    t.is(zero.handles, 0)
    t.is(zero.queues, 0)
    t.is(zero.tables, 0)
    t.is(zero.callbacks, 0)
    t.is(zero.timers, 0)
    t.is(zero.secretBytes, 0)
  } finally {
    revokeObserver()
    await routing.destroy()
    await closeResponder()
    for (const fresh of generationHarnesses) await closeLiveAuthorityHarness(fresh)
    await closeLiveAuthorityHarness(harness)
  }
})

test('suspend retains only reconnect and emits no routed packets', async (t) => {
  const { harness, routing } = await controlledHarness(101, 48861)
  try {
    const before = harness.fakeSocket.sends.length
    const firstSuspend = routing.suspend()
    const secondSuspend = routing.suspend()
    t.is(firstSuspend, secondSuspend)
    t.is(await firstSuspend, true)
    t.is(routing.snapshot().state, PRIVATE_ROUTING_STATE.SUSPENDED)
    t.is(routing.snapshot().activeQueries, 0)
    t.is(routing.snapshot().transportDHT, false)
    t.is(routing.snapshot().routedDHTIO, false)
    t.is(routing.snapshot().routeManager, false)
    t.is(routing.snapshot().guardLease, false)
    t.is(routing.snapshot().reconnect, true)
    t.is(await code(routing.immutableGet(seed(102))), 'ERR_PRIVACY_UNAVAILABLE')
    t.is(harness.fakeSocket.sends.length, before)
    const firstDestroy = routing.destroy()
    const secondDestroy = routing.destroy()
    t.is(firstDestroy, secondDestroy)
    await firstDestroy
    t.alike(routing.snapshot(), {
      state: PRIVATE_ROUTING_STATE.DESTROYED,
      generation: routing.snapshot().generation,
      endpointAuthority: 'none',
      packetEdges: [],
      lookupGeneration: null,
      announceGeneration: null,
      activeQueries: 0,
      transportDHT: false,
      routedDHTIO: false,
      liveRouteAuthority: false,
      routeManager: false,
      guardLease: false,
      reconnect: false,
      endpointSockets: 0,
      handles: 0,
      queues: 0,
      tables: 0,
      callbacks: 0,
      timers: 0,
      secretBytes: 0
    })
  } finally {
    await routing.destroy()
    await closeLiveAuthorityHarness(harness)
  }
})

const HOSTED_TAIL_READY_DOMAIN = b4a.from('hyperdht-private-routes/m3/tail-ready/v1')

function hostedWriteU16(target, value, offset) {
  target[offset] = value >>> 8
  target[offset + 1] = value
}

function hostedWriteU32(target, value, offset) {
  target[offset] = value >>> 24
  target[offset + 1] = value >>> 16
  target[offset + 2] = value >>> 8
  target[offset + 3] = value
}

function hostedWriteU64(target, value, offset) {
  for (let index = 7; index >= 0; index--) {
    target[offset + index] = Number(value & 0xffn)
    value >>= 8n
  }
}

function hostedTailEnvelope(encoded) {
  const frame = b4a.alloc(1100)
  frame.set(encoded)
  return require('../../lib/private/m3-context').encodeM3ContextEnvelope({
    contextClass: CONTEXT_CLASS.TAIL_CONTROL_ORDERED,
    frame
  })
}

function hostedTailReady(extended, request, signer, transcriptDigest, expiresAtMs) {
  const body = b4a.alloc(210)
  body[0] = extended.branchClass
  body.set(extended.branchId, 1)
  body.set(extended.circuitId, 17)
  hostedWriteU64(body, extended.generation, 33)
  body[41] = extended.extensionIndex
  body.set(transcriptDigest, 42)
  body.set(signer.publicKey, 74)
  body.set(extended.responderAdvertisementDigest, 106)
  body.set(request.clientNonce, 138)
  body.set(b4a.alloc(32, 0x7a), 170)
  hostedWriteU64(body, expiresAtMs, 202)
  const input = b4a.alloc(10 + HOSTED_TAIL_READY_DOMAIN.byteLength + body.byteLength)
  hostedWriteU16(input, HOSTED_TAIL_READY_DOMAIN.byteLength, 0)
  input.set(HOSTED_TAIL_READY_DOMAIN, 2)
  hostedWriteU32(input, 1, 2 + HOSTED_TAIL_READY_DOMAIN.byteLength)
  hostedWriteU16(input, M3_MESSAGE_ID.TAIL_READY_V1, 6 + HOSTED_TAIL_READY_DOMAIN.byteLength)
  hostedWriteU16(input, body.byteLength, 8 + HOSTED_TAIL_READY_DOMAIN.byteLength)
  input.set(body, 10 + HOSTED_TAIL_READY_DOMAIN.byteLength)
  return encodeM3Object({
    messageId: M3_MESSAGE_ID.TAIL_READY_V1,
    body,
    authSuffix: cryptoSuite.sign(input, signer.secretKey)
  })
}

async function answerHostedMiddle(tail, records, wallNow, monotonicNow) {
  const authority = createTailControlResponderAuthority(tail, records.responderToken, {
    adjacencyAdopter: Object.freeze({}),
    extensionCommitter: Object.freeze({}),
    adjacentLinkFactory: Object.freeze({}),
    tailReadySigner: Object.freeze({}),
    wallNow,
    monotonicNow,
    randomBytes: (size) => b4a.alloc(size, 0x73),
    schedule: setTimeout,
    cancelScheduled: clearTimeout
  })
  try {
    const transport = borrowTailControlTransport(tail)
    for (let hop = 0; hop < 2; hop++) {
      const admitted = admitTailExtend(authority, await transport.receive())
      const taken = takeAdmittedExtendRequest(admitted)
      const request = taken.request
      const index = records.values.findIndex((record) =>
        b4a.equals(record.canonicalBytes, request.advertisement)
      )
      const signer =
        index === 1
          ? identityFor(ROLE.SAFETY, 1)
          : index === 2
            ? identityFor(ROLE.SAFETY, 2)
            : index === 3
              ? identityFor(ROLE.PRIVATE, 0)
              : identityFor(ROLE.PRIVATE, 1)
      const responderAdvertisementDigest = digestRelayCapabilityAdvertisement(
        request.advertisement,
        {
          now: wallNow()
        }
      )
      const expiresAtMs = request.requestedLimits.expiresAtMs
      const proof = signRedactedResponderProof(
        {
          responderAdvertisementDigest,
          initiatorIdentity: taken.currentTailIdentity,
          responderIdentity: signer.publicKey,
          branchClass: request.branchClass,
          branchId: request.branchId,
          circuitId: request.circuitId,
          generation: request.generation,
          extensionIndex: request.extensionIndex,
          clientTailEphemeralPublicKey: request.clientTailEphemeralPublicKey,
          clientNonce: request.clientNonce,
          advertisedRouteEncryptionPublicKey:
            require('../../lib/private/relay-capability').decodeRelayCapabilityAdvertisement(
              request.advertisement,
              { now: wallNow() }
            ).routeEncryptionPublicKey,
          admittedLimitsDigest: digestAdmittedLimits(request.requestedLimits),
          expiresAtMs,
          responderProofNonce: b4a.alloc(32, 0x74 + hop)
        },
        signer.secretKey
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
      await transport.send(hostedTailEnvelope(encodeExtended(extended)))
      await transport.send(
        hostedTailEnvelope(
          hostedTailReady(
            extended,
            request,
            signer,
            readTailControlTranscriptDigest(tail),
            expiresAtMs
          )
        )
      )
      records.extensionsAnswered = hop + 1
      records.middleAnswered = true
      records.exitAnswered = hop === 1
    }
  } finally {
    destroyTailControlResponderAuthority(authority)
  }
}
class HostedDhtSocket {
  constructor(value) {
    this.sends = []
    this.messageHandler = null
    this.value = value
  }
  bind() {}
  on(name, handler) {
    if (name === 'message') this.messageHandler = handler
  }
  send(packet, port, host) {
    this.sends.push({ packet: b4a.from(packet), port, host })
    if (this.sends.length > 1) {
      const suffix = b4a.concat([b4a.from([this.value.byteLength]), this.value])
      Promise.resolve().then(() =>
        this.message(dhtResponseFor(packet, 0x10, suffix), { host, port })
      )
    }
    return true
  }
  message(packet, from) {
    this.messageHandler(packet, from)
  }
  close() {}
}

function hostedDhtResponse(packet) {
  const response = b4a.alloc(10)
  response[0] = 0x13
  response[1] = 0
  response[2] = packet[2]
  response[3] = packet[3]
  response.set([10, 1, 2, 3, 0x12, 0xa1], 4)
  return response
}

async function waitHosted(check) {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (check()) return
    await Promise.resolve()
  }
  throw new Error('hosted DHT condition was not reached')
}

async function waitHostedTimer(check, timeout = 20_000) {
  const deadline = Date.now() + timeout
  while (Date.now() < deadline) {
    if (check()) return
    await new Promise((resolve) => setTimeout(resolve, 1))
  }
  throw new Error('hosted lifecycle condition was not reached')
}

async function driveHostedFinal(exit, exitRecords, wallNow, monotonicNow, immutableValue) {
  const record = exitRecords.find((value) => b4a.equals(value.identity, exit.identity.publicKey))
  if (!record) throw new Error('terminal exit identity has no signed advertisement')
  const handoff = exit.tail.takeFinalExitHandoff()
  const claim = createFinalExitActivationClaim(handoff)
  const activationOwner = claimFinalExitActivation(handoff, claim)
  const factory = createFinalExitActivationFactory({
    wallNow,
    monotonicNow,
    randomBytes: (size) => b4a.alloc(size, 0xef),
    schedule: setTimeout,
    cancelScheduled: clearTimeout
  })
  const responder = openFinalExit(factory, {
    handoff: activationOwner,
    crypto: cryptoSuite,
    payloadParameters: decodeRelayCapabilityAdvertisement(record.canonicalBytes),
    readySigner: createDhtExitReadySigner(exit.identityOwner)
  })
  const authority = await driveDhtExitFinalExit(responder)
  const channel = createDhtExitReservationChannel(authority)
  const table = createDhtExitDestinationTable(channel.tableIssuer, {
    local: { host: '10.1.2.3', port: 41234 },
    configuredBootstrap: [{ host: '8.8.8.8', port: 49737 }],
    monotonicNow,
    randomBytes: (size) => b4a.alloc(size, 0xf0)
  })
  const socket = new HostedDhtSocket(immutableValue)
  const replies = []
  const io = createDhtExitIOForTest(
    {
      host: '10.1.2.3',
      port: 41234,
      monotonicNow,
      schedule: setTimeout,
      cancelScheduled: clearTimeout,
      onReply(replyAuthority) {
        replies.push(replyAuthority)
      }
    },
    TEST_ONLY_DHT_EXIT_SOCKET_ISSUER.create(() => socket),
    consumeDhtExitReservationIOConsumer(channel.ioConsumer)
  )
  const probe = reserveConfiguredBootstrapProbe(table, 0, monotonicNow() + 1_000n)
  sendReservedExitDhtPacket(io, probe.sendAuthority)
  socket.message(hostedDhtResponse(socket.sends[0].packet), { host: '8.8.8.8', port: 49737 })
  await waitHosted(() => replies.length === 1)
  settleExitDhtReservation(probe.settlementAuthority, replies.shift())
  installDhtExitRoute(io, table)
  await sendDhtExitSeeds(
    io,
    createDhtExitSeedsDeliveryAuthority(table),
    b4a.alloc(32, exit.identity.publicKey[0]),
    exit.identity.secretKey
  )
  return { authority, responder, activationOwner, table, io, socket }
}

test('public start hosts both native branches, reaches READY, and returns exact immutable value', async (t) => {
  const leftPort = 48991
  const hostedImmutableValue = b4a.from('hosted-public-controller-immutable-value')
  const hostedImmutableTarget = cryptoSuite.hash([hostedImmutableValue])
  const rightPort = 48992
  const { monotonicNow, wallNow } = createCoherentTestClock()
  const guardIdentity = identityFor(ROLE.SAFETY, 90)
  const guardRoute = cryptoSuite.encryptionKeyPair(seed(218))
  const middleIdentities = [
    identityFor(ROLE.SAFETY, 1),
    identityFor(ROLE.SAFETY, 2),
    identityFor(ROLE.SAFETY, 3)
  ]
  const exitIdentities = [
    identityFor(ROLE.PRIVATE, 0),
    identityFor(ROLE.PRIVATE, 1),
    identityFor(ROLE.PRIVATE, 2)
  ]
  const guardPairs = await Promise.all(
    middleIdentities.map((identity) => nativeAdjacentPair(guardIdentity, identity))
  )
  const exitPairs = await Promise.all(
    middleIdentities.map((identity, index) =>
      nativeAdjacentPair(identity, exitIdentities[index], TOPOLOGY_ROLE.SAFETY_FINAL)
    )
  )
  const guard = candidate(ROLE.SAFETY, 90, 90, {
    endpointBytes: canonicalEndpointForHost('127.0.0.1', rightPort),
    identityPair: guardIdentity,
    validationNow: wallNow(),
    issuedAtMs: wallNow() - 1_000n,
    expiresAtMs: wallNow() + 60_000n
  })
  const liveRecord = () => ({
    validationNow: wallNow(),
    issuedAtMs: wallNow() - 1_000n,
    expiresAtMs: wallNow() + 60_000n
  })
  const middleRecords = middleIdentities.map((identity, index) =>
    candidate(ROLE.SAFETY, index + 1, index + 2, { ...liveRecord(), identityPair: identity })
  )
  const exitRecords = exitIdentities.map((identity, index) =>
    candidate(ROLE.PRIVATE, index, index + 40, { ...liveRecord(), identityPair: identity })
  )
  const records = [guard, ...middleRecords, ...exitRecords]
  let rightAuthority = null
  let rightSession = null
  let random = 0x31
  const hostedResponse = {
    branches: 0,
    middles: 0,
    exits: 0,
    finals: 0,
    middleAnswered: false,
    exitAnswered: false
  }
  let hostedMiddleError = null
  const hostedMiddlePromises = []
  const rightFailures = []
  let rightCells = 0
  const rightUnhandled = []
  let guardRegistered = false
  const guardResources = []
  const hostedResources = []
  const finalResources = []
  const middleSigningOwners = middleIdentities.map((identity) =>
    createRelayIdentitySigningAuthority({ identitySecretKey: identity.secretKey })
  )
  const exitSigningOwners = exitIdentities.map((identity) =>
    createRelayIdentitySigningAuthority({ identitySecretKey: identity.secretKey })
  )
  const exitTargets = exitRecords.map((record, index) => ({
    advertisement: record.canonicalBytes,
    endpoint: record.canonicalEndpointBytes,
    identity: exitIdentities[index],
    identityOwner: exitSigningOwners[index],
    route: cryptoSuite.encryptionKeyPair(seed(168 + index)),
    pair: exitPairs[index],
    predecessorEndpoint: exitPairs[index].predecessorEndpoint,
    next: null
  }))
  const middleTargets = middleRecords.map((record, index) => ({
    advertisement: record.canonicalBytes,
    endpoint: record.canonicalEndpointBytes,
    identity: middleIdentities[index],
    identityOwner: middleSigningOwners[index],
    route: cryptoSuite.encryptionKeyPair(seed(130 + index)),
    pair: guardPairs[index],
    predecessorEndpoint: guardPairs[index].predecessorEndpoint,
    next: {
      pair: Object.freeze({ destroy() {} }),
      role: ROLE.PRIVATE,
      resolveEndpoint(endpoint) {
        const target = exitTargets.find((value) => b4a.equals(value.endpoint, endpoint))
        if (!target) throw new Error('selected exit has no hosted target')
        return target
      }
    }
  }))
  const guardPlan = {
    pair: Object.freeze({ destroy() {} }),
    role: ROLE.SAFETY,
    resolveEndpoint(endpoint) {
      const target = middleTargets.find((value) => b4a.equals(value.endpoint, endpoint))
      if (!target) throw new Error('selected middle has no hosted target')
      return target
    }
  }
  const sessions = []
  const caps = new CapsResponder({
    now: wallNow,
    advertisement: guard.canonicalBytes,
    identitySecretKey: guardIdentity.secretKey,
    routeEncryptionSecretKey: guardRoute.secretKey,
    selectAdvertisements: () => records.map((record) => record.canonicalBytes)
  })
  const right = new endpointModule.UdxCellEndpoint({
    host: '127.0.0.1',
    port: rightPort,
    async onBootstrap(packet) {
      if (((packet[0] << 8) | packet[1]) === 0xd301) {
        const bytes = (packet[2] << 8) | packet[3]
        const id = decodeM3Object(packet.subarray(4, 4 + bytes)).messageId
        const source = encodeCanonicalEndpoint({
          addressFamily: 4,
          addressBytes: b4a.from([127, 0, 0, 1]),
          port: leftPort
        })
        const responses = caps.receive(packet, source)
        if (id === 4) {
          const capsModule = require('../../lib/private/caps-responder')
          const takeAccept =
            capsModule[Symbol.for('hyperdht-private-routes/bootstrap-accept-authority-taker')]
          const createAcceptHandle =
            endpointModule[Symbol.for('hyperdht-private-routes/bootstrap-accept-handle-factory')]
          const createDynamicSetup =
            sessionModule[Symbol.for('hyperdht-private-routes/dynamic-responder-setup-factory')]
          const handle = createAcceptHandle(takeAccept(caps))
          const now = Number(monotonicNow())
          rightSession = right.openLink(handle, {
            mode: 'accept',
            codec: new BootstrapEnvelopeCodec({
              linkHandle: handle,
              localIdentitySecretKey: guardIdentity.secretKey,
              padding: (size) => b4a.alloc(size, random++)
            }),
            linkSetup: createLinkSetupAuthority({
              now: () => Number(wallNow()),
              randomBytes: (size) => b4a.alloc(size, random++)
            }),
            setup: createDynamicSetup({
              responderStaticSecretKey: guardRoute.secretKey,
              responderIdentitySecretKey: guardIdentity.secretKey
            }),
            now: () => Number(monotonicNow()),
            schedule: setTimeout,
            cancel: clearTimeout,
            randomBytes: (size) => b4a.alloc(size, random++),
            absoluteDeadline: now + 30_000,
            signedExpiry: now + 60_000,
            authorizedExpiry: Number(wallNow() + 60_000n)
          })
          sessions.push(rightSession)
        }
        for (const response of responses) {
          await endpointModule.sendConfigured(rightAuthority, 0, response)
        }
        return
      }
      if (rightSession) await rightSession.receive(packet)
      if (rightSession && rightSession.established && !guardRegistered) {
        guardRegistered = true
        const established = rightSession.established
        t.exception(
          () =>
            endpointModule.registerSharedGuardBranchResponder(
              established.handle,
              Object.freeze({ accept() {} })
            ),
          'raw link handle cannot claim the established responder capability'
        )
        endpointModule.registerSharedGuardBranchResponder(
          established,
          Object.freeze({
            accept({ offer, physicalChannel }) {
              const responder = createIndexZeroGuardLinkResponder({
                advertisement: guard.canonicalBytes,
                responderIdentitySecretKey: guardIdentity.secretKey,
                responderRouteEncryptionSecretKey: guardRoute.secretKey,
                now: wallNow,
                receiveOffer: () =>
                  Object.freeze({
                    offer,
                    observedPredecessorEndpoint: canonicalEndpointForHost('127.0.0.1', leftPort),
                    physicalChannel
                  }),
                randomBytes: (size) => b4a.alloc(size, random++)
              })
              const accepted = responder.accept()
              const authority = new M3AdjacencyAuthority({
                wallNow,
                monotonicNow,
                schedule: setTimeout,
                cancelScheduled: clearTimeout,
                crypto: cryptoSuite
              })
              const adopted = authority.adopt(accepted.established)
              let hosted
              try {
                hosted = createHostedTailResponder({
                  adjacency: adopted,
                  adjacencyAuthority: authority,
                  identity: guardIdentity,
                  clocks: {
                    wallNow,
                    monotonicNow,
                    schedule: setTimeout,
                    cancelScheduled: clearTimeout
                  },
                  plan: guardPlan,
                  resources: hostedResources
                })
              } catch (err) {
                hostedMiddleError = err
                throw err
              }
              guardResources.push({ authority, runtime: adopted.runtime, tail: null })
              hostedResponse.branches++
              const hostedMiddlePromise = hosted
                .serve()
                .then((middle) => {
                  hostedResponse.middles++
                  hostedResponse.middleAnswered = true
                  return middle.serve()
                })
                .then(async (exit) => {
                  hostedResponse.exits++
                  hostedResponse.exitAnswered = true
                  const final = await driveHostedFinal(
                    exit,
                    exitRecords,
                    wallNow,
                    monotonicNow,
                    hostedImmutableValue
                  )
                  finalResources.push(final)
                  hostedResponse.finals++
                  return final
                })
                .catch((err) => {
                  hostedMiddleError = err
                })
              hostedMiddlePromises.push(hostedMiddlePromise)
              return accepted.accept
            }
          })
        )
      }
    },
    onCell(payload, handle, metadata) {
      let messageId = null
      let decodeError = null
      try {
        messageId = decodeM3Object(payload).messageId
      } catch (err) {
        decodeError = err && err.code
      }
      rightUnhandled.push({ messageId, decodeError, generation: String(metadata.generation) })
      return true
    },
    onLinkFailure(handle, direction, reason) {
      rightFailures.push({ direction, reason })
    }
  })
  await right.bind()
  const rightDeadline = Number(monotonicNow() + 30_000n)
  rightAuthority = endpointModule.createBootstrapUdxAuthority({
    endpoint: right,
    configuredEndpoints: [{ host: '127.0.0.1', port: leftPort }],
    localSecretCapability: endpointModule.createLocalIdentitySecretCapability({
      localIdentity: guardIdentity.publicKey,
      localSecretKey: guardIdentity.secretKey
    }),
    maxProspectiveGuards: 1,
    monotonicDeadline: rightDeadline
  })
  endpointModule.bindBootstrapUdxOperation(rightAuthority, rightDeadline, Object.freeze({}))
  const local = cryptoSuite.keyPair(seed(0x29))
  const routing = createPrivateRoutingController({
    endpointBootstrapAuthority: createEndpointBootstrapAuthority({
      bootstrapEndpoints: [{ host: '127.0.0.1', port: rightPort }],
      localIdentity: local.publicKey,
      localSecretKey: local.secretKey,
      host: '127.0.0.1',
      port: leftPort,
      wallNow,
      monotonicNow,
      schedule: setTimeout,
      cancelScheduled: clearTimeout,
      randomBytes: (size) => b4a.alloc(size, random++)
    })
  })
  try {
    const seen = []
    let settled = false
    const starting = routing
      .start()
      .then(
        () => null,
        (err) => err
      )
      .finally(() => {
        settled = true
      })
    while (!settled) {
      const current = routing.snapshot().state
      if (seen[seen.length - 1] !== current) seen.push(current)
      await new Promise((resolve) => setTimeout(resolve, 1))
    }
    const publicStartError = await starting
    if (hostedResponse.branches === 0) {
      throw (
        hostedMiddleError ||
        publicStartError ||
        new Error(
          `public start failed before branch service activity; cells: ${rightCells}, unhandled: ${JSON.stringify(rightUnhandled)}, guard failures: ${JSON.stringify(rightFailures)}, states: ${seen.join(' -> ')}`
        )
      )
    }
    if (hostedResponse.finals !== 2) {
      await Promise.race([
        Promise.all(hostedMiddlePromises),
        new Promise((resolve) => setTimeout(resolve, 100))
      ])
      throw (
        hostedMiddleError ||
        publicStartError ||
        new Error(
          `hosted branches=${hostedResponse.branches} middles=${hostedResponse.middles} exits=${hostedResponse.exits} finals=${hostedResponse.finals}`
        )
      )
    }
    if (publicStartError) throw publicStartError
    t.is(publicStartError, null)
    t.is(guardRegistered, true)
    t.is(routing.snapshot().state, PRIVATE_ROUTING_STATE.READY)
    const immutable = await routing.immutableGet(hostedImmutableTarget)
    t.alike(immutable.value, hostedImmutableValue)
    const initialGeneration = routing.snapshot()
    const lookupMiddle = hostedResources[1]
    // Close the link belonging to the exit actually on this branch. Indexing
    // exitPairs by the middle's index happens to work today, because first-match
    // selection pairs middle i with exit i, but that is a coincidence of record
    // order rather than a guarantee; see KI-6. Look the exit up by identity.
    const lookupExit = hostedResources[2]
    const lookupExitIndex = exitIdentities.findIndex((identity) =>
      b4a.equals(identity.publicKey, lookupExit.identity.publicKey)
    )
    t.ok(lookupExitIndex >= 0, 'lookup exit has a native downstream link')
    await exitPairs[lookupExitIndex].closeLink()
    await waitHostedTimer(() => lookupMiddle.forwarding.diagnostics().state === 'DESTROYED', 1_000)
    t.is(lookupMiddle.forwarding.diagnostics().state, 'DESTROYED')
    const lookupGuard = hostedResources[0]
    await waitHostedTimer(() => lookupGuard.forwarding.diagnostics().state === 'DESTROYED', 1_000)
    t.is(lookupGuard.forwarding.diagnostics().state, 'DESTROYED')
    await waitHostedTimer(() => routing.snapshot().state === PRIVATE_ROUTING_STATE.ROTATING, 1_000)
    const rotatingLookup = routing.snapshot()
    t.is(rotatingLookup.guardLease, true)
    t.is(rotatingLookup.announceGeneration, initialGeneration.announceGeneration)
    t.is(await code(routing.immutableGet(hostedImmutableTarget)), 'ERR_PRIVATE_BRANCH_ROTATING')
    await waitHostedTimer(() => {
      const state = routing.snapshot().state
      return state === PRIVATE_ROUTING_STATE.READY || state === PRIVATE_ROUTING_STATE.UNAVAILABLE
    })
    if (routing.snapshot().state !== PRIVATE_ROUTING_STATE.READY) {
      throw (
        hostedMiddleError ||
        new Error(
          `hosted rotation failed: branches=${hostedResponse.branches} middles=${hostedResponse.middles} exits=${hostedResponse.exits} finals=${hostedResponse.finals}`
        )
      )
    }
    const rotatedGeneration = routing.snapshot()
    t.is(rotatedGeneration.lookupGeneration, initialGeneration.lookupGeneration + 1n)
    t.is(rotatedGeneration.announceGeneration, initialGeneration.announceGeneration)
    t.is(hostedResponse.finals, 3)
    const rotatedImmutable = await routing.immutableGet(hostedImmutableTarget)
    t.alike(rotatedImmutable.value, hostedImmutableValue)
    t.is(rotatedGeneration.guardLease, true)
    const announceExit = hostedResources[5]
    const announceExitIndex = exitIdentities.findIndex((identity) =>
      b4a.equals(identity.publicKey, announceExit.identity.publicKey)
    )
    t.ok(announceExitIndex >= 0, 'announce exit has a native downstream link')
    await exitPairs[announceExitIndex].closeLink()
    await waitHostedTimer(() => routing.snapshot().state === PRIVATE_ROUTING_STATE.ROTATING, 1_000)
    const rotatingAnnounce = routing.snapshot()
    t.is(rotatingAnnounce.guardLease, true)
    t.is(rotatingAnnounce.lookupGeneration, rotatedGeneration.lookupGeneration)
    await waitHostedTimer(() => {
      const state = routing.snapshot().state
      return state === PRIVATE_ROUTING_STATE.READY || state === PRIVATE_ROUTING_STATE.UNAVAILABLE
    })
    if (routing.snapshot().state === PRIVATE_ROUTING_STATE.READY) {
      const announceRotatedGeneration = routing.snapshot()
      t.is(announceRotatedGeneration.announceGeneration, rotatedGeneration.announceGeneration + 1n)
      t.is(announceRotatedGeneration.lookupGeneration, rotatedGeneration.lookupGeneration)
      t.is(announceRotatedGeneration.guardLease, true)
      t.is(hostedResponse.finals, 4)
      const afterAnnounceRotation = await routing.immutableGet(hostedImmutableTarget)
      t.alike(afterAnnounceRotation.value, hostedImmutableValue)
    } else {
      t.is(routing.snapshot().state, PRIVATE_ROUTING_STATE.UNAVAILABLE)
    }
    await rightSession.close()
    await waitHostedTimer(() => routing.snapshot().state === PRIVATE_ROUTING_STATE.UNAVAILABLE)
    t.is(routing.snapshot().state, PRIVATE_ROUTING_STATE.UNAVAILABLE)
  } finally {
    await routing.destroy()
    for (const final of finalResources) {
      try {
        await closeDhtExitIO(final.io)
      } catch {}
      try {
        destroyDhtExitDestinationTable(final.table)
      } catch {}
      try {
        final.responder.destroy()
      } catch {}
    }
    caps.destroy()
    endpointModule.destroyBootstrapUdxAuthority(rightAuthority)
    for (const resource of hostedResources) resource.destroy()
    for (const resource of guardResources) {
      if (resource.tail) destroyTailControlSession(resource.tail)
      try {
        resource.runtime.destroy()
      } catch {}
    }
    await Promise.allSettled([
      ...guardPairs.map((pair) => pair.destroy()),
      ...exitPairs.map((pair) => pair.destroy()),
      ...sessions.map((session) => session.close()),
      right.close()
    ])
  }
})

test('public start enters UNAVAILABLE when the hosted guard service is absent', async (t) => {
  const identity = cryptoSuite.keyPair(seed(0xf8))
  const routing = createPrivateRoutingController({
    endpointBootstrapAuthority: createEndpointBootstrapAuthority({
      bootstrapEndpoints: [{ host: '127.0.0.1', port: 48999 }],
      localIdentity: identity.publicKey,
      localSecretKey: identity.secretKey,
      host: '127.0.0.1',
      port: 48998,
      ...createCoherentTestClock(),
      schedule: setTimeout,
      cancelScheduled: clearTimeout,
      randomBytes: (size) => b4a.alloc(size, 0xf9)
    })
  })
  try {
    const error = await routing.start().then(
      () => null,
      (err) => err
    )
    t.is(error && error.code, 'ERR_PRIVATE_GUARD_UNAVAILABLE')
    t.is(routing.snapshot().state, PRIVATE_ROUTING_STATE.UNAVAILABLE)
  } finally {
    await routing.destroy()
  }
})
