'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { fragment, Reassembler } = require('../../lib/private/fragments')
const { encodeImmutableGetResponse } = require('../../lib/private/dht-exit-wire')
const {
  ROUTE_ENDPOINT,
  RoutePayloadCodec,
  mintCreatedRoutePayloadContext
} = require('../../lib/private/route-payload')
const {
  LiveRouteAuthority,
  bindOpenRouteTransport,
  createLiveRouteReferralAuthority,
  destroyOpenRouteTransport,
  issueLiveRouteDestination,
  receiveOpenRouteSeedPayload,
  snapshotLiveRouteDestination
} = require('../../lib/private/live-route-authority')
const {
  TEST_ONLY_ROUTE_MANAGER_OBSERVER,
  createFinalExitActivationFactory,
  createRouteExtensionFactory,
  createRouteManager
} = require('../../lib/private/route-manager')
const {
  candidate,
  liveTopologyFixture,
  NOW,
  routeClock: topologyRouteClock
} = require('./live-topology-fixture')
const finalExitActivation = require('../../lib/private/final-exit-activation')
const {
  DatagramReplayWindow,
  OrderedReceiver,
  SenderCounter
} = require('../../lib/private/counters')
const { encodeDestinationRef } = require('../../lib/private/destination-ref')
const opaqueDestination = require('../../lib/private/opaque-destination')
const {
  clearRoutedReply,
  clearRoutedRequest,
  decodeRoutedRequest,
  commitRoutedReplyAdmission,
  encodeRoutedReply,
  encodeRoutedRequest,
  validateRoutedReplyForRequest
} = require('../../lib/private/routed-dht')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const guardLinks = require('../../lib/private/guard-link')
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
  BRANCH_CLASS,
  CELL_CLASS,
  DIRECTION,
  M3_MESSAGE_ID,
  ROLE
} = require('../../lib/private/protocol')

const TEST_ONLY_AUTHENTICATED_REPLY_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-authenticated-reply-issuer'
)
const TEST_ONLY_BRANCH_SEED_READY_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-branch-seed-ready-issuer'
)
const TEST_ONLY_ENDPOINT_DHT_EXIT_OPEN_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-endpoint-dht-exit-open-issuer'
)

function expectCode(t, operation, code) {
  let error = null
  try {
    operation()
  } catch (err) {
    error = err
  }
  t.is(error && error.code, code)
}

function replyAuthorityFixture(seed = 0x21) {
  const branchId = b4a.alloc(16, seed)
  const circuitId = b4a.alloc(16, seed + 1)
  const finalTranscriptDigest = b4a.alloc(32, seed + 2)
  const requestId = b4a.alloc(16, seed + 3)
  const target = b4a.alloc(32, seed + 4)
  const id = b4a.alloc(32, seed + 5)
  const destinationRef = encodeDestinationRef({
    id,
    handle: b4a.alloc(130, seed + 6)
  })
  const owner = opaqueDestination.createLiveOpaqueDestinations({
    branch: BRANCH_CLASS.LOOKUP,
    circuitId,
    generation: 7n,
    expiresAt: 10_000n,
    wallNow: () => 1_000n,
    monotonicNow: () => 1_000n
  })
  const issuer = opaqueDestination[TEST_ONLY_AUTHENTICATED_REPLY_ISSUER]
  issuer.bindOwner(owner, { branchId, finalTranscriptDigest })
  const from = opaqueDestination.issueLiveOpaqueDestination(owner, { id, destinationRef })
  const referralAuthority = opaqueDestination.createRoutedReplyReferralAuthority(owner, {
    from,
    target,
    requestId,
    deadline: 4_000n
  })
  const encodedRequest = encodeRoutedRequest({
    requestId,
    operationClass: BRANCH_CLASS.LOOKUP,
    commandId: M3_MESSAGE_ID.IMMUTABLE_GET_V1,
    absoluteDeadlineMs: 4_000n,
    destination: destinationRef,
    encodedBody: target
  })
  const encodedReply = encodeRoutedReply({
    requestId,
    commandId: M3_MESSAGE_ID.IMMUTABLE_GET_V1,
    commandVersion: 1,
    operationClass: BRANCH_CLASS.LOOKUP,
    from: destinationRef,
    errorCode: 0,
    token: b4a.alloc(0),
    closerNodes: [],
    encodedResponse: b4a.alloc(0)
  })
  const authenticatedReplyAuthority = issuer.create(owner, {
    branch: BRANCH_CLASS.LOOKUP,
    branchId,
    circuitId,
    generation: 7n,
    finalTranscriptDigest,
    requestId,
    fromEncoded: destinationRef,
    deadline: 4_000n,
    encodedReply
  })
  return {
    owner,
    from,
    branchId,
    circuitId,
    finalTranscriptDigest,
    requestId,
    target,
    destinationRef,
    referralAuthority,
    encodedRequest,
    encodedReply,
    authenticatedReplyAuthority
  }
}
const TEST_ONLY_M3_ESTABLISHED_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-m3-established-issuer'
)

function routeClock() {
  return {
    wallNow: () => 1_000n,
    monotonicNow: () => 10_000n,
    schedule: () => Object.freeze({}),
    cancelScheduled() {}
  }
}

function routeCellContexts(initiator) {
  const contexts = {}
  for (const cellClass of [CELL_CLASS.CONTROL, CELL_CLASS.STREAM, CELL_CLASS.DATAGRAM]) {
    const forwardKey = b4a.alloc(32, 0x10 + cellClass)
    const reverseKey = b4a.alloc(32, 0x20 + cellClass)
    const forwardNonce = b4a.alloc(16, 0x30 + cellClass)
    const reverseNonce = b4a.alloc(16, 0x40 + cellClass)
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
            : new OrderedReceiver({
                window: 256,
                gapTimeout: 5_000,
                now: () => 1_000
              })
      }
    }
  }
  return contexts
}

function channelPair(edges) {
  const queues = [[], []]
  const waiters = [[], []]
  const channels = [0, 1].map((side) => ({
    send(packet) {
      const peer = side ^ 1
      edges.push(side === 0 ? 'endpoint>guard' : 'guard>endpoint')
      if (waiters[peer].length > 0) waiters[peer].shift()(b4a.from(packet))
      else queues[peer].push(b4a.from(packet))
      return true
    },
    receive() {
      if (queues[side].length > 0) return Promise.resolve(queues[side].shift())
      return new Promise((resolve) => waiters[side].push(resolve))
    },
    destroy() {}
  }))
  return channels
}

function routeTransportPair(edges = [], binding = {}, clock = routeClock()) {
  const channels = channelPair(edges)
  const digest = b4a.alloc(32, 0x71)
  const ids = deriveM3CellIds(digest, { crypto: cryptoSuite })
  const branchId = binding.branchId || b4a.alloc(16, 0x72)
  const circuitId = binding.circuitId || b4a.alloc(16, 0x73)
  const branchClass = binding.branchClass === undefined ? BRANCH_CLASS.LOOKUP : binding.branchClass
  const generation = binding.generation === undefined ? 7n : binding.generation
  const endpointIdentity = b4a.alloc(32, 0x51)
  const guardIdentity = b4a.alloc(32, 0x52)
  const authority = new M3AdjacencyAuthority({
    ...clock,
    crypto: cryptoSuite
  })
  const adopted = [true, false].map((initiator, side) =>
    authority.adopt(
      guardLinks[TEST_ONLY_M3_ESTABLISHED_ISSUER].issue({
        initiator,
        completeOfferDigest: b4a.from(digest),
        localId: b4a.from(initiator ? ids.initiatorCellId : ids.responderCellId),
        peerLocalId: b4a.from(initiator ? ids.responderCellId : ids.initiatorCellId),
        branchClass,
        branchId: b4a.from(branchId),
        circuitId: b4a.from(circuitId),
        generation,
        extensionIndex: initiator ? 0 : 0,
        localIdentity: b4a.from(initiator ? endpointIdentity : guardIdentity),
        peerIdentity: b4a.from(initiator ? guardIdentity : endpointIdentity),
        expiresAt: 2_000n,
        contexts: routeCellContexts(initiator),
        physicalChannel: channels[side],
        clientTailEphemeralSecretKey: initiator ? b4a.alloc(32, 0x74) : null,
        tailControlTranscript: b4a.alloc(290, 0x75)
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
    left: takeM3RouteTransport(moved[0].transportOwner),
    right: takeM3RouteTransport(moved[1].transportOwner)
  }
}

function sequenceBytes(first) {
  let value = first
  return (size) => b4a.alloc(size, value++)
}

function openMaterialFor(branch, value) {
  const finalTranscriptDigest = b4a.alloc(32, value + 11)
  const material = {
    initiator: true,
    expiresAt: NOW + 20_000n,
    branchClass: branch.branchClass,
    branchId: b4a.from(branch.branchId),
    circuitId: b4a.from(branch.circuitId),
    generation: branch.generation,
    exitIdentity: b4a.from(branch.exit.identity),
    policyDigest: b4a.alloc(32, value + 1),
    payloadDigest: b4a.alloc(32, value + 2),
    payloadForwardKey: b4a.alloc(32, value + 3),
    payloadReverseKey: b4a.alloc(32, value + 4),
    payloadForwardNoncePrefix: b4a.alloc(16, value + 5),
    payloadReverseNoncePrefix: b4a.alloc(16, value + 6),
    controlForwardKey: b4a.alloc(32, value + 7),
    controlReverseKey: b4a.alloc(32, value + 8),
    controlForwardNoncePrefix: b4a.alloc(16, value + 9),
    controlReverseNoncePrefix: b4a.alloc(16, value + 10),
    endpointOpenAuthority: null
  }
  return { material, finalTranscriptDigest }
}

function endpointCodecFor(material) {
  return new RoutePayloadCodec({
    crypto: cryptoSuite,
    context: mintCreatedRoutePayloadContext({
      endpointRole: ROUTE_ENDPOINT.DESTINATION,
      descriptorId: material.payloadDigest,
      circuitId: material.circuitId,
      forwardKey: material.payloadForwardKey,
      forwardNoncePrefix: material.payloadForwardNoncePrefix,
      reverseKey: material.payloadReverseKey,
      reverseNoncePrefix: material.payloadReverseNoncePrefix
    }),
    window: 64,
    gapTimeout: 5_000,
    now: () => 10_000
  })
}

async function productionAuthorityFixture(t, port = 47601, options = {}) {
  const topology = await liveTopologyFixture(
    port,
    port + 1,
    { left: '127.0.0.1', right: '127.0.0.2' },
    {
      clock: options.clock,
      records: [
        candidate(ROLE.SAFETY, 1, 2),
        candidate(ROLE.SAFETY, 2, 3),
        candidate(ROLE.PRIVATE, 0, 40),
        candidate(ROLE.PRIVATE, 1, 41),
        candidate(ROLE.PRIVATE, 2, 42),
        candidate(ROLE.PRIVATE, 3, 43),
        candidate(ROLE.PRIVATE, 4, 44),
        candidate(ROLE.PRIVATE, 5, 45)
      ]
    }
  )
  const randomBytes = sequenceBytes(0x31)
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
  const materialOffset = port - 47601
  const branches = [
    [BRANCH_CLASS.LOOKUP, 'lookup', 0x41 + materialOffset],
    [BRANCH_CLASS.ANNOUNCE, 'announce', 0x61 + materialOffset]
  ]
  const handoffs = {}
  const materials = {}
  const pairs = {}
  const owners = {}
  const byHandoff = new Map()
  for (const [branchClass, name, value] of branches) {
    const branch = draft[name]
    const created = openMaterialFor(branch, value)
    const pair = routeTransportPair([], branch, options.transportClock)
    created.material.endpointOpenAuthority = finalExitActivation[
      TEST_ONLY_ENDPOINT_DHT_EXIT_OPEN_ISSUER
    ].create({
      branchClass,
      branchId: branch.branchId,
      circuitId: branch.circuitId,
      generation: branch.generation,
      exitIdentity: branch.exit.identity,
      finalTranscriptDigest: created.finalTranscriptDigest,
      expiresAt: created.material.expiresAt,
      absoluteDeadline: draft.absoluteDeadline,
      controlKey: b4a.alloc(32, value + 12),
      controlNoncePrefix: b4a.alloc(16, value + 13)
    })
    bindOpenRouteTransport(created.material, {
      transport: pair.left,
      finalTranscriptDigest: created.finalTranscriptDigest
    })
    const handoff = Object.freeze({})
    handoffs[name] = handoff
    materials[name] = created.material
    pairs[name] = pair
    byHandoff.set(handoff, created.material)
  }
  const openRouteHandoff = require('../../lib/private/open-route-handoff')
  const original = {
    consumeOpenRouteHandoff: openRouteHandoff.consumeOpenRouteHandoff,
    revokeOpenRouteHandoff: openRouteHandoff.revokeOpenRouteHandoff,
    destroyOpenRouteMaterial: openRouteHandoff.destroyOpenRouteMaterial
  }
  Object.assign(openRouteHandoff, {
    consumeOpenRouteHandoff(handoff) {
      const material = byHandoff.get(handoff)
      if (!material) throw new Error('unknown OPEN handoff')
      byHandoff.delete(handoff)
      return material
    },
    revokeOpenRouteHandoff(handoff) {
      return byHandoff.delete(handoff)
    },
    destroyOpenRouteMaterial() {
      return true
    }
  })
  try {
    manager.publishInitialPair(Object.freeze(handoffs))
  } finally {
    Object.assign(openRouteHandoff, original)
  }
  for (const [branchClass, name] of branches) {
    const branch = draft[name]
    const owner = opaqueDestination.createLiveOpaqueDestinations({
      branch: branchClass,
      circuitId: branch.circuitId,
      generation: branch.generation,
      expiresAt: materials[name].expiresAt,
      wallNow: topology.clock.wallNow,
      monotonicNow: topology.clock.monotonicNow
    })
    manager.createDhtSeedAdmission(branchClass, owner)
    owners[name] = owner
  }
  manager.publishInitialSeedPair({
    lookup: opaqueDestination[TEST_ONLY_BRANCH_SEED_READY_ISSUER].create({
      branchClass: BRANCH_CLASS.LOOKUP,
      branchId: draft.lookup.branchId,
      circuitId: draft.lookup.circuitId,
      generation: draft.lookup.generation,
      exitIdentity: draft.lookup.exit.identity,
      expiresAt: materials.lookup.expiresAt
    }),
    announce: opaqueDestination[TEST_ONLY_BRANCH_SEED_READY_ISSUER].create({
      branchClass: BRANCH_CLASS.ANNOUNCE,
      branchId: draft.announce.branchId,
      circuitId: draft.announce.circuitId,
      generation: draft.announce.generation,
      exitIdentity: draft.announce.exit.identity,
      expiresAt: materials.announce.expiresAt
    })
  })
  const authority = new LiveRouteAuthority({ routeManager: manager })
  t.teardown(async () => {
    try {
      authority.destroy()
    } catch {}
    try {
      manager.destroy()
    } catch {}
    for (const pair of Object.values(pairs)) {
      try {
        destroyM3RouteTransport(pair.right)
      } catch {}
    }
    await topology.close()
  })
  return { authority, manager, materials, pairs, topology }
}

function startProductionLookupRequest(authority, value) {
  const id = b4a.alloc(32, value)
  const destinationRef = encodeDestinationRef({
    id,
    handle: b4a.alloc(130, value + 1)
  })
  issueLiveRouteDestination(authority, {
    branch: BRANCH_CLASS.LOOKUP,
    id,
    destinationRef
  })
  const encodedRequest = encodeRoutedRequest({
    requestId: b4a.alloc(16, value + 2),
    operationClass: BRANCH_CLASS.LOOKUP,
    commandId: M3_MESSAGE_ID.IMMUTABLE_GET_V1,
    absoluteDeadlineMs: 14_000n,
    destination: destinationRef,
    encodedBody: b4a.alloc(32, value + 3)
  })
  return {
    destinationRef,
    encodedRequest,
    operation: authority.request({
      branch: BRANCH_CLASS.LOOKUP,
      destinationRef,
      encodedRequest,
      attempt: 1
    })
  }
}

const AUTHORITY_METHODS = Object.freeze([
  'ready',
  'suspend',
  'resume',
  'destroy',
  'bootstrap',
  'closest',
  'request'
])

test('LiveRouteAuthority exposes exactly the seven-method authority surface', (t) => {
  const { LiveRouteAuthority } = require('../../lib/private/live-route-authority')
  t.alike(
    Reflect.ownKeys(LiveRouteAuthority.prototype)
      .filter((name) => name !== 'constructor')
      .sort(),
    [...AUTHORITY_METHODS].sort()
  )
})

test('OPEN transport moves fixed route frames through authenticated M3 cells', async (t) => {
  const edges = []
  const pair = routeTransportPair(edges)
  const frame = b4a.alloc(1100, 0x76)

  await sendM3RouteFrame(pair.left, frame)
  const received = await receiveM3RouteFrame(pair.right)

  t.alike(received, frame)
  t.alike(edges, ['endpoint>guard'])
  t.is(destroyM3RouteTransport(pair.left), true)
  t.is(destroyM3RouteTransport(pair.right), true)
})

test('OPEN seed setup failure destroys and forgets a partially initialized binding', async (t) => {
  const branch = {
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: b4a.alloc(16, 0x81),
    circuitId: b4a.alloc(16, 0x82),
    generation: 7n,
    exit: { identity: b4a.alloc(32, 0x83) }
  }
  const created = openMaterialFor(branch, 0x84)
  const failed = routeTransportPair([], branch)
  bindOpenRouteTransport(created.material, {
    transport: failed.left,
    finalTranscriptDigest: created.finalTranscriptDigest
  })
  destroyM3RouteTransport(failed.left)

  const setupError = await receiveOpenRouteSeedPayload(created.material, () => 10_000n).then(
    () => null,
    (error) => error
  )
  t.is(setupError && setupError.code, 'ERR_DESTROYED')
  t.is(
    destroyOpenRouteTransport(created.material),
    false,
    'failed reserve already destroys and forgets the binding'
  )

  destroyM3RouteTransport(failed.right)
})

for (const failurePoint of ['send', 'receive']) {
  test(`LiveRouteAuthority reports lookup ${failurePoint} transport rejection before rethrow`, async (t) => {
    const { authority, manager, pairs } = await productionAuthorityFixture(
      t,
      failurePoint === 'send' ? 47621 : 47631
    )
    if (failurePoint === 'send') destroyM3RouteTransport(pairs.lookup.left)
    const request = startProductionLookupRequest(authority, failurePoint === 'send' ? 0xb1 : 0xc1)
    if (failurePoint === 'receive') {
      const frame = await receiveM3RouteFrame(pairs.lookup.right)
      frame.fill(0)
      destroyM3RouteTransport(pairs.lookup.left)
    }

    const transportError = await request.operation.promise.then(
      () => null,
      (error) => error
    )
    t.is(transportError && transportError.code, 'ERR_DESTROYED')
    expectCode(
      t,
      () => manager.branchCapability(BRANCH_CLASS.LOOKUP),
      'ERR_PRIVATE_BRANCH_ROTATING'
    )
    t.ok(manager.branchCapability(BRANCH_CLASS.ANNOUNCE), 'unfailed branch remains available')
    request.destinationRef.fill(0)
    request.encodedRequest.fill(0)
  })
}

test('authenticated routed reply bind atomically joins and consumes both one-shot authorities', (t) => {
  const fixture = replyAuthorityFixture()
  const bound = opaqueDestination.bindAuthenticatedRoutedReply(
    fixture.referralAuthority,
    fixture.authenticatedReplyAuthority,
    fixture.encodedReply
  )
  t.alike(Reflect.ownKeys(bound), [])
  t.is(Object.isFrozen(bound), true)
  expectCode(
    t,
    () =>
      opaqueDestination.bindAuthenticatedRoutedReply(
        fixture.referralAuthority,
        fixture.authenticatedReplyAuthority,
        fixture.encodedReply
      ),
    'ERR_REPLAY'
  )
  const validated = validateRoutedReplyForRequest(fixture.encodedReply, {
    encodedRequest: fixture.encodedRequest,
    target: fixture.target,
    branch: BRANCH_CLASS.LOOKUP,
    circuitId: fixture.circuitId,
    generation: 7n,
    now: 1_000n,
    referralAuthority: bound
  })
  t.alike(commitRoutedReplyAdmission(validated.admission), [])
  clearRoutedReply(validated.reply)
  opaqueDestination.destroyLiveOpaqueDestinations(fixture.owner)
})

test('authenticated routed reply bind rejects cross-request, digest, deadline, and owner mismatch', (t) => {
  for (const mismatch of ['request', 'digest', 'deadline', 'owner']) {
    const fixture = replyAuthorityFixture(0x31 + mismatch.length)
    let authority = fixture.authenticatedReplyAuthority
    let encodedReply = fixture.encodedReply
    if (mismatch === 'digest') {
      encodedReply = b4a.from(encodedReply)
      encodedReply[encodedReply.length - 1] ^= 1
    } else {
      const issuer = opaqueDestination[TEST_ONLY_AUTHENTICATED_REPLY_ISSUER]
      const owner = mismatch === 'owner' ? replyAuthorityFixture(0x61).owner : fixture.owner
      authority = issuer.create(owner, {
        branch: BRANCH_CLASS.LOOKUP,
        branchId: fixture.branchId,
        circuitId: fixture.circuitId,
        generation: 7n,
        finalTranscriptDigest: fixture.finalTranscriptDigest,
        requestId: mismatch === 'request' ? b4a.alloc(16, 0xa1) : fixture.requestId,
        fromEncoded: fixture.destinationRef,
        deadline: mismatch === 'deadline' ? 4_001n : 4_000n,
        encodedReply: fixture.encodedReply
      })
    }
    expectCode(
      t,
      () =>
        opaqueDestination.bindAuthenticatedRoutedReply(
          fixture.referralAuthority,
          authority,
          encodedReply
        ),
      'ERR_AUTHENTICATION'
    )
    expectCode(
      t,
      () =>
        opaqueDestination.bindAuthenticatedRoutedReply(
          fixture.referralAuthority,
          authority,
          fixture.encodedReply
        ),
      'ERR_REPLAY'
    )
  }
})

test('LiveRouteAuthority production request owns exact reply authority and drops cancellation', async (t) => {
  const { authority, manager, materials, pairs, topology } = await productionAuthorityFixture(
    t,
    47611
  )
  const id = b4a.alloc(32, 0x91)
  const destinationRef = encodeDestinationRef({
    id,
    handle: b4a.alloc(130, 0x92)
  })
  const destination = issueLiveRouteDestination(authority, {
    branch: BRANCH_CLASS.LOOKUP,
    id,
    destinationRef
  })
  const exitCodec = endpointCodecFor(materials.lookup)
  const requestReassembler = new Reassembler({
    now: () => Number(topology.clock.monotonicNow()),
    epochExpiresAt: Number(materials.lookup.expiresAt)
  })
  const receiveRequest = async () => {
    let encoded = null
    while (encoded === null) {
      const frame = await receiveM3RouteFrame(pairs.lookup.right)
      const opened = exitCodec.open({ direction: DIRECTION.FORWARD }, frame)
      frame.fill(0)
      encoded = requestReassembler.pushAuthenticated(opened.payload)
      opened.payload.fill(0)
    }
    return encoded
  }
  let replyOrdinal = 0
  const sendReply = async (request, value) => {
    const encodedResponse = encodeImmutableGetResponse({ valuePresent: true, value })
    const encodedReply = encodeRoutedReply({
      requestId: request.requestId,
      commandId: request.commandId,
      commandVersion: request.commandVersion,
      operationClass: request.operationClass,
      from: request.destinationEncoded,
      errorCode: 0,
      token: b4a.alloc(0),
      closerNodes: [],
      encodedResponse
    })
    const payloads = fragment(encodedReply, {
      randomBytes: (size) => b4a.alloc(size, 0x93 + replyOrdinal++)
    })
    for (const payload of payloads) {
      const frame = exitCodec.seal({
        direction: DIRECTION.REVERSE,
        class: CELL_CLASS.DATAGRAM,
        payload
      })
      await sendM3RouteFrame(pairs.lookup.right, frame)
      frame.fill(0)
      payload.fill(0)
    }
    encodedResponse.fill(0)
    return encodedReply
  }

  const requestId = b4a.alloc(16, 0x94)
  const target = b4a.alloc(32, 0x95)
  const deadline = topology.clock.monotonicNow() + 4_000n
  const encodedRequest = encodeRoutedRequest({
    requestId,
    operationClass: BRANCH_CLASS.LOOKUP,
    commandId: M3_MESSAGE_ID.IMMUTABLE_GET_V1,
    absoluteDeadlineMs: deadline,
    destination: destinationRef,
    encodedBody: target
  })
  const referralAuthority = createLiveRouteReferralAuthority(authority, destination, {
    target,
    requestId,
    deadline
  })
  const operation = authority.request({
    branch: BRANCH_CLASS.LOOKUP,
    destinationRef,
    encodedRequest,
    attempt: 1
  })
  const receivedRequest = decodeRoutedRequest(await receiveRequest())
  const expectedReply = await sendReply(receivedRequest, b4a.from([0xaa]))
  const result = await operation.promise
  t.alike(Reflect.ownKeys(result).sort(), ['authenticatedReplyAuthority', 'encodedReply', 'rtt'])
  t.alike(result.encodedReply, expectedReply)
  const bound = opaqueDestination.bindAuthenticatedRoutedReply(
    referralAuthority,
    result.authenticatedReplyAuthority,
    result.encodedReply
  )
  expectCode(
    t,
    () =>
      opaqueDestination.bindAuthenticatedRoutedReply(
        referralAuthority,
        result.authenticatedReplyAuthority,
        result.encodedReply
      ),
    'ERR_REPLAY'
  )
  const validated = validateRoutedReplyForRequest(result.encodedReply, {
    encodedRequest,
    target,
    branch: BRANCH_CLASS.LOOKUP,
    circuitId: materials.lookup.circuitId,
    generation: materials.lookup.generation,
    now: topology.clock.monotonicNow(),
    referralAuthority: bound
  })
  t.alike(commitRoutedReplyAdmission(validated.admission), [])
  clearRoutedReply(validated.reply)
  clearRoutedRequest(receivedRequest)
  expectedReply.fill(0)

  const cancelledRequest = encodeRoutedRequest({
    requestId: b4a.alloc(16, 0xa1),
    operationClass: BRANCH_CLASS.LOOKUP,
    commandId: M3_MESSAGE_ID.IMMUTABLE_GET_V1,
    absoluteDeadlineMs: deadline,
    destination: destinationRef,
    encodedBody: target
  })
  const cancelled = authority.request({
    branch: BRANCH_CLASS.LOOKUP,
    destinationRef,
    encodedRequest: cancelledRequest,
    attempt: 1
  })
  const cancellation = cancelled.promise.then(
    () => null,
    (error) => error
  )
  const lateRequest = decodeRoutedRequest(await receiveRequest())
  t.is(cancelled.cancel(), true)
  const followupRequest = encodeRoutedRequest({
    requestId: b4a.alloc(16, 0xa2),
    operationClass: BRANCH_CLASS.LOOKUP,
    commandId: M3_MESSAGE_ID.IMMUTABLE_GET_V1,
    absoluteDeadlineMs: deadline,
    destination: destinationRef,
    encodedBody: target
  })
  const followup = authority.request({
    branch: BRANCH_CLASS.LOOKUP,
    destinationRef,
    encodedRequest: followupRequest,
    attempt: 1
  })
  const receivedFollowup = decodeRoutedRequest(await receiveRequest())
  const lateReply = await sendReply(lateRequest, b4a.from([0xbb]))
  const expectedFollowupReply = await sendReply(receivedFollowup, b4a.from([0xcc]))
  const followupResult = await followup.promise
  t.alike(followupResult.encodedReply, expectedFollowupReply)
  const cancellationError = await cancellation
  t.is(cancellationError && cancellationError.code, 'ERR_DESTROYED')
  clearRoutedRequest(lateRequest)
  clearRoutedRequest(receivedFollowup)
  lateReply.fill(0)
  expectedFollowupReply.fill(0)

  authority.suspend()
  t.is(authority.ready(), false)
  expectCode(t, () => authority.resume(), 'ERR_DESTROYED')
  expectCode(t, () => snapshotLiveRouteDestination(authority, destination), 'ERR_DESTROYED')
  t.ok(
    manager.branchCapability(BRANCH_CLASS.LOOKUP),
    'intentional suspend does not report transport destruction as branch loss'
  )
  t.is(manager.destroy(), true)
  authority.destroy()
  expectCode(t, () => authority.ready(), 'ERR_AUTHENTICATION')
  encodedRequest.fill(0)
  cancelledRequest.fill(0)
  followupRequest.fill(0)
  requestReassembler.destroy()
  exitCodec.destroy()
})

// The endpoint arms its own `absoluteDeadlineMs` on the route transport's injected
// scheduler, so these fire that timer directly instead of waiting out any real interval.
// Clock values mirror `routeClock` above; only `schedule` differs, by being observable.
function instrumentedTransportClock() {
  const armed = []
  // Only the four capabilities the authority accepts may go on `clock`; it is exact-checked.
  const clock = {
    wallNow: () => 1_000n,
    monotonicNow: () => 10_000n,
    schedule(callback, delay) {
      const handle = Object.freeze({})
      armed.push({ handle, delay, callback })
      return handle
    },
    cancelScheduled(handle) {
      const index = armed.findIndex((entry) => entry.handle === handle)
      if (index !== -1) armed.splice(index, 1)
    }
  }
  return {
    clock,
    armedDelays() {
      return armed.map((entry) => entry.delay)
    },
    fireArmed(delay) {
      const index = armed.findIndex((entry) => entry.delay === delay)
      if (index === -1) return false
      const [entry] = armed.splice(index, 1)
      entry.callback()
      return true
    }
  }
}

// Monotonic start is 10_000n, so this deadline leaves 3_137ms of budget: an unusual figure,
// so the timer fired below cannot be confused with an adjacency lifetime timer.
const DEADLINE_MS = 13_137n
const DEADLINE_DELAY = 3_137

function deadlineRequest(authority, value = 0xc1) {
  const id = b4a.alloc(32, value)
  const destinationRef = encodeDestinationRef({ id, handle: b4a.alloc(130, value + 1) })
  issueLiveRouteDestination(authority, { branch: BRANCH_CLASS.LOOKUP, id, destinationRef })
  const encodedRequest = encodeRoutedRequest({
    requestId: b4a.alloc(16, value + 2),
    operationClass: BRANCH_CLASS.LOOKUP,
    commandId: M3_MESSAGE_ID.IMMUTABLE_GET_V1,
    absoluteDeadlineMs: DEADLINE_MS,
    destination: destinationRef,
    encodedBody: b4a.alloc(32, value + 3)
  })
  return authority.request({
    branch: BRANCH_CLASS.LOOKUP,
    destinationRef,
    encodedRequest,
    attempt: 1
  })
}

test('production request enforces its own deadline and reports the branch lost', async (t) => {
  const timers = instrumentedTransportClock()
  const { authority, manager } = await productionAuthorityFixture(t, 47651, {
    transportClock: timers.clock
  })
  const operation = deadlineRequest(authority)
  t.ok(
    timers.armedDelays().includes(DEADLINE_DELAY),
    'the endpoint arms a timer for exactly the remaining budget on its own deadline'
  )
  let error = null
  const settled = operation.promise.catch((err) => {
    error = err
  })
  t.ok(timers.fireArmed(DEADLINE_DELAY), 'the deadline timer fires')
  await settled
  t.is(error && error.code, 'ERR_PRIVACY_UNAVAILABLE')
  // Same observable the transport-rejection tests above use: a reported loss puts the branch
  // into rotation, which distinguishes reporting the loss from merely cancelling the operation.
  expectCode(t, () => manager.branchCapability(BRANCH_CLASS.LOOKUP), 'ERR_PRIVATE_BRANCH_ROTATING')
  t.ok(manager.branchCapability(BRANCH_CLASS.ANNOUNCE), 'the sibling branch is untouched')
})

test('a cancelled production request disarms its deadline and reports no loss', async (t) => {
  const timers = instrumentedTransportClock()
  const { authority, manager } = await productionAuthorityFixture(t, 47653, {
    transportClock: timers.clock
  })
  const operation = deadlineRequest(authority)
  t.ok(timers.armedDelays().includes(DEADLINE_DELAY))
  let error = null
  const settled = operation.promise.catch((err) => {
    error = err
  })
  t.ok(operation.cancel(new Error('caller went away')))
  await settled
  t.is(error && error.message, 'caller went away')
  t.absent(
    timers.armedDelays().includes(DEADLINE_DELAY),
    'cancelling an operation disarms its deadline instead of leaking a timer'
  )
  t.ok(
    manager.branchCapability(BRANCH_CLASS.LOOKUP),
    'a caller cancellation must not mark the branch lost'
  )
})
