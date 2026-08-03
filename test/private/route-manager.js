'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { consumeInitialBranchBuild } = require('../../lib/private/branch-path-authority')
const activation = require('../../lib/private/final-exit-activation')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { encodeDestinationRef } = require('../../lib/private/destination-ref')
const { encodeDhtExitSeeds, signDhtExitSeeds } = require('../../lib/private/dht-exit-seeds')
const { PrivateRouteError } = require('../../lib/private/errors')
const { BRANCH_CLASS, DESTINATION_VALIDATION_CLASS, ROLE } = require('../../lib/private/protocol')
const { encodeCanonicalEndpoint } = require('../../lib/private/relay-capability')
const { kInspectRelayCandidateDirectory } = require('../../lib/private/relay-candidate-directory')
const {
  INITIAL_PAIR_DEADLINE_MS,
  TEST_ONLY_ROUTE_MANAGER_OBSERVER,
  createFinalExitActivationFactory,
  createRouteExtensionFactory,
  createRouteManager,
  readRouteManagerGenerations,
  isRouteManager
} = require('../../lib/private/route-manager')
const {
  destroyGuardLease,
  issueGuardLeaseM3CellLinkTransferIssuer,
  readGuardLeaseScope
} = require('../../lib/private/guard-lease')
const { revokeGuardReconnectAuthority } = require('../../lib/private/guard-reconnect-authority')
const openRouteHandoff = require('../../lib/private/open-route-handoff')
const TEST_ONLY_ENDPOINT_DHT_EXIT_OPEN_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-endpoint-dht-exit-open-issuer'
)
const opaqueDestination = require('../../lib/private/opaque-destination')
const {
  NOW,
  candidate,
  canonicalEndpointForHost,
  directoryFixture,
  identityFor,
  endpoint,
  liveTopologyFixture,
  routeClock
} = require('./live-topology-fixture')

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

function sequenceId(first) {
  let value = first
  return (size) => b4a.alloc(size, value++)
}

function managerOptions(fixture, randomBytes = sequenceId(0x31)) {
  return {
    guardLease: fixture.guardLease,
    candidateDirectory: fixture.directory,
    extensionFactory: createRouteExtensionFactory({
      wallNow: fixture.clock.wallNow,
      monotonicNow: fixture.clock.monotonicNow,
      randomBytes,
      schedule: fixture.clock.schedule,
      cancelScheduled: fixture.clock.cancelScheduled
    }),
    terminalFactory: createFinalExitActivationFactory({
      wallNow: fixture.clock.wallNow,
      monotonicNow: fixture.clock.monotonicNow,
      randomBytes,
      schedule: fixture.clock.schedule,
      cancelScheduled: fixture.clock.cancelScheduled
    }),
    monotonicNow: fixture.clock.monotonicNow,
    randomBytes
  }
}

function openMaterial(branch, seed) {
  return {
    initiator: false,
    expiresAt: 20_000n,
    branchClass: branch.branchClass,
    branchId: b4a.from(branch.branchId),
    circuitId: b4a.from(branch.circuitId),
    generation: branch.generation,
    exitIdentity: b4a.from(branch.exit.identity),
    policyDigest: b4a.alloc(32, seed + 1),
    payloadDigest: b4a.alloc(32, seed + 2),
    payloadForwardKey: b4a.alloc(32, seed + 3),
    payloadReverseKey: b4a.alloc(32, seed + 4),
    payloadForwardNoncePrefix: b4a.alloc(16, seed + 5),
    payloadReverseNoncePrefix: b4a.alloc(16, seed + 6),
    controlForwardKey: b4a.alloc(32, seed + 7),
    controlReverseKey: b4a.alloc(32, seed + 8),
    controlForwardNoncePrefix: b4a.alloc(16, seed + 9),
    controlReverseNoncePrefix: b4a.alloc(16, seed + 10)
  }
}

const TEST_ONLY_BRANCH_SEED_READY_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-branch-seed-ready-issuer'
)

function branchSeedReady(branch, material) {
  return opaqueDestination[TEST_ONLY_BRANCH_SEED_READY_ISSUER].create({
    branchClass: branch.branchClass,
    branchId: branch.branchId,
    circuitId: branch.circuitId,
    generation: branch.generation,
    exitIdentity: material.exitIdentity,
    expiresAt: material.expiresAt
  })
}

function publishInitialSeeds(manager, draft, lookupMaterial, announceMaterial) {
  return manager.publishInitialSeedPair({
    lookup: branchSeedReady(draft.lookup, lookupMaterial),
    announce: branchSeedReady(draft.announce, announceMaterial)
  })
}

function privateIdentityPair(identity) {
  for (let ordinal = 0; ordinal < 16; ordinal++) {
    const pair = identityFor(ROLE.PRIVATE, ordinal)
    if (b4a.equals(pair.publicKey, identity)) return pair
  }
  throw new Error('missing private identity pair')
}

function attachEndpointOpenAuthority(material, branch, absoluteDeadline) {
  material.endpointOpenAuthority = activation[TEST_ONLY_ENDPOINT_DHT_EXIT_OPEN_ISSUER].create({
    branchClass: branch.branchClass,
    branchId: branch.branchId,
    circuitId: branch.circuitId,
    generation: branch.generation,
    exitIdentity: material.exitIdentity,
    finalTranscriptDigest: b4a.alloc(32, 0x41 + branch.branchClass),
    expiresAt: material.expiresAt,
    absoluteDeadline,
    controlKey: b4a.alloc(32, 0x51 + branch.branchClass),
    controlNoncePrefix: b4a.alloc(16, 0x61 + branch.branchClass)
  })
}

function encodedSeedsFor(branch, material, value) {
  const destinationRef = encodeDestinationRef({
    id: b4a.alloc(32, value),
    handle: b4a.concat([
      b4a.from([1, DESTINATION_VALIDATION_CLASS.DHT_NODE_HANDLE]),
      b4a.alloc(128, value + 1)
    ])
  })
  return encodeDhtExitSeeds(
    signDhtExitSeeds(
      {
        branchClass: branch.branchClass,
        branchId: branch.branchId,
        circuitId: branch.circuitId,
        generation: branch.generation,
        exitIdentity: material.exitIdentity,
        seedSetNonce: b4a.alloc(32, value + 2),
        destinationRefs: [destinationRef]
      },
      privateIdentityPair(material.exitIdentity).secretKey
    )
  )
}

function stubOpenRouteHandoff(t, handlers) {
  const originals = {
    consumeOpenRouteHandoff: openRouteHandoff.consumeOpenRouteHandoff,
    revokeOpenRouteHandoff: openRouteHandoff.revokeOpenRouteHandoff,
    destroyOpenRouteMaterial: openRouteHandoff.destroyOpenRouteMaterial
  }
  Object.assign(openRouteHandoff, handlers)
  t.teardown(() => Object.assign(openRouteHandoff, originals))
}

test('RouteManager factories are empty exact clock graph capabilities', async (t) => {
  const fixture = await liveTopologyFixture(47415, 47416)
  const randomBytes = sequenceId(0x21)
  const options = {
    wallNow: fixture.clock.wallNow,
    monotonicNow: fixture.clock.monotonicNow,
    randomBytes,
    schedule: fixture.clock.schedule,
    cancelScheduled: fixture.clock.cancelScheduled
  }
  const extensionFactory = createRouteExtensionFactory(options)
  const terminalFactory = createFinalExitActivationFactory(options)

  t.alike(Reflect.ownKeys(extensionFactory), [])
  t.alike(Reflect.ownKeys(terminalFactory), [])
  t.ok(Object.isFrozen(extensionFactory))
  t.ok(Object.isFrozen(terminalFactory))
  expectCode(
    t,
    () => createRouteExtensionFactory({ ...options, now: options.wallNow }),
    'INVALID_ROUTE'
  )
  expectCode(
    t,
    () =>
      createRouteManager({
        ...managerOptions(fixture, randomBytes),
        extensionFactory: Object.freeze({}),
        terminalFactory
      }),
    'UNAUTHORIZED'
  )
  expectCode(
    t,
    () =>
      createRouteManager({
        ...managerOptions(fixture, randomBytes),
        extensionFactory,
        terminalFactory: createFinalExitActivationFactory({
          ...options,
          schedule(callback, delay) {
            return options.schedule(callback, delay)
          }
        })
      }),
    'INVALID_ROUTE'
  )

  await fixture.close()
})

test('RouteManager constructs an atomic initial lookup and announce pair', async (t) => {
  const fixture = await liveTopologyFixture(47401, 47402)
  const manager = createRouteManager(managerOptions(fixture))

  t.is(isRouteManager(manager), true)
  t.is(manager.ready(), false)
  t.is(manager.buildInitialPair(), false)

  const observed = manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]()
  t.is(observed.status, 'BUILDING')
  t.is(observed.ready, false)
  t.is(observed.draft.issuerCount, 2)
  t.is(observed.draft.absoluteDeadline, fixture.clock.monotonicNow() + INITIAL_PAIR_DEADLINE_MS)
  t.is(observed.draft.lookup.branchClass, BRANCH_CLASS.LOOKUP)
  t.is(observed.draft.announce.branchClass, BRANCH_CLASS.ANNOUNCE)
  t.is(observed.draft.lookup.generation, 1n)
  t.is(observed.draft.announce.generation, 1n)
  t.is(observed.draft.lookup.branchId.byteLength, 16)
  t.is(observed.draft.lookup.circuitId.byteLength, 16)
  t.is(observed.draft.announce.branchId.byteLength, 16)
  t.is(observed.draft.announce.circuitId.byteLength, 16)
  t.not(
    b4a.toString(observed.draft.lookup.branchId, 'hex'),
    b4a.toString(observed.draft.announce.branchId, 'hex')
  )
  t.not(
    b4a.toString(observed.draft.lookup.circuitId, 'hex'),
    b4a.toString(observed.draft.announce.circuitId, 'hex')
  )

  const selectedIdentities = [
    observed.draft.lookup.middle.identity,
    observed.draft.lookup.exit.identity,
    observed.draft.announce.middle.identity,
    observed.draft.announce.exit.identity
  ].map((identity) => b4a.toString(identity, 'hex'))
  t.is(new Set(selectedIdentities).size, 4)
  const buildAuthority = manager.claimInitialBuild()
  t.ok(Object.isFrozen(buildAuthority))
  t.alike(Reflect.ownKeys(buildAuthority), [])
  const build = consumeInitialBranchBuild(buildAuthority)
  t.is(build.transaction !== null, true)
  t.alike(Reflect.ownKeys(build.selections), ['lookup', 'announce'])
  t.is(build.issuers.length, 2)
  expectCode(t, () => consumeInitialBranchBuild(buildAuthority), 'ERR_REPLAY')
  const extraOne = issueGuardLeaseM3CellLinkTransferIssuer(fixture.guardLease)
  const extraTwo = issueGuardLeaseM3CellLinkTransferIssuer(fixture.guardLease)
  expectCode(
    t,
    () => issueGuardLeaseM3CellLinkTransferIssuer(fixture.guardLease),
    'ERR_QUOTA_EXCEEDED'
  )
  t.is(extraOne.destroy(), true)
  t.is(extraTwo.destroy(), true)
  t.is(fixture.directory[kInspectRelayCandidateDirectory]().pendingCount, 2)

  t.is(manager.destroy(), true)
  t.is(fixture.directory[kInspectRelayCandidateDirectory]().pendingCount, 0)
  expectCode(t, () => issueGuardLeaseM3CellLinkTransferIssuer(fixture.guardLease), 'ERR_DESTROYED')
  await fixture.close()
})

test('RouteManager rejects every guard and selected path collision before slot allocation', async (t) => {
  const fixture = await liveTopologyFixture(47403, 47404)
  const guardScope = readGuardLeaseScope(fixture.guardLease)
  const guardEndpoint = guardScope.endpointBytes
  const sameGuardSubnet = encodeCanonicalEndpoint({
    addressFamily: 4,
    addressBytes: b4a.from([127, 0, 0, 99]),
    port: 49_999
  })

  const cases = [
    {
      name: 'guard-middle identity',
      records: [
        candidate(ROLE.SAFETY, 1, 2, { identityPair: fixture.guardFixture.links.b }),
        candidate(ROLE.SAFETY, 2, 3),
        candidate(ROLE.PRIVATE, 0, 40),
        candidate(ROLE.PRIVATE, 1, 41)
      ]
    },
    {
      name: 'guard-exit endpoint',
      records: [
        candidate(ROLE.SAFETY, 1, 2),
        candidate(ROLE.SAFETY, 2, 3),
        candidate(ROLE.PRIVATE, 0, 40, { endpointBytes: guardEndpoint }),
        candidate(ROLE.PRIVATE, 1, 41)
      ]
    },
    {
      name: 'guard-middle ipv4 subnet',
      records: [
        candidate(ROLE.SAFETY, 1, 2, { endpointBytes: sameGuardSubnet }),
        candidate(ROLE.SAFETY, 2, 3),
        candidate(ROLE.PRIVATE, 0, 40),
        candidate(ROLE.PRIVATE, 1, 41)
      ]
    },
    {
      name: 'middle-middle identity',
      records: [
        candidate(ROLE.SAFETY, 1, 2),
        candidate(ROLE.SAFETY, 1, 3),
        candidate(ROLE.PRIVATE, 0, 40),
        candidate(ROLE.PRIVATE, 1, 41)
      ]
    },
    {
      name: 'exit-exit subnet',
      records: [
        candidate(ROLE.SAFETY, 1, 2),
        candidate(ROLE.SAFETY, 2, 3),
        candidate(ROLE.PRIVATE, 0, 40),
        candidate(ROLE.PRIVATE, 1, 42, { endpointBytes: endpoint(40, 49_998) })
      ]
    }
  ]

  const managers = []
  for (const item of cases) {
    const clock = routeClock()
    const directory = directoryFixture(clock, {
      guard: fixture.guard,
      records: item.records
    }).directory
    const manager = createRouteManager(
      managerOptions({ ...fixture, clock, directory }, sequenceId(0x41))
    )
    managers.push(manager)
    expectCode(t, () => manager.buildInitialPair(), 'ERR_INCOMPATIBLE_RELAY')
    t.is(manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().status, 'UNAVAILABLE', item.name)
    t.is(directory[kInspectRelayCandidateDirectory]().pendingCount, 0)
    const issuer = issueGuardLeaseM3CellLinkTransferIssuer(fixture.guardLease)
    t.is(issuer.destroy(), true)
  }
  for (const manager of managers) t.is(manager.destroy(), true)

  await fixture.close()
})

test('RouteManager binds the directory scope to the pinned GuardLease', async (t) => {
  const fixture = await liveTopologyFixture(47411, 47412)
  const mismatched = directoryFixture(routeClock()).directory
  const manager = createRouteManager(
    managerOptions({ ...fixture, directory: mismatched }, sequenceId(0x71))
  )

  expectCode(t, () => manager.buildInitialPair(), 'ERR_INCOMPATIBLE_RELAY')
  t.is(mismatched[kInspectRelayCandidateDirectory]().pendingCount, 0)
  const issuer = issueGuardLeaseM3CellLinkTransferIssuer(fixture.guardLease)
  t.is(issuer.destroy(), true)
  t.is(manager.destroy(), true)
  mismatched.destroy()
  await fixture.close()
})

test('RouteManager binds an IPv6 GuardLease scope through canonical endpoint bytes', async (t) => {
  const fixture = await liveTopologyFixture(47413, 47414, {
    left: 'fd00::1',
    right: 'fd00::2'
  })
  const manager = createRouteManager(managerOptions(fixture, sequenceId(0x81)))
  const scope = readGuardLeaseScope(fixture.guardLease)

  t.alike(scope.endpointBytes, canonicalEndpointForHost('fd00::2', 47414))
  t.is(manager.buildInitialPair(), false)
  t.is(manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().draft.issuerCount, 2)
  t.is(manager.destroy(), true)
  await fixture.close()
})

test('RouteManager rejects branch capability before terminal OPEN publication', async (t) => {
  const fixture = await liveTopologyFixture(47405, 47406)
  const manager = createRouteManager(managerOptions(fixture))
  manager.buildInitialPair()
  expectCode(t, () => manager.branchCapability(BRANCH_CLASS.LOOKUP), 'ERR_PRIVACY_UNAVAILABLE')
  expectCode(t, () => manager.branchCapability(99), 'INVALID_ROUTE')
  t.is(manager.destroy(), true)
  await fixture.close()
})

test('RouteManager publishes lookup and announce OPEN handoffs atomically', async (t) => {
  const fixture = await liveTopologyFixture(47419, 47420)
  const manager = createRouteManager(managerOptions(fixture, sequenceId(0x91)))
  const destroyed = []
  const handoffs = Object.freeze({ lookup: Object.freeze({}), announce: Object.freeze({}) })

  t.is(manager.buildInitialPair(), false)
  const draft = manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().draft
  const lookupMaterial = openMaterial(draft.lookup, 0xa1)
  const announceMaterial = openMaterial(draft.announce, 0xb1)
  const materials = new Map([
    [handoffs.lookup, lookupMaterial],
    [handoffs.announce, announceMaterial]
  ])
  stubOpenRouteHandoff(t, {
    consumeOpenRouteHandoff(handoff) {
      const material = materials.get(handoff)
      if (!material) throw PrivateRouteError.UNAUTHORIZED()
      materials.delete(handoff)
      return material
    },
    revokeOpenRouteHandoff() {
      return false
    },
    destroyOpenRouteMaterial(material) {
      destroyed.push(material)
      return true
    }
  })

  t.is(manager.publishInitialPair(handoffs), true)
  t.is(manager.ready(), false)
  t.is(manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().status, 'OPEN_PENDING_SEEDS')
  t.is(publishInitialSeeds(manager, draft, lookupMaterial, announceMaterial), true)
  t.is(manager.ready(), true)
  t.is(manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().status, 'READY')
  t.is(fixture.directory[kInspectRelayCandidateDirectory]().generationRecordCount, 2)
  const extraOne = issueGuardLeaseM3CellLinkTransferIssuer(fixture.guardLease)
  const extraTwo = issueGuardLeaseM3CellLinkTransferIssuer(fixture.guardLease)
  expectCode(
    t,
    () => issueGuardLeaseM3CellLinkTransferIssuer(fixture.guardLease),
    'ERR_QUOTA_EXCEEDED'
  )
  t.is(extraOne.destroy(), true)
  t.is(extraTwo.destroy(), true)

  const lookup = manager.branchCapability(BRANCH_CLASS.LOOKUP)
  const announce = manager.branchCapability(BRANCH_CLASS.ANNOUNCE)
  t.alike(Reflect.ownKeys(lookup), [])
  t.alike(Reflect.ownKeys(announce), [])
  t.ok(Object.isFrozen(lookup))
  t.ok(Object.isFrozen(announce))
  expectCode(t, () => manager.publishInitialPair(handoffs), 'ERR_BUSY')

  t.is(manager.destroy(), true)
  t.is(destroyed.length, 2)
  expectCode(t, () => issueGuardLeaseM3CellLinkTransferIssuer(fixture.guardLease), 'ERR_DESTROYED')
  await fixture.close()
})

test('RouteManager admits signed seeds through endpoint OPEN authorities', async (t) => {
  const fixture = await liveTopologyFixture(47535, 47536)
  const manager = createRouteManager(managerOptions(fixture, sequenceId(0x25)))
  const handoffs = Object.freeze({ lookup: Object.freeze({}), announce: Object.freeze({}) })
  t.is(manager.buildInitialPair(), false)
  const draft = manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().draft
  const lookupMaterial = openMaterial(draft.lookup, 0x35)
  const announceMaterial = openMaterial(draft.announce, 0x45)
  lookupMaterial.expiresAt = NOW + 20_000n
  announceMaterial.expiresAt = NOW + 20_000n
  attachEndpointOpenAuthority(lookupMaterial, draft.lookup, draft.absoluteDeadline)
  attachEndpointOpenAuthority(announceMaterial, draft.announce, draft.absoluteDeadline)
  const materials = new Map([
    [handoffs.lookup, lookupMaterial],
    [handoffs.announce, announceMaterial]
  ])
  stubOpenRouteHandoff(t, {
    consumeOpenRouteHandoff(handoff) {
      const material = materials.get(handoff)
      if (!material) throw PrivateRouteError.UNAUTHORIZED()
      materials.delete(handoff)
      return material
    },
    revokeOpenRouteHandoff() {
      return false
    },
    destroyOpenRouteMaterial() {
      return true
    }
  })
  t.is(manager.publishInitialPair(handoffs), true)

  const lookupOwner = opaqueDestination.createLiveOpaqueDestinations({
    branch: BRANCH_CLASS.LOOKUP,
    circuitId: draft.lookup.circuitId,
    generation: draft.lookup.generation,
    expiresAt: lookupMaterial.expiresAt,
    wallNow: fixture.clock.wallNow,
    monotonicNow: fixture.clock.monotonicNow
  })
  const announceOwner = opaqueDestination.createLiveOpaqueDestinations({
    branch: BRANCH_CLASS.ANNOUNCE,
    circuitId: draft.announce.circuitId,
    generation: draft.announce.generation,
    expiresAt: announceMaterial.expiresAt,
    wallNow: fixture.clock.wallNow,
    monotonicNow: fixture.clock.monotonicNow
  })
  const lookupAdmission = manager.createDhtSeedAdmission(BRANCH_CLASS.LOOKUP, lookupOwner)
  const announceAdmission = manager.createDhtSeedAdmission(BRANCH_CLASS.ANNOUNCE, announceOwner)
  opaqueDestination.stageDhtSeedAdmission(
    lookupAdmission,
    encodedSeedsFor(draft.lookup, lookupMaterial, 0x71)
  )
  opaqueDestination.stageDhtSeedAdmission(
    announceAdmission,
    encodedSeedsFor(draft.announce, announceMaterial, 0x81)
  )
  const lookupCommitted = opaqueDestination.commitDhtSeedAdmission(
    opaqueDestination.sealDhtSeedAdmission(lookupAdmission)
  )
  const announceCommitted = opaqueDestination.commitDhtSeedAdmission(
    opaqueDestination.sealDhtSeedAdmission(announceAdmission)
  )
  t.is(
    manager.publishInitialSeedPair({
      lookup: lookupCommitted.branchSeedReady,
      announce: announceCommitted.branchSeedReady
    }),
    true
  )
  t.is(manager.ready(), true)
  t.is(manager.destroy(), true)
  opaqueDestination.destroyLiveOpaqueDestinations(lookupOwner)
  opaqueDestination.destroyLiveOpaqueDestinations(announceOwner)
  await fixture.close()
})

test('RouteManager revokes transferred seed admission on sibling failure', async (t) => {
  const fixture = await liveTopologyFixture(47537, 47538)
  const manager = createRouteManager(managerOptions(fixture, sequenceId(0x31)))
  const handoffs = Object.freeze({ lookup: Object.freeze({}), announce: Object.freeze({}) })
  t.is(manager.buildInitialPair(), false)
  const draft = manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().draft
  const lookupMaterial = openMaterial(draft.lookup, 0x41)
  const announceMaterial = openMaterial(draft.announce, 0x51)
  lookupMaterial.expiresAt = NOW + 20_000n
  announceMaterial.expiresAt = NOW + 20_000n
  attachEndpointOpenAuthority(lookupMaterial, draft.lookup, draft.absoluteDeadline)
  attachEndpointOpenAuthority(announceMaterial, draft.announce, draft.absoluteDeadline)
  const materials = new Map([
    [handoffs.lookup, lookupMaterial],
    [handoffs.announce, announceMaterial]
  ])
  stubOpenRouteHandoff(t, {
    consumeOpenRouteHandoff(handoff) {
      const material = materials.get(handoff)
      if (!material) throw PrivateRouteError.UNAUTHORIZED()
      materials.delete(handoff)
      return material
    },
    revokeOpenRouteHandoff() {
      return false
    },
    destroyOpenRouteMaterial() {
      return true
    }
  })
  t.is(manager.publishInitialPair(handoffs), true)
  const lookupOwner = opaqueDestination.createLiveOpaqueDestinations({
    branch: BRANCH_CLASS.LOOKUP,
    circuitId: draft.lookup.circuitId,
    generation: draft.lookup.generation,
    expiresAt: lookupMaterial.expiresAt,
    wallNow: fixture.clock.wallNow,
    monotonicNow: fixture.clock.monotonicNow
  })
  const lookupAdmission = manager.createDhtSeedAdmission(BRANCH_CLASS.LOOKUP, lookupOwner)
  expectCode(
    t,
    () => manager.createDhtSeedAdmission(BRANCH_CLASS.ANNOUNCE, lookupOwner),
    'ERR_AUTHENTICATION'
  )
  expectCode(
    t,
    () => opaqueDestination.stageDhtSeedAdmission(lookupAdmission, b4a.alloc(0)),
    'INVALID_ROUTE'
  )
  t.is(manager.ready(), false)
  t.is(manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().status, 'UNAVAILABLE')
  t.is(fixture.clock.pendingTimers(), 0)
  t.is(fixture.directory[kInspectRelayCandidateDirectory]().pendingCount, 0)
  t.is(manager.destroy(), true)
  await fixture.close()
})

test('RouteManager aborts seed readiness received before terminal OPEN', async (t) => {
  const fixture = await liveTopologyFixture(47531, 47532)
  const manager = createRouteManager(managerOptions(fixture, sequenceId(0x41)))
  t.is(manager.buildInitialPair(), false)
  const draft = manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().draft
  const lookup = branchSeedReady(draft.lookup, openMaterial(draft.lookup, 0x51))
  const announce = branchSeedReady(draft.announce, openMaterial(draft.announce, 0x61))

  expectCode(
    t,
    () => manager.publishInitialSeedPair({ lookup, announce }),
    'ERR_PRIVACY_UNAVAILABLE'
  )
  t.is(manager.ready(), false)
  t.is(manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().status, 'UNAVAILABLE')
  t.is(fixture.directory[kInspectRelayCandidateDirectory]().pendingCount, 0)
  expectCode(t, () => opaqueDestination.consumeBranchSeedReady(lookup), 'ERR_REPLAY')
  expectCode(t, () => opaqueDestination.consumeBranchSeedReady(announce), 'ERR_REPLAY')
  t.is(manager.destroy(), true)
  await fixture.close()
})

test('RouteManager aborts OPEN branches when seeds miss the shared deadline', async (t) => {
  const clock = routeClock(NOW, NOW)
  const fixture = await liveTopologyFixture(
    47533,
    47534,
    { left: '127.0.0.1', right: '127.0.0.2' },
    { clock }
  )
  const manager = createRouteManager(managerOptions(fixture, sequenceId(0x71)))
  const destroyed = []
  const handoffs = Object.freeze({ lookup: Object.freeze({}), announce: Object.freeze({}) })
  t.is(manager.buildInitialPair(), false)
  const draft = manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().draft
  const lookupMaterial = openMaterial(draft.lookup, 0x81)
  const announceMaterial = openMaterial(draft.announce, 0x91)
  lookupMaterial.expiresAt = NOW + 20_000n
  attachEndpointOpenAuthority(lookupMaterial, draft.lookup, draft.absoluteDeadline)
  const materials = new Map([
    [handoffs.lookup, lookupMaterial],
    [handoffs.announce, announceMaterial]
  ])
  stubOpenRouteHandoff(t, {
    consumeOpenRouteHandoff(handoff) {
      const material = materials.get(handoff)
      if (!material) throw PrivateRouteError.UNAUTHORIZED()
      materials.delete(handoff)
      return material
    },
    revokeOpenRouteHandoff() {
      return false
    },
    destroyOpenRouteMaterial(material) {
      destroyed.push(material)
      return true
    }
  })
  t.is(manager.publishInitialPair(handoffs), true)
  const lookupOwner = opaqueDestination.createLiveOpaqueDestinations({
    branch: BRANCH_CLASS.LOOKUP,
    circuitId: draft.lookup.circuitId,
    generation: draft.lookup.generation,
    expiresAt: lookupMaterial.expiresAt,
    wallNow: fixture.clock.wallNow,
    monotonicNow: fixture.clock.monotonicNow
  })
  const lookupAdmission = manager.createDhtSeedAdmission(BRANCH_CLASS.LOOKUP, lookupOwner)
  t.is(clock.pendingTimers(), 1)
  t.is(clock.fireNext(), true)
  t.is(clock.pendingTimers(), 1)
  t.is(manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().status, 'OPEN_PENDING_SEEDS')
  clock.advance(Number(INITIAL_PAIR_DEADLINE_MS))
  t.is(clock.fireNext(), true)
  t.is(clock.pendingTimers(), 0)
  expectCode(
    t,
    () => opaqueDestination.stageDhtSeedAdmission(lookupAdmission, b4a.alloc(0)),
    'INVALID_ROUTE'
  )
  t.is(manager.ready(), false)
  t.is(manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().status, 'UNAVAILABLE')
  t.is(destroyed.length, 2)
  t.is(fixture.directory[kInspectRelayCandidateDirectory]().pendingCount, 0)
  expectCode(t, () => manager.branchCapability(BRANCH_CLASS.LOOKUP), 'ERR_PRIVACY_UNAVAILABLE')
  t.is(manager.buildInitialPair(), false)
  t.is(fixture.directory[kInspectRelayCandidateDirectory]().pendingCount, 2)
  t.is(manager.destroy(), true)
  await fixture.close()
})

test('RouteManager fails closed when its seed timer fires synchronously', async (t) => {
  const clock = routeClock(NOW, NOW)
  clock.schedule = (callback) => {
    callback()
    return 1
  }
  const fixture = await liveTopologyFixture(
    47539,
    47540,
    { left: '127.0.0.1', right: '127.0.0.2' },
    { clock }
  )
  const manager = createRouteManager(managerOptions(fixture, sequenceId(0x81)))
  const destroyed = []
  const handoffs = Object.freeze({ lookup: Object.freeze({}), announce: Object.freeze({}) })
  t.is(manager.buildInitialPair(), false)
  const draft = manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().draft
  const materials = new Map([
    [handoffs.lookup, openMaterial(draft.lookup, 0x91)],
    [handoffs.announce, openMaterial(draft.announce, 0xa1)]
  ])
  stubOpenRouteHandoff(t, {
    consumeOpenRouteHandoff(handoff) {
      const material = materials.get(handoff)
      if (!material) throw PrivateRouteError.UNAUTHORIZED()
      materials.delete(handoff)
      return material
    },
    revokeOpenRouteHandoff() {
      return false
    },
    destroyOpenRouteMaterial(material) {
      destroyed.push(material)
      return true
    }
  })
  expectCode(t, () => manager.publishInitialPair(handoffs), 'ERR_PRIVACY_UNAVAILABLE')
  t.is(manager.ready(), false)
  t.is(manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().status, 'UNAVAILABLE')
  t.is(destroyed.length, 2)
  t.is(clock.pendingTimers(), 0)
  t.is(fixture.directory[kInspectRelayCandidateDirectory]().pendingCount, 0)
  t.is(manager.destroy(), true)
  await fixture.close()
})

test('RouteManager rolls back both initial branches on half publication failure', async (t) => {
  const fixture = await liveTopologyFixture(47421, 47422)
  const manager = createRouteManager(managerOptions(fixture, sequenceId(0xc1)))
  const destroyed = []
  const revoked = []
  const handoffs = Object.freeze({ lookup: Object.freeze({}), announce: Object.freeze({}) })

  t.is(manager.buildInitialPair(), false)
  const draft = manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().draft
  stubOpenRouteHandoff(t, {
    consumeOpenRouteHandoff(handoff) {
      if (handoff === handoffs.lookup) return openMaterial(draft.lookup, 0xd1)
      throw PrivateRouteError.UNAUTHORIZED()
    },
    revokeOpenRouteHandoff(handoff) {
      revoked.push(handoff)
      return true
    },
    destroyOpenRouteMaterial(material) {
      destroyed.push(material)
      return true
    }
  })

  expectCode(t, () => manager.publishInitialPair(handoffs), 'UNAUTHORIZED')
  t.is(manager.ready(), false)
  t.is(manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().status, 'UNAVAILABLE')
  t.is(fixture.directory[kInspectRelayCandidateDirectory]().pendingCount, 0)
  t.is(destroyed.length, 1)
  t.alike(revoked, [handoffs.announce])
  const replacement = issueGuardLeaseM3CellLinkTransferIssuer(fixture.guardLease)
  t.is(replacement.destroy(), true)
  t.is(manager.destroy(), true)
  await fixture.close()
})

test('RouteManager rotates one branch make-before-break under signed expiry cap', async (t) => {
  const clock = routeClock(NOW, NOW)
  const records = [
    candidate(ROLE.SAFETY, 1, 2, { expiresAtMs: NOW + 30_000n }),
    candidate(ROLE.SAFETY, 2, 3, { expiresAtMs: NOW + 30_000n }),
    candidate(ROLE.PRIVATE, 0, 40, { expiresAtMs: NOW + 30_000n }),
    candidate(ROLE.PRIVATE, 1, 41, { expiresAtMs: NOW + 30_000n }),
    candidate(ROLE.SAFETY, 3, 4, { expiresAtMs: NOW + 3_000n }),
    candidate(ROLE.PRIVATE, 2, 42, { expiresAtMs: NOW + 4_000n })
  ]
  const fixture = await liveTopologyFixture(
    47423,
    47424,
    { left: '127.0.0.1', right: '127.0.0.2' },
    { clock, records }
  )
  const manager = createRouteManager(managerOptions(fixture, sequenceId(0xe1)))
  const destroyed = []
  const handoffs = {
    initialLookup: Object.freeze({}),
    initialAnnounce: Object.freeze({}),
    rotationLookup: Object.freeze({})
  }
  const materials = new Map()

  t.is(manager.buildInitialPair(), false)
  const initial = manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().draft
  const initialLookup = openMaterial(initial.lookup, 0xe1)
  const initialAnnounce = openMaterial(initial.announce, 0xf1)
  initialLookup.expiresAt = NOW + 20_000n
  initialAnnounce.expiresAt = NOW + 20_000n
  materials.set(handoffs.initialLookup, initialLookup)
  materials.set(handoffs.initialAnnounce, initialAnnounce)
  stubOpenRouteHandoff(t, {
    consumeOpenRouteHandoff(handoff) {
      const material = materials.get(handoff)
      if (!material) throw PrivateRouteError.UNAUTHORIZED()
      materials.delete(handoff)
      return material
    },
    revokeOpenRouteHandoff() {
      return false
    },
    destroyOpenRouteMaterial(material) {
      destroyed.push(material)
      return true
    }
  })

  t.is(
    manager.publishInitialPair({
      lookup: handoffs.initialLookup,
      announce: handoffs.initialAnnounce
    }),
    true
  )
  t.is(publishInitialSeeds(manager, initial, initialLookup, initialAnnounce), true)
  const oldLookupCapability = manager.branchCapability(BRANCH_CLASS.LOOKUP)
  const announceCapability = manager.branchCapability(BRANCH_CLASS.ANNOUNCE)

  t.is(manager.rotate(BRANCH_CLASS.LOOKUP), false)
  const observed = manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]()
  t.is(observed.status, 'ROTATING')
  t.is(observed.ready, true)
  t.is(observed.rotations.lookup.issuerCount, 1)
  t.is(observed.rotations.lookup.branch.generation, 2n)
  t.is(observed.rotations.lookup.absoluteDeadline, NOW + 3_000n)
  expectCode(t, () => manager.branchCapability(BRANCH_CLASS.LOOKUP), 'ERR_PRIVATE_BRANCH_ROTATING')
  t.is(manager.branchCapability(BRANCH_CLASS.ANNOUNCE), announceCapability)
  expectCode(t, () => manager.rotate(BRANCH_CLASS.ANNOUNCE), 'ERR_PRIVATE_BRANCH_ROTATING')

  const replacement = openMaterial(observed.rotations.lookup.branch, 0xa7)
  replacement.expiresAt = NOW + 10_000n
  attachEndpointOpenAuthority(
    replacement,
    observed.rotations.lookup.branch,
    observed.rotations.lookup.absoluteDeadline
  )
  materials.set(handoffs.rotationLookup, replacement)
  t.is(manager.publishRotation(BRANCH_CLASS.LOOKUP, handoffs.rotationLookup), true)
  t.is(destroyed.length, 0)
  expectCode(t, () => manager.branchCapability(BRANCH_CLASS.LOOKUP), 'ERR_PRIVATE_BRANCH_ROTATING')
  const replacementOwner = opaqueDestination.createLiveOpaqueDestinations({
    branch: BRANCH_CLASS.LOOKUP,
    circuitId: observed.rotations.lookup.branch.circuitId,
    generation: observed.rotations.lookup.branch.generation,
    expiresAt: replacement.expiresAt,
    wallNow: fixture.clock.wallNow,
    monotonicNow: fixture.clock.monotonicNow
  })
  const replacementAdmission = manager.createDhtSeedAdmission(BRANCH_CLASS.LOOKUP, replacementOwner)
  opaqueDestination.stageDhtSeedAdmission(
    replacementAdmission,
    encodedSeedsFor(observed.rotations.lookup.branch, replacement, 0x91)
  )
  const replacementCommitted = opaqueDestination.commitDhtSeedAdmission(
    opaqueDestination.sealDhtSeedAdmission(replacementAdmission)
  )
  t.is(manager.publishRotationSeed(BRANCH_CLASS.LOOKUP, replacementCommitted.branchSeedReady), true)
  t.is(destroyed[0], initialLookup)
  t.alike(readRouteManagerGenerations(manager), {
    lookupGeneration: 2n,
    announceGeneration: 1n
  })
  t.is(manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().lookupGeneration, 2n)
  t.is(fixture.directory[kInspectRelayCandidateDirectory]().generationRecordCount, 2)
  t.not(manager.branchCapability(BRANCH_CLASS.LOOKUP), oldLookupCapability)
  t.is(manager.branchCapability(BRANCH_CLASS.ANNOUNCE), announceCapability)

  const extraOne = issueGuardLeaseM3CellLinkTransferIssuer(fixture.guardLease)
  const extraTwo = issueGuardLeaseM3CellLinkTransferIssuer(fixture.guardLease)
  expectCode(
    t,
    () => issueGuardLeaseM3CellLinkTransferIssuer(fixture.guardLease),
    'ERR_QUOTA_EXCEEDED'
  )
  t.is(extraOne.destroy(), true)
  t.is(extraTwo.destroy(), true)

  t.is(manager.destroy(), true)
  t.is(destroyed.length, 3)
  opaqueDestination.destroyLiveOpaqueDestinations(replacementOwner)
  await fixture.close()
})

test('RouteManager rolls back failed rotation without masking old branch', async (t) => {
  const clock = routeClock(NOW, NOW)
  const records = [
    candidate(ROLE.SAFETY, 1, 2),
    candidate(ROLE.SAFETY, 2, 3),
    candidate(ROLE.PRIVATE, 0, 40),
    candidate(ROLE.PRIVATE, 1, 41),
    candidate(ROLE.SAFETY, 3, 4),
    candidate(ROLE.PRIVATE, 2, 42)
  ]
  const fixture = await liveTopologyFixture(
    47425,
    47426,
    { left: '127.0.0.1', right: '127.0.0.2' },
    { clock, records }
  )
  const manager = createRouteManager(managerOptions(fixture, sequenceId(0xb7)))
  const destroyed = []
  const handoffs = {
    initialLookup: Object.freeze({}),
    initialAnnounce: Object.freeze({}),
    rotationAnnounce: Object.freeze({}),
    rotationTimeout: Object.freeze({})
  }
  const materials = new Map()

  t.is(manager.buildInitialPair(), false)
  const initial = manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().draft
  const initialLookup = openMaterial(initial.lookup, 0xc7)
  const initialAnnounce = openMaterial(initial.announce, 0xd7)
  initialLookup.expiresAt = NOW + 20_000n
  initialAnnounce.expiresAt = NOW + 20_000n
  materials.set(handoffs.initialLookup, initialLookup)
  materials.set(handoffs.initialAnnounce, initialAnnounce)
  stubOpenRouteHandoff(t, {
    consumeOpenRouteHandoff(handoff) {
      const material = materials.get(handoff)
      if (!material) throw PrivateRouteError.UNAUTHORIZED()
      materials.delete(handoff)
      return material
    },
    revokeOpenRouteHandoff() {
      return false
    },
    destroyOpenRouteMaterial(material) {
      destroyed.push(material)
      return true
    }
  })

  t.is(
    manager.publishInitialPair({
      lookup: handoffs.initialLookup,
      announce: handoffs.initialAnnounce
    }),
    true
  )
  t.is(publishInitialSeeds(manager, initial, initialLookup, initialAnnounce), true)
  const announceCapability = manager.branchCapability(BRANCH_CLASS.ANNOUNCE)
  t.is(manager.rotate(BRANCH_CLASS.ANNOUNCE), false)
  const rotation = manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().rotations.announce
  const invalidMaterial = openMaterial(rotation.branch, 0xe7)
  invalidMaterial.branchId = b4a.alloc(16, 0xee)
  materials.set(handoffs.rotationAnnounce, invalidMaterial)

  expectCode(
    t,
    () => manager.publishRotation(BRANCH_CLASS.ANNOUNCE, handoffs.rotationAnnounce),
    'UNAUTHORIZED'
  )
  t.is(destroyed[0], invalidMaterial)
  t.is(manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().status, 'READY')
  t.is(manager.branchCapability(BRANCH_CLASS.ANNOUNCE), announceCapability)
  t.is(fixture.directory[kInspectRelayCandidateDirectory]().pendingCount, 0)
  t.is(manager.rotate(BRANCH_CLASS.ANNOUNCE), false)
  const timeoutRotation = manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().rotations.announce
  const timeoutMaterial = openMaterial(timeoutRotation.branch, 0xf7)
  timeoutMaterial.expiresAt = NOW + 20_000n
  attachEndpointOpenAuthority(
    timeoutMaterial,
    timeoutRotation.branch,
    timeoutRotation.absoluteDeadline
  )
  materials.set(handoffs.rotationTimeout, timeoutMaterial)
  t.is(manager.publishRotation(BRANCH_CLASS.ANNOUNCE, handoffs.rotationTimeout), true)
  const timeoutOwner = opaqueDestination.createLiveOpaqueDestinations({
    branch: BRANCH_CLASS.ANNOUNCE,
    circuitId: timeoutRotation.branch.circuitId,
    generation: timeoutRotation.branch.generation,
    expiresAt: timeoutMaterial.expiresAt,
    wallNow: fixture.clock.wallNow,
    monotonicNow: fixture.clock.monotonicNow
  })
  const timeoutAdmission = manager.createDhtSeedAdmission(BRANCH_CLASS.ANNOUNCE, timeoutOwner)
  t.is(clock.pendingTimers(), 1)
  t.is(clock.fireNext(), true)
  t.is(clock.pendingTimers(), 1)
  t.is(manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().status, 'ROTATING')
  clock.advance(Number(INITIAL_PAIR_DEADLINE_MS))
  t.is(clock.fireNext(), true)
  t.is(clock.pendingTimers(), 0)
  expectCode(
    t,
    () => opaqueDestination.stageDhtSeedAdmission(timeoutAdmission, b4a.alloc(0)),
    'INVALID_ROUTE'
  )
  t.is(manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().status, 'READY')
  t.is(manager.branchCapability(BRANCH_CLASS.ANNOUNCE), announceCapability)
  t.is(destroyed[1], timeoutMaterial)
  t.is(fixture.directory[kInspectRelayCandidateDirectory]().pendingCount, 0)
  const extraOne = issueGuardLeaseM3CellLinkTransferIssuer(fixture.guardLease)
  const extraTwo = issueGuardLeaseM3CellLinkTransferIssuer(fixture.guardLease)
  t.is(extraOne.destroy(), true)
  t.is(extraTwo.destroy(), true)

  t.is(manager.destroy(), true)
  await fixture.close()
})

test('RouteManager rejects rotation before terminal OPEN publication', async (t) => {
  const fixture = await liveTopologyFixture(47417, 47418)
  const manager = createRouteManager(managerOptions(fixture))

  expectCode(t, () => manager.rotate(99), 'INVALID_ROUTE')
  expectCode(t, () => manager.rotate(BRANCH_CLASS.LOOKUP), 'ERR_PRIVACY_UNAVAILABLE')
  t.is(manager.buildInitialPair(), false)
  expectCode(t, () => manager.rotate(BRANCH_CLASS.ANNOUNCE), 'ERR_BUSY')
  t.is(manager.destroy(), true)
  expectCode(t, () => manager.rotate(BRANCH_CLASS.LOOKUP), 'ERR_DESTROYED')
  await fixture.close()
})

test('RouteManager suspend seals directory and leaves only one reconnect authority', async (t) => {
  const records = [
    candidate(ROLE.SAFETY, 1, 2),
    candidate(ROLE.SAFETY, 2, 3),
    candidate(ROLE.PRIVATE, 0, 40),
    candidate(ROLE.PRIVATE, 1, 41),
    candidate(ROLE.SAFETY, 3, 4),
    candidate(ROLE.PRIVATE, 2, 42)
  ]
  const fixture = await liveTopologyFixture(
    47419,
    47420,
    { left: '127.0.0.1', right: '127.0.0.2' },
    { records }
  )
  const manager = createRouteManager(managerOptions(fixture))
  const destroyed = []
  const handoffs = {
    lookup: Object.freeze({}),
    announce: Object.freeze({})
  }
  const rotationHandoff = Object.freeze({})
  const materials = new Map()

  t.is(manager.buildInitialPair(), false)
  const draft = manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().draft
  const lookupMaterial = openMaterial(draft.lookup, 0xf1)
  const announceMaterial = openMaterial(draft.announce, 0xf2)
  lookupMaterial.expiresAt = NOW + 20_000n
  announceMaterial.expiresAt = NOW + 20_000n
  materials.set(handoffs.lookup, lookupMaterial)
  materials.set(handoffs.announce, announceMaterial)
  stubOpenRouteHandoff(t, {
    consumeOpenRouteHandoff(handoff) {
      const material = materials.get(handoff)
      if (!material) throw PrivateRouteError.UNAUTHORIZED()
      materials.delete(handoff)
      return material
    },
    revokeOpenRouteHandoff() {
      return false
    },
    destroyOpenRouteMaterial(material) {
      destroyed.push(material)
      return true
    }
  })

  t.is(manager.publishInitialPair(handoffs), true)
  t.is(publishInitialSeeds(manager, draft, lookupMaterial, announceMaterial), true)
  t.is(manager.rotate(BRANCH_CLASS.LOOKUP), false)
  const rotation = manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().rotations.lookup
  const rotationMaterial = openMaterial(rotation.branch, 0xf3)
  materials.set(rotationHandoff, rotationMaterial)
  t.is(manager.publishRotation(BRANCH_CLASS.LOOKUP, rotationHandoff), true)
  t.is(fixture.directory[kInspectRelayCandidateDirectory]().pendingCount, 1)
  const reconnect = manager.suspend()

  t.alike(Reflect.ownKeys(reconnect), ['reconnect'])
  t.is(typeof reconnect.reconnect, 'function')
  t.is(isRouteManager(manager), false)
  expectCode(t, () => manager.branchCapability(BRANCH_CLASS.LOOKUP), 'ERR_DESTROYED')
  t.is(manager.destroy(), false)
  t.is(destroyed.length, 3)
  t.is(fixture.directory[kInspectRelayCandidateDirectory]().pendingCount, 0)
  expectCode(t, () => issueGuardLeaseM3CellLinkTransferIssuer(fixture.guardLease), 'ERR_DESTROYED')
  t.is(revokeGuardReconnectAuthority(reconnect, 'test-cleanup'), true)
  expectCode(t, () => reconnect.reconnect(), 'ERR_DESTROYED')
  for (
    let attempt = 0;
    attempt < 100 && !fixture.guardFixture.leftObserver.sockets[0].closed;
    attempt++
  ) {
    await new Promise((resolve) => setTimeout(resolve, 1))
  }
  t.is(fixture.guardFixture.leftObserver.sockets[0].closed, true)

  await fixture.close()

  const failureFixture = await liveTopologyFixture(47429, 47430)
  const failedManager = createRouteManager(managerOptions(failureFixture))
  t.is(destroyGuardLease(failureFixture.guardLease), true)
  expectCode(t, () => failedManager.suspend(), 'ERR_DESTROYED')
  t.is(failureFixture.directory.destroy(), undefined)
  t.is(failedManager.destroy(), false)
  await failureFixture.close()
})
