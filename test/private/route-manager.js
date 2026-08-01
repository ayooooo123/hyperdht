'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { PrivateRouteError } = require('../../lib/private/errors')
const { BRANCH_CLASS, ROLE } = require('../../lib/private/protocol')
const { encodeCanonicalEndpoint } = require('../../lib/private/relay-capability')
const { kInspectRelayCandidateDirectory } = require('../../lib/private/relay-candidate-directory')
const {
  INITIAL_PAIR_DEADLINE_MS,
  TEST_ONLY_ROUTE_MANAGER_OBSERVER,
  createFinalExitActivationFactory,
  createRouteExtensionFactory,
  createRouteManager,
  isRouteManager
} = require('../../lib/private/route-manager')
const {
  issueGuardLeaseM3CellLinkTransferIssuer,
  readGuardLeaseScope
} = require('../../lib/private/guard-lease')
const {
  candidate,
  canonicalEndpointForHost,
  directoryFixture,
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
  t.is(observed.draft.issuerCount, 4)
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
  expectCode(
    t,
    () => issueGuardLeaseM3CellLinkTransferIssuer(fixture.guardLease),
    'ERR_QUOTA_EXCEEDED'
  )
  t.is(fixture.directory[kInspectRelayCandidateDirectory]().pendingCount, 2)

  t.is(manager.destroy(), true)
  t.is(fixture.directory[kInspectRelayCandidateDirectory]().pendingCount, 0)
  const replacement = issueGuardLeaseM3CellLinkTransferIssuer(fixture.guardLease)
  t.is(replacement.destroy(), true)
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

  for (const item of cases) {
    const clock = routeClock()
    const directory = directoryFixture(clock, {
      guard: fixture.guard,
      records: item.records
    }).directory
    const manager = createRouteManager(
      managerOptions({ ...fixture, clock, directory }, sequenceId(0x41))
    )
    expectCode(t, () => manager.buildInitialPair(), 'ERR_INCOMPATIBLE_RELAY')
    t.is(manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().status, 'UNAVAILABLE', item.name)
    t.is(directory[kInspectRelayCandidateDirectory]().pendingCount, 0)
    const issuer = issueGuardLeaseM3CellLinkTransferIssuer(fixture.guardLease)
    t.is(issuer.destroy(), true)
    t.is(manager.destroy(), true)
    directory.destroy()
  }

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
  t.is(manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().draft.issuerCount, 4)
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
