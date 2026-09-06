'use strict'

// KI-9. A branch expiry signal that arrives while the controller is ROTATING is
// refused, which is correct - the controller accepts branch signals only in READY.
// What was not correct is that the refusal destroyed the branch's only rotation
// trigger: `issueBranchSink` nulls the sink before issuing, the signal is one-shot
// and consumed, and `expired` has already dropped the timer. The branch then never
// rotated again for the life of the controller.
//
// This drives the real thing. Both branches are minted with the same signed expiry,
// so when the clock passes their rotation lead both expiry timers are due in the
// same pass: the manager issues the lookup one, the controller accepts it and
// enters ROTATING, and the announce one lands in that window and is refused. The
// test then completes the lookup rotation, returns the controller to READY, and
// asserts that the announce branch rotates with nothing further prodding it.
//
// The controller's own replacement build is suppressed by `testManualBuild`, the
// same seam that already lets a test own the initial build, so the test publishes
// the replacement branch itself. Every signal, sink and timer on the path under
// test is the production one.

const test = require('brittle')
const b4a = require('b4a')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  createEndpointBootstrapAuthority
} = require('../../lib/private/endpoint-bootstrap-authority')
const {
  createPrivateRoutingController,
  PRIVATE_ROUTING_STATE,
  TEST_ONLY_PRIVATE_ROUTING_CONTROLLER_ISSUER: controllerIssuer
} = require('../../lib/private/private-routing-controller')
const {
  TEST_ONLY_ROUTE_MANAGER_OBSERVER,
  createRouteManagerBranchLossRegistration,
  issueRouteManagerBranchPhysicalLoss
} = require('../../lib/private/route-manager')
const { bindOpenRouteTransport } = require('../../lib/private/live-route-authority')
const finalExitActivation = require('../../lib/private/final-exit-activation')
const opaqueDestination = require('../../lib/private/opaque-destination')
const openRouteHandoff = require('../../lib/private/open-route-handoff')
const { BRANCH_CLASS, ROLE } = require('../../lib/private/protocol')
const { NOW, candidate } = require('./live-topology-fixture')
const {
  closeLiveAuthorityHarness,
  createBranchNetwork,
  liveAuthorityHarness,
  openMaterialFor,
  routeTransportPair
} = require('./routed-dht-traversal')

const TEST_ONLY_ENDPOINT_DHT_EXIT_OPEN_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-endpoint-dht-exit-open-issuer'
)
const TEST_ONLY_BRANCH_SEED_READY_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-branch-seed-ready-issuer'
)

// A fresh branch outlives the pair it replaces, so its own expiry is not already
// due when it commits. Still inside the candidate expiry, NOW + 30_000.
const REPLACEMENT_EXPIRES_AT = NOW + 25_000n

const seed = (value, size = 32) => b4a.alloc(size, value)

// Two live branches consume two middles and two exits, so a rotation needs a third
// of each or `chooseReplacementPair` fails closed before any build starts.
function spareRecords() {
  return [
    candidate(ROLE.SAFETY, 1, 2),
    candidate(ROLE.SAFETY, 2, 3),
    candidate(ROLE.SAFETY, 3, 4),
    candidate(ROLE.PRIVATE, 0, 40),
    candidate(ROLE.PRIVATE, 1, 41),
    candidate(ROLE.PRIVATE, 2, 42)
  ]
}

function controller(value, port, clock) {
  const identity = cryptoSuite.keyPair(seed(value))
  return createPrivateRoutingController({
    endpointBootstrapAuthority: createEndpointBootstrapAuthority({
      bootstrapEndpoints: [{ host: '127.0.0.2', port: port + 1 }],
      localIdentity: identity.publicKey,
      localSecretKey: identity.secretKey,
      host: '127.0.0.1',
      port,
      wallNow: clock.wallNow,
      monotonicNow: clock.monotonicNow,
      schedule: setTimeout,
      cancelScheduled: clearTimeout,
      randomBytes: (size) => b4a.alloc(size, value + 1)
    })
  })
}

async function settle() {
  for (let attempt = 0; attempt < 8; attempt++) {
    await new Promise((resolve) => setTimeout(resolve, 1))
  }
}

async function runClock(clock, ticks) {
  for (let tick = 0; tick < ticks; tick++) {
    if (!clock.fireNext()) return
    await settle()
  }
}

async function runClockUntil(clock, reached, limit = 24) {
  for (let tick = 0; tick < limit && !reached(); tick++) {
    if (!clock.fireNext()) break
    await settle()
  }
  return reached()
}

async function waitForReady(routing) {
  for (let attempt = 0; attempt < 200; attempt++) {
    const state = routing.snapshot().state
    if (state === PRIVATE_ROUTING_STATE.READY) return
    if (state === PRIVATE_ROUTING_STATE.UNAVAILABLE) {
      throw (
        controllerIssuer.buildFailure(routing) ||
        new Error('controller entered UNAVAILABLE before READY')
      )
    }
    await new Promise((resolve) => setTimeout(resolve, 1))
  }
  throw new Error(`controller remained ${routing.snapshot().state}`)
}

// Play the network for one replacement branch: build its opaque forwarders and
// route transport, mint the OPEN material the exit would have signed, then publish
// the rotation and its seed exactly as the manager's own caller would.
function publishReplacementBranch(harness, branchClass, digestSeed, materialSeed) {
  const clock = harness.topology.clock
  const manager = harness.manager
  const key = branchClass === BRANCH_CLASS.LOOKUP ? 'lookup' : 'announce'
  const rotation = manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().rotations[key]
  if (!rotation) throw new Error(`no ${key} rotation draft to publish`)
  const branch = rotation.branch
  const guardIdentity = harness.topology.records.find(
    (record) => record.role === ROLE.SAFETY
  ).identity
  const network = createBranchNetwork(branch, guardIdentity, clock, [], digestSeed)
  const created = openMaterialFor(branch, materialSeed)
  created.material.expiresAt = REPLACEMENT_EXPIRES_AT
  const pair = routeTransportPair(branch, network, clock)
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
    absoluteDeadline: rotation.absoluteDeadline,
    controlKey: seed(digestSeed + 1),
    controlNoncePrefix: seed(digestSeed + 2, 16)
  })
  bindOpenRouteTransport(created.material, {
    transport: pair.endpoint,
    finalTranscriptDigest: created.finalTranscriptDigest
  })
  const handoff = Object.freeze({})
  const original = {
    consumeOpenRouteHandoff: openRouteHandoff.consumeOpenRouteHandoff,
    revokeOpenRouteHandoff: openRouteHandoff.revokeOpenRouteHandoff,
    destroyOpenRouteMaterial: openRouteHandoff.destroyOpenRouteMaterial
  }
  let pending = created.material
  Object.assign(openRouteHandoff, {
    consumeOpenRouteHandoff(value) {
      if (value !== handoff) return original.consumeOpenRouteHandoff(value)
      if (pending === null) throw new Error('spent replacement OPEN handoff')
      const material = pending
      pending = null
      return material
    },
    revokeOpenRouteHandoff(value) {
      if (value !== handoff) return original.revokeOpenRouteHandoff(value)
      const live = pending !== null
      pending = null
      return live
    },
    destroyOpenRouteMaterial(material) {
      if (material !== created.material) return original.destroyOpenRouteMaterial(material)
      return true
    }
  })
  try {
    manager.publishRotation(branchClass, handoff)
  } finally {
    Object.assign(openRouteHandoff, original)
  }
  // The owner is what makes the replacement claimable as a live pair; the manager
  // takes it through the seed admission, as `receiveInitialSeedPair` does for a
  // branch built by the real path.
  manager.createDhtSeedAdmission(
    branchClass,
    opaqueDestination.createLiveOpaqueDestinations({
      branch: branchClass,
      circuitId: branch.circuitId,
      generation: branch.generation,
      expiresAt: created.material.expiresAt,
      wallNow: clock.wallNow,
      monotonicNow: clock.monotonicNow
    })
  )
  manager.publishRotationSeed(
    branchClass,
    opaqueDestination[TEST_ONLY_BRANCH_SEED_READY_ISSUER].create({
      branchClass,
      branchId: branch.branchId,
      circuitId: branch.circuitId,
      generation: branch.generation,
      exitIdentity: branch.exit.identity,
      expiresAt: created.material.expiresAt
    })
  )
  return { network, pair }
}

test('a branch expiry refused during a rotation still rotates that branch', async (t) => {
  let routing = null
  const harness = await liveAuthorityHarness(
    (manager, topology) => {
      routing = controller(157, 48957, topology.clock)
      const builder = controllerIssuer.registerManager(routing, manager)
      return {
        publishInitialPair: (handoffs) =>
          controllerIssuer.publishInitialPair(routing, builder, handoffs),
        createDhtSeedAdmission: (branchClass, owner) =>
          controllerIssuer.createDhtSeedAdmission(routing, builder, branchClass, owner),
        publishInitialSeedPair: (readiness) =>
          controllerIssuer.publishInitialSeedPair(routing, builder, readiness)
      }
    },
    null,
    { records: spareRecords() }
  )
  const clock = harness.topology.clock
  const observe = () => harness.manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]()
  const replacements = []
  try {
    await waitForReady(routing)
    t.is(routing.snapshot().lookupGeneration, 1n)
    t.is(routing.snapshot().announceGeneration, 1n)

    // Both branches carry the same signed expiry, so one pass of the clock past
    // the rotation lead makes both expiry timers due.
    clock.advance(15_000)
    await runClock(clock, clock.pendingTimers())

    // The lookup expiry was accepted. The announce expiry arrived inside the
    // rotation window and was refused: no announce rotation, no generation move.
    t.is(routing.snapshot().state, PRIVATE_ROUTING_STATE.ROTATING)
    t.is(observe().status, 'ROTATING')
    t.is(observe().rotations.lookup.branch.generation, 2n)
    t.is(observe().rotations.announce, undefined)
    t.is(routing.snapshot().announceGeneration, 1n)

    replacements.push(publishReplacementBranch(harness, BRANCH_CLASS.LOOKUP, 0xe1, 0xe2))
    await settle()
    t.is(routing.snapshot().state, PRIVATE_ROUTING_STATE.READY)
    t.is(routing.snapshot().lookupGeneration, 2n)
    t.is(routing.snapshot().announceGeneration, 1n)

    // Nothing here re-issues the announce expiry. The only thing that can rotate
    // the announce branch now is the trigger the refused delivery left behind.
    const rotated = await runClockUntil(
      clock,
      () => routing.snapshot().state === PRIVATE_ROUTING_STATE.ROTATING
    )
    t.ok(rotated, 'the refused announce expiry was redelivered and accepted')
    const announceRotation = observe().rotations.announce
    t.is(announceRotation ? announceRotation.branch.generation : null, 2n)
    t.is(observe().rotations.lookup, undefined)

    // Guarded so that a controller which never rotates the announce branch fails
    // these assertions rather than throwing out of the harness, which would hide
    // the rest of them.
    if (announceRotation) {
      replacements.push(publishReplacementBranch(harness, BRANCH_CLASS.ANNOUNCE, 0xf1, 0xf2))
      await settle()
    }
    t.is(routing.snapshot().state, PRIVATE_ROUTING_STATE.READY)
    t.is(routing.snapshot().announceGeneration, 2n)
    t.is(routing.snapshot().lookupGeneration, 2n)
  } finally {
    if (routing) await routing.destroy()
    await closeLiveAuthorityHarness(harness)
    for (const replacement of replacements) {
      for (const forwarder of replacement.network.forwarders) {
        try {
          forwarder.destroy()
        } catch {}
      }
    }
  }
})

async function lossHarness(t, value, port) {
  let routing = null
  const harness = await liveAuthorityHarness(
    (manager, topology) => {
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
    },
    null,
    { records: spareRecords() }
  )
  const replacements = []
  t.teardown(async () => {
    await routing.destroy()
    await closeLiveAuthorityHarness(harness)
    for (const replacement of replacements) {
      for (const forwarder of replacement.network.forwarders) forwarder.destroy()
    }
  })
  await waitForReady(routing)
  return { harness, routing, replacements }
}

for (const duringRotation of [false, true]) {
  test(`branch loss survives ${duringRotation ? 'manager rotation' : 'controller refusal'}`, async (t) => {
    const { harness, routing, replacements } = await lossHarness(
      t,
      duringRotation ? 163 : 159,
      duringRotation ? 48963 : 48959
    )
    const digestSeed = duringRotation ? 0x91 : 0xc1
    const manager = harness.manager
    const observe = () => manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]()
    const lookup = createRouteManagerBranchLossRegistration(manager, BRANCH_CLASS.LOOKUP)
    const announce = createRouteManagerBranchLossRegistration(manager, BRANCH_CLASS.ANNOUNCE)
    const stale = createRouteManagerBranchLossRegistration(manager, BRANCH_CLASS.LOOKUP)

    t.is(issueRouteManagerBranchPhysicalLoss(lookup), true)
    if (duringRotation) await settle()
    t.is(issueRouteManagerBranchPhysicalLoss(announce), true, 'sibling loss is retained')
    await settle()
    t.is(observe().rotations.lookup.branch.generation, 2n)
    t.is(observe().rotations.announce, undefined)

    replacements.push(
      publishReplacementBranch(harness, BRANCH_CLASS.LOOKUP, digestSeed, digestSeed + 1)
    )
    await settle()
    const pending = observe().rotations.announce
    t.is(pending ? pending.branch.generation : null, 2n, 'loss starts replacement without expiry')
    t.is(routing.snapshot().lookupGeneration, 2n)
    t.is(
      issueRouteManagerBranchPhysicalLoss(stale),
      false,
      'retired registration cannot lose replacement'
    )
    if (pending) {
      replacements.push(
        publishReplacementBranch(harness, BRANCH_CLASS.ANNOUNCE, digestSeed + 16, digestSeed + 17)
      )
      await waitForReady(routing)
    }
    await settle()
    t.is(routing.snapshot().state, PRIVATE_ROUTING_STATE.READY)
    t.is(routing.snapshot().lookupGeneration, 2n)
    t.is(routing.snapshot().announceGeneration, 2n)
    t.is(harness.topology.clock.wallNow(), NOW, 'neither recovery waited for lease expiry')
  })
}

test('loss of a retiring branch does not rotate its replacement', async (t) => {
  const { harness, routing, replacements } = await lossHarness(t, 161, 48961)
  const manager = harness.manager
  const loss = createRouteManagerBranchLossRegistration(manager, BRANCH_CLASS.LOOKUP)
  controllerIssuer.issue(routing, controllerIssuer.sinks(routing).lookupBranchExpiry)
  await settle()
  t.is(routing.snapshot().state, PRIVATE_ROUTING_STATE.ROTATING)
  issueRouteManagerBranchPhysicalLoss(loss)
  await settle()
  replacements.push(publishReplacementBranch(harness, BRANCH_CLASS.LOOKUP, 0xa1, 0xa2))
  await waitForReady(routing)
  await settle()
  t.is(routing.snapshot().state, PRIVATE_ROUTING_STATE.READY)
  t.is(routing.snapshot().lookupGeneration, 2n)
  t.is(routing.snapshot().announceGeneration, 1n)
  t.ok(manager.branchCapability(BRANCH_CLASS.LOOKUP), 'replacement remains usable')
  const replacementLoss = createRouteManagerBranchLossRegistration(manager, BRANCH_CLASS.LOOKUP)
  t.is(issueRouteManagerBranchPhysicalLoss(replacementLoss), true)
  await settle()
  t.is(
    manager[TEST_ONLY_ROUTE_MANAGER_OBSERVER]().rotations.lookup.branch.generation,
    3n,
    'retiring loss did not consume the replacement loss sink'
  )
})

test('network change clears loss waiting behind a rotation', async (t) => {
  const { harness, routing } = await lossHarness(t, 165, 48965)
  const manager = harness.manager
  const lookup = createRouteManagerBranchLossRegistration(manager, BRANCH_CLASS.LOOKUP)
  const announce = createRouteManagerBranchLossRegistration(manager, BRANCH_CLASS.ANNOUNCE)
  issueRouteManagerBranchPhysicalLoss(lookup)
  await settle()
  issueRouteManagerBranchPhysicalLoss(announce)
  await settle()
  await routing.networkChanged()
  await runClock(harness.topology.clock, harness.topology.clock.pendingTimers())
  const snapshot = routing.snapshot()
  t.is(snapshot.state, PRIVATE_ROUTING_STATE.UNAVAILABLE)
  t.is(snapshot.routeManager, false)
  t.is(snapshot.endpointSockets, 0)
  t.is(snapshot.queues, 0)
  t.is(
    await routing.immutableGet(seed(0x61)).then(
      () => null,
      (err) => err.code
    ),
    'ERR_PRIVACY_UNAVAILABLE',
    'pending recovery cannot restore request authority after network change'
  )
})

test('rotation failure after same-branch loss does not restore ready state', async (t) => {
  const { harness, routing } = await lossHarness(t, 167, 48967)
  const manager = harness.manager
  const lookup = createRouteManagerBranchLossRegistration(manager, BRANCH_CLASS.LOOKUP)

  controllerIssuer.issue(routing, controllerIssuer.sinks(routing).lookupBranchExpiry)
  await settle()
  t.is(routing.snapshot().state, PRIVATE_ROUTING_STATE.ROTATING)
  t.is(
    issueRouteManagerBranchPhysicalLoss(lookup),
    true,
    'loss is retained during same-branch rotation'
  )
  await settle()

  t.exception(
    () => manager.publishRotation(BRANCH_CLASS.LOOKUP, {}),
    'fails replacement before publication'
  )
  await settle()

  t.is(manager.ready(), false, 'failed replacement cannot restore a lost branch to READY')
  let code = null
  try {
    manager.branchCapability(BRANCH_CLASS.LOOKUP)
  } catch (err) {
    code = err.code
  }
  t.is(code, 'ERR_PRIVACY_UNAVAILABLE', 'lost branch cannot regain request authority')
  t.is(harness.topology.clock.wallNow(), NOW, 'failure does not depend on lease expiry')
})
