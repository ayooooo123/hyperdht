'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { PrivateRouteError } = require('../../lib/private/errors')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  createEndpointBootstrapAuthority
} = require('../../lib/private/endpoint-bootstrap-authority')
const {
  PRIVATE_ROUTING_STATE,
  TEST_ONLY_PRIVATE_ROUTING_CONTROLLER_ISSUER,
  createPrivateRoutingController
} = require('../../lib/private/private-routing-controller')
const { BRANCH_CLASS } = require('../../lib/private/protocol')
const {
  createFinalExitActivationFactory,
  createRouteExtensionFactory,
  createRouteManager,
  TEST_ONLY_ROUTE_MANAGER_OBSERVER,
  TEST_ONLY_ROUTE_MANAGER_FACTORY_ISSUER
} = require('../../lib/private/route-manager')
const openRouteHandoff = require('../../lib/private/open-route-handoff')
const opaqueDestination = require('../../lib/private/opaque-destination')
const { liveTopologyFixture } = require('./live-topology-fixture')

const seed = (value) => b4a.alloc(32, value)

function authority(value, port) {
  const identity = cryptoSuite.keyPair(seed(value))
  return createEndpointBootstrapAuthority({
    bootstrapEndpoints: [{ host: '127.0.0.2', port: port + 1 }],
    localIdentity: identity.publicKey,
    localSecretKey: identity.secretKey,
    host: '127.0.0.1',
    port,
    wallNow: () => 1_000n,
    monotonicNow: () => 1_000n,
    schedule: setTimeout,
    cancelScheduled: clearTimeout,
    randomBytes: (size) => b4a.alloc(size, value + 1)
  })
}

function methodNames(controller) {
  return Object.getOwnPropertyNames(Object.getPrototypeOf(controller))
    .filter((name) => name !== 'constructor')
    .sort()
}
function sequenceId(first) {
  return (size) => b4a.alloc(size, first++)
}

function deferred() {
  let resolve
  let reject
  const promise = new Promise((onResolve, onReject) => {
    resolve = onResolve
    reject = onReject
  })
  return { promise, resolve, reject }
}

const TEST_ONLY_BRANCH_SEED_READY_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-branch-seed-ready-issuer'
)

function openMaterial(branch, value) {
  return {
    expiresAt: 20_000n,
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
    controlReverseNoncePrefix: b4a.alloc(16, value + 10)
  }
}

async function readySuspendFixture(t, port, handlers) {
  const topology = await liveTopologyFixture(port, port + 1)
  const randomBytes = sequenceId(0x31)
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
  const lookupMaterial = openMaterial(draft.lookup, 0x91)
  const announceMaterial = openMaterial(draft.announce, 0xa1)
  const handoffs = { lookup: Object.freeze({}), announce: Object.freeze({}) }
  const handoffMaterials = new Map([
    [handoffs.lookup, lookupMaterial],
    [handoffs.announce, announceMaterial]
  ])
  const originals = {
    consumeOpenRouteHandoff: openRouteHandoff.consumeOpenRouteHandoff,
    revokeOpenRouteHandoff: openRouteHandoff.revokeOpenRouteHandoff,
    destroyOpenRouteMaterial: openRouteHandoff.destroyOpenRouteMaterial
  }
  Object.assign(openRouteHandoff, {
    consumeOpenRouteHandoff(handoff) {
      const material = handoffMaterials.get(handoff)
      if (!material) throw PrivateRouteError.UNAUTHORIZED()
      handoffMaterials.delete(handoff)
      return material
    },
    revokeOpenRouteHandoff() {
      return false
    },
    destroyOpenRouteMaterial: handlers.destroyOpenRouteMaterial
  })
  const restoreTeardown = TEST_ONLY_ROUTE_MANAGER_FACTORY_ISSUER.installTeardown(
    handlers.teardownOpenRouteMaterial
  )
  manager.publishInitialPair(handoffs)
  manager.publishInitialSeedPair({
    lookup: opaqueDestination[TEST_ONLY_BRANCH_SEED_READY_ISSUER].create({
      branchClass: BRANCH_CLASS.LOOKUP,
      branchId: lookupMaterial.branchId,
      circuitId: lookupMaterial.circuitId,
      generation: lookupMaterial.generation,
      exitIdentity: lookupMaterial.exitIdentity,
      expiresAt: lookupMaterial.expiresAt
    }),
    announce: opaqueDestination[TEST_ONLY_BRANCH_SEED_READY_ISSUER].create({
      branchClass: BRANCH_CLASS.ANNOUNCE,
      branchId: announceMaterial.branchId,
      circuitId: announceMaterial.circuitId,
      generation: announceMaterial.generation,
      exitIdentity: announceMaterial.exitIdentity,
      expiresAt: announceMaterial.expiresAt
    })
  })
  const controller = createPrivateRoutingController({
    endpointBootstrapAuthority: authority(port & 0xff, port + 2)
  })
  const trace = handlers.trace
  const routedDHTIO = {
    async suspend() {
      trace.push('applications-stopped')
    },
    async destroy() {
      trace.push('transport-destroyed')
    }
  }
  const liveRouteAuthority = {
    destroy() {
      trace.push('authority-destroyed')
    }
  }
  TEST_ONLY_PRIVATE_ROUTING_CONTROLLER_ISSUER.installReadyForSuspend(controller, {
    routeManager: manager,
    routedDHTIO,
    liveRouteAuthority,
    guardLease: topology.guardLease
  })
  return {
    announceMaterial,
    controller,
    lookupMaterial,
    manager,
    topology,
    async close() {
      restoreTeardown()
      Object.assign(openRouteHandoff, originals)
      await controller.destroy()
      await topology.close()
    }
  }
}

test('private routing controller exposes only the internal lifecycle surface', async (t) => {
  const controller = createPrivateRoutingController({
    endpointBootstrapAuthority: authority(11, 47811)
  })

  t.ok(Object.isFrozen(controller))
  t.alike(Reflect.ownKeys(controller), [])
  t.alike(methodNames(controller), [
    'destroy',
    'immutableGet',
    'networkChanged',
    'resume',
    'snapshot',
    'start',
    'suspend'
  ])
  t.alike(controller.snapshot(), {
    state: PRIVATE_ROUTING_STATE.OFF,
    generation: 0n,
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

  await controller.destroy()
})

test('private routing controller destroy is ordered, idempotent, and zero-state', async (t) => {
  const controller = createPrivateRoutingController({
    endpointBootstrapAuthority: authority(13, 47813)
  })
  const first = controller.destroy()
  const second = controller.destroy()
  t.is(first, second)
  await first
  t.alike(controller.snapshot(), {
    state: PRIVATE_ROUTING_STATE.DESTROYED,
    generation: 1n,
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
  t.is(await controller.destroy(), undefined)
})

test('private routing signal sinks are empty typed one-shot capabilities', async (t) => {
  const left = createPrivateRoutingController({
    endpointBootstrapAuthority: authority(15, 47815)
  })
  const right = createPrivateRoutingController({
    endpointBootstrapAuthority: authority(17, 47817)
  })
  const leftSinks = TEST_ONLY_PRIVATE_ROUTING_CONTROLLER_ISSUER.sinks(left)
  const rightSinks = TEST_ONLY_PRIVATE_ROUTING_CONTROLLER_ISSUER.sinks(right)

  t.alike(Object.keys(leftSinks).sort(), [
    'announceBranchExpiry',
    'announceBranchLoss',
    'announceSeedReady',
    'guardLoss',
    'lookupBranchExpiry',
    'lookupBranchLoss',
    'lookupSeedReady',
    'networkChange',
    'wallClockRollback'
  ])
  for (const sink of Object.values(leftSinks)) {
    t.ok(Object.isFrozen(sink))
    t.alike(Reflect.ownKeys(sink), [])
  }

  let cross = null
  try {
    TEST_ONLY_PRIVATE_ROUTING_CONTROLLER_ISSUER.issue(left, rightSinks.guardLoss)
  } catch (err) {
    cross = err
  }
  t.is(cross && cross.code, 'UNAUTHORIZED')

  t.is(TEST_ONLY_PRIVATE_ROUTING_CONTROLLER_ISSUER.issue(left, leftSinks.guardLoss), true)
  let replay = null
  try {
    TEST_ONLY_PRIVATE_ROUTING_CONTROLLER_ISSUER.issue(left, leftSinks.guardLoss)
  } catch (err) {
    replay = err
  }
  t.is(replay && replay.code, 'ERR_REPLAY')
  await Promise.resolve()
  await Promise.resolve()
  t.is(left.snapshot().state, PRIVATE_ROUTING_STATE.OFF)
  t.alike(left.snapshot().packetEdges, [])
  t.is(left.snapshot().queues, 0)

  let callback = false
  let dataError = null
  try {
    TEST_ONLY_PRIVATE_ROUTING_CONTROLLER_ISSUER.issue(left, leftSinks.wallClockRollback, () => {
      callback = true
    })
  } catch (err) {
    dataError = err
  }
  t.is(dataError && dataError.code, 'INVALID_ROUTE')
  t.is(callback, false)

  await left.destroy()
  await right.destroy()
})

test('OFF network change consumes sealed bootstrap ownership and permanently fails closed', async (t) => {
  const controller = createPrivateRoutingController({
    endpointBootstrapAuthority: authority(19, 47819)
  })
  t.is(await controller.networkChanged(), true)
  t.is(controller.snapshot().state, PRIVATE_ROUTING_STATE.UNAVAILABLE)
  t.is(controller.snapshot().endpointSockets, 0)
  const before = controller.snapshot().generation
  let error = null
  try {
    await controller.start()
  } catch (err) {
    error = err
  }
  t.is(error && error.code, 'CIRCUIT_STATE')
  t.is(controller.snapshot().generation, before)
  t.alike(controller.snapshot().packetEdges, [])
  await controller.destroy()
})

test('BOOTSTRAPPING network change closes endpoint ownership before start can continue', async (t) => {
  const controller = createPrivateRoutingController({
    endpointBootstrapAuthority: authority(21, 47821)
  })
  const starting = controller.start().then(
    () => null,
    (err) => err
  )
  await Promise.resolve()
  await Promise.resolve()
  t.is(controller.snapshot().state, PRIVATE_ROUTING_STATE.BOOTSTRAPPING)
  t.is(controller.snapshot().endpointSockets, 1)
  t.is(await controller.networkChanged(), true)
  t.is(controller.snapshot().state, PRIVATE_ROUTING_STATE.UNAVAILABLE)
  t.is(controller.snapshot().endpointSockets, 0)
  const generation = controller.snapshot().generation
  const error = await starting
  t.ok(error)
  t.is(controller.snapshot().state, PRIVATE_ROUTING_STATE.UNAVAILABLE)
  t.is(controller.snapshot().generation, generation)
  t.alike(controller.snapshot().packetEdges, [])
  await controller.destroy()
})
test('controller suspend awaits the manager teardown transaction before reconnect publication', async (t) => {
  const trace = []
  const lookupAck = deferred()
  const announceAck = deferred()
  let fixture
  try {
    fixture = await readySuspendFixture(t, 48131, {
      trace,
      teardownOpenRouteMaterial(material) {
        trace.push(`teardown:${material.branchClass}`)
        return material.branchClass === BRANCH_CLASS.LOOKUP
          ? lookupAck.promise
          : announceAck.promise
      },
      destroyOpenRouteMaterial(material) {
        trace.push(`destroy:${material.branchClass}`)
        return true
      }
    })
    let settled = false
    const suspending = fixture.controller.suspend().then(() => {
      settled = true
    })
    await Promise.resolve()
    await Promise.resolve()
    t.alike(trace, [
      'applications-stopped',
      `teardown:${BRANCH_CLASS.LOOKUP}`,
      `teardown:${BRANCH_CLASS.ANNOUNCE}`
    ])
    t.is(settled, false)
    t.is(fixture.controller.snapshot().reconnect, false)
    lookupAck.resolve(true)
    await Promise.resolve()
    t.is(settled, false, 'one branch cannot publish reconnect')
    announceAck.resolve(true)
    await suspending
    t.is(fixture.controller.snapshot().state, PRIVATE_ROUTING_STATE.SUSPENDED)
    t.is(fixture.controller.snapshot().reconnect, true)
    t.alike(trace, [
      'applications-stopped',
      `teardown:${BRANCH_CLASS.LOOKUP}`,
      `teardown:${BRANCH_CLASS.ANNOUNCE}`,
      `destroy:${BRANCH_CLASS.LOOKUP}`,
      `destroy:${BRANCH_CLASS.ANNOUNCE}`,
      'transport-destroyed',
      'authority-destroyed'
    ])
    t.is(await fixture.controller.networkChanged(), true)
    t.is(fixture.controller.snapshot().state, PRIVATE_ROUTING_STATE.UNAVAILABLE)
  } finally {
    if (fixture) await fixture.close()
  }
})

test('network change during teardown cancels both branches and leaves zero ownership', async (t) => {
  const trace = []
  const held = new Map()
  let fixture
  try {
    fixture = await readySuspendFixture(t, 48141, {
      trace,
      teardownOpenRouteMaterial(material) {
        const operation = deferred()
        held.set(material, operation)
        trace.push(`teardown:${material.branchClass}`)
        return operation.promise
      },
      destroyOpenRouteMaterial(material) {
        trace.push(`destroy:${material.branchClass}`)
        const operation = held.get(material)
        if (operation) operation.reject(PrivateRouteError.ERR_DESTROYED())
        return true
      }
    })
    const suspending = fixture.controller.suspend()
    await Promise.resolve()
    await Promise.resolve()
    t.is(await fixture.controller.networkChanged(), true)
    await t.exception(suspending)
    const snapshot = fixture.controller.snapshot()
    t.is(snapshot.state, PRIVATE_ROUTING_STATE.UNAVAILABLE)
    t.is(snapshot.routeManager, false)
    t.is(snapshot.guardLease, false)
    t.is(snapshot.reconnect, false)
    t.is(snapshot.routedDHTIO, false)
    t.is(snapshot.liveRouteAuthority, false)
    t.is(snapshot.timers, 0)
    t.is(
      new Set(trace.filter((value) => value.startsWith('destroy:'))).size,
      2,
      'both exact branch owners are destroyed'
    )
  } finally {
    if (fixture) await fixture.close()
  }
})

test('destroy during teardown joins cancellation and reaches zero-state', async (t) => {
  const trace = []
  const held = new Map()
  let fixture
  try {
    fixture = await readySuspendFixture(t, 48151, {
      trace,
      teardownOpenRouteMaterial(material) {
        const operation = deferred()
        held.set(material, operation)
        return operation.promise
      },
      destroyOpenRouteMaterial(material) {
        const operation = held.get(material)
        if (operation) operation.reject(PrivateRouteError.ERR_DESTROYED())
        return true
      }
    })
    const suspending = fixture.controller.suspend()
    await Promise.resolve()
    await Promise.resolve()
    await fixture.controller.destroy()
    await t.exception(suspending)
    const snapshot = fixture.controller.snapshot()
    t.is(snapshot.state, PRIVATE_ROUTING_STATE.DESTROYED)
    t.is(snapshot.routeManager, false)
    t.is(snapshot.guardLease, false)
    t.is(snapshot.reconnect, false)
    t.is(snapshot.endpointSockets, 0)
    t.is(snapshot.timers, 0)
    t.is(snapshot.handles, 0)
    t.is(snapshot.callbacks, 0)
  } finally {
    if (fixture) await fixture.close()
  }
})
