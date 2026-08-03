'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  createEndpointBootstrapAuthority
} = require('../../lib/private/endpoint-bootstrap-authority')
const {
  PRIVATE_ROUTING_STATE,
  TEST_ONLY_PRIVATE_ROUTING_CONTROLLER_ISSUER,
  createPrivateRoutingController
} = require('../../lib/private/private-routing-controller')

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
