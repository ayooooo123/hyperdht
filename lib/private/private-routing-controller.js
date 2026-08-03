'use strict'
const b4a = require('b4a')

const {
  consumeEndpointBootstrapAuthority,
  registerEndpointBootstrapController
} = require('./endpoint-bootstrap-authority')
const {
  consumeInitialBranchBuild,
  consumeReplacementBranchBuild
} = require('./branch-path-authority')
const DHT = require('dht-rpc')
const { consumeBootstrapGuardPin } = require('./bootstrap-io')
const { COMMANDS } = require('../constants')
const { cryptoSuite } = require('./crypto-suite')
const {
  createGuardBranchOpenAuthority,
  createGuardLease,
  destroyGuardLease,
  openGuardBranch
} = require('./guard-lease')
const {
  claimFinalExitActivation,
  createFinalExitActivationClaim,
  driveEndpointFinalExit,
  openFinalExit
} = require('./final-exit-activation')
const { revokeGuardReconnectAuthority } = require('./guard-reconnect-authority')
const { LiveRouteAuthority, createRotatedLiveRouteAuthority } = require('./live-route-authority')
const { openRouteExtension, takeRouteExtensionTransfer } = require('./route-extension')
const { BRANCH_CLASS } = require('./protocol')
const { revokeOpenRouteHandoff } = require('./open-route-handoff')
const { createQueryContexts } = require('./query-context')
const routeManagerModule = require('./route-manager')
const udxModule = require('./udx-cell-endpoint')
const consumeSuspendedDirectory =
  routeManagerModule[Symbol.for('hyperdht-private-routes/suspended-directory-consumer')]
const consumeReconnectedGuardPin =
  udxModule[Symbol.for('hyperdht-private-routes/reconnected-guard-pin-consumer')]
const createResumedRouteManager =
  routeManagerModule[Symbol.for('hyperdht-private-routes/resumed-route-manager-factory')]
const {
  createFinalExitActivationFactory,
  createRouteExtensionFactory,
  createRouteManager,
  createRouteManagerBranchLossRegistration,
  isRouteManager,
  issueRouteManagerBranchPhysicalLoss,
  readRouteManagerGenerations,
  registerRouteManagerLifecycleSinks,
  registerRouteManagerReplacementSinks,
  registerRouteManagerReadySink,
  revokeRouteManagerBranchLossRegistration
} = routeManagerModule
const { destroyTailControlSession } = require('./tail-control')
const { RoutedDHTIO } = require('./routed-dht-io')
const { PrivateRouteError } = require('./errors')
const { destroyBootstrapUdxAuthority } = udxModule
const {
  registerM3RuntimePhysicalLossSink,
  revokeM3RuntimePhysicalLossSink
} = require('./m3-adjacency-runtime')

const PRIVATE_ROUTING_STATE = Object.freeze({
  OFF: 'OFF',
  BOOTSTRAPPING: 'BOOTSTRAPPING',
  GUARD_PINNED: 'GUARD_PINNED',
  BUILDING: 'BUILDING',
  READY: 'READY',
  ROTATING: 'ROTATING',
  SUSPENDED: 'SUSPENDED',
  UNAVAILABLE: 'UNAVAILABLE',
  DESTROYED: 'DESTROYED'
})

const STATES = new WeakMap()
const BUILDERS = new WeakMap()
const SIGNALS = new WeakMap()
const SPENT_SIGNALS = new WeakSet()
const SIGNAL_NAMES = Object.freeze([
  'guardLoss',
  'lookupBranchLoss',
  'announceBranchLoss',
  'lookupBranchExpiry',
  'announceBranchExpiry',
  'wallClockRollback',
  'lookupSeedReady',
  'announceSeedReady',
  'networkChange'
])

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function destroyed() {
  throw PrivateRouteError.ERR_DESTROYED()
}

function unavailable() {
  throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function exactOptions(options) {
  if (!isObject(options) || Object.getPrototypeOf(options) !== Object.prototype) invalid()
  const keys = Reflect.ownKeys(options)
  if (keys.length !== 1 || keys[0] !== 'endpointBootstrapAuthority') invalid()
  const descriptor = Object.getOwnPropertyDescriptor(options, 'endpointBootstrapAuthority')
  if (!descriptor || !Object.hasOwn(descriptor, 'value')) invalid()
}

function stateFor(controller) {
  const state = isObject(controller) ? STATES.get(controller) : null
  if (!state) throw PrivateRouteError.UNAUTHORIZED()
  return state
}

function transition(state, expected, next, effect = null) {
  if (
    state.transitioning ||
    state.destroying ||
    state.state === PRIVATE_ROUTING_STATE.DESTROYED ||
    (Array.isArray(expected) ? !expected.includes(state.state) : state.state !== expected)
  ) {
    if (state.state === PRIVATE_ROUTING_STATE.DESTROYED || state.destroying) destroyed()
    throw PrivateRouteError.CIRCUIT_STATE()
  }
  const token = Object.freeze({})
  const generation = state.generation
  state.transitioning = token
  try {
    if (
      state.transitioning !== token ||
      state.generation !== generation ||
      state.state === PRIVATE_ROUTING_STATE.DESTROYED
    ) {
      destroyed()
    }
    const result = effect === null ? undefined : effect(token, generation)
    if (
      state.transitioning !== token ||
      state.generation !== generation ||
      state.state === PRIVATE_ROUTING_STATE.DESTROYED
    ) {
      destroyed()
    }
    state.state = next
    state.generation = generation + 1n
    return result
  } finally {
    if (state.transitioning === token) state.transitioning = null
  }
}

function packetAuthority(state) {
  switch (state.state) {
    case PRIVATE_ROUTING_STATE.BOOTSTRAPPING:
      return 'bounded-bootstrap'
    case PRIVATE_ROUTING_STATE.GUARD_PINNED:
    case PRIVATE_ROUTING_STATE.BUILDING:
    case PRIVATE_ROUTING_STATE.READY:
    case PRIVATE_ROUTING_STATE.ROTATING:
      return 'pinned-guard'
    default:
      return 'none'
  }
}

function packetEdges(state) {
  switch (state.state) {
    case PRIVATE_ROUTING_STATE.BOOTSTRAPPING:
      return ['configured-bootstrap', 'prospective-guard']
    case PRIVATE_ROUTING_STATE.GUARD_PINNED:
    case PRIVATE_ROUTING_STATE.BUILDING:
    case PRIVATE_ROUTING_STATE.READY:
    case PRIVATE_ROUTING_STATE.ROTATING:
      return ['pinned-guard']
    default:
      return []
  }
}

function closeEndpointResources(resources) {
  if (!resources) return Promise.resolve()
  try {
    resources.bootstrapIO.destroy()
  } catch {}
  try {
    destroyBootstrapUdxAuthority(resources.bootstrapUdxAuthority)
  } catch {}
  try {
    return Promise.resolve(resources.endpoint.close()).catch(() => {})
  } catch {
    return Promise.resolve()
  }
}

function takeSealedEndpointResources(state) {
  if (!state.endpointBootstrapAuthority || !state.controllerRegistration) return null
  const authority = state.endpointBootstrapAuthority
  const registration = state.controllerRegistration
  state.endpointBootstrapAuthority = null
  state.controllerRegistration = null
  return consumeEndpointBootstrapAuthority(authority, registration)
}

function createSignal(state, kind, generation = state.signalGeneration) {
  const sink = Object.freeze({})
  SIGNALS.set(sink, {
    state,
    kind,
    generation,
    consumed: false
  })
  state.signalSinks.add(sink)
  return sink
}

function createSignalSet(state) {
  const sinks = {}
  for (const name of SIGNAL_NAMES) sinks[name] = createSignal(state, name)
  return Object.freeze(sinks)
}

function revokeSignal(state, sink) {
  const signal = isObject(sink) ? SIGNALS.get(sink) : null
  if (!signal || signal.state !== state) return false
  signal.consumed = true
  SIGNALS.delete(sink)
  SPENT_SIGNALS.add(sink)
  state.signalSinks.delete(sink)
  return true
}

function revokeSignals(state) {
  for (const sink of Array.from(state.signalSinks)) revokeSignal(state, sink)
}

async function handleQueuedSignal(signal) {
  const state = signal.state
  if (
    state.state === PRIVATE_ROUTING_STATE.DESTROYED ||
    state.destroying ||
    signal.generation !== state.signalGeneration
  ) {
    return false
  }
  switch (signal.kind) {
    case 'guardLoss':
    case 'wallClockRollback':
    case 'networkChange':
      if (
        state.state === PRIVATE_ROUTING_STATE.GUARD_PINNED ||
        state.state === PRIVATE_ROUTING_STATE.BUILDING ||
        state.state === PRIVATE_ROUTING_STATE.READY ||
        state.state === PRIVATE_ROUTING_STATE.ROTATING ||
        state.state === PRIVATE_ROUTING_STATE.SUSPENDED
      ) {
        await enterUnavailable(state)
        return true
      }
      return false
    case 'lookupBranchLoss':
    case 'announceBranchLoss':
    case 'lookupBranchExpiry':
    case 'announceBranchExpiry': {
      if (state.state !== PRIVATE_ROUTING_STATE.READY || !state.routeManager) return false
      const branchClass = signal.kind.startsWith('lookup')
        ? BRANCH_CLASS.LOOKUP
        : BRANCH_CLASS.ANNOUNCE
      let authority = null
      try {
        authority = transition(
          state,
          PRIVATE_ROUTING_STATE.READY,
          PRIVATE_ROUTING_STATE.ROTATING,
          () => {
            registerRouteManagerReadySink(state.routeManager, createSignal(state, 'pairReady'))
            state.routeManager.rotate(branchClass)
            registerReplacementLifecycle(state, state.routeManager, branchClass)
            state.rotationBranch = branchClass
            return state.routeManager.claimReplacementBuild(branchClass)
          }
        )
      } catch (err) {
        state.rotationBranch = null
        await enterUnavailable(state)
        throw err
      }
      state.branchBuildPromise = coordinateReplacementRouteBuild(state, authority, branchClass)
      void state.branchBuildPromise.catch(() => {})
      return true
    }
    case 'pairReady':
      if (
        state.state !== PRIVATE_ROUTING_STATE.BUILDING &&
        state.state !== PRIVATE_ROUTING_STATE.ROTATING
      )
        return false
      await installReadyGeneration(state)
      return true
    case 'lookupSeedReady':
    case 'announceSeedReady':
      return false
    default:
      return false
  }
}

function issuePrivateRoutingControllerSignal(sink) {
  if (arguments.length !== 1) invalid()
  const signal = isObject(sink) ? SIGNALS.get(sink) : null
  if (!signal) {
    if (isObject(sink) && SPENT_SIGNALS.has(sink)) replaySignal()
    throw PrivateRouteError.UNAUTHORIZED()
  }
  if (signal.consumed) replaySignal()
  const state = signal.state
  signal.consumed = true
  SIGNALS.delete(sink)
  SPENT_SIGNALS.add(sink)
  state.signalSinks.delete(sink)
  state.queuedTransitions++
  Promise.resolve().then(async () => {
    try {
      await handleQueuedSignal(signal)
    } catch (err) {
      if (state.readyReject) {
        const reject = state.readyReject
        state.readyResolve = null
        state.readyReject = null
        reject(err)
      }
      if (state.state === PRIVATE_ROUTING_STATE.BUILDING) {
        if (state.routeManager) {
          try {
            state.routeManager.destroy()
          } catch {}
          state.routeManager = null
          state.guardLease = null
        }
        transition(state, PRIVATE_ROUTING_STATE.BUILDING, PRIVATE_ROUTING_STATE.UNAVAILABLE)
      }
    } finally {
      state.queuedTransitions--
    }
  })
  return true
}

function replaySignal() {
  throw PrivateRouteError.ERR_REPLAY()
}

const TEST_ONLY_PRIVATE_ROUTING_CONTROLLER_ISSUER = Object.freeze({
  sinks(controller) {
    return stateFor(controller).testSignals
  },
  issue(controller, sink) {
    if (arguments.length !== 2) invalid()
    const state = stateFor(controller)
    const signal = isObject(sink) ? SIGNALS.get(sink) : null
    if (!signal) {
      if (isObject(sink) && SPENT_SIGNALS.has(sink)) replaySignal()
      throw PrivateRouteError.UNAUTHORIZED()
    }
    if (signal.state !== state) throw PrivateRouteError.UNAUTHORIZED()
    return issuePrivateRoutingControllerSignal(sink)
  },
  registerManager(controller, manager) {
    const state = stateFor(controller)
    if (
      state.state !== PRIVATE_ROUTING_STATE.OFF ||
      state.routeManager !== null ||
      !isRouteManager(manager)
    )
      throw PrivateRouteError.CIRCUIT_STATE()
    const resources = takeSealedEndpointResources(state)
    state.endpointResources = resources
    state.monotonicNow = resources.monotonicNow
    state.randomBytes = resources.randomBytes
    state.cancelScheduled = resources.cancelScheduled
    state.wallNow = resources.wallNow
    state.schedule = resources.schedule
    state.routeManager = manager
    state.testManualBuild = true
    registerManagerLifecycle(state, manager)
    transition(state, PRIVATE_ROUTING_STATE.OFF, PRIVATE_ROUTING_STATE.BUILDING)
    registerRouteManagerReadySink(manager, createSignal(state, 'pairReady'))
    const builder = Object.freeze({})
    BUILDERS.set(builder, { state, manager })
    state.builderCapability = builder
    return builder
  },
  builder(controller) {
    const state = stateFor(controller)
    if (state.state !== PRIVATE_ROUTING_STATE.BUILDING) throw PrivateRouteError.CIRCUIT_STATE()
    if (state.builderCapability) return state.builderCapability
    const builder = Object.freeze({})
    BUILDERS.set(builder, { state, manager: state.routeManager })
    state.builderCapability = builder
    return builder
  },
  publishInitialPair(controller, builder, handoffs) {
    const state = stateFor(controller)
    const record = isObject(builder) ? BUILDERS.get(builder) : null
    if (!record || record.state !== state || record.manager !== state.routeManager)
      throw PrivateRouteError.UNAUTHORIZED()
    return record.manager.publishInitialPair(handoffs)
  },
  createDhtSeedAdmission(controller, builder, branchClass, owner) {
    const state = stateFor(controller)
    const record = isObject(builder) ? BUILDERS.get(builder) : null
    if (!record || record.state !== state || record.manager !== state.routeManager)
      throw PrivateRouteError.UNAUTHORIZED()
    return record.manager.createDhtSeedAdmission(branchClass, owner)
  },
  publishInitialSeedPair(controller, builder, readiness) {
    const state = stateFor(controller)
    const record = isObject(builder) ? BUILDERS.get(builder) : null
    if (!record || record.state !== state || record.manager !== state.routeManager)
      throw PrivateRouteError.UNAUTHORIZED()
    const result = record.manager.publishInitialSeedPair(readiness)
    BUILDERS.delete(builder)
    state.builderCapability = null
    return result
  },
  buildFailure(controller) {
    return stateFor(controller).branchBuildError
  }
})

function createRouteFactories(resources) {
  const options = {
    wallNow: resources.wallNow,
    monotonicNow: resources.monotonicNow,
    randomBytes: resources.randomBytes,
    schedule: resources.schedule,
    cancelScheduled: resources.cancelScheduled
  }
  return {
    extensionFactory: createRouteExtensionFactory(options),
    terminalFactory: createFinalExitActivationFactory(options)
  }
}
function registerManagerLifecycle(state, manager) {
  registerRouteManagerLifecycleSinks(manager, {
    lookupBranchLoss: state.testSignals.lookupBranchLoss,
    announceBranchLoss: state.testSignals.announceBranchLoss,
    lookupBranchExpiry: state.testSignals.lookupBranchExpiry,
    announceBranchExpiry: state.testSignals.announceBranchExpiry,
    wallClockRollback: state.testSignals.wallClockRollback
  })
}

function registerReplacementLifecycle(state, manager, branchClass) {
  if (branchClass === BRANCH_CLASS.LOOKUP) {
    registerRouteManagerReplacementSinks(manager, branchClass, {
      lookupBranchLoss: createSignal(state, 'lookupBranchLoss'),
      lookupBranchExpiry: createSignal(state, 'lookupBranchExpiry')
    })
  } else {
    registerRouteManagerReplacementSinks(manager, branchClass, {
      announceBranchLoss: createSignal(state, 'announceBranchLoss'),
      announceBranchExpiry: createSignal(state, 'announceBranchExpiry')
    })
  }
}
function loseBranchConnection(state, branchClass, connection) {
  if (!connection || connection.lost) return false
  connection.lost = true
  connection.physicalLossRegistration = null
  const managerRegistration = connection.managerLossRegistration
  connection.managerLossRegistration = null
  if (state.branchConnections.get(branchClass) === connection) {
    state.branchConnections.delete(branchClass)
  }
  if (managerRegistration) {
    issueRouteManagerBranchPhysicalLoss(managerRegistration)
  } else if (
    !state.destroying &&
    state.state !== PRIVATE_ROUTING_STATE.DESTROYED &&
    state.state !== PRIVATE_ROUTING_STATE.UNAVAILABLE
  ) {
    void enterUnavailable(state)
  }
  return true
}

function createBranchConnection(state, branchClass, guardTail) {
  const connection = {
    runtime: guardTail.runtime,
    adjacencyAuthority: guardTail.adjacencyAuthority,
    physicalLossRegistration: null,
    managerLossRegistration: null,
    lost: false
  }
  return connection
}

function commitBranchConnection(state, branchClass, connection) {
  if (
    !connection ||
    connection.lost ||
    connection.managerLossRegistration ||
    connection.physicalLossRegistration
  ) {
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
  connection.managerLossRegistration = createRouteManagerBranchLossRegistration(
    state.routeManager,
    branchClass
  )
  try {
    connection.physicalLossRegistration = registerM3RuntimePhysicalLossSink(
      connection.runtime,
      () => loseBranchConnection(state, branchClass, connection)
    )
  } catch (err) {
    revokeRouteManagerBranchLossRegistration(connection.managerLossRegistration)
    connection.managerLossRegistration = null
    throw err
  }
  return true
}

function destroyBranchConnection(connection) {
  if (!connection) return false
  if (connection.physicalLossRegistration) {
    revokeM3RuntimePhysicalLossSink(connection.physicalLossRegistration)
    connection.physicalLossRegistration = null
  }
  if (connection.managerLossRegistration) {
    revokeRouteManagerBranchLossRegistration(connection.managerLossRegistration)
    connection.managerLossRegistration = null
  }
  connection.lost = true
  if (connection.tailControl) {
    try {
      destroyTailControlSession(connection.tailControl)
    } catch {}
  }
  if (connection.runtime) {
    try {
      connection.runtime.destroy()
    } catch {}
  }
  if (connection.adjacencyAuthority) {
    try {
      connection.adjacencyAuthority.destroy()
    } catch {}
  }
  return true
}

function clearBranchConnections(state) {
  for (const connection of state.branchConnections.values()) {
    destroyBranchConnection(connection)
  }
  state.branchConnections.clear()
}

async function openInitialBranch(state, build, branchClass, issuerIndex) {
  const branchKey = branchClass === BRANCH_CLASS.LOOKUP ? 'lookup' : 'announce'
  const branch = build.branches[branchKey]
  const selections = build.selections[branchKey]
  const exitPayloadParameters = branch.exit.payloadParameters
  const openAuthority = createGuardBranchOpenAuthority(state.guardLease, {
    branch,
    issuer: build.issuers[issuerIndex],
    absoluteDeadline: build.absoluteDeadline
  })
  const guardTail = await openGuardBranch(state.guardLease, openAuthority)
  const connection = createBranchConnection(state, branchClass, guardTail)
  state.branchConnections.set(branchClass, connection)
  const routeExpiresAt = guardTail.requestedLimits.expiresAtMs
  let tailControl = guardTail.tailControl
  for (const [position, extensionIndex] of [
    ['middle', 1],
    ['exit', 2]
  ]) {
    const transfer = await openRouteExtension(state.routeFactories.extensionFactory, {
      transaction: build.transaction,
      selection: selections[position],
      branchClass,
      position,
      generation: branch.generation,
      extensionIndex,
      limits: guardTail.limits,
      absoluteDeadline: build.absoluteDeadline,
      signedExpiry:
        branch[position].expiresAt < routeExpiresAt ? branch[position].expiresAt : routeExpiresAt,
      cancel() {},
      tailControl
    })
    tailControl = takeRouteExtensionTransfer(transfer).tailControl
  }
  const finalHandoff = tailControl.takeFinalExitHandoff()
  const claim = createFinalExitActivationClaim(finalHandoff)
  const activationOwner = claimFinalExitActivation(finalHandoff, claim)
  const finalSession = openFinalExit(state.routeFactories.terminalFactory, {
    handoff: activationOwner,
    crypto: cryptoSuite,
    payloadParameters: exitPayloadParameters,
    readySigner: undefined
  })
  const openHandoff = await driveEndpointFinalExit(finalSession)
  return openHandoff
}

async function openReplacementBranch(state, build, branchClass) {
  const branch = build.branch
  if (!branch || branch.branchClass !== branchClass) throw PrivateRouteError.UNAUTHORIZED()
  const exitPayloadParameters = branch.exit.payloadParameters
  const openAuthority = createGuardBranchOpenAuthority(state.guardLease, {
    branch,
    issuer: build.issuers[0],
    absoluteDeadline: build.absoluteDeadline
  })
  let guardTail = null
  let connection = null
  try {
    guardTail = await openGuardBranch(state.guardLease, openAuthority)
    connection = createBranchConnection(state, branchClass, guardTail)
    const routeExpiresAt = guardTail.requestedLimits.expiresAtMs
    let tailControl = guardTail.tailControl
    for (const [position, extensionIndex] of [
      ['middle', 1],
      ['exit', 2]
    ]) {
      const transfer = await openRouteExtension(state.routeFactories.extensionFactory, {
        transaction: build.transaction,
        selection: build.selections[position],
        branchClass,
        position,
        generation: branch.generation,
        extensionIndex,
        limits: guardTail.limits,
        absoluteDeadline: build.absoluteDeadline,
        signedExpiry:
          branch[position].expiresAt < routeExpiresAt ? branch[position].expiresAt : routeExpiresAt,
        cancel() {},
        tailControl
      })
      tailControl = takeRouteExtensionTransfer(transfer).tailControl
    }
    const finalHandoff = tailControl.takeFinalExitHandoff()
    const claim = createFinalExitActivationClaim(finalHandoff)
    const activationOwner = claimFinalExitActivation(finalHandoff, claim)
    const finalSession = openFinalExit(state.routeFactories.terminalFactory, {
      handoff: activationOwner,
      crypto: cryptoSuite,
      payloadParameters: exitPayloadParameters,
      readySigner: undefined
    })
    const openHandoff = await driveEndpointFinalExit(finalSession)
    return Object.freeze({ openHandoff, connection })
  } catch (err) {
    destroyBranchConnection(connection || guardTail)
    throw err
  }
}

async function coordinateInitialRouteBuild(state, authority) {
  const build = consumeInitialBranchBuild(authority)
  state.branchBuild = build
  let lookup = null
  let announce = null
  try {
    lookup = await openInitialBranch(state, build, BRANCH_CLASS.LOOKUP, 0)
    announce = await openInitialBranch(state, build, BRANCH_CLASS.ANNOUNCE, 1)
    state.routeManager.publishInitialPair(Object.freeze({ lookup, announce }))
    lookup = null
    announce = null
    await state.routeManager.receiveInitialSeedPair()
    commitBranchConnection(
      state,
      BRANCH_CLASS.LOOKUP,
      state.branchConnections.get(BRANCH_CLASS.LOOKUP)
    )
    commitBranchConnection(
      state,
      BRANCH_CLASS.ANNOUNCE,
      state.branchConnections.get(BRANCH_CLASS.ANNOUNCE)
    )
  } catch (err) {
    if (lookup) {
      try {
        revokeOpenRouteHandoff(lookup)
      } catch {}
    }
    if (announce) {
      try {
        revokeOpenRouteHandoff(announce)
      } catch {}
    }
    clearBranchConnections(state)
    state.branchBuildError = err
    if (!state.destroying && state.state !== PRIVATE_ROUTING_STATE.DESTROYED) {
      await enterUnavailable(state)
    }
    throw err
  } finally {
    state.branchBuild = null
  }
}

async function coordinateReplacementRouteBuild(state, authority, branchClass) {
  const build = consumeReplacementBranchBuild(authority)
  state.branchBuild = build
  let opened = null
  let published = false
  try {
    opened = await openReplacementBranch(state, build, branchClass)
    state.routeManager.publishRotation(branchClass, opened.openHandoff)
    published = true
    await state.routeManager.receiveRotationSeed(branchClass)
    commitBranchConnection(state, branchClass, opened.connection)
    const previous = state.branchConnections.get(branchClass)
    state.branchConnections.set(branchClass, opened.connection)
    opened = null
    destroyBranchConnection(previous)
    return true
  } catch (err) {
    if (opened) {
      if (!published) {
        try {
          revokeOpenRouteHandoff(opened.openHandoff)
        } catch {}
      }
      destroyBranchConnection(opened.connection)
    }
    state.branchBuildError = err
    if (!state.destroying && state.state !== PRIVATE_ROUTING_STATE.DESTROYED) {
      await enterUnavailable(state)
    }
    throw err
  } finally {
    state.branchBuild = null
  }
}

function beginRouteBuild(state, resources, guardPin) {
  return beginRouteBuildWithTransfer(state, resources, consumeBootstrapGuardPin(guardPin))
}

function beginRouteBuildWithTransfer(state, resources, transfer, generations = null) {
  let guardLease = null
  let routeManager = null
  try {
    revokeSignals(state)
    state.signalGeneration++
    state.testSignals = createSignalSet(state)
    const guardLossSink = state.testSignals.guardLoss
    guardLease = createGuardLease({
      guardLeaseMaterial: transfer.guardLeaseMaterial,
      pinnedGuard: transfer.pinnedGuard,
      wallNow: resources.wallNow,
      monotonicNow: resources.monotonicNow,
      setTimer: resources.schedule,
      clearTimer: resources.cancelScheduled,
      guardLossSink
    })
    state.guardLease = guardLease
    state.endpointResources = null
    transition(state, PRIVATE_ROUTING_STATE.BOOTSTRAPPING, PRIVATE_ROUTING_STATE.GUARD_PINNED)
    const factories = (state.routeFactories = createRouteFactories(resources))
    const managerOptions = {
      guardLease,
      candidateDirectory: transfer.candidateDirectory,
      extensionFactory: factories.extensionFactory,
      terminalFactory: factories.terminalFactory,
      monotonicNow: resources.monotonicNow,
      randomBytes: resources.randomBytes
    }
    routeManager =
      generations === null
        ? createRouteManager(managerOptions)
        : createResumedRouteManager({
            managerOptions,
            lookupGeneration: generations.lookupGeneration,
            announceGeneration: generations.announceGeneration
          })
    state.routeManager = routeManager
    registerManagerLifecycle(state, routeManager)
    registerRouteManagerReadySink(routeManager, createSignal(state, 'pairReady'))
    routeManager.buildInitialPair()
    if (!state.testManualBuild) {
      const buildAuthority = routeManager.claimInitialBuild()
      state.branchBuildPromise = coordinateInitialRouteBuild(state, buildAuthority)
      void state.branchBuildPromise.catch(() => {})
    }
    transition(state, PRIVATE_ROUTING_STATE.GUARD_PINNED, PRIVATE_ROUTING_STATE.BUILDING)
    return true
  } catch (err) {
    if (routeManager) {
      try {
        routeManager.destroy()
      } catch {}
    } else {
      if (guardLease) destroyGuardLease(guardLease)
      try {
        transfer.candidateDirectory.destroy()
      } catch {}
    }
    state.guardLease = null
    state.routeManager = null
    throw err
  }
}

async function destroyOwnedTransport(dht, routed, authority, queries) {
  for (const query of queries) {
    if (typeof query.finished === 'function') {
      try {
        void Promise.resolve(query.finished()).catch(() => {})
      } catch {}
    }
    try {
      query.destroy(PrivateRouteError.ERR_DESTROYED())
    } catch {}
  }
  if (dht) {
    try {
      await dht.destroy()
    } catch {}
  } else if (routed) {
    try {
      await routed.destroy()
    } catch {}
  }
  if (authority) {
    try {
      authority.destroy()
    } catch {}
  }
}

async function destroyTransportGeneration(state) {
  const dht = state.transportDHT
  const routed = state.routedDHTIO
  const authority = state.liveRouteAuthority
  const queries = []
  for (const [query, owner] of state.activeQueries) {
    if (owner !== dht) continue
    state.activeQueries.delete(query)
    queries.push(query)
  }
  state.transportDHT = null
  state.routedDHTIO = null
  state.liveRouteAuthority = null
  state.queryContexts = null
  await destroyOwnedTransport(dht, routed, authority, queries)
}

async function enterUnavailable(state) {
  state.rotationBranch = null
  const endpointResources = state.endpointResources
  state.endpointResources = null
  if (state.state === PRIVATE_ROUTING_STATE.BOOTSTRAPPING) {
    transition(state, PRIVATE_ROUTING_STATE.BOOTSTRAPPING, PRIVATE_ROUTING_STATE.UNAVAILABLE)
  }
  await closeEndpointResources(endpointResources)
  await destroyTransportGeneration(state)
  clearBranchConnections(state)
  if (state.routeManager) {
    try {
      state.routeManager.destroy()
    } catch {}
    state.routeManager = null
    state.guardLease = null
  } else if (state.guardLease) {
    destroyGuardLease(state.guardLease)
    state.guardLease = null
  }
  if (state.reconnect) {
    try {
      revokeGuardReconnectAuthority(state.reconnect, 'unavailable')
    } catch {}
    state.reconnect = null
  }
  if (state.suspendedDirectory) {
    try {
      state.suspendedDirectory.destroy()
    } catch {}
    state.suspendedDirectory = null
    state.resumeGenerations = null
  }
  if (state.readyReject) {
    const reject = state.readyReject
    state.readyResolve = null
    state.readyReject = null
    reject(state.branchBuildError || PrivateRouteError.ERR_PRIVACY_UNAVAILABLE())
  }
  if (
    state.state !== PRIVATE_ROUTING_STATE.UNAVAILABLE &&
    state.state !== PRIVATE_ROUTING_STATE.DESTROYED
  )
    transition(state, state.state, PRIVATE_ROUTING_STATE.UNAVAILABLE)
}

async function installReadyGeneration(state) {
  if (
    state.state !== PRIVATE_ROUTING_STATE.BUILDING &&
    state.state !== PRIVATE_ROUTING_STATE.ROTATING
  )
    throw PrivateRouteError.CIRCUIT_STATE()
  if (!state.routeManager || !state.routeManager.ready()) unavailable()
  const expected = state.state
  const committedGenerations = readRouteManagerGenerations(state.routeManager)
  const oldDht = state.transportDHT
  const oldRouted = state.routedDHTIO
  const oldAuthority = state.liveRouteAuthority
  const oldQueries = []
  let authority = null
  let routed = null
  let dht = null
  try {
    if (expected === PRIVATE_ROUTING_STATE.ROTATING && oldDht) {
      const draining = []
      for (const [query, owner] of state.activeQueries) {
        if (owner !== oldDht || typeof query.finished !== 'function') continue
        draining.push(
          Promise.resolve()
            .then(() => query.finished())
            .catch(() => {})
        )
      }
      await Promise.all(draining)
    }
    authority =
      expected === PRIVATE_ROUTING_STATE.ROTATING
        ? createRotatedLiveRouteAuthority(oldAuthority, state.routeManager, state.rotationBranch)
        : new LiveRouteAuthority({ routeManager: state.routeManager })
    const contexts = createQueryContexts()
    routed = new RoutedDHTIO({
      authority,
      contexts,
      now: () => Number(state.monotonicNow()),
      randomBytes(buffer) {
        const random = state.randomBytes(buffer.byteLength)
        if (!b4a.isBuffer(random) || random.byteLength !== buffer.byteLength) invalid()
        buffer.set(random)
        random.fill(0)
      }
    })
    await routed.ready()
    dht = new DHT({
      outboundPolicy: 'transport-only',
      requestTransport: routed,
      requestTimeout: 3000,
      concurrency: 1
    })
    state.liveRouteAuthority = authority
    state.routedDHTIO = routed
    state.transportDHT = dht
    state.queryContexts = contexts
    state.lookupGeneration = committedGenerations.lookupGeneration
    state.announceGeneration = committedGenerations.announceGeneration
    transition(state, expected, PRIVATE_ROUTING_STATE.READY)
    state.rotationBranch = null
    for (const [query, owner] of state.activeQueries) {
      if (owner !== oldDht) continue
      state.activeQueries.delete(query)
      oldQueries.push(query)
    }
    await destroyOwnedTransport(oldDht, oldRouted, oldAuthority, oldQueries)
    if (state.readyResolve) {
      const resolve = state.readyResolve
      state.readyResolve = null
      state.readyReject = null
      resolve(true)
    }
    return true
  } catch (err) {
    if (dht) {
      try {
        await dht.destroy()
      } catch {}
    } else if (routed) {
      try {
        await routed.destroy()
      } catch {}
    }
    if (authority) {
      try {
        authority.destroy()
      } catch {}
    }
    state.branchBuildError = err
    await enterUnavailable(state)
    throw err
  }
}

class PrivateRoutingController {
  start() {
    const state = stateFor(this)
    if (state.state === PRIVATE_ROUTING_STATE.DESTROYED || state.destroying) destroyed()
    if (state.startPromise !== null) return state.startPromise
    if (state.state !== PRIVATE_ROUTING_STATE.OFF) throw PrivateRouteError.CIRCUIT_STATE()
    const resources = transition(
      state,
      PRIVATE_ROUTING_STATE.OFF,
      PRIVATE_ROUTING_STATE.BOOTSTRAPPING,
      () => takeSealedEndpointResources(state)
    )
    state.endpointResources = resources
    state.monotonicNow = resources.monotonicNow
    state.randomBytes = resources.randomBytes
    state.cancelScheduled = resources.cancelScheduled
    state.wallNow = resources.wallNow
    state.schedule = resources.schedule
    state.readyPromise = new Promise((resolve, reject) => {
      state.readyResolve = resolve
      state.readyReject = reject
    })
    void state.readyPromise.catch(() => {})
    state.startPromise = Promise.resolve()
      .then(() => resources.endpoint.bind())
      .then(() => resources.bootstrapIO.start())
      .then((guardPin) => {
        beginRouteBuild(state, resources, guardPin)
        return state.readyPromise
      })
      .catch(async (err) => {
        if (state.readyReject) {
          const reject = state.readyReject
          state.readyResolve = null
          state.readyReject = null
          reject(err)
        }
        if (state.state !== PRIVATE_ROUTING_STATE.DESTROYED && !state.destroying) {
          const owned = state.endpointResources
          state.endpointResources = null
          await closeEndpointResources(owned)
          if (state.routeManager) {
            try {
              state.routeManager.destroy()
            } catch {}
            state.routeManager = null
            state.guardLease = null
          } else if (state.guardLease) {
            destroyGuardLease(state.guardLease)
            state.guardLease = null
          }
          if (state.state !== PRIVATE_ROUTING_STATE.UNAVAILABLE) {
            transition(state, state.state, PRIVATE_ROUTING_STATE.UNAVAILABLE)
          }
        }
        throw err
      })
    return state.startPromise
  }

  async immutableGet(target) {
    const state = stateFor(this)
    if (state.state === PRIVATE_ROUTING_STATE.DESTROYED || state.destroying) {
      throw PrivateRouteError.ERR_DESTROYED()
    }
    if (state.state === PRIVATE_ROUTING_STATE.ROTATING) {
      throw PrivateRouteError.ERR_PRIVATE_BRANCH_ROTATING()
    }
    if (
      state.state !== PRIVATE_ROUTING_STATE.READY ||
      !state.transportDHT ||
      !state.queryContexts ||
      !b4a.isBuffer(target) ||
      target.byteLength !== 32
    ) {
      unavailable()
    }
    const query = state.transportDHT.query(
      { target, command: COMMANDS.IMMUTABLE_GET, value: null },
      {
        transportContext: state.queryContexts.immutableGet.lookup,
        concurrency: 1,
        retries: 1
      }
    )
    state.activeQueries.set(query, state.transportDHT)
    try {
      for await (const response of query) {
        if (!response || response.value === null || response.value === undefined) continue
        if (!b4a.isBuffer(response.value)) throw PrivateRouteError.ERR_AUTHENTICATION()
        const digest = cryptoSuite.hash([response.value])
        const valid = b4a.equals(digest, target)
        digest.fill(0)
        if (!valid) throw PrivateRouteError.ERR_AUTHENTICATION()
        return Object.freeze({
          value: b4a.from(response.value),
          from: response.from
        })
      }
      unavailable()
    } finally {
      state.activeQueries.delete(query)
      try {
        query.destroy()
      } catch {}
      if (typeof query.finished === 'function') {
        try {
          await query.finished()
        } catch {}
      }
    }
  }

  suspend() {
    const state = stateFor(this)
    if (state.state === PRIVATE_ROUTING_STATE.DESTROYED || state.destroying) destroyed()
    if (state.suspendPromise !== null) return state.suspendPromise
    if (state.state !== PRIVATE_ROUTING_STATE.READY || !state.routeManager) unavailable()
    const operation = (async () => {
      await destroyTransportGeneration(state)
      let reconnect = null
      try {
        reconnect = state.routeManager.suspend()
        const retained = consumeSuspendedDirectory(reconnect)
        state.suspendedDirectory = retained.directory
        state.resumeGenerations = Object.freeze({
          lookupGeneration: retained.lookupGeneration,
          announceGeneration: retained.announceGeneration
        })
        state.reconnect = reconnect
      } catch (err) {
        if (reconnect) {
          try {
            revokeGuardReconnectAuthority(reconnect, err)
          } catch {}
        }
        if (state.suspendedDirectory) {
          try {
            state.suspendedDirectory.destroy()
          } catch {}
          state.suspendedDirectory = null
        }
        state.resumeGenerations = null
        state.routeManager = null
        state.guardLease = null
        await enterUnavailable(state)
        throw err
      } finally {
        state.routeManager = null
        state.guardLease = null
      }
      state.signalGeneration++
      revokeSignals(state)
      state.testSignals = createSignalSet(state)
      transition(state, PRIVATE_ROUTING_STATE.READY, PRIVATE_ROUTING_STATE.SUSPENDED)
      return true
    })()
    state.suspendPromise = operation
    void operation
      .finally(() => {
        if (state.suspendPromise === operation) state.suspendPromise = null
      })
      .catch(() => {})
    return operation
  }

  async resume() {
    const state = stateFor(this)
    if (state.state === PRIVATE_ROUTING_STATE.DESTROYED || state.destroying) destroyed()
    if (
      state.state !== PRIVATE_ROUTING_STATE.SUSPENDED ||
      !state.reconnect ||
      !state.suspendedDirectory
    )
      unavailable()
    const reconnect = state.reconnect
    const directory = state.suspendedDirectory
    state.reconnect = null
    transition(state, PRIVATE_ROUTING_STATE.SUSPENDED, PRIVATE_ROUTING_STATE.BOOTSTRAPPING)
    state.readyPromise = new Promise((resolve, reject) => {
      state.readyResolve = resolve
      state.readyReject = reject
    })
    void state.readyPromise.catch(() => {})
    let transfer = null
    try {
      const capability = await reconnect.reconnect()
      const moved = consumeReconnectedGuardPin(capability)
      try {
        moved.candidateDirectory.destroy()
      } catch {}
      transfer = Object.freeze({
        guardLeaseMaterial: moved.guardLeaseMaterial,
        pinnedGuard: moved.pinnedGuard,
        candidateDirectory: directory
      })
      directory.resume()
      state.suspendedDirectory = null
      beginRouteBuildWithTransfer(state, state, transfer, state.resumeGenerations)
      transfer = null
      state.resumeGenerations = null
      await state.readyPromise
      return true
    } catch (err) {
      state.resumeGenerations = null
      state.readyResolve = null
      state.readyReject = null
      if (transfer) {
        try {
          udxModule.destroyGuardLeaseMaterial(transfer.guardLeaseMaterial)
        } catch {}
        try {
          transfer.candidateDirectory.destroy()
        } catch {}
      }
      try {
        revokeGuardReconnectAuthority(reconnect, err)
      } catch {}
      await enterUnavailable(state)
      throw err
    }
  }

  async networkChanged() {
    const state = stateFor(this)
    if (state.state === PRIVATE_ROUTING_STATE.DESTROYED || state.destroying) return false
    if (state.state === PRIVATE_ROUTING_STATE.OFF) {
      const resources = transition(
        state,
        PRIVATE_ROUTING_STATE.OFF,
        PRIVATE_ROUTING_STATE.UNAVAILABLE,
        () => takeSealedEndpointResources(state)
      )
      await closeEndpointResources(resources)
      return true
    }
    if (state.reconnect) {
      const reconnect = state.reconnect
      state.reconnect = null
      try {
        revokeGuardReconnectAuthority(reconnect, 'network-change')
      } catch {}
    }
    await enterUnavailable(state)
    return true
  }

  snapshot() {
    const state = stateFor(this)
    return Object.freeze({
      state: state.state,
      generation: state.generation,
      endpointAuthority: packetAuthority(state),
      packetEdges: Object.freeze(packetEdges(state)),
      lookupGeneration: state.lookupGeneration,
      announceGeneration: state.announceGeneration,
      activeQueries: state.activeQueries.size,
      transportDHT: state.transportDHT !== null,
      routedDHTIO: state.routedDHTIO !== null,
      liveRouteAuthority: state.liveRouteAuthority !== null,
      routeManager: state.routeManager !== null,
      guardLease: state.guardLease !== null,
      reconnect: state.reconnect !== null,
      endpointSockets: state.endpointResources === null ? 0 : 1,
      handles: state.handles,
      queues: state.queuedTransitions,
      tables: state.tables,
      callbacks: state.callbacks,
      timers: state.timers.size,
      secretBytes: state.secretBytes
    })
  }

  destroy() {
    const state = stateFor(this)
    if (state.destroyPromise !== null) return state.destroyPromise
    state.destroying = true
    state.destroyPromise = Promise.resolve().then(async () => {
      let resources = state.endpointResources
      state.endpointResources = null
      if (!resources) {
        try {
          resources = takeSealedEndpointResources(state)
        } catch {}
      }
      if (state.readyReject) {
        const reject = state.readyReject
        state.readyResolve = null
        state.readyReject = null
        reject(PrivateRouteError.ERR_DESTROYED())
      }
      await destroyTransportGeneration(state)
      clearBranchConnections(state)
      revokeSignals(state)
      if (state.routeManager) {
        try {
          state.routeManager.destroy()
        } catch {}
        state.routeManager = null
      }
      state.guardLease = null
      if (state.reconnect) {
        try {
          revokeGuardReconnectAuthority(state.reconnect, 'destroy')
        } catch {}
      }
      const suspendedDirectory = state.suspendedDirectory
      state.suspendedDirectory = null
      if (suspendedDirectory) {
        try {
          suspendedDirectory.destroy()
        } catch {}
      }
      state.resumeGenerations = null
      if (state.builderCapability) {
        BUILDERS.delete(state.builderCapability)
        state.builderCapability = null
      }
      state.reconnect = null
      await closeEndpointResources(resources)
      for (const handle of state.timers) {
        try {
          state.cancelScheduled(handle)
        } catch {}
      }
      state.timers.clear()
      state.handles = 0
      state.queuedTransitions = 0
      state.tables = 0
      state.callbacks = 0
      state.secretBytes = 0
      state.lookupGeneration = null
      state.announceGeneration = null
      state.rotationBranch = null
      state.destroying = false
      const prior = state.state
      transition(state, prior, PRIVATE_ROUTING_STATE.DESTROYED)
    })
    return state.destroyPromise
  }
}

Object.freeze(PrivateRoutingController.prototype)
Object.freeze(PrivateRoutingController)

function createPrivateRoutingController(options) {
  exactOptions(options)
  const controller = new PrivateRoutingController()
  Object.freeze(controller)
  const state = {
    controller,
    state: PRIVATE_ROUTING_STATE.OFF,
    generation: 0n,
    signalGeneration: 0n,
    transitioning: null,
    destroying: false,
    signalSinks: new Set(),
    testSignals: null,
    suspendPromise: null,
    endpointBootstrapAuthority: options.endpointBootstrapAuthority,
    controllerRegistration: null,
    endpointResources: null,
    startPromise: null,
    readyPromise: null,
    readyResolve: null,
    readyReject: null,
    destroyPromise: null,
    builderCapability: null,
    branchBuild: null,
    branchConnections: new Map(),
    routeFactories: null,
    branchBuildPromise: null,
    branchBuildError: null,
    rotationBranch: null,
    testManualBuild: false,
    liveRouteAuthority: null,
    routedDHTIO: null,
    transportDHT: null,
    routeManager: null,
    guardLease: null,
    resumeGenerations: null,
    suspendedDirectory: null,
    reconnect: null,
    lookupGeneration: null,
    announceGeneration: null,
    activeQueries: new Map(),
    timers: new Set(),
    handles: 0,
    queuedTransitions: 0,
    tables: 0,
    callbacks: 0,
    secretBytes: 0,
    cancelScheduled: null,
    wallNow: null,
    schedule: null,
    monotonicNow: null,
    randomBytes: null
  }
  STATES.set(controller, state)
  state.testSignals = createSignalSet(state)
  try {
    state.controllerRegistration = registerEndpointBootstrapController(
      options.endpointBootstrapAuthority,
      controller
    )
  } catch (err) {
    STATES.delete(controller)
    throw err
  }
  return controller
}

module.exports = Object.freeze({
  PRIVATE_ROUTING_STATE,
  TEST_ONLY_PRIVATE_ROUTING_CONTROLLER_ISSUER,
  createPrivateRoutingController,
  issuePrivateRoutingControllerSignal
})
