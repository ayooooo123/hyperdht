'use strict'

const b4a = require('b4a')

const { PrivateRouteError } = require('./errors')
const { BRANCH_CLASS } = require('./protocol')
const { isGuardLease } = require('./guard-lease')
const {
  createInitialBranchDrafts,
  destroyInitialBranchDrafts,
  inspectInitialBranchDrafts
} = require('./branch-path-authority')
const { createRouteExtensionFactory, readRouteExtensionFactory } = require('./route-extension')
const {
  createFinalExitActivationFactory,
  readFinalExitActivationFactory
} = require('./final-exit-activation')

const INITIAL_PAIR_DEADLINE_MS = 5_000n
const MANAGERS = new WeakMap()
const DESTROYED_MANAGERS = new WeakSet()
const TEST_ONLY_ROUTE_MANAGER_OBSERVER = Symbol.for(
  'hyperdht-private-routes/test-only-route-manager-observer'
)
const MANAGER_FIELDS = Object.freeze([
  'guardLease',
  'candidateDirectory',
  'extensionFactory',
  'terminalFactory',
  'monotonicNow',
  'randomBytes'
])

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function destroyed() {
  throw PrivateRouteError.ERR_DESTROYED()
}

function busy() {
  throw PrivateRouteError.ERR_BUSY()
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function exactObject(value, fields) {
  if (!isObject(value)) invalid()
  const names = Reflect.ownKeys(value)
  if (names.length !== fields.length) invalid()
  for (const field of fields) {
    if (!Object.prototype.hasOwnProperty.call(value, field)) invalid()
  }
}

function absoluteNow(now) {
  const value = now()
  if (typeof value === 'bigint' && value >= 0n) return value
  if (Number.isSafeInteger(value) && value >= 0) return BigInt(value)
  invalid()
}

function randomId(randomBytes) {
  const value = randomBytes(16)
  if (!b4a.isBuffer(value) || value.byteLength !== 16) invalid()
  return value
}

function readManagerFactory(readFactory, factory) {
  try {
    return readFactory(factory)
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'ERR_AUTHENTICATION') {
      throw PrivateRouteError.UNAUTHORIZED()
    }
    throw err
  }
}

class RouteManager {
  buildInitialPair() {
    const state = readRouteManager(this)
    if (state.destroyed) destroyed()
    if (state.ready || state.initialDrafts !== null || state.building) busy()
    state.building = true
    try {
      const start = absoluteNow(state.monotonicNow)
      const drafts = createInitialBranchDrafts({
        guardLease: state.guardLease,
        candidateDirectory: state.candidateDirectory,
        lookupGeneration: state.lookupGeneration,
        announceGeneration: state.announceGeneration,
        lookupBranchId: randomId(state.randomBytes),
        announceBranchId: randomId(state.randomBytes),
        lookupCircuitId: randomId(state.randomBytes),
        announceCircuitId: randomId(state.randomBytes),
        absoluteDeadline: start + INITIAL_PAIR_DEADLINE_MS
      })
      state.initialDrafts = drafts
      state.status = 'BUILDING'
      return false
    } catch (err) {
      state.status = 'UNAVAILABLE'
      throw err
    } finally {
      state.building = false
    }
  }

  ready() {
    const state = readRouteManager(this)
    return state.ready
  }

  branchCapability(branchClass) {
    const state = readRouteManager(this)
    if (branchClass !== BRANCH_CLASS.LOOKUP && branchClass !== BRANCH_CLASS.ANNOUNCE) invalid()
    if (!state.ready) throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    return state.capabilities.get(branchClass)
  }

  destroy() {
    const state = MANAGERS.get(this)
    if (!state || state.destroyed) return false
    state.destroyed = true
    MANAGERS.delete(this)
    DESTROYED_MANAGERS.add(this)
    if (state.initialDrafts !== null) destroyInitialBranchDrafts(state.initialDrafts)
    state.initialDrafts = null
    state.capabilities.clear()
    return true
  }

  [TEST_ONLY_ROUTE_MANAGER_OBSERVER]() {
    const state = readRouteManager(this)
    const draft =
      state.initialDrafts === null ? null : inspectInitialBranchDrafts(state.initialDrafts)
    return Object.freeze({
      status: state.status,
      ready: state.ready,
      building: state.building,
      lookupGeneration: state.lookupGeneration,
      announceGeneration: state.announceGeneration,
      draft
    })
  }
}

function readRouteManager(manager) {
  const state = isObject(manager) ? MANAGERS.get(manager) : null
  if (!state) {
    if (isObject(manager) && DESTROYED_MANAGERS.has(manager)) destroyed()
    throw PrivateRouteError.UNAUTHORIZED()
  }
  if (state.destroyed) destroyed()
  return state
}

function createRouteManager(options) {
  exactObject(options, MANAGER_FIELDS)
  if (!isGuardLease(options.guardLease)) throw PrivateRouteError.UNAUTHORIZED()
  if (!isObject(options.candidateDirectory)) invalid()
  const extensionState = readManagerFactory(readRouteExtensionFactory, options.extensionFactory)
  const terminalState = readManagerFactory(readFinalExitActivationFactory, options.terminalFactory)
  if (
    extensionState.wallNow !== terminalState.wallNow ||
    extensionState.monotonicNow !== options.monotonicNow ||
    terminalState.monotonicNow !== options.monotonicNow ||
    extensionState.monotonicNow !== terminalState.monotonicNow ||
    extensionState.randomBytes !== options.randomBytes ||
    terminalState.randomBytes !== options.randomBytes ||
    extensionState.randomBytes !== terminalState.randomBytes ||
    extensionState.schedule !== terminalState.schedule ||
    extensionState.cancelScheduled !== terminalState.cancelScheduled
  ) {
    invalid()
  }
  if (typeof options.monotonicNow !== 'function' || typeof options.randomBytes !== 'function')
    invalid()
  const manager = new RouteManager()
  MANAGERS.set(manager, {
    guardLease: options.guardLease,
    candidateDirectory: options.candidateDirectory,
    extensionFactory: options.extensionFactory,
    terminalFactory: options.terminalFactory,
    extensionClock: extensionState,
    terminalClock: terminalState,
    monotonicNow: options.monotonicNow,
    randomBytes: options.randomBytes,
    lookupGeneration: 1n,
    announceGeneration: 1n,
    initialDrafts: null,
    capabilities: new Map(),
    status: 'EMPTY',
    ready: false,
    building: false,
    destroyed: false
  })
  return Object.freeze(manager)
}

function isRouteManager(manager) {
  const state = isObject(manager) ? MANAGERS.get(manager) : null
  return !!(state && !state.destroyed)
}

module.exports = {
  INITIAL_PAIR_DEADLINE_MS,
  TEST_ONLY_ROUTE_MANAGER_OBSERVER,
  createFinalExitActivationFactory,
  createRouteExtensionFactory,
  readFinalExitActivationFactory,
  readRouteExtensionFactory,
  createRouteManager,
  isRouteManager
}
