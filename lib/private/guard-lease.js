'use strict'

const b4a = require('b4a')

const { PrivateRouteError } = require('./errors')
const {
  createSharedGuardM3CellLinkTransferIssuer,
  destroySharedGuardM3CellLinkTransfers,
  destroyTakenGuardLeaseMaterial,
  readSharedGuardM3CellLinkTransferCount,
  takeGuardLeaseMaterial
} = require('./udx-cell-endpoint')

const MAX_GUARD_LEASE_BRANCH_SLOTS = 4
const LEASES = new WeakMap()
const DESTROYED_LEASES = new WeakSet()

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

function isFunction(value) {
  return typeof value === 'function'
}

function same(a, b) {
  return b4a.isBuffer(a) && b4a.isBuffer(b) && b4a.equals(a, b)
}

function validatePinnedGuard(pinnedGuard, materialState) {
  if (!isObject(pinnedGuard)) invalid()
  const identity = pinnedGuard.identity32 || pinnedGuard.identity || pinnedGuard.peerIdentity32
  if (!same(identity, materialState.identity)) throw PrivateRouteError.UNAUTHORIZED()
  const endpoint = pinnedGuard.endpoint || pinnedGuard.peerAddress || pinnedGuard.address
  if (endpoint !== undefined) {
    if (!isObject(endpoint)) invalid()
    if (endpoint.host !== materialState.host || endpoint.port !== materialState.port) {
      throw PrivateRouteError.UNAUTHORIZED()
    }
    return
  }
  if (pinnedGuard.host !== materialState.host || pinnedGuard.port !== materialState.port) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
}

function createGuardLease(options) {
  if (!isObject(options)) invalid()
  const {
    guardLeaseMaterial,
    pinnedGuard,
    wallNow,
    monotonicNow,
    setTimer,
    clearTimer,
    guardLossSink
  } = options
  if (
    !isFunction(wallNow) ||
    !isFunction(monotonicNow) ||
    !isFunction(setTimer) ||
    !isFunction(clearTimer) ||
    !isObject(guardLossSink)
  ) {
    invalid()
  }
  const materialState = takeGuardLeaseMaterial(guardLeaseMaterial)
  let lease = null
  try {
    validatePinnedGuard(pinnedGuard, materialState)
    if (!materialState.establishedLink) unavailable()
    lease = Object.freeze({})
    LEASES.set(lease, {
      materialState,
      wallNow,
      monotonicNow,
      setTimer,
      clearTimer,
      guardLossSink,
      issuers: new Set(),
      destroyed: false
    })
    return lease
  } catch (err) {
    destroyTakenGuardLeaseMaterial(materialState)
    if (lease) DESTROYED_LEASES.add(lease)
    throw err
  }
}

function readGuardLease(lease) {
  const state = isObject(lease) ? LEASES.get(lease) : null
  if (!state) {
    if (isObject(lease) && DESTROYED_LEASES.has(lease)) destroyed()
    throw PrivateRouteError.UNAUTHORIZED()
  }
  if (state.destroyed) destroyed()
  return state
}

function isGuardLease(lease) {
  const state = isObject(lease) ? LEASES.get(lease) : null
  return !!(state && !state.destroyed)
}

function issueGuardLeaseM3CellLinkTransferIssuer(lease) {
  const state = readGuardLease(lease)
  const liveSlots = readSharedGuardM3CellLinkTransferCount(state.materialState.establishedLink)
  if (liveSlots >= MAX_GUARD_LEASE_BRANCH_SLOTS) {
    throw PrivateRouteError.ERR_QUOTA_EXCEEDED()
  }
  const issuer = createSharedGuardM3CellLinkTransferIssuer(state.materialState.establishedLink)
  state.issuers.add(issuer)
  return issuer
}

function destroyGuardLease(lease) {
  const state = isObject(lease) ? LEASES.get(lease) : null
  if (!state || state.destroyed) return false
  state.destroyed = true
  LEASES.delete(lease)
  DESTROYED_LEASES.add(lease)
  destroySharedGuardM3CellLinkTransfers(state.materialState.establishedLink)
  for (const issuer of state.issuers) issuer.destroy()
  state.issuers.clear()
  destroyTakenGuardLeaseMaterial(state.materialState)
  state.materialState = null
  state.guardLossSink = null
  return true
}

function suspendGuardLease(lease) {
  readGuardLease(lease)
  throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
}

function sendToGuard(lease) {
  readGuardLease(lease)
  throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
}

module.exports = {
  MAX_GUARD_LEASE_BRANCH_SLOTS,
  createGuardLease,
  isGuardLease,
  issueGuardLeaseM3CellLinkTransferIssuer,
  destroyGuardLease,
  suspendGuardLease,
  sendToGuard
}
