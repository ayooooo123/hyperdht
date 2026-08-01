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
const { encodeCanonicalEndpoint } = require('./relay-capability')
const { createGuardReconnectAuthority } = require('./guard-reconnect-authority')

const OPTIONAL_RECONNECT_FIELDS = Object.freeze([
  'advertisement',
  'advertisementDigest',
  'epoch',
  'expiresAt',
  'canonicalEndpointBytes'
])

const MAX_U64 = 0xffff_ffff_ffff_ffffn

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

function copy(value, size) {
  if (!b4a.isBuffer(value) || (size !== undefined && value.byteLength !== size)) invalid()
  return b4a.from(value)
}

function timestamp(value) {
  const result = value()
  if (typeof result === 'bigint' && result >= 0n) return result
  if (Number.isSafeInteger(result) && result >= 0) return BigInt(result)
  invalid()
}

function endpointAddress(host) {
  if (typeof host !== 'string') invalid()
  if (/^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$/.test(host)) {
    const parts = host.split('.')
    const addressBytes = b4a.alloc(4)
    for (let i = 0; i < 4; i++) {
      const value = Number(parts[i])
      if (value > 255) invalid()
      addressBytes[i] = value
    }
    return { addressFamily: 4, addressBytes }
  }
  if (!/^[0-9a-f:]+$/.test(host) || host.includes('%') || host.includes('.')) invalid()
  const marker = host.indexOf('::')
  if (marker !== -1 && marker !== host.lastIndexOf('::')) invalid()
  const left = (marker === -1 ? host : host.slice(0, marker)).split(':').filter(Boolean)
  const right = (marker === -1 ? '' : host.slice(marker + 2)).split(':').filter(Boolean)
  const words = [...left, ...right]
  if (!words.every((part) => /^[0-9a-f]{1,4}$/.test(part))) invalid()
  const zeroWords = marker === -1 ? 0 : 8 - words.length
  if (marker === -1 ? words.length !== 8 : zeroWords < 1) invalid()
  const normalized = marker === -1 ? words : [...left, ...Array(zeroWords).fill('0'), ...right]
  const addressBytes = b4a.alloc(16)
  for (let i = 0; i < normalized.length; i++) {
    const value = Number.parseInt(normalized[i], 16)
    addressBytes[i * 2] = value >>> 8
    addressBytes[i * 2 + 1] = value
  }
  return { addressFamily: 6, addressBytes }
}

function readReconnectOptions(pinnedGuard, endpointBytes) {
  let present = 0
  for (const field of OPTIONAL_RECONNECT_FIELDS) {
    if (pinnedGuard[field] !== undefined) present++
  }
  if (present === 0) return null
  if (
    present !== OPTIONAL_RECONNECT_FIELDS.length ||
    typeof pinnedGuard.epoch !== 'bigint' ||
    pinnedGuard.epoch === 0n ||
    pinnedGuard.epoch > MAX_U64 ||
    typeof pinnedGuard.expiresAt !== 'bigint' ||
    pinnedGuard.expiresAt === 0n ||
    pinnedGuard.expiresAt > MAX_U64
  ) {
    invalid()
  }
  if (!same(pinnedGuard.canonicalEndpointBytes, endpointBytes))
    throw PrivateRouteError.UNAUTHORIZED()
  return Object.freeze({
    advertisement: copy(pinnedGuard.advertisement),
    advertisementDigest: copy(pinnedGuard.advertisementDigest, 32),
    epoch: pinnedGuard.epoch,
    expiresAt: pinnedGuard.expiresAt,
    canonicalEndpointBytes: copy(pinnedGuard.canonicalEndpointBytes, 19)
  })
}

function validatePinnedGuard(pinnedGuard, materialState) {
  if (!isObject(pinnedGuard)) invalid()
  const identity = pinnedGuard.identity32 || pinnedGuard.identity || pinnedGuard.peerIdentity32
  if (!same(identity, materialState.identity)) throw PrivateRouteError.UNAUTHORIZED()
  const endpoint = pinnedGuard.endpoint || pinnedGuard.peerAddress || pinnedGuard.address
  let endpointBytes = null
  if (endpoint !== undefined) {
    if (!isObject(endpoint)) invalid()
    if (endpoint.host !== materialState.host || endpoint.port !== materialState.port) {
      throw PrivateRouteError.UNAUTHORIZED()
    }
    const address = endpointAddress(endpoint.host)
    endpointBytes = encodeCanonicalEndpoint({
      addressFamily: address.addressFamily,
      addressBytes: address.addressBytes,
      port: endpoint.port
    })
  } else {
    if (pinnedGuard.host !== materialState.host || pinnedGuard.port !== materialState.port) {
      throw PrivateRouteError.UNAUTHORIZED()
    }
    const address = endpointAddress(pinnedGuard.host)
    endpointBytes = encodeCanonicalEndpoint({
      addressFamily: address.addressFamily,
      addressBytes: address.addressBytes,
      port: pinnedGuard.port
    })
  }
  return readReconnectOptions(pinnedGuard, endpointBytes)
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
    const reconnectOptions = validatePinnedGuard(pinnedGuard, materialState)
    if (!materialState.establishedLink) unavailable()
    lease = Object.freeze({})
    LEASES.set(lease, {
      materialState,
      reconnectOptions,
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
function readGuardLeaseScope(lease) {
  const state = readGuardLease(lease)
  const materialState = state.materialState
  const address = endpointAddress(materialState.host)
  const endpointBytes = encodeCanonicalEndpoint({
    addressFamily: address.addressFamily,
    addressBytes: address.addressBytes,
    port: materialState.port
  })
  return Object.freeze({
    identity32: b4a.from(materialState.identity),
    endpoint: Object.freeze({ host: materialState.host, port: materialState.port }),
    endpointBytes
  })
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
  const state = readGuardLease(lease)
  const materialState = state.materialState
  const reconnectOptions = state.reconnectOptions
  if (
    !reconnectOptions ||
    !materialState.secret ||
    !isFunction(materialState.reconnectTransportFactory)
  ) {
    unavailable()
  }
  let reconnect = null
  try {
    reconnect = createGuardReconnectAuthority({
      guardIdentity: materialState.identity,
      guardEndpoint: reconnectOptions.canonicalEndpointBytes,
      advertisement: reconnectOptions.advertisement,
      advertisementDigest: reconnectOptions.advertisementDigest,
      epoch: reconnectOptions.epoch,
      expiresAt: reconnectOptions.expiresAt,
      localIdentity: materialState.secret.localIdentity,
      localSecretKey: materialState.secret.localSecretKey,
      reconnectDatagrams: materialState.reconnectTransportFactory,
      wallNow: () => timestamp(state.wallNow),
      monotonicNow: () => timestamp(state.monotonicNow),
      setTimer: state.setTimer,
      clearTimer: state.clearTimer
    })
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    unavailable()
  }
  state.destroyed = true
  LEASES.delete(lease)
  DESTROYED_LEASES.add(lease)
  destroySharedGuardM3CellLinkTransfers(materialState.establishedLink)
  for (const issuer of state.issuers) issuer.destroy()
  state.issuers.clear()
  destroyTakenGuardLeaseMaterial(materialState)
  state.materialState = null
  state.reconnectOptions = null
  state.guardLossSink = null
  return reconnect
}

function sendToGuard(lease) {
  readGuardLease(lease)
  throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
}

module.exports = {
  MAX_GUARD_LEASE_BRANCH_SLOTS,
  createGuardLease,
  isGuardLease,
  readGuardLeaseScope,
  issueGuardLeaseM3CellLinkTransferIssuer,
  destroyGuardLease,
  suspendGuardLease,
  sendToGuard
}
