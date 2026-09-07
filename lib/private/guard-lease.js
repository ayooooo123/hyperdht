'use strict'

const b4a = require('b4a')

const { PrivateRouteError } = require('./errors')
const { cryptoSuite } = require('./crypto-suite')
const {
  abortIndexZeroGuardLink,
  completeIndexZeroGuardLink,
  createIndexZeroGuardLinkOffer
} = require('./guard-link')
const { M3AdjacencyAuthority } = require('./m3-adjacency-runtime')
const { createTailControlSession } = require('./tail-control')
const {
  createSharedGuardM3CellLinkTransferIssuer,
  destroySharedGuardM3CellLinkTransfers,
  destroyTakenGuardLeaseMaterial,
  exchangeSharedGuardBranch,
  readSharedGuardM3CellLinkTransferCount,
  registerSharedGuardLossRegistration,
  unregisterSharedGuardLossRegistration,
  takeGuardLeaseMaterial
} = require('./udx-cell-endpoint')
const {
  decodeRelayCapabilityAdvertisement,
  encodeCanonicalEndpoint
} = require('./relay-capability')
const { digestPayloadParameters } = require('./link-parameters')
const { BRANCH_CLASS } = require('./protocol')
const { createGuardReconnectAuthority } = require('./guard-reconnect-authority')
const BRANCH_OPEN_AUTHORITIES = new WeakMap()
const SPENT_BRANCH_OPEN_AUTHORITIES = new WeakSet()
const MAX_GUARD_BRANCH_ROUTE_MS = 15_000n

const OPTIONAL_RECONNECT_FIELDS = Object.freeze([
  'advertisement',
  'advertisementDigest',
  'epoch',
  'expiresAt'
])

const MAX_U64 = 0xffff_ffff_ffff_ffffn

const MAX_GUARD_LEASE_BRANCH_SLOTS = 4
const LEASES = new WeakMap()
const DESTROYED_LEASES = new WeakSet()
const LOSS_REGISTRATIONS = new WeakMap()

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
  const transferredEndpoint =
    pinnedGuard.canonicalEndpoint === undefined
      ? pinnedGuard.canonicalEndpointBytes
      : pinnedGuard.canonicalEndpoint
  if (
    transferredEndpoint === undefined ||
    (pinnedGuard.canonicalEndpoint !== undefined &&
      pinnedGuard.canonicalEndpointBytes !== undefined) ||
    !same(transferredEndpoint, endpointBytes)
  ) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  return Object.freeze({
    advertisement: copy(pinnedGuard.advertisement),
    advertisementDigest: copy(pinnedGuard.advertisementDigest, 32),
    epoch: pinnedGuard.epoch,
    expiresAt: pinnedGuard.expiresAt,
    canonicalEndpointBytes: copy(endpointBytes, 19)
  })
}

function validatePinnedGuard(pinnedGuard, materialState) {
  if (!isObject(pinnedGuard)) invalid()
  const identity = pinnedGuard.identity32 || pinnedGuard.identity || pinnedGuard.peerIdentity32
  if (!same(identity, materialState.identity)) throw PrivateRouteError.UNAUTHORIZED()
  const expectedAddress = endpointAddress(materialState.host)
  const expectedEndpoint = encodeCanonicalEndpoint({
    addressFamily: expectedAddress.addressFamily,
    addressBytes: expectedAddress.addressBytes,
    port: materialState.port
  })
  const transferredEndpoint =
    pinnedGuard.canonicalEndpoint === undefined
      ? pinnedGuard.canonicalEndpointBytes
      : pinnedGuard.canonicalEndpoint
  let endpointBytes = null
  if (transferredEndpoint !== undefined) {
    if (
      pinnedGuard.canonicalEndpoint !== undefined &&
      pinnedGuard.canonicalEndpointBytes !== undefined
    ) {
      invalid()
    }
    endpointBytes = copy(transferredEndpoint, 19)
    if (OPTIONAL_RECONNECT_FIELDS.some((field) => pinnedGuard[field] !== undefined)) {
      return readReconnectOptions(pinnedGuard, expectedEndpoint)
    }
    if (!same(endpointBytes, expectedEndpoint)) throw PrivateRouteError.UNAUTHORIZED()
  } else {
    const endpoint = pinnedGuard.endpoint || pinnedGuard.peerAddress || pinnedGuard.address
    if (endpoint !== undefined) {
      if (!isObject(endpoint)) invalid()
      if (endpoint.host !== materialState.host || endpoint.port !== materialState.port) {
        throw PrivateRouteError.UNAUTHORIZED()
      }
    } else if (pinnedGuard.host !== materialState.host || pinnedGuard.port !== materialState.port) {
      throw PrivateRouteError.UNAUTHORIZED()
    }
    endpointBytes = b4a.from(expectedEndpoint)
  }
  return readReconnectOptions(pinnedGuard, endpointBytes)
}

function clearGuardExpiry(state) {
  const handle = state.expiryTimer
  state.expiryTimer = null
  if (handle === null) return
  try {
    state.clearTimer(handle)
  } catch {}
}

function tombstoneGuardLease(state, emitLoss) {
  if (!state || state.destroyed) return false
  state.destroyed = true
  LEASES.delete(state.lease)
  DESTROYED_LEASES.add(state.lease)
  LOSS_REGISTRATIONS.delete(state.lossRegistration)
  unregisterSharedGuardLossRegistration(state.materialState.establishedLink, state.lossRegistration)
  clearGuardExpiry(state)
  destroySharedGuardM3CellLinkTransfers(state.materialState.establishedLink)
  for (const issuer of state.issuers) issuer.destroy()
  state.issuers.clear()
  const sink = state.guardLossSink
  state.guardLossSink = null
  destroyTakenGuardLeaseMaterial(state.materialState)
  state.materialState = null
  state.reconnectOptions = null
  if (emitLoss && sink) {
    try {
      const { issuePrivateRoutingControllerSignal } = require('./private-routing-controller')
      issuePrivateRoutingControllerSignal(sink)
    } catch {}
  }
  return true
}

function issueGuardLeasePhysicalLoss(registration) {
  const state = isObject(registration) ? LOSS_REGISTRATIONS.get(registration) : null
  return tombstoneGuardLease(state, true)
}

function armGuardExpiry(state) {
  const expiresAt =
    state.reconnectOptions === null
      ? state.materialState.expiresAt
      : state.reconnectOptions.expiresAt
  if (typeof expiresAt !== 'bigint' || expiresAt < 1n) invalid()
  const wallStart = timestamp(state.wallNow)
  const monotonicStart = timestamp(state.monotonicNow)
  if (expiresAt <= wallStart) return issueGuardLeasePhysicalLoss(state.lossRegistration)
  const deadline = monotonicStart + (expiresAt - wallStart)
  const schedule = () => {
    const now = timestamp(state.monotonicNow)
    if (now >= deadline) return issueGuardLeasePhysicalLoss(state.lossRegistration)
    let arming = true
    let firedSynchronously = false
    let handle = null
    const expired = () => {
      if (arming) {
        firedSynchronously = true
        return
      }
      if (state.destroyed || state.expiryTimer !== handle) return
      state.expiryTimer = null
      schedule()
    }
    try {
      handle = state.setTimer(expired, Number(deadline - now))
    } catch {
      arming = false
      issueGuardLeasePhysicalLoss(state.lossRegistration)
      unavailable()
    }
    arming = false
    if (firedSynchronously || handle === null || handle === undefined) {
      try {
        state.clearTimer(handle)
      } catch {}
      issueGuardLeasePhysicalLoss(state.lossRegistration)
      unavailable()
    }
    state.expiryTimer = handle
    return true
  }
  return schedule()
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
    !isObject(guardLossSink) ||
    !Object.isFrozen(guardLossSink) ||
    Reflect.ownKeys(guardLossSink).length !== 0
  ) {
    invalid()
  }
  const materialState = takeGuardLeaseMaterial(guardLeaseMaterial)
  let lease = null
  try {
    const reconnectOptions = validatePinnedGuard(pinnedGuard, materialState)
    if (!materialState.establishedLink) unavailable()
    lease = Object.freeze({})
    const lossRegistration = Object.freeze({})
    const state = {
      lease,
      materialState,
      reconnectOptions,
      wallNow,
      monotonicNow,
      setTimer,
      clearTimer,
      guardLossSink,
      lossRegistration,
      expiryTimer: null,
      issuers: new Set(),
      destroyed: false
    }
    LEASES.set(lease, state)
    LOSS_REGISTRATIONS.set(lossRegistration, state)
    registerSharedGuardLossRegistration(materialState.establishedLink, lossRegistration)
    armGuardExpiry(state)
    if (state.destroyed) unavailable()
    return lease
  } catch (err) {
    const state = lease ? LEASES.get(lease) : null
    if (state) tombstoneGuardLease(state, false)
    else destroyTakenGuardLeaseMaterial(materialState)
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
  return tombstoneGuardLease(state, false)
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
  unregisterSharedGuardLossRegistration(materialState.establishedLink, state.lossRegistration)
  LOSS_REGISTRATIONS.delete(state.lossRegistration)
  clearGuardExpiry(state)
  let reconnectTransport = null
  try {
    reconnectTransport = materialState.reconnectTransportFactory()
    materialState.reconnectTransport = null
    reconnect = createGuardReconnectAuthority({
      guardIdentity: materialState.identity,
      guardEndpoint: reconnectOptions.canonicalEndpointBytes,
      advertisement: reconnectOptions.advertisement,
      advertisementDigest: reconnectOptions.advertisementDigest,
      epoch: reconnectOptions.epoch,
      expiresAt: reconnectOptions.expiresAt,
      localIdentity: materialState.secret.localIdentity,
      localSecretKey: materialState.secret.localSecretKey,
      reconnectDatagrams: reconnectTransport,
      wallNow: () => timestamp(state.wallNow),
      monotonicNow: () => timestamp(state.monotonicNow),
      setTimer: state.setTimer,
      clearTimer: state.clearTimer
    })
    reconnectTransport = null
  } catch (err) {
    if (reconnectTransport) {
      try {
        reconnectTransport.destroy()
      } catch {}
    }
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

function createGuardBranchOpenAuthority(lease, options) {
  const state = readGuardLease(lease)
  if (
    !isObject(options) ||
    Reflect.ownKeys(options).length !== 3 ||
    !isObject(options.branch) ||
    !isObject(options.issuer) ||
    typeof options.absoluteDeadline !== 'bigint'
  )
    invalid()
  const branch = options.branch
  if (
    (branch.branchClass !== BRANCH_CLASS.LOOKUP && branch.branchClass !== BRANCH_CLASS.ANNOUNCE) ||
    !b4a.isBuffer(branch.branchId) ||
    branch.branchId.byteLength !== 16 ||
    !b4a.isBuffer(branch.circuitId) ||
    branch.circuitId.byteLength !== 16 ||
    typeof branch.generation !== 'bigint' ||
    branch.generation < 1n
  )
    invalid()
  const advertisement = state.reconnectOptions && state.reconnectOptions.advertisement
  if (!advertisement) unavailable()
  const wallStart = timestamp(state.wallNow)
  const monotonicStart = timestamp(state.monotonicNow)
  if (options.absoluteDeadline <= monotonicStart) unavailable()
  const decoded = decodeRelayCapabilityAdvertisement(advertisement, { now: wallStart })
  const expiresAtMs = [wallStart + MAX_GUARD_BRANCH_ROUTE_MS, decoded.expiresAtMs].reduce(
    (left, right) => (left < right ? left : right)
  )
  const limits = Object.freeze({
    maxCells: Math.min(decoded.maxCellsPerCircuit, 64),
    maxBytes: Math.min(decoded.maxBytesPerCircuit, 65_536),
    maxCommands: Math.min(decoded.maxCommandsPerCircuit, 10),
    idleTimeoutMs: Math.min(decoded.idleTimeoutMs, 5_000)
  })
  const requestedLimits = Object.freeze({
    cellSize: 1200,
    ...limits,
    expiresAtMs
  })
  const authority = Object.freeze({})
  BRANCH_OPEN_AUTHORITIES.set(authority, {
    state,
    branch,
    issuer: options.issuer,
    absoluteDeadline: options.absoluteDeadline,
    limits,
    requestedLimits
  })
  return authority
}

async function openGuardBranch(lease, authority) {
  const state = readGuardLease(lease)
  const open = isObject(authority) ? BRANCH_OPEN_AUTHORITIES.get(authority) : null
  if (!open) {
    if (isObject(authority) && SPENT_BRANCH_OPEN_AUTHORITIES.has(authority)) {
      throw PrivateRouteError.ERR_REPLAY()
    }
    throw PrivateRouteError.UNAUTHORIZED()
  }
  if (open.state !== state) throw PrivateRouteError.UNAUTHORIZED()
  BRANCH_OPEN_AUTHORITIES.delete(authority)
  SPENT_BRANCH_OPEN_AUTHORITIES.add(authority)
  const material = state.materialState
  const branch = open.branch
  const advertisement = state.reconnectOptions && state.reconnectOptions.advertisement
  if (!advertisement || !material.secret) unavailable()
  let pending = null
  let established = null
  let decoded = null
  try {
    const now = timestamp(state.wallNow)
    decoded = decodeRelayCapabilityAdvertisement(advertisement, { now })
    const routeDeadline = timestamp(state.monotonicNow) + (open.requestedLimits.expiresAtMs - now)
    const clientSeed = b4a.from(material.secret.localSecretKey.subarray(0, 32))
    const clientIdentity = cryptoSuite.keyPair(clientSeed)
    clientSeed.fill(0)
    const tailSeed = cryptoSuite.randomBytes(32)
    const clientTailEphemeral = cryptoSuite.encryptionKeyPair(tailSeed)
    tailSeed.fill(0)
    const initiated = createIndexZeroGuardLinkOffer({
      advertisement,
      now,
      randomBytes: cryptoSuite.randomBytes,
      branchClass: branch.branchClass,
      branchId: branch.branchId,
      circuitId: branch.circuitId,
      generation: branch.generation,
      clientCircuitIdentity: clientIdentity,
      clientTailEphemeral,
      payloadParametersDigest: digestPayloadParameters(decoded),
      requestedLimits: open.requestedLimits
    })
    pending = initiated.pending
    const accept = await exchangeSharedGuardBranch(material.establishedLink, {
      offer: initiated.offer,
      generation: branch.generation,
      absoluteDeadline: open.absoluteDeadline,
      now: state.monotonicNow,
      schedule: state.setTimer,
      cancel: state.clearTimer
    })
    established = completeIndexZeroGuardLink(pending, accept, {
      advertisement,
      physicalChannel: open.issuer,
      now: timestamp(state.wallNow)
    })
    pending = null
    const adjacencyAuthority = new M3AdjacencyAuthority({
      wallNow: state.wallNow,
      monotonicNow: state.monotonicNow,
      schedule: state.setTimer,
      cancelScheduled: state.clearTimer,
      crypto: cryptoSuite
    })
    const adjacency = adjacencyAuthority.adopt(established)
    established = null
    const tailControl = createTailControlSession(adjacency.tail, {
      wallNow: state.wallNow,
      monotonicNow: state.monotonicNow,
      schedule: state.setTimer,
      cancelScheduled: state.clearTimer,
      absoluteDeadline: routeDeadline,
      crypto: cryptoSuite
    })
    return Object.freeze({
      tailControl,
      runtime: adjacency.runtime,
      adjacencyAuthority,
      limits: open.limits,
      requestedLimits: open.requestedLimits
    })
  } catch (err) {
    if (pending) abortIndexZeroGuardLink(pending)
    if (established && typeof established.destroy === 'function') established.destroy()
    throw err instanceof PrivateRouteError ? err : PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
}

function readGuardSurbHop(lease, wallNow) {
  const state = readGuardLease(lease)
  const advertisement = state.reconnectOptions && state.reconnectOptions.advertisement
  if (!advertisement || !state.materialState) unavailable()
  const now = timestamp(typeof wallNow === 'function' ? wallNow : state.wallNow)
  const decoded = decodeRelayCapabilityAdvertisement(advertisement, { now })
  return Object.freeze({
    id: b4a.from(decoded.relayIdentity),
    routeKey: b4a.from(decoded.routeEncryptionPublicKey),
    capabilityEpoch: decoded.epoch,
    issuedAtMs: decoded.issuedAtMs,
    expiresAtMs: decoded.expiresAtMs
  })
}

module.exports = {
  MAX_GUARD_LEASE_BRANCH_SLOTS,
  createGuardLease,
  isGuardLease,
  readGuardLeaseScope,
  issueGuardLeaseM3CellLinkTransferIssuer,
  destroyGuardLease,
  suspendGuardLease,
  createGuardBranchOpenAuthority,
  openGuardBranch,
  issueGuardLeasePhysicalLoss,
  readGuardSurbHop
}
