'use strict'

const b4a = require('b4a')

const { PrivateRouteError } = require('./errors')
const { cryptoSuite } = require('./crypto-suite')
const { fragment, Reassembler } = require('./fragments')
const {
  cancelM3RouteFrameReservation,
  destroyM3RouteTransport,
  receiveReservedM3RouteFrame,
  reserveM3RouteFrame,
  sendM3RouteFrame
} = require('./m3-adjacency-runtime')
const { encodeImmutableGetResponse } = require('./dht-exit-wire')
const {
  bindLiveOpaqueDestinationOwnerSession,
  createLiveOpaqueDestinations,
  createAuthenticatedRoutedReplyAuthority,
  createRoutedReplyReferralAuthorityForDestination,
  destroyLiveOpaqueDestinations,
  findLiveOpaqueDestination,
  idLiveOpaqueDestination,
  issueLiveOpaqueDestination,
  isLiveOpaqueDestinationOwnedBy,
  keyLiveOpaqueDestination,
  revokeLiveOpaqueDestination,
  snapshotLiveOpaqueDestinations,
  snapshotLiveOpaqueDestination
} = require('./opaque-destination')
const opaqueDestination = require('./opaque-destination')
const { BRANCH_CLASS, CELL_CLASS, DIRECTION, M3_MESSAGE_ID } = require('./protocol')
const {
  clearRoutedReply,
  clearRoutedRequest,
  decodeRoutedReply,
  decodeRoutedRequest,
  encodeRoutedReply
} = require('./routed-dht')
const {
  ROUTE_ENDPOINT,
  RoutePayloadCodec,
  mintCreatedRoutePayloadContext
} = require('./route-payload')

const TEST_ONLY_LIVE_ROUTE_AUTHORITY_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-live-route-authority-issuer'
)
const TEST_ONLY_AUTHENTICATED_REPLY_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-authenticated-reply-issuer'
)
const STATES = new WeakMap()
const DESTINATION_OWNERS = new WeakMap()
const OPEN_ROUTE_TRANSPORTS = new WeakMap()

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function authentication() {
  throw PrivateRouteError.ERR_AUTHENTICATION()
}

function stateFor(authority) {
  const state =
    authority !== null && (typeof authority === 'object' || typeof authority === 'function')
      ? STATES.get(authority)
      : null
  if (!state || state.destroyed) authentication()
  return state
}

function bindOpenRouteTransport(material, value) {
  if (
    material === null ||
    typeof material !== 'object' ||
    value === null ||
    typeof value !== 'object' ||
    Reflect.ownKeys(value).length !== 2 ||
    !Object.prototype.hasOwnProperty.call(value, 'transport') ||
    !Object.prototype.hasOwnProperty.call(value, 'finalTranscriptDigest') ||
    !b4a.isBuffer(value.finalTranscriptDigest) ||
    value.finalTranscriptDigest.byteLength !== 32 ||
    OPEN_ROUTE_TRANSPORTS.has(material)
  ) {
    invalid()
  }
  OPEN_ROUTE_TRANSPORTS.set(material, {
    transport: value.transport,
    finalTranscriptDigest: b4a.from(value.finalTranscriptDigest),
    claimed: false,
    destroyed: false
  })
  return true
}

function claimOpenRouteTransport(material) {
  const binding =
    material !== null && typeof material === 'object' ? OPEN_ROUTE_TRANSPORTS.get(material) : null
  if (!binding || binding.destroyed || binding.claimed) authentication()
  binding.claimed = true
  return binding
}

function destroyOpenRouteTransport(material) {
  const binding =
    material !== null && typeof material === 'object' ? OPEN_ROUTE_TRANSPORTS.get(material) : null
  if (!binding || binding.destroyed) return false
  binding.destroyed = true
  OPEN_ROUTE_TRANSPORTS.delete(material)
  binding.finalTranscriptDigest.fill(0)
  try {
    destroyM3RouteTransport(binding.transport)
  } catch {}
  binding.transport = null
  return true
}

function ownerFor(state, branch) {
  if (branch !== BRANCH_CLASS.LOOKUP && branch !== BRANCH_CLASS.ANNOUNCE) invalid()
  const owner = state.owners.get(branch)
  if (!owner) authentication()
  return owner
}

function issueLiveRouteDestination(authority, value) {
  const state = stateFor(authority)
  if (!value || typeof value !== 'object') invalid()
  const owner = ownerFor(state, value.branch)
  const existing = findLiveOpaqueDestination(owner.capability, {
    id: value.id,
    destinationRef: value.destinationRef
  })
  const destination =
    existing ||
    issueLiveOpaqueDestination(owner.capability, {
      id: value.id,
      destinationRef: value.destinationRef
    })
  DESTINATION_OWNERS.set(destination, owner)
  return destination
}

function destinationOwner(state, destination) {
  const known = DESTINATION_OWNERS.get(destination)
  if (known && known.state === state) return known
  for (const owner of state.owners.values()) {
    try {
      if (!isLiveOpaqueDestinationOwnedBy(owner.capability, destination)) continue
      DESTINATION_OWNERS.set(destination, owner)
      return owner
    } catch {}
  }
  authentication()
}

function snapshotLiveRouteDestination(authority, destination) {
  const state = stateFor(authority)
  const snapshot = snapshotLiveOpaqueDestination(destination)
  try {
    destinationOwner(state, destination)
    return snapshot
  } catch (err) {
    snapshot.id.fill(0)
    snapshot.destinationRef.fill(0)
    snapshot.circuitId.fill(0)
    throw err
  }
  return snapshot
}

function keyLiveRouteDestination(authority, destination) {
  snapshotLiveRouteDestination(authority, destination)
  return keyLiveOpaqueDestination(destination)
}

function idLiveRouteDestination(authority, destination) {
  snapshotLiveRouteDestination(authority, destination)
  return idLiveOpaqueDestination(destination)
}

function revokeLiveRouteDestination(authority, destination) {
  snapshotLiveRouteDestination(authority, destination)
  DESTINATION_OWNERS.delete(destination)
  return revokeLiveOpaqueDestination(destination)
}

function createLiveRouteReferralAuthority(authority, destination, value) {
  const state = stateFor(authority)
  const owner = destinationOwner(state, destination)
  if (!owner || owner.state !== state || owner.branch !== BRANCH_CLASS.LOOKUP) authentication()
  return createRoutedReplyReferralAuthorityForDestination(owner.capability, destination, value)
}

function liveRouteBranchBinding(authority, branch) {
  const state = stateFor(authority)
  const owner = ownerFor(state, branch)
  return Object.freeze({
    circuitId: b4a.from(owner.circuitId),
    generation: owner.generation,
    enforceHash: state.enforceHash
  })
}

function revokeTestState(state) {
  if (!state || state.destroyed) return false
  state.destroyed = true
  for (const owner of state.owners.values()) {
    try {
      destroyLiveOpaqueDestinations(owner.capability)
    } catch {}
  }
  state.owners.clear()
  return true
}

function registerTestAuthority(authority, options = {}) {
  if (authority === null || (typeof authority !== 'object' && typeof authority !== 'function')) {
    invalid()
  }
  if (STATES.has(authority)) return authority
  const wallNow = options.wallNow || (() => 1_000n)
  const monotonicNow = options.monotonicNow || (() => 1_000n)
  if (typeof wallNow !== 'function' || typeof monotonicNow !== 'function') invalid()
  const state = {
    authority,
    owners: new Map(),
    destroyed: false,
    enforceHash: options.enforceHash === true
  }
  for (const branch of [BRANCH_CLASS.LOOKUP, BRANCH_CLASS.ANNOUNCE]) {
    const offset = branch === BRANCH_CLASS.LOOKUP ? 0 : 0x10
    const branchId = b4a.alloc(16, 0x31 + offset)
    const circuitId = b4a.alloc(16, 0x32 + offset)
    const finalTranscriptDigest = b4a.alloc(32, 0x33 + offset)
    const capability = createLiveOpaqueDestinations({
      branch,
      circuitId,
      generation: 7n,
      expiresAt: 10_000n,
      wallNow,
      monotonicNow
    })
    bindLiveOpaqueDestinationOwnerSession(capability, { branchId, finalTranscriptDigest })
    state.owners.set(branch, {
      state,
      branch,
      capability,
      branchId,
      circuitId,
      finalTranscriptDigest,
      generation: 7n,
      deadline: 4_000n
    })
  }
  STATES.set(authority, state)
  return authority
}

function authenticateTestAuthorityResponse(authority, operation, response) {
  const state = stateFor(authority)
  if (!operation || typeof operation !== 'object' || !response || typeof response !== 'object') {
    invalid()
  }
  let request = null
  let encodedResponse = null
  let encodedReply = null
  try {
    request = decodeRoutedRequest(operation.encodedRequest)
    const owner = ownerFor(state, operation.branch)
    if (
      operation.branch !== BRANCH_CLASS.LOOKUP ||
      request.operationClass !== BRANCH_CLASS.LOOKUP ||
      request.commandId !== M3_MESSAGE_ID.IMMUTABLE_GET_V1
    ) {
      authentication()
    }
    if (!Number.isSafeInteger(response.rtt) || response.rtt < 0) invalid()
    if (!Number.isSafeInteger(response.error) || response.error < 0) invalid()
    encodedResponse =
      response.error === 0
        ? encodeImmutableGetResponse({
            valuePresent: response.value !== null,
            value: response.value
          })
        : b4a.alloc(0)
    encodedReply = encodeRoutedReply({
      requestId: request.requestId,
      commandId: request.commandId,
      commandVersion: request.commandVersion,
      operationClass: request.operationClass,
      from: request.destinationEncoded,
      errorCode: response.error,
      token: response.token === null ? b4a.alloc(0) : response.token,
      closerNodes: response.closerNodes.map((record) => record.destinationRef),
      encodedResponse
    })
    const issuer = opaqueDestination[TEST_ONLY_AUTHENTICATED_REPLY_ISSUER]
    const authenticatedReplyAuthority = issuer.create(owner.capability, {
      branch: owner.branch,
      branchId: owner.branchId,
      circuitId: owner.circuitId,
      generation: owner.generation,
      finalTranscriptDigest: owner.finalTranscriptDigest,
      requestId: request.requestId,
      fromEncoded: request.destinationEncoded,
      deadline: request.absoluteDeadlineMs,
      encodedReply
    })
    const result = Object.freeze({
      encodedReply: b4a.from(encodedReply),
      authenticatedReplyAuthority,
      rtt: response.rtt
    })
    return result
  } finally {
    if (encodedResponse) encodedResponse.fill(0)
    if (encodedReply) encodedReply.fill(0)
    clearRoutedRequest(request)
  }
}

function createPayloadCodec(material, endpointRole, monotonicNow) {
  const context = mintCreatedRoutePayloadContext({
    endpointRole,
    descriptorId: material.payloadDigest,
    circuitId: material.circuitId,
    forwardKey: material.payloadForwardKey,
    forwardNoncePrefix: material.payloadForwardNoncePrefix,
    reverseKey: material.payloadReverseKey,
    reverseNoncePrefix: material.payloadReverseNoncePrefix
  })
  return new RoutePayloadCodec({
    crypto: cryptoSuite,
    context,
    window: 64,
    gapTimeout: 5_000,
    now: () => Number(monotonicNow())
  })
}

function createProductionState(authority, routeManager) {
  const { claimLiveRoutePair, readLiveRoutePair } = require('./route-manager')
  const lease = claimLiveRoutePair(routeManager)
  let pair = null
  let complete = false
  const owners = new Map()
  try {
    pair = readLiveRoutePair(lease)
    for (const [branch, name] of [
      [BRANCH_CLASS.LOOKUP, 'lookup'],
      [BRANCH_CLASS.ANNOUNCE, 'announce']
    ]) {
      const published = pair[name]
      const binding = claimOpenRouteTransport(published.material)
      bindLiveOpaqueDestinationOwnerSession(published.owner, {
        branchId: published.material.branchId,
        finalTranscriptDigest: binding.finalTranscriptDigest
      })
      owners.set(branch, {
        state: null,
        branch,
        capability: published.owner,
        branchId: b4a.from(published.material.branchId),
        circuitId: b4a.from(published.material.circuitId),
        finalTranscriptDigest: b4a.from(binding.finalTranscriptDigest),
        generation: published.material.generation,
        deadline: published.material.expiresAt,
        material: published.material,
        binding,
        codec:
          branch === BRANCH_CLASS.LOOKUP
            ? createPayloadCodec(published.material, ROUTE_ENDPOINT.SOURCE, pair.monotonicNow)
            : null
      })
    }
    const state = {
      authority,
      routeManager,
      lease,
      owners,
      operations: new Set(),
      wallNow: pair.wallNow,
      monotonicNow: pair.monotonicNow,
      randomBytes: pair.randomBytes,
      destroyed: false,
      resourcesRevoked: false,
      suspended: false,
      enforceHash: true,
      real: true
    }
    for (const owner of owners.values()) owner.state = state
    complete = true
    return state
  } finally {
    if (!complete) {
      const { revokeLiveRoutePair } = require('./route-manager')
      try {
        revokeLiveRoutePair(lease)
      } catch {}
      for (const owner of owners.values()) {
        try {
          if (owner.codec) owner.codec.destroy()
        } catch {}
      }
    }
  }
}

function assertProductionCurrent(state) {
  if (state.resourcesRevoked) throw PrivateRouteError.ERR_DESTROYED()
  if (!state.real) return
  const { readLiveRoutePair } = require('./route-manager')
  readLiveRoutePair(state.lease)
}

function exactRequestOptions(options) {
  if (options === null || typeof options !== 'object' || Reflect.ownKeys(options).length !== 4) {
    invalid()
  }
  for (const name of ['branch', 'destinationRef', 'encodedRequest', 'attempt']) {
    const descriptor = Object.getOwnPropertyDescriptor(options, name)
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) invalid()
  }
  return options
}

function cancelProductionOperations(state, reason) {
  for (const operation of Array.from(state.operations)) {
    try {
      operation.cancel(reason)
    } catch {}
  }
  state.operations.clear()
}

function revokeProductionResources(state, reason) {
  if (state.resourcesRevoked) return false
  state.resourcesRevoked = true
  cancelProductionOperations(state, reason)
  for (const owner of state.owners.values()) {
    try {
      destroyLiveOpaqueDestinations(owner.capability)
    } catch {}
    try {
      if (owner.codec) owner.codec.destroy()
    } catch {}
    try {
      destroyOpenRouteTransport(owner.material)
    } catch {}
    owner.codec = null
    owner.branchId.fill(0)
    owner.circuitId.fill(0)
    owner.finalTranscriptDigest.fill(0)
  }
  state.owners.clear()
  if (state.real) {
    const { revokeLiveRoutePair } = require('./route-manager')
    try {
      revokeLiveRoutePair(state.lease)
    } catch {}
  }
  return true
}

function requestProduction(authority, state, options) {
  assertProductionCurrent(state)
  if (state.suspended) throw PrivateRouteError.ERR_DESTROYED()
  options = exactRequestOptions(options)
  if (options.branch !== BRANCH_CLASS.LOOKUP) {
    const error = new Error('Private DHT command is unsupported')
    error.code = 'ERR_PRIVATE_COMMAND_UNSUPPORTED'
    throw error
  }
  if (!Number.isSafeInteger(options.attempt) || options.attempt < 1 || options.attempt > 4) {
    invalid()
  }
  const owner = ownerFor(state, BRANCH_CLASS.LOOKUP)
  if (state.operations.size !== 0 || !b4a.isBuffer(options.encodedRequest)) {
    throw PrivateRouteError.ERR_BUSY()
  }
  let request = null
  let destinationRef = null
  let encodedRequest = null
  try {
    request = decodeRoutedRequest(options.encodedRequest)
    destinationRef = b4a.from(options.destinationRef)
    encodedRequest = b4a.from(options.encodedRequest)
    if (
      request.operationClass !== BRANCH_CLASS.LOOKUP ||
      request.commandId !== M3_MESSAGE_ID.IMMUTABLE_GET_V1 ||
      !b4a.equals(request.destinationEncoded, destinationRef) ||
      request.absoluteDeadlineMs <= state.monotonicNow()
    ) {
      authentication()
    }
    const started = state.monotonicNow()
    const reassembler = new Reassembler({
      now: () => Number(state.monotonicNow()),
      epochExpiresAt: Number(owner.material.expiresAt)
    })
    const operationState = {
      live: true,
      cancelReject: null,
      reassembler,
      receiveReservation: null
    }
    const cancellation = new Promise((resolve, reject) => {
      operationState.cancelReject = reject
    })
    const ownedRequest = request
    const ownedDestinationRef = destinationRef
    const ownedEncodedRequest = encodedRequest
    const ownedReassembler = reassembler
    const run = (async () => {
      const outbound = fragment(ownedEncodedRequest, { randomBytes: state.randomBytes })
      try {
        for (const payload of outbound) {
          if (!operationState.live) throw PrivateRouteError.ERR_DESTROYED()
          const frame = owner.codec.seal({
            direction: DIRECTION.FORWARD,
            class: CELL_CLASS.DATAGRAM,
            payload
          })
          try {
            await sendM3RouteFrame(owner.binding.transport, frame)
          } finally {
            frame.fill(0)
          }
        }
      } finally {
        for (const payload of outbound) payload.fill(0)
      }
      while (operationState.live) {
        const receiveReservation = reserveM3RouteFrame(owner.binding.transport)
        operationState.receiveReservation = receiveReservation
        let frame = null
        try {
          frame = await receiveReservedM3RouteFrame(receiveReservation)
        } finally {
          if (operationState.receiveReservation === receiveReservation) {
            operationState.receiveReservation = null
          }
        }
        let opened = null
        try {
          if (!operationState.live) throw PrivateRouteError.ERR_DESTROYED()
          opened = owner.codec.open({ direction: DIRECTION.REVERSE }, frame)
          if (
            !opened ||
            Array.isArray(opened) ||
            opened.class !== CELL_CLASS.DATAGRAM ||
            !b4a.isBuffer(opened.payload)
          ) {
            invalid()
          }
          const encodedReply = ownedReassembler.pushAuthenticated(opened.payload)
          if (encodedReply === null) continue
          assertProductionCurrent(state)
          if (!operationState.live || state.suspended) {
            encodedReply.fill(0)
            throw PrivateRouteError.ERR_DESTROYED()
          }
          let decodedReply = null
          try {
            decodedReply = decodeRoutedReply(encodedReply)
            if (
              !b4a.equals(decodedReply.requestId, ownedRequest.requestId) ||
              decodedReply.commandId !== ownedRequest.commandId ||
              decodedReply.commandVersion !== ownedRequest.commandVersion ||
              decodedReply.operationClass !== ownedRequest.operationClass ||
              !b4a.equals(decodedReply.fromEncoded, ownedRequest.destinationEncoded)
            ) {
              encodedReply.fill(0)
              continue
            }
          } catch {
            encodedReply.fill(0)
            continue
          } finally {
            clearRoutedReply(decodedReply)
          }
          const authenticatedReplyAuthority = createAuthenticatedRoutedReplyAuthority(
            owner.capability,
            {
              branch: owner.branch,
              branchId: owner.branchId,
              circuitId: owner.circuitId,
              generation: owner.generation,
              finalTranscriptDigest: owner.finalTranscriptDigest,
              requestId: ownedRequest.requestId,
              fromEncoded: ownedRequest.destinationEncoded,
              deadline: ownedRequest.absoluteDeadlineMs,
              encodedReply
            }
          )
          const elapsed = state.monotonicNow() - started
          const rtt =
            elapsed > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(elapsed)
          return Object.freeze({
            encodedReply,
            authenticatedReplyAuthority,
            rtt
          })
        } finally {
          frame.fill(0)
          if (opened && opened.payload) opened.payload.fill(0)
        }
      }
      throw PrivateRouteError.ERR_DESTROYED()
    })()
    const promise = Promise.race([run, cancellation]).finally(() => {
      operationState.live = false
      state.operations.delete(operation)
      cancelM3RouteFrameReservation(operationState.receiveReservation)
      operationState.receiveReservation = null
      ownedReassembler.destroy()
      ownedEncodedRequest.fill(0)
      ownedDestinationRef.fill(0)
      clearRoutedRequest(ownedRequest)
    })
    const operation = Object.freeze({
      promise,
      cancel(reason) {
        if (!operationState.live) return false
        operationState.live = false
        state.operations.delete(operation)
        cancelM3RouteFrameReservation(operationState.receiveReservation)
        operationState.receiveReservation = null
        reassembler.destroy()
        operationState.cancelReject(
          reason instanceof Error ? reason : PrivateRouteError.ERR_DESTROYED()
        )
        return true
      }
    })
    state.operations.add(operation)
    request = null
    destinationRef = null
    encodedRequest = null
    return operation
  } finally {
    clearRoutedRequest(request)
    if (destinationRef) destinationRef.fill(0)
    if (encodedRequest) encodedRequest.fill(0)
  }
}

class LiveRouteAuthority {
  constructor(options) {
    if (
      options === null ||
      typeof options !== 'object' ||
      Reflect.ownKeys(options).length !== 1 ||
      !Object.prototype.hasOwnProperty.call(options, 'routeManager')
    ) {
      invalid()
    }
    const state = createProductionState(this, options.routeManager)
    STATES.set(this, state)
    Object.freeze(this)
  }

  ready() {
    const state = stateFor(this)
    if (state.suspended || state.resourcesRevoked) return false
    assertProductionCurrent(state)
    return true
  }

  suspend() {
    const state = stateFor(this)
    if (state.suspended || state.resourcesRevoked) return
    state.suspended = true
    revokeProductionResources(state, PrivateRouteError.ERR_DESTROYED())
  }

  resume() {
    const state = stateFor(this)
    if (state.suspended || state.resourcesRevoked) throw PrivateRouteError.ERR_DESTROYED()
    assertProductionCurrent(state)
  }

  destroy() {
    const state = stateFor(this)
    state.suspended = true
    revokeProductionResources(state, PrivateRouteError.ERR_DESTROYED())
    state.destroyed = true
    STATES.delete(this)
  }

  bootstrap(options) {
    const state = stateFor(this)
    assertProductionCurrent(state)
    if (state.suspended) throw PrivateRouteError.ERR_DESTROYED()
    if (
      options === null ||
      typeof options !== 'object' ||
      Reflect.ownKeys(options).length !== 3 ||
      !b4a.isBuffer(options.target) ||
      options.target.byteLength !== 32 ||
      !Number.isSafeInteger(options.limit) ||
      options.limit < 0 ||
      options.limit > 20
    ) {
      invalid()
    }
    if (options.branch === BRANCH_CLASS.ANNOUNCE) return Object.freeze([])
    if (options.branch !== BRANCH_CLASS.LOOKUP) invalid()
    return snapshotLiveOpaqueDestinations(
      ownerFor(state, BRANCH_CLASS.LOOKUP).capability,
      options.limit
    )
  }

  closest(options) {
    return this.bootstrap(options)
  }

  request(options) {
    return requestProduction(this, stateFor(this), options)
  }
}

Object.freeze(LiveRouteAuthority.prototype)
Object.freeze(LiveRouteAuthority)

module.exports = Object.freeze({
  LiveRouteAuthority,
  TEST_ONLY_LIVE_ROUTE_AUTHORITY_ISSUER: Object.freeze({
    bindOpenTransport: bindOpenRouteTransport,
    authenticateResponse: authenticateTestAuthorityResponse,
    register: registerTestAuthority
  }),
  bindOpenRouteTransport,
  createLiveRouteReferralAuthority,
  destroyOpenRouteTransport,
  idLiveRouteDestination,
  issueLiveRouteDestination,
  keyLiveRouteDestination,
  liveRouteBranchBinding,
  revokeLiveRouteDestination,
  snapshotLiveRouteDestination
})
