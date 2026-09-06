'use strict'

const b4a = require('b4a')

const { PrivateRouteError } = require('./errors')
const { cryptoSuite } = require('./crypto-suite')
const { fragment, Reassembler } = require('./fragments')
const {
  beginM3RouteTeardown,
  cancelM3RouteFrameReservation,
  destroyM3RouteTransport,
  receiveReservedM3RouteFrame,
  reserveM3RouteFrame,
  scheduleM3RouteTransportTimer,
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
const { EXIT_ORIGIN_SERVICE_POLICY } = require('./exit-policy')

const TEST_ONLY_LIVE_ROUTE_AUTHORITY_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-live-route-authority-issuer'
)
const TEST_ONLY_AUTHENTICATED_REPLY_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-authenticated-reply-issuer'
)
const STATES = new WeakMap()
const DESTINATION_OWNERS = new WeakMap()
const OPEN_ROUTE_TRANSPORTS = new WeakMap()
const MAX_UINT64 = 0xffff_ffff_ffff_ffffn
// The endpoint must not arm a bound the exit would refuse: a budget over the exit's
// advertised ceiling is rejected there, so waiting on it locally buys nothing and turns a
// refused request into a long silence. Read from the same policy table the exit enforces
// rather than restated as a second constant - that coincidence is how KI-15's ceiling and
// the endpoint's budget came to agree by accident. A missing entry yields 0n, which fails
// every budget closed.
function perCommandBudgetCeilingMs(commandId) {
  return EXIT_ORIGIN_SERVICE_POLICY.reduce(
    (ceiling, entry) => (entry.commandId === commandId ? BigInt(entry.timeoutMs) : ceiling),
    0n
  )
}

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function authentication() {
  throw PrivateRouteError.ERR_AUTHENTICATION()
}

function uint64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= MAX_UINT64
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
    destroyed: false,
    seedReceiving: false,
    seedReceived: false,
    codec: null,
    teardownStarted: false
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

async function receiveOpenRouteSeedPayload(material, monotonicNow) {
  const binding =
    material !== null && typeof material === 'object' ? OPEN_ROUTE_TRANSPORTS.get(material) : null
  if (
    !binding ||
    binding.destroyed ||
    binding.claimed ||
    binding.seedReceiving ||
    binding.seedReceived ||
    typeof monotonicNow !== 'function'
  ) {
    authentication()
  }
  binding.seedReceiving = true
  let codec = null
  let reservation = null
  let frame = null
  let opened = null
  try {
    codec = createPayloadCodec(material, ROUTE_ENDPOINT.SOURCE, monotonicNow)
    reservation = reserveM3RouteFrame(binding.transport)
    frame = await receiveReservedM3RouteFrame(reservation)
    opened = codec.open({ direction: DIRECTION.REVERSE }, frame)
    if (
      !opened ||
      Array.isArray(opened) ||
      opened.class !== CELL_CLASS.DATAGRAM ||
      !b4a.isBuffer(opened.payload)
    ) {
      invalid()
    }
    binding.seedReceived = true
    binding.codec = codec
    codec = null
    return b4a.from(opened.payload)
  } catch (err) {
    if (reservation) cancelM3RouteFrameReservation(reservation)
    destroyOpenRouteTransport(material)
    throw err instanceof PrivateRouteError ? err : PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  } finally {
    binding.seedReceiving = false
    if (frame) frame.fill(0)
    if (opened && opened.payload) opened.payload.fill(0)
    if (codec) codec.destroy()
  }
}

function teardownOpenRouteTransport(material, teardownId) {
  const binding =
    material !== null && typeof material === 'object' ? OPEN_ROUTE_TRANSPORTS.get(material) : null
  if (!binding || binding.destroyed || !binding.claimed || binding.teardownStarted) {
    return Promise.reject(PrivateRouteError.ERR_REPLAY())
  }
  binding.teardownStarted = true
  return beginM3RouteTeardown(binding.transport, teardownId)
}

function destroyOpenRouteTransport(material) {
  const binding =
    material !== null && typeof material === 'object' ? OPEN_ROUTE_TRANSPORTS.get(material) : null
  if (!binding || binding.destroyed) return false
  binding.destroyed = true
  OPEN_ROUTE_TRANSPORTS.delete(material)
  binding.finalTranscriptDigest.fill(0)
  if (binding.codec) {
    try {
      binding.codec.destroy()
    } catch {}
    binding.codec = null
  }
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
  if (
    !owner ||
    owner.state !== state ||
    (owner.branch !== BRANCH_CLASS.LOOKUP && owner.branch !== BRANCH_CLASS.ANNOUNCE)
  ) {
    authentication()
  }
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

async function openTestRouteAuthority(openHandoff, options) {
  if (
    options === null ||
    typeof options !== 'object' ||
    Reflect.ownKeys(options).length !== 3 ||
    typeof options.wallNow !== 'function' ||
    typeof options.monotonicNow !== 'function' ||
    typeof options.randomBytes !== 'function'
  ) {
    invalid()
  }
  const { consumeOpenRouteHandoff, destroyOpenRouteMaterial } = require('./open-route-handoff')
  let material = null
  let owner = null
  let encoded = null
  let authority = null
  try {
    material = consumeOpenRouteHandoff(openHandoff)
    if (material.branchClass !== BRANCH_CLASS.LOOKUP) invalid()
    encoded = await receiveOpenRouteSeedPayload(material, options.monotonicNow)
    owner = createLiveOpaqueDestinations({
      branch: BRANCH_CLASS.LOOKUP,
      circuitId: material.circuitId,
      generation: material.generation,
      expiresAt: material.expiresAt,
      wallNow: options.wallNow,
      monotonicNow: options.monotonicNow
    })
    const admission = opaqueDestination.createDhtSeedAdmissionAuthority(
      owner,
      material.endpointOpenAuthority
    )
    material.endpointOpenAuthority = null
    opaqueDestination.stageDhtSeedAdmission(admission, encoded)
    opaqueDestination.commitDhtSeedAdmission(opaqueDestination.sealDhtSeedAdmission(admission))
    const binding = claimOpenRouteTransport(material)
    bindLiveOpaqueDestinationOwnerSession(owner, {
      branchId: material.branchId,
      finalTranscriptDigest: binding.finalTranscriptDigest
    })
    authority = Object.create(LiveRouteAuthority.prototype)
    const ownerState = {
      state: null,
      branch: BRANCH_CLASS.LOOKUP,
      capability: owner,
      branchId: b4a.from(material.branchId),
      circuitId: b4a.from(material.circuitId),
      finalTranscriptDigest: b4a.from(binding.finalTranscriptDigest),
      generation: material.generation,
      deadline: material.expiresAt,
      material,
      binding,
      codec:
        binding.codec || createPayloadCodec(material, ROUTE_ENDPOINT.SOURCE, options.monotonicNow)
    }
    binding.codec = null
    const state = {
      authority,
      routeManager: null,
      lease: null,
      owners: new Map([[BRANCH_CLASS.LOOKUP, ownerState]]),
      operations: new Set(),
      wallNow: options.wallNow,
      monotonicNow: options.monotonicNow,
      randomBytes: options.randomBytes,
      destroyed: false,
      resourcesRevoked: false,
      suspended: false,
      enforceHash: true,
      real: false
    }
    ownerState.state = state
    STATES.set(authority, state)
    Object.freeze(authority)
    material = null
    owner = null
    return authority
  } catch (err) {
    if (authority !== null && STATES.has(authority)) {
      try {
        authority.destroy()
      } catch {}
    } else {
      if (owner !== null) {
        try {
          destroyLiveOpaqueDestinations(owner)
        } catch {}
      }
      if (material !== null) {
        try {
          destroyOpenRouteMaterial(material)
        } catch {}
      }
    }
    throw err
  } finally {
    if (encoded !== null) encoded.fill(0)
  }
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
      (operation.branch !== BRANCH_CLASS.LOOKUP && operation.branch !== BRANCH_CLASS.ANNOUNCE) ||
      request.operationClass !== operation.branch ||
      !branchAllowsCommand(operation.branch, request.commandId)
    ) {
      authentication()
    }
    // The reply binding is an endpoint-local absolute instant, so it comes from the caller's
    // own clock domain and never from the request's relative `operationBudgetMs` (KI-15).
    if (!uint64(operation.operationDeadlineMs)) invalid()
    if (!Number.isSafeInteger(response.rtt) || response.rtt < 0) invalid()
    if (!Number.isSafeInteger(response.error) || response.error < 0) invalid()
    if (response.error === 0) {
      if (
        request.commandId === M3_MESSAGE_ID.IMMUTABLE_PUT_V1 ||
        request.commandId === M3_MESSAGE_ID.MUTABLE_PUT_V1
      ) {
        encodedResponse = b4a.from([0x00])
      } else if (request.commandId === M3_MESSAGE_ID.MUTABLE_GET_V1) {
        encodedResponse =
          response.value === null || response.value === undefined
            ? b4a.alloc(0)
            : b4a.from(response.value)
      } else {
        encodedResponse = encodeImmutableGetResponse({
          valuePresent: response.value !== null,
          value: response.value
        })
      }
    } else {
      encodedResponse = b4a.alloc(0)
    }
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
      deadline: operation.operationDeadlineMs,
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
        // Production seed receive sets binding.codec for both branches before claim.
        // The harness may omit announce seed frames; create only for lookup then.
        codec:
          binding.codec ||
          (branch === BRANCH_CLASS.LOOKUP
            ? createPayloadCodec(published.material, ROUTE_ENDPOINT.SOURCE, pair.monotonicNow)
            : null)
      })
      binding.codec = null
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
  if (options === null || typeof options !== 'object' || Reflect.ownKeys(options).length !== 5) {
    invalid()
  }
  for (const name of [
    'branch',
    'destinationRef',
    'encodedRequest',
    'attempt',
    'operationDeadlineMs'
  ]) {
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

function reportOwnedRouteFailure(state, branchClass) {
  if (
    !state.real ||
    state.destroyed ||
    state.suspended ||
    state.resourcesRevoked ||
    !state.routeManager
  )
    return false
  try {
    const { reportRouteManagerBranchLoss } = require('./route-manager')
    const owner = state.owners.get(branchClass)
    if (!owner) return false
    return reportRouteManagerBranchLoss(state.routeManager, branchClass, owner.generation)
  } catch {
    return false
  }
}

function noopRejection() {}

function clearOperationDeadline(operationState) {
  const cancel = operationState.cancelDeadline
  operationState.cancelDeadline = null
  if (typeof cancel === 'function') cancel()
}

// Nothing held the endpoint to any bound: the receive loop below awaits a reply with no
// deadline, so a hop that died silently left the operation hanging until branch material
// expired. The bound is the endpoint's OWN absolute deadline, derived by its caller from its
// OWN monotonic clock and handed over as `operationDeadlineMs`; the request's
// `operationBudgetMs` is the relative figure the exit admits and converts in its own domain.
// Since KI-15 the two are never compared across hosts, so this subtraction stays inside one
// clock domain - the same one `started` and the admission check in `requestProduction` read.
function branchAllowsCommand(branch, commandId) {
  if (branch === BRANCH_CLASS.LOOKUP) {
    return (
      commandId === M3_MESSAGE_ID.IMMUTABLE_GET_V1 || commandId === M3_MESSAGE_ID.MUTABLE_GET_V1
    )
  }
  if (branch === BRANCH_CLASS.ANNOUNCE) {
    return (
      commandId === M3_MESSAGE_ID.IMMUTABLE_GET_V1 ||
      commandId === M3_MESSAGE_ID.MUTABLE_GET_V1 ||
      commandId === M3_MESSAGE_ID.IMMUTABLE_PUT_V1 ||
      commandId === M3_MESSAGE_ID.MUTABLE_PUT_V1
    )
  }
  return false
}

// `operationBudgetMs` is the relative figure the exit admits and converts in its own domain.
// Since KI-15 the two are never compared across hosts, so this subtraction stays inside one
// clock domain - the same one `started` and the admission check in `requestProduction` read.
function armOperationDeadline(state, owner, operationState, operation, deadline, started) {
  const remaining = deadline - started
  const delayMs = remaining > 0n ? Number(remaining) : 0
  try {
    operationState.cancelDeadline = scheduleM3RouteTransportTimer(
      owner.binding.transport,
      delayMs,
      () => {
        operationState.cancelDeadline = null
        if (!operationState.live) return
        // Report before unwinding, matching the transport-error sites in the receive loop: a
        // route that missed its own deadline is a branch the manager must stop using.
        reportOwnedRouteFailure(state, owner.branch)
        operation.cancel(PrivateRouteError.ERR_PRIVACY_UNAVAILABLE())
      }
    )
  } catch (err) {
    // A transport that is already gone cannot be waited on, so it needs no deadline:
    // the send or receive below fails at once and reports the branch through the
    // transport-error path that already exists. Any other failure is a real fault.
    if (!(err instanceof PrivateRouteError) || err.code !== 'ERR_DESTROYED') throw err
  }
}

function requestProduction(authority, state, options) {
  assertProductionCurrent(state)
  if (state.suspended) throw PrivateRouteError.ERR_DESTROYED()
  options = exactRequestOptions(options)
  if (options.branch !== BRANCH_CLASS.LOOKUP && options.branch !== BRANCH_CLASS.ANNOUNCE) {
    const error = new Error('Private DHT command is unsupported')
    error.code = 'ERR_PRIVATE_COMMAND_UNSUPPORTED'
    throw error
  }
  if (!Number.isSafeInteger(options.attempt) || options.attempt < 1 || options.attempt > 4) {
    invalid()
  }
  const owner = ownerFor(state, options.branch)
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
    // The wire budget and this local deadline are two views of one bound, minted together
    // in `routed-dht-io.js`. Sampled once here so the two comparisons cannot straddle a
    // clock tick: the deadline must be in this host's future, and it must not outlast the
    // budget the exit was asked to admit. Without the second check a caller could
    // advertise 1ms and then wait minutes, which is the KI-15 fault re-entering from the
    // endpoint side rather than across hosts.
    const admitted = state.monotonicNow()
    const budgetCeiling = perCommandBudgetCeilingMs(request.commandId)
    if (
      request.operationClass !== options.branch ||
      !branchAllowsCommand(options.branch, request.commandId) ||
      !b4a.equals(request.destinationEncoded, destinationRef) ||
      request.operationBudgetMs === 0n ||
      request.operationBudgetMs > budgetCeiling ||
      !uint64(options.operationDeadlineMs) ||
      options.operationDeadlineMs <= admitted ||
      options.operationDeadlineMs - admitted > request.operationBudgetMs
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
      awaitingNetwork: false,
      receiveReservation: null,
      cancelDeadline: null
    }
    const cancellation = new Promise((resolve, reject) => {
      operationState.cancelReject = reject
    })
    const ownedRequest = request
    const ownedDestinationRef = destinationRef
    const ownedEncodedRequest = encodedRequest
    const ownedReassembler = reassembler
    const ownedDeadline = options.operationDeadlineMs
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
          operationState.awaitingNetwork = true
          try {
            await sendM3RouteFrame(owner.binding.transport, frame)
          } catch (err) {
            if (operationState.live) reportOwnedRouteFailure(state, owner.branch)
            throw err
          } finally {
            operationState.awaitingNetwork = false
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
        operationState.awaitingNetwork = true
        try {
          frame = await receiveReservedM3RouteFrame(receiveReservation)
        } catch (err) {
          if (operationState.live) reportOwnedRouteFailure(state, owner.branch)
          throw err
        } finally {
          operationState.awaitingNetwork = false
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
              // Must equal the referral authority's deadline, which the caller minted on this
              // same clock: `opaque-destination.js` creates and verifies both here, so this
              // binding stays a local monotonic absolute rather than the wire budget (KI-15).
              deadline: ownedDeadline,
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
      operationState.awaitingNetwork = false
      state.operations.delete(operation)
      cancelM3RouteFrameReservation(operationState.receiveReservation)
      operationState.receiveReservation = null
      ownedReassembler.destroy()
      ownedEncodedRequest.fill(0)
      ownedDestinationRef.fill(0)
      clearRoutedRequest(ownedRequest)
      clearOperationDeadline(operationState)
    })
    const operation = Object.freeze({
      promise,
      cancel(reason) {
        if (!operationState.live) return false
        operationState.live = false
        operationState.awaitingNetwork = false
        state.operations.delete(operation)
        cancelM3RouteFrameReservation(operationState.receiveReservation)
        operationState.receiveReservation = null
        reassembler.destroy()
        clearOperationDeadline(operationState)
        operationState.cancelReject(
          reason instanceof Error ? reason : PrivateRouteError.ERR_DESTROYED()
        )
        return true
      }
    })
    try {
      armOperationDeadline(state, owner, operationState, operation, ownedDeadline, started)
    } catch (err) {
      // Arming is the first statement here that can fail, and `run` is already in flight.
      // Unwind it through the operation's own cancel path so no orphaned receive loop and
      // no unobserved rejection outlives the throw.
      promise.catch(noopRejection)
      operation.cancel(err instanceof Error ? err : PrivateRouteError.ERR_DESTROYED())
      throw err
    }
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

function createRotatedLiveRouteAuthority(previousAuthority, routeManager, branchClass) {
  const previous = stateFor(previousAuthority)
  if (
    !previous.real ||
    previous.resourcesRevoked ||
    previous.suspended ||
    previous.operations.size !== 0 ||
    (branchClass !== BRANCH_CLASS.LOOKUP && branchClass !== BRANCH_CLASS.ANNOUNCE)
  ) {
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
  const { claimRotatedLiveRoutePair, revokeLiveRoutePair } = require('./route-manager')
  const claimed = claimRotatedLiveRoutePair(routeManager, branchClass)
  const unchangedClass =
    branchClass === BRANCH_CLASS.LOOKUP ? BRANCH_CLASS.ANNOUNCE : BRANCH_CLASS.LOOKUP
  const unchanged = previous.owners.get(unchangedClass)
  const name = branchClass === BRANCH_CLASS.LOOKUP ? 'lookup' : 'announce'
  const published = claimed.pair[name]
  const authority = Object.create(LiveRouteAuthority.prototype)
  let replacement = null
  let complete = false
  try {
    const binding = claimOpenRouteTransport(published.material)
    bindLiveOpaqueDestinationOwnerSession(published.owner, {
      branchId: published.material.branchId,
      finalTranscriptDigest: binding.finalTranscriptDigest
    })
    replacement = {
      state: null,
      branch: branchClass,
      capability: published.owner,
      branchId: b4a.from(published.material.branchId),
      circuitId: b4a.from(published.material.circuitId),
      finalTranscriptDigest: b4a.from(binding.finalTranscriptDigest),
      generation: published.material.generation,
      deadline: published.material.expiresAt,
      material: published.material,
      binding,
      codec:
        binding.codec ||
        (branchClass === BRANCH_CLASS.LOOKUP
          ? createPayloadCodec(published.material, ROUTE_ENDPOINT.SOURCE, claimed.pair.monotonicNow)
          : null)
    }
    binding.codec = null
    if (!unchanged || unchanged.state !== previous) {
      throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    }
    const owners = new Map([
      [unchangedClass, unchanged],
      [branchClass, replacement]
    ])
    const state = {
      authority,
      routeManager,
      lease: claimed.lease,
      owners,
      operations: new Set(),
      wallNow: claimed.pair.wallNow,
      monotonicNow: claimed.pair.monotonicNow,
      randomBytes: claimed.pair.randomBytes,
      destroyed: false,
      resourcesRevoked: false,
      suspended: false,
      enforceHash: true,
      real: true
    }
    unchanged.state = state
    replacement.state = state
    previous.owners.delete(unchangedClass)
    STATES.set(authority, state)
    Object.freeze(authority)
    complete = true
    return authority
  } finally {
    if (!complete) {
      try {
        revokeLiveRoutePair(claimed.lease)
      } catch {}
      if (replacement) {
        try {
          if (replacement.codec) replacement.codec.destroy()
        } catch {}
        try {
          destroyOpenRouteTransport(replacement.material)
        } catch {}
      }
    }
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
  }

  suspend() {
    const state = stateFor(this)
    if (state.suspended || state.resourcesRevoked) return
    state.suspended = true
    cancelProductionOperations(state, PrivateRouteError.ERR_DESTROYED())
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
    if (options.branch !== BRANCH_CLASS.LOOKUP && options.branch !== BRANCH_CLASS.ANNOUNCE) {
      invalid()
    }
    return snapshotLiveOpaqueDestinations(ownerFor(state, options.branch).capability, options.limit)
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
    open: openTestRouteAuthority,
    register: registerTestAuthority
  }),
  createRotatedLiveRouteAuthority,
  bindOpenRouteTransport,
  receiveOpenRouteSeedPayload,
  createLiveRouteReferralAuthority,
  destroyOpenRouteTransport,
  teardownOpenRouteTransport,
  idLiveRouteDestination,
  issueLiveRouteDestination,
  keyLiveRouteDestination,
  liveRouteBranchBinding,
  revokeLiveRouteDestination,
  snapshotLiveRouteDestination
})
