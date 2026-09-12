'use strict'

const b4a = require('b4a')

const { PrivateRouteError } = require('./errors')
const { LINK_OPERATION } = require('./protocol')
const {
  readPeerRelayOwner,
  readVerifiedPeerAdvertisement,
  createPeerCandidateLocator
} = require('./peer-capability')
const {
  readLinkHandle,
  subscribeLinkHandleClose,
  unsubscribeLinkHandleClose,
  parseAddress
} = require('./topology-grant')
const {
  createPeerLedger,
  reservePeerLedger,
  releasePeerLedger,
  readPeerLedger
} = require('./peer-ledger')
const { takePeerActiveCandidate } = require('./peer-direct-bootstrap')
const {
  createM3CellLinkTransferIssuer,
  registerPeerNeighborIssuerReleaseHook,
  exchangeSharedGuardPeerBranch,
  bindPeerNeighborServiceLedgers,
  registerPeerNeighborPhysicalLossSink,
  revokePeerNeighborPhysicalLossSink,
  closePeerNeighborSession,
  destroyPeerEstablishedLinkTeardown,
  createPeerCandidateDirectTransport,
  destroyPeerDirectRequesterTransport,
  UdxCellEndpoint
} = require('./udx-cell-endpoint')
const { encodeCanonicalEndpoint } = require('./relay-capability')

const POOLS = new WeakMap()
const POOL_COMPLETIONS = new WeakMap()
const NEIGHBOR_RESERVATIONS = new WeakMap()
const DESTROYED_NEIGHBOR_RESERVATIONS = new WeakSet()
const MAX_U64 = 0xffff_ffff_ffff_ffffn
const MAX_SHARED_BRANCH_SLOTS = 4
const MAX_TIMER_DELAY_MS = 2147483647n
const RATIFIED_CLOSE_PARTITION = Object.freeze({
  cells: 10,
  bytes: 12_000n,
  commands: 10
})
const DISCOVERY_RESERVATION = Object.freeze({
  cells: 24,
  bytes: 28800n,
  commands: 0
})
const NEIGHBOR_SERVICE_OWNERS = new WeakMap()

function toBigInt(val) {
  if (typeof val === 'bigint') return val
  if (typeof val === 'number' && Number.isSafeInteger(val) && val >= 0) return BigInt(val)
  throw PrivateRouteError.INVALID_ROUTE()
}

function createNeighborServiceOwner(session, endpoint, serviceLedger, closeLedger, lifetime) {
  if (!serviceLedger || !closeLedger || !isObject(lifetime)) throw PrivateRouteError.INVALID_ROUTE()
  readPeerLedger(serviceLedger)
  readPeerLedger(closeLedger)
  const token = Object.freeze({})
  NEIGHBOR_SERVICE_OWNERS.set(token, {
    session,
    endpoint,
    serviceLedger,
    closeLedger,
    clockIdentity: lifetime.clockIdentity,
    wallNow: lifetime.wallNow,
    monotonicNow: lifetime.monotonicNow,
    setTimer: lifetime.setTimer,
    clearTimer: lifetime.clearTimer,
    parentWireExpiresAt: lifetime.parentWireExpiresAt,
    parentLocalDeadline: lifetime.parentLocalDeadline,
    consumed: false
  })
  return token
}

function takeNeighborServiceOwner(token, session, endpoint) {
  const state = isObject(token) ? NEIGHBOR_SERVICE_OWNERS.get(token) : null
  if (!state || state.consumed) throw PrivateRouteError.UNAUTHORIZED()
  if (state.session !== session || state.endpoint !== endpoint) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  state.consumed = true
  NEIGHBOR_SERVICE_OWNERS.delete(token)
  readPeerLedger(state.serviceLedger)
  readPeerLedger(state.closeLedger)
  return {
    serviceLedger: state.serviceLedger,
    closeLedger: state.closeLedger,
    clockIdentity: state.clockIdentity,
    wallNow: state.wallNow,
    monotonicNow: state.monotonicNow,
    setTimer: state.setTimer,
    clearTimer: state.clearTimer,
    parentWireExpiresAt: state.parentWireExpiresAt,
    parentLocalDeadline: state.parentLocalDeadline
  }
}

function isObject(val) {
  return val !== null && typeof val === 'object' && !Array.isArray(val)
}

function armNeighborExpiryTimer(poolState, neighborRecord, parentLocalDeadline) {
  function step(initial = false) {
    if (neighborRecord.destroyed || poolState.destroyed) {
      neighborRecord.cleanup('expired')
      if (initial) throw PrivateRouteError.UNAUTHORIZED()
      return
    }
    const nowMono = BigInt(poolState.monotonicNow())
    const nowWall = BigInt(poolState.wallNow())
    if (nowMono >= parentLocalDeadline || nowWall >= neighborRecord.wireExpiresAt) {
      neighborRecord.cleanup('expired')
      if (initial) throw PrivateRouteError.UNAUTHORIZED()
      return
    }
    const remaining = parentLocalDeadline - nowMono
    const delay = Number(remaining > MAX_TIMER_DELAY_MS ? MAX_TIMER_DELAY_MS : remaining)
    let arming = true
    let fired = false
    let handle = null
    try {
      handle = poolState.setTimer(() => {
        if (arming) {
          fired = true
          return
        }
        if (neighborRecord.destroyed || neighborRecord.expiryTimer === null) return
        step(false)
      }, delay)
    } catch (err) {
      neighborRecord.cleanup('timer_failed')
      throw err
    }
    arming = false
    if (fired || neighborRecord.destroyed || poolState.destroyed) {
      neighborRecord.expiryTimer = null
      try {
        if (handle !== null) poolState.clearTimer(handle)
      } catch {}
      neighborRecord.cleanup('expired')
      if (initial || fired) {
        throw PrivateRouteError.UNAUTHORIZED()
      }
      return
    }
    neighborRecord.expiryTimer = handle
  }
  step(true)
}

function createPeerNativeNeighborPool(options) {
  if (!isObject(options)) throw PrivateRouteError.INVALID_ROUTE()

  const {
    relayOwner,
    endpoint,
    maxNeighbors = 16,
    nodeServiceBudget,
    neighborServiceReservation,
    neighborCloseReservation
  } = options

  if (!relayOwner || !endpoint || !(endpoint instanceof UdxCellEndpoint)) {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  if (!Number.isSafeInteger(maxNeighbors) || maxNeighbors < 1) {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  if (
    !isObject(neighborServiceReservation) ||
    typeof neighborServiceReservation.cells !== 'number' ||
    typeof neighborServiceReservation.commands !== 'number'
  ) {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  const neighborServiceBytes = toBigInt(neighborServiceReservation.bytes)

  if (neighborCloseReservation !== undefined) {
    if (
      !isObject(neighborCloseReservation) ||
      neighborCloseReservation.cells !== RATIFIED_CLOSE_PARTITION.cells ||
      toBigInt(neighborCloseReservation.bytes) !== RATIFIED_CLOSE_PARTITION.bytes ||
      neighborCloseReservation.commands !== RATIFIED_CLOSE_PARTITION.commands
    ) {
      throw PrivateRouteError.INVALID_ROUTE()
    }
  }
  if (
    !isObject(nodeServiceBudget) ||
    typeof nodeServiceBudget.cells !== 'number' ||
    typeof nodeServiceBudget.commands !== 'number'
  ) {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  const nodeServiceBytes = toBigInt(nodeServiceBudget.bytes)

  // Derive clocks from the owned relay owner
  const ownerInfo = readPeerRelayOwner(relayOwner, endpoint)

  // Always create the pool-owned root ledger from numeric allocation
  const nodeServiceLedger = createPeerLedger({
    cells: nodeServiceBudget.cells,
    bytes: nodeServiceBytes,
    commands: nodeServiceBudget.commands
  })
  const pool = Object.freeze({})
  let resolveCompletion
  const completion = new Promise((resolve) => {
    resolveCompletion = resolve
  })
  POOL_COMPLETIONS.set(pool, completion)
  const poolState = {
    pool,
    relayOwner,
    ownerInfo,
    endpoint,
    maxNeighbors,
    nodeServiceLedger,
    neighborServiceReservation: {
      cells: neighborServiceReservation.cells,
      bytes: neighborServiceBytes,
      commands: neighborServiceReservation.commands
    },
    neighborCloseReservation: RATIFIED_CLOSE_PARTITION,
    clockIdentity: ownerInfo.clockIdentity,
    wallNow: ownerInfo.wallNow,
    monotonicNow: ownerInfo.monotonicNow,
    setTimer: ownerInfo.setTimer,
    clearTimer: ownerInfo.clearTimer,
    neighbors: new Map(),
    pendingNeighborKeys: new Set(),
    pendingNeighborRecords: new Set(),
    reservations: new Map(),
    discoveries: new Set(),
    activeTeardowns: new Set(),
    resolveCompletion,
    destroyed: false
  }

  POOLS.set(pool, poolState)
  return pool
}

async function provisionPeerNativeNeighbor(pool, options) {
  const poolState = isObject(pool) ? POOLS.get(pool) : null
  if (!poolState || poolState.destroyed) {
    throw PrivateRouteError.UNAUTHORIZED()
  }

  // Revalidate relayOwner against endpoint live registry
  let ownerInfo
  try {
    ownerInfo = readPeerRelayOwner(poolState.relayOwner, poolState.endpoint)
  } catch (err) {
    destroyPeerNativeNeighborPool(poolState.pool)
    if (err instanceof PrivateRouteError) throw err
    throw PrivateRouteError.UNAUTHORIZED()
  }
  if (!ownerInfo) {
    destroyPeerNativeNeighborPool(poolState.pool)
    throw PrivateRouteError.UNAUTHORIZED()
  }

  if (!isObject(options)) throw PrivateRouteError.INVALID_ROUTE()
  if (options.topologyGrant !== undefined) throw PrivateRouteError.INVALID_ROUTE()
  if (!isObject(options.linkHandle)) throw PrivateRouteError.UNAUTHORIZED()

  // Strict mode validation
  if (options.mode !== 'initiate' && options.mode !== 'accept') {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  const mode = options.mode

  // Required real sessionOptions (no fake {mode} fallback)
  if (!isObject(options.sessionOptions)) {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  const sessionOptions = options.sessionOptions
  if (sessionOptions.mode !== mode) {
    throw PrivateRouteError.INVALID_ROUTE()
  }

  // Native absoluteDeadline must be a non-negative safe integer matching LinkBootstrapSession contract
  if (
    !Number.isSafeInteger(sessionOptions.absoluteDeadline) ||
    sessionOptions.absoluteDeadline < 0
  ) {
    throw PrivateRouteError.INVALID_ROUTE()
  }

  if (!sessionOptions.clockIdentity || sessionOptions.clockIdentity !== poolState.clockIdentity) {
    throw PrivateRouteError.UNAUTHORIZED()
  }

  // Verify deadlines
  const currWall = BigInt(poolState.wallNow())
  const currMono = BigInt(poolState.monotonicNow())
  if (poolState.destroyed || POOLS.get(pool) !== poolState) {
    throw PrivateRouteError.UNAUTHORIZED()
  }

  if (options.operationDeadline !== undefined) {
    if (
      typeof options.operationDeadline !== 'bigint' &&
      (typeof options.operationDeadline !== 'number' ||
        !Number.isSafeInteger(options.operationDeadline) ||
        options.operationDeadline < 0)
    ) {
      throw PrivateRouteError.INVALID_ROUTE()
    }
    const opDeadline = BigInt(options.operationDeadline)
    if (opDeadline <= currMono) {
      throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    }
  }

  if (BigInt(sessionOptions.absoluteDeadline) <= currMono) {
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }

  let adInfo
  let verifiedAdvertisement
  try {
    verifiedAdvertisement = options.advertisement
    adInfo = readVerifiedPeerAdvertisement(verifiedAdvertisement)
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    throw PrivateRouteError.UNAUTHORIZED()
  }

  if (
    adInfo.clockIdentity !== poolState.clockIdentity ||
    adInfo.wallNow !== poolState.wallNow ||
    adInfo.monotonicNow !== poolState.monotonicNow
  ) {
    throw PrivateRouteError.UNAUTHORIZED()
  }

  let link
  try {
    link = readLinkHandle(options.linkHandle)
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    throw PrivateRouteError.UNAUTHORIZED()
  }
  if (!link) throw PrivateRouteError.UNAUTHORIZED()

  const requiredOp = mode === 'accept' ? LINK_OPERATION.ACCEPT : LINK_OPERATION.INITIATE
  if ((link.operations & requiredOp) !== requiredOp) {
    throw PrivateRouteError.UNAUTHORIZED()
  }

  if (!b4a.equals(link.localIdentity32, poolState.ownerInfo.relayIdentity32)) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  if (!b4a.equals(link.peerIdentity32, adInfo.relayIdentity32)) {
    throw PrivateRouteError.UNAUTHORIZED()
  }

  let parsedPeer
  try {
    parsedPeer = parseAddress(link.peerAddress.host)
  } catch {
    throw PrivateRouteError.INVALID_ROUTE()
  }

  const peerEndpoint19 = encodeCanonicalEndpoint({
    addressFamily: parsedPeer.family,
    addressBytes: parsedPeer.bytes,
    port: link.peerAddress.port
  })

  if (!b4a.equals(peerEndpoint19, adInfo.reachableEndpoint19)) {
    throw PrivateRouteError.UNAUTHORIZED()
  }

  // Lifetime bounding BEFORE dialing
  const linkWireExpiresAt = BigInt(link.expiresAt)
  const adWireExpiresAt = BigInt(adInfo.wireExpiresAt || adInfo.expiresAt)
  const wireExpiresAt = linkWireExpiresAt < adWireExpiresAt ? linkWireExpiresAt : adWireExpiresAt
  if (wireExpiresAt <= currWall) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  const projectedDeadline = currMono + (wireExpiresAt - currWall)
  let parentLocalDeadline = projectedDeadline
  if (
    adInfo.clockIdentity === poolState.clockIdentity &&
    adInfo.localDeadline !== null &&
    adInfo.localDeadline !== undefined
  ) {
    const retained = BigInt(adInfo.localDeadline)
    if (retained < parentLocalDeadline) {
      parentLocalDeadline = retained
    }
  }
  if (parentLocalDeadline <= currMono) {
    throw PrivateRouteError.UNAUTHORIZED()
  }

  let clampedDeadlineBigInt = BigInt(sessionOptions.absoluteDeadline)
  if (options.operationDeadline !== undefined) {
    const opDeadline = BigInt(options.operationDeadline)
    if (opDeadline < clampedDeadlineBigInt) clampedDeadlineBigInt = opDeadline
  }
  if (parentLocalDeadline < clampedDeadlineBigInt) {
    clampedDeadlineBigInt = parentLocalDeadline
  }
  if (clampedDeadlineBigInt <= currMono) {
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
  if (clampedDeadlineBigInt > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  const clampedDeadline = Number(clampedDeadlineBigInt)

  const neighborKey = b4a.toString(adInfo.relayIdentity32, 'hex')
  const existingNeighbor = poolState.neighbors.get(neighborKey)

  // Do not publish over an expired same-identity record without cleanup:
  // if still live, reject with CIRCUIT_STATE; if expired, synchronously trigger cleanup
  if (existingNeighbor && !existingNeighbor.destroyed) {
    if (existingNeighbor.wireExpiresAt > currWall) {
      throw PrivateRouteError.CIRCUIT_STATE()
    }
    try {
      existingNeighbor.cleanup('expired')
    } catch {}
    if (poolState.neighbors.has(neighborKey)) {
      throw PrivateRouteError.CIRCUIT_STATE()
    }
  }

  if (poolState.pendingNeighborKeys.has(neighborKey)) {
    throw PrivateRouteError.CIRCUIT_STATE()
  }

  if (
    poolState.neighbors.size +
      poolState.pendingNeighborKeys.size +
      poolState.activeTeardowns.size >=
    poolState.maxNeighbors
  ) {
    throw PrivateRouteError.CIRCUIT_LIMIT()
  }

  // Synchronous reservation of peer identity and maxNeighbors slot BEFORE any async operations
  poolState.pendingNeighborKeys.add(neighborKey)

  // Transactional ledger reservation
  let serviceLedger
  let closeLedger
  try {
    serviceLedger = reservePeerLedger(
      poolState.nodeServiceLedger,
      poolState.neighborServiceReservation
    )
  } catch {
    poolState.pendingNeighborKeys.delete(neighborKey)
    throw PrivateRouteError.CIRCUIT_LIMIT()
  }
  try {
    closeLedger = reservePeerLedger(poolState.nodeServiceLedger, poolState.neighborCloseReservation)
  } catch {
    releasePeerLedger(serviceLedger)
    poolState.pendingNeighborKeys.delete(neighborKey)
    throw PrivateRouteError.CIRCUIT_LIMIT()
  }

  // Open link on endpoint with pool-owned timing fields and clamped safe deadline
  const actualSessionOptions = {
    ...sessionOptions,
    now: () => Number(poolState.monotonicNow()),
    schedule: (cb, ms) => poolState.setTimer(cb, ms),
    cancel: (timer) => poolState.clearTimer(timer),
    absoluteDeadline: clampedDeadline
  }

  let session
  try {
    session = poolState.endpoint.openLink(options.linkHandle, actualSessionOptions)
  } catch (err) {
    releasePeerLedger(serviceLedger)
    releasePeerLedger(closeLedger)
    poolState.pendingNeighborKeys.delete(neighborKey)
    throw err
  }

  // Centralized idempotent neighbor record and teardown owner
  const neighborRecord = {
    pool: poolState,
    peerIdentity32: b4a.from(adInfo.relayIdentity32),
    currentDhtNodeId32: b4a.from(adInfo.currentDhtNodeId32),
    capabilityMask: adInfo.capabilityMask,
    verifiedAdvertisement,
    canonicalAdvertisement260: b4a.from(adInfo.canonicalBytes260),
    advertisementDigest32: b4a.from(adInfo.advertisementDigest32),
    routeEncryptionPublicKey32: b4a.from(adInfo.routeEncryptionPublicKey32),
    localIdentity32: b4a.from(poolState.ownerInfo.relayIdentity32),
    peerEndpoint19,
    advertisementEpoch: adInfo.epoch,
    nativeEpoch: link.epoch,
    grantDigest32: b4a.from(link.digest32),
    runId32: b4a.from(link.runId32),
    operations: link.operations,
    wireExpiresAt,
    parentLocalDeadline,
    endpoint: poolState.endpoint,
    linkHandle: options.linkHandle,
    session,
    serviceLedger,
    closeLedger,
    branches: new Set(),
    discoveries: new Set(),
    lossRegistration: null,
    expiryTimer: null,
    linkCloseSub: null,
    bound: false,
    published: false,
    destroyed: false,
    teardownPromise: null,
    cleanup: null
  }

  // Track pending neighbor record in pool so pool destruction owns full teardown
  poolState.pendingNeighborRecords.add(neighborRecord)

  function cleanupNeighbor(reason) {
    if (neighborRecord.destroyed) {
      return neighborRecord.teardownPromise || Promise.resolve()
    }
    neighborRecord.destroyed = true
    let resolveTeardown
    const settled = new Promise((resolve) => {
      resolveTeardown = resolve
    })
    neighborRecord.teardownPromise = settled
    poolState.activeTeardowns.add(settled)

    const expiryTimer = neighborRecord.expiryTimer
    neighborRecord.expiryTimer = null
    if (expiryTimer !== null) {
      try {
        poolState.clearTimer(expiryTimer)
      } catch {}
    }

    if (neighborRecord.linkCloseSub !== null) {
      try {
        unsubscribeLinkHandleClose(neighborRecord.linkCloseSub)
      } catch {}
      neighborRecord.linkCloseSub = null
    }

    if (neighborRecord.lossRegistration !== null) {
      try {
        revokePeerNeighborPhysicalLossSink(neighborRecord.lossRegistration)
      } catch {}
      neighborRecord.lossRegistration = null
    }

    // Synchronously remove pool admission and revoke all branches immediately
    poolState.pendingNeighborKeys.delete(neighborKey)
    poolState.pendingNeighborRecords.delete(neighborRecord)
    if (poolState.neighbors.get(neighborKey) === neighborRecord) {
      poolState.neighbors.delete(neighborKey)
    }

    for (const res of Array.from(neighborRecord.branches)) {
      try {
        destroyPeerNeighborReservation(res)
      } catch {}
    }
    neighborRecord.branches.clear()
    if (neighborRecord.discoveries) {
      for (const disc of Array.from(neighborRecord.discoveries)) {
        try {
          disc.close()
        } catch {}
      }
      neighborRecord.discoveries.clear()
    }

    // Determine teardown promise: use closePeerNeighborSession or destroyPeerEstablishedLinkTeardown after binding
    let teardownPromise
    if (neighborRecord.bound) {
      if (neighborRecord.established) {
        teardownPromise = destroyPeerEstablishedLinkTeardown(neighborRecord.established, 0, {
          schedule: poolState.setTimer,
          cancel: poolState.clearTimer
        }).then(() => closePeerNeighborSession(session))
      } else {
        teardownPromise = closePeerNeighborSession(session)
      }
    } else {
      try {
        void session.close().catch(() => {})
      } catch {}
      teardownPromise = Promise.resolve()
    }

    const releaseLedgers = () => {
      try {
        releasePeerLedger(serviceLedger)
      } catch {}
      try {
        releasePeerLedger(closeLedger)
      } catch {}
    }

    void Promise.resolve(teardownPromise)
      .then(releaseLedgers, releaseLedgers)
      .then(() => {
        poolState.activeTeardowns.delete(settled)
        resolveTeardown()
      })
    return settled
  }

  neighborRecord.cleanup = cleanupNeighbor

  // Mint one-shot opaque neighbor-service owner
  const ownerToken = createNeighborServiceOwner(
    session,
    poolState.endpoint,
    serviceLedger,
    closeLedger,
    {
      clockIdentity: poolState.clockIdentity,
      wallNow: poolState.wallNow,
      monotonicNow: poolState.monotonicNow,
      setTimer: poolState.setTimer,
      clearTimer: poolState.clearTimer,
      parentWireExpiresAt: wireExpiresAt,
      parentLocalDeadline
    }
  )
  // Bind neighbor service/close ownership BEFORE calling session.open()
  try {
    bindPeerNeighborServiceLedgers(session, ownerToken)
    neighborRecord.bound = true
  } catch (err) {
    cleanupNeighbor('bind_failed')
    throw err
  }

  // Register native physical loss sink immediately after binding
  try {
    neighborRecord.lossRegistration = registerPeerNeighborPhysicalLossSink(session, (reason) => {
      cleanupNeighbor(reason || 'physical_loss')
    })
  } catch (err) {
    cleanupNeighbor('loss_sink_failed')
    throw err
  }

  let established = session.established
  if (!established) {
    if (mode === 'initiate' && typeof session.open === 'function') {
      try {
        await session.open()
        established = session.established
      } catch (err) {
        cleanupNeighbor('open_failed')
        throw err
      }
    } else if (mode === 'accept') {
      try {
        if (typeof session.waitAccepted !== 'function') {
          throw PrivateRouteError.UNAUTHORIZED()
        }
        established = await session.waitAccepted()
      } catch (err) {
        cleanupNeighbor('accept_failed')
        throw err
      }
    }
  }

  // Genuine established handle MUST be obtained from session
  if (!established || !isObject(established) || neighborRecord.destroyed) {
    cleanupNeighbor('unestablished')
    throw PrivateRouteError.UNAUTHORIZED()
  }

  // Ensure same live pool, owner, link and deadline after awaits before publish
  if (poolState.destroyed) {
    cleanupNeighbor('pool_destroyed')
    throw PrivateRouteError.ERR_DESTROYED()
  }

  let postOwner
  try {
    postOwner = readPeerRelayOwner(poolState.relayOwner, poolState.endpoint)
  } catch (err) {
    cleanupNeighbor('owner_check_failed')
    if (err instanceof PrivateRouteError) throw err
    throw PrivateRouteError.UNAUTHORIZED()
  }
  if (!postOwner || !b4a.equals(postOwner.relayIdentity32, poolState.ownerInfo.relayIdentity32)) {
    cleanupNeighbor('owner_mismatch')
    throw PrivateRouteError.UNAUTHORIZED()
  }

  // Re-read linkHandle post-await and establish exact same link properties before publish
  let postLink
  try {
    postLink = readLinkHandle(options.linkHandle)
  } catch (err) {
    cleanupNeighbor('link_read_failed')
    if (err instanceof PrivateRouteError) throw err
    throw PrivateRouteError.UNAUTHORIZED()
  }
  if (
    !postLink ||
    !b4a.equals(postLink.localIdentity32, link.localIdentity32) ||
    !b4a.equals(postLink.peerIdentity32, link.peerIdentity32) ||
    !b4a.equals(postLink.digest32, link.digest32) ||
    !b4a.equals(postLink.runId32, link.runId32) ||
    postLink.epoch !== link.epoch ||
    postLink.operations !== link.operations ||
    postLink.expiresAt !== link.expiresAt ||
    postLink.peerAddress.host !== link.peerAddress.host ||
    postLink.peerAddress.port !== link.peerAddress.port ||
    postLink.localAddress.host !== link.localAddress.host ||
    postLink.localAddress.port !== link.localAddress.port
  ) {
    cleanupNeighbor('link_mismatch')
    throw PrivateRouteError.UNAUTHORIZED()
  }

  let postParsedPeer
  try {
    postParsedPeer = parseAddress(postLink.peerAddress.host)
  } catch {
    cleanupNeighbor('endpoint_parse_failed')
    throw PrivateRouteError.INVALID_ROUTE()
  }
  const postPeerEndpoint19 = encodeCanonicalEndpoint({
    addressFamily: postParsedPeer.family,
    addressBytes: postParsedPeer.bytes,
    port: postLink.peerAddress.port
  })
  if (!b4a.equals(postPeerEndpoint19, adInfo.reachableEndpoint19)) {
    cleanupNeighbor('endpoint_mismatch')
    throw PrivateRouteError.UNAUTHORIZED()
  }

  const postWall = BigInt(poolState.wallNow())
  const postMono = BigInt(poolState.monotonicNow())
  if (wireExpiresAt <= postWall || parentLocalDeadline <= postMono) {
    cleanupNeighbor('expired')
    throw PrivateRouteError.UNAUTHORIZED()
  }

  if (session.state === 'CLOSED' || session.state === 'TOMBSTONE') {
    cleanupNeighbor('session_closed')
    throw PrivateRouteError.UNAUTHORIZED()
  }

  if (!poolState.pendingNeighborKeys.has(neighborKey)) {
    cleanupNeighbor('pending_revoked')
    throw PrivateRouteError.UNAUTHORIZED()
  }

  neighborRecord.established = established

  // Publish neighbor into live pool map and release pending keys
  poolState.neighbors.set(neighborKey, neighborRecord)
  neighborRecord.published = true
  poolState.pendingNeighborKeys.delete(neighborKey)
  poolState.pendingNeighborRecords.delete(neighborRecord)

  armNeighborExpiryTimer(poolState, neighborRecord, parentLocalDeadline)

  // Arm link close subscription with arming/fired-synchronously guard
  let subArming = true
  let subFired = false
  let subHandle = null
  try {
    subHandle = subscribeLinkHandleClose(options.linkHandle, () => {
      if (subArming) {
        subFired = true
        return
      }
      cleanupNeighbor('closed')
    })
  } catch (err) {
    cleanupNeighbor('sub_failed')
    throw err
  }
  subArming = false
  if (subFired || neighborRecord.destroyed || poolState.destroyed) {
    try {
      unsubscribeLinkHandleClose(subHandle)
    } catch {}
    cleanupNeighbor('closed')
    throw PrivateRouteError.UNAUTHORIZED()
  }
  neighborRecord.linkCloseSub = subHandle

  // Final check for synchronous reentry destruction
  if (neighborRecord.destroyed) {
    throw PrivateRouteError.UNAUTHORIZED()
  }

  return Object.freeze({
    kind: 'neighbor',
    identity32: b4a.from(adInfo.relayIdentity32),
    endpoint: poolState.endpoint,
    established
  })
}

function reservePeerNeighborLink(pool, options) {
  const poolState = isObject(pool) ? POOLS.get(pool) : null
  if (!poolState || poolState.destroyed) {
    throw PrivateRouteError.UNAUTHORIZED()
  }

  // Revalidate relayOwner against endpoint live registry
  try {
    readPeerRelayOwner(poolState.relayOwner, poolState.endpoint)
  } catch (err) {
    destroyPeerNativeNeighborPool(poolState.pool)
    if (err instanceof PrivateRouteError) throw err
    throw PrivateRouteError.UNAUTHORIZED()
  }

  if (!isObject(options)) throw PrivateRouteError.INVALID_ROUTE()

  const { advertisement260, activeCandidate, absoluteDeadline } = options
  if (!b4a.isBuffer(advertisement260) || advertisement260.byteLength !== 260) {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  if (typeof absoluteDeadline !== 'bigint') {
    throw PrivateRouteError.INVALID_ROUTE()
  }

  const nowMono = BigInt(poolState.monotonicNow())
  if (absoluteDeadline <= nowMono) {
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }

  const nowWall = BigInt(poolState.wallNow())

  // Match live neighbor first: exact advertisement, identity, endpoint, epoch, clock
  let matchingNeighbor = null
  for (const neighbor of poolState.neighbors.values()) {
    if (
      !neighbor.destroyed &&
      b4a.equals(neighbor.canonicalAdvertisement260, advertisement260) &&
      neighbor.wireExpiresAt > nowWall &&
      neighbor.parentLocalDeadline > nowMono
    ) {
      matchingNeighbor = neighbor
      break
    }
  }

  if (!matchingNeighbor) {
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }

  // All v1/v2 branches share the existing physical four-slot set
  if (matchingNeighbor.branches.size >= MAX_SHARED_BRANCH_SLOTS) {
    throw PrivateRouteError.CIRCUIT_LIMIT()
  }

  // Synchronously install provisional state and branch slot before callbacks/issuer creation
  const reservation = Object.freeze({})
  const resState = {
    reservation,
    pool: poolState,
    neighbor: matchingNeighbor,
    physicalIssuer: null,
    absoluteDeadline,
    deadlineTimer: null,
    taken: false,
    exchanged: false,
    exchanging: false,
    exchangeSuccess: false,
    destroyed: false
  }

  matchingNeighbor.branches.add(reservation)
  NEIGHBOR_RESERVATIONS.set(reservation, resState)
  poolState.reservations.set(reservation, resState)

  function rollbackReservation(err) {
    destroyPeerNeighborReservation(reservation)
    throw err
  }

  // Transactional creation of physical issuer, hook registration, and candidate take
  let physicalIssuer
  try {
    physicalIssuer = createM3CellLinkTransferIssuer(
      matchingNeighbor.endpoint,
      matchingNeighbor.established,
      { sharedGuard: true }
    )
  } catch (err) {
    rollbackReservation(err instanceof PrivateRouteError ? err : PrivateRouteError.CIRCUIT_LIMIT())
  }
  if (!physicalIssuer) {
    rollbackReservation(PrivateRouteError.CIRCUIT_LIMIT())
  }
  resState.physicalIssuer = physicalIssuer
  if (resState.destroyed || matchingNeighbor.destroyed || poolState.destroyed) {
    physicalIssuer.destroy()
    rollbackReservation(PrivateRouteError.UNAUTHORIZED())
  }

  try {
    registerPeerNeighborIssuerReleaseHook(physicalIssuer, () => {
      destroyPeerNeighborReservation(reservation)
    })
  } catch (err) {
    rollbackReservation(err instanceof PrivateRouteError ? err : PrivateRouteError.UNAUTHORIZED())
  }

  // Match THEN consume candidate provenance with expectedKind: 'candidate' and expectedAdvertisement260
  let candidate
  try {
    candidate = takePeerActiveCandidate(activeCandidate, {
      expectedKind: 'candidate',
      expectedIdentity32: matchingNeighbor.peerIdentity32,
      expectedEndpoint19: matchingNeighbor.peerEndpoint19,
      expectedEpoch: matchingNeighbor.advertisementEpoch,
      expectedAdvertisement260: matchingNeighbor.canonicalAdvertisement260,
      clockIdentity: poolState.clockIdentity
    })
  } catch (err) {
    rollbackReservation(err instanceof PrivateRouteError ? err : PrivateRouteError.UNAUTHORIZED())
  }

  if (!candidate) {
    rollbackReservation(PrivateRouteError.UNAUTHORIZED())
  }

  if (matchingNeighbor.parentLocalDeadline < resState.absoluteDeadline) {
    resState.absoluteDeadline = matchingNeighbor.parentLocalDeadline
  }
  if (candidate.localDeadline < resState.absoluteDeadline) {
    resState.absoluteDeadline = candidate.localDeadline
  }
  const opTimeoutMs = Number(resState.absoluteDeadline - BigInt(poolState.monotonicNow()))
  if (opTimeoutMs <= 0) {
    rollbackReservation(PrivateRouteError.ERR_PRIVACY_UNAVAILABLE())
  }

  let resArming = true
  let resFired = false
  let resTimer = null

  function armReservationTimer() {
    if (resState.destroyed || matchingNeighbor.destroyed || poolState.destroyed) return
    const nowMono = BigInt(poolState.monotonicNow())
    const nowWall = BigInt(poolState.wallNow())
    if (nowMono >= resState.absoluteDeadline || nowWall >= matchingNeighbor.wireExpiresAt) {
      destroyPeerNeighborReservation(reservation)
      return
    }
    const remaining = resState.absoluteDeadline - nowMono
    const chunkMs = Number(remaining > MAX_TIMER_DELAY_MS ? MAX_TIMER_DELAY_MS : remaining)

    resArming = true
    resFired = false
    try {
      resTimer = poolState.setTimer(() => {
        if (resArming) {
          resFired = true
          return
        }
        if (resState.destroyed || resState.deadlineTimer === null) return
        armReservationTimer()
      }, chunkMs)
    } catch (err) {
      rollbackReservation(err)
      return
    }
    resArming = false
    if (resFired || resState.destroyed || matchingNeighbor.destroyed || poolState.destroyed) {
      resState.deadlineTimer = null
      try {
        if (resTimer !== null) poolState.clearTimer(resTimer)
      } catch {}
      destroyPeerNeighborReservation(reservation)
      if (resFired) {
        throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
      }
      return
    }
    resState.deadlineTimer = resTimer
  }

  armReservationTimer()
  // Guard synchronous callback / timer firing reentry
  if (resState.destroyed) {
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }

  return reservation
}

function readPeerNeighborReservation(reservation, relayOwner) {
  if (!isObject(reservation)) return null
  if (DESTROYED_NEIGHBOR_RESERVATIONS.has(reservation)) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  const resState = NEIGHBOR_RESERVATIONS.get(reservation)
  if (!resState) return null
  if (resState.destroyed || resState.neighbor.destroyed || resState.pool.destroyed) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  if (BigInt(resState.pool.monotonicNow()) >= resState.absoluteDeadline) {
    destroyPeerNeighborReservation(reservation)
    throw PrivateRouteError.UNAUTHORIZED()
  }

  const { pool, neighbor } = resState

  let ownerInfo
  try {
    ownerInfo = readPeerRelayOwner(relayOwner, neighbor.endpoint)
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    throw PrivateRouteError.UNAUTHORIZED()
  }
  if (!ownerInfo || ownerInfo.clockIdentity !== pool.clockIdentity) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  if (!b4a.equals(ownerInfo.relayIdentity32, neighbor.localIdentity32)) {
    throw PrivateRouteError.UNAUTHORIZED()
  }

  return Object.freeze({
    kind: 'candidate',
    endpoint: neighbor.endpoint,
    established: neighbor.established,
    localIdentity32: b4a.from(neighbor.localIdentity32),
    peerIdentity32: b4a.from(neighbor.peerIdentity32),
    peerEndpoint19: b4a.from(neighbor.peerEndpoint19),
    nativeEpoch: neighbor.nativeEpoch,
    grantDigest32: b4a.from(neighbor.grantDigest32),
    runId32: b4a.from(neighbor.runId32),
    operations: neighbor.operations,
    clockIdentity: pool.clockIdentity,
    wallNow: pool.wallNow,
    monotonicNow: pool.monotonicNow,
    setTimer: pool.setTimer,
    clearTimer: pool.clearTimer,
    parentWireExpiresAt: neighbor.wireExpiresAt,
    parentLocalDeadline: neighbor.parentLocalDeadline,
    operationLocalDeadline: resState.absoluteDeadline
  })
}

function exchangePeerNeighborLink(reservation, options) {
  const resState = isObject(reservation) ? NEIGHBOR_RESERVATIONS.get(reservation) : null
  if (
    !resState ||
    resState.destroyed ||
    resState.taken ||
    resState.exchanged ||
    resState.exchanging
  ) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  const { pool, neighbor } = resState
  if (pool.destroyed || neighbor.destroyed) {
    throw PrivateRouteError.ERR_DESTROYED()
  }

  try {
    readPeerRelayOwner(pool.relayOwner, neighbor.endpoint)
  } catch (err) {
    destroyPeerNativeNeighborPool(pool.pool)
    if (err instanceof PrivateRouteError) throw err
    throw PrivateRouteError.UNAUTHORIZED()
  }

  const nowMono = BigInt(pool.monotonicNow())
  if (nowMono >= resState.absoluteDeadline) {
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }

  if (
    !isObject(options) ||
    !b4a.isBuffer(options.offer) ||
    options.offer.byteLength !== 432 ||
    typeof options.generation !== 'bigint' ||
    options.generation < 1n ||
    options.generation > MAX_U64 ||
    !options.sendLedger ||
    !options.receiveLedger
  ) {
    throw PrivateRouteError.INVALID_ROUTE()
  }

  try {
    readPeerLedger(options.sendLedger)
    readPeerLedger(options.receiveLedger)
  } catch {
    throw PrivateRouteError.UNAUTHORIZED()
  }

  resState.exchanging = true

  let sending
  try {
    sending = exchangeSharedGuardPeerBranch(neighbor.established, {
      offer: options.offer,
      generation: options.generation,
      sendLedger: options.sendLedger,
      receiveLedger: options.receiveLedger,
      issuer: resState.physicalIssuer,
      absoluteDeadline: resState.absoluteDeadline,
      now: pool.monotonicNow,
      schedule: pool.setTimer,
      cancel: pool.clearTimer
    })
  } catch (err) {
    resState.exchanging = false
    destroyPeerNeighborReservation(reservation)
    throw err
  }

  return Promise.resolve(sending).then(
    (accept) => {
      resState.exchanging = false

      // Bound and check deadline and liveness again on exchange fulfillment before returning bytes
      if (resState.destroyed || pool.destroyed || neighbor.destroyed) {
        destroyPeerNeighborReservation(reservation)
        throw PrivateRouteError.ERR_DESTROYED()
      }

      const postMono = BigInt(pool.monotonicNow())
      if (postMono >= resState.absoluteDeadline) {
        destroyPeerNeighborReservation(reservation)
        throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
      }

      const postWall = BigInt(pool.wallNow())
      if (postWall >= neighbor.wireExpiresAt) {
        destroyPeerNeighborReservation(reservation)
        throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
      }

      resState.exchanged = true
      resState.exchangeSuccess = true
      return accept
    },
    (err) => {
      resState.exchanging = false
      resState.exchanged = true
      resState.exchangeSuccess = false
      destroyPeerNeighborReservation(reservation)
      throw err
    }
  )
}

function takePeerNeighborPhysicalIssuer(reservation) {
  const resState = isObject(reservation) ? NEIGHBOR_RESERVATIONS.get(reservation) : null
  if (!resState || resState.destroyed || resState.taken) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  if (!resState.exchanged || !resState.exchangeSuccess) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  const preMono = BigInt(resState.pool.monotonicNow())
  const preWall = BigInt(resState.pool.wallNow())
  if (
    resState.pool.destroyed ||
    resState.neighbor.destroyed ||
    preMono >= resState.absoluteDeadline ||
    preWall >= resState.neighbor.wireExpiresAt
  ) {
    destroyPeerNeighborReservation(reservation)
    throw PrivateRouteError.UNAUTHORIZED()
  }
  resState.taken = true
  const timer = resState.deadlineTimer
  resState.deadlineTimer = null
  try {
    if (timer !== null) resState.pool.clearTimer(timer)
  } catch (err) {
    destroyPeerNeighborReservation(reservation)
    throw err
  }
  const postMono = BigInt(resState.pool.monotonicNow())
  const postWall = BigInt(resState.pool.wallNow())
  if (
    resState.destroyed ||
    resState.pool.destroyed ||
    resState.neighbor.destroyed ||
    postMono >= resState.absoluteDeadline ||
    postWall >= resState.neighbor.wireExpiresAt
  ) {
    destroyPeerNeighborReservation(reservation)
    throw PrivateRouteError.UNAUTHORIZED()
  }
  const issuer = resState.physicalIssuer
  resState.physicalIssuer = null
  return issuer
}

function destroyPeerNeighborReservation(reservation) {
  if (!isObject(reservation)) return false
  if (DESTROYED_NEIGHBOR_RESERVATIONS.has(reservation)) return false
  const resState = NEIGHBOR_RESERVATIONS.get(reservation)
  if (!resState) return false

  DESTROYED_NEIGHBOR_RESERVATIONS.add(reservation)
  resState.destroyed = true
  const timer = resState.deadlineTimer
  resState.deadlineTimer = null
  if (timer !== null) {
    try {
      resState.pool.clearTimer(timer)
    } catch {}
  }
  NEIGHBOR_RESERVATIONS.delete(reservation)
  if (resState.pool) {
    resState.pool.reservations.delete(reservation)
  }
  if (resState.neighbor) {
    resState.neighbor.branches.delete(reservation)
  }
  if (resState.physicalIssuer && typeof resState.physicalIssuer.destroy === 'function') {
    try {
      resState.physicalIssuer.destroy()
    } catch {}
    resState.physicalIssuer = null
  }
  return true
}

function destroyPeerNativeNeighborPool(pool) {
  if (!isObject(pool)) return false
  const state = POOLS.get(pool)
  if (!state || state.destroyed) return false
  state.destroyed = true
  POOLS.delete(pool)

  for (const reservation of Array.from(state.reservations.keys())) {
    try {
      destroyPeerNeighborReservation(reservation)
    } catch {}
  }
  state.reservations.clear()
  if (state.discoveries) {
    for (const disc of Array.from(state.discoveries)) {
      try {
        disc.close()
      } catch {}
    }
    state.discoveries.clear()
  }

  // Clean up all pending neighbor records via their own idempotent cleanup
  for (const pendingRecord of Array.from(state.pendingNeighborRecords)) {
    try {
      pendingRecord.cleanup('pool_destroyed')
    } catch {}
  }
  state.pendingNeighborRecords.clear()
  state.pendingNeighborKeys.clear()

  for (const neighbor of Array.from(state.neighbors.values())) {
    if (typeof neighbor.cleanup === 'function') {
      try {
        neighbor.cleanup('pool_destroyed')
      } catch {}
    }
  }
  state.neighbors.clear()

  if (state.nodeServiceLedger) {
    const nodeLedger = state.nodeServiceLedger
    state.nodeServiceLedger = null

    // Settle all active teardowns before releasing root nodeServiceLedger
    function settleTeardowns() {
      if (state.activeTeardowns.size === 0) {
        try {
          releasePeerLedger(nodeLedger)
        } catch {}
        state.resolveCompletion(true)
        return
      }
      const current = Array.from(state.activeTeardowns)
      Promise.allSettled(current).then(settleTeardowns, settleTeardowns)
    }
    settleTeardowns()
  }

  return true
}

// Destruction revokes synchronously. This join proves actual native completion
// and ledger release, not merely caller cancellation or the close grace deadline.
function joinPeerNativeNeighborPool(pool) {
  return POOL_COMPLETIONS.get(pool) || Promise.resolve(false)
}

function readPeerNativeNeighborDiagnostics(pool) {
  const state = isObject(pool) ? POOLS.get(pool) : null
  if (!state) return null
  return Object.freeze({
    destroyed: state.destroyed,
    neighborCount: state.neighbors.size,
    pendingCount: state.pendingNeighborKeys.size,
    reservationCount: state.reservations.size,
    maxNeighbors: state.maxNeighbors,
    nodeServiceLedger: state.nodeServiceLedger ? readPeerLedger(state.nodeServiceLedger) : null
  })
}
const discoveryByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get

function discoveryTime(value) {
  if (typeof value === 'number' && Number.isSafeInteger(value)) value = BigInt(value)
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  return value
}

function copyDiscoveryBytes(value, size) {
  if (!b4a.isBuffer(value) || discoveryByteLength.call(value) !== size) {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  const copy = b4a.allocUnsafeSlow(size)
  Uint8Array.prototype.set.call(copy, value)
  return copy
}

function snapshotDiscoveryRequest(request) {
  try {
    const keys = Reflect.ownKeys(request)
    const allowed = [
      'mode',
      'requestedMask',
      'randomTarget32',
      'suppliedAdvertisement260',
      'clockIdentity',
      'wireExpiresAt',
      'localDeadline'
    ]
    if (keys.length !== allowed.length || keys.some((key) => !allowed.includes(key))) {
      throw PrivateRouteError.INVALID_ROUTE()
    }
    const fields = {}
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(request, key)
      if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
        throw PrivateRouteError.INVALID_ROUTE()
      }
      fields[key] = descriptor.value
    }
    if (
      (fields.mode !== 1 && fields.mode !== 2) ||
      (fields.requestedMask !== 9 && fields.requestedMask !== 11) ||
      (fields.mode === 2 && fields.requestedMask !== 11) ||
      (fields.mode === 1 && fields.suppliedAdvertisement260 !== null)
    ) {
      throw PrivateRouteError.INVALID_ROUTE()
    }
    fields.wireExpiresAt = discoveryTime(fields.wireExpiresAt)
    fields.localDeadline = discoveryTime(fields.localDeadline)
    fields.randomTarget32 = copyDiscoveryBytes(fields.randomTarget32, 32)
    if (fields.mode === 2) {
      fields.suppliedAdvertisement260 = copyDiscoveryBytes(fields.suppliedAdvertisement260, 260)
    }
    return Object.freeze(fields)
  } catch {
    throw PrivateRouteError.INVALID_ROUTE()
  }
}

function compareXorDistance(nodeIdA, nodeIdB, target32, identityA, identityB) {
  for (let i = 0; i < 32; i++) {
    const da = nodeIdA[i] ^ target32[i]
    const db = nodeIdB[i] ^ target32[i]
    if (da !== db) return da < db ? -1 : 1
  }
  return b4a.compare(identityA, identityB)
}

function createPeerNativeNeighborDiscovery(pool, request) {
  const poolState = POOLS.get(pool)
  if (!poolState || poolState.destroyed) throw PrivateRouteError.UNAUTHORIZED()
  const fields = snapshotDiscoveryRequest(request)
  if (fields.clockIdentity !== poolState.clockIdentity) throw PrivateRouteError.UNAUTHORIZED()

  let nowWall
  let nowMono
  try {
    nowWall = discoveryTime(poolState.wallNow())
    nowMono = discoveryTime(poolState.monotonicNow())
    readPeerRelayOwner(poolState.relayOwner, poolState.endpoint)
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    throw PrivateRouteError.INVALID_ROUTE()
  }
  if (poolState.destroyed) throw PrivateRouteError.UNAUTHORIZED()
  if (fields.wireExpiresAt <= nowWall || fields.localDeadline <= nowMono) {
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }

  let selectedNeighbor = null
  let selectedKey = null
  for (const [key, neighbor] of poolState.neighbors) {
    if (
      neighbor.destroyed ||
      !neighbor.published ||
      !neighbor.established ||
      neighbor.wireExpiresAt <= nowWall ||
      neighbor.parentLocalDeadline <= nowMono ||
      (neighbor.capabilityMask & fields.requestedMask) !== fields.requestedMask
    )
      continue
    if (
      fields.mode === 2 &&
      !b4a.equals(neighbor.canonicalAdvertisement260, fields.suppliedAdvertisement260)
    )
      continue
    if (
      !selectedNeighbor ||
      compareXorDistance(
        neighbor.currentDhtNodeId32,
        selectedNeighbor.currentDhtNodeId32,
        fields.randomTarget32,
        neighbor.peerIdentity32,
        selectedNeighbor.peerIdentity32
      ) < 0
    ) {
      selectedNeighbor = neighbor
      selectedKey = key
    }
  }
  if (!selectedNeighbor) throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()

  const opWireExpiresAt =
    fields.wireExpiresAt < selectedNeighbor.wireExpiresAt
      ? fields.wireExpiresAt
      : selectedNeighbor.wireExpiresAt
  let effectiveLocalDeadline =
    fields.localDeadline < selectedNeighbor.parentLocalDeadline
      ? fields.localDeadline
      : selectedNeighbor.parentLocalDeadline
  const projectedWire = nowMono + (opWireExpiresAt - nowWall)
  if (projectedWire < effectiveLocalDeadline) effectiveLocalDeadline = projectedWire
  const operationDeadline = nowMono + 5000n
  if (operationDeadline < effectiveLocalDeadline) effectiveLocalDeadline = operationDeadline
  if (effectiveLocalDeadline <= nowMono) throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()

  let discoveryLedger = null
  let transport = null
  let deadlineTimer = null
  let closed = false
  const discoveryRecord = { close }

  function close() {
    if (closed) return false
    closed = true
    selectedNeighbor.discoveries.delete(discoveryRecord)
    poolState.discoveries.delete(discoveryRecord)
    const timer = deadlineTimer
    deadlineTimer = null
    if (timer !== null) {
      try {
        poolState.clearTimer(timer)
      } catch {}
    }
    if (transport) {
      try {
        destroyPeerDirectRequesterTransport(transport)
      } catch {}
    }
    if (discoveryLedger) {
      try {
        releasePeerLedger(discoveryLedger)
      } catch {}
    }
    return true
  }

  function checkLive() {
    const wall = discoveryTime(poolState.wallNow())
    const mono = discoveryTime(poolState.monotonicNow())
    readPeerRelayOwner(poolState.relayOwner, poolState.endpoint)
    if (
      closed ||
      poolState.destroyed ||
      selectedNeighbor.destroyed ||
      poolState.neighbors.get(selectedKey) !== selectedNeighbor
    )
      throw PrivateRouteError.UNAUTHORIZED()
    if (wall >= opWireExpiresAt || mono >= effectiveLocalDeadline) {
      throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    }
    return mono
  }

  function armDiscoveryTimer() {
    const mono = checkLive()
    const remaining = effectiveLocalDeadline - mono
    let arming = true
    let firedSynchronously = false
    const handle = poolState.setTimer(
      () => {
        if (arming) {
          firedSynchronously = true
          return
        }
        deadlineTimer = null
        if (closed) return
        try {
          armDiscoveryTimer()
        } catch {
          close()
        }
      },
      Number(remaining > MAX_TIMER_DELAY_MS ? MAX_TIMER_DELAY_MS : remaining)
    )
    arming = false
    if (firedSynchronously || closed || handle === null || handle === undefined) {
      if (handle !== null && handle !== undefined) {
        try {
          poolState.clearTimer(handle)
        } catch {}
      }
      throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    }
    deadlineTimer = handle
    checkLive()
  }

  try {
    try {
      discoveryLedger = reservePeerLedger(selectedNeighbor.serviceLedger, DISCOVERY_RESERVATION)
    } catch {
      throw PrivateRouteError.CIRCUIT_LIMIT()
    }
    selectedNeighbor.discoveries.add(discoveryRecord)
    poolState.discoveries.add(discoveryRecord)
    const deadlineBounds = Object.freeze({
      clockIdentity: poolState.clockIdentity,
      wireExpiresAt: opWireExpiresAt,
      localDeadline: effectiveLocalDeadline
    })
    const locator = createPeerCandidateLocator(
      poolState.relayOwner,
      selectedNeighbor.verifiedAdvertisement,
      deadlineBounds
    )
    transport = createPeerCandidateDirectTransport(poolState.endpoint, locator)
    if (closed) {
      destroyPeerDirectRequesterTransport(transport)
      throw PrivateRouteError.UNAUTHORIZED()
    }
    checkLive()
    armDiscoveryTimer()
    return Object.freeze({
      transport,
      ledger: discoveryLedger,
      advertisement260: b4a.from(selectedNeighbor.canonicalAdvertisement260),
      close
    })
  } catch (err) {
    close()
    if (err instanceof PrivateRouteError) throw err
    throw PrivateRouteError.INVALID_ROUTE()
  }
}
module.exports = {
  createPeerNativeNeighborPool,
  provisionPeerNativeNeighbor,
  reservePeerNeighborLink,
  readPeerNeighborReservation,
  exchangePeerNeighborLink,
  takePeerNeighborPhysicalIssuer,
  destroyPeerNeighborReservation,
  destroyPeerNativeNeighborPool,
  joinPeerNativeNeighborPool,
  readPeerNativeNeighborDiagnostics,
  takeNeighborServiceOwner,
  createPeerNativeNeighborDiscovery
}
