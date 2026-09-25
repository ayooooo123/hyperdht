'use strict'

// Per-node relay-neighbor admission owner (native peer-tail stack).
//
// Packet §3.4: only a locally configured, authenticated topology authority may
// provision a relay's neighbor pool. This owner admits format 1 topology
// grants whose local side is signed by one of the node's configured
// authorities, then for each grant:
//
//   1. authorizes a fresh single-use link handle from a per-attempt
//      LinkDirectory (handles are consumed by `openLink`);
//   2. fetches the granted peer's current signed advertisement with the
//      grant-pinned CAPS/ACTIVE exchange, charged to the node service ledger;
//   3. provisions the neighbor through `provisionPeerNativeNeighbor`, dialing
//      or accepting as the grant says. The responder's link static key is the
//      peer's advertised route key, as in the routed-DHT stack.
//
// Nothing here takes an address or advertisement from a caller: the grant is
// the only dial authority, and the advertisement is fetched from the granted
// identity and address.
//
// Every grant on one endpoint shares one (epoch, runId32): the endpoint's NAT
// authority is scoped to one pair, and a grant carries one pair for both ends.

const b4a = require('b4a')

const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')
const { LINK_OPERATION } = require('./protocol')
const {
  LinkDirectory,
  MAX_TOPOLOGY_AUTHORITIES,
  readVerifiedTopologyGrant,
  verifyTopologyGrantV1
} = require('./topology-grant')
const {
  readPeerRelayOwner,
  readVerifiedPeerAdvertisement,
  verifyPeerAdvertisement
} = require('./peer-capability')
const {
  createPeerNativeNeighborPool,
  destroyPeerNativeNeighborPool,
  joinPeerNativeNeighborPool,
  provisionPeerNativeNeighbor,
  readPeerNativeNeighborDiagnostics,
  reservePeerNativeNeighborService
} = require('./peer-native-neighbors')
const {
  destroyPeerActiveCandidate,
  discoverPeerCandidate,
  takePeerActiveCandidate
} = require('./peer-direct-bootstrap')
const {
  UdxCellEndpoint,
  createPeerGrantDirectTransport,
  destroyPeerDirectRequesterTransport,
  registerSharedGuardPeerBranchResponder
} = require('./udx-cell-endpoint')
const { BootstrapEnvelopeCodec } = require('./bootstrap-envelope')
const { createLinkSetupAuthority } = require('./link-setup')
const { releasePeerLedger } = require('./peer-ledger')

const createDynamicResponderSetup = require('./link-bootstrap-session')[
  Symbol.for('hyperdht-private-routes/dynamic-responder-setup-factory')
]

const MAX_ADMISSION_GRANTS = 16
const LINK_DEADLINE_MS = 10_000
const DEFAULT_MAX_ATTEMPTS = 3
const RETRY_DELAY_MS = 1_000
// Mask 9 is the relay capability every neighbor role advertises; a terminal's
// mask 11 includes it.
const NEIGHBOR_ADVERTISEMENT_MASK = 9

const OWNERS = new WeakMap()

function isObject(value) {
  return value !== null && typeof value === 'object'
}

function fixed(value, size) {
  return b4a.isBuffer(value) && value.byteLength === size
}

function invalid() {
  return PrivateRouteError.INVALID_ROUTE()
}

function clear(value) {
  if (b4a.isBuffer(value)) value.fill(0)
}

function safeCode(err) {
  return err instanceof PrivateRouteError ? err.code : 'ROUTE_UNAVAILABLE'
}

function copyKeyPair(pair, secretSize) {
  if (!isObject(pair) || !fixed(pair.publicKey, 32) || !fixed(pair.secretKey, secretSize)) {
    throw PrivateRouteError.INVALID_KEY()
  }
  return { publicKey: b4a.from(pair.publicKey), secretKey: b4a.from(pair.secretKey) }
}

function hasOperation(operations, operation) {
  return (operations & operation) === operation
}

// The endpoint that dials is the one whose grant side may INITIATE. When both
// may, the lower identity dials so exactly one side opens the link.
function dialsFirst(local, peer) {
  const localInitiates = hasOperation(local.operations, LINK_OPERATION.INITIATE)
  const peerInitiates = hasOperation(peer.operations, LINK_OPERATION.INITIATE)
  if (localInitiates && !peerInitiates) return true
  if (!localInitiates && peerInitiates) return false
  if (localInitiates && peerInitiates) return b4a.compare(local.identity32, peer.identity32) < 0
  return null
}

function admitGrant(state, encoding) {
  if (!b4a.isBuffer(encoding)) throw invalid()
  const verified = verifyTopologyGrantV1(b4a.from(encoding), state.authorityPublicKeys, {
    localIdentity32: state.identityKeyPair.publicKey,
    now: BigInt(state.wallNow())
  })
  const view = readVerifiedTopologyGrant(verified)
  try {
    if (view.epoch !== state.epoch || !b4a.equals(view.runId32, state.runId32)) {
      throw PrivateRouteError.UNAUTHORIZED()
    }
    const dialer = dialsFirst(view.local, view.peer)
    if (dialer === null) throw invalid()
    if (!dialer && !hasOperation(view.local.operations, LINK_OPERATION.ACCEPT)) throw invalid()
    return {
      encoding: b4a.from(encoding),
      localRole: view.local.role,
      peerRole: view.peer.role,
      peerIdentity32: b4a.from(view.peer.identity32),
      peerKey: b4a.toString(view.peer.identity32, 'hex'),
      expiresAt: view.expiresAt,
      dialer
    }
  } finally {
    clear(view.digest32)
    clear(view.encoding)
  }
}

function createSlot(grant) {
  return {
    ...grant,
    // A newer grant for the same peer waits here until the current neighbor
    // ends; the pool holds one neighbor per identity.
    next: null,
    state: 'pending',
    attempts: 0,
    lastError: null,
    directory: null,
    neighbor: null,
    lostWhileProvisioning: false,
    transport: null,
    running: null
  }
}

function applyNextGrant(slot) {
  const next = slot.next
  slot.next = null
  clear(slot.encoding)
  slot.encoding = next.encoding
  slot.localRole = next.localRole
  slot.peerRole = next.peerRole
  slot.expiresAt = next.expiresAt
  slot.dialer = next.dialer
}

function grantExpired(state, slot) {
  return BigInt(state.wallNow()) >= slot.expiresAt
}

function createPeerNeighborAdmission(options) {
  if (!isObject(options)) throw invalid()
  const {
    relayOwner,
    endpoint,
    identityKeyPair,
    routeKeyPair,
    authorityPublicKeys,
    epoch,
    runId32,
    grants,
    maxNeighbors = 4,
    nodeServiceBudget,
    neighborServiceReservation,
    branchResponder = null,
    maxAttempts = DEFAULT_MAX_ATTEMPTS,
    onError = null
  } = options

  if (!(endpoint instanceof UdxCellEndpoint)) throw invalid()
  if (typeof epoch !== 'bigint' || epoch < 0n || !fixed(runId32, 32)) throw invalid()
  if (
    !Array.isArray(authorityPublicKeys) ||
    authorityPublicKeys.length < 1 ||
    authorityPublicKeys.length > MAX_TOPOLOGY_AUTHORITIES
  ) {
    throw invalid()
  }
  if (!Array.isArray(grants) || grants.length < 1 || grants.length > MAX_ADMISSION_GRANTS) {
    throw invalid()
  }
  if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1) throw invalid()
  if (onError !== null && typeof onError !== 'function') throw invalid()
  if (branchResponder !== null && !isObject(branchResponder)) throw invalid()

  const ownerInfo = readPeerRelayOwner(relayOwner, endpoint)
  const identity = copyKeyPair(identityKeyPair, 64)
  const route = copyKeyPair(routeKeyPair, 32)
  if (
    !b4a.equals(identity.publicKey, ownerInfo.relayIdentity32) ||
    !b4a.equals(route.publicKey, ownerInfo.routeEncryptionPublicKey32)
  ) {
    clear(identity.secretKey)
    clear(route.secretKey)
    throw PrivateRouteError.INVALID_KEY()
  }
  // The grant-pinned discovery requires the neighbor's advertised epoch to
  // equal the grant epoch; this node's own advertisement must agree as well.
  if (ownerInfo.parsedAdvertisement.epoch !== epoch) {
    clear(identity.secretKey)
    clear(route.secretKey)
    throw invalid()
  }

  const state = {
    relayOwner,
    endpoint,
    identityKeyPair: identity,
    routeKeyPair: route,
    authorityPublicKeys: authorityPublicKeys.map((key) => b4a.from(key)),
    epoch,
    runId32: b4a.from(runId32),
    clockIdentity: ownerInfo.clockIdentity,
    wallNow: ownerInfo.wallNow,
    monotonicNow: ownerInfo.monotonicNow,
    setTimer: ownerInfo.setTimer,
    clearTimer: ownerInfo.clearTimer,
    branchResponder,
    maxAttempts,
    onError,
    slots: new Map(),
    // Pending retry delays: timer -> resolve, so destroy can end them.
    timers: new Map(),
    pool: null,
    destroyed: false,
    closing: null
  }

  try {
    for (const encoding of grants) {
      const grant = admitGrant(state, encoding)
      if (state.slots.has(grant.peerKey)) throw PrivateRouteError.CIRCUIT_STATE()
      state.slots.set(grant.peerKey, createSlot(grant))
    }
    state.pool = createPeerNativeNeighborPool({
      relayOwner,
      endpoint,
      maxNeighbors,
      nodeServiceBudget,
      neighborServiceReservation,
      onNeighborClosed: (identity32, reason) => neighborClosed(state, identity32, reason)
    })
  } catch (err) {
    wipe(state)
    throw err
  }

  const owner = Object.freeze({ kind: 'peerNeighborAdmission' })
  OWNERS.set(owner, state)
  for (const slot of state.slots.values()) startSlot(state, slot)
  return owner
}

function report(state, slot, err) {
  slot.lastError = safeCode(err)
  if (state.onError === null) return
  try {
    state.onError({ peerIdentity32: b4a.from(slot.peerIdentity32), code: slot.lastError })
  } catch {}
}

function delay(state, ms) {
  return new Promise((resolve) => {
    const timer = state.setTimer(() => {
      state.timers.delete(timer)
      resolve()
    }, ms)
    state.timers.set(timer, resolve)
  })
}

function startSlot(state, slot, initialDelay = 0) {
  slot.running = (async () => {
    if (initialDelay > 0) await delay(state, initialDelay)
    await runSlot(state, slot)
  })()
}

async function runSlot(state, slot) {
  while (!state.destroyed && slot.attempts < state.maxAttempts) {
    if (slot.next && (grantExpired(state, slot) || slot.next.expiresAt > slot.expiresAt)) {
      applyNextGrant(slot)
    }
    if (grantExpired(state, slot)) {
      slot.state = 'expired'
      return
    }
    slot.attempts++
    try {
      await attemptSlot(state, slot)
      return
    } catch (err) {
      releaseSlotDirectory(slot)
      if (state.destroyed) return
      report(state, slot, err)
    }
    if (slot.attempts < state.maxAttempts) await delay(state, RETRY_DELAY_MS)
  }
  if (!state.destroyed) slot.state = 'failed'
}

// A published neighbor ended: native loss, the grant or the peer's
// advertisement expired, or its link closed. Reconnect with the newest grant,
// which also refetches the peer's current advertisement.
function neighborClosed(state, identity32, reason) {
  if (state.destroyed) return
  const slot = state.slots.get(b4a.toString(identity32, 'hex'))
  if (!slot) return
  // The pool may publish and then lose a neighbor before this owner marks it
  // live; the attempt sees the flag and retries instead of claiming it.
  if (slot.state === 'provisioning') {
    slot.lostWhileProvisioning = true
    return
  }
  if (slot.state !== 'live') return
  slot.neighbor = null
  releaseSlotDirectory(slot)
  slot.state = 'reconnecting'
  slot.lastError = typeof reason === 'string' ? reason : null
  slot.attempts = 0
  startSlot(state, slot, RETRY_DELAY_MS)
}

// Installs a grant after construction: a first grant for a new peer starts
// provisioning; a grant for a known peer replaces the current one the next
// time that neighbor is (re)provisioned.
function addPeerNeighborGrant(owner, encoding) {
  const state = isObject(owner) ? OWNERS.get(owner) : null
  if (!state || state.destroyed) throw PrivateRouteError.UNAUTHORIZED()
  const grant = admitGrant(state, encoding)
  const slot = state.slots.get(grant.peerKey)
  if (!slot) {
    if (state.slots.size >= MAX_ADMISSION_GRANTS) {
      clear(grant.encoding)
      throw PrivateRouteError.CIRCUIT_LIMIT()
    }
    const created = createSlot(grant)
    state.slots.set(grant.peerKey, created)
    startSlot(state, created)
    return
  }
  if (slot.next) clear(slot.next.encoding)
  slot.next = grant
  if (slot.state === 'failed' || slot.state === 'expired') {
    slot.attempts = 0
    startSlot(state, slot)
  }
}

function releaseSlotDirectory(slot) {
  const directory = slot.directory
  slot.directory = null
  if (directory) {
    try {
      directory.destroy()
    } catch {}
  }
}

function authorizeAttempt(state, slot) {
  // A link handle is single-use, and a directory returns the same handle for a
  // grant it already holds, so every attempt gets its own directory. It lives
  // as long as the neighbor: destroying it closes the handle and the neighbor.
  const directory = new LinkDirectory({
    localIdentity32: state.identityKeyPair.publicKey,
    localRole: slot.localRole,
    authorityPublicKeys: state.authorityPublicKeys,
    epoch: state.epoch,
    runId32: state.runId32,
    now: () => BigInt(state.wallNow()),
    schedule: (callback, ms) => state.setTimer(callback, ms),
    cancel: (timer) => state.clearTimer(timer),
    onClose() {},
    maxGrants: 1,
    maxHandles: 1
  })
  slot.directory = directory
  const digest32 = directory.add(slot.encoding)
  try {
    const handle = directory.authorize({
      digest32,
      operation: slot.dialer ? LINK_OPERATION.INITIATE : LINK_OPERATION.ACCEPT,
      localIdentity32: state.identityKeyPair.publicKey,
      localRole: slot.localRole,
      peerIdentity32: slot.peerIdentity32,
      peerRole: slot.peerRole,
      epoch: state.epoch,
      runId32: state.runId32
    })
    return { handle, digest32: b4a.from(digest32) }
  } finally {
    clear(digest32)
  }
}

async function fetchAdvertisement(state, slot, handle, digest32) {
  const ledger = reservePeerNativeNeighborService(state.pool)
  let transport = null
  let candidate = null
  try {
    transport = createPeerGrantDirectTransport(state.endpoint, handle, state.relayOwner)
    slot.transport = transport
    candidate = await discoverPeerCandidate(transport, {
      ledger,
      requestedMask: NEIGHBOR_ADVERTISEMENT_MASK,
      randomTarget: cryptoSuite.randomBytes(32)
    })
    const facts = takePeerActiveCandidate(candidate, {
      expectedKind: 'guard',
      expectedIdentity32: slot.peerIdentity32,
      expectedGrantDigest: digest32,
      expectedRunId: state.runId32,
      expectedEpoch: state.epoch,
      clockIdentity: state.clockIdentity
    })
    try {
      return verifyPeerAdvertisement(facts.completeAdvertisement, {
        expectedIdentity32: slot.peerIdentity32,
        clockIdentity: state.clockIdentity,
        wallNow: state.wallNow,
        monotonicNow: state.monotonicNow
      })
    } finally {
      clear(facts.completeAdvertisement)
      clear(facts.activeResponse312)
    }
  } finally {
    if (candidate) destroyPeerActiveCandidate(candidate)
    slot.transport = null
    if (transport) {
      try {
        destroyPeerDirectRequesterTransport(transport)
      } catch {}
    }
    try {
      releasePeerLedger(ledger)
    } catch {}
  }
}

function sessionOptions(state, slot, handle, advertisement) {
  const randomBytes = (size) => cryptoSuite.randomBytes(size)
  const wall = Number(state.wallNow())
  const mono = Number(state.monotonicNow())
  const signedExpiry = Number(slot.expiresAt)
  if (!Number.isSafeInteger(signedExpiry) || signedExpiry <= wall) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  const common = {
    mode: slot.dialer ? 'initiate' : 'accept',
    clockIdentity: state.clockIdentity,
    codec: new BootstrapEnvelopeCodec({
      linkHandle: handle,
      localIdentitySecretKey: state.identityKeyPair.secretKey,
      padding: randomBytes
    }),
    // Link setup expiries are signed wall-clock values; session timers are
    // monotonic. This split matches the routed-DHT link owners.
    linkSetup: createLinkSetupAuthority({ now: () => Number(state.wallNow()), randomBytes }),
    now: () => Number(state.monotonicNow()),
    schedule: (callback, ms) => state.setTimer(callback, ms),
    cancel: (timer) => state.clearTimer(timer),
    randomBytes,
    // An accept waits for the peer to dial whenever it can, bounded only by
    // the grant; a dial is one bounded operation.
    absoluteDeadline: slot.dialer ? mono + LINK_DEADLINE_MS : mono + (signedExpiry - wall),
    signedExpiry,
    authorizedExpiry: signedExpiry
  }
  if (!slot.dialer) {
    common.setup = createDynamicResponderSetup({
      responderStaticSecretKey: state.routeKeyPair.secretKey,
      responderIdentitySecretKey: state.identityKeyPair.secretKey
    })
    return common
  }
  const adInfo = readVerifiedPeerAdvertisement(advertisement)
  common.setup = {
    circuitId: cryptoSuite.randomBytes(16),
    epoch: state.epoch,
    initiatorIdentity: b4a.from(state.identityKeyPair.publicKey),
    responderIdentity: b4a.from(slot.peerIdentity32),
    initiatorLocalId: cryptoSuite.randomBytes(16),
    responderLocalId: cryptoSuite.randomBytes(16),
    expiresAt: slot.expiresAt,
    responderStaticKey: b4a.from(adInfo.routeEncryptionPublicKey32),
    initiatorIdentitySecretKey: b4a.from(state.identityKeyPair.secretKey)
  }
  return common
}

async function attemptSlot(state, slot) {
  slot.state = 'fetching'
  slot.lostWhileProvisioning = false
  const { handle, digest32 } = authorizeAttempt(state, slot)
  let advertisement
  try {
    advertisement = await fetchAdvertisement(state, slot, handle, digest32)
  } finally {
    clear(digest32)
  }
  if (state.destroyed) throw PrivateRouteError.ERR_DESTROYED()
  slot.state = 'provisioning'
  const options = sessionOptions(state, slot, handle, advertisement)
  let neighbor
  try {
    neighbor = await provisionPeerNativeNeighbor(state.pool, {
      linkHandle: handle,
      advertisement,
      mode: options.mode,
      sessionOptions: options
    })
  } finally {
    if (isObject(options.setup) && slot.dialer) {
      for (const value of Object.values(options.setup)) clear(value)
    }
  }
  if (state.destroyed) throw PrivateRouteError.ERR_DESTROYED()
  // The accepting side answers LINK_OFFER extensions from its dialer.
  if (!slot.dialer && state.branchResponder !== null) {
    registerSharedGuardPeerBranchResponder(neighbor.established, state.branchResponder)
  }
  if (slot.lostWhileProvisioning) throw PrivateRouteError.ROUTE_UNAVAILABLE()
  slot.neighbor = neighbor
  slot.state = 'live'
}

function readPeerNeighborAdmission(owner) {
  const state = isObject(owner) ? OWNERS.get(owner) : null
  if (!state) throw PrivateRouteError.UNAUTHORIZED()
  const neighbors = []
  for (const slot of state.slots.values()) {
    neighbors.push(
      Object.freeze({
        peerIdentity32: b4a.from(slot.peerIdentity32),
        localRole: slot.localRole,
        peerRole: slot.peerRole,
        dialer: slot.dialer,
        state: slot.state,
        attempts: slot.attempts,
        lastError: slot.lastError,
        nextGrant: slot.next !== null
      })
    )
  }
  return Object.freeze({
    destroyed: state.destroyed,
    pool: state.pool,
    diagnostics: state.pool ? readPeerNativeNeighborDiagnostics(state.pool) : null,
    neighbors: Object.freeze(neighbors)
  })
}

// Resolves when every provisioning attempt has settled (live or failed).
function settlePeerNeighborAdmission(owner) {
  const state = isObject(owner) ? OWNERS.get(owner) : null
  if (!state) return Promise.reject(PrivateRouteError.UNAUTHORIZED())
  return Promise.all(Array.from(state.slots.values(), (slot) => slot.running)).then(() => {})
}

function wipe(state) {
  clear(state.identityKeyPair.secretKey)
  clear(state.routeKeyPair.secretKey)
  for (const slot of state.slots.values()) {
    releaseSlotDirectory(slot)
    clear(slot.encoding)
    if (slot.next) clear(slot.next.encoding)
  }
}

function destroyPeerNeighborAdmission(owner) {
  const state = isObject(owner) ? OWNERS.get(owner) : null
  if (!state) return Promise.resolve(false)
  if (state.closing) return state.closing
  state.destroyed = true
  for (const [timer, resolve] of state.timers) {
    try {
      state.clearTimer(timer)
    } catch {}
    resolve()
  }
  state.timers.clear()
  // Cancel in-flight advertisement fetches; the pool revokes provisioning.
  for (const slot of state.slots.values()) {
    if (slot.transport) {
      try {
        destroyPeerDirectRequesterTransport(slot.transport)
      } catch {}
    }
  }
  const pool = state.pool
  destroyPeerNativeNeighborPool(pool)
  state.closing = Promise.allSettled(Array.from(state.slots.values(), (slot) => slot.running))
    .then(() => joinPeerNativeNeighborPool(pool))
    .then(() => {
      wipe(state)
      OWNERS.delete(owner)
      return true
    })
  return state.closing
}

module.exports = {
  createPeerNeighborAdmission,
  addPeerNeighborGrant,
  readPeerNeighborAdmission,
  settlePeerNeighborAdmission,
  destroyPeerNeighborAdmission
}
