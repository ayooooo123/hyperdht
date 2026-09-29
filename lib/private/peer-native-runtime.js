'use strict'

// Production host for native private routing. It assembles the native primitives with
// production inputs only: a lease on the ordinary DHT's bound socket, one coherent real
// clock, one node-wide memory pool, relay advertisement generations, the direct discovery
// responder, grant-driven neighbor admission, branch and tail hosting, and one-time final
// tail leases. It holds no test authority and exports no raw socket or secret.

const b4a = require('b4a')
const process = require('process')
const sodium = require('sodium-universal')

const { PrivateRouteError } = require('./errors')
const { cryptoSuite } = require('./crypto-suite')
const { RELAY_CAPABILITY, ROLE, TOPOLOGY_ROLE, roleForIdentity } = require('./protocol')
const { decodeTopologyGrantV1 } = require('./topology-grant')
const {
  deriveM3DhtNodeId,
  encodeCanonicalEndpoint,
  encodeRelayCapabilityAdvertisement,
  providerServicePolicyForCapabilities,
  signRelayCapabilityAdvertisement
} = require('./relay-capability')
const { CapsResponder } = require('./caps-responder')
const { BootstrapEnvelopeCodec } = require('./bootstrap-envelope')
const { createLinkSetupAuthority } = require('./link-setup')
const createDynamicResponderSetup = require('./link-bootstrap-session')[
  Symbol.for('hyperdht-private-routes/dynamic-responder-setup-factory')
]
const { createCoherentClock } = require('./runtime-clock')
const {
  createPeerLedger,
  createPeerMemoryPool,
  releasePeerLedger,
  reservePeerMemory,
  releasePeerMemory,
  readPeerMemory,
  createPeerBranchSlots,
  closePeerBranchSlots,
  readPeerBranchSlots
} = require('./peer-ledger')
const { hashPeer, derivePeerPurposeTerminalKeyPair } = require('./peer-crypto')
const {
  leaseDhtUdxSocket,
  readDhtUdxSocketLease,
  revokeDhtUdxSocketLease,
  createLeasedUdxCellEndpoint,
  observeDhtUdxSocketLease,
  createSendAttemptSequence,
  registerPeerDirectResponder,
  destroyPeerDirectResponderRegistration,
  registerGuardBootstrapResponder,
  destroyGuardBootstrapResponderRegistration,
  registerSharedGuardPeerBranchResponder,
  guardBootstrapLinkBudget,
  guardBootstrapPinBudget,
  createBootstrapUdxAuthority,
  createLocalIdentitySecretCapability,
  destroyBootstrapUdxAuthority,
  destroyGuardLeaseMaterial
} = require('./udx-cell-endpoint')
const {
  createPeerRelayOwner,
  destroyPeerRelayOwner,
  verifyPeerAdvertisement,
  readVerifiedPeerAdvertisement
} = require('./peer-capability')
const {
  createPeerBootstrapResponder,
  destroyPeerBootstrapResponder,
  discoverPeerCandidate,
  readPeerActiveCandidateFacts,
  destroyPeerActiveCandidate
} = require('./peer-direct-bootstrap')
const {
  createPeerLinkResponder,
  destroyPeerLinkResponder,
  openPeerGuardLink,
  destroyPeerEstablishedLink
} = require('./peer-guard-link')
const {
  MAX_NATIVE_PIN_BRANCH_SLOTS,
  createGuardLease,
  destroyGuardLease,
  isGuardLease,
  createPeerGuardBootstrapTransport
} = require('./guard-lease')
const { BootstrapIO, consumeBootstrapGuardPin } = require('./bootstrap-io')
const { createRelayCandidateDirectorySink } = require('./relay-candidate-directory')
const {
  createPeerM3AdjacencyAuthority,
  adoptPeerEstablishedLink,
  destroyPeerM3Runtime,
  issuePeerM3RouteCarrier,
  readPeerM3Runtime,
  takePeerM3RouteCarrier
} = require('./peer-m3-adjacency-runtime')
const {
  createPeerTailControl,
  destroyPeerTailControl,
  discoverPeerTailCandidate,
  readPeerTailCandidateBounds,
  extendPeerTail,
  readPeerTailControl,
  createPeerFinalExitHandoff,
  takePeerTailFinalRuntime
} = require('./peer-tail-control')
const {
  createPeerNeighborAdmission,
  settlePeerNeighborAdmission,
  readPeerNeighborAdmission,
  destroyPeerNeighborAdmission
} = require('./peer-neighbor-admission')
const { readPeerNativeNeighborDiagnostics } = require('./peer-native-neighbors')
const {
  createFinalExitActivationClaim,
  claimFinalExitActivation,
  consumeFinalExitActivationOwner,
  destroyFinalExitActivationOwner
} = require('./final-exit-activation')
const { CARRIER_BRAND } = require('./peer-purpose-owner')
const {
  PRESENCE_PARAMETERS_DIGEST,
  createPresenceTerminal,
  readTerminalPolicy
} = require('./peer-presence')

const TAIL_CONTROL_TRANSCRIPT_DIGEST_DOMAIN =
  'hyperdht-private-routes/m3/tail-control/transcript-digest/v2'
const TRANSCRIPT_BYTES = 290
const T_CIRCUIT_ID = 73
const T_GENERATION = 89
const T_ADVERTISEMENT_DIGEST = 162
const CLOSURE = Object.freeze({ cells: 10, bytes: 12000n, commands: 1 })
// Predecessor and successor branch of one forwarded circuit.
const BRANCHES_PER_CIRCUIT = 2
// A guard's v1 capability advertisement lives at most 30 minutes, and a guard-hosting
// generation shares one expiry across both of its advertisements.
const GUARD_ADVERTISEMENT_MAX_LIFETIME_MS = 1_800_000
// A source must finish its bootstrap link within this time after its ACTIVE challenge.
const GUARD_ACCEPT_DEADLINE_MS = 30_000
// Accepted guard links that may be setting up at once.
const GUARD_PENDING_ACCEPTS = 8
// A source re-pins its guard when less than this remains of the pin, so a build never
// starts a circuit that would expire with the pin almost at once.
const PIN_REFRESH_MS = 60_000n
// A relay renews a generation at most this long before its advertisements expire.
const RENEWAL_MARGIN_MS = 60_000n
// The longest delay a platform timer accepts.
const MAX_TIMER_MS = 0x7fffffffn
// D0 is one bounded direct exchange: 24 sends in each direction (packet §3.3).
const D0_BUDGET = Object.freeze({ cells: 24, bytes: 28_800n, commands: 0 })
// Each hop of a build must answer within this time.
const BUILD_OPERATION_MS = 10_000n
// Directional limit bounds every hop accepts: bytes follow cells exactly and must fit u32.
// A forwarding relay's allowance for the circuit must hold the closure partition, the
// 24-cell D1/D2 reservation it makes for the circuit, and the eight-attempt budgets of the
// LINK_ACCEPT and TAIL_READY that precede that discovery.
const MIN_BUILD_CELLS = CLOSURE.cells + 24 + 8 + 8
const MAX_BUILD_CELLS = Math.floor(0xffffffff / 1200)
const MIN_BUILD_COMMANDS = 2
// The source's local peer owner exists only to sign its guard link offers under the pin
// identity; its advertisement never leaves the process.
const SOURCE_OWNER_LIMITS = Object.freeze({
  maxConcurrentCircuits: 8,
  capacityClass: 1,
  maxCells: 10_000,
  maxBytes: 1_000_000,
  maxCommands: 1000,
  idleTimeoutMs: 30_000,
  maxQueuedBytes: 524_288
})
// Node-pool work the owner may reserve outside any circuit.
const RESERVATION_KINDS = new Set(['semantic', 'record', 'registration'])
const RUNTIMES = new WeakMap()
const LEASES = new WeakMap()
// Hosted terminal tails whose source asked for the presence service.
const PRESENCE_SESSIONS = new WeakSet()

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

// An exact own-data boolean: absent means false, and a getter, an inherited property, or
// a non-boolean value is rejected instead of coerced.
function readExactOwnBoolean(object, key) {
  const descriptor = Object.getOwnPropertyDescriptor(object, key)
  if (descriptor === undefined) return false
  if (!('value' in descriptor) || typeof descriptor.value !== 'boolean') invalid()
  return descriptor.value
}

function destroyed() {
  throw PrivateRouteError.ERR_DESTROYED()
}

function isObject(value) {
  return value !== null && typeof value === 'object'
}

function fixed(value, size) {
  return b4a.isBuffer(value) && value.byteLength === size
}

function clear(value) {
  if (b4a.isBuffer(value)) value.fill(0)
}

function copy(value, size) {
  if (!fixed(value, size)) invalid()
  return b4a.from(value)
}

function positiveInteger(value, max = Number.MAX_SAFE_INTEGER) {
  return Number.isSafeInteger(value) && value > 0 && value <= max
}

function endpointTuple(value) {
  if (
    !isObject(value) ||
    typeof value.host !== 'string' ||
    value.host.length === 0 ||
    !positiveInteger(value.port, 0xffff)
  ) {
    invalid()
  }
  return Object.freeze({ host: value.host, port: value.port })
}

// The four address bytes of a dotted IPv4 host, or null.
function ipv4Bytes(host) {
  const parts = host.split('.')
  if (parts.length !== 4) return null
  const bytes = b4a.alloc(4)
  for (let index = 0; index < 4; index++) {
    const part = parts[index]
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255) return null
    bytes[index] = Number(part)
  }
  return bytes
}

function randomBytes(size) {
  const out = b4a.allocUnsafeSlow(size)
  sodium.randombytes_buf(out)
  return out
}

// ---------------------------------------------------------------------------
// Validated configuration (supplied by the controller slice as copied values)
// ---------------------------------------------------------------------------

function readLimits(value) {
  if (!isObject(value)) invalid()
  const limits = {
    maxConcurrentCircuits: value.maxConcurrentCircuits,
    capacityClass: value.capacityClass,
    maxCells: value.maxCells,
    maxBytes: value.maxBytes,
    maxCommands: value.maxCommands,
    idleTimeoutMs: value.idleTimeoutMs,
    maxQueuedBytes: value.maxQueuedBytes
  }
  if (
    !positiveInteger(limits.maxConcurrentCircuits, 0xffff) ||
    ![0, 1, 2].includes(limits.capacityClass) ||
    !positiveInteger(limits.maxCells, 0xffffffff) ||
    !positiveInteger(limits.maxBytes, 0xffffffff) ||
    !positiveInteger(limits.maxCommands, 0xffffffff) ||
    !positiveInteger(limits.idleTimeoutMs, 0xffffffff) ||
    !positiveInteger(limits.maxQueuedBytes, 0xffffffff) ||
    limits.maxCells <= CLOSURE.cells ||
    limits.maxBytes <= Number(CLOSURE.bytes) ||
    limits.maxCommands <= CLOSURE.commands
  ) {
    invalid()
  }
  return Object.freeze(limits)
}

function readAdmission(value) {
  if (!isObject(value)) invalid()
  const { authorityPublicKeys, runId32, grants, maxNeighbors = 4 } = value
  if (!Array.isArray(authorityPublicKeys) || authorityPublicKeys.length === 0) invalid()
  if (!Array.isArray(grants) || grants.length === 0) invalid()
  if (!positiveInteger(maxNeighbors, 64)) invalid()
  return Object.freeze({
    authorityPublicKeys: Object.freeze(authorityPublicKeys.map((key) => copy(key, 32))),
    runId32: copy(runId32, 32),
    grants: Object.freeze(
      grants.map((grant) => {
        if (!b4a.isBuffer(grant) || grant.byteLength === 0) invalid()
        return b4a.from(grant)
      })
    ),
    maxNeighbors
  })
}

// Native relay roles are positional within the safety class (packet §2: guard is the first
// safety-role adjacency). Each grant is one edge oriented away from sources: its upstream
// end holds SAFETY_GUARD and its downstream end SAFETY_FINAL. A relay that is upstream in
// any grant forwards circuits, as guard or safety (mask 9). A relay that is only ever
// downstream has no neighbor to forward to and ends circuits as a terminal (mask 11).
// Signatures and authorities are verified later by neighbor admission.
function deriveCapabilityMask(identityPublicKey, grants) {
  let upstream = false
  for (const grant of grants) {
    let decoded
    try {
      decoded = decodeTopologyGrantV1(grant)
    } catch {
      invalid()
    }
    const { endpointA, endpointB } = decoded
    const localA = b4a.equals(endpointA.identity32, identityPublicKey)
    const localB = b4a.equals(endpointB.identity32, identityPublicKey)
    if (localA === localB) invalid()
    const local = localA ? endpointA : endpointB
    const peer = localA ? endpointB : endpointA
    const roles = [local.role, peer.role].sort()
    if (roles[0] !== TOPOLOGY_ROLE.SAFETY_GUARD || roles[1] !== TOPOLOGY_ROLE.SAFETY_FINAL) {
      invalid()
    }
    if (local.role === TOPOLOGY_ROLE.SAFETY_GUARD) upstream = true
  }
  return upstream ? 9 : 11
}

function readNativeConfig(config) {
  if (!isObject(config)) invalid()
  const role = config.role
  if (role !== 'relay' && role !== 'source') invalid()
  if (!positiveInteger(config.memoryBytes)) invalid()
  const result = {
    role,
    memoryBytes: config.memoryBytes,
    identity: null,
    relay: null,
    source: null
  }
  if (role === 'relay') {
    const identity = config.identity
    if (!isObject(identity)) invalid()
    result.identity = Object.freeze({
      publicKey: copy(identity.publicKey, 32),
      secretKey: copy(identity.secretKey, 64)
    })
    // Relay topology roles are bound to the identity itself; a relay identity that does
    // not hash to the safety role could never satisfy its grants.
    if (roleForIdentity(result.identity.publicKey) !== ROLE.SAFETY) invalid()
    const relay = config.relay
    if (!isObject(relay)) invalid()
    // The capability mask follows from the grants and is never configured.
    if (relay.capabilityMask !== undefined) invalid()
    if (!positiveInteger(relay.lifetimeMs)) invalid()
    if (typeof relay.epoch !== 'bigint' || relay.epoch < 0n) invalid()
    const admission = readAdmission(relay.admission)
    const capabilityMask = deriveCapabilityMask(result.identity.publicKey, admission.grants)
    // Presence is served by terminals only; a forwarding relay ignores its presence policy.
    const presence = readTerminalPolicy(relay.presence)
    // Legacy egress is an exact own-data boolean, default false; only a grant-derived
    // mask-11 terminal may enable it, so a forwarding relay that sets it is rejected.
    const legacyEgress = readExactOwnBoolean(relay, 'legacyEgress')
    if (legacyEgress && capabilityMask !== 11) invalid()
    // A mask-9 relay also hosts guards through a v1 capability advertisement, which
    // needs an IPv4 reachable tuple, a non-zero epoch and a bounded lifetime.
    if (
      capabilityMask === 9 &&
      (relay.epoch === 0n ||
        relay.lifetimeMs > GUARD_ADVERTISEMENT_MAX_LIFETIME_MS ||
        !isObject(relay.reachable) ||
        typeof relay.reachable.host !== 'string' ||
        ipv4Bytes(relay.reachable.host) === null)
    ) {
      invalid()
    }
    result.relay = Object.freeze({
      capabilityMask,
      legacyEgress,
      reachable: endpointTuple(relay.reachable),
      limits: readLimits(relay.limits),
      lifetimeMs: relay.lifetimeMs,
      epoch: relay.epoch,
      admission,
      presence: capabilityMask === 11 ? presence : null
    })
  } else {
    const source = config.source
    if (!isObject(source) || !Array.isArray(source.guards)) invalid()
    if (source.guards.length < 1 || source.guards.length > 3) invalid()
    const maxProspectiveGuards =
      source.maxProspectiveGuards === undefined ? 3 : source.maxProspectiveGuards
    if (!positiveInteger(maxProspectiveGuards, 3)) invalid()
    result.source = Object.freeze({
      guards: Object.freeze(source.guards.map(endpointTuple)),
      maxProspectiveGuards
    })
  }
  return Object.freeze(result)
}

// ---------------------------------------------------------------------------
// Roots: one coherent real clock, the node pool, and socket-generation leases
// ---------------------------------------------------------------------------

function createRoots(memoryBytes) {
  const clock = createCoherentClock(() => process.hrtime.bigint(), Date.now)
  const clocks = Object.freeze({
    clockIdentity: clock,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    setTimer: (callback, ms) => setTimeout(callback, ms),
    clearTimer: (timer) => clearTimeout(timer)
  })
  return { clock, clocks, pool: createPeerMemoryPool(memoryBytes) }
}

function leaseCurrentSocket(state) {
  const socket = state.dht.io && state.dht.io.serverSocket
  if (!socket || socket.bound !== true) throw PrivateRouteError.ROUTE_UNAVAILABLE()
  state.socketGeneration++
  const lease = leaseDhtUdxSocket(socket, state.socketGeneration, state.sendSequence)
  if (state.sendObserver) {
    const observer = state.sendObserver
    state.revokeLeaseObserver = observeDhtUdxSocketLease(lease, (event) => observer(event))
  }
  return lease
}

function createEndpoint(state, lease, reachable) {
  const tuple = readDhtUdxSocketLease(lease)
  const options = {
    host: tuple.host,
    port: tuple.port,
    onBootstrap() {},
    onCell() {
      return true
    },
    onLinkFailure() {}
  }
  if (reachable && (reachable.host !== tuple.host || reachable.port !== tuple.port)) {
    options.advertisedHost = reachable.host
    options.advertisedPort = reachable.port
  }
  return createLeasedUdxCellEndpoint(options, lease)
}

// ---------------------------------------------------------------------------
// Final tail leases (one-time transfer of one completed local tail)
// ---------------------------------------------------------------------------

// The purpose owner accepts only carriers branded by its module; the runtime is the only
// production issuer of that brand.
function brandCarrier(carrier) {
  return Object.freeze({
    [CARRIER_BRAND]: true,
    sendFrame: (frame) => carrier.sendFrame(frame),
    sendFinalizeFrame: (frame) => carrier.sendFinalizeFrame(frame),
    activate: () => carrier.activate(),
    reserveReceive: () => carrier.reserveReceive(),
    receiveEnvelope: (reservation) => carrier.receiveEnvelope(reservation),
    receiveFrame: (reservation) => carrier.receiveFrame(reservation),
    cancelReceive: (reservation) => carrier.cancelReceive(reservation),
    schedule: (delayMs, callback) => carrier.schedule(delayMs, callback),
    clock: carrier.clock,
    destroy: () => carrier.destroy(),
    diagnostics: () => carrier.diagnostics(),
    bindLedgers: (partitions) => carrier.bindLedgers(partitions)
  })
}

function readU64(buffer, offset) {
  let value = 0n
  for (let index = offset; index < offset + 8; index++)
    value = (value << 8n) | BigInt(buffer[index])
  return value
}

// Takes the final runtime of a completed tail session and builds the local view that
// the purpose owner consumes. The shared secret and transcript are erased once the
// digests, identifiers and per-circuit purpose key pair exist.
// `extras` adds role-specific fields to the view: a source names its terminal's
// advertisement.
// The view is funded by the circuit's own branch at this end: `sendLedger` and
// `receiveLedger` are that branch's admitted authority each way, less its closure
// partitions and everything it has spent. They stay the branch's: a purpose owner reserves
// its partitions below them and binds those to the carrier, and never releases them.
function takeFinalTail(session, role, pool, extras = null) {
  let handoff = null
  let activationOwner = null
  let material = null
  let carrier = null
  let purpose = null
  try {
    handoff = createPeerFinalExitHandoff(session)
    activationOwner = claimFinalExitActivation(handoff, createFinalExitActivationClaim(handoff))
    material = consumeFinalExitActivationOwner(activationOwner)
    const transcript = material.tailControlTranscript
    if (!fixed(transcript, TRANSCRIPT_BYTES) || !fixed(material.sharedSecret, 32)) invalid()
    const taken = takePeerTailFinalRuntime(session, activationOwner)
    carrier = takePeerM3RouteCarrier(issuePeerM3RouteCarrier(taken.runtime, taken.authorization))
    purpose = derivePeerPurposeTerminalKeyPair(material.sharedSecret, transcript)
    const view = {
      role,
      carrier: brandCarrier(carrier),
      circuitId: b4a.from(transcript.subarray(T_CIRCUIT_ID, T_CIRCUIT_ID + 16)),
      generation: readU64(transcript, T_GENERATION),
      tailControlTranscriptDigest: hashPeer(TAIL_CONTROL_TRANSCRIPT_DIGEST_DOMAIN, [transcript]),
      terminalAdvertisementDigest: b4a.from(
        transcript.subarray(T_ADVERTISEMENT_DIGEST, T_ADVERTISEMENT_DIGEST + 32)
      ),
      finalizeKeys: Object.freeze({
        finalizeForwardKey: b4a.from(material.finalizeForwardKey),
        finalizeForwardNoncePrefix: b4a.from(material.finalizeForwardNoncePrefix),
        finalizeReverseKey: b4a.from(material.finalizeReverseKey),
        finalizeReverseNoncePrefix: b4a.from(material.finalizeReverseNoncePrefix)
      }),
      purposeTerminalPublicKey: purpose.publicKey,
      purposeTerminalSecretKey: role === 'terminal' ? purpose.secretKey : null,
      terminalAdvertisement260: extras ? extras.terminalAdvertisement260 : null,
      parentWireExpiresAt: material.wireExpiresAt,
      parentLocalDeadline: material.localDeadline,
      clockIdentity: material.clockIdentity,
      sendLedger: carrier.ledgers.sendLedger,
      receiveLedger: carrier.ledgers.receiveLedger,
      memoryPool: pool
    }
    if (role !== 'terminal') clear(purpose.secretKey)
    return { view, activationOwner, carrier }
  } catch (err) {
    if (carrier) {
      try {
        carrier.destroy()
      } catch {}
    }
    if (purpose) {
      clear(purpose.secretKey)
      clear(purpose.publicKey)
    }
    if (activationOwner) destroyFinalExitActivationOwner(activationOwner)
    throw err
  } finally {
    if (material) {
      clear(material.sharedSecret)
      clear(material.tailControlTranscript)
    }
  }
}

function eraseView(view) {
  clear(view.circuitId)
  clear(view.tailControlTranscriptDigest)
  clear(view.terminalAdvertisementDigest)
  for (const value of Object.values(view.finalizeKeys)) clear(value)
  clear(view.purposeTerminalPublicKey)
  clear(view.purposeTerminalSecretKey)
  clear(view.terminalAdvertisement260)
}

// Tracks one owner's real join promise in a closing host's set until it settles.
function trackPendingJoin(set, join) {
  if (!set || !join || typeof join.then !== 'function') return
  set.add(join)
  const forget = () => set.delete(join)
  join.then(forget, forget)
}

// A lease lives in its owner's set, the runtime's source finals or a generation's
// terminal finals, until it is revoked, so short circuits do not accumulate there.
function createFinalTailLease(taken, finals) {
  const lease = Object.freeze({
    consume() {
      const state = LEASES.get(lease)
      if (!state || state.consumed || state.revoked) destroyed()
      state.consumed = true
      return Object.freeze({ ...state.taken.view })
    },
    revoke() {
      const state = LEASES.get(lease)
      if (!state || state.revoked) return false
      state.revoked = true
      finals.delete(lease)
      // The carrier's destroy join: settles only when its closure duty and every native
      // completion have, so a closing owner can await the true retirement.
      let join = null
      try {
        join = state.taken.carrier.destroy()
      } catch {}
      destroyFinalExitActivationOwner(state.taken.activationOwner)
      if (!state.consumed) eraseView(state.taken.view)
      return join || true
    }
  })
  LEASES.set(lease, { taken, consumed: false, revoked: false })
  finals.add(lease)
  return lease
}

// ---------------------------------------------------------------------------
// Relay generation: one advertisement, its responders, admission and hosted tails
// ---------------------------------------------------------------------------

// A generation's native branches hold authority under its branch-slot pool: at most two per
// advertised concurrent circuit, the predecessor branch it accepted and the successor
// branch it opened. Each admitted branch takes its own slot with fresh authority of exactly
// its admitted rows, what it spends is final, and its slot frees only once the branch has
// fully closed; a closing branch keeps its slot until then. The advertised concurrent-
// circuit limit is enforced separately, when a branch is accepted.
function generationBranchSlots(limits) {
  return createPeerBranchSlots(limits.maxConcurrentCircuits * BRANCHES_PER_CIRCUIT)
}

function advertisementFields(state, identity, routeKeyPair, relay) {
  const now = state.roots.clock.wallNow()
  return {
    relayIdentity32: identity.publicKey,
    currentDhtNodeId32: state.dhtNodeId,
    reachableEndpoint: { host: relay.reachable.host, port: relay.reachable.port },
    routeEncryptionPublicKey32: routeKeyPair.publicKey,
    capabilityMask: relay.capabilityMask,
    minimumVersion: 3,
    maximumVersion: 3,
    datagramReplayWindow: 64,
    maxConcurrentCircuits: relay.limits.maxConcurrentCircuits,
    capacityClass: relay.limits.capacityClass,
    maxCells: relay.limits.maxCells,
    maxBytes: relay.limits.maxBytes,
    maxCommands: relay.limits.maxCommands,
    idleTimeoutMs: relay.limits.idleTimeoutMs,
    maxQueuedBytes: relay.limits.maxQueuedBytes,
    epoch: relay.epoch,
    issuedAt: now,
    expiresAt: now + BigInt(relay.lifetimeMs),
    policyCount: 0
  }
}

function startRelayGeneration(state) {
  const relay = state.config.relay
  const identity = state.config.identity
  const generation = {
    endpoint: null,
    routeKeyPair: null,
    relayOwner: null,
    bootstrap: null,
    registration: null,
    authority: null,
    branchSlots: null,
    linkResponder: null,
    admission: null,
    guardRouteKeyPair: null,
    caps: null,
    guardRegistration: null,
    guardLedger: null,
    sessions: new Set(),
    runtimes: new Set(),
    finals: new Set(),
    pendingJoins: new Set(),
    expiresAt: 0n,
    renewTimer: null,
    closing: null
  }
  try {
    generation.endpoint = createEndpoint(state, state.lease, relay.reachable)
    generation.routeKeyPair = cryptoSuite.encryptionKeyPair()
    const fields = advertisementFields(state, identity, generation.routeKeyPair, relay)
    generation.expiresAt = fields.expiresAt
    generation.relayOwner = createPeerRelayOwner({
      endpoint: generation.endpoint,
      identityKeyPair: { publicKey: identity.publicKey, secretKey: identity.secretKey },
      routeKeyPair: generation.routeKeyPair,
      advertisementFields: fields,
      ...state.roots.clocks
    })
    generation.bootstrap = createPeerBootstrapResponder(generation.relayOwner)
    generation.registration = registerPeerDirectResponder(generation.endpoint, generation.bootstrap)
    generation.authority = createPeerM3AdjacencyAuthority(state.roots.clocks)
    generation.branchSlots = generationBranchSlots(relay.limits)
    generation.linkResponder = createPeerLinkResponder(generation.relayOwner, {
      branchSlots: generation.branchSlots,
      onEstablished(handle) {
        const runtime = adoptPeerEstablishedLink(generation.authority, handle)
        generation.runtimes.add(runtime)
        queueMicrotask(() => hostTail(state, generation, runtime))
        return runtime
      }
    })
    generation.admission = createPeerNeighborAdmission({
      relayOwner: generation.relayOwner,
      endpoint: generation.endpoint,
      identityKeyPair: { publicKey: identity.publicKey, secretKey: identity.secretKey },
      routeKeyPair: generation.routeKeyPair,
      authorityPublicKeys: relay.admission.authorityPublicKeys,
      epoch: relay.epoch,
      runId32: relay.admission.runId32,
      grants: relay.admission.grants,
      maxNeighbors: relay.admission.maxNeighbors,
      branchResponder: generation.linkResponder
    })
    if (relay.capabilityMask === 9) startGuardHost(state, generation, fields.issuedAt)
    return generation
  } catch (err) {
    void closeRelayGeneration(generation)
    throw err
  }
}

// A mask-9 relay also serves as a guard. Sources bootstrap to it over v1 CAPS and an
// ACTIVE challenge, then run their native guard link as a shared branch over the accepted
// bootstrap link. The v1 advertisement and its route key belong to this generation and
// expire with it; the v1 route key is never the native route key.
function startGuardHost(state, generation, issuedAt) {
  const relay = state.config.relay
  const identity = state.config.identity
  generation.guardRouteKeyPair = cryptoSuite.encryptionKeyPair()
  const advertisement = guardAdvertisement(
    identity,
    generation.guardRouteKeyPair,
    relay,
    issuedAt,
    generation.expiresAt
  )
  try {
    generation.caps = new CapsResponder({
      now: state.roots.clocks.wallNow,
      advertisement,
      identitySecretKey: identity.secretKey,
      routeEncryptionSecretKey: generation.guardRouteKeyPair.secretKey
    })
  } finally {
    clear(advertisement)
  }
  // Guard-bootstrap traffic of this generation's accepted links: every established link
  // and every accept in progress, each for the generation's whole lifetime.
  const linkBudget = guardBootstrapLinkBudget(relay.lifetimeMs)
  const links = relay.limits.maxConcurrentCircuits + GUARD_PENDING_ACCEPTS
  generation.guardLedger = createPeerLedger({
    cells: links * linkBudget.cells,
    bytes: BigInt(links) * linkBudget.bytes,
    commands: 0
  })
  generation.guardRegistration = registerGuardBootstrapResponder(generation.endpoint, {
    caps: generation.caps,
    ledger: generation.guardLedger,
    linkBudget,
    maxPendingAccepts: GUARD_PENDING_ACCEPTS,
    // Every guard link carries at least one circuit.
    maxEstablished: relay.limits.maxConcurrentCircuits,
    acceptOptions: (handle) => guardAcceptOptions(state, generation, handle),
    onEstablished(established) {
      if (state.destroyed || generation.closing) invalid()
      registerSharedGuardPeerBranchResponder(established, generation.linkResponder)
    }
  })
}

function guardAdvertisement(identity, routeKeyPair, relay, issuedAt, expiresAt) {
  const reachableEndpoint = encodeCanonicalEndpoint({
    addressFamily: 4,
    addressBytes: ipv4Bytes(relay.reachable.host),
    port: relay.reachable.port
  })
  const signed = signRelayCapabilityAdvertisement(
    {
      relayIdentity: identity.publicKey,
      currentDhtNodeId: deriveM3DhtNodeId(reachableEndpoint),
      reachableEndpoint,
      routeEncryptionPublicKey: routeKeyPair.publicKey,
      capabilityMask: RELAY_CAPABILITY.CIRCUIT_RELAY_V1,
      minimumProtocolVersion: 1,
      maximumProtocolVersion: 1,
      cellSize: 1200,
      maxCellPayload: 1146,
      contextEnvelopeSize: 1101,
      routeFrameSize: 1100,
      maxRoutePayload: 1073,
      datagramReplayWindow: 64,
      maxConcurrentCircuits: relay.limits.maxConcurrentCircuits,
      capacityClass: relay.limits.capacityClass,
      maxCellsPerCircuit: relay.limits.maxCells,
      maxBytesPerCircuit: relay.limits.maxBytes,
      maxCommandsPerCircuit: relay.limits.maxCommands,
      idleTimeoutMs: relay.limits.idleTimeoutMs,
      maxQueuedBytes: relay.limits.maxQueuedBytes,
      epoch: relay.epoch,
      issuedAtMs: issuedAt,
      expiresAtMs: expiresAt,
      providerServicePolicyEntries: providerServicePolicyForCapabilities(
        RELAY_CAPABILITY.CIRCUIT_RELAY_V1
      )
    },
    identity.secretKey
  )
  return encodeRelayCapabilityAdvertisement(signed)
}

// Options for one accepted bootstrap link. The link may not outlive the generation, and
// the source must complete it within the accept deadline.
function guardAcceptOptions(state, generation, handle) {
  const identity = state.config.identity
  const clocks = state.roots.clocks
  const expiry = Number(generation.expiresAt)
  return {
    mode: 'accept',
    codec: new BootstrapEnvelopeCodec({
      linkHandle: handle,
      localIdentitySecretKey: identity.secretKey,
      padding: randomBytes
    }),
    linkSetup: createLinkSetupAuthority({ now: () => Number(clocks.wallNow()), randomBytes }),
    setup: createDynamicResponderSetup({
      responderStaticSecretKey: generation.guardRouteKeyPair.secretKey,
      responderIdentitySecretKey: identity.secretKey
    }),
    now: () => Number(clocks.monotonicNow()),
    schedule: clocks.setTimer,
    cancel: clocks.clearTimer,
    randomBytes,
    absoluteDeadline: Number(clocks.monotonicNow()) + GUARD_ACCEPT_DEADLINE_MS,
    signedExpiry: expiry,
    authorizedExpiry: expiry
  }
}

// Constructs the tail owner for one incoming branch. A failure here destroys only that
// branch; the generation keeps serving its other branches.
function hostTail(state, generation, runtime) {
  if (state.destroyed || generation.closing) {
    try {
      destroyPeerM3Runtime(runtime)
    } catch {}
    return
  }
  let session = null
  try {
    session = createPeerTailControl(runtime, {
      relayOwner: generation.relayOwner,
      neighborPool: readPeerNeighborAdmission(generation.admission).pool,
      runtimeAuthority: generation.authority,
      memoryPool: state.roots.pool,
      branchSlots: generation.branchSlots,
      joinSet: generation.pendingJoins,
      onFinalReady: (ready) => deliverTerminalFinal(state, generation, ready),
      // A hosted tail stops counting the moment its session ends, whichever path ends it:
      // terminal delivery, a forwarder that ends with its legs, or a failed extension.
      onDestroyed: () => generation.sessions.delete(session)
    })
    // A terminal learns from its predecessor's OFFER which service the source asked for. A
    // presence circuit never reaches the route owner, even where presence is disabled.
    const { payloadParametersDigest } = readPeerM3Runtime(runtime)
    if (b4a.equals(payloadParametersDigest, PRESENCE_PARAMETERS_DIGEST)) {
      PRESENCE_SESSIONS.add(session)
    }
    generation.runtimes.delete(runtime)
    generation.sessions.add(session)
  } catch {
    generation.runtimes.delete(runtime)
    if (session) destroyPeerTailControl(session)
  }
}

// A terminal completes its tail when READY2 is first dispatched: its final runtime moves
// into a route carrier at once, so finalization frames that arrive early are retained. A
// presence circuit goes to the presence service, every other circuit to the route owner.
function deliverTerminalFinal(state, generation, session) {
  const presence = PRESENCE_SESSIONS.delete(session)
  const callback = presence ? null : state.incomingFinal
  let taken = null
  try {
    if ((presence ? state.presence === null : !callback) || state.destroyed || generation.closing) {
      invalid()
    }
    taken = takeFinalTail(session, 'terminal', state.roots.pool)
  } catch {
    destroyPeerTailControl(session)
    return
  }
  destroyPeerTailControl(session)
  const lease = createFinalTailLease(taken, generation.finals)
  try {
    if (presence) state.presence.serve(lease)
    else callback(lease)
  } catch {
    lease.revoke()
  }
}

function readNeighborService(generation) {
  const admission = generation.admission ? readPeerNeighborAdmission(generation.admission) : null
  const facts =
    admission && admission.pool ? readPeerNativeNeighborDiagnostics(admission.pool) : null
  return facts ? facts.nodeServiceLedger : null
}

async function closeRelayGeneration(generation) {
  if (generation.closing) return generation.closing
  generation.closing = (async () => {
    if (generation.renewTimer) clearTimeout(generation.renewTimer)
    generation.renewTimer = null
    // Stop admitting new work before anything that live work depends on is released.
    if (generation.guardRegistration) {
      try {
        destroyGuardBootstrapResponderRegistration(generation.guardRegistration)
      } catch {}
    }
    if (generation.caps) generation.caps.destroy()
    if (generation.registration) {
      try {
        destroyPeerDirectResponderRegistration(generation.registration)
      } catch {}
    }
    if (generation.bootstrap) {
      try {
        destroyPeerBootstrapResponder(generation.bootstrap)
      } catch {}
    }
    for (const lease of generation.finals) {
      try {
        trackPendingJoin(generation.pendingJoins, lease.revoke())
      } catch {}
    }
    generation.finals.clear()
    for (const session of generation.sessions) destroyPeerTailControl(session)
    generation.sessions.clear()
    // Every branch's DESTROY/TEARDOWN duty and native completion must join before its
    // slot can be freed: closePeerBranchSlots runs only after the runtime joins settle.
    await Promise.all(
      Array.from(generation.runtimes, (runtime) => {
        try {
          return Promise.resolve(destroyPeerM3Runtime(runtime)).catch(() => {})
        } catch {
          return Promise.resolve()
        }
      })
    )
    generation.runtimes.clear()
    // Hosted tails, forwarding owners and moved final carriers are no longer in the
    // runtime set: their destroy joins collected above must all settle before the branch
    // pool retires anything. Already-settled joins removed themselves.
    await Promise.all(
      Array.from(generation.pendingJoins, (join) => Promise.resolve(join).catch(() => {}))
    )
    generation.pendingJoins.clear()
    if (generation.admission) {
      try {
        await destroyPeerNeighborAdmission(generation.admission)
      } catch {}
    }
    if (generation.linkResponder) {
      try {
        destroyPeerLinkResponder(generation.linkResponder)
      } catch {}
    }
    if (generation.authority) {
      try {
        generation.authority.destroy()
      } catch {}
    }
    // Revokes every branch still holding authority; nothing can be admitted any more.
    if (generation.branchSlots) closePeerBranchSlots(generation.branchSlots)
    if (generation.relayOwner) {
      try {
        destroyPeerRelayOwner(generation.relayOwner)
      } catch {}
    }
    if (generation.endpoint) {
      try {
        await generation.endpoint.close()
      } catch {}
    }
    // Accepted guard links close with the endpoint, spending their own close allowance
    // first; only then is their parent ledger released.
    if (generation.guardLedger) {
      try {
        releasePeerLedger(generation.guardLedger)
      } catch {}
    }
    if (generation.routeKeyPair) clear(generation.routeKeyPair.secretKey)
    if (generation.guardRouteKeyPair) clear(generation.guardRouteKeyPair.secretKey)
  })()
  return generation.closing
}

// ---------------------------------------------------------------------------
// Source: pinned guards and circuit builds
// ---------------------------------------------------------------------------

// The live pin, replaced when its lease is gone or about to expire. One pin is created at
// a time; concurrent builds share it. Published pins whose leases have ended and that no
// build uses are closed here; a pin still being created has no lease yet and is kept.
function currentSourcePin(state) {
  for (const pin of state.sourcePins) {
    if (pin.published && pin !== state.sourcePin && pin.builds === 0 && !isGuardLease(pin.lease)) {
      void closeSourcePin(state, pin)
    }
  }
  const pin = state.sourcePin
  if (
    pin !== null &&
    isGuardLease(pin.lease) &&
    state.roots.clock.wallNow() + PIN_REFRESH_MS < pin.expiresAt
  ) {
    return Promise.resolve(pin)
  }
  if (state.sourcePinning === null) {
    state.sourcePinning = pinSourceGuard(state)
      .then((fresh) => {
        fresh.published = true
        state.sourcePin = fresh
        return fresh
      })
      .finally(() => {
        state.sourcePinning = null
      })
  }
  return state.sourcePinning
}

// A pin owns one leased endpoint, which pinning dedicates to its guard link; a fresh
// identity used with no other guard; the guard lease; and a local peer owner for that
// identity. The owner's advertisement is never sent and its node identifier is random.
async function pinSourceGuard(state) {
  const source = state.config.source
  const clocks = state.roots.clocks
  const pin = {
    endpoint: null,
    identity: cryptoSuite.keyPair(),
    authority: null,
    io: null,
    lease: null,
    routeKeyPair: null,
    owner: null,
    expiresAt: 0n,
    discovery: Promise.resolve(),
    builds: 0,
    published: false,
    // The pin's bootstrap requests and its guard link's setup and control, for at most
    // the v1 capability lifetime that bounds the pinned link.
    ledger: createPeerLedger(guardBootstrapPinBudget(GUARD_ADVERTISEMENT_MAX_LIFETIME_MS)),
    // The pin's circuit branches, one per circuit it carries, each with its own authority.
    branchSlots: createPeerBranchSlots(MAX_NATIVE_PIN_BRANCH_SLOTS)
  }
  state.sourcePins.add(pin)
  try {
    pin.endpoint = createEndpoint(state, state.lease, null)
    await pin.endpoint.bind()
    if (state.destroyed) destroyed()
    const guards = source.guards.map((guard) => ({ host: guard.host, port: guard.port }))
    pin.authority = createBootstrapUdxAuthority({
      endpoint: pin.endpoint,
      configuredEndpoints: guards,
      localSecretCapability: createLocalIdentitySecretCapability({
        localIdentity: pin.identity.publicKey,
        localSecretKey: pin.identity.secretKey
      }),
      maxProspectiveGuards: source.maxProspectiveGuards,
      monotonicDeadline: clocks.monotonicNow,
      guardBootstrapLedger: pin.ledger
    })
    pin.io = new BootstrapIO({
      endpoints: guards,
      localIdentity: pin.identity.publicKey,
      localSecretKey: pin.identity.secretKey,
      datagrams: pin.authority,
      wallNow: clocks.wallNow,
      monotonicNow: clocks.monotonicNow,
      randomBytes,
      candidateDirectorySink: createRelayCandidateDirectorySink({
        wallNow: clocks.wallNow,
        monotonicNow: clocks.monotonicNow,
        randomBytes
      })
    })
    const transfer = consumeBootstrapGuardPin(await pin.io.start())
    // Native circuits discover their own relays; the v1 candidate directory is unused.
    try {
      transfer.candidateDirectory.destroy()
    } catch {}
    try {
      pin.lease = createGuardLease({
        guardLeaseMaterial: transfer.guardLeaseMaterial,
        pinnedGuard: transfer.pinnedGuard,
        wallNow: clocks.wallNow,
        monotonicNow: clocks.monotonicNow,
        setTimer: clocks.setTimer,
        clearTimer: clocks.clearTimer,
        guardLossSink: Object.freeze({}),
        // The lease, its link and every circuit over it share the runtime's one clock.
        clockIdentity: clocks.clockIdentity,
        // Native circuits: up to sixteen at once over this pin.
        native: true
      })
    } catch (err) {
      destroyGuardLeaseMaterial(transfer.guardLeaseMaterial)
      throw err
    }
    pin.expiresAt = transfer.pinnedGuard.expiresAt
    if (state.destroyed) destroyed()
    const tuple = readDhtUdxSocketLease(state.lease)
    pin.routeKeyPair = cryptoSuite.encryptionKeyPair()
    pin.owner = createPeerRelayOwner({
      endpoint: pin.endpoint,
      identityKeyPair: { publicKey: pin.identity.publicKey, secretKey: pin.identity.secretKey },
      routeKeyPair: pin.routeKeyPair,
      advertisementFields: {
        relayIdentity32: pin.identity.publicKey,
        currentDhtNodeId32: randomBytes(32),
        reachableEndpoint: { host: tuple.host, port: tuple.port },
        routeEncryptionPublicKey32: pin.routeKeyPair.publicKey,
        capabilityMask: 9,
        minimumVersion: 3,
        maximumVersion: 3,
        datagramReplayWindow: 64,
        ...SOURCE_OWNER_LIMITS,
        epoch: 1n,
        issuedAt: clocks.wallNow(),
        expiresAt: pin.expiresAt,
        policyCount: 0
      },
      ...clocks
    })
    // Every holder of the identity secret keeps its own copy.
    clear(pin.identity.secretKey)
    return pin
  } catch (err) {
    await closeSourcePin(state, pin)
    throw err
  }
}

async function closeSourcePin(state, pin) {
  if (!state.sourcePins.delete(pin)) return
  if (state.sourcePin === pin) state.sourcePin = null
  if (pin.io) {
    try {
      pin.io.destroy()
    } catch {}
  }
  // A pinned authority was consumed by its lease; an unpinned one is released here.
  if (pin.authority) destroyBootstrapUdxAuthority(pin.authority)
  if (pin.lease) {
    try {
      destroyGuardLease(pin.lease)
    } catch {}
  }
  if (pin.owner) {
    try {
      destroyPeerRelayOwner(pin.owner)
    } catch {}
  }
  if (pin.endpoint) {
    try {
      await pin.endpoint.close()
    } catch {}
  }
  if (pin.routeKeyPair) clear(pin.routeKeyPair.secretKey)
  closePeerBranchSlots(pin.branchSlots)
  try {
    releasePeerLedger(pin.ledger)
  } catch {}
  clear(pin.identity.secretKey)
}

function readBuildLimits(value) {
  if (!isObject(value)) invalid()
  const limits = {
    maxCells: value.maxCells,
    maxCommands: value.maxCommands,
    idleTimeoutMs: value.idleTimeoutMs
  }
  if (
    !positiveInteger(limits.maxCells, MAX_BUILD_CELLS) ||
    limits.maxCells < MIN_BUILD_CELLS ||
    !positiveInteger(limits.maxCommands, 0xffffffff) ||
    limits.maxCommands < MIN_BUILD_COMMANDS ||
    !positiveInteger(limits.idleTimeoutMs, 0xffffffff)
  ) {
    invalid()
  }
  return Object.freeze(limits)
}

function readBuildRequest(options) {
  if (!isObject(options)) invalid()
  const request = {
    forwardLimits: readBuildLimits(options.forwardLimits),
    reverseLimits: readBuildLimits(options.reverseLimits),
    payloadParametersDigest: copy(options.payloadParametersDigest, 32),
    terminal: null
  }
  if (options.terminal !== null && options.terminal !== undefined) {
    if (!isObject(options.terminal)) invalid()
    request.terminal = copy(options.terminal.advertisement260, 260)
  }
  return request
}

// Wire limits for one hop: bytes follow cells exactly, and the expiry is the earliest
// bound that hop admits.
function wireLimits(limits, expiresAt) {
  return {
    cellSize: 1200,
    maxCells: limits.maxCells,
    maxBytes: limits.maxCells * 1200,
    maxCommands: limits.maxCommands,
    idleTimeoutMs: limits.idleTimeoutMs,
    expiresAt
  }
}

function earliest(first, ...rest) {
  let result = first
  for (const value of rest) if (value < result) result = value
  return result
}

function guardAdvertisementExpiry(facts, clocks) {
  const verified = verifyPeerAdvertisement(facts.completeAdvertisement, {
    expectedIdentity32: facts.identity32,
    expectedRole: 1,
    clockIdentity: clocks.clockIdentity,
    wallNow: clocks.wallNow,
    monotonicNow: clocks.monotonicNow
  })
  const info = readVerifiedPeerAdvertisement(verified)
  for (const value of Object.values(info)) clear(value)
  return info.expiresAt
}

function checkBuild(state) {
  if (state.destroyed) destroyed()
  if (state.suspended) throw PrivateRouteError.ROUTE_UNAVAILABLE()
}

// D0 uses the lease's single bootstrap transport, so discoveries through one pin run one
// at a time.
function discoverThroughGuard(pin) {
  const run = () =>
    discoverPeerCandidate(createPeerGuardBootstrapTransport(pin.lease), {
      ledger: createPeerLedger(D0_BUDGET),
      requestedMask: 9,
      randomTarget: randomBytes(32),
      maximumResults: 1
    })
  const discovery = pin.discovery.then(run, run)
  pin.discovery = discovery.then(
    () => {},
    () => {}
  )
  return discovery
}

// One circuit: D0 through the pinned guard, the guard link, then the safety and the
// terminal through the growing tail. Only the terminal receives the caller's payload
// parameters digest; the guard and the safety each receive an independent random digest,
// so no offer shares a value with another hop's.
async function buildSourceTail(state, request) {
  const clocks = state.roots.clocks
  const pin = await currentSourcePin(state)
  checkBuild(state)
  pin.builds++
  let candidate = null
  let handle = null
  let session = null
  try {
    candidate = await discoverThroughGuard(pin)
    checkBuild(state)
    const facts = readPeerActiveCandidateFacts(candidate)
    let expiresAt
    try {
      expiresAt = earliest(pin.expiresAt, guardAdvertisementExpiry(facts, clocks))
    } finally {
      clear(facts.identity32)
      clear(facts.endpoint19)
      clear(facts.activeResponseDigest)
    }
    const forwardLimits = wireLimits(request.forwardLimits, expiresAt)
    const reverseLimits = wireLimits(request.reverseLimits, expiresAt)
    const tailKeyPair = cryptoSuite.encryptionKeyPair()
    try {
      handle = await openPeerGuardLink({
        guardLease: pin.lease,
        activeCandidate: candidate,
        relayOwner: pin.owner,
        advertisement: facts.completeAdvertisement,
        branchId: randomBytes(16),
        circuitId: randomBytes(16),
        generation: 1n,
        extensionIndex: 0,
        clientTailEphemeralPublicKey: tailKeyPair.publicKey,
        clientTailSecretKey: tailKeyPair.secretKey,
        clientNonce: randomBytes(32),
        payloadParametersDigest: randomBytes(32),
        candidateAuthorityCommitment32: b4a.alloc(32),
        forwardLimits,
        reverseLimits,
        operationDeadline: clocks.monotonicNow() + BUILD_OPERATION_MS,
        branchSlots: pin.branchSlots
      })
    } finally {
      clear(tailKeyPair.secretKey)
      clear(facts.completeAdvertisement)
    }
    candidate = null
    checkBuild(state)
    const runtime = adoptPeerEstablishedLink(state.sourceAuthority, handle)
    handle = null
    // Tail control owns the runtime from here and destroys it if its setup fails.
    session = createPeerTailControl(runtime, { memoryPool: state.roots.pool })
    const hops = [
      { requestedMask: 9, supplied: null, digest: randomBytes(32) },
      { requestedMask: 11, supplied: request.terminal, digest: request.payloadParametersDigest }
    ]
    for (const hop of hops) {
      const bound = earliest(expiresAt, readPeerTailControl(session).wireExpiresAt)
      const discovery = {
        mode: hop.supplied === null ? 1 : 2,
        requestedMask: hop.requestedMask,
        randomTarget32: randomBytes(32),
        expiresAt: bound
      }
      if (hop.supplied !== null) discovery.suppliedAdvertisement260 = hop.supplied
      const next = await discoverPeerTailCandidate(session, discovery)
      checkBuild(state)
      // The successor link lives no longer than the successor's advertisement, so neither
      // direction of this hop may outlive it.
      const { advertisementExpiresAt } = readPeerTailCandidateBounds(next)
      const hopBound = earliest(bound, advertisementExpiresAt)
      await extendPeerTail(session, {
        candidate: next,
        forwardLimits: wireLimits(request.forwardLimits, hopBound),
        reverseLimits: wireLimits(request.reverseLimits, hopBound),
        payloadParametersDigest: hop.digest
      })
      checkBuild(state)
    }
    const descriptor = readPeerTailControl(session)
    const taken = takeFinalTail(session, 'source', state.roots.pool, {
      terminalAdvertisement260: descriptor.advertisement
    })
    destroyPeerTailControl(session)
    session = null
    return createFinalTailLease(taken, state.sourceFinals)
  } catch (err) {
    // A build whose guard link or path went away fails as unavailable, and the next build
    // pins afresh; ERR_DESTROYED means only that this runtime was destroyed.
    if (!state.destroyed && err instanceof PrivateRouteError && err.code === 'ERR_DESTROYED') {
      throw PrivateRouteError.ROUTE_UNAVAILABLE()
    }
    throw err
  } finally {
    pin.builds--
    if (candidate) {
      try {
        destroyPeerActiveCandidate(candidate)
      } catch {}
    }
    if (handle) {
      try {
        destroyPeerEstablishedLink(handle)
      } catch {}
    }
    if (session) destroyPeerTailControl(session)
  }
}

// ---------------------------------------------------------------------------
// Runtime
// ---------------------------------------------------------------------------

// Every step re-checks destruction and suspension: a destroy or suspend that lands
// mid-start closes what the start created, and the start then fails instead of
// publishing a half-built runtime.
async function startRuntime(state) {
  checkRunning(state)
  state.lease = leaseCurrentSocket(state)
  state.localTuple = readDhtUdxSocketLease(state.lease)
  if (state.config.role === 'relay') {
    await provisionRelayGeneration(state, true)
  } else {
    // Every circuit this source builds is adopted by one adjacency authority.
    state.sourceAuthority = createPeerM3AdjacencyAuthority(state.roots.clocks)
  }
  state.started = true
}

function checkRunning(state, generation = null) {
  if (state.destroyed) destroyed()
  if (state.suspended || (generation !== null && generation.closing)) {
    throw PrivateRouteError.ROUTE_UNAVAILABLE()
  }
}

// Starts a generation on the current lease. A first start needs every configured neighbor
// live; a renewed or resumed generation serves with the neighbors it admits, and the rest
// follow their admission slots.
async function provisionRelayGeneration(state, requireAllNeighbors) {
  const generation = startRelayGeneration(state)
  state.relayGeneration = generation
  state.generations++
  try {
    await generation.endpoint.bind()
    checkRunning(state, generation)
    await settlePeerNeighborAdmission(generation.admission)
    checkRunning(state, generation)
    if (requireAllNeighbors) {
      const neighbors = readPeerNeighborAdmission(generation.admission).neighbors
      if (!neighbors.every((slot) => slot.state === 'live')) {
        throw PrivateRouteError.ROUTE_UNAVAILABLE()
      }
    }
    armRenewal(state, generation)
  } catch (err) {
    if (state.relayGeneration === generation) state.relayGeneration = null
    await closeRelayGeneration(generation)
    throw err
  }
}

// A generation is replaced a quarter of its lifetime before its advertisements expire,
// and at most RENEWAL_MARGIN_MS before. The old generation is torn down first, ending its
// links, hosted tails and undelivered final leases: an endpoint keys its peers by address,
// so two generations cannot share the socket.
function armRenewal(state, generation) {
  const lifetime = BigInt(state.config.relay.lifetimeMs)
  const margin = lifetime / 4n < RENEWAL_MARGIN_MS ? lifetime / 4n : RENEWAL_MARGIN_MS
  const renewAt = generation.expiresAt - margin
  const due = renewAt - state.roots.clock.wallNow()
  const delay = due <= 0n ? 0n : due > MAX_TIMER_MS ? MAX_TIMER_MS : due
  generation.renewTimer = setTimeout(() => {
    generation.renewTimer = null
    if (generation.closing) return
    // A timer longer than the platform allows is re-armed until renewal is due.
    if (renewAt > state.roots.clock.wallNow()) armRenewal(state, generation)
    else void renewRelayGeneration(state, generation)
  }, Number(delay))
}

async function renewRelayGeneration(state, generation) {
  if (state.destroyed || state.suspended || state.relayGeneration !== generation) return
  const renewing = (async () => {
    await closeRelayGeneration(generation)
    if (state.destroyed || state.suspended || state.relayGeneration !== generation) return
    state.relayGeneration = null
    await provisionRelayGeneration(state, false)
  })()
  state.renewing = renewing
  try {
    await renewing
  } catch (err) {
    // A relay whose renewal fails serves nothing until its owner acts; diagnostics say so.
    state.lastError = err instanceof PrivateRouteError ? err.code : 'ROUTE_UNAVAILABLE'
  } finally {
    if (state.renewing === renewing) state.renewing = null
  }
}

// Suspension ends everything bound to the current socket generation and joins its native
// sends before the socket is suspended or replaced. A pending start or renewal ends with
// the generation it was provisioning.
async function suspendRuntime(state) {
  state.suspended = true
  if (state.relayGeneration) void closeRelayGeneration(state.relayGeneration)
  if (state.starting) await state.starting.catch(() => {})
  if (state.renewing) await state.renewing.catch(() => {})
  await stopRuntime(state)
}

// Resumption leases the DHT's next socket generation. A relay resumes only on the local
// tuple it served before, because its configured tuple, grants and neighbors name it.
async function resumeRuntime(state) {
  state.suspended = false
  if (!state.started) return
  state.lease = leaseCurrentSocket(state)
  const tuple = readDhtUdxSocketLease(state.lease)
  if (state.config.role === 'relay') {
    if (tuple.host !== state.localTuple.host || tuple.port !== state.localTuple.port) {
      throw PrivateRouteError.ROUTE_UNAVAILABLE()
    }
    await provisionRelayGeneration(state, false)
  } else {
    state.localTuple = tuple
    state.sourceAuthority = createPeerM3AdjacencyAuthority(state.roots.clocks)
  }
}

async function stopRuntime(state) {
  const generation = state.relayGeneration
  state.relayGeneration = null
  if (generation) await closeRelayGeneration(generation)
  await Promise.all(
    Array.from(state.sourceFinals, (lease) => {
      try {
        return Promise.resolve(lease.revoke()).catch(() => {})
      } catch {
        return null
      }
    })
  )
  state.sourceFinals.clear()
  // Closing a pin ends every build and circuit that uses its guard link.
  await Promise.all(Array.from(state.sourcePins, (pin) => closeSourcePin(state, pin)))
  if (state.sourceAuthority) {
    try {
      state.sourceAuthority.destroy()
    } catch {}
    state.sourceAuthority = null
  }
  if (state.revokeLeaseObserver) {
    state.revokeLeaseObserver()
    state.revokeLeaseObserver = null
  }
  const lease = state.lease
  state.lease = null
  if (lease) await revokeDhtUdxSocketLease(lease)
}

function createPeerNativeRuntime(options) {
  if (!isObject(options)) invalid()
  const { dht } = options
  if (!isObject(dht) || !isObject(dht.io)) invalid()
  const config = readNativeConfig(options.config)
  let dhtNodeId = null
  if (config.role === 'relay') {
    // The advertisement names this node's real DHT identifier.
    if (!fixed(dht.id, 32)) throw PrivateRouteError.ROUTE_UNAVAILABLE()
    dhtNodeId = b4a.from(dht.id)
  }
  const state = {
    dht,
    config,
    dhtNodeId,
    roots: createRoots(config.memoryBytes),
    lease: null,
    socketGeneration: 0,
    // One attempt sequence for every socket generation this runtime leases.
    sendSequence: createSendAttemptSequence(),
    sendObserver: null,
    revokeLeaseObserver: null,
    relayGeneration: null,
    sourceAuthority: null,
    sourcePins: new Set(),
    sourcePin: null,
    sourcePinning: null,
    sourceFinals: new Set(),
    reservations: new Set(),
    incomingFinal: null,
    presence:
      config.relay && config.relay.presence
        ? createPresenceTerminal({ dht, policy: config.relay.presence })
        : null,
    suspended: false,
    started: false,
    localTuple: null,
    generations: 0,
    lastError: null,
    renewing: null,
    suspending: null,
    resuming: null,
    destroyed: false,
    starting: null,
    closing: null
  }
  const runtime = Object.freeze({
    ready() {
      if (state.destroyed) return Promise.reject(PrivateRouteError.ERR_DESTROYED())
      if (state.suspended) return Promise.reject(PrivateRouteError.ROUTE_UNAVAILABLE())
      if (!state.starting) {
        const starting = startRuntime(state).catch(async (err) => {
          await stopRuntime(state)
          // A start that failed may be retried by a later ready().
          if (state.starting === starting) state.starting = null
          throw err
        })
        state.starting = starting
      }
      return state.starting
    },
    buildTail(options) {
      if (state.destroyed) return Promise.reject(PrivateRouteError.ERR_DESTROYED())
      if (state.config.role !== 'source') return Promise.reject(PrivateRouteError.INVALID_ROUTE())
      let request
      try {
        request = readBuildRequest(options)
      } catch (err) {
        return Promise.reject(err)
      }
      return runtime.ready().then(() => buildSourceTail(state, request))
    },
    onIncomingFinal(callback) {
      if (state.destroyed) destroyed()
      if (typeof callback !== 'function' || state.incomingFinal !== null) invalid()
      if (!state.config.relay || state.config.relay.capabilityMask !== 11) invalid()
      state.incomingFinal = callback
      return function unregisterIncomingFinal() {
        if (state.incomingFinal !== callback) return false
        state.incomingFinal = null
        return true
      }
    },
    // A scoped reservation from the node pool. The pool bounds the sum of every owner's
    // reservations; the runtime releases whatever its owner has not when it is destroyed.
    reserve(kind, bytes) {
      if (state.destroyed) destroyed()
      if (!RESERVATION_KINDS.has(kind) || !positiveInteger(bytes, 0xffffffff)) invalid()
      if (readPeerMemory(state.roots.pool).remainingBytes < bytes) {
        throw PrivateRouteError.CIRCUIT_LIMIT()
      }
      const reservation = reservePeerMemory(state.roots.pool, `native-runtime/${kind}`, bytes)
      state.reservations.add(reservation)
      return reservation
    },
    release(reservation) {
      if (!state.reservations.delete(reservation)) return false
      return releasePeerMemory(reservation)
    },
    observeSendAttempts(listener) {
      if (state.destroyed) destroyed()
      if (typeof listener !== 'function' || state.sendObserver !== null) invalid()
      state.sendObserver = listener
      if (state.lease) {
        state.revokeLeaseObserver = observeDhtUdxSocketLease(state.lease, (event) =>
          listener(event)
        )
      }
      return function stopObservingSends() {
        if (state.sendObserver !== listener) return false
        state.sendObserver = null
        if (state.revokeLeaseObserver) {
          state.revokeLeaseObserver()
          state.revokeLeaseObserver = null
        }
        return true
      }
    },
    suspend() {
      if (state.destroyed) return Promise.reject(PrivateRouteError.ERR_DESTROYED())
      if (state.suspending === null) {
        state.resuming = null
        state.suspending = suspendRuntime(state)
      }
      return state.suspending
    },
    resume() {
      if (state.destroyed) return Promise.reject(PrivateRouteError.ERR_DESTROYED())
      if (state.suspending === null) return state.resuming || Promise.resolve()
      if (state.resuming === null) {
        state.resuming = state.suspending.then(() => {
          state.suspending = null
          return resumeRuntime(state).catch(async (err) => {
            // A runtime that cannot resume stays suspended; its owner recreates it.
            state.suspended = true
            await stopRuntime(state)
            state.lastError = err instanceof PrivateRouteError ? err.code : 'ROUTE_UNAVAILABLE'
            throw err
          })
        })
      }
      return state.resuming
    },
    diagnostics() {
      const generation = state.relayGeneration
      return Object.freeze({
        socketGeneration: state.socketGeneration,
        leased: state.lease !== null,
        suspended: state.suspended,
        generations: state.generations,
        lastError: state.lastError,
        // Source: whether a live guard pin exists for the next build.
        guardPinned: state.sourcePin !== null && isGuardLease(state.sourcePin.lease),
        hostedTails: generation ? generation.sessions.size : 0,
        // Relay: this generation's live and retired circuit branches and what they spent.
        // Source: the same for the current pin's branches.
        branches: generation
          ? readPeerBranchSlots(generation.branchSlots)
          : state.sourcePin
            ? readPeerBranchSlots(state.sourcePin.branchSlots)
            : null,
        neighbors: generation
          ? readPeerNeighborAdmission(generation.admission).neighbors.map((slot) => slot.state)
          : [],
        // Relay: the node-service ledger that funds neighbor provisioning, maintenance and
        // close. Circuit work, including D1/D2 discovery, never spends it.
        neighborService: generation ? readNeighborService(generation) : null,
        // Terminal: presence circuits in service, operations answered, circuits refused.
        presence: state.presence ? state.presence.diagnostics() : null
      })
    },
    destroy() {
      if (state.closing) return state.closing
      state.destroyed = true
      state.incomingFinal = null
      const presenceClosing = state.presence ? state.presence.close() : null
      removeDhtListeners()
      const starting = state.starting
      state.closing = (async () => {
        // Presence carriers revoked at close join first: their branches are funded from
        // the relay generation's pool, so its close must not retire anything before them.
        if (presenceClosing) await presenceClosing.catch(() => {})
        // Closing the generation ends an admission settle a pending start waits on.
        if (state.relayGeneration) void closeRelayGeneration(state.relayGeneration)
        if (starting) await starting.catch(() => {})
        for (const pending of [state.renewing, state.suspending, state.resuming]) {
          if (pending) await pending.catch(() => {})
        }
        await stopRuntime(state)
        for (const reservation of state.reservations) releasePeerMemory(reservation)
        state.reservations.clear()
        clear(state.dhtNodeId)
        if (state.config.identity) clear(state.config.identity.secretKey)
      })()
      return state.closing
    }
  })
  // An owner suspends and resumes the runtime around the DHT's own suspension. The DHT's
  // events cover an owner that does not, once the socket is already closed or rebound.
  const onDhtSuspend = () => {
    if (!state.destroyed && !state.suspended) void runtime.suspend().catch(() => {})
  }
  const onDhtResume = () => {
    if (!state.destroyed && state.suspended) void runtime.resume().catch(() => {})
  }
  const removeDhtListeners = () => {
    const off = typeof dht.off === 'function' ? dht.off : dht.removeListener
    if (typeof off !== 'function') return
    off.call(dht, 'suspend', onDhtSuspend)
    off.call(dht, 'resume', onDhtResume)
  }
  if (typeof dht.on === 'function') {
    dht.on('suspend', onDhtSuspend)
    dht.on('resume', onDhtResume)
  }
  RUNTIMES.set(runtime, state)
  return runtime
}

function isPeerNativeRuntime(value) {
  return isObject(value) && RUNTIMES.has(value)
}

module.exports = {
  createPeerNativeRuntime,
  isPeerNativeRuntime,
  readNativeConfig
}
