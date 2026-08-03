'use strict'

const runtime = require('#private-route-process')
const b4a = require('b4a')
const HyperDHT = require('../../..')
const UDX = require('udx-native')

const { cryptoSuite } = require('../../../lib/private/crypto-suite')
const {
  createEndpointBootstrapAuthority
} = require('../../../lib/private/endpoint-bootstrap-authority')
const {
  createPrivateRoutingController
} = require('../../../lib/private/private-routing-controller')
const { RelayService } = require('../../../lib/private/relay-service')
const { ROLE } = require('../../../lib/private/protocol')
const { encodeCanonicalEndpoint } = require('../../../lib/private/relay-capability')
const { UdxCellEndpoint } = require('../../../lib/private/udx-cell-endpoint')
const { AUDIT_CLASSES, AUDIT_PHASES, TEST_ONLY_AUDIT_CONTEXT_ISSUER } = require('./audit-event')
const {
  ControlFrameDecoder,
  decodeCanonicalBody,
  encodeCanonicalBody,
  encodeControlFrame,
  validateControlMessage
} = require('./control-channel')
const { CODEC_VECTOR_DIGEST_HEX } = require('./codec-vectors')
const {
  armSetupDhtAudit,
  createDhtSetupAuditController,
  destroyDhtSetupAuditController,
  drainDhtSetupAuditEvents
} = require('./dht-setup-audit-udx')
const { PROCESS_PLANS } = require('./topology-fixture')
const {
  acceptProjectedExtension,
  activateFinalExitActor,
  createGuardProcessService,
  createProjectedLinkService
} = require('./wire-services')

const UDX_VERSION = require('udx-native/package.json').version
const CODEC_VECTOR_DIGEST = b4a.from(CODEC_VECTOR_DIGEST_HEX, 'hex')
const DHT_ROLES = new Set(['dht-seed', 'dht-referral', 'dht-value'])
const RELAY_ROLES = new Set(['guard', 'lookup-middle-a', 'lookup-middle-b', 'announce-middle'])
const MIDDLE_ROLES = new Set(['lookup-middle-a', 'lookup-middle-b', 'announce-middle'])
const EXIT_ROLES = new Set(['lookup-exit-a', 'lookup-exit-b', 'announce-exit'])

let projection = null
let generation = 0n
let phaseSequence = 0n
let state = 'NEW'
let commandQueue = Promise.resolve()
let stopped = false
let cellEndpoint = null
let relayService = null
let endpointController = null
let dht = null
let setupAudit = null
let wireService = null
let guardProcessService = null
let incomingActor = null
let incomingActorPromise = null
let incomingRearmHandle = null
let rearming = false
const roleActors = new Set()
let finalExitService = null
let finalExitServicePromise = null
let isolatedGrantPending = null
let isolatedGrantRequestSequence = 0n
let activeOperation = null
let operationSequence = 0n
let endpointMonitorHandle = null
let endpointMonitorSnapshot = null
let endpointMonitorBusy = false

function sanitizeCode(err) {
  if (
    err &&
    typeof err.code === 'string' &&
    /^(ERR_[A-Z0-9_]{1,60}|PROCESS_[A-Z0-9_]{1,60})$/.test(err.code)
  ) {
    return err.code
  }
  return 'PROCESS_ROLE_FAILURE'
}

function same(left, right) {
  return b4a.isBuffer(left) && b4a.isBuffer(right) && b4a.equals(left, right)
}

function event(type, fields = {}) {
  return Object.freeze({
    generation,
    phaseSequence,
    role: projection.role,
    roleIndex: projection.roleIndex,
    type,
    ...fields
  })
}

function writeMessage(message) {
  const frame = encodeControlFrame(message)
  return new Promise((resolve, reject) => {
    try {
      runtime.stdout.write(frame, (err) => {
        frame.fill(0)
        if (err) reject(err)
        else resolve()
      })
    } catch (err) {
      frame.fill(0)
      reject(err)
    }
  })
}

function emit(type, fields) {
  return writeMessage(event(type, fields))
}

function schedule(fn, ms) {
  return setTimeout(fn, ms)
}

function cancelScheduled(handle) {
  clearTimeout(handle)
}

function randomBytes(size) {
  return cryptoSuite.randomBytes(size)
}

function tupleForRole(roleIndex) {
  if (projection.plan === PROCESS_PLANS.PORTABLE_LOOPBACK.name) {
    return Object.freeze({ host: `127.64.${roleIndex}.1`, port: 42_000 + roleIndex })
  }
  if (projection.plan === PROCESS_PLANS.LINUX_NAMESPACE.name) {
    return Object.freeze({ host: `10.203.${roleIndex}.2`, port: 42_000 + roleIndex })
  }
  throw Object.assign(new Error(), { code: 'PROCESS_PROJECTION_INVALID' })
}

function planCapability() {
  if (projection.plan === PROCESS_PLANS.PORTABLE_LOOPBACK.name) {
    return PROCESS_PLANS.PORTABLE_LOOPBACK
  }
  if (projection.plan === PROCESS_PLANS.LINUX_NAMESPACE.name) return PROCESS_PLANS.LINUX_NAMESPACE
  throw Object.assign(new Error(), { code: 'PROCESS_PROJECTION_INVALID' })
}

function verifyBound(owner) {
  const address = owner.address()
  if (!address || address.host !== projection.bind.host || address.port !== projection.bind.port) {
    throw Object.assign(new Error(), { code: 'PROCESS_BIND_MISMATCH' })
  }
}

async function createEndpointOwner() {
  const authority = createEndpointBootstrapAuthority({
    bootstrapEndpoints: [projection.guardBootstrap],
    cancelScheduled,
    host: projection.bind.host,
    localIdentity: projection.identityPublicKey,
    localSecretKey: b4a.from(projection.localIdentitySecretKey),
    monotonicNow: runtime.monotonicNow,
    port: projection.bind.port,
    randomBytes,
    schedule,
    wallNow: runtime.wallNow
  })
  endpointController = createPrivateRoutingController({ endpointBootstrapAuthority: authority })
}

function canonicalTuple(tuple) {
  return encodeCanonicalEndpoint({
    addressFamily: 4,
    addressBytes: b4a.from(tuple.host.split('.').map(Number)),
    port: tuple.port
  })
}

function receiveRoleBootstrap(packet) {
  if (guardProcessService) return guardProcessService.receiveBootstrap(packet)
  if (wireService === null) return false
  // A predecessor rebuilding its branch retries `LINK_CREATE`, and this role has no
  // other way to learn that its old circuit is gone: a peer closing a link is silent
  // on the wire. An unmatched bootstrap packet therefore rearms the accept session,
  // and the retry lands on it.
  if (wireService.snapshot().pending === 0) scheduleIncomingRearm()
  return wireService.receiveBootstrap(packet)
}

function receiveRoleCell(packet, handle, metadata) {
  if (guardProcessService) return guardProcessService.receiveCell(packet, handle, metadata)
  if (wireService) return wireService.receiveCell(packet, handle, metadata)
  return false
}

// Losing an adjacent link is normal protocol traffic for a relay: a commanded
// `rotate`/`guard-loss`, or a BRANCH_DESTROY arriving from a neighbour, tears down
// every actor bound to that circuit. Those roles must survive it — the scenario
// still stops them and requires exit 0 — so only non-loss failures are fatal.
const LINK_LOSS_CODES = new Set([
  'ERR_DESTROYED',
  'ERR_PRIVACY_UNAVAILABLE',
  'PROCESS_LINK_LOSS',
  'PROCESS_LINK_SESSION_UNAVAILABLE'
])

function receiveRoleLinkFailure(handle, direction, reason) {
  if (guardProcessService) {
    guardProcessService.receiveLinkFailure(handle, direction, reason)
    return
  }
  if (wireService) wireService.receiveLinkFailure(handle, direction, reason)
  scheduleIncomingRearm()
}

function actorFailure(err) {
  const code = err && typeof err.code === 'string' ? err.code : 'PROCESS_LINK_SESSION_UNAVAILABLE'
  if (LINK_LOSS_CODES.has(code)) {
    scheduleIncomingRearm()
    return
  }
  void fatal(Object.assign(new Error(), { code }))
}

// A rebuilt branch opens a new adjacent link, so a relay that lost its circuit must
// tear the old actor down and prearm a fresh accept. The rearm is deferred one turn
// because a single teardown reports through several callbacks, and it is skipped while
// an accept is already pending so the teardown it performs cannot retrigger itself.
function scheduleIncomingRearm() {
  if (stopped || rearming || incomingRearmHandle !== null) return
  if (!MIDDLE_ROLES.has(projection.role) && !EXIT_ROLES.has(projection.role)) return
  if (wireService !== null && wireService.snapshot().pending > 0) return
  incomingRearmHandle = schedule(() => {
    incomingRearmHandle = null
    void rearmIncomingExtension().catch((err) => fatal(err))
  }, 0)
}

async function rearmIncomingExtension() {
  if (stopped || rearming || wireService === null || state !== 'READY') return
  if (wireService.snapshot().pending > 0) return
  rearming = true
  try {
    for (const actor of roleActors) actor.destroy()
    roleActors.clear()
    incomingActor = null
    incomingActorPromise = null
    if (finalExitService !== null) {
      const owner = finalExitService
      finalExitService = null
      await owner.destroy().catch(() => {})
    }
    finalExitServicePromise = null
    // Both adjacent links belong to the circuit that just died. Dropping them releases
    // their grants, so the rebuilt branch can authorize the same signed grants again.
    await wireService.faultPhysicalLink().catch(() => false)
    if (stopped || wireService === null || state !== 'READY') return
    startIncomingExtension()
  } finally {
    rearming = false
  }
}

async function requestIsolatedGrant(tupleDigest) {
  if (
    isolatedGrantPending !== null ||
    !EXIT_ROLES.has(projection.role) ||
    !b4a.isBuffer(tupleDigest) ||
    tupleDigest.byteLength !== 32
  ) {
    throw Object.assign(new Error(), { code: 'PROCESS_GRANT_REPLAY' })
  }
  const requestSequence = ++isolatedGrantRequestSequence
  const ownedDigest = b4a.from(tupleDigest)
  let resolveGrant
  let rejectGrant
  const granted = new Promise((resolve, reject) => {
    resolveGrant = resolve
    rejectGrant = reject
  })
  void granted.catch(() => {})
  isolatedGrantPending = {
    digest: ownedDigest,
    reject: rejectGrant,
    requestSequence,
    resolve: resolveGrant
  }
  await emit('isolated-grant-request', {
    requestSequence,
    run: projection.run,
    tupleDigest: ownedDigest
  })
  return granted
}

function startIncomingExtension() {
  let accepted = null
  let observedPredecessorEndpoint = null
  let outgoing = null
  if (MIDDLE_ROLES.has(projection.role)) {
    accepted = wireService.prearmAccept(projection.grants[0])
    observedPredecessorEndpoint = canonicalTuple(projection.adjacencies[0].tuple)
    outgoing = {
      allowedRole: ROLE.PRIVATE,
      extensionIndex: 2,
      grant: projection.grants[1],
      linkService: wireService,
      peerIdentity: projection.adjacencies[1].identity
    }
  } else if (EXIT_ROLES.has(projection.role)) {
    accepted = wireService.prearmAccept(projection.middleGrant)
    observedPredecessorEndpoint = canonicalTuple(projection.middleAdjacency.tuple)
  } else {
    return
  }
  incomingActorPromise = acceptProjectedExtension({
    accepted,
    advertisement: projection.advertisement,
    clocks: {
      wallNow: runtime.wallNow,
      monotonicNow: runtime.monotonicNow,
      schedule,
      cancelScheduled
    },
    identityPublicKey: projection.identityPublicKey,
    identitySecretKey: projection.identitySecretKey,
    linkService: wireService,
    observedPredecessorEndpoint,
    outgoing,
    routeSecretKey: projection.routeSecretKey
  }).then((actor) => {
    observedPredecessorEndpoint.fill(0)
    incomingActor = actor
    roleActors.add(actor)
    if (outgoing) void actor.serve().catch(actorFailure)
    if (!outgoing) {
      finalExitServicePromise = activateFinalExitActor({
        actor,
        advertisement: projection.advertisement,
        identityPublicKey: projection.identityPublicKey,
        identitySecretKey: projection.identitySecretKey,
        clocks: {
          wallNow: runtime.wallNow,
          monotonicNow: runtime.monotonicNow,
          schedule,
          cancelScheduled
        },
        local: {
          host: projection.bind.host,
          port: 43_000 + projection.roleIndex
        },
        dhtSeed: projection.dhtSeed,
        dhtSeedId: projection.dhtSeedId,
        exitRole: projection.roleIndex,
        generation,
        initialSeedGrant: projection.initialSeedGrant,
        isolatedGrantVerifier: projection.isolatedGrantVerifier,
        requestIsolatedGrant
      }).then((service) => {
        finalExitService = service
        return service
      })
      void finalExitServicePromise.catch(actorFailure)
    }
    return actor
  })
  void incomingActorPromise.catch((err) => {
    observedPredecessorEndpoint.fill(0)
    actorFailure(err)
  })
}

async function createCellOwner() {
  cellEndpoint = new UdxCellEndpoint({
    host: projection.bind.host,
    onBootstrap: receiveRoleBootstrap,
    onCell: receiveRoleCell,
    onLinkFailure: receiveRoleLinkFailure,
    port: projection.bind.port
  })
  try {
    await cellEndpoint.bind()
  } catch {
    throw Object.assign(new Error(), { code: 'PROCESS_BIND_UNAVAILABLE' })
  }
  wireService = createProjectedLinkService({
    endpoint: cellEndpoint,
    authorityPublicKey: projection.topologyAuthorityPublicKey,
    epoch: projection.topologyEpoch,
    localIdentity: projection.identityPublicKey,
    localIdentitySecretKey: projection.identitySecretKey,
    localRouteSecretKey: projection.routeSecretKey,
    runId32: projection.topologyRunId,
    wallNow: runtime.wallNow,
    monotonicNow: runtime.monotonicNow,
    schedule,
    cancelScheduled,
    onLinkFailure() {
      actorFailure(Object.assign(new Error(), { code: 'PROCESS_LINK_LOSS' }))
    }
  })
  if (projection.role === 'guard') {
    const middleRoutes = projection.middleAdjacencies.map((contact, index) => ({
      endpoint: canonicalTuple(contact.tuple),
      extensionIndex: 1,
      grant: projection.middleGrants[index],
      linkService: wireService,
      peerIdentity: contact.identity
    }))
    guardProcessService = createGuardProcessService({
      endpoint: cellEndpoint,
      advertisement: projection.advertisement,
      candidateAdvertisements: projection.candidateAdvertisements,
      endpointTuple: projection.endpointAdjacentBinding,
      identityPublicKey: projection.identityPublicKey,
      identitySecretKey: projection.identitySecretKey,
      routeSecretKey: projection.routeSecretKey,
      linkService: wireService,
      middleRoutes,
      clocks: {
        wallNow: runtime.wallNow,
        monotonicNow: runtime.monotonicNow,
        schedule,
        cancelScheduled
      },
      onActor(actor) {
        roleActors.add(actor)
      },
      onFailure: actorFailure
    })
    await guardProcessService.start()
  }
  if (RELAY_ROLES.has(projection.role)) {
    relayService = new RelayService({
      cancel: cancelScheduled,
      limits: {
        maxCircuits: 3,
        maxCircuitsPerNeighbor: 1,
        maxQueuedBytes: 262_144,
        maxQueuedBytesPerCircuit: 262_144
      },
      now: () => Number(runtime.monotonicNow()),
      schedule
    })
  }
}

async function prepare() {
  if (state !== 'CONFIGURED') throw Object.assign(new Error(), { code: 'PROCESS_PHASE_INVALID' })
  if (DHT_ROLES.has(projection.role)) {
    state = 'PREPARED'
    return
  }
  if (projection.role === 'endpoint') await createEndpointOwner()
  else await createCellOwner()
  state = 'PREPARED'
}

function setupAuditEmitter(message) {
  void writeMessage(message).catch(() => {
    runtime.exit(1)
  })
}

async function createDhtOwner() {
  const options = {
    ...projection.dhtOptions,
    bootstrap: projection.dhtOptions.bootstrap.slice(),
    nodes: projection.dhtOptions.nodes.map((node) => ({ host: node.host, port: node.port }))
  }
  if (projection.role === 'dht-referral') {
    const native = new UDX()
    setupAudit = createDhtSetupAuditController({
      auditContext: TEST_ONLY_AUDIT_CONTEXT_ISSUER.context({
        destinationRoleIndex: 11,
        phase: AUDIT_PHASES.DHT_SETUP,
        plan: planCapability(),
        roleIndex: 10
      }),
      destination: tupleForRole(11),
      emit: setupAuditEmitter,
      onFailure(err) {
        void fatal(err)
      },
      generation,
      key: projection.controlAuditMacKey,
      maximumCorrelations: 64,
      maximumEvents: 16,
      monotonicNow: runtime.monotonicNow,
      permittedTuples: [tupleForRole(9), tupleForRole(11)],
      phaseSequence: () => phaseSequence,
      randomBytes,
      source: projection.bind,
      udx: native
    })
    options.udx = setupAudit.udx
  }
  dht = new HyperDHT(options)
  await dht.ready()
  verifyBound(dht)
}

async function activate() {
  if (state !== 'PREPARED' && state !== 'DHT_SETUP') {
    throw Object.assign(new Error(), { code: 'PROCESS_PHASE_INVALID' })
  }
  if (DHT_ROLES.has(projection.role)) {
    await createDhtOwner()
    state = 'DHT_SETUP'
  } else if (projection.role === 'endpoint') {
    state = 'BOOTSTRAPPING'
    await endpointController.start()
    if (endpointController.snapshot().state !== 'READY') {
      throw Object.assign(new Error(), { code: 'PROCESS_ENDPOINT_NOT_READY' })
    }
    state = 'READY'
    startEndpointMonitor()
  } else {
    if (projection.role !== 'guard') startIncomingExtension()
    state = 'READY'
  }
}

function auditSpec(auditClass, command, target, value) {
  return {
    class: auditClass,
    command,
    destination: tupleForRole(11),
    target,
    valueDigest: value === null ? b4a.alloc(32) : cryptoSuite.hash(value)
  }
}

async function storeImmutable(value) {
  if (projection.role !== 'dht-referral' || state !== 'DHT_SETUP' || dht === null) {
    throw Object.assign(new Error(), { code: 'PROCESS_PHASE_INVALID' })
  }
  const target = cryptoSuite.hash(value)
  try {
    armSetupDhtAudit(setupAudit, auditSpec(AUDIT_CLASSES.SETUP_STORE_TOKEN, 9, target, null))
    const tokenReply = await dht.request(
      { command: 9, target, token: null, value: null },
      tupleForRole(11),
      { retry: false }
    )
    if (!tokenReply || !b4a.isBuffer(tokenReply.token) || tokenReply.token.byteLength !== 32) {
      throw Object.assign(new Error(), { code: 'PROCESS_STORE_TOKEN_INVALID' })
    }

    armSetupDhtAudit(setupAudit, auditSpec(AUDIT_CLASSES.SETUP_STORE_PUT, 8, target, value))
    await dht.request({ command: 8, target, token: tokenReply.token, value }, tupleForRole(11), {
      retry: false
    })

    armSetupDhtAudit(setupAudit, auditSpec(AUDIT_CLASSES.SETUP_STORE_READBACK, 9, target, null))
    const readback = await dht.request(
      { command: 9, target, token: null, value: null },
      tupleForRole(11),
      { retry: false }
    )
    if (
      !readback ||
      !same(readback.value, value) ||
      !same(cryptoSuite.hash(readback.value), target)
    ) {
      throw Object.assign(new Error(), { code: 'PROCESS_STORE_READBACK_INVALID' })
    }
    const events = drainDhtSetupAuditEvents(setupAudit)
    const closes = events.filter((entry) => entry.type === 'audit-close')
    if (closes.length !== 3)
      throw Object.assign(new Error(), { code: 'PROCESS_STORE_AUDIT_INVALID' })
    await emit('stored', {
      setupAuditDigests: closes.map((entry) => entry.recordDigest),
      setupAuditSequences: closes.map((entry) => entry.recordSequence),
      valueDigest: target
    })
  } finally {
    target.fill(0)
  }
}

async function routedImmutableGet(target, sequence) {
  const reply = await endpointController.immutableGet(target)
  if (activeOperation === null || activeOperation.sequence !== sequence) return
  if (!reply || !b4a.isBuffer(reply.value) || !same(cryptoSuite.hash(reply.value), target)) {
    throw Object.assign(new Error(), { code: 'PROCESS_VALUE_INVALID' })
  }
  activeOperation = null
  await emit('value', { target, value: reply.value })
}

function immutableGet(target) {
  if (projection.role !== 'endpoint' || (state !== 'READY' && state !== 'BOOTSTRAPPING')) {
    throw Object.assign(new Error(), { code: 'PROCESS_PHASE_INVALID' })
  }
  if (activeOperation !== null)
    throw Object.assign(new Error(), { code: 'PROCESS_OPERATION_ACTIVE' })
  const sequence = ++operationSequence
  const ownedTarget = b4a.from(target)
  const timer = schedule(() => {
    if (activeOperation === null || activeOperation.sequence !== sequence) return
    activeOperation.timer = null
    void routedImmutableGet(ownedTarget, sequence).catch((err) => fatal(err))
  }, 25)
  activeOperation = { sequence, target: ownedTarget, timer }
  return sequence
}

async function cancelOperation(sequence) {
  if (
    projection.role !== 'endpoint' ||
    activeOperation === null ||
    activeOperation.sequence !== sequence
  ) {
    throw Object.assign(new Error(), { code: 'PROCESS_OPERATION_INVALID' })
  }
  const operation = activeOperation
  activeOperation = null
  if (operation.timer === null) {
    throw Object.assign(new Error(), { code: 'PROCESS_OPERATION_ACTIVE' })
  }
  cancelScheduled(operation.timer)
  operation.target.fill(0)
  await emit('cancelled', { operationSequence: sequence })
}

function storedValues() {
  if (!dht || !dht._persistent || !dht._persistent.immutables) return []
  return Array.from(dht._persistent.immutables.values())
}

function summaryDigest(summary) {
  const encoded = encodeCanonicalBody(summary)
  try {
    return cryptoSuite.hash(encoded)
  } finally {
    encoded.fill(0)
  }
}

function snapshotFields(closed = false) {
  const values = closed ? [] : storedValues()
  const controllerSnapshot =
    closed || endpointController === null ? null : endpointController.snapshot()
  const wireSnapshot = closed || wireService === null ? null : wireService.snapshot()
  const exitSnapshot = closed || finalExitService === null ? null : finalExitService.snapshot()
  const guardOnly =
    controllerSnapshot !== null &&
    controllerSnapshot.endpointAuthority === 'pinned-guard' &&
    controllerSnapshot.packetEdges.length === 1 &&
    controllerSnapshot.packetEdges[0] === 'pinned-guard'
  const summary = {
    activeOperations:
      (activeOperation === null ? 0 : 1) +
      (controllerSnapshot === null ? 0 : controllerSnapshot.activeQueries),
    activeExitOperations: exitSnapshot === null ? 0 : exitSnapshot.activeOperations,
    announceGeneration: controllerSnapshot === null ? null : controllerSnapshot.announceGeneration,
    controllerGeneration: controllerSnapshot === null ? null : controllerSnapshot.generation,
    endpointSockets: controllerSnapshot === null ? 0 : controllerSnapshot.endpointSockets,
    guardOnly,
    lookupGeneration: controllerSnapshot === null ? null : controllerSnapshot.lookupGeneration,
    openLinks: wireSnapshot === null ? 0 : wireSnapshot.openLinks,
    openResources: closed
      ? 0
      : Number(cellEndpoint !== null) +
        Number(dht !== null) +
        (controllerSnapshot === null ? 0 : controllerSnapshot.endpointSockets),
    ordinaryRequestCount: exitSnapshot === null ? 0 : exitSnapshot.ordinaryRequestCount,
    pendingGrantRequests: isolatedGrantPending === null ? 0 : 1,
    pendingLinks: wireSnapshot === null ? 0 : wireSnapshot.pending,
    pendingPackets: exitSnapshot === null ? 0 : exitSnapshot.pendingPackets,
    queuedBytes: cellEndpoint === null ? 0 : cellEndpoint.queuedBytes,
    referralProbeCount: exitSnapshot === null ? 0 : exitSnapshot.referralProbeCount,
    state: closed ? 'CLOSED' : state,
    tableEntryCount: exitSnapshot === null ? 0 : exitSnapshot.tableEntryCount
  }
  const fields = {
    ...summary,
    summaryDigest: summaryDigest(summary)
  }
  if (projection.role === 'dht-value') {
    fields.storedValueCount = values.length
    fields.storedValueDigest = values.length === 1 ? cryptoSuite.hash(values[0]) : b4a.alloc(32)
  } else if (projection.role === 'dht-referral') {
    fields.storedValueCount = 0
    fields.transientValueBytes = 0
  } else if (projection.role === 'dht-seed') {
    fields.storedValueCount = 0
  }
  return fields
}

async function stopOwners() {
  if (incomingRearmHandle !== null) {
    cancelScheduled(incomingRearmHandle)
    incomingRearmHandle = null
  }
  if (endpointMonitorHandle !== null) {
    cancelScheduled(endpointMonitorHandle)
    endpointMonitorHandle = null
  }
  endpointMonitorSnapshot = null
  endpointMonitorBusy = false
  if (activeOperation !== null) {
    const operation = activeOperation
    activeOperation = null
    if (operation.timer !== null) cancelScheduled(operation.timer)
    operation.target.fill(0)
  }
  if (dht !== null) {
    const owner = dht
    dht = null
    await owner.destroy({ force: true }).catch(() => {})
  }
  if (setupAudit !== null) {
    destroyDhtSetupAuditController(setupAudit)
    setupAudit = null
  }
  if (isolatedGrantPending !== null) {
    const pending = isolatedGrantPending
    isolatedGrantPending = null
    pending.digest.fill(0)
    pending.reject(Object.assign(new Error(), { code: 'PROCESS_CANCELLED' }))
  }
  if (finalExitService !== null) {
    const owner = finalExitService
    finalExitService = null
    await owner.destroy().catch(() => {})
  }
  finalExitServicePromise = null
  if (endpointController !== null) {
    const owner = endpointController
    endpointController = null
    await owner.destroy().catch(() => {})
  }
  if (guardProcessService !== null) {
    const owner = guardProcessService
    guardProcessService = null
    await owner.destroy().catch(() => {})
  }
  for (const actor of roleActors) actor.destroy()
  roleActors.clear()
  incomingActor = null
  incomingActorPromise = null
  if (wireService !== null) {
    const owner = wireService
    wireService = null
    await owner.destroy().catch(() => {})
  }
  if (cellEndpoint !== null) {
    const owner = cellEndpoint
    cellEndpoint = null
    await owner.close().catch(() => {})
  }
  if (relayService !== null) {
    relayService.destroy()
    relayService = null
  }
  state = 'CLOSED'
}

async function configure(message) {
  if (state !== 'NEW' || message.type !== 'configure') {
    throw Object.assign(new Error(), { code: 'PROCESS_PHASE_INVALID' })
  }
  const decoded = decodeCanonicalBody(message.projection)
  projection = decoded
  generation = decoded.generation
  phaseSequence = message.phaseSequence
  validateControlMessage(message, {
    direction: 'command',
    generation,
    phaseSequence,
    projection: decoded.plan,
    role: decoded.role,
    roleIndex: decoded.roleIndex,
    run: decoded.run
  })
  if (
    message.runtime !== runtime.runtime ||
    message.runtimeVersion !== runtime.version ||
    !same(message.codecVectorDigest, CODEC_VECTOR_DIGEST) ||
    UDX_VERSION !== '1.20.7' ||
    !same(message.run, decoded.run)
  ) {
    throw Object.assign(new Error(), { code: 'PROCESS_RUNTIME_MISMATCH' })
  }
  state = 'CONFIGURED'
  await emit('configured')
}

function resetEndpointMonitor() {
  if (endpointController !== null) endpointMonitorSnapshot = endpointController.snapshot()
}

function scheduleEndpointMonitor() {
  if (
    stopped ||
    endpointController === null ||
    endpointMonitorHandle !== null ||
    endpointMonitorBusy
  ) {
    return
  }
  endpointMonitorHandle = schedule(() => {
    endpointMonitorHandle = null
    void observeEndpointLifecycle().catch((err) => fatal(err))
  }, 5)
}

function startEndpointMonitor() {
  resetEndpointMonitor()
  scheduleEndpointMonitor()
}

async function observeEndpointLifecycle() {
  if (stopped || endpointController === null || endpointMonitorBusy) return
  endpointMonitorBusy = true
  try {
    const previous = endpointMonitorSnapshot
    const current = endpointController.snapshot()
    endpointMonitorSnapshot = current
    if (
      state === 'READY' &&
      previous !== null &&
      current.state === 'READY' &&
      current.lookupGeneration !== previous.lookupGeneration
    ) {
      const previousGeneration = generation
      generation++
      phaseSequence++
      await emit('rotated', { previousGeneration })
    } else if (state === 'READY' && current.state === 'UNAVAILABLE') {
      phaseSequence++
      state = 'UNAVAILABLE'
      await emit('unavailable', { reason: 'GUARD_LOSS' })
    }
  } finally {
    endpointMonitorBusy = false
    scheduleEndpointMonitor()
  }
}

async function handle(message) {
  if (projection === null) return configure(message)
  if (message.role !== projection.role || message.roleIndex !== projection.roleIndex) {
    throw Object.assign(new Error(), { code: 'PROCESS_ROLE_MISMATCH' })
  }
  if (message.type === 'rotate') {
    validateControlMessage(message, {
      direction: 'command',
      generation,
      phaseSequence: message.phaseSequence,
      projection: projection.plan,
      role: projection.role,
      roleIndex: projection.roleIndex,
      run: projection.run
    })
    phaseSequence = message.phaseSequence
    if (
      projection.role !== 'lookup-middle-a' ||
      incomingActor === null ||
      typeof incomingActor.faultOutgoingPhysicalLink !== 'function' ||
      !incomingActor.faultOutgoingPhysicalLink()
    ) {
      throw Object.assign(new Error(), { code: 'PROCESS_LINK_SESSION_UNAVAILABLE' })
    }
    await emit('ready', { state })
    return
  }
  phaseSequence = message.phaseSequence
  validateControlMessage(message, {
    direction: 'command',
    generation,
    phaseSequence,
    projection: projection.plan,
    role: projection.role,
    roleIndex: projection.roleIndex,
    run: projection.run,
    receiver: message.type === 'isolated-grant'
  })
  if (message.type === 'isolated-grant') {
    if (
      !EXIT_ROLES.has(projection.role) ||
      isolatedGrantPending === null ||
      isolatedGrantPending.requestSequence !== message.requestSequence ||
      !same(isolatedGrantPending.digest, message.tupleDigest)
    ) {
      throw Object.assign(new Error(), { code: 'PROCESS_GRANT_REPLAY' })
    }
    const pending = isolatedGrantPending
    isolatedGrantPending = null
    pending.digest.fill(0)
    pending.resolve(b4a.from(message.grant))
    return
  }
  switch (message.type) {
    case 'prepare':
      await prepare()
      await emit('prepared')
      return
    case 'activate':
      await activate()
      await emit('ready', { state })
      return
    case 'store-immutable':
      await storeImmutable(message.value)
      return
    case 'immutable-get':
      immutableGet(message.target)
      return
    case 'cancel':
      await cancelOperation(message.operationSequence)
      return
    case 'suspend':
      if (projection.role !== 'endpoint')
        throw Object.assign(new Error(), { code: 'PROCESS_ROLE_MISMATCH' })
      state = 'SUSPENDING'
      await endpointController.suspend()
      resetEndpointMonitor()
      state = 'SUSPENDED'
      await emit('suspended')
      return
    case 'resume':
      if (projection.role !== 'endpoint')
        throw Object.assign(new Error(), { code: 'PROCESS_ROLE_MISMATCH' })
      state = 'RESUMING'
      await endpointController.resume()
      resetEndpointMonitor()
      state = 'READY'
      await emit('resumed')
      return
    case 'network-change':
      if (projection.role !== 'endpoint')
        throw Object.assign(new Error(), { code: 'PROCESS_ROLE_MISMATCH' })
      state = 'NETWORK_CHANGING'
      await endpointController.networkChanged()
      resetEndpointMonitor()
      state = 'UNAVAILABLE'
      await emit('unavailable', { reason: 'NETWORK_CHANGE' })
      return
    case 'guard-loss':
      if (
        projection.role !== 'guard' ||
        wireService === null ||
        typeof wireService.faultPhysicalLink !== 'function' ||
        !(await wireService.faultPhysicalLink())
      ) {
        throw Object.assign(new Error(), { code: 'PROCESS_LINK_SESSION_UNAVAILABLE' })
      }
      await emit('ready', { state })
      return
    case 'snapshot':
      await emit('snapshot', snapshotFields())
      return
    case 'stop':
      stopped = true
      await stopOwners()
      await emit('snapshot', snapshotFields(true))
      await emit('closed')
      runtime.exit(0)
      return
    default:
      throw Object.assign(new Error(), { code: 'PROCESS_COMMAND_UNSUPPORTED' })
  }
}

async function fatal(err) {
  if (stopped) return
  stopped = true
  if (projection !== null) {
    try {
      await emit('error', { code: sanitizeCode(err) })
    } catch {}
  }
  await stopOwners().catch(() => {})
  runtime.exit(1)
}

const decoder = new ControlFrameDecoder((message) => {
  commandQueue = commandQueue.then(() => handle(message)).catch((err) => fatal(err))
})

runtime.stdin.on('data', (chunk) => {
  try {
    decoder.push(chunk)
  } catch (err) {
    void fatal(err)
  }
})
runtime.stdin.on('end', () => {
  if (!stopped) void fatal(Object.assign(new Error(), { code: 'PROCESS_STDIN_CLOSED' }))
})
if (typeof runtime.stdin.resume === 'function') runtime.stdin.resume()
