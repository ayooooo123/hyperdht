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
const { PROCESS_PLANS, ROLES } = require('./topology-fixture')
const {
  acceptProjectedExtension,
  activateFinalExitActor,
  blackholeRouteCells,
  createGuardProcessService,
  createProjectedCellEndpoint,
  createProjectedLinkService
} = require('./wire-services')

const UDX_VERSION = require('udx-native/package.json').version
const CODEC_VECTOR_DIGEST = b4a.from(CODEC_VECTOR_DIGEST_HEX, 'hex')
const DHT_ROLES = new Set(['dht-seed', 'dht-referral', 'dht-value'])
const RELAY_ROLES = new Set(['guard', 'lookup-middle-a', 'lookup-middle-b', 'announce-middle'])
const MIDDLE_ROLES = new Set(['lookup-middle-a', 'lookup-middle-b', 'announce-middle'])
const EXIT_ROLES = new Set(['lookup-exit-a', 'lookup-exit-b', 'announce-exit'])
const BLACKHOLE_ROLES = new Set(['lookup-middle-a', 'lookup-middle-b'])

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
let selectedExitRoleIndex = null
let selectedMiddleRoleIndex = null

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

// Exit roles own a second socket for reaching DHT nodes.
const EXIT_ROLE_INDEXES = Object.freeze([4, 6, 8])
const DHT_ROLE_INDEXES_FOR_AUDIT = Object.freeze([9, 10, 11])

function invalidProjection() {
  throw Object.assign(new Error(), { code: 'PROCESS_PROJECTION_INVALID' })
}

function meshTuple(list, offset) {
  const tuple = Array.isArray(list) ? list[offset] : null
  if (
    !tuple ||
    typeof tuple !== 'object' ||
    typeof tuple.host !== 'string' ||
    !Number.isInteger(tuple.port)
  ) {
    invalidProjection()
  }
  return Object.freeze({ host: tuple.host, port: tuple.port })
}

function tupleForRole(roleIndex) {
  if (projection.plan === PROCESS_PLANS.PORTABLE_LOOPBACK.name) {
    return Object.freeze({ host: `127.64.${roleIndex}.1`, port: 42_000 + roleIndex })
  }
  if (projection.plan === PROCESS_PLANS.LINUX_NAMESPACE.name) {
    return Object.freeze({ host: `10.203.${roleIndex}.2`, port: 42_000 + roleIndex })
  }
  // Roles on separate hosts cannot compute each other's addresses: behind a NAT a
  // peer's address is whatever its own reflection reported, so it travels with the
  // projection instead.
  if (projection.plan === PROCESS_PLANS.DHT_MESH.name) {
    if (!projection.meshPeers) invalidProjection()
    return meshTuple(projection.meshPeers.tuples, roleIndex - 1)
  }
  invalidProjection()
}

// An exit reaches DHT nodes from its dedicated DHT-exit socket, so that is the
// tuple a DHT node observes as the source, not the exit's cell endpoint.
function exitDhtTupleForRole(roleIndex) {
  if (projection.plan === PROCESS_PLANS.DHT_MESH.name) {
    if (!projection.meshPeers) invalidProjection()
    const offset = EXIT_ROLE_INDEXES.indexOf(roleIndex)
    if (offset === -1) invalidProjection()
    return meshTuple(projection.meshPeers.exitDht, offset)
  }
  return Object.freeze({ host: tupleForRole(roleIndex).host, port: 43_000 + roleIndex })
}

// An audit record binds the two addresses it describes. Derived plans compute them
// from role indexes; a discovered topology has to state them.
function auditContextFields(roleIndex, destinationRoleIndex) {
  if (projection.plan !== PROCESS_PLANS.DHT_MESH.name) return {}
  const source =
    EXIT_ROLE_INDEXES.includes(roleIndex) &&
    DHT_ROLE_INDEXES_FOR_AUDIT.includes(destinationRoleIndex)
      ? exitDhtTupleForRole(roleIndex)
      : tupleForRole(roleIndex)
  return {
    destinationTuple: tupleForRole(destinationRoleIndex),
    sourceTuple: source
  }
}

function planCapability() {
  if (projection.plan === PROCESS_PLANS.PORTABLE_LOOPBACK.name) {
    return PROCESS_PLANS.PORTABLE_LOOPBACK
  }
  if (projection.plan === PROCESS_PLANS.LINUX_NAMESPACE.name) return PROCESS_PLANS.LINUX_NAMESPACE
  if (projection.plan === PROCESS_PLANS.DHT_MESH.name) return PROCESS_PLANS.DHT_MESH
  invalidProjection()
}

function verifyBound(owner) {
  const address = owner.address()
  if (!address || address.host !== projection.bind.host || address.port !== projection.bind.port) {
    throw Object.assign(new Error(), { code: 'PROCESS_BIND_MISMATCH' })
  }
}

async function createEndpointOwner() {
  // The endpoint's bootstrap socket is a cell endpoint like any other, so on
  // separate hosts it too is bound locally and reached at a translated address.
  // Without the advertised pair its link handles would claim the bound address,
  // which is not the address the guard's capability names.
  const advertised =
    projection.plan === PROCESS_PLANS.DHT_MESH.name ? tupleForRole(projection.roleIndex) : null
  const authority = createEndpointBootstrapAuthority({
    ...(advertised === null
      ? {}
      : { advertisedHost: advertised.host, advertisedPort: advertised.port }),
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

function receiveRoleBootstrap(packet, sourceHandle) {
  if (guardProcessService) return guardProcessService.receiveBootstrap(packet, sourceHandle)
  if (wireService === null) return false
  // A predecessor rebuilding its branch retries `LINK_CREATE`, and this role has no
  // other way to learn that its old circuit is gone: a peer closing a link is silent
  // on the wire. An unmatched bootstrap packet therefore rearms the accept session,
  // and the retry lands on it.
  if (wireService.snapshot().pending === 0) scheduleIncomingRearm()
  return wireService.receiveBootstrap(packet, sourceHandle)
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
  selectedExitRoleIndex = null
  selectedMiddleRoleIndex = null
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
  selectedExitRoleIndex = null
  selectedMiddleRoleIndex = null

  const acceptActor = (accepted, observedPredecessorEndpoint, outgoing) => {
    const actorPromise = acceptProjectedExtension({
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
    })
    return actorPromise.then(
      (actor) => {
        observedPredecessorEndpoint.fill(0)
        incomingActor = actor
        roleActors.add(actor)
        if (outgoing) {
          void actor
            .serve()
            .catch(actorFailure)
            .finally(() => {
              for (const route of outgoing.routes) route.endpoint.fill(0)
            })
        } else {
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
            // Same divergence as the cell endpoint: the socket is bound locally and a DHT
            // node observes it at the published DHT-exit address, which is the address a
            // reply echoes back.
            ...(projection.plan === PROCESS_PLANS.DHT_MESH.name
              ? { advertised: exitDhtTupleForRole(projection.roleIndex) }
              : {}),
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
      },
      (err) => {
        observedPredecessorEndpoint.fill(0)
        throw err
      }
    )
  }

  if (MIDDLE_ROLES.has(projection.role)) {
    const routes = projection.adjacencies.slice(1).map((contact, index) => ({
      endpoint: canonicalTuple(contact.tuple),
      extensionIndex: 2,
      grant: projection.grants[index + 1],
      linkService: wireService,
      peerIdentity: contact.identity,
      roleIndex: ROLES.indexOf(contact.role) + 1
    }))
    const outgoing = {
      allowedRole: ROLE.PRIVATE,
      routes,
      resolve(selection) {
        const route = routes.find(
          (candidate) =>
            same(candidate.peerIdentity, selection.relayIdentity) &&
            same(candidate.endpoint, selection.reachableEndpoint)
        )
        if (route === undefined) throw Object.assign(new Error(), { code: 'ERR_AUTHENTICATION' })
        selectedExitRoleIndex = route.roleIndex
        return route
      }
    }
    incomingActorPromise = acceptActor(
      wireService.prearmAccept(projection.grants[0]),
      canonicalTuple(projection.adjacencies[0].tuple),
      outgoing
    )
  } else if (EXIT_ROLES.has(projection.role)) {
    incomingActorPromise = wireService.prearmAcceptAny(projection.middleGrants).then((accepted) => {
      const contact = projection.middleAdjacencies[accepted.grantIndex]
      if (contact === undefined)
        throw Object.assign(new Error(), { code: 'PROCESS_PROJECTION_INVALID' })
      selectedMiddleRoleIndex = ROLES.indexOf(contact.role) + 1
      return acceptActor(Promise.resolve(accepted.link), canonicalTuple(contact.tuple), null)
    })
  } else {
    return
  }
  void incomingActorPromise.catch(actorFailure)
}

async function createCellOwner() {
  const endpointOptions = {
    host: projection.bind.host,
    // On separate hosts the socket is bound locally and reached at a translated
    // address, which is the one the role's capability names.
    ...(projection.plan === PROCESS_PLANS.DHT_MESH.name
      ? {
          advertisedHost: tupleForRole(projection.roleIndex).host,
          advertisedPort: tupleForRole(projection.roleIndex).port
        }
      : {}),
    onBootstrap: receiveRoleBootstrap,
    onCell: receiveRoleCell,
    onLinkFailure: receiveRoleLinkFailure,
    port: projection.bind.port
  }
  // Only lookup middles pay for the datagram-dropping test adapter. Every other role
  // constructs the production endpoint with an unwrapped UDX socket.
  cellEndpoint = BLACKHOLE_ROLES.has(projection.role)
    ? createProjectedCellEndpoint(endpointOptions)
    : new UdxCellEndpoint(endpointOptions)
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
        ...auditContextFields(10, 11),
        phase: AUDIT_PHASES.DHT_SETUP,
        plan: planCapability(),
        roleIndex: 10
      }),
      destination: tupleForRole(11),
      // Bound locally, observed by the DHT node as the published address.
      ...(projection.plan === PROCESS_PLANS.DHT_MESH.name
        ? { observedSource: tupleForRole(10) }
        : {}),
      emit: setupAuditEmitter,
      onFailure(err) {
        void fatal(err)
      },
      generation,
      key: projection.controlAuditMacKey,
      maximumCorrelations: 64,
      maximumEvents: 16,
      monotonicNow: runtime.monotonicNow,
      // Seed and value are its DHT peers; the three exits reach it from their
      // DHT-exit sockets, which ALLOW_EDGES already permits.
      permittedTuples: [
        tupleForRole(9),
        tupleForRole(11),
        exitDhtTupleForRole(4),
        exitDhtTupleForRole(6),
        exitDhtTupleForRole(8)
      ],
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

// dht.stats.requests is dht-rpc's live io counter (dht-rpc/lib/io.js, the
// `stats.requests` object built in the IO constructor). `responses` increments
// in exactly one place, io.js's RESPONSE_ID branch, and only after a reply
// datagram has matched an inflight request - so it counts requests that were
// ANSWERED. `total` counts requests SENT and `timeouts` counts the ones that
// were not, and neither distinguishes a live peer from a deaf one. Roles that
// own no DHT node report 0, which is the only value the control codec accepts
// from them.
function answeredRequestCount() {
  return dht === null ? 0 : dht.stats.requests.responses
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
    isolatedGrantRequestCount: Number(isolatedGrantRequestSequence),
    pendingGrantRequests: isolatedGrantPending === null ? 0 : 1,
    pendingLinks: wireSnapshot === null ? 0 : wireSnapshot.pending,
    pendingPackets: exitSnapshot === null ? 0 : exitSnapshot.pendingPackets,
    queuedBytes: cellEndpoint === null ? 0 : cellEndpoint.queuedBytes,
    referralProbeCount: exitSnapshot === null ? 0 : exitSnapshot.referralProbeCount,
    selectedExitRoleIndex: closed ? null : selectedExitRoleIndex,
    selectedMiddleRoleIndex: closed ? null : selectedMiddleRoleIndex,
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
      !MIDDLE_ROLES.has(projection.role) ||
      incomingActor === null ||
      typeof incomingActor.faultOutgoingPhysicalLink !== 'function' ||
      !incomingActor.faultOutgoingPhysicalLink()
    ) {
      throw Object.assign(new Error(), { code: 'PROCESS_LINK_SESSION_UNAVAILABLE' })
    }
    await emit('ready', { answeredRequestCount: answeredRequestCount(), state })
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
      await emit('ready', { answeredRequestCount: answeredRequestCount(), state })
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
      await emit('ready', { answeredRequestCount: answeredRequestCount(), state })
      return
    // Silent death: drop both directions while every local object and socket stays live.
    // The native link detector must discover the loss and drive route rotation.
    case 'blackhole':
      if (!BLACKHOLE_ROLES.has(projection.role) || !blackholeRouteCells()) {
        throw Object.assign(new Error(), { code: 'PROCESS_BLACKHOLE_UNAVAILABLE' })
      }
      await emit('ready', { answeredRequestCount: answeredRequestCount(), state })
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

// The control channel only carries a strict code, on purpose: a role must not
// be able to put arbitrary text on it. When PR_ROLE_FATAL_LOG names a file, a
// role additionally appends its stack there, which is how an intermittent
// failure on a machine you cannot attach to gets diagnosed. Off by default, and
// never on the wire.
function traceFatal(err) {
  const target = runtime.fatalLog
  if (!target) return
  try {
    require('fs').appendFileSync(
      target,
      `${projection ? projection.role : 'unknown'} ${sanitizeCode(err)}\n${(err && err.stack) || String(err)}\n\n`
    )
  } catch {}
}

async function fatal(err) {
  if (stopped) return
  stopped = true
  traceFatal(err)
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
