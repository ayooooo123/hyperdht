'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { PrivateRouteError } = require('../../lib/private/errors')
const {
  LINK_OPERATION,
  PROTOCOL_VERSION,
  ROLE,
  TOPOLOGY_ROLE,
  roleForIdentity
} = require('../../lib/private/protocol')
const {
  assembleTopologyGrantV1,
  decodeUnsignedTopologyGrantV1,
  encodeUnsignedTopologyGrantV1,
  signTopologyGrantV1
} = require('../../lib/private/topology-grant')
const { createPeerRelayOwner, destroyPeerRelayOwner } = require('../../lib/private/peer-capability')
const {
  createPeerBootstrapResponder,
  destroyPeerBootstrapResponder
} = require('../../lib/private/peer-direct-bootstrap')
const {
  UdxCellEndpoint,
  registerPeerDirectResponder,
  destroyPeerDirectResponderRegistration
} = require('../../lib/private/udx-cell-endpoint')
const { selectUdxLoopbackHosts } = require('../../lib/private/udx-adapter')
const {
  addPeerNeighborGrant,
  createPeerNeighborAdmission,
  destroyPeerNeighborAdmission,
  readPeerNeighborAdmission,
  settlePeerNeighborAdmission
} = require('../../lib/private/peer-neighbor-admission')
const { createCoherentTestClock } = require('./coherent-clock')
const NativeUDX = require('udx-native')
const { unwrapDirectRpcPacket } = require('../../lib/private/peer-direct-bootstrap')
const { PEER_MESSAGE_ID } = require('../../lib/private/peer-protocol')

// Direct discovery replies are charged to the responder's fixed startup pool
// (packet §3.2), not to its node service ledger.
const RESPONDER_REPLIES = new Set([
  PEER_MESSAGE_ID.PEER_CAPS_COOKIE_CHALLENGE_V2,
  PEER_MESSAGE_ID.PEER_CAPS_RESPONSE_V2,
  PEER_MESSAGE_ID.PEER_ACTIVE_CHALLENGE_RESPONSE_V2
])

function isResponderReply(packet) {
  try {
    return RESPONDER_REPLIES.has(unwrapDirectRpcPacket(b4a.from(packet)).messageId)
  } catch {
    return false
  }
}

// Counts every datagram each native socket hands to UDX, by local port.
async function countNativeSends(t, setup) {
  const counts = new Map()
  const createSocket = NativeUDX.prototype.createSocket
  NativeUDX.prototype.createSocket = function (options) {
    const socket = createSocket.call(this, options)
    for (const name of ['send', 'trySend']) {
      const original = socket[name]
      socket[name] = function (packet, ...rest) {
        const port = socket.address().port
        const entry = counts.get(port) || { service: 0, responder: 0 }
        if (isResponderReply(packet)) entry.responder++
        else entry.service++
        counts.set(port, entry)
        return original.call(this, packet, ...rest)
      }
    }
    return socket
  }
  try {
    return { counts, value: await setup() }
  } finally {
    NativeUDX.prototype.createSocket = createSocket
  }
}

const EPOCH = 7n
const RUN_ID = b4a.alloc(32, 0x5a)
const SERVICE = {
  maxNeighbors: 4,
  nodeServiceBudget: { cells: 300, bytes: 360_000n, commands: 300 },
  neighborServiceReservation: { cells: 60, bytes: 72_000n, commands: 60 }
}

function safetyIdentity(start) {
  for (let value = start; value < 256; value++) {
    const pair = cryptoSuite.keyPair(b4a.alloc(32, value))
    if (roleForIdentity(pair.publicKey) === ROLE.SAFETY) return pair
  }
  throw new Error('missing safety identity')
}

function clocks() {
  const clock = createCoherentTestClock()
  return {
    clockIdentity: clock,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    setTimer: (callback, ms) => setTimeout(callback, ms),
    clearTimer: (timer) => clearTimeout(timer)
  }
}

async function createRelay(t, { host, port, identity, authority, capabilityMask = 9 }) {
  const endpoint = new UdxCellEndpoint({
    host,
    port,
    advertisedHost: host,
    advertisedPort: port,
    onBootstrap() {},
    onCell() {
      return true
    },
    onLinkFailure() {}
  })
  await endpoint.bind()
  const route = cryptoSuite.encryptionKeyPair()
  const clock = clocks()
  const now = BigInt(Date.now())
  const relayOwner = createPeerRelayOwner({
    endpoint,
    identityKeyPair: identity,
    routeKeyPair: route,
    advertisementFields: {
      relayIdentity32: identity.publicKey,
      currentDhtNodeId32: cryptoSuite.randomBytes(32),
      reachableEndpoint: { host, port },
      routeEncryptionPublicKey32: route.publicKey,
      capabilityMask,
      minimumVersion: 2,
      maximumVersion: 2,
      datagramReplayWindow: 64,
      maxConcurrentCircuits: 128,
      capacityClass: 1,
      maxCells: 10000,
      maxBytes: 1000000,
      maxCommands: 1000,
      idleTimeoutMs: 30000,
      maxQueuedBytes: 524288,
      epoch: EPOCH,
      issuedAt: now,
      expiresAt: now + 600_000n,
      policyCount: 0
    },
    ...clock
  })
  const responder = createPeerBootstrapResponder(relayOwner)
  const registration = registerPeerDirectResponder(endpoint, responder)
  const relay = { host, port, identity, route, authority, endpoint, relayOwner, admission: null }
  t.teardown(async () => {
    if (relay.admission) await destroyPeerNeighborAdmission(relay.admission)
    destroyPeerDirectResponderRegistration(registration)
    destroyPeerBootstrapResponder(responder)
    destroyPeerRelayOwner(relayOwner)
    await endpoint.close()
  })
  return relay
}

function twoAuthorityGrant(dialer, acceptor, overrides = {}) {
  const now = BigInt(Date.now())
  const unsigned = encodeUnsignedTopologyGrantV1({
    version: PROTOCOL_VERSION,
    format: 1,
    grantId32: cryptoSuite.randomBytes(32),
    endpointA: {
      identity32: dialer.identity.publicKey,
      role: TOPOLOGY_ROLE.SAFETY_GUARD,
      host: dialer.host,
      port: dialer.port,
      operations: LINK_OPERATION.INITIATE,
      authority32: dialer.authority.publicKey
    },
    endpointB: {
      identity32: acceptor.identity.publicKey,
      role: TOPOLOGY_ROLE.SAFETY_FINAL,
      host: acceptor.host,
      port: acceptor.port,
      operations: LINK_OPERATION.ACCEPT,
      authority32: acceptor.authority.publicKey
    },
    epoch: EPOCH,
    notBefore: now - 1000n,
    expiresAt: now + 300_000n,
    runId32: RUN_ID,
    ...overrides
  })
  const decoded = decodeUnsignedTopologyGrantV1(unsigned)
  const signer = (key) =>
    b4a.equals(key, dialer.authority.publicKey) ? dialer.authority : acceptor.authority
  return assembleTopologyGrantV1(
    unsigned,
    signTopologyGrantV1(unsigned, signer(decoded.endpointA.authority32)),
    signTopologyGrantV1(unsigned, signer(decoded.endpointB.authority32))
  )
}

function admit(relay, grant, overrides = {}) {
  relay.admission = createPeerNeighborAdmission({
    relayOwner: relay.relayOwner,
    endpoint: relay.endpoint,
    identityKeyPair: relay.identity,
    routeKeyPair: relay.route,
    authorityPublicKeys: [relay.authority.publicKey],
    epoch: EPOCH,
    runId32: RUN_ID,
    grants: [grant],
    ...SERVICE,
    ...overrides
  })
  return relay.admission
}

function expectCode(t, fn, code) {
  let error = null
  try {
    fn()
  } catch (err) {
    error = err
  }
  t.ok(error instanceof PrivateRouteError, `throws ${code}`)
  if (error) t.is(error.code, code)
}

async function twoRelays(t) {
  const [hostA, hostB] = selectUdxLoopbackHosts({
    platform: global.Bare ? global.Bare.platform : process.platform
  })
  const guard = await createRelay(t, {
    host: hostA,
    port: 48701,
    identity: safetyIdentity(20),
    authority: cryptoSuite.keyPair()
  })
  const safety = await createRelay(t, {
    host: hostB,
    port: 48702,
    identity: safetyIdentity(60),
    authority: cryptoSuite.keyPair()
  })
  return { guard, safety }
}

test('two relays admit one two-authority grant and publish the native neighbor', async (t) => {
  const { guard, safety } = await twoRelays(t)
  const grant = twoAuthorityGrant(guard, safety)
  const guardAdmission = admit(guard, grant)
  const safetyAdmission = admit(safety, grant)

  await Promise.all([
    settlePeerNeighborAdmission(guardAdmission),
    settlePeerNeighborAdmission(safetyAdmission)
  ])

  const guardView = readPeerNeighborAdmission(guardAdmission)
  const safetyView = readPeerNeighborAdmission(safetyAdmission)
  t.is(guardView.neighbors[0].state, 'live', `guard live (${guardView.neighbors[0].lastError})`)
  t.is(safetyView.neighbors[0].state, 'live', `safety live (${safetyView.neighbors[0].lastError})`)
  t.is(guardView.neighbors[0].dialer, true)
  t.is(safetyView.neighbors[0].dialer, false)
  t.alike(guardView.neighbors[0].peerIdentity32, safety.identity.publicKey)
  t.is(guardView.diagnostics.neighborCount, 1)
  t.is(safetyView.diagnostics.neighborCount, 1)
  t.ok(
    guardView.diagnostics.nodeServiceLedger.cellsSpent > 0,
    'advertisement fetch and link setup are charged to the node service ledger'
  )
})

test('every neighbor service send is charged to the node service ledger first', async (t) => {
  const { counts, value } = await countNativeSends(t, () => twoRelays(t))
  const { guard, safety } = value
  const grant = twoAuthorityGrant(guard, safety)
  admit(guard, grant)
  admit(safety, grant)
  await Promise.all([
    settlePeerNeighborAdmission(guard.admission),
    settlePeerNeighborAdmission(safety.admission)
  ])
  // Let link keepalives run so steady-state service traffic is included.
  await new Promise((resolve) => setTimeout(resolve, 1200))
  for (const relay of [guard, safety]) {
    const ledger = readPeerNeighborAdmission(relay.admission).diagnostics.nodeServiceLedger
    const sent = counts.get(relay.port)
    t.is(
      sent.service,
      ledger.cellsSpent,
      `port ${relay.port}: discovery requests, link setup and keepalives each spent one cell`
    )
    t.ok(sent.responder > 0, 'discovery replies were sent from the separate responder pool')
  }
})

test('a relay cannot be provisioned by a grant its own authority did not sign', async (t) => {
  const { guard, safety } = await twoRelays(t)
  const grant = twoAuthorityGrant(guard, safety)
  // The guard trusts only the safety operator's key: both signatures are
  // valid, but nothing configured on the guard admits the guard's side.
  expectCode(
    t,
    () => admit(guard, grant, { authorityPublicKeys: [safety.authority.publicKey] }),
    'UNAUTHORIZED'
  )
})

test('every grant on an endpoint must carry the node epoch and run ID', async (t) => {
  const { guard, safety } = await twoRelays(t)
  const otherRun = twoAuthorityGrant(guard, safety, { runId32: b4a.alloc(32, 0x5b) })
  expectCode(t, () => admit(guard, otherRun), 'UNAUTHORIZED')
  const otherEpoch = twoAuthorityGrant(guard, safety, { epoch: EPOCH + 1n })
  expectCode(t, () => admit(guard, otherEpoch), 'UNAUTHORIZED')
})

async function waitFor(predicate, timeoutMs) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (predicate()) return true
    await new Promise((resolve) => setTimeout(resolve, 50))
  }
  return predicate()
}

function slotOf(relay) {
  return readPeerNeighborAdmission(relay.admission).neighbors[0]
}

test('neighbors reconnect under a replacement grant when the first grant expires', async (t) => {
  const { guard, safety } = await twoRelays(t)
  const shortLived = twoAuthorityGrant(guard, safety, { expiresAt: BigInt(Date.now()) + 2500n })
  admit(guard, shortLived)
  admit(safety, shortLived)
  await Promise.all([
    settlePeerNeighborAdmission(guard.admission),
    settlePeerNeighborAdmission(safety.admission)
  ])
  t.is(slotOf(guard).state, 'live')
  t.is(slotOf(safety).state, 'live')

  const renewed = twoAuthorityGrant(guard, safety)
  addPeerNeighborGrant(guard.admission, renewed)
  addPeerNeighborGrant(safety.admission, renewed)
  t.is(slotOf(guard).nextGrant, true, 'the live neighbor keeps its grant until it ends')

  t.ok(
    await waitFor(() => slotOf(guard).state === 'reconnecting', 5000),
    'grant expiry ends the neighbor'
  )
  const reconnected = await waitFor(
    () => slotOf(guard).state === 'live' && slotOf(safety).state === 'live',
    15000
  )
  t.ok(
    reconnected,
    `both sides live again (${slotOf(guard).lastError}/${slotOf(safety).lastError})`
  )
  t.is(slotOf(guard).nextGrant, false, 'the replacement grant is now current')
  t.is(readPeerNeighborAdmission(guard.admission).diagnostics.neighborCount, 1)
  t.is(readPeerNeighborAdmission(safety.admission).diagnostics.neighborCount, 1)
})

test('a neighbor whose grant expires with no replacement ends expired', async (t) => {
  const { guard, safety } = await twoRelays(t)
  const shortLived = twoAuthorityGrant(guard, safety, { expiresAt: BigInt(Date.now()) + 2000n })
  admit(guard, shortLived)
  admit(safety, shortLived)
  await Promise.all([
    settlePeerNeighborAdmission(guard.admission),
    settlePeerNeighborAdmission(safety.admission)
  ])
  t.is(slotOf(guard).state, 'live')
  t.ok(
    await waitFor(
      () => slotOf(guard).state === 'expired' && slotOf(safety).state === 'expired',
      8000
    ),
    'both sides stop instead of redialing on an expired grant'
  )
  t.is(readPeerNeighborAdmission(guard.admission).diagnostics.neighborCount, 0)
  t.is(readPeerNeighborAdmission(safety.admission).diagnostics.neighborCount, 0)
})

test('a dialer reconnects after its neighbor restarts', async (t) => {
  const { guard, safety } = await twoRelays(t)
  const grant = twoAuthorityGrant(guard, safety)
  admit(guard, grant)
  admit(safety, grant)
  await Promise.all([
    settlePeerNeighborAdmission(guard.admission),
    settlePeerNeighborAdmission(safety.admission)
  ])
  t.is(slotOf(guard).state, 'live')

  await destroyPeerNeighborAdmission(safety.admission)
  safety.admission = null
  t.ok(
    await waitFor(() => slotOf(guard).state !== 'live', 10000),
    `the dialer observes the lost neighbor (${slotOf(guard).lastError})`
  )
  admit(safety, grant)
  const reconnected = await waitFor(
    () => slotOf(guard).state === 'live' && slotOf(safety).state === 'live',
    20000
  )
  t.ok(reconnected, `both sides live again (${slotOf(guard).state}/${slotOf(safety).state})`)
})

test('destroy ends an admission whose peer never answers', async (t) => {
  const { guard, safety } = await twoRelays(t)
  const grant = twoAuthorityGrant(guard, safety)
  const admission = admit(guard, grant)
  // The safety relay answers discovery but never arms an accept, so the
  // guard's dial cannot complete.
  const started = Date.now()
  await new Promise((resolve) => setTimeout(resolve, 100))
  t.is(await destroyPeerNeighborAdmission(admission), true)
  guard.admission = null
  t.ok(Date.now() - started < 5000, 'destroy does not wait for the fetch deadline')
  t.is(readPeerNeighborAdmissionSafe(admission), null)
  void safety
})

function readPeerNeighborAdmissionSafe(owner) {
  try {
    return readPeerNeighborAdmission(owner)
  } catch {
    return null
  }
}
