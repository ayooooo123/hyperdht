'use strict'

const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-universal')

const { BOOTSTRAP_SIZE, BootstrapEnvelopeCodec } = require('../../lib/private/bootstrap-envelope')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { createLinkSetupAuthority } = require('../../lib/private/link-setup')
const {
  CAPACITY_CLASS,
  decodeM3Object,
  LINK_OPERATION,
  PROTOCOL_VERSION,
  ROLE,
  TOPOLOGY_ROLE,
  roleForIdentity
} = require('../../lib/private/protocol')
const {
  deriveM3DhtNodeId,
  digestRelayCapabilityAdvertisement,
  encodeCanonicalEndpoint,
  encodeRelayCapabilityAdvertisement,
  providerServicePolicyForCapabilities,
  signRelayCapabilityAdvertisement
} = require('../../lib/private/relay-capability')
const { CapsResponder } = require('../../lib/private/caps-responder')
const { LinkDirectory, signTopologyGrant } = require('../../lib/private/topology-grant')
const endpointModule = require('../../lib/private/udx-cell-endpoint')
const {
  TEST_ONLY_UDX_ADAPTER_ISSUER,
  UdxCellEndpoint,
  registerSharedGuardBranchResponder,
  admitBootstrapUdxGuard,
  bindBootstrapUdxOperation,
  createBootstrapUdxAuthority,
  createLocalIdentitySecretCapability,
  createBootstrapUdxGuardSessionOptions,
  isGuardLeaseMaterial,
  openBootstrapUdxGuard,
  pinBootstrapUdxGuard,
  registerPeerDirectResponder,
  destroyPeerDirectResponderRegistration,
  takePeerDirectRequesterTransport,
  destroyPeerDirectRequesterTransport
} = endpointModule
const { revokeGuardReconnectAuthority } = require('../../lib/private/guard-reconnect-authority')
const {
  createGuardLease,
  createGuardBranchOpenAuthority,
  destroyGuardLease,
  isGuardLease,
  readGuardLeaseScope,
  issueGuardLeaseM3CellLinkTransferIssuer,
  openGuardBranch,
  suspendGuardLease,
  createPeerGuardPhysicalReservation,
  exchangePeerGuardLink,
  destroyPeerGuardPhysicalReservation,
  createPeerGuardBootstrapTransport,
  MAX_GUARD_LEASE_BRANCH_SLOTS
} = require('../../lib/private/guard-lease')
const {
  createPeerBootstrapResponder,
  destroyPeerBootstrapResponder,
  discoverPeerCandidate,
  takePeerActiveCandidate,
  destroyPeerActiveCandidate
} = require('../../lib/private/peer-direct-bootstrap')
const {
  createPeerRelayOwner,
  destroyPeerRelayOwner,
  readPeerRelayOwner
} = require('../../lib/private/peer-capability')
const { createPeerLedger, readPeerLedger } = require('../../lib/private/peer-ledger')
const { PEER_MESSAGE_ID } = require('../../lib/private/peer-protocol')
const { encodePeerTransport } = require('../../lib/private/peer-transport-wire')
const { createM3CellLinkTransferIssuer, registerM3CellLinkTransfer } = endpointModule
const guardLink = require('../../lib/private/guard-link')
const { createIndexZeroGuardLinkResponder } = guardLink
const { destroyTailControlSession } = require('../../lib/private/tail-control')
const {
  openPeerGuardLink,
  createPeerLinkResponder,
  destroyPeerLinkResponder
} = require('../../lib/private/peer-guard-link')
const {
  createPeerM3AdjacencyAuthority,
  adoptPeerEstablishedLink,
  sendPeerM3Payload,
  receivePeerM3Payload,
  beginPeerM3BranchTeardown
} = require('../../lib/private/peer-m3-adjacency-runtime')
const {
  fakeClock,
  sequence,
  nativeGuardAdvertisement,
  pinnedMaterialFixture,
  leaseOptions,
  closeFixture,
  peerBranchLedgers,
  peerGuardFixture
} = require('./peer-native-fixture')
const TEST_ONLY_M3_ESTABLISHED_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-m3-established-issuer'
)

const seed = (value) => b4a.alloc(32, value)

function safetyIdentity(start = 100) {
  for (let value = start; value < 256; value++) {
    const pair = cryptoSuite.keyPair(seed(value))
    if (roleForIdentity(pair.publicKey) === ROLE.SAFETY) return pair
  }
  throw new Error('missing safety identity')
}

async function settles() {
  await Promise.resolve()
  await Promise.resolve()
}

test('A0 rejects a candidate from another grant without consuming the original authority', async (t) => {
  const clock = fakeClock()
  const original = await peerGuardFixture(t, 47601, 47602, { clock })
  const other = await peerGuardFixture(t, 47601, 47602, { clock, grantId32: seed(95) })
  const candidate = await original.discover()
  const rejectedLedgers = peerBranchLedgers()
  let error = null
  try {
    await other.open(candidate, rejectedLedgers)
  } catch (err) {
    error = err
  }
  t.is(
    error && error.code,
    'INVALID_ROUTE',
    'same identity, endpoint, epoch and clock cannot substitute a different grant'
  )
  t.is(
    readPeerLedger(rejectedLedgers.sendLedger).cellsSpent,
    0,
    'cross-grant rejection publishes no OFFER'
  )
  t.is(
    readPeerLedger(rejectedLedgers.sendLedger).cellsReserved,
    0,
    'rejected admission releases its reservation'
  )
  const runtime = adoptPeerEstablishedLink(original.localAuthority, await original.open(candidate))
  const payload = b4a.alloc(1100, 0x81)
  const received = receivePeerM3Payload(original.guardRuntime)
  await sendPeerM3Payload(runtime, payload)
  t.alike(
    await received,
    payload,
    'original candidate remains consumable under its exact pinned grant'
  )
  t.is(await beginPeerM3BranchTeardown(runtime, b4a.alloc(16, 0x82)), true)
})

test('A0 retires pending admission at the candidate original deadline, not a fresh OFFER deadline', async (t) => {
  const setup = await peerGuardFixture(t, 47611, 47612)
  const candidate = await setup.discover()
  setup.clock.advance(4800)
  const socket = setup.fixture.rightObserver.socket
  const send = socket.send
  const held = []
  socket.send = function (packet, port, host) {
    held.push({ packet: b4a.from(packet), port, host })
    return true
  }
  const localLedgers = peerBranchLedgers()
  const opening = Promise.resolve(setup.open(candidate, localLedgers)).then(
    (handle) => ({ handle }),
    (error) => ({ error })
  )
  await new Promise(setImmediate)
  t.is(held.length, 1, 'genuine signed ACCEPT is delayed at the native wire boundary')
  setup.clock.advance(201)
  const outcome = await Promise.race([
    opening,
    new Promise((resolve) => setTimeout(() => resolve({ stalled: true }), 100))
  ])
  t.ok(
    outcome.error instanceof require('../../lib/private/errors').PrivateRouteError,
    'pending A0 rejects at D0 expiry while its requested deadline is still in the future'
  )
  socket.send = send
  for (const item of held) send.call(socket, item.packet, item.port, item.host)
  await new Promise(setImmediate)
  setup.clock.advance(2000)
  await new Promise(setImmediate)
  t.is(
    readPeerLedger(localLedgers.sendLedger).cellsSpent,
    1,
    'expired candidate cannot authorize another OFFER retry'
  )
  t.is(
    readPeerLedger(localLedgers.sendLedger).cellsReserved,
    0,
    'failed admission releases its ordinary child'
  )
  const fresh = await setup.discover()
  const runtime = adoptPeerEstablishedLink(setup.localAuthority, await setup.open(fresh))
  const payload = b4a.alloc(1100, 0x83)
  const received = receivePeerM3Payload(runtime)
  await sendPeerM3Payload(setup.guardRuntime, payload)
  t.alike(await received, payload, 'fresh discovery still admits on the same pinned physical guard')
  t.is(await beginPeerM3BranchTeardown(runtime, b4a.alloc(16, 0x84)), true)
})

test('A0 native established lifetime survives the consumed candidate setup deadline', async (t) => {
  const setup = await peerGuardFixture(t, 47621, 47622, { native: true })
  const candidate = await setup.discover()
  setup.clock.advance(4800)
  const runtime = adoptPeerEstablishedLink(setup.localAuthority, await setup.open(candidate))
  setup.clock.advance(250)
  const payload = b4a.alloc(1100, 0x85)
  const forward = receivePeerM3Payload(setup.guardRuntime)
  await sendPeerM3Payload(runtime, payload)
  t.alike(await forward, payload)
  const reverse = receivePeerM3Payload(runtime)
  await sendPeerM3Payload(setup.guardRuntime, payload)
  t.alike(
    await reverse,
    payload,
    'candidate expiry constrains setup, not the established negotiated lifetime'
  )
  t.is(await beginPeerM3BranchTeardown(runtime, b4a.alloc(16, 0x86)), true)
})

test('A0 reserves exact directional children, rolls back failed admission and preserves its sibling', async (t) => {
  const setup = await peerGuardFixture(t, 47631, 47632, { native: true })
  const parents = peerBranchLedgers(3)
  const first = adoptPeerEstablishedLink(
    setup.localAuthority,
    await setup.open(await setup.discover(), {
      ...parents,
      forwardLimits: { ...setup.limits, idleTimeoutMs: 31000 }
    })
  )
  const firstPeer = setup.guardRuntime
  t.is(
    readPeerLedger(parents.sendLedger).cellsReserved,
    19,
    'A0 reserves twenty ordinary cells and spends its first OFFER'
  )
  t.is(
    readPeerLedger(parents.teardownSendLedger).cellsReserved,
    10,
    'closure owns a disjoint exact child'
  )
  const before = Object.values(parents).map(readPeerLedger)
  const peerBefore = Object.values(setup.peerLedgers).map(readPeerLedger)
  for (const override of [
    { reverseLimits: { ...setup.limits, idleTimeoutMs: 31000 } },
    { forwardLimits: { ...setup.limits, expiresAt: 60001n } }
  ]) {
    let error = null
    try {
      await setup.open(await setup.discover(), override)
    } catch (err) {
      error = err
    }
    t.is(
      error && error.code,
      'UNAUTHORIZED',
      'reverse advertisement and forward parent bounds are enforced'
    )
  }
  const insufficient = {
    ...peerBranchLedgers(),
    receiveLedger: createPeerLedger({ cells: 19, bytes: 22800n, commands: 20 })
  }
  const rollback = Object.values(insufficient).map(readPeerLedger)
  let error = null
  try {
    await setup.open(await setup.discover(), insufficient)
  } catch (err) {
    error = err
  }
  t.is(error && error.code, 'INVALID_ROUTE')
  t.alike(
    Object.values(insufficient).map(readPeerLedger),
    rollback,
    'partial receive failure returns the earlier send reservation'
  )
  t.alike(Object.values(parents).map(readPeerLedger), before)
  t.alike(
    Object.values(setup.peerLedgers).map(readPeerLedger),
    peerBefore,
    'rejected A0 admissions send no OFFER or allocate responder commands'
  )
  const second = adoptPeerEstablishedLink(
    setup.localAuthority,
    await setup.open(await setup.discover(), parents)
  )
  const secondPeer = setup.guardRuntime
  const payload = b4a.alloc(1100, 0x87)
  let delivered = true
  for (let attempt = 0; attempt < 19; attempt++) {
    const received = receivePeerM3Payload(firstPeer)
    await sendPeerM3Payload(first, payload)
    delivered &&= b4a.equals(await received, payload)
  }
  t.is(
    delivered,
    true,
    'the admitted forward profile is usable despite exceeding the source advertisement idle maximum'
  )
  error = null
  try {
    await sendPeerM3Payload(first, payload)
  } catch (err) {
    error = err
  }
  t.is(
    error && error.code,
    'ROUTE_UNAVAILABLE',
    'the first A0 cannot borrow spare parent or sibling capacity'
  )
  t.is(await beginPeerM3BranchTeardown(first, b4a.alloc(16, 0x88)), true)
  const forward = receivePeerM3Payload(secondPeer)
  await sendPeerM3Payload(second, payload)
  t.alike(await forward, payload, 'first-branch release preserves the sibling forward partition')
  const reverse = receivePeerM3Payload(second)
  await sendPeerM3Payload(secondPeer, payload)
  t.alike(await reverse, payload)
  t.is(await beginPeerM3BranchTeardown(second, b4a.alloc(16, 0x89)), true)
  t.is(
    Object.values(parents).every((ledger) => readPeerLedger(ledger).cellsReserved === 0),
    true
  )
})

test('GuardLease consumes the opaque BootstrapIO pinned guard transfer shape', async (t) => {
  const fixture = await pinnedMaterialFixture(47225, 47226)
  const canonicalEndpoint = encodeCanonicalEndpoint({
    addressFamily: 4,
    addressBytes: b4a.from([127, 0, 0, 2]),
    port: fixture.rightPort
  })
  const lease = createGuardLease(
    leaseOptions(fixture, {
      pinnedGuard: {
        identity: fixture.links.b.publicKey,
        canonicalEndpoint,
        advertisement: b4a.alloc(256, 0x41),
        advertisementDigest: b4a.alloc(32, 0x42),
        epoch: 1n,
        expiresAt: 60_000n
      }
    })
  )

  t.is(isGuardLease(lease), true)
  t.alike(readGuardLeaseScope(lease).endpointBytes, canonicalEndpoint)
  t.is(destroyGuardLease(lease), true)
  await closeFixture(fixture)
})

test('GuardLease consumes pinned material and owns one physical close', async (t) => {
  const fixture = await pinnedMaterialFixture(47201, 47202)
  const socket = fixture.leftObserver.sockets[0]
  const lease = createGuardLease(leaseOptions(fixture))

  t.is(isGuardLease(lease), true)
  t.is(isGuardLeaseMaterial(fixture.material), false)
  t.is(socket.closed, false)

  let reuse = null
  try {
    createGuardLease(leaseOptions(fixture))
  } catch (err) {
    reuse = err
  }
  t.is(reuse && reuse.code, 'UNAUTHORIZED')

  t.is(destroyGuardLease(lease), true)
  await settles()
  t.is(socket.closed, true)
  t.is(socket.closeCalls, 1)
  t.is(destroyGuardLease(lease), false)
  await settles()
  t.is(socket.closeCalls, 1)

  await closeFixture(fixture)
})

test('GuardLease pinning rejects a preexisting generic M3 transfer owner', async (t) => {
  const fixture = await pinnedMaterialFixture(47209, 47210, { pin: false })
  const issuer = createM3CellLinkTransferIssuer(fixture.left, fixture.established)
  let error = null
  try {
    pinBootstrapUdxGuard(fixture.authority, fixture.admission, fixture.established)
  } catch (err) {
    error = err
  }
  t.is(error && error.code, 'UNAUTHORIZED')
  t.is(issuer.destroy(), true)
  await fixture.left.close()
  await closeFixture(fixture)
})

test('GuardLease rejects pinned guard identity and endpoint substitution', async (t) => {
  const identityMismatch = await pinnedMaterialFixture(47203, 47204)
  let identityError = null
  try {
    createGuardLease(
      leaseOptions(identityMismatch, {
        pinnedGuard: { identity32: seed(1), endpoint: { host: '127.0.0.2', port: 47204 } }
      })
    )
  } catch (err) {
    identityError = err
  }
  t.is(identityError && identityError.code, 'UNAUTHORIZED')
  await settles()
  await closeFixture(identityMismatch)

  const endpointMismatch = await pinnedMaterialFixture(47205, 47206)
  let endpointError = null
  try {
    createGuardLease(
      leaseOptions(endpointMismatch, {
        pinnedGuard: {
          identity32: endpointMismatch.links.b.publicKey,
          endpoint: { host: '127.0.0.9', port: 47206 }
        }
      })
    )
  } catch (err) {
    endpointError = err
  }
  t.is(endpointError && endpointError.code, 'UNAUTHORIZED')
  await settles()
  await closeFixture(endpointMismatch)
})

test('GuardLease rejects partial reconnect metadata at pin time', async (t) => {
  const fixture = await pinnedMaterialFixture(47211, 47212)
  let error = null
  try {
    createGuardLease(
      leaseOptions(fixture, {
        pinnedGuard: {
          identity32: fixture.links.b.publicKey,
          endpoint: { host: '127.0.0.2', port: fixture.rightPort },
          advertisement: seed(0x21)
        }
      })
    )
  } catch (err) {
    error = err
  }

  t.is(error && error.code, 'INVALID_ROUTE')

  const malformed = await pinnedMaterialFixture(47213, 47214)
  let malformedError = null
  try {
    createGuardLease(
      leaseOptions(malformed, {
        pinnedGuard: {
          identity32: malformed.links.b.publicKey,
          endpoint: { host: '127.0.0.2', port: malformed.rightPort },
          advertisement: seed(0x31),
          advertisementDigest: seed(0x32),
          canonicalEndpointBytes: b4a.alloc(19, 0x33),
          epoch: 0n,
          expiresAt: 1
        }
      })
    )
  } catch (err) {
    malformedError = err
  }

  t.is(malformedError && malformedError.code, 'INVALID_ROUTE')
  await settles()
  await closeFixture(malformed)
  await settles()
  await closeFixture(fixture)
})

function branchBinding(issuer) {
  return guardLink[TEST_ONLY_M3_ESTABLISHED_ISSUER].issueAuthenticatedBranchBinding(
    {
      localId: b4a.alloc(16, 0x41),
      peerLocalId: b4a.alloc(16, 0x42),
      generation: 1n,
      initiator: true
    },
    issuer
  )
}

test('GuardLease bounds shared guard branch issuers and releases logical slots', async (t) => {
  const fixture = await pinnedMaterialFixture(47207, 47208)
  const lease = createGuardLease(leaseOptions(fixture))
  const issuers = []

  for (let i = 0; i < MAX_GUARD_LEASE_BRANCH_SLOTS; i++) {
    issuers.push(issueGuardLeaseM3CellLinkTransferIssuer(lease))
  }

  let quota = null
  try {
    issueGuardLeaseM3CellLinkTransferIssuer(lease)
  } catch (err) {
    quota = err
  }
  t.is(quota && quota.code, 'ERR_QUOTA_EXCEEDED')

  const transfer = registerM3CellLinkTransfer(issuers[0], branchBinding(issuers[0]))
  t.is(issuers[0].destroy(), false)
  t.is(transfer.destroy(), true)
  t.is(fixture.leftObserver.sockets[0].closed, false)
  const replacement = issueGuardLeaseM3CellLinkTransferIssuer(lease)
  t.is(typeof replacement.destroy, 'function')

  t.is(destroyGuardLease(lease), true)
  for (const issuer of issuers.slice(1)) t.is(issuer.destroy(), false)
  t.is(replacement.destroy(), false)

  await closeFixture(fixture)
})

test('native guard reconnect returns a fresh opaque pinned transfer', async (t) => {
  const fixture = await pinnedMaterialFixture(47209, 47210, { native: true })
  const signed = nativeGuardAdvertisement(fixture)
  const lease = createGuardLease(
    leaseOptions(fixture, {
      pinnedGuard: {
        identity: fixture.links.b.publicKey,
        canonicalEndpoint: signed.endpoint,
        advertisement: signed.advertisement,
        advertisementDigest: signed.advertisementDigest,
        epoch: 7n,
        expiresAt: 60_000n
      }
    })
  )
  const caps = new CapsResponder({
    now: () => 1_000n,
    advertisement: signed.advertisement,
    identitySecretKey: fixture.links.b.secretKey,
    routeEncryptionSecretKey: signed.route.secretKey
  })
  const capsModule = require('../../lib/private/caps-responder')
  const sessionModule = require('../../lib/private/link-bootstrap-session')
  const takeAcceptAuthority =
    capsModule[Symbol.for('hyperdht-private-routes/bootstrap-accept-authority-taker')]
  const createAcceptHandle =
    endpointModule[Symbol.for('hyperdht-private-routes/bootstrap-accept-handle-factory')]
  const createDynamicSetup =
    sessionModule[Symbol.for('hyperdht-private-routes/dynamic-responder-setup-factory')]
  const receivedIds = []
  let linkPackets = 0
  let responderInstalled = false
  fixture.setRightBootstrapHandler(async (packet) => {
    if (((packet[0] << 8) | packet[1]) === 0xd301) {
      const bytes = (packet[2] << 8) | packet[3]
      const id = decodeM3Object(packet.subarray(4, 4 + bytes)).messageId
      receivedIds.push(id)
      const source = encodeCanonicalEndpoint({
        addressFamily: 4,
        addressBytes: b4a.from([127, 0, 0, 1]),
        port: 47209
      })
      const responses = caps.receive(packet, source)
      if (id === 4 && !responderInstalled) {
        const handle = createAcceptHandle(takeAcceptAuthority(caps))
        const setup = createDynamicSetup({
          responderStaticSecretKey: signed.route.secretKey,
          responderIdentitySecretKey: fixture.links.b.secretKey
        })
        fixture.installDynamicRightSession(handle, setup)
        responderInstalled = true
      }
      for (const response of responses) {
        await endpointModule.sendConfigured(fixture.rightAuthority, 0, response)
      }
      return
    }
    linkPackets++
    await fixture.receiveRight(packet)
  })
  const reconnect = suspendGuardLease(lease)
  let moved = null
  try {
    const transfer = await reconnect.reconnect()
    t.alike(Reflect.ownKeys(transfer), [])
    const consume =
      endpointModule[Symbol.for('hyperdht-private-routes/reconnected-guard-pin-consumer')]
    moved = consume(transfer)
    t.alike(Reflect.ownKeys(moved.guardLeaseMaterial), [])
    t.alike(moved.pinnedGuard.identity, fixture.links.b.publicKey)
    t.alike(receivedIds, [2, 2, 2, 2, 4])
    t.ok(linkPackets > 0)
  } finally {
    revokeGuardReconnectAuthority(reconnect, 'test-cleanup')
    if (moved) {
      endpointModule.destroyGuardLeaseMaterial(moved.guardLeaseMaterial)
      moved.candidateDirectory.destroy()
    }
    caps.destroy()
    await closeFixture(fixture)
  }
})

test('GuardLease tombstones on idle physical guard loss before any branch send', async (t) => {
  const fixture = await pinnedMaterialFixture(47231, 47232)
  const lease = createGuardLease(leaseOptions(fixture))
  t.is(isGuardLease(lease), true)
  await fixture.left.close()
  await settles()
  t.is(isGuardLease(lease), false)
  t.is(destroyGuardLease(lease), false)
  let error = null
  try {
    issueGuardLeaseM3CellLinkTransferIssuer(lease)
  } catch (err) {
    error = err
  }
  t.is(error && error.code, 'ERR_DESTROYED')
  await fixture.rightSession.close()
  await fixture.right.close()
  fixture.links.left.directory.destroy()
  fixture.links.right.directory.destroy()
})

test('GuardLease signed expiry tombstones idle ownership before issuing loss', async (t) => {
  const fixture = await pinnedMaterialFixture(47233, 47234)
  let wall = 1_000n
  let monotonic = 1_000n
  let expired = null
  const lease = createGuardLease(
    leaseOptions(fixture, {
      wallNow: () => wall,
      monotonicNow: () => monotonic,
      setTimer(callback, delay) {
        t.is(delay, 59_000)
        expired = callback
        return Object.freeze({})
      },
      clearTimer() {}
    })
  )
  t.is(isGuardLease(lease), true)
  wall = 60_000n
  monotonic = 60_000n
  expired()
  await settles()
  t.is(isGuardLease(lease), false)
  t.is(destroyGuardLease(lease), false)
  await fixture.rightSession.close()
  await fixture.right.close()
  fixture.links.left.directory.destroy()
  fixture.links.right.directory.destroy()
})

test('GuardLease opens an authenticated native index-zero tail over the pinned guard', async (t) => {
  const fixture = await pinnedMaterialFixture(47235, 47236)
  const signed = nativeGuardAdvertisement(fixture)
  const clock = {
    wallNow: () => 1_000n,
    monotonicNow: () => 1_000n,
    schedule: setTimeout,
    cancelScheduled: clearTimeout
  }
  const lease = createGuardLease(
    leaseOptions(fixture, {
      pinnedGuard: {
        identity: fixture.links.b.publicKey,
        canonicalEndpoint: signed.endpoint,
        advertisement: signed.advertisement,
        advertisementDigest: signed.advertisementDigest,
        epoch: 7n,
        expiresAt: 60_000n
      },
      ...clock,
      setTimer: clock.schedule,
      clearTimer: clock.cancelScheduled
    })
  )
  let received = null
  let accepted = null
  const responder = createIndexZeroGuardLinkResponder({
    advertisement: signed.advertisement,
    responderIdentitySecretKey: fixture.links.b.secretKey,
    responderRouteEncryptionSecretKey: signed.route.secretKey,
    now: clock.wallNow,
    receiveOffer: () => received,
    randomBytes: sequence(0xa1)
  })
  registerSharedGuardBranchResponder(fixture.rightSession.established, {
    accept(exchange) {
      received = Object.freeze({
        offer: exchange.offer,
        observedPredecessorEndpoint: encodeCanonicalEndpoint({
          addressFamily: 4,
          addressBytes: b4a.from([127, 0, 0, 1]),
          port: 47235
        }),
        physicalChannel: exchange.physicalChannel
      })
      accepted = responder.accept()
      return accepted.accept
    }
  })
  const issuer = issueGuardLeaseM3CellLinkTransferIssuer(lease)
  const authority = createGuardBranchOpenAuthority(lease, {
    branch: Object.freeze({
      branchClass: 0,
      branchId: b4a.alloc(16, 0x41),
      circuitId: b4a.alloc(16, 0x42),
      generation: 1n
    }),
    issuer,
    absoluteDeadline: 6_000n
  })
  let opened = null
  try {
    opened = await openGuardBranch(lease, authority)
    t.alike(Reflect.ownKeys(authority), [])
    t.ok(opened.tailControl)
    t.ok(accepted.established)
  } finally {
    if (opened) {
      destroyTailControlSession(opened.tailControl)
      opened.runtime.destroy()
    }
    if (accepted && accepted.established) {
      const { destroyM3EstablishedLink } = require('../../lib/private/guard-link')
      destroyM3EstablishedLink(accepted.established)
    }
    destroyGuardLease(lease)
    await closeFixture(fixture)
  }
})

test('Peer physical exchange clears exchanging on sync throw after reservation admit', async (t) => {
  const wall = 1_000n
  let monoCalls = 0
  let tripAfter = Number.POSITIVE_INFINITY
  const fixture = await pinnedMaterialFixture(47301, 47302)
  const lease = createGuardLease(
    leaseOptions(fixture, {
      wallNow: () => wall,
      // Outer exchange precheck must see mono < deadline; downstream options.now() must see mono >= deadline.
      monotonicNow: () => {
        monoCalls++
        return monoCalls > tripAfter ? 11_000n : 10_000n
      },
      setTimer: () => Object.freeze({}),
      clearTimer: () => {}
    })
  )
  const reservation = createPeerGuardPhysicalReservation(lease, {
    absoluteDeadline: 11_000n
  })
  const limits = {
    cellSize: 1200,
    maxCells: 8,
    maxBytes: 9600,
    maxCommands: 8,
    idleTimeoutMs: 1000,
    expiresAt: 2000n
  }
  const exchangeOptions = {
    offer: encodePeerTransport(
      PEER_MESSAGE_ID.PEER_LINK_OFFER_V2,
      {
        advertisementDigest: seed(1),
        initiatorIdentity: fixture.links.a.publicKey,
        responderIdentity: fixture.links.b.publicKey,
        initiatorRole: 0,
        responderRole: 1,
        branchClass: 2,
        branchId: b4a.alloc(16, 1),
        circuitId: b4a.alloc(16, 2),
        generation: 1n,
        extensionIndex: 0,
        initiatorLinkEphemeralPublicKey: seed(3),
        clientTailEphemeralPublicKey: seed(4),
        clientNonce: seed(5),
        payloadParametersDigest: seed(6),
        requestedLimits: limits,
        offerDeadline: 2000n,
        initiatorForwardLimits: limits,
        candidateAuthorityCommitment: b4a.alloc(32)
      },
      b4a.alloc(64)
    ),
    generation: 1n,
    absoluteDeadline: 11_000n,
    sendLedger: createPeerLedger({ cells: 8, bytes: 9600n, commands: 1 }),
    receiveLedger: createPeerLedger({ cells: 8, bytes: 9600n, commands: 1 })
  }
  // Next mono sample is outer precheck (still under deadline); the one after is exchangeSharedGuardPeerBranch now().
  tripAfter = monoCalls + 1
  let err = null
  try {
    exchangePeerGuardLink(reservation, exchangeOptions)
  } catch (e) {
    err = e
  }
  t.ok(err)
  t.is(err instanceof require('../../lib/private/errors').PrivateRouteError, true)
  t.is(err.code, 'ERR_PRIVACY_UNAVAILABLE')
  // Catch path destroyed reservation; not stranded exchanging.
  t.is(destroyPeerGuardPhysicalReservation(reservation), false)
  let reuse = null
  try {
    exchangePeerGuardLink(reservation, exchangeOptions)
  } catch (e) {
    reuse = e
  }
  t.is(reuse && reuse.code, 'UNAUTHORIZED')
  destroyGuardLease(lease)
  await closeFixture(fixture)
})

test('Peer guard bootstrap transport is single-live-owner per lease', async (t) => {
  const fixture = await pinnedMaterialFixture(47311, 47312)
  const lease = createGuardLease(leaseOptions(fixture))
  const { destroyPeerDirectRequesterTransport } = endpointModule

  const first = createPeerGuardBootstrapTransport(lease)
  t.ok(first)

  let secondErr = null
  try {
    createPeerGuardBootstrapTransport(lease)
  } catch (err) {
    secondErr = err
  }
  t.is(secondErr && secondErr.code, 'UNAUTHORIZED')

  t.is(destroyPeerDirectRequesterTransport(first), true)

  const third = createPeerGuardBootstrapTransport(lease)
  t.ok(third)
  t.is(third === first, false)
  t.is(destroyPeerDirectRequesterTransport(third), true)

  destroyGuardLease(lease)
  await closeFixture(fixture)
})

test('genuine native established+lease guarded D0 six-packet discover', async (t) => {
  const fixture = await pinnedMaterialFixture(47401, 47402, { native: true })
  const lease = createGuardLease(
    leaseOptions(fixture, {
      pinnedGuard: {
        identity32: fixture.links.b.publicKey,
        endpoint: { host: '127.0.0.1', port: fixture.rightPort }
      },
      wallNow: () => 1_000n,
      monotonicNow: () => 10_000n,
      setTimer: setTimeout,
      clearTimer: clearTimeout
    })
  )

  // Far-end guard runs v2 bootstrap responder with the same identity as the pin.
  const route = cryptoSuite.encryptionKeyPair(seed(201))
  const clockIdentity = Object.freeze({ wallNow: () => 1_000n, monotonicNow: () => 10_000n })
  const guardOwner = createPeerRelayOwner({
    endpoint: fixture.right,
    identityKeyPair: {
      publicKey: fixture.links.b.publicKey,
      secretKey: fixture.links.b.secretKey
    },
    routeKeyPair: route,
    advertisementFields: {
      relayIdentity32: fixture.links.b.publicKey,
      currentDhtNodeId32: deriveM3DhtNodeId(
        encodeCanonicalEndpoint({
          addressFamily: 4,
          addressBytes: b4a.from([127, 0, 0, 1]),
          port: fixture.rightPort
        })
      ),
      reachableEndpoint: { host: '127.0.0.1', port: fixture.rightPort },
      routeEncryptionPublicKey32: route.publicKey,
      capabilityMask: 9,
      minimumVersion: 2,
      maximumVersion: 2,
      datagramReplayWindow: 64,
      maxConcurrentCircuits: 8,
      capacityClass: 0,
      maxCells: 100,
      maxBytes: 100000,
      maxCommands: 10,
      idleTimeoutMs: 30000,
      maxQueuedBytes: 65536,
      epoch: 7n,
      issuedAt: 1_000n,
      expiresAt: 60_000n,
      policyCount: 0
    },
    clockIdentity,
    wallNow: () => 1_000n,
    monotonicNow: () => 10_000n,
    setTimer: setTimeout,
    clearTimer: clearTimeout
  })
  const responder = createPeerBootstrapResponder(guardOwner)
  const registration = registerPeerDirectResponder(fixture.right, responder)

  // Single-live bootstrap transport slot.
  const transport = createPeerGuardBootstrapTransport(lease)
  let dup = null
  try {
    createPeerGuardBootstrapTransport(lease)
  } catch (err) {
    dup = err
  }
  t.is(dup && dup.code, 'UNAUTHORIZED')

  const ledger = createPeerLedger({ cells: 64, bytes: 64n * 1200n, commands: 0 })
  const candidatePromise = discoverPeerCandidate(transport, {
    ledger,
    requestedMask: 9,
    randomTarget: b4a.alloc(32, 0xa1),
    maximumResults: 1
  })

  // Real timers drive the six-packet COOKIE/CAPS/ACTIVE exchange on native UDX.
  const candidate = await candidatePromise
  t.is(candidate.kind, 'peerActiveCandidate')
  let wrongKindRejected = false
  try {
    takePeerActiveCandidate(candidate, { expectedKind: 'candidate' })
  } catch (err) {
    wrongKindRejected = err.code === 'INVALID_ROUTE'
  }
  t.ok(wrongKindRejected, 'pinned guard discovery cannot satisfy neighbor provenance')
  const taken = takePeerActiveCandidate(candidate, {
    expectedKind: 'guard',
    expectedIdentity32: fixture.links.b.publicKey,
    expectedEpoch: 7n
  })
  t.alike(taken.identity32, fixture.links.b.publicKey)
  t.is(taken.kind, 'guard')
  const digestDomain = b4a.from('hyperdht-private-routes/m3/active-challenge-response-digest/v2')
  const digestDomainLength = b4a.alloc(2)
  digestDomainLength.writeUInt16BE(digestDomain.byteLength)
  const expectedDigest = b4a.alloc(32)
  sodium.crypto_generichash(
    expectedDigest,
    b4a.concat([digestDomainLength, digestDomain, taken.activeResponse312])
  )
  t.alike(taken.activeResponseDigest, expectedDigest)
  t.is(b4a.isBuffer(taken.grantDigest), true)
  t.is(b4a.isBuffer(taken.runId), true)
  t.is(typeof taken.operations, 'number')

  const snap = readPeerLedger(ledger)
  t.ok(snap.cellsSpent >= 3)

  t.is(destroyPeerActiveCandidate(candidate), true)
  destroyPeerDirectResponderRegistration(registration)
  destroyPeerBootstrapResponder(responder)
  destroyPeerRelayOwner(guardOwner)
  destroyGuardLease(lease)
  await closeFixture(fixture)
})
test('negative canonical-packet send regressions over native UDX established+lease boundary', async (t) => {
  const UDX = require('udx-native')
  const bootstrap = require('../../lib/private/peer-direct-bootstrap')
  const { encodePeerObject, PEER_MESSAGE_ID } = require('../../lib/private/peer-protocol')
  const { PrivateRouteError } = require('../../lib/private/errors')
  const originalTakeBinding = bootstrap.takePeerBootstrapResponderBinding
  let nativeReplySend = null
  bootstrap.takePeerBootstrapResponderBinding = function (...args) {
    const binding = originalTakeBinding(...args)
    return Object.freeze({
      receive(packet, endpoint, sendReply) {
        nativeReplySend = sendReply
        return binding.receive(packet, endpoint, sendReply)
      },
      destroy: binding.destroy
    })
  }
  const origCreateSocket = UDX.prototype.createSocket
  const createdSockets = []

  UDX.prototype.createSocket = function (...args) {
    const sock = origCreateSocket.apply(this, args)
    sock._sendCount = 0
    const origSend = sock.send
    sock.send = function (...sendArgs) {
      sock._sendCount++
      return origSend.apply(this, sendArgs)
    }
    createdSockets.push(sock)
    return sock
  }

  t.teardown(() => {
    UDX.prototype.createSocket = origCreateSocket
    bootstrap.takePeerBootstrapResponderBinding = originalTakeBinding
  })

  const fixture = await pinnedMaterialFixture(47403, 47404, { native: true })
  const lease = createGuardLease(
    leaseOptions(fixture, {
      pinnedGuard: {
        identity32: fixture.links.b.publicKey,
        endpoint: { host: '127.0.0.1', port: fixture.rightPort }
      },
      wallNow: () => 1_000n,
      monotonicNow: () => 10_000n,
      setTimer: setTimeout,
      clearTimer: clearTimeout
    })
  )

  const route = cryptoSuite.encryptionKeyPair(seed(202))
  const clockIdentity = Object.freeze({ wallNow: () => 1_000n, monotonicNow: () => 10_000n })
  const guardOwner = createPeerRelayOwner({
    endpoint: fixture.right,
    identityKeyPair: {
      publicKey: fixture.links.b.publicKey,
      secretKey: fixture.links.b.secretKey
    },
    routeKeyPair: route,
    advertisementFields: {
      relayIdentity32: fixture.links.b.publicKey,
      currentDhtNodeId32: deriveM3DhtNodeId(
        encodeCanonicalEndpoint({
          addressFamily: 4,
          addressBytes: b4a.from([127, 0, 0, 1]),
          port: fixture.rightPort
        })
      ),
      reachableEndpoint: { host: '127.0.0.1', port: fixture.rightPort },
      routeEncryptionPublicKey32: route.publicKey,
      capabilityMask: 9,
      minimumVersion: 2,
      maximumVersion: 2,
      datagramReplayWindow: 64,
      maxConcurrentCircuits: 8,
      capacityClass: 0,
      maxCells: 100,
      maxBytes: 100000,
      maxCommands: 10,
      idleTimeoutMs: 30000,
      maxQueuedBytes: 65536,
      epoch: 7n,
      issuedAt: 1_000n,
      expiresAt: 60_000n,
      policyCount: 0
    },
    clockIdentity,
    wallNow: () => 1_000n,
    monotonicNow: () => 10_000n,
    setTimer: setTimeout,
    clearTimer: clearTimeout
  })
  const responder = createPeerBootstrapResponder(guardOwner)
  const registration = registerPeerDirectResponder(fixture.right, responder)
  t.teardown(async () => {
    destroyPeerDirectResponderRegistration(registration)
    destroyPeerBootstrapResponder(responder)
    destroyPeerRelayOwner(guardOwner)
    destroyGuardLease(lease)
    await closeFixture(fixture)
  })

  const transport = createPeerGuardBootstrapTransport(lease)
  const requesterTransport = takePeerDirectRequesterTransport(transport)

  t.ok(createdSockets.length >= 2, 'fixture created native UDX sockets')
  const leftSocket = createdSockets[0]
  const rightSocket = createdSockets[1]

  const queryBody = b4a.alloc(110)
  queryBody.writeUInt32BE(9, 0)
  queryBody.fill(0x31, 4, 36)
  queryBody.fill(0x32, 36, 68)
  queryBody[68] = 1
  const query = bootstrap.wrapDirectRpcPacket(
    encodePeerObject({
      messageId: PEER_MESSAGE_ID.PEER_CAPS_QUERY_V2,
      body: queryBody
    })
  )
  const cookieReceived = new Promise((resolve) => {
    requesterTransport.onPacket((packet) => resolve(b4a.from(packet)))
  })
  await requesterTransport.send(query)
  const reply = await cookieReceived
  const initialLeftSends = leftSocket._sendCount
  const initialRightSends = rightSocket._sendCount

  function malformedPackets(canonical, wrongDirection, mutateScalar) {
    const magic = b4a.from(canonical)
    magic.writeUInt16BE(0xd302, 0)
    const padding = b4a.from(canonical)
    padding[4 + padding.readUInt16BE(2)] = 0xff
    const version = b4a.from(canonical)
    version.writeUInt32BE(1, 4)
    const geometry = b4a.from(canonical)
    geometry.writeUInt16BE(geometry.readUInt16BE(10) - 1, 10)
    const scalar = b4a.from(canonical)
    mutateScalar(scalar)
    return [
      ['magic', magic],
      ['padding', padding],
      ['version', version],
      ['direction', wrongDirection],
      ['geometry', geometry],
      ['scalar', scalar]
    ]
  }
  const directions = [
    [
      'requester',
      requesterTransport.send,
      malformedPackets(query, reply, (packet) => {
        packet[80] = 2
      })
    ],
    [
      'responder',
      nativeReplySend,
      malformedPackets(reply, query, (packet) => {
        packet.fill(0, 44, 52)
      })
    ]
  ]
  for (const [direction, send, packets] of directions) {
    for (const [fault, packet] of packets) {
      let error = null
      try {
        await send(packet)
      } catch (err) {
        error = err
      }
      t.ok(error instanceof PrivateRouteError, direction + ' rejects ' + fault)
      t.is(
        leftSocket._sendCount,
        initialLeftSends,
        'no requester native send for ' + direction + '/' + fault
      )
      t.is(
        rightSocket._sendCount,
        initialRightSends,
        'no responder native send for ' + direction + '/' + fault
      )
    }
  }
  requesterTransport.destroy()
  const freshTransport = createPeerGuardBootstrapTransport(lease)

  // 6. Canonical positive exchange still works and increases send counts on both real sockets
  const ledger = createPeerLedger({ cells: 64, bytes: 64n * 1200n, commands: 0 })
  const candidatePromise = discoverPeerCandidate(freshTransport, {
    ledger,
    requestedMask: 9,
    randomTarget: b4a.alloc(32, 0xa2),
    maximumResults: 1
  })
  const candidate = await candidatePromise
  t.is(candidate.kind, 'peerActiveCandidate')
  t.ok(
    leftSocket._sendCount > initialLeftSends,
    'canonical positive exchange produced native send attempts on requester socket'
  )
  t.ok(
    rightSocket._sendCount > initialRightSends,
    'canonical positive exchange produced native send attempts on responder socket'
  )

  t.is(destroyPeerActiveCandidate(candidate), true)
})
