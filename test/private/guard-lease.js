'use strict'

const test = require('brittle')
const b4a = require('b4a')

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
  pinBootstrapUdxGuard
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
  MAX_GUARD_LEASE_BRANCH_SLOTS
} = require('../../lib/private/guard-lease')
const { createM3CellLinkTransferIssuer, registerM3CellLinkTransfer } = endpointModule
const guardLink = require('../../lib/private/guard-link')
const { createIndexZeroGuardLinkResponder } = guardLink
const { destroyTailControlSession } = require('../../lib/private/tail-control')
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

function nativeGuardAdvertisement(fixture) {
  const route = cryptoSuite.encryptionKeyPair(seed(121))
  const endpoint = encodeCanonicalEndpoint({
    addressFamily: 4,
    addressBytes: b4a.from(fixture.rightHost.split('.').map(Number)),
    port: fixture.rightPort
  })
  const signed = signRelayCapabilityAdvertisement(
    {
      relayIdentity: fixture.links.b.publicKey,
      currentDhtNodeId: deriveM3DhtNodeId(endpoint),
      reachableEndpoint: endpoint,
      routeEncryptionPublicKey: route.publicKey,
      capabilityMask: 1,
      minimumProtocolVersion: 1,
      maximumProtocolVersion: 1,
      cellSize: 1200,
      maxCellPayload: 1146,
      contextEnvelopeSize: 1101,
      routeFrameSize: 1100,
      maxRoutePayload: 1073,
      datagramReplayWindow: 64,
      maxConcurrentCircuits: 8,
      capacityClass: CAPACITY_CLASS.SMALL,
      maxCellsPerCircuit: 100,
      maxBytesPerCircuit: 100_000,
      maxCommandsPerCircuit: 10,
      idleTimeoutMs: 30_000,
      maxQueuedBytes: 65_536,
      epoch: 7n,
      issuedAtMs: 1_000n,
      expiresAtMs: 60_000n,
      providerServicePolicyEntries: providerServicePolicyForCapabilities(1)
    },
    fixture.links.b.secretKey
  )
  const advertisement = encodeRelayCapabilityAdvertisement(signed)
  return {
    advertisement,
    advertisementDigest: digestRelayCapabilityAdvertisement(advertisement, { now: 1_000n }),
    endpoint,
    route
  }
}
function linkPair(hostA, portA, hostB, portB) {
  const authority = cryptoSuite.keyPair(seed(90))
  const a = cryptoSuite.keyPair(seed(91))
  const b = safetyIdentity(92)
  const runId32 = seed(93)
  const grant = signTopologyGrant(
    {
      version: PROTOCOL_VERSION,
      format: 0,
      grantId32: seed(94),
      endpointA: {
        identity32: a.publicKey,
        role: TOPOLOGY_ROLE.SOURCE,
        host: hostA,
        port: portA,
        operations: LINK_OPERATION.INITIATE
      },
      endpointB: {
        identity32: b.publicKey,
        role: TOPOLOGY_ROLE.SAFETY_GUARD,
        host: hostB,
        port: portB,
        operations: LINK_OPERATION.ACCEPT
      },
      epoch: 7n,
      notBefore: 0n,
      expiresAt: 60_000n,
      runId32
    },
    authority.secretKey
  )
  const make = (local, peer, localRole, peerRole, operation) => {
    const directory = new LinkDirectory({
      localIdentity32: local.publicKey,
      localRole,
      authorityPublicKey: authority.publicKey,
      epoch: 7n,
      runId32,
      now: () => 1n,
      schedule: setTimeout,
      cancel: clearTimeout,
      onClose() {}
    })
    const digest32 = directory.add(grant)
    const handle = directory.authorize({
      digest32,
      operation,
      localIdentity32: local.publicKey,
      localRole,
      peerIdentity32: peer.publicKey,
      peerRole,
      epoch: 7n,
      runId32
    })
    return { directory, handle }
  }
  return {
    left: make(a, b, TOPOLOGY_ROLE.SOURCE, TOPOLOGY_ROLE.SAFETY_GUARD, LINK_OPERATION.INITIATE),
    right: make(b, a, TOPOLOGY_ROLE.SAFETY_GUARD, TOPOLOGY_ROLE.SOURCE, LINK_OPERATION.ACCEPT),
    a,
    b
  }
}

class FakeSocket {
  constructor(network, observer = null) {
    this.network = network
    this.observer = observer
    this.listeners = new Map()
    this.host = null
    this.port = null
    this.closed = false
    this.closeCalls = 0
  }
  on(name, listener) {
    const values = this.listeners.get(name) || new Set()
    values.add(listener)
    this.listeners.set(name, values)
  }
  off(name, listener) {
    const values = this.listeners.get(name)
    if (values) values.delete(listener)
  }
  emit(name, ...args) {
    for (const listener of this.listeners.get(name) || []) listener(...args)
  }
  bind(port, host) {
    this.port = port
    this.host = host
    this.network.set(`${host}:${port}`, this)
    return true
  }
  send(packet, port, host) {
    const peer = this.network.get(`${host}:${port}`)
    if (!peer) return false
    queueMicrotask(() =>
      peer.emit('message', b4a.from(packet), { host: this.host, port: this.port })
    )
    return true
  }
  close() {
    this.closeCalls++
    this.closed = true
    this.network.delete(`${this.host}:${this.port}`)
    if (this.observer) this.observer.events.push(['close', this])
    return true
  }
}

function fakeFactory(network, observer = {}) {
  return () => ({
    create() {
      return {
        createSocket() {
          const socket = new FakeSocket(network, observer)
          observer.socket = socket
          if (!observer.sockets) observer.sockets = []
          if (!observer.events) observer.events = []
          observer.sockets.push(socket)
          observer.events.push(['create', socket])
          return socket
        }
      }
    }
  })
}

function options(host, port, overrides = {}) {
  return {
    host,
    port,
    onBootstrap() {},
    onCell() {},
    onLinkFailure() {},
    ...overrides
  }
}

async function settles() {
  await Promise.resolve()
  await Promise.resolve()
}

function sequence(first) {
  let value = first
  return (size) => b4a.alloc(size, value++)
}

function linkSessionOptions(links, side, deadline = 10_000) {
  const now = () => 1
  const responderStatic = cryptoSuite.encryptionKeyPair(seed(98))
  const common = {
    circuitId: b4a.alloc(16, 0x51),
    epoch: 7n,
    initiatorIdentity: links.a.publicKey,
    responderIdentity: links.b.publicKey,
    initiatorLocalId: b4a.alloc(16, 0x52),
    responderLocalId: b4a.alloc(16, 0x53),
    expiresAt: 60_000n
  }
  const initiate = side === 'left'
  return {
    mode: initiate ? 'initiate' : 'accept',
    codec: new BootstrapEnvelopeCodec({
      linkHandle: initiate ? links.left.handle : links.right.handle,
      localIdentitySecretKey: initiate ? links.a.secretKey : links.b.secretKey,
      padding: sequence(initiate ? 0x81 : 0x91)
    }),
    linkSetup: createLinkSetupAuthority({
      now,
      randomBytes: sequence(initiate ? 0x61 : 0x71)
    }),
    setup: initiate
      ? {
          ...common,
          responderStaticKey: responderStatic.publicKey,
          initiatorIdentitySecretKey: links.a.secretKey
        }
      : {
          ...common,
          responderStaticSecretKey: responderStatic.secretKey,
          responderIdentitySecretKey: links.b.secretKey
        },
    now,
    schedule: setTimeout,
    cancel: clearTimeout,
    randomBytes: sequence(initiate ? 1 : 11),
    absoluteDeadline: deadline,
    signedExpiry: 60_000,
    authorizedExpiry: 60_000
  }
}

async function pinnedMaterialFixture(leftPort, rightPort, fixtureOptions = {}) {
  const network = new Map()
  const issuer = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER]
  const rightHost = fixtureOptions.native === true ? '127.0.0.1' : '127.0.0.2'
  const links = linkPair('127.0.0.1', leftPort, rightHost, rightPort)
  const leftObserver = {}
  let leftSession = null
  let rightSession = null
  let rightBootstrapHandler = null
  const leftEndpointOptions = {
    ...options('127.0.0.1', leftPort),
    onBootstrap(packet, handle) {
      if (leftSession) return leftSession.receive(packet, handle)
    }
  }
  const left =
    fixtureOptions.native === true
      ? new UdxCellEndpoint(leftEndpointOptions)
      : issuer.createUdxCellEndpointForTest(
          leftEndpointOptions,
          issuer.createTestUdxAdapterAuthority(fakeFactory(network, leftObserver))
        )
  const rightEndpointOptions = {
    ...options(rightHost, rightPort),
    onBootstrap(packet, handle) {
      if (rightBootstrapHandler) return rightBootstrapHandler(packet, handle)
      if (rightSession) return rightSession.receive(packet, handle)
    }
  }
  const right =
    fixtureOptions.native === true
      ? new UdxCellEndpoint(rightEndpointOptions)
      : issuer.createUdxCellEndpointForTest(
          rightEndpointOptions,
          issuer.createTestUdxAdapterAuthority(fakeFactory(network))
        )
  let rightAuthority = null
  if (fixtureOptions.native === true) {
    rightAuthority = createBootstrapUdxAuthority({
      endpoint: right,
      configuredEndpoints: [{ host: '127.0.0.1', port: leftPort }],
      localSecretCapability: createLocalIdentitySecretCapability({
        localIdentity: links.b.publicKey,
        localSecretKey: links.b.secretKey
      }),
      maxProspectiveGuards: 1,
      monotonicDeadline: 10_000
    })
    bindBootstrapUdxOperation(rightAuthority, 10_000, Object.freeze({}))
  }
  await left.bind()
  await right.bind()
  const authority = createBootstrapUdxAuthority({
    endpoint: left,
    configuredEndpoints: [{ host: rightHost, port: rightPort }],
    localSecretCapability: createLocalIdentitySecretCapability({
      localIdentity: links.a.publicKey,
      localSecretKey: links.a.secretKey
    }),
    maxProspectiveGuards: 3,
    monotonicDeadline: 10_000
  })
  bindBootstrapUdxOperation(authority, 10_000, Object.freeze({}))
  const admission = admitBootstrapUdxGuard(authority, {
    identity: links.b.publicKey,
    host: rightHost,
    port: rightPort
  })
  const leftOptions = linkSessionOptions(links, 'left')
  const sessionOptions = createBootstrapUdxGuardSessionOptions(
    authority,
    admission,
    links.left.handle,
    {
      circuitId: leftOptions.setup.circuitId,
      epoch: leftOptions.setup.epoch,
      initiatorLocalId: leftOptions.setup.initiatorLocalId,
      responderLocalId: leftOptions.setup.responderLocalId,
      expiresAt: leftOptions.setup.expiresAt,
      responderStaticKey: leftOptions.setup.responderStaticKey,
      now: leftOptions.now,
      handleNow: leftOptions.now,
      wallNow: leftOptions.now,
      schedule: leftOptions.schedule,
      cancel: leftOptions.cancel,
      randomBytes: leftOptions.randomBytes,
      absoluteDeadline: leftOptions.absoluteDeadline,
      signedExpiry: leftOptions.signedExpiry
    }
  )
  leftSession = openBootstrapUdxGuard(authority, admission, links.left.handle, sessionOptions)
  rightSession = right.openLink(links.right.handle, linkSessionOptions(links, 'right'))
  const established = await leftSession.open()
  if (fixtureOptions.pin === false) {
    return {
      left,
      right,
      leftObserver,
      links,
      rightPort,
      rightSession,
      authority,
      admission,
      established
    }
  }
  return {
    left,
    right,
    leftObserver,
    links,
    rightHost,
    rightPort,
    rightSession,
    rightAuthority,
    installDynamicRightSession(handle, setup) {
      const acceptOptions = linkSessionOptions(links, 'right')
      acceptOptions.codec = new BootstrapEnvelopeCodec({
        linkHandle: handle,
        localIdentitySecretKey: links.b.secretKey,
        padding: sequence(0x91)
      })
      acceptOptions.setup = setup
      rightSession = right.openLink(handle, acceptOptions)
    },
    receiveRight(packet) {
      return rightSession.receive(packet)
    },
    inspectRightSession() {
      const module = require('../../lib/private/link-bootstrap-session')
      return rightSession[module.TEST_ONLY_LINK_BOOTSTRAP_SESSION_OBSERVER]()
    },
    material: pinBootstrapUdxGuard(authority, admission, established),
    setRightBootstrapHandler(handler) {
      rightBootstrapHandler = handler
    }
  }
}

function leaseOptions(fixture, overrides = {}) {
  return {
    guardLeaseMaterial: fixture.material,
    pinnedGuard: {
      identity32: fixture.links.b.publicKey,
      endpoint: { host: '127.0.0.2', port: fixture.rightPort }
    },
    wallNow: () => 1_000,
    monotonicNow: () => 10_000,
    setTimer: setTimeout,
    clearTimer: clearTimeout,
    guardLossSink: Object.freeze({}),
    ...overrides
  }
}

async function closeFixture(fixture) {
  if (fixture.rightAuthority) endpointModule.destroyBootstrapUdxAuthority(fixture.rightAuthority)
  await fixture.rightSession.close()
  await fixture.right.close()
  fixture.links.left.directory.destroy()
  fixture.links.right.directory.destroy()
}

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
