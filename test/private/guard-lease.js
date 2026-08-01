'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { BOOTSTRAP_SIZE, BootstrapEnvelopeCodec } = require('../../lib/private/bootstrap-envelope')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { createLinkSetupAuthority } = require('../../lib/private/link-setup')
const {
  LINK_OPERATION,
  PROTOCOL_VERSION,
  ROLE,
  TOPOLOGY_ROLE,
  roleForIdentity
} = require('../../lib/private/protocol')
const { LinkDirectory, signTopologyGrant } = require('../../lib/private/topology-grant')
const {
  TEST_ONLY_UDX_ADAPTER_ISSUER,
  UdxCellEndpoint,
  admitBootstrapUdxGuard,
  bindBootstrapUdxOperation,
  createBootstrapUdxAuthority,
  createLocalIdentitySecretCapability,
  isGuardLeaseMaterial,
  openBootstrapUdxGuard,
  pinBootstrapUdxGuard
} = require('../../lib/private/udx-cell-endpoint')
const endpointModule = require('../../lib/private/udx-cell-endpoint')
const guardLink = require('../../lib/private/guard-link')
const TEST_ONLY_M3_ESTABLISHED_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-m3-established-issuer'
)
const {
  createGuardLease,
  destroyGuardLease,
  isGuardLease,
  issueGuardLeaseM3CellLinkTransferIssuer,
  MAX_GUARD_LEASE_BRANCH_SLOTS
} = require('../../lib/private/guard-lease')
const { createM3CellLinkTransferIssuer, registerM3CellLinkTransfer } = endpointModule

const seed = (value) => b4a.alloc(32, value)

function safetyIdentity(start = 100) {
  for (let value = start; value < 256; value++) {
    const pair = cryptoSuite.keyPair(seed(value))
    if (roleForIdentity(pair.publicKey) === ROLE.SAFETY) return pair
  }
  throw new Error('missing safety identity')
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
    signedExpiry: 60_000
  }
}

async function pinnedMaterialFixture(leftPort, rightPort, fixtureOptions = {}) {
  const network = new Map()
  const issuer = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER]
  const links = linkPair('127.0.0.1', leftPort, '127.0.0.2', rightPort)
  const leftObserver = {}
  let leftSession = null
  let rightSession = null
  const left = issuer.createUdxCellEndpointForTest(
    {
      ...options('127.0.0.1', leftPort),
      onBootstrap(packet) {
        if (leftSession) void leftSession.receive(packet)
      }
    },
    issuer.createTestUdxAdapterAuthority(fakeFactory(network, leftObserver))
  )
  const right = issuer.createUdxCellEndpointForTest(
    {
      ...options('127.0.0.2', rightPort),
      onBootstrap(packet) {
        if (rightSession) void rightSession.receive(packet)
      }
    },
    issuer.createTestUdxAdapterAuthority(fakeFactory(network))
  )
  await left.bind()
  await right.bind()
  const authority = createBootstrapUdxAuthority({
    endpoint: left,
    configuredEndpoints: [{ host: '127.0.0.2', port: rightPort }],
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
    host: '127.0.0.2',
    port: rightPort
  })
  leftSession = openBootstrapUdxGuard(
    authority,
    admission,
    links.left.handle,
    linkSessionOptions(links, 'left')
  )
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
    rightPort,
    rightSession,
    material: pinBootstrapUdxGuard(authority, admission, established)
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
  await fixture.rightSession.close()
  await fixture.right.close()
  fixture.links.left.directory.destroy()
  fixture.links.right.directory.destroy()
}

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
