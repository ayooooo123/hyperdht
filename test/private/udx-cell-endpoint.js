'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { BOOTSTRAP_CLASS, BOOTSTRAP_SIZE } = require('../../lib/private/bootstrap-envelope')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { BootstrapEnvelopeCodec } = require('../../lib/private/bootstrap-envelope')
const { PrivateRouteError } = require('../../lib/private/errors')
const { createLinkSetupAuthority } = require('../../lib/private/link-setup')
const {
  LINK_OPERATION,
  PROTOCOL_VERSION,
  ROLE,
  TOPOLOGY_ROLE,
  roleForIdentity
} = require('../../lib/private/protocol')
const { LinkDirectory, signTopologyGrant } = require('../../lib/private/topology-grant')
const { deriveM3DhtNodeId, encodeCanonicalEndpoint } = require('../../lib/private/relay-capability')
const { UDX_ENDPOINT_RESERVATION_STATS } = require('../../lib/private/udx-adapter')
const {
  TEST_ONLY_UDX_ADAPTER_ISSUER,
  UdxCellEndpoint,
  admitBootstrapUdxGuard,
  bindBootstrapUdxOperation,
  createBootstrapUdxAuthority,
  createBootstrapUdxGuardSessionOptions,
  createLocalIdentitySecretCapability,
  destroyBootstrapUdxAuthority,
  destroyGuardLeaseMaterial,
  isGuardLeaseMaterial,
  openBootstrapUdxGuard,
  pinBootstrapUdxGuard,
  requestConfigured,
  sendConfigured,
  sendProspectiveGuard
} = require('../../lib/private/udx-cell-endpoint')
const endpointModule = require('../../lib/private/udx-cell-endpoint')

// Adapted from the reviewed private-routes prototype at commit
// 0305df915b6a767093f9e75e6c06bc0a35da6169 and narrowed to Gate 3B1.

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
  constructor(network, hold, observer = null) {
    this.network = network
    this.hold = hold
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
    if (this.observer && this.observer.failBindAt === this.observer.sockets.length) {
      throw new Error('injected bind failure')
    }
    this.port = port
    this.host = host
    this.network.set(`${host}:${port}`, this)
    return true
  }
  send(packet, port, host) {
    if (
      this.observer &&
      this.observer.holdSendAt === this.observer.sockets.length &&
      this.observer.sendHold
    )
      return this.observer.sendHold
    if (this.hold) return this.hold
    const peer = this.network.get(`${host}:${port}`)
    if (!peer) return false
    queueMicrotask(() =>
      peer.emit('message', b4a.from(packet), { host: this.host, port: this.port })
    )
    return true
  }
  close() {
    this.closeCalls++
    const finish = () => {
      this.closed = true
      this.network.delete(`${this.host}:${this.port}`)
      if (this.observer) this.observer.events.push(['close', this])
      return true
    }
    return this.observer && this.observer.closeHold
      ? Promise.resolve(this.observer.closeHold).then(finish)
      : finish()
  }
}

function fakeFactory(network, hold = null, observer = {}) {
  return () => ({
    create() {
      return {
        createSocket() {
          const socket = new FakeSocket(network, hold, observer)
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

function options(host, port, received, overrides = {}) {
  return {
    host,
    port,
    onBootstrap(packet, handle) {
      received.push({ packet: b4a.from(packet), handle })
    },
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
  const linkHandle = initiate ? links.left.handle : links.right.handle
  return {
    mode: initiate ? 'initiate' : 'accept',
    codec: new BootstrapEnvelopeCodec({
      linkHandle,
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

async function pinnedMaterialFixture(leftPort, rightPort, observerOptions = {}) {
  const network = new Map()
  const issuer = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER]
  const links = linkPair('127.0.0.1', leftPort, '127.0.0.2', rightPort)
  const leftObserver = { ...observerOptions }
  let leftSession = null
  let rightSession = null
  const left = issuer.createUdxCellEndpointForTest(
    {
      ...options('127.0.0.1', leftPort, []),
      onBootstrap(packet) {
        if (leftSession) void leftSession.receive(packet)
      }
    },
    issuer.createTestUdxAdapterAuthority(fakeFactory(network, null, leftObserver))
  )
  const right = issuer.createUdxCellEndpointForTest(
    {
      ...options('127.0.0.2', rightPort, []),
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
  const leftOptions = linkSessionOptions(links, 'left')
  const leftSessionOptions = createBootstrapUdxGuardSessionOptions(
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
      wallNow: leftOptions.now,
      handleNow: leftOptions.now,
      schedule: leftOptions.schedule,
      cancel: leftOptions.cancel,
      randomBytes: leftOptions.randomBytes,
      absoluteDeadline: leftOptions.absoluteDeadline,
      signedExpiry: leftOptions.signedExpiry
    }
  )
  leftSession = openBootstrapUdxGuard(authority, admission, links.left.handle, leftSessionOptions)
  rightSession = right.openLink(links.right.handle, linkSessionOptions(links, 'right'))
  const established = await leftSession.open()
  return {
    issuer,
    left,
    right,
    leftObserver,
    links,
    rightSession,
    material: pinBootstrapUdxGuard(authority, admission, established)
  }
}

test('BootstrapUdxAuthority correlates native responses by exact live direct source token', async (t) => {
  const network = new Map()
  const issuer = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER]
  const leftObserver = {}
  const rightObserver = {}
  const wrongObserver = {}
  const received = []
  const left = issuer.createUdxCellEndpointForTest(
    options('127.0.0.1', 47101, received),
    issuer.createTestUdxAdapterAuthority(fakeFactory(network, null, leftObserver))
  )
  const right = issuer.createUdxCellEndpointForTest(
    options('127.0.0.2', 47102, []),
    issuer.createTestUdxAdapterAuthority(fakeFactory(network, null, rightObserver))
  )
  const wrong = issuer.createUdxCellEndpointForTest(
    options('127.0.0.3', 47103, []),
    issuer.createTestUdxAdapterAuthority(fakeFactory(network, null, wrongObserver))
  )
  await left.bind()
  await right.bind()
  await wrong.bind()
  const identity = cryptoSuite.keyPair(seed(119))
  const authority = createBootstrapUdxAuthority({
    endpoint: left,
    configuredEndpoints: [{ host: '127.0.0.2', port: 47102 }],
    localSecretCapability: createLocalIdentitySecretCapability({
      localIdentity: identity.publicKey,
      localSecretKey: identity.secretKey
    }),
    maxProspectiveGuards: 3,
    monotonicDeadline: 10_000
  })
  bindBootstrapUdxOperation(authority, 10_000, Object.freeze({}))
  const request = b4a.alloc(BOOTSTRAP_SIZE, 0x81)
  const response = b4a.alloc(BOOTSTRAP_SIZE, 0x91)
  let completed = false
  const pending = requestConfigured(authority, 0, request).then((value) => {
    completed = true
    return value
  })
  await settles()

  t.is(wrongObserver.socket.send(response, 47101, '127.0.0.1'), true)
  await settles()
  t.is(completed, false)

  t.is(rightObserver.socket.send(response, 47101, '127.0.0.1'), true)
  const owned = await pending
  response.fill(0)
  t.alike(owned, b4a.alloc(BOOTSTRAP_SIZE, 0x91))
  t.is(received.length, 0)

  t.is(rightObserver.socket.send(owned, 47101, '127.0.0.1'), true)
  await settles()
  t.is(received.length, 1)
  t.alike(received[0].packet, owned)

  const stale = requestConfigured(authority, 0, request)
  await settles()
  t.is(destroyBootstrapUdxAuthority(authority), true)
  let staleError = null
  try {
    await stale
  } catch (err) {
    staleError = err
  }
  t.is(staleError && staleError.code, 'ERR_DESTROYED')
  t.is(rightObserver.socket.send(owned, 47101, '127.0.0.1'), true)
  await settles()
  t.is(received.length, 1)

  await right.close()
  await wrong.close()
})

test('UDX test adapter authority is opaque, one-shot, and exact constructor rejects injection', async (t) => {
  const issuer = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER]
  t.is(typeof issuer.createTestUdxAdapterAuthority, 'function')
  t.is(typeof issuer.createUdxCellEndpointForTest, 'function')
  t.is(typeof issuer.sendBootstrapForTest, 'function')
  t.is(typeof issuer.sendBootstrapWithOptionsForTest, 'function')
  t.is(typeof issuer.sendEstablishedForTest, 'function')
  t.is(typeof issuer.inspectGuardLeaseMaterial, 'function')
  t.is(typeof endpointModule.bindBootstrapUdxOperation, 'function')
  t.is('createBootstrapGuardLeaseMaterial' in endpointModule, false)
  const authority = issuer.createTestUdxAdapterAuthority(fakeFactory(new Map()))
  t.is(Object.keys(authority).length, 0)
  const endpoint = issuer.createUdxCellEndpointForTest(options('127.0.0.1', 47101, []), authority)
  await endpoint.bind()
  let error = null
  try {
    issuer.createUdxCellEndpointForTest(options('127.0.0.1', 47102, []), authority)
  } catch (err) {
    error = err
  }
  t.ok(error instanceof PrivateRouteError)
  t.is(error && error.code, 'UNAUTHORIZED')
  t.exception(() => new UdxCellEndpoint({ ...options('127.0.0.1', 47103, []), adapter: {} }))
  await endpoint.close()
})

test('malformed created socket is closed once before endpoint construction fails', (t) => {
  const issuer = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER]
  let closeCalls = 0
  const authority = issuer.createTestUdxAdapterAuthority(() => ({
    create() {
      return {
        createSocket() {
          return {
            bind() {},
            close() {
              closeCalls++
            },
            on() {}
          }
        }
      }
    }
  }))
  t.exception(() => issuer.createUdxCellEndpointForTest(options('127.0.0.1', 47104, []), authority))
  t.is(closeCalls, 1)
  t.exception(() => issuer.createUdxCellEndpointForTest(options('127.0.0.1', 47105, []), authority))
  t.is(closeCalls, 1)
})

test('fake UDX endpoint binds exact tuple, drops spoofing, and revokes post-close sends', async (t) => {
  const network = new Map()
  const issuer = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER]
  const leftReceived = []
  const rightReceived = []
  const leftObserver = {}
  const rightObserver = {}
  const left = issuer.createUdxCellEndpointForTest(
    options('127.0.0.1', 47111, leftReceived),
    issuer.createTestUdxAdapterAuthority(fakeFactory(network, null, leftObserver))
  )
  const right = issuer.createUdxCellEndpointForTest(
    options('127.0.0.2', 47112, rightReceived),
    issuer.createTestUdxAdapterAuthority(fakeFactory(network, null, rightObserver))
  )
  await left.bind()
  await right.bind()
  const links = linkPair('127.0.0.1', 47111, '127.0.0.2', 47112)
  const leftSession = left.openLink(links.left.handle, linkSessionOptions(links, 'left'))
  const rightSession = right.openLink(links.right.handle, linkSessionOptions(links, 'right'))
  const packet = b4a.alloc(BOOTSTRAP_SIZE)
  packet[1] = BOOTSTRAP_CLASS
  t.is(await issuer.sendBootstrapForTest(left, leftSession, packet), true)
  await settles()
  t.is(rightReceived.length, 1)
  t.alike(rightReceived[0].packet, packet)

  rightObserver.socket.emit('message', packet, { host: '127.0.0.9', port: 47111 })
  await settles()
  t.is(rightReceived.length, 1)
  await left.close()
  t.is(leftObserver.socket.closed, true)
  await t.exception(issuer.sendBootstrapForTest(left, leftSession, packet))
  await rightSession.close()
  await right.close()
  links.left.directory.destroy()
  links.right.directory.destroy()
})

test('test-only source matcher binds opaque endpoint handles to exact live sessions', async (t) => {
  const network = new Map()
  const issuer = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER]
  const rightReceived = []
  const leftA = issuer.createUdxCellEndpointForTest(
    options('127.0.0.1', 47113, []),
    issuer.createTestUdxAdapterAuthority(fakeFactory(network))
  )
  const leftB = issuer.createUdxCellEndpointForTest(
    options('127.0.0.2', 47114, []),
    issuer.createTestUdxAdapterAuthority(fakeFactory(network))
  )
  const right = issuer.createUdxCellEndpointForTest(
    options('127.0.0.3', 47115, rightReceived),
    issuer.createTestUdxAdapterAuthority(fakeFactory(network))
  )
  await Promise.all([leftA.bind(), leftB.bind(), right.bind()])
  const linksA = linkPair('127.0.0.1', 47113, '127.0.0.3', 47115)
  const linksB = linkPair('127.0.0.2', 47114, '127.0.0.3', 47115)
  const leftSessionA = leftA.openLink(linksA.left.handle, linkSessionOptions(linksA, 'left'))
  const leftSessionB = leftB.openLink(linksB.left.handle, linkSessionOptions(linksB, 'left'))
  const rightSessionA = right.openLink(linksA.right.handle, linkSessionOptions(linksA, 'right'))
  const rightSessionB = right.openLink(linksB.right.handle, linkSessionOptions(linksB, 'right'))
  const packet = b4a.alloc(BOOTSTRAP_SIZE)
  packet[1] = BOOTSTRAP_CLASS
  await issuer.sendBootstrapForTest(leftA, leftSessionA, packet)
  await issuer.sendBootstrapForTest(leftB, leftSessionB, packet)
  await settles()
  const handleA = rightReceived[0].handle
  const handleB = rightReceived[1].handle
  t.is(issuer.matchesLinkSessionSource(right, rightSessionA, handleA), true, 'same arm matches')
  t.is(issuer.matchesLinkSessionSource(right, rightSessionB, handleB), true, 'second arm matches')
  t.is(
    issuer.matchesLinkSessionSource(right, rightSessionB, handleA),
    false,
    'armed cross-arm handle does not match'
  )
  t.is(
    issuer.matchesLinkSessionSource(right, rightSessionA, Object.freeze({})),
    false,
    'structural substitute does not match'
  )
  await rightSessionA.close()
  t.is(
    issuer.matchesLinkSessionSource(right, rightSessionA, handleA),
    false,
    'closed arm no longer matches'
  )
  await Promise.allSettled([
    leftSessionA.close(),
    leftSessionB.close(),
    rightSessionB.close(),
    leftA.close(),
    leftB.close(),
    right.close()
  ])
  linksA.left.directory.destroy()
  linksA.right.directory.destroy()
  linksB.left.directory.destroy()
  linksB.right.directory.destroy()
})

test('openLink consumes the topology handle and never returns a raw send handle', async (t) => {
  const issuer = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER]
  const endpoint = issuer.createUdxCellEndpointForTest(
    options('127.0.0.1', 47118, []),
    issuer.createTestUdxAdapterAuthority(fakeFactory(new Map()))
  )
  await endpoint.bind()
  const links = linkPair('127.0.0.1', 47118, '127.0.0.2', 47119)
  let first = null
  let second = null
  try {
    endpoint.openLink(links.left.handle)
  } catch (err) {
    first = err
  }
  try {
    endpoint.openLink(links.left.handle, {})
  } catch (err) {
    second = err
  }
  t.is(first && first.code, 'INVALID_ROUTE')
  t.is(second && second.code, 'UNAUTHORIZED')
  await endpoint.close()
  links.left.directory.destroy()
  links.right.directory.destroy()
})

test('failed bootstrap authority creation consumes and clears its local-secret capability', async (t) => {
  const issuer = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER]
  const endpoint = issuer.createUdxCellEndpointForTest(
    options('127.0.0.1', 47121, []),
    issuer.createTestUdxAdapterAuthority(fakeFactory(new Map()))
  )
  const identity = cryptoSuite.keyPair(seed(97))
  const capability = createLocalIdentitySecretCapability({
    localIdentity: identity.publicKey,
    localSecretKey: identity.secretKey
  })
  t.exception(() =>
    createBootstrapUdxAuthority({
      endpoint,
      configuredEndpoints: [{ host: '127.0.0.2', port: 47122 }],
      localSecretCapability: capability,
      maxProspectiveGuards: 4,
      monotonicDeadline: 10_000
    })
  )
  let error = null
  try {
    createBootstrapUdxAuthority({
      endpoint,
      configuredEndpoints: [{ host: '127.0.0.2', port: 47122 }],
      localSecretCapability: capability,
      maxProspectiveGuards: 3,
      monotonicDeadline: 10_000
    })
  } catch (err) {
    error = err
  }
  t.is(error && error.code, 'UNAUTHORIZED')
  t.ok(
    identity.secretKey.some((byte) => byte !== 0),
    'caller secret remains untouched'
  )
  await endpoint.close()
})

test('direct records canonically encode numeric IPv4 and expanded IPv6 endpoints', (t) => {
  const canonicalDirectRecord = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER].canonicalDirectRecord
  t.alike(
    canonicalDirectRecord({ host: '192.0.2.44', port: 47120 }),
    encodeCanonicalEndpoint({
      addressFamily: 4,
      addressBytes: b4a.from([192, 0, 2, 44]),
      port: 47120
    })
  )
  t.alike(
    canonicalDirectRecord({ host: '2001:DB8::A:1', port: 47121 }),
    encodeCanonicalEndpoint({
      addressFamily: 6,
      addressBytes: b4a.from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a, 0, 1]),
      port: 47121
    })
  )
})

test('direct record canonicalization rejects malformed and non-numeric hosts', (t) => {
  const canonicalDirectRecord = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER].canonicalDirectRecord
  for (const host of [
    '192.0.2.999',
    '192.0.2',
    '2001:db8:::1',
    '2001:db8::1::2',
    '2001:db8:1',
    'bootstrap.example'
  ]) {
    let error = null
    try {
      canonicalDirectRecord({ host, port: 47122 })
    } catch (err) {
      error = err
    }
    t.is(error && error.code, 'INVALID_ROUTE', host)
  }
})

test('IPv6 relay advertisements remain incompatible at the HyperDHT compact-ID boundary', (t) => {
  const endpoint = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER].canonicalDirectRecord({
    host: '2001:db8::1',
    port: 47122
  })
  let error = null
  try {
    deriveM3DhtNodeId(endpoint)
  } catch (err) {
    error = err
  }
  t.is(error && error.code, 'ERR_INCOMPATIBLE_RELAY')
})

test('destroying an unconsumed production guard lease closes its original owner once', async (t) => {
  const fixture = await pinnedMaterialFixture(47125, 47126)
  const socket = fixture.leftObserver.sockets[0]
  t.is(socket.closed, false)
  t.is(socket.closeCalls, 0)
  t.is(destroyGuardLeaseMaterial(fixture.material), true)
  await settles()
  t.is(socket.closed, true)
  t.is(socket.closeCalls, 1)
  t.is(destroyGuardLeaseMaterial(fixture.material), false)
  await settles()
  t.is(socket.closeCalls, 1)
  await fixture.rightSession.close()
  await fixture.right.close()
  fixture.links.left.directory.destroy()
  fixture.links.right.directory.destroy()
})

test('bootstrap authority destroy closes socket but retains held native direct ownership', async (t) => {
  let releaseNative = null
  const heldNative = new Promise((resolve) => {
    releaseNative = resolve
  })
  const observer = {}
  const issuer = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER]
  const endpoint = issuer.createUdxCellEndpointForTest(
    options('127.0.0.1', 47123, []),
    issuer.createTestUdxAdapterAuthority(fakeFactory(new Map(), heldNative, observer))
  )
  await endpoint.bind()
  const identity = cryptoSuite.keyPair(seed(96))
  const authority = createBootstrapUdxAuthority({
    endpoint,
    configuredEndpoints: [{ host: '127.0.0.2', port: 47124 }],
    localSecretCapability: createLocalIdentitySecretCapability({
      localIdentity: identity.publicKey,
      localSecretKey: identity.secretKey
    }),
    maxProspectiveGuards: 3,
    monotonicDeadline: 10_000
  })
  bindBootstrapUdxOperation(authority, 10_000, Object.freeze({}))
  const sending = sendConfigured(authority, 0, b4a.alloc(BOOTSTRAP_SIZE))
  await settles()
  t.alike(endpoint[UDX_ENDPOINT_RESERVATION_STATS](), {
    packets: 1,
    bytes: BOOTSTRAP_SIZE
  })
  t.is(destroyBootstrapUdxAuthority(authority), true)
  const closing = endpoint.close()
  let closed = false
  void closing.then(() => {
    closed = true
  })
  await settles()
  t.is(observer.socket.closed, true)
  t.is(closed, false, 'endpoint close still waits for native completion')
  t.alike(endpoint[UDX_ENDPOINT_RESERVATION_STATS](), { packets: 1, bytes: BOOTSTRAP_SIZE })
  releaseNative(true)
  await t.exception(sending)
  await closing
  t.is(observer.socket.closed, true)
  t.alike(endpoint[UDX_ENDPOINT_RESERVATION_STATS](), { packets: 0, bytes: 0 })
})

test('detached reconnect transport is frozen exact and revokes during owner close', async (t) => {
  let releaseClose = null
  const closeHold = new Promise((resolve) => {
    releaseClose = resolve
  })
  const fixture = await pinnedMaterialFixture(47127, 47128, { closeHold })
  const lease = fixture.issuer.inspectGuardLeaseMaterial(fixture.material)
  const transport = lease.reconnectTransportFactory()
  t.alike(Reflect.ownKeys(transport).sort(), ['destroy', 'reconnect'])
  t.is(Object.isFrozen(transport), true)
  t.is(transport.send, undefined)
  t.exception(() => lease.reconnectTransportFactory())
  t.is(fixture.leftObserver.sockets.length, 1)
  t.is(destroyGuardLeaseMaterial(fixture.material), true)
  t.is(fixture.leftObserver.sockets.length, 1)
  releaseClose(true)
  await t.exception(transport.reconnect(Object.freeze({})))
  await settles()
  t.is(fixture.leftObserver.sockets.length, 1)
  t.is(fixture.leftObserver.sockets[0].closed, true)
  t.is(fixture.leftObserver.sockets[0].closeCalls, 1)
  await fixture.rightSession.close()
  await fixture.right.close()
  fixture.links.left.directory.destroy()
  fixture.links.right.directory.destroy()
})

test('detached reconnect transport destroy is idempotent and blocks fresh ownership', async (t) => {
  const fixture = await pinnedMaterialFixture(47135, 47136)
  const lease = fixture.issuer.inspectGuardLeaseMaterial(fixture.material)
  const transport = lease.reconnectTransportFactory()
  t.alike(Reflect.ownKeys(transport).sort(), ['destroy', 'reconnect'])
  t.is(Object.isFrozen(transport), true)
  t.is(transport.destroy(), true)
  t.is(transport.destroy(), false)
  await t.exception(transport.reconnect(Object.freeze({})))
  t.is(destroyGuardLeaseMaterial(fixture.material), true)
  await settles()
  t.is(fixture.leftObserver.sockets.length, 1)
  t.is(fixture.leftObserver.sockets[0].closed, true)
  await fixture.rightSession.close()
  await fixture.right.close()
  fixture.links.left.directory.destroy()
  fixture.links.right.directory.destroy()
})

test('bootstrap UDX authority consumes identity secret and revokes every direct send before pin', async (t) => {
  const network = new Map()
  const issuer = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER]
  const links = linkPair('127.0.0.1', 47131, '127.0.0.2', 47132)
  const leftObserver = {}
  let leftSession = null
  let rightSession = null
  const left = issuer.createUdxCellEndpointForTest(
    {
      ...options('127.0.0.1', 47131, []),
      onBootstrap(packet) {
        if (leftSession) void leftSession.receive(packet)
      }
    },
    issuer.createTestUdxAdapterAuthority(fakeFactory(network, null, leftObserver))
  )
  const right = issuer.createUdxCellEndpointForTest(
    {
      ...options('127.0.0.2', 47132, []),
      onBootstrap(packet) {
        if (rightSession) void rightSession.receive(packet)
      }
    },
    issuer.createTestUdxAdapterAuthority(fakeFactory(network))
  )
  await left.bind()
  await right.bind()
  const secret = createLocalIdentitySecretCapability({
    localIdentity: links.a.publicKey,
    localSecretKey: links.a.secretKey
  })
  const authority = createBootstrapUdxAuthority({
    endpoint: left,
    configuredEndpoints: [{ host: '127.0.0.2', port: 47132 }],
    localSecretCapability: secret,
    maxProspectiveGuards: 3,
    monotonicDeadline: 10_000
  })
  await t.exception(sendConfigured(authority, 0, b4a.alloc(BOOTSTRAP_SIZE)))
  bindBootstrapUdxOperation(authority, 10_000, Object.freeze({}))
  const admission = admitBootstrapUdxGuard(authority, {
    identity: links.b.publicKey,
    host: '127.0.0.2',
    port: 47132
  })
  t.exception(() =>
    issuer.createTestBootstrapUdxLinkReservation(authority, admission, async () => true)
  )
  const probe = b4a.alloc(BOOTSTRAP_SIZE)
  probe[1] = BOOTSTRAP_CLASS
  t.is(await sendConfigured(authority, 0, probe), true)
  t.is(await sendProspectiveGuard(authority, admission, probe), true)

  const now = () => 1
  const sequence = (first) => {
    let value = first
    return (size) => b4a.alloc(size, value++)
  }
  const common = {
    circuitId: b4a.alloc(16, 0x51),
    epoch: 7n,
    initiatorIdentity: links.a.publicKey,
    responderIdentity: links.b.publicKey,
    initiatorLocalId: b4a.alloc(16, 0x52),
    responderLocalId: b4a.alloc(16, 0x53),
    expiresAt: 60_000n
  }
  const leftSessionOptions = createBootstrapUdxGuardSessionOptions(
    authority,
    admission,
    links.left.handle,
    {
      circuitId: common.circuitId,
      epoch: common.epoch,
      initiatorLocalId: common.initiatorLocalId,
      responderLocalId: common.responderLocalId,
      expiresAt: common.expiresAt,
      responderStaticKey: cryptoSuite.encryptionKeyPair(seed(98)).publicKey,
      now,
      wallNow: now,
      handleNow: now,
      schedule: setTimeout,
      cancel: clearTimeout,
      randomBytes: sequence(1),
      absoluteDeadline: 10_000,
      signedExpiry: 60_000
    }
  )
  leftSession = openBootstrapUdxGuard(authority, admission, links.left.handle, leftSessionOptions)
  const responderStatic = cryptoSuite.encryptionKeyPair(seed(98))
  rightSession = right.openLink(links.right.handle, {
    mode: 'accept',
    codec: new BootstrapEnvelopeCodec({
      linkHandle: links.right.handle,
      localIdentitySecretKey: links.b.secretKey,
      padding: sequence(0x91)
    }),
    linkSetup: createLinkSetupAuthority({ now, randomBytes: sequence(0x71) }),
    setup: {
      ...common,
      responderStaticSecretKey: responderStatic.secretKey,
      responderIdentitySecretKey: links.b.secretKey
    },
    now,
    schedule: setTimeout,
    cancel: clearTimeout,
    randomBytes: sequence(11),
    absoluteDeadline: 10_000,
    signedExpiry: 60_000,
    authorizedExpiry: 60_000
  })
  const otherLinks = linkPair('127.0.0.1', 47131, '127.0.0.4', 47134)
  const otherSession = left.openLink(otherLinks.left.handle, linkSessionOptions(otherLinks, 'left'))
  const established = await leftSession.open()
  const substitutedEndpoint = issuer.createUdxCellEndpointForTest(
    options('127.0.0.3', 47133, []),
    issuer.createTestUdxAdapterAuthority(fakeFactory(network))
  )
  await substitutedEndpoint.bind()
  const substitutedSecret = createLocalIdentitySecretCapability({
    localIdentity: links.a.publicKey,
    localSecretKey: links.a.secretKey
  })
  const substitutedAuthority = createBootstrapUdxAuthority({
    endpoint: substitutedEndpoint,
    configuredEndpoints: [{ host: '127.0.0.2', port: 47139 }],
    localSecretCapability: substitutedSecret,
    maxProspectiveGuards: 3,
    monotonicDeadline: 10_000
  })
  bindBootstrapUdxOperation(substitutedAuthority, 10_000, Object.freeze({}))
  const substitutedAdmission = admitBootstrapUdxGuard(substitutedAuthority, {
    identity: links.b.publicKey,
    host: '127.0.0.2',
    port: 47139
  })
  let substitutedMaterial = null
  let substitutionError = null
  try {
    substitutedMaterial = pinBootstrapUdxGuard(
      substitutedAuthority,
      substitutedAdmission,
      established
    )
  } catch (err) {
    substitutionError = err
  }
  t.is(substitutionError && substitutionError.code, 'UNAUTHORIZED')
  if (substitutedMaterial) destroyGuardLeaseMaterial(substitutedMaterial)
  destroyBootstrapUdxAuthority(substitutedAuthority)
  await substitutedEndpoint.close()
  const material = pinBootstrapUdxGuard(authority, admission, established)
  t.is(Object.keys(material).length, 0)
  t.is(isGuardLeaseMaterial(material), true)
  const lease = issuer.inspectGuardLeaseMaterial(material)
  t.is(lease.reconnectTransportFactory.length, 0)
  t.exception(() => lease.reconnectTransportFactory('127.0.0.2'))
  const originalSocket = leftObserver.sockets[0]
  let reconnectTransport = null
  let reconnectError = null
  try {
    reconnectTransport = lease.reconnectTransportFactory()
  } catch (err) {
    reconnectError = err
  }
  t.is(reconnectError, null)
  if (reconnectTransport) {
    t.alike(Reflect.ownKeys(reconnectTransport).sort(), ['destroy', 'reconnect'])
    t.is(Object.isFrozen(reconnectTransport), true)
    t.is(reconnectTransport.send, undefined)
    t.is(leftObserver.sockets.length, 1, 'fresh owner waits for authenticated reconnect')
    t.exception(() => lease.reconnectTransportFactory())
    t.is(reconnectTransport.destroy(), true)
    t.is(reconnectTransport.destroy(), false)
    await t.exception(reconnectTransport.reconnect(Object.freeze({})))
    await settles()
    t.is(originalSocket.closed, true)
    t.is(originalSocket.closeCalls, 1)
    t.is(leftObserver.sockets.length, 1)
    t.alike(
      leftObserver.events.map(([event]) => event),
      ['create', 'close']
    )
  }
  t.is(otherSession.state, 'TOMBSTONE')
  await t.exception(issuer.sendBootstrapForTest(left, otherSession, probe))
  await t.exception(sendConfigured(authority, 0, probe))
  await t.exception(sendProspectiveGuard(authority, admission, probe))
  t.is(destroyGuardLeaseMaterial(material), true)
  t.is(destroyGuardLeaseMaterial(material), false)
  await rightSession.close()
  await right.close()
  links.left.directory.destroy()
  links.right.directory.destroy()
  otherLinks.left.directory.destroy()
  otherLinks.right.directory.destroy()
})

test('outbound capacity reserves before allocation and close waits native ownership', async (t) => {
  const network = new Map()
  let releaseNative
  const heldNative = new Promise((resolve) => {
    releaseNative = resolve
  })
  const observer = {}
  const issuer = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER]
  const endpoint = issuer.createUdxCellEndpointForTest(
    options('127.0.0.1', 47141, [], { maxQueuedPackets: 1, maxQueuedBytes: BOOTSTRAP_SIZE }),
    issuer.createTestUdxAdapterAuthority(fakeFactory(network, heldNative, observer))
  )
  await endpoint.bind()
  const links = linkPair('127.0.0.1', 47141, '127.0.0.2', 47142)
  const session = endpoint.openLink(links.left.handle, linkSessionOptions(links, 'left'))
  const packet = b4a.alloc(BOOTSTRAP_SIZE)
  packet[1] = BOOTSTRAP_CLASS
  const failedFrom = b4a.from
  b4a.from = (...args) => {
    if (args[0] === packet) throw new Error('allocation failed')
    return failedFrom(...args)
  }
  try {
    await t.exception(issuer.sendBootstrapForTest(endpoint, session, packet))
  } finally {
    b4a.from = failedFrom
  }
  t.alike(endpoint[UDX_ENDPOINT_RESERVATION_STATS](), { packets: 0, bytes: 0 })
  let acceptedReservation = null
  const acceptedFrom = b4a.from
  b4a.from = (...args) => {
    if (args[0] === packet && acceptedReservation === null) {
      acceptedReservation = endpoint[UDX_ENDPOINT_RESERVATION_STATS]()
    }
    return acceptedFrom(...args)
  }
  let first
  try {
    first = issuer.sendBootstrapForTest(endpoint, session, packet)
  } finally {
    b4a.from = acceptedFrom
  }
  t.alike(acceptedReservation, { packets: 1, bytes: BOOTSTRAP_SIZE })
  await Promise.resolve()
  let allocations = 0
  const originalFrom = b4a.from
  b4a.from = (...args) => {
    if (b4a.isBuffer(args[0]) && args[0].byteLength === BOOTSTRAP_SIZE) allocations++
    return originalFrom(...args)
  }
  let secondError = null
  try {
    await issuer.sendBootstrapForTest(endpoint, session, packet)
  } catch (err) {
    secondError = err
  } finally {
    b4a.from = originalFrom
  }
  t.is(secondError && secondError.code, 'CIRCUIT_LIMIT')
  t.is(allocations, 0, 'rejected capacity allocates no owned packet')
  const closing = endpoint.close()
  await Promise.resolve()
  t.is(observer.socket.closed, true, 'socket close starts before waiting for native ownership')
  t.alike(endpoint[UDX_ENDPOINT_RESERVATION_STATS](), { packets: 1, bytes: BOOTSTRAP_SIZE })
  releaseNative(true)
  let firstError = null
  try {
    await first
  } catch (err) {
    firstError = err
  }
  t.is(firstError && firstError.code, 'ROUTE_UNAVAILABLE')
  await closing
  t.is(observer.socket.closed, true)
  links.left.directory.destroy()
  links.right.directory.destroy()
})

test('outbound option getter close releases reservation before copy or native send', async (t) => {
  const observer = {}
  const issuer = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER]
  const endpoint = issuer.createUdxCellEndpointForTest(
    options('127.0.0.1', 47145, []),
    issuer.createTestUdxAdapterAuthority(fakeFactory(new Map(), null, observer))
  )
  await endpoint.bind()
  const links = linkPair('127.0.0.1', 47145, '127.0.0.2', 47146)
  const session = endpoint.openLink(links.left.handle, linkSessionOptions(links, 'left'))
  const packet = b4a.alloc(BOOTSTRAP_SIZE)
  packet[1] = BOOTSTRAP_CLASS
  let nativeSends = 0
  observer.socket.send = () => {
    nativeSends++
    return true
  }
  let closing = null
  let copies = 0
  const originalFrom = b4a.from
  b4a.from = (...args) => {
    if (args[0] === packet) copies++
    return originalFrom(...args)
  }
  try {
    await t.exception(
      issuer.sendBootstrapWithOptionsForTest(endpoint, session, packet, {
        get signal() {
          closing = endpoint.close()
          return undefined
        }
      })
    )
  } finally {
    b4a.from = originalFrom
  }
  await closing
  t.alike(endpoint[UDX_ENDPOINT_RESERVATION_STATS](), { packets: 0, bytes: 0 })
  t.is(copies, 0)
  t.is(nativeSends, 0)
  links.left.directory.destroy()
  links.right.directory.destroy()
})

test('inbound global/per-peer ownership drops excess, late, address-changed, and unreserved packets', async (t) => {
  const network = new Map()
  const issuer = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER]
  const received = []
  let releaseFirst
  const held = new Promise((resolve) => {
    releaseFirst = resolve
  })
  const rightObserver = {}
  const left = issuer.createUdxCellEndpointForTest(
    options('127.0.0.1', 47151, []),
    issuer.createTestUdxAdapterAuthority(fakeFactory(network))
  )
  const right = issuer.createUdxCellEndpointForTest(
    options('127.0.0.2', 47152, received, {
      maxInboundPackets: 1,
      maxInboundBytes: BOOTSTRAP_SIZE,
      maxInboundPacketsPerPeer: 1,
      maxInboundBytesPerPeer: BOOTSTRAP_SIZE,
      onBootstrap(packet) {
        received.push(b4a.from(packet))
        if (received.length === 1) return held
      }
    }),
    issuer.createTestUdxAdapterAuthority(fakeFactory(network, null, rightObserver))
  )
  await left.bind()
  await right.bind()
  const links = linkPair('127.0.0.1', 47151, '127.0.0.2', 47152)
  const leftSession = left.openLink(links.left.handle, linkSessionOptions(links, 'left'))
  const rightSession = right.openLink(links.right.handle, linkSessionOptions(links, 'right'))
  const packet = b4a.alloc(BOOTSTRAP_SIZE)
  packet[1] = BOOTSTRAP_CLASS
  let reentered = false
  const reentrantFrom = b4a.from
  b4a.from = (...args) => {
    if (args[0] === packet && !reentered) {
      reentered = true
      rightObserver.socket.emit('message', packet, { host: '127.0.0.1', port: 47151 })
    }
    return reentrantFrom(...args)
  }
  try {
    rightObserver.socket.emit('message', packet, { host: '127.0.0.1', port: 47151 })
  } finally {
    b4a.from = reentrantFrom
  }
  await settles()
  t.is(received.length, 1, 'reserved receive capacity is visible before packet allocation re-entry')
  await issuer.sendBootstrapForTest(left, leftSession, packet)
  await settles()
  t.is(received.length, 1, 'inbound owner drops excess while first callback owns bytes')
  rightObserver.socket.emit('message', packet, { host: '127.0.0.9', port: 47151 })
  rightObserver.socket.emit('message', packet, { host: '127.0.0.1', port: 47159 })
  await settles()
  t.is(received.length, 1, 'address changes and unreserved tuples are dropped')
  releaseFirst(true)
  await settles()
  const failedFrom = b4a.from
  b4a.from = (...args) => {
    if (args[0] === packet) throw new Error('allocation failed')
    return failedFrom(...args)
  }
  try {
    rightObserver.socket.emit('message', packet, { host: '127.0.0.1', port: 47151 })
  } finally {
    b4a.from = failedFrom
  }
  await settles()
  t.is(received.length, 1, 'failed allocation rolls back reserved receive capacity')
  await issuer.sendBootstrapForTest(left, leftSession, packet)
  await settles()
  t.is(received.length, 2, 'capacity returns only after callback settlement')
  await right.close()
  rightObserver.socket.emit('message', packet, { host: '127.0.0.1', port: 47151 })
  await settles()
  t.is(received.length, 2, 'late receive after close is inert')
  await left.close()
  await rightSession.close()
  links.left.directory.destroy()
  links.right.directory.destroy()
})

test('direct bootstrap receive reserves before allocation re-entry and rolls back failure', async (t) => {
  const issuer = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER]
  const observer = {}
  let received = 0
  let releaseFirst
  const held = new Promise((resolve) => {
    releaseFirst = resolve
  })
  const endpoint = issuer.createUdxCellEndpointForTest(
    options('127.0.0.2', 47162, [], {
      maxInboundPackets: 1,
      maxInboundBytes: BOOTSTRAP_SIZE,
      maxInboundPacketsPerPeer: 1,
      maxInboundBytesPerPeer: BOOTSTRAP_SIZE,
      onBootstrap() {
        received++
        if (received === 1) return held
      }
    }),
    issuer.createTestUdxAdapterAuthority(fakeFactory(new Map(), null, observer))
  )
  await endpoint.bind()
  const identity = cryptoSuite.keyPair(seed(110))
  const authority = createBootstrapUdxAuthority({
    endpoint,
    configuredEndpoints: [{ host: '127.0.0.1', port: 47161 }],
    localSecretCapability: createLocalIdentitySecretCapability({
      localIdentity: identity.publicKey,
      localSecretKey: identity.secretKey
    }),
    maxProspectiveGuards: 3,
    monotonicDeadline: 10_000
  })
  bindBootstrapUdxOperation(authority, 10_000, Object.freeze({}))
  const packet = b4a.alloc(BOOTSTRAP_SIZE)
  packet[1] = BOOTSTRAP_CLASS
  const source = { host: '127.0.0.1', port: 47161 }
  let reentered = false
  const reentrantFrom = b4a.from
  b4a.from = (...args) => {
    if (args[0] === packet && !reentered) {
      reentered = true
      observer.socket.emit('message', packet, source)
    }
    return reentrantFrom(...args)
  }
  try {
    observer.socket.emit('message', packet, source)
  } finally {
    b4a.from = reentrantFrom
  }
  await settles()
  t.is(received, 1, 'direct receive capacity is visible before packet allocation re-entry')
  releaseFirst(true)
  await settles()
  const failedFrom = b4a.from
  b4a.from = (...args) => {
    if (args[0] === packet) throw new Error('allocation failed')
    return failedFrom(...args)
  }
  try {
    observer.socket.emit('message', packet, source)
  } finally {
    b4a.from = failedFrom
  }
  await settles()
  observer.socket.emit('message', packet, source)
  await settles()
  t.is(received, 2, 'direct allocation failure releases capacity for the next packet')
  destroyBootstrapUdxAuthority(authority)
  await endpoint.close()
})

test('endpoint-wide close releases a send completed by socket close', async (t) => {
  let releaseHold
  const heldSend = new Promise((resolve) => {
    releaseHold = resolve
  })
  const observer = {}
  const issuer = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER]
  const endpoint = issuer.createUdxCellEndpointForTest(
    options('127.0.0.1', 47199, []),
    issuer.createTestUdxAdapterAuthority(fakeFactory(new Map(), heldSend, observer))
  )
  await endpoint.bind()
  const socket = observer.socket
  const originalClose = socket.close.bind(socket)
  socket.close = () => {
    releaseHold(false)
    return originalClose()
  }
  const links = linkPair('127.0.0.1', 47199, '127.0.0.2', 47200)
  t.teardown(() => {
    links.left.directory.destroy()
    links.right.directory.destroy()
  })
  const session = endpoint.openLink(links.left.handle, linkSessionOptions(links, 'left'))
  const packet = b4a.alloc(BOOTSTRAP_SIZE)
  packet[1] = BOOTSTRAP_CLASS
  const sending = issuer.sendBootstrapForTest(endpoint, session, packet)
  await settles()
  t.alike(endpoint[UDX_ENDPOINT_RESERVATION_STATS](), { packets: 1, bytes: BOOTSTRAP_SIZE })
  await endpoint.close()
  await t.exception(sending)
  t.alike(endpoint[UDX_ENDPOINT_RESERVATION_STATS](), { packets: 0, bytes: 0 })
})

test('Native: stored deadline unchanged by wall rollback and forward wall expiry rejects', async (t) => {
  const { setupTwoEndedNativeAdjacency, fakeClock } = require('./peer-native-fixture')
  const { readPeerEstablishedLinkBinding } = require('../../lib/private/udx-cell-endpoint')

  const clock = fakeClock(10_000n)
  const f = await setupTwoEndedNativeAdjacency({ t, clock, localPort: 48511, peerPort: 48512 })
  const established = f.neighbor.established
  const owner = f.localRelayOwner

  const binding1 = readPeerEstablishedLinkBinding(established, owner)
  const initialDeadline = binding1.parentLocalDeadline
  const initialMono = clock.monotonicNow()

  // Wall clock rollback only
  clock.advanceWall(-2000)
  t.is(clock.monotonicNow(), initialMono, 'monotonic remains unchanged during wall rollback')
  const binding2 = readPeerEstablishedLinkBinding(established, owner)
  t.is(binding2.parentLocalDeadline, initialDeadline, 'stored deadline unchanged by wall rollback')

  // Forward wall expiry rejects while monotonic remains below deadline
  const remainingToExpiry = Number(binding1.parentWireExpiresAt - BigInt(clock.wallNow())) + 10
  clock.advanceWall(remainingToExpiry)
  t.ok(
    BigInt(clock.monotonicNow()) < binding1.parentLocalDeadline,
    'monotonic still below local deadline'
  )
  let expireErr = null
  try {
    readPeerEstablishedLinkBinding(established, owner)
  } catch (err) {
    expireErr = err
  }
  t.is(expireErr && expireErr.code, 'UNAUTHORIZED', 'forward wall expiry rejects')
})

test('Native: ordinary traffic cannot access teardown ledger, forged closure tokens reject', async (t) => {
  const { authenticatedPeer } = require('./peer-native-fixture')
  const {
    takePeerEstablishedLink,
    destroyTakenPeerEstablishedLink
  } = require('../../lib/private/peer-guard-link')
  const { registerPeerM3CellLinkTransfer } = require('../../lib/private/udx-cell-endpoint')
  const { CellCodec } = require('../../lib/private/cell-codec')
  const { CELL_CLASS, DIRECTION } = require('../../lib/private/protocol')
  const { readPeerLedger } = require('../../lib/private/peer-ledger')
  const { receivePeerM3Payload } = require('../../lib/private/peer-m3-adjacency-runtime')
  const p = await authenticatedPeer(t, 48611)
  const taken = takePeerEstablishedLink(p.handle)
  const transfer = registerPeerM3CellLinkTransfer(taken.physicalChannel, taken.m3BranchBinding)
  t.teardown(() => {
    transfer.destroy()
    destroyTakenPeerEstablishedLink(taken)
  })
  await t.exception(transfer.sendClosure(Object.freeze({})), { code: 'UNAUTHORIZED' })
  const codec = new CellCodec({ crypto: cryptoSuite, cellSize: BOOTSTRAP_SIZE })
  const { SenderCounter } = require('../../lib/private/counters')
  t.not(taken.linkEpoch, taken.generation, 'the clear header epoch is not the circuit generation')
  for (const cellClass of [CELL_CLASS.DATAGRAM, CELL_CLASS.CONTROL]) {
    const context = taken.contexts[cellClass].tx
    const payload = b4a.from('ordinary authenticated payload')
    const sealWithEpoch = (epoch, senderCounter) =>
      codec.seal({
        key: context.key,
        noncePrefix: context.noncePrefix,
        senderCounter,
        class: cellClass,
        direction: DIRECTION.FORWARD,
        epoch,
        circuitId: taken.peerLocalId,
        payload
      })
    // The refused probe spends a throwaway counter so the ordered lane keeps no gap.
    await t.exception(
      transfer.send(sealWithEpoch(taken.generation, new SenderCounter()), taken.sendLedger),
      { code: 'UNAUTHORIZED' }
    )
    const packet = sealWithEpoch(taken.linkEpoch, context.counter)
    await t.exception(transfer.send(packet, taken.teardownSendLedger), { code: 'UNAUTHORIZED' })
    const receiving = receivePeerM3Payload(p.peerRuntime)
    await transfer.send(packet, taken.sendLedger)
    t.alike(await receiving, payload, 'same authenticated packet succeeds on its ordinary ledger')
  }
  t.is(readPeerLedger(p.localLedgers.teardownSendLedger).cellsSpent, 0)
})

test('Native: genuine closure dispatch charges teardown partition and releases its branch', async (t) => {
  const { authenticatedPeer } = require('./peer-native-fixture')
  const { readPeerLedger } = require('../../lib/private/peer-ledger')
  const { readPeerNativeNeighborDiagnostics } = require('../../lib/private/peer-native-neighbors')
  const {
    adoptPeerEstablishedLink,
    beginPeerM3BranchTeardown
  } = require('../../lib/private/peer-m3-adjacency-runtime')
  const p = await authenticatedPeer(t, 48631)
  const localRuntime = adoptPeerEstablishedLink(p.localAuthority, p.handle)
  const ordinaryBefore = readPeerLedger(p.localLedgers.sendLedger)
  t.is(await beginPeerM3BranchTeardown(localRuntime, b4a.alloc(16, 0x99)), true)
  const spent = readPeerLedger(p.localLedgers.teardownSendLedger)
  t.is(spent.commandsSpent, 1)
  t.is(spent.cellsSpent, 1)
  t.is(spent.bytesSpent, 1200n)
  t.is(readPeerLedger(p.localLedgers.sendLedger).cellsSpent, ordinaryBefore.cellsSpent)
  t.is(readPeerNativeNeighborDiagnostics(p.f.pool).reservationCount, 0)
})

test('authenticated six- and seven-byte closure prefixes fail without ordinary delivery', async (t) => {
  const { authenticatedPeer } = require('./peer-native-fixture')
  const {
    takePeerEstablishedLink,
    destroyTakenPeerEstablishedLink
  } = require('../../lib/private/peer-guard-link')
  const { registerPeerM3CellLinkTransfer } = require('../../lib/private/udx-cell-endpoint')
  const { CellCodec } = require('../../lib/private/cell-codec')
  const { CELL_CLASS, DIRECTION } = require('../../lib/private/protocol')
  const {
    receivePeerM3Payload,
    isPeerM3Runtime
  } = require('../../lib/private/peer-m3-adjacency-runtime')
  const { PEER_PROTOCOL_VERSION } = require('../../lib/private/peer-protocol')
  let port = 48700
  for (const cellClass of [CELL_CLASS.DATAGRAM, CELL_CLASS.CONTROL]) {
    for (const size of [6, 7]) {
      for (const messageId of [0x030e, 0x030f, 0x0310]) {
        const p = await authenticatedPeer(t, port)
        port += 2
        const taken = takePeerEstablishedLink(p.handle)
        const transfer = registerPeerM3CellLinkTransfer(
          taken.physicalChannel,
          taken.m3BranchBinding
        )
        try {
          const payload = b4a.alloc(size)
          b4a.writeUInt32BE(payload, PEER_PROTOCOL_VERSION, 0)
          payload[4] = messageId >>> 8
          payload[5] = messageId & 0xff
          const context = taken.contexts[cellClass].tx
          const codec = new CellCodec({ crypto: cryptoSuite, cellSize: BOOTSTRAP_SIZE })
          const packet = codec.seal({
            key: context.key,
            noncePrefix: context.noncePrefix,
            senderCounter: context.counter,
            class: cellClass,
            direction: DIRECTION.FORWARD,
            epoch: taken.linkEpoch,
            circuitId: taken.peerLocalId,
            payload
          })
          const receiving = receivePeerM3Payload(p.peerRuntime)
          const rejected = t.exception(receiving, { code: 'ERR_DESTROYED' })
          await transfer.send(packet, taken.sendLedger)
          await rejected
          t.is(isPeerM3Runtime(p.peerRuntime), false)
        } finally {
          transfer.destroy()
          destroyTakenPeerEstablishedLink(taken)
        }
      }
    }
  }
})

test('twelve authenticated teardown requests cannot exceed one branch reserve or borrow from a sibling', async (t) => {
  const { authenticatedPeer } = require('./peer-native-fixture')
  const {
    takePeerEstablishedLink,
    destroyTakenPeerEstablishedLink
  } = require('../../lib/private/peer-guard-link')
  const {
    registerPeerM3CellLinkTransfer,
    releaseM3CellLinkPacket
  } = require('../../lib/private/udx-cell-endpoint')
  const { CellCodec } = require('../../lib/private/cell-codec')
  const { CELL_CLASS, DIRECTION } = require('../../lib/private/protocol')
  const { PEER_MESSAGE_ID } = require('../../lib/private/peer-protocol')
  const { encodePeerTransport } = require('../../lib/private/peer-transport-wire')
  const { readPeerLedger } = require('../../lib/private/peer-ledger')
  const {
    adoptPeerEstablishedLink,
    isPeerM3Runtime,
    beginPeerM3BranchTeardown
  } = require('../../lib/private/peer-m3-adjacency-runtime')
  const p = await authenticatedPeer(t, 48740)
  const sibling = await p.openAdditional()
  const siblingRuntime = adoptPeerEstablishedLink(p.localAuthority, sibling.handle)
  const taken = takePeerEstablishedLink(p.handle)
  const transfer = registerPeerM3CellLinkTransfer(taken.physicalChannel, taken.m3BranchBinding)
  const codec = new CellCodec({ crypto: cryptoSuite, cellSize: BOOTSTRAP_SIZE })
  const context = taken.contexts[CELL_CLASS.DATAGRAM].tx
  const payload = encodePeerTransport(PEER_MESSAGE_ID.PEER_BRANCH_TEARDOWN_V2, {
    branchClass: 2,
    branchId: taken.branchId,
    circuitId: taken.circuitId,
    generation: taken.generation,
    reason: 2,
    teardownId: b4a.alloc(16, 0x7b)
  })
  try {
    for (let attempt = 0; attempt < 12; attempt++) {
      const packet = codec.seal({
        key: context.key,
        noncePrefix: context.noncePrefix,
        senderCounter: context.counter,
        class: CELL_CLASS.DATAGRAM,
        direction: DIRECTION.FORWARD,
        epoch: taken.linkEpoch,
        circuitId: taken.peerLocalId,
        payload
      })
      await transfer.send(packet, taken.sendLedger)
      await settles()
      if (attempt < 10) releaseM3CellLinkPacket(await transfer.receive())
      if (attempt === 9) {
        t.is(
          p.peerRuntime.diagnostics().state,
          'ACK_CACHED',
          'ten requests retain the original ACK cache'
        )
      }
    }
    t.is(readPeerLedger(p.peerLedgers.teardownReceiveLedger).cellsSpent, 10)
    t.is(readPeerLedger(p.peerLedgers.teardownReceiveLedger).commandsSpent, 1)
    t.is(readPeerLedger(p.peerLedgers.teardownSendLedger).cellsSpent, 10)
    t.is(readPeerLedger(p.peerLedgers.teardownSendLedger).commandsSpent, 1)
    t.is(
      isPeerM3Runtime(p.peerRuntime),
      false,
      'excess authenticated closure traffic closes only its own branch'
    )
    t.is(await beginPeerM3BranchTeardown(siblingRuntime, b4a.alloc(16, 0x7e)), true)
    t.is(
      readPeerLedger(p.peerLedgers.teardownSendLedger).cellsSpent,
      11,
      'the sibling retains its own ACK allowance'
    )
    t.is(readPeerLedger(p.peerLedgers.teardownReceiveLedger).cellsSpent, 11)
  } finally {
    transfer.destroy()
    destroyTakenPeerEstablishedLink(taken)
  }
})

test('authenticated ordinary CONTROL spends no physical-closure allowance', async (t) => {
  const { authenticatedPeer } = require('./peer-native-fixture')
  const {
    takePeerEstablishedLink,
    destroyTakenPeerEstablishedLink
  } = require('../../lib/private/peer-guard-link')
  const { registerPeerM3CellLinkTransfer } = require('../../lib/private/udx-cell-endpoint')
  const { receivePeerM3Payload } = require('../../lib/private/peer-m3-adjacency-runtime')
  const { readPeerLedger } = require('../../lib/private/peer-ledger')
  const { CellCodec } = require('../../lib/private/cell-codec')
  const { CELL_CLASS, DIRECTION } = require('../../lib/private/protocol')
  const p = await authenticatedPeer(t, 48742)
  const taken = takePeerEstablishedLink(p.handle)
  const transfer = registerPeerM3CellLinkTransfer(taken.physicalChannel, taken.m3BranchBinding)
  const codec = new CellCodec({ crypto: cryptoSuite, cellSize: BOOTSTRAP_SIZE })
  const context = taken.contexts[CELL_CLASS.CONTROL].tx
  const payload = b4a.from('ordinary authenticated control')
  const before = readPeerLedger(p.peerLedgers.receiveLedger)
  try {
    const received = receivePeerM3Payload(p.peerRuntime)
    await transfer.send(
      codec.seal({
        key: context.key,
        noncePrefix: context.noncePrefix,
        senderCounter: context.counter,
        class: CELL_CLASS.CONTROL,
        direction: DIRECTION.FORWARD,
        epoch: taken.linkEpoch,
        circuitId: taken.peerLocalId,
        payload
      }),
      taken.sendLedger
    )
    t.alike(await received, payload)
    t.is(readPeerLedger(p.peerLedgers.receiveLedger).cellsSpent, before.cellsSpent + 1)
    t.is(readPeerLedger(p.peerLedgers.receiveLedger).commandsSpent, before.commandsSpent + 1)
    t.is(readPeerLedger(p.peerLedgers.teardownReceiveLedger).cellsSpent, 0)
    t.is(readPeerLedger(p.peerLedgers.teardownReceiveLedger).commandsSpent, 0)
  } finally {
    transfer.destroy()
    destroyTakenPeerEstablishedLink(taken)
  }
})

// Real DHT nodes, real sockets and one real coherent clock: a leased private endpoint
// shares the DHT's bound socket without binding or closing it.
async function leasedDiscoveryPair(t, sequence = null) {
  const createTestnet = require('../../testnet')
  const process = require('process')
  const { createCoherentClock } = require('../../lib/private/runtime-clock')
  const { createPeerLedger } = require('../../lib/private/peer-ledger')
  const {
    createPeerRelayOwner,
    readPeerRelayOwner,
    verifyPeerAdvertisement,
    createPeerCandidateLocator,
    destroyPeerRelayOwner
  } = require('../../lib/private/peer-capability')
  const {
    createPeerBootstrapResponder,
    destroyPeerBootstrapResponder
  } = require('../../lib/private/peer-direct-bootstrap')

  const testnet = await createTestnet(3, { host: '127.0.0.1' })
  const coherent = createCoherentClock(() => process.hrtime.bigint(), Date.now)
  const clocks = {
    clockIdentity: coherent,
    wallNow: coherent.wallNow,
    monotonicNow: coherent.monotonicNow,
    setTimer: setTimeout,
    clearTimer: clearTimeout
  }
  const relayNode = testnet.nodes[1]
  const sourceNode = testnet.nodes[2]
  const relayLease = endpointModule.leaseDhtUdxSocket(relayNode.io.serverSocket, 1, sequence)
  const sourceLease = endpointModule.leaseDhtUdxSocket(sourceNode.io.serverSocket, 2, sequence)
  const endpointFor = (lease) => {
    const tuple = endpointModule.readDhtUdxSocketLease(lease)
    return endpointModule.createLeasedUdxCellEndpoint(
      {
        host: tuple.host,
        port: tuple.port,
        onBootstrap() {},
        onCell() {},
        onLinkFailure() {}
      },
      lease
    )
  }
  const relayEndpoint = endpointFor(relayLease)
  const sourceEndpoint = endpointFor(sourceLease)
  await relayEndpoint.bind()
  await sourceEndpoint.bind()

  const now = coherent.wallNow()
  const adFields = (ed, x, endpoint, mask) => ({
    relayIdentity32: ed.publicKey,
    currentDhtNodeId32: cryptoSuite.hash(ed.publicKey),
    reachableEndpoint: endpoint,
    routeEncryptionPublicKey32: x.publicKey,
    capabilityMask: mask,
    minimumVersion: 3,
    maximumVersion: 3,
    datagramReplayWindow: 64,
    maxConcurrentCircuits: 8,
    capacityClass: 1,
    maxCells: 1000,
    maxBytes: 1_200_000,
    maxCommands: 1000,
    idleTimeoutMs: 30000,
    maxQueuedBytes: 524288,
    epoch: 1n,
    issuedAt: now - 1000n,
    expiresAt: now + 600_000n,
    policyCount: 0
  })
  const relayEd = cryptoSuite.keyPair()
  const relayX = cryptoSuite.encryptionKeyPair()
  const relayAddress = { host: '127.0.0.1', port: relayNode.port }
  const relayOwner = createPeerRelayOwner({
    endpoint: relayEndpoint,
    identityKeyPair: relayEd,
    routeKeyPair: relayX,
    advertisementFields: adFields(relayEd, relayX, relayAddress, 11),
    ...clocks
  })
  const responder = createPeerBootstrapResponder(relayOwner)
  const registration = endpointModule.registerPeerDirectResponder(relayEndpoint, responder)
  const sourceEd = cryptoSuite.keyPair()
  const sourceX = cryptoSuite.encryptionKeyPair()
  const sourceOwner = createPeerRelayOwner({
    endpoint: sourceEndpoint,
    identityKeyPair: sourceEd,
    routeKeyPair: sourceX,
    advertisementFields: adFields(
      sourceEd,
      sourceX,
      { host: '127.0.0.1', port: sourceNode.port },
      11
    ),
    ...clocks
  })
  const verifiedRelay = verifyPeerAdvertisement(
    readPeerRelayOwner(relayOwner, relayEndpoint).canonicalAdvertisement260,
    {
      expectedIdentity32: relayEd.publicKey,
      expectedCapabilityMask: 11,
      clockIdentity: coherent,
      wallNow: coherent.wallNow,
      monotonicNow: coherent.monotonicNow
    }
  )
  const newTransport = () =>
    endpointModule.createPeerCandidateDirectTransport(
      sourceEndpoint,
      createPeerCandidateLocator(sourceOwner, verifiedRelay)
    )
  const transport = newTransport()
  const ledger = createPeerLedger({ cells: 64, bytes: 64n * 1200n, commands: 0 })
  t.teardown(async () => {
    try {
      endpointModule.destroyPeerDirectResponderRegistration(registration)
    } catch {}
    try {
      destroyPeerBootstrapResponder(responder)
    } catch {}
    destroyPeerRelayOwner(relayOwner)
    destroyPeerRelayOwner(sourceOwner)
    await endpointModule.revokeDhtUdxSocketLease(relayLease)
    await endpointModule.revokeDhtUdxSocketLease(sourceLease)
    await testnet.destroy()
  })
  return {
    testnet,
    relayNode,
    sourceNode,
    relayLease,
    sourceLease,
    transport,
    newTransport,
    ledger
  }
}

test('Native: a leased DHT socket carries direct discovery beside ordinary DHT RPC', async (t) => {
  const {
    discoverPeerCandidate,
    destroyPeerActiveCandidate
  } = require('../../lib/private/peer-direct-bootstrap')
  const pair = await leasedDiscoveryPair(t)
  const serverSocket = pair.relayNode.io.serverSocket
  const candidate = await discoverPeerCandidate(pair.transport, {
    ledger: pair.ledger,
    requestedMask: 11,
    randomTarget: cryptoSuite.randomBytes(32),
    maximumResults: 1
  })
  t.is(candidate.kind, 'peerActiveCandidate', 'discovery completes over the leased sockets')
  destroyPeerActiveCandidate(candidate)
  t.ok(
    await pair.sourceNode.ping({ host: '127.0.0.1', port: pair.relayNode.port }),
    'ordinary DHT RPC reaches the leased socket'
  )

  await endpointModule.revokeDhtUdxSocketLease(pair.relayLease)
  t.is(endpointModule.readDhtUdxSocketLease(pair.relayLease).endpoints, 0, 'revocation joins')
  t.is(serverSocket.bound, true, 'the DHT still owns its bound socket')
  t.ok(
    await pair.sourceNode.ping({ host: '127.0.0.1', port: pair.relayNode.port }),
    'ordinary DHT RPC continues after the lease ends'
  )
  t.exception(
    () =>
      endpointModule.createLeasedUdxCellEndpoint(
        {
          host: '127.0.0.1',
          port: pair.relayNode.port,
          onBootstrap() {},
          onCell() {},
          onLinkFailure() {}
        },
        pair.relayLease
      ),
    /unavailable/i,
    'a revoked lease builds no endpoint'
  )
})

// A2-CONTRACTS §4.3: every kind the emitter can produce, with its class and category.
// Circuit, neighbor and guard-bootstrap kinds are charged and name their ledger and
// ordinal; every other kind is uncharged and names the bounded owner that governs it.
const SEND_KINDS = Object.freeze({
  circuit: ['circuit', 'circuit'],
  closure: ['circuit', 'circuit'],
  'circuit-discovery': ['circuit', 'circuit'],
  'neighbor-service': ['neighbor', 'service'],
  'neighbor-close': ['neighbor', 'service'],
  'neighbor-discovery': ['neighbor', 'service'],
  'bootstrap-request': ['guard-bootstrap', 'bootstrap'],
  'link-setup': ['guard-bootstrap', 'bootstrap'],
  'link-control': ['guard-bootstrap', 'bootstrap'],
  'discovery-response': ['responder-cache', 'service'],
  'bootstrap-response': ['responder-cache', 'bootstrap'],
  'routed-branch': ['v1-routed-branch', 'v1-routed'],
  'nat-reflection': ['nat-traversal', 'traversal'],
  'nat-punch': ['nat-traversal', 'traversal']
})
const CHARGED_CLASSES = new Set(['circuit', 'neighbor', 'guard-bootstrap'])

function sendOwnerFollowsContract(event) {
  const rule = SEND_KINDS[event.owner.kind]
  if (!rule || event.owner.class !== rule[0] || event.owner.category !== rule[1]) return false
  const charged = CHARGED_CLASSES.has(rule[0])
  if (event.owner.charged !== charged) return false
  return charged
    ? Number.isInteger(event.owner.ledger) &&
        Number.isInteger(event.owner.ordinal) &&
        event.owner.ordinal > 0 &&
        event.owner.governor === null
    : event.owner.ledger === null &&
        event.owner.ordinal === null &&
        Number.isInteger(event.owner.governor)
}

test('Native: the lease observer sees each private send once with its owner', async (t) => {
  const {
    discoverPeerCandidate,
    destroyPeerActiveCandidate
  } = require('../../lib/private/peer-direct-bootstrap')
  const { readPeerLedger } = require('../../lib/private/peer-ledger')
  // One sequence shared by both leases, as a runtime shares one across its socket
  // generations.
  const pair = await leasedDiscoveryPair(t, endpointModule.createSendAttemptSequence())
  const emitted = []
  const sourceEvents = []
  const relayEvents = []
  const stopSource = endpointModule.observeDhtUdxSocketLease(pair.sourceLease, (event) => {
    emitted.push(event)
    sourceEvents.push(event)
  })
  const stopRelay = endpointModule.observeDhtUdxSocketLease(pair.relayLease, (event) => {
    emitted.push(event)
    relayEvents.push(event)
    throw new Error('an observer failure cannot affect sends')
  })
  const candidate = await discoverPeerCandidate(pair.transport, {
    ledger: pair.ledger,
    requestedMask: 11,
    randomTarget: cryptoSuite.randomBytes(32),
    maximumResults: 1
  })
  destroyPeerActiveCandidate(candidate)
  await new Promise((resolve) => setTimeout(resolve, 20))

  const attempts = emitted.filter((event) => event.kind === 'attempt')
  t.ok(
    attempts.every(
      (event, index) => index === 0 || event.attemptId > attempts[index - 1].attemptId
    ),
    'attempt identifiers increase across both leases of one sequence'
  )
  t.ok(attempts.every(sendOwnerFollowsContract), 'every owner follows the documented kind rules')

  const requests = sourceEvents.filter((event) => event.kind === 'attempt')
  t.is(requests.length, readPeerLedger(pair.ledger).cellsSpent, 'one attempt per charged cell')
  t.alike(
    requests.map((event) => event.owner.ordinal),
    requests.map((_, index) => index + 1),
    'each request names the ordinal its ledger was charged at'
  )
  t.is(new Set(requests.map((event) => event.owner.ledger)).size, 1, 'one ledger owns them all')
  for (const event of requests) {
    t.is(event.owner.kind, 'circuit-discovery')
    t.is(event.socketGeneration, 2)
    t.is(event.bytes, BOOTSTRAP_SIZE)
    t.is(event.remote.port, pair.relayNode.port)
    t.is(event.local.port, pair.sourceNode.port)
    t.ok(/^[0-9a-f]{64}$/.test(event.digest))
    t.ok(Object.isFrozen(event) && Object.isFrozen(event.owner))
  }
  const completions = sourceEvents.filter((event) => event.kind === 'completion')
  t.alike(
    completions.map((event) => event.attemptId).sort((a, b) => a - b),
    requests.map((event) => event.attemptId),
    'every attempt reports its native completion'
  )
  t.ok(completions.every((event) => event.outcome === 'sent'))

  const responses = relayEvents.filter((event) => event.kind === 'attempt')
  t.ok(responses.length > 0, 'the responder side observes its replies')
  t.ok(responses.every((event) => event.owner.kind === 'discovery-response'))
  t.is(new Set(responses.map((event) => event.owner.governor)).size, 1, 'one responder governs')
  t.ok(
    emitted.every((event) => !('packet' in event) && !('payload' in event)),
    'events carry no datagram bytes'
  )

  // A revoked observer sees nothing more, while the other lease keeps observing.
  t.is(stopRelay(), true)
  t.is(stopRelay(), false, 'revocation happens once')
  const relayBefore = relayEvents.length
  const sourceBefore = sourceEvents.length
  const again = await discoverPeerCandidate(pair.newTransport(), {
    ledger: pair.ledger,
    requestedMask: 11,
    randomTarget: cryptoSuite.randomBytes(32),
    maximumResults: 1
  })
  destroyPeerActiveCandidate(again)
  t.ok(sourceEvents.length > sourceBefore, 'the live observer sees the second discovery')
  t.is(relayEvents.length, relayBefore, 'the revoked observer receives nothing')
  t.is(stopSource(), true)
})

test('Native: a requester send that names no charged ledger is refused before the socket', async (t) => {
  const pair = await leasedDiscoveryPair(t)
  const observed = []
  endpointModule.observeDhtUdxSocketLease(pair.sourceLease, (event) => observed.push(event))
  const capability = endpointModule.takePeerDirectRequesterTransport(pair.transport)
  const body = b4a.alloc(110)
  body.writeUInt32BE(11, 0)
  body[68] = 1
  const { PEER_MESSAGE_ID, encodePeerObject } = require('../../lib/private/peer-protocol')
  const wire = encodePeerObject({ messageId: PEER_MESSAGE_ID.PEER_CAPS_QUERY_V2, body })
  const packet = b4a.alloc(BOOTSTRAP_SIZE)
  packet.writeUInt16BE(0xd301, 0)
  packet.writeUInt16BE(wire.byteLength, 2)
  packet.set(wire, 4)
  await t.exception(capability.send(packet), { code: 'INVALID_ROUTE' })
  t.is(observed.length, 0, 'nothing was sent or observed')
  capability.destroy()
})

function countSends(socket) {
  const counter = { count: 0 }
  const send = socket.send
  socket.send = function countedSend(...args) {
    counter.count++
    return send.apply(this, args)
  }
  return counter
}

// Two fake-socket endpoints; the left one opens a guard link through a bootstrap authority
// funded by `ledger`.
async function chargedGuardLink(t, leftPort, rightPort, ledger) {
  const network = new Map()
  const issuer = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER]
  const links = linkPair('127.0.0.1', leftPort, '127.0.0.2', rightPort)
  const observer = {}
  let leftSession = null
  let rightSession = null
  const left = issuer.createUdxCellEndpointForTest(
    {
      ...options('127.0.0.1', leftPort, []),
      onBootstrap(packet) {
        if (leftSession) void leftSession.receive(packet)
      }
    },
    issuer.createTestUdxAdapterAuthority(fakeFactory(network, null, observer))
  )
  const right = issuer.createUdxCellEndpointForTest(
    {
      ...options('127.0.0.2', rightPort, []),
      onBootstrap(packet) {
        if (rightSession) void rightSession.receive(packet)
      }
    },
    issuer.createTestUdxAdapterAuthority(fakeFactory(network))
  )
  t.teardown(async () => {
    await left.close()
    await right.close()
    links.left.directory.destroy()
    links.right.directory.destroy()
  })
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
    monotonicDeadline: 10_000,
    guardBootstrapLedger: ledger
  })
  bindBootstrapUdxOperation(authority, 10_000, Object.freeze({}))
  const admission = admitBootstrapUdxGuard(authority, {
    identity: links.b.publicKey,
    host: '127.0.0.2',
    port: rightPort
  })
  const leftOptions = linkSessionOptions(links, 'left')
  leftSession = openBootstrapUdxGuard(
    authority,
    admission,
    links.left.handle,
    createBootstrapUdxGuardSessionOptions(authority, admission, links.left.handle, {
      circuitId: leftOptions.setup.circuitId,
      epoch: leftOptions.setup.epoch,
      initiatorLocalId: leftOptions.setup.initiatorLocalId,
      responderLocalId: leftOptions.setup.responderLocalId,
      expiresAt: leftOptions.setup.expiresAt,
      responderStaticKey: leftOptions.setup.responderStaticKey,
      now: leftOptions.now,
      wallNow: leftOptions.now,
      handleNow: leftOptions.now,
      schedule: leftOptions.schedule,
      cancel: leftOptions.cancel,
      randomBytes: leftOptions.randomBytes,
      absoluteDeadline: leftOptions.absoluteDeadline,
      signedExpiry: leftOptions.signedExpiry
    })
  )
  rightSession = right.openLink(links.right.handle, linkSessionOptions(links, 'right'))
  const established = await leftSession.open()
  return { left, observer, established }
}

test('Native: a circuit cell that lost its funding is refused, never charged as link traffic', async (t) => {
  const { createPeerLedger, readPeerLedger } = require('../../lib/private/peer-ledger')
  const { CELL_CLASS, DIRECTION } = require('../../lib/private/protocol')
  const ledger = createPeerLedger(endpointModule.guardBootstrapPinBudget(60_000))
  const { left, observer, established } = await chargedGuardLink(t, 47811, 47812, ledger)
  const setupSpent = readPeerLedger(ledger).cellsSpent
  t.ok(setupSpent > 0, 'the guard link setup was charged to its guard-bootstrap ledger')
  const sends = countSends(observer.socket)
  const issuer = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER]
  const cell = (extra) => ({
    class: CELL_CLASS.DATAGRAM,
    direction: DIRECTION.FORWARD,
    generation: 1n,
    payload: b4a.from('circuit'),
    ...extra
  })
  await t.exception(
    issuer.sendEstablishedForTest(
      left,
      established,
      cell({ [endpointModule.CIRCUIT_SEND_PERMIT]: undefined })
    ),
    { code: 'INVALID_ROUTE' },
    'a circuit cell whose permit is missing is refused'
  )
  await t.exception(
    issuer.sendEstablishedForTest(left, established, cell({})),
    { code: 'INVALID_ROUTE' },
    'a native link carries no unpermitted cell as its own traffic'
  )
  await settles()
  t.is(sends.count, 0, 'nothing reached the socket')
  t.is(readPeerLedger(ledger).cellsSpent, setupSpent, 'the guard link ledger was not charged')
})

test('Native: a neighbor link without its service ledgers sends nothing', async (t) => {
  const network = new Map()
  const issuer = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER]
  const links = linkPair('127.0.0.1', 47813, '127.0.0.2', 47814)
  const observer = {}
  const left = issuer.createUdxCellEndpointForTest(
    options('127.0.0.1', 47813, []),
    issuer.createTestUdxAdapterAuthority(fakeFactory(network, null, observer))
  )
  const right = issuer.createUdxCellEndpointForTest(
    options('127.0.0.2', 47814, []),
    issuer.createTestUdxAdapterAuthority(fakeFactory(network))
  )
  t.teardown(async () => {
    await left.close()
    await right.close()
    links.left.directory.destroy()
    links.right.directory.destroy()
  })
  await left.bind()
  await right.bind()
  const sends = countSends(observer.socket)
  const session = left.openLink(links.left.handle, {
    ...linkSessionOptions(links, 'left'),
    [endpointModule.LINK_SEND_CLASS]: endpointModule.SEND_CLASS.NEIGHBOR
  })
  await t.exception(session.open(), 'the link cannot open without funding')
  await settles()
  t.is(sends.count, 0, 'its setup request never reached the socket')
})

test('Native: a source pins a leased guard with every bootstrap send charged or governed', async (t) => {
  const createTestnet = require('../../testnet')
  const process = require('process')
  const { createCoherentClock } = require('../../lib/private/runtime-clock')
  const { createPeerLedger, readPeerLedger } = require('../../lib/private/peer-ledger')
  const { CapsResponder } = require('../../lib/private/caps-responder')
  const { BootstrapIO, consumeBootstrapGuardPin } = require('../../lib/private/bootstrap-io')
  const {
    createRelayCandidateDirectorySink
  } = require('../../lib/private/relay-candidate-directory')
  const createDynamicResponderSetup = require('../../lib/private/link-bootstrap-session')[
    Symbol.for('hyperdht-private-routes/dynamic-responder-setup-factory')
  ]
  const {
    encodeRelayCapabilityAdvertisement,
    providerServicePolicyForCapabilities,
    signRelayCapabilityAdvertisement
  } = require('../../lib/private/relay-capability')
  const { RELAY_CAPABILITY } = require('../../lib/private/protocol')

  const testnet = await createTestnet(3, { host: '127.0.0.1' })
  const clock = createCoherentClock(() => process.hrtime.bigint(), Date.now)
  const sequence = endpointModule.createSendAttemptSequence()
  const guardNode = testnet.nodes[1]
  const sourceNode = testnet.nodes[2]
  const guardLease = endpointModule.leaseDhtUdxSocket(guardNode.io.serverSocket, 1, sequence)
  const sourceLease = endpointModule.leaseDhtUdxSocket(sourceNode.io.serverSocket, 1, sequence)
  const events = []
  endpointModule.observeDhtUdxSocketLease(guardLease, (event) => events.push(['guard', event]))
  endpointModule.observeDhtUdxSocketLease(sourceLease, (event) => events.push(['source', event]))
  const endpointFor = (lease) => {
    const tuple = endpointModule.readDhtUdxSocketLease(lease)
    return endpointModule.createLeasedUdxCellEndpoint(
      {
        host: tuple.host,
        port: tuple.port,
        onBootstrap() {},
        onCell() {
          return true
        },
        onLinkFailure() {}
      },
      lease
    )
  }
  const guardEndpoint = endpointFor(guardLease)
  const sourceEndpoint = endpointFor(sourceLease)
  await guardEndpoint.bind()
  await sourceEndpoint.bind()

  const lifetimeMs = 60_000
  const issuedAt = clock.wallNow()
  const guardIdentity = safetyIdentity(120)
  const guardRoute = cryptoSuite.encryptionKeyPair()
  const reachableEndpoint = encodeCanonicalEndpoint({
    addressFamily: 4,
    addressBytes: b4a.from([127, 0, 0, 1]),
    port: guardNode.port
  })
  const caps = new CapsResponder({
    now: clock.wallNow,
    advertisement: encodeRelayCapabilityAdvertisement(
      signRelayCapabilityAdvertisement(
        {
          relayIdentity: guardIdentity.publicKey,
          currentDhtNodeId: deriveM3DhtNodeId(reachableEndpoint),
          reachableEndpoint,
          routeEncryptionPublicKey: guardRoute.publicKey,
          capabilityMask: RELAY_CAPABILITY.CIRCUIT_RELAY_V1,
          minimumProtocolVersion: 1,
          maximumProtocolVersion: 1,
          cellSize: 1200,
          maxCellPayload: 1146,
          contextEnvelopeSize: 1101,
          routeFrameSize: 1100,
          maxRoutePayload: 1073,
          datagramReplayWindow: 64,
          maxConcurrentCircuits: 4,
          capacityClass: 1,
          maxCellsPerCircuit: 200,
          maxBytesPerCircuit: 240_000,
          maxCommandsPerCircuit: 100,
          idleTimeoutMs: 30_000,
          maxQueuedBytes: 524_288,
          epoch: 11n,
          issuedAtMs: issuedAt,
          expiresAtMs: issuedAt + BigInt(lifetimeMs),
          providerServicePolicyEntries: providerServicePolicyForCapabilities(
            RELAY_CAPABILITY.CIRCUIT_RELAY_V1
          )
        },
        guardIdentity.secretKey
      )
    ),
    identitySecretKey: guardIdentity.secretKey,
    routeEncryptionSecretKey: guardRoute.secretKey
  })
  const linkBudget = endpointModule.guardBootstrapLinkBudget(lifetimeMs)
  const guardLedger = createPeerLedger({
    cells: 2 * linkBudget.cells,
    bytes: 2n * linkBudget.bytes,
    commands: 0
  })
  const expiry = Number(issuedAt) + lifetimeMs
  const accepted = []
  const registration = endpointModule.registerGuardBootstrapResponder(guardEndpoint, {
    caps,
    ledger: guardLedger,
    linkBudget,
    maxEstablished: 1,
    acceptOptions: (handle) => ({
      mode: 'accept',
      codec: new BootstrapEnvelopeCodec({
        linkHandle: handle,
        localIdentitySecretKey: guardIdentity.secretKey,
        padding: cryptoSuite.randomBytes
      }),
      linkSetup: createLinkSetupAuthority({
        now: () => Number(clock.wallNow()),
        randomBytes: cryptoSuite.randomBytes
      }),
      setup: createDynamicResponderSetup({
        responderStaticSecretKey: guardRoute.secretKey,
        responderIdentitySecretKey: guardIdentity.secretKey
      }),
      now: () => Number(clock.monotonicNow()),
      schedule: setTimeout,
      cancel: clearTimeout,
      randomBytes: cryptoSuite.randomBytes,
      absoluteDeadline: Number(clock.monotonicNow()) + 30_000,
      signedExpiry: expiry,
      authorizedExpiry: expiry
    }),
    onEstablished(established) {
      accepted.push(established)
    }
  })

  const sourceIdentity = cryptoSuite.keyPair()
  const pinLedger = createPeerLedger(endpointModule.guardBootstrapPinBudget(lifetimeMs))
  const guards = [{ host: '127.0.0.1', port: guardNode.port }]
  const authority = createBootstrapUdxAuthority({
    endpoint: sourceEndpoint,
    configuredEndpoints: guards,
    localSecretCapability: createLocalIdentitySecretCapability({
      localIdentity: sourceIdentity.publicKey,
      localSecretKey: sourceIdentity.secretKey
    }),
    maxProspectiveGuards: 1,
    monotonicDeadline: clock.monotonicNow,
    guardBootstrapLedger: pinLedger
  })
  const io = new BootstrapIO({
    endpoints: guards,
    localIdentity: sourceIdentity.publicKey,
    localSecretKey: sourceIdentity.secretKey,
    datagrams: authority,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    randomBytes: cryptoSuite.randomBytes,
    candidateDirectorySink: createRelayCandidateDirectorySink({
      wallNow: clock.wallNow,
      monotonicNow: clock.monotonicNow,
      randomBytes: cryptoSuite.randomBytes
    })
  })
  let transfer = null
  t.teardown(async () => {
    if (transfer) destroyGuardLeaseMaterial(transfer.guardLeaseMaterial)
    endpointModule.destroyGuardBootstrapResponderRegistration(registration)
    caps.destroy()
    await endpointModule.revokeDhtUdxSocketLease(guardLease)
    await endpointModule.revokeDhtUdxSocketLease(sourceLease)
    await testnet.destroy()
  })
  transfer = consumeBootstrapGuardPin(await io.start())
  transfer.candidateDirectory.destroy()
  for (let turn = 0; turn < 50 && accepted.length === 0; turn++) {
    await new Promise((resolve) => setTimeout(resolve, 10))
  }
  t.is(accepted.length, 1, 'the guard reports the accepted link once, when it establishes')
  t.alike(transfer.pinnedGuard.identity, guardIdentity.publicKey, 'the source pinned this guard')

  const attempts = events.filter(([, event]) => event.kind === 'attempt')
  t.ok(
    attempts.every(([, event]) => sendOwnerFollowsContract(event)),
    'every owner follows §4.3'
  )
  const sourceCharged = attempts.filter(([side, event]) => side === 'source' && event.owner.charged)
  const sourceKinds = new Set(sourceCharged.map(([, event]) => event.owner.kind))
  t.ok(sourceKinds.has('bootstrap-request') && sourceKinds.has('link-setup'))
  t.ok(
    attempts.every(([side, event]) => side !== 'source' || event.owner.class === 'guard-bootstrap'),
    'every source send is guard-bootstrap traffic'
  )
  t.is(
    readPeerLedger(pinLedger).cellsSpent,
    sourceCharged.length,
    'the pin ledger holds exactly the charged source sends'
  )
  const guardSends = attempts.filter(([side]) => side === 'guard').map(([, event]) => event)
  t.ok(
    guardSends.some((event) => event.owner.kind === 'bootstrap-response'),
    'CAPS answers are governed responder traffic'
  )
  const guardLinkSends = guardSends.filter((event) => event.owner.charged)
  t.ok(guardLinkSends.length > 0, 'the accepted link answers its setup')
  t.is(new Set(guardLinkSends.map((event) => event.owner.ledger)).size, 1, 'one link reservation')
  t.alike(
    guardLinkSends.map((event) => event.owner.ordinal),
    guardLinkSends.map((_, index) => index + 1),
    'the accepted link spends only its own reservation'
  )
})
