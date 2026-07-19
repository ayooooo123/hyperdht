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
const { UDX_ENDPOINT_RESERVATION_STATS } = require('../../lib/private/udx-adapter')
const {
  DEFAULT_MAX_UDX_INBOUND_BYTES,
  DEFAULT_MAX_UDX_INBOUND_PACKETS,
  DEFAULT_MAX_UDX_QUEUED_BYTES,
  DEFAULT_MAX_UDX_QUEUED_PACKETS,
  TEST_ONLY_UDX_ADAPTER_ISSUER,
  UdxCellEndpoint,
  admitBootstrapUdxGuard,
  bindBootstrapUdxOperation,
  createBootstrapUdxAuthority,
  createLocalIdentitySecretCapability,
  destroyBootstrapUdxAuthority,
  destroyGuardLeaseMaterial,
  isGuardLeaseMaterial,
  openBootstrapUdxGuard,
  pinBootstrapUdxGuard,
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
    signedExpiry: 60_000
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
  leftSession = openBootstrapUdxGuard(
    authority,
    admission,
    links.left.handle,
    linkSessionOptions(links, 'left')
  )
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

test('UDX endpoint freezes 64-packet and 76,800-byte queue/inbound defaults', (t) => {
  t.is(DEFAULT_MAX_UDX_QUEUED_PACKETS, 64)
  t.is(DEFAULT_MAX_UDX_QUEUED_BYTES, 76_800)
  t.is(DEFAULT_MAX_UDX_INBOUND_PACKETS, 64)
  t.is(DEFAULT_MAX_UDX_INBOUND_BYTES, 76_800)
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

test('reconnect destroy during owner close and bind failure leave no live socket owner', async (t) => {
  let releaseClose = null
  const closeHold = new Promise((resolve) => {
    releaseClose = resolve
  })
  const closing = await pinnedMaterialFixture(47127, 47128, { closeHold })
  const closingLease = closing.issuer.inspectGuardLeaseMaterial(closing.material)
  const closingTransport = closingLease.reconnectTransportFactory()
  t.is(closing.leftObserver.sockets.length, 1)
  t.is(destroyGuardLeaseMaterial(closing.material), true)
  t.is(closing.leftObserver.sockets.length, 1)
  releaseClose(true)
  await t.exception(closingTransport.send('127.0.0.2', 47128, b4a.alloc(BOOTSTRAP_SIZE)))
  await settles()
  t.is(closing.leftObserver.sockets.length, 1)
  t.is(closing.leftObserver.sockets[0].closed, true)
  t.is(closing.leftObserver.sockets[0].closeCalls, 1)
  await closing.rightSession.close()
  await closing.right.close()
  closing.links.left.directory.destroy()
  closing.links.right.directory.destroy()

  const failing = await pinnedMaterialFixture(47129, 47130, { failBindAt: 2 })
  const failingLease = failing.issuer.inspectGuardLeaseMaterial(failing.material)
  const failingTransport = failingLease.reconnectTransportFactory()
  await t.exception(failingTransport.send('127.0.0.2', 47130, b4a.alloc(BOOTSTRAP_SIZE)))
  await settles()
  t.is(failing.leftObserver.sockets.length, 2)
  t.is(failing.leftObserver.sockets[0].closed, true)
  t.is(failing.leftObserver.sockets[1].closed, true)
  t.is(destroyGuardLeaseMaterial(failing.material), true)
  await failing.rightSession.close()
  await failing.right.close()
  failing.links.left.directory.destroy()
  failing.links.right.directory.destroy()
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
  leftSession = openBootstrapUdxGuard(authority, admission, links.left.handle, {
    mode: 'initiate',
    codec: new BootstrapEnvelopeCodec({
      linkHandle: links.left.handle,
      localIdentitySecretKey: links.a.secretKey,
      padding: sequence(0x81)
    }),
    linkSetup: createLinkSetupAuthority({ now, randomBytes: sequence(0x61) }),
    setup: {
      ...common,
      responderStaticKey: cryptoSuite.encryptionKeyPair(seed(98)).publicKey,
      initiatorIdentitySecretKey: links.a.secretKey
    },
    now,
    schedule: setTimeout,
    cancel: clearTimeout,
    randomBytes: sequence(1),
    absoluteDeadline: 10_000,
    signedExpiry: 60_000
  })
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
    signedExpiry: 60_000
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
    t.is(leftObserver.sockets.length, 1, 'fresh owner waits for original owner close')
    t.is(await reconnectTransport.send('127.0.0.2', 47132, probe), true)
    t.is(originalSocket.closed, true)
    t.is(originalSocket.closeCalls, 1)
    t.is(leftObserver.sockets.length, 2)
    t.is(leftObserver.sockets[1] === originalSocket, false)
    t.is(leftObserver.sockets[1].closed, false)
    t.alike(
      leftObserver.events.map(([event]) => event),
      ['create', 'close', 'create']
    )
    await t.exception(reconnectTransport.send('127.0.0.2', 47139, probe))
    reconnectTransport.destroy()
    await settles()
    t.is(leftObserver.sockets[1].closed, true)
    await t.exception(reconnectTransport.send('127.0.0.2', 47132, probe))
    t.exception(() => lease.reconnectTransportFactory())
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
  t.is(observer.socket.closed, false, 'socket remains open while native send owns bytes')
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
