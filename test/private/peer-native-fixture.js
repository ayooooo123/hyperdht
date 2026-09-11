'use strict'

const b4a = require('b4a')
const {
  CAPACITY_CLASS,
  LINK_OPERATION,
  PROTOCOL_VERSION,
  ROLE,
  roleForIdentity,
  TOPOLOGY_ROLE
} = require('../../lib/private/protocol')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  createPeerNativeNeighborPool,
  destroyPeerNativeNeighborPool,
  provisionPeerNativeNeighbor
} = require('../../lib/private/peer-native-neighbors')
const {
  TEST_ONLY_UDX_ADAPTER_ISSUER,
  UdxCellEndpoint,
  createPeerCandidateDirectTransport,
  registerSharedGuardPeerBranchResponder,
  registerPeerDirectResponder,
  destroyPeerDirectResponderRegistration
} = require('../../lib/private/udx-cell-endpoint')
const {
  LinkDirectory,
  signTopologyGrant,
  readLinkHandle
} = require('../../lib/private/topology-grant')
const { createPeerLedger, createPeerMemoryPool } = require('../../lib/private/peer-ledger')
const {
  createPeerRelayOwner,
  readPeerRelayOwner,
  destroyPeerRelayOwner,
  verifyPeerAdvertisement,
  readVerifiedPeerAdvertisement,
  createPeerCandidateLocator
} = require('../../lib/private/peer-capability')
const { BootstrapEnvelopeCodec } = require('../../lib/private/bootstrap-envelope')
const { createLinkSetupAuthority } = require('../../lib/private/link-setup')
const {
  createPeerBootstrapResponder,
  destroyPeerBootstrapResponder,
  discoverPeerCandidate
} = require('../../lib/private/peer-direct-bootstrap')
const issuer = require('../../lib/private/udx-cell-endpoint')[TEST_ONLY_UDX_ADAPTER_ISSUER]
const { selectUdxLoopbackHosts } = require('../../lib/private/udx-adapter')
const {
  openPeerNeighborLink,
  createPeerLinkResponder,
  destroyPeerLinkResponder
} = require('../../lib/private/peer-guard-link')
const {
  createPeerM3AdjacencyAuthority,
  adoptPeerEstablishedLink
} = require('../../lib/private/peer-m3-adjacency-runtime')
const {
  createGuardLease,
  destroyGuardLease,
  createPeerGuardBootstrapTransport
} = require('../../lib/private/guard-lease')
const { openPeerGuardLink } = require('../../lib/private/peer-guard-link')
const {
  admitBootstrapUdxGuard,
  bindBootstrapUdxOperation,
  createBootstrapUdxAuthority,
  createLocalIdentitySecretCapability,
  createBootstrapUdxGuardSessionOptions,
  openBootstrapUdxGuard,
  pinBootstrapUdxGuard,
  destroyBootstrapUdxAuthority
} = require('../../lib/private/udx-cell-endpoint')
const {
  deriveM3DhtNodeId,
  digestRelayCapabilityAdvertisement,
  encodeCanonicalEndpoint,
  encodeRelayCapabilityAdvertisement,
  providerServicePolicyForCapabilities,
  signRelayCapabilityAdvertisement
} = require('../../lib/private/relay-capability')
const {
  createPeerTailControl,
  destroyPeerTailControl
} = require('../../lib/private/peer-tail-control')
const seed = (n) => b4a.alloc(32, n)

function safetyIdentity(start) {
  for (let value = start; value < 256; value++) {
    const pair = cryptoSuite.keyPair(seed(value))
    if (roleForIdentity(pair.publicKey) === ROLE.SAFETY) return pair
  }
  throw new Error('missing safety identity')
}
function distinctSafetyIdentity(start = 0, excludedKeys = []) {
  for (let value = start; value < 256; value++) {
    const pair = cryptoSuite.keyPair(seed(value))
    if (roleForIdentity(pair.publicKey) === ROLE.SAFETY) {
      if (!excludedKeys.some((ex) => b4a.equals(ex, pair.publicKey))) {
        return pair
      }
    }
  }
  throw new Error('missing distinct safety identity')
}

function fixtureKeys() {
  const authority = cryptoSuite.keyPair(seed(0x10))
  const local = safetyIdentity(0x11)
  const localRoute = cryptoSuite.encryptionKeyPair(seed(0x12))
  const peer = safetyIdentity(0x40)
  const peerRoute = cryptoSuite.encryptionKeyPair(seed(0x14))
  return { authority, local, localRoute, peer, peerRoute }
}

function fakeClock(startTime = 1000n) {
  let wall = startTime
  let mono = startTime
  const timers = new Map()
  let nextId = 1
  let fireImmediately = false
  let onClearTimer = null
  return {
    wallNow: () => wall,
    monotonicNow: () => mono,
    timerCount: () => timers.size,
    setTimer: (cb, ms) => {
      const id = nextId++
      if (fireImmediately) {
        cb()
        return id
      }
      timers.set(id, { cb, trigger: mono + BigInt(ms) })
      return id
    },
    clearTimer: (id) => {
      timers.delete(id)
      if (typeof onClearTimer === 'function') {
        const fn = onClearTimer
        onClearTimer = null
        fn()
      }
    },
    setOnClearTimer: (fn) => {
      onClearTimer = fn
    },
    fireSynchronously: (enabled) => {
      fireImmediately = enabled
    },
    advanceWall: (ms) => {
      wall += BigInt(ms)
    },
    advance: (ms) => {
      wall += BigInt(ms)
      mono += BigInt(ms)
      for (const [id, t] of Array.from(timers.entries())) {
        if (mono >= t.trigger) {
          timers.delete(id)
          try {
            t.cb()
          } catch {}
        }
      }
    }
  }
}

class FakeSocket {
  constructor(network, observer = null) {
    this.network = network
    this.observer = observer
    this.listeners = new Map()
    this.sent = []
    this.port = 0
    this.host = ''
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
    const out = b4a.from(packet)
    this.sent.push({ packet: out, host, port })
    const peer = this.network.get(`${host}:${port}`)
    if (!peer) return false
    const deliver = () => peer.emit('message', b4a.from(out), { host: this.host, port: this.port })
    queueMicrotask(deliver)
    return true
  }

  close() {
    this.closeCalls++
    this.closed = true
    this.network.delete(`${this.host}:${this.port}`)
    if (this.observer && Array.isArray(this.observer.events)) {
      this.observer.events.push(['close', this])
    }
    return true
  }
}

function fakeFactory(network, observer = {}) {
  return () => ({
    create() {
      return {
        createSocket() {
          const socket = new FakeSocket(network, observer)
          if (observer) {
            if (!observer.sockets) observer.sockets = []
            if (!observer.events) observer.events = []
            observer.sockets.push(socket)
            observer.socket = socket
          }
          return socket
        }
      }
    }
  })
}

function createBoundEndpoint(network, host, port, onBootstrap = null, native = false) {
  const options = {
    host,
    port,
    advertisedHost: host,
    advertisedPort: port,
    onBootstrap(packet) {
      if (typeof onBootstrap === 'function') onBootstrap(packet)
    },
    onCell() {
      return true
    },
    onLinkFailure() {}
  }
  return native
    ? new UdxCellEndpoint(options)
    : issuer.createUdxCellEndpointForTest(
        options,
        issuer.createTestUdxAdapterAuthority(fakeFactory(network))
      )
}

function buildSignedGrant({
  authority,
  local,
  peer,
  localHost,
  localPort,
  peerHost,
  peerPort,
  epoch = 1n,
  runId32 = seed(0x99),
  expiresAt = 60_000n,
  grantId32 = seed(0x01),
  localRole = TOPOLOGY_ROLE.SAFETY_GUARD,
  peerRole = TOPOLOGY_ROLE.SAFETY_FINAL,
  localOperations = LINK_OPERATION.INITIATE,
  peerOperations = LINK_OPERATION.ACCEPT
}) {
  return signTopologyGrant(
    {
      version: PROTOCOL_VERSION,
      format: 0,
      grantId32,
      endpointA: {
        identity32: local.publicKey,
        role: localRole,
        host: localHost,
        port: localPort,
        operations: localOperations
      },
      endpointB: {
        identity32: peer.publicKey,
        role: peerRole,
        host: peerHost,
        port: peerPort,
        operations: peerOperations
      },
      epoch,
      notBefore: 0n,
      expiresAt,
      runId32
    },
    authority.secretKey
  )
}

function options(host, port, overrides = {}) {
  return {
    host,
    port,
    advertisedHost: host,
    advertisedPort: port,
    onBootstrap() {},
    onCell() {
      return true
    },
    onLinkFailure() {},
    ...overrides
  }
}

function sequence(first) {
  let value = first
  return (size) => b4a.alloc(size, value++)
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

function linkPair(hostA, portA, hostB, portB, grantOptions = {}) {
  const authority = cryptoSuite.keyPair(seed(90))
  const a = cryptoSuite.keyPair(seed(91))
  const b = safetyIdentity(92)
  const runId32 = seed(93)
  const grant = signTopologyGrant(
    {
      version: PROTOCOL_VERSION,
      format: 0,
      grantId32: grantOptions.grantId32 || seed(94),
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

async function closeFixtureResources(cleanup) {
  let failure
  let failed = false
  while (cleanup.length) {
    try {
      await cleanup.pop()()
    } catch (err) {
      if (!failed) {
        failure = err
        failed = true
      }
    }
  }
  if (failed) throw failure
}

async function pinnedMaterialFixture(leftPort, rightPort, fixtureOptions = {}) {
  const cleanup = []
  try {
    const network = new Map()
    const udxIssuer = issuer
    const rightHost = fixtureOptions.native === true ? '127.0.0.1' : '127.0.0.2'
    const links = linkPair('127.0.0.1', leftPort, rightHost, rightPort, fixtureOptions)
    cleanup.push(
      () => links.left.directory.destroy(),
      () => links.right.directory.destroy()
    )
    const leftObserver = {}
    const rightObserver = {}
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
        : udxIssuer.createUdxCellEndpointForTest(
            leftEndpointOptions,
            udxIssuer.createTestUdxAdapterAuthority(fakeFactory(network, leftObserver))
          )
    cleanup.push(() => left.close())
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
        : udxIssuer.createUdxCellEndpointForTest(
            rightEndpointOptions,
            udxIssuer.createTestUdxAdapterAuthority(fakeFactory(network, rightObserver))
          )
    cleanup.push(() => right.close())
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
      cleanup.push(() => destroyBootstrapUdxAuthority(rightAuthority))
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
    cleanup.push(() => destroyBootstrapUdxAuthority(authority))
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
    cleanup.push(() => leftSession.close())
    rightSession = right.openLink(links.right.handle, linkSessionOptions(links, 'right'))
    cleanup.push(() => rightSession.close())
    const established = await leftSession.open()
    if (fixtureOptions.pin === false) {
      cleanup.length = 0
      return {
        left,
        right,
        leftObserver,
        links,
        rightPort,
        rightSession,
        authority,
        admission,
        established,
        network
      }
    }
    const material = pinBootstrapUdxGuard(authority, admission, established)
    cleanup.length = 0
    return {
      left,
      right,
      leftObserver,
      links,
      rightObserver,
      rightHost,
      rightPort,
      rightSession,
      rightAuthority,
      network,
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
        const linkBootstrapModule = require('../../lib/private/link-bootstrap-session')
        return rightSession[linkBootstrapModule.TEST_ONLY_LINK_BOOTSTRAP_SESSION_OBSERVER]()
      },
      material,
      setRightBootstrapHandler(handler) {
        rightBootstrapHandler = handler
      }
    }
  } catch (err) {
    try {
      await closeFixtureResources(cleanup)
    } catch (cleanupError) {
      throw new AggregateError([err, cleanupError], 'Pinned fixture setup and cleanup failed', {
        cause: err
      })
    }
    throw err
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
  if (fixture.rightAuthority) destroyBootstrapUdxAuthority(fixture.rightAuthority)
  await fixture.rightSession.close()
  await fixture.right.close()
  fixture.links.left.directory.destroy()
  fixture.links.right.directory.destroy()
}

function peerBranchLedgers(branches = 1) {
  return ledgers(branches)
}

async function peerGuardFixture(t, leftPort, rightPort, fixtureOptions = {}) {
  const clock = fixtureOptions.clock || fakeClock()
  const clocks = {
    clockIdentity: clock,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer
  }
  const fixture = await pinnedMaterialFixture(leftPort, rightPort, fixtureOptions)
  const lease = createGuardLease(
    leaseOptions(fixture, {
      pinnedGuard: {
        identity32: fixture.links.b.publicKey,
        endpoint: { host: fixture.rightHost, port: rightPort }
      },
      ...clocks
    })
  )
  const owners = []
  const makeOwner = (endpoint, identityKeyPair, host, port, keySeed) => {
    const routeKeyPair = cryptoSuite.encryptionKeyPair(seed(keySeed))
    const owner = createPeerRelayOwner({
      endpoint,
      identityKeyPair,
      routeKeyPair,
      advertisementFields: {
        relayIdentity32: identityKeyPair.publicKey,
        currentDhtNodeId32: seed(keySeed + 1),
        reachableEndpoint: { host, port },
        routeEncryptionPublicKey32: routeKeyPair.publicKey,
        capabilityMask: 9,
        minimumVersion: 2,
        maximumVersion: 2,
        datagramReplayWindow: 64,
        maxConcurrentCircuits: 8,
        capacityClass: 0,
        maxCells: 100,
        maxBytes: 120000,
        maxCommands: 100,
        idleTimeoutMs: 30000,
        maxQueuedBytes: 65536,
        epoch: 7n,
        issuedAt: 1000n,
        expiresAt: 60000n,
        policyCount: 0
      },
      ...clocks
    })
    owners.push(owner)
    return owner
  }
  const sourceOwner = makeOwner(fixture.left, fixture.links.a, '127.0.0.1', leftPort, 201)
  const guardOwner = makeOwner(fixture.right, fixture.links.b, fixture.rightHost, rightPort, 203)
  const bootstrap = createPeerBootstrapResponder(guardOwner)
  const registration = registerPeerDirectResponder(fixture.right, bootstrap)
  const localAuthority = createPeerM3AdjacencyAuthority(clocks)
  const guardAuthority = createPeerM3AdjacencyAuthority(clocks)
  let guardRuntime = null
  const pLedgers = peerBranchLedgers(4)
  const responder = createPeerLinkResponder(guardOwner, {
    ...pLedgers,
    onEstablished(handle) {
      guardRuntime = adoptPeerEstablishedLink(guardAuthority, handle)
      return guardRuntime
    }
  })
  registerSharedGuardPeerBranchResponder(fixture.rightSession.established, responder)
  t.teardown(async () => {
    localAuthority.destroy()
    guardAuthority.destroy()
    destroyPeerLinkResponder(responder)
    destroyPeerDirectResponderRegistration(registration)
    destroyPeerBootstrapResponder(bootstrap)
    for (const owner of owners) destroyPeerRelayOwner(owner)
    destroyGuardLease(lease)
    await closeFixture(fixture)
  })
  const advertisement = readPeerRelayOwner(guardOwner).canonicalAdvertisement260
  const limits = {
    cellSize: 1200,
    maxCells: 30,
    maxBytes: 36000,
    maxCommands: 21,
    idleTimeoutMs: 30000,
    expiresAt: 50000n
  }
  let branchNumber = 0
  return {
    fixture,
    lease,
    clock,
    localAuthority,
    peerLedgers: pLedgers,
    limits,
    get guardRuntime() {
      return guardRuntime
    },
    discover() {
      return discoverPeerCandidate(createPeerGuardBootstrapTransport(lease), {
        ledger: createPeerLedger({ cells: 24, bytes: 28800n, commands: 0 }),
        requestedMask: 9,
        randomTarget: seed(0xa1),
        maximumResults: 1
      })
    },
    open(activeCandidate, overrides = {}) {
      const number = ++branchNumber
      const tailKeyPair = cryptoSuite.encryptionKeyPair(seed(0xb1))
      return openPeerGuardLink({
        guardLease: lease,
        activeCandidate,
        relayOwner: sourceOwner,
        advertisement,
        branchId: b4a.alloc(16, number),
        circuitId: b4a.alloc(16, number + 10),
        generation: 1n,
        extensionIndex: 0,
        clientTailEphemeralPublicKey: tailKeyPair.publicKey,
        clientTailSecretKey: tailKeyPair.secretKey,
        clientNonce: seed(number + 20),
        payloadParametersDigest: seed(0xb2),
        candidateAuthorityCommitment32: b4a.alloc(32),
        forwardLimits: limits,
        reverseLimits: limits,
        operationDeadline: clock.monotonicNow() + 2000n,
        ...peerBranchLedgers(),
        ...overrides
      })
    }
  }
}

function createDeferred() {
  let resolve = null
  let reject = null
  const promise = new Promise((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

async function setupFourNodeNativeFixture({
  t,
  clock = null,
  basePort = 48200,
  native = false,
  maxConcurrentCircuits = 128,
  sourceMemoryPool = null,
  guardMemoryPool = null,
  safetyMemoryPool = null,
  terminalMemoryPool = null,
  poolCapacity = null,
  onTerminalFinalReady = null,
  safetyCapabilityMask = 9,
  terminalCapabilityMask = 11,
  expiresAt = 2000000n,
  nodeServiceCells = 300,
  serviceCells = 60,
  suppressSafetyTailReady = false,
  safetyRelayOwnerOverride = null
}) {
  const cleanup = []
  let closing = null
  const close = () => {
    if (!closing) {
      closing = Promise.resolve().then(() => closeFixtureResources(cleanup))
    }
    return closing
  }
  if (t && typeof t.teardown === 'function') t.teardown(close)

  try {
    const c = clock || fakeClock()
    const clocks = {
      clockIdentity: c,
      wallNow: c.wallNow,
      monotonicNow: c.monotonicNow,
      setTimer: c.setTimer,
      clearTimer: c.clearTimer
    }

    const localAuthority = createPeerM3AdjacencyAuthority(clocks)
    cleanup.push(() => localAuthority.destroy())
    const guardAuthority = createPeerM3AdjacencyAuthority(clocks)
    cleanup.push(() => guardAuthority.destroy())
    const safetyAuthority = createPeerM3AdjacencyAuthority(clocks)
    cleanup.push(() => safetyAuthority.destroy())
    const terminalAuthority = createPeerM3AdjacencyAuthority(clocks)
    cleanup.push(() => terminalAuthority.destroy())
    const grantAuthority = cryptoSuite.keyPair(seed(0x10))

    const guardTailStarted = createDeferred()
    const safetyTailStarted = createDeferred()
    const terminalTailStarted = createDeferred()

    const [localHost, peerHost] = native
      ? selectUdxLoopbackHosts({ platform: global.Bare ? Bare.platform : process.platform })
      : ['127.0.0.1', '127.0.0.1']

    const sourcePort = basePort
    const guardPort = basePort + 1
    const safetyPort = basePort + 2
    const terminalPort = basePort + 3

    const getPool = (supplied) => {
      if (supplied) return supplied
      if (typeof poolCapacity === 'number' && poolCapacity > 0)
        return createPeerMemoryPool(poolCapacity)
      throw new Error(
        'options.memoryPool must be supplied by caller or configured via poolCapacity'
      )
    }

    const srcPool = getPool(sourceMemoryPool)
    const grdPool = getPool(guardMemoryPool)
    const sftPool = getPool(safetyMemoryPool)
    const trmPool = getPool(terminalMemoryPool)
    const sourceRoute = cryptoSuite.encryptionKeyPair(seed(201))
    const guardRoute = cryptoSuite.encryptionKeyPair(seed(203))
    const safetyRoute = cryptoSuite.encryptionKeyPair(seed(205))
    const terminalRoute = cryptoSuite.encryptionKeyPair(seed(207))

    const fixture = await pinnedMaterialFixture(sourcePort, guardPort, { native, clock: c })
    cleanup.push(
      () => fixture.left.close(),
      () => closeFixture(fixture)
    )
    const guardPublicKey = fixture.links.b.publicKey
    const safetyKeys = distinctSafetyIdentity(0, [guardPublicKey])
    const terminalKeys = distinctSafetyIdentity(0, [guardPublicKey, safetyKeys.publicKey])
    const lease = createGuardLease(
      leaseOptions(fixture, {
        pinnedGuard: {
          identity32: fixture.links.b.publicKey,
          endpoint: { host: fixture.rightHost, port: guardPort }
        },
        ...clocks
      })
    )
    cleanup.push(() => destroyGuardLease(lease))

    const sourceRelayOwner = createPeerRelayOwner({
      endpoint: fixture.left,
      identityKeyPair: fixture.links.a,
      routeKeyPair: sourceRoute,
      advertisementFields: {
        relayIdentity32: fixture.links.a.publicKey,
        currentDhtNodeId32: seed(0x31),
        reachableEndpoint: { host: '127.0.0.1', port: sourcePort },
        routeEncryptionPublicKey32: sourceRoute.publicKey,
        capabilityMask: 11,
        minimumVersion: 2,
        maximumVersion: 2,
        datagramReplayWindow: 64,
        maxConcurrentCircuits,
        capacityClass: 1,
        maxCells: 10000,
        maxBytes: 1000000,
        maxCommands: 1000,
        idleTimeoutMs: 30000,
        maxQueuedBytes: 524288,
        epoch: 7n,
        issuedAt: 1000n,
        expiresAt,
        policyCount: 0
      },
      ...clocks
    })
    cleanup.push(() => destroyPeerRelayOwner(sourceRelayOwner))

    const guardRelayOwner = createPeerRelayOwner({
      endpoint: fixture.right,
      identityKeyPair: fixture.links.b,
      routeKeyPair: guardRoute,
      advertisementFields: {
        relayIdentity32: fixture.links.b.publicKey,
        currentDhtNodeId32: seed(0x32),
        reachableEndpoint: { host: fixture.rightHost, port: guardPort },
        routeEncryptionPublicKey32: guardRoute.publicKey,
        capabilityMask: 9,
        minimumVersion: 2,
        maximumVersion: 2,
        datagramReplayWindow: 64,
        maxConcurrentCircuits,
        capacityClass: 1,
        maxCells: 10000,
        maxBytes: 1000000,
        maxCommands: 1000,
        idleTimeoutMs: 30000,
        maxQueuedBytes: 524288,
        epoch: 7n,
        issuedAt: 1000n,
        expiresAt,
        policyCount: 0
      },
      ...clocks
    })
    cleanup.push(() => destroyPeerRelayOwner(guardRelayOwner))

    const guardPool = createPeerNativeNeighborPool({
      relayOwner: guardRelayOwner,
      endpoint: fixture.right,
      maxNeighbors: 4,
      nodeServiceBudget: {
        cells: nodeServiceCells,
        bytes: 1200n * BigInt(nodeServiceCells),
        commands: nodeServiceCells
      },
      neighborServiceReservation: {
        cells: serviceCells,
        bytes: 1200n * BigInt(serviceCells),
        commands: serviceCells
      },
      neighborCloseReservation: { cells: 10, bytes: 12_000n, commands: 10 }
    })
    cleanup.push(() => destroyPeerNativeNeighborPool(guardPool))

    const bootstrap = createPeerBootstrapResponder(guardRelayOwner)
    cleanup.push(() => destroyPeerBootstrapResponder(bootstrap))
    const registration = registerPeerDirectResponder(fixture.right, bootstrap)
    cleanup.push(() => destroyPeerDirectResponderRegistration(registration))

    let guardRuntime = null
    let guardTailSession = null
    const guardParentLedgers = ledgers(2)
    const guardResponder = createPeerLinkResponder(guardRelayOwner, {
      ...guardParentLedgers,
      onEstablished(handle) {
        guardRuntime = adoptPeerEstablishedLink(guardAuthority, handle)
        queueMicrotask(() => {
          try {
            if (guardRuntime && !guardTailSession) {
              guardTailSession = createPeerTailControl(guardRuntime, {
                relayOwner: guardRelayOwner,
                neighborPool: guardPool,
                runtimeAuthority: guardAuthority,
                memoryPool: grdPool,
                sendLedger: guardParentLedgers.sendLedger,
                receiveLedger: guardParentLedgers.receiveLedger,
                teardownSendLedger: guardParentLedgers.teardownSendLedger,
                teardownReceiveLedger: guardParentLedgers.teardownReceiveLedger
              })
              cleanup.push(() => destroyPeerTailControl(guardTailSession))
              guardTailStarted.resolve(guardTailSession)
            }
          } catch (err) {
            guardTailStarted.reject(err)
          }
        })
        return guardRuntime
      }
    })
    cleanup.push(() => destroyPeerLinkResponder(guardResponder))
    registerSharedGuardPeerBranchResponder(fixture.rightSession.established, guardResponder)

    const safetyEndpoint = createBoundEndpoint(fixture.network, peerHost, safetyPort, null, native)
    cleanup.push(() => safetyEndpoint.close())
    await safetyEndpoint.bind()

    const safetyRelayOwner = createPeerRelayOwner({
      endpoint: safetyEndpoint,
      identityKeyPair: safetyKeys,
      routeKeyPair: safetyRoute,
      advertisementFields: {
        relayIdentity32: safetyKeys.publicKey,
        currentDhtNodeId32: seed(0x33),
        reachableEndpoint: { host: peerHost, port: safetyPort },
        routeEncryptionPublicKey32: safetyRoute.publicKey,
        capabilityMask: safetyCapabilityMask,
        minimumVersion: 2,
        maximumVersion: 2,
        datagramReplayWindow: 64,
        maxConcurrentCircuits,
        capacityClass: 1,
        maxCells: 10000,
        maxBytes: 1000000,
        maxCommands: 1000,
        idleTimeoutMs: 30000,
        maxQueuedBytes: 524288,
        epoch: 7n,
        issuedAt: 1000n,
        expiresAt,
        policyCount: 0
      },
      ...clocks
    })
    cleanup.push(() => destroyPeerRelayOwner(safetyRelayOwner))

    const safetyCanonicalWire260 = readPeerRelayOwner(
      safetyRelayOwner,
      safetyEndpoint
    ).canonicalAdvertisement260
    const safetyVerifiedAd = verifyPeerAdvertisement(safetyCanonicalWire260, {
      expectedIdentity32: safetyKeys.publicKey,
      expectedRole: 1,
      ...clocks
    })
    const safetyBootstrap = createPeerBootstrapResponder(safetyRelayOwner)
    cleanup.push(() => destroyPeerBootstrapResponder(safetyBootstrap))
    const safetyRegistration = registerPeerDirectResponder(safetyEndpoint, safetyBootstrap)
    cleanup.push(() => destroyPeerDirectResponderRegistration(safetyRegistration))

    const safetyPool = createPeerNativeNeighborPool({
      relayOwner: safetyRelayOwner,
      endpoint: safetyEndpoint,
      maxNeighbors: 4,
      nodeServiceBudget: {
        cells: nodeServiceCells,
        bytes: 1200n * BigInt(nodeServiceCells),
        commands: nodeServiceCells
      },
      neighborServiceReservation: {
        cells: serviceCells,
        bytes: 1200n * BigInt(serviceCells),
        commands: serviceCells
      },
      neighborCloseReservation: { cells: 10, bytes: 12_000n, commands: 10 }
    })
    cleanup.push(() => destroyPeerNativeNeighborPool(safetyPool))

    let safetyRuntime = null
    let safetyTailSession = null
    const safetyParentLedgers = ledgers(2)
    const safetyResponder = createPeerLinkResponder(safetyRelayOwner, {
      ...safetyParentLedgers,
      onEstablished(handle) {
        safetyRuntime = adoptPeerEstablishedLink(safetyAuthority, handle)
        if (suppressSafetyTailReady) {
          safetyTailStarted.resolve(null)
          return safetyRuntime
        }
        queueMicrotask(() => {
          try {
            if (safetyRuntime && !safetyTailSession) {
              safetyTailSession = createPeerTailControl(safetyRuntime, {
                relayOwner: safetyRelayOwnerOverride || safetyRelayOwner,
                neighborPool: safetyPool,
                runtimeAuthority: safetyAuthority,
                memoryPool: sftPool,
                sendLedger: safetyParentLedgers.sendLedger,
                receiveLedger: safetyParentLedgers.receiveLedger,
                teardownSendLedger: safetyParentLedgers.teardownSendLedger,
                teardownReceiveLedger: safetyParentLedgers.teardownReceiveLedger
              })
              cleanup.push(() => destroyPeerTailControl(safetyTailSession))
              safetyTailStarted.resolve(safetyTailSession)
            }
          } catch (err) {
            safetyTailStarted.reject(err)
          }
        })
        return safetyRuntime
      }
    })
    cleanup.push(() => destroyPeerLinkResponder(safetyResponder))

    const guardSafetyDir = new LinkDirectory({
      localIdentity32: fixture.links.b.publicKey,
      localRole: TOPOLOGY_ROLE.SAFETY_GUARD,
      authorityPublicKey: grantAuthority.publicKey,
      epoch: 7n,
      runId32: seed(0x81),
      now: () => 1n,
      schedule: setTimeout,
      cancel: clearTimeout,
      onClose() {}
    })
    cleanup.push(() => guardSafetyDir.destroy())

    const safetyGuardDir = new LinkDirectory({
      localIdentity32: safetyKeys.publicKey,
      localRole: TOPOLOGY_ROLE.SAFETY_FINAL,
      authorityPublicKey: grantAuthority.publicKey,
      epoch: 7n,
      runId32: seed(0x81),
      now: () => 1n,
      schedule: setTimeout,
      cancel: clearTimeout,
      onClose() {}
    })
    cleanup.push(() => safetyGuardDir.destroy())

    const grantGuardSafety = buildSignedGrant({
      authority: grantAuthority,
      local: fixture.links.b,
      peer: safetyKeys,
      localHost: fixture.rightHost,
      localPort: guardPort,
      peerHost,
      peerPort: safetyPort,
      epoch: 7n,
      runId32: seed(0x81),
      grantId32: seed(0x82),
      localRole: TOPOLOGY_ROLE.SAFETY_GUARD,
      peerRole: TOPOLOGY_ROLE.SAFETY_FINAL,
      expiresAt
    })

    const guardLinkHandle = guardSafetyDir.authorize({
      digest32: guardSafetyDir.add(grantGuardSafety),
      operation: LINK_OPERATION.INITIATE,
      localIdentity32: fixture.links.b.publicKey,
      localRole: TOPOLOGY_ROLE.SAFETY_GUARD,
      peerIdentity32: safetyKeys.publicKey,
      peerRole: TOPOLOGY_ROLE.SAFETY_FINAL,
      epoch: 7n,
      runId32: seed(0x81)
    })

    const safetyLinkHandle = safetyGuardDir.authorize({
      digest32: safetyGuardDir.add(grantGuardSafety),
      operation: LINK_OPERATION.ACCEPT,
      localIdentity32: safetyKeys.publicKey,
      localRole: TOPOLOGY_ROLE.SAFETY_FINAL,
      peerIdentity32: fixture.links.b.publicKey,
      peerRole: TOPOLOGY_ROLE.SAFETY_GUARD,
      epoch: 7n,
      runId32: seed(0x81)
    })

    const staticPair1 = cryptoSuite.encryptionKeyPair(seed(0xd5))
    const sessionIds1 = {
      circuitId: seed(0xe1).subarray(0, 16),
      initiatorLocalId: seed(0xe2).subarray(0, 16),
      responderLocalId: seed(0xe3).subarray(0, 16)
    }
    const guardSessionOptions = buildSessionOptions(
      guardLinkHandle,
      'initiate',
      fixture.links.b,
      safetyKeys,
      staticPair1,
      c,
      sessionIds1
    )
    const safetySessionOptions = buildSessionOptions(
      safetyLinkHandle,
      'accept',
      fixture.links.b,
      safetyKeys,
      staticPair1,
      c,
      sessionIds1
    )

    const guardCanonicalWire260 = readPeerRelayOwner(
      guardRelayOwner,
      fixture.right
    ).canonicalAdvertisement260
    const guardVerifiedAd = verifyPeerAdvertisement(guardCanonicalWire260, {
      expectedIdentity32: fixture.links.b.publicKey,
      expectedRole: 0,
      ...clocks
    })

    const [guardNeighbor, safetyNeighborFromGuard] = await Promise.all([
      provisionPeerNativeNeighbor(guardPool, {
        linkHandle: guardLinkHandle,
        advertisement: safetyVerifiedAd,
        mode: 'initiate',
        sessionOptions: guardSessionOptions
      }),
      provisionPeerNativeNeighbor(safetyPool, {
        linkHandle: safetyLinkHandle,
        advertisement: guardVerifiedAd,
        mode: 'accept',
        sessionOptions: safetySessionOptions
      })
    ])
    registerSharedGuardPeerBranchResponder(safetyNeighborFromGuard.established, safetyResponder)

    const terminalEndpoint = createBoundEndpoint(
      fixture.network,
      peerHost,
      terminalPort,
      null,
      native
    )
    cleanup.push(() => terminalEndpoint.close())
    await terminalEndpoint.bind()

    const terminalRelayOwner = createPeerRelayOwner({
      endpoint: terminalEndpoint,
      identityKeyPair: terminalKeys,
      routeKeyPair: terminalRoute,
      advertisementFields: {
        relayIdentity32: terminalKeys.publicKey,
        currentDhtNodeId32: seed(0x34),
        reachableEndpoint: { host: peerHost, port: terminalPort },
        routeEncryptionPublicKey32: terminalRoute.publicKey,
        capabilityMask: terminalCapabilityMask,
        minimumVersion: 2,
        maximumVersion: 2,
        datagramReplayWindow: 64,
        maxConcurrentCircuits,
        capacityClass: 1,
        maxCells: 10000,
        maxBytes: 1000000,
        maxCommands: 1000,
        idleTimeoutMs: 30000,
        maxQueuedBytes: 524288,
        epoch: 7n,
        issuedAt: 1000n,
        expiresAt,
        policyCount: 0
      },
      ...clocks
    })
    cleanup.push(() => destroyPeerRelayOwner(terminalRelayOwner))

    const terminalCanonicalWire260 = readPeerRelayOwner(
      terminalRelayOwner,
      terminalEndpoint
    ).canonicalAdvertisement260
    const terminalVerifiedAd = verifyPeerAdvertisement(terminalCanonicalWire260, {
      expectedIdentity32: terminalKeys.publicKey,
      expectedRole: 2,
      ...clocks
    })
    const terminalBootstrap = createPeerBootstrapResponder(terminalRelayOwner)
    cleanup.push(() => destroyPeerBootstrapResponder(terminalBootstrap))
    const terminalRegistration = registerPeerDirectResponder(terminalEndpoint, terminalBootstrap)
    cleanup.push(() => destroyPeerDirectResponderRegistration(terminalRegistration))

    const terminalPool = createPeerNativeNeighborPool({
      relayOwner: terminalRelayOwner,
      endpoint: terminalEndpoint,
      maxNeighbors: 4,
      nodeServiceBudget: {
        cells: nodeServiceCells,
        bytes: 1200n * BigInt(nodeServiceCells),
        commands: nodeServiceCells
      },
      neighborServiceReservation: {
        cells: serviceCells,
        bytes: 1200n * BigInt(serviceCells),
        commands: serviceCells
      },
      neighborCloseReservation: { cells: 10, bytes: 12_000n, commands: 10 }
    })
    cleanup.push(() => destroyPeerNativeNeighborPool(terminalPool))

    let terminalRuntime = null
    let terminalTailSession = null
    const terminalParentLedgers = ledgers(1)
    const terminalResponder = createPeerLinkResponder(terminalRelayOwner, {
      ...terminalParentLedgers,
      onEstablished(handle) {
        terminalRuntime = adoptPeerEstablishedLink(terminalAuthority, handle)
        queueMicrotask(() => {
          try {
            if (terminalRuntime && !terminalTailSession) {
              terminalTailSession = createPeerTailControl(terminalRuntime, {
                relayOwner: terminalRelayOwner,
                memoryPool: trmPool,
                onFinalReady(session) {
                  if (typeof onTerminalFinalReady === 'function') {
                    onTerminalFinalReady(session)
                  }
                }
              })
              cleanup.push(() => destroyPeerTailControl(terminalTailSession))
              terminalTailStarted.resolve(terminalTailSession)
            }
          } catch (err) {
            terminalTailStarted.reject(err)
          }
        })
        return terminalRuntime
      }
    })
    cleanup.push(() => destroyPeerLinkResponder(terminalResponder))
    const safetyTerminalDir = new LinkDirectory({
      localIdentity32: safetyKeys.publicKey,
      localRole: TOPOLOGY_ROLE.SAFETY_GUARD,
      authorityPublicKey: grantAuthority.publicKey,
      epoch: 7n,
      runId32: seed(0x91),
      now: () => 1n,
      schedule: setTimeout,
      cancel: clearTimeout,
      onClose() {}
    })
    cleanup.push(() => safetyTerminalDir.destroy())

    const terminalSafetyDir = new LinkDirectory({
      localIdentity32: terminalKeys.publicKey,
      localRole: TOPOLOGY_ROLE.SAFETY_FINAL,
      authorityPublicKey: grantAuthority.publicKey,
      epoch: 7n,
      runId32: seed(0x91),
      now: () => 1n,
      schedule: setTimeout,
      cancel: clearTimeout,
      onClose() {}
    })
    cleanup.push(() => terminalSafetyDir.destroy())

    const grantSafetyTerminal = buildSignedGrant({
      authority: grantAuthority,
      local: safetyKeys,
      peer: terminalKeys,
      localHost: peerHost,
      localPort: safetyPort,
      peerHost,
      peerPort: terminalPort,
      epoch: 7n,
      runId32: seed(0x91),
      grantId32: seed(0x92),
      localRole: TOPOLOGY_ROLE.SAFETY_GUARD,
      peerRole: TOPOLOGY_ROLE.SAFETY_FINAL,
      expiresAt
    })

    const safetyTerminalLinkHandle = safetyTerminalDir.authorize({
      digest32: safetyTerminalDir.add(grantSafetyTerminal),
      operation: LINK_OPERATION.INITIATE,
      localIdentity32: safetyKeys.publicKey,
      localRole: TOPOLOGY_ROLE.SAFETY_GUARD,
      peerIdentity32: terminalKeys.publicKey,
      peerRole: TOPOLOGY_ROLE.SAFETY_FINAL,
      epoch: 7n,
      runId32: seed(0x91)
    })

    const terminalSafetyLinkHandle = terminalSafetyDir.authorize({
      digest32: terminalSafetyDir.add(grantSafetyTerminal),
      operation: LINK_OPERATION.ACCEPT,
      localIdentity32: terminalKeys.publicKey,
      localRole: TOPOLOGY_ROLE.SAFETY_FINAL,
      peerIdentity32: safetyKeys.publicKey,
      peerRole: TOPOLOGY_ROLE.SAFETY_GUARD,
      epoch: 7n,
      runId32: seed(0x91)
    })

    const staticPair2 = cryptoSuite.encryptionKeyPair(seed(0xd6))
    const sessionIds2 = {
      circuitId: seed(0xf1).subarray(0, 16),
      initiatorLocalId: seed(0xf2).subarray(0, 16),
      responderLocalId: seed(0xf3).subarray(0, 16)
    }
    const safetyTerminalSessionOptions = buildSessionOptions(
      safetyTerminalLinkHandle,
      'initiate',
      safetyKeys,
      terminalKeys,
      staticPair2,
      c,
      sessionIds2
    )
    const terminalSafetySessionOptions = buildSessionOptions(
      terminalSafetyLinkHandle,
      'accept',
      safetyKeys,
      terminalKeys,
      staticPair2,
      c,
      sessionIds2
    )

    const [safetyToTerminalNeighbor, terminalNeighborFromSafety] = await Promise.all([
      provisionPeerNativeNeighbor(safetyPool, {
        linkHandle: safetyTerminalLinkHandle,
        advertisement: terminalVerifiedAd,
        mode: 'initiate',
        sessionOptions: safetyTerminalSessionOptions
      }),
      provisionPeerNativeNeighbor(terminalPool, {
        linkHandle: terminalSafetyLinkHandle,
        advertisement: safetyVerifiedAd,
        mode: 'accept',
        sessionOptions: terminalSafetySessionOptions
      })
    ])
    registerSharedGuardPeerBranchResponder(
      terminalNeighborFromSafety.established,
      terminalResponder
    )

    const guardAdvertisement = readPeerRelayOwner(guardRelayOwner).canonicalAdvertisement260

    async function openSourceA0(overrides = {}) {
      const candidate = await discoverPeerCandidate(createPeerGuardBootstrapTransport(lease), {
        ledger: createPeerLedger({ cells: 24, bytes: 28800n, commands: 0 }),
        requestedMask: 9,
        randomTarget: seed(0xa1),
        maximumResults: 1
      })
      const tailKeyPair = cryptoSuite.encryptionKeyPair(seed(0xb1))
      const limits = {
        cellSize: 1200,
        maxCells: 30,
        maxBytes: 36000,
        maxCommands: 21,
        idleTimeoutMs: 30000,
        expiresAt: 50000n
      }
      const handle = await openPeerGuardLink({
        guardLease: lease,
        activeCandidate: candidate,
        relayOwner: sourceRelayOwner,
        advertisement: guardAdvertisement,
        branchId: b4a.alloc(16, 0x01),
        circuitId: b4a.alloc(16, 0x02),
        generation: 1n,
        extensionIndex: 0,
        clientTailEphemeralPublicKey: tailKeyPair.publicKey,
        clientTailSecretKey: tailKeyPair.secretKey,
        clientNonce: seed(0x03),
        payloadParametersDigest: seed(0x04),
        candidateAuthorityCommitment32: b4a.alloc(32),
        forwardLimits: limits,
        reverseLimits: limits,
        operationDeadline: c.monotonicNow() + 2000n,
        ...ledgers(),
        ...overrides
      })
      const sourceRuntime = adoptPeerEstablishedLink(localAuthority, handle)
      await guardTailStarted.promise
      const sourceTailSession = createPeerTailControl(sourceRuntime, {
        memoryPool: srcPool
      })
      cleanup.push(() => destroyPeerTailControl(sourceTailSession))
      return {
        sourceRuntime,
        sourceTailSession,
        limits
      }
    }

    return {
      close,
      fixture,
      clock: c,
      clocks,
      openSourceA0,
      source: {
        endpoint: fixture.left,
        relayOwner: sourceRelayOwner,
        identity32: b4a.from(fixture.links.a.publicKey),
        lease,
        memoryPool: srcPool,
        authority: localAuthority
      },
      guard: {
        endpoint: fixture.right,
        relayOwner: guardRelayOwner,
        identity32: b4a.from(fixture.links.b.publicKey),
        pool: guardPool,
        memoryPool: grdPool,
        authority: guardAuthority,
        neighbor: guardNeighbor,
        tailStarted: guardTailStarted.promise,
        get runtime() {
          return guardRuntime
        },
        get tailSession() {
          return guardTailSession
        }
      },
      safety: {
        endpoint: safetyEndpoint,
        relayOwner: safetyRelayOwner,
        identity32: b4a.from(safetyKeys.publicKey),
        pool: safetyPool,
        memoryPool: sftPool,
        authority: safetyAuthority,
        verifiedAd: safetyVerifiedAd,
        neighborFromGuard: safetyNeighborFromGuard,
        neighborToTerminal: safetyToTerminalNeighbor,
        tailStarted: safetyTailStarted.promise,
        get runtime() {
          return safetyRuntime
        },
        get tailSession() {
          return safetyTailSession
        }
      },
      terminal: {
        endpoint: terminalEndpoint,
        relayOwner: terminalRelayOwner,
        identity32: b4a.from(terminalKeys.publicKey),
        pool: terminalPool,
        memoryPool: trmPool,
        authority: terminalAuthority,
        verifiedAd: terminalVerifiedAd,
        neighborFromSafety: terminalNeighborFromSafety,
        tailStarted: terminalTailStarted.promise,
        get runtime() {
          return terminalRuntime
        },
        get tailSession() {
          return terminalTailSession
        }
      }
    }
  } catch (err) {
    try {
      await close()
    } catch (cleanupError) {
      throw new AggregateError([err, cleanupError], 'Native fixture setup and cleanup failed', {
        cause: err
      })
    }
    throw err
  }
}

function buildVerifiedAd({
  peer,
  peerRoute,
  host,
  port,
  epoch = 1n,
  expiresAt = 60_000n,
  capabilityMask = 11,
  clock,
  endpoint = null,
  maxConcurrentCircuits = 128
}) {
  const peerEndpoint = endpoint || createBoundEndpoint(new Map(), host, port)
  const owner = createPeerRelayOwner({
    endpoint: peerEndpoint,
    identityKeyPair: peer,
    routeKeyPair: peerRoute,
    advertisementFields: {
      relayIdentity32: peer.publicKey,
      currentDhtNodeId32: seed(0x33),
      reachableEndpoint: { host, port },
      routeEncryptionPublicKey32: peerRoute.publicKey,
      capabilityMask,
      minimumVersion: 2,
      maximumVersion: 2,
      datagramReplayWindow: 64,
      maxConcurrentCircuits,
      capacityClass: 1,
      maxCells: 10000,
      maxBytes: 1000000,
      maxCommands: 1000,
      idleTimeoutMs: 30000,
      maxQueuedBytes: 524288,
      epoch,
      issuedAt: 1000n,
      expiresAt,
      policyCount: 0
    },
    clockIdentity: clock,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer
  })
  const ownerInfo = readPeerRelayOwner(owner, peerEndpoint)
  const canonicalWire260 = ownerInfo.canonicalAdvertisement260

  const verified = verifyPeerAdvertisement(canonicalWire260, {
    expectedIdentity32: peer.publicKey,
    expectedRole: capabilityMask === 9 ? 1 : 2,
    clockIdentity: clock,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow
  })
  return { owner, verified }
}

function buildSessionOptions(handle, mode, localKey, peerKey, staticPair, clock, sessionIds = {}) {
  const initiate = mode === 'initiate'
  let random = initiate ? 0x61 : 0x71
  const randomBytes = (size) => b4a.alloc(size, random++)
  const now = () => Number(clock.monotonicNow())
  const common = {
    circuitId: sessionIds.circuitId || b4a.alloc(16, 0xd5),
    epoch: sessionIds.epoch !== undefined ? sessionIds.epoch : readLinkHandle(handle).epoch,
    initiatorIdentity: localKey.publicKey,
    responderIdentity: peerKey.publicKey,
    initiatorLocalId: sessionIds.initiatorLocalId || b4a.alloc(16, 0xd6),
    responderLocalId: sessionIds.responderLocalId || b4a.alloc(16, 0xd7),
    expiresAt: 60_000n
  }
  return {
    mode,
    clockIdentity: clock,
    codec: new BootstrapEnvelopeCodec({
      linkHandle: handle,
      localIdentitySecretKey: initiate ? localKey.secretKey : peerKey.secretKey,
      padding: randomBytes
    }),
    linkSetup: createLinkSetupAuthority({ now, randomBytes }),
    setup: initiate
      ? {
          ...common,
          responderStaticKey: staticPair.publicKey,
          initiatorIdentitySecretKey: localKey.secretKey
        }
      : {
          ...common,
          responderStaticSecretKey: staticPair.secretKey,
          responderIdentitySecretKey: peerKey.secretKey
        },
    now,
    schedule: (cb, ms) => clock.setTimer(cb, ms),
    cancel: (id) => clock.clearTimer(id),
    randomBytes,
    absoluteDeadline: now() + 10_000,
    signedExpiry: 60_000,
    authorizedExpiry: 60_000
  }
}

// -----------------------------------------------------------------------------
// Two-Ended Live Native Adjacency Fixture
// -----------------------------------------------------------------------------

async function setupNativePoolPreflight({
  t,
  clock,
  localPort = 48101,
  peerPort = 48102,
  capabilityMask = 11,
  native = false,
  maxNeighbors = 4,
  expiresAt = 2000000n,
  serviceCells = 20,
  nodeServiceCells = 100,
  maxConcurrentCircuits = 128
} = {}) {
  const network = new Map()
  const { authority, local, localRoute, peer, peerRoute } = fixtureKeys()
  const runId32 = seed(0x99)
  const staticPair = cryptoSuite.encryptionKeyPair(seed(0xd4))

  const [localHost, peerHost] = native
    ? selectUdxLoopbackHosts({ platform: global.Bare ? Bare.platform : process.platform })
    : ['127.0.0.1', '127.0.0.1']
  const localEndpoint = createBoundEndpoint(network, localHost, localPort, null, native)
  const peerEndpoint = createBoundEndpoint(network, peerHost, peerPort, null, native)

  await localEndpoint.bind()
  await peerEndpoint.bind()

  const localRelayOwner = createPeerRelayOwner({
    endpoint: localEndpoint,
    identityKeyPair: local,
    routeKeyPair: localRoute,
    advertisementFields: {
      relayIdentity32: local.publicKey,
      currentDhtNodeId32: seed(0x30),
      reachableEndpoint: { host: localHost, port: localPort },
      routeEncryptionPublicKey32: localRoute.publicKey,
      capabilityMask: 11,
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
      epoch: 1n,
      issuedAt: 1000n,
      expiresAt,
      policyCount: 0
    },
    clockIdentity: clock,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer
  })

  const localDirectory = new LinkDirectory({
    localIdentity32: local.publicKey,
    localRole: TOPOLOGY_ROLE.SAFETY_GUARD,
    authorityPublicKey: authority.publicKey,
    epoch: 1n,
    runId32,
    now: () => 1n,
    schedule: setTimeout,
    cancel: clearTimeout,
    onClose() {}
  })

  const peerDirectory = new LinkDirectory({
    localIdentity32: peer.publicKey,
    localRole: TOPOLOGY_ROLE.SAFETY_FINAL,
    authorityPublicKey: authority.publicKey,
    epoch: 1n,
    runId32,
    now: () => 1n,
    schedule: setTimeout,
    cancel: clearTimeout,
    onClose() {}
  })

  const grant = buildSignedGrant({
    authority,
    local,
    peer,
    localHost,
    localPort,
    peerHost,
    peerPort,
    epoch: 1n,
    runId32,
    expiresAt
  })

  const { owner: peerRelayOwner, verified: verifiedAd } = buildVerifiedAd({
    peer,
    peerRoute,
    host: peerHost,
    port: peerPort,
    epoch: 1n,
    clock,
    capabilityMask,
    endpoint: peerEndpoint,
    expiresAt,
    maxConcurrentCircuits
  })

  const localCanonicalWire260 = readPeerRelayOwner(
    localRelayOwner,
    localEndpoint
  ).canonicalAdvertisement260
  const localVerifiedAd = verifyPeerAdvertisement(localCanonicalWire260, {
    expectedIdentity32: local.publicKey,
    expectedRole: 2,
    clockIdentity: clock,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow
  })

  // Authorize accept handle on peer
  const peerDigest = peerDirectory.add(grant)
  const peerLinkHandle = peerDirectory.authorize({
    digest32: peerDigest,
    operation: LINK_OPERATION.ACCEPT,
    localIdentity32: peer.publicKey,
    localRole: TOPOLOGY_ROLE.SAFETY_FINAL,
    peerIdentity32: local.publicKey,
    peerRole: TOPOLOGY_ROLE.SAFETY_GUARD,
    epoch: 1n,
    runId32
  })
  const peerSessionOptions = buildSessionOptions(
    peerLinkHandle,
    'accept',
    local,
    peer,
    staticPair,
    clock
  )

  // Create local neighbor pool (no linkDirectory)
  const pool = createPeerNativeNeighborPool({
    relayOwner: localRelayOwner,
    endpoint: localEndpoint,
    maxNeighbors,
    nodeServiceBudget: {
      cells: nodeServiceCells,
      bytes: 1200n * BigInt(nodeServiceCells),
      commands: nodeServiceCells
    },
    neighborServiceReservation: {
      cells: serviceCells,
      bytes: 1200n * BigInt(serviceCells),
      commands: serviceCells
    },
    neighborCloseReservation: { cells: 10, bytes: 12_000n, commands: 10 }
  })

  // Create peer neighbor pool (no linkDirectory)
  const peerPool = createPeerNativeNeighborPool({
    relayOwner: peerRelayOwner,
    endpoint: peerEndpoint,
    maxNeighbors,
    nodeServiceBudget: {
      cells: nodeServiceCells,
      bytes: 1200n * BigInt(nodeServiceCells),
      commands: nodeServiceCells
    },
    neighborServiceReservation: {
      cells: serviceCells,
      bytes: 1200n * BigInt(serviceCells),
      commands: serviceCells
    },
    neighborCloseReservation: { cells: 10, bytes: 12_000n, commands: 10 }
  })
  // Authorize initiate handle on local
  const localDigest = localDirectory.add(grant)
  const localLinkHandle = localDirectory.authorize({
    digest32: localDigest,
    operation: LINK_OPERATION.INITIATE,
    localIdentity32: local.publicKey,
    localRole: TOPOLOGY_ROLE.SAFETY_GUARD,
    peerIdentity32: peer.publicKey,
    peerRole: TOPOLOGY_ROLE.SAFETY_FINAL,
    epoch: 1n,
    runId32
  })
  const localSessionOptions = buildSessionOptions(
    localLinkHandle,
    'initiate',
    local,
    peer,
    staticPair,
    clock
  )

  t.teardown(async () => {
    destroyPeerNativeNeighborPool(pool)
    destroyPeerNativeNeighborPool(peerPool)
    localDirectory.destroy()
    peerDirectory.destroy()
    await Promise.allSettled([localEndpoint.close(), peerEndpoint.close()])
  })

  return {
    authority,
    runId32,
    local,
    localRoute,
    peer,
    peerRoute,
    clock,
    localRelayOwner,
    peerRelayOwner,
    localEndpoint,
    peerEndpoint,
    localSocket: native ? null : network.get(`${localHost}:${localPort}`),
    peerSocket: native ? null : network.get(`${peerHost}:${peerPort}`),
    localDirectory,
    peerDirectory,
    grant,
    verifiedAd,
    localVerifiedAd,
    localLinkHandle,
    peerLinkHandle,
    localSessionOptions,
    peerSessionOptions,
    async discover() {
      const responder = createPeerBootstrapResponder(peerRelayOwner)
      const registration = registerPeerDirectResponder(peerEndpoint, responder)
      try {
        const locator = createPeerCandidateLocator(localRelayOwner, verifiedAd)
        const transport = createPeerCandidateDirectTransport(localEndpoint, locator)
        return await discoverPeerCandidate(transport, {
          ledger: createPeerLedger({ cells: 24, bytes: 28_800n, commands: 0 }),
          requestedMask: capabilityMask,
          randomTarget: seed(0x7a),
          maximumResults: 1
        })
      } finally {
        destroyPeerDirectResponderRegistration(registration)
        destroyPeerBootstrapResponder(responder)
      }
    },
    peerPool,
    pool,
    network,
    localHost,
    peerHost,
    native,
    localPort,
    peerPort,
    capabilityMask
  }
}

async function setupTwoEndedNativeAdjacency({
  t,
  clock,
  localPort = 48101,
  peerPort = 48102,
  capabilityMask = 11,
  native = false,
  maxNeighbors = 4,
  expiresAt = 2000000n,
  serviceCells = 20,
  nodeServiceCells = 100,
  maxConcurrentCircuits = 128
} = {}) {
  const f = await setupNativePoolPreflight({
    t,
    clock,
    localPort,
    peerPort,
    capabilityMask,
    native,
    maxNeighbors,
    expiresAt,
    serviceCells,
    nodeServiceCells,
    maxConcurrentCircuits
  })

  const [peerNeighbor, localNeighbor] = await Promise.all([
    provisionPeerNativeNeighbor(f.peerPool, {
      linkHandle: f.peerLinkHandle,
      advertisement: f.localVerifiedAd,
      mode: 'accept',
      sessionOptions: f.peerSessionOptions
    }),
    provisionPeerNativeNeighbor(f.pool, {
      linkHandle: f.localLinkHandle,
      advertisement: f.verifiedAd,
      mode: 'initiate',
      sessionOptions: f.localSessionOptions
    })
  ])
  return {
    ...f,
    neighbor: localNeighbor,
    peerNeighbor
  }
}

function ledgers(branches = 1) {
  const budget = { cells: 20 * branches, bytes: 24000n * BigInt(branches), commands: 20 * branches }
  const closure = { cells: 10 * branches, bytes: 12000n * BigInt(branches), commands: branches }
  return {
    sendLedger: createPeerLedger(budget),
    receiveLedger: createPeerLedger(budget),
    teardownSendLedger: createPeerLedger(closure),
    teardownReceiveLedger: createPeerLedger(closure)
  }
}

async function authenticatedPeer(t, port, extensionIndex = 2, native = false, options = {}) {
  const clock = fakeClock()
  const maxConcurrentCircuits = options.maxConcurrentCircuits || 128
  const f = await setupTwoEndedNativeAdjacency({
    t,
    clock,
    native,
    localPort: port,
    peerPort: port + 1,
    capabilityMask: extensionIndex === 1 ? 9 : 11,
    serviceCells: 60,
    nodeServiceCells: options.nodeServiceCells || (options.maxConcurrentCircuits ? 300 : 100),
    maxConcurrentCircuits
  })
  const authorityOptions = {
    clockIdentity: clock,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer
  }
  const localAuthority = createPeerM3AdjacencyAuthority(authorityOptions)
  const peerAuthority = createPeerM3AdjacencyAuthority(authorityOptions)
  const peerLedgers = ledgers(options.peerBranches || 6)
  const adoptedPeerRuntimes = []
  let peerRuntime = null
  const responder = createPeerLinkResponder(f.peerRelayOwner, {
    ...peerLedgers,
    onEstablished(handle) {
      peerRuntime = adoptPeerEstablishedLink(peerAuthority, handle)
      adoptedPeerRuntimes.push(peerRuntime)
      return peerRuntime
    }
  })
  registerSharedGuardPeerBranchResponder(f.peerNeighbor.established, responder)
  t.teardown(() => {
    destroyPeerLinkResponder(responder)
    localAuthority.destroy()
    peerAuthority.destroy()
  })
  const limits = {
    cellSize: 1200,
    maxCells: 30,
    maxBytes: 36000,
    maxCommands: 21,
    idleTimeoutMs: 30000,
    expiresAt: 50000n
  }
  let branchNumber = 0
  async function openAdditional({
    forwardLimits = limits,
    reverseLimits = limits,
    localLedgers = ledgers()
  } = {}) {
    const number = branchNumber++
    const handle = await openPeerNeighborLink({
      neighborPool: f.pool,
      activeCandidate: await f.discover(),
      relayOwner: f.localRelayOwner,
      advertisement: readVerifiedPeerAdvertisement(f.verifiedAd).canonicalBytes260,
      branchId: b4a.alloc(16, 0x41 + number),
      circuitId: b4a.alloc(16, 0x42 + number),
      generation: 1n,
      extensionIndex,
      clientTailEphemeralPublicKey: cryptoSuite.encryptionKeyPair(seed(0x43)).publicKey,
      clientNonce: seed(0x44 + number),
      payloadParametersDigest: seed(0x45),
      candidateAuthorityCommitment32: seed(0x46),
      forwardLimits,
      reverseLimits,
      operationDeadline: clock.monotonicNow() + 2000n,
      ...localLedgers
    })
    return { handle, peerRuntime, localLedgers }
  }
  return {
    f,
    clock,
    responder,
    adoptedPeerRuntimes,
    localAuthority,
    peerAuthority,
    limits,
    peerLedgers,
    ...(await openAdditional()),
    openAdditional
  }
}

async function setupDistinctNativeNeighbor(
  f,
  {
    t,
    responder,
    adoptedPeerRuntimes = null,
    port = 48532,
    limits = null,
    keySeed = 0x70,
    staticSeed = 0xd5
  } = {}
) {
  const initiatorKey = safetyIdentity(keySeed)
  const initiatorRouteKey = cryptoSuite.encryptionKeyPair(seed(keySeed + 1))
  const runId32 = f.runId32
  const staticPair = cryptoSuite.encryptionKeyPair(seed(staticSeed))

  const initiatorEndpoint = createBoundEndpoint(f.network, f.localHost, port, null, f.native)
  await initiatorEndpoint.bind()

  const initiatorRelayOwner = createPeerRelayOwner({
    endpoint: initiatorEndpoint,
    identityKeyPair: initiatorKey,
    routeKeyPair: initiatorRouteKey,
    advertisementFields: {
      relayIdentity32: initiatorKey.publicKey,
      currentDhtNodeId32: seed(keySeed + 3),
      reachableEndpoint: { host: f.localHost, port },
      routeEncryptionPublicKey32: initiatorRouteKey.publicKey,
      capabilityMask: 11,
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
      epoch: 1n,
      issuedAt: 1000n,
      expiresAt: 2000000n,
      policyCount: 0
    },
    clockIdentity: f.clock,
    wallNow: f.clock.wallNow,
    monotonicNow: f.clock.monotonicNow,
    setTimer: f.clock.setTimer,
    clearTimer: f.clock.clearTimer
  })

  const initiatorCanonicalWire260 = readPeerRelayOwner(
    initiatorRelayOwner,
    initiatorEndpoint
  ).canonicalAdvertisement260
  const initiatorVerifiedAd = verifyPeerAdvertisement(initiatorCanonicalWire260, {
    expectedIdentity32: initiatorKey.publicKey,
    expectedRole: 2,
    clockIdentity: f.clock,
    wallNow: f.clock.wallNow,
    monotonicNow: f.clock.monotonicNow
  })

  const initiatorDirectory = new LinkDirectory({
    localIdentity32: initiatorKey.publicKey,
    localRole: TOPOLOGY_ROLE.SAFETY_GUARD,
    authorityPublicKey: f.authority.publicKey,
    epoch: 1n,
    runId32,
    now: () => 1n,
    schedule: setTimeout,
    cancel: clearTimeout,
    onClose() {}
  })

  const grant = buildSignedGrant({
    authority: f.authority,
    local: initiatorKey,
    peer: f.peer,
    localHost: f.localHost,
    localPort: port,
    peerHost: f.peerHost,
    peerPort: f.peerPort,
    epoch: 1n,
    runId32,
    expiresAt: 2000000n
  })

  const peerDigest = f.peerDirectory.add(grant)
  const peerLinkHandle = f.peerDirectory.authorize({
    digest32: peerDigest,
    operation: LINK_OPERATION.ACCEPT,
    localIdentity32: f.peer.publicKey,
    localRole: TOPOLOGY_ROLE.SAFETY_FINAL,
    peerIdentity32: initiatorKey.publicKey,
    peerRole: TOPOLOGY_ROLE.SAFETY_GUARD,
    epoch: 1n,
    runId32
  })

  const initiatorDigest = initiatorDirectory.add(grant)
  const initiatorLinkHandle = initiatorDirectory.authorize({
    digest32: initiatorDigest,
    operation: LINK_OPERATION.INITIATE,
    localIdentity32: initiatorKey.publicKey,
    localRole: TOPOLOGY_ROLE.SAFETY_GUARD,
    peerIdentity32: f.peer.publicKey,
    peerRole: TOPOLOGY_ROLE.SAFETY_FINAL,
    epoch: 1n,
    runId32
  })

  const sessionIds = {
    circuitId: seed(keySeed + 5).subarray(0, 16),
    initiatorLocalId: seed(keySeed + 6).subarray(0, 16),
    responderLocalId: seed(keySeed + 7).subarray(0, 16)
  }
  const peerSessionOptions = buildSessionOptions(
    peerLinkHandle,
    'accept',
    initiatorKey,
    f.peer,
    staticPair,
    f.clock,
    sessionIds
  )
  const initiatorSessionOptions = buildSessionOptions(
    initiatorLinkHandle,
    'initiate',
    initiatorKey,
    f.peer,
    staticPair,
    f.clock,
    sessionIds
  )

  const initiatorPool = createPeerNativeNeighborPool({
    relayOwner: initiatorRelayOwner,
    endpoint: initiatorEndpoint,
    maxNeighbors: 4,
    nodeServiceBudget: { cells: 300, bytes: 360_000n, commands: 300 },
    neighborServiceReservation: {
      cells: 60,
      bytes: 1200n * 60n,
      commands: 60
    },
    neighborCloseReservation: { cells: 10, bytes: 12_000n, commands: 10 }
  })

  const [peerNeighbor, initiatorNeighbor] = await Promise.all([
    provisionPeerNativeNeighbor(f.peerPool, {
      linkHandle: peerLinkHandle,
      advertisement: initiatorVerifiedAd,
      mode: 'accept',
      sessionOptions: peerSessionOptions
    }),
    provisionPeerNativeNeighbor(initiatorPool, {
      linkHandle: initiatorLinkHandle,
      advertisement: f.verifiedAd,
      mode: 'initiate',
      sessionOptions: initiatorSessionOptions
    })
  ])

  registerSharedGuardPeerBranchResponder(peerNeighbor.established, responder)

  const authorityOptions = {
    clockIdentity: f.clock,
    wallNow: f.clock.wallNow,
    monotonicNow: f.clock.monotonicNow,
    setTimer: f.clock.setTimer,
    clearTimer: f.clock.clearTimer
  }
  const initiatorAuthority = createPeerM3AdjacencyAuthority(authorityOptions)

  if (t && typeof t.teardown === 'function') {
    t.teardown(async () => {
      initiatorAuthority.destroy()
      destroyPeerNativeNeighborPool(initiatorPool)
      initiatorDirectory.destroy()
      await initiatorEndpoint.close()
    })
  }

  const branchLimits = limits || {
    cellSize: 1200,
    maxCells: 30,
    maxBytes: 36000,
    maxCommands: 21,
    idleTimeoutMs: 30000,
    expiresAt: 50000n
  }

  async function discover() {
    const bootstrap = createPeerBootstrapResponder(f.peerRelayOwner)
    const registration = registerPeerDirectResponder(f.peerEndpoint, bootstrap)
    try {
      const locator = createPeerCandidateLocator(initiatorRelayOwner, f.verifiedAd)
      const transport = createPeerCandidateDirectTransport(initiatorEndpoint, locator)
      return await discoverPeerCandidate(transport, {
        ledger: createPeerLedger({ cells: 24, bytes: 28_800n, commands: 0 }),
        requestedMask: f.capabilityMask || 11,
        randomTarget: seed(keySeed + 4),
        maximumResults: 1
      })
    } finally {
      destroyPeerDirectResponderRegistration(registration)
      destroyPeerBootstrapResponder(bootstrap)
    }
  }

  let branchCount = 0
  async function openBranch({
    forwardLimits = branchLimits,
    reverseLimits = branchLimits,
    activeCandidate = null,
    localLedgers = ledgers(4)
  } = {}) {
    const n = branchCount++
    const handle = await openPeerNeighborLink({
      neighborPool: initiatorPool,
      activeCandidate: activeCandidate || (await discover()),
      relayOwner: initiatorRelayOwner,
      advertisement: readVerifiedPeerAdvertisement(f.verifiedAd).canonicalBytes260,
      branchId: b4a.alloc(16, keySeed + n),
      circuitId: b4a.alloc(16, keySeed + n + 1),
      generation: 1n,
      extensionIndex: 2,
      clientTailEphemeralPublicKey: cryptoSuite.encryptionKeyPair(seed(0x63 + n)).publicKey,
      clientNonce: seed(0x64 + n),
      payloadParametersDigest: seed(0x65),
      candidateAuthorityCommitment32: seed(0x66),
      forwardLimits,
      reverseLimits,
      operationDeadline: f.clock.monotonicNow() + 2000n,
      ...localLedgers
    })
    return {
      handle,
      peerRuntime: adoptedPeerRuntimes ? adoptedPeerRuntimes[adoptedPeerRuntimes.length - 1] : null,
      localLedgers
    }
  }

  return {
    initiator: {
      key: initiatorKey,
      routeKey: initiatorRouteKey,
      endpoint: initiatorEndpoint,
      relayOwner: initiatorRelayOwner,
      pool: initiatorPool,
      directory: initiatorDirectory,
      neighbor: initiatorNeighbor
    },
    peerNeighbor,
    authority: initiatorAuthority,
    limits: branchLimits,
    discover,
    openBranch
  }
}

module.exports = {
  seed,
  ledgers,
  authenticatedPeer,
  safetyIdentity,
  fixtureKeys,
  fakeClock,
  createBoundEndpoint,
  buildSignedGrant,
  buildVerifiedAd,
  setupNativePoolPreflight,
  setupTwoEndedNativeAdjacency,
  setupDistinctNativeNeighbor,
  options,
  sequence,
  nativeGuardAdvertisement,
  linkPair,
  linkSessionOptions,
  pinnedMaterialFixture,
  leaseOptions,
  closeFixture,
  peerBranchLedgers,
  peerGuardFixture,
  setupFourNodeNativeFixture,
  distinctSafetyIdentity
}
