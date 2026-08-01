'use strict'

const b4a = require('b4a')

const { BOOTSTRAP_SIZE, BootstrapEnvelopeCodec } = require('../../lib/private/bootstrap-envelope')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { createLinkSetupAuthority } = require('../../lib/private/link-setup')
const {
  BRANCH_CLASS,
  CAPACITY_CLASS,
  LINK_OPERATION,
  PROTOCOL_VERSION,
  RELAY_CAPABILITY,
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
const {
  consumeSealedRelayCandidateDirectory,
  createRelayCandidateDirectorySink,
  sealRelayCandidateDirectorySink
} = require('../../lib/private/relay-candidate-directory')
const { LinkDirectory, signTopologyGrant } = require('../../lib/private/topology-grant')
const endpointModule = require('../../lib/private/udx-cell-endpoint')
const {
  TEST_ONLY_UDX_ADAPTER_ISSUER,
  admitBootstrapUdxGuard,
  bindBootstrapUdxOperation,
  createBootstrapUdxAuthority,
  createLocalIdentitySecretCapability,
  openBootstrapUdxGuard,
  pinBootstrapUdxGuard
} = endpointModule
const { createGuardLease, destroyGuardLease } = require('../../lib/private/guard-lease')

const NOW = 1_000_000n

function seed(value, size = 32) {
  return b4a.alloc(size, value)
}

function sequence(first) {
  let value = first
  return (size) => b4a.alloc(size, value++)
}

function identityFor(role, ordinal) {
  let found = -1
  for (let value = 1; value < 256; value++) {
    const pair = cryptoSuite.keyPair(seed(value))
    if (roleForIdentity(pair.publicKey) !== role) continue
    found++
    if (found === ordinal) return pair
  }
  throw new Error('missing deterministic identity')
}

function endpoint(index, port = 40_000 + index) {
  return encodeCanonicalEndpoint({
    addressFamily: 4,
    addressBytes: b4a.from([198, 18, index, 1]),
    port
  })
}
function canonicalEndpointForHost(host, port) {
  if (host.includes(':')) {
    const marker = host.indexOf('::')
    const left = (marker === -1 ? host : host.slice(0, marker)).split(':').filter(Boolean)
    const right = (marker === -1 ? '' : host.slice(marker + 2)).split(':').filter(Boolean)
    const words =
      marker === -1 ? left : [...left, ...Array(8 - left.length - right.length).fill('0'), ...right]
    const addressBytes = b4a.alloc(16)
    for (let i = 0; i < words.length; i++) {
      const value = Number.parseInt(words[i], 16)
      addressBytes[i * 2] = value >>> 8
      addressBytes[i * 2 + 1] = value
    }
    return encodeCanonicalEndpoint({ addressFamily: 6, addressBytes, port })
  }
  return encodeCanonicalEndpoint({
    addressFamily: 4,
    addressBytes: b4a.from(host.split('.').map((part) => Number(part))),
    port
  })
}

function candidate(role, ordinal, index, overrides = {}) {
  const {
    endpointBytes = endpoint(index),
    identityPair = null,
    validationNow = NOW,
    ...advertisementOverrides
  } = overrides
  const signer = identityPair || identityFor(role, ordinal)
  const route = cryptoSuite.encryptionKeyPair(seed(128 + index))
  const capabilityMask =
    role === ROLE.SAFETY
      ? RELAY_CAPABILITY.CIRCUIT_RELAY_V1
      : RELAY_CAPABILITY.CIRCUIT_RELAY_V1 | RELAY_CAPABILITY.DHT_EXIT_V1
  const value = {
    relayIdentity: signer.publicKey,
    currentDhtNodeId: deriveM3DhtNodeId(endpointBytes),
    reachableEndpoint: endpointBytes,
    routeEncryptionPublicKey: route.publicKey,
    capabilityMask,
    minimumProtocolVersion: 1,
    maximumProtocolVersion: 1,
    cellSize: 1200,
    maxCellPayload: 1146,
    contextEnvelopeSize: 1101,
    routeFrameSize: 1100,
    maxRoutePayload: 1073,
    datagramReplayWindow: 64,
    maxConcurrentCircuits: 32,
    capacityClass: CAPACITY_CLASS.MEDIUM,
    maxCellsPerCircuit: 10_000,
    maxBytesPerCircuit: 10_000_000,
    maxCommandsPerCircuit: 256,
    idleTimeoutMs: 30_000,
    maxQueuedBytes: 262_144,
    epoch: 1n,
    issuedAtMs: NOW,
    expiresAtMs: NOW + 30_000n,
    providerServicePolicyEntries: providerServicePolicyForCapabilities(capabilityMask),
    ...advertisementOverrides
  }
  const signed = signRelayCapabilityAdvertisement(value, signer.secretKey)
  const canonicalBytes = encodeRelayCapabilityAdvertisement(signed)
  return {
    canonicalBytes,
    digest: digestRelayCapabilityAdvertisement(canonicalBytes, { now: validationNow }),
    identity: b4a.from(value.relayIdentity),
    canonicalEndpointBytes: b4a.from(value.reachableEndpoint),
    routePublicKey: b4a.from(value.routeEncryptionPublicKey),
    role,
    capabilityMask,
    epoch: value.epoch,
    issuedAt: value.issuedAtMs,
    expiresAt: value.expiresAtMs
  }
}

function routeClock(start = NOW, monotonicStart = 10_000n) {
  let wall = start
  let monotonic = monotonicStart
  const timers = new Map()
  let next = 1
  return {
    wallNow: () => wall,
    monotonicNow: () => monotonic,
    schedule(callback, delay) {
      const handle = next++
      timers.set(handle, { callback, delay })
      return handle
    },
    cancelScheduled(handle) {
      return timers.delete(handle)
    },
    advance(ms) {
      wall += BigInt(ms)
      monotonic += BigInt(ms)
    },
    pendingTimers() {
      return timers.size
    }
  }
}

function directoryFixture(clock = routeClock(), options = {}) {
  const guard = options.guard || candidate(ROLE.SAFETY, 0, 1)
  const records = options.records || [
    candidate(ROLE.SAFETY, 1, 2),
    candidate(ROLE.SAFETY, 2, 3),
    candidate(ROLE.PRIVATE, 0, 40),
    candidate(ROLE.PRIVATE, 1, 41)
  ]
  const sink = createRelayCandidateDirectorySink({
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow
  })
  return {
    clock,
    guard,
    records,
    directory: consumeSealedRelayCandidateDirectory(
      sealRelayCandidateDirectorySink(sink, records, {
        guardIdentity: guard.identity,
        guardEndpoint: guard.canonicalEndpointBytes,
        guardAdvertisementDigest: guard.digest,
        guardEpoch: guard.epoch,
        guardExpiresAt: guard.expiresAt
      })
    )
  }
}

function linkPair(hostA, portA, hostB, portB) {
  const authority = cryptoSuite.keyPair(seed(90))
  const a = cryptoSuite.keyPair(seed(91))
  const b = identityFor(ROLE.SAFETY, 90)
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

function endpointOptions(host, port, overrides = {}) {
  return {
    host,
    port,
    onBootstrap() {},
    onCell() {},
    onLinkFailure() {},
    ...overrides
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
    signedExpiry: 60_000
  }
}

async function pinnedMaterialFixture(
  leftPort,
  rightPort,
  hosts = { left: '127.0.0.1', right: '127.0.0.2' }
) {
  const network = new Map()
  const issuer = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER]
  const links = linkPair(hosts.left, leftPort, hosts.right, rightPort)
  const leftObserver = {}
  let leftSession = null
  let rightSession = null
  const left = issuer.createUdxCellEndpointForTest(
    {
      ...endpointOptions(hosts.left, leftPort),
      onBootstrap(packet) {
        if (leftSession) void leftSession.receive(packet)
      }
    },
    issuer.createTestUdxAdapterAuthority(fakeFactory(network, leftObserver))
  )
  const right = issuer.createUdxCellEndpointForTest(
    {
      ...endpointOptions(hosts.right, rightPort),
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
    configuredEndpoints: [{ host: hosts.right, port: rightPort }],
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
    host: hosts.right,
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
    left,
    right,
    leftObserver,
    links,
    rightPort,
    rightSession,
    material: pinBootstrapUdxGuard(authority, admission, established)
  }
}

async function liveTopologyFixture(
  leftPort = 47401,
  rightPort = 47402,
  hosts = { left: '127.0.0.1', right: '127.0.0.2' }
) {
  const guard = await pinnedMaterialFixture(leftPort, rightPort, hosts)
  const clock = routeClock()
  const pinnedGuardRecord = {
    identity: b4a.from(guard.links.b.publicKey),
    canonicalEndpointBytes: canonicalEndpointForHost(hosts.right, rightPort),
    digest: seed(0xda),
    epoch: 1n,
    expiresAt: NOW + 30_000n
  }
  const directory = directoryFixture(clock, { guard: pinnedGuardRecord })
  const guardLease = createGuardLease({
    guardLeaseMaterial: guard.material,
    pinnedGuard: {
      identity32: guard.links.b.publicKey,
      endpoint: { host: hosts.right, port: rightPort }
    },
    wallNow: () => Number(clock.wallNow()),
    monotonicNow: () => Number(clock.monotonicNow()),
    setTimer: setTimeout,
    clearTimer: clearTimeout,
    guardLossSink: Object.freeze({})
  })
  return {
    ...directory,
    guardLease,
    guardFixture: guard,
    async close() {
      destroyGuardLease(guardLease)
      await guard.rightSession.close()
      await guard.right.close()
      guard.links.left.directory.destroy()
      guard.links.right.directory.destroy()
    }
  }
}

module.exports = {
  BOOTSTRAP_SIZE,
  BRANCH_CLASS,
  NOW,
  ROLE,
  candidate,
  canonicalEndpointForHost,
  directoryFixture,
  endpoint,
  identityFor,
  liveTopologyFixture,
  routeClock,
  seed
}
