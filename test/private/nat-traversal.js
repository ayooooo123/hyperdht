'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { signNatPunchPlan } = require('../../lib/private/nat-punch-plan')
const { readReflectedEndpointClaim } = require('../../lib/private/nat-reflect')
const {
  LINK_OPERATION,
  PROTOCOL_VERSION,
  ROLE,
  TOPOLOGY_ROLE,
  roleForIdentity
} = require('../../lib/private/protocol')
const {
  LinkDirectory,
  readLinkHandle,
  signTopologyGrant
} = require('../../lib/private/topology-grant')
const endpointModule = require('../../lib/private/udx-cell-endpoint')
const {
  NAT_PUNCH_ATTEMPT_OPTION,
  TEST_ONLY_UDX_ADAPTER_ISSUER,
  armNatPunch,
  bindReflectedEndpointClaim,
  createLocalIdentitySecretCapability,
  createNatTraversalAuthority,
  destroyNatTraversalAuthority,
  readNatPunchAttemptStats,
  startNatPunchAttempt,
  stopNatPunchAttempt
} = endpointModule

const seed = (value) => b4a.alloc(32, value)
const issuer = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER]

const TEST_REFLECTORS = Object.freeze([
  Object.freeze({
    host: '203.0.113.201',
    port: 1,
    identity32: cryptoSuite.hash([b4a.from('nat-reflector-a')])
  }),
  Object.freeze({
    host: '203.0.113.202',
    port: 2,
    identity32: cryptoSuite.hash([b4a.from('nat-reflector-b')])
  })
])

function bindClaim(auth, host, port) {
  return bindReflectedEndpointClaim(auth, { host, port }, { reflectors: TEST_REFLECTORS })
}

function expectCode(t, fn, code) {
  try {
    fn()
    t.fail('expected ' + code)
  } catch (err) {
    t.is(err && err.code, code)
  }
}

function safetyIdentity(start = 100) {
  for (let value = start; value < 256; value++) {
    const pair = cryptoSuite.keyPair(seed(value))
    if (roleForIdentity(pair.publicKey) === ROLE.SAFETY) return pair
  }
  throw new Error('missing safety identity')
}

class FakeSocket {
  constructor(network) {
    this.network = network
    this.listeners = new Map()
    this.host = null
    this.port = null
    this.closed = false
    this.sent = []
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
    this.sent.push({ packet: b4a.from(packet), host, port })
    const peer = this.network.get(`${host}:${port}`)
    if (!peer) return true
    queueMicrotask(() =>
      peer.emit('message', b4a.from(packet), { host: this.host, port: this.port })
    )
    return true
  }
  close() {
    this.closed = true
    this.network.delete(`${this.host}:${this.port}`)
    return true
  }
}

function fakeFactory(network) {
  return () => ({
    create() {
      return {
        createSocket() {
          return new FakeSocket(network)
        }
      }
    }
  })
}

function options(host, port) {
  return {
    host,
    port,
    advertisedHost: host,
    advertisedPort: port,
    onBootstrap() {},
    onCell() {},
    onLinkFailure() {}
  }
}

function fixture(hostA, portA, hostB, portB) {
  const topologyAuthority = cryptoSuite.keyPair(seed(90))
  const a = cryptoSuite.keyPair(seed(91))
  const b = safetyIdentity(92)
  const runId32 = seed(93)
  const epoch = 7n
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
      epoch,
      notBefore: 0n,
      expiresAt: 60_000n,
      runId32
    },
    topologyAuthority.secretKey
  )
  const make = (local, peer, localRole, peerRole, operation) => {
    const directory = new LinkDirectory({
      localIdentity32: local.publicKey,
      localRole,
      authorityPublicKey: topologyAuthority.publicKey,
      epoch,
      runId32,
      now: () => 1_000n,
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
      epoch,
      runId32
    })
    return { directory, handle, digest32 }
  }
  return {
    a,
    b,
    runId32,
    epoch,
    left: make(a, b, TOPOLOGY_ROLE.SOURCE, TOPOLOGY_ROLE.SAFETY_GUARD, LINK_OPERATION.INITIATE),
    right: make(b, a, TOPOLOGY_ROLE.SAFETY_GUARD, TOPOLOGY_ROLE.SOURCE, LINK_OPERATION.ACCEPT),
    hostA,
    portA,
    hostB,
    portB
  }
}

function destroyFixture(fx) {
  try {
    fx.left.directory.destroy()
  } catch {}
  try {
    fx.right.directory.destroy()
  } catch {}
}

async function endpointPair(portA, portB) {
  const network = new Map()
  const left = issuer.createUdxCellEndpointForTest(
    options('127.0.0.1', portA),
    issuer.createTestUdxAdapterAuthority(fakeFactory(network))
  )
  const right = issuer.createUdxCellEndpointForTest(
    options('127.0.0.1', portB),
    issuer.createTestUdxAdapterAuthority(fakeFactory(network))
  )
  await left.bind()
  await right.bind()
  return { left, right, network }
}

function authorityFor(endpoint, identityPair, epoch, runId32) {
  const secret = createLocalIdentitySecretCapability({
    localIdentity: identityPair.publicKey,
    localSecretKey: identityPair.secretKey
  })
  return createNatTraversalAuthority(endpoint, {
    localSecretCapability: secret,
    epoch,
    runId32,
    now: () => 1_000n,
    schedule: setTimeout,
    cancel: clearTimeout,
    randomBytes: cryptoSuite.randomBytes
  })
}

function signedPlan(fx, claimA, claimB, overrides = {}) {
  const viewA = readReflectedEndpointClaim(claimA, { now: 1_000n })
  const viewB = readReflectedEndpointClaim(claimB, { now: 1_000n })
  return signNatPunchPlan(
    {
      version: PROTOCOL_VERSION,
      format: 0,
      planId32: overrides.planId32 || seed(9),
      topologyGrantDigest32: overrides.digest32 || fx.left.digest32,
      epoch: overrides.epoch === undefined ? fx.epoch : overrides.epoch,
      runId32: overrides.runId32 || fx.runId32,
      notBefore: 0n,
      expiresAt: overrides.expiresAt === undefined ? 5_500n : overrides.expiresAt,
      initiator: {
        identity32: fx.a.publicKey,
        role: TOPOLOGY_ROLE.SOURCE,
        host: overrides.localHost || fx.hostA,
        port: overrides.localPort || fx.portA,
        reflectionClaimDigest32: viewA.digest32,
        nonce32: seed(13)
      },
      responder: {
        identity32: fx.b.publicKey,
        role: TOPOLOGY_ROLE.SAFETY_GUARD,
        host: overrides.peerHost || fx.hostB,
        port: overrides.peerPort || fx.portB,
        reflectionClaimDigest32: viewB.digest32,
        nonce32: seed(14)
      },
      punchProfileId: 0
    },
    {
      initiatorSecretKey: fx.a.secretKey,
      responderSecretKey: fx.b.secretKey
    }
  )
}

test('armNatPunch zero-send refusals cover trust binding (scenarios 1-10)', async (t) => {
  const { left, right, network } = await endpointPair(48301, 48302)
  const fx = fixture('127.0.0.1', 48301, '127.0.0.1', 48302)
  const leftAuth = authorityFor(left, fx.a, fx.epoch, fx.runId32)
  const rightAuth = authorityFor(right, fx.b, fx.epoch, fx.runId32)
  t.teardown(async () => {
    destroyNatTraversalAuthority(leftAuth)
    destroyNatTraversalAuthority(rightAuth)
    destroyFixture(fx)
    await Promise.all([left.close(), right.close()])
  })

  const claimA = bindClaim(leftAuth, fx.hostA, fx.portA)
  const claimB = bindClaim(rightAuth, fx.hostB, fx.portB)
  const good = signedPlan(fx, claimA, claimB)
  const leftSocket = network.get('127.0.0.1:48301')
  const before = leftSocket.sent.length

  expectCode(
    t,
    () =>
      armNatPunch(
        leftAuth,
        fx.left.handle,
        signedPlan(fx, claimA, claimB, { digest32: seed(55) }),
        {
          mode: 'initiate',
          reflectionClaim: claimA
        }
      ),
    'UNAUTHORIZED'
  )
  expectCode(
    t,
    () =>
      armNatPunch(leftAuth, fx.left.handle, signedPlan(fx, claimA, claimB, { epoch: 99n }), {
        mode: 'initiate',
        reflectionClaim: claimA
      }),
    'UNAUTHORIZED'
  )
  expectCode(
    t,
    () =>
      armNatPunch(leftAuth, fx.left.handle, signedPlan(fx, claimA, claimB, { runId32: seed(8) }), {
        mode: 'initiate',
        reflectionClaim: claimA
      }),
    'UNAUTHORIZED'
  )
  expectCode(
    t,
    () =>
      armNatPunch(
        leftAuth,
        fx.left.handle,
        signedPlan(fx, claimA, claimB, { peerHost: '127.0.0.1', peerPort: 9 }),
        { mode: 'initiate', reflectionClaim: claimA }
      ),
    'UNAUTHORIZED'
  )
  expectCode(
    t,
    () =>
      armNatPunch(leftAuth, fx.left.handle, signedPlan(fx, claimA, claimB, { expiresAt: 500n }), {
        mode: 'initiate',
        reflectionClaim: claimA
      }),
    'UNAUTHORIZED'
  )
  const flipped = b4a.from(good)
  flipped[flipped.byteLength - 1] ^= 1
  expectCode(
    t,
    () =>
      armNatPunch(leftAuth, fx.left.handle, flipped, {
        mode: 'initiate',
        reflectionClaim: claimA
      }),
    'UNAUTHORIZED'
  )
  expectCode(
    t,
    () =>
      armNatPunch(leftAuth, fx.left.handle, good, {
        mode: 'accept',
        reflectionClaim: claimA
      }),
    'UNAUTHORIZED'
  )
  t.is(leftSocket.sent.length, before, 'refusals send zero UDP')

  const attempt = armNatPunch(leftAuth, fx.left.handle, good, {
    mode: 'initiate',
    reflectionClaim: claimA
  })
  t.ok(attempt)
  expectCode(
    t,
    () =>
      armNatPunch(leftAuth, fx.left.handle, good, {
        mode: 'initiate',
        reflectionClaim: claimA
      }),
    'CIRCUIT_STATE'
  )
  stopNatPunchAttempt(attempt, 'test-done')
})

test('armed punch sends and counts peer/stray (scenarios 20-22, 24, 30)', async (t) => {
  const { left, right, network } = await endpointPair(48401, 48402)
  const fx = fixture('127.0.0.1', 48401, '127.0.0.1', 48402)
  const leftAuth = authorityFor(left, fx.a, fx.epoch, fx.runId32)
  const rightAuth = authorityFor(right, fx.b, fx.epoch, fx.runId32)
  t.teardown(async () => {
    destroyNatTraversalAuthority(leftAuth)
    destroyNatTraversalAuthority(rightAuth)
    destroyFixture(fx)
    await Promise.all([left.close(), right.close()])
  })
  const claimA = bindClaim(leftAuth, fx.hostA, fx.portA)
  const claimB = bindClaim(rightAuth, fx.hostB, fx.portB)
  const encoding = signedPlan(fx, claimA, claimB, { planId32: seed(21) })
  const attempt = armNatPunch(leftAuth, fx.left.handle, encoding, {
    mode: 'initiate',
    reflectionClaim: claimA
  })
  await startNatPunchAttempt(attempt)
  await new Promise((resolve) => setTimeout(resolve, 30))

  const leftSocket = network.get('127.0.0.1:48401')
  t.ok(leftSocket.sent.length >= 1, 'at least one punch send')
  const punch = leftSocket.sent[0]
  t.is(punch.port, 48402)
  t.ok(b4a.equals(punch.packet.subarray(0, 11), b4a.from('pr-punch/1\n')))

  leftSocket.emit('message', punch.packet, { host: '127.0.0.1', port: 9 })
  const stats = readNatPunchAttemptStats(attempt)
  t.ok(stats.sent >= 1)
  t.ok(stats.strayReceived >= 1)
  stopNatPunchAttempt(attempt, 'done')
  await left.close()
  t.ok(leftSocket.closed)
})

test('grant revoke stops attempt (scenario 26)', async (t) => {
  const { left, right } = await endpointPair(48501, 48502)
  const fx = fixture('127.0.0.1', 48501, '127.0.0.1', 48502)
  const leftAuth = authorityFor(left, fx.a, fx.epoch, fx.runId32)
  const rightAuth = authorityFor(right, fx.b, fx.epoch, fx.runId32)
  t.teardown(async () => {
    destroyNatTraversalAuthority(leftAuth)
    destroyNatTraversalAuthority(rightAuth)
    destroyFixture(fx)
    await Promise.all([left.close(), right.close()])
  })
  const claimA = bindClaim(leftAuth, fx.hostA, fx.portA)
  const claimB = bindClaim(rightAuth, fx.hostB, fx.portB)
  const encoding = signedPlan(fx, claimA, claimB, { planId32: seed(26) })
  const attempt = armNatPunch(leftAuth, fx.left.handle, encoding, {
    mode: 'initiate',
    reflectionClaim: claimA
  })
  await startNatPunchAttempt(attempt)
  fx.left.directory.revoke({
    digest32: fx.left.digest32,
    epoch: fx.epoch,
    runId32: fx.runId32
  })
  await new Promise((resolve) => setTimeout(resolve, 10))
  const stats = readNatPunchAttemptStats(attempt)
  t.is(stats.live, false)
  t.is(stats.stopReason, 'grant-revoked')
})

test('public surface stays closed (scenarios 32-34)', (t) => {
  const root = require('../../index.js')
  t.is(root.createNatTraversalAuthority, undefined)
  t.is(root.armNatPunch, undefined)
  t.is(root.reflectNatEndpoint, undefined)
  t.is(typeof NAT_PUNCH_ATTEMPT_OPTION, 'symbol')
})

test('readLinkHandle exposes expiry and binding fields', (t) => {
  const fx = fixture('127.0.0.1', 48701, '127.0.0.1', 48702)
  t.teardown(() => destroyFixture(fx))
  const view = readLinkHandle(fx.left.handle)
  t.ok(typeof view.expiresAt === 'bigint')
  t.ok(view.digest32.byteLength === 32)
  t.is(view.epoch, fx.epoch)
  t.ok(view.runId32.equals(fx.runId32))
  t.is(view.localRole, TOPOLOGY_ROLE.SOURCE)
  t.is(view.peerRole, TOPOLOGY_ROLE.SAFETY_GUARD)
})

test('destroy and stop without arm are safe (scenario 31 partial)', async (t) => {
  const { left } = await endpointPair(48601, 48602)
  const fx = fixture('127.0.0.1', 48601, '127.0.0.1', 48602)
  t.teardown(async () => {
    destroyFixture(fx)
    await left.close()
  })
  const auth = authorityFor(left, fx.a, fx.epoch, fx.runId32)
  t.ok(destroyNatTraversalAuthority(auth))
  t.is(destroyNatTraversalAuthority(auth), false)
  t.is(stopNatPunchAttempt({}), false)
  expectCode(t, () => startNatPunchAttempt({}), 'UNAUTHORIZED')
  expectCode(t, () => readNatPunchAttemptStats({}), 'UNAUTHORIZED')
})
