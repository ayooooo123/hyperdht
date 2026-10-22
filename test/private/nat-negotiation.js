'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  DOMAIN_NAT_PUNCH_PLAN,
  decodeNatPunchCounter,
  decodeUnsignedNatPunchPlan,
  encodeNatPunchCounter,
  encodeUnsignedNatPunchPlan,
  unsignedNatPunchCounterMatchesOffer
} = require('../../lib/private/nat-punch-plan')
const { readReflectedEndpointClaim } = require('../../lib/private/nat-reflect')
const {
  LINK_OPERATION,
  PROTOCOL_VERSION,
  ROLE,
  TOPOLOGY_ROLE,
  roleForIdentity
} = require('../../lib/private/protocol')
const { LinkDirectory, signTopologyGrant } = require('../../lib/private/topology-grant')
const endpointModule = require('../../lib/private/udx-cell-endpoint')
const {
  TEST_ONLY_UDX_ADAPTER_ISSUER,
  acceptNatPunch,
  bindReflectedEndpointClaim,
  completeNatPunch,
  counterNatPunch,
  createLocalIdentitySecretCapability,
  createNatTraversalAuthority,
  destroyNatTraversalAuthority,
  offerNatPunch,
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

function expectCode(t, fn, code) {
  try {
    fn()
    t.fail('expected ' + code)
  } catch (err) {
    t.is(err && err.code, code)
  }
}

async function expectCodeAsync(t, fn, code) {
  try {
    await fn()
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

function fixture(hostA, portA, hostB, portB, nowFn = () => 1_000n) {
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
      now: nowFn,
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

function authorityFor(endpoint, identityPair, epoch, runId32, nowFn = () => 1_000n) {
  const secret = createLocalIdentitySecretCapability({
    localIdentity: identityPair.publicKey,
    localSecretKey: identityPair.secretKey
  })
  return createNatTraversalAuthority(endpoint, {
    localSecretCapability: secret,
    epoch,
    runId32,
    now: nowFn,
    schedule: setTimeout,
    cancel: clearTimeout,
    randomBytes: cryptoSuite.randomBytes
  })
}

function bindClaim(auth, host, port, now) {
  const opts = { reflectors: TEST_REFLECTORS }
  if (now !== undefined) opts.now = now
  return bindReflectedEndpointClaim(auth, { host, port }, opts)
}

test('offer→counter→complete→accept→both start and exchange punches', async (t) => {
  const { left, right, network } = await endpointPair(49301, 49302)
  const fx = fixture('127.0.0.1', 49301, '127.0.0.1', 49302)
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

  const { offer, token: offerToken } = offerNatPunch(leftAuth, fx.left.handle, claimA)
  const { counter, token: counterToken } = counterNatPunch(
    rightAuth,
    fx.right.handle,
    claimB,
    offer
  )
  const { plan, attempt: leftAttempt } = completeNatPunch(leftAuth, offerToken, counter)
  const rightAttempt = acceptNatPunch(rightAuth, counterToken, plan)

  const leftFirst = await startNatPunchAttempt(leftAttempt)
  const rightFirst = await startNatPunchAttempt(rightAttempt)
  t.is(leftFirst, true)
  t.is(rightFirst, true)

  await new Promise((resolve) => setTimeout(resolve, 40))

  const leftStats = readNatPunchAttemptStats(leftAttempt)
  const rightStats = readNatPunchAttemptStats(rightAttempt)
  t.ok(leftStats.firstOwnedSend)
  t.ok(rightStats.firstOwnedSend)
  t.ok(leftStats.received >= 1, 'left received peer punch')
  t.ok(rightStats.received >= 1, 'right received peer punch')

  stopNatPunchAttempt(leftAttempt, 'done')
  stopNatPunchAttempt(rightAttempt, 'done')
})

test('counter that changes a non-allowed byte is refused', async (t) => {
  const { left, right } = await endpointPair(49311, 49312)
  const fx = fixture('127.0.0.1', 49311, '127.0.0.1', 49312)
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
  const { offer, token } = offerNatPunch(leftAuth, fx.left.handle, claimA)
  const { counter } = counterNatPunch(rightAuth, fx.right.handle, claimB, offer)

  const decoded = decodeNatPunchCounter(counter)
  const tamperedUnsigned = b4a.from(decoded.unsigned)
  // Flip planId byte: structure stays valid, offer match fails.
  tamperedUnsigned[5] ^= 1
  const badCounter = b4a.concat([tamperedUnsigned, decoded.responderSignature])

  expectCode(t, () => completeNatPunch(leftAuth, token, badCounter), 'UNAUTHORIZED')
})

test('counter that raises expiresAt is refused', async (t) => {
  const { left, right } = await endpointPair(49321, 49322)
  const fx = fixture('127.0.0.1', 49321, '127.0.0.1', 49322)
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
  const { offer, token } = offerNatPunch(leftAuth, fx.left.handle, claimA)
  const offerBody = decodeUnsignedNatPunchPlan(offer)
  const viewB = readReflectedEndpointClaim(claimB, { now: 1_000n })

  const raised = {
    version: offerBody.version,
    format: offerBody.format,
    planId32: offerBody.planId32,
    topologyGrantDigest32: offerBody.topologyGrantDigest32,
    epoch: offerBody.epoch,
    runId32: offerBody.runId32,
    notBefore: offerBody.notBefore,
    expiresAt: offerBody.expiresAt + 1n,
    initiator: {
      identity32: offerBody.initiator.identity32,
      role: offerBody.initiator.role,
      host: offerBody.initiator.host,
      port: offerBody.initiator.port,
      reflectionClaimDigest32: offerBody.initiator.reflectionClaimDigest32,
      nonce32: offerBody.initiator.nonce32
    },
    responder: {
      identity32: offerBody.responder.identity32,
      role: offerBody.responder.role,
      host: offerBody.responder.host,
      port: offerBody.responder.port,
      reflectionClaimDigest32: viewB.digest32,
      nonce32: seed(44)
    },
    punchProfileId: offerBody.punchProfileId
  }
  const raisedUnsigned = encodeUnsignedNatPunchPlan(raised)
  t.is(unsignedNatPunchCounterMatchesOffer(offer, raisedUnsigned), false)
  const digest = cryptoSuite.hash([DOMAIN_NAT_PUNCH_PLAN, raisedUnsigned])
  const sig = cryptoSuite.sign(digest, fx.b.secretKey)
  const badCounter = encodeNatPunchCounter(raisedUnsigned, sig)
  expectCode(t, () => completeNatPunch(leftAuth, token, badCounter), 'UNAUTHORIZED')
})

test('wrong responder signature is refused', async (t) => {
  const { left, right } = await endpointPair(49331, 49332)
  const fx = fixture('127.0.0.1', 49331, '127.0.0.1', 49332)
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
  const { offer, token } = offerNatPunch(leftAuth, fx.left.handle, claimA)
  const { counter } = counterNatPunch(rightAuth, fx.right.handle, claimB, offer)
  const decoded = decodeNatPunchCounter(counter)
  const badSig = b4a.from(decoded.responderSignature)
  badSig[0] ^= 1
  const badCounter = encodeNatPunchCounter(decoded.unsigned, badSig)
  expectCode(t, () => completeNatPunch(leftAuth, token, badCounter), 'UNAUTHORIZED')
})

test('acceptNatPunch refuses plan whose unsigned differs from counter', async (t) => {
  const { left, right } = await endpointPair(49341, 49342)
  const fx = fixture('127.0.0.1', 49341, '127.0.0.1', 49342)
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
  const { offer, token: offerToken } = offerNatPunch(leftAuth, fx.left.handle, claimA)
  const { counter, token: counterToken } = counterNatPunch(
    rightAuth,
    fx.right.handle,
    claimB,
    offer
  )
  const { plan } = completeNatPunch(leftAuth, offerToken, counter)
  const badPlan = b4a.from(plan)
  badPlan[10] ^= 1
  expectCode(t, () => acceptNatPunch(rightAuth, counterToken, badPlan), 'UNAUTHORIZED')
})

test('token reuse is REPLAY', async (t) => {
  const { left, right } = await endpointPair(49351, 49352)
  const fx = fixture('127.0.0.1', 49351, '127.0.0.1', 49352)
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
  const { offer, token: offerToken } = offerNatPunch(leftAuth, fx.left.handle, claimA)
  const { counter, token: counterToken } = counterNatPunch(
    rightAuth,
    fx.right.handle,
    claimB,
    offer
  )
  const { plan, attempt } = completeNatPunch(leftAuth, offerToken, counter)
  stopNatPunchAttempt(attempt, 'done')
  expectCode(t, () => completeNatPunch(leftAuth, offerToken, counter), 'REPLAY')

  // Fresh offer/counter for accept reuse path
  const claimA2 = bindClaim(leftAuth, fx.hostA, fx.portA)
  const claimB2 = bindClaim(rightAuth, fx.hostB, fx.portB)
  const second = offerNatPunch(leftAuth, fx.left.handle, claimA2)
  const secondCounter = counterNatPunch(rightAuth, fx.right.handle, claimB2, second.offer)
  const secondComplete = completeNatPunch(leftAuth, second.token, secondCounter.counter)
  stopNatPunchAttempt(secondComplete.attempt, 'done')
  const acceptAttempt = acceptNatPunch(rightAuth, secondCounter.token, secondComplete.plan)
  stopNatPunchAttempt(acceptAttempt, 'done')
  expectCode(t, () => acceptNatPunch(rightAuth, secondCounter.token, secondComplete.plan), 'REPLAY')
  void counterToken
  void plan
})

test('offer after authority destroy is UNAUTHORIZED', async (t) => {
  const { left, right } = await endpointPair(49361, 49362)
  const fx = fixture('127.0.0.1', 49361, '127.0.0.1', 49362)
  const leftAuth = authorityFor(left, fx.a, fx.epoch, fx.runId32)
  t.teardown(async () => {
    destroyFixture(fx)
    await Promise.all([left.close(), right.close()])
  })
  const claimA = bindClaim(leftAuth, fx.hostA, fx.portA)
  destroyNatTraversalAuthority(leftAuth)
  expectCode(t, () => offerNatPunch(leftAuth, fx.left.handle, claimA), 'UNAUTHORIZED')
})

test('offer after endpoint close (guard-pin path) is UNAUTHORIZED', async (t) => {
  const { left, right } = await endpointPair(49371, 49372)
  const fx = fixture('127.0.0.1', 49371, '127.0.0.1', 49372)
  const leftAuth = authorityFor(left, fx.a, fx.epoch, fx.runId32)
  t.teardown(async () => {
    destroyFixture(fx)
    await right.close()
  })
  const claimA = bindClaim(leftAuth, fx.hostA, fx.portA)
  await left.close()
  expectCode(t, () => offerNatPunch(leftAuth, fx.left.handle, claimA), 'UNAUTHORIZED')
})

test('pending cap is CIRCUIT_LIMIT', async (t) => {
  const { left, right } = await endpointPair(49381, 49382)
  const fx = fixture('127.0.0.1', 49381, '127.0.0.1', 49382)
  const leftAuth = authorityFor(left, fx.a, fx.epoch, fx.runId32)
  t.teardown(async () => {
    destroyNatTraversalAuthority(leftAuth)
    destroyFixture(fx)
    await Promise.all([left.close(), right.close()])
  })
  for (let i = 0; i < 8; i++) {
    const claim = bindClaim(leftAuth, fx.hostA, fx.portA)
    offerNatPunch(leftAuth, fx.left.handle, claim)
  }
  const overflow = bindClaim(leftAuth, fx.hostA, fx.portA)
  expectCode(t, () => offerNatPunch(leftAuth, fx.left.handle, overflow), 'CIRCUIT_LIMIT')
})

test('claim mismatch observed tuple is UNAUTHORIZED', async (t) => {
  const { left, right } = await endpointPair(49391, 49392)
  const fx = fixture('127.0.0.1', 49391, '127.0.0.1', 49392)
  const leftAuth = authorityFor(left, fx.a, fx.epoch, fx.runId32)
  t.teardown(async () => {
    destroyNatTraversalAuthority(leftAuth)
    destroyFixture(fx)
    await Promise.all([left.close(), right.close()])
  })
  const mismatch = bindClaim(leftAuth, '127.0.0.1', 9)
  expectCode(t, () => offerNatPunch(leftAuth, fx.left.handle, mismatch), 'UNAUTHORIZED')
})

test('expired offer token is UNAUTHORIZED and sends nothing', async (t) => {
  let now = 1_000n
  const timers = []
  const schedule = (fn, ms) => {
    const entry = { fn, ms, cleared: false }
    timers.push(entry)
    return entry
  }
  const cancel = (entry) => {
    if (entry) entry.cleared = true
  }

  const network = new Map()
  const left = issuer.createUdxCellEndpointForTest(
    options('127.0.0.1', 49401),
    issuer.createTestUdxAdapterAuthority(fakeFactory(network))
  )
  const right = issuer.createUdxCellEndpointForTest(
    options('127.0.0.1', 49402),
    issuer.createTestUdxAdapterAuthority(fakeFactory(network))
  )
  await left.bind()
  await right.bind()
  const fx = fixture('127.0.0.1', 49401, '127.0.0.1', 49402, () => now)
  const secret = createLocalIdentitySecretCapability({
    localIdentity: fx.a.publicKey,
    localSecretKey: fx.a.secretKey
  })
  const leftAuth = createNatTraversalAuthority(left, {
    localSecretCapability: secret,
    epoch: fx.epoch,
    runId32: fx.runId32,
    now: () => now,
    schedule,
    cancel,
    randomBytes: cryptoSuite.randomBytes
  })
  const rightAuth = authorityFor(right, fx.b, fx.epoch, fx.runId32, () => now)
  t.teardown(async () => {
    destroyNatTraversalAuthority(leftAuth)
    destroyNatTraversalAuthority(rightAuth)
    destroyFixture(fx)
    await Promise.all([left.close(), right.close()])
  })

  const claimA = bindClaim(leftAuth, fx.hostA, fx.portA, now)
  const claimB = bindClaim(rightAuth, fx.hostB, fx.portB, now)
  const { offer, token } = offerNatPunch(leftAuth, fx.left.handle, claimA)
  const { counter } = counterNatPunch(rightAuth, fx.right.handle, claimB, offer)

  const leftSocket = network.get('127.0.0.1:49401')
  const before = leftSocket.sent.length

  now = 20_000n
  for (const entry of timers) {
    if (!entry.cleared) entry.fn()
  }

  expectCode(t, () => completeNatPunch(leftAuth, token, counter), 'UNAUTHORIZED')
  t.is(leftSocket.sent.length, before, 'expired token sends zero UDP')
})
