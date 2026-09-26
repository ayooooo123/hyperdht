'use strict'

const test = require('brittle')
const b4a = require('b4a')
const crypto = require('hypercore-crypto')
const sodium = require('sodium-universal')

const { PrivateRouteError } = require('../../lib/private/errors')
const {
  createPeerRelayOwner,
  readPeerRelayOwner,
  verifyPeerAdvertisement,
  createPeerCandidateLocator,
  encodeReachableEndpoint
} = require('../../lib/private/peer-capability')
const {
  createPeerBootstrapResponder,
  takePeerBootstrapResponderBinding,
  destroyPeerBootstrapResponder,
  discoverPeerCandidate,
  readPeerActiveCandidateFacts,
  takePeerActiveCandidate,
  destroyPeerActiveCandidate,
  wrapDirectRpcPacket,
  unwrapDirectRpcPacket
} = require('../../lib/private/peer-direct-bootstrap')
const { createPeerLedger, readPeerLedger } = require('../../lib/private/peer-ledger')
const {
  PEER_MESSAGE_ID,
  encodePeerObject,
  decodePeerObject
} = require('../../lib/private/peer-protocol')
const endpointModule = require('../../lib/private/udx-cell-endpoint')
const {
  TEST_ONLY_UDX_ADAPTER_ISSUER,
  createPeerCandidateDirectTransport,
  takePeerDirectRequesterTransport,
  registerPeerDirectResponder,
  destroyPeerDirectResponderRegistration,
  destroyPeerDirectRequesterTransport
} = endpointModule
const {
  createGuardLease,
  createPeerGuardBootstrapTransport,
  destroyGuardLease
} = require('../../lib/private/guard-lease')

const issuer = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER]

function generateEd25519KeyPair() {
  const pk = b4a.alloc(32)
  const sk = b4a.alloc(64)
  sodium.crypto_sign_keypair(pk, sk)
  return { publicKey: pk, secretKey: sk }
}

function generateX25519KeyPair() {
  const pk = b4a.alloc(32)
  const sk = b4a.alloc(32)
  sodium.crypto_box_keypair(pk, sk)
  return { publicKey: pk, secretKey: sk }
}

function createMockClock(startWall = 1000000n, startMono = 500000n, hooks = {}) {
  let wall = startWall
  let mono = startMono
  const timers = new Map()
  let nextId = 1
  return {
    clockIdentity: Object.freeze({ id: 'bootstrap-clock' }),
    wallNow: () => wall,
    monotonicNow: () => mono,
    pendingTimers: () => timers.size,
    setTimer: (fn, ms) => {
      const id = nextId++
      timers.set(id, { fn, due: mono + BigInt(ms) })
      if (hooks.onSchedule) hooks.onSchedule(ms)
      return id
    },
    clearTimer: (id) => {
      timers.delete(id)
    },
    advance(ms) {
      wall += BigInt(ms)
      mono += BigInt(ms)
      for (const [id, timer] of Array.from(timers.entries())) {
        if (timer.due <= mono) {
          timers.delete(id)
          timer.fn()
        }
      }
    },
    // Advance wall/mono without firing timers (late-ingress regressions).
    advanceSilent(ms) {
      wall += BigInt(ms)
      mono += BigInt(ms)
    }
  }
}

function buildTestAdvertisementFields(edKeys, xKeys, endpoint, expiresAt = 2000000n, mask = 11) {
  return {
    relayIdentity32: edKeys.publicKey,
    currentDhtNodeId32: crypto.hash(edKeys.publicKey),
    reachableEndpoint: endpoint,
    routeEncryptionPublicKey32: xKeys.publicKey,
    capabilityMask: mask,
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
  }
}

class FakeSocket {
  constructor(network, mutateOutbound) {
    this.network = network
    this.mutateOutbound = typeof mutateOutbound === 'function' ? mutateOutbound : null
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
    let out = b4a.from(packet)
    if (this.mutateOutbound) {
      const mutated = this.mutateOutbound(out, host, port, this)
      if (mutated === false) {
        this.sent.push({ packet: out, host, port, dropped: true })
        return true
      }
      if (mutated) out = mutated
    }
    this.sent.push({ packet: b4a.from(out), host, port })
    const peer = this.network.get(`${host}:${port}`)
    if (!peer) return true
    const deliver = () => peer.emit('message', b4a.from(out), { host: this.host, port: this.port })
    if (this.network.deliver) this.network.deliver(deliver)
    else queueMicrotask(deliver)
    return true
  }
  close() {
    this.closed = true
    this.network.delete(`${this.host}:${this.port}`)
    return true
  }
}

function fakeFactory(network, mutateOutbound) {
  return () => ({
    create() {
      return {
        createSocket() {
          return new FakeSocket(network, mutateOutbound)
        }
      }
    }
  })
}

function endpointOptions(host, port) {
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
async function endpointPair(portA, portB, mutateRightOutbound) {
  const network = new Map()
  const left = issuer.createUdxCellEndpointForTest(
    endpointOptions('127.0.0.1', portA),
    issuer.createTestUdxAdapterAuthority(fakeFactory(network, null))
  )
  const right = issuer.createUdxCellEndpointForTest(
    endpointOptions('127.0.0.1', portB),
    issuer.createTestUdxAdapterAuthority(fakeFactory(network, mutateRightOutbound || null))
  )
  await left.bind()
  await right.bind()
  return { left, right, network }
}

function buildCapsQuery(mask, target, nonce, phase, cookieExp, cookie) {
  const body = b4a.alloc(110, 0)
  body.writeUInt32BE(mask, 0)
  body.set(target, 4)
  body.set(nonce, 36)
  body[68] = 1
  body[69] = phase
  if (cookieExp) body.writeBigUInt64BE(cookieExp, 70)
  if (cookie) body.set(cookie, 78)
  return wrapDirectRpcPacket(
    encodePeerObject({ messageId: PEER_MESSAGE_ID.PEER_CAPS_QUERY_V2, body })
  )
}

function makeRelay(mask, host, port, clock) {
  const edKeys = generateEd25519KeyPair()
  const xKeys = generateX25519KeyPair()
  const endpointToken = { host, port }
  const owner = createPeerRelayOwner({
    endpoint: endpointToken,
    identityKeyPair: edKeys,
    routeKeyPair: xKeys,
    advertisementFields: buildTestAdvertisementFields(
      edKeys,
      xKeys,
      { host, port },
      2000000n,
      mask
    ),
    clockIdentity: clock.clockIdentity,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer
  })
  return { edKeys, xKeys, owner, endpointToken }
}

function reSignAdvertisement(body188, secretKey) {
  const label = b4a.from('hyperdht-private-routes/m3/capability-advertisement/v2')
  const labelLen = b4a.allocUnsafe(2)
  labelLen.writeUInt16BE(label.byteLength, 0)
  const sigInput = b4a.concat([
    labelLen,
    label,
    b4a.from([0, 0, 0, 2]),
    b4a.from([0x03, 0x00]),
    b4a.from([0x00, 0xbc]),
    body188
  ])
  const sig = b4a.alloc(64)
  sodium.crypto_sign_detached(sig, sigInput, secretKey)
  return encodePeerObject({
    messageId: PEER_MESSAGE_ID.PEER_CAPABILITY_ADVERTISEMENT_V2,
    body: body188,
    authSuffix: sig
  })
}

function wrapInner(messageId, body, authSuffix) {
  const opts = { messageId, body }
  if (authSuffix) opts.authSuffix = authSuffix
  return wrapDirectRpcPacket(encodePeerObject(opts))
}

function isDirectMessage(packet, messageId) {
  try {
    const obj = unwrapDirectRpcPacket(packet)
    return obj.messageId === messageId ? obj : null
  } catch {
    return null
  }
}

async function driveClock(clock, steps = 40, ms = 50) {
  for (let i = 0; i < steps; i++) {
    await new Promise((resolve) => queueMicrotask(resolve))
    clock.advance(ms)
  }
}

async function setupDiscoverPair(
  t,
  ports,
  mutateRightOutbound,
  clock = createMockClock(),
  deadlineBounds
) {
  const { left, right, network } = await endpointPair(ports.left, ports.right, mutateRightOutbound)
  t.teardown(async () => {
    try {
      await left.close()
    } catch {}
    try {
      await right.close()
    } catch {}
  })
  const remoteAddr = { host: '127.0.0.1', port: ports.right }
  const localToken = { host: '127.0.0.1', port: ports.left }
  const edKeys = generateEd25519KeyPair()
  const xKeys = generateX25519KeyPair()
  const remoteOwner = createPeerRelayOwner({
    endpoint: right,
    identityKeyPair: edKeys,
    routeKeyPair: xKeys,
    advertisementFields: buildTestAdvertisementFields(edKeys, xKeys, remoteAddr, 2000000n, 11),
    clockIdentity: clock.clockIdentity,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer
  })
  const remoteFacts = readPeerRelayOwner(remoteOwner, right)
  const responder = createPeerBootstrapResponder(remoteOwner)
  const registration = registerPeerDirectResponder(right, responder)
  t.teardown(() => {
    try {
      destroyPeerDirectResponderRegistration(registration)
    } catch {}
    try {
      destroyPeerBootstrapResponder(responder)
    } catch {}
  })
  const localEd = generateEd25519KeyPair()
  const localX = generateX25519KeyPair()
  const localOwner = createPeerRelayOwner({
    endpoint: left,
    identityKeyPair: localEd,
    routeKeyPair: localX,
    advertisementFields: buildTestAdvertisementFields(localEd, localX, localToken, 2000000n, 11),
    clockIdentity: clock.clockIdentity,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer
  })
  const verifiedRemote = verifyPeerAdvertisement(remoteFacts.canonicalAdvertisement260, {
    expectedIdentity32: edKeys.publicKey,
    expectedCapabilityMask: 11,
    clockIdentity: clock.clockIdentity,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow
  })
  const locator = createPeerCandidateLocator(localOwner, verifiedRemote, deadlineBounds)
  const transport = createPeerCandidateDirectTransport(left, locator)
  const ledger = createPeerLedger({ cells: 64, bytes: 64n * 1200n, commands: 0 })
  return {
    clock,
    left,
    right,
    network,
    ports,
    edKeys,
    remoteAddr,
    remoteFacts,
    transport,
    ledger
  }
}

test('direct RPC packet wrapping validates 1200-byte padding magic and full inner decode', (t) => {
  const body = b4a.alloc(110, 0x11)
  body.writeUInt32BE(11, 0)
  body[68] = 1
  body.fill(0, 69)
  const packet = wrapInner(PEER_MESSAGE_ID.PEER_CAPS_QUERY_V2, body)
  t.is(packet.byteLength, 1200)
  t.is(packet.readUInt16BE(0), 0xd301)
  const unwrapped = unwrapDirectRpcPacket(packet)
  t.is(unwrapped.messageId, PEER_MESSAGE_ID.PEER_CAPS_QUERY_V2)
  const badPadding = b4a.from(packet)
  badPadding[1199] = 0x01
  let badPadErr = null
  try {
    unwrapDirectRpcPacket(badPadding)
  } catch (e) {
    badPadErr = e
  }
  t.ok(badPadErr && badPadErr.code === 'INVALID_ROUTE')
})

test('same observedEndpoint+queryNonce with changed phase1 fields conflicts without fresh row', (t) => {
  const clock = createMockClock()
  const { owner, endpointToken } = makeRelay(11, '127.0.0.1', 40001, clock)
  const responder = createPeerBootstrapResponder(owner)
  const binding = takePeerBootstrapResponderBinding(responder, endpointToken)
  const clientEp19 = encodeReachableEndpoint({ host: '10.0.0.5', port: 50005 })
  let lastReply = null
  const sendReply = (pkt) => {
    lastReply = b4a.from(pkt)
  }
  const qNonce = b4a.alloc(32, 0x11)
  const targetA = b4a.alloc(32, 0x22)
  const targetB = b4a.alloc(32, 0x33)

  t.is(
    binding.receive(buildCapsQuery(11, targetA, qNonce, 0, 0n, null), clientEp19, sendReply),
    true
  )
  const ch1 = unwrapDirectRpcPacket(lastReply)
  const cookieExp1 = ch1.body.readBigUInt64BE(32)
  const cookie1 = b4a.from(ch1.body.subarray(40, 72))
  t.is(
    binding.receive(
      buildCapsQuery(11, targetA, qNonce, 1, cookieExp1, cookie1),
      clientEp19,
      sendReply
    ),
    true
  )
  const firstCaps = b4a.from(lastReply)

  t.is(
    binding.receive(
      buildCapsQuery(11, targetA, qNonce, 1, cookieExp1, cookie1),
      clientEp19,
      sendReply
    ),
    true
  )
  t.alike(lastReply, firstCaps)

  t.is(
    binding.receive(buildCapsQuery(11, targetB, qNonce, 0, 0n, null), clientEp19, sendReply),
    true
  )
  const ch2 = unwrapDirectRpcPacket(lastReply)
  const cookieExp2 = ch2.body.readBigUInt64BE(32)
  const cookie2 = b4a.from(ch2.body.subarray(40, 72))
  t.ok(!b4a.equals(cookie1, cookie2))
  t.is(
    binding.receive(
      buildCapsQuery(11, targetB, qNonce, 1, cookieExp2, cookie2),
      clientEp19,
      sendReply
    ),
    false
  )

  t.is(
    binding.receive(
      buildCapsQuery(11, targetA, qNonce, 0, 0n, null),
      { host: '10.0.0.5', port: 50005 },
      sendReply
    ),
    false
  )
  destroyPeerBootstrapResponder(responder)
})

test('ACTIVE SPENT retries after failed first send without candidatePublished', (t) => {
  const clock = createMockClock()
  const { edKeys, owner, endpointToken } = makeRelay(11, '127.0.0.1', 40001, clock)
  const responder = createPeerBootstrapResponder(owner)
  const binding = takePeerBootstrapResponderBinding(responder, endpointToken)
  const clientEp19 = encodeReachableEndpoint({ host: '10.0.0.5', port: 50005 })
  let lastReply = null
  const sendReply = (pkt) => {
    lastReply = b4a.from(pkt)
  }
  const qNonce = b4a.alloc(32, 0x11)
  const rTarget = b4a.alloc(32, 0x22)
  t.is(
    binding.receive(buildCapsQuery(11, rTarget, qNonce, 0, 0n, null), clientEp19, sendReply),
    true
  )
  const ch = unwrapDirectRpcPacket(lastReply)
  const cookieExp = ch.body.readBigUInt64BE(32)
  const cookie = b4a.from(ch.body.subarray(40, 72))
  t.is(
    binding.receive(
      buildCapsQuery(11, rTarget, qNonce, 1, cookieExp, cookie),
      clientEp19,
      sendReply
    ),
    true
  )
  const caps = unwrapDirectRpcPacket(lastReply)
  const adWire = caps.body.subarray(75, 335)
  const verified = verifyPeerAdvertisement(adWire)
  const { readVerifiedPeerAdvertisement } = require('../../lib/private/peer-capability')
  const readAd = readVerifiedPeerAdvertisement(verified)
  const clientEphem = generateX25519KeyPair()
  const challengeExp = cookieExp < readAd.expiresAt ? cookieExp : readAd.expiresAt
  const activeBody = b4a.alloc(176, 0)
  activeBody.set(readAd.advertisementDigest32, 0)
  activeBody.set(edKeys.publicKey, 32)
  activeBody.set(clientEphem.publicKey, 64)
  activeBody.writeBigUInt64BE(challengeExp, 96)
  activeBody.set(qNonce, 104)
  activeBody.writeBigUInt64BE(cookieExp, 136)
  activeBody.set(cookie, 144)
  const activePacket = wrapInner(PEER_MESSAGE_ID.PEER_ACTIVE_CHALLENGE_V2, activeBody)

  t.is(
    binding.receive(activePacket, clientEp19, () => {
      throw new Error('network write error')
    }),
    true
  )
  t.is(binding.receive(activePacket, clientEp19, sendReply), true)
  t.is(
    unwrapDirectRpcPacket(lastReply).messageId,
    PEER_MESSAGE_ID.PEER_ACTIVE_CHALLENGE_RESPONSE_V2
  )
  for (let i = 2; i < 8; i++) t.is(binding.receive(activePacket, clientEp19, sendReply), true)
  t.is(binding.receive(activePacket, clientEp19, sendReply), false)
  destroyPeerBootstrapResponder(responder)
})

test('guard-only local ad cannot satisfy terminal requestedMask 11', (t) => {
  const clock = createMockClock()
  const { owner, endpointToken } = makeRelay(9, '127.0.0.1', 40001, clock)
  const responder = createPeerBootstrapResponder(owner)
  const binding = takePeerBootstrapResponderBinding(responder, endpointToken)
  const clientEp19 = encodeReachableEndpoint({ host: '10.0.0.9', port: 50009 })
  let called = false
  t.is(
    binding.receive(
      buildCapsQuery(11, b4a.alloc(32, 1), b4a.alloc(32, 2), 0, 0n, null),
      clientEp19,
      () => {
        called = true
      }
    ),
    false
  )
  t.is(called, false)
  destroyPeerBootstrapResponder(responder)
})

test('discoverPeerCandidate positive path over branded native endpoints', async (t) => {
  const setup = await setupDiscoverPair(t, { left: 41201, right: 41202 }, null)
  const candidatePromise = discoverPeerCandidate(setup.transport, {
    ledger: setup.ledger,
    requestedMask: 11,
    randomTarget: b4a.alloc(32, 0xab),
    maximumResults: 1
  })
  await driveClock(setup.clock)
  const candidate = await candidatePromise
  t.is(candidate.kind, 'peerActiveCandidate')
  const facts = readPeerActiveCandidateFacts(candidate)
  const activeDigest = b4a.from(facts.activeResponseDigest)
  facts.completeAdvertisement.fill(0)
  facts.activeResponseDigest.fill(0)
  const reread = readPeerActiveCandidateFacts(candidate)
  t.alike(reread.completeAdvertisement, setup.remoteFacts.canonicalAdvertisement260)
  t.alike(reread.activeResponseDigest, activeDigest, 'fact reads cannot alter retained proof bytes')
  let wrongKindRejected = false
  try {
    takePeerActiveCandidate(candidate, { expectedKind: 'guard' })
  } catch (err) {
    wrongKindRejected = err.code === 'INVALID_ROUTE'
  }
  t.ok(wrongKindRejected, 'candidate discovery cannot satisfy guard provenance')
  const taken = takePeerActiveCandidate(candidate, {
    expectedKind: 'candidate',
    expectedIdentity32: setup.edKeys.publicKey,
    expectedEndpoint19: encodeReachableEndpoint(setup.remoteAddr),
    clockIdentity: setup.clock.clockIdentity,
    expectedEpoch: 1n
  })
  t.alike(taken.completeAdvertisement, setup.remoteFacts.canonicalAdvertisement260)
  t.is(taken.activeResponse312.byteLength, 312)
  t.is(taken.activeResponseDigest.byteLength, 32)
  t.alike(taken.activeResponseDigest, activeDigest, 'fact reads leave one-shot consumption intact')
  let spentRead = null
  try {
    readPeerActiveCandidateFacts(candidate)
  } catch (err) {
    spentRead = err
  }
  t.is(spentRead && spentRead.code, 'INVALID_ROUTE', 'consumed candidates cannot publish new facts')
  t.alike(taken.identity32, setup.edKeys.publicKey)
  const snap = readPeerLedger(setup.ledger)
  t.ok(snap.cellsSpent >= 3)
  t.is(destroyPeerActiveCandidate(candidate), true)
})

test('active discovery signs and publishes the original transport wire deadline', async (t) => {
  const clock = createMockClock()
  const wireBound = clock.wallNow() + 2000n
  const projectedBound = clock.monotonicNow() + 2000n
  const setup = await setupDiscoverPair(t, { left: 41901, right: 41902 }, null, clock, {
    clockIdentity: clock.clockIdentity,
    wireExpiresAt: wireBound,
    localDeadline: clock.monotonicNow() + 4000n
  })
  const pending = discoverPeerCandidate(setup.transport, {
    ledger: setup.ledger,
    requestedMask: 11,
    randomTarget: b4a.alloc(32, 0xad),
    maximumResults: 1
  })
  await driveClock(clock, 40, 10)
  const candidate = await pending
  const facts = readPeerActiveCandidateFacts(candidate)
  t.is(
    facts.wireExpiresAt,
    wireBound,
    'candidate publication retains the shorter transport wire bound'
  )
  t.is(facts.localDeadline, projectedBound, 'local publication retains the same bounded projection')
  const taken = takePeerActiveCandidate(candidate, {
    expectedKind: 'candidate',
    expectedIdentity32: setup.edKeys.publicKey,
    expectedEndpoint19: encodeReachableEndpoint(setup.remoteAddr),
    clockIdentity: clock.clockIdentity,
    expectedEpoch: 1n
  })
  const response = decodePeerObject(taken.activeResponse312)
  t.is(
    response.body.readBigUInt64BE(128),
    wireBound,
    'the authenticated ACTIVE proof carries the bound'
  )
  destroyPeerActiveCandidate(candidate)
})

test('timer registration cannot orphan retry ownership after phase or attempt changes', async (t) => {
  for (const transition of ['phase', 'attempt']) {
    const hooks = {}
    const clock = createMockClock(undefined, undefined, hooks)
    const setup = await setupDiscoverPair(t, { left: 41621, right: 41622 }, null, clock)
    const deliveries = []
    setup.network.deliver = (deliver) => deliveries.push(deliver)
    hooks.onSchedule = (ms) => {
      if (ms !== 250) return
      hooks.onSchedule = null
      if (transition === 'phase') {
        // Deliver PHASE0 and its cookie before the first timer handle is issued.
        deliveries.shift()()
        deliveries.shift()()
      } else {
        // Fire the first retry while its handle is still being registered.
        clock.advance(250)
      }
    }
    const pending = discoverPeerCandidate(setup.transport, {
      ledger: setup.ledger,
      requestedMask: 11,
      randomTarget: b4a.alloc(32, 0xae),
      maximumResults: 1
    })
    if (transition === 'attempt') {
      deliveries.shift()()
      // Deliver that cookie before the queued retry, advancing to COOKIE_FROZEN.
      deliveries.pop()()
    }
    while (deliveries.length) deliveries.shift()()
    const candidate = await pending
    t.is(clock.pendingTimers(), 0, transition + ': completion retires every timer')
    t.is(readPeerLedger(setup.ledger).cellsSpent, transition === 'phase' ? 3 : 4)
    destroyPeerActiveCandidate(candidate)
  }
})

test('candidate consumption cannot publish after synchronous revocation', async (t) => {
  const setup = await setupDiscoverPair(t, { left: 41203, right: 41204 }, null)
  const pending = discoverPeerCandidate(setup.transport, {
    ledger: setup.ledger,
    requestedMask: 11,
    randomTarget: b4a.alloc(32, 0xac),
    maximumResults: 1
  })
  await driveClock(setup.clock)
  const candidate = await pending
  let error = null
  try {
    takePeerActiveCandidate(
      candidate,
      new Proxy(
        {
          expectedKind: 'candidate',
          expectedIdentity32: setup.edKeys.publicKey
        },
        {
          getOwnPropertyDescriptor(target, key) {
            if (key === 'expectedIdentity32') destroyPeerActiveCandidate(candidate)
            return Reflect.getOwnPropertyDescriptor(target, key)
          }
        }
      )
    )
  } catch (err) {
    error = err
  }
  t.ok(error instanceof PrivateRouteError, 'revoked authority is never published')
  t.is(error && error.code, 'INVALID_ROUTE')
})

test('candidate expectation schema rejects accessors and unknown fields without consumption', async (t) => {
  const setup = await setupDiscoverPair(t, { left: 41611, right: 41612 }, null)
  const pending = discoverPeerCandidate(setup.transport, {
    ledger: setup.ledger,
    requestedMask: 11,
    randomTarget: b4a.alloc(32, 0xad),
    maximumResults: 1
  })
  await driveClock(setup.clock)
  const candidate = await pending
  let reads = 0
  const accessor = {
    expectedKind: 'candidate',
    get expectedIdentity32() {
      reads++
      return setup.edKeys.publicKey
    }
  }
  for (const expected of [
    undefined,
    null,
    { expectedKind: 'candidate', extra: true },
    { expectedKind: 'candidate', [Symbol('extra')]: true },
    accessor
  ]) {
    let error = null
    try {
      takePeerActiveCandidate(candidate, expected)
    } catch (err) {
      error = err
    }
    t.is(error && error.code, 'INVALID_ROUTE', 'invalid schema does not consume authority')
  }
  t.is(reads, 0, 'expectation accessors never execute')
  const taken = takePeerActiveCandidate(candidate, {
    expectedKind: 'candidate',
    expectedIdentity32: setup.edKeys.publicKey
  })
  t.alike(taken.identity32, setup.edKeys.publicKey, 'valid subsequent consumer retains authority')
  destroyPeerActiveCandidate(candidate)
})

test('candidate advertisement mismatch preserves authority for its exact advertisement', async (t) => {
  const setup = await setupDiscoverPair(t, { left: 41613, right: 41614 }, null)
  const pending = discoverPeerCandidate(setup.transport, {
    ledger: setup.ledger,
    requestedMask: 11,
    randomTarget: b4a.alloc(32, 0xae),
    maximumResults: 1
  })
  await driveClock(setup.clock)
  const candidate = await pending
  const advertisement = setup.remoteFacts.canonicalAdvertisement260
  const replacementBody = b4a.from(advertisement.subarray(8, 196))
  replacementBody.writeBigUInt64BE(9n, 162)
  const replacement = reSignAdvertisement(replacementBody, setup.edKeys.secretKey)
  let error = null
  try {
    takePeerActiveCandidate(candidate, {
      expectedKind: 'candidate',
      expectedIdentity32: setup.edKeys.publicKey,
      expectedAdvertisement260: replacement
    })
  } catch (err) {
    error = err
  }
  t.is(error && error.code, 'INVALID_ROUTE', 'same signer cannot substitute another advertisement')
  const taken = takePeerActiveCandidate(candidate, {
    expectedKind: 'candidate',
    expectedAdvertisement260: advertisement
  })
  t.alike(taken.completeAdvertisement, advertisement, 'mismatch did not consume exact authority')
  destroyPeerActiveCandidate(candidate)
})

test('discover rejects same-identity re-signed replacement CAPS against locator bytes', async (t) => {
  let edKeysRef = null
  let canonicalRef = null
  const mutate = (packet) => {
    const obj = isDirectMessage(packet, PEER_MESSAGE_ID.PEER_CAPS_RESPONSE_V2)
    if (!obj || !edKeysRef || !canonicalRef) return null
    const body = b4a.from(obj.body)
    const mutAdBody = b4a.from(canonicalRef.subarray(8, 196))
    mutAdBody.writeBigUInt64BE(9n, 162)
    const replacementAd = reSignAdvertisement(mutAdBody, edKeysRef.secretKey)
    body.set(replacementAd, 75)
    const label = b4a.from('hyperdht-private-routes/m3/caps-response/v2')
    const labelLen = b4a.allocUnsafe(2)
    labelLen.writeUInt16BE(label.byteLength, 0)
    const sigInput = b4a.concat([
      labelLen,
      label,
      b4a.from([0, 0, 0, 2]),
      b4a.from([0x03, 0x03]),
      b4a.from([0x01, 0x4f]),
      body
    ])
    const sig = b4a.alloc(64)
    sodium.crypto_sign_detached(sig, sigInput, edKeysRef.secretKey)
    return wrapInner(PEER_MESSAGE_ID.PEER_CAPS_RESPONSE_V2, body, sig)
  }
  const setup = await setupDiscoverPair(t, { left: 41211, right: 41212 }, mutate)
  edKeysRef = setup.edKeys
  canonicalRef = setup.remoteFacts.canonicalAdvertisement260
  const candidatePromise = discoverPeerCandidate(setup.transport, {
    ledger: setup.ledger,
    requestedMask: 11,
    randomTarget: b4a.alloc(32, 0xcd),
    maximumResults: 1
  })
  await driveClock(setup.clock, 60, 100)
  try {
    await candidatePromise
    t.fail('replacement CAPS must not complete discovery')
  } catch (err) {
    t.ok(err && typeof err.code === 'string')
  }
})

test('late cookie after phase/operation deadline cannot advance or publish', async (t) => {
  const held = []
  const mutate = (packet) => {
    const obj = isDirectMessage(packet, PEER_MESSAGE_ID.PEER_CAPS_COOKIE_CHALLENGE_V2)
    if (!obj) return null
    held.push(b4a.from(packet))
    return false
  }
  const setup = await setupDiscoverPair(t, { left: 41501, right: 41502 }, mutate)
  const candidatePromise = discoverPeerCandidate(setup.transport, {
    ledger: setup.ledger,
    requestedMask: 11,
    randomTarget: b4a.alloc(32, 0xef),
    maximumResults: 1
  })

  // Let PHASE0 send and hold the cookie reply.
  for (let i = 0; i < 10; i++) await new Promise((resolve) => queueMicrotask(resolve))
  t.ok(held.length >= 1)

  // Expire operationLocalDeadline without firing retry timers.
  setup.clock.advanceSilent(6000)

  const leftSock = setup.network.get(`127.0.0.1:${setup.ports.left}`)
  t.ok(leftSock)
  leftSock.emit('message', held[0], {
    host: '127.0.0.1',
    port: setup.ports.right
  })
  for (let i = 0; i < 10; i++) await new Promise((resolve) => queueMicrotask(resolve))

  // Delivery itself must settle ROUTE_UNAVAILABLE before timers fire.
  try {
    await candidatePromise
    t.fail('late cookie must not complete discovery')
  } catch (err) {
    t.ok(err && err.code === 'ROUTE_UNAVAILABLE')
  }
})

test('discover rejects each individually mutated ACTIVE frozen binding', async (t) => {
  const fields = [
    { name: 'adDigest', offset: 0, len: 1 },
    { name: 'responderIdentity', offset: 32, len: 1 },
    { name: 'requesterEphemeral', offset: 64, len: 1 },
    { name: 'challengeExpiry', offset: 128, len: 1 },
    { name: 'queryNonce', offset: 136, len: 1 },
    { name: 'cookieExpiry', offset: 168, len: 1 },
    { name: 'cookie', offset: 176, len: 1 }
  ]

  for (let i = 0; i < fields.length; i++) {
    const field = fields[i]
    const mutate = (packet) => {
      const obj = isDirectMessage(packet, PEER_MESSAGE_ID.PEER_ACTIVE_CHALLENGE_RESPONSE_V2)
      if (!obj) return null
      const body = b4a.from(obj.body)
      body[field.offset] ^= 0xff
      // Keep original auth so signature fails OR frozen compare fails first.
      return wrapInner(PEER_MESSAGE_ID.PEER_ACTIVE_CHALLENGE_RESPONSE_V2, body, obj.authSuffix)
    }
    const setup = await setupDiscoverPair(t, { left: 41301 + i * 2, right: 41302 + i * 2 }, mutate)
    const candidatePromise = discoverPeerCandidate(setup.transport, {
      ledger: setup.ledger,
      requestedMask: 11,
      randomTarget: b4a.alloc(32, 0x10 + i),
      maximumResults: 1
    })
    await driveClock(setup.clock, 60, 100)
    try {
      await candidatePromise
      t.fail('mutated ' + field.name + ' must not publish candidate')
    } catch (err) {
      t.ok(err && typeof err.code === 'string', field.name)
    }
  }
})

test('discoverPeerCandidate rejects untrusted transport input before ledger charge', async (t) => {
  try {
    await discoverPeerCandidate(Object.freeze({ kind: 'candidate' }), {
      ledger: createPeerLedger({ cells: 8, bytes: 8n * 1200n, commands: 0 })
    })
    t.fail('should reject')
  } catch (err) {
    t.ok(err && typeof err.code === 'string')
  }
})

test('duplicate direct responder registration rejects before second token consume', async (t) => {
  const clock = createMockClock()
  const { left, right } = await endpointPair(41401, 41402)
  t.teardown(async () => {
    try {
      await left.close()
    } catch {}
    try {
      await right.close()
    } catch {}
  })
  const edKeys = generateEd25519KeyPair()
  const xKeys = generateX25519KeyPair()
  const ownerA = createPeerRelayOwner({
    endpoint: right,
    identityKeyPair: edKeys,
    routeKeyPair: xKeys,
    advertisementFields: buildTestAdvertisementFields(
      edKeys,
      xKeys,
      { host: '127.0.0.1', port: 41402 },
      2000000n,
      11
    ),
    clockIdentity: clock.clockIdentity,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer
  })
  const responderA = createPeerBootstrapResponder(ownerA)
  const reg = registerPeerDirectResponder(right, responderA)

  const edKeysB = generateEd25519KeyPair()
  const xKeysB = generateX25519KeyPair()
  const ownerB = createPeerRelayOwner({
    endpoint: right,
    identityKeyPair: edKeysB,
    routeKeyPair: xKeysB,
    advertisementFields: buildTestAdvertisementFields(
      edKeysB,
      xKeysB,
      { host: '127.0.0.1', port: 41402 },
      2000000n,
      11
    ),
    clockIdentity: clock.clockIdentity,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer
  })
  const responderB = createPeerBootstrapResponder(ownerB)
  try {
    registerPeerDirectResponder(right, responderB)
    t.fail('duplicate registration should reject')
  } catch (err) {
    t.ok(err && typeof err.code === 'string')
  }
  const bindingB = takePeerBootstrapResponderBinding(responderB, right)
  t.ok(bindingB && typeof bindingB.receive === 'function')
  destroyPeerDirectResponderRegistration(reg)
  destroyPeerBootstrapResponder(responderA)
  destroyPeerBootstrapResponder(responderB)
})
