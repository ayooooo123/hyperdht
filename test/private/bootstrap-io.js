'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { PrivateRouteError } = require('../../lib/private/errors')
const {
  createIndexZeroGuardLinkResponder,
  destroyM3EstablishedLink
} = require('../../lib/private/guard-link')
const {
  CAPACITY_CLASS,
  RELAY_CAPABILITY,
  ROLE,
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
  createRelayCandidateDirectorySink,
  kInspectRelayCandidateDirectory
} = require('../../lib/private/relay-candidate-directory')
const {
  TEST_ONLY_BOOTSTRAP_IO_OBSERVER,
  BootstrapIO,
  consumeBootstrapGuardPin,
  revokeBootstrapGuardPin
} = require('../../lib/private/bootstrap-io')

const NOW = 1_000n
const seed = (value) => b4a.alloc(32, value)

function expectCode(t, fn, code) {
  let error = null
  try {
    fn()
  } catch (err) {
    error = err
  }
  t.ok(error instanceof PrivateRouteError)
  t.is(error && error.code, code)
}

async function expectCodeAsync(t, fn, code) {
  let error = null
  try {
    await fn()
  } catch (err) {
    error = err
  }
  t.ok(error instanceof PrivateRouteError)
  t.is(error && error.code, code)
}

function identityFor(role, start) {
  for (let value = start; value < 256; value++) {
    const pair = cryptoSuite.keyPair(seed(value))
    if (roleForIdentity(pair.publicKey) === role) return pair
  }
  throw new Error('missing deterministic identity')
}

function endpoint(host, port) {
  return { host, port }
}

function endpointBytes(host, port) {
  return encodeCanonicalEndpoint({
    addressFamily: 4,
    addressBytes: b4a.from(host.split('.').map(Number)),
    port
  })
}

function advertisement(role, index, host, port) {
  const signer = identityFor(role, 20 + index * 5)
  const route = cryptoSuite.encryptionKeyPair(seed(120 + index))
  const reachableEndpoint = endpointBytes(host, port)
  const capabilityMask = role === ROLE.SAFETY ? 1 : 3
  const signed = signRelayCapabilityAdvertisement(
    {
      relayIdentity: signer.publicKey,
      currentDhtNodeId: deriveM3DhtNodeId(reachableEndpoint),
      reachableEndpoint,
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
      maxConcurrentCircuits: 8,
      capacityClass: CAPACITY_CLASS.SMALL,
      maxCellsPerCircuit: 100,
      maxBytesPerCircuit: 100_000,
      maxCommandsPerCircuit: 10,
      idleTimeoutMs: 30_000,
      maxQueuedBytes: 65_536,
      epoch: 1n,
      issuedAtMs: NOW,
      expiresAtMs: NOW + 20_000n,
      providerServicePolicyEntries: providerServicePolicyForCapabilities(capabilityMask)
    },
    signer.secretKey
  )
  return {
    bytes: encodeRelayCapabilityAdvertisement(signed),
    digest: null,
    endpoint: reachableEndpoint,
    signer,
    route
  }
}

function fakeClock() {
  let wall = NOW
  let monotonic = 0n
  return {
    wallNow: () => wall,
    monotonicNow: () => monotonic,
    advance(value) {
      wall += BigInt(value)
      monotonic += BigInt(value)
    }
  }
}

function fixture(options = {}) {
  const clock = fakeClock()
  const local = identityFor(ROLE.SAFETY, 2)
  const configured = [endpoint('192.0.2.41', 49737), endpoint('198.51.100.42', 49738)]
  const guard = advertisement(ROLE.SAFETY, 1, configured[0].host, configured[0].port)
  guard.digest = digestRelayCapabilityAdvertisement(guard.bytes, { now: NOW })
  const middleA = advertisement(ROLE.SAFETY, 2, '203.0.113.43', 49739)
  const middleB = advertisement(ROLE.SAFETY, 3, '198.18.4.44', 49740)
  const exitA = advertisement(ROLE.PRIVATE, 4, '198.19.5.45', 49741)
  const exitB = advertisement(ROLE.PRIVATE, 5, '203.0.120.46', 49742)
  const advertisements = [guard, middleA, middleB, exitA, exitB]
  for (let index = 0; index < (options.extraAdvertisements || 0); index++) {
    advertisements.push(
      advertisement(
        index % 2 === 0 ? ROLE.SAFETY : ROLE.PRIVATE,
        10 + index,
        `198.${30 + index}.1.${50 + index}`,
        49800 + index
      )
    )
  }
  const calls = []
  let destroyed = false
  let responder = null
  let responderEstablished = null
  let physicalDestroys = 0
  let inFlight = 0
  let maximumInFlight = 0
  const datagrams = {
    async send(host, port, request) {
      if (destroyed) throw new Error('generic send authority revoked')
      inFlight++
      maximumInFlight = Math.max(maximumInFlight, inFlight)
      calls.push([host, port, request.kind])
      try {
        if (options.onSend) await options.onSend({ host, port, request, clock })
        if (request.kind === 'cookie') return { cookie: b4a.alloc(32, 0x77) }
        if (request.kind === 'caps') {
          return { advertisements: advertisements.map((entry) => entry.bytes) }
        }
        if (request.kind === 'challenge') {
          if (options.rejectChallenges) throw new Error('challenge rejected')
          return { advertisementDigest: b4a.from(guard.digest) }
        }
        if (request.kind === 'link') {
          const responderPhysical = Object.freeze({ destroy() {} })
          responder = createIndexZeroGuardLinkResponder({
            advertisement: guard.bytes,
            responderIdentitySecretKey: guard.signer.secretKey,
            responderRouteEncryptionSecretKey: guard.route.secretKey,
            now: () => NOW,
            receiveOffer: () => ({
              offer: request.bytes,
              observedPredecessorEndpoint: endpointBytes('10.0.0.2', 44000),
              physicalChannel: responderPhysical
            }),
            randomBytes: (size) => b4a.alloc(size, 0x55)
          })
          const accepted = responder.accept()
          responderEstablished = accepted.established
          return {
            accept: accepted.accept,
            physicalChannel: Object.freeze({
              destroy() {
                physicalDestroys++
              }
            })
          }
        }
        throw new Error('unexpected request')
      } finally {
        inFlight--
      }
    },
    destroy() {
      destroyed = true
      calls.push(['destroy'])
    }
  }
  let io = null
  const sink = createRelayCandidateDirectorySink({
    wallNow: clock.wallNow,
    monotonicNow() {
      if (options.onSinkMonotonic) options.onSinkMonotonic({ io, clock })
      return clock.monotonicNow()
    }
  })
  io = new BootstrapIO({
    endpoints: configured,
    localIdentity: local.publicKey,
    localSecretKey: local.secretKey,
    datagrams,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    randomBytes: (size) => b4a.alloc(size, 0x44),
    candidateDirectorySink: sink
  })
  return {
    advertisements,
    calls,
    clock,
    configured,
    datagrams,
    get destroyed() {
      return destroyed
    },
    get maximumInFlight() {
      return maximumInFlight
    },
    get physicalDestroys() {
      return physicalDestroys
    },
    io,
    cleanup() {
      if (responderEstablished) destroyM3EstablishedLink(responderEstablished)
      if (responder) responder.destroy()
    }
  }
}

test('BootstrapIO exposes only the narrowed cold-start lifecycle', (t) => {
  t.alike(Object.keys(require('../../lib/private/bootstrap-io')).sort(), [
    'BootstrapIO',
    'TEST_ONLY_BOOTSTRAP_IO_OBSERVER',
    'consumeBootstrapGuardPin',
    'revokeBootstrapGuardPin'
  ])
  t.alike(Object.getOwnPropertyNames(BootstrapIO.prototype).sort(), [
    'cancel',
    'constructor',
    'destroy',
    'start'
  ])
})

test('numeric configured endpoints are owned, deduplicated, and bounded to three', (t) => {
  const f = fixture()
  t.is(f.io[TEST_ONLY_BOOTSTRAP_IO_OBSERVER]().endpointCount, 2)
  f.io.cancel()
  expectCode(
    t,
    () =>
      new BootstrapIO({
        endpoints: [endpoint('bootstrap.example', 1)],
        localIdentity: b4a.alloc(32),
        localSecretKey: b4a.alloc(64),
        datagrams: { send() {}, destroy() {} },
        wallNow: () => NOW,
        monotonicNow: () => 0n,
        randomBytes: (size) => b4a.alloc(size),
        candidateDirectorySink: {}
      }),
    'INVALID_ROUTE'
  )
  const four = ['192.0.2.1', '198.51.100.2', '203.0.113.3', '198.18.4.4'].map((host, i) =>
    endpoint(host, 4000 + i)
  )
  expectCode(
    t,
    () =>
      new BootstrapIO({
        endpoints: four,
        localIdentity: b4a.alloc(32),
        localSecretKey: b4a.alloc(64),
        datagrams: { send() {}, destroy() {} },
        wallNow: () => NOW,
        monotonicNow: () => 0n,
        randomBytes: (size) => b4a.alloc(size),
        candidateDirectorySink: {}
      }),
    'INVALID_ROUTE'
  )
})

test('cold start contacts sequentially, pins one guard, revokes generic send before resolve, and transfers no send authority', async (t) => {
  const f = fixture()
  const transfer = await f.io.start().then((value) => {
    t.ok(f.destroyed, 'transport is destroyed before the continuation runs')
    return value
  })
  t.is(
    f.io[TEST_ONLY_BOOTSTRAP_IO_OBSERVER]().recordKeyCount,
    0,
    'identity index releases every candidate record before resolution'
  )
  t.is(f.maximumInFlight, 1)
  t.alike(
    f.calls.map((call) => call[2] || call[0]),
    ['cookie', 'caps', 'cookie', 'caps', 'challenge', 'link', 'destroy']
  )
  const moved = consumeBootstrapGuardPin(transfer)
  t.alike(Object.keys(moved.guardLeaseMaterial), [])
  t.is(typeof moved.pinnedGuard.identity, 'object')
  t.is('send' in moved, false)
  t.is('send' in moved.pinnedGuard, false)
  t.ok(moved.exposureReport.length <= 6)
  for (const entry of moved.exposureReport) {
    t.alike(Object.keys(entry).sort(), [
      'attemptCount',
      'contactCategory',
      'firstAttemptMs',
      'lastAttemptMs',
      'outcome',
      'phase',
      'redactedEndpoint'
    ])
    t.is(entry.redactedEndpoint.includes('192.0.2.41'), false)
  }
  t.is(moved.candidateDirectory[kInspectRelayCandidateDirectory]().identityCount, 4)
  expectCode(t, () => consumeBootstrapGuardPin(transfer), 'ERR_REPLAY')
  moved.candidateDirectory.destroy()
  f.cleanup()
})

test('challenge exhaustion fails closed without link, fallback, DNS, or more than three prospective guards', async (t) => {
  const f = fixture({ rejectChallenges: true })
  await expectCodeAsync(t, () => f.io.start(), 'ERR_PRIVATE_GUARD_UNAVAILABLE')
  t.is(f.calls.filter((call) => call[2] === 'challenge').length, 3)
  t.is(
    f.calls.some((call) => call[2] === 'link'),
    false
  )
  t.is(
    f.calls.some((call) => call[2] === 'fallback' || call[2] === 'dns'),
    false
  )
  t.ok(f.destroyed)
  f.cleanup()
})

test('one monotonic ten-second budget covers cookie, CAPS, challenge, and first link', async (t) => {
  const f = fixture({
    onSend({ clock }) {
      clock.advance(2_100)
    }
  })
  await expectCodeAsync(t, () => f.io.start(), 'ERR_PRIVATE_GUARD_UNAVAILABLE')
  t.is(
    f.calls.some((call) => call[2] === 'link'),
    false
  )
  t.ok(f.destroyed)
  f.cleanup()
})

test('a CAPS response cannot make BootstrapIO retain or challenge more than sixteen candidates', async (t) => {
  const f = fixture({ extraAdvertisements: 12 })
  await expectCodeAsync(t, () => f.io.start(), 'ERR_PRIVATE_GUARD_UNAVAILABLE')
  t.is(f.io[TEST_ONLY_BOOTSTRAP_IO_OBSERVER]().candidateCount, 0)
  t.is(
    f.calls.some((call) => call[2] === 'challenge'),
    false
  )
  t.ok(f.destroyed)
  f.cleanup()
})

test('transfer revocation is one-shot and destroys both unpublished resources', async (t) => {
  const f = fixture()
  const transfer = await f.io.start()
  t.ok(revokeBootstrapGuardPin(transfer))
  t.is(f.physicalDestroys, 1, 'revocation destroys unpublished guard lease material')
  expectCode(t, () => revokeBootstrapGuardPin(transfer), 'ERR_REPLAY')
  expectCode(t, () => consumeBootstrapGuardPin(transfer), 'ERR_REPLAY')
  f.cleanup()
})

test('sealed-directory consume failure atomically destroys the guard lease and returns no partial value', async (t) => {
  const f = fixture()
  const transfer = await f.io.start()
  f.clock.advance(20_001)
  expectCode(t, () => consumeBootstrapGuardPin(transfer), 'ERR_REPLAY')
  t.is(f.physicalDestroys, 1)
  expectCode(t, () => consumeBootstrapGuardPin(transfer), 'ERR_REPLAY')
  f.cleanup()
})

test('cancel during a pending datagram emits no later packet', async (t) => {
  let release = null
  const f = fixture({
    onSend() {
      return new Promise((resolve) => {
        release = resolve
      })
    }
  })
  const started = f.io.start()
  while (release === null) await Promise.resolve()
  t.ok(f.io.cancel())
  release()
  await expectCodeAsync(t, () => started, 'ERR_PRIVATE_GUARD_UNAVAILABLE')
  t.is(f.calls.filter((call) => call[2]).length, 1)
  t.alike(
    f.calls.map((call) => call[2] || call[0]),
    ['cookie', 'destroy']
  )
  f.cleanup()
})

test('three prospective configured guards are challenged sequentially and never as middle or exit contacts', async (t) => {
  const clock = fakeClock()
  const local = identityFor(ROLE.SAFETY, 2)
  const configured = [
    endpoint('192.0.2.41', 49737),
    endpoint('198.51.100.42', 49738),
    endpoint('203.0.113.43', 49739)
  ]
  const guards = configured.map((value, index) =>
    advertisement(ROLE.SAFETY, index + 1, value.host, value.port)
  )
  const contacts = []
  let active = 0
  let maximum = 0
  const datagrams = {
    async send(host, port, request) {
      active++
      maximum = Math.max(maximum, active)
      contacts.push([host, port, request.kind])
      try {
        if (request.kind === 'cookie') return { cookie: b4a.alloc(32, 1) }
        if (request.kind === 'caps') return { advertisements: guards.map((value) => value.bytes) }
        if (request.kind === 'challenge') throw new Error('no proof')
        throw new Error('unexpected contact')
      } finally {
        active--
      }
    },
    destroy() {}
  }
  const io = new BootstrapIO({
    endpoints: configured,
    localIdentity: local.publicKey,
    localSecretKey: local.secretKey,
    datagrams,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    randomBytes: (size) => b4a.alloc(size, 9),
    candidateDirectorySink: createRelayCandidateDirectorySink({
      wallNow: clock.wallNow,
      monotonicNow: clock.monotonicNow
    })
  })
  await expectCodeAsync(t, () => io.start(), 'ERR_PRIVATE_GUARD_UNAVAILABLE')
  t.is(contacts.filter((entry) => entry[2] === 'challenge').length, 3)
  t.is(maximum, 1)
  t.is(
    contacts.some((entry) => entry[2] === 'middle' || entry[2] === 'exit'),
    false
  )
})

test('candidate projection allocation failure zeroizes every earlier owned copy', async (t) => {
  const original = b4a.allocUnsafeSlow
  const allocations = []
  let armed = false
  let count = 0
  b4a.allocUnsafeSlow = (size) => {
    if (armed && ++count === 4) throw new Error('injected candidate allocation failure')
    const value = original(size)
    if (armed) allocations.push(value)
    return value
  }
  let f = null
  try {
    f = fixture({
      onSend({ request }) {
        if (request.kind === 'caps') armed = true
      }
    })
    await expectCodeAsync(t, () => f.io.start(), 'ERR_PRIVATE_GUARD_UNAVAILABLE')
  } finally {
    b4a.allocUnsafeSlow = original
    if (f) f.cleanup()
  }
  t.ok(allocations.length >= 3)
  for (const value of allocations) t.alike(value, b4a.alloc(value.byteLength))
})

test('guard-pin consume allocation failure clears earlier pinned projection copies and returns no partial resource', async (t) => {
  const f = fixture()
  const transfer = await f.io.start()
  const original = b4a.allocUnsafeSlow
  const allocations = []
  let count = 0
  b4a.allocUnsafeSlow = (size) => {
    if (++count === 3) throw new Error('injected pinned projection allocation failure')
    const value = original(size)
    allocations.push(value)
    return value
  }
  try {
    t.exception(() => consumeBootstrapGuardPin(transfer))
  } finally {
    b4a.allocUnsafeSlow = original
    f.cleanup()
  }
  t.is(f.physicalDestroys, 1, 'lease is destroyed when the sibling projection fails')
  t.is(allocations.length, 2)
  for (const value of allocations) t.alike(value, b4a.alloc(value.byteLength))
  expectCode(t, () => consumeBootstrapGuardPin(transfer), 'ERR_REPLAY')
})

test('constructor partial allocation failure zeroizes the owned identity and performs no IO', (t) => {
  const original = b4a.allocUnsafeSlow
  const allocations = []
  let count = 0
  b4a.allocUnsafeSlow = (size) => {
    if (++count === 2) throw new Error('injected constructor allocation failure')
    const value = original(size)
    allocations.push(value)
    return value
  }
  try {
    t.exception(() => fixture())
  } finally {
    b4a.allocUnsafeSlow = original
  }
  t.is(allocations.length, 1)
  t.alike(allocations[0], b4a.alloc(allocations[0].byteLength))
})

test('reentrant directory sealing cancels IO and publishes neither guard resource', async (t) => {
  let reenter = true
  const f = fixture({
    onSinkMonotonic({ io }) {
      if (!reenter) return
      reenter = false
      io.cancel()
    }
  })
  await expectCodeAsync(t, () => f.io.start(), 'ERR_PRIVATE_GUARD_UNAVAILABLE')
  t.ok(f.destroyed)
  t.is(f.physicalDestroys, 1, 'established guard is destroyed after sealing loses authority')
  t.is(f.io[TEST_ONLY_BOOTSTRAP_IO_OBSERVER]().candidateCount, 0)
  f.cleanup()
})
