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
  createActiveChallengeResponderAuthority,
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
  let nextTimer = 0
  const timers = new Map()
  return {
    wallNow: () => wall,
    monotonicNow: () => monotonic,
    setTimer(callback, delay) {
      const id = ++nextTimer
      timers.set(id, { at: monotonic + BigInt(delay), callback })
      return id
    },
    clearTimer(id) {
      timers.delete(id)
    },
    advance(value) {
      wall += BigInt(value)
      monotonic += BigInt(value)
      for (const [id, timer] of timers) {
        if (timer.at > monotonic) continue
        timers.delete(id)
        timer.callback()
      }
    }
  }
}

function fixture(options = {}) {
  const clock = fakeClock()
  const local = identityFor(ROLE.SAFETY, 2)
  const configured = [
    endpoint('192.0.2.41', 49737),
    endpoint('198.51.100.42', 49738),
    endpoint('203.0.113.43', 49739)
  ].slice(0, options.configuredCount || 2)
  const guards = configured.map((value, index) =>
    advertisement(ROLE.SAFETY, index + 1, value.host, value.port)
  )
  for (const guard of guards) {
    guard.digest = digestRelayCapabilityAdvertisement(guard.bytes, { now: NOW })
  }
  const guard = guards[0]
  const middleB = advertisement(ROLE.SAFETY, 6, '198.18.4.44', 49740)
  const exitA = advertisement(ROLE.PRIVATE, 4, '198.19.5.45', 49741)
  const exitB = advertisement(ROLE.PRIVATE, 5, '203.0.120.46', 49742)
  const advertisements = options.onlyGuardAdvertisement
    ? [...guards]
    : [...guards, middleB, exitA, exitB]
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
  let replayedChallengeResponse = null
  const capsResponders = new Map()
  const capsBindings = new Map()
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
        if (
          (options.failFirstAt === request.kind && host === configured[0].host) ||
          options.failAllAt === request.kind
        ) {
          throw new Error(`injected ${request.kind} failure`)
        }
        if (options.strictTask2Caps !== false) {
          const endpointKey = `${host}:${port}`
          let capsResponder = capsResponders.get(endpointKey)
          if (!capsResponder) {
            capsResponder = createActiveChallengeResponderAuthority({
              now: clock.wallNow,
              setTimeout: clock.setTimer,
              clearTimeout: clock.clearTimer,
              crypto: { ...cryptoSuite, randomBytes: (size) => b4a.alloc(size, 0x5d) }
            })
            capsResponders.set(endpointKey, capsResponder)
          }
          if (request.kind === 'caps-query') {
            const query = {
              sourceEndpoint: endpointBytes('10.0.0.2', 44000),
              requestedCapabilityMask: request.requestedCapabilityMask,
              randomTarget: request.randomTarget,
              queryNonce: request.queryNonce,
              maximumResults: request.maximumResults
            }
            const cookie = capsResponder.issueCookie(query)
            if (options.onCapsQueryResponse) options.onCapsQueryResponse()
            let response = Object.freeze({
              sourceEndpoint: query.sourceEndpoint,
              cookieExpiresAtMs: cookie.cookieExpiresAtMs,
              returnRoutabilityCookie: cookie.returnRoutabilityCookie,
              advertisements: advertisements.map((entry) => entry.bytes)
            })
            if (options.forgeCapsSource) {
              response = Object.freeze({
                ...response,
                sourceEndpoint: endpointBytes('10.0.0.9', 44009)
              })
            }
            if (options.wrongRoleAdvertisement) {
              response = Object.freeze({ ...response, advertisements: [exitA.bytes] })
            }
            return response
          }
          if (request.kind === 'caps-retry') {
            const binding = capsResponder.admitCapsRetry({
              sourceEndpoint: request.sourceEndpoint,
              requestedCapabilityMask: request.requestedCapabilityMask,
              randomTarget: request.randomTarget,
              queryNonce: request.queryNonce,
              maximumResults: request.maximumResults,
              cookieExpiresAtMs: request.cookieExpiresAtMs,
              returnRoutabilityCookie: request.returnRoutabilityCookie,
              advertisement: request.advertisement
            })
            capsBindings.set(endpointKey, {
              advertisement: request.advertisement,
              binding,
              responder: capsResponder,
              sourceEndpoint: request.sourceEndpoint
            })
            return Object.freeze({})
          }
          if (request.kind === 'active-challenge') {
            if (options.rejectChallenges) throw new Error('challenge rejected')
            const stored = capsBindings.get(endpointKey)
            if (!stored) throw new Error('missing CAPS retry binding')
            const selected = advertisements.find((entry) =>
              b4a.equals(entry.bytes, stored.advertisement)
            )
            if (!selected) throw new Error('unknown challenged advertisement')
            capsBindings.delete(endpointKey)
            let bytes = stored.responder.respond(stored.binding, request.bytes, {
              sourceEndpoint: stored.sourceEndpoint,
              advertisement: selected.bytes,
              identitySecretKey: selected.signer.secretKey,
              routeEncryptionSecretKey: selected.route.secretKey
            })
            if (options.replayActiveChallenge) {
              if (replayedChallengeResponse) bytes = b4a.from(replayedChallengeResponse)
              else replayedChallengeResponse = b4a.from(bytes)
            }
            if (options.forgeActiveChallenge) {
              bytes = b4a.from(bytes)
              bytes[bytes.byteLength - 1] ^= 1
            }
            if (options.expireActiveChallenge) clock.advance(5_001)
            if (options.cancelAt === 'active-challenge') io.cancel()
            return Object.freeze({ bytes })
          }
          if (request.kind !== 'link') throw new Error('legacy CAPS transport shape')
        }
        if (request.kind === 'cookie') return { cookie: b4a.alloc(32, 0x77) }
        if (request.kind === 'caps') {
          return { advertisements: advertisements.map((entry) => entry.bytes) }
        }
        if (request.kind === 'challenge') {
          if (options.rejectChallenges) throw new Error('challenge rejected')
          return { advertisementDigest: b4a.from(guard.digest) }
        }
        if (request.kind === 'link') {
          const selectedGuard = guards.find(
            (entry) =>
              b4a.equals(entry.endpoint, endpointBytes(host, port)) &&
              roleForIdentity(entry.signer.publicKey) === ROLE.SAFETY
          )
          if (!selectedGuard) throw new Error('link attempted for non-guard')
          const responderPhysical = Object.freeze({ destroy() {} })
          responder = createIndexZeroGuardLinkResponder({
            advertisement: selectedGuard.bytes,
            responderIdentitySecretKey: selectedGuard.signer.secretKey,
            responderRouteEncryptionSecretKey: selectedGuard.route.secretKey,
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
    wallNow() {
      if (options.onSinkWall) options.onSinkWall({ io, clock })
      return clock.wallNow()
    },
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
      for (const capsResponder of capsResponders.values()) capsResponder.destroy()
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
    ['caps-query', 'caps-query', 'caps-retry', 'active-challenge', 'link', 'destroy']
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

test('cold start authenticates CAPS through the Task2 cookie binding and encoded active challenge', async (t) => {
  const f = fixture({ strictTask2Caps: true })
  let transfer = null
  try {
    transfer = await f.io.start()
    const activeChallenge = f.calls.find((call) => call[2] === 'active-challenge')
    t.ok(activeChallenge, 'Task2 active challenge is emitted')
    t.is(
      f.calls.some((call) => call[2] === 'challenge'),
      false,
      'legacy digest-shaped challenge is never emitted'
    )
    const moved = consumeBootstrapGuardPin(transfer)
    transfer = null
    moved.candidateDirectory.destroy()
  } finally {
    if (transfer) revokeBootstrapGuardPin(transfer)
    f.cleanup()
  }
})

test('Task2 CAPS integration rejects forged source cookies and wrong-role advertisements', async (t) => {
  for (const options of [{ forgeCapsSource: true }, { wrongRoleAdvertisement: true }]) {
    const f = fixture({ configuredCount: 1, ...options })
    await expectCodeAsync(t, () => f.io.start(), 'ERR_PRIVATE_GUARD_UNAVAILABLE')
    t.is(
      f.calls.some((call) => call[2] === 'link'),
      false
    )
    t.ok(f.destroyed)
    f.cleanup()
  }
})

test('Task2 active challenge rejects forgery, replay, expiry, and cancellation reentry', async (t) => {
  for (const options of [
    { configuredCount: 1, forgeActiveChallenge: true },
    { configuredCount: 2, replayActiveChallenge: true, failFirstAt: 'link' },
    { configuredCount: 1, expireActiveChallenge: true },
    { configuredCount: 1, cancelAt: 'active-challenge' }
  ]) {
    const f = fixture(options)
    await expectCodeAsync(t, () => f.io.start(), 'ERR_PRIVATE_GUARD_UNAVAILABLE')
    t.ok(f.destroyed)
    t.is(f.calls.filter((call) => call[2] === 'link').length, options.replayActiveChallenge ? 1 : 0)
    f.cleanup()
  }
})

test('each failed configured endpoint boundary is cleared before the next endpoint succeeds', async (t) => {
  for (const failedKind of ['caps-query', 'caps-retry', 'active-challenge', 'link']) {
    const f = fixture({ failFirstAt: failedKind })
    let transfer = null
    try {
      transfer = await f.io.start()
      t.is(f.maximumInFlight, 1, `${failedKind} never overlaps endpoint attempts`)
      t.ok(
        f.calls.some((call) => call[0] === f.configured[1].host && call[2] === 'caps-query'),
        `${failedKind} advances to the second configured endpoint`
      )
      const moved = consumeBootstrapGuardPin(transfer)
      transfer = null
      moved.candidateDirectory.destroy()
    } finally {
      if (transfer) revokeBootstrapGuardPin(transfer)
      f.cleanup()
    }
  }
})

test('all configured endpoint failures exhaust without parallel, fallback, or DNS traffic', async (t) => {
  for (const failedKind of ['caps-query', 'caps-retry', 'active-challenge', 'link']) {
    const f = fixture({ failAllAt: failedKind })
    try {
      await expectCodeAsync(t, () => f.io.start(), 'ERR_PRIVATE_GUARD_UNAVAILABLE')
      t.is(f.maximumInFlight, 1, `${failedKind} remains sequential`)
      t.is(
        f.calls.some((call) => call[2] === 'fallback' || call[2] === 'dns'),
        false,
        `${failedKind} cannot create fallback traffic`
      )
    } finally {
      f.cleanup()
    }
  }
})

test('challenge exhaustion fails closed without link, fallback, DNS, or more than three prospective guards', async (t) => {
  const f = fixture({ configuredCount: 3, rejectChallenges: true })
  await expectCodeAsync(t, () => f.io.start(), 'ERR_PRIVATE_GUARD_UNAVAILABLE')
  t.is(f.calls.filter((call) => call[2] === 'active-challenge').length, 3)
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
    true,
    'the first-link request is covered and its over-budget response is rejected'
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
    ['caps-query', 'destroy']
  )
  f.cleanup()
})

test('three prospective configured guards are challenged sequentially and never as middle or exit contacts', async (t) => {
  const f = fixture({ configuredCount: 3, rejectChallenges: true })
  await expectCodeAsync(t, () => f.io.start(), 'ERR_PRIVATE_GUARD_UNAVAILABLE')
  t.is(f.calls.filter((entry) => entry[2] === 'active-challenge').length, 3)
  t.is(f.maximumInFlight, 1)
  t.is(
    f.calls.some((entry) => entry[2] === 'middle' || entry[2] === 'exit'),
    false
  )
  f.cleanup()
})

test('candidate projection clears every earlier owned copy at all five allocation positions', async (t) => {
  for (let failurePosition = 1; failurePosition <= 5; failurePosition++) {
    const original = b4a.allocUnsafeSlow
    const owned = []
    let armed = false
    let sequence = 0
    let position = 0
    let f = null
    try {
      f = fixture({
        configuredCount: 1,
        onCapsQueryResponse() {
          armed = true
        }
      })
      const encodedSize = f.advertisements[0].bytes.byteLength
      const expectedSizes = [encodedSize, 32, 32, 19, 32]
      const snapshots = f.advertisements.map((entry) => b4a.from(entry.bytes))
      b4a.allocUnsafeSlow = (size) => {
        if (armed && position === 0 && size === expectedSizes[0]) {
          sequence++
          position = 1
        } else if (armed && position > 0 && size === expectedSizes[position]) {
          position++
        } else if (armed) {
          position = size === expectedSizes[0] ? 1 : 0
        }
        const target = sequence === 2 && position === failurePosition
        if (target) throw new Error(`candidate copy ${failurePosition}`)
        const value = original(size)
        if (sequence === 2 && position > 0 && position < failurePosition) owned.push(value)
        if (position === expectedSizes.length) position = 0
        return value
      }
      await expectCodeAsync(t, () => f.io.start(), 'ERR_PRIVATE_GUARD_UNAVAILABLE')
      t.is(owned.length, failurePosition - 1, `copy ${failurePosition} owns no partial suffix`)
      for (const value of owned) t.alike(value, b4a.alloc(value.byteLength))
      for (let index = 0; index < snapshots.length; index++) {
        t.alike(
          f.advertisements[index].bytes,
          snapshots[index],
          'caller advertisement is untouched'
        )
      }
    } finally {
      b4a.allocUnsafeSlow = original
      if (f) f.cleanup()
    }
  }
})

test('guard-pin publication clears every earlier owned copy at all three allocation positions', async (t) => {
  for (let failurePosition = 1; failurePosition <= 3; failurePosition++) {
    const original = b4a.allocUnsafeSlow
    const allocations = []
    let armed = false
    let position = 0
    let f = null
    try {
      f = fixture({
        configuredCount: 1,
        onlyGuardAdvertisement: true,
        onSinkMonotonic() {
          armed = true
        }
      })
      const sizes = [32, 19, 32]
      b4a.allocUnsafeSlow = (size) => {
        if (armed && size === sizes[position]) position++
        else if (armed) position = size === sizes[0] ? 1 : 0
        if (position === failurePosition) throw new Error(`published pin ${failurePosition}`)
        const value = original(size)
        if (armed && position > 0 && position < failurePosition) allocations.push(value)
        if (position === sizes.length) position = 0
        return value
      }
      await expectCodeAsync(t, () => f.io.start(), 'ERR_PRIVATE_GUARD_UNAVAILABLE')
      t.is(f.physicalDestroys, 1, `copy ${failurePosition} destroys the established link`)
      t.is(allocations.length, failurePosition - 1)
      for (const value of allocations) t.alike(value, b4a.alloc(value.byteLength))
    } finally {
      b4a.allocUnsafeSlow = original
      if (f) f.cleanup()
    }
  }
})

test('guard-pin consume clears sibling resources at all three pinned copy positions', async (t) => {
  for (let failurePosition = 1; failurePosition <= 3; failurePosition++) {
    const f = fixture({ configuredCount: 1, onlyGuardAdvertisement: true })
    const transfer = await f.io.start()
    const original = b4a.allocUnsafeSlow
    const allocations = []
    let count = 0
    b4a.allocUnsafeSlow = (size) => {
      if (++count === failurePosition) throw new Error(`pinned copy ${failurePosition}`)
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
    t.is(f.physicalDestroys, 1, `copy ${failurePosition} destroys the sibling lease`)
    t.is(allocations.length, failurePosition - 1)
    for (const value of allocations) t.alike(value, b4a.alloc(value.byteLength))
    expectCode(t, () => consumeBootstrapGuardPin(transfer), 'ERR_REPLAY')
  }
})

test('reentrant guard-pin revocation poisons an in-progress consume and publishes nothing', async (t) => {
  let transfer = null
  let reenter = false
  let revokeResult = null
  const f = fixture({
    onSinkWall() {
      if (!reenter) return
      reenter = false
      revokeResult = revokeBootstrapGuardPin(transfer)
    }
  })
  transfer = await f.io.start()
  reenter = true
  expectCode(t, () => consumeBootstrapGuardPin(transfer), 'ERR_REPLAY')
  t.is(revokeResult, true, 'reentrant revoke terminally poisons the transfer')
  t.is(f.physicalDestroys, 1, 'poison destroys the unpublished lease')
  expectCode(t, () => consumeBootstrapGuardPin(transfer), 'ERR_REPLAY')
  f.cleanup()
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
