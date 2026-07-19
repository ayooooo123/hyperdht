'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { PrivateRouteError } = require('../../lib/private/errors')
const {
  createIndexZeroGuardLinkResponder,
  destroyM3EstablishedLink
} = require('../../lib/private/guard-link')
const { CAPACITY_CLASS, ROLE, roleForIdentity } = require('../../lib/private/protocol')
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
  createGuardReconnectAuthority,
  revokeGuardReconnectAuthority
} = require('../../lib/private/guard-reconnect-authority')

const NOW = 1_000n
const RECONNECT_DEADLINE = 5_000n
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
  throw new Error('missing identity')
}

function endpointBytes(host, port) {
  return encodeCanonicalEndpoint({
    addressFamily: 4,
    addressBytes: b4a.from(host.split('.').map(Number)),
    port
  })
}

function signedGuard() {
  const signer = identityFor(ROLE.SAFETY, 20)
  const route = cryptoSuite.encryptionKeyPair(seed(121))
  const endpoint = endpointBytes('192.0.2.41', 49737)
  const signed = signRelayCapabilityAdvertisement(
    {
      relayIdentity: signer.publicKey,
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
      epoch: 1n,
      issuedAtMs: NOW,
      expiresAtMs: NOW + 20_000n,
      providerServicePolicyEntries: providerServicePolicyForCapabilities(1)
    },
    signer.secretKey
  )
  const advertisement = encodeRelayCapabilityAdvertisement(signed)
  return {
    advertisement,
    advertisementDigest: digestRelayCapabilityAdvertisement(advertisement, { now: NOW }),
    endpoint,
    signer,
    route
  }
}

function fakeClock() {
  let wall = NOW
  let monotonic = 0n
  let next = 0
  const timers = new Map()
  const clock = {
    onClearTimer: null,
    wallNow: () => wall,
    monotonicNow: () => monotonic,
    setTimer(callback, delay) {
      const id = ++next
      timers.set(id, { callback, delay })
      return id
    },
    clearTimer(id) {
      timers.delete(id)
      if (clock.onClearTimer) clock.onClearTimer(id)
    },
    advance(value) {
      wall += BigInt(value)
      monotonic += BigInt(value)
    },
    fire(id) {
      const timer = timers.get(id)
      timers.delete(id)
      timer.callback()
    },
    timers
  }
  return clock
}

function fixture(options = {}) {
  const clock = fakeClock()
  const guard = signedGuard()
  const local = identityFor(ROLE.SAFETY, 2)
  const calls = []
  let destroyed = false
  let responder = null
  let responderEstablished = null
  let linkEstablished = false
  let clientPhysicalDestroyed = false
  let cleanupReentryCount = 0
  let cleanupReentryResult = null
  let cleanupReentryError = null
  const capsResponder = createActiveChallengeResponderAuthority({
    now: clock.wallNow,
    setTimeout,
    clearTimeout,
    crypto: { ...cryptoSuite, randomBytes: (size) => b4a.alloc(size, 0x5d) }
  })
  let capsBinding = null
  let sourceEndpoint = null
  let authority = null
  const reenterCleanup = () => {
    cleanupReentryCount++
    try {
      cleanupReentryResult = revokeGuardReconnectAuthority(authority, 'cleanup-reentry')
    } catch (err) {
      cleanupReentryError = err
    }
  }
  clock.onClearTimer = () => {
    if (options.revokeAfterLinkAt === 'clearTimer' && linkEstablished) reenterCleanup()
  }
  const datagrams = {
    async send(host, port, request, signal) {
      if (destroyed) throw new Error('revoked transport')
      calls.push({ host, port, kind: request.kind, signal })
      if (options.onSend) await options.onSend({ host, port, request, signal, clock })
      if (request.kind === 'caps-query') {
        sourceEndpoint = endpointBytes('10.0.0.2', 44000)
        const query = {
          sourceEndpoint,
          requestedCapabilityMask: request.requestedCapabilityMask,
          randomTarget: request.randomTarget,
          queryNonce: request.queryNonce,
          maximumResults: request.maximumResults
        }
        const cookie = capsResponder.issueCookie(query)
        const response = Object.freeze({
          sourceEndpoint,
          cookieExpiresAtMs: cookie.cookieExpiresAtMs,
          returnRoutabilityCookie: cookie.returnRoutabilityCookie,
          advertisements: [b4a.from(guard.advertisement)]
        })
        return options.capsQueryResponse ? options.capsQueryResponse(response, guard) : response
      }
      if (request.kind === 'caps-retry') {
        capsBinding = capsResponder.admitCapsRetry({
          sourceEndpoint: request.sourceEndpoint,
          requestedCapabilityMask: request.requestedCapabilityMask,
          randomTarget: request.randomTarget,
          queryNonce: request.queryNonce,
          maximumResults: request.maximumResults,
          cookieExpiresAtMs: request.cookieExpiresAtMs,
          returnRoutabilityCookie: request.returnRoutabilityCookie,
          advertisement: request.advertisement
        })
        return Object.freeze({})
      }
      if (request.kind === 'active-challenge') {
        let bytes = capsResponder.respond(capsBinding, request.bytes, {
          sourceEndpoint,
          advertisement: guard.advertisement,
          identitySecretKey: guard.signer.secretKey,
          routeEncryptionSecretKey: guard.route.secretKey
        })
        if (options.forgeActiveChallenge) {
          bytes = b4a.from(bytes)
          bytes[bytes.byteLength - 1] ^= 1
        }
        if (options.expireActiveChallenge) clock.advance(5_001)
        if (options.revokeAtActiveChallenge) {
          revokeGuardReconnectAuthority(authority, 'reentrant-challenge')
        }
        return Object.freeze({
          bytes
        })
      }
      if (request.kind === 'link') {
        responder = createIndexZeroGuardLinkResponder({
          advertisement: guard.advertisement,
          responderIdentitySecretKey: guard.signer.secretKey,
          responderRouteEncryptionSecretKey: guard.route.secretKey,
          now: () => clock.wallNow(),
          receiveOffer: () => ({
            offer: request.bytes,
            observedPredecessorEndpoint: endpointBytes('10.0.0.2', 44000),
            physicalChannel: Object.freeze({ destroy() {} })
          }),
          randomBytes: (size) => b4a.alloc(size, 0x55)
        })
        const accepted = responder.accept()
        responderEstablished = accepted.established
        linkEstablished = true
        return {
          accept: accepted.accept,
          physicalChannel: Object.freeze({
            destroy() {
              clientPhysicalDestroyed = true
            }
          })
        }
      }
      throw new Error('unexpected request')
    },
    destroy() {
      destroyed = true
      if (options.revokeAfterLinkAt === 'datagram-destroy' && linkEstablished) {
        reenterCleanup()
      }
    }
  }
  authority = createGuardReconnectAuthority({
    guardIdentity: guard.signer.publicKey,
    guardEndpoint: guard.endpoint,
    advertisement: guard.advertisement,
    advertisementDigest: guard.advertisementDigest,
    epoch: 1n,
    expiresAt: NOW + 20_000n,
    localIdentity: local.publicKey,
    localSecretKey: local.secretKey,
    reconnectDatagrams: options.transportFactory
      ? function exactTupleReconnectFactory() {
          if (arguments.length !== 0) throw new Error('factory arguments exposed')
          options.transportFactory.calls++
          return datagrams
        }
      : datagrams,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer
  })
  return {
    authority,
    calls,
    clock,
    datagrams,
    guard,
    get destroyed() {
      return destroyed
    },
    get clientPhysicalDestroyed() {
      return clientPhysicalDestroyed
    },
    get cleanupReentryCount() {
      return cleanupReentryCount
    },
    get cleanupReentryResult() {
      return cleanupReentryResult
    },
    get cleanupReentryError() {
      return cleanupReentryError
    },
    cleanup(established = null) {
      capsResponder.destroy()
      if (established) destroyM3EstablishedLink(established)
      if (responderEstablished) destroyM3EstablishedLink(responderEstablished)
      if (responder) responder.destroy()
    }
  }
}

test('reconnect obtains its exact-tuple transport from a zero-argument one-shot factory', async (t) => {
  const transportFactory = { calls: 0 }
  const f = fixture({ transportFactory })
  t.is(transportFactory.calls, 0)
  const established = await f.authority.reconnect()
  t.ok(established)
  t.is(transportFactory.calls, 1)
  let error = null
  try {
    await f.authority.reconnect()
  } catch (err) {
    error = err
  }
  t.is(error && error.code, 'ERR_REPLAY')
  t.is(transportFactory.calls, 1)
  f.cleanup(established)
})

test('guard reconnect capability is opaque, zero-argument, and one-shot before first IO', async (t) => {
  const f = fixture()
  t.alike(Object.keys(require('../../lib/private/guard-reconnect-authority')).sort(), [
    'createGuardReconnectAuthority',
    'revokeGuardReconnectAuthority'
  ])
  t.alike(Object.keys(f.authority), ['reconnect'])
  t.is(f.authority.reconnect.length, 0)
  expectCode(t, () => f.authority.reconnect('192.0.2.99', 1), 'INVALID_ROUTE')
  t.is(f.calls.length, 0)
  const established = await f.authority.reconnect()
  t.alike(
    f.calls.map((call) => call.kind),
    ['caps-query', 'caps-retry', 'active-challenge', 'link']
  )
  for (const call of f.calls) {
    t.is(call.host, '192.0.2.41')
    t.is(call.port, 49737)
  }
  t.ok(f.destroyed)
  expectCode(t, () => f.authority.reconnect(), 'ERR_REPLAY')
  f.cleanup(established)
})

test('CAPS substitution and referral-shaped responses cannot alter the bound tuple', async (t) => {
  const f = fixture({
    capsQueryResponse(response) {
      return {
        ...response,
        referral: { host: '203.0.113.9', port: 1 }
      }
    }
  })
  await expectCodeAsync(t, () => f.authority.reconnect(), 'ERR_PRIVATE_GUARD_UNAVAILABLE')
  t.alike(
    f.calls.map((call) => [call.host, call.port, call.kind]),
    [['192.0.2.41', 49737, 'caps-query']]
  )
  t.ok(f.destroyed)
  f.cleanup()
})

test('reconnect active challenge rejects forgery, expiry, and revocation reentry', async (t) => {
  for (const [options, code] of [
    [{ forgeActiveChallenge: true }, 'ERR_PRIVATE_GUARD_UNAVAILABLE'],
    [{ expireActiveChallenge: true }, 'ERR_PRIVATE_GUARD_UNAVAILABLE'],
    [{ revokeAtActiveChallenge: true }, 'ERR_DESTROYED']
  ]) {
    const f = fixture(options)
    await expectCodeAsync(t, () => f.authority.reconnect(), code)
    t.is(
      f.calls.some((call) => call.kind === 'link'),
      false
    )
    t.ok(f.destroyed)
    f.cleanup()
  }
})

test('revoke before reconnect sends no packet and never restores READY', (t) => {
  const f = fixture()
  t.ok(revokeGuardReconnectAuthority(f.authority, 'network-change'))
  expectCode(t, () => f.authority.reconnect(), 'ERR_DESTROYED')
  expectCode(t, () => revokeGuardReconnectAuthority(f.authority, 'again'), 'ERR_REPLAY')
  t.is(f.calls.length, 0)
  t.ok(f.destroyed)
  f.cleanup()
})

test('revoke during flight aborts the exact operation and emits no later packet', async (t) => {
  let release = null
  const f = fixture({
    onSend() {
      return new Promise((resolve) => {
        release = resolve
      })
    }
  })
  const operation = f.authority.reconnect()
  while (release === null) await Promise.resolve()
  t.ok(revokeGuardReconnectAuthority(f.authority, 'network-change'))
  release()
  await expectCodeAsync(t, () => operation, 'ERR_DESTROYED')
  t.alike(
    f.calls.map((call) => call.kind),
    ['caps-query']
  )
  t.ok(f.calls[0].signal.aborted)
  f.cleanup()
})

test('reconnect uses one 5000ms timer and a spent authority cannot start a second operation', async (t) => {
  const f = fixture()
  t.is(RECONNECT_DEADLINE, 5_000n)
  t.is(f.clock.timers.size, 1, 'authority owns only its expiry timer before use')
  const operation = f.authority.reconnect()
  t.is(f.clock.timers.size, 1, 'expiry is replaced by the one operation deadline')
  expectCode(t, () => f.authority.reconnect(), 'ERR_REPLAY')
  const established = await operation
  t.is(f.clock.timers.size, 0)
  f.cleanup(established)
})

test('hung reconnect expires, aborts the exact in-flight record, and emits no later packet', async (t) => {
  let release = null
  const f = fixture({
    onSend() {
      return new Promise((resolve) => {
        release = resolve
      })
    }
  })
  const operation = f.authority.reconnect()
  while (release === null) await Promise.resolve()
  t.is(f.clock.timers.size, 1)
  f.clock.advance(5_000)
  for (const id of [...f.clock.timers.keys()]) f.clock.fire(id)
  await expectCodeAsync(t, () => operation, 'ERR_PRIVATE_GUARD_UNAVAILABLE')
  t.ok(f.calls[0].signal.aborted)
  release()
  await Promise.resolve()
  t.alike(
    f.calls.map((call) => call.kind),
    ['caps-query']
  )
  t.ok(f.destroyed)
  f.cleanup()
})

test('clearTimer cleanup reentry revokes before an established link can be published', async (t) => {
  const f = fixture({ revokeAfterLinkAt: 'clearTimer' })
  await expectCodeAsync(t, () => f.authority.reconnect(), 'ERR_DESTROYED')
  t.is(f.cleanupReentryCount, 1)
  t.is(f.cleanupReentryResult, true)
  t.is(f.cleanupReentryError, null)
  t.ok(f.clientPhysicalDestroyed)
  t.ok(f.destroyed)
  f.cleanup()
})

test('datagram destroy cleanup reentry revokes before an established link can be published', async (t) => {
  const f = fixture({ revokeAfterLinkAt: 'datagram-destroy' })
  await expectCodeAsync(t, () => f.authority.reconnect(), 'ERR_DESTROYED')
  t.is(f.cleanupReentryCount, 1)
  t.is(f.cleanupReentryResult, true)
  t.is(f.cleanupReentryError, null)
  t.ok(f.clientPhysicalDestroyed)
  t.ok(f.destroyed)
  f.cleanup()
})

test('in-flight reconnect copies are atomic after the public authority becomes spent', (t) => {
  for (let failurePosition = 1; failurePosition <= 6; failurePosition++) {
    const f = fixture()
    const original = b4a.allocUnsafeSlow
    const allocations = []
    let count = 0
    b4a.allocUnsafeSlow = (size) => {
      if (++count === failurePosition) throw new Error(`in-flight copy ${failurePosition}`)
      const value = original(size)
      allocations.push(value)
      return value
    }
    try {
      t.exception(() => f.authority.reconnect())
    } finally {
      b4a.allocUnsafeSlow = original
    }
    t.is(f.calls.length, 0)
    t.is(allocations.length, failurePosition - 1)
    for (const value of allocations) t.alike(value, b4a.alloc(value.byteLength))
    expectCode(t, () => f.authority.reconnect(), 'ERR_DESTROYED')
    f.cleanup()
  }
})
