'use strict'

const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-universal')

const publicApi = require('../..')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { PrivateRouteError } = require('../../lib/private/errors')
const {
  CAPACITY_CLASS,
  M3_MESSAGE_ID,
  RELAY_CAPABILITY,
  ROLE,
  encodeM3Object,
  roleForIdentity
} = require('../../lib/private/protocol')
const {
  ACTIVE_CHALLENGE_TIMEOUT,
  CAPABILITY_ADVERTISEMENT_FIXED_BODY,
  CAPABILITY_ADVERTISEMENT_MAX_BYTES,
  CAPABILITY_ADVERTISEMENT_MIN_BYTES,
  MAX_CAPABILITY_LIFETIME,
  RelayCapabilityVerifier,
  createActiveChallengeResponderAuthority,
  createActiveChallengeSendAuthority,
  decodeCanonicalEndpoint,
  decodeRelayCapabilityAdvertisement,
  deriveM3DhtNodeId,
  digestRelayCapabilityAdvertisement,
  encodeCanonicalEndpoint,
  encodeRelayCapabilityAdvertisement,
  providerServicePolicyForCapabilities,
  signRelayCapabilityAdvertisement
} = require('../../lib/private/relay-capability')

const NOW = 1_000_000n
const ADVERTISEMENT_VECTOR =
  '00000001000100bc8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39427cace6a03c83195acce043c5083da3e577f86c2370492dc4931a49586c4efde04000000000000000000000000c0000207c24960346e7c911a5f6ba154129174cafe75b294ac3bbd5549632f48cec6266f841000000001000000010000000104b0047a044d044c043100400020010000271000989680000001000000753000040000000000000000000700000000000f424000000000000fb7700000c575e4e054448ac98b1d4105e1184b20113379ae5bc414d477bcaf2d938e3da976ec8cb172b4f35850838d06f52bcce905634beeda9d15c1d2c6f61eb3f5b003'
const CAPS_COOKIE_VECTOR = '7d4c1f5fa85748b2fa7c377997bfc9cfd4a1a24c80c3fd87db71e207a62235e7'
const ACTIVE_CHALLENGE_VECTOR =
  '00000001000400b03e52c4d4e3ea2357cdb8cadebfb33ed7582a6d9a35904c921a0d681c9ea5455742424242424242424242424242424242424242424242424242424242424242421043ad34d3296c17cfe556e170452b6d896e52c4ed911f254711398e58476e2000000000000f55c8d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d300000000000f55c87d4c1f5fa85748b2fa7c377997bfc9cfd4a1a24c80c3fd87db71e207a62235e7'
const ACTIVE_RESPONSE_VECTOR =
  '00000001000501103e52c4d4e3ea2357cdb8cadebfb33ed7582a6d9a35904c921a0d681c9ea545578139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39442424242424242424242424242424242424242424242424242424242424242421043ad34d3296c17cfe556e170452b6d896e52c4ed911f254711398e58476e205d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d00000000000f55c8d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d300000000000f55c87d4c1f5fa85748b2fa7c377997bfc9cfd4a1a24c80c3fd87db71e207a62235e7e3e4dfdc0859f646e27a494fc796884dd737e50f0537c37d66ee12d528c5a3783f233220d8c0b9b873e648cc8ec4b214e5e872c492a5d377db649fbb215efac4a787c25b5303911c8cee4ddfc6832004a92c407e353bfdebcfd3c6fa0ab0790d'

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

function trackedRelayCapability(cryptoOverrides = null) {
  const modulePath = require.resolve('../../lib/private/relay-capability')
  const cryptoSuitePath = require.resolve('../../lib/private/crypto-suite')
  const cacheKey = (path) =>
    require.cache[path] === undefined
      ? Object.keys(require.cache).find((key) => key.endsWith(path))
      : path
  const moduleCacheKey = cacheKey(modulePath)
  const cryptoSuiteCacheKey = cacheKey(cryptoSuitePath)
  const cached = require.cache[moduleCacheKey]
  const cachedCryptoSuite = require.cache[cryptoSuiteCacheKey]
  const originalCryptoSuiteExports = cachedCryptoSuite.exports
  const BufferConstructor = b4a.alloc(0).constructor
  const originalB4a = b4a.allocUnsafeSlow
  const originalBuffer = BufferConstructor.allocUnsafeSlow
  const originalConcat = b4a.concat
  const allocations = []
  let tracking = false
  let failingSize = null
  let failingAllocation = null
  let allocationCount = 0
  let failAfterConcat = false
  const allocate = (size) => {
    if (tracking) allocationCount++
    if (tracking && allocationCount === failingAllocation) {
      failingAllocation = null
      throw new Error('injected allocation failure')
    }
    if (tracking && size === failingSize) {
      failingSize = null
      throw new Error('injected allocation failure')
    }
    const value = Reflect.apply(originalBuffer, BufferConstructor, [size])
    if (tracking) allocations.push(value)
    return value
  }
  const concatenate = (parts) => {
    const value = Reflect.apply(originalConcat, b4a, [parts])
    if (tracking) allocations.push(value)
    if (tracking && failAfterConcat) {
      failAfterConcat = false
      failingAllocation = allocationCount + 1
    }
    return value
  }
  b4a.allocUnsafeSlow = allocate
  BufferConstructor.allocUnsafeSlow = allocate
  b4a.concat = concatenate
  if (cryptoOverrides !== null) {
    cachedCryptoSuite.exports = {
      ...originalCryptoSuiteExports,
      cryptoSuite: Object.freeze({
        ...originalCryptoSuiteExports.cryptoSuite,
        ...cryptoOverrides
      })
    }
  }
  let fresh
  try {
    delete require.cache[moduleCacheKey]
    fresh = require(modulePath)
  } catch (err) {
    b4a.allocUnsafeSlow = originalB4a
    BufferConstructor.allocUnsafeSlow = originalBuffer
    throw err
  } finally {
    b4a.concat = originalConcat
    cachedCryptoSuite.exports = originalCryptoSuiteExports
    delete require.cache[moduleCacheKey]
    if (cached) require.cache[moduleCacheKey] = cached
  }
  let restored = false
  return {
    fresh,
    start() {
      allocations.length = 0
      failingSize = null
      failingAllocation = null
      allocationCount = 0
      failAfterConcat = false
      tracking = true
    },
    failAllocationAt(position) {
      failingAllocation = position
    },
    failNextAllocation() {
      failingAllocation = allocationCount + 1
    },
    failAllocationOfSize(size) {
      failingSize = size
    },
    failOutputAllocationAfterConcat() {
      failAfterConcat = true
    },
    take() {
      tracking = false
      failingSize = null
      failingAllocation = null
      allocationCount = 0
      failAfterConcat = false
      return allocations.splice(0)
    },
    restore() {
      if (restored) return
      restored = true
      tracking = false
      failingSize = null
      failingAllocation = null
      allocationCount = 0
      failAfterConcat = false
      b4a.allocUnsafeSlow = originalB4a
      BufferConstructor.allocUnsafeSlow = originalBuffer
    }
  }
}

function seed(value) {
  return b4a.alloc(32, value)
}

function identity(value) {
  return cryptoSuite.keyPair(seed(value))
}

function routeKey(value) {
  return cryptoSuite.encryptionKeyPair(seed(value))
}

function endpoint(last = 7, port = 49737) {
  return encodeCanonicalEndpoint({
    addressFamily: 4,
    addressBytes: b4a.from([192, 0, 2, last]),
    port
  })
}

function exactRoleIdentity(role) {
  for (let value = 1; value < 255; value++) {
    const pair = identity(value)
    if (roleForIdentity(pair.publicKey) === role) return pair
  }
  throw new Error('missing deterministic role fixture')
}

function advertisement(signer, route, overrides = {}) {
  const reachableEndpoint = endpoint()
  const capabilityMask = RELAY_CAPABILITY.CIRCUIT_RELAY_V1
  return {
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
    maxConcurrentCircuits: 32,
    capacityClass: CAPACITY_CLASS.MEDIUM,
    maxCellsPerCircuit: 10_000,
    maxBytesPerCircuit: 10_000_000,
    maxCommandsPerCircuit: 256,
    idleTimeoutMs: 30_000,
    maxQueuedBytes: 262_144,
    epoch: 7n,
    issuedAtMs: NOW,
    expiresAtMs: NOW + 30_000n,
    providerServicePolicyEntries: providerServicePolicyForCapabilities(capabilityMask),
    ...overrides
  }
}

function signedAdvertisement(overrides = {}) {
  const { routeSeed = 2, ...advertisementOverrides } = overrides
  const mask = advertisementOverrides.capabilityMask ?? RELAY_CAPABILITY.CIRCUIT_RELAY_V1
  const role = mask === 3 ? ROLE.PRIVATE : ROLE.SAFETY
  const signer = exactRoleIdentity(role)
  const route = routeKey(routeSeed)
  const value = advertisement(signer, route, advertisementOverrides)
  const signed = signRelayCapabilityAdvertisement(value, signer.secretKey)
  return {
    encoded: encodeRelayCapabilityAdvertisement(signed),
    route,
    signer,
    signed,
    value
  }
}

function clock(start = NOW) {
  let wall = start
  let monotonic = 0n
  let next = 0
  const timers = new Map()
  return {
    wallNow: () => wall,
    monotonicNow: () => monotonic,
    setTimer(callback, delay) {
      const id = ++next
      timers.set(id, { at: monotonic + BigInt(delay), callback })
      return id
    },
    clearTimer(id) {
      timers.delete(id)
    },
    advance(delay) {
      wall += BigInt(delay)
      monotonic += BigInt(delay)
      for (const [id, timer] of timers) {
        if (timer.at > monotonic) continue
        timers.delete(id)
        timer.callback()
      }
    },
    jumpWall(delay) {
      wall += BigInt(delay)
    },
    pending: () => timers.size
  }
}

function verifier(fake, onInvalidated = () => {}) {
  return new RelayCapabilityVerifier({
    wallNow: fake.wallNow,
    monotonicNow: fake.monotonicNow,
    setTimer: fake.setTimer,
    clearTimer: fake.clearTimer,
    onInvalidated
  })
}

function acceptSafety(owner, fixture) {
  return owner.accept(fixture.encoded, {
    expectedRole: ROLE.SAFETY,
    expectedCapabilityMask: RELAY_CAPABILITY.CIRCUIT_RELAY_V1
  })
}

function challengeAuthority(projection, send, overrides = {}) {
  return createActiveChallengeSendAuthority({
    capsBinding: {
      advertisement: projection,
      sourceEndpoint: endpoint(238),
      queryNonce: seed(206),
      cookieExpiresAtMs: NOW + ACTIVE_CHALLENGE_TIMEOUT,
      returnRoutabilityCookie: seed(205),
      advertisementDigest: projection.digest,
      relayIdentity: projection.identity,
      ...overrides
    },
    send
  })
}

test('M3 relay advertisement is canonical, signed, exact-sized, and defensively copied', (t) => {
  const fixture = signedAdvertisement()
  t.is(CAPABILITY_ADVERTISEMENT_FIXED_BODY, 188)
  t.is(CAPABILITY_ADVERTISEMENT_MIN_BYTES, 260)
  t.is(CAPABILITY_ADVERTISEMENT_MAX_BYTES, 388)
  t.is(fixture.encoded.byteLength, 260)
  t.is(fixture.encoded.readUInt32BE(0), 1)
  t.is(fixture.encoded.readUInt16BE(4), M3_MESSAGE_ID.CAPABILITY_ADVERTISEMENT_V1)
  t.is(fixture.encoded.readUInt16BE(6), 188)
  t.is(
    b4a.toString(fixture.value.reachableEndpoint, 'hex'),
    '04000000000000000000000000c0000207c249'
  )
  t.is(roleForIdentity(fixture.signer.publicKey), ROLE.SAFETY)
  t.is(b4a.toString(fixture.encoded, 'hex'), ADVERTISEMENT_VECTOR)

  const decoded = decodeRelayCapabilityAdvertisement(fixture.encoded, { now: NOW + 1n })
  t.alike(decoded.relayIdentity, fixture.value.relayIdentity)
  t.alike(decoded.reachableEndpoint, fixture.value.reachableEndpoint)
  t.alike(decoded.providerServicePolicyEntries, [])

  fixture.encoded.fill(0)
  fixture.value.relayIdentity.fill(0)
  t.absent(b4a.equals(decoded.relayIdentity, b4a.alloc(32)))
  t.absent(b4a.equals(decoded.reachableEndpoint, b4a.alloc(19)))
})

test('M3 DHT node identity uses IPv4 octets and little-endian port exactly', (t) => {
  const reachableEndpoint = endpoint(9, 0x1234)
  const expected = b4a.alloc(32)
  sodium.crypto_generichash(expected, b4a.from([192, 0, 2, 9, 0x34, 0x12]))
  t.alike(deriveM3DhtNodeId(reachableEndpoint), expected)
  t.alike(decodeCanonicalEndpoint(reachableEndpoint), reachableEndpoint)
})

test('provider policy is the exact capability-derived 0/4/5/9 tuple set', (t) => {
  const safety = providerServicePolicyForCapabilities(1)
  const dht = providerServicePolicyForCapabilities(3)
  const privateRecords = providerServicePolicyForCapabilities(4)
  const relayAndPrivateRecords = providerServicePolicyForCapabilities(5)
  const all = providerServicePolicyForCapabilities(7)
  t.is(safety.length, 0)
  t.alike(
    dht.map((entry) => entry.commandId),
    [0x0120, 0x0121, 0x0122, 0x0123]
  )
  t.alike(
    privateRecords.map((entry) => entry.commandId),
    [0x0200, 0x02a0, 0x02a1, 0x02a2, 0x02a3]
  )
  t.alike(relayAndPrivateRecords, privateRecords)
  t.alike(
    all.map((entry) => entry.commandId),
    [0x0120, 0x0121, 0x0122, 0x0123, 0x0200, 0x02a0, 0x02a1, 0x02a2, 0x02a3]
  )
  t.ok(Object.isFrozen(safety))
  t.ok(Object.isFrozen(dht))
  t.ok(dht.every(Object.isFrozen))
  const exit = signedAdvertisement({
    capabilityMask: 3,
    providerServicePolicyEntries: dht
  })
  t.is(roleForIdentity(exit.signer.publicKey), ROLE.PRIVATE)
  for (const mask of [0, 2, 6, 8]) {
    expectCode(t, () => providerServicePolicyForCapabilities(mask), 'ERR_INCOMPATIBLE_RELAY')
  }

  const fixture = exit
  t.is(fixture.encoded.byteLength, 388)
  t.is(fixture.encoded.readUInt16BE(6), 188 + 4 * 32)
  t.is(decodeRelayCapabilityAdvertisement(fixture.encoded, { now: NOW }).capabilityMask, 3)
})

test('advertisement validation rejects time, signature, role, capability, policy, and endpoint mismatches', (t) => {
  const fixture = signedAdvertisement()
  const forged = b4a.from(fixture.encoded)
  forged[20] ^= 1
  expectCode(
    t,
    () => decodeRelayCapabilityAdvertisement(forged, { now: NOW }),
    'ERR_AUTHENTICATION'
  )
  expectCode(
    t,
    () => decodeRelayCapabilityAdvertisement(fixture.encoded, { now: NOW + 30_000n }),
    'ERR_INCOMPATIBLE_RELAY'
  )
  t.ok(decodeRelayCapabilityAdvertisement(fixture.encoded, { now: NOW - 30_000n }))
  expectCode(
    t,
    () => decodeRelayCapabilityAdvertisement(fixture.encoded, { now: NOW - 30_001n }),
    'ERR_INCOMPATIBLE_RELAY'
  )

  for (const overrides of [
    { expiresAtMs: NOW + MAX_CAPABILITY_LIFETIME + 1n },
    { issuedAtMs: NOW + 1n, expiresAtMs: NOW },
    { cellSize: 1199 },
    { currentDhtNodeId: seed(99) },
    { capabilityMask: 2, providerServicePolicyEntries: [] },
    { capabilityMask: 3, providerServicePolicyEntries: [] },
    { capabilityMask: 4, providerServicePolicyEntries: providerServicePolicyForCapabilities(4) },
    { capabilityMask: 5, providerServicePolicyEntries: providerServicePolicyForCapabilities(5) },
    { capabilityMask: 7, providerServicePolicyEntries: providerServicePolicyForCapabilities(7) }
  ]) {
    expectCode(t, () => signedAdvertisement(overrides), 'ERR_INCOMPATIBLE_RELAY')
  }

  const wrongRole = exactRoleIdentity(ROLE.PRIVATE)
  const route = routeKey(8)
  expectCode(
    t,
    () =>
      encodeRelayCapabilityAdvertisement(
        signRelayCapabilityAdvertisement(advertisement(wrongRole, route), wrongRole.secretKey)
      ),
    'ERR_INCOMPATIBLE_RELAY'
  )

  const ipv6 = encodeCanonicalEndpoint({
    addressFamily: 6,
    addressBytes: b4a.from('20010db8000000000000000000000001', 'hex'),
    port: 49737
  })
  expectCode(
    t,
    () =>
      signedAdvertisement({
        reachableEndpoint: ipv6,
        currentDhtNodeId: seed(1)
      }),
    'ERR_INCOMPATIBLE_RELAY'
  )
  for (const bad of [
    { addressFamily: 4, addressBytes: b4a.from([127, 0, 0, 1]), port: 1, hostname: 'x' },
    Object.create({ addressFamily: 4 }),
    Object.defineProperty({ addressBytes: b4a.alloc(4), port: 1 }, 'addressFamily', {
      get() {
        return 4
      }
    })
  ]) {
    expectCode(t, () => encodeCanonicalEndpoint(bad), 'ERR_INCOMPATIBLE_RELAY')
  }
})

test('advertisement digest is exact and unavailable before canonical signature validation', (t) => {
  const fixture = signedAdvertisement()
  const digest = digestRelayCapabilityAdvertisement(fixture.encoded, { now: NOW })
  t.is(
    b4a.toString(digest, 'hex'),
    '3e52c4d4e3ea2357cdb8cadebfb33ed7582a6d9a35904c921a0d681c9ea54557'
  )
  const forged = b4a.from(fixture.encoded)
  forged[20] ^= 1
  expectCode(
    t,
    () => digestRelayCapabilityAdvertisement(forged, { now: NOW }),
    'ERR_AUTHENTICATION'
  )
})

test('relay advertisement inputs require exact own data properties and never alias', (t) => {
  const fixture = signedAdvertisement()
  const withUnknown = { ...fixture.value, unknown: true }
  const inherited = Object.create({ relayIdentity: fixture.value.relayIdentity })
  Object.assign(inherited, fixture.value)
  delete inherited.relayIdentity
  const inheritedUnknown = Object.assign(Object.create({ unknown: true }), fixture.value)
  const accessor = { ...fixture.value }
  Object.defineProperty(accessor, 'epoch', { get: () => 7n })
  for (const value of [withUnknown, inherited, inheritedUnknown, accessor]) {
    expectCode(
      t,
      () => signRelayCapabilityAdvertisement(value, fixture.signer.secretKey),
      'ERR_INCOMPATIBLE_RELAY'
    )
  }

  const signed = signRelayCapabilityAdvertisement(fixture.value, fixture.signer.secretKey)
  const expected = b4a.from(signed.relayIdentity)
  fixture.value.relayIdentity.fill(0)
  t.alike(signed.relayIdentity, expected)
})

test('advertisement signing clears normalized ownership on late setup failures', (t) => {
  const tracked = trackedRelayCapability()
  t.teardown(tracked.restore)
  const signer = exactRoleIdentity(ROLE.SAFETY)
  const route = routeKey(92)
  const value = advertisement(signer, route)
  const invalidSecret = b4a.alloc(63, 0xa7)
  const callerBuffers = [
    value.relayIdentity,
    value.currentDhtNodeId,
    value.reachableEndpoint,
    value.routeEncryptionPublicKey,
    invalidSecret,
    signer.secretKey
  ]
  const snapshots = callerBuffers.map((buffer) => b4a.from(buffer))

  tracked.start()
  expectCode(
    t,
    () => tracked.fresh.signRelayCapabilityAdvertisement(value, invalidSecret),
    'ERR_INCOMPATIBLE_RELAY'
  )
  const invalidSecretAllocations = tracked.take()
  t.ok(invalidSecretAllocations.length > 4, 'normalization and body allocation completed')
  for (const buffer of invalidSecretAllocations) t.alike(buffer, b4a.alloc(buffer.byteLength))

  tracked.start()
  tracked.failAllocationOfSize(252)
  expectCode(
    t,
    () => tracked.fresh.signRelayCapabilityAdvertisement(value, signer.secretKey),
    'ERR_AUTHENTICATION'
  )
  const signatureInputAllocations = tracked.take()
  t.ok(signatureInputAllocations.length > 5, 'normalization, body, and secret were allocated')
  for (const buffer of signatureInputAllocations) t.alike(buffer, b4a.alloc(buffer.byteLength))

  for (let index = 0; index < callerBuffers.length; index++) {
    t.alike(callerBuffers[index], snapshots[index], 'caller-owned signing input is unchanged')
  }
})

test('advertisement hash and signature adapters clear raw crypto temporaries', (t) => {
  const hashOutputs = []
  const signatureOutputs = []
  let failHashCopy = false
  let failSignatureCopy = false
  let tracked = null
  tracked = trackedRelayCapability({
    hash(parts) {
      const output = cryptoSuite.hash(parts)
      hashOutputs.push(output)
      if (failHashCopy) tracked.failNextAllocation()
      return output
    },
    sign(message, secretKey) {
      const output = cryptoSuite.sign(message, secretKey)
      signatureOutputs.push(output)
      if (failSignatureCopy) tracked.failNextAllocation()
      return output
    }
  })
  t.teardown(tracked.restore)
  const fixture = signedAdvertisement({ routeSeed: 97 })
  const callerBuffers = [
    fixture.encoded,
    fixture.value.relayIdentity,
    fixture.value.currentDhtNodeId,
    fixture.value.reachableEndpoint,
    fixture.value.routeEncryptionPublicKey,
    fixture.signer.secretKey
  ]
  const snapshots = callerBuffers.map((buffer) => b4a.from(buffer))

  const signed = tracked.fresh.signRelayCapabilityAdvertisement(
    fixture.value,
    fixture.signer.secretKey
  )
  t.is(signatureOutputs.length, 1)
  t.alike(signatureOutputs.shift(), b4a.alloc(64), 'successful signing clears raw signature')
  t.unlike(signed.signature, b4a.alloc(64), 'returned signature retains transferred ownership')

  const advertisementDigest = tracked.fresh.digestRelayCapabilityAdvertisement(fixture.encoded, {
    now: NOW
  })
  t.is(hashOutputs.length, 1)
  t.alike(hashOutputs.shift(), b4a.alloc(32), 'successful digest clears raw hash output')
  t.unlike(advertisementDigest, b4a.alloc(32), 'returned digest retains copied ownership')

  tracked.start()
  failHashCopy = true
  let hashError = null
  try {
    tracked.fresh.digestRelayCapabilityAdvertisement(fixture.encoded, { now: NOW })
  } catch (err) {
    hashError = err
  }
  failHashCopy = false
  const failedHashOwnership = tracked.take()
  t.ok(hashError instanceof Error)
  t.is(hashOutputs.length, 1)
  t.alike(hashOutputs.shift(), b4a.alloc(32), 'digest copy failure clears raw hash output')
  for (const output of failedHashOwnership) {
    t.alike(output, b4a.alloc(output.byteLength), 'digest copy failure clears owned buffers')
  }

  tracked.start()
  failSignatureCopy = true
  expectCode(
    t,
    () => tracked.fresh.signRelayCapabilityAdvertisement(fixture.value, fixture.signer.secretKey),
    'ERR_AUTHENTICATION'
  )
  failSignatureCopy = false
  const failedSignatureOwnership = tracked.take()
  t.is(signatureOutputs.length, 1)
  t.alike(
    signatureOutputs.shift(),
    b4a.alloc(64),
    'signature copy failure clears raw signature output'
  )
  for (const output of failedSignatureOwnership) {
    t.alike(output, b4a.alloc(output.byteLength), 'signature copy failure clears owned buffers')
  }

  for (let index = 0; index < callerBuffers.length; index++) {
    t.alike(callerBuffers[index], snapshots[index], 'crypto adapter leaves caller bytes untouched')
  }
})

test('verifier owns epochs, idempotence, equivocation quarantine, and projections', (t) => {
  const fake = clock()
  const owner = verifier(fake)
  const first = signedAdvertisement()
  const projection = acceptSafety(owner, first)
  t.ok(Object.isFrozen(projection))
  t.alike(projection.canonicalBytes, first.encoded)
  t.alike(projection.digest, digestRelayCapabilityAdvertisement(first.encoded, { now: NOW }))
  t.is(projection.role, ROLE.SAFETY)
  t.is(projection.capabilityMask, 1)
  t.is(projection.epoch, 7n)

  const identical = acceptSafety(owner, first)
  t.alike(identical.digest, projection.digest)
  t.is(identical === projection, false)

  first.encoded.fill(0)
  t.absent(b4a.equals(projection.canonicalBytes, b4a.alloc(projection.canonicalBytes.byteLength)))

  expectCode(t, () => acceptSafety(owner, signedAdvertisement({ epoch: 6n })), 'ERR_REPLAY')
  const conflicting = signedAdvertisement({ maxQueuedBytes: 262_145, routeSeed: 3 })
  expectCode(t, () => acceptSafety(owner, conflicting), 'ERR_AUTHENTICATION')
  const original = signedAdvertisement()
  expectCode(t, () => acceptSafety(owner, original), 'ERR_AUTHENTICATION')
  owner.destroy()
})

test('projection copy failures clear partial ownership without publishing state', (t) => {
  const tracked = trackedRelayCapability()
  t.teardown(tracked.restore)
  const fixture = signedAdvertisement({ routeSeed: 95, expiresAtMs: NOW + 60_000n })
  const callerSnapshot = b4a.from(fixture.encoded)
  const createOwner = (fake, onInvalidated = () => {}) =>
    new tracked.fresh.RelayCapabilityVerifier({
      wallNow: fake.wallNow,
      monotonicNow: fake.monotonicNow,
      setTimer: fake.setTimer,
      clearTimer: fake.clearTimer,
      onInvalidated
    })

  const profileClock = clock()
  const profileOwner = createOwner(profileClock)
  acceptSafety(profileOwner, fixture)
  tracked.start()
  const profiledProjection = acceptSafety(profileOwner, fixture)
  const profiledAllocations = tracked.take()
  const projectionBuffers = [
    profiledProjection.canonicalBytes,
    profiledProjection.digest,
    profiledProjection.identity,
    profiledProjection.canonicalEndpointBytes,
    profiledProjection.routePublicKey
  ]
  const projectionAllocationPositions = projectionBuffers.map(
    (buffer) => profiledAllocations.indexOf(buffer) + 1
  )
  t.ok(projectionAllocationPositions.every((position) => position > 0))
  for (let index = 1; index < projectionAllocationPositions.length; index++) {
    t.is(
      projectionAllocationPositions[index],
      projectionAllocationPositions[index - 1] + 1,
      'projection copies are the expected sequential allocation boundary'
    )
  }
  profileOwner.destroy()

  for (let copyPosition = 2; copyPosition <= 5; copyPosition++) {
    const fake = clock()
    let invalidations = 0
    const owner = createOwner(fake, () => invalidations++)
    const source = acceptSafety(owner, fixture)
    const sourceBuffers = [
      source.canonicalBytes,
      source.digest,
      source.identity,
      source.canonicalEndpointBytes,
      source.routePublicKey
    ]
    const sourceSnapshots = sourceBuffers.map((buffer) => b4a.from(buffer))

    tracked.start()
    tracked.failAllocationAt(projectionAllocationPositions[copyPosition - 1])
    expectCode(t, () => acceptSafety(owner, fixture), 'ERR_AUTHENTICATION')
    const failedAllocations = tracked.take()
    t.ok(failedAllocations.length > 0, `copy ${copyPosition} fails after owned allocation`)
    for (const buffer of failedAllocations) {
      t.alike(buffer, b4a.alloc(buffer.byteLength), `copy ${copyPosition} clears owned bytes`)
    }
    for (let index = 0; index < sourceBuffers.length; index++) {
      t.alike(
        sourceBuffers[index],
        sourceSnapshots[index],
        `copy ${copyPosition} leaves source state untouched`
      )
    }
    t.is(fake.pending(), 1, `copy ${copyPosition} publishes no timer or replacement record`)
    t.is(invalidations, 0, `copy ${copyPosition} does not invalidate the verifier`)
    t.alike(fixture.encoded, callerSnapshot, `copy ${copyPosition} leaves caller bytes untouched`)

    const retry = acceptSafety(owner, fixture)
    t.alike(retry.digest, source.digest, `copy ${copyPosition} leaves the live record selectable`)
    t.is(fake.pending(), 1, `copy ${copyPosition} publishes no hidden record on retry`)
    owner.destroy()
    t.is(fake.pending(), 0)
  }
})

test('verifier accept publishes nothing when expiry timer setup reenters and throws', (t) => {
  const tracked = trackedRelayCapability()
  t.teardown(tracked.restore)
  const fixture = signedAdvertisement({ routeSeed: 93, expiresAtMs: NOW + 60_000n })
  const encodedSnapshot = b4a.from(fixture.encoded)
  const timers = new Map()
  let nextTimer = 0
  let armed = true
  let invalidations = 0
  let owner = null
  let reentrantProjection = null
  let reentrantError = null
  const setTimer = (callback, delay) => {
    if (armed) {
      armed = false
      callback()
      try {
        reentrantProjection = acceptSafety(owner, fixture)
      } catch (err) {
        reentrantError = err
      }
      throw new Error('injected timer setup failure')
    }
    const timer = ++nextTimer
    timers.set(timer, { callback, delay })
    return timer
  }
  owner = new tracked.fresh.RelayCapabilityVerifier({
    wallNow: () => NOW,
    monotonicNow: () => 0n,
    setTimer,
    clearTimer(timer) {
      timers.delete(timer)
    },
    onInvalidated() {
      invalidations++
    }
  })

  tracked.start()
  expectCode(t, () => acceptSafety(owner, fixture), 'ERR_AUTHENTICATION')
  const failedAllocations = tracked.take()
  t.is(reentrantProjection, null, 'timer reentry cannot observe a selectable candidate')
  t.ok(reentrantError instanceof PrivateRouteError)
  t.is(reentrantError && reentrantError.code, 'ERR_AUTHENTICATION')
  t.is(timers.size, 0, 'failed acceptance retains no timer handle')
  t.is(invalidations, 0, 'timer setup failure does not invalidate the verifier')
  for (const buffer of failedAllocations) t.alike(buffer, b4a.alloc(buffer.byteLength))
  t.alike(fixture.encoded, encodedSnapshot, 'caller advertisement bytes are unchanged')

  const projection = acceptSafety(owner, fixture)
  t.is(projection.epoch, fixture.signed.epoch)
  t.is(timers.size, 1, 'retry installs the first live advertisement expiry timer')
  t.is(invalidations, 0)
  owner.destroy()
  t.is(timers.size, 0)
})

test('same-epoch equivocation stays revoked and quarantined when timer cleanup reenters and throws', (t) => {
  const fixture = signedAdvertisement({ routeSeed: 98, expiresAtMs: NOW + 60_000n })
  const conflict = signedAdvertisement({
    routeSeed: 99,
    maxQueuedBytes: 262_145,
    expiresAtMs: NOW + 60_000n
  })
  const fixtureSnapshot = b4a.from(fixture.encoded)
  const conflictSnapshot = b4a.from(conflict.encoded)
  const timers = new Map()
  let nextTimer = 0
  let clearCalls = 0
  let invalidations = 0
  let owner = null
  let reentrantProjection = null
  let reentrantError = null
  owner = new RelayCapabilityVerifier({
    wallNow: () => NOW,
    monotonicNow: () => 0n,
    setTimer(callback, delay) {
      const timer = ++nextTimer
      timers.set(timer, { callback, delay })
      return timer
    },
    clearTimer(timer) {
      clearCalls++
      if (clearCalls === 1) {
        try {
          reentrantProjection = acceptSafety(owner, fixture)
        } catch (err) {
          reentrantError = err
        }
        timers.delete(timer)
        throw new Error('injected clearTimer failure')
      }
      timers.delete(timer)
    },
    onInvalidated() {
      invalidations++
    }
  })
  const projection = acceptSafety(owner, fixture)
  const sensitive = [
    projection.canonicalBytes,
    projection.digest,
    projection.identity,
    projection.canonicalEndpointBytes,
    projection.routePublicKey
  ]

  expectCode(t, () => acceptSafety(owner, conflict), 'ERR_AUTHENTICATION')
  t.is(reentrantProjection, null, 'timer cleanup reentry observes no selectable record')
  t.ok(reentrantError instanceof PrivateRouteError)
  t.is(reentrantError && reentrantError.code, 'ERR_AUTHENTICATION')
  for (const buffer of sensitive) t.alike(buffer, b4a.alloc(buffer.byteLength))
  t.is(timers.size, 0, 'throwing cleanup leaves no live timer in the injected scheduler')
  t.is(invalidations, 0, 'equivocation quarantine does not invalidate the verifier')
  expectCode(t, () => acceptSafety(owner, fixture), 'ERR_AUTHENTICATION')
  expectCode(
    t,
    () =>
      createActiveChallengeSendAuthority({
        capsBinding: {
          advertisement: projection,
          sourceEndpoint: endpoint(225),
          queryNonce: seed(146),
          cookieExpiresAtMs: NOW + ACTIVE_CHALLENGE_TIMEOUT,
          returnRoutabilityCookie: seed(147),
          advertisementDigest: projection.digest,
          relayIdentity: projection.identity
        },
        send() {
          throw new Error('revoked projection must not send')
        }
      }),
    'ERR_AUTHENTICATION'
  )
  t.alike(fixture.encoded, fixtureSnapshot)
  t.alike(conflict.encoded, conflictSnapshot)
  owner.destroy()
})

test('newer relay epochs replace prior state when timer cleanup reenters and throws', (t) => {
  const fixture = signedAdvertisement({ routeSeed: 100, expiresAtMs: NOW + 60_000n })
  const newer = signedAdvertisement({
    epoch: fixture.signed.epoch + 1n,
    routeSeed: 101,
    expiresAtMs: NOW + 60_000n
  })
  const timers = new Map()
  let nextTimer = 0
  let clearCalls = 0
  let owner = null
  let reentrantProjection = null
  let reentrantError = null
  owner = new RelayCapabilityVerifier({
    wallNow: () => NOW,
    monotonicNow: () => 0n,
    setTimer(callback, delay) {
      const timer = ++nextTimer
      timers.set(timer, { callback, delay })
      return timer
    },
    clearTimer(timer) {
      clearCalls++
      timers.delete(timer)
      if (clearCalls !== 1) return
      try {
        reentrantProjection = acceptSafety(owner, fixture)
      } catch (err) {
        reentrantError = err
      }
      throw new Error('injected prior timer cleanup failure')
    },
    onInvalidated() {}
  })
  const prior = acceptSafety(owner, fixture)
  const sensitive = [
    prior.canonicalBytes,
    prior.digest,
    prior.identity,
    prior.canonicalEndpointBytes,
    prior.routePublicKey
  ]

  const replacement = acceptSafety(owner, newer)
  t.is(replacement.epoch, newer.signed.epoch)
  t.is(reentrantProjection, null, 'timer cleanup reentry cannot select the prior epoch')
  t.ok(reentrantError instanceof PrivateRouteError)
  t.is(reentrantError && reentrantError.code, 'ERR_AUTHENTICATION')
  for (const buffer of sensitive) t.alike(buffer, b4a.alloc(buffer.byteLength))
  t.is(timers.size, 1, 'only the replacement expiry timer remains live')
  expectCode(
    t,
    () =>
      createActiveChallengeSendAuthority({
        capsBinding: {
          advertisement: prior,
          sourceEndpoint: endpoint(226),
          queryNonce: seed(148),
          cookieExpiresAtMs: NOW + ACTIVE_CHALLENGE_TIMEOUT,
          returnRoutabilityCookie: seed(149),
          advertisementDigest: prior.digest,
          relayIdentity: prior.identity
        },
        send() {
          throw new Error('replaced projection must not send')
        }
      }),
    'ERR_AUTHENTICATION'
  )
  owner.destroy()
  t.is(timers.size, 0)
})

test('verifier clears a timer handle whose callback fires during accept publication', (t) => {
  const tracked = trackedRelayCapability()
  t.teardown(tracked.restore)
  const fixture = signedAdvertisement({ routeSeed: 94, expiresAtMs: NOW + 60_000n })
  const encodedSnapshot = b4a.from(fixture.encoded)
  const timers = new Set()
  let fireSynchronously = true
  let invalidations = 0
  const owner = new tracked.fresh.RelayCapabilityVerifier({
    wallNow: () => NOW,
    monotonicNow: () => 0n,
    setTimer(callback) {
      const timer = {
        unref() {
          if (!fireSynchronously) return
          fireSynchronously = false
          callback()
        }
      }
      timers.add(timer)
      return timer
    },
    clearTimer(timer) {
      timers.delete(timer)
    },
    onInvalidated() {
      invalidations++
    }
  })

  tracked.start()
  expectCode(t, () => acceptSafety(owner, fixture), 'ERR_INCOMPATIBLE_RELAY')
  const failedAllocations = tracked.take()
  t.is(timers.size, 0, 'synchronously fired handle is cancelled before rollback')
  t.is(invalidations, 0)
  for (const buffer of failedAllocations) t.alike(buffer, b4a.alloc(buffer.byteLength))
  t.alike(fixture.encoded, encodedSnapshot, 'caller advertisement bytes are unchanged')

  const projection = acceptSafety(owner, fixture)
  t.is(projection.epoch, fixture.signed.epoch)
  t.is(timers.size, 1, 'retry remains a first acceptance with one live timer')
  owner.destroy()
  t.is(timers.size, 0)
})

test('verifier poisons rather than evicting a seventeenth route key', (t) => {
  const fake = clock()
  const owner = verifier(fake)
  acceptSafety(owner, signedAdvertisement({ expiresAtMs: NOW + 100n }))
  for (let index = 1; index < 17; index++) {
    fake.advance(101)
    expectCode(
      t,
      () =>
        acceptSafety(
          owner,
          signedAdvertisement({
            routeSeed: 20 + index,
            maxQueuedBytes: 262_144 + index,
            issuedAtMs: fake.wallNow(),
            expiresAtMs: fake.wallNow() + 100n
          })
        ),
      'ERR_AUTHENTICATION'
    )
  }
  fake.advance(101)
  expectCode(
    t,
    () =>
      acceptSafety(
        owner,
        signedAdvertisement({
          epoch: 8n,
          routeSeed: 200,
          issuedAtMs: fake.wallNow(),
          expiresAtMs: fake.wallNow() + 100n
        })
      ),
    'ERR_AUTHENTICATION'
  )
  owner.destroy()
})

test('seventeenth route key poison atomically revokes live selection and challenge state', async (t) => {
  const fake = clock()
  const owner = verifier(fake)
  let projection = acceptSafety(
    owner,
    signedAdvertisement({ expiresAtMs: NOW + 60_000n, routeSeed: 30 })
  )
  for (let index = 1; index < 16; index++) {
    projection = acceptSafety(
      owner,
      signedAdvertisement({
        epoch: 7n + BigInt(index),
        routeSeed: 30 + index,
        maxQueuedBytes: 262_144 + index,
        expiresAtMs: NOW + 60_000n
      })
    )
  }
  const canonicalBytes = projection.canonicalBytes
  const digest = projection.digest
  const routePublicKey = projection.routePublicKey
  let sentChallenge = null
  const inFlightAuthority = challengeAuthority(projection, (challenge) => {
    sentChallenge = challenge
    return new Promise(() => {})
  })
  const unusedAuthority = challengeAuthority(projection, () => {
    throw new Error('poisoned authority must not perform IO')
  })
  let settled = false
  let code = null
  const pending = owner.beginChallenge(projection, inFlightAuthority).catch((err) => {
    settled = true
    code = err && err.code
  })
  await Promise.resolve()
  expectCode(
    t,
    () =>
      acceptSafety(
        owner,
        signedAdvertisement({
          epoch: 23n,
          routeSeed: 99,
          maxQueuedBytes: 262_199,
          expiresAtMs: NOW + 60_000n
        })
      ),
    'ERR_AUTHENTICATION'
  )
  t.alike(sentChallenge, b4a.alloc(sentChallenge.byteLength), 'poison clears IO bytes atomically')
  for (let index = 0; index < 4; index++) await Promise.resolve()
  t.ok(settled, 'poison rejects the in-flight challenge immediately')
  t.is(code, 'ERR_AUTHENTICATION')
  t.alike(canonicalBytes, b4a.alloc(canonicalBytes.byteLength))
  t.alike(digest, b4a.alloc(32))
  t.alike(routePublicKey, b4a.alloc(32))
  t.alike(sentChallenge, b4a.alloc(sentChallenge.byteLength))
  t.is(fake.pending(), 0, 'poison cancels record and challenge timers')
  await expectCodeAsync(
    t,
    () => owner.beginChallenge(projection, unusedAuthority),
    'ERR_AUTHENTICATION'
  )
  await pending
  owner.destroy()
})

test('verifier invalidates atomically on clock rollback and forward expiry', async (t) => {
  const fake = clock()
  let invalidations = 0
  let leakedArguments = null
  const owner = verifier(fake, (...args) => {
    invalidations++
    leakedArguments = args
  })
  const fixture = signedAdvertisement({ expiresAtMs: NOW + 60_000n })
  const projection = acceptSafety(owner, fixture)
  const rollbackAuthority = challengeAuthority(projection, async () => b4a.alloc(344))
  fake.jumpWall(-30_001)
  await expectCodeAsync(
    t,
    () => owner.beginChallenge(projection, rollbackAuthority),
    'ERR_INCOMPATIBLE_RELAY'
  )
  t.is(invalidations, 1)
  t.alike(leakedArguments, [])
  expectCode(t, () => acceptSafety(owner, fixture), 'ERR_INCOMPATIBLE_RELAY')
  t.is(invalidations, 1)
  owner.destroy()

  const nextClock = clock()
  const next = verifier(nextClock)
  const nextProjection = acceptSafety(next, fixture)
  const expiredAuthority = challengeAuthority(nextProjection, async () => b4a.alloc(344))
  nextClock.jumpWall(60_000)
  await expectCodeAsync(
    t,
    () => next.beginChallenge(nextProjection, expiredAuthority),
    'ERR_INCOMPATIBLE_RELAY'
  )
  next.destroy()
  t.is(nextClock.pending(), 0)
})

test('expiry and rollback revoke relay state before timer cleanup can reenter', (t) => {
  for (const mode of ['expiry', 'rollback']) {
    const fake = clock()
    const fixture = signedAdvertisement({
      routeSeed: mode === 'expiry' ? 102 : 103,
      expiresAtMs: NOW + 60_000n
    })
    let clearCalls = 0
    let invalidations = 0
    let owner = null
    let reentrantProjection = null
    let reentrantError = null
    owner = new RelayCapabilityVerifier({
      wallNow: fake.wallNow,
      monotonicNow: fake.monotonicNow,
      setTimer: fake.setTimer,
      clearTimer(timer) {
        clearCalls++
        if (clearCalls === 1) {
          try {
            reentrantProjection = acceptSafety(owner, fixture)
          } catch (err) {
            reentrantError = err
          }
        }
        fake.clearTimer(timer)
      },
      onInvalidated() {
        invalidations++
      }
    })
    const projection = acceptSafety(owner, fixture)
    const sensitive = [
      projection.canonicalBytes,
      projection.digest,
      projection.identity,
      projection.canonicalEndpointBytes,
      projection.routePublicKey
    ]

    fake.jumpWall(mode === 'expiry' ? 60_000 : -30_001)
    expectCode(t, () => acceptSafety(owner, fixture), 'ERR_INCOMPATIBLE_RELAY')
    t.is(reentrantProjection, null, `${mode} cleanup reentry observes no projection`)
    t.ok(reentrantError instanceof PrivateRouteError)
    t.is(reentrantError && reentrantError.code, 'ERR_INCOMPATIBLE_RELAY')
    t.is(clearCalls, 1, `${mode} cleanup does not recursively invalidate live state`)
    t.is(invalidations, mode === 'rollback' ? 1 : 0)
    for (const buffer of sensitive) t.alike(buffer, b4a.alloc(buffer.byteLength))
    owner.destroy()
    t.is(fake.pending(), 0)
  }
})

test('relay verification exposes no public discovery or dialing API', async (t) => {
  t.is(publicApi.RelayCapabilityVerifier, undefined)
  t.is(publicApi.createActiveChallengeResponderAuthority, undefined)
  t.is(publicApi.createActiveChallengeSendAuthority, undefined)
  t.is(publicApi.decodeRelayCapabilityAdvertisement, undefined)

  const fake = clock()
  const owner = verifier(fake)
  const fixture = signedAdvertisement()
  const projection = acceptSafety(owner, fixture)
  let contacts = 0
  await expectCodeAsync(
    t,
    () =>
      owner.beginChallenge(Object.freeze({ ...projection }), async () => {
        contacts++
        return b4a.alloc(344)
      }),
    'ERR_AUTHENTICATION'
  )
  t.is(contacts, 0)
  owner.destroy()
})

test('CAPS cookie binds every query field and responder consumes one active response', (t) => {
  const fake = clock()
  const responder = createActiveChallengeResponderAuthority({
    now: fake.wallNow,
    setTimeout: fake.setTimer,
    clearTimeout: fake.clearTimer,
    crypto: { ...cryptoSuite, randomBytes: (size) => b4a.alloc(size, 0x5d) }
  })
  const fixture = signedAdvertisement()
  const query = {
    sourceEndpoint: endpoint(240),
    requestedCapabilityMask: 1,
    randomTarget: seed(210),
    queryNonce: seed(211),
    maximumResults: 1
  }
  const cookie = responder.issueCookie(query)
  t.is(cookie.cookieExpiresAtMs, NOW + 5_000n)
  t.is(cookie.returnRoutabilityCookie.byteLength, 32)
  t.is(b4a.toString(cookie.returnRoutabilityCookie, 'hex'), CAPS_COOKIE_VECTOR)
  const binding = responder.admitCapsRetry({ ...query, ...cookie, advertisement: fixture.encoded })
  t.is(responder.admitCapsRetry({ ...query, ...cookie, advertisement: fixture.encoded }), binding)
  for (const changed of [
    { ...query, maximumResults: 2 },
    { ...query, requestedCapabilityMask: 3 },
    { ...query, queryNonce: seed(212) }
  ]) {
    expectCode(
      t,
      () => responder.admitCapsRetry({ ...changed, ...cookie, advertisement: fixture.encoded }),
      'ERR_AUTHENTICATION'
    )
  }

  const ephemeral = routeKey(65)
  const body = b4a.alloc(176)
  body.set(digestRelayCapabilityAdvertisement(fixture.encoded, { now: NOW }), 0)
  body.set(seed(66), 32)
  body.set(ephemeral.publicKey, 64)
  body.writeBigUInt64BE(NOW + 5_000n, 96)
  body.set(query.queryNonce, 104)
  body.writeBigUInt64BE(cookie.cookieExpiresAtMs, 136)
  body.set(cookie.returnRoutabilityCookie, 144)
  const challenge = encodeM3Object({ messageId: M3_MESSAGE_ID.ACTIVE_CHALLENGE_V1, body })
  t.is(b4a.toString(challenge, 'hex'), ACTIVE_CHALLENGE_VECTOR)
  const response = responder.respond(binding, challenge, {
    sourceEndpoint: query.sourceEndpoint,
    advertisement: fixture.encoded,
    identitySecretKey: fixture.signer.secretKey,
    routeEncryptionSecretKey: fixture.route.secretKey
  })
  t.is(b4a.toString(response, 'hex'), ACTIVE_RESPONSE_VECTOR)
  expectCode(
    t,
    () =>
      responder.respond(binding, challenge, {
        sourceEndpoint: query.sourceEndpoint,
        advertisement: fixture.encoded,
        identitySecretKey: fixture.signer.secretKey,
        routeEncryptionSecretKey: fixture.route.secretKey
      }),
    'ERR_REPLAY'
  )

  const lowOrderQuery = { ...query, queryNonce: seed(213) }
  const lowOrderCookie = responder.issueCookie(lowOrderQuery)
  const lowOrderBinding = responder.admitCapsRetry({
    ...lowOrderQuery,
    ...lowOrderCookie,
    advertisement: fixture.encoded
  })
  const lowOrderBody = b4a.from(body)
  lowOrderBody.fill(0, 64, 96)
  lowOrderBody.set(lowOrderQuery.queryNonce, 104)
  lowOrderBody.writeBigUInt64BE(lowOrderCookie.cookieExpiresAtMs, 136)
  lowOrderBody.set(lowOrderCookie.returnRoutabilityCookie, 144)
  const lowOrderChallenge = encodeM3Object({
    messageId: M3_MESSAGE_ID.ACTIVE_CHALLENGE_V1,
    body: lowOrderBody
  })
  expectCode(
    t,
    () =>
      responder.respond(lowOrderBinding, lowOrderChallenge, {
        sourceEndpoint: query.sourceEndpoint,
        advertisement: fixture.encoded,
        identitySecretKey: fixture.signer.secretKey,
        routeEncryptionSecretKey: fixture.route.secretKey
      }),
    'ERR_AUTHENTICATION'
  )
  responder.destroy()
})

test('CAPS query late failures clear every earlier owned field copy', (t) => {
  const tracked = trackedRelayCapability()
  t.teardown(tracked.restore)
  const fake = clock()
  const responder = tracked.fresh.createActiveChallengeResponderAuthority({
    now: fake.wallNow,
    setTimeout: fake.setTimer,
    clearTimeout: fake.clearTimer,
    crypto: { ...cryptoSuite, randomBytes: (size) => b4a.alloc(size, 0x5d) }
  })
  const fixture = signedAdvertisement()
  const query = {
    sourceEndpoint: endpoint(235),
    requestedCapabilityMask: 1,
    randomTarget: b4a.alloc(32, 0xa1),
    queryNonce: b4a.alloc(32, 0xb2),
    maximumResults: 1
  }
  const snapshots = {
    sourceEndpoint: b4a.from(query.sourceEndpoint),
    randomTarget: b4a.from(query.randomTarget),
    queryNonce: b4a.from(query.queryNonce)
  }
  const cookie = responder.issueCookie(query)
  const retry = { ...query, ...cookie, advertisement: fixture.encoded }

  tracked.start()
  expectCode(
    t,
    () => responder.admitCapsRetry({ ...retry, queryNonce: b4a.alloc(31, 0xc3) }),
    'ERR_INCOMPATIBLE_RELAY'
  )
  const invalidFieldAllocations = tracked.take()
  t.alike(
    invalidFieldAllocations.map((value) => value.byteLength),
    [19, 32]
  )
  for (const value of invalidFieldAllocations) t.alike(value, b4a.alloc(value.byteLength))

  const descriptorReads = new Map()
  const hostile = new Proxy(retry, {
    getOwnPropertyDescriptor(target, name) {
      const reads = (descriptorReads.get(name) || 0) + 1
      descriptorReads.set(name, reads)
      if (name === 'maximumResults' && reads === 2) throw new Error('late descriptor trap')
      return Reflect.getOwnPropertyDescriptor(target, name)
    }
  })
  tracked.start()
  expectCode(t, () => responder.admitCapsRetry(hostile), 'ERR_INCOMPATIBLE_RELAY')
  const proxyAllocations = tracked.take()
  t.alike(
    proxyAllocations.map((value) => value.byteLength),
    [19, 32, 32]
  )
  for (const value of proxyAllocations) t.alike(value, b4a.alloc(value.byteLength))
  t.alike(query.sourceEndpoint, snapshots.sourceEndpoint)
  t.alike(query.randomTarget, snapshots.randomTarget)
  t.alike(query.queryNonce, snapshots.queryNonce)
  responder.destroy()
})

test('keyed hash clears concatenated input and output on setup and hashing failures', (t) => {
  const tracked = trackedRelayCapability()
  t.teardown(tracked.restore)
  const fake = clock()
  const responder = tracked.fresh.createActiveChallengeResponderAuthority({
    now: fake.wallNow,
    setTimeout: fake.setTimer,
    clearTimeout: fake.clearTimer,
    crypto: { ...cryptoSuite, randomBytes: (size) => b4a.alloc(size, 0x5d) }
  })
  const query = {
    sourceEndpoint: endpoint(224),
    requestedCapabilityMask: 1,
    randomTarget: seed(144),
    queryNonce: seed(145),
    maximumResults: 1
  }
  const callerBuffers = [query.sourceEndpoint, query.randomTarget, query.queryNonce]
  const snapshots = callerBuffers.map((buffer) => b4a.from(buffer))

  tracked.start()
  tracked.failOutputAllocationAfterConcat()
  let allocationError = null
  try {
    responder.issueCookie(query)
  } catch (err) {
    allocationError = err
  }
  const allocationFailureOwned = tracked.take()
  t.ok(allocationError instanceof Error)
  for (const output of allocationFailureOwned) {
    t.alike(output, b4a.alloc(output.byteLength), 'output allocation failure clears hash input')
  }

  const originalHash = sodium.crypto_generichash
  let capturedOutput = null
  let capturedInput = null
  sodium.crypto_generichash = (output, input) => {
    capturedOutput = output
    capturedInput = input
    throw new Error('injected keyed hash failure')
  }
  try {
    tracked.start()
    let hashingError = null
    try {
      responder.issueCookie(query)
    } catch (err) {
      hashingError = err
    }
    const hashingFailureOwned = tracked.take()
    t.ok(hashingError instanceof Error)
    t.ok(capturedOutput)
    t.ok(capturedInput)
    for (const output of hashingFailureOwned) {
      t.alike(output, b4a.alloc(output.byteLength), 'hashing failure clears input and output')
    }
  } finally {
    sodium.crypto_generichash = originalHash
  }

  for (let index = 0; index < callerBuffers.length; index++) {
    t.alike(callerBuffers[index], snapshots[index], 'keyed hash leaves caller bytes untouched')
  }
  responder.destroy()
})

test('responder pre-validation failures clear source and advertisement copies', (t) => {
  const tracked = trackedRelayCapability()
  t.teardown(tracked.restore)
  const fake = clock()
  const responder = tracked.fresh.createActiveChallengeResponderAuthority({
    now: fake.wallNow,
    setTimeout: fake.setTimer,
    clearTimeout: fake.clearTimer,
    crypto: { ...cryptoSuite, randomBytes: (size) => b4a.alloc(size, 0x5d) }
  })
  const fixture = signedAdvertisement()
  const query = {
    sourceEndpoint: endpoint(234),
    requestedCapabilityMask: 1,
    randomTarget: seed(198),
    queryNonce: seed(199),
    maximumResults: 1
  }
  const sourceSnapshot = b4a.from(query.sourceEndpoint)
  const advertisementSnapshot = b4a.from(fixture.encoded)
  const cookie = responder.issueCookie(query)
  const retry = { ...query, ...cookie, advertisement: fixture.encoded }
  const binding = responder.admitCapsRetry(retry)
  const responseOptions = {
    sourceEndpoint: query.sourceEndpoint,
    advertisement: fixture.encoded,
    identitySecretKey: fixture.signer.secretKey,
    routeEncryptionSecretKey: fixture.route.secretKey
  }

  tracked.start()
  expectCode(
    t,
    () => responder.respond(binding, b4a.alloc(0), { ...responseOptions, advertisement: {} }),
    'ERR_INCOMPATIBLE_RELAY'
  )
  const invalidAdvertisementAllocations = tracked.take()
  t.alike(
    invalidAdvertisementAllocations.map((value) => value.byteLength),
    [19]
  )
  for (const value of invalidAdvertisementAllocations) {
    t.alike(value, b4a.alloc(value.byteLength))
  }
  t.is(responder.admitCapsRetry(retry), binding, 'pre-validation failure does not consume binding')

  tracked.start()
  expectCode(
    t,
    () => responder.respond(binding, b4a.alloc(0), responseOptions),
    'ERR_AUTHENTICATION'
  )
  const malformedChallengeAllocations = tracked.take()
  t.alike(
    malformedChallengeAllocations.map((value) => value.byteLength),
    [19, fixture.encoded.byteLength]
  )
  for (const value of malformedChallengeAllocations) {
    t.alike(value, b4a.alloc(value.byteLength))
  }
  t.is(responder.admitCapsRetry(retry), binding, 'malformed challenge does not consume binding')
  t.alike(query.sourceEndpoint, sourceSnapshot)
  t.alike(fixture.encoded, advertisementSnapshot)
  responder.destroy()
})

test('verifier consumes one opaque CAPS-bound send authority with the exact challenge tail', async (t) => {
  const fake = clock()
  const owner = verifier(fake)
  const fixture = signedAdvertisement({ expiresAtMs: NOW + 60_000n })
  const projection = acceptSafety(owner, fixture)
  const responder = createActiveChallengeResponderAuthority({
    now: fake.wallNow,
    setTimeout: fake.setTimer,
    clearTimeout: fake.clearTimer,
    crypto: { ...cryptoSuite, randomBytes: (size) => b4a.alloc(size, 0x5d) }
  })
  const query = {
    sourceEndpoint: endpoint(239),
    requestedCapabilityMask: 1,
    randomTarget: seed(207),
    queryNonce: seed(208),
    maximumResults: 1
  }
  const cookie = responder.issueCookie(query)
  const responderBinding = responder.admitCapsRetry({
    ...query,
    ...cookie,
    advertisement: fixture.encoded
  })
  let sends = 0
  let sentChallenge = null
  const sendAuthority = createActiveChallengeSendAuthority({
    capsBinding: {
      advertisement: projection,
      sourceEndpoint: query.sourceEndpoint,
      queryNonce: query.queryNonce,
      cookieExpiresAtMs: cookie.cookieExpiresAtMs,
      returnRoutabilityCookie: cookie.returnRoutabilityCookie,
      advertisementDigest: projection.digest,
      relayIdentity: projection.identity
    },
    send(challenge) {
      sends++
      sentChallenge = challenge
      const body = challenge.subarray(8)
      t.alike(body.subarray(104, 136), query.queryNonce)
      t.is(body.readBigUInt64BE(136), cookie.cookieExpiresAtMs)
      t.alike(body.subarray(144, 176), cookie.returnRoutabilityCookie)
      return responder.respond(responderBinding, challenge, {
        sourceEndpoint: query.sourceEndpoint,
        advertisement: fixture.encoded,
        identitySecretKey: fixture.signer.secretKey,
        routeEncryptionSecretKey: fixture.route.secretKey
      })
    }
  })
  t.ok(Object.isFrozen(sendAuthority))
  t.alike(Object.getOwnPropertyNames(sendAuthority), [])
  const validated = await owner.beginChallenge(projection, sendAuthority)
  t.is(sends, 1)
  t.alike(validated.digest, projection.digest)
  t.alike(
    sentChallenge,
    b4a.alloc(sentChallenge.byteLength),
    'consumed challenge bytes are cleared'
  )

  await expectCodeAsync(t, () => owner.beginChallenge(projection, sendAuthority), 'ERR_REPLAY')
  let forgedCalls = 0
  await expectCodeAsync(
    t,
    () =>
      owner.beginChallenge(projection, async () => {
        forgedCalls++
        return b4a.alloc(344)
      }),
    'ERR_AUTHENTICATION'
  )
  t.is(forgedCalls, 0)
  responder.destroy()
  owner.destroy()
})

test('completed CAPS tuple stays tombstoned and conflicting retry fails until cookie expiry', (t) => {
  const fake = clock()
  const responder = createActiveChallengeResponderAuthority({
    now: fake.wallNow,
    setTimeout: fake.setTimer,
    clearTimeout: fake.clearTimer,
    crypto: { ...cryptoSuite, randomBytes: (size) => b4a.alloc(size, 0x5d) }
  })
  const fixture = signedAdvertisement()
  const query = {
    sourceEndpoint: endpoint(237),
    requestedCapabilityMask: 1,
    randomTarget: seed(203),
    queryNonce: seed(204),
    maximumResults: 1
  }
  const cookie = responder.issueCookie(query)
  const retry = { ...query, ...cookie, advertisement: fixture.encoded }
  const binding = responder.admitCapsRetry(retry)
  const state = responder._bindings.get(binding)
  const ownedNonce = state.query.queryNonce
  const ownedCookie = state.query.returnRoutabilityCookie
  const ownedDigest = state.advertisementDigest
  const ephemeral = routeKey(64)
  const body = b4a.alloc(176)
  body.set(digestRelayCapabilityAdvertisement(fixture.encoded, { now: NOW }), 0)
  body.set(seed(63), 32)
  body.set(ephemeral.publicKey, 64)
  body.writeBigUInt64BE(NOW + ACTIVE_CHALLENGE_TIMEOUT, 96)
  body.set(query.queryNonce, 104)
  body.writeBigUInt64BE(cookie.cookieExpiresAtMs, 136)
  body.set(cookie.returnRoutabilityCookie, 144)
  const challenge = encodeM3Object({ messageId: M3_MESSAGE_ID.ACTIVE_CHALLENGE_V1, body })
  responder.respond(binding, challenge, {
    sourceEndpoint: query.sourceEndpoint,
    advertisement: fixture.encoded,
    identitySecretKey: fixture.signer.secretKey,
    routeEncryptionSecretKey: fixture.route.secretKey
  })

  t.unlike(ownedNonce, b4a.alloc(32), 'replay tombstone owns the canonical query')
  t.unlike(ownedCookie, b4a.alloc(32), 'replay tombstone owns the canonical cookie')
  t.unlike(ownedDigest, b4a.alloc(32), 'replay tombstone owns the advertisement digest')
  expectCode(t, () => responder.admitCapsRetry(retry), 'ERR_REPLAY')
  const conflicting = signedAdvertisement({ maxQueuedBytes: 262_145 })
  expectCode(
    t,
    () => responder.admitCapsRetry({ ...query, ...cookie, advertisement: conflicting.encoded }),
    'ERR_AUTHENTICATION'
  )

  fake.advance(5_001)
  responder.issueCookie({ ...query, queryNonce: seed(202) })
  t.alike(ownedNonce, b4a.alloc(32))
  t.alike(ownedCookie, b4a.alloc(32))
  t.alike(ownedDigest, b4a.alloc(32))
  responder.destroy()
})

test('responder consumes a binding before every injected crypto hook can reenter', (t) => {
  for (const hook of ['randomBytes', 'keyAgreement', 'sign']) {
    let responder = null
    let binding = null
    let challenge = null
    let responseOptions = null
    let armed = false
    let reentered = false
    let innerResponse = null
    let innerError = null
    let hookCalls = 0
    const temporary = []
    const reenter = () => {
      if (reentered) return
      reentered = true
      try {
        innerResponse = responder.respond(binding, challenge, responseOptions)
      } catch (err) {
        innerError = err
      }
    }
    const crypto = {
      randomBytes(size) {
        const output = b4a.alloc(size, 0x6a)
        if (armed) temporary.push(output)
        if (armed && hook === 'randomBytes') {
          hookCalls++
          reenter()
        }
        return output
      },
      keyAgreement(secretKey, publicKey) {
        const output = cryptoSuite.keyAgreement(secretKey, publicKey)
        if (armed) temporary.push(secretKey, output)
        if (armed && hook === 'keyAgreement') {
          hookCalls++
          reenter()
        }
        return output
      },
      sign(message, secretKey) {
        const output = cryptoSuite.sign(message, secretKey)
        if (armed) temporary.push(message, secretKey, output)
        if (armed && hook === 'sign') {
          hookCalls++
          reenter()
        }
        return output
      }
    }
    const fake = clock()
    responder = createActiveChallengeResponderAuthority({
      now: fake.wallNow,
      setTimeout: fake.setTimer,
      clearTimeout: fake.clearTimer,
      crypto
    })
    const fixture = signedAdvertisement()
    const query = {
      sourceEndpoint: endpoint(236),
      requestedCapabilityMask: 1,
      randomTarget: seed(200),
      queryNonce: seed(201),
      maximumResults: 1
    }
    const cookie = responder.issueCookie(query)
    binding = responder.admitCapsRetry({ ...query, ...cookie, advertisement: fixture.encoded })
    const ephemeral = routeKey(62)
    const body = b4a.alloc(176)
    body.set(digestRelayCapabilityAdvertisement(fixture.encoded, { now: NOW }), 0)
    body.set(seed(61), 32)
    body.set(ephemeral.publicKey, 64)
    body.writeBigUInt64BE(NOW + ACTIVE_CHALLENGE_TIMEOUT, 96)
    body.set(query.queryNonce, 104)
    body.writeBigUInt64BE(cookie.cookieExpiresAtMs, 136)
    body.set(cookie.returnRoutabilityCookie, 144)
    challenge = encodeM3Object({ messageId: M3_MESSAGE_ID.ACTIVE_CHALLENGE_V1, body })
    responseOptions = {
      sourceEndpoint: query.sourceEndpoint,
      advertisement: fixture.encoded,
      identitySecretKey: fixture.signer.secretKey,
      routeEncryptionSecretKey: fixture.route.secretKey
    }
    armed = true
    const outerResponse = responder.respond(binding, challenge, responseOptions)
    armed = false

    t.is(outerResponse.readUInt16BE(4), M3_MESSAGE_ID.ACTIVE_CHALLENGE_RESPONSE_V1, hook)
    t.is(hookCalls, 1, `${hook} executes for exactly one consume attempt`)
    t.is(innerResponse, null, `${hook} cannot complete a second response`)
    t.ok(innerError instanceof PrivateRouteError, hook)
    t.is(innerError && innerError.code, 'ERR_REPLAY', hook)
    expectCode(
      t,
      () => responder.admitCapsRetry({ ...query, ...cookie, advertisement: fixture.encoded }),
      'ERR_REPLAY'
    )
    for (const bytes of temporary) t.alike(bytes, b4a.alloc(bytes.byteLength), hook)
    responder.destroy()
  }
})

test('responder constructor accepts only plain or null-prototype own-data options', (t) => {
  const timers = {
    setTimeout() {
      return 1
    },
    clearTimeout() {}
  }
  let inheritedReads = 0
  const inheritedPrototype = {}
  Object.defineProperty(inheritedPrototype, 'unknown', {
    get() {
      inheritedReads++
      throw new Error('inherited getter must not run')
    }
  })
  const inherited = Object.assign(Object.create(inheritedPrototype), {
    now: () => NOW,
    ...timers
  })
  expectCode(t, () => createActiveChallengeResponderAuthority(inherited), 'ERR_INCOMPATIBLE_RELAY')
  t.is(inheritedReads, 0)

  let accessorReads = 0
  const accessor = { ...timers }
  Object.defineProperty(accessor, 'now', {
    enumerable: true,
    get() {
      accessorReads++
      return () => NOW
    }
  })
  expectCode(t, () => createActiveChallengeResponderAuthority(accessor), 'ERR_INCOMPATIBLE_RELAY')
  t.is(accessorReads, 0)

  let proxyGets = 0
  const hostile = new Proxy(
    { now: () => NOW, ...timers },
    {
      ownKeys() {
        throw new Error('hostile ownKeys')
      },
      get() {
        proxyGets++
        throw new Error('hostile get')
      }
    }
  )
  expectCode(t, () => createActiveChallengeResponderAuthority(hostile), 'ERR_INCOMPATIBLE_RELAY')
  t.is(proxyGets, 0)

  const nullPrototype = Object.assign(Object.create(null), {
    now: () => NOW,
    ...timers
  })
  const responder = createActiveChallengeResponderAuthority(nullPrototype)
  t.ok(responder)
  responder.destroy()
})

test('CAPS cookie survives only the live prior-secret overlap at exact rotation', (t) => {
  const fake = clock(0n)
  let generated = 0
  const responder = createActiveChallengeResponderAuthority({
    now: fake.wallNow,
    setTimeout: fake.setTimer,
    clearTimeout: fake.clearTimer,
    crypto: {
      ...cryptoSuite,
      randomBytes(size) {
        generated++
        return b4a.alloc(size, generated)
      }
    }
  })
  const fixture = signedAdvertisement({ issuedAtMs: 0n, expiresAtMs: 1_000_000n })
  const query = {
    sourceEndpoint: endpoint(241),
    requestedCapabilityMask: 1,
    randomTarget: seed(214),
    queryNonce: seed(215),
    maximumResults: 1
  }

  fake.advance(299_999)
  const cookie = responder.issueCookie(query)
  const originalSecret = responder._currentSecret.secret
  fake.advance(1)
  t.is(generated, 2, 'idle timer rotates exactly at five minutes')
  t.unlike(originalSecret, b4a.alloc(32), 'the immediately prior secret remains live')
  const binding = responder.admitCapsRetry({
    ...query,
    ...cookie,
    advertisement: fixture.encoded
  })
  t.ok(binding)
  fake.advance(4_998)
  t.is(responder.admitCapsRetry({ ...query, ...cookie, advertisement: fixture.encoded }), binding)
  fake.advance(1)
  expectCode(
    t,
    () => responder.admitCapsRetry({ ...query, ...cookie, advertisement: fixture.encoded }),
    'ERR_AUTHENTICATION'
  )

  t.is(fake.pending(), 2)
  fake.advance(1)
  t.is(fake.pending(), 1, 'prior-secret erasure does not extend past its original deadline')
  t.alike(originalSecret, b4a.alloc(32), 'expired prior secret is cleared')
  const currentSecret = responder._currentSecret.secret
  responder.destroy()
  t.alike(currentSecret, b4a.alloc(32), 'destroy clears the current secret')
})

test('CAPS responder catches up delayed rotations without reviving stale overlap', (t) => {
  for (const resume of ['api', 'timer']) {
    const fake = clock(0n)
    let generated = 0
    const responder = createActiveChallengeResponderAuthority({
      now: fake.wallNow,
      setTimeout: fake.setTimer,
      clearTimeout: fake.clearTimer,
      crypto: {
        ...cryptoSuite,
        randomBytes(size) {
          generated++
          return b4a.alloc(size, generated)
        }
      }
    })
    const fixture = signedAdvertisement({ issuedAtMs: 0n, expiresAtMs: 1_000_000n })
    const query = {
      sourceEndpoint: endpoint(242),
      requestedCapabilityMask: 1,
      randomTarget: seed(216),
      queryNonce: seed(217),
      maximumResults: 1
    }
    fake.advance(299_999)
    const cookie = responder.issueCookie(query)
    const staleSecret = responder._currentSecret.secret
    fake.jumpWall(10_001)
    if (resume === 'api') {
      expectCode(
        t,
        () => responder.admitCapsRetry({ ...query, ...cookie, advertisement: fixture.encoded }),
        'ERR_AUTHENTICATION'
      )
    } else {
      fake.advance(1)
    }
    t.is(generated, 2)
    t.is(fake.pending(), 1, 'late catch-up retains only the next rotation timer')
    t.alike(staleSecret, b4a.alloc(32), 'late catch-up synchronously clears stale secrets')
    responder.destroy()
  }
})

test('verifier clears raw RNG outputs before challenge publication on every path', async (t) => {
  const rawOutputs = []
  let mode = 'ordinary'
  let reentryOwner = null
  let reentryProjection = null
  let reentryAuthority = null
  let reentryResult = null
  const tracked = trackedRelayCapability({
    randomBytes(size) {
      const output = b4a.alloc(size, rawOutputs.length + 0x71)
      rawOutputs.push(output)
      return output
    },
    encryptionKeyPair(seedValue) {
      if (mode === 'reenter') {
        reentryResult = reentryOwner.beginChallenge(reentryProjection, reentryAuthority).then(
          () => null,
          (err) => err
        )
        throw new Error('injected key generation failure')
      }
      return cryptoSuite.encryptionKeyPair(seedValue)
    }
  })
  t.teardown(tracked.restore)
  const fixture = signedAdvertisement({ routeSeed: 96, expiresAtMs: NOW + 60_000n })
  const encodedSnapshot = b4a.from(fixture.encoded)
  const createOwner = (fake) =>
    new tracked.fresh.RelayCapabilityVerifier({
      wallNow: fake.wallNow,
      monotonicNow: fake.monotonicNow,
      setTimer: fake.setTimer,
      clearTimer: fake.clearTimer,
      onInvalidated() {}
    })
  const createAuthority = (projection, send, offset) =>
    tracked.fresh.createActiveChallengeSendAuthority({
      capsBinding: {
        advertisement: projection,
        sourceEndpoint: endpoint(220 + offset),
        queryNonce: seed(120 + offset),
        cookieExpiresAtMs: NOW + ACTIVE_CHALLENGE_TIMEOUT,
        returnRoutabilityCookie: seed(130 + offset),
        advertisementDigest: projection.digest,
        relayIdentity: projection.identity
      },
      send
    })

  const allocationClock = clock()
  const allocationOwner = createOwner(allocationClock)
  const allocationProjection = acceptSafety(allocationOwner, fixture)
  let allocationSends = 0
  const allocationAuthority = createAuthority(
    allocationProjection,
    () => {
      allocationSends++
      return b4a.alloc(0)
    },
    1
  )
  rawOutputs.length = 0
  tracked.start()
  tracked.failAllocationAt(2)
  await expectCodeAsync(
    t,
    () => allocationOwner.beginChallenge(allocationProjection, allocationAuthority),
    'ERR_AUTHENTICATION'
  )
  const allocationFailureOwned = tracked.take()
  t.is(rawOutputs.length, 2)
  for (const output of rawOutputs)
    t.alike(output, b4a.alloc(32), 'allocation failure clears raw RNG')
  for (const output of allocationFailureOwned) {
    t.alike(output, b4a.alloc(output.byteLength), 'allocation failure clears copied ownership')
  }
  t.is(allocationSends, 0, 'allocation failure publishes no challenge')
  t.is(allocationClock.pending(), 1, 'allocation failure adds no pending timer')
  allocationOwner.destroy()

  const reentryClock = clock()
  reentryOwner = createOwner(reentryClock)
  reentryProjection = acceptSafety(reentryOwner, fixture)
  let reentrySends = 0
  reentryAuthority = createAuthority(
    reentryProjection,
    () => {
      reentrySends++
      return b4a.alloc(0)
    },
    2
  )
  rawOutputs.length = 0
  mode = 'reenter'
  await expectCodeAsync(
    t,
    () => reentryOwner.beginChallenge(reentryProjection, reentryAuthority),
    'ERR_AUTHENTICATION'
  )
  const reentryError = await reentryResult
  t.ok(reentryError instanceof PrivateRouteError)
  t.is(reentryError && reentryError.code, 'ERR_REPLAY')
  t.is(rawOutputs.length, 2)
  for (const output of rawOutputs) t.alike(output, b4a.alloc(32), 'reentry failure clears raw RNG')
  t.is(reentrySends, 0, 'reentry failure publishes no challenge')
  t.is(reentryClock.pending(), 1, 'reentry failure adds no pending timer')
  reentryOwner.destroy()

  const successClock = clock()
  const successOwner = createOwner(successClock)
  const successProjection = acceptSafety(successOwner, fixture)
  const responderClock = clock()
  const responder = createActiveChallengeResponderAuthority({
    now: responderClock.wallNow,
    setTimeout: responderClock.setTimer,
    clearTimeout: responderClock.clearTimer,
    crypto: { ...cryptoSuite, randomBytes: (size) => b4a.alloc(size, 0x5d) }
  })
  const query = {
    sourceEndpoint: endpoint(223),
    requestedCapabilityMask: 1,
    randomTarget: seed(142),
    queryNonce: seed(143),
    maximumResults: 1
  }
  const cookie = responder.issueCookie(query)
  const binding = responder.admitCapsRetry({
    ...query,
    ...cookie,
    advertisement: fixture.encoded
  })
  const successAuthority = tracked.fresh.createActiveChallengeSendAuthority({
    capsBinding: {
      advertisement: successProjection,
      sourceEndpoint: query.sourceEndpoint,
      queryNonce: query.queryNonce,
      cookieExpiresAtMs: cookie.cookieExpiresAtMs,
      returnRoutabilityCookie: cookie.returnRoutabilityCookie,
      advertisementDigest: successProjection.digest,
      relayIdentity: successProjection.identity
    },
    send(challenge) {
      return responder.respond(binding, challenge, {
        sourceEndpoint: query.sourceEndpoint,
        advertisement: fixture.encoded,
        identitySecretKey: fixture.signer.secretKey,
        routeEncryptionSecretKey: fixture.route.secretKey
      })
    }
  })
  rawOutputs.length = 0
  mode = 'ordinary'
  const validated = await successOwner.beginChallenge(successProjection, successAuthority)
  t.alike(validated.digest, successProjection.digest)
  t.is(rawOutputs.length, 2)
  for (const output of rawOutputs) t.alike(output, b4a.alloc(32), 'success clears raw RNG')
  t.alike(fixture.encoded, encodedSnapshot, 'all paths leave caller advertisement unchanged')
  responder.destroy()
  successOwner.destroy()
})

test('active challenge uses exact vectors, monotonic deadline, possession proof, and single completion', async (t) => {
  const fake = clock()
  const owner = verifier(fake)
  const fixture = signedAdvertisement({ expiresAtMs: NOW + 60_000n })
  const projection = acceptSafety(owner, fixture)
  const responderNonce = seed(99)
  let calls = 0
  let completedResponse = null

  const result = await owner.beginChallenge(
    projection,
    challengeAuthority(projection, async (message) => {
      calls++
      t.is(message.byteLength, 184)
      t.is(message.readUInt16BE(4), M3_MESSAGE_ID.ACTIVE_CHALLENGE_V1)
      const body = message.subarray(8)
      const shared = cryptoSuite.keyAgreement(fixture.route.secretKey, body.subarray(64, 96))
      const responseBody = b4a.alloc(272)
      responseBody.set(body.subarray(0, 32), 0)
      responseBody.set(fixture.signer.publicKey, 32)
      responseBody.set(body.subarray(32, 96), 64)
      responseBody.set(responderNonce, 128)
      responseBody.set(body.subarray(96, 176), 160)
      const domain = b4a.from('hyperdht-private-routes/m3/active-challenge/route-key-proof/v1')
      const proofInput = b4a.concat([
        b4a.from([domain.byteLength >>> 8, domain.byteLength]),
        domain,
        responseBody.subarray(0, 240)
      ])
      sodium.crypto_generichash(responseBody.subarray(240), proofInput, shared)
      const signatureDomain = b4a.from('hyperdht-private-routes/m3/active-challenge-response/v1')
      const signatureInput = b4a.alloc(2 + signatureDomain.byteLength + 8 + responseBody.byteLength)
      signatureInput.writeUInt16BE(signatureDomain.byteLength, 0)
      signatureInput.set(signatureDomain, 2)
      signatureInput.writeUInt32BE(1, 2 + signatureDomain.byteLength)
      signatureInput.writeUInt16BE(
        M3_MESSAGE_ID.ACTIVE_CHALLENGE_RESPONSE_V1,
        6 + signatureDomain.byteLength
      )
      signatureInput.writeUInt16BE(responseBody.byteLength, 8 + signatureDomain.byteLength)
      signatureInput.set(responseBody, 10 + signatureDomain.byteLength)
      const signature = cryptoSuite.sign(signatureInput, fixture.signer.secretKey)
      completedResponse = encodeM3Object({
        messageId: M3_MESSAGE_ID.ACTIVE_CHALLENGE_RESPONSE_V1,
        body: responseBody,
        authSuffix: signature
      })
      return completedResponse
    })
  )
  t.is(calls, 1)
  t.alike(result.digest, projection.digest)

  await expectCodeAsync(
    t,
    () =>
      owner.beginChallenge(
        projection,
        challengeAuthority(projection, async () => completedResponse, {
          queryNonce: seed(209),
          returnRoutabilityCookie: seed(210)
        })
      ),
    'ERR_REPLAY'
  )

  const slowFixture = signedAdvertisement({ epoch: 8n, routeSeed: 9, expiresAtMs: NOW + 60_000n })
  const slow = acceptSafety(owner, slowFixture)
  await expectCodeAsync(
    t,
    () =>
      owner.beginChallenge(
        slow,
        challengeAuthority(slow, async () => {
          fake.advance(Number(ACTIVE_CHALLENGE_TIMEOUT) + 1)
          return b4a.alloc(344)
        })
      ),
    'ERR_INCOMPATIBLE_RELAY'
  )
  owner.destroy()
})

test('active challenge timer cannot outlive a shorter signed advertisement expiry', async (t) => {
  const fake = clock()
  const delays = []
  const owner = new RelayCapabilityVerifier({
    wallNow: fake.wallNow,
    monotonicNow: fake.monotonicNow,
    setTimer(callback, delay) {
      delays.push(delay)
      return fake.setTimer(callback, delay)
    },
    clearTimer: fake.clearTimer,
    onInvalidated() {}
  })
  const fixture = signedAdvertisement({ expiresAtMs: NOW + 1_000n })
  const projection = acceptSafety(owner, fixture)
  let sentChallenge = null
  let settled = false
  let code = null
  const operation = owner
    .beginChallenge(
      projection,
      challengeAuthority(projection, (challenge) => {
        sentChallenge = challenge
        return new Promise(() => {})
      })
    )
    .catch((err) => {
      settled = true
      code = err && err.code
    })
  await Promise.resolve()
  t.alike(delays, [1_000, 1_000], 'record and challenge timers share the signed deadline')
  t.is(sentChallenge.subarray(8).readBigUInt64BE(96), NOW + 1_000n)
  fake.advance(1_000)
  for (let index = 0; index < 4; index++) await Promise.resolve()
  t.ok(settled)
  t.is(code, 'ERR_INCOMPATIBLE_RELAY')
  t.alike(sentChallenge, b4a.alloc(sentChallenge.byteLength))
  t.alike(projection.canonicalBytes, b4a.alloc(projection.canonicalBytes.byteLength))
  t.is(fake.pending(), 0)
  await operation
  owner.destroy()
})

test('destroy erases verifier state and stable-fails every method', async (t) => {
  const fake = clock()
  const owner = verifier(fake)
  const fixture = signedAdvertisement()
  const projection = acceptSafety(owner, fixture)
  owner.destroy()
  owner.destroy()
  expectCode(t, () => acceptSafety(owner, fixture), 'ERR_DESTROYED')
  await expectCodeAsync(
    t,
    () => owner.beginChallenge(projection, async () => b4a.alloc(344)),
    'ERR_DESTROYED'
  )
  t.is(fake.pending(), 0)
})

test('destroy aborts and erases an in-flight challenge', async (t) => {
  const fake = clock()
  const owner = verifier(fake)
  const fixture = signedAdvertisement({ expiresAtMs: NOW + 60_000n })
  const projection = acceptSafety(owner, fixture)
  const operation = owner.beginChallenge(
    projection,
    challengeAuthority(projection, () => new Promise(() => {}))
  )
  await Promise.resolve()
  owner.destroy()
  await expectCodeAsync(t, () => operation, 'ERR_DESTROYED')
  t.is(fake.pending(), 0)
  t.alike(projection.canonicalBytes, b4a.alloc(projection.canonicalBytes.byteLength))
})
