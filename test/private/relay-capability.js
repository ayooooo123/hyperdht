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
  fake.jumpWall(-30_001)
  await expectCodeAsync(
    t,
    () => owner.beginChallenge(projection, async () => b4a.alloc(344)),
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
  nextClock.jumpWall(60_000)
  await expectCodeAsync(
    t,
    () => next.beginChallenge(nextProjection, async () => b4a.alloc(344)),
    'ERR_INCOMPATIBLE_RELAY'
  )
  next.destroy()
  t.is(nextClock.pending(), 0)
})

test('relay verification exposes no public discovery or dialing API', async (t) => {
  t.is(publicApi.RelayCapabilityVerifier, undefined)
  t.is(publicApi.createActiveChallengeResponderAuthority, undefined)
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

test('active challenge uses exact vectors, monotonic deadline, possession proof, and single completion', async (t) => {
  const fake = clock()
  const owner = verifier(fake)
  const fixture = signedAdvertisement({ expiresAtMs: NOW + 60_000n })
  const projection = acceptSafety(owner, fixture)
  const responderNonce = seed(99)
  let calls = 0
  let completedResponse = null

  const result = await owner.beginChallenge(projection, async (message) => {
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
  t.is(calls, 1)
  t.alike(result.digest, projection.digest)

  await expectCodeAsync(
    t,
    () => owner.beginChallenge(projection, async () => completedResponse),
    'ERR_REPLAY'
  )

  const slowFixture = signedAdvertisement({ epoch: 8n, routeSeed: 9, expiresAtMs: NOW + 60_000n })
  const slow = acceptSafety(owner, slowFixture)
  await expectCodeAsync(
    t,
    () =>
      owner.beginChallenge(slow, async () => {
        fake.advance(Number(ACTIVE_CHALLENGE_TIMEOUT) + 1)
        return b4a.alloc(344)
      }),
    'ERR_INCOMPATIBLE_RELAY'
  )
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
  const operation = owner.beginChallenge(projection, () => new Promise(() => {}))
  await Promise.resolve()
  owner.destroy()
  await expectCodeAsync(t, () => operation, 'ERR_DESTROYED')
  t.is(fake.pending(), 0)
  t.alike(projection.canonicalBytes, b4a.alloc(projection.canonicalBytes.byteLength))
})
