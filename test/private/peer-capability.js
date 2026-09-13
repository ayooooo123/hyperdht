'use strict'

const test = require('brittle')
const b4a = require('b4a')
const crypto = require('hypercore-crypto')
const sodium = require('sodium-universal')

const { PrivateRouteError } = require('../../lib/private/errors')
const {
  createPeerRelayOwner,
  readPeerRelayOwner,
  destroyPeerRelayOwner,
  verifyPeerAdvertisement,
  readVerifiedPeerAdvertisement,
  createPeerCandidateLocator,
  takePeerCandidateLocator,
  encodeReachableEndpoint,
  decodeReachableEndpoint,
  buildAdvertisementSignatureInput
} = require('../../lib/private/peer-capability')
const { PEER_MESSAGE_ID, encodePeerObject } = require('../../lib/private/peer-protocol')

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

function createMockClock() {
  let wall = 1000000n
  let mono = 500000n
  return {
    clockIdentity: Object.freeze({ id: 'test-clock-1' }),
    wallNow: () => wall,
    monotonicNow: () => mono,
    setTimer: (fn, ms) => setTimeout(fn, ms),
    clearTimer: (id) => clearTimeout(id),
    advance: (ms) => {
      wall += BigInt(ms)
      mono += BigInt(ms)
    }
  }
}

function buildTestAdvertisementFields(edKeys, xKeys, endpoint, expiresAt = 2000000n, mask = 11) {
  return {
    relayIdentity32: edKeys.publicKey,
    currentDhtNodeId32: crypto.hash(edKeys.publicKey),
    reachableEndpoint: endpoint || { host: '127.0.0.1', port: 40001 },
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

function expectThrows(t, fn, code) {
  let err = null
  try {
    fn()
  } catch (e) {
    err = e
  }
  t.ok(err)
  t.ok(err instanceof PrivateRouteError)
  if (code) t.is(err.code, code)
}

function assertSignature(t, label, messageId, body, signature, publicKey) {
  const domain = b4a.from(`hyperdht-private-routes/m3/${label}/v2`)
  const domainLength = b4a.alloc(2)
  domainLength.writeUInt16BE(domain.byteLength)
  const wire = encodePeerObject({ messageId, body, authSuffix: signature })
  const signed = b4a.concat([domainLength, domain, wire.subarray(0, wire.byteLength - 64)])
  t.ok(sodium.crypto_sign_verify_detached(signature, signed, publicKey))
}

function makeOwner(mask = 11) {
  const edKeys = generateEd25519KeyPair()
  const xKeys = generateX25519KeyPair()
  const clock = createMockClock()
  const endpoint = { host: '127.0.0.1', port: 40001 }
  const owner = createPeerRelayOwner({
    endpoint,
    identityKeyPair: edKeys,
    routeKeyPair: xKeys,
    advertisementFields: buildTestAdvertisementFields(edKeys, xKeys, endpoint, 2000000n, mask),
    clockIdentity: clock.clockIdentity,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer
  })
  return { edKeys, xKeys, clock, endpoint, owner }
}

test('encode/decode reachable endpoint uses canonical family4/6 layout and rejects fallbacks', (t) => {
  const v4 = encodeReachableEndpoint({ host: '10.1.2.3', port: 40001 })
  t.is(v4.byteLength, 19)
  t.is(v4[0], 4)
  t.is(v4[13], 10)
  t.is(v4.readUInt16BE(17), 40001)
  expectThrows(t, () => encodeReachableEndpoint({ host: 'not-an-ip', port: 1 }), 'INVALID_ROUTE')
  expectThrows(t, () => encodeReachableEndpoint({ host: '127.0.0.1', port: 0 }), 'INVALID_ROUTE')
  const malformed = b4a.alloc(19, 0)
  malformed[0] = 4
  malformed[1] = 1
  malformed[13] = 127
  malformed[16] = 1
  malformed.writeUInt16BE(80, 17)
  expectThrows(t, () => decodeReachableEndpoint(malformed))
})

test('createPeerRelayOwner creates, reads, and destroys without leaking raw secrets', (t) => {
  const { edKeys, xKeys, endpoint, owner } = makeOwner(11)

  const readData = readPeerRelayOwner(owner, endpoint)
  t.alike(readData.relayIdentity32, edKeys.publicKey)
  t.alike(readData.routeEncryptionPublicKey32, xKeys.publicKey)
  t.is(readData.identitySecretKey, undefined)
  t.is(readData.routeEncryptionSecretKey, undefined)

  const body335 = b4a.alloc(335, 0)
  body335.set(edKeys.publicKey, 0)
  body335.set(b4a.alloc(32, 0x22), 32)
  body335.writeBigUInt64BE(1000000n, 64)
  body335[72] = 1
  body335.writeUInt16BE(260, 73)
  body335.set(readData.canonicalAdvertisement260, 75)
  readData.parsedAdvertisement.relayIdentity32.fill(0)
  readData.parsedAdvertisement.routeEncryptionPublicKey32.fill(0)
  const sig = readData.signPeerObject(PEER_MESSAGE_ID.PEER_CAPS_RESPONSE_V2, body335)
  assertSignature(
    t,
    'caps-response',
    PEER_MESSAGE_ID.PEER_CAPS_RESPONSE_V2,
    body335,
    sig,
    edKeys.publicKey
  )

  const junk = b4a.alloc(335, 0x11)
  junk.set(edKeys.publicKey, 0)
  expectThrows(
    t,
    () => readData.signPeerObject(PEER_MESSAGE_ID.PEER_CAPS_RESPONSE_V2, junk),
    'INVALID_ROUTE'
  )
  expectThrows(t, () => readData.signPeerObject(0x9999, body335), 'INVALID_ROUTE')

  // OFFER: body adDigest is the selected responder/candidate ad, not the initiator owner's.
  const offer = b4a.alloc(360, 1)
  const foreignResponderDigest = b4a.alloc(32, 0xab)
  t.ok(!b4a.equals(foreignResponderDigest, readData.advertisementDigest32))
  offer.set(foreignResponderDigest, 0)
  offer.set(edKeys.publicKey, 32) // initiator identity = signer
  offer.set(b4a.alloc(32, 0xcd), 64) // responder identity
  offer[96] = 0 // initiatorRole
  offer[97] = 1 // responderRole
  offer[98] = 2 // branchClass
  offer.writeBigUInt64BE(1n, 131) // generation
  offer[139] = 0 // extensionIndex
  offer.writeUInt16BE(1200, 268)
  offer.writeUInt16BE(1200, 302)
  offer.fill(0, 328)
  const offerSig = readData.signPeerObject(PEER_MESSAGE_ID.PEER_LINK_OFFER_V2, offer)
  assertSignature(
    t,
    'link-offer',
    PEER_MESSAGE_ID.PEER_LINK_OFFER_V2,
    offer,
    offerSig,
    edKeys.publicKey
  )
  offer[139] = 3 // invalid extensionIndex
  expectThrows(
    t,
    () => readData.signPeerObject(PEER_MESSAGE_ID.PEER_LINK_OFFER_V2, offer),
    'INVALID_ROUTE'
  )

  // REDACTED_PROOF: extensionIndex must be 1 or 2 (not 0).
  const proof = b4a.alloc(306, 1)
  proof.set(readData.advertisementDigest32, 0)
  proof.set(b4a.alloc(32, 0x11), 32) // initiator
  proof.set(edKeys.publicKey, 64) // responder identity = signer
  proof[96] = 2 // branchClass
  proof.writeBigUInt64BE(1n, 129) // generation
  proof[137] = 1 // valid extensionIndex
  proof.set(xKeys.publicKey, 202) // route pk
  const proofSig = readData.signPeerObject(PEER_MESSAGE_ID.PEER_REDACTED_RESPONDER_PROOF_V2, proof)
  assertSignature(
    t,
    'redacted-responder-proof',
    PEER_MESSAGE_ID.PEER_REDACTED_RESPONDER_PROOF_V2,
    proof,
    proofSig,
    edKeys.publicKey
  )
  proof[137] = 0 // invalid for proof (allowed on OFFER, not here)
  expectThrows(
    t,
    () => readData.signPeerObject(PEER_MESSAGE_ID.PEER_REDACTED_RESPONDER_PROOF_V2, proof),
    'INVALID_ROUTE'
  )
  proof[137] = 3
  expectThrows(
    t,
    () => readData.signPeerObject(PEER_MESSAGE_ID.PEER_REDACTED_RESPONDER_PROOF_V2, proof),
    'INVALID_ROUTE'
  )

  const remote = generateX25519KeyPair()
  let shared = null
  try {
    shared = readData.agreeRoute(remote.publicKey)
    const reciprocal = b4a.alloc(32)
    sodium.crypto_scalarmult(reciprocal, remote.secretKey, xKeys.publicKey)
    t.alike(shared, reciprocal)
    reciprocal.fill(0)
  } finally {
    if (shared) shared.fill(0)
  }
  expectThrows(t, () => readData.agreeRoute(b4a.alloc(32, 0)), 'INVALID_KEY')
  expectThrows(t, () => readPeerRelayOwner(owner, { ...endpoint }), 'INVALID_ROUTE')

  destroyPeerRelayOwner(owner)
  destroyPeerRelayOwner(owner)
  expectThrows(t, () => readPeerRelayOwner(owner, endpoint), 'INVALID_ROUTE')
  expectThrows(
    t,
    () => readData.signPeerObject(PEER_MESSAGE_ID.PEER_CAPS_RESPONSE_V2, body335),
    'INVALID_ROUTE'
  )
  expectThrows(t, () => readData.agreeRoute(remote.publicKey), 'INVALID_ROUTE')
})

test('createPeerRelayOwner rejects mismatched keypairs and bad masks', (t) => {
  const edKeys = generateEd25519KeyPair()
  const xKeys = generateX25519KeyPair()
  const wrongEdKeys = generateEd25519KeyPair()
  const clock = createMockClock()
  const endpoint = { host: '127.0.0.1', port: 40001 }
  const mismatchedKeys = { publicKey: edKeys.publicKey, secretKey: wrongEdKeys.secretKey }

  expectThrows(
    t,
    () =>
      createPeerRelayOwner({
        endpoint,
        identityKeyPair: mismatchedKeys,
        routeKeyPair: xKeys,
        advertisementFields: buildTestAdvertisementFields(mismatchedKeys, xKeys, endpoint),
        clockIdentity: clock.clockIdentity,
        wallNow: clock.wallNow,
        monotonicNow: clock.monotonicNow,
        setTimer: clock.setTimer,
        clearTimer: clock.clearTimer
      }),
    'INVALID_KEY'
  )

  expectThrows(
    t,
    () =>
      createPeerRelayOwner({
        endpoint,
        identityKeyPair: edKeys,
        routeKeyPair: xKeys,
        advertisementFields: buildTestAdvertisementFields(edKeys, xKeys, endpoint, 2000000n, 16),
        clockIdentity: clock.clockIdentity,
        wallNow: clock.wallNow,
        monotonicNow: clock.monotonicNow,
        setTimer: clock.setTimer,
        clearTimer: clock.clearTimer
      }),
    'INVALID_ROUTE'
  )
})

test('verifyPeerAdvertisement rejects re-signed malformed ads and unsupported masks', (t) => {
  const { edKeys, xKeys, clock, endpoint, owner } = makeOwner(11)
  const readData = readPeerRelayOwner(owner, endpoint)
  const canonicalWire = readData.canonicalAdvertisement260

  t.ok(
    verifyPeerAdvertisement(canonicalWire, {
      expectedIdentity32: edKeys.publicKey,
      expectedCapabilityMask: 9
    })
  )

  function reSign(body188) {
    const sigInput = buildAdvertisementSignatureInput(body188)
    const sig = b4a.alloc(64)
    sodium.crypto_sign_detached(sig, sigInput, edKeys.secretKey)
    return encodePeerObject({
      messageId: PEER_MESSAGE_ID.PEER_CAPABILITY_ADVERTISEMENT_V2,
      body: body188,
      authSuffix: sig
    })
  }

  const validBody = canonicalWire.subarray(8, 196)
  t.ok(verifyPeerAdvertisement(reSign(validBody)))

  const badVerBody = b4a.from(validBody)
  badVerBody.writeUInt32BE(1, 119)
  expectThrows(t, () => verifyPeerAdvertisement(reSign(badVerBody)), 'INVALID_DESCRIPTOR')

  const badMaskBody = b4a.from(validBody)
  badMaskBody.writeUInt32BE(16, 115)
  expectThrows(t, () => verifyPeerAdvertisement(reSign(badMaskBody)), 'INVALID_DESCRIPTOR')

  const badCellBody = b4a.from(validBody)
  badCellBody.writeUInt16BE(1000, 127)
  expectThrows(t, () => verifyPeerAdvertisement(reSign(badCellBody)), 'INVALID_DESCRIPTOR')

  const zeroRouteBody = b4a.from(validBody)
  zeroRouteBody.fill(0, 83, 115)
  expectThrows(t, () => verifyPeerAdvertisement(reSign(zeroRouteBody)), 'INVALID_DESCRIPTOR')

  const guard = makeOwner(9)
  const guardWire = readPeerRelayOwner(guard.owner, guard.endpoint).canonicalAdvertisement260
  expectThrows(
    t,
    () => verifyPeerAdvertisement(guardWire, { expectedCapabilityMask: 11 }),
    'INVALID_DESCRIPTOR'
  )
  t.ok(verifyPeerAdvertisement(guardWire, { expectedCapabilityMask: 9 }))
})

test('createPeerCandidateLocator and takePeerCandidateLocator enforce one-shot deadline bounds', (t) => {
  const { edKeys, endpoint, owner } = makeOwner(11)
  const readData = readPeerRelayOwner(owner, endpoint)
  const verified = verifyPeerAdvertisement(readData.canonicalAdvertisement260)
  const locator = createPeerCandidateLocator(owner, verified)
  t.is(locator.kind, 'peerCandidateLocator')

  const taken = takePeerCandidateLocator(locator, endpoint)
  t.is(taken.endpoint, endpoint)
  t.alike(taken.identity32, edKeys.publicKey)
  t.is(taken.wireExpiresAt, 2000000n)
  t.is(taken.localDeadline, 500000n + (2000000n - 1000000n))
  t.is(taken.completeAdvertisement.byteLength, 260)
  t.is(taken.grantDigest, undefined)

  expectThrows(t, () => takePeerCandidateLocator(locator, endpoint), 'INVALID_ROUTE')
})

test('candidate locator snapshots deadline caps and preserves the earlier advertisement projection', (t) => {
  const { clock, endpoint, owner } = makeOwner()
  t.teardown(() => destroyPeerRelayOwner(owner))
  const advertisement = readPeerRelayOwner(owner, endpoint).canonicalAdvertisement260
  const verified = verifyPeerAdvertisement(advertisement)
  const bounds = {
    clockIdentity: clock.clockIdentity,
    wireExpiresAt: 1000500n,
    localDeadline: 500400n
  }
  const locator = createPeerCandidateLocator(owner, verified, bounds)
  bounds.wireExpiresAt = 2000000n
  bounds.localDeadline = 1500000n
  const taken = takePeerCandidateLocator(locator, endpoint)
  t.is(taken.wireExpiresAt, 1000500n, 'later caller mutation cannot extend the wire lifetime')
  t.is(taken.localDeadline, 500400n, 'earlier monotonic cap is retained')
  const wireLimited = takePeerCandidateLocator(
    createPeerCandidateLocator(owner, verified, {
      clockIdentity: clock.clockIdentity,
      wireExpiresAt: 1000200n,
      localDeadline: 500400n
    }),
    endpoint
  )
  t.is(wireLimited.localDeadline, 500200n, 'the shortened wire lifetime also caps its projection')
  const earlierAdvertisement = verifyPeerAdvertisement(advertisement, {
    clockIdentity: clock.clockIdentity,
    wallNow: clock.wallNow,
    monotonicNow: () => clock.monotonicNow() - 100n
  })
  const earlier = takePeerCandidateLocator(
    createPeerCandidateLocator(owner, earlierAdvertisement, bounds),
    endpoint
  )
  t.is(
    earlier.localDeadline,
    1499900n,
    'the original advertisement projection is never rebased later'
  )
  expectThrows(
    t,
    () =>
      createPeerCandidateLocator(owner, verified, {
        ...bounds,
        clockIdentity: {}
      }),
    'INVALID_ROUTE'
  )
  expectThrows(
    t,
    () =>
      createPeerCandidateLocator(owner, verified, {
        ...bounds,
        localDeadline: clock.monotonicNow()
      }),
    'INVALID_ROUTE'
  )
  let getterCalls = 0
  expectThrows(
    t,
    () =>
      createPeerCandidateLocator(owner, verified, {
        ...bounds,
        get localDeadline() {
          getterCalls++
          return 500400n
        }
      }),
    'INVALID_ROUTE'
  )
  t.is(getterCalls, 0, 'deadline accessors do not execute')
  expectThrows(
    t,
    () =>
      createPeerCandidateLocator(
        owner,
        verified,
        new Proxy(bounds, {
          getOwnPropertyDescriptor(target, key) {
            if (key === 'localDeadline') destroyPeerRelayOwner(owner)
            return Reflect.getOwnPropertyDescriptor(target, key)
          }
        })
      ),
    'INVALID_ROUTE'
  )
})
