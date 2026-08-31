'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  PLAN_FORMAT,
  MAX_PLAN_BYTES,
  encodeNatPunchPlan,
  encodeUnsignedPlan,
  signNatPunchPlan,
  verifyNatPunchPlan
} = require('../../lib/private/nat-punch')
const { PROTOCOL_VERSION } = require('../../lib/private/protocol')

const seed = (value) => b4a.alloc(32, value)

function keyPairAt(value) {
  return cryptoSuite.keyPair(seed(value))
}

function plan(overrides = {}) {
  return {
    version: PROTOCOL_VERSION,
    format: PLAN_FORMAT,
    planId32: seed(9),
    endpointA: {
      identity32: keyPairAt(1).publicKey,
      role: 0,
      host: '203.0.113.7',
      port: 51001
    },
    endpointB: {
      identity32: keyPairAt(2).publicKey,
      role: 1,
      host: '203.0.113.9',
      port: 51002
    },
    epoch: 3n,
    notBefore: 100n,
    expiresAt: 200n,
    runId32: seed(4),
    ...overrides
  }
}

test('a signed plan verifies for both named peers and orders endpoints canonically', (t) => {
  const authority = keyPairAt(3)
  const a = keyPairAt(1)
  const b = keyPairAt(2)
  const encoding = signNatPunchPlan(plan(), authority.secretKey)

  t.ok(encoding.byteLength <= MAX_PLAN_BYTES, 'an encoded plan fits the wire budget')

  const viewA = verifyNatPunchPlan(encoding, authority.publicKey, {
    localIdentity32: a.publicKey,
    now: 150n
  })
  t.alike(
    { host: viewA.local.host, port: viewA.local.port },
    { host: '203.0.113.7', port: 51001 },
    'peer A reads itself as local'
  )
  t.alike(
    { host: viewA.peer.host, port: viewA.peer.port },
    { host: '203.0.113.9', port: 51002 },
    'peer A reads B as its peer'
  )
  t.ok(viewA.planId32.equals(seed(9)), 'both sides read the same plan id')

  const viewB = verifyNatPunchPlan(encoding, authority.publicKey, {
    localIdentity32: b.publicKey,
    now: 150n
  })
  t.is(viewB.local.port, 51002, 'peer B reads itself as local')
  t.is(viewB.peer.port, 51001, 'peer B reads A as its peer')
})

test('a plan signed by the wrong authority is refused', (t) => {
  const stranger = keyPairAt(30)
  const encoding = signNatPunchPlan(plan(), stranger.secretKey)
  t.exception(
    () =>
      verifyNatPunchPlan(encoding, keyPairAt(3).publicKey, {
        localIdentity32: keyPairAt(1).publicKey,
        now: 150n
      }),
    'a stranger cannot sign a plan'
  )
})

test('a plan naming a third party is refused for every other reader', (t) => {
  const authority = keyPairAt(3)
  const encoding = signNatPunchPlan(plan(), authority.secretKey)
  t.exception(
    () =>
      verifyNatPunchPlan(encoding, authority.publicKey, {
        localIdentity32: keyPairAt(31).publicKey,
        now: 150n
      }),
    'an identity outside the plan has no side'
  )
})

test('a plan outside its validity window is refused', (t) => {
  const authority = keyPairAt(3)
  const encoding = signNatPunchPlan(plan(), authority.secretKey)
  t.exception(
    () =>
      verifyNatPunchPlan(encoding, authority.publicKey, {
        localIdentity32: keyPairAt(1).publicKey,
        now: 200n
      }),
    'the expiry bound is exclusive'
  )
  t.exception(
    () =>
      verifyNatPunchPlan(encoding, authority.publicKey, {
        localIdentity32: keyPairAt(1).publicKey,
        now: 99n
      }),
    'the notBefore bound is inclusive'
  )
})

test('a tampered plan is refused byte-for-byte', (t) => {
  const authority = keyPairAt(3)
  const encoding = signNatPunchPlan(plan(), authority.secretKey)

  const portTampered = b4a.from(encoding)
  portTampered[MAX_PLAN_BYTES - 64 - 3] ^= 0x01
  t.exception(
    () =>
      verifyNatPunchPlan(portTampered, authority.publicKey, {
        localIdentity32: keyPairAt(1).publicKey,
        now: 150n
      }),
    'flipping a port byte breaks the signature'
  )

  const hostTampered = b4a.from(encoding)
  hostTampered[44] ^= 0x01
  t.exception(
    () =>
      verifyNatPunchPlan(hostTampered, authority.publicKey, {
        localIdentity32: keyPairAt(1).publicKey,
        now: 150n
      }),
    'flipping an address byte breaks the signature'
  )

  const idTampered = b4a.from(encoding)
  idTampered[9] ^= 0x01
  t.exception(
    () =>
      verifyNatPunchPlan(idTampered, authority.publicKey, {
        localIdentity32: keyPairAt(1).publicKey,
        now: 150n
      }),
    'flipping a plan-id byte breaks the signature'
  )
})

test('a plan for one epoch or run does not read as another', (t) => {
  const authority = keyPairAt(3)
  const epochPlan = signNatPunchPlan(plan({ epoch: 4n }), authority.secretKey)
  const verified = verifyNatPunchPlan(epochPlan, authority.publicKey, {
    localIdentity32: keyPairAt(1).publicKey,
    now: 150n
  })
  t.is(verified.epoch, 4n, 'the epoch is inside the signed bytes')
  t.ok(verified.runId32.equals(seed(4)), 'the run id survives verification')
})

test('the same peers in reversed order verify to the same published tuple', (t) => {
  const authority = keyPairAt(3)
  const forward = signNatPunchPlan(plan(), authority.secretKey)
  const reversed = signNatPunchPlan(
    plan({ endpointA: plan().endpointB, endpointB: plan().endpointA }),
    authority.secretKey
  )
  const left = verifyNatPunchPlan(forward, authority.publicKey, {
    localIdentity32: keyPairAt(1).publicKey,
    now: 150n
  })
  const right = verifyNatPunchPlan(reversed, authority.publicKey, {
    localIdentity32: keyPairAt(1).publicKey,
    now: 150n
  })
  t.alike(
    { host: left.peer.host, port: left.peer.port },
    { host: right.peer.host, port: right.peer.port },
    'mirrored plans agree on the peer address'
  )
})

test('malformed plans are refused at the codec', (t) => {
  const authority = keyPairAt(3)
  t.exception(
    () =>
      verifyNatPunchPlan(b4a.alloc(10), authority.publicKey, {
        localIdentity32: keyPairAt(1).publicKey,
        now: 150n
      }),
    'a short encoding is refused'
  )

  t.exception(
    () =>
      verifyNatPunchPlan(b4a.alloc(MAX_PLAN_BYTES + 1), authority.publicKey, {
        localIdentity32: keyPairAt(1).publicKey,
        now: 150n
      }),
    'an oversized encoding is refused'
  )

  const unsigned = encodeUnsignedPlan(plan())
  t.exception(
    () =>
      verifyNatPunchPlan(unsigned, authority.publicKey, {
        localIdentity32: keyPairAt(1).publicKey,
        now: 150n
      }),
    'an unsigned encoding has no side'
  )
  t.is(
    unsigned.byteLength,
    MAX_PLAN_BYTES - 64,
    'the unsigned body is the plan minus the signature'
  )

  t.exception(
    () => signNatPunchPlan(plan({ notBefore: 200n, expiresAt: 100n }), authority.secretKey),
    'an inverted window cannot be signed'
  )
})
