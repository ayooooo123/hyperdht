'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  MAX_PLAN_BYTES,
  PLAN_FORMAT,
  clearVerifiedNatPunchPlan,
  readVerifiedNatPunchPlan,
  signNatPunchPlan,
  verifyNatPunchPlan
} = require('../../lib/private/nat-punch-plan')
const {
  PROTOCOL_VERSION,
  ROLE,
  TOPOLOGY_ROLE,
  roleForIdentity
} = require('../../lib/private/protocol')

const seed = (value) => b4a.alloc(32, value)

function expectCode(t, fn, code) {
  try {
    fn()
    t.fail('expected ' + code)
  } catch (err) {
    t.is(err && err.code, code)
  }
}

function safety(start = 40) {
  for (let value = start; value < 256; value++) {
    const pair = cryptoSuite.keyPair(seed(value))
    if (roleForIdentity(pair.publicKey) === ROLE.SAFETY) return pair
  }
  throw new Error('missing safety identity')
}

function planBody(overrides = {}) {
  const a = overrides.initiatorPair || cryptoSuite.keyPair(seed(31))
  const b = overrides.responderPair || safety(50)
  const initiator = overrides.initiator || {
    identity32: a.publicKey,
    role: TOPOLOGY_ROLE.SOURCE,
    host: '203.0.113.7',
    port: 51001,
    reflectionClaimDigest32: seed(11),
    nonce32: seed(13)
  }
  const responder = overrides.responder || {
    identity32: b.publicKey,
    role: TOPOLOGY_ROLE.SAFETY_GUARD,
    host: '203.0.113.9',
    port: 51002,
    reflectionClaimDigest32: seed(12),
    nonce32: seed(14)
  }
  return {
    value: {
      version: overrides.version === undefined ? PROTOCOL_VERSION : overrides.version,
      format: overrides.format === undefined ? PLAN_FORMAT : overrides.format,
      planId32: overrides.planId32 || seed(9),
      topologyGrantDigest32: overrides.topologyGrantDigest32 || seed(10),
      epoch: overrides.epoch === undefined ? 3n : overrides.epoch,
      runId32: overrides.runId32 || seed(4),
      notBefore: overrides.notBefore === undefined ? 100n : overrides.notBefore,
      expiresAt: overrides.expiresAt === undefined ? 5_000n : overrides.expiresAt,
      initiator,
      responder,
      punchProfileId: overrides.punchProfileId === undefined ? 0 : overrides.punchProfileId
    },
    a,
    b
  }
}

function sign(body) {
  return {
    encoding: signNatPunchPlan(body.value, {
      initiatorSecretKey: body.a.secretKey,
      responderSecretKey: body.b.secretKey
    }),
    a: body.a,
    b: body.b,
    value: body.value
  }
}

test('bilateral plan verifies for both peers (scenarios 1-2 positive path)', (t) => {
  const body = planBody()
  const { encoding, a, b } = sign(body)
  t.ok(encoding.byteLength <= MAX_PLAN_BYTES)
  const left = readVerifiedNatPunchPlan(
    verifyNatPunchPlan(encoding, { localIdentity32: a.publicKey, now: 150n })
  )
  t.is(left.local.port, 51001)
  t.is(left.peer.port, 51002)
  t.is(left.localIsInitiator, true)
  const right = readVerifiedNatPunchPlan(
    verifyNatPunchPlan(encoding, { localIdentity32: b.publicKey, now: 150n })
  )
  t.is(right.local.port, 51002)
  t.is(right.localIsInitiator, false)
})

test('wrong signer or missing peer signature is refused (scenarios 1-2)', (t) => {
  const body = planBody()
  const { encoding, a } = sign(body)
  const flipped = b4a.from(encoding)
  flipped[encoding.byteLength - 1] ^= 0x01
  expectCode(
    t,
    () => verifyNatPunchPlan(flipped, { localIdentity32: a.publicKey, now: 150n }),
    'UNAUTHORIZED'
  )
  expectCode(
    t,
    () => verifyNatPunchPlan(encoding, { localIdentity32: seed(77), now: 150n }),
    'UNAUTHORIZED'
  )
})

test('plan fields bind grant digest, epoch, run, roles, tuples (scenarios 3-6)', (t) => {
  const { encoding, a } = sign(planBody())
  const view = readVerifiedNatPunchPlan(
    verifyNatPunchPlan(encoding, { localIdentity32: a.publicKey, now: 150n })
  )
  t.ok(view.topologyGrantDigest32.equals(seed(10)))
  t.is(view.epoch, 3n)
  t.ok(view.runId32.equals(seed(4)))
  t.is(view.local.role, TOPOLOGY_ROLE.SOURCE)
  t.is(view.peer.role, TOPOLOGY_ROLE.SAFETY_GUARD)
  t.is(view.local.host, '203.0.113.7')
  t.is(view.peer.host, '203.0.113.9')
})

test('validity window is exclusive at expiry (scenario 7 time half)', (t) => {
  const { encoding, a } = sign(planBody())
  expectCode(
    t,
    () => verifyNatPunchPlan(encoding, { localIdentity32: a.publicKey, now: 5_000n }),
    'UNAUTHORIZED'
  )
  expectCode(
    t,
    () => verifyNatPunchPlan(encoding, { localIdentity32: a.publicKey, now: 99n }),
    'UNAUTHORIZED'
  )
})

test('IPv6 and mixed-family size boundaries (scenario 16)', (t) => {
  const a = cryptoSuite.keyPair(seed(31))
  const b = safety(50)
  const body = planBody({
    initiatorPair: a,
    responderPair: b,
    initiator: {
      identity32: a.publicKey,
      role: TOPOLOGY_ROLE.SOURCE,
      host: '2001:db8::7',
      port: 51001,
      reflectionClaimDigest32: seed(11),
      nonce32: seed(13)
    },
    responder: {
      identity32: b.publicKey,
      role: TOPOLOGY_ROLE.SAFETY_GUARD,
      host: '203.0.113.9',
      port: 51002,
      reflectionClaimDigest32: seed(12),
      nonce32: seed(14)
    }
  })
  const { encoding } = sign(body)
  t.ok(encoding.byteLength <= MAX_PLAN_BYTES)
  const view = readVerifiedNatPunchPlan(
    verifyNatPunchPlan(encoding, { localIdentity32: a.publicKey, now: 150n })
  )
  t.is(view.local.host, '2001:db8::7')
  t.is(view.peer.host, '203.0.113.9')
})

test('initiator and responder meaning is preserved under canonical bytes', (t) => {
  const { encoding, a } = sign(planBody())
  const view = readVerifiedNatPunchPlan(
    verifyNatPunchPlan(encoding, { localIdentity32: a.publicKey, now: 150n })
  )
  t.is(view.initiator.port, 51001)
  t.is(view.responder.port, 51002)
  t.is(view.localIsInitiator, true)
})

test('clearVerifiedNatPunchPlan erases retained material (scenario 31 partial)', (t) => {
  const { encoding, a } = sign(planBody())
  const plan = verifyNatPunchPlan(encoding, { localIdentity32: a.publicKey, now: 150n })
  t.ok(clearVerifiedNatPunchPlan(plan))
  expectCode(t, () => readVerifiedNatPunchPlan(plan), 'UNAUTHORIZED')
})
