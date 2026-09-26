'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  createDhtExitWireReservation,
  decodeDhtReplyEnvelope,
  encodeDhtExitRequest
} = require('../../lib/private/dht-exit-wire')
const { PrivateRouteError } = require('../../lib/private/errors')
const {
  createReflectionProbe,
  destroyReflectedEndpointClaim,
  issueReflectedEndpointClaim,
  observeReflectionReply,
  readReflectedEndpointClaim,
  validateReflectorSet
} = require('../../lib/private/nat-reflect')

const seed = (value) => b4a.alloc(32, value)

function expectCode(t, fn, code) {
  try {
    fn()
    t.fail('expected throw ' + code)
  } catch (err) {
    t.is(err && err.code, code)
  }
}

function reflector(n, host, port) {
  return {
    host,
    port,
    identity32: seed(n)
  }
}

test('two distinct reflectors that agree issue one claim (scenario 11)', (t) => {
  const r1 = reflector(1, '203.0.113.1', 49737)
  const r2 = reflector(2, '203.0.113.2', 49737)
  const claim = issueReflectedEndpointClaim({
    reflectors: [r1, r2],
    observations: [
      { reflectorIdentity32: r1.identity32, observed: { host: '198.51.100.7', port: 40001 } },
      { reflectorIdentity32: r2.identity32, observed: { host: '198.51.100.7', port: 40001 } }
    ],
    endpointId32: seed(10),
    socketGeneration: 1,
    localIdentity32: seed(11),
    epoch: 3n,
    runId32: seed(12),
    now: 1000n
  })
  const view = readReflectedEndpointClaim(claim, { now: 1001n })
  t.alike(view.observed, { host: '198.51.100.7', port: 40001 })
  t.is(view.socketGeneration, 1)
  destroyReflectedEndpointClaim(claim)
})

test('reflectors that disagree produce no claim (scenario 12)', (t) => {
  const r1 = reflector(1, '203.0.113.1', 49737)
  const r2 = reflector(2, '203.0.113.2', 49737)
  expectCode(
    t,
    () =>
      issueReflectedEndpointClaim({
        reflectors: [r1, r2],
        observations: [
          { reflectorIdentity32: r1.identity32, observed: { host: '198.51.100.7', port: 40001 } },
          { reflectorIdentity32: r2.identity32, observed: { host: '198.51.100.8', port: 40001 } }
        ],
        endpointId32: seed(10),
        socketGeneration: 1,
        localIdentity32: seed(11),
        epoch: 3n,
        runId32: seed(12),
        now: 1000n
      }),
    'UNAUTHORIZED'
  )
})

test('one response only produces no claim (scenario 13)', (t) => {
  const r1 = reflector(1, '203.0.113.1', 49737)
  const r2 = reflector(2, '203.0.113.2', 49737)
  expectCode(
    t,
    () =>
      issueReflectedEndpointClaim({
        reflectors: [r1, r2],
        observations: [
          { reflectorIdentity32: r1.identity32, observed: { host: '198.51.100.7', port: 40001 } }
        ],
        endpointId32: seed(10),
        socketGeneration: 1,
        localIdentity32: seed(11),
        epoch: 3n,
        runId32: seed(12),
        now: 1000n
      }),
    'UNAUTHORIZED'
  )
})

test('wrong source or transaction is ignored by observation (scenario 14)', (t) => {
  const remote = { host: '203.0.113.9', port: 49737 }
  const probe = createReflectionProbe(
    { ...remote, identity32: seed(1) },
    { tid: 0x1234, randomBytes: cryptoSuite.randomBytes }
  )
  const reply = b4a.from(
    '131734120a01020312a1ebbd82e1821bd6b655180ad77d6770c263d7a70abaab1ff867c06203335b6ac2cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01c6336407419c0568656c6c6f',
    'hex'
  )
  expectCode(
    t,
    () => observeReflectionReply(probe, { host: '203.0.113.10', port: 49737 }, reply),
    'UNAUTHORIZED'
  )
  const wrongTid = b4a.from(reply)
  wrongTid[2] ^= 1
  expectCode(t, () => observeReflectionReply(probe, remote, wrongTid), 'INVALID_ROUTE')
})

test('valid response prefix with trailing bytes is rejected (scenario 15)', (t) => {
  const remote = { host: '203.0.113.9', port: 49737 }
  const local = { host: '10.1.2.3', port: 41234 }
  const reservation = createDhtExitWireReservation({ remote, local, tid: 0x1234 })
  const reply = b4a.from(
    '131734120a01020312a1ebbd82e1821bd6b655180ad77d6770c263d7a70abaab1ff867c06203335b6ac2cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01c6336407419c0568656c6c6f',
    'hex'
  )
  const trailing = b4a.alloc(reply.byteLength + 1)
  trailing.set(reply)
  expectCode(
    t,
    () => decodeDhtReplyEnvelope(reservation, remote, trailing, { observeLocalTuple: true }),
    'INVALID_ROUTE'
  )
  const ok = decodeDhtReplyEnvelope(reservation, remote, reply, { observeLocalTuple: true })
  t.alike(ok.to, local)
})

test('IPv4 and IPv6 claims are accepted (scenario 16)', (t) => {
  const r1 = reflector(1, '203.0.113.1', 49737)
  const r2 = reflector(2, '203.0.113.2', 49737)
  const v4 = issueReflectedEndpointClaim({
    reflectors: [r1, r2],
    observations: [
      { reflectorIdentity32: r1.identity32, observed: { host: '198.51.100.7', port: 40001 } },
      { reflectorIdentity32: r2.identity32, observed: { host: '198.51.100.7', port: 40001 } }
    ],
    endpointId32: seed(10),
    socketGeneration: 1,
    localIdentity32: seed(11),
    epoch: 3n,
    runId32: seed(12),
    now: 1000n
  })
  t.is(readReflectedEndpointClaim(v4, { now: 1001n }).observed.host, '198.51.100.7')
  destroyReflectedEndpointClaim(v4)

  const v6 = issueReflectedEndpointClaim({
    reflectors: [r1, r2],
    observations: [
      { reflectorIdentity32: r1.identity32, observed: { host: '2001:db8::1', port: 40001 } },
      { reflectorIdentity32: r2.identity32, observed: { host: '2001:db8::1', port: 40001 } }
    ],
    endpointId32: seed(10),
    socketGeneration: 1,
    localIdentity32: seed(11),
    epoch: 3n,
    runId32: seed(12),
    now: 1000n
  })
  t.is(readReflectedEndpointClaim(v6, { now: 1001n }).observed.host, '2001:db8::1')
  destroyReflectedEndpointClaim(v6)
})

test('expired claim and wrong generation are unusable (scenarios 8, 10, 18)', (t) => {
  const r1 = reflector(1, '203.0.113.1', 49737)
  const r2 = reflector(2, '203.0.113.2', 49737)
  const claim = issueReflectedEndpointClaim({
    reflectors: [r1, r2],
    observations: [
      { reflectorIdentity32: r1.identity32, observed: { host: '198.51.100.7', port: 40001 } },
      { reflectorIdentity32: r2.identity32, observed: { host: '198.51.100.7', port: 40001 } }
    ],
    endpointId32: seed(10),
    socketGeneration: 1,
    localIdentity32: seed(11),
    epoch: 3n,
    runId32: seed(12),
    now: 1000n,
    ttlMs: 5n
  })
  expectCode(t, () => readReflectedEndpointClaim(claim, { now: 1006n }), 'UNAUTHORIZED')
  const claim2 = issueReflectedEndpointClaim({
    reflectors: [r1, r2],
    observations: [
      { reflectorIdentity32: r1.identity32, observed: { host: '198.51.100.7', port: 40001 } },
      { reflectorIdentity32: r2.identity32, observed: { host: '198.51.100.7', port: 40001 } }
    ],
    endpointId32: seed(10),
    socketGeneration: 2,
    localIdentity32: seed(11),
    epoch: 3n,
    runId32: seed(12),
    now: 1000n
  })
  expectCode(
    t,
    () =>
      readReflectedEndpointClaim(claim2, {
        now: 1001n,
        socketGeneration: 1
      }),
    'UNAUTHORIZED'
  )
  destroyReflectedEndpointClaim(claim2)
})

test('reflector set rejects duplicates and under-size sets', (t) => {
  expectCode(t, () => validateReflectorSet([reflector(1, '203.0.113.1', 1)]), 'INVALID_ROUTE')
  expectCode(
    t,
    () => validateReflectorSet([reflector(1, '203.0.113.1', 1), reflector(1, '203.0.113.2', 2)]),
    'INVALID_ROUTE'
  )
})

test('probe encodes a bounded PING', (t) => {
  const probe = createReflectionProbe(
    { host: '203.0.113.9', port: 49737, identity32: seed(1) },
    { tid: 7, randomBytes: () => b4a.from([0, 7]) }
  )
  t.is(probe.tid, 7)
  t.ok(b4a.isBuffer(probe.packet))
  t.is(probe.packet[0] & 0x0f, 0x03)
})
