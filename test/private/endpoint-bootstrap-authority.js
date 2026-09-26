'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  inspectEndpointBootstrapAuthority,
  consumeEndpointBootstrapAuthority,
  createEndpointBootstrapAuthority,
  prepareEndpointNatTraversal,
  registerEndpointBootstrapController
} = require('../../lib/private/endpoint-bootstrap-authority')
const { TEST_ONLY_BOOTSTRAP_IO_OBSERVER } = require('../../lib/private/bootstrap-io')
const { issueReflectedEndpointClaim } = require('../../lib/private/nat-reflect')
const udxCellEndpoint = require('../../lib/private/udx-cell-endpoint')
const { bindBootstrapUdxOperation, destroyNatTraversalAuthority } = udxCellEndpoint

const seed = (value) => b4a.alloc(32, value)

function options(value, port) {
  const identity = cryptoSuite.keyPair(seed(value))
  const secret = b4a.from(identity.secretKey)
  let now = 1_000n
  return {
    advance(delta) {
      now += BigInt(delta)
    },
    secret,
    value: {
      bootstrapEndpoints: [{ host: '127.0.0.2', port: port + 1 }],
      localIdentity: identity.publicKey,
      localSecretKey: secret,
      host: '127.0.0.1',
      port,
      wallNow: () => now,
      monotonicNow: () => now,
      schedule: setTimeout,
      cancelScheduled: clearTimeout,
      randomBytes(size) {
        return b4a.alloc(size, value + 1)
      }
    }
  }
}

function code(t, fn, expected) {
  let error = null
  try {
    fn()
  } catch (err) {
    error = err
  }
  t.is(error && error.code, expected)
}

test('endpoint bootstrap authority is a frozen empty one-shot aggregate', (t) => {
  const fixture = options(1, 47801)
  const authority = createEndpointBootstrapAuthority(fixture.value)
  const controller = Object.freeze({})
  const registration = registerEndpointBootstrapController(authority, controller)

  t.alike(Reflect.ownKeys(authority), [])
  t.ok(Object.isFrozen(authority))
  t.ok(fixture.secret.every((byte) => byte === 0))

  const resources = consumeEndpointBootstrapAuthority(authority, registration)
  t.is(resources.controller, controller)
  t.ok(Object.isFrozen(resources))
  t.ok(resources.bootstrapIO)
  t.ok(resources.endpoint)
  t.ok(resources.bootstrapUdxAuthority)
  t.is(typeof resources.wallNow, 'function')
  t.is(typeof resources.monotonicNow, 'function')
  t.is(typeof resources.schedule, 'function')
  t.is(typeof resources.cancelScheduled, 'function')
  t.is(typeof resources.randomBytes, 'function')

  code(t, () => consumeEndpointBootstrapAuthority(authority, registration), 'ERR_REPLAY')
  resources.bootstrapIO.destroy()
})

test('endpoint bootstrap authority mismatch destroys every owned resource', (t) => {
  const left = options(3, 47803)
  const right = options(5, 47805)
  const leftAuthority = createEndpointBootstrapAuthority(left.value)
  const rightAuthority = createEndpointBootstrapAuthority(right.value)
  const leftRegistration = registerEndpointBootstrapController(leftAuthority, Object.freeze({}))
  const rightRegistration = registerEndpointBootstrapController(rightAuthority, Object.freeze({}))

  code(t, () => consumeEndpointBootstrapAuthority(leftAuthority, rightRegistration), 'UNAUTHORIZED')
  code(t, () => consumeEndpointBootstrapAuthority(leftAuthority, leftRegistration), 'ERR_REPLAY')

  const snapshot = inspectEndpointBootstrapAuthority(leftAuthority)
  t.alike(snapshot, {
    status: 'DESTROYED',
    bootstrapIO: false,
    endpoint: false,
    bootstrapUdxAuthority: false,
    registration: false,
    secretBytes: 0
  })

  const resources = consumeEndpointBootstrapAuthority(rightAuthority, rightRegistration)
  resources.bootstrapIO.destroy()
})

test('endpoint bootstrap authority rejects cross and reentrant registration consumption', (t) => {
  const fixture = options(7, 47807)
  const authority = createEndpointBootstrapAuthority(fixture.value)
  const controller = Object.freeze({})
  const registration = registerEndpointBootstrapController(authority, controller)

  code(t, () => registerEndpointBootstrapController(authority, Object.freeze({})), 'ERR_REPLAY')

  const resources = consumeEndpointBootstrapAuthority(authority, registration)
  code(t, () => consumeEndpointBootstrapAuthority(authority, registration), 'ERR_REPLAY')
  resources.bootstrapIO.destroy()
})

test('endpoint bootstrap authority binds a delayed nonzero absolute bootstrap deadline once', (t) => {
  const fixture = options(9, 47809)
  const authority = createEndpointBootstrapAuthority(fixture.value)
  const registration = registerEndpointBootstrapController(authority, Object.freeze({}))
  fixture.advance(250)
  const resources = consumeEndpointBootstrapAuthority(authority, registration)
  const generation = Object.freeze({})

  t.ok(
    bindBootstrapUdxOperation(
      resources.bootstrapUdxAuthority,
      11_250,
      generation,
      fixture.value.monotonicNow,
      1_250n
    )
  )
  code(
    t,
    () => bindBootstrapUdxOperation(resources.bootstrapUdxAuthority, 11_250, generation),
    'UNAUTHORIZED'
  )
  resources.bootstrapIO.destroy()
})

test('bootstrap deadline binding does not re-sample an advancing shared clock', (t) => {
  const fixture = options(10, 47810)
  let now = 5_000n
  fixture.value.monotonicNow = () => ++now
  const authority = createEndpointBootstrapAuthority(fixture.value)
  const registration = registerEndpointBootstrapController(authority, Object.freeze({}))
  const resources = consumeEndpointBootstrapAuthority(authority, registration)
  const startedAt = fixture.value.monotonicNow()

  t.ok(
    bindBootstrapUdxOperation(
      resources.bootstrapUdxAuthority,
      Number(startedAt + 10_000n),
      Object.freeze({}),
      fixture.value.monotonicNow,
      startedAt
    )
  )
  t.is(now, startedAt)
  resources.bootstrapIO.destroy()
})

// A claim exists only when at least two reflectors agreed, so three are configured
// and one stays silent; the claim itself names the two that answered.
test('prepareEndpointNatTraversal records observed and silent reflector outcomes in exposure report', async (t) => {
  const originalReflect = udxCellEndpoint.reflectNatEndpoint
  try {
    const fixture = options(11, 47811)
    const authority = createEndpointBootstrapAuthority(fixture.value)
    const controller = Object.freeze({})
    const registration = registerEndpointBootstrapController(authority, controller)

    const reflectors = [
      { identity32: seed(101), host: '198.51.100.1', port: 49737 },
      { identity32: seed(102), host: '198.51.100.2', port: 49738 },
      { identity32: seed(103), host: '198.51.100.3', port: 49739 }
    ]
    const observed = { host: '203.0.113.50', port: 40001 }

    udxCellEndpoint.reflectNatEndpoint = async (natAuthority, configured) =>
      issueReflectedEndpointClaim({
        reflectors: configured,
        observations: [
          { reflectorIdentity32: reflectors[0].identity32, observed },
          { reflectorIdentity32: reflectors[2].identity32, observed }
        ],
        endpointId32: seed(7),
        socketGeneration: 0,
        localIdentity32: seed(11),
        epoch: 1n,
        runId32: seed(1),
        now: 1_000n
      })

    const prepared = await prepareEndpointNatTraversal(authority, {
      epoch: 1n,
      runId32: seed(1),
      reflectors
    })
    t.ok(prepared.natAuthority)
    t.ok(prepared.claim)

    const resources = consumeEndpointBootstrapAuthority(authority, registration)
    const report = resources.bootstrapIO[TEST_ONLY_BOOTSTRAP_IO_OBSERVER]().exposureReport
    t.alike(
      report.map((entry) => [
        entry.phase,
        entry.contactCategory,
        entry.outcome,
        entry.attemptCount
      ]),
      [
        ['reflect', 'reflector', 'observed', 1],
        ['reflect', 'reflector', 'silent', 1],
        ['reflect', 'reflector', 'observed', 1]
      ],
      'one entry per configured reflector, in configured order, answered or silent'
    )
    t.is(new Set(report.map((entry) => entry.redactedEndpoint)).size, 3)
    for (const entry of report) {
      t.is(entry.redactedEndpoint.length, 24)
      t.is(/198\.51\.100|4973/.test(entry.redactedEndpoint), false)
    }
    destroyNatTraversalAuthority(prepared.natAuthority)
    resources.bootstrapIO.destroy()
    await resources.endpoint.close()
  } finally {
    udxCellEndpoint.reflectNatEndpoint = originalReflect
  }
})

test('prepareEndpointNatTraversal records rejected reflector outcomes when reflection throws and preserves error code', async (t) => {
  const originalReflect = udxCellEndpoint.reflectNatEndpoint
  try {
    const fixture = options(12, 47812)
    const authority = createEndpointBootstrapAuthority(fixture.value)
    const controller = Object.freeze({})
    const registration = registerEndpointBootstrapController(authority, controller)

    const r1 = {
      identity32: seed(103),
      host: '198.51.100.3',
      port: 49739
    }
    const r2 = {
      identity32: seed(104),
      host: '198.51.100.4',
      port: 49740
    }

    const reflectionError = new Error('simulated reflection network error')
    reflectionError.code = 'ERR_SIMULATED_REFLECTION_FAILURE'
    udxCellEndpoint.reflectNatEndpoint = async () => {
      throw reflectionError
    }

    let caughtError = null
    try {
      await prepareEndpointNatTraversal(authority, {
        epoch: 1n,
        runId32: seed(2),
        reflectors: [r1, r2]
      })
    } catch (err) {
      caughtError = err
    }

    t.is(caughtError, reflectionError)
    t.is(caughtError && caughtError.code, 'ERR_SIMULATED_REFLECTION_FAILURE')

    const resources = consumeEndpointBootstrapAuthority(authority, registration)
    const report = resources.bootstrapIO[TEST_ONLY_BOOTSTRAP_IO_OBSERVER]().exposureReport
    t.is(report.length, 2)
    t.is(report[0].phase, 'reflect')
    t.is(report[0].contactCategory, 'reflector')
    t.is(report[0].outcome, 'rejected')
    t.is(report[0].attemptCount, 1)
    t.is(report[0].redactedEndpoint.length, 24)

    t.is(report[1].phase, 'reflect')
    t.is(report[1].contactCategory, 'reflector')
    t.is(report[1].outcome, 'rejected')
    t.is(report[1].attemptCount, 1)
    t.is(report[1].redactedEndpoint.length, 24)

    resources.bootstrapIO.destroy()
    await resources.endpoint.close()
  } finally {
    udxCellEndpoint.reflectNatEndpoint = originalReflect
  }
})
