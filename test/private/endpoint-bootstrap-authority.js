'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  inspectEndpointBootstrapAuthority,
  consumeEndpointBootstrapAuthority,
  createEndpointBootstrapAuthority,
  registerEndpointBootstrapController
} = require('../../lib/private/endpoint-bootstrap-authority')
const { bindBootstrapUdxOperation } = require('../../lib/private/udx-cell-endpoint')

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
