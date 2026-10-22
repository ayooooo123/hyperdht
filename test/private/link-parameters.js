'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { PrivateRouteError } = require('../../lib/private/errors')
const {
  ADMITTED_LIMITS_SIZE,
  PAYLOAD_PARAMETERS_SIZE,
  decodeAdmittedLimits,
  decodePayloadParameters,
  digestAdmittedLimits,
  digestPayloadParameters,
  encodeAdmittedLimits,
  encodePayloadParameters
} = require('../../lib/private/link-parameters')

const limits = Object.freeze({
  cellSize: 1200,
  maxCells: 4096,
  maxBytes: 1_048_576,
  maxCommands: 512,
  idleTimeoutMs: 30_000,
  expiresAtMs: 0x0102_0304_0506_0708n
})
const parameters = Object.freeze({
  cellSize: 1200,
  maxCellPayload: 1146,
  contextEnvelopeSize: 1101,
  routeFrameSize: 1100,
  maxRoutePayload: 1073,
  datagramReplayWindow: 64,
  maxQueuedBytes: 262_144,
  idleTimeoutMs: 30_000
})

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

test('admitted limits exact bytes and digest match the prototype registry', (t) => {
  const encoded = encodeAdmittedLimits(limits)
  t.is(ADMITTED_LIMITS_SIZE, 26)
  t.is(b4a.toString(encoded, 'hex'), '04b0000010000010000000000200000075300102030405060708')
  t.alike(decodeAdmittedLimits(encoded), limits)
  t.is(
    b4a.toString(digestAdmittedLimits(limits), 'hex'),
    'ea5dbf85e3dd17534b675e815453b0ef3a2254f3736d0297ab1acd5955ee790c'
  )
})

test('payload parameters exact bytes and digest match the prototype registry', (t) => {
  const encoded = encodePayloadParameters(parameters)
  t.is(PAYLOAD_PARAMETERS_SIZE, 20)
  t.is(b4a.toString(encoded, 'hex'), '04b0047a044d044c043100400004000000007530')
  t.alike(decodePayloadParameters(encoded), parameters)
  t.is(
    b4a.toString(digestPayloadParameters(parameters), 'hex'),
    '1d248fe6302060ddfb8b015e3a7d51e2ff895f6c73ad8ce85329a68f82b04db2'
  )
})

test('parameter encoders reject changed inherited constants and zero limits', (t) => {
  expectCode(t, () => encodeAdmittedLimits({ ...limits, cellSize: 1199 }), 'INVALID_ROUTE')
  for (const name of ['maxCells', 'maxBytes', 'maxCommands', 'idleTimeoutMs', 'expiresAtMs']) {
    expectCode(
      t,
      () => encodeAdmittedLimits({ ...limits, [name]: name === 'expiresAtMs' ? 0n : 0 }),
      'INVALID_ROUTE'
    )
  }
  for (const name of [
    'cellSize',
    'maxCellPayload',
    'contextEnvelopeSize',
    'routeFrameSize',
    'maxRoutePayload',
    'datagramReplayWindow'
  ]) {
    expectCode(
      t,
      () => encodePayloadParameters({ ...parameters, [name]: parameters[name] - 1 }),
      'INVALID_ROUTE'
    )
  }
})

test('hostile shapes and forged encoded extents map to stable route errors', (t) => {
  const hostile = new Proxy(
    { ...parameters },
    {
      getPrototypeOf() {
        throw new Error('hostile')
      }
    }
  )
  expectCode(t, () => encodePayloadParameters(hostile), 'INVALID_ROUTE')
  const trailing = b4a.concat([encodePayloadParameters(parameters), b4a.from([0])])
  Object.defineProperty(trailing, 'byteLength', { value: PAYLOAD_PARAMETERS_SIZE })
  expectCode(t, () => digestPayloadParameters(trailing), 'INVALID_ROUTE')
  const inherited = Object.create(parameters)
  expectCode(t, () => encodePayloadParameters(inherited), 'INVALID_ROUTE')
})
