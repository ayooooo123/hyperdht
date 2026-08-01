'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { PrivateRouteError } = require('../../lib/private/errors')
const {
  TEST_ISOLATED_ADDRESS_GRANT_SIZE,
  decodeTestIsolatedAddressGrant,
  digestTestIsolatedAddressTuple,
  encodeTestIsolatedAddressGrant,
  verifyTestIsolatedAddressGrant
} = require('../../lib/private/dht-exit-test-topology-grant')

function seed(value, size = 32) {
  return b4a.alloc(size, value)
}

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

test('test isolated address grants encode exact signed tuple-digest payloads', (t) => {
  const pair = cryptoSuite.keyPair(seed(0x01))
  const tupleDigest = digestTestIsolatedAddressTuple({
    tuple: { host: '198.51.101.7', port: 49737 },
    id: seed(0x02),
    exitRole: 5,
    generation: 7n
  })
  const encoded = encodeTestIsolatedAddressGrant(
    {
      runNonce: seed(0x03, 16),
      exitRole: 5,
      generation: 7n,
      grantSequence: 9n,
      expiresAt: 20_000n,
      tupleDigest
    },
    pair.secretKey
  )
  const decoded = decodeTestIsolatedAddressGrant(encoded)
  const verified = verifyTestIsolatedAddressGrant(encoded, pair.publicKey, {
    runNonce: seed(0x03, 16),
    exitRole: 5,
    generation: 7n,
    tupleDigest,
    now: 1_000n
  })

  t.is(encoded.byteLength, TEST_ISOLATED_ADDRESS_GRANT_SIZE)
  t.alike(decoded.tupleDigest, tupleDigest)
  t.is(decoded.grantSequence, 9n)
  t.alike(verified.tupleDigest, tupleDigest)
  t.alike(
    verifyTestIsolatedAddressGrant(encoded, pair.publicKey, {
      runNonce: seed(0x03, 16),
      exitRole: 5,
      generation: 7n,
      tupleDigest,
      now: 0n
    }).tupleDigest,
    tupleDigest
  )

  encoded[0] ^= 1
  expectCode(
    t,
    () =>
      verifyTestIsolatedAddressGrant(encoded, pair.publicKey, {
        runNonce: seed(0x03, 16),
        exitRole: 5,
        generation: 7n,
        tupleDigest,
        now: 1_000n
      }),
    'ERR_AUTHENTICATION'
  )
})

test('test isolated address grant verification is exact and expires', (t) => {
  const pair = cryptoSuite.keyPair(seed(0x04))
  const tupleDigest = digestTestIsolatedAddressTuple({
    tuple: { host: '8.8.8.8', port: 49737 },
    id: seed(0x05),
    exitRole: 2,
    generation: 11n
  })
  const encoded = encodeTestIsolatedAddressGrant(
    {
      runNonce: seed(0x06, 16),
      exitRole: 2,
      generation: 11n,
      grantSequence: 1n,
      expiresAt: 2_000n,
      tupleDigest
    },
    pair.secretKey
  )

  expectCode(
    t,
    () =>
      verifyTestIsolatedAddressGrant(encoded, pair.publicKey, {
        runNonce: seed(0x07, 16),
        exitRole: 2,
        generation: 11n,
        tupleDigest,
        now: 1_000n
      }),
    'ERR_AUTHENTICATION'
  )
  expectCode(
    t,
    () =>
      verifyTestIsolatedAddressGrant(encoded, pair.publicKey, {
        runNonce: seed(0x06, 16),
        exitRole: 2,
        generation: 11n,
        tupleDigest,
        now: 2_000n
      }),
    'ERR_AUTHENTICATION'
  )
})
