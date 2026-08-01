'use strict'

const b4a = require('b4a')
const sodium = require('sodium-universal')

const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')

const TEST_ISOLATED_ADDRESS_GRANT_SIZE = 137
const MAX_U64 = 0xffff_ffff_ffff_ffffn
const GRANT_DOMAIN = b4a.from('hyperdht-private-routes/test/isolated-address-grant/v1')
const TUPLE_DOMAIN = b4a.from('hyperdht-private-routes/test/isolated-address-tuple/v1')
const TEST_TOPOLOGY_AUTHORITIES = new WeakMap()
const SPENT_TEST_TOPOLOGY_AUTHORITIES = new WeakSet()
const TEST_ONLY_DHT_EXIT_TOPOLOGY_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-dht-exit-topology-issuer'
)
const GRANT_FIELDS = Object.freeze([
  'runNonce',
  'exitRole',
  'generation',
  'grantSequence',
  'expiresAt',
  'tupleDigest'
])
const VERIFY_FIELDS = Object.freeze(['runNonce', 'exitRole', 'generation', 'tupleDigest', 'now'])
const TUPLE_FIELDS = Object.freeze(['tuple', 'id', 'exitRole', 'generation'])

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function authentication() {
  throw PrivateRouteError.ERR_AUTHENTICATION()
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function exactOwnData(value, fields) {
  if (!isObject(value) || Reflect.ownKeys(value).length !== fields.length) invalid()
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field)
    if (!descriptor || !('value' in descriptor)) invalid()
  }
}

function fixed(value, size) {
  if (!b4a.isBuffer(value) || value.byteLength !== size) invalid()
  return b4a.from(value)
}

function uint8(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xff) invalid()
  return value
}

function uint64(value) {
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) invalid()
  return value
}

function tuple(value) {
  exactOwnData(value, ['host', 'port'])
  if (typeof value.host !== 'string' || !Number.isSafeInteger(value.port)) invalid()
  const parts = value.host.split('.')
  if (parts.length !== 4 || value.port < 0 || value.port > 0xffff) invalid()
  const out = b4a.allocUnsafeSlow(6)
  for (let i = 0; i < 4; i++) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(parts[i])) invalid()
    const byte = Number(parts[i])
    if (byte > 255) invalid()
    out[i] = byte
  }
  out[4] = value.port
  out[5] = value.port >> 8
  return out
}

function writeU64(target, value, offset) {
  for (let i = offset + 7; i >= offset; i--) {
    target[i] = Number(value & 0xffn)
    value >>= 8n
  }
}

function readU64(target, offset) {
  let value = 0n
  for (let i = offset; i < offset + 8; i++) value = (value << 8n) | BigInt(target[i])
  return value
}

function grantInput(body) {
  return b4a.concat([GRANT_DOMAIN, body])
}

function digestTestIsolatedAddressTuple(value) {
  exactOwnData(value, TUPLE_FIELDS)
  const tupleBytes = tuple(value.tuple)
  const body = b4a.allocUnsafeSlow(47)
  body.set(tupleBytes, 0)
  body.set(fixed(value.id, 32), 6)
  body[38] = uint8(value.exitRole)
  writeU64(body, uint64(value.generation), 39)
  const out = b4a.allocUnsafeSlow(32)
  sodium.crypto_generichash(out, b4a.concat([TUPLE_DOMAIN, body]))
  tupleBytes.fill(0)
  body.fill(0)
  return out
}

function encodeGrantBody(value) {
  exactOwnData(value, GRANT_FIELDS)
  const body = b4a.allocUnsafeSlow(TEST_ISOLATED_ADDRESS_GRANT_SIZE - 64)
  body.set(fixed(value.runNonce, 16), 0)
  body[16] = uint8(value.exitRole)
  writeU64(body, uint64(value.generation), 17)
  writeU64(body, uint64(value.grantSequence), 25)
  writeU64(body, uint64(value.expiresAt), 33)
  body.set(fixed(value.tupleDigest, 32), 41)
  return body
}

function encodeTestIsolatedAddressGrant(value, secretKey) {
  const body = encodeGrantBody(value)
  const input = grantInput(body)
  const ownedSecretKey = fixed(secretKey, 64)
  try {
    const signature = cryptoSuite.sign(input, ownedSecretKey)
    if (!b4a.isBuffer(signature) || signature.byteLength !== 64) invalid()
    return b4a.concat([body, signature])
  } finally {
    ownedSecretKey.fill(0)
    body.fill(0)
    input.fill(0)
  }
}

function decodeTestIsolatedAddressGrant(encoded) {
  const input = fixed(encoded, TEST_ISOLATED_ADDRESS_GRANT_SIZE)
  return Object.freeze({
    runNonce: b4a.from(input.subarray(0, 16)),
    exitRole: input[16],
    generation: readU64(input, 17),
    grantSequence: readU64(input, 25),
    expiresAt: readU64(input, 33),
    tupleDigest: b4a.from(input.subarray(41, 73)),
    signature: b4a.from(input.subarray(73, 137))
  })
}

function same(left, right) {
  return b4a.isBuffer(left) && b4a.isBuffer(right) && b4a.equals(left, right)
}

function verifyTestIsolatedAddressGrant(encoded, publicKey, expected) {
  exactOwnData(expected, VERIFY_FIELDS)
  const decoded = decodeTestIsolatedAddressGrant(encoded)
  const body = fixed(encoded, TEST_ISOLATED_ADDRESS_GRANT_SIZE).subarray(0, 73)
  const input = grantInput(body)
  const current = uint64(expected.now)
  try {
    if (
      !same(decoded.runNonce, expected.runNonce) ||
      decoded.exitRole !== expected.exitRole ||
      decoded.generation !== expected.generation ||
      !same(decoded.tupleDigest, expected.tupleDigest) ||
      current >= decoded.expiresAt ||
      !cryptoSuite.verify(input, decoded.signature, fixed(publicKey, 32))
    ) {
      authentication()
    }
    return decoded
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    authentication()
  } finally {
    input.fill(0)
  }
}

function createTestDhtExitTopologyAuthority(tuples) {
  if (!Array.isArray(tuples) || tuples.length < 1 || tuples.length > 64) invalid()
  const permitted = new Set()
  for (const value of tuples) {
    const encoded = tuple(value)
    const key = b4a.toString(encoded, 'hex')
    encoded.fill(0)
    if (permitted.has(key)) invalid()
    permitted.add(key)
  }
  const authority = Object.freeze({})
  TEST_TOPOLOGY_AUTHORITIES.set(authority, permitted)
  return authority
}

function consumeTestDhtExitTopologyAuthority(authority) {
  const permitted =
    authority !== null && typeof authority === 'object'
      ? TEST_TOPOLOGY_AUTHORITIES.get(authority)
      : null
  if (!permitted) {
    if (
      authority !== null &&
      typeof authority === 'object' &&
      SPENT_TEST_TOPOLOGY_AUTHORITIES.has(authority)
    ) {
      throw PrivateRouteError.ERR_REPLAY()
    }
    authentication()
  }
  TEST_TOPOLOGY_AUTHORITIES.delete(authority)
  SPENT_TEST_TOPOLOGY_AUTHORITIES.add(authority)
  return Object.freeze({
    permits(value) {
      const encoded = tuple(value)
      const key = b4a.toString(encoded, 'hex')
      encoded.fill(0)
      return permitted.has(key)
    }
  })
}

module.exports = Object.freeze({
  TEST_ISOLATED_ADDRESS_GRANT_SIZE,
  TEST_ONLY_DHT_EXIT_TOPOLOGY_ISSUER: Object.freeze({
    create: createTestDhtExitTopologyAuthority
  }),
  decodeTestIsolatedAddressGrant,
  digestTestIsolatedAddressTuple,
  encodeTestIsolatedAddressGrant,
  consumeTestDhtExitTopologyAuthority,
  verifyTestIsolatedAddressGrant
})
