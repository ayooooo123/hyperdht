'use strict'

const b4a = require('b4a')
const test = require('brittle')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { encodeDestinationRef } = require('../../lib/private/destination-ref')
const { PrivateRouteError } = require('../../lib/private/errors')
const {
  BRANCH_CLASS,
  DOMAIN,
  M3_MESSAGE_ID,
  M3_PROTOCOL_VERSION,
  encodeM3Object
} = require('../../lib/private/protocol')
const {
  DHT_EXIT_DHT_SEEDS_BODY_FIXED_SIZE,
  DHT_EXIT_DHT_SEEDS_MAX_COUNT,
  DHT_EXIT_DHT_SEEDS_MIN_COUNT,
  decodeDhtExitSeeds,
  encodeDhtExitSeeds,
  signDhtExitSeeds,
  verifyDhtExitSeeds,
  clearDhtExitSeeds
} = require('../../lib/private/dht-exit-seeds')

const FIXED_VECTORS = Object.freeze({
  1: Object.freeze({
    digest: '6b026b4c6036b33a60f605f5269ab864a5c3c76f7ec8c9bb379d47e5f2e1a538',
    signature:
      '0700851580b1d2068c6ce7ef04d2138ecb05e09616a481736bf17fc7d7b13f8e355fe826951e1b36e592d10f21da0507a871e46bcc6b93355c57d52649f2270f'
  }),
  3: Object.freeze({
    digest: 'a8bb2bd6fa7e2b3106cf4876d983f20bf1ae5a80177b31beaf4c9eda1d2002e0',
    signature:
      'bce17f98dcea64abc2e53dfb62da2c2cc9647daf1c5d34de0dd4f63b61294c6c0b59111c2dbb3b7a1cd11a1c470b332139cfe738dadde048da986016166edb0b'
  })
})

function seed(value, size = 32) {
  return b4a.alloc(size, value)
}

function writeUint16(target, value, offset) {
  target[offset] = value >>> 8
  target[offset + 1] = value
}

function writeUint32(target, value, offset) {
  target[offset] = value >>> 24
  target[offset + 1] = value >>> 16
  target[offset + 2] = value >>> 8
  target[offset + 3] = value
}

function writeUint64(target, value, offset) {
  for (let index = offset + 7; index >= offset; index--) {
    target[index] = Number(value & 0xffn)
    value >>= 8n
  }
}

function signatureInput(messageId, body) {
  const domain = DOMAIN.DHT_EXIT_DHT_SEEDS
  const input = b4a.alloc(10 + domain.byteLength + body.byteLength)
  writeUint16(input, domain.byteLength, 0)
  input.set(domain, 2)
  writeUint32(input, M3_PROTOCOL_VERSION, 2 + domain.byteLength)
  writeUint16(input, messageId, 6 + domain.byteLength)
  writeUint16(input, body.byteLength, 8 + domain.byteLength)
  input.set(body, 10 + domain.byteLength)
  return input
}

function digestInput(refs) {
  const domain = DOMAIN.DHT_EXIT_DHT_SEEDS_SET
  const input = b4a.alloc(3 + domain.byteLength + refs.length * 172)
  writeUint16(input, domain.byteLength, 0)
  input.set(domain, 2)
  input[2 + domain.byteLength] = refs.length
  let offset = 3 + domain.byteLength
  for (const ref of refs) {
    input.set(ref, offset)
    offset += 172
  }
  return input
}

function destination(idByte, handleByte) {
  return encodeDestinationRef({ id: seed(idByte), handle: seed(handleByte, 130) })
}

function vector(count) {
  const exit = cryptoSuite.keyPair(seed(0x90 + count))
  const destinationRefs = [
    destination(0x31, 0x41),
    destination(0x32, 0x40),
    destination(0x33, 0x3f)
  ].slice(0, count)
  return {
    value: {
      branchClass: BRANCH_CLASS.LOOKUP,
      branchId: seed(0x11, 16),
      circuitId: seed(0x12, 16),
      generation: 7n,
      exitIdentity: exit.publicKey,
      seedSetNonce: seed(0x13),
      destinationRefs
    },
    exit
  }
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

test('DHT_EXIT_DHT_SEEDS_V1 has exact min/max vectors and domains', (t) => {
  t.is(M3_MESSAGE_ID.DHT_EXIT_DHT_SEEDS_V1, 0x0045)
  t.is(M3_MESSAGE_ID.DHT_EXIT_SEEDS_V1, 0x0044)
  t.is(DHT_EXIT_DHT_SEEDS_BODY_FIXED_SIZE, 138)
  t.is(DHT_EXIT_DHT_SEEDS_MIN_COUNT, 1)
  t.is(DHT_EXIT_DHT_SEEDS_MAX_COUNT, 3)
  const oldMinimum = encodeM3Object({
    messageId: M3_MESSAGE_ID.DHT_EXIT_SEEDS_V1,
    body: seed(0x04, 905),
    authSuffix: seed(0x44, 64)
  })
  const oldMaximum = encodeM3Object({
    messageId: M3_MESSAGE_ID.DHT_EXIT_SEEDS_V1,
    body: seed(0x05, 4265),
    authSuffix: seed(0x45, 64)
  })
  expectCode(t, () => decodeDhtExitSeeds(oldMinimum), 'INVALID_ROUTE')
  expectCode(t, () => decodeDhtExitSeeds(oldMaximum), 'INVALID_ROUTE')
  t.is(oldMinimum.byteLength, 977)
  t.is(oldMaximum.byteLength, 4337)
  expectCode(
    t,
    () =>
      encodeM3Object({
        messageId: M3_MESSAGE_ID.DHT_EXIT_SEEDS_V1,
        body: seed(0x06, 904),
        authSuffix: seed(0x46, 64)
      }),
    'INVALID_ROUTE'
  )

  for (const count of [1, 3]) {
    const { value, exit } = vector(count)
    const signed = signDhtExitSeeds(value, exit.secretKey)
    const encoded = encodeDhtExitSeeds(signed)
    const decoded = decodeDhtExitSeeds(encoded)
    const bodyBytes = 138 + 172 * count

    t.is(signed.seedSetDigest.byteLength, 32)
    t.alike(signed.seedSetDigest, b4a.from(FIXED_VECTORS[count].digest, 'hex'))
    t.alike(signed.seedSetDigest, cryptoSuite.hash([digestInput(value.destinationRefs)]))
    t.alike(signed.signature, b4a.from(FIXED_VECTORS[count].signature, 'hex'))
    t.is(encoded.byteLength, 8 + bodyBytes + 64)
    t.is(encoded.readUInt32BE(0), M3_PROTOCOL_VERSION)
    t.is(encoded.readUInt16BE(4), M3_MESSAGE_ID.DHT_EXIT_DHT_SEEDS_V1)
    t.is(encoded.readUInt16BE(6), bodyBytes)
    t.is(decoded.destinationRefs.length, count)
    t.alike(decoded.branchId, value.branchId)
    t.alike(decoded.circuitId, value.circuitId)
    t.is(decoded.generation, value.generation)
    t.alike(decoded.exitIdentity, exit.publicKey)
    t.alike(decoded.seedSetDigest, signed.seedSetDigest)
    t.alike(
      encoded.subarray(8 + bodyBytes),
      cryptoSuite.sign(signatureInput(0x0045, encoded.subarray(8, 8 + bodyBytes)), exit.secretKey)
    )
    t.alike(
      verifyDhtExitSeeds(
        encoded,
        {
          branchClass: value.branchClass,
          branchId: value.branchId,
          circuitId: value.circuitId,
          generation: value.generation,
          exitIdentity: exit.publicKey,
          expiresAt: 20_000n
        },
        10_000n
      ).seedSetNonce,
      value.seedSetNonce
    )
    clearDhtExitSeeds(decoded)
  }
})

test('DHT_EXIT_DHT_SEEDS_V1 rejects invalid count order duplicates and signatures', (t) => {
  const { value, exit } = vector(2)
  const signed = signDhtExitSeeds(value, exit.secretKey)
  const encoded = encodeDhtExitSeeds(signed)

  expectCode(
    t,
    () => signDhtExitSeeds({ ...value, destinationRefs: [] }, exit.secretKey),
    'INVALID_ROUTE'
  )
  expectCode(
    t,
    () =>
      signDhtExitSeeds(
        {
          ...value,
          destinationRefs: [
            destination(0x31, 0x41),
            destination(0x32, 0x42),
            destination(0x33, 0x43),
            destination(0x34, 0x44)
          ]
        },
        exit.secretKey
      ),
    'INVALID_ROUTE'
  )
  expectCode(
    t,
    () =>
      signDhtExitSeeds(
        Object.defineProperty({ ...value }, 'branchClass', {
          get() {
            throw new Error('getter must not run')
          }
        }),
        exit.secretKey
      ),
    'INVALID_ROUTE'
  )
  expectCode(
    t,
    () =>
      signDhtExitSeeds(
        { ...value, destinationRefs: [destination(0x31, 0x41), destination(0x31, 0x41)] },
        exit.secretKey
      ),
    'INVALID_ROUTE'
  )
  expectCode(
    t,
    () =>
      signDhtExitSeeds(
        { ...value, destinationRefs: [destination(0x32, 0x41), destination(0x31, 0x42)] },
        exit.secretKey
      ),
    'INVALID_ROUTE'
  )
  expectCode(t, () => decodeDhtExitSeeds(b4a.concat([encoded, seed(0x01, 1)])), 'INVALID_ROUTE')
  const tampered = b4a.from(encoded)
  tampered[tampered.byteLength - 1] ^= 1
  expectCode(
    t,
    () =>
      verifyDhtExitSeeds(
        tampered,
        {
          branchClass: value.branchClass,
          branchId: value.branchId,
          circuitId: value.circuitId,
          generation: value.generation,
          exitIdentity: exit.publicKey,
          expiresAt: 20_000n
        },
        10_000n
      ),
    'ERR_AUTHENTICATION'
  )
  expectCode(
    t,
    () =>
      verifyDhtExitSeeds(
        encoded,
        {
          branchClass: BRANCH_CLASS.ANNOUNCE,
          branchId: value.branchId,
          circuitId: value.circuitId,
          generation: value.generation,
          exitIdentity: exit.publicKey,
          expiresAt: 20_000n
        },
        10_000n
      ),
    'ERR_AUTHENTICATION'
  )
  expectCode(
    t,
    () =>
      verifyDhtExitSeeds(
        encoded,
        {
          branchClass: value.branchClass,
          branchId: value.branchId,
          circuitId: value.circuitId,
          generation: value.generation,
          exitIdentity: exit.publicKey,
          expiresAt: 20_000n
        },
        20_000n
      ),
    'ERR_AUTHENTICATION'
  )

  const cleared = decodeDhtExitSeeds(encoded)
  clearDhtExitSeeds(cleared)
  t.alike(cleared.branchId, seed(0, 16))
  t.alike(cleared.circuitId, seed(0, 16))
  t.alike(cleared.exitIdentity, seed(0))
  t.alike(cleared.seedSetNonce, seed(0))
  t.alike(cleared.seedSetDigest, seed(0))
  t.alike(cleared.destinationRefs[0], seed(0, 172))
})
