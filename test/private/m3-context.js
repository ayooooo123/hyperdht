'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { CONTEXT_CLASS, DIRECTION, M3_PROTOCOL_VERSION } = require('../../lib/private/protocol')
const { PrivateRouteError } = require('../../lib/private/errors')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  M3_CONTEXT_AD_SIZE,
  M3_CONTEXT_ENVELOPE_SIZE,
  encodeM3ContextAD,
  decodeM3ContextAD,
  encodeM3ContextEnvelope,
  decodeM3ContextEnvelope
} = require('../../lib/private/m3-context')

// Adapted from the reviewed private-routes prototype at commit
// 0305df915b6a767093f9e75e6c06bc0a35da6169.

function sequence(start, size) {
  const value = b4a.allocUnsafe(size)
  for (let index = 0; index < size; index++) value[index] = start + index
  return value
}

function uint32(value) {
  return b4a.from([value >>> 24, value >>> 16, value >>> 8, value])
}

function uint64(value) {
  const output = b4a.alloc(8)
  for (let index = 7; index >= 0; index--) {
    output[index] = Number(value & 0xffn)
    value >>= 8n
  }
  return output
}

function expectInvalid(t, operation) {
  let error = null
  try {
    operation()
  } catch (err) {
    error = err
  }
  t.ok(error instanceof PrivateRouteError)
  t.is(error && error.code, 'INVALID_ROUTE')
}

const CONTEXT = Object.freeze({
  contextClass: CONTEXT_CLASS.ROUTE_PAYLOAD,
  branchId: sequence(0x00, 16),
  circuitId: sequence(0x10, 16),
  generation: 0x0102_0304_0506_0708n,
  direction: DIRECTION.REVERSE,
  innerCounter: 0x1112_1314_1516_1718n
})

test('M3 context associated data freezes the exact 54-byte vector', (t) => {
  const expected = b4a.concat([
    b4a.from([CONTEXT_CLASS.ROUTE_PAYLOAD]),
    uint32(M3_PROTOCOL_VERSION),
    sequence(0x00, 16),
    sequence(0x10, 16),
    uint64(0x0102_0304_0506_0708n),
    b4a.from([DIRECTION.REVERSE]),
    uint64(0x1112_1314_1516_1718n)
  ])
  const encoded = encodeM3ContextAD(CONTEXT)

  t.is(M3_CONTEXT_AD_SIZE, 54)
  t.alike(encoded, expected)
  t.alike(decodeM3ContextAD(encoded), CONTEXT)
})

test('M3 context envelope freezes 1,101 bytes and owns decoded frame', (t) => {
  const frame = b4a.alloc(1100, 0x5a)
  const encoded = encodeM3ContextEnvelope({
    contextClass: CONTEXT_CLASS.ROUTE_PAYLOAD,
    frame
  })
  const decoded = decodeM3ContextEnvelope(encoded)

  t.is(M3_CONTEXT_ENVELOPE_SIZE, 1101)
  t.alike(encoded, b4a.concat([b4a.from([CONTEXT_CLASS.ROUTE_PAYLOAD]), frame]))
  encoded.fill(0)
  frame.fill(0)
  t.alike(decoded.frame, b4a.alloc(1100, 0x5a))
})

test('M3 context freezes an authenticated known-answer vector and binds padding bytes', (t) => {
  const key = sequence(0x21, 32)
  const noncePrefix = sequence(0x41, 16)
  const associatedData = encodeM3ContextAD(CONTEXT)
  const plaintext = b4a.from('m3-context-binding:padding=00000000')
  const ciphertext = cryptoSuite.seal({
    key,
    noncePrefix,
    counter: CONTEXT.innerCounter,
    associatedData,
    plaintext
  })
  t.is(
    b4a.toString(ciphertext, 'hex'),
    'e24ed5914b4c95fd95880598e0a273fa54ff36ef89ffc16e7c0d85816bbdb2906a2381c201567a8ee41ccee12beba74ca4430f'
  )
  t.alike(
    cryptoSuite.open({
      key,
      noncePrefix,
      counter: CONTEXT.innerCounter,
      associatedData,
      ciphertext
    }),
    plaintext
  )
  const substitutedPadding = b4a.from(ciphertext)
  substitutedPadding[plaintext.byteLength - 1] ^= 1
  t.is(
    cryptoSuite.open({
      key,
      noncePrefix,
      counter: CONTEXT.innerCounter,
      associatedData,
      ciphertext: substitutedPadding
    }),
    null
  )
})

test('M3 context fields, widths, classes, and trailing bytes fail closed', (t) => {
  const baseline = encodeM3ContextAD(CONTEXT)
  const substitutions = [0, 5, 21, 37, 45, 46]
  const key = b4a.alloc(32, 0x41)
  const noncePrefix = b4a.alloc(16, 0x42)
  const ciphertext = cryptoSuite.seal({
    key,
    noncePrefix,
    counter: CONTEXT.innerCounter,
    associatedData: baseline,
    plaintext: b4a.from('m3-context-binding')
  })
  for (const offset of substitutions) {
    const changed = b4a.from(baseline)
    changed[offset] ^= 1
    t.unlike(changed, baseline)
    t.is(
      cryptoSuite.open({
        key,
        noncePrefix,
        counter: CONTEXT.innerCounter,
        associatedData: changed,
        ciphertext
      }),
      null
    )
  }
  const changedTag = b4a.from(ciphertext)
  changedTag[changedTag.byteLength - 1] ^= 1
  t.is(
    cryptoSuite.open({
      key,
      noncePrefix,
      counter: CONTEXT.innerCounter,
      associatedData: baseline,
      ciphertext: changedTag
    }),
    null
  )
  t.is(
    cryptoSuite.open({
      key,
      noncePrefix,
      counter: CONTEXT.innerCounter + 1n,
      associatedData: baseline,
      ciphertext
    }),
    null
  )

  const wrongVersion = b4a.from(baseline)
  wrongVersion[4] ^= 1
  expectInvalid(t, () => decodeM3ContextAD(wrongVersion))
  const wrongClass = b4a.from(baseline)
  wrongClass[0] = 5
  expectInvalid(t, () => decodeM3ContextAD(wrongClass))
  const wrongDirection = b4a.from(baseline)
  wrongDirection[45] = 2
  expectInvalid(t, () => decodeM3ContextAD(wrongDirection))
  expectInvalid(t, () => encodeM3ContextAD({ ...CONTEXT, branchId: b4a.alloc(15) }))
  expectInvalid(t, () => encodeM3ContextAD({ ...CONTEXT, circuitId: b4a.alloc(17) }))
  expectInvalid(t, () => encodeM3ContextAD({ ...CONTEXT, generation: 1n << 64n }))
  expectInvalid(t, () => encodeM3ContextAD({ ...CONTEXT, innerCounter: -1n }))
  expectInvalid(t, () => decodeM3ContextAD(b4a.concat([baseline, b4a.alloc(1)])))

  const envelope = encodeM3ContextEnvelope({ contextClass: 3, frame: b4a.alloc(1100) })
  const invalidEnvelope = b4a.from(envelope)
  invalidEnvelope[0] = 5
  expectInvalid(t, () => decodeM3ContextEnvelope(invalidEnvelope))
  expectInvalid(t, () => decodeM3ContextEnvelope(b4a.concat([envelope, b4a.alloc(1)])))
  expectInvalid(t, () => encodeM3ContextEnvelope({ contextClass: 3, frame: b4a.alloc(1099) }))
})
