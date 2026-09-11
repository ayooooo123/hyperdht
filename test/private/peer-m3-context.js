'use strict'

const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-universal')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { PrivateRouteError } = require('../../lib/private/errors')
const {
  encodePeerTailControlAD,
  encodePeerTailFinalizeAD,
  encodePeerRouteAD,
  sealPeerContextFrame,
  openPeerContextFrame,
  encodePeerContextEnvelope,
  decodePeerContextEnvelope
} = require('../../lib/private/peer-m3-context')

function sequence(start, size) {
  const output = b4a.allocUnsafe(size)
  for (let index = 0; index < size; index++) output[index] = start + index
  return output
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

const TAIL = Object.freeze({
  circuitId: sequence(0x20, 16),
  generation: 0x0102_0304_0506_0708n,
  direction: 1,
  counter: 0x1112_1314_1516_1718n
})

const ROUTE = Object.freeze({
  routeId: sequence(0x00, 16),
  circuitId: sequence(0x10, 16),
  generation: 0x0102_0304_0506_0708n,
  purpose: 2,
  direction: 0,
  counter: 0x2122_2324_2526_2728n
})

test('v2 class5 and class6 associated data freeze exact vectors', (t) => {
  const tailExpected = b4a.concat([
    b4a.from([5]),
    uint32(2),
    TAIL.circuitId,
    uint64(TAIL.generation),
    b4a.from([TAIL.direction]),
    uint64(TAIL.counter)
  ])
  const routeExpected = b4a.concat([
    b4a.from([6]),
    uint32(2),
    ROUTE.routeId,
    ROUTE.circuitId,
    uint64(ROUTE.generation),
    b4a.from([ROUTE.purpose, ROUTE.direction]),
    uint64(ROUTE.counter)
  ])

  const tail = encodePeerTailFinalizeAD(TAIL)
  const route = encodePeerRouteAD(ROUTE)
  t.is(tail.byteLength, 38)
  t.is(route.byteLength, 55)
  t.alike(tail, tailExpected)
  t.alike(route, routeExpected)

  TAIL.circuitId.fill(0)
  ROUTE.routeId.fill(0)
  ROUTE.circuitId.fill(0)
  t.alike(tail, tailExpected)
  t.alike(route, routeExpected)
})

test('class6 AD binds every field through the native AEAD', (t) => {
  const key = b4a.alloc(32, 0x41)
  const noncePrefix = b4a.alloc(16, 0x61)
  const associatedData = encodePeerRouteAD({
    routeId: b4a.alloc(16, 0x01),
    circuitId: b4a.alloc(16, 0x02),
    generation: 3n,
    purpose: 1,
    direction: 1,
    counter: 4n
  })
  const plaintext = b4a.from('class6 binding')
  const ciphertext = cryptoSuite.seal({
    key,
    noncePrefix,
    counter: 4n,
    associatedData,
    plaintext
  })

  for (const offset of [0, 1, 5, 21, 37, 45, 46, 47, 54]) {
    const changed = b4a.from(associatedData)
    changed[offset] ^= 1
    t.is(
      cryptoSuite.open({
        key,
        noncePrefix,
        counter: 4n,
        associatedData: changed,
        ciphertext
      }),
      null,
      `changed class6 AD byte ${offset} rejects`
    )
  }
})

test('v2 class AD rejects widths, ranges, and accessors', (t) => {
  expectInvalid(t, () => encodePeerTailFinalizeAD({ ...TAIL, circuitId: b4a.alloc(15) }))
  expectInvalid(t, () => encodePeerTailFinalizeAD({ ...TAIL, generation: 1n << 64n }))
  expectInvalid(t, () => encodePeerTailFinalizeAD({ ...TAIL, direction: 2 }))
  expectInvalid(t, () => encodePeerTailFinalizeAD({ ...TAIL, counter: -1n }))
  expectInvalid(t, () => encodePeerTailFinalizeAD(b4a.concat([b4a.alloc(1), b4a.alloc(37)])))

  expectInvalid(t, () => encodePeerRouteAD({ ...ROUTE, routeId: b4a.alloc(15) }))
  expectInvalid(t, () => encodePeerRouteAD({ ...ROUTE, circuitId: b4a.alloc(17) }))
  expectInvalid(t, () => encodePeerRouteAD({ ...ROUTE, purpose: 0 }))
  expectInvalid(t, () => encodePeerRouteAD({ ...ROUTE, purpose: 4 }))
  expectInvalid(t, () => encodePeerRouteAD({ ...ROUTE, direction: 2 }))
  expectInvalid(t, () => encodePeerRouteAD({ ...ROUTE, counter: 1n << 64n }))
  expectInvalid(t, () => encodePeerRouteAD(b4a.concat([b4a.alloc(1), b4a.alloc(54)])))

  let invoked = false
  const accessor = {
    get circuitId() {
      invoked = true
      throw new Error('circuit getter must not run')
    },
    generation: 1n,
    direction: 0,
    counter: 0n
  }
  expectInvalid(t, () => encodePeerTailFinalizeAD(accessor))
  t.is(invoked, false)
})

test('sealPeerContextFrame and openPeerContextFrame round-trip class5 and class6 and verify DATAGRAM marker', (t) => {
  const key = b4a.alloc(32, 0x07)
  const noncePrefix = b4a.alloc(16, 0x08)
  const payload = b4a.from('hello v2 context frame')

  const opts5 = {
    contextClass: 5,
    circuitId: b4a.alloc(16, 0x01),
    generation: 10n,
    direction: 0,
    counter: 0n,
    key,
    noncePrefix,
    payload
  }

  const frame5 = sealPeerContextFrame(opts5)
  t.is(frame5.byteLength, 1100)

  const opened5 = openPeerContextFrame(opts5, frame5)
  t.is(opened5.counter, 0n)
  t.alike(opened5.payload, payload)
  t.is(opened5.plaintext.byteLength, 1076)
  t.is(opened5.plaintext[0], 2, 'decrypted plaintext[0] is DATAGRAM marker (2)')

  const opts6 = {
    contextClass: 6,
    routeId: b4a.alloc(16, 0x02),
    circuitId: b4a.alloc(16, 0x03),
    generation: 15n,
    purpose: 2,
    direction: 1,
    counter: 42n,
    key,
    noncePrefix,
    payload
  }

  const frame6 = sealPeerContextFrame(opts6)
  t.is(frame6.byteLength, 1100)

  const opened6 = openPeerContextFrame(opts6, frame6)
  t.is(opened6.counter, 42n)
  t.alike(opened6.payload, payload)
  t.is(opened6.plaintext[0], 2, 'decrypted plaintext[0] is DATAGRAM marker (2)')
})

test('sealPeerContextFrame handles max payload and empty payload', (t) => {
  const key = b4a.alloc(32, 0x0a)
  const noncePrefix = b4a.alloc(16, 0x0b)
  const maxPayload = b4a.alloc(1073, 0xff)

  const optsMax = {
    contextClass: 5,
    circuitId: b4a.alloc(16, 0x01),
    generation: 1n,
    direction: 0,
    counter: 0n,
    key,
    noncePrefix,
    payload: maxPayload
  }

  const frameMax = sealPeerContextFrame(optsMax)
  t.is(frameMax.byteLength, 1100)

  const openedMax = openPeerContextFrame(optsMax, frameMax)
  t.alike(openedMax.payload, maxPayload)
  t.is(openedMax.plaintext[0], 2)

  const optsEmpty = {
    ...optsMax,
    payload: b4a.alloc(0)
  }

  const frameEmpty = sealPeerContextFrame(optsEmpty)
  t.is(frameEmpty.byteLength, 1100)

  const openedEmpty = openPeerContextFrame(optsEmpty, frameEmpty)
  t.is(openedEmpty.payload.byteLength, 0)
  t.is(openedEmpty.plaintext[0], 2)
})

test('sealPeerContextFrame rejects payload over 1073 bytes or UINT64_MAX counter', (t) => {
  const key = b4a.alloc(32, 0x01)
  const noncePrefix = b4a.alloc(16, 0x02)

  const optsOver = {
    contextClass: 5,
    circuitId: b4a.alloc(16, 0x01),
    generation: 1n,
    direction: 0,
    counter: 0n,
    key,
    noncePrefix,
    payload: b4a.alloc(1074)
  }
  expectInvalid(t, () => sealPeerContextFrame(optsOver))

  const optsCounterMax = {
    ...optsOver,
    payload: b4a.alloc(10),
    counter: 0xffff_ffff_ffff_ffffn
  }
  expectInvalid(t, () => sealPeerContextFrame(optsCounterMax))
})

test('openPeerContextFrame rejects tampered ciphertext, modified AD bindings, and missing/mismatched counter', (t) => {
  const key = b4a.alloc(32, 0x05)
  const noncePrefix = b4a.alloc(16, 0x06)
  const payload = b4a.from('tamper check')

  const opts = {
    contextClass: 6,
    routeId: b4a.alloc(16, 0x01),
    circuitId: b4a.alloc(16, 0x02),
    generation: 1n,
    purpose: 1,
    direction: 0,
    counter: 5n,
    key,
    noncePrefix,
    payload
  }

  const frame = sealPeerContextFrame(opts)

  // Tamper frame byte
  const tamperedFrame = b4a.from(frame)
  tamperedFrame[100] ^= 0xff
  expectInvalid(t, () => openPeerContextFrame(opts, tamperedFrame))

  // Mismatched direction
  expectInvalid(t, () => openPeerContextFrame({ ...opts, direction: 1 }, frame))

  // Mismatched purpose
  expectInvalid(t, () => openPeerContextFrame({ ...opts, purpose: 2 }, frame))

  // Mismatched routeId
  expectInvalid(t, () => openPeerContextFrame({ ...opts, routeId: b4a.alloc(16, 0x99) }, frame))

  // Mismatched counter
  expectInvalid(t, () => openPeerContextFrame({ ...opts, counter: 6n }, frame))

  // Missing counter
  expectInvalid(t, () => openPeerContextFrame({ ...opts, counter: undefined }, frame))
})

test('encodePeerContextEnvelope and decodePeerContextEnvelope round-trip and return owned frame copy', (t) => {
  const frame = b4a.alloc(1100, 0x55)

  const env5 = encodePeerContextEnvelope(5, frame)
  t.is(env5.byteLength, 1101)
  t.is(env5[0], 5)

  const dec5 = decodePeerContextEnvelope(env5)
  t.is(dec5.contextClass, 5)
  t.alike(dec5.frame, frame)

  // Mutating input envelope MUST NOT alter returned frame copy
  env5[10] ^= 0xff
  t.not(dec5.frame[9], env5[10], 'decoded frame is an owned copy, independent of input envelope mutation')

  const env6 = encodePeerContextEnvelope(6, frame)
  t.is(env6.byteLength, 1101)
  t.is(env6[0], 6)

  const dec6 = decodePeerContextEnvelope(env6)
  t.is(dec6.contextClass, 6)
  t.alike(dec6.frame, frame)

  expectInvalid(t, () => encodePeerContextEnvelope(4, frame))
  expectInvalid(t, () => encodePeerContextEnvelope(7, frame))
  expectInvalid(t, () => encodePeerContextEnvelope(5, b4a.alloc(1099)))
  expectInvalid(t, () => decodePeerContextEnvelope(b4a.alloc(1100)))
})

test('native false authentication result rejects and erases plaintext before parsing', (t) => {
  const options = {
    ...ROUTE,
    contextClass: 6,
    key: sequence(0x40, 32),
    noncePrefix: sequence(0x60, 16),
    payload: b4a.from('authenticated')
  }
  const frame = sealPeerContextFrame(options)
  const decrypt = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt
  let attemptedPlaintext = null
  let returned = null
  let error = null
  try {
    sodium.crypto_aead_xchacha20poly1305_ietf_decrypt = (plaintext) => {
      attemptedPlaintext = plaintext
      plaintext.fill(0)
      plaintext[0] = 2
      plaintext[2] = 1
      plaintext[3] = 0x42
      return false
    }
    try {
      returned = openPeerContextFrame(options, frame)
    } catch (err) {
      error = err
    }
  } finally {
    sodium.crypto_aead_xchacha20poly1305_ietf_decrypt = decrypt
  }
  t.is(returned, null, 'unauthenticated plaintext is never returned')
  t.is(error && error.code, 'INVALID_ROUTE')
  t.ok(attemptedPlaintext && attemptedPlaintext.every((byte) => byte === 0), 'failed plaintext is erased')
})
test('v2 contextClass 1 associated data freezes exact vector and rejects invalid metadata', (t) => {
  const branchId = sequence(0x10, 16)
  const circuitId = sequence(0x20, 16)
  const generation = 0x0102030405060708n
  const direction = 1
  const wireCounter = 0x0a0b0c0d0e0f1012n

  const ad = encodePeerTailControlAD({
    branchId,
    circuitId,
    generation,
    direction,
    counter: wireCounter
  })

  t.is(ad.byteLength, 54)
  t.is(ad[0], 1) // contextClass 1
  t.alike(ad.subarray(1, 5), b4a.from([0, 0, 0, 2])) // PEER_PROTOCOL_VERSION 2
  t.alike(ad.subarray(5, 21), branchId)
  t.alike(ad.subarray(21, 37), circuitId)
  t.alike(ad.subarray(37, 45), b4a.from([1, 2, 3, 4, 5, 6, 7, 8]))
  t.is(ad[45], 1)
  t.alike(ad.subarray(46, 54), b4a.from([0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x12]))

  expectInvalid(t, () => encodePeerTailControlAD({ branchId: b4a.alloc(15), circuitId, generation, direction, counter: wireCounter }))
  expectInvalid(t, () => encodePeerTailControlAD({ branchId, circuitId: b4a.alloc(15), generation, direction, counter: wireCounter }))
  expectInvalid(t, () => encodePeerTailControlAD({ branchId, circuitId, generation: 0n, direction, counter: wireCounter }))
  expectInvalid(t, () => encodePeerTailControlAD({ branchId, circuitId, generation, direction: 2, counter: wireCounter }))
})

test('v2 contextClass 1 ordered-only frame sealing, opening, counter encoding, and odd-counter rejection', (t) => {
  const options0 = {
    contextClass: 1,
    branchId: sequence(0x10, 16),
    circuitId: sequence(0x20, 16),
    generation: 1n,
    direction: 0,
    key: sequence(0x30, 32),
    noncePrefix: sequence(0x40, 16),
    counter: 0n,
    payload: b4a.from('tail control 0')
  }

  const frame0 = sealPeerContextFrame(options0)
  t.is(frame0.byteLength, 1100)

  // Verify wire counter 0 in header
  let headerCounter = 0n
  for (let i = 0; i < 8; i++) headerCounter = (headerCounter << 8n) | BigInt(frame0[i])
  t.is(headerCounter, 0n)

  const opened0 = openPeerContextFrame(options0, frame0)
  t.is(opened0.counter, 0n)
  t.is(opened0.logicalCounter, 0n)
  t.alike(opened0.payload, b4a.from('tail control 0'))

  // Logical counter 1 -> wire counter 2
  const options1 = { ...options0, counter: 1n, payload: b4a.from('tail control 1') }
  const frame1 = sealPeerContextFrame(options1)
  let headerCounter1 = 0n
  for (let i = 0; i < 8; i++) headerCounter1 = (headerCounter1 << 8n) | BigInt(frame1[i])
  t.is(headerCounter1, 2n, 'logical counter 1 encodes to wire counter 2 for ordered class 1')

  const opened1 = openPeerContextFrame(options1, frame1)
  t.is(opened1.counter, 2n)
  t.is(opened1.logicalCounter, 1n)
  t.alike(opened1.payload, b4a.from('tail control 1'))

  // Compare with Class 5 counter 1 -> wire counter 1
  const optionsClass5 = {
    contextClass: 5,
    circuitId: sequence(0x20, 16),
    generation: 1n,
    direction: 0,
    key: sequence(0x30, 32),
    noncePrefix: sequence(0x40, 16),
    counter: 1n,
    payload: b4a.from('tail finalize 1')
  }
  const frameClass5 = sealPeerContextFrame(optionsClass5)
  let headerCounter5 = 0n
  for (let i = 0; i < 8; i++) headerCounter5 = (headerCounter5 << 8n) | BigInt(frameClass5[i])
  t.is(headerCounter5, 1n, 'unmodified class 5 uses wire counter 1')

  // Authenticated odd-counter rejection test for class 1
  // Construct a frame manually with wire counter 1 (odd) and valid AEAD encrypt
  const oddWireCounter = 1n
  const adOdd = encodePeerTailControlAD({
    branchId: options0.branchId,
    circuitId: options0.circuitId,
    generation: options0.generation,
    direction: options0.direction,
    counter: oddWireCounter
  })
  const plaintextOdd = b4a.alloc(1076)
  plaintextOdd[0] = 1 // STREAM1
  plaintextOdd[1] = 0
  plaintextOdd[2] = 4
  plaintextOdd.set(b4a.from('test'), 3)

  const nonceOdd = b4a.alloc(24)
  nonceOdd.set(options0.noncePrefix, 0)
  nonceOdd.writeBigUInt64BE(oddWireCounter, 16)

  const frameOdd = b4a.alloc(1100)
  frameOdd[7] = 1 // header wire counter 1
  sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    frameOdd.subarray(8),
    plaintextOdd,
    adOdd,
    null,
    nonceOdd,
    options0.key
  )

  // Decryption of frameOdd succeeds at AEAD layer, but parity check (odd wire counter) rejects post-auth
  expectInvalid(t, () => openPeerContextFrame({ ...options0, counter: 0n }, frameOdd))

  // Reordering rejection test
  expectInvalid(t, () => openPeerContextFrame({ ...options0, counter: 0n }, frame1))

  // Exhaustion / bounds check
  expectInvalid(t, () => sealPeerContextFrame({ ...options0, counter: 1n << 63n }))

  // Envelope round trip for class 1
  const env1 = encodePeerContextEnvelope(1, frame0)
  t.is(env1.byteLength, 1101)
  t.is(env1[0], 1)
  const dec1 = decodePeerContextEnvelope(env1)
  t.is(dec1.contextClass, 1)
  t.alike(dec1.frame, frame0)
})
