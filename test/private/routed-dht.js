'use strict'

const test = require('brittle')
const b4a = require('b4a')

const {
  DESTINATION_REF_SIZE,
  ROUTED_REQUEST_FIXED_BODY_SIZE,
  clearRoutedRequest,
  decodeDestinationRef,
  decodeRoutedRequest,
  encodeDestinationRef,
  encodeRoutedRequest,
  validateRoutedRequestForExit
} = require('../../lib/private/routed-dht')
const { PrivateRouteError } = require('../../lib/private/errors')
const { BRANCH_CLASS, M3_MESSAGE_ID } = require('../../lib/private/protocol')

const COMMANDS = Object.freeze([
  [M3_MESSAGE_ID.IMMUTABLE_GET_V1, 32, 32, true, true],
  [M3_MESSAGE_ID.IMMUTABLE_PUT_V1, 67, 1090, false, true],
  [M3_MESSAGE_ID.MUTABLE_GET_V1, 40, 40, true, true],
  [M3_MESSAGE_ID.MUTABLE_PUT_V1, 171, 1066, false, true],
  [M3_MESSAGE_ID.PRIVATE_FIND_NODE_V1, 69, 69, true, true],
  [M3_MESSAGE_ID.PRIVATE_LOOKUP_V1, 134, 134, true, false],
  [M3_MESSAGE_ID.PRIVATE_PREPARE_V1, 189, 189, false, true],
  [M3_MESSAGE_ID.PRIVATE_ANNOUNCE_V1, 394, 1161, false, true],
  [M3_MESSAGE_ID.PRIVATE_UNANNOUNCE_V1, 393, 393, false, true]
])

function expectCode(t, operation, code) {
  let error = null
  try {
    operation()
  } catch (err) {
    error = err
  }
  t.ok(error instanceof PrivateRouteError)
  t.is(error && error.code, code)
}

function seed(byte, size) {
  return b4a.alloc(size, byte)
}

function destination() {
  return { id: seed(0x11, 32), handle: seed(0x12, 130) }
}

function request(overrides = {}) {
  return encodeRoutedRequest({
    requestId: seed(0x21, 16),
    operationClass: BRANCH_CLASS.LOOKUP,
    commandId: M3_MESSAGE_ID.IMMUTABLE_GET_V1,
    absoluteDeadlineMs: 4_000n,
    destination: destination(),
    encodedBody: seed(0x22, 32),
    ...overrides
  })
}

function u16(value) {
  return b4a.from([value >>> 8, value])
}

function u32(value) {
  return b4a.from([value >>> 24, value >>> 16, value >>> 8, value])
}

function u64(value) {
  const result = b4a.alloc(8)
  for (let index = 7; index >= 0; index--) {
    result[index] = Number(value & 0xffn)
    value >>= 8n
  }
  return result
}

function m3(messageId, body) {
  return b4a.concat([u32(1), u16(messageId), u16(body.byteLength), body])
}

function expectedDestination() {
  return m3(
    M3_MESSAGE_ID.DESTINATION_REF_V1,
    b4a.concat([seed(0x11, 32), u16(130), seed(0x12, 130)])
  )
}

function expectedRequest() {
  const body = b4a.concat([
    seed(0x21, 16),
    b4a.from([BRANCH_CLASS.LOOKUP]),
    u16(M3_MESSAGE_ID.IMMUTABLE_GET_V1),
    u16(1),
    b4a.from([0, 1]),
    u32(4706),
    u32(4445),
    u32(1),
    u32(2),
    u64(4_000n),
    expectedDestination(),
    u16(32),
    seed(0x22, 32)
  ])
  return m3(M3_MESSAGE_ID.ROUTED_REQUEST_V1, body)
}

function allZero(value) {
  for (const byte of value) {
    if (byte !== 0) return false
  }
  return true
}

function hostileOption(name, value) {
  const options = {}
  Object.defineProperty(options, name, {
    get() {
      throw new Error('accessor must not run')
    }
  })
  for (const [key, item] of Object.entries(value)) {
    if (key !== name) options[key] = item
  }
  return options
}

test('DESTINATION_REF_V1 has exact bytes and transfers immutable owned values', (t) => {
  const value = destination()
  const encoded = encodeDestinationRef(value)
  const decoded = decodeDestinationRef(encoded)

  t.is(DESTINATION_REF_SIZE, 172)
  t.is(encoded.byteLength, DESTINATION_REF_SIZE)
  t.alike(encoded, expectedDestination())
  t.alike(decoded, value)
  t.ok(Object.isFrozen(decoded))
  t.absent(decoded.id === value.id)
  t.absent(decoded.handle === value.handle)

  value.id.fill(0)
  value.handle.fill(0)
  encoded.fill(0)
  t.alike(decoded.id, seed(0x11, 32))
  t.alike(decoded.handle, seed(0x12, 130))
})

test('destination encoder accepts exact own data properties only', (t) => {
  const value = destination()
  for (const invalid of [
    { id: seed(1, 31), handle: value.handle },
    { id: value.id, handle: seed(1, 129) },
    Object.create(value),
    hostileOption('id', value),
    null,
    []
  ]) {
    expectCode(t, () => encodeDestinationRef(invalid), 'INVALID_ROUTE')
  }

  const trapped = new Proxy(value, {
    getOwnPropertyDescriptor() {
      throw new Error('descriptor trap')
    }
  })
  expectCode(t, () => encodeDestinationRef(trapped), 'INVALID_ROUTE')
})

test('ROUTED_REQUEST_V1 has exact immutable-get bytes and bound policy fields', (t) => {
  const encoded = request()
  const decoded = decodeRoutedRequest(encoded)

  t.is(ROUTED_REQUEST_FIXED_BODY_SIZE, 221)
  t.is(encoded.byteLength, 261)
  t.alike(encoded, expectedRequest())
  t.alike(decoded.requestId, seed(0x21, 16))
  t.is(decoded.operationClass, BRANCH_CLASS.LOOKUP)
  t.is(decoded.commandId, M3_MESSAGE_ID.IMMUTABLE_GET_V1)
  t.is(decoded.commandVersion, 1)
  t.is(decoded.mutationFlag, 0)
  t.is(decoded.destinationValidationClass, 1)
  t.is(decoded.maxResponseBytes, 4706)
  t.is(decoded.maxAmplificationBytes, 4445)
  t.is(decoded.requestCost, 1)
  t.is(decoded.responseCost, 2)
  t.is(decoded.absoluteDeadlineMs, 4_000n)
  t.alike(decoded.destination, destination())
  t.alike(decoded.destinationEncoded, expectedDestination())
  t.alike(decoded.encodedBody, seed(0x22, 32))
  t.ok(Object.isFrozen(decoded))
  t.ok(Object.isFrozen(decoded.destination))

  encoded.fill(0)
  t.alike(decoded.requestId, seed(0x21, 16))
  t.alike(decoded.encodedBody, seed(0x22, 32))
  clearRoutedRequest(decoded)
})

test('routed command table preserves every body bound and branch permission', (t) => {
  for (const [commandId, minimum, maximum, lookup, announce] of COMMANDS) {
    for (const [operationClass, allowed] of [
      [BRANCH_CLASS.LOOKUP, lookup],
      [BRANCH_CLASS.ANNOUNCE, announce]
    ]) {
      const operation = () =>
        request({ commandId, operationClass, encodedBody: seed(commandId & 0xff, minimum) })
      if (allowed) {
        const decoded = decodeRoutedRequest(operation())
        t.is(decoded.commandId, commandId)
        t.is(decoded.operationClass, operationClass)
        clearRoutedRequest(decoded)

        const maximumDecoded = decodeRoutedRequest(
          request({
            commandId,
            operationClass,
            encodedBody: seed((commandId + 1) & 0xff, maximum)
          })
        )
        t.is(maximumDecoded.commandId, commandId)
        t.is(maximumDecoded.operationClass, operationClass)
        t.is(maximumDecoded.encodedBody.byteLength, maximum)
        clearRoutedRequest(maximumDecoded)
      } else {
        expectCode(t, operation, 'ERR_AUTHENTICATION')
      }
    }

    if (minimum > 0) {
      expectCode(
        t,
        () => request({ commandId, encodedBody: seed(1, minimum - 1) }),
        'INVALID_ROUTE'
      )
    }
    expectCode(t, () => request({ commandId, encodedBody: seed(1, maximum + 1) }), 'INVALID_ROUTE')
  }
})

test('routed request requires a 16-byte ID, uint64 deadline, and own data options', (t) => {
  for (const invalid of [
    { requestId: seed(1, 15) },
    { requestId: seed(1, 17) },
    { absoluteDeadlineMs: -1n },
    { absoluteDeadlineMs: 0x1_0000_0000_0000_0000n },
    { absoluteDeadlineMs: 1 },
    { commandId: 0xffff }
  ]) {
    expectCode(t, () => request(invalid), 'INVALID_ROUTE')
  }

  const base = {
    requestId: seed(0x21, 16),
    operationClass: BRANCH_CLASS.LOOKUP,
    commandId: M3_MESSAGE_ID.IMMUTABLE_GET_V1,
    absoluteDeadlineMs: 4_000n,
    destination: destination(),
    encodedBody: seed(0x22, 32)
  }
  expectCode(t, () => encodeRoutedRequest(Object.create(base)), 'INVALID_ROUTE')
  for (const name of Object.keys(base)) {
    expectCode(t, () => encodeRoutedRequest(hostileOption(name, base)), 'INVALID_ROUTE')
  }

  const maximum = decodeRoutedRequest(request({ absoluteDeadlineMs: 0xffff_ffff_ffff_ffffn }))
  t.is(maximum.absoluteDeadlineMs, 0xffff_ffff_ffff_ffffn)
  clearRoutedRequest(maximum)
})

test('decode rejects tampered policy, command, framing, and body size canonically', (t) => {
  const encoded = request()
  for (const offset of [19, 21, 22, 23, 27, 31, 35]) {
    const policy = b4a.from(encoded)
    policy[8 + offset] ^= 1
    expectCode(t, () => decodeRoutedRequest(policy), 'ERR_AUTHENTICATION')
  }

  const command = request({
    operationClass: BRANCH_CLASS.ANNOUNCE,
    commandId: M3_MESSAGE_ID.IMMUTABLE_PUT_V1,
    encodedBody: seed(0x31, 394)
  })
  command[8 + 17] = M3_MESSAGE_ID.PRIVATE_ANNOUNCE_V1 >>> 8
  command[8 + 18] = M3_MESSAGE_ID.PRIVATE_ANNOUNCE_V1
  expectCode(t, () => decodeRoutedRequest(command), 'ERR_AUTHENTICATION')

  const unknown = b4a.from(encoded)
  unknown[8 + 17] = 0xff
  unknown[8 + 18] = 0xff
  expectCode(t, () => decodeRoutedRequest(unknown), 'INVALID_ROUTE')

  for (const invalid of [
    encoded.subarray(0, -1),
    b4a.concat([encoded, b4a.from([0])]),
    encoded.subarray(0, ROUTED_REQUEST_FIXED_BODY_SIZE + 7)
  ]) {
    expectCode(t, () => decodeRoutedRequest(invalid), 'INVALID_ROUTE')
  }
})

test('tampered and malformed requests fail before destination authority IO', (t) => {
  const encoded = request()
  const changedPolicy = b4a.from(encoded)
  changedPolicy[8 + 27] ^= 1
  const changedCommand = request({
    operationClass: BRANCH_CLASS.ANNOUNCE,
    commandId: M3_MESSAGE_ID.IMMUTABLE_PUT_V1,
    encodedBody: seed(0x31, 394)
  })
  changedCommand[8 + 17] = M3_MESSAGE_ID.PRIVATE_ANNOUNCE_V1 >>> 8
  changedCommand[8 + 18] = M3_MESSAGE_ID.PRIVATE_ANNOUNCE_V1
  const unknown = b4a.from(encoded)
  unknown[8 + 17] = 0xff
  unknown[8 + 18] = 0xff

  let authorityCalls = 0
  for (const [value, code] of [
    [changedPolicy, 'ERR_AUTHENTICATION'],
    [changedCommand, 'ERR_AUTHENTICATION'],
    [unknown, 'INVALID_ROUTE'],
    [encoded.subarray(0, -1), 'INVALID_ROUTE'],
    [b4a.concat([encoded, b4a.from([0])]), 'INVALID_ROUTE']
  ]) {
    expectCode(
      t,
      () =>
        validateRoutedRequestForExit(value, {
          now: () => 1_000n,
          branchClass: BRANCH_CLASS.LOOKUP,
          verifyDestination() {
            authorityCalls++
            return true
          }
        }),
      code
    )
  }
  t.is(authorityCalls, 0)
})

test('exit validation authenticates branch, deadline, and destination before route IO', (t) => {
  const encoded = request()
  let verified = 0
  const decoded = validateRoutedRequestForExit(encoded, {
    now: () => 1_000,
    branchClass: BRANCH_CLASS.LOOKUP,
    verifyDestination(value) {
      verified++
      t.alike(value.destination, destination())
      t.alike(value.destinationEncoded, expectedDestination())
      t.is(value.destinationValidationClass, 1)
      t.is(value.absoluteDeadlineMs, 4_000n)
      t.is(value.commandId, M3_MESSAGE_ID.IMMUTABLE_GET_V1)
      return true
    }
  })
  t.is(verified, 1)
  clearRoutedRequest(decoded)

  for (const [overrides, code] of [
    [{ branchClass: BRANCH_CLASS.ANNOUNCE }, 'ERR_AUTHENTICATION'],
    [{ now: () => 4_001n }, 'ERR_AUTHENTICATION'],
    [{ now: () => 999n }, 'ERR_AUTHENTICATION'],
    [{ now: () => -1n }, 'INVALID_ROUTE'],
    [{ now: () => 1.5 }, 'INVALID_ROUTE']
  ]) {
    let calls = 0
    expectCode(
      t,
      () =>
        validateRoutedRequestForExit(encoded, {
          now: () => 1_000n,
          branchClass: BRANCH_CLASS.LOOKUP,
          verifyDestination() {
            calls++
            return true
          },
          ...overrides
        }),
      code
    )
    t.is(calls, 0)
  }

  expectCode(
    t,
    () =>
      validateRoutedRequestForExit(encoded, {
        now: () => 1_000n,
        branchClass: BRANCH_CLASS.LOOKUP,
        verifyDestination: () => false
      }),
    'ERR_AUTHENTICATION'
  )
})

test('hostile validation options fail before destination authority', (t) => {
  const encoded = request()
  const base = {
    now: () => 1_000n,
    branchClass: BRANCH_CLASS.LOOKUP,
    verifyDestination: () => true
  }
  let authorityCalls = 0

  for (const name of Object.keys(base)) {
    const hostile = hostileOption(name, {
      ...base,
      verifyDestination() {
        authorityCalls++
        return true
      }
    })
    expectCode(t, () => validateRoutedRequestForExit(encoded, hostile), 'INVALID_ROUTE')
  }
  expectCode(t, () => validateRoutedRequestForExit(encoded, Object.create(base)), 'INVALID_ROUTE')
  const trapped = new Proxy(base, {
    getOwnPropertyDescriptor() {
      throw new Error('descriptor trap')
    }
  })
  expectCode(t, () => validateRoutedRequestForExit(encoded, trapped), 'INVALID_ROUTE')
  t.is(authorityCalls, 0)
})

test('callbacks cannot mutate authenticated returned bytes or captured intrinsics', (t) => {
  const encoded = request()
  const original = b4a.from(encoded)
  const saved = {
    ceil: Math.ceil,
    safe: Number.isSafeInteger,
    isBuffer: b4a.isBuffer,
    apply: Reflect.apply,
    construct: Reflect.construct,
    array: Array.isArray,
    freeze: Object.freeze,
    descriptor: Object.getOwnPropertyDescriptor,
    set: Uint8Array.prototype.set,
    fill: Uint8Array.prototype.fill,
    subarray: Uint8Array.prototype.subarray,
    BigInt: globalThis.BigInt
  }
  const BufferConstructor = b4a.alloc(0).constructor
  const allocate = BufferConstructor.allocUnsafe
  const allocateSlow = BufferConstructor.allocUnsafeSlow
  let callbackValue = null
  let decoded

  try {
    decoded = validateRoutedRequestForExit(encoded, {
      now() {
        encoded.fill(0)
        Math.ceil = () => 0
        Number.isSafeInteger = () => false
        b4a.isBuffer = () => false
        BufferConstructor.allocUnsafe = () => original
        BufferConstructor.allocUnsafeSlow = () => original
        Array.isArray = () => {
          throw new Error('live Array.isArray ran')
        }
        Object.freeze = () => {
          throw new Error('live Object.freeze ran')
        }
        Object.getOwnPropertyDescriptor = () => {
          throw new Error('live descriptor intrinsic ran')
        }
        Reflect.construct = () => {
          throw new Error('live Reflect.construct ran')
        }
        Uint8Array.prototype.set = () => {
          throw new Error('live typed-array set ran')
        }
        Uint8Array.prototype.fill = () => {
          throw new Error('live typed-array fill ran')
        }
        Uint8Array.prototype.subarray = () => {
          throw new Error('live typed-array subarray ran')
        }
        globalThis.BigInt = () => {
          throw new Error('live BigInt ran')
        }
        return 1_000n
      },
      branchClass: BRANCH_CLASS.LOOKUP,
      verifyDestination(value) {
        callbackValue = value
        saved.apply(saved.fill, value.destination.id, [0])
        saved.apply(saved.fill, value.destination.handle, [0])
        saved.apply(saved.fill, value.destinationEncoded, [0])
        Reflect.apply = () => {
          throw new Error('live Reflect.apply ran')
        }
        return true
      }
    })
  } finally {
    Math.ceil = saved.ceil
    Number.isSafeInteger = saved.safe
    b4a.isBuffer = saved.isBuffer
    Reflect.apply = saved.apply
    Reflect.construct = saved.construct
    Array.isArray = saved.array
    Object.freeze = saved.freeze
    Object.getOwnPropertyDescriptor = saved.descriptor
    Uint8Array.prototype.set = saved.set
    Uint8Array.prototype.fill = saved.fill
    Uint8Array.prototype.subarray = saved.subarray
    globalThis.BigInt = saved.BigInt
    BufferConstructor.allocUnsafe = allocate
    BufferConstructor.allocUnsafeSlow = allocateSlow
  }

  t.alike(decoded.requestId, seed(0x21, 16))
  t.alike(decoded.destination, destination())
  t.alike(decoded.destinationEncoded, expectedDestination())
  t.alike(decoded.encodedBody, seed(0x22, 32))
  t.ok(allZero(callbackValue.destination.id))
  t.ok(allZero(callbackValue.destination.handle))
  t.ok(allZero(callbackValue.destinationEncoded))
  clearRoutedRequest(decoded)
})

test('encoded destination uses one owned snapshot through validation and embedding', (t) => {
  const canonicalDestination = expectedDestination()
  const canonicalRequest = expectedRequest()
  const shared = new Uint8Array(new SharedArrayBuffer(canonicalDestination.byteLength))
  Uint8Array.prototype.set.call(shared, canonicalDestination)
  const isBuffer = Buffer.isBuffer
  let originalChecks = 0
  let snapshot = null
  let snapshotChecks = 0
  let mutations = 0

  Buffer.isBuffer = function (value) {
    const result = isBuffer.call(Buffer, value)
    if (value === shared) {
      originalChecks++
      if (originalChecks === 4 && mutations === 0) {
        mutations++
        shared[50] ^= 1
      }
    } else if (value && value.byteLength === shared.byteLength) {
      if (snapshot === null) snapshot = value
      if (value === snapshot) {
        snapshotChecks++
        if (snapshotChecks === 2 && mutations === 0) {
          mutations++
          shared[50] ^= 1
        }
      }
    }
    return result
  }

  let encoded
  try {
    encoded = request({ destination: shared })
  } finally {
    Buffer.isBuffer = isBuffer
  }

  t.is(mutations, 1)
  t.alike(encoded, canonicalRequest)
})

test('caught validation reentry fails the outer request closed and clears callback copies', (t) => {
  const encoded = request()
  let callbackValue = null
  expectCode(
    t,
    () =>
      validateRoutedRequestForExit(encoded, {
        now: () => 1_000n,
        branchClass: BRANCH_CLASS.LOOKUP,
        verifyDestination(value) {
          callbackValue = value
          try {
            validateRoutedRequestForExit(encoded, {
              now: () => 1_000n,
              branchClass: BRANCH_CLASS.LOOKUP,
              verifyDestination: () => true
            })
          } catch {}
          return true
        }
      }),
    'INVALID_ROUTE'
  )
  t.ok(allZero(callbackValue.destination.id))
  t.ok(allZero(callbackValue.destination.handle))
  t.ok(allZero(callbackValue.destinationEncoded))
})

test('failed authority validation and explicit clear zero every transferred buffer', (t) => {
  const encoded = request()
  let callbackValue = null
  expectCode(
    t,
    () =>
      validateRoutedRequestForExit(encoded, {
        now: () => 1_000n,
        branchClass: BRANCH_CLASS.LOOKUP,
        verifyDestination(value) {
          callbackValue = value
          return false
        }
      }),
    'ERR_AUTHENTICATION'
  )
  t.ok(allZero(callbackValue.destination.id))
  t.ok(allZero(callbackValue.destination.handle))
  t.ok(allZero(callbackValue.destinationEncoded))

  const decoded = decodeRoutedRequest(encoded)
  clearRoutedRequest(decoded)
  t.ok(allZero(decoded.requestId))
  t.ok(allZero(decoded.destination.id))
  t.ok(allZero(decoded.destination.handle))
  t.ok(allZero(decoded.destinationEncoded))
  t.ok(allZero(decoded.encodedBody))
  clearRoutedRequest(decoded)
  clearRoutedRequest(null)
})

test('clearRoutedRequest is idempotent and ignores hostile arbitrary values', (t) => {
  let getterCalls = 0
  const accessor = {}
  for (const name of ['requestId', 'destination', 'destinationEncoded', 'encodedBody']) {
    Object.defineProperty(accessor, name, {
      get() {
        getterCalls++
        throw new Error('getter must not run')
      }
    })
  }
  const inherited = Object.create(accessor)
  const trapped = new Proxy(
    {},
    {
      getOwnPropertyDescriptor() {
        throw new Error('descriptor trap')
      }
    }
  )
  const revoked = Proxy.revocable({}, {})
  revoked.revoke()

  for (const value of [accessor, inherited, trapped, revoked.proxy, 1, 'request', true]) {
    let error = null
    try {
      clearRoutedRequest(value)
      clearRoutedRequest(value)
    } catch (err) {
      error = err
    }
    t.is(error, null)
  }
  t.is(getterCalls, 0)

  const decoded = decodeRoutedRequest(request())
  clearRoutedRequest(decoded)
  clearRoutedRequest(decoded)
  t.ok(allZero(decoded.requestId))
  t.ok(allZero(decoded.destination.id))
  t.ok(allZero(decoded.destination.handle))
  t.ok(allZero(decoded.destinationEncoded))
  t.ok(allZero(decoded.encodedBody))
})
