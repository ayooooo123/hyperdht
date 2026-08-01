'use strict'

const b4a = require('b4a')

const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')
const { DESTINATION_VALIDATION_CLASS, M3_MESSAGE_ID, MUTATION_FLAG } = require('./protocol')

// Ported from the reviewed private-routes prototype at commit
// 0305df915b6a767093f9e75e6c06bc0a35da6169. Live exit activation and socket
// ownership deliberately remain outside Gate 3A.

const SERVICE_POLICY_ENTRY_SIZE = 32
const POLICY_BYTES = 2 + 9 * SERVICE_POLICY_ENTRY_SIZE
const POLICY_DOMAIN = b4a.from('hyperdht-private-routes/final-exit/service-policy/v1')

const bufferByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
const bufferFill = Uint8Array.prototype.fill
const bufferSet = Uint8Array.prototype.set
const Uint8ArrayConstructor = Uint8Array
const trustedBuffer = b4a.alloc(0)
const trustedBufferConstructor = trustedBuffer.constructor
function OwnedBufferConstructor() {}
OwnedBufferConstructor.prototype = trustedBufferConstructor.prototype
const b4aIsBuffer = b4a.isBuffer
const arrayIsArray = Array.isArray
const objectFreeze = Object.freeze
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectHasOwnProperty = Object.prototype.hasOwnProperty
const reflectApply = Reflect.apply
const reflectConstruct = Reflect.construct
const reflectHas = Reflect.has
const cryptoHash = cryptoSuite.hash

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function bufferLength(value) {
  try {
    return b4aIsBuffer(value) ? reflectApply(bufferByteLength, value, []) : -1
  } catch {
    return -1
  }
}

function clear(value) {
  try {
    if (b4aIsBuffer(value)) reflectApply(bufferFill, value, [0])
  } catch {
    // Best-effort zeroization only.
  }
}

function allocate(size) {
  let output = null
  try {
    output = reflectConstruct(Uint8ArrayConstructor, [size], OwnedBufferConstructor)
    if (bufferLength(output) !== size) invalid()
    return output
  } catch (err) {
    clear(output)
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function copy(value) {
  let output = null
  try {
    const size = bufferLength(value)
    if (size < 0) invalid()
    output = allocate(size)
    reflectApply(bufferSet, output, [value, 0])
    return output
  } catch (err) {
    clear(output)
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function dataProperty(value, name, required = true) {
  let descriptor
  try {
    descriptor = objectGetOwnPropertyDescriptor(value, name)
  } catch {
    invalid()
  }

  if (descriptor === undefined) {
    let inherited = false
    try {
      inherited = reflectApply(reflectHas, null, [value, name])
    } catch {
      invalid()
    }
    if (required || inherited) invalid()
    return undefined
  }
  if (!reflectApply(objectHasOwnProperty, descriptor, ['value'])) invalid()
  return descriptor.value
}

function policyEntry(
  commandId,
  maxRequestBytes,
  maxResponseBytes,
  timeoutMs,
  maxOutstanding,
  requestCost,
  responseCost,
  maxAmplificationBytes,
  mutationFlag,
  destinationValidationClass
) {
  return objectFreeze({
    commandId,
    commandVersion: 1,
    maxRequestBytes,
    maxResponseBytes,
    timeoutMs,
    maxOutstanding,
    requestCost,
    responseCost,
    maxAmplificationBytes,
    mutationFlag,
    destinationValidationClass
  })
}

const EXIT_ORIGIN_SERVICE_POLICY = objectFreeze([
  policyEntry(
    M3_MESSAGE_ID.IMMUTABLE_GET_V1,
    32,
    4706,
    3000,
    10,
    1,
    2,
    4445,
    MUTATION_FLAG.READ_ONLY,
    DESTINATION_VALIDATION_CLASS.DHT_NODE_HANDLE
  ),
  policyEntry(
    M3_MESSAGE_ID.IMMUTABLE_PUT_V1,
    1090,
    209,
    3000,
    5,
    3,
    1,
    0,
    MUTATION_FLAG.MUTATING,
    DESTINATION_VALIDATION_CLASS.DHT_NODE_HANDLE
  ),
  policyEntry(
    M3_MESSAGE_ID.MUTABLE_GET_V1,
    40,
    4650,
    3000,
    10,
    1,
    2,
    4381,
    MUTATION_FLAG.READ_ONLY,
    DESTINATION_VALIDATION_CLASS.DHT_NODE_HANDLE
  ),
  policyEntry(
    M3_MESSAGE_ID.MUTABLE_PUT_V1,
    1066,
    209,
    3000,
    5,
    3,
    1,
    0,
    MUTATION_FLAG.MUTATING,
    DESTINATION_VALIDATION_CLASS.DHT_NODE_HANDLE
  ),
  policyEntry(
    M3_MESSAGE_ID.PRIVATE_FIND_NODE_V1,
    69,
    4031,
    5000,
    3,
    2,
    8,
    3733,
    MUTATION_FLAG.READ_ONLY,
    DESTINATION_VALIDATION_CLASS.SIGNED_CAPABILITY_HANDLE
  ),
  policyEntry(
    M3_MESSAGE_ID.PRIVATE_LOOKUP_V1,
    134,
    8270,
    5000,
    3,
    2,
    12,
    7907,
    MUTATION_FLAG.READ_ONLY,
    DESTINATION_VALIDATION_CLASS.SIGNED_CAPABILITY_HANDLE
  ),
  policyEntry(
    M3_MESSAGE_ID.PRIVATE_PREPARE_V1,
    189,
    288,
    3000,
    5,
    3,
    2,
    0,
    MUTATION_FLAG.MUTATING,
    DESTINATION_VALIDATION_CLASS.SIGNED_CAPABILITY_HANDLE
  ),
  policyEntry(
    M3_MESSAGE_ID.PRIVATE_ANNOUNCE_V1,
    1161,
    581,
    5000,
    5,
    5,
    3,
    0,
    MUTATION_FLAG.MUTATING,
    DESTINATION_VALIDATION_CLASS.SIGNED_CAPABILITY_HANDLE
  ),
  policyEntry(
    M3_MESSAGE_ID.PRIVATE_UNANNOUNCE_V1,
    393,
    581,
    5000,
    5,
    5,
    3,
    0,
    MUTATION_FLAG.MUTATING,
    DESTINATION_VALIDATION_CLASS.SIGNED_CAPABILITY_HANDLE
  )
])

const DHT_EXIT_ORIGIN_SERVICE_POLICY = objectFreeze(EXIT_ORIGIN_SERVICE_POLICY.slice(0, 4))

const POLICY_FIELDS = objectFreeze([
  'commandId',
  'commandVersion',
  'maxRequestBytes',
  'maxResponseBytes',
  'timeoutMs',
  'maxOutstanding',
  'requestCost',
  'responseCost',
  'maxAmplificationBytes',
  'mutationFlag',
  'destinationValidationClass'
])

function entriesArray(value) {
  try {
    if (!arrayIsArray(value)) invalid()
    const length = dataProperty(value, 'length')
    if (length !== DHT_EXIT_ORIGIN_SERVICE_POLICY.length && length !== EXIT_ORIGIN_SERVICE_POLICY.length) {
      invalid()
    }
    return value
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function exactEntry(actual, expected) {
  try {
    if (actual === null || typeof actual !== 'object' || arrayIsArray(actual)) invalid()
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }

  for (let index = 0; index < POLICY_FIELDS.length; index++) {
    const name = POLICY_FIELDS[index]
    if (dataProperty(actual, name) !== expected[name]) invalid()
  }
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

function readUint16(target, offset) {
  return (target[offset] << 8) | target[offset + 1]
}

function readUint32(target, offset) {
  return (
    target[offset] * 0x1000000 +
    (target[offset + 1] << 16) +
    (target[offset + 2] << 8) +
    target[offset + 3]
  )
}

function encodeExitOriginServicePolicy(entries = EXIT_ORIGIN_SERVICE_POLICY) {
  let output = null
  let complete = false
  try {
    entries = entriesArray(entries)
    const entryCount = dataProperty(entries, 'length')
    for (let index = 0; index < entryCount; index++) {
      exactEntry(dataProperty(entries, String(index)), EXIT_ORIGIN_SERVICE_POLICY[index])
    }

    output = allocate(2 + entryCount * SERVICE_POLICY_ENTRY_SIZE)
    writeUint16(output, entryCount, 0)
    let offset = 2
    for (let index = 0; index < entryCount; index++) {
      const entry = EXIT_ORIGIN_SERVICE_POLICY[index]
      writeUint16(output, entry.commandId, offset)
      writeUint16(output, entry.commandVersion, offset + 2)
      writeUint32(output, entry.maxRequestBytes, offset + 4)
      writeUint32(output, entry.maxResponseBytes, offset + 8)
      writeUint32(output, entry.timeoutMs, offset + 12)
      writeUint16(output, entry.maxOutstanding, offset + 16)
      writeUint32(output, entry.requestCost, offset + 18)
      writeUint32(output, entry.responseCost, offset + 22)
      writeUint32(output, entry.maxAmplificationBytes, offset + 26)
      output[offset + 30] = entry.mutationFlag
      output[offset + 31] = entry.destinationValidationClass
      offset += SERVICE_POLICY_ENTRY_SIZE
    }
    complete = true
    return output
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    if (!complete) clear(output)
  }
}

function decodeExitOriginServicePolicy(encoded) {
  try {
    const entryCount = bufferLength(encoded) >= 2 ? readUint16(encoded, 0) : -1
    if (
      (entryCount !== DHT_EXIT_ORIGIN_SERVICE_POLICY.length &&
        entryCount !== EXIT_ORIGIN_SERVICE_POLICY.length) ||
      bufferLength(encoded) !== 2 + entryCount * SERVICE_POLICY_ENTRY_SIZE
    ) {
      invalid()
    }
    const entries = []
    let offset = 2
    for (let index = 0; index < entryCount; index++) {
      const entry = objectFreeze({
        commandId: readUint16(encoded, offset),
        commandVersion: readUint16(encoded, offset + 2),
        maxRequestBytes: readUint32(encoded, offset + 4),
        maxResponseBytes: readUint32(encoded, offset + 8),
        timeoutMs: readUint32(encoded, offset + 12),
        maxOutstanding: readUint16(encoded, offset + 16),
        requestCost: readUint32(encoded, offset + 18),
        responseCost: readUint32(encoded, offset + 22),
        maxAmplificationBytes: readUint32(encoded, offset + 26),
        mutationFlag: encoded[offset + 30],
        destinationValidationClass: encoded[offset + 31]
      })
      exactEntry(entry, EXIT_ORIGIN_SERVICE_POLICY[index])
      entries[index] = entry
      offset += SERVICE_POLICY_ENTRY_SIZE
    }
    return objectFreeze(entries)
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function digestExitOriginServicePolicy(value = EXIT_ORIGIN_SERVICE_POLICY) {
  let encoded = null
  let digest = null
  let complete = false
  try {
    if (bufferLength(value) >= 0) {
      encoded = copy(value)
      decodeExitOriginServicePolicy(encoded)
    } else {
      encoded = encodeExitOriginServicePolicy(value)
    }
    digest = allocate(32)
    cryptoHash([POLICY_DOMAIN, encoded], digest)
    if (bufferLength(digest) !== 32) invalid()
    complete = true
    return digest
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    clear(encoded)
    if (!complete) clear(digest)
  }
}

module.exports = {
  EXIT_ORIGIN_SERVICE_POLICY,
  DHT_EXIT_ORIGIN_SERVICE_POLICY,
  SERVICE_POLICY_ENTRY_SIZE,
  decodeExitOriginServicePolicy,
  digestExitOriginServicePolicy,
  encodeExitOriginServicePolicy
}
