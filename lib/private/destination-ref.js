'use strict'

const b4a = require('b4a')

const { PrivateRouteError } = require('./errors')
const { M3_MESSAGE_ID } = require('./protocol')

const DESTINATION_REF_SIZE = 172

const M3_HEADER_SIZE = 8
const DESTINATION_BODY_SIZE = 164
const MAX_ROUTED_REQUEST_BODY_SIZE = 1382
const bufferByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
const bufferFill = Uint8Array.prototype.fill
const bufferSet = Uint8Array.prototype.set
const bufferSubarray = Uint8Array.prototype.subarray
const Uint8ArrayConstructor = Uint8Array
const trustedBuffer = b4a.alloc(0)
const trustedBufferConstructor = trustedBuffer.constructor
function OwnedBufferConstructor() {}
OwnedBufferConstructor.prototype = trustedBufferConstructor.prototype
const b4aIsBuffer = b4a.isBuffer
const arrayIsArray = Array.isArray
const numberIsSafeInteger = Number.isSafeInteger
const objectFreeze = Object.freeze
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectHasOwnProperty = Object.prototype.hasOwnProperty
const reflectApply = Reflect.apply
const reflectConstruct = Reflect.construct
const reflectHas = Reflect.has

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function object(value) {
  try {
    if (value === null || typeof value !== 'object' || arrayIsArray(value)) invalid()
    return value
  } catch (err) {
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
    if (
      !numberIsSafeInteger(size) ||
      size < 0 ||
      size > M3_HEADER_SIZE + MAX_ROUTED_REQUEST_BODY_SIZE
    ) {
      invalid()
    }
    output = reflectConstruct(Uint8ArrayConstructor, [size], OwnedBufferConstructor)
    if (bufferLength(output) !== size) invalid()
    return output
  } catch (err) {
    clear(output)
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function set(target, source, offset = 0) {
  try {
    reflectApply(bufferSet, target, [source, offset])
  } catch {
    invalid()
  }
}

function subarray(value, start, end) {
  try {
    return reflectApply(bufferSubarray, value, [start, end])
  } catch {
    invalid()
  }
}

function copy(value) {
  let output = null
  try {
    const size = bufferLength(value)
    if (size < 0) invalid()
    output = allocate(size)
    set(output, value)
    return output
  } catch (err) {
    clear(output)
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function fixed(value, size) {
  return bufferLength(value) === size
}

function writeUint16(target, value, offset) {
  target[offset] = value >>> 8
  target[offset + 1] = value
}

function readUint16(target, offset) {
  return (target[offset] << 8) | target[offset + 1]
}

function writeUint32(target, value, offset) {
  target[offset] = value >>> 24
  target[offset + 1] = value >>> 16
  target[offset + 2] = value >>> 8
  target[offset + 3] = value
}

function readUint32(target, offset) {
  return (
    target[offset] * 0x1000000 +
    (target[offset + 1] << 16) +
    (target[offset + 2] << 8) +
    target[offset + 3]
  )
}

function encodeM3(body) {
  const bodyBytes = bufferLength(body)
  if (bodyBytes !== DESTINATION_BODY_SIZE) invalid()

  let output = null
  let complete = false
  try {
    output = allocate(M3_HEADER_SIZE + bodyBytes)
    writeUint32(output, 1, 0)
    writeUint16(output, M3_MESSAGE_ID.DESTINATION_REF_V1, 4)
    writeUint16(output, bodyBytes, 6)
    set(output, body, M3_HEADER_SIZE)
    complete = true
    return output
  } finally {
    if (!complete) clear(output)
  }
}

function decodeM3(encoded) {
  let owned = null
  let body = null
  let complete = false
  try {
    const encodedBytes = bufferLength(encoded)
    if (encodedBytes !== DESTINATION_REF_SIZE) invalid()
    owned = copy(encoded)
    if (
      readUint32(owned, 0) !== 1 ||
      readUint16(owned, 4) !== M3_MESSAGE_ID.DESTINATION_REF_V1 ||
      readUint16(owned, 6) !== DESTINATION_BODY_SIZE
    ) {
      invalid()
    }
    body = copy(subarray(owned, M3_HEADER_SIZE))
    complete = true
    return body
  } finally {
    clear(owned)
    if (!complete) clear(body)
  }
}

function encodeDestinationRef(value) {
  let id = null
  let handle = null
  let body = null
  try {
    value = object(value)
    const callerId = dataProperty(value, 'id')
    const callerHandle = dataProperty(value, 'handle')
    if (!fixed(callerId, 32) || !fixed(callerHandle, 130)) invalid()
    id = copy(callerId)
    handle = copy(callerHandle)
    body = allocate(DESTINATION_BODY_SIZE)
    set(body, id, 0)
    writeUint16(body, 130, 32)
    set(body, handle, 34)
    return encodeM3(body)
  } finally {
    clear(id)
    clear(handle)
    clear(body)
  }
}

function decodeDestinationRef(encoded) {
  let body = null
  let id = null
  let handle = null
  let result = null
  let complete = false
  try {
    body = decodeM3(encoded)
    if (readUint16(body, 32) !== 130) invalid()
    id = copy(subarray(body, 0, 32))
    handle = copy(subarray(body, 34, DESTINATION_BODY_SIZE))
    result = objectFreeze({ id, handle })
    id = null
    handle = null
    complete = true
    return result
  } finally {
    clear(body)
    clear(id)
    clear(handle)
    if (!complete && result) {
      clear(result.id)
      clear(result.handle)
    }
  }
}

module.exports = objectFreeze({ DESTINATION_REF_SIZE, decodeDestinationRef, encodeDestinationRef })
