'use strict'

const b4a = require('b4a')

const { EXIT_ORIGIN_SERVICE_POLICY } = require('./exit-policy')
const { PrivateRouteError } = require('./errors')
const { BRANCH_CLASS, M3_MESSAGE_ID } = require('./protocol')

// Ported from the reviewed private-routes prototype at commit
// 0305df915b6a767093f9e75e6c06bc0a35da6169. This is wire ownership and
// validation only: there is no routed-reply codec, socket, or exit activation.

const DESTINATION_REF_SIZE = 172
const ROUTED_REQUEST_FIXED_BODY_SIZE = 221

const MAX_UINT64 = 0xffff_ffff_ffff_ffffn
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
const bigIntConstructor = BigInt
const numberConstructor = Number
const numberIsSafeInteger = Number.isSafeInteger
const objectFreeze = Object.freeze
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectHasOwnProperty = Object.prototype.hasOwnProperty
const reflectApply = Reflect.apply
const reflectConstruct = Reflect.construct
const reflectHas = Reflect.has

const COMMANDS = objectFreeze([
  objectFreeze({
    commandId: M3_MESSAGE_ID.IMMUTABLE_GET_V1,
    min: 32,
    max: 32,
    lookup: true,
    announce: true
  }),
  objectFreeze({
    commandId: M3_MESSAGE_ID.IMMUTABLE_PUT_V1,
    min: 67,
    max: 1090,
    lookup: false,
    announce: true
  }),
  objectFreeze({
    commandId: M3_MESSAGE_ID.MUTABLE_GET_V1,
    min: 40,
    max: 40,
    lookup: true,
    announce: true
  }),
  objectFreeze({
    commandId: M3_MESSAGE_ID.MUTABLE_PUT_V1,
    min: 171,
    max: 1066,
    lookup: false,
    announce: true
  }),
  objectFreeze({
    commandId: M3_MESSAGE_ID.PRIVATE_FIND_NODE_V1,
    min: 69,
    max: 69,
    lookup: true,
    announce: true
  }),
  objectFreeze({
    commandId: M3_MESSAGE_ID.PRIVATE_LOOKUP_V1,
    min: 134,
    max: 134,
    lookup: true,
    announce: false
  }),
  objectFreeze({
    commandId: M3_MESSAGE_ID.PRIVATE_PREPARE_V1,
    min: 189,
    max: 189,
    lookup: false,
    announce: true
  }),
  objectFreeze({
    commandId: M3_MESSAGE_ID.PRIVATE_ANNOUNCE_V1,
    min: 394,
    max: 1161,
    lookup: false,
    announce: true
  }),
  objectFreeze({
    commandId: M3_MESSAGE_ID.PRIVATE_UNANNOUNCE_V1,
    min: 393,
    max: 393,
    lookup: false,
    announce: true
  })
])

let activeValidation = null

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function policyMismatch() {
  throw PrivateRouteError.ERR_AUTHENTICATION()
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

function uint64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= MAX_UINT64
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

function writeUint64(target, value, offset) {
  for (let index = offset + 7; index >= offset; index--) {
    target[index] = numberConstructor(value & 0xffn)
    value >>= 8n
  }
}

function readUint64(target, offset) {
  let value = 0n
  for (let index = offset; index < offset + 8; index++) {
    value = (value << 8n) | bigIntConstructor(target[index])
  }
  return value
}

function branchClass(value) {
  if (value !== BRANCH_CLASS.LOOKUP && value !== BRANCH_CLASS.ANNOUNCE) invalid()
  return value
}

function command(commandId, operationClass, bodyBytes) {
  let definition = null
  let policy = null
  for (let index = 0; index < COMMANDS.length; index++) {
    if (COMMANDS[index].commandId === commandId) definition = COMMANDS[index]
  }
  for (let index = 0; index < EXIT_ORIGIN_SERVICE_POLICY.length; index++) {
    if (EXIT_ORIGIN_SERVICE_POLICY[index].commandId === commandId) {
      policy = EXIT_ORIGIN_SERVICE_POLICY[index]
    }
  }
  if (!definition || !policy || bodyBytes < definition.min || bodyBytes > definition.max) invalid()
  if (
    (operationClass === BRANCH_CLASS.LOOKUP && !definition.lookup) ||
    (operationClass === BRANCH_CLASS.ANNOUNCE && !definition.announce)
  ) {
    policyMismatch()
  }
  return { definition, policy }
}

function encodeM3(messageId, body) {
  const bodyBytes = bufferLength(body)
  let minimum
  let maximum
  if (messageId === M3_MESSAGE_ID.DESTINATION_REF_V1) {
    minimum = DESTINATION_BODY_SIZE
    maximum = DESTINATION_BODY_SIZE
  } else if (messageId === M3_MESSAGE_ID.ROUTED_REQUEST_V1) {
    minimum = ROUTED_REQUEST_FIXED_BODY_SIZE
    maximum = MAX_ROUTED_REQUEST_BODY_SIZE
  } else {
    invalid()
  }
  if (bodyBytes < minimum || bodyBytes > maximum) invalid()

  let output = null
  let complete = false
  try {
    output = allocate(M3_HEADER_SIZE + bodyBytes)
    writeUint32(output, 1, 0)
    writeUint16(output, messageId, 4)
    writeUint16(output, bodyBytes, 6)
    set(output, body, M3_HEADER_SIZE)
    complete = true
    return output
  } finally {
    if (!complete) clear(output)
  }
}

function decodeM3(encoded, expectedMessageId, minimum, maximum) {
  let owned = null
  let body = null
  let complete = false
  try {
    const encodedBytes = bufferLength(encoded)
    if (encodedBytes < M3_HEADER_SIZE || encodedBytes > M3_HEADER_SIZE + maximum) invalid()
    owned = copy(encoded)
    if (readUint32(owned, 0) !== 1 || readUint16(owned, 4) !== expectedMessageId) invalid()
    const bodyBytes = readUint16(owned, 6)
    if (bodyBytes < minimum || bodyBytes > maximum || encodedBytes !== M3_HEADER_SIZE + bodyBytes) {
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
    return encodeM3(M3_MESSAGE_ID.DESTINATION_REF_V1, body)
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
    body = decodeM3(
      encoded,
      M3_MESSAGE_ID.DESTINATION_REF_V1,
      DESTINATION_BODY_SIZE,
      DESTINATION_BODY_SIZE
    )
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

function encodedDestination(value) {
  if (bufferLength(value) === DESTINATION_REF_SIZE) {
    const decoded = decodeDestinationRef(value)
    clear(decoded.id)
    clear(decoded.handle)
    return copy(value)
  }
  return encodeDestinationRef(value)
}

function encodeRoutedRequest(value) {
  let requestId = null
  let encodedBody = null
  let destination = null
  let body = null
  try {
    value = object(value)
    const callerRequestId = dataProperty(value, 'requestId')
    const operationClass = branchClass(dataProperty(value, 'operationClass'))
    const commandId = dataProperty(value, 'commandId')
    const absoluteDeadlineMs = dataProperty(value, 'absoluteDeadlineMs')
    const callerDestination = dataProperty(value, 'destination')
    const callerEncodedBody = dataProperty(value, 'encodedBody')
    const encodedBodyBytes = bufferLength(callerEncodedBody)
    if (!fixed(callerRequestId, 16) || !uint64(absoluteDeadlineMs) || encodedBodyBytes < 0) {
      invalid()
    }
    const selected = command(commandId, operationClass, encodedBodyBytes)
    requestId = copy(callerRequestId)
    encodedBody = copy(callerEncodedBody)
    destination = encodedDestination(callerDestination)
    body = allocate(ROUTED_REQUEST_FIXED_BODY_SIZE + encodedBodyBytes)
    set(body, requestId, 0)
    body[16] = operationClass
    writeUint16(body, commandId, 17)
    writeUint16(body, 1, 19)
    body[21] = selected.policy.mutationFlag
    body[22] = selected.policy.destinationValidationClass
    writeUint32(body, selected.policy.maxResponseBytes, 23)
    writeUint32(body, selected.policy.maxAmplificationBytes, 27)
    writeUint32(body, selected.policy.requestCost, 31)
    writeUint32(body, selected.policy.responseCost, 35)
    writeUint64(body, absoluteDeadlineMs, 39)
    set(body, destination, 47)
    writeUint16(body, encodedBodyBytes, 219)
    set(body, encodedBody, 221)
    return encodeM3(M3_MESSAGE_ID.ROUTED_REQUEST_V1, body)
  } finally {
    clear(requestId)
    clear(encodedBody)
    clear(destination)
    clear(body)
  }
}

function decodeRoutedRequest(encoded) {
  let body = null
  let destinationEncoded = null
  let destination = null
  let requestId = null
  let encodedBody = null
  let result = null
  let complete = false
  try {
    body = decodeM3(
      encoded,
      M3_MESSAGE_ID.ROUTED_REQUEST_V1,
      ROUTED_REQUEST_FIXED_BODY_SIZE,
      MAX_ROUTED_REQUEST_BODY_SIZE
    )
    const operationClass = branchClass(body[16])
    const commandId = readUint16(body, 17)
    const encodedBodyBytes = readUint16(body, 219)
    if (bufferLength(body) !== ROUTED_REQUEST_FIXED_BODY_SIZE + encodedBodyBytes) invalid()
    const selected = command(commandId, operationClass, encodedBodyBytes)
    if (
      readUint16(body, 19) !== 1 ||
      body[21] !== selected.policy.mutationFlag ||
      body[22] !== selected.policy.destinationValidationClass ||
      readUint32(body, 23) !== selected.policy.maxResponseBytes ||
      readUint32(body, 27) !== selected.policy.maxAmplificationBytes ||
      readUint32(body, 31) !== selected.policy.requestCost ||
      readUint32(body, 35) !== selected.policy.responseCost
    ) {
      policyMismatch()
    }
    destinationEncoded = copy(subarray(body, 47, 219))
    destination = decodeDestinationRef(destinationEncoded)
    requestId = copy(subarray(body, 0, 16))
    encodedBody = copy(subarray(body, 221))
    result = objectFreeze({
      requestId,
      operationClass,
      commandId,
      commandVersion: 1,
      mutationFlag: body[21],
      destinationValidationClass: body[22],
      maxResponseBytes: readUint32(body, 23),
      maxAmplificationBytes: readUint32(body, 27),
      requestCost: readUint32(body, 31),
      responseCost: readUint32(body, 35),
      absoluteDeadlineMs: readUint64(body, 39),
      destination,
      destinationEncoded,
      encodedBody
    })
    requestId = null
    encodedBody = null
    destination = null
    destinationEncoded = null
    complete = true
    return result
  } finally {
    clear(body)
    clear(requestId)
    clear(encodedBody)
    if (!complete && result) clearRoutedRequest(result)
    if (destination) {
      clear(destination.id)
      clear(destination.handle)
    }
    clear(destinationEncoded)
  }
}

function validationOptions(options) {
  options = object(options)
  const now = dataProperty(options, 'now')
  const expectedBranchClass = branchClass(dataProperty(options, 'branchClass'))
  const verifyDestination = dataProperty(options, 'verifyDestination')
  if (typeof now !== 'function' || typeof verifyDestination !== 'function') invalid()
  return { now, expectedBranchClass, verifyDestination }
}

function callbackDestination(request) {
  let id = null
  let handle = null
  let destinationEncoded = null
  let result = null
  let complete = false
  try {
    id = copy(request.destination.id)
    handle = copy(request.destination.handle)
    destinationEncoded = copy(request.destinationEncoded)
    result = objectFreeze({
      destination: objectFreeze({ id, handle }),
      destinationEncoded,
      destinationValidationClass: request.destinationValidationClass,
      absoluteDeadlineMs: request.absoluteDeadlineMs,
      commandId: request.commandId
    })
    id = null
    handle = null
    destinationEncoded = null
    complete = true
    return result
  } finally {
    clear(id)
    clear(handle)
    clear(destinationEncoded)
    if (!complete && result) clearCallbackDestination(result)
  }
}

function clearCallbackDestination(value) {
  if (!value) return
  if (value.destination) {
    clear(value.destination.id)
    clear(value.destination.handle)
  }
  clear(value.destinationEncoded)
}

function validateRoutedRequestForExit(encoded, options) {
  if (activeValidation !== null) {
    activeValidation.reentered = true
    invalid()
  }

  const guard = { reentered: false }
  activeValidation = guard
  let request = null
  let callbackValue = null
  let complete = false
  try {
    const { now, expectedBranchClass, verifyDestination } = validationOptions(options)
    request = decodeRoutedRequest(encoded)
    let current
    try {
      current = now()
    } catch {
      invalid()
    }
    if (guard.reentered) invalid()
    if (numberIsSafeInteger(current) && current >= 0) current = bigIntConstructor(current)
    if (!uint64(current)) invalid()

    let policy = null
    for (let index = 0; index < EXIT_ORIGIN_SERVICE_POLICY.length; index++) {
      if (EXIT_ORIGIN_SERVICE_POLICY[index].commandId === request.commandId) {
        policy = EXIT_ORIGIN_SERVICE_POLICY[index]
      }
    }
    if (
      policy === null ||
      request.operationClass !== expectedBranchClass ||
      request.absoluteDeadlineMs < current ||
      request.absoluteDeadlineMs > current + bigIntConstructor(policy.timeoutMs)
    ) {
      policyMismatch()
    }

    callbackValue = callbackDestination(request)
    let valid
    try {
      valid = verifyDestination(callbackValue)
    } catch {
      invalid()
    }
    if (guard.reentered) invalid()
    if (valid !== true) policyMismatch()
    complete = true
    return request
  } finally {
    clearCallbackDestination(callbackValue)
    if (!complete) clearRoutedRequest(request)
    activeValidation = null
  }
}

function clearRoutedRequest(request) {
  if (!request) return
  clear(request.requestId)
  if (request.destination) {
    clear(request.destination.id)
    clear(request.destination.handle)
  }
  clear(request.destinationEncoded)
  clear(request.encodedBody)
}

module.exports = {
  DESTINATION_REF_SIZE,
  ROUTED_REQUEST_FIXED_BODY_SIZE,
  clearRoutedRequest,
  decodeDestinationRef,
  decodeRoutedRequest,
  encodeDestinationRef,
  encodeRoutedRequest,
  validateRoutedRequestForExit
}
