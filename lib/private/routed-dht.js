'use strict'

const b4a = require('b4a')

const { EXIT_ORIGIN_SERVICE_POLICY } = require('./exit-policy')
const { PrivateRouteError } = require('./errors')
const {
  BRANCH_CLASS,
  DESTINATION_VALIDATION_CLASS,
  M3_MESSAGE_ID,
  ROUTED_ERROR
} = require('./protocol')
const {
  DESTINATION_REF_SIZE,
  decodeDestinationRef,
  encodeDestinationRef
} = require('./destination-ref')
const {
  abortRoutedReplyAdmission,
  commitRoutedReplyAdmission,
  revokeRoutedReplyReferralAuthority,
  sealRoutedReplyAdmission,
  stageRoutedReplyReferral,
  verifyRoutedReplyReferralAuthority
} = require('./opaque-destination')

// Ported from the reviewed private-routes prototype at commit
// 0305df915b6a767093f9e75e6c06bc0a35da6169. This module owns routed wire
// validation only; it has no socket or exit activation authority.

const ROUTED_REQUEST_FIXED_BODY_SIZE = 221
const ROUTED_REPLY_FIXED_BODY_SIZE = 200
const MAX_ROUTED_REPLY_BYTES = 4706

const MAX_UINT64 = 0xffff_ffff_ffff_ffffn
const M3_HEADER_SIZE = 8
const MAX_ROUTED_REQUEST_BODY_SIZE = 1382
const MAX_ROUTED_REPLY_BODY_SIZE = MAX_ROUTED_REPLY_BYTES - M3_HEADER_SIZE
const MAX_ROUTED_REPLY_AMPLIFICATION = 4445
const MAX_IMMUTABLE_RESPONSE_BYTES = 1026
const MAX_CLOSER_NODES = 20
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
const arrayIndexOf = Array.prototype.indexOf
const arrayPush = Array.prototype.push
const arraySlice = Array.prototype.slice
const bigIntConstructor = BigInt
const numberConstructor = Number
const numberIsSafeInteger = Number.isSafeInteger
const stringConstructor = String
const objectFreeze = Object.freeze
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectHasOwnProperty = Object.prototype.hasOwnProperty
const reflectApply = Reflect.apply
const reflectConstruct = Reflect.construct
const reflectHas = Reflect.has
const reflectOwnKeys = Reflect.ownKeys

const ROUTED_REPLY_FIELDS = objectFreeze([
  'requestId',
  'commandId',
  'commandVersion',
  'operationClass',
  'from',
  'errorCode',
  'token',
  'closerNodes',
  'encodedResponse'
])
const ROUTED_REPLY_OPTION_FIELDS = objectFreeze([
  'encodedRequest',
  'target',
  'branch',
  'circuitId',
  'generation',
  'now',
  'referralAuthority'
])

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

function exactData(value, names) {
  value = object(value)
  let keys
  try {
    keys = reflectApply(reflectOwnKeys, null, [value])
  } catch {
    invalid()
  }
  if (keys.length !== names.length) invalid()
  for (let index = 0; index < keys.length; index++) {
    if (
      typeof keys[index] !== 'string' ||
      reflectApply(arrayIndexOf, names, [keys[index]]) === -1
    ) {
      invalid()
    }
  }
  const result = {}
  for (let index = 0; index < names.length; index++) {
    result[names[index]] = dataProperty(value, names[index])
  }
  return result
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
      size > M3_HEADER_SIZE + MAX_ROUTED_REPLY_BODY_SIZE
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

function same(left, right) {
  if (bufferLength(left) !== bufferLength(right)) return false
  let difference = 0
  for (let index = 0; index < bufferLength(left); index++) difference |= left[index] ^ right[index]
  return difference === 0
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
  if (messageId === M3_MESSAGE_ID.ROUTED_REQUEST_V1) {
    minimum = ROUTED_REQUEST_FIXED_BODY_SIZE
    maximum = MAX_ROUTED_REQUEST_BODY_SIZE
  } else if (messageId === M3_MESSAGE_ID.ROUTED_REPLY_V1) {
    minimum = ROUTED_REPLY_FIXED_BODY_SIZE
    maximum = MAX_ROUTED_REPLY_BODY_SIZE
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

function encodedDestination(value) {
  if (bufferLength(value) === DESTINATION_REF_SIZE) {
    let owned = null
    let decoded = null
    let complete = false
    try {
      owned = copy(value)
      decoded = decodeDestinationRef(owned)
      complete = true
      return owned
    } finally {
      if (decoded) {
        clear(decoded.id)
        clear(decoded.handle)
      }
      if (!complete) clear(owned)
    }
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

function knownRoutedError(value) {
  return value === 0 || (value >= ROUTED_ERROR.MALFORMED && value <= ROUTED_ERROR.QUOTA_EXCEEDED)
}

function replyCloserNodes(value) {
  if (!arrayIsArray(value)) invalid()
  const length = dataProperty(value, 'length')
  if (!numberIsSafeInteger(length) || length < 0 || length > MAX_CLOSER_NODES) invalid()
  const result = []
  for (let index = 0; index < length; index++) {
    reflectApply(arrayPush, result, [dataProperty(value, stringConstructor(index))])
  }
  return result
}

function encodeRoutedReply(value) {
  const fields = exactData(value, ROUTED_REPLY_FIELDS)
  let requestId = null
  let from = null
  let token = null
  let encodedResponse = null
  let body = null
  const closerEncoded = []
  const closerDecoded = []
  try {
    requestId = copy(fields.requestId)
    if (!fixed(requestId, 16)) invalid()
    if (
      fields.commandId !== M3_MESSAGE_ID.IMMUTABLE_GET_V1 ||
      fields.commandVersion !== 1 ||
      fields.operationClass !== BRANCH_CLASS.LOOKUP ||
      !numberIsSafeInteger(fields.errorCode) ||
      !knownRoutedError(fields.errorCode)
    ) {
      invalid()
    }
    from = encodedDestination(fields.from)
    token = copy(fields.token)
    if (bufferLength(token) !== 0 && bufferLength(token) !== 32) invalid()
    encodedResponse = copy(fields.encodedResponse)
    if (bufferLength(encodedResponse) > MAX_IMMUTABLE_RESPONSE_BYTES) invalid()
    const callers = replyCloserNodes(fields.closerNodes)
    for (let index = 0; index < callers.length; index++) {
      const encoded = encodedDestination(callers[index])
      const decoded = decodeDestinationRef(encoded)
      reflectApply(arrayPush, closerEncoded, [encoded])
      reflectApply(arrayPush, closerDecoded, [decoded])
    }
    if (
      fields.errorCode !== 0 &&
      (bufferLength(token) !== 0 ||
        closerEncoded.length !== 0 ||
        bufferLength(encodedResponse) !== 0)
    ) {
      invalid()
    }
    const bodyBytes =
      ROUTED_REPLY_FIXED_BODY_SIZE +
      bufferLength(token) +
      DESTINATION_REF_SIZE * closerEncoded.length +
      bufferLength(encodedResponse)
    if (M3_HEADER_SIZE + bodyBytes > MAX_ROUTED_REPLY_BYTES) invalid()
    body = allocate(bodyBytes)
    let offset = 0
    set(body, requestId, offset)
    offset += 16
    writeUint16(body, fields.commandId, offset)
    offset += 2
    writeUint16(body, fields.commandVersion, offset)
    offset += 2
    body[offset++] = fields.operationClass
    set(body, from, offset)
    offset += DESTINATION_REF_SIZE
    writeUint16(body, fields.errorCode, offset)
    offset += 2
    writeUint16(body, bufferLength(token), offset)
    offset += 2
    set(body, token, offset)
    offset += bufferLength(token)
    body[offset++] = closerEncoded.length
    for (let index = 0; index < closerEncoded.length; index++) {
      set(body, closerEncoded[index], offset)
      offset += DESTINATION_REF_SIZE
    }
    writeUint16(body, bufferLength(encodedResponse), offset)
    offset += 2
    set(body, encodedResponse, offset)
    return encodeM3(M3_MESSAGE_ID.ROUTED_REPLY_V1, body)
  } finally {
    clear(requestId)
    clear(from)
    clear(token)
    clear(encodedResponse)
    clear(body)
    for (let index = 0; index < closerEncoded.length; index++) clear(closerEncoded[index])
    for (let index = 0; index < closerDecoded.length; index++) {
      clear(closerDecoded[index].id)
      clear(closerDecoded[index].handle)
    }
  }
}

function decodeRoutedReply(encoded) {
  let body = null
  let requestId = null
  let fromEncoded = null
  let from = null
  let token = null
  let encodedResponse = null
  let result = null
  const closerNodes = []
  const closerNodeEncoded = []
  let complete = false
  try {
    body = decodeM3(
      encoded,
      M3_MESSAGE_ID.ROUTED_REPLY_V1,
      ROUTED_REPLY_FIXED_BODY_SIZE,
      MAX_ROUTED_REPLY_BODY_SIZE
    )
    let offset = 0
    requestId = copy(subarray(body, offset, offset + 16))
    offset += 16
    const commandId = readUint16(body, offset)
    offset += 2
    const commandVersion = readUint16(body, offset)
    offset += 2
    const operationClass = body[offset++]
    if (
      commandId !== M3_MESSAGE_ID.IMMUTABLE_GET_V1 ||
      commandVersion !== 1 ||
      operationClass !== BRANCH_CLASS.LOOKUP
    ) {
      invalid()
    }
    fromEncoded = copy(subarray(body, offset, offset + DESTINATION_REF_SIZE))
    from = decodeDestinationRef(fromEncoded)
    offset += DESTINATION_REF_SIZE
    const errorCode = readUint16(body, offset)
    offset += 2
    if (!knownRoutedError(errorCode)) invalid()
    const tokenBytes = readUint16(body, offset)
    offset += 2
    if ((tokenBytes !== 0 && tokenBytes !== 32) || offset + tokenBytes + 3 > bufferLength(body)) {
      invalid()
    }
    token = copy(subarray(body, offset, offset + tokenBytes))
    offset += tokenBytes
    const closerCount = body[offset++]
    if (closerCount > MAX_CLOSER_NODES) invalid()
    if (offset + DESTINATION_REF_SIZE * closerCount + 2 > bufferLength(body)) invalid()
    for (let index = 0; index < closerCount; index++) {
      const closerEncoded = copy(subarray(body, offset, offset + DESTINATION_REF_SIZE))
      let closer = null
      try {
        closer = decodeDestinationRef(closerEncoded)
        reflectApply(arrayPush, closerNodeEncoded, [closerEncoded])
        reflectApply(arrayPush, closerNodes, [closer])
      } catch (error) {
        clear(closerEncoded)
        if (closer !== null) {
          clear(closer.id)
          clear(closer.handle)
        }
        throw error
      }
      offset += DESTINATION_REF_SIZE
    }
    const responseBytes = readUint16(body, offset)
    offset += 2
    if (offset + responseBytes !== bufferLength(body)) invalid()
    encodedResponse = copy(subarray(body, offset))
    if (errorCode !== 0 && (tokenBytes !== 0 || closerCount !== 0 || responseBytes !== 0)) {
      invalid()
    }
    const ownedCloserNodes = objectFreeze(reflectApply(arraySlice, closerNodes, []))
    const ownedCloserNodeEncoded = objectFreeze(reflectApply(arraySlice, closerNodeEncoded, []))
    result = objectFreeze({
      requestId,
      commandId,
      commandVersion,
      operationClass,
      from,
      fromEncoded,
      errorCode,
      token,
      closerNodes: ownedCloserNodes,
      closerNodeEncoded: ownedCloserNodeEncoded,
      encodedResponse
    })
    requestId = null
    from = null
    fromEncoded = null
    token = null
    encodedResponse = null
    closerNodes.length = 0
    closerNodeEncoded.length = 0
    complete = true
    return result
  } finally {
    clear(body)
    clear(requestId)
    if (from !== null) {
      clear(from.id)
      clear(from.handle)
    }
    clear(fromEncoded)
    clear(token)
    clear(encodedResponse)
    for (let index = 0; index < closerNodes.length; index++) {
      clear(closerNodes[index].id)
      clear(closerNodes[index].handle)
    }
    for (let index = 0; index < closerNodeEncoded.length; index++) {
      clear(closerNodeEncoded[index])
    }
    if (!complete && result !== null) clearRoutedReply(result)
  }
}

function compareCloser(left, right, target) {
  for (let index = 0; index < 32; index++) {
    const leftDistance = left.id[index] ^ target[index]
    const rightDistance = right.id[index] ^ target[index]
    if (leftDistance !== rightDistance) return leftDistance < rightDistance ? -1 : 1
  }
  for (let index = 0; index < 32; index++) {
    if (left.id[index] !== right.id[index]) return left.id[index] < right.id[index] ? -1 : 1
  }
  return 0
}

function sameRegion(value, offset, expected, expectedBytes) {
  let difference = 0
  for (let index = 0; index < expectedBytes; index++) {
    difference |= value[offset + index] ^ expected[index]
  }
  return difference === 0
}

function validateRoutedReplyStructure(encoded, request, requestBytes) {
  const encodedBytes = bufferLength(encoded)
  if (
    encodedBytes < M3_HEADER_SIZE + ROUTED_REPLY_FIXED_BODY_SIZE ||
    encodedBytes > MAX_ROUTED_REPLY_BYTES ||
    encodedBytes - requestBytes > MAX_ROUTED_REPLY_AMPLIFICATION ||
    readUint32(encoded, 0) !== 1 ||
    readUint16(encoded, 4) !== M3_MESSAGE_ID.ROUTED_REPLY_V1
  ) {
    invalid()
  }

  const bodyBytes = readUint16(encoded, 6)
  if (
    bodyBytes < ROUTED_REPLY_FIXED_BODY_SIZE ||
    bodyBytes > MAX_ROUTED_REPLY_BODY_SIZE ||
    encodedBytes !== M3_HEADER_SIZE + bodyBytes ||
    !sameRegion(encoded, M3_HEADER_SIZE, request.requestId, 16) ||
    readUint16(encoded, M3_HEADER_SIZE + 16) !== request.commandId ||
    readUint16(encoded, M3_HEADER_SIZE + 18) !== request.commandVersion ||
    encoded[M3_HEADER_SIZE + 20] !== request.operationClass ||
    !sameRegion(encoded, M3_HEADER_SIZE + 21, request.destinationEncoded, DESTINATION_REF_SIZE)
  ) {
    invalid()
  }

  const errorCode = readUint16(encoded, M3_HEADER_SIZE + 193)
  const tokenBytes = readUint16(encoded, M3_HEADER_SIZE + 195)
  if (!knownRoutedError(errorCode) || (tokenBytes !== 0 && tokenBytes !== 32)) invalid()

  const closerCountOffset = M3_HEADER_SIZE + 197 + tokenBytes
  if (closerCountOffset + 3 > encodedBytes) invalid()
  const closerCount = encoded[closerCountOffset]
  if (closerCount > MAX_CLOSER_NODES) invalid()

  const responseLengthOffset = closerCountOffset + 1 + DESTINATION_REF_SIZE * closerCount
  if (responseLengthOffset + 2 > encodedBytes) invalid()
  const responseBytes = readUint16(encoded, responseLengthOffset)
  if (
    responseLengthOffset + 2 + responseBytes !== encodedBytes ||
    (errorCode !== 0 && (tokenBytes !== 0 || closerCount !== 0 || responseBytes !== 0))
  ) {
    invalid()
  }
  return {
    encodedBytes,
    bodyBytes,
    errorCode,
    tokenBytes,
    closerCount,
    closerNodesOffset: closerCountOffset + 1,
    responseLengthOffset,
    responseBytes
  }
}

function sameRoutedReplyStructure(left, right) {
  return (
    left.encodedBytes === right.encodedBytes &&
    left.bodyBytes === right.bodyBytes &&
    left.errorCode === right.errorCode &&
    left.tokenBytes === right.tokenBytes &&
    left.closerCount === right.closerCount &&
    left.closerNodesOffset === right.closerNodesOffset &&
    left.responseLengthOffset === right.responseLengthOffset &&
    left.responseBytes === right.responseBytes
  )
}

function validateRoutedReplyForRequest(encoded, options) {
  let reply = null
  let request = null
  let target = null
  let circuitId = null
  let ownedEncoded = null
  let authority = null
  let admission = null
  let complete = false
  const closerNodes = []
  const closerNodeEncoded = []
  try {
    const fields = exactData(options, ROUTED_REPLY_OPTION_FIELDS)
    authority = fields.referralAuthority
    request = decodeRoutedRequest(fields.encodedRequest)
    target = copy(fields.target)
    circuitId = copy(fields.circuitId)
    if (
      !fixed(target, 32) ||
      !fixed(circuitId, 16) ||
      fields.branch !== BRANCH_CLASS.LOOKUP ||
      !uint64(fields.generation) ||
      !uint64(fields.now)
    ) {
      invalid()
    }
    if (
      request.commandId !== M3_MESSAGE_ID.IMMUTABLE_GET_V1 ||
      request.commandVersion !== 1 ||
      request.operationClass !== fields.branch ||
      request.destinationValidationClass !== DESTINATION_VALIDATION_CLASS.DHT_NODE_HANDLE ||
      !same(request.encodedBody, target)
    ) {
      policyMismatch()
    }
    const requestBytes = bufferLength(fields.encodedRequest)
    const structure = validateRoutedReplyStructure(encoded, request, requestBytes)
    verifyRoutedReplyReferralAuthority(authority, {
      fromEncoded: request.destinationEncoded,
      target,
      requestId: request.requestId,
      branch: fields.branch,
      circuitId,
      generation: fields.generation,
      now: fields.now
    })
    const verifiedStructure = validateRoutedReplyStructure(encoded, request, requestBytes)
    if (!sameRoutedReplyStructure(structure, verifiedStructure)) invalid()
    for (let index = 0; index < structure.closerCount; index++) {
      const offset = structure.closerNodesOffset + DESTINATION_REF_SIZE * index
      const closerEncoded = copy(subarray(encoded, offset, offset + DESTINATION_REF_SIZE))
      let closer = null
      try {
        closer = decodeDestinationRef(closerEncoded)
        reflectApply(arrayPush, closerNodeEncoded, [closerEncoded])
        reflectApply(arrayPush, closerNodes, [closer])
      } catch (error) {
        clear(closerEncoded)
        if (closer !== null) {
          clear(closer.id)
          clear(closer.handle)
        }
        throw error
      }
    }
    for (let index = 0; index < closerNodes.length; index++) {
      if (index > 0 && compareCloser(closerNodes[index - 1], closerNodes[index], target) >= 0) {
        invalid()
      }
    }
    for (let index = 0; index < closerNodes.length; index++) {
      stageRoutedReplyReferral(authority, {
        encoded: closerNodeEncoded[index],
        decoded: closerNodes[index]
      })
    }
    const stagedStructure = validateRoutedReplyStructure(encoded, request, requestBytes)
    if (
      !sameRoutedReplyStructure(structure, stagedStructure) ||
      stagedStructure.responseBytes > MAX_IMMUTABLE_RESPONSE_BYTES
    ) {
      invalid()
    }
    ownedEncoded = copy(encoded)
    const ownedStructure = validateRoutedReplyStructure(ownedEncoded, request, requestBytes)
    if (!sameRoutedReplyStructure(structure, ownedStructure)) invalid()
    reply = decodeRoutedReply(ownedEncoded)
    if (
      !same(reply.requestId, request.requestId) ||
      reply.commandId !== request.commandId ||
      reply.commandVersion !== request.commandVersion ||
      reply.operationClass !== request.operationClass ||
      !same(reply.fromEncoded, request.destinationEncoded) ||
      reply.errorCode !== structure.errorCode ||
      bufferLength(reply.token) !== structure.tokenBytes ||
      reply.closerNodes.length !== structure.closerCount ||
      bufferLength(reply.encodedResponse) !== structure.responseBytes ||
      bufferLength(reply.encodedResponse) > MAX_IMMUTABLE_RESPONSE_BYTES
    ) {
      invalid()
    }
    for (let index = 0; index < closerNodeEncoded.length; index++) {
      if (!same(reply.closerNodeEncoded[index], closerNodeEncoded[index])) invalid()
    }
    admission = sealRoutedReplyAdmission(authority)
    authority = null
    const result = objectFreeze({ reply, admission })
    reply = null
    admission = null
    complete = true
    return result
  } finally {
    clear(target)
    clear(circuitId)
    clear(ownedEncoded)
    clearRoutedRequest(request)
    for (let index = 0; index < closerNodes.length; index++) {
      clear(closerNodes[index].id)
      clear(closerNodes[index].handle)
    }
    for (let index = 0; index < closerNodeEncoded.length; index++) {
      clear(closerNodeEncoded[index])
    }
    if (!complete) {
      clearRoutedReply(reply)
      if (admission !== null) {
        try {
          abortRoutedReplyAdmission(admission)
        } catch {}
      }
      if (authority !== null) {
        try {
          revokeRoutedReplyReferralAuthority(authority)
        } catch {}
      }
    }
  }
}

function clearRoutedReply(reply) {
  const requestId = clearDataProperty(reply, 'requestId')
  const from = clearDataProperty(reply, 'from')
  const fromEncoded = clearDataProperty(reply, 'fromEncoded')
  const token = clearDataProperty(reply, 'token')
  const closerNodes = clearDataProperty(reply, 'closerNodes')
  const closerNodeEncoded = clearDataProperty(reply, 'closerNodeEncoded')
  const encodedResponse = clearDataProperty(reply, 'encodedResponse')
  clear(requestId)
  if (from !== null) {
    clear(clearDataProperty(from, 'id'))
    clear(clearDataProperty(from, 'handle'))
  }
  clear(fromEncoded)
  clear(token)
  const closerLength = clearDataProperty(closerNodes, 'length')
  if (numberIsSafeInteger(closerLength) && closerLength >= 0 && closerLength <= MAX_CLOSER_NODES) {
    for (let index = 0; index < closerLength; index++) {
      const closer = clearDataProperty(closerNodes, stringConstructor(index))
      if (closer !== null) {
        clear(clearDataProperty(closer, 'id'))
        clear(clearDataProperty(closer, 'handle'))
      }
    }
  }
  const encodedLength = clearDataProperty(closerNodeEncoded, 'length')
  if (
    numberIsSafeInteger(encodedLength) &&
    encodedLength >= 0 &&
    encodedLength <= MAX_CLOSER_NODES
  ) {
    for (let index = 0; index < encodedLength; index++) {
      clear(clearDataProperty(closerNodeEncoded, stringConstructor(index)))
    }
  }
  clear(encodedResponse)
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

function clearDataProperty(value, name) {
  if (value === null || (typeof value !== 'object' && typeof value !== 'function')) {
    return null
  }

  try {
    const descriptor = objectGetOwnPropertyDescriptor(value, name)
    if (descriptor === undefined || !reflectApply(objectHasOwnProperty, descriptor, ['value'])) {
      return null
    }
    return descriptor.value
  } catch {
    return null
  }
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
  const requestId = clearDataProperty(request, 'requestId')
  const destination = clearDataProperty(request, 'destination')
  const destinationEncoded = clearDataProperty(request, 'destinationEncoded')
  const encodedBody = clearDataProperty(request, 'encodedBody')

  clear(requestId)
  if (destination !== null) {
    clear(clearDataProperty(destination, 'id'))
    clear(clearDataProperty(destination, 'handle'))
  }
  clear(destinationEncoded)
  clear(encodedBody)
}

module.exports = {
  DESTINATION_REF_SIZE,
  MAX_ROUTED_REPLY_BYTES,
  ROUTED_REPLY_FIXED_BODY_SIZE,
  ROUTED_REQUEST_FIXED_BODY_SIZE,
  abortRoutedReplyAdmission,
  clearRoutedReply,
  clearRoutedRequest,
  commitRoutedReplyAdmission,
  decodeDestinationRef,
  decodeRoutedReply,
  decodeRoutedRequest,
  encodeDestinationRef,
  encodeRoutedReply,
  encodeRoutedRequest,
  validateRoutedReplyForRequest,
  validateRoutedRequestForExit
}
