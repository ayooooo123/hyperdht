'use strict'

const b4a = require('b4a')

const { PrivateRouteError } = require('./errors')
const {
  PEER_MESSAGE_ID,
  PEER_SEMANTIC_ID_REGISTRY,
  encodePeerObject,
  decodePeerObject
} = require('./peer-protocol')

const MAX_U64 = 0xffff_ffff_ffff_ffffn
const EMPTY = b4a.alloc(0)

const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype)
const bufferByteLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get
const bufferSet = Uint8Array.prototype.set
const bufferSubarray = Uint8Array.prototype.subarray
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectHasOwnProperty = Object.prototype.hasOwnProperty
const reflectOwnKeys = Reflect.ownKeys
const arrayIsArray = Array.isArray

const ID = Object.freeze({
  capability: PEER_MESSAGE_ID.PEER_CAPABILITY_ADVERTISEMENT_V2,
  capsQuery: PEER_MESSAGE_ID.PEER_CAPS_QUERY_V2,
  capsCookieChallenge: PEER_MESSAGE_ID.PEER_CAPS_COOKIE_CHALLENGE_V2,
  capsResponse: PEER_MESSAGE_ID.PEER_CAPS_RESPONSE_V2,
  activeChallenge: PEER_MESSAGE_ID.PEER_ACTIVE_CHALLENGE_V2,
  activeChallengeResponse: PEER_MESSAGE_ID.PEER_ACTIVE_CHALLENGE_RESPONSE_V2,
  discoverRequest: PEER_MESSAGE_ID.PEER_DISCOVER_REQUEST_V2,
  discoverResponse: PEER_MESSAGE_ID.PEER_DISCOVER_RESPONSE_V2,
  linkOffer: PEER_MESSAGE_ID.PEER_LINK_OFFER_V2,
  linkAccept: PEER_MESSAGE_ID.PEER_LINK_ACCEPT_V2,
  redactedResponderProof: PEER_MESSAGE_ID.PEER_REDACTED_RESPONDER_PROOF_V2,
  extended: PEER_MESSAGE_ID.PEER_EXTENDED_V2,
  tailReady: PEER_MESSAGE_ID.PEER_TAIL_READY_V2,
  extendRequest: PEER_MESSAGE_ID.PEER_EXTEND_REQUEST_V2,
  branchDestroy: PEER_MESSAGE_ID.PEER_BRANCH_DESTROY_V2,
  branchTeardown: PEER_MESSAGE_ID.PEER_BRANCH_TEARDOWN_V2,
  branchTeardownAck: PEER_MESSAGE_ID.PEER_BRANCH_TEARDOWN_ACK_V2,
  routeOffer: PEER_MESSAGE_ID.PEER_ROUTE_OFFER_V2,
  routeAccept: PEER_MESSAGE_ID.PEER_ROUTE_ACCEPT_V2,
  routeReject: PEER_MESSAGE_ID.PEER_ROUTE_REJECT_V2,
  reliablePacket: PEER_MESSAGE_ID.PEER_RELIABLE_PACKET_V2,
  reliableAck: PEER_MESSAGE_ID.PEER_RELIABLE_ACK_V2,
  open: PEER_MESSAGE_ID.PEER_OPEN_V2,
  opened: PEER_MESSAGE_ID.PEER_OPENED_V2,
  handshake: PEER_MESSAGE_ID.PEER_HANDSHAKE_V2,
  data: PEER_MESSAGE_ID.PEER_DATA_V2,
  credit: PEER_MESSAGE_ID.PEER_CREDIT_V2,
  fin: PEER_MESSAGE_ID.PEER_FIN_V2,
  close: PEER_MESSAGE_ID.PEER_CLOSE_V2,
  reset: PEER_MESSAGE_ID.PEER_RESET_V2,
  routeClose: PEER_MESSAGE_ID.PEER_ROUTE_CLOSE_V2,
  routeCloseAck: PEER_MESSAGE_ID.PEER_ROUTE_CLOSE_ACK_V2
})

const STREAM_IDS = Object.freeze([
  ID.open,
  ID.opened,
  ID.handshake,
  ID.data,
  ID.credit,
  ID.fin,
  ID.close,
  ID.reset
])

const COMMON_NAMES = Object.freeze([
  'routeId',
  'streamId',
  'streamEpoch',
  'direction',
  'flags',
  'reserved',
  'position'
])
const LIMIT_NAMES = Object.freeze([
  'cellSize',
  'maxCells',
  'maxBytes',
  'maxCommands',
  'idleTimeoutMs',
  'expiresAt'
])

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function safeObject(value) {
  try {
    return value !== null && typeof value === 'object' && !arrayIsArray(value)
  } catch {
    return false
  }
}

function ownData(value, name) {
  let descriptor
  try {
    descriptor = objectGetOwnPropertyDescriptor(value, name)
  } catch {
    invalid()
  }
  if (descriptor === undefined || !objectHasOwnProperty.call(descriptor, 'value')) invalid()
  return descriptor.value
}

function exactObject(value, names) {
  if (!safeObject(value)) invalid()
  let keys
  try {
    keys = reflectOwnKeys(value)
  } catch {
    invalid()
  }
  if (keys.length !== names.length) invalid()
  const expected = new Set(names)
  for (const key of keys) {
    if (typeof key !== 'string' || !expected.has(key)) invalid()
  }
  const result = {}
  for (const name of names) result[name] = ownData(value, name)
  return result
}

function bufferLength(value) {
  try {
    if (!b4a.isBuffer(value)) return -1
    if (objectGetOwnPropertyDescriptor(value, 'byteLength') !== undefined) return -1
    return bufferByteLength.call(value)
  } catch {
    return -1
  }
}

function fixedBuffer(value, size) {
  return bufferLength(value) === size
}

function zeroBuffer(value) {
  const length = bufferLength(value)
  if (length < 0) return false
  for (let index = 0; index < length; index++) {
    if (value[index] !== 0) return false
  }
  return true
}

function nonzeroBuffer(value) {
  const length = bufferLength(value)
  if (length < 0) return false
  for (let index = 0; index < length; index++) {
    if (value[index] !== 0) return true
  }
  return false
}

function clearBuffer(value) {
  try {
    if (b4a.isBuffer(value)) value.fill(0)
  } catch {}
}

function slice(value, start, end) {
  try {
    return bufferSubarray.call(value, start, end)
  } catch {
    invalid()
  }
}

function setBuffer(target, source, offset) {
  try {
    bufferSet.call(target, source, offset)
  } catch {
    invalid()
  }
}

function u8(value) {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= 0xff
}

function u16(value) {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= 0xffff
}

function u32(value) {
  return (
    typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= 0xffff_ffff
  )
}

function u64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= MAX_U64
}

function readU16(buffer, offset) {
  return (buffer[offset] << 8) | buffer[offset + 1]
}

function readU32(buffer, offset) {
  return (
    buffer[offset] * 0x1000000 +
    (buffer[offset + 1] << 16) +
    (buffer[offset + 2] << 8) +
    buffer[offset + 3]
  )
}

function readU64(buffer, offset) {
  let value = 0n
  for (let index = offset; index < offset + 8; index++) {
    value = (value << 8n) | BigInt(buffer[index])
  }
  return value
}

function writeU16(buffer, value, offset) {
  buffer[offset] = value >>> 8
  buffer[offset + 1] = value
}

function writeU32(buffer, value, offset) {
  buffer[offset] = value >>> 24
  buffer[offset + 1] = value >>> 16
  buffer[offset + 2] = value >>> 8
  buffer[offset + 3] = value
}

function writeU64(buffer, value, offset) {
  for (let index = offset + 7; index >= offset; index--) {
    buffer[index] = Number(value & 0xffn)
    value >>= 8n
  }
}

function bytesField(name, size, options = {}) {
  return Object.assign({ name, kind: 'bytes', size }, options)
}

function dynamicBytesField(name, lengthFrom, minimum, maximum, options = {}) {
  return Object.assign({ name, kind: 'bytes', size: null, lengthFrom, minimum, maximum }, options)
}

function scalarField(name, kind, options = {}) {
  return Object.assign({ name, kind }, options)
}

function commonField(stable) {
  return { name: 'common', kind: 'common', stable }
}

function limitsField(name) {
  return { name, kind: 'limits' }
}

function schema(messageId, minimumBodyBytes, maximumBodyBytes, suffixBytes, fields, validate) {
  return {
    messageId,
    minimumBodyBytes,
    maximumBodyBytes,
    suffixBytes,
    fields,
    fieldNames: Object.freeze(fields.map((field) => field.name)),
    validate
  }
}

function validateScalar(field, value) {
  const valid =
    field.kind === 'u8'
      ? u8(value)
      : field.kind === 'u16'
        ? u16(value)
        : field.kind === 'u32'
          ? u32(value)
          : field.kind === 'u64'
            ? u64(value)
            : false
  if (!valid) invalid()
  if (field.constant !== undefined && value !== field.constant) invalid()
  if (field.allowed !== undefined && !field.allowed.includes(value)) invalid()
  if (field.nonzero && (value === 0 || value === 0n)) invalid()
}

function validateLimitsObject(value) {
  const normalized = exactObject(value, LIMIT_NAMES)
  validateScalar({ kind: 'u16', constant: 1200 }, normalized.cellSize)
  validateScalar({ kind: 'u32', nonzero: true }, normalized.maxCells)
  validateScalar({ kind: 'u32', nonzero: true }, normalized.maxBytes)
  validateScalar({ kind: 'u32', nonzero: true }, normalized.maxCommands)
  validateScalar({ kind: 'u32', nonzero: true }, normalized.idleTimeoutMs)
  validateScalar({ kind: 'u64', nonzero: true }, normalized.expiresAt)
  return normalized
}

function validateCommonObject(value, stable) {
  const common = exactObject(value, COMMON_NAMES)
  if (!fixedBuffer(common.routeId, 16)) invalid()
  validateScalar({ kind: 'u64', nonzero: true }, common.streamId)
  validateScalar({ kind: 'u32', nonzero: true }, common.streamEpoch)
  validateScalar({ kind: 'u8', allowed: [0, 1] }, common.direction)
  validateScalar({ kind: 'u8', constant: 0 }, common.flags)
  validateScalar({ kind: 'u16', constant: 0 }, common.reserved)
  validateScalar({ kind: 'u64' }, common.position)
  if (stable && common.position !== 0n) invalid()
  return common
}

function validateNestedPeerObject(value, field, values) {
  let nested = null
  try {
    if (bufferLength(value) < 0) invalid()
    nested = decodePeerObject(value)
    if (!nested || nested.protocolVersion !== 2) invalid()
    if (field.expectedId !== undefined && nested.messageId !== field.expectedId) invalid()
    if (field.allowedIds !== undefined && !field.allowedIds.includes(nested.messageId)) invalid()

    if (field.parseKnown !== false) {
      const nestedSchema = SCHEMAS.get(nested.messageId)
      if (nestedSchema) {
        const nestedFields = decodeFieldsBody(nested.body, nestedSchema)
        if (field.matchCommonRouteId && values && values.routeId && nestedFields.common) {
          if (!b4a.equals(nestedFields.common.routeId, values.routeId)) invalid()
        }
        if (field.checkLaneFlags && values && values.flags !== undefined && nestedFields.common) {
          if (nested.messageId === ID.data && values.flags !== 0) invalid()
          if (
            (nested.messageId === ID.open ||
              nested.messageId === ID.opened ||
              nested.messageId === ID.credit ||
              nested.messageId === ID.fin ||
              nested.messageId === ID.close ||
              nested.messageId === ID.reset) &&
            values.flags !== 1
          ) {
            invalid()
          }
        }
      }
    }
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  } finally {
    if (nested) {
      clearBuffer(nested.body)
      clearBuffer(nested.authSuffix)
    }
  }
}

function validateBytesField(field, value, expectedLength, values) {
  if (!fixedBuffer(value, expectedLength)) invalid()
  if (field.nonzero && !nonzeroBuffer(value)) invalid()
  if (expectedLength !== 0 && (field.expectedId !== undefined || field.allowedIds !== undefined)) {
    validateNestedPeerObject(value, field, values)
  }
  return value
}

function normalizeDescriptor(field, value, values) {
  if (field.kind === 'common') return validateCommonObject(value, field.stable)
  if (field.kind === 'limits') return validateLimitsObject(value)
  if (field.kind === 'bytes') {
    const expectedLength = field.size === null ? values[field.lengthFrom] : field.size
    if (!u32(expectedLength)) invalid()
    if (expectedLength < field.minimum || expectedLength > field.maximum) invalid()
    return validateBytesField(field, value, expectedLength, values)
  }
  validateScalar(field, value)
  return value
}

function normalizeFields(value, currentSchema) {
  const source = exactObject(value, currentSchema.fieldNames)
  const normalized = {}
  for (const field of currentSchema.fields) {
    normalized[field.name] = normalizeDescriptor(field, source[field.name], normalized)
  }
  if (currentSchema.validate) currentSchema.validate(normalized)
  return normalized
}

function descriptorSize(field, value) {
  if (field.kind === 'common') return 40
  if (field.kind === 'limits') return 26
  if (field.kind === 'u8') return 1
  if (field.kind === 'u16') return 2
  if (field.kind === 'u32') return 4
  if (field.kind === 'u64') return 8
  if (field.size !== null) return field.size
  return bufferLength(value)
}

function bodySize(currentSchema, values) {
  let size = 0
  for (const field of currentSchema.fields) {
    size += descriptorSize(field, values[field.name])
  }
  if (
    !Number.isSafeInteger(size) ||
    size < currentSchema.minimumBodyBytes ||
    size > currentSchema.maximumBodyBytes
  ) {
    invalid()
  }
  return size
}

function writeCommon(buffer, value, offset) {
  setBuffer(buffer, value.routeId, offset)
  writeU64(buffer, value.streamId, offset + 16)
  writeU32(buffer, value.streamEpoch, offset + 24)
  buffer[offset + 28] = value.direction
  buffer[offset + 29] = value.flags
  writeU16(buffer, value.reserved, offset + 30)
  writeU64(buffer, value.position, offset + 32)
}

function writeLimits(buffer, value, offset) {
  writeU16(buffer, value.cellSize, offset)
  writeU32(buffer, value.maxCells, offset + 2)
  writeU32(buffer, value.maxBytes, offset + 6)
  writeU32(buffer, value.maxCommands, offset + 10)
  writeU32(buffer, value.idleTimeoutMs, offset + 14)
  writeU64(buffer, value.expiresAt, offset + 18)
}

function encodePeerLimits(limits) {
  const normalized = validateLimitsObject(limits)
  const buffer = b4a.allocUnsafeSlow(26)
  writeLimits(buffer, normalized, 0)
  return buffer
}

function decodePeerLimits(buffer) {
  if (!fixedBuffer(buffer, 26)) invalid()
  return decodeLimitsObject(buffer, 0)
}

function encodeBody(values, currentSchema) {
  const body = b4a.allocUnsafeSlow(bodySize(currentSchema, values))
  let offset = 0
  try {
    for (const field of currentSchema.fields) {
      const value = values[field.name]
      if (field.kind === 'common') {
        writeCommon(body, value, offset)
      } else if (field.kind === 'limits') {
        writeLimits(body, value, offset)
      } else if (field.kind === 'bytes') {
        setBuffer(body, value, offset)
      } else if (field.kind === 'u8') {
        body[offset] = value
      } else if (field.kind === 'u16') {
        writeU16(body, value, offset)
      } else if (field.kind === 'u32') {
        writeU32(body, value, offset)
      } else {
        writeU64(body, value, offset)
      }
      offset += descriptorSize(field, value)
    }
    if (offset !== body.byteLength) invalid()
    return body
  } catch (err) {
    clearBuffer(body)
    throw err
  }
}

function decodeCommonObject(body, offset, stable) {
  const common = {
    routeId: slice(body, offset, offset + 16),
    streamId: readU64(body, offset + 16),
    streamEpoch: readU32(body, offset + 24),
    direction: body[offset + 28],
    flags: body[offset + 29],
    reserved: readU16(body, offset + 30),
    position: readU64(body, offset + 32)
  }
  validateCommonObject(common, stable)
  return common
}

function decodeLimitsObject(body, offset) {
  return validateLimitsObject({
    cellSize: readU16(body, offset),
    maxCells: readU32(body, offset + 2),
    maxBytes: readU32(body, offset + 6),
    maxCommands: readU32(body, offset + 10),
    idleTimeoutMs: readU32(body, offset + 14),
    expiresAt: readU64(body, offset + 18)
  })
}

function decodeDescriptor(body, field, values, offset) {
  if (field.kind === 'common')
    return { value: decodeCommonObject(body, offset, field.stable), size: 40 }
  if (field.kind === 'limits') return { value: decodeLimitsObject(body, offset), size: 26 }
  if (field.kind === 'u8') {
    const value = body[offset]
    validateScalar(field, value)
    return { value, size: 1 }
  }
  if (field.kind === 'u16') {
    const value = readU16(body, offset)
    validateScalar(field, value)
    return { value, size: 2 }
  }
  if (field.kind === 'u32') {
    const value = readU32(body, offset)
    validateScalar(field, value)
    return { value, size: 4 }
  }
  if (field.kind === 'u64') {
    const value = readU64(body, offset)
    validateScalar(field, value)
    return { value, size: 8 }
  }

  const expectedLength = field.size === null ? values[field.lengthFrom] : field.size
  if (!u32(expectedLength)) invalid()
  if (expectedLength < field.minimum || expectedLength > field.maximum) invalid()
  const value = slice(body, offset, offset + expectedLength)
  validateBytesField(field, value, expectedLength, values)
  return { value, size: expectedLength }
}

function decodeFieldsBody(body, currentSchema) {
  const length = bufferLength(body)
  if (length < currentSchema.minimumBodyBytes || length > currentSchema.maximumBodyBytes) {
    invalid()
  }
  const fields = {}
  let offset = 0
  for (const field of currentSchema.fields) {
    const decoded = decodeDescriptor(body, field, fields, offset)
    fields[field.name] = decoded.value
    offset += decoded.size
    if (offset > length) invalid()
  }
  if (offset !== length) invalid()
  if (currentSchema.validate) currentSchema.validate(fields)
  return fields
}

function validMask(value) {
  return value === 9 || value === 11
}

function validateCapability(value) {
  if (!validMask(value.capabilityMask)) invalid()
  if (value.issuedAt >= value.expiresAt) invalid()
}

function validateCapsQuery(value) {
  if (!validMask(value.requestedMask)) invalid()
  if (value.phase === 0) {
    if (value.cookieExpiresAt !== 0n || !zeroBuffer(value.returnCookie)) invalid()
  } else if (value.cookieExpiresAt === 0n) {
    invalid()
  }
}

function validateCookieChallenge(value) {
  if (value.cookieExpiresAt === 0n) invalid()
}

function validateActiveChallenge(value) {
  if (value.challengeExpiresAt === 0n || value.cookieExpiresAt === 0n) invalid()
  if (value.challengeExpiresAt > value.cookieExpiresAt) invalid()
}

function validateActiveChallengeResponse(value) {
  if (value.challengeExpiresAt === 0n || value.cookieExpiresAt === 0n) invalid()
  if (value.challengeExpiresAt > value.cookieExpiresAt) invalid()
}

function validateDiscoverRequest(value) {
  if (!validMask(value.requestedMask)) invalid()
  if (value.mode === 1) {
    if (value.suppliedAdvertisementLength !== 0) invalid()
  } else {
    if (value.suppliedAdvertisementLength !== 260 || value.requestedMask !== 11) invalid()
  }
}

function validateDiscoverResponse(value) {
  if (value.verifiedAt >= value.expiresAt) invalid()
}

function validateLinkOffer(value) {
  if (value.extensionIndex === 0) {
    if (!zeroBuffer(value.candidateAuthorityCommitment)) invalid()
  } else {
    if (!nonzeroBuffer(value.candidateAuthorityCommitment)) invalid()
  }
}

function validateExtendRequest(value) {
  if (value.extensionIndex === 0) {
    if (!zeroBuffer(value.candidateAuthorityCommitment)) invalid()
  } else {
    if (!nonzeroBuffer(value.candidateAuthorityCommitment)) invalid()
  }
}

function validateAck(value) {
  if (value.controlBitmap >> 16n !== 0n) invalid()
  if (value.ackSnapshot === 0) {
    if (
      value.dataCumulative !== MAX_U64 ||
      value.dataBitmap !== 0n ||
      value.controlCumulative !== MAX_U64 ||
      value.controlBitmap !== 0n
    ) {
      invalid()
    }
  }
}

function validateOpen(value) {
  if (value.semanticFirstId === 0x0349) {
    if (
      value.semanticClass !== 1 ||
      value.firstSemanticWireBytes !== 486 ||
      value.requestedHandshakeFrames !== 2 ||
      value.requestedHandshakeBytes !== 582n
    ) {
      invalid()
    }
  } else if (value.semanticFirstId === 0x0360) {
    if (
      value.semanticClass !== 2 ||
      value.firstSemanticWireBytes !== 757 ||
      value.requestedHandshakeFrames !== 4 ||
      (value.requestedHandshakeBytes !== 1297n && value.requestedHandshakeBytes !== 1393n)
    ) {
      invalid()
    }
  } else if (value.semanticFirstId === 0x0341) {
    if (
      value.semanticClass !== 2 ||
      value.firstSemanticWireBytes !== 112 ||
      value.requestedHandshakeFrames !== 12 ||
      value.requestedHandshakeBytes !== 4807n
    ) {
      invalid()
    }
  } else {
    invalid()
  }
}

function validateHandshake(value) {
  const offset = value.semanticObjectOffset
  const payload = value.bytes
  const flags = value.fragmentFlags
  if ((flags & ~3) !== 0) invalid()
  const first = (flags & 1) !== 0
  const last = (flags & 2) !== 0

  if ((offset !== 0 && offset !== 981) || first !== (offset === 0)) invalid()

  if (offset === 0) {
    if (payload.byteLength < 8) invalid()
    const ver = readU32(payload, 0)
    const semId = readU16(payload, 4)
    const bodyBytes = readU16(payload, 6)
    if (ver !== 2) invalid()
    if (!PEER_SEMANTIC_ID_REGISTRY.includes(semId)) invalid()
    const totalWire = 8 + bodyBytes
    if (totalWire < 8 || totalWire > 1073) invalid()
    if (totalWire <= 981) {
      if (payload.byteLength !== totalWire || !last) invalid()
    } else {
      if (payload.byteLength !== 981 || last) invalid()
    }
  } else {
    if (payload.byteLength > 92 || !last) invalid()
  }
}

function validateFin(value) {
  if ((value.finalCiphertextOffset === 0n) !== (value.finalDataSequence === MAX_U64)) invalid()
}

function validateRouteReject(value) {
  if (!zeroBuffer(value.reserved3)) invalid()
}

function validateRouteClose(value) {
  if (
    !nonzeroBuffer(value.routeId) ||
    value.generation === 0n ||
    !nonzeroBuffer(value.closeNonce)
  ) {
    invalid()
  }
}

const SCHEMAS = new Map([
  [
    ID.capability,
    schema(
      ID.capability,
      188,
      188,
      64,
      [
        bytesField('relayIdentity', 32),
        bytesField('currentDhtNodeId', 32),
        bytesField('reachableEndpoint', 19),
        bytesField('routeEncryptionPublicKey', 32),
        scalarField('capabilityMask', 'u32', { allowed: [9, 11] }),
        scalarField('minimumVersion', 'u32', { constant: 2 }),
        scalarField('maximumVersion', 'u32', { constant: 2 }),
        scalarField('cellSize', 'u16', { constant: 1200 }),
        scalarField('maxCellPayload', 'u16', { constant: 1146 }),
        scalarField('contextEnvelopeSize', 'u16', { constant: 1101 }),
        scalarField('routeFrameSize', 'u16', { constant: 1100 }),
        scalarField('maxRoutePayload', 'u16', { constant: 1073 }),
        scalarField('datagramReplayWindow', 'u16', { constant: 64 }),
        scalarField('maxConcurrentCircuits', 'u16', { nonzero: true }),
        scalarField('capacityClass', 'u8', { allowed: [0, 1, 2] }),
        scalarField('maxCells', 'u32', { nonzero: true }),
        scalarField('maxBytes', 'u32', { nonzero: true }),
        scalarField('maxCommands', 'u32', { nonzero: true }),
        scalarField('idleTimeoutMs', 'u32', { nonzero: true }),
        scalarField('maxQueuedBytes', 'u32', { nonzero: true }),
        scalarField('epoch', 'u64', { nonzero: true }),
        scalarField('issuedAt', 'u64'),
        scalarField('expiresAt', 'u64', { nonzero: true }),
        scalarField('policyCount', 'u16', { constant: 0 })
      ],
      validateCapability
    )
  ],
  [
    ID.capsQuery,
    schema(
      ID.capsQuery,
      110,
      110,
      0,
      [
        scalarField('requestedMask', 'u32', { allowed: [9, 11] }),
        bytesField('randomTarget', 32),
        bytesField('queryNonce', 32),
        scalarField('maximumResults', 'u8', { constant: 1 }),
        scalarField('phase', 'u8', { allowed: [0, 1] }),
        scalarField('cookieExpiresAt', 'u64'),
        bytesField('returnCookie', 32)
      ],
      validateCapsQuery
    )
  ],
  [
    ID.capsCookieChallenge,
    schema(
      ID.capsCookieChallenge,
      72,
      72,
      0,
      [
        bytesField('queryNonce', 32),
        scalarField('cookieExpiresAt', 'u64'),
        bytesField('returnCookie', 32)
      ],
      validateCookieChallenge
    )
  ],
  [
    ID.capsResponse,
    schema(ID.capsResponse, 335, 335, 64, [
      bytesField('responderIdentity', 32),
      bytesField('queryNonce', 32),
      scalarField('responseTime', 'u64'),
      scalarField('count', 'u8', { constant: 1 }),
      scalarField('advertisementLength', 'u16', { constant: 260 }),
      bytesField('completeAdvertisement', 260, {
        expectedId: ID.capability,
        parseKnown: true
      })
    ])
  ],
  [
    ID.activeChallenge,
    schema(
      ID.activeChallenge,
      176,
      176,
      0,
      [
        bytesField('advertisementDigest', 32),
        bytesField('responderIdentity', 32),
        bytesField('requesterEphemeralX25519PublicKey', 32),
        scalarField('challengeExpiresAt', 'u64'),
        bytesField('queryNonce', 32),
        scalarField('cookieExpiresAt', 'u64'),
        bytesField('returnCookie', 32)
      ],
      validateActiveChallenge
    )
  ],
  [
    ID.activeChallengeResponse,
    schema(
      ID.activeChallengeResponse,
      240,
      240,
      64,
      [
        bytesField('advertisementDigest', 32),
        bytesField('responderIdentity', 32),
        bytesField('requesterEphemeralPublicKey', 32),
        bytesField('responderNonce', 32),
        scalarField('challengeExpiresAt', 'u64'),
        bytesField('queryNonce', 32),
        scalarField('cookieExpiresAt', 'u64'),
        bytesField('returnCookie', 32),
        bytesField('routeKeyProof', 32)
      ],
      validateActiveChallengeResponse
    )
  ],
  [
    ID.discoverRequest,
    schema(
      ID.discoverRequest,
      79,
      339,
      0,
      [
        bytesField('requestNonce', 32),
        scalarField('mode', 'u8', { allowed: [1, 2] }),
        scalarField('requestedMask', 'u32', { allowed: [9, 11] }),
        bytesField('randomTarget', 32),
        scalarField('expiresAt', 'u64', { nonzero: true }),
        scalarField('suppliedAdvertisementLength', 'u16', { allowed: [0, 260] }),
        dynamicBytesField('suppliedAdvertisement', 'suppliedAdvertisementLength', 0, 260, {
          expectedId: ID.capability,
          parseKnown: true
        })
      ],
      validateDiscoverRequest
    )
  ],
  [
    ID.discoverResponse,
    schema(
      ID.discoverResponse,
      436,
      436,
      0,
      [
        bytesField('requestNonce', 32),
        bytesField('currentTailIdentity', 32),
        bytesField('completeAdvertisement', 260, {
          expectedId: ID.capability,
          parseKnown: true
        }),
        bytesField('activeResponseDigest', 32),
        bytesField('candidateAuthorityNonce', 32),
        scalarField('verifiedAt', 'u64'),
        scalarField('expiresAt', 'u64', { nonzero: true }),
        bytesField('candidateAuthorityCommitment', 32)
      ],
      validateDiscoverResponse
    )
  ],
  [
    ID.linkOffer,
    schema(
      ID.linkOffer,
      360,
      360,
      64,
      [
        bytesField('advertisementDigest', 32),
        bytesField('initiatorIdentity', 32),
        bytesField('responderIdentity', 32),
        scalarField('initiatorRole', 'u8', { allowed: [0, 1, 2] }),
        scalarField('responderRole', 'u8', { allowed: [0, 1, 2] }),
        scalarField('branchClass', 'u8', { constant: 2 }),
        bytesField('branchId', 16),
        bytesField('circuitId', 16),
        scalarField('generation', 'u64', { nonzero: true }),
        scalarField('extensionIndex', 'u8', { allowed: [0, 1, 2] }),
        bytesField('initiatorLinkEphemeralPublicKey', 32),
        bytesField('clientTailEphemeralPublicKey', 32),
        bytesField('clientNonce', 32),
        bytesField('payloadParametersDigest', 32),
        limitsField('requestedLimits'),
        scalarField('offerDeadline', 'u64', { nonzero: true }),
        limitsField('initiatorForwardLimits'),
        bytesField('candidateAuthorityCommitment', 32)
      ],
      validateLinkOffer
    )
  ],
  [
    ID.linkAccept,
    schema(ID.linkAccept, 213, 213, 64, [
      bytesField('offerDigest', 32),
      bytesField('advertisementDigest', 32),
      bytesField('responderIdentity', 32),
      bytesField('observedPredecessorEndpoint', 19),
      bytesField('responderLinkEphemeralPublicKey', 32),
      limitsField('admittedLimits'),
      scalarField('acceptedAt', 'u64', { nonzero: true }),
      bytesField('acceptNonce', 32)
    ])
  ],
  [
    ID.redactedResponderProof,
    schema(ID.redactedResponderProof, 306, 306, 64, [
      bytesField('responderAdvertisementDigest', 32),
      bytesField('initiatorIdentity', 32),
      bytesField('responderIdentity', 32),
      scalarField('branchClass', 'u8', { constant: 2 }),
      bytesField('branchId', 16),
      bytesField('circuitId', 16),
      scalarField('generation', 'u64', { nonzero: true }),
      scalarField('extensionIndex', 'u8', { allowed: [0, 1, 2] }),
      bytesField('clientTailEphemeralPublicKey', 32),
      bytesField('clientNonce', 32),
      bytesField('advertisedRouteEncryptionPublicKey', 32),
      bytesField('admittedLimitsDigest', 32),
      scalarField('expiresAt', 'u64', { nonzero: true }),
      bytesField('responderProofNonce', 32)
    ])
  ],
  [
    ID.extended,
    schema(ID.extended, 486, 486, 0, [
      scalarField('branchClass', 'u8', { constant: 2 }),
      bytesField('branchId', 16),
      bytesField('circuitId', 16),
      scalarField('generation', 'u64', { nonzero: true }),
      scalarField('extensionIndex', 'u8', { allowed: [0, 1, 2] }),
      bytesField('responderAdvertisementDigest', 32),
      scalarField('proofLength', 'u16', { constant: 378 }),
      bytesField('completeProof', 378, {
        expectedId: ID.redactedResponderProof,
        parseKnown: true
      }),
      bytesField('extensionNonce', 32)
    ])
  ],
  [
    ID.tailReady,
    schema(ID.tailReady, 210, 210, 64, [
      scalarField('branchClass', 'u8', { constant: 2 }),
      bytesField('branchId', 16),
      bytesField('circuitId', 16),
      scalarField('generation', 'u64', { nonzero: true }),
      scalarField('extensionIndex', 'u8', { allowed: [0, 1, 2] }),
      bytesField('tailControlTranscriptDigest', 32),
      bytesField('tailIdentity', 32),
      bytesField('tailAdvertisementDigest', 32),
      bytesField('clientNonce', 32),
      bytesField('readyNonce', 32),
      scalarField('expiresAt', 'u64', { nonzero: true })
    ])
  ],
  [
    ID.extendRequest,
    schema(
      ID.extendRequest,
      516,
      516,
      0,
      [
        scalarField('branchClass', 'u8', { constant: 2 }),
        bytesField('branchId', 16),
        bytesField('circuitId', 16),
        scalarField('generation', 'u64', { nonzero: true }),
        scalarField('extensionIndex', 'u8', { allowed: [0, 1, 2] }),
        scalarField('advertisementLength', 'u16', { constant: 260 }),
        bytesField('advertisement', 260, { expectedId: ID.capability, parseKnown: true }),
        bytesField('clientTailEphemeralPublicKey', 32),
        bytesField('clientNonce', 32),
        bytesField('payloadParametersDigest', 32),
        limitsField('successorReverseLimits'),
        bytesField('extensionNonce', 32),
        limitsField('currentTailForwardLimits'),
        bytesField('candidateAuthorityCommitment', 32)
      ],
      validateExtendRequest
    )
  ],
  [
    ID.branchDestroy,
    schema(ID.branchDestroy, 42, 42, 0, [
      scalarField('branchClass', 'u8', { constant: 2 }),
      bytesField('branchId', 16),
      bytesField('circuitId', 16),
      scalarField('generation', 'u64', { nonzero: true }),
      scalarField('reason', 'u8', { constant: 1 })
    ])
  ],
  [
    ID.branchTeardown,
    schema(ID.branchTeardown, 58, 58, 0, [
      scalarField('branchClass', 'u8', { constant: 2 }),
      bytesField('branchId', 16),
      bytesField('circuitId', 16),
      scalarField('generation', 'u64', { nonzero: true }),
      scalarField('reason', 'u8', { constant: 2 }),
      bytesField('teardownId', 16, { nonzero: true })
    ])
  ],
  [
    ID.branchTeardownAck,
    schema(ID.branchTeardownAck, 58, 58, 0, [
      scalarField('branchClass', 'u8', { constant: 2 }),
      bytesField('branchId', 16),
      bytesField('circuitId', 16),
      scalarField('generation', 'u64', { nonzero: true }),
      scalarField('reason', 'u8', { constant: 2 }),
      bytesField('teardownId', 16, { nonzero: true })
    ])
  ],
  [
    ID.routeOffer,
    schema(ID.routeOffer, 212, 212, 16, [
      bytesField('routeId', 16),
      bytesField('circuitId', 16),
      scalarField('generation', 'u64', { nonzero: true }),
      scalarField('purpose', 'u8', { allowed: [1, 2, 3] }),
      scalarField('sourceDirection', 'u8', { constant: 0 }),
      scalarField('flags', 'u16', { constant: 0 }),
      scalarField('expiresAt', 'u64', { nonzero: true }),
      bytesField('terminalAdvertisementDigest', 32),
      bytesField('queryNonce', 32),
      bytesField('clientEphemeralPublicKey', 32),
      scalarField('forwardCells', 'u32', { nonzero: true }),
      scalarField('forwardBytes', 'u64', { nonzero: true }),
      scalarField('forwardCommands', 'u32', { nonzero: true }),
      scalarField('reverseCells', 'u32', { nonzero: true }),
      scalarField('reverseBytes', 'u64', { nonzero: true }),
      scalarField('reverseCommands', 'u32', { nonzero: true }),
      scalarField('maxStreams', 'u16', { nonzero: true }),
      scalarField('receiveFrames', 'u16', { nonzero: true }),
      scalarField('receiveBytes', 'u32', { nonzero: true }),
      scalarField('semanticOwnedBytes', 'u32', { nonzero: true }),
      scalarField('maxQueuedBytes', 'u32', { nonzero: true }),
      bytesField('offerNonce', 16)
    ])
  ],
  [
    ID.routeAccept,
    schema(ID.routeAccept, 260, 260, 16, [
      bytesField('routeId', 16),
      bytesField('circuitId', 16),
      scalarField('generation', 'u64', { nonzero: true }),
      scalarField('purpose', 'u8', { allowed: [1, 2, 3] }),
      scalarField('sourceDirection', 'u8', { constant: 0 }),
      scalarField('flags', 'u16', { constant: 0 }),
      scalarField('expiresAt', 'u64', { nonzero: true }),
      bytesField('terminalAdvertisementDigest', 32),
      bytesField('queryNonce', 32),
      bytesField('clientEphemeralPublicKey', 32),
      bytesField('offerDigest', 32),
      scalarField('admittedForwardCells', 'u32', { nonzero: true }),
      scalarField('admittedForwardBytes', 'u64', { nonzero: true }),
      scalarField('admittedForwardCommands', 'u32', { nonzero: true }),
      scalarField('admittedReverseCells', 'u32', { nonzero: true }),
      scalarField('admittedReverseBytes', 'u64', { nonzero: true }),
      scalarField('admittedReverseCommands', 'u32', { nonzero: true }),
      scalarField('admittedMaxStreams', 'u16', { nonzero: true }),
      scalarField('admittedReceiveFrames', 'u16', { nonzero: true }),
      scalarField('admittedReceiveBytes', 'u32', { nonzero: true }),
      scalarField('admittedSemanticOwnedBytes', 'u32', { nonzero: true }),
      scalarField('admittedMaxQueuedBytes', 'u32', { nonzero: true }),
      bytesField('offerNonce', 16),
      bytesField('acceptNonce', 16)
    ])
  ],
  [
    ID.routeReject,
    schema(
      ID.routeReject,
      64,
      64,
      16,
      [
        bytesField('routeId', 16),
        scalarField('generation', 'u64', { nonzero: true }),
        scalarField('purpose', 'u8', { allowed: [1, 2, 3] }),
        bytesField('reserved3', 3),
        bytesField('offerNonce', 16),
        scalarField('reason', 'u16'),
        scalarField('reserved', 'u16', { constant: 0 }),
        bytesField('rejectNonce', 16)
      ],
      validateRouteReject
    )
  ],
  [
    ID.reliablePacket,
    schema(ID.reliablePacket, 29, 1065, 0, [
      bytesField('routeId', 16),
      scalarField('laneSequence', 'u64'),
      scalarField('nestedLength', 'u16'),
      scalarField('flags', 'u16', { allowed: [0, 1] }),
      dynamicBytesField('completeNestedObject', 'nestedLength', 1, 1037, {
        allowedIds: STREAM_IDS,
        matchCommonRouteId: true,
        checkLaneFlags: true,
        parseKnown: true
      })
    ])
  ],
  [
    ID.reliableAck,
    schema(
      ID.reliableAck,
      64,
      64,
      0,
      [
        bytesField('routeId', 16),
        scalarField('generation', 'u64'),
        scalarField('dataCumulative', 'u64'),
        scalarField('dataBitmap', 'u64'),
        scalarField('controlCumulative', 'u64'),
        scalarField('controlBitmap', 'u64'),
        scalarField('ackSnapshot', 'u32'),
        scalarField('reservedZero', 'u32', { constant: 0 })
      ],
      validateAck
    )
  ],
  [
    ID.open,
    schema(
      ID.open,
      88,
      88,
      0,
      [
        commonField(true),
        scalarField('semanticFirstId', 'u16'),
        scalarField('semanticClass', 'u8', { allowed: [1, 2] }),
        scalarField('reservedZero', 'u8', { constant: 0 }),
        scalarField('firstSemanticWireBytes', 'u32'),
        scalarField('requestedHandshakeFrames', 'u32', { nonzero: true }),
        scalarField('requestedHandshakeBytes', 'u64', { nonzero: true }),
        scalarField('requestedDataFrames', 'u32'),
        scalarField('requestedDataBytes', 'u64'),
        bytesField('openNonce', 16)
      ],
      validateOpen
    )
  ],
  [
    ID.opened,
    schema(ID.opened, 64, 64, 0, [
      commonField(true),
      bytesField('openNonce', 16),
      scalarField('admittedDataFrames', 'u32'),
      scalarField('admittedDataBytes', 'u32')
    ])
  ],
  [
    ID.handshake,
    schema(
      ID.handshake,
      49,
      1029,
      0,
      [
        commonField(false),
        scalarField('semanticObjectOffset', 'u32'),
        scalarField('fragmentBytes', 'u16'),
        scalarField('fragmentFlags', 'u16', { allowed: [0, 1, 2, 3] }),
        dynamicBytesField('bytes', 'fragmentBytes', 1, 981)
      ],
      validateHandshake
    )
  ],
  [
    ID.data,
    schema(ID.data, 45, 1021, 0, [
      commonField(false),
      scalarField('dataBytes', 'u16'),
      scalarField('dataFlags', 'u16', { constant: 0 }),
      dynamicBytesField('bytes', 'dataBytes', 1, 977)
    ])
  ],
  [
    ID.credit,
    schema(ID.credit, 60, 60, 0, [
      commonField(true),
      scalarField('cumulativeGrantedFrames', 'u64'),
      scalarField('cumulativeGrantedBytes', 'u64'),
      scalarField('creditEpoch', 'u32', { nonzero: true })
    ])
  ],
  [
    ID.fin,
    schema(
      ID.fin,
      56,
      56,
      0,
      [
        commonField(true),
        scalarField('finalCiphertextOffset', 'u64'),
        scalarField('finalDataSequence', 'u64')
      ],
      validateFin
    )
  ],
  [
    ID.close,
    schema(ID.close, 56, 56, 0, [
      commonField(true),
      scalarField('finalCiphertextOffset', 'u64'),
      scalarField('finalDataSequence', 'u64')
    ])
  ],
  [
    ID.reset,
    schema(ID.reset, 60, 60, 0, [
      commonField(true),
      scalarField('finalCiphertextOffset', 'u64'),
      scalarField('finalDataSequence', 'u64'),
      scalarField('errorCode', 'u16', { allowed: [1, 2, 3, 4, 5, 6, 7, 8] }),
      scalarField('reserved', 'u16', { constant: 0 })
    ])
  ],
  [
    ID.routeClose,
    schema(
      ID.routeClose,
      40,
      40,
      0,
      [
        bytesField('routeId', 16, { nonzero: true }),
        scalarField('generation', 'u64', { nonzero: true }),
        bytesField('closeNonce', 16, { nonzero: true })
      ],
      validateRouteClose
    )
  ],
  [
    ID.routeCloseAck,
    schema(
      ID.routeCloseAck,
      40,
      40,
      0,
      [
        bytesField('routeId', 16, { nonzero: true }),
        scalarField('generation', 'u64', { nonzero: true }),
        bytesField('closeNonce', 16, { nonzero: true })
      ],
      validateRouteClose
    )
  ]
])

function currentSchema(messageId) {
  if (!Number.isSafeInteger(messageId)) invalid()
  const value = SCHEMAS.get(messageId)
  if (!value) invalid()
  return value
}

function encodePeerTransport(messageId, fields, authSuffix) {
  const current = currentSchema(messageId)
  let body = null
  try {
    const normalized = normalizeFields(fields, current)
    body = encodeBody(normalized, current)
    const suffix = authSuffix === undefined ? EMPTY : authSuffix
    if (bufferLength(suffix) !== current.suffixBytes) invalid()
    return encodePeerObject({ messageId, body, authSuffix: suffix })
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  } finally {
    clearBuffer(body)
  }
}

function decodePeerTransport(wire) {
  let decoded = null
  let transferred = false
  try {
    decoded = decodePeerObject(wire)
    if (!decoded || decoded.protocolVersion !== 2) invalid()
    const current = currentSchema(decoded.messageId)
    if (
      bufferLength(decoded.body) < 0 ||
      bufferLength(decoded.authSuffix) !== current.suffixBytes
    ) {
      invalid()
    }
    const fields = decodeFieldsBody(decoded.body, current)
    const result = {
      protocolVersion: decoded.protocolVersion,
      messageId: decoded.messageId,
      fields,
      body: decoded.body,
      authSuffix: decoded.authSuffix
    }
    transferred = true
    return result
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  } finally {
    if (!transferred && decoded) {
      clearBuffer(decoded.body)
      clearBuffer(decoded.authSuffix)
    }
  }
}

function peerLinkReplyLength(extensionIndex) {
  if (extensionIndex === 0) return 285
  if (extensionIndex === 1 || extensionIndex === 2) return 663
  invalid()
}

function validatePeerLinkReplyMembers(accept285, proof378, expectedExtensionIndex) {
  if (bufferLength(accept285) !== 285 || (proof378 !== null && bufferLength(proof378) !== 378)) {
    invalid()
  }
  let accept = null
  let proof = null
  try {
    accept = decodePeerTransport(accept285)
    if (accept.messageId !== ID.linkAccept) invalid()
    if (proof378 === null) {
      if (expectedExtensionIndex !== 0) invalid()
      return
    }
    proof = decodePeerTransport(proof378)
    if (proof.messageId !== ID.redactedResponderProof) invalid()
    const index = proof.fields.extensionIndex
    if (index !== 1 && index !== 2) invalid()
    if (index !== expectedExtensionIndex) invalid()
    if (
      !b4a.equals(accept.fields.advertisementDigest, proof.fields.responderAdvertisementDigest) ||
      !b4a.equals(accept.fields.responderIdentity, proof.fields.responderIdentity) ||
      accept.fields.admittedLimits.expiresAt !== proof.fields.expiresAt
    ) {
      invalid()
    }
  } finally {
    if (accept) {
      clearBuffer(accept.body)
      clearBuffer(accept.authSuffix)
    }
    if (proof) {
      clearBuffer(proof.body)
      clearBuffer(proof.authSuffix)
    }
  }
}

function encodePeerLinkReply(accept285, proof378, expectedExtensionIndex) {
  const length = peerLinkReplyLength(expectedExtensionIndex)
  validatePeerLinkReplyMembers(accept285, proof378, expectedExtensionIndex)
  const wire = b4a.allocUnsafe(length)
  setBuffer(wire, accept285, 0)
  if (proof378 !== null) setBuffer(wire, proof378, 285)
  return wire
}

function decodePeerLinkReply(wire, expectedExtensionIndex) {
  if (bufferLength(wire) !== peerLinkReplyLength(expectedExtensionIndex)) invalid()
  const accept285 = bufferSubarray.call(wire, 0, 285)
  const proof378 = expectedExtensionIndex === 0 ? null : bufferSubarray.call(wire, 285)
  validatePeerLinkReplyMembers(accept285, proof378, expectedExtensionIndex)
  return {
    accept285: b4a.from(accept285),
    proof378: proof378 === null ? null : b4a.from(proof378)
  }
}

module.exports = {
  decodePeerTransport,
  encodePeerTransport,
  encodePeerLimits,
  decodePeerLimits,
  decodePeerLinkReply,
  encodePeerLinkReply
}
