'use strict'

const b4a = require('b4a')
const { PrivateRouteError } = require('./errors')
const { decodePeerTransport } = require('./peer-transport-wire')
const { PEER_MESSAGE_ID, decodePeerObject, encodePeerObject } = require('./peer-protocol')

const PEER_PROTOCOL_VERSION = 2
const ADVERTISEMENT_MESSAGE_ID = 0x0300
const ADVERTISEMENT_BODY_BYTES = 188
const ADVERTISEMENT_WIRE_BYTES = 260
const ADVERTISEMENT_SIGNATURE_BYTES = 64
const DESCRIPTOR_MESSAGE_ID = 0x0340
const DESCRIPTOR_BODY_BYTES = 511
const DESCRIPTOR_WIRE_BYTES = 519
const NOISE_FRAGMENT_PREFIX_BYTES = 63
const NOISE_FRAGMENT_BYTES = 1002
const MAX_LEGACY_NOISE_BYTES = 4096
const PRIVATE_IK1_BYTES = 101
const EMPTY_AUTH_SUFFIX = b4a.alloc(0)

const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectHasOwnProperty = Object.prototype.hasOwnProperty
const reflectApply = Reflect.apply
const reflectOwnKeys = Reflect.ownKeys
const numberIsSafeInteger = Number.isSafeInteger
const typedArrayPrototype = Uint8Array.prototype
const typedArrayByteLength = objectGetOwnPropertyDescriptor(
  Object.getPrototypeOf(typedArrayPrototype),
  'byteLength'
).get
const typedArraySet = typedArrayPrototype.set
const typedArraySubarray = typedArrayPrototype.subarray
const typedArrayFill = typedArrayPrototype.fill

const ID = Object.freeze({
  PEER_DESCRIPTOR_V2: PEER_MESSAGE_ID.PEER_DESCRIPTOR_V2,
  LEGACY_RESOLVE_V2: PEER_MESSAGE_ID.LEGACY_RESOLVE_V2,
  LEGACY_RESOLVED_V2: PEER_MESSAGE_ID.LEGACY_RESOLVED_V2,
  LEGACY_RESERVE_V2: PEER_MESSAGE_ID.LEGACY_RESERVE_V2,
  LEGACY_RESERVED_V2: PEER_MESSAGE_ID.LEGACY_RESERVED_V2,
  PEER_NOISE_FRAGMENT_V2: PEER_MESSAGE_ID.PEER_NOISE_FRAGMENT_V2,
  LEGACY_HANDSHAKE_ACCEPT_V2: PEER_MESSAGE_ID.LEGACY_HANDSHAKE_ACCEPT_V2,
  LEGACY_OPEN_V2: PEER_MESSAGE_ID.LEGACY_OPEN_V2,
  ENTRY_REGISTER_V2: PEER_MESSAGE_ID.ENTRY_REGISTER_V2,
  ENTRY_REGISTERED_V2: PEER_MESSAGE_ID.ENTRY_REGISTERED_V2,
  ENTRY_REVOKE_V2: PEER_MESSAGE_ID.ENTRY_REVOKE_V2,
  PRIVATE_ACTIVATE_V2: PEER_MESSAGE_ID.PRIVATE_ACTIVATE_V2,
  PRIVATE_READY_V2: PEER_MESSAGE_ID.PRIVATE_READY_V2,
  PRIVATE_ACK_V2: PEER_MESSAGE_ID.PRIVATE_ACK_V2,
  PRIVATE_ACCEPTED_V2: PEER_MESSAGE_ID.PRIVATE_ACCEPTED_V2,
  PRIVATE_SOURCE_RECEIPT_V2: PEER_MESSAGE_ID.PRIVATE_SOURCE_RECEIPT_V2,
  PRIVATE_OPEN_V2: PEER_MESSAGE_ID.PRIVATE_OPEN_V2
})

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function isInvalidRoute(err) {
  return err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE'
}

function bufferLength(value) {
  try {
    if (!b4a.isBuffer(value)) return -1
    if (objectGetOwnPropertyDescriptor(value, 'byteLength') !== undefined) return -1
    return reflectApply(typedArrayByteLength, value, [])
  } catch {
    return -1
  }
}

function bufferSlice(value, start, end) {
  try {
    return reflectApply(typedArraySubarray, value, [start, end])
  } catch {
    invalid()
  }
}

function copyBytes(target, source, offset) {
  try {
    reflectApply(typedArraySet, target, [source, offset])
  } catch {
    invalid()
  }
}

function clearBuffer(value) {
  try {
    if (bufferLength(value) >= 0) reflectApply(typedArrayFill, value, [0])
  } catch {}
}

function exactBuffer(value, bytes) {
  if (bufferLength(value) !== bytes) invalid()
}

function nonZeroBuffer(value) {
  const bytes = bufferLength(value)
  if (bytes < 0) invalid()
  for (let index = 0; index < bytes; index++) {
    if (value[index] !== 0) return
  }
  invalid()
}

function uint(value, maximum) {
  if (typeof value !== 'number' || !numberIsSafeInteger(value) || value < 0 || value > maximum) {
    invalid()
  }
}

function positiveUint(value, maximum) {
  uint(value, maximum)
  if (value === 0) invalid()
}

function u64(value) {
  if (typeof value !== 'bigint' || value < 0n || value > 0xffffffffffffffffn) invalid()
}

function positiveU64(value) {
  u64(value)
  if (value === 0n) invalid()
}

function writeU16(buffer, value, offset) {
  buffer[offset] = value >>> 8
  buffer[offset + 1] = value
}

function writeU32(buffer, value, offset) {
  buffer[offset] = Math.floor(value / 0x1000000)
  buffer[offset + 1] = value >>> 16
  buffer[offset + 2] = value >>> 8
  buffer[offset + 3] = value
}

function writeU64(buffer, value, offset) {
  let current = value
  for (let index = 7; index >= 0; index--) {
    buffer[offset + index] = Number(current & 0xffn)
    current >>= 8n
  }
}

function readU16(buffer, offset) {
  return buffer[offset] * 0x100 + buffer[offset + 1]
}

function readU32(buffer, offset) {
  return (
    buffer[offset] * 0x1000000 +
    buffer[offset + 1] * 0x10000 +
    buffer[offset + 2] * 0x100 +
    buffer[offset + 3]
  )
}

function readU64(buffer, offset) {
  let value = 0n
  for (let index = 0; index < 8; index++) {
    value = (value << 8n) | BigInt(buffer[offset + index])
  }
  return value
}

function u8Field(name) {
  return Object.freeze({ name, type: 'u8' })
}

function u16Field(name) {
  return Object.freeze({ name, type: 'u16' })
}

function u32Field(name) {
  return Object.freeze({ name, type: 'u32' })
}

function u64Field(name) {
  return Object.freeze({ name, type: 'u64' })
}

function bytesField(name, bytes) {
  return Object.freeze({ name, type: 'bytes', bytes })
}

function trailingBytesField(name) {
  return Object.freeze({ name, type: 'trailing-bytes' })
}

function makeSchema(tag, fields, bodyBytes) {
  return Object.freeze({
    tag,
    fields: Object.freeze(fields),
    names: Object.freeze(fields.map((field) => field.name)),
    bodyBytes
  })
}

const schemas = new Map([
  [
    ID.PEER_DESCRIPTOR_V2,
    makeSchema(
      'descriptor',
      [
        u8Field('kind'),
        bytesField('expectedDestinationNoiseKey', 32),
        bytesField('entryIdentity', 32),
        u16Field('advertisementLength'),
        bytesField('advertisement', ADVERTISEMENT_WIRE_BYTES),
        bytesField('destinationPurposeDigest', 32),
        bytesField('destinationFinalTranscriptDigest', 32),
        bytesField('destinationCircuitId', 16),
        u64Field('destinationGeneration'),
        u64Field('entryEpoch'),
        u32Field('maxFrames'),
        u64Field('maxBytes'),
        u32Field('idleTimeoutMs'),
        u64Field('expiresAtUnixMs'),
        bytesField('admissionToken', 32),
        bytesField('registrationCommitment', 32)
      ],
      DESCRIPTOR_BODY_BYTES
    )
  ],
  [
    ID.LEGACY_RESOLVE_V2,
    makeSchema(
      'legacy-resolve',
      [
        bytesField('sessionId', 16),
        bytesField('expectedNoiseKey', 32),
        bytesField('clientNonce', 32),
        u64Field('deadlineUnixMs'),
        u16Field('maxCandidates'),
        u16Field('maxNoiseBytes'),
        u32Field('requestedFrames'),
        u64Field('requestedBytes')
      ],
      104
    )
  ],
  [
    ID.LEGACY_RESOLVED_V2,
    makeSchema(
      'legacy-resolved',
      [
        bytesField('sessionId', 16),
        bytesField('clientNonce', 32),
        bytesField('egressRef', 32),
        u16Field('candidateCount'),
        u64Field('expiresAtUnixMs'),
        bytesField('reservationNonce', 16)
      ],
      106
    )
  ],
  [
    ID.LEGACY_RESERVE_V2,
    makeSchema(
      'legacy-reserve',
      [
        bytesField('sessionId', 16),
        bytesField('egressRef', 32),
        bytesField('reservationNonce', 16),
        bytesField('egressServiceIdentity', 32)
      ],
      96
    )
  ],
  [
    ID.LEGACY_RESERVED_V2,
    makeSchema(
      'legacy-reserved',
      [
        bytesField('sessionId', 16),
        bytesField('egressRef', 32),
        bytesField('reservationNonce', 16),
        bytesField('sessionCapability', 32),
        u32Field('egressRawUdxId'),
        bytesField('egressServiceIdentity', 32)
      ],
      132
    )
  ],
  [
    ID.PEER_NOISE_FRAGMENT_V2,
    makeSchema(
      'noise-fragment',
      [
        bytesField('sessionId', 16),
        u8Field('flight'),
        bytesField('wholeCiphertextCommitment', 32),
        u32Field('totalCiphertextBytes'),
        u16Field('fragmentIndex'),
        u16Field('fragmentCount'),
        u32Field('ciphertextOffset'),
        u16Field('fragmentBytes'),
        trailingBytesField('ciphertext')
      ],
      null
    )
  ],
  [
    ID.LEGACY_HANDSHAKE_ACCEPT_V2,
    makeSchema(
      'legacy-handshake-accept',
      [
        bytesField('sessionId', 16),
        bytesField('egressRef', 32),
        bytesField('reservationNonce', 16),
        bytesField('ik1Digest', 32),
        bytesField('ik2Digest', 32),
        u32Field('validatedResponderUdxId')
      ],
      132
    )
  ],
  [
    ID.LEGACY_OPEN_V2,
    makeSchema(
      'legacy-open',
      [
        bytesField('sessionId', 16),
        bytesField('egressRef', 32),
        bytesField('reservationNonce', 16),
        u32Field('pendingRemoteUdxId'),
        bytesField('ik2Digest', 32)
      ],
      100
    )
  ],
  [
    ID.ENTRY_REGISTER_V2,
    makeSchema(
      'entry-register',
      [
        bytesField('destinationNoiseKey', 32),
        bytesField('circuitId', 16),
        u64Field('generation'),
        bytesField('purposeDigest', 32),
        bytesField('finalTranscriptDigest', 32),
        u64Field('entryEpoch'),
        u32Field('maxFrames'),
        u64Field('maxBytes'),
        u32Field('idleMs'),
        u64Field('expiresAtUnixMs'),
        u16Field('advertisementLength'),
        bytesField('advertisement', ADVERTISEMENT_WIRE_BYTES),
        bytesField('registerNonce', 32),
        bytesField('requestCommitment', 32)
      ],
      478
    )
  ],
  [
    ID.ENTRY_REGISTERED_V2,
    makeSchema(
      'entry-registered',
      [
        bytesField('registerNonce', 32),
        bytesField('token', 32),
        bytesField('registrationCommitment', 32),
        bytesField('circuitId', 16),
        u64Field('generation'),
        u64Field('expiresAtUnixMs'),
        u64Field('entryEpoch')
      ],
      136
    )
  ],
  [
    ID.ENTRY_REVOKE_V2,
    makeSchema(
      'entry-revoke',
      [
        bytesField('token', 32),
        bytesField('registrationCommitment', 32),
        bytesField('circuitId', 16),
        u64Field('generation')
      ],
      88
    )
  ],
  [
    ID.PRIVATE_ACTIVATE_V2,
    makeSchema(
      'private-activate',
      [
        bytesField('sessionId', 16),
        bytesField('sourceCircuitId', 16),
        u64Field('sourceGeneration'),
        bytesField('sourceFinalTranscriptDigest', 32),
        bytesField('sourcePurposeDigest', 32),
        bytesField('sourceNonce', 32),
        u16Field('descriptorLength'),
        bytesField('completeDescriptor', DESCRIPTOR_WIRE_BYTES),
        u32Field('sourceMaxFrames'),
        u64Field('sourceMaxBytes'),
        u32Field('sourceIdleMs'),
        u64Field('expiresAtUnixMs'),
        bytesField('ik1Digest', 32),
        u32Field('ik1Bytes'),
        bytesField('activateCommitment', 32)
      ],
      749
    )
  ],
  [
    ID.PRIVATE_READY_V2,
    makeSchema(
      'private-ready',
      [
        bytesField('sessionId', 16),
        bytesField('activateCommitment', 32),
        bytesField('destinationCircuitId', 16),
        u64Field('destinationGeneration'),
        bytesField('destinationNonce', 32),
        bytesField('ik1Digest', 32),
        bytesField('ik2Digest', 32),
        u64Field('expiresAtUnixMs'),
        u32Field('maxFrames'),
        u64Field('maxBytes'),
        bytesField('readyMac', 32)
      ],
      220
    )
  ],
  [
    ID.PRIVATE_ACK_V2,
    makeSchema(
      'private-ack',
      [
        bytesField('sessionId', 16),
        bytesField('activateCommitment', 32),
        bytesField('readyMac', 32),
        bytesField('sourceCircuitId', 16),
        u64Field('sourceGeneration'),
        bytesField('sourceNonce', 32),
        bytesField('destinationNonce', 32),
        bytesField('ik2Digest', 32),
        bytesField('ackMac', 32)
      ],
      232
    )
  ],
  [
    ID.PRIVATE_ACCEPTED_V2,
    makeSchema(
      'private-accepted',
      [
        bytesField('sessionId', 16),
        bytesField('activateCommitment', 32),
        bytesField('readyMac', 32),
        bytesField('ackMac', 32),
        bytesField('destinationCircuitId', 16),
        u64Field('destinationGeneration'),
        bytesField('acceptedMac', 32)
      ],
      168
    )
  ],
  [
    ID.PRIVATE_SOURCE_RECEIPT_V2,
    makeSchema(
      'private-source-receipt',
      [
        bytesField('sessionId', 16),
        bytesField('acceptedMac', 32),
        bytesField('sourceCircuitId', 16),
        u64Field('sourceGeneration'),
        bytesField('receiptNonce', 16),
        bytesField('receiptMac', 32)
      ],
      120
    )
  ],
  [
    ID.PRIVATE_OPEN_V2,
    makeSchema(
      'private-open',
      [
        bytesField('sessionId', 16),
        bytesField('activateCommitment', 32),
        bytesField('readyMac', 32),
        bytesField('ackMac', 32),
        bytesField('bridgeId', 16),
        u64Field('sourceGeneration'),
        u64Field('destinationGeneration'),
        u64Field('expiresAtUnixMs'),
        u32Field('maxFrames'),
        u64Field('maxBytes'),
        u32Field('idleMs'),
        bytesField('receiptNonce', 16),
        bytesField('receiptMac', 32)
      ],
      216
    )
  ]
])

function readDataFields(value, schema) {
  if (value === null || typeof value !== 'object') invalid()

  let keys
  try {
    keys = reflectOwnKeys(value)
  } catch {
    invalid()
  }

  if (keys.length !== schema.names.length) invalid()

  const fields = Object.create(null)
  try {
    for (const name of schema.names) {
      const descriptor = objectGetOwnPropertyDescriptor(value, name)
      if (descriptor === undefined || !objectHasOwnProperty.call(descriptor, 'value')) invalid()
      fields[name] = descriptor.value
    }
  } catch (err) {
    if (isInvalidRoute(err)) throw err
    invalid()
  }
  return fields
}

function validateAdvertisement(value) {
  exactBuffer(value, ADVERTISEMENT_WIRE_BYTES)

  let decoded
  try {
    decoded = decodePeerTransport(value)
    if (
      decoded.protocolVersion !== PEER_PROTOCOL_VERSION ||
      decoded.messageId !== ADVERTISEMENT_MESSAGE_ID ||
      bufferLength(decoded.body) !== ADVERTISEMENT_BODY_BYTES ||
      bufferLength(decoded.authSuffix) !== ADVERTISEMENT_SIGNATURE_BYTES
    ) {
      invalid()
    }

    const body = decoded.body
    if (
      readU32(body, 115) !== 11 ||
      readU32(body, 119) !== PEER_PROTOCOL_VERSION ||
      readU32(body, 123) !== PEER_PROTOCOL_VERSION ||
      readU16(body, 186) !== 0
    ) {
      invalid()
    }
  } catch (err) {
    if (isInvalidRoute(err)) throw err
    invalid()
  } finally {
    if (decoded !== undefined) {
      clearBuffer(decoded.body)
      clearBuffer(decoded.authSuffix)
    }
  }
}

function validateDescriptorWire(value) {
  exactBuffer(value, DESCRIPTOR_WIRE_BYTES)
  if (
    readU32(value, 0) !== PEER_PROTOCOL_VERSION ||
    readU16(value, 4) !== DESCRIPTOR_MESSAGE_ID ||
    readU16(value, 6) !== DESCRIPTOR_BODY_BYTES
  ) {
    invalid()
  }
  decodeBody(schemas.get(ID.PEER_DESCRIPTOR_V2), bufferSlice(value, 8, DESCRIPTOR_WIRE_BYTES))
}

function validateNonZeroField(fields, name) {
  nonZeroBuffer(fields[name])
}

function validateBodyFields(schema, fields) {
  for (const field of schema.fields) {
    const value = fields[field.name]
    switch (field.type) {
      case 'u8':
        uint(value, 0xff)
        break
      case 'u16':
        uint(value, 0xffff)
        break
      case 'u32':
        uint(value, 0xffffffff)
        break
      case 'u64':
        u64(value)
        break
      case 'bytes':
        exactBuffer(value, field.bytes)
        break
      case 'trailing-bytes':
        if (bufferLength(value) < 1 || bufferLength(value) > NOISE_FRAGMENT_BYTES) invalid()
        break
      default:
        invalid()
    }
  }

  switch (schema.tag) {
    case 'descriptor':
      if (fields.kind !== 1 || fields.advertisementLength !== ADVERTISEMENT_WIRE_BYTES) invalid()
      validateNonZeroField(fields, 'expectedDestinationNoiseKey')
      validateNonZeroField(fields, 'entryIdentity')
      validateNonZeroField(fields, 'destinationCircuitId')
      validateNonZeroField(fields, 'admissionToken')
      positiveU64(fields.destinationGeneration)
      positiveU64(fields.entryEpoch)
      positiveUint(fields.maxFrames, 0xffffffff)
      positiveU64(fields.maxBytes)
      positiveUint(fields.idleTimeoutMs, 0xffffffff)
      positiveU64(fields.expiresAtUnixMs)
      validateAdvertisement(fields.advertisement)
      break

    case 'legacy-resolve':
      validateNonZeroField(fields, 'sessionId')
      validateNonZeroField(fields, 'expectedNoiseKey')
      validateNonZeroField(fields, 'clientNonce')
      positiveU64(fields.deadlineUnixMs)
      if (fields.maxCandidates < 1 || fields.maxCandidates > 8) invalid()
      if (fields.maxNoiseBytes !== MAX_LEGACY_NOISE_BYTES) invalid()
      positiveUint(fields.requestedFrames, 0xffffffff)
      positiveU64(fields.requestedBytes)
      break

    case 'legacy-resolved':
      validateNonZeroField(fields, 'sessionId')
      validateNonZeroField(fields, 'clientNonce')
      validateNonZeroField(fields, 'egressRef')
      if (fields.candidateCount < 1 || fields.candidateCount > 8) invalid()
      positiveU64(fields.expiresAtUnixMs)
      validateNonZeroField(fields, 'reservationNonce')
      break

    case 'legacy-reserve':
      validateNonZeroField(fields, 'sessionId')
      validateNonZeroField(fields, 'egressRef')
      validateNonZeroField(fields, 'reservationNonce')
      validateNonZeroField(fields, 'egressServiceIdentity')
      break

    case 'legacy-reserved':
      validateNonZeroField(fields, 'sessionId')
      validateNonZeroField(fields, 'egressRef')
      validateNonZeroField(fields, 'reservationNonce')
      validateNonZeroField(fields, 'sessionCapability')
      positiveUint(fields.egressRawUdxId, 0xffffffff)
      validateNonZeroField(fields, 'egressServiceIdentity')
      break

    case 'noise-fragment': {
      validateNonZeroField(fields, 'sessionId')
      if (fields.flight !== 1 && fields.flight !== 2) invalid()
      if (fields.totalCiphertextBytes < 1 || fields.totalCiphertextBytes > MAX_LEGACY_NOISE_BYTES) {
        invalid()
      }
      const expectedFragmentCount = Math.ceil(fields.totalCiphertextBytes / NOISE_FRAGMENT_BYTES)
      if (
        fields.fragmentCount !== expectedFragmentCount ||
        fields.fragmentIndex >= fields.fragmentCount ||
        fields.ciphertextOffset !== fields.fragmentIndex * NOISE_FRAGMENT_BYTES
      ) {
        invalid()
      }
      const remainingBytes = fields.totalCiphertextBytes - fields.ciphertextOffset
      const expectedFragmentBytes = Math.min(NOISE_FRAGMENT_BYTES, remainingBytes)
      if (fields.fragmentBytes !== expectedFragmentBytes) invalid()
      if (bufferLength(fields.ciphertext) !== expectedFragmentBytes) invalid()
      break
    }

    case 'legacy-handshake-accept':
      validateNonZeroField(fields, 'sessionId')
      validateNonZeroField(fields, 'egressRef')
      validateNonZeroField(fields, 'reservationNonce')
      positiveUint(fields.validatedResponderUdxId, 0xffffffff)
      break

    case 'legacy-open':
      validateNonZeroField(fields, 'sessionId')
      validateNonZeroField(fields, 'egressRef')
      validateNonZeroField(fields, 'reservationNonce')
      positiveUint(fields.pendingRemoteUdxId, 0xffffffff)
      break

    case 'entry-register':
      validateNonZeroField(fields, 'destinationNoiseKey')
      validateNonZeroField(fields, 'circuitId')
      positiveU64(fields.generation)
      positiveU64(fields.entryEpoch)
      positiveUint(fields.maxFrames, 0xffffffff)
      positiveU64(fields.maxBytes)
      positiveUint(fields.idleMs, 0xffffffff)
      positiveU64(fields.expiresAtUnixMs)
      if (fields.advertisementLength !== ADVERTISEMENT_WIRE_BYTES) invalid()
      validateAdvertisement(fields.advertisement)
      validateNonZeroField(fields, 'registerNonce')
      break

    case 'entry-registered':
      validateNonZeroField(fields, 'registerNonce')
      validateNonZeroField(fields, 'token')
      validateNonZeroField(fields, 'circuitId')
      positiveU64(fields.generation)
      positiveU64(fields.expiresAtUnixMs)
      positiveU64(fields.entryEpoch)
      break

    case 'entry-revoke':
      validateNonZeroField(fields, 'token')
      validateNonZeroField(fields, 'circuitId')
      positiveU64(fields.generation)
      break

    case 'private-activate':
      validateNonZeroField(fields, 'sessionId')
      validateNonZeroField(fields, 'sourceCircuitId')
      positiveU64(fields.sourceGeneration)
      validateNonZeroField(fields, 'sourceNonce')
      if (fields.descriptorLength !== DESCRIPTOR_WIRE_BYTES) invalid()
      validateDescriptorWire(fields.completeDescriptor)
      positiveUint(fields.sourceMaxFrames, 0xffffffff)
      positiveU64(fields.sourceMaxBytes)
      positiveUint(fields.sourceIdleMs, 0xffffffff)
      positiveU64(fields.expiresAtUnixMs)
      if (fields.ik1Bytes !== PRIVATE_IK1_BYTES) invalid()
      break

    case 'private-ready':
      validateNonZeroField(fields, 'sessionId')
      validateNonZeroField(fields, 'destinationCircuitId')
      validateNonZeroField(fields, 'destinationNonce')
      positiveU64(fields.destinationGeneration)
      positiveU64(fields.expiresAtUnixMs)
      positiveUint(fields.maxFrames, 0xffffffff)
      positiveU64(fields.maxBytes)
      break

    case 'private-ack':
      validateNonZeroField(fields, 'sessionId')
      validateNonZeroField(fields, 'sourceCircuitId')
      validateNonZeroField(fields, 'sourceNonce')
      validateNonZeroField(fields, 'destinationNonce')
      positiveU64(fields.sourceGeneration)
      break

    case 'private-accepted':
      validateNonZeroField(fields, 'sessionId')
      validateNonZeroField(fields, 'destinationCircuitId')
      positiveU64(fields.destinationGeneration)
      break

    case 'private-source-receipt':
      validateNonZeroField(fields, 'sessionId')
      validateNonZeroField(fields, 'sourceCircuitId')
      validateNonZeroField(fields, 'receiptNonce')
      positiveU64(fields.sourceGeneration)
      break

    case 'private-open':
      validateNonZeroField(fields, 'sessionId')
      validateNonZeroField(fields, 'bridgeId')
      validateNonZeroField(fields, 'receiptNonce')
      positiveU64(fields.sourceGeneration)
      positiveU64(fields.destinationGeneration)
      positiveU64(fields.expiresAtUnixMs)
      positiveUint(fields.maxFrames, 0xffffffff)
      positiveU64(fields.maxBytes)
      positiveUint(fields.idleMs, 0xffffffff)
      break

    default:
      invalid()
  }
}

function bodyLength(schema, fields) {
  if (schema.bodyBytes !== null) return schema.bodyBytes
  let bytes = 0
  for (const field of schema.fields) {
    if (field.type === 'u8') bytes += 1
    else if (field.type === 'u16') bytes += 2
    else if (field.type === 'u32') bytes += 4
    else if (field.type === 'u64') bytes += 8
    else if (field.type === 'bytes') bytes += field.bytes
    else if (field.type === 'trailing-bytes') bytes += bufferLength(fields[field.name])
    else invalid()
  }
  return bytes
}

function encodeBody(schema, fields) {
  validateBodyFields(schema, fields)
  const bytes = bodyLength(schema, fields)
  if (bytes < 1 || bytes > 0xffff) invalid()

  const body = b4a.allocUnsafe(bytes)
  let offset = 0
  for (const field of schema.fields) {
    const value = fields[field.name]
    switch (field.type) {
      case 'u8':
        body[offset] = value
        offset += 1
        break
      case 'u16':
        writeU16(body, value, offset)
        offset += 2
        break
      case 'u32':
        writeU32(body, value, offset)
        offset += 4
        break
      case 'u64':
        writeU64(body, value, offset)
        offset += 8
        break
      case 'bytes':
        copyBytes(body, value, offset)
        offset += field.bytes
        break
      case 'trailing-bytes':
        copyBytes(body, value, offset)
        offset += bufferLength(value)
        break
      default:
        clearBuffer(body)
        invalid()
    }
  }

  if (offset !== bytes) {
    clearBuffer(body)
    invalid()
  }
  return body
}

function decodeBody(schema, body) {
  const bytes = bufferLength(body)
  if (bytes < 0) invalid()
  if (schema.bodyBytes === null) {
    if (
      bytes < NOISE_FRAGMENT_PREFIX_BYTES + 1 ||
      bytes > NOISE_FRAGMENT_PREFIX_BYTES + NOISE_FRAGMENT_BYTES
    ) {
      invalid()
    }
  } else if (bytes !== schema.bodyBytes) {
    invalid()
  }

  const fields = Object.create(null)
  let offset = 0
  for (const field of schema.fields) {
    switch (field.type) {
      case 'u8':
        fields[field.name] = body[offset]
        offset += 1
        break
      case 'u16':
        fields[field.name] = readU16(body, offset)
        offset += 2
        break
      case 'u32':
        fields[field.name] = readU32(body, offset)
        offset += 4
        break
      case 'u64':
        fields[field.name] = readU64(body, offset)
        offset += 8
        break
      case 'bytes':
        fields[field.name] = bufferSlice(body, offset, offset + field.bytes)
        offset += field.bytes
        break
      case 'trailing-bytes':
        fields[field.name] = bufferSlice(body, offset, bytes)
        offset = bytes
        break
      default:
        invalid()
    }
  }

  if (offset !== bytes) invalid()
  validateBodyFields(schema, fields)
  return fields
}

function publicFields(schema, values) {
  const fields = {}
  for (const field of schema.fields) fields[field.name] = values[field.name]
  return fields
}

function encodePeerSemantic(messageId, fields) {
  let body
  try {
    if (typeof messageId !== 'number' || !numberIsSafeInteger(messageId)) invalid()
    const schema = schemas.get(messageId)
    if (schema === undefined) invalid()
    const values = readDataFields(fields, schema)
    body = encodeBody(schema, values)
    return encodePeerObject({ messageId, body, authSuffix: EMPTY_AUTH_SUFFIX })
  } catch (err) {
    if (isInvalidRoute(err)) throw err
    invalid()
  } finally {
    if (body !== undefined) clearBuffer(body)
  }
}

function decodePeerSemantic(wire) {
  let decoded
  try {
    decoded = decodePeerObject(wire)
    if (decoded.protocolVersion !== PEER_PROTOCOL_VERSION) invalid()
    const schema = schemas.get(decoded.messageId)
    if (schema === undefined) invalid()
    if (bufferLength(decoded.authSuffix) !== 0) invalid()
    const values = decodeBody(schema, decoded.body)
    return {
      protocolVersion: decoded.protocolVersion,
      messageId: decoded.messageId,
      fields: publicFields(schema, values),
      body: decoded.body,
      authSuffix: decoded.authSuffix
    }
  } catch (err) {
    if (decoded !== undefined) {
      clearBuffer(decoded.body)
      clearBuffer(decoded.authSuffix)
    }
    if (isInvalidRoute(err)) throw err
    invalid()
  }
}

module.exports = {
  decodePeerSemantic,
  encodePeerSemantic
}
