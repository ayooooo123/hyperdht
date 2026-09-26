'use strict'

// Extracted from the reviewed private-routes prototype at commit
// 0305df915b6a767093f9e75e6c06bc0a35da6169 and narrowed to Gate 3B1.

const b4a = require('b4a')

const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')

const ADMITTED_LIMITS_SIZE = 26
const PAYLOAD_PARAMETERS_SIZE = 20
const MAX_U32 = 0xffff_ffff
const MAX_U64 = 0xffff_ffff_ffff_ffffn
const LIMITS_DOMAIN = b4a.from('hyperdht-private-routes/tail-control/limits/v1')
const PARAMETERS_DOMAIN = b4a.from('hyperdht-private-routes/final-exit/payload-parameters/v1')

const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype)
const bufferByteLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get
const bufferSet = Uint8Array.prototype.set
const bufferFill = Uint8Array.prototype.fill
const bufferSubarray = Uint8Array.prototype.subarray
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectGetPrototypeOf = Object.getPrototypeOf

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function fixed(value, size) {
  try {
    return b4a.isBuffer(value) && bufferByteLength.call(value) === size
  } catch {
    return false
  }
}

function clear(value) {
  try {
    if (b4a.isBuffer(value)) bufferFill.call(value, 0)
  } catch {}
}

function copy(value) {
  const output = b4a.allocUnsafeSlow(bufferByteLength.call(value))
  bufferSet.call(output, value)
  return output
}

function ownRecord(value, names) {
  try {
    if (
      value === null ||
      typeof value !== 'object' ||
      objectGetPrototypeOf(value) !== Object.prototype
    ) {
      invalid()
    }
    for (const name of names) {
      const descriptor = objectGetOwnPropertyDescriptor(value, name)
      if (!descriptor || !('value' in descriptor) || descriptor.enumerable !== true) invalid()
    }
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function own(value, name) {
  const descriptor = objectGetOwnPropertyDescriptor(value, name)
  if (!descriptor || !('value' in descriptor)) invalid()
  return descriptor.value
}

function u32(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= MAX_U32
}

function u64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= MAX_U64
}

function writeU16(output, value, offset) {
  output[offset] = value >>> 8
  output[offset + 1] = value
}

function writeU32(output, value, offset) {
  output[offset] = value >>> 24
  output[offset + 1] = value >>> 16
  output[offset + 2] = value >>> 8
  output[offset + 3] = value
}

function writeU64(output, value, offset) {
  for (let index = offset + 7; index >= offset; index--) {
    output[index] = Number(value & 0xffn)
    value >>= 8n
  }
}

function readU16(input, offset) {
  return input[offset] * 0x100 + input[offset + 1]
}

function readU32(input, offset) {
  return (
    input[offset] * 0x1_000000 +
    input[offset + 1] * 0x1_0000 +
    input[offset + 2] * 0x100 +
    input[offset + 3]
  )
}

function readU64(input, offset) {
  let value = 0n
  for (let index = offset; index < offset + 8; index++) value = (value << 8n) | BigInt(input[index])
  return value
}

function encodeAdmittedLimits(value) {
  const names = ['cellSize', 'maxCells', 'maxBytes', 'maxCommands', 'idleTimeoutMs', 'expiresAtMs']
  ownRecord(value, names)
  const cellSize = own(value, 'cellSize')
  const maxCells = own(value, 'maxCells')
  const maxBytes = own(value, 'maxBytes')
  const maxCommands = own(value, 'maxCommands')
  const idleTimeoutMs = own(value, 'idleTimeoutMs')
  const expiresAtMs = own(value, 'expiresAtMs')
  if (
    cellSize !== 1200 ||
    !u32(maxCells) ||
    maxCells === 0 ||
    !u32(maxBytes) ||
    maxBytes === 0 ||
    !u32(maxCommands) ||
    maxCommands === 0 ||
    !u32(idleTimeoutMs) ||
    idleTimeoutMs === 0 ||
    !u64(expiresAtMs) ||
    expiresAtMs === 0n
  )
    invalid()
  const output = b4a.allocUnsafeSlow(ADMITTED_LIMITS_SIZE)
  writeU16(output, cellSize, 0)
  writeU32(output, maxCells, 2)
  writeU32(output, maxBytes, 6)
  writeU32(output, maxCommands, 10)
  writeU32(output, idleTimeoutMs, 14)
  writeU64(output, expiresAtMs, 18)
  return output
}

function decodeAdmittedLimits(encoded) {
  if (!fixed(encoded, ADMITTED_LIMITS_SIZE)) invalid()
  const value = {
    cellSize: readU16(encoded, 0),
    maxCells: readU32(encoded, 2),
    maxBytes: readU32(encoded, 6),
    maxCommands: readU32(encoded, 10),
    idleTimeoutMs: readU32(encoded, 14),
    expiresAtMs: readU64(encoded, 18)
  }
  const canonical = encodeAdmittedLimits(value)
  clear(canonical)
  return value
}

function digest(domain, value, encode, decode, size) {
  let encoded = null
  let result = null
  try {
    encoded = fixed(value, size) ? copy(value) : encode(value)
    decode(encoded)
    result = cryptoSuite.hash([domain, encoded])
    if (!fixed(result, 32)) invalid()
    return copy(result)
  } finally {
    clear(encoded)
    clear(result)
  }
}

function digestAdmittedLimits(value) {
  return digest(
    LIMITS_DOMAIN,
    value,
    encodeAdmittedLimits,
    decodeAdmittedLimits,
    ADMITTED_LIMITS_SIZE
  )
}

function encodePayloadParameters(value) {
  const names = [
    'cellSize',
    'maxCellPayload',
    'contextEnvelopeSize',
    'routeFrameSize',
    'maxRoutePayload',
    'datagramReplayWindow',
    'maxQueuedBytes',
    'idleTimeoutMs'
  ]
  ownRecord(value, names)
  const fields = names.map((name) => own(value, name))
  const exact = [1200, 1146, 1101, 1100, 1073, 64]
  for (let index = 0; index < exact.length; index++) {
    if (fields[index] !== exact[index]) invalid()
  }
  if (!u32(fields[6]) || fields[6] === 0 || !u32(fields[7]) || fields[7] === 0) invalid()
  const output = b4a.allocUnsafeSlow(PAYLOAD_PARAMETERS_SIZE)
  for (let index = 0; index < 6; index++) writeU16(output, fields[index], index * 2)
  writeU32(output, fields[6], 12)
  writeU32(output, fields[7], 16)
  return output
}

function decodePayloadParameters(encoded) {
  if (!fixed(encoded, PAYLOAD_PARAMETERS_SIZE)) invalid()
  const value = {
    cellSize: readU16(encoded, 0),
    maxCellPayload: readU16(encoded, 2),
    contextEnvelopeSize: readU16(encoded, 4),
    routeFrameSize: readU16(encoded, 6),
    maxRoutePayload: readU16(encoded, 8),
    datagramReplayWindow: readU16(encoded, 10),
    maxQueuedBytes: readU32(encoded, 12),
    idleTimeoutMs: readU32(encoded, 16)
  }
  const canonical = encodePayloadParameters(value)
  clear(canonical)
  return value
}

function digestPayloadParameters(value) {
  return digest(
    PARAMETERS_DOMAIN,
    value,
    encodePayloadParameters,
    decodePayloadParameters,
    PAYLOAD_PARAMETERS_SIZE
  )
}

module.exports = {
  ADMITTED_LIMITS_SIZE,
  PAYLOAD_PARAMETERS_SIZE,
  encodeAdmittedLimits,
  decodeAdmittedLimits,
  digestAdmittedLimits,
  encodePayloadParameters,
  decodePayloadParameters,
  digestPayloadParameters
}
