'use strict'

const b4a = require('b4a')

const { PrivateRouteError } = require('./errors')
const { DIRECTION, M3_PROTOCOL_VERSION } = require('./protocol')

// Ported from the reviewed private-routes prototype at commit
// 0305df915b6a767093f9e75e6c06bc0a35da6169 and narrowed to Gate 3B1.

const M3_CONTEXT_AD_SIZE = 54
const M3_CONTEXT_ENVELOPE_SIZE = 1101
const M3_CONTEXT_FRAME_SIZE = 1100
const MAX_UINT64 = 0xffff_ffff_ffff_ffffn
const bufferByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
const bufferSet = Uint8Array.prototype.set
const bufferSubarray = Uint8Array.prototype.subarray

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function object(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid()
  return value
}

function option(value, name) {
  try {
    return value[name]
  } catch {
    invalid()
  }
}

function fixed(value, size) {
  try {
    return b4a.isBuffer(value) && bufferByteLength.call(value) === size
  } catch {
    return false
  }
}

function set(target, source, offset = 0) {
  try {
    bufferSet.call(target, source, offset)
  } catch {
    invalid()
  }
}

function subarray(value, start, end) {
  try {
    return bufferSubarray.call(value, start, end)
  } catch {
    invalid()
  }
}

function clear(value) {
  try {
    if (value) b4a.fill(value, 0)
  } catch {}
}

function copy(value) {
  let output = null
  try {
    const length = bufferByteLength.call(value)
    output = b4a.allocUnsafeSlow(length)
    set(output, value)
    const result = output
    output = null
    return result
  } catch {
    invalid()
  } finally {
    clear(output)
  }
}

function uint64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= MAX_UINT64
}

function contextClass(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 4) invalid()
  return value
}

function direction(value) {
  if (value !== DIRECTION.FORWARD && value !== DIRECTION.REVERSE) invalid()
  return value
}

function writeUint32(buffer, value, offset) {
  buffer[offset] = value >>> 24
  buffer[offset + 1] = value >>> 16
  buffer[offset + 2] = value >>> 8
  buffer[offset + 3] = value
}

function readUint32(buffer, offset) {
  return (
    buffer[offset] * 0x1000000 +
    (buffer[offset + 1] << 16) +
    (buffer[offset + 2] << 8) +
    buffer[offset + 3]
  )
}

function writeUint64(buffer, value, offset) {
  for (let index = offset + 7; index >= offset; index--) {
    buffer[index] = Number(value & 0xffn)
    value >>= 8n
  }
}

function readUint64(buffer, offset) {
  let value = 0n
  for (let index = offset; index < offset + 8; index++) {
    value = (value << 8n) | BigInt(buffer[index])
  }
  return value
}

function encodeM3ContextAD(value) {
  let output = null
  try {
    object(value)
    const selectedClass = contextClass(option(value, 'contextClass'))
    const branchId = option(value, 'branchId')
    const circuitId = option(value, 'circuitId')
    const generation = option(value, 'generation')
    const selectedDirection = direction(option(value, 'direction'))
    const innerCounter = option(value, 'innerCounter')

    if (!fixed(branchId, 16) || !fixed(circuitId, 16)) invalid()
    if (!uint64(generation) || !uint64(innerCounter)) invalid()

    output = b4a.allocUnsafeSlow(M3_CONTEXT_AD_SIZE)
    output[0] = selectedClass
    writeUint32(output, M3_PROTOCOL_VERSION, 1)
    set(output, branchId, 5)
    set(output, circuitId, 21)
    writeUint64(output, generation, 37)
    output[45] = selectedDirection
    writeUint64(output, innerCounter, 46)
    const result = output
    output = null
    return result
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  } finally {
    clear(output)
  }
}

function decodeM3ContextAD(encoded) {
  let branchId = null
  let circuitId = null
  try {
    if (!fixed(encoded, M3_CONTEXT_AD_SIZE)) invalid()
    const selectedClass = contextClass(encoded[0])
    if (readUint32(encoded, 1) !== M3_PROTOCOL_VERSION) invalid()
    const selectedDirection = direction(encoded[45])
    branchId = copy(subarray(encoded, 5, 21))
    circuitId = copy(subarray(encoded, 21, 37))
    const result = {
      contextClass: selectedClass,
      branchId,
      circuitId,
      generation: readUint64(encoded, 37),
      direction: selectedDirection,
      innerCounter: readUint64(encoded, 46)
    }
    branchId = null
    circuitId = null
    return result
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  } finally {
    clear(branchId)
    clear(circuitId)
  }
}

function encodeM3ContextEnvelope(value) {
  let output = null
  try {
    object(value)
    const selectedClass = contextClass(option(value, 'contextClass'))
    const frame = option(value, 'frame')
    if (!fixed(frame, M3_CONTEXT_FRAME_SIZE)) invalid()
    output = b4a.allocUnsafeSlow(M3_CONTEXT_ENVELOPE_SIZE)
    output[0] = selectedClass
    set(output, frame, 1)
    const result = output
    output = null
    return result
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  } finally {
    clear(output)
  }
}

function decodeM3ContextEnvelope(encoded) {
  let frame = null
  try {
    if (!fixed(encoded, M3_CONTEXT_ENVELOPE_SIZE)) invalid()
    frame = copy(subarray(encoded, 1, M3_CONTEXT_ENVELOPE_SIZE))
    const result = { contextClass: contextClass(encoded[0]), frame }
    frame = null
    return result
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  } finally {
    clear(frame)
  }
}

module.exports = {
  M3_CONTEXT_AD_SIZE,
  M3_CONTEXT_ENVELOPE_SIZE,
  encodeM3ContextAD,
  decodeM3ContextAD,
  encodeM3ContextEnvelope,
  decodeM3ContextEnvelope
}
