'use strict'

const b4a = require('b4a')
const sodium = require('sodium-universal')

const { PrivateRouteError } = require('./errors')

const PEER_PROTOCOL_VERSION = 2
const PEER_TAIL_CONTROL_CONTEXT_CLASS = 1
const PEER_TAIL_FINALIZE_CONTEXT_CLASS = 5
const PEER_ROUTE_CONTEXT_CLASS = 6
const CELL_CLASS_STREAM = 1
const CELL_CLASS_DATAGRAM = 2
const PEER_TAIL_CONTROL_AD_SIZE = 54
const PEER_TAIL_FINALIZE_AD_SIZE = 38
const PEER_ROUTE_AD_SIZE = 55
const MAX_UINT64 = 0xffff_ffff_ffff_ffffn
const MAX_COUNTER = MAX_UINT64 - 1n
const MAX_LOGICAL_COUNTER = (1n << 63n) - 1n
const MAX_PAYLOAD_SIZE = 1073
const PLAINTEXT_SIZE = 1076
const FRAME_SIZE = 1100
const ENVELOPE_SIZE = 1101
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype)
const bufferByteLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get
const bufferSet = Uint8Array.prototype.set
const bufferSubarray = Uint8Array.prototype.subarray
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectHasOwnProperty = Object.prototype.hasOwnProperty
const arrayIsArray = Array.isArray

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

function bufferLength(value) {
  try {
    if (!b4a.isBuffer(value)) return -1
    if (objectGetOwnPropertyDescriptor(value, 'byteLength') !== undefined) return -1
    return bufferByteLength.call(value)
  } catch {
    return -1
  }
}

function fixed(value, size) {
  return bufferLength(value) === size
}

function uint64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= MAX_UINT64
}

function validCounter(value) {
  return typeof value === 'bigint' && value >= 0n && value <= MAX_COUNTER
}

function direction(value) {
  return value === 0 || value === 1
}

function purpose(value) {
  return Number.isSafeInteger(value) && value >= 1 && value <= 3
}

function set(target, source, offset = 0) {
  try {
    bufferSet.call(target, source, offset)
  } catch {
    invalid()
  }
}

function slice(value, start, end) {
  try {
    return bufferSubarray.call(value, start, end)
  } catch {
    invalid()
  }
}

function copyBuffer(value) {
  const length = bufferLength(value)
  if (length < 0) invalid()
  const output = b4a.allocUnsafeSlow(length)
  set(output, value)
  return output
}

function clearBuffer(value) {
  try {
    if (b4a.isBuffer(value)) value.fill(0)
  } catch {}
}

function writeUint16(buffer, value, offset) {
  buffer[offset] = value >>> 8
  buffer[offset + 1] = value
}

function readUint16(buffer, offset) {
  return (buffer[offset] << 8) | buffer[offset + 1]
}

function writeUint32(buffer, value, offset) {
  buffer[offset] = value >>> 24
  buffer[offset + 1] = value >>> 16
  buffer[offset + 2] = value >>> 8
  buffer[offset + 3] = value
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

function encodePeerTailControlAD(value) {
  if (!safeObject(value)) invalid()
  const branchId = ownData(value, 'branchId')
  const circuitId = ownData(value, 'circuitId')
  const generation = ownData(value, 'generation')
  const selectedDirection = ownData(value, 'direction')
  const wireCounter = ownData(value, 'counter')

  if (
    !fixed(branchId, 16) ||
    !fixed(circuitId, 16) ||
    !uint64(generation) ||
    generation === 0n ||
    !direction(selectedDirection) ||
    !uint64(wireCounter)
  ) {
    invalid()
  }

  let output = null
  let transferred = false
  try {
    output = b4a.allocUnsafeSlow(PEER_TAIL_CONTROL_AD_SIZE)
    if (bufferLength(output) !== PEER_TAIL_CONTROL_AD_SIZE) invalid()
    output[0] = PEER_TAIL_CONTROL_CONTEXT_CLASS
    writeUint32(output, PEER_PROTOCOL_VERSION, 1)
    set(output, branchId, 5)
    set(output, circuitId, 21)
    writeUint64(output, generation, 37)
    output[45] = selectedDirection
    writeUint64(output, wireCounter, 46)
    transferred = true
    return output
  } finally {
    if (!transferred) {
      clearBuffer(output)
    }
  }
}

function encodePeerTailFinalizeAD(value) {
  if (!safeObject(value)) invalid()
  const circuitId = ownData(value, 'circuitId')
  const generation = ownData(value, 'generation')
  const selectedDirection = ownData(value, 'direction')
  const counter = ownData(value, 'counter')

  if (
    !fixed(circuitId, 16) ||
    !uint64(generation) ||
    generation === 0n ||
    !direction(selectedDirection) ||
    !uint64(counter)
  ) {
    invalid()
  }

  let output = null
  let transferred = false
  try {
    output = b4a.allocUnsafeSlow(PEER_TAIL_FINALIZE_AD_SIZE)
    if (bufferLength(output) !== PEER_TAIL_FINALIZE_AD_SIZE) invalid()
    output[0] = PEER_TAIL_FINALIZE_CONTEXT_CLASS
    writeUint32(output, PEER_PROTOCOL_VERSION, 1)
    set(output, circuitId, 5)
    writeUint64(output, generation, 21)
    output[29] = selectedDirection
    writeUint64(output, counter, 30)
    transferred = true
    return output
  } finally {
    if (!transferred) {
      clearBuffer(output)
    }
  }
}

function encodePeerRouteAD(value) {
  if (!safeObject(value)) invalid()
  const routeId = ownData(value, 'routeId')
  const circuitId = ownData(value, 'circuitId')
  const generation = ownData(value, 'generation')
  const selectedPurpose = ownData(value, 'purpose')
  const selectedDirection = ownData(value, 'direction')
  const counter = ownData(value, 'counter')

  if (
    !fixed(routeId, 16) ||
    !fixed(circuitId, 16) ||
    !uint64(generation) ||
    generation === 0n ||
    !purpose(selectedPurpose) ||
    !direction(selectedDirection) ||
    !uint64(counter)
  ) {
    invalid()
  }

  let output = null
  let transferred = false
  try {
    output = b4a.allocUnsafeSlow(PEER_ROUTE_AD_SIZE)
    if (bufferLength(output) !== PEER_ROUTE_AD_SIZE) invalid()
    output[0] = PEER_ROUTE_CONTEXT_CLASS
    writeUint32(output, PEER_PROTOCOL_VERSION, 1)
    set(output, routeId, 5)
    set(output, circuitId, 21)
    writeUint64(output, generation, 37)
    output[45] = selectedPurpose
    output[46] = selectedDirection
    writeUint64(output, counter, 47)
    transferred = true
    return output
  } finally {
    if (!transferred) {
      clearBuffer(output)
    }
  }
}

function makeNonce(noncePrefix, counter) {
  const nonce = b4a.allocUnsafeSlow(24)
  set(nonce, noncePrefix, 0)
  writeUint64(nonce, counter, 16)
  return nonce
}

function sealPeerContextFrame(options) {
  if (!safeObject(options)) invalid()

  const contextClass = ownData(options, 'contextClass')
  const circuitId = ownData(options, 'circuitId')
  const generation = ownData(options, 'generation')
  const selectedDirection = ownData(options, 'direction')
  const counter = ownData(options, 'counter')
  const key = ownData(options, 'key')
  const noncePrefix = ownData(options, 'noncePrefix')
  const payload = ownData(options, 'payload')

  if (
    (contextClass !== PEER_TAIL_CONTROL_CONTEXT_CLASS &&
      contextClass !== PEER_TAIL_FINALIZE_CONTEXT_CLASS &&
      contextClass !== PEER_ROUTE_CONTEXT_CLASS) ||
    !fixed(circuitId, 16) ||
    !uint64(generation) ||
    generation === 0n ||
    !direction(selectedDirection) ||
    !fixed(key, 32) ||
    !fixed(noncePrefix, 16) ||
    bufferLength(payload) < 0 ||
    bufferLength(payload) > MAX_PAYLOAD_SIZE
  ) {
    invalid()
  }

  let wireCounter = 0n
  let ad = null
  let marker = CELL_CLASS_DATAGRAM

  if (contextClass === PEER_TAIL_CONTROL_CONTEXT_CLASS) {
    const branchId = ownData(options, 'branchId')
    if (!fixed(branchId, 16)) invalid()
    if (typeof counter !== 'bigint' || counter < 0n || counter > MAX_LOGICAL_COUNTER) invalid()
    wireCounter = counter << 1n
    ad = encodePeerTailControlAD({
      branchId,
      circuitId,
      generation,
      direction: selectedDirection,
      counter: wireCounter
    })
    marker = CELL_CLASS_STREAM
  } else if (contextClass === PEER_TAIL_FINALIZE_CONTEXT_CLASS) {
    if (!validCounter(counter)) invalid()
    wireCounter = counter
    ad = encodePeerTailFinalizeAD({
      circuitId,
      generation,
      direction: selectedDirection,
      counter: wireCounter
    })
  } else {
    if (!validCounter(counter)) invalid()
    wireCounter = counter
    const routeId = ownData(options, 'routeId')
    const selectedPurpose = ownData(options, 'purpose')
    ad = encodePeerRouteAD({
      routeId,
      circuitId,
      generation,
      purpose: selectedPurpose,
      direction: selectedDirection,
      counter: wireCounter
    })
  }

  let plaintext = null
  let nonce = null
  let frame = null
  let success = false

  try {
    plaintext = b4a.allocUnsafeSlow(PLAINTEXT_SIZE)
    plaintext[0] = marker
    writeUint16(plaintext, payload.byteLength, 1)
    set(plaintext, payload, 3)

    const paddingLen = MAX_PAYLOAD_SIZE - payload.byteLength
    if (paddingLen > 0) {
      sodium.randombytes_buf(slice(plaintext, 3 + payload.byteLength, PLAINTEXT_SIZE))
    }

    nonce = makeNonce(noncePrefix, wireCounter)
    frame = b4a.allocUnsafeSlow(FRAME_SIZE)
    writeUint64(frame, wireCounter, 0)

    sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      slice(frame, 8, FRAME_SIZE),
      plaintext,
      ad,
      null,
      nonce,
      key
    )

    success = true
    return frame
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  } finally {
    clearBuffer(plaintext)
    clearBuffer(nonce)
    clearBuffer(ad)
    if (!success) clearBuffer(frame)
  }
}

function openPeerContextFrame(options, frame1100) {
  if (!safeObject(options) || !fixed(frame1100, FRAME_SIZE)) invalid()

  const contextClass = ownData(options, 'contextClass')
  const circuitId = ownData(options, 'circuitId')
  const generation = ownData(options, 'generation')
  const selectedDirection = ownData(options, 'direction')
  const key = ownData(options, 'key')
  const noncePrefix = ownData(options, 'noncePrefix')

  if (
    (contextClass !== PEER_TAIL_CONTROL_CONTEXT_CLASS &&
      contextClass !== PEER_TAIL_FINALIZE_CONTEXT_CLASS &&
      contextClass !== PEER_ROUTE_CONTEXT_CLASS) ||
    !fixed(circuitId, 16) ||
    !uint64(generation) ||
    generation === 0n ||
    !direction(selectedDirection) ||
    !fixed(key, 32) ||
    !fixed(noncePrefix, 16)
  ) {
    invalid()
  }

  const wireCounter = readUint64(frame1100, 0)
  if (!uint64(wireCounter)) invalid()

  if (contextClass !== PEER_TAIL_CONTROL_CONTEXT_CLASS) {
    if (!validCounter(wireCounter)) invalid()
    const optCounter = ownData(options, 'counter')
    if (!validCounter(optCounter) || optCounter !== wireCounter) invalid()
  }

  let ad = null
  let expectedMarker = CELL_CLASS_DATAGRAM
  const isOrdered = contextClass === PEER_TAIL_CONTROL_CONTEXT_CLASS

  if (isOrdered) {
    const branchId = ownData(options, 'branchId')
    if (!fixed(branchId, 16)) invalid()
    ad = encodePeerTailControlAD({
      branchId,
      circuitId,
      generation,
      direction: selectedDirection,
      counter: wireCounter
    })
    expectedMarker = CELL_CLASS_STREAM
  } else if (contextClass === PEER_TAIL_FINALIZE_CONTEXT_CLASS) {
    ad = encodePeerTailFinalizeAD({
      circuitId,
      generation,
      direction: selectedDirection,
      counter: wireCounter
    })
  } else {
    const routeId = ownData(options, 'routeId')
    const selectedPurpose = ownData(options, 'purpose')
    ad = encodePeerRouteAD({
      routeId,
      circuitId,
      generation,
      purpose: selectedPurpose,
      direction: selectedDirection,
      counter: wireCounter
    })
  }

  const ciphertext = slice(frame1100, 8, FRAME_SIZE)
  let nonce = null
  let plaintext = null
  let success = false

  try {
    nonce = makeNonce(noncePrefix, wireCounter)
    plaintext = b4a.allocUnsafeSlow(PLAINTEXT_SIZE)

    try {
      const authenticated = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext,
        null,
        ciphertext,
        ad,
        nonce,
        key
      )
      if (authenticated === false) invalid()
    } catch {
      invalid()
    }

    if (isOrdered) {
      if ((wireCounter & 1n) !== 0n) invalid()
      const logicalCounter = wireCounter >> 1n
      if (logicalCounter > MAX_LOGICAL_COUNTER) invalid()
      const optCounter = ownData(options, 'counter')
      if (typeof optCounter !== 'bigint' || optCounter !== logicalCounter) invalid()
    }

    if (plaintext[0] !== expectedMarker) invalid()
    const payloadLength = readUint16(plaintext, 1)
    if (payloadLength > MAX_PAYLOAD_SIZE) invalid()

    const payload = slice(plaintext, 3, 3 + payloadLength)
    const result = Object.freeze({
      counter: wireCounter,
      ...(isOrdered ? { logicalCounter: wireCounter >> 1n } : {}),
      payload,
      plaintext
    })
    success = true
    return result
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  } finally {
    clearBuffer(nonce)
    clearBuffer(ad)
    if (!success) clearBuffer(plaintext)
  }
}
function encodePeerContextEnvelope(contextClass, frame1100) {
  if (
    (contextClass !== PEER_TAIL_CONTROL_CONTEXT_CLASS &&
      contextClass !== PEER_TAIL_FINALIZE_CONTEXT_CLASS &&
      contextClass !== PEER_ROUTE_CONTEXT_CLASS) ||
    !fixed(frame1100, FRAME_SIZE)
  ) {
    invalid()
  }

  const envelope = b4a.allocUnsafeSlow(ENVELOPE_SIZE)
  envelope[0] = contextClass
  set(envelope, frame1100, 1)
  return envelope
}

function decodePeerContextEnvelope(envelope1101) {
  if (!fixed(envelope1101, ENVELOPE_SIZE)) invalid()

  const contextClass = envelope1101[0]
  if (
    contextClass !== PEER_TAIL_CONTROL_CONTEXT_CLASS &&
    contextClass !== PEER_TAIL_FINALIZE_CONTEXT_CLASS &&
    contextClass !== PEER_ROUTE_CONTEXT_CLASS
  ) {
    invalid()
  }

  const frame = copyBuffer(slice(envelope1101, 1, ENVELOPE_SIZE))
  return Object.freeze({
    contextClass,
    frame
  })
}

module.exports = Object.freeze({
  encodePeerTailControlAD,
  encodePeerTailFinalizeAD,
  encodePeerRouteAD,
  sealPeerContextFrame,
  openPeerContextFrame,
  encodePeerContextEnvelope,
  decodePeerContextEnvelope
})
