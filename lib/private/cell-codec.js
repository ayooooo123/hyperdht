'use strict'

const b4a = require('b4a')

const { PrivateRouteError } = require('./errors')
const { CELL_CLASS, DIRECTION, DOMAIN, PROTOCOL_VERSION } = require('./protocol')

// Ported from the reviewed private-routes prototype at commit
// 0305df915b6a767093f9e75e6c06bc0a35da6169.

const CELL_SIZE = 1200
const CELL_HEADER_SIZE = 36
const CELL_BODY_SIZE = 1148
const MAX_CELL_PAYLOAD = 1146
const AEAD_TAG_BYTES = 16
const TEST_ONLY_CELL_ALLOCATOR = Symbol('test-only-cell-allocator')

const MAX_UINT64 = (1n << 64n) - 1n
const CELL_HEADER_DOMAIN = DOMAIN.CELL_HEADER
const RECEIVER_FAILURES = new Set(['REPLAY', 'COUNTER_INVALID', 'COUNTER_GAP', 'COUNTER_EXHAUSTED'])
const bufferByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
const bufferArrayBuffer = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'buffer'
).get
const bufferByteOffset = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteOffset'
).get
const bufferFill = Uint8Array.prototype.fill
const bufferSet = Uint8Array.prototype.set
const bufferSubarray = Uint8Array.prototype.subarray
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectGetPrototypeOf = Object.getPrototypeOf
const objectHasOwnProperty = Object.prototype.hasOwnProperty
const reflectApply = Reflect.apply

function invalid() {
  throw PrivateRouteError.CELL_INVALID()
}

function optionsObject(options) {
  try {
    if (options === null || typeof options !== 'object' || Array.isArray(options)) invalid()
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
  return options
}

function option(options, name, required = true) {
  let descriptor
  try {
    descriptor = objectGetOwnPropertyDescriptor(options, name)
  } catch {
    invalid()
  }
  if (descriptor === undefined) {
    let inherited = false
    try {
      inherited = name in options
    } catch {
      invalid()
    }
    if (required || inherited) invalid()
    return undefined
  }
  if (!objectHasOwnProperty.call(descriptor, 'value')) invalid()
  return descriptor.value
}

function dataMethod(target, name) {
  if (target === null || (typeof target !== 'object' && typeof target !== 'function')) invalid()
  let current = target
  for (let depth = 0; depth < 8 && current !== null; depth++) {
    let descriptor
    try {
      descriptor = objectGetOwnPropertyDescriptor(current, name)
    } catch {
      invalid()
    }
    if (descriptor !== undefined) {
      if (
        !objectHasOwnProperty.call(descriptor, 'value') ||
        typeof descriptor.value !== 'function'
      ) {
        invalid()
      }
      const method = descriptor.value
      return (...args) => reflectApply(method, target, args)
    }
    try {
      current = objectGetPrototypeOf(current)
    } catch {
      invalid()
    }
  }
  invalid()
}

function bufferLength(value) {
  try {
    return b4a.isBuffer(value) ? bufferByteLength.call(value) : -1
  } catch {
    return -1
  }
}

function isBuffer(value, size) {
  return bufferLength(value) === size
}

function clear(value) {
  try {
    if (bufferLength(value) >= 0) bufferFill.call(value, 0)
  } catch {
    // Best-effort zeroization only.
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

function equal(left, right) {
  const leftLength = bufferLength(left)
  if (leftLength < 0 || leftLength !== bufferLength(right)) return false
  let difference = 0
  for (let i = 0; i < leftLength; i++) difference |= left[i] ^ right[i]
  return difference === 0
}

function overlaps(left, right) {
  const leftLength = bufferLength(left)
  const rightLength = bufferLength(right)
  if (leftLength <= 0 || rightLength <= 0) return false
  try {
    if (bufferArrayBuffer.call(left) !== bufferArrayBuffer.call(right)) return false
    const leftStart = bufferByteOffset.call(left)
    const rightStart = bufferByteOffset.call(right)
    return leftStart < rightStart + rightLength && rightStart < leftStart + leftLength
  } catch {
    return true
  }
}

function overlapsAny(value, protectedValues) {
  for (const protectedValue of protectedValues) {
    if (overlaps(value, protectedValue)) return true
  }
  return false
}

function copy(value) {
  const length = bufferLength(value)
  if (length < 0) invalid()
  let owned = null
  try {
    owned = b4a.allocUnsafeSlow(length)
    if (!isBuffer(owned, length)) invalid()
    set(owned, value)
    return owned
  } catch (err) {
    clear(owned)
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function uint64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= MAX_UINT64
}

function knownClass(value) {
  return (
    value === CELL_CLASS.CONTROL || value === CELL_CLASS.STREAM || value === CELL_CLASS.DATAGRAM
  )
}

function knownDirection(value) {
  return value === DIRECTION.FORWARD || value === DIRECTION.REVERSE
}

function writeUint16BE(buffer, value, offset) {
  buffer[offset] = value >>> 8
  buffer[offset + 1] = value
}

function writeUint64BE(buffer, value, offset) {
  for (let i = offset + 7; i >= offset; i--) {
    buffer[i] = Number(value & 0xffn)
    value >>= 8n
  }
}

function readUint64BE(buffer, offset) {
  let value = 0n
  for (let i = offset; i < offset + 8; i++) value = (value << 8n) | BigInt(buffer[i])
  return value
}

function defaultAllocate(size) {
  return b4a.allocUnsafeSlow(size)
}

function defaultRelease() {}

function allocateScratch(scratch, size) {
  let value = null
  try {
    value = scratch.allocate(size)
  } catch {
    invalid()
  }
  if (isBuffer(value, size)) return value
  clear(value)
  try {
    scratch.release(value)
  } catch {
    invalid()
  }
  invalid()
}

function releaseScratch(scratch, values) {
  let failed = false
  for (const value of values) {
    if (value === null) continue
    clear(value)
    try {
      scratch.release(value)
    } catch {
      failed = true
    }
  }
  if (failed) invalid()
}

function associatedData(header, scratch) {
  let data = null
  let transferred = false
  try {
    data = allocateScratch(scratch, bufferLength(CELL_HEADER_DOMAIN) + CELL_HEADER_SIZE)
    set(data, CELL_HEADER_DOMAIN)
    set(data, header, bufferLength(CELL_HEADER_DOMAIN))
    transferred = true
    return data
  } finally {
    if (!transferred && data !== null) releaseScratch(scratch, [data])
  }
}

function receiverFailureCode(err) {
  try {
    if (!(err instanceof PrivateRouteError)) return null
    const descriptor = objectGetOwnPropertyDescriptor(err, 'code')
    if (!descriptor || !objectHasOwnProperty.call(descriptor, 'value')) return null
    return RECEIVER_FAILURES.has(descriptor.value) ? descriptor.value : null
  } catch {
    return null
  }
}

function invokeReceiver(operation) {
  try {
    return operation()
  } catch (err) {
    const code = receiverFailureCode(err)
    if (code !== null) throw new PrivateRouteError(code)
    invalid()
  }
}

function retainsPayload(delivery, payload) {
  if (delivery === payload) return true
  if (!Array.isArray(delivery)) return false
  for (const value of delivery) if (value === payload) return true
  return false
}

class CellCodec {
  #seal
  #open
  #padding
  #scratch

  constructor(options) {
    options = optionsObject(options)
    const crypto = option(options, 'crypto')
    const cellSize = option(options, 'cellSize')
    const configuredPadding = option(options, 'padding', false)
    const configuredScratch = option(options, TEST_ONLY_CELL_ALLOCATOR, false)

    if (cellSize !== CELL_SIZE) invalid()
    this.#seal = dataMethod(crypto, 'seal')
    this.#open = dataMethod(crypto, 'open')
    this.#padding =
      configuredPadding === undefined
        ? dataMethod(crypto, 'randomBytes')
        : typeof configuredPadding === 'function'
          ? configuredPadding
          : invalid()
    this.#scratch = Object.freeze({
      allocate:
        configuredScratch === undefined
          ? defaultAllocate
          : dataMethod(configuredScratch, 'allocate'),
      release:
        configuredScratch === undefined ? defaultRelease : dataMethod(configuredScratch, 'release')
    })
  }

  seal(options) {
    options = optionsObject(options)
    const key = option(options, 'key')
    const noncePrefix = option(options, 'noncePrefix')
    const senderCounter = option(options, 'senderCounter')
    const cellClass = option(options, 'class')
    const direction = option(options, 'direction')
    const epoch = option(options, 'epoch')
    const circuitId = option(options, 'circuitId')
    const payload = option(options, 'payload')
    const payloadLength = bufferLength(payload)
    const next = dataMethod(senderCounter, 'next')

    if (
      !isBuffer(key, 32) ||
      !isBuffer(noncePrefix, 16) ||
      !knownClass(cellClass) ||
      !knownDirection(direction) ||
      !uint64(epoch) ||
      !isBuffer(circuitId, 16) ||
      payloadLength < 0 ||
      payloadLength > MAX_CELL_PAYLOAD
    ) {
      invalid()
    }

    let header = null
    let body = null
    let data = null
    let padding = null
    let ciphertext = null
    let packet = null
    let ownedKey = null
    let ownedNoncePrefix = null
    let transferred = false
    try {
      header = allocateScratch(this.#scratch, CELL_HEADER_SIZE)
      body = allocateScratch(this.#scratch, CELL_BODY_SIZE)
      writeUint16BE(body, payloadLength, 0)
      set(body, payload, 2)

      const paddingSize = MAX_CELL_PAYLOAD - payloadLength
      if (paddingSize > 0) {
        try {
          padding = this.#padding(paddingSize)
        } catch {
          invalid()
        }
        if (!isBuffer(padding, paddingSize)) invalid()
        set(body, padding, 2 + payloadLength)
      }

      ownedKey = copy(key)
      ownedNoncePrefix = copy(noncePrefix)

      let counter
      try {
        counter = next()
      } catch (err) {
        const code = receiverFailureCode(err)
        if (code !== null) throw new PrivateRouteError(code)
        invalid()
      }
      if (!uint64(counter)) invalid()

      header[0] = PROTOCOL_VERSION
      header[1] = cellClass
      header[2] = direction
      header[3] = 0
      writeUint64BE(header, epoch, 4)
      set(header, circuitId, 12)
      writeUint64BE(header, counter, 28)
      data = associatedData(header, this.#scratch)
      ciphertext = this.#seal({
        key: ownedKey,
        noncePrefix: ownedNoncePrefix,
        counter,
        associatedData: data,
        plaintext: body
      })
      if (!isBuffer(ciphertext, CELL_BODY_SIZE + AEAD_TAG_BYTES)) invalid()

      packet = b4a.allocUnsafeSlow(CELL_SIZE)
      if (!isBuffer(packet, CELL_SIZE)) invalid()
      set(packet, header)
      set(packet, ciphertext, CELL_HEADER_SIZE)
      transferred = true
      return packet
    } finally {
      if (!transferred) clear(packet)
      let cleanupError = null
      try {
        releaseScratch(this.#scratch, [data, body, header])
      } catch (err) {
        clear(packet)
        cleanupError = err
      }
      clear(ownedKey)
      clear(ownedNoncePrefix)
      if (cleanupError !== null) throw cleanupError
      // Padding and ciphertext are adapter-owned public outputs and may alias caller storage.
    }
  }

  open(options, packet) {
    if (!isBuffer(packet, CELL_SIZE)) invalid()
    const header = subarray(packet, 0, CELL_HEADER_SIZE)
    const version = header[0]
    const cellClass = header[1]
    const direction = header[2]
    const flags = header[3]
    if (
      version !== PROTOCOL_VERSION ||
      !knownClass(cellClass) ||
      !knownDirection(direction) ||
      flags !== 0
    ) {
      invalid()
    }

    const epoch = readUint64BE(header, 4)
    const circuitId = subarray(header, 12, 28)
    const counter = readUint64BE(header, 28)
    options = optionsObject(options)
    const key = option(options, 'key')
    const noncePrefix = option(options, 'noncePrefix')
    const expectedClass = option(options, 'expectedClass')
    const expectedDirection = option(options, 'expectedDirection')
    const expectedEpoch = option(options, 'expectedEpoch')
    const expectedCircuitId = option(options, 'expectedCircuitId')
    if (
      !isBuffer(key, 32) ||
      !isBuffer(noncePrefix, 16) ||
      !knownClass(expectedClass) ||
      !knownDirection(expectedDirection) ||
      !uint64(expectedEpoch) ||
      !isBuffer(expectedCircuitId, 16) ||
      cellClass !== expectedClass ||
      direction !== expectedDirection ||
      epoch !== expectedEpoch ||
      !equal(circuitId, expectedCircuitId)
    ) {
      invalid()
    }

    let data = null
    let plaintext = null
    let payload = null
    let ownedKey = null
    let ownedNoncePrefix = null
    let transferred = false
    try {
      ownedKey = copy(key)
      ownedNoncePrefix = copy(noncePrefix)
      data = associatedData(header, this.#scratch)
      const candidate = this.#open({
        key: ownedKey,
        noncePrefix: ownedNoncePrefix,
        counter,
        associatedData: data,
        ciphertext: subarray(packet, CELL_HEADER_SIZE)
      })
      if (candidate === null || bufferLength(candidate) < 0) invalid()
      if (
        overlapsAny(candidate, [
          packet,
          key,
          noncePrefix,
          expectedCircuitId,
          ownedKey,
          ownedNoncePrefix,
          data
        ])
      ) {
        invalid()
      }
      plaintext = candidate
      if (!isBuffer(plaintext, CELL_BODY_SIZE)) invalid()
      releaseScratch(this.#scratch, [data])
      data = null
      const payloadLength = (plaintext[0] << 8) | plaintext[1]
      if (payloadLength > MAX_CELL_PAYLOAD) invalid()
      payload = copy(subarray(plaintext, 2, 2 + payloadLength))
      const receiver = option(options, 'receiver')

      if (cellClass === CELL_CLASS.DATAGRAM) {
        const accept = dataMethod(receiver, 'acceptAuthenticated')
        if (invokeReceiver(() => accept(counter)) !== true) invalid()
        transferred = true
        return payload
      }

      const push = dataMethod(receiver, 'pushAuthenticated')
      const delivery = invokeReceiver(() => push(counter, payload))
      transferred = retainsPayload(delivery, payload)
      return delivery
    } finally {
      clear(plaintext)
      if (!transferred) clear(payload)
      let cleanupError = null
      try {
        releaseScratch(this.#scratch, [data])
      } catch (err) {
        cleanupError = err
      }
      clear(ownedKey)
      clear(ownedNoncePrefix)
      if (cleanupError !== null) throw cleanupError
    }
  }
}

module.exports = {
  AEAD_TAG_BYTES,
  CELL_BODY_SIZE,
  CELL_HEADER_SIZE,
  CELL_SIZE,
  CellCodec,
  MAX_CELL_PAYLOAD,
  TEST_ONLY_CELL_ALLOCATOR
}
