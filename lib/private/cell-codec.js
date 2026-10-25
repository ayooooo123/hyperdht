'use strict'

const b4a = require('b4a')

const { PrivateRouteError } = require('./errors')
const { cryptoSuite, cellAead } = require('./crypto-suite')
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
const arrayBufferByteLength = Object.getOwnPropertyDescriptor(
  ArrayBuffer.prototype,
  'byteLength'
).get

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

// Reusable contexts snapshot static inputs once. Only the exact production
// adapter is eligible: arbitrary allocating providers retain the old contract.
// Successful outputs belong to the caller, never to the context. Any failure
// destroys the context and wipes non-aliasing output; rejected aliases are not
// cleared because doing so would modify caller inputs or another active cell.
function reusableContext(options, scratch, sealing, configuredPadding) {
  options = optionsObject(options)
  const sourceKey = option(options, 'key')
  const sourcePrefix = option(options, 'noncePrefix')
  const cellClass = option(options, sealing ? 'class' : 'expectedClass')
  const direction = option(options, sealing ? 'direction' : 'expectedDirection')
  const epoch = option(options, sealing ? 'epoch' : 'expectedEpoch')
  const circuitId = option(options, sealing ? 'circuitId' : 'expectedCircuitId')
  const next = sealing ? dataMethod(option(options, 'senderCounter'), 'next') : null
  const paddingInto = sealing ? option(options, 'paddingInto', false) : undefined
  if (
    !ordinaryBuffer(sourceKey) ||
    !isBuffer(sourceKey, 32) ||
    !ordinaryBuffer(sourcePrefix) ||
    !isBuffer(sourcePrefix, 16) ||
    !knownClass(cellClass) ||
    !knownDirection(direction) ||
    !uint64(epoch) ||
    !ordinaryBuffer(circuitId) ||
    !isBuffer(circuitId, 16) ||
    (sealing && configuredPadding !== undefined && paddingInto === undefined) ||
    (paddingInto !== undefined && typeof paddingInto !== 'function')
  ) {
    invalid()
  }

  const sources = [sourceKey, sourcePrefix, circuitId, CELL_HEADER_DOMAIN]
  const allocations = []
  const buffers = []
  let destroyed = false
  let busy = false
  let authenticatedCounter = null
  let key, prefix, nonce, header, data, body, ciphertext, padding

  function allocate(size) {
    let value
    try {
      value = scratch.allocate(size)
    } catch {
      invalid()
    }
    // An allocator must transfer exclusive storage, including on failure.
    // Never clear or release a rejected alias owned by the caller.
    if (overlapsAny(value, sources) || overlapsAny(value, buffers)) invalid()
    allocations.push(value)
    if (!ordinaryBuffer(value) || !isBuffer(value, size)) invalid()
    // Canonical fixed views prevent allocator/padding hooks from shadowing the
    // native adapter's buffer metadata. Creating views here allocates no backing.
    const view = new Uint8Array(bufferArrayBuffer.call(value), bufferByteOffset.call(value), size)
    Object.preventExtensions(view)
    buffers.push(view)
    clear(view)
    return view
  }

  function destroy() {
    if (destroyed) return
    destroyed = true
    authenticatedCounter = null
    releaseScratch(scratch, allocations)
  }

  function clearTransient() {
    clear(nonce)
    clear(data)
    clear(body)
    clear(ciphertext)
    clear(padding)
  }

  function checkLive() {
    if (destroyed) invalid()
    // Hooks may detach storage. Never pass stale geometry to native crypto.
    if (
      !isBuffer(key, 32) ||
      !isBuffer(prefix, 16) ||
      !isBuffer(nonce, 24) ||
      !isBuffer(header, CELL_HEADER_SIZE) ||
      !isBuffer(data, bufferLength(CELL_HEADER_DOMAIN) + CELL_HEADER_SIZE) ||
      !isBuffer(body, CELL_BODY_SIZE) ||
      !isBuffer(ciphertext, CELL_BODY_SIZE + AEAD_TAG_BYTES) ||
      (sealing && !isBuffer(padding, MAX_CELL_PAYLOAD))
    ) {
      invalid()
    }
  }

  function safeOutput(output, input) {
    return (
      ordinaryBuffer(output) &&
      !overlaps(output, input) &&
      !overlapsAny(output, sources) &&
      !overlapsAny(output, buffers)
    )
  }

  try {
    key = allocate(32)
    prefix = allocate(16)
    nonce = allocate(24)
    header = allocate(CELL_HEADER_SIZE)
    data = allocate(bufferLength(CELL_HEADER_DOMAIN) + CELL_HEADER_SIZE)
    body = allocate(CELL_BODY_SIZE)
    ciphertext = allocate(CELL_BODY_SIZE + AEAD_TAG_BYTES)
    if (sealing) padding = allocate(MAX_CELL_PAYLOAD)
    set(key, sourceKey)
    set(prefix, sourcePrefix)
    header[0] = PROTOCOL_VERSION
    header[1] = cellClass
    header[2] = direction
    header[3] = 0
    writeUint64BE(header, epoch, 4)
    set(header, circuitId, 12)
  } catch (err) {
    destroy()
    throw err
  }

  function sealInto(packetOutput, payload, packetOffset = 0) {
    let wipe = false
    let complete = false
    const reentrant = busy
    busy = true
    try {
      wipe = safeOutput(packetOutput, payload)
      if (destroyed || reentrant) invalid()
      const payloadLength = bufferLength(payload)
      if (
        !wipe ||
        !Number.isSafeInteger(packetOffset) ||
        packetOffset < 0 ||
        bufferLength(packetOutput) - packetOffset < CELL_SIZE ||
        !ordinaryBuffer(payload) ||
        payloadLength > MAX_CELL_PAYLOAD ||
        overlapsAny(payload, buffers)
      ) {
        invalid()
      }
      checkLive()
      writeUint16BE(body, payloadLength, 0)
      set(body, payload, 2)
      const paddingSize = MAX_CELL_PAYLOAD - payloadLength
      if (paddingSize > 0) {
        try {
          if (paddingInto === undefined) cellAead.randomFill(padding)
          else paddingInto(padding)
        } catch {
          invalid()
        }
        checkLive()
        for (let i = 0; i < paddingSize; i++) body[2 + payloadLength + i] = padding[i]
      }
      let counter
      try {
        counter = next()
      } catch (err) {
        const code = receiverFailureCode(err)
        if (code !== null) throw new PrivateRouteError(code)
        invalid()
      }
      checkLive()
      if (!uint64(counter)) invalid()
      set(nonce, prefix)
      writeUint64BE(nonce, counter, 16)
      set(data, CELL_HEADER_DOMAIN)
      const headerOffset = bufferLength(CELL_HEADER_DOMAIN)
      set(data, header, headerOffset)
      writeUint64BE(data, counter, headerOffset + 28)
      cellAead.sealInto(ciphertext, body, data, nonce, key)
      checkLive()
      if (bufferLength(packetOutput) - packetOffset < CELL_SIZE) invalid()
      for (let i = 0; i < CELL_HEADER_SIZE; i++) {
        packetOutput[packetOffset + i] = data[headerOffset + i]
      }
      set(packetOutput, ciphertext, packetOffset + CELL_HEADER_SIZE)
      complete = true
      return CELL_SIZE
    } finally {
      if (!complete) {
        if (wipe) clearOutputRange(packetOutput, packetOffset, CELL_SIZE)
        destroy()
      } else {
        clearTransient()
      }
      busy = false
    }
  }

  // This authenticates geometry, not replay or ordering. The caller MUST pass
  // counter through its existing receiver before delivery. bodyOutput includes
  // the two-byte length prefix; copy payload [2, 2 + length) before queueing it
  // or handing it to any asynchronous consumer that can outlive caller reuse.
  function openInto(packet, bodyOutput) {
    let wipe = false
    let complete = false
    const reentrant = busy
    busy = true
    authenticatedCounter = null
    try {
      wipe = safeOutput(bodyOutput, packet)
      if (destroyed || reentrant) invalid()
      if (
        !wipe ||
        !isBuffer(bodyOutput, CELL_BODY_SIZE) ||
        !ordinaryBuffer(packet) ||
        !isBuffer(packet, CELL_SIZE) ||
        overlapsAny(packet, buffers)
      ) {
        invalid()
      }
      checkLive()
      for (let i = 0; i < 28; i++) {
        if (packet[i] !== header[i]) invalid()
      }
      const counter = readUint64BE(packet, 28)
      set(nonce, prefix)
      writeUint64BE(nonce, counter, 16)
      set(data, CELL_HEADER_DOMAIN)
      const headerOffset = bufferLength(CELL_HEADER_DOMAIN)
      for (let i = 0; i < CELL_HEADER_SIZE; i++) data[headerOffset + i] = packet[i]
      for (let i = 0; i < CELL_BODY_SIZE + AEAD_TAG_BYTES; i++) {
        ciphertext[i] = packet[CELL_HEADER_SIZE + i]
      }
      if (!cellAead.openInto(body, ciphertext, data, nonce, key)) invalid()
      checkLive()
      const payloadLength = (body[0] << 8) | body[1]
      if (payloadLength > MAX_CELL_PAYLOAD || !isBuffer(bodyOutput, CELL_BODY_SIZE)) invalid()
      set(bodyOutput, body)
      authenticatedCounter = counter
      complete = true
      return payloadLength
    } finally {
      if (!complete) {
        if (wipe) clear(bodyOutput)
        destroy()
      } else {
        clearTransient()
      }
      busy = false
    }
  }

  return sealing
    ? Object.freeze({ sealInto, destroy })
    : Object.freeze({
        openInto,
        get counter() {
          return authenticatedCounter
        },
        destroy
      })
}

function ordinaryBuffer(value) {
  if (bufferLength(value) < 0) return false
  try {
    // Shared backing permits concurrent mutation during authentication.
    arrayBufferByteLength.call(bufferArrayBuffer.call(value))
    return true
  } catch {
    return false
  }
}

function clearOutputRange(output, offset, length) {
  if (!Number.isSafeInteger(offset) || offset < 0) return
  try {
    bufferFill.call(output, 0, offset, Math.min(bufferLength(output), offset + length))
  } catch {
    // Detached or malformed output cannot be safely written.
  }
}

class CellCodec {
  #seal
  #open
  #padding
  #scratch
  #reusable
  #configuredPadding

  constructor(options) {
    options = optionsObject(options)
    const crypto = option(options, 'crypto')
    const cellSize = option(options, 'cellSize')
    const configuredPadding = option(options, 'padding', false)
    const configuredScratch = option(options, TEST_ONLY_CELL_ALLOCATOR, false)

    if (cellSize !== CELL_SIZE) invalid()
    this.#reusable = crypto === cryptoSuite
    this.#configuredPadding = configuredPadding
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

  // paddingInto, when explicitly supplied, must synchronously fill its complete
  // MAX_CELL_PAYLOAD-byte scratch with fresh secure randomness. Deterministic
  // fills are test-only. An allocating constructor padding hook is never ignored.
  createSealer(options) {
    if (!this.#reusable) invalid()
    return reusableContext(options, this.#scratch, true, this.#configuredPadding)
  }

  createOpener(options) {
    if (!this.#reusable) invalid()
    return reusableContext(options, this.#scratch, false, undefined)
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
