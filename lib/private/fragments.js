'use strict'

const b4a = require('b4a')

const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')
const { MAX_ROUTE_PAYLOAD } = require('./route-payload')

// Ported from the reviewed private-routes prototype at commit
// 0305df915b6a767093f9e75e6c06bc0a35da6169, with the smaller resource
// ceilings required by the reviewed Gate 3A specification.

const FRAGMENT_HEADER_SIZE = 20
const MAX_FRAGMENT_DATA = MAX_ROUTE_PAYLOAD - FRAGMENT_HEADER_SIZE
const MAX_FRAGMENTS = 8
// Eight full data chunks are 8,424 application bytes. Their headers make the
// eight encoded route payloads 8,584 bytes; 8,584 is not an application limit.
const MAX_MESSAGE_DATA_BYTES = MAX_FRAGMENTS * MAX_FRAGMENT_DATA
const MAX_ENCODED_MESSAGE_BYTES = MAX_FRAGMENTS * MAX_ROUTE_PAYLOAD
const MAX_MESSAGES = 8
const MAX_BUFFERED_FRAGMENTS = 8
const MAX_BUFFERED_ENCODED_BYTES = MAX_ENCODED_MESSAGE_BYTES
const MAX_COMPLETED_IDS = 64
const MESSAGE_TIMEOUT = 5000

// Deep-imported only by this module's tests. It is absent from the documented
// package entry point and is explicitly not an access-control boundary.
const TEST_ONLY_FRAGMENT_OBSERVER = Symbol('test-only-fragment-observer')

const MESSAGE_ID_BYTES = 16
const HEX = '0123456789abcdef'
const bufferByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
const bufferFill = Uint8Array.prototype.fill
const bufferSet = Uint8Array.prototype.set
const bufferSubarray = Uint8Array.prototype.subarray
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectHasOwnProperty = Object.prototype.hasOwnProperty

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function limit() {
  throw PrivateRouteError.CIRCUIT_LIMIT()
}

function optionsObject(options, optional = false) {
  if (options === undefined && optional) return {}

  try {
    if (options === null || typeof options !== 'object' || Array.isArray(options)) invalid()
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }

  return options
}

function option(options, name, required = false) {
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
    if (inherited || required) invalid()
    return undefined
  }

  if (!objectHasOwnProperty.call(descriptor, 'value')) invalid()
  return descriptor.value
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
    if (b4a.isBuffer(value)) bufferFill.call(value, 0)
  } catch {
    // Best-effort zeroization only.
  }
}

function allocate(size) {
  let owned = null
  try {
    owned = b4a.allocUnsafeSlow(size)
    if (!isBuffer(owned, size)) invalid()
    return owned
  } catch (err) {
    clear(owned)
    if (err instanceof PrivateRouteError) throw err
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

function set(target, source, offset = 0) {
  try {
    bufferSet.call(target, source, offset)
  } catch {
    invalid()
  }
}

function copy(value) {
  let owned = null
  try {
    const length = bufferLength(value)
    if (length < 0) invalid()
    owned = allocate(length)
    set(owned, value)
    return owned
  } catch (err) {
    clear(owned)
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function positiveLimit(value, maximum) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) invalid()
  return value
}

function timeoutValue(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > MESSAGE_TIMEOUT) invalid()
  return value
}

function timeValue(value) {
  if (!Number.isSafeInteger(value) || value < 0) invalid()
  return value
}

function idKey(value) {
  let key = ''
  for (let i = 0; i < MESSAGE_ID_BYTES; i++) {
    const byte = value[i]
    key += HEX[byte >>> 4] + HEX[byte & 15]
  }
  return key
}

function same(a, b) {
  const length = bufferLength(a)
  if (length < 0 || bufferLength(b) !== length) invalid()
  let different = 0
  for (let i = 0; i < length; i++) different |= a[i] ^ b[i]
  return different === 0
}

function writeUint16BE(buffer, value, offset) {
  buffer[offset] = value >>> 8
  buffer[offset + 1] = value
}

function readUint16BE(buffer, offset) {
  return (buffer[offset] << 8) | buffer[offset + 1]
}

function fragment(message, options) {
  const messageLength = bufferLength(message)
  if (messageLength < 0 || messageLength > MAX_MESSAGE_DATA_BYTES) invalid()

  options = optionsObject(options, true)
  let messageId = option(options, 'messageId')
  const randomBytes = option(options, 'randomBytes')
  if (messageId === undefined) {
    const random = randomBytes === undefined ? cryptoSuite.randomBytes : randomBytes
    if (typeof random !== 'function') invalid()
    try {
      messageId = random(MESSAGE_ID_BYTES)
    } catch {
      invalid()
    }
  }
  if (!isBuffer(messageId, MESSAGE_ID_BYTES)) invalid()

  const total = Math.max(1, Math.ceil(messageLength / MAX_FRAGMENT_DATA))
  const frames = new Array(total)
  let current = null
  try {
    for (let index = 0; index < total; index++) {
      const start = index * MAX_FRAGMENT_DATA
      const end = Math.min(start + MAX_FRAGMENT_DATA, messageLength)
      current = allocate(FRAGMENT_HEADER_SIZE + end - start)
      set(current, messageId)
      writeUint16BE(current, index, 16)
      writeUint16BE(current, total, 18)
      set(current, subarray(message, start, end), FRAGMENT_HEADER_SIZE)
      frames[index] = current
      current = null
    }
    return frames
  } catch {
    clear(current)
    for (const value of frames) clear(value)
    invalid()
  }
}

class Reassembler {
  #now
  #epochExpiresAt
  #maxMessageBytes
  #maxMessages
  #maxBufferedFragments
  #maxBufferedEncodedBytes
  #maxCompletedIds
  #messageTimeout
  #observe
  #messages
  #completed
  #bufferedFragments
  #bufferedDataBytes
  #bufferedEncodedBytes
  #lastNow
  #destroyed
  #mutating
  #destroyRequested

  constructor(options) {
    options = optionsObject(options)
    const now = option(options, 'now', true)
    const epochExpiresAt = option(options, 'epochExpiresAt', true)
    const maxMessageBytes = option(options, 'maxMessageBytes')
    const maxMessages = option(options, 'maxMessages')
    const maxBufferedFragments = option(options, 'maxBufferedFragments')
    const maxBufferedEncodedBytes = option(options, 'maxBufferedEncodedBytes')
    const maxCompletedIds = option(options, 'maxCompletedIds')
    const messageTimeout = option(options, 'messageTimeout')
    const observe = option(options, TEST_ONLY_FRAGMENT_OBSERVER)

    if (typeof now !== 'function') invalid()
    if (observe !== undefined && typeof observe !== 'function') invalid()
    this.#now = now
    this.#epochExpiresAt = timeValue(epochExpiresAt)
    this.#maxMessageBytes = positiveLimit(
      maxMessageBytes === undefined ? MAX_MESSAGE_DATA_BYTES : maxMessageBytes,
      MAX_MESSAGE_DATA_BYTES
    )
    this.#maxMessages = positiveLimit(
      maxMessages === undefined ? MAX_MESSAGES : maxMessages,
      MAX_MESSAGES
    )
    this.#maxBufferedFragments = positiveLimit(
      maxBufferedFragments === undefined ? MAX_BUFFERED_FRAGMENTS : maxBufferedFragments,
      MAX_BUFFERED_FRAGMENTS
    )
    this.#maxBufferedEncodedBytes = positiveLimit(
      maxBufferedEncodedBytes === undefined ? MAX_BUFFERED_ENCODED_BYTES : maxBufferedEncodedBytes,
      MAX_BUFFERED_ENCODED_BYTES
    )
    this.#maxCompletedIds = positiveLimit(
      maxCompletedIds === undefined ? MAX_COMPLETED_IDS : maxCompletedIds,
      MAX_COMPLETED_IDS
    )
    this.#messageTimeout = timeoutValue(
      messageTimeout === undefined ? MESSAGE_TIMEOUT : messageTimeout
    )
    this.#observe = observe || null
    this.#messages = new Map()
    this.#completed = new Set()
    this.#bufferedFragments = 0
    this.#bufferedDataBytes = 0
    this.#bufferedEncodedBytes = 0
    this.#lastNow = null
    this.#destroyed = false
    this.#mutating = false
    this.#destroyRequested = false
  }

  get stats() {
    return Object.freeze({
      destroyed: this.#destroyed,
      messages: this.#messages.size,
      bufferedFragments: this.#bufferedFragments,
      bufferedDataBytes: this.#bufferedDataBytes,
      bufferedEncodedBytes: this.#bufferedEncodedBytes,
      completedIds: this.#completed.size
    })
  }

  pushAuthenticated(value) {
    return this.#mutate(() => this.#pushAuthenticated(value))
  }

  expire(at) {
    return this.#mutate(() => {
      this.#assertOpen()
      const current = at === undefined ? this.#readNow() : this.#observeTime(at)
      return this.#expireAt(current)
    })
  }

  destroy() {
    if (this.#destroyed && !this.#mutating) return
    if (this.#mutating) {
      this.#destroyed = true
      this.#destroyRequested = true
      return
    }
    this.#destroyAll()
  }

  #pushAuthenticated(value) {
    this.#assertOpen()
    const length = bufferLength(value)
    if (length < FRAGMENT_HEADER_SIZE) {
      if (length >= MESSAGE_ID_BYTES) {
        const key = idKey(subarray(value, 0, MESSAGE_ID_BYTES))
        const existing = this.#messages.get(key)
        if (existing) this.#remove(existing)
      }
      invalid()
    }

    const messageId = subarray(value, 0, MESSAGE_ID_BYTES)
    const key = idKey(messageId)
    const beforeClock = this.#messages.get(key)
    if (length > MAX_ROUTE_PAYLOAD) {
      if (beforeClock) this.#remove(beforeClock)
      invalid()
    }

    const index = readUint16BE(value, 16)
    const total = readUint16BE(value, 18)
    const dataLength = length - FRAGMENT_HEADER_SIZE
    if (total === 0 || total > MAX_FRAGMENTS || index >= total) {
      if (beforeClock) this.#remove(beforeClock)
      invalid()
    }
    if (index < total - 1 && dataLength !== MAX_FRAGMENT_DATA) {
      if (beforeClock) this.#remove(beforeClock)
      invalid()
    }
    if (total > 1 && index === total - 1 && dataLength === 0) {
      if (beforeClock) this.#remove(beforeClock)
      invalid()
    }
    if (beforeClock && beforeClock.total !== total) {
      this.#remove(beforeClock)
      invalid()
    }

    const maximumBytes = (total - 1) * MAX_FRAGMENT_DATA + dataLength
    if (
      total > Math.ceil(this.#maxMessageBytes / MAX_FRAGMENT_DATA) ||
      (index === total - 1 && maximumBytes > this.#maxMessageBytes)
    ) {
      if (beforeClock) this.#remove(beforeClock)
      limit()
    }

    const current = this.#readNow()
    this.#expireAt(current)
    if (this.#completed.has(key)) throw PrivateRouteError.REPLAY()
    const existing = this.#messages.get(key)
    if (existing && existing.total !== total) {
      this.#remove(existing)
      invalid()
    }

    const data = subarray(value, FRAGMENT_HEADER_SIZE)
    if (existing && existing.parts.has(index)) {
      const accepted = existing.parts.get(index)
      if (same(accepted, data)) throw PrivateRouteError.REPLAY()
      this.#remove(existing)
      invalid()
    }

    if (!existing && this.#completed.size >= this.#maxCompletedIds) limit()
    const completes = existing ? existing.parts.size + 1 === total : total === 1
    if (completes && this.#completed.size >= this.#maxCompletedIds) {
      if (existing) this.#remove(existing)
      limit()
    }
    if (!existing && this.#messages.size >= this.#maxMessages) limit()
    if (this.#bufferedFragments + 1 > this.#maxBufferedFragments) limit()
    const encodedLength = FRAGMENT_HEADER_SIZE + dataLength
    if (this.#bufferedEncodedBytes + encodedLength > this.#maxBufferedEncodedBytes) limit()

    let owned = null
    try {
      owned = copy(data)
    } catch (err) {
      if (existing) this.#remove(existing)
      throw err
    }

    let state = existing
    if (!state) {
      state = {
        key,
        total,
        startedAt: current,
        parts: new Map(),
        dataBytes: 0,
        encodedBytes: 0
      }
      this.#messages.set(key, state)
    }
    state.parts.set(index, owned)
    state.dataBytes += dataLength
    state.encodedBytes += encodedLength
    this.#bufferedFragments++
    this.#bufferedDataBytes += dataLength
    this.#bufferedEncodedBytes += encodedLength
    this.#notify(owned)

    if (state.parts.size !== total) return null
    return this.#complete(state)
  }

  #complete(state) {
    if (state.dataBytes > this.#maxMessageBytes) {
      this.#remove(state)
      limit()
    }

    let message = null
    try {
      message = allocate(state.dataBytes)
      let offset = 0
      for (let index = 0; index < state.total; index++) {
        const part = state.parts.get(index)
        if (!part) invalid()
        const length = bufferLength(part)
        if (length < 0) invalid()
        set(message, part, offset)
        offset += length
      }
      if (offset !== state.dataBytes) invalid()
    } catch {
      clear(message)
      this.#remove(state)
      invalid()
    }

    this.#completed.add(state.key)
    this.#remove(state)
    return message
  }

  #notify(owned) {
    if (this.#observe === null) return
    try {
      this.#observe(owned)
    } catch {
      this.#destroyAll()
      invalid()
    }
    this.#assertNoDeferredDestroy()
  }

  #mutate(operation) {
    if (this.#mutating) invalid()
    this.#mutating = true
    try {
      const result = operation()
      if (this.#destroyRequested) {
        clear(result)
        this.#destroyAll()
        invalid()
      }
      return result
    } finally {
      if (this.#destroyRequested) this.#destroyAll()
      this.#mutating = false
    }
  }

  #assertOpen() {
    if (this.#destroyed) throw PrivateRouteError.CIRCUIT_STATE()
  }

  #assertNoDeferredDestroy() {
    if (!this.#destroyRequested) return
    this.#destroyAll()
    invalid()
  }

  #readNow() {
    let current
    try {
      current = this.#now()
    } catch {
      this.#destroyAll()
      invalid()
    }
    this.#assertNoDeferredDestroy()
    return this.#observeTime(current)
  }

  #observeTime(current) {
    if (!Number.isSafeInteger(current) || current < 0) {
      this.#destroyAll()
      invalid()
    }
    if (this.#lastNow !== null && current < this.#lastNow) {
      this.#destroyAll()
      invalid()
    }
    this.#lastNow = current
    if (current >= this.#epochExpiresAt) {
      this.#destroyAll()
      throw PrivateRouteError.CIRCUIT_STATE()
    }
    return current
  }

  #expireAt(current) {
    let expired = 0
    for (const state of this.#messages.values()) {
      if (current - state.startedAt < this.#messageTimeout) continue
      this.#remove(state)
      expired++
    }
    return expired
  }

  #remove(state) {
    if (!this.#messages.delete(state.key)) return
    for (const part of state.parts.values()) clear(part)
    this.#bufferedFragments -= state.parts.size
    this.#bufferedDataBytes -= state.dataBytes
    this.#bufferedEncodedBytes -= state.encodedBytes
    state.parts.clear()
    state.dataBytes = 0
    state.encodedBytes = 0
  }

  #destroyAll() {
    for (const state of this.#messages.values()) {
      for (const part of state.parts.values()) clear(part)
      state.parts.clear()
      state.dataBytes = 0
      state.encodedBytes = 0
    }
    this.#messages.clear()
    this.#completed.clear()
    this.#bufferedFragments = 0
    this.#bufferedDataBytes = 0
    this.#bufferedEncodedBytes = 0
    this.#destroyed = true
    this.#destroyRequested = false
  }
}

module.exports = {
  FRAGMENT_HEADER_SIZE,
  MAX_FRAGMENT_DATA,
  MAX_FRAGMENTS,
  MAX_MESSAGE_DATA_BYTES,
  MAX_MESSAGE_BYTES: MAX_MESSAGE_DATA_BYTES,
  MAX_ENCODED_MESSAGE_BYTES,
  MAX_MESSAGES,
  MAX_BUFFERED_FRAGMENTS,
  MAX_BUFFERED_ENCODED_BYTES,
  MAX_BUFFERED_BYTES: MAX_BUFFERED_ENCODED_BYTES,
  MAX_COMPLETED_IDS,
  MESSAGE_TIMEOUT,
  Reassembler,
  TEST_ONLY_FRAGMENT_OBSERVER,
  fragment
}
