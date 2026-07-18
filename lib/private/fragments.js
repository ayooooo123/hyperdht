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

// Deep-imported only by this module's tests. These are absent from the
// documented package entry point and are explicitly not access-control
// boundaries. The allocation seam can only fail before the trusted allocator;
// it cannot observe or provide storage.
const TEST_ONLY_FRAGMENT_OBSERVER = Symbol('test-only-fragment-observer')
const TEST_ONLY_FRAGMENT_ALLOCATION_FAILURE = Symbol('test-only-fragment-allocation-failure')

const MESSAGE_ID_BYTES = 16
const HEX = '0123456789abcdef'
const bufferByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
const bufferFill = Uint8Array.prototype.fill
const bufferSet = Uint8Array.prototype.set
const bufferSubarray = Uint8Array.prototype.subarray
const b4aAllocUnsafeSlow = b4a.allocUnsafeSlow
const b4aIsBuffer = b4a.isBuffer
const mathCeil = Math.ceil
const mathMax = Math.max
const mathMin = Math.min
const numberIsSafeInteger = Number.isSafeInteger
const MapConstructor = Map
const SetConstructor = Set
const mapPrototype = MapConstructor.prototype
const setPrototype = SetConstructor.prototype
const mapSize = Object.getOwnPropertyDescriptor(mapPrototype, 'size').get
const setSize = Object.getOwnPropertyDescriptor(setPrototype, 'size').get
const mapGet = mapPrototype.get
const mapHas = mapPrototype.has
const mapSet = mapPrototype.set
const mapDelete = mapPrototype.delete
const mapClear = mapPrototype.clear
const mapValues = mapPrototype.values
const setHas = setPrototype.has
const setAdd = setPrototype.add
const setDelete = setPrototype.delete
const setClear = setPrototype.clear
const setValues = setPrototype.values
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectGetPrototypeOf = Object.getPrototypeOf
const objectHasOwnProperty = Object.prototype.hasOwnProperty
const reflectApply = Reflect.apply
const mapIteratorNext = objectGetOwnPropertyDescriptor(
  objectGetPrototypeOf(reflectApply(mapValues, new MapConstructor(), [])),
  'next'
).value
const setIteratorNext = objectGetOwnPropertyDescriptor(
  objectGetPrototypeOf(reflectApply(setValues, new SetConstructor(), [])),
  'next'
).value

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

function isBuffer(value, size) {
  return bufferLength(value) === size
}

function clear(value) {
  try {
    if (b4aIsBuffer(value)) reflectApply(bufferFill, value, [0])
  } catch {
    // Best-effort zeroization only.
  }
}

function allocationFailure(options) {
  const at = option(options, TEST_ONLY_FRAGMENT_ALLOCATION_FAILURE)
  if (at === undefined) return null
  if (!numberIsSafeInteger(at) || at < 1 || at > MAX_COMPLETED_IDS * (MAX_FRAGMENTS + 1)) {
    invalid()
  }
  return { at, count: 0 }
}

function allocate(size, failure = null) {
  let owned = null
  try {
    if (failure !== null && ++failure.count === failure.at) invalid()
    owned = reflectApply(b4aAllocUnsafeSlow, b4a, [size])
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
    return reflectApply(bufferSubarray, value, [start, end])
  } catch {
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

function copy(value, failure = null) {
  let owned = null
  try {
    const length = bufferLength(value)
    if (length < 0) invalid()
    owned = allocate(length, failure)
    set(owned, value)
    return owned
  } catch (err) {
    clear(owned)
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function positiveLimit(value, maximum) {
  if (!numberIsSafeInteger(value) || value < 1 || value > maximum) invalid()
  return value
}

function timeoutValue(value) {
  if (!numberIsSafeInteger(value) || value < 0 || value > MESSAGE_TIMEOUT) invalid()
  return value
}

function timeValue(value) {
  if (!numberIsSafeInteger(value) || value < 0) invalid()
  return value
}

function mapSizeOf(map) {
  return reflectApply(mapSize, map, [])
}

function setSizeOf(set) {
  return reflectApply(setSize, set, [])
}

function mapGetValue(map, key) {
  return reflectApply(mapGet, map, [key])
}

function mapHasValue(map, key) {
  return reflectApply(mapHas, map, [key])
}

function mapSetValue(map, key, value) {
  reflectApply(mapSet, map, [key, value])
}

function mapDeleteValue(map, key) {
  return reflectApply(mapDelete, map, [key])
}

function mapClearValues(map) {
  reflectApply(mapClear, map, [])
}

function setHasValue(set, value) {
  return reflectApply(setHas, set, [value])
}

function setAddValue(set, value) {
  reflectApply(setAdd, set, [value])
}

function setClearValues(set) {
  reflectApply(setClear, set, [])
}

function forEachMapValue(map, visit) {
  const iterator = reflectApply(mapValues, map, [])
  while (true) {
    const step = reflectApply(mapIteratorNext, iterator, [])
    if (step.done) return
    visit(step.value)
  }
}

// Captured even though Gate 3A currently only needs Set membership, insertion,
// and clearing. Future deep-only changes must not fall back to live dispatch.
function forEachSetValue(set, visit) {
  const iterator = reflectApply(setValues, set, [])
  while (true) {
    const step = reflectApply(setIteratorNext, iterator, [])
    if (step.done) return
    visit(step.value)
  }
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
  const failure = allocationFailure(options)
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

  const total = mathMax(1, mathCeil(messageLength / MAX_FRAGMENT_DATA))
  const frames = []
  let current = null
  try {
    for (let index = 0; index < total; index++) {
      const start = index * MAX_FRAGMENT_DATA
      const end = mathMin(start + MAX_FRAGMENT_DATA, messageLength)
      current = allocate(FRAGMENT_HEADER_SIZE + end - start, failure)
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
    for (let index = 0; index < frames.length; index++) clear(frames[index])
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
  #allocationFailure
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
    const failure = allocationFailure(options)

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
    this.#allocationFailure = failure
    this.#messages = new MapConstructor()
    this.#completed = new SetConstructor()
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
      messages: mapSizeOf(this.#messages),
      bufferedFragments: this.#bufferedFragments,
      bufferedDataBytes: this.#bufferedDataBytes,
      bufferedEncodedBytes: this.#bufferedEncodedBytes,
      completedIds: setSizeOf(this.#completed)
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
        const existing = mapGetValue(this.#messages, key)
        if (existing) this.#remove(existing)
      }
      invalid()
    }

    const messageId = subarray(value, 0, MESSAGE_ID_BYTES)
    const key = idKey(messageId)
    const beforeClock = mapGetValue(this.#messages, key)
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
      total > mathCeil(this.#maxMessageBytes / MAX_FRAGMENT_DATA) ||
      (index === total - 1 && maximumBytes > this.#maxMessageBytes)
    ) {
      if (beforeClock) this.#remove(beforeClock)
      limit()
    }

    const data = subarray(value, FRAGMENT_HEADER_SIZE)
    let owned = null
    try {
      owned = copy(data, this.#allocationFailure)
    } catch (err) {
      if (beforeClock) this.#remove(beforeClock)
      throw err
    }

    let current = null
    let existing = null
    let state = null
    const encodedLength = FRAGMENT_HEADER_SIZE + dataLength
    try {
      current = this.#readNow()
      this.#expireAt(current)
      if (setHasValue(this.#completed, key)) throw PrivateRouteError.REPLAY()
      existing = mapGetValue(this.#messages, key)
      if (existing && existing.total !== total) {
        this.#remove(existing)
        invalid()
      }

      if (existing && mapHasValue(existing.parts, index)) {
        const accepted = mapGetValue(existing.parts, index)
        if (same(accepted, owned)) throw PrivateRouteError.REPLAY()
        this.#remove(existing)
        invalid()
      }

      if (!existing && setSizeOf(this.#completed) >= this.#maxCompletedIds) limit()
      const completes = existing ? mapSizeOf(existing.parts) + 1 === total : total === 1
      if (completes && setSizeOf(this.#completed) >= this.#maxCompletedIds) {
        if (existing) this.#remove(existing)
        limit()
      }
      if (!existing && mapSizeOf(this.#messages) >= this.#maxMessages) limit()
      if (this.#bufferedFragments + 1 > this.#maxBufferedFragments) limit()
      if (this.#bufferedEncodedBytes + encodedLength > this.#maxBufferedEncodedBytes) limit()
    } catch (err) {
      clear(owned)
      throw err
    }

    state = existing
    try {
      if (!state) {
        state = {
          key,
          total,
          startedAt: current,
          parts: new MapConstructor(),
          dataBytes: 0,
          encodedBytes: 0
        }
        mapSetValue(this.#messages, key, state)
      }
      mapSetValue(state.parts, index, owned)
      state.dataBytes += dataLength
      state.encodedBytes += encodedLength
      this.#bufferedFragments++
      this.#bufferedDataBytes += dataLength
      this.#bufferedEncodedBytes += encodedLength
    } catch {
      clear(owned)
      if (state) this.#remove(state)
      invalid()
    }
    this.#notify(owned)

    if (mapSizeOf(state.parts) !== total) return null
    return this.#complete(state)
  }

  #complete(state) {
    if (state.dataBytes > this.#maxMessageBytes) {
      this.#remove(state)
      limit()
    }

    let message = null
    try {
      message = allocate(state.dataBytes, this.#allocationFailure)
      let offset = 0
      for (let index = 0; index < state.total; index++) {
        const part = mapGetValue(state.parts, index)
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

    setAddValue(this.#completed, state.key)
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
    if (this.#mutating) {
      this.#destroyed = true
      this.#destroyRequested = true
      invalid()
    }
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
    if (!numberIsSafeInteger(current) || current < 0) {
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
    forEachMapValue(this.#messages, (state) => {
      if (current - state.startedAt < this.#messageTimeout) return
      this.#remove(state)
      expired++
    })
    return expired
  }

  #remove(state) {
    if (!mapDeleteValue(this.#messages, state.key)) return
    forEachMapValue(state.parts, clear)
    this.#bufferedFragments -= mapSizeOf(state.parts)
    this.#bufferedDataBytes -= state.dataBytes
    this.#bufferedEncodedBytes -= state.encodedBytes
    mapClearValues(state.parts)
    state.dataBytes = 0
    state.encodedBytes = 0
  }

  #destroyAll() {
    forEachMapValue(this.#messages, (state) => {
      forEachMapValue(state.parts, clear)
      mapClearValues(state.parts)
      state.dataBytes = 0
      state.encodedBytes = 0
    })
    mapClearValues(this.#messages)
    setClearValues(this.#completed)
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
  TEST_ONLY_FRAGMENT_ALLOCATION_FAILURE,
  TEST_ONLY_FRAGMENT_OBSERVER,
  fragment
}
