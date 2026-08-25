'use strict'

const b4a = require('b4a')

let isProxy
try {
  isProxy = require('util').types.isProxy
} catch {
  isProxy = require('bare-utils').types.isProxy
}

const MAX_BODY_BYTES = 65_536
const MAX_BUFFERED_BYTES = 131_072
const MAX_STRING_BYTES = 16_384
const MAX_ARRAY_ITEMS = 4_096
const MAX_OBJECT_FIELDS = 256
const MAX_CANONICAL_NODES = 8_192
const MAX_CANONICAL_WORK = 8_191
const MAX_U64 = 0xffff_ffff_ffff_ffffn
const TEST_ONLY_CONTROL_BUFFER_OBSERVER = Symbol('test-only-control-buffer-observer')

const COMMANDS = Object.freeze([
  'configure',
  'prepare',
  'isolated-grant',
  'store-immutable',
  'activate',
  'immutable-get',
  'cancel',
  'rotate',
  'blackhole',
  'suspend',
  'resume',
  'network-change',
  'guard-loss',
  'phase-ack',
  'snapshot',
  'stop'
])

const EVENTS = Object.freeze([
  'configured',
  'prepared',
  'isolated-grant-request',
  'stored',
  'phase',
  'phase-pending',
  'audit-open',
  'audit-close',
  'ready',
  'value',
  'cancelled',
  'rotated',
  'suspended',
  'resumed',
  'unavailable',
  'snapshot',
  'closed',
  'error'
])

const ROLES = Object.freeze([
  'endpoint',
  'guard',
  'lookup-middle-a',
  'lookup-exit-a',
  'lookup-middle-b',
  'lookup-exit-b',
  'announce-middle',
  'announce-exit',
  'dht-seed',
  'dht-referral',
  'dht-value'
])

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype'])
const STATES = new Set([
  'NEW',
  'CONFIGURED',
  'PREPARED',
  'DHT_SETUP',
  'BOOTSTRAPPING',
  'READY',
  'ROTATING',
  'SUSPENDED',
  'UNAVAILABLE',
  'CLOSED'
])
const UNAVAILABLE_REASONS = new Set(['NETWORK_CHANGE', 'GUARD_LOSS', 'CANCELLED', 'ERROR'])
const RUNTIMES = new Set(['node', 'bare'])
const EXIT_ROLES = new Set(['lookup-exit-a', 'lookup-exit-b', 'announce-exit'])
const AUDIT_ROLES = new Set([...EXIT_ROLES, 'dht-referral'])
const DHT_ROLES = new Set(['dht-seed', 'dht-referral', 'dht-value'])

const TAG = Object.freeze({
  NULL: 0,
  FALSE: 1,
  TRUE: 2,
  INTEGER: 3,
  STRING: 4,
  ARRAY: 5,
  OBJECT: 6,
  U64: 7,
  BYTES: 8
})

const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype)
const byteLengthGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get
const bufferSet = Uint8Array.prototype.set
const bufferFill = Uint8Array.prototype.fill
const bufferSubarray = Uint8Array.prototype.subarray
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectGetPrototypeOf = Object.getPrototypeOf
const reflectOwnKeys = Reflect.ownKeys

class ProcessProtocolError extends Error {
  constructor(code) {
    super(code)
    this.code = code
  }
}

function invalid() {
  throw new ProcessProtocolError('PROCESS_PROTOCOL_INVALID')
}

function replay() {
  throw new ProcessProtocolError('PROCESS_PROTOCOL_REPLAY')
}

function closed() {
  throw new ProcessProtocolError('PROCESS_PROTOCOL_CLOSED')
}

function safeProxy(value) {
  try {
    return isProxy(value)
  } catch {
    return true
  }
}

function bufferLength(value) {
  try {
    if (!b4a.isBuffer(value) || safeProxy(value)) return -1
    return byteLengthGetter.call(value)
  } catch {
    return -1
  }
}

function clear(value) {
  try {
    if (bufferLength(value) >= 0) bufferFill.call(value, 0)
  } catch {}
}

function copy(value) {
  const size = bufferLength(value)
  if (size < 0) invalid()
  const output = b4a.allocUnsafeSlow(size)
  bufferSet.call(output, value)
  return output
}

function uint16(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 0xffff
}

function uint64(value, nonzero = false) {
  return typeof value === 'bigint' && value >= (nonzero ? 1n : 0n) && value <= MAX_U64
}

function ownData(value, key) {
  let descriptor
  try {
    descriptor = objectGetOwnPropertyDescriptor(value, key)
  } catch {
    invalid()
  }
  if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) invalid()
  return descriptor.value
}

function exactObject(value, fields) {
  let keys
  try {
    if (
      value === null ||
      typeof value !== 'object' ||
      safeProxy(value) ||
      objectGetPrototypeOf(value) !== Object.prototype
    ) {
      invalid()
    }
    keys = reflectOwnKeys(value)
  } catch (err) {
    if (err instanceof ProcessProtocolError) throw err
    invalid()
  }
  if (keys.length !== fields.length || keys.some((key) => typeof key !== 'string')) invalid()
  const actual = keys.slice().sort()
  const expected = fields.slice().sort()
  for (let index = 0; index < expected.length; index++)
    if (actual[index] !== expected[index]) invalid()
  for (const field of fields) ownData(value, field)
}

function validString(value, maximum = MAX_STRING_BYTES) {
  if (typeof value !== 'string') return false
  for (let index = 0; index < value.length; index++) {
    const unit = value.charCodeAt(index)
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++index)
      if (next < 0xdc00 || next > 0xdfff) return false
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false
    }
  }
  return b4a.byteLength(value) <= maximum
}

function stringBytes(value, maximum = MAX_STRING_BYTES) {
  if (!validString(value, maximum)) invalid()
  return b4a.from(value)
}

function validUtf8(input) {
  for (let index = 0; index < input.byteLength; index++) {
    const first = input[index]
    if (first <= 0x7f) continue
    let count
    let lower = 0x80
    let upper = 0xbf
    if (first >= 0xc2 && first <= 0xdf) count = 1
    else if (first >= 0xe0 && first <= 0xef) {
      count = 2
      if (first === 0xe0) lower = 0xa0
      if (first === 0xed) upper = 0x9f
    } else if (first >= 0xf0 && first <= 0xf4) {
      count = 3
      if (first === 0xf0) lower = 0x90
      if (first === 0xf4) upper = 0x8f
    } else return false
    if (index + count >= input.byteLength) return false
    const second = input[++index]
    if (second < lower || second > upper) return false
    for (let offset = 1; offset < count; offset++) {
      const next = input[++index]
      if (next < 0x80 || next > 0xbf) return false
    }
  }
  return true
}

function writeU16(target, value, offset) {
  target[offset] = value >>> 8
  target[offset + 1] = value
}

function writeU32(target, value, offset) {
  target[offset] = value >>> 24
  target[offset + 1] = value >>> 16
  target[offset + 2] = value >>> 8
  target[offset + 3] = value
}

function writeU64(target, value, offset) {
  for (let index = offset + 7; index >= offset; index--) {
    target[index] = Number(value & 0xffn)
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

function chargeWork(state, amount) {
  if (!Number.isSafeInteger(amount) || amount < 0 || state.work + amount > MAX_CANONICAL_WORK)
    invalid()
  state.work += amount
}

function reserveBytes(state, size) {
  if (!Number.isSafeInteger(size) || size < 0 || state.size + size > MAX_BODY_BYTES) invalid()
  state.size += size
}

function allocateChunk(state, size) {
  reserveBytes(state, size)
  const output = b4a.allocUnsafeSlow(size)
  state.chunks.push(output)
  return output
}

function sortedObjectEntries(value, state) {
  exactPlainContainer(value)
  const keys = reflectOwnKeys(value)
  if (keys.length > MAX_OBJECT_FIELDS || keys.some((key) => typeof key !== 'string')) invalid()
  chargeWork(state, keys.length)
  const entries = []
  try {
    for (const key of keys) {
      if (FORBIDDEN_KEYS.has(key) || !validString(key, 0xffff)) invalid()
      const keySize = b4a.byteLength(key)
      const entryValue = ownData(value, key)
      reserveBytes(state, 2 + keySize)
      const keyHeader = b4a.allocUnsafeSlow(2)
      const keyBytes = b4a.from(key)
      writeU16(keyHeader, keySize, 0)
      entries.push({ keyBytes, keyHeader, value: entryValue })
    }
    entries.sort((left, right) => b4a.compare(left.keyBytes, right.keyBytes))
    for (let index = 1; index < entries.length; index++) {
      if (b4a.compare(entries[index - 1].keyBytes, entries[index].keyBytes) === 0) invalid()
    }
    return entries
  } catch (err) {
    for (const entry of entries) {
      clear(entry.keyHeader)
      clear(entry.keyBytes)
    }
    throw err
  }
}

function exactPlainContainer(value) {
  try {
    if (safeProxy(value) || objectGetPrototypeOf(value) !== Object.prototype) invalid()
  } catch (err) {
    if (err instanceof ProcessProtocolError) throw err
    invalid()
  }
}

function encodeValue(value, state, ancestors, depth) {
  if (depth > 64 || ++state.nodes > MAX_CANONICAL_NODES) invalid()
  if (value === null || value === false || value === true) {
    const output = allocateChunk(state, 1)
    output[0] = value === null ? TAG.NULL : value ? TAG.TRUE : TAG.FALSE
    return
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) invalid()
    const output = allocateChunk(state, 9)
    output[0] = TAG.INTEGER
    writeU64(output, BigInt.asUintN(64, BigInt(value)), 1)
    return
  }
  if (typeof value === 'bigint') {
    if (!uint64(value)) invalid()
    const decimal = value.toString(10)
    const size = b4a.byteLength(decimal)
    reserveBytes(state, 2 + size)
    const bytes = b4a.from(decimal)
    const output = b4a.allocUnsafeSlow(2 + size)
    output[0] = TAG.U64
    output[1] = size
    bufferSet.call(output, bytes, 2)
    clear(bytes)
    state.chunks.push(output)
    return
  }
  if (typeof value === 'string') {
    if (!validString(value)) invalid()
    const size = b4a.byteLength(value)
    reserveBytes(state, 5 + size)
    const header = b4a.allocUnsafeSlow(5)
    const bytes = b4a.from(value)
    header[0] = TAG.STRING
    writeU32(header, size, 1)
    state.chunks.push(header, bytes)
    return
  }
  const byteSize = bufferLength(value)
  if (byteSize >= 0) {
    reserveBytes(state, 5 + byteSize)
    const header = b4a.allocUnsafeSlow(5)
    header[0] = TAG.BYTES
    writeU32(header, byteSize, 1)
    state.chunks.push(header, copy(value))
    return
  }
  if (value === null || typeof value !== 'object' || safeProxy(value)) invalid()
  if (ancestors.has(value)) invalid()
  ancestors.add(value)
  try {
    if (Array.isArray(value)) {
      const lengthDescriptor = objectGetOwnPropertyDescriptor(value, 'length')
      if (!lengthDescriptor || !('value' in lengthDescriptor)) invalid()
      const length = lengthDescriptor.value
      if (!Number.isSafeInteger(length) || length < 0 || length > MAX_ARRAY_ITEMS) invalid()
      chargeWork(state, length)
      const keys = reflectOwnKeys(value)
      if (keys.length !== length + 1) invalid()
      const header = allocateChunk(state, 5)
      header[0] = TAG.ARRAY
      writeU32(header, length, 1)
      for (let index = 0; index < length; index++) {
        const descriptor = objectGetOwnPropertyDescriptor(value, String(index))
        if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) invalid()
        encodeValue(descriptor.value, state, ancestors, depth + 1)
      }
      return
    }
    const header = allocateChunk(state, 5)
    header[0] = TAG.OBJECT
    const entries = sortedObjectEntries(value, state)
    writeU32(header, entries.length, 1)
    try {
      for (const entry of entries) {
        state.chunks.push(entry.keyHeader, entry.keyBytes)
        entry.keyHeader = null
        entry.keyBytes = null
        encodeValue(entry.value, state, ancestors, depth + 1)
      }
    } finally {
      for (const entry of entries) {
        clear(entry.keyHeader)
        clear(entry.keyBytes)
      }
    }
  } finally {
    ancestors.delete(value)
  }
}

function encodeCanonicalBody(value) {
  const state = { chunks: [], nodes: 0, size: 0, work: 0 }
  try {
    encodeValue(value, state, new Set(), 0)
    const output = b4a.allocUnsafeSlow(state.size)
    let offset = 0
    for (const chunk of state.chunks) {
      bufferSet.call(output, chunk, offset)
      offset += chunk.byteLength
    }
    return output
  } finally {
    for (const chunk of state.chunks) clear(chunk)
  }
}

class BodyReader {
  constructor(input) {
    const size = bufferLength(input)
    if (size < 1 || size > MAX_BODY_BYTES) invalid()
    this.input = input
    this.offset = 0
  }

  take(size) {
    if (!Number.isSafeInteger(size) || size < 0 || this.offset + size > this.input.byteLength)
      invalid()
    const output = bufferSubarray.call(this.input, this.offset, this.offset + size)
    this.offset += size
    return output
  }

  u8() {
    return this.take(1)[0]
  }

  u16() {
    const offset = this.offset
    this.take(2)
    return readU16(this.input, offset)
  }

  u32() {
    const offset = this.offset
    this.take(4)
    return readU32(this.input, offset)
  }

  u64() {
    const offset = this.offset
    this.take(8)
    return readU64(this.input, offset)
  }
}

function decodeString(reader, maximum, lengthBytes = 4) {
  const size = lengthBytes === 2 ? reader.u16() : reader.u32()
  if (size > maximum) invalid()
  const bytes = reader.take(size)
  if (!validUtf8(bytes)) invalid()
  return b4a.toString(bytes)
}

function decodeValue(reader, state, depth) {
  if (depth > 64 || ++state.nodes > MAX_CANONICAL_NODES) invalid()
  const tag = reader.u8()
  switch (tag) {
    case TAG.NULL:
      return null
    case TAG.FALSE:
      return false
    case TAG.TRUE:
      return true
    case TAG.INTEGER: {
      let value = reader.u64()
      if (value >= 0x8000_0000_0000_0000n) value -= 0x1_0000_0000_0000_0000n
      const number = Number(value)
      if (!Number.isSafeInteger(number)) invalid()
      return number
    }
    case TAG.STRING:
      return decodeString(reader, MAX_STRING_BYTES)
    case TAG.U64: {
      const size = reader.u8()
      if (size < 1 || size > 20) invalid()
      const bytes = reader.take(size)
      if (!validUtf8(bytes)) invalid()
      const text = b4a.toString(bytes)
      if (!/^(0|[1-9][0-9]*)$/.test(text)) invalid()
      const value = BigInt(text)
      if (!uint64(value) || value.toString(10) !== text) invalid()
      return value
    }
    case TAG.BYTES: {
      const size = reader.u32()
      if (size > MAX_BODY_BYTES) invalid()
      let output = null
      try {
        output = copy(reader.take(size))
        state.owned.push(output)
        return output
      } catch (err) {
        clear(output)
        throw err
      }
    }
    case TAG.ARRAY: {
      const count = reader.u32()
      if (count > MAX_ARRAY_ITEMS) invalid()
      chargeWork(state, count)
      const output = []
      for (let index = 0; index < count; index++) output.push(decodeValue(reader, state, depth + 1))
      return Object.freeze(output)
    }
    case TAG.OBJECT: {
      const count = reader.u32()
      if (count > MAX_OBJECT_FIELDS) invalid()
      chargeWork(state, count)
      const output = {}
      let previous = null
      for (let index = 0; index < count; index++) {
        const keySize = reader.u16()
        if (keySize > 0xffff) invalid()
        const keyBytes = reader.take(keySize)
        if (!validUtf8(keyBytes)) invalid()
        if (previous !== null && b4a.compare(previous, keyBytes) >= 0) invalid()
        previous = keyBytes
        const key = b4a.toString(keyBytes)
        if (FORBIDDEN_KEYS.has(key)) invalid()
        Object.defineProperty(output, key, {
          configurable: false,
          enumerable: true,
          value: decodeValue(reader, state, depth + 1),
          writable: false
        })
      }
      return Object.freeze(output)
    }
    default:
      invalid()
  }
}

function decodeCanonicalBody(input) {
  if (bufferLength(input) < 0 || safeProxy(input)) invalid()
  const state = { nodes: 0, owned: [], work: 0 }
  let complete = false
  try {
    const reader = new BodyReader(input)
    const value = decodeValue(reader, state, 0)
    if (reader.offset !== input.byteLength) invalid()
    complete = true
    state.owned.length = 0
    return value
  } finally {
    if (!complete) for (const value of state.owned) clear(value)
    state.owned.length = 0
  }
}

function encodeControlFrame(value) {
  const body = encodeCanonicalBody(value)
  if (body.byteLength > MAX_BODY_BYTES) {
    clear(body)
    invalid()
  }
  const output = b4a.allocUnsafeSlow(4 + body.byteLength)
  writeU32(output, body.byteLength, 0)
  bufferSet.call(output, body, 4)
  clear(body)
  return output
}

function decodeControlFrame(frame) {
  const size = bufferLength(frame)
  if (size < 5) invalid()
  const bodySize = readU32(frame, 0)
  if (bodySize < 1 || bodySize > MAX_BODY_BYTES || size !== bodySize + 4) invalid()
  return decodeCanonicalBody(bufferSubarray.call(frame, 4))
}

class ControlFrameDecoder {
  constructor(dispatch, options = {}) {
    if (typeof dispatch !== 'function') invalid()
    if (options === undefined) options = {}
    exactPlainContainer(options)
    const keys = reflectOwnKeys(options)
    if (keys.length > 1) invalid()
    for (const key of keys) if (key !== TEST_ONLY_CONTROL_BUFFER_OBSERVER) invalid()
    const observer = keys.length === 0 ? null : ownData(options, TEST_ONLY_CONTROL_BUFFER_OBSERVER)
    if (observer !== null && typeof observer !== 'function') invalid()
    this._body = null
    this._bodyOffset = 0
    this._bodySize = 0
    this._destroyed = false
    this._dispatch = dispatch
    this._observer = observer
    this._prefix = b4a.allocUnsafeSlow(4)
    this._prefixOffset = 0
    bufferFill.call(this._prefix, 0)
    try {
      this._observe(this._prefix)
    } catch {
      clear(this._prefix)
      this._prefix = null
      this._dispatch = null
      this._observer = null
      this._destroyed = true
      invalid()
    }
  }

  get destroyed() {
    return this._destroyed
  }

  _observe(buffer) {
    if (this._observer !== null) this._observer(buffer)
  }

  push(chunk) {
    if (this._destroyed) closed()
    const incomingSize = bufferLength(chunk)
    if (incomingSize < 0) return this._fail()
    if (this._prefixOffset + this._bodyOffset + incomingSize > MAX_BUFFERED_BYTES)
      return this._fail()
    let offset = 0
    try {
      while (offset < incomingSize) {
        if (this._body === null) {
          const available = 4 - this._prefixOffset
          const amount = Math.min(available, incomingSize - offset)
          bufferSet.call(
            this._prefix,
            bufferSubarray.call(chunk, offset, offset + amount),
            this._prefixOffset
          )
          this._prefixOffset += amount
          offset += amount
          if (this._prefixOffset < 4) continue

          const bodySize = readU32(this._prefix, 0)
          if (bodySize < 1 || bodySize > MAX_BODY_BYTES) return this._fail()
          this._body = b4a.allocUnsafeSlow(bodySize)
          this._bodyOffset = 0
          this._bodySize = bodySize
          this._observe(this._body)
          clear(this._prefix)
          this._prefixOffset = 0
        }

        const available = this._bodySize - this._bodyOffset
        const amount = Math.min(available, incomingSize - offset)
        bufferSet.call(
          this._body,
          bufferSubarray.call(chunk, offset, offset + amount),
          this._bodyOffset
        )
        this._bodyOffset += amount
        offset += amount
        if (this._bodyOffset < this._bodySize) continue

        const complete = this._body
        this._body = null
        this._bodyOffset = 0
        this._bodySize = 0
        try {
          const value = decodeCanonicalBody(complete)
          this._dispatch(value)
        } finally {
          clear(complete)
        }
        if (this._destroyed) return true
      }
      return true
    } catch (err) {
      if (!this._destroyed) this.destroy()
      if (err instanceof ProcessProtocolError) throw err
      invalid()
    }
  }

  _fail() {
    this.destroy()
    invalid()
  }

  destroy() {
    if (this._destroyed) return
    this._destroyed = true
    clear(this._body)
    this._body = null
    this._bodyOffset = 0
    this._bodySize = 0
    clear(this._prefix)
    this._prefix = null
    this._prefixOffset = 0
    this._dispatch = null
    this._observer = null
  }
}

const BASE_FIELDS = Object.freeze(['generation', 'phaseSequence', 'role', 'roleIndex', 'type'])
const COMMAND_FIELDS = Object.freeze({
  configure: Object.freeze([
    ...BASE_FIELDS,
    'codecVectorDigest',
    'projection',
    'run',
    'runtime',
    'runtimeVersion'
  ]),
  prepare: BASE_FIELDS,
  'isolated-grant': Object.freeze([...BASE_FIELDS, 'grant', 'requestSequence', 'tupleDigest']),
  'store-immutable': Object.freeze([...BASE_FIELDS, 'value']),
  activate: BASE_FIELDS,
  'immutable-get': Object.freeze([...BASE_FIELDS, 'target']),
  cancel: Object.freeze([...BASE_FIELDS, 'operationSequence']),
  rotate: Object.freeze([...BASE_FIELDS, 'nextGeneration']),
  blackhole: BASE_FIELDS,
  suspend: BASE_FIELDS,
  resume: BASE_FIELDS,
  'network-change': BASE_FIELDS,
  'guard-loss': BASE_FIELDS,
  'phase-ack': Object.freeze([...BASE_FIELDS, 'acknowledgedPhaseSequence']),
  snapshot: BASE_FIELDS,
  stop: BASE_FIELDS
})
const EVENT_FIELDS = Object.freeze({
  configured: BASE_FIELDS,
  prepared: BASE_FIELDS,
  'isolated-grant-request': Object.freeze([
    ...BASE_FIELDS,
    'requestSequence',
    'run',
    'tupleDigest'
  ]),
  stored: Object.freeze([
    ...BASE_FIELDS,
    'setupAuditDigests',
    'setupAuditSequences',
    'valueDigest'
  ]),
  phase: Object.freeze([...BASE_FIELDS, 'state']),
  'phase-pending': Object.freeze([...BASE_FIELDS, 'pendingPhaseSequence']),
  'audit-open': Object.freeze([
    ...BASE_FIELDS,
    'class',
    'eventMAC',
    'openingPhaseSequence',
    'recordDigest',
    'recordNonce',
    'recordSequence',
    'transactionId'
  ]),
  'audit-close': Object.freeze([
    ...BASE_FIELDS,
    'class',
    'closingPhaseSequence',
    'eventMAC',
    'openingPhaseSequence',
    'outcome',
    'recordDigest',
    'recordNonce',
    'recordSequence',
    'replyDigest',
    'transactionId'
  ]),
  ready: Object.freeze([...BASE_FIELDS, 'answeredRequestCount', 'state']),
  value: Object.freeze([...BASE_FIELDS, 'target', 'value']),
  cancelled: Object.freeze([...BASE_FIELDS, 'operationSequence']),
  rotated: Object.freeze([...BASE_FIELDS, 'previousGeneration']),
  suspended: BASE_FIELDS,
  resumed: BASE_FIELDS,
  unavailable: Object.freeze([...BASE_FIELDS, 'reason']),
  snapshot: Object.freeze([
    ...BASE_FIELDS,
    'activeOperations',
    'activeExitOperations',
    'announceGeneration',
    'controllerGeneration',
    'endpointSockets',
    'guardOnly',
    'lookupGeneration',
    'openLinks',
    'ordinaryRequestCount',
    'pendingGrantRequests',
    'pendingLinks',
    'pendingPackets',
    'referralProbeCount',
    'tableEntryCount',
    'openResources',
    'queuedBytes',
    'state',
    'summaryDigest'
  ]),
  closed: BASE_FIELDS,
  error: Object.freeze([...BASE_FIELDS, 'code'])
})
const DHT_SEED_SNAPSHOT_FIELDS = Object.freeze([...EVENT_FIELDS.snapshot, 'storedValueCount'])
const DHT_VALUE_SNAPSHOT_FIELDS = Object.freeze([
  ...EVENT_FIELDS.snapshot,
  'storedValueCount',
  'storedValueDigest'
])
const DHT_REFERRAL_SNAPSHOT_FIELDS = Object.freeze([
  ...EVENT_FIELDS.snapshot,
  'storedValueCount',
  'transientValueBytes'
])

const PENDING_GRANTS = new WeakMap()
const SPENT_PENDING_GRANTS = new WeakSet()
const SNAPSHOT_COUNT_FIELDS = Object.freeze([
  'activeExitOperations',
  'endpointSockets',
  'openLinks',
  'ordinaryRequestCount',
  'pendingGrantRequests',
  'pendingLinks',
  'pendingPackets',
  'referralProbeCount',
  'tableEntryCount'
])

function issuePendingGrant(value) {
  exactObject(value, ['generation', 'requestSequence', 'role', 'tupleDigest'])
  if (!uint64(value.generation, true) || !uint64(value.requestSequence, true)) invalid()
  if (!EXIT_ROLES.has(value.role) || bufferLength(value.tupleDigest) !== 32) invalid()
  const capability = Object.freeze({})
  PENDING_GRANTS.set(capability, {
    generation: value.generation,
    requestSequence: value.requestSequence,
    role: value.role,
    tupleDigest: copy(value.tupleDigest)
  })
  return capability
}

const TEST_ONLY_CONTROL_AUTHORITY_ISSUER = Object.freeze({
  pendingGrant: issuePendingGrant
})

function consumePhaseGate(capability, common, context) {
  if (
    context.projection !== 'linux-namespace' ||
    common.role !== 'endpoint' ||
    common.roleIndex !== 1 ||
    !fixed(context.run, 16)
  )
    invalid()
  let status
  try {
    status = require('./topology-fixture').consumeProcessPhaseGate(capability, {
      generation: common.generation,
      plan: context.projection,
      role: common.role,
      roleIndex: common.roleIndex,
      run: context.run
    })
  } catch {
    invalid()
  }
  if (status === 'replay') replay()
  if (status !== 'ok') invalid()
}

function same(left, right) {
  return bufferLength(left) >= 0 && bufferLength(right) >= 0 && b4a.equals(left, right)
}

function consumePendingGrant(capability, message) {
  if (capability === null || typeof capability !== 'object') invalid()
  const pending = PENDING_GRANTS.get(capability)
  if (!pending) {
    if (SPENT_PENDING_GRANTS.has(capability)) replay()
    invalid()
  }
  if (
    pending.generation !== message.generation ||
    pending.requestSequence !== message.requestSequence ||
    pending.role !== message.role ||
    !same(pending.tupleDigest, message.tupleDigest)
  ) {
    invalid()
  }
  PENDING_GRANTS.delete(capability)
  SPENT_PENDING_GRANTS.add(capability)
  clear(pending.tupleDigest)
}

function fixed(value, size) {
  return bufferLength(value) === size
}

function zeroBytes(value, size) {
  if (!fixed(value, size)) return false
  for (let index = 0; index < size; index++) if (value[index] !== 0) return false
  return true
}

function boundedBytes(value, maximum, nonempty = false) {
  const size = bufferLength(value)
  return size >= (nonempty ? 1 : 0) && size <= maximum
}

function baseMessage(message, context, direction) {
  if (context === null || typeof context !== 'object' || safeProxy(context)) invalid()
  const type = ownData(message, 'type')
  const role = ownData(message, 'role')
  const roleIndex = ownData(message, 'roleIndex')
  const generation = ownData(message, 'generation')
  const phaseSequence = ownData(message, 'phaseSequence')
  if (
    context.direction !== direction ||
    typeof type !== 'string' ||
    !ROLES.includes(role) ||
    roleIndex !== ROLES.indexOf(role) + 1 ||
    !uint64(generation, true) ||
    !uint64(phaseSequence, true) ||
    context.role !== role ||
    context.roleIndex !== roleIndex ||
    context.generation !== generation ||
    context.phaseSequence !== phaseSequence
  ) {
    invalid()
  }
  return { generation, phaseSequence, role, roleIndex, type }
}

function validateCommand(message, context) {
  const type = ownData(message, 'type')
  const fields = COMMAND_FIELDS[type]
  if (!fields) invalid()
  exactObject(message, fields)
  const common = baseMessage(message, context, 'command')
  switch (type) {
    case 'configure':
      if (
        !fixed(message.codecVectorDigest, 32) ||
        !boundedBytes(message.projection, 48 * 1024, true) ||
        !fixed(message.run, 16) ||
        !RUNTIMES.has(message.runtime) ||
        !validString(message.runtimeVersion, 64) ||
        message.runtimeVersion.length === 0
      )
        invalid()
      break
    case 'isolated-grant':
      if (
        !EXIT_ROLES.has(common.role) ||
        (context.coordinator !== true && context.receiver !== true) ||
        (context.projection !== 'portable-loopback' &&
          context.projection !== 'linux-namespace' &&
          context.projection !== 'dht-mesh') ||
        !fixed(message.grant, 137) ||
        !uint64(message.requestSequence, true) ||
        !fixed(message.tupleDigest, 32)
      )
        invalid()
      if (context.coordinator === true) consumePendingGrant(context.pendingGrant, message)
      break
    case 'store-immutable':
      if (common.role !== 'dht-referral' || !boundedBytes(message.value, 4096, true)) invalid()
      break
    case 'immutable-get':
      if (common.role !== 'endpoint' || !fixed(message.target, 32)) invalid()
      break
    case 'cancel':
      if (common.role !== 'endpoint' || !uint64(message.operationSequence, true)) invalid()
      break
    case 'rotate':
      if (
        common.role !== 'lookup-middle-a' ||
        !uint64(message.nextGeneration, true) ||
        message.nextGeneration <= common.generation
      )
        invalid()
      break
    // Same role restriction as `rotate`, and for the same reason: the fault verbs exist to
    // fault one named hop of the lookup branch. `blackhole` carries no generation, because
    // unlike `rotate` it produces no notification for anything to rotate on.
    case 'blackhole':
      if (common.role !== 'lookup-middle-a') invalid()
      break
    case 'guard-loss':
      if (common.role !== 'guard') invalid()
      break
    case 'phase-ack':
      if (message.acknowledgedPhaseSequence !== common.phaseSequence) invalid()
      consumePhaseGate(context.phaseGate, common, context)
      break
  }
  return message
}

function arrayValues3(value) {
  try {
    if (!Array.isArray(value) || safeProxy(value)) return null
    const keys = reflectOwnKeys(value)
    if (
      keys.length !== 4 ||
      keys.some(
        (key) =>
          typeof key !== 'string' || (key !== '0' && key !== '1' && key !== '2' && key !== 'length')
      )
    )
      return null
    const lengthDescriptor = objectGetOwnPropertyDescriptor(value, 'length')
    if (!lengthDescriptor || !('value' in lengthDescriptor) || lengthDescriptor.value !== 3)
      return null
    const values = []
    for (let index = 0; index < 3; index++) {
      const descriptor = objectGetOwnPropertyDescriptor(value, String(index))
      if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) return null
      values.push(descriptor.value)
    }
    return values
  } catch {
    return null
  }
}

function digestArray(value) {
  const values = arrayValues3(value)
  return values !== null && fixed(values[0], 32) && fixed(values[1], 32) && fixed(values[2], 32)
}

function sequenceArray(value) {
  const values = arrayValues3(value)
  return (
    values !== null &&
    uint64(values[0], true) &&
    uint64(values[1], true) &&
    uint64(values[2], true) &&
    values[0] < values[1] &&
    values[1] < values[2]
  )
}

function validAuditFields(message, close) {
  if (
    ![1, 2, 3, 4, 5].includes(message.class) ||
    !fixed(message.eventMAC, 32) ||
    !uint64(message.openingPhaseSequence, true) ||
    !fixed(message.recordDigest, 32) ||
    !fixed(message.recordNonce, 16) ||
    !uint64(message.recordSequence, true) ||
    !uint16(message.transactionId)
  )
    return false
  if (!close) return true
  return (
    uint64(message.closingPhaseSequence, true) &&
    message.closingPhaseSequence >= message.openingPhaseSequence &&
    [0, 1, 2, 3].includes(message.outcome) &&
    fixed(message.replyDigest, 32)
  )
}

function validateEvent(message, context) {
  const type = ownData(message, 'type')
  let fields = EVENT_FIELDS[type]
  if (type === 'snapshot') {
    const role = ownData(message, 'role')
    if (role === 'dht-value') fields = DHT_VALUE_SNAPSHOT_FIELDS
    else if (role === 'dht-seed') fields = DHT_SEED_SNAPSHOT_FIELDS
    else if (role === 'dht-referral') fields = DHT_REFERRAL_SNAPSHOT_FIELDS
  }
  if (!fields) invalid()
  exactObject(message, fields)
  const common = baseMessage(message, context, 'event')
  switch (type) {
    case 'isolated-grant-request':
      if (
        !EXIT_ROLES.has(common.role) ||
        !uint64(message.requestSequence, true) ||
        !fixed(message.run, 16) ||
        !fixed(message.tupleDigest, 32)
      )
        invalid()
      break
    case 'stored':
      if (
        common.role !== 'dht-referral' ||
        !digestArray(message.setupAuditDigests) ||
        !sequenceArray(message.setupAuditSequences) ||
        !fixed(message.valueDigest, 32)
      )
        invalid()
      break
    case 'phase':
      if (!STATES.has(message.state)) invalid()
      break
    case 'ready':
      // A role that owns no DHT node cannot have had a DHT request answered, so
      // any count but zero from one is a shape fault rather than a small lie.
      if (
        !STATES.has(message.state) ||
        !Number.isSafeInteger(message.answeredRequestCount) ||
        message.answeredRequestCount < 0 ||
        message.answeredRequestCount > 4096 ||
        (!DHT_ROLES.has(common.role) && message.answeredRequestCount !== 0)
      )
        invalid()
      break
    case 'phase-pending':
      if (
        !uint64(message.pendingPhaseSequence, true) ||
        message.pendingPhaseSequence <= common.phaseSequence
      )
        invalid()
      consumePhaseGate(context.phaseGate, common, context)
      break
    case 'audit-open':
    case 'audit-close':
      if (!AUDIT_ROLES.has(common.role) || !validAuditFields(message, type === 'audit-close'))
        invalid()
      break
    case 'value':
      if (
        common.role !== 'endpoint' ||
        !fixed(message.target, 32) ||
        !boundedBytes(message.value, 4096, true)
      )
        invalid()
      break
    case 'cancelled':
      if (common.role !== 'endpoint' || !uint64(message.operationSequence, true)) invalid()
      break
    case 'rotated':
      if (
        common.role !== 'endpoint' ||
        !uint64(message.previousGeneration, true) ||
        message.previousGeneration >= common.generation
      )
        invalid()
      break
    case 'unavailable':
      if (common.role !== 'endpoint' || !UNAVAILABLE_REASONS.has(message.reason)) invalid()
      break
    case 'snapshot':
      if (
        SNAPSHOT_COUNT_FIELDS.some(
          (field) =>
            !Number.isSafeInteger(message[field]) || message[field] < 0 || message[field] > 4096
        ) ||
        typeof message.guardOnly !== 'boolean' ||
        (message.controllerGeneration !== null && !uint64(message.controllerGeneration, true)) ||
        (message.lookupGeneration !== null && !uint64(message.lookupGeneration, true)) ||
        (message.announceGeneration !== null && !uint64(message.announceGeneration, true))
      )
        invalid()
      if (
        !Number.isSafeInteger(message.activeOperations) ||
        message.activeOperations < 0 ||
        message.activeOperations > 4096 ||
        !Number.isSafeInteger(message.openResources) ||
        message.openResources < 0 ||
        message.openResources > 4096 ||
        !Number.isSafeInteger(message.queuedBytes) ||
        message.queuedBytes < 0 ||
        message.queuedBytes > MAX_BUFFERED_BYTES ||
        !STATES.has(message.state) ||
        !fixed(message.summaryDigest, 32)
      )
        invalid()
      if (
        common.role === 'dht-value' &&
        (!Number.isSafeInteger(message.storedValueCount) ||
          message.storedValueCount < 0 ||
          message.storedValueCount > 1 ||
          !fixed(message.storedValueDigest, 32) ||
          (message.storedValueCount === 0 && !zeroBytes(message.storedValueDigest, 32)) ||
          (message.storedValueCount === 1 && zeroBytes(message.storedValueDigest, 32)))
      )
        invalid()
      if (
        common.role === 'dht-referral' &&
        (message.storedValueCount !== 0 || message.transientValueBytes !== 0)
      )
        invalid()
      if (common.role === 'dht-seed' && message.storedValueCount !== 0) invalid()
      break
    case 'error':
      if (
        typeof message.code !== 'string' ||
        !/^(ERR_[A-Z0-9_]{1,60}|PROCESS_[A-Z0-9_]{1,60})$/.test(message.code)
      )
        invalid()
      break
  }
  return message
}

function validateControlMessage(message, context) {
  if (message === null || typeof message !== 'object' || safeProxy(message)) invalid()
  if (context === null || typeof context !== 'object' || safeProxy(context)) invalid()
  if (context.direction === 'command') return validateCommand(message, context)
  if (context.direction === 'event') return validateEvent(message, context)
  invalid()
}

module.exports = Object.freeze({
  COMMANDS,
  COMMAND_FIELDS,
  EVENTS,
  EVENT_FIELDS,
  MAX_BODY_BYTES,
  MAX_BUFFERED_BYTES,
  MAX_STRING_BYTES,
  ROLES,
  TEST_ONLY_CONTROL_AUTHORITY_ISSUER,
  TEST_ONLY_CONTROL_BUFFER_OBSERVER,
  ControlFrameDecoder,
  ProcessProtocolError,
  decodeCanonicalBody,
  decodeControlFrame,
  encodeCanonicalBody,
  encodeControlFrame,
  validateControlMessage
})
