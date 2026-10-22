'use strict'

const b4a = require('b4a')
const sodium = require('sodium-universal')
const { PROCESS_PLANS } = require('./topology-fixture')

let isProxy
try {
  isProxy = require('util').types.isProxy
} catch {
  isProxy = require('bare-utils').types.isProxy
}

const AUDIT_CLASSES = Object.freeze({
  EXIT_VALIDATION_PROBE: 0x01,
  ORDINARY_DHT_REQUEST: 0x02,
  SETUP_STORE_TOKEN: 0x03,
  SETUP_STORE_PUT: 0x04,
  SETUP_STORE_READBACK: 0x05
})
const AUDIT_OUTCOMES = Object.freeze({ SUCCESS: 0, TIMEOUT: 1, CANCELLED: 2, ERROR: 3 })
const AUDIT_PHASES = Object.freeze({
  CAPTURE_START: 0x00,
  DHT_SETUP: 0x01,
  BOOTSTRAPPING: 0x02,
  GUARD_PINNED: 0x03,
  BUILDING: 0x04,
  READY: 0x05,
  ROTATING: 0x06,
  SUSPENDED: 0x07,
  RESUME_BUILDING: 0x08,
  UNAVAILABLE: 0x09,
  TEARDOWN: 0x0a,
  DESTROYED: 0x0b,
  CAPTURE_STOP: 0x0c
})
const CLASS_BYTES = new Set(Object.values(AUDIT_CLASSES))
const OUTCOME_BYTES = new Set(Object.values(AUDIT_OUTCOMES))
const AUDIT_PHASE_BYTES = new Set(Object.values(AUDIT_PHASES))
const SETUP_SEQUENCE = Object.freeze([
  AUDIT_CLASSES.SETUP_STORE_TOKEN,
  AUDIT_CLASSES.SETUP_STORE_PUT,
  AUDIT_CLASSES.SETUP_STORE_READBACK
])
const EXIT_ROLE_INDEXES = new Set([4, 6, 8])
const DHT_ROLE_INDEXES = new Set([9, 10, 11])
const RECORD_DOMAIN = b4a.from('hyperdht-private-routes/test/dht-audit-record/v1')
const EVENT_DOMAIN = b4a.from('hyperdht-private-routes/test/dht-audit-event/v1')
const RECORD_FIELDS = Object.freeze([
  'class',
  'command',
  'destination',
  'generation',
  'nonce',
  'openingPhaseSequence',
  'outboundPayload',
  'recordSequence',
  'source',
  'transactionId'
])
const OPEN_FIELDS = Object.freeze([
  'class',
  'eventMAC',
  'generation',
  'openingPhaseSequence',
  'recordDigest',
  'recordNonce',
  'recordSequence',
  'roleIndex',
  'transactionId'
])
const CLOSE_FIELDS = Object.freeze([
  'class',
  'closingPhaseSequence',
  'eventMAC',
  'generation',
  'openingPhaseSequence',
  'outcome',
  'recordDigest',
  'recordNonce',
  'recordSequence',
  'replyDigest',
  'roleIndex',
  'transactionId'
])
const CLOSE_INPUT_FIELDS = Object.freeze([
  'closingPhaseSequence',
  'outcome',
  'recordNonce',
  'recordSequence',
  'replyPayload'
])
const CAPTURED_REPLY_FIELDS = Object.freeze(['destination', 'payload', 'source', 'transactionId'])
const MAX_U64 = 0xffff_ffff_ffff_ffffn

const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype)
const byteLengthGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get
const bufferSet = Uint8Array.prototype.set
const bufferFill = Uint8Array.prototype.fill
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectGetPrototypeOf = Object.getPrototypeOf
const reflectOwnKeys = Reflect.ownKeys
const AUDIT_CONTEXTS = new WeakMap()

class ProcessAuditError extends Error {
  constructor(code) {
    super(code)
    this.code = code
  }
}

function invalid() {
  throw new ProcessAuditError('PROCESS_AUDIT_INVALID')
}

function replay() {
  throw new ProcessAuditError('PROCESS_AUDIT_REPLAY')
}

function closed() {
  throw new ProcessAuditError('PROCESS_AUDIT_CLOSED')
}

function safeProxy(value) {
  try {
    return isProxy(value)
  } catch {
    return true
  }
}

function length(value) {
  try {
    if (!b4a.isBuffer(value) || safeProxy(value)) return -1
    return byteLengthGetter.call(value)
  } catch {
    return -1
  }
}

function clear(value) {
  try {
    if (length(value) >= 0) bufferFill.call(value, 0)
  } catch {}
}

function copy(value, size = null) {
  const bytes = length(value)
  if (bytes < 0 || (size !== null && bytes !== size)) invalid()
  const output = b4a.allocUnsafeSlow(bytes)
  bufferSet.call(output, value)
  return output
}

function fixed(value, size) {
  return length(value) === size
}

function zeroDigest(value) {
  if (!fixed(value, 32)) return false
  for (let index = 0; index < 32; index++) if (value[index] !== 0) return false
  return true
}

function uint8(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 0xff
}

function uint16(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 0xffff
}

function uint64(value, nonzero = false) {
  return typeof value === 'bigint' && value >= (nonzero ? 1n : 0n) && value <= MAX_U64
}

function exactObject(value, fields) {
  let keys
  try {
    if (
      value === null ||
      typeof value !== 'object' ||
      safeProxy(value) ||
      objectGetPrototypeOf(value) !== Object.prototype
    )
      invalid()
    keys = reflectOwnKeys(value)
  } catch (err) {
    if (err instanceof ProcessAuditError) throw err
    invalid()
  }
  if (keys.length !== fields.length || keys.some((key) => typeof key !== 'string')) invalid()
  const actual = keys.slice().sort()
  const expected = fields.slice().sort()
  for (let index = 0; index < expected.length; index++)
    if (actual[index] !== expected[index]) invalid()
  for (const field of fields) {
    let descriptor
    try {
      descriptor = objectGetOwnPropertyDescriptor(value, field)
    } catch {
      invalid()
    }
    if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) invalid()
  }
}

function tuple(value) {
  const output = copy(value, 19)
  let valid = (output[0] === 4 || output[0] === 6) && (output[17] !== 0 || output[18] !== 0)
  if (output[0] === 4) {
    for (let index = 1; index < 13; index++) if (output[index] !== 0) valid = false
  }
  if (!valid) {
    clear(output)
    invalid()
  }
  return output
}

function writeU16(output, value, offset) {
  output[offset] = value >>> 8
  output[offset + 1] = value
}

function writeU64(output, value, offset) {
  for (let index = offset + 7; index >= offset; index--) {
    output[index] = Number(value & 0xffn)
    value >>= 8n
  }
}

function hash(input, key = null) {
  const output = b4a.allocUnsafeSlow(32)
  try {
    if (key === null) sodium.crypto_generichash(output, input)
    else sodium.crypto_generichash(output, input, key)
    return output
  } catch (err) {
    clear(output)
    invalid()
  }
}

function digestPayload(payload) {
  if (length(payload) < 0 || length(payload) > 65_536) invalid()
  return hash(payload)
}

function validateRecord(value) {
  exactObject(value, RECORD_FIELDS)
  if (
    !CLASS_BYTES.has(value.class) ||
    !uint16(value.command) ||
    !uint64(value.generation) ||
    !fixed(value.nonce, 16) ||
    !uint64(value.openingPhaseSequence, true) ||
    length(value.outboundPayload) < 0 ||
    length(value.outboundPayload) > 65_536 ||
    !uint64(value.recordSequence, true) ||
    !uint16(value.transactionId)
  )
    invalid()
}

function digestAuditRecord(value) {
  validateRecord(value)
  let source = null
  let destination = null
  let payloadDigest = null
  let input = null
  try {
    source = tuple(value.source)
    destination = tuple(value.destination)
    payloadDigest = digestPayload(value.outboundPayload)
    input = b4a.allocUnsafeSlow(
      RECORD_DOMAIN.byteLength + 8 + 16 + 1 + 2 + 8 + 19 + 19 + 2 + 8 + 32
    )
    let offset = 0
    bufferSet.call(input, RECORD_DOMAIN, offset)
    offset += RECORD_DOMAIN.byteLength
    writeU64(input, value.recordSequence, offset)
    offset += 8
    bufferSet.call(input, value.nonce, offset)
    offset += 16
    input[offset++] = value.class
    writeU16(input, value.transactionId, offset)
    offset += 2
    writeU64(input, value.generation, offset)
    offset += 8
    bufferSet.call(input, source, offset)
    offset += 19
    bufferSet.call(input, destination, offset)
    offset += 19
    writeU16(input, value.command, offset)
    offset += 2
    writeU64(input, value.openingPhaseSequence, offset)
    offset += 8
    bufferSet.call(input, payloadDigest, offset)
    return hash(input)
  } finally {
    clear(source)
    clear(destination)
    clear(payloadDigest)
    clear(input)
  }
}

function macInput(fields, discriminator) {
  const close = discriminator === 1
  const input = b4a.allocUnsafeSlow(
    EVENT_DOMAIN.byteLength + 1 + 8 + 16 + 1 + 1 + 2 + 8 + 8 + 8 + 1 + 32 + 32
  )
  let offset = 0
  bufferSet.call(input, EVENT_DOMAIN, offset)
  offset += EVENT_DOMAIN.byteLength
  input[offset++] = discriminator
  writeU64(input, fields.recordSequence, offset)
  offset += 8
  bufferSet.call(input, fields.recordNonce, offset)
  offset += 16
  input[offset++] = fields.roleIndex
  input[offset++] = fields.class
  writeU16(input, fields.transactionId, offset)
  offset += 2
  writeU64(input, fields.generation, offset)
  offset += 8
  writeU64(input, fields.openingPhaseSequence, offset)
  offset += 8
  writeU64(input, close ? fields.closingPhaseSequence : 0n, offset)
  offset += 8
  input[offset++] = close ? fields.outcome : 0xff
  bufferSet.call(input, fields.recordDigest, offset)
  offset += 32
  if (close) bufferSet.call(input, fields.replyDigest, offset)
  else bufferFill.call(input, 0, offset, offset + 32)
  return input
}

function eventMac(fields, discriminator, key) {
  let input = null
  try {
    input = macInput(fields, discriminator)
    return hash(input, key)
  } finally {
    clear(input)
  }
}

// A tuple in wire form from an address a role discovered. Same nineteen bytes the
// derived plans produce, so a record's digest is built the one way.
function statedTuple(value) {
  const output = b4a.allocUnsafeSlow(19)
  bufferFill.call(output, 0)
  if (
    value === null ||
    typeof value !== 'object' ||
    typeof value.host !== 'string' ||
    !uint16(value.port)
  ) {
    clear(output)
    invalid()
  }
  const parts = value.host.split('.')
  if (parts.length !== 4) {
    clear(output)
    invalid()
  }
  output[0] = 4
  for (let index = 0; index < 4; index++) {
    const octet = Number(parts[index])
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) {
      clear(output)
      invalid()
    }
    output[13 + index] = octet
  }
  writeU16(output, value.port, 17)
  return output
}

function projectedTuple(plan, roleIndex) {
  const output = b4a.allocUnsafeSlow(19)
  bufferFill.call(output, 0)
  const port = 42_000 + roleIndex
  output[0] = 4
  if (plan === PROCESS_PLANS.PORTABLE_LOOPBACK) {
    output[13] = 127
    output[14] = 64
    output[15] = roleIndex
    output[16] = 1
  } else if (plan === PROCESS_PLANS.LINUX_NAMESPACE) {
    output[13] = 10
    output[14] = 203
    output[15] = roleIndex
    output[16] = 2
  } else {
    clear(output)
    invalid()
  }
  writeU16(output, port, 17)
  return output
}

function issueAuditContext(value) {
  // Under the discovered plan no address can be derived from a role index, so the
  // two addresses this record binds are stated instead.
  const mesh = value !== null && typeof value === 'object' && value.plan === PROCESS_PLANS.DHT_MESH
  exactObject(
    value,
    mesh
      ? ['destinationRoleIndex', 'destinationTuple', 'phase', 'plan', 'roleIndex', 'sourceTuple']
      : ['destinationRoleIndex', 'phase', 'plan', 'roleIndex']
  )
  if (
    (value.plan !== PROCESS_PLANS.PORTABLE_LOOPBACK &&
      value.plan !== PROCESS_PLANS.LINUX_NAMESPACE &&
      !mesh) ||
    !uint8(value.roleIndex) ||
    !uint8(value.destinationRoleIndex) ||
    !AUDIT_PHASE_BYTES.has(value.phase)
  )
    invalid()
  if (mesh) {
    // Validated now so a bad address fails at issue rather than mid-record.
    clear(statedTuple(value.sourceTuple))
    clear(statedTuple(value.destinationTuple))
  }
  const setup =
    value.roleIndex === 10 &&
    value.destinationRoleIndex === 11 &&
    value.phase === AUDIT_PHASES.DHT_SETUP
  const exit =
    EXIT_ROLE_INDEXES.has(value.roleIndex) &&
    DHT_ROLE_INDEXES.has(value.destinationRoleIndex) &&
    value.phase !== AUDIT_PHASES.DHT_SETUP
  if (!setup && !exit) invalid()
  const capability = Object.freeze({})
  AUDIT_CONTEXTS.set(
    capability,
    Object.freeze({
      destinationRoleIndex: value.destinationRoleIndex,
      ...(mesh
        ? {
            destinationTuple: Object.freeze({
              host: value.destinationTuple.host,
              port: value.destinationTuple.port
            }),
            sourceTuple: Object.freeze({
              host: value.sourceTuple.host,
              port: value.sourceTuple.port
            })
          }
        : {}),
      phase: value.phase,
      plan: value.plan,
      roleIndex: value.roleIndex
    })
  )
  return capability
}

const TEST_ONLY_AUDIT_CONTEXT_ISSUER = Object.freeze({
  context: issueAuditContext
})

function validateOptions(options) {
  exactObject(options, ['context', 'key', 'maximumRecords'])
  if (!fixed(options.key, 32)) invalid()
  if (
    !Number.isSafeInteger(options.maximumRecords) ||
    options.maximumRecords < 1 ||
    options.maximumRecords > 256
  )
    invalid()
  const context = AUDIT_CONTEXTS.get(options.context)
  if (!context) invalid()
  return {
    destination:
      context.plan === PROCESS_PLANS.DHT_MESH
        ? statedTuple(context.destinationTuple)
        : projectedTuple(context.plan, context.destinationRoleIndex),
    destinationRoleIndex: context.destinationRoleIndex,
    phase: context.phase,
    roleIndex: context.roleIndex,
    source:
      context.plan === PROCESS_PLANS.DHT_MESH
        ? statedTuple(context.sourceTuple)
        : projectedTuple(context.plan, context.roleIndex)
  }
}

function nonceKey(value) {
  return b4a.toString(value, 'hex')
}

function validateRecordContext(record, state) {
  if (
    !b4a.equals(record.source, state.source) ||
    !b4a.equals(record.destination, state.destination)
  )
    invalid()
  if (record.class === AUDIT_CLASSES.EXIT_VALIDATION_PROBE) {
    if (
      !EXIT_ROLE_INDEXES.has(state.roleIndex) ||
      !DHT_ROLE_INDEXES.has(state.destinationRoleIndex) ||
      state.phase === AUDIT_PHASES.DHT_SETUP ||
      record.command !== 0
    )
      invalid()
    return false
  }
  if (record.class === AUDIT_CLASSES.ORDINARY_DHT_REQUEST) {
    if (
      !EXIT_ROLE_INDEXES.has(state.roleIndex) ||
      !DHT_ROLE_INDEXES.has(state.destinationRoleIndex) ||
      state.phase === AUDIT_PHASES.DHT_SETUP ||
      record.command === 0
    )
      invalid()
    return false
  }
  const expectedCommand =
    record.class === AUDIT_CLASSES.SETUP_STORE_TOKEN
      ? 9
      : record.class === AUDIT_CLASSES.SETUP_STORE_PUT
        ? 8
        : record.class === AUDIT_CLASSES.SETUP_STORE_READBACK
          ? 9
          : -1
  if (
    state.roleIndex !== 10 ||
    state.destinationRoleIndex !== 11 ||
    state.phase !== AUDIT_PHASES.DHT_SETUP ||
    record.command !== expectedCommand ||
    SETUP_SEQUENCE[state.setupOrdinal] !== record.class
  )
    invalid()
  return true
}

function baseRecord(record, digest, roleIndex) {
  return {
    class: record.class,
    destination: copy(record.destination, 19),
    generation: record.generation,
    openingPhaseSequence: record.openingPhaseSequence,
    recordDigest: copy(digest, 32),
    recordNonce: copy(record.nonce, 16),
    recordSequence: record.recordSequence,
    roleIndex,
    source: copy(record.source, 19),
    transactionId: record.transactionId
  }
}

function clearRecord(record) {
  if (!record) return
  clear(record.destination)
  clear(record.recordDigest)
  clear(record.recordNonce)
  clear(record.source)
}

function openEvent(record, key) {
  const mac = eventMac(record, 0, key)
  return Object.freeze({
    class: record.class,
    eventMAC: mac,
    generation: record.generation,
    openingPhaseSequence: record.openingPhaseSequence,
    recordDigest: copy(record.recordDigest, 32),
    recordNonce: copy(record.recordNonce, 16),
    recordSequence: record.recordSequence,
    roleIndex: record.roleIndex,
    transactionId: record.transactionId
  })
}

function closeEvent(record, closingPhaseSequence, outcome, replyDigest, key) {
  const fields = { ...record, closingPhaseSequence, outcome, replyDigest }
  const mac = eventMac(fields, 1, key)
  return Object.freeze({
    class: record.class,
    closingPhaseSequence,
    eventMAC: mac,
    generation: record.generation,
    openingPhaseSequence: record.openingPhaseSequence,
    outcome,
    recordDigest: copy(record.recordDigest, 32),
    recordNonce: copy(record.recordNonce, 16),
    recordSequence: record.recordSequence,
    replyDigest: copy(replyDigest, 32),
    roleIndex: record.roleIndex,
    transactionId: record.transactionId
  })
}

function createAuditEventStream(options) {
  const context = validateOptions(options)
  const state = {
    closed: false,
    destination: context.destination,
    destinationRoleIndex: context.destinationRoleIndex,
    key: copy(options.key, 32),
    lastSequence: 0n,
    maximumRecords: options.maximumRecords,
    nonceKeys: new Set(),
    open: new Map(),
    phase: context.phase,
    roleIndex: context.roleIndex,
    source: context.source,
    setupOrdinal: 0,
    tombstones: new Set()
  }
  return Object.freeze({
    open(value) {
      if (state.closed) closed()
      validateRecord(value)
      const setup = validateRecordContext(value, state)
      const sequenceKey = value.recordSequence.toString(10)
      const uniqueNonce = nonceKey(value.nonce)
      if (
        value.recordSequence <= state.lastSequence ||
        state.nonceKeys.has(uniqueNonce) ||
        state.open.has(sequenceKey) ||
        state.open.size >= state.maximumRecords
      )
        replay()
      let digest = null
      let stored = null
      try {
        digest = digestAuditRecord(value)
        stored = baseRecord(value, digest, state.roleIndex)
        const event = openEvent(stored, state.key)
        state.lastSequence = value.recordSequence
        state.nonceKeys.add(uniqueNonce)
        state.open.set(sequenceKey, stored)
        if (setup) state.setupOrdinal++
        stored = null
        return event
      } finally {
        clear(digest)
        clearRecord(stored)
      }
    },
    close(value) {
      if (state.closed) closed()
      exactObject(value, CLOSE_INPUT_FIELDS)
      const payloadLength = length(value.replyPayload)
      if (
        !uint64(value.recordSequence, true) ||
        !fixed(value.recordNonce, 16) ||
        !uint64(value.closingPhaseSequence, true) ||
        !OUTCOME_BYTES.has(value.outcome) ||
        payloadLength < 0 ||
        payloadLength > 65_536 ||
        (value.outcome !== AUDIT_OUTCOMES.SUCCESS && payloadLength !== 0)
      )
        invalid()
      const sequenceKey = value.recordSequence.toString(10)
      const current = state.open.get(sequenceKey)
      if (!current) {
        if (state.tombstones.has(sequenceKey)) replay()
        invalid()
      }
      if (
        !b4a.equals(current.recordNonce, value.recordNonce) ||
        value.closingPhaseSequence < current.openingPhaseSequence
      )
        invalid()
      let replyDigest = null
      try {
        replyDigest =
          value.outcome === AUDIT_OUTCOMES.SUCCESS
            ? digestPayload(value.replyPayload)
            : b4a.allocUnsafeSlow(32)
        if (value.outcome !== AUDIT_OUTCOMES.SUCCESS) bufferFill.call(replyDigest, 0)
        const event = closeEvent(
          current,
          value.closingPhaseSequence,
          value.outcome,
          replyDigest,
          state.key
        )
        state.open.delete(sequenceKey)
        state.tombstones.add(sequenceKey)
        clearRecord(current)
        return event
      } finally {
        clear(replyDigest)
      }
    },
    destroy() {
      if (state.closed) return
      state.closed = true
      clear(state.key)
      clear(state.destination)
      for (const record of state.open.values()) clearRecord(record)
      state.open.clear()
      state.nonceKeys.clear()
      state.tombstones.clear()
      clear(state.source)
    }
  })
}

function validateOpenEvent(value) {
  exactObject(value, OPEN_FIELDS)
  if (
    !CLASS_BYTES.has(value.class) ||
    !fixed(value.eventMAC, 32) ||
    !uint64(value.generation) ||
    !uint64(value.openingPhaseSequence, true) ||
    !fixed(value.recordDigest, 32) ||
    !fixed(value.recordNonce, 16) ||
    !uint64(value.recordSequence, true) ||
    !uint8(value.roleIndex) ||
    value.roleIndex < 1 ||
    value.roleIndex > 11 ||
    !uint16(value.transactionId)
  )
    invalid()
}

function validateCloseEvent(value) {
  exactObject(value, CLOSE_FIELDS)
  if (
    !CLASS_BYTES.has(value.class) ||
    !uint64(value.closingPhaseSequence, true) ||
    !fixed(value.eventMAC, 32) ||
    !uint64(value.generation) ||
    !uint64(value.openingPhaseSequence, true) ||
    value.closingPhaseSequence < value.openingPhaseSequence ||
    !OUTCOME_BYTES.has(value.outcome) ||
    !fixed(value.recordDigest, 32) ||
    !fixed(value.recordNonce, 16) ||
    !uint64(value.recordSequence, true) ||
    !fixed(value.replyDigest, 32) ||
    !uint8(value.roleIndex) ||
    value.roleIndex < 1 ||
    value.roleIndex > 11 ||
    !uint16(value.transactionId)
  )
    invalid()
}

function equalFields(event, record, digest, roleIndex) {
  return (
    event.roleIndex === roleIndex &&
    event.class === record.class &&
    event.transactionId === record.transactionId &&
    event.generation === record.generation &&
    event.openingPhaseSequence === record.openingPhaseSequence &&
    event.recordSequence === record.recordSequence &&
    b4a.equals(event.recordNonce, record.nonce) &&
    b4a.equals(event.recordDigest, digest)
  )
}

function createAuditEventVerifier(options) {
  const context = validateOptions(options)
  const state = {
    closed: false,
    destination: context.destination,
    destinationRoleIndex: context.destinationRoleIndex,
    key: copy(options.key, 32),
    lastSequence: 0n,
    maximumRecords: options.maximumRecords,
    nonceKeys: new Set(),
    open: new Map(),
    phase: context.phase,
    roleIndex: context.roleIndex,
    source: context.source,
    setupOrdinal: 0,
    tombstones: new Set()
  }
  return Object.freeze({
    verifyOpen(event, capturedRecord) {
      if (state.closed) closed()
      validateOpenEvent(event)
      validateRecord(capturedRecord)
      const setup = validateRecordContext(capturedRecord, state)
      const sequenceKey = event.recordSequence.toString(10)
      const uniqueNonce = nonceKey(event.recordNonce)
      if (event.recordSequence <= state.lastSequence || state.nonceKeys.has(uniqueNonce)) replay()
      if (state.open.size >= state.maximumRecords) invalid()
      let digest = null
      let expectedMac = null
      let stored = null
      try {
        digest = digestAuditRecord(capturedRecord)
        if (!equalFields(event, capturedRecord, digest, state.roleIndex)) invalid()
        expectedMac = eventMac(event, 0, state.key)
        if (!b4a.equals(expectedMac, event.eventMAC)) invalid()
        stored = baseRecord(capturedRecord, digest, state.roleIndex)
        state.lastSequence = event.recordSequence
        state.nonceKeys.add(uniqueNonce)
        state.open.set(sequenceKey, stored)
        if (setup) state.setupOrdinal++
        stored = null
        return true
      } finally {
        clear(digest)
        clear(expectedMac)
        clearRecord(stored)
      }
    },
    verifyClose(event, capturedReply) {
      if (state.closed) closed()
      validateCloseEvent(event)
      const success = event.outcome === AUDIT_OUTCOMES.SUCCESS
      if (success) {
        exactObject(capturedReply, CAPTURED_REPLY_FIELDS)
        if (
          !uint16(capturedReply.transactionId) ||
          length(capturedReply.payload) < 0 ||
          length(capturedReply.payload) > 65_536
        )
          invalid()
      } else if (capturedReply !== undefined || !zeroDigest(event.replyDigest)) {
        invalid()
      }
      const sequenceKey = event.recordSequence.toString(10)
      const current = state.open.get(sequenceKey)
      if (!current) {
        if (state.tombstones.has(sequenceKey)) replay()
        invalid()
      }
      let source = null
      let destination = null
      let replyDigest = null
      let expectedMac = null
      try {
        if (success) {
          source = tuple(capturedReply.source)
          destination = tuple(capturedReply.destination)
          if (
            !b4a.equals(source, current.destination) ||
            !b4a.equals(destination, current.source) ||
            capturedReply.transactionId !== current.transactionId
          )
            invalid()
          replyDigest = digestPayload(capturedReply.payload)
        } else {
          replyDigest = b4a.allocUnsafeSlow(32)
          bufferFill.call(replyDigest, 0)
        }
        if (
          event.roleIndex !== current.roleIndex ||
          event.class !== current.class ||
          event.transactionId !== current.transactionId ||
          event.generation !== current.generation ||
          event.openingPhaseSequence !== current.openingPhaseSequence ||
          event.recordSequence !== current.recordSequence ||
          !b4a.equals(event.recordNonce, current.recordNonce) ||
          !b4a.equals(event.recordDigest, current.recordDigest) ||
          !b4a.equals(event.replyDigest, replyDigest)
        )
          invalid()
        expectedMac = eventMac(event, 1, state.key)
        if (!b4a.equals(expectedMac, event.eventMAC)) invalid()
        state.open.delete(sequenceKey)
        state.tombstones.add(sequenceKey)
        clearRecord(current)
        return true
      } finally {
        clear(source)
        clear(destination)
        clear(replyDigest)
        clear(expectedMac)
      }
    },
    destroy() {
      if (state.closed) return
      state.closed = true
      clear(state.destination)
      clear(state.key)
      clear(state.source)
      for (const record of state.open.values()) clearRecord(record)
      state.open.clear()
      state.nonceKeys.clear()
      state.tombstones.clear()
    }
  })
}

module.exports = Object.freeze({
  AUDIT_CLASSES,
  AUDIT_OUTCOMES,
  AUDIT_PHASES,
  TEST_ONLY_AUDIT_CONTEXT_ISSUER,
  ProcessAuditError,
  createAuditEventStream,
  createAuditEventVerifier,
  digestAuditRecord,
  digestPayload
})
