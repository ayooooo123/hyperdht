'use strict'

// EXPERIMENTAL — Gate C SURB batch reply authority and terminal admission.
// Owner-approved wire integration only. NOT external cryptographic review.
// No anonymity claim. Public required mode stays disabled.
// Puts stay correlated in this slice.

const b4a = require('b4a')
const { cryptoSuite } = require('./crypto-suite')

const { PrivateRouteError } = require('./errors')
const { fragment, SURB_REPLY_FRAGMENT_PROFILE, SURB_REPLY_MAX_DATA_BYTES } = require('./fragments')
const { REPLY_MODE, ROUTED_ERROR } = require('./protocol')
const {
  MAX_SURB_BATCH,
  MAX_SURB_REPLY_APPLICATION_BYTES,
  encodeSurbHopMessage,
  encodeSurbReplyBinding,
  sealSurbReply,
  openSurbReply,
  revokeSurbOpenAuthority
} = require('./surb')

const SURB_HOP_MAGIC = b4a.from('SURB-HOP-V1')
const SURB_TERMINAL_MAGIC = b4a.from('SURB-TERM-V1')
const objectFreeze = Object.freeze
const WeakMapConstructor = WeakMap
const weakMapGet = WeakMap.prototype.get
const weakMapSet = WeakMap.prototype.set
const WeakSetConstructor = WeakSet
const weakSetAdd = WeakSet.prototype.add
const weakSetHas = WeakSet.prototype.has
const MapConstructor = Map

const batchRecords = new WeakMapConstructor()
const spentBatches = new WeakSetConstructor()
const terminalTables = new WeakMapConstructor()

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function destroyed() {
  throw PrivateRouteError.ERR_DESTROYED()
}

function responseTooLarge() {
  const err = PrivateRouteError.INVALID_ROUTE()
  err.routedError = ROUTED_ERROR.RESPONSE_TOO_LARGE
  throw err
}

function clear(buf) {
  try {
    if (b4a.isBuffer(buf)) buf.fill(0)
  } catch {
    // best-effort
  }
}

function isBuffer(value, size) {
  return b4a.isBuffer(value) && (size === undefined || value.byteLength === size)
}

function isUint64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= 0xffff_ffff_ffff_ffffn
}

function encodeSurbHopCell(message) {
  const hop = encodeSurbHopMessage(message)
  const out = b4a.allocUnsafeSlow(SURB_HOP_MAGIC.byteLength + hop.byteLength)
  out.set(SURB_HOP_MAGIC, 0)
  out.set(hop, SURB_HOP_MAGIC.byteLength)
  clear(hop)
  return out
}

function tryDecodeSurbHopCell(payload) {
  if (!isBuffer(payload) || payload.byteLength <= SURB_HOP_MAGIC.byteLength) return null
  for (let i = 0; i < SURB_HOP_MAGIC.byteLength; i++) {
    if (payload[i] !== SURB_HOP_MAGIC[i]) return null
  }
  return b4a.from(payload.subarray(SURB_HOP_MAGIC.byteLength))
}

function encodeSurbTerminalCell(terminalHandle, payload) {
  if (!isBuffer(terminalHandle, 32) || !isBuffer(payload)) invalid()
  const out = b4a.allocUnsafeSlow(SURB_TERMINAL_MAGIC.byteLength + 32 + payload.byteLength)
  out.set(SURB_TERMINAL_MAGIC, 0)
  out.set(terminalHandle, SURB_TERMINAL_MAGIC.byteLength)
  out.set(payload, SURB_TERMINAL_MAGIC.byteLength + 32)
  return out
}

function tryDecodeSurbTerminalCell(payload) {
  if (!isBuffer(payload) || payload.byteLength <= SURB_TERMINAL_MAGIC.byteLength + 32) return null
  for (let i = 0; i < SURB_TERMINAL_MAGIC.byteLength; i++) {
    if (payload[i] !== SURB_TERMINAL_MAGIC[i]) return null
  }
  const offset = SURB_TERMINAL_MAGIC.byteLength
  return objectFreeze({
    terminalHandle: b4a.from(payload.subarray(offset, offset + 32)),
    payload: b4a.from(payload.subarray(offset + 32))
  })
}

function createSurbBatchReplyAuthority(options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) invalid()
  const replyMode = options.replyMode
  const batchId = options.batchId
  const requestId = options.requestId
  const messageId = options.messageId
  const descriptors = options.descriptors
  const sendHopMessage = options.sendHopMessage
  const now = options.now
  const localDeadline = options.localDeadline

  if (replyMode !== REPLY_MODE.SURB_REQUIRED) invalid()
  if (!isBuffer(batchId, 16) || !isBuffer(requestId, 16) || !isBuffer(messageId, 16)) invalid()
  if (
    !Array.isArray(descriptors) ||
    descriptors.length < 1 ||
    descriptors.length > MAX_SURB_BATCH
  ) {
    invalid()
  }
  if (typeof sendHopMessage !== 'function') invalid()
  if (typeof now !== 'function') invalid()
  if (!isUint64(localDeadline)) invalid()

  const ownedDescriptors = new Array(descriptors.length)
  for (let i = 0; i < descriptors.length; i++) {
    const d = descriptors[i]
    if (!d || typeof d !== 'object') invalid()
    ownedDescriptors[i] = objectFreeze({
      firstHop: b4a.from(d.firstHop),
      ephem: b4a.from(d.ephem),
      header: b4a.from(d.header),
      mac: b4a.from(d.mac),
      replyPubKey: b4a.from(d.replyPubKey)
    })
  }

  const authority = objectFreeze({})
  const state = {
    active: true,
    batchId: b4a.from(batchId),
    requestId: b4a.from(requestId),
    messageId: b4a.from(messageId),
    descriptors: ownedDescriptors,
    sendHopMessage,
    now,
    localDeadline,
    surbIdSeed: options.surbIds || null
  }
  weakMapSet.call(batchRecords, authority, state)
  return authority
}

function clearBatchState(state) {
  clear(state.batchId)
  clear(state.requestId)
  clear(state.messageId)
  if (state.descriptors) {
    for (let i = 0; i < state.descriptors.length; i++) {
      const d = state.descriptors[i]
      if (!d) continue
      clear(d.firstHop)
      clear(d.ephem)
      clear(d.header)
      clear(d.mac)
      clear(d.replyPubKey)
    }
  }
  state.descriptors = null
  state.active = false
}

function liveBatch(authority) {
  const state =
    authority !== null && (typeof authority === 'object' || typeof authority === 'function')
      ? weakMapGet.call(batchRecords, authority)
      : undefined
  if (state === undefined || !state.active) {
    if (
      authority !== null &&
      (typeof authority === 'object' || typeof authority === 'function') &&
      weakSetHas.call(spentBatches, authority)
    ) {
      destroyed()
    }
    invalid()
  }
  const current = state.now()
  if (!isUint64(current) || current >= state.localDeadline) {
    batchRecords.delete(authority)
    weakSetAdd.call(spentBatches, authority)
    clearBatchState(state)
    invalid()
  }
  return state
}

function sendSurbBatchFragments(authority, encodedReply) {
  const state = liveBatch(authority)
  if (!isBuffer(encodedReply)) invalid()

  batchRecords.delete(authority)
  weakSetAdd.call(spentBatches, authority)
  state.active = false

  let frames = null
  try {
    if (encodedReply.byteLength > MAX_SURB_REPLY_APPLICATION_BYTES) responseTooLarge()
    const committed = state.descriptors.length
    const maxData = committed * SURB_REPLY_MAX_DATA_BYTES
    if (encodedReply.byteLength > maxData) responseTooLarge()
    let sealedPlain = encodedReply
    let padded = null
    if (encodedReply.byteLength < maxData) {
      padded = b4a.alloc(maxData)
      padded.set(encodedReply)
      sealedPlain = padded
    }
    try {
      frames = fragment(sealedPlain, { profile: SURB_REPLY_FRAGMENT_PROFILE })
    } finally {
      clear(padded)
    }
    if (frames.length !== committed) {
      for (let i = 0; i < frames.length; i++) clear(frames[i])
      invalid()
    }

    const fragmentCount = frames.length
    for (let i = 0; i < fragmentCount; i++) {
      const frame = frames[i]
      const dataLen = frame.byteLength - 20
      if (dataLen > SURB_REPLY_MAX_DATA_BYTES) invalid()

      let surbId = null
      if (state.surbIdSeed && isBuffer(state.surbIdSeed[i], 16)) {
        surbId = b4a.from(state.surbIdSeed[i])
      } else {
        surbId = b4a.alloc(16)
        cryptoSuite.hash([state.batchId, b4a.from([i & 0xff])], surbId)
      }

      let binding = null
      let sealed = null
      let cell = null
      try {
        binding = encodeSurbReplyBinding({
          surbId,
          batchId: state.batchId,
          requestId: state.requestId,
          messageId: state.messageId,
          fragmentIndex: i,
          fragmentCount
        })
        sealed = sealSurbReply({
          descriptor: state.descriptors[i],
          replyBinding: binding,
          plaintext: frame
        })
        cell = encodeSurbHopCell(sealed)
        const ownedCell = b4a.from(cell)
        clear(cell)
        cell = null
        try {
          state.sendHopMessage({
            firstHop: b4a.from(state.descriptors[i].firstHop),
            cell: ownedCell,
            fragmentIndex: i,
            fragmentCount
          })
        } catch (err) {
          clear(ownedCell)
          throw err
        }
      } finally {
        clear(surbId)
        clear(binding)
        if (sealed) {
          clear(sealed.ephem)
          clear(sealed.header)
          clear(sealed.mac)
          clear(sealed.payload)
        }
        clear(cell)
      }
    }
    return true
  } finally {
    if (frames) {
      for (let i = 0; i < frames.length; i++) clear(frames[i])
    }
    clearBatchState(state)
  }
}

function revokeSurbBatchReplyAuthority(authority) {
  const state =
    authority !== null && (typeof authority === 'object' || typeof authority === 'function')
      ? weakMapGet.call(batchRecords, authority)
      : undefined
  if (state === undefined) {
    if (
      authority !== null &&
      (typeof authority === 'object' || typeof authority === 'function') &&
      weakSetHas.call(spentBatches, authority)
    ) {
      return false
    }
    invalid()
  }
  batchRecords.delete(authority)
  weakSetAdd.call(spentBatches, authority)
  clearBatchState(state)
  return true
}

function createSurbTerminalAdmission(options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) invalid()
  const now = options.now
  const localDeadline = options.localDeadline
  if (typeof now !== 'function' || !isUint64(localDeadline)) invalid()
  const table = objectFreeze({})
  const state = {
    active: true,
    now,
    localDeadline,
    byHandle: new MapConstructor()
  }
  weakMapSet.call(terminalTables, table, state)
  return table
}

function registerSurbTerminalHandle(table, options) {
  const state = weakMapGet.call(terminalTables, table)
  if (!state || !state.active) invalid()
  if (options === null || typeof options !== 'object' || Array.isArray(options)) invalid()
  const terminalHandle = options.terminalHandle
  const openAuthority = options.openAuthority
  const replyBinding = options.replyBinding
  const requestId = options.requestId
  const batchId = options.batchId
  if (!isBuffer(terminalHandle, 32) || !isBuffer(requestId, 16) || !isBuffer(batchId, 16)) {
    invalid()
  }
  if (!openAuthority || !isBuffer(replyBinding)) invalid()
  const key = b4a.toString(terminalHandle, 'hex')
  if (state.byHandle.has(key)) invalid()
  state.byHandle.set(
    key,
    objectFreeze({
      openAuthority,
      replyBinding: b4a.from(replyBinding),
      requestId: b4a.from(requestId),
      batchId: b4a.from(batchId),
      terminalHandle: b4a.from(terminalHandle)
    })
  )
  return true
}

function admitSurbTerminalPayload(table, options) {
  const state = weakMapGet.call(terminalTables, table)
  if (!state || !state.active) invalid()
  if (options === null || typeof options !== 'object' || Array.isArray(options)) invalid()
  const terminalHandle = options.terminalHandle
  const payload = options.payload
  if (!isBuffer(terminalHandle, 32) || !isBuffer(payload)) invalid()
  const current = state.now()
  if (!isUint64(current) || current >= state.localDeadline) {
    revokeSurbTerminalAdmission(table)
    invalid()
  }
  const key = b4a.toString(terminalHandle, 'hex')
  const entry = state.byHandle.get(key)
  if (!entry) return null
  state.byHandle.delete(key)
  try {
    return openSurbReply({
      openAuthority: entry.openAuthority,
      replyBinding: entry.replyBinding,
      payload,
      now: current
    })
  } finally {
    clear(entry.replyBinding)
    clear(entry.requestId)
    clear(entry.batchId)
    clear(entry.terminalHandle)
  }
}

function revokeSurbTerminalAdmission(table) {
  const state = weakMapGet.call(terminalTables, table)
  if (!state) return false
  terminalTables.delete(table)
  state.active = false
  for (const entry of state.byHandle.values()) {
    try {
      revokeSurbOpenAuthority(entry.openAuthority)
    } catch {}
    clear(entry.replyBinding)
    clear(entry.requestId)
    clear(entry.batchId)
    clear(entry.terminalHandle)
  }
  state.byHandle.clear()
  return true
}

module.exports = {
  SURB_HOP_MAGIC,
  SURB_TERMINAL_MAGIC,
  MAX_SURB_REPLY_APPLICATION_BYTES,
  createSurbBatchReplyAuthority,
  sendSurbBatchFragments,
  revokeSurbBatchReplyAuthority,
  encodeSurbHopCell,
  tryDecodeSurbHopCell,
  encodeSurbTerminalCell,
  tryDecodeSurbTerminalCell,
  createSurbTerminalAdmission,
  registerSurbTerminalHandle,
  admitSurbTerminalPayload,
  revokeSurbTerminalAdmission
}
