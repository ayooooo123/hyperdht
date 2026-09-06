'use strict'

// EXPERIMENTAL — Gate C SURB path helpers.
// Owner-approved wire only. NOT external cryptographic review.
// No anonymity claim.

const b4a = require('b4a')

const { PrivateRouteError } = require('./errors')
const {
  MAX_SURB_BATCH,
  MAX_SURB_REPLY_APPLICATION_BYTES,
  SURB_DESCRIPTOR_SIZE,
  SURB_REPLY_DATA_BYTES,
  buildSurb,
  encodeSurbReplyBinding
} = require('./surb')
const {
  encodeSurbHopCell,
  encodeSurbTerminalCell,
  tryDecodeSurbHopCell,
  tryDecodeSurbTerminalCell
} = require('./surb-batch')
const { fragment, SURB_REPLY_FRAGMENT_PROFILE } = require('./fragments')
const { cryptoSuite } = require('./crypto-suite')

const objectFreeze = Object.freeze
const ROUTE_FRAME_SIZE = 1100

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
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

function hopProjection(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid()
  if (
    !isBuffer(value.id, 32) ||
    !isBuffer(value.routeKey, 32) ||
    typeof value.capabilityEpoch !== 'bigint' ||
    typeof value.issuedAtMs !== 'bigint' ||
    typeof value.expiresAtMs !== 'bigint'
  ) {
    invalid()
  }
  return objectFreeze({
    id: b4a.from(value.id),
    routeKey: b4a.from(value.routeKey),
    capabilityEpoch: value.capabilityEpoch,
    issuedAtMs: value.issuedAtMs,
    expiresAtMs: value.expiresAtMs
  })
}

function copyReturnPath(hops) {
  if (!Array.isArray(hops) || hops.length < 1) invalid()
  return objectFreeze(hops.map(hopProjection))
}

function deriveSurbId(batchId, index) {
  const out = b4a.alloc(16)
  cryptoSuite.hash([batchId, b4a.from([index & 0xff])], out)
  return out
}

// Build one SURB per fragment slot for a required reply batch.
function buildSurbBatch(options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) invalid()
  const hops = copyReturnPath(options.hops)
  const batchId = options.batchId
  const requestId = options.requestId
  const messageId = options.messageId || requestId
  const surbCount = options.surbCount
  const now = options.now
  const randomBytes = options.randomBytes
  if (!isBuffer(batchId, 16) || !isBuffer(requestId, 16) || !isBuffer(messageId, 16)) invalid()
  if (!Number.isSafeInteger(surbCount) || surbCount < 1 || surbCount > MAX_SURB_BATCH) invalid()
  if (typeof now !== 'bigint') invalid()
  if (typeof randomBytes !== 'function') invalid()

  const descriptors = []
  const openAuthorities = []
  const terminalHandles = []
  const replyBindings = []
  const surbIds = []

  for (let i = 0; i < surbCount; i++) {
    const surbId = deriveSurbId(batchId, i)
    const terminalHandle = randomBytes(32)
    if (!isBuffer(terminalHandle, 32)) invalid()
    const replyBinding = encodeSurbReplyBinding({
      surbId,
      batchId,
      requestId,
      messageId,
      fragmentIndex: i,
      fragmentCount: surbCount
    })
    const built = buildSurb({
      hops,
      terminalHandle,
      replyBinding,
      now
    })
    descriptors.push(built.descriptor)
    openAuthorities.push(built.openAuthority)
    terminalHandles.push(b4a.from(terminalHandle))
    replyBindings.push(replyBinding)
    surbIds.push(surbId)
  }

  return objectFreeze({
    batchId: b4a.from(batchId),
    requestId: b4a.from(requestId),
    messageId: b4a.from(messageId),
    surbCount,
    descriptors: objectFreeze(descriptors),
    openAuthorities: objectFreeze(openAuthorities),
    terminalHandles: objectFreeze(terminalHandles),
    replyBindings: objectFreeze(replyBindings),
    surbIds: objectFreeze(surbIds)
  })
}

// Pack a SURB hop/terminal cell into a fixed 1100-byte route frame: magic||u16be(len)||body||pad.
function packSurbRouteFrame(cell) {
  if (!isBuffer(cell) || cell.byteLength < 1 || cell.byteLength > ROUTE_FRAME_SIZE - 2) invalid()
  const frame = b4a.alloc(ROUTE_FRAME_SIZE)
  frame[0] = (cell.byteLength >>> 8) & 0xff
  frame[1] = cell.byteLength & 0xff
  frame.set(cell, 2)
  return frame
}

function unpackSurbRouteFrame(frame) {
  if (!isBuffer(frame, ROUTE_FRAME_SIZE)) return null
  const len = (frame[0] << 8) | frame[1]
  if (len < 1 || len > ROUTE_FRAME_SIZE - 2) return null
  return b4a.from(frame.subarray(2, 2 + len))
}

module.exports = {
  MAX_SURB_BATCH,
  MAX_SURB_REPLY_APPLICATION_BYTES,
  SURB_DESCRIPTOR_SIZE,
  SURB_REPLY_DATA_BYTES,
  ROUTE_FRAME_SIZE,
  hopProjection,
  copyReturnPath,
  deriveSurbId,
  buildSurbBatch,
  packSurbRouteFrame,
  unpackSurbRouteFrame,
  encodeSurbHopCell,
  tryDecodeSurbHopCell,
  encodeSurbTerminalCell,
  tryDecodeSurbTerminalCell
}
