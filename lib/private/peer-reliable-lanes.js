'use strict'

/**
 * PeerReliableLanes — network-authority-free reliable-lane state machine.
 *
 * Pure bounded ARQ (CellCodec/ReplayWindow class). Does not mint route handles,
 * own circuit keys, charge ledgers, or act as purpose/semantic authority.
 * Purpose runtime authenticates class-6 and binds route owner before use.
 *
 * Fixed arena: exactly 157200 bytes. Digests while resident are derived
 * ephemerally from arena bytes; after delivery they live only in fixed 48-byte
 * history rows inside the arena.
 */

const b4a = require('b4a')

const { PrivateRouteError } = require('./errors')
const { PEER_MESSAGE_ID, PEER_PROTOCOL_VERSION, decodePeerObject } = require('./peer-protocol')
const { encodePeerTransport, decodePeerTransport } = require('./peer-transport-wire')
const { hashPeer } = require('./peer-crypto')

const MAX_U64 = 0xffff_ffff_ffff_ffffn
const MAX_U32 = 0xffff_ffff

const LANE_DATA = 0
const LANE_CONTROL = 1
const FLAG_CONTROL = 1

const RTO_MS = 250
const MAX_ATTEMPTS = 8
const OP_DEADLINE_MS = 2000
const ACK_COALESCE_MS = 10

const DATA_SEND_SLOTS = 24
const CTRL_SEND_SLOTS = 8
const SEND_SLOTS = 32

const DATA_REORDER = 64
const CTRL_REORDER = 16
const DATA_HISTORY = 64
const CTRL_HISTORY = 16
const HISTORY_ROWS = 80
const HISTORY_ROW_BYTES = 48
const DATA_READY = 24
const CTRL_READY = 8

const WRAPPER_MAX = 1073
const NESTED_MAX = 1037

const ARENA_SIZE =
  SEND_SLOTS * WRAPPER_MAX +
  DATA_REORDER * WRAPPER_MAX +
  CTRL_REORDER * WRAPPER_MAX +
  HISTORY_ROWS * HISTORY_ROW_BYTES +
  DATA_READY * NESTED_MAX +
  CTRL_READY * NESTED_MAX

const NESTED_DIGEST_DOMAIN = 'hyperdht-private-routes/m3/peer-reliable-nested-digest/v2'
const WRAPPER_DIGEST_DOMAIN = 'hyperdht-private-routes/m3/peer-reliable-wrapper-digest/v2'

const ID = Object.freeze({
  reliablePacket: PEER_MESSAGE_ID.PEER_RELIABLE_PACKET_V2,
  reliableAck: PEER_MESSAGE_ID.PEER_RELIABLE_ACK_V2,
  open: PEER_MESSAGE_ID.PEER_OPEN_V2,
  opened: PEER_MESSAGE_ID.PEER_OPENED_V2,
  handshake: PEER_MESSAGE_ID.PEER_HANDSHAKE_V2,
  data: PEER_MESSAGE_ID.PEER_DATA_V2,
  credit: PEER_MESSAGE_ID.PEER_CREDIT_V2,
  fin: PEER_MESSAGE_ID.PEER_FIN_V2,
  close: PEER_MESSAGE_ID.PEER_CLOSE_V2,
  reset: PEER_MESSAGE_ID.PEER_RESET_V2
})

const CONTROL_NESTED_IDS = new Set([ID.open, ID.opened, ID.credit, ID.fin, ID.close, ID.reset])

const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype)
const bufferByteLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get
const bufferFill = Uint8Array.prototype.fill
const bufferSet = Uint8Array.prototype.set
const bufferSubarray = Uint8Array.prototype.subarray
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectHasOwnProperty = Object.prototype.hasOwnProperty

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function destroyedErr() {
  throw PrivateRouteError.ERR_DESTROYED()
}

function bufferLength(value) {
  try {
    return b4a.isBuffer(value) ? bufferByteLength.call(value) : -1
  } catch {
    return -1
  }
}

function clearBuffer(buf) {
  try {
    if (b4a.isBuffer(buf) && bufferLength(buf) > 0) bufferFill.call(buf, 0)
  } catch {
    /* best-effort */
  }
}

function ownData(target, name) {
  let descriptor
  try {
    descriptor = objectGetOwnPropertyDescriptor(target, name)
  } catch {
    invalid()
  }
  if (descriptor === undefined || !objectHasOwnProperty.call(descriptor, 'value')) invalid()
  return descriptor.value
}

function optionsObject(value) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid()
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
  return value
}

function requireFn(value) {
  if (typeof value !== 'function') invalid()
  return value
}

function requireBigInt(value) {
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) invalid()
  return value
}

function requirePurpose(value) {
  if (value !== 1 && value !== 2 && value !== 3) invalid()
  return value
}

function requireDirection(value) {
  if (value !== 0 && value !== 1) invalid()
  return value
}

function requireRouteId(value) {
  if (bufferLength(value) !== 16) invalid()
  return value
}

function writeU64BE(buf, value, offset) {
  let v = value
  for (let i = offset + 7; i >= offset; i--) {
    buf[i] = Number(v & 0xffn)
    v >>= 8n
  }
}

function readU64BE(buf, offset) {
  let value = 0n
  for (let i = offset; i < offset + 8; i++) value = (value << 8n) | BigInt(buf[i])
  return value
}

function checkedAddU64(a, b) {
  const sum = a + b
  if (sum > MAX_U64) invalid()
  return sum
}

function checkedIncU64(a) {
  if (a === MAX_U64) throw PrivateRouteError.COUNTER_EXHAUSTED()
  return a + 1n
}

function checkedIncU32(a) {
  if (a === MAX_U32) throw PrivateRouteError.COUNTER_EXHAUSTED()
  return (a + 1) >>> 0
}

function digestOf(domain, parts) {
  return hashPeer(domain, parts)
}

function arenaView(arena, offset, length) {
  return bufferSubarray.call(arena, offset, offset + length)
}

function copyInto(dst, src, dstOffset, length) {
  bufferSet.call(dst, bufferSubarray.call(src, 0, length), dstOffset)
}

function buffersEqual(a, b, len) {
  for (let i = 0; i < len; i++) if (a[i] !== b[i]) return false
  return true
}

function ignorePromiseSettlement() {}

function observeNativePromise(value) {
  try {
    if (value === null || (typeof value !== 'object' && typeof value !== 'function')) return
    const then = value.then
    if (typeof then === 'function') {
      then.call(value, ignorePromiseSettlement, ignorePromiseSettlement)
    }
  } catch {
    // The attempt was already spent. Native settlement cannot mutate lane state.
  }
}

function readU16BE(buf, offset) {
  return (buf[offset] << 8) | buf[offset + 1]
}

function readU32BE(buf, offset) {
  return (
    buf[offset] * 0x1000000 + ((buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3])
  )
}

/**
 * Decode reliable-packet outer fields only. Does NOT parse nested stream object.
 * Nested bytes are returned as a view for later validation on new identities only.
 */
function decodeReliableOuter(wire) {
  const len = bufferLength(wire)
  if (len < 8) invalid()
  const version = readU32BE(wire, 0)
  if (version !== PEER_PROTOCOL_VERSION) invalid()
  const messageId = readU16BE(wire, 4)
  const bodyLen = readU16BE(wire, 6)
  if (len !== 8 + bodyLen) invalid()
  if (messageId !== ID.reliablePacket) {
    return { messageId, bodyLen, wire }
  }
  // body: routeId16 | laneSequence u64 | nestedLength u16 | flags u16 | nested
  if (bodyLen < 28) invalid()
  const body = bufferSubarray.call(wire, 8, 8 + bodyLen)
  const nestedLength = readU16BE(body, 24)
  const flags = readU16BE(body, 26)
  if (nestedLength < 1 || nestedLength > NESTED_MAX) invalid()
  if (bodyLen !== 28 + nestedLength) invalid()
  if (flags !== 0 && flags !== FLAG_CONTROL) invalid()
  return {
    messageId,
    routeId: bufferSubarray.call(body, 0, 16),
    laneSequence: readU64BE(body, 16),
    nestedLength,
    flags,
    nested: bufferSubarray.call(body, 28, 28 + nestedLength),
    bodyLen
  }
}

function parseNestedHeader(nestedBytes) {
  if (bufferLength(nestedBytes) < 8) invalid()
  let decoded
  try {
    decoded = decodePeerObject(nestedBytes)
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
  const body = decoded.body
  if (bufferLength(body) < 40) {
    clearBuffer(decoded.body)
    clearBuffer(decoded.authSuffix)
    invalid()
  }
  const streamId = readU64BE(body, 16)
  const streamEpoch = readU32BE(body, 24)
  const direction = body[28]
  const commonFlags = body[29]
  clearBuffer(decoded.authSuffix)
  return {
    messageId: decoded.messageId,
    streamId,
    streamEpoch: streamEpoch >>> 0,
    direction,
    commonFlags,
    body,
    commonRouteId: bufferSubarray.call(body, 0, 16)
  }
}

function classifyOutboundNested(nestedBytes, purpose, localDirection, routeId) {
  let decoded = null
  try {
    // Validate the complete nested schema before reserving a slot or sequence.
    decoded = decodePeerTransport(nestedBytes)
    const common = decoded.fields.common
    if (!common || common.flags !== 0 || !b4a.equals(common.routeId, routeId)) invalid()

    let lane
    let flags
    let isRegistrationControl = false

    if (decoded.messageId === ID.data) {
      lane = LANE_DATA
      flags = 0
      if (common.direction !== localDirection) invalid()
    } else if (CONTROL_NESTED_IDS.has(decoded.messageId)) {
      lane = LANE_CONTROL
      flags = FLAG_CONTROL
      isRegistrationControl = purpose === 3 && common.streamId === 1n
      if (decoded.messageId === ID.opened || decoded.messageId === ID.credit) {
        if (common.direction !== (localDirection ^ 1)) invalid()
      } else if (common.direction !== localDirection) {
        invalid()
      }
    } else if (decoded.messageId === ID.handshake) {
      isRegistrationControl = purpose === 3 && common.streamId === 1n
      if (isRegistrationControl) {
        lane = LANE_CONTROL
        flags = FLAG_CONTROL
      } else {
        lane = LANE_DATA
        flags = 0
      }
      if (common.direction !== localDirection) invalid()
    } else {
      invalid()
    }

    return {
      lane,
      flags,
      streamId: common.streamId,
      streamEpoch: common.streamEpoch,
      isRegistrationControl
    }
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    if (decoded) {
      clearBuffer(decoded.body)
      clearBuffer(decoded.authSuffix)
    }
  }
}

/** Bounded ack membership: O(1). */
function seqIsAcked(cumulative, bitmap, sequence) {
  if (cumulative === MAX_U64) {
    if (sequence > 63n) return false
    return ((bitmap >> sequence) & 1n) !== 0n
  }
  if (sequence <= cumulative) return true
  const off = sequence - (cumulative + 1n)
  if (off < 0n || off > 63n) return false
  return ((bitmap >> off) & 1n) !== 0n
}

function cumulativeAdvanced(previous, next) {
  if (previous === MAX_U64) return next !== MAX_U64
  return next !== MAX_U64 && next > previous
}

/**
 * Prove every cumulative/bitmap bit names an issued sequence ≤ highestIssued.
 * highestIssued === MAX_U64 means none issued.
 */
function assertAckNamesIssued(cumulative, bitmap, highestIssued) {
  const none = highestIssued === MAX_U64
  if (cumulative === MAX_U64) {
    for (let i = 0; i < 64; i++) {
      if (((bitmap >> BigInt(i)) & 1n) === 0n) continue
      const seq = BigInt(i)
      if (none || seq > highestIssued) invalid()
    }
    return
  }
  if (none || cumulative > highestIssued) invalid()
  for (let i = 0; i < 64; i++) {
    if (((bitmap >> BigInt(i)) & 1n) === 0n) continue
    const seq = cumulative + 1n + BigInt(i)
    if (seq > highestIssued) invalid()
  }
}

/**
 * Rebase check without enumerating 0..cumulative.
 * Horizon-bounded loops only (≤64).
 */
function assertAckRebase(oldCum, oldBitmap, newCum, newBitmap, horizon) {
  if (oldCum !== MAX_U64) {
    if (newCum === MAX_U64) invalid()
    if (newCum < oldCum) invalid()
  }

  const newBase = newCum === MAX_U64 ? 0n : newCum + 1n
  const newEnd = newBase + BigInt(horizon)

  // Old cumulative coverage that still lies inside the new horizon must remain acked.
  if (oldCum !== MAX_U64) {
    let start = newBase
    let end = oldCum + 1n
    if (end > newEnd) end = newEnd
    // end-start ≤ horizon
    for (let seq = start; seq < end; seq++) {
      if (!seqIsAcked(newCum, newBitmap, seq)) invalid()
    }
  }

  // Old selective bits still in new horizon must remain acked.
  for (let i = 0; i < 64; i++) {
    if (((oldBitmap >> BigInt(i)) & 1n) === 0n) continue
    const seq = oldCum === MAX_U64 ? BigInt(i) : oldCum + 1n + BigInt(i)
    if (seq >= newBase && seq < newEnd) {
      if (!seqIsAcked(newCum, newBitmap, seq)) invalid()
    }
  }
}

class PeerReliableLanes {
  constructor(options) {
    options = optionsObject(options)

    this._routeId = requireRouteId(ownData(options, 'routeId'))
    this._generation = requireBigInt(ownData(options, 'generation'))
    this._purpose = requirePurpose(ownData(options, 'purpose'))
    this._localDirection = requireDirection(ownData(options, 'localDirection'))
    this._clockIdentity = ownData(options, 'clockIdentity')
    if (
      this._clockIdentity === null ||
      (typeof this._clockIdentity !== 'object' && typeof this._clockIdentity !== 'function')
    ) {
      invalid()
    }
    this._monotonicNow = requireFn(ownData(options, 'monotonicNow'))
    this._schedule = requireFn(ownData(options, 'schedule'))
    this._localDeadline = requireBigInt(ownData(options, 'localDeadline'))

    this._onTransmit = requireFn(ownData(options, 'onTransmit'))
    this._onAdmit = requireFn(ownData(options, 'onAdmit'))
    this._onDeliver = requireFn(ownData(options, 'onDeliver'))
    this._onAcknowledged = requireFn(ownData(options, 'onAcknowledged'))
    this._onConflict = requireFn(ownData(options, 'onConflict'))
    this._onFailure = requireFn(ownData(options, 'onFailure'))
    this._onWritable = requireFn(ownData(options, 'onWritable'))

    if (ARENA_SIZE !== 157200) invalid()
    this._arena = b4a.alloc(ARENA_SIZE)

    this._lifetime = 0
    this._destroyed = false
    this._failureNotified = false

    let o = 0
    this._offSend = o
    o += SEND_SLOTS * WRAPPER_MAX
    this._offDataReorder = o
    o += DATA_REORDER * WRAPPER_MAX
    this._offCtrlReorder = o
    o += CTRL_REORDER * WRAPPER_MAX
    this._offHistory = o
    o += HISTORY_ROWS * HISTORY_ROW_BYTES
    this._offDataReady = o
    o += DATA_READY * NESTED_MAX
    this._offCtrlReady = o
    o += CTRL_READY * NESTED_MAX
    if (o !== ARENA_SIZE) invalid()

    // Sender scalars
    this._sendUsed = new Uint8Array(SEND_SLOTS)
    this._sendLane = new Uint8Array(SEND_SLOTS)
    this._sendLen = new Uint16Array(SEND_SLOTS)
    this._sendSeq = new BigUint64Array(SEND_SLOTS)
    this._sendAttempts = new Uint8Array(SEND_SLOTS)
    this._sendAcked = new Uint8Array(SEND_SLOTS)
    this._sendIsReg = new Uint8Array(SEND_SLOTS)
    this._sendDeadline = new BigUint64Array(SEND_SLOTS)
    this._sendCancel = new Array(SEND_SLOTS).fill(null)
    this._sendBorrows = new Uint8Array(SEND_SLOTS)
    this._sendEpoch = new Uint32Array(SEND_SLOTS)
    this._sendQuarantined = new Uint8Array(SEND_SLOTS)
    this._sendCount = [0, 0]

    this._nextSeq = [0n, 0n]
    this._highestIssued = [MAX_U64, MAX_U64]
    this._remoteCumulative = [MAX_U64, MAX_U64]
    this._remoteBitmap = [0n, 0n]

    this._lastAckSnapshot = 0

    // Receiver
    this._recvCumulative = [MAX_U64, MAX_U64]
    this._reorderUsed = [new Uint8Array(DATA_REORDER), new Uint8Array(CTRL_REORDER)]
    this._reorderLen = [new Uint16Array(DATA_REORDER), new Uint16Array(CTRL_REORDER)]
    this._reorderSeq = [new BigUint64Array(DATA_REORDER), new BigUint64Array(CTRL_REORDER)]
    this._reorderArrivals = [new Uint8Array(DATA_REORDER), new Uint8Array(CTRL_REORDER)]
    this._reorderConflict = [new Uint8Array(DATA_REORDER), new Uint8Array(CTRL_REORDER)]
    this._reorderStreamId = [new BigUint64Array(DATA_REORDER), new BigUint64Array(CTRL_REORDER)]
    this._reorderStreamEpoch = [new Uint32Array(DATA_REORDER), new Uint32Array(CTRL_REORDER)]

    this._readyUsed = [new Uint8Array(DATA_READY), new Uint8Array(CTRL_READY)]
    this._readyLen = [new Uint16Array(DATA_READY), new Uint16Array(CTRL_READY)]
    this._readySeq = [new BigUint64Array(DATA_READY), new BigUint64Array(CTRL_READY)]
    this._readyHead = [0, 0]
    this._readyTail = [0, 0]
    this._readyCount = [0, 0]

    this._histCount = [0, 0]
    this._histBaseSeq = [MAX_U64, MAX_U64]
    this._histStreamId = [new BigUint64Array(DATA_HISTORY), new BigUint64Array(CTRL_HISTORY)]
    this._histStreamEpoch = [new Uint32Array(DATA_HISTORY), new Uint32Array(CTRL_HISTORY)]

    this._ackSnapshotOut = 0
    this._pendingAck = false
    this._ackImmediate = false
    this._ackCancel = null
    // Synchronous encode/onTransmit reentrancy only; never gates on Promise settlement.
    this._ackSending = false

    this._regSlotHeld = this._purpose === 3
    this._regInFlight = false
  }

  /* ---------------- public API ---------------- */

  trySend(canonicalNestedBytes) {
    if (this._destroyed) destroyedErr()
    const nestedLen = bufferLength(canonicalNestedBytes)
    if (nestedLen < 1 || nestedLen > NESTED_MAX) invalid()

    const classified = classifyOutboundNested(
      canonicalNestedBytes,
      this._purpose,
      this._localDirection,
      this._routeId
    )
    const { lane, flags, isRegistrationControl } = classified

    if (!this._canAcceptSend(lane, isRegistrationControl)) return null

    const nextSeq = this._nextSeq[lane]
    if (nextSeq === MAX_U64) {
      this._fail(PrivateRouteError.COUNTER_EXHAUSTED())
      return null
    }
    if (!this._withinSenderHorizon(lane, nextSeq)) return null

    const slot = this._allocSendSlot(lane)
    if (slot < 0) return null

    const sequence = nextSeq
    try {
      this._nextSeq[lane] = checkedIncU64(nextSeq)
    } catch (err) {
      this._fail(err)
      return null
    }
    this._highestIssued[lane] = sequence

    let wrapper
    try {
      wrapper = encodePeerTransport(ID.reliablePacket, {
        routeId: this._routeId,
        laneSequence: sequence,
        nestedLength: nestedLen,
        flags,
        completeNestedObject: canonicalNestedBytes
      })
    } catch (err) {
      this._nextSeq[lane] = sequence // rare: encoding failed after seq assign — close instead
      this._fail(err instanceof PrivateRouteError ? err : PrivateRouteError.INVALID_ROUTE())
      return null
    }

    const wlen = bufferLength(wrapper)
    if (wlen < 1 || wlen > WRAPPER_MAX) {
      clearBuffer(wrapper)
      this._fail(PrivateRouteError.INVALID_ROUTE())
      return null
    }

    const slotBuf = this._sendSlotBuf(slot)
    clearBuffer(slotBuf)
    copyInto(slotBuf, wrapper, 0, wlen)
    clearBuffer(wrapper)

    this._sendEpoch[slot] = (this._sendEpoch[slot] + 1) >>> 0
    this._sendUsed[slot] = 1
    this._sendQuarantined[slot] = 0
    this._sendLane[slot] = lane
    this._sendLen[slot] = wlen
    this._sendSeq[slot] = sequence
    this._sendAttempts[slot] = 0
    this._sendAcked[slot] = 0
    this._sendIsReg[slot] = isRegistrationControl ? 1 : 0
    this._sendCount[lane]++
    if (isRegistrationControl) this._regInFlight = true

    let now
    let startDl
    try {
      now = this._safeNow()
      startDl = checkedAddU64(now, BigInt(OP_DEADLINE_MS))
    } catch (err) {
      this._fail(err instanceof PrivateRouteError ? err : PrivateRouteError.INVALID_ROUTE())
      return null
    }
    this._sendDeadline[slot] = startDl < this._localDeadline ? startDl : this._localDeadline

    this._beginTransmit(slot)
    return { lane, sequence }
  }

  receive(canonicalReliableOrAckBytes) {
    if (this._destroyed) destroyedErr()
    if (bufferLength(canonicalReliableOrAckBytes) < 8) invalid()

    // Peek message id without nested validation.
    let messageId
    try {
      const version = readU32BE(canonicalReliableOrAckBytes, 0)
      if (version !== PEER_PROTOCOL_VERSION) invalid()
      messageId = readU16BE(canonicalReliableOrAckBytes, 4)
    } catch (err) {
      this._fail(err instanceof PrivateRouteError ? err : PrivateRouteError.INVALID_ROUTE())
      return false
    }

    if (messageId === ID.reliableAck) {
      let decoded
      try {
        decoded = decodePeerTransport(canonicalReliableOrAckBytes)
      } catch (err) {
        this._fail(err instanceof PrivateRouteError ? err : PrivateRouteError.INVALID_ROUTE())
        return false
      }
      try {
        return this._receiveAck(decoded)
      } finally {
        if (decoded) {
          clearBuffer(decoded.body)
          clearBuffer(decoded.authSuffix)
        }
      }
    }

    if (messageId === ID.reliablePacket) {
      let outer
      try {
        outer = decodeReliableOuter(canonicalReliableOrAckBytes)
      } catch (err) {
        this._fail(err instanceof PrivateRouteError ? err : PrivateRouteError.INVALID_ROUTE())
        return false
      }
      return this._receivePacketOuter(outer, canonicalReliableOrAckBytes)
    }

    this._fail(PrivateRouteError.INVALID_ROUTE())
    return false
  }
  _receivePacketOuter(outer, rawWire) {
    if (!b4a.equals(outer.routeId, this._routeId)) {
      this._fail(PrivateRouteError.INVALID_ROUTE())
      return false
    }
    const flags = outer.flags
    const lane = flags === FLAG_CONTROL ? LANE_CONTROL : LANE_DATA
    const sequence = outer.laneSequence
    const nested = outer.nested

    // 1) History / older — full-wrapper identity only; no nested parse
    const hist = this._historyLookup(lane, sequence)
    if (hist === 'older') {
      return false // silent ignore, no ACK
    }
    if (hist) {
      const wrapperDigest = digestOf(WRAPPER_DIGEST_DOMAIN, [rawWire])
      try {
        if (!buffersEqual(hist.digest, wrapperDigest, 32)) {
          if (!hist.conflictRecorded) {
            this._historySetConflict(lane, hist.idx)
            this._safeConflict({
              lane,
              sequence,
              streamId: hist.streamId,
              streamEpoch: hist.streamEpoch
            })
          }
          return false
        }
        if (hist.arrivals >= MAX_ATTEMPTS) return false
        this._historySetArrivals(lane, hist.idx, hist.arrivals + 1)
        this._queueAck(true)
        return !this._destroyed
      } finally {
        clearBuffer(wrapperDigest)
      }
    }

    // 2) Resident reorder — full-wrapper compare only; no nested parse
    const idx = this._reorderIndexIfPresent(lane, sequence)
    if (idx >= 0) {
      const slotBuf = this._reorderBuf(lane, idx)
      const slotLen = this._reorderLen[lane][idx]
      const rawLen = bufferLength(rawWire)
      if (rawLen === slotLen && buffersEqual(slotBuf, rawWire, slotLen)) {
        const arrivals = this._reorderArrivals[lane][idx]
        if (arrivals >= MAX_ATTEMPTS) return false
        this._reorderArrivals[lane][idx] = arrivals + 1
        this._queueAck(true)
        return !this._destroyed
      }
      if (!this._reorderConflict[lane][idx]) {
        this._reorderConflict[lane][idx] = 1
        this._safeConflict({
          lane,
          sequence,
          streamId: this._reorderStreamId[lane][idx],
          streamEpoch: this._reorderStreamEpoch[lane][idx]
        })
      }
      return false
    }

    // 3) New identity — horizon then full nested validation
    if (sequence === MAX_U64) {
      this._fail(PrivateRouteError.COUNTER_EXHAUSTED())
      return false
    }
    if (!this._inRecvHorizon(lane, sequence)) {
      this._fail(PrivateRouteError.INVALID_ROUTE())
      return false
    }
    const admittedWithGap = sequence !== this._horizonBase(lane)
    const newIdx = this._reorderIndex(lane, sequence)
    if (newIdx < 0 || this._reorderUsed[lane][newIdx]) {
      this._fail(PrivateRouteError.INVALID_ROUTE())
      return false
    }

    let streamId = 0n
    let streamEpoch = 0
    try {
      // Full nested validation only for new in-horizon identities.
      // decodePeerTransport on the whole wire enforces nested schema + lane flags.
      const fully = decodePeerTransport(rawWire)
      try {
        if (!b4a.equals(fully.fields.routeId, this._routeId)) invalid()
        if (fully.fields.flags !== flags || fully.fields.laneSequence !== sequence) invalid()
        const ni = parseNestedHeader(nested)
        try {
          if (!b4a.equals(ni.commonRouteId, this._routeId)) invalid()
          if (ni.commonFlags !== 0) invalid()
          // Inbound outer travel direction is peer→us = localDirection ^ 1.
          // Ordinary nested common.direction must equal that outer travel direction.
          // OPENED/CREDIT carry the named/saved direction while traveling opposite it,
          // so inbound OPENED/CREDIT common.direction equals localDirection.
          if (ni.messageId === ID.opened || ni.messageId === ID.credit) {
            if (ni.direction !== this._localDirection) invalid()
          } else if (
            ni.messageId === ID.data ||
            ni.messageId === ID.open ||
            ni.messageId === ID.handshake ||
            ni.messageId === ID.fin ||
            ni.messageId === ID.close ||
            ni.messageId === ID.reset
          ) {
            if (ni.direction !== (this._localDirection ^ 1)) invalid()
          } else {
            // Only OPEN/OPENED/HANDSHAKE/DATA/CREDIT/FIN/CLOSE/RESET may nest.
            invalid()
          }
          if (ni.messageId === ID.data && flags !== 0) invalid()
          if (CONTROL_NESTED_IDS.has(ni.messageId) && flags !== FLAG_CONTROL) invalid()
          if (ni.messageId === ID.handshake) {
            const isReg = this._purpose === 3 && ni.streamId === 1n
            if (isReg && flags !== FLAG_CONTROL) invalid()
            if (!isReg && flags !== 0) invalid()
          }
          streamId = ni.streamId
          streamEpoch = ni.streamEpoch
        } finally {
          clearBuffer(ni.body)
        }
      } finally {
        clearBuffer(fully.body)
        clearBuffer(fully.authSuffix)
      }
    } catch {
      this._fail(PrivateRouteError.INVALID_ROUTE())
      return false
    }

    const nestedDigest = digestOf(NESTED_DIGEST_DOMAIN, [nested])
    const wrapperDigest = digestOf(WRAPPER_DIGEST_DOMAIN, [rawWire])
    const meta = { lane, sequence, nestedDigest, wrapperDigest }

    const admissionLifetime = this._lifetime
    let admitted = false
    try {
      admitted = this._onAdmit(meta, nested) === true
    } catch {
      admitted = false
    }
    if (this._destroyed || this._lifetime !== admissionLifetime) {
      clearBuffer(nestedDigest)
      clearBuffer(wrapperDigest)
      return false
    }
    if (!admitted) {
      clearBuffer(nestedDigest)
      clearBuffer(wrapperDigest)
      return false
    }

    const rawLen = bufferLength(rawWire)
    if (rawLen > WRAPPER_MAX) {
      clearBuffer(nestedDigest)
      clearBuffer(wrapperDigest)
      this._fail(PrivateRouteError.INVALID_ROUTE())
      return false
    }
    const rbuf = this._reorderBuf(lane, newIdx)
    clearBuffer(rbuf)
    copyInto(rbuf, rawWire, 0, rawLen)
    this._reorderUsed[lane][newIdx] = 1
    this._reorderLen[lane][newIdx] = rawLen
    this._reorderSeq[lane][newIdx] = sequence
    this._reorderArrivals[lane][newIdx] = 1
    this._reorderConflict[lane][newIdx] = 0
    this._reorderStreamId[lane][newIdx] = streamId
    this._reorderStreamEpoch[lane][newIdx] = streamEpoch

    clearBuffer(nestedDigest)
    clearBuffer(wrapperDigest)

    const promoted = this._promoteContiguous(lane)
    this._queueAck(lane === LANE_CONTROL || admittedWithGap || promoted)
    if (this._destroyed) return false
    if (promoted) this._drainReady(lane)
    return !this._destroyed
  }

  drain() {
    if (this._destroyed) return
    this._drainReady(LANE_DATA)
    this._drainReady(LANE_CONTROL)
  }

  isCumulativelyAcknowledged(lane, sequence) {
    if (lane !== LANE_DATA && lane !== LANE_CONTROL) invalid()
    requireBigInt(sequence)
    if (this._destroyed) return false
    const cum = this._remoteCumulative[lane]
    if (cum === MAX_U64) return false
    return sequence <= cum
  }

  releaseRegistrationControlReservation() {
    if (this._destroyed) destroyedErr()
    if (this._purpose !== 3) invalid()
    if (!this._regSlotHeld) invalid()
    if (this._regInFlight) invalid()
    this._regSlotHeld = false
    this._emitWritable()
  }

  destroy(error) {
    if (this._destroyed) return
    this._destroyed = true
    this._lifetime = (this._lifetime + 1) >>> 0

    this._cancelAckTimer()
    for (let i = 0; i < SEND_SLOTS; i++) this._cancelSendTimer(i)

    if (!this._failureNotified) {
      this._failureNotified = true
      try {
        if (this._onFailure) this._onFailure(error || PrivateRouteError.ERR_DESTROYED())
      } catch {
        /* swallow */
      }
    }

    this._onTransmit = null
    this._onAdmit = null
    this._onDeliver = null
    this._onAcknowledged = null
    this._onConflict = null
    this._onFailure = null
    this._onWritable = null
    this._schedule = null
    this._monotonicNow = null
    this._routeId = null

    if (this._arena) {
      clearBuffer(arenaView(this._arena, this._offDataReorder, DATA_REORDER * WRAPPER_MAX))
      clearBuffer(arenaView(this._arena, this._offCtrlReorder, CTRL_REORDER * WRAPPER_MAX))
      clearBuffer(arenaView(this._arena, this._offHistory, HISTORY_ROWS * HISTORY_ROW_BYTES))
      clearBuffer(arenaView(this._arena, this._offDataReady, DATA_READY * NESTED_MAX))
      clearBuffer(arenaView(this._arena, this._offCtrlReady, CTRL_READY * NESTED_MAX))
    }

    let anyBorrowed = false
    for (let i = 0; i < SEND_SLOTS; i++) {
      if (this._sendBorrows[i] === 0) {
        if (this._arena) clearBuffer(this._sendSlotBuf(i))
      } else {
        anyBorrowed = true
      }
      this._sendUsed[i] = 0
      this._sendLen[i] = 0
      this._sendAttempts[i] = 0
      this._sendAcked[i] = 0
    }

    if (!anyBorrowed) {
      if (this._arena) clearBuffer(this._arena)
      this._arena = null
    }

    this._pendingAck = false
    this._ackImmediate = false
    this._ackSending = false
  }

  /* ---------------- send ---------------- */

  _canAcceptSend(lane, isReg) {
    if (lane === LANE_DATA) return this._sendCount[LANE_DATA] < DATA_SEND_SLOTS
    const used = this._sendCount[LANE_CONTROL]
    if (isReg) {
      if (this._regInFlight) return false
      return used < CTRL_SEND_SLOTS
    }
    if (this._regSlotHeld) {
      let nonReg = 0
      for (let i = DATA_SEND_SLOTS; i < SEND_SLOTS; i++) {
        if (this._sendUsed[i] && !this._sendIsReg[i]) nonReg++
      }
      return nonReg < CTRL_SEND_SLOTS - 1 && used < CTRL_SEND_SLOTS
    }
    return used < CTRL_SEND_SLOTS
  }

  _withinSenderHorizon(lane, sequence) {
    const horizon = lane === LANE_DATA ? DATA_REORDER : CTRL_REORDER
    const cum = this._remoteCumulative[lane]
    const base = cum === MAX_U64 ? 0n : cum + 1n
    return sequence >= base && sequence < base + BigInt(horizon)
  }

  _allocSendSlot(lane) {
    const start = lane === LANE_DATA ? 0 : DATA_SEND_SLOTS
    const end = lane === LANE_DATA ? DATA_SEND_SLOTS : SEND_SLOTS
    for (let i = start; i < end; i++) {
      if (!this._sendUsed[i] && !this._sendQuarantined[i] && this._sendBorrows[i] === 0) return i
    }
    return -1
  }

  _freeSendSlot(slot) {
    this._cancelSendTimer(slot)
    if (!this._sendUsed[slot]) return
    const lane = this._sendLane[slot]
    const wasReg = this._sendIsReg[slot]
    this._sendUsed[slot] = 0
    this._sendCount[lane]--
    if (wasReg) this._regInFlight = false

    if (this._sendBorrows[slot] === 0) {
      this._sendQuarantined[slot] = 0
      this._sendLen[slot] = 0
      this._sendAttempts[slot] = 0
      this._sendAcked[slot] = 0
      this._sendIsReg[slot] = 0
      if (this._arena) clearBuffer(this._sendSlotBuf(slot))
    } else {
      this._sendQuarantined[slot] = 1
    }
  }

  _sendSlotBuf(slot) {
    return arenaView(this._arena, this._offSend + slot * WRAPPER_MAX, WRAPPER_MAX)
  }

  _beginTransmit(slot) {
    if (this._destroyed || !this._sendUsed[slot] || this._sendAcked[slot]) return

    const lifetime = this._lifetime
    const sequence = this._sendSeq[slot]
    const clockIdentity = this._clockIdentity
    const deadline = this._sendDeadline[slot]
    const attempts = this._sendAttempts[slot]
    const epoch = this._sendEpoch[slot]

    if (attempts >= MAX_ATTEMPTS) {
      this._fail(PrivateRouteError.CIRCUIT_LIMIT())
      return
    }
    let now
    try {
      now = this._safeNow()
    } catch (err) {
      this._fail(err instanceof PrivateRouteError ? err : PrivateRouteError.INVALID_ROUTE())
      return
    }
    if (now >= deadline || now >= this._localDeadline) {
      this._fail(PrivateRouteError.CIRCUIT_LIMIT())
      return
    }

    // Spend the attempt and arm its next RTO/deadline check before native transmission.
    const attempt = attempts + 1
    this._sendAttempts[slot] = attempt
    this._armRto(slot, lifetime, sequence, attempt, clockIdentity, deadline)

    if (
      this._destroyed ||
      this._lifetime !== lifetime ||
      this._clockIdentity !== clockIdentity ||
      !this._sendUsed[slot] ||
      this._sendSeq[slot] !== sequence ||
      this._sendDeadline[slot] !== deadline ||
      this._sendAcked[slot] ||
      this._sendAttempts[slot] !== attempt ||
      this._sendEpoch[slot] !== epoch ||
      !this._arena ||
      typeof this._onTransmit !== 'function'
    ) {
      return
    }
    const len = this._sendLen[slot]
    const borrowed = arenaView(this._arena, this._offSend + slot * WRAPPER_MAX, len)

    this._sendBorrows[slot]++
    let settled = false
    const onSettle = () => {
      if (settled) return
      settled = true
      this._onSendBorrowSettled(slot, epoch)
    }
    try {
      const nativePromise = this._onTransmit(borrowed)
      const then = nativePromise == null ? undefined : nativePromise.then
      if (typeof then === 'function') then.call(nativePromise, onSettle, onSettle)
      else onSettle()
    } catch {
      // Attempt already spent; its independently armed RTO remains authoritative.
      onSettle()
    }
  }

  _onSendBorrowSettled(slot, epoch) {
    if (epoch !== this._sendEpoch[slot]) return
    if (this._sendBorrows[slot] > 0) {
      this._sendBorrows[slot]--
    }
    if (this._sendBorrows[slot] === 0) {
      if (this._destroyed) {
        if (this._arena) clearBuffer(this._sendSlotBuf(slot))
        this._checkAllBorrowsClearedOnDestroy()
      } else if (this._sendQuarantined[slot]) {
        this._sendQuarantined[slot] = 0
        this._sendLen[slot] = 0
        this._sendAttempts[slot] = 0
        this._sendAcked[slot] = 0
        this._sendIsReg[slot] = 0
        if (this._arena) clearBuffer(this._sendSlotBuf(slot))
        this._emitWritable()
      }
    }
  }

  _checkAllBorrowsClearedOnDestroy() {
    if (!this._destroyed) return
    for (let i = 0; i < SEND_SLOTS; i++) {
      if (this._sendBorrows[i] > 0) return
    }
    if (this._arena) {
      clearBuffer(this._arena)
      this._arena = null
    }
  }

  _armRto(slot, lifetime, sequence, attempt, clockIdentity, deadline) {
    this._cancelSendTimer(slot)
    if (this._destroyed || this._lifetime !== lifetime) return
    if (!this._sendUsed[slot] || this._sendSeq[slot] !== sequence) return
    if (this._sendAcked[slot]) return
    if (this._sendAttempts[slot] !== attempt) return
    if (typeof this._schedule !== 'function') return

    let now
    try {
      now = this._safeNow()
    } catch (err) {
      this._fail(err instanceof PrivateRouteError ? err : PrivateRouteError.INVALID_ROUTE())
      return
    }
    if (now >= deadline || now >= this._localDeadline) {
      this._fail(PrivateRouteError.CIRCUIT_LIMIT())
      return
    }
    const remaining = deadline - now
    const delayMs = remaining < BigInt(RTO_MS) ? Number(remaining) : RTO_MS

    let cancel
    try {
      cancel = this._schedule(delayMs, () => {
        if (this._destroyed || this._lifetime !== lifetime) return
        if (this._clockIdentity !== clockIdentity) return
        if (!this._sendUsed[slot] || this._sendSeq[slot] !== sequence) return
        if (this._sendDeadline[slot] !== deadline) return
        if (this._sendAcked[slot]) return
        if (this._sendAttempts[slot] !== attempt) return
        let current
        try {
          current = this._safeNow()
        } catch (err) {
          this._fail(err instanceof PrivateRouteError ? err : PrivateRouteError.INVALID_ROUTE())
          return
        }
        if (current >= deadline || current >= this._localDeadline) {
          this._fail(PrivateRouteError.CIRCUIT_LIMIT())
          return
        }
        if (this._sendAttempts[slot] >= MAX_ATTEMPTS) {
          this._fail(PrivateRouteError.CIRCUIT_LIMIT())
          return
        }
        this._beginTransmit(slot)
      })
    } catch {
      this._fail(PrivateRouteError.INVALID_ROUTE())
      return
    }
    if (typeof cancel !== 'function') {
      this._fail(PrivateRouteError.INVALID_ROUTE())
      return
    }
    if (
      this._destroyed ||
      this._lifetime !== lifetime ||
      this._clockIdentity !== clockIdentity ||
      !this._sendUsed[slot] ||
      this._sendSeq[slot] !== sequence ||
      this._sendDeadline[slot] !== deadline ||
      this._sendAcked[slot] ||
      this._sendAttempts[slot] !== attempt
    ) {
      try {
        cancel()
      } catch {
        /* ignore */
      }
      return
    }
    this._sendCancel[slot] = cancel
  }

  _cancelSendTimer(slot) {
    const c = this._sendCancel[slot]
    this._sendCancel[slot] = null
    if (typeof c === 'function') {
      try {
        c()
      } catch {
        /* ignore */
      }
    }
  }

  /* ---------------- receive packet ---------------- */


  _horizonBase(lane) {
    const cum = this._recvCumulative[lane]
    return cum === MAX_U64 ? 0n : cum + 1n
  }

  _inRecvHorizon(lane, sequence) {
    const horizon = lane === LANE_DATA ? DATA_REORDER : CTRL_REORDER
    const base = this._horizonBase(lane)
    return sequence >= base && sequence < base + BigInt(horizon)
  }

  _reorderIndex(lane, sequence) {
    if (!this._inRecvHorizon(lane, sequence)) return -1
    return Number(sequence - this._horizonBase(lane))
  }

  _reorderIndexIfPresent(lane, sequence) {
    const cap = lane === LANE_DATA ? DATA_REORDER : CTRL_REORDER
    for (let i = 0; i < cap; i++) {
      if (this._reorderUsed[lane][i] && this._reorderSeq[lane][i] === sequence) return i
    }
    return -1
  }

  _reorderBuf(lane, idx) {
    const base = lane === LANE_DATA ? this._offDataReorder : this._offCtrlReorder
    return arenaView(this._arena, base + idx * WRAPPER_MAX, WRAPPER_MAX)
  }

  _readyBuf(lane, idx) {
    const base = lane === LANE_DATA ? this._offDataReady : this._offCtrlReady
    return arenaView(this._arena, base + idx * NESTED_MAX, NESTED_MAX)
  }

  _readyCap(lane) {
    return lane === LANE_DATA ? DATA_READY : CTRL_READY
  }

  _promoteContiguous(lane) {
    let promoted = false
    for (;;) {
      const next = this._horizonBase(lane)
      const index = this._reorderIndex(lane, next)
      if (index !== 0 || !this._reorderUsed[lane][0]) break
      if (this._readyCount[lane] >= this._readyCap(lane)) break

      const wlen = this._reorderLen[lane][0]
      const wbuf = this._reorderBuf(lane, 0)

      let nested
      let nestedLen
      let dec
      try {
        dec = decodePeerTransport(bufferSubarray.call(wbuf, 0, wlen))
        nested = dec.fields.completeNestedObject
        nestedLen = bufferLength(nested)
      } catch {
        this._fail(PrivateRouteError.INVALID_ROUTE())
        return promoted
      }

      const ridx = this._readyTail[lane]
      const rbuf = this._readyBuf(lane, ridx)
      clearBuffer(rbuf)
      copyInto(rbuf, nested, 0, nestedLen)
      this._readyUsed[lane][ridx] = 1
      this._readyLen[lane][ridx] = nestedLen
      this._readySeq[lane][ridx] = next
      this._readyTail[lane] = (ridx + 1) % this._readyCap(lane)
      this._readyCount[lane]++

      const wrapperDigest = digestOf(WRAPPER_DIGEST_DOMAIN, [bufferSubarray.call(wbuf, 0, wlen)])
      this._historyRecord(
        lane,
        next,
        wrapperDigest,
        this._reorderArrivals[lane][0],
        this._reorderConflict[lane][0],
        this._reorderStreamId[lane][0],
        this._reorderStreamEpoch[lane][0]
      )
      clearBuffer(wrapperDigest)
      if (dec.body) clearBuffer(dec.body)
      if (dec.authSuffix) clearBuffer(dec.authSuffix)
      clearBuffer(nested)

      this._clearReorderIndex(lane, 0)
      this._shiftReorderLeft(lane)
      this._recvCumulative[lane] = next
      promoted = true
    }
    return promoted
  }

  _clearReorderIndex(lane, idx) {
    this._reorderUsed[lane][idx] = 0
    this._reorderLen[lane][idx] = 0
    this._reorderArrivals[lane][idx] = 0
    this._reorderConflict[lane][idx] = 0
    clearBuffer(this._reorderBuf(lane, idx))
  }

  _shiftReorderLeft(lane) {
    const cap = lane === LANE_DATA ? DATA_REORDER : CTRL_REORDER
    for (let i = 0; i < cap - 1; i++) {
      if (this._reorderUsed[lane][i + 1]) {
        const src = this._reorderBuf(lane, i + 1)
        const dst = this._reorderBuf(lane, i)
        const len = this._reorderLen[lane][i + 1]
        clearBuffer(dst)
        copyInto(dst, src, 0, len)
        this._reorderUsed[lane][i] = 1
        this._reorderLen[lane][i] = len
        this._reorderSeq[lane][i] = this._reorderSeq[lane][i + 1]
        this._reorderArrivals[lane][i] = this._reorderArrivals[lane][i + 1]
        this._reorderConflict[lane][i] = this._reorderConflict[lane][i + 1]
        this._reorderStreamId[lane][i] = this._reorderStreamId[lane][i + 1]
        this._reorderStreamEpoch[lane][i] = this._reorderStreamEpoch[lane][i + 1]
        this._clearReorderIndex(lane, i + 1)
      } else {
        this._clearReorderIndex(lane, i)
      }
    }
    this._clearReorderIndex(lane, cap - 1)
  }

  _drainReady(lane) {
    if (this._destroyed || !this._arena || typeof this._onDeliver !== 'function') return
    const cap = this._readyCap(lane)
    while (!this._destroyed && this._readyCount[lane] > 0) {
      const head = this._readyHead[lane]
      if (!this._readyUsed[lane][head]) break
      const len = this._readyLen[lane][head]
      const seq = this._readySeq[lane][head]
      const nested = this._readyBuf(lane, head)
      const view = bufferSubarray.call(nested, 0, len)

      const hist = this._historyLookup(lane, seq)
      let nestedDigest = null
      let wrapperDigest = null
      const deliveryLifetime = this._lifetime
      try {
        nestedDigest = digestOf(NESTED_DIGEST_DOMAIN, [view])
        wrapperDigest = hist && hist !== 'older' ? b4a.from(hist.digest) : digestOf(WRAPPER_DIGEST_DOMAIN, [view])
        const meta = { lane, sequence: seq, nestedDigest, wrapperDigest }
        let ok = false
        try {
          ok = this._onDeliver(meta, view) === true
        } catch {
          ok = false
        }
        if (!ok) return
      } finally {
        clearBuffer(nestedDigest)
        clearBuffer(wrapperDigest)
      }

      if (this._destroyed || this._lifetime !== deliveryLifetime) return

      this._readyUsed[lane][head] = 0
      this._readyLen[lane][head] = 0
      clearBuffer(nested)
      this._readyHead[lane] = (head + 1) % cap
      this._readyCount[lane]--

      // Local delivery progress consumes no new network-arrival ACK allowance.
      this._promoteContiguous(lane)
    }
  }

  /* ---------------- history ---------------- */

  _historyRowOffset(lane, indexInLane) {
    const base = lane === LANE_DATA ? 0 : DATA_HISTORY
    return this._offHistory + (base + indexInLane) * HISTORY_ROW_BYTES
  }

  _historyRecord(lane, sequence, wrapperDigest32, arrivals, conflict, streamId, streamEpoch) {
    const max = lane === LANE_DATA ? DATA_HISTORY : CTRL_HISTORY
    let count = this._histCount[lane]
    if (this._histBaseSeq[lane] === MAX_U64) {
      this._histBaseSeq[lane] = sequence
      count = 0
    }

    const expected = this._histBaseSeq[lane] + BigInt(count)
    if (count > 0 && sequence !== expected) {
      this._histBaseSeq[lane] = sequence
      count = 0
    }

    if (count >= max) {
      this._histBaseSeq[lane] = this._histBaseSeq[lane] + 1n
      for (let i = 0; i < max - 1; i++) {
        const src = arenaView(this._arena, this._historyRowOffset(lane, i + 1), HISTORY_ROW_BYTES)
        const dst = arenaView(this._arena, this._historyRowOffset(lane, i), HISTORY_ROW_BYTES)
        bufferSet.call(dst, src)
        this._histStreamId[lane][i] = this._histStreamId[lane][i + 1]
        this._histStreamEpoch[lane][i] = this._histStreamEpoch[lane][i + 1]
      }
      count = max - 1
    }

    const row = arenaView(this._arena, this._historyRowOffset(lane, count), HISTORY_ROW_BYTES)
    clearBuffer(row)
    writeU64BE(row, sequence, 0)
    bufferSet.call(row, bufferSubarray.call(wrapperDigest32, 0, 32), 8)
    row[40] = arrivals & 0xff
    row[41] = conflict ? 1 : 0
    this._histStreamId[lane][count] = streamId
    this._histStreamEpoch[lane][count] = streamEpoch >>> 0
    this._histCount[lane] = count + 1
  }

  /**
   * @returns {'older'|null|{digest,arrivals,conflictRecorded,streamId,streamEpoch,idx}}
   */
  _historyLookup(lane, sequence) {
    const count = this._histCount[lane]
    if (count === 0 || this._histBaseSeq[lane] === MAX_U64) return null
    if (sequence < this._histBaseSeq[lane]) return 'older'
    const idx = Number(sequence - this._histBaseSeq[lane])
    if (idx < 0 || idx >= count) return null
    const row = arenaView(this._arena, this._historyRowOffset(lane, idx), HISTORY_ROW_BYTES)
    return {
      digest: bufferSubarray.call(row, 8, 40),
      arrivals: row[40],
      conflictRecorded: row[41] !== 0,
      streamId: this._histStreamId[lane][idx],
      streamEpoch: this._histStreamEpoch[lane][idx],
      idx
    }
  }

  _historySetArrivals(lane, idx, arrivals) {
    const row = arenaView(this._arena, this._historyRowOffset(lane, idx), HISTORY_ROW_BYTES)
    row[40] = arrivals & 0xff
  }

  _historySetConflict(lane, idx) {
    const row = arenaView(this._arena, this._historyRowOffset(lane, idx), HISTORY_ROW_BYTES)
    row[41] = 1
  }

  /* ---------------- ACK receive (atomic both lanes) ---------------- */

  _receiveAck(decoded) {
    const f = decoded.fields
    if (!b4a.equals(f.routeId, this._routeId)) {
      this._fail(PrivateRouteError.INVALID_ROUTE())
      return false
    }
    if (f.generation !== this._generation) {
      this._fail(PrivateRouteError.INVALID_ROUTE())
      return false
    }
    if (f.reservedZero !== 0) {
      this._fail(PrivateRouteError.INVALID_ROUTE())
      return false
    }
    if ((f.controlBitmap >> 16n) !== 0n) {
      this._fail(PrivateRouteError.INVALID_ROUTE())
      return false
    }

    // Sentinel snapshot 0 never enters normal ARQ
    if (f.ackSnapshot === 0) return false
    if (f.ackSnapshot < 1) {
      this._fail(PrivateRouteError.INVALID_ROUTE())
      return false
    }

    if (bufferLength(decoded.body) !== 64) {
      this._fail(PrivateRouteError.INVALID_ROUTE())
      return false
    }

    // Equal snapshot number must be byte-identical; otherwise protocol violation
    if (this._lastAckSnapshot !== 0 && f.ackSnapshot === this._lastAckSnapshot) {
      if (
        f.dataCumulative === this._remoteCumulative[LANE_DATA] &&
        f.dataBitmap === this._remoteBitmap[LANE_DATA] &&
        f.controlCumulative === this._remoteCumulative[LANE_CONTROL] &&
        f.controlBitmap === this._remoteBitmap[LANE_CONTROL]
      ) {
        return true // exact repeat, no release
      }
      this._fail(PrivateRouteError.INVALID_ROUTE())
      return false
    }

    // Stale lower snapshot: no release
    if (this._lastAckSnapshot !== 0 && f.ackSnapshot < this._lastAckSnapshot) {
      return false
    }

    // Validate BOTH lanes fully before mutating either (atomic forged-ACK rejection)
    try {
      assertAckNamesIssued(f.dataCumulative, f.dataBitmap, this._highestIssued[LANE_DATA])
      assertAckNamesIssued(f.controlCumulative, f.controlBitmap, this._highestIssued[LANE_CONTROL])
      assertAckRebase(
        this._remoteCumulative[LANE_DATA],
        this._remoteBitmap[LANE_DATA],
        f.dataCumulative,
        f.dataBitmap,
        DATA_REORDER
      )
      assertAckRebase(
        this._remoteCumulative[LANE_CONTROL],
        this._remoteBitmap[LANE_CONTROL],
        f.controlCumulative,
        f.controlBitmap,
        CTRL_REORDER
      )
    } catch (err) {
      this._fail(err instanceof PrivateRouteError ? err : PrivateRouteError.INVALID_ROUTE())
      return false
    }

    const cumulativeProgress =
      cumulativeAdvanced(this._remoteCumulative[LANE_DATA], f.dataCumulative) ||
      cumulativeAdvanced(this._remoteCumulative[LANE_CONTROL], f.controlCumulative)

    // Commit both lanes atomically
    this._remoteCumulative[LANE_DATA] = f.dataCumulative
    this._remoteBitmap[LANE_DATA] = f.dataBitmap
    this._remoteCumulative[LANE_CONTROL] = f.controlCumulative
    this._remoteBitmap[LANE_CONTROL] = f.controlBitmap

    this._lastAckSnapshot = f.ackSnapshot

    const progressed = this._applySenderAcks()
    if (progressed || cumulativeProgress) this._emitWritable()
    return true
  }

  _applySenderAcks() {
    let progressed = false
    for (let slot = 0; slot < SEND_SLOTS; slot++) {
      if (!this._sendUsed[slot] || this._sendAcked[slot]) continue
      const lane = this._sendLane[slot]
      const seq = this._sendSeq[slot]
      if (!seqIsAcked(this._remoteCumulative[lane], this._remoteBitmap[lane], seq)) continue

      this._sendAcked[slot] = 1
      this._cancelSendTimer(slot)
      const cum = this._remoteCumulative[lane]
      const cumulativeCovered = cum !== MAX_U64 && seq <= cum
      try {
        this._onAcknowledged({ lane, sequence: seq, cumulativeCovered })
      } catch {
        /* ignore */
      }
      this._freeSendSlot(slot)
      progressed = true
    }
    return progressed
  }

  /* ---------------- ACK send ---------------- */

  _queueAck(immediate) {
    if (this._destroyed) return
    if (immediate) this._ackImmediate = true
    this._pendingAck = true
    if (this._ackImmediate) {
      this._cancelAckTimer()
      this._sendAckNow()
      return
    }
    this._armAckTimer(ACK_COALESCE_MS)
  }

  _armAckTimer(delayMs) {
    if (this._destroyed || this._ackCancel) return
    if (typeof this._schedule !== 'function') return
    const lifetime = this._lifetime
    const clockIdentity = this._clockIdentity
    let cancel
    try {
      cancel = this._schedule(delayMs, () => {
        if (this._ackCancel !== cancel) return
        if (this._destroyed || this._lifetime !== lifetime) return
        if (this._clockIdentity !== clockIdentity) return
        this._ackCancel = null
        this._sendAckNow()
      })
    } catch {
      this._fail(PrivateRouteError.INVALID_ROUTE())
      return
    }
    if (typeof cancel !== 'function') {
      this._fail(PrivateRouteError.INVALID_ROUTE())
      return
    }
    if (
      this._destroyed ||
      this._lifetime !== lifetime ||
      this._clockIdentity !== clockIdentity ||
      !this._pendingAck
    ) {
      try {
        cancel()
      } catch {
        /* ignore */
      }
      return
    }
    this._ackCancel = cancel
  }

  _cancelAckTimer() {
    const c = this._ackCancel
    this._ackCancel = null
    if (typeof c === 'function') {
      try {
        c()
      } catch {
        /* ignore */
      }
    }
  }

  _buildLocalBitmap(lane) {
    const cum = this._recvCumulative[lane]
    const horizon = lane === LANE_DATA ? DATA_REORDER : CTRL_REORDER
    let bitmap = 0n
    for (let i = 0; i < horizon; i++) {
      if (!this._reorderUsed[lane][i]) continue
      const seq = this._reorderSeq[lane][i]
      if (cum === MAX_U64) {
        if (seq <= 63n) bitmap |= 1n << seq
      } else if (seq > cum) {
        const off = seq - (cum + 1n)
        if (off >= 0n && off <= 63n) bitmap |= 1n << off
      }
    }
    if (lane === LANE_CONTROL) bitmap &= (1n << 16n) - 1n
    return bitmap
  }

  /** Emit pending ACK snapshots without recursion or native-settlement gating. */
  _sendAckNow() {
    if (this._destroyed || !this._pendingAck) return
    // Reentrant arrivals only set pending; this outer frame drains their coalesced state.
    if (this._ackSending) return

    this._ackSending = true
    try {
      while (this._pendingAck && !this._destroyed) {
        this._pendingAck = false
        this._ackImmediate = false

        let snapshot
        try {
          snapshot = this._ackSnapshotOut === 0 ? 1 : checkedIncU32(this._ackSnapshotOut)
        } catch (err) {
          this._fail(err instanceof PrivateRouteError ? err : PrivateRouteError.COUNTER_EXHAUSTED())
          return
        }

        if (!this._routeId || typeof this._onTransmit !== 'function') return

        let wire = null
        try {
          try {
            wire = encodePeerTransport(ID.reliableAck, {
              routeId: this._routeId,
              generation: this._generation,
              dataCumulative: this._recvCumulative[LANE_DATA],
              dataBitmap: this._buildLocalBitmap(LANE_DATA),
              controlCumulative: this._recvCumulative[LANE_CONTROL],
              controlBitmap: this._buildLocalBitmap(LANE_CONTROL),
              ackSnapshot: snapshot,
              reservedZero: 0
            })
          } catch (err) {
            this._fail(err instanceof PrivateRouteError ? err : PrivateRouteError.INVALID_ROUTE())
            return
          }

          this._ackSnapshotOut = snapshot
          let nativePromise
          try {
            // Caller seals/copies borrowed bytes before returning its native Promise.
            nativePromise = this._onTransmit(wire)
          } catch {
            // This arrival's ACK allowance is spent; ACKs have no retry train.
            continue
          }
          observeNativePromise(nativePromise)
        } finally {
          clearBuffer(wire)
        }
      }
    } finally {
      this._ackSending = false
    }
  }

  /* ---------------- helpers ---------------- */

  _safeNow() {
    let now
    try {
      now = this._monotonicNow()
    } catch {
      invalid()
    }
    if (typeof now !== 'bigint' || now < 0n) invalid()
    return now
  }

  _emitWritable() {
    if (this._destroyed || !this._onWritable) return
    try {
      this._onWritable()
    } catch {
      /* ignore */
    }
  }

  _safeConflict(info) {
    if (this._destroyed || !this._onConflict) return
    try {
      this._onConflict(info)
    } catch {
      /* ignore */
    }
  }

  _fail(err) {
    if (this._destroyed) return
    this.destroy(err instanceof PrivateRouteError ? err : PrivateRouteError.INVALID_ROUTE())
  }
}

module.exports = {
  PeerReliableLanes,
  LANE_DATA,
  LANE_CONTROL,
  FLAG_CONTROL,
  ARENA_SIZE,
  WRAPPER_MAX,
  NESTED_MAX,
  DATA_SEND_SLOTS,
  CTRL_SEND_SLOTS,
  DATA_REORDER,
  CTRL_REORDER,
  DATA_READY,
  CTRL_READY,
  MAX_ATTEMPTS,
  RTO_MS,
  MAX_U64,
  NESTED_DIGEST_DOMAIN,
  WRAPPER_DIGEST_DOMAIN
}
