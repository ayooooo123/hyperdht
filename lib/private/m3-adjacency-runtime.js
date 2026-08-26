const b4a = require('b4a')

const { CELL_SIZE, CellCodec } = require('./cell-codec')
const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')
const { MAX_FRAGMENTS } = require('./fragments')
const { destroyTakenM3EstablishedLink, takeM3EstablishedLink } = require('./guard-link')
const { createM3ResponderAdopter } = require('./m3-adjacency-adopter')
const {
  BRANCH_CLASS,
  CELL_CLASS,
  DIRECTION,
  M3_MESSAGE_ID,
  decodeM3Object,
  encodeM3Object
} = require('./protocol')

const DEFAULT_MAX_M3_ADJACENCY_RUNTIMES = 128
const MAX_M3_ADJACENCY_RUNTIMES = 4096
const MAX_TIMER_DELAY = 0x7fff_ffff
const TEST_ONLY_M3_ADJACENCY_OBSERVER = Symbol('test-only-m3-adjacency-observer')

const INITIATOR_CELL_ID_DOMAIN = b4a.from('hyperdht-private-routes/m3/cell-id/initiator/v1')
const RESPONDER_CELL_ID_DOMAIN = b4a.from('hyperdht-private-routes/m3/cell-id/responder/v1')
const BRANCH_DESTROY_BODY_BYTES = 42
const BRANCH_DESTROY_PACKET_BYTES = 8 + BRANCH_DESTROY_BODY_BYTES
const BRANCH_DESTROY_REASON_DOWNSTREAM_PHYSICAL_LOSS = 1
// `record.received` holds OPENED route frames: decrypted plaintext. Residency is
// therefore capped rather than letting a reader that has gone away accumulate route
// payloads.
//
// The cap is MAX_FRAGMENTS, imported rather than written out, and it rests on TWO
// facts of which only the first is visible from this file:
//   1. one reply occupies at most MAX_FRAGMENTS route frames (./fragments), and
//   2. at most one reply is ever in flight on a route transport, enforced by
//      `requestProduction` in ./live-route-authority, which throws ERR_BUSY while
//      `state.operations.size !== 0`.
// BOTH are load-bearing. If that ERR_BUSY guard is ever relaxed to permit concurrent
// operations, a legitimate burst becomes larger than this cap and this pump starts
// discarding fragments a reader was still coming back for. From in here that
// coupling is invisible, so it is written down: a change that looks entirely local,
// eight hundred lines away, breaks this limit.
//
// The cap is on RESIDENCY, not on READING, and conflating the two is what wedged
// this transport. `consumeM3RouteBranchDestroy` is reachable only from the pump
// below, so a pump that stops reading while a frame is queued can never deliver a
// branch loss, and nothing rearms it: the endpoint keeps routing into a dead branch
// until its material expires. The pump therefore reads for as long as the transport
// is live and tests every opened frame for BRANCH_DESTROY before anything else. Only
// a frame that would exceed the cap is discarded, which this cell class already
// permits - a route transport carries CELL_CLASS.DATAGRAM only, whose receive
// counter is a DatagramReplayWindow rather than an OrderedReceiver.
//
// Do NOT key retention on `record.waiters.length`, or on whether a reservation is
// outstanding. A reader legitimately holds no waiter between fragments, while it is
// inside codec.open and pushAuthenticated for the one it just took, so "no waiter"
// occurs routinely in healthy operation and does not distinguish a wanted fragment
// from an orphan. Anything keyed on it drops fragments in the narrowest window there
// is.
//
// Sizing: the live captures of this fault all show queue depth 1. That is NOT
// evidence that bursts do not happen - the old pump halted AT depth 1 and so could
// not observe depth 2. Size this from ./fragments, never from a trace. The price is
// about 1.1KB of resident plaintext before, about 8.8KB at the cap; still a hard
// cap, and not scalable by anything a peer controls.
const ROUTE_FRAME_RESIDENCY_LIMIT = MAX_FRAGMENTS
// Frames one pump cycle processes before it reschedules itself, so that a peer
// feeding an idle transport cannot hold the microtask queue for an unbounded run of
// opens. This bounds WORK per cycle where the cap above bounds PLAINTEXT held; the
// two do different jobs and neither substitutes for the other. It never ends the
// read: the reschedule at the tail of the pump is unconditional, because a budget
// that could stop reading would be the fault this pump was fixed for, with extra
// steps.
const ROUTE_FRAMES_PER_PUMP_CYCLE = 16
const AUTHORITIES = new WeakSet()
const AUTHORITY_STATES = new WeakMap()
const RUNTIMES = new WeakMap()
const DESTROYED_RUNTIMES = new WeakSet()
const MOVED_RUNTIMES = new WeakSet()
const TAILS = new WeakMap()
const SPENT_TAILS = new WeakSet()
const ADOPTED_M3_ADJACENCIES = new WeakMap()
const SPENT_ADOPTED_M3_ADJACENCIES = new WeakSet()
const TAIL_RESPONDER_TOKENS = new WeakMap()
const SPENT_TAIL_RESPONDER_TOKENS = new WeakSet()
const CONSUMED_TAIL_RESPONDER_TOKENS = new WeakMap()
const TAIL_RESPONDER_BINDINGS = new WeakMap()
const M3_TAIL_CONTROL_TRANSPORTS = new WeakMap()
const M3_ROUTE_TRANSPORTS = new WeakMap()
const DESTROYED_M3_ROUTE_TRANSPORTS = new WeakSet()
const M3_ROUTE_RECEIVE_RESERVATIONS = new WeakMap()
const SPENT_M3_ROUTE_RECEIVE_RESERVATIONS = new WeakSet()
const M3_RUNTIME_PHYSICAL_LOSS_REGISTRATIONS = new WeakMap()
const FORWARDING_OWNERS = new WeakMap()
const INSTALL_PLANS = new WeakMap()
const CLAIMED_FORWARDING_FACADES = new WeakSet()
const STAGED_FORWARDING_FACADES = new WeakMap()
const M3_FORWARDING_PUBLICATION_CLAIMS = new WeakMap()
const M3_TAIL_FORWARDING_LEASES = new WeakMap()
const M3_TAIL_FORWARDING_PUBLICATIONS = new WeakMap()
const TAKEN_M3_TAIL_FORWARDING_PUBLICATIONS = new WeakMap()
const M3_RELAY_FORWARDING_STATES = new WeakMap()
const byteLengthGetter = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
const fillIntrinsic = Uint8Array.prototype.fill
const setIntrinsic = Uint8Array.prototype.set
const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const reflectOwnKeys = Reflect.ownKeys

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function unavailable() {
  throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
}

function destroyed() {
  throw PrivateRouteError.ERR_DESTROYED()
}
const M3_RECEIVED_ENVELOPES = new WeakMap()
const M3_RECEIVED_ENVELOPES_BY_OWNER = new WeakMap()

function busy() {
  throw PrivateRouteError.ERR_BUSY()
}

function safeObject(value) {
  try {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
  } catch {
    return false
  }
}
function exactOptions(value) {
  let keys
  try {
    keys = reflectOwnKeys(value)
  } catch {
    invalid()
  }
  for (const key of keys) {
    if (
      key !== 'wallNow' &&
      key !== 'monotonicNow' &&
      key !== 'schedule' &&
      key !== 'cancelScheduled' &&
      key !== 'crypto' &&
      key !== 'maxRuntimes' &&
      key !== TEST_ONLY_M3_ADJACENCY_OBSERVER
    ) {
      invalid()
    }
    const descriptor = getOwnPropertyDescriptor(value, key)
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) invalid()
  }
}

function option(value, key) {
  const descriptor = getOwnPropertyDescriptor(value, key)
  return descriptor ? descriptor.value : undefined
}

function length(value) {
  try {
    return b4a.isBuffer(value) ? byteLengthGetter.call(value) : -1
  } catch {
    return -1
  }
}

function fixed(value, size) {
  return length(value) === size
}

function clear(value) {
  try {
    if (b4a.isBuffer(value)) fillIntrinsic.call(value, 0)
  } catch {
    // Best-effort zeroization only.
  }
}

function copy(value, size) {
  if (!fixed(value, size)) invalid()
  const result = b4a.allocUnsafeSlow(size)
  try {
    setIntrinsic.call(result, value)
    return result
  } catch {
    clear(result)
    invalid()
  }
}

function same(left, right) {
  if (length(left) < 0 || length(left) !== length(right)) return false
  try {
    return b4a.equals(left, right)
  } catch {
    return false
  }
}

function nonzero(value) {
  if (length(value) < 0) return false
  for (let index = 0; index < value.byteLength; index++) {
    if (value[index] !== 0) return true
  }
  return false
}

function u64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= 0xffff_ffff_ffff_ffffn
}

function writeU64(target, value, offset) {
  if (!u64(value)) invalid()
  for (let index = 7; index >= 0; index--) {
    target[offset + index] = Number(value & 0xffn)
    value >>= 8n
  }
}

function readU64(source, offset) {
  let value = 0n
  for (let index = 0; index < 8; index++) {
    value = (value << 8n) | BigInt(source[offset + index])
  }
  return value
}

function sameRange(source, offset, expected) {
  if (length(source) < offset + length(expected)) return false
  for (let index = 0; index < expected.byteLength; index++) {
    if (source[offset + index] !== expected[index]) return false
  }
  return true
}

function encodeBranchDestroy(state) {
  const body = b4a.allocUnsafeSlow(BRANCH_DESTROY_BODY_BYTES)
  try {
    body[0] = state.branchClass
    setIntrinsic.call(body, state.branchId, 1)
    setIntrinsic.call(body, state.circuitId, 17)
    writeU64(body, state.generation, 33)
    body[41] = BRANCH_DESTROY_REASON_DOWNSTREAM_PHYSICAL_LOSS
    return encodeM3Object({
      messageId: M3_MESSAGE_ID.BRANCH_DESTROY_V1,
      body
    })
  } finally {
    clear(body)
  }
}

function isBranchDestroyPayload(payload) {
  return (
    fixed(payload, BRANCH_DESTROY_PACKET_BYTES) &&
    payload[0] === 0 &&
    payload[1] === 0 &&
    payload[2] === 0 &&
    payload[3] === 1 &&
    payload[4] === M3_MESSAGE_ID.BRANCH_DESTROY_V1 >>> 8 &&
    payload[5] === M3_MESSAGE_ID.BRANCH_DESTROY_V1 &&
    payload[6] === 0 &&
    payload[7] === BRANCH_DESTROY_BODY_BYTES
  )
}

function decodeBranchDestroy(payload, state) {
  if (!isBranchDestroyPayload(payload)) return false
  let decoded = null
  try {
    decoded = decodeM3Object(payload)
    const body = decoded.body
    if (
      decoded.messageId !== M3_MESSAGE_ID.BRANCH_DESTROY_V1 ||
      !fixed(body, BRANCH_DESTROY_BODY_BYTES) ||
      !fixed(decoded.authSuffix, 0) ||
      body[0] !== state.branchClass ||
      !sameRange(body, 1, state.branchId) ||
      !sameRange(body, 17, state.circuitId) ||
      readU64(body, 33) !== state.generation ||
      body[41] !== BRANCH_DESTROY_REASON_DOWNSTREAM_PHYSICAL_LOSS
    ) {
      invalid()
    }
    return true
  } finally {
    if (decoded) {
      clear(decoded.body)
      clear(decoded.authSuffix)
    }
  }
}

function nowValue(now) {
  let value
  try {
    value = now()
  } catch {
    unavailable()
  }
  if (typeof value === 'bigint') {
    if (!u64(value)) invalid()
    return value
  }
  if (!Number.isSafeInteger(value) || value < 0) invalid()
  return BigInt(value)
}

function sampleWallNow(owner) {
  const current = nowValue(owner.wallNow)
  if (owner.lastWallNow !== null && current < owner.lastWallNow) unavailable()
  owner.lastWallNow = current
  return current
}

function sampleMonotonicNow(owner) {
  const current = nowValue(owner.monotonicNow)
  if (owner.lastMonotonicNow !== null && current < owner.lastMonotonicNow) unavailable()
  owner.lastMonotonicNow = current
  return current
}

function timerDelay(remaining) {
  return remaining > BigInt(MAX_TIMER_DELAY) ? MAX_TIMER_DELAY : Number(remaining)
}

function projectWireExpiry(owner, wireExpiresAt) {
  const wall = sampleWallNow(owner)
  const monotonic = sampleMonotonicNow(owner)
  const remaining = wireExpiresAt - wall
  if (remaining <= 0n) unavailable()
  const routeLocalDeadline = monotonic + remaining
  if (!u64(routeLocalDeadline) || routeLocalDeadline <= monotonic) unavailable()
  return {
    current: monotonic,
    delay: timerDelay(remaining),
    deadline: Object.freeze({
      wireExpiresAt,
      routeLocalDeadline,
      operationDeadline: routeLocalDeadline,
      clockIdentity: owner.clockIdentity
    })
  }
}
function projectM3TailWireDeadline(deadline, wireExpiresAt) {
  if (
    !safeObject(deadline) ||
    !u64(deadline.wireExpiresAt) ||
    deadline.wireExpiresAt === 0n ||
    !u64(deadline.routeLocalDeadline) ||
    deadline.routeLocalDeadline === 0n ||
    !u64(deadline.operationDeadline) ||
    deadline.operationDeadline === 0n ||
    deadline.operationDeadline > deadline.routeLocalDeadline ||
    !u64(wireExpiresAt) ||
    wireExpiresAt === 0n ||
    wireExpiresAt > deadline.wireExpiresAt
  ) {
    invalid()
  }
  const reduction = deadline.wireExpiresAt - wireExpiresAt
  if (reduction >= deadline.routeLocalDeadline) unavailable()
  const projected = deadline.routeLocalDeadline - reduction
  if (!u64(projected) || projected === 0n) unavailable()
  return projected
}

function bindingKey(peerIdentity, localId) {
  try {
    return `${b4a.toString(peerIdentity, 'hex')}:${b4a.toString(localId, 'hex')}`
  } catch {
    invalid()
  }
}

function reserveBinding(authority, owner, state) {
  if (
    !safeObject(state) ||
    !fixed(state.peerIdentity, 32) ||
    !fixed(state.localId, 16) ||
    !nonzero(state.localId)
  ) {
    invalid()
  }
  const key = bindingKey(state.peerIdentity, state.localId)
  if (owner.reservations.has(key)) throw PrivateRouteError.ERR_REPLAY()
  const reservation = {
    authority,
    key,
    released: false,
    runtimeState: null,
    forwardingOwner: null
  }
  owner.reservations.set(key, reservation)
  return reservation
}

function hashOne(hash, label, completeOfferDigest) {
  const prefix = b4a.allocUnsafeSlow(2)
  prefix[0] = label.byteLength >>> 8
  prefix[1] = label.byteLength
  let output = null
  try {
    output = hash([prefix, label, completeOfferDigest])
    if (!fixed(output, 32)) invalid()
    return copy(output, 32)
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    clear(prefix)
    clear(output)
  }
}
function issueTailResponderToken(owner, tail, tailState, localIdentity) {
  let hashed = null
  let bindingDigest = null
  let bindingIdentity = null
  let tokenDigest = null
  let tokenIdentity = null
  let issued = false
  try {
    if (tailState.initiator !== false || !fixed(tailState.transcript, 290)) invalid()
    hashed = owner.crypto.hash([tailState.transcript])
    if (!fixed(hashed, 32)) invalid()
    bindingDigest = copy(hashed, 32)
    bindingIdentity = copy(localIdentity, 32)
    tokenDigest = copy(bindingDigest, 32)
    tokenIdentity = copy(bindingIdentity, 32)
    const binding = Object.freeze({})
    const token = Object.freeze({})
    const bindingState = {
      transcriptDigest: bindingDigest,
      localIdentity: bindingIdentity,
      initiator: false,
      wireExpiresAt: tailState.deadline.wireExpiresAt,
      deadline: tailState.deadline,
      owner,
      tail,
      token,
      tailState
    }
    const tokenState = {
      binding,
      transcriptDigest: tokenDigest,
      localIdentity: tokenIdentity,
      initiator: false,
      wireExpiresAt: tailState.deadline.wireExpiresAt,
      deadline: tailState.deadline
    }
    TAIL_RESPONDER_BINDINGS.set(binding, bindingState)
    TAIL_RESPONDER_TOKENS.set(token, tokenState)
    tailState.binding = binding
    issued = true
    if (owner.observe) {
      const bindingFields = Object.freeze({
        transcriptDigest: bindingState.transcriptDigest,
        localIdentity: bindingState.localIdentity,
        initiator: bindingState.initiator,
        wireExpiresAt: bindingState.wireExpiresAt,
        deadline: bindingState.deadline
      })
      const tokenFields = Object.freeze({
        transcriptDigest: tokenState.transcriptDigest,
        localIdentity: tokenState.localIdentity,
        initiator: tokenState.initiator,
        wireExpiresAt: tokenState.wireExpiresAt,
        deadline: tokenState.deadline
      })
      const corruptToken = (field) => {
        if (field === 'transcriptDigest') tokenState.transcriptDigest[0] ^= 0xff
        else if (field === 'localIdentity') tokenState.localIdentity[0] ^= 0xff
        else if (field === 'initiator') tokenState.initiator = true
        else if (field === 'wireExpiresAt') tokenState.wireExpiresAt++
        else if (field === 'deadline') tokenState.deadline = null
      }
      try {
        owner.observe(
          Object.freeze({
            type: 'responder-binding',
            binding,
            bindingFields,
            tokenFields,
            corruptToken
          })
        )
      } catch {}
    }
    return token
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    clear(hashed)
    if (!issued) {
      clear(bindingDigest)
      clear(bindingIdentity)
      clear(tokenDigest)
      clear(tokenIdentity)
    }
  }
}

function clearTailResponderTokenState(state) {
  if (!state) return
  clear(state.transcriptDigest)
  clear(state.localIdentity)
  state.transcriptDigest = null
  state.localIdentity = null
  state.binding = null
  state.deadline = null
}

function clearTailState(state) {
  if (!state) return
  clear(state.secret)
  clear(state.transcript)
  state.secret = null
  state.transcript = null
  state.binding = null
  state.lastMonotonic = null
  if (state.transportOwner) releaseM3TailControlTransport(state.transportOwner)
  state.transportOwner = null
  state.used = true
}

function shortenM3TailOperationDeadline(state, operationDeadline) {
  if (!safeObject(state) || !safeObject(state.deadline) || !u64(operationDeadline)) invalid()
  const current = state.deadline
  if (
    !u64(current.wireExpiresAt) ||
    current.wireExpiresAt === 0n ||
    !u64(current.routeLocalDeadline) ||
    current.routeLocalDeadline === 0n ||
    !u64(current.operationDeadline) ||
    current.operationDeadline === 0n ||
    current.operationDeadline > current.routeLocalDeadline ||
    operationDeadline === 0n ||
    operationDeadline > current.operationDeadline
  ) {
    invalid()
  }
  if (operationDeadline === current.operationDeadline) return current
  state.deadline = Object.freeze({
    wireExpiresAt: current.wireExpiresAt,
    routeLocalDeadline: current.routeLocalDeadline,
    operationDeadline,
    clockIdentity: current.clockIdentity
  })
  const transport = state.transportOwner
    ? M3_TAIL_CONTROL_TRANSPORTS.get(state.transportOwner)
    : null
  if (transport) transport.deadline = state.deadline
  return state.deadline
}

function tailControlTransportRuntimeState(owner) {
  const record = safeObject(owner) ? M3_TAIL_CONTROL_TRANSPORTS.get(owner) : null
  if (!record) invalid()
  const state = RUNTIMES.get(record.runtime)
  if (!state || state !== record.runtimeState || state.cleared || state.installing) invalid()
  checkRuntimeTime(state)
  return state
}

function sendM3TailControl(owner, envelope) {
  const state = tailControlTransportRuntimeState(owner)
  if (!fixed(envelope, 1101)) invalid()
  const channel = state.physicalChannel
  if (!safeObject(channel) || typeof channel.send !== 'function') invalid()
  let packet = null
  try {
    packet = state.runtime.sealTail({
      class: CELL_CLASS.CONTROL,
      payload: envelope
    })
    return Promise.resolve(channel.send(packet))
  } catch (err) {
    clear(packet)
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function registerM3ReceivedEnvelope(owner, state, envelope) {
  M3_RECEIVED_ENVELOPES.set(envelope, {
    owner,
    runtime: state.runtime,
    runtimeState: state,
    spent: false
  })
  let envelopes = M3_RECEIVED_ENVELOPES_BY_OWNER.get(owner)
  if (!envelopes) {
    envelopes = new Set()
    M3_RECEIVED_ENVELOPES_BY_OWNER.set(owner, envelopes)
  }
  envelopes.add(envelope)
}

function removeM3TailControlWaiter(record, waiter) {
  if (!Array.isArray(record.waiters)) return
  const index = record.waiters.indexOf(waiter)
  if (index !== -1) record.waiters.splice(index, 1)
}

function shiftM3TailControlWaiter(record) {
  if (!Array.isArray(record.waiters)) return null
  while (record.waiters.length > 0) {
    const waiter = record.waiters.shift()
    if (waiter && !waiter.settled) return waiter
  }
  return null
}

function dispatchM3TailControlEnvelope(owner, state, record, envelope) {
  if (tailControlTransportRuntimeState(owner) !== state) invalid()
  const waiter = shiftM3TailControlWaiter(record)
  if (!waiter) {
    record.received.push(envelope)
    return true
  }
  registerM3ReceivedEnvelope(owner, state, envelope)
  waiter.settled = true
  waiter.resolve(envelope)
  return true
}

function rejectM3TailControlWaiters(record, err) {
  if (!Array.isArray(record.waiters)) return
  const waiters = record.waiters.splice(0)
  const reason = err || PrivateRouteError.ERR_DESTROYED()
  for (const waiter of waiters) {
    if (waiter.settled) continue
    waiter.settled = true
    try {
      waiter.reject(reason)
    } catch {}
  }
}

function pumpM3TailControl(owner, state, record, channel) {
  if (record.pumping) return
  record.pumping = true
  Promise.resolve()
    .then(function receiveNextPacket() {
      if (tailControlTransportRuntimeState(owner) !== state) invalid()
      if (!Array.isArray(record.waiters) || record.waiters.length === 0) return null
      return Promise.resolve()
        .then(() => channel.receive())
        .then((packet) => {
          let opened = null
          try {
            if (tailControlTransportRuntimeState(owner) !== state) invalid()
            opened = state.runtime.openTail(packet)
            if (!Array.isArray(opened)) invalid()
            for (const value of opened) {
              if (!fixed(value, 1101)) invalid()
            }
            if (opened.length === 0) return receiveNextPacket()
            if (tailControlTransportRuntimeState(owner) !== state) invalid()
            for (let i = 0; i < opened.length; i++) {
              const envelope = opened[i]
              opened[i] = null
              try {
                dispatchM3TailControlEnvelope(owner, state, record, envelope)
              } catch (err) {
                clear(envelope)
                throw err
              }
            }
            return receiveNextPacket()
          } finally {
            if (opened) {
              for (const envelope of opened) clear(envelope)
            }
            let released = false
            try {
              const { releaseM3CellLinkPacket } = require('./udx-cell-endpoint')
              released = releaseM3CellLinkPacket(packet)
            } catch {}
            if (!released) clear(packet)
          }
        })
    })
    .then(
      () => {
        record.pumping = false
        if (
          M3_TAIL_CONTROL_TRANSPORTS.get(owner) === record &&
          Array.isArray(record.waiters) &&
          record.waiters.length > 0
        ) {
          pumpM3TailControl(owner, state, record, channel)
        }
      },
      (err) => {
        record.pumping = false
        rejectM3TailControlWaiters(record, err)
      }
    )
}

function receiveM3TailControl(owner) {
  const state = tailControlTransportRuntimeState(owner)
  const record = M3_TAIL_CONTROL_TRANSPORTS.get(owner)
  if (!record || record.runtimeState !== state) invalid()
  const channel = state.physicalChannel
  if (!safeObject(channel) || typeof channel.receive !== 'function') invalid()
  const queued = record.received
  if (!Array.isArray(queued) || !Array.isArray(record.waiters)) invalid()
  if (queued.length > 0) {
    const envelope = queued.shift()
    if (!fixed(envelope, 1101)) invalid()
    registerM3ReceivedEnvelope(owner, state, envelope)
    return Promise.resolve(envelope)
  }
  const waiter = {
    settled: false,
    resolve: null,
    reject: null
  }
  const result = new Promise((resolve, reject) => {
    waiter.resolve = resolve
    waiter.reject = reject
    record.waiters.push(waiter)
  })
  pumpM3TailControl(owner, state, record, channel)
  return result
}

function takeM3ReceivedEnvelope(owner, envelope) {
  const state = tailControlTransportRuntimeState(owner)
  const record = safeObject(envelope) ? M3_RECEIVED_ENVELOPES.get(envelope) : null
  if (
    !record ||
    record.spent ||
    record.owner !== owner ||
    record.runtime !== state.runtime ||
    record.runtimeState !== state
  ) {
    invalid()
  }
  record.spent = true
  return envelope
}

function releaseM3ReceivedEnvelope(owner, envelope) {
  const record = safeObject(envelope) ? M3_RECEIVED_ENVELOPES.get(envelope) : null
  if (!record || record.owner !== owner) return false
  M3_RECEIVED_ENVELOPES.delete(envelope)
  const envelopes = M3_RECEIVED_ENVELOPES_BY_OWNER.get(owner)
  if (envelopes) {
    envelopes.delete(envelope)
    if (envelopes.size === 0) M3_RECEIVED_ENVELOPES_BY_OWNER.delete(owner)
  }
  clear(envelope)
  record.owner = null
  record.runtime = null
  record.runtimeState = null
  record.spent = true
  return true
}

function releaseM3TailControlTransport(owner) {
  const record = safeObject(owner) ? M3_TAIL_CONTROL_TRANSPORTS.get(owner) : null
  if (!record) return false
  M3_TAIL_CONTROL_TRANSPORTS.delete(owner)
  rejectM3TailControlWaiters(record)
  const envelopes = M3_RECEIVED_ENVELOPES_BY_OWNER.get(owner)
  if (envelopes) {
    M3_RECEIVED_ENVELOPES_BY_OWNER.delete(owner)
    for (const envelope of envelopes) {
      const received = M3_RECEIVED_ENVELOPES.get(envelope)
      if (received && received.owner === owner) {
        M3_RECEIVED_ENVELOPES.delete(envelope)
        clear(envelope)
        received.owner = null
        received.runtime = null
        received.runtimeState = null
        received.spent = true
      }
    }
    envelopes.clear()
  }
  if (Array.isArray(record.received)) {
    for (const envelope of record.received) clear(envelope)
    record.received.length = 0
  }
  record.runtime = null
  record.runtimeState = null
  return true
}

function takeM3RouteTransport(owner) {
  const tail = safeObject(owner) ? M3_TAIL_CONTROL_TRANSPORTS.get(owner) : null
  if (
    !tail ||
    !Array.isArray(tail.waiters) ||
    tail.waiters.length !== 0 ||
    !Array.isArray(tail.received) ||
    tail.received.length !== 0
  ) {
    invalid()
  }
  const state = RUNTIMES.get(tail.runtime)
  if (!state || state !== tail.runtimeState || state.cleared || state.installing) invalid()
  checkRuntimeTime(state)
  M3_TAIL_CONTROL_TRANSPORTS.delete(owner)
  tail.runtime = null
  tail.runtimeState = null
  const transport = Object.freeze({})
  M3_ROUTE_TRANSPORTS.set(transport, {
    active: true,
    runtime: state.runtime,
    runtimeState: state,
    received: [],
    waiters: [],
    pumping: false,
    droppedFrames: 0,
    branchDestroyConsumed: false
  })
  pumpM3RouteTransport(transport, M3_ROUTE_TRANSPORTS.get(transport))
  return transport
}

function routeTransportState(transport) {
  const record = safeObject(transport) ? M3_ROUTE_TRANSPORTS.get(transport) : null
  if (!record || !record.active) destroyed()
  const state = RUNTIMES.get(record.runtime)
  if (!state || state !== record.runtimeState || state.cleared || state.installing) destroyed()
  checkRuntimeTime(state)
  return record
}

function releaseM3RoutePacket(packet) {
  let released = false
  try {
    const { releaseM3CellLinkPacket } = require('./udx-cell-endpoint')
    released = releaseM3CellLinkPacket(packet)
  } catch {}
  if (!released) clear(packet)
}

function sendM3RouteFrame(transport, frame) {
  const record = routeTransportState(transport)
  if (!fixed(frame, 1100)) invalid()
  const state = record.runtimeState
  const channel = state.physicalChannel
  if (!safeObject(channel) || typeof channel.send !== 'function') invalid()
  let packet = null
  try {
    packet = state.runtime.sealTail({
      class: CELL_CLASS.DATAGRAM,
      payload: frame
    })
    const result = channel.send(packet)
    packet = null
    return Promise.resolve(result)
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    clear(packet)
  }
}

// A route transport's own adjacency authority already owns the only injected scheduler on
// this path, so an endpoint-side operation deadline is armed here rather than against a
// global timer: it is then driven by the same clock that governs the transport, and a test
// that fakes that clock fakes this too.
function scheduleM3RouteTransportTimer(transport, delayMs, callback) {
  const record = routeTransportState(transport)
  const owner = AUTHORITY_STATES.get(record.runtimeState.authority)
  if (!owner || typeof callback !== 'function') invalid()
  if (typeof delayMs !== 'number' || !Number.isFinite(delayMs)) invalid()
  const boundedDelay = Math.min(Math.max(delayMs, 0), MAX_TIMER_DELAY)
  let live = true
  let handle = null
  const onExpiry = () => {
    if (!live) return
    live = false
    handle = null
    callback()
  }
  try {
    handle = owner.schedule(onExpiry, boundedDelay)
  } catch {
    live = false
    unavailable()
  }
  if (live && (handle === null || handle === undefined)) {
    live = false
    unavailable()
  }
  return () => {
    if (!live) return false
    live = false
    const armed = handle
    handle = null
    try {
      owner.cancelScheduled(armed)
    } catch {}
    return true
  }
}

function finishM3RouteReceiveReservation(state) {
  if (!state || !state.observed || !state.settled) return
  M3_ROUTE_RECEIVE_RESERVATIONS.delete(state.reservation)
  SPENT_M3_ROUTE_RECEIVE_RESERVATIONS.add(state.reservation)
}

function settleM3RouteWaiter(waiter, method, value) {
  if (!waiter || waiter.settled) return false
  waiter.settled = true
  const reservationState = waiter.reservationState
  if (reservationState) {
    reservationState.settled = true
    finishM3RouteReceiveReservation(reservationState)
  }
  try {
    waiter[method](value)
  } catch {}
  return true
}

function removeM3RouteWaiter(record, waiter) {
  const index = record.waiters.indexOf(waiter)
  if (index === -1) return false
  record.waiters.splice(index, 1)
  return true
}

function shiftM3RouteWaiter(record) {
  while (record.waiters.length > 0) {
    const waiter = record.waiters.shift()
    if (waiter && !waiter.settled) return waiter
  }
  return null
}

function rejectM3RouteWaiters(record, error) {
  const waiters = record.waiters.splice(0)
  for (const waiter of waiters) {
    settleM3RouteWaiter(waiter, 'reject', error)
  }
}

function dispatchM3RouteFrame(record, frame) {
  const waiter = shiftM3RouteWaiter(record)
  if (!waiter) {
    // Past the residency cap the frame is declined and the caller disposes of it. The
    // count is the only record that it happened, and it exists so that a missing
    // datagram can be told apart from one that was never sent.
    if (record.received.length >= ROUTE_FRAME_RESIDENCY_LIMIT) {
      record.droppedFrames++
      return false
    }
    record.received.push(frame)
    return true
  }
  settleM3RouteWaiter(waiter, 'resolve', frame)
  return true
}

function consumeM3RouteBranchDestroy(transport, record, payload) {
  const state = record.runtimeState
  if (!decodeBranchDestroy(payload, state)) return false
  if (record.branchDestroyConsumed) invalid()
  record.branchDestroyConsumed = true
  const loss = takeM3RuntimePhysicalLossState(state)
  M3_ROUTE_TRANSPORTS.delete(transport)
  DESTROYED_M3_ROUTE_TRANSPORTS.add(transport)
  record.active = false
  rejectM3RouteWaiters(record, PrivateRouteError.ERR_DESTROYED())
  for (const frame of record.received) clear(frame)
  record.received.length = 0
  RUNTIMES.delete(state.runtime)
  DESTROYED_RUNTIMES.add(state.runtime)
  clearRuntimeState(state)
  record.runtime = null
  record.runtimeState = null
  if (loss) issueTakenM3RuntimePhysicalLoss(loss)
  return true
}

function pumpM3RouteTransport(transport, record) {
  if (record.pumping) return
  record.pumping = true
  let budget = ROUTE_FRAMES_PER_PUMP_CYCLE
  Promise.resolve()
    .then(function receiveNextRoutePacket() {
      const current = routeTransportState(transport)
      if (current !== record) return null
      const state = record.runtimeState
      const channel = state.physicalChannel
      if (!safeObject(channel) || typeof channel.receive !== 'function') invalid()
      return Promise.resolve(channel.receive()).then((packet) => {
        let opened = null
        try {
          if (
            routeTransportState(transport) !== record ||
            !fixed(packet, CELL_SIZE) ||
            packet[1] !== CELL_CLASS.DATAGRAM
          ) {
            invalid()
          }
          opened = state.runtime.openTail(packet)
          if (!Array.isArray(opened) || opened.length !== 1) invalid()
          if (consumeM3RouteBranchDestroy(transport, record, opened[0])) return null
          if (!fixed(opened[0], 1100)) invalid()
          // The slot is surrendered only when the frame is taken. A frame the cap
          // declined stays in `opened`, so the finally below clears its plaintext and
          // returns its packet to the pool exactly as a taken frame's would be: the
          // drop path gets the same hygiene as the consume path.
          if (dispatchM3RouteFrame(record, opened[0])) opened[0] = null
          return --budget > 0 ? receiveNextRoutePacket() : null
        } finally {
          if (opened) for (const frame of opened) clear(frame)
          releaseM3RoutePacket(packet)
        }
      })
    })
    .then(
      () => {
        record.pumping = false
        if (M3_ROUTE_TRANSPORTS.get(transport) !== record || !record.active) return
        pumpM3RouteTransport(transport, record)
      },
      (error) => {
        record.pumping = false
        rejectM3RouteWaiters(record, error)
      }
    )
}

function reserveM3RouteFrame(transport) {
  const record = routeTransportState(transport)
  const reservation = Object.freeze({})
  const waiter = {
    settled: false,
    resolve: null,
    reject: null,
    reservationState: null
  }
  const promise = new Promise((resolve, reject) => {
    waiter.resolve = resolve
    waiter.reject = reject
  })
  const state = {
    reservation,
    record,
    waiter,
    promise,
    observed: false,
    settled: false
  }
  waiter.reservationState = state
  M3_ROUTE_RECEIVE_RESERVATIONS.set(reservation, state)
  if (record.received.length > 0) {
    settleM3RouteWaiter(waiter, 'resolve', record.received.shift())
    pumpM3RouteTransport(transport, record)
  } else {
    record.waiters.push(waiter)
    pumpM3RouteTransport(transport, record)
  }
  return reservation
}

function receiveReservedM3RouteFrame(reservation) {
  const state = safeObject(reservation) ? M3_ROUTE_RECEIVE_RESERVATIONS.get(reservation) : null
  if (!state || state.observed) {
    if (safeObject(reservation) && SPENT_M3_ROUTE_RECEIVE_RESERVATIONS.has(reservation)) {
      throw PrivateRouteError.ERR_REPLAY()
    }
    invalid()
  }
  state.observed = true
  finishM3RouteReceiveReservation(state)
  return state.promise
}

function cancelM3RouteFrameReservation(reservation) {
  const state = safeObject(reservation) ? M3_ROUTE_RECEIVE_RESERVATIONS.get(reservation) : null
  if (!state || state.settled) return false
  removeM3RouteWaiter(state.record, state.waiter)
  return settleM3RouteWaiter(state.waiter, 'reject', PrivateRouteError.ERR_DESTROYED())
}

function receiveM3RouteFrame(transport) {
  const reservation = reserveM3RouteFrame(transport)
  return receiveReservedM3RouteFrame(reservation)
}

// Counts only, and null once the transport is gone. `droppedFrames` is the one place
// a discarded datagram is visible at all: without it, a frame that arrived, was
// decrypted and was deliberately dropped past the residency cap looks exactly like a
// frame that was never sent.
function readM3RouteTransportDiagnostics(transport) {
  const record = safeObject(transport) ? M3_ROUTE_TRANSPORTS.get(transport) : null
  if (!record) return null
  return Object.freeze({
    active: record.active,
    received: record.received.length,
    waiters: record.waiters.length,
    droppedFrames: record.droppedFrames,
    branchDestroyConsumed: record.branchDestroyConsumed
  })
}

function destroyM3RouteTransport(transport) {
  const record = safeObject(transport) ? M3_ROUTE_TRANSPORTS.get(transport) : null
  if (!record) {
    if (safeObject(transport) && DESTROYED_M3_ROUTE_TRANSPORTS.has(transport)) return false
    return false
  }
  M3_ROUTE_TRANSPORTS.delete(transport)
  DESTROYED_M3_ROUTE_TRANSPORTS.add(transport)
  record.active = false
  rejectM3RouteWaiters(record, PrivateRouteError.ERR_DESTROYED())
  for (const frame of record.received) clear(frame)
  record.received.length = 0
  try {
    record.runtime.destroy()
  } catch {}
  record.runtime = null
  record.runtimeState = null
  return true
}

function clearTailResponderBinding(binding) {
  const state = safeObject(binding) ? TAIL_RESPONDER_BINDINGS.get(binding) : null
  if (!state) return false
  TAIL_RESPONDER_BINDINGS.delete(binding)
  if (state.token) CONSUMED_TAIL_RESPONDER_TOKENS.delete(state.token)
  clear(state.transcriptDigest)
  clear(state.localIdentity)
  state.transcriptDigest = null
  state.localIdentity = null
  const tokenState = state.token ? TAIL_RESPONDER_TOKENS.get(state.token) : null
  if (tokenState) {
    TAIL_RESPONDER_TOKENS.delete(state.token)
    SPENT_TAIL_RESPONDER_TOKENS.add(state.token)
    clearTailResponderTokenState(tokenState)
  }
  if (state.tail) {
    const tailState = TAILS.get(state.tail)
    if (tailState === state.tailState) {
      TAILS.delete(state.tail)
      SPENT_TAILS.add(state.tail)
    }
  }
  clearTailState(state.tailState)
  state.tail = null
  state.tailState = null
  state.token = null
  state.deadline = null
  return true
}

function validTailResponderToken(state, bindingState) {
  return (
    bindingState &&
    state.binding &&
    TAIL_RESPONDER_BINDINGS.get(state.binding) === bindingState &&
    fixed(bindingState.transcriptDigest, 32) &&
    fixed(bindingState.localIdentity, 32) &&
    fixed(state.transcriptDigest, 32) &&
    fixed(state.localIdentity, 32) &&
    same(state.transcriptDigest, bindingState.transcriptDigest) &&
    same(state.localIdentity, bindingState.localIdentity) &&
    state.initiator === false &&
    bindingState.initiator === false &&
    state.wireExpiresAt === bindingState.wireExpiresAt &&
    state.deadline === bindingState.deadline &&
    state.wireExpiresAt === state.deadline.wireExpiresAt &&
    u64(state.deadline.routeLocalDeadline) &&
    state.deadline.routeLocalDeadline > 0n &&
    u64(state.deadline.operationDeadline) &&
    state.deadline.operationDeadline > 0n &&
    state.deadline.operationDeadline <= state.deadline.routeLocalDeadline &&
    safeObject(state.deadline.clockIdentity) &&
    typeof state.deadline.clockIdentity.wallNow === 'function' &&
    typeof state.deadline.clockIdentity.monotonicNow === 'function'
  )
}

function consumeTailResponderToken(token) {
  const validToken = safeObject(token)
  const state = validToken ? TAIL_RESPONDER_TOKENS.get(token) : null
  if (!state) {
    if (validToken && SPENT_TAIL_RESPONDER_TOKENS.has(token)) {
      throw PrivateRouteError.ERR_REPLAY()
    }
    invalid()
  }
  TAIL_RESPONDER_TOKENS.delete(token)
  SPENT_TAIL_RESPONDER_TOKENS.add(token)
  const binding = state.binding
  const bindingState = binding ? TAIL_RESPONDER_BINDINGS.get(binding) : null
  if (!validTailResponderToken(state, bindingState)) {
    clearTailResponderTokenState(state)
    clearTailResponderBinding(binding)
    invalid()
  }
  clearTailResponderTokenState(state)
  CONSUMED_TAIL_RESPONDER_TOKENS.set(token, binding)
  return binding
}

function revokeTailResponderToken(token) {
  const validToken = safeObject(token)
  const state = validToken ? TAIL_RESPONDER_TOKENS.get(token) : null
  const consumedBinding = validToken ? CONSUMED_TAIL_RESPONDER_TOKENS.get(token) : null
  if (!state && !consumedBinding) return false
  if (state) {
    TAIL_RESPONDER_TOKENS.delete(token)
    SPENT_TAIL_RESPONDER_TOKENS.add(token)
    const binding = state.binding
    clearTailResponderTokenState(state)
    clearTailResponderBinding(binding)
  } else {
    CONSUMED_TAIL_RESPONDER_TOKENS.delete(token)
    clearTailResponderBinding(consumedBinding)
  }
  return true
}

function deriveM3CellIds(completeOfferDigest, { crypto = cryptoSuite } = {}) {
  const digest = copy(completeOfferDigest, 32)
  let hash
  try {
    hash = crypto && crypto.hash
  } catch {
    clear(digest)
    invalid()
  }
  if (typeof hash !== 'function') {
    clear(digest)
    invalid()
  }
  let initiator = null
  let responder = null
  try {
    initiator = hashOne(hash.bind(crypto), INITIATOR_CELL_ID_DOMAIN, digest)
    responder = hashOne(hash.bind(crypto), RESPONDER_CELL_ID_DOMAIN, digest)
    const initiatorCellId = copy(initiator.subarray(0, 16), 16)
    const responderCellId = copy(responder.subarray(0, 16), 16)
    if (
      !nonzero(initiatorCellId) ||
      !nonzero(responderCellId) ||
      same(initiatorCellId, responderCellId)
    ) {
      clear(initiatorCellId)
      clear(responderCellId)
      invalid()
    }
    return Object.freeze({ initiatorCellId, responderCellId })
  } finally {
    clear(digest)
    clear(initiator)
    clear(responder)
  }
}

function contextList(contexts) {
  const result = []
  for (const cellClass of [CELL_CLASS.CONTROL, CELL_CLASS.STREAM, CELL_CLASS.DATAGRAM]) {
    let pair
    try {
      pair = contexts[cellClass]
    } catch {
      invalid()
    }
    if (!safeObject(pair)) invalid()
    for (const direction of ['tx', 'rx']) {
      let context
      try {
        context = pair[direction]
      } catch {
        invalid()
      }
      if (
        !safeObject(context) ||
        !fixed(context.key, 32) ||
        !fixed(context.noncePrefix, 16) ||
        !safeObject(context.counter)
      ) {
        invalid()
      }
      result.push(context)
    }
  }
  return result
}

function validateState(state, ids) {
  if (
    !safeObject(state) ||
    typeof state.initiator !== 'boolean' ||
    !fixed(state.completeOfferDigest, 32) ||
    !fixed(state.localId, 16) ||
    !fixed(state.peerLocalId, 16) ||
    !nonzero(state.localId) ||
    !nonzero(state.peerLocalId) ||
    same(state.localId, state.peerLocalId) ||
    (state.branchClass !== BRANCH_CLASS.LOOKUP && state.branchClass !== BRANCH_CLASS.ANNOUNCE) ||
    !fixed(state.branchId, 16) ||
    !nonzero(state.branchId) ||
    !fixed(state.circuitId, 16) ||
    !nonzero(state.circuitId) ||
    !u64(state.generation) ||
    state.generation === 0n ||
    !Number.isInteger(state.extensionIndex) ||
    state.extensionIndex < 0 ||
    state.extensionIndex > 2 ||
    !fixed(state.localIdentity, 32) ||
    !fixed(state.peerIdentity, 32) ||
    same(state.localIdentity, state.peerIdentity) ||
    !u64(state.expiresAt) ||
    !safeObject(state.physicalChannel) ||
    typeof state.physicalChannel.destroy !== 'function' ||
    !same(state.localId, state.initiator ? ids.initiatorCellId : ids.responderCellId) ||
    !same(state.peerLocalId, state.initiator ? ids.responderCellId : ids.initiatorCellId)
  ) {
    invalid()
  }
  contextList(state.contexts)
}

function clearContexts(contexts) {
  let values = []
  try {
    values = contextList(contexts)
  } catch {
    values = []
  }
  for (const context of values) {
    clear(context.key)
    clear(context.noncePrefix)
    try {
      if (typeof context.counter.destroy === 'function') context.counter.destroy()
    } catch {}
  }
}

function releaseReservation(state) {
  const reservation = state && state.reservation
  if (!reservation || reservation.released) return
  reservation.released = true
  const owner = AUTHORITY_STATES.get(reservation.authority)
  if (owner && owner.reservations.get(reservation.key) === reservation) {
    owner.reservations.delete(reservation.key)
  }
  reservation.runtimeState = null
  reservation.forwardingOwner = null
}

function cancelRuntimeTimer(state) {
  const handle = state && state.timer
  if (handle === null || handle === undefined) return
  state.timer = null
  state.timerGeneration++
  const owner = AUTHORITY_STATES.get(state.authority)
  if (!owner) return
  try {
    owner.cancelScheduled(handle)
  } catch {}
}

function takeM3RuntimePhysicalLossState(state) {
  const record = state && state.physicalLossRegistration
  if (!record) return null
  state.physicalLossRegistration = null
  M3_RUNTIME_PHYSICAL_LOSS_REGISTRATIONS.delete(record.registration)
  if (record.udxRegistration) {
    try {
      const { revokeM3CellLinkPhysicalLossSink } = require('./udx-cell-endpoint')
      revokeM3CellLinkPhysicalLossSink(record.udxRegistration)
    } catch {}
  }
  record.udxRegistration = null
  record.state = null
  return record
}

function revokeM3RuntimePhysicalLossState(state) {
  const record = takeM3RuntimePhysicalLossState(state)
  if (!record) return false
  record.sink = null
  return true
}

function issueTakenM3RuntimePhysicalLoss(record) {
  const sink = record.sink
  record.sink = null
  if (typeof sink !== 'function') return false
  try {
    sink()
  } catch {}
  return true
}

function issueM3RuntimePhysicalLoss(registration) {
  const record = safeObject(registration)
    ? M3_RUNTIME_PHYSICAL_LOSS_REGISTRATIONS.get(registration)
    : null
  if (!record || !record.state || record.state.physicalLossRegistration !== record) return false
  takeM3RuntimePhysicalLossState(record.state)
  return issueTakenM3RuntimePhysicalLoss(record)
}

function detachRuntimeState(state) {
  if (!state || state.cleared) return null
  state.cleared = true
  revokeM3RuntimePhysicalLossState(state)
  cancelRuntimeTimer(state)
  if (state.tail) {
    revokeM3TailCapability(state.tail)
    state.tail = null
  }
  releaseReservation(state)
  const channel = state.physicalChannel
  state.physicalChannel = null
  return { state, channel }
}

function zeroDetachedRuntimeState(detached) {
  if (!detached) return null
  const { state, channel } = detached
  clearContexts(state.contexts)
  clear(state.completeOfferDigest)
  clear(state.localId)
  clear(state.peerLocalId)
  clear(state.branchId)
  clear(state.circuitId)
  clear(state.localIdentity)
  clear(state.peerIdentity)
  clear(state.pendingTailSecret)
  clear(state.pendingTailTranscript)
  state.pendingTailSecret = null
  state.pendingTailTranscript = null
  return channel
}

function destroyChannel(channel) {
  try {
    if (channel) channel.destroy()
  } catch {}
}

function clearRuntimeState(state) {
  destroyChannel(zeroDetachedRuntimeState(detachRuntimeState(state)))
}

function expireRuntimeState(state) {
  if (!state || state.cleared) return false
  const forwardingOwner = state.reservation && state.reservation.forwardingOwner
  RUNTIMES.delete(state.runtime)
  DESTROYED_RUNTIMES.add(state.runtime)
  if (forwardingOwner) return destroyM3ForwardingOwner(forwardingOwner)
  clearRuntimeState(state)
  return true
}

function runRuntimeTimer(state) {
  const owner = AUTHORITY_STATES.get(state.authority)
  if (!owner || state.cleared) return
  try {
    const current = sampleMonotonicNow(owner)
    if (current < state.localDeadline) {
      armRuntimeState(state, timerDelay(state.localDeadline - current))
      return
    }
  } catch {}
  expireRuntimeState(state)
}

function armRuntimeState(state, delay) {
  const owner = AUTHORITY_STATES.get(state.authority)
  if (!owner || state.cleared) unavailable()
  const boundedDelay = Math.min(delay, MAX_TIMER_DELAY)
  const generation = ++state.timerGeneration
  let arming = true
  let fired = false
  let handle = null
  const onExpiry = () => {
    if (arming) {
      fired = true
      return
    }
    if (state.timerGeneration !== generation) return
    state.timer = null
    runRuntimeTimer(state)
  }
  try {
    handle = owner.schedule(onExpiry, boundedDelay)
  } catch {
    arming = false
    unavailable()
  }
  arming = false
  if (
    handle === null ||
    handle === undefined ||
    fired ||
    state.cleared ||
    state.reservation.released ||
    state.reservation.runtimeState !== state
  ) {
    state.timerGeneration++
    if (handle !== null && handle !== undefined) {
      try {
        owner.cancelScheduled(handle)
      } catch {}
    }
    unavailable()
  }
  state.timer = handle
}

function sweepExpired(owner, current, excluded = null) {
  for (const reservation of [...owner.reservations.values()]) {
    if (reservation === excluded || reservation.released || !reservation.runtimeState) continue
    const state = reservation.runtimeState
    if (state.localDeadline > current) continue
    expireRuntimeState(state)
  }
}

function runtimeState(runtime) {
  const state = safeObject(runtime) ? RUNTIMES.get(runtime) : null
  if (state) return state
  if (MOVED_RUNTIMES.has(runtime)) destroyed()
  destroyed()
}

function checkRuntimeTime(state) {
  const owner = AUTHORITY_STATES.get(state.authority)
  if (!owner || sampleMonotonicNow(owner) >= state.localDeadline) {
    expireRuntimeState(state)
    destroyed()
  }
}

class M3AdjacencyRuntime {
  sealTail(options) {
    const state = runtimeState(this)
    if (state.installing) busy()
    checkRuntimeTime(state)
    let cellClass
    let payload
    try {
      cellClass = options.class
      payload = options.payload
    } catch {
      invalid()
    }
    if (
      cellClass !== CELL_CLASS.CONTROL &&
      cellClass !== CELL_CLASS.STREAM &&
      cellClass !== CELL_CLASS.DATAGRAM
    ) {
      invalid()
    }
    const context = state.contexts[cellClass].tx
    return state.codec.seal({
      key: context.key,
      noncePrefix: context.noncePrefix,
      senderCounter: context.counter,
      class: cellClass,
      direction: state.initiator ? DIRECTION.FORWARD : DIRECTION.REVERSE,
      epoch: state.generation,
      circuitId: state.peerLocalId,
      payload
    })
  }

  openTail(packet) {
    const state = runtimeState(this)
    if (state.installing) busy()
    checkRuntimeTime(state)
    if (!fixed(packet, CELL_SIZE)) invalid()
    const cellClass = packet[1]
    if (
      cellClass !== CELL_CLASS.CONTROL &&
      cellClass !== CELL_CLASS.STREAM &&
      cellClass !== CELL_CLASS.DATAGRAM
    ) {
      invalid()
    }
    const context = state.contexts[cellClass].rx
    const opened = state.codec.open(
      {
        key: context.key,
        noncePrefix: context.noncePrefix,
        receiver: context.counter,
        expectedClass: cellClass,
        expectedDirection: state.initiator ? DIRECTION.REVERSE : DIRECTION.FORWARD,
        expectedEpoch: state.generation,
        expectedCircuitId: state.localId
      },
      packet
    )
    return Array.isArray(opened) ? opened : [opened]
  }

  diagnostics() {
    const state = runtimeState(this)
    if (state.installing) busy()
    checkRuntimeTime(state)
    return Object.freeze({ state: 'TAIL_ENDPOINT', expiresAt: state.expiresAt })
  }

  revoke() {
    return this.#destroy()
  }

  destroy() {
    return this.#destroy()
  }

  #destroy() {
    const state = RUNTIMES.get(this)
    if (!state) {
      if (MOVED_RUNTIMES.has(this)) destroyed()
      return false
    }
    if (state.installing) busy()
    RUNTIMES.delete(this)
    DESTROYED_RUNTIMES.add(this)
    clearRuntimeState(state)
    return true
  }
}

class M3AdjacencyAuthority {
  constructor(options = {}) {
    if (!safeObject(options)) invalid()
    exactOptions(options)
    const wallNow = option(options, 'wallNow')
    const monotonicNow = option(options, 'monotonicNow')
    const schedule = option(options, 'schedule')
    const cancelScheduled = option(options, 'cancelScheduled')
    const selectedCrypto = option(options, 'crypto')
    const crypto = selectedCrypto === undefined ? cryptoSuite : selectedCrypto
    const maximum = option(options, 'maxRuntimes')
    const observe = option(options, TEST_ONLY_M3_ADJACENCY_OBSERVER)
    if (
      typeof wallNow !== 'function' ||
      typeof monotonicNow !== 'function' ||
      typeof schedule !== 'function' ||
      typeof cancelScheduled !== 'function' ||
      !safeObject(crypto) ||
      typeof crypto.hash !== 'function' ||
      typeof crypto.seal !== 'function' ||
      typeof crypto.open !== 'function' ||
      typeof crypto.randomBytes !== 'function' ||
      (maximum !== undefined &&
        (!Number.isInteger(maximum) || maximum < 1 || maximum > MAX_M3_ADJACENCY_RUNTIMES)) ||
      (observe !== undefined && typeof observe !== 'function')
    ) {
      invalid()
    }
    const state = {
      authority: this,
      wallNow,
      monotonicNow,
      schedule,
      cancelScheduled,
      crypto,
      clockIdentity: Object.freeze({ wallNow, monotonicNow }),
      lastWallNow: null,
      lastMonotonicNow: null,
      maxRuntimes: maximum === undefined ? DEFAULT_MAX_M3_ADJACENCY_RUNTIMES : maximum,
      observe: observe || null,
      responderAdopter: null,
      reservations: new Map()
    }
    AUTHORITIES.add(this)
    AUTHORITY_STATES.set(this, state)
    state.responderAdopter = createM3ResponderAdopter(
      (established) => this.adopt(established),
      (adjacency) => {
        try {
          adjacency.runtime.destroy()
        } finally {
          revokeM3TailCapability(adjacency.tail)
        }
      }
    )
  }

  responderAdopter() {
    const state = AUTHORITY_STATES.get(this)
    if (!state) destroyed()
    return state.responderAdopter
  }

  adopt(establishedHandle) {
    const owner = AUTHORITY_STATES.get(this)
    if (!owner) destroyed()
    let state = null
    let ids = null
    let reservation = null
    let branchBinding = null
    let runtime = null
    let runtimeValue = null
    let tail = null
    let responderToken = null
    let adopted = false
    try {
      state = takeM3EstablishedLink(establishedHandle)
      reservation = reserveBinding(this, owner, state)
      ids = deriveM3CellIds(state.completeOfferDigest, { crypto: owner.crypto })
      validateState(state, ids)
      try {
        if (state.testOnly === true) {
          const { registerM3CellLinkTransfer } = require('./udx-cell-endpoint')
          const transfer = registerM3CellLinkTransfer(state.physicalChannel, {
            receiveEpoch: state.generation,
            receiveCircuitId: state.localId,
            receiveDirection: state.initiator ? DIRECTION.REVERSE : DIRECTION.FORWARD,
            sendEpoch: state.generation,
            sendCircuitId: state.peerLocalId,
            sendDirection: state.initiator ? DIRECTION.FORWARD : DIRECTION.REVERSE
          })
          if (transfer) state.physicalChannel = transfer
        } else {
          branchBinding = state.m3BranchBinding
          const { registerM3CellLinkTransfer } = require('./udx-cell-endpoint')
          const transfer = registerM3CellLinkTransfer(state.physicalChannel, branchBinding)
          if (!transfer) throw PrivateRouteError.UNAUTHORIZED()
          state.m3BranchBinding = null
          branchBinding = null
          state.physicalChannel = transfer
        }
      } catch (err) {
        if (err instanceof PrivateRouteError) throw err
        invalid()
      }
      const projection = projectWireExpiry(owner, state.expiresAt)
      sweepExpired(owner, projection.current, reservation)
      if (owner.reservations.size > owner.maxRuntimes) busy()
      if (owner.observe) {
        try {
          owner.observe(Object.freeze({ type: 'reserved' }))
        } catch {}
      }
      if (owner.reservations.get(reservation.key) !== reservation || reservation.released)
        destroyed()

      runtime = new M3AdjacencyRuntime()
      tail = Object.freeze({})
      const tailSecret = state.tailSharedSecret || state.clientTailEphemeralSecretKey || null
      const tailTranscript = state.tailControlTranscript || null
      state.tailSharedSecret = null
      state.tailControlTranscript = null
      state.clientTailEphemeralSecretKey = null
      runtimeValue = {
        ...state,
        authority: this,
        codec: new CellCodec({ crypto: owner.crypto, cellSize: CELL_SIZE }),
        cleared: false,
        epoch: state.generation,
        expiresAt: state.expiresAt,
        wireExpiresAt: projection.deadline.wireExpiresAt,
        localDeadline: projection.deadline.routeLocalDeadline,
        installing: false,
        pendingTailSecret: tailSecret,
        pendingTailTranscript: tailTranscript,
        reservation,
        runtime,
        tail,
        timer: null,
        timerGeneration: 0,
        physicalLossRegistration: null
      }
      reservation.runtimeState = runtimeValue
      armRuntimeState(runtimeValue, projection.delay)
      const tailState = {
        initiator: state.initiator,
        secret: runtimeValue.pendingTailSecret,
        transcript: runtimeValue.pendingTailTranscript,
        transportOwner: Object.freeze({}),
        deadline: projection.deadline,
        lastMonotonic: projection.current,
        binding: null,
        extensionIndex: state.extensionIndex,
        used: false
      }
      M3_TAIL_CONTROL_TRANSPORTS.set(tailState.transportOwner, {
        runtime,
        runtimeState: runtimeValue,
        deadline: tailState.deadline,
        clockIdentity: projection.deadline.clockIdentity,
        received: [],
        waiters: [],
        pumping: false
      })
      if (!state.initiator) {
        responderToken = issueTailResponderToken(owner, tail, tailState, state.localIdentity)
      }
      const current = sampleMonotonicNow(owner)
      if (
        AUTHORITY_STATES.get(this) !== owner ||
        runtimeValue.cleared ||
        reservation.released ||
        owner.reservations.get(reservation.key) !== reservation ||
        reservation.runtimeState !== runtimeValue ||
        current >= runtimeValue.localDeadline
      ) {
        unavailable()
      }
      tailState.lastMonotonic = current
      RUNTIMES.set(runtime, runtimeValue)
      TAILS.set(tail, tailState)
      runtimeValue.pendingTailSecret = null
      runtimeValue.pendingTailTranscript = null
      const result = Object.freeze(
        responderToken ? { runtime, tail, responderToken } : { runtime, tail }
      )
      ADOPTED_M3_ADJACENCIES.set(result, { initiator: state.initiator, runtime, tail })
      adopted = true
      return result
    } catch (err) {
      if (reservation && !reservation.released) {
        const ownerState = AUTHORITY_STATES.get(this)
        if (ownerState && ownerState.reservations.get(reservation.key) === reservation) {
          ownerState.reservations.delete(reservation.key)
        }
        reservation.released = true
      }
      if (err instanceof PrivateRouteError) throw err
      unavailable()
    } finally {
      if (!adopted && responderToken) revokeTailResponderToken(responderToken)
      if (!adopted && runtimeValue) clearRuntimeState(runtimeValue)
      else if (!adopted && state) destroyTakenM3EstablishedLink(state)
      if (ids) {
        clear(ids.initiatorCellId)
        clear(ids.responderCellId)
      }
    }
  }

  diagnostics() {
    const state = AUTHORITY_STATES.get(this)
    if (!state) destroyed()
    sweepExpired(state, sampleMonotonicNow(state))
    return Object.freeze({
      activeRuntimes: state.reservations.size,
      maxRuntimes: state.maxRuntimes
    })
  }
}

function takeM3InitiatorRuntime(adjacency) {
  const record = safeObject(adjacency) ? ADOPTED_M3_ADJACENCIES.get(adjacency) : null
  if (!record) return null
  if (!record.initiator) invalid()
  ADOPTED_M3_ADJACENCIES.delete(adjacency)
  SPENT_ADOPTED_M3_ADJACENCIES.add(adjacency)
  const runtime = record.runtime
  record.runtime = null
  revokeM3TailCapability(record.tail)
  record.tail = null
  return runtime
}

function isM3AdjacencyAuthority(value) {
  return safeObject(value) && AUTHORITIES.has(value)
}

function revokeM3TailCapability(capability) {
  const state = safeObject(capability) ? TAILS.get(capability) : null
  if (!state) return false
  TAILS.delete(capability)
  SPENT_TAILS.add(capability)
  const binding = state.binding
  clearTailState(state)
  clearTailResponderBinding(binding)
  return true
}

// Deep production import used only by TailControlSession. Ownership moves out
// of the adjacency authority once and raw key material is never returned by a
// public package API.
function takeM3TailCapability(capability, clocks) {
  const validCapability = safeObject(capability)
  const state = validCapability ? TAILS.get(capability) : null
  if (!state) {
    if (validCapability && SPENT_TAILS.has(capability)) throw PrivateRouteError.ERR_REPLAY()
    invalid()
  }
  TAILS.delete(capability)
  SPENT_TAILS.add(capability)
  state.used = true
  let moved = false
  try {
    if (!safeObject(clocks)) invalid()
    let keys
    try {
      keys = reflectOwnKeys(clocks)
    } catch {
      invalid()
    }
    if (keys.length !== 2 || !keys.includes('wallNow') || !keys.includes('monotonicNow')) {
      invalid()
    }
    let wallDescriptor
    let monotonicDescriptor
    try {
      wallDescriptor = getOwnPropertyDescriptor(clocks, 'wallNow')
      monotonicDescriptor = getOwnPropertyDescriptor(clocks, 'monotonicNow')
    } catch {
      invalid()
    }
    if (
      !wallDescriptor ||
      !monotonicDescriptor ||
      !Object.prototype.hasOwnProperty.call(wallDescriptor, 'value') ||
      !Object.prototype.hasOwnProperty.call(monotonicDescriptor, 'value') ||
      wallDescriptor.value !== state.deadline.clockIdentity.wallNow ||
      monotonicDescriptor.value !== state.deadline.clockIdentity.monotonicNow
    ) {
      invalid()
    }
    moved = true
    return state
  } finally {
    if (!moved) {
      const binding = state.binding
      clearTailState(state)
      clearTailResponderBinding(binding)
    }
  }
}

function createM3RelayForwardingFacade(previousRuntime, nextRuntime) {
  const previous = safeObject(previousRuntime) ? RUNTIMES.get(previousRuntime) : null
  const next = safeObject(nextRuntime) ? RUNTIMES.get(nextRuntime) : null
  if (!previous || !next || previous === next) invalid()
  let live = true
  let stopping = false
  let failure = null
  let branchDestroyForwarded = false
  const terminalState = { terminal: false, release: null }
  const releaseTerminalForwarding = () => {
    if (terminalState.terminal) return
    terminalState.terminal = true
    const release = terminalState.release
    if (typeof release !== 'function') return
    try {
      release()
    } catch {}
  }

  const sendPayload = async (target, cellClass, payload) => {
    const tx = target.contexts[cellClass].tx
    let sealed = null
    try {
      sealed = target.codec.seal({
        key: tx.key,
        noncePrefix: tx.noncePrefix,
        senderCounter: tx.counter,
        class: cellClass,
        direction: target.initiator ? DIRECTION.FORWARD : DIRECTION.REVERSE,
        epoch: target.generation,
        circuitId: target.peerLocalId,
        payload
      })
      await target.physicalChannel.send(sealed)
    } finally {
      clear(sealed)
    }
  }

  const emitBranchDestroyUpstream = async () => {
    let payload = null
    try {
      payload = encodeBranchDestroy(previous)
      await sendPayload(previous, CELL_CLASS.DATAGRAM, payload)
    } finally {
      clear(payload)
    }
  }

  const stopAfterFailure = async (err, downstreamFailure) => {
    if (!live || stopping) return
    failure = err instanceof PrivateRouteError ? err.code : 'ERR_PRIVACY_UNAVAILABLE'
    if (!downstreamFailure) {
      live = false
      releaseTerminalForwarding()
      return
    }
    stopping = true
    try {
      await emitBranchDestroyUpstream()
    } catch (sendError) {
      failure = sendError instanceof PrivateRouteError ? sendError.code : 'ERR_PRIVACY_UNAVAILABLE'
    } finally {
      live = false
      releaseTerminalForwarding()
    }
  }

  const relay = async (source, target) => {
    const reverse = source === next && target === previous
    while (live && !stopping) {
      let packet = null
      let opened = null
      let failureLocation = source === next ? 'downstream' : 'upstream'
      try {
        packet = await source.physicalChannel.receive()
        if (!live || stopping) break
        if (!fixed(packet, CELL_SIZE)) invalid()
        const cellClass = packet[1]
        if (
          cellClass !== CELL_CLASS.CONTROL &&
          cellClass !== CELL_CLASS.STREAM &&
          cellClass !== CELL_CLASS.DATAGRAM
        ) {
          invalid()
        }
        const rx = source.contexts[cellClass].rx
        opened = source.codec.open(
          {
            key: rx.key,
            noncePrefix: rx.noncePrefix,
            receiver: rx.counter,
            expectedClass: cellClass,
            expectedDirection: source.initiator ? DIRECTION.REVERSE : DIRECTION.FORWARD,
            expectedEpoch: source.generation,
            expectedCircuitId: source.localId
          },
          packet
        )
        const payloads = Array.isArray(opened) ? opened : [opened]
        opened = payloads
        for (const payload of payloads) {
          if (!live || stopping) break
          if (decodeBranchDestroy(payload, source)) {
            if (
              !reverse ||
              cellClass !== CELL_CLASS.DATAGRAM ||
              payloads.length !== 1 ||
              branchDestroyForwarded
            ) {
              invalid()
            }
            stopping = true
            failureLocation = 'upstream'
            try {
              await sendPayload(target, CELL_CLASS.DATAGRAM, payload)
              branchDestroyForwarded = true
            } finally {
              live = false
              releaseTerminalForwarding()
            }
            break
          }
          failureLocation = target === next ? 'downstream' : 'upstream'
          await sendPayload(target, cellClass, payload)
        }
      } catch (err) {
        await stopAfterFailure(err, failureLocation === 'downstream')
        break
      } finally {
        releaseM3RoutePacket(packet)
        if (Array.isArray(opened)) {
          for (const payload of opened) clear(payload)
        } else {
          clear(opened)
        }
      }
    }
  }

  void relay(previous, next)
  void relay(next, previous)
  const facade = Object.freeze({
    diagnostics() {
      return Object.freeze({ state: live ? 'FORWARDING' : 'DESTROYED', failure })
    },
    destroy() {
      if (!live && failure === null) return false
      stopping = true
      live = false
      failure = null
      return true
    }
  })
  M3_RELAY_FORWARDING_STATES.set(facade, terminalState)
  return facade
}

function takeForwardingFacade(forwarding) {
  if (
    !safeObject(forwarding) ||
    STAGED_FORWARDING_FACADES.has(forwarding) ||
    CLAIMED_FORWARDING_FACADES.has(forwarding)
  )
    invalid()
  CLAIMED_FORWARDING_FACADES.add(forwarding)
  let keys
  let diagnosticsDescriptor
  let destroyDescriptor
  let frozen
  try {
    keys = reflectOwnKeys(forwarding)
    diagnosticsDescriptor = getOwnPropertyDescriptor(forwarding, 'diagnostics')
    destroyDescriptor = getOwnPropertyDescriptor(forwarding, 'destroy')
    frozen = Object.isFrozen(forwarding)
  } catch {
    invalid()
  }
  if (
    !frozen ||
    keys.length !== 2 ||
    !keys.includes('diagnostics') ||
    !keys.includes('destroy') ||
    !diagnosticsDescriptor ||
    !destroyDescriptor ||
    !Object.prototype.hasOwnProperty.call(diagnosticsDescriptor, 'value') ||
    !Object.prototype.hasOwnProperty.call(destroyDescriptor, 'value') ||
    typeof diagnosticsDescriptor.value !== 'function' ||
    typeof destroyDescriptor.value !== 'function'
  ) {
    invalid()
  }
  const terminalState = M3_RELAY_FORWARDING_STATES.get(forwarding) || null
  M3_RELAY_FORWARDING_STATES.delete(forwarding)
  return {
    diagnostics: diagnosticsDescriptor.value,
    destroy: destroyDescriptor.value,
    terminalState
  }
}

function createM3ForwardingOwnerFromFacade(taken) {
  const capability = Object.freeze({})
  const facade = Object.freeze({
    diagnostics() {
      const state = FORWARDING_OWNERS.get(capability)
      if (!state) destroyed()
      return state.diagnostics()
    },
    destroy() {
      return destroyM3ForwardingOwner(capability)
    }
  })
  FORWARDING_OWNERS.set(capability, {
    destroy: taken.destroy,
    diagnostics: taken.diagnostics,
    destroying: false,
    pair: null,
    terminalState: taken.terminalState || null,
    facade
  })
  return capability
}

function createM3ForwardingOwner(forwarding) {
  return createM3ForwardingOwnerFromFacade(takeForwardingFacade(forwarding))
}

function armM3ForwardingOwnerTerminal(capability, state) {
  const terminalState = state && state.terminalState
  if (!terminalState) return
  terminalState.release = () => destroyM3ForwardingOwner(capability)
  if (terminalState.terminal) terminalState.release()
}

function releaseInstalledPair(pair) {
  if (!pair) return
  const previousDetached = detachRuntimeState(pair.previous)
  const nextDetached = detachRuntimeState(pair.next)
  const previousChannel = zeroDetachedRuntimeState(previousDetached)
  const nextChannel = zeroDetachedRuntimeState(nextDetached)
  destroyChannel(previousChannel)
  destroyChannel(nextChannel)
}

function tombstoneM3TailForwardingPublication(state) {
  if (!state || state.phase === 'DESTROYED') return false
  if (state.publication) M3_TAIL_FORWARDING_PUBLICATIONS.delete(state.publication)
  if (state.taken) TAKEN_M3_TAIL_FORWARDING_PUBLICATIONS.delete(state.taken)
  if (state.claim) M3_FORWARDING_PUBLICATION_CLAIMS.delete(state.claim)
  const lease = state.leaseRecord || M3_TAIL_FORWARDING_LEASES.get(state.lease)
  state.phase = 'DESTROYED'
  if (lease) {
    M3_TAIL_FORWARDING_LEASES.delete(state.lease)
    spendM3TailForwardingLeaseOwner(lease)
    lease.phase = 'DESTROYED'
  }
  return true
}

function destroyStagedM3ForwardingFacade(forwarding) {
  const record = STAGED_FORWARDING_FACADES.get(forwarding)
  STAGED_FORWARDING_FACADES.delete(forwarding)
  M3_RELAY_FORWARDING_STATES.delete(forwarding)
  CLAIMED_FORWARDING_FACADES.add(forwarding)
  const destroy = record ? record.destroy : null
  try {
    if (typeof destroy === 'function') destroy()
  } catch {}
}

function destroyM3ForwardingOwnerState(capability, state, publication) {
  if (!state || state.destroying) return false
  FORWARDING_OWNERS.delete(capability)
  state.destroying = true
  const destroy = state.destroy
  const terminalState = state.terminalState
  state.terminalState = null
  if (terminalState) terminalState.release = null
  const pair = state.pair
  state.destroy = null
  state.diagnostics = null
  state.publication = null
  try {
    tombstoneM3TailForwardingPublication(publication)
    try {
      destroy()
    } catch {}
  } finally {
    releaseInstalledPair(pair)
    state.destroying = false
  }
  return true
}

function destroyM3ForwardingOwner(capability) {
  const state = FORWARDING_OWNERS.get(capability)
  return destroyM3ForwardingOwnerState(capability, state, state ? state.publication : null)
}

function validateInstallState(previous, next, serviceIdentity, current, maxCircuits) {
  if (
    previous === next ||
    previous.authority !== next.authority ||
    previous.initiator !== false ||
    next.initiator !== true ||
    !same(previous.localIdentity, serviceIdentity) ||
    !same(next.localIdentity, serviceIdentity) ||
    previous.branchClass !== next.branchClass ||
    !same(previous.branchId, next.branchId) ||
    !same(previous.circuitId, next.circuitId) ||
    previous.generation !== next.generation ||
    !(
      (previous.extensionIndex === 0 && next.extensionIndex === 1) ||
      (previous.extensionIndex === 1 && next.extensionIndex === 2)
    ) ||
    same(previous.peerIdentity, next.peerIdentity) ||
    same(previous.localId, next.localId) ||
    previous.expiresAt <= current ||
    next.expiresAt <= current
  ) {
    invalid()
  }
  const owner = AUTHORITY_STATES.get(previous.authority)
  if (!owner || owner.maxRuntimes > maxCircuits) invalid()
}

function beginM3Install(previousRuntime, nextRuntime) {
  const previous = safeObject(previousRuntime) ? RUNTIMES.get(previousRuntime) : null
  const next = safeObject(nextRuntime) ? RUNTIMES.get(nextRuntime) : null
  if (!previous || !next || previous.installing || next.installing) invalid()
  previous.installing = true
  next.installing = true
  const plan = Object.freeze({})
  INSTALL_PLANS.set(plan, {
    previous,
    next,
    previousRuntime,
    nextRuntime,
    phase: 'OPEN',
    publicationClaim: null,
    validated: false,
    claimingReentered: false
  })
  return plan
}

function validateM3Install(plan, serviceIdentity, maxCircuits, current) {
  const state = safeObject(plan) ? INSTALL_PLANS.get(plan) : null
  if (
    !state ||
    state.phase !== 'OPEN' ||
    !state.previous.installing ||
    !state.next.installing ||
    RUNTIMES.get(state.previousRuntime) !== state.previous ||
    RUNTIMES.get(state.nextRuntime) !== state.next ||
    !Number.isInteger(maxCircuits) ||
    maxCircuits < 1 ||
    maxCircuits > MAX_M3_ADJACENCY_RUNTIMES ||
    !u64(current)
  ) {
    invalid()
  }
  validateInstallState(state.previous, state.next, serviceIdentity, current, maxCircuits)
  state.validated = true
  return plan
}

function abortM3Install(plan) {
  const state = safeObject(plan) ? INSTALL_PLANS.get(plan) : null
  if (!state || state.phase !== 'OPEN') return false
  INSTALL_PLANS.delete(plan)
  state.phase = 'ABORTED'
  state.previous.installing = false
  state.next.installing = false
  if (state.publicationClaim) {
    const claim = M3_FORWARDING_PUBLICATION_CLAIMS.get(state.publicationClaim)
    M3_FORWARDING_PUBLICATION_CLAIMS.delete(state.publicationClaim)
    state.publicationClaim = null
    if (claim && claim.phase === 'OPEN') {
      claim.phase = 'ABORTED'
      const leaseHandle = claim.lease
      const lease = safeObject(leaseHandle) ? M3_TAIL_FORWARDING_LEASES.get(leaseHandle) : null
      if (lease) {
        lease.phase = 'ABORTED'
        M3_TAIL_FORWARDING_LEASES.delete(leaseHandle)
        spendM3TailForwardingLeaseOwner(lease)
      }
      destroyStagedM3ForwardingFacade(claim.forwarding)
    }
  }
  return true
}

function createM3ForwardingPublicationClaim(plan, forwarding) {
  const state = safeObject(plan) ? INSTALL_PLANS.get(plan) : null
  if (state && state.phase === 'CLAIMING') state.claimingReentered = true
  if (
    !state ||
    state.phase !== 'OPEN' ||
    !state.validated ||
    state.publicationClaim !== null ||
    !safeObject(forwarding) ||
    STAGED_FORWARDING_FACADES.has(forwarding) ||
    CLAIMED_FORWARDING_FACADES.has(forwarding)
  ) {
    invalid()
  }
  const claim = Object.freeze({})
  state.phase = 'CLAIMING'
  state.publicationClaim = claim
  state.claimingReentered = false
  let complete = false
  try {
    const facade = validForwardingFacade(forwarding)
    if (
      state.claimingReentered ||
      STAGED_FORWARDING_FACADES.has(forwarding) ||
      CLAIMED_FORWARDING_FACADES.has(forwarding)
    ) {
      invalid()
    }
    STAGED_FORWARDING_FACADES.set(forwarding, facade)
    M3_FORWARDING_PUBLICATION_CLAIMS.set(claim, {
      plan,
      state,
      forwarding,
      forwardingDestroy: facade.destroy,
      lease: null,
      phase: 'OPEN'
    })
    state.claimingReentered = false
    state.phase = 'OPEN'
    complete = true
    return claim
  } finally {
    if (!complete) {
      if (state.publicationClaim === claim) state.publicationClaim = null
      state.claimingReentered = false
      if (state.phase === 'CLAIMING') state.phase = 'OPEN'
    }
  }
}

function stageM3TailForwardingInstall(
  transportOwner,
  nextRuntime,
  serviceIdentity,
  maxCircuits,
  current,
  forwarding
) {
  const transport = safeObject(transportOwner)
    ? M3_TAIL_CONTROL_TRANSPORTS.get(transportOwner)
    : null
  if (!transport || transport.runtimeState.cleared) invalid()
  const plan = beginM3Install(transport.runtime, nextRuntime)
  let complete = false
  try {
    validateM3Install(plan, serviceIdentity, maxCircuits, current)
    const claim = createM3ForwardingPublicationClaim(plan, forwarding)
    complete = true
    return claim
  } finally {
    if (!complete) abortM3Install(plan)
  }
}

function validForwardingFacade(value) {
  if (!safeObject(value)) invalid()
  let keys
  let diagnosticsDescriptor
  let destroyDescriptor
  let frozen
  try {
    keys = reflectOwnKeys(value)
    diagnosticsDescriptor = getOwnPropertyDescriptor(value, 'diagnostics')
    destroyDescriptor = getOwnPropertyDescriptor(value, 'destroy')
    frozen = Object.isFrozen(value)
  } catch {
    invalid()
  }
  if (
    !frozen ||
    keys.length !== 2 ||
    !keys.includes('diagnostics') ||
    !keys.includes('destroy') ||
    !diagnosticsDescriptor ||
    !destroyDescriptor ||
    !Object.prototype.hasOwnProperty.call(diagnosticsDescriptor, 'value') ||
    !Object.prototype.hasOwnProperty.call(destroyDescriptor, 'value') ||
    typeof diagnosticsDescriptor.value !== 'function' ||
    typeof destroyDescriptor.value !== 'function'
  ) {
    invalid()
  }
  return Object.freeze({
    diagnostics: diagnosticsDescriptor.value,
    destroy: destroyDescriptor.value,
    terminalState: M3_RELAY_FORWARDING_STATES.get(value) || null
  })
}

function spendM3TailForwardingLeaseOwner(lease) {
  if (!lease || lease.ownerSpent) return false
  lease.ownerSpent = true
  const destroy = lease.ownerDestroy
  lease.ownerDestroy = null
  lease.lifetime = null
  try {
    destroy()
  } catch {}
  return true
}

function createM3TailForwardingLease(transportOwner, lifetime, ownerDestroy, publicationClaim) {
  const claim = safeObject(publicationClaim)
    ? M3_FORWARDING_PUBLICATION_CLAIMS.get(publicationClaim)
    : null
  const transport = safeObject(transportOwner)
    ? M3_TAIL_CONTROL_TRANSPORTS.get(transportOwner)
    : null
  if (
    !claim ||
    claim.phase !== 'OPEN' ||
    !transport ||
    transport.runtime !== claim.state.previousRuntime ||
    transport.runtimeState !== claim.state.previous ||
    lifetime !== transport.deadline ||
    typeof ownerDestroy !== 'function'
  ) {
    invalid()
  }
  const lease = Object.freeze({})
  M3_TAIL_FORWARDING_LEASES.set(lease, {
    claim: publicationClaim,
    state: claim.state,
    transportOwner,
    lifetime,
    ownerDestroy,
    deadline: transport.deadline,
    clockIdentity: transport.clockIdentity,
    ownerSpent: false,
    phase: 'OPEN'
  })
  claim.lease = lease
  releaseM3TailControlTransport(transportOwner)
  return lease
}

function publishM3TailForwarding(publicationClaim, m3ForwardingLease, forwarding) {
  const claim = safeObject(publicationClaim)
    ? M3_FORWARDING_PUBLICATION_CLAIMS.get(publicationClaim)
    : null
  const lease = safeObject(m3ForwardingLease)
    ? M3_TAIL_FORWARDING_LEASES.get(m3ForwardingLease)
    : null
  const staged = STAGED_FORWARDING_FACADES.get(forwarding)
  if (
    !claim ||
    !lease ||
    !staged ||
    claim.phase !== 'OPEN' ||
    lease.phase !== 'OPEN' ||
    lease.claim !== publicationClaim ||
    claim.forwarding !== forwarding
  ) {
    invalid()
  }
  const state = claim.state
  const owner = AUTHORITY_STATES.get(state.previous.authority)
  if (!owner) destroyed()
  const runtimeExpiresAt =
    state.previous.expiresAt < state.next.expiresAt
      ? state.previous.expiresAt
      : state.next.expiresAt
  const expiresAt =
    lease.deadline.wireExpiresAt < runtimeExpiresAt
      ? lease.deadline.wireExpiresAt
      : runtimeExpiresAt
  const previousDeadline = shortenedLocalDeadline(state.previous, expiresAt)
  const nextDeadline = shortenedLocalDeadline(state.next, expiresAt)
  state.phase = 'PUBLISHING'
  claim.phase = 'PUBLISHING'
  lease.phase = 'PUBLISHING'
  let forwardingOwner = null
  try {
    STAGED_FORWARDING_FACADES.delete(forwarding)
    M3_RELAY_FORWARDING_STATES.delete(forwarding)
    CLAIMED_FORWARDING_FACADES.add(forwarding)
    forwardingOwner = createM3ForwardingOwnerFromFacade(staged)
    const forwardingState = FORWARDING_OWNERS.get(forwardingOwner)
    const wallCurrent = sampleWallNow(owner)
    const localCurrent = sampleMonotonicNow(owner)
    if (
      expiresAt <= wallCurrent ||
      previousDeadline <= localCurrent ||
      nextDeadline <= localCurrent
    ) {
      unavailable()
    }
    rearmShorterRuntime(state.previous, expiresAt, previousDeadline, localCurrent)
    rearmShorterRuntime(state.next, expiresAt, nextDeadline, localCurrent)
    RUNTIMES.delete(state.previousRuntime)
    RUNTIMES.delete(state.nextRuntime)
    MOVED_RUNTIMES.add(state.previousRuntime)
    MOVED_RUNTIMES.add(state.nextRuntime)
    state.previous.installing = false
    state.next.installing = false
    state.previous.expiresAt = expiresAt
    state.next.expiresAt = expiresAt
    state.previous.reservation.forwardingOwner = forwardingOwner
    state.next.reservation.forwardingOwner = forwardingOwner
    forwardingState.pair = { previous: state.previous, next: state.next }
    claim.phase = 'PUBLISHED'
    lease.phase = 'PUBLISHED'
    state.phase = 'PUBLISHED'
    INSTALL_PLANS.delete(claim.plan)
    M3_FORWARDING_PUBLICATION_CLAIMS.delete(publicationClaim)
    const publication = Object.freeze({})
    const publicationState = {
      publication,
      claim: publicationClaim,
      lease: m3ForwardingLease,
      taken: null,
      forwardingOwner,
      facade: forwardingState.facade,
      phase: 'OPEN',
      leaseRecord: lease
    }
    M3_TAIL_FORWARDING_PUBLICATIONS.set(publication, publicationState)
    forwardingState.publication = publicationState
    armM3ForwardingOwnerTerminal(forwardingOwner, forwardingState)
    return publication
  } catch (err) {
    claim.phase = 'FAILED'
    lease.phase = 'FAILED'
    M3_FORWARDING_PUBLICATION_CLAIMS.delete(publicationClaim)
    M3_TAIL_FORWARDING_LEASES.delete(m3ForwardingLease)
    if (!forwardingOwner) destroyStagedM3ForwardingFacade(forwarding)
    spendM3TailForwardingLeaseOwner(lease)
    failCommittingInstall(claim.plan, state, forwardingOwner)
    if (err instanceof PrivateRouteError) throw err
    unavailable()
  }
}

function takeM3TailForwardingPublication(publication, m3ForwardingLease, publicationClaim) {
  const state = safeObject(publication) ? M3_TAIL_FORWARDING_PUBLICATIONS.get(publication) : null
  if (
    !state ||
    state.phase !== 'OPEN' ||
    state.lease !== m3ForwardingLease ||
    state.claim !== publicationClaim ||
    !FORWARDING_OWNERS.has(state.forwardingOwner)
  ) {
    invalid()
  }
  M3_TAIL_FORWARDING_PUBLICATIONS.delete(publication)
  M3_TAIL_FORWARDING_LEASES.delete(m3ForwardingLease)
  const taken = Object.freeze({
    m3ForwardingOwner: state.forwardingOwner,
    m3ForwardingLease,
    publicationClaim,
    forwarding: state.facade
  })
  TAKEN_M3_TAIL_FORWARDING_PUBLICATIONS.set(taken, state)
  state.taken = taken
  state.phase = 'TAKEN'
  return taken
}

function revokeM3TailForwardingLease(m3ForwardingLease) {
  const lease = safeObject(m3ForwardingLease)
    ? M3_TAIL_FORWARDING_LEASES.get(m3ForwardingLease)
    : null
  if (!lease || lease.phase !== 'OPEN') return false
  const claim = M3_FORWARDING_PUBLICATION_CLAIMS.get(lease.claim)
  lease.phase = 'REVOKED'
  M3_TAIL_FORWARDING_LEASES.delete(m3ForwardingLease)
  spendM3TailForwardingLeaseOwner(lease)
  if (claim && claim.phase === 'OPEN') {
    claim.phase = 'REVOKED'
    destroyStagedM3ForwardingFacade(claim.forwarding)
    M3_FORWARDING_PUBLICATION_CLAIMS.delete(lease.claim)
    abortM3Install(claim.plan)
  }
  return true
}

function destroyM3TailForwardingPublication(publication) {
  const state = safeObject(publication)
    ? M3_TAIL_FORWARDING_PUBLICATIONS.get(publication) ||
      TAKEN_M3_TAIL_FORWARDING_PUBLICATIONS.get(publication)
    : null
  if (!state || state.phase === 'DESTROYED') return false
  const ownerState = FORWARDING_OWNERS.get(state.forwardingOwner)
  return destroyM3ForwardingOwnerState(state.forwardingOwner, ownerState, state)
}

function shortenedLocalDeadline(state, wireExpiresAt) {
  if (!u64(wireExpiresAt) || wireExpiresAt === 0n || wireExpiresAt > state.wireExpiresAt) {
    invalid()
  }
  const reduction = state.wireExpiresAt - wireExpiresAt
  if (reduction >= state.localDeadline) unavailable()
  return state.localDeadline - reduction
}

function destroyFailedInstall(plan) {
  RUNTIMES.delete(plan.previousRuntime)
  RUNTIMES.delete(plan.nextRuntime)
  DESTROYED_RUNTIMES.add(plan.previousRuntime)
  DESTROYED_RUNTIMES.add(plan.nextRuntime)
  clearRuntimeState(plan.previous)
  clearRuntimeState(plan.next)
}

function rearmShorterRuntime(state, wireExpiresAt, localDeadline, current) {
  if (localDeadline >= state.localDeadline) return
  cancelRuntimeTimer(state)
  state.wireExpiresAt = wireExpiresAt
  state.expiresAt = wireExpiresAt
  state.localDeadline = localDeadline
  armRuntimeState(state, timerDelay(localDeadline - current))
}

function failCommittingInstall(plan, state, forwardingOwner) {
  INSTALL_PLANS.delete(plan)
  state.phase = 'FAILED'
  if (forwardingOwner) destroyM3ForwardingOwner(forwardingOwner)
  destroyFailedInstall(state)
}

function commitM3Install(plan, expiresAt, forwarding) {
  const state = safeObject(plan) ? INSTALL_PLANS.get(plan) : null
  if (
    !state ||
    state.phase !== 'OPEN' ||
    !state.validated ||
    !state.previous.installing ||
    !state.next.installing ||
    RUNTIMES.get(state.previousRuntime) !== state.previous ||
    RUNTIMES.get(state.nextRuntime) !== state.next
  ) {
    invalid()
  }
  const owner = AUTHORITY_STATES.get(state.previous.authority)
  if (!owner) destroyed()
  const previousDeadline = shortenedLocalDeadline(state.previous, expiresAt)
  const nextDeadline = shortenedLocalDeadline(state.next, expiresAt)
  state.phase = 'COMMITTING'
  let forwardingOwner = null
  try {
    forwardingOwner = createM3ForwardingOwner(forwarding)
    const forwardingState = FORWARDING_OWNERS.get(forwardingOwner)
    const wallCurrent = sampleWallNow(owner)
    const localCurrent = sampleMonotonicNow(owner)
    if (
      expiresAt <= wallCurrent ||
      previousDeadline <= localCurrent ||
      nextDeadline <= localCurrent
    ) {
      unavailable()
    }
    rearmShorterRuntime(state.previous, expiresAt, previousDeadline, localCurrent)
    rearmShorterRuntime(state.next, expiresAt, nextDeadline, localCurrent)
    RUNTIMES.delete(state.previousRuntime)
    RUNTIMES.delete(state.nextRuntime)
    MOVED_RUNTIMES.add(state.previousRuntime)
    MOVED_RUNTIMES.add(state.nextRuntime)
    state.previous.installing = false
    state.next.installing = false
    state.previous.expiresAt = expiresAt
    state.next.expiresAt = expiresAt
    state.previous.reservation.forwardingOwner = forwardingOwner
    state.next.reservation.forwardingOwner = forwardingOwner
    forwardingState.pair = { previous: state.previous, next: state.next }
    armM3ForwardingOwnerTerminal(forwardingOwner, forwardingState)
    state.phase = 'COMMITTED'
    INSTALL_PLANS.delete(plan)
    return forwardingState.facade
  } catch (err) {
    failCommittingInstall(plan, state, forwardingOwner)
    if (err instanceof PrivateRouteError) throw err
    unavailable()
  }
}

function registerM3RuntimePhysicalLossSink(runtime, sink) {
  const state = safeObject(runtime) ? RUNTIMES.get(runtime) : null
  if (
    !state ||
    state.cleared ||
    state.installing ||
    state.physicalLossRegistration ||
    typeof sink !== 'function'
  ) {
    invalid()
  }
  const registration = Object.freeze({})
  const record = {
    registration,
    state,
    sink,
    udxRegistration: null
  }
  state.physicalLossRegistration = record
  M3_RUNTIME_PHYSICAL_LOSS_REGISTRATIONS.set(registration, record)
  try {
    const { registerM3CellLinkPhysicalLossSink } = require('./udx-cell-endpoint')
    record.udxRegistration = registerM3CellLinkPhysicalLossSink(state.physicalChannel, () =>
      issueM3RuntimePhysicalLoss(registration)
    )
    return registration
  } catch (err) {
    M3_RUNTIME_PHYSICAL_LOSS_REGISTRATIONS.delete(registration)
    if (state.physicalLossRegistration === record) state.physicalLossRegistration = null
    record.state = null
    record.sink = null
    throw err
  }
}

function revokeM3RuntimePhysicalLossSink(registration) {
  const record = safeObject(registration)
    ? M3_RUNTIME_PHYSICAL_LOSS_REGISTRATIONS.get(registration)
    : null
  if (!record || !record.state || record.state.physicalLossRegistration !== record) return false
  return revokeM3RuntimePhysicalLossState(record.state)
}
module.exports = {
  DEFAULT_MAX_M3_ADJACENCY_RUNTIMES,
  MAX_M3_ADJACENCY_RUNTIMES,
  TEST_ONLY_M3_ADJACENCY_OBSERVER,
  deriveM3CellIds,
  M3AdjacencyAuthority,
  isM3AdjacencyAuthority,
  revokeM3TailCapability,
  consumeTailResponderToken,
  revokeTailResponderToken,
  takeM3TailCapability,
  shortenM3TailOperationDeadline,
  projectM3TailWireDeadline,
  sendM3TailControl,
  receiveM3TailControl,
  takeM3ReceivedEnvelope,
  releaseM3ReceivedEnvelope,
  releaseM3TailControlTransport,
  takeM3InitiatorRuntime,
  takeM3RouteTransport,
  reserveM3RouteFrame,
  sendM3RouteFrame,
  scheduleM3RouteTransportTimer,
  receiveM3RouteFrame,
  receiveReservedM3RouteFrame,
  cancelM3RouteFrameReservation,
  destroyM3RouteTransport,
  readM3RouteTransportDiagnostics,
  createM3RelayForwardingFacade,
  beginM3Install,
  validateM3Install,
  abortM3Install,
  createM3ForwardingPublicationClaim,
  stageM3TailForwardingInstall,
  createM3TailForwardingLease,
  publishM3TailForwarding,
  takeM3TailForwardingPublication,
  revokeM3TailForwardingLease,
  destroyM3TailForwardingPublication,
  registerM3RuntimePhysicalLossSink,
  revokeM3RuntimePhysicalLossSink,
  commitM3Install
}
