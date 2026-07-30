const b4a = require('b4a')

const { CELL_SIZE, CellCodec } = require('./cell-codec')
const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')
const { destroyTakenM3EstablishedLink, takeM3EstablishedLink } = require('./guard-link')
const { createM3ResponderAdopter } = require('./m3-adjacency-adopter')
const { BRANCH_CLASS, CELL_CLASS, DIRECTION } = require('./protocol')

const DEFAULT_MAX_M3_ADJACENCY_RUNTIMES = 128
const MAX_M3_ADJACENCY_RUNTIMES = 4096
const MAX_TIMER_DELAY = 0x7fff_ffff
const TEST_ONLY_M3_ADJACENCY_OBSERVER = Symbol('test-only-m3-adjacency-observer')

const INITIATOR_CELL_ID_DOMAIN = b4a.from('hyperdht-private-routes/m3/cell-id/initiator/v1')
const RESPONDER_CELL_ID_DOMAIN = b4a.from('hyperdht-private-routes/m3/cell-id/responder/v1')
const AUTHORITIES = new WeakSet()
const AUTHORITY_STATES = new WeakMap()
const RUNTIMES = new WeakMap()
const DESTROYED_RUNTIMES = new WeakSet()
const MOVED_RUNTIMES = new WeakSet()
const TAILS = new WeakMap()
const SPENT_TAILS = new WeakSet()
const TAIL_RESPONDER_TOKENS = new WeakMap()
const SPENT_TAIL_RESPONDER_TOKENS = new WeakSet()
const CONSUMED_TAIL_RESPONDER_TOKENS = new WeakMap()
const TAIL_RESPONDER_BINDINGS = new WeakMap()
const M3_TAIL_CONTROL_TRANSPORTS = new WeakMap()
const FORWARDING_OWNERS = new WeakMap()
const INSTALL_PLANS = new WeakMap()
const CLAIMED_FORWARDING_FACADES = new WeakSet()
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
  const localDeadline = monotonic + remaining
  if (!u64(localDeadline) || localDeadline <= monotonic) unavailable()
  return {
    current: monotonic,
    delay: timerDelay(remaining),
    deadline: Object.freeze({
      wireExpiresAt,
      localDeadline,
      clockIdentity: owner.clockIdentity
    })
  }
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
  if (state.transportOwner) M3_TAIL_CONTROL_TRANSPORTS.delete(state.transportOwner)
  state.transportOwner = null
  state.used = true
}

function shortenM3TailLifetime(state, localDeadline) {
  if (!safeObject(state) || !safeObject(state.deadline) || !u64(localDeadline)) invalid()
  const current = state.deadline
  if (localDeadline === 0n || localDeadline > current.localDeadline) invalid()
  if (localDeadline === current.localDeadline) return current
  const delta = current.localDeadline - localDeadline
  const wireExpiresAt = current.wireExpiresAt - delta
  if (!u64(wireExpiresAt) || wireExpiresAt === 0n) invalid()
  state.deadline = Object.freeze({
    wireExpiresAt,
    localDeadline,
    clockIdentity: current.clockIdentity
  })
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

function receiveM3TailControl(owner) {
  const state = tailControlTransportRuntimeState(owner)
  const channel = state.physicalChannel
  if (!safeObject(channel) || typeof channel.receive !== 'function') invalid()
  return Promise.resolve()
    .then(() => channel.receive())
    .then((packet) => {
      let envelope = null
      let complete = false
      try {
        if (tailControlTransportRuntimeState(owner) !== state) invalid()
        const opened = state.runtime.openTail(packet)
        if (!Array.isArray(opened) || opened.length !== 1 || !fixed(opened[0], 1101)) invalid()
        envelope = opened[0]
        if (tailControlTransportRuntimeState(owner) !== state) invalid()
        registerM3ReceivedEnvelope(owner, state, envelope)
        const result = envelope
        envelope = null
        complete = true
        return result
      } finally {
        clear(envelope)
        if (!complete) clear(packet)
      }
    })
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
    state.deadline.localDeadline > 0n &&
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

function detachRuntimeState(state) {
  if (!state || state.cleared) return null
  state.cleared = true
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
        localDeadline: projection.deadline.localDeadline,
        installing: false,
        pendingTailSecret: tailSecret,
        pendingTailTranscript: tailTranscript,
        reservation,
        runtime,
        tail,
        timer: null,
        timerGeneration: 0
      }
      reservation.runtimeState = runtimeValue
      armRuntimeState(runtimeValue, projection.delay)
      const tailState = {
        initiator: state.initiator,
        secret: runtimeValue.pendingTailSecret,
        transcript: runtimeValue.pendingTailTranscript,
      transportOwner: Object.freeze({}),
        deadline: projection.deadline,
        binding: null,
        used: false
      }
      M3_TAIL_CONTROL_TRANSPORTS.set(tailState.transportOwner, {
        runtime,
        runtimeState: runtimeValue
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
      RUNTIMES.set(runtime, runtimeValue)
      TAILS.set(tail, tailState)
      runtimeValue.pendingTailSecret = null
      runtimeValue.pendingTailTranscript = null
      adopted = true
      return Object.freeze(responderToken ? { runtime, tail, responderToken } : { runtime, tail })
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

function takeForwardingFacade(forwarding) {
  if (!safeObject(forwarding) || CLAIMED_FORWARDING_FACADES.has(forwarding)) invalid()
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
  return {
    diagnostics: diagnosticsDescriptor.value,
    destroy: destroyDescriptor.value
  }
}

function createM3ForwardingOwner(forwarding) {
  const taken = takeForwardingFacade(forwarding)
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
    facade
  })
  return capability
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

function destroyM3ForwardingOwner(capability) {
  const state = FORWARDING_OWNERS.get(capability)
  if (!state || state.destroying) return false
  FORWARDING_OWNERS.delete(capability)
  state.destroying = true
  const destroy = state.destroy
  const pair = state.pair
  state.destroy = null
  state.diagnostics = null
  state.pair = null
  try {
    try {
      destroy()
    } catch {}
  } finally {
    releaseInstalledPair(pair)
    state.destroying = false
  }
  return true
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
    validated: false
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
  return true
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
    state.phase = 'COMMITTED'
    INSTALL_PLANS.delete(plan)
    return forwardingState.facade
  } catch (err) {
    failCommittingInstall(plan, state, forwardingOwner)
    if (err instanceof PrivateRouteError) throw err
    unavailable()
  }
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
  shortenM3TailLifetime,
  sendM3TailControl,
  receiveM3TailControl,
  takeM3ReceivedEnvelope,
  releaseM3ReceivedEnvelope,
  releaseM3TailControlTransport,
  beginM3Install,
  validateM3Install,
  abortM3Install,
  commitM3Install
}
