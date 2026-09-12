'use strict'

const b4a = require('b4a')

const { CELL_SIZE, CellCodec } = require('./cell-codec')
const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')
const { chargePeerLedger } = require('./peer-ledger')
const { encodePeerContextEnvelope, decodePeerContextEnvelope } = require('./peer-m3-context')
const { CELL_CLASS, DIRECTION, PROTOCOL_VERSION } = require('./protocol')
const { PEER_MESSAGE_ID } = require('./peer-protocol')
const { encodePeerTransport, decodePeerTransport } = require('./peer-transport-wire')
const { LINK_CIRCUIT_TEARDOWN_TIMEOUT, LINK_PING_AFTER } = require('./link-control-session')

const CLOSURE_MODE = Object.freeze({
  NONE: 'NONE',
  DESTROY: 'DESTROY',
  TEARDOWN: 'TEARDOWN'
})

const CLOSURE_STATE = Object.freeze({
  LIVE: 'LIVE',
  DRAINING: 'DRAINING',
  ACK_CACHED: 'ACK_CACHED',
  PHYSICALLY_CLOSING: 'PHYSICALLY_CLOSING',
  CLOSED: 'CLOSED'
})

const CLOSURE_ROLE = Object.freeze({
  NONE: 'NONE',
  INITIATOR: 'INITIATOR',
  RESPONDER: 'RESPONDER'
})

const MAX_TEARDOWN_ATTEMPTS = 10
const MAX_DESTROY_ATTEMPTS = 8
const CLOSURE_SEND_TOKENS = new WeakMap()
const PEER_TAIL_CONTROL_CONTEXT_CLASS = 1
const PEER_TAIL_FINALIZE_CONTEXT_CLASS = 5
const PEER_ROUTE_CONTEXT_CLASS = 6
const DEFAULT_MAX_M3_ADJACENCY_RUNTIMES = 128
const MAX_M3_ADJACENCY_RUNTIMES = 4096
const MAX_TIMER_DELAY = 0x7fff_ffff
const TEST_ONLY_M3_ADJACENCY_OBSERVER = Symbol('test-only-m3-adjacency-observer')

const ROUTE_FRAME_RESIDENCY_LIMIT = 64

const AUTHORITIES = new WeakSet()
const AUTHORITY_STATES = new WeakMap()
const RUNTIMES = new WeakMap()
const DESTROYED_RUNTIMES = new WeakSet()
const MOVED_RUNTIMES = new WeakSet()
const PHYSICAL_LOSS_REGISTRATIONS = new WeakMap()
const FORWARDING_OWNERS = new WeakMap()
const ROUTE_CARRIER_AUTHORIZATIONS = new WeakMap()
const TAKEN_ROUTE_CARRIER_OWNERS = new WeakSet()
const FINAL_CARRIER_TAKES = new WeakMap()
const CARRIER_RECEIVE_RESERVATIONS = new WeakMap()

const bufferByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
const bufferSet = Uint8Array.prototype.set

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function unavailable() {
  throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
}

function authentication() {
  throw PrivateRouteError.ERR_AUTHENTICATION()
}

function replay() {
  throw PrivateRouteError.ERR_REPLAY()
}

function destroyed() {
  throw PrivateRouteError.ERR_DESTROYED()
}

function busy() {
  throw PrivateRouteError.ERR_BUSY()
}

function unauthorized() {
  throw PrivateRouteError.UNAUTHORIZED()
}

function safeObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function length(value) {
  try {
    return bufferByteLength.call(value)
  } catch {
    return -1
  }
}

function fixed(value, size) {
  return length(value) === size
}

function clear(value) {
  try {
    if (value && typeof value.fill === 'function') value.fill(0)
  } catch {}
}

function copy(value, size) {
  if (size !== undefined && length(value) !== size) invalid()
  const len = size !== undefined ? size : length(value)
  if (len < 0) invalid()
  const result = b4a.allocUnsafeSlow(len)
  bufferSet.call(result, value, 0)
  return result
}

function u64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= 0xffff_ffff_ffff_ffffn
}

function timerDelay(remaining) {
  if (remaining <= 0n) return 0
  return remaining > BigInt(MAX_TIMER_DELAY) ? MAX_TIMER_DELAY : Number(remaining)
}

function releaseM3RoutePacket(packet) {
  let released = false
  try {
    const { releaseM3CellLinkPacket } = require('./udx-cell-endpoint')
    if (typeof releaseM3CellLinkPacket === 'function') {
      released = releaseM3CellLinkPacket(packet) === true
    }
  } catch {}
  if (!released) clear(packet)
}

function nonzero(buffer) {
  if (!buffer) return false
  for (let i = 0; i < buffer.length; i++) {
    if (buffer[i] !== 0) return true
  }
  return false
}

function readPeerUint16(buffer, offset) {
  return (buffer[offset] << 8) | buffer[offset + 1]
}

function readPeerUint32(buffer, offset) {
  return (
    buffer[offset] * 0x1000000 +
    (buffer[offset + 1] << 16) +
    (buffer[offset + 2] << 8) +
    buffer[offset + 3]
  )
}

function isClosureWire(payload) {
  if (!payload || length(payload) < 6) return false
  if (readPeerUint32(payload, 0) !== 2) return false
  const msgId = readPeerUint16(payload, 4)
  return msgId >= 0x030e && msgId <= 0x0310
}

function isClosureObject(payload) {
  if (!payload) return false
  if (safeObject(payload)) {
    if (
      typeof payload.messageId === 'number' &&
      payload.messageId >= 0x030e &&
      payload.messageId <= 0x0310
    ) {
      return true
    }
    if (b4a.isBuffer(payload.payload) && isClosureWire(payload.payload)) return true
    if (
      safeObject(payload.payload) &&
      typeof payload.payload.messageId === 'number' &&
      payload.payload.messageId >= 0x030e &&
      payload.payload.messageId <= 0x0310
    ) {
      return true
    }
  }
  if (b4a.isBuffer(payload) && isClosureWire(payload)) return true
  return false
}

function getOrCreateClosureDispatchOwner(state, mode, deadline) {
  if (state.closureDispatchOwner) return state.closureDispatchOwner
  const dispatchOwner = {
    active: true,
    now() {
      return state.monotonicNow()
    },
    deadline,
    records: new Set(),
    onDispatch() {
      if (
        !dispatchOwner.active ||
        state.closureDutyEnded ||
        state.closureMode !== mode ||
        typeof state.monotonicNow !== 'function' ||
        typeof state.wallNow !== 'function'
      ) {
        return false
      }
      const mono = state.monotonicNow()
      const wall = state.wallNow()
      if (
        typeof mono !== 'bigint' ||
        typeof wall !== 'bigint' ||
        mono >= deadline ||
        mono >= state.localDeadline ||
        wall >= state.wireExpiresAt
      ) {
        return false
      }
      return true
    }
  }
  state.closureDispatchOwner = dispatchOwner
  return dispatchOwner
}

function mintPeerM3ClosureToken(state, packet, mode, deadline) {
  const token = Object.freeze({})
  CLOSURE_SEND_TOKENS.set(token, {
    packet,
    ledger: state.teardownSendLedger,
    transfer: state.physicalChannel,
    state,
    mode,
    deadline,
    dispatchOwner: getOrCreateClosureDispatchOwner(state, mode, deadline)
  })
  return token
}

function takePeerM3ClosureSendPermit(token, transfer) {
  if (!safeObject(token) || !CLOSURE_SEND_TOKENS.has(token)) {
    unauthorized()
  }
  const entry = CLOSURE_SEND_TOKENS.get(token)
  if (entry.transfer !== transfer) {
    unauthorized()
  }
  CLOSURE_SEND_TOKENS.delete(token)

  return {
    packet: entry.packet,
    ledger: entry.ledger,
    dispatchOwner: entry.dispatchOwner
  }
}

function sendClosurePacket(state, wirePayload, mode, deadline) {
  if ((state.cleared && state.closureDutyEnded) || !state.physicalChannel) {
    return Promise.reject(PrivateRouteError.ERR_DESTROYED())
  }
  let packet = null
  try {
    packet = state.codec.seal({
      key: state.contexts[CELL_CLASS.DATAGRAM].tx.key,
      noncePrefix: state.contexts[CELL_CLASS.DATAGRAM].tx.noncePrefix,
      senderCounter: state.contexts[CELL_CLASS.DATAGRAM].tx.counter,
      class: CELL_CLASS.DATAGRAM,
      direction: state.initiator ? DIRECTION.FORWARD : DIRECTION.REVERSE,
      epoch: state.generation,
      circuitId: state.peerLocalId,
      payload: wirePayload
    })
  } catch (err) {
    return Promise.reject(err)
  }

  const token = mintPeerM3ClosureToken(state, packet, mode, deadline)
  let sendPromise = null
  try {
    if (typeof state.physicalChannel.sendClosure === 'function') {
      sendPromise = Promise.resolve(state.physicalChannel.sendClosure(token))
    } else {
      sendPromise = Promise.reject(PrivateRouteError.UNAUTHORIZED())
    }
  } catch (err) {
    sendPromise = Promise.reject(err)
  }

  const retainedPacket = packet
  state.retainedPackets.add(retainedPacket)
  const held = { packet: retainedPacket, promise: sendPromise }
  state.heldSends.add(held)

  sendPromise
    .finally(() => {
      state.heldSends.delete(held)
    })
    .catch(() => {})

  return sendPromise
}

function getTakePeerEstablishedLink() {
  try {
    const peerGuard = require('./peer-guard-link')
    if (typeof peerGuard.takePeerEstablishedLink === 'function') {
      return peerGuard.takePeerEstablishedLink
    }
  } catch {}
  return null
}

function getDestroyTakenPeerEstablishedLink() {
  try {
    const peerGuard = require('./peer-guard-link')
    if (typeof peerGuard.destroyTakenPeerEstablishedLink === 'function') {
      return peerGuard.destroyTakenPeerEstablishedLink
    }
  } catch {}
  return null
}

function getTakePeerEstablishedProof() {
  try {
    const peerGuard = require('./peer-guard-link')
    if (typeof peerGuard.takePeerEstablishedProof === 'function') {
      return peerGuard.takePeerEstablishedProof
    }
  } catch {}
  return null
}

function getRegisterPeerM3CellLinkTransfer() {
  try {
    const udxEndpoint = require('./udx-cell-endpoint')
    if (typeof udxEndpoint.registerPeerM3CellLinkTransfer === 'function') {
      return udxEndpoint.registerPeerM3CellLinkTransfer
    }
  } catch {}
  return null
}

function getNativePhysicalLossRegistration() {
  try {
    const udxEndpoint = require('./udx-cell-endpoint')
    if (
      typeof udxEndpoint.registerM3CellLinkPhysicalLossSink === 'function' &&
      typeof udxEndpoint.revokeM3CellLinkPhysicalLossSink === 'function'
    ) {
      return {
        register: udxEndpoint.registerM3CellLinkPhysicalLossSink,
        revoke: udxEndpoint.revokeM3CellLinkPhysicalLossSink
      }
    }
  } catch {}
  return null
}

function clearContextPair(pair) {
  if (!pair) return
  if (pair.tx) {
    clear(pair.tx.key)
    clear(pair.tx.noncePrefix)
    if (pair.tx.counter && typeof pair.tx.counter.destroy === 'function') {
      try {
        pair.tx.counter.destroy()
      } catch {}
    }
  }
  if (pair.rx) {
    clear(pair.rx.key)
    clear(pair.rx.noncePrefix)
    if (pair.rx.counter && typeof pair.rx.counter.destroy === 'function') {
      try {
        pair.rx.counter.destroy()
      } catch {}
    }
  }
}

function clearContexts(contexts) {
  if (!contexts) return
  for (const key of [0, 2, '0', '2']) {
    if (contexts[key]) {
      clearContextPair(contexts[key])
    }
  }
}

function sealTailState(state, options) {
  let cellClass
  let payload
  try {
    cellClass = options.class
    payload = options.payload
  } catch {
    invalid()
  }

  if (cellClass !== CELL_CLASS.CONTROL && cellClass !== CELL_CLASS.DATAGRAM) {
    invalid()
  }

  const context = state.contexts[cellClass] && state.contexts[cellClass].tx
  if (!context) invalid()

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

function openTailState(state, packet) {
  if (!fixed(packet, CELL_SIZE)) invalid()
  const cellClass = packet[1]
  if (cellClass !== CELL_CLASS.CONTROL && cellClass !== CELL_CLASS.DATAGRAM) {
    invalid()
  }

  const context = state.contexts[cellClass] && state.contexts[cellClass].rx
  if (!context) invalid()

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

class PeerM3AdjacencyRuntime {
  sealTail(options) {
    const state = RUNTIMES.get(this)
    if (!state || state.cleared) destroyed()
    checkRuntimeTime(state)
    return sealTailState(state, options)
  }

  openTail(packet) {
    const state = RUNTIMES.get(this)
    if (!state || state.cleared) destroyed()
    checkRuntimeTime(state)
    return openTailState(state, packet)
  }
  diagnostics() {
    const state = RUNTIMES.get(this)
    if (!state || state.cleared) destroyed()
    checkRuntimeTime(state)
    return Object.freeze({
      state: state.closureStatus === CLOSURE_STATE.LIVE ? 'TAIL_ENDPOINT' : state.closureStatus,
      closureMode: state.closureMode,
      generation: state.generation,
      wireExpiresAt: state.wireExpiresAt,
      localDeadline: state.localDeadline,
      active: !state.cleared
    })
  }

  destroy() {
    return destroyPeerM3Runtime(this)
  }
}

function checkRuntimeTime(state) {
  if (state.cleared) destroyed()
  const now = state.monotonicNow()
  if (state.cleared) destroyed()
  if (typeof now !== 'bigint' || now >= state.localDeadline) {
    destroyRuntimeState(state, { source: 'expired' })
    destroyed()
  }
}

function clearTeardownRetryTimer(state) {
  if (state.teardownTimer !== null && state.clearTimer) {
    try {
      state.clearTimer(state.teardownTimer)
    } catch {}
    state.teardownTimer = null
  }
}

function clearTeardownAckRetryTimer(state) {
  if (state.ackTimer !== null && state.clearTimer) {
    try {
      state.clearTimer(state.ackTimer)
    } catch {}
    state.ackTimer = null
  }
}

function armTeardownAckRetryTimer(state) {
  // Responder ACK duty: at most MAX_TEARDOWN_ATTEMPTS local directional attempts
  // (including timer and duplicate triggers), original fixed deadline, LINK_PING_AFTER cadence.
  const setFn = state.setTimer || (state.authorityState && state.authorityState.setTimer)
  if (!setFn) return

  clearTeardownAckRetryTimer(state)
  state.ackTimer = setFn(() => {
    state.ackTimer = null
    if (state.cleared || state.closureDutyEnded || state.closureMode !== CLOSURE_MODE.TEARDOWN) {
      return
    }
    if (
      state.teardownAttempts >= MAX_TEARDOWN_ATTEMPTS ||
      state.monotonicNow() >= state.teardownDeadline
    ) {
      // Attempt exhaustion stops sends but preserves the original bounded deadline
      // and armed cache duty: the cache timer owns the final cleanup.
      return
    }
    state.teardownAttempts++
    sendClosurePacket(state, state.teardownAckWire, CLOSURE_MODE.TEARDOWN, state.teardownDeadline)
    armTeardownAckRetryTimer(state)
  }, LINK_PING_AFTER)
}

function clearTeardownCacheDeadlineTimer(state) {
  if (state.cacheTimer !== null && state.clearTimer) {
    try {
      state.clearTimer(state.cacheTimer)
    } catch {}
    state.cacheTimer = null
  }
}

function armTeardownCacheDeadlineTimer(state) {
  const setFn = state.setTimer || (state.authorityState && state.authorityState.setTimer)
  if (!setFn) return
  const nowMono = state.monotonicNow()
  const remaining = state.teardownDeadline - nowMono
  if (remaining <= 0n) return
  const delay = timerDelay(remaining)
  state.cacheTimer = setFn(() => {
    state.cacheTimer = null
    destroyRuntimeState(state, { source: 'teardown-cache-expired' })
  }, delay)
}

function settleTeardownInitiatorSuccess(state) {
  const obligations = []
  if (state.downstreamReleaseObligation) {
    obligations.push(Promise.resolve(state.downstreamReleaseObligation))
  }
  return Promise.all(obligations)
    .then(() => {
      return destroyRuntimeState(state, { source: 'teardown-success', success: true })
    })
    .then(() => {
      if (state.initiatorTeardown && !state.initiatorTeardown.settled) {
        state.initiatorTeardown.settled = true
        state.initiatorTeardown.resolve(true)
      }
      return true
    })
    .catch(() => {
      if (state.initiatorTeardown && !state.initiatorTeardown.settled) {
        state.initiatorTeardown.settled = true
        state.initiatorTeardown.resolve(false)
      }
      return destroyRuntimeState(state, { source: 'teardown-failed' })
    })
}

function releaseFinalReadiness(state) {
  const train = state.finalReadinessTrain
  if (!train) return
  state.finalReadinessTrain = null
  train.sendAfterTake = null
  train.releaseReadiness()
}

function revokeRuntimeTraffic(state, source) {
  if (state.trafficRevoked) return
  state.trafficRevoked = true
  state.cleared = true

  if (state.runtime) {
    RUNTIMES.delete(state.runtime)
    DESTROYED_RUNTIMES.add(state.runtime)
  }
  state.establishedHandle = null
  releaseFinalReadiness(state)
  const carrierCleanup = state.carrierCleanup
  state.carrierCleanup = null
  if (carrierCleanup) carrierCleanup()

  if (state.timer !== null && state.clearTimer) {
    try {
      state.clearTimer(state.timer)
    } catch {}
    state.timer = null
  }

  if (state.physicalLossRegistration !== null) {
    const lossHooks = getNativePhysicalLossRegistration()
    if (lossHooks) {
      try {
        lossHooks.revoke(state.physicalLossRegistration)
      } catch {}
    }
    state.physicalLossRegistration = null
  }

  if (state.reservation && state.authorityState) {
    const existing = state.authorityState.reservations.get(state.reservation.key)
    if (existing === state.reservation) {
      state.authorityState.reservations.delete(state.reservation.key)
    }
    state.reservation.released = true
  }

  // Notify physicalLossSinks ONLY for actual native physical loss!
  if (source === 'physical-loss' || source === 'downstream-physical-loss') {
    if (state.physicalLossSinks) {
      const sinks = Array.from(state.physicalLossSinks)
      state.physicalLossSinks.clear()
      for (const sink of sinks) {
        try {
          sink(state.runtime)
        } catch {}
      }
    }
  }

  if (state.waiters && state.waiters.length > 0) {
    const waiters = state.waiters.splice(0)
    for (const waiter of waiters) {
      try {
        waiter.reject(PrivateRouteError.ERR_DESTROYED())
      } catch {}
    }
  }

  if (state.received && state.received.length > 0) {
    for (const entry of state.received) {
      if (entry && typeof entry === 'object') {
        clear(entry.payload)
      } else {
        clear(entry)
      }
    }
    state.received.length = 0
  }
}

function finalizeRuntimeCleanup(state) {
  if (state.finalized) return
  state.finalized = true
  state.closureStatus = CLOSURE_STATE.CLOSED

  if (state.retainedPackets) {
    for (const p of state.retainedPackets) {
      clear(p)
    }
    state.retainedPackets.clear()
  }

  if (state.contexts) {
    clearContexts(state.contexts)
    state.contexts = null
  }

  if (state.physicalChannel) {
    try {
      state.physicalChannel.destroy()
    } catch {}
  }

  clear(state.localId)
  clear(state.peerLocalId)
  clear(state.localIdentity)
  clear(state.peerIdentity)
  clear(state.branchId)
  clear(state.circuitId)
  clear(state.tailSharedSecret)
  clear(state.tailAdvertisement260)
  clear(state.tailControlTranscript)
  clear(state.successorProof378)
  clear(state.destroyWire)
  clear(state.teardownWire)
  clear(state.teardownAckWire)
  clear(state.teardownId)
  state.destroyWire = null
  state.teardownWire = null
  state.teardownAckWire = null
  state.teardownId = null
  if (state.teardownState) {
    clear(state.teardownState.teardownId)
    clear(state.teardownState.ackWire)
    state.teardownState = null
  }
}

function beginRuntimeTeardownCleanup(state, options = {}) {
  if (state.cleanupPromise) return state.cleanupPromise

  clearTeardownRetryTimer(state)
  clearTeardownCacheDeadlineTimer(state)
  clearTeardownAckRetryTimer(state)
  state.closureDutyEnded = true

  if (state.physicalChannel && typeof state.physicalChannel.cancelClosureSends === 'function') {
    try {
      state.physicalChannel.cancelClosureSends()
    } catch {}
  }

  const callerSends = []
  if (state.heldSends && state.heldSends.size > 0) {
    for (const held of state.heldSends) {
      callerSends.push(held.promise.catch(() => {}))
    }
  }
  const callerWait = Promise.all(callerSends)

  let nativeWait = Promise.resolve()
  if (state.physicalChannel && typeof state.physicalChannel.waitForClosureSends === 'function') {
    try {
      nativeWait = Promise.resolve(state.physicalChannel.waitForClosureSends()).catch(() => {})
    } catch {
      nativeWait = Promise.resolve()
    }
  }

  state.cleanupPromise = Promise.all([callerWait, nativeWait]).then(() => {
    finalizeRuntimeCleanup(state)
    if (state.initiatorTeardown && !state.initiatorTeardown.settled) {
      state.initiatorTeardown.settled = true
      state.initiatorTeardown.resolve(options.success === true)
    }
  })

  return state.cleanupPromise
}

function clearDestroyRetryTimer(state) {
  if (state.destroyRetryTimer !== null && state.clearTimer) {
    try {
      state.clearTimer(state.destroyRetryTimer)
    } catch {}
    state.destroyRetryTimer = null
  }
}

function scheduleDestroyRetryDuty(state, destroyWire, deadline) {
  // Local abrupt destroy duty: at most MAX_DESTROY_ATTEMPTS sends from the same
  // byte-frozen body through the fixed deadline. Ordinary traffic is revoked
  // immediately, but queued closure DESTROY keeps dispatching until the duty ends.
  // Only then are queued closure sends cancelled and drained.
  if (state.destroyDutyPromise) return state.destroyDutyPromise

  let resolveDuty
  let rejectDuty
  const duty = new Promise((resolve, reject) => {
    resolveDuty = resolve
    rejectDuty = reject
  })

  const finishDuty = () => {
    if (state.destroyDutyDone) return
    state.destroyDutyDone = true
    clearDestroyRetryTimer(state)
    Promise.resolve(beginRuntimeTeardownCleanup(state))
      .then(() => resolveDuty(true))
      .catch((err) => rejectDuty(err))
  }

  state.destroyDutyPromise = duty
  state.destroyAttempts = 1
  sendClosurePacket(state, destroyWire, CLOSURE_MODE.DESTROY, deadline)
  const setFn = state.setTimer || (state.authorityState && state.authorityState.setTimer)

  const retry = () => {
    if (state.destroyDutyDone || state.closureDutyEnded) return
    if (
      state.destroyAttempts >= MAX_DESTROY_ATTEMPTS ||
      typeof state.monotonicNow !== 'function' ||
      state.monotonicNow() >= deadline
    ) {
      finishDuty()
      return
    }
    if (!setFn) {
      finishDuty()
      return
    }
    state.destroyRetryTimer = setFn(() => {
      state.destroyRetryTimer = null
      if (state.destroyDutyDone || state.closureDutyEnded) return
      state.destroyAttempts++
      sendClosurePacket(state, destroyWire, CLOSURE_MODE.DESTROY, deadline)
      retry()
    }, LINK_PING_AFTER)
  }

  retry()
  return duty
}

function destroyRuntimeState(state, options = {}) {
  if (state.cleared && state.finalized) return state.cleanupPromise || Promise.resolve()
  const isExpired = options === true || (safeObject(options) && options.source === 'expired')
  const source = safeObject(options) ? options.source : isExpired ? 'expired' : 'local-destroy'

  if (state.closureMode === CLOSURE_MODE.NONE) {
    state.closureMode = CLOSURE_MODE.DESTROY
    state.closureStatus = CLOSURE_STATE.PHYSICALLY_CLOSING

    // Native physical loss/remote DESTROY gets no echo; local abrupt destroy emits at most 8 attempts from the same byte-frozen body.
    // Downstream physical loss in forwarding propagates upstream DESTROY!
    if (
      source !== 'remote-destroy' &&
      source !== 'physical-loss' &&
      source !== 'setup-failed' &&
      state.physicalChannel &&
      state.destroyAttempts === 0
    ) {
      try {
        const destroyWire = encodePeerTransport(PEER_MESSAGE_ID.PEER_BRANCH_DESTROY_V2, {
          branchClass: 2,
          branchId: state.branchId,
          circuitId: state.circuitId,
          generation: state.generation,
          reason: 1
        })
        state.destroyWire = destroyWire
        scheduleDestroyRetryDuty(state, destroyWire, state.localDeadline)
      } catch {}
    }
  } else if (state.closureMode === CLOSURE_MODE.TEARDOWN) {
    // Mode cannot switch between physical DESTROY and intentional TEARDOWN.
    // Remote native loss during intentional mode cleans without opposite-mode sends.
    state.closureStatus = CLOSURE_STATE.PHYSICALLY_CLOSING
  }

  revokeRuntimeTraffic(state, source)
  if (state.closureMode === CLOSURE_MODE.TEARDOWN || state.destroyDutyPromise === null) {
    return beginRuntimeTeardownCleanup(state, options)
  }
  return state.destroyDutyPromise
}

class PeerM3AdjacencyAuthority {
  constructor(options = {}) {
    if (!safeObject(options)) invalid()
    const wallNow = options.wallNow
    const monotonicNow = options.monotonicNow
    const schedule = options.schedule || options.setTimer
    const cancelScheduled = options.cancelScheduled || options.clearTimer
    const clockIdentity = options.clockIdentity || Object.freeze({ wallNow, monotonicNow })
    const setTimer = options.setTimer || schedule
    const clearTimer = options.clearTimer || cancelScheduled
    const crypto = options.crypto === undefined ? cryptoSuite : options.crypto
    const maxRuntimes =
      options.maxRuntimes === undefined ? DEFAULT_MAX_M3_ADJACENCY_RUNTIMES : options.maxRuntimes
    const observe = options[TEST_ONLY_M3_ADJACENCY_OBSERVER]

    if (
      typeof wallNow !== 'function' ||
      typeof monotonicNow !== 'function' ||
      typeof schedule !== 'function' ||
      typeof cancelScheduled !== 'function' ||
      !safeObject(crypto) ||
      typeof crypto.seal !== 'function' ||
      typeof crypto.open !== 'function' ||
      typeof crypto.randomBytes !== 'function' ||
      !Number.isInteger(maxRuntimes) ||
      maxRuntimes < 1 ||
      maxRuntimes > MAX_M3_ADJACENCY_RUNTIMES ||
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
      clockIdentity,
      setTimer,
      clearTimer,
      crypto,
      maxRuntimes,
      observe: observe || null,
      reservations: new Map(),
      active: true
    }

    AUTHORITIES.add(this)
    AUTHORITY_STATES.set(this, state)
  }

  adopt(handle) {
    return adoptPeerEstablishedLink(this, handle)
  }

  diagnostics() {
    const state = AUTHORITY_STATES.get(this)
    if (!state || !state.active) destroyed()
    return Object.freeze({
      activeRuntimes: state.reservations.size,
      maxRuntimes: state.maxRuntimes
    })
  }

  destroy() {
    const state = AUTHORITY_STATES.get(this)
    if (!state || !state.active) return false
    state.active = false
    AUTHORITY_STATES.delete(this)
    const reservations = Array.from(state.reservations.values())
    state.reservations.clear()
    for (const res of reservations) {
      if (res.runtimeState) {
        destroyRuntimeState(res.runtimeState)
      }
    }
    return true
  }
}

function createPeerM3AdjacencyAuthority(options) {
  return new PeerM3AdjacencyAuthority(options)
}

function adoptPeerEstablishedLink(authority, handle) {
  const authorityState = safeObject(authority) ? AUTHORITY_STATES.get(authority) : null
  if (!authorityState || !authorityState.active) destroyed()

  const taker = getTakePeerEstablishedLink()
  if (!taker) authentication()

  let state = null
  try {
    state = taker(handle)
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    authentication()
  }

  if (!state || typeof state !== 'object') {
    authentication()
  }

  const destroyer = getDestroyTakenPeerEstablishedLink()

  let reservation = null
  let adopted = false
  let runtimeState = null
  let transfer = null
  let successorProof378 = null

  try {
    if (
      typeof state.initiator !== 'boolean' ||
      state.branchClass !== 2 ||
      !u64(state.generation) ||
      state.generation === 0n ||
      !Number.isInteger(state.extensionIndex) ||
      !safeObject(state.contexts) ||
      !fixed(state.localId, 16) ||
      !fixed(state.peerLocalId, 16) ||
      !fixed(state.localIdentity, 32) ||
      !fixed(state.peerIdentity, 32) ||
      !fixed(state.branchId, 16) ||
      !fixed(state.circuitId, 16) ||
      !u64(state.wireExpiresAt) ||
      !u64(state.localDeadline)
    ) {
      invalid()
    }

    if (
      !state.clockIdentity ||
      state.clockIdentity !== authorityState.clockIdentity ||
      state.wallNow !== authorityState.wallNow ||
      state.monotonicNow !== authorityState.monotonicNow
    ) {
      authentication()
    }

    const currentWall = state.wallNow()
    const currentMonotonic = state.monotonicNow()
    if (
      typeof currentWall !== 'bigint' ||
      typeof currentMonotonic !== 'bigint' ||
      currentWall >= state.wireExpiresAt ||
      currentMonotonic >= state.localDeadline
    ) {
      authentication()
    }

    if (authorityState.reservations.size >= authorityState.maxRuntimes) {
      busy()
    }

    const reservationKey =
      b4a.toString(state.peerIdentity, 'hex') +
      ':' +
      b4a.toString(state.circuitId, 'hex') +
      ':' +
      state.generation.toString()

    if (authorityState.reservations.has(reservationKey)) {
      busy()
    }

    reservation = {
      key: reservationKey,
      released: false,
      runtimeState: null
    }
    authorityState.reservations.set(reservationKey, reservation)

    const registerTransfer = getRegisterPeerM3CellLinkTransfer()
    if (!registerTransfer) unauthorized()

    transfer = registerTransfer(state.physicalChannel, state.m3BranchBinding)
    if (!transfer) {
      unauthorized()
    }

    const channel = transfer
    if (
      !safeObject(channel) ||
      typeof channel.send !== 'function' ||
      typeof channel.receive !== 'function' ||
      typeof channel.destroy !== 'function' ||
      typeof channel.bindSetupFailure !== 'function' ||
      typeof channel.sendClosure !== 'function' ||
      typeof channel.cancelClosureSends !== 'function' ||
      typeof channel.waitForClosureSends !== 'function'
    ) {
      unauthorized()
    }

    // Move contexts directly without fabricating counters or duplicating keys
    const contexts = state.contexts
    for (const cellClass of [CELL_CLASS.CONTROL, CELL_CLASS.DATAGRAM]) {
      const src = contexts[cellClass]
      if (
        !src ||
        !src.tx ||
        !src.rx ||
        !fixed(src.tx.key, 32) ||
        !fixed(src.tx.noncePrefix, 16) ||
        !fixed(src.rx.key, 32) ||
        !fixed(src.rx.noncePrefix, 16) ||
        !src.tx.counter ||
        typeof src.tx.counter.next !== 'function' ||
        !src.rx.counter
      ) {
        invalid()
      }
      if (cellClass === CELL_CLASS.DATAGRAM) {
        if (typeof src.rx.counter.acceptAuthenticated !== 'function') invalid()
      } else {
        if (typeof src.rx.counter.pushAuthenticated !== 'function') invalid()
      }
    }

    if (state.initiator && (state.extensionIndex === 1 || state.extensionIndex === 2)) {
      const takeProof = getTakePeerEstablishedProof()
      if (!takeProof) authentication()
      successorProof378 = takeProof(state)
      if (!successorProof378 || !fixed(successorProof378, 378)) {
        authentication()
      }
    } else if (state.successorProof378 !== null && state.successorProof378 !== undefined) {
      authentication()
    }

    const runtime = new PeerM3AdjacencyRuntime()
    const codec = new CellCodec({ crypto: authorityState.crypto, cellSize: CELL_SIZE })

    runtimeState = {
      runtime,
      establishedHandle: handle,
      authority,
      authorityState,
      initiator: state.initiator,
      branchClass: state.branchClass,
      generation: state.generation,
      extensionIndex: state.extensionIndex,
      localId: state.localId,
      peerLocalId: state.peerLocalId,
      localIdentity: state.localIdentity,
      peerIdentity: state.peerIdentity,
      branchId: state.branchId,
      circuitId: state.circuitId,
      physicalChannel: channel,
      sendLedger: state.sendLedger || null,
      receiveLedger: state.receiveLedger || null,
      teardownSendLedger: state.teardownSendLedger || null,
      teardownReceiveLedger: state.teardownReceiveLedger || null,
      tailSharedSecret: state.tailSharedSecret || null,
      tailAdvertisement260: state.tailAdvertisement260 || null,
      tailControlTranscript: state.tailControlTranscript || null,
      successorProof378,
      tailMaterialTaken: false,
      extensionProofTaken: false,
      wireExpiresAt: state.wireExpiresAt,
      localDeadline: state.localDeadline,
      clockIdentity: state.clockIdentity,
      wallNow: state.wallNow,
      monotonicNow: state.monotonicNow,
      setTimer: state.setTimer || authorityState.setTimer,
      clearTimer: state.clearTimer || authorityState.clearTimer,
      contexts,
      codec,
      reservation,
      cleared: false,
      timer: null,
      physicalLossRegistration: null,
      physicalLossSinks: new Set(),
      waiters: [],
      received: [],
      pumping: false,
      carrierCleanup: null,
      finalCarrierTaken: false,
      finalReadinessTrain: null,
      closureMode: CLOSURE_MODE.NONE,
      closureRole: CLOSURE_ROLE.NONE,
      closureStatus: CLOSURE_STATE.LIVE,
      closureTransitionSeen: false,
      closureDispatchOwner: null,
      teardownId: null,
      teardownWire: null,
      teardownAckWire: null,
      teardownAttempts: 0,
      destroyWire: null,
      destroyAttempts: 0,
      teardownDeadline: 0n,
      teardownTimer: null,
      ackTimer: null,
      cacheTimer: null,
      destroyRetryTimer: null,
      destroyDutyPromise: null,
      destroyDutyDone: false,
      initiatorTeardown: null,
      drainHandler: null,
      drainPromise: null,
      heldSends: new Set(),
      retainedPackets: new Set(),
      closureDutyEnded: false,
      cleanupPromise: null,
      pendingFinalCleanup: false,
      trafficRevoked: false,
      finalized: false,
      downstreamReleaseObligation: null,
      teardownState: null,
      teardownEmitted: false
    }

    reservation.runtimeState = runtimeState

    RUNTIMES.set(runtime, runtimeState)
    channel.bindSetupFailure(() => {
      destroyRuntimeState(runtimeState, {
        source: adopted ? 'setup-violation' : 'setup-failed'
      })
    })

    const remaining = state.localDeadline - currentMonotonic
    const delay = timerDelay(remaining)
    let armedTimer = null
    try {
      armedTimer = runtimeState.setTimer(() => {
        runtimeState.timer = null
        destroyRuntimeState(runtimeState, { source: adopted ? 'expired' : 'setup-failed' })
      }, delay)
      runtimeState.timer = armedTimer
    } catch (err) {
      destroyRuntimeState(runtimeState, { source: 'setup-failed' })
      throw err
    }

    if (runtimeState.cleared || !authorityState.active) {
      if (armedTimer !== null && runtimeState.clearTimer) {
        try {
          runtimeState.clearTimer(armedTimer)
        } catch {}
        runtimeState.timer = null
      }
      if (!runtimeState.cleared) {
        destroyRuntimeState(runtimeState, true)
      }
      destroyed()
    }

    const lossHooks = getNativePhysicalLossRegistration()
    let lossRegistration = null
    if (lossHooks) {
      try {
        lossRegistration = lossHooks.register(channel, () => {
          destroyRuntimeState(runtimeState, { source: 'physical-loss' })
        })
        runtimeState.physicalLossRegistration = lossRegistration
      } catch (err) {
        destroyRuntimeState(runtimeState, { source: 'setup-failed' })
        throw err
      }
    }

    if (runtimeState.cleared || !authorityState.active) {
      if (lossRegistration !== null && lossHooks) {
        try {
          lossHooks.revoke(lossRegistration)
        } catch {}
        runtimeState.physicalLossRegistration = null
      }
      if (armedTimer !== null && runtimeState.clearTimer) {
        try {
          runtimeState.clearTimer(armedTimer)
        } catch {}
        runtimeState.timer = null
      }
      if (!runtimeState.cleared) {
        destroyRuntimeState(runtimeState, false)
      }
      destroyed()
    }

    adopted = true
    if (authorityState.observe) {
      try {
        authorityState.observe(Object.freeze({ type: 'adopted', runtime }))
      } catch {}
    }
    pumpRuntimeReceive(runtimeState)
    return runtime
  } catch (err) {
    if (!adopted && transfer) {
      try {
        transfer.destroy()
      } catch {}
    }
    if (reservation && !reservation.released) {
      authorityState.reservations.delete(reservation.key)
      reservation.released = true
    }
    if (runtimeState) {
      destroyRuntimeState(runtimeState, { source: 'setup-failed' })
    } else {
      if (successorProof378) {
        clear(successorProof378)
        successorProof378 = null
      }
      if (transfer && typeof transfer.destroy === 'function') {
        try {
          transfer.destroy()
        } catch {}
      }
      if (destroyer) {
        try {
          destroyer(state)
        } catch {}
      }
    }
    if (err instanceof PrivateRouteError) throw err
    unavailable()
  }
}

function isPeerM3Runtime(handle) {
  return (
    safeObject(handle) &&
    RUNTIMES.has(handle) &&
    !DESTROYED_RUNTIMES.has(handle) &&
    !MOVED_RUNTIMES.has(handle)
  )
}

function isPeerM3RuntimeForLink(runtime, establishedHandle) {
  return isPeerM3Runtime(runtime) && RUNTIMES.get(runtime).establishedHandle === establishedHandle
}

function readPeerM3Runtime(handle) {
  if (!safeObject(handle)) return null
  const state = RUNTIMES.get(handle)
  if (!state || state.cleared) {
    if (DESTROYED_RUNTIMES.has(handle)) destroyed()
    return null
  }
  checkRuntimeTime(state)
  return Object.freeze({
    initiator: state.initiator,
    branchClass: state.branchClass,
    generation: state.generation,
    extensionIndex: state.extensionIndex,
    wireExpiresAt: state.wireExpiresAt,
    localDeadline: state.localDeadline,
    circuitId: copy(state.circuitId, 16),
    branchId: copy(state.branchId, 16),
    active: !state.cleared
  })
}

function takePeerM3TailMaterial(runtime) {
  if (!isPeerM3Runtime(runtime)) invalid()
  const state = RUNTIMES.get(runtime)
  if (!state || state.cleared) destroyed()
  if (state.tailMaterialTaken) replay()
  checkRuntimeTime(state)

  if (state.initiator && state.extensionIndex !== 0) {
    unauthorized()
  }

  if (!state.tailSharedSecret || !fixed(state.tailSharedSecret, 32)) {
    unauthorized()
  }

  state.tailMaterialTaken = true
  const tailSharedSecret = state.tailSharedSecret
  const tailControlTranscript = state.tailControlTranscript
  const tailAdvertisement260 = state.tailAdvertisement260
  state.tailSharedSecret = null
  state.tailControlTranscript = null
  state.tailAdvertisement260 = null

  return Object.freeze({
    initiator: state.initiator,
    branchClass: state.branchClass,
    generation: state.generation,
    extensionIndex: state.extensionIndex,
    wireExpiresAt: state.wireExpiresAt,
    localDeadline: state.localDeadline,
    circuitId: copy(state.circuitId, 16),
    branchId: copy(state.branchId, 16),
    tailSharedSecret,
    tailAdvertisement260,
    tailControlTranscript,
    clockIdentity: state.clockIdentity,
    wallNow: state.wallNow,
    monotonicNow: state.monotonicNow,
    setTimer: state.setTimer,
    clearTimer: state.clearTimer
  })
}

function takePeerM3ExtensionProof(runtime) {
  if (!isPeerM3Runtime(runtime)) invalid()
  const state = RUNTIMES.get(runtime)
  if (!state || state.cleared) destroyed()
  if (state.extensionProofTaken) replay()
  checkRuntimeTime(state)

  if (!state.initiator || (state.extensionIndex !== 1 && state.extensionIndex !== 2)) {
    unauthorized()
  }

  if (!state.successorProof378 || !fixed(state.successorProof378, 378)) {
    unauthorized()
  }

  state.extensionProofTaken = true
  const successorProof378 = state.successorProof378
  state.successorProof378 = null

  return Object.freeze({
    initiator: state.initiator,
    generation: state.generation,
    extensionIndex: state.extensionIndex,
    circuitId: copy(state.circuitId, 16),
    branchId: copy(state.branchId, 16),
    successorProof378
  })
}

function sendPeerM3PayloadInternal(state, payload) {
  if (!state || state.cleared || state.closureMode !== CLOSURE_MODE.NONE) destroyed()
  checkRuntimeTime(state)

  if (isClosureObject(payload)) {
    unauthorized()
  }

  let cellClass = CELL_CLASS.DATAGRAM
  let rawPayload = null

  if (safeObject(payload) && !b4a.isBuffer(payload)) {
    if (payload.class !== undefined) {
      cellClass = payload.class
    }
    rawPayload = payload.payload
  } else if (b4a.isBuffer(payload)) {
    rawPayload = payload
  } else {
    invalid()
  }

  if (cellClass !== CELL_CLASS.CONTROL && cellClass !== CELL_CLASS.DATAGRAM) {
    invalid()
  }

  if (!b4a.isBuffer(rawPayload)) {
    invalid()
  }

  if (isClosureWire(rawPayload)) {
    unauthorized()
  }
  const targetLedger = state.sendLedger

  let packet = null
  try {
    packet = sealTailState(state, { class: cellClass, payload: rawPayload })
    // Native send dispatch spends the ledger directly; runtime must not call chargePeerLedger here
    const result = state.physicalChannel.send(packet, targetLedger)
    const retainedPacket = packet
    packet = null
    return Promise.resolve(result).finally(() => clear(retainedPacket))
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    clear(packet)
  }
}

function sendPeerM3Payload(runtime, payload) {
  if (!safeObject(runtime)) invalid()
  const state = RUNTIMES.get(runtime)
  if (!state || state.cleared) destroyed()
  return sendPeerM3PayloadInternal(state, payload)
}

function receivePeerM3PayloadItemInternal(state) {
  if (!state || state.cleared) return Promise.reject(PrivateRouteError.ERR_DESTROYED())
  try {
    checkRuntimeTime(state)
  } catch (err) {
    return Promise.reject(err)
  }

  if (state.received.length > 0) {
    return Promise.resolve(state.received.shift())
  }

  const waiter = {}
  const promise = new Promise((resolve, reject) => {
    waiter.resolve = resolve
    waiter.reject = reject
  })
  state.waiters.push(waiter)

  if (!state.pumping) {
    pumpRuntimeReceive(state)
  }

  return promise
}

function receivePeerM3PayloadInternal(state) {
  return receivePeerM3PayloadItemInternal(state).then((item) => {
    return item && item.payload !== undefined ? item.payload : item
  })
}

function receivePeerM3Payload(runtime) {
  if (!safeObject(runtime)) invalid()
  const state = RUNTIMES.get(runtime)
  if (!state || state.cleared) return Promise.reject(PrivateRouteError.ERR_DESTROYED())
  return receivePeerM3PayloadInternal(state)
}

function pumpRuntimeReceive(state) {
  if (state.pumping || state.cleared) return
  state.pumping = true

  const step = () => {
    if (state.cleared) {
      state.pumping = false
      return
    }

    state.physicalChannel
      .receive()
      .then((packet) => {
        if (state.cleared) {
          releaseM3RoutePacket(packet)
          return
        }

        let opened = null
        const cellClass = packet[1]
        try {
          opened = openTailState(state, packet)
        } catch {
          // Dropped invalid / replay / corrupt packet
          return step()
        } finally {
          releaseM3RoutePacket(packet)
        }

        if (Array.isArray(opened)) {
          for (const item of opened) {
            if (!item) continue
            const payload = item.payload !== undefined ? item.payload : item

            // Closure-shaped payloads are valid only on outer DATAGRAM cells.
            // A CONTROL cell carrying IDs 030e..0310 is malformed and fails the branch.
            if (cellClass === CELL_CLASS.CONTROL && isClosureWire(payload)) {
              destroyRuntimeState(state, { source: 'malformed-closure' })
              return
            }

            // Intercept closure-shaped messages in DATAGRAM:
            // All PEER_BRANCH_DESTROY_V2/TEARDOWN_V2/TEARDOWN_ACK_V2 are immediate outer DATAGRAM, never CONTROL.
            // IDs 030e..0310 are intercepted after successful DATAGRAM authentication and before ordinary route delivery.
            // Malformed/mismatched closure-shaped messages fail the branch, never fall through.
            if (cellClass === CELL_CLASS.DATAGRAM && isClosureWire(payload)) {
              let closureWire = null
              try {
                closureWire = decodePeerTransport(payload)
              } catch {
                destroyRuntimeState(state, { source: 'malformed-closure' })
                return
              }

              if (!closureWire || !closureWire.fields) {
                destroyRuntimeState(state, { source: 'malformed-closure' })
                return
              }

              const fields = closureWire.fields
              if (
                fields.branchClass !== 2 ||
                !fields.branchId ||
                !b4a.equals(fields.branchId, state.branchId) ||
                !fields.circuitId ||
                !b4a.equals(fields.circuitId, state.circuitId) ||
                fields.generation !== state.generation
              ) {
                destroyRuntimeState(state, { source: 'mismatched-closure' })
                return
              }

              // First receive-side closure transition charges one command, subsequent authenticated occurrences only cells/bytes.
              const isFirstTransition = !state.closureTransitionSeen
              state.closureTransitionSeen = true
              if (state.teardownReceiveLedger) {
                try {
                  chargePeerLedger(state.teardownReceiveLedger, {
                    cells: 1,
                    bytes: 1200n,
                    commands: isFirstTransition ? 1 : 0
                  })
                } catch {
                  destroyRuntimeState(state, { source: 'quota-exhausted' })
                  return
                }
              }

              const messageId = closureWire.messageId
              if (messageId === PEER_MESSAGE_ID.PEER_BRANCH_DESTROY_V2) {
                if (fields.reason !== 1) {
                  destroyRuntimeState(state, { source: 'mismatched-closure' })
                  return
                }
                // Native physical loss/remote DESTROY gets no echo
                destroyRuntimeState(state, { source: 'remote-destroy' })
                return
              }

              if (messageId === PEER_MESSAGE_ID.PEER_BRANCH_TEARDOWN_V2) {
                if (
                  fields.reason !== 2 ||
                  !fixed(fields.teardownId, 16) ||
                  !nonzero(fields.teardownId)
                ) {
                  destroyRuntimeState(state, { source: 'mismatched-closure' })
                  return
                }

                if (state.closureMode === CLOSURE_MODE.DESTROY) {
                  // Mode cannot switch between physical DESTROY and intentional TEARDOWN
                  continue
                }

                if (state.closureMode === CLOSURE_MODE.NONE) {
                  // First authenticated remote TEARDOWN selects responder mode
                  state.closureMode = CLOSURE_MODE.TEARDOWN
                  state.closureRole = CLOSURE_ROLE.RESPONDER
                  state.closureStatus = CLOSURE_STATE.DRAINING
                  state.teardownId = copy(fields.teardownId, 16)
                  const nowMono = state.monotonicNow()
                  const timeout = BigInt(LINK_CIRCUIT_TEARDOWN_TIMEOUT)
                  const candidateDeadline = nowMono + timeout
                  state.teardownDeadline =
                    candidateDeadline < state.localDeadline
                      ? candidateDeadline
                      : state.localDeadline
                  state.teardownAttempts = 0

                  // Stop ordinary admission
                  if (state.waiters && state.waiters.length > 0) {
                    const waiters = state.waiters.splice(0)
                    for (const waiter of waiters) {
                      try {
                        waiter.reject(PrivateRouteError.ERR_DESTROYED())
                      } catch {}
                    }
                  }

                  // Exact ACK body
                  state.teardownAckWire = encodePeerTransport(
                    PEER_MESSAGE_ID.PEER_BRANCH_TEARDOWN_ACK_V2,
                    {
                      branchClass: 2,
                      branchId: state.branchId,
                      circuitId: state.circuitId,
                      generation: state.generation,
                      reason: 2,
                      teardownId: state.teardownId
                    }
                  )

                  // Cache remains through original bounded deadline
                  armTeardownCacheDeadlineTimer(state)

                  // Invoke one private logical drain handler
                  let drainPromise = Promise.resolve()
                  if (typeof state.drainHandler === 'function') {
                    try {
                      drainPromise = Promise.resolve(state.drainHandler(state.teardownId))
                    } catch (err) {
                      drainPromise = Promise.reject(err)
                    }
                  }
                  state.drainPromise = drainPromise

                  drainPromise
                    .then(() => {
                      if (state.cleared || state.closureMode !== CLOSURE_MODE.TEARDOWN) return
                      state.closureStatus = CLOSURE_STATE.ACK_CACHED
                      if (
                        state.teardownAttempts < MAX_TEARDOWN_ATTEMPTS &&
                        state.monotonicNow() < state.teardownDeadline
                      ) {
                        state.teardownAttempts++
                        sendClosurePacket(
                          state,
                          state.teardownAckWire,
                          CLOSURE_MODE.TEARDOWN,
                          state.teardownDeadline
                        )
                      }
                      // Timer-driven retries share the attempt boundary and original deadline
                      armTeardownAckRetryTimer(state)
                    })
                    .catch(() => {
                      destroyRuntimeState(state, { source: 'drain-failed' })
                    })
                  continue
                }

                if (state.closureStatus === CLOSURE_STATE.DRAINING) {
                  // Duplicate while draining does not rerun it or ACK early.
                  if (!b4a.equals(fields.teardownId, state.teardownId)) {
                    // Changed IDs conflict: fail the named branch, retaining TEARDOWN mode; no DESTROY is sent.
                    destroyRuntimeState(state, { source: 'teardown-conflict' })
                    return
                  }
                  continue
                }

                if (state.closureStatus === CLOSURE_STATE.ACK_CACHED) {
                  if (!b4a.equals(fields.teardownId, state.teardownId)) {
                    // Changed IDs conflict: fail the named branch, retaining TEARDOWN mode; no DESTROY is sent.
                    destroyRuntimeState(state, { source: 'teardown-conflict' })
                    return
                  }
                  // Exact duplicates reuse cache and remaining attempts without deadline extension
                  if (
                    state.teardownAttempts < MAX_TEARDOWN_ATTEMPTS &&
                    state.monotonicNow() < state.teardownDeadline
                  ) {
                    state.teardownAttempts++
                    sendClosurePacket(
                      state,
                      state.teardownAckWire,
                      CLOSURE_MODE.TEARDOWN,
                      state.teardownDeadline
                    )
                  }
                  // Cache remains through original bounded deadline, even after attempt exhaustion
                  continue
                }

                continue
              }

              if (messageId === PEER_MESSAGE_ID.PEER_BRANCH_TEARDOWN_ACK_V2) {
                if (
                  fields.reason !== 2 ||
                  !fixed(fields.teardownId, 16) ||
                  !nonzero(fields.teardownId)
                ) {
                  destroyRuntimeState(state, { source: 'mismatched-closure' })
                  return
                }

                if (
                  state.closureMode === CLOSURE_MODE.TEARDOWN &&
                  state.closureRole === CLOSURE_ROLE.INITIATOR &&
                  state.initiatorTeardown &&
                  !state.initiatorTeardown.settled
                ) {
                  if (b4a.equals(fields.teardownId, state.teardownId)) {
                    // Genuine matching ACK
                    clearTeardownRetryTimer(state)
                    state.closureStatus = CLOSURE_STATE.PHYSICALLY_CLOSING
                    settleTeardownInitiatorSuccess(state)
                  }
                }
                continue
              }
              continue
            }

            // Charge receive ledger for ordinary payloads
            const targetLedger = state.receiveLedger
            if (targetLedger) {
              try {
                chargePeerLedger(targetLedger, {
                  cells: 1,
                  bytes: 1200n,
                  commands: cellClass === CELL_CLASS.CONTROL ? 1 : 0
                })
              } catch (err) {
                destroyRuntimeState(state, { source: 'quota-exhausted' })
                return
              }
            }

            // If runtime is in closure mode, stop ordinary admission
            if (state.closureMode !== CLOSURE_MODE.NONE) {
              continue
            }

            // Ordinary DATAGRAM payload dispatch
            const delivery = { class: cellClass, payload }
            // The physical receive may have started before the final ownership move.
            // Retired tail traffic still spends its cell, but never a carrier reader.
            if (
              state.finalCarrierTaken &&
              peerM3PayloadContextClass(delivery) === PEER_TAIL_CONTROL_CONTEXT_CLASS
            ) {
              clear(payload)
              continue
            }
            if (state.waiters.length > 0) {
              const waiter = state.waiters.shift()
              waiter.resolve(delivery)
            } else if (state.received.length < ROUTE_FRAME_RESIDENCY_LIMIT) {
              state.received.push(delivery)
            }
          }
        }

        step()
      })
      .catch(() => {
        if (!state.cleared) {
          destroyRuntimeState(state)
        }
      })
  }

  step()
}

function destroyPeerM3Runtime(runtime) {
  if (!safeObject(runtime)) return false
  const state = RUNTIMES.get(runtime)
  if (!state) {
    return false
  }
  return destroyRuntimeState(state)
}

function beginPeerM3BranchTeardownState(state, teardownId16) {
  if (!state || state.cleared || state.finalized) {
    return Promise.reject(PrivateRouteError.ERR_DESTROYED())
  }

  if (!fixed(teardownId16, 16) || !nonzero(teardownId16)) {
    return Promise.reject(PrivateRouteError.INVALID_ROUTE())
  }

  if (state.closureMode !== CLOSURE_MODE.NONE) {
    return Promise.reject(PrivateRouteError.ERR_REPLAY())
  }

  try {
    checkRuntimeTime(state)
  } catch (err) {
    return Promise.reject(err)
  }

  state.closureMode = CLOSURE_MODE.TEARDOWN
  state.closureRole = CLOSURE_ROLE.INITIATOR
  state.closureStatus = CLOSURE_STATE.DRAINING
  state.teardownId = copy(teardownId16, 16)

  const currentMono = state.monotonicNow()
  const timeout = BigInt(LINK_CIRCUIT_TEARDOWN_TIMEOUT)
  const candidateDeadline = currentMono + timeout
  state.teardownDeadline =
    candidateDeadline < state.localDeadline ? candidateDeadline : state.localDeadline
  state.teardownAttempts = 0

  // Stop ordinary admission
  if (state.waiters && state.waiters.length > 0) {
    const waiters = state.waiters.splice(0)
    for (const waiter of waiters) {
      try {
        waiter.reject(PrivateRouteError.ERR_DESTROYED())
      } catch {}
    }
  }

  let wire = null
  try {
    wire = encodePeerTransport(PEER_MESSAGE_ID.PEER_BRANCH_TEARDOWN_V2, {
      branchClass: 2,
      branchId: state.branchId,
      circuitId: state.circuitId,
      generation: state.generation,
      reason: 2,
      teardownId: state.teardownId
    })
    state.teardownWire = wire
  } catch (err) {
    destroyRuntimeState(state, { source: 'teardown-encode-failed' })
    return Promise.reject(err)
  }

  let resolveTeardown
  let rejectTeardown
  const teardownPromise = new Promise((resolve, reject) => {
    resolveTeardown = resolve
    rejectTeardown = reject
  })

  state.initiatorTeardown = {
    resolve: resolveTeardown,
    reject: rejectTeardown,
    promise: teardownPromise,
    settled: false
  }

  // Attempt 1 of at most 10
  state.teardownAttempts = 1
  sendClosurePacket(state, state.teardownWire, CLOSURE_MODE.TEARDOWN, state.teardownDeadline)

  // Arm retry timer (LINK_PING_AFTER = 500ms)
  const scheduleRetry = () => {
    if (state.cleared || !state.initiatorTeardown || state.initiatorTeardown.settled) return
    const nowMono = state.monotonicNow()
    if (nowMono >= state.teardownDeadline || state.teardownAttempts >= MAX_TEARDOWN_ATTEMPTS) {
      state.initiatorTeardown.settled = true
      destroyRuntimeState(state, { source: 'teardown-timeout' }).then(() => {
        resolveTeardown(false)
      })
      return
    }

    const setFn = state.setTimer || (state.authorityState && state.authorityState.setTimer)
    if (!setFn) return

    state.teardownTimer = setFn(() => {
      state.teardownTimer = null
      if (state.cleared || !state.initiatorTeardown || state.initiatorTeardown.settled) return
      const currentNow = state.monotonicNow()
      if (currentNow >= state.teardownDeadline || state.teardownAttempts >= MAX_TEARDOWN_ATTEMPTS) {
        state.initiatorTeardown.settled = true
        destroyRuntimeState(state, { source: 'teardown-timeout' }).then(() => {
          resolveTeardown(false)
        })
        return
      }
      state.teardownAttempts++
      sendClosurePacket(state, state.teardownWire, CLOSURE_MODE.TEARDOWN, state.teardownDeadline)
      scheduleRetry()
    }, LINK_PING_AFTER)
  }

  scheduleRetry()

  return teardownPromise
}

function beginPeerM3BranchTeardown(runtime, teardownId16) {
  if (!safeObject(runtime)) return Promise.reject(PrivateRouteError.INVALID_ROUTE())
  const state = RUNTIMES.get(runtime)
  if (!state || state.cleared) return Promise.reject(PrivateRouteError.ERR_DESTROYED())
  return beginPeerM3BranchTeardownState(state, teardownId16)
}

function registerStatePhysicalLossSink(state, sink) {
  if (!state || typeof sink !== 'function') invalid()

  const registration = Object.freeze({ runtime: state.runtime, sink })
  PHYSICAL_LOSS_REGISTRATIONS.set(registration, { state, sink, active: true })
  state.physicalLossSinks.add(sink)
  return registration
}

function revokeStatePhysicalLossSink(registration) {
  if (!safeObject(registration)) return false
  const record = PHYSICAL_LOSS_REGISTRATIONS.get(registration)
  if (!record || !record.active) return false
  record.active = false
  PHYSICAL_LOSS_REGISTRATIONS.delete(registration)
  if (record.state && record.state.physicalLossSinks) {
    record.state.physicalLossSinks.delete(record.sink)
  }
  return true
}

function registerPeerM3PhysicalLossSink(runtime, sink) {
  if (!safeObject(runtime) || typeof sink !== 'function') invalid()
  const state = RUNTIMES.get(runtime)
  if (!state || state.cleared) destroyed()
  return registerStatePhysicalLossSink(state, sink)
}

function revokePeerM3PhysicalLossSink(registration) {
  return revokeStatePhysicalLossSink(registration)
}

function createPeerM3ForwardingOwner(previous, next, options = {}) {
  let previousPayloadHandler = null
  try {
    if (!safeObject(options)) invalid()
    const descriptor = Object.getOwnPropertyDescriptor(options, 'onPreviousPayload')
    if (descriptor) {
      if (
        !Object.prototype.hasOwnProperty.call(descriptor, 'value') ||
        typeof descriptor.value !== 'function'
      )
        invalid()
      previousPayloadHandler = descriptor.value
    }
  } catch {
    invalid()
  }
  if (!isPeerM3Runtime(previous) || !isPeerM3Runtime(next) || previous === next) {
    invalid()
  }

  const prevState = RUNTIMES.get(previous)
  const nextState = RUNTIMES.get(next)
  if (!prevState || prevState.cleared || !nextState || nextState.cleared) {
    destroyed()
  }
  if (prevState.waiters.length !== 0 || nextState.waiters.length !== 0) busy()

  // 1. Reserve/mark both states as moved first
  RUNTIMES.delete(previous)
  RUNTIMES.delete(next)
  MOVED_RUNTIMES.add(previous)
  MOVED_RUNTIMES.add(next)

  const owner = Object.freeze({})
  const forwardingState = {
    owner,
    previous,
    next,
    prevState,
    nextState,
    active: true,
    prevReg: null,
    nextReg: null
  }

  const teardownBoth = () => {
    destroyPeerM3ForwardingOwner(owner)
  }

  // Forwarding drain handlers:
  // upstream TEARDOWN gates downstream beginPeerM3BranchTeardown with same semantic ID, waits downstream release, then permits upstream cached ACK.
  prevState.drainHandler = async (teardownId) => {
    const downstreamSuccess = await beginPeerM3BranchTeardownState(nextState, teardownId)
    if (!downstreamSuccess) {
      throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    }
  }

  nextState.drainHandler = async (teardownId) => {
    const upstreamSuccess = await beginPeerM3BranchTeardownState(prevState, teardownId)
    if (!upstreamSuccess) {
      throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    }
  }

  // Downstream physical loss propagates upstream DESTROY only.
  // Do not let generic receive-loop failure/physical-loss sinks preempt that with dual abrupt destruction.
  const onPrevLoss = () => {
    if (!forwardingState.active) return
    forwardingState.active = false
    destroyRuntimeState(nextState, { source: 'upstream-physical-loss' })
  }

  const onNextLoss = () => {
    if (!forwardingState.active) return
    forwardingState.active = false
    destroyRuntimeState(prevState, { source: 'downstream-physical-loss' })
  }

  // 2. Install both registrations against the captured states with rollback
  try {
    forwardingState.prevReg = registerStatePhysicalLossSink(prevState, onPrevLoss)
  } catch (err) {
    destroyRuntimeState(prevState)
    destroyRuntimeState(nextState)
    throw err
  }

  try {
    forwardingState.nextReg = registerStatePhysicalLossSink(nextState, onNextLoss)
  } catch (err) {
    if (forwardingState.prevReg) {
      revokeStatePhysicalLossSink(forwardingState.prevReg)
      forwardingState.prevReg = null
    }
    destroyRuntimeState(prevState)
    destroyRuntimeState(nextState)
    throw err
  }

  // 3. Publish owner
  FORWARDING_OWNERS.set(owner, forwardingState)

  // 4. Start pumps
  const pumpLeg = (srcState, dstState, onPayload = null) => {
    const loop = () => {
      if (!forwardingState.active || srcState.cleared || dstState.cleared) return
      receivePeerM3PayloadItemInternal(srcState)
        .then((item) => {
          try {
            if (!forwardingState.active || srcState.cleared || dstState.cleared) return
            if (onPayload) {
              const consumed = onPayload(item.payload)
              if (consumed === true) return
              if (consumed !== false) invalid()
              if (!forwardingState.active || srcState.cleared || dstState.cleared) return
            }
            return sendPeerM3PayloadInternal(dstState, item)
          } finally {
            clear(item.payload)
          }
        })
        .then(() => {
          if (forwardingState.active) loop()
        })
        .catch(() => {
          // Do not let generic receive-loop failure preempt intentional closure with dual abrupt destruction
          if (
            srcState.closureMode === CLOSURE_MODE.TEARDOWN ||
            dstState.closureMode === CLOSURE_MODE.TEARDOWN
          ) {
            return
          }
          teardownBoth()
        })
    }
    loop()
  }

  pumpLeg(prevState, nextState, previousPayloadHandler)
  pumpLeg(nextState, prevState)

  return owner
}

function sendPeerM3ForwardingTailControl(owner, envelope) {
  const state = safeObject(owner) ? FORWARDING_OWNERS.get(owner) : null
  if (!state || !state.active || state.prevState.cleared || state.nextState.cleared) destroyed()
  if (!fixed(envelope, 1101) || envelope[0] !== PEER_TAIL_CONTROL_CONTEXT_CLASS) invalid()
  checkRuntimeTime(state.nextState)
  return sendPeerM3PayloadInternal(state.prevState, envelope)
}

function destroyPeerM3ForwardingOwner(owner) {
  if (!safeObject(owner)) return false
  const state = FORWARDING_OWNERS.get(owner)
  if (!state || !state.active) return false
  state.active = false
  FORWARDING_OWNERS.delete(owner)

  if (state.prevReg) {
    revokeStatePhysicalLossSink(state.prevReg)
    state.prevReg = null
  }
  if (state.nextReg) {
    revokeStatePhysicalLossSink(state.nextReg)
    state.nextReg = null
  }

  destroyRuntimeState(state.prevState, { source: 'forwarding-destroy' })
  destroyRuntimeState(state.nextState, { source: 'forwarding-destroy' })
  return true
}

function peerM3PayloadContextClass(item) {
  if (!safeObject(item) || item.class !== CELL_CLASS.DATAGRAM || !fixed(item.payload, 1101)) {
    return -1
  }
  return item.payload[0]
}

function canTakeFinalCarrierQueue(state) {
  if (state.waiters.length !== 0) return false
  for (const item of state.received) {
    const contextClass = peerM3PayloadContextClass(item)
    // Class6 needs purpose negotiation; only early class5 may cross this move.
    if (
      contextClass !== PEER_TAIL_CONTROL_CONTEXT_CLASS &&
      contextClass !== PEER_TAIL_FINALIZE_CONTEXT_CLASS
    )
      return false
  }
  return true
}

function authorizePeerM3FinalCarrierTake(
  runtime,
  clockIdentity,
  generation,
  parentLocalDeadline,
  wireExpiresAt,
  localDeadline,
  readinessTrain
) {
  const pending = FINAL_CARRIER_TAKES.get(runtime)
  const state = RUNTIMES.get(runtime)
  if (
    !pending ||
    pending.authorized ||
    state !== pending.state ||
    state.cleared ||
    state.closureMode !== CLOSURE_MODE.NONE ||
    clockIdentity !== state.clockIdentity ||
    generation !== state.generation ||
    parentLocalDeadline !== state.localDeadline ||
    !u64(wireExpiresAt) ||
    wireExpiresAt <= pending.wall ||
    wireExpiresAt > state.wireExpiresAt ||
    !u64(localDeadline) ||
    localDeadline <= pending.mono ||
    localDeadline > state.localDeadline ||
    !canTakeFinalCarrierQueue(state) ||
    (readinessTrain !== null && (readinessTrain.settled || readinessTrain.deadline <= pending.mono))
  )
    return false
  pending.wireExpiresAt = wireExpiresAt
  pending.localDeadline = localDeadline
  pending.readinessTrain = readinessTrain
  pending.authorized = true
  return true
}

function issuePeerM3RouteCarrier(runtime, finalAuthorization) {
  if (!isPeerM3Runtime(runtime)) invalid()
  const state = RUNTIMES.get(runtime)
  let wall
  let mono
  try {
    mono = state.monotonicNow()
    wall = state.wallNow()
  } catch {
    destroyRuntimeState(state)
    destroyed()
  }
  if (!u64(wall) || !u64(mono) || wall >= state.wireExpiresAt || mono >= state.localDeadline) {
    destroyRuntimeState(state, { source: 'expired' })
    destroyed()
  }
  if (RUNTIMES.get(runtime) !== state || state.cleared || state.closureMode !== CLOSURE_MODE.NONE) {
    destroyed()
  }
  if (!canTakeFinalCarrierQueue(state)) busy()
  const { takePeerFinalCarrierAuthorization } = require('./peer-tail-control')
  const carrierOwner = Object.freeze({})
  const record = {
    owner: carrierOwner,
    runtime,
    state,
    wall,
    mono,
    authorized: false,
    wireExpiresAt: 0n,
    localDeadline: 0n,
    phase: 0,
    active: true
  }
  FINAL_CARRIER_TAKES.set(runtime, record)
  try {
    takePeerFinalCarrierAuthorization(finalAuthorization, runtime)
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    unauthorized()
  } finally {
    FINAL_CARRIER_TAKES.delete(runtime)
  }
  if (!record.authorized) {
    destroyRuntimeState(state)
    unauthorized()
  }
  state.finalCarrierTaken = true
  const readinessTrain = record.readinessTrain
  if (readinessTrain) {
    state.finalReadinessTrain = readinessTrain
    // Only the already-sealed READY2 envelope may use this transferred send duty.
    // Its original counter, attempts, deadline and storage move without resetting.
    readinessTrain.sendAfterTake = () => sendPeerM3PayloadInternal(state, readinessTrain.envelope)
    readinessTrain.drained.then(() => {
      if (state.finalReadinessTrain === readinessTrain && readinessTrain.closedBy === 'attempts') {
        releaseFinalReadiness(state)
      }
    })
    readinessTrain.expired.catch(() => {
      if (state.finalReadinessTrain !== readinessTrain) return
      releaseFinalReadiness(state)
      destroyRuntimeState(state, { source: 'readiness-failed' })
    })
  }
  // Final tail authorization retires old control traffic. Preserve already-arrived
  // finalization frames in order, without copying or charging another attempt.
  let retained = 0
  for (const item of state.received) {
    if (item.payload[0] === PEER_TAIL_CONTROL_CONTEXT_CLASS) clear(item.payload)
    else state.received[retained++] = item
  }
  state.received.length = retained
  RUNTIMES.delete(runtime)
  MOVED_RUNTIMES.add(runtime)
  ROUTE_CARRIER_AUTHORIZATIONS.set(carrierOwner, record)
  return carrierOwner
}

function takePeerM3RouteCarrier(owner) {
  if (!safeObject(owner)) return null
  if (TAKEN_ROUTE_CARRIER_OWNERS.has(owner)) throw PrivateRouteError.ERR_REPLAY()
  const carrierRecord = ROUTE_CARRIER_AUTHORIZATIONS.get(owner)
  if (!carrierRecord) return null
  ROUTE_CARRIER_AUTHORIZATIONS.delete(owner)
  TAKEN_ROUTE_CARRIER_OWNERS.add(owner)

  const state = carrierRecord.state
  if (!carrierRecord.active || state.cleared) throw PrivateRouteError.ERR_DESTROYED()
  const carrierReservations = new Set()
  const consumedReservations = new WeakSet()
  const timers = new Set()
  const setFn = state.setTimer || state.authorityState.setTimer
  const clearFn = state.clearTimer || state.authorityState.clearTimer

  function cancelTimer(timer) {
    if (!timer.active) return false
    timer.active = false
    timer.callback = null
    timers.delete(timer)
    if (timer.registered) {
      timer.registered = false
      try {
        clearFn(timer.handle)
      } catch {}
      timer.handle = null
    }
    return true
  }

  function releaseCarrier() {
    const active = carrierRecord.active
    carrierRecord.active = false
    if (state.carrierCleanup === releaseCarrier) state.carrierCleanup = null
    for (const timer of Array.from(timers)) cancelTimer(timer)
    for (const record of carrierReservations) {
      record.cancelled = true
      CARRIER_RECEIVE_RESERVATIONS.delete(record.reservation)
    }
    carrierReservations.clear()
    return active
  }

  // `source` only labels the cause for the runtime's own closure duty; it never selects
  // between the mutually exclusive DESTROY and TEARDOWN modes the runtime already owns.
  function destroyCarrier(source) {
    const active = releaseCarrier()
    if (!state.cleared) destroyRuntimeState(state, { source })
    return active
  }

  // Pure liveness: returns one paired clock sample or null. It never mutates and never
  // closes anything, so an inspection can never retire a live route.
  function evaluate() {
    if (!carrierRecord.active || state.cleared || state.closureMode !== CLOSURE_MODE.NONE) {
      return null
    }
    let mono
    let wall
    try {
      mono = state.monotonicNow()
      wall = state.wallNow()
    } catch {
      return null
    }
    // The clock functions are foreign callbacks: re-check the owner after reading them.
    if (
      !carrierRecord.active ||
      state.cleared ||
      state.closureMode !== CLOSURE_MODE.NONE ||
      !u64(mono) ||
      !u64(wall) ||
      mono >= carrierRecord.localDeadline ||
      wall >= carrierRecord.wireExpiresAt
    ) {
      return null
    }
    return { mono, wall }
  }

  function live() {
    const now = evaluate()
    if (now === null) {
      destroyCarrier('expired')
      throw PrivateRouteError.ERR_DESTROYED()
    }
    return now
  }

  // One arming discipline for every carrier timer. A scheduler that dispatches
  // synchronously has already run the duty and cancelled the timer inside `onExpiry`;
  // the only remaining obligation is releasing its handle, which is not a failure.
  function arm(delayMs, callback, guarded) {
    const timer = { active: true, registered: false, handle: null, callback }
    timers.add(timer)
    const onExpiry = () => {
      if (!timer.active) return
      const fire = timer.callback
      timer.registered = false
      timer.handle = null
      cancelTimer(timer)
      if (guarded) {
        try {
          live()
        } catch {
          return
        }
      }
      fire()
    }
    let handle = null
    try {
      handle = setFn(onExpiry, delayMs)
    } catch (err) {
      cancelTimer(timer)
      throw err
    }
    if (!timer.active) {
      try {
        clearFn(handle)
      } catch {}
      return null
    }
    timer.handle = handle
    timer.registered = true
    return timer
  }

  function schedule(delayMs, callback) {
    if (typeof delayMs !== 'number' || !Number.isFinite(delayMs) || typeof callback !== 'function')
      invalid()
    const { mono, wall } = live()
    const localRemaining = carrierRecord.localDeadline - mono
    const wireRemaining = carrierRecord.wireExpiresAt - wall
    const remaining = localRemaining < wireRemaining ? localRemaining : wireRemaining
    const boundedDelay = Math.min(Math.max(delayMs, 0), timerDelay(remaining))
    let timer
    try {
      timer = arm(boundedDelay, callback, true)
    } catch (err) {
      destroyCarrier('local-destroy')
      throw err instanceof PrivateRouteError ? err : PrivateRouteError.INVALID_ROUTE()
    }
    if (timer === null) {
      // Dispatched inline: the callback already ran under its own liveness guard, so the
      // only remaining question is whether this carrier survived that dispatch.
      live()
      return () => false
    }
    live()
    return () => cancelTimer(timer)
  }

  // Outer context selection is a local authority. Class5 carries finalization, class6
  // carries route traffic, and nothing observed on the wire moves either choice.
  function sendContextFrame(contextClass, frame) {
    let envelope = null
    try {
      live()
      if (!fixed(frame, 1100)) invalid()
      envelope = encodePeerContextEnvelope(contextClass, frame)
      return sendPeerM3PayloadInternal(state, { class: CELL_CLASS.DATAGRAM, payload: envelope })
    } catch (err) {
      return Promise.reject(err)
    } finally {
      clear(envelope)
    }
  }

  // Incoming outer class never promotes local phase. `expectedClass` is null for the
  // class-aware reader, which reports whichever authenticated class arrived; the
  // class-blind compatibility reader passes the class its caller can key, so a class5
  // finalization frame can never reach a caller expecting class6 route bytes.
  function consumeReceiveReservation(reservation, expectedClass) {
    if (safeObject(reservation) && consumedReservations.has(reservation)) {
      throw PrivateRouteError.ERR_REPLAY()
    }
    const record = safeObject(reservation) ? CARRIER_RECEIVE_RESERVATIONS.get(reservation) : null
    if (!record || record.carrier !== carrier) invalid()
    live()
    record.consumed = true
    consumedReservations.add(reservation)
    return receivePeerM3PayloadItemInternal(state)
      .then((item) => {
        let decoded = null
        try {
          live()
          if (record.cancelled) throw PrivateRouteError.ERR_DESTROYED()
          // Finalization and route frames are both DATAGRAM contexts; a route envelope
          // arriving on the adjacency CONTROL lane is not route material.
          const contextClass = peerM3PayloadContextClass(item)
          if (
            (contextClass !== PEER_TAIL_FINALIZE_CONTEXT_CLASS &&
              contextClass !== PEER_ROUTE_CONTEXT_CLASS) ||
            (expectedClass !== null && contextClass !== expectedClass)
          ) {
            invalid()
          }
          decoded = decodePeerContextEnvelope(item.payload)
          const opened = decoded
          decoded = null
          return opened
        } catch (err) {
          if (decoded !== null) clear(decoded.frame)
          throw err
        } finally {
          if (safeObject(item)) clear(item.payload)
        }
      })
      .finally(() => {
        CARRIER_RECEIVE_RESERVATIONS.delete(reservation)
        carrierReservations.delete(record)
      })
  }

  // Private capability metadata for the purpose owner: the authorized final bounds from
  // the take compare-and-swap plus this runtime's own clock functions and clock identity.
  // Built once, frozen once, handed out by reference. It mints nothing, holds no sample,
  // and never rebases: the purpose owner takes its own paired sample under this identity
  // and caps its child projection with these bounds.
  const clockTuple = Object.freeze({
    clockIdentity: state.clockIdentity,
    wireExpiresAt: carrierRecord.wireExpiresAt,
    localDeadline: carrierRecord.localDeadline,
    wallNow: state.wallNow,
    monotonicNow: state.monotonicNow
  })

  const carrier = Object.freeze({
    // Phase default: finalization before local route readiness, route traffic after.
    sendFrame(frame) {
      return sendContextFrame(
        carrierRecord.phase === 1 ? PEER_ROUTE_CONTEXT_CLASS : PEER_TAIL_FINALIZE_CONTEXT_CLASS,
        frame
      )
    },

    // A cached canonical OFFER/ACCEPT retry keeps sealing a fresh class5 wrapper after
    // local class6 readiness; readiness never revokes a finalization retry obligation.
    sendFinalizeFrame(frame) {
      return sendContextFrame(PEER_TAIL_FINALIZE_CONTEXT_CLASS, frame)
    },

    // Locally authorized class6 readiness, taken exactly once. It is not a second
    // ownership move: the one runtime-to-carrier drain already happened under the take
    // compare-and-swap, so buffered finalize retries and outstanding reservations
    // remain valid across it and never fail the promotion.
    activate() {
      live()
      if (carrierRecord.phase !== 0) throw PrivateRouteError.ERR_REPLAY()
      carrierRecord.phase = 1
      return true
    },

    reserveReceive() {
      live()
      const reservation = Object.freeze({})
      const record = { reservation, carrier, consumed: false, cancelled: false }
      CARRIER_RECEIVE_RESERVATIONS.set(reservation, record)
      carrierReservations.add(record)
      return reservation
    },

    // Reports the authenticated adjacency context class with the owned frame copy. The
    // purpose owner authenticates class5 finalization and class6 route payloads, so it
    // reads here and an independently identified class5 retry always arrives.
    receiveEnvelope(reservation) {
      return consumeReceiveReservation(reservation, null)
    },

    // Compatibility reader for the existing route-transport bridge, which cannot see a
    // class tag. It keeps the phase-appropriate class fixed at call time: finalization
    // before local route readiness, route traffic after.
    receiveFrame(reservation) {
      return consumeReceiveReservation(
        reservation,
        carrierRecord.phase === 1 ? PEER_ROUTE_CONTEXT_CLASS : PEER_TAIL_FINALIZE_CONTEXT_CLASS
      ).then((opened) => opened.frame)
    },

    cancelReceive(reservation) {
      const record = safeObject(reservation) ? CARRIER_RECEIVE_RESERVATIONS.get(reservation) : null
      if (!record || record.carrier !== carrier || record.consumed || record.cancelled) return false
      record.cancelled = true
      CARRIER_RECEIVE_RESERVATIONS.delete(reservation)
      carrierReservations.delete(record)
      return true
    },

    schedule,

    // The one frozen capability tuple, exposed by reference.
    clock: clockTuple,

    destroy() {
      return destroyCarrier('local-destroy')
    },

    diagnostics() {
      const now = evaluate()
      return Object.freeze({
        active: now !== null,
        expiresAt: now === null ? 0n : carrierRecord.wireExpiresAt
      })
    }
  })

  // Final-bound duty. Both authorized bounds are fixed at take time, but the wall and
  // monotonic clocks advance independently of the scheduler, so a fire re-samples both
  // and settles the carrier only once a bound is actually reached; otherwise it re-arms
  // for the freshly computed nearer remainder. A live sample proves both bounds are
  // still in the future, so every re-arm requests at least one millisecond and the duty
  // can neither spin nor recurse through its own callback.
  let lifetimeArming = false
  let lifetimeSyncFire = false

  function lifetimeExpiry() {
    if (lifetimeArming) {
      lifetimeSyncFire = true
      return
    }
    armLifetime()
  }

  function armLifetime() {
    const now = evaluate()
    if (now === null) {
      destroyCarrier('expired')
      return
    }
    const localRemaining = carrierRecord.localDeadline - now.mono
    const wireRemaining = carrierRecord.wireExpiresAt - now.wall
    const remaining = localRemaining < wireRemaining ? localRemaining : wireRemaining
    lifetimeSyncFire = false
    lifetimeArming = true
    let timer
    try {
      timer = arm(timerDelay(remaining), lifetimeExpiry, false)
    } finally {
      lifetimeArming = false
    }
    if (timer !== null) return
    if (!lifetimeSyncFire) return
    // The request was at least one millisecond and the scheduler dispatched it inline:
    // it cannot carry a deadline duty at all. Fail closed on that local defect instead
    // of leaving the authorized bounds unenforced.
    destroyCarrier('local-destroy')
  }

  state.carrierCleanup = releaseCarrier
  try {
    armLifetime()
  } catch (err) {
    // A scheduler that throws on registration leaves the bounds unenforceable; the take
    // fails closed as a route error rather than surfacing a host exception.
    destroyCarrier('local-destroy')
    throw err instanceof PrivateRouteError ? err : PrivateRouteError.INVALID_ROUTE()
  }
  if (!carrierRecord.active) throw PrivateRouteError.ERR_DESTROYED()
  return carrier
}

module.exports = {
  createPeerM3AdjacencyAuthority,
  adoptPeerEstablishedLink,
  isPeerM3Runtime,
  isPeerM3RuntimeForLink,
  readPeerM3Runtime,
  takePeerM3TailMaterial,
  takePeerM3ExtensionProof,
  sendPeerM3Payload,
  receivePeerM3Payload,
  destroyPeerM3Runtime,
  takePeerM3ClosureSendPermit,
  beginPeerM3BranchTeardown,
  registerPeerM3PhysicalLossSink,
  revokePeerM3PhysicalLossSink,
  createPeerM3ForwardingOwner,
  sendPeerM3ForwardingTailControl,
  destroyPeerM3ForwardingOwner,
  authorizePeerM3FinalCarrierTake,
  issuePeerM3RouteCarrier,
  takePeerM3RouteCarrier,
  DEFAULT_MAX_M3_ADJACENCY_RUNTIMES,
  MAX_M3_ADJACENCY_RUNTIMES,
  TEST_ONLY_M3_ADJACENCY_OBSERVER
}
