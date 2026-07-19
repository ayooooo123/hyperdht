'use strict'

const b4a = require('b4a')

const { PrivateRouteError } = require('./errors')
const { CELL_CLASS, DIRECTION, PROTOCOL_VERSION } = require('./protocol')

// Ported from the reviewed private-routes prototype at commit
// 0305df915b6a767093f9e75e6c06bc0a35da6169 and narrowed to Gate 3B1.
// The prototype's remote actor and async route-control integrations are excluded;
// this owner retains only authenticated adjacent-link control and teardown.

const LINK_PING_AFTER = 500
const LINK_UNRESPONSIVE_AFTER = 1_500
const STREAM_ACK_TIMEOUT = 5_000
const LINK_CIRCUIT_TEARDOWN_TIMEOUT = 5_000
const DEFAULT_MAX_UNACKNOWLEDGED_STREAMS = 64
const DEFAULT_MAX_UNACKNOWLEDGED_BYTES = 64 * 1_146
const DEFAULT_MAX_STREAM_SPACES = 64
const DEFAULT_MAX_CONTROL_SENDS = 64
const MAX_EVENT_PAYLOAD = 1_146
const MAX_UINT64 = (1n << 64n) - 1n
const CONTROL_NAMESPACE_LINK = 0
const LINK_CONTROL_SIZE = 45
const LINK_CONTROL_KIND = Object.freeze({ PING: 0, PONG: 1, ACK: 2, DESTROY: 3 })
const CIRCUIT_DESTROY_REASON = Object.freeze({
  REQUESTED: 0,
  EXPIRED: 1,
  REVOKED: 2,
  TRANSPORT_LOST: 3,
  ACK_TIMEOUT: 4
})
const DESTROY_REASONS = new Set(Object.values(CIRCUIT_DESTROY_REASON))
const CONSUMERS = new WeakMap()
const EVENTS = new WeakMap()
const SESSIONS = new WeakMap()
const DIRECTION_CAPABILITIES = new WeakMap()
const TEARDOWNS = new WeakMap()
const CONTROL_CONSUMED = Object.freeze({})
const TEST_ONLY_LINK_CONTROL_SESSION_OBSERVER = Symbol('test-only-link-control-session-observer')
const bufferByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
const bufferSet = Uint8Array.prototype.set
const bufferSubarray = Uint8Array.prototype.subarray
const bufferFill = Uint8Array.prototype.fill

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function unavailable() {
  return PrivateRouteError.ROUTE_UNAVAILABLE()
}

function isObject(value) {
  try {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
  } catch {
    return false
  }
}

function fixed(value, size) {
  try {
    return b4a.isBuffer(value) && bufferByteLength.call(value) === size
  } catch {
    return false
  }
}

function clear(value) {
  try {
    if (value && b4a.isBuffer(value)) b4a.fill(value, 0)
  } catch {}
}

function same(left, right) {
  try {
    return fixed(left, bufferByteLength.call(right)) && b4a.equals(left, right)
  } catch {
    return false
  }
}

function allZero(value) {
  try {
    for (const byte of value) if (byte !== 0) return false
    return true
  } catch {
    return true
  }
}

function u64(value, nonzero = false) {
  return typeof value === 'bigint' && value >= (nonzero ? 1n : 0n) && value <= MAX_UINT64
}

function knownDirection(value) {
  return value === DIRECTION.FORWARD || value === DIRECTION.REVERSE
}

function knownClass(value) {
  return (
    value === CELL_CLASS.CONTROL || value === CELL_CLASS.STREAM || value === CELL_CLASS.DATAGRAM
  )
}

function opposite(value) {
  if (!knownDirection(value)) invalid()
  return value === DIRECTION.FORWARD ? DIRECTION.REVERSE : DIRECTION.FORWARD
}

function bound(value, fallback) {
  if (value === undefined) return fallback
  if (!Number.isSafeInteger(value) || value < 1 || value > fallback) invalid()
  return value
}

function set(target, source, offset) {
  try {
    bufferSet.call(target, source, offset)
  } catch {
    invalid()
  }
}

function slice(value, start, end) {
  try {
    return bufferSubarray.call(value, start, end)
  } catch {
    invalid()
  }
}

function writeU64(buffer, value, offset) {
  for (let index = offset + 7; index >= offset; index--) {
    buffer[index] = Number(value & 0xffn)
    value >>= 8n
  }
}

function readU64(buffer, offset) {
  let value = 0n
  for (let index = offset; index < offset + 8; index++)
    value = (value << 8n) | BigInt(buffer[index])
  return value
}

function encodeLink(state, message) {
  let output = null
  try {
    output = b4a.allocUnsafeSlow(LINK_CONTROL_SIZE)
    output[0] = CONTROL_NAMESPACE_LINK
    output[1] = PROTOCOL_VERSION
    output[2] = message.kind
    output[3] = 0
    output[4] = message.direction
    set(output, state.circuitId, 5)
    writeU64(output, message.generation || 0n, 21)
    if (message.kind === LINK_CONTROL_KIND.ACK) {
      writeU64(output, message.counter, 29)
      bufferFill.call(output, 0, 37)
    } else if (message.kind === LINK_CONTROL_KIND.DESTROY) {
      output[29] = message.reason
      bufferFill.call(output, 0, 30)
    } else {
      set(output, message.challenge, 29)
    }
    return output
  } catch (err) {
    clear(output)
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function decodeLink(state, payload, direction) {
  if (!fixed(payload, LINK_CONTROL_SIZE) || payload[0] !== 0 || payload[1] !== PROTOCOL_VERSION)
    invalid()
  const kind = payload[2]
  if (kind < 0 || kind > 3 || payload[3] !== 0 || payload[4] !== direction) invalid()
  if (!same(slice(payload, 5, 21), state.circuitId)) invalid()
  const generation = readU64(payload, 21)
  if (kind === LINK_CONTROL_KIND.ACK) {
    if (generation === 0n) invalid()
    for (let index = 37; index < 45; index++) if (payload[index] !== 0) invalid()
    return {
      kind,
      direction,
      generation,
      acknowledgedDirection: opposite(direction),
      counter: readU64(payload, 29)
    }
  }
  if (kind === LINK_CONTROL_KIND.DESTROY) {
    if (generation !== 0n || !DESTROY_REASONS.has(payload[29])) invalid()
    for (let index = 30; index < 45; index++) if (payload[index] !== 0) invalid()
    return { kind, direction, generation, reason: payload[29] }
  }
  const challenge = b4a.from(slice(payload, 29, 45))
  if (generation !== 0n || allZero(challenge)) {
    clear(challenge)
    invalid()
  }
  return { kind, direction, generation, challenge }
}

function readNow(state) {
  let now
  try {
    now = state.now()
  } catch {
    throw unavailable()
  }
  if (!Number.isSafeInteger(now) || now < 0 || now < state.lastNow || state.closed)
    throw unavailable()
  state.lastNow = now
  return now
}

function cancelTimer(state, name) {
  const timer = state[name]
  state[name] = null
  if (timer === null) return
  try {
    state.cancel(timer)
  } catch {}
}

function arm(state, name, delay, operation) {
  let arming = true
  let synchronous = false
  let timer = null
  const callback = () => {
    if (arming) {
      synchronous = true
      return
    }
    if (state.closed || state[name] !== timer) return
    state[name] = null
    try {
      operation()
    } catch {
      closeState(state)
    }
  }
  try {
    timer = state.schedule(callback, delay)
  } catch {
    arming = false
    throw unavailable()
  }
  arming = false
  if (synchronous || timer === null || timer === undefined || state.closed) {
    try {
      state.cancel(timer)
    } catch {}
    throw unavailable()
  }
  state[name] = timer
}

function closeState(state, reason = 'ROUTE_UNAVAILABLE') {
  if (!state || state.closed) return false
  state.closed = true
  state.reason = reason
  cancelTimer(state, 'livenessTimer')
  cancelTimer(state, 'ackTimer')
  clear(state.challenge)
  state.challenge = null
  for (const space of state.streams.values()) space.records.length = 0
  state.streams.clear()
  state.inboundStreams.clear()
  state.pendingStreams = 0
  state.pendingBytes = 0
  const sends = Array.from(state.sendRecords)
  state.sendRecords.clear()
  for (const record of sends) {
    record.active = false
    clear(record.payload)
    if (record.reject) record.reject(unavailable())
  }
  try {
    state.cancelPending()
  } catch {}
  try {
    state.notifyCircuit(state.heartbeatDirection, reason)
  } catch {}
  try {
    state.closeLink()
  } catch {}
  const authority = state.control ? CONSUMERS.get(state.control) : null
  if (authority) authority.session = CONTROL_CONSUMED
  clear(state.circuitId)
  state.control = null
  state.circuitId = null
  state.now = null
  state.schedule = null
  state.cancel = null
  state.randomBytes = null
  state.sendControl = null
  state.cancelPending = null
  state.notifyCircuit = null
  state.closeLink = null
  return true
}

function sendPayload(state, payload, wait = false) {
  if (state.closed || state.sendRecords.size >= state.maxControlSends) {
    clear(payload)
    closeState(state, 'CIRCUIT_LIMIT')
    throw unavailable()
  }
  let resolve = null
  let reject = null
  const completion = wait
    ? new Promise((res, rej) => {
        resolve = res
        reject = rej
      })
    : true
  const record = { payload, active: true, resolve, reject }
  state.sendRecords.add(record)
  let sending
  try {
    sending = state.sendControl(payload)
  } catch {
    state.sendRecords.delete(record)
    record.active = false
    clear(payload)
    closeState(state)
    throw unavailable()
  }
  Promise.resolve(sending).then(
    (sent) => {
      if (!record.active) return
      record.active = false
      state.sendRecords.delete(record)
      clear(record.payload)
      if (sent === true) {
        if (resolve) resolve(true)
      } else {
        if (reject) reject(unavailable())
        closeState(state)
      }
    },
    () => {
      if (!record.active) return
      record.active = false
      state.sendRecords.delete(record)
      clear(record.payload)
      if (reject) reject(unavailable())
      closeState(state)
    }
  )
  return completion
}

function sendLink(state, message, wait = false) {
  return sendPayload(state, encodeLink(state, message), wait)
}

function scheduleLiveness(state) {
  if (state.closed) return
  const current = readNow(state)
  const due = Math.min(state.nextPingAt, state.lastActivity + LINK_UNRESPONSIVE_AFTER)
  arm(state, 'livenessTimer', Math.max(0, due - current), () => runLiveness(state))
}

function sendPing(state) {
  let challenge = null
  try {
    challenge = state.randomBytes(16)
    if (!fixed(challenge, 16) || allZero(challenge) || state.closed) throw unavailable()
    clear(state.challenge)
    state.challenge = b4a.from(challenge)
    state.nextPingAt = state.lastNow + LINK_PING_AFTER
    sendLink(state, {
      kind: LINK_CONTROL_KIND.PING,
      direction: state.heartbeatDirection,
      generation: 0n,
      challenge
    })
  } catch {
    closeState(state)
  } finally {
    clear(challenge)
  }
}

function runLiveness(state) {
  if (state.closed) return
  const current = readNow(state)
  if (current - state.lastActivity >= LINK_UNRESPONSIVE_AFTER) return void closeState(state)
  if (current >= state.nextPingAt) sendPing(state)
  if (!state.closed) scheduleLiveness(state)
}

function streamKey(direction, generation) {
  return `${direction}:${generation}`
}

function oldest(state) {
  let result = null
  for (const space of state.streams.values()) {
    const record = space.records[0]
    if (record && (!result || record.deadline < result.deadline)) result = record
  }
  return result
}

function scheduleAck(state) {
  cancelTimer(state, 'ackTimer')
  const record = oldest(state)
  if (!record || state.closed) return
  const current = readNow(state)
  arm(state, 'ackTimer', Math.max(0, record.deadline - current), () => {
    const currentRecord = oldest(state)
    if (currentRecord && readNow(state) >= currentRecord.deadline) closeState(state, 'ACK_TIMEOUT')
    else scheduleAck(state)
  })
}

function acknowledge(state, message) {
  const space = state.streams.get(streamKey(message.acknowledgedDirection, message.generation))
  if (
    !space ||
    space.highestSent === null ||
    message.counter > space.highestSent ||
    (space.highestAck !== null && message.counter <= space.highestAck)
  )
    throw unavailable()
  let released = 0
  while (space.records.length && space.records[0].counter <= message.counter) {
    const record = space.records.shift()
    state.pendingStreams--
    state.pendingBytes -= record.bytes
    released++
  }
  if (released === 0) throw unavailable()
  space.highestAck = message.counter
  scheduleAck(state)
}

function receiveLink(state, message) {
  if (message.kind === LINK_CONTROL_KIND.DESTROY) {
    clear(message.challenge)
    closeState(state, 'TRANSPORT_LOST')
    return true
  }
  if (message.kind === LINK_CONTROL_KIND.PING) {
    try {
      return sendLink(state, {
        kind: LINK_CONTROL_KIND.PONG,
        direction: opposite(message.direction),
        generation: 0n,
        challenge: message.challenge
      })
    } finally {
      clear(message.challenge)
    }
  }
  if (message.kind === LINK_CONTROL_KIND.PONG) {
    const accepted =
      state.challenge &&
      message.direction === opposite(state.heartbeatDirection) &&
      same(message.challenge, state.challenge)
    clear(message.challenge)
    if (!accepted) throw unavailable()
    clear(state.challenge)
    state.challenge = null
    return true
  }
  acknowledge(state, message)
  return true
}

function createLinkControlBoundary(options = {}) {
  if (!isObject(options)) invalid()
  const { link, epoch, circuitId } = options
  if (!isObject(link) || !u64(epoch) || !fixed(circuitId, 16) || allZero(circuitId)) invalid()
  const consumer = Object.freeze({})
  const state = {
    link,
    epoch,
    circuitId: b4a.from(circuitId),
    events: new Set(),
    session: null,
    destroyed: false
  }
  CONSUMERS.set(consumer, state)
  return Object.freeze({
    consumer,
    pushAuthenticated(value) {
      if (
        state.destroyed ||
        !isObject(value) ||
        value.link !== link ||
        value.epoch !== epoch ||
        !same(value.circuitId, state.circuitId) ||
        !knownClass(value.class) ||
        !knownDirection(value.direction) ||
        !u64(value.generation) ||
        (value.class !== CELL_CLASS.CONTROL && !u64(value.generation, true)) ||
        !u64(value.counter) ||
        (value.deliver !== undefined && typeof value.deliver !== 'boolean') ||
        !b4a.isBuffer(value.payload) ||
        value.payload.byteLength > MAX_EVENT_PAYLOAD ||
        state.events.size >= 64
      )
        invalid()
      const event = Object.freeze({})
      EVENTS.set(event, {
        consumer,
        value: {
          class: value.class,
          direction: value.direction,
          generation: value.generation,
          counter: value.counter,
          deliver: value.deliver === undefined ? true : value.deliver,
          payload: b4a.from(value.payload)
        }
      })
      state.events.add(event)
      return event
    },
    destroy() {
      if (state.destroyed) return false
      state.destroyed = true
      CONSUMERS.delete(consumer)
      for (const event of state.events) {
        const record = EVENTS.get(event)
        if (record) clear(record.value.payload)
        EVENTS.delete(event)
      }
      state.events.clear()
      clear(state.circuitId)
      return true
    }
  })
}

function readEvent(event, consumer) {
  const state = CONSUMERS.get(consumer)
  const record = isObject(event) ? EVENTS.get(event) : null
  if (!state || !record || record.consumer !== consumer) invalid()
  EVENTS.delete(event)
  state.events.delete(event)
  return record.value
}

class LinkControlSession {
  constructor(options = {}) {
    if (!isObject(options)) invalid()
    const {
      control,
      circuitId,
      epoch,
      heartbeatDirection,
      now,
      schedule,
      cancel,
      randomBytes,
      sendControl,
      cancelPending,
      notifyCircuit,
      closeLink
    } = options
    const authority = isObject(control) ? CONSUMERS.get(control) : null
    if (
      !authority ||
      !fixed(circuitId, 16) ||
      allZero(circuitId) ||
      !u64(epoch) ||
      !knownDirection(heartbeatDirection) ||
      typeof now !== 'function' ||
      typeof schedule !== 'function' ||
      typeof cancel !== 'function' ||
      typeof randomBytes !== 'function' ||
      typeof sendControl !== 'function' ||
      typeof cancelPending !== 'function' ||
      typeof notifyCircuit !== 'function' ||
      typeof closeLink !== 'function' ||
      authority.session !== null ||
      authority.epoch !== epoch ||
      !same(authority.circuitId, circuitId)
    )
      invalid()
    const state = {
      control,
      circuitId: b4a.from(circuitId),
      epoch,
      heartbeatDirection,
      now,
      schedule,
      cancel,
      randomBytes,
      sendControl,
      cancelPending,
      notifyCircuit,
      closeLink,
      maxPendingStreams: bound(options.maxPendingStreams, DEFAULT_MAX_UNACKNOWLEDGED_STREAMS),
      maxPendingBytes: bound(options.maxPendingBytes, DEFAULT_MAX_UNACKNOWLEDGED_BYTES),
      maxStreamSpaces: bound(options.maxStreamSpaces, DEFAULT_MAX_STREAM_SPACES),
      maxControlSends: bound(options.maxControlSends, DEFAULT_MAX_CONTROL_SENDS),
      streams: new Map(),
      inboundStreams: new Map(),
      sendRecords: new Set(),
      pendingStreams: 0,
      pendingBytes: 0,
      lastNow: -1,
      lastActivity: 0,
      nextPingAt: 0,
      livenessTimer: null,
      ackTimer: null,
      challenge: null,
      closed: false,
      reason: null,
      destroyPromise: null
    }
    authority.session = this
    SESSIONS.set(this, state)
    try {
      state.lastActivity = readNow(state)
      state.nextPingAt = state.lastActivity + LINK_PING_AFTER
      scheduleLiveness(state)
    } catch {
      closeState(state)
      throw unavailable()
    }
  }

  get closed() {
    return SESSIONS.get(this).closed
  }
  get pendingStreams() {
    return SESSIONS.get(this).pendingStreams
  }
  get pendingBytes() {
    return SESSIONS.get(this).pendingBytes
  }
  get pendingSends() {
    return SESSIONS.get(this).sendRecords.size
  }

  destroy(reason = CIRCUIT_DESTROY_REASON.REQUESTED) {
    const state = SESSIONS.get(this)
    if (!DESTROY_REASONS.has(reason)) return Promise.reject(unavailable())
    if (state.destroyPromise) return state.destroyPromise
    if (state.closed) return Promise.resolve(true)
    try {
      state.destroyPromise = Promise.resolve(
        sendLink(
          state,
          {
            kind: LINK_CONTROL_KIND.DESTROY,
            direction: state.heartbeatDirection,
            generation: 0n,
            reason
          },
          true
        )
      ).then(() => true)
    } catch {
      state.destroyPromise = Promise.resolve(false)
    }
    return state.destroyPromise.finally(() => closeState(state, 'REQUESTED'))
  }

  trackStream(direction, generation, counter, bytes) {
    const state = SESSIONS.get(this)
    if (state.closed) throw unavailable()
    try {
      if (
        !knownDirection(direction) ||
        !u64(generation, true) ||
        !u64(counter) ||
        !Number.isSafeInteger(bytes) ||
        bytes < 0 ||
        bytes > MAX_EVENT_PAYLOAD
      )
        invalid()
      if (counter === MAX_UINT64) throw PrivateRouteError.COUNTER_EXHAUSTED()
      const key = streamKey(direction, generation)
      let space = state.streams.get(key)
      if (!space) {
        if (counter !== 0n) throw PrivateRouteError.COUNTER_GAP()
        if (state.streams.size >= state.maxStreamSpaces) throw PrivateRouteError.CIRCUIT_LIMIT()
        space = {
          direction,
          generation,
          nextCounter: 0n,
          highestSent: null,
          highestAck: null,
          records: []
        }
        state.streams.set(key, space)
      }
      if (counter < space.nextCounter) throw PrivateRouteError.REPLAY()
      if (counter !== space.nextCounter) throw PrivateRouteError.COUNTER_GAP()
      if (
        state.pendingStreams >= state.maxPendingStreams ||
        state.pendingBytes + bytes > state.maxPendingBytes
      )
        throw PrivateRouteError.CIRCUIT_LIMIT()
      const current = readNow(state)
      space.records.push({ counter, bytes, deadline: current + STREAM_ACK_TIMEOUT })
      space.highestSent = counter
      space.nextCounter = counter + 1n
      state.pendingStreams++
      state.pendingBytes += bytes
      scheduleAck(state)
      return true
    } catch (err) {
      closeState(state, err && err.code === 'CIRCUIT_LIMIT' ? 'CIRCUIT_LIMIT' : 'ROUTE_UNAVAILABLE')
      throw err instanceof PrivateRouteError ? err : unavailable()
    }
  }

  receiveAuthenticated(event, handlers = {}) {
    const state = SESSIONS.get(this)
    if (state.closed || !isObject(handlers)) throw unavailable()
    let value = null
    let decoded = null
    try {
      value = readEvent(event, state.control)
      const current = readNow(state)
      if (!value.deliver) return true
      state.lastActivity = current
      state.nextPingAt = current + LINK_PING_AFTER
      cancelTimer(state, 'livenessTimer')
      scheduleLiveness(state)
      if (value.class === CELL_CLASS.CONTROL) {
        decoded = decodeLink(state, value.payload, value.direction)
        return receiveLink(state, decoded)
      }
      if (value.class === CELL_CLASS.STREAM) {
        if (typeof handlers.enqueueStream !== 'function') invalid()
        const key = streamKey(value.direction, value.generation)
        let inbound = state.inboundStreams.get(key)
        if (!inbound) {
          if (state.inboundStreams.size >= state.maxStreamSpaces || value.counter !== 0n)
            throw PrivateRouteError.COUNTER_GAP()
          inbound = { nextCounter: 0n, blocked: false }
          state.inboundStreams.set(key, inbound)
        }
        if (value.counter < inbound.nextCounter) throw PrivateRouteError.REPLAY()
        if (value.counter !== inbound.nextCounter) throw PrivateRouteError.COUNTER_GAP()
        inbound.nextCounter++
        if (inbound.blocked) return false
        let owned = b4a.from(value.payload)
        let accepted = false
        try {
          accepted =
            handlers.enqueueStream(owned, {
              class: CELL_CLASS.STREAM,
              direction: value.direction,
              generation: value.generation,
              counter: value.counter
            }) === true
          if (accepted) owned = null
        } finally {
          clear(owned)
        }
        if (!accepted) {
          inbound.blocked = true
          return false
        }
        sendLink(state, {
          kind: LINK_CONTROL_KIND.ACK,
          direction: opposite(value.direction),
          generation: value.generation,
          counter: value.counter
        })
        return true
      }
      if (typeof handlers.enqueueDatagram !== 'function') invalid()
      let owned = b4a.from(value.payload)
      let accepted = false
      try {
        accepted =
          handlers.enqueueDatagram(owned, {
            class: CELL_CLASS.DATAGRAM,
            direction: value.direction,
            generation: value.generation,
            counter: value.counter
          }) === true
        if (accepted) owned = null
        return accepted
      } finally {
        clear(owned)
      }
    } catch (err) {
      closeState(state)
      throw err instanceof PrivateRouteError ? err : unavailable()
    } finally {
      if (decoded) clear(decoded.challenge)
      if (value) clear(value.payload)
    }
  }

  close(reason = 'ROUTE_UNAVAILABLE') {
    return closeState(SESSIONS.get(this), reason)
  }

  [TEST_ONLY_LINK_CONTROL_SESSION_OBSERVER]() {
    const state = SESSIONS.get(this)
    const references = [
      state.control,
      state.circuitId,
      state.now,
      state.schedule,
      state.cancel,
      state.randomBytes,
      state.sendControl,
      state.cancelPending,
      state.notifyCircuit,
      state.closeLink,
      state.challenge
    ]
    return Object.freeze({
      retainedReferences: references.reduce((count, value) => count + (value !== null), 0),
      streams: state.streams.size,
      inboundStreams: state.inboundStreams.size,
      pendingSends: state.sendRecords.size,
      closed: state.closed
    })
  }
}

function readLinkControlStreamProgress(session, direction, generation) {
  const state = SESSIONS.get(session)
  if (!state || state.closed || !knownDirection(direction) || !u64(generation, true)) invalid()
  const space = state.streams.get(streamKey(direction, generation))
  if (!space)
    return Object.freeze({
      highestSent: null,
      highestAck: null,
      pendingStreams: 0,
      pendingBytes: 0
    })
  let pendingBytes = 0
  for (const record of space.records) pendingBytes += record.bytes
  return Object.freeze({
    highestSent: space.highestSent,
    highestAck: space.highestAck,
    pendingStreams: space.records.length,
    pendingBytes
  })
}

function createOpenCircuitDirectionCapability(options = {}) {
  if (
    !isObject(options) ||
    !isObject(options.link) ||
    !knownDirection(options.direction) ||
    !SESSIONS.has(options.session) ||
    options.session.closed
  )
    invalid()
  const capability = Object.freeze({})
  DIRECTION_CAPABILITIES.set(capability, {
    link: options.link,
    direction: options.direction,
    session: options.session
  })
  return capability
}

class LinkCircuitTeardown {
  constructor(options = {}) {
    if (
      !isObject(options) ||
      typeof options.now !== 'function' ||
      typeof options.schedule !== 'function' ||
      typeof options.cancel !== 'function'
    )
      invalid()
    TEARDOWNS.set(this, {
      now: options.now,
      schedule: options.schedule,
      cancel: options.cancel,
      records: new Set(),
      closed: false
    })
  }
  add(capability) {
    const state = TEARDOWNS.get(this)
    const record = DIRECTION_CAPABILITIES.get(capability)
    if (
      !state ||
      state.closed ||
      !record ||
      record.session.closed ||
      state.records.size >= DEFAULT_MAX_STREAM_SPACES
    )
      invalid()
    DIRECTION_CAPABILITIES.delete(capability)
    state.records.add({ ...record, timer: null })
    return true
  }
  fail(link, direction) {
    const state = TEARDOWNS.get(this)
    if (!state || state.closed || !isObject(link) || !knownDirection(direction)) invalid()
    let matched = false
    for (const record of state.records) {
      if (record.link !== link || record.direction !== direction) continue
      matched = true
      record.timer = state.schedule(() => {
        record.timer = null
        record.session.close('TRANSPORT_LOST')
        state.records.delete(record)
      }, LINK_CIRCUIT_TEARDOWN_TIMEOUT)
      void record.session
        .destroy(CIRCUIT_DESTROY_REASON.TRANSPORT_LOST)
        .finally(() => {
          if (record.timer !== null) state.cancel(record.timer)
          record.timer = null
          state.records.delete(record)
        })
        .catch(() => {})
    }
    return matched
  }
  close() {
    const state = TEARDOWNS.get(this)
    if (!state || state.closed) return Promise.resolve(true)
    state.closed = true
    for (const record of state.records) {
      if (record.timer !== null) state.cancel(record.timer)
      record.session.close()
    }
    state.records.clear()
    return Promise.resolve(true)
  }
}

module.exports = {
  TEST_ONLY_LINK_CONTROL_SESSION_OBSERVER,
  LINK_PING_AFTER,
  LINK_UNRESPONSIVE_AFTER,
  STREAM_ACK_TIMEOUT,
  LINK_CIRCUIT_TEARDOWN_TIMEOUT,
  DEFAULT_MAX_UNACKNOWLEDGED_STREAMS,
  DEFAULT_MAX_UNACKNOWLEDGED_BYTES,
  DEFAULT_MAX_STREAM_SPACES,
  DEFAULT_MAX_CONTROL_SENDS,
  CIRCUIT_DESTROY_REASON,
  createOpenCircuitDirectionCapability,
  LinkCircuitTeardown,
  createLinkControlBoundary,
  LinkControlSession,
  readLinkControlStreamProgress
}
