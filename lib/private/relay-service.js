'use strict'

const b4a = require('b4a')

const { PrivateRouteError } = require('./errors')
const { DIRECTION } = require('./protocol')
const { processSurbHop, consumeSurbForwardingAuthority, decodeSurbHopMessage } = require('./surb')
const { tryDecodeSurbHopCell, encodeSurbHopCell } = require('./surb-batch')

// Ported from the reviewed private-routes prototype at commit
// 0305df915b6a767093f9e75e6c06bc0a35da6169 and narrowed to Gate 3B1.

const MAX_RELAY_CIRCUITS = 128
const MAX_RELAY_CIRCUITS_PER_NEIGHBOR = 32
const MAX_RELAY_CIRCUIT_QUEUE = 256 * 1024
const MAX_RELAY_GLOBAL_QUEUE = 8 * 1024 * 1024
const RELAY_FORWARD_DEADLINE = 5_000
const MAX_RELAY_TOMBSTONES = 256
const TEST_ONLY_RELAY_SERVICE_OBSERVER = Symbol('test-only-relay-service-observer')
const STATES = new WeakMap()
const bufferByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
const bufferSet = Uint8Array.prototype.set
const bufferFill = Uint8Array.prototype.fill

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function destroyed() {
  throw PrivateRouteError.ERR_DESTROYED()
}

function busy() {
  throw PrivateRouteError.ERR_BUSY()
}

function quota() {
  throw PrivateRouteError.ERR_QUOTA_EXCEEDED()
}

function unavailable() {
  throw PrivateRouteError.ROUTE_UNAVAILABLE()
}

function isObject(value) {
  try {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
  } catch {
    return false
  }
}

function isBuffer(value, size = -1) {
  try {
    return b4a.isBuffer(value) && (size === -1 || bufferByteLength.call(value) === size)
  } catch {
    return false
  }
}

function fixedCopy(value, size) {
  if (!isBuffer(value, size)) invalid()
  return b4a.from(value)
}

function clear(value) {
  try {
    if (value && b4a.isBuffer(value)) bufferFill.call(value, 0)
  } catch {}
}

function u64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= (1n << 64n) - 1n
}

function knownDirection(value) {
  return value === DIRECTION.FORWARD || value === DIRECTION.REVERSE
}

function circuitKey(value) {
  if (!isBuffer(value, 16)) invalid()
  return b4a.toString(value, 'hex')
}

function peerKey(value) {
  if (!isBuffer(value, 32)) invalid()
  return b4a.toString(value, 'hex')
}

function clampLimit(value, fallback, minimum = 0) {
  if (value === undefined) return fallback
  if (!Number.isSafeInteger(value) || value < minimum) invalid()
  return value > fallback ? fallback : value
}

function readLimits(options) {
  const limits = isObject(options) ? options.limits : undefined
  if (limits !== undefined && !isObject(limits)) invalid()
  return Object.freeze({
    maxCircuits: clampLimit(limits && limits.maxCircuits, MAX_RELAY_CIRCUITS, 1),
    maxCircuitsPerNeighbor: clampLimit(
      limits && limits.maxCircuitsPerNeighbor,
      MAX_RELAY_CIRCUITS_PER_NEIGHBOR,
      1
    ),
    maxQueuedBytesPerCircuit: clampLimit(
      limits && limits.maxQueuedBytesPerCircuit,
      MAX_RELAY_CIRCUIT_QUEUE
    ),
    maxQueuedBytes: clampLimit(limits && limits.maxQueuedBytes, MAX_RELAY_GLOBAL_QUEUE)
  })
}

function createState(options) {
  if (!isObject(options)) invalid()
  if (
    typeof options.schedule !== 'function' ||
    typeof options.cancel !== 'function' ||
    typeof options.now !== 'function'
  ) {
    invalid()
  }
  const allocate = options.allocate === undefined ? b4a.allocUnsafeSlow : options.allocate
  if (typeof allocate !== 'function') invalid()
  return {
    schedule: options.schedule,
    cancel: options.cancel,
    now: options.now,
    allocate,
    onReserved: typeof options.onReserved === 'function' ? options.onReserved : null,
    onSent: typeof options.onSent === 'function' ? options.onSent : null,
    onExpired: typeof options.onExpired === 'function' ? options.onExpired : null,
    onEvent: typeof options.onEvent === 'function' ? options.onEvent : null,
    circuits: new Map(),
    peers: new Map(),
    tombstones: new Map(),
    fair: [],
    cursor: 0,
    globalBytes: 0,
    destroyed: false,
    dispatching: false
  }
}

function parseReserveArgs(first, second, third) {
  if (isObject(first) && second === undefined && third === undefined) return first
  if (!isObject(third)) third = {}
  return {
    ...third,
    peerId: first,
    circuitId: second
  }
}

function emit(state, event) {
  if (state.onEvent === null) return
  state.onEvent(Object.freeze({ ...event }))
}

function getPeerSet(state, key, create) {
  let set = state.peers.get(key)
  if (!set && create) {
    set = new Set()
    state.peers.set(key, set)
  }
  return set
}

function observeCircuit(record) {
  return Object.freeze({
    peerId: b4a.from(record.peerId),
    circuitId: b4a.from(record.circuitId),
    generation: record.generation,
    queuedBytes: record.queuedBytes,
    queuedCells: record.queue.length,
    expiresAt: record.expiresAt,
    previousHop: record.previousHop,
    nextHop: record.nextHop
  })
}

function addTombstone(state, key, reason, circuitId, peerId) {
  state.tombstones.delete(key)
  state.tombstones.set(
    key,
    Object.freeze({
      reason,
      circuitId: circuitId ? b4a.from(circuitId) : null,
      peerId: peerId ? b4a.from(peerId) : null,
      at: state.now()
    })
  )
  while (state.tombstones.size > MAX_RELAY_TOMBSTONES) {
    const oldest = state.tombstones.keys().next().value
    state.tombstones.delete(oldest)
  }
}

function removeFair(state, key) {
  const index = state.fair.indexOf(key)
  if (index === -1) return
  state.fair.splice(index, 1)
  if (state.cursor > index) state.cursor--
  if (state.cursor >= state.fair.length) state.cursor = 0
}

function releaseQueued(state, record) {
  for (const item of record.queue) clear(item.payload)
  record.queue.length = 0
  state.globalBytes -= record.queuedBytes
  if (state.globalBytes < 0) state.globalBytes = 0
  record.queuedBytes = 0
  removeFair(state, record.key)
}

function closeCapability(capability, reason) {
  if (!capability || !isObject(capability)) return
  if (typeof capability.destroy === 'function') capability.destroy(reason)
  else if (typeof capability.close === 'function') capability.close(reason)
}

function destroyRecord(state, record, reason, notify) {
  if (!record || record.closed) return false
  record.closed = true
  const key = record.key
  const previousHop = record.previousHop
  const nextHop = record.nextHop
  const peer = state.peers.get(record.peerKey)
  const queuedBytes = record.queuedBytes
  if (record.timer !== null) {
    try {
      state.cancel(record.timer)
    } catch {}
    record.timer = null
  }
  state.circuits.delete(key)
  if (peer) {
    peer.delete(key)
    if (peer.size === 0) state.peers.delete(record.peerKey)
  }
  releaseQueued(state, record)
  addTombstone(state, key, reason, record.circuitId, record.peerId)
  record.previousHop = null
  record.nextHop = null
  if (notify && state.onExpired !== null) state.onExpired(b4a.from(record.circuitId), reason)
  emit(state, { type: 'destroyed', circuitId: b4a.from(record.circuitId), reason, queuedBytes })
  try {
    closeCapability(previousHop, reason)
  } finally {
    closeCapability(nextHop, reason)
  }
  clear(record.circuitId)
  clear(record.peerId)
  return true
}

function lookup(state, circuitId) {
  if (state.destroyed) destroyed()
  const key = circuitKey(circuitId)
  const record = state.circuits.get(key)
  if (!record) {
    if (state.tombstones.has(key)) destroyed()
    invalid()
  }
  return record
}

function scheduleExpiry(state, record) {
  let timer = null
  try {
    timer = state.schedule(() => {
      if (record.closed || state.circuits.get(record.key) !== record) return
      destroyRecord(state, record, 'EXPIRED', true)
    }, RELAY_FORWARD_DEADLINE)
  } catch {
    unavailable()
  }
  if (timer === undefined || timer === null) invalid()
  record.timer = timer
  record.expiresAt = state.now() + RELAY_FORWARD_DEADLINE
}

function deliver(capability, payload, metadata) {
  if (!capability || !isObject(capability)) return false
  if (typeof capability.sendAuthenticated === 'function') {
    return capability.sendAuthenticated(payload, metadata) !== false
  }
  if (typeof capability.enqueueStream === 'function')
    return capability.enqueueStream(payload, metadata) === true
  if (typeof capability.send === 'function') return capability.send(payload, metadata) !== false
  if (typeof capability.forward === 'function')
    return capability.forward(payload, metadata) !== false
  return false
}

function rollBackQueued(state, record, item, bytes) {
  if (item !== null) clear(item.payload)
  if (record.queue[record.queue.length - 1] === item) record.queue.pop()
  const charged = item === null ? bytes : item.bytes
  record.queuedBytes -= charged
  state.globalBytes -= charged
  if (record.queuedBytes < 0) record.queuedBytes = 0
  if (state.globalBytes < 0) state.globalBytes = 0
  if (record.queue.length === 0) removeFair(state, record.key)
}

class RelayService {
  constructor(options = {}) {
    STATES.set(this, createState(options))
  }

  get destroyed() {
    const state = STATES.get(this)
    return !state || state.destroyed
  }

  reserveCircuit(first, second, third) {
    const state = STATES.get(this)
    if (!state || state.destroyed) destroyed()
    const options = parseReserveArgs(first, second, third)
    if (!isObject(options)) invalid()
    const key = circuitKey(options.circuitId)
    if (state.circuits.has(key)) invalid()
    if (state.tombstones.has(key)) destroyed()

    const pkey = peerKey(options.peerId)
    const peer = getPeerSet(state, pkey, false)
    const limits = readLimits(options)
    const generation = options.generation === undefined ? 0n : options.generation
    if (!u64(generation) || !isObject(options.previousHop) || !isObject(options.nextHop)) invalid()
    if (state.circuits.size >= limits.maxCircuits) quota()
    if (peer && peer.size >= limits.maxCircuitsPerNeighbor) busy()

    const record = {
      key,
      peerKey: pkey,
      peerId: fixedCopy(options.peerId, 32),
      circuitId: fixedCopy(options.circuitId, 16),
      generation,
      previousHop: options.previousHop,
      nextHop: options.nextHop,
      limits,
      queue: [],
      queuedBytes: 0,
      timer: null,
      expiresAt: 0,
      closed: false,
      seen: Object.freeze({
        [DIRECTION.FORWARD]: new Set(),
        [DIRECTION.REVERSE]: new Set()
      })
    }
    state.circuits.set(key, record)
    getPeerSet(state, pkey, true).add(key)
    try {
      scheduleExpiry(state, record)
      if (state.onReserved !== null)
        state.onReserved(b4a.from(record.circuitId), b4a.from(record.peerId))
      emit(state, {
        type: 'reserve',
        circuitId: b4a.from(record.circuitId),
        peerId: b4a.from(record.peerId)
      })
      return Object.freeze({
        circuitId: b4a.from(record.circuitId),
        peerId: b4a.from(record.peerId)
      })
    } catch (err) {
      destroyRecord(state, record, 'FAILED', false)
      if (err instanceof PrivateRouteError) throw err
      unavailable()
    }
  }

  trySend(circuitId, direction, payload, options = {}) {
    const state = STATES.get(this)
    const record = lookup(state, circuitId)
    if (!knownDirection(direction) || !isBuffer(payload) || !isObject(options)) invalid()
    const bytes = bufferByteLength.call(payload)
    const counter = options.counter === undefined ? null : options.counter
    let seen = null
    let counterKey = null
    if (counter !== null) {
      if (!u64(counter)) invalid()
      seen = record.seen[direction]
      counterKey = counter.toString(16)
      if (seen.has(counterKey)) throw PrivateRouteError.ERR_REPLAY()
    }
    if (record.queuedBytes + bytes > record.limits.maxQueuedBytesPerCircuit) quota()
    if (state.globalBytes + bytes > record.limits.maxQueuedBytes) quota()

    record.queuedBytes += bytes
    state.globalBytes += bytes
    let item = null
    let counterCommitted = false
    try {
      const owned = state.allocate(bytes)
      if (!isBuffer(owned, bytes)) invalid()
      bufferSet.call(owned, payload, 0)
      item = Object.freeze({
        direction,
        payload: owned,
        bytes,
        generation: record.generation,
        counter
      })
      record.queue.push(item)
      if (seen !== null) {
        seen.add(counterKey)
        counterCommitted = true
      }
      if (record.queue.length === 1 && state.fair.indexOf(record.key) === -1)
        state.fair.push(record.key)
      emit(state, { type: 'queued', circuitId: b4a.from(record.circuitId), direction, bytes })
      return true
    } catch (err) {
      if (counterCommitted) seen.delete(counterKey)
      rollBackQueued(state, record, item, bytes)
      if (err instanceof PrivateRouteError) throw err
      unavailable()
    }
  }

  forward(circuitId, direction, payload, options) {
    return this.trySend(circuitId, direction, payload, options)
  }

  dispatch(limit = 1) {
    const state = STATES.get(this)
    if (!state || state.destroyed) destroyed()
    if (!Number.isSafeInteger(limit) || limit < 0) invalid()
    if (state.dispatching) return 0
    state.dispatching = true
    let sent = 0
    try {
      while (sent < limit && state.fair.length > 0) {
        if (state.cursor >= state.fair.length) state.cursor = 0
        const key = state.fair[state.cursor]
        const record = state.circuits.get(key)
        if (!record || record.queue.length === 0) {
          removeFair(state, key)
          continue
        }
        const item = record.queue.shift()
        record.queuedBytes -= item.bytes
        state.globalBytes -= item.bytes
        if (record.queue.length === 0) removeFair(state, key)
        else state.cursor = (state.cursor + 1) % state.fair.length
        const target = item.direction === DIRECTION.FORWARD ? record.nextHop : record.previousHop
        const metadata = Object.freeze({
          circuitId: b4a.from(record.circuitId),
          direction: item.direction,
          generation: item.generation,
          counter: item.counter
        })
        let ok = false
        try {
          ok = deliver(target, item.payload, metadata)
        } finally {
          clear(item.payload)
        }
        if (!ok) destroyRecord(state, record, 'UNAVAILABLE', true)
        if (state.onSent !== null) state.onSent(b4a.from(record.circuitId), item.bytes)
        emit(state, {
          type: 'sent',
          circuitId: b4a.from(record.circuitId),
          direction: item.direction,
          bytes: item.bytes
        })
        sent++
      }
      return sent
    } finally {
      state.dispatching = false
    }
  }

  expireGeneration(generation, reason = 'GENERATION_EXPIRED') {
    const state = STATES.get(this)
    if (!state || state.destroyed) destroyed()
    if (!u64(generation)) invalid()
    let expired = 0
    for (const record of Array.from(state.circuits.values())) {
      if (record.generation !== generation) continue
      if (destroyRecord(state, record, String(reason), true)) expired++
    }
    return expired
  }

  expireCircuit(circuitId, reason = 'EXPIRED') {
    const state = STATES.get(this)
    const record = lookup(state, circuitId)
    return destroyRecord(state, record, String(reason), true)
  }

  cancelCircuit(circuitId, reason = 'CANCELLED') {
    return this.expireCircuit(circuitId, reason)
  }

  status(circuitId) {
    const state = STATES.get(this)
    if (!state) invalid()
    const key = circuitKey(circuitId)
    const record = state.circuits.get(key)
    if (record) {
      return Object.freeze({
        state: 'OPEN',
        queuedBytes: record.queuedBytes,
        queuedCells: record.queue.length,
        expiresAt: record.expiresAt
      })
    }
    const tombstone = state.tombstones.get(key)
    if (tombstone) return Object.freeze({ state: 'DESTROYED', tombstone })
    return Object.freeze({ state: state.destroyed ? 'DESTROYED' : 'UNKNOWN' })
  }

  destroy() {
    const state = STATES.get(this)
    if (!state || state.destroyed) return false
    const records = Array.from(state.circuits.values())
    const payload = Object.freeze({
      globalBytes: state.globalBytes,
      circuits: Object.freeze(records.map((record) => observeCircuit(record)))
    })
    state.destroyed = true
    state.circuits.clear()
    state.peers.clear()
    state.fair.length = 0
    state.cursor = 0
    state.globalBytes = 0
    for (const record of records) {
      record.closed = true
      if (record.timer !== null) {
        try {
          state.cancel(record.timer)
        } catch {}
        record.timer = null
      }
      releaseQueued(state, record)
      addTombstone(state, record.key, 'DESTROYED', record.circuitId, record.peerId)
    }
    for (const record of records) {
      const previousHop = record.previousHop
      const nextHop = record.nextHop
      record.previousHop = null
      record.nextHop = null
      try {
        closeCapability(previousHop, 'DESTROYED')
      } finally {
        closeCapability(nextHop, 'DESTROYED')
      }
      clear(record.circuitId)
      clear(record.peerId)
    }
    emit(state, {
      type: 'destroyed',
      globalBytes: payload.globalBytes,
      circuits: payload.circuits.length
    })
    return payload
  }

  [TEST_ONLY_RELAY_SERVICE_OBSERVER]() {
    const state = STATES.get(this)
    if (!state) invalid()
    return Object.freeze({
      destroyed: state.destroyed,
      circuits: state.circuits.size,
      peers: state.peers.size,
      globalBytes: state.globalBytes,
      queuedCircuits: state.fair.length,
      tombstones: state.tombstones.size,
      records: Object.freeze(Array.from(state.circuits.values(), observeCircuit))
    })
  }
}

// SURB hop message on a link: verify, admit, wrap, forward as the same cell kind.
// The relay learns nothing but "a SURB hop message". Terminal delivers payload only.
function processRelaySurbHop(options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) invalid()
  const payload = options.payload
  const capabilityAuthority = options.capabilityAuthority
  const replayAuthority = options.replayAuthority
  const hopBytes = tryDecodeSurbHopCell(payload)
  if (hopBytes === null) return null
  const message = decodeSurbHopMessage(hopBytes)
  hopBytes.fill(0)
  const authority = processSurbHop({
    message,
    capabilityAuthority,
    replayAuthority
  })
  const result = consumeSurbForwardingAuthority(authority)
  if (result.terminal) {
    return Object.freeze({
      terminal: true,
      nextHop: result.nextHop,
      payload: result.message.payload
    })
  }
  const nextCell = encodeSurbHopCell(result.message)
  return Object.freeze({
    terminal: false,
    nextHop: result.nextHop,
    payload: nextCell
  })
}

module.exports = {
  MAX_RELAY_CIRCUITS,
  MAX_RELAY_CIRCUITS_PER_NEIGHBOR,
  MAX_RELAY_CIRCUIT_QUEUE,
  MAX_RELAY_GLOBAL_QUEUE,
  RELAY_FORWARD_DEADLINE,
  TEST_ONLY_RELAY_SERVICE_OBSERVER,
  RelayService,
  processRelaySurbHop
}
