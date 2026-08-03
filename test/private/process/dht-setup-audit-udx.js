'use strict'

const b4a = require('b4a')
const c = require('compact-encoding')

const { cryptoSuite } = require('../../../lib/private/crypto-suite')
const { AUDIT_CLASSES, AUDIT_OUTCOMES, createAuditEventStream } = require('./audit-event')

const MAX_DATAGRAM_BYTES = 65_536
const ARM_LIMIT = 3
const DEFAULT_CORRELATION_TTL_MS = 5_000n
const SETUP_CLASSES = Object.freeze([
  AUDIT_CLASSES.SETUP_STORE_TOKEN,
  AUDIT_CLASSES.SETUP_STORE_PUT,
  AUDIT_CLASSES.SETUP_STORE_READBACK
])
const STATES = new WeakMap()

class DhtSetupAuditError extends Error {
  constructor(code = 'PROCESS_DHT_SETUP_AUDIT_INVALID') {
    super(code)
    this.code = code
  }
}

function invalid(code) {
  throw new DhtSetupAuditError(code)
}

function exactTuple(value) {
  if (
    !value ||
    Reflect.ownKeys(value).length !== 2 ||
    typeof value.host !== 'string' ||
    !Number.isSafeInteger(value.port) ||
    value.port < 1 ||
    value.port > 65_535
  ) {
    invalid()
  }
  const parts = value.host.split('.')
  if (parts.length !== 4) invalid()
  for (const part of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255) invalid()
  }
  return Object.freeze({ host: value.host, port: value.port })
}

function tupleKey(value) {
  return `${value.host}:${value.port}`
}

function tupleBytes(value) {
  const output = b4a.allocUnsafeSlow(19)
  output.fill(0)
  output[0] = 4
  const parts = value.host.split('.')
  for (let index = 0; index < 4; index++) output[index + 13] = Number(parts[index])
  output[17] = value.port >>> 8
  output[18] = value.port
  return output
}

function fixed(value, size) {
  if (!b4a.isBuffer(value) || value.byteLength !== size) invalid()
  return b4a.from(value)
}

function now(state) {
  const value = state.monotonicNow()
  if (typeof value !== 'bigint' || value < 0n) invalid()
  return value
}

function digestValue(value) {
  if (value === null) return b4a.alloc(32)
  return cryptoSuite.hash(value)
}

function decodePacket(input) {
  if (!b4a.isBuffer(input) || input.byteLength < 10 || input.byteLength > MAX_DATAGRAM_BYTES) {
    invalid('PROCESS_DHT_SETUP_PACKET_INVALID')
  }
  const type = input[0]
  if (type !== 0x03 && type !== 0x13) invalid('PROCESS_DHT_SETUP_PACKET_INVALID')
  const state = { buffer: input, start: 1, end: input.byteLength }
  try {
    const flags = c.uint.decode(state)
    if (flags > 31) invalid('PROCESS_DHT_SETUP_PACKET_INVALID')
    const transactionId = c.uint16.decode(state)
    const to = c.ipv4Address.decode(state)
    if (type === 0x03) {
      const id = flags & 1 ? c.fixed32.decode(state) : null
      const token = flags & 2 ? c.fixed32.decode(state) : null
      const internal = (flags & 4) !== 0
      const command = c.uint.decode(state)
      const target = flags & 8 ? c.fixed32.decode(state) : null
      const value = flags & 16 ? c.buffer.decode(state) : null
      if (state.start !== state.end || command > 65_535) invalid('PROCESS_DHT_SETUP_PACKET_INVALID')
      return { command, flags, id, internal, target, to, token, transactionId, type, value }
    }
    const id = flags & 1 ? c.fixed32.decode(state) : null
    const token = flags & 2 ? c.fixed32.decode(state) : null
    const closerNodes = flags & 4 ? c.array(c.ipv4Address).decode(state) : null
    const error = flags & 8 ? c.uint.decode(state) : 0
    const value = flags & 16 ? c.buffer.decode(state) : null
    if (state.start !== state.end) invalid('PROCESS_DHT_SETUP_PACKET_INVALID')
    return { closerNodes, error, flags, id, to, token, transactionId, type, value }
  } catch (err) {
    if (err instanceof DhtSetupAuditError) throw err
    invalid('PROCESS_DHT_SETUP_PACKET_INVALID')
  }
}

function correlationKey(kind, host, port, transactionId) {
  return `${kind}:${host}:${port}:${transactionId}`
}

function purgeExpired(state) {
  const current = now(state)
  for (const [key, correlation] of state.correlations) {
    if (current >= correlation.expiresAt) state.correlations.delete(key)
  }
}

function addCorrelation(state, key, value) {
  purgeExpired(state)
  if (state.correlations.size >= state.maximumCorrelations) {
    invalid('PROCESS_DHT_SETUP_CORRELATION_OVERFLOW')
  }
  if (state.correlations.has(key)) invalid('PROCESS_DHT_SETUP_REPLAY')
  state.correlations.set(key, {
    ...value,
    expiresAt: now(state) + DEFAULT_CORRELATION_TTL_MS
  })
}

function emitAudit(state, type, event) {
  if (state.eventQueue.length >= state.maximumEvents) {
    invalid('PROCESS_DHT_SETUP_EVENT_OVERFLOW')
  }
  const message = Object.freeze({
    ...event,
    phaseSequence: state.phaseSequence(),
    role: 'dht-referral',
    type
  })
  state.eventQueue.push(message)
  state.emit(message)
  return message
}

function setupRequest(state, socketState, packet, decoded, host, port, ttl) {
  if (
    tupleKey({ host, port }) !== state.destinationKey ||
    tupleKey(decoded.to) !== state.destinationKey
  ) {
    invalid('PROCESS_DHT_SETUP_DESTINATION')
  }
  if (tupleKey(socketState.boundAddress) !== state.sourceKey) {
    invalid('PROCESS_DHT_SETUP_SOURCE')
  }
  const arm = state.arms[0]
  if (!arm || arm.open) invalid('PROCESS_DHT_SETUP_UNARMED')
  if (
    decoded.command !== arm.command ||
    decoded.internal ||
    !b4a.equals(decoded.target || b4a.alloc(0), arm.target)
  ) {
    invalid('PROCESS_DHT_SETUP_ARM_MISMATCH')
  }
  const valueDigest = digestValue(decoded.value)
  try {
    if (!b4a.equals(valueDigest, arm.valueDigest)) invalid('PROCESS_DHT_SETUP_ARM_MISMATCH')
  } finally {
    valueDigest.fill(0)
  }

  const recordSequence = ++state.recordSequence
  const nonce = fixed(state.randomBytes(16), 16)
  const source = tupleBytes(state.source)
  const destination = tupleBytes(state.destination)
  let open
  try {
    open = state.audit.open({
      class: arm.class,
      command: decoded.command,
      destination,
      generation: state.generation,
      nonce,
      openingPhaseSequence: state.phaseSequence(),
      outboundPayload: packet,
      recordSequence,
      source,
      transactionId: decoded.transactionId
    })
  } finally {
    source.fill(0)
    destination.fill(0)
  }
  arm.open = true
  arm.recordNonce = nonce
  arm.recordSequence = recordSequence
  const key = correlationKey('setup', host, port, decoded.transactionId)
  addCorrelation(state, key, {
    arm,
    destination: state.destinationKey,
    transactionId: decoded.transactionId,
    type: 'setup'
  })
  emitAudit(state, 'audit-open', open)
  try {
    return socketState.socket.trySend(packet, port, host, ttl)
  } catch (err) {
    closeSetup(state, key, null, AUDIT_OUTCOMES.ERROR)
    throw err
  }
}

function closeSetup(state, key, packet, outcome = AUDIT_OUTCOMES.SUCCESS) {
  const correlation = state.correlations.get(key)
  if (!correlation || correlation.type !== 'setup') invalid('PROCESS_DHT_SETUP_FORGED_RESPONSE')
  state.correlations.delete(key)
  const arm = correlation.arm
  const close = state.audit.close({
    closingPhaseSequence: state.phaseSequence(),
    outcome,
    recordNonce: arm.recordNonce,
    recordSequence: arm.recordSequence,
    replyPayload: packet === null ? b4a.alloc(0) : packet
  })
  emitAudit(state, 'audit-close', close)
  state.arms.shift()
  arm.target.fill(0)
  arm.valueDigest.fill(0)
  arm.recordNonce.fill(0)
}

function outgoing(state, socketState, packet, port, host, ttl) {
  if (state.destroyed) invalid('PROCESS_DHT_SETUP_DESTROYED')
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535 || typeof host !== 'string') {
    invalid('PROCESS_DHT_SETUP_PACKET_INVALID')
  }
  const decoded = decodePacket(packet)
  const destinationKey = tupleKey({ host, port })
  if (decoded.type === 0x03) {
    if (!decoded.internal && (decoded.command === 8 || decoded.command === 9)) {
      return setupRequest(state, socketState, packet, decoded, host, port, ttl)
    }
    if (!decoded.internal || decoded.command < 0 || decoded.command > 3) {
      invalid('PROCESS_DHT_SETUP_UNCLASSIFIED')
    }
    if (!state.permittedTuples.has(destinationKey) || tupleKey(decoded.to) !== destinationKey) {
      invalid('PROCESS_DHT_SETUP_DESTINATION')
    }
    addCorrelation(state, correlationKey('internal', host, port, decoded.transactionId), {
      transactionId: decoded.transactionId,
      type: 'internal'
    })
    return socketState.socket.trySend(packet, port, host, ttl)
  }

  const key = correlationKey('server', host, port, decoded.transactionId)
  const correlation = state.correlations.get(key)
  if (!correlation || correlation.type !== 'server') {
    invalid('PROCESS_DHT_SETUP_UNCLASSIFIED')
  }
  state.correlations.delete(key)
  return socketState.socket.trySend(packet, port, host, ttl)
}

function inbound(state, socketState, packet, source) {
  if (state.destroyed) invalid('PROCESS_DHT_SETUP_DESTROYED')
  const sourceKey = tupleKey(source)
  if (!state.permittedTuples.has(sourceKey)) invalid('PROCESS_DHT_SETUP_SOURCE')
  const decoded = decodePacket(packet)
  if (decoded.type === 0x13) {
    if (tupleKey(decoded.to) !== state.sourceKey) invalid('PROCESS_DHT_SETUP_FORGED_RESPONSE')
    const setupKey = correlationKey('setup', source.host, source.port, decoded.transactionId)
    const internalKey = correlationKey('internal', source.host, source.port, decoded.transactionId)
    if (state.correlations.has(setupKey)) closeSetup(state, setupKey, packet)
    else if (state.correlations.has(internalKey)) state.correlations.delete(internalKey)
    else invalid('PROCESS_DHT_SETUP_FORGED_RESPONSE')
  } else {
    if (tupleKey(decoded.to) !== state.sourceKey) invalid('PROCESS_DHT_SETUP_SOURCE')
    addCorrelation(
      state,
      correlationKey('server', source.host, source.port, decoded.transactionId),
      { transactionId: decoded.transactionId, type: 'server' }
    )
  }
  for (const listener of socketState.messageListeners.slice()) listener(packet, source)
}

function rejectInbound(state, socketState, err) {
  const onFailure = state.onFailure
  const code = err instanceof DhtSetupAuditError ? err.code : 'PROCESS_DHT_SETUP_AUDIT_INVALID'
  destroyDhtSetupAuditController(state.controller)
  try {
    const closing = socketState.socket.close()
    if (closing && typeof closing.catch === 'function') void closing.catch(() => false)
  } catch {}
  onFailure(new DhtSetupAuditError(code))
}

function wrapSocket(state, socket) {
  const socketState = {
    boundAddress: null,
    messageListeners: [],
    nativeMessage: null,
    socket
  }
  socketState.nativeMessage = (packet, from) => {
    try {
      const source = exactTuple({
        host: from && from.host,
        port: from && from.port
      })
      inbound(state, socketState, packet, source)
    } catch (err) {
      rejectInbound(state, socketState, err)
    }
  }
  socket.on('message', socketState.nativeMessage)
  state.sockets.add(socketState)

  const proxy = {
    get bound() {
      return socket.bound
    },
    address() {
      return socket.address()
    },
    bind(port, host) {
      if (state.destroyed) invalid('PROCESS_DHT_SETUP_DESTROYED')
      const result = socket.bind(port, host)
      const address = socket.address()
      socketState.boundAddress = exactTuple({ host: address.host, port: address.port })
      return result
    },
    close() {
      socketState.messageListeners.length = 0
      state.sockets.delete(socketState)
      if (typeof socket.removeListener === 'function') {
        socket.removeListener('message', socketState.nativeMessage)
      }
      return socket.close()
    },
    on(name, listener) {
      if (typeof listener !== 'function') invalid()
      if (name === 'message') socketState.messageListeners.push(listener)
      else socket.on(name, listener)
      return proxy
    },
    addListener(name, listener) {
      return proxy.on(name, listener)
    },
    once(name, listener) {
      if (name !== 'message') {
        socket.once(name, listener)
        return proxy
      }
      const wrapped = (...args) => {
        proxy.removeListener(name, wrapped)
        listener(...args)
      }
      socketState.messageListeners.push(wrapped)
      return proxy
    },
    off(name, listener) {
      return proxy.removeListener(name, listener)
    },
    removeListener(name, listener) {
      if (name === 'message') {
        const index = socketState.messageListeners.indexOf(listener)
        if (index !== -1) socketState.messageListeners.splice(index, 1)
      } else if (typeof socket.removeListener === 'function') {
        socket.removeListener(name, listener)
      }
      return proxy
    },
    trySend(packet, port, host, ttl) {
      return outgoing(state, socketState, packet, port, host, ttl)
    }
  }
  return Object.freeze(proxy)
}

function createDhtSetupAuditController(options) {
  if (!options || typeof options !== 'object') invalid()
  const source = exactTuple(options.source)
  const destination = exactTuple(options.destination)
  if (
    typeof options.emit !== 'function' ||
    typeof options.onFailure !== 'function' ||
    typeof options.monotonicNow !== 'function' ||
    typeof options.phaseSequence !== 'function' ||
    typeof options.randomBytes !== 'function' ||
    typeof options.generation !== 'bigint' ||
    options.generation < 1n ||
    options.maximumCorrelations !== 64 ||
    options.maximumEvents !== 16 ||
    !options.udx ||
    typeof options.udx.createSocket !== 'function' ||
    typeof options.udx.watchNetworkInterfaces !== 'function'
  ) {
    invalid()
  }
  const key = fixed(options.key, 32)
  let audit
  try {
    audit = createAuditEventStream({
      context: options.auditContext,
      key,
      maximumRecords: ARM_LIMIT
    })
  } catch (err) {
    key.fill(0)
    throw err
  }
  const controller = {}
  const permittedTuples = new Set([tupleKey(destination)])
  if (options.permittedTuples !== undefined) {
    if (!Array.isArray(options.permittedTuples)) invalid()
    for (const value of options.permittedTuples) permittedTuples.add(tupleKey(exactTuple(value)))
  }
  const state = {
    arms: [],
    audit,
    controller,
    correlations: new Map(),
    destination,
    destinationKey: tupleKey(destination),
    destroyed: false,
    emit: options.emit,
    eventQueue: [],
    generation: options.generation,
    key,
    maximumCorrelations: options.maximumCorrelations,
    maximumEvents: options.maximumEvents,
    onFailure: options.onFailure,
    monotonicNow: options.monotonicNow,
    nextArm: 0,
    permittedTuples,
    phaseSequence: options.phaseSequence,
    randomBytes: options.randomBytes,
    recordSequence: 0n,
    sockets: new Set(),
    source,
    sourceKey: tupleKey(source),
    udx: options.udx,
    wrappedUDX: null
  }
  state.wrappedUDX = Object.freeze({
    createSocket() {
      if (state.destroyed) invalid('PROCESS_DHT_SETUP_DESTROYED')
      return wrapSocket(state, state.udx.createSocket())
    },
    watchNetworkInterfaces(...args) {
      if (state.destroyed) invalid('PROCESS_DHT_SETUP_DESTROYED')
      return state.udx.watchNetworkInterfaces(...args)
    }
  })
  Object.defineProperty(controller, 'udx', {
    configurable: false,
    enumerable: true,
    value: state.wrappedUDX,
    writable: false
  })
  Object.freeze(controller)
  STATES.set(controller, state)
  return controller
}

function armSetupDhtAudit(controller, spec) {
  const state = STATES.get(controller)
  if (!state || state.destroyed) invalid('PROCESS_DHT_SETUP_DESTROYED')
  if (!spec || Reflect.ownKeys(spec).length !== 5) invalid()
  if (state.nextArm >= ARM_LIMIT || spec.class !== SETUP_CLASSES[state.nextArm]) {
    invalid('PROCESS_DHT_SETUP_ORDER')
  }
  const destination = exactTuple(spec.destination)
  if (tupleKey(destination) !== state.destinationKey) invalid('PROCESS_DHT_SETUP_DESTINATION')
  if (
    !Number.isSafeInteger(spec.command) ||
    (spec.command !== 8 && spec.command !== 9) ||
    (spec.class === AUDIT_CLASSES.SETUP_STORE_PUT ? spec.command !== 8 : spec.command !== 9)
  ) {
    invalid('PROCESS_DHT_SETUP_ARM_MISMATCH')
  }
  state.arms.push({
    class: spec.class,
    command: spec.command,
    open: false,
    recordNonce: null,
    recordSequence: 0n,
    target: fixed(spec.target, 32),
    valueDigest: fixed(spec.valueDigest, 32)
  })
  state.nextArm++
}

function drainDhtSetupAuditEvents(controller) {
  const state = STATES.get(controller)
  if (!state || state.destroyed) invalid('PROCESS_DHT_SETUP_DESTROYED')
  const events = state.eventQueue.slice()
  state.eventQueue.length = 0
  return Object.freeze(events)
}

function destroyDhtSetupAuditController(controller) {
  const state = STATES.get(controller)
  if (!state || state.destroyed) return
  state.destroyed = true
  for (const arm of state.arms) {
    arm.target.fill(0)
    arm.valueDigest.fill(0)
    if (arm.recordNonce !== null) arm.recordNonce.fill(0)
  }
  state.arms.length = 0
  state.correlations.clear()
  state.eventQueue.length = 0
  for (const socketState of state.sockets) {
    socketState.messageListeners.length = 0
    if (typeof socketState.socket.removeListener === 'function') {
      socketState.socket.removeListener('message', socketState.nativeMessage)
    }
  }
  state.sockets.clear()
  state.audit.destroy()
  state.key.fill(0)
  state.permittedTuples.clear()
  state.emit = null
  state.onFailure = null
  state.udx = null
  state.wrappedUDX = null
  STATES.delete(controller)
}

module.exports = Object.freeze({
  ARM_LIMIT,
  DhtSetupAuditError,
  armSetupDhtAudit,
  createDhtSetupAuditController,
  destroyDhtSetupAuditController,
  drainDhtSetupAuditEvents
})
