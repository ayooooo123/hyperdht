'use strict'

const b4a = require('b4a')

const { BOOTSTRAP_CLASS, BOOTSTRAP_SIZE } = require('./bootstrap-envelope')
const { MAX_CELL_PAYLOAD, CellCodec } = require('./cell-codec')
const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')
const {
  createLinkControlBoundary,
  LinkControlSession,
  readLinkControlStreamProgress
} = require('./link-control-session')
const {
  LINK_BOOTSTRAP_SESSION_INVALIDATE,
  LinkBootstrapSession,
  readEstablishedLinkReservation
} = require('./link-bootstrap-session')
const {
  readLinkHandle,
  subscribeLinkHandleClose,
  unsubscribeLinkHandleClose
} = require('./topology-grant')
const {
  UDX_LINK_CLOSE,
  UDX_LINK_DESTROY_CIRCUIT,
  UDX_LINK_OPEN,
  UDX_LINK_STATS,
  UDX_LINK_STREAM_PROGRESS,
  UDX_ENDPOINT_RESERVATION_STATS,
  TEST_ONLY_UDX_STREAM_COUNTER,
  UDX_SEND_CELL,
  UDX_TRY_SEND_CELL,
  UDX_SEND_DISPATCH,
  UdxAdapter
} = require('./udx-adapter')
const { CELL_CLASS, DIRECTION } = require('./protocol')

// Ported from the reviewed private-routes prototype at commit
// 0305df915b6a767093f9e75e6c06bc0a35da6169 and narrowed to Gate 3B1.

const DEFAULT_MAX_UDX_QUEUED_PACKETS = 64
const DEFAULT_MAX_UDX_QUEUED_BYTES = BOOTSTRAP_SIZE * DEFAULT_MAX_UDX_QUEUED_PACKETS
const DEFAULT_MAX_UDX_INBOUND_PACKETS = 64
const DEFAULT_MAX_UDX_INBOUND_BYTES = BOOTSTRAP_SIZE * DEFAULT_MAX_UDX_INBOUND_PACKETS
const DEFAULT_MAX_UDX_INBOUND_PACKETS_PER_PEER = 8
const DEFAULT_MAX_UDX_INBOUND_BYTES_PER_PEER =
  BOOTSTRAP_SIZE * DEFAULT_MAX_UDX_INBOUND_PACKETS_PER_PEER
const ENDPOINTS = new WeakMap()
const SEND_HANDLES = new WeakMap()
const TEST_ADAPTER_AUTHORITIES = new WeakMap()
const LOCAL_SECRET_CAPABILITIES = new WeakMap()
const BOOTSTRAP_UDX_AUTHORITIES = new WeakMap()
const BOOTSTRAP_UDX_ADMISSIONS = new WeakMap()
const GUARD_LEASE_MATERIALS = new WeakMap()
const TEST_CONSTRUCTION = Object.freeze({})
const TEST_ONLY_UDX_ADAPTER_ISSUER = Symbol('test-only-udx-adapter-issuer')
const ENDPOINT_OPTION_KEYS = new Set([
  'host',
  'port',
  'onBootstrap',
  'onCell',
  'onLinkFailure',
  'maxQueuedPackets',
  'maxQueuedBytes',
  'maxInboundPackets',
  'maxInboundBytes',
  'maxInboundPacketsPerPeer',
  'maxInboundBytesPerPeer'
])
const LOCAL_SECRET_FIELDS = new Set(['localIdentity', 'localSecretKey'])
const BOOTSTRAP_AUTHORITY_FIELDS = new Set([
  'endpoint',
  'configuredEndpoints',
  'localSecretCapability',
  'maxProspectiveGuards',
  'monotonicDeadline'
])
const ADMISSION_FIELDS = new Set(['identity', 'host', 'port'])
const ROUTE_GENERATION_BYTES = 8
const STREAM_LOGICAL_COUNTER_BYTES = 8
const MAX_DATAGRAM_PAYLOAD = MAX_CELL_PAYLOAD - ROUTE_GENERATION_BYTES
const MAX_STREAM_PAYLOAD = MAX_CELL_PAYLOAD - ROUTE_GENERATION_BYTES - STREAM_LOGICAL_COUNTER_BYTES
const MAX_UINT64 = (1n << 64n) - 1n
const bufferByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
const bufferSubarray = Uint8Array.prototype.subarray

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function unavailable() {
  return PrivateRouteError.ROUTE_UNAVAILABLE()
}

function stateError() {
  return PrivateRouteError.CIRCUIT_STATE()
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function exactOwnData(value, keys) {
  if (!isObject(value) || Object.getPrototypeOf(value) !== Object.prototype) return false
  let descriptors
  try {
    descriptors = Object.getOwnPropertyDescriptors(value)
  } catch {
    return false
  }
  for (const [name, descriptor] of Object.entries(descriptors)) {
    if (!keys.has(name) || !Object.hasOwn(descriptor, 'value')) return false
  }
  return true
}

function numericHost(host) {
  if (typeof host !== 'string' || host.length === 0) return false
  if (/^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$/.test(host)) {
    return host.split('.').every((part) => Number(part) <= 255)
  }
  if (!/^[0-9a-f:]+$/.test(host) || host.includes('%') || host.includes('.')) return false
  const marker = host.indexOf('::')
  if (marker !== -1 && marker !== host.lastIndexOf('::')) return false
  const left = (marker === -1 ? host : host.slice(0, marker)).split(':').filter(Boolean)
  const right = (marker === -1 ? '' : host.slice(marker + 2)).split(':').filter(Boolean)
  if (![...left, ...right].every((part) => /^[0-9a-f]{1,4}$/.test(part))) return false
  return marker === -1 ? left.length === 8 : left.length + right.length < 8
}

function exactEndpoint(value) {
  if (!exactOwnData(value, new Set(['host', 'port']))) invalid()
  if (
    !numericHost(value.host) ||
    !Number.isInteger(value.port) ||
    value.port < 1 ||
    value.port > 0xffff
  )
    invalid()
  return { host: value.host, port: value.port }
}

function endpointKey(endpoint) {
  return `${endpoint.host}:${endpoint.port}`
}

function bound(value, fallback) {
  if (value === undefined) return fallback
  if (!Number.isSafeInteger(value) || value < 1 || value > fallback) invalid()
  return value
}

function clear(value) {
  try {
    if (b4a.isBuffer(value)) b4a.fill(value, 0)
  } catch {}
}

function fixed(value, size) {
  try {
    return b4a.isBuffer(value) && bufferByteLength.call(value) === size
  } catch {
    return false
  }
}

function same(left, right) {
  try {
    return fixed(left, right.byteLength) && b4a.equals(left, right)
  } catch {
    return false
  }
}

function readUint64BE(buffer, offset) {
  let value = 0n
  for (let index = offset; index < offset + 8; index++) {
    value = (value << 8n) | BigInt(buffer[index])
  }
  return value
}

function writeUint64BE(buffer, value, offset) {
  for (let index = offset + 7; index >= offset; index--) {
    buffer[index] = Number(value & 0xffn)
    value >>= 8n
  }
}

function frameEstablished(cellClass, generation, logicalCounter, payload) {
  const prefix =
    ROUTE_GENERATION_BYTES + (cellClass === CELL_CLASS.STREAM ? STREAM_LOGICAL_COUNTER_BYTES : 0)
  const framed = b4a.allocUnsafeSlow(prefix + payload.byteLength)
  writeUint64BE(framed, generation, 0)
  if (cellClass === CELL_CLASS.STREAM) {
    writeUint64BE(framed, logicalCounter, ROUTE_GENERATION_BYTES)
  }
  framed.set(payload, prefix)
  return framed
}

function opposite(direction) {
  return direction === DIRECTION.FORWARD ? DIRECTION.REVERSE : DIRECTION.FORWARD
}

function establishedOptions(value) {
  if (!isObject(value) || !isObject(value.linkState)) invalid()
  const { linkState, mode, now, schedule, cancel, randomBytes } = value
  if (
    (mode !== 'initiate' && mode !== 'accept') ||
    !b4a.isBuffer(linkState.circuitId) ||
    linkState.circuitId.byteLength !== 16 ||
    typeof linkState.epoch !== 'bigint' ||
    !isObject(linkState.contexts) ||
    typeof now !== 'function' ||
    typeof schedule !== 'function' ||
    typeof cancel !== 'function' ||
    typeof randomBytes !== 'function'
  ) {
    invalid()
  }
  for (const cellClass of [CELL_CLASS.CONTROL, CELL_CLASS.STREAM, CELL_CLASS.DATAGRAM]) {
    const pair = linkState.contexts[cellClass]
    if (!isObject(pair) || !isObject(pair.tx) || !isObject(pair.rx)) invalid()
  }
  return { linkState, mode, now, schedule, cancel, randomBytes }
}

function receiveEstablished(state, authority, packet) {
  const cellClass = packet[1]
  const direction = packet[2]
  const counter = readUint64BE(packet, 28)
  const expectedDirection = opposite(authority.heartbeatDirection)
  const context = authority.linkState.contexts[cellClass]
  if (!context || direction !== expectedDirection) throw PrivateRouteError.CELL_INVALID()
  const before = cellClass === CELL_CLASS.DATAGRAM ? null : context.rx.counter.next
  const delivery = authority.cellCodec.open(
    {
      key: context.rx.key,
      noncePrefix: context.rx.noncePrefix,
      receiver: context.rx.counter,
      expectedClass: cellClass,
      expectedDirection,
      expectedEpoch: authority.linkState.epoch,
      expectedCircuitId: authority.linkState.circuitId
    },
    packet
  )
  const values = cellClass === CELL_CLASS.DATAGRAM ? [delivery] : delivery
  if (values.length === 0) {
    const event = authority.linkBoundary.pushAuthenticated({
      link: authority,
      epoch: authority.linkState.epoch,
      circuitId: authority.linkState.circuitId,
      class: cellClass,
      direction,
      generation: cellClass === CELL_CLASS.CONTROL ? 0n : 1n,
      counter,
      deliver: false,
      payload: b4a.alloc(0)
    })
    return authority.linkControl.receiveAuthenticated(event)
  }
  let accepted = true
  try {
    for (let index = 0; index < values.length; index++) {
      const payload = values[index]
      if (cellClass !== CELL_CLASS.CONTROL && payload.byteLength < ROUTE_GENERATION_BYTES) invalid()
      const generation = cellClass === CELL_CLASS.CONTROL ? 0n : readUint64BE(payload, 0)
      if (cellClass !== CELL_CLASS.CONTROL && generation === 0n) invalid()
      if (
        cellClass === CELL_CLASS.STREAM &&
        payload.byteLength < ROUTE_GENERATION_BYTES + STREAM_LOGICAL_COUNTER_BYTES
      ) {
        invalid()
      }
      const logicalCounter =
        cellClass === CELL_CLASS.STREAM ? readUint64BE(payload, ROUTE_GENERATION_BYTES) : counter
      const prefix =
        cellClass === CELL_CLASS.CONTROL
          ? 0
          : ROUTE_GENERATION_BYTES +
            (cellClass === CELL_CLASS.STREAM ? STREAM_LOGICAL_COUNTER_BYTES : 0)
      const applicationPayload =
        cellClass === CELL_CLASS.CONTROL ? payload : payload.subarray(prefix)
      const deliveredCounter =
        cellClass === CELL_CLASS.STREAM
          ? logicalCounter
          : cellClass === CELL_CLASS.DATAGRAM
            ? counter
            : before + BigInt(index)
      const event = authority.linkBoundary.pushAuthenticated({
        link: authority,
        epoch: authority.linkState.epoch,
        circuitId: authority.linkState.circuitId,
        class: cellClass,
        direction,
        generation,
        counter: deliveredCounter,
        payload: applicationPayload
      })
      const current = authority.linkControl.receiveAuthenticated(event, {
        dispatchActor(fragment, metadata) {
          return state.onCell(fragment, authority.handle, metadata) === true
        },
        enqueueStream(owned, metadata) {
          return state.onCell(owned, authority.handle, metadata) === true
        },
        enqueueDatagram(owned, metadata) {
          return state.onCell(owned, authority.handle, metadata) === true
        }
      })
      if (!current) accepted = false
    }
  } finally {
    for (const payload of values) clear(payload)
  }
  return accepted
}

function installLinkControl(state, record, value) {
  const options = establishedOptions(value)
  const heartbeatDirection = options.mode === 'initiate' ? DIRECTION.FORWARD : DIRECTION.REVERSE
  const boundary = createLinkControlBoundary({
    link: record,
    epoch: options.linkState.epoch,
    circuitId: options.linkState.circuitId
  })
  const codec = new CellCodec({ crypto: cryptoSuite, cellSize: BOOTSTRAP_SIZE })
  record.linkState = options.linkState
  record.cellCodec = codec
  record.linkBoundary = boundary
  record.heartbeatDirection = heartbeatDirection
  record.streamCounters = new Map()
  const linkControl = new LinkControlSession({
    control: boundary.consumer,
    circuitId: options.linkState.circuitId,
    epoch: options.linkState.epoch,
    heartbeatDirection,
    now: options.now,
    schedule: options.schedule,
    cancel: options.cancel,
    randomBytes: options.randomBytes,
    sendControl(payload) {
      const context = options.linkState.contexts[CELL_CLASS.CONTROL].tx
      const direction = payload[4]
      if (direction !== heartbeatDirection && direction !== opposite(heartbeatDirection)) invalid()
      let packet = null
      try {
        packet = codec.seal({
          key: context.key,
          noncePrefix: context.noncePrefix,
          senderCounter: context.counter,
          class: CELL_CLASS.CONTROL,
          direction,
          epoch: options.linkState.epoch,
          circuitId: options.linkState.circuitId,
          payload
        })
        return state.endpoint.send(record.handle, packet)
      } finally {
        clear(packet)
      }
    },
    cancelPending() {
      if (record.phase === 'OPEN') record.phase = 'CLOSING'
      for (const queued of state.queue) {
        if (queued.authority === record) queued.cancelled = true
      }
      if (state.dispatching && state.dispatching.authority === record) {
        state.dispatching.cancelled = true
      }
    },
    notifyCircuit(direction, reason) {
      state.onLinkFailure(record.handle, direction, reason)
    },
    closeLink() {
      state.endpoint[UDX_LINK_CLOSE](record.handle)
    }
  })
  if (state.closing || record.phase !== 'OPEN' || record.endpoint !== state.endpoint) {
    linkControl.close()
    throw unavailable()
  }
  record.linkControl = linkControl
}

function detachAbort(record) {
  const signal = record.signal
  const abort = record.abort
  const removeAbort = record.removeAbort
  record.signal = null
  record.abort = null
  record.removeAbort = null
  if (!signal || !abort || !removeAbort) return
  try {
    removeAbort.call(signal, 'abort', abort)
  } catch {}
}

function releasePacket(record) {
  clear(record.packet)
  record.packet = null
}

function rejectCaller(record, error) {
  if (record.settled) return
  record.settled = true
  detachAbort(record)
  record.reject(error)
  return true
}

function rejectRecord(record, error) {
  if (!rejectCaller(record, error)) return
  releasePacket(record)
}

function settleRecord(record, value) {
  if (record.settled) return
  record.settled = true
  releasePacket(record)
  detachAbort(record)
  record.resolve(value)
}

function removeQueued(state, record) {
  const index = state.queue.indexOf(record)
  if (index === -1) return false
  state.queue.splice(index, 1)
  state.queuedBytes -= BOOTSTRAP_SIZE
  state.reservedPackets--
  state.reservedBytes -= BOOTSTRAP_SIZE
  return true
}

function rejectQueue(state, error) {
  const queued = state.queue.splice(0)
  state.queuedBytes = 0
  for (const record of queued) {
    state.reservedPackets--
    state.reservedBytes -= BOOTSTRAP_SIZE
    rejectRecord(record, error)
  }
}

function invalidateRecord(state, record) {
  if (!record || record.phase === 'CLOSED') return
  record.phase = 'CLOSED'
  const linkControl = record.linkControl
  record.linkControl = null
  if (linkControl) {
    try {
      linkControl.close()
    } catch {}
  }
  if (record.closeSubscription) {
    unsubscribeLinkHandleClose(record.closeSubscription)
    record.closeSubscription = null
  }
  if (record.session) {
    record.session[LINK_BOOTSTRAP_SESSION_INVALIDATE]()
    record.session = null
  }
  for (let index = state.queue.length - 1; index >= 0; index--) {
    const queued = state.queue[index]
    if (queued.authority !== record) continue
    state.queue.splice(index, 1)
    state.queuedBytes -= BOOTSTRAP_SIZE
    state.reservedPackets--
    state.reservedBytes -= BOOTSTRAP_SIZE
    rejectRecord(queued, PrivateRouteError.UNAUTHORIZED())
  }
  if (state.dispatching && state.dispatching.authority === record) {
    state.dispatching.cancelled = true
    rejectCaller(state.dispatching, unavailable())
  }
  if (state.sources.get(record.source) === record.handle) state.sources.delete(record.source)
  state.handles.delete(record.linkHandle)
  state.records.delete(record)
  SEND_HANDLES.delete(record.handle)
  record.endpoint = null
  record.peer = null
  record.peerKey = null
  record.linkHandle = null
  record.linkState = null
  record.cellCodec = null
  record.linkBoundary = null
  record.streamCounters = null
  record.bootstrapBinding = null
}

function validateRecord(state, record) {
  if (!record || record.endpoint !== state.endpoint || record.phase === 'CLOSED') return false
  try {
    readLinkHandle(record.linkHandle)
    return true
  } catch {
    invalidateRecord(state, record)
    return false
  }
}

function pump(state) {
  if (state.dispatching || state.queue.length === 0 || state.closing) return
  const record = state.queue.shift()
  state.queuedBytes -= BOOTSTRAP_SIZE
  if (record.settled) {
    pump(state)
    return
  }
  if (!validateRecord(state, record.authority)) {
    state.reservedPackets--
    state.reservedBytes -= BOOTSTRAP_SIZE
    rejectRecord(record, PrivateRouteError.UNAUTHORIZED())
    pump(state)
    return
  }
  state.dispatching = record
  state.inFlight++
  let releaseNative
  const native = new Promise((resolve) => {
    releaseNative = resolve
  })
  const completion = native
    .then((result) => result)
    .then(
      (sent) => {
        if (record.cancelled || sent !== true) rejectRecord(record, unavailable())
        else settleRecord(record, true)
      },
      () => rejectRecord(record, unavailable())
    )
    .finally(() => {
      releasePacket(record)
      state.nativeWaits.delete(completion)
      state.inFlight--
      state.reservedPackets--
      state.reservedBytes -= BOOTSTRAP_SIZE
      state.dispatching = null
      if (!state.closing) pump(state)
    })
  state.nativeWaits.add(completion)
  try {
    if (record.onDispatch) record.onDispatch()
    if (state.closing || record.cancelled || !validateRecord(state, record.authority)) {
      releaseNative(false)
      return
    }
    releaseNative(state.socket.send(record.packet, record.peer.port, record.peer.host))
  } catch {
    releaseNative(false)
  }
}

function reservePacket(state, authority) {
  if (
    state.reservedPackets >= state.maxQueuedPackets ||
    state.reservedBytes + BOOTSTRAP_SIZE > state.maxQueuedBytes
  ) {
    return null
  }
  state.reservedPackets++
  state.reservedBytes += BOOTSTRAP_SIZE
  return { state, authority, active: true }
}

function releaseReservation(reservation) {
  if (!reservation || !reservation.active) return
  reservation.active = false
  reservation.state.reservedPackets--
  reservation.state.reservedBytes -= BOOTSTRAP_SIZE
}

function sendReserved(state, authority, packet, reservation) {
  if (
    !reservation ||
    !reservation.active ||
    reservation.state !== state ||
    reservation.authority !== authority ||
    state.closing ||
    !validateRecord(state, authority)
  ) {
    releaseReservation(reservation)
    throw unavailable()
  }
  let record
  let sending
  try {
    const owned = b4a.from(packet)
    sending = new Promise((resolve, reject) => {
      record = {
        packet: owned,
        peer: authority.peer,
        authority,
        signal: null,
        removeAbort: null,
        onDispatch: null,
        abort: null,
        admitted: true,
        resolve,
        reject,
        settled: false,
        cancelled: false
      }
    })
    reservation.active = false
    state.queue.push(record)
    state.queuedBytes += BOOTSTRAP_SIZE
    void sending.catch(() => {})
    pump(state)
    return sending
  } catch (err) {
    releaseReservation(reservation)
    throw err
  }
}

function releaseReceive(state, record) {
  if (!record.active) return
  record.active = false
  state.receiveRecords.delete(record)
  state.inboundPackets--
  state.inboundBytes -= BOOTSTRAP_SIZE
  const peer = state.inboundPeers.get(record.peerKey)
  if (peer) {
    peer.packets--
    peer.bytes -= BOOTSTRAP_SIZE
    if (peer.packets === 0) state.inboundPeers.delete(record.peerKey)
  }
  clear(record.packet)
  record.packet = null
}

function reserveReceive(state, peerKey) {
  const peer = state.inboundPeers.get(peerKey) || { packets: 0, bytes: 0 }
  if (
    state.inboundPackets >= state.maxInboundPackets ||
    state.inboundBytes + BOOTSTRAP_SIZE > state.maxInboundBytes ||
    peer.packets >= state.maxInboundPacketsPerPeer ||
    peer.bytes + BOOTSTRAP_SIZE > state.maxInboundBytesPerPeer
  ) {
    return null
  }
  const record = { packet: null, peerKey, completion: null, active: true }
  state.inboundPackets++
  state.inboundBytes += BOOTSTRAP_SIZE
  peer.packets++
  peer.bytes += BOOTSTRAP_SIZE
  state.inboundPeers.set(peerKey, peer)
  state.receiveRecords.add(record)
  return record
}

function ownReceive(state, peerKey, packet) {
  const record = reserveReceive(state, peerKey)
  if (!record) return null
  try {
    record.packet = b4a.from(packet)
  } catch {
    releaseReceive(state, record)
    return null
  }
  let settle
  const ownership = new Promise((resolve) => {
    settle = resolve
  })
  record.completion = ownership.finally(() => releaseReceive(state, record))
  return { packet: record.packet, settle }
}

async function waitForReceives(state) {
  const completions = Array.from(state.receiveRecords, (record) => record.completion)
  if (completions.length === 0) return
  await Promise.allSettled(completions)
  for (const record of Array.from(state.receiveRecords)) releaseReceive(state, record)
}

function receive(state, packet, from) {
  if (state.closing || !b4a.isBuffer(packet) || packet.byteLength !== BOOTSTRAP_SIZE) return
  let source
  try {
    source = `${from.host}:${from.port}`
  } catch {
    return
  }
  const direct = state.directSources.get(source)
  if (direct && direct.active && direct.state === state.bootstrapAuthority) {
    const peerKey = `direct:${source}`
    const owned = ownReceive(state, peerKey, packet)
    if (!owned) return
    try {
      const result = state.onBootstrap(owned.packet, direct.token)
      if (result === state.closePromise) owned.settle()
      Promise.resolve(result).then(owned.settle, owned.settle)
    } catch {
      owned.settle()
    }
    return
  }
  const sendHandle = state.sources.get(source)
  if (!sendHandle) return
  const authority = SEND_HANDLES.get(sendHandle)
  if (!validateRecord(state, authority)) return
  if (packet[0] !== 0) return
  if (packet[1] !== BOOTSTRAP_CLASS && packet[1] > 2) return
  if (packet[1] !== BOOTSTRAP_CLASS && authority.phase !== 'OPEN') return
  const peerKey = authority.peerKey
  const owned = ownReceive(state, peerKey, packet)
  if (!owned) return
  // A handler promise owns its packet until settlement. The exact endpoint
  // close promise is recognized below; another handler promise must not await
  // that close because an indirect promise cycle cannot be identified safely.
  try {
    const result =
      owned.packet[1] === BOOTSTRAP_CLASS
        ? state.onBootstrap(owned.packet, sendHandle)
        : authority.linkControl
          ? receiveEstablished(state, authority, owned.packet)
          : state.onCell(owned.packet, sendHandle)
    if (result === state.closePromise) owned.settle()
    Promise.resolve(result).then(owned.settle, owned.settle)
  } catch {
    owned.settle()
  }
}

function trySendEstablishedCell(endpoint, handle, value) {
  const state = ENDPOINTS.get(endpoint)
  const record = isObject(handle) ? SEND_HANDLES.get(handle) : null
  if (
    state.closing ||
    !validateRecord(state, record) ||
    record.phase !== 'OPEN' ||
    !record.linkControl ||
    !isObject(value)
  ) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  const cellClass = value.class
  const direction = value.direction
  const generation = value.generation
  const payload = value.payload
  if (
    (cellClass !== CELL_CLASS.STREAM && cellClass !== CELL_CLASS.DATAGRAM) ||
    direction !== record.heartbeatDirection ||
    typeof generation !== 'bigint' ||
    generation < 1n ||
    generation > MAX_UINT64 ||
    !b4a.isBuffer(payload) ||
    payload.byteLength >
      (cellClass === CELL_CLASS.STREAM ? MAX_STREAM_PAYLOAD : MAX_DATAGRAM_PAYLOAD)
  ) {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  const reservation = reservePacket(state, record)
  if (!reservation) return null
  let context = null
  let logical = null
  let logicalKey = null
  let logicalState = null
  let packet = null
  let framed = null
  try {
    context = record.linkState.contexts[cellClass].tx
    if (cellClass === CELL_CLASS.STREAM) {
      logicalKey = `${direction}:${generation}`
      logicalState = record.streamCounters.get(logicalKey) || { next: 0n, closed: false }
      if (logicalState.closed) throw PrivateRouteError.COUNTER_EXHAUSTED()
      logical = logicalState.next
    }
    framed = frameEstablished(cellClass, generation, logical, payload)
    packet = record.cellCodec.seal({
      key: context.key,
      noncePrefix: context.noncePrefix,
      senderCounter: context.counter,
      class: cellClass,
      direction,
      epoch: record.linkState.epoch,
      circuitId: record.linkState.circuitId,
      payload: framed
    })
    if (cellClass === CELL_CLASS.STREAM) {
      record.linkControl.trackStream(direction, generation, logical, payload.byteLength)
      if (logical === MAX_UINT64) logicalState.closed = true
      else logicalState.next = logical + 1n
      record.streamCounters.set(logicalKey, logicalState)
    }
    const sending = sendReserved(state, record, packet, reservation).catch((err) => {
      if (record.linkControl) record.linkControl.close()
      throw err
    })
    return Object.freeze({ sending })
  } catch (err) {
    releaseReservation(reservation)
    if (record.linkControl) record.linkControl.close()
    throw err instanceof PrivateRouteError ? err : unavailable()
  } finally {
    clear(packet)
    clear(framed)
  }
}

class UdxCellEndpoint {
  constructor(options = {}, construction = null) {
    if (!exactOwnData(options, ENDPOINT_OPTION_KEYS)) invalid()
    let adapter = null
    if (construction !== null) {
      if (construction.token !== TEST_CONSTRUCTION || !construction.adapter) invalid()
      adapter = construction.adapter
    } else {
      adapter = new UdxAdapter()
    }
    const { host, port, onBootstrap, onCell, onLinkFailure } = options
    if (
      !adapter ||
      typeof adapter.create !== 'function' ||
      !numericHost(host) ||
      !Number.isInteger(port) ||
      port < 1 ||
      port > 0xffff ||
      typeof onBootstrap !== 'function' ||
      typeof onCell !== 'function' ||
      typeof onLinkFailure !== 'function'
    ) {
      invalid()
    }
    let udx
    let socket
    try {
      udx = adapter.create()
      socket = udx.createSocket()
    } catch {
      throw unavailable()
    }
    if (
      !socket ||
      typeof socket.bind !== 'function' ||
      typeof socket.send !== 'function' ||
      typeof socket.close !== 'function' ||
      typeof socket.on !== 'function'
    ) {
      invalid()
    }
    const state = {
      endpoint: this,
      udx,
      socket,
      host,
      port,
      onBootstrap,
      onCell,
      onLinkFailure,
      maxQueuedPackets: bound(options.maxQueuedPackets, DEFAULT_MAX_UDX_QUEUED_PACKETS),
      maxQueuedBytes: bound(options.maxQueuedBytes, DEFAULT_MAX_UDX_QUEUED_BYTES),
      maxInboundPackets: bound(options.maxInboundPackets, DEFAULT_MAX_UDX_INBOUND_PACKETS),
      maxInboundBytes: bound(options.maxInboundBytes, DEFAULT_MAX_UDX_INBOUND_BYTES),
      maxInboundPacketsPerPeer: bound(
        options.maxInboundPacketsPerPeer,
        DEFAULT_MAX_UDX_INBOUND_PACKETS_PER_PEER
      ),
      maxInboundBytesPerPeer: bound(
        options.maxInboundBytesPerPeer,
        DEFAULT_MAX_UDX_INBOUND_BYTES_PER_PEER
      ),
      handles: new WeakMap(),
      consumedHandles: new WeakSet(),
      records: new Set(),
      sources: new Map(),
      queue: [],
      queuedBytes: 0,
      reservedPackets: 0,
      reservedBytes: 0,
      dispatching: null,
      inFlight: 0,
      nativeWaits: new Set(),
      receiveRecords: new Set(),
      inboundPackets: 0,
      inboundBytes: 0,
      inboundPeers: new Map(),
      directSources: new Map(),
      bootstrapAuthority: null,
      bound: false,
      closing: false,
      closePromise: null
    }
    state.onMessage = (packet, from) => receive(state, packet, from)
    state.onError = () => {
      void this.close().catch(() => {})
    }
    socket.on('message', state.onMessage)
    socket.on('error', state.onError)
    ENDPOINTS.set(this, state)
  }

  get queuedPackets() {
    return ENDPOINTS.get(this).queue.length
  }

  get queuedBytes() {
    return ENDPOINTS.get(this).queuedBytes
  }

  get inFlightSends() {
    return ENDPOINTS.get(this).inFlight
  }

  [UDX_ENDPOINT_RESERVATION_STATS]() {
    const state = ENDPOINTS.get(this)
    return Object.freeze({ packets: state.reservedPackets, bytes: state.reservedBytes })
  }

  [TEST_ONLY_UDX_STREAM_COUNTER](handle, direction, generation, next, closed) {
    const state = ENDPOINTS.get(this)
    const record = isObject(handle) ? SEND_HANDLES.get(handle) : null
    if (
      state.closing ||
      !validateRecord(state, record) ||
      record.phase !== 'OPEN' ||
      direction !== record.heartbeatDirection ||
      typeof generation !== 'bigint' ||
      generation < 1n ||
      generation > MAX_UINT64 ||
      typeof next !== 'bigint' ||
      next < 0n ||
      next > MAX_UINT64 ||
      typeof closed !== 'boolean'
    ) {
      throw PrivateRouteError.INVALID_ROUTE()
    }
    record.streamCounters.set(`${direction}:${generation}`, { next, closed })
  }

  async bind() {
    const state = ENDPOINTS.get(this)
    if (state.closing) throw stateError()
    if (state.bound) return true
    try {
      const result = state.socket.bind(state.port, state.host)
      if (result && typeof result.then === 'function') await result
      state.bound = true
      return true
    } catch {
      throw unavailable()
    }
  }

  openLink(linkHandle, sessionOptions) {
    const state = ENDPOINTS.get(this)
    if (state.closing || !state.bound) throw stateError()
    let link
    try {
      if (!isObject(linkHandle) || state.consumedHandles.has(linkHandle)) {
        throw PrivateRouteError.UNAUTHORIZED()
      }
      link = readLinkHandle(linkHandle)
    } catch {
      throw PrivateRouteError.UNAUTHORIZED()
    }
    state.consumedHandles.add(linkHandle)
    if (!isObject(sessionOptions)) invalid()
    if (link.localAddress.host !== state.host || link.localAddress.port !== state.port) {
      throw PrivateRouteError.UNAUTHORIZED()
    }
    const source = `${link.peerAddress.host}:${link.peerAddress.port}`
    if (state.sources.has(source)) {
      const existingHandle = state.sources.get(source)
      const existing = SEND_HANDLES.get(existingHandle)
      if (validateRecord(state, existing)) throw PrivateRouteError.CIRCUIT_STATE()
    }
    const sendHandle = Object.freeze({})
    const record = {
      endpoint: this,
      handle: sendHandle,
      linkHandle,
      peer: { host: link.peerAddress.host, port: link.peerAddress.port },
      peerKey: b4a.toString(link.peerIdentity32, 'hex'),
      source,
      phase: 'PENDING',
      session: null,
      linkControl: null,
      linkBoundary: null,
      linkState: null,
      cellCodec: null,
      heartbeatDirection: null,
      streamCounters: null,
      bootstrapBinding: null,
      closeSubscription: null
    }
    SEND_HANDLES.set(sendHandle, record)
    state.handles.set(linkHandle, sendHandle)
    state.sources.set(source, sendHandle)
    state.records.add(record)
    try {
      record.closeSubscription = subscribeLinkHandleClose(linkHandle, () => {
        invalidateRecord(state, record)
      })
    } catch (err) {
      invalidateRecord(state, record)
      throw err
    }
    try {
      const session = new LinkBootstrapSession({
        ...sessionOptions,
        endpoint: this,
        sendHandle,
        linkHandle
      })
      record.session = session
      return session
    } catch (err) {
      invalidateRecord(state, record)
      throw err
    }
  }

  send(handle, packet, options = {}) {
    const state = ENDPOINTS.get(this)
    if (state.closing) return Promise.reject(stateError())
    if (!state.bound) return Promise.reject(stateError())
    const authority = isObject(handle) ? SEND_HANDLES.get(handle) : null
    if (!authority || authority.endpoint !== this) {
      return Promise.reject(PrivateRouteError.UNAUTHORIZED())
    }
    if (!validateRecord(state, authority)) {
      return Promise.reject(PrivateRouteError.UNAUTHORIZED())
    }
    if (authority.phase === 'CLOSING') return Promise.reject(stateError())
    if (!b4a.isBuffer(packet) || packet.byteLength !== BOOTSTRAP_SIZE || !isObject(options)) {
      return Promise.reject(PrivateRouteError.INVALID_ROUTE())
    }
    if (packet[1] !== BOOTSTRAP_CLASS && authority.phase !== 'OPEN') {
      return Promise.reject(stateError())
    }
    const reservation = reservePacket(state, authority)
    if (!reservation) return Promise.reject(PrivateRouteError.CIRCUIT_LIMIT())
    let signal
    let onDispatch
    let addAbort = null
    let removeAbort = null
    let aborted = false
    try {
      signal = options.signal
      onDispatch = options[UDX_SEND_DISPATCH]
      if (signal !== undefined) {
        if (!isObject(signal)) throw PrivateRouteError.INVALID_ROUTE()
        addAbort = signal.addEventListener
        removeAbort = signal.removeEventListener
        aborted = signal.aborted
      }
    } catch {
      releaseReservation(reservation)
      if (state.closing) return Promise.reject(stateError())
      if (!validateRecord(state, authority)) {
        return Promise.reject(PrivateRouteError.UNAUTHORIZED())
      }
      return Promise.reject(PrivateRouteError.INVALID_ROUTE())
    }
    if (state.closing) return Promise.reject(stateError())
    if (!validateRecord(state, authority)) {
      releaseReservation(reservation)
      return Promise.reject(PrivateRouteError.UNAUTHORIZED())
    }
    if (
      signal !== undefined &&
      (typeof addAbort !== 'function' || typeof removeAbort !== 'function')
    ) {
      releaseReservation(reservation)
      return Promise.reject(PrivateRouteError.INVALID_ROUTE())
    }
    if (onDispatch !== undefined && typeof onDispatch !== 'function') {
      releaseReservation(reservation)
      return Promise.reject(PrivateRouteError.INVALID_ROUTE())
    }
    if (aborted) {
      releaseReservation(reservation)
      return Promise.reject(unavailable())
    }
    let dispatch = false
    let owned = null
    let sending
    try {
      owned = b4a.from(packet)
      sending = new Promise((resolve, reject) => {
        const record = {
          packet: owned,
          peer: authority.peer,
          authority,
          signal,
          removeAbort,
          onDispatch,
          abort: null,
          admitted: false,
          resolve,
          reject,
          settled: false,
          cancelled: false
        }
        record.abort = () => {
          record.cancelled = true
          if (removeQueued(state, record) || !record.admitted) rejectRecord(record, unavailable())
          else rejectCaller(record, unavailable())
        }
        if (signal) {
          let abortedAfter = false
          try {
            addAbort.call(signal, 'abort', record.abort, { once: true })
            abortedAfter = signal.aborted
          } catch {
            const error = state.closing
              ? stateError()
              : validateRecord(state, authority)
                ? unavailable()
                : PrivateRouteError.UNAUTHORIZED()
            rejectRecord(record, error)
            return
          }
          if (abortedAfter && !record.settled) record.abort()
        }
        if (record.settled) return
        if (state.closing) {
          rejectRecord(record, stateError())
          return
        }
        if (!validateRecord(state, authority)) {
          rejectRecord(record, PrivateRouteError.UNAUTHORIZED())
          return
        }
        record.admitted = true
        reservation.active = false
        state.queue.push(record)
        state.queuedBytes += BOOTSTRAP_SIZE
        dispatch = true
      })
    } catch (err) {
      clear(owned)
      releaseReservation(reservation)
      return Promise.reject(err)
    }
    releaseReservation(reservation)
    // Bare's native UDX send may re-enter teardown before this call returns.
    // Own the rejection before crossing that boundary while returning the
    // original promise so callers still observe the exact send outcome.
    void sending.catch(() => {})
    if (dispatch) pump(state)
    return sending
  }

  [UDX_LINK_OPEN](handle, established) {
    const state = ENDPOINTS.get(this)
    const record = isObject(handle) ? SEND_HANDLES.get(handle) : null
    if (state.closing || !validateRecord(state, record)) throw PrivateRouteError.UNAUTHORIZED()
    if (record.phase === 'OPEN' || record.linkControl) throw stateError()
    record.phase = 'OPEN'
    if (established !== undefined) {
      try {
        installLinkControl(state, record, established)
      } catch (err) {
        invalidateRecord(state, record)
        throw err
      }
    }
  }

  [UDX_LINK_CLOSE](handle) {
    const state = ENDPOINTS.get(this)
    const record = isObject(handle) ? SEND_HANDLES.get(handle) : null
    if (record && record.endpoint === this) invalidateRecord(state, record)
  }

  [UDX_LINK_DESTROY_CIRCUIT](handle, reason) {
    const state = ENDPOINTS.get(this)
    const record = isObject(handle) ? SEND_HANDLES.get(handle) : null
    if (
      state.closing ||
      !validateRecord(state, record) ||
      record.phase !== 'OPEN' ||
      !record.linkControl
    ) {
      return Promise.reject(PrivateRouteError.UNAUTHORIZED())
    }
    return record.linkControl.destroy(reason)
  }

  [UDX_SEND_CELL](handle, value) {
    try {
      const admitted = trySendEstablishedCell(this, handle, value)
      return admitted ? admitted.sending : Promise.reject(PrivateRouteError.CIRCUIT_LIMIT())
    } catch (err) {
      return Promise.reject(err instanceof PrivateRouteError ? err : unavailable())
    }
  }

  [UDX_TRY_SEND_CELL](handle, value) {
    return trySendEstablishedCell(this, handle, value)
  }

  [UDX_LINK_STATS](handle) {
    const state = ENDPOINTS.get(this)
    const record = isObject(handle) ? SEND_HANDLES.get(handle) : null
    if (!validateRecord(state, record) || !record.linkControl) {
      throw PrivateRouteError.UNAUTHORIZED()
    }
    return {
      pendingStreams: record.linkControl.pendingStreams,
      pendingBytes: record.linkControl.pendingBytes,
      pendingSends: record.linkControl.pendingSends,
      closed: record.linkControl.closed
    }
  }

  [UDX_LINK_STREAM_PROGRESS](handle, direction, generation) {
    const state = ENDPOINTS.get(this)
    const record = isObject(handle) ? SEND_HANDLES.get(handle) : null
    if (!validateRecord(state, record) || !record.linkControl || !record.linkState) {
      throw PrivateRouteError.UNAUTHORIZED()
    }
    const progress = readLinkControlStreamProgress(record.linkControl, direction, generation)
    return Object.freeze({
      epoch: record.linkState.epoch,
      circuitId: b4a.from(record.linkState.circuitId),
      direction,
      generation,
      highestSent: progress.highestSent,
      highestAck: progress.highestAck,
      pendingStreams: progress.pendingStreams,
      pendingBytes: progress.pendingBytes
    })
  }

  close() {
    const state = ENDPOINTS.get(this)
    if (state.closePromise) return state.closePromise
    state.closing = true
    rejectQueue(state, stateError())
    for (const record of Array.from(state.records)) invalidateRecord(state, record)
    try {
      if (typeof state.socket.off === 'function') {
        state.socket.off('message', state.onMessage)
        state.socket.off('error', state.onError)
      } else if (typeof state.socket.removeListener === 'function') {
        state.socket.removeListener('message', state.onMessage)
        state.socket.removeListener('error', state.onError)
      }
    } catch {}
    state.onMessage = null
    state.onError = null
    const nativeWaits = Array.from(state.nativeWaits)
    state.closePromise = (async () => {
      await Promise.allSettled(nativeWaits)
      await waitForReceives(state)
      try {
        await state.socket.close()
      } catch {
        throw unavailable()
      } finally {
        state.sources.clear()
        state.directSources.clear()
        state.bootstrapAuthority = null
        state.handles = new WeakMap()
        state.consumedHandles = new WeakSet()
        state.onBootstrap = null
        state.onCell = null
        state.onLinkFailure = null
        state.udx = null
      }
    })()
    return state.closePromise
  }
}

function createLocalIdentitySecretCapability(options) {
  if (!exactOwnData(options, LOCAL_SECRET_FIELDS)) invalid()
  let localIdentity = null
  let localSecretKey = null
  let seed = null
  let pair = null
  try {
    if (!fixed(options.localIdentity, 32) || !fixed(options.localSecretKey, 64)) invalid()
    localIdentity = b4a.from(options.localIdentity)
    localSecretKey = b4a.from(options.localSecretKey)
    seed = b4a.from(bufferSubarray.call(options.localSecretKey, 0, 32))
    pair = cryptoSuite.keyPair(seed)
    if (!b4a.equals(pair.publicKey, localIdentity) || !b4a.equals(pair.secretKey, localSecretKey))
      invalid()
    const capability = Object.freeze({})
    LOCAL_SECRET_CAPABILITIES.set(capability, { localIdentity, localSecretKey })
    localIdentity = null
    localSecretKey = null
    return capability
  } finally {
    clear(localIdentity)
    clear(localSecretKey)
    clear(seed)
    if (pair) {
      clear(pair.publicKey)
      clear(pair.secretKey)
    }
  }
}

function clearSecretRecord(record) {
  if (!record) return
  clear(record.localIdentity)
  clear(record.localSecretKey)
  record.localIdentity = null
  record.localSecretKey = null
}

function destroyLocalIdentitySecretCapability(capability) {
  const record = isObject(capability) ? LOCAL_SECRET_CAPABILITIES.get(capability) : null
  if (!record) return false
  LOCAL_SECRET_CAPABILITIES.delete(capability)
  clearSecretRecord(record)
  return true
}

function createBootstrapGuardLeaseMaterial(establishedLink, localSecretCapability) {
  const secret = isObject(localSecretCapability)
    ? LOCAL_SECRET_CAPABILITIES.get(localSecretCapability)
    : null
  if (!secret) throw PrivateRouteError.UNAUTHORIZED()
  try {
    require('./guard-link').readM3EstablishedLink(establishedLink)
  } catch {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  LOCAL_SECRET_CAPABILITIES.delete(localSecretCapability)
  const material = Object.freeze({})
  GUARD_LEASE_MATERIALS.set(material, {
    establishedLink,
    endpoint: null,
    secret,
    identity: null,
    host: null,
    port: null,
    reconnectTransportFactory() {
      if (arguments.length !== 0) invalid()
      throw unavailable()
    },
    kind: 'bootstrap-fake'
  })
  return material
}

function revokeDirectRecords(state) {
  for (const record of state.configured) record.active = false
  for (const record of state.admissions) {
    record.active = false
    BOOTSTRAP_UDX_ADMISSIONS.delete(record.token)
    clear(record.identity)
  }
  state.configured.length = 0
  state.admissions.clear()
  const endpointState = ENDPOINTS.get(state.endpoint)
  if (endpointState && endpointState.bootstrapAuthority === state) {
    endpointState.directSources.clear()
    endpointState.bootstrapAuthority = null
  }
}

function destroyBootstrapUdxAuthority(authority) {
  const state = isObject(authority) ? BOOTSTRAP_UDX_AUTHORITIES.get(authority) : null
  if (!state) return false
  BOOTSTRAP_UDX_AUTHORITIES.delete(authority)
  state.live = false
  state.operation = null
  revokeDirectRecords(state)
  clearSecretRecord(state.secret)
  state.secret = null
  if (state.testTransport) {
    try {
      state.testTransport.destroy()
    } catch {}
    state.testTransport = null
  }
  if (state.ownsEndpoint) void state.endpoint.close().catch(() => {})
  state.endpoint = null
  return true
}

function createBootstrapUdxAuthority(options) {
  if (!exactOwnData(options, BOOTSTRAP_AUTHORITY_FIELDS)) invalid()
  const endpointState = ENDPOINTS.get(options.endpoint)
  const secret = isObject(options.localSecretCapability)
    ? LOCAL_SECRET_CAPABILITIES.get(options.localSecretCapability)
    : null
  if (!endpointState || endpointState.closing || endpointState.bootstrapAuthority || !secret)
    throw PrivateRouteError.UNAUTHORIZED()
  LOCAL_SECRET_CAPABILITIES.delete(options.localSecretCapability)
  const configured = []
  const seen = new Set()
  try {
    if (
      !Array.isArray(options.configuredEndpoints) ||
      options.configuredEndpoints.length < 1 ||
      options.configuredEndpoints.length > 3 ||
      !Number.isSafeInteger(options.maxProspectiveGuards) ||
      options.maxProspectiveGuards < 1 ||
      options.maxProspectiveGuards > 3 ||
      !Number.isSafeInteger(options.monotonicDeadline) ||
      options.monotonicDeadline < 1
    )
      invalid()
    for (const value of options.configuredEndpoints) {
      const tuple = exactEndpoint(value)
      const key = endpointKey(tuple)
      if (seen.has(key)) invalid()
      seen.add(key)
      configured.push({ ...tuple, key, token: Object.freeze({}), active: true })
    }
    const authority = Object.freeze({})
    const state = {
      authority,
      endpoint: options.endpoint,
      configured,
      admissions: new Set(),
      maxProspectiveGuards: options.maxProspectiveGuards,
      monotonicDeadline: options.monotonicDeadline,
      secret,
      live: true,
      pinned: false,
      ownsEndpoint: true,
      operation: null
    }
    BOOTSTRAP_UDX_AUTHORITIES.set(authority, state)
    endpointState.bootstrapAuthority = state
    for (const record of configured) {
      endpointState.directSources.set(record.key, { state, token: record.token, active: true })
    }
    return authority
  } catch (err) {
    for (const record of configured) record.active = false
    clearSecretRecord(secret)
    throw err
  }
}

function admitBootstrapUdxGuard(authority, value) {
  const state = isObject(authority) ? BOOTSTRAP_UDX_AUTHORITIES.get(authority) : null
  if (!state || !state.live || state.pinned || !state.operation)
    throw PrivateRouteError.UNAUTHORIZED()
  if (!exactOwnData(value, ADMISSION_FIELDS) || !fixed(value.identity, 32)) invalid()
  const tuple = exactEndpoint({ host: value.host, port: value.port })
  if (state.admissions.size >= state.maxProspectiveGuards) throw PrivateRouteError.CIRCUIT_LIMIT()
  const key = endpointKey(tuple)
  for (const current of state.admissions) {
    if (current.key === key || b4a.equals(current.identity, value.identity)) invalid()
  }
  const admission = Object.freeze({})
  const record = {
    state,
    identity: b4a.from(value.identity),
    ...tuple,
    key,
    token: admission,
    active: true
  }
  state.admissions.add(record)
  BOOTSTRAP_UDX_ADMISSIONS.set(admission, record)
  const endpointState = state.endpoint ? ENDPOINTS.get(state.endpoint) : null
  if (endpointState) endpointState.directSources.set(key, { state, token: admission, active: true })
  return admission
}

async function sendDirect(state, record, packet) {
  if (state.kind === 'test') {
    if (!state.live || state.pinned || !state.operation || !record.active) throw unavailable()
    return state.testTransport.send(record.host, record.port, packet)
  }
  const endpointState = ENDPOINTS.get(state.endpoint)
  if (
    !state.live ||
    state.pinned ||
    !state.operation ||
    !record.active ||
    !endpointState ||
    endpointState.closing ||
    !endpointState.bound ||
    !fixed(packet, BOOTSTRAP_SIZE)
  )
    throw unavailable()
  if (
    endpointState.reservedPackets >= endpointState.maxQueuedPackets ||
    endpointState.reservedBytes + BOOTSTRAP_SIZE > endpointState.maxQueuedBytes
  )
    throw PrivateRouteError.CIRCUIT_LIMIT()
  let owned = null
  endpointState.reservedPackets++
  endpointState.reservedBytes += BOOTSTRAP_SIZE
  try {
    owned = b4a.from(packet)
    const sent = await endpointState.socket.send(owned, record.port, record.host)
    if (sent !== true) throw unavailable()
    return true
  } finally {
    endpointState.reservedPackets--
    endpointState.reservedBytes -= BOOTSTRAP_SIZE
    clear(owned)
  }
}

function bindBootstrapUdxOperation(authority, deadline, generation) {
  const state = isObject(authority) ? BOOTSTRAP_UDX_AUTHORITIES.get(authority) : null
  if (
    !state ||
    !state.live ||
    state.pinned ||
    state.operation ||
    !Number.isSafeInteger(deadline) ||
    deadline !== state.monotonicDeadline ||
    !isObject(generation)
  )
    throw PrivateRouteError.UNAUTHORIZED()
  const token = Object.freeze({})
  state.operation = { token, deadline, generation }
  return token
}

function sendConfigured(authority, index, packet) {
  const state = isObject(authority) ? BOOTSTRAP_UDX_AUTHORITIES.get(authority) : null
  if (!state || !Number.isSafeInteger(index) || index < 0 || index >= state.configured.length)
    return Promise.reject(PrivateRouteError.UNAUTHORIZED())
  return sendDirect(state, state.configured[index], packet)
}

function sendProspectiveGuard(authority, admission, packet) {
  const state = isObject(authority) ? BOOTSTRAP_UDX_AUTHORITIES.get(authority) : null
  const record = isObject(admission) ? BOOTSTRAP_UDX_ADMISSIONS.get(admission) : null
  if (!state || !record || record.state !== state || !state.admissions.has(record))
    return Promise.reject(PrivateRouteError.UNAUTHORIZED())
  return sendDirect(state, record, packet)
}

function openBootstrapUdxGuard(authority, admission, linkHandle, sessionOptions) {
  const state = isObject(authority) ? BOOTSTRAP_UDX_AUTHORITIES.get(authority) : null
  const admitted = isObject(admission) ? BOOTSTRAP_UDX_ADMISSIONS.get(admission) : null
  if (
    !state ||
    state.kind === 'test' ||
    !admitted ||
    admitted.state !== state ||
    !state.live ||
    state.pinned ||
    !state.operation ||
    !isObject(sessionOptions) ||
    sessionOptions.absoluteDeadline !== state.monotonicDeadline
  )
    throw PrivateRouteError.UNAUTHORIZED()
  let link
  try {
    link = readLinkHandle(linkHandle)
  } catch {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  if (
    !same(link.peerIdentity32, admitted.identity) ||
    link.peerAddress.host !== admitted.host ||
    link.peerAddress.port !== admitted.port
  )
    throw PrivateRouteError.UNAUTHORIZED()
  const session = state.endpoint.openLink(linkHandle, sessionOptions)
  const endpointState = ENDPOINTS.get(state.endpoint)
  const sendHandle = endpointState.handles.get(linkHandle)
  const record = sendHandle && SEND_HANDLES.get(sendHandle)
  if (!record || record.session !== session || record.phase !== 'PENDING') {
    try {
      void session.close().catch(() => {})
    } catch {}
    throw PrivateRouteError.UNAUTHORIZED()
  }
  record.bootstrapBinding = Object.freeze({
    authority,
    admission,
    generation: state.operation.generation,
    deadline: state.monotonicDeadline
  })
  return session
}

function createReconnectTransport(material, materialState) {
  if (materialState.reconnectIssued) throw PrivateRouteError.UNAUTHORIZED()
  materialState.reconnectIssued = true
  const transportState = { active: true }
  materialState.reconnectTransport = transportState
  return Object.freeze({
    send(host, port, packet) {
      const endpointState = materialState.endpoint && ENDPOINTS.get(materialState.endpoint)
      if (
        !transportState.active ||
        GUARD_LEASE_MATERIALS.get(material) !== materialState ||
        host !== materialState.host ||
        port !== materialState.port ||
        !endpointState ||
        endpointState.closing ||
        !endpointState.bound ||
        !fixed(packet, BOOTSTRAP_SIZE)
      )
        return Promise.reject(PrivateRouteError.UNAUTHORIZED())
      if (
        endpointState.reservedPackets >= endpointState.maxQueuedPackets ||
        endpointState.reservedBytes + BOOTSTRAP_SIZE > endpointState.maxQueuedBytes
      )
        return Promise.reject(PrivateRouteError.CIRCUIT_LIMIT())
      endpointState.reservedPackets++
      endpointState.reservedBytes += BOOTSTRAP_SIZE
      let owned = null
      try {
        owned = b4a.from(packet)
      } catch {
        endpointState.reservedPackets--
        endpointState.reservedBytes -= BOOTSTRAP_SIZE
        return Promise.reject(unavailable())
      }
      return Promise.resolve(
        endpointState.socket.send(owned, materialState.port, materialState.host)
      )
        .then((sent) => {
          if (!transportState.active || sent !== true) throw unavailable()
          return true
        })
        .finally(() => {
          endpointState.reservedPackets--
          endpointState.reservedBytes -= BOOTSTRAP_SIZE
          clear(owned)
        })
    },
    destroy() {
      if (!transportState.active) return false
      transportState.active = false
      return true
    }
  })
}

function pinBootstrapUdxGuard(authority, admission, establishedLink) {
  const state = isObject(authority) ? BOOTSTRAP_UDX_AUTHORITIES.get(authority) : null
  const record = isObject(admission) ? BOOTSTRAP_UDX_ADMISSIONS.get(admission) : null
  if (
    !state ||
    !record ||
    record.state !== state ||
    !state.live ||
    state.pinned ||
    !state.operation
  )
    throw PrivateRouteError.UNAUTHORIZED()
  let link
  if (state.kind === 'test') {
    try {
      link = require('./guard-link').readM3EstablishedLink(establishedLink)
    } catch {
      throw PrivateRouteError.UNAUTHORIZED()
    }
    if (!same(link.peerIdentity, record.identity)) throw PrivateRouteError.UNAUTHORIZED()
    let identity
    try {
      identity = b4a.from(record.identity)
    } catch {
      throw unavailable()
    }
    state.pinned = true
    state.live = false
    BOOTSTRAP_UDX_AUTHORITIES.delete(authority)
    revokeDirectRecords(state)
    const secret = state.secret
    state.secret = null
    const transport = state.testTransport
    state.testTransport = null
    try {
      transport.destroy()
    } catch {}
    const material = Object.freeze({})
    GUARD_LEASE_MATERIALS.set(material, {
      establishedLink,
      endpoint: null,
      secret,
      identity,
      host: record.host,
      port: record.port,
      reconnectTransportFactory() {
        if (arguments.length !== 0) invalid()
        throw unavailable()
      },
      kind: 'bootstrap-fake'
    })
    return material
  }
  let reservation
  try {
    reservation = readEstablishedLinkReservation(establishedLink)
    link = reservation.linkState
  } catch {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  const endpointState = ENDPOINTS.get(state.endpoint)
  const endpointRecord = reservation && SEND_HANDLES.get(reservation.sendHandle)
  const binding = endpointRecord && endpointRecord.bootstrapBinding
  if (
    !endpointState ||
    endpointState.closing ||
    reservation.endpoint !== state.endpoint ||
    !endpointRecord ||
    endpointRecord.endpoint !== state.endpoint ||
    endpointRecord.linkHandle !== reservation.linkHandle ||
    endpointRecord.session !== reservation.session ||
    endpointRecord.phase !== 'OPEN' ||
    reservation.mode !== 'initiate' ||
    reservation.absoluteDeadline !== state.monotonicDeadline ||
    !binding ||
    binding.authority !== authority ||
    binding.admission !== admission ||
    binding.generation !== state.operation.generation ||
    binding.deadline !== state.monotonicDeadline ||
    !same(reservation.link.peerIdentity32, record.identity) ||
    reservation.link.peerAddress.host !== record.host ||
    reservation.link.peerAddress.port !== record.port ||
    !same(link.peerIdentity, record.identity)
  )
    throw PrivateRouteError.UNAUTHORIZED()
  let identity = null
  try {
    identity = b4a.from(record.identity)
  } catch {
    throw unavailable()
  }
  state.pinned = true
  state.live = false
  state.ownsEndpoint = false
  BOOTSTRAP_UDX_AUTHORITIES.delete(authority)
  for (const candidate of Array.from(endpointState.records)) {
    if (candidate !== endpointRecord) invalidateRecord(endpointState, candidate)
  }
  endpointState.sources.clear()
  endpointState.sources.set(endpointRecord.source, endpointRecord.handle)
  revokeDirectRecords(state)
  const endpoint = state.endpoint
  const secret = state.secret
  state.endpoint = null
  state.secret = null
  const material = Object.freeze({})
  const materialState = {
    establishedLink,
    endpoint,
    secret,
    identity,
    host: record.host,
    port: record.port,
    reconnectIssued: false,
    reconnectTransport: null,
    reconnectTransportFactory() {
      if (arguments.length !== 0) invalid()
      if (GUARD_LEASE_MATERIALS.get(material) !== materialState)
        throw PrivateRouteError.UNAUTHORIZED()
      return createReconnectTransport(material, materialState)
    }
  }
  GUARD_LEASE_MATERIALS.set(material, materialState)
  return material
}

function destroyGuardLeaseMaterial(material) {
  const state = isObject(material) ? GUARD_LEASE_MATERIALS.get(material) : null
  if (!state) return false
  GUARD_LEASE_MATERIALS.delete(material)
  clear(state.identity)
  if (state.reconnectTransport) state.reconnectTransport.active = false
  state.reconnectTransport = null
  if (state.kind === 'bootstrap-fake' && state.establishedLink) {
    try {
      require('./guard-link').destroyM3EstablishedLink(state.establishedLink)
    } catch {}
  }
  clearSecretRecord(state.secret)
  state.secret = null
  if (state.endpoint) void state.endpoint.close().catch(() => {})
  state.endpoint = null
  state.establishedLink = null
  state.reconnectTransportFactory = null
  return true
}

function isGuardLeaseMaterial(material) {
  return isObject(material) && GUARD_LEASE_MATERIALS.has(material)
}

function isBootstrapUdxAuthority(authority) {
  const state = isObject(authority) ? BOOTSTRAP_UDX_AUTHORITIES.get(authority) : null
  return !!(state && state.live && !state.pinned)
}

function createTestBootstrapUdxAuthority(options) {
  if (!isObject(options)) invalid()
  const {
    configuredEndpoints,
    localIdentity,
    localSecretKey,
    send,
    destroy,
    monotonicDeadline = 10_000
  } = options
  if (
    !Array.isArray(configuredEndpoints) ||
    configuredEndpoints.length < 1 ||
    configuredEndpoints.length > 3 ||
    typeof send !== 'function' ||
    typeof destroy !== 'function' ||
    !Number.isSafeInteger(monotonicDeadline) ||
    monotonicDeadline < 1
  )
    invalid()
  const capability = createLocalIdentitySecretCapability({ localIdentity, localSecretKey })
  const secret = LOCAL_SECRET_CAPABILITIES.get(capability)
  LOCAL_SECRET_CAPABILITIES.delete(capability)
  const configured = []
  const seen = new Set()
  try {
    for (const value of configuredEndpoints) {
      const tuple = exactEndpoint(value)
      const key = endpointKey(tuple)
      if (seen.has(key)) invalid()
      seen.add(key)
      configured.push({ ...tuple, key, token: Object.freeze({}), active: true })
    }
    const authority = Object.freeze({})
    BOOTSTRAP_UDX_AUTHORITIES.set(authority, {
      authority,
      kind: 'test',
      endpoint: null,
      configured,
      admissions: new Set(),
      maxProspectiveGuards: 3,
      monotonicDeadline,
      secret,
      live: true,
      pinned: false,
      ownsEndpoint: false,
      operation: null,
      testTransport: { send, destroy }
    })
    return authority
  } catch (err) {
    clearSecretRecord(secret)
    throw err
  }
}

function createTestUdxAdapterAuthority(fakeFactory) {
  if (typeof fakeFactory !== 'function') invalid()
  const authority = Object.freeze({})
  TEST_ADAPTER_AUTHORITIES.set(authority, { fakeFactory, used: false })
  return authority
}

function createUdxCellEndpointForTest(options, authority) {
  const record = isObject(authority) ? TEST_ADAPTER_AUTHORITIES.get(authority) : null
  if (!record || record.used) throw PrivateRouteError.UNAUTHORIZED()
  record.used = true
  TEST_ADAPTER_AUTHORITIES.delete(authority)
  let adapter
  try {
    adapter = record.fakeFactory()
  } catch {
    throw unavailable()
  } finally {
    record.fakeFactory = null
  }
  if (!adapter || typeof adapter.create !== 'function') throw unavailable()
  return new UdxCellEndpoint(options, { token: TEST_CONSTRUCTION, adapter })
}

function sendBootstrapForTest(endpoint, session, packet) {
  const state = isObject(endpoint) ? ENDPOINTS.get(endpoint) : null
  if (!state || state.closing) return Promise.reject(PrivateRouteError.UNAUTHORIZED())
  for (const record of state.records) {
    if (record.session === session && validateRecord(state, record)) {
      return endpoint.send(record.handle, packet)
    }
  }
  return Promise.reject(PrivateRouteError.UNAUTHORIZED())
}

function sendEstablishedForTest(endpoint, established, value) {
  let reservation
  try {
    reservation = readEstablishedLinkReservation(established)
  } catch {
    return Promise.reject(PrivateRouteError.UNAUTHORIZED())
  }
  if (reservation.endpoint !== endpoint) return Promise.reject(PrivateRouteError.UNAUTHORIZED())
  return endpoint[UDX_SEND_CELL](reservation.sendHandle, value)
}

function inspectGuardLeaseMaterial(material) {
  const state = isObject(material) ? GUARD_LEASE_MATERIALS.get(material) : null
  if (!state) throw PrivateRouteError.UNAUTHORIZED()
  return Object.freeze({ reconnectTransportFactory: state.reconnectTransportFactory })
}

const testOnlyAdapterIssuer = Object.freeze({
  createTestUdxAdapterAuthority,
  createUdxCellEndpointForTest,
  sendBootstrapForTest,
  sendEstablishedForTest,
  inspectGuardLeaseMaterial,
  createTestBootstrapUdxAuthority
})

module.exports = {
  DEFAULT_MAX_UDX_QUEUED_PACKETS,
  DEFAULT_MAX_UDX_QUEUED_BYTES,
  DEFAULT_MAX_UDX_INBOUND_PACKETS,
  DEFAULT_MAX_UDX_INBOUND_BYTES,
  DEFAULT_MAX_UDX_INBOUND_PACKETS_PER_PEER,
  DEFAULT_MAX_UDX_INBOUND_BYTES_PER_PEER,
  UdxCellEndpoint,
  TEST_ONLY_UDX_ADAPTER_ISSUER,
  [TEST_ONLY_UDX_ADAPTER_ISSUER]: testOnlyAdapterIssuer,
  createLocalIdentitySecretCapability,
  createBootstrapUdxAuthority,
  bindBootstrapUdxOperation,
  isBootstrapUdxAuthority,
  createBootstrapGuardLeaseMaterial,
  destroyLocalIdentitySecretCapability,
  admitBootstrapUdxGuard,
  sendConfigured,
  sendProspectiveGuard,
  openBootstrapUdxGuard,
  pinBootstrapUdxGuard,
  destroyBootstrapUdxAuthority,
  destroyGuardLeaseMaterial,
  isGuardLeaseMaterial
}
