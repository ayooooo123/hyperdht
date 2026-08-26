'use strict'

const b4a = require('b4a')

const { BOOTSTRAP_CLASS, BOOTSTRAP_SIZE, BootstrapEnvelopeCodec } = require('./bootstrap-envelope')
const { MAX_CELL_PAYLOAD, CellCodec } = require('./cell-codec')
const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')
const { createLinkSetupAuthority } = require('./link-setup')
const {
  createLinkControlBoundary,
  LinkControlSession,
  readLinkControlStreamProgress
} = require('./link-control-session')
const {
  LINK_BOOTSTRAP_SESSION_INVALIDATE,
  LinkBootstrapSession
} = require('./link-bootstrap-session')
const {
  LINK_BOOTSTRAP_BIND_OWNERSHIP,
  LINK_BOOTSTRAP_CONSUME_OWNERSHIP,
  LINK_BOOTSTRAP_REGISTER_ESTABLISHED
} = require('./link-bootstrap-ownership')
const {
  closeBootstrapLinkHandleSubscriptions,
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
const {
  LINK_OPERATION,
  CELL_CLASS,
  DIRECTION,
  M3_MESSAGE_ID,
  M3_PROTOCOL_VERSION,
  PROTOCOL_VERSION,
  decodeM3Object,
  roleForIdentity,
  encodeM3Object
} = require('./protocol')
const { decodeCanonicalEndpoint, encodeCanonicalEndpoint } = require('./relay-capability')

// Ported from the reviewed private-routes prototype at commit
// 0305df915b6a767093f9e75e6c06bc0a35da6169 and narrowed to Gate 3B1.

const DEFAULT_MAX_UDX_QUEUED_PACKETS = 64
const DEFAULT_MAX_UDX_QUEUED_BYTES = BOOTSTRAP_SIZE * DEFAULT_MAX_UDX_QUEUED_PACKETS
const DEFAULT_MAX_UDX_INBOUND_PACKETS = 64
const DEFAULT_MAX_UDX_INBOUND_BYTES = BOOTSTRAP_SIZE * DEFAULT_MAX_UDX_INBOUND_PACKETS
const DEFAULT_MAX_UDX_INBOUND_PACKETS_PER_PEER = 8
const DEFAULT_MAX_UDX_INBOUND_BYTES_PER_PEER =
  BOOTSTRAP_SIZE * DEFAULT_MAX_UDX_INBOUND_PACKETS_PER_PEER
const CAPS_RESPONSE_DOMAIN = b4a.from('hyperdht-private-routes/m3/caps-response/v1')
const CORE_FRAGMENT_DOMAIN = b4a.from('hyperdht-private-routes/m3/core-fragment/object/v1')
const DIRECT_FRAGMENT_DATA_BYTES = 1_140
const DIRECT_OBJECT_BYTES = 12_288
const BOOTSTRAP_RPC_MAGIC = 0xd301
const CAPS_QUERY_REQUEST_FIELDS = new Set([
  'kind',
  'requestedCapabilityMask',
  'randomTarget',
  'queryNonce',
  'maximumResults'
])
const CAPS_RETRY_REQUEST_FIELDS = new Set([
  'kind',
  'sourceEndpoint',
  'requestedCapabilityMask',
  'randomTarget',
  'queryNonce',
  'maximumResults',
  'cookieExpiresAtMs',
  'returnRoutabilityCookie',
  'advertisement'
])
const BYTES_REQUEST_FIELDS = new Set(['kind', 'bytes'])
const ENDPOINTS = new WeakMap()
const SEND_HANDLES = new WeakMap()
const TEST_ADAPTER_AUTHORITIES = new WeakMap()
const LOCAL_SECRET_CAPABILITIES = new WeakMap()
const BOOTSTRAP_UDX_AUTHORITIES = new WeakMap()
const BOOTSTRAP_UDX_ADMISSIONS = new WeakMap()
const GUARD_LEASE_MATERIALS = new WeakMap()
const RECONNECTED_GUARD_PINS = new WeakMap()
const RECONNECTED_GUARD_PIN_CONSUMER = Symbol.for(
  'hyperdht-private-routes/reconnected-guard-pin-consumer'
)
const BOOTSTRAP_ACCEPT_HANDLE_FACTORY = Symbol.for(
  'hyperdht-private-routes/bootstrap-accept-handle-factory'
)
const BOOTSTRAP_ACCEPT_HANDLE_CLAIMER = Symbol.for(
  'hyperdht-private-routes/bootstrap-accept-handle-claimer'
)
const ESTABLISHED_SEND_HANDLES = new WeakMap()
const EXTENSION_SETUP_TRANSPORTS = new WeakMap()
let TEST_RECEIVE_OBSERVER = null
const M3_CELL_LINK_TRANSFERS = new WeakMap()
const M3_CELL_LINK_TRANSFER_ISSUERS = new WeakMap()
const M3_CELL_LINK_PHYSICAL_LOSS_REGISTRATIONS = new WeakMap()
const MAX_SHARED_GUARD_M3_CELL_LINK_TRANSFERS = 4
const M3_CELL_LINK_PACKET_OWNERS = new WeakMap()
const TEST_BOOTSTRAP_LINK_RESERVATIONS = new WeakMap()
const BOOTSTRAP_LINK_RESERVATIONS = new WeakMap()
const BOOTSTRAP_LINK_HANDLES = new WeakMap()
const TEST_BOOTSTRAP_LINK_SESSIONS = new WeakMap()
const TEST_BOOTSTRAP_ESTABLISHED = new WeakMap()
const BOOTSTRAP_GUARD_SESSION_OPTIONS = new WeakMap()
const TEST_CONSTRUCTION = Object.freeze({})
const TEST_ONLY_UDX_ADAPTER_ISSUER = Symbol('test-only-udx-adapter-issuer')
// A link handle is authorised for one link, so it may be opened once and by one
// endpoint. Tracking that per endpoint used to be backed by the bound-address check,
// which no longer refuses a second endpoint that declares the same advertised pair.
const CONSUMED_LINK_HANDLES = new WeakSet()
const ENDPOINT_OPTION_KEYS = new Set([
  'host',
  'port',
  // The address peers reach this endpoint at, when a translation sits in between.
  // Absent, it is the bound address, which is the only case the derived test plans
  // and a public host ever produce.
  'advertisedHost',
  'advertisedPort',
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
const GUARD_SESSION_OPTION_FIELDS = new Set([
  'circuitId',
  'epoch',
  'initiatorLocalId',
  'responderLocalId',
  'expiresAt',
  'responderStaticKey',
  'now',
  'handleNow',
  'wallNow',
  'schedule',
  'cancel',
  'randomBytes',
  'absoluteDeadline',
  'signedExpiry'
])
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
  if (!/^[0-9a-fA-F:]+$/.test(host) || host.includes('%') || host.includes('.')) return false
  const marker = host.indexOf('::')
  if (marker !== -1 && marker !== host.lastIndexOf('::')) return false
  const left = (marker === -1 ? host : host.slice(0, marker)).split(':').filter(Boolean)
  const right = (marker === -1 ? '' : host.slice(marker + 2)).split(':').filter(Boolean)
  if (![...left, ...right].every((part) => /^[0-9a-fA-F]{1,4}$/.test(part))) return false
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

function sendGuardBranchDatagram(record, generation, payload) {
  return record.endpoint[UDX_SEND_CELL](record.handle, {
    class: CELL_CLASS.DATAGRAM,
    direction: record.heartbeatDirection,
    generation,
    payload
  })
}

function dispatchGuardBranchExchange(state, authority, payload, metadata) {
  if (metadata.class !== CELL_CLASS.DATAGRAM) return false
  let message = null
  try {
    message = decodeM3Object(payload)
  } catch {
    return false
  }
  if (message.messageId === M3_MESSAGE_ID.LINK_ACCEPT_V1) {
    const pending = authority.guardBranchPending
    if (!pending || pending.generation !== metadata.generation) return true
    authority.guardBranchPending = null
    pending.resolve(b4a.from(payload))
    return true
  }
  if (message.messageId !== M3_MESSAGE_ID.LINK_OFFER_V1 || !authority.guardBranchResponder) {
    return false
  }
  const responder = authority.guardBranchResponder
  if (authority.guardBranchResponding) return true
  authority.guardBranchResponding = true
  let issuer = null
  try {
    issuer = createM3CellLinkTransferIssuer(authority.endpoint, authority.established, {
      sharedGuard: true
    })
  } catch {
    authority.guardBranchResponding = false
    return true
  }
  Promise.resolve()
    .then(() =>
      responder.accept(
        Object.freeze({
          offer: b4a.from(payload),
          physicalChannel: issuer
        })
      )
    )
    .then(async (accept) => {
      const decoded = decodeM3Object(accept)
      if (decoded.messageId !== M3_MESSAGE_ID.LINK_ACCEPT_V1) invalid()
      await sendGuardBranchDatagram(authority, metadata.generation, accept)
      issuer = null
    })
    .catch(() => {})
    .finally(() => {
      authority.guardBranchResponding = false
      if (issuer) issuer.destroy()
    })
  return true
}

function dispatchExtensionSetupTransport(authority, payload, metadata) {
  const transport = authority.extensionSetupTransport
  const state = transport ? EXTENSION_SETUP_TRANSPORTS.get(transport) : null
  if (
    !state ||
    !state.active ||
    metadata.class !== CELL_CLASS.STREAM ||
    metadata.generation !== 1n
  ) {
    return false
  }
  const owned = b4a.from(payload)
  const waiter = state.waiters.shift()
  if (waiter) waiter.resolve(owned)
  else if (state.received.length < 8) state.received.push(owned)
  else {
    clear(owned)
    destroyExtensionSetupTransport(transport, PrivateRouteError.ERR_BUSY(), true)
  }
  return true
}

function deliverEstablishedCell(state, authority, payload, metadata) {
  if (dispatchExtensionSetupTransport(authority, payload, metadata)) return true
  if (dispatchGuardBranchExchange(state, authority, payload, metadata)) return true
  return state.onCell(payload, authority.handle, metadata) === true
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
          return deliverEstablishedCell(state, authority, fragment, metadata)
        },
        enqueueStream(owned, metadata) {
          return deliverEstablishedCell(state, authority, owned, metadata)
        },
        enqueueDatagram(owned, metadata) {
          return deliverEstablishedCell(state, authority, owned, metadata)
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

function clearM3CellLinkBinding(binding) {
  if (!binding) return
  clear(binding.receiveCircuitId)
  clear(binding.sendCircuitId)
}

function destroyM3CellLinkTransferState(state, physicalLoss = false) {
  if (!state || !state.active) return false
  const endpointState = state.endpointState
  const record = state.record
  const physicalLossRegistration = state.physicalLossRegistration
  state.physicalLossRegistration = null
  state.active = false
  if (state.transfer) M3_CELL_LINK_TRANSFERS.delete(state.transfer)
  if (state.issuer) M3_CELL_LINK_TRANSFER_ISSUERS.delete(state.issuer)
  if (physicalLossRegistration) {
    M3_CELL_LINK_PHYSICAL_LOSS_REGISTRATIONS.delete(physicalLossRegistration)
  }
  if (record) {
    if (record.m3CellTransfer === state) record.m3CellTransfer = null
    if (record.m3CellTransfers) {
      record.m3CellTransfers.delete(state)
      if (record.m3CellTransfers.size === 0) record.m3CellTransfers = null
    }
  }
  for (const waiter of (state.waiters || []).splice(0))
    waiter.reject(PrivateRouteError.ERR_DESTROYED())
  for (const owned of (state.queue || []).splice(0)) {
    M3_CELL_LINK_PACKET_OWNERS.delete(owned.packet)
    owned.settle()
  }
  clearM3CellLinkBinding(state.binding)
  state.binding = null
  if (state.transfer && !state.sharedGuard && endpointState && record)
    invalidateRecord(endpointState, record)
  state.endpoint = null
  state.endpointState = null
  state.record = null
  state.established = null
  if (physicalLoss && physicalLossRegistration) {
    try {
      physicalLossRegistration.sink()
    } catch {}
  }
  return true
}
function endpointFromCanonical(encoded) {
  const value = decodeCanonicalEndpoint(encoded)
  try {
    const port = readUint16BE(value, 17)
    if (value[0] === 4) {
      return {
        host: `${value[13]}.${value[14]}.${value[15]}.${value[16]}`,
        port
      }
    }
    const words = []
    for (let offset = 1; offset < 17; offset += 2) {
      words.push(readUint16BE(value, offset).toString(16))
    }
    return { host: words.join(':'), port }
  } finally {
    clear(value)
  }
}

function createBootstrapAcceptLinkHandle(authority) {
  const caps = require('./caps-responder')
  const consume = caps[Symbol.for('hyperdht-private-routes/bootstrap-accept-authority-consumer')]
  const record = consume(authority)
  let localEndpoint = null
  let peerEndpoint = null
  try {
    localEndpoint = endpointFromCanonical(record.localEndpoint)
    peerEndpoint = endpointFromCanonical(record.sourceEndpoint)
    const handle = Object.freeze({})
    BOOTSTRAP_LINK_HANDLES.set(handle, {
      live: true,
      dynamicPeer: true,
      now: record.now,
      expiresAt: record.expiresAt,
      authorizedExpiry: record.expiresAt,
      digest32: b4a.alloc(32),
      localIdentity32: b4a.from(record.localIdentity),
      localRole: roleForIdentity(record.localIdentity),
      localAddress: {
        family: localEndpoint.host.includes(':') ? 6 : 4,
        host: localEndpoint.host,
        port: localEndpoint.port
      },
      peerIdentity32: b4a.alloc(32),
      peerRole: null,
      peerAddress: {
        family: peerEndpoint.host.includes(':') ? 6 : 4,
        host: peerEndpoint.host,
        port: peerEndpoint.port
      },
      epoch: record.epoch,
      runId32: b4a.alloc(32),
      operations: LINK_OPERATION.ACCEPT
    })
    return handle
  } finally {
    clear(record.sourceEndpoint)
    clear(record.localIdentity)
    clear(record.localEndpoint)
  }
}

function claimBootstrapAcceptLinkHandle(handle, identity, source) {
  const state = isObject(handle) ? BOOTSTRAP_LINK_HANDLES.get(handle) : null
  if (
    !state ||
    !state.live ||
    !state.dynamicPeer ||
    !fixed(identity, 32) ||
    !isObject(source) ||
    source.host !== state.peerAddress.host ||
    source.port !== state.peerAddress.port
  ) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  state.peerIdentity32.fill(0)
  state.peerIdentity32 = b4a.from(identity)
  state.peerRole = roleForIdentity(identity)
  state.dynamicPeer = false
  return true
}

function readBootstrapLinkHandle(handle) {
  const state = isObject(handle) ? BOOTSTRAP_LINK_HANDLES.get(handle) : null
  if (!state || !state.live) return null
  let now
  try {
    now = BigInt(state.now())
  } catch {
    destroyOwnedBootstrapLinkHandle(handle)
    return null
  }
  if (now >= state.expiresAt) {
    destroyOwnedBootstrapLinkHandle(handle)
    return null
  }
  return {
    digest32: b4a.from(state.digest32),
    localIdentity32: b4a.from(state.localIdentity32),
    localRole: state.localRole,
    localAddress: { ...state.localAddress },
    peerIdentity32: b4a.from(state.peerIdentity32),
    peerRole: state.peerRole,
    peerAddress: { ...state.peerAddress },
    epoch: state.epoch,
    runId32: b4a.from(state.runId32),
    operations: state.operations,
    dynamicPeer: state.dynamicPeer === true,
    authorizedExpiry: state.authorizedExpiry
  }
}

function readEndpointLinkHandle(handle, mode) {
  const local = readBootstrapLinkHandle(handle)
  const link = local || readLinkHandle(handle)
  const required = mode === 'initiate' ? LINK_OPERATION.INITIATE : LINK_OPERATION.ACCEPT
  if ((mode !== 'initiate' && mode !== 'accept') || (link.operations & required) !== required) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  return link
}

function destroyOwnedBootstrapLinkHandle(handle) {
  const state = isObject(handle) ? BOOTSTRAP_LINK_HANDLES.get(handle) : null
  if (!state || !state.live) return false
  state.live = false
  BOOTSTRAP_LINK_HANDLES.delete(handle)
  closeBootstrapLinkHandleSubscriptions(handle)
  clear(state.digest32)
  clear(state.localIdentity32)
  clear(state.peerIdentity32)
  clear(state.runId32)
  return true
}

function destroyRecordM3CellTransfers(record) {
  destroyM3CellLinkTransferState(record.m3CellTransfer, true)
  if (!record.m3CellTransfers) return
  for (const state of Array.from(record.m3CellTransfers)) {
    destroyM3CellLinkTransferState(state, true)
  }
}

function invalidateRecord(state, record) {
  if (!record || record.phase === 'CLOSED') return
  const guardBranchPending = record.guardBranchPending || null
  record.guardBranchPending = null
  record.guardBranchResponder = null
  const guardLossRegistration = record.guardLossRegistration || null
  record.guardLossRegistration = null
  if (record.extensionSetupTransport) {
    destroyExtensionSetupTransport(
      record.extensionSetupTransport,
      PrivateRouteError.ERR_DESTROYED(),
      false
    )
  }
  record.phase = 'CLOSED'
  destroyRecordM3CellTransfers(record)
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
  if (record.bootstrapOwnedHandle) {
    destroyOwnedBootstrapLinkHandle(record.bootstrapOwnedHandle)
    record.bootstrapOwnedHandle = null
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
  if (record.established) ESTABLISHED_SEND_HANDLES.delete(record.established)
  record.established = null
  if (guardLossRegistration) {
    try {
      const { issueGuardLeasePhysicalLoss } = require('./guard-lease')
      issueGuardLeasePhysicalLoss(guardLossRegistration)
    } catch {}
  }
  if (guardBranchPending) guardBranchPending.reject(PrivateRouteError.ERR_DESTROYED())
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
  record.settle = null
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
  const record = { packet: null, peerKey, completion: null, settle: null, active: true }
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
  record.settle = settle
  record.completion = ownership.finally(() => releaseReceive(state, record))
  return { packet: record.packet, settle }
}

function matchesM3CellLinkTransfer(state, packet) {
  if (!state || !state.active || !state.binding) return false
  const cellClass = packet[1]
  return (
    packet[0] === PROTOCOL_VERSION &&
    (cellClass === CELL_CLASS.CONTROL || cellClass === CELL_CLASS.DATAGRAM) &&
    packet[2] === state.binding.receiveDirection &&
    readUint64BE(packet, 4) === state.binding.receiveEpoch &&
    b4a.equals(bufferSubarray.call(packet, 12, 28), state.binding.receiveCircuitId)
  )
}

function receiveM3CellLinkTransfer(state, owned) {
  if (!matchesM3CellLinkTransfer(state, owned.packet)) return false
  const waiter = state.waiters.shift()
  M3_CELL_LINK_PACKET_OWNERS.set(owned.packet, owned)
  if (waiter) waiter.resolve(owned.packet)
  else state.queue.push(owned)
  return true
}

async function waitForReceives(state) {
  const completions = Array.from(state.receiveRecords, (record) => record.completion)
  if (completions.length === 0) return
  await Promise.allSettled(completions)
  for (const record of Array.from(state.receiveRecords)) releaseReceive(state, record)
}

function settleBootstrapUdxResponse(state, pending) {
  if (state.pendingResponse !== pending || pending.response === null || !pending.sendComplete) {
    return false
  }
  state.pendingResponse = null
  const response = pending.response
  pending.response = null
  pending.active = false
  pending.resolve(response)
  return true
}

function rejectBootstrapUdxResponse(state, error) {
  const pending = state.pendingResponse
  if (!pending) return false
  state.pendingResponse = null
  pending.active = false
  clear(pending.response)
  pending.response = null
  pending.reject(error)
  return true
}

function receiveBootstrapUdxResponse(state, direct, packet) {
  const authorityState = direct.state
  const pending = authorityState.pendingResponse
  if (
    !pending ||
    !pending.active ||
    pending.record.token !== direct.token ||
    pending.operation !== authorityState.operation ||
    !authorityState.live ||
    authorityState.pinned
  ) {
    return false
  }
  let owned = null
  try {
    owned = b4a.from(packet)
  } catch {
    return false
  }
  if (
    authorityState.pendingResponse !== pending ||
    pending.response !== null ||
    pending.record.token !== direct.token
  ) {
    clear(owned)
    return false
  }
  let accepted = null
  try {
    accepted = pending.accept(owned)
  } catch (err) {
    clear(owned)
    rejectBootstrapUdxResponse(authorityState, err)
    return true
  }
  if (accepted === null) {
    clear(owned)
    return true
  }
  if (accepted !== owned) clear(owned)
  pending.response = accepted
  settleBootstrapUdxResponse(authorityState, pending)
  return true
}
function isAuthenticatedCapsRequestPacket(packet) {
  if (
    packet[0] !== 0xd3 ||
    packet[1] !== 0x01 ||
    readUint16BE(packet, 2) < 8 ||
    readUint16BE(packet, 2) > BOOTSTRAP_SIZE - 4
  )
    return false
  try {
    const bytes = readUint16BE(packet, 2)
    for (let index = 4 + bytes; index < packet.byteLength; index++) {
      if (packet[index] !== 0) return false
    }
    const decoded = decodeM3Object(packet.subarray(4, 4 + bytes))
    return (
      decoded.messageId === M3_MESSAGE_ID.CAPS_QUERY_V1 ||
      decoded.messageId === M3_MESSAGE_ID.ACTIVE_CHALLENGE_V1
    )
  } catch {
    return false
  }
}

function dispatchDirectBootstrap(state, source, direct, packet) {
  if (receiveBootstrapUdxResponse(state, direct, packet)) return
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
}

function receive(state, packet, from) {
  if (state.closing || !b4a.isBuffer(packet) || packet.byteLength !== BOOTSTRAP_SIZE) return
  let source
  try {
    source = `${from.host}:${from.port}`
  } catch {
    return
  }
  const sendHandle = state.sources.get(source)
  const authority = isObject(sendHandle) ? SEND_HANDLES.get(sendHandle) : null
  const linked = validateRecord(state, authority)
  const direct = state.directSources.get(source)
  const directLive = direct && direct.active && direct.state === state.bootstrapAuthority
  if (TEST_RECEIVE_OBSERVER) {
    try {
      TEST_RECEIVE_OBSERVER({
        endpoint: `${state.host}:${state.port}`,
        source,
        owner:
          directLive && (!linked || isAuthenticatedCapsRequestPacket(packet))
            ? 'direct'
            : linked
              ? 'link'
              : 'none',
        first: packet[0],
        second: packet[1]
      })
    } catch {}
  }
  if (directLive && (!linked || isAuthenticatedCapsRequestPacket(packet))) {
    dispatchDirectBootstrap(state, source, direct, packet)
    return
  }
  if (!linked) return
  if (packet[0] !== 0) return
  if (packet[1] !== BOOTSTRAP_CLASS && packet[1] > 2) return
  if (packet[1] !== BOOTSTRAP_CLASS && authority.phase !== 'OPEN') return
  const peerKey = authority.peerKey
  const owned = ownReceive(state, peerKey, packet)
  if (!owned) return
  if (owned.packet[1] !== BOOTSTRAP_CLASS) {
    if (receiveM3CellLinkTransfer(authority.m3CellTransfer, owned)) return
    if (authority.m3CellTransfers) {
      for (const transfer of authority.m3CellTransfers) {
        if (receiveM3CellLinkTransfer(transfer, owned)) return
      }
    }
  }
  // A handler promise owns its packet until settlement. The exact endpoint
  // close promise is recognized below; another handler promise must not await
  // that close because an indirect promise cycle cannot be identified safely.
  try {
    const result =
      owned.packet[1] === BOOTSTRAP_CLASS
        ? authority.bootstrapBinding && authority.session
          ? authority.session.receive(owned.packet)
          : state.onBootstrap(owned.packet, sendHandle)
        : authority.linkControl
          ? receiveEstablished(state, authority, owned.packet)
          : state.onCell(owned.packet, sendHandle)
    if (TEST_RECEIVE_OBSERVER && owned.packet[1] === BOOTSTRAP_CLASS && authority.session) {
      Promise.resolve(result).then(
        (value) => {
          try {
            TEST_RECEIVE_OBSERVER({
              endpoint: `${state.host}:${state.port}`,
              source,
              owner: 'session-result',
              result: value === false ? false : value === true ? true : 'established'
            })
          } catch {}
        },
        (err) => {
          try {
            TEST_RECEIVE_OBSERVER({
              endpoint: `${state.host}:${state.port}`,
              source,
              owner: 'session-error',
              error: err && err.code
            })
          } catch {}
        }
      )
    }
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
    let freshAdapterFactory = null
    let testConstruction = false
    if (construction !== null) {
      if (
        construction.token !== TEST_CONSTRUCTION ||
        !construction.adapter ||
        typeof construction.freshAdapterFactory !== 'function'
      )
        invalid()
      adapter = construction.adapter
      freshAdapterFactory = construction.freshAdapterFactory
      testConstruction = true
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
    // A socket is bound to an address this host owns and is reached at whatever a
    // translation in between presents. Both are stated or neither is: a half stated
    // pair would leave the advertised address half derived from the bound one.
    const advertisedGiven =
      options.advertisedHost !== undefined || options.advertisedPort !== undefined
    const advertisedHost = advertisedGiven ? options.advertisedHost : host
    const advertisedPort = advertisedGiven ? options.advertisedPort : port
    if (
      advertisedGiven &&
      (options.advertisedHost === undefined ||
        options.advertisedPort === undefined ||
        !numericHost(advertisedHost) ||
        !Number.isInteger(advertisedPort) ||
        advertisedPort < 1 ||
        advertisedPort > 0xffff)
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
      if (socket && typeof socket.close === 'function') {
        try {
          const closing = socket.close()
          if (closing && typeof closing.catch === 'function') void closing.catch(() => {})
        } catch {}
      }
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
      advertisedHost,
      advertisedPort,
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
      freshOwnerTemplate: Object.freeze({
        testConstruction,
        freshAdapterFactory,
        options: Object.freeze({
          host,
          port,
          advertisedHost,
          advertisedPort,
          onBootstrap() {},
          onCell() {},
          onLinkFailure() {},
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
          )
        })
      }),
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
    if (!isObject(sessionOptions)) invalid()
    const mode = sessionOptions.mode
    let link
    try {
      if (
        !isObject(linkHandle) ||
        state.consumedHandles.has(linkHandle) ||
        CONSUMED_LINK_HANDLES.has(linkHandle)
      ) {
        throw PrivateRouteError.UNAUTHORIZED()
      }
      link = readEndpointLinkHandle(linkHandle, mode)
    } catch {
      throw PrivateRouteError.UNAUTHORIZED()
    }
    state.consumedHandles.add(linkHandle)
    CONSUMED_LINK_HANDLES.add(linkHandle)
    // A link handle carries the local address a signed capability names, which is the
    // advertised one. Comparing it against the bound address holds only when nothing
    // translates in between, and rejects every link on a host behind a NAT.
    //
    // What this check is: the endpoint declares one address pair when it is
    // constructed, and a handle naming any other pair is not its link. What it is
    // not: proof that this host owns that address. That proof is the signed grant the
    // handle was authorised from, which binds an identity to an address; the check
    // above only stops an endpoint from serving links it was never named in.
    if (
      link.localAddress.host !== state.advertisedHost ||
      link.localAddress.port !== state.advertisedPort
    ) {
      throw PrivateRouteError.UNAUTHORIZED()
    }
    const source = `${link.peerAddress.host}:${link.peerAddress.port}`
    if (state.sources.has(source)) {
      const existingHandle = state.sources.get(source)
      const existing = SEND_HANDLES.get(existingHandle)
      if (validateRecord(state, existing)) {
        if (link.dynamicPeer !== true) throw PrivateRouteError.CIRCUIT_STATE()
        invalidateRecord(state, existing)
      }
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
      bootstrapOwnedHandle: null,
      sharedGuard: false,
      established: null,
      m3CellTransfer: null,
      m3CellTransfers: null,
      extensionSetupTransport: null,
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
    if (state.closing) {
      releaseReservation(reservation)
      return Promise.reject(stateError())
    }
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

  [LINK_BOOTSTRAP_REGISTER_ESTABLISHED](handle, established) {
    const state = ENDPOINTS.get(this)
    const record = isObject(handle) ? SEND_HANDLES.get(handle) : null
    if (
      state.closing ||
      !validateRecord(state, record) ||
      record.phase !== 'OPEN' ||
      record.established !== null ||
      !isObject(established)
    ) {
      throw PrivateRouteError.UNAUTHORIZED()
    }
    ESTABLISHED_SEND_HANDLES.set(established, record)
    record.established = established
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
    state.closePromise = Promise.resolve().then(async () => {
      for (const record of Array.from(state.receiveRecords)) {
        if (typeof record.settle === 'function') record.settle()
      }
      await waitForReceives(state)
      await Promise.allSettled(Array.from(state.nativeWaits))
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
    })
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

function clearBootstrapCapsSessions(state) {
  if (!state.capsSessions) return
  for (const session of state.capsSessions.values()) {
    clear(session.returnRoutabilityCookie)
    for (const advertisement of session.advertisements) clear(advertisement)
    session.advertisements.length = 0
  }
  state.capsSessions.clear()
}

function revokeDirectRecords(state) {
  rejectBootstrapUdxResponse(state, PrivateRouteError.ERR_DESTROYED())
  for (const record of state.configured) record.active = false
  clearBootstrapCapsSessions(state)
  if (state.linkReservations) {
    for (const reservation of state.linkReservations)
      BOOTSTRAP_LINK_RESERVATIONS.delete(reservation)
    state.linkReservations.clear()
  }
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
      (!Number.isSafeInteger(options.monotonicDeadline) &&
        typeof options.monotonicDeadline !== 'function') ||
      (Number.isSafeInteger(options.monotonicDeadline) && options.monotonicDeadline < 1)
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
      monotonicDeadline:
        typeof options.monotonicDeadline === 'function' ? null : options.monotonicDeadline,
      monotonicNow:
        typeof options.monotonicDeadline === 'function' ? options.monotonicDeadline : null,
      secret,
      live: true,
      pinned: false,
      ownsEndpoint: false,
      operation: null,
      capsSessions: new Map(),
      linkReservations: new Set(),
      pendingResponse: null
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
    return state.testTransport.send(record.host, record.port, packet, record.token)
  }
  return sendEndpointDirect(
    state.endpoint,
    record.host,
    record.port,
    packet,
    () => state.live && !state.pinned && !!state.operation && record.active
  )
}

async function sendEndpointDirect(endpoint, host, port, packet, active = () => true) {
  const endpointState = ENDPOINTS.get(endpoint)
  if (
    !active() ||
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
  let nativeOwned = false
  endpointState.reservedPackets++
  endpointState.reservedBytes += BOOTSTRAP_SIZE
  try {
    owned = b4a.from(packet)
    nativeOwned = true
    const sent = await trackNativeOwnership(
      endpointState,
      () => endpointState.socket.send(owned, port, host),
      () => {
        endpointState.reservedPackets--
        endpointState.reservedBytes -= BOOTSTRAP_SIZE
        clear(owned)
        owned = null
      }
    )
    if (!active() || sent !== true) throw unavailable()
    return true
  } finally {
    if (!nativeOwned) {
      endpointState.reservedPackets--
      endpointState.reservedBytes -= BOOTSTRAP_SIZE
      clear(owned)
    }
  }
}

function trackNativeOwnership(state, send, release) {
  let resolveNative = null
  let rejectNative = null
  const native = new Promise((resolve, reject) => {
    resolveNative = resolve
    rejectNative = reject
  })
  const completion = native.finally(() => {
    try {
      release()
    } finally {
      state.nativeWaits.delete(completion)
    }
  })
  state.nativeWaits.add(completion)
  void completion.catch(() => {})
  try {
    Promise.resolve(send()).then(resolveNative, rejectNative)
  } catch (err) {
    rejectNative(err)
  }
  return completion
}

function sendBootstrapUdxRequest(state, record, packet, accept = (response) => response) {
  if (state.kind === 'test') return sendDirect(state, record, packet)
  if (
    !state.live ||
    state.pinned ||
    !state.operation ||
    !record.active ||
    state.pendingResponse !== null
  ) {
    return Promise.reject(
      state.pendingResponse === null
        ? PrivateRouteError.UNAUTHORIZED()
        : PrivateRouteError.ERR_BUSY()
    )
  }
  let resolveResponse = null
  let rejectResponse = null
  const result = new Promise((resolve, reject) => {
    resolveResponse = resolve
    rejectResponse = reject
  })
  const pending = {
    state,
    record,
    operation: state.operation,
    response: null,
    accept,
    sendComplete: false,
    active: true,
    resolve: resolveResponse,
    reject: rejectResponse
  }
  state.pendingResponse = pending
  Promise.resolve()
    .then(() => sendDirect(state, record, packet))
    .then(
      (sent) => {
        if (
          !pending.active ||
          state.pendingResponse !== pending ||
          pending.operation !== state.operation ||
          sent !== true
        ) {
          if (pending.active) rejectBootstrapUdxResponse(state, PrivateRouteError.ERR_DESTROYED())
          return
        }
        pending.sendComplete = true
        settleBootstrapUdxResponse(state, pending)
      },
      (err) => {
        if (state.pendingResponse === pending) rejectBootstrapUdxResponse(state, err)
      }
    )
  return result
}
function writeUint16BE(output, value, offset) {
  output[offset] = value >>> 8
  output[offset + 1] = value
}

function writeUint32BE(output, value, offset) {
  output[offset] = value >>> 24
  output[offset + 1] = value >>> 16
  output[offset + 2] = value >>> 8
  output[offset + 3] = value
}

function readUint16BE(input, offset) {
  return (input[offset] << 8) | input[offset + 1]
}

function readUint32BE(input, offset) {
  return (
    input[offset] * 0x1000000 +
    (input[offset + 1] << 16) +
    (input[offset + 2] << 8) +
    input[offset + 3]
  )
}

function capsSignatureInput(body) {
  const output = b4a.allocUnsafe(2 + CAPS_RESPONSE_DOMAIN.byteLength + 8 + body.byteLength)
  writeUint16BE(output, CAPS_RESPONSE_DOMAIN.byteLength, 0)
  output.set(CAPS_RESPONSE_DOMAIN, 2)
  writeUint32BE(output, M3_PROTOCOL_VERSION, 2 + CAPS_RESPONSE_DOMAIN.byteLength)
  writeUint16BE(output, M3_MESSAGE_ID.CAPS_RESPONSE_V1, 6 + CAPS_RESPONSE_DOMAIN.byteLength)
  writeUint16BE(output, body.byteLength, 8 + CAPS_RESPONSE_DOMAIN.byteLength)
  output.set(body, 10 + CAPS_RESPONSE_DOMAIN.byteLength)
  return output
}

function encodeCapsQueryPacket(message, phase, expiresAt = 0n, cookie = b4a.alloc(32)) {
  const body = b4a.alloc(110)
  writeUint32BE(body, message.requestedCapabilityMask, 0)
  body.set(message.randomTarget, 4)
  body.set(message.queryNonce, 36)
  body[68] = message.maximumResults
  body[69] = phase
  writeUint64BE(body, expiresAt, 70)
  body.set(cookie, 78)
  return encodeM3Object({ messageId: M3_MESSAGE_ID.CAPS_QUERY_V1, body })
}

function decodeCapsChallenge(packet, message) {
  const object = decodeM3Object(packet)
  if (
    object.messageId !== M3_MESSAGE_ID.CAPS_COOKIE_CHALLENGE_V1 ||
    packet.byteLength !== 80 ||
    !same(object.body.subarray(0, 32), message.queryNonce)
  ) {
    throw PrivateRouteError.ERR_AUTHENTICATION()
  }
  const cookieExpiresAtMs = readUint64BE(object.body, 32)
  const returnRoutabilityCookie = b4a.from(object.body.subarray(40, 72))
  if (cookieExpiresAtMs === 0n || !returnRoutabilityCookie.some((byte) => byte !== 0)) {
    clear(returnRoutabilityCookie)
    throw PrivateRouteError.ERR_AUTHENTICATION()
  }
  return { cookieExpiresAtMs, returnRoutabilityCookie }
}

function decodeCapsResponsePacket(packet, message) {
  const object = decodeM3Object(packet)
  if (object.messageId !== M3_MESSAGE_ID.CAPS_RESPONSE_V1) invalid()
  const body = object.body
  const responderIdentity = b4a.from(body.subarray(0, 32))
  if (!same(body.subarray(32, 64), message.queryNonce)) {
    clear(responderIdentity)
    throw PrivateRouteError.ERR_AUTHENTICATION()
  }
  const input = capsSignatureInput(body)
  const verified = cryptoSuite.verify(input, object.authSuffix, responderIdentity)
  clear(input)
  clear(responderIdentity)
  if (!verified) throw PrivateRouteError.ERR_AUTHENTICATION()
  const count = body[72]
  if (count < 1 || count > message.maximumResults) invalid()
  const advertisements = []
  let offset = 73
  try {
    for (let index = 0; index < count; index++) {
      if (offset + 2 > body.byteLength) invalid()
      const bytes = readUint16BE(body, offset)
      offset += 2
      if (bytes < 260 || bytes > 548 || offset + bytes > body.byteLength) invalid()
      advertisements.push(b4a.from(body.subarray(offset, offset + bytes)))
      offset += bytes
    }
    if (offset !== body.byteLength) invalid()
    return advertisements
  } catch (err) {
    for (const advertisement of advertisements) clear(advertisement)
    throw err
  }
}

function capsResponseAssembler(message) {
  let total = null
  let count = null
  let digest = null
  let output = null
  const received = new Set()
  return (packet) => {
    const object = decodeM3Object(packet)
    if (object.messageId === M3_MESSAGE_ID.CAPS_RESPONSE_V1) {
      return decodeCapsResponsePacket(packet, message)
    }
    if (object.messageId !== M3_MESSAGE_ID.CORE_FRAGMENT_V1) invalid()
    const body = object.body
    const objectMessageId = readUint16BE(body, 0)
    const nextDigest = body.subarray(2, 34)
    const nextTotal = readUint32BE(body, 34)
    const index = readUint16BE(body, 38)
    const nextCount = readUint16BE(body, 40)
    const fragmentOffset = readUint32BE(body, 42)
    const bytes = readUint16BE(body, 46)
    if (
      objectMessageId !== M3_MESSAGE_ID.CAPS_RESPONSE_V1 ||
      nextTotal < 407 ||
      nextTotal > DIRECT_OBJECT_BYTES ||
      nextCount !== Math.ceil(nextTotal / DIRECT_FRAGMENT_DATA_BYTES) ||
      index >= nextCount ||
      fragmentOffset !== index * DIRECT_FRAGMENT_DATA_BYTES ||
      bytes !== body.byteLength - 48
    ) {
      invalid()
    }
    if (output === null) {
      if (index !== 0) invalid()
      total = nextTotal
      count = nextCount
      digest = b4a.from(nextDigest)
      output = b4a.allocUnsafe(total)
    } else if (total !== nextTotal || count !== nextCount || !same(digest, nextDigest)) {
      invalid()
    }
    const data = body.subarray(48)
    if (received.has(index)) {
      if (!same(output.subarray(fragmentOffset, fragmentOffset + bytes), data)) invalid()
      return null
    }
    output.set(data, fragmentOffset)
    received.add(index)
    if (received.size !== count) return null
    const observed = cryptoSuite.hash([CORE_FRAGMENT_DOMAIN, output])
    const valid = same(observed, digest)
    clear(observed)
    clear(digest)
    if (!valid) {
      clear(output)
      invalid()
    }
    const complete = output
    output = null
    try {
      return decodeCapsResponsePacket(complete, message)
    } finally {
      clear(complete)
    }
  }
}

function canonicalDirectRecord(record) {
  if (!isObject(record) || !numericHost(record.host)) invalid()
  if (record.host.includes('.')) {
    const addressBytes = b4a.from(record.host.split('.').map((part) => Number(part)))
    return encodeCanonicalEndpoint({ addressFamily: 4, addressBytes, port: record.port })
  }
  const split = record.host.split('::')
  const left = split[0] === '' ? [] : split[0].split(':')
  const right = split.length === 1 || split[1] === '' ? [] : split[1].split(':')
  const missing = 8 - left.length - right.length
  const words = [...left, ...Array(missing).fill('0'), ...right]
  const addressBytes = b4a.allocUnsafeSlow(16)
  for (let index = 0; index < words.length; index++) {
    const word = Number.parseInt(words[index], 16)
    addressBytes[index * 2] = word >>> 8
    addressBytes[index * 2 + 1] = word
  }
  return encodeCanonicalEndpoint({ addressFamily: 6, addressBytes, port: record.port })
}

function encodeBootstrapRpcPacket(packet) {
  if (!b4a.isBuffer(packet) || packet.byteLength < 8 || packet.byteLength > BOOTSTRAP_SIZE - 4)
    invalid()
  const output = b4a.alloc(BOOTSTRAP_SIZE)
  writeUint16BE(output, BOOTSTRAP_RPC_MAGIC, 0)
  writeUint16BE(output, packet.byteLength, 2)
  output.set(packet, 4)
  return output
}

function decodeBootstrapRpcPacket(packet) {
  if (!fixed(packet, BOOTSTRAP_SIZE) || readUint16BE(packet, 0) !== BOOTSTRAP_RPC_MAGIC) {
    invalid()
  }
  const bytes = readUint16BE(packet, 2)
  if (bytes < 8 || bytes > BOOTSTRAP_SIZE - 4) invalid()
  for (let index = 4 + bytes; index < packet.byteLength; index++) {
    if (packet[index] !== 0) invalid()
  }
  return packet.subarray(4, 4 + bytes)
}

function requestBootstrapM3(state, record, packet, accept = (value) => b4a.from(value)) {
  const framed = encodeBootstrapRpcPacket(packet)
  return sendBootstrapUdxRequest(state, record, framed, (response) =>
    accept(decodeBootstrapRpcPacket(response))
  )
}

async function requestBootstrapLogical(state, record, message) {
  if (state.kind === 'test' || b4a.isBuffer(message)) {
    return sendBootstrapUdxRequest(state, record, message)
  }
  if (!isObject(message) || typeof message.kind !== 'string') invalid()
  if (
    message.kind === 'caps-query' &&
    (!exactOwnData(message, CAPS_QUERY_REQUEST_FIELDS) ||
      message.requestedCapabilityMask !== 1 ||
      !fixed(message.randomTarget, 32) ||
      !fixed(message.queryNonce, 32) ||
      !Number.isSafeInteger(message.maximumResults) ||
      message.maximumResults < 1 ||
      message.maximumResults > 8)
  ) {
    invalid()
  }
  if (
    message.kind === 'caps-retry' &&
    (!exactOwnData(message, CAPS_RETRY_REQUEST_FIELDS) ||
      message.requestedCapabilityMask !== 1 ||
      !fixed(message.sourceEndpoint, 19) ||
      !fixed(message.randomTarget, 32) ||
      !fixed(message.queryNonce, 32) ||
      !Number.isSafeInteger(message.maximumResults) ||
      message.maximumResults < 1 ||
      message.maximumResults > 8 ||
      typeof message.cookieExpiresAtMs !== 'bigint' ||
      !fixed(message.returnRoutabilityCookie, 32) ||
      !b4a.isBuffer(message.advertisement))
  ) {
    invalid()
  }
  if (
    (message.kind === 'active-challenge' || message.kind === 'link') &&
    (!exactOwnData(message, BYTES_REQUEST_FIELDS) || !b4a.isBuffer(message.bytes))
  ) {
    invalid()
  }
  if (message.kind === 'caps-query') {
    const phase0 = encodeCapsQueryPacket(message, 0)
    const challengePacket = await requestBootstrapM3(state, record, phase0)
    const challenge = decodeCapsChallenge(challengePacket, message)
    clear(challengePacket)
    const phase1 = encodeCapsQueryPacket(
      message,
      1,
      challenge.cookieExpiresAtMs,
      challenge.returnRoutabilityCookie
    )
    const advertisements = await requestBootstrapM3(
      state,
      record,
      phase1,
      capsResponseAssembler(message)
    )
    const sourceEndpoint = canonicalDirectRecord(record)
    state.capsSessions.set(record.token, {
      message,
      cookieExpiresAtMs: challenge.cookieExpiresAtMs,
      returnRoutabilityCookie: b4a.from(challenge.returnRoutabilityCookie),
      advertisements: advertisements.map((value) => b4a.from(value))
    })
    return Object.freeze({
      sourceEndpoint,
      cookieExpiresAtMs: challenge.cookieExpiresAtMs,
      returnRoutabilityCookie: challenge.returnRoutabilityCookie,
      advertisements
    })
  }
  if (message.kind === 'caps-retry') {
    const session = state.capsSessions.get(record.token)
    if (
      !session ||
      session.cookieExpiresAtMs !== message.cookieExpiresAtMs ||
      !same(session.returnRoutabilityCookie, message.returnRoutabilityCookie) ||
      !session.advertisements.some((value) => same(value, message.advertisement))
    ) {
      throw PrivateRouteError.ERR_AUTHENTICATION()
    }
    return Object.freeze({})
  }
  if (message.kind === 'active-challenge') {
    const bytes = await requestBootstrapM3(state, record, message.bytes)
    return Object.freeze({ bytes })
  }
  if (message.kind === 'link') {
    if (!state.operation || !record.active || !state.admissions.has(record)) {
      throw PrivateRouteError.UNAUTHORIZED()
    }
    const reservation = Object.freeze({})
    const reservationState = {
      reservation,
      authority: state,
      admission: record,
      operation: state.operation,
      generation: state.operation.generation,
      deadline: state.monotonicDeadline,
      live: true
    }
    BOOTSTRAP_LINK_RESERVATIONS.set(reservation, reservationState)
    state.linkReservations.add(reservation)
    return Object.freeze({ reservation })
  }
  throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
}

function bindBootstrapUdxOperation(
  authority,
  deadline,
  generation,
  monotonicNow = null,
  startedAt = null
) {
  const state = isObject(authority) ? BOOTSTRAP_UDX_AUTHORITIES.get(authority) : null
  if (
    !state ||
    !state.live ||
    state.pinned ||
    state.operation ||
    !Number.isSafeInteger(deadline) ||
    !isObject(generation)
  ) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  if (state.monotonicDeadline === null) {
    const sampledStart =
      typeof startedAt === 'bigint' && startedAt <= BigInt(Number.MAX_SAFE_INTEGER)
        ? Number(startedAt)
        : startedAt
    if (
      monotonicNow !== state.monotonicNow ||
      !Number.isSafeInteger(sampledStart) ||
      sampledStart < 0 ||
      deadline - sampledStart !== 10_000
    ) {
      throw PrivateRouteError.UNAUTHORIZED()
    }
    state.monotonicDeadline = deadline
    state.monotonicNow = null
  } else if (deadline !== state.monotonicDeadline) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
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

function requestConfigured(authority, index, packet) {
  const state = isObject(authority) ? BOOTSTRAP_UDX_AUTHORITIES.get(authority) : null
  if (!state || !Number.isSafeInteger(index) || index < 0 || index >= state.configured.length)
    return Promise.reject(PrivateRouteError.UNAUTHORIZED())
  return requestBootstrapLogical(state, state.configured[index], packet)
}

function requestProspectiveGuard(authority, admission, packet) {
  const state = isObject(authority) ? BOOTSTRAP_UDX_AUTHORITIES.get(authority) : null
  const record = isObject(admission) ? BOOTSTRAP_UDX_ADMISSIONS.get(admission) : null
  if (!state || !record || record.state !== state || !state.admissions.has(record))
    return Promise.reject(PrivateRouteError.UNAUTHORIZED())
  return requestBootstrapLogical(state, record, packet)
}

function createBootstrapUdxGuardSessionOptions(authority, admission, reservation, options) {
  const state = isObject(authority) ? BOOTSTRAP_UDX_AUTHORITIES.get(authority) : null
  const admitted = isObject(admission) ? BOOTSTRAP_UDX_ADMISSIONS.get(admission) : null
  if (
    !state ||
    !admitted ||
    admitted.state !== state ||
    !state.live ||
    state.pinned ||
    !state.operation ||
    !isObject(reservation) ||
    !exactOwnData(options, GUARD_SESSION_OPTION_FIELDS) ||
    !fixed(options.circuitId, 16) ||
    typeof options.epoch !== 'bigint' ||
    !fixed(options.initiatorLocalId, 16) ||
    !fixed(options.responderLocalId, 16) ||
    typeof options.expiresAt !== 'bigint' ||
    options.expiresAt > BigInt(Number.MAX_SAFE_INTEGER) ||
    !fixed(options.responderStaticKey, 32) ||
    typeof options.now !== 'function' ||
    typeof options.handleNow !== 'function' ||
    typeof options.wallNow !== 'function' ||
    typeof options.schedule !== 'function' ||
    typeof options.cancel !== 'function' ||
    typeof options.randomBytes !== 'function' ||
    options.absoluteDeadline !== state.monotonicDeadline ||
    !Number.isSafeInteger(options.signedExpiry)
  )
    throw PrivateRouteError.UNAUTHORIZED()
  if (state.kind === 'test') {
    const testReservation = TEST_BOOTSTRAP_LINK_RESERVATIONS.get(reservation)
    if (
      !testReservation ||
      testReservation.state !== state ||
      testReservation.admission !== admitted
    )
      throw PrivateRouteError.UNAUTHORIZED()
  } else {
    const pending = BOOTSTRAP_LINK_RESERVATIONS.get(reservation)
    const validPending =
      pending &&
      pending.live &&
      pending.authority === state &&
      pending.admission === admitted &&
      pending.operation === state.operation &&
      pending.generation === state.operation.generation &&
      pending.deadline === state.monotonicDeadline
    if (!validPending) {
      let link
      try {
        link = readLinkHandle(reservation)
      } catch {
        throw PrivateRouteError.UNAUTHORIZED()
      }
      if (
        !same(link.peerIdentity32, admitted.identity) ||
        link.peerAddress.host !== admitted.host ||
        link.peerAddress.port !== admitted.port
      )
        throw PrivateRouteError.UNAUTHORIZED()
    }
  }
  const capability = Object.freeze({})
  BOOTSTRAP_GUARD_SESSION_OPTIONS.set(capability, {
    authority,
    admission,
    reservation,
    options: {
      circuitId: b4a.from(options.circuitId),
      epoch: options.epoch,
      initiatorLocalId: b4a.from(options.initiatorLocalId),
      responderLocalId: b4a.from(options.responderLocalId),
      expiresAt: options.expiresAt,
      handleNow: options.handleNow,
      responderStaticKey: b4a.from(options.responderStaticKey),
      now: options.now,
      wallNow: options.wallNow,
      schedule: options.schedule,
      cancel: options.cancel,
      randomBytes: options.randomBytes,
      absoluteDeadline: options.absoluteDeadline,
      signedExpiry: options.signedExpiry
    }
  })
  return capability
}

function openBootstrapUdxGuard(authority, admission, linkHandle, sessionOptions) {
  const state = isObject(authority) ? BOOTSTRAP_UDX_AUTHORITIES.get(authority) : null
  const admitted = isObject(admission) ? BOOTSTRAP_UDX_ADMISSIONS.get(admission) : null
  if (
    !state ||
    !admitted ||
    admitted.state !== state ||
    !state.live ||
    state.pinned ||
    !state.operation ||
    !isObject(sessionOptions)
  )
    throw PrivateRouteError.UNAUTHORIZED()
  const encoded = BOOTSTRAP_GUARD_SESSION_OPTIONS.get(sessionOptions)
  if (encoded) {
    if (
      encoded.authority !== authority ||
      encoded.admission !== admission ||
      encoded.reservation !== linkHandle
    )
      throw PrivateRouteError.UNAUTHORIZED()
    BOOTSTRAP_GUARD_SESSION_OPTIONS.delete(sessionOptions)
  } else if (state.kind !== 'test') {
    throw PrivateRouteError.UNAUTHORIZED()
  } else if (sessionOptions.absoluteDeadline !== state.monotonicDeadline) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  if (state.kind === 'test') {
    const reservation = isObject(linkHandle)
      ? TEST_BOOTSTRAP_LINK_RESERVATIONS.get(linkHandle)
      : null
    if (
      !reservation ||
      reservation.used ||
      reservation.state !== state ||
      reservation.admission !== admitted
    ) {
      throw PrivateRouteError.UNAUTHORIZED()
    }
    reservation.used = true
    TEST_BOOTSTRAP_LINK_RESERVATIONS.delete(linkHandle)
    const session = Object.freeze({
      async open() {
        const sessionState = TEST_BOOTSTRAP_LINK_SESSIONS.get(session)
        if (!sessionState || sessionState.used) throw PrivateRouteError.UNAUTHORIZED()
        sessionState.used = true
        await reservation.open(encoded ? encoded.options : sessionOptions)
        if (!state.live || state.pinned || !state.operation) throw unavailable()
        const established = Object.freeze({})
        TEST_BOOTSTRAP_ESTABLISHED.set(established, {
          state,
          admission: admitted,
          session,
          expiresAt: encoded ? encoded.options.expiresAt : sessionOptions.setup.expiresAt,
          live: true
        })
        sessionState.established = established
        return established
      },
      close() {
        const sessionState = TEST_BOOTSTRAP_LINK_SESSIONS.get(session)
        if (!sessionState) return Promise.resolve(false)
        TEST_BOOTSTRAP_LINK_SESSIONS.delete(session)
        if (sessionState.established) {
          TEST_BOOTSTRAP_ESTABLISHED.delete(sessionState.established)
          sessionState.established = null
        }
        return Promise.resolve(true)
      }
    })
    TEST_BOOTSTRAP_LINK_SESSIONS.set(session, {
      state,
      admission: admitted,
      used: false,
      established: null
    })
    return session
  }
  const pending = BOOTSTRAP_LINK_RESERVATIONS.get(linkHandle)
  let ownedBootstrapHandle = null
  if (pending) {
    if (
      !pending.live ||
      pending.authority !== state ||
      pending.admission !== admitted ||
      pending.operation !== state.operation ||
      pending.generation !== state.operation.generation ||
      pending.deadline !== state.monotonicDeadline ||
      !encoded
    ) {
      pending.live = false
      BOOTSTRAP_LINK_RESERVATIONS.delete(linkHandle)
      state.linkReservations.delete(linkHandle)
      throw PrivateRouteError.UNAUTHORIZED()
    }
    pending.live = false
    BOOTSTRAP_LINK_RESERVATIONS.delete(linkHandle)
    state.linkReservations.delete(linkHandle)
    const bootstrapEndpointState = ENDPOINTS.get(state.endpoint)
    if (!bootstrapEndpointState || bootstrapEndpointState.closing || !bootstrapEndpointState.bound)
      throw PrivateRouteError.UNAUTHORIZED()
    const values = encoded.options
    ownedBootstrapHandle = Object.freeze({})
    BOOTSTRAP_LINK_HANDLES.set(ownedBootstrapHandle, {
      live: true,
      now: values.handleNow,
      expiresAt: BigInt(values.signedExpiry),
      authorizedExpiry: values.expiresAt,
      digest32: b4a.alloc(32),
      localIdentity32: b4a.from(state.secret.localIdentity),
      localRole: roleForIdentity(state.secret.localIdentity),
      localAddress: {
        family: bootstrapEndpointState.advertisedHost.includes(':') ? 6 : 4,
        host: bootstrapEndpointState.advertisedHost,
        port: bootstrapEndpointState.advertisedPort
      },
      peerIdentity32: b4a.from(admitted.identity),
      peerRole: roleForIdentity(admitted.identity),
      peerAddress: {
        family: admitted.host.includes(':') ? 6 : 4,
        host: admitted.host,
        port: admitted.port
      },
      epoch: values.epoch,
      runId32: b4a.alloc(32),
      operations: LINK_OPERATION.INITIATE
    })
    linkHandle = ownedBootstrapHandle
  }
  let link
  try {
    link = readLinkHandle(linkHandle)
  } catch {
    destroyOwnedBootstrapLinkHandle(ownedBootstrapHandle)
    throw PrivateRouteError.UNAUTHORIZED()
  }
  if (
    !same(link.peerIdentity32, admitted.identity) ||
    link.peerAddress.host !== admitted.host ||
    link.peerAddress.port !== admitted.port
  ) {
    destroyOwnedBootstrapLinkHandle(ownedBootstrapHandle)
    throw PrivateRouteError.UNAUTHORIZED()
  }
  const ownership = Object.freeze({})
  let actualOptions = sessionOptions
  if (encoded) {
    const values = encoded.options
    actualOptions = {
      mode: 'initiate',
      codec: new BootstrapEnvelopeCodec({
        linkHandle,
        localIdentitySecretKey: state.secret.localSecretKey,
        padding: values.randomBytes
      }),
      linkSetup: createLinkSetupAuthority({ now: values.wallNow, randomBytes: values.randomBytes }),
      setup: {
        circuitId: values.circuitId,
        epoch: values.epoch,
        initiatorIdentity: state.secret.localIdentity,
        responderIdentity: admitted.identity,
        initiatorLocalId: values.initiatorLocalId,
        responderLocalId: values.responderLocalId,
        expiresAt: values.expiresAt,
        responderStaticKey: values.responderStaticKey,
        initiatorIdentitySecretKey: state.secret.localSecretKey
      },
      now: values.now,
      schedule: values.schedule,
      cancel: values.cancel,
      randomBytes: values.randomBytes,
      authorizedExpiry: Number(values.expiresAt),
      absoluteDeadline: values.absoluteDeadline,
      signedExpiry: values.signedExpiry
    }
  }
  const endpointState = ENDPOINTS.get(state.endpoint)
  const direct = endpointState && endpointState.directSources.get(admitted.key)
  if (!direct || direct.state !== state || direct.token !== admission || !direct.active) {
    destroyOwnedBootstrapLinkHandle(ownedBootstrapHandle)
    throw PrivateRouteError.UNAUTHORIZED()
  }
  direct.active = false
  admitted.active = false
  endpointState.directSources.delete(admitted.key)
  let session
  try {
    session = state.endpoint.openLink(linkHandle, actualOptions)
  } catch (err) {
    destroyOwnedBootstrapLinkHandle(ownedBootstrapHandle)
    throw err
  }

  const sendHandle = endpointState.handles.get(linkHandle)
  const record = sendHandle && SEND_HANDLES.get(sendHandle)
  if (!record || record.session !== session || record.phase !== 'PENDING') {
    try {
      void session.close().catch(() => {})
    } catch {}
    destroyOwnedBootstrapLinkHandle(ownedBootstrapHandle)
    throw PrivateRouteError.UNAUTHORIZED()
  }
  try {
    session[LINK_BOOTSTRAP_BIND_OWNERSHIP](ownership)
  } catch {
    try {
      void session.close().catch(() => {})
    } catch {}
    destroyOwnedBootstrapLinkHandle(ownedBootstrapHandle)
    throw PrivateRouteError.UNAUTHORIZED()
  }
  record.bootstrapOwnedHandle = ownedBootstrapHandle
  record.bootstrapBinding = Object.freeze({
    authority,
    admission,
    generation: state.operation.generation,
    deadline: state.monotonicDeadline,
    expiresAt: actualOptions.setup.expiresAt,
    ownership
  })
  return session
}

function closeOriginalGuardOwner(materialState) {
  if (materialState.originalOwnerClose) return materialState.originalOwnerClose
  const owner = materialState.originalOwner
  materialState.originalOwner = null
  if (!owner) {
    materialState.originalOwnerClose = Promise.resolve(true)
    return materialState.originalOwnerClose
  }
  try {
    materialState.originalOwnerClose = Promise.resolve(owner.close())
  } catch (err) {
    materialState.originalOwnerClose = Promise.reject(err)
  }
  void materialState.originalOwnerClose.catch(() => {})
  return materialState.originalOwnerClose
}

function createFreshReconnectOwner(template) {
  if (!template) throw unavailable()
  if (template.testConstruction) {
    return new UdxCellEndpoint(template.options, {
      token: TEST_CONSTRUCTION,
      adapter: template.freshAdapterFactory(),
      freshAdapterFactory: template.freshAdapterFactory
    })
  }
  return new UdxCellEndpoint(template.options)
}

function createReconnectTransport(material, materialState) {
  if (materialState.reconnectIssued) throw PrivateRouteError.UNAUTHORIZED()
  materialState.reconnectIssued = true
  const transportState = {
    active: true,
    owner: null,
    ready: closeOriginalGuardOwner(materialState),
    template: materialState.freshOwnerTemplate,
    host: materialState.host,
    port: materialState.port
  }
  materialState.freshOwnerTemplate = null
  materialState.reconnectTransport = transportState
  transportState.ready = transportState.ready
    .then(async () => {
      if (!transportState.active) throw PrivateRouteError.UNAUTHORIZED()
      const owner = createFreshReconnectOwner(transportState.template)
      transportState.template = null
      transportState.owner = owner
      await owner.bind()
      if (!transportState.active) throw PrivateRouteError.UNAUTHORIZED()
      return owner
    })
    .catch(async (err) => {
      transportState.active = false
      if (transportState.owner) {
        try {
          await transportState.owner.close()
        } catch {}
      }
      throw err instanceof PrivateRouteError ? err : unavailable()
    })
  void transportState.ready.catch(() => {})
  return Object.freeze({
    async reconnect(request) {
      if (!transportState.active) throw PrivateRouteError.UNAUTHORIZED()
      const reconnectModule = require('./guard-reconnect-authority')
      const consumeGuardReconnectRequest =
        reconnectModule[Symbol.for('hyperdht-private-routes/guard-reconnect-request-consumer')]
      const details = consumeGuardReconnectRequest(request)
      let candidateDirectorySink = null
      let localSecretCapability = null
      let bootstrapAuthority = null
      let bootstrapIO = null
      let moved = null
      let transferred = false
      let expectedEndpoint = null
      try {
        expectedEndpoint = canonicalDirectRecord({
          host: transportState.host,
          port: transportState.port
        })
        if (!same(expectedEndpoint, details.guardEndpoint)) {
          throw PrivateRouteError.UNAUTHORIZED()
        }
        const owner = await transportState.ready
        if (!transportState.active || owner !== transportState.owner) {
          throw PrivateRouteError.UNAUTHORIZED()
        }
        const bootstrapModule = require('./bootstrap-io')
        const { consumeBootstrapGuardPin } = bootstrapModule
        const createReconnectBootstrapIO =
          bootstrapModule[Symbol.for('hyperdht-private-routes/reconnect-bootstrap-io-factory')]
        const {
          createRelayCandidateDirectorySink,
          revokeRelayCandidateDirectorySink
        } = require('./relay-candidate-directory')
        candidateDirectorySink = createRelayCandidateDirectorySink({
          wallNow: details.wallNow,
          monotonicNow: details.monotonicNow
        })
        localSecretCapability = createLocalIdentitySecretCapability({
          localIdentity: details.localIdentity,
          localSecretKey: details.localSecretKey
        })
        bootstrapAuthority = createBootstrapUdxAuthority({
          endpoint: owner,
          configuredEndpoints: [
            {
              host: transportState.host,
              port: transportState.port
            }
          ],
          localSecretCapability,
          maxProspectiveGuards: 1,
          monotonicDeadline: Number(details.deadlineAt)
        })
        localSecretCapability = null
        bootstrapIO = createReconnectBootstrapIO(
          {
            endpoints: [
              {
                host: transportState.host,
                port: transportState.port
              }
            ],
            localIdentity: details.localIdentity,
            localSecretKey: details.localSecretKey,
            datagrams: bootstrapAuthority,
            wallNow: details.wallNow,
            monotonicNow: details.monotonicNow,
            randomBytes: cryptoSuite.randomBytes,
            candidateDirectorySink
          },
          details.deadlineAt
        )
        candidateDirectorySink = null
        const pin = await bootstrapIO.start()
        moved = consumeBootstrapGuardPin(pin)
        bootstrapIO = null
        bootstrapAuthority = null
        const pinned = moved.pinnedGuard
        if (
          !same(pinned.identity, details.guardIdentity) ||
          !same(pinned.canonicalEndpoint, details.guardEndpoint) ||
          !same(pinned.advertisement, details.advertisement) ||
          !same(pinned.advertisementDigest, details.advertisementDigest) ||
          pinned.epoch !== details.epoch ||
          pinned.expiresAt < details.expiresAt
        ) {
          throw PrivateRouteError.UNAUTHORIZED()
        }
        const transfer = Object.freeze({})
        RECONNECTED_GUARD_PINS.set(transfer, moved)
        moved = null
        transportState.active = false
        transportState.owner = null
        transferred = true
        return transfer
      } finally {
        clear(expectedEndpoint)
        clear(details.guardIdentity)
        clear(details.guardEndpoint)
        clear(details.advertisement)
        clear(details.advertisementDigest)
        clear(details.localIdentity)
        clear(details.localSecretKey)
        if (!transferred) {
          try {
            if (moved) {
              destroyGuardLeaseMaterial(moved.guardLeaseMaterial)
              moved.candidateDirectory.destroy()
            }
          } catch {}
          try {
            if (bootstrapIO) bootstrapIO.destroy()
          } catch {}
          try {
            if (bootstrapAuthority) destroyBootstrapUdxAuthority(bootstrapAuthority)
          } catch {}
          try {
            if (candidateDirectorySink) revokeRelayCandidateDirectorySink(candidateDirectorySink)
          } catch {}
          try {
            if (localSecretCapability) destroyLocalIdentitySecretCapability(localSecretCapability)
          } catch {}
        }
      }
    },
    destroy() {
      if (!transportState.active) return false
      transportState.active = false
      transportState.template = null
      if (transportState.owner) void transportState.owner.close().catch(() => {})
      transportState.owner = null
      return true
    }
  })
}

function consumeReconnectedGuardPin(transfer) {
  const moved =
    transfer !== null && typeof transfer === 'object' ? RECONNECTED_GUARD_PINS.get(transfer) : null
  if (!moved) throw PrivateRouteError.ERR_REPLAY()
  RECONNECTED_GUARD_PINS.delete(transfer)
  return moved
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
  if (state.kind === 'test') {
    const established = isObject(establishedLink)
      ? TEST_BOOTSTRAP_ESTABLISHED.get(establishedLink)
      : null
    if (
      !established ||
      !established.live ||
      established.state !== state ||
      established.admission !== record
    )
      throw PrivateRouteError.UNAUTHORIZED()
    established.live = false
    TEST_BOOTSTRAP_ESTABLISHED.delete(establishedLink)
    TEST_BOOTSTRAP_LINK_SESSIONS.delete(established.session)
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
      establishedLink: null,
      endpoint: null,
      secret,
      identity,
      host: record.host,
      port: record.port,
      expiresAt: established.expiresAt,
      reconnectTransportFactory() {
        if (arguments.length !== 0) invalid()
        throw unavailable()
      },
      kind: 'bootstrap-fake'
    })
    return material
  }
  const endpointState = ENDPOINTS.get(state.endpoint)
  let endpointRecord = null
  if (endpointState) {
    for (const candidate of endpointState.records) {
      if (candidate.established === establishedLink) {
        endpointRecord = candidate
        break
      }
    }
  }
  const binding = endpointRecord && endpointRecord.bootstrapBinding
  const link = endpointRecord && endpointRecord.linkState
  const topology = endpointRecord && readLinkHandle(endpointRecord.linkHandle)
  if (
    !endpointState ||
    endpointState.closing ||
    !endpointRecord ||
    endpointRecord.endpoint !== state.endpoint ||
    endpointRecord.phase !== 'OPEN' ||
    endpointRecord.m3CellTransfer !== null ||
    endpointRecord.m3CellTransfers !== null ||
    !binding ||
    binding.authority !== authority ||
    binding.admission !== admission ||
    binding.generation !== state.operation.generation ||
    binding.deadline !== state.monotonicDeadline ||
    !topology ||
    !same(topology.peerIdentity32, record.identity) ||
    topology.peerAddress.host !== record.host ||
    topology.peerAddress.port !== record.port ||
    !same(link.peerIdentity, record.identity)
  )
    throw PrivateRouteError.UNAUTHORIZED()
  try {
    establishedLink[LINK_BOOTSTRAP_CONSUME_OWNERSHIP](binding.ownership)
  } catch {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  endpointRecord.sharedGuard = true
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
  const originalOwner = state.endpoint
  const freshOwnerTemplate = endpointState.freshOwnerTemplate
  const secret = state.secret
  state.endpoint = null
  state.secret = null
  const material = Object.freeze({})
  const materialState = {
    establishedLink,
    endpoint: null,
    originalOwner,
    originalOwnerClose: null,
    freshOwnerTemplate,
    secret,
    identity,
    host: record.host,
    port: record.port,
    expiresAt: binding.expiresAt,
    reconnectIssued: false,
    reconnectTransport: null,
    reconnectOwner: null,
    reconnectTransportFactory() {
      if (arguments.length !== 0) invalid()
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
  void closeOriginalGuardOwner(state).catch(() => {})
  if (state.reconnectOwner) void state.reconnectOwner.close().catch(() => {})
  state.reconnectTransport = null
  state.reconnectOwner = null
  state.freshOwnerTemplate = null
  state.originalOwner = null
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

function createTestBootstrapResponderLinkHandle(options) {
  if (
    !isObject(options) ||
    !fixed(options.localIdentity32, 32) ||
    !fixed(options.peerIdentity32, 32) ||
    !isObject(options.localAddress) ||
    !isObject(options.peerAddress) ||
    !numericHost(options.localAddress.host) ||
    !Number.isSafeInteger(options.localAddress.port) ||
    !numericHost(options.peerAddress.host) ||
    !Number.isSafeInteger(options.peerAddress.port) ||
    typeof options.epoch !== 'bigint' ||
    typeof options.expiresAt !== 'bigint' ||
    typeof options.now !== 'function'
  )
    invalid()
  const handle = Object.freeze({})
  BOOTSTRAP_LINK_HANDLES.set(handle, {
    live: true,
    now: options.now,
    expiresAt: options.expiresAt,
    digest32: b4a.alloc(32),
    localIdentity32: b4a.from(options.localIdentity32),
    localRole: roleForIdentity(options.localIdentity32),
    localAddress: {
      family: options.localAddress.host.includes(':') ? 6 : 4,
      host: options.localAddress.host,
      port: options.localAddress.port
    },
    peerIdentity32: b4a.from(options.peerIdentity32),
    peerRole: roleForIdentity(options.peerIdentity32),
    peerAddress: {
      family: options.peerAddress.host.includes(':') ? 6 : 4,
      host: options.peerAddress.host,
      port: options.peerAddress.port
    },
    epoch: options.epoch,
    runId32: b4a.alloc(32),
    operations: LINK_OPERATION.ACCEPT
  })
  return handle
}

function createTestBootstrapUdxLinkReservation(authority, admission, open) {
  const state = isObject(authority) ? BOOTSTRAP_UDX_AUTHORITIES.get(authority) : null
  const admitted = isObject(admission) ? BOOTSTRAP_UDX_ADMISSIONS.get(admission) : null
  if (
    !state ||
    state.kind !== 'test' ||
    !state.live ||
    state.pinned ||
    !state.operation ||
    !admitted ||
    admitted.state !== state ||
    typeof open !== 'function'
  )
    throw PrivateRouteError.UNAUTHORIZED()
  const reservation = Object.freeze({})
  TEST_BOOTSTRAP_LINK_RESERVATIONS.set(reservation, {
    state,
    admission: admitted,
    open,
    used: false
  })
  return reservation
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
  const freshAdapterFactory = record.fakeFactory
  let adapter
  try {
    adapter = freshAdapterFactory()
  } catch {
    throw unavailable()
  } finally {
    record.fakeFactory = null
  }
  if (!adapter || typeof adapter.create !== 'function') throw unavailable()
  return new UdxCellEndpoint(options, {
    token: TEST_CONSTRUCTION,
    adapter,
    freshAdapterFactory
  })
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

function sendBootstrapWithOptionsForTest(endpoint, session, packet, options) {
  const state = isObject(endpoint) ? ENDPOINTS.get(endpoint) : null
  if (!state || state.closing) return Promise.reject(PrivateRouteError.UNAUTHORIZED())
  for (const record of state.records) {
    if (record.session === session && validateRecord(state, record)) {
      return endpoint.send(record.handle, packet, options)
    }
  }
  return Promise.reject(PrivateRouteError.UNAUTHORIZED())
}

function sendEstablishedForTest(endpoint, established, value) {
  const record = isObject(established) ? ESTABLISHED_SEND_HANDLES.get(established) : null
  if (!record || record.endpoint !== endpoint)
    return Promise.reject(PrivateRouteError.UNAUTHORIZED())
  return endpoint[UDX_SEND_CELL](record.handle, value)
}

function createM3CellLinkTransferIssuer(endpoint, established, options = undefined) {
  const state = isObject(endpoint) ? ENDPOINTS.get(endpoint) : null
  const record = isObject(established) ? ESTABLISHED_SEND_HANDLES.get(established) : null
  const sharedGuard =
    options === undefined
      ? false
      : isObject(options) && options.sharedGuard === true && Object.keys(options).length === 1
  if (options !== undefined && !sharedGuard) invalid()
  const sharedCount = record && record.m3CellTransfers ? record.m3CellTransfers.size : 0
  if (
    !state ||
    state.closing ||
    !record ||
    record.endpoint !== endpoint ||
    record.phase !== 'OPEN' ||
    !validateRecord(state, record) ||
    (!sharedGuard && (record.m3CellTransfer !== null || record.m3CellTransfers !== null)) ||
    (sharedGuard &&
      (!record.sharedGuard ||
        record.m3CellTransfer !== null ||
        sharedCount >= MAX_SHARED_GUARD_M3_CELL_LINK_TRANSFERS))
  ) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  const issuer = Object.freeze({
    destroy() {
      const current = M3_CELL_LINK_TRANSFER_ISSUERS.get(issuer)
      return destroyM3CellLinkTransferState(current)
    }
  })
  const issuerState = {
    issuer,
    endpoint,
    endpointState: state,
    record,
    established,
    active: true,
    sharedGuard
  }
  if (sharedGuard) {
    if (!record.m3CellTransfers) record.m3CellTransfers = new Set()
    record.m3CellTransfers.add(issuerState)
  } else {
    record.m3CellTransfer = issuerState
  }
  M3_CELL_LINK_TRANSFER_ISSUERS.set(issuer, issuerState)
  return issuer
}

function destroyExtensionSetupTransport(transport, err, closeLink) {
  const state = isObject(transport) ? EXTENSION_SETUP_TRANSPORTS.get(transport) : null
  if (!state || !state.active) return false
  state.active = false
  EXTENSION_SETUP_TRANSPORTS.delete(transport)
  if (state.record && state.record.extensionSetupTransport === transport) {
    state.record.extensionSetupTransport = null
  }
  const reason = err || PrivateRouteError.ERR_DESTROYED()
  for (const waiter of state.waiters.splice(0)) waiter.reject(reason)
  for (const packet of state.received.splice(0)) clear(packet)
  if (closeLink && state.endpointState && state.record) {
    invalidateRecord(state.endpointState, state.record)
  }
  state.endpointState = null
  state.record = null
  return true
}

function createExtensionSetupTransport(established) {
  const record = isObject(established) ? ESTABLISHED_SEND_HANDLES.get(established) : null
  const endpointState = record && record.endpoint ? ENDPOINTS.get(record.endpoint) : null
  if (
    !record ||
    !endpointState ||
    endpointState.closing ||
    record.phase !== 'OPEN' ||
    record.extensionSetupTransport ||
    record.m3CellTransfer !== null ||
    record.m3CellTransfers !== null ||
    !validateRecord(endpointState, record)
  ) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  const transport = Object.freeze({
    send(payload) {
      const state = EXTENSION_SETUP_TRANSPORTS.get(transport)
      if (
        !state ||
        !state.active ||
        !b4a.isBuffer(payload) ||
        payload.byteLength < 1 ||
        payload.byteLength > MAX_STREAM_PAYLOAD
      ) {
        return Promise.reject(PrivateRouteError.UNAUTHORIZED())
      }
      let reserved
      try {
        reserved = trySendEstablishedCell(state.record.endpoint, state.record.handle, {
          class: CELL_CLASS.STREAM,
          direction: state.record.heartbeatDirection,
          generation: 1n,
          payload
        })
      } catch (err) {
        destroyExtensionSetupTransport(transport, err, true)
        return Promise.reject(err)
      }
      if (!reserved) {
        const err = PrivateRouteError.ERR_BUSY()
        destroyExtensionSetupTransport(transport, err, true)
        return Promise.reject(err)
      }
      return reserved.sending.catch((err) => {
        destroyExtensionSetupTransport(transport, err, true)
        throw err
      })
    },
    receive() {
      const state = EXTENSION_SETUP_TRANSPORTS.get(transport)
      if (!state || !state.active) return Promise.reject(PrivateRouteError.ERR_DESTROYED())
      const packet = state.received.shift()
      if (packet) return Promise.resolve(packet)
      return new Promise((resolve, reject) => state.waiters.push({ resolve, reject }))
    },
    takePhysicalChannel() {
      const state = EXTENSION_SETUP_TRANSPORTS.get(transport)
      if (!state || !state.active || state.physicalChannel !== null) {
        throw PrivateRouteError.UNAUTHORIZED()
      }
      state.physicalChannel = createM3CellLinkTransferIssuer(state.record.endpoint, established)
      return state.physicalChannel
    },
    finish() {
      const state = EXTENSION_SETUP_TRANSPORTS.get(transport)
      if (
        !state ||
        !state.active ||
        state.physicalChannel === null ||
        state.waiters.length !== 0 ||
        state.received.length !== 0
      ) {
        throw PrivateRouteError.UNAUTHORIZED()
      }
      state.active = false
      EXTENSION_SETUP_TRANSPORTS.delete(transport)
      state.record.extensionSetupTransport = null
      state.endpointState = null
      state.record = null
      state.physicalChannel = null
      return true
    },
    destroy() {
      return destroyExtensionSetupTransport(transport, PrivateRouteError.ERR_DESTROYED(), true)
    }
  })
  EXTENSION_SETUP_TRANSPORTS.set(transport, {
    active: true,
    endpointState,
    received: [],
    physicalChannel: null,
    record,
    waiters: []
  })
  record.extensionSetupTransport = transport
  return transport
}

function createM3CellLinkTransferIssuerFromEstablished(established) {
  if (!isObject(established)) throw PrivateRouteError.UNAUTHORIZED()
  if (M3_CELL_LINK_TRANSFER_ISSUERS.has(established)) return established
  const record = ESTABLISHED_SEND_HANDLES.get(established)
  if (!record || !record.endpoint) throw PrivateRouteError.UNAUTHORIZED()
  return createM3CellLinkTransferIssuer(record.endpoint, established)
}

function registerM3CellLinkTransfer(issuer, authenticatedBinding) {
  const issuerState = isObject(issuer) ? M3_CELL_LINK_TRANSFER_ISSUERS.get(issuer) : null
  if (!issuerState) return null
  if (!issuerState.active) invalid()
  const { endpoint, endpointState, record, established } = issuerState
  if (
    !endpoint ||
    !endpointState ||
    endpointState.closing ||
    !record ||
    record.endpoint !== endpoint ||
    (record.m3CellTransfer !== issuerState &&
      (!record.m3CellTransfers || !record.m3CellTransfers.has(issuerState))) ||
    !validateRecord(endpointState, record)
  ) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  let binding = null
  try {
    const { takeM3AuthenticatedBranchBinding } = require('./guard-link')
    binding = takeM3AuthenticatedBranchBinding(authenticatedBinding, issuer)
  } catch (err) {
    destroyM3CellLinkTransferState(issuerState)
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
  const {
    receiveEpoch,
    receiveCircuitId,
    receiveDirection,
    sendEpoch,
    sendCircuitId,
    sendDirection
  } = binding
  if (
    binding.issuer !== issuer ||
    typeof receiveEpoch !== 'bigint' ||
    typeof sendEpoch !== 'bigint' ||
    !b4a.isBuffer(receiveCircuitId) ||
    bufferByteLength.call(receiveCircuitId) !== 16 ||
    !b4a.isBuffer(sendCircuitId) ||
    bufferByteLength.call(sendCircuitId) !== 16 ||
    (receiveDirection !== DIRECTION.FORWARD && receiveDirection !== DIRECTION.REVERSE) ||
    (sendDirection !== DIRECTION.FORWARD && sendDirection !== DIRECTION.REVERSE)
  ) {
    destroyM3CellLinkTransferState(issuerState)
    clearM3CellLinkBinding(binding)
    invalid()
  }
  issuerState.active = false
  M3_CELL_LINK_TRANSFER_ISSUERS.delete(issuer)
  const transfer = Object.freeze({
    send(packet) {
      const current = M3_CELL_LINK_TRANSFERS.get(transfer)
      if (
        !current ||
        !current.active ||
        !current.binding ||
        current.endpointState.closing ||
        !validateRecord(current.endpointState, current.record) ||
        !b4a.isBuffer(packet) ||
        bufferByteLength.call(packet) !== BOOTSTRAP_SIZE ||
        packet[0] !== PROTOCOL_VERSION ||
        (packet[1] !== CELL_CLASS.CONTROL && packet[1] !== CELL_CLASS.DATAGRAM) ||
        packet[2] !== current.binding.sendDirection ||
        readUint64BE(packet, 4) !== current.binding.sendEpoch ||
        !b4a.equals(bufferSubarray.call(packet, 12, 28), current.binding.sendCircuitId)
      ) {
        return Promise.reject(PrivateRouteError.UNAUTHORIZED())
      }
      return current.endpoint.send(current.record.handle, packet)
    },
    receive() {
      const current = M3_CELL_LINK_TRANSFERS.get(transfer)
      if (
        !current ||
        !current.active ||
        current.endpointState.closing ||
        !validateRecord(current.endpointState, current.record)
      ) {
        return Promise.reject(PrivateRouteError.UNAUTHORIZED())
      }
      const owned = current.queue.shift()
      if (owned) return Promise.resolve(owned.packet)
      const pending = new Promise((resolve, reject) => current.waiters.push({ resolve, reject }))
      void pending.catch(() => {})
      return pending
    },
    destroy() {
      const current = M3_CELL_LINK_TRANSFERS.get(transfer)
      return destroyM3CellLinkTransferState(current)
    }
  })
  let transferState = null
  try {
    const transferBinding = Object.freeze({
      receiveEpoch,
      receiveCircuitId: b4a.from(receiveCircuitId),
      receiveDirection,
      sendEpoch,
      sendCircuitId: b4a.from(sendCircuitId),
      sendDirection
    })
    transferState = {
      transfer,
      endpoint,
      endpointState,
      record,
      established,
      queue: [],
      waiters: [],
      binding: transferBinding,
      active: true,
      sharedGuard: issuerState.sharedGuard,
      physicalLossRegistration: null
    }
    if (record.m3CellTransfer === issuerState) record.m3CellTransfer = transferState
    else if (record.m3CellTransfers) {
      record.m3CellTransfers.delete(issuerState)
      record.m3CellTransfers.add(transferState)
    }
    issuerState.endpoint = null
    issuerState.endpointState = null
    issuerState.record = null
    issuerState.established = null
    M3_CELL_LINK_TRANSFERS.set(transfer, transferState)
  } catch (err) {
    issuerState.active = false
    issuerState.endpoint = null
    issuerState.endpointState = null
    issuerState.record = null
    issuerState.established = null
    if (record.m3CellTransfer === issuerState) record.m3CellTransfer = null
    else if (record.m3CellTransfers) {
      record.m3CellTransfers.delete(issuerState)
      if (record.m3CellTransfers.size === 0) record.m3CellTransfers = null
    }
    clearM3CellLinkBinding(transferState && transferState.binding)
    clearM3CellLinkBinding(binding)
    throw err
  }
  clear(receiveCircuitId)
  clear(sendCircuitId)
  return transfer
}

function registerM3CellLinkPhysicalLossSink(transfer, sink) {
  const state = isObject(transfer) ? M3_CELL_LINK_TRANSFERS.get(transfer) : null
  if (!state || !state.active || state.physicalLossRegistration || typeof sink !== 'function') {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  const registration = Object.freeze({})
  const record = { registration, state, sink }
  state.physicalLossRegistration = record
  M3_CELL_LINK_PHYSICAL_LOSS_REGISTRATIONS.set(registration, record)
  return registration
}

function revokeM3CellLinkPhysicalLossSink(registration) {
  const record = isObject(registration)
    ? M3_CELL_LINK_PHYSICAL_LOSS_REGISTRATIONS.get(registration)
    : null
  if (!record) return false
  M3_CELL_LINK_PHYSICAL_LOSS_REGISTRATIONS.delete(registration)
  if (record.state.physicalLossRegistration === record) {
    record.state.physicalLossRegistration = null
  }
  record.state = null
  record.sink = null
  return true
}

function releaseM3CellLinkPacket(packet) {
  const owned = M3_CELL_LINK_PACKET_OWNERS.get(packet)
  if (!owned) return false
  M3_CELL_LINK_PACKET_OWNERS.delete(packet)
  owned.settle()
  return true
}

function takeGuardLeaseMaterial(material) {
  const state = isObject(material) ? GUARD_LEASE_MATERIALS.get(material) : null
  if (!state) throw PrivateRouteError.UNAUTHORIZED()
  GUARD_LEASE_MATERIALS.delete(material)
  return state
}

function destroyTakenGuardLeaseMaterial(state) {
  if (!isObject(state)) return false
  clear(state.identity)
  if (state.reconnectTransport) state.reconnectTransport.active = false
  void closeOriginalGuardOwner(state).catch(() => {})
  if (state.reconnectOwner) void state.reconnectOwner.close().catch(() => {})
  state.reconnectTransport = null
  state.reconnectOwner = null
  state.freshOwnerTemplate = null
  state.originalOwner = null
  clearSecretRecord(state.secret)
  state.secret = null
  if (state.endpoint) void state.endpoint.close().catch(() => {})
  state.endpoint = null
  state.establishedLink = null
  state.reconnectTransportFactory = null
  return true
}

function registerSharedGuardBranchResponder(established, responder) {
  const record = ESTABLISHED_SEND_HANDLES.get(established)
  if (
    !record ||
    !record.endpoint ||
    record.guardBranchResponder ||
    !isObject(responder) ||
    typeof responder.accept !== 'function'
  ) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  record.sharedGuard = true
  record.guardBranchResponder = responder
  return true
}

function exchangeSharedGuardBranch(established, options) {
  const record = ESTABLISHED_SEND_HANDLES.get(established)
  if (
    !record ||
    !record.endpoint ||
    record.sharedGuard !== true ||
    record.guardBranchPending ||
    !isObject(options) ||
    !b4a.isBuffer(options.offer) ||
    typeof options.generation !== 'bigint' ||
    typeof options.absoluteDeadline !== 'bigint' ||
    typeof options.now !== 'function' ||
    typeof options.schedule !== 'function' ||
    typeof options.cancel !== 'function'
  ) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  const now = BigInt(options.now())
  if (now >= options.absoluteDeadline) throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  let timer = null
  let resolvePending = null
  let rejectPending = null
  const response = new Promise((resolve, reject) => {
    resolvePending = resolve
    rejectPending = reject
  })
  const pending = {
    generation: options.generation,
    resolve(value) {
      options.cancel(timer)
      resolvePending(value)
    },
    reject(err) {
      options.cancel(timer)
      rejectPending(err)
    }
  }
  record.guardBranchPending = pending
  try {
    timer = options.schedule(
      () => {
        if (record.guardBranchPending !== pending) return
        record.guardBranchPending = null
        pending.reject(PrivateRouteError.ERR_PRIVACY_UNAVAILABLE())
      },
      Number(options.absoluteDeadline - now)
    )
    const sending = sendGuardBranchDatagram(record, options.generation, options.offer)
    Promise.resolve(sending).catch((err) => {
      if (record.guardBranchPending !== pending) return
      record.guardBranchPending = null
      pending.reject(err)
    })
  } catch (err) {
    record.guardBranchPending = null
    pending.reject(err)
  }
  return response
}

function registerSharedGuardLossRegistration(established, registration) {
  const record = ESTABLISHED_SEND_HANDLES.get(established)
  if (
    !record ||
    !record.endpoint ||
    record.sharedGuard !== true ||
    record.guardLossRegistration ||
    !isObject(registration) ||
    !Object.isFrozen(registration) ||
    Reflect.ownKeys(registration).length !== 0
  ) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  record.guardLossRegistration = registration
  return true
}

function unregisterSharedGuardLossRegistration(established, registration) {
  const record = ESTABLISHED_SEND_HANDLES.get(established)
  if (!record || record.guardLossRegistration !== registration) return false
  record.guardLossRegistration = null
  return true
}

function createSharedGuardM3CellLinkTransferIssuer(established) {
  const record = ESTABLISHED_SEND_HANDLES.get(established)
  if (!record || !record.endpoint || record.sharedGuard !== true) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  return createM3CellLinkTransferIssuer(record.endpoint, established, { sharedGuard: true })
}

function destroySharedGuardM3CellLinkTransfers(established) {
  const record = ESTABLISHED_SEND_HANDLES.get(established)
  if (!record || record.sharedGuard !== true) return false
  const hadSingle = !!record.m3CellTransfer
  const hadShared = !!(record.m3CellTransfers && record.m3CellTransfers.size)
  destroyRecordM3CellTransfers(record)
  return hadSingle || hadShared
}

function readSharedGuardM3CellLinkTransferCount(established) {
  const record = ESTABLISHED_SEND_HANDLES.get(established)
  if (!record || record.sharedGuard !== true) throw PrivateRouteError.UNAUTHORIZED()
  return (
    (record.m3CellTransfer ? 1 : 0) + (record.m3CellTransfers ? record.m3CellTransfers.size : 0)
  )
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
  sendBootstrapWithOptionsForTest,
  sendEstablishedForTest,
  inspectGuardLeaseMaterial,
  canonicalDirectRecord,
  createTestBootstrapUdxAuthority,
  createTestBootstrapResponderLinkHandle,
  observeReceives(observer) {
    if (typeof observer !== 'function' || TEST_RECEIVE_OBSERVER !== null) invalid()
    TEST_RECEIVE_OBSERVER = observer
    return function revokeReceiveObserver() {
      if (TEST_RECEIVE_OBSERVER !== observer) return false
      TEST_RECEIVE_OBSERVER = null
      return true
    }
  },
  createTestBootstrapUdxLinkReservation
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
  createM3CellLinkTransferIssuer,
  createExtensionSetupTransport,
  createM3CellLinkTransferIssuerFromEstablished,
  registerM3CellLinkTransfer,
  registerM3CellLinkPhysicalLossSink,
  revokeM3CellLinkPhysicalLossSink,
  releaseM3CellLinkPacket,
  [TEST_ONLY_UDX_ADAPTER_ISSUER]: testOnlyAdapterIssuer,
  createLocalIdentitySecretCapability,
  createBootstrapUdxAuthority,
  bindBootstrapUdxOperation,
  isBootstrapUdxAuthority,
  destroyLocalIdentitySecretCapability,
  admitBootstrapUdxGuard,
  sendConfigured,
  sendProspectiveGuard,
  requestConfigured,
  requestProspectiveGuard,
  openBootstrapUdxGuard,
  createBootstrapUdxGuardSessionOptions,
  pinBootstrapUdxGuard,
  readBootstrapLinkHandle,
  destroyBootstrapUdxAuthority,
  destroyGuardLeaseMaterial,
  takeGuardLeaseMaterial,
  [RECONNECTED_GUARD_PIN_CONSUMER]: consumeReconnectedGuardPin,
  [BOOTSTRAP_ACCEPT_HANDLE_FACTORY]: createBootstrapAcceptLinkHandle,
  [BOOTSTRAP_ACCEPT_HANDLE_CLAIMER]: claimBootstrapAcceptLinkHandle,
  destroyTakenGuardLeaseMaterial,
  destroySharedGuardM3CellLinkTransfers,
  readSharedGuardM3CellLinkTransferCount,
  createSharedGuardM3CellLinkTransferIssuer,
  registerSharedGuardLossRegistration,
  registerSharedGuardBranchResponder,
  exchangeSharedGuardBranch,
  unregisterSharedGuardLossRegistration,
  isGuardLeaseMaterial
}
