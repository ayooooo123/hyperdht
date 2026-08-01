'use strict'

const b4a = require('b4a')
const sodium = require('sodium-universal')

const { PrivateRouteError } = require('./errors')
const { BRANCH_CLASS } = require('./protocol')
const { createDhtExitWireReservation } = require('./dht-exit-wire')

const OPEN_AUTHORITIES = new WeakMap()
const SPENT_OPEN_AUTHORITIES = new WeakSet()
const CHANNELS_BY_TABLE = new WeakMap()
const CHANNELS_BY_IO = new WeakMap()
const TABLE_STATES = new WeakMap()
const IO_STATES = new WeakMap()
const PACKET_RESERVATIONS = new WeakMap()
const SPENT_PACKET_RESERVATIONS = new WeakSet()
const PACKET_TRANSFERS = new WeakMap()
const SPENT_PACKET_TRANSFERS = new WeakSet()
const CORRELATED_REPLIES = new WeakMap()
const SPENT_CORRELATED_REPLIES = new WeakSet()
const DHT_EXIT_ROUTES = new WeakSet()
const DESTROYED_DHT_EXIT_ROUTES = new WeakSet()
const TEST_ONLY_DHT_EXIT_OPEN_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-dht-exit-open-issuer'
)
const OPEN_FIELDS = Object.freeze([
  'branchClass',
  'branchId',
  'circuitId',
  'generation',
  'exitIdentity',
  'finalTranscriptDigest',
  'expiresAt',
  'absoluteDeadline',
  'controlKey',
  'controlNoncePrefix'
])
const ROUTE_FIELDS = Object.freeze([
  'transport',
  'payloadDigest',
  'payloadForwardKey',
  'payloadReverseKey',
  'payloadForwardNoncePrefix',
  'payloadReverseNoncePrefix'
])
const PACKET_FIELDS = Object.freeze([
  'remote',
  'local',
  'token',
  'internal',
  'command',
  'target',
  'value',
  'deadline',
  'auditClass'
])

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function replay() {
  throw PrivateRouteError.ERR_REPLAY()
}

function authentication() {
  throw PrivateRouteError.ERR_AUTHENTICATION()
}

function destroyed() {
  throw PrivateRouteError.ERR_DESTROYED()
}
function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function exactOwnData(value, fields) {
  if (!isObject(value) || Reflect.ownKeys(value).length !== fields.length) invalid()
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field)
    if (!descriptor || !('value' in descriptor)) invalid()
  }
}

function fixed(value, size) {
  if (!b4a.isBuffer(value) || value.byteLength !== size) invalid()
  return b4a.from(value)
}

function tuple(value) {
  exactOwnData(value, ['host', 'port'])
  const { host, port } = value
  if (typeof host !== 'string' || !Number.isSafeInteger(port) || port < 0 || port > 65535) {
    invalid()
  }
  return Object.freeze({ host, port })
}

function closerNode(value) {
  exactOwnData(value, ['id', 'host', 'port'])
  if (value.id !== null) invalid()
  const parsed = tuple({ host: value.host, port: value.port })
  return Object.freeze({ id: null, host: parsed.host, port: parsed.port })
}

function uint64(value) {
  if (typeof value !== 'bigint' || value < 0n || value > 0xffff_ffff_ffff_ffffn) invalid()
  return value
}

function uint16(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) invalid()
  return value
}

function branchClass(value) {
  if (value !== BRANCH_CLASS.LOOKUP && value !== BRANCH_CLASS.ANNOUNCE) invalid()
  return value
}

function openMaterial(value) {
  exactOwnData(value, OPEN_FIELDS)
  return Object.freeze({
    branchClass: branchClass(value.branchClass),
    branchId: fixed(value.branchId, 16),
    circuitId: fixed(value.circuitId, 16),
    generation: uint64(value.generation),
    exitIdentity: fixed(value.exitIdentity, 32),
    finalTranscriptDigest: fixed(value.finalTranscriptDigest, 32),
    expiresAt: uint64(value.expiresAt),
    absoluteDeadline: uint64(value.absoluteDeadline),
    controlKey: fixed(value.controlKey, 32),
    controlNoncePrefix: fixed(value.controlNoncePrefix, 16)
  })
}

function routeMaterial(value) {
  if (value === null) return null
  exactOwnData(value, ROUTE_FIELDS)
  if (!isObject(value.transport)) invalid()
  const route = {
    transport: value.transport,
    payloadDigest: fixed(value.payloadDigest, 32),
    payloadForwardKey: fixed(value.payloadForwardKey, 32),
    payloadReverseKey: fixed(value.payloadReverseKey, 32),
    payloadForwardNoncePrefix: fixed(value.payloadForwardNoncePrefix, 16),
    payloadReverseNoncePrefix: fixed(value.payloadReverseNoncePrefix, 16)
  }
  DHT_EXIT_ROUTES.add(route)
  return route
}

function copyNullable32(value) {
  return value === null ? null : fixed(value, 32)
}

function copyNullableBuffer(value) {
  return value === null ? null : b4a.from(value)
}

function digestReply(reply) {
  const chunks = [b4a.alloc(2), b4a.alloc(2), b4a.alloc(2)]
  chunks[0][0] = reply.tid >>> 8
  chunks[0][1] = reply.tid
  chunks[1][0] = reply.error >>> 8
  chunks[1][1] = reply.error
  chunks[2][0] = reply.valuePresent ? 1 : 0
  chunks.push(reply.token || b4a.alloc(0))
  chunks.push(reply.value || b4a.alloc(0))
  const input = b4a.concat(chunks)
  const out = b4a.allocUnsafeSlow(32)
  sodium.crypto_generichash(out, input)
  input.fill(0)
  return out
}

function createDhtExitOpenAuthority(material, route = null) {
  const authority = Object.freeze({})
  OPEN_AUTHORITIES.set(authority, {
    material: openMaterial(material),
    route: routeMaterial(route),
    spent: false
  })
  return authority
}

function destroyDhtExitOpenAuthority(authority) {
  const state = isObject(authority) ? OPEN_AUTHORITIES.get(authority) : null
  if (!state) return false
  OPEN_AUTHORITIES.delete(authority)
  SPENT_OPEN_AUTHORITIES.add(authority)
  state.spent = true
  destroyDhtExitRouteTransportForIO(state.route)
  state.route = null
  for (const name of [
    'branchId',
    'circuitId',
    'exitIdentity',
    'finalTranscriptDigest',
    'controlKey',
    'controlNoncePrefix'
  ]) {
    state.material[name].fill(0)
  }
  return true
}

function consumeOpenAuthority(authority) {
  const state = isObject(authority) ? OPEN_AUTHORITIES.get(authority) : null
  if (!state) {
    if (isObject(authority) && SPENT_OPEN_AUTHORITIES.has(authority)) replay()
    authentication()
  }
  OPEN_AUTHORITIES.delete(authority)
  SPENT_OPEN_AUTHORITIES.add(authority)
  state.spent = true
  return state
}

function createDhtExitReservationChannel(openAuthority) {
  const claimed = consumeOpenAuthority(openAuthority)
  const tableIssuer = Object.freeze({})
  const ioConsumer = Object.freeze({})
  const channel = {
    tableIssuer,
    ioConsumer,
    material: claimed.material,
    route: claimed.route,
    routeClaimed: false,
    tableInstalled: false,
    ioInstalled: false,
    revoked: false
  }
  CHANNELS_BY_TABLE.set(tableIssuer, channel)
  CHANNELS_BY_IO.set(ioConsumer, channel)
  return Object.freeze({ tableIssuer, ioConsumer })
}

function viewFor(channel) {
  return Object.freeze({
    branchClass: channel.material.branchClass,
    branchId: b4a.from(channel.material.branchId),
    circuitId: b4a.from(channel.material.circuitId),
    generation: channel.material.generation,
    exitIdentity: b4a.from(channel.material.exitIdentity),
    finalTranscriptDigest: b4a.from(channel.material.finalTranscriptDigest),
    expiresAt: channel.material.expiresAt,
    absoluteDeadline: channel.material.absoluteDeadline
  })
}

function consumeDhtExitReservationTableIssuer(tableIssuer) {
  const channel = isObject(tableIssuer) ? CHANNELS_BY_TABLE.get(tableIssuer) : null
  if (!channel) replay()
  if (channel.revoked || channel.tableInstalled) replay()
  CHANNELS_BY_TABLE.delete(tableIssuer)
  channel.tableInstalled = true
  const table = viewFor(channel)
  TABLE_STATES.set(table, channel)
  return table
}

function consumeDhtExitReservationIOConsumer(ioConsumer) {
  const channel = isObject(ioConsumer) ? CHANNELS_BY_IO.get(ioConsumer) : null
  if (!channel) replay()
  if (channel.revoked || channel.ioInstalled) replay()
  CHANNELS_BY_IO.delete(ioConsumer)
  channel.ioInstalled = true
  const io = viewFor(channel)
  IO_STATES.set(io, channel)
  return io
}

function takeDhtExitRouteTransportForIO(io) {
  const channel = isObject(io) ? IO_STATES.get(io) : null
  if (!channel || channel.revoked || !channel.ioInstalled) authentication()
  if (channel.routeClaimed) replay()
  channel.routeClaimed = true
  const route = channel.route
  channel.route = null
  return route
}

function destroyDhtExitRouteTransportForIO(route) {
  if (!isObject(route) || !DHT_EXIT_ROUTES.has(route) || DESTROYED_DHT_EXIT_ROUTES.has(route)) {
    return false
  }
  DHT_EXIT_ROUTES.delete(route)
  DESTROYED_DHT_EXIT_ROUTES.add(route)
  try {
    const { destroyM3RouteTransport } = require('./m3-adjacency-runtime')
    destroyM3RouteTransport(route.transport)
  } catch {}
  route.transport = null
  for (const name of [
    'payloadDigest',
    'payloadForwardKey',
    'payloadReverseKey',
    'payloadForwardNoncePrefix',
    'payloadReverseNoncePrefix'
  ]) {
    route[name].fill(0)
    route[name] = null
  }
  return true
}

function revokeDhtExitReservationChannel(handle) {
  const channel = isObject(handle)
    ? CHANNELS_BY_TABLE.get(handle) || CHANNELS_BY_IO.get(handle)
    : null
  if (!channel || channel.revoked) return false
  channel.revoked = true
  CHANNELS_BY_TABLE.delete(channel.tableIssuer)
  CHANNELS_BY_IO.delete(channel.ioConsumer)
  destroyDhtExitRouteTransportForIO(channel.route)
  channel.route = null
  channel.routeClaimed = true
  return true
}

function createDhtExitPacketReservation(table, options) {
  const channel = isObject(table) ? TABLE_STATES.get(table) : null
  if (!channel || channel.revoked || !channel.tableInstalled) authentication()
  exactOwnData(options, PACKET_FIELDS)
  const deadline = uint64(options.deadline)
  if (deadline > channel.material.absoluteDeadline || deadline > channel.material.expiresAt)
    invalid()
  const message = Object.freeze({
    token: copyNullable32(options.token),
    internal: options.internal,
    command: options.command,
    target: copyNullable32(options.target),
    value: copyNullableBuffer(options.value)
  })
  const reservation = Object.freeze({})
  PACKET_RESERVATIONS.set(reservation, {
    channel,
    remote: tuple(options.remote),
    local: tuple(options.local),
    deadline,
    auditClass: options.auditClass,
    message
  })
  return reservation
}

function consumeDhtExitPacketReservationForIO(io, reservation, allocatedTid) {
  const ioChannel = isObject(io) ? IO_STATES.get(io) : null
  if (!ioChannel || ioChannel.revoked || !ioChannel.ioInstalled) authentication()
  const messageTid = uint16(allocatedTid)
  const state = isObject(reservation) ? PACKET_RESERVATIONS.get(reservation) : null
  if (!state) {
    if (isObject(reservation) && SPENT_PACKET_RESERVATIONS.has(reservation)) replay()
    authentication()
  }
  if (
    isObject(state.auditClass) &&
    isObject(state.auditClass.table) &&
    state.auditClass.table.live === false
  ) {
    PACKET_RESERVATIONS.delete(reservation)
    SPENT_PACKET_RESERVATIONS.add(reservation)
    destroyed()
  }
  if (state.channel !== ioChannel || state.channel.revoked) authentication()
  PACKET_RESERVATIONS.delete(reservation)
  SPENT_PACKET_RESERVATIONS.add(reservation)
  const message = Object.freeze({ tid: messageTid, ...state.message })
  const transfer = Object.freeze({})
  PACKET_TRANSFERS.set(transfer, {
    channel: state.channel,
    wireReservation: createDhtExitWireReservation({
      remote: state.remote,
      local: state.local,
      tid: messageTid
    }),
    remote: state.remote,
    local: state.local,
    message,
    deadline: state.deadline,
    auditClass: state.auditClass
  })
  return transfer
}

function readDhtExitPacketReservationTransferForIO(transfer) {
  const state = isObject(transfer) ? PACKET_TRANSFERS.get(transfer) : null
  if (!state) authentication()
  return state
}

function createDhtExitCorrelatedReplyAuthorityForIO(transfer, source, reply) {
  const transferState = readDhtExitPacketReservationTransferForIO(transfer)
  if (SPENT_PACKET_TRANSFERS.has(transfer)) replay()
  const from = tuple(source)
  if (from.host !== transferState.remote.host || from.port !== transferState.remote.port) invalid()
  if (!isObject(reply) || reply.tid !== transferState.message.tid) invalid()
  const replyFrom = tuple(reply.from)
  const replyTo = tuple(reply.to)
  if (replyFrom.host !== from.host || replyFrom.port !== from.port) invalid()
  if (replyTo.host !== transferState.local.host || replyTo.port !== transferState.local.port)
    invalid()
  if (!Array.isArray(reply.closerNodes)) invalid()
  const replyRecord = Object.freeze({
    tid: reply.tid,
    from,
    to: replyTo,
    token: copyNullable32(reply.token),
    closerNodes: Object.freeze(reply.closerNodes.map(closerNode)),
    error: reply.error,
    valuePresent: reply.valuePresent,
    value: copyNullableBuffer(reply.value)
  })
  const replyDigest = digestReply(replyRecord)
  SPENT_PACKET_TRANSFERS.add(transfer)
  PACKET_TRANSFERS.delete(transfer)
  const authority = Object.freeze({})
  CORRELATED_REPLIES.set(authority, {
    channel: transferState.channel,
    auditClass: transferState.auditClass,
    remote: transferState.remote,
    local: transferState.local,
    message: transferState.message,
    deadline: transferState.deadline,
    reply: replyRecord,
    replyDigest
  })
  return authority
}

function consumeDhtExitCorrelatedReplyAuthority(authority) {
  const state = isObject(authority) ? CORRELATED_REPLIES.get(authority) : null
  if (!state) {
    if (isObject(authority) && SPENT_CORRELATED_REPLIES.has(authority)) replay()
    authentication()
  }
  CORRELATED_REPLIES.delete(authority)
  SPENT_CORRELATED_REPLIES.add(authority)
  return state
}

function encodeDhtExitPacketReservationTransfer(transfer) {
  const { encodeDhtExitRequest } = require('./dht-exit-wire')
  const state = readDhtExitPacketReservationTransferForIO(transfer)
  return encodeDhtExitRequest(state.wireReservation, state.message)
}

module.exports = {
  TEST_ONLY_DHT_EXIT_OPEN_ISSUER: Object.freeze({ create: createDhtExitOpenAuthority }),
  consumeDhtExitCorrelatedReplyAuthority,
  destroyDhtExitRouteTransportForIO,
  consumeDhtExitPacketReservationForIO,
  encodeDhtExitPacketReservationTransfer,
  readDhtExitPacketReservationTransferForIO,
  consumeDhtExitReservationIOConsumer,
  consumeDhtExitReservationTableIssuer,
  createDhtExitCorrelatedReplyAuthorityForIO,
  createDhtExitOpenAuthority,
  destroyDhtExitOpenAuthority,
  createDhtExitPacketReservation,
  takeDhtExitRouteTransportForIO,
  createDhtExitReservationChannel,
  revokeDhtExitReservationChannel
}
