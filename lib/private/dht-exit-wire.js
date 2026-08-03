'use strict'

// DHT-RPC client packet subset adapted from dht-rpc
// fe04496196ea2ce42d1de27b0f770b02d2a87cd5 (MIT):
// Request._encodeRequest, decodeReply, validateId, and lib/peer.js IPv4 codec.

const c = require('compact-encoding')
const b4a = require('b4a')
const sodium = require('sodium-universal')

const { PrivateRouteError } = require('./errors')

const VERSION = 0b11
const RESPONSE_ID = (0b0001 << 4) | VERSION
const REQUEST_ID = (0b0000 << 4) | VERSION
const PING = 0
const IMMUTABLE_GET = 9
const RESPONSE_FLAGS = 1 | 2 | 4 | 8 | 16
const MESSAGE_FIELDS = Object.freeze(['tid', 'token', 'internal', 'command', 'target', 'value'])
const IMMUTABLE_RESPONSE_FIELDS = Object.freeze(['valuePresent', 'value'])
const MAX_IMMUTABLE_VALUE_BYTES = 1023
const RESERVATIONS = new WeakMap()
const TEST_ONLY_DHT_EXIT_WIRE_RESERVATION = Symbol.for(
  'hyperdht-private-routes/test-only-dht-exit-wire-reservation'
)

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
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

function exactTuple(value) {
  if (!isObject(value) || Reflect.ownKeys(value).length !== 2) invalid()
  const host = value.host
  const port = value.port
  if (typeof host !== 'string' || !Number.isSafeInteger(port) || port < 0 || port > 65535) {
    invalid()
  }
  if (!/^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$/.test(host)) invalid()
  for (const part of host.split('.')) {
    if (Number(part) > 255) invalid()
  }
  return Object.freeze({ host, port })
}

function sameTuple(left, right) {
  return left.host === right.host && left.port === right.port
}

function copy(value, size) {
  if (!b4a.isBuffer(value) || (size !== undefined && value.byteLength !== size)) invalid()
  return b4a.from(value)
}

function nullableFixed32(value) {
  if (value === null) return null
  return copy(value, 32)
}

function tid(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) invalid()
  return value
}

function readReservation(reservation) {
  const state = isObject(reservation) ? RESERVATIONS.get(reservation) : null
  if (!state) throw PrivateRouteError.UNAUTHORIZED()
  return state
}

const ipv4 = {
  ...c.ipv4Address,
  decode(state) {
    const ip = c.ipv4Address.decode(state)
    return Object.freeze({ id: null, host: ip.host, port: ip.port })
  }
}
const ipv4Array = c.array(ipv4)

function peerId(host, port, out = b4a.allocUnsafeSlow(32)) {
  const addr = out.subarray(0, 6)
  ipv4.encode({ start: 0, end: 6, buffer: addr }, { host, port })
  sodium.crypto_generichash(out, addr)
  return out
}

function encodedSize(encode) {
  const state = { start: 0, end: 0, buffer: null }
  encode.preencode(state)
  return state.end
}

function writeUint(state, value) {
  c.uint.encode(state, value)
}

function validateMessage(message, expectedTid) {
  exactOwnData(message, MESSAGE_FIELDS)
  const id = tid(message.tid)
  if (expectedTid !== null && id !== expectedTid) invalid()
  const token = nullableFixed32(message.token)
  const target = nullableFixed32(message.target)
  if (message.value !== null) invalid()
  if (message.command === PING) {
    if (message.internal !== true || token !== null || target !== null) invalid()
  } else if (message.command === IMMUTABLE_GET) {
    if (message.internal !== false || target === null) invalid()
  } else {
    invalid()
  }
  return { tid: id, token, internal: message.internal, command: message.command, target }
}

function encodeDhtExitRequest(reservation, message) {
  const reservationState = readReservation(reservation)
  const request = validateMessage(message, reservationState.tid)
  const to = reservationState.remote
  const value = null
  const state = { start: 0, end: 1 + 1 + 6 + 2, buffer: null }

  if (request.token) state.end += 32
  state.end += encodedSize({ preencode: (s) => c.uint.preencode(s, request.command) })
  if (request.target) state.end += 32

  state.buffer = b4a.allocUnsafeSlow(state.end)
  state.buffer[state.start++] = REQUEST_ID
  state.buffer[state.start++] =
    (request.token ? 2 : 0) |
    (request.internal ? 4 : 0) |
    (request.target ? 8 : 0) |
    (value ? 16 : 0)
  c.uint16.encode(state, request.tid)
  ipv4.encode(state, to)
  if (request.token) c.fixed32.encode(state, request.token)
  writeUint(state, request.command)
  if (request.target) c.fixed32.encode(state, request.target)
  return state.buffer
}

function decodeDhtExitReply(reservation, source, packet) {
  const reservationState = readReservation(reservation)
  const from = exactTuple(source)
  if (!sameTuple(from, reservationState.remote)) invalid()
  if (!b4a.isBuffer(packet) || packet.byteLength < 10 || packet[0] !== RESPONSE_ID) invalid()
  const state = { start: 1, end: packet.byteLength, buffer: packet }
  let decoded
  try {
    const flags = c.uint.decode(state)
    if ((flags & ~RESPONSE_FLAGS) !== 0) invalid()
    const decodedTid = c.uint16.decode(state)
    if (decodedTid !== reservationState.tid) invalid()
    const to = ipv4.decode(state)
    if (!sameTuple(to, reservationState.local)) invalid()
    const id = flags & 1 ? c.fixed32.decode(state) : null
    const token = flags & 2 ? c.fixed32.decode(state) : null
    const closerNodes = flags & 4 ? ipv4Array.decode(state) : null
    const error = flags & 8 ? c.uint.decode(state) : 0
    const value = flags & 16 ? c.buffer.decode(state) : null
    if (value !== null && value.byteLength > MAX_IMMUTABLE_VALUE_BYTES) invalid()
    if (id !== null && !b4a.equals(peerId(from.host, from.port), id)) invalid()
    if (state.start !== state.end) invalid()
    decoded = {
      tid: decodedTid,
      from,
      to: Object.freeze({ host: to.host, port: to.port }),
      token: token === null ? null : b4a.from(token),
      closerNodes: Object.freeze(
        (closerNodes || []).map((node) =>
          Object.freeze({ id: null, host: node.host, port: node.port })
        )
      ),
      error,
      valuePresent: value !== null,
      value: value === null ? null : b4a.from(value)
    }
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
  return Object.freeze(decoded)
}
function encodeImmutableGetResponse(response) {
  exactOwnData(response, IMMUTABLE_RESPONSE_FIELDS)
  if (response.valuePresent === false) {
    if (response.value !== null) invalid()
    return b4a.alloc(0)
  }
  if (
    response.valuePresent !== true ||
    !b4a.isBuffer(response.value) ||
    response.value.byteLength > MAX_IMMUTABLE_VALUE_BYTES
  ) {
    invalid()
  }
  const state = { start: 0, end: 0, buffer: null }
  c.buffer.preencode(state, response.value)
  state.buffer = b4a.allocUnsafeSlow(state.end)
  c.buffer.encode(state, response.value)
  return state.buffer
}

function decodeImmutableGetResponse(encoded) {
  if (!b4a.isBuffer(encoded)) invalid()
  if (encoded.byteLength === 0) return Object.freeze({ valuePresent: false, value: null })
  const state = { start: 0, end: encoded.byteLength, buffer: encoded }
  try {
    const decoded = c.buffer.decode(state)
    if (state.start !== state.end || decoded.byteLength > MAX_IMMUTABLE_VALUE_BYTES) invalid()
    return Object.freeze({ valuePresent: true, value: b4a.from(decoded) })
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function createDhtExitWireReservation(options) {
  if (!isObject(options)) invalid()
  const remote = exactTuple(options.remote)
  const local = exactTuple(options.local)
  const reservation = Object.freeze({})
  RESERVATIONS.set(reservation, {
    remote,
    local,
    tid: options.tid === null || options.tid === undefined ? null : tid(options.tid)
  })
  return reservation
}

module.exports = {
  TEST_ONLY_DHT_EXIT_WIRE_RESERVATION: Object.freeze({ create: createDhtExitWireReservation }),
  createDhtExitWireReservation,
  decodeDhtExitReply,
  decodeImmutableGetResponse,
  encodeDhtExitRequest,
  encodeImmutableGetResponse
}
