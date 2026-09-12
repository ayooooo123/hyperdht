const b4a = require('b4a')

const { PrivateRouteError } = require('./errors')

const PEER_PROTOCOL_VERSION = 2
const EMPTY_AUTH_SUFFIX = b4a.alloc(0)

const PEER_MESSAGE_ID = Object.freeze({
  PEER_CAPABILITY_ADVERTISEMENT_V2: 0x0300,
  PEER_CAPS_QUERY_V2: 0x0301,
  PEER_CAPS_COOKIE_CHALLENGE_V2: 0x0302,
  PEER_CAPS_RESPONSE_V2: 0x0303,
  PEER_ACTIVE_CHALLENGE_V2: 0x0304,
  PEER_ACTIVE_CHALLENGE_RESPONSE_V2: 0x0305,
  PEER_DISCOVER_REQUEST_V2: 0x0306,
  PEER_DISCOVER_RESPONSE_V2: 0x0307,
  PEER_LINK_OFFER_V2: 0x0308,
  PEER_LINK_ACCEPT_V2: 0x0309,
  PEER_REDACTED_RESPONDER_PROOF_V2: 0x030a,
  PEER_EXTENDED_V2: 0x030b,
  PEER_TAIL_READY_V2: 0x030c,
  PEER_EXTEND_REQUEST_V2: 0x030d,
  PEER_BRANCH_DESTROY_V2: 0x030e,
  PEER_BRANCH_TEARDOWN_V2: 0x030f,
  PEER_BRANCH_TEARDOWN_ACK_V2: 0x0310,
  PEER_ROUTE_OFFER_V2: 0x0311,
  PEER_ROUTE_ACCEPT_V2: 0x0312,
  PEER_ROUTE_REJECT_V2: 0x0313,
  PEER_RELIABLE_PACKET_V2: 0x0314,
  PEER_RELIABLE_ACK_V2: 0x0315,
  PEER_OPEN_V2: 0x0316,
  PEER_OPENED_V2: 0x0317,
  PEER_HANDSHAKE_V2: 0x0318,
  PEER_DATA_V2: 0x0319,
  PEER_CREDIT_V2: 0x031a,
  PEER_FIN_V2: 0x031b,
  PEER_CLOSE_V2: 0x031c,
  PEER_RESET_V2: 0x031d,
  PEER_ROUTE_CLOSE_V2: 0x031e,
  PEER_ROUTE_CLOSE_ACK_V2: 0x031f,
  PEER_DESCRIPTOR_V2: 0x0340,
  LEGACY_RESOLVE_V2: 0x0341,
  LEGACY_RESOLVED_V2: 0x0342,
  LEGACY_RESERVE_V2: 0x0343,
  LEGACY_RESERVED_V2: 0x0344,
  PEER_NOISE_FRAGMENT_V2: 0x0345,
  LEGACY_HANDSHAKE_ACCEPT_V2: 0x0346,
  LEGACY_OPEN_V2: 0x0347,
  ENTRY_REGISTER_V2: 0x0349,
  ENTRY_REGISTERED_V2: 0x034a,
  ENTRY_REVOKE_V2: 0x034b,
  PRIVATE_ACTIVATE_V2: 0x0360,
  PRIVATE_READY_V2: 0x0361,
  PRIVATE_ACK_V2: 0x0362,
  PRIVATE_ACCEPTED_V2: 0x0363,
  PRIVATE_SOURCE_RECEIPT_V2: 0x0364,
  PRIVATE_OPEN_V2: 0x0365
})

const PEER_PURPOSE = Object.freeze({
  LEGACY_PEER_EGRESS: 1,
  PRIVATE_PEER_SOURCE: 2,
  PRIVATE_PEER_DESTINATION: 3
})

const PEER_BRANCH_CLASS = Object.freeze({ PEER: 2 })

const PEER_LINK_ROLE = Object.freeze({ CLIENT: 0, SAFETY_RELAY: 1, TERMINAL: 2 })

const PEER_CONTEXT_CLASS = Object.freeze({
  PEER_TAIL_FINALIZE_DATAGRAM: 5,
  PEER_ROUTE_DATAGRAM: 6
})

const PEER_SEMANTIC_CLASS = Object.freeze({ REGISTRATION_CONTROL: 1, APPLICATION: 2 })

const PEER_TRANSPORT_ID_REGISTRY = Object.freeze(
  Object.values(PEER_MESSAGE_ID).filter((messageId) => messageId >= 0x0300 && messageId <= 0x031f)
)

const PEER_SEMANTIC_ID_REGISTRY = Object.freeze(
  Object.values(PEER_MESSAGE_ID).filter((messageId) => messageId >= 0x0340 && messageId <= 0x0365)
)

const PEER_ID_REGISTRY = Object.freeze(
  [...PEER_TRANSPORT_ID_REGISTRY, ...PEER_SEMANTIC_ID_REGISTRY].sort((left, right) => left - right)
)

const bufferByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
const bufferSet = Uint8Array.prototype.set
const bufferSubarray = Uint8Array.prototype.subarray
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectHasOwnProperty = Object.prototype.hasOwnProperty

// Each entry is [minimum body bytes, maximum body bytes, suffix bytes].
// An optional fourth entry lists the allowed lengths for a disjoint range.
const PEER_OBJECT_LAYOUT = new Map([
  [PEER_MESSAGE_ID.PEER_CAPABILITY_ADVERTISEMENT_V2, [188, 188, 64]],
  [PEER_MESSAGE_ID.PEER_CAPS_QUERY_V2, [110, 110, 0]],
  [PEER_MESSAGE_ID.PEER_CAPS_COOKIE_CHALLENGE_V2, [72, 72, 0]],
  [PEER_MESSAGE_ID.PEER_CAPS_RESPONSE_V2, [335, 335, 64]],
  [PEER_MESSAGE_ID.PEER_ACTIVE_CHALLENGE_V2, [176, 176, 0]],
  [PEER_MESSAGE_ID.PEER_ACTIVE_CHALLENGE_RESPONSE_V2, [240, 240, 64]],
  [PEER_MESSAGE_ID.PEER_DISCOVER_REQUEST_V2, [79, 339, 0, [79, 339]]],
  [PEER_MESSAGE_ID.PEER_DISCOVER_RESPONSE_V2, [436, 436, 0]],
  [PEER_MESSAGE_ID.PEER_LINK_OFFER_V2, [360, 360, 64]],
  [PEER_MESSAGE_ID.PEER_LINK_ACCEPT_V2, [213, 213, 64]],
  [PEER_MESSAGE_ID.PEER_REDACTED_RESPONDER_PROOF_V2, [306, 306, 64]],
  [PEER_MESSAGE_ID.PEER_EXTENDED_V2, [486, 486, 0]],
  [PEER_MESSAGE_ID.PEER_TAIL_READY_V2, [210, 210, 64]],
  [PEER_MESSAGE_ID.PEER_EXTEND_REQUEST_V2, [516, 516, 0]],
  [PEER_MESSAGE_ID.PEER_BRANCH_DESTROY_V2, [42, 42, 0]],
  [PEER_MESSAGE_ID.PEER_BRANCH_TEARDOWN_V2, [58, 58, 0]],
  [PEER_MESSAGE_ID.PEER_BRANCH_TEARDOWN_ACK_V2, [58, 58, 0]],
  [PEER_MESSAGE_ID.PEER_ROUTE_OFFER_V2, [212, 212, 16]],
  [PEER_MESSAGE_ID.PEER_ROUTE_ACCEPT_V2, [260, 260, 16]],
  [PEER_MESSAGE_ID.PEER_ROUTE_REJECT_V2, [64, 64, 16]],
  [PEER_MESSAGE_ID.PEER_RELIABLE_PACKET_V2, [29, 1065, 0]],
  [PEER_MESSAGE_ID.PEER_RELIABLE_ACK_V2, [64, 64, 0]],
  [PEER_MESSAGE_ID.PEER_OPEN_V2, [88, 88, 0]],
  [PEER_MESSAGE_ID.PEER_OPENED_V2, [64, 64, 0]],
  [PEER_MESSAGE_ID.PEER_HANDSHAKE_V2, [49, 1029, 0]],
  [PEER_MESSAGE_ID.PEER_DATA_V2, [45, 1021, 0]],
  [PEER_MESSAGE_ID.PEER_CREDIT_V2, [60, 60, 0]],
  [PEER_MESSAGE_ID.PEER_FIN_V2, [56, 56, 0]],
  [PEER_MESSAGE_ID.PEER_CLOSE_V2, [56, 56, 0]],
  [PEER_MESSAGE_ID.PEER_RESET_V2, [60, 60, 0]],
  [PEER_MESSAGE_ID.PEER_ROUTE_CLOSE_V2, [40, 40, 0]],
  [PEER_MESSAGE_ID.PEER_ROUTE_CLOSE_ACK_V2, [40, 40, 0]],
  [PEER_MESSAGE_ID.PEER_DESCRIPTOR_V2, [511, 511, 0]],
  [PEER_MESSAGE_ID.LEGACY_RESOLVE_V2, [104, 104, 0]],
  [PEER_MESSAGE_ID.LEGACY_RESOLVED_V2, [106, 106, 0]],
  [PEER_MESSAGE_ID.LEGACY_RESERVE_V2, [96, 96, 0]],
  [PEER_MESSAGE_ID.LEGACY_RESERVED_V2, [132, 132, 0]],
  [PEER_MESSAGE_ID.PEER_NOISE_FRAGMENT_V2, [64, 1065, 0]],
  [PEER_MESSAGE_ID.LEGACY_HANDSHAKE_ACCEPT_V2, [132, 132, 0]],
  [PEER_MESSAGE_ID.LEGACY_OPEN_V2, [100, 100, 0]],
  [PEER_MESSAGE_ID.ENTRY_REGISTER_V2, [478, 478, 0]],
  [PEER_MESSAGE_ID.ENTRY_REGISTERED_V2, [136, 136, 0]],
  [PEER_MESSAGE_ID.ENTRY_REVOKE_V2, [88, 88, 0]],
  [PEER_MESSAGE_ID.PRIVATE_ACTIVATE_V2, [749, 749, 0]],
  [PEER_MESSAGE_ID.PRIVATE_READY_V2, [220, 220, 0]],
  [PEER_MESSAGE_ID.PRIVATE_ACK_V2, [232, 232, 0]],
  [PEER_MESSAGE_ID.PRIVATE_ACCEPTED_V2, [168, 168, 0]],
  [PEER_MESSAGE_ID.PRIVATE_SOURCE_RECEIPT_V2, [120, 120, 0]],
  [PEER_MESSAGE_ID.PRIVATE_OPEN_V2, [216, 216, 0]]
])

function invalidPeerObject() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function peerBufferLength(value) {
  try {
    return b4a.isBuffer(value) ? bufferByteLength.call(value) : -1
  } catch {
    return -1
  }
}

function peerSet(target, source, offset = 0) {
  try {
    bufferSet.call(target, source, offset)
  } catch {
    invalidPeerObject()
  }
}

function peerSubarray(value, start, end) {
  try {
    return bufferSubarray.call(value, start, end)
  } catch {
    invalidPeerObject()
  }
}

function peerCopy(value) {
  const length = peerBufferLength(value)
  if (length < 0) invalidPeerObject()
  const output = b4a.allocUnsafeSlow(length)
  peerSet(output, value)
  return output
}

function peerObjectDataProperty(value, name, required) {
  const descriptor = objectGetOwnPropertyDescriptor(value, name)

  if (descriptor === undefined) {
    if (required) invalidPeerObject()
    return undefined
  }
  if (!objectHasOwnProperty.call(descriptor, 'value')) invalidPeerObject()

  return descriptor.value
}

function peerObjectOptions(value) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) invalidPeerObject()
    const messageId = peerObjectDataProperty(value, 'messageId', true)
    const body = peerObjectDataProperty(value, 'body', true)
    const authSuffix = peerObjectDataProperty(value, 'authSuffix', false)

    return {
      messageId,
      body,
      authSuffix: authSuffix === undefined ? EMPTY_AUTH_SUFFIX : authSuffix
    }
  } catch {
    invalidPeerObject()
  }
}

function peerObjectLayout(messageId) {
  if (!Number.isSafeInteger(messageId)) invalidPeerObject()
  const layout = PEER_OBJECT_LAYOUT.get(messageId)
  if (layout === undefined) invalidPeerObject()
  return layout
}

function validPeerBodyLength(bodyBytes, layout) {
  const [minimumBodyBytes, maximumBodyBytes, , allowedLengths] = layout
  if (allowedLengths) return allowedLengths.includes(bodyBytes)
  return bodyBytes >= minimumBodyBytes && bodyBytes <= maximumBodyBytes
}

function writePeerUint16(buffer, value, offset) {
  buffer[offset] = value >>> 8
  buffer[offset + 1] = value
}

function writePeerUint32(buffer, value, offset) {
  buffer[offset] = value >>> 24
  buffer[offset + 1] = value >>> 16
  buffer[offset + 2] = value >>> 8
  buffer[offset + 3] = value
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

function encodePeerObject(value) {
  const { messageId, body, authSuffix } = peerObjectOptions(value)
  const layout = peerObjectLayout(messageId)
  const [, , authBytes] = layout
  const bodyBytes = peerBufferLength(body)
  const actualAuthBytes = peerBufferLength(authSuffix)

  if (
    !validPeerBodyLength(bodyBytes, layout) ||
    bodyBytes > 0xffff ||
    actualAuthBytes !== authBytes
  ) {
    invalidPeerObject()
  }

  const output = b4a.allocUnsafe(8 + bodyBytes + authBytes)
  writePeerUint32(output, PEER_PROTOCOL_VERSION, 0)
  writePeerUint16(output, messageId, 4)
  writePeerUint16(output, bodyBytes, 6)
  peerSet(output, body, 8)
  peerSet(output, authSuffix, 8 + bodyBytes)
  return output
}

function decodePeerObject(encoded) {
  try {
    const encodedBytes = peerBufferLength(encoded)
    if (encodedBytes < 8) invalidPeerObject()
    if (readPeerUint32(encoded, 0) !== PEER_PROTOCOL_VERSION) invalidPeerObject()

    const messageId = readPeerUint16(encoded, 4)
    const layout = peerObjectLayout(messageId)
    const bodyBytes = readPeerUint16(encoded, 6)
    const [, , authBytes] = layout

    if (!validPeerBodyLength(bodyBytes, layout) || encodedBytes !== 8 + bodyBytes + authBytes) {
      invalidPeerObject()
    }

    return {
      protocolVersion: PEER_PROTOCOL_VERSION,
      messageId,
      body: peerCopy(peerSubarray(encoded, 8, 8 + bodyBytes)),
      authSuffix: peerCopy(peerSubarray(encoded, 8 + bodyBytes, encodedBytes))
    }
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalidPeerObject()
  }
}

module.exports = {
  PEER_BRANCH_CLASS,
  PEER_CONTEXT_CLASS,
  PEER_ID_REGISTRY,
  PEER_LINK_ROLE,
  PEER_MESSAGE_ID,
  PEER_PROTOCOL_VERSION,
  PEER_PURPOSE,
  PEER_SEMANTIC_CLASS,
  PEER_SEMANTIC_ID_REGISTRY,
  PEER_TRANSPORT_ID_REGISTRY,
  decodePeerObject,
  encodePeerObject
}
