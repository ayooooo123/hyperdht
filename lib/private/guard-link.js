'use strict'

// Ported from the reviewed private-routes prototype at commit
// 0305df915b6a767093f9e75e6c06bc0a35da6169 and narrowed to the index-zero Gate 3B1 surface.

const b4a = require('b4a')
const sodium = require('sodium-universal')

const { DatagramReplayWindow, OrderedReceiver, SenderCounter } = require('./counters')
const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')
const { digestAdmittedLimits, digestPayloadParameters } = require('./link-parameters')
const { takeAdmittedExtendRequest } = require('./tail-control')
const {
  REDACTED_RESPONDER_PROOF_SIZE,
  decodeRedactedResponderProof,
  revokeVerifiedRedactedResponderProof,
  signRedactedResponderProofWithSigner,
  verifyExpectedRedactedResponderProof
} = require('./redacted-responder-proof')
const {
  destroyExtensionResponderSigner,
  destroyLinkOfferSigner,
  signLinkAccept,
  signLinkOffer
} = require('./relay-identity-signer')
const {
  adoptM3ResponderLink,
  destroyM3ResponderLink,
  isM3ResponderAdopter,
  takeM3ResponderLink
} = require('./m3-adjacency-adopter')
const {
  destroyExtensionOfferReceiver,
  destroyExtensionResponseReceiver,
  destroyExtensionResponseWriter,
  finishExtensionResponse,
  isExtensionOfferReceiver,
  isExtensionResponseReceiver,
  sendExtensionAccept,
  sendExtensionProof,
  takeExtensionOffer,
  takeExtensionResponse
} = require('./extension-setup-channel')
const {
  createExtensionLinkCompletion,
  destroyExtensionLinkCompletion
} = require('./extension-link-completion')
const MAX_ADJACENT_LINK_MS = 15_000n
const {
  decodeCanonicalEndpoint,
  decodeRelayCapabilityAdvertisement,
  digestRelayCapabilityAdvertisement
} = require('./relay-capability')
const {
  BRANCH_CLASS,
  CELL_CLASS,
  DOMAIN,
  DIRECTION,
  M3_LINK_ROLE,
  M3_MESSAGE_ID,
  M3_PROTOCOL_VERSION,
  ROLE,
  decodeM3Object,
  encodeM3Object,
  roleForIdentity
} = require('./protocol')

const LINK_OFFER_SIZE = 374
const LINK_ACCEPT_SIZE = 285
const CANONICAL_ENDPOINT_SIZE = 19

const LINK_OFFER_BODY_SIZE = 302
const LINK_ACCEPT_BODY_SIZE = 213
const LINK_OFFER_DOMAIN = b4a.from('hyperdht-private-routes/m3/link-offer/v1')
const LINK_ACCEPT_DOMAIN = b4a.from('hyperdht-private-routes/m3/link-accept/v1')
const LINK_OFFER_DIGEST_DOMAIN = b4a.from('hyperdht-private-routes/m3/link-offer-digest/v1')
const LINK_ACCEPT_DIGEST_DOMAIN = b4a.from('hyperdht-private-routes/m3/link-accept-digest/v1')
const INITIATOR_CELL_ID_DOMAIN = b4a.from('hyperdht-private-routes/m3/cell-id/initiator/v1')
const RESPONDER_CELL_ID_DOMAIN = b4a.from('hyperdht-private-routes/m3/cell-id/responder/v1')
const TAIL_CONTROL_TRANSCRIPT_SIZE = 290
const TAIL_CONTROL_DOMAIN = b4a.from('hyperdht-private-routes/tail-control/transcript/v1')
const MAX_U32 = 0xffff_ffff
const MAX_U64 = 0xffff_ffff_ffff_ffffn
const PENDING = new WeakMap()
const PENDING_TOKENS = new Set()
const SPENT = new WeakSet()
const ESTABLISHED = new WeakMap()
const SPENT_ESTABLISHED = new WeakSet()
const M3_AUTHENTICATED_BRANCH_BINDINGS = new WeakMap()
const SPENT_M3_AUTHENTICATED_BRANCH_BINDINGS = new WeakSet()
const EXTENSION_PENDING = new WeakMap()
const EXTENSION_PENDING_TOKENS = new Set()
const SPENT_EXTENSION_PENDING = new WeakSet()
const EXTENSION_RESPONDER_ADJACENCIES = new WeakMap()
const SPENT_EXTENSION_RESPONDER_ADJACENCIES = new WeakSet()
const ACCEPTED_EXTENSION_ADJACENCY_TRANSFERS = new WeakMap()
const SPENT_ACCEPTED_EXTENSION_ADJACENCY_TRANSFERS = new WeakSet()
const ACCEPTED_EXTENSION_ADJACENCY_OWNERS = new WeakMap()
const SPENT_ACCEPTED_EXTENSION_ADJACENCY_OWNERS = new WeakSet()
const MAX_PENDING_OFFERS = 4096
const MAX_RESPONDER_REPLAYS = 4096
const MAX_TIMER_DELAY = 0x7fff_ffff
let responderReplayOwners = 0
let lastExtensionResourceTime = 0n
const SOCKET_OWNER_LEASES = new WeakMap()
const RELAY_DIAL_AUTHORITIES = new WeakMap()
const SPENT_RELAY_DIAL_AUTHORITIES = new WeakSet()
const DESTROYED_RELAY_DIAL_AUTHORITIES = new WeakSet()
const EXTENSION_ADJACENT_FACTORIES = new WeakMap()
const SPENT_EXTENSION_ADJACENT_FACTORIES = new WeakSet()
const STAGED_RELAY_ADJACENT_OFFERS = new WeakMap()
const TAKE_STAGED_RELAY_ADJACENT_OFFER = Symbol.for(
  'hyperdht-private-routes/relay-adjacent-staged-offer-taker'
)
let pendingRelayDials = 0
const TEST_ONLY_COUNTER_FACTORY = Symbol.for('hyperdht-private-routes/test-only-counter-factory')
const TEST_ONLY_M3_ESTABLISHED_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-m3-established-issuer'
)
const testOnlyM3EstablishedIssuer = Object.freeze({
  issue(state) {
    const handle = Object.freeze({})
    ESTABLISHED.set(handle, { ...state, testOnly: true })
    return handle
  },
  issueAuthenticatedBranchBinding(state, issuer) {
    return createM3AuthenticatedBranchBinding(state, issuer)
  }
})
const byteLengthGetter = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
const setIntrinsic = Uint8Array.prototype.set
const subarrayIntrinsic = Uint8Array.prototype.subarray
const fillIntrinsic = Uint8Array.prototype.fill
const getOwnPropertyDescriptorIntrinsic = Object.getOwnPropertyDescriptor
const reflectOwnKeysIntrinsic = Reflect.ownKeys
const arrayIsArrayIntrinsic = Array.isArray
const objectCreateIntrinsic = Object.create
const getPrototypeOfIntrinsic = Object.getPrototypeOf
const objectFreezeIntrinsic = Object.freeze
const reflectApplyIntrinsic = Reflect.apply
const dateNowIntrinsic = Date.now
const objectPrototypeIntrinsic = Object.prototype
const RELAY_DIAL_AUTHORITY_OPTIONS = Object.freeze([
  'socketOwner',
  'allowedRole',
  'dial',
  'destroy'
])
const RELAY_DIAL_OPTIONS = Object.freeze([
  'advertisement',
  'advertisementDigest',
  'requiredRole',
  'wireExpiresAt',
  'localDeadline'
])
const EXTENSION_ADJACENT_FACTORY_OPTIONS = Object.freeze([
  'dialAuthority',
  'linkOfferSigner',
  'proofVerifier',
  'proofConsumer',
  'wallNow',
  'monotonicNow',
  'randomBytes',
  'schedule',
  'cancelScheduled',
  'destroy'
])
const TERMINAL_EXTENSION_ADJACENT_BINDING = Object.freeze({})
const EXTENSION_RESPONDER_REQUIRED_OPTIONS = Object.freeze([
  'advertisement',
  'adjacencyAdopter',
  'extensionResponderSigner',
  'responderRouteEncryptionSecretKey',
  'wallNow',
  'monotonicNow',
  'randomBytes',
  'schedule',
  'cancelScheduled',
  'offerReceiver'
])

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function authentication() {
  throw PrivateRouteError.ERR_AUTHENTICATION()
}

function busy() {
  throw PrivateRouteError.ERR_BUSY()
}

function routeUnavailable() {
  throw PrivateRouteError.ROUTE_UNAVAILABLE()
}

function extensionResourceTime() {
  let now = 0n
  try {
    now = BigInt(reflectApplyIntrinsic(dateNowIntrinsic, Date, []))
  } catch {
    now = lastExtensionResourceTime
  }
  if (now < lastExtensionResourceTime) return lastExtensionResourceTime
  lastExtensionResourceTime = now
  return now
}

function destroyed() {
  throw PrivateRouteError.ERR_DESTROYED()
}

function exactOwnData(value, expected) {
  try {
    if (value === null || typeof value !== 'object' || arrayIsArrayIntrinsic(value)) invalid()
    const prototype = getPrototypeOfIntrinsic(value)
    if (prototype !== objectPrototypeIntrinsic && prototype !== null) invalid()
    const keys = reflectOwnKeysIntrinsic(value)
    if (keys.length !== expected.length) invalid()
    const snapshot = objectCreateIntrinsic(null)
    for (const name of expected) {
      const descriptor = getOwnPropertyDescriptorIntrinsic(value, name)
      if (!descriptor || !('value' in descriptor)) invalid()
      snapshot[name] = descriptor.value
    }
    return snapshot
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function ownDataCandidate(value, name) {
  try {
    if (value === null || typeof value !== 'object') return null
    const descriptor = getOwnPropertyDescriptorIntrinsic(value, name)
    return descriptor && 'value' in descriptor ? descriptor.value : null
  } catch {
    return null
  }
}

function invokeNoArguments(callback) {
  if (typeof callback !== 'function') return false
  try {
    reflectApplyIntrinsic(callback, undefined, [])
  } catch {}
  return true
}

function replay() {
  throw PrivateRouteError.ERR_REPLAY()
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

function safe(value, name) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid()
    return value[name]
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function exactKeys(value, expected) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
    const keys = Object.keys(value).sort()
    const wanted = [...expected].sort()
    return keys.length === wanted.length && keys.every((key, index) => key === wanted[index])
  } catch {
    return false
  }
}

function copy(value, size = length(value)) {
  let output = null
  let complete = false
  try {
    if (!fixed(value, size)) invalid()
    output = b4a.allocUnsafeSlow(size)
    if (!fixed(output, size)) invalid()
    setIntrinsic.call(output, value)
    complete = true
    return output
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    if (!complete) clear(output)
  }
}

function subarray(value, start, end) {
  try {
    return subarrayIntrinsic.call(value, start, end)
  } catch {
    invalid()
  }
}

function clear(value) {
  try {
    if (b4a.isBuffer(value)) fillIntrinsic.call(value, 0)
  } catch {}
}

function equal(left, right) {
  try {
    return length(left) === length(right) && b4a.equals(left, right)
  } catch {
    return false
  }
}

function u32(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= MAX_U32
}

function u64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= MAX_U64
}

function clockValue(clock) {
  let value
  try {
    value = reflectApplyIntrinsic(clock, undefined, [])
  } catch {
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) invalid()
    value = BigInt(value)
  }
  if (!u64(value)) invalid()
  return value
}

function timerDelay(remaining) {
  return remaining > BigInt(MAX_TIMER_DELAY) ? MAX_TIMER_DELAY : Number(remaining)
}

function nonzero(value) {
  if (length(value) < 1) return false
  for (const byte of value) if (byte !== 0) return true
  return false
}

function writeU16(output, value, offset) {
  output[offset] = value >>> 8
  output[offset + 1] = value
}

function writeU32(output, value, offset) {
  output[offset] = value >>> 24
  output[offset + 1] = value >>> 16
  output[offset + 2] = value >>> 8
  output[offset + 3] = value
}

function readU16(input, offset) {
  return (input[offset] << 8) | input[offset + 1]
}

function readU32(input, offset) {
  return (
    input[offset] * 0x1000000 +
    (input[offset + 1] << 16) +
    (input[offset + 2] << 8) +
    input[offset + 3]
  )
}

function writeU64(output, value, offset) {
  for (let index = offset + 7; index >= offset; index--) {
    output[index] = Number(value & 0xffn)
    value >>= 8n
  }
}

function readU64(input, offset) {
  let value = 0n
  for (let index = offset; index < offset + 8; index++) {
    value = (value << 8n) | BigInt(input[index])
  }
  return value
}

// The index-zero link owns the exact initial tail transcript. Later tail
// extension behavior remains outside this Chunk 1 module.
function encodeTailControlTranscript(value) {
  const branchClass = safe(value, 'branchClass')
  const branchId = safe(value, 'branchId')
  const circuitId = safe(value, 'circuitId')
  const generation = safe(value, 'generation')
  const extensionIndex = safe(value, 'extensionIndex')
  const fields = [
    safe(value, 'clientTailEphemeralPublicKey'),
    safe(value, 'advertisedTailRouteEncryptionPublicKey'),
    safe(value, 'candidateAdvertisementDigest'),
    safe(value, 'clientNonce'),
    safe(value, 'tailIdentity'),
    safe(value, 'admittedLimitsDigest')
  ]
  if (
    (branchClass !== BRANCH_CLASS.LOOKUP && branchClass !== BRANCH_CLASS.ANNOUNCE) ||
    !fixed(branchId, 16) ||
    !fixed(circuitId, 16) ||
    !u64(generation) ||
    !Number.isSafeInteger(extensionIndex) ||
    extensionIndex < 0 ||
    extensionIndex > 2 ||
    fields.some((field) => !fixed(field, 32))
  ) {
    invalid()
  }
  const output = b4a.allocUnsafeSlow(TAIL_CONTROL_TRANSCRIPT_SIZE)
  let offset = 0
  writeU16(output, TAIL_CONTROL_DOMAIN.byteLength, offset)
  offset += 2
  setIntrinsic.call(output, TAIL_CONTROL_DOMAIN, offset)
  offset += TAIL_CONTROL_DOMAIN.byteLength
  writeU32(output, M3_PROTOCOL_VERSION, offset)
  offset += 4
  output[offset++] = branchClass
  setIntrinsic.call(output, branchId, offset)
  offset += 16
  setIntrinsic.call(output, circuitId, offset)
  offset += 16
  writeU64(output, generation, offset)
  offset += 8
  output[offset++] = extensionIndex
  for (const field of fields) {
    setIntrinsic.call(output, field, offset)
    offset += 32
  }
  return output
}

function signatureInput(domain, messageId, body) {
  const output = b4a.allocUnsafeSlow(2 + domain.byteLength + 8 + body.byteLength)
  writeU16(output, domain.byteLength, 0)
  setIntrinsic.call(output, domain, 2)
  writeU32(output, M3_PROTOCOL_VERSION, 2 + domain.byteLength)
  writeU16(output, messageId, 6 + domain.byteLength)
  writeU16(output, body.byteLength, 8 + domain.byteLength)
  setIntrinsic.call(output, body, 10 + domain.byteLength)
  return output
}

function digest(domain, bytes) {
  const domainLength = length(domain)
  if (domainLength < 0 || domainLength > 0xffff || length(bytes) < 0) invalid()
  const prefix = b4a.allocUnsafeSlow(2)
  try {
    writeU16(prefix, domainLength, 0)
    return cryptoSuite.hash([prefix, domain, bytes])
  } finally {
    clear(prefix)
  }
}

function cellIds(completeOfferDigest) {
  const initiator = digest(INITIATOR_CELL_ID_DOMAIN, completeOfferDigest)
  const responder = digest(RESPONDER_CELL_ID_DOMAIN, completeOfferDigest)
  let initiatorCellId = null
  let responderCellId = null
  let transferred = false
  try {
    initiatorCellId = copy(subarray(initiator, 0, 16), 16)
    responderCellId = copy(subarray(responder, 0, 16), 16)
    const result = { initiatorCellId, responderCellId }
    transferred = true
    return result
  } finally {
    clear(initiator)
    clear(responder)
    if (!transferred) {
      clear(initiatorCellId)
      clear(responderCellId)
    }
  }
}

function encodeLimits(value) {
  const cellSize = safe(value, 'cellSize')
  const maxCells = safe(value, 'maxCells')
  const maxBytes = safe(value, 'maxBytes')
  const maxCommands = safe(value, 'maxCommands')
  const idleTimeoutMs = safe(value, 'idleTimeoutMs')
  const expiresAtMs = safe(value, 'expiresAtMs')
  if (
    cellSize !== 1200 ||
    !u32(maxCells) ||
    maxCells === 0 ||
    !u32(maxBytes) ||
    maxBytes === 0 ||
    !u32(maxCommands) ||
    maxCommands === 0 ||
    !u32(idleTimeoutMs) ||
    idleTimeoutMs === 0 ||
    !u64(expiresAtMs)
  ) {
    invalid()
  }
  const output = b4a.allocUnsafeSlow(26)
  writeU16(output, cellSize, 0)
  writeU32(output, maxCells, 2)
  writeU32(output, maxBytes, 6)
  writeU32(output, maxCommands, 10)
  writeU32(output, idleTimeoutMs, 14)
  writeU64(output, expiresAtMs, 18)
  return output
}

function decodeLimits(bytes) {
  if (!fixed(bytes, 26)) invalid()
  const value = {
    cellSize: readU16(bytes, 0),
    maxCells: readU32(bytes, 2),
    maxBytes: readU32(bytes, 6),
    maxCommands: readU32(bytes, 10),
    idleTimeoutMs: readU32(bytes, 14),
    expiresAtMs: readU64(bytes, 18)
  }
  encodeLimits(value)
  return value
}

function limitsWithin(admitted, requested) {
  return (
    admitted.cellSize === requested.cellSize &&
    admitted.maxCells <= requested.maxCells &&
    admitted.maxBytes <= requested.maxBytes &&
    admitted.maxCommands <= requested.maxCommands &&
    admitted.idleTimeoutMs <= requested.idleTimeoutMs &&
    admitted.expiresAtMs <= requested.expiresAtMs
  )
}

function limitsWithinAdvertisement(limits, advertisement, now) {
  return (
    limits.maxCells <= advertisement.maxCellsPerCircuit &&
    limits.maxBytes <= advertisement.maxBytesPerCircuit &&
    limits.maxCommands <= advertisement.maxCommandsPerCircuit &&
    limits.idleTimeoutMs <= advertisement.idleTimeoutMs &&
    limits.expiresAtMs <= advertisement.expiresAtMs &&
    limits.expiresAtMs <= now + 300_000n
  )
}

function clearPending(state) {
  if (!state) return
  clear(state.advertisementDigest)
  clear(state.ephemeralSecretKey)
  clearDecoded(state.offer)
}

function clearExtensionPending(state) {
  if (!state) return
  clear(state.advertisement)
  clear(state.advertisementDigest)
  clear(state.advertisedRouteEncryptionPublicKey)
  clear(state.ephemeralSecretKey)
  clear(state.extensionNonce)
  clearDecoded(state.offer)
}

function clearExtendRequest(value) {
  if (!value) return
  for (const field of [
    'advertisement',
    'advertisementDigest',
    'clientTailEphemeralPublicKey',
    'clientNonce',
    'payloadParametersDigest',
    'requestedLimits',
    'extensionNonce'
  ]) {
    clear(value[field])
    try {
      value[field] = null
    } catch {}
  }
  try {
    value.generation = 0n
    value.extensionIndex = -1
    value.branchClass = -1
  } catch {}
}

function clearAdmittedExtensionMaterial(value) {
  if (!value) return
  clearExtendRequest(value.request)
  clear(value.currentTailIdentity)
  clear(value.currentTailAdvertisementDigest)
  try {
    value.request = null
    value.currentTailIdentity = null
    value.currentTailAdvertisementDigest = null
    value.localDeadline = 0n
    value.wireExpiresAt = 0n
  } catch {}
}

function prunePending(now) {
  for (const token of PENDING_TOKENS) {
    const state = PENDING.get(token)
    if (state && state.offer.offerDeadlineMs > now) continue
    PENDING.delete(token)
    PENDING_TOKENS.delete(token)
    SPENT.add(token)
    clearPending(state)
  }
}

function pruneExtensionPending(now) {
  for (const token of EXTENSION_PENDING_TOKENS) {
    const state = EXTENSION_PENDING.get(token)
    if (!state || state.resourceDeadline > now) continue
    EXTENSION_PENDING.delete(token)
    EXTENSION_PENDING_TOKENS.delete(token)
    SPENT_EXTENSION_PENDING.add(token)
    clearExtensionPending(state)
  }
}

function decodeOffer(encoded) {
  const object = decodeM3Object(encoded)
  if (
    length(encoded) !== LINK_OFFER_SIZE ||
    object.messageId !== M3_MESSAGE_ID.LINK_OFFER_V1 ||
    length(object.body) !== LINK_OFFER_BODY_SIZE
  ) {
    invalid()
  }
  const body = object.body
  const result = {
    body,
    signature: object.authSuffix,
    initiatorRole: body[96],
    responderRole: body[97],
    branchClass: body[98],
    generation: readU64(body, 131),
    extensionIndex: body[139],
    requestedLimits: decodeLimits(subarray(body, 268, 294)),
    offerDeadlineMs: readU64(body, 294)
  }
  let transferred = false
  try {
    result.encoded = copy(encoded, LINK_OFFER_SIZE)
    result.responderAdvertisementDigest = copy(subarray(body, 0, 32), 32)
    result.initiatorIdentity = copy(subarray(body, 32, 64), 32)
    result.responderIdentity = copy(subarray(body, 64, 96), 32)
    result.branchId = copy(subarray(body, 99, 115), 16)
    result.circuitId = copy(subarray(body, 115, 131), 16)
    result.initiatorLinkEphemeralPublicKey = copy(subarray(body, 140, 172), 32)
    result.clientTailEphemeralPublicKey = copy(subarray(body, 172, 204), 32)
    result.clientNonce = copy(subarray(body, 204, 236), 32)
    result.payloadParametersDigest = copy(subarray(body, 236, 268), 32)
    transferred = true
    return result
  } finally {
    if (!transferred) clearDecoded(result)
  }
}

function decodeAccept(encoded) {
  const object = decodeM3Object(encoded)
  if (
    length(encoded) !== LINK_ACCEPT_SIZE ||
    object.messageId !== M3_MESSAGE_ID.LINK_ACCEPT_V1 ||
    length(object.body) !== LINK_ACCEPT_BODY_SIZE
  ) {
    invalid()
  }
  const body = object.body
  const result = {
    body,
    signature: object.authSuffix,
    admittedLimits: decodeLimits(subarray(body, 147, 173)),
    acceptedAtMs: readU64(body, 173)
  }
  let transferred = false
  try {
    result.encoded = copy(encoded, LINK_ACCEPT_SIZE)
    result.completeOfferDigest = copy(subarray(body, 0, 32), 32)
    result.responderAdvertisementDigest = copy(subarray(body, 32, 64), 32)
    result.responderIdentity = copy(subarray(body, 64, 96), 32)
    result.observedPredecessorEndpoint = copy(subarray(body, 96, 115), 19)
    result.responderLinkEphemeralPublicKey = copy(subarray(body, 115, 147), 32)
    result.acceptNonce = copy(subarray(body, 181, 213), 32)
    transferred = true
    return result
  } finally {
    if (!transferred) clearDecoded(result)
  }
}

function validOffer(offer, now) {
  const input = signatureInput(LINK_OFFER_DOMAIN, M3_MESSAGE_ID.LINK_OFFER_V1, offer.body)
  const signatureValid = cryptoSuite.verify(input, offer.signature, offer.initiatorIdentity)
  clear(input)
  if (
    !signatureValid ||
    offer.initiatorRole !== M3_LINK_ROLE.CLIENT ||
    offer.responderRole !== M3_LINK_ROLE.SAFETY_RELAY ||
    (offer.branchClass !== BRANCH_CLASS.LOOKUP && offer.branchClass !== BRANCH_CLASS.ANNOUNCE) ||
    offer.extensionIndex !== 0 ||
    offer.generation === 0n ||
    offer.offerDeadlineMs <= now ||
    offer.offerDeadlineMs > now + MAX_ADJACENT_LINK_MS ||
    offer.requestedLimits.expiresAtMs < offer.offerDeadlineMs ||
    equal(offer.initiatorIdentity, offer.responderIdentity) ||
    !nonzero(offer.branchId) ||
    !nonzero(offer.circuitId) ||
    !nonzero(offer.initiatorLinkEphemeralPublicKey) ||
    !nonzero(offer.clientTailEphemeralPublicKey) ||
    !nonzero(offer.clientNonce) ||
    !nonzero(offer.payloadParametersDigest)
  ) {
    authentication()
  }
}
function validExtensionOffer(offer, now) {
  const input = signatureInput(LINK_OFFER_DOMAIN, M3_MESSAGE_ID.LINK_OFFER_V1, offer.body)
  const signatureValid = cryptoSuite.verify(input, offer.signature, offer.initiatorIdentity)
  clear(input)
  const expectedResponderRole =
    offer.extensionIndex === 1 ? M3_LINK_ROLE.SAFETY_RELAY : M3_LINK_ROLE.DHT_EXIT
  const expectedIdentityRole = offer.extensionIndex === 1 ? ROLE.SAFETY : ROLE.PRIVATE
  if (
    !signatureValid ||
    (offer.extensionIndex !== 1 && offer.extensionIndex !== 2) ||
    offer.initiatorRole !== M3_LINK_ROLE.SAFETY_RELAY ||
    offer.responderRole !== expectedResponderRole ||
    roleForIdentity(offer.initiatorIdentity) !== ROLE.SAFETY ||
    roleForIdentity(offer.responderIdentity) !== expectedIdentityRole ||
    (offer.branchClass !== BRANCH_CLASS.LOOKUP && offer.branchClass !== BRANCH_CLASS.ANNOUNCE) ||
    offer.generation === 0n ||
    offer.offerDeadlineMs <= now ||
    offer.offerDeadlineMs > now + MAX_ADJACENT_LINK_MS ||
    offer.requestedLimits.expiresAtMs < offer.offerDeadlineMs ||
    equal(offer.initiatorIdentity, offer.responderIdentity) ||
    !nonzero(offer.branchId) ||
    !nonzero(offer.circuitId) ||
    !nonzero(offer.initiatorLinkEphemeralPublicKey) ||
    !nonzero(offer.clientTailEphemeralPublicKey) ||
    !nonzero(offer.clientNonce) ||
    !nonzero(offer.payloadParametersDigest)
  ) {
    authentication()
  }
}

function createCounter(cellClass, sender, now) {
  return sender
    ? new SenderCounter()
    : cellClass === CELL_CLASS.DATAGRAM
      ? new DatagramReplayWindow({ window: 256 })
      : new OrderedReceiver({ window: 256, gapTimeout: 5000, now })
}

function context(cellClass, key, noncePrefix, sender, now, counterFactory) {
  let ownedKey = null
  let ownedNoncePrefix = null
  let counter = null
  let transferred = false
  try {
    ownedKey = copy(key, 32)
    ownedNoncePrefix = copy(noncePrefix, 16)
    counter = counterFactory(cellClass, sender, now)
    const result = { key: ownedKey, noncePrefix: ownedNoncePrefix, counter }
    transferred = true
    return result
  } finally {
    if (!transferred) {
      clear(ownedKey)
      clear(ownedNoncePrefix)
      try {
        if (counter) counter.destroy()
      } catch {}
    }
  }
}

function m3CellLinkTransferIssuerForPhysicalChannel(physicalChannel) {
  try {
    const { createM3CellLinkTransferIssuerFromEstablished } = require('./udx-cell-endpoint')
    return createM3CellLinkTransferIssuerFromEstablished(physicalChannel)
  } catch (err) {
    if (err instanceof PrivateRouteError) return physicalChannel
    throw err
  }
}

function deriveState(
  shared,
  tailShared,
  offer,
  accept,
  initiator,
  physicalChannel,
  now,
  tailRouteEncryptionPublicKey,
  counterFactory
) {
  let offerDigest = null
  let acceptDigest = null
  let ids = null
  const contexts = {}
  let admittedLimitsDigest = null
  let tailControlTranscript = null
  try {
    offerDigest = digest(LINK_OFFER_DIGEST_DOMAIN, offer.encoded)
    acceptDigest = digest(LINK_ACCEPT_DIGEST_DOMAIN, accept.encoded)
    ids = cellIds(offerDigest)
    for (const cellClass of [CELL_CLASS.CONTROL, CELL_CLASS.STREAM, CELL_CLASS.DATAGRAM]) {
      let transcript = null
      let keys = null
      try {
        transcript = b4a.concat([
          DOMAIN.LINK_CREATED,
          offerDigest,
          acceptDigest,
          b4a.from([cellClass])
        ])
        keys = cryptoSuite.deriveKeys(shared, transcript)
        let tx = null
        let rx = null
        try {
          tx = context(
            cellClass,
            initiator ? keys.forwardKey : keys.reverseKey,
            initiator ? keys.forwardNoncePrefix : keys.reverseNoncePrefix,
            true,
            now,
            counterFactory
          )
          rx = context(
            cellClass,
            initiator ? keys.reverseKey : keys.forwardKey,
            initiator ? keys.reverseNoncePrefix : keys.forwardNoncePrefix,
            false,
            now,
            counterFactory
          )
          contexts[cellClass] = { tx, rx }
          tx = null
          rx = null
        } finally {
          clearContexts({ partial: { tx, rx } })
        }
      } finally {
        clear(keys && keys.forwardKey)
        clear(keys && keys.reverseKey)
        clear(keys && keys.forwardNoncePrefix)
        clear(keys && keys.reverseNoncePrefix)
        clear(transcript)
      }
    }
    if (tailShared) {
      admittedLimitsDigest = digestAdmittedLimits(accept.admittedLimits)
      tailControlTranscript = encodeTailControlTranscript({
        branchClass: offer.branchClass,
        branchId: offer.branchId,
        circuitId: offer.circuitId,
        generation: offer.generation,
        extensionIndex: offer.extensionIndex,
        clientTailEphemeralPublicKey: offer.clientTailEphemeralPublicKey,
        advertisedTailRouteEncryptionPublicKey: tailRouteEncryptionPublicKey,
        candidateAdvertisementDigest: offer.responderAdvertisementDigest,
        clientNonce: offer.clientNonce,
        tailIdentity: offer.responderIdentity,
        admittedLimitsDigest
      })
    }
    const result = {
      initiator,
      branchClass: offer.branchClass,
      generation: offer.generation,
      extensionIndex: offer.extensionIndex,
      expiresAt: accept.admittedLimits.expiresAtMs,
      admittedLimits: accept.admittedLimits,
      contexts
    }
    let transferred = false
    let physicalChannelIssuer = null
    try {
      result.completeOfferDigest = copy(offerDigest, 32)
      result.localId = copy(initiator ? ids.initiatorCellId : ids.responderCellId, 16)
      result.peerLocalId = copy(initiator ? ids.responderCellId : ids.initiatorCellId, 16)
      result.localIdentity = copy(initiator ? offer.initiatorIdentity : offer.responderIdentity, 32)
      result.peerIdentity = copy(initiator ? offer.responderIdentity : offer.initiatorIdentity, 32)
      result.branchId = copy(offer.branchId, 16)
      result.circuitId = copy(offer.circuitId, 16)
      result.responderAdvertisementDigest = copy(offer.responderAdvertisementDigest, 32)
      result.tailSharedSecret = tailShared ? copy(tailShared, 32) : null
      result.tailControlTranscript = tailControlTranscript
      physicalChannelIssuer = m3CellLinkTransferIssuerForPhysicalChannel(physicalChannel)
      result.m3BranchBinding = createM3AuthenticatedBranchBinding(result, physicalChannelIssuer)
      result.physicalChannel = physicalChannelIssuer
      physicalChannelIssuer = null
      transferred = true
    } finally {
      if (!transferred) {
        clearState(result)
        result.physicalChannel = null
        try {
          if (
            physicalChannelIssuer &&
            physicalChannelIssuer !== physicalChannel &&
            typeof physicalChannelIssuer.destroy === 'function'
          ) {
            physicalChannelIssuer.destroy()
          }
        } catch {}
      }
    }
    tailControlTranscript = null
    return result
  } catch (err) {
    clearContexts(contexts)
    throw err
  } finally {
    clear(ids && ids.initiatorCellId)
    clear(ids && ids.responderCellId)
    clear(offerDigest)
    clear(acceptDigest)
    clear(admittedLimitsDigest)
    clear(tailControlTranscript)
  }
}

function establish(state) {
  const handle = Object.freeze({})
  ESTABLISHED.set(handle, state)
  return handle
}

function createM3AuthenticatedBranchBinding(state, issuer) {
  const binding = Object.freeze({})
  let receiveCircuitId = null
  let sendCircuitId = null
  try {
    receiveCircuitId = copy(state.localId, 16)
    sendCircuitId = copy(state.peerLocalId, 16)
    M3_AUTHENTICATED_BRANCH_BINDINGS.set(binding, {
      issuer,
      receiveEpoch: state.generation,
      receiveCircuitId,
      receiveDirection: state.initiator ? DIRECTION.REVERSE : DIRECTION.FORWARD,
      sendEpoch: state.generation,
      sendCircuitId,
      sendDirection: state.initiator ? DIRECTION.FORWARD : DIRECTION.REVERSE
    })
    receiveCircuitId = null
    sendCircuitId = null
    return binding
  } finally {
    clear(receiveCircuitId)
    clear(sendCircuitId)
  }
}

function takeM3AuthenticatedBranchBinding(binding, issuer) {
  const state =
    binding !== null && typeof binding === 'object'
      ? M3_AUTHENTICATED_BRANCH_BINDINGS.get(binding)
      : null
  if (!state) {
    if (
      binding !== null &&
      typeof binding === 'object' &&
      SPENT_M3_AUTHENTICATED_BRANCH_BINDINGS.has(binding)
    ) {
      replay()
    }
    authentication()
  }
  M3_AUTHENTICATED_BRANCH_BINDINGS.delete(binding)
  SPENT_M3_AUTHENTICATED_BRANCH_BINDINGS.add(binding)
  if (state.issuer !== issuer) {
    clear(state.receiveCircuitId)
    clear(state.sendCircuitId)
    authentication()
  }
  return state
}

function destroyM3AuthenticatedBranchBinding(binding) {
  const state =
    binding !== null && typeof binding === 'object'
      ? M3_AUTHENTICATED_BRANCH_BINDINGS.get(binding)
      : null
  if (!state) return false
  M3_AUTHENTICATED_BRANCH_BINDINGS.delete(binding)
  SPENT_M3_AUTHENTICATED_BRANCH_BINDINGS.add(binding)
  clear(state.receiveCircuitId)
  clear(state.sendCircuitId)
  return true
}

function clearContexts(contexts) {
  for (const pair of Object.values(contexts || {})) {
    for (const value of [pair && pair.tx, pair && pair.rx]) {
      if (!value) continue
      clear(value.key)
      clear(value.noncePrefix)
      try {
        value.counter.destroy()
      } catch {}
    }
  }
}

function clearState(state) {
  if (!state) return
  const physicalChannel = state.physicalChannel
  clear(state.localIdentity)
  clear(state.peerIdentity)
  clear(state.completeOfferDigest)
  clear(state.localId)
  clear(state.peerLocalId)
  clear(state.branchId)
  clear(state.circuitId)
  clear(state.responderAdvertisementDigest)
  clear(state.clientTailEphemeralSecretKey)
  clear(state.tailSharedSecret)
  clear(state.tailControlTranscript)
  clearContexts(state.contexts)
  destroyM3AuthenticatedBranchBinding(state.m3BranchBinding)
  state.m3BranchBinding = null
  state.physicalChannel = null
  try {
    if (physicalChannel && typeof physicalChannel.destroy === 'function') physicalChannel.destroy()
  } catch {}
}

function clearDecoded(value) {
  if (!value) return
  for (const entry of Object.values(value)) clear(entry)
}

function createSocketOwnerLease(socketOwner, destroyOwner) {
  const lease = objectFreezeIntrinsic({})
  SOCKET_OWNER_LEASES.set(lease, { socketOwner, destroyOwner })
  return lease
}

function spendSocketOwnerLease(lease) {
  const state = lease !== null && typeof lease === 'object' ? SOCKET_OWNER_LEASES.get(lease) : null
  if (!state) return false
  SOCKET_OWNER_LEASES.delete(lease)
  const destroyOwner = state.destroyOwner
  state.socketOwner = null
  state.destroyOwner = null
  invokeNoArguments(destroyOwner)
  return true
}
function retireStagedRelayAdjacentOffer(record) {
  if (!record || record.phase !== 'LIVE') return false
  record.phase = 'SPENT'
  clear(record.endpoint)
  clear(record.offer)
  record.endpoint = null
  record.offer = null
  return true
}

function stageRelayAdjacentOffer(socketOwner, authorityGeneration, endpoint, offer) {
  const previous = STAGED_RELAY_ADJACENT_OFFERS.get(socketOwner)
  if (previous && previous.phase === 'LIVE') authentication()
  const record = {
    phase: 'LIVE',
    authorityGeneration,
    endpoint: copy(endpoint, CANONICAL_ENDPOINT_SIZE),
    offer: copy(offer, LINK_OFFER_SIZE)
  }
  STAGED_RELAY_ADJACENT_OFFERS.set(socketOwner, record)
  return record
}

function takeStagedRelayAdjacentOffer(socketOwner, endpoint) {
  const record =
    socketOwner !== null && typeof socketOwner === 'object'
      ? STAGED_RELAY_ADJACENT_OFFERS.get(socketOwner)
      : null
  if (!record) authentication()
  if (record.phase !== 'LIVE') replay()
  if (!fixed(endpoint, CANONICAL_ENDPOINT_SIZE) || !equal(record.endpoint, endpoint)) {
    retireStagedRelayAdjacentOffer(record)
    authentication()
  }
  const offer = record.offer
  record.phase = 'SPENT'
  clear(record.endpoint)
  record.endpoint = null
  record.offer = null
  return offer
}

function releaseRelayDialReservation(state) {
  if (!state || !state.reserved) return false
  state.reserved = false
  pendingRelayDials--
  return true
}

function finalizeRelayDialAuthority(state, terminal) {
  if (!state || state.terminal) return false
  state.terminal = true
  state.phase = terminal
  RELAY_DIAL_AUTHORITIES.delete(state.capability)
  if (terminal === 'DESTROYED') {
    DESTROYED_RELAY_DIAL_AUTHORITIES.add(state.capability)
  } else {
    SPENT_RELAY_DIAL_AUTHORITIES.add(state.capability)
  }
  if (state.factoryState && state.factoryState !== TERMINAL_EXTENSION_ADJACENT_BINDING) {
    state.factoryState.dialSpent = true
  }
  spendSocketOwnerLease(state.socketOwnerLease)
  state.socketOwnerLease = null
  state.socketOwner = null
  state.dial = null
  if (!state.dialPending) releaseRelayDialReservation(state)
  return true
}

function createRelayAdjacentDialAuthority(options) {
  const values = exactOwnData(options, RELAY_DIAL_AUTHORITY_OPTIONS)
  const socketOwner = values.socketOwner
  const allowedRole = values.allowedRole
  const dial = values.dial
  const destroyOwner = values.destroy
  if (
    socketOwner === null ||
    typeof socketOwner !== 'object' ||
    arrayIsArrayIntrinsic(socketOwner) ||
    (allowedRole !== ROLE.SAFETY && allowedRole !== ROLE.PRIVATE) ||
    typeof dial !== 'function' ||
    typeof destroyOwner !== 'function'
  ) {
    invokeNoArguments(destroyOwner)
    invalid()
  }

  const socketOwnerLease = createSocketOwnerLease(socketOwner, destroyOwner)
  const capability = objectFreezeIntrinsic({})
  RELAY_DIAL_AUTHORITIES.set(capability, {
    capability,
    phase: 'UNUSED',
    terminal: false,
    reserved: false,
    dialPending: false,
    socketOwner,
    socketOwnerLease,
    allowedRole,
    dial,
    factoryState: null,
    generation: objectFreezeIntrinsic({})
  })
  return capability
}

function transferRelayDialAuthority(state) {
  if (!state || state.terminal) return null
  state.terminal = true
  state.phase = 'TRANSFERRED'
  RELAY_DIAL_AUTHORITIES.delete(state.capability)
  SPENT_RELAY_DIAL_AUTHORITIES.add(state.capability)
  if (state.factoryState && state.factoryState !== TERMINAL_EXTENSION_ADJACENT_BINDING) {
    state.factoryState.dialSpent = true
  }
  const lease = state.socketOwnerLease
  state.socketOwnerLease = null
  state.socketOwner = null
  state.dial = null
  releaseRelayDialReservation(state)
  return lease
}

function clearDialEndpoint(endpoint) {
  clear(endpoint)
}

function dialRelayAdvertisement(authority, options) {
  const state =
    authority !== null && typeof authority === 'object'
      ? RELAY_DIAL_AUTHORITIES.get(authority)
      : null
  if (!state) {
    if (
      authority !== null &&
      typeof authority === 'object' &&
      DESTROYED_RELAY_DIAL_AUTHORITIES.has(authority)
    ) {
      destroyed()
    }
    authentication()
  }
  if (state.phase !== 'UNUSED') authentication()

  state.phase = 'DIALING'
  state.generation = objectFreezeIntrinsic({})
  if (pendingRelayDials >= MAX_PENDING_OFFERS) {
    finalizeRelayDialAuthority(state, 'SPENT')
    busy()
  }
  pendingRelayDials++
  state.reserved = true

  let values = null
  let decoded = null
  let advertisementDigest = null
  let endpoint = null
  let stagedOffer = null
  try {
    values = exactOwnData(options, RELAY_DIAL_OPTIONS)

    if (
      state.terminal ||
      RELAY_DIAL_AUTHORITIES.get(authority) !== state ||
      state.phase !== 'DIALING'
    ) {
      finalizeRelayDialAuthority(state, 'DESTROYED')
      destroyed()
    }

    const operation = state.factoryState && state.factoryState.operation
    if (operation === null || operation === undefined) {
      finalizeRelayDialAuthority(state, 'SPENT')
      destroyed()
    }

    const now = operation.wallNow()
    if (
      !u64(now) ||
      values.requiredRole !== state.allowedRole ||
      values.requiredRole !== operation.requiredRole ||
      values.wireExpiresAt !== operation.wireExpiresAt ||
      values.localDeadline !== operation.localDeadline
    ) {
      finalizeRelayDialAuthority(state, 'SPENT')
      authentication()
    }

    decoded = decodeRelayCapabilityAdvertisement(values.advertisement, { now })
    advertisementDigest = digestRelayCapabilityAdvertisement(values.advertisement, { now })
    if (
      !equal(advertisementDigest, values.advertisementDigest) ||
      roleForIdentity(decoded.relayIdentity) !== values.requiredRole ||
      values.wireExpiresAt > decoded.expiresAtMs
    ) {
      finalizeRelayDialAuthority(state, 'SPENT')
      authentication()
    }

    endpoint = copy(decoded.reachableEndpoint, CANONICAL_ENDPOINT_SIZE)
    state.dialPending = true
    let promise = null
    stagedOffer = stageRelayAdjacentOffer(
      state.socketOwner,
      state.generation,
      endpoint,
      operation.setupOffer
    )
    try {
      promise = state.dial(state.socketOwner, endpoint)
    } catch (err) {
      state.dialPending = false
      releaseRelayDialReservation(state)
      throw err
    }
    retireStagedRelayAdjacentOffer(stagedOffer)
    stagedOffer = null
    if (!promise || typeof promise.then !== 'function') {
      state.dialPending = false
      releaseRelayDialReservation(state)
      if (isExtensionResponseReceiver(promise)) {
        try {
          destroyExtensionResponseReceiver(promise)
        } catch {}
      }
      clearDialEndpoint(endpoint)
      endpoint = null
      finalizeRelayDialAuthority(state, 'SPENT')
      invalid()
    }
    return promise.then(
      (receiver) => {
        state.dialPending = false
        releaseRelayDialReservation(state)
        if (!isExtensionResponseReceiver(receiver)) {
          clearDialEndpoint(endpoint)
          endpoint = null
          finalizeRelayDialAuthority(state, 'SPENT')
          routeUnavailable()
        }
        const liveOperation = state.factoryState && state.factoryState.operation
        const currentWall = operation.wallNow()
        const currentMonotonic = operation.monotonicNow()
        if (
          state.terminal ||
          RELAY_DIAL_AUTHORITIES.get(authority) !== state ||
          state.phase !== 'DIALING' ||
          liveOperation !== operation ||
          !u64(currentWall) ||
          !u64(currentMonotonic) ||
          currentWall >= operation.wireExpiresAt ||
          currentMonotonic >= operation.localDeadline
        ) {
          try {
            destroyExtensionResponseReceiver(receiver)
          } catch {}
          clearDialEndpoint(endpoint)
          endpoint = null
          finalizeRelayDialAuthority(state, 'SPENT')
          routeUnavailable()
        }
        const lease = transferRelayDialAuthority(state)
        if (!lease) {
          try {
            destroyExtensionResponseReceiver(receiver)
          } catch {}
          destroyed()
        }
        operation.socketOwnerLease = lease
        operation.receiver = receiver
        clearDialEndpoint(endpoint)
        endpoint = null
        return receiver
      },
      () => {
        state.dialPending = false
        releaseRelayDialReservation(state)
        clearDialEndpoint(endpoint)
        endpoint = null
        finalizeRelayDialAuthority(state, 'SPENT')
        routeUnavailable()
      }
    )
  } catch (err) {
    if (!state.terminal) finalizeRelayDialAuthority(state, 'SPENT')
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    retireStagedRelayAdjacentOffer(stagedOffer)
    clearDecoded(decoded)
    clear(advertisementDigest)
  }
}

function destroyRelayAdjacentDialAuthority(authority) {
  const state =
    authority !== null && typeof authority === 'object'
      ? RELAY_DIAL_AUTHORITIES.get(authority)
      : null
  if (!state) return false
  return finalizeRelayDialAuthority(state, 'DESTROYED')
}

function bestEffortExtensionAdjacentFactoryInputs(options) {
  const values = objectCreateIntrinsic(null)
  values.dialAuthority = ownDataCandidate(options, 'dialAuthority')
  values.linkOfferSigner = ownDataCandidate(options, 'linkOfferSigner')
  values.proofVerifier = ownDataCandidate(options, 'proofVerifier')
  values.proofConsumer = ownDataCandidate(options, 'proofConsumer')
  values.destroy = ownDataCandidate(options, 'destroy')
  return values
}

function cleanupExtensionAdjacentFactoryInputs(values) {
  const authority = values && values.dialAuthority
  const signer = values && values.linkOfferSigner
  const destroyOwner = values && values.destroy
  const authorityState =
    authority !== null && typeof authority === 'object'
      ? RELAY_DIAL_AUTHORITIES.get(authority)
      : null
  const ownsAuthority =
    authorityState && authorityState.phase === 'UNUSED' && authorityState.factoryState === null
  if (ownsAuthority) authorityState.factoryState = TERMINAL_EXTENSION_ADJACENT_BINDING
  try {
    try {
      destroyLinkOfferSigner(signer)
    } catch {}
    invokeNoArguments(destroyOwner)
  } finally {
    if (ownsAuthority) destroyRelayAdjacentDialAuthority(authority)
  }
}

function createExtensionAdjacentLinkFactory(options) {
  let values = null
  try {
    values = exactOwnData(options, EXTENSION_ADJACENT_FACTORY_OPTIONS)
    const authorityState =
      values.dialAuthority !== null && typeof values.dialAuthority === 'object'
        ? RELAY_DIAL_AUTHORITIES.get(values.dialAuthority)
        : null
    if (!authorityState || authorityState.phase !== 'UNUSED' || authorityState.factoryState) {
      authentication()
    }
    if (
      values.linkOfferSigner === null ||
      typeof values.linkOfferSigner !== 'object' ||
      values.proofVerifier === null ||
      typeof values.proofVerifier !== 'object' ||
      values.proofConsumer === null ||
      typeof values.proofConsumer !== 'object' ||
      typeof values.wallNow !== 'function' ||
      typeof values.monotonicNow !== 'function' ||
      typeof values.randomBytes !== 'function' ||
      typeof values.schedule !== 'function' ||
      typeof values.cancelScheduled !== 'function' ||
      typeof values.destroy !== 'function'
    ) {
      invalid()
    }

    const capability = objectFreezeIntrinsic({})
    const state = {
      capability,
      dialAuthority: values.dialAuthority,
      linkOfferSigner: values.linkOfferSigner,
      proofVerifier: values.proofVerifier,
      proofConsumer: values.proofConsumer,
      wallNow: values.wallNow,
      monotonicNow: values.monotonicNow,
      randomBytes: values.randomBytes,
      schedule: values.schedule,
      cancelScheduled: values.cancelScheduled,
      destroyOwner: values.destroy,
      operation: null,
      dialSpent: false
    }
    EXTENSION_ADJACENT_FACTORIES.set(capability, state)
    authorityState.factoryState = state
    return capability
  } catch (err) {
    cleanupExtensionAdjacentFactoryInputs(
      values || bestEffortExtensionAdjacentFactoryInputs(options)
    )
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function cancelExtensionAdjacentOperationTimer(operation) {
  if (!operation) return
  const handle = operation.timer
  if (handle === null || handle === undefined) return
  operation.timer = null
  operation.timerGeneration++
  try {
    reflectApplyIntrinsic(operation.cancelScheduled, undefined, [handle])
  } catch {}
}

function rejectExtensionAdjacentOperation(operation) {
  if (!operation || typeof operation.reject !== 'function') return
  const reject = operation.reject
  operation.reject = null
  try {
    reject(PrivateRouteError.ROUTE_UNAVAILABLE())
  } catch {}
}

function destroyExtensionAdjacentOperation(operation) {
  if (!operation) return
  cancelExtensionAdjacentOperationTimer(operation)
  abortExtensionLinkOffer(operation.pending)
  destroyExtensionResponseReceiver(operation.receiver)
  spendSocketOwnerLease(operation.socketOwnerLease)
  clear(operation.setupOffer)
  operation.pending = null
  operation.receiver = null
  operation.socketOwnerLease = null
  operation.setupOffer = null
}

function expireExtensionAdjacentOperation(state, operation) {
  if (!state || state.operation !== operation) return
  rejectExtensionAdjacentOperation(operation)
  state.operation = null
  destroyExtensionAdjacentOperation(operation)
  if (operation.dialStarted) destroyRelayAdjacentDialAuthority(state.dialAuthority)
}

function runExtensionAdjacentOperationTimer(state, operation) {
  if (!state || state.operation !== operation) return
  try {
    const current = clockValue(operation.monotonicNow)
    if (current < operation.localDeadline) {
      armExtensionAdjacentOperationTimer(
        state,
        operation,
        timerDelay(operation.localDeadline - current)
      )
      return
    }
  } catch {}
  expireExtensionAdjacentOperation(state, operation)
}

function armExtensionAdjacentOperationTimer(state, operation, delay) {
  const generation = ++operation.timerGeneration
  let arming = true
  let fired = false
  let handle = null
  const onExpiry = () => {
    if (arming) {
      fired = true
      return
    }
    if (state.operation !== operation || operation.timerGeneration !== generation) return
    operation.timer = null
    runExtensionAdjacentOperationTimer(state, operation)
  }
  try {
    handle = reflectApplyIntrinsic(operation.schedule, undefined, [onExpiry, delay])
  } catch {
    arming = false
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
  arming = false
  if (
    handle === null ||
    handle === undefined ||
    fired ||
    state.operation !== operation ||
    operation.timerGeneration !== generation
  ) {
    operation.timerGeneration++
    if (handle !== null && handle !== undefined) {
      try {
        reflectApplyIntrinsic(operation.cancelScheduled, undefined, [handle])
      } catch {}
    }
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
  operation.timer = handle
}

function abortExtensionAdjacentLink(factory) {
  const state =
    factory !== null && typeof factory === 'object'
      ? EXTENSION_ADJACENT_FACTORIES.get(factory)
      : null
  if (!state || state.operation === null) return false
  const operation = state.operation
  rejectExtensionAdjacentOperation(operation)
  state.operation = null
  destroyExtensionAdjacentOperation(operation)
  if (operation.dialStarted) destroyRelayAdjacentDialAuthority(state.dialAuthority)
  return true
}

function openExtensionAdjacentLink(factory, admittedRequest) {
  const state =
    factory !== null && typeof factory === 'object'
      ? EXTENSION_ADJACENT_FACTORIES.get(factory)
      : null
  if (!state) {
    if (
      factory !== null &&
      typeof factory === 'object' &&
      SPENT_EXTENSION_ADJACENT_FACTORIES.has(factory)
    ) {
      destroyed()
    }
    authentication()
  }
  if (state.operation !== null || state.dialSpent) busy()
  const operation = {
    pending: null,
    receiver: null,
    socketOwnerLease: null,
    setupOffer: null,
    requiredRole: null,
    wireExpiresAt: 0n,
    localDeadline: 0n,
    wallNow: state.wallNow,
    monotonicNow: state.monotonicNow,
    schedule: state.schedule,
    cancelScheduled: state.cancelScheduled,
    timer: null,
    timerGeneration: 0,
    dialStarted: false,
    reject: null
  }
  state.operation = operation
  let pending = null
  try {
    const offerWall = state.wallNow()
    const offerMonotonic = state.monotonicNow()
    const offered = createExtensionLinkOffer(admittedRequest, {
      now: offerWall,
      monotonicNow: offerMonotonic,
      randomBytes: state.randomBytes,
      linkOfferSigner: state.linkOfferSigner
    })
    pending = offered.pending
    operation.pending = pending
    operation.setupOffer = copy(offered.offer, LINK_OFFER_SIZE)
    const pendingState = EXTENSION_PENDING.get(pending)
    if (!pendingState) invalid()
    operation.requiredRole = pendingState.requiredRole
    operation.wireExpiresAt = pendingState.wireExpiresAt
    const currentWall = clockValue(operation.wallNow)
    const currentMonotonic = clockValue(operation.monotonicNow)
    if (currentWall >= pendingState.wireExpiresAt) authentication()
    operation.localDeadline = pendingState.localDeadline
    if (!u64(operation.localDeadline) || currentMonotonic >= operation.localDeadline) {
      authentication()
    }
    armExtensionAdjacentOperationTimer(
      state,
      operation,
      timerDelay(operation.localDeadline - currentMonotonic)
    )
    operation.dialStarted = true
    const cancelled = new Promise((resolve, reject) => {
      operation.reject = reject
    })
    let dialPromise = null
    try {
      dialPromise = dialRelayAdvertisement(state.dialAuthority, {
        advertisement: pendingState.advertisement,
        advertisementDigest: pendingState.advertisementDigest,
        requiredRole: pendingState.requiredRole,
        wireExpiresAt: pendingState.wireExpiresAt,
        localDeadline: operation.localDeadline
      })
    } finally {
      clear(operation.setupOffer)
      operation.setupOffer = null
    }
    const dial = dialPromise.then(
      (receiver) => {
        try {
          if (state.operation !== operation || operation.pending !== pending) destroyed()
          const completion = completeExtensionLink(pending, {
            now: state.wallNow,
            proofVerifier: state.proofVerifier,
            proofConsumer: state.proofConsumer,
            setupReceiver: receiver,
            socketOwnerLease: operation.socketOwnerLease
          })
          if (state.operation !== operation || operation.pending !== pending) {
            destroyExtensionLinkCompletion(completion)
            destroyed()
          }
          pending = null
          operation.pending = null
          operation.receiver = null
          operation.socketOwnerLease = null
          operation.reject = null
          cancelExtensionAdjacentOperationTimer(operation)
          state.operation = null
          return completion
        } catch (err) {
          if (state.operation === operation) state.operation = null
          operation.reject = null
          destroyExtensionAdjacentOperation(operation)
          throw err
        }
      },
      () => {
        if (state.operation === operation) state.operation = null
        operation.reject = null
        destroyExtensionAdjacentOperation(operation)
        routeUnavailable()
      }
    )
    return Promise.race([dial, cancelled])
  } catch (err) {
    if (state.operation === operation) state.operation = null
    destroyExtensionAdjacentOperation(operation)
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function destroyExtensionAdjacentLinkFactory(factory) {
  const state =
    factory !== null && typeof factory === 'object'
      ? EXTENSION_ADJACENT_FACTORIES.get(factory)
      : null
  if (!state) return false
  EXTENSION_ADJACENT_FACTORIES.delete(factory)
  SPENT_EXTENSION_ADJACENT_FACTORIES.add(factory)
  const dialAuthority = state.dialAuthority
  const linkOfferSigner = state.linkOfferSigner
  const destroyOwner = state.destroyOwner
  state.dialAuthority = null
  state.linkOfferSigner = null
  state.proofVerifier = null
  state.proofConsumer = null
  state.wallNow = null
  state.monotonicNow = null
  state.randomBytes = null
  state.schedule = null
  state.cancelScheduled = null
  state.destroyOwner = null
  const operation = state.operation
  rejectExtensionAdjacentOperation(operation)
  state.operation = null
  destroyExtensionAdjacentOperation(operation)
  try {
    destroyLinkOfferSigner(linkOfferSigner)
  } catch {}
  invokeNoArguments(destroyOwner)
  destroyRelayAdjacentDialAuthority(dialAuthority)
  return true
}

function createIndexZeroGuardLinkOffer(options = {}) {
  let advertisement = null
  let branchId = null
  let circuitId = null
  let clientPublicKey = null
  let clientSecretKey = null
  let clientTailEphemeralPublicKey = null
  let clientTailEphemeralSecretKey = null
  let payloadParametersDigest = null
  let requestedLimits = null
  let decodedAdvertisement = null
  let advertisementDigest = null
  let seed = null
  let pair = null
  let clientNonce = null
  let body = null
  let input = null
  let signature = null
  let pending = null
  let pendingState = null
  let pendingOffer = null
  let installed = false
  let complete = false
  try {
    advertisement = copy(safe(options, 'advertisement'))
    const now = safe(options, 'now')
    const randomBytes = safe(options, 'randomBytes') || cryptoSuite.randomBytes
    const branchClass = safe(options, 'branchClass')
    branchId = copy(safe(options, 'branchId'), 16)
    circuitId = copy(safe(options, 'circuitId'), 16)
    const generation = safe(options, 'generation')
    const client = safe(options, 'clientCircuitIdentity')
    clientPublicKey = copy(safe(client, 'publicKey'), 32)
    clientSecretKey = copy(safe(client, 'secretKey'), 64)
    const clientTailEphemeral = safe(options, 'clientTailEphemeral')
    clientTailEphemeralPublicKey = copy(safe(clientTailEphemeral, 'publicKey'), 32)
    clientTailEphemeralSecretKey = copy(safe(clientTailEphemeral, 'secretKey'), 32)
    payloadParametersDigest = copy(safe(options, 'payloadParametersDigest'), 32)
    requestedLimits = encodeLimits(safe(options, 'requestedLimits'))
    if (
      !u64(now) ||
      (branchClass !== BRANCH_CLASS.LOOKUP && branchClass !== BRANCH_CLASS.ANNOUNCE) ||
      !u64(generation) ||
      generation === 0n ||
      typeof randomBytes !== 'function'
    ) {
      invalid()
    }
    decodedAdvertisement = decodeRelayCapabilityAdvertisement(advertisement, { now })
    advertisementDigest = digestRelayCapabilityAdvertisement(advertisement, { now })
    seed = copy(randomBytes(32), 32)
    pair = cryptoSuite.encryptionKeyPair(seed)
    clientNonce = copy(randomBytes(32), 32)
    let deadline = now + MAX_ADJACENT_LINK_MS
    const limits = decodeLimits(requestedLimits)
    if (!limitsWithinAdvertisement(limits, decodedAdvertisement, now)) invalid()
    if (limits.expiresAtMs < deadline) deadline = limits.expiresAtMs
    if (decodedAdvertisement.expiresAtMs < deadline) deadline = decodedAdvertisement.expiresAtMs
    if (deadline <= now) invalid()
    body = b4a.allocUnsafeSlow(LINK_OFFER_BODY_SIZE)
    setIntrinsic.call(body, advertisementDigest, 0)
    setIntrinsic.call(body, clientPublicKey, 32)
    setIntrinsic.call(body, decodedAdvertisement.relayIdentity, 64)
    body[96] = M3_LINK_ROLE.CLIENT
    body[97] = M3_LINK_ROLE.SAFETY_RELAY
    body[98] = branchClass
    setIntrinsic.call(body, branchId, 99)
    setIntrinsic.call(body, circuitId, 115)
    writeU64(body, generation, 131)
    body[139] = 0
    setIntrinsic.call(body, pair.publicKey, 140)
    setIntrinsic.call(body, clientTailEphemeralPublicKey, 172)
    setIntrinsic.call(body, clientNonce, 204)
    setIntrinsic.call(body, payloadParametersDigest, 236)
    setIntrinsic.call(body, requestedLimits, 268)
    writeU64(body, deadline, 294)
    input = signatureInput(LINK_OFFER_DOMAIN, M3_MESSAGE_ID.LINK_OFFER_V1, body)
    signature = cryptoSuite.sign(input, clientSecretKey)
    const offer = encodeM3Object({
      messageId: M3_MESSAGE_ID.LINK_OFFER_V1,
      body,
      authSuffix: signature
    })
    pending = Object.freeze({})
    prunePending(now)
    if (PENDING_TOKENS.size >= MAX_PENDING_OFFERS) throw PrivateRouteError.ERR_BUSY()
    const pendingAdvertisementDigest = copy(advertisementDigest, 32)
    let pendingEphemeralSecretKey = null
    let pendingTailSecretKey = null
    try {
      pendingEphemeralSecretKey = copy(pair.secretKey, 32)
      pendingOffer = decodeOffer(offer)
      pendingTailSecretKey = copy(clientTailEphemeralSecretKey, 32)
      pendingOffer.clientTailEphemeralSecretKey = pendingTailSecretKey
      pendingTailSecretKey = null
      pendingState = {
        advertisementDigest: pendingAdvertisementDigest,
        ephemeralSecretKey: pendingEphemeralSecretKey,
        offer: pendingOffer
      }
      pendingEphemeralSecretKey = null
      pendingOffer = null
    } finally {
      if (!pendingState) clear(pendingAdvertisementDigest)
      clear(pendingEphemeralSecretKey)
      clear(pendingTailSecretKey)
      clearDecoded(pendingOffer)
    }
    PENDING.set(pending, pendingState)
    pendingState = null
    PENDING_TOKENS.add(pending)
    installed = true
    complete = true
    return Object.freeze({ offer, pending })
  } finally {
    if (installed && !complete) abortIndexZeroGuardLink(pending)
    clearPending(pendingState)
    clearDecoded(pendingOffer)
    clear(advertisement)
    clear(branchId)
    clear(circuitId)
    clear(clientPublicKey)
    clear(clientSecretKey)
    clear(clientTailEphemeralPublicKey)
    clear(clientTailEphemeralSecretKey)
    clear(payloadParametersDigest)
    clear(requestedLimits)
    clearDecoded(decodedAdvertisement)
    clear(advertisementDigest)
    clear(seed)
    clear(pair && pair.publicKey)
    clear(pair && pair.secretKey)
    clear(clientNonce)
    clear(body)
    clear(input)
    clear(signature)
  }
}

function receiveGuardOffer(receiveOffer) {
  let physicalChannel = null
  try {
    const received = receiveOffer()
    physicalChannel = safe(received, 'physicalChannel')
    if (
      physicalChannel === null ||
      typeof physicalChannel !== 'object' ||
      typeof physicalChannel.destroy !== 'function'
    ) {
      invalid()
    }
    if (!exactKeys(received, ['offer', 'observedPredecessorEndpoint', 'physicalChannel'])) {
      invalid()
    }
    const result = {
      offer: copy(safe(received, 'offer'), LINK_OFFER_SIZE),
      observedPredecessorEndpoint: decodeCanonicalEndpoint(
        safe(received, 'observedPredecessorEndpoint')
      ),
      physicalChannel
    }
    physicalChannel = null
    return result
  } finally {
    try {
      if (physicalChannel) physicalChannel.destroy()
    } catch {}
  }
}

function createIndexZeroGuardLinkResponder(options = {}) {
  const {
    advertisement,
    responderIdentitySecretKey,
    responderRouteEncryptionSecretKey,
    now,
    receiveOffer,
    randomBytes = cryptoSuite.randomBytes
  } = options
  const counterFactory = options[TEST_ONLY_COUNTER_FACTORY] || createCounter
  if (
    typeof now !== 'function' ||
    typeof receiveOffer !== 'function' ||
    typeof randomBytes !== 'function' ||
    typeof counterFactory !== 'function'
  ) {
    invalid()
  }
  let advertisementBytes = null
  let responderSecretKey = null
  let responderRouteSecretKey = null
  let decodedAdvertisement = null
  let identitySeed = null
  let identityPair = null
  let routePublicKey = null
  try {
    advertisementBytes = copy(advertisement)
    responderSecretKey = copy(responderIdentitySecretKey, 64)
    responderRouteSecretKey = copy(responderRouteEncryptionSecretKey, 32)
    const current = now()
    if (!u64(current)) invalid()
    decodedAdvertisement = decodeRelayCapabilityAdvertisement(advertisementBytes, {
      now: current
    })
    identitySeed = copy(subarray(responderSecretKey, 0, 32), 32)
    identityPair = cryptoSuite.keyPair(identitySeed)
    routePublicKey = b4a.allocUnsafeSlow(32)
    sodium.crypto_scalarmult_base(routePublicKey, responderRouteSecretKey)
    if (
      !equal(identityPair.publicKey, decodedAdvertisement.relayIdentity) ||
      !equal(routePublicKey, decodedAdvertisement.routeEncryptionPublicKey)
    ) {
      authentication()
    }
  } catch (err) {
    clear(advertisementBytes)
    clear(responderSecretKey)
    clear(responderRouteSecretKey)
    throw err
  } finally {
    clearDecoded(decodedAdvertisement)
    clear(identitySeed)
    clear(identityPair && identityPair.secretKey)
    clear(identityPair && identityPair.publicKey)
    clear(routePublicKey)
  }
  const replayCache = new Map()
  let isDestroyed = false
  let generation = Object.freeze({})
  const assertGeneration = (operationGeneration) => {
    if (isDestroyed || generation !== operationGeneration) {
      throw PrivateRouteError.ERR_DESTROYED()
    }
  }
  return Object.freeze({
    accept() {
      if (isDestroyed) throw PrivateRouteError.ERR_DESTROYED()
      const operationGeneration = generation
      let received = null
      let physicalChannel = null
      let offer = null
      let advertisementDigest = null
      let decodedAdvertisement = null
      let offerDigest = null
      let expectedParametersDigest = null
      let seed = null
      let pair = null
      let acceptNonce = null
      let admittedLimits = null
      let body = null
      let input = null
      let signature = null
      let shared = null
      let tailShared = null
      let decodedAccept = null
      let replayKey = null
      let replayReservation = null
      let replayCommitted = false
      let randomScratch = null
      let derivedState = null
      try {
        const current = now()
        assertGeneration(operationGeneration)
        if (!u64(current)) invalid()
        received = receiveGuardOffer(receiveOffer)
        assertGeneration(operationGeneration)
        physicalChannel = received.physicalChannel
        offer = decodeOffer(received.offer)
        validOffer(offer, current)
        decodedAdvertisement = decodeRelayCapabilityAdvertisement(advertisementBytes, {
          now: current
        })
        advertisementDigest = digestRelayCapabilityAdvertisement(advertisementBytes, {
          now: current
        })
        expectedParametersDigest = digestPayloadParameters(decodedAdvertisement)
        offerDigest = digest(LINK_OFFER_DIGEST_DOMAIN, offer.encoded)
        replayKey = b4a.toString(offerDigest, 'hex')
        for (const [key, reservation] of replayCache) {
          if (reservation.expiresAt <= current) replayCache.delete(key)
        }
        if (replayCache.has(replayKey)) replay()
        if (replayCache.size >= MAX_RESPONDER_REPLAYS) throw PrivateRouteError.ERR_BUSY()
        if (
          !equal(offer.responderIdentity, decodedAdvertisement.relayIdentity) ||
          !equal(offer.responderAdvertisementDigest, advertisementDigest) ||
          !equal(offer.payloadParametersDigest, expectedParametersDigest)
        ) {
          authentication()
        }
        if (!limitsWithinAdvertisement(offer.requestedLimits, decodedAdvertisement, current)) {
          authentication()
        }
        replayReservation = {
          completed: false,
          expiresAt: offer.offerDeadlineMs
        }
        replayCache.set(replayKey, replayReservation)
        tailShared = cryptoSuite.keyAgreement(
          responderRouteSecretKey,
          offer.clientTailEphemeralPublicKey
        )
        randomScratch = randomBytes(32)
        assertGeneration(operationGeneration)
        seed = copy(randomScratch, 32)
        clear(randomScratch)
        randomScratch = null
        pair = cryptoSuite.encryptionKeyPair(seed)
        randomScratch = randomBytes(32)
        assertGeneration(operationGeneration)
        acceptNonce = copy(randomScratch, 32)
        clear(randomScratch)
        randomScratch = null
        admittedLimits = encodeLimits(offer.requestedLimits)
        body = b4a.allocUnsafeSlow(LINK_ACCEPT_BODY_SIZE)
        setIntrinsic.call(body, offerDigest, 0)
        setIntrinsic.call(body, advertisementDigest, 32)
        setIntrinsic.call(body, decodedAdvertisement.relayIdentity, 64)
        setIntrinsic.call(body, received.observedPredecessorEndpoint, 96)
        setIntrinsic.call(body, pair.publicKey, 115)
        setIntrinsic.call(body, admittedLimits, 147)
        writeU64(body, current, 173)
        setIntrinsic.call(body, acceptNonce, 181)
        input = signatureInput(LINK_ACCEPT_DOMAIN, M3_MESSAGE_ID.LINK_ACCEPT_V1, body)
        signature = cryptoSuite.sign(input, responderSecretKey)
        const accept = encodeM3Object({
          messageId: M3_MESSAGE_ID.LINK_ACCEPT_V1,
          body,
          authSuffix: signature
        })
        decodedAccept = decodeAccept(accept)
        shared = cryptoSuite.keyAgreement(pair.secretKey, offer.initiatorLinkEphemeralPublicKey)
        assertGeneration(operationGeneration)
        if (replayCache.get(replayKey) !== replayReservation) replay()
        derivedState = deriveState(
          shared,
          tailShared,
          offer,
          decodedAccept,
          false,
          physicalChannel,
          now,
          decodedAdvertisement.routeEncryptionPublicKey,
          counterFactory
        )
        physicalChannel = null
        assertGeneration(operationGeneration)
        if (replayCache.get(replayKey) !== replayReservation) replay()
        const established = establish(derivedState)
        derivedState = null
        replayReservation.completed = true
        replayCommitted = true
        return Object.freeze({ accept, established })
      } finally {
        if (
          replayReservation &&
          !replayCommitted &&
          replayCache.get(replayKey) === replayReservation
        ) {
          replayCache.delete(replayKey)
        }
        try {
          if (physicalChannel) physicalChannel.destroy()
        } catch {}
        clear(received && received.offer)
        clear(received && received.observedPredecessorEndpoint)
        clearDecoded(offer)
        clearDecoded(decodedAdvertisement)
        clear(advertisementDigest)
        clear(offerDigest)
        clear(expectedParametersDigest)
        clear(seed)
        clear(pair && pair.publicKey)
        clear(pair && pair.secretKey)
        clear(acceptNonce)
        clear(admittedLimits)
        clear(body)
        clear(input)
        clear(signature)
        clear(shared)
        clear(tailShared)
        clearDecoded(decodedAccept)
        clear(randomScratch)
        clearState(derivedState)
      }
    },
    destroy() {
      if (isDestroyed) return false
      isDestroyed = true
      generation = null
      clear(advertisementBytes)
      clear(responderSecretKey)
      clear(responderRouteSecretKey)
      replayCache.clear()
      return true
    }
  })
}

function createExtensionLinkOffer(admittedRequest, options = {}) {
  let material = null
  let decodedAdvertisement = null
  let advertisementDigest = null
  let expectedPayloadParametersDigest = null
  let requestedLimits = null
  let seed = null
  let pair = null
  let body = null
  let input = null
  let signature = null
  let offer = null
  let pendingState = null
  const pending = Object.freeze({})
  let reserved = false
  let installed = false
  let complete = false
  try {
    const resourceDeadline = extensionResourceTime() + 5_000n
    pruneExtensionPending(resourceDeadline - 5_000n)
    if (EXTENSION_PENDING_TOKENS.size >= MAX_PENDING_OFFERS) {
      throw PrivateRouteError.ERR_BUSY()
    }
    EXTENSION_PENDING_TOKENS.add(pending)
    reserved = true
    material = takeAdmittedExtendRequest(admittedRequest)
    const now = safe(options, 'now')
    const monotonicNow = safe(options, 'monotonicNow')
    const randomBytes = safe(options, 'randomBytes') || cryptoSuite.randomBytes
    const linkOfferSigner = safe(options, 'linkOfferSigner')
    if (!u64(now) || !u64(monotonicNow) || typeof randomBytes !== 'function') {
      invalid()
    }
    const request = material.request
    decodedAdvertisement = decodeRelayCapabilityAdvertisement(request.advertisement, { now })
    advertisementDigest = digestRelayCapabilityAdvertisement(request.advertisement, { now })
    expectedPayloadParametersDigest = digestPayloadParameters(decodedAdvertisement)
    requestedLimits = encodeLimits(request.requestedLimits)
    const limits = decodeLimits(requestedLimits)
    const expectedResponderRole =
      request.extensionIndex === 1 ? M3_LINK_ROLE.SAFETY_RELAY : M3_LINK_ROLE.DHT_EXIT
    const expectedIdentityRole = request.extensionIndex === 1 ? ROLE.SAFETY : ROLE.PRIVATE
    if (
      (request.extensionIndex !== 1 && request.extensionIndex !== 2) ||
      roleForIdentity(material.currentTailIdentity) !== ROLE.SAFETY ||
      roleForIdentity(decodedAdvertisement.relayIdentity) !== expectedIdentityRole ||
      equal(material.currentTailIdentity, decodedAdvertisement.relayIdentity) ||
      !equal(request.payloadParametersDigest, expectedPayloadParametersDigest) ||
      !limitsWithinAdvertisement(limits, decodedAdvertisement, now) ||
      !nonzero(material.currentTailAdvertisementDigest)
    ) {
      authentication()
    }
    let deadline = material.wireExpiresAt
    if (now + MAX_ADJACENT_LINK_MS < deadline) deadline = now + MAX_ADJACENT_LINK_MS
    if (limits.expiresAtMs < deadline) deadline = limits.expiresAtMs
    if (decodedAdvertisement.expiresAtMs < deadline) {
      deadline = decodedAdvertisement.expiresAtMs
    }
    if (deadline <= now) authentication()
    const remaining = deadline - now
    const localDeadline = monotonicNow + remaining
    if (!u64(localDeadline) || localDeadline === 0n || localDeadline > material.localDeadline) {
      authentication()
    }
    seed = copy(randomBytes(32), 32)
    pair = cryptoSuite.encryptionKeyPair(seed)
    body = b4a.allocUnsafeSlow(LINK_OFFER_BODY_SIZE)
    if (!fixed(body, LINK_OFFER_BODY_SIZE)) invalid()
    setIntrinsic.call(body, advertisementDigest, 0)
    setIntrinsic.call(body, material.currentTailIdentity, 32)
    setIntrinsic.call(body, decodedAdvertisement.relayIdentity, 64)
    body[96] = M3_LINK_ROLE.SAFETY_RELAY
    body[97] = expectedResponderRole
    body[98] = request.branchClass
    setIntrinsic.call(body, request.branchId, 99)
    setIntrinsic.call(body, request.circuitId, 115)
    writeU64(body, request.generation, 131)
    body[139] = request.extensionIndex
    setIntrinsic.call(body, pair.publicKey, 140)
    setIntrinsic.call(body, request.clientTailEphemeralPublicKey, 172)
    setIntrinsic.call(body, request.clientNonce, 204)
    setIntrinsic.call(body, request.payloadParametersDigest, 236)
    setIntrinsic.call(body, requestedLimits, 268)
    writeU64(body, deadline, 294)
    input = signatureInput(LINK_OFFER_DOMAIN, M3_MESSAGE_ID.LINK_OFFER_V1, body)
    signature = signLinkOffer(linkOfferSigner, body, material.currentTailIdentity)
    if (
      !fixed(signature, 64) ||
      !cryptoSuite.verify(input, signature, material.currentTailIdentity)
    ) {
      authentication()
    }
    offer = encodeM3Object({
      messageId: M3_MESSAGE_ID.LINK_OFFER_V1,
      body,
      authSuffix: signature
    })
    if (!fixed(offer, LINK_OFFER_SIZE)) invalid()
    pendingState = {
      advertisement: copy(request.advertisement),
      advertisementDigest: copy(advertisementDigest, 32),
      advertisedRouteEncryptionPublicKey: copy(decodedAdvertisement.routeEncryptionPublicKey, 32),
      ephemeralSecretKey: copy(pair.secretKey, 32),
      extensionNonce: copy(request.extensionNonce, 32),
      offer: decodeOffer(offer),
      requiredRole: expectedIdentityRole,
      wireExpiresAt: deadline,
      localDeadline,
      inheritedLocalDeadline: material.localDeadline,
      deadline,
      resourceDeadline
    }
    EXTENSION_PENDING.set(pending, pendingState)
    installed = true
    pendingState = null
    complete = true
    return Object.freeze({ offer, pending })
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    if (reserved && !installed) EXTENSION_PENDING_TOKENS.delete(pending)
    clearAdmittedExtensionMaterial(material)
    clearDecoded(decodedAdvertisement)
    clear(advertisementDigest)
    clear(expectedPayloadParametersDigest)
    clear(requestedLimits)
    clear(seed)
    clear(pair && pair.publicKey)
    clear(pair && pair.secretKey)
    clear(body)
    clear(input)
    clear(signature)
    if (!complete) clear(offer)
    clearExtensionPending(pendingState)
  }
}

function abortExtensionLinkOffer(pending) {
  pruneExtensionPending(extensionResourceTime())
  const state =
    pending !== null && typeof pending === 'object' ? EXTENSION_PENDING.get(pending) : null
  if (!state) return false
  EXTENSION_PENDING.delete(pending)
  EXTENSION_PENDING_TOKENS.delete(pending)
  SPENT_EXTENSION_PENDING.add(pending)
  clearExtensionPending(state)
  return true
}

function receiveGuardOffer(receiveOffer) {
  let physicalChannel = null
  try {
    const received = receiveOffer()
    physicalChannel = safe(received, 'physicalChannel')
    if (
      physicalChannel === null ||
      typeof physicalChannel !== 'object' ||
      typeof physicalChannel.destroy !== 'function'
    ) {
      invalid()
    }
    if (!exactKeys(received, ['offer', 'observedPredecessorEndpoint', 'physicalChannel'])) {
      invalid()
    }
    const result = {
      offer: copy(safe(received, 'offer'), LINK_OFFER_SIZE),
      observedPredecessorEndpoint: decodeCanonicalEndpoint(
        safe(received, 'observedPredecessorEndpoint')
      ),
      physicalChannel
    }
    physicalChannel = null
    return result
  } finally {
    try {
      if (physicalChannel) physicalChannel.destroy()
    } catch {}
  }
}

function reserveResponderReplayOwner() {
  if (responderReplayOwners >= MAX_RESPONDER_REPLAYS) busy()
  responderReplayOwners++
}

function releaseResponderReplayOwner(state) {
  if (!state || !state.reserved) return
  state.reserved = false
  responderReplayOwners--
}

function cancelAcceptedExtensionOwnerTimer(state) {
  if (!state) return
  const handle = state.timer
  if (handle === null || handle === undefined) return
  state.timer = null
  state.timerGeneration++
  try {
    reflectApplyIntrinsic(state.cancelScheduled, undefined, [handle])
  } catch {}
}

function clearAcceptedExtensionOwnerState(state) {
  if (!state) return
  clear(state.offerDigest)
  clear(state.clientNonce)
  clear(state.acceptNonce)
  clear(state.proofNonce)
  clear(state.accept)
  clear(state.proof)
  state.offerDigest = null
  state.clientNonce = null
  state.acceptNonce = null
  state.proofNonce = null
  state.accept = null
  state.proof = null
  state.pair = null
}

function destroyAcceptedExtensionAdjacencyOwner(owner) {
  const state =
    owner !== null && typeof owner === 'object'
      ? ACCEPTED_EXTENSION_ADJACENCY_OWNERS.get(owner)
      : null
  if (!state) return false
  ACCEPTED_EXTENSION_ADJACENCY_OWNERS.delete(owner)
  SPENT_ACCEPTED_EXTENSION_ADJACENCY_OWNERS.add(owner)
  state.destroyed = true
  cancelAcceptedExtensionOwnerTimer(state)
  clearAcceptedExtensionOwnerState(state)
  releaseResponderReplayOwner(state)
  return true
}

function destroyAcceptedExtensionAdjacencyState(accepted, state) {
  if (!state) return false
  EXTENSION_RESPONDER_ADJACENCIES.delete(accepted)
  SPENT_EXTENSION_RESPONDER_ADJACENCIES.add(accepted)
  state.acceptedAdjacencies.delete(accepted)
  const adoption = state.adoption
  const replayOwner = state.replayOwner
  state.adoption = null
  state.replayOwner = null
  const ownerState = ACCEPTED_EXTENSION_ADJACENCY_OWNERS.get(replayOwner)
  if (ownerState) ownerState.pair = null
  try {
    destroyM3ResponderLink(adoption)
  } finally {
    destroyAcceptedExtensionAdjacencyOwner(replayOwner)
  }
  return true
}

function destroyAcceptedExtensionAdjacencyTransferState(transfer, state) {
  if (!state) return false
  ACCEPTED_EXTENSION_ADJACENCY_TRANSFERS.delete(transfer)
  SPENT_ACCEPTED_EXTENSION_ADJACENCY_TRANSFERS.add(transfer)
  const adoption = state.adoption
  const replayOwner = state.replayOwner
  state.adoption = null
  state.replayOwner = null
  const ownerState = ACCEPTED_EXTENSION_ADJACENCY_OWNERS.get(replayOwner)
  if (ownerState) ownerState.pair = null
  try {
    destroyM3ResponderLink(adoption)
  } finally {
    destroyAcceptedExtensionAdjacencyOwner(replayOwner)
  }
  return true
}

function expireAcceptedExtensionAdjacencyOwner(owner, state) {
  if (ACCEPTED_EXTENSION_ADJACENCY_OWNERS.get(owner) !== state) return
  const pair = state.pair
  if (pair && pair.accepted) {
    const acceptedState = EXTENSION_RESPONDER_ADJACENCIES.get(pair.accepted)
    if (acceptedState && acceptedState.replayOwner === owner) {
      destroyAcceptedExtensionAdjacencyState(pair.accepted, acceptedState)
      return
    }
  }
  if (pair && pair.transfer) {
    const transferState = ACCEPTED_EXTENSION_ADJACENCY_TRANSFERS.get(pair.transfer)
    if (transferState && transferState.replayOwner === owner) {
      destroyAcceptedExtensionAdjacencyTransferState(pair.transfer, transferState)
      return
    }
  }
  destroyAcceptedExtensionAdjacencyOwner(owner)
}

function sampleAcceptedExtensionOwnerMonotonic(owner, state) {
  const generation = state.timerGeneration
  const current = clockValue(state.monotonicNow)
  if (
    ACCEPTED_EXTENSION_ADJACENCY_OWNERS.get(owner) !== state ||
    state.timerGeneration !== generation
  ) {
    return null
  }
  if (current < state.lastMonotonic) {
    expireAcceptedExtensionAdjacencyOwner(owner, state)
    return null
  }
  state.lastMonotonic = current
  return current
}

function runAcceptedExtensionOwnerTimer(owner, state) {
  if (ACCEPTED_EXTENSION_ADJACENCY_OWNERS.get(owner) !== state) return
  try {
    const current = sampleAcceptedExtensionOwnerMonotonic(owner, state)
    if (current === null) return
    if (current < state.localDeadline) {
      armAcceptedExtensionOwnerTimer(owner, state, timerDelay(state.localDeadline - current))
      return
    }
  } catch {}
  expireAcceptedExtensionAdjacencyOwner(owner, state)
}

function armAcceptedExtensionOwnerTimer(owner, state, delay) {
  const generation = ++state.timerGeneration
  let arming = true
  let fired = false
  let handle = null
  const onExpiry = () => {
    if (arming) {
      fired = true
      return
    }
    if (
      ACCEPTED_EXTENSION_ADJACENCY_OWNERS.get(owner) !== state ||
      state.timerGeneration !== generation
    ) {
      return
    }
    state.timer = null
    runAcceptedExtensionOwnerTimer(owner, state)
  }
  try {
    handle = reflectApplyIntrinsic(state.schedule, undefined, [onExpiry, delay])
  } catch {
    arming = false
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
  arming = false
  if (
    handle === null ||
    handle === undefined ||
    fired ||
    ACCEPTED_EXTENSION_ADJACENCY_OWNERS.get(owner) !== state
  ) {
    state.timerGeneration++
    if (handle !== null && handle !== undefined) {
      try {
        reflectApplyIntrinsic(state.cancelScheduled, undefined, [handle])
      } catch {}
    }
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
  state.timer = handle
}

function createAcceptedExtensionAdjacencyOwner(options) {
  let owner = null
  let state = null
  let complete = false
  try {
    const wall = reflectApplyIntrinsic(options.wallNow, undefined, [])
    const monotonic = clockValue(options.monotonicNow)
    const remaining = options.wireExpiresAt - wall
    const localDeadline = monotonic + remaining
    if (remaining <= 0n || !u64(localDeadline) || localDeadline <= monotonic) authentication()
    owner = objectFreezeIntrinsic({})
    state = {
      offerDigest: null,
      clientNonce: null,
      acceptNonce: null,
      proofNonce: null,
      accept: null,
      proof: null,
      wireExpiresAt: options.wireExpiresAt,
      localDeadline,
      lastMonotonic: monotonic,
      monotonicNow: options.monotonicNow,
      schedule: options.schedule,
      cancelScheduled: options.cancelScheduled,
      timer: null,
      timerGeneration: 0,
      pair: null,
      reserved: true,
      answering: false,
      destroyed: false
    }
    state.offerDigest = copy(options.offerDigest, 32)
    state.clientNonce = copy(options.clientNonce, 32)
    state.acceptNonce = copy(options.acceptNonce, 32)
    state.proofNonce = copy(options.proofNonce, 32)
    state.accept = copy(options.accept, LINK_ACCEPT_SIZE)
    state.proof = copy(options.proof, REDACTED_RESPONDER_PROOF_SIZE)
    ACCEPTED_EXTENSION_ADJACENCY_OWNERS.set(owner, state)
    armAcceptedExtensionOwnerTimer(owner, state, timerDelay(remaining))
    complete = true
    return owner
  } finally {
    if (!complete) {
      if (owner && ACCEPTED_EXTENSION_ADJACENCY_OWNERS.get(owner) === state) {
        state.reserved = false
        destroyAcceptedExtensionAdjacencyOwner(owner)
      } else {
        clearAcceptedExtensionOwnerState(state)
      }
    }
  }
}

function snapshotExtensionResponderOptions(options) {
  let extensionResponderSigner = null
  let offerReceiver = null
  try {
    if (options === null || typeof options !== 'object' || Array.isArray(options)) invalid()

    const signerDescriptor = getOwnPropertyDescriptorIntrinsic(options, 'extensionResponderSigner')
    if (signerDescriptor && 'value' in signerDescriptor) {
      extensionResponderSigner = signerDescriptor.value
    }
    const receiverDescriptor = getOwnPropertyDescriptorIntrinsic(options, 'offerReceiver')
    if (receiverDescriptor && 'value' in receiverDescriptor) {
      offerReceiver = receiverDescriptor.value
    }

    const keys = reflectOwnKeysIntrinsic(options)
    if (keys.length !== EXTENSION_RESPONDER_REQUIRED_OPTIONS.length) invalid()
    for (const key of keys) {
      if (typeof key !== 'string' || !EXTENSION_RESPONDER_REQUIRED_OPTIONS.includes(key)) {
        invalid()
      }
    }

    const snapshot = objectCreateIntrinsic(null)
    for (const name of EXTENSION_RESPONDER_REQUIRED_OPTIONS) {
      const descriptor =
        name === 'extensionResponderSigner'
          ? signerDescriptor
          : name === 'offerReceiver'
            ? receiverDescriptor
            : getOwnPropertyDescriptorIntrinsic(options, name)
      if (!descriptor || !('value' in descriptor)) invalid()
      snapshot[name] = descriptor.value
    }
    return snapshot
  } catch (err) {
    destroyExtensionResponderSigner(extensionResponderSigner)
    destroyExtensionOfferReceiver(offerReceiver)
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function createExtensionLinkResponder(options = {}) {
  const {
    advertisement,
    adjacencyAdopter,
    extensionResponderSigner: transferredExtensionResponderSigner,
    responderRouteEncryptionSecretKey,
    wallNow,
    monotonicNow,
    schedule,
    cancelScheduled,
    offerReceiver: transferredOfferReceiver,
    randomBytes
  } = snapshotExtensionResponderOptions(options)
  let extensionResponderSigner = transferredExtensionResponderSigner
  let offerReceiver = transferredOfferReceiver
  if (
    !isM3ResponderAdopter(adjacencyAdopter) ||
    !isExtensionOfferReceiver(offerReceiver) ||
    typeof wallNow !== 'function' ||
    typeof monotonicNow !== 'function' ||
    typeof schedule !== 'function' ||
    typeof cancelScheduled !== 'function' ||
    typeof randomBytes !== 'function'
  ) {
    destroyExtensionResponderSigner(extensionResponderSigner)
    destroyExtensionOfferReceiver(offerReceiver)
    invalid()
  }
  let wallHighWater = null
  const sampleWall = () => {
    const current = clockValue(wallNow)
    if (wallHighWater !== null && current < wallHighWater) authentication()
    wallHighWater = current
    return current
  }
  let advertisementBytes = null
  let responderRouteSecretKey = null
  let decodedAdvertisement = null
  let routePublicKey = null
  try {
    advertisementBytes = copy(advertisement)
    responderRouteSecretKey = copy(responderRouteEncryptionSecretKey, 32)
    const current = sampleWall()
    decodedAdvertisement = decodeRelayCapabilityAdvertisement(advertisementBytes, {
      now: current
    })
    routePublicKey = b4a.allocUnsafeSlow(32)
    if (!fixed(routePublicKey, 32)) invalid()
    sodium.crypto_scalarmult_base(routePublicKey, responderRouteSecretKey)
    if (!equal(routePublicKey, decodedAdvertisement.routeEncryptionPublicKey)) {
      authentication()
    }
  } catch (err) {
    clear(advertisementBytes)
    destroyExtensionResponderSigner(extensionResponderSigner)
    extensionResponderSigner = null
    clear(responderRouteSecretKey)
    destroyExtensionOfferReceiver(offerReceiver)
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    clearDecoded(decodedAdvertisement)
    clear(routePublicKey)
  }
  const replayCache = new Map()
  const acceptedAdjacencies = new Set()
  let isDestroyed = false
  let generation = Object.freeze({})
  let mutating = false
  let violated = false
  const destroyResponder = () => {
    if (isDestroyed) return false
    isDestroyed = true
    generation = null
    for (const accepted of acceptedAdjacencies) {
      const state = EXTENSION_RESPONDER_ADJACENCIES.get(accepted)
      if (!state) continue
      destroyAcceptedExtensionAdjacencyState(accepted, state)
    }
    acceptedAdjacencies.clear()
    clear(advertisementBytes)
    clear(responderRouteSecretKey)
    destroyExtensionResponderSigner(extensionResponderSigner)
    extensionResponderSigner = null
    destroyExtensionOfferReceiver(offerReceiver)
    replayCache.clear()
    return true
  }
  const assertGeneration = (operationGeneration) => {
    if (violated) {
      destroyResponder()
      invalid()
    }
    if (isDestroyed || generation !== operationGeneration) {
      throw PrivateRouteError.ERR_DESTROYED()
    }
  }
  let responder = null
  responder = Object.freeze({
    accept() {
      if (isDestroyed) throw PrivateRouteError.ERR_DESTROYED()
      if (mutating) {
        violated = true
        throw PrivateRouteError.ERR_BUSY()
      }
      mutating = true
      violated = false
      const operationGeneration = generation
      let received = null
      let physicalChannel = null
      let offer = null
      let advertisementDigest = null
      let currentAdvertisement = null
      let offerDigest = null
      let expectedParametersDigest = null
      let seed = null
      let pair = null
      let acceptNonce = null
      let proofNonce = null
      let admittedLimits = null
      let admittedLimitsDigest = null
      let body = null
      let signature = null
      let shared = null
      let tailShared = null
      let decodedAccept = null
      let replayKey = null
      let replayReservation = null
      let replayCommitted = false
      let randomScratch = null
      let derivedState = null
      let accept = null
      let proof = null
      let adoption = null
      let accepted = null
      let responseWriter = null
      let replayOwner = null
      let replaySlotReserved = false
      let offerConsumed = false
      let operationComplete = false
      try {
        reserveResponderReplayOwner()
        replaySlotReserved = true
        let current = sampleWall()
        assertGeneration(operationGeneration)
        received = takeExtensionOffer(offerReceiver)
        offerReceiver = null
        offerConsumed = true
        physicalChannel = received.physicalChannel
        responseWriter = received.responseWriter
        current = sampleWall()
        assertGeneration(operationGeneration)
        offer = decodeOffer(received.offer)
        validExtensionOffer(offer, current)
        currentAdvertisement = decodeRelayCapabilityAdvertisement(advertisementBytes, {
          now: current
        })
        advertisementDigest = digestRelayCapabilityAdvertisement(advertisementBytes, {
          now: current
        })
        expectedParametersDigest = digestPayloadParameters(currentAdvertisement)
        offerDigest = digest(LINK_OFFER_DIGEST_DOMAIN, offer.encoded)
        replayKey = b4a.toString(offerDigest, 'hex')
        for (const [key, reservation] of replayCache) {
          if (reservation.expiresAt <= current) replayCache.delete(key)
        }
        if (replayCache.has(replayKey)) replay()
        if (replayCache.size >= MAX_RESPONDER_REPLAYS) throw PrivateRouteError.ERR_BUSY()
        const expectedResponderRole = offer.extensionIndex === 1 ? ROLE.SAFETY : ROLE.PRIVATE
        if (
          roleForIdentity(currentAdvertisement.relayIdentity) !== expectedResponderRole ||
          !equal(offer.responderIdentity, currentAdvertisement.relayIdentity) ||
          !equal(offer.responderAdvertisementDigest, advertisementDigest) ||
          !equal(offer.payloadParametersDigest, expectedParametersDigest) ||
          !limitsWithinAdvertisement(offer.requestedLimits, currentAdvertisement, current)
        ) {
          authentication()
        }
        replayReservation = {
          completed: false,
          expiresAt: offer.offerDeadlineMs
        }
        replayCache.set(replayKey, replayReservation)
        tailShared = cryptoSuite.keyAgreement(
          responderRouteSecretKey,
          offer.clientTailEphemeralPublicKey
        )
        randomScratch = randomBytes(32)
        current = sampleWall()
        assertGeneration(operationGeneration)
        if (current >= offer.offerDeadlineMs) authentication()
        seed = copy(randomScratch, 32)
        clear(randomScratch)
        randomScratch = null
        pair = cryptoSuite.encryptionKeyPair(seed)
        randomScratch = randomBytes(32)
        current = sampleWall()
        assertGeneration(operationGeneration)
        if (current >= offer.offerDeadlineMs) authentication()
        acceptNonce = copy(randomScratch, 32)
        clear(randomScratch)
        randomScratch = null
        admittedLimits = encodeLimits({
          ...offer.requestedLimits,
          expiresAtMs:
            offer.requestedLimits.expiresAtMs < offer.offerDeadlineMs
              ? offer.requestedLimits.expiresAtMs
              : offer.offerDeadlineMs
        })
        body = b4a.allocUnsafeSlow(LINK_ACCEPT_BODY_SIZE)
        if (!fixed(body, LINK_ACCEPT_BODY_SIZE)) invalid()
        setIntrinsic.call(body, offerDigest, 0)
        setIntrinsic.call(body, advertisementDigest, 32)
        setIntrinsic.call(body, currentAdvertisement.relayIdentity, 64)
        setIntrinsic.call(body, received.observedPredecessorEndpoint, 96)
        setIntrinsic.call(body, pair.publicKey, 115)
        setIntrinsic.call(body, admittedLimits, 147)
        writeU64(body, current, 173)
        setIntrinsic.call(body, acceptNonce, 181)
        signature = signLinkAccept(
          extensionResponderSigner,
          body,
          currentAdvertisement.relayIdentity
        )
        accept = encodeM3Object({
          messageId: M3_MESSAGE_ID.LINK_ACCEPT_V1,
          body,
          authSuffix: signature
        })
        if (!fixed(accept, LINK_ACCEPT_SIZE)) invalid()
        decodedAccept = decodeAccept(accept)
        shared = cryptoSuite.keyAgreement(pair.secretKey, offer.initiatorLinkEphemeralPublicKey)
        assertGeneration(operationGeneration)
        if (replayCache.get(replayKey) !== replayReservation) replay()
        derivedState = deriveState(
          shared,
          tailShared,
          offer,
          decodedAccept,
          false,
          physicalChannel,
          wallNow,
          currentAdvertisement.routeEncryptionPublicKey,
          createCounter
        )
        physicalChannel = null
        current = sampleWall()
        assertGeneration(operationGeneration)
        if (current >= offer.offerDeadlineMs || current >= currentAdvertisement.expiresAtMs) {
          authentication()
        }
        admittedLimitsDigest = digestAdmittedLimits(decodedAccept.admittedLimits)
        const established = establish(derivedState)
        derivedState = null
        adoption = adoptM3ResponderLink(adjacencyAdopter, established)
        current = sampleWall()
        assertGeneration(operationGeneration)
        if (current >= offer.offerDeadlineMs || current >= currentAdvertisement.expiresAtMs) {
          authentication()
        }
        randomScratch = randomBytes(32)
        current = sampleWall()
        assertGeneration(operationGeneration)
        if (current >= offer.offerDeadlineMs || current >= currentAdvertisement.expiresAtMs) {
          authentication()
        }
        proofNonce = copy(randomScratch, 32)
        clear(randomScratch)
        randomScratch = null
        proof = signRedactedResponderProofWithSigner(
          {
            responderAdvertisementDigest: advertisementDigest,
            initiatorIdentity: offer.initiatorIdentity,
            responderIdentity: offer.responderIdentity,
            branchClass: offer.branchClass,
            branchId: offer.branchId,
            circuitId: offer.circuitId,
            generation: offer.generation,
            extensionIndex: offer.extensionIndex,
            clientTailEphemeralPublicKey: offer.clientTailEphemeralPublicKey,
            clientNonce: offer.clientNonce,
            advertisedRouteEncryptionPublicKey: currentAdvertisement.routeEncryptionPublicKey,
            admittedLimitsDigest,
            expiresAtMs: decodedAccept.admittedLimits.expiresAtMs,
            responderProofNonce: proofNonce
          },
          extensionResponderSigner
        )
        assertGeneration(operationGeneration)
        if (replayCache.get(replayKey) !== replayReservation) replay()
        replayOwner = createAcceptedExtensionAdjacencyOwner({
          offerDigest,
          clientNonce: offer.clientNonce,
          acceptNonce,
          proofNonce,
          accept,
          proof,
          wireExpiresAt: decodedAccept.admittedLimits.expiresAtMs,
          wallNow: sampleWall,
          monotonicNow,
          schedule,
          cancelScheduled
        })
        replaySlotReserved = false
        assertGeneration(operationGeneration)
        sendExtensionAccept(responseWriter, accept)
        current = sampleWall()
        assertGeneration(operationGeneration)
        if (
          current >= offer.offerDeadlineMs ||
          current >= decodedAccept.admittedLimits.expiresAtMs ||
          current >= currentAdvertisement.expiresAtMs
        ) {
          authentication()
        }
        sendExtensionProof(responseWriter, proof)
        current = sampleWall()
        assertGeneration(operationGeneration)
        if (
          current >= offer.offerDeadlineMs ||
          current >= decodedAccept.admittedLimits.expiresAtMs ||
          current >= currentAdvertisement.expiresAtMs
        ) {
          authentication()
        }
        finishExtensionResponse(responseWriter)
        responseWriter = null
        current = sampleWall()
        assertGeneration(operationGeneration)
        if (
          current >= offer.offerDeadlineMs ||
          current >= decodedAccept.admittedLimits.expiresAtMs ||
          current >= currentAdvertisement.expiresAtMs
        ) {
          authentication()
        }
        accepted = objectFreezeIntrinsic({})
        EXTENSION_RESPONDER_ADJACENCIES.set(accepted, {
          responder,
          adoption,
          replayOwner,
          acceptedAdjacencies
        })
        acceptedAdjacencies.add(accepted)
        const replayOwnerState = ACCEPTED_EXTENSION_ADJACENCY_OWNERS.get(replayOwner)
        replayOwnerState.pair = { accepted }
        adoption = null
        replayOwner = null
        replayReservation.completed = true
        replayCommitted = true
        const result = Object.freeze({ accepted })
        operationComplete = true
        return result
      } catch (err) {
        if (err instanceof PrivateRouteError) throw err
        invalid()
      } finally {
        if (
          replayReservation &&
          !replayCommitted &&
          replayCache.get(replayKey) === replayReservation
        ) {
          replayCache.delete(replayKey)
        }
        try {
          if (physicalChannel) physicalChannel.destroy()
        } catch {}
        clear(received && received.offer)
        clear(received && received.observedPredecessorEndpoint)
        clearDecoded(offer)
        clearDecoded(currentAdvertisement)
        clear(advertisementDigest)
        clear(offerDigest)
        clear(expectedParametersDigest)
        clear(seed)
        clear(pair && pair.publicKey)
        clear(pair && pair.secretKey)
        clear(acceptNonce)
        clear(proofNonce)
        clear(admittedLimits)
        clear(admittedLimitsDigest)
        clear(body)
        clear(signature)
        clear(shared)
        clear(tailShared)
        clearDecoded(decodedAccept)
        clear(randomScratch)
        clearState(derivedState)
        destroyExtensionResponseWriter(responseWriter)
        if (adoption) destroyM3ResponderLink(adoption)
        destroyAcceptedExtensionAdjacencyOwner(replayOwner)
        if (replaySlotReserved) responderReplayOwners--
        clear(accept)
        clear(proof)
        if (!operationComplete && offerConsumed) {
          destroyExtensionResponderSigner(extensionResponderSigner)
          extensionResponderSigner = null
        }
        mutating = false
        if (violated && !isDestroyed) destroyResponder()
      }
    },
    destroy() {
      if (mutating) violated = true
      return destroyResponder()
    }
  })
  return responder
}

function takeExtensionResponderAdjacency(responder, accepted) {
  const state =
    accepted !== null && typeof accepted === 'object'
      ? EXTENSION_RESPONDER_ADJACENCIES.get(accepted)
      : null
  if (!state || state.responder !== responder) {
    if (
      accepted !== null &&
      typeof accepted === 'object' &&
      SPENT_EXTENSION_RESPONDER_ADJACENCIES.has(accepted)
    ) {
      replay()
    }
    authentication()
  }
  const transfer = objectFreezeIntrinsic({})
  const transferState = {
    adoption: state.adoption,
    replayOwner: state.replayOwner
  }
  ACCEPTED_EXTENSION_ADJACENCY_TRANSFERS.set(transfer, transferState)
  EXTENSION_RESPONDER_ADJACENCIES.delete(accepted)
  SPENT_EXTENSION_RESPONDER_ADJACENCIES.add(accepted)
  state.acceptedAdjacencies.delete(accepted)
  state.adoption = null
  state.replayOwner = null
  const ownerState = ACCEPTED_EXTENSION_ADJACENCY_OWNERS.get(transferState.replayOwner)
  ownerState.pair = { transfer }
  return transfer
}

function takeAcceptedExtensionAdjacencyTransfer(transfer) {
  const state =
    transfer !== null && typeof transfer === 'object'
      ? ACCEPTED_EXTENSION_ADJACENCY_TRANSFERS.get(transfer)
      : null
  if (!state) {
    if (
      transfer !== null &&
      typeof transfer === 'object' &&
      SPENT_ACCEPTED_EXTENSION_ADJACENCY_TRANSFERS.has(transfer)
    ) {
      replay()
    }
    authentication()
  }
  ACCEPTED_EXTENSION_ADJACENCY_TRANSFERS.delete(transfer)
  SPENT_ACCEPTED_EXTENSION_ADJACENCY_TRANSFERS.add(transfer)
  const ownerState = ACCEPTED_EXTENSION_ADJACENCY_OWNERS.get(state.replayOwner)
  if (!ownerState) {
    destroyM3ResponderLink(state.adoption)
    state.adoption = null
    state.replayOwner = null
    throw PrivateRouteError.ERR_DESTROYED()
  }
  ownerState.pair = null
  let adoption = state.adoption
  let replayOwner = state.replayOwner
  state.adoption = null
  state.replayOwner = null
  try {
    const material = {
      adjacency: null,
      replayOwner
    }
    material.adjacency = takeM3ResponderLink(adoption)
    adoption = null
    replayOwner = null
    return objectFreezeIntrinsic(material)
  } finally {
    try {
      destroyM3ResponderLink(adoption)
    } finally {
      destroyAcceptedExtensionAdjacencyOwner(replayOwner)
    }
  }
}

function revokeAcceptedExtensionAdjacencyTransfer(transfer) {
  const state =
    transfer !== null && typeof transfer === 'object'
      ? ACCEPTED_EXTENSION_ADJACENCY_TRANSFERS.get(transfer)
      : null
  if (!state) return false
  return destroyAcceptedExtensionAdjacencyTransferState(transfer, state)
}

function answerAcceptedExtensionReplay(owner, offerReceiver) {
  const state =
    owner !== null && typeof owner === 'object'
      ? ACCEPTED_EXTENSION_ADJACENCY_OWNERS.get(owner)
      : null
  if (!state) {
    if (
      owner !== null &&
      typeof owner === 'object' &&
      SPENT_ACCEPTED_EXTENSION_ADJACENCY_OWNERS.has(owner)
    ) {
      destroyed()
    }
    authentication()
  }
  if (state.answering) busy()
  let received = null
  let physicalChannel = null
  let responseWriter = null
  let offer = null
  let offerDigest = null
  let decodedAccept = null
  let decodedProof = null
  state.answering = true
  const assertOwner = () => {
    if (ACCEPTED_EXTENSION_ADJACENCY_OWNERS.get(owner) !== state) destroyed()
    let current
    try {
      current = sampleAcceptedExtensionOwnerMonotonic(owner, state)
    } catch (err) {
      destroyAcceptedExtensionAdjacencyOwner(owner)
      throw err
    }
    if (current === null) destroyed()
    if (current >= state.localDeadline) {
      expireAcceptedExtensionAdjacencyOwner(owner, state)
      destroyed()
    }
  }
  try {
    assertOwner()
    received = takeExtensionOffer(offerReceiver)
    physicalChannel = received.physicalChannel
    responseWriter = received.responseWriter
    assertOwner()
    offer = decodeOffer(received.offer)
    offerDigest = digest(LINK_OFFER_DIGEST_DOMAIN, offer.encoded)
    decodedAccept = decodeAccept(state.accept)
    decodedProof = decodeRedactedResponderProof(state.proof)
    if (
      !equal(offerDigest, state.offerDigest) ||
      !equal(offer.clientNonce, state.clientNonce) ||
      !equal(decodedAccept.completeOfferDigest, state.offerDigest) ||
      !equal(decodedAccept.acceptNonce, state.acceptNonce) ||
      !equal(decodedProof.clientNonce, state.clientNonce) ||
      !equal(decodedProof.responderProofNonce, state.proofNonce)
    ) {
      authentication()
    }
    assertOwner()
    sendExtensionAccept(responseWriter, state.accept)
    assertOwner()
    sendExtensionProof(responseWriter, state.proof)
    assertOwner()
    finishExtensionResponse(responseWriter)
    responseWriter = null
    assertOwner()
    return true
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    if (ACCEPTED_EXTENSION_ADJACENCY_OWNERS.get(owner) === state) state.answering = false
    destroyExtensionResponseWriter(responseWriter)
    try {
      if (physicalChannel) physicalChannel.destroy()
    } catch {}
    clear(received && received.offer)
    clear(received && received.observedPredecessorEndpoint)
    clearDecoded(offer)
    clear(offerDigest)
    clearDecoded(decodedAccept)
    clearDecoded(decodedProof)
  }
}

function completeExtensionLink(pending, options = {}) {
  pruneExtensionPending(extensionResourceTime())
  const state =
    pending !== null && typeof pending === 'object' ? EXTENSION_PENDING.get(pending) : null
  if (!state) {
    if (pending !== null && typeof pending === 'object' && SPENT_EXTENSION_PENDING.has(pending)) {
      replay()
    }
    authentication()
  }
  EXTENSION_PENDING.delete(pending)
  EXTENSION_PENDING_TOKENS.delete(pending)
  SPENT_EXTENSION_PENDING.add(pending)
  let physicalChannel = null
  let received = null
  let accept = null
  let decodedProof = null
  let observedEndpoint = null
  let offerDigest = null
  let input = null
  let shared = null
  let admittedLimitsDigest = null
  let derivedState = null
  let verifiedProof = null
  let proofConsumer = null
  let expectedProof = null
  let extensionNonce = null
  let redactedProof = null
  let socketOwnerLease = null
  let established = null
  let completion = null
  let transferred = false
  try {
    const now = safe(options, 'now')
    const proofVerifier = safe(options, 'proofVerifier')
    proofConsumer = safe(options, 'proofConsumer')
    socketOwnerLease = safe(options, 'socketOwnerLease')
    const setupReceiver = safe(options, 'setupReceiver')
    if (typeof now !== 'function' || !isExtensionResponseReceiver(setupReceiver)) invalid()
    let current = now()
    if (!u64(current)) invalid()
    received = takeExtensionResponse(setupReceiver)
    physicalChannel = received.physicalChannel
    current = now()
    if (!u64(current)) invalid()
    accept = decodeAccept(received.accept)
    decodedProof = decodeRedactedResponderProof(received.proof)
    observedEndpoint = decodeCanonicalEndpoint(accept.observedPredecessorEndpoint)
    offerDigest = digest(LINK_OFFER_DIGEST_DOMAIN, state.offer.encoded)
    input = signatureInput(LINK_ACCEPT_DOMAIN, M3_MESSAGE_ID.LINK_ACCEPT_V1, accept.body)
    const validSignature = cryptoSuite.verify(
      input,
      accept.signature,
      state.offer.responderIdentity
    )
    if (
      !validSignature ||
      !equal(accept.completeOfferDigest, offerDigest) ||
      !equal(accept.responderAdvertisementDigest, state.advertisementDigest) ||
      !equal(accept.responderIdentity, state.offer.responderIdentity) ||
      accept.acceptedAtMs > state.offer.offerDeadlineMs ||
      accept.acceptedAtMs > current ||
      current >= state.offer.offerDeadlineMs ||
      !limitsWithin(accept.admittedLimits, state.offer.requestedLimits) ||
      accept.admittedLimits.expiresAtMs > state.offer.offerDeadlineMs ||
      accept.admittedLimits.expiresAtMs <= current ||
      !nonzero(accept.responderLinkEphemeralPublicKey) ||
      !nonzero(accept.acceptNonce)
    ) {
      authentication()
    }
    shared = cryptoSuite.keyAgreement(
      state.ephemeralSecretKey,
      accept.responderLinkEphemeralPublicKey
    )
    derivedState = deriveState(
      shared,
      null,
      state.offer,
      accept,
      true,
      physicalChannel,
      () => Number(current),
      state.advertisedRouteEncryptionPublicKey,
      createCounter
    )
    physicalChannel = null
    admittedLimitsDigest = digestAdmittedLimits(accept.admittedLimits)
    current = now()
    if (!u64(current) || current >= state.offer.offerDeadlineMs) authentication()
    expectedProof = {
      responderAdvertisementDigest: copy(state.advertisementDigest, 32),
      initiatorIdentity: copy(state.offer.initiatorIdentity, 32),
      responderIdentity: copy(state.offer.responderIdentity, 32),
      branchClass: state.offer.branchClass,
      branchId: copy(state.offer.branchId, 16),
      circuitId: copy(state.offer.circuitId, 16),
      generation: state.offer.generation,
      extensionIndex: state.offer.extensionIndex,
      clientTailEphemeralPublicKey: copy(state.offer.clientTailEphemeralPublicKey, 32),
      clientNonce: copy(state.offer.clientNonce, 32),
      advertisedRouteEncryptionPublicKey: copy(state.advertisedRouteEncryptionPublicKey, 32),
      admittedLimitsDigest: copy(admittedLimitsDigest, 32),
      expiresAtMs: accept.admittedLimits.expiresAtMs,
      responderProofNonce: copy(decodedProof.responderProofNonce, 32)
    }
    verifiedProof = verifyExpectedRedactedResponderProof(
      proofVerifier,
      proofConsumer,
      received.proof,
      expectedProof
    )
    current = now()
    if (
      !u64(current) ||
      current >= state.offer.offerDeadlineMs ||
      current >= accept.admittedLimits.expiresAtMs
    ) {
      authentication()
    }
    established = establish(derivedState)
    derivedState = null
    extensionNonce = copy(state.extensionNonce, 32)
    redactedProof = copy(received.proof, REDACTED_RESPONDER_PROOF_SIZE)
    completion = createExtensionLinkCompletion(
      {
        established,
        verifiedProof,
        proofConsumer,
        expectedProof,
        socketOwnerLease,
        destroySocketOwnerLease: spendSocketOwnerLease,
        redactedProof,
        extensionNonce
      },
      (material) => {
        destroyM3EstablishedLink(material.established)
        try {
          if (material.verifiedProof) {
            revokeVerifiedRedactedResponderProof(material.proofConsumer, material.verifiedProof)
          }
        } catch {}
        spendSocketOwnerLease(material.socketOwnerLease)
        material.destroySocketOwnerLease = null
        clearDecoded(material.expectedProof)
        clear(material.redactedProof)
        clear(material.extensionNonce)
        material.established = null
        material.verifiedProof = null
        material.proofConsumer = null
        material.expectedProof = null
        material.socketOwnerLease = null
        material.redactedProof = null
        material.extensionNonce = null
      }
    )
    socketOwnerLease = null
    established = null
    verifiedProof = null
    proofConsumer = null
    expectedProof = null
    redactedProof = null
    extensionNonce = null
    transferred = true
    return completion
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    if (!transferred && verifiedProof) {
      try {
        revokeVerifiedRedactedResponderProof(proofConsumer, verifiedProof)
      } catch {}
    }
    if (physicalChannel) {
      try {
        physicalChannel.destroy()
      } catch {}
    }
    clearDecoded(accept)
    clearDecoded(decodedProof)
    clear(received && received.accept)
    clear(received && received.proof)
    if (!transferred) spendSocketOwnerLease(socketOwnerLease)
    clear(observedEndpoint)
    clear(offerDigest)
    clear(input)
    clear(shared)
    clear(admittedLimitsDigest)
    destroyM3EstablishedLink(established)
    clearDecoded(expectedProof)
    clear(redactedProof)
    clear(extensionNonce)
    clearState(derivedState)
    clearExtensionPending(state)
  }
}

function abortExtensionLinkCompletion(completion) {
  return destroyExtensionLinkCompletion(completion)
}

function completeIndexZeroGuardLink(pending, encodedAccept, options = {}) {
  const { advertisement, physicalChannel, now } = options
  const counterFactory = options[TEST_ONLY_COUNTER_FACTORY] || createCounter
  const ownsPhysical =
    physicalChannel !== null &&
    typeof physicalChannel === 'object' &&
    typeof physicalChannel.destroy === 'function'
  const state = pending !== null && typeof pending === 'object' ? PENDING.get(pending) : null
  if (!state) {
    try {
      if (ownsPhysical) physicalChannel.destroy()
    } catch {}
    if (pending !== null && typeof pending === 'object' && SPENT.has(pending)) replay()
    authentication()
  }
  PENDING.delete(pending)
  PENDING_TOKENS.delete(pending)
  SPENT.add(pending)
  let accept = null
  let shared = null
  let advertisementBytes = null
  let decodedAdvertisement = null
  let advertisementDigest = null
  let offerDigest = null
  let input = null
  let tailShared = null
  let transferred = false
  try {
    if (!u64(now) || !ownsPhysical) invalid()
    advertisementBytes = copy(advertisement)
    decodedAdvertisement = decodeRelayCapabilityAdvertisement(advertisementBytes, { now })
    advertisementDigest = digestRelayCapabilityAdvertisement(advertisementBytes, { now })
    accept = decodeAccept(encodedAccept)
    offerDigest = digest(LINK_OFFER_DIGEST_DOMAIN, state.offer.encoded)
    input = signatureInput(LINK_ACCEPT_DOMAIN, M3_MESSAGE_ID.LINK_ACCEPT_V1, accept.body)
    const validSignature = cryptoSuite.verify(
      input,
      accept.signature,
      state.offer.responderIdentity
    )
    if (
      !validSignature ||
      !equal(accept.completeOfferDigest, offerDigest) ||
      !equal(accept.responderAdvertisementDigest, state.advertisementDigest) ||
      !equal(accept.responderAdvertisementDigest, advertisementDigest) ||
      !equal(accept.responderIdentity, state.offer.responderIdentity) ||
      !nonzero(accept.observedPredecessorEndpoint) ||
      accept.acceptedAtMs > state.offer.offerDeadlineMs ||
      accept.acceptedAtMs > now ||
      now >= state.offer.offerDeadlineMs ||
      !limitsWithin(accept.admittedLimits, state.offer.requestedLimits) ||
      accept.admittedLimits.expiresAtMs <= now ||
      !nonzero(accept.responderLinkEphemeralPublicKey) ||
      !nonzero(accept.acceptNonce)
    ) {
      authentication()
    }
    shared = cryptoSuite.keyAgreement(
      state.ephemeralSecretKey,
      accept.responderLinkEphemeralPublicKey
    )
    tailShared = cryptoSuite.keyAgreement(
      state.offer.clientTailEphemeralSecretKey,
      decodedAdvertisement.routeEncryptionPublicKey
    )
    const established = establish(
      deriveState(
        shared,
        tailShared,
        state.offer,
        accept,
        true,
        physicalChannel,
        () => Number(now),
        decodedAdvertisement.routeEncryptionPublicKey,
        counterFactory
      )
    )
    transferred = true
    return established
  } finally {
    if (!transferred && ownsPhysical) {
      try {
        physicalChannel.destroy()
      } catch {}
    }
    clear(advertisementBytes)
    clearDecoded(decodedAdvertisement)
    clear(advertisementDigest)
    clear(offerDigest)
    clear(input)
    clear(shared)
    clear(tailShared)
    clearPending(state)
    clearDecoded(accept)
  }
}

function abortIndexZeroGuardLink(pending) {
  const state = pending !== null && typeof pending === 'object' ? PENDING.get(pending) : null
  if (!state) return false
  PENDING.delete(pending)
  PENDING_TOKENS.delete(pending)
  SPENT.add(pending)
  clearPending(state)
  return true
}

function readM3EstablishedLink(value) {
  const state = value !== null && typeof value === 'object' ? ESTABLISHED.get(value) : null
  if (!state) authentication()
  return state
}

function destroyM3EstablishedLink(value) {
  const state = value !== null && typeof value === 'object' ? ESTABLISHED.get(value) : null
  if (!state) return false
  ESTABLISHED.delete(value)
  SPENT_ESTABLISHED.add(value)
  clearState(state)
  return true
}

// Deep production import used only by M3AdjacencyAuthority. Ownership moves
// out of guard-link exactly once; callers cannot inspect or reuse the handle.
function takeM3EstablishedLink(value) {
  const state = value !== null && typeof value === 'object' ? ESTABLISHED.get(value) : null
  if (!state) {
    if (value !== null && typeof value === 'object' && SPENT_ESTABLISHED.has(value)) replay()
    authentication()
  }
  ESTABLISHED.delete(value)
  SPENT_ESTABLISHED.add(value)
  return state
}

// Deep production import used when adoption fails after the one-shot take.
function destroyTakenM3EstablishedLink(state) {
  if (state === null || typeof state !== 'object') return false
  clearState(state)
  return true
}

module.exports = {
  LINK_OFFER_SIZE,
  LINK_ACCEPT_SIZE,
  abortExtensionAdjacentLink,
  abortExtensionLinkCompletion,
  abortExtensionLinkOffer,
  answerAcceptedExtensionReplay,
  completeExtensionLink,
  createExtensionAdjacentLinkFactory,
  openExtensionAdjacentLink,
  createExtensionLinkOffer,
  createExtensionLinkResponder,
  destroyAcceptedExtensionAdjacencyOwner,
  takeExtensionResponderAdjacency,
  revokeAcceptedExtensionAdjacencyTransfer,
  takeAcceptedExtensionAdjacencyTransfer,
  createRelayAdjacentDialAuthority,
  destroyExtensionAdjacentLinkFactory,
  destroyRelayAdjacentDialAuthority,
  dialRelayAdvertisement,
  createIndexZeroGuardLinkOffer,
  createIndexZeroGuardLinkResponder,
  completeIndexZeroGuardLink,
  abortIndexZeroGuardLink,
  readM3EstablishedLink,
  takeM3EstablishedLink,
  destroyM3EstablishedLink,
  destroyTakenM3EstablishedLink,
  takeM3AuthenticatedBranchBinding,
  destroyM3AuthenticatedBranchBinding,
  [TAKE_STAGED_RELAY_ADJACENT_OFFER]: takeStagedRelayAdjacentOffer,
  [TEST_ONLY_M3_ESTABLISHED_ISSUER]: testOnlyM3EstablishedIssuer
}
