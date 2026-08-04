const b4a = require('b4a')
const sodium = require('sodium-universal')

const { cryptoSuite } = require('./crypto-suite')
const { digestPayloadParameters } = require('./link-parameters')
const { PrivateRouteError } = require('./errors')
const {
  decodeM3ContextEnvelope,
  encodeM3ContextAD,
  encodeM3ContextEnvelope
} = require('./m3-context')
const {
  BRANCH_CLASS,
  CELL_CLASS,
  CONTEXT_CLASS,
  DIRECTION,
  M3_LINK_ROLE,
  M3_MESSAGE_ID,
  M3_PROTOCOL_VERSION,
  RELAY_CAPABILITY,
  ROLE,
  decodeM3Object,
  encodeM3Object,
  roleForIdentity
} = require('./protocol')
const {
  decodeRelayCapabilityAdvertisement,
  digestRelayCapabilityAdvertisement
} = require('./relay-capability')
const { decodeRedactedResponderProof } = require('./redacted-responder-proof')

const ADMITTED_LIMITS_SIZE = 26
const EXTENDED_SIZE = 494
const EXTEND_REQUEST_MIN_SIZE = 466
const EXTEND_REQUEST_MAX_SIZE = 754
const TAIL_CONTROL_TRANSCRIPT_SIZE = 290
const TAIL_READY_SIZE = 282

const MAX_UINT32 = 0xffff_ffff
const MAX_TIMER_DELAY = 0x7fff_ffff
const MAX_UINT64 = 0xffff_ffff_ffff_ffffn
const TAIL_DOMAIN = b4a.from('hyperdht-private-routes/tail-control/transcript/v1')
const REDACTED_RESPONDER_PROOF_DOMAIN = b4a.from(
  'hyperdht-private-routes/m3/redacted-responder-proof/v1'
)
const LIMITS_DOMAIN = b4a.from('hyperdht-private-routes/tail-control/limits/v1')
const TAIL_DIGEST_DOMAIN = b4a.from('hyperdht-private-routes/final-exit/tail-digest/v1')
const TAIL_READY_DOMAIN = b4a.from('hyperdht-private-routes/m3/tail-ready/v1')
const TAIL_READY_TRANSCRIPT_DOMAIN = b4a.from(
  'hyperdht-private-routes/m3/tail-control/transcript-digest/v1'
)
const TAIL_READY_BODY_SIZE = 210
const IMPORTED_SUCCESSOR_READY_AUTHORITIES = new WeakSet()
const EXTEND_REQUEST_FIXED_BODY_SIZE = 198
const REDACTED_RESPONDER_PROOF_BODY_SIZE = 306
const EXTENDED_BODY_SIZE = 486
const REDACTED_RESPONDER_PROOF_SIZE = 378
const SESSIONS = new WeakMap()
const DESTROYED_SESSIONS = new WeakSet()
const FINAL_EXIT_HANDOFFS = new WeakMap()
const FINAL_EXIT_HANDOFF_OWNERS = new WeakMap()
const FINAL_EXIT_TRANSFERS = new WeakMap()
const FINAL_EXIT_ACTIVATIONS = new WeakMap()
const FINAL_EXIT_TIMER_STATES = new WeakMap()
const FINAL_EXIT_PREPARE_CONSUMES = new WeakSet()
const RESPONDER_AUTHORITIES = new WeakMap()
const DESTROYED_RESPONDER_AUTHORITIES = new WeakSet()
const ADMITTED_EXTEND_REQUESTS = new WeakMap()
const CLIENT_EXTENSION_COMPLETIONS = new WeakMap()
const SPENT_CLIENT_EXTENSION_COMPLETIONS = new WeakSet()
const SUCCESSOR_TAIL_READY_CONTEXTS = new WeakMap()
const SPENT_SUCCESSOR_TAIL_READY_CONTEXTS = new WeakSet()
const CLIENT_EXTENSION_COMPLETION_RESERVED = Object.freeze({})
const bufferByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
const bufferFill = Uint8Array.prototype.fill
const bufferSet = Uint8Array.prototype.set
const bufferSubarray = Uint8Array.prototype.subarray

const TAIL_LABELS = Object.freeze({
  forwardKey: 'hyperdht-private-routes/kdf/v1/tail-control/forward-key',
  reverseKey: 'hyperdht-private-routes/kdf/v1/tail-control/reverse-key',
  forwardNonce: 'hyperdht-private-routes/kdf/v1/tail-control/forward-nonce',
  reverseNonce: 'hyperdht-private-routes/kdf/v1/tail-control/reverse-nonce'
})

const FINALIZE_LABELS = Object.freeze({
  finalizeForwardKey: 'hyperdht-private-routes/kdf/v1/tail-finalize/forward-key',
  finalizeReverseKey: 'hyperdht-private-routes/kdf/v1/tail-finalize/reverse-key',
  finalizeForwardNonce: 'hyperdht-private-routes/kdf/v1/tail-finalize/forward-nonce',
  finalizeReverseNonce: 'hyperdht-private-routes/kdf/v1/tail-finalize/reverse-nonce'
})

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function busy() {
  throw PrivateRouteError.ERR_BUSY()
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

function object(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid()
  return value
}

function exactValueDescriptor(source, name) {
  let descriptor
  try {
    descriptor = Object.getOwnPropertyDescriptor(source, name)
  } catch {
    invalid()
  }
  if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) invalid()
  return descriptor.value
}

function option(value, name) {
  try {
    return value[name]
  } catch {
    invalid()
  }
}

function exactObject(value, expected) {
  value = object(value)
  let keys
  try {
    keys = Reflect.ownKeys(value)
  } catch {
    invalid()
  }
  if (
    keys.length !== expected.length ||
    keys.some((key) => typeof key !== 'string' || !expected.includes(key))
  ) {
    invalid()
  }
  return value
}

function fixed(value, size) {
  return bufferLength(value) === size
}

function bufferLength(value) {
  try {
    return b4a.isBuffer(value) ? bufferByteLength.call(value) : -1
  } catch {
    return -1
  }
}

function set(target, source, offset = 0) {
  try {
    bufferSet.call(target, source, offset)
  } catch {
    invalid()
  }
}

function subarray(value, start, end) {
  try {
    return bufferSubarray.call(value, start, end)
  } catch {
    invalid()
  }
}

function copy(value, size = bufferLength(value)) {
  let output = null
  try {
    if (size < 0 || !fixed(value, size)) invalid()
    output = b4a.allocUnsafeSlow(size)
    if (!fixed(output, size)) invalid()
    set(output, value)
    return output
  } catch (err) {
    clear(output)
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  }
}

function uint16(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 0xffff
}

function uint32(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= MAX_UINT32
}

function relayCapabilityMask(value) {
  const known =
    RELAY_CAPABILITY.CIRCUIT_RELAY_V1 |
    RELAY_CAPABILITY.DHT_EXIT_V1 |
    RELAY_CAPABILITY.PRIVATE_RECORDS_V1
  if (!uint32(value) || value === 0 || value & ~known) {
    invalid()
  }
  return value
}

function uint64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= MAX_UINT64
}

function branchClass(value) {
  if (value !== BRANCH_CLASS.LOOKUP && value !== BRANCH_CLASS.ANNOUNCE) invalid()
  return value
}

function extensionIndex(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 2) invalid()
  return value
}

function nextExtensionIndex(value) {
  value = extensionIndex(value)
  if (value === 0) invalid()
  return value
}

function nonzero(value) {
  const length = bufferLength(value)
  if (length < 1) return false
  for (let index = 0; index < length; index++) if (value[index] !== 0) return true
  return false
}

function writeUint16(buffer, value, offset) {
  buffer[offset] = value >>> 8
  buffer[offset + 1] = value
}

function writeUint32(buffer, value, offset) {
  buffer[offset] = value >>> 24
  buffer[offset + 1] = value >>> 16
  buffer[offset + 2] = value >>> 8
  buffer[offset + 3] = value
}

function writeUint64(buffer, value, offset) {
  for (let index = offset + 7; index >= offset; index--) {
    buffer[index] = Number(value & 0xffn)
    value >>= 8n
  }
}

function readUint16(buffer, offset) {
  return (buffer[offset] << 8) | buffer[offset + 1]
}

function readUint32(buffer, offset) {
  return (
    buffer[offset] * 0x1000000 +
    (buffer[offset + 1] << 16) +
    (buffer[offset + 2] << 8) +
    buffer[offset + 3]
  )
}

function readUint64(buffer, offset) {
  let value = 0n
  for (let index = offset; index < offset + 8; index++) {
    value = (value << 8n) | BigInt(buffer[index])
  }
  return value
}

function clear(buffer) {
  try {
    if (b4a.isBuffer(buffer)) bufferFill.call(buffer, 0)
  } catch {
    // Best-effort zeroization only.
  }
}

function encodeRequestedLimits(value) {
  value = object(value)
  const cellSize = option(value, 'cellSize')
  const maxCells = option(value, 'maxCells')
  const maxBytes = option(value, 'maxBytes')
  const maxCommands = option(value, 'maxCommands')
  const idleTimeoutMs = option(value, 'idleTimeoutMs')
  const expiresAtMs = option(value, 'expiresAtMs')
  if (
    cellSize !== 1200 ||
    !uint32(maxCells) ||
    maxCells === 0 ||
    !uint32(maxBytes) ||
    maxBytes === 0 ||
    !uint32(maxCommands) ||
    maxCommands === 0 ||
    !uint32(idleTimeoutMs) ||
    idleTimeoutMs === 0 ||
    !uint64(expiresAtMs) ||
    expiresAtMs === 0n
  ) {
    invalid()
  }
  let encoded = null
  let complete = false
  try {
    encoded = b4a.allocUnsafeSlow(ADMITTED_LIMITS_SIZE)
    if (!fixed(encoded, ADMITTED_LIMITS_SIZE)) invalid()
    writeUint16(encoded, cellSize, 0)
    writeUint32(encoded, maxCells, 2)
    writeUint32(encoded, maxBytes, 6)
    writeUint32(encoded, maxCommands, 10)
    writeUint32(encoded, idleTimeoutMs, 14)
    writeUint64(encoded, expiresAtMs, 18)
    complete = true
    return encoded
  } finally {
    if (!complete) clear(encoded)
  }
}

function decodeRequestedLimits(encoded) {
  if (!fixed(encoded, ADMITTED_LIMITS_SIZE)) invalid()
  const value = Object.freeze({
    cellSize: readUint16(encoded, 0),
    maxCells: readUint32(encoded, 2),
    maxBytes: readUint32(encoded, 6),
    maxCommands: readUint32(encoded, 10),
    idleTimeoutMs: readUint32(encoded, 14),
    expiresAtMs: readUint64(encoded, 18)
  })
  const canonical = encodeRequestedLimits(value)
  clear(canonical)
  return value
}

function assertNestedObject(encoded, messageId, bodySize, authSize) {
  const nested = decodeM3Object(encoded)
  try {
    if (
      nested.messageId !== messageId ||
      !fixed(nested.body, bodySize) ||
      !fixed(nested.authSuffix, authSize)
    ) {
      invalid()
    }
  } finally {
    clear(nested.body)
    clear(nested.authSuffix)
  }
}

function clearExtendRequest(value) {
  if (!value) return
  for (const field of [
    'branchId',
    'circuitId',
    'advertisement',
    'clientTailEphemeralPublicKey',
    'clientNonce',
    'payloadParametersDigest',
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

function clearAdmittedExtendRequest(record) {
  if (!record) return
  try {
    if (!Object.prototype.hasOwnProperty.call(record, 'status')) return
  } catch {
    return
  }
  if (record.capability) ADMITTED_EXTEND_REQUESTS.delete(record.capability)
  clearExtendRequest(record.request)
  clear(record.currentTailIdentity)
  clear(record.currentTailAdvertisementDigest)
  record.capability = null
  record.request = null
  record.currentTailIdentity = null
  record.currentTailAdvertisementDigest = null
  record.session = null
  record.status = 'DESTROYED'
  record.localDeadline = 0n
  record.wireExpiresAt = 0n
  record.key = null
  clear(record.extensionNonce)
  record.extensionNonce = null
}

function copyExtendRequestMaterial(value) {
  if (!value) return null
  return {
    branchClass: value.branchClass,
    branchId: copy(value.branchId, 16),
    circuitId: copy(value.circuitId, 16),
    generation: value.generation,
    extensionIndex: value.extensionIndex,
    advertisement: copy(value.advertisement),
    clientTailEphemeralPublicKey: copy(value.clientTailEphemeralPublicKey, 32),
    clientNonce: copy(value.clientNonce, 32),
    payloadParametersDigest: copy(value.payloadParametersDigest, 32),
    requestedLimits: Object.freeze({
      cellSize: value.requestedLimits.cellSize,
      maxCells: value.requestedLimits.maxCells,
      maxBytes: value.requestedLimits.maxBytes,
      maxCommands: value.requestedLimits.maxCommands,
      idleTimeoutMs: value.requestedLimits.idleTimeoutMs,
      expiresAtMs: value.requestedLimits.expiresAtMs
    }),
    extensionNonce: copy(value.extensionNonce, 32)
  }
}

function clearTailOpening(value) {
  if (!value) return
  clearExtendRequest(value.request)
  clear(value.currentTailIdentity)
  clear(value.currentTailAdvertisementDigest)
  clear(value.responderAdvertisementDigest)
  clear(value.responderRouteEncryptionPublicKey)
  clear(value.responderIdentity)
  if (value.completion) {
    try {
      const { destroyExtensionLinkCompletion } = require('./extension-link-completion')
      destroyExtensionLinkCompletion(value.completion)
    } catch {}
  }
  value.request = null
  value.currentTailIdentity = null
  value.currentTailAdvertisementDigest = null
  value.responderAdvertisementDigest = null
  value.responderIdentity = null
  value.responderRouteEncryptionPublicKey = null
  value.promise = null
  value.completion = null
  value.adjacentLinkFactory = null
  value.successorTailReadyContext = null
}

function abortTailOpening(state) {
  const opening = state && state.responderOpening
  if (!opening) return false
  state.responderOpening = null
  try {
    const { abortExtensionAdjacentLink } = require('./guard-link')
    abortExtensionAdjacentLink(opening.adjacentLinkFactory)
  } catch {}
  clearTailOpening(opening)
  return true
}

function clearTailInstalled(value) {
  if (!value) return
  for (const field of [
    'branchId',
    'circuitId',
    'tailControlTranscriptDigest',
    'tailIdentity',
    'tailAdvertisementDigest',
    'clientNonce'
  ]) {
    clear(value[field])
    value[field] = null
  }
  if (value.forwarding && typeof value.forwarding.destroy === 'function') {
    try {
      value.forwarding.destroy()
    } catch {}
  }
  if (value.destroySocketOwnerLease && value.socketOwnerLease) {
    try {
      value.destroySocketOwnerLease(value.socketOwnerLease)
    } catch {}
  }
  value.forwarding = null
  value.socketOwnerLease = null
  value.destroySocketOwnerLease = null
  value.readySealed = false
  value.generation = 0n
  value.extensionIndex = -1
  value.branchClass = -1
  value.expiresAtMs = 0n
}

function clearAdmittedExtendMaterial(value) {
  if (!value) return
  clearExtendRequest(value.request)
  clear(value.currentTailIdentity)
  clear(value.currentTailAdvertisementDigest)
  value.request = null
  value.currentTailIdentity = null
  value.currentTailAdvertisementDigest = null
  value.localDeadline = 0n
  value.wireExpiresAt = 0n
}

function clearBranchPathMaterial(value) {
  if (!value) return
  for (const field of [
    'advertisement',
    'advertisementDigest',
    'routeEncryptionPublicKey',
    'currentTailIdentity',
    'currentTailAdvertisementDigest',
    'branchId',
    'circuitId'
  ]) {
    clear(value[field])
    try {
      value[field] = null
    } catch {}
  }
  try {
    value.reservation = null
  } catch {}
}

function rollbackClientExtension(record) {
  if (!record) return false
  const authorization = record.authorization
  record.authorization = null
  const reservation = record.reservation
  record.reservation = null
  if (authorization) {
    try {
      failBranchPathAuthorization(authorization)
    } catch {}
  } else if (reservation) {
    try {
      failBranchPathReservation(reservation)
    } catch {}
  }
  for (const field of [
    'advertisementDigest',
    'routeEncryptionPublicKey',
    'responderIdentity',
    'branchId',
    'circuitId',
    'currentTailIdentity',
    'currentTailAdvertisementDigest',
    'clientTailEphemeralPublicKey',
    'clientTailEphemeralSecretKey',
    'clientNonce',
    'extensionNonce'
  ]) {
    clear(record[field])
    record[field] = null
  }
  record.generation = 0n
  record.extensionIndex = -1
  record.deadline = 0n
  record.requestedExpiresAt = 0n
  return true
}

function destroyClientExtensionCompletionState(state) {
  if (!state || state.destroyed) return false
  state.destroyed = true
  try {
    if (state.session) state.session.destroy()
  } catch {}
  state.session = null
  if (state.reservation) {
    try {
      failBranchPathReservation(state.reservation)
    } catch {}
  }
  state.reservation = null
  return true
}

function createClientExtensionCompletion(session, reservation) {
  const completion = Object.freeze({})
  CLIENT_EXTENSION_COMPLETIONS.set(completion, { session, reservation, destroyed: false })
  return completion
}

function encodeTailControlOrderedEnvelope(encoded) {
  let frame = null
  try {
    frame = b4a.alloc(1100)
    set(frame, encoded)
    return encodeM3ContextEnvelope({
      contextClass: CONTEXT_CLASS.TAIL_CONTROL_ORDERED,
      frame
    })
  } finally {
    clear(frame)
  }
}

function reserveAdmittedExtendRequest(state, session) {
  const record = {
    capability: null,
    request: null,
    currentTailIdentity: null,
    currentTailAdvertisementDigest: null,
    session,
    status: 'PENDING',
    localDeadline: 0n,
    wireExpiresAt: 0n,
    key: null,
    extensionNonce: null
  }
  state.extensionRequest = record
  return record
}

function publishAdmittedExtendRequest(
  state,
  reservation,
  request,
  key,
  localDeadline,
  wireExpiresAt,
  transcript
) {
  if (!reservation || state.extensionRequest !== reservation || reservation.status !== 'PENDING')
    invalid()
  let complete = false
  try {
    reservation.currentTailIdentity = copy(transcript.tailIdentity, 32)
    reservation.currentTailAdvertisementDigest = copy(transcript.candidateAdvertisementDigest, 32)
    reservation.extensionNonce = copy(request.extensionNonce, 32)
    reservation.capability = Object.freeze({})
    reservation.request = request
    reservation.localDeadline = localDeadline
    reservation.wireExpiresAt = wireExpiresAt
    reservation.key = key
    reservation.status = 'LIVE'
    ADMITTED_EXTEND_REQUESTS.set(reservation.capability, reservation)
    complete = true
    return reservation.capability
  } finally {
    if (!complete) clearAdmittedExtendRequest(reservation)
  }
}

function decodeReceivedTailControlObject(envelope) {
  let decoded = null
  let encoded = null
  try {
    decoded = decodeM3ContextEnvelope(envelope)
    if (decoded.contextClass !== CONTEXT_CLASS.TAIL_CONTROL_ORDERED) invalid()
    const frame = decoded.frame
    const bodyBytes = readUint16(frame, 6)
    const encodedBytes = 8 + bodyBytes
    if (
      encodedBytes < EXTEND_REQUEST_MIN_SIZE ||
      encodedBytes > EXTEND_REQUEST_MAX_SIZE ||
      encodedBytes > bufferLength(frame)
    ) {
      invalid()
    }
    for (let index = encodedBytes; index < bufferLength(frame); index++) {
      if (frame[index] !== 0) invalid()
    }
    encoded = copy(subarray(frame, 0, encodedBytes), encodedBytes)
    const result = encoded
    encoded = null
    return result
  } finally {
    if (decoded) clear(decoded.frame)
    clear(encoded)
  }
}

function rearmShortenedTailControlSession(session, state, localDeadline) {
  const { shortenM3TailLifetime } = require('./m3-adjacency-runtime')
  const current = BigInt(state.monotonicNow())
  if (!uint64(current)) invalid()
  if (current >= localDeadline) {
    destroyTailControlSession(session)
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
  if (localDeadline >= state.deadline.localDeadline) return state.deadline
  if (state.handle !== null) {
    try {
      state.cancelScheduled(state.handle)
    } catch {
      invalid()
    }
    state.handle = null
  }
  const deadline = shortenM3TailLifetime(state, localDeadline)
  try {
    armTailControlSession(session, state, current)
  } catch (err) {
    destroyTailControlSession(session)
    throw err
  }
  return deadline
}

function clearDecodedTailControlTranscript(value) {
  if (!value) return
  for (const field of [
    'branchId',
    'circuitId',
    'clientTailEphemeralPublicKey',
    'advertisedTailRouteEncryptionPublicKey',
    'candidateAdvertisementDigest',
    'clientNonce',
    'tailIdentity',
    'admittedLimitsDigest'
  ]) {
    clear(value[field])
    try {
      value[field] = null
    } catch {}
  }
}

function clearRelayCapabilityAdvertisement(value) {
  if (!value) return
  clear(value.relayIdentity)
  clear(value.currentDhtNodeId)
  clear(value.reachableEndpoint)
  clear(value.routeEncryptionPublicKey)
  clear(value.signature)
}

function authenticateRequestedLimitsDigest(requestedLimits, admittedLimitsDigest) {
  const digest = digestAdmittedLimits(requestedLimits)
  try {
    if (!b4a.equals(digest, admittedLimitsDigest)) authentication()
  } finally {
    clear(digest)
  }
}

function enforceRequestedLimitsWithinAdvertisement(requestedLimits, advertisement) {
  if (
    requestedLimits.cellSize !== advertisement.cellSize ||
    requestedLimits.maxCells > advertisement.maxCellsPerCircuit ||
    requestedLimits.maxBytes > advertisement.maxBytesPerCircuit ||
    requestedLimits.maxCommands > advertisement.maxCommandsPerCircuit ||
    requestedLimits.idleTimeoutMs > advertisement.idleTimeoutMs
  ) {
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
}

function randomBuffer(randomBytes) {
  if (typeof randomBytes !== 'function') invalid()
  let value
  try {
    value = randomBytes(32)
  } catch {
    invalid()
  }
  return copy(value, 32)
}

function clearClientExtensionCompletionRecord(completionState) {
  if (!completionState || completionState.destroyed) return false
  if (completionState.completion) {
    CLIENT_EXTENSION_COMPLETIONS.delete(completionState.completion)
    SPENT_CLIENT_EXTENSION_COMPLETIONS.add(completionState.completion)
  }
  completionState.destroyed = true
  clearExtended(completionState.extended)
  clearProofProjection(completionState.proof)
  clear(completionState.transcriptDigest)
  if (completionState.owner && completionState.owner.clientCompletion === completionState) {
    completionState.owner.clientCompletion = null
  }
  completionState.completion = null
  completionState.owner = null
  completionState.session = null
  completionState.record = null
  completionState.extended = null
  completionState.proof = null
  completionState.transcriptDigest = null
  return true
}

function clearClientExtension(record) {
  if (!record) return
  for (const field of [
    'advertisementDigest',
    'responderIdentity',
    'routeEncryptionPublicKey',
    'clientTailEphemeralPublicKey',
    'clientTailEphemeralSecretKey',
    'clientNonce',
    'payloadParametersDigest',
    'extensionNonce'
  ]) {
    clear(record[field])
    record[field] = null
  }
  record.requestedLimits = null
  record.deadline = 0n
}

function sealTailExtend(session, state, options) {
  if (SESSIONS.get(session) !== state || state.destroyed || !state.initiator) invalid()
  if (state.finalExitStage !== null) invalid()
  exactObject(options, [
    'advertisement',
    'advertisementDigest',
    'extensionIndex',
    'requestedLimits',
    'absoluteDeadline',
    'randomBytes'
  ])
  if (state.clientExtension !== null) busy()

  let transcript = null
  let advertisement = null
  let advertisementDigest = null
  let expectedAdvertisementDigest = null
  let payloadParametersDigest = null
  let decodedAdvertisement = null
  let clientTailEphemeralSeed = null
  let clientTailEphemeral = null
  let clientNonce = null
  let extensionNonce = null
  let encoded = null
  let record = null
  let complete = false
  try {
    const wall = BigInt(state.wallNow())
    const current = BigInt(state.monotonicNow())
    if (!uint64(wall) || current >= state.deadline.localDeadline) {
      throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    }
    const absoluteDeadline = option(options, 'absoluteDeadline')
    if (
      !uint64(absoluteDeadline) ||
      absoluteDeadline === 0n ||
      absoluteDeadline > state.deadline.localDeadline ||
      absoluteDeadline <= current
    ) {
      invalid()
    }
    transcript = decodeTailControlTranscript(state.transcript)
    const selectedExtensionIndex = nextExtensionIndex(option(options, 'extensionIndex'))
    if (selectedExtensionIndex !== transcript.extensionIndex + 1) invalid()
    const suppliedAdvertisement = option(options, 'advertisement')
    advertisement = copy(suppliedAdvertisement, bufferLength(suppliedAdvertisement))
    if (bufferLength(advertisement) < 260 || bufferLength(advertisement) > 548) invalid()
    decodedAdvertisement = decodeRelayCapabilityAdvertisement(advertisement, {
      now: wall
    })
    advertisementDigest = copy(option(options, 'advertisementDigest'), 32)
    expectedAdvertisementDigest = digestRelayCapabilityAdvertisement(advertisement, {
      now: wall
    })
    const expectedIdentityRole = selectedExtensionIndex === 1 ? ROLE.SAFETY : ROLE.PRIVATE
    if (
      !b4a.equals(advertisementDigest, expectedAdvertisementDigest) ||
      roleForIdentity(transcript.tailIdentity) !== ROLE.SAFETY ||
      roleForIdentity(decodedAdvertisement.relayIdentity) !== expectedIdentityRole ||
      b4a.equals(decodedAdvertisement.relayIdentity, transcript.tailIdentity)
    ) {
      authentication()
    }
    const requestedLimits = option(options, 'requestedLimits')
    authenticateRequestedLimitsDigest(requestedLimits, transcript.admittedLimitsDigest)
    enforceRequestedLimitsWithinAdvertisement(requestedLimits, decodedAdvertisement)
    const requestedWireExpiresAt = option(object(requestedLimits), 'expiresAtMs')
    if (!uint64(requestedWireExpiresAt) || requestedWireExpiresAt === 0n) invalid()
    // Two independent bounds, thrown separately so a stack attributes the
    // rejection to the one that fired. Same error and same fail-closed
    // behaviour either way; splitting them costs nothing and is the difference
    // between a diagnosable report and a guess.
    if (requestedWireExpiresAt > state.deadline.wireExpiresAt) {
      throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    }
    if (requestedWireExpiresAt > decodedAdvertisement.expiresAtMs) {
      throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    }
    clientTailEphemeralSeed = randomBuffer(option(options, 'randomBytes'))
    clientTailEphemeral = state.crypto.encryptionKeyPair(clientTailEphemeralSeed)
    clientNonce = randomBuffer(option(options, 'randomBytes'))
    extensionNonce = randomBuffer(option(options, 'randomBytes'))
    payloadParametersDigest = digestPayloadParameters(decodedAdvertisement)
    encoded = encodeExtendRequest({
      branchClass: transcript.branchClass,
      branchId: transcript.branchId,
      circuitId: transcript.circuitId,
      generation: transcript.generation,
      extensionIndex: selectedExtensionIndex,
      advertisement,
      clientTailEphemeralPublicKey: clientTailEphemeral.publicKey,
      clientNonce,
      payloadParametersDigest,
      requestedLimits,
      extensionNonce
    })
    record = {
      advertisementDigest: copy(advertisementDigest, 32),
      responderIdentity: copy(decodedAdvertisement.relayIdentity, 32),
      routeEncryptionPublicKey: copy(decodedAdvertisement.routeEncryptionPublicKey, 32),
      clientTailEphemeralPublicKey: copy(clientTailEphemeral.publicKey, 32),
      clientTailEphemeralSecretKey: copy(clientTailEphemeral.secretKey, 32),
      clientNonce: copy(clientNonce, 32),
      payloadParametersDigest: copy(payloadParametersDigest, 32),
      requestedLimits,
      extensionNonce: copy(extensionNonce, 32),
      deadline: absoluteDeadline
    }
    state.clientExtension = record
    complete = true
    return encoded
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    clearDecodedTailControlTranscript(transcript)
    clear(advertisement)
    clear(advertisementDigest)
    clear(expectedAdvertisementDigest)
    clear(payloadParametersDigest)
    clear(clientTailEphemeralSeed)
    if (clientTailEphemeral) {
      clear(clientTailEphemeral.publicKey)
      clear(clientTailEphemeral.secretKey)
    }
    clearRelayCapabilityAdvertisement(decodedAdvertisement)
    clear(clientNonce)
    clear(extensionNonce)
    if (!complete) {
      if (state.clientExtension === record) state.clientExtension = null
      clearClientExtension(record)
      clear(encoded)
    }
  }
}

function encodeExtendRequest(value) {
  value = object(value)
  let branchId = null
  let circuitId = null
  let advertisement = null
  let clientTailEphemeralPublicKey = null
  let clientNonce = null
  let payloadParametersDigest = null
  let requestedLimits = null
  let extensionNonce = null
  let body = null
  try {
    const selectedBranchClass = branchClass(option(value, 'branchClass'))
    branchId = copy(option(value, 'branchId'), 16)
    circuitId = copy(option(value, 'circuitId'), 16)
    const generation = option(value, 'generation')
    const selectedExtensionIndex = nextExtensionIndex(option(value, 'extensionIndex'))
    const suppliedAdvertisement = option(value, 'advertisement')
    const advertisementLength = bufferLength(suppliedAdvertisement)
    if (advertisementLength < 260 || advertisementLength > 548) invalid()
    advertisement = copy(suppliedAdvertisement, advertisementLength)
    clientTailEphemeralPublicKey = copy(option(value, 'clientTailEphemeralPublicKey'), 32)
    clientNonce = copy(option(value, 'clientNonce'), 32)
    payloadParametersDigest = copy(option(value, 'payloadParametersDigest'), 32)
    requestedLimits = encodeRequestedLimits(option(value, 'requestedLimits'))
    extensionNonce = copy(option(value, 'extensionNonce'), 32)
    if (
      !fixed(branchId, 16) ||
      !fixed(circuitId, 16) ||
      !uint64(generation) ||
      generation === 0n ||
      !nonzero(branchId) ||
      !nonzero(circuitId) ||
      !nonzero(clientTailEphemeralPublicKey) ||
      !nonzero(clientNonce) ||
      !nonzero(payloadParametersDigest) ||
      !nonzero(extensionNonce)
    ) {
      invalid()
    }
    assertNestedObject(
      advertisement,
      M3_MESSAGE_ID.CAPABILITY_ADVERTISEMENT_V1,
      bufferLength(advertisement) - 72,
      64
    )
    body = b4a.allocUnsafeSlow(EXTEND_REQUEST_FIXED_BODY_SIZE + bufferLength(advertisement))
    if (!fixed(body, EXTEND_REQUEST_FIXED_BODY_SIZE + bufferLength(advertisement))) invalid()
    body[0] = selectedBranchClass
    set(body, branchId, 1)
    set(body, circuitId, 17)
    writeUint64(body, generation, 33)
    body[41] = selectedExtensionIndex
    writeUint16(body, advertisement.byteLength, 42)
    set(body, advertisement, 44)
    let offset = 44 + advertisement.byteLength
    for (const encoded of [
      clientTailEphemeralPublicKey,
      clientNonce,
      payloadParametersDigest,
      requestedLimits,
      extensionNonce
    ]) {
      set(body, encoded, offset)
      offset += encoded.byteLength
    }
    return encodeM3Object({ messageId: M3_MESSAGE_ID.EXTEND_REQUEST_V1, body })
  } finally {
    for (const encoded of [
      branchId,
      circuitId,
      advertisement,
      clientTailEphemeralPublicKey,
      clientNonce,
      payloadParametersDigest,
      requestedLimits,
      extensionNonce,
      body
    ]) {
      clear(encoded)
    }
  }
}

function decodeExtendRequest(encoded) {
  const object = decodeM3Object(encoded)
  let result = null
  let complete = false
  try {
    if (
      bufferLength(encoded) < EXTEND_REQUEST_MIN_SIZE ||
      bufferLength(encoded) > EXTEND_REQUEST_MAX_SIZE ||
      object.messageId !== M3_MESSAGE_ID.EXTEND_REQUEST_V1 ||
      bufferLength(object.authSuffix) !== 0 ||
      bufferLength(object.body) < EXTEND_REQUEST_FIXED_BODY_SIZE + 260
    ) {
      invalid()
    }
    const body = object.body
    const advertisementLength = readUint16(body, 42)
    if (
      advertisementLength < 260 ||
      advertisementLength > 548 ||
      bufferLength(body) !== EXTEND_REQUEST_FIXED_BODY_SIZE + advertisementLength
    ) {
      invalid()
    }
    const advertisement = subarray(body, 44, 44 + advertisementLength)
    assertNestedObject(
      advertisement,
      M3_MESSAGE_ID.CAPABILITY_ADVERTISEMENT_V1,
      advertisementLength - 72,
      64
    )
    let offset = 44 + advertisementLength
    result = {}
    result.branchClass = branchClass(body[0])
    result.branchId = copy(subarray(body, 1, 17), 16)
    result.circuitId = copy(subarray(body, 17, 33), 16)
    result.generation = readUint64(body, 33)
    result.extensionIndex = nextExtensionIndex(body[41])
    result.advertisement = copy(advertisement, advertisementLength)
    result.clientTailEphemeralPublicKey = copy(subarray(body, offset, offset + 32), 32)
    result.clientNonce = copy(subarray(body, offset + 32, offset + 64), 32)
    result.payloadParametersDigest = copy(subarray(body, offset + 64, offset + 96), 32)
    result.requestedLimits = decodeRequestedLimits(subarray(body, offset + 96, offset + 122))
    result.extensionNonce = copy(subarray(body, offset + 122, offset + 154), 32)
    if (
      result.generation === 0n ||
      !nonzero(result.branchId) ||
      !nonzero(result.circuitId) ||
      !nonzero(result.clientTailEphemeralPublicKey) ||
      !nonzero(result.clientNonce) ||
      !nonzero(result.payloadParametersDigest) ||
      !nonzero(result.extensionNonce)
    ) {
      invalid()
    }
    complete = true
    return Object.freeze(result)
  } finally {
    clear(object.body)
    clear(object.authSuffix)
    if (!complete) clearExtendRequest(result)
  }
}

function clearExtended(value) {
  if (!value) return
  for (const field of [
    'branchId',
    'circuitId',
    'responderAdvertisementDigest',
    'redactedProof',
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

function encodeExtended(value) {
  value = object(value)
  let branchId = null
  let circuitId = null
  let responderAdvertisementDigest = null
  let redactedProof = null
  let extensionNonce = null
  let body = null
  try {
    const selectedBranchClass = branchClass(option(value, 'branchClass'))
    branchId = copy(option(value, 'branchId'), 16)
    circuitId = copy(option(value, 'circuitId'), 16)
    const generation = option(value, 'generation')
    const selectedExtensionIndex = nextExtensionIndex(option(value, 'extensionIndex'))
    responderAdvertisementDigest = copy(option(value, 'responderAdvertisementDigest'), 32)
    redactedProof = copy(option(value, 'redactedProof'), REDACTED_RESPONDER_PROOF_SIZE)
    extensionNonce = copy(option(value, 'extensionNonce'), 32)
    if (
      !fixed(branchId, 16) ||
      !fixed(circuitId, 16) ||
      !uint64(generation) ||
      generation === 0n ||
      !nonzero(branchId) ||
      !nonzero(circuitId) ||
      !nonzero(responderAdvertisementDigest) ||
      !nonzero(extensionNonce)
    ) {
      invalid()
    }
    assertNestedObject(redactedProof, M3_MESSAGE_ID.REDACTED_RESPONDER_PROOF_V1, 306, 64)
    body = b4a.allocUnsafeSlow(EXTENDED_BODY_SIZE)
    if (!fixed(body, EXTENDED_BODY_SIZE)) invalid()
    body[0] = selectedBranchClass
    set(body, branchId, 1)
    set(body, circuitId, 17)
    writeUint64(body, generation, 33)
    body[41] = selectedExtensionIndex
    set(body, responderAdvertisementDigest, 42)
    writeUint16(body, REDACTED_RESPONDER_PROOF_SIZE, 74)
    set(body, redactedProof, 76)
    set(body, extensionNonce, 454)
    return encodeM3Object({ messageId: M3_MESSAGE_ID.EXTENDED_V1, body })
  } finally {
    for (const encoded of [
      branchId,
      circuitId,
      responderAdvertisementDigest,
      redactedProof,
      extensionNonce,
      body
    ]) {
      clear(encoded)
    }
  }
}

function decodeExtended(encoded) {
  const object = decodeM3Object(encoded)
  let result = null
  let complete = false
  try {
    if (
      !fixed(encoded, EXTENDED_SIZE) ||
      object.messageId !== M3_MESSAGE_ID.EXTENDED_V1 ||
      !fixed(object.body, EXTENDED_BODY_SIZE) ||
      bufferLength(object.authSuffix) !== 0 ||
      readUint16(object.body, 74) !== REDACTED_RESPONDER_PROOF_SIZE
    ) {
      invalid()
    }
    const proof = subarray(object.body, 76, 454)
    assertNestedObject(proof, M3_MESSAGE_ID.REDACTED_RESPONDER_PROOF_V1, 306, 64)
    result = {}
    result.branchClass = branchClass(object.body[0])
    result.branchId = copy(subarray(object.body, 1, 17), 16)
    result.circuitId = copy(subarray(object.body, 17, 33), 16)
    result.generation = readUint64(object.body, 33)
    result.extensionIndex = nextExtensionIndex(object.body[41])
    result.responderAdvertisementDigest = copy(subarray(object.body, 42, 74), 32)
    result.redactedProof = copy(proof, REDACTED_RESPONDER_PROOF_SIZE)
    result.extensionNonce = copy(subarray(object.body, 454, 486), 32)
    if (
      result.generation === 0n ||
      !nonzero(result.branchId) ||
      !nonzero(result.circuitId) ||
      !nonzero(result.responderAdvertisementDigest) ||
      !nonzero(result.extensionNonce)
    ) {
      invalid()
    }
    complete = true
    return Object.freeze(result)
  } finally {
    clear(object.body)
    clear(object.authSuffix)
    if (!complete) clearExtended(result)
  }
}

function encodeAdmittedLimits(value) {
  try {
    object(value)
    const cellSize = option(value, 'cellSize')
    const maxCells = option(value, 'maxCells')
    const maxBytes = option(value, 'maxBytes')
    const maxCommands = option(value, 'maxCommands')
    const idleTimeoutMs = option(value, 'idleTimeoutMs')
    const expiresAtMs = option(value, 'expiresAtMs')

    if (
      cellSize !== 1200 ||
      !uint16(cellSize) ||
      !uint32(maxCells) ||
      maxCells === 0 ||
      !uint32(maxBytes) ||
      maxBytes === 0 ||
      !uint32(maxCommands) ||
      maxCommands === 0 ||
      !uint32(idleTimeoutMs) ||
      idleTimeoutMs === 0 ||
      !uint64(expiresAtMs) ||
      expiresAtMs === 0n
    ) {
      invalid()
    }

    const output = b4a.allocUnsafe(ADMITTED_LIMITS_SIZE)
    writeUint16(output, cellSize, 0)
    writeUint32(output, maxCells, 2)
    writeUint32(output, maxBytes, 6)
    writeUint32(output, maxCommands, 10)
    writeUint32(output, idleTimeoutMs, 14)
    writeUint64(output, expiresAtMs, 18)
    return output
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  }
}

function decodeAdmittedLimits(encoded) {
  if (!fixed(encoded, ADMITTED_LIMITS_SIZE)) invalid()
  const value = {
    cellSize: readUint16(encoded, 0),
    maxCells: readUint32(encoded, 2),
    maxBytes: readUint32(encoded, 6),
    maxCommands: readUint32(encoded, 10),
    idleTimeoutMs: readUint32(encoded, 14),
    expiresAtMs: readUint64(encoded, 18)
  }
  const canonical = encodeAdmittedLimits(value)
  clear(canonical)
  return value
}

function digestAdmittedLimits(value) {
  const encoded = encodeAdmittedLimits(value)
  try {
    return copy(cryptoSuite.hash([LIMITS_DOMAIN, encoded]))
  } finally {
    clear(encoded)
  }
}

function encodeTailControlTranscript(value) {
  try {
    object(value)
    const selectedBranchClass = branchClass(option(value, 'branchClass'))
    const branchId = option(value, 'branchId')
    const circuitId = option(value, 'circuitId')
    const generation = option(value, 'generation')
    const selectedExtensionIndex = extensionIndex(option(value, 'extensionIndex'))
    const clientTailEphemeralPublicKey = option(value, 'clientTailEphemeralPublicKey')
    const advertisedTailRouteEncryptionPublicKey = option(
      value,
      'advertisedTailRouteEncryptionPublicKey'
    )
    const candidateAdvertisementDigest = option(value, 'candidateAdvertisementDigest')
    const clientNonce = option(value, 'clientNonce')
    const tailIdentity = option(value, 'tailIdentity')
    const admittedLimitsDigest = option(value, 'admittedLimitsDigest')

    if (
      !fixed(branchId, 16) ||
      !fixed(circuitId, 16) ||
      !uint64(generation) ||
      !fixed(clientTailEphemeralPublicKey, 32) ||
      !fixed(advertisedTailRouteEncryptionPublicKey, 32) ||
      !fixed(candidateAdvertisementDigest, 32) ||
      !fixed(clientNonce, 32) ||
      !fixed(tailIdentity, 32) ||
      !fixed(admittedLimitsDigest, 32)
    ) {
      invalid()
    }

    const output = b4a.allocUnsafe(TAIL_CONTROL_TRANSCRIPT_SIZE)
    let offset = 0
    const tailDomainBytes = bufferLength(TAIL_DOMAIN)
    writeUint16(output, tailDomainBytes, offset)
    offset += 2
    set(output, TAIL_DOMAIN, offset)
    offset += tailDomainBytes
    writeUint32(output, M3_PROTOCOL_VERSION, offset)
    offset += 4
    output[offset++] = selectedBranchClass
    set(output, branchId, offset)
    offset += 16
    set(output, circuitId, offset)
    offset += 16
    writeUint64(output, generation, offset)
    offset += 8
    output[offset++] = selectedExtensionIndex
    for (const field of [
      clientTailEphemeralPublicKey,
      advertisedTailRouteEncryptionPublicKey,
      candidateAdvertisementDigest,
      clientNonce,
      tailIdentity,
      admittedLimitsDigest
    ]) {
      set(output, field, offset)
      offset += 32
    }
    return output
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  }
}

function validateTailControlTranscript(encoded) {
  if (!fixed(encoded, TAIL_CONTROL_TRANSCRIPT_SIZE)) invalid()
  const tailDomainBytes = bufferLength(TAIL_DOMAIN)
  if (readUint16(encoded, 0) !== tailDomainBytes) invalid()
  if (!b4a.equals(subarray(encoded, 2, 2 + tailDomainBytes), TAIL_DOMAIN)) invalid()

  let offset = 2 + tailDomainBytes
  if (readUint32(encoded, offset) !== M3_PROTOCOL_VERSION) invalid()
  offset += 4
  branchClass(encoded[offset++])
  offset += 16 + 16 + 8
  return extensionIndex(encoded[offset])
}

function decodeTailControlTranscript(encoded) {
  try {
    validateTailControlTranscript(encoded)
    const tailDomainBytes = bufferLength(TAIL_DOMAIN)
    let offset = 2 + tailDomainBytes
    offset += 4
    const selectedBranchClass = encoded[offset++]
    const branchId = copy(subarray(encoded, offset, offset + 16))
    offset += 16
    const circuitId = copy(subarray(encoded, offset, offset + 16))
    offset += 16
    const generation = readUint64(encoded, offset)
    offset += 8
    const selectedExtensionIndex = encoded[offset++]
    const fields = []
    for (let index = 0; index < 6; index++) {
      fields.push(copy(subarray(encoded, offset, offset + 32)))
      offset += 32
    }

    return {
      branchClass: selectedBranchClass,
      branchId,
      circuitId,
      generation,
      extensionIndex: selectedExtensionIndex,
      clientTailEphemeralPublicKey: fields[0],
      advertisedTailRouteEncryptionPublicKey: fields[1],
      candidateAdvertisementDigest: fields[2],
      clientNonce: fields[3],
      tailIdentity: fields[4],
      admittedLimitsDigest: fields[5]
    }
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  }
}

function digestTailControlTranscript(transcript) {
  validateTailControlTranscript(transcript)
  return copy(cryptoSuite.hash([TAIL_DIGEST_DOMAIN, transcript]))
}

function derive(secret, label, transcript) {
  let input = null
  let output = null
  try {
    const labelBytes = b4a.from(label)
    const labelLength = bufferLength(labelBytes)
    const transcriptLength = bufferLength(transcript)
    input = b4a.allocUnsafe(2 + labelLength + 4 + 4 + transcriptLength)
    writeUint16(input, labelLength, 0)
    set(input, labelBytes, 2)
    writeUint32(input, M3_PROTOCOL_VERSION, 2 + labelLength)
    writeUint32(input, transcriptLength, 6 + labelLength)
    set(input, transcript, 10 + labelLength)
    output = b4a.allocUnsafeSlow(32)
    sodium.crypto_generichash(output, input, secret)
    return output
  } catch {
    clear(output)
    invalid()
  } finally {
    clear(input)
  }
}

function deriveTailControlTestVector(sharedSecret, transcript, selectedExtensionIndex) {
  if (!fixed(sharedSecret, 32)) invalid()
  const transcriptExtensionIndex = validateTailControlTranscript(transcript)
  if (extensionIndex(selectedExtensionIndex) !== transcriptExtensionIndex) invalid()

  const labels = selectedExtensionIndex === 2 ? { ...TAIL_LABELS, ...FINALIZE_LABELS } : TAIL_LABELS
  const result = {}
  const owned = []
  let complete = false

  try {
    for (const [name, label] of Object.entries(labels)) {
      const output = derive(sharedSecret, label, transcript)
      owned.push(output)
      if (name.endsWith('Nonce')) result[`${name}Prefix`] = copy(subarray(output, 0, 16))
      else result[name] = output
    }
    complete = true
    return Object.freeze(result)
  } finally {
    for (const output of owned) {
      if (!Object.values(result).includes(output) || !complete) clear(output)
    }
    if (!complete) {
      for (const output of Object.values(result)) clear(output)
    }
  }
}

function tailReadySignatureInput(body) {
  const output = b4a.allocUnsafeSlow(10 + TAIL_READY_DOMAIN.byteLength + body.byteLength)
  writeUint16(output, TAIL_READY_DOMAIN.byteLength, 0)
  set(output, TAIL_READY_DOMAIN, 2)
  writeUint32(output, M3_PROTOCOL_VERSION, 2 + TAIL_READY_DOMAIN.byteLength)
  writeUint16(output, M3_MESSAGE_ID.TAIL_READY_V1, 6 + TAIL_READY_DOMAIN.byteLength)
  writeUint16(output, body.byteLength, 8 + TAIL_READY_DOMAIN.byteLength)
  set(output, body, 10 + TAIL_READY_DOMAIN.byteLength)
  return output
}

function redactedResponderProofSignatureInput(body) {
  const output = b4a.allocUnsafeSlow(
    10 + REDACTED_RESPONDER_PROOF_DOMAIN.byteLength + body.byteLength
  )
  writeUint16(output, REDACTED_RESPONDER_PROOF_DOMAIN.byteLength, 0)
  set(output, REDACTED_RESPONDER_PROOF_DOMAIN, 2)
  writeUint32(output, M3_PROTOCOL_VERSION, 2 + REDACTED_RESPONDER_PROOF_DOMAIN.byteLength)
  writeUint16(
    output,
    M3_MESSAGE_ID.REDACTED_RESPONDER_PROOF_V1,
    6 + REDACTED_RESPONDER_PROOF_DOMAIN.byteLength
  )
  writeUint16(output, body.byteLength, 8 + REDACTED_RESPONDER_PROOF_DOMAIN.byteLength)
  set(output, body, 10 + REDACTED_RESPONDER_PROOF_DOMAIN.byteLength)
  return output
}

function verifyRedactedResponderProofSignature(encoded, responderIdentity) {
  let object = null
  let input = null
  try {
    object = decodeM3Object(encoded)
    if (
      object.messageId !== M3_MESSAGE_ID.REDACTED_RESPONDER_PROOF_V1 ||
      !fixed(object.body, REDACTED_RESPONDER_PROOF_BODY_SIZE) ||
      !fixed(object.authSuffix, 64)
    ) {
      authentication()
    }
    input = redactedResponderProofSignatureInput(object.body)
    if (cryptoSuite.verify(input, object.authSuffix, responderIdentity) !== true) authentication()
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    authentication()
  } finally {
    clear(input)
    clear(object && object.body)
    clear(object && object.authSuffix)
  }
}

function digestTailReadyTranscript(transcript) {
  let output = null
  try {
    output = cryptoSuite.hash([TAIL_READY_TRANSCRIPT_DOMAIN, transcript])
    if (!fixed(output, 32)) invalid()
    return copy(output)
  } finally {
    clear(output)
  }
}

function decodeTailReadyBody(body) {
  if (!fixed(body, TAIL_READY_BODY_SIZE)) invalid()
  return {
    branchClass: branchClass(body[0]),
    branchId: copy(subarray(body, 1, 17)),
    circuitId: copy(subarray(body, 17, 33)),
    generation: readUint64(body, 33),
    extensionIndex: extensionIndex(body[41]),
    tailControlTranscriptDigest: copy(subarray(body, 42, 74)),
    tailIdentity: copy(subarray(body, 74, 106)),
    tailAdvertisementDigest: copy(subarray(body, 106, 138)),
    clientNonce: copy(subarray(body, 138, 170)),
    readyNonce: copy(subarray(body, 170, 202)),
    expiresAtMs: readUint64(body, 202)
  }
}

function clearTailReady(value) {
  if (!value) return
  for (const child of Object.values(value)) clear(child)
}

function decodeTailReady(encoded) {
  const object = decodeM3Object(encoded)
  if (
    !fixed(encoded, TAIL_READY_SIZE) ||
    object.messageId !== M3_MESSAGE_ID.TAIL_READY_V1 ||
    !fixed(object.body, TAIL_READY_BODY_SIZE) ||
    !fixed(object.authSuffix, 64)
  ) {
    clear(object.body)
    clear(object.authSuffix)
    invalid()
  }
  const decoded = decodeTailReadyBody(object.body)
  decoded.body = object.body
  decoded.signature = object.authSuffix
  decoded.encoded = copy(encoded)
  return decoded
}

function clearProofProjection(value) {
  if (!value) return
  for (const child of Object.values(value)) clear(child)
}

function verifyTailReadySignature(ready) {
  let input = null
  try {
    input = tailReadySignatureInput(ready.body)
    if (cryptoSuite.verify(input, ready.signature, ready.tailIdentity) !== true) authentication()
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    authentication()
  } finally {
    clear(input)
  }
}

function fieldsMatchExtended(transcript, record, extended, proof, wallNow) {
  let limitsDigest = null
  try {
    limitsDigest = digestAdmittedLimits(record.requestedLimits)
    return (
      extended.branchClass === transcript.branchClass &&
      b4a.equals(extended.branchId, transcript.branchId) &&
      b4a.equals(extended.circuitId, transcript.circuitId) &&
      extended.generation === transcript.generation &&
      extended.extensionIndex === transcript.extensionIndex + 1 &&
      b4a.equals(extended.extensionNonce, record.extensionNonce) &&
      b4a.equals(extended.responderAdvertisementDigest, record.advertisementDigest) &&
      b4a.equals(proof.responderAdvertisementDigest, extended.responderAdvertisementDigest) &&
      b4a.equals(proof.initiatorIdentity, transcript.tailIdentity) &&
      b4a.equals(proof.responderIdentity, record.responderIdentity) &&
      proof.branchClass === extended.branchClass &&
      b4a.equals(proof.branchId, extended.branchId) &&
      b4a.equals(proof.circuitId, extended.circuitId) &&
      proof.generation === extended.generation &&
      proof.extensionIndex === extended.extensionIndex &&
      b4a.equals(proof.clientTailEphemeralPublicKey, record.clientTailEphemeralPublicKey) &&
      b4a.equals(proof.clientNonce, record.clientNonce) &&
      b4a.equals(proof.advertisedRouteEncryptionPublicKey, record.routeEncryptionPublicKey) &&
      b4a.equals(proof.admittedLimitsDigest, limitsDigest) &&
      proof.expiresAtMs <= record.requestedLimits.expiresAtMs &&
      proof.expiresAtMs > wallNow
    )
  } finally {
    clear(limitsDigest)
  }
}

function fieldsMatchReady(record, extended, proof, transcriptDigest, ready) {
  return (
    ready.branchClass === extended.branchClass &&
    b4a.equals(ready.branchId, extended.branchId) &&
    b4a.equals(ready.circuitId, extended.circuitId) &&
    ready.generation === extended.generation &&
    ready.extensionIndex === extended.extensionIndex &&
    b4a.equals(ready.tailControlTranscriptDigest, transcriptDigest) &&
    b4a.equals(ready.tailIdentity, proof.responderIdentity) &&
    b4a.equals(ready.tailAdvertisementDigest, extended.responderAdvertisementDigest) &&
    b4a.equals(ready.clientNonce, record.clientNonce) &&
    ready.expiresAtMs === proof.expiresAtMs
  )
}

function openClientExtended(session, state, encoded) {
  if (SESSIONS.get(session) !== state || state.destroyed || !state.initiator) invalid()
  if (state.finalExitStage !== null) invalid()
  const record = state.clientExtension
  if (state.clientCompletion) busy()
  if (!record) invalid()
  state.clientCompletion = CLIENT_EXTENSION_COMPLETION_RESERVED
  let transcript = null
  let extended = null
  let proof = null
  let transcriptDigest = null
  let published = false
  try {
    transcript = decodeTailControlTranscript(state.transcript)
    extended = decodeExtended(encoded)
    proof = decodeRedactedResponderProof(extended.redactedProof)
    verifyRedactedResponderProofSignature(extended.redactedProof, proof.responderIdentity)
    const wallNow = BigInt(state.wallNow())
    if (!uint64(wallNow) || !fieldsMatchExtended(transcript, record, extended, proof, wallNow)) {
      authentication()
    }
    transcriptDigest = digestTailReadyTranscript(state.transcript)
    const completion = Object.freeze({})
    const completionState = {
      completion,
      owner: state,
      session,
      record,
      extended,
      proof,
      transcriptDigest,
      destroyed: false,
      committing: false
    }
    CLIENT_EXTENSION_COMPLETIONS.set(completion, completionState)
    state.clientCompletion = completionState
    published = true
    extended = null
    proof = null
    transcriptDigest = null
    return completion
  } finally {
    clearDecodedTailControlTranscript(transcript)
    clearExtended(extended)
    clearProofProjection(proof)
    clear(transcriptDigest)
    if (!published && state.clientCompletion === CLIENT_EXTENSION_COMPLETION_RESERVED) {
      state.clientCompletion = null
    }
  }
}

function clearFinalExitMaterial(material) {
  if (!material) return false
  try {
    const { destroyFinalExitHandoffMaterial } = require('./final-exit-handoff')
    return destroyFinalExitHandoffMaterial(material)
  } catch {
    return false
  }
}

function clearTailControlDerived(value) {
  if (!value) return
  clear(value.forwardKey)
  clear(value.reverseKey)
  clear(value.forwardNoncePrefix)
  clear(value.reverseNoncePrefix)
  clear(value.finalizeForwardKey)
  clear(value.finalizeForwardNoncePrefix)
  clear(value.finalizeReverseKey)
  clear(value.finalizeReverseNoncePrefix)
}

function clearTailControlSuccessorMaterial(material) {
  if (!material) return
  clear(material.transcript)
  clear(material.sharedSecret)
  material.transcript = null
  material.sharedSecret = null
}

function clampTailControlProofDeadline(session, state, proofExpiresAt) {
  if (!uint64(proofExpiresAt) || proofExpiresAt === 0n) authentication()
  const deadline = state.deadline
  if (proofExpiresAt > deadline.wireExpiresAt) authentication()
  if (proofExpiresAt === deadline.wireExpiresAt) return deadline
  const delta = deadline.wireExpiresAt - proofExpiresAt
  if (delta >= deadline.localDeadline) {
    destroyTailControlSession(session)
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
  const localDeadline = deadline.localDeadline - delta
  return rearmShortenedTailControlSession(session, state, localDeadline)
}

function createTailControlSuccessorMaterial(state, record, completionState) {
  let transcript = null
  let sharedSecret = null
  let derived = null
  let agreed = null
  let material = null
  let complete = false
  try {
    transcript = encodeTailControlTranscript({
      branchClass: completionState.proof.branchClass,
      branchId: completionState.proof.branchId,
      circuitId: completionState.proof.circuitId,
      generation: completionState.proof.generation,
      extensionIndex: completionState.proof.extensionIndex,
      clientTailEphemeralPublicKey: record.clientTailEphemeralPublicKey,
      advertisedTailRouteEncryptionPublicKey: record.routeEncryptionPublicKey,
      candidateAdvertisementDigest: completionState.proof.responderAdvertisementDigest,
      clientNonce: record.clientNonce,
      tailIdentity: completionState.proof.responderIdentity,
      admittedLimitsDigest: completionState.proof.admittedLimitsDigest
    })
    agreed = state.crypto.keyAgreement(
      record.clientTailEphemeralSecretKey,
      record.routeEncryptionPublicKey
    )
    if (!fixed(agreed, 32)) authentication()
    sharedSecret = copy(agreed)
    derived = deriveTailControlTestVector(sharedSecret, transcript, 1)
    material = { transcript, sharedSecret }
    complete = true
    transcript = null
    sharedSecret = null
    return material
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    clear(agreed)
    clearTailControlDerived(derived)
    if (!complete) {
      clear(transcript)
      clear(sharedSecret)
      clearTailControlSuccessorMaterial(material)
    }
  }
}

function createFinalExitMaterial(session, state, record, completionState) {
  let transcript = null
  let sharedSecret = null
  let derived = null
  let agreed = null
  let material = null
  let complete = false
  try {
    transcript = encodeTailControlTranscript({
      branchClass: completionState.proof.branchClass,
      branchId: completionState.proof.branchId,
      circuitId: completionState.proof.circuitId,
      generation: completionState.proof.generation,
      extensionIndex: completionState.proof.extensionIndex,
      clientTailEphemeralPublicKey: record.clientTailEphemeralPublicKey,
      advertisedTailRouteEncryptionPublicKey: record.routeEncryptionPublicKey,
      candidateAdvertisementDigest: completionState.proof.responderAdvertisementDigest,
      clientNonce: record.clientNonce,
      tailIdentity: completionState.proof.responderIdentity,
      admittedLimitsDigest: completionState.proof.admittedLimitsDigest
    })
    agreed = state.crypto.keyAgreement(
      record.clientTailEphemeralSecretKey,
      record.routeEncryptionPublicKey
    )
    if (!fixed(agreed, 32)) authentication()
    sharedSecret = copy(agreed)
    derived = deriveTailControlTestVector(sharedSecret, transcript, 2)
    material = {
      clockIdentity: state.deadline.clockIdentity,
      expiresAt: completionState.proof.expiresAtMs,
      finalizeForwardKey: derived.finalizeForwardKey,
      finalizeForwardNoncePrefix: derived.finalizeForwardNoncePrefix,
      finalizeReverseKey: derived.finalizeReverseKey,
      finalizeReverseNoncePrefix: derived.finalizeReverseNoncePrefix,
      initiator: true,
      localDeadline: state.deadline.localDeadline,
      sharedSecret,
      tailControl: session,
      tailControlTranscript: transcript,
      wireExpiresAt: state.deadline.wireExpiresAt
    }
    clear(derived.forwardKey)
    clear(derived.reverseKey)
    clear(derived.forwardNoncePrefix)
    clear(derived.reverseNoncePrefix)
    complete = true
    return material
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    clear(agreed)
    if (!complete) {
      clear(transcript)
      clear(sharedSecret)
      clearTailControlDerived(derived)
      clearFinalExitMaterial(material)
    }
  }
}

function createResponderFinalExitMaterial(session, state) {
  let derived = null
  let material = null
  let complete = false
  try {
    if (state.initiator || state.extensionIndex !== 2 || !fixed(state.secret, 32)) invalid()
    derived = deriveTailControlTestVector(state.secret, state.transcript, 2)
    material = {
      clockIdentity: state.deadline.clockIdentity,
      expiresAt: state.deadline.wireExpiresAt,
      finalizeForwardKey: derived.finalizeForwardKey,
      finalizeForwardNoncePrefix: derived.finalizeForwardNoncePrefix,
      finalizeReverseKey: derived.finalizeReverseKey,
      finalizeReverseNoncePrefix: derived.finalizeReverseNoncePrefix,
      initiator: false,
      localDeadline: state.deadline.localDeadline,
      sharedSecret: copy(state.secret, 32),
      tailControl: session,
      tailControlTranscript: copy(state.transcript, TAIL_CONTROL_TRANSCRIPT_SIZE),
      wireExpiresAt: state.deadline.wireExpiresAt
    }
    clear(derived.forwardKey)
    clear(derived.reverseKey)
    clear(derived.forwardNoncePrefix)
    clear(derived.reverseNoncePrefix)
    complete = true
    return material
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    if (!complete) {
      clearTailControlDerived(derived)
      clearFinalExitMaterial(material)
    }
  }
}

function takeFinalExitHandoff(session, state) {
  if (SESSIONS.get(session) !== state || state.destroyed) invalid()
  let material = state.finalExitMaterial
  if (!material && !state.initiator && state.extensionIndex === 2 && state.responderAuthority) {
    material = createResponderFinalExitMaterial(session, state)
    state.finalExitMaterial = material
    state.finalExitStage = 'FINAL_EXIT_READY'
  }
  if (!material) invalid()
  state.finalExitMaterial = null
  const { createFinalExitHandoff } = require('./final-exit-handoff')
  let handoff = null
  let complete = false
  try {
    handoff = createFinalExitHandoff(session, material)
    FINAL_EXIT_HANDOFFS.set(handoff, {
      owner: session,
      state,
      material,
      claiming: false,
      generation: ++state.finalExitGeneration
    })
    FINAL_EXIT_HANDOFF_OWNERS.set(session, handoff)
    FINAL_EXIT_TIMER_STATES.set(session, state)
    SESSIONS.delete(session)
    DESTROYED_SESSIONS.add(session)
    state.finalExitStage = 'FINAL_EXIT_HANDOFF'
    complete = true
    return handoff
  } finally {
    if (!complete) {
      state.finalExitMaterial = material
      state.finalExitStage = null
      FINAL_EXIT_HANDOFF_OWNERS.delete(session)
      if (handoff) FINAL_EXIT_HANDOFFS.delete(handoff)
    }
  }
}
function prepareTailControlFinalExitActivation(handoff, activationOwner) {
  const record = object(handoff) ? FINAL_EXIT_HANDOFFS.get(handoff) : null
  if (!record || !object(activationOwner)) authentication()
  const state = record.state
  const material = record.material
  if (
    !state ||
    !material ||
    record.claiming ||
    state.finalExitStage !== 'FINAL_EXIT_HANDOFF' ||
    state.finalExitMaterial !== null ||
    material.tailControl !== record.owner ||
    material.localDeadline !== state.deadline.localDeadline ||
    material.wireExpiresAt !== state.deadline.wireExpiresAt ||
    material.clockIdentity !== state.deadline.clockIdentity
  ) {
    invalid()
  }
  record.claiming = true
  const {
    reserveFinalExitActivationOwner,
    revokeFinalExitActivationOwnerReservation
  } = require('./final-exit-activation')
  const { consumeFinalExitHandoff } = require('./final-exit-handoff')
  let reservation = null
  let consumed = null
  let complete = false
  try {
    const current = BigInt(state.monotonicNow())
    if (!uint64(current) || current >= state.deadline.localDeadline) invalid()
    reservation = reserveFinalExitActivationOwner(activationOwner)
    FINAL_EXIT_PREPARE_CONSUMES.add(handoff)
    try {
      consumed = consumeFinalExitHandoff(handoff)
    } finally {
      FINAL_EXIT_PREPARE_CONSUMES.delete(handoff)
    }
    FINAL_EXIT_HANDOFF_OWNERS.delete(record.owner)
    if (consumed !== material) authentication()
    FINAL_EXIT_HANDOFFS.delete(handoff)
    const transfer = Object.freeze({})
    FINAL_EXIT_TRANSFERS.set(transfer, {
      owner: record.owner,
      state,
      handoff,
      activationOwner,
      reservation,
      material,
      generation: ++state.finalExitGeneration,
      committed: false
    })
    complete = true
    return Object.freeze({ transfer, material })
  } finally {
    if (!complete) {
      record.claiming = false
      if (reservation) revokeFinalExitActivationOwnerReservation(reservation)
      if (consumed === material) clearFinalExitMaterial(material)
    }
  }
}

function commitTailControlFinalExitActivation(transfer, activationOwner) {
  const record = object(transfer) ? FINAL_EXIT_TRANSFERS.get(transfer) : null
  if (!record || record.committed || record.activationOwner !== activationOwner) authentication()
  const state = record.state
  const material = record.material
  if (
    !state ||
    !material ||
    state.finalExitStage !== 'FINAL_EXIT_HANDOFF' ||
    material.tailControl !== record.owner ||
    material.localDeadline !== state.deadline.localDeadline ||
    material.wireExpiresAt !== state.deadline.wireExpiresAt ||
    material.clockIdentity !== state.deadline.clockIdentity
  ) {
    invalid()
  }
  const current = BigInt(state.monotonicNow())
  if (!uint64(current) || current >= state.deadline.localDeadline) invalid()
  const { consumeFinalExitActivationOwnerReservation } = require('./final-exit-activation')
  const consumed = consumeFinalExitActivationOwnerReservation(record.reservation, activationOwner)
  if (consumed !== material) authentication()
  FINAL_EXIT_TRANSFERS.delete(transfer)
  record.committed = true
  state.finalExitActivationOwner = activationOwner
  state.finalExitActivationMaterial = material
  FINAL_EXIT_ACTIVATIONS.set(activationOwner, {
    owner: record.owner,
    state,
    material
  })
  state.finalExitStage = 'FINAL_EXIT_ACTIVATION'
  return true
}

function revokeTailControlFinalExitActivation(transfer) {
  const record = object(transfer) ? FINAL_EXIT_TRANSFERS.get(transfer) : null
  if (!record || record.committed) return false
  FINAL_EXIT_TRANSFERS.delete(transfer)
  const { revokeFinalExitActivationOwnerReservation } = require('./final-exit-activation')
  revokeFinalExitActivationOwnerReservation(record.reservation)
  record.state.finalExitActivationMaterial = record.material
  record.state.finalExitStage = 'FINAL_EXIT_REVOKED'
  releaseFinalExitTailControlState(record.owner, record.state)
  return true
}
function releaseFinalExitTailControlState(owner, state) {
  if (!object(owner) || !state || state.destroyed) return false
  FINAL_EXIT_TIMER_STATES.delete(owner)
  const handoff = FINAL_EXIT_HANDOFF_OWNERS.get(owner)
  if (handoff) {
    FINAL_EXIT_HANDOFF_OWNERS.delete(owner)
    FINAL_EXIT_HANDOFFS.delete(handoff)
    try {
      const { revokeFinalExitHandoff } = require('./final-exit-handoff')
      revokeFinalExitHandoff(owner)
    } catch {}
  }
  const activationOwner = state.finalExitActivationOwner
  if (activationOwner) {
    FINAL_EXIT_ACTIVATIONS.delete(activationOwner)
    state.finalExitActivationOwner = null
    try {
      const { destroyFinalExitActivationOwner } = require('./final-exit-activation')
      destroyFinalExitActivationOwner(activationOwner)
    } catch {}
  }
  state.destroyed = true
  releaseTailControlSessionState(state)
  return true
}

function rejectTailControlFinalExitHandoffConsume(owner) {
  const handoff = object(owner) ? FINAL_EXIT_HANDOFF_OWNERS.get(owner) : null
  const record = handoff ? FINAL_EXIT_HANDOFFS.get(handoff) : null
  return !!(record && record.claiming && !FINAL_EXIT_PREPARE_CONSUMES.has(handoff))
}

function destroyTailControlFinalExitHandoffOwner(owner) {
  const handoff = object(owner) ? FINAL_EXIT_HANDOFF_OWNERS.get(owner) : null
  const record = handoff ? FINAL_EXIT_HANDOFFS.get(handoff) : null
  if (!record) return false
  if (FINAL_EXIT_PREPARE_CONSUMES.has(handoff)) return false
  FINAL_EXIT_HANDOFF_OWNERS.delete(owner)
  FINAL_EXIT_HANDOFFS.delete(handoff)
  record.state.finalExitStage = 'FINAL_EXIT_REVOKED'
  releaseFinalExitTailControlState(owner, record.state)
  return true
}

function takeTailControlRouteTransport(tailControlOwner, activationOwner) {
  if (!object(tailControlOwner) || !object(activationOwner)) authentication()
  const record = FINAL_EXIT_ACTIVATIONS.get(activationOwner)
  if (
    !record ||
    record.owner !== tailControlOwner ||
    record.state.finalExitActivationOwner !== activationOwner ||
    record.state.finalExitStage !== 'FINAL_EXIT_ACTIVATION'
  ) {
    authentication()
  }
  if (record.state.transportOwner === null) replay()
  const { takeM3RouteTransport } = require('./m3-adjacency-runtime')
  const transport = takeM3RouteTransport(record.state.transportOwner)
  record.state.transportOwner = null
  record.state.transport = null
  return transport
}

function destroyTailControlFinalExitActivation(tailControlOwner, activationOwner) {
  if (!object(tailControlOwner) || !object(activationOwner)) return false
  const record = FINAL_EXIT_ACTIVATIONS.get(activationOwner)
  if (
    !record ||
    record.owner !== tailControlOwner ||
    record.state.finalExitActivationOwner !== activationOwner
  ) {
    return false
  }
  FINAL_EXIT_ACTIVATIONS.delete(activationOwner)
  record.state.finalExitActivationOwner = null
  record.state.finalExitStage = 'FINAL_EXIT_DESTROYED'
  releaseFinalExitTailControlState(record.owner, record.state)
  return true
}

function completeClientExtension(session, state, completion, encoded) {
  if (SESSIONS.get(session) !== state || state.destroyed || !state.initiator) invalid()
  const record = state.clientExtension
  const completionState = object(completion) ? CLIENT_EXTENSION_COMPLETIONS.get(completion) : null
  if (!completionState || completionState.destroyed || completionState.session !== session) {
    if (object(completion) && SPENT_CLIENT_EXTENSION_COMPLETIONS.has(completion)) replay()
    authentication()
  }
  if (
    !record ||
    completionState.record !== record ||
    state.clientCompletion !== completionState ||
    completionState.committing
  )
    invalid()
  completionState.committing = true
  let complete = false
  let ready = null
  let finalExitMaterial = null
  let successorMaterial = null
  try {
    ready = decodeTailReady(encoded)
    if (
      !fieldsMatchReady(
        record,
        completionState.extended,
        completionState.proof,
        completionState.transcriptDigest,
        ready
      )
    ) {
      authentication()
    }
    verifyTailReadySignature(ready)
    const wallNow = BigInt(state.wallNow())
    if (!uint64(wallNow) || wallNow >= completionState.proof.expiresAtMs) authentication()
    clampTailControlProofDeadline(session, state, completionState.proof.expiresAtMs)
    if (completionState.proof.extensionIndex === 1) {
      successorMaterial = createTailControlSuccessorMaterial(state, record, completionState)
    } else if (completionState.proof.extensionIndex === 2) {
      if (state.finalExitMaterial !== null) replay()
      finalExitMaterial = createFinalExitMaterial(session, state, record, completionState)
    } else {
      invalid()
    }
    clearClientExtensionCompletionRecord(completionState)
    state.clientExtension = null
    clearClientExtension(record)
    if (successorMaterial !== null) {
      clear(state.secret)
      clear(state.transcript)
      state.secret = successorMaterial.sharedSecret
      state.transcript = successorMaterial.transcript
      successorMaterial.sharedSecret = null
      successorMaterial.transcript = null
      successorMaterial = null
    }
    if (finalExitMaterial !== null) {
      state.finalExitMaterial = finalExitMaterial
      state.finalExitStage = 'FINAL_EXIT_READY'
      finalExitMaterial = null
    }
    complete = true
    return session
  } finally {
    clearTailReady(ready)
    clearFinalExitMaterial(finalExitMaterial)
    clearTailControlSuccessorMaterial(successorMaterial)
    if (!complete && !completionState.destroyed) completionState.committing = false
  }
}

function abortClientExtension(session, state, completion) {
  if (SESSIONS.get(session) !== state || state.destroyed || !state.initiator) invalid()
  const completionState = object(completion) ? CLIENT_EXTENSION_COMPLETIONS.get(completion) : null
  if (!completionState || completionState.destroyed || completionState.session !== session)
    return false
  const record = completionState.record
  clearClientExtensionCompletionRecord(completionState)
  if (state.clientExtension === record) {
    state.clientExtension = null
    clearClientExtension(record)
  }
  return true
}

function tailControlTimerDelay(remaining) {
  return remaining > BigInt(MAX_TIMER_DELAY) ? MAX_TIMER_DELAY : Number(remaining)
}

function runTailControlSessionTimer(session, generation) {
  const state = object(session)
    ? SESSIONS.get(session) || FINAL_EXIT_TIMER_STATES.get(session)
    : null
  if (!state || state.destroyed || state.timerGeneration !== generation) return
  let current
  try {
    current = BigInt(state.monotonicNow())
  } catch {
    if (FINAL_EXIT_TIMER_STATES.has(session)) releaseFinalExitTailControlState(session, state)
    else destroyTailControlSession(session)
    return
  }
  if (current < state.deadline.localDeadline) {
    try {
      armTailControlSession(session, state)
    } catch {
      if (FINAL_EXIT_TIMER_STATES.has(session)) releaseFinalExitTailControlState(session, state)
      else destroyTailControlSession(session)
    }
    return
  }
  if (FINAL_EXIT_TIMER_STATES.has(session)) releaseFinalExitTailControlState(session, state)
  else destroyTailControlSession(session)
}

function tailControlSessionStateLive(session, state) {
  return SESSIONS.get(session) === state || FINAL_EXIT_TIMER_STATES.get(session) === state
}

function releaseUnpublishedTailControlState(session, state) {
  if (FINAL_EXIT_TIMER_STATES.get(session) === state)
    releaseFinalExitTailControlState(session, state)
  else releaseTailControlSessionState(state)
}

function armTailControlSession(session, state, sampledCurrent) {
  const current = sampledCurrent === undefined ? BigInt(state.monotonicNow()) : sampledCurrent
  if (!uint64(current) || current >= state.deadline.localDeadline) invalid()
  const delay = tailControlTimerDelay(state.deadline.localDeadline - current)
  const generation = ++state.timerGeneration
  let arming = true
  let fired = false
  let handle = null
  const onExpiry = () => {
    if (arming) {
      fired = true
      return
    }
    if (state.timerGeneration !== generation) return
    state.handle = null
    runTailControlSessionTimer(session, generation)
  }
  state.arming = true
  try {
    handle = state.schedule(onExpiry, delay)
  } catch (err) {
    if (state.destroyed || !tailControlSessionStateLive(session, state)) {
      releaseUnpublishedTailControlState(session, state)
    }
    throw err
  } finally {
    arming = false
    state.arming = false
  }
  if (
    handle === null ||
    handle === undefined ||
    fired ||
    state.destroyed ||
    !tailControlSessionStateLive(session, state)
  ) {
    state.timerGeneration++
    if (handle !== null && handle !== undefined) {
      try {
        state.cancelScheduled(handle)
      } catch {}
    }
    if (state.destroyed || !tailControlSessionStateLive(session, state)) {
      releaseUnpublishedTailControlState(session, state)
    }
    invalid()
  }
  state.handle = handle
}

function createTailControlSession(capability, options) {
  if (!object(options)) invalid()
  let keys
  try {
    keys = Reflect.ownKeys(options)
  } catch {
    invalid()
  }
  for (const key of keys) {
    if (
      key !== 'wallNow' &&
      key !== 'monotonicNow' &&
      key !== 'schedule' &&
      key !== 'cancelScheduled' &&
      key !== 'absoluteDeadline' &&
      key !== 'crypto'
    ) {
      invalid()
    }
  }
  if (
    !keys.includes('wallNow') ||
    !keys.includes('monotonicNow') ||
    !keys.includes('schedule') ||
    !keys.includes('cancelScheduled')
  ) {
    invalid()
  }
  const wallDescriptor = Object.getOwnPropertyDescriptor(options, 'wallNow')
  const monotonicDescriptor = Object.getOwnPropertyDescriptor(options, 'monotonicNow')
  const scheduleDescriptor = Object.getOwnPropertyDescriptor(options, 'schedule')
  const cancelDescriptor = Object.getOwnPropertyDescriptor(options, 'cancelScheduled')
  const deadlineDescriptor = Object.getOwnPropertyDescriptor(options, 'absoluteDeadline')
  const cryptoDescriptor = Object.getOwnPropertyDescriptor(options, 'crypto')
  if (
    !wallDescriptor ||
    !monotonicDescriptor ||
    !cancelDescriptor ||
    !Object.prototype.hasOwnProperty.call(wallDescriptor, 'value') ||
    !Object.prototype.hasOwnProperty.call(monotonicDescriptor, 'value') ||
    !Object.prototype.hasOwnProperty.call(scheduleDescriptor, 'value') ||
    !Object.prototype.hasOwnProperty.call(cancelDescriptor, 'value') ||
    (deadlineDescriptor && !Object.prototype.hasOwnProperty.call(deadlineDescriptor, 'value')) ||
    (cryptoDescriptor && !Object.prototype.hasOwnProperty.call(cryptoDescriptor, 'value')) ||
    typeof wallDescriptor.value !== 'function' ||
    typeof monotonicDescriptor.value !== 'function' ||
    typeof scheduleDescriptor.value !== 'function' ||
    typeof cancelDescriptor.value !== 'function'
  ) {
    invalid()
  }
  const selectedCrypto = cryptoDescriptor ? cryptoDescriptor.value : cryptoSuite
  if (
    !object(selectedCrypto) ||
    typeof selectedCrypto.encryptionKeyPair !== 'function' ||
    typeof selectedCrypto.keyAgreement !== 'function'
  ) {
    invalid()
  }
  const { shortenM3TailLifetime, takeM3TailCapability } = require('./m3-adjacency-runtime')
  const tailState = takeM3TailCapability(capability, {
    wallNow: wallDescriptor.value,
    monotonicNow: monotonicDescriptor.value
  })
  let deadline = tailState.deadline
  if (tailState.initiator) {
    if (
      !deadlineDescriptor ||
      !uint64(deadlineDescriptor.value) ||
      deadlineDescriptor.value === 0n
    ) {
      invalid()
    }
    if (deadlineDescriptor.value < deadline.localDeadline) {
      deadline = shortenM3TailLifetime(tailState, deadlineDescriptor.value)
    }
  }
  let session = null
  const state = {
    arming: false,
    cancelScheduled: cancelDescriptor.value,
    clientExtension: null,
    clientCompletion: null,
    crypto: selectedCrypto,
    deadline,
    extensionRequest: null,
    destroyed: false,
    handle: null,
    initiator: tailState.initiator,
    extensionIndex: tailState.extensionIndex,
    binding: tailState.binding,
    finalExitMaterial: null,
    finalExitActivationOwner: null,
    finalExitGeneration: 0,
    finalExitStage: null,
    monotonicNow: monotonicDescriptor.value,
    responderOpening: null,
    responderInstalled: null,
    responderAuthority: null,
    schedule: scheduleDescriptor.value,
    secret: tailState.secret,
    timerGeneration: 0,
    transcript: tailState.transcript,
    transport: null,
    transportOwner: tailState.transportOwner,
    wallNow: wallDescriptor.value
  }
  try {
    session = Object.freeze({
      sealExtend(options) {
        return sealTailExtend(session, state, options)
      },
      openExtended(encoded) {
        return openClientExtended(session, state, encoded)
      },
      completeClientExtension(completion, encoded) {
        return completeClientExtension(session, state, completion, encoded)
      },
      abortClientExtension(completion) {
        return abortClientExtension(session, state, completion)
      },
      takeFinalExitHandoff() {
        return takeFinalExitHandoff(session, state)
      }
    })
    SESSIONS.set(session, state)
    armTailControlSession(session, state)
  } catch (err) {
    if (session) SESSIONS.delete(session)
    state.destroyed = true
    releaseTailControlSessionState(state)
    tailState.secret = null
    tailState.transcript = null
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
  tailState.secret = null
  tailState.transcript = null
  return session
}

function isTailControlSession(value) {
  return object(value) && SESSIONS.has(value)
}

function clearResponderAuthorityState(record) {
  if (!record || record.destroyed) return false
  RESPONDER_AUTHORITIES.delete(record.authority)
  DESTROYED_RESPONDER_AUTHORITIES.add(record.authority)
  record.destroyed = true
  if (record.handle !== null && record.cancelScheduled !== null) {
    try {
      record.cancelScheduled(record.handle)
    } catch {}
  }
  if (record.sessionState && record.sessionState.extensionRequest) {
    clearAdmittedExtendRequest(record.sessionState.extensionRequest)
    record.sessionState.extensionRequest = null
  }
  if (record.sessionState && record.sessionState.responderAuthority === record) {
    record.sessionState.responderAuthority = null
  }
  if (record.responderToken) {
    try {
      const { revokeTailResponderToken } = require('./m3-adjacency-runtime')
      revokeTailResponderToken(record.responderToken)
    } catch {}
  }
  if (record.sessionState && record.sessionState.responderOpening) {
    abortTailOpening(record.sessionState)
  }
  if (record.sessionState && record.sessionState.responderInstalled) {
    clearTailInstalled(record.sessionState.responderInstalled)
    record.sessionState.responderInstalled = null
  }
  if (record.extensionCommitter) {
    try {
      const { destroyTailExtensionCommitter } = require('./tail-extension-committer')
      destroyTailExtensionCommitter(record.extensionCommitter)
    } catch {}
  }
  if (record.adjacentLinkFactory) {
    try {
      const { destroyExtensionAdjacentLinkFactory } = require('./guard-link')
      destroyExtensionAdjacentLinkFactory(record.adjacentLinkFactory)
    } catch {}
  }
  if (record.tailReadySigner) {
    try {
      const { destroyTailReadySigner } = require('./relay-identity-signer')
      destroyTailReadySigner(record.tailReadySigner)
    } catch {}
  }
  record.authority = null
  record.session = null
  record.sessionState = null
  record.binding = null
  record.responderToken = null
  record.adjacencyAdopter = null
  record.extensionCommitter = null
  record.adjacentLinkFactory = null
  record.tailReadySigner = null
  record.wallNow = null
  record.monotonicNow = null
  record.randomBytes = null
  record.schedule = null
  record.cancelScheduled = null
  record.handle = null
  return true
}

function armResponderAuthority(record) {
  const current = BigInt(record.monotonicNow())
  if (current >= record.sessionState.deadline.localDeadline) invalid()
  const delay = tailControlTimerDelay(record.sessionState.deadline.localDeadline - current)
  let arming = true
  let fired = false
  let handle = null
  const onExpiry = () => {
    if (arming) {
      fired = true
      return
    }
    const ownedSession = record.session
    clearResponderAuthorityState(record)
    if (ownedSession) destroyTailControlSession(ownedSession)
  }
  try {
    handle = record.schedule(onExpiry, delay)
  } catch (err) {
    const ownedSession = record.session
    clearResponderAuthorityState(record)
    if (ownedSession) destroyTailControlSession(ownedSession)
    throw err
  } finally {
    arming = false
  }
  if (
    handle === null ||
    handle === undefined ||
    fired ||
    record.destroyed ||
    record.sessionState.destroyed ||
    !SESSIONS.has(record.session)
  ) {
    if (handle !== null && handle !== undefined) {
      try {
        record.cancelScheduled(handle)
      } catch {}
    }
    const ownedSession = record.session
    clearResponderAuthorityState(record)
    if (ownedSession) destroyTailControlSession(ownedSession)
    invalid()
  }
  record.handle = handle
}

function createTailControlResponderAuthority(session, responderToken, options) {
  const sessionState = object(session) ? SESSIONS.get(session) : null
  if (!sessionState || sessionState.destroyed || sessionState.initiator) invalid()
  const terminalResponder = sessionState.extensionIndex === 2
  if (terminalResponder) {
    exactObject(options, [
      'tailReadySigner',
      'wallNow',
      'monotonicNow',
      'randomBytes',
      'schedule',
      'cancelScheduled'
    ])
  } else {
    exactObject(options, [
      'adjacencyAdopter',
      'extensionCommitter',
      'adjacentLinkFactory',
      'tailReadySigner',
      'wallNow',
      'monotonicNow',
      'randomBytes',
      'schedule',
      'cancelScheduled'
    ])
  }
  const adjacencyAdopter = terminalResponder
    ? null
    : exactValueDescriptor(options, 'adjacencyAdopter')
  const extensionCommitter = terminalResponder
    ? null
    : exactValueDescriptor(options, 'extensionCommitter')
  const adjacentLinkFactory = terminalResponder
    ? null
    : exactValueDescriptor(options, 'adjacentLinkFactory')
  const tailReadySigner = exactValueDescriptor(options, 'tailReadySigner')
  const wallNow = exactValueDescriptor(options, 'wallNow')
  const monotonicNow = exactValueDescriptor(options, 'monotonicNow')
  const randomBytes = exactValueDescriptor(options, 'randomBytes')
  const schedule = exactValueDescriptor(options, 'schedule')
  const cancelScheduled = exactValueDescriptor(options, 'cancelScheduled')
  if (
    wallNow !== sessionState.wallNow ||
    monotonicNow !== sessionState.monotonicNow ||
    typeof randomBytes !== 'function' ||
    typeof schedule !== 'function' ||
    typeof cancelScheduled !== 'function'
  ) {
    invalid()
  }
  if (sessionState.responderAuthority !== null) busy()
  const { consumeTailResponderToken } = require('./m3-adjacency-runtime')
  const binding = consumeTailResponderToken(responderToken)
  if (binding !== sessionState.binding) {
    try {
      const { revokeTailResponderToken } = require('./m3-adjacency-runtime')
      revokeTailResponderToken(responderToken)
    } catch {}
    invalid()
  }
  const authority = Object.freeze({})
  const record = {
    authority,
    session,
    sessionState,
    binding,
    responderToken,
    adjacencyAdopter,
    extensionCommitter,
    adjacentLinkFactory,
    tailReadySigner,
    wallNow,
    monotonicNow,
    randomBytes,
    schedule,
    cancelScheduled,
    handle: null,
    destroyed: false
  }
  try {
    RESPONDER_AUTHORITIES.set(authority, record)
    sessionState.responderAuthority = record
    armResponderAuthority(record)
    return authority
  } catch (err) {
    clearResponderAuthorityState(record)
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function destroyTailControlResponderAuthority(authority) {
  const record = object(authority) ? RESPONDER_AUTHORITIES.get(authority) : null
  if (!record || record.destroyed || DESTROYED_RESPONDER_AUTHORITIES.has(authority)) return false
  return clearResponderAuthorityState(record)
}

function admitTailExtend(authority, envelope) {
  const record = object(authority) ? RESPONDER_AUTHORITIES.get(authority) : null
  if (
    !record ||
    record.destroyed ||
    DESTROYED_RESPONDER_AUTHORITIES.has(authority) ||
    !record.sessionState ||
    record.sessionState.destroyed ||
    record.sessionState.initiator ||
    SESSIONS.get(record.session) !== record.sessionState
  ) {
    invalid()
  }
  const state = record.sessionState
  const { takeM3ReceivedEnvelope, releaseM3ReceivedEnvelope } = require('./m3-adjacency-runtime')
  if (
    state.extensionRequest !== null ||
    state.responderOpening !== null ||
    state.responderInstalled !== null
  ) {
    let busyReceived = null
    try {
      busyReceived = takeM3ReceivedEnvelope(state.transportOwner, envelope)
    } catch {}
    if (busyReceived !== null) releaseM3ReceivedEnvelope(state.transportOwner, busyReceived)
    busy()
  }
  let received = null
  let encoded = null
  let request = null
  let transcript = null
  let decodedAdvertisement = null
  let payloadParametersDigest = null
  let reservation = null
  let complete = false
  try {
    reservation = reserveAdmittedExtendRequest(state, record.session)
    received = takeM3ReceivedEnvelope(state.transportOwner, envelope)
    encoded = decodeReceivedTailControlObject(received)
    request = decodeExtendRequest(encoded)
    transcript = decodeTailControlTranscript(state.transcript)
    const wall = BigInt(record.wallNow())
    const current = BigInt(record.monotonicNow())
    if (!uint64(wall) || current >= state.deadline.localDeadline) {
      throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    }
    decodedAdvertisement = decodeRelayCapabilityAdvertisement(request.advertisement, {
      now: wall
    })
    payloadParametersDigest = digestPayloadParameters(decodedAdvertisement)
    const expectedIdentityRole = request.extensionIndex === 1 ? ROLE.SAFETY : ROLE.PRIVATE
    if (
      request.branchClass !== transcript.branchClass ||
      request.generation !== transcript.generation ||
      request.extensionIndex !== transcript.extensionIndex + 1 ||
      !b4a.equals(request.branchId, transcript.branchId) ||
      !b4a.equals(request.circuitId, transcript.circuitId) ||
      roleForIdentity(transcript.tailIdentity) !== ROLE.SAFETY ||
      roleForIdentity(decodedAdvertisement.relayIdentity) !== expectedIdentityRole ||
      b4a.equals(decodedAdvertisement.relayIdentity, transcript.tailIdentity) ||
      !b4a.equals(payloadParametersDigest, request.payloadParametersDigest)
    ) {
      authentication()
    }
    authenticateRequestedLimitsDigest(request.requestedLimits, transcript.admittedLimitsDigest)
    enforceRequestedLimitsWithinAdvertisement(request.requestedLimits, decodedAdvertisement)
    const requestedWireExpiresAt = request.requestedLimits.expiresAtMs
    if (!uint64(requestedWireExpiresAt) || requestedWireExpiresAt <= wall) {
      throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    }
    let effectiveLocalDeadline = current + (requestedWireExpiresAt - wall)
    if (
      effectiveLocalDeadline <= current ||
      requestedWireExpiresAt > state.deadline.wireExpiresAt ||
      requestedWireExpiresAt > decodedAdvertisement.expiresAtMs
    ) {
      throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    }
    if (effectiveLocalDeadline > state.deadline.localDeadline) {
      effectiveLocalDeadline = state.deadline.localDeadline
    }
    if (!uint64(effectiveLocalDeadline)) {
      throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    }
    try {
      rearmShortenedTailControlSession(record.session, state, effectiveLocalDeadline)
    } catch (err) {
      const ownedSession = record.session
      if (ownedSession) destroyTailControlSession(ownedSession)
      throw err
    }
    const admitted = publishAdmittedExtendRequest(
      state,
      reservation,
      request,
      null,
      effectiveLocalDeadline,
      requestedWireExpiresAt,
      transcript
    )
    complete = true
    return admitted
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    if (received !== null) releaseM3ReceivedEnvelope(state.transportOwner, received)
    clear(encoded)
    clearDecodedTailControlTranscript(transcript)
    clearRelayCapabilityAdvertisement(decodedAdvertisement)
    clear(payloadParametersDigest)
    if (!complete) clearExtendRequest(request)
    if (!complete && reservation !== null) {
      if (state.extensionRequest === reservation) state.extensionRequest = null
      clearAdmittedExtendRequest(reservation)
    }
  }
}

function takeAdmittedExtendRequest(capability) {
  const record = object(capability) ? ADMITTED_EXTEND_REQUESTS.get(capability) : null
  if (!record || record.status !== 'LIVE') invalid()
  const request = record.request
  const currentTailIdentity = record.currentTailIdentity
  const currentTailAdvertisementDigest = record.currentTailAdvertisementDigest
  const localDeadline = record.localDeadline
  const wireExpiresAt = record.wireExpiresAt
  ADMITTED_EXTEND_REQUESTS.delete(capability)
  record.capability = null
  record.request = null
  record.currentTailIdentity = null
  record.currentTailAdvertisementDigest = null
  record.session = null
  record.status = 'TAKEN'
  record.localDeadline = 0n
  record.wireExpiresAt = 0n
  record.key = null
  clear(record.extensionNonce)
  record.extensionNonce = null
  return Object.freeze({
    request,
    currentTailIdentity,
    currentTailAdvertisementDigest,
    localDeadline,
    wireExpiresAt
  })
}

function readAdmittedTailSelection(authority, admittedRequest) {
  const owner = object(authority) ? RESPONDER_AUTHORITIES.get(authority) : null
  const admitted = object(admittedRequest) ? ADMITTED_EXTEND_REQUESTS.get(admittedRequest) : null
  if (
    !owner ||
    owner.destroyed ||
    !admitted ||
    admitted.session !== owner.session ||
    admitted.status !== 'LIVE'
  ) {
    invalid()
  }
  let decoded = null
  try {
    decoded = decodeRelayCapabilityAdvertisement(admitted.request.advertisement)
    return Object.freeze({
      advertisement: copy(admitted.request.advertisement),
      advertisementDigest: digestRelayCapabilityAdvertisement(admitted.request.advertisement),
      extensionIndex: admitted.request.extensionIndex,
      reachableEndpoint: copy(decoded.reachableEndpoint),
      relayIdentity: copy(decoded.relayIdentity, 32),
      routeEncryptionPublicKey: copy(decoded.routeEncryptionPublicKey, 32)
    })
  } finally {
    clearRelayCapabilityAdvertisement(decoded)
  }
}

function createSuccessorTailReadyContext(authority, admittedRequest) {
  const owner = object(authority) ? RESPONDER_AUTHORITIES.get(authority) : null
  const admitted = object(admittedRequest) ? ADMITTED_EXTEND_REQUESTS.get(admittedRequest) : null
  if (
    !owner ||
    owner.destroyed ||
    !admitted ||
    admitted.session !== owner.session ||
    admitted.status !== 'LIVE' ||
    admitted.successorTailReadyContext
  ) {
    invalid()
  }
  const decoded = decodeRelayCapabilityAdvertisement(admitted.request.advertisement)
  const capability = Object.freeze({})
  const record = {
    capability,
    branchClass: admitted.request.branchClass,
    branchId: copy(admitted.request.branchId, 16),
    circuitId: copy(admitted.request.circuitId, 16),
    generation: admitted.request.generation,
    extensionIndex: admitted.request.extensionIndex,
    predecessorTranscriptDigest: digestTailReadyTranscript(owner.sessionState.transcript),
    tailIdentity: copy(decoded.relayIdentity, 32),
    tailAdvertisementDigest: digestRelayCapabilityAdvertisement(admitted.request.advertisement),
    clientNonce: copy(admitted.request.clientNonce, 32),
    expiresAtMs: 0n,
    exported: false,
    finalized: false
  }
  clearRelayCapabilityAdvertisement(decoded)
  admitted.successorTailReadyContext = capability
  SUCCESSOR_TAIL_READY_CONTEXTS.set(capability, record)
  return capability
}
function encodeSuccessorTailReadyContext(capability) {
  const context = object(capability) ? SUCCESSOR_TAIL_READY_CONTEXTS.get(capability) : null
  if (!context || context.exported) {
    if (object(capability) && SPENT_SUCCESSOR_TAIL_READY_CONTEXTS.has(capability)) replay()
    invalid()
  }
  context.exported = true
  const readyNonce = b4a.alloc(32)
  try {
    return encodeTailReadyBody({
      ...context,
      tailControlTranscriptDigest: context.predecessorTranscriptDigest,
      readyNonce,
      expiresAtMs: 0n
    })
  } finally {
    clear(readyNonce)
  }
}

function importSuccessorTailReadyContext(authority, encoded) {
  const owner = object(authority) ? RESPONDER_AUTHORITIES.get(authority) : null
  if (
    !owner ||
    owner.destroyed ||
    IMPORTED_SUCCESSOR_READY_AUTHORITIES.has(authority) ||
    !fixed(encoded, TAIL_READY_BODY_SIZE)
  ) {
    if (object(authority) && IMPORTED_SUCCESSOR_READY_AUTHORITIES.has(authority)) replay()
    invalid()
  }
  let decoded = null
  let transcript = null
  try {
    decoded = decodeTailReadyBody(encoded)
    transcript = decodeTailControlTranscript(owner.sessionState.transcript)
    if (
      decoded.expiresAtMs !== 0n ||
      decoded.readyNonce.some((value) => value !== 0) ||
      transcript.branchClass !== decoded.branchClass ||
      transcript.generation !== decoded.generation ||
      transcript.extensionIndex !== decoded.extensionIndex ||
      !b4a.equals(transcript.branchId, decoded.branchId) ||
      !b4a.equals(transcript.circuitId, decoded.circuitId) ||
      !b4a.equals(transcript.tailIdentity, decoded.tailIdentity) ||
      !b4a.equals(transcript.candidateAdvertisementDigest, decoded.tailAdvertisementDigest) ||
      !b4a.equals(transcript.clientNonce, decoded.clientNonce)
    ) {
      authentication()
    }
    const capability = Object.freeze({})
    SUCCESSOR_TAIL_READY_CONTEXTS.set(capability, {
      capability,
      branchClass: decoded.branchClass,
      branchId: copy(decoded.branchId, 16),
      circuitId: copy(decoded.circuitId, 16),
      generation: decoded.generation,
      extensionIndex: decoded.extensionIndex,
      predecessorTranscriptDigest: copy(decoded.tailControlTranscriptDigest, 32),
      tailIdentity: copy(decoded.tailIdentity, 32),
      tailAdvertisementDigest: copy(decoded.tailAdvertisementDigest, 32),
      clientNonce: copy(decoded.clientNonce, 32),
      expiresAtMs: owner.sessionState.deadline.wireExpiresAt,
      exported: true,
      finalized: true
    })
    IMPORTED_SUCCESSOR_READY_AUTHORITIES.add(authority)
    return capability
  } finally {
    clearTailReady(decoded)
    clearDecodedTailControlTranscript(transcript)
  }
}

function sealSuccessorTailReady(authority, capability) {
  const owner = object(authority) ? RESPONDER_AUTHORITIES.get(authority) : null
  const context = object(capability) ? SUCCESSOR_TAIL_READY_CONTEXTS.get(capability) : null
  if (!owner || owner.destroyed || !context || !context.finalized) {
    if (object(capability) && SPENT_SUCCESSOR_TAIL_READY_CONTEXTS.has(capability)) replay()
    invalid()
  }
  const transcript = decodeTailControlTranscript(owner.sessionState.transcript)
  let readyNonce = null
  let body = null
  let signature = null
  try {
    if (
      transcript.branchClass !== context.branchClass ||
      transcript.generation !== context.generation ||
      transcript.extensionIndex !== context.extensionIndex ||
      !b4a.equals(transcript.branchId, context.branchId) ||
      !b4a.equals(transcript.circuitId, context.circuitId) ||
      !b4a.equals(transcript.tailIdentity, context.tailIdentity) ||
      !b4a.equals(transcript.candidateAdvertisementDigest, context.tailAdvertisementDigest) ||
      !b4a.equals(transcript.clientNonce, context.clientNonce)
    ) {
      authentication()
    }
    readyNonce = randomBuffer(owner.randomBytes)
    body = encodeTailReadyBody({
      ...context,
      tailControlTranscriptDigest: context.predecessorTranscriptDigest,
      readyNonce
    })
    const { signTailReady } = require('./relay-identity-signer')
    signature = signTailReady(owner.tailReadySigner, body, context.tailIdentity)
    if (!fixed(signature, 64)) authentication()
    return encodeM3Object({
      messageId: M3_MESSAGE_ID.TAIL_READY_V1,
      body,
      authSuffix: signature
    })
  } finally {
    SUCCESSOR_TAIL_READY_CONTEXTS.delete(capability)
    SPENT_SUCCESSOR_TAIL_READY_CONTEXTS.add(capability)
    clearDecodedTailControlTranscript(transcript)
    clear(readyNonce)
    clear(body)
    clear(signature)
    for (const field of [
      'branchId',
      'circuitId',
      'predecessorTranscriptDigest',
      'tailIdentity',
      'tailAdvertisementDigest',
      'clientNonce'
    ]) {
      clear(context[field])
      context[field] = null
    }
  }
}

function validateTailExtensionCompletion(opening, material) {
  const proof = material && typeof material === 'object' ? material.expectedProof : null
  if (
    !proof ||
    typeof proof !== 'object' ||
    Array.isArray(proof) ||
    !fixed(material.redactedProof, REDACTED_RESPONDER_PROOF_SIZE) ||
    !fixed(material.extensionNonce, 32) ||
    proof.branchClass !== opening.request.branchClass ||
    proof.generation !== opening.request.generation ||
    proof.extensionIndex !== opening.request.extensionIndex ||
    !uint64(proof.expiresAtMs) ||
    proof.expiresAtMs === 0n ||
    proof.expiresAtMs > opening.request.requestedLimits.expiresAtMs ||
    proof.expiresAtMs > opening.wireExpiresAt ||
    !b4a.equals(proof.branchId, opening.request.branchId) ||
    !b4a.equals(proof.circuitId, opening.request.circuitId) ||
    !b4a.equals(proof.clientNonce, opening.request.clientNonce) ||
    !b4a.equals(proof.clientTailEphemeralPublicKey, opening.request.clientTailEphemeralPublicKey) ||
    !b4a.equals(proof.responderAdvertisementDigest, opening.responderAdvertisementDigest) ||
    !b4a.equals(proof.responderIdentity, opening.responderIdentity) ||
    !b4a.equals(proof.initiatorIdentity, opening.currentTailIdentity) ||
    !b4a.equals(
      proof.advertisedRouteEncryptionPublicKey,
      opening.responderRouteEncryptionPublicKey
    ) ||
    !b4a.equals(material.extensionNonce, opening.request.extensionNonce)
  ) {
    authentication()
  }
  authenticateRequestedLimitsDigest(opening.request.requestedLimits, proof.admittedLimitsDigest)
}

function openTailAdjacentLink(authority, admittedRequest) {
  const record = object(authority) ? RESPONDER_AUTHORITIES.get(authority) : null
  if (!record || record.destroyed || !record.sessionState || record.sessionState.destroyed) {
    invalid()
  }
  const state = record.sessionState
  const admitted = object(admittedRequest) ? ADMITTED_EXTEND_REQUESTS.get(admittedRequest) : null
  if (
    !admitted ||
    admitted.session !== record.session ||
    admitted.status !== 'LIVE' ||
    state.extensionRequest !== admitted ||
    state.responderOpening !== null ||
    state.responderInstalled !== null
  ) {
    invalid()
  }
  const decodedAdvertisement = decodeRelayCapabilityAdvertisement(admitted.request.advertisement)
  let opening = null
  let complete = false
  try {
    opening = {
      request: copyExtendRequestMaterial(admitted.request),
      currentTailIdentity: copy(admitted.currentTailIdentity, 32),
      responderIdentity: copy(decodedAdvertisement.relayIdentity, 32),
      currentTailAdvertisementDigest: copy(admitted.currentTailAdvertisementDigest, 32),
      responderAdvertisementDigest: digestRelayCapabilityAdvertisement(
        admitted.request.advertisement
      ),
      responderRouteEncryptionPublicKey: copy(decodedAdvertisement.routeEncryptionPublicKey, 32),
      localDeadline: admitted.localDeadline,
      wireExpiresAt: admitted.wireExpiresAt,
      promise: null,
      completion: null,
      adjacentLinkFactory: record.adjacentLinkFactory,
      successorTailReadyContext: admitted.successorTailReadyContext
    }
    state.responderOpening = opening
    const { openExtensionAdjacentLink } = require('./guard-link')
    const promise = openExtensionAdjacentLink(record.adjacentLinkFactory, admittedRequest)
    if (admitted.status === 'TAKEN' && state.extensionRequest === admitted) {
      state.extensionRequest = null
    }
    if (!promise || typeof promise.then !== 'function') invalid()
    opening.promise = promise.then(
      (completion) => {
        if (state.responderOpening !== opening || state.destroyed) {
          try {
            const { destroyExtensionLinkCompletion } = require('./extension-link-completion')
            destroyExtensionLinkCompletion(completion)
          } catch {}
          destroyed()
        }
        opening.completion = completion
        return completion
      },
      (err) => {
        if (state.responderOpening === opening) {
          state.responderOpening = null
          clearTailOpening(opening)
        }
        throw err
      }
    )
    complete = true
    return opening.promise
  } catch (err) {
    if (state.responderOpening === opening) state.responderOpening = null
    if (state.extensionRequest === admitted) {
      state.extensionRequest = null
      clearAdmittedExtendRequest(admitted)
    }
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    clearRelayCapabilityAdvertisement(decodedAdvertisement)
    if (!complete) clearTailOpening(opening)
  }
}

function completeTailExtend(authority, completion) {
  const record = object(authority) ? RESPONDER_AUTHORITIES.get(authority) : null
  if (!record || record.destroyed || !record.sessionState || record.sessionState.destroyed)
    invalid()
  const state = record.sessionState
  const opening = state.responderOpening
  if (!opening || opening.completion !== completion || state.responderInstalled !== null) invalid()
  const now = BigInt(record.wallNow())
  if (!uint64(now) || now >= opening.wireExpiresAt) authentication()
  const {
    takeExtensionLinkCompletion,
    destroyTakenExtensionLinkCompletion
  } = require('./extension-link-completion')
  const material = takeExtensionLinkCompletion(completion)
  let extended = null
  let envelope = null
  let adoption = null
  let runtime = null
  let runtimeExtracted = false
  let forwarding = null
  let adjacencyAdopter = null
  let extensionCommitter = null
  let committerPublished = false
  let installed = null
  let successorReady = null
  let complete = false
  successorReady = opening.successorTailReadyContext
  try {
    validateTailExtensionCompletion(opening, material)
    if (now >= material.expectedProof.expiresAtMs) authentication()
    const successorContext =
      successorReady !== null && typeof successorReady === 'object'
        ? SUCCESSOR_TAIL_READY_CONTEXTS.get(successorReady)
        : null
    if (successorContext) {
      successorContext.expiresAtMs = material.expectedProof.expiresAtMs
      successorContext.finalized = true
    }
    clampTailControlProofDeadline(record.session, state, material.expectedProof.expiresAtMs)
    extended = encodeExtended({
      branchClass: material.expectedProof.branchClass,
      branchId: material.expectedProof.branchId,
      circuitId: material.expectedProof.circuitId,
      generation: material.expectedProof.generation,
      extensionIndex: material.expectedProof.extensionIndex,
      responderAdvertisementDigest: material.expectedProof.responderAdvertisementDigest,
      redactedProof: material.redactedProof,
      extensionNonce: material.extensionNonce
    })
    envelope = encodeTailControlOrderedEnvelope(extended)
    const {
      adoptM3ResponderLink,
      takeM3ResponderLink,
      destroyTakenM3ResponderLink
    } = require('./m3-adjacency-adopter')
    adjacencyAdopter = record.adjacencyAdopter
    extensionCommitter = record.extensionCommitter
    record.extensionCommitter = null
    adoption = adoptM3ResponderLink(adjacencyAdopter, material.established)
    material.established = null
    runtime = takeM3ResponderLink(adoption)
    adoption = null
    const { takeM3InitiatorRuntime } = require('./m3-adjacency-runtime')
    const productionRuntime = takeM3InitiatorRuntime(runtime)
    if (productionRuntime !== null) {
      runtime = productionRuntime
      runtimeExtracted = true
    }
    const { enqueueTailExtended, installTailExtension } = require('./tail-extension-committer')
    enqueueTailExtended(extensionCommitter, envelope)
    if (record.destroyed || state.destroyed) throw PrivateRouteError.ERR_DESTROYED()
    forwarding = installTailExtension(
      extensionCommitter,
      runtime,
      material.expectedProof.expiresAtMs
    )
    runtime = null
    committerPublished = true
    if (record.destroyed || state.destroyed) throw PrivateRouteError.ERR_DESTROYED()
    installed = {
      branchClass: material.expectedProof.branchClass,
      branchId: copy(material.expectedProof.branchId, 16),
      circuitId: copy(material.expectedProof.circuitId, 16),
      generation: material.expectedProof.generation,
      extensionIndex: material.expectedProof.extensionIndex,
      tailControlTranscriptDigest: digestTailReadyTranscript(state.transcript),
      tailIdentity: copy(material.expectedProof.responderIdentity, 32),
      tailAdvertisementDigest: copy(material.expectedProof.responderAdvertisementDigest, 32),
      clientNonce: copy(material.expectedProof.clientNonce, 32),
      expiresAtMs: material.expectedProof.expiresAtMs,
      forwarding,
      socketOwnerLease: material.socketOwnerLease,
      destroySocketOwnerLease: material.destroySocketOwnerLease,
      readySealed: false
    }
    forwarding = null
    material.socketOwnerLease = null
    material.destroySocketOwnerLease = null
    opening.completion = null
    state.responderInstalled = installed
    installed = null
    state.responderOpening = null
    clearTailOpening(opening)
    complete = true
    return envelope
  } catch (err) {
    if (adoption) {
      try {
        const { destroyM3ResponderLink } = require('./m3-adjacency-adopter')
        destroyM3ResponderLink(adoption)
      } catch {}
    }
    if (runtime) {
      try {
        if (runtimeExtracted) runtime.destroy()
        else {
          const { destroyTakenM3ResponderLink } = require('./m3-adjacency-adopter')
          destroyTakenM3ResponderLink(adjacencyAdopter, runtime)
        }
      } catch {}
    }
    if (!committerPublished && extensionCommitter) {
      try {
        const { destroyTailExtensionCommitter } = require('./tail-extension-committer')
        destroyTailExtensionCommitter(extensionCommitter)
      } catch {}
    }
    if (forwarding && typeof forwarding.destroy === 'function') {
      try {
        forwarding.destroy()
      } catch {}
    }
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    destroyTakenExtensionLinkCompletion(material)
    clear(extended)
    if (!complete) clear(envelope)
    clearTailInstalled(installed)
  }
}

function abortTailExtend(authority) {
  const record = object(authority) ? RESPONDER_AUTHORITIES.get(authority) : null
  if (!record || record.destroyed || !record.sessionState || record.sessionState.destroyed)
    invalid()
  const state = record.sessionState
  if (!state.responderOpening) return false
  return abortTailOpening(state)
}

function encodeTailReadyBody(value) {
  let body = null
  try {
    body = b4a.allocUnsafeSlow(TAIL_READY_BODY_SIZE)
    body[0] = value.branchClass
    set(body, value.branchId, 1)
    set(body, value.circuitId, 17)
    writeUint64(body, value.generation, 33)
    body[41] = value.extensionIndex
    set(body, value.tailControlTranscriptDigest, 42)
    set(body, value.tailIdentity, 74)
    set(body, value.tailAdvertisementDigest, 106)
    set(body, value.clientNonce, 138)
    set(body, value.readyNonce, 170)
    writeUint64(body, value.expiresAtMs, 202)
    const result = body
    body = null
    return result
  } finally {
    clear(body)
  }
}

function sealTailReady(authority) {
  const record = object(authority) ? RESPONDER_AUTHORITIES.get(authority) : null
  if (!record || record.destroyed || !record.sessionState || record.sessionState.destroyed)
    invalid()
  const installed = record.sessionState.responderInstalled
  if (!installed) invalid()
  if (installed.readySealed) replay()
  installed.readySealed = true
  let current = BigInt(record.monotonicNow())
  if (!uint64(current) || current >= record.sessionState.deadline.localDeadline) invalid()
  const readyNonce = randomBuffer(record.randomBytes)
  let body = null
  let signature = null
  try {
    body = encodeTailReadyBody({
      ...installed,
      readyNonce
    })
    const { signTailReady } = require('./relay-identity-signer')
    signature = signTailReady(record.tailReadySigner, body, installed.tailIdentity)
    current = BigInt(record.monotonicNow())
    if (!uint64(current) || current >= record.sessionState.deadline.localDeadline) invalid()
    if (!fixed(signature, 64)) authentication()
    return encodeM3Object({
      messageId: M3_MESSAGE_ID.TAIL_READY_V1,
      body,
      authSuffix: signature
    })
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    clear(readyNonce)
    clear(body)
    clear(signature)
  }
}

function borrowTailControlTransport(session) {
  const state = object(session) ? SESSIONS.get(session) : null
  if (!state || state.destroyed) invalid()
  if (state.finalExitStage !== null) invalid()
  if (state.transport) return state.transport
  const {
    receiveM3TailControl,
    releaseM3ReceivedEnvelope,
    sendM3TailControl
  } = require('./m3-adjacency-runtime')
  const transport = {
    send(envelope) {
      if (SESSIONS.get(session) !== state || state.destroyed || state.finalExitStage !== null)
        invalid()
      return sendM3TailControl(state.transportOwner, envelope)
    },
    receive() {
      if (SESSIONS.get(session) !== state || state.destroyed || state.finalExitStage !== null)
        invalid()
      return receiveM3TailControl(state.transportOwner)
    }
  }
  Object.defineProperty(transport, 'release', {
    value(envelope) {
      if (SESSIONS.get(session) !== state || state.destroyed || state.finalExitStage !== null)
        invalid()
      return releaseM3ReceivedEnvelope(state.transportOwner, envelope)
    }
  })
  Object.freeze(transport)
  state.transport = transport
  return transport
}

function readTailControlDeadline(session) {
  const state = object(session) ? SESSIONS.get(session) : null
  if (!state || state.destroyed) invalid()
  return state.deadline.localDeadline
}
function readTailControlTranscriptDigest(session) {
  const state = object(session) ? SESSIONS.get(session) : null
  if (!state || state.destroyed || !state.transcript) invalid()
  return digestTailReadyTranscript(state.transcript)
}

function releaseTailControlSessionState(state) {
  if (!state) return
  if (state.handle !== null && state.cancelScheduled !== null) {
    try {
      state.cancelScheduled(state.handle)
    } catch {}
  }
  if (state.transportOwner) {
    try {
      const { releaseM3TailControlTransport } = require('./m3-adjacency-runtime')
      releaseM3TailControlTransport(state.transportOwner)
    } catch {}
  }
  clear(state.secret)
  clear(state.transcript)
  clearFinalExitMaterial(state.finalExitMaterial)
  state.finalExitMaterial = null
  clearFinalExitMaterial(state.finalExitActivationMaterial)
  state.finalExitActivationMaterial = null
  state.finalExitActivationOwner = null
  state.finalExitStage = null
  clearClientExtensionCompletionRecord(state.clientCompletion)
  state.clientCompletion = null
  clearClientExtension(state.clientExtension)
  state.clientExtension = null
  clearAdmittedExtendRequest(state.extensionRequest)
  state.extensionRequest = null
  abortTailOpening(state)
  clearTailInstalled(state.responderInstalled)
  state.responderInstalled = null
  if (state.responderAuthority) clearResponderAuthorityState(state.responderAuthority)
  state.responderAuthority = null
  state.cancelScheduled = null
  state.handle = null
  state.arming = false
  state.secret = null
  state.transcript = null
  state.deadline = null
  state.transport = null
  state.transportOwner = null
}

function destroyTailControlSession(session) {
  const state = object(session) ? SESSIONS.get(session) : null
  if (!state || state.destroyed || DESTROYED_SESSIONS.has(session)) return false
  SESSIONS.delete(session)
  DESTROYED_SESSIONS.add(session)
  state.destroyed = true
  if (state.arming) return true
  releaseTailControlSessionState(state)
  return true
}

module.exports = {
  ADMITTED_LIMITS_SIZE,
  EXTENDED_SIZE,
  EXTEND_REQUEST_MIN_SIZE,
  abortTailExtend,
  admitTailExtend,
  commitTailControlFinalExitActivation,
  completeTailExtend,
  destroyTailControlFinalExitActivation,
  EXTEND_REQUEST_MAX_SIZE,
  TAIL_CONTROL_TRANSCRIPT_SIZE,
  openTailAdjacentLink,
  TAIL_READY_SIZE,
  borrowTailControlTransport,
  createTailControlResponderAuthority,
  createTailControlSession,
  isTailControlSession,
  encodeExtendRequest,
  decodeExtendRequest,
  encodeExtended,
  decodeExtended,
  encodeAdmittedLimits,
  decodeAdmittedLimits,
  digestAdmittedLimits,
  encodeTailControlTranscript,
  decodeTailControlTranscript,
  digestTailControlTranscript,
  deriveTailControlTestVector,
  rejectTailControlFinalExitHandoffConsume,
  destroyTailControlFinalExitHandoffOwner,
  prepareTailControlFinalExitActivation,
  readTailControlTranscriptDigest,
  readTailControlDeadline,
  revokeTailControlFinalExitActivation,
  takeTailControlRouteTransport,
  createSuccessorTailReadyContext,
  encodeSuccessorTailReadyContext,
  importSuccessorTailReadyContext,
  sealSuccessorTailReady,
  readAdmittedTailSelection,
  takeAdmittedExtendRequest,
  destroyTailControlSession,
  decodeTailReady,
  sealTailReady,
  destroyTailControlResponderAuthority
}
