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
const LIMITS_DOMAIN = b4a.from('hyperdht-private-routes/tail-control/limits/v1')
const TAIL_DIGEST_DOMAIN = b4a.from('hyperdht-private-routes/final-exit/tail-digest/v1')
const TAIL_READY_DOMAIN = b4a.from('hyperdht-private-routes/m3/tail-ready/v1')
const TAIL_READY_TRANSCRIPT_DOMAIN = b4a.from(
  'hyperdht-private-routes/m3/tail-control/transcript-digest/v1'
)
const TAIL_READY_BODY_SIZE = 210
const EXTEND_REQUEST_FIXED_BODY_SIZE = 198
const EXTENDED_BODY_SIZE = 486
const REDACTED_RESPONDER_PROOF_SIZE = 378
const SESSIONS = new WeakMap()
const DESTROYED_SESSIONS = new WeakSet()
const RESPONDER_AUTHORITIES = new WeakMap()
const DESTROYED_RESPONDER_AUTHORITIES = new WeakSet()
const ADMITTED_EXTEND_REQUESTS = new WeakMap()
const CLIENT_EXTENSION_COMPLETIONS = new WeakMap()
const SPENT_CLIENT_EXTENSION_COMPLETIONS = new WeakSet()
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
  record.deadline = 0n
  record.key = null
  clear(record.extensionNonce)
  record.extensionNonce = null
}

function clearAdmittedExtendMaterial(value) {
  if (!value) return
  clearExtendRequest(value.request)
  clear(value.currentTailIdentity)
  clear(value.currentTailAdvertisementDigest)
  value.request = null
  value.currentTailIdentity = null
  value.currentTailAdvertisementDigest = null
  value.deadline = 0n
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
    'relayIdentity',
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

function reserveAdmittedExtendRequest(state, session) {
  const record = {
    capability: null,
    request: null,
    currentTailIdentity: null,
    currentTailAdvertisementDigest: null,
    session,
    status: 'PENDING',
    deadline: 0n,
    key: null,
    extensionNonce: null
  }
  state.extensionRequest = record
  return record
}

function publishAdmittedExtendRequest(state, reservation, request, key, deadline, transcript) {
  if (!reservation || state.extensionRequest !== reservation || reservation.status !== 'PENDING') invalid()
  let complete = false
  try {
    reservation.currentTailIdentity = copy(transcript.tailIdentity, 32)
    reservation.currentTailAdvertisementDigest = copy(transcript.candidateAdvertisementDigest, 32)
    reservation.extensionNonce = copy(request.extensionNonce, 32)
    reservation.capability = Object.freeze({})
    reservation.request = request
    reservation.deadline = deadline
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
  armTailControlSession(session, state)
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

function clearClientExtension(record) {
  if (!record) return
  for (const field of [
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
    const projectedWireExpiresAt = wall + (absoluteDeadline - current)
    if (!uint64(projectedWireExpiresAt) || !uint64(requestedWireExpiresAt) || requestedWireExpiresAt === 0n) invalid()
    if (
      requestedWireExpiresAt > projectedWireExpiresAt ||
      requestedWireExpiresAt > state.deadline.wireExpiresAt ||
      requestedWireExpiresAt > decodedAdvertisement.expiresAtMs
    ) {
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


function tailControlTimerDelay(remaining) {
  return remaining > BigInt(MAX_TIMER_DELAY) ? MAX_TIMER_DELAY : Number(remaining)
}

function runTailControlSessionTimer(session, generation) {
  const state = object(session) ? SESSIONS.get(session) : null
  if (!state || state.destroyed || state.timerGeneration !== generation) return
  let current
  try {
    current = BigInt(state.monotonicNow())
  } catch {
    destroyTailControlSession(session)
    return
  }
  if (current < state.deadline.localDeadline) {
    try {
      armTailControlSession(session, state)
    } catch {
      destroyTailControlSession(session)
    }
    return
  }
  destroyTailControlSession(session)
}

function armTailControlSession(session, state) {
  const current = BigInt(state.monotonicNow())
  if (current >= state.deadline.localDeadline) invalid()
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
    if (state.destroyed || !SESSIONS.has(session)) {
      releaseTailControlSessionState(state)
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
    !SESSIONS.has(session)
  ) {
    state.timerGeneration++
    if (handle !== null && handle !== undefined) {
      try {
        state.cancelScheduled(handle)
      } catch {}
    }
    if (state.destroyed || !SESSIONS.has(session)) {
      releaseTailControlSessionState(state)
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
  if (!object(selectedCrypto) || typeof selectedCrypto.encryptionKeyPair !== 'function') invalid()
  const { shortenM3TailLifetime, takeM3TailCapability } = require('./m3-adjacency-runtime')
  const tailState = takeM3TailCapability(capability, {
    wallNow: wallDescriptor.value,
    monotonicNow: monotonicDescriptor.value
  })
  let deadline = tailState.deadline
  if (tailState.initiator) {
    if (!deadlineDescriptor || !uint64(deadlineDescriptor.value) || deadlineDescriptor.value === 0n) {
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
    crypto: selectedCrypto,
    deadline,
    extensionRequest: null,
    destroyed: false,
    handle: null,
    initiator: tailState.initiator,
    binding: tailState.binding,
    monotonicNow: monotonicDescriptor.value,
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
      openExtended() {
        invalid()
      },
      completeClientExtension() {
        invalid()
      },
      abortClientExtension() {
        invalid()
      },
      takeFinalExitHandoff() {
        invalid()
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
  const adjacencyAdopter = exactValueDescriptor(options, 'adjacencyAdopter')
  const extensionCommitter = exactValueDescriptor(options, 'extensionCommitter')
  const adjacentLinkFactory = exactValueDescriptor(options, 'adjacentLinkFactory')
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
  if (state.extensionRequest !== null) {
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
  const deadline = record.deadline
  ADMITTED_EXTEND_REQUESTS.delete(capability)
  record.capability = null
  record.request = null
  record.currentTailIdentity = null
  record.currentTailAdvertisementDigest = null
  record.session = null
  record.status = 'TAKEN'
  record.deadline = 0n
  record.key = null
  clear(record.extensionNonce)
  record.extensionNonce = null
  return Object.freeze({
    request,
    currentTailIdentity,
    currentTailAdvertisementDigest,
    deadline
  })
}

function openTailAdjacentLink() {
  invalid()
}

function completeTailExtend() {
  invalid()
}

function abortTailExtend() {
  invalid()
}

function sealTailReady() {
  invalid()
}

function borrowTailControlTransport(session) {
  const state = object(session) ? SESSIONS.get(session) : null
  if (!state || state.destroyed) invalid()
  if (state.transport) return state.transport
  const { receiveM3TailControl, sendM3TailControl } = require('./m3-adjacency-runtime')
  const transport = Object.freeze({
    send(envelope) {
      if (SESSIONS.get(session) !== state || state.destroyed) invalid()
      return sendM3TailControl(state.transportOwner, envelope)
    },
    receive() {
      if (SESSIONS.get(session) !== state || state.destroyed) invalid()
      return receiveM3TailControl(state.transportOwner)
    }
  })
  state.transport = transport
  return transport
}

function readTailControlDeadline(session) {
  const state = object(session) ? SESSIONS.get(session) : null
  if (!state || state.destroyed) invalid()
  return state.deadline.localDeadline
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
  clearClientExtension(state.clientExtension)
  state.clientExtension = null
  clearAdmittedExtendRequest(state.extensionRequest)
  state.extensionRequest = null
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
  completeTailExtend,
  EXTEND_REQUEST_MAX_SIZE,
  TAIL_CONTROL_TRANSCRIPT_SIZE,
  openTailAdjacentLink,
  TAIL_READY_SIZE,
  borrowTailControlTransport,
  createTailControlResponderAuthority,
  createTailControlSession,
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
  readTailControlDeadline,
  takeAdmittedExtendRequest,
  destroyTailControlSession,
  decodeTailReady,
  sealTailReady,
  destroyTailControlResponderAuthority
}
