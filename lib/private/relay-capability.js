'use strict'

const b4a = require('b4a')
const sodium = require('sodium-universal')

const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')
const { EXIT_ORIGIN_SERVICE_POLICY } = require('./exit-policy')
const {
  CAPACITY_CLASS,
  M3_MESSAGE_ID,
  M3_PROTOCOL_VERSION,
  RELAY_CAPABILITY,
  ROLE,
  decodeM3Object,
  encodeM3Object,
  roleForIdentity
} = require('./protocol')

// Ported from the reviewed private-routes prototype at commit
// 0305df915b6a767093f9e75e6c06bc0a35da6169 and narrowed to Gate 3B1.

const CAPABILITY_ADVERTISEMENT_FIXED_BODY = 188
const CAPABILITY_ADVERTISEMENT_MIN_BYTES = 260
const CAPABILITY_ADVERTISEMENT_MAX_BYTES = 388
const MAX_CAPABILITY_ADVERTISEMENTS = 8
const MAX_CAPABILITY_LIFETIME = 1_800_000n
const MAX_FUTURE_SKEW = 30_000n
const ACTIVE_CHALLENGE_TIMEOUT = 5_000n

const MAX_ROUTE_KEY_HISTORY = 16
const CAPS_COOKIE_LIFETIME = 5_000n
const CAPS_COOKIE_ROTATION = 300_000n
const MAX_CAPS_BINDINGS = 4_096
// Test-only observation is discard-new at this cap so it cannot retain unbounded buffers.
const MAX_RESPONDER_OBSERVATION_EVENTS = 64
const MAX_RESPONDER_OBSERVATION_DROPS = 9_007_199_254_740_991
const MAX_U32 = 0xffff_ffff
const MAX_U64 = 0xffff_ffff_ffff_ffffn
const X25519_CHECK_SECRET = b4a.alloc(32, 0x5a)
const ZERO_32 = b4a.alloc(32)

const CAPABILITY_DOMAIN = b4a.from('hyperdht-private-routes/m3/capability-advertisement/v1')
const CAPABILITY_DIGEST_DOMAIN = b4a.from(
  'hyperdht-private-routes/m3/capability-advertisement-digest/v1'
)
const ACTIVE_RESPONSE_DOMAIN = b4a.from('hyperdht-private-routes/m3/active-challenge-response/v1')
const ACTIVE_PROOF_DOMAIN = b4a.from(
  'hyperdht-private-routes/m3/active-challenge/route-key-proof/v1'
)
const CAPS_COOKIE_DOMAIN = b4a.from('hyperdht-private-routes/m3/caps-return-cookie/v1')

const ADVERTISEMENT_FIELDS = Object.freeze([
  'relayIdentity',
  'currentDhtNodeId',
  'reachableEndpoint',
  'routeEncryptionPublicKey',
  'capabilityMask',
  'minimumProtocolVersion',
  'maximumProtocolVersion',
  'cellSize',
  'maxCellPayload',
  'contextEnvelopeSize',
  'routeFrameSize',
  'maxRoutePayload',
  'datagramReplayWindow',
  'maxConcurrentCircuits',
  'capacityClass',
  'maxCellsPerCircuit',
  'maxBytesPerCircuit',
  'maxCommandsPerCircuit',
  'idleTimeoutMs',
  'maxQueuedBytes',
  'epoch',
  'issuedAtMs',
  'expiresAtMs',
  'providerServicePolicyEntries'
])
const SIGNED_ADVERTISEMENT_FIELDS = Object.freeze([...ADVERTISEMENT_FIELDS, 'signature'])
const POLICY_FIELDS = Object.freeze([
  'commandId',
  'commandVersion',
  'maxRequestBytes',
  'maxResponseBytes',
  'timeoutMs',
  'maxOutstanding',
  'requestCost',
  'responseCost',
  'maxAmplificationBytes',
  'mutationFlag',
  'destinationValidationClass'
])
const ENDPOINT_FIELDS = Object.freeze(['addressFamily', 'addressBytes', 'port'])
const ACCEPT_FIELDS = Object.freeze(['expectedRole', 'expectedCapabilityMask'])
const CONSTRUCTOR_FIELDS = Object.freeze([
  'wallNow',
  'monotonicNow',
  'setTimer',
  'clearTimer',
  'onInvalidated'
])
const CAPS_QUERY_FIELDS = Object.freeze([
  'sourceEndpoint',
  'requestedCapabilityMask',
  'randomTarget',
  'queryNonce',
  'maximumResults'
])
const CAPS_RETRY_FIELDS = Object.freeze([
  ...CAPS_QUERY_FIELDS,
  'cookieExpiresAtMs',
  'returnRoutabilityCookie',
  'advertisement'
])
const RESPOND_FIELDS = Object.freeze([
  'sourceEndpoint',
  'advertisement',
  'identitySecretKey',
  'routeEncryptionSecretKey'
])
const SEND_AUTHORITY_FIELDS = Object.freeze(['capsBinding', 'send'])
const SEND_CAPS_BINDING_FIELDS = Object.freeze([
  'advertisement',
  'sourceEndpoint',
  'queryNonce',
  'cookieExpiresAtMs',
  'returnRoutabilityCookie',
  'advertisementDigest',
  'relayIdentity'
])

const byteLengthGetter = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
const bufferSet = Uint8Array.prototype.set
const bufferSubarray = Uint8Array.prototype.subarray
const bufferFill = Uint8Array.prototype.fill
const arrayIsArray = Array.isArray
const objectFreeze = Object.freeze
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectGetOwnPropertyNames = Object.getOwnPropertyNames
const objectGetOwnPropertySymbols = Object.getOwnPropertySymbols
const objectGetPrototypeOf = Object.getPrototypeOf
const objectHasOwnProperty = Object.prototype.hasOwnProperty
const objectPrototype = Object.prototype
const arrayIncludes = Array.prototype.includes
const arrayPush = Array.prototype.push
const arraySome = Array.prototype.some
const reflectApply = Reflect.apply
const b4aAllocUnsafeSlow = b4a.allocUnsafeSlow
const b4aConcat = b4a.concat
const b4aEquals = b4a.equals
const b4aIsBuffer = b4a.isBuffer
const b4aToString = b4a.toString
const verifierStates = new WeakMap()
const projectionOwners = new WeakMap()
const sendAuthorityStates = new WeakMap()
const consumedSendAuthorities = new WeakSet()

function incompatible() {
  throw PrivateRouteError.ERR_INCOMPATIBLE_RELAY()
}

function authentication() {
  throw PrivateRouteError.ERR_AUTHENTICATION()
}

function replay() {
  throw PrivateRouteError.ERR_REPLAY()
}

function destroyed() {
  throw PrivateRouteError.ERR_DESTROYED()
}

function bufferLength(value) {
  try {
    return b4aIsBuffer(value) ? reflectApply(byteLengthGetter, value, []) : -1
  } catch {
    return -1
  }
}

function clear(value) {
  try {
    if (bufferLength(value) >= 0) reflectApply(bufferFill, value, [0])
  } catch {
    // Best-effort zeroization only.
  }
}

function allocate(size) {
  if (!Number.isSafeInteger(size) || size < 0 || size > CAPABILITY_ADVERTISEMENT_MAX_BYTES + 512) {
    incompatible()
  }
  return b4aAllocUnsafeSlow(size)
}

function copy(value, expected = null) {
  const size = bufferLength(value)
  if (size < 0 || (expected !== null && size !== expected)) incompatible()
  const output = allocate(size)
  try {
    reflectApply(bufferSet, output, [value, 0])
    return output
  } catch {
    clear(output)
    incompatible()
  }
}

function subarray(value, start, end) {
  try {
    return reflectApply(bufferSubarray, value, [start, end])
  } catch {
    incompatible()
  }
}

function set(target, source, offset = 0) {
  try {
    reflectApply(bufferSet, target, [source, offset])
  } catch {
    incompatible()
  }
}

function equal(left, right) {
  try {
    return bufferLength(left) === bufferLength(right) && b4aEquals(left, right)
  } catch {
    return false
  }
}

function exactObject(value, fields) {
  try {
    if (value === null || typeof value !== 'object' || arrayIsArray(value)) incompatible()
    const prototype = objectGetPrototypeOf(value)
    if (prototype !== objectPrototype && prototype !== null) incompatible()
    if (objectGetOwnPropertySymbols(value).length !== 0) incompatible()
    const names = objectGetOwnPropertyNames(value)
    if (names.length !== fields.length) incompatible()
    for (const field of fields) {
      if (!reflectApply(arrayIncludes, names, [field])) incompatible()
      const descriptor = objectGetOwnPropertyDescriptor(value, field)
      if (!descriptor || !reflectApply(objectHasOwnProperty, descriptor, ['value'])) incompatible()
    }
    return value
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    incompatible()
  }
}

function dataProperty(value, name) {
  try {
    const descriptor = objectGetOwnPropertyDescriptor(value, name)
    if (!descriptor || !reflectApply(objectHasOwnProperty, descriptor, ['value'])) incompatible()
    return descriptor.value
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    incompatible()
  }
}

function uint16(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 0xffff
}

function uint32(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= MAX_U32
}

function uint64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= MAX_U64
}

function writeUint16(output, value, offset) {
  output[offset] = value >>> 8
  output[offset + 1] = value
}

function writeUint32(output, value, offset) {
  output[offset] = value >>> 24
  output[offset + 1] = value >>> 16
  output[offset + 2] = value >>> 8
  output[offset + 3] = value
}

function writeUint64(output, value, offset) {
  for (let index = offset + 7; index >= offset; index--) {
    output[index] = Number(value & 0xffn)
    value >>= 8n
  }
}

function readUint16(input, offset) {
  return (input[offset] << 8) | input[offset + 1]
}

function readUint32(input, offset) {
  return (
    input[offset] * 0x1000000 +
    (input[offset + 1] << 16) +
    (input[offset + 2] << 8) +
    input[offset + 3]
  )
}

function readUint64(input, offset) {
  let value = 0n
  for (let index = offset; index < offset + 8; index++) value = (value << 8n) | BigInt(input[index])
  return value
}

function signatureInput(domain, messageId, body) {
  const output = allocate(2 + domain.byteLength + 8 + body.byteLength)
  writeUint16(output, domain.byteLength, 0)
  set(output, domain, 2)
  writeUint32(output, M3_PROTOCOL_VERSION, 2 + domain.byteLength)
  writeUint16(output, messageId, 6 + domain.byteLength)
  writeUint16(output, body.byteLength, 8 + domain.byteLength)
  set(output, body, 10 + domain.byteLength)
  return output
}

function digest(parts) {
  let source = null
  try {
    source = cryptoSuite.hash(parts)
    return copy(source, 32)
  } finally {
    clear(source)
  }
}

function keyedHash(key, parts) {
  let input = null
  let output = null
  try {
    input = b4aConcat(parts)
    output = allocate(32)
    sodium.crypto_generichash(output, input, key)
    const result = output
    output = null
    return result
  } finally {
    clear(input)
    clear(output)
  }
}

function encodeCanonicalEndpoint(value) {
  exactObject(value, ENDPOINT_FIELDS)
  const family = dataProperty(value, 'addressFamily')
  const address = dataProperty(value, 'addressBytes')
  const port = dataProperty(value, 'port')
  if ((family !== 4 && family !== 6) || !uint16(port) || port === 0) incompatible()
  if (bufferLength(address) !== (family === 4 ? 4 : 16)) incompatible()
  const output = allocate(19)
  clear(output)
  output[0] = family
  set(output, address, family === 4 ? 13 : 1)
  writeUint16(output, port, 17)
  return output
}

function decodeCanonicalEndpoint(encoded) {
  const value = copy(encoded, 19)
  try {
    const family = value[0]
    if (family !== 4 && family !== 6) incompatible()
    if (readUint16(value, 17) === 0) incompatible()
    if (family === 4) {
      for (let index = 1; index < 13; index++) if (value[index] !== 0) incompatible()
    } else if (
      value[1] === 0 &&
      value[2] === 0 &&
      value[3] === 0 &&
      value[4] === 0 &&
      value[5] === 0 &&
      value[6] === 0 &&
      value[7] === 0 &&
      value[8] === 0 &&
      value[9] === 0 &&
      value[10] === 0 &&
      value[11] === 0xff &&
      value[12] === 0xff
    ) {
      incompatible()
    }
    return value
  } catch (err) {
    clear(value)
    throw err
  }
}

function deriveM3DhtNodeId(reachableEndpoint) {
  const endpoint = decodeCanonicalEndpoint(reachableEndpoint)
  let compact = null
  let output = null
  try {
    if (endpoint[0] !== 4) incompatible()
    compact = allocate(6)
    set(compact, subarray(endpoint, 13, 17))
    compact[4] = endpoint[18]
    compact[5] = endpoint[17]
    output = allocate(32)
    sodium.crypto_generichash(output, compact)
    return output
  } catch (err) {
    clear(output)
    throw err
  } finally {
    clear(compact)
    clear(endpoint)
  }
}

function copyPolicyEntry(entry) {
  const output = {}
  for (const name of POLICY_FIELDS) output[name] = entry[name]
  return objectFreeze(output)
}

function providerServicePolicyForCapabilities(capabilityMask) {
  if (
    !uint32(capabilityMask) ||
    capabilityMask === 0 ||
    capabilityMask & ~7 ||
    (capabilityMask & RELAY_CAPABILITY.DHT_EXIT_V1 &&
      !(capabilityMask & RELAY_CAPABILITY.CIRCUIT_RELAY_V1))
  ) {
    incompatible()
  }
  const entries = []
  if (capabilityMask & RELAY_CAPABILITY.DHT_EXIT_V1) {
    for (let index = 0; index < 4; index++) {
      reflectApply(arrayPush, entries, [copyPolicyEntry(EXIT_ORIGIN_SERVICE_POLICY[index])])
    }
  }
  if (capabilityMask & RELAY_CAPABILITY.PRIVATE_RECORDS_V1) {
    for (let index = 4; index < 9; index++) {
      reflectApply(arrayPush, entries, [copyPolicyEntry(EXIT_ORIGIN_SERVICE_POLICY[index])])
    }
  }
  return objectFreeze(entries)
}

function exactPolicyEntries(actual, capabilityMask) {
  if (!arrayIsArray(actual)) incompatible()
  const expected = providerServicePolicyForCapabilities(capabilityMask)
  const lengthDescriptor = objectGetOwnPropertyDescriptor(actual, 'length')
  if (!lengthDescriptor || lengthDescriptor.value !== expected.length) incompatible()
  if (objectGetOwnPropertySymbols(actual).length !== 0) incompatible()
  const names = objectGetOwnPropertyNames(actual)
  if (names.length !== expected.length + 1) incompatible()
  for (let index = 0; index < expected.length; index++) {
    const descriptor = objectGetOwnPropertyDescriptor(actual, String(index))
    if (!descriptor || !reflectApply(objectHasOwnProperty, descriptor, ['value'])) incompatible()
    const entry = exactObject(descriptor.value, POLICY_FIELDS)
    for (const name of POLICY_FIELDS) {
      if (dataProperty(entry, name) !== expected[index][name]) incompatible()
    }
  }
  return expected
}

function validateRoutePublicKey(value) {
  const key = copy(value, 32)
  let shared = null
  try {
    shared = cryptoSuite.keyAgreement(X25519_CHECK_SECRET, key)
    return key
  } catch {
    clear(key)
    incompatible()
  } finally {
    clear(shared)
  }
}

function clearAdvertisement(value) {
  if (!value) return
  clear(value.relayIdentity)
  clear(value.currentDhtNodeId)
  clear(value.reachableEndpoint)
  clear(value.routeEncryptionPublicKey)
  clear(value.signature)
}

function normalizeAdvertisement(value, signed = false) {
  exactObject(value, signed ? SIGNED_ADVERTISEMENT_FIELDS : ADVERTISEMENT_FIELDS)
  let relayIdentity = null
  let currentDhtNodeId = null
  let reachableEndpoint = null
  let routeEncryptionPublicKey = null
  try {
    relayIdentity = copy(dataProperty(value, 'relayIdentity'), 32)
    currentDhtNodeId = copy(dataProperty(value, 'currentDhtNodeId'), 32)
    reachableEndpoint = decodeCanonicalEndpoint(dataProperty(value, 'reachableEndpoint'))
    routeEncryptionPublicKey = validateRoutePublicKey(
      dataProperty(value, 'routeEncryptionPublicKey')
    )
    const capabilityMask = dataProperty(value, 'capabilityMask')
    const minimumProtocolVersion = dataProperty(value, 'minimumProtocolVersion')
    const maximumProtocolVersion = dataProperty(value, 'maximumProtocolVersion')
    const cellSize = dataProperty(value, 'cellSize')
    const maxCellPayload = dataProperty(value, 'maxCellPayload')
    const contextEnvelopeSize = dataProperty(value, 'contextEnvelopeSize')
    const routeFrameSize = dataProperty(value, 'routeFrameSize')
    const maxRoutePayload = dataProperty(value, 'maxRoutePayload')
    const datagramReplayWindow = dataProperty(value, 'datagramReplayWindow')
    const maxConcurrentCircuits = dataProperty(value, 'maxConcurrentCircuits')
    const capacityClass = dataProperty(value, 'capacityClass')
    const maxCellsPerCircuit = dataProperty(value, 'maxCellsPerCircuit')
    const maxBytesPerCircuit = dataProperty(value, 'maxBytesPerCircuit')
    const maxCommandsPerCircuit = dataProperty(value, 'maxCommandsPerCircuit')
    const idleTimeoutMs = dataProperty(value, 'idleTimeoutMs')
    const maxQueuedBytes = dataProperty(value, 'maxQueuedBytes')
    const epoch = dataProperty(value, 'epoch')
    const issuedAtMs = dataProperty(value, 'issuedAtMs')
    const expiresAtMs = dataProperty(value, 'expiresAtMs')
    const providerServicePolicyEntries = exactPolicyEntries(
      dataProperty(value, 'providerServicePolicyEntries'),
      capabilityMask
    )

    if (
      (capabilityMask !== 1 && capabilityMask !== 3) ||
      reachableEndpoint[0] !== 4 ||
      minimumProtocolVersion !== 1 ||
      maximumProtocolVersion !== 1 ||
      cellSize !== 1200 ||
      maxCellPayload !== 1146 ||
      contextEnvelopeSize !== 1101 ||
      routeFrameSize !== 1100 ||
      maxRoutePayload !== 1073 ||
      datagramReplayWindow !== 64 ||
      !uint16(maxConcurrentCircuits) ||
      maxConcurrentCircuits === 0 ||
      (capacityClass !== CAPACITY_CLASS.SMALL &&
        capacityClass !== CAPACITY_CLASS.MEDIUM &&
        capacityClass !== CAPACITY_CLASS.LARGE) ||
      !uint32(maxCellsPerCircuit) ||
      maxCellsPerCircuit === 0 ||
      !uint32(maxBytesPerCircuit) ||
      maxBytesPerCircuit === 0 ||
      !uint32(maxCommandsPerCircuit) ||
      maxCommandsPerCircuit === 0 ||
      !uint32(idleTimeoutMs) ||
      idleTimeoutMs === 0 ||
      !uint32(maxQueuedBytes) ||
      maxQueuedBytes === 0 ||
      !uint64(epoch) ||
      epoch === 0n ||
      !uint64(issuedAtMs) ||
      !uint64(expiresAtMs) ||
      issuedAtMs >= expiresAtMs ||
      expiresAtMs - issuedAtMs > MAX_CAPABILITY_LIFETIME
    ) {
      incompatible()
    }

    const first = reachableEndpoint[13]
    const unspecified =
      first === 0 &&
      reachableEndpoint[14] === 0 &&
      reachableEndpoint[15] === 0 &&
      reachableEndpoint[16] === 0
    const broadcast =
      first === 255 &&
      reachableEndpoint[14] === 255 &&
      reachableEndpoint[15] === 255 &&
      reachableEndpoint[16] === 255
    if (unspecified || broadcast || first >= 224) incompatible()

    const derived = deriveM3DhtNodeId(reachableEndpoint)
    try {
      if (!equal(derived, currentDhtNodeId)) incompatible()
    } finally {
      clear(derived)
    }
    const requiredRole = capabilityMask === 3 ? ROLE.PRIVATE : ROLE.SAFETY
    if (roleForIdentity(relayIdentity) !== requiredRole) incompatible()

    const result = {
      relayIdentity,
      currentDhtNodeId,
      reachableEndpoint,
      routeEncryptionPublicKey,
      capabilityMask,
      minimumProtocolVersion,
      maximumProtocolVersion,
      cellSize,
      maxCellPayload,
      contextEnvelopeSize,
      routeFrameSize,
      maxRoutePayload,
      datagramReplayWindow,
      maxConcurrentCircuits,
      capacityClass,
      maxCellsPerCircuit,
      maxBytesPerCircuit,
      maxCommandsPerCircuit,
      idleTimeoutMs,
      maxQueuedBytes,
      epoch,
      issuedAtMs,
      expiresAtMs,
      providerServicePolicyEntries
    }
    if (signed) result.signature = copy(dataProperty(value, 'signature'), 64)
    relayIdentity = null
    currentDhtNodeId = null
    reachableEndpoint = null
    routeEncryptionPublicKey = null
    return result
  } finally {
    clear(relayIdentity)
    clear(currentDhtNodeId)
    clear(reachableEndpoint)
    clear(routeEncryptionPublicKey)
  }
}

function encodePolicyEntry(output, entry, offset) {
  writeUint16(output, entry.commandId, offset)
  writeUint16(output, entry.commandVersion, offset + 2)
  writeUint32(output, entry.maxRequestBytes, offset + 4)
  writeUint32(output, entry.maxResponseBytes, offset + 8)
  writeUint32(output, entry.timeoutMs, offset + 12)
  writeUint16(output, entry.maxOutstanding, offset + 16)
  writeUint32(output, entry.requestCost, offset + 18)
  writeUint32(output, entry.responseCost, offset + 22)
  writeUint32(output, entry.maxAmplificationBytes, offset + 26)
  output[offset + 30] = entry.mutationFlag
  output[offset + 31] = entry.destinationValidationClass
}

function encodeAdvertisementBody(value, signed = false) {
  const normalized = normalizeAdvertisement(value, signed)
  let body = null
  try {
    body = allocate(
      CAPABILITY_ADVERTISEMENT_FIXED_BODY + normalized.providerServicePolicyEntries.length * 32
    )
    let offset = 0
    for (const field of [
      normalized.relayIdentity,
      normalized.currentDhtNodeId,
      normalized.reachableEndpoint,
      normalized.routeEncryptionPublicKey
    ]) {
      set(body, field, offset)
      offset += field.byteLength
    }
    writeUint32(body, normalized.capabilityMask, offset)
    writeUint32(body, normalized.minimumProtocolVersion, offset + 4)
    writeUint32(body, normalized.maximumProtocolVersion, offset + 8)
    offset += 12
    for (const scalar of [
      normalized.cellSize,
      normalized.maxCellPayload,
      normalized.contextEnvelopeSize,
      normalized.routeFrameSize,
      normalized.maxRoutePayload,
      normalized.datagramReplayWindow,
      normalized.maxConcurrentCircuits
    ]) {
      writeUint16(body, scalar, offset)
      offset += 2
    }
    body[offset++] = normalized.capacityClass
    for (const scalar of [
      normalized.maxCellsPerCircuit,
      normalized.maxBytesPerCircuit,
      normalized.maxCommandsPerCircuit,
      normalized.idleTimeoutMs,
      normalized.maxQueuedBytes
    ]) {
      writeUint32(body, scalar, offset)
      offset += 4
    }
    for (const scalar of [normalized.epoch, normalized.issuedAtMs, normalized.expiresAtMs]) {
      writeUint64(body, scalar, offset)
      offset += 8
    }
    writeUint16(body, normalized.providerServicePolicyEntries.length, offset)
    offset += 2
    for (const entry of normalized.providerServicePolicyEntries) {
      encodePolicyEntry(body, entry, offset)
      offset += 32
    }
    return { body, normalized }
  } catch (err) {
    clear(body)
    clearAdvertisement(normalized)
    throw err
  }
}

function decodePolicyEntry(body, offset) {
  return objectFreeze({
    commandId: readUint16(body, offset),
    commandVersion: readUint16(body, offset + 2),
    maxRequestBytes: readUint32(body, offset + 4),
    maxResponseBytes: readUint32(body, offset + 8),
    timeoutMs: readUint32(body, offset + 12),
    maxOutstanding: readUint16(body, offset + 16),
    requestCost: readUint32(body, offset + 18),
    responseCost: readUint32(body, offset + 22),
    maxAmplificationBytes: readUint32(body, offset + 26),
    mutationFlag: body[offset + 30],
    destinationValidationClass: body[offset + 31]
  })
}

function decodeAdvertisementBody(body) {
  if (
    body.byteLength < CAPABILITY_ADVERTISEMENT_FIXED_BODY ||
    body.byteLength > CAPABILITY_ADVERTISEMENT_FIXED_BODY + 4 * 32 ||
    (body.byteLength - CAPABILITY_ADVERTISEMENT_FIXED_BODY) % 32 !== 0
  ) {
    incompatible()
  }
  let offset = 0
  const owned = []
  const take = (size) => {
    const value = copy(subarray(body, offset, offset + size), size)
    offset += size
    reflectApply(arrayPush, owned, [value])
    return value
  }
  try {
    const value = {
      relayIdentity: take(32),
      currentDhtNodeId: take(32),
      reachableEndpoint: take(19),
      routeEncryptionPublicKey: take(32),
      capabilityMask: readUint32(body, offset),
      minimumProtocolVersion: readUint32(body, offset + 4),
      maximumProtocolVersion: readUint32(body, offset + 8)
    }
    offset += 12
    for (const name of [
      'cellSize',
      'maxCellPayload',
      'contextEnvelopeSize',
      'routeFrameSize',
      'maxRoutePayload',
      'datagramReplayWindow',
      'maxConcurrentCircuits'
    ]) {
      value[name] = readUint16(body, offset)
      offset += 2
    }
    value.capacityClass = body[offset++]
    for (const name of [
      'maxCellsPerCircuit',
      'maxBytesPerCircuit',
      'maxCommandsPerCircuit',
      'idleTimeoutMs',
      'maxQueuedBytes'
    ]) {
      value[name] = readUint32(body, offset)
      offset += 4
    }
    value.epoch = readUint64(body, offset)
    value.issuedAtMs = readUint64(body, offset + 8)
    value.expiresAtMs = readUint64(body, offset + 16)
    offset += 24
    const count = readUint16(body, offset)
    offset += 2
    if (count !== (body.byteLength - CAPABILITY_ADVERTISEMENT_FIXED_BODY) / 32) incompatible()
    value.providerServicePolicyEntries = []
    for (let index = 0; index < count; index++) {
      reflectApply(arrayPush, value.providerServicePolicyEntries, [decodePolicyEntry(body, offset)])
      offset += 32
    }
    const normalized = normalizeAdvertisement(value)
    for (const buffer of owned) clear(buffer)
    return normalized
  } catch (err) {
    for (const buffer of owned) clear(buffer)
    throw err
  }
}

function signRelayCapabilityAdvertisement(value, identitySecretKey) {
  let body = null
  let normalized = null
  let secret = null
  let input = null
  let signatureSource = null
  let signature = null
  try {
    const encoded = encodeAdvertisementBody(value)
    body = encoded.body
    normalized = encoded.normalized
    secret = copy(identitySecretKey, 64)
    input = signatureInput(CAPABILITY_DOMAIN, M3_MESSAGE_ID.CAPABILITY_ADVERTISEMENT_V1, body)
    signatureSource = cryptoSuite.sign(input, secret)
    signature = copy(signatureSource, 64)
    if (!cryptoSuite.verify(input, signature, normalized.relayIdentity)) {
      authentication()
    }
    const result = objectFreeze({ ...normalized, signature })
    normalized = null
    signature = null
    return result
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    authentication()
  } finally {
    clearAdvertisement(normalized)
    clear(signatureSource)
    clear(signature)
    clear(secret)
    clear(input)
    clear(body)
  }
}

function encodeRelayCapabilityAdvertisement(value) {
  const { body, normalized } = encodeAdvertisementBody(value, true)
  try {
    return encodeM3Object({
      messageId: M3_MESSAGE_ID.CAPABILITY_ADVERTISEMENT_V1,
      body,
      authSuffix: normalized.signature
    })
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code.startsWith('ERR_')) throw err
    incompatible()
  } finally {
    clear(body)
    clearAdvertisement(normalized)
  }
}

function decodeNowOptions(options) {
  if (options === undefined) return undefined
  exactObject(options, ['now'])
  return dataProperty(options, 'now')
}

function decodeRelayCapabilityAdvertisement(encoded, options) {
  const now = decodeNowOptions(options)
  let object = null
  let value = null
  let input = null
  try {
    try {
      object = decodeM3Object(encoded)
    } catch {
      incompatible()
    }
    if (object.messageId !== M3_MESSAGE_ID.CAPABILITY_ADVERTISEMENT_V1) incompatible()
    value = decodeAdvertisementBody(object.body)
    input = signatureInput(
      CAPABILITY_DOMAIN,
      M3_MESSAGE_ID.CAPABILITY_ADVERTISEMENT_V1,
      object.body
    )
    if (!cryptoSuite.verify(input, object.authSuffix, value.relayIdentity)) authentication()
    if (now !== undefined) {
      if (!uint64(now)) incompatible()
      if (value.issuedAtMs > now + MAX_FUTURE_SKEW || value.expiresAtMs <= now) incompatible()
    }
    const result = objectFreeze({
      ...value,
      providerServicePolicyEntries: objectFreeze(value.providerServicePolicyEntries),
      signature: copy(object.authSuffix, 64)
    })
    value = null
    return result
  } finally {
    clear(input)
    clearAdvertisement(value)
    if (object) {
      clear(object.body)
      clear(object.authSuffix)
    }
  }
}

function rawAdvertisementDigest(encoded) {
  return digest([CAPABILITY_DIGEST_DOMAIN, encoded])
}

function digestRelayCapabilityAdvertisement(encoded, options) {
  const decoded = decodeRelayCapabilityAdvertisement(encoded, options)
  try {
    return rawAdvertisementDigest(encoded)
  } finally {
    clearAdvertisement(decoded)
  }
}

function challengeBody(challenge) {
  let object = null
  try {
    object = decodeM3Object(challenge)
  } catch {
    authentication()
  }
  if (object.messageId !== M3_MESSAGE_ID.ACTIVE_CHALLENGE_V1 || object.body.byteLength !== 176) {
    clear(object.body)
    clear(object.authSuffix)
    authentication()
  }
  clear(object.authSuffix)
  return object.body
}

function responseObject(response) {
  let object = null
  try {
    object = decodeM3Object(response)
  } catch {
    authentication()
  }
  if (
    object.messageId !== M3_MESSAGE_ID.ACTIVE_CHALLENGE_RESPONSE_V1 ||
    object.body.byteLength !== 272
  ) {
    clear(object.body)
    clear(object.authSuffix)
    authentication()
  }
  return object
}

function activeProof(shared, bodyWithoutProof) {
  const prefix = allocate(2 + ACTIVE_PROOF_DOMAIN.byteLength)
  writeUint16(prefix, ACTIVE_PROOF_DOMAIN.byteLength, 0)
  set(prefix, ACTIVE_PROOF_DOMAIN, 2)
  try {
    return keyedHash(shared, [prefix, bodyWithoutProof])
  } finally {
    clear(prefix)
  }
}

function readCapsQuery(value, includeCookie) {
  exactObject(value, includeCookie ? CAPS_RETRY_FIELDS : CAPS_QUERY_FIELDS)
  let sourceEndpoint = null
  let randomTarget = null
  let queryNonce = null
  let returnRoutabilityCookie = null
  let advertisement = null
  try {
    sourceEndpoint = decodeCanonicalEndpoint(dataProperty(value, 'sourceEndpoint'))
    const requestedCapabilityMask = dataProperty(value, 'requestedCapabilityMask')
    randomTarget = copy(dataProperty(value, 'randomTarget'), 32)
    queryNonce = copy(dataProperty(value, 'queryNonce'), 32)
    const maximumResults = dataProperty(value, 'maximumResults')
    if (
      (requestedCapabilityMask !== 1 && requestedCapabilityMask !== 3) ||
      !Number.isSafeInteger(maximumResults) ||
      maximumResults < 1 ||
      maximumResults > MAX_CAPABILITY_ADVERTISEMENTS
    ) {
      incompatible()
    }
    let cookieExpiresAtMs
    if (includeCookie) {
      cookieExpiresAtMs = dataProperty(value, 'cookieExpiresAtMs')
      returnRoutabilityCookie = copy(dataProperty(value, 'returnRoutabilityCookie'), 32)
      advertisement = copy(dataProperty(value, 'advertisement'))
      if (!uint64(cookieExpiresAtMs)) incompatible()
    }
    const query = {
      sourceEndpoint,
      requestedCapabilityMask,
      randomTarget,
      queryNonce,
      maximumResults
    }
    if (includeCookie) {
      query.cookieExpiresAtMs = cookieExpiresAtMs
      query.returnRoutabilityCookie = returnRoutabilityCookie
      query.advertisement = advertisement
    }
    sourceEndpoint = null
    randomTarget = null
    queryNonce = null
    returnRoutabilityCookie = null
    advertisement = null
    return query
  } finally {
    clear(sourceEndpoint)
    clear(randomTarget)
    clear(queryNonce)
    clear(returnRoutabilityCookie)
    clear(advertisement)
  }
}

function clearCapsQuery(query) {
  if (!query) return
  clear(query.sourceEndpoint)
  clear(query.randomTarget)
  clear(query.queryNonce)
  clear(query.returnRoutabilityCookie)
  clear(query.advertisement)
}

function capsCookieInput(query) {
  const output = allocate(2 + CAPS_COOKIE_DOMAIN.byteLength + 19 + 4 + 32 + 32 + 1 + 8)
  let offset = 0
  writeUint16(output, CAPS_COOKIE_DOMAIN.byteLength, offset)
  offset += 2
  set(output, CAPS_COOKIE_DOMAIN, offset)
  offset += CAPS_COOKIE_DOMAIN.byteLength
  set(output, query.sourceEndpoint, offset)
  offset += 19
  writeUint32(output, query.requestedCapabilityMask, offset)
  offset += 4
  set(output, query.randomTarget, offset)
  offset += 32
  set(output, query.queryNonce, offset)
  offset += 32
  output[offset++] = query.maximumResults
  writeUint64(output, query.cookieExpiresAtMs, offset)
  return output
}

function sameCapsQuery(left, right) {
  return (
    equal(left.sourceEndpoint, right.sourceEndpoint) &&
    left.requestedCapabilityMask === right.requestedCapabilityMask &&
    equal(left.randomTarget, right.randomTarget) &&
    equal(left.queryNonce, right.queryNonce) &&
    left.maximumResults === right.maximumResults &&
    left.cookieExpiresAtMs === right.cookieExpiresAtMs &&
    equal(left.returnRoutabilityCookie, right.returnRoutabilityCookie)
  )
}

function unrefTimer(timer) {
  try {
    if (timer && typeof timer.unref === 'function') timer.unref()
  } catch {}
}

const responderStates = new WeakMap()
const responderObservations = new WeakMap()

function observeResponderClear(state, type, reason, buffers) {
  let observation = null
  try {
    observation = responderObservations.get(state)
    if (!observation) return
    if (observation.events.length >= MAX_RESPONDER_OBSERVATION_EVENTS) {
      if (observation.droppedEvents < MAX_RESPONDER_OBSERVATION_DROPS) observation.droppedEvents++
      return
    }
    const retained = []
    for (let index = 0; index < buffers.length; index++) {
      const value = buffers[index]
      if (bufferLength(value) >= 0) reflectApply(arrayPush, retained, [value])
    }
    objectFreeze(retained)
    const event = objectFreeze({ type, reason, buffers: retained })
    reflectApply(arrayPush, observation.events, [event])
  } catch {
    if (observation && observation.droppedEvents < MAX_RESPONDER_OBSERVATION_DROPS) {
      observation.droppedEvents++
    }
  }
}

function clearResponderBinding(state, bindingState, reason) {
  const buffers = [
    bindingState.query.sourceEndpoint,
    bindingState.query.randomTarget,
    bindingState.query.queryNonce,
    bindingState.query.returnRoutabilityCookie,
    bindingState.query.advertisement,
    bindingState.advertisementDigest
  ]
  clearCapsQuery(bindingState.query)
  clear(bindingState.advertisementDigest)
  observeResponderClear(state, 'binding-cleared', reason, buffers)
}

function clearResponderSecret(state, secret, reason) {
  if (!secret) return
  clear(secret)
  observeResponderClear(state, 'secret-cleared', reason, [secret])
}

function cancelResponderTimer(token) {
  if (!token || token.cancelled) return
  token.cancelled = true
  if (token.handle === null) return
  try {
    token.clearTimer(token.handle)
  } catch {}
}

function destroyResponder(state) {
  if (!state || state.destroyed) return
  state.destroyed = true
  state.staging = false
  state.stagingTransaction = null
  state.generation++
  const rotationTimer = state.rotationTimer
  const priorEraseTimer = state.priorEraseTimer
  const currentSecret = state.currentSecret && state.currentSecret.secret
  const priorSecret = state.priorSecret && state.priorSecret.secret
  const bindings = [...state.cache.values()]
  state.rotationTimer = null
  state.priorEraseTimer = null
  state.currentSecret = null
  state.priorSecret = null
  state.bindings.clear()
  state.cache.clear()
  state.completed = null
  state.now = null
  state.setTimer = null
  state.clearTimer = null
  state.crypto = null
  cancelResponderTimer(rotationTimer)
  cancelResponderTimer(priorEraseTimer)
  clearResponderSecret(state, currentSecret, 'destroy-current')
  clearResponderSecret(state, priorSecret, 'destroy-prior')
  for (const bindingState of bindings) clearResponderBinding(state, bindingState, 'destroy')
}

function assertResponderLive(state) {
  if (!state || state.destroyed) destroyed()
}

function responderState(authority) {
  const state = responderStates.get(authority)
  assertResponderLive(state)
  if (state.staging) {
    destroyResponder(state)
    destroyed()
  }
  return state
}

function beginResponderTimerStaging(state, generation) {
  const transaction = { generation }
  state.staging = true
  state.stagingTransaction = transaction
  return transaction
}

function validStagedResponderTimer(state, token, transaction, kind) {
  return (
    token !== null &&
    token.kind === kind &&
    token.transaction === transaction &&
    token.generation === transaction.generation &&
    !token.published &&
    !token.cancelled &&
    !token.firedDuringInstall &&
    !state.destroyed &&
    state.staging &&
    state.stagingTransaction === transaction
  )
}

function stageResponderTimer(state, transaction, kind, delay, run) {
  const token = {
    kind,
    transaction,
    generation: transaction.generation,
    handle: null,
    clearTimer: state.clearTimer,
    published: false,
    cancelled: false,
    firedDuringInstall: false
  }
  const callback = () => {
    if (!token.published) {
      token.firedDuringInstall = true
      return
    }
    if (token.cancelled || state.destroyed || state.generation !== token.generation) return
    if (kind === 'rotation') {
      if (state.rotationTimer !== token) return
      state.rotationTimer = null
    } else {
      if (state.priorEraseTimer !== token) return
      state.priorEraseTimer = null
    }
    token.cancelled = true
    try {
      run()
    } catch {
      destroyResponder(state)
    }
  }
  try {
    token.handle = state.setTimer(callback, delay)
    if (!validStagedResponderTimer(state, token, transaction, kind))
      throw new Error('timer staging')
    unrefTimer(token.handle)
    if (!validStagedResponderTimer(state, token, transaction, kind))
      throw new Error('timer staging')
    return token
  } catch (err) {
    cancelResponderTimer(token)
    throw err
  }
}

function expireResponderBindings(state, now) {
  for (const [cacheKey, bindingState] of state.cache) {
    if (bindingState.query.cookieExpiresAtMs > now) continue
    state.cache.delete(cacheKey)
    state.bindings.delete(bindingState.binding)
    clearResponderBinding(state, bindingState, 'expired')
  }
}

function expireResponderPrior(state, now) {
  if (!state.priorSecret || state.priorSecret.expiresAt > now) return
  const prior = state.priorSecret
  const timer = state.priorEraseTimer
  state.priorSecret = null
  state.priorEraseTimer = null
  cancelResponderTimer(timer)
  clearResponderSecret(state, prior.secret, 'prior-expired')
  assertResponderLive(state)
}

function sampleResponderNow(state) {
  const now = state.now()
  assertResponderLive(state)
  if (!uint64(now)) {
    destroyResponder(state)
    incompatible()
  }
  return now
}

function runResponderRotation(authority, state, now) {
  assertResponderLive(state)
  if (state.staging) {
    destroyResponder(state)
    destroyed()
  }
  expireResponderBindings(state, now)
  expireResponderPrior(state, now)
  if (now < state.rotationDeadline) {
    if (state.rotationTimer !== null) return
    const transaction = beginResponderTimerStaging(state, state.generation)
    let timer = null
    try {
      timer = stageResponderTimer(
        state,
        transaction,
        'rotation',
        Number(state.rotationDeadline - now),
        () => runResponderRotation(authority, state, sampleResponderNow(state))
      )
      if (!validStagedResponderTimer(state, timer, transaction, 'rotation'))
        throw new Error('timer staging')
      state.rotationTimer = timer
      timer.published = true
      state.staging = false
      state.stagingTransaction = null
      return
    } catch (err) {
      cancelResponderTimer(timer)
      destroyResponder(state)
      throw err
    }
  }

  const generation = state.generation + 1
  const transaction = beginResponderTimerStaging(state, generation)
  const oldRotationTimer = state.rotationTimer
  const oldPriorTimer = state.priorEraseTimer
  const oldPrior = state.priorSecret
  state.rotationTimer = null
  state.priorEraseTimer = null
  state.priorSecret = null
  if (oldPrior) clearResponderSecret(state, oldPrior.secret, 'rotation-old-prior')
  cancelResponderTimer(oldRotationTimer)
  cancelResponderTimer(oldPriorTimer)
  let randomScratch = null
  let nextSecret = null
  let priorTimer = null
  let rotationTimer = null
  try {
    assertResponderLive(state)
    randomScratch = state.crypto.randomBytes(32)
    assertResponderLive(state)
    if (!state.staging) destroyed()
    nextSecret = copy(randomScratch, 32)
    const elapsed = now - state.rotationDeadline
    const skipped = elapsed / CAPS_COOKIE_ROTATION
    const rotationAt = state.rotationDeadline + skipped * CAPS_COOKIE_ROTATION
    const priorExpiresAt = state.rotationDeadline + CAPS_COOKIE_LIFETIME
    const retainPrior = skipped === 0n && now < priorExpiresAt
    const prior = retainPrior
      ? { secret: state.currentSecret.secret, expiresAt: priorExpiresAt }
      : null
    if (prior) {
      priorTimer = stageResponderTimer(
        state,
        transaction,
        'prior',
        Number(priorExpiresAt - now),
        () => {
          if (state.priorSecret !== prior) return
          state.priorSecret = null
          clearResponderSecret(state, prior.secret, 'prior-expired')
        }
      )
    }
    const rotationDeadline = rotationAt + CAPS_COOKIE_ROTATION
    rotationTimer = stageResponderTimer(
      state,
      transaction,
      'rotation',
      Number(rotationDeadline > now ? rotationDeadline - now : 0n),
      () => runResponderRotation(authority, state, sampleResponderNow(state))
    )
    assertResponderLive(state)
    if (
      (priorTimer && !validStagedResponderTimer(state, priorTimer, transaction, 'prior')) ||
      !validStagedResponderTimer(state, rotationTimer, transaction, 'rotation')
    ) {
      throw new Error('timer staging')
    }
    const oldCurrent = state.currentSecret.secret
    state.currentSecret = { secret: nextSecret, rotatedAt: rotationAt }
    nextSecret = null
    state.priorSecret = prior
    state.priorEraseTimer = priorTimer
    state.rotationTimer = rotationTimer
    state.rotationDeadline = rotationDeadline
    state.generation = generation
    if (priorTimer) priorTimer.published = true
    rotationTimer.published = true
    state.staging = false
    state.stagingTransaction = null
    if (!retainPrior) clearResponderSecret(state, oldCurrent, 'rotation-stale-current')
  } catch (err) {
    cancelResponderTimer(priorTimer)
    cancelResponderTimer(rotationTimer)
    clear(nextSecret)
    destroyResponder(state)
    throw err
  } finally {
    clear(randomScratch)
  }
}

function responderCookie(secret, query) {
  const input = capsCookieInput(query)
  try {
    return keyedHash(secret, [input])
  } finally {
    clear(input)
  }
}

class ActiveChallengeResponderAuthority {
  constructor(options = {}) {
    const allowed = ['now', 'crypto', 'setTimeout', 'clearTimeout', 'maxBindings']
    const values = {}
    try {
      if (options === null || typeof options !== 'object' || arrayIsArray(options)) incompatible()
      const prototype = objectGetPrototypeOf(options)
      if (prototype !== objectPrototype && prototype !== null) incompatible()
      if (objectGetOwnPropertySymbols(options).length !== 0) incompatible()
      for (const name of objectGetOwnPropertyNames(options)) {
        if (!reflectApply(arrayIncludes, allowed, [name])) incompatible()
        const descriptor = objectGetOwnPropertyDescriptor(options, name)
        if (!descriptor || !reflectApply(objectHasOwnProperty, descriptor, ['value']))
          incompatible()
        values[name] = descriptor.value
      }
    } catch (err) {
      if (err instanceof PrivateRouteError) throw err
      incompatible()
    }
    const now = values.now
    const crypto = values.crypto === undefined ? cryptoSuite : values.crypto
    const setTimer = values.setTimeout === undefined ? globalThis.setTimeout : values.setTimeout
    const clearTimer =
      values.clearTimeout === undefined ? globalThis.clearTimeout : values.clearTimeout
    const maxBindings = values.maxBindings === undefined ? MAX_CAPS_BINDINGS : values.maxBindings
    const randomBytes = dataProperty(crypto, 'randomBytes')
    const keyAgreement = dataProperty(crypto, 'keyAgreement')
    const sign = dataProperty(crypto, 'sign')
    if (
      typeof now !== 'function' ||
      typeof randomBytes !== 'function' ||
      typeof keyAgreement !== 'function' ||
      typeof sign !== 'function' ||
      typeof setTimer !== 'function' ||
      typeof clearTimer !== 'function' ||
      !Number.isSafeInteger(maxBindings) ||
      maxBindings < 1 ||
      maxBindings > MAX_CAPS_BINDINGS
    ) {
      incompatible()
    }
    const current = now()
    if (!uint64(current)) incompatible()
    const initialTransaction = { generation: 0 }
    const state = {
      now,
      setTimer,
      clearTimer,
      crypto: { randomBytes, keyAgreement, sign },
      currentSecret: null,
      priorSecret: null,
      bindings: new Map(),
      cache: new Map(),
      completed: new WeakSet(),
      maxBindings,
      destroyed: false,
      staging: true,
      stagingTransaction: initialTransaction,
      generation: 0,
      rotationTimer: null,
      priorEraseTimer: null,
      rotationDeadline: current + CAPS_COOKIE_ROTATION
    }
    responderStates.set(this, state)
    let randomScratch = null
    let rotationTimer = null
    try {
      randomScratch = randomBytes(32)
      assertResponderLive(state)
      state.currentSecret = { secret: copy(randomScratch, 32), rotatedAt: current }
      rotationTimer = stageResponderTimer(
        state,
        initialTransaction,
        'rotation',
        Number(CAPS_COOKIE_ROTATION),
        () => runResponderRotation(this, state, sampleResponderNow(state))
      )
      if (!validStagedResponderTimer(state, rotationTimer, initialTransaction, 'rotation'))
        throw new Error('timer staging')
      state.rotationTimer = rotationTimer
      rotationTimer.published = true
      state.staging = false
      state.stagingTransaction = null
      objectFreeze(this)
    } catch (err) {
      cancelResponderTimer(rotationTimer)
      destroyResponder(state)
      throw err
    } finally {
      clear(randomScratch)
    }
  }

  issueCookie(value) {
    const state = responderState(this)
    const now = sampleResponderNow(state)
    runResponderRotation(this, state, now)
    assertResponderLive(state)
    const query = readCapsQuery(value, false)
    try {
      query.cookieExpiresAtMs = now + CAPS_COOKIE_LIFETIME
      return objectFreeze({
        cookieExpiresAtMs: query.cookieExpiresAtMs,
        returnRoutabilityCookie: responderCookie(state.currentSecret.secret, query)
      })
    } finally {
      clearCapsQuery(query)
    }
  }

  admitCapsRetry(value) {
    const state = responderState(this)
    const now = sampleResponderNow(state)
    runResponderRotation(this, state, now)
    assertResponderLive(state)
    const query = readCapsQuery(value, true)
    let expected = null
    let advertisementDigest = null
    try {
      if (query.cookieExpiresAtMs <= now || query.cookieExpiresAtMs > now + CAPS_COOKIE_LIFETIME) {
        authentication()
      }
      expected = responderCookie(state.currentSecret.secret, query)
      let valid = equal(expected, query.returnRoutabilityCookie)
      clear(expected)
      expected = null
      if (!valid && state.priorSecret && state.priorSecret.expiresAt > now) {
        expected = responderCookie(state.priorSecret.secret, query)
        valid = equal(expected, query.returnRoutabilityCookie)
      }
      if (!valid) authentication()
      const advertisement = decodeRelayCapabilityAdvertisement(query.advertisement, { now })
      clearAdvertisement(advertisement)
      advertisementDigest = rawAdvertisementDigest(query.advertisement)
      const cacheKey = b4aToString(query.returnRoutabilityCookie, 'hex')
      const existing = state.cache.get(cacheKey)
      if (existing) {
        const exact =
          sameCapsQuery(existing.query, query) &&
          equal(existing.query.advertisement, query.advertisement) &&
          equal(existing.advertisementDigest, advertisementDigest)
        clearCapsQuery(query)
        clear(advertisementDigest)
        if (!exact) authentication()
        if (existing.used) replay()
        return existing.binding
      }
      if (state.cache.size >= state.maxBindings) throw PrivateRouteError.ERR_BUSY()
      const binding = objectFreeze({})
      const bindingState = { query, advertisementDigest, binding, cacheKey, used: false }
      state.bindings.set(binding, bindingState)
      state.cache.set(cacheKey, bindingState)
      return binding
    } catch (err) {
      clearCapsQuery(query)
      clear(advertisementDigest)
      throw err
    } finally {
      clear(expected)
    }
  }

  respond(binding, challenge, options) {
    const responder = responderState(this)
    if (binding !== null && typeof binding === 'object' && responder.completed.has(binding))
      replay()
    const state = responder.bindings.get(binding)
    if (!state) authentication()
    exactObject(options, RESPOND_FIELDS)
    const now = sampleResponderNow(responder)
    runResponderRotation(this, responder, now)
    if (!responder.bindings.has(binding) || state.query.cookieExpiresAtMs <= now) authentication()
    let sourceEndpoint = null
    let advertisement = null
    let body = null
    let advert = null
    let advertDigest = null
    let randomScratch = null
    let responderNonce = null
    let routeSecret = null
    let identitySecret = null
    let shared = null
    let proof = null
    let responseBody = null
    let input = null
    let signature = null
    try {
      sourceEndpoint = decodeCanonicalEndpoint(dataProperty(options, 'sourceEndpoint'))
      advertisement = copy(dataProperty(options, 'advertisement'))
      body = challengeBody(challenge)
      if (
        !equal(sourceEndpoint, state.query.sourceEndpoint) ||
        !equal(advertisement, state.query.advertisement) ||
        !equal(subarray(body, 0, 32), state.advertisementDigest) ||
        readUint64(body, 96) <= now ||
        readUint64(body, 96) > now + ACTIVE_CHALLENGE_TIMEOUT ||
        !equal(subarray(body, 104, 136), state.query.queryNonce) ||
        readUint64(body, 136) !== state.query.cookieExpiresAtMs ||
        !equal(subarray(body, 144, 176), state.query.returnRoutabilityCookie)
      ) {
        authentication()
      }
      advert = decodeRelayCapabilityAdvertisement(advertisement, { now })
      advertDigest = rawAdvertisementDigest(advertisement)
      routeSecret = copy(dataProperty(options, 'routeEncryptionSecretKey'), 32)
      identitySecret = copy(dataProperty(options, 'identitySecretKey'), 64)
      state.used = true
      responder.bindings.delete(binding)
      responder.completed.add(binding)
      randomScratch = responder.crypto.randomBytes(32)
      responderNonce = copy(randomScratch, 32)
      clear(randomScratch)
      randomScratch = null
      shared = responder.crypto.keyAgreement(routeSecret, subarray(body, 64, 96))
      if (equal(shared, ZERO_32)) authentication()
      responseBody = allocate(272)
      set(responseBody, advertDigest, 0)
      set(responseBody, advert.relayIdentity, 32)
      set(responseBody, subarray(body, 32, 96), 64)
      set(responseBody, responderNonce, 128)
      set(responseBody, subarray(body, 96, 176), 160)
      proof = activeProof(shared, subarray(responseBody, 0, 240))
      set(responseBody, proof, 240)
      input = signatureInput(
        ACTIVE_RESPONSE_DOMAIN,
        M3_MESSAGE_ID.ACTIVE_CHALLENGE_RESPONSE_V1,
        responseBody
      )
      signature = responder.crypto.sign(input, identitySecret)
      const response = encodeM3Object({
        messageId: M3_MESSAGE_ID.ACTIVE_CHALLENGE_RESPONSE_V1,
        body: responseBody,
        authSuffix: signature
      })
      return response
    } catch (err) {
      if (err instanceof PrivateRouteError && err.code.startsWith('ERR_')) throw err
      authentication()
    } finally {
      clear(sourceEndpoint)
      clear(advertisement)
      clear(body)
      clearAdvertisement(advert)
      clear(advertDigest)
      clear(randomScratch)
      clear(responderNonce)
      clear(routeSecret)
      clear(identitySecret)
      clear(shared)
      clear(proof)
      clear(responseBody)
      clear(input)
      clear(signature)
    }
  }

  destroy() {
    destroyResponder(responderStates.get(this))
  }
}

objectFreeze(ActiveChallengeResponderAuthority.prototype)

function createActiveChallengeResponderAuthority(options) {
  return new ActiveChallengeResponderAuthority(options)
}

// Test-only deep import. This is not an access-control boundary: it exposes only
// non-authorizing metadata and buffers after ownership was detached and zeroized.
function observeActiveChallengeResponderForTests(authority) {
  const state = responderStates.get(authority)
  if (!state) throw new TypeError('unknown responder authority')
  let observation = responderObservations.get(state)
  if (!observation) {
    observation = { events: [], droppedEvents: 0 }
    responderObservations.set(state, observation)
  }
  const events = observation.events
  const droppedEvents = observation.droppedEvents
  observation.events = []
  observation.droppedEvents = 0
  objectFreeze(events)
  return objectFreeze({
    destroyed: state.destroyed,
    staging: state.staging,
    rotationScheduled: state.rotationTimer !== null,
    priorEraseScheduled: state.priorEraseTimer !== null,
    bindingCount: state.cache.size,
    events,
    droppedEvents
  })
}

function clearProjection(projection) {
  if (!projection) return
  clear(projection.canonicalBytes)
  clear(projection.digest)
  clear(projection.identity)
  clear(projection.canonicalEndpointBytes)
  clear(projection.routePublicKey)
}

function projectionFor(record) {
  let canonicalBytes = null
  let digest = null
  let identity = null
  let canonicalEndpointBytes = null
  let routePublicKey = null
  try {
    canonicalBytes = copy(record.encoded)
    digest = copy(record.digest, 32)
    identity = copy(record.advertisement.relayIdentity, 32)
    canonicalEndpointBytes = copy(record.advertisement.reachableEndpoint, 19)
    routePublicKey = copy(record.advertisement.routeEncryptionPublicKey, 32)
    const projection = objectFreeze({
      canonicalBytes,
      digest,
      identity,
      canonicalEndpointBytes,
      routePublicKey,
      role: roleForIdentity(record.advertisement.relayIdentity),
      capabilityMask: record.advertisement.capabilityMask,
      epoch: record.advertisement.epoch,
      issuedAt: record.advertisement.issuedAtMs,
      expiresAt: record.advertisement.expiresAtMs
    })
    canonicalBytes = null
    digest = null
    identity = null
    canonicalEndpointBytes = null
    routePublicKey = null
    return projection
  } finally {
    clear(canonicalBytes)
    clear(digest)
    clear(identity)
    clear(canonicalEndpointBytes)
    clear(routePublicKey)
  }
}

function publishProjection(state, record, projection) {
  while (record.projections.size >= MAX_CAPABILITY_ADVERTISEMENTS) {
    const oldest = record.projections.values().next().value
    record.projections.delete(oldest)
    state.projections.delete(oldest)
    projectionOwners.delete(oldest)
    for (const capability of record.sendAuthorities) {
      const authorityState = sendAuthorityStates.get(capability)
      if (authorityState && authorityState.projection === oldest) {
        clearSendAuthority(authorityState)
      }
    }
    clearProjection(oldest)
  }
  projectionOwners.set(projection, { state, record })
  record.projections.add(projection)
  state.projections.set(projection, record)
}

function clearSendAuthority(authorityState) {
  if (!authorityState) return
  sendAuthorityStates.delete(authorityState.capability)
  if (authorityState.record) authorityState.record.sendAuthorities.delete(authorityState.capability)
  clear(authorityState.sourceEndpoint)
  clear(authorityState.queryNonce)
  clear(authorityState.returnRoutabilityCookie)
  clear(authorityState.advertisementDigest)
  clear(authorityState.relayIdentity)
  authorityState.state = null
  authorityState.record = null
  authorityState.projection = null
  authorityState.send = null
}

function consumeSendAuthority(authorityState) {
  sendAuthorityStates.delete(authorityState.capability)
  consumedSendAuthorities.add(authorityState.capability)
  authorityState.record.sendAuthorities.delete(authorityState.capability)
}

function clearRecord(state, record, error = PrivateRouteError.ERR_AUTHENTICATION()) {
  if (!record) return
  for (const pending of state.pending) {
    if (pending.record !== record) continue
    state.pending.delete(pending)
    if (pending.reject) pending.reject(error)
    clearPending(pending)
  }
  for (const capability of record.sendAuthorities) {
    clearSendAuthority(sendAuthorityStates.get(capability))
  }
  record.sendAuthorities.clear()
  clear(record.encoded)
  clear(record.digest)
  clearAdvertisement(record.advertisement)
  for (const projection of record.projections) {
    state.projections.delete(projection)
    projectionOwners.delete(projection)
    clearProjection(projection)
  }
  record.projections.clear()
}

function ownsRecord(state, record) {
  for (const current of state.records.values()) {
    if (current === record) return true
  }
  return false
}

function clearHistory(history) {
  if (!history) return
  clear(history.encoded)
  clear(history.digest)
  for (const key of history.routeKeys) clear(key)
  history.routeKeys.length = 0
}

function poisonIdentity(state, identity, history, record) {
  history.poisoned = true
  if (record) {
    if (record.timer !== null) {
      try {
        state.clearTimer(record.timer)
      } catch {}
      record.timer = null
    }
    clearRecord(state, record, PrivateRouteError.ERR_AUTHENTICATION())
    state.records.delete(identity)
  }
  clearHistory(history)
  state.quarantine.delete(identity)
}

function clearPending(pending) {
  if (!pending) return
  clear(pending.challenge)
  clear(pending.ephemeralSecretKey)
  clear(pending.outboundMessage)
  clearSendAuthority(pending.authorityState)
  pending.outboundMessage = null
  pending.authorityState = null
  if (pending.timer !== null) {
    try {
      pending.state.clearTimer(pending.timer)
    } catch {}
  }
  pending.timer = null
  pending.reject = null
}

function invalidateAll(state, notify, error) {
  state.poisoned = true
  for (const record of state.records.values()) {
    if (record.timer !== null) {
      try {
        state.clearTimer(record.timer)
      } catch {}
      record.timer = null
    }
    clearRecord(state, record, error)
  }
  for (const history of state.histories.values()) clearHistory(history)
  for (const pending of state.pending) {
    if (pending.reject) pending.reject(error)
    clearPending(pending)
  }
  state.records.clear()
  state.histories.clear()
  state.quarantine.clear()
  state.projections.clear()
  state.pending.clear()
  state.accepting.clear()
  state.responseTombstones.clear()
  if (notify && !state.invalidated) {
    state.invalidated = true
    try {
      state.onInvalidated()
    } catch {}
  }
}

function sampleWall(state) {
  const now = state.wallNow()
  if (!uint64(now)) incompatible()
  if (state.poisoned) incompatible()
  if (state.lastAcceptedWallNow !== null && now + MAX_FUTURE_SKEW < state.lastAcceptedWallNow) {
    invalidateAll(state, true, PrivateRouteError.ERR_INCOMPATIBLE_RELAY())
    incompatible()
  }
  if (state.lastAcceptedWallNow === null || now > state.lastAcceptedWallNow) {
    state.lastAcceptedWallNow = now
  }
  expireRecords(state, now)
  pruneResponseTombstones(state, now)
  return now
}

function sampleMonotonic(state) {
  const now = state.monotonicNow()
  if (!uint64(now)) incompatible()
  return now
}

function expireRecords(state, now) {
  for (const [identity, record] of state.records) {
    if (record.advertisement.expiresAtMs > now) continue
    const timer = record.timer
    record.timer = null
    state.records.delete(identity)
    clearRecord(state, record, PrivateRouteError.ERR_INCOMPATIBLE_RELAY())
    if (timer !== null) {
      try {
        state.clearTimer(timer)
      } catch {}
    }
  }
  for (const [identity, expiresAt] of state.quarantine) {
    if (expiresAt <= now) state.quarantine.delete(identity)
  }
}

function pruneResponseTombstones(state, now) {
  for (const [responseDigest, expiresAt] of state.responseTombstones) {
    if (expiresAt <= now) state.responseTombstones.delete(responseDigest)
  }
}

function scheduleRecordExpiry(state, identity, record, now, acceptance = null) {
  let timer = null
  let installing = true
  let firedDuringInstallation = false
  try {
    timer = state.setTimer(
      () => {
        if (installing || (acceptance !== null && acceptance.phase !== 'published')) {
          firedDuringInstallation = true
          return
        }
        record.timer = null
        if (state.destroyed) return
        let current
        try {
          current = sampleWall(state)
        } catch {
          return
        }
        if (record.advertisement.expiresAtMs > current) {
          scheduleRecordExpiry(state, identity, record, current)
          return
        }
        if (state.records.get(identity) === record) {
          state.records.delete(identity)
          clearRecord(state, record, PrivateRouteError.ERR_INCOMPATIBLE_RELAY())
        }
      },
      Number(record.advertisement.expiresAtMs - now)
    )
    record.timer = timer
    installing = false
    unrefTimer(timer)
    if (firedDuringInstallation) incompatible()
  } catch (err) {
    installing = false
    if (timer !== null) {
      try {
        state.clearTimer(timer)
      } catch {}
    }
    record.timer = null
    throw err
  }
}

function ensureState(verifier) {
  const state = verifierStates.get(verifier)
  if (!state || state.destroyed) destroyed()
  return state
}

function createActiveChallengeSendAuthority(options) {
  exactObject(options, SEND_AUTHORITY_FIELDS)
  const binding = dataProperty(options, 'capsBinding')
  const send = dataProperty(options, 'send')
  exactObject(binding, SEND_CAPS_BINDING_FIELDS)
  if (typeof send !== 'function') incompatible()
  const advertisement = dataProperty(binding, 'advertisement')
  const owner =
    advertisement !== null && typeof advertisement === 'object'
      ? projectionOwners.get(advertisement)
      : null
  if (
    !owner ||
    owner.state.destroyed ||
    owner.state.projections.get(advertisement) !== owner.record
  ) {
    authentication()
  }
  const now = sampleWall(owner.state)
  if (owner.state.projections.get(advertisement) !== owner.record) authentication()
  const cookieExpiresAtMs = dataProperty(binding, 'cookieExpiresAtMs')
  if (
    !uint64(cookieExpiresAtMs) ||
    cookieExpiresAtMs <= now ||
    cookieExpiresAtMs > now + CAPS_COOKIE_LIFETIME
  ) {
    authentication()
  }
  let sourceEndpoint = null
  let queryNonce = null
  let returnRoutabilityCookie = null
  let advertisementDigest = null
  let relayIdentity = null
  try {
    sourceEndpoint = decodeCanonicalEndpoint(dataProperty(binding, 'sourceEndpoint'))
    queryNonce = copy(dataProperty(binding, 'queryNonce'), 32)
    returnRoutabilityCookie = copy(dataProperty(binding, 'returnRoutabilityCookie'), 32)
    advertisementDigest = copy(dataProperty(binding, 'advertisementDigest'), 32)
    relayIdentity = copy(dataProperty(binding, 'relayIdentity'), 32)
    if (!equal(advertisementDigest, owner.record.digest)) authentication()
    if (!equal(relayIdentity, owner.record.advertisement.relayIdentity)) authentication()
    const capability = objectFreeze({})
    const authorityState = {
      capability,
      state: owner.state,
      record: owner.record,
      projection: advertisement,
      sourceEndpoint,
      queryNonce,
      cookieExpiresAtMs,
      returnRoutabilityCookie,
      advertisementDigest,
      relayIdentity,
      send
    }
    sendAuthorityStates.set(capability, authorityState)
    owner.record.sendAuthorities.add(capability)
    sourceEndpoint = null
    queryNonce = null
    returnRoutabilityCookie = null
    advertisementDigest = null
    relayIdentity = null
    return capability
  } finally {
    clear(sourceEndpoint)
    clear(queryNonce)
    clear(returnRoutabilityCookie)
    clear(advertisementDigest)
    clear(relayIdentity)
  }
}

class RelayCapabilityVerifier {
  constructor(options) {
    exactObject(options, CONSTRUCTOR_FIELDS)
    const wallNow = dataProperty(options, 'wallNow')
    const monotonicNow = dataProperty(options, 'monotonicNow')
    const setTimer = dataProperty(options, 'setTimer')
    const clearTimer = dataProperty(options, 'clearTimer')
    const onInvalidated = dataProperty(options, 'onInvalidated')
    if (
      typeof wallNow !== 'function' ||
      typeof monotonicNow !== 'function' ||
      typeof setTimer !== 'function' ||
      typeof clearTimer !== 'function' ||
      typeof onInvalidated !== 'function'
    ) {
      incompatible()
    }
    verifierStates.set(this, {
      wallNow,
      monotonicNow,
      setTimer,
      clearTimer,
      onInvalidated,
      lastAcceptedWallNow: null,
      records: new Map(),
      histories: new Map(),
      quarantine: new Map(),
      projections: new Map(),
      pending: new Set(),
      accepting: new Map(),
      responseTombstones: new Map(),
      invalidated: false,
      poisoned: false,
      destroyed: false
    })
  }

  accept(encoded, options) {
    const state = ensureState(this)
    exactObject(options, ACCEPT_FIELDS)
    const expectedRole = dataProperty(options, 'expectedRole')
    const expectedCapabilityMask = dataProperty(options, 'expectedCapabilityMask')
    if (
      (expectedRole !== ROLE.SAFETY && expectedRole !== ROLE.PRIVATE) ||
      (expectedCapabilityMask !== 1 && expectedCapabilityMask !== 3)
    ) {
      incompatible()
    }
    const now = sampleWall(state)
    let advertisement = null
    let bytes = null
    let advertisementDigest = null
    let identity = null
    let record = null
    let projection = null
    let nextHistory = null
    let acceptance = null
    let published = false
    try {
      bytes = copy(encoded)
      advertisement = decodeRelayCapabilityAdvertisement(bytes, { now })
      const actualRole = roleForIdentity(advertisement.relayIdentity)
      if (actualRole !== expectedRole || advertisement.capabilityMask !== expectedCapabilityMask) {
        incompatible()
      }
      advertisementDigest = rawAdvertisementDigest(bytes)
      identity = b4aToString(advertisement.relayIdentity, 'hex')
      if (state.accepting.has(identity)) authentication()
      const quarantinedUntil = state.quarantine.get(identity)
      if (quarantinedUntil !== undefined && quarantinedUntil > now) authentication()
      const history = state.histories.get(identity)
      const current = state.records.get(identity)
      if (history) {
        if (history.poisoned) authentication()
        if (advertisement.epoch < history.epoch) replay()
        if (advertisement.epoch === history.epoch) {
          if (equal(advertisementDigest, history.digest)) {
            const source = current || {
              advertisement,
              encoded: bytes,
              digest: advertisementDigest,
              projections: new Set(),
              sendAuthorities: new Set(),
              timer: null
            }
            projection = projectionFor(source)
            publishProjection(state, source, projection)
            const result = projection
            projection = null
            return result
          }
          const newRouteKey = !reflectApply(arraySome, history.routeKeys, [
            (key) => equal(key, advertisement.routeEncryptionPublicKey)
          ])
          if (newRouteKey && history.routeKeys.length === MAX_ROUTE_KEY_HISTORY) {
            poisonIdentity(state, identity, history, current)
            authentication()
          }
          const quarantinedUntil =
            advertisement.expiresAtMs > history.expiresAtMs
              ? advertisement.expiresAtMs
              : history.expiresAtMs
          state.records.delete(identity)
          state.quarantine.set(identity, quarantinedUntil)
          if (current) {
            const timer = current.timer
            current.timer = null
            clearRecord(state, current)
            if (timer !== null) {
              try {
                state.clearTimer(timer)
              } catch {}
            }
          }
          if (newRouteKey) {
            let routeKey = null
            try {
              routeKey = copy(advertisement.routeEncryptionPublicKey, 32)
              reflectApply(arrayPush, history.routeKeys, [routeKey])
              routeKey = null
            } catch {
              clear(routeKey)
              poisonIdentity(state, identity, history, null)
              authentication()
            }
          }
          authentication()
        }
        if (
          reflectApply(arraySome, history.routeKeys, [
            (key) => equal(key, advertisement.routeEncryptionPublicKey)
          ])
        ) {
          replay()
        }
        if (history.routeKeys.length === MAX_ROUTE_KEY_HISTORY) {
          poisonIdentity(state, identity, history, current)
          authentication()
        }
      }

      record = {
        advertisement,
        encoded: bytes,
        digest: advertisementDigest,
        projections: new Set(),
        sendAuthorities: new Set(),
        timer: null
      }
      projection = projectionFor(record)
      nextHistory = {
        encoded: null,
        digest: null,
        epoch: 0n,
        expiresAtMs: 0n,
        routeKeys: [],
        poisoned: false
      }
      nextHistory.encoded = copy(bytes)
      nextHistory.digest = copy(advertisementDigest, 32)
      nextHistory.epoch = advertisement.epoch
      nextHistory.expiresAtMs = advertisement.expiresAtMs
      if (history) {
        for (const key of history.routeKeys) {
          reflectApply(arrayPush, nextHistory.routeKeys, [copy(key, 32)])
        }
      }
      reflectApply(arrayPush, nextHistory.routeKeys, [
        copy(advertisement.routeEncryptionPublicKey, 32)
      ])
      acceptance = { epoch: advertisement.epoch, phase: 'preparing' }
      state.accepting.set(identity, acceptance)
      scheduleRecordExpiry(state, identity, record, now, acceptance)
      ensureState(this)
      if (state.accepting.get(identity) !== acceptance) authentication()
      if (current) {
        const timer = current.timer
        current.timer = null
        clearRecord(state, current)
        if (timer !== null) {
          try {
            state.clearTimer(timer)
          } catch {}
        }
      }
      if (history) clearHistory(history)
      state.records.set(identity, record)
      state.histories.set(identity, nextHistory)
      publishProjection(state, record, projection)
      acceptance.phase = 'published'
      state.accepting.delete(identity)
      published = true
      const result = projection
      advertisement = null
      bytes = null
      advertisementDigest = null
      projection = null
      nextHistory = null
      return result
    } catch (err) {
      if (err instanceof PrivateRouteError) throw err
      authentication()
    } finally {
      if (acceptance !== null && state.accepting.get(identity) === acceptance) {
        state.accepting.delete(identity)
      }
      if (!published && record !== null && record.timer !== null) {
        try {
          state.clearTimer(record.timer)
        } catch {}
        record.timer = null
      }
      if (!published && projection !== null) {
        state.projections.delete(projection)
        projectionOwners.delete(projection)
        if (record !== null) record.projections.delete(projection)
        clearProjection(projection)
      }
      if (!published) clearHistory(nextHistory)
      clearAdvertisement(advertisement)
      clear(bytes)
      clear(advertisementDigest)
    }
  }

  async beginChallenge(advertisement, sendChallenge) {
    const state = ensureState(this)
    const record =
      advertisement !== null && typeof advertisement === 'object'
        ? state.projections.get(advertisement)
        : null
    if (!record) authentication()
    const authorityState =
      sendChallenge !== null && typeof sendChallenge === 'object'
        ? sendAuthorityStates.get(sendChallenge)
        : null
    if (!authorityState) {
      if (
        sendChallenge !== null &&
        typeof sendChallenge === 'object' &&
        consumedSendAuthorities.has(sendChallenge)
      ) {
        replay()
      }
      authentication()
    }
    if (
      authorityState.state !== state ||
      authorityState.record !== record ||
      authorityState.projection !== advertisement
    ) {
      clearSendAuthority(authorityState)
      authentication()
    }
    const wallStart = sampleWall(state)
    if (
      state.projections.get(advertisement) !== record ||
      sendAuthorityStates.get(sendChallenge) !== authorityState ||
      record.advertisement.expiresAtMs <= wallStart ||
      authorityState.cookieExpiresAtMs <= wallStart
    ) {
      clearSendAuthority(authorityState)
      incompatible()
    }
    const monoStart = sampleMonotonic(state)
    let nonceSource = null
    let nonce = null
    let ephemeralSeedSource = null
    let ephemeralSeed = null
    let ephemeral = null
    let body = null
    let message = null
    let response = null
    let object = null
    let input = null
    let shared = null
    let expected = null
    let deadlineReject = null
    let deadlinePromise = null
    const pending = {
      state,
      record,
      authorityState,
      challenge: null,
      ephemeralSecretKey: null,
      outboundMessage: null,
      timer: null,
      reject: null
    }
    try {
      consumeSendAuthority(authorityState)
      nonceSource = cryptoSuite.randomBytes(32)
      nonce = copy(nonceSource, 32)
      ephemeralSeedSource = cryptoSuite.randomBytes(32)
      ephemeralSeed = copy(ephemeralSeedSource, 32)
      ephemeral = cryptoSuite.encryptionKeyPair(ephemeralSeed)
      body = allocate(176)
      clear(body)
      set(body, record.digest, 0)
      set(body, nonce, 32)
      set(body, ephemeral.publicKey, 64)
      const wallDeadline =
        authorityState.cookieExpiresAtMs < record.advertisement.expiresAtMs
          ? authorityState.cookieExpiresAtMs < wallStart + ACTIVE_CHALLENGE_TIMEOUT
            ? authorityState.cookieExpiresAtMs
            : wallStart + ACTIVE_CHALLENGE_TIMEOUT
          : record.advertisement.expiresAtMs < wallStart + ACTIVE_CHALLENGE_TIMEOUT
            ? record.advertisement.expiresAtMs
            : wallStart + ACTIVE_CHALLENGE_TIMEOUT
      writeUint64(body, wallDeadline, 96)
      set(body, authorityState.queryNonce, 104)
      writeUint64(body, authorityState.cookieExpiresAtMs, 136)
      set(body, authorityState.returnRoutabilityCookie, 144)
      message = encodeM3Object({ messageId: M3_MESSAGE_ID.ACTIVE_CHALLENGE_V1, body })
      pending.challenge = copy(body)
      pending.ephemeralSecretKey = copy(ephemeral.secretKey, 32)
      state.pending.add(pending)
      deadlinePromise = new Promise((resolve, reject) => {
        deadlineReject = reject
      })
      pending.reject = deadlineReject
      void deadlinePromise.catch(() => {})
      pending.timer = state.setTimer(
        () => {
          pending.timer = null
          try {
            sampleWall(state)
          } catch (err) {
            deadlineReject(err)
            return
          }
          deadlineReject(PrivateRouteError.ERR_INCOMPATIBLE_RELAY())
        },
        Number(wallDeadline - wallStart)
      )
      unrefTimer(pending.timer)
      const ownedMessage = copy(message)
      pending.outboundMessage = ownedMessage
      let responseSource
      try {
        responseSource = await Promise.race([
          Promise.resolve().then(() => authorityState.send(ownedMessage)),
          deadlinePromise
        ])
      } finally {
        clear(ownedMessage)
        if (pending.outboundMessage === ownedMessage) pending.outboundMessage = null
      }
      response = copy(responseSource)
      ensureState(this)
      const wallComplete = sampleWall(state)
      const monoComplete = sampleMonotonic(state)
      if (
        monoComplete < monoStart ||
        monoComplete - monoStart >= wallDeadline - wallStart ||
        wallComplete >= wallDeadline ||
        record.advertisement.expiresAtMs <= wallComplete
      ) {
        incompatible()
      }
      object = responseObject(response)
      const responseDigestBytes = digest([object.body, object.authSuffix])
      const responseDigest = b4aToString(responseDigestBytes, 'hex')
      clear(responseDigestBytes)
      if (state.responseTombstones.has(responseDigest)) replay()
      if (
        !equal(subarray(object.body, 0, 32), record.digest) ||
        !equal(subarray(object.body, 32, 64), record.advertisement.relayIdentity) ||
        !equal(subarray(object.body, 64, 128), subarray(body, 32, 96)) ||
        !equal(subarray(object.body, 160, 240), subarray(body, 96, 176))
      ) {
        authentication()
      }
      input = signatureInput(
        ACTIVE_RESPONSE_DOMAIN,
        M3_MESSAGE_ID.ACTIVE_CHALLENGE_RESPONSE_V1,
        object.body
      )
      if (!cryptoSuite.verify(input, object.authSuffix, record.advertisement.relayIdentity)) {
        authentication()
      }
      shared = cryptoSuite.keyAgreement(
        ephemeral.secretKey,
        record.advertisement.routeEncryptionPublicKey
      )
      if (equal(shared, ZERO_32)) authentication()
      expected = activeProof(shared, subarray(object.body, 0, 240))
      if (!equal(expected, subarray(object.body, 240, 272))) authentication()
      ensureState(this)
      const wallVerified = sampleWall(state)
      ensureState(this)
      const monoVerified = sampleMonotonic(state)
      ensureState(this)
      if (
        monoVerified < monoStart ||
        monoVerified - monoStart >= wallDeadline - wallStart ||
        wallVerified >= wallDeadline ||
        record.advertisement.expiresAtMs <= wallVerified ||
        state.projections.get(advertisement) !== record ||
        !ownsRecord(state, record)
      ) {
        incompatible()
      }
      if (state.responseTombstones.size >= MAX_CAPS_BINDINGS) {
        throw PrivateRouteError.ERR_BUSY()
      }
      state.responseTombstones.set(responseDigest, wallDeadline)
      const projection = projectionFor(record)
      publishProjection(state, record, projection)
      return projection
    } catch (err) {
      if (err instanceof PrivateRouteError) throw err
      authentication()
    } finally {
      state.pending.delete(pending)
      clearPending(pending)
      clear(nonceSource)
      clear(nonce)
      clear(ephemeralSeedSource)
      clear(ephemeralSeed)
      clear(ephemeral && ephemeral.publicKey)
      clear(ephemeral && ephemeral.secretKey)
      clear(body)
      clear(message)
      clear(response)
      if (object) {
        clear(object.body)
        clear(object.authSuffix)
      }
      clear(input)
      clear(shared)
      clear(expected)
      clearSendAuthority(authorityState)
    }
  }

  destroy() {
    const state = verifierStates.get(this)
    if (!state || state.destroyed) return
    state.destroyed = true
    for (const record of state.records.values()) {
      if (record.timer !== null) {
        try {
          state.clearTimer(record.timer)
        } catch {}
      }
    }
    invalidateAll(state, false, PrivateRouteError.ERR_DESTROYED())
    state.responseTombstones.clear()
    state.wallNow = null
    state.monotonicNow = null
    state.setTimer = null
    state.clearTimer = null
    state.onInvalidated = null
  }
}

module.exports = {
  ACTIVE_CHALLENGE_TIMEOUT,
  CAPABILITY_ADVERTISEMENT_FIXED_BODY,
  CAPABILITY_ADVERTISEMENT_MAX_BYTES,
  CAPABILITY_ADVERTISEMENT_MIN_BYTES,
  MAX_CAPABILITY_ADVERTISEMENTS,
  MAX_CAPABILITY_LIFETIME,
  RelayCapabilityVerifier,
  createActiveChallengeResponderAuthority,
  createActiveChallengeSendAuthority,
  decodeCanonicalEndpoint,
  decodeRelayCapabilityAdvertisement,
  deriveM3DhtNodeId,
  digestRelayCapabilityAdvertisement,
  encodeCanonicalEndpoint,
  encodeRelayCapabilityAdvertisement,
  observeActiveChallengeResponderForTests,
  providerServicePolicyForCapabilities,
  signRelayCapabilityAdvertisement
}
