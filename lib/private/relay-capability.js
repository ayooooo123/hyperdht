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
  return copy(cryptoSuite.hash(parts), 32)
}

function keyedHash(key, parts) {
  const input = b4aConcat(parts)
  const output = allocate(32)
  try {
    sodium.crypto_generichash(output, input, key)
    return output
  } finally {
    clear(input)
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
  const body = allocate(
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
  const { body, normalized } = encodeAdvertisementBody(value)
  const secret = copy(identitySecretKey, 64)
  const input = signatureInput(CAPABILITY_DOMAIN, M3_MESSAGE_ID.CAPABILITY_ADVERTISEMENT_V1, body)
  try {
    const signature = copy(cryptoSuite.sign(input, secret), 64)
    if (!cryptoSuite.verify(input, signature, normalized.relayIdentity)) {
      clear(signature)
      authentication()
    }
    return objectFreeze({ ...normalized, signature })
  } catch (err) {
    clearAdvertisement(normalized)
    if (err instanceof PrivateRouteError) throw err
    authentication()
  } finally {
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
  const query = {
    sourceEndpoint: decodeCanonicalEndpoint(dataProperty(value, 'sourceEndpoint')),
    requestedCapabilityMask: dataProperty(value, 'requestedCapabilityMask'),
    randomTarget: copy(dataProperty(value, 'randomTarget'), 32),
    queryNonce: copy(dataProperty(value, 'queryNonce'), 32),
    maximumResults: dataProperty(value, 'maximumResults')
  }
  try {
    if (
      (query.requestedCapabilityMask !== 1 && query.requestedCapabilityMask !== 3) ||
      !Number.isSafeInteger(query.maximumResults) ||
      query.maximumResults < 1 ||
      query.maximumResults > MAX_CAPABILITY_ADVERTISEMENTS
    ) {
      incompatible()
    }
    if (includeCookie) {
      query.cookieExpiresAtMs = dataProperty(value, 'cookieExpiresAtMs')
      query.returnRoutabilityCookie = copy(dataProperty(value, 'returnRoutabilityCookie'), 32)
      query.advertisement = copy(dataProperty(value, 'advertisement'))
      if (!uint64(query.cookieExpiresAtMs)) incompatible()
    }
    return query
  } catch (err) {
    clearCapsQuery(query)
    throw err
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

class ActiveChallengeResponderAuthority {
  constructor(options = {}) {
    const allowed = ['now', 'crypto', 'setTimeout', 'clearTimeout', 'maxBindings']
    if (options === null || typeof options !== 'object' || arrayIsArray(options)) incompatible()
    for (const name of objectGetOwnPropertyNames(options)) {
      if (!reflectApply(arrayIncludes, allowed, [name])) incompatible()
      const descriptor = objectGetOwnPropertyDescriptor(options, name)
      if (!descriptor || !reflectApply(objectHasOwnProperty, descriptor, ['value'])) incompatible()
    }
    if (objectGetOwnPropertySymbols(options).length !== 0) incompatible()
    const now = objectGetOwnPropertyDescriptor(options, 'now')?.value
    const crypto = objectGetOwnPropertyDescriptor(options, 'crypto')?.value || cryptoSuite
    const setTimer =
      objectGetOwnPropertyDescriptor(options, 'setTimeout')?.value || globalThis.setTimeout
    const clearTimer =
      objectGetOwnPropertyDescriptor(options, 'clearTimeout')?.value || globalThis.clearTimeout
    const maxBindings =
      objectGetOwnPropertyDescriptor(options, 'maxBindings')?.value || MAX_CAPS_BINDINGS
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
    this._now = now
    this._setTimer = setTimer
    this._clearTimer = clearTimer
    this._crypto = { randomBytes, keyAgreement, sign }
    this._currentSecret = {
      secret: null,
      rotatedAt: current
    }
    this._priorSecret = null
    this._bindings = new Map()
    this._completed = new WeakSet()
    this._maxBindings = maxBindings
    this._destroyed = false
    this._rotationTimer = null
    this._priorEraseTimer = null
    this._rotationDeadline = current + CAPS_COOKIE_ROTATION
    let randomScratch = null
    try {
      randomScratch = randomBytes(32)
      this._currentSecret.secret = copy(randomScratch, 32)
      this._scheduleRotation()
    } catch (err) {
      this.destroy()
      throw err
    } finally {
      clear(randomScratch)
    }
  }

  _assertLive() {
    if (this._destroyed) destroyed()
  }

  _scheduleRotation() {
    const now = this._now()
    this._assertLive()
    if (!uint64(now)) {
      this.destroy()
      return
    }
    let timer = null
    try {
      timer = this._setTimer(
        () => {
          this._rotationTimer = null
          if (this._destroyed) return
          const current = this._now()
          if (this._destroyed) return
          if (!uint64(current)) {
            this.destroy()
            return
          }
          this._catchUpRotation(current)
        },
        Number(this._rotationDeadline > now ? this._rotationDeadline - now : 0n)
      )
      this._assertLive()
    } catch (err) {
      if (timer !== null) {
        try {
          this._clearTimer(timer)
        } catch {}
      }
      throw err
    }
    this._rotationTimer = timer
    unrefTimer(this._rotationTimer)
  }

  _catchUpRotation(now) {
    this._assertLive()
    if (this._priorSecret && this._priorSecret.expiresAt <= now) {
      clear(this._priorSecret.secret)
      this._priorSecret = null
      if (this._priorEraseTimer !== null) {
        try {
          this._clearTimer(this._priorEraseTimer)
        } catch {}
        this._assertLive()
        this._priorEraseTimer = null
      }
    }
    if (now < this._rotationDeadline) return
    let randomScratch = null
    let nextSecret = null
    try {
      randomScratch = this._crypto.randomBytes(32)
      this._assertLive()
      nextSecret = copy(randomScratch, 32)
    } finally {
      clear(randomScratch)
    }
    try {
      if (this._rotationTimer !== null) {
        try {
          this._clearTimer(this._rotationTimer)
        } catch {}
        this._assertLive()
        this._rotationTimer = null
      }
      if (this._priorEraseTimer !== null) {
        try {
          this._clearTimer(this._priorEraseTimer)
        } catch {}
        this._assertLive()
        this._priorEraseTimer = null
      }
      if (this._priorSecret) {
        clear(this._priorSecret.secret)
        this._priorSecret = null
      }
      const elapsed = now - this._rotationDeadline
      const skipped = elapsed / CAPS_COOKIE_ROTATION
      const rotationAt = this._rotationDeadline + skipped * CAPS_COOKIE_ROTATION
      const priorExpiresAt = this._rotationDeadline + CAPS_COOKIE_LIFETIME
      if (skipped === 0n && now < priorExpiresAt) {
        const prior = {
          secret: this._currentSecret.secret,
          expiresAt: priorExpiresAt
        }
        let priorTimer = null
        try {
          priorTimer = this._setTimer(
            () => {
              this._priorEraseTimer = null
              if (this._priorSecret !== prior) return
              clear(prior.secret)
              this._priorSecret = null
            },
            Number(priorExpiresAt - now)
          )
          this._assertLive()
        } catch (err) {
          if (priorTimer !== null) {
            try {
              this._clearTimer(priorTimer)
            } catch {}
          }
          throw err
        }
        this._priorSecret = prior
        this._priorEraseTimer = priorTimer
        unrefTimer(this._priorEraseTimer)
      } else {
        clear(this._currentSecret.secret)
      }
      this._currentSecret = {
        secret: nextSecret,
        rotatedAt: rotationAt
      }
      nextSecret = null
      this._rotationDeadline = rotationAt + CAPS_COOKIE_ROTATION
      this._scheduleRotation()
    } finally {
      clear(nextSecret)
    }
  }

  _expire(now) {
    this._catchUpRotation(now)
    for (const [binding, state] of this._bindings) {
      if (state.query.cookieExpiresAtMs > now) continue
      this._bindings.delete(binding)
      clearCapsQuery(state.query)
      clear(state.advertisementDigest)
    }
  }

  _cookie(secret, query) {
    const input = capsCookieInput(query)
    try {
      return keyedHash(secret, [input])
    } finally {
      clear(input)
    }
  }

  issueCookie(value) {
    this._assertLive()
    const now = this._now()
    if (!uint64(now)) incompatible()
    this._expire(now)
    const query = readCapsQuery(value, false)
    try {
      query.cookieExpiresAtMs = now + CAPS_COOKIE_LIFETIME
      return objectFreeze({
        cookieExpiresAtMs: query.cookieExpiresAtMs,
        returnRoutabilityCookie: this._cookie(this._currentSecret.secret, query)
      })
    } finally {
      clearCapsQuery(query)
    }
  }

  admitCapsRetry(value) {
    this._assertLive()
    const now = this._now()
    if (!uint64(now)) incompatible()
    this._expire(now)
    const query = readCapsQuery(value, true)
    let expected = null
    let advertisementDigest = null
    try {
      if (query.cookieExpiresAtMs <= now || query.cookieExpiresAtMs > now + CAPS_COOKIE_LIFETIME) {
        authentication()
      }
      expected = this._cookie(this._currentSecret.secret, query)
      let valid = equal(expected, query.returnRoutabilityCookie)
      clear(expected)
      expected = null
      if (!valid && this._priorSecret && this._priorSecret.expiresAt > now) {
        expected = this._cookie(this._priorSecret.secret, query)
        valid = equal(expected, query.returnRoutabilityCookie)
      }
      if (!valid) authentication()
      const advertisement = decodeRelayCapabilityAdvertisement(query.advertisement, { now })
      clearAdvertisement(advertisement)
      advertisementDigest = rawAdvertisementDigest(query.advertisement)
      for (const [binding, state] of this._bindings) {
        if (!equal(state.query.returnRoutabilityCookie, query.returnRoutabilityCookie)) continue
        if (
          sameCapsQuery(state.query, query) &&
          equal(state.query.advertisement, query.advertisement) &&
          equal(state.advertisementDigest, advertisementDigest)
        ) {
          clearCapsQuery(query)
          clear(advertisementDigest)
          return binding
        }
        authentication()
      }
      if (this._bindings.size >= this._maxBindings) throw PrivateRouteError.ERR_BUSY()
      const binding = objectFreeze({})
      this._bindings.set(binding, { query, advertisementDigest })
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
    this._assertLive()
    if (binding !== null && typeof binding === 'object' && this._completed.has(binding)) replay()
    const state = this._bindings.get(binding)
    if (!state) authentication()
    exactObject(options, RESPOND_FIELDS)
    const now = this._now()
    if (!uint64(now)) incompatible()
    this._expire(now)
    if (!this._bindings.has(binding) || state.query.cookieExpiresAtMs <= now) authentication()
    const sourceEndpoint = decodeCanonicalEndpoint(dataProperty(options, 'sourceEndpoint'))
    const advertisement = copy(dataProperty(options, 'advertisement'))
    const body = challengeBody(challenge)
    let advert = null
    let advertDigest = null
    let responderNonce = null
    let routeSecret = null
    let identitySecret = null
    let shared = null
    let proof = null
    let responseBody = null
    let input = null
    try {
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
      responderNonce = copy(this._crypto.randomBytes(32), 32)
      routeSecret = copy(dataProperty(options, 'routeEncryptionSecretKey'), 32)
      identitySecret = copy(dataProperty(options, 'identitySecretKey'), 64)
      shared = this._crypto.keyAgreement(routeSecret, subarray(body, 64, 96))
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
      const response = encodeM3Object({
        messageId: M3_MESSAGE_ID.ACTIVE_CHALLENGE_RESPONSE_V1,
        body: responseBody,
        authSuffix: this._crypto.sign(input, identitySecret)
      })
      this._bindings.delete(binding)
      this._completed.add(binding)
      clearCapsQuery(state.query)
      clear(state.advertisementDigest)
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
      clear(responderNonce)
      clear(routeSecret)
      clear(identitySecret)
      clear(shared)
      clear(proof)
      clear(responseBody)
      clear(input)
    }
  }

  destroy() {
    if (this._destroyed) return
    this._destroyed = true
    if (this._rotationTimer !== null) {
      try {
        this._clearTimer(this._rotationTimer)
      } catch {}
    }
    if (this._priorEraseTimer !== null) {
      try {
        this._clearTimer(this._priorEraseTimer)
      } catch {}
    }
    this._rotationTimer = null
    this._priorEraseTimer = null
    clear(this._currentSecret.secret)
    if (this._priorSecret) clear(this._priorSecret.secret)
    for (const state of this._bindings.values()) {
      clearCapsQuery(state.query)
      clear(state.advertisementDigest)
    }
    this._bindings.clear()
    this._priorSecret = null
    this._setTimer = null
    this._clearTimer = null
  }
}

function createActiveChallengeResponderAuthority(options) {
  return new ActiveChallengeResponderAuthority(options)
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
  return objectFreeze({
    canonicalBytes: copy(record.encoded),
    digest: copy(record.digest, 32),
    identity: copy(record.advertisement.relayIdentity, 32),
    canonicalEndpointBytes: copy(record.advertisement.reachableEndpoint, 19),
    routePublicKey: copy(record.advertisement.routeEncryptionPublicKey, 32),
    role: roleForIdentity(record.advertisement.relayIdentity),
    capabilityMask: record.advertisement.capabilityMask,
    epoch: record.advertisement.epoch,
    issuedAt: record.advertisement.issuedAtMs,
    expiresAt: record.advertisement.expiresAtMs
  })
}

function clearRecord(state, record) {
  if (!record) return
  clear(record.encoded)
  clear(record.digest)
  clearAdvertisement(record.advertisement)
  for (const projection of record.projections) {
    state.projections.delete(projection)
    clearProjection(projection)
  }
  record.projections.clear()
}

function clearHistory(history) {
  if (!history) return
  clear(history.encoded)
  clear(history.digest)
  for (const key of history.routeKeys) clear(key)
  history.routeKeys.length = 0
}

function clearPending(pending) {
  if (!pending) return
  clear(pending.challenge)
  clear(pending.ephemeralSecretKey)
  if (pending.timer !== null) {
    try {
      pending.state.clearTimer(pending.timer)
    } catch {}
  }
  pending.timer = null
  pending.reject = null
}

function invalidateAll(state, notify, error) {
  for (const record of state.records.values()) {
    if (record.timer !== null) {
      try {
        state.clearTimer(record.timer)
      } catch {}
      record.timer = null
    }
    clearRecord(state, record)
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
  state.seenResponses.clear()
  state.poisoned = true
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
  if (state.lastAcceptedWallNow !== null && now + MAX_FUTURE_SKEW < state.lastAcceptedWallNow) {
    invalidateAll(state, true, PrivateRouteError.ERR_INCOMPATIBLE_RELAY())
    incompatible()
  }
  if (state.poisoned) incompatible()
  if (state.lastAcceptedWallNow === null || now > state.lastAcceptedWallNow) {
    state.lastAcceptedWallNow = now
  }
  expireRecords(state, now)
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
    if (record.timer !== null) {
      try {
        state.clearTimer(record.timer)
      } catch {}
      record.timer = null
    }
    clearRecord(state, record)
    state.records.delete(identity)
  }
  for (const [identity, expiresAt] of state.quarantine) {
    if (expiresAt <= now) state.quarantine.delete(identity)
  }
}

function scheduleRecordExpiry(state, identity, record, now) {
  const timer = state.setTimer(
    () => {
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
        clearRecord(state, record)
        state.records.delete(identity)
      }
    },
    Number(record.advertisement.expiresAtMs - now)
  )
  record.timer = timer
  unrefTimer(timer)
}

function ensureState(verifier) {
  const state = verifierStates.get(verifier)
  if (!state || state.destroyed) destroyed()
  return state
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
      seenResponses: new Set(),
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
    try {
      bytes = copy(encoded)
      advertisement = decodeRelayCapabilityAdvertisement(bytes, { now })
      const actualRole = roleForIdentity(advertisement.relayIdentity)
      if (actualRole !== expectedRole || advertisement.capabilityMask !== expectedCapabilityMask) {
        incompatible()
      }
      advertisementDigest = rawAdvertisementDigest(bytes)
      const identity = b4aToString(advertisement.relayIdentity, 'hex')
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
              timer: null
            }
            const projection = projectionFor(source)
            source.projections.add(projection)
            state.projections.set(projection, source)
            return projection
          }
          if (
            !reflectApply(arraySome, history.routeKeys, [
              (key) => equal(key, advertisement.routeEncryptionPublicKey)
            ])
          ) {
            if (history.routeKeys.length === MAX_ROUTE_KEY_HISTORY) history.poisoned = true
            else
              reflectApply(arrayPush, history.routeKeys, [
                copy(advertisement.routeEncryptionPublicKey, 32)
              ])
          }
          if (current) {
            if (current.timer !== null) state.clearTimer(current.timer)
            clearRecord(state, current)
            state.records.delete(identity)
          }
          state.quarantine.set(
            identity,
            advertisement.expiresAtMs > history.expiresAtMs
              ? advertisement.expiresAtMs
              : history.expiresAtMs
          )
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
          history.poisoned = true
          authentication()
        }
      }

      const record = {
        advertisement,
        encoded: bytes,
        digest: advertisementDigest,
        projections: new Set(),
        timer: null
      }
      const projection = projectionFor(record)
      record.projections.add(projection)
      state.projections.set(projection, record)
      const nextHistory = history || {
        encoded: null,
        digest: null,
        epoch: 0n,
        expiresAtMs: 0n,
        routeKeys: [],
        poisoned: false
      }
      clear(nextHistory.encoded)
      clear(nextHistory.digest)
      nextHistory.encoded = copy(bytes)
      nextHistory.digest = copy(advertisementDigest, 32)
      nextHistory.epoch = advertisement.epoch
      nextHistory.expiresAtMs = advertisement.expiresAtMs
      reflectApply(arrayPush, nextHistory.routeKeys, [
        copy(advertisement.routeEncryptionPublicKey, 32)
      ])
      if (current) {
        if (current.timer !== null) state.clearTimer(current.timer)
        clearRecord(state, current)
      }
      state.records.set(identity, record)
      state.histories.set(identity, nextHistory)
      scheduleRecordExpiry(state, identity, record, now)
      advertisement = null
      bytes = null
      advertisementDigest = null
      return projection
    } finally {
      clearAdvertisement(advertisement)
      clear(bytes)
      clear(advertisementDigest)
    }
  }

  async beginChallenge(advertisement, sendChallenge) {
    const state = ensureState(this)
    if (typeof sendChallenge !== 'function') incompatible()
    const record =
      advertisement !== null && typeof advertisement === 'object'
        ? state.projections.get(advertisement)
        : null
    if (!record) authentication()
    const wallStart = sampleWall(state)
    if (record.advertisement.expiresAtMs <= wallStart) incompatible()
    const monoStart = sampleMonotonic(state)
    let nonce = null
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
      challenge: null,
      ephemeralSecretKey: null,
      timer: null,
      reject: null
    }
    try {
      nonce = copy(cryptoSuite.randomBytes(32), 32)
      ephemeralSeed = copy(cryptoSuite.randomBytes(32), 32)
      ephemeral = cryptoSuite.encryptionKeyPair(ephemeralSeed)
      body = allocate(176)
      clear(body)
      set(body, record.digest, 0)
      set(body, nonce, 32)
      set(body, ephemeral.publicKey, 64)
      const wallDeadline =
        record.advertisement.expiresAtMs < wallStart + ACTIVE_CHALLENGE_TIMEOUT
          ? record.advertisement.expiresAtMs
          : wallStart + ACTIVE_CHALLENGE_TIMEOUT
      writeUint64(body, wallDeadline, 96)
      message = encodeM3Object({ messageId: M3_MESSAGE_ID.ACTIVE_CHALLENGE_V1, body })
      pending.challenge = copy(body)
      pending.ephemeralSecretKey = copy(ephemeral.secretKey, 32)
      state.pending.add(pending)
      deadlinePromise = new Promise((resolve, reject) => {
        deadlineReject = reject
      })
      pending.reject = deadlineReject
      void deadlinePromise.catch(() => {})
      pending.timer = state.setTimer(() => {
        pending.timer = null
        deadlineReject(PrivateRouteError.ERR_INCOMPATIBLE_RELAY())
      }, Number(ACTIVE_CHALLENGE_TIMEOUT))
      unrefTimer(pending.timer)
      const responseSource = await Promise.race([
        Promise.resolve().then(() => sendChallenge(copy(message))),
        deadlinePromise
      ])
      response = copy(responseSource)
      ensureState(this)
      const wallComplete = sampleWall(state)
      const monoComplete = sampleMonotonic(state)
      if (
        monoComplete < monoStart ||
        monoComplete - monoStart >= ACTIVE_CHALLENGE_TIMEOUT ||
        wallComplete >= wallDeadline ||
        record.advertisement.expiresAtMs <= wallComplete
      ) {
        incompatible()
      }
      object = responseObject(response)
      const responseDigestBytes = digest([object.body, object.authSuffix])
      const responseDigest = b4aToString(responseDigestBytes, 'hex')
      clear(responseDigestBytes)
      if (state.seenResponses.has(responseDigest)) replay()
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
      sampleWall(state)
      if (state.seenResponses.size >= MAX_CAPS_BINDINGS) throw PrivateRouteError.ERR_BUSY()
      state.seenResponses.add(responseDigest)
      const projection = projectionFor(record)
      record.projections.add(projection)
      state.projections.set(projection, record)
      return projection
    } catch (err) {
      if (err instanceof PrivateRouteError) throw err
      authentication()
    } finally {
      state.pending.delete(pending)
      clearPending(pending)
      clear(nonce)
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
    state.seenResponses.clear()
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
  decodeCanonicalEndpoint,
  decodeRelayCapabilityAdvertisement,
  deriveM3DhtNodeId,
  digestRelayCapabilityAdvertisement,
  encodeCanonicalEndpoint,
  encodeRelayCapabilityAdvertisement,
  providerServicePolicyForCapabilities,
  signRelayCapabilityAdvertisement
}
