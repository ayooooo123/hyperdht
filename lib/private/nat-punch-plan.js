'use strict'

// Bilateral adjacent-link NAT punch plan. Both adjacent identities sign one
// canonical body. The plan authorizes a bounded punch round only; it never
// authorizes a link, readiness, or public dial authority.
//
// Seat decisions D1/D3/D4/D5: bilateral signatures, topology address codec,
// punch is connectivity evidence only, short validity window.

const b4a = require('b4a')

const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')
const { PROTOCOL_VERSION } = require('./protocol')
const {
  hostFromAddress,
  parseAddress,
  validateAdjacency,
  validateRoleBinding
} = require('./topology-grant')

const PLAN_FORMAT = 0
const SIGNATURE_SIZE = 64
const DOMAIN_NAT_PUNCH_PLAN = b4a.from('hyperdht-private-routes/nat-punch-plan/v0')

// Fixed profile registry. Wire encodes only the profile id.
const PUNCH_PROFILES = Object.freeze({
  0: Object.freeze({
    id: 0,
    rounds: 6,
    intervalMs: 500,
    firstSendDeadlineMs: 1_000
  })
})
const DEFAULT_PUNCH_PROFILE_ID = 0

// Per-side payload without address bytes: identity32 + role + family + port + claim + nonce
const SIDE_FIXED_BYTES = 32 + 1 + 1 + 2 + 32 + 32
// Common header without endpoints: version + format + planId + digest + epoch + run + nbf + exp + profile
const HEADER_FIXED_BYTES = 4 + 1 + 32 + 32 + 8 + 32 + 8 + 8 + 1
const MIN_UNSIGNED_SIZE = HEADER_FIXED_BYTES + 2 * (SIDE_FIXED_BYTES + 4)
const MAX_UNSIGNED_SIZE = HEADER_FIXED_BYTES + 2 * (SIDE_FIXED_BYTES + 16)
const MAX_PLAN_BYTES = MAX_UNSIGNED_SIZE + SIGNATURE_SIZE * 2
const MAX_PLAN_LIFETIME_MS = 15_000n

const VERIFIED_PLANS = new WeakMap()

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function unauthorized() {
  throw PrivateRouteError.UNAUTHORIZED()
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function exactKeys(value, fields) {
  if (!isObject(value)) return false
  const actual = Object.keys(value).sort()
  const wanted = [...fields].sort()
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index])
}

function fixed(value, size) {
  return b4a.isBuffer(value) && value.byteLength === size
}

function validU64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= 0xffff_ffff_ffff_ffffn
}

function clear(buffer) {
  if (b4a.isBuffer(buffer)) b4a.fill(buffer, 0)
}

function writeU16(buffer, value, offset) {
  buffer[offset] = value >>> 8
  buffer[offset + 1] = value
}

function writeU32(buffer, value, offset) {
  buffer[offset] = value >>> 24
  buffer[offset + 1] = value >>> 16
  buffer[offset + 2] = value >>> 8
  buffer[offset + 3] = value
}

function writeU64(buffer, value, offset) {
  for (let shift = 56n; shift >= 0n; shift -= 8n) {
    buffer[offset++] = Number((value >> shift) & 0xffn)
  }
  return offset
}

function createReader(buffer) {
  if (!b4a.isBuffer(buffer)) invalid()
  let offset = 0
  function take(size) {
    if (offset + size > buffer.byteLength) invalid()
    const value = b4a.from(buffer.subarray(offset, offset + size))
    offset += size
    return value
  }
  return {
    u8() {
      return take(1)[0]
    },
    u16() {
      const bytes = take(2)
      return bytes[0] * 0x100 + bytes[1]
    },
    u32() {
      const bytes = take(4)
      return bytes[0] * 0x1000000 + bytes[1] * 0x10000 + bytes[2] * 0x100 + bytes[3]
    },
    u64() {
      const bytes = take(8)
      let value = 0n
      for (const byte of bytes) value = (value << 8n) | BigInt(byte)
      return value
    },
    take,
    done() {
      if (offset !== buffer.byteLength) invalid()
    }
  }
}

function normalizeSide(value, label) {
  if (
    !exactKeys(value, ['identity32', 'role', 'host', 'port', 'reflectionClaimDigest32', 'nonce32'])
  ) {
    invalid()
  }
  if (!fixed(value.identity32, 32)) invalid()
  validateRoleBinding(value.identity32, value.role)
  if (!Number.isInteger(value.port) || value.port < 1 || value.port > 0xffff) invalid()
  if (!fixed(value.reflectionClaimDigest32, 32) || !fixed(value.nonce32, 32)) invalid()
  const address = parseAddress(value.host)
  return {
    label,
    identity32: b4a.from(value.identity32),
    role: value.role,
    address: { ...address, port: value.port },
    reflectionClaimDigest32: b4a.from(value.reflectionClaimDigest32),
    nonce32: b4a.from(value.nonce32)
  }
}

function publicSide(value) {
  return {
    identity32: b4a.from(value.identity32),
    role: value.role,
    host: value.address.host,
    port: value.address.port,
    family: value.address.family,
    reflectionClaimDigest32: b4a.from(value.reflectionClaimDigest32),
    nonce32: b4a.from(value.nonce32)
  }
}

function resolveProfile(profileId) {
  if (
    !Number.isInteger(profileId) ||
    !Object.prototype.hasOwnProperty.call(PUNCH_PROFILES, profileId)
  ) {
    invalid()
  }
  return PUNCH_PROFILES[profileId]
}

function normalizePlan(value, signed) {
  const fields = [
    'version',
    'format',
    'planId32',
    'topologyGrantDigest32',
    'epoch',
    'runId32',
    'notBefore',
    'expiresAt',
    'initiator',
    'responder',
    'punchProfileId'
  ]
  if (signed) {
    fields.push('initiatorSignature', 'responderSignature')
  }
  if (!exactKeys(value, fields)) invalid()
  if (value.version !== PROTOCOL_VERSION || value.format !== PLAN_FORMAT) invalid()
  if (!fixed(value.planId32, 32) || !fixed(value.topologyGrantDigest32, 32)) invalid()
  if (!fixed(value.runId32, 32)) invalid()
  if (!validU64(value.epoch) || !validU64(value.notBefore) || !validU64(value.expiresAt)) invalid()
  if (value.notBefore >= value.expiresAt) invalid()
  if (value.expiresAt - value.notBefore > MAX_PLAN_LIFETIME_MS) invalid()
  const profile = resolveProfile(value.punchProfileId)
  if (signed) {
    if (
      !fixed(value.initiatorSignature, SIGNATURE_SIZE) ||
      !fixed(value.responderSignature, SIGNATURE_SIZE)
    ) {
      invalid()
    }
  }

  const initiator = normalizeSide(value.initiator, 'initiator')
  const responder = normalizeSide(value.responder, 'responder')
  if (b4a.equals(initiator.identity32, responder.identity32)) invalid()
  validateAdjacency(initiator.role, responder.role)

  return {
    version: value.version,
    format: value.format,
    planId32: b4a.from(value.planId32),
    topologyGrantDigest32: b4a.from(value.topologyGrantDigest32),
    epoch: value.epoch,
    runId32: b4a.from(value.runId32),
    notBefore: value.notBefore,
    expiresAt: value.expiresAt,
    initiator,
    responder,
    punchProfileId: profile.id,
    ...(signed
      ? {
          initiatorSignature: b4a.from(value.initiatorSignature),
          responderSignature: b4a.from(value.responderSignature)
        }
      : {})
  }
}

function writeSide(buffer, value, offset) {
  buffer.set(value.identity32, offset)
  offset += 32
  buffer[offset++] = value.role
  buffer[offset++] = value.address.family
  buffer.set(value.address.bytes, offset)
  offset += value.address.bytes.byteLength
  writeU16(buffer, value.address.port, offset)
  offset += 2
  buffer.set(value.reflectionClaimDigest32, offset)
  offset += 32
  buffer.set(value.nonce32, offset)
  offset += 32
  return offset
}

function encodeNormalizedUnsigned(value) {
  const exact =
    4 + // version
    1 + // format
    32 + // planId
    32 + // grant digest
    8 + // epoch
    32 + // run
    8 + // nbf
    8 + // exp
    (32 + 1 + 1 + value.initiator.address.bytes.byteLength + 2 + 32 + 32) +
    (32 + 1 + 1 + value.responder.address.bytes.byteLength + 2 + 32 + 32) +
    1 // profile
  const buffer = b4a.allocUnsafe(exact)
  let offset = 0
  writeU32(buffer, value.version, offset)
  offset += 4
  buffer[offset++] = value.format
  buffer.set(value.planId32, offset)
  offset += 32
  buffer.set(value.topologyGrantDigest32, offset)
  offset += 32
  offset = writeU64(buffer, value.epoch, offset)
  buffer.set(value.runId32, offset)
  offset += 32
  offset = writeU64(buffer, value.notBefore, offset)
  offset = writeU64(buffer, value.expiresAt, offset)
  offset = writeSide(buffer, value.initiator, offset)
  offset = writeSide(buffer, value.responder, offset)
  buffer[offset++] = value.punchProfileId
  if (offset !== exact) invalid()
  return buffer
}

function encodeUnsignedNatPunchPlan(value) {
  return encodeNormalizedUnsigned(normalizePlan(value, false))
}

function decodeSide(reader) {
  const identity32 = reader.take(32)
  const role = reader.u8()
  const family = reader.u8()
  if (family !== 4 && family !== 6) invalid()
  const address = reader.take(family === 4 ? 4 : 16)
  const port = reader.u16()
  const reflectionClaimDigest32 = reader.take(32)
  const nonce32 = reader.take(32)
  return {
    identity32,
    role,
    host: hostFromAddress(family, address),
    port,
    reflectionClaimDigest32,
    nonce32
  }
}

function decodeValue(buffer, signed) {
  if (!b4a.isBuffer(buffer)) invalid()
  const maximum = MAX_UNSIGNED_SIZE + (signed ? SIGNATURE_SIZE * 2 : 0)
  const minimum = MIN_UNSIGNED_SIZE + (signed ? SIGNATURE_SIZE * 2 : 0)
  if (buffer.byteLength < minimum || buffer.byteLength > maximum) invalid()
  const reader = createReader(buffer)
  const value = {
    version: reader.u32(),
    format: reader.u8(),
    planId32: reader.take(32),
    topologyGrantDigest32: reader.take(32),
    epoch: reader.u64(),
    runId32: reader.take(32),
    notBefore: reader.u64(),
    expiresAt: reader.u64(),
    initiator: decodeSide(reader),
    responder: decodeSide(reader),
    punchProfileId: reader.u8()
  }
  if (signed) {
    value.initiatorSignature = reader.take(SIGNATURE_SIZE)
    value.responderSignature = reader.take(SIGNATURE_SIZE)
  }
  reader.done()
  const normalized = normalizePlan(value, signed)
  return {
    version: normalized.version,
    format: normalized.format,
    planId32: normalized.planId32,
    topologyGrantDigest32: normalized.topologyGrantDigest32,
    epoch: normalized.epoch,
    runId32: normalized.runId32,
    notBefore: normalized.notBefore,
    expiresAt: normalized.expiresAt,
    initiator: publicSide(normalized.initiator),
    responder: publicSide(normalized.responder),
    punchProfileId: normalized.punchProfileId,
    punchProfile: resolveProfile(normalized.punchProfileId),
    ...(signed
      ? {
          initiatorSignature: normalized.initiatorSignature,
          responderSignature: normalized.responderSignature
        }
      : {})
  }
}

function encodeNatPunchPlan(value) {
  const normalized = normalizePlan(value, true)
  return b4a.concat([
    encodeNormalizedUnsigned(normalized),
    normalized.initiatorSignature,
    normalized.responderSignature
  ])
}

function planDigest(unsigned) {
  return cryptoSuite.hash([DOMAIN_NAT_PUNCH_PLAN, unsigned])
}

function signNatPunchPlanSide(value, secretKey) {
  if (!fixed(secretKey, 64)) invalid()
  const unsigned = encodeUnsignedNatPunchPlan(value)
  const digest = planDigest(unsigned)
  try {
    return cryptoSuite.sign(digest, secretKey)
  } finally {
    clear(digest)
  }
}

function signNatPunchPlan(value, secrets) {
  if (
    !isObject(secrets) ||
    !fixed(secrets.initiatorSecretKey, 64) ||
    !fixed(secrets.responderSecretKey, 64)
  ) {
    invalid()
  }
  const unsigned = encodeUnsignedNatPunchPlan(value)
  const digest = planDigest(unsigned)
  let initiatorSignature = null
  let responderSignature = null
  try {
    initiatorSignature = cryptoSuite.sign(digest, secrets.initiatorSecretKey)
    responderSignature = cryptoSuite.sign(digest, secrets.responderSecretKey)
    return b4a.concat([unsigned, initiatorSignature, responderSignature])
  } finally {
    clear(digest)
    clear(initiatorSignature)
    clear(responderSignature)
  }
}

function verifyNatPunchPlan(encoding, options) {
  if (!isObject(options)) invalid()
  if (!fixed(options.localIdentity32, 32) || !validU64(options.now)) invalid()
  if (!b4a.isBuffer(encoding) || encoding.byteLength > MAX_PLAN_BYTES) invalid()

  const decoded = decodeValue(encoding, true)
  const unsigned = b4a.from(encoding.subarray(0, encoding.byteLength - SIGNATURE_SIZE * 2))
  const digest = planDigest(unsigned)
  try {
    if (
      !cryptoSuite.verify(digest, decoded.initiatorSignature, decoded.initiator.identity32) ||
      !cryptoSuite.verify(digest, decoded.responderSignature, decoded.responder.identity32)
    ) {
      unauthorized()
    }
  } finally {
    clear(digest)
    clear(unsigned)
  }

  if (options.now < decoded.notBefore || options.now >= decoded.expiresAt) unauthorized()

  let local = decoded.initiator
  let peer = decoded.responder
  let localIsInitiator = true
  if (b4a.equals(options.localIdentity32, decoded.responder.identity32)) {
    local = decoded.responder
    peer = decoded.initiator
    localIsInitiator = false
  } else if (!b4a.equals(options.localIdentity32, decoded.initiator.identity32)) {
    unauthorized()
  }

  const plan = Object.freeze({})
  const view = {
    encoding: b4a.from(encoding),
    planId32: b4a.from(decoded.planId32),
    topologyGrantDigest32: b4a.from(decoded.topologyGrantDigest32),
    epoch: decoded.epoch,
    runId32: b4a.from(decoded.runId32),
    notBefore: decoded.notBefore,
    expiresAt: decoded.expiresAt,
    local: {
      identity32: b4a.from(local.identity32),
      role: local.role,
      host: local.host,
      port: local.port,
      family: local.family,
      reflectionClaimDigest32: b4a.from(local.reflectionClaimDigest32),
      nonce32: b4a.from(local.nonce32)
    },
    peer: {
      identity32: b4a.from(peer.identity32),
      role: peer.role,
      host: peer.host,
      port: peer.port,
      family: peer.family,
      reflectionClaimDigest32: b4a.from(peer.reflectionClaimDigest32),
      nonce32: b4a.from(peer.nonce32)
    },
    localIsInitiator,
    punchProfileId: decoded.punchProfileId,
    punchProfile: resolveProfile(decoded.punchProfileId),
    initiator: {
      identity32: b4a.from(decoded.initiator.identity32),
      role: decoded.initiator.role,
      host: decoded.initiator.host,
      port: decoded.initiator.port,
      family: decoded.initiator.family,
      reflectionClaimDigest32: b4a.from(decoded.initiator.reflectionClaimDigest32),
      nonce32: b4a.from(decoded.initiator.nonce32)
    },
    responder: {
      identity32: b4a.from(decoded.responder.identity32),
      role: decoded.responder.role,
      host: decoded.responder.host,
      port: decoded.responder.port,
      family: decoded.responder.family,
      reflectionClaimDigest32: b4a.from(decoded.responder.reflectionClaimDigest32),
      nonce32: b4a.from(decoded.responder.nonce32)
    }
  }
  VERIFIED_PLANS.set(plan, view)
  return plan
}

function readVerifiedNatPunchPlan(plan) {
  const view = isObject(plan) ? VERIFIED_PLANS.get(plan) : null
  if (!view) unauthorized()
  return {
    encoding: b4a.from(view.encoding),
    planId32: b4a.from(view.planId32),
    topologyGrantDigest32: b4a.from(view.topologyGrantDigest32),
    epoch: view.epoch,
    runId32: b4a.from(view.runId32),
    notBefore: view.notBefore,
    expiresAt: view.expiresAt,
    local: {
      identity32: b4a.from(view.local.identity32),
      role: view.local.role,
      host: view.local.host,
      port: view.local.port,
      family: view.local.family,
      reflectionClaimDigest32: b4a.from(view.local.reflectionClaimDigest32),
      nonce32: b4a.from(view.local.nonce32)
    },
    peer: {
      identity32: b4a.from(view.peer.identity32),
      role: view.peer.role,
      host: view.peer.host,
      port: view.peer.port,
      family: view.peer.family,
      reflectionClaimDigest32: b4a.from(view.peer.reflectionClaimDigest32),
      nonce32: b4a.from(view.peer.nonce32)
    },
    localIsInitiator: view.localIsInitiator,
    punchProfileId: view.punchProfileId,
    punchProfile: resolveProfile(view.punchProfileId),
    initiator: {
      identity32: b4a.from(view.initiator.identity32),
      role: view.initiator.role,
      host: view.initiator.host,
      port: view.initiator.port,
      family: view.initiator.family,
      reflectionClaimDigest32: b4a.from(view.initiator.reflectionClaimDigest32),
      nonce32: b4a.from(view.initiator.nonce32)
    },
    responder: {
      identity32: b4a.from(view.responder.identity32),
      role: view.responder.role,
      host: view.responder.host,
      port: view.responder.port,
      family: view.responder.family,
      reflectionClaimDigest32: b4a.from(view.responder.reflectionClaimDigest32),
      nonce32: b4a.from(view.responder.nonce32)
    }
  }
}

function clearVerifiedNatPunchPlan(plan) {
  const view = isObject(plan) ? VERIFIED_PLANS.get(plan) : null
  if (!view) return false
  VERIFIED_PLANS.delete(plan)
  clear(view.encoding)
  clear(view.planId32)
  clear(view.topologyGrantDigest32)
  clear(view.runId32)
  clear(view.local.identity32)
  clear(view.local.reflectionClaimDigest32)
  clear(view.local.nonce32)
  clear(view.peer.identity32)
  clear(view.peer.reflectionClaimDigest32)
  clear(view.peer.nonce32)
  clear(view.initiator.identity32)
  clear(view.initiator.reflectionClaimDigest32)
  clear(view.initiator.nonce32)
  clear(view.responder.identity32)
  clear(view.responder.reflectionClaimDigest32)
  clear(view.responder.nonce32)
  return true
}

function getPunchProfile(profileId = DEFAULT_PUNCH_PROFILE_ID) {
  return resolveProfile(profileId)
}

module.exports = Object.freeze({
  PLAN_FORMAT,
  MAX_PLAN_BYTES,
  MAX_PLAN_LIFETIME_MS,
  DEFAULT_PUNCH_PROFILE_ID,
  PUNCH_PROFILES,
  DOMAIN_NAT_PUNCH_PLAN,
  encodeUnsignedNatPunchPlan,
  encodeNatPunchPlan,
  signNatPunchPlan,
  signNatPunchPlanSide,
  verifyNatPunchPlan,
  readVerifiedNatPunchPlan,
  clearVerifiedNatPunchPlan,
  getPunchProfile
})
