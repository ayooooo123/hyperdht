'use strict'

// The authenticated simultaneous punch plan. KI-13's production half.
//
// Two peers behind NATs open a path neither can open alone: each sends UDP
// datagrams to the address the other will send from, and the sends must cross in
// flight so each host's mapping exists before the other's packets arrive. The
// datagram content is irrelevant; the send is the whole point.
//
// WHO may punch WHOM is an authorization question, and this codebase answers
// those with topology-authority signatures. A punch is a reachability grant: it
// tells each side the reflected address of the other, which a link grant also
// names. So the punch plan is signed the same way a topology grant is, by the
// same authority, over a canonical encoding that binds:
//
//   - both peer identities (so a plan for peer A cannot be replayed by peer B),
//   - both published endpoint tuples (the reflected addresses and the exact
//     ports the peers will punch from, which is the only mapping a punch opens),
//   - the epoch and run id (so a plan from one topology epoch is dead in the
//     next),
//   - a validity window (notBefore/expiresAt, wall-clock milliseconds, so a
//     captured plan dies with its run),
//   - a plan id (so the two sides can agree they hold the SAME plan, which is
//     what makes the simultaneous round simultaneous).
//
// The plan authorizes the PUNCH ROUND ONLY. A datagram that arrives tagged as a
// punch is counted as evidence of connectivity and nothing else: it never
// advances a bootstrap session, never opens a send handle, and never stands in
// for the signed grant the link itself requires. Spoofed punch traffic can
// therefore inflate nothing that matters - at worst it burns a few sends.

const b4a = require('b4a')

const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')
const { DOMAIN, PROTOCOL_VERSION } = require('./protocol')
const { hostFromAddress, parseAddress } = require('./topology-grant')

const PLAN_FORMAT = 0
const SIGNATURE_SIZE = 64
const MIN_UNSIGNED_SIZE = 173
const MAX_UNSIGNED_SIZE = 173
const MAX_PLAN_BYTES = MAX_UNSIGNED_SIZE + SIGNATURE_SIZE

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

function endpoint(value) {
  if (!exactKeys(value, ['identity32', 'role', 'host', 'port'])) invalid()
  if (!fixed(value.identity32, 32)) invalid()
  if (!Number.isInteger(value.port) || value.port < 1 || value.port > 0xffff) invalid()
  const address = parseAddress(value.host)
  return {
    identity32: b4a.from(value.identity32),
    role: value.role,
    address: { ...address, port: value.port }
  }
}

function copyEndpoint(value) {
  return {
    identity32: b4a.from(value.identity32),
    role: value.role,
    address: {
      family: value.address.family,
      host: value.address.host,
      port: value.address.port
    }
  }
}

function normalizePlan(value, signed) {
  const fields = [
    'version',
    'format',
    'planId32',
    'endpointA',
    'endpointB',
    'epoch',
    'notBefore',
    'expiresAt',
    'runId32'
  ]
  if (signed) fields.push('signature')
  if (!exactKeys(value, fields)) invalid()
  if (value.version !== PROTOCOL_VERSION || value.format !== PLAN_FORMAT) invalid()
  if (!fixed(value.planId32, 32) || !fixed(value.runId32, 32)) invalid()
  if (!validU64(value.epoch) || !validU64(value.notBefore) || !validU64(value.expiresAt)) invalid()
  if (value.notBefore >= value.expiresAt) invalid()
  if (signed && !fixed(value.signature, SIGNATURE_SIZE)) invalid()

  let a = endpoint(value.endpointA)
  let b = endpoint(value.endpointB)
  const ordering = b4a.compare(a.identity32, b.identity32)
  if (ordering === 0) invalid()
  if (ordering > 0) [a, b] = [b, a]

  return {
    version: value.version,
    format: PLAN_FORMAT,
    planId32: b4a.from(value.planId32),
    endpointA: a,
    endpointB: b,
    epoch: value.epoch,
    notBefore: value.notBefore,
    expiresAt: value.expiresAt,
    runId32: b4a.from(value.runId32),
    ...(signed ? { signature: b4a.from(value.signature) } : {})
  }
}

function writeU64(buffer, value, offset) {
  for (let shift = 56n; shift >= 0n; shift -= 8n)
    buffer[offset++] = Number((value >> shift) & 0xffn)
  return offset
}

function writeEndpoint(buffer, value, offset) {
  buffer.set(value.identity32, offset)
  offset += 32
  buffer[offset++] = value.role
  buffer[offset++] = value.address.family
  buffer.set(value.address.bytes, offset)
  offset += value.address.bytes.byteLength
  buffer[offset++] = value.address.port >>> 8
  buffer[offset++] = value.address.port & 0xff
  return offset
}

function encodeNormalizedUnsigned(value) {
  const size =
    4 + 1 + 32 + (32 + 1 + 1 + value.endpointA.address.bytes.byteLength + 2) * 2 + 8 + 8 + 8 + 32
  const buffer = b4a.allocUnsafe(size)
  let offset = 0
  buffer[offset++] = (value.version >>> 24) & 0xff
  buffer[offset++] = (value.version >>> 16) & 0xff
  buffer[offset++] = (value.version >>> 8) & 0xff
  buffer[offset++] = value.version & 0xff
  buffer[offset++] = value.format
  buffer.set(value.planId32, offset)
  offset += 32
  offset = writeEndpoint(buffer, value.endpointA, offset)
  offset = writeEndpoint(buffer, value.endpointB, offset)
  offset = writeU64(buffer, value.epoch, offset)
  offset = writeU64(buffer, value.notBefore, offset)
  offset = writeU64(buffer, value.expiresAt, offset)
  buffer.set(value.runId32, offset)
  return buffer
}

function createReader(buffer) {
  if (
    !b4a.isBuffer(buffer) ||
    buffer.byteLength < MIN_UNSIGNED_SIZE ||
    buffer.byteLength > MAX_UNSIGNED_SIZE + SIGNATURE_SIZE
  ) {
    invalid()
  }
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

function decodeEndpoint(reader) {
  const identity32 = reader.take(32)
  const role = reader.u8()
  const family = reader.u8()
  if (family !== 4 && family !== 6) invalid()
  const address = reader.take(family === 4 ? 4 : 16)
  return {
    identity32,
    role,
    host: hostFromAddress(family, address),
    port: reader.u16()
  }
}

function decodeValue(buffer, signed) {
  if (!b4a.isBuffer(buffer)) invalid()
  const minimum = MIN_UNSIGNED_SIZE + (signed ? SIGNATURE_SIZE : 0)
  const maximum = MAX_UNSIGNED_SIZE + (signed ? SIGNATURE_SIZE : 0)
  if (buffer.byteLength < minimum || buffer.byteLength > maximum) invalid()
  const reader = createReader(buffer)
  const value = {
    version: reader.u32(),
    format: reader.u8(),
    planId32: reader.take(32),
    endpointA: decodeEndpoint(reader),
    endpointB: decodeEndpoint(reader),
    epoch: reader.u64(),
    notBefore: reader.u64(),
    expiresAt: reader.u64(),
    runId32: reader.take(32)
  }
  if (signed) value.signature = reader.take(SIGNATURE_SIZE)
  reader.done()
  const normalized = normalizePlan(value, signed)
  if (!b4a.equals(normalized.endpointA.identity32, value.endpointA.identity32)) invalid()
  return {
    version: normalized.version,
    format: normalized.format,
    planId32: normalized.planId32,
    endpointA: publicEndpoint(normalized.endpointA),
    endpointB: publicEndpoint(normalized.endpointB),
    epoch: normalized.epoch,
    notBefore: normalized.notBefore,
    expiresAt: normalized.expiresAt,
    runId32: normalized.runId32,
    ...(signed ? { signature: normalized.signature } : {})
  }
}

function publicEndpoint(value) {
  return {
    identity32: b4a.from(value.identity32),
    role: value.role,
    host: value.address.host,
    port: value.address.port
  }
}

function encodeUnsignedPlan(value) {
  return encodeNormalizedUnsigned(normalizePlan(value, false))
}

function encodeNatPunchPlan(value) {
  const normalized = normalizePlan(value, true)
  return b4a.concat([encodeNormalizedUnsigned(normalized), normalized.signature])
}

function signNatPunchPlan(value, secretKey) {
  const unsigned = encodeUnsignedPlan(value)
  const digest = cryptoSuite.hash([DOMAIN.NAT_PUNCH_PLAN, unsigned])
  const signature = cryptoSuite.sign(digest, secretKey)
  return b4a.concat([unsigned, signature])
}

// Verifies an encoded plan against the topology authority and returns the side
// of the named identity. The endpoint ordering is canonical, so a plan and its
// mirror verify to the same bytes: both peers receive one encoding and each
// reads out its own view.
function verifyNatPunchPlan(encoding, authorityPublicKey, options) {
  if (!fixed(authorityPublicKey, 32)) unauthorized()
  if (!exactKeys(options, ['localIdentity32', 'now'])) invalid()
  if (!fixed(options.localIdentity32, 32) || !validU64(options.now)) invalid()

  const unsigned = b4a.from(encoding.subarray(0, encoding.byteLength - SIGNATURE_SIZE))
  const signedDigest = cryptoSuite.hash([DOMAIN.NAT_PUNCH_PLAN, unsigned])
  const decoded = decodeValue(encoding, true)
  if (!cryptoSuite.verify(signedDigest, decoded.signature, authorityPublicKey)) unauthorized()
  if (options.now < decoded.notBefore || options.now >= decoded.expiresAt) unauthorized()

  let local = decoded.endpointA
  let peer = decoded.endpointB
  if (b4a.equals(options.localIdentity32, decoded.endpointB.identity32)) {
    local = decoded.endpointB
    peer = decoded.endpointA
  } else if (!b4a.equals(options.localIdentity32, decoded.endpointA.identity32)) {
    unauthorized()
  }

  return Object.freeze({
    planId32: b4a.from(decoded.planId32),
    epoch: decoded.epoch,
    notBefore: decoded.notBefore,
    expiresAt: decoded.expiresAt,
    runId32: b4a.from(decoded.runId32),
    local: {
      identity32: b4a.from(local.identity32),
      role: local.role,
      host: local.host,
      port: local.port
    },
    peer: {
      identity32: b4a.from(peer.identity32),
      role: peer.role,
      host: peer.host,
      port: peer.port
    }
  })
}

module.exports = Object.freeze({
  PLAN_FORMAT,
  MAX_PLAN_BYTES,
  encodeUnsignedPlan,
  encodeNatPunchPlan,
  signNatPunchPlan,
  verifyNatPunchPlan,
  copyEndpoint
})
