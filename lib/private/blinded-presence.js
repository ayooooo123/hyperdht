'use strict'

// Gate D: address-free private presence records under blinded Ed25519 keys.
//
// Seat decisions:
// - Storage key is the DHT mutable target = generichash(A'). A separate k_e
//   address domain is NOT available under the mutable contract; the blinded
//   public key A' is both the verification key and the storage-key input.
// - Owner authentication is the DHT mutable signature under a' over
//   NS.MUTABLE_PUT || generichash(encode(mutableSignable{seq,value})). Type,
//   period, scope, target, and descriptor length sit inside the AEAD body, so a
//   reader-credential holder cannot re-seal without a'.
// - Highest revision wins: an owner-signed DESCRIPTOR at a higher revision than
//   a PERIOD tombstone re-enables presence (owner choice).
// - No JavaScript scalar arithmetic. Blinding and signing use native
//   crypto_core_ed25519_scalar_* and crypto_scalarmult_ed25519_* only.

const b4a = require('b4a')
const c = require('compact-encoding')
const sodium = require('sodium-universal')

const { NS } = require('../constants')
const m = require('../messages')
const Persistent = require('../persistent')
const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')

if (typeof sodium.crypto_core_ed25519_scalar_mul !== 'function') {
  throw new Error(
    'Gate D requires sodium.crypto_core_ed25519_scalar_mul (native scalar×scalar); no fallback'
  )
}

const PRESENCE_RECORD_VERSION = 1
const PRESENCE_RECORD_SIZE = 895
const HEADER_BYTES = 1 + 4 + 16 // version | revision | noncePrefix
const AEAD_TAG_BYTES = 16
const BODY_FIXED_BYTES = 1 + 8 + 1 + 32 + 2 // type|period|scope|target|descriptorLength
const MAX_DESCRIPTOR_BYTES = PRESENCE_RECORD_SIZE - HEADER_BYTES - AEAD_TAG_BYTES - BODY_FIXED_BYTES

const RECORD_TYPE = Object.freeze({
  DESCRIPTOR: 1,
  TOMBSTONE: 2
})

const TOMBSTONE_SCOPE = Object.freeze({
  PERIOD: 1,
  RECORD: 2
})

const PERIOD_MS = 86_400_000n
const OVERLAP_MS = 3_600_000n
const MAX_UINT64 = 0xffff_ffff_ffff_ffffn
const MAX_UINT32 = 0xffff_ffff
const MAX_UINT16 = 0xffff

const BLIND_DOMAIN = b4a.from('hyperdht-private-routes/presence/blind/v1\n')
const NONCE_DOMAIN = b4a.from('hyperdht-private-routes/presence/nonce/v1\n')
const AD_DOMAIN = b4a.from('hyperdht-private-routes/presence/ad/v1\n')
const READER_DOMAIN = b4a.from('hyperdht-private-routes/presence/reader/v1\n')

const ZERO32 = b4a.alloc(32)
const signerState = new WeakMap()

function clear(buffer) {
  if (b4a.isBuffer(buffer)) buffer.fill(0)
}

function isFixed(value, size) {
  return b4a.isBuffer(value) && value.byteLength === size
}

function isUint64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= MAX_UINT64
}

function isUint32(value) {
  return Number.isInteger(value) && value >= 0 && value <= MAX_UINT32
}

function writeU64BE(target, value, offset) {
  target.writeBigUInt64BE(value, offset)
}

function writeU32BE(target, value, offset) {
  target.writeUInt32BE(value >>> 0, offset)
}

function writeU16BE(target, value, offset) {
  target.writeUInt16BE(value & 0xffff, offset)
}

function readU64BE(source, offset) {
  return source.readBigUInt64BE(offset)
}

function readU32BE(source, offset) {
  return source.readUInt32BE(offset)
}

function readU16BE(source, offset) {
  return source.readUInt16BE(offset)
}

function encodeU64BE(value) {
  const buffer = b4a.alloc(8)
  writeU64BE(buffer, value, 0)
  return buffer
}

function encodeU32BE(value) {
  const buffer = b4a.alloc(4)
  writeU32BE(buffer, value, 0)
  return buffer
}

function periodBytes(period) {
  const buffer = b4a.alloc(12)
  writeU64BE(buffer, period, 0)
  writeU32BE(buffer, Number(PERIOD_MS), 8)
  return buffer
}

function isAllZero(buffer) {
  for (let i = 0; i < buffer.byteLength; i++) {
    if (buffer[i] !== 0) return false
  }
  return true
}

function clampScalar(scalar) {
  scalar[0] &= 248
  scalar[31] &= 63
  scalar[31] |= 64
}

function hashSha512(parts) {
  const input = b4a.concat(parts)
  const out = b4a.alloc(64)
  try {
    sodium.crypto_hash_sha512(out, input)
    return out
  } finally {
    clear(input)
  }
}

function reduceScalar(hash64) {
  const scalar = b4a.alloc(32)
  sodium.crypto_core_ed25519_scalar_reduce(scalar, hash64)
  return scalar
}

function deriveBlindingMaterial(identityPublicKey, period, identitySecretKey) {
  if (!isFixed(identityPublicKey, 32)) throw PrivateRouteError.INVALID_KEY()
  if (!isUint64(period)) throw PrivateRouteError.INVALID_DESCRIPTOR()

  let expanded = null
  let a = null
  let nonceRoot = null
  let hIn = null
  let h = null
  let aPrime = null
  let APrime = null
  let check = null
  let ownedSeed = null

  try {
    if (identitySecretKey !== null) {
      if (!isFixed(identitySecretKey, 64)) throw PrivateRouteError.INVALID_KEY()
      ownedSeed = b4a.from(identitySecretKey.subarray(0, 32))
      expanded = b4a.alloc(64)
      sodium.crypto_hash_sha512(expanded, ownedSeed)
      a = b4a.from(expanded.subarray(0, 32))
      clampScalar(a)
      nonceRoot = b4a.from(expanded.subarray(32, 64))
    }

    hIn = hashSha512([BLIND_DOMAIN, identityPublicKey, periodBytes(period)])
    h = reduceScalar(hIn)
    if (isAllZero(h)) throw PrivateRouteError.INVALID_KEY()

    APrime = b4a.alloc(32)
    sodium.crypto_scalarmult_ed25519_noclamp(APrime, h, identityPublicKey)
    if (!sodium.crypto_core_ed25519_is_valid_point(APrime)) {
      throw PrivateRouteError.INVALID_KEY()
    }

    if (a !== null) {
      aPrime = b4a.alloc(32)
      sodium.crypto_core_ed25519_scalar_mul(aPrime, h, a)
      check = b4a.alloc(32)
      sodium.crypto_scalarmult_ed25519_base_noclamp(check, aPrime)
      if (!b4a.equals(check, APrime)) throw PrivateRouteError.INVALID_KEY()
    }

    const result = {
      publicKey: b4a.from(APrime),
      secretScalar: aPrime === null ? null : b4a.from(aPrime),
      nonceRoot: nonceRoot === null ? null : b4a.from(nonceRoot),
      blindingScalar: b4a.from(h)
    }
    return result
  } finally {
    clear(expanded)
    clear(a)
    clear(nonceRoot)
    clear(hIn)
    clear(h)
    clear(aPrime)
    clear(APrime)
    clear(check)
    clear(ownedSeed)
  }
}

function deriveBlindedPublicKey(identityPublicKey, period) {
  const material = deriveBlindingMaterial(identityPublicKey, period, null)
  try {
    return material.publicKey
  } finally {
    clear(material.blindingScalar)
  }
}

function signUnderBlinded(state, message) {
  if (!b4a.isBuffer(message)) throw PrivateRouteError.INVALID_DESCRIPTOR()

  let rIn = null
  let r = null
  let R = null
  let kIn = null
  let k = null
  let ka = null
  let S = null
  let signature = null

  try {
    rIn = hashSha512([NONCE_DOMAIN, state.nonceRoot, state.blindingScalar, message])
    r = reduceScalar(rIn)
    R = b4a.alloc(32)
    sodium.crypto_scalarmult_ed25519_base_noclamp(R, r)

    kIn = hashSha512([R, state.publicKey, message])
    k = reduceScalar(kIn)
    ka = b4a.alloc(32)
    sodium.crypto_core_ed25519_scalar_mul(ka, k, state.secretScalar)
    S = b4a.alloc(32)
    sodium.crypto_core_ed25519_scalar_add(S, r, ka)

    signature = b4a.alloc(64)
    signature.set(R, 0)
    signature.set(S, 32)
    return signature
  } finally {
    clear(rIn)
    clear(r)
    clear(R)
    clear(kIn)
    clear(k)
    clear(ka)
    clear(S)
  }
}

function createBlindedSigner(identityKeyPair, period) {
  if (
    !identityKeyPair ||
    !isFixed(identityKeyPair.publicKey, 32) ||
    !isFixed(identityKeyPair.secretKey, 64)
  ) {
    throw PrivateRouteError.INVALID_KEY()
  }

  const material = deriveBlindingMaterial(
    identityKeyPair.publicKey,
    period,
    identityKeyPair.secretKey
  )

  const state = {
    live: true,
    publicKey: material.publicKey,
    secretScalar: material.secretScalar,
    nonceRoot: material.nonceRoot,
    blindingScalar: material.blindingScalar
  }

  const authority = Object.freeze({
    publicKey: b4a.from(state.publicKey),
    sign(message) {
      const current = signerState.get(authority)
      if (!current || !current.live) throw PrivateRouteError.UNAUTHORIZED()
      if (!b4a.isBuffer(message)) throw PrivateRouteError.INVALID_DESCRIPTOR()
      return signUnderBlinded(current, message)
    },
    destroy() {
      const current = signerState.get(authority)
      if (!current || !current.live) return
      current.live = false
      clear(current.secretScalar)
      clear(current.nonceRoot)
      clear(current.blindingScalar)
      clear(current.publicKey)
    }
  })

  signerState.set(authority, state)
  return authority
}

function periodOf(wallMs) {
  if (typeof wallMs !== 'number' || !Number.isFinite(wallMs) || wallMs < 0) {
    throw PrivateRouteError.INVALID_DESCRIPTOR()
  }
  return BigInt(Math.floor(wallMs / Number(PERIOD_MS)))
}

function publishPeriods(wallMs) {
  const current = periodOf(wallMs)
  const nextStart = (current + 1n) * PERIOD_MS
  if (BigInt(Math.floor(wallMs)) >= nextStart - OVERLAP_MS) {
    return [current, current + 1n]
  }
  return [current]
}

function lookupPeriods(wallMs) {
  const current = periodOf(wallMs)
  const currentStart = current * PERIOD_MS
  if (current > 0n && BigInt(Math.floor(wallMs)) < currentStart + OVERLAP_MS) {
    return [current, current - 1n]
  }
  return [current]
}

function buildAssociatedData(publicKey, version, period, revision) {
  const buffer = b4a.alloc(AD_DOMAIN.byteLength + 32 + 1 + 8 + 4)
  let offset = 0
  buffer.set(AD_DOMAIN, offset)
  offset += AD_DOMAIN.byteLength
  buffer.set(publicKey, offset)
  offset += 32
  buffer[offset++] = version
  writeU64BE(buffer, period, offset)
  offset += 8
  writeU32BE(buffer, revision, offset)
  return buffer
}

function deriveReaderKey(readerSecret, publicKey, period) {
  if (!isFixed(readerSecret, 32)) throw PrivateRouteError.INVALID_KEY()
  if (!isFixed(publicKey, 32)) throw PrivateRouteError.INVALID_KEY()
  if (!isUint64(period)) throw PrivateRouteError.INVALID_DESCRIPTOR()

  const input = b4a.concat([READER_DOMAIN, readerSecret, publicKey, encodeU64BE(period)])
  try {
    return cryptoSuite.hash([input])
  } finally {
    clear(input)
  }
}

function encodeBody({ type, period, tombstoneScope, tombstoneTarget, descriptor }) {
  if (type !== RECORD_TYPE.DESCRIPTOR && type !== RECORD_TYPE.TOMBSTONE) {
    throw PrivateRouteError.INVALID_DESCRIPTOR()
  }
  if (!isUint64(period)) throw PrivateRouteError.INVALID_DESCRIPTOR()

  const body = b4a.alloc(BODY_FIXED_BYTES + MAX_DESCRIPTOR_BYTES)
  body[0] = type
  writeU64BE(body, period, 1)
  body[9] = tombstoneScope
  body.set(tombstoneTarget, 10)

  if (type === RECORD_TYPE.DESCRIPTOR) {
    if (tombstoneScope !== 0 || !isAllZero(tombstoneTarget)) {
      throw PrivateRouteError.INVALID_DESCRIPTOR()
    }
    if (!b4a.isBuffer(descriptor) || descriptor.byteLength > MAX_DESCRIPTOR_BYTES) {
      throw PrivateRouteError.INVALID_DESCRIPTOR()
    }
    writeU16BE(body, descriptor.byteLength, 42)
    body.set(descriptor, 44)
  } else {
    if (descriptor !== null && descriptor !== undefined && descriptor.byteLength !== 0) {
      throw PrivateRouteError.INVALID_DESCRIPTOR()
    }
    if (tombstoneScope !== TOMBSTONE_SCOPE.PERIOD && tombstoneScope !== TOMBSTONE_SCOPE.RECORD) {
      throw PrivateRouteError.INVALID_DESCRIPTOR()
    }
    if (!isFixed(tombstoneTarget, 32)) throw PrivateRouteError.INVALID_DESCRIPTOR()
    if (tombstoneScope === TOMBSTONE_SCOPE.RECORD && isAllZero(tombstoneTarget)) {
      throw PrivateRouteError.INVALID_DESCRIPTOR()
    }
    if (tombstoneScope === TOMBSTONE_SCOPE.PERIOD && !isAllZero(tombstoneTarget)) {
      throw PrivateRouteError.INVALID_DESCRIPTOR()
    }
    writeU16BE(body, 0, 42)
  }

  return body
}

function encodePresenceRecord(options) {
  if (!options || typeof options !== 'object') throw PrivateRouteError.INVALID_DESCRIPTOR()

  const signer = options.signer
  const period = options.period
  const revision = options.revision
  const readerSecret = options.readerSecret
  const type = options.type

  if (!signer || typeof signer.sign !== 'function' || !isFixed(signer.publicKey, 32)) {
    throw PrivateRouteError.INVALID_KEY()
  }
  if (!isUint64(period)) throw PrivateRouteError.INVALID_DESCRIPTOR()
  if (!isUint32(revision)) throw PrivateRouteError.INVALID_DESCRIPTOR()
  if (!isFixed(readerSecret, 32)) throw PrivateRouteError.INVALID_KEY()

  let descriptor = null
  let tombstoneScope = 0
  let tombstoneTarget = ZERO32

  if (type === RECORD_TYPE.DESCRIPTOR) {
    descriptor = options.descriptor
    if (!b4a.isBuffer(descriptor)) throw PrivateRouteError.INVALID_DESCRIPTOR()
    if (descriptor.byteLength > MAX_DESCRIPTOR_BYTES) {
      throw PrivateRouteError.INVALID_DESCRIPTOR()
    }
  } else if (type === RECORD_TYPE.TOMBSTONE) {
    const tombstone = options.tombstone
    if (!tombstone || typeof tombstone !== 'object') throw PrivateRouteError.INVALID_DESCRIPTOR()
    tombstoneScope = tombstone.scope
    if (tombstoneScope === TOMBSTONE_SCOPE.RECORD) {
      if (!isFixed(tombstone.target, 32) || isAllZero(tombstone.target)) {
        throw PrivateRouteError.INVALID_DESCRIPTOR()
      }
      tombstoneTarget = tombstone.target
    } else if (tombstoneScope === TOMBSTONE_SCOPE.PERIOD) {
      tombstoneTarget = ZERO32
    } else {
      throw PrivateRouteError.INVALID_DESCRIPTOR()
    }
    descriptor = null
  } else {
    throw PrivateRouteError.INVALID_DESCRIPTOR()
  }

  const publicKey = b4a.from(signer.publicKey)
  const noncePrefix = cryptoSuite.randomBytes(16)
  let body = null
  let readerKey = null
  let associatedData = null
  let ciphertext = null
  let value = null

  try {
    body = encodeBody({
      type,
      period,
      tombstoneScope,
      tombstoneTarget,
      descriptor
    })
    readerKey = deriveReaderKey(readerSecret, publicKey, period)
    associatedData = buildAssociatedData(publicKey, PRESENCE_RECORD_VERSION, period, revision)
    ciphertext = cryptoSuite.seal({
      key: readerKey,
      noncePrefix,
      counter: 0n,
      associatedData,
      plaintext: body
    })

    if (ciphertext.byteLength !== BODY_FIXED_BYTES + MAX_DESCRIPTOR_BYTES + AEAD_TAG_BYTES) {
      throw PrivateRouteError.INVALID_DESCRIPTOR()
    }

    value = b4a.alloc(PRESENCE_RECORD_SIZE)
    value[0] = PRESENCE_RECORD_VERSION
    writeU32BE(value, revision, 1)
    value.set(noncePrefix, 5)
    value.set(ciphertext, HEADER_BYTES)

    if (value.byteLength !== PRESENCE_RECORD_SIZE) {
      throw PrivateRouteError.INVALID_DESCRIPTOR()
    }

    const frozenPublicKey = b4a.from(publicKey)
    const frozenRevision = revision

    return Object.freeze({
      publicKey: frozenPublicKey,
      seq: frozenRevision,
      value,
      signMutable(seq, recordValue, keyPair) {
        if (seq !== frozenRevision) throw PrivateRouteError.UNAUTHORIZED()
        if (
          !keyPair ||
          !isFixed(keyPair.publicKey, 32) ||
          !b4a.equals(keyPair.publicKey, frozenPublicKey)
        ) {
          throw PrivateRouteError.UNAUTHORIZED()
        }
        if (!isFixed(recordValue, PRESENCE_RECORD_SIZE)) {
          throw PrivateRouteError.INVALID_DESCRIPTOR()
        }

        const signable = b4a.allocUnsafe(64)
        signable.set(NS.MUTABLE_PUT, 0)
        sodium.crypto_generichash(
          signable.subarray(32),
          c.encode(m.mutableSignable, { seq, value: recordValue })
        )
        return signer.sign(signable)
      }
    })
  } finally {
    clear(body)
    clear(readerKey)
    clear(associatedData)
    clear(ciphertext)
    clear(noncePrefix)
    clear(publicKey)
  }
}

function openPresenceRecord(options) {
  if (!options || typeof options !== 'object') throw PrivateRouteError.INVALID_DESCRIPTOR()

  const identityPublicKey = options.identityPublicKey
  const period = options.period
  const revision = options.revision
  const readerSecret = options.readerSecret
  const value = options.value
  const signature = options.signature

  if (!isFixed(identityPublicKey, 32)) throw PrivateRouteError.INVALID_KEY()
  if (!isUint64(period)) throw PrivateRouteError.INVALID_DESCRIPTOR()
  if (!isUint32(revision)) throw PrivateRouteError.INVALID_DESCRIPTOR()
  if (!isFixed(readerSecret, 32)) throw PrivateRouteError.INVALID_KEY()
  if (!isFixed(value, PRESENCE_RECORD_SIZE)) throw PrivateRouteError.INVALID_DESCRIPTOR()
  if (!isFixed(signature, 64)) throw PrivateRouteError.ERR_AUTHENTICATION()

  const expectedPublicKey = deriveBlindedPublicKey(identityPublicKey, period)
  let readerKey = null
  let associatedData = null
  let plaintext = null

  try {
    if (value[0] !== PRESENCE_RECORD_VERSION) throw PrivateRouteError.INVALID_DESCRIPTOR()
    const headerRevision = readU32BE(value, 1)
    if (headerRevision !== revision) throw PrivateRouteError.INVALID_DESCRIPTOR()

    if (!Persistent.verifyMutable(signature, revision, value, expectedPublicKey)) {
      throw PrivateRouteError.ERR_AUTHENTICATION()
    }

    const noncePrefix = value.subarray(5, 21)
    const ciphertext = value.subarray(HEADER_BYTES)
    readerKey = deriveReaderKey(readerSecret, expectedPublicKey, period)
    associatedData = buildAssociatedData(
      expectedPublicKey,
      PRESENCE_RECORD_VERSION,
      period,
      revision
    )

    plaintext = cryptoSuite.open({
      key: readerKey,
      noncePrefix,
      counter: 0n,
      associatedData,
      ciphertext
    })

    if (plaintext === null) throw PrivateRouteError.ERR_AUTHENTICATION()
    if (plaintext.byteLength !== BODY_FIXED_BYTES + MAX_DESCRIPTOR_BYTES) {
      throw PrivateRouteError.INVALID_DESCRIPTOR()
    }

    const type = plaintext[0]
    const innerPeriod = readU64BE(plaintext, 1)
    if (innerPeriod !== period) throw PrivateRouteError.INVALID_DESCRIPTOR()

    const tombstoneScope = plaintext[9]
    const tombstoneTarget = b4a.from(plaintext.subarray(10, 42))
    const descriptorLength = readU16BE(plaintext, 42)
    if (descriptorLength > MAX_DESCRIPTOR_BYTES) throw PrivateRouteError.INVALID_DESCRIPTOR()

    const descriptorRegion = plaintext.subarray(44, 44 + MAX_DESCRIPTOR_BYTES)
    for (let i = descriptorLength; i < MAX_DESCRIPTOR_BYTES; i++) {
      if (descriptorRegion[i] !== 0) throw PrivateRouteError.INVALID_DESCRIPTOR()
    }

    if (type === RECORD_TYPE.DESCRIPTOR) {
      if (tombstoneScope !== 0 || !isAllZero(tombstoneTarget)) {
        throw PrivateRouteError.INVALID_DESCRIPTOR()
      }
      return Object.freeze({
        type,
        period,
        revision,
        descriptor: b4a.from(descriptorRegion.subarray(0, descriptorLength))
      })
    }

    if (type === RECORD_TYPE.TOMBSTONE) {
      if (descriptorLength !== 0) throw PrivateRouteError.INVALID_DESCRIPTOR()
      if (tombstoneScope !== TOMBSTONE_SCOPE.PERIOD && tombstoneScope !== TOMBSTONE_SCOPE.RECORD) {
        throw PrivateRouteError.INVALID_DESCRIPTOR()
      }
      if (tombstoneScope === TOMBSTONE_SCOPE.RECORD && isAllZero(tombstoneTarget)) {
        throw PrivateRouteError.INVALID_DESCRIPTOR()
      }
      if (tombstoneScope === TOMBSTONE_SCOPE.PERIOD && !isAllZero(tombstoneTarget)) {
        throw PrivateRouteError.INVALID_DESCRIPTOR()
      }
      return Object.freeze({
        type,
        period,
        revision,
        tombstone: Object.freeze({
          scope: tombstoneScope,
          target: tombstoneTarget
        })
      })
    }

    throw PrivateRouteError.INVALID_DESCRIPTOR()
  } finally {
    clear(readerKey)
    clear(associatedData)
    clear(plaintext)
  }
}

function recordDigestOf(value) {
  if (!isFixed(value, PRESENCE_RECORD_SIZE)) throw PrivateRouteError.INVALID_DESCRIPTOR()
  return cryptoSuite.hash([value])
}

function resolvePresenceState({ previous, opened }) {
  if (!opened || typeof opened !== 'object') throw PrivateRouteError.INVALID_DESCRIPTOR()
  if (!isUint32(opened.revision) || !isUint64(opened.period) || !isFixed(opened.recordDigest, 32))
    throw PrivateRouteError.INVALID_DESCRIPTOR()

  const samePeriod = previous != null && previous.period === opened.period
  const sameRecord =
    samePeriod &&
    opened.revision === previous.revision &&
    isFixed(previous.recordDigest, 32) &&
    b4a.equals(opened.recordDigest, previous.recordDigest)
  if (
    samePeriod &&
    isUint32(previous.revision) &&
    (opened.revision < previous.revision || (opened.revision === previous.revision && !sameRecord))
  ) {
    throw PrivateRouteError.REPLAY()
  }

  if (opened.type === RECORD_TYPE.TOMBSTONE) {
    const scope = opened.tombstone && opened.tombstone.scope
    const state = {
      period: opened.period,
      revision: opened.revision,
      recordDigest: b4a.from(opened.recordDigest)
    }
    if (scope === TOMBSTONE_SCOPE.PERIOD) {
      return Object.freeze({ present: false, ...state })
    }
    if (scope === TOMBSTONE_SCOPE.RECORD) {
      if (sameRecord && previous.present === false) {
        return Object.freeze({ present: false, ...state })
      }
      const target = opened.tombstone.target
      if (
        samePeriod &&
        isFixed(previous.recordDigest, 32) &&
        isFixed(target, 32) &&
        b4a.equals(target, previous.recordDigest)
      ) {
        return Object.freeze({ present: false, ...state })
      }
      return Object.freeze({ present: null, ignoredTombstone: true, ...state })
    }
    throw PrivateRouteError.INVALID_DESCRIPTOR()
  }

  if (opened.type === RECORD_TYPE.DESCRIPTOR) {
    if (!b4a.isBuffer(opened.descriptor)) throw PrivateRouteError.INVALID_DESCRIPTOR()
    return Object.freeze({
      present: true,
      descriptor: b4a.from(opened.descriptor),
      period: opened.period,
      revision: opened.revision,
      recordDigest: b4a.from(opened.recordDigest)
    })
  }

  throw PrivateRouteError.INVALID_DESCRIPTOR()
}

module.exports = {
  PRESENCE_RECORD_VERSION,
  PRESENCE_RECORD_SIZE,
  RECORD_TYPE,
  TOMBSTONE_SCOPE,
  PERIOD_MS,
  OVERLAP_MS,
  MAX_DESCRIPTOR_BYTES,
  deriveBlindedPublicKey,
  createBlindedSigner,
  periodOf,
  publishPeriods,
  lookupPeriods,
  encodePresenceRecord,
  openPresenceRecord,
  recordDigestOf,
  resolvePresenceState
}
