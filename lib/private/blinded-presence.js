'use strict'

// Gate D host-path boundary: canonical fixed padded private presence records
// with epoch-scoped addressing and reader-credential encryption.
//
// Status of this slice, stated plainly:
// - Owner authentication is a stable-identity certificate over an epoch
//   keypair. The certificate is carried inside the encrypted payload, so a
//   reader credential is required to verify ownership. A credential holder
//   can decrypt but cannot mint records: the certificate is made with the
//   stable secret key, which readers do not hold.
// - Epoch keys are hash-ratcheted from the identity seed, the same pattern as
//   the session keys in crypto-suite, not algebraically blinded. Multiplicative
//   blinding (a' = h*a, public verification under a blinded key) needs a
//   scalar-on-scalar multiply that this dependency tree does not export; see
//   the Gate D record in docs/private-routing-migration.md.
// - Point blinding itself (A' = h*A) is the Tor v3 construction and the native
//   primitive used here is pinned against Tor's published test vector in
//   test/private/blinded-presence.js.
// - There is no public export, no public required mode, and no exit-side
//   presence command. DHT-exit_io admits immutable get only, so the routed
//   integration fetches records by content hash; storage-key addressing is
//   provided and verified here but the exit does not yet resolve it.

const b4a = require('b4a')
const sodium = require('sodium-universal')

const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')

const EPOCH_ADDRESS_DOMAIN = b4a.from('hyperdht-private-routes/presence/epoch-address/v1\n')
const EPOCH_KEY_DOMAIN = b4a.from('hyperdht-private-routes/presence/epoch-key/v1\n')
const EPOCH_CERTIFICATE_DOMAIN = b4a.from('hyperdht-private-routes/presence/epoch-certificate/v1\n')

const RECORD_SIZE = 1023 // dht-exit-wire MAX_IMMUTABLE_VALUE_BYTES
const RECORD_VERSION_DESCRIPTOR = 1
const RECORD_VERSION_TOMBSTONE = 2
const EPOCH_BYTES = 8
const RESERVED_BYTES = 31
const ADDRESS_BYTES = 32
const HEADER_BYTES = 1 + EPOCH_BYTES + RESERVED_BYTES + ADDRESS_BYTES
const NONCE_PREFIX_BYTES = 16
const COUNTER_BYTES = 8
const TAG_BYTES = 16
const PLAINTEXT_BYTES = RECORD_SIZE - HEADER_BYTES - NONCE_PREFIX_BYTES - COUNTER_BYTES - TAG_BYTES
const EPOCH_KEY_BYTES = 32
const SIGNATURE_BYTES = 64
const BODY_OFFSET = EPOCH_KEY_BYTES + SIGNATURE_BYTES
const MAX_DESCRIPTOR_BYTES = PLAINTEXT_BYTES - BODY_OFFSET
const ZERO = b4a.alloc(32)

const EPOCH_MS = 604_800_000n // 7 days
const OVERLAP_MS = 86_400_000n // 1 day, Tor-style publish-before/keep-after

const MAX_UINT64 = 0xffff_ffff_ffff_ffffn

function invalid() {
  throw PrivateRouteError.INVALID_DESCRIPTOR()
}

function key() {
  throw PrivateRouteError.INVALID_KEY()
}

function clear(buffer) {
  if (b4a.isBuffer(buffer)) buffer.fill(0)
}

function exactOwnData(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid()
  if (Reflect.ownKeys(value).length !== fields.length) invalid()
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field)
    if (!descriptor || !('value' in descriptor)) invalid()
  }
}

function fixed(value, size) {
  return b4a.isBuffer(value) && value.byteLength === size
}

function uint64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= MAX_UINT64
}

function encodeEpoch(epoch) {
  const buffer = b4a.alloc(EPOCH_BYTES)
  buffer.writeBigUInt64BE(epoch, 0)
  return buffer
}

function deriveEpochAddressKey(identityPublicKey, epoch) {
  if (!fixed(identityPublicKey, 32)) key()
  if (!uint64(epoch)) invalid()
  const input = b4a.concat([EPOCH_ADDRESS_DOMAIN, identityPublicKey, encodeEpoch(epoch)])
  try {
    return cryptoSuite.hash([input])
  } finally {
    clear(input)
  }
}

// Tor v3 [KEYBLIND] A.2: h = H(BLIND_STRING | A | s | B | N), clamped, with
// A' = h*A as a point multiplication. The digest here is keyed BLAKE2b-256
// (the repo derivation primitive) rather than Tor's SHA3-256, which is not
// exported by bare-crypto; portability of the clamp and of A' = h*A is what
// this slice needs, and the pinned Tor vector in the test suite proves the
// point-multiply path byte-for-byte.
function deriveEpochBlindingParam(identityPublicKey, epoch) {
  if (!fixed(identityPublicKey, 32)) key()
  if (!uint64(epoch)) invalid()
  const input = b4a.concat([
    EPOCH_KEY_DOMAIN,
    identityPublicKey,
    encodeEpoch(epoch),
    b4a.from(
      '(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)'
    )
  ])
  const param = cryptoSuite.hash([input])
  try {
    param[0] &= 248
    param[31] &= 63
    param[31] |= 64
    return param
  } finally {
    clear(input)
  }
}

// Tor v3 [KEYBLIND] A.2 public half: A' = h*A = (h*a)*B via the native
// constant-time point multiply. Cross-checked byte-exactly against Tor's
// published blinding vector.
function blindPublicKey(identityPublicKey, param) {
  if (!fixed(identityPublicKey, 32)) key()
  if (!fixed(param, 32)) key()
  const blinded = b4a.alloc(32)
  const ownedParam = b4a.from(param)
  try {
    ownedParam[0] &= 248
    ownedParam[31] &= 63
    ownedParam[31] |= 64
    sodium.crypto_scalarmult_ed25519_noclamp(blinded, ownedParam, identityPublicKey)
    return blinded
  } finally {
    clear(ownedParam)
  }
}

function deriveEpochKeyPair(identitySecretKey, epoch) {
  if (!fixed(identitySecretKey, 64)) key()
  if (!uint64(epoch)) invalid()
  // libsodium Ed25519 secret keys carry the 32-byte seed in their first half.
  const epochSeed = cryptoSuite.hash([
    EPOCH_KEY_DOMAIN,
    identitySecretKey.subarray(0, 32),
    encodeEpoch(epoch)
  ])
  try {
    return cryptoSuite.keyPair(epochSeed)
  } finally {
    clear(epochSeed)
  }
}

function epochCertificate(identityKeyPair, epochKeyPair, epoch, address, descriptorDigest) {
  if (
    !identityKeyPair ||
    !fixed(identityKeyPair.secretKey, 64) ||
    !fixed(identityKeyPair.publicKey, 32)
  )
    key()
  if (!epochKeyPair || !fixed(epochKeyPair.publicKey, 32)) key()
  if (!fixed(address, 32) || !fixed(descriptorDigest, 32)) invalid()
  const signable = b4a.concat([
    EPOCH_CERTIFICATE_DOMAIN,
    identityKeyPair.publicKey,
    epochKeyPair.publicKey,
    encodeEpoch(epoch),
    address,
    descriptorDigest
  ])
  try {
    return cryptoSuite.sign(signable, identityKeyPair.secretKey)
  } finally {
    clear(signable)
  }
}

function verifyEpochCertificate(
  identityPublicKey,
  epochKeyPair,
  epoch,
  address,
  descriptorDigest,
  signature
) {
  if (!fixed(identityPublicKey, 32)) return false
  if (!epochKeyPair || !fixed(epochKeyPair.publicKey, 32)) return false
  if (!fixed(address, 32) || !fixed(descriptorDigest, 32) || !fixed(signature, SIGNATURE_BYTES)) {
    return false
  }
  const signable = b4a.concat([
    EPOCH_CERTIFICATE_DOMAIN,
    identityPublicKey,
    epochKeyPair.publicKey,
    encodeEpoch(epoch),
    address,
    descriptorDigest
  ])
  try {
    return cryptoSuite.verify(signable, signature, identityPublicKey) === true
  } catch {
    return false
  } finally {
    clear(signable)
  }
}

function currentEpoch(wallMs) {
  if (typeof wallMs !== 'number' || !Number.isFinite(wallMs) || wallMs < 0) invalid()
  return BigInt(Math.floor(wallMs / Number(EPOCH_MS)))
}

// A host announces into the current epoch and the next one before it begins,
// so readers on either side of the boundary find it.
function announceEpochs(wallMs) {
  const current = currentEpoch(wallMs)
  return [current, current + 1n]
}

// A reader resolves the current epoch and keeps the previous one alive across
// the boundary, matching Tor's overlapping-descriptor window.
function lookupEpochs(wallMs) {
  const current = currentEpoch(wallMs)
  return current === 0n ? [current] : [current, current - 1n]
}

function encodeHeader(version, epoch, address) {
  const header = b4a.alloc(HEADER_BYTES)
  header[0] = version
  header.writeBigUInt64BE(epoch, 1)
  // reserved bytes stay zero: canonical fixed padding
  header.set(address, 1 + EPOCH_BYTES + RESERVED_BYTES)
  return header
}

function padBody(region, size) {
  if (!fixed(region, size)) invalid()
  for (let index = 0; index < region.byteLength; index++) {
    if (region[index] !== 0) invalid()
  }
}

function sealRecord(version, identityKeyPair, epoch, descriptor, readerSecret) {
  if (!fixed(readerSecret, 32)) key()
  if (!b4a.isBuffer(descriptor) || descriptor.byteLength > MAX_DESCRIPTOR_BYTES) invalid()
  if (!uint64(epoch)) invalid()

  const address = deriveEpochAddressKey(identityKeyPair.publicKey, epoch)
  const epochKeyPair = deriveEpochKeyPair(identityKeyPair.secretKey, epoch)
  const signature = epochCertificate(
    identityKeyPair,
    epochKeyPair,
    epoch,
    address,
    cryptoSuite.hash([descriptor, b4a.alloc(MAX_DESCRIPTOR_BYTES - descriptor.byteLength)])
  )
  const body = b4a.alloc(PLAINTEXT_BYTES)
  let record = null
  try {
    body.set(epochKeyPair.publicKey, 0)
    body.set(signature, EPOCH_KEY_BYTES)
    body.set(descriptor, BODY_OFFSET)
    const header = encodeHeader(version, epoch, address)
    const noncePrefix = cryptoSuite.randomBytes(NONCE_PREFIX_BYTES)
    const ciphertext = cryptoSuite.seal({
      key: readerSecret,
      noncePrefix,
      counter: 0n,
      associatedData: header,
      plaintext: body
    })
    record = b4a.concat([
      header,
      noncePrefix,
      encodeEpoch(0n).subarray(0, COUNTER_BYTES),
      ciphertext
    ])
    return Object.freeze({
      storageKey: address,
      epoch,
      epochPublicKey: b4a.from(epochKeyPair.publicKey),
      record: record
    })
  } finally {
    clear(body)
    if (record !== null && record !== undefined) {
      // record is returned; nothing else to clear here
    }
  }
}

function openRecord(recordBytes, readerSecret) {
  if (!fixed(recordBytes, RECORD_SIZE)) invalid()
  if (!fixed(readerSecret, 32)) key()
  const version = recordBytes[0]
  if (version !== RECORD_VERSION_DESCRIPTOR && version !== RECORD_VERSION_TOMBSTONE) invalid()
  const epoch = recordBytes.readBigUInt64BE(1)
  const reserved = recordBytes.subarray(1 + EPOCH_BYTES, 1 + EPOCH_BYTES + RESERVED_BYTES)
  padBody(reserved, RESERVED_BYTES)
  const address = b4a.from(recordBytes.subarray(HEADER_BYTES - ADDRESS_BYTES, HEADER_BYTES))
  const noncePrefix = b4a.from(
    recordBytes.subarray(HEADER_BYTES, HEADER_BYTES + NONCE_PREFIX_BYTES)
  )
  const ciphertext = b4a.from(
    recordBytes.subarray(HEADER_BYTES + NONCE_PREFIX_BYTES + COUNTER_BYTES)
  )
  const header = b4a.from(recordBytes.subarray(0, HEADER_BYTES))
  const plaintext = cryptoSuite.open({
    key: readerSecret,
    noncePrefix,
    counter: 0n,
    associatedData: header,
    ciphertext
  })
  if (plaintext === null) throw PrivateRouteError.ERR_AUTHENTICATION()
  return Object.freeze({ version, epoch, address, plaintext })
}

function assertOwnedRecord(publicKey, epoch, opened) {
  if (opened.epoch !== epoch) throw PrivateRouteError.REPLAY()
  const expectedAddress = deriveEpochAddressKey(publicKey, opened.epoch)
  if (!b4a.equals(expectedAddress, opened.address)) throw PrivateRouteError.ERR_AUTHENTICATION()
  return expectedAddress
}

function verifyEpochOwnership(publicKey, opened) {
  const epochPublicKey = b4a.from(opened.plaintext.subarray(0, EPOCH_KEY_BYTES))
  const signature = b4a.from(
    opened.plaintext.subarray(EPOCH_KEY_BYTES, EPOCH_KEY_BYTES + SIGNATURE_BYTES)
  )
  const descriptorDigest = cryptoSuite.hash([opened.plaintext.subarray(BODY_OFFSET)])
  if (
    !verifyEpochCertificate(
      publicKey,
      { publicKey: epochPublicKey },
      opened.epoch,
      opened.address,
      descriptorDigest,
      signature
    )
  ) {
    throw PrivateRouteError.ERR_AUTHENTICATION()
  }
  return epochPublicKey
}

// Publishes a presence descriptor for one epoch. Returns the storage address
// and the canonical fixed-size record bytes for the routed store.
function createPresenceRecord(options) {
  exactOwnData(options, ['identityKeyPair', 'epoch', 'descriptor', 'readerSecret'])
  const { identityKeyPair, epoch, descriptor, readerSecret } = options
  if (
    !identityKeyPair ||
    !fixed(identityKeyPair.secretKey, 64) ||
    !fixed(identityKeyPair.publicKey, 32)
  )
    key()
  if (!uint64(epoch)) invalid()
  return sealRecord(RECORD_VERSION_DESCRIPTOR, identityKeyPair, epoch, descriptor, readerSecret)
}

// Publishes an owner-signed tombstone. digest may be 32 zero bytes to kill
// every record of the epoch, or the exact hash of the record bytes it retires.
function createPresenceTombstone(options) {
  exactOwnData(options, ['identityKeyPair', 'epoch', 'digest', 'readerSecret'])
  const { identityKeyPair, epoch, digest, readerSecret } = options
  if (
    !identityKeyPair ||
    !fixed(identityKeyPair.secretKey, 64) ||
    !fixed(identityKeyPair.publicKey, 32)
  )
    key()
  if (!fixed(digest, 32)) invalid()
  return sealRecord(RECORD_VERSION_TOMBSTONE, identityKeyPair, epoch, digest, readerSecret)
}

// Resolves record bytes into a verified descriptor. Everything is verified
// before anything is returned: canonical padding, storage-key binding, epoch
// binding, and the stable-identity certificate over the epoch key.
function resolvePresenceRecord(options) {
  exactOwnData(options, ['publicKey', 'epoch', 'record', 'readerSecret'])
  const { publicKey, epoch, record, readerSecret } = options
  if (!fixed(publicKey, 32)) key()
  if (!uint64(epoch)) invalid()
  let opened = null
  try {
    opened = openRecord(record, readerSecret)
    if (opened.version !== RECORD_VERSION_DESCRIPTOR) invalid()
    assertOwnedRecord(publicKey, epoch, opened)
    const epochPublicKey = verifyEpochOwnership(publicKey, opened)
    const region = opened.plaintext.subarray(BODY_OFFSET)
    let end = region.byteLength
    while (end > 0 && region[end - 1] === 0) end--
    const descriptor = b4a.from(region.subarray(0, end))
    return Object.freeze({
      epoch: opened.epoch,
      storageKey: b4a.from(opened.address),
      epochPublicKey,
      descriptor
    })
  } finally {
    if (opened !== null) clear(opened.plaintext)
  }
}

function resolvePresenceTombstone(options) {
  exactOwnData(options, ['publicKey', 'epoch', 'record', 'readerSecret'])
  const { publicKey, epoch, record, readerSecret } = options
  if (!fixed(publicKey, 32)) key()
  if (!uint64(epoch)) invalid()
  let opened = null
  try {
    opened = openRecord(record, readerSecret)
    if (opened.version !== RECORD_VERSION_TOMBSTONE) invalid()
    assertOwnedRecord(publicKey, epoch, opened)
    const epochPublicKey = verifyEpochOwnership(publicKey, opened)
    const digest = b4a.from(opened.plaintext.subarray(BODY_OFFSET, BODY_OFFSET + 32))
    const pad = b4a.from(opened.plaintext.subarray(BODY_OFFSET + 32))
    padBody(pad, pad.byteLength)
    return Object.freeze({
      epoch: opened.epoch,
      storageKey: b4a.from(opened.address),
      epochPublicKey,
      digest
    })
  } finally {
    if (opened !== null) clear(opened.plaintext)
  }
}

// Tombstones win over descriptors: an epoch with a verified tombstone resolves
// to null. A tombstone carrying a nonzero digest retires only the matching
// record; a zero digest retires the whole epoch.
function resolvePresence(options) {
  exactOwnData(options, ['publicKey', 'epoch', 'record', 'tombstone', 'readerSecret'])
  const { publicKey, epoch, record, tombstone, readerSecret } = options
  let resolved = null
  try {
    resolved = resolvePresenceRecord({ publicKey, epoch, record, readerSecret })
  } catch (err) {
    if (!(err instanceof PrivateRouteError) || err.code !== 'INVALID_DESCRIPTOR') throw err
    resolved = null
  }
  let killed = null
  try {
    killed = resolvePresenceTombstone({ publicKey, epoch, record: tombstone, readerSecret })
  } catch (err) {
    // A tombstone that is not ours (wrong identity, wrong epoch, wrong
    // credential) simply does not kill anything. Only a canonical-record
    // failure means the caller passed garbage.
    if (!(err instanceof PrivateRouteError)) throw err
    if (
      err.code !== 'INVALID_DESCRIPTOR' &&
      err.code !== 'ERR_AUTHENTICATION' &&
      err.code !== 'REPLAY'
    ) {
      throw err
    }
    killed = null
  }
  if (killed !== null) {
    if (b4a.equals(killed.digest, ZERO) || b4a.equals(killed.digest, cryptoSuite.hash([record]))) {
      return null
    }
  }
  return resolved
}

module.exports = {
  RECORD_SIZE,
  MAX_DESCRIPTOR_BYTES,
  EPOCH_MS,
  OVERLAP_MS,
  EPOCH_ADDRESS_DOMAIN,
  EPOCH_KEY_DOMAIN,
  EPOCH_CERTIFICATE_DOMAIN,
  announceEpochs,
  currentEpoch,
  deriveEpochAddressKey,
  deriveEpochBlindingParam,
  blindPublicKey,
  deriveEpochKeyPair,
  epochCertificate,
  verifyEpochCertificate,
  lookupEpochs,
  createPresenceRecord,
  createPresenceTombstone,
  resolvePresence,
  resolvePresenceRecord,
  resolvePresenceTombstone
}
