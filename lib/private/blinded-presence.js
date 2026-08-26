'use strict'

const b4a = require('b4a')
const sodium = require('sodium-universal')
const { PrivateRouteError } = require('./errors')

// Domain separation tags for Gate D blinded presence operations
const BLIND_FACTOR_DOMAIN = b4a.from('hyperdht-private-routes/presence/route-blind/v1\n')
const STORAGE_ADDR_DOMAIN = b4a.from('hyperdht-private-routes/presence/addr/v1\n')
const DESCRIPTOR_KEY_DOMAIN = b4a.from('hyperdht-private-routes/presence/descriptor-key/v1\n')
const DESCRIPTOR_CIPHER_DOMAIN = b4a.from('hyperdht-private-routes/presence/descriptor-cipher/v1\n')

// Ed25519 main group order L = 2^252 + 27742317777372353535851937790883648493
const ED25519_L = (1n << 252n) + 27742317777372353535851937790883648493n
const MAX_UINT64 = 0xffff_ffff_ffff_ffffn
const MAX_DESCRIPTOR_SIZE = 4096
const NONCE_SIZE = 24
const MAC_SIZE = 16

function invalid() {
  throw PrivateRouteError.INVALID_KEY()
}

function authentication() {
  throw PrivateRouteError.ERR_AUTHENTICATION()
}

function clear(buffer) {
  if (b4a.isBuffer(buffer)) buffer.fill(0)
}

function uint64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= MAX_UINT64
}

function bufToBigIntLE(buf) {
  let res = 0n
  for (let i = 0; i < buf.length; i++) {
    res += BigInt(buf[i]) << (BigInt(i) * 8n)
  }
  return res
}

function bigIntToBufLE(num, size = 32) {
  const buf = b4a.alloc(size)
  for (let i = 0; i < size; i++) {
    buf[i] = Number((num >> (BigInt(i) * 8n)) & 0xffn)
  }
  return buf
}

function encodeEpochBigEndian(epoch) {
  const buf = b4a.alloc(8)
  buf.writeBigUInt64BE(epoch, 0)
  return buf
}

/**
 * Derives a 32-byte Ed25519 scalar h mod L from a public key and epoch.
 */
function deriveBlindingScalar(publicKey, epoch, options = {}) {
  if (!b4a.isBuffer(publicKey) || publicKey.byteLength !== 32) invalid()
  if (!uint64(epoch)) invalid()

  const periodContext = options.periodContext
  if (periodContext !== undefined && !b4a.isBuffer(periodContext)) invalid()

  const epochBytes = encodeEpochBigEndian(epoch)
  const h64 = b4a.alloc(64)
  const h32 = b4a.alloc(32)
  const inputParts = [BLIND_FACTOR_DOMAIN, publicKey, epochBytes]
  if (periodContext) inputParts.push(periodContext)
  const input = b4a.concat(inputParts)

  try {
    sodium.crypto_generichash(h64, input)
    sodium.crypto_core_ed25519_scalar_reduce(h32, h64)
    return b4a.from(h32)
  } finally {
    clear(h64)
    clear(h32)
    clear(epochBytes)
    clear(input)
  }
}

/**
 * Computes blinded public key A' = h * A.
 */
function blindPublicKey(publicKey, blindingScalar) {
  if (!b4a.isBuffer(publicKey) || publicKey.byteLength !== 32) invalid()
  if (!b4a.isBuffer(blindingScalar) || blindingScalar.byteLength !== 32) invalid()

  const blindedPk = b4a.alloc(32)
  try {
    const success = sodium.crypto_scalarmult_ed25519_noclamp(blindedPk, blindingScalar, publicKey)
    if (success !== 0 && typeof success === 'number') invalid()
    return b4a.from(blindedPk)
  } catch (err) {
    clear(blindedPk)
    invalid()
  }
}

/**
 * Computes blinded private scalar a' = (h * a) mod L from 64-byte Ed25519 secret key.
 */
function blindSecretKey(secretKey, blindingScalar) {
  if (!b4a.isBuffer(secretKey) || secretKey.byteLength !== 64) invalid()
  if (!b4a.isBuffer(blindingScalar) || blindingScalar.byteLength !== 32) invalid()

  const aScalar = b4a.alloc(32)
  let aPrime = null

  try {
    sodium.extension_tweak_ed25519_sk_to_scalar(aScalar, secretKey)
    const aVal = bufToBigIntLE(aScalar)
    const hVal = bufToBigIntLE(blindingScalar)
    const aPrimeVal = (hVal * aVal) % ED25519_L
    aPrime = bigIntToBufLE(aPrimeVal, 32)
    return b4a.from(aPrime)
  } catch (err) {
    if (aPrime) clear(aPrime)
    invalid()
  } finally {
    clear(aScalar)
  }
}

/**
 * Derives DHT storage address key k_e = BLAKE2b(STORAGE_ADDR_DOMAIN || A' || epoch).
 */
function deriveStorageKey(blindedPublicKey, epoch, options = {}) {
  if (!b4a.isBuffer(blindedPublicKey) || blindedPublicKey.byteLength !== 32) invalid()
  if (!uint64(epoch)) invalid()

  const periodContext = options.periodContext
  if (periodContext !== undefined && !b4a.isBuffer(periodContext)) invalid()

  const storageKey = b4a.alloc(32)
  const epochBytes = encodeEpochBigEndian(epoch)
  const inputParts = [STORAGE_ADDR_DOMAIN, blindedPublicKey, epochBytes]
  if (periodContext) inputParts.push(periodContext)
  const input = b4a.concat(inputParts)

  try {
    sodium.crypto_generichash(storageKey, input)
    return b4a.from(storageKey)
  } finally {
    clear(storageKey)
    clear(epochBytes)
    clear(input)
  }
}

/**
 * Signs a presence descriptor using the blinded private scalar a' under blinded public key A'.
 */
function signPresenceDescriptor(blindedSecretKey, blindedPublicKey, descriptor) {
  if (!b4a.isBuffer(blindedSecretKey) || blindedSecretKey.byteLength !== 32) invalid()
  if (!b4a.isBuffer(blindedPublicKey) || blindedPublicKey.byteLength !== 32) invalid()
  if (!b4a.isBuffer(descriptor)) invalid()

  const signature = b4a.alloc(64)
  try {
    sodium.extension_tweak_ed25519_sign_detached(
      signature,
      descriptor,
      blindedSecretKey,
      blindedPublicKey
    )
    return b4a.from(signature)
  } catch (err) {
    clear(signature)
    invalid()
  }
}

/**
 * Verifies a presence descriptor signature under the blinded public key A'.
 */
function verifyPresenceDescriptor(blindedPublicKey, descriptor, signature) {
  if (!b4a.isBuffer(blindedPublicKey) || blindedPublicKey.byteLength !== 32) return false
  if (!b4a.isBuffer(descriptor)) return false
  if (!b4a.isBuffer(signature) || signature.byteLength !== 64) return false

  try {
    return sodium.crypto_sign_verify_detached(signature, descriptor, blindedPublicKey) === true
  } catch {
    return false
  }
}

/**
 * Encrypts a presence descriptor under a reader credential/secret using XChaCha20-Poly1305.
 */
function encryptPresenceDescriptor(readerSecret, descriptor, options = {}) {
  if (!b4a.isBuffer(readerSecret) || readerSecret.byteLength !== 32) invalid()
  if (!b4a.isBuffer(descriptor) || descriptor.byteLength > MAX_DESCRIPTOR_SIZE) invalid()

  const nonce = options.nonce || b4a.alloc(NONCE_SIZE)
  if (!options.nonce) sodium.randombytes_buf(nonce)
  if (nonce.byteLength !== NONCE_SIZE) invalid()

  const encKey = b4a.alloc(32)
  const ciphertext = b4a.alloc(descriptor.byteLength + MAC_SIZE)

  try {
    // Domain-separated encryption key derivation from reader secret
    sodium.crypto_generichash(encKey, DESCRIPTOR_KEY_DOMAIN, readerSecret)
    sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      ciphertext,
      descriptor,
      DESCRIPTOR_CIPHER_DOMAIN,
      null,
      nonce,
      encKey
    )

    return b4a.concat([nonce, ciphertext])
  } finally {
    clear(encKey)
  }
}

/**
 * Decrypts a presence descriptor under a reader credential/secret.
 */
function decryptPresenceDescriptor(readerSecret, encryptedPayload) {
  if (!b4a.isBuffer(readerSecret) || readerSecret.byteLength !== 32) invalid()
  if (!b4a.isBuffer(encryptedPayload) || encryptedPayload.byteLength < NONCE_SIZE + MAC_SIZE) {
    authentication()
  }

  const nonce = encryptedPayload.subarray(0, NONCE_SIZE)
  const ciphertext = encryptedPayload.subarray(NONCE_SIZE)
  const plaintext = b4a.alloc(ciphertext.byteLength - MAC_SIZE)
  const encKey = b4a.alloc(32)

  try {
    sodium.crypto_generichash(encKey, DESCRIPTOR_KEY_DOMAIN, readerSecret)
    let result
    try {
      result = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext,
        null,
        ciphertext,
        DESCRIPTOR_CIPHER_DOMAIN,
        nonce,
        encKey
      )
    } catch {
      authentication()
    }
    if (result === false) authentication()
    return b4a.from(plaintext)
  } finally {
    clear(encKey)
    clear(plaintext)
  }
}

/**
 * High-level helper: Creates a self-contained private presence record for publishing to the DHT.
 */
function createPresenceRecord(options = {}) {
  const { keyPair, readerSecret, epoch, descriptor, periodContext } = options
  if (!keyPair || !b4a.isBuffer(keyPair.publicKey) || !b4a.isBuffer(keyPair.secretKey)) invalid()
  if (!uint64(epoch)) invalid()
  if (!b4a.isBuffer(descriptor)) invalid()

  const blindingScalar = deriveBlindingScalar(keyPair.publicKey, epoch, { periodContext })
  let blindedSecretKey = null

  try {
    const blindedPublicKey = blindPublicKey(keyPair.publicKey, blindingScalar)
    blindedSecretKey = blindSecretKey(keyPair.secretKey, blindingScalar)
    const storageKey = deriveStorageKey(blindedPublicKey, epoch, { periodContext })

    const encryptedPayload = readerSecret
      ? encryptPresenceDescriptor(readerSecret, descriptor)
      : b4a.from(descriptor)

    // Sign the encrypted payload under the blinded key
    const signature = signPresenceDescriptor(blindedSecretKey, blindedPublicKey, encryptedPayload)

    return Object.freeze({
      storageKey,
      blindedPublicKey,
      epoch,
      signature,
      payload: encryptedPayload
    })
  } finally {
    clear(blindingScalar)
    if (blindedSecretKey) clear(blindedSecretKey)
  }
}

/**
 * High-level helper: Verifies and optionally decrypts a private presence record.
 */
function verifyAndDecryptPresenceRecord(options = {}) {
  const { publicKey, readerSecret, record, periodContext } = options
  if (!b4a.isBuffer(publicKey) || publicKey.byteLength !== 32) return null
  if (!record || typeof record !== 'object') return null
  if (!uint64(record.epoch)) return null
  if (!b4a.isBuffer(record.blindedPublicKey) || !b4a.isBuffer(record.signature)) return null
  if (!b4a.isBuffer(record.payload)) return null

  // 1. Verify that blindedPublicKey matches the expected derivation for this epoch
  const expectedBlindingScalar = deriveBlindingScalar(publicKey, record.epoch, { periodContext })
  try {
    const expectedBlindedPk = blindPublicKey(publicKey, expectedBlindingScalar)
    if (!b4a.equals(expectedBlindedPk, record.blindedPublicKey)) return null

    // 2. Verify signature under the blinded public key
    const validSig = verifyPresenceDescriptor(
      record.blindedPublicKey,
      record.payload,
      record.signature
    )
    if (!validSig) return null

    // 3. Decrypt payload if readerSecret is provided
    const decryptedDescriptor = readerSecret
      ? decryptPresenceDescriptor(readerSecret, record.payload)
      : b4a.from(record.payload)

    return {
      valid: true,
      epoch: record.epoch,
      blindedPublicKey: b4a.from(record.blindedPublicKey),
      descriptor: decryptedDescriptor
    }
  } catch {
    return null
  } finally {
    clear(expectedBlindingScalar)
  }
}

module.exports = {
  BLIND_FACTOR_DOMAIN,
  STORAGE_ADDR_DOMAIN,
  DESCRIPTOR_KEY_DOMAIN,
  DESCRIPTOR_CIPHER_DOMAIN,
  ED25519_L,
  deriveBlindingScalar,
  blindPublicKey,
  blindSecretKey,
  deriveStorageKey,
  signPresenceDescriptor,
  verifyPresenceDescriptor,
  encryptPresenceDescriptor,
  decryptPresenceDescriptor,
  createPresenceRecord,
  verifyAndDecryptPresenceRecord
}
