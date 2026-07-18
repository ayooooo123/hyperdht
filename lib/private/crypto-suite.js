const b4a = require('b4a')
const crypto = require('hypercore-crypto')
const sodium = require('sodium-universal')

const { PrivateRouteError } = require('./errors')
const { DOMAIN, PROTOCOL_VERSION } = require('./protocol')

// Ported from the reviewed private-routes prototype at commit
// 0305df915b6a767093f9e75e6c06bc0a35da6169.
//
// This is a generic primitive adapter. It deliberately does not construct the
// exact v1 role, branch, circuit, or generation transcripts. Gate 3B must add
// those transcript constructors and their M3 vectors.

const ZERO_KEY = b4a.alloc(32)
const MAX_TRANSCRIPT = 4096
const MAX_ASSOCIATED_DATA = 512
const AEAD_TAG_BYTES = 16
const MAX_COUNTER = 0xffff_ffff_ffff_ffffn
const bufferByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
const bufferFill = Uint8Array.prototype.fill
const bufferSet = Uint8Array.prototype.set
const bufferSubarray = Uint8Array.prototype.subarray
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectHasOwnProperty = Object.prototype.hasOwnProperty

const MAX_AEAD_PLAINTEXT = 65_535

function bufferLength(value) {
  try {
    return b4a.isBuffer(value) ? bufferByteLength.call(value) : -1
  } catch {
    return -1
  }
}

function copySlow(buffer) {
  const length = bufferLength(buffer)
  if (length < 0) throw new TypeError('Invalid internal buffer')

  const copy = b4a.allocUnsafeSlow(length)
  if (bufferLength(copy) !== length) throw new TypeError('Invalid internal allocation')
  bufferSet.call(copy, buffer)
  return copy
}

// JavaScript zeroization is best-effort. Secret buffers returned by this adapter are caller-owned.
function clear(buffer) {
  try {
    if (bufferLength(buffer) >= 0) bufferFill.call(buffer, 0)
  } catch {
    // Best-effort zeroization only.
  }
}

function validateSeed(seed) {
  if (seed !== undefined && bufferLength(seed) !== 32) throw PrivateRouteError.INVALID_KEY()
}

function keyPair(seed) {
  validateSeed(seed)
  let ownedSeed = null
  let pair = null

  try {
    ownedSeed = seed === undefined ? undefined : copySlow(seed)
    pair = crypto.keyPair(ownedSeed)
    return {
      publicKey: copySlow(pair.publicKey),
      secretKey: copySlow(pair.secretKey)
    }
  } finally {
    if (pair !== null) clear(pair.secretKey)
    clear(ownedSeed)
  }
}

function encryptionKeyPair(seed) {
  validateSeed(seed)
  let ownedSeed = null
  let pair = null

  try {
    ownedSeed = seed === undefined ? undefined : copySlow(seed)
    pair = crypto.encryptionKeyPair(ownedSeed)
    return {
      publicKey: copySlow(pair.publicKey),
      secretKey: copySlow(pair.secretKey)
    }
  } finally {
    if (pair !== null) clear(pair.secretKey)
    clear(ownedSeed)
  }
}

function keyAgreement(localSecretKey, remotePublicKey) {
  if (bufferLength(localSecretKey) !== 32 || bufferLength(remotePublicKey) !== 32) {
    throw PrivateRouteError.INVALID_KEY()
  }

  let ownedLocalSecretKey = null
  let ownedRemotePublicKey = null
  let shared = null

  try {
    ownedLocalSecretKey = copySlow(localSecretKey)
    ownedRemotePublicKey = copySlow(remotePublicKey)
    shared = b4a.allocUnsafeSlow(32)
    if (bufferLength(shared) !== 32) throw PrivateRouteError.INVALID_KEY()

    let result
    try {
      result = sodium.crypto_scalarmult(shared, ownedLocalSecretKey, ownedRemotePublicKey)
    } catch (err) {
      if (isNativeLowOrderError(err)) throw PrivateRouteError.INVALID_KEY()
      throw err
    }
    if (result === false || b4a.equals(shared, ZERO_KEY)) throw PrivateRouteError.INVALID_KEY()

    return copySlow(shared)
  } finally {
    clear(shared)
    clear(ownedLocalSecretKey)
    clear(ownedRemotePublicKey)
  }
}

function isNativeLowOrderError(err) {
  try {
    return err !== null && err.constructor === Error && err.message === 'status: -1'
  } catch {
    return false
  }
}

function writeUint16BE(buffer, value, offset) {
  buffer[offset] = value >>> 8
  buffer[offset + 1] = value
}

function writeUint32BE(buffer, value, offset) {
  buffer[offset] = value >>> 24
  buffer[offset + 1] = value >>> 16
  buffer[offset + 2] = value >>> 8
  buffer[offset + 3] = value
}

function derive(sharedSecret, label, transcript) {
  const labelLength = bufferLength(label)
  const transcriptLength = bufferLength(transcript)
  const message = b4a.allocUnsafe(2 + labelLength + 4 + 4 + transcriptLength)
  let offset = 0

  writeUint16BE(message, labelLength, offset)
  offset += 2
  bufferSet.call(message, label, offset)
  offset += labelLength
  writeUint32BE(message, PROTOCOL_VERSION, offset)
  offset += 4
  writeUint32BE(message, transcriptLength, offset)
  offset += 4
  bufferSet.call(message, transcript, offset)

  const output = b4a.allocUnsafeSlow(32)
  let complete = false

  try {
    sodium.crypto_generichash(output, message, sharedSecret)
    complete = true
    return output
  } finally {
    clear(message)
    if (!complete) clear(output)
  }
}

function deriveKeys(sharedSecret, transcript) {
  const transcriptLength = bufferLength(transcript)
  if (
    bufferLength(sharedSecret) !== 32 ||
    transcriptLength < 0 ||
    transcriptLength > MAX_TRANSCRIPT
  ) {
    throw PrivateRouteError.INVALID_KEY()
  }

  let ownedSharedSecret = null
  let ownedTranscript = null
  let forwardNonce = null
  let reverseNonce = null
  let forwardKey = null
  let reverseKey = null
  let forwardNoncePrefix = null
  let reverseNoncePrefix = null
  let transferred = false

  try {
    ownedSharedSecret = copySlow(sharedSecret)
    ownedTranscript = copySlow(transcript)
    forwardNonce = derive(ownedSharedSecret, DOMAIN.KDF_FORWARD_NONCE, ownedTranscript)
    reverseNonce = derive(ownedSharedSecret, DOMAIN.KDF_REVERSE_NONCE, ownedTranscript)
    forwardKey = derive(ownedSharedSecret, DOMAIN.KDF_FORWARD_KEY, ownedTranscript)
    reverseKey = derive(ownedSharedSecret, DOMAIN.KDF_REVERSE_KEY, ownedTranscript)
    forwardNoncePrefix = copySlow(bufferSubarray.call(forwardNonce, 0, 16))
    reverseNoncePrefix = copySlow(bufferSubarray.call(reverseNonce, 0, 16))

    const result = {
      forwardKey,
      reverseKey,
      forwardNoncePrefix,
      reverseNoncePrefix
    }
    transferred = true
    return result
  } finally {
    clear(ownedSharedSecret)
    clear(ownedTranscript)
    clear(forwardNonce)
    clear(reverseNonce)
    if (!transferred) {
      clear(forwardKey)
      clear(reverseKey)
      clear(forwardNoncePrefix)
      clear(reverseNoncePrefix)
    }
  }
}

function validateKeyAndNoncePrefix(key, noncePrefix) {
  if (bufferLength(key) !== 32 || bufferLength(noncePrefix) !== 16) {
    throw PrivateRouteError.INVALID_KEY()
  }
}

function snapshotCellInputs(options, payloadName) {
  let validOptions = false
  try {
    validOptions = options !== null && typeof options === 'object' && !Array.isArray(options)
  } catch {
    throw PrivateRouteError.CELL_INVALID()
  }

  if (!validOptions) {
    throw PrivateRouteError.CELL_INVALID()
  }

  const key = ownDataOption(options, 'key')
  const noncePrefix = ownDataOption(options, 'noncePrefix')
  const counter = ownDataOption(options, 'counter')
  const associatedData = ownDataOption(options, 'associatedData')
  const payload = ownDataOption(options, payloadName)

  validateKeyAndNoncePrefix(key, noncePrefix)

  const associatedDataLength = bufferLength(associatedData)
  if (
    typeof counter !== 'bigint' ||
    counter < 0n ||
    counter > MAX_COUNTER ||
    associatedDataLength < 0 ||
    associatedDataLength > MAX_ASSOCIATED_DATA
  ) {
    throw PrivateRouteError.CELL_INVALID()
  }

  return { key, noncePrefix, counter, associatedData, payload }
}

function ownDataOption(options, name) {
  let descriptor
  try {
    descriptor = objectGetOwnPropertyDescriptor(options, name)
  } catch {
    throw PrivateRouteError.CELL_INVALID()
  }

  if (descriptor === undefined || !objectHasOwnProperty.call(descriptor, 'value')) {
    throw PrivateRouteError.CELL_INVALID()
  }

  return descriptor.value
}

function nonceFor(noncePrefix, counter) {
  const nonce = b4a.allocUnsafe(24)
  if (bufferLength(nonce) !== 24) throw PrivateRouteError.CELL_INVALID()
  bufferSet.call(nonce, noncePrefix, 0)

  for (let i = 23; i >= 16; i--) {
    nonce[i] = Number(counter & 0xffn)
    counter >>= 8n
  }

  return nonce
}

function seal(options) {
  const {
    key,
    noncePrefix,
    counter,
    associatedData,
    payload: plaintext
  } = snapshotCellInputs(options, 'plaintext')
  const plaintextLength = bufferLength(plaintext)

  if (plaintextLength < 0 || plaintextLength > MAX_AEAD_PLAINTEXT) {
    throw PrivateRouteError.CELL_INVALID()
  }

  let ownedKey = null
  let ownedAssociatedData = null
  let ownedPlaintext = null
  let ciphertext = null
  let nonce = null
  let complete = false

  try {
    ownedKey = copySlow(key)
    ownedAssociatedData = copySlow(associatedData)
    ownedPlaintext = copySlow(plaintext)
    ciphertext = b4a.allocUnsafeSlow(plaintextLength + AEAD_TAG_BYTES)
    if (bufferLength(ciphertext) !== plaintextLength + AEAD_TAG_BYTES) {
      throw PrivateRouteError.CELL_INVALID()
    }
    nonce = nonceFor(noncePrefix, counter)
    sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      ciphertext,
      ownedPlaintext,
      ownedAssociatedData,
      null,
      nonce,
      ownedKey
    )
    complete = true
  } finally {
    if (!complete) clear(ciphertext)
    clear(nonce)
    clear(ownedKey)
    clear(ownedAssociatedData)
    clear(ownedPlaintext)
  }

  return ciphertext
}

function open(options) {
  const {
    key,
    noncePrefix,
    counter,
    associatedData,
    payload: ciphertext
  } = snapshotCellInputs(options, 'ciphertext')
  const ciphertextLength = bufferLength(ciphertext)

  if (ciphertextLength < AEAD_TAG_BYTES || ciphertextLength > MAX_AEAD_PLAINTEXT + AEAD_TAG_BYTES) {
    throw PrivateRouteError.CELL_INVALID()
  }

  let ownedKey = null
  let ownedAssociatedData = null
  let ownedCiphertext = null
  let plaintext = null
  let nonce = null

  try {
    ownedKey = copySlow(key)
    ownedAssociatedData = copySlow(associatedData)
    ownedCiphertext = copySlow(ciphertext)
    plaintext = b4a.allocUnsafeSlow(ciphertextLength - AEAD_TAG_BYTES)
    if (bufferLength(plaintext) !== ciphertextLength - AEAD_TAG_BYTES) {
      throw PrivateRouteError.CELL_INVALID()
    }
    nonce = nonceFor(noncePrefix, counter)
    let result

    try {
      result = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext,
        null,
        ownedCiphertext,
        ownedAssociatedData,
        nonce,
        ownedKey
      )
    } catch (err) {
      // sodium-native throws this exact error for authentication failure in Node and Bare.
      if (err && err.message === 'could not verify data') return null
      throw err
    }

    if (result === false) return null
    return copySlow(plaintext)
  } finally {
    clear(plaintext)
    clear(nonce)
    clear(ownedKey)
    clear(ownedAssociatedData)
    clear(ownedCiphertext)
  }
}

const cryptoSuite = Object.freeze({
  keyPair,
  encryptionKeyPair,
  sign: crypto.sign,
  verify: crypto.verify,
  hash: crypto.hash,
  randomBytes: crypto.randomBytes,
  keyAgreement,
  deriveKeys,
  seal,
  open
})

module.exports = {
  MAX_AEAD_PLAINTEXT,
  cryptoSuite
}
