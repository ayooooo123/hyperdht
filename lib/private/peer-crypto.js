'use strict'

const b4a = require('b4a')
const sodium = require('sodium-universal')

const { PrivateRouteError } = require('./errors')
const { cryptoSuite } = require('./crypto-suite')
const { PEER_MESSAGE_ID } = require('./peer-protocol')

const PEER_PROTOCOL_VERSION = 2
const TAIL_CONTROL_TRANSCRIPT_SIZE = 290
const PEER_ADJACENCY_TRANSCRIPT_SIZE = 104
const PEER_LIMITS_SIZE = 26
const PEER_LIMITS_INPUT_SIZE = 88
const CONFIRMATION_CONTEXT_SIZE = 176
const CONFIRMATION_HASH_STATE_SIZE = 384
const CONFIRMATION_KEY_SIZE = 32
const CONFIRMATION_TAG_SIZE = 32
const CONFIRMATION_FRAMING_SIZE = 80
const CONFIRMATION_ARENA_SIZE =
  CONFIRMATION_HASH_STATE_SIZE +
  CONFIRMATION_KEY_SIZE +
  CONFIRMATION_TAG_SIZE +
  CONFIRMATION_FRAMING_SIZE
const MAX_UINT16 = 0xffff
const MAX_UINT32 = 0xffff_ffff
const MAX_UINT64 = 0xffff_ffff_ffff_ffffn

const TAIL_CONTROL_DOMAIN = b4a.from('hyperdht-private-routes/tail-control/transcript/v2')
const TAIL_LIMITS_DOMAIN = b4a.from('hyperdht-private-routes/tail-control/limits/v2')
const ADJACENCY_PREFIX_DOMAIN = b4a.from('hyperdht-private-routes/link/created/v2')
const ADJACENCY_OFFER_DIGEST_DOMAIN = 'hyperdht-private-routes/m3/link-offer-digest/v2'
const ADJACENCY_ACCEPT_DIGEST_DOMAIN = 'hyperdht-private-routes/m3/link-accept-digest/v2'

const ADJACENCY_LABELS = Object.freeze({
  FORWARD_KEY: 'hyperdht-private-routes/kdf/v2/forward-key',
  REVERSE_KEY: 'hyperdht-private-routes/kdf/v2/reverse-key',
  FORWARD_NONCE: 'hyperdht-private-routes/kdf/v2/forward-nonce',
  REVERSE_NONCE: 'hyperdht-private-routes/kdf/v2/reverse-nonce'
})
const PURPOSE_PRETRANSCRIPT_DOMAIN = 'hyperdht-private-routes/m3/peer-route-prepurpose/v2'
const PURPOSE_OFFER_DIGEST_DOMAIN = 'hyperdht-private-routes/m3/peer-route-offer-digest/v2'
const PURPOSE_ACCEPT_DIGEST_DOMAIN = 'hyperdht-private-routes/m3/peer-route-accept-digest/v2'
const PURPOSE_DIGEST_DOMAIN = 'hyperdht-private-routes/m3/peer-route-purpose-digest/v2'
const PURPOSE_SOURCE_CONFIRM_DOMAIN = 'hyperdht-private-routes/m3/peer-route/source-confirm/v2'
const PURPOSE_TERMINAL_CONFIRM_DOMAIN = 'hyperdht-private-routes/m3/peer-route/terminal-confirm/v2'
const PURPOSE_FINAL_TRANSCRIPT_DOMAIN =
  'hyperdht-private-routes/m3/peer-route-final-transcript-digest/v2'

const PURPOSE_LABELS = Object.freeze({
  PRE_SOURCE_MAC: 'hyperdht-private-routes/kdf/v2/peer-route/pre/source-mac',
  PRE_TERMINAL_MAC: 'hyperdht-private-routes/kdf/v2/peer-route/pre/terminal-mac',
  FORWARD_KEY: 'hyperdht-private-routes/kdf/v2/peer-route/forward-key',
  REVERSE_KEY: 'hyperdht-private-routes/kdf/v2/peer-route/reverse-key',
  FORWARD_NONCE: 'hyperdht-private-routes/kdf/v2/peer-route/forward-nonce',
  REVERSE_NONCE: 'hyperdht-private-routes/kdf/v2/peer-route/reverse-nonce'
})

const PURPOSE_OFFER_BODY_SIZE = 212
const PURPOSE_OFFER_WIRE_SIZE = 236
const PURPOSE_ACCEPT_BODY_SIZE = 260
const PURPOSE_ACCEPT_WIRE_SIZE = 284
const PURPOSE_RELIABLE_ACK_BODY_SIZE = 64
const PURPOSE_MAC_SIZE = 16
const PURPOSE_PRETRANSCRIPT_SIZE =
  2 + PURPOSE_PRETRANSCRIPT_DOMAIN.length + 4 + 32 * 5 + PURPOSE_OFFER_BODY_SIZE

const CONFIRMATION_LABELS = Object.freeze([
  'hyperdht-private-routes/peer/private-ready-confirmation-key/v2',
  'hyperdht-private-routes/peer/private-ack-confirmation-key/v2',
  'hyperdht-private-routes/peer/private-accepted-confirmation-key/v2',
  'hyperdht-private-routes/peer/private-receipt-confirmation-key/v2'
])
const CONFIRMATION_LABEL_BYTES = Object.freeze(CONFIRMATION_LABELS.map((label) => b4a.from(label)))

const bufferByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
const bufferFill = Uint8Array.prototype.fill
const bufferSet = Uint8Array.prototype.set
const bufferSubarray = Uint8Array.prototype.subarray
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectHasOwnProperty = Object.prototype.hasOwnProperty

const HELD_CONFIRMATION_ARENAS = new WeakSet()

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function invalidKey() {
  throw PrivateRouteError.INVALID_KEY()
}

function bufferLength(value) {
  try {
    return b4a.isBuffer(value) ? bufferByteLength.call(value) : -1
  } catch {
    return -1
  }
}

function fixed(value, size) {
  return bufferLength(value) === size
}
function isZero32(buffer) {
  try {
    if (typeof sodium.sodium_is_zero === 'function') {
      return sodium.sodium_is_zero(buffer)
    }
  } catch {}
  for (let i = 0; i < 32; i++) {
    if (buffer[i] !== 0) return false
  }
  return true
}

function clear(value) {
  try {
    if (bufferLength(value) >= 0) bufferFill.call(value, 0)
  } catch {
    // Best-effort zeroization only.
  }
}

function copy(value) {
  const length = bufferLength(value)
  if (length < 0) invalid()

  let output = null
  try {
    output = b4a.allocUnsafeSlow(length)
    if (bufferLength(output) !== length) invalid()
    bufferSet.call(output, value)
    const result = output
    output = null
    return result
  } finally {
    clear(output)
  }
}

function set(target, source, offset = 0) {
  try {
    bufferSet.call(target, source, offset)
  } catch {
    invalid()
  }
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

function uint32(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= MAX_UINT32
}

function uint64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= MAX_UINT64
}

function textBytes(value) {
  if (typeof value === 'string') {
    let bytes = null
    try {
      bytes = b4a.from(value, 'utf8')
    } catch {
      invalid()
    }
    const length = bufferLength(bytes)
    if (length <= 0 || length > MAX_UINT16) {
      clear(bytes)
      invalid()
    }
    return { bytes, owned: true }
  }

  const length = bufferLength(value)
  if (length <= 0 || length > MAX_UINT16) invalid()
  return { bytes: value, owned: false }
}

function own(value, name) {
  let descriptor
  try {
    descriptor = objectGetOwnPropertyDescriptor(value, name)
  } catch {
    invalid()
  }
  if (!descriptor || !objectHasOwnProperty.call(descriptor, 'value')) invalid()
  return descriptor.value
}

function ownObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid()
  return value
}

function snapshotParts(parts) {
  if (!Array.isArray(parts)) invalid()

  let lengthDescriptor
  try {
    lengthDescriptor = objectGetOwnPropertyDescriptor(parts, 'length')
  } catch {
    invalid()
  }
  if (
    !lengthDescriptor ||
    !objectHasOwnProperty.call(lengthDescriptor, 'value') ||
    !uint32(lengthDescriptor.value)
  ) {
    invalid()
  }

  const values = new Array(lengthDescriptor.value)
  let total = 0
  for (let index = 0; index < values.length; index++) {
    let descriptor
    try {
      descriptor = objectGetOwnPropertyDescriptor(parts, String(index))
    } catch {
      invalid()
    }
    if (!descriptor || !objectHasOwnProperty.call(descriptor, 'value')) invalid()

    const value = descriptor.value
    const length = bufferLength(value)
    if (length < 0 || total > MAX_UINT32 - length) invalid()
    values[index] = value
    total += length
  }

  return { values, total }
}

function hashPeer(domain, parts) {
  const domainInfo = textBytes(domain)
  let prefix = null
  let state = null
  let output = null
  let transferred = false

  try {
    const snapshot = snapshotParts(parts)
    prefix = b4a.allocUnsafe(2)
    if (bufferLength(prefix) !== 2) invalid()
    writeUint16(prefix, bufferLength(domainInfo.bytes), 0)

    state = b4a.allocUnsafeSlow(CONFIRMATION_HASH_STATE_SIZE)
    output = b4a.allocUnsafeSlow(32)
    if (bufferLength(state) !== CONFIRMATION_HASH_STATE_SIZE || bufferLength(output) !== 32) {
      invalid()
    }

    sodium.crypto_generichash_init(state, null, 32)
    sodium.crypto_generichash_update(state, prefix)
    sodium.crypto_generichash_update(state, domainInfo.bytes)
    for (const value of snapshot.values) sodium.crypto_generichash_update(state, value)
    sodium.crypto_generichash_final(state, output)

    transferred = true
    return output
  } finally {
    if (!transferred) clear(output)
    clear(prefix)
    clear(state)
    if (domainInfo.owned) clear(domainInfo.bytes)
  }
}

function derivePeerKey(sharedSecret32, label, transcript) {
  if (!fixed(sharedSecret32, 32)) invalidKey()
  const transcriptLength = bufferLength(transcript)
  if (transcriptLength < 0 || transcriptLength > MAX_UINT32) invalid()

  const labelInfo = textBytes(label)
  let framing = null
  let state = null
  let output = null
  let transferred = false

  try {
    const labelLength = bufferLength(labelInfo.bytes)
    framing = b4a.allocUnsafeSlow(2 + labelLength + 4 + 4)
    if (bufferLength(framing) !== 10 + labelLength) invalid()
    writeUint16(framing, labelLength, 0)
    set(framing, labelInfo.bytes, 2)
    writeUint32(framing, PEER_PROTOCOL_VERSION, 2 + labelLength)
    writeUint32(framing, transcriptLength, 6 + labelLength)

    state = b4a.allocUnsafeSlow(CONFIRMATION_HASH_STATE_SIZE)
    output = b4a.allocUnsafeSlow(32)
    if (bufferLength(state) !== CONFIRMATION_HASH_STATE_SIZE || bufferLength(output) !== 32) {
      invalid()
    }

    sodium.crypto_generichash_init(state, sharedSecret32, 32)
    sodium.crypto_generichash_update(state, framing)
    sodium.crypto_generichash_update(state, transcript)
    sodium.crypto_generichash_final(state, output)

    transferred = true
    return output
  } finally {
    if (!transferred) clear(output)
    clear(framing)
    clear(state)
    if (labelInfo.owned) clear(labelInfo.bytes)
  }
}

function digestPeerLimits(reverseLimits26, forwardLimits26, candidateCommitment32) {
  if (
    !fixed(reverseLimits26, PEER_LIMITS_SIZE) ||
    !fixed(forwardLimits26, PEER_LIMITS_SIZE) ||
    !fixed(candidateCommitment32, 32)
  ) {
    invalid()
  }

  let input = null
  try {
    input = b4a.allocUnsafeSlow(PEER_LIMITS_INPUT_SIZE)
    if (bufferLength(input) !== PEER_LIMITS_INPUT_SIZE) invalid()
    writeUint32(input, PEER_PROTOCOL_VERSION, 0)
    set(input, reverseLimits26, 4)
    set(input, forwardLimits26, 30)
    set(input, candidateCommitment32, 56)
    return hashPeer(TAIL_LIMITS_DOMAIN, [input])
  } finally {
    clear(input)
  }
}

function createPeerTailTranscript(fields) {
  ownObject(fields)

  const branchId = own(fields, 'branchId')
  const circuitId = own(fields, 'circuitId')
  const generation = own(fields, 'generation')
  const extensionIndex = own(fields, 'extensionIndex')
  const clientTailEphemeralPublicKey = own(fields, 'clientTailEphemeralPublicKey')
  const advertisedTailRouteEncryptionPublicKey = own(
    fields,
    'advertisedTailRouteEncryptionPublicKey'
  )
  const candidateAdvertisementDigest = own(fields, 'candidateAdvertisementDigest')
  const clientNonce = own(fields, 'clientNonce')
  const tailIdentity = own(fields, 'tailIdentity')
  const reverseLimits = own(fields, 'reverseLimits')
  const forwardLimits = own(fields, 'forwardLimits')
  const candidateAuthorityCommitment = own(fields, 'candidateAuthorityCommitment')

  if (
    !fixed(branchId, 16) ||
    !fixed(circuitId, 16) ||
    !uint64(generation) ||
    !Number.isSafeInteger(extensionIndex) ||
    extensionIndex < 0 ||
    extensionIndex > 2 ||
    !fixed(clientTailEphemeralPublicKey, 32) ||
    !fixed(advertisedTailRouteEncryptionPublicKey, 32) ||
    !fixed(candidateAdvertisementDigest, 32) ||
    !fixed(clientNonce, 32) ||
    !fixed(tailIdentity, 32) ||
    !fixed(reverseLimits, PEER_LIMITS_SIZE) ||
    !fixed(forwardLimits, PEER_LIMITS_SIZE) ||
    !fixed(candidateAuthorityCommitment, 32)
  ) {
    invalid()
  }

  let output = null
  let limitsDigest = null
  let transferred = false
  try {
    limitsDigest = digestPeerLimits(reverseLimits, forwardLimits, candidateAuthorityCommitment)
    output = b4a.allocUnsafeSlow(TAIL_CONTROL_TRANSCRIPT_SIZE)
    if (bufferLength(output) !== TAIL_CONTROL_TRANSCRIPT_SIZE) invalid()

    let offset = 0
    writeUint16(output, bufferLength(TAIL_CONTROL_DOMAIN), offset)
    offset += 2
    set(output, TAIL_CONTROL_DOMAIN, offset)
    offset += bufferLength(TAIL_CONTROL_DOMAIN)
    writeUint32(output, PEER_PROTOCOL_VERSION, offset)
    offset += 4
    output[offset++] = 2
    set(output, branchId, offset)
    offset += 16
    set(output, circuitId, offset)
    offset += 16
    writeUint64(output, generation, offset)
    offset += 8
    output[offset++] = extensionIndex
    set(output, clientTailEphemeralPublicKey, offset)
    offset += 32
    set(output, advertisedTailRouteEncryptionPublicKey, offset)
    offset += 32
    set(output, candidateAdvertisementDigest, offset)
    offset += 32
    set(output, clientNonce, offset)
    offset += 32
    set(output, tailIdentity, offset)
    offset += 32
    set(output, limitsDigest, offset)
    offset += 32
    if (offset !== TAIL_CONTROL_TRANSCRIPT_SIZE) invalid()

    transferred = true
    return output
  } finally {
    if (!transferred) clear(output)
    clear(limitsDigest)
  }
}
function createPeerAdjacencyTranscript(completeOffer432, completeAccept285, cellClass) {
  if (
    !fixed(completeOffer432, 432) ||
    !fixed(completeAccept285, 285) ||
    (cellClass !== 0 && cellClass !== 2)
  ) {
    invalid()
  }

  let offerDigest = null
  let acceptDigest = null
  let output = null
  let transferred = false

  try {
    offerDigest = hashPeer(ADJACENCY_OFFER_DIGEST_DOMAIN, [completeOffer432])
    acceptDigest = hashPeer(ADJACENCY_ACCEPT_DIGEST_DOMAIN, [completeAccept285])

    output = b4a.allocUnsafeSlow(PEER_ADJACENCY_TRANSCRIPT_SIZE)
    if (bufferLength(output) !== PEER_ADJACENCY_TRANSCRIPT_SIZE) invalid()

    let offset = 0
    set(output, ADJACENCY_PREFIX_DOMAIN, offset)
    offset += 39
    set(output, offerDigest, offset)
    offset += 32
    set(output, acceptDigest, offset)
    offset += 32
    output[offset++] = cellClass

    if (offset !== PEER_ADJACENCY_TRANSCRIPT_SIZE) invalid()

    transferred = true
    return output
  } finally {
    if (!transferred) clear(output)
    clear(offerDigest)
    clear(acceptDigest)
  }
}
function createPeerPurposePreTranscript(fields) {
  ownObject(fields)

  const tailControlTranscriptDigest = own(fields, 'tailControlTranscriptDigest')
  const terminalAdvertisementDigest = own(fields, 'terminalAdvertisementDigest')
  const queryNonce = own(fields, 'queryNonce')
  const clientEphemeralPublicKey = own(fields, 'clientEphemeralPublicKey')
  const terminalRoutePublicKey = own(fields, 'terminalRoutePublicKey')
  const offerBody = own(fields, 'offerBody')

  if (
    !fixed(tailControlTranscriptDigest, 32) ||
    !fixed(terminalAdvertisementDigest, 32) ||
    !fixed(queryNonce, 32) ||
    !fixed(clientEphemeralPublicKey, 32) ||
    !fixed(terminalRoutePublicKey, 32) ||
    !fixed(offerBody, PURPOSE_OFFER_BODY_SIZE)
  ) {
    invalid()
  }

  const label = b4a.from(PURPOSE_PRETRANSCRIPT_DOMAIN)
  let output = null
  let transferred = false
  try {
    output = b4a.allocUnsafeSlow(
      2 + bufferLength(label) + 4 + 32 + 32 + 32 + 32 + 32 + PURPOSE_OFFER_BODY_SIZE
    )
    let offset = 0
    writeUint16(output, bufferLength(label), offset)
    offset += 2
    set(output, label, offset)
    offset += bufferLength(label)
    writeUint32(output, PEER_PROTOCOL_VERSION, offset)
    offset += 4
    set(output, tailControlTranscriptDigest, offset)
    offset += 32
    set(output, terminalAdvertisementDigest, offset)
    offset += 32
    set(output, queryNonce, offset)
    offset += 32
    set(output, clientEphemeralPublicKey, offset)
    offset += 32
    set(output, terminalRoutePublicKey, offset)
    offset += 32
    set(output, offerBody, offset)
    offset += PURPOSE_OFFER_BODY_SIZE
    if (offset !== output.byteLength) invalid()
    transferred = true
    return output
  } finally {
    if (!transferred) clear(output)
    clear(label)
  }
}

function createPeerPurposeTranscript(preTranscript, completeOffer, acceptBody) {
  if (
    bufferLength(preTranscript) !== PURPOSE_PRETRANSCRIPT_SIZE ||
    bufferLength(completeOffer) !== PURPOSE_OFFER_WIRE_SIZE ||
    bufferLength(acceptBody) !== PURPOSE_ACCEPT_BODY_SIZE
  ) {
    invalid()
  }

  let output = null
  let transferred = false
  try {
    output = b4a.allocUnsafeSlow(
      bufferLength(preTranscript) + PURPOSE_OFFER_WIRE_SIZE + PURPOSE_ACCEPT_BODY_SIZE
    )
    let offset = 0
    set(output, preTranscript, offset)
    offset += bufferLength(preTranscript)
    set(output, completeOffer, offset)
    offset += PURPOSE_OFFER_WIRE_SIZE
    set(output, acceptBody, offset)
    if (offset + PURPOSE_ACCEPT_BODY_SIZE !== output.byteLength) invalid()
    transferred = true
    return output
  } finally {
    if (!transferred) clear(output)
  }
}

function derivePeerPurposeSharedSecret(localSecretKey, remotePublicKey) {
  if (!fixed(localSecretKey, 32) || !fixed(remotePublicKey, 32)) invalidKey()
  if (isZero32(localSecretKey) || isZero32(remotePublicKey)) invalidKey()

  try {
    return cryptoSuite.keyAgreement(localSecretKey, remotePublicKey)
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalidKey()
  }
}
function validPeerPurposeHeaderBody(value) {
  const length = bufferLength(value)
  if (length < 8) return false
  const version = value[0] * 0x1000000 + (value[1] << 16) + (value[2] << 8) + value[3]
  const messageId = (value[4] << 8) | value[5]
  const bodyLength = (value[6] << 8) | value[7]
  if (version !== PEER_PROTOCOL_VERSION || bodyLength !== length - 8) return false
  return (
    (messageId === PEER_MESSAGE_ID.PEER_ROUTE_OFFER_V2 && bodyLength === PURPOSE_OFFER_BODY_SIZE) ||
    (messageId === PEER_MESSAGE_ID.PEER_ROUTE_ACCEPT_V2 &&
      bodyLength === PURPOSE_ACCEPT_BODY_SIZE) ||
    (messageId === PEER_MESSAGE_ID.PEER_ROUTE_REJECT_V2 && bodyLength === 64)
  )
}

function computePeerPurposeMac(key16, completeHeaderBody) {
  if (!fixed(key16, PURPOSE_MAC_SIZE) || !validPeerPurposeHeaderBody(completeHeaderBody)) {
    invalid()
  }
  let output = null
  try {
    output = b4a.allocUnsafeSlow(PURPOSE_MAC_SIZE)
    sodium.crypto_generichash(output, completeHeaderBody, key16)
    return output
  } catch (err) {
    clear(output)
    throw err
  }
}

function verifyPeerPurposeMac(key16, completeHeaderBody, receivedMac16) {
  if (
    !fixed(key16, PURPOSE_MAC_SIZE) ||
    !validPeerPurposeHeaderBody(completeHeaderBody) ||
    !fixed(receivedMac16, PURPOSE_MAC_SIZE)
  ) {
    invalid()
  }
  let computed = null
  try {
    computed = computePeerPurposeMac(key16, completeHeaderBody)
    return sodium.sodium_memcmp(computed, receivedMac16)
  } finally {
    clear(computed)
  }
}

function derivePeerPurposeKeys(sharedSecret32, preTranscript, purposeTranscript) {
  if (!fixed(sharedSecret32, 32) || isZero32(sharedSecret32)) invalidKey()
  if (
    bufferLength(preTranscript) !== PURPOSE_PRETRANSCRIPT_SIZE ||
    bufferLength(purposeTranscript) !==
      PURPOSE_PRETRANSCRIPT_SIZE + PURPOSE_OFFER_WIRE_SIZE + PURPOSE_ACCEPT_BODY_SIZE
  ) {
    invalid()
  }

  let preSourceMac = null
  let preTerminalMac = null
  let forwardKey = null
  let reverseKey = null
  let forwardNonce = null
  let reverseNonce = null
  let keys = null
  let transferred = false
  try {
    preSourceMac = derivePeerKey(sharedSecret32, PURPOSE_LABELS.PRE_SOURCE_MAC, preTranscript)
    preTerminalMac = derivePeerKey(sharedSecret32, PURPOSE_LABELS.PRE_TERMINAL_MAC, preTranscript)
    forwardKey = derivePeerKey(sharedSecret32, PURPOSE_LABELS.FORWARD_KEY, purposeTranscript)
    reverseKey = derivePeerKey(sharedSecret32, PURPOSE_LABELS.REVERSE_KEY, purposeTranscript)
    forwardNonce = derivePeerKey(sharedSecret32, PURPOSE_LABELS.FORWARD_NONCE, purposeTranscript)
    reverseNonce = derivePeerKey(sharedSecret32, PURPOSE_LABELS.REVERSE_NONCE, purposeTranscript)

    keys = {
      preSourceMacKey: copy(bufferSubarray.call(preSourceMac, 0, PURPOSE_MAC_SIZE)),
      preTerminalMacKey: copy(bufferSubarray.call(preTerminalMac, 0, PURPOSE_MAC_SIZE)),
      forwardKey: copy(forwardKey),
      reverseKey: copy(reverseKey),
      forwardNoncePrefix: copy(bufferSubarray.call(forwardNonce, 0, 16)),
      reverseNoncePrefix: copy(bufferSubarray.call(reverseNonce, 0, 16))
    }
    transferred = true
    return keys
  } finally {
    clear(preSourceMac)
    clear(preTerminalMac)
    clear(forwardKey)
    clear(reverseKey)
    clear(forwardNonce)
    clear(reverseNonce)
    if (!transferred) clearPeerPurposeKeys(keys)
  }
}

function clearPeerPurposeKeys(keys) {
  if (!keys) return
  for (const value of Object.values(keys)) clear(value)
}

function digestPeerPurposeOffer(completeOffer) {
  if (bufferLength(completeOffer) !== PURPOSE_OFFER_WIRE_SIZE) invalid()
  return hashPeer(PURPOSE_OFFER_DIGEST_DOMAIN, [completeOffer])
}

function digestPeerPurposeAccept(completeAccept) {
  if (bufferLength(completeAccept) !== PURPOSE_ACCEPT_WIRE_SIZE) invalid()
  return hashPeer(PURPOSE_ACCEPT_DIGEST_DOMAIN, [completeAccept])
}

function createPeerPurposeDigest(fields) {
  ownObject(fields)

  const tailControlTranscriptDigest = own(fields, 'tailControlTranscriptDigest')
  const terminalAdvertisementDigest = own(fields, 'terminalAdvertisementDigest')
  const routeId = own(fields, 'routeId')
  const circuitId = own(fields, 'circuitId')
  const generation = own(fields, 'generation')
  const purpose = own(fields, 'purpose')
  const sourceDirection = own(fields, 'sourceDirection')
  const offerDigest = own(fields, 'offerDigest')
  const acceptDigest = own(fields, 'acceptDigest')
  const admittedForwardCells = own(fields, 'admittedForwardCells')
  const admittedForwardBytes = own(fields, 'admittedForwardBytes')
  const admittedForwardCommands = own(fields, 'admittedForwardCommands')
  const admittedReverseCells = own(fields, 'admittedReverseCells')
  const admittedReverseBytes = own(fields, 'admittedReverseBytes')
  const admittedReverseCommands = own(fields, 'admittedReverseCommands')
  const admittedMaxStreams = own(fields, 'admittedMaxStreams')
  const admittedReceiveFrames = own(fields, 'admittedReceiveFrames')
  const admittedReceiveBytes = own(fields, 'admittedReceiveBytes')
  const admittedSemanticOwnedBytes = own(fields, 'admittedSemanticOwnedBytes')
  const admittedMaxQueuedBytes = own(fields, 'admittedMaxQueuedBytes')
  const offerNonce = own(fields, 'offerNonce')
  const acceptNonce = own(fields, 'acceptNonce')

  if (
    !fixed(tailControlTranscriptDigest, 32) ||
    !fixed(terminalAdvertisementDigest, 32) ||
    !fixed(routeId, 16) ||
    !fixed(circuitId, 16) ||
    !uint64(generation) ||
    !Number.isSafeInteger(purpose) ||
    purpose < 1 ||
    purpose > 3 ||
    !Number.isSafeInteger(sourceDirection) ||
    (sourceDirection !== 0 && sourceDirection !== 1) ||
    !fixed(offerDigest, 32) ||
    !fixed(acceptDigest, 32) ||
    !uint32(admittedForwardCells) ||
    !uint64(admittedForwardBytes) ||
    !uint32(admittedForwardCommands) ||
    !uint32(admittedReverseCells) ||
    !uint64(admittedReverseBytes) ||
    !uint32(admittedReverseCommands) ||
    !Number.isSafeInteger(admittedMaxStreams) ||
    admittedMaxStreams < 0 ||
    admittedMaxStreams > MAX_UINT16 ||
    !Number.isSafeInteger(admittedReceiveFrames) ||
    admittedReceiveFrames < 0 ||
    admittedReceiveFrames > MAX_UINT16 ||
    !uint32(admittedReceiveBytes) ||
    !uint32(admittedSemanticOwnedBytes) ||
    !uint32(admittedMaxQueuedBytes) ||
    !fixed(offerNonce, 16) ||
    !fixed(acceptNonce, 16)
  ) {
    invalid()
  }

  let input = null
  try {
    input = b4a.allocUnsafeSlow(254)
    let offset = 0
    writeUint32(input, PEER_PROTOCOL_VERSION, offset)
    offset += 4
    set(input, tailControlTranscriptDigest, offset)
    offset += 32
    set(input, terminalAdvertisementDigest, offset)
    offset += 32
    set(input, routeId, offset)
    offset += 16
    set(input, circuitId, offset)
    offset += 16
    writeUint64(input, generation, offset)
    offset += 8
    input[offset++] = purpose
    input[offset++] = sourceDirection
    set(input, offerDigest, offset)
    offset += 32
    set(input, acceptDigest, offset)
    offset += 32
    writeUint32(input, admittedForwardCells, offset)
    offset += 4
    writeUint64(input, admittedForwardBytes, offset)
    offset += 8
    writeUint32(input, admittedForwardCommands, offset)
    offset += 4
    writeUint32(input, admittedReverseCells, offset)
    offset += 4
    writeUint64(input, admittedReverseBytes, offset)
    offset += 8
    writeUint32(input, admittedReverseCommands, offset)
    offset += 4
    writeUint16(input, admittedMaxStreams, offset)
    offset += 2
    writeUint16(input, admittedReceiveFrames, offset)
    offset += 2
    writeUint32(input, admittedReceiveBytes, offset)
    offset += 4
    writeUint32(input, admittedSemanticOwnedBytes, offset)
    offset += 4
    writeUint32(input, admittedMaxQueuedBytes, offset)
    offset += 4
    set(input, offerNonce, offset)
    offset += 16
    set(input, acceptNonce, offset)
    offset += 16
    if (offset !== 254) invalid()
    return hashPeer(PURPOSE_DIGEST_DOMAIN, [input])
  } finally {
    clear(input)
  }
}

function digestPeerPurposeConfirmation(kind, sentinelBody) {
  if (
    (kind !== 'source' && kind !== 'terminal') ||
    bufferLength(sentinelBody) !== PURPOSE_RELIABLE_ACK_BODY_SIZE
  ) {
    invalid()
  }
  return hashPeer(
    kind === 'source' ? PURPOSE_SOURCE_CONFIRM_DOMAIN : PURPOSE_TERMINAL_CONFIRM_DOMAIN,
    [sentinelBody]
  )
}

function createPeerPurposeFinalTranscript(fields) {
  ownObject(fields)
  const values = [
    own(fields, 'tailControlTranscriptDigest'),
    own(fields, 'purposeDigest'),
    own(fields, 'offerDigest'),
    own(fields, 'acceptDigest'),
    own(fields, 'sourceConfirmDigest'),
    own(fields, 'terminalConfirmDigest')
  ]
  if (values.some((value) => !fixed(value, 32))) invalid()

  const version = b4a.allocUnsafeSlow(4)
  try {
    writeUint32(version, PEER_PROTOCOL_VERSION, 0)
    return hashPeer(PURPOSE_FINAL_TRANSCRIPT_DOMAIN, [version, ...values])
  } finally {
    clear(version)
  }
}

function clearPeerAdjacencyKeys(keys) {
  if (!keys) return
  for (const value of Object.values(keys)) clear(value)
}

function derivePeerAdjacencyKeys(sharedSecret32, completeOffer432, completeAccept285, cellClass) {
  if (!fixed(sharedSecret32, 32) || isZero32(sharedSecret32)) invalidKey()

  let transcript = null
  let keys = null
  let forwardNonce = null
  let reverseNonce = null
  let transferred = false

  try {
    transcript = createPeerAdjacencyTranscript(completeOffer432, completeAccept285, cellClass)

    keys = {}
    keys.forwardKey = derivePeerKey(sharedSecret32, ADJACENCY_LABELS.FORWARD_KEY, transcript)
    keys.reverseKey = derivePeerKey(sharedSecret32, ADJACENCY_LABELS.REVERSE_KEY, transcript)

    forwardNonce = derivePeerKey(sharedSecret32, ADJACENCY_LABELS.FORWARD_NONCE, transcript)
    reverseNonce = derivePeerKey(sharedSecret32, ADJACENCY_LABELS.REVERSE_NONCE, transcript)

    keys.forwardNoncePrefix = copy(bufferSubarray.call(forwardNonce, 0, 16))
    keys.reverseNoncePrefix = copy(bufferSubarray.call(reverseNonce, 0, 16))

    transferred = true
    return keys
  } finally {
    clear(forwardNonce)
    clear(reverseNonce)
    clear(transcript)
    if (!transferred) clearPeerAdjacencyKeys(keys)
  }
}

function clearTailKeys(keys) {
  if (!keys) return
  for (const value of Object.values(keys)) clear(value)
}

function derivePeerTailKeys(sharedSecret32, transcript290) {
  if (!fixed(sharedSecret32, 32)) invalidKey()
  if (!fixed(transcript290, TAIL_CONTROL_TRANSCRIPT_SIZE)) invalid()

  let keys = null
  let tailControlForwardNonce = null
  let tailControlReverseNonce = null
  let finalizeForwardNonce = null
  let finalizeReverseNonce = null
  let transferred = false

  try {
    keys = {}
    keys.tailControlForwardKey = derivePeerKey(
      sharedSecret32,
      'hyperdht-private-routes/kdf/v2/tail-control/forward-key',
      transcript290
    )
    keys.tailControlReverseKey = derivePeerKey(
      sharedSecret32,
      'hyperdht-private-routes/kdf/v2/tail-control/reverse-key',
      transcript290
    )
    keys.finalizeForwardKey = derivePeerKey(
      sharedSecret32,
      'hyperdht-private-routes/kdf/v2/tail-finalize/forward-key',
      transcript290
    )
    keys.finalizeReverseKey = derivePeerKey(
      sharedSecret32,
      'hyperdht-private-routes/kdf/v2/tail-finalize/reverse-key',
      transcript290
    )

    tailControlForwardNonce = derivePeerKey(
      sharedSecret32,
      'hyperdht-private-routes/kdf/v2/tail-control/forward-nonce',
      transcript290
    )
    tailControlReverseNonce = derivePeerKey(
      sharedSecret32,
      'hyperdht-private-routes/kdf/v2/tail-control/reverse-nonce',
      transcript290
    )
    finalizeForwardNonce = derivePeerKey(
      sharedSecret32,
      'hyperdht-private-routes/kdf/v2/tail-finalize/forward-nonce',
      transcript290
    )
    finalizeReverseNonce = derivePeerKey(
      sharedSecret32,
      'hyperdht-private-routes/kdf/v2/tail-finalize/reverse-nonce',
      transcript290
    )

    keys.tailControlForwardNoncePrefix = copy(bufferSubarray.call(tailControlForwardNonce, 0, 16))
    keys.tailControlReverseNoncePrefix = copy(bufferSubarray.call(tailControlReverseNonce, 0, 16))
    keys.finalizeForwardNoncePrefix = copy(bufferSubarray.call(finalizeForwardNonce, 0, 16))
    keys.finalizeReverseNoncePrefix = copy(bufferSubarray.call(finalizeReverseNonce, 0, 16))

    transferred = true
    return keys
  } finally {
    clear(tailControlForwardNonce)
    clear(tailControlReverseNonce)
    clear(finalizeForwardNonce)
    clear(finalizeReverseNonce)
    if (!transferred) clearTailKeys(keys)
  }
}

function acquireConfirmationArena(arena) {
  if (!fixed(arena, CONFIRMATION_ARENA_SIZE)) invalid()
  if (HELD_CONFIRMATION_ARENAS.has(arena)) invalid()
  HELD_CONFIRMATION_ARENAS.add(arena)
}

function snapshotConfirmationOptions(options, operation) {
  ownObject(options)

  const directionKey = own(options, 'directionKey')
  const labelValue = own(options, 'label')
  const noiseHash = own(options, 'noiseHash')
  const sessionId = own(options, 'sessionId')
  const sourcePurposeDigest = own(options, 'sourcePurposeDigest')
  const destinationPurposeDigest = own(options, 'destinationPurposeDigest')
  const registrationCommitment = own(options, 'registrationCommitment')
  const transcriptParts = own(options, 'transcriptParts')
  const result = {
    directionKey,
    label: confirmationLabel(labelValue),
    noiseHash,
    sessionId,
    sourcePurposeDigest,
    destinationPurposeDigest,
    registrationCommitment,
    transcriptParts: snapshotParts(transcriptParts)
  }

  if (!fixed(directionKey, 32)) invalidKey()
  if (!fixed(noiseHash, 64)) invalid()
  if (!fixed(sessionId, 16)) invalid()
  if (!fixed(sourcePurposeDigest, 32)) invalid()
  if (!fixed(destinationPurposeDigest, 32)) invalid()
  if (!fixed(registrationCommitment, 32)) invalid()

  const tagName = operation === 'compute' ? 'outputTag32' : 'receivedTag32'
  const tag = own(options, tagName)
  if (!fixed(tag, 32)) invalid()
  result.tag = tag
  return result
}

function confirmationLabel(value) {
  if (typeof value === 'string') {
    const index = CONFIRMATION_LABELS.indexOf(value)
    if (index !== -1) return CONFIRMATION_LABEL_BYTES[index]
    invalid()
  }

  const length = bufferLength(value)
  if (length < 0) invalid()
  for (const candidate of CONFIRMATION_LABEL_BYTES) {
    if (length === bufferLength(candidate) && sodium.sodium_memcmp(value, candidate)) {
      return candidate
    }
  }
  invalid()
}

function confirmationProcess(arena, options, operation) {
  const state = bufferSubarray.call(arena, 0, CONFIRMATION_HASH_STATE_SIZE)
  const confirmationKey = bufferSubarray.call(
    arena,
    CONFIRMATION_HASH_STATE_SIZE,
    CONFIRMATION_HASH_STATE_SIZE + CONFIRMATION_KEY_SIZE
  )
  const computedTag = bufferSubarray.call(
    arena,
    CONFIRMATION_HASH_STATE_SIZE + CONFIRMATION_KEY_SIZE,
    CONFIRMATION_HASH_STATE_SIZE + CONFIRMATION_KEY_SIZE + CONFIRMATION_TAG_SIZE
  )
  const framing = bufferSubarray.call(
    arena,
    CONFIRMATION_HASH_STATE_SIZE + CONFIRMATION_KEY_SIZE + CONFIRMATION_TAG_SIZE,
    CONFIRMATION_ARENA_SIZE
  )

  const labelLength = bufferLength(options.label)
  const kdfPrefixLength = 10 + labelLength
  if (kdfPrefixLength > framing.byteLength) invalid()
  bufferFill.call(framing, 0)
  writeUint16(framing, labelLength, 0)
  set(framing, options.label, 2)
  writeUint32(framing, PEER_PROTOCOL_VERSION, 2 + labelLength)
  writeUint32(framing, CONFIRMATION_CONTEXT_SIZE, 6 + labelLength)

  sodium.crypto_generichash_init(state, options.directionKey, 32)
  sodium.crypto_generichash_update(state, bufferSubarray.call(framing, 0, kdfPrefixLength))
  sodium.crypto_generichash_update(state, options.noiseHash)
  sodium.crypto_generichash_update(state, options.sessionId)
  sodium.crypto_generichash_update(state, options.sourcePurposeDigest)
  sodium.crypto_generichash_update(state, options.destinationPurposeDigest)
  sodium.crypto_generichash_update(state, options.registrationCommitment)
  sodium.crypto_generichash_final(state, confirmationKey)

  writeUint32(framing, options.transcriptParts.total, 0)
  sodium.crypto_generichash_init(state, confirmationKey, 32)
  sodium.crypto_generichash_update(state, bufferSubarray.call(framing, 0, 4))
  for (const value of options.transcriptParts.values) sodium.crypto_generichash_update(state, value)
  sodium.crypto_generichash_final(state, computedTag)

  if (operation === 'compute') {
    set(options.tag, computedTag)
    return undefined
  }
  return sodium.sodium_memcmp(computedTag, options.tag)
}

function computePeerConfirmation(arena, options) {
  acquireConfirmationArena(arena)
  try {
    const snapshot = snapshotConfirmationOptions(options, 'compute')
    confirmationProcess(arena, snapshot, 'compute')
  } finally {
    clear(arena)
    HELD_CONFIRMATION_ARENAS.delete(arena)
  }
}

function verifyPeerConfirmation(arena, options) {
  acquireConfirmationArena(arena)
  try {
    const snapshot = snapshotConfirmationOptions(options, 'verify')
    return confirmationProcess(arena, snapshot, 'verify')
  } finally {
    clear(arena)
    HELD_CONFIRMATION_ARENAS.delete(arena)
  }
}

module.exports = Object.freeze({
  hashPeer,
  derivePeerKey,
  digestPeerLimits,
  createPeerTailTranscript,
  derivePeerTailKeys,
  clearTailKeys,
  createPeerAdjacencyTranscript,
  derivePeerAdjacencyKeys,
  clearPeerAdjacencyKeys,
  createPeerPurposePreTranscript,
  createPeerPurposeTranscript,
  derivePeerPurposeSharedSecret,
  computePeerPurposeMac,
  verifyPeerPurposeMac,
  derivePeerPurposeKeys,
  clearPeerPurposeKeys,
  digestPeerPurposeOffer,
  digestPeerPurposeAccept,
  createPeerPurposeDigest,
  digestPeerPurposeConfirmation,
  createPeerPurposeFinalTranscript,
  computePeerConfirmation,
  verifyPeerConfirmation
})
