'use strict'

const b4a = require('b4a')
const crypto = require('hypercore-crypto')
const sodium = require('sodium-universal')

const { PrivateRouteError } = require('./errors')
const {
  PEER_MESSAGE_ID,
  PEER_PROTOCOL_VERSION,
  decodePeerObject,
  encodePeerObject
} = require('./peer-protocol')
const { decodePeerTransport } = require('./peer-transport-wire')
const { decodeCanonicalEndpoint, encodeCanonicalEndpoint } = require('./relay-capability')

const MAX_U64 = 0xffff_ffff_ffff_ffffn
const typedArrayByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get

const BOOTSTRAP_RPC_MAGIC = 0xd301

const ADVERTISEMENT_LABEL = b4a.from('hyperdht-private-routes/m3/capability-advertisement/v2')
const ADVERTISEMENT_DIGEST_DOMAIN = 'hyperdht-private-routes/m3/capability-advertisement-digest/v2'
const CAPS_RESPONSE_LABEL = b4a.from('hyperdht-private-routes/m3/caps-response/v2')
const ACTIVE_RESPONSE_LABEL = b4a.from('hyperdht-private-routes/m3/active-challenge-response/v2')
const LINK_OFFER_LABEL = b4a.from('hyperdht-private-routes/m3/link-offer/v2')
const LINK_ACCEPT_LABEL = b4a.from('hyperdht-private-routes/m3/link-accept/v2')
const REDACTED_PROOF_LABEL = b4a.from('hyperdht-private-routes/m3/redacted-responder-proof/v2')
const TAIL_READY_LABEL = b4a.from('hyperdht-private-routes/m3/tail-ready/v2')

const relayOwners = new WeakMap()
const verifiedAdvertisements = new WeakMap()
const candidateLocators = new WeakMap()

// Fixed permitted signed-object registry: messageId -> { label, bodyBytes }.
const SIGN_PEER_OBJECT_REGISTRY = new Map([
  [
    PEER_MESSAGE_ID.PEER_CAPABILITY_ADVERTISEMENT_V2,
    { label: ADVERTISEMENT_LABEL, bodyBytes: 188 }
  ],
  [PEER_MESSAGE_ID.PEER_CAPS_RESPONSE_V2, { label: CAPS_RESPONSE_LABEL, bodyBytes: 335 }],
  [
    PEER_MESSAGE_ID.PEER_ACTIVE_CHALLENGE_RESPONSE_V2,
    { label: ACTIVE_RESPONSE_LABEL, bodyBytes: 240 }
  ],
  [PEER_MESSAGE_ID.PEER_LINK_OFFER_V2, { label: LINK_OFFER_LABEL, bodyBytes: 360 }],
  [PEER_MESSAGE_ID.PEER_LINK_ACCEPT_V2, { label: LINK_ACCEPT_LABEL, bodyBytes: 213 }],
  [
    PEER_MESSAGE_ID.PEER_REDACTED_RESPONDER_PROOF_V2,
    { label: REDACTED_PROOF_LABEL, bodyBytes: 306 }
  ],
  [PEER_MESSAGE_ID.PEER_TAIL_READY_V2, { label: TAIL_READY_LABEL, bodyBytes: 210 }]
])

function hashPeer(domain, parts) {
  const domainBuf = typeof domain === 'string' ? b4a.from(domain, 'utf8') : domain
  const labelLen = b4a.allocUnsafe(2)
  labelLen.writeUInt16BE(domainBuf.byteLength, 0)

  const bufs = [labelLen, domainBuf]
  if (Array.isArray(parts)) {
    for (const p of parts) bufs.push(p)
  } else if (parts) {
    bufs.push(parts)
  }

  return crypto.hash(bufs)
}

function bufferLength(val) {
  try {
    return b4a.isBuffer(val) ? Reflect.apply(typedArrayByteLength, val, []) : -1
  } catch {
    return -1
  }
}

function bufferCopy(val) {
  const len = bufferLength(val)
  if (len < 0) throw PrivateRouteError.INVALID_ROUTE()
  const out = b4a.allocUnsafe(len)
  out.set(val, 0)
  return out
}

function readU16BE(buf, offset) {
  return (buf[offset] << 8) | buf[offset + 1]
}

function readU32BE(buf, offset) {
  return (
    buf[offset] * 0x1000000 + (buf[offset + 1] << 16) + (buf[offset + 2] << 8) + buf[offset + 3]
  )
}

function readU64BE(buf, offset) {
  const hi = readU32BE(buf, offset)
  const lo = readU32BE(buf, offset + 4)
  return (BigInt(hi) << 32n) | BigInt(lo)
}

function writeU16BE(buf, val, offset) {
  buf[offset] = val >>> 8
  buf[offset + 1] = val
}

function writeU32BE(buf, val, offset) {
  buf[offset] = val >>> 24
  buf[offset + 1] = val >>> 16
  buf[offset + 2] = val >>> 8
  buf[offset + 3] = val
}

function writeU64BE(buf, val, offset) {
  const hi = Number(val >> 32n)
  const lo = Number(val & 0xffffffffn)
  writeU32BE(buf, hi, offset)
  writeU32BE(buf, lo, offset + 4)
}

function ed25519Sign(message, secretKey) {
  const sig = b4a.alloc(64)
  sodium.crypto_sign_detached(sig, message, secretKey)
  return sig
}

function ed25519Verify(sig, message, publicKey) {
  return sodium.crypto_sign_verify_detached(sig, message, publicKey)
}

function buildAdvertisementSignatureInput(body188) {
  const labelLen = b4a.allocUnsafe(2)
  labelLen.writeUInt16BE(ADVERTISEMENT_LABEL.byteLength, 0)
  const ver = b4a.from([0, 0, 0, 2])
  const msgId = b4a.from([0x03, 0x00])
  const bodyLen = b4a.from([0x00, 0xbc]) // 188
  return b4a.concat([labelLen, ADVERTISEMENT_LABEL, ver, msgId, bodyLen, body188])
}

function parseNumericHost(host) {
  if (typeof host !== 'string' || host.length === 0) throw PrivateRouteError.INVALID_ROUTE()
  if (/^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$/.test(host)) {
    const parts = host.split('.')
    const addressBytes = b4a.alloc(4)
    for (let i = 0; i < 4; i++) {
      const value = Number(parts[i])
      if (!Number.isInteger(value) || value < 0 || value > 255)
        throw PrivateRouteError.INVALID_ROUTE()
      addressBytes[i] = value
    }
    return { addressFamily: 4, addressBytes }
  }
  if (!/^[0-9a-f:]+$/i.test(host) || host.includes('%') || host.includes('.')) {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  const lower = host.toLowerCase()
  const marker = lower.indexOf('::')
  if (marker !== -1 && marker !== lower.lastIndexOf('::')) throw PrivateRouteError.INVALID_ROUTE()
  const left = (marker === -1 ? lower : lower.slice(0, marker)).split(':').filter(Boolean)
  const right = (marker === -1 ? '' : lower.slice(marker + 2)).split(':').filter(Boolean)
  const words = [...left, ...right]
  if (!words.every((part) => /^[0-9a-f]{1,4}$/.test(part))) throw PrivateRouteError.INVALID_ROUTE()
  const zeroWords = marker === -1 ? 0 : 8 - words.length
  if (marker === -1 ? words.length !== 8 : zeroWords < 1) throw PrivateRouteError.INVALID_ROUTE()
  const normalized = marker === -1 ? words : [...left, ...Array(zeroWords).fill('0'), ...right]
  const addressBytes = b4a.alloc(16)
  for (let i = 0; i < normalized.length; i++) {
    const value = Number.parseInt(normalized[i], 16)
    if (!Number.isInteger(value) || value < 0 || value > 0xffff)
      throw PrivateRouteError.INVALID_ROUTE()
    addressBytes[i * 2] = value >>> 8
    addressBytes[i * 2 + 1] = value
  }
  return { addressFamily: 6, addressBytes }
}

function encodeReachableEndpoint(endpoint) {
  if (!endpoint || typeof endpoint !== 'object') throw PrivateRouteError.INVALID_ROUTE()
  const host = ownDataProperty(endpoint, 'host')
  const port = ownDataProperty(endpoint, 'port')
  if (typeof port !== 'number' || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  const parsed = parseNumericHost(host)
  return encodeCanonicalEndpoint({
    addressFamily: parsed.addressFamily,
    addressBytes: parsed.addressBytes,
    port
  })
}

function formatCanonicalHost(buf19) {
  const family = buf19[0]
  if (family === 4) {
    return `${buf19[13]}.${buf19[14]}.${buf19[15]}.${buf19[16]}`
  }
  const words = []
  for (let offset = 1; offset < 17; offset += 2) {
    words.push(((buf19[offset] << 8) | buf19[offset + 1]).toString(16))
  }
  return words.join(':')
}

function decodeReachableEndpoint(buf19) {
  const canonical = decodeCanonicalEndpoint(buf19)
  try {
    const port = readU16BE(canonical, 17)
    if (port === 0) throw PrivateRouteError.INVALID_ROUTE()
    return {
      host: formatCanonicalHost(canonical),
      port,
      family: canonical[0]
    }
  } finally {
    // decodeCanonicalEndpoint returns an owned copy; keep caller-owned bytes intact
  }
}

function requireCanonicalEndpoint19(value) {
  if (bufferLength(value) !== 19) throw PrivateRouteError.INVALID_ROUTE()
  const canonical = decodeCanonicalEndpoint(value)
  return bufferCopy(canonical)
}

function ownDataProperty(obj, key) {
  if (obj === null || typeof obj !== 'object') return undefined
  const desc = Object.getOwnPropertyDescriptor(obj, key)
  if (!desc || !Object.prototype.hasOwnProperty.call(desc, 'value')) return undefined
  return desc.value
}

function buildAdvertisementBody(fields) {
  const body = b4a.alloc(188, 0)

  const relayIdentity32 = ownDataProperty(fields, 'relayIdentity32')
  if (bufferLength(relayIdentity32) !== 32) throw PrivateRouteError.INVALID_IDENTITY()
  body.set(relayIdentity32, 0)

  const currentDhtNodeId32 = ownDataProperty(fields, 'currentDhtNodeId32')
  if (bufferLength(currentDhtNodeId32) !== 32) throw PrivateRouteError.INVALID_IDENTITY()
  body.set(currentDhtNodeId32, 32)

  const reachableEndpoint19 = ownDataProperty(fields, 'reachableEndpoint19')
  const reachableEndpoint = ownDataProperty(fields, 'reachableEndpoint')
  const ep19 =
    bufferLength(reachableEndpoint19) === 19
      ? requireCanonicalEndpoint19(reachableEndpoint19)
      : encodeReachableEndpoint(reachableEndpoint)
  body.set(ep19, 64)

  const routeEncryptionPublicKey32 = ownDataProperty(fields, 'routeEncryptionPublicKey32')
  if (bufferLength(routeEncryptionPublicKey32) !== 32) throw PrivateRouteError.INVALID_KEY()
  body.set(routeEncryptionPublicKey32, 83)

  const capabilityMask = ownDataProperty(fields, 'capabilityMask')
  if (capabilityMask !== 9 && capabilityMask !== 11) throw PrivateRouteError.INVALID_ROUTE()
  writeU32BE(body, capabilityMask, 115)

  const minimumVersion = ownDataProperty(fields, 'minimumVersion')
  const maximumVersion = ownDataProperty(fields, 'maximumVersion')
  if (minimumVersion !== 2 || maximumVersion !== 2) throw PrivateRouteError.INVALID_ROUTE()
  writeU32BE(body, minimumVersion, 119)
  writeU32BE(body, maximumVersion, 123)

  writeU16BE(body, 1200, 127) // cellSize
  writeU16BE(body, 1146, 129) // maxCellPayload
  writeU16BE(body, 1101, 131) // contextEnvelopeSize
  writeU16BE(body, 1100, 133) // routeFrameSize
  writeU16BE(body, 1073, 135) // maxRoutePayload

  const datagramReplayWindow = ownDataProperty(fields, 'datagramReplayWindow')
  if (typeof datagramReplayWindow !== 'number') throw PrivateRouteError.INVALID_ROUTE()
  writeU16BE(body, datagramReplayWindow, 137)

  const maxConcurrentCircuits = ownDataProperty(fields, 'maxConcurrentCircuits')
  if (typeof maxConcurrentCircuits !== 'number') throw PrivateRouteError.INVALID_ROUTE()
  writeU16BE(body, maxConcurrentCircuits, 139)

  const capacityClass = ownDataProperty(fields, 'capacityClass')
  if (typeof capacityClass !== 'number' || capacityClass < 0 || capacityClass > 2)
    throw PrivateRouteError.INVALID_ROUTE()
  body[141] = capacityClass

  const maxCells = ownDataProperty(fields, 'maxCells')
  if (typeof maxCells !== 'number') throw PrivateRouteError.INVALID_ROUTE()
  writeU32BE(body, maxCells, 142)

  const maxBytes = ownDataProperty(fields, 'maxBytes')
  if (typeof maxBytes !== 'number') throw PrivateRouteError.INVALID_ROUTE()
  writeU32BE(body, maxBytes, 146)

  const maxCommands = ownDataProperty(fields, 'maxCommands')
  if (typeof maxCommands !== 'number') throw PrivateRouteError.INVALID_ROUTE()
  writeU32BE(body, maxCommands, 150)

  const idleTimeoutMs = ownDataProperty(fields, 'idleTimeoutMs')
  if (typeof idleTimeoutMs !== 'number') throw PrivateRouteError.INVALID_ROUTE()
  writeU32BE(body, idleTimeoutMs, 154)

  const maxQueuedBytes = ownDataProperty(fields, 'maxQueuedBytes')
  if (typeof maxQueuedBytes !== 'number') throw PrivateRouteError.INVALID_ROUTE()
  writeU32BE(body, maxQueuedBytes, 158)

  const epoch = ownDataProperty(fields, 'epoch')
  if (typeof epoch !== 'bigint') throw PrivateRouteError.INVALID_ROUTE()
  writeU64BE(body, epoch, 162)

  const issuedAt = ownDataProperty(fields, 'issuedAt')
  if (typeof issuedAt !== 'bigint') throw PrivateRouteError.INVALID_ROUTE()
  writeU64BE(body, issuedAt, 170)

  const expiresAt = ownDataProperty(fields, 'expiresAt')
  if (typeof expiresAt !== 'bigint') throw PrivateRouteError.INVALID_ROUTE()
  writeU64BE(body, expiresAt, 178)
  const policyCount = ownDataProperty(fields, 'policyCount')
  if (policyCount !== 0) throw PrivateRouteError.INVALID_ROUTE()
  writeU16BE(body, 0, 186)
  return body
}

function parseAdvertisementBody(body188) {
  if (bufferLength(body188) !== 188) throw PrivateRouteError.INVALID_ROUTE()
  const reachableEndpoint19 = requireCanonicalEndpoint19(body188.subarray(64, 83))
  const capabilityMask = readU32BE(body188, 115)
  if (capabilityMask !== 9 && capabilityMask !== 11) throw PrivateRouteError.INVALID_ROUTE()
  const minimumVersion = readU32BE(body188, 119)
  const maximumVersion = readU32BE(body188, 123)
  if (minimumVersion !== 2 || maximumVersion !== 2) throw PrivateRouteError.INVALID_ROUTE()
  const cellSize = readU16BE(body188, 127)
  const maxCellPayload = readU16BE(body188, 129)
  const contextEnvelopeSize = readU16BE(body188, 131)
  const routeFrameSize = readU16BE(body188, 133)
  const maxRoutePayload = readU16BE(body188, 135)
  if (
    cellSize !== 1200 ||
    maxCellPayload !== 1146 ||
    contextEnvelopeSize !== 1101 ||
    routeFrameSize !== 1100 ||
    maxRoutePayload !== 1073
  ) {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  const policyCount = readU16BE(body188, 186)
  if (policyCount !== 0) throw PrivateRouteError.INVALID_ROUTE()
  return {
    relayIdentity32: bufferCopy(body188.subarray(0, 32)),
    currentDhtNodeId32: bufferCopy(body188.subarray(32, 64)),
    reachableEndpoint19,
    reachableEndpoint: decodeReachableEndpoint(reachableEndpoint19),
    routeEncryptionPublicKey32: bufferCopy(body188.subarray(83, 115)),
    capabilityMask,
    minimumVersion,
    maximumVersion,
    cellSize,
    maxCellPayload,
    contextEnvelopeSize,
    routeFrameSize,
    maxRoutePayload,
    datagramReplayWindow: readU16BE(body188, 137),
    maxConcurrentCircuits: readU16BE(body188, 139),
    capacityClass: body188[141],
    maxCells: readU32BE(body188, 142),
    maxBytes: readU32BE(body188, 146),
    maxCommands: readU32BE(body188, 150),
    idleTimeoutMs: readU32BE(body188, 154),
    maxQueuedBytes: readU32BE(body188, 158),
    epoch: readU64BE(body188, 162),
    issuedAt: readU64BE(body188, 170),
    expiresAt: readU64BE(body188, 178),
    policyCount
  }
}

function createPeerRelayOwner(options) {
  if (!options || typeof options !== 'object') throw PrivateRouteError.INVALID_ROUTE()

  const endpoint = ownDataProperty(options, 'endpoint')
  const identityKeyPair = ownDataProperty(options, 'identityKeyPair')
  const routeKeyPair = ownDataProperty(options, 'routeKeyPair')
  const advertisementFields = ownDataProperty(options, 'advertisementFields')
  const clockIdentity = ownDataProperty(options, 'clockIdentity')
  const wallNow = ownDataProperty(options, 'wallNow')
  const monotonicNow = ownDataProperty(options, 'monotonicNow')
  const setTimer = ownDataProperty(options, 'setTimer')
  const clearTimer = ownDataProperty(options, 'clearTimer')

  if (!endpoint || typeof endpoint !== 'object') throw PrivateRouteError.INVALID_ROUTE()
  if (
    !identityKeyPair ||
    bufferLength(identityKeyPair.publicKey) !== 32 ||
    bufferLength(identityKeyPair.secretKey) !== 64
  ) {
    throw PrivateRouteError.INVALID_KEY()
  }
  if (
    !routeKeyPair ||
    bufferLength(routeKeyPair.publicKey) !== 32 ||
    bufferLength(routeKeyPair.secretKey) !== 32
  ) {
    throw PrivateRouteError.INVALID_KEY()
  }
  if (
    !clockIdentity ||
    typeof clockIdentity !== 'object' ||
    typeof wallNow !== 'function' ||
    typeof monotonicNow !== 'function'
  ) {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  if (typeof setTimer !== 'function' || typeof clearTimer !== 'function') {
    throw PrivateRouteError.INVALID_ROUTE()
  }

  if (!advertisementFields || typeof advertisementFields !== 'object')
    throw PrivateRouteError.INVALID_ROUTE()

  const relId = ownDataProperty(advertisementFields, 'relayIdentity32')
  if (!relId || bufferLength(relId) !== 32) throw PrivateRouteError.INVALID_KEY()

  const routePk = ownDataProperty(advertisementFields, 'routeEncryptionPublicKey32')
  if (!routePk || bufferLength(routePk) !== 32) throw PrivateRouteError.INVALID_KEY()

  const derivedEdPk = b4a.alloc(32)
  try {
    sodium.crypto_sign_ed25519_sk_to_pk(derivedEdPk, identityKeyPair.secretKey)
  } catch {
    throw PrivateRouteError.INVALID_KEY()
  }
  const edMatch =
    sodium.sodium_memcmp(derivedEdPk, identityKeyPair.publicKey) &&
    sodium.sodium_memcmp(derivedEdPk, relId)
  derivedEdPk.fill(0)
  if (!edMatch) throw PrivateRouteError.INVALID_KEY()

  const derivedXPk = b4a.alloc(32)
  try {
    sodium.crypto_scalarmult_base(derivedXPk, routeKeyPair.secretKey)
  } catch {
    throw PrivateRouteError.INVALID_KEY()
  }
  const xMatch =
    sodium.sodium_memcmp(derivedXPk, routeKeyPair.publicKey) &&
    sodium.sodium_memcmp(derivedXPk, routePk)
  derivedXPk.fill(0)
  if (!xMatch) throw PrivateRouteError.INVALID_KEY()
  const body188 = buildAdvertisementBody(advertisementFields)
  const sigInput = buildAdvertisementSignatureInput(body188)
  const signature64 = ed25519Sign(sigInput, identityKeyPair.secretKey)
  const canonicalAdvertisement260 = encodePeerObject({
    messageId: PEER_MESSAGE_ID.PEER_CAPABILITY_ADVERTISEMENT_V2,
    body: body188,
    authSuffix: signature64
  })

  const advertisementDigest32 = hashPeer(ADVERTISEMENT_DIGEST_DOMAIN, canonicalAdvertisement260)

  const ownerState = {
    destroyed: false,
    endpoint,
    identityKeyPair: {
      publicKey: bufferCopy(identityKeyPair.publicKey),
      secretKey: bufferCopy(identityKeyPair.secretKey)
    },
    routeKeyPair: {
      publicKey: bufferCopy(routeKeyPair.publicKey),
      secretKey: bufferCopy(routeKeyPair.secretKey)
    },
    canonicalAdvertisement260: bufferCopy(canonicalAdvertisement260),
    advertisementDigest32: bufferCopy(advertisementDigest32),
    parsedAdvertisement: parseAdvertisementBody(body188),
    clockIdentity,
    wallNow,
    monotonicNow,
    setTimer,
    clearTimer
  }

  const ownerHandle = Object.freeze({ kind: 'peerRelayOwner' })
  relayOwners.set(ownerHandle, ownerState)
  return ownerHandle
}

function buildSignPeerObjectInput(messageId, body, label) {
  const headerOffset = 2 + label.byteLength
  const bodyBytes = bufferLength(body)
  const input = b4a.alloc(headerOffset + 8 + bodyBytes + 64)
  input.writeUInt16BE(label.byteLength, 0)
  input.set(label, 2)
  input.writeUInt32BE(PEER_PROTOCOL_VERSION, headerOffset)
  input.writeUInt16BE(messageId, headerOffset + 4)
  input.writeUInt16BE(bodyBytes, headerOffset + 6)
  input.set(body, headerOffset + 8)
  return input
}

function liveRelayOwnerState(owner, endpoint) {
  const state = relayOwners.get(owner)
  if (!state || state.destroyed) throw PrivateRouteError.INVALID_ROUTE()
  if (endpoint && state.endpoint !== endpoint) throw PrivateRouteError.INVALID_ROUTE()
  return state
}

function readPeerRelayOwner(owner, endpoint) {
  const state = liveRelayOwnerState(owner, endpoint)
  const boundEndpoint = state.endpoint

  function validateSignBody(live, messageId, body) {
    const id = live.identityKeyPair.publicKey
    const adDigest = live.advertisementDigest32
    const adBytes = live.canonicalAdvertisement260
    const routePk = live.routeKeyPair.publicKey
    const adBody = adBytes.subarray(8, 196)

    if (messageId === PEER_MESSAGE_ID.PEER_CAPABILITY_ADVERTISEMENT_V2) {
      if (!b4a.equals(body, adBody)) throw PrivateRouteError.INVALID_ROUTE()
      return
    }
    if (messageId === PEER_MESSAGE_ID.PEER_CAPS_RESPONSE_V2) {
      // responderIdentity32 | queryNonce32 | responseTime u64 | count=1 | adLen=260 | ad260
      if (!b4a.equals(body.subarray(0, 32), id)) throw PrivateRouteError.INVALID_ROUTE()
      if (!b4a.equals(body.subarray(75, 335), adBytes)) throw PrivateRouteError.INVALID_ROUTE()
      return
    }
    if (messageId === PEER_MESSAGE_ID.PEER_ACTIVE_CHALLENGE_RESPONSE_V2) {
      // adDigest | responderIdentity | ... | proof
      if (!b4a.equals(body.subarray(0, 32), adDigest)) throw PrivateRouteError.INVALID_ROUTE()
      if (!b4a.equals(body.subarray(32, 64), id)) throw PrivateRouteError.INVALID_ROUTE()
      return
    }
    if (messageId === PEER_MESSAGE_ID.PEER_LINK_OFFER_V2) {
      // adDigest32 is the selected responder/candidate advertisement, not the initiator owner's.
      if (!b4a.equals(body.subarray(32, 64), id)) throw PrivateRouteError.INVALID_ROUTE()
      return
    }
    if (messageId === PEER_MESSAGE_ID.PEER_LINK_ACCEPT_V2) {
      // offerDigest32 | adDigest32 | responderIdentity32 | observedEndpoint19 | ...
      if (!b4a.equals(body.subarray(32, 64), adDigest)) throw PrivateRouteError.INVALID_ROUTE()
      if (!b4a.equals(body.subarray(64, 96), id)) throw PrivateRouteError.INVALID_ROUTE()
      return
    }
    if (messageId === PEER_MESSAGE_ID.PEER_REDACTED_RESPONDER_PROOF_V2) {
      // responderAdDigest | initiatorId | responderId | branchClass=2 @96 | generation @129 | ext @137 ∈ {1,2} | ... | routePk @202
      if (!b4a.equals(body.subarray(0, 32), adDigest)) throw PrivateRouteError.INVALID_ROUTE()
      if (!b4a.equals(body.subarray(64, 96), id)) throw PrivateRouteError.INVALID_ROUTE()
      if (body[137] !== 1 && body[137] !== 2) throw PrivateRouteError.INVALID_ROUTE()
      if (!b4a.equals(body.subarray(202, 234), routePk)) throw PrivateRouteError.INVALID_ROUTE()
      return
    }
    if (messageId === PEER_MESSAGE_ID.PEER_TAIL_READY_V2) {
      if (!b4a.equals(body.subarray(74, 106), id)) throw PrivateRouteError.INVALID_ROUTE()
      if (!b4a.equals(body.subarray(106, 138), adDigest)) throw PrivateRouteError.INVALID_ROUTE()
      return
    }
    throw PrivateRouteError.INVALID_ROUTE()
  }

  function signPeerObject(messageId, canonicalBody) {
    const live = liveRelayOwnerState(owner, boundEndpoint)
    const entry = SIGN_PEER_OBJECT_REGISTRY.get(messageId)
    if (!entry) throw PrivateRouteError.INVALID_ROUTE()
    if (bufferLength(canonicalBody) !== entry.bodyBytes) throw PrivateRouteError.INVALID_ROUTE()
    if (!b4a.equals(live.identityKeyPair.publicKey, live.parsedAdvertisement.relayIdentity32)) {
      throw PrivateRouteError.INVALID_KEY()
    }
    let input = null
    try {
      input = buildSignPeerObjectInput(messageId, canonicalBody, entry.label)
      const wire = input.subarray(2 + entry.label.byteLength)
      decodePeerTransport(wire)
      validateSignBody(live, messageId, wire.subarray(8, wire.byteLength - 64))
      return ed25519Sign(input.subarray(0, input.byteLength - 64), live.identityKeyPair.secretKey)
    } finally {
      if (input) input.fill(0)
    }
  }

  function agreeRoute(remotePublicKey32) {
    const live = liveRelayOwnerState(owner, boundEndpoint)
    if (bufferLength(remotePublicKey32) !== 32) throw PrivateRouteError.INVALID_KEY()
    let zero = 0
    for (let i = 0; i < 32; i++) zero |= remotePublicKey32[i]
    if (zero === 0) throw PrivateRouteError.INVALID_KEY()
    const shared = b4a.alloc(32)
    try {
      sodium.crypto_scalarmult(shared, live.routeKeyPair.secretKey, remotePublicKey32)
    } catch {
      shared.fill(0)
      throw PrivateRouteError.INVALID_KEY()
    }
    let outZero = 0
    for (let i = 0; i < 32; i++) outZero |= shared[i]
    if (outZero === 0) {
      shared.fill(0)
      throw PrivateRouteError.INVALID_KEY()
    }
    // Caller owns returned buffer and must erase in finally.
    return shared
  }

  const canonicalAdvertisement260 = bufferCopy(state.canonicalAdvertisement260)
  return Object.freeze({
    relayIdentity32: bufferCopy(state.identityKeyPair.publicKey),
    routeEncryptionPublicKey32: bufferCopy(state.routeKeyPair.publicKey),
    canonicalAdvertisement260,
    advertisementDigest32: bufferCopy(state.advertisementDigest32),
    parsedAdvertisement: Object.freeze(
      parseAdvertisementBody(canonicalAdvertisement260.subarray(8, 196))
    ),
    clockIdentity: state.clockIdentity,
    wallNow: state.wallNow,
    monotonicNow: state.monotonicNow,
    setTimer: state.setTimer,
    clearTimer: state.clearTimer,
    signPeerObject,
    agreeRoute
  })
}

function destroyPeerRelayOwner(owner) {
  const state = relayOwners.get(owner)
  if (!state) return false
  if (state.destroyed) return true

  state.destroyed = true
  state.identityKeyPair.secretKey.fill(0)
  state.routeKeyPair.secretKey.fill(0)
  return true
}

function verifyPeerAdvertisement(wire, expectations = {}) {
  let transportObj
  try {
    transportObj = decodePeerTransport(wire)
  } catch {
    throw PrivateRouteError.INVALID_DESCRIPTOR()
  }

  if (
    !transportObj ||
    transportObj.messageId !== PEER_MESSAGE_ID.PEER_CAPABILITY_ADVERTISEMENT_V2
  ) {
    throw PrivateRouteError.INVALID_DESCRIPTOR()
  }

  const { body, authSuffix } = transportObj
  if (bufferLength(authSuffix) !== 64 || bufferLength(body) !== 188) {
    throw PrivateRouteError.INVALID_DESCRIPTOR()
  }

  const parsed = parseAdvertisementBody(body)

  if (parsed.minimumVersion !== 2 || parsed.maximumVersion !== 2) {
    throw PrivateRouteError.INVALID_DESCRIPTOR()
  }
  if (parsed.policyCount !== 0) throw PrivateRouteError.INVALID_DESCRIPTOR()

  if (parsed.capabilityMask !== 9 && parsed.capabilityMask !== 11) {
    throw PrivateRouteError.INVALID_DESCRIPTOR()
  }

  if (
    parsed.cellSize !== 1200 ||
    parsed.maxCellPayload !== 1146 ||
    parsed.contextEnvelopeSize !== 1101 ||
    parsed.routeFrameSize !== 1100 ||
    parsed.maxRoutePayload !== 1073
  ) {
    throw PrivateRouteError.INVALID_DESCRIPTOR()
  }

  if (bufferLength(parsed.routeEncryptionPublicKey32) !== 32) {
    throw PrivateRouteError.INVALID_DESCRIPTOR()
  }
  let zeroCount = 0
  for (let i = 0; i < 32; i++) {
    if (parsed.routeEncryptionPublicKey32[i] === 0) zeroCount++
  }
  if (zeroCount === 32) throw PrivateRouteError.INVALID_DESCRIPTOR()

  const sigInput = buildAdvertisementSignatureInput(body)
  if (!ed25519Verify(authSuffix, sigInput, parsed.relayIdentity32)) {
    throw PrivateRouteError.INVALID_DESCRIPTOR()
  }

  if (
    expectations.expectedIdentity32 &&
    !b4a.equals(expectations.expectedIdentity32, parsed.relayIdentity32)
  ) {
    throw PrivateRouteError.INVALID_DESCRIPTOR()
  }
  if (expectations.expectedCapabilityMask !== undefined) {
    if (
      (parsed.capabilityMask & expectations.expectedCapabilityMask) !==
      expectations.expectedCapabilityMask
    ) {
      throw PrivateRouteError.INVALID_DESCRIPTOR()
    }
  }
  if (expectations.expectedRole !== undefined) {
    if (expectations.expectedRole === 2 && parsed.capabilityMask !== 11) {
      throw PrivateRouteError.INVALID_DESCRIPTOR()
    }
    if (
      (expectations.expectedRole === 0 || expectations.expectedRole === 1) &&
      parsed.capabilityMask !== 9
    ) {
      throw PrivateRouteError.INVALID_DESCRIPTOR()
    }
  }

  let localDeadline = null
  let clockIdentity = null
  let wallNowFn = null
  let monotonicNowFn = null

  if (expectations.wallNow && expectations.monotonicNow) {
    const wallNow = BigInt(expectations.wallNow())
    if (wallNow >= parsed.expiresAt) throw PrivateRouteError.INVALID_DESCRIPTOR()
    const monoNow = BigInt(expectations.monotonicNow())
    localDeadline = monoNow + (parsed.expiresAt - wallNow)
    clockIdentity = expectations.clockIdentity || null
    wallNowFn = expectations.wallNow
    monotonicNowFn = expectations.monotonicNow
  }

  const canonicalWire260 = encodePeerObject({
    messageId: PEER_MESSAGE_ID.PEER_CAPABILITY_ADVERTISEMENT_V2,
    body,
    authSuffix
  })
  const advertisementDigest32 = hashPeer(ADVERTISEMENT_DIGEST_DOMAIN, canonicalWire260)

  const verifiedState = {
    canonicalBytes260: canonicalWire260,
    advertisementDigest32,
    parsed,
    wireExpiresAt: parsed.expiresAt,
    localDeadline,
    clockIdentity,
    wallNow: wallNowFn,
    monotonicNow: monotonicNowFn
  }

  const handle = Object.freeze({ kind: 'verifiedPeerAdvertisement' })
  verifiedAdvertisements.set(handle, verifiedState)
  return handle
}

function readVerifiedPeerAdvertisement(handle) {
  const state = verifiedAdvertisements.get(handle)
  if (!state) throw PrivateRouteError.INVALID_DESCRIPTOR()
  return Object.freeze({
    canonicalBytes260: bufferCopy(state.canonicalBytes260),
    advertisementDigest32: bufferCopy(state.advertisementDigest32),
    relayIdentity32: bufferCopy(state.parsed.relayIdentity32),
    currentDhtNodeId32: bufferCopy(state.parsed.currentDhtNodeId32),
    reachableEndpoint19: bufferCopy(state.parsed.reachableEndpoint19),
    reachableEndpoint: Object.freeze({ ...state.parsed.reachableEndpoint }),
    routeEncryptionPublicKey32: bufferCopy(state.parsed.routeEncryptionPublicKey32),
    capabilityMask: state.parsed.capabilityMask,
    maxCells: state.parsed.maxCells,
    maxBytes: state.parsed.maxBytes,
    maxCommands: state.parsed.maxCommands,
    idleTimeoutMs: state.parsed.idleTimeoutMs,
    epoch: state.parsed.epoch,
    expiresAt: state.parsed.expiresAt,
    wireExpiresAt: state.wireExpiresAt,
    localDeadline: state.localDeadline,
    clockIdentity: state.clockIdentity,
    wallNow: state.wallNow,
    monotonicNow: state.monotonicNow
  })
}

function createPeerCandidateLocator(relayOwner, verifiedAdvertisement, deadlineBounds) {
  const ownerState = relayOwners.get(relayOwner)
  if (!ownerState || ownerState.destroyed) throw PrivateRouteError.INVALID_ROUTE()

  const adState = verifiedAdvertisements.get(verifiedAdvertisement)
  if (!adState) throw PrivateRouteError.INVALID_DESCRIPTOR()

  let bounds = null
  if (deadlineBounds !== undefined) {
    try {
      const keys = Reflect.ownKeys(deadlineBounds)
      if (
        keys.length !== 3 ||
        !keys.every(
          (key) => key === 'clockIdentity' || key === 'wireExpiresAt' || key === 'localDeadline'
        )
      ) {
        throw PrivateRouteError.INVALID_ROUTE()
      }
      bounds = Object.freeze({
        clockIdentity: ownDataProperty(deadlineBounds, 'clockIdentity'),
        wireExpiresAt: ownDataProperty(deadlineBounds, 'wireExpiresAt'),
        localDeadline: ownDataProperty(deadlineBounds, 'localDeadline')
      })
      if (
        bounds.clockIdentity !== ownerState.clockIdentity ||
        typeof bounds.wireExpiresAt !== 'bigint' ||
        bounds.wireExpiresAt < 0n ||
        bounds.wireExpiresAt > MAX_U64 ||
        typeof bounds.localDeadline !== 'bigint' ||
        bounds.localDeadline < 0n ||
        bounds.localDeadline > MAX_U64 ||
        (adState.localDeadline !== null && adState.clockIdentity !== ownerState.clockIdentity)
      ) {
        throw PrivateRouteError.INVALID_ROUTE()
      }
    } catch {
      throw PrivateRouteError.INVALID_ROUTE()
    }
  }

  let wallNow
  let monotonicNow
  try {
    wallNow = BigInt(ownerState.wallNow())
    monotonicNow = BigInt(ownerState.monotonicNow())
  } catch {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  if (
    ownerState.destroyed ||
    wallNow < 0n ||
    wallNow > MAX_U64 ||
    monotonicNow < 0n ||
    monotonicNow > MAX_U64
  ) {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  if (wallNow >= adState.parsed.expiresAt) throw PrivateRouteError.INVALID_DESCRIPTOR()
  const wireExpiresAt =
    bounds && bounds.wireExpiresAt < adState.parsed.expiresAt
      ? bounds.wireExpiresAt
      : adState.parsed.expiresAt
  if (wallNow >= wireExpiresAt) throw PrivateRouteError.INVALID_ROUTE()
  let projectedLocalDeadline = monotonicNow + (wireExpiresAt - wallNow)
  if (bounds) {
    if (bounds.localDeadline < projectedLocalDeadline) projectedLocalDeadline = bounds.localDeadline
    if (adState.localDeadline !== null && adState.localDeadline < projectedLocalDeadline) {
      projectedLocalDeadline = adState.localDeadline
    }
  }
  if (projectedLocalDeadline <= monotonicNow || projectedLocalDeadline > MAX_U64) {
    throw PrivateRouteError.INVALID_ROUTE()
  }

  const locatorState = {
    consumed: false,
    relayOwner,
    endpoint: ownerState.endpoint,
    relayIdentity32: bufferCopy(adState.parsed.relayIdentity32),
    reachableEndpoint19: bufferCopy(adState.parsed.reachableEndpoint19),
    reachableEndpoint: Object.freeze({ ...adState.parsed.reachableEndpoint }),
    canonicalAdvertisement260: bufferCopy(adState.canonicalBytes260),
    advertisementDigest32: bufferCopy(adState.advertisementDigest32),
    epoch: adState.parsed.epoch,
    clockIdentity: ownerState.clockIdentity,
    wallNow: ownerState.wallNow,
    monotonicNow: ownerState.monotonicNow,
    setTimer: ownerState.setTimer,
    clearTimer: ownerState.clearTimer,
    wireExpiresAt,
    localDeadline: projectedLocalDeadline
  }

  const locatorHandle = Object.freeze({ kind: 'peerCandidateLocator' })
  candidateLocators.set(locatorHandle, locatorState)
  return locatorHandle
}

function takePeerCandidateLocator(locator, endpoint) {
  const state = candidateLocators.get(locator)
  if (!state || state.consumed) throw PrivateRouteError.INVALID_ROUTE()
  if (endpoint && state.endpoint !== endpoint) throw PrivateRouteError.INVALID_ROUTE()

  const monotonicNow = BigInt(state.monotonicNow())
  if (monotonicNow >= state.localDeadline) throw PrivateRouteError.INVALID_ROUTE()

  state.consumed = true

  return Object.freeze({
    endpoint: state.endpoint,
    observedEndpoint: state.reachableEndpoint,
    endpoint19: bufferCopy(state.reachableEndpoint19),
    identity32: bufferCopy(state.relayIdentity32),
    epoch: state.epoch,
    advertisementDigest: bufferCopy(state.advertisementDigest32),
    completeAdvertisement: bufferCopy(state.canonicalAdvertisement260),
    clockIdentity: state.clockIdentity,
    wallNow: state.wallNow,
    monotonicNow: state.monotonicNow,
    setTimer: state.setTimer,
    clearTimer: state.clearTimer,
    wireExpiresAt: state.wireExpiresAt,
    localDeadline: state.localDeadline
  })
}

module.exports = {
  createPeerRelayOwner,
  readPeerRelayOwner,
  destroyPeerRelayOwner,
  verifyPeerAdvertisement,
  readVerifiedPeerAdvertisement,
  createPeerCandidateLocator,
  takePeerCandidateLocator,
  hashPeer,
  buildAdvertisementBody,
  buildAdvertisementSignatureInput,
  parseAdvertisementBody,
  encodeReachableEndpoint,
  decodeReachableEndpoint,
  requireCanonicalEndpoint19
}
