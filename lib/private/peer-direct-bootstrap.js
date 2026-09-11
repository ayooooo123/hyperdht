'use strict'

const b4a = require('b4a')
const crypto = require('hypercore-crypto')
const sodium = require('sodium-universal')

const { PrivateRouteError } = require('./errors')
const {
  hashPeer,
  readPeerRelayOwner,
  readVerifiedPeerAdvertisement,
  takePeerCandidateLocator,
  verifyPeerAdvertisement,
  encodeReachableEndpoint,
  requireCanonicalEndpoint19
} = require('./peer-capability')
const { takePeerDirectRequesterTransport } = require('./udx-cell-endpoint')
const { chargePeerLedger } = require('./peer-ledger')
const { PEER_MESSAGE_ID, PEER_PROTOCOL_VERSION, encodePeerObject } = require('./peer-protocol')
const { decodePeerTransport } = require('./peer-transport-wire')

const BOOTSTRAP_RPC_MAGIC = 0xd301
const MAX_U64 = 0xffff_ffff_ffff_ffffn
const DIRECT_CELL_BYTES = 1200n

const COOKIE_LABEL = b4a.from('hyperdht-private-routes/m3/caps-return-cookie/v2')
const CAPS_RESPONSE_LABEL = b4a.from('hyperdht-private-routes/m3/caps-response/v2')
const ROUTE_KEY_PROOF_LABEL = b4a.from(
  'hyperdht-private-routes/m3/active-challenge/route-key-proof/v2'
)
const ACTIVE_RESPONSE_LABEL = b4a.from('hyperdht-private-routes/m3/active-challenge-response/v2')
const ACTIVE_RESPONSE_DIGEST_DOMAIN =
  'hyperdht-private-routes/m3/active-challenge-response-digest/v2'

const responderHandles = new WeakMap()
const responderBindings = new WeakMap()
const activeCandidates = new WeakMap()

function bufferLength(val) {
  return b4a.isBuffer(val) ? val.byteLength : -1
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
    buf[offset] * 0x1000000 + ((buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3])
  )
}

function readU64BE(buf, offset) {
  const hi = readU32BE(buf, offset)
  const lo = readU32BE(buf, offset + 4)
  return (BigInt(hi) << 32n) | BigInt(lo >>> 0)
}

function writeU16BE(buf, val, offset) {
  buf[offset] = (val >>> 8) & 0xff
  buf[offset + 1] = val & 0xff
}

function writeU32BE(buf, val, offset) {
  buf[offset] = (val >>> 24) & 0xff
  buf[offset + 1] = (val >>> 16) & 0xff
  buf[offset + 2] = (val >>> 8) & 0xff
  buf[offset + 3] = val & 0xff
}

function writeU64BE(buf, val, offset) {
  const v = BigInt(val)
  writeU32BE(buf, Number((v >> 32n) & 0xffffffffn), offset)
  writeU32BE(buf, Number(v & 0xffffffffn), offset + 4)
}

function checkedU64Add(a, b) {
  const sum = BigInt(a) + BigInt(b)
  if (sum < 0n || sum > MAX_U64) throw PrivateRouteError.INVALID_ROUTE()
  return sum
}

function checkedU64Sub(a, b) {
  const left = BigInt(a)
  const right = BigInt(b)
  if (left < right) throw PrivateRouteError.INVALID_ROUTE()
  return left - right
}

function minBigInt(a, b) {
  return a < b ? a : b
}

function ed25519Sign(message, secretKey) {
  const sig = b4a.alloc(64)
  sodium.crypto_sign_detached(sig, message, secretKey)
  return sig
}

function ed25519Verify(sig, message, publicKey) {
  return sodium.crypto_sign_verify_detached(sig, message, publicKey)
}

function x25519KeyPair() {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(32)
  sodium.crypto_box_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

function x25519SharedSecret(secretKey, remotePublicKey) {
  const out = b4a.alloc(32)
  sodium.crypto_scalarmult(out, secretKey, remotePublicKey)
  let zero = 0
  for (let i = 0; i < 32; i++) zero |= out[i]
  if (zero === 0) {
    out.fill(0)
    throw PrivateRouteError.INVALID_KEY()
  }
  return out
}

function computeCookie(
  secret32,
  observedEndpoint19,
  requestedMask,
  randomTarget32,
  queryNonce32,
  maximumResults,
  cookieExpiresAt
) {
  const labelLen = b4a.allocUnsafe(2)
  labelLen.writeUInt16BE(COOKIE_LABEL.byteLength, 0)
  const ver = b4a.from([0, 0, 0, 2])
  const maskBuf = b4a.allocUnsafe(4)
  writeU32BE(maskBuf, requestedMask, 0)
  const maxBuf = b4a.from([maximumResults])
  const expBuf = b4a.allocUnsafe(8)
  writeU64BE(expBuf, cookieExpiresAt, 0)
  const input = b4a.concat([
    labelLen,
    COOKIE_LABEL,
    ver,
    observedEndpoint19,
    maskBuf,
    randomTarget32,
    queryNonce32,
    maxBuf,
    expBuf
  ])
  const mac = b4a.alloc(32)
  sodium.crypto_generichash(mac, input, secret32)
  return mac
}

function computeRouteKeyProof(x25519Secret, body208) {
  const labelLen = b4a.allocUnsafe(2)
  labelLen.writeUInt16BE(ROUTE_KEY_PROOF_LABEL.byteLength, 0)
  const input = b4a.concat([labelLen, ROUTE_KEY_PROOF_LABEL, body208])
  const mac = b4a.alloc(32)
  sodium.crypto_generichash(mac, input, x25519Secret)
  return mac
}

function computeLookupDigest(observedEndpoint19, queryNonce32, cookieExpiresAt, returnCookie32) {
  const expBuf = b4a.allocUnsafe(8)
  writeU64BE(expBuf, cookieExpiresAt, 0)
  return crypto.hash(b4a.concat([observedEndpoint19, queryNonce32, expBuf, returnCookie32]))
}

function wrapDirectRpcPacket(wireObj) {
  const wireBytes = bufferLength(wireObj)
  if (wireBytes < 8 || wireBytes > 1196) throw PrivateRouteError.INVALID_ROUTE()
  const packet = b4a.alloc(1200, 0)
  writeU16BE(packet, BOOTSTRAP_RPC_MAGIC, 0)
  writeU16BE(packet, wireBytes, 2)
  packet.set(wireObj, 4)
  return packet
}

function unwrapDirectRpcPacket(packet1200) {
  if (bufferLength(packet1200) !== 1200) throw PrivateRouteError.INVALID_ROUTE()
  const magic = readU16BE(packet1200, 0)
  if (magic !== BOOTSTRAP_RPC_MAGIC) throw PrivateRouteError.INVALID_ROUTE()
  const wireLen = readU16BE(packet1200, 2)
  if (wireLen < 8 || wireLen > 1196) throw PrivateRouteError.INVALID_ROUTE()
  for (let i = 4 + wireLen; i < 1200; i++) {
    if (packet1200[i] !== 0) throw PrivateRouteError.INVALID_ROUTE()
  }
  const wire = packet1200.subarray(4, 4 + wireLen)
  return decodePeerTransport(wire)
}

function buildCapsQueryBody(
  requestedMask,
  randomTarget32,
  queryNonce32,
  maximumResults,
  phase,
  cookieExpiresAt,
  returnCookie32
) {
  const body = b4a.alloc(110, 0)
  writeU32BE(body, requestedMask, 0)
  body.set(randomTarget32, 4)
  body.set(queryNonce32, 36)
  body[68] = maximumResults
  body[69] = phase
  if (cookieExpiresAt) writeU64BE(body, cookieExpiresAt, 70)
  if (returnCookie32) body.set(returnCookie32, 78)
  return body
}

function buildCapsCookieChallengeBody(queryNonce32, cookieExpiresAt, returnCookie32) {
  const body = b4a.alloc(72, 0)
  body.set(queryNonce32, 0)
  writeU64BE(body, cookieExpiresAt, 32)
  body.set(returnCookie32, 40)
  return body
}

function buildCapsResponseBody(
  responderIdentity32,
  queryNonce32,
  responseTime,
  count,
  canonicalAdvertisement260
) {
  const body = b4a.alloc(335, 0)
  body.set(responderIdentity32, 0)
  body.set(queryNonce32, 32)
  writeU64BE(body, responseTime, 64)
  body[72] = count
  writeU16BE(body, 260, 73)
  body.set(canonicalAdvertisement260, 75)
  return body
}

function buildActiveChallengeBody(
  advertisementDigest32,
  responderIdentity32,
  ephemeralX25519Pk32,
  challengeExpiresAt,
  queryNonce32,
  cookieExpiresAt,
  returnCookie32
) {
  const body = b4a.alloc(176, 0)
  body.set(advertisementDigest32, 0)
  body.set(responderIdentity32, 32)
  body.set(ephemeralX25519Pk32, 64)
  writeU64BE(body, challengeExpiresAt, 96)
  body.set(queryNonce32, 104)
  writeU64BE(body, cookieExpiresAt, 136)
  body.set(returnCookie32, 144)
  return body
}

function buildActiveChallengeResponseBody(
  advertisementDigest32,
  responderIdentity32,
  ephemeralX25519Pk32,
  responderNonce32,
  challengeExpiresAt,
  queryNonce32,
  cookieExpiresAt,
  returnCookie32,
  routeKeyProof32
) {
  const body = b4a.alloc(240, 0)
  body.set(advertisementDigest32, 0)
  body.set(responderIdentity32, 32)
  body.set(ephemeralX25519Pk32, 64)
  body.set(responderNonce32, 96)
  writeU64BE(body, challengeExpiresAt, 128)
  body.set(queryNonce32, 136)
  writeU64BE(body, cookieExpiresAt, 168)
  body.set(returnCookie32, 176)
  body.set(routeKeyProof32, 208)
  return body
}

function labelPrefix(label, messageId, bodyLen) {
  const labelLen = b4a.allocUnsafe(2)
  labelLen.writeUInt16BE(label.byteLength, 0)
  const ver = b4a.from([0, 0, 0, 2])
  const id = b4a.allocUnsafe(2)
  writeU16BE(id, messageId, 0)
  const len = b4a.allocUnsafe(2)
  writeU16BE(len, bodyLen, 0)
  return b4a.concat([labelLen, label, ver, id, len])
}

function safeSendReply(sendReply, packet, generation, onSuccess) {
  try {
    const result = sendReply(packet)
    if (result && typeof result.then === 'function') {
      void Promise.resolve(result)
        .then(
          (sent) => {
            if (sent !== false && onSuccess) onSuccess(generation)
          },
          () => {}
        )
        .catch(() => {})
    } else if (result !== false && onSuccess) {
      onSuccess(generation)
    }
  } catch {}
}

function activeSendCompletion(owner, rowIndex, timerOwnerId) {
  return (generation) => {
    const state = owner.state
    if (!state || state.destroyed || state.generation !== generation) return
    const meta = getRowMeta(state.rowsMeta, rowIndex)
    if (meta[209] !== 2 || readU64BE(meta, 213) !== timerOwnerId) return
    const now = BigInt(state.monotonicNow())
    if (now >= readU64BE(meta, 201) || now >= rowCookieDeadline(meta)) return
    if (meta[212] === 0) meta[212] = 1
  }
}

function createPeerBootstrapResponder(relayOwner) {
  // 256 rows * (2 * 1200 + 256) + 64 secrets = 680000
  const pool = b4a.alloc(680000, 0)
  const rowsMeta = pool.subarray(0, 65536)
  const responseCache = pool.subarray(65536, 65536 + 614400)
  const secrets = pool.subarray(680000 - 64, 680000)
  sodium.randombytes_buf(secrets.subarray(0, 32))
  sodium.randombytes_buf(secrets.subarray(32, 64))
  const publicationOwner = { state: null }

  const responderState = {
    destroyed: false,
    relayOwner,
    pool,
    rowsMeta,
    responseCache,
    secrets,
    publicationOwner,
    monotonicNow: null,
    currentSecretIndex: 0,
    lastRotationMonotonic: 0n,
    rowsCount: 256,
    nextTimerOwnerId: 1n,
    boundEndpoint: null,
    generation: 0n
  }
  publicationOwner.state = responderState

  const handle = Object.freeze({ kind: 'peerBootstrapResponder' })
  responderHandles.set(handle, responderState)
  return handle
}

function getRowMeta(rowsMeta, index) {
  const offset = index * 256
  return rowsMeta.subarray(offset, offset + 256)
}

function getRowResponseSlot(responseCache, index, slotNumber) {
  const offset = index * 2400 + slotNumber * 1200
  return responseCache.subarray(offset, offset + 1200)
}

function rowState(meta) {
  return meta[209]
}

function rowCookieDeadline(meta) {
  return readU64BE(meta, 193)
}

function countEndpointRows(rowsMeta, observedEndpoint19, monotonicNow) {
  let count = 0
  for (let i = 0; i < 256; i++) {
    const meta = getRowMeta(rowsMeta, i)
    const state = rowState(meta)
    if (state === 1 || state === 2) {
      if (rowCookieDeadline(meta) > monotonicNow) {
        if (b4a.equals(meta.subarray(0, 19), observedEndpoint19)) count++
      }
    }
  }
  return count
}

function findFreeRow(rowsMeta, monotonicNow) {
  for (let i = 0; i < 256; i++) {
    const meta = getRowMeta(rowsMeta, i)
    const state = rowState(meta)
    if (state === 0) return i
    if (rowCookieDeadline(meta) <= monotonicNow) {
      meta.fill(0)
      return i
    }
  }
  return -1
}

function readRowTuple(meta) {
  return {
    observedEndpoint19: meta.subarray(0, 19),
    phase1Body: meta.subarray(19, 129),
    queryNonce32: meta.subarray(55, 87),
    cookieExpiresAt: readU64BE(meta, 89),
    returnCookie32: meta.subarray(97, 129),
    activeChallengeDigest: meta.subarray(129, 161),
    lookupDigest: meta.subarray(161, 193)
  }
}

function takePeerBootstrapResponderBinding(responder, endpoint) {
  const state = responderHandles.get(responder)
  if (!state || state.destroyed) throw PrivateRouteError.INVALID_ROUTE()
  if (state.boundEndpoint) throw PrivateRouteError.INVALID_ROUTE()

  // Validate relay owner against endpoint before binding.
  const relayFacts = readPeerRelayOwner(state.relayOwner, endpoint)
  state.monotonicNow = relayFacts.monotonicNow
  state.boundEndpoint = endpoint
  state.generation = checkedU64Add(state.generation, 1n)
  const bindingGeneration = state.generation

  const bindingObj = Object.freeze({
    receive(packet1200, observedEndpoint19, sendReply) {
      if (state.destroyed || state.generation !== bindingGeneration) return false
      if (bufferLength(packet1200) !== 1200) return false
      if (typeof sendReply !== 'function') return false

      let observedEp19
      try {
        observedEp19 = requireCanonicalEndpoint19(observedEndpoint19)
      } catch {
        return false
      }

      let peerObj
      try {
        peerObj = unwrapDirectRpcPacket(packet1200)
      } catch {
        return false
      }

      const relayFacts = readPeerRelayOwner(state.relayOwner, endpoint)
      const wallNow = BigInt(relayFacts.wallNow())
      const monotonicNow = BigInt(relayFacts.monotonicNow())
      const localMask = relayFacts.parsedAdvertisement.capabilityMask

      if (monotonicNow - state.lastRotationMonotonic >= 300000n) {
        state.currentSecretIndex = (state.currentSecretIndex + 1) % 2
        const currentSec = state.secrets.subarray(
          state.currentSecretIndex * 32,
          (state.currentSecretIndex + 1) * 32
        )
        sodium.randombytes_buf(currentSec)
        state.lastRotationMonotonic = monotonicNow
      }

      const curSecret = state.secrets.subarray(
        state.currentSecretIndex * 32,
        (state.currentSecretIndex + 1) * 32
      )
      const prevSecret = state.secrets.subarray(
        ((state.currentSecretIndex + 1) % 2) * 32,
        (((state.currentSecretIndex + 1) % 2) + 1) * 32
      )

      if (peerObj.messageId === PEER_MESSAGE_ID.PEER_CAPS_QUERY_V2) {
        const body = peerObj.body
        if (bufferLength(body) !== 110) return false

        const requestedMask = readU32BE(body, 0)
        const randomTarget32 = body.subarray(4, 36)
        const queryNonce32 = body.subarray(36, 68)
        const maxResults = body[68]
        const phase = body[69]
        const cookieExpiresAt = readU64BE(body, 70)
        const returnCookie32 = body.subarray(78, 110)

        if (maxResults !== 1) return false
        if (requestedMask !== 9 && requestedMask !== 11) return false
        // Local canonical advertisement must satisfy requested mask.
        if ((localMask & requestedMask) !== requestedMask) return false

        if (phase === 0) {
          if (cookieExpiresAt !== 0n) return false
          for (let i = 0; i < 32; i++) {
            if (returnCookie32[i] !== 0) return false
          }

          const cookieExp = checkedU64Add(wallNow, 5000n)
          const mac = computeCookie(
            curSecret,
            observedEp19,
            requestedMask,
            randomTarget32,
            queryNonce32,
            maxResults,
            cookieExp
          )
          const challengeBody = buildCapsCookieChallengeBody(queryNonce32, cookieExp, mac)
          const challengeWire = encodePeerObject({
            messageId: PEER_MESSAGE_ID.PEER_CAPS_COOKIE_CHALLENGE_V2,
            body: challengeBody
          })
          const challengePacket = wrapDirectRpcPacket(challengeWire)
          safeSendReply(sendReply, challengePacket, bindingGeneration, null)
          return true
        }

        if (phase === 1) {
          if (wallNow >= cookieExpiresAt) return false

          const macCur = computeCookie(
            curSecret,
            observedEp19,
            requestedMask,
            randomTarget32,
            queryNonce32,
            maxResults,
            cookieExpiresAt
          )
          const macPrev = computeCookie(
            prevSecret,
            observedEp19,
            requestedMask,
            randomTarget32,
            queryNonce32,
            maxResults,
            cookieExpiresAt
          )
          if (!b4a.equals(returnCookie32, macCur) && !b4a.equals(returnCookie32, macPrev)) {
            return false
          }

          const lookupDigest = computeLookupDigest(
            observedEp19,
            queryNonce32,
            cookieExpiresAt,
            returnCookie32
          )

          // Scan fixed pool. Same observedEndpoint19+queryNonce is reserved:
          // exact full key+full body => replay; any mismatch => conflict (no fresh row).
          for (let i = 0; i < 256; i++) {
            const meta = getRowMeta(state.rowsMeta, i)
            const rState = rowState(meta)
            if (rState !== 1 && rState !== 2) continue
            if (rowCookieDeadline(meta) <= monotonicNow) continue

            const tuple = readRowTuple(meta)
            const sameEndpointNonce =
              b4a.equals(tuple.observedEndpoint19, observedEp19) &&
              b4a.equals(tuple.queryNonce32, queryNonce32)
            if (!sameEndpointNonce) continue

            const digestMatch = b4a.equals(tuple.lookupDigest, lookupDigest)
            const keyMatch =
              tuple.cookieExpiresAt === cookieExpiresAt &&
              b4a.equals(tuple.returnCookie32, returnCookie32)
            const bodyMatch = b4a.equals(tuple.phase1Body, body.subarray(0, 110))

            // Exact full key + full body: original counter/cache replay only.
            if ((digestMatch || keyMatch) && bodyMatch) {
              const capsAttempts = meta[210]
              if (capsAttempts >= 8) return false
              meta[210] = capsAttempts + 1
              const cachedCapsPacket = getRowResponseSlot(state.responseCache, i, 0)
              safeSendReply(sendReply, cachedCapsPacket, bindingGeneration, null)
              return true
            }

            // Same endpoint+nonce reserved: changed cookie/body/key is conflict.
            return false
          }

          if (countEndpointRows(state.rowsMeta, observedEp19, monotonicNow) >= 8) return false
          const freeRowIdx = findFreeRow(state.rowsMeta, monotonicNow)
          if (freeRowIdx < 0) return false

          const rowMeta = getRowMeta(state.rowsMeta, freeRowIdx)
          rowMeta.fill(0)
          rowMeta.set(observedEp19, 0)
          rowMeta.set(body.subarray(0, 110), 19)
          rowMeta.set(lookupDigest, 161)

          let cookieLocalDeadline
          try {
            cookieLocalDeadline = checkedU64Add(
              monotonicNow,
              checkedU64Sub(cookieExpiresAt, wallNow)
            )
          } catch {
            return false
          }
          writeU64BE(rowMeta, cookieLocalDeadline, 193)

          const timerOwnerId = state.nextTimerOwnerId++
          writeU64BE(rowMeta, timerOwnerId, 213)
          rowMeta[209] = 1 // LIVE
          rowMeta[210] = 1 // capsAttempts
          rowMeta[211] = 0
          rowMeta[212] = 0

          const respBody = buildCapsResponseBody(
            relayFacts.relayIdentity32,
            queryNonce32,
            wallNow,
            1,
            relayFacts.canonicalAdvertisement260
          )
          let sig
          try {
            sig = relayFacts.signPeerObject(PEER_MESSAGE_ID.PEER_CAPS_RESPONSE_V2, respBody)
          } catch {
            return false
          }
          const capsWire = encodePeerObject({
            messageId: PEER_MESSAGE_ID.PEER_CAPS_RESPONSE_V2,
            body: respBody,
            authSuffix: sig
          })
          const capsPacket = wrapDirectRpcPacket(capsWire)
          const slot0 = getRowResponseSlot(state.responseCache, freeRowIdx, 0)
          slot0.set(capsPacket, 0)
          safeSendReply(sendReply, capsPacket, bindingGeneration, null)
          return true
        }

        return false
      }

      if (peerObj.messageId === PEER_MESSAGE_ID.PEER_ACTIVE_CHALLENGE_V2) {
        const body = peerObj.body
        if (bufferLength(body) !== 176) return false

        const adDigest = body.subarray(0, 32)
        const respIdent = body.subarray(32, 64)
        const reqEphemPk = body.subarray(64, 96)
        const challengeExp = readU64BE(body, 96)
        const queryNonce = body.subarray(104, 136)
        const cookieExp = readU64BE(body, 136)
        const returnCookie = body.subarray(144, 176)

        if (!b4a.equals(adDigest, relayFacts.advertisementDigest32)) return false
        if (!b4a.equals(respIdent, relayFacts.relayIdentity32)) return false

        const localAdExp = relayFacts.parsedAdvertisement.expiresAt
        const maxAllowedExp = cookieExp < localAdExp ? cookieExp : localAdExp
        if (wallNow >= challengeExp || challengeExp > maxAllowedExp) return false

        for (let i = 0; i < 256; i++) {
          const meta = getRowMeta(state.rowsMeta, i)
          const rState = rowState(meta)
          if (rState !== 1 && rState !== 2) continue
          if (!b4a.equals(meta.subarray(0, 19), observedEp19)) continue
          if (!b4a.equals(meta.subarray(55, 87), queryNonce)) continue

          const cookieDeadline = rowCookieDeadline(meta)
          if (monotonicNow >= cookieDeadline) return false

          // Confirm cookie binding matches stored phase1 body.
          if (readU64BE(meta, 89) !== cookieExp) return false
          if (!b4a.equals(meta.subarray(97, 129), returnCookie)) return false

          if (rState === 2) {
            const challengeDeadline = readU64BE(meta, 201)
            if (monotonicNow >= challengeDeadline) return false
            // candidatePublished may still be false after a failed first send; remaining
            // original cached attempts must still be spendable for byte-identical challenge.
            const activeAttempts = meta[211]
            if (activeAttempts >= 8) return false
            const chalDigest = crypto.hash(body)
            if (!b4a.equals(meta.subarray(129, 161), chalDigest)) return false
            meta[211] = activeAttempts + 1
            const cachedActivePacket = getRowResponseSlot(state.responseCache, i, 1)
            safeSendReply(
              sendReply,
              cachedActivePacket,
              bindingGeneration,
              activeSendCompletion(state.publicationOwner, i, readU64BE(meta, 213))
            )
            return true
          }

          // LIVE -> construct then commit SPENT before send.
          let dhSecret = null
          let proof = null
          let activeRespPrefix = null
          try {
            dhSecret = relayFacts.agreeRoute(reqEphemPk)
            const responderNonce32 = b4a.alloc(32)
            sodium.randombytes_buf(responderNonce32)

            activeRespPrefix = buildActiveChallengeResponseBody(
              adDigest,
              respIdent,
              reqEphemPk,
              responderNonce32,
              challengeExp,
              queryNonce,
              cookieExp,
              returnCookie,
              b4a.alloc(32)
            )
            proof = computeRouteKeyProof(dhSecret, activeRespPrefix.subarray(0, 208))
            activeRespPrefix.set(proof, 208)

            let sig
            try {
              sig = relayFacts.signPeerObject(
                PEER_MESSAGE_ID.PEER_ACTIVE_CHALLENGE_RESPONSE_V2,
                activeRespPrefix
              )
            } catch {
              return false
            }
            const activeWire = encodePeerObject({
              messageId: PEER_MESSAGE_ID.PEER_ACTIVE_CHALLENGE_RESPONSE_V2,
              body: activeRespPrefix,
              authSuffix: sig
            })
            const activePacket = wrapDirectRpcPacket(activeWire)

            let challengeLocalDeadline
            try {
              const projected = checkedU64Add(monotonicNow, checkedU64Sub(challengeExp, wallNow))
              challengeLocalDeadline = minBigInt(cookieDeadline, projected)
            } catch {
              return false
            }

            const chalDigest = crypto.hash(body)
            meta[209] = 2 // SPENT before send
            meta[211] = 1
            meta[212] = 0
            meta.set(chalDigest, 129)
            writeU64BE(meta, challengeLocalDeadline, 201)
            const expectedTimerOwnerId = readU64BE(meta, 213)

            const slot1 = getRowResponseSlot(state.responseCache, i, 1)
            slot1.set(activePacket, 0)

            safeSendReply(
              sendReply,
              activePacket,
              bindingGeneration,
              activeSendCompletion(state.publicationOwner, i, expectedTimerOwnerId)
            )
            return true
          } catch {
            return false
          } finally {
            if (dhSecret) dhSecret.fill(0)
            if (proof) proof.fill(0)
            if (activeRespPrefix) activeRespPrefix.fill(0)
          }
        }
        return false
      }

      return false
    },
    destroy() {
      if (state.destroyed) return
      state.destroyed = true
      state.publicationOwner.state = null
      state.generation = checkedU64Add(state.generation, 1n)
      state.pool.fill(0)
    }
  })

  responderBindings.set(responder, bindingObj)
  return bindingObj
}

function destroyPeerBootstrapResponder(responder) {
  const state = responderHandles.get(responder)
  if (!state) return false
  if (state.destroyed) return true
  state.destroyed = true
  state.publicationOwner.state = null
  state.generation = checkedU64Add(state.generation || 0n, 1n)
  state.pool.fill(0)
  state.secrets.fill(0)
  state.pool = null
  state.rowsMeta = null
  state.responseCache = null
  state.secrets = null
  state.monotonicNow = null
  return true
}

function ownOption(options, key) {
  if (!options || typeof options !== 'object') return undefined
  const desc = Object.getOwnPropertyDescriptor(options, key)
  if (!desc || !Object.prototype.hasOwnProperty.call(desc, 'value')) return undefined
  return desc.value
}

function isObject(val) {
  return val !== null && typeof val === 'object' && !Array.isArray(val)
}

function discoverPeerCandidate(transportInput, options = {}) {
  return new Promise((resolve, reject) => {
    let directTransport
    try {
      directTransport = takePeerDirectRequesterTransport(transportInput)
    } catch (err) {
      return reject(err)
    }
    if (!directTransport || typeof directTransport !== 'object') {
      return reject(PrivateRouteError.INVALID_ROUTE())
    }

    const kind = directTransport.kind
    if (kind !== 'guard' && kind !== 'candidate') {
      return reject(PrivateRouteError.INVALID_ROUTE())
    }

    const {
      send,
      onPacket,
      onDestroy,
      schedule,
      destroy,
      identity32,
      endpoint19,
      epoch,
      clockIdentity,
      wallNow,
      monotonicNow,
      wireExpiresAt,
      localDeadline
    } = directTransport

    if (
      typeof send !== 'function' ||
      typeof onPacket !== 'function' ||
      typeof onDestroy !== 'function' ||
      typeof schedule !== 'function' ||
      typeof destroy !== 'function' ||
      typeof wallNow !== 'function' ||
      typeof monotonicNow !== 'function' ||
      !isObject(clockIdentity) ||
      bufferLength(identity32) !== 32 ||
      bufferLength(endpoint19) !== 19 ||
      typeof epoch !== 'bigint' ||
      typeof wireExpiresAt !== 'bigint' ||
      typeof localDeadline !== 'bigint'
    ) {
      try {
        destroy()
      } catch {}
      return reject(PrivateRouteError.INVALID_ROUTE())
    }

    const ledger = ownOption(options, 'ledger')
    if (!ledger) {
      try {
        destroy()
      } catch {}
      return reject(PrivateRouteError.INVALID_ROUTE())
    }

    let requestedMask = ownOption(options, 'requestedMask')
    if (requestedMask === undefined) requestedMask = kind === 'guard' ? 9 : 11
    if (requestedMask !== 9 && requestedMask !== 11) {
      try {
        destroy()
      } catch {}
      return reject(PrivateRouteError.INVALID_ROUTE())
    }

    let randomTarget32 = ownOption(options, 'randomTarget')
    if (randomTarget32 === undefined) {
      randomTarget32 = b4a.alloc(32)
      sodium.randombytes_buf(randomTarget32)
    } else if (bufferLength(randomTarget32) !== 32) {
      try {
        destroy()
      } catch {}
      return reject(PrivateRouteError.INVALID_ROUTE())
    } else {
      randomTarget32 = bufferCopy(randomTarget32)
    }

    let maximumResults = ownOption(options, 'maximumResults')
    if (maximumResults === undefined) maximumResults = 1
    if (maximumResults !== 1) {
      try {
        destroy()
      } catch {}
      return reject(PrivateRouteError.INVALID_ROUTE())
    }

    const candidateAdvertisementDigest =
      kind === 'candidate' ? directTransport.advertisementDigest : null
    const candidateCompleteAdvertisement =
      kind === 'candidate' ? directTransport.completeAdvertisement : null
    let guardGrantDigest = null
    let guardRunId = null
    let guardOperations = null
    if (kind === 'candidate') {
      if (
        bufferLength(candidateAdvertisementDigest) !== 32 ||
        bufferLength(candidateCompleteAdvertisement) !== 260
      ) {
        try {
          destroy()
        } catch {}
        return reject(PrivateRouteError.INVALID_ROUTE())
      }
      if (
        directTransport.grantDigest !== undefined ||
        directTransport.runId !== undefined ||
        directTransport.operations !== undefined
      ) {
        try {
          destroy()
        } catch {}
        return reject(PrivateRouteError.INVALID_ROUTE())
      }
    } else {
      // guard
      if (
        directTransport.advertisementDigest !== undefined ||
        directTransport.completeAdvertisement !== undefined
      ) {
        try {
          destroy()
        } catch {}
        return reject(PrivateRouteError.INVALID_ROUTE())
      }
      guardGrantDigest = directTransport.grantDigest
      guardRunId = directTransport.runId
      guardOperations = directTransport.operations
      if (
        bufferLength(guardGrantDigest) !== 32 ||
        bufferLength(guardRunId) !== 32 ||
        typeof guardOperations !== 'number' ||
        !Number.isInteger(guardOperations)
      ) {
        try {
          destroy()
        } catch {}
        return reject(PrivateRouteError.INVALID_ROUTE())
      }
      guardGrantDigest = bufferCopy(guardGrantDigest)
      guardRunId = bufferCopy(guardRunId)
    }

    let settled = false
    let phaseToken = 0n
    let stateName = 'PHASE0'
    let currentCancel = null
    let attemptCount = 0
    let frozenPacket = null
    let phaseLocalDeadline = 0n

    const queryNonce32 = b4a.alloc(32)
    sodium.randombytes_buf(queryNonce32)

    let frozenCookieExp = 0n
    let frozenCookieLocalDeadline = 0n
    let frozenReturnCookie = null
    let frozenVerifiedAd = null
    let frozenAdBytes = null
    let frozenAdDigest = null
    let frozenChallengeExp = 0n
    let frozenChallengeLocalDeadline = 0n
    let ephemeralX25519 = null
    let frozenActiveBody = null

    let operationLocalDeadline
    try {
      const opStartMonotonic = BigInt(monotonicNow())
      operationLocalDeadline = minBigInt(
        BigInt(localDeadline),
        checkedU64Add(opStartMonotonic, 5000n)
      )
    } catch (err) {
      try {
        destroy()
      } catch {}
      return reject(err instanceof PrivateRouteError ? err : PrivateRouteError.INVALID_ROUTE())
    }

    function cleanup(err) {
      if (settled) return
      settled = true
      stateName = 'FAILED'
      phaseToken = checkedU64Add(phaseToken, 1n)
      if (currentCancel) {
        try {
          currentCancel()
        } catch {}
        currentCancel = null
      }
      try {
        destroy()
      } catch {}
      if (ephemeralX25519) {
        ephemeralX25519.secretKey.fill(0)
        ephemeralX25519 = null
      }
      reject(err || PrivateRouteError.ROUTE_UNAVAILABLE())
    }

    function succeed(value) {
      if (settled) return
      settled = true
      stateName = 'COMPLETE'
      phaseToken = checkedU64Add(phaseToken, 1n)
      if (currentCancel) {
        try {
          currentCancel()
        } catch {}
        currentCancel = null
      }
      try {
        destroy()
      } catch {}
      if (ephemeralX25519) {
        ephemeralX25519.secretKey.fill(0)
        ephemeralX25519 = null
      }
      resolve(value)
    }

    function checkDeadline(token) {
      if (settled || phaseToken !== token) return false
      const now = BigInt(monotonicNow())
      if (now >= operationLocalDeadline || now >= phaseLocalDeadline) {
        cleanup(PrivateRouteError.ROUTE_UNAVAILABLE())
        return false
      }
      return true
    }

    function cancelPhaseWork() {
      if (currentCancel) {
        try {
          currentCancel()
        } catch {}
        currentCancel = null
      }
    }

    function beginPhase(nextState, packet, deadline) {
      cancelPhaseWork()
      phaseToken = checkedU64Add(phaseToken, 1n)
      const token = phaseToken
      stateName = nextState
      attemptCount = 0
      frozenPacket = packet
      phaseLocalDeadline = deadline
      startTrain(token)
      return token
    }

    function chargeAttempt(token) {
      if (settled || phaseToken !== token) return false
      try {
        chargePeerLedger(ledger, { cells: 1, bytes: DIRECT_CELL_BYTES, commands: 0 })
        return true
      } catch (err) {
        cleanup(err instanceof PrivateRouteError ? err : PrivateRouteError.INVALID_ROUTE())
        return false
      }
    }

    function observeSend(token, expectedState, result) {
      if (result && typeof result.then === 'function') {
        result.then(
          () => {
            // Fulfillment observed only against exact phase generation.
            if (settled || phaseToken !== token || stateName !== expectedState) return
          },
          () => {
            if (settled || phaseToken !== token || stateName !== expectedState) return
            // Failure stays charged; no rebudget or late publication.
          }
        )
      }
    }

    function startTrain(token) {
      function step() {
        if (settled || phaseToken !== token) return
        if (stateName === 'COMPLETE' || stateName === 'FAILED') return
        if (!checkDeadline(token)) return
        if (attemptCount >= 8) {
          cleanup(PrivateRouteError.ROUTE_UNAVAILABLE())
          return
        }
        attemptCount++
        const attempt = attemptCount
        if (!chargeAttempt(token)) return
        const expectedState = stateName
        let result
        try {
          result = send(frozenPacket)
        } catch {
          // Sync throw remains charged against this attempt.
          result = null
        }
        observeSend(token, expectedState, result)
        if (settled || phaseToken !== token || attemptCount !== attempt) return
        try {
          const cancel = schedule(250, () => {
            if (phaseToken !== token || attemptCount !== attempt) return
            currentCancel = null
            step()
          })
          if (settled || phaseToken !== token || attemptCount !== attempt) {
            cancel()
          } else {
            currentCancel = cancel
          }
        } catch (err) {
          if (!settled && phaseToken === token && attemptCount === attempt) {
            cleanup(err instanceof PrivateRouteError ? err : PrivateRouteError.ROUTE_UNAVAILABLE())
          }
        }
      }
      step()
    }

    try {
      onDestroy(cleanup)
    } catch (err) {
      cleanup(err instanceof PrivateRouteError ? err : PrivateRouteError.INVALID_ROUTE())
      return
    }
    if (settled) return

    onPacket((incomingPacket) => {
      if (settled) return
      const ingressToken = phaseToken
      if (!checkDeadline(ingressToken)) return
      if (bufferLength(incomingPacket) !== 1200) return

      let peerObj
      try {
        peerObj = unwrapDirectRpcPacket(incomingPacket)
      } catch {
        return
      }
      // Stale/cancelled phase: ignore without transition.
      if (settled || phaseToken !== ingressToken) return
      if (!checkDeadline(ingressToken)) return

      if (
        stateName === 'PHASE0' &&
        peerObj.messageId === PEER_MESSAGE_ID.PEER_CAPS_COOKIE_CHALLENGE_V2
      ) {
        const body = peerObj.body
        if (bufferLength(body) !== 72) return
        if (!b4a.equals(body.subarray(0, 32), queryNonce32)) return

        const sampleWall = BigInt(wallNow())
        const sampleMono = BigInt(monotonicNow())
        const exp = readU64BE(body, 32)
        if (sampleWall >= exp) return

        let cookieLocal
        try {
          cookieLocal = minBigInt(
            operationLocalDeadline,
            checkedU64Add(sampleMono, checkedU64Sub(exp, sampleWall))
          )
        } catch {
          return
        }

        frozenCookieExp = exp
        frozenCookieLocalDeadline = cookieLocal
        frozenReturnCookie = bufferCopy(body.subarray(40, 72))

        const phase1Body = buildCapsQueryBody(
          requestedMask,
          randomTarget32,
          queryNonce32,
          1,
          1,
          frozenCookieExp,
          frozenReturnCookie
        )
        const wire = encodePeerObject({
          messageId: PEER_MESSAGE_ID.PEER_CAPS_QUERY_V2,
          body: phase1Body
        })
        const packet = wrapDirectRpcPacket(wire)
        // Cancel PHASE0 work before transition.
        if (settled || phaseToken !== ingressToken) return
        if (!checkDeadline(ingressToken)) return
        beginPhase('COOKIE_FROZEN', packet, cookieLocal)
        return
      }

      if (
        stateName === 'COOKIE_FROZEN' &&
        peerObj.messageId === PEER_MESSAGE_ID.PEER_CAPS_RESPONSE_V2
      ) {
        const body = peerObj.body
        if (bufferLength(body) !== 335) return
        if (bufferLength(peerObj.authSuffix) !== 64) return

        const respIdent = body.subarray(0, 32)
        const qNonce = body.subarray(32, 64)
        const responseTime = readU64BE(body, 64)
        const count = body[72]
        const adLen = readU16BE(body, 73)
        if (count !== 1 || adLen !== 260) return
        if (!b4a.equals(qNonce, queryNonce32)) return
        if (!b4a.equals(respIdent, identity32)) return

        // responseTime must fall inside the stored cookie window.
        const cookieIssuedFloor = checkedU64Sub(frozenCookieExp, 5000n)
        if (responseTime < cookieIssuedFloor || responseTime > frozenCookieExp) return

        const adWire = body.subarray(75, 335)
        let verifiedAd
        try {
          verifiedAd = verifyPeerAdvertisement(adWire, {
            expectedIdentity32: identity32,
            expectedCapabilityMask: requestedMask,
            clockIdentity,
            wallNow,
            monotonicNow
          })
        } catch {
          return
        }

        const readAd = readVerifiedPeerAdvertisement(verifiedAd)

        if (kind === 'candidate') {
          if (!b4a.equals(readAd.canonicalBytes260, candidateCompleteAdvertisement)) return
          if (!b4a.equals(readAd.advertisementDigest32, candidateAdvertisementDigest)) return
          if (!b4a.equals(readAd.reachableEndpoint19, endpoint19)) return
          if (readAd.epoch !== epoch) return
        } else {
          // Guard: pinned identity/epoch/scope. Mask already required via expectedCapabilityMask.
          if (readAd.epoch !== epoch) return
          if (!b4a.equals(readAd.relayIdentity32, identity32)) return
          if (requestedMask === 11 && readAd.capabilityMask !== 11) return
          if (requestedMask === 9 && (readAd.capabilityMask & 9) !== 9) return
        }

        const sigInput = b4a.concat([
          labelPrefix(CAPS_RESPONSE_LABEL, PEER_MESSAGE_ID.PEER_CAPS_RESPONSE_V2, 335),
          body
        ])
        if (!ed25519Verify(peerObj.authSuffix, sigInput, identity32)) return

        const sampleWall = BigInt(wallNow())
        const sampleMono = BigInt(monotonicNow())
        frozenChallengeExp = minBigInt(wireExpiresAt, minBigInt(frozenCookieExp, readAd.expiresAt))
        if (sampleWall >= frozenChallengeExp) return

        let challengeLocal
        try {
          challengeLocal = minBigInt(
            operationLocalDeadline,
            minBigInt(
              frozenCookieLocalDeadline,
              checkedU64Add(sampleMono, checkedU64Sub(frozenChallengeExp, sampleWall))
            )
          )
        } catch {
          return
        }

        ephemeralX25519 = x25519KeyPair()
        frozenVerifiedAd = verifiedAd
        frozenAdBytes = bufferCopy(readAd.canonicalBytes260)
        frozenAdDigest = bufferCopy(readAd.advertisementDigest32)
        frozenChallengeLocalDeadline = challengeLocal

        const activeBody = buildActiveChallengeBody(
          frozenAdDigest,
          identity32,
          ephemeralX25519.publicKey,
          frozenChallengeExp,
          queryNonce32,
          frozenCookieExp,
          frozenReturnCookie
        )
        frozenActiveBody = bufferCopy(activeBody)
        const wire = encodePeerObject({
          messageId: PEER_MESSAGE_ID.PEER_ACTIVE_CHALLENGE_V2,
          body: activeBody
        })
        const packet = wrapDirectRpcPacket(wire)
        if (settled || phaseToken !== ingressToken) return
        if (!checkDeadline(ingressToken)) return
        beginPhase('CAPS_FROZEN', packet, challengeLocal)
        return
      }

      if (
        stateName === 'CAPS_FROZEN' &&
        peerObj.messageId === PEER_MESSAGE_ID.PEER_ACTIVE_CHALLENGE_RESPONSE_V2
      ) {
        const body = peerObj.body
        if (bufferLength(body) !== 240) return
        if (bufferLength(peerObj.authSuffix) !== 64) return
        if (!frozenActiveBody || !ephemeralX25519) return

        // Compare EVERY frozen ACTIVE binding before signature/proof.
        if (!b4a.equals(body.subarray(0, 32), frozenAdDigest)) return
        if (!b4a.equals(body.subarray(32, 64), identity32)) return
        if (!b4a.equals(body.subarray(64, 96), ephemeralX25519.publicKey)) return
        if (readU64BE(body, 128) !== frozenChallengeExp) return
        if (!b4a.equals(body.subarray(136, 168), queryNonce32)) return
        if (readU64BE(body, 168) !== frozenCookieExp) return
        if (!b4a.equals(body.subarray(176, 208), frozenReturnCookie)) return

        const sigInput = b4a.concat([
          labelPrefix(
            ACTIVE_RESPONSE_LABEL,
            PEER_MESSAGE_ID.PEER_ACTIVE_CHALLENGE_RESPONSE_V2,
            240
          ),
          body
        ])
        if (!ed25519Verify(peerObj.authSuffix, sigInput, identity32)) return

        const readAd = readVerifiedPeerAdvertisement(frozenVerifiedAd)
        let dhSecret
        try {
          dhSecret = x25519SharedSecret(
            ephemeralX25519.secretKey,
            readAd.routeEncryptionPublicKey32
          )
        } catch {
          return
        }
        const expectedProof = computeRouteKeyProof(dhSecret, body.subarray(0, 208))
        dhSecret.fill(0)
        if (!b4a.equals(body.subarray(208, 240), expectedProof)) return

        if (settled || phaseToken !== ingressToken) return
        if (!checkDeadline(ingressToken)) return

        const activeResponse312 = encodePeerObject({
          messageId: PEER_MESSAGE_ID.PEER_ACTIVE_CHALLENGE_RESPONSE_V2,
          body,
          authSuffix: peerObj.authSuffix
        })
        if (bufferLength(activeResponse312) !== 312) return

        // Move ACTIVE_FROZEN then COMPLETE once after valid publication.
        cancelPhaseWork()
        phaseToken = checkedU64Add(phaseToken, 1n)
        stateName = 'ACTIVE_FROZEN'

        const activeCandidateState = {
          destroyed: false,
          consumed: false,
          verifiedAdvertisement: frozenVerifiedAd,
          completeAdvertisement: frozenAdBytes,
          activeResponse312: bufferCopy(activeResponse312),
          activeResponseDigest: hashPeer(ACTIVE_RESPONSE_DIGEST_DOMAIN, activeResponse312),
          identity32: bufferCopy(identity32),
          endpoint19: bufferCopy(endpoint19),
          epoch,
          kind,
          grantDigest: kind === 'guard' ? bufferCopy(guardGrantDigest) : null,
          runId: kind === 'guard' ? bufferCopy(guardRunId) : null,
          operations: kind === 'guard' ? guardOperations : null,
          clockIdentity,
          wallNow,
          monotonicNow,
          wireExpiresAt: frozenChallengeExp,
          localDeadline: minBigInt(operationLocalDeadline, frozenChallengeLocalDeadline)
        }

        const candidateHandle = Object.freeze({ kind: 'peerActiveCandidate' })
        activeCandidates.set(candidateHandle, activeCandidateState)
        succeed(candidateHandle)
      }
    })

    // Initiate PHASE0 train with immutable packet.
    const phase0Body = buildCapsQueryBody(
      requestedMask,
      randomTarget32,
      queryNonce32,
      1,
      0,
      0n,
      null
    )
    const phase0Wire = encodePeerObject({
      messageId: PEER_MESSAGE_ID.PEER_CAPS_QUERY_V2,
      body: phase0Body
    })
    const phase0Packet = wrapDirectRpcPacket(phase0Wire)
    beginPhase('PHASE0', phase0Packet, operationLocalDeadline)
  })
}

const CANDIDATE_EXPECTATION_KEYS = new Set([
  'expectedKind',
  'expectedIdentity32',
  'expectedEndpoint19',
  'clockIdentity',
  'expectedEpoch',
  'expectedGrantDigest',
  'expectedRunId',
  'expectedOperations',
  'expectedAdvertisement260'
])

function snapshotCandidateExpectations(expected) {
  if (!expected || typeof expected !== 'object') throw PrivateRouteError.INVALID_ROUTE()
  const snapshot = Object.create(null)
  try {
    const prototype = Object.getPrototypeOf(expected)
    if (prototype !== Object.prototype && prototype !== null)
      throw PrivateRouteError.INVALID_ROUTE()
    for (const key of Reflect.ownKeys(expected)) {
      if (!CANDIDATE_EXPECTATION_KEYS.has(key)) throw PrivateRouteError.INVALID_ROUTE()
      const descriptor = Object.getOwnPropertyDescriptor(expected, key)
      if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
        throw PrivateRouteError.INVALID_ROUTE()
      }
      snapshot[key] = descriptor.value
    }
  } catch {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  return snapshot
}

function readPeerActiveCandidateFacts(candidate) {
  const state = activeCandidates.get(candidate)
  if (!state || state.destroyed || state.consumed) throw PrivateRouteError.INVALID_ROUTE()
  let wall
  let mono
  try {
    wall = checkedU64Add(state.wallNow(), 0n)
    mono = checkedU64Add(state.monotonicNow(), 0n)
  } catch {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  if (
    state.destroyed ||
    state.consumed ||
    wall >= state.wireExpiresAt ||
    mono >= state.localDeadline
  ) {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  return Object.freeze({
    completeAdvertisement: bufferCopy(state.completeAdvertisement),
    activeResponseDigest: bufferCopy(state.activeResponseDigest),
    identity32: bufferCopy(state.identity32),
    endpoint19: bufferCopy(state.endpoint19),
    epoch: state.epoch,
    kind: state.kind,
    clockIdentity: state.clockIdentity,
    wireExpiresAt: state.wireExpiresAt,
    localDeadline: state.localDeadline
  })
}

function takePeerActiveCandidate(candidate, expected) {
  expected = snapshotCandidateExpectations(expected)
  const state = activeCandidates.get(candidate)
  if (!state || state.destroyed || state.consumed) throw PrivateRouteError.INVALID_ROUTE()
  const expectedKind = ownOption(expected, 'expectedKind')
  if ((expectedKind !== 'guard' && expectedKind !== 'candidate') || expectedKind !== state.kind) {
    throw PrivateRouteError.INVALID_ROUTE()
  }

  if (expected.expectedIdentity32 !== undefined) {
    if (
      bufferLength(expected.expectedIdentity32) !== 32 ||
      !b4a.equals(expected.expectedIdentity32, state.identity32)
    ) {
      throw PrivateRouteError.INVALID_ROUTE()
    }
  }
  if (expected.expectedEndpoint19 !== undefined) {
    if (
      bufferLength(expected.expectedEndpoint19) !== 19 ||
      !b4a.equals(expected.expectedEndpoint19, state.endpoint19)
    ) {
      throw PrivateRouteError.INVALID_ROUTE()
    }
  }
  if (expected.clockIdentity !== undefined && expected.clockIdentity !== state.clockIdentity) {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  if (expected.expectedEpoch !== undefined && expected.expectedEpoch !== state.epoch) {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  if (expected.expectedAdvertisement260 !== undefined) {
    if (
      bufferLength(expected.expectedAdvertisement260) !== 260 ||
      !b4a.equals(expected.expectedAdvertisement260, state.completeAdvertisement)
    ) {
      throw PrivateRouteError.INVALID_ROUTE()
    }
  }

  if (state.kind === 'guard') {
    if (
      expected.expectedGrantDigest !== undefined &&
      (bufferLength(expected.expectedGrantDigest) !== 32 ||
        !b4a.equals(expected.expectedGrantDigest, state.grantDigest))
    ) {
      throw PrivateRouteError.INVALID_ROUTE()
    }
    if (
      expected.expectedRunId !== undefined &&
      (bufferLength(expected.expectedRunId) !== 32 ||
        !b4a.equals(expected.expectedRunId, state.runId))
    ) {
      throw PrivateRouteError.INVALID_ROUTE()
    }
    if (
      expected.expectedOperations !== undefined &&
      expected.expectedOperations !== state.operations
    ) {
      throw PrivateRouteError.INVALID_ROUTE()
    }
  } else if (
    expected.expectedGrantDigest !== undefined ||
    expected.expectedRunId !== undefined ||
    expected.expectedOperations !== undefined
  ) {
    throw PrivateRouteError.INVALID_ROUTE()
  }

  const now = BigInt(state.monotonicNow())
  if (state.destroyed || state.consumed || now >= state.localDeadline) {
    throw PrivateRouteError.INVALID_ROUTE()
  }

  state.consumed = true
  const ad = readVerifiedPeerAdvertisement(state.verifiedAdvertisement)

  const result = {
    completeAdvertisement: bufferCopy(ad.canonicalBytes260),
    activeResponse312: bufferCopy(state.activeResponse312),
    activeResponseDigest: bufferCopy(state.activeResponseDigest),
    identity32: bufferCopy(state.identity32),
    endpoint19: bufferCopy(state.endpoint19),
    epoch: state.epoch,
    kind: state.kind,
    clockIdentity: state.clockIdentity,
    wallNow: state.wallNow,
    monotonicNow: state.monotonicNow,
    wireExpiresAt: state.wireExpiresAt,
    localDeadline: state.localDeadline
  }
  if (state.kind === 'guard') {
    result.grantDigest = bufferCopy(state.grantDigest)
    result.runId = bufferCopy(state.runId)
    result.operations = state.operations
  }
  return Object.freeze(result)
}

function destroyPeerActiveCandidate(candidate) {
  const state = activeCandidates.get(candidate)
  if (!state) return false
  if (state.destroyed) return true
  state.destroyed = true
  if (state.activeResponse312) state.activeResponse312.fill(0)
  if (state.completeAdvertisement) state.completeAdvertisement.fill(0)
  if (state.grantDigest) state.grantDigest.fill(0)
  if (state.runId) state.runId.fill(0)
  return true
}
module.exports = {
  createPeerBootstrapResponder,
  takePeerBootstrapResponderBinding,
  destroyPeerBootstrapResponder,
  discoverPeerCandidate,
  readPeerActiveCandidateFacts,
  takePeerActiveCandidate,
  destroyPeerActiveCandidate,
  takePeerCandidateLocator,
  wrapDirectRpcPacket,
  unwrapDirectRpcPacket,
  computeLookupDigest
}
