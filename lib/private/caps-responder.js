'use strict'

const b4a = require('b4a')
const sodium = require('sodium-universal')

const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')
const {
  createActiveChallengeResponderAuthority,
  decodeCanonicalEndpoint,
  decodeRelayCapabilityAdvertisement
} = require('./relay-capability')
const { M3_MESSAGE_ID, M3_PROTOCOL_VERSION, decodeM3Object, encodeM3Object } = require('./protocol')

const CAPS_RESPONSE_DOMAIN = b4a.from('hyperdht-private-routes/m3/caps-response/v1')
const CORE_FRAGMENT_DOMAIN = b4a.from('hyperdht-private-routes/m3/core-fragment/object/v1')
const DIRECT_FRAGMENT_DATA_BYTES = 1_140
const BOOTSTRAP_SIZE = 1_200
const BOOTSTRAP_RPC_MAGIC = 0xd301
const BOOTSTRAP_ACCEPT_AUTHORITIES = new WeakMap()
const BOOTSTRAP_ACCEPT_AUTHORITY_TAKER = Symbol.for(
  'hyperdht-private-routes/bootstrap-accept-authority-taker'
)
const BOOTSTRAP_ACCEPT_AUTHORITY_CONSUMER = Symbol.for(
  'hyperdht-private-routes/bootstrap-accept-authority-consumer'
)

function invalid() {
  throw PrivateRouteError.ERR_INCOMPATIBLE_RELAY()
}

function authentication() {
  throw PrivateRouteError.ERR_AUTHENTICATION()
}

function clear(value) {
  if (b4a.isBuffer(value)) value.fill(0)
}

function copy(value, size = null) {
  if (!b4a.isBuffer(value) || (size !== null && value.byteLength !== size)) invalid()
  return b4a.from(value)
}

function takeBootstrapAcceptAuthority(responder) {
  const authority =
    responder && typeof responder === 'object' ? responder.bootstrapAcceptAuthority : null
  if (!authority || typeof authority !== 'object' || !BOOTSTRAP_ACCEPT_AUTHORITIES.has(authority)) {
    throw PrivateRouteError.ERR_REPLAY()
  }
  responder.bootstrapAcceptAuthority = null
  return authority
}

function consumeBootstrapAcceptAuthority(authority) {
  const record =
    authority && typeof authority === 'object' ? BOOTSTRAP_ACCEPT_AUTHORITIES.get(authority) : null
  if (!record) throw PrivateRouteError.ERR_REPLAY()
  BOOTSTRAP_ACCEPT_AUTHORITIES.delete(authority)
  return record
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

function signatureInput(body) {
  const output = b4a.allocUnsafe(2 + CAPS_RESPONSE_DOMAIN.byteLength + 8 + body.byteLength)
  writeUint16(output, CAPS_RESPONSE_DOMAIN.byteLength, 0)
  output.set(CAPS_RESPONSE_DOMAIN, 2)
  writeUint32(output, M3_PROTOCOL_VERSION, 2 + CAPS_RESPONSE_DOMAIN.byteLength)
  writeUint16(output, M3_MESSAGE_ID.CAPS_RESPONSE_V1, 6 + CAPS_RESPONSE_DOMAIN.byteLength)
  writeUint16(output, body.byteLength, 8 + CAPS_RESPONSE_DOMAIN.byteLength)
  output.set(body, 10 + CAPS_RESPONSE_DOMAIN.byteLength)
  return output
}

function parseQuery(datagram) {
  const object = decodeM3Object(datagram)
  if (object.messageId !== M3_MESSAGE_ID.CAPS_QUERY_V1 || datagram.byteLength !== 118) invalid()
  const body = object.body
  const query = {
    requestedCapabilityMask: readUint32(body, 0),
    randomTarget: b4a.from(body.subarray(4, 36)),
    queryNonce: b4a.from(body.subarray(36, 68)),
    maximumResults: body[68],
    phase: body[69],
    cookieExpiresAtMs: readUint64(body, 70),
    returnRoutabilityCookie: b4a.from(body.subarray(78, 110))
  }
  if (
    query.requestedCapabilityMask < 1 ||
    query.requestedCapabilityMask > 7 ||
    query.maximumResults < 1 ||
    query.maximumResults > 8 ||
    (query.phase !== 0 && query.phase !== 1)
  )
    invalid()
  return query
}

function queryAuthority(query, sourceEndpoint) {
  return {
    sourceEndpoint,
    requestedCapabilityMask: query.requestedCapabilityMask,
    randomTarget: query.randomTarget,
    queryNonce: query.queryNonce,
    maximumResults: query.maximumResults
  }
}

function challenge(query, cookie) {
  const body = b4a.alloc(72)
  body.set(query.queryNonce, 0)
  writeUint64(body, cookie.cookieExpiresAtMs, 32)
  body.set(cookie.returnRoutabilityCookie, 40)
  return encodeM3Object({ messageId: M3_MESSAGE_ID.CAPS_COOKIE_CHALLENGE_V1, body })
}

function decodeBootstrapRpcPacket(packet) {
  if (
    !b4a.isBuffer(packet) ||
    packet.byteLength !== BOOTSTRAP_SIZE ||
    ((packet[0] << 8) | packet[1]) !== BOOTSTRAP_RPC_MAGIC
  )
    invalid()
  const bytes = (packet[2] << 8) | packet[3]
  if (bytes < 8 || bytes > BOOTSTRAP_SIZE - 4) invalid()
  for (let index = 4 + bytes; index < packet.byteLength; index++) {
    if (packet[index] !== 0) invalid()
  }
  return packet.subarray(4, 4 + bytes)
}

function encodeBootstrapRpcPacket(packet) {
  if (!b4a.isBuffer(packet) || packet.byteLength < 8 || packet.byteLength > BOOTSTRAP_SIZE - 4)
    invalid()
  const output = b4a.alloc(BOOTSTRAP_SIZE)
  writeUint16(output, BOOTSTRAP_RPC_MAGIC, 0)
  writeUint16(output, packet.byteLength, 2)
  output.set(packet, 4)
  return output
}

function wireResponses(responses, framed) {
  return framed ? responses.map(encodeBootstrapRpcPacket) : responses
}

function fragments(complete) {
  if (complete.byteLength <= BOOTSTRAP_SIZE - 4) return [b4a.from(complete)]
  const digest = cryptoSuite.hash([CORE_FRAGMENT_DOMAIN, complete])
  const count = Math.ceil(complete.byteLength / DIRECT_FRAGMENT_DATA_BYTES)
  const result = []
  for (let index = 0; index < count; index++) {
    const offset = index * DIRECT_FRAGMENT_DATA_BYTES
    const data = complete.subarray(
      offset,
      Math.min(offset + DIRECT_FRAGMENT_DATA_BYTES, complete.byteLength)
    )
    const body = b4a.alloc(48 + data.byteLength)
    writeUint16(body, M3_MESSAGE_ID.CAPS_RESPONSE_V1, 0)
    body.set(digest, 2)
    writeUint32(body, complete.byteLength, 34)
    writeUint16(body, index, 38)
    writeUint16(body, count, 40)
    writeUint32(body, offset, 42)
    writeUint16(body, data.byteLength, 46)
    body.set(data, 48)
    result.push(encodeM3Object({ messageId: M3_MESSAGE_ID.CORE_FRAGMENT_V1, body }))
  }
  clear(digest)
  return result
}

class CapsResponder {
  constructor(options) {
    if (!options || typeof options !== 'object') invalid()
    this.now = options.now
    this.advertisement = copy(options.advertisement)
    this.identitySecretKey = copy(options.identitySecretKey, 64)
    this.routeEncryptionSecretKey = copy(options.routeEncryptionSecretKey, 32)
    this.selectAdvertisements = options.selectAdvertisements || (() => [this.advertisement])
    if (typeof this.now !== 'function' || typeof this.selectAdvertisements !== 'function') invalid()
    const decoded = decodeRelayCapabilityAdvertisement(this.advertisement, { now: this.now() })
    this.identity = b4a.from(decoded.relayIdentity)
    this.reachableEndpoint = b4a.from(decoded.reachableEndpoint)
    this.epoch = decoded.epoch
    this.expiresAt = decoded.expiresAtMs
    const routePublicKey = b4a.alloc(32)
    sodium.crypto_scalarmult_base(routePublicKey, this.routeEncryptionSecretKey)
    if (
      !b4a.equals(this.identitySecretKey.subarray(32), this.identity) ||
      !b4a.equals(routePublicKey, decoded.routeEncryptionPublicKey)
    )
      authentication()
    clear(routePublicKey)
    this.active = createActiveChallengeResponderAuthority({
      now: this.now,
      crypto: cryptoSuite,
      setTimeout: options.setTimeout || setTimeout,
      clearTimeout: options.clearTimeout || clearTimeout,
      maxBindings: options.maxBindings || 4_096
    })
    this.bindings = new Map()
    this.bootstrapAcceptAuthority = null
    this.destroyed = false
  }

  receive(datagram, observedSourceEndpoint) {
    if (this.destroyed) throw PrivateRouteError.ERR_DESTROYED()
    let source = null
    let query = null
    const framed =
      b4a.isBuffer(datagram) &&
      datagram.byteLength === BOOTSTRAP_SIZE &&
      ((datagram[0] << 8) | datagram[1]) === BOOTSTRAP_RPC_MAGIC
    try {
      source = decodeCanonicalEndpoint(observedSourceEndpoint)
      if (framed) datagram = decodeBootstrapRpcPacket(datagram)
      const object = decodeM3Object(datagram)
      if (object.messageId === M3_MESSAGE_ID.ACTIVE_CHALLENGE_V1) {
        const cookie = b4a.toString(object.body.subarray(144, 176), 'hex')
        const record = this.bindings.get(cookie)
        if (!record || !b4a.equals(record.source, source)) return []
        this.bindings.delete(cookie)
        const response = this.active.respond(record.binding, datagram, {
          sourceEndpoint: source,
          advertisement: this.advertisement,
          identitySecretKey: this.identitySecretKey,
          routeEncryptionSecretKey: this.routeEncryptionSecretKey
        })
        const authority = Object.freeze({})
        BOOTSTRAP_ACCEPT_AUTHORITIES.set(authority, {
          sourceEndpoint: b4a.from(source),
          localIdentity: b4a.from(this.identity),
          localEndpoint: b4a.from(this.reachableEndpoint),
          epoch: this.epoch,
          expiresAt: this.expiresAt,
          now: this.now
        })
        this.bootstrapAcceptAuthority = authority
        return wireResponses([response], framed)
      }
      query = parseQuery(datagram)
      if (query.phase === 0) {
        return wireResponses(
          [challenge(query, this.active.issueCookie(queryAuthority(query, source)))],
          framed
        )
      }
      const binding = this.active.admitCapsRetry({
        ...queryAuthority(query, source),
        cookieExpiresAtMs: query.cookieExpiresAtMs,
        returnRoutabilityCookie: query.returnRoutabilityCookie,
        advertisement: this.advertisement
      })
      const selected = this.selectAdvertisements({
        requestedCapabilityMask: query.requestedCapabilityMask,
        randomTarget: b4a.from(query.randomTarget),
        queryNonce: b4a.from(query.queryNonce),
        maximumResults: query.maximumResults,
        now: this.now()
      })
      if (!Array.isArray(selected) || selected.length < 1 || selected.length > query.maximumResults)
        invalid()
      let bytes = 73
      for (const value of selected) bytes += 2 + value.byteLength
      const body = b4a.alloc(bytes)
      body.set(this.identity, 0)
      body.set(query.queryNonce, 32)
      writeUint64(body, this.now(), 64)
      body[72] = selected.length
      let offset = 73
      for (const value of selected) {
        writeUint16(body, value.byteLength, offset)
        offset += 2
        body.set(value, offset)
        offset += value.byteLength
      }
      const input = signatureInput(body)
      const signature = cryptoSuite.sign(input, this.identitySecretKey)
      const response = encodeM3Object({
        messageId: M3_MESSAGE_ID.CAPS_RESPONSE_V1,
        body,
        authSuffix: signature
      })
      clear(input)
      clear(signature)
      this.bindings.set(b4a.toString(query.returnRoutabilityCookie, 'hex'), {
        source: b4a.from(source),
        binding
      })
      return wireResponses(fragments(response), framed)
    } catch (err) {
      if (err instanceof PrivateRouteError && err.code === 'ERR_DESTROYED') throw err
      return []
    } finally {
      clear(source)
      if (query) {
        clear(query.randomTarget)
        clear(query.queryNonce)
        clear(query.returnRoutabilityCookie)
      }
    }
  }

  destroy() {
    if (this.destroyed) return false
    this.destroyed = true
    this.active.destroy()
    for (const value of this.bindings.values()) clear(value.source)
    this.bindings.clear()
    clear(this.advertisement)
    clear(this.identity)
    clear(this.identitySecretKey)
    if (this.bootstrapAcceptAuthority) {
      const record = BOOTSTRAP_ACCEPT_AUTHORITIES.get(this.bootstrapAcceptAuthority)
      BOOTSTRAP_ACCEPT_AUTHORITIES.delete(this.bootstrapAcceptAuthority)
      if (record) {
        clear(record.sourceEndpoint)
        clear(record.localIdentity)
        clear(record.localEndpoint)
      }
      this.bootstrapAcceptAuthority = null
    }
    clear(this.reachableEndpoint)
    clear(this.routeEncryptionSecretKey)
    return true
  }
}

module.exports = {
  CapsResponder,
  [BOOTSTRAP_ACCEPT_AUTHORITY_TAKER]: takeBootstrapAcceptAuthority,
  [BOOTSTRAP_ACCEPT_AUTHORITY_CONSUMER]: consumeBootstrapAcceptAuthority
}
