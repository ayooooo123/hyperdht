'use strict'

const b4a = require('b4a')
const sodium = require('sodium-universal')

const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')
const {
  EXIT_ORIGIN_SERVICE_POLICY,
  DHT_EXIT_ORIGIN_SERVICE_POLICY,
  SERVICE_POLICY_ENTRY_SIZE,
  decodeExitOriginServicePolicy,
  digestExitOriginServicePolicy,
  encodeExitOriginServicePolicy
} = require('./exit-policy')
const {
  PAYLOAD_PARAMETERS_SIZE,
  decodePayloadParameters,
  digestPayloadParameters,
  encodePayloadParameters
} = require('./link-parameters')
const {
  BRANCH_CLASS,
  M3_MESSAGE_ID,
  M3_PROTOCOL_VERSION,
  decodeM3Object,
  encodeM3Object
} = require('./protocol')

const FINAL_EXIT_TRANSCRIPT_SIZE = 287
const DHT_EXIT_ACTIVATE_SIZE = 104
const DHT_EXIT_READY_SIZE = 305
const DHT_EXIT_READY_ACK_SIZE = 113
const DHT_EXIT_OPEN_SIZE = 177

const MAX_UINT64 = 0xffff_ffff_ffff_ffffn
const FINAL_DOMAIN = b4a.from('hyperdht-private-routes/final-exit/transcript/v1')
const FINAL_DIGEST_DOMAIN = b4a.from('hyperdht-private-routes/m3/final-exit/transcript-digest/v1')
const DHT_EXIT_READY_DOMAIN = b4a.from('hyperdht-private-routes/m3/dht-exit-ready/v1')
const DHT_EXIT_READY_DIGEST_DOMAIN = b4a.from('hyperdht-private-routes/m3/dht-exit-ready-digest/v1')
const DHT_EXIT_READY_ACK_DIGEST_DOMAIN = b4a.from(
  'hyperdht-private-routes/m3/dht-exit-ready-ack-digest/v1'
)
const DHT_EXIT_READY_BODY_SIZE = 233
const DHT_EXIT_READY_ACK_BODY_SIZE = 105
const DHT_EXIT_OPEN_BODY_SIZE = 169

const FINAL_LABELS = Object.freeze({
  payloadForwardKey: 'hyperdht-private-routes/kdf/v1/final-exit/payload/forward-key',
  payloadReverseKey: 'hyperdht-private-routes/kdf/v1/final-exit/payload/reverse-key',
  payloadForwardNonce: 'hyperdht-private-routes/kdf/v1/final-exit/payload/forward-nonce',
  payloadReverseNonce: 'hyperdht-private-routes/kdf/v1/final-exit/payload/reverse-nonce',
  controlForwardKey: 'hyperdht-private-routes/kdf/v1/final-exit/control/forward-key',
  controlReverseKey: 'hyperdht-private-routes/kdf/v1/final-exit/control/reverse-key',
  controlForwardNonce: 'hyperdht-private-routes/kdf/v1/final-exit/control/forward-nonce',
  controlReverseNonce: 'hyperdht-private-routes/kdf/v1/final-exit/control/reverse-nonce',
  finalizeForwardKey: 'hyperdht-private-routes/kdf/v1/final-exit/finalize/forward-key',
  finalizeReverseKey: 'hyperdht-private-routes/kdf/v1/final-exit/finalize/reverse-key',
  finalizeForwardNonce: 'hyperdht-private-routes/kdf/v1/final-exit/finalize/forward-nonce',
  finalizeReverseNonce: 'hyperdht-private-routes/kdf/v1/final-exit/finalize/reverse-nonce'
})

const bufferByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
const bufferFill = Uint8Array.prototype.fill
const bufferSet = Uint8Array.prototype.set
const bufferSubarray = Uint8Array.prototype.subarray

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function object(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid()
  return value
}

function option(value, name) {
  try {
    return value[name]
  } catch {
    invalid()
  }
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

function clear(value) {
  try {
    if (b4a.isBuffer(value)) bufferFill.call(value, 0)
  } catch {}
}

function set(target, source, offset = 0) {
  try {
    bufferSet.call(target, source, offset)
  } catch {
    invalid()
  }
}

function subarray(value, start, end) {
  try {
    return bufferSubarray.call(value, start, end)
  } catch {
    invalid()
  }
}

function copy(value) {
  let output = null
  try {
    const length = bufferLength(value)
    if (length < 0) invalid()
    output = b4a.allocUnsafeSlow(length)
    set(output, value)
    return output
  } catch (err) {
    clear(output)
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  }
}

function uint64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= MAX_UINT64
}

function branchClass(value) {
  if (value !== BRANCH_CLASS.LOOKUP && value !== BRANCH_CLASS.ANNOUNCE) invalid()
  return value
}

function writeUint16(target, value, offset) {
  target[offset] = value >>> 8
  target[offset + 1] = value
}

function writeUint32(target, value, offset) {
  target[offset] = value >>> 24
  target[offset + 1] = value >>> 16
  target[offset + 2] = value >>> 8
  target[offset + 3] = value
}

function writeUint64(target, value, offset) {
  for (let index = offset + 7; index >= offset; index--) {
    target[index] = Number(value & 0xffn)
    value >>= 8n
  }
}

function readUint16(target, offset) {
  return (target[offset] << 8) | target[offset + 1]
}

function readUint32(target, offset) {
  return (
    target[offset] * 0x1000000 +
    (target[offset + 1] << 16) +
    (target[offset + 2] << 8) +
    target[offset + 3]
  )
}

function readUint64(target, offset) {
  let value = 0n
  for (let index = offset; index < offset + 8; index++) {
    value = (value << 8n) | BigInt(target[index])
  }
  return value
}

function encodeDhtExitActivate(value) {
  let body = null
  try {
    object(value)
    const fields = [
      option(value, 'clientActivationNonce'),
      option(value, 'exitOriginCommandPolicyDigest'),
      option(value, 'payloadParametersDigest')
    ]
    if (fields.some((field) => !fixed(field, 32))) invalid()
    body = b4a.allocUnsafeSlow(96)
    for (let index = 0; index < fields.length; index++) set(body, fields[index], index * 32)
    return encodeM3Object({ messageId: M3_MESSAGE_ID.DHT_EXIT_ACTIVATE_V1, body })
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  } finally {
    clear(body)
  }
}

function decodeDhtExitActivate(encoded) {
  let decoded = null
  let result = null
  let complete = false
  try {
    decoded = decodeM3Object(encoded)
    if (
      decoded.messageId !== M3_MESSAGE_ID.DHT_EXIT_ACTIVATE_V1 ||
      !fixed(decoded.body, 96) ||
      !fixed(decoded.authSuffix, 0)
    ) {
      invalid()
    }
    result = {
      clientActivationNonce: copy(subarray(decoded.body, 0, 32)),
      exitOriginCommandPolicyDigest: copy(subarray(decoded.body, 32, 64)),
      payloadParametersDigest: copy(subarray(decoded.body, 64, 96))
    }
    complete = true
    return result
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  } finally {
    if (decoded) {
      clear(decoded.body)
      clear(decoded.authSuffix)
    }
    if (!complete && result) {
      clear(result.clientActivationNonce)
      clear(result.exitOriginCommandPolicyDigest)
      clear(result.payloadParametersDigest)
    }
  }
}

function encodeDhtExitReadyBody(value) {
  let output = null
  try {
    object(value)
    const selectedBranchClass = branchClass(option(value, 'branchClass'))
    const branchId = option(value, 'branchId')
    const circuitId = option(value, 'circuitId')
    const generation = option(value, 'generation')
    const fields = [
      option(value, 'exitIdentity'),
      option(value, 'clientActivationNonce'),
      option(value, 'exitOriginCommandPolicyDigest'),
      option(value, 'payloadParametersDigest'),
      option(value, 'finalExitTranscriptDigest'),
      option(value, 'readyNonce')
    ]
    if (!fixed(branchId, 16) || !fixed(circuitId, 16) || !uint64(generation)) invalid()
    if (fields.some((field) => !fixed(field, 32))) invalid()

    output = b4a.allocUnsafeSlow(DHT_EXIT_READY_BODY_SIZE)
    output[0] = selectedBranchClass
    set(output, branchId, 1)
    set(output, circuitId, 17)
    writeUint64(output, generation, 33)
    let offset = 41
    for (const field of fields) {
      set(output, field, offset)
      offset += 32
    }
    return output
  } catch (err) {
    clear(output)
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  }
}

function dhtExitReadySignatureInput(body) {
  let output = null
  try {
    if (!fixed(body, DHT_EXIT_READY_BODY_SIZE)) invalid()
    output = b4a.allocUnsafeSlow(10 + DHT_EXIT_READY_DOMAIN.byteLength + body.byteLength)
    writeUint16(output, DHT_EXIT_READY_DOMAIN.byteLength, 0)
    set(output, DHT_EXIT_READY_DOMAIN, 2)
    writeUint32(output, M3_PROTOCOL_VERSION, 2 + DHT_EXIT_READY_DOMAIN.byteLength)
    writeUint16(output, M3_MESSAGE_ID.DHT_EXIT_READY_V1, 6 + DHT_EXIT_READY_DOMAIN.byteLength)
    writeUint16(output, body.byteLength, 8 + DHT_EXIT_READY_DOMAIN.byteLength)
    set(output, body, 10 + DHT_EXIT_READY_DOMAIN.byteLength)
    return output
  } catch (err) {
    clear(output)
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  }
}

function encodeDhtExitReady(value) {
  let body = null
  try {
    object(value)
    const signature = option(value, 'signature')
    if (!fixed(signature, 64)) invalid()
    body = encodeDhtExitReadyBody(value)
    return encodeM3Object({
      messageId: M3_MESSAGE_ID.DHT_EXIT_READY_V1,
      body,
      authSuffix: signature
    })
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  } finally {
    clear(body)
  }
}

function decodeDhtExitReady(encoded) {
  let decoded = null
  let result = null
  let complete = false
  try {
    decoded = decodeM3Object(encoded)
    if (
      decoded.messageId !== M3_MESSAGE_ID.DHT_EXIT_READY_V1 ||
      !fixed(decoded.body, DHT_EXIT_READY_BODY_SIZE) ||
      !fixed(decoded.authSuffix, 64)
    ) {
      invalid()
    }
    branchClass(decoded.body[0])
    result = {
      body: copy(decoded.body),
      signature: copy(decoded.authSuffix),
      branchClass: decoded.body[0],
      branchId: copy(subarray(decoded.body, 1, 17)),
      circuitId: copy(subarray(decoded.body, 17, 33)),
      generation: readUint64(decoded.body, 33),
      exitIdentity: copy(subarray(decoded.body, 41, 73)),
      clientActivationNonce: copy(subarray(decoded.body, 73, 105)),
      exitOriginCommandPolicyDigest: copy(subarray(decoded.body, 105, 137)),
      payloadParametersDigest: copy(subarray(decoded.body, 137, 169)),
      finalExitTranscriptDigest: copy(subarray(decoded.body, 169, 201)),
      readyNonce: copy(subarray(decoded.body, 201, 233))
    }
    complete = true
    return result
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  } finally {
    if (decoded) {
      clear(decoded.body)
      clear(decoded.authSuffix)
    }
    if (!complete && result) {
      for (const value of Object.values(result)) clear(value)
    }
  }
}

function encodeDhtExitReadyAck(value) {
  let body = null
  try {
    object(value)
    const selectedBranchClass = branchClass(option(value, 'branchClass'))
    const branchId = option(value, 'branchId')
    const circuitId = option(value, 'circuitId')
    const generation = option(value, 'generation')
    const clientActivationNonce = option(value, 'clientActivationNonce')
    const readyDigest = option(value, 'readyDigest')
    if (
      !fixed(branchId, 16) ||
      !fixed(circuitId, 16) ||
      !uint64(generation) ||
      !fixed(clientActivationNonce, 32) ||
      !fixed(readyDigest, 32)
    ) {
      invalid()
    }

    body = b4a.allocUnsafeSlow(DHT_EXIT_READY_ACK_BODY_SIZE)
    body[0] = selectedBranchClass
    set(body, branchId, 1)
    set(body, circuitId, 17)
    writeUint64(body, generation, 33)
    set(body, clientActivationNonce, 41)
    set(body, readyDigest, 73)
    return encodeM3Object({ messageId: M3_MESSAGE_ID.DHT_EXIT_READY_ACK_V1, body })
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  } finally {
    clear(body)
  }
}

function decodeDhtExitReadyAck(encoded) {
  let decoded = null
  let result = null
  let complete = false
  try {
    decoded = decodeM3Object(encoded)
    if (
      decoded.messageId !== M3_MESSAGE_ID.DHT_EXIT_READY_ACK_V1 ||
      !fixed(decoded.body, DHT_EXIT_READY_ACK_BODY_SIZE) ||
      !fixed(decoded.authSuffix, 0)
    ) {
      invalid()
    }
    branchClass(decoded.body[0])
    result = {
      branchClass: decoded.body[0],
      branchId: copy(subarray(decoded.body, 1, 17)),
      circuitId: copy(subarray(decoded.body, 17, 33)),
      generation: readUint64(decoded.body, 33),
      clientActivationNonce: copy(subarray(decoded.body, 41, 73)),
      readyDigest: copy(subarray(decoded.body, 73, 105))
    }
    complete = true
    return result
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  } finally {
    if (decoded) {
      clear(decoded.body)
      clear(decoded.authSuffix)
    }
    if (!complete && result) {
      for (const value of Object.values(result)) clear(value)
    }
  }
}

function encodeDhtExitOpen(value) {
  let body = null
  try {
    object(value)
    const selectedBranchClass = branchClass(option(value, 'branchClass'))
    const branchId = option(value, 'branchId')
    const circuitId = option(value, 'circuitId')
    const generation = option(value, 'generation')
    const fields = [
      option(value, 'ackDigest'),
      option(value, 'clientActivationNonce'),
      option(value, 'exitOriginCommandPolicyDigest'),
      option(value, 'payloadParametersDigest')
    ]
    if (!fixed(branchId, 16) || !fixed(circuitId, 16) || !uint64(generation)) invalid()
    if (fields.some((field) => !fixed(field, 32))) invalid()

    body = b4a.allocUnsafeSlow(DHT_EXIT_OPEN_BODY_SIZE)
    body[0] = selectedBranchClass
    set(body, branchId, 1)
    set(body, circuitId, 17)
    writeUint64(body, generation, 33)
    let offset = 41
    for (const field of fields) {
      set(body, field, offset)
      offset += 32
    }
    return encodeM3Object({ messageId: M3_MESSAGE_ID.DHT_EXIT_OPEN_V1, body })
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  } finally {
    clear(body)
  }
}

function decodeDhtExitOpen(encoded) {
  let decoded = null
  let result = null
  let complete = false
  try {
    decoded = decodeM3Object(encoded)
    if (
      decoded.messageId !== M3_MESSAGE_ID.DHT_EXIT_OPEN_V1 ||
      !fixed(decoded.body, DHT_EXIT_OPEN_BODY_SIZE) ||
      !fixed(decoded.authSuffix, 0)
    ) {
      invalid()
    }
    branchClass(decoded.body[0])
    result = {
      branchClass: decoded.body[0],
      branchId: copy(subarray(decoded.body, 1, 17)),
      circuitId: copy(subarray(decoded.body, 17, 33)),
      generation: readUint64(decoded.body, 33),
      ackDigest: copy(subarray(decoded.body, 41, 73)),
      clientActivationNonce: copy(subarray(decoded.body, 73, 105)),
      exitOriginCommandPolicyDigest: copy(subarray(decoded.body, 105, 137)),
      payloadParametersDigest: copy(subarray(decoded.body, 137, 169))
    }
    complete = true
    return result
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  } finally {
    if (decoded) {
      clear(decoded.body)
      clear(decoded.authSuffix)
    }
    if (!complete && result) {
      for (const value of Object.values(result)) clear(value)
    }
  }
}

function digestCanonicalDhtExit(encoded, decode, domain) {
  let canonical = null
  let projection = null
  let output = null
  try {
    canonical = copy(encoded)
    projection = decode(canonical)
    output = cryptoSuite.hash([domain, canonical])
    if (!fixed(output, 32)) invalid()
    return copy(output)
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  } finally {
    clear(canonical)
    if (projection) {
      for (const value of Object.values(projection)) clear(value)
    }
    clear(output)
  }
}

function digestDhtExitReady(encoded) {
  return digestCanonicalDhtExit(encoded, decodeDhtExitReady, DHT_EXIT_READY_DIGEST_DOMAIN)
}

function digestDhtExitReadyAck(encoded) {
  return digestCanonicalDhtExit(encoded, decodeDhtExitReadyAck, DHT_EXIT_READY_ACK_DIGEST_DOMAIN)
}

function encodeFinalExitTranscript(value) {
  try {
    object(value)
    const selectedBranchClass = branchClass(option(value, 'branchClass'))
    const branchId = option(value, 'branchId')
    const circuitId = option(value, 'circuitId')
    const generation = option(value, 'generation')
    const fields = [
      option(value, 'tailControlTranscriptDigest'),
      option(value, 'exitAdvertisementDigest'),
      option(value, 'exitIdentity'),
      option(value, 'clientActivationNonce'),
      option(value, 'exitOriginCommandPolicyDigest'),
      option(value, 'payloadParametersDigest')
    ]
    if (!fixed(branchId, 16) || !fixed(circuitId, 16) || !uint64(generation)) invalid()
    if (fields.some((field) => !fixed(field, 32))) invalid()

    const output = b4a.allocUnsafeSlow(FINAL_EXIT_TRANSCRIPT_SIZE)
    let offset = 0
    writeUint16(output, FINAL_DOMAIN.byteLength, offset)
    offset += 2
    set(output, FINAL_DOMAIN, offset)
    offset += FINAL_DOMAIN.byteLength
    writeUint32(output, M3_PROTOCOL_VERSION, offset)
    offset += 4
    output[offset++] = selectedBranchClass
    set(output, branchId, offset)
    offset += 16
    set(output, circuitId, offset)
    offset += 16
    writeUint64(output, generation, offset)
    offset += 8
    for (const field of fields) {
      set(output, field, offset)
      offset += 32
    }
    return output
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  }
}

function validateFinalExitTranscript(encoded) {
  if (!fixed(encoded, FINAL_EXIT_TRANSCRIPT_SIZE)) invalid()
  if (readUint16(encoded, 0) !== FINAL_DOMAIN.byteLength) invalid()
  if (!b4a.equals(subarray(encoded, 2, 2 + FINAL_DOMAIN.byteLength), FINAL_DOMAIN)) invalid()
  let offset = 2 + FINAL_DOMAIN.byteLength
  if (readUint32(encoded, offset) !== M3_PROTOCOL_VERSION) invalid()
  offset += 4
  branchClass(encoded[offset])
}

function decodeFinalExitTranscript(encoded) {
  try {
    validateFinalExitTranscript(encoded)
    let offset = 2 + FINAL_DOMAIN.byteLength
    offset += 4
    const selectedBranchClass = encoded[offset++]
    const branchId = copy(subarray(encoded, offset, offset + 16))
    offset += 16
    const circuitId = copy(subarray(encoded, offset, offset + 16))
    offset += 16
    const generation = readUint64(encoded, offset)
    offset += 8
    const fields = []
    for (let index = 0; index < 6; index++) {
      fields.push(copy(subarray(encoded, offset, offset + 32)))
      offset += 32
    }
    return {
      branchClass: selectedBranchClass,
      branchId,
      circuitId,
      generation,
      tailControlTranscriptDigest: fields[0],
      exitAdvertisementDigest: fields[1],
      exitIdentity: fields[2],
      clientActivationNonce: fields[3],
      exitOriginCommandPolicyDigest: fields[4],
      payloadParametersDigest: fields[5]
    }
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  }
}

function digestFinalExitTranscript(encoded) {
  let output = null
  try {
    validateFinalExitTranscript(encoded)
    output = cryptoSuite.hash([FINAL_DIGEST_DOMAIN, encoded])
    if (!fixed(output, 32)) invalid()
    return copy(output)
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  } finally {
    clear(output)
  }
}

function derive(sharedSecret, label, transcript) {
  let labelBytes = null
  let input = null
  let output = null
  try {
    if (!fixed(sharedSecret, 32)) invalid()
    validateFinalExitTranscript(transcript)
    labelBytes = b4a.from(label)
    input = b4a.allocUnsafe(2 + labelBytes.byteLength + 4 + 4 + transcript.byteLength)
    writeUint16(input, labelBytes.byteLength, 0)
    set(input, labelBytes, 2)
    writeUint32(input, M3_PROTOCOL_VERSION, 2 + labelBytes.byteLength)
    writeUint32(input, transcript.byteLength, 6 + labelBytes.byteLength)
    set(input, transcript, 10 + labelBytes.byteLength)
    output = b4a.allocUnsafeSlow(32)
    sodium.crypto_generichash(output, input, sharedSecret)
    return output
  } catch (err) {
    clear(output)
    if (err instanceof PrivateRouteError && err.code === 'INVALID_ROUTE') throw err
    invalid()
  } finally {
    clear(input)
  }
}

function deriveFinalExitTestVector(sharedSecret, transcript) {
  const result = {}
  const owned = []
  let complete = false
  try {
    for (const [name, label] of Object.entries(FINAL_LABELS)) {
      const output = derive(sharedSecret, label, transcript)
      owned.push(output)
      if (name.endsWith('Nonce')) result[`${name}Prefix`] = copy(subarray(output, 0, 16))
      else result[name] = output
    }
    complete = true
    return Object.freeze(result)
  } finally {
    for (const output of owned) {
      if (!Object.values(result).includes(output) || !complete) clear(output)
    }
    if (!complete) {
      for (const output of Object.values(result)) clear(output)
    }
  }
}

module.exports = {
  DHT_EXIT_ACTIVATE_SIZE,
  DHT_EXIT_OPEN_SIZE,
  DHT_EXIT_READY_ACK_SIZE,
  DHT_EXIT_READY_SIZE,
  EXIT_ORIGIN_SERVICE_POLICY,
  DHT_EXIT_ORIGIN_SERVICE_POLICY,
  FINAL_EXIT_TRANSCRIPT_SIZE,
  FINAL_LABELS,
  PAYLOAD_PARAMETERS_SIZE,
  SERVICE_POLICY_ENTRY_SIZE,
  decodeDhtExitActivate,
  decodeDhtExitOpen,
  decodeDhtExitReady,
  decodeDhtExitReadyAck,
  decodeExitOriginServicePolicy,
  decodeFinalExitTranscript,
  decodePayloadParameters,
  deriveFinalExitTestVector,
  dhtExitReadySignatureInput,
  digestDhtExitReady,
  digestDhtExitReadyAck,
  digestExitOriginServicePolicy,
  digestFinalExitTranscript,
  digestPayloadParameters,
  encodeDhtExitActivate,
  encodeDhtExitOpen,
  encodeDhtExitReady,
  encodeDhtExitReadyAck,
  encodeDhtExitReadyBody,
  encodeExitOriginServicePolicy,
  encodeFinalExitTranscript,
  encodePayloadParameters
}
