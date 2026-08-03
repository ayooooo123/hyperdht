'use strict'

const b4a = require('b4a')
const test = require('brittle')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  EXIT_ORIGIN_SERVICE_POLICY,
  digestExitOriginServicePolicy
} = require('../../lib/private/exit-policy')
const {
  digestAdmittedLimits,
  digestPayloadParameters,
  encodeAdmittedLimits,
  encodePayloadParameters
} = require('../../lib/private/link-parameters')
const {
  BRANCH_CLASS,
  M3_MESSAGE_ID,
  M3_PROTOCOL_VERSION,
  decodeM3Object,
  encodeM3Object
} = require('../../lib/private/protocol')
const {
  digestTailControlTranscript,
  encodeTailControlTranscript
} = require('../../lib/private/tail-control')
const {
  DHT_EXIT_ACTIVATE_SIZE,
  DHT_EXIT_OPEN_SIZE,
  DHT_EXIT_READY_SIZE,
  DHT_EXIT_READY_ACK_SIZE,
  FINAL_EXIT_TRANSCRIPT_SIZE,
  FINAL_LABELS,
  decodeDhtExitActivate,
  decodeDhtExitOpen,
  decodeDhtExitReady,
  decodeDhtExitReadyAck,
  decodeFinalExitTranscript,
  deriveFinalExitTestVector,
  dhtExitReadySignatureInput,
  digestDhtExitReady,
  digestDhtExitReadyAck,
  digestFinalExitTranscript,
  encodeDhtExitActivate,
  encodeDhtExitOpen,
  encodeDhtExitReady,
  encodeDhtExitReadyAck,
  encodeDhtExitReadyBody,
  encodeFinalExitTranscript
} = require('../../lib/private/final-exit')

const EXPECTED_VECTORS = Object.freeze({
  admittedLimitsDigest: 'ea5dbf85e3dd17534b675e815453b0ef3a2254f3736d0297ab1acd5955ee790c',
  policyDigest: '61445e852f5e70095e836e2c1128cc1c024a15784406a476990279fe7094610b',
  parametersDigest: '1d248fe6302060ddfb8b015e3a7d51e2ff895f6c73ad8ce85329a68f82b04db2',
  tailDigest: '005d3b85d52d89a1b471a3a4a88f3e06967fdc2f1606470e195aa24618ed697f',
  finalOutputs: Object.freeze({
    payloadForwardKey: 'd7e08006283ee9b52738b0ee84394482bee178dbbcaae8d51697bfff51b8e884',
    payloadReverseKey: 'e922c9931f8e8ba0e30bedf8bf6d89abc4494ccf4ab7f5e7a66e0fd3450221c3',
    payloadForwardNoncePrefix: 'ab9789ba0bf03ea392cf64929db0ec49',
    payloadReverseNoncePrefix: 'ec9df25e5f0a1daf592c3ae4fe087029',
    controlForwardKey: '4a709055daf4843d09d24a8cc7a155dbe1e825603c1e5afc7efdf1eaf54472fc',
    controlReverseKey: 'c92c834d793103bca7d41339e14eccd91734add5d13fbb53a12ba4b1a822296e',
    controlForwardNoncePrefix: 'f9570e0e631559c2235895d595423ee4',
    controlReverseNoncePrefix: '9a19451b7cd13c9c25bc748b0370cab1',
    finalizeForwardKey: '24793191f580a0f2acec7c0707aaf4e8bcf2edd3cb0b4938a5b2b48d3202a15f',
    finalizeReverseKey: '8f089a69f6ee91caa71f0f922edff6da1151a6145a0cb04063450296c8de15e3',
    finalizeForwardNoncePrefix: '696467f2d8b1031ca3cb4416e6d7350b',
    finalizeReverseNoncePrefix: 'c323919f000a5e60b65db39ed1f9cb9d'
  })
})

function seed(byte, size = 32) {
  return b4a.alloc(size, byte)
}

function sequence(start, size) {
  const value = b4a.allocUnsafe(size)
  for (let index = 0; index < size; index++) value[index] = start + index
  return value
}

function u16(value) {
  return b4a.from([value >>> 8, value])
}

function u32(value) {
  return b4a.from([value >>> 24, value >>> 16, value >>> 8, value])
}

function u64(value) {
  const result = b4a.alloc(8)
  for (let index = 7; index >= 0; index--) {
    result[index] = Number(value & 0xffn)
    value >>= 8n
  }
  return result
}

function expectCode(t, operation, code, message) {
  let error = null
  try {
    operation()
  } catch (err) {
    error = err
  }
  t.is(error && error.code, code, message)
}

function validFinalTranscriptValue() {
  const limits = {
    cellSize: 1200,
    maxCells: 4096,
    maxBytes: 1_048_576,
    maxCommands: 512,
    idleTimeoutMs: 30_000,
    expiresAtMs: 0x0102_0304_0506_0708n
  }
  const tailTranscript = encodeTailControlTranscript({
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: sequence(0x00, 16),
    circuitId: sequence(0x10, 16),
    generation: 0x0102_0304_0506_0708n,
    extensionIndex: 2,
    clientTailEphemeralPublicKey: b4a.alloc(32, 0x20),
    advertisedTailRouteEncryptionPublicKey: b4a.alloc(32, 0x21),
    candidateAdvertisementDigest: b4a.alloc(32, 0x22),
    clientNonce: b4a.alloc(32, 0x23),
    tailIdentity: b4a.alloc(32, 0x24),
    admittedLimitsDigest: digestAdmittedLimits(limits)
  })
  const parameters = {
    cellSize: 1200,
    maxCellPayload: 1146,
    contextEnvelopeSize: 1101,
    routeFrameSize: 1100,
    maxRoutePayload: 1073,
    datagramReplayWindow: 64,
    maxQueuedBytes: 262_144,
    idleTimeoutMs: 30_000
  }
  return {
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: sequence(0x00, 16),
    circuitId: sequence(0x10, 16),
    generation: 0x0102_0304_0506_0708n,
    tailControlTranscriptDigest: digestTailControlTranscript(tailTranscript),
    exitAdvertisementDigest: b4a.alloc(32, 0x31),
    exitIdentity: b4a.alloc(32, 0x32),
    clientActivationNonce: b4a.alloc(32, 0x33),
    exitOriginCommandPolicyDigest: digestExitOriginServicePolicy(EXIT_ORIGIN_SERVICE_POLICY),
    payloadParametersDigest: digestPayloadParameters(parameters)
  }
}

test('final-exit labels are exact and frozen', (t) => {
  t.alike(Object.keys(FINAL_LABELS), [
    'payloadForwardKey',
    'payloadReverseKey',
    'payloadForwardNonce',
    'payloadReverseNonce',
    'controlForwardKey',
    'controlReverseKey',
    'controlForwardNonce',
    'controlReverseNonce',
    'finalizeForwardKey',
    'finalizeReverseKey',
    'finalizeForwardNonce',
    'finalizeReverseNonce'
  ])
  t.alike(Object.values(FINAL_LABELS), [
    'hyperdht-private-routes/kdf/v1/final-exit/payload/forward-key',
    'hyperdht-private-routes/kdf/v1/final-exit/payload/reverse-key',
    'hyperdht-private-routes/kdf/v1/final-exit/payload/forward-nonce',
    'hyperdht-private-routes/kdf/v1/final-exit/payload/reverse-nonce',
    'hyperdht-private-routes/kdf/v1/final-exit/control/forward-key',
    'hyperdht-private-routes/kdf/v1/final-exit/control/reverse-key',
    'hyperdht-private-routes/kdf/v1/final-exit/control/forward-nonce',
    'hyperdht-private-routes/kdf/v1/final-exit/control/reverse-nonce',
    'hyperdht-private-routes/kdf/v1/final-exit/finalize/forward-key',
    'hyperdht-private-routes/kdf/v1/final-exit/finalize/reverse-key',
    'hyperdht-private-routes/kdf/v1/final-exit/finalize/forward-nonce',
    'hyperdht-private-routes/kdf/v1/final-exit/finalize/reverse-nonce'
  ])
  t.ok(Object.isFrozen(FINAL_LABELS))
})

test('final-exit transcript and KDF outputs are byte exact', (t) => {
  const value = validFinalTranscriptValue()
  const finalDomain = b4a.from('hyperdht-private-routes/final-exit/transcript/v1')
  const expected = b4a.concat([
    u16(finalDomain.byteLength),
    finalDomain,
    u32(M3_PROTOCOL_VERSION),
    b4a.from([BRANCH_CLASS.LOOKUP]),
    value.branchId,
    value.circuitId,
    u64(value.generation),
    value.tailControlTranscriptDigest,
    value.exitAdvertisementDigest,
    value.exitIdentity,
    value.clientActivationNonce,
    value.exitOriginCommandPolicyDigest,
    value.payloadParametersDigest
  ])
  const transcript = encodeFinalExitTranscript(value)

  t.is(FINAL_EXIT_TRANSCRIPT_SIZE, 287)
  t.alike(value.tailControlTranscriptDigest, b4a.from(EXPECTED_VECTORS.tailDigest, 'hex'))
  t.alike(value.exitOriginCommandPolicyDigest, b4a.from(EXPECTED_VECTORS.policyDigest, 'hex'))
  t.alike(value.payloadParametersDigest, b4a.from(EXPECTED_VECTORS.parametersDigest, 'hex'))
  t.alike(transcript, expected)
  t.alike(decodeFinalExitTranscript(transcript), value)

  const derived = deriveFinalExitTestVector(seed(0x61), transcript)
  for (const [name, expectedHex] of Object.entries(EXPECTED_VECTORS.finalOutputs)) {
    t.alike(derived[name], b4a.from(expectedHex, 'hex'), name)
  }
})

test('DHT_EXIT_ACTIVATE_V1 has one canonical unsigned encoding', (t) => {
  const value = {
    clientActivationNonce: seed(0x11),
    exitOriginCommandPolicyDigest: seed(0x12),
    payloadParametersDigest: seed(0x13)
  }
  const encoded = encodeDhtExitActivate(value)
  const object = decodeM3Object(encoded)

  t.is(encoded.byteLength, DHT_EXIT_ACTIVATE_SIZE)
  t.is(object.messageId, M3_MESSAGE_ID.DHT_EXIT_ACTIVATE_V1)
  t.is(object.body.byteLength, 96)
  t.is(object.authSuffix.byteLength, 0)
  t.alike(decodeDhtExitActivate(encoded), value)
})

test('DHT_EXIT_READY_V1 has one canonical signed encoding and signature input', (t) => {
  const value = {
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: seed(0x21, 16),
    circuitId: seed(0x22, 16),
    generation: 0x0102_0304_0506_0708n,
    exitIdentity: seed(0x23),
    clientActivationNonce: seed(0x24),
    exitOriginCommandPolicyDigest: seed(0x25),
    payloadParametersDigest: seed(0x26),
    finalExitTranscriptDigest: seed(0x27),
    readyNonce: seed(0x28)
  }
  const body = encodeDhtExitReadyBody(value)
  const readyDomain = b4a.from('hyperdht-private-routes/m3/dht-exit-ready/v1')
  const expectedInput = b4a.concat([
    u16(readyDomain.byteLength),
    readyDomain,
    u32(M3_PROTOCOL_VERSION),
    u16(M3_MESSAGE_ID.DHT_EXIT_READY_V1),
    u16(233),
    body
  ])
  const signature = seed(0x29, 64)
  const encoded = encodeDhtExitReady({ ...value, signature })
  const decoded = decodeDhtExitReady(encoded)

  t.is(body.byteLength, 233)
  t.alike(dhtExitReadySignatureInput(body), expectedInput)
  t.is(encoded.byteLength, DHT_EXIT_READY_SIZE)
  t.alike(decoded.body, body)
  t.alike(decoded.signature, signature)
  for (const [name, expected] of Object.entries(value)) t.alike(decoded[name], expected, name)
})

test('DHT_EXIT_READY_ACK_V1 and OPEN_V1 bind branch and digest fields exactly', (t) => {
  const ack = {
    branchClass: BRANCH_CLASS.ANNOUNCE,
    branchId: seed(0x41, 16),
    circuitId: seed(0x42, 16),
    generation: 9n,
    clientActivationNonce: seed(0x43),
    readyDigest: seed(0x44)
  }
  const encodedAck = encodeDhtExitReadyAck(ack)
  const open = {
    branchClass: BRANCH_CLASS.ANNOUNCE,
    branchId: ack.branchId,
    circuitId: ack.circuitId,
    generation: ack.generation,
    ackDigest: digestDhtExitReadyAck(encodedAck),
    clientActivationNonce: ack.clientActivationNonce,
    exitOriginCommandPolicyDigest: seed(0x45),
    payloadParametersDigest: seed(0x46)
  }
  const encodedOpen = encodeDhtExitOpen(open)

  t.is(encodedAck.byteLength, DHT_EXIT_READY_ACK_SIZE)
  t.alike(decodeDhtExitReadyAck(encodedAck), ack)
  t.is(encodedOpen.byteLength, DHT_EXIT_OPEN_SIZE)
  t.alike(decodeDhtExitOpen(encodedOpen), open)
})

test('final-exit codecs reject malformed framing and substituted transcript fields', (t) => {
  const value = validFinalTranscriptValue()
  const transcript = encodeFinalExitTranscript(value)
  const derived = deriveFinalExitTestVector(seed(0x72), transcript)
  const substitutions = [
    { ...value, branchClass: BRANCH_CLASS.ANNOUNCE },
    { ...value, branchId: seed(0xa1, 16) },
    { ...value, circuitId: seed(0xa2, 16) },
    { ...value, generation: value.generation + 1n },
    { ...value, tailControlTranscriptDigest: seed(0xa3) },
    { ...value, exitAdvertisementDigest: seed(0xa4) },
    { ...value, exitIdentity: seed(0xa5) },
    { ...value, clientActivationNonce: seed(0xa6) },
    { ...value, exitOriginCommandPolicyDigest: seed(0xa7) },
    { ...value, payloadParametersDigest: seed(0xa8) }
  ]

  for (const substitution of substitutions) {
    const encoded = encodeFinalExitTranscript(substitution)
    t.is(b4a.equals(encoded, transcript), false)
    t.is(
      b4a.equals(
        deriveFinalExitTestVector(seed(0x72), encoded).payloadForwardKey,
        derived.payloadForwardKey
      ),
      false
    )
  }

  const wrongVersion = b4a.from(transcript)
  wrongVersion.writeUInt32BE(
    M3_PROTOCOL_VERSION + 1,
    2 + 'hyperdht-private-routes/final-exit/transcript/v1'.length
  )
  expectCode(t, () => decodeFinalExitTranscript(wrongVersion), 'INVALID_ROUTE')
  expectCode(
    t,
    () => decodeFinalExitTranscript(b4a.concat([transcript, b4a.from([0])])),
    'INVALID_ROUTE'
  )
  expectCode(
    t,
    () =>
      encodeDhtExitActivate({
        ...decodeDhtExitActivate(
          encodeDhtExitActivate({
            clientActivationNonce: seed(1),
            exitOriginCommandPolicyDigest: seed(2),
            payloadParametersDigest: seed(3)
          })
        ),
        clientActivationNonce: seed(1, 31)
      }),
    'INVALID_ROUTE'
  )

  const ready = encodeDhtExitReady({
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: seed(1, 16),
    circuitId: seed(2, 16),
    generation: 1n,
    exitIdentity: seed(3),
    clientActivationNonce: seed(4),
    exitOriginCommandPolicyDigest: seed(5),
    payloadParametersDigest: seed(6),
    finalExitTranscriptDigest: seed(7),
    readyNonce: seed(8),
    signature: seed(9, 64)
  })
  const readyDigest = digestDhtExitReady(ready)
  const tampered = b4a.from(ready)
  tampered[tampered.byteLength - 1] ^= 1
  t.is(b4a.equals(digestDhtExitReady(tampered), readyDigest), false)
})

// Keeps Task 7 dependency on the already migrated payload-parameter owner explicit.
test('payload parameters used by final-exit remain the existing link-parameters bytes', (t) => {
  const parameters = {
    cellSize: 1200,
    maxCellPayload: 1146,
    contextEnvelopeSize: 1101,
    routeFrameSize: 1100,
    maxRoutePayload: 1073,
    datagramReplayWindow: 64,
    maxQueuedBytes: 262_144,
    idleTimeoutMs: 30_000
  }
  t.alike(
    encodePayloadParameters(parameters),
    b4a.concat([
      u16(1200),
      u16(1146),
      u16(1101),
      u16(1100),
      u16(1073),
      u16(64),
      u32(262_144),
      u32(30_000)
    ])
  )
})
