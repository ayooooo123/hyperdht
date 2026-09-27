'use strict'

const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-universal')
const { PrivateRouteError } = require('../../lib/private/errors')
const { PEER_PROTOCOL_VERSION } = require('../../lib/private/peer-protocol')

const {
  PEER_LAYER_BLOCK_SIZE,
  hashPeer,
  derivePeerKey,
  digestPeerLimits,
  createPeerTailTranscript,
  combinePeerTailSecret,
  agreePeerTailSecret,
  derivePeerTailKeys,
  createPeerAdjacencyTranscript,
  derivePeerAdjacencyKeys,
  derivePeerAdjacencyHeader,
  clearPeerAdjacencyKeys,
  derivePeerLayerKeys,
  clearPeerLayerKeys,
  sealPeerLayer,
  openPeerLayer,
  sealPeerSourceLayers,
  openPeerSourceLayers,
  createPeerPurposePreTranscript,
  createPeerPurposeTranscript,
  derivePeerPurposeSharedSecret,
  derivePeerPurposeTerminalKeyPair,
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
} = require('../../lib/private/peer-crypto')

function sequence(start, size) {
  const output = b4a.allocUnsafe(size)
  for (let index = 0; index < size; index++) output[index] = start + index
  return output
}

function uint16(value) {
  return b4a.from([value >>> 8, value])
}

function uint32(value) {
  return b4a.from([value >>> 24, value >>> 16, value >>> 8, value])
}

function uint64(value) {
  const output = b4a.alloc(8)
  for (let index = 7; index >= 0; index--) {
    output[index] = Number(value & 0xffn)
    value >>= 8n
  }
  return output
}

function expectCode(t, operation, code) {
  let error = null
  try {
    operation()
  } catch (err) {
    error = err
  }
  t.ok(error instanceof PrivateRouteError)
  t.is(error && error.code, code)
}

function allZero(value) {
  for (const byte of value) {
    if (byte !== 0) return false
  }
  return true
}

const LIMITS_INPUT = b4a.from(
  '0000000304b0000003e900124f810000001500001388000001d1a94a200104b0000003ea00124f820000001600001388000001d1a94a20020303030303030303030303030303030303030303030303030303030303030303',
  'hex'
)
const REVERSE_LIMITS = LIMITS_INPUT.subarray(4, 30)
const FORWARD_LIMITS = LIMITS_INPUT.subarray(30, 56)
const CANDIDATE_COMMITMENT = LIMITS_INPUT.subarray(56)

const TAIL_FIELDS = Object.freeze({
  branchId: b4a.alloc(16, 0x04),
  circuitId: b4a.alloc(16, 0x05),
  generation: 6n,
  extensionIndex: 2,
  clientTailEphemeralPublicKey: b4a.alloc(32, 0x07),
  advertisedTailRouteEncryptionPublicKey: b4a.alloc(32, 0x08),
  candidateAdvertisementDigest: b4a.alloc(32, 0x09),
  clientNonce: b4a.alloc(32, 0x0a),
  tailIdentity: b4a.alloc(32, 0x0b),
  reverseLimits: REVERSE_LIMITS,
  forwardLimits: FORWARD_LIMITS,
  candidateAuthorityCommitment: CANDIDATE_COMMITMENT
})

function expectedTailTranscript(limitsDigest) {
  return b4a.concat([
    uint16(50),
    b4a.from('hyperdht-private-routes/tail-control/transcript/v2'),
    uint32(PEER_PROTOCOL_VERSION),
    b4a.from([2]),
    TAIL_FIELDS.branchId,
    TAIL_FIELDS.circuitId,
    uint64(TAIL_FIELDS.generation),
    b4a.from([TAIL_FIELDS.extensionIndex]),
    TAIL_FIELDS.clientTailEphemeralPublicKey,
    TAIL_FIELDS.advertisedTailRouteEncryptionPublicKey,
    TAIL_FIELDS.candidateAdvertisementDigest,
    TAIL_FIELDS.clientNonce,
    TAIL_FIELDS.tailIdentity,
    limitsDigest
  ])
}

test('v3 tail transcript, limits digest, and eight KDF labels freeze vectors', (t) => {
  t.is(PEER_PROTOCOL_VERSION, 3)
  const expectedLimitsDigest = b4a.from(
    '8edb23aa9f458f8e53d08480f7c529c7db042c12ee66f48f105b2965a69d5e39',
    'hex'
  )
  const limitsDigest = digestPeerLimits(REVERSE_LIMITS, FORWARD_LIMITS, CANDIDATE_COMMITMENT)
  t.is(LIMITS_INPUT.byteLength, 88)
  t.alike(limitsDigest, expectedLimitsDigest)

  const expectedTranscript = expectedTailTranscript(expectedLimitsDigest)
  const transcript = createPeerTailTranscript(TAIL_FIELDS)
  t.is(transcript.byteLength, 290)
  t.alike(transcript, expectedTranscript)
  t.alike(
    hashPeer('hyperdht-private-routes/m3/tail-control/transcript-digest/v2', [transcript]),
    b4a.from('cd57d311b1f4aa7eaeae3a4db0c31f47063082795b401b27687159b21d75d9f0', 'hex')
  )

  const keys = derivePeerTailKeys(b4a.alloc(32, 0x0c), transcript)
  const expected = {
    tailControlForwardKey: '89ffbeaf368d86eeb613dc6c901b2cf3cb8dbf8c02c8acc6b9ec92d992a93a68',
    tailControlReverseKey: 'c9be7d7e6099b174fd71c17cc204c9bf9627829a8f9000ac0aab2ffe7885049f',
    tailControlForwardNoncePrefix: '2b9661de2a758c3fd32d651a2aea5513',
    tailControlReverseNoncePrefix: '3544cc7165d30efd66d3eadea32f9b15',
    finalizeForwardKey: 'bca72230ab6a9e8afd3dd571560771d7544e436b0407c37e0edfe00ff99f69de',
    finalizeReverseKey: 'a27cef3a41cf51a1564f0e38ea1c1a5c9122da164a4bffbfa2bc4b5b33ecf840',
    finalizeForwardNoncePrefix: '387db24fb5c9c09a4afc2b214c6b86a9',
    finalizeReverseNoncePrefix: '100c08090e1923c236b1521c56dc3bce'
  }
  for (const [name, hex] of Object.entries(expected)) t.alike(keys[name], b4a.from(hex, 'hex'))

  const changedCandidate = b4a.from(CANDIDATE_COMMITMENT)
  changedCandidate[0] ^= 1
  const changedFields = { ...TAIL_FIELDS, candidateAuthorityCommitment: changedCandidate }
  const changedTranscript = createPeerTailTranscript(changedFields)
  t.unlike(changedTranscript, transcript)
  t.unlike(
    derivePeerTailKeys(b4a.alloc(32, 0x0c), changedTranscript).tailControlForwardKey,
    keys.tailControlForwardKey
  )
})

test('derivePeerKey uses the exact v3 framing and independent output32', (t) => {
  const sharedSecret = b4a.alloc(32, 0x31)
  const label = 'peer-test-kdf/v2'
  const transcript = b4a.from('exact transcript bytes')
  const expectedInput = b4a.concat([
    uint16(Buffer.byteLength(label)),
    b4a.from(label),
    uint32(PEER_PROTOCOL_VERSION),
    uint32(transcript.byteLength),
    transcript
  ])
  const expected = b4a.alloc(32)
  sodium.crypto_generichash(expected, expectedInput, sharedSecret)
  t.alike(derivePeerKey(sharedSecret, label, transcript), expected)
  t.is(derivePeerKey(sharedSecret, label, transcript).byteLength, 32)
  t.unlike(derivePeerKey(sharedSecret, 'peer-test-kdf/other-v2', transcript), expected)
})

function referenceConfirmation(options) {
  const label = b4a.from(options.label)
  const context = b4a.concat([
    options.noiseHash,
    options.sessionId,
    options.sourcePurposeDigest,
    options.destinationPurposeDigest,
    options.registrationCommitment
  ])
  const kdfInput = b4a.concat([
    uint16(label.byteLength),
    label,
    uint32(PEER_PROTOCOL_VERSION),
    uint32(context.byteLength),
    context
  ])
  const confirmationKey = b4a.alloc(32)
  sodium.crypto_generichash(confirmationKey, kdfInput, options.directionKey)
  const transcript = b4a.concat(options.transcriptParts)
  const confirmInput = b4a.concat([uint32(transcript.byteLength), transcript])
  const output = b4a.alloc(32)
  sodium.crypto_generichash(output, confirmInput, confirmationKey)
  return output
}

function confirmationOptions() {
  return {
    directionKey: b4a.alloc(32, 0x19),
    label: 'hyperdht-private-routes/peer/private-ready-confirmation-key/v2',
    noiseHash: sequence(0x30, 64),
    sessionId: sequence(0x70, 16),
    sourcePurposeDigest: sequence(0x90, 32),
    destinationPurposeDigest: sequence(0xb0, 32),
    registrationCommitment: sequence(0xd0, 32),
    transcriptParts: [
      b4a.from('canonical-activate'),
      sequence(0x10, 37),
      b4a.from('canonical-ready-before-mac')
    ]
  }
}

test('confirmation incrementally matches independent native vector and erases arena', (t) => {
  const base = confirmationOptions()
  const expected = referenceConfirmation(base)
  const outputTag32 = b4a.alloc(32)
  const arena = b4a.alloc(528, 0xa5)
  computePeerConfirmation(arena, { ...base, outputTag32 })
  t.alike(outputTag32, expected)
  t.ok(allZero(arena), 'compute erases all 528 arena bytes')

  const verifyArena = b4a.alloc(528, 0x5a)
  t.ok(verifyPeerConfirmation(verifyArena, { ...base, receivedTag32: outputTag32 }))
  t.ok(allZero(verifyArena), 'verify erases all 528 arena bytes')

  const changedPurpose = b4a.from(base.sourcePurposeDigest)
  changedPurpose[0] ^= 1
  const changedArena = b4a.alloc(528, 0x5a)
  t.is(
    verifyPeerConfirmation(changedArena, {
      ...base,
      sourcePurposeDigest: changedPurpose,
      receivedTag32: outputTag32
    }),
    false
  )
  t.ok(allZero(changedArena), 'changed binding still erases arena')

  const changedTranscript = b4a.from(base.transcriptParts[1])
  changedTranscript[0] ^= 1
  const changedTranscriptArena = b4a.alloc(528, 0x5a)
  t.is(
    verifyPeerConfirmation(changedTranscriptArena, {
      ...base,
      transcriptParts: [base.transcriptParts[0], changedTranscript, base.transcriptParts[2]],
      receivedTag32: outputTag32
    }),
    false
  )
  t.ok(allZero(changedTranscriptArena), 'changed transcript still erases arena')
})

test('confirmation rejects accessors, unknown labels, wrong widths, and reentry', (t) => {
  const base = confirmationOptions()
  const expected = referenceConfirmation(base)

  const accessorOptions = { ...base, outputTag32: b4a.alloc(32) }
  let invoked = false
  Object.defineProperty(accessorOptions, 'label', {
    enumerable: true,
    get() {
      invoked = true
      throw new Error('label getter must not run')
    }
  })
  const accessorArena = b4a.alloc(528, 0xa5)
  expectCode(t, () => computePeerConfirmation(accessorArena, accessorOptions), 'INVALID_ROUTE')
  t.is(invoked, false)
  t.ok(allZero(accessorArena))

  const unknownLabelArena = b4a.alloc(528, 0xa5)
  expectCode(
    t,
    () =>
      computePeerConfirmation(unknownLabelArena, {
        ...base,
        label: 'hyperdht-private-routes/peer/private-unknown-confirmation-key/v2',
        outputTag32: b4a.alloc(32)
      }),
    'INVALID_ROUTE'
  )
  t.ok(allZero(unknownLabelArena))

  const wrongTagArena = b4a.alloc(528, 0xa5)
  expectCode(
    t,
    () => verifyPeerConfirmation(wrongTagArena, { ...base, receivedTag32: b4a.alloc(31) }),
    'INVALID_ROUTE'
  )
  t.ok(allZero(wrongTagArena))

  const originalUpdate = sodium.crypto_generichash_update
  const reentryArena = b4a.alloc(528, 0x5a)
  const reentryOptions = { ...base, outputTag32: b4a.alloc(32) }
  let reentryCode = null
  sodium.crypto_generichash_update = function (state, input) {
    if (reentryCode === null) {
      try {
        computePeerConfirmation(reentryArena, reentryOptions)
      } catch (err) {
        reentryCode = err && err.code
      }
    }
    return originalUpdate(state, input)
  }
  try {
    computePeerConfirmation(reentryArena, reentryOptions)
  } finally {
    sodium.crypto_generichash_update = originalUpdate
  }
  t.is(reentryCode, 'INVALID_ROUTE')
  t.alike(reentryOptions.outputTag32, expected)
  t.ok(allZero(reentryArena))

  const originalFinal = sodium.crypto_generichash_final
  const failureArena = b4a.alloc(528, 0x7c)
  sodium.crypto_generichash_final = function () {
    throw new Error('injected native failure')
  }
  let failure = null
  try {
    computePeerConfirmation(failureArena, { ...base, outputTag32: b4a.alloc(32) })
  } catch (err) {
    failure = err
  } finally {
    sodium.crypto_generichash_final = originalFinal
  }
  t.is(failure && failure.message, 'injected native failure')
  t.ok(allZero(failureArena), 'native failure erases arena')

  const originalConcat = b4a.concat
  b4a.concat = function () {
    throw new Error('runtime must not concatenate private transcript')
  }
  const noConcatArena = b4a.alloc(528, 0x21)
  const noConcatOutput = b4a.alloc(32)
  let noConcatFailure = null
  try {
    computePeerConfirmation(noConcatArena, { ...base, outputTag32: noConcatOutput })
  } catch (err) {
    noConcatFailure = err
  } finally {
    b4a.concat = originalConcat
  }
  t.absent(noConcatFailure)
  t.alike(noConcatOutput, expected)
  t.ok(allZero(noConcatArena))
})

test('peer crypto rejects malformed transcript, limits, and confirmation keys', (t) => {
  expectCode(
    t,
    () => digestPeerLimits(b4a.alloc(25), FORWARD_LIMITS, CANDIDATE_COMMITMENT),
    'INVALID_ROUTE'
  )
  expectCode(
    t,
    () => createPeerTailTranscript({ ...TAIL_FIELDS, extensionIndex: 3 }),
    'INVALID_ROUTE'
  )
  expectCode(t, () => derivePeerTailKeys(b4a.alloc(31), b4a.alloc(290)), 'INVALID_KEY')
  expectCode(t, () => derivePeerTailKeys(b4a.alloc(32), b4a.alloc(290)), 'INVALID_KEY')
  expectCode(t, () => derivePeerTailKeys(b4a.alloc(32, 1), b4a.alloc(289)), 'INVALID_ROUTE')
  expectCode(
    t,
    () => derivePeerKey(b4a.alloc(32), 'x'.repeat(0x10000), b4a.alloc(0)),
    'INVALID_ROUTE'
  )
  expectCode(t, () => hashPeer('x'.repeat(0x10000), []), 'INVALID_ROUTE')

  const base = confirmationOptions()
  const arena = b4a.alloc(528, 0x44)
  expectCode(
    t,
    () =>
      computePeerConfirmation(arena, {
        ...base,
        directionKey: b4a.alloc(31),
        outputTag32: b4a.alloc(32)
      }),
    'INVALID_KEY'
  )
  t.ok(allZero(arena))
})

test('tail key derivation erases earlier outputs when a later derivation fails', (t) => {
  const transcript = createPeerTailTranscript(TAIL_FIELDS)
  const originalFinal = sodium.crypto_generichash_final
  const outputs = []
  const failure = new Error('injected second derivation failure')
  let caught = null
  sodium.crypto_generichash_final = function (state, output) {
    originalFinal(state, output)
    outputs.push(output)
    if (outputs.length === 2) throw failure
  }
  try {
    derivePeerTailKeys(b4a.alloc(32, 0x0c), transcript)
  } catch (err) {
    caught = err
  } finally {
    sodium.crypto_generichash_final = originalFinal
  }
  t.is(caught, failure)
  t.is(outputs.length, 2)
  t.ok(allZero(outputs[0]), 'earlier completed key is erased')
  t.ok(allZero(outputs[1]), 'failing derivation output is erased')
})
function referenceHashPeer(domain, parts) {
  const domainBytes = b4a.from(domain, 'utf8')
  const prefix = b4a.alloc(2)
  prefix[0] = domainBytes.byteLength >>> 8
  prefix[1] = domainBytes.byteLength & 0xff
  const state = b4a.alloc(384)
  const out = b4a.alloc(32)
  sodium.crypto_generichash_init(state, null, 32)
  sodium.crypto_generichash_update(state, prefix)
  sodium.crypto_generichash_update(state, domainBytes)
  for (const part of parts) sodium.crypto_generichash_update(state, part)
  sodium.crypto_generichash_final(state, out)
  return out
}

function referenceDerivePeerKey(
  sharedSecret,
  label,
  transcript,
  protocolVersion = PEER_PROTOCOL_VERSION
) {
  const labelBytes = b4a.from(label, 'utf8')
  const framing = b4a.alloc(10 + labelBytes.byteLength)
  framing[0] = labelBytes.byteLength >>> 8
  framing[1] = labelBytes.byteLength & 0xff
  framing.set(labelBytes, 2)
  const vOffset = 2 + labelBytes.byteLength
  framing[vOffset] = protocolVersion >>> 24
  framing[vOffset + 1] = (protocolVersion >>> 16) & 0xff
  framing[vOffset + 2] = (protocolVersion >>> 8) & 0xff
  framing[vOffset + 3] = protocolVersion & 0xff
  const tOffset = vOffset + 4
  framing[tOffset] = transcript.byteLength >>> 24
  framing[tOffset + 1] = (transcript.byteLength >>> 16) & 0xff
  framing[tOffset + 2] = (transcript.byteLength >>> 8) & 0xff
  framing[tOffset + 3] = transcript.byteLength & 0xff

  const state = b4a.alloc(384)
  const output = b4a.alloc(32)
  sodium.crypto_generichash_init(state, sharedSecret, 32)
  sodium.crypto_generichash_update(state, framing)
  sodium.crypto_generichash_update(state, transcript)
  sodium.crypto_generichash_final(state, output)
  return output
}

function referenceAdjacencyKeys(
  sharedSecret,
  completeOffer,
  completeAccept,
  cellClass,
  protocolVersion = PEER_PROTOCOL_VERSION
) {
  const prefix = b4a.from('hyperdht-private-routes/link/created/v2', 'utf8')
  const offerDigest = referenceHashPeer('hyperdht-private-routes/m3/link-offer-digest/v2', [
    completeOffer
  ])
  const acceptDigest = referenceHashPeer('hyperdht-private-routes/m3/link-accept-digest/v2', [
    completeAccept
  ])
  const transcript = b4a.alloc(104)
  transcript.set(prefix, 0)
  transcript.set(offerDigest, 39)
  transcript.set(acceptDigest, 71)
  transcript[103] = cellClass

  const fKey = referenceDerivePeerKey(
    sharedSecret,
    'hyperdht-private-routes/kdf/v2/forward-key',
    transcript,
    protocolVersion
  )
  const rKey = referenceDerivePeerKey(
    sharedSecret,
    'hyperdht-private-routes/kdf/v2/reverse-key',
    transcript,
    protocolVersion
  )
  const fNonce = referenceDerivePeerKey(
    sharedSecret,
    'hyperdht-private-routes/kdf/v2/forward-nonce',
    transcript,
    protocolVersion
  )
  const rNonce = referenceDerivePeerKey(
    sharedSecret,
    'hyperdht-private-routes/kdf/v2/reverse-nonce',
    transcript,
    protocolVersion
  )

  return {
    transcript,
    forwardKey: fKey,
    reverseKey: rKey,
    forwardNoncePrefix: b4a.from(fNonce.subarray(0, 16)),
    reverseNoncePrefix: b4a.from(rNonce.subarray(0, 16))
  }
}

test('v3 adjacency KDF derives 8 distinct outputs across CONTROL0 and DATAGRAM2 and matches independent reference', (t) => {
  const secret = sequence(0x01, 32)
  const offer = sequence(0x10, 432)
  const accept = sequence(0x20, 285)

  const controlKeys = derivePeerAdjacencyKeys(secret, offer, accept, 0)
  const datagramKeys = derivePeerAdjacencyKeys(secret, offer, accept, 2)

  const refControl = referenceAdjacencyKeys(secret, offer, accept, 0)
  const refDatagram = referenceAdjacencyKeys(secret, offer, accept, 2)

  t.alike(controlKeys.forwardKey, refControl.forwardKey)
  t.alike(controlKeys.reverseKey, refControl.reverseKey)
  t.alike(controlKeys.forwardNoncePrefix, refControl.forwardNoncePrefix)
  t.alike(controlKeys.reverseNoncePrefix, refControl.reverseNoncePrefix)

  t.alike(datagramKeys.forwardKey, refDatagram.forwardKey)
  t.alike(datagramKeys.reverseKey, refDatagram.reverseKey)
  t.alike(datagramKeys.forwardNoncePrefix, refDatagram.forwardNoncePrefix)
  t.alike(datagramKeys.reverseNoncePrefix, refDatagram.reverseNoncePrefix)

  // Verify direction / class separation
  t.absent(b4a.equals(controlKeys.forwardKey, controlKeys.reverseKey))
  t.absent(b4a.equals(controlKeys.forwardNoncePrefix, controlKeys.reverseNoncePrefix))
  t.absent(b4a.equals(controlKeys.forwardKey, datagramKeys.forwardKey))
  t.absent(b4a.equals(controlKeys.reverseKey, datagramKeys.reverseKey))
  t.absent(b4a.equals(controlKeys.forwardNoncePrefix, datagramKeys.forwardNoncePrefix))

  // Verify sensitivity to offer change
  const offerTampered = sequence(0x10, 432)
  offerTampered[0] ^= 0xff
  const controlTamperedOffer = derivePeerAdjacencyKeys(secret, offerTampered, accept, 0)
  t.absent(b4a.equals(controlKeys.forwardKey, controlTamperedOffer.forwardKey))

  // Verify sensitivity to accept change
  const acceptTampered = sequence(0x20, 285)
  acceptTampered[0] ^= 0xff
  const controlTamperedAccept = derivePeerAdjacencyKeys(secret, offer, acceptTampered, 0)
  t.absent(b4a.equals(controlKeys.forwardKey, controlTamperedAccept.forwardKey))

  // Verify scalar0 and scalar2 (version 2 wire) material never equals version 3 keys
  const scalar0Control = referenceAdjacencyKeys(secret, offer, accept, 0, 0)
  t.absent(b4a.equals(controlKeys.forwardKey, scalar0Control.forwardKey))
  const scalar2Control = referenceAdjacencyKeys(secret, offer, accept, 0, 2)
  t.absent(b4a.equals(controlKeys.forwardKey, scalar2Control.forwardKey))

  clearPeerAdjacencyKeys(controlKeys)
  clearPeerAdjacencyKeys(datagramKeys)
})

test('v3 adjacency KDF rejects zero shared secret, wrong widths, non-adjacency classes, and erases partial outputs on late failure', (t) => {
  const secret = sequence(0x01, 32)
  const offer = sequence(0x10, 432)
  const accept = sequence(0x20, 285)
  const zeroSecret = b4a.alloc(32, 0)

  expectCode(t, () => derivePeerAdjacencyKeys(zeroSecret, offer, accept, 0), 'INVALID_KEY')
  expectCode(t, () => derivePeerAdjacencyKeys(b4a.alloc(31), offer, accept, 0), 'INVALID_KEY')
  expectCode(t, () => derivePeerAdjacencyKeys(secret, b4a.alloc(431), accept, 0), 'INVALID_ROUTE')
  expectCode(t, () => derivePeerAdjacencyKeys(secret, offer, b4a.alloc(284), 0), 'INVALID_ROUTE')
  expectCode(t, () => derivePeerAdjacencyKeys(secret, offer, accept, 1), 'INVALID_ROUTE')
  expectCode(t, () => derivePeerAdjacencyKeys(secret, offer, accept, 3), 'INVALID_ROUTE')
  expectCode(
    t,
    () => createPeerAdjacencyTranscript(b4a.alloc(432), b4a.alloc(285), 1),
    'INVALID_ROUTE'
  )

  // Late derivation failure erasure test
  const originalFinal = sodium.crypto_generichash_final
  const outputs = []
  const failure = new Error('injected derivation failure')
  let caught = null
  sodium.crypto_generichash_final = function (state, output) {
    originalFinal(state, output)
    outputs.push(output)
    if (outputs.length === 3) throw failure
  }
  try {
    derivePeerAdjacencyKeys(secret, offer, accept, 0)
  } catch (err) {
    caught = err
  } finally {
    sodium.crypto_generichash_final = originalFinal
  }
  t.is(caught, failure)
  t.is(outputs.length, 3)
  for (const out of outputs) {
    t.ok(allZero(out), 'partial output is erased on failure')
  }
})

function purposeFixture() {
  const offerBody = sequence(0x20, 212)
  const offerHeaderBody = b4a.alloc(220)
  offerHeaderBody[0] = 0
  offerHeaderBody[1] = 0
  offerHeaderBody[2] = 0
  offerHeaderBody[3] = PEER_PROTOCOL_VERSION
  offerHeaderBody[4] = 0x03
  offerHeaderBody[5] = 0x11
  offerHeaderBody[6] = 0
  offerHeaderBody[7] = 212
  offerHeaderBody.set(offerBody, 8)

  const acceptBody = sequence(0x40, 260)
  const acceptHeaderBody = b4a.alloc(268)
  acceptHeaderBody[0] = 0
  acceptHeaderBody[1] = 0
  acceptHeaderBody[2] = 0
  acceptHeaderBody[3] = PEER_PROTOCOL_VERSION
  acceptHeaderBody[4] = 0x03
  acceptHeaderBody[5] = 0x12
  acceptHeaderBody[6] = 1
  acceptHeaderBody[7] = 4
  acceptHeaderBody.set(acceptBody, 8)

  const preFields = {
    tailControlTranscriptDigest: sequence(0x01, 32),
    terminalAdvertisementDigest: sequence(0x21, 32),
    queryNonce: sequence(0x41, 32),
    clientEphemeralPublicKey: sequence(0x61, 32),
    terminalRoutePublicKey: sequence(0x81, 32),
    offerBody
  }
  const preTranscript = createPeerPurposePreTranscript(preFields)
  const sharedSecret = sequence(0xa1, 32)
  const preSourceMacKey = derivePeerKey(
    sharedSecret,
    'hyperdht-private-routes/kdf/v2/peer-route/pre/source-mac',
    preTranscript
  ).subarray(0, 16)
  const preTerminalMacKey = derivePeerKey(
    sharedSecret,
    'hyperdht-private-routes/kdf/v2/peer-route/pre/terminal-mac',
    preTranscript
  ).subarray(0, 16)
  const offerMac = computePeerPurposeMac(preSourceMacKey, offerHeaderBody)
  const completeOffer = b4a.concat([offerHeaderBody, offerMac])
  const acceptMac = computePeerPurposeMac(preTerminalMacKey, acceptHeaderBody)
  const completeAccept = b4a.concat([acceptHeaderBody, acceptMac])
  const purposeTranscript = createPeerPurposeTranscript(preTranscript, completeOffer, acceptBody)

  return {
    offerBody,
    offerHeaderBody,
    completeOffer,
    acceptBody,
    acceptHeaderBody,
    completeAccept,
    preTranscript,
    purposeTranscript,
    sharedSecret
  }
}

test('v3 purpose transcript, MACs, agreement, and route KDFs match independent framing', (t) => {
  const fixture = purposeFixture()
  const expectedPre = b4a.concat([
    uint16(Buffer.byteLength('hyperdht-private-routes/m3/peer-route-prepurpose/v2')),
    b4a.from('hyperdht-private-routes/m3/peer-route-prepurpose/v2'),
    uint32(PEER_PROTOCOL_VERSION),
    sequence(0x01, 32),
    sequence(0x21, 32),
    sequence(0x41, 32),
    sequence(0x61, 32),
    sequence(0x81, 32),
    fixture.offerBody
  ])
  t.alike(fixture.preTranscript, expectedPre)
  t.alike(
    fixture.purposeTranscript,
    b4a.concat([fixture.preTranscript, fixture.completeOffer, fixture.acceptBody])
  )

  t.ok(
    verifyPeerPurposeMac(
      derivePeerKey(
        fixture.sharedSecret,
        'hyperdht-private-routes/kdf/v2/peer-route/pre/source-mac',
        fixture.preTranscript
      ).subarray(0, 16),
      fixture.offerHeaderBody,
      fixture.completeOffer.subarray(-16)
    )
  )
  t.ok(
    verifyPeerPurposeMac(
      derivePeerKey(
        fixture.sharedSecret,
        'hyperdht-private-routes/kdf/v2/peer-route/pre/terminal-mac',
        fixture.preTranscript
      ).subarray(0, 16),
      fixture.acceptHeaderBody,
      fixture.completeAccept.subarray(-16)
    )
  )

  const rejectHeaderBody = b4a.alloc(72)
  rejectHeaderBody.set(uint32(PEER_PROTOCOL_VERSION), 0)
  rejectHeaderBody[4] = 0x03
  rejectHeaderBody[5] = 0x13
  rejectHeaderBody[6] = 0
  rejectHeaderBody[7] = 64
  rejectHeaderBody.set(sequence(0x60, 64), 8)
  const rejectKeyMaterial = derivePeerKey(
    fixture.sharedSecret,
    'hyperdht-private-routes/kdf/v2/peer-route/pre/terminal-mac',
    fixture.preTranscript
  )
  const rejectKey = rejectKeyMaterial.subarray(0, 16)
  const rejectMac = computePeerPurposeMac(rejectKey, rejectHeaderBody)
  t.ok(verifyPeerPurposeMac(rejectKey, rejectHeaderBody, rejectMac))
  rejectMac.fill(0)
  rejectKeyMaterial.fill(0)
  rejectHeaderBody.fill(0)

  const keys = derivePeerPurposeKeys(
    fixture.sharedSecret,
    fixture.preTranscript,
    fixture.purposeTranscript
  )
  const expectedForward = derivePeerKey(
    fixture.sharedSecret,
    'hyperdht-private-routes/kdf/v2/peer-route/forward-key',
    fixture.purposeTranscript
  )
  const expectedReverse = derivePeerKey(
    fixture.sharedSecret,
    'hyperdht-private-routes/kdf/v2/peer-route/reverse-key',
    fixture.purposeTranscript
  )
  t.alike(keys.forwardKey, expectedForward)
  t.alike(keys.preSourceMacKey, b4a.from('6e36b6bfb94da6806d3fe2f3252c4c17', 'hex'))
  t.alike(keys.preTerminalMacKey, b4a.from('bc3f9d0a72aef77ce66d8c38ac02a3b6', 'hex'))
  t.alike(
    keys.forwardKey,
    b4a.from('969fcb1fe4326ae2025924c28303bcb819a80f19dd3e698ace6c7a267a73247e', 'hex')
  )
  t.alike(
    keys.reverseKey,
    b4a.from('bfe074ade0b2b6905d0ec2e14586d62ef25d87db5c201a50b39980e4704513f2', 'hex')
  )
  t.alike(keys.forwardNoncePrefix, b4a.from('5b2bf5a34fb72b18405105e44b8e84c0', 'hex'))
  t.alike(keys.reverseNoncePrefix, b4a.from('8c5651195d6717482182133523155f71', 'hex'))
  t.alike(keys.reverseKey, expectedReverse)
  t.alike(
    keys.preSourceMacKey,
    derivePeerKey(
      fixture.sharedSecret,
      'hyperdht-private-routes/kdf/v2/peer-route/pre/source-mac',
      fixture.preTranscript
    ).subarray(0, 16)
  )
  t.is(keys.forwardNoncePrefix.byteLength, 16)
  t.is(keys.reverseNoncePrefix.byteLength, 16)
  t.unlike(keys.preSourceMacKey, keys.preTerminalMacKey)
  t.unlike(keys.forwardKey, keys.reverseKey)

  clearPeerPurposeKeys(keys)
  t.ok(allZero(keys.forwardKey))
  t.ok(allZero(keys.preSourceMacKey))
})

test('v3 purpose agreement rejects low-order inputs and MAC forgery', (t) => {
  const alicePublic = b4a.alloc(32)
  const aliceSecret = b4a.alloc(32)
  const bobPublic = b4a.alloc(32)
  const bobSecret = b4a.alloc(32)
  sodium.crypto_box_seed_keypair(alicePublic, aliceSecret, sequence(0x11, 32))
  sodium.crypto_box_seed_keypair(bobPublic, bobSecret, sequence(0x51, 32))

  const aliceShared = derivePeerPurposeSharedSecret(aliceSecret, bobPublic)
  const bobShared = derivePeerPurposeSharedSecret(bobSecret, alicePublic)
  t.alike(aliceShared, bobShared)
  t.absent(allZero(aliceShared))

  expectCode(t, () => derivePeerPurposeSharedSecret(aliceSecret, b4a.alloc(32)), 'INVALID_KEY')
  expectCode(t, () => derivePeerPurposeSharedSecret(b4a.alloc(31), bobPublic), 'INVALID_KEY')

  const originalScalarmult = sodium.crypto_scalarmult
  sodium.crypto_scalarmult = () => false
  try {
    expectCode(t, () => derivePeerPurposeSharedSecret(aliceSecret, bobPublic), 'INVALID_KEY')
  } finally {
    sodium.crypto_scalarmult = originalScalarmult
  }

  const fixture = purposeFixture()
  const sourceKey = derivePeerKey(
    fixture.sharedSecret,
    'hyperdht-private-routes/kdf/v2/peer-route/pre/source-mac',
    fixture.preTranscript
  ).subarray(0, 16)
  const forged = b4a.from(fixture.completeOffer.subarray(-16))
  forged[0] ^= 1
  t.absent(verifyPeerPurposeMac(sourceKey, fixture.offerHeaderBody, forged))
  expectCode(t, () => computePeerPurposeMac(sourceKey, b4a.alloc(8)), 'INVALID_ROUTE')
})

test('v3 purpose and final digests bind every negotiated field and direction', (t) => {
  const fixture = purposeFixture()
  const digestFields = {
    tailControlTranscriptDigest: sequence(0x01, 32),
    terminalAdvertisementDigest: sequence(0x21, 32),
    routeId: sequence(0x10, 16),
    circuitId: sequence(0x20, 16),
    generation: 3n,
    purpose: 2,
    sourceDirection: 0,
    offerDigest: digestPeerPurposeOffer(fixture.completeOffer),
    acceptDigest: digestPeerPurposeAccept(fixture.completeAccept),
    admittedForwardCells: 11,
    admittedForwardBytes: 12000n,
    admittedForwardCommands: 13,
    admittedReverseCells: 17,
    admittedReverseBytes: 18000n,
    admittedReverseCommands: 19,
    admittedMaxStreams: 2,
    admittedReceiveFrames: 23,
    admittedReceiveBytes: 24000,
    admittedSemanticOwnedBytes: 25000,
    admittedMaxQueuedBytes: 26000,
    offerNonce: sequence(0x60, 16),
    acceptNonce: sequence(0x70, 16)
  }
  const purposeDigest = createPeerPurposeDigest(digestFields)
  t.alike(
    digestFields.offerDigest,
    b4a.from('fad093d437101d2ad4d39b807270912e74e70eb02f4d3e16c254d124d67b96ac', 'hex')
  )
  t.alike(
    digestFields.acceptDigest,
    b4a.from('8a8918a08617ba1a9f5681f67180809f66d3dfe59394fabdc4688802fbb76c18', 'hex')
  )
  const changed = createPeerPurposeDigest({
    ...digestFields,
    admittedReverseBytes: digestFields.admittedReverseBytes + 1n
  })
  t.unlike(purposeDigest, changed)
  t.alike(
    purposeDigest,
    b4a.from('dff13a2d50b1d4271bcc6bdb756c89bc832f197d0da743e55a6b0680bcdab60a', 'hex')
  )

  const sourceBody = sequence(0x91, 64)
  const terminalBody = sequence(0x91, 64)
  const sourceConfirmDigest = digestPeerPurposeConfirmation('source', sourceBody)
  const terminalConfirmDigest = digestPeerPurposeConfirmation('terminal', terminalBody)
  t.unlike(sourceConfirmDigest, terminalConfirmDigest)
  t.alike(
    sourceConfirmDigest,
    b4a.from('1e6051cbb098f255192fcbe13310323fb9b77c2cc82883fcbdae279d69f3392e', 'hex')
  )
  t.alike(
    terminalConfirmDigest,
    b4a.from('49c3b11522c6bcbc95c4e82136951432fb8b8130d4395d23226e498507d5cda5', 'hex')
  )
  const finalDigest = createPeerPurposeFinalTranscript({
    tailControlTranscriptDigest: digestFields.tailControlTranscriptDigest,
    purposeDigest,
    offerDigest: digestFields.offerDigest,
    acceptDigest: digestFields.acceptDigest,
    sourceConfirmDigest,
    terminalConfirmDigest
  })
  t.alike(
    finalDigest,
    b4a.from('e17f0aae747c2b20ec8bd5f3be56c7f3fe75be19a3f39e5c3cc5d87c41cbb2c0', 'hex')
  )
  t.unlike(
    finalDigest,
    createPeerPurposeFinalTranscript({
      tailControlTranscriptDigest: digestFields.tailControlTranscriptDigest,
      purposeDigest: changed,
      offerDigest: digestFields.offerDigest,
      acceptDigest: digestFields.acceptDigest,
      sourceConfirmDigest,
      terminalConfirmDigest
    })
  )
})

function x25519KeyPair(seedByte) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(32, seedByte)
  sodium.crypto_scalarmult_base(publicKey, secretKey)
  return { publicKey, secretKey }
}

function x25519(secretKey, publicKey) {
  const output = b4a.alloc(32)
  sodium.crypto_scalarmult(output, secretKey, publicKey)
  return output
}

function differingBytes(left, right) {
  let count = 0
  for (let index = 0; index < left.byteLength; index++) {
    if (left[index] !== right[index]) count++
  }
  return count
}

function referenceLayerRound(block, roundKey, kind) {
  const left = block.subarray(0, 32)
  const right = block.subarray(32)
  if (kind === 'stream') {
    const streamKey = b4a.alloc(32)
    for (let index = 0; index < 32; index++) streamKey[index] = left[index] ^ roundKey[index]
    const keystream = b4a.alloc(right.byteLength)
    sodium.crypto_stream_xchacha20(keystream, b4a.alloc(24), streamKey)
    for (let index = 0; index < right.byteLength; index++) right[index] ^= keystream[index]
  } else {
    const digest = b4a.alloc(32)
    sodium.crypto_generichash(digest, right, roundKey)
    for (let index = 0; index < 32; index++) left[index] ^= digest[index]
  }
}

function referenceSealLayer(roundKeys, input) {
  const block = b4a.from(input)
  referenceLayerRound(block, roundKeys[0], 'stream')
  referenceLayerRound(block, roundKeys[1], 'hash')
  referenceLayerRound(block, roundKeys[2], 'stream')
  referenceLayerRound(block, roundKeys[3], 'hash')
  return block
}

test('v3 tail secret binds the static agreement, the responder ephemeral agreement, and its public key', (t) => {
  const staticShared = b4a.alloc(32, 0x21)
  const ephemeralShared = b4a.alloc(32, 0x22)
  const responderEphemeral = b4a.alloc(32, 0x23)
  const expected = referenceDerivePeerKey(
    staticShared,
    'hyperdht-private-routes/kdf/v3/tail-secret',
    b4a.concat([ephemeralShared, responderEphemeral])
  )
  const combined = combinePeerTailSecret(staticShared, ephemeralShared, responderEphemeral)
  t.alike(combined, expected)
  t.alike(
    combined,
    b4a.from('bbb676d5e1bbfb71f8eab433986e8af47babad08dc46127ac6e7ab90ed89a332', 'hex')
  )

  // Both ends compute the same secret from their own secrets.
  const client = x25519KeyPair(0x31)
  const route = x25519KeyPair(0x32)
  const responder = x25519KeyPair(0x33)
  const sourceSide = combinePeerTailSecret(
    x25519(client.secretKey, route.publicKey),
    x25519(client.secretKey, responder.publicKey),
    responder.publicKey
  )
  const relaySide = combinePeerTailSecret(
    x25519(route.secretKey, client.publicKey),
    x25519(responder.secretKey, client.publicKey),
    responder.publicKey
  )
  t.alike(sourceSide, relaySide)

  // A party holding the route secret and the recorded public values, but not the
  // erased responder ephemeral, cannot reproduce the secret.
  const withoutEphemeral = combinePeerTailSecret(
    x25519(route.secretKey, client.publicKey),
    x25519(route.secretKey, responder.publicKey),
    responder.publicKey
  )
  t.unlike(withoutEphemeral, sourceSide)

  const otherResponder = x25519KeyPair(0x34)
  t.unlike(
    combinePeerTailSecret(
      x25519(client.secretKey, route.publicKey),
      x25519(client.secretKey, otherResponder.publicKey),
      otherResponder.publicKey
    ),
    sourceSide
  )
  t.unlike(
    combinePeerTailSecret(staticShared, ephemeralShared, b4a.alloc(32, 0x24)),
    combined,
    'the responder public key is bound even with equal agreements'
  )

  expectCode(
    t,
    () => combinePeerTailSecret(b4a.alloc(32), ephemeralShared, responderEphemeral),
    'INVALID_KEY'
  )
  expectCode(
    t,
    () => combinePeerTailSecret(staticShared, b4a.alloc(32), responderEphemeral),
    'INVALID_KEY'
  )
  expectCode(
    t,
    () => combinePeerTailSecret(staticShared, ephemeralShared, b4a.alloc(32)),
    'INVALID_KEY'
  )
  expectCode(
    t,
    () => combinePeerTailSecret(staticShared, ephemeralShared, b4a.alloc(31, 1)),
    'INVALID_KEY'
  )
})

test('v3 adjacency header derives one epoch and four counter origins per link from an independent reference', (t) => {
  const secret = sequence(0x01, 32)
  const offer = sequence(0x10, 432)
  const accept = sequence(0x20, 285)
  const transcript = b4a.concat([
    referenceHashPeer('hyperdht-private-routes/m3/link-offer-digest/v2', [offer]),
    referenceHashPeer('hyperdht-private-routes/m3/link-accept-digest/v2', [accept])
  ])
  const epochOutput = referenceDerivePeerKey(
    secret,
    'hyperdht-private-routes/kdf/v3/link-epoch',
    transcript
  )
  const originOutput = referenceDerivePeerKey(
    secret,
    'hyperdht-private-routes/kdf/v3/counter-origin',
    transcript
  )

  const header = derivePeerAdjacencyHeader(secret, offer, accept)
  t.is(header.epoch, epochOutput.readBigUInt64BE(0))
  t.is(header.origins[0].forward, BigInt(originOutput.readUInt32BE(0)))
  t.is(header.origins[0].reverse, BigInt(originOutput.readUInt32BE(4)))
  t.is(header.origins[2].forward, BigInt(originOutput.readUInt32BE(8)))
  t.is(header.origins[2].reverse, BigInt(originOutput.readUInt32BE(12)))
  t.is(header.epoch, 0x5235aecc6fe5a2c0n)
  t.alike(
    [
      header.origins[0].forward,
      header.origins[0].reverse,
      header.origins[2].forward,
      header.origins[2].reverse
    ],
    [37187354n, 995430871n, 1448339244n, 1087487158n]
  )

  // Another link differs in every header value, so no clear value repeats across hops.
  const otherOffer = sequence(0x11, 432)
  const other = derivePeerAdjacencyHeader(secret, otherOffer, accept)
  t.not(other.epoch, header.epoch)
  for (const cellClass of [0, 2]) {
    t.not(other.origins[cellClass].forward, header.origins[cellClass].forward)
    t.not(other.origins[cellClass].reverse, header.origins[cellClass].reverse)
  }

  expectCode(t, () => derivePeerAdjacencyHeader(b4a.alloc(32), offer, accept), 'INVALID_KEY')
  expectCode(t, () => derivePeerAdjacencyHeader(secret, b4a.alloc(431), accept), 'INVALID_ROUTE')
  expectCode(t, () => derivePeerAdjacencyHeader(secret, offer, b4a.alloc(284)), 'INVALID_ROUTE')
})

test('v3 layer keys and wide-block layer transform match an independent reference', (t) => {
  const transcript = createPeerTailTranscript(TAIL_FIELDS)
  const secret = b4a.alloc(32, 0x0c)
  const keys = derivePeerLayerKeys(secret, transcript)
  const labels = []
  for (const direction of ['forward', 'reverse']) {
    for (let round = 1; round <= 4; round++) {
      labels.push(`hyperdht-private-routes/kdf/v3/layer/${direction}/${round}`)
    }
  }
  const derived = [...keys.forward, ...keys.reverse]
  t.is(derived.length, 8)
  for (let index = 0; index < 8; index++) {
    t.alike(derived[index], referenceDerivePeerKey(secret, labels[index], transcript))
  }
  t.is(new Set(derived.map((key) => b4a.toString(key, 'hex'))).size, 8, 'eight distinct keys')
  t.alike(
    keys.forward[0],
    b4a.from('756c924a744c32c956fc0ffe32cbefe9f7f096d193b7579e0572b79aa52c00dd', 'hex')
  )

  t.is(PEER_LAYER_BLOCK_SIZE, 1101)
  const plain = sequence(0x00, PEER_LAYER_BLOCK_SIZE)
  const sealed = sealPeerLayer(keys.forward, b4a.from(plain))
  t.alike(sealed, referenceSealLayer(keys.forward, plain))
  t.alike(
    sealed.subarray(0, 48),
    b4a.from(
      'b029b909e54c7052ec23d6381f49eb9a9f97d92e01f98bb3b26e4ffa07a9890b4f431e5402d6129e98e4b9800ce7d49c',
      'hex'
    )
  )
  t.alike(openPeerLayer(keys.forward, b4a.from(sealed)), plain, 'round trip')
  t.ok(differingBytes(sealed, plain) > 1000, 'every region of the envelope changes')

  // One flipped input bit changes the whole output.
  const flippedInput = b4a.from(plain)
  flippedInput[600] ^= 1
  t.ok(differingBytes(sealPeerLayer(keys.forward, flippedInput), sealed) > 1000)

  // A modified sealed block opens to unrelated bytes, not to a recognisable mark.
  const tampered = b4a.from(sealed)
  tampered[1000] ^= 0x80
  const opened = openPeerLayer(keys.forward, tampered)
  t.ok(differingBytes(opened, plain) > 1000, 'tampering is not a controllable change')

  // Two hops' layers over the same envelope are unrelated.
  const otherKeys = derivePeerLayerKeys(b4a.alloc(32, 0x0d), transcript)
  t.ok(differingBytes(sealPeerLayer(otherKeys.forward, b4a.from(plain)), sealed) > 1000)
  t.ok(differingBytes(sealPeerLayer(keys.reverse, b4a.from(plain)), sealed) > 1000)

  expectCode(t, () => sealPeerLayer(keys.forward, b4a.alloc(1100)), 'INVALID_ROUTE')
  expectCode(t, () => openPeerLayer(keys.forward.slice(0, 3), b4a.alloc(1101)), 'INVALID_ROUTE')
  expectCode(t, () => derivePeerLayerKeys(b4a.alloc(32), transcript), 'INVALID_KEY')
  expectCode(t, () => derivePeerLayerKeys(secret, b4a.alloc(289)), 'INVALID_ROUTE')

  clearPeerLayerKeys(keys)
  t.ok(
    [...keys.forward, ...keys.reverse].every((key) => allZero(key)),
    'layer keys erase'
  )
})

test('v3 source layer stacks lose one layer per forwarder and give every link its own view', (t) => {
  const transcript = createPeerTailTranscript(TAIL_FIELDS)
  const guard = derivePeerLayerKeys(b4a.alloc(32, 0x41), transcript)
  const safety = derivePeerLayerKeys(b4a.alloc(32, 0x42), transcript)
  const stack = [guard, safety]
  const envelope = sequence(0x10, PEER_LAYER_BLOCK_SIZE)
  const distinct = (views, label) => {
    for (let a = 0; a < views.length; a++) {
      for (let b = a + 1; b < views.length; b++) {
        t.ok(differingBytes(views[a], views[b]) > 1000, `${label} views ${a} and ${b} differ`)
      }
    }
  }

  // Forward: the source wraps once; each forwarder removes exactly its own layer.
  const sourceToGuard = sealPeerSourceLayers(stack, b4a.from(envelope))
  const guardToSafety = openPeerLayer(guard.forward, b4a.from(sourceToGuard))
  const safetyToTerminal = openPeerLayer(safety.forward, b4a.from(guardToSafety))
  t.alike(safetyToTerminal, envelope, 'the terminal receives the envelope the source sealed')
  distinct([sourceToGuard, guardToSafety, safetyToTerminal], 'forward')

  // Reverse: each forwarder adds its layer; the source removes them guard first.
  const safetyToGuard = sealPeerLayer(safety.reverse, b4a.from(envelope))
  const guardToSource = sealPeerLayer(guard.reverse, b4a.from(safetyToGuard))
  t.alike(openPeerSourceLayers(stack, b4a.from(guardToSource)), envelope, 'reverse round trip')
  distinct([envelope, safetyToGuard, guardToSource], 'reverse')
  t.ok(differingBytes(guardToSource, sourceToGuard) > 1000, 'directions differ on one link')

  // A frame the safety sends itself carries only the guard's layer: removing both layers
  // gives noise, never a readable frame.
  const safetyOwn = sealPeerLayer(guard.reverse, b4a.from(envelope))
  t.ok(differingBytes(openPeerSourceLayers(stack, b4a.from(safetyOwn)), envelope) > 1000)

  // Before any extension the guard is the tail and the stack is empty.
  t.alike(sealPeerSourceLayers([], b4a.from(envelope)), envelope)
  t.alike(openPeerSourceLayers([], b4a.from(envelope)), envelope)
  expectCode(t, () => sealPeerSourceLayers(null, b4a.from(envelope)), 'INVALID_ROUTE')
  expectCode(t, () => openPeerSourceLayers(stack, b4a.alloc(1100)), 'INVALID_ROUTE')
  clearPeerLayerKeys(guard)
  clearPeerLayerKeys(safety)
})

test('v3 tail agreement runs both agreements under caller custody and erases them', (t) => {
  const client = x25519KeyPair(0x51)
  const route = x25519KeyPair(0x52)
  const responder = x25519KeyPair(0x53)
  let staticShared = null
  let ephemeralShared = null
  const secret = agreePeerTailSecret(
    () => (staticShared = x25519(client.secretKey, route.publicKey)),
    () => (ephemeralShared = x25519(client.secretKey, responder.publicKey)),
    responder.publicKey
  )
  t.alike(
    secret,
    combinePeerTailSecret(
      x25519(route.secretKey, client.publicKey),
      x25519(responder.secretKey, client.publicKey),
      responder.publicKey
    ),
    'the relay side, using its own secrets, derives the same tail secret'
  )
  t.ok(allZero(staticShared) && allZero(ephemeralShared), 'both agreements are erased')

  let first = null
  expectCode(
    t,
    () =>
      agreePeerTailSecret(
        () => (first = x25519(client.secretKey, route.publicKey)),
        () => {
          throw PrivateRouteError.INVALID_KEY()
        },
        responder.publicKey
      ),
    'INVALID_KEY'
  )
  t.ok(allZero(first), 'a failed second agreement still erases the first')
  expectCode(t, () => agreePeerTailSecret(null, () => null, responder.publicKey), 'INVALID_ROUTE')
})

test('v3 purpose terminal key pair derives from the final tail secret and agrees under X25519', (t) => {
  const transcript = createPeerTailTranscript(TAIL_FIELDS)
  const secret = b4a.alloc(32, 0x0c)
  const pair = derivePeerPurposeTerminalKeyPair(secret, transcript)
  t.alike(
    pair.secretKey,
    referenceDerivePeerKey(
      secret,
      'hyperdht-private-routes/kdf/v3/peer-route/terminal-key',
      transcript
    )
  )
  const expectedPublic = b4a.alloc(32)
  sodium.crypto_scalarmult_base(expectedPublic, pair.secretKey)
  t.alike(pair.publicKey, expectedPublic)
  t.alike(
    pair.publicKey,
    b4a.from('1b6f081f4183f011099d45c752d1eacffd261e9ea23f4ff1bc2f1cac528eab4e', 'hex')
  )

  const client = x25519KeyPair(0x41)
  t.alike(
    derivePeerPurposeSharedSecret(client.secretKey, pair.publicKey),
    derivePeerPurposeSharedSecret(pair.secretKey, client.publicKey),
    'source and terminal reach the same purpose agreement'
  )
  const otherTail = derivePeerPurposeTerminalKeyPair(b4a.alloc(32, 0x0d), transcript)
  t.unlike(otherTail.publicKey, pair.publicKey)

  expectCode(t, () => derivePeerPurposeTerminalKeyPair(b4a.alloc(32), transcript), 'INVALID_KEY')
  expectCode(t, () => derivePeerPurposeTerminalKeyPair(secret, b4a.alloc(290 - 1)), 'INVALID_ROUTE')
})
