'use strict'

const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-universal')
const { PrivateRouteError } = require('../../lib/private/errors')

const {
  hashPeer,
  derivePeerKey,
  digestPeerLimits,
  createPeerTailTranscript,
  derivePeerTailKeys,
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
  '0000000204b0000003e900124f810000001500001388000001d1a94a200104b0000003ea00124f820000001600001388000001d1a94a20020303030303030303030303030303030303030303030303030303030303030303',
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
    uint32(2),
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

test('v2 tail transcript, limits digest, and eight KDF labels freeze vectors', (t) => {
  const expectedLimitsDigest = b4a.from(
    'ad0ea505115f3f93c0997d090ab23f43434ef367393d3ae69d877adc7652d5e8',
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
    b4a.from('f158224e74734e8be5175f6ffe1e180962f40aa7d53174ffe1dc60d4bc1b401d', 'hex')
  )

  const keys = derivePeerTailKeys(b4a.alloc(32, 0x0c), transcript)
  const expected = {
    tailControlForwardKey: 'a61e4ed99877699833f6f0afa35b7a13012a660c6417ee3dff910a1e3c5ce9d9',
    tailControlReverseKey: '995d929cd27c297e1e4059130aad72e0a8cc76cbce5dba17f6f5b8f76d15790f',
    tailControlForwardNoncePrefix: '6d4cb3a68abb51204a3d0edb017b7fdd',
    tailControlReverseNoncePrefix: 'fb29994fd3c5b9d6c70adfd24b64dfae',
    finalizeForwardKey: '2fa2c353e2e8d9aecd54451a420181f7e7453989c1f2474d5ce3d3e0114b5169',
    finalizeReverseKey: 'c412cf148ebe85c60cc2eb157ce6cef899199ad97c28dfac0d1f5fbc7ee01c29',
    finalizeForwardNoncePrefix: '2d6fff80ca66b45febc47bfeb04d80d8',
    finalizeReverseNoncePrefix: 'ad2b084cbda9203cfb7b801dba5eecb7'
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

test('derivePeerKey uses the exact v2 framing and independent output32', (t) => {
  const sharedSecret = b4a.alloc(32, 0x31)
  const label = 'peer-test-kdf/v2'
  const transcript = b4a.from('exact transcript bytes')
  const expectedInput = b4a.concat([
    uint16(Buffer.byteLength(label)),
    b4a.from(label),
    uint32(2),
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
    uint32(2),
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
  expectCode(t, () => derivePeerTailKeys(b4a.alloc(32), b4a.alloc(289)), 'INVALID_ROUTE')
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

function referenceDerivePeerKey(sharedSecret, label, transcript, protocolVersion = 2) {
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
  protocolVersion = 2
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

test('v2 adjacency KDF derives 8 distinct outputs across CONTROL0 and DATAGRAM2 and matches independent reference', (t) => {
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

  // Verify scalar0 / protocol version mismatch
  const scalar0Control = referenceAdjacencyKeys(secret, offer, accept, 0, 0)
  t.absent(b4a.equals(controlKeys.forwardKey, scalar0Control.forwardKey))

  clearPeerAdjacencyKeys(controlKeys)
  clearPeerAdjacencyKeys(datagramKeys)
})

test('v2 adjacency KDF rejects zero shared secret, wrong widths, non-adjacency classes, and erases partial outputs on late failure', (t) => {
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
  offerHeaderBody[3] = 2
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
  acceptHeaderBody[3] = 2
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

test('v2 purpose transcript, MACs, agreement, and route KDFs match independent framing', (t) => {
  const fixture = purposeFixture()
  const expectedPre = b4a.concat([
    uint16(Buffer.byteLength('hyperdht-private-routes/m3/peer-route-prepurpose/v2')),
    b4a.from('hyperdht-private-routes/m3/peer-route-prepurpose/v2'),
    uint32(2),
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
  rejectHeaderBody.set(uint32(2), 0)
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
  t.alike(keys.preSourceMacKey, b4a.from('b6b47d6e1decbee8bd245159a9839098', 'hex'))
  t.alike(keys.preTerminalMacKey, b4a.from('fca4b5f20b27a180e18624234859fe22', 'hex'))
  t.alike(
    keys.forwardKey,
    b4a.from('f013048edbf4bb121167b9768320b5f5dc5b01dad902195aa14edea12807dc5b', 'hex')
  )
  t.alike(
    keys.reverseKey,
    b4a.from('bedf0810f498277863cb2ed3c0a381377a7b89ee9a0ab213120f99e087c338ea', 'hex')
  )
  t.alike(keys.forwardNoncePrefix, b4a.from('bcfef037702da0f74f5ddf48bb9efd6f', 'hex'))
  t.alike(keys.reverseNoncePrefix, b4a.from('fd220087ff3d9ae37ecd7c33d6b526ee', 'hex'))
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

test('v2 purpose agreement rejects low-order inputs and MAC forgery', (t) => {
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

test('v2 purpose and final digests bind every negotiated field and direction', (t) => {
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
    b4a.from('fc128d276e5871c1e0a7351ad192db38be3d0a8d839a5a201e0f4adf35c63cf7', 'hex')
  )
  t.alike(
    digestFields.acceptDigest,
    b4a.from('1091e932c0a5f3afa6872b6bb78be2a7f0cecbfc988547daec78141a84633b0b', 'hex')
  )
  const changed = createPeerPurposeDigest({
    ...digestFields,
    admittedReverseBytes: digestFields.admittedReverseBytes + 1n
  })
  t.unlike(purposeDigest, changed)
  t.alike(
    purposeDigest,
    b4a.from('7129808f0223eb417786f67478ed204b3045d8dbf01c18c2a60e79608c6dd7ae', 'hex')
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
    b4a.from('57edc09c02cc467d18de3965875afdca2725c85b7b3ac85b3d9f45864f487006', 'hex')
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
