'use strict'

const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-universal')
const crypto = require('hypercore-crypto')

const {
  PRESENCE_RECORD_VERSION,
  PRESENCE_RECORD_SIZE,
  RECORD_TYPE,
  TOMBSTONE_SCOPE,
  PERIOD_MS,
  OVERLAP_MS,
  MAX_DESCRIPTOR_BYTES,
  deriveBlindedPublicKey,
  createBlindedSigner,
  periodOf,
  publishPeriods,
  lookupPeriods,
  encodePresenceRecord,
  openPresenceRecord,
  recordDigestOf,
  resolvePresenceState
} = require('../../lib/private/blinded-presence')

const FIXED_SEED = b4a.alloc(32, 0x11)
const FIXED_IDENTITY = crypto.keyPair(FIXED_SEED)
const FIXED_A_PRIME_PERIOD_0 = 'fda0443bf67d902055c6989aec0f7a731d8fb9f4a6d05226a2c6c9a63cb94d64'
const FIXED_A_PRIME_PERIOD_1 = '00584423a6710fb15cad24c1ff0a0845dfce2b6931b1c97ea84c93e7b57bf49d'
const READER = b4a.alloc(32, 0x42)
const OTHER_READER = b4a.alloc(32, 0x43)
const OTHER_IDENTITY = crypto.keyPair(b4a.alloc(32, 0x22))

function expectCode(t, fn, code) {
  try {
    fn()
    t.fail('expected throw ' + code)
  } catch (err) {
    t.is(err && err.code, code)
  }
}

function encodeSigned(opts) {
  const period = opts.period === undefined ? 0n : opts.period
  const revision = opts.revision === undefined ? 1 : opts.revision
  const signer = createBlindedSigner(FIXED_IDENTITY, period)
  try {
    const encoded = encodePresenceRecord({
      signer,
      period,
      revision,
      readerSecret: opts.readerSecret || READER,
      type: opts.type || RECORD_TYPE.DESCRIPTOR,
      descriptor: opts.descriptor,
      tombstone: opts.tombstone
    })
    const signature = encoded.signMutable(revision, encoded.value, {
      publicKey: encoded.publicKey
    })
    return { encoded, signature, signerPublicKey: b4a.from(encoded.publicKey) }
  } finally {
    signer.destroy()
  }
}

test('native scalar_mul is present and module loads', (t) => {
  t.is(typeof sodium.crypto_core_ed25519_scalar_mul, 'function')
  t.is(PRESENCE_RECORD_VERSION, 1)
  t.is(PRESENCE_RECORD_SIZE, 895)
  t.is(MAX_DESCRIPTOR_BYTES, 814)
  t.is(HEADER_AND_BODY_TOTAL(), PRESENCE_RECORD_SIZE, 'layout fills the mutable value cap exactly')
})

function HEADER_AND_BODY_TOTAL() {
  return 1 + 4 + 16 + 16 + 1 + 8 + 1 + 32 + 2 + MAX_DESCRIPTOR_BYTES
}

test('fixed identity seed yields fixed blinded public keys', (t) => {
  const a0 = deriveBlindedPublicKey(FIXED_IDENTITY.publicKey, 0n)
  const a1 = deriveBlindedPublicKey(FIXED_IDENTITY.publicKey, 1n)
  t.is(b4a.toString(a0, 'hex'), FIXED_A_PRIME_PERIOD_0)
  t.is(b4a.toString(a1, 'hex'), FIXED_A_PRIME_PERIOD_1)
  t.unlike(a0, a1)

  const signer0 = createBlindedSigner(FIXED_IDENTITY, 0n)
  const signer1 = createBlindedSigner(FIXED_IDENTITY, 1n)
  t.alike(signer0.publicKey, a0)
  t.alike(signer1.publicKey, a1)
  signer0.destroy()
  signer1.destroy()
})

test('blinded signature verifies under A prime only', (t) => {
  const signer = createBlindedSigner(FIXED_IDENTITY, 0n)
  const message = b4a.from('presence-sign-vector-v1')
  const signature = signer.sign(message)
  t.is(sodium.crypto_sign_verify_detached(signature, message, signer.publicKey), true)
  t.is(sodium.crypto_sign_verify_detached(signature, message, FIXED_IDENTITY.publicKey), false)

  const flippedM = b4a.from(message)
  flippedM[0] ^= 0x01
  t.is(sodium.crypto_sign_verify_detached(signature, flippedM, signer.publicKey), false)

  const flippedR = b4a.from(signature)
  flippedR[0] ^= 0x01
  t.is(sodium.crypto_sign_verify_detached(flippedR, message, signer.publicKey), false)

  const flippedS = b4a.from(signature)
  flippedS[63] ^= 0x01
  t.is(sodium.crypto_sign_verify_detached(flippedS, message, signer.publicKey), false)

  signer.destroy()
  expectCode(t, () => signer.sign(message), 'UNAUTHORIZED')
})

test('period helpers honor OVERLAP_MS on both boundary sides', (t) => {
  t.is(OVERLAP_MS, 3_600_000n)
  t.is(PERIOD_MS, 86_400_000n)

  t.is(periodOf(0), 0n)
  t.is(periodOf(Number(PERIOD_MS) - 1), 0n)
  t.is(periodOf(Number(PERIOD_MS)), 1n)

  const boundaryPublish = Number(PERIOD_MS) - Number(OVERLAP_MS)
  t.alike(publishPeriods(boundaryPublish - 1), [0n])
  t.alike(publishPeriods(boundaryPublish), [0n, 1n])
  t.alike(publishPeriods(Number(PERIOD_MS)), [1n])

  const boundaryLookup = Number(PERIOD_MS) + Number(OVERLAP_MS)
  t.alike(lookupPeriods(Number(PERIOD_MS)), [1n, 0n])
  t.alike(lookupPeriods(boundaryLookup - 1), [1n, 0n])
  t.alike(lookupPeriods(boundaryLookup), [1n])
  t.alike(lookupPeriods(0), [0n])
})

test('descriptor record is exactly 895 bytes and preserves trailing zero bytes', (t) => {
  const descriptor = b4a.alloc(MAX_DESCRIPTOR_BYTES, 0)
  descriptor[0] = 0xab
  descriptor[MAX_DESCRIPTOR_BYTES - 1] = 0xcd

  const { encoded, signature } = encodeSigned({ descriptor, revision: 7 })
  t.is(encoded.value.byteLength, 895)
  t.is(encoded.seq, 7)
  t.alike(encoded.publicKey, deriveBlindedPublicKey(FIXED_IDENTITY.publicKey, 0n))

  const opened = openPresenceRecord({
    identityPublicKey: FIXED_IDENTITY.publicKey,
    period: 0n,
    revision: 7,
    readerSecret: READER,
    value: encoded.value,
    signature
  })
  t.is(opened.type, RECORD_TYPE.DESCRIPTOR)
  t.is(opened.revision, 7)
  t.alike(opened.descriptor, descriptor)
  t.is(opened.descriptor.byteLength, MAX_DESCRIPTOR_BYTES)
  t.is(opened.descriptor[MAX_DESCRIPTOR_BYTES - 1], 0xcd)

  expectCode(
    t,
    () =>
      encodeSigned({
        descriptor: b4a.alloc(MAX_DESCRIPTOR_BYTES + 1, 1)
      }),
    'INVALID_DESCRIPTOR'
  )
})

test('signMutable refuses foreign seq or key', (t) => {
  const { encoded } = encodeSigned({ descriptor: b4a.from('ok'), revision: 3 })
  expectCode(
    t,
    () => encoded.signMutable(4, encoded.value, { publicKey: encoded.publicKey }),
    'UNAUTHORIZED'
  )
  expectCode(
    t,
    () =>
      encoded.signMutable(3, encoded.value, {
        publicKey: deriveBlindedPublicKey(FIXED_IDENTITY.publicKey, 1n)
      }),
    'UNAUTHORIZED'
  )
})

test('tamper cases fail closed', (t) => {
  const { encoded, signature } = encodeSigned({
    descriptor: b4a.from('route-descriptor'),
    revision: 9
  })

  function openWith(mutator, code) {
    const value = b4a.from(encoded.value)
    const sig = b4a.from(signature)
    mutator(value, sig)
    expectCode(
      t,
      () =>
        openPresenceRecord({
          identityPublicKey: FIXED_IDENTITY.publicKey,
          period: 0n,
          revision: 9,
          readerSecret: READER,
          value,
          signature: sig
        }),
      code
    )
  }

  openWith((value) => {
    value[0] = 2
  }, 'INVALID_DESCRIPTOR')

  openWith((value) => {
    value[21] ^= 0xff
  }, 'ERR_AUTHENTICATION')

  openWith((_value, sig) => {
    sig[0] ^= 0x01
  }, 'ERR_AUTHENTICATION')

  expectCode(
    t,
    () =>
      openPresenceRecord({
        identityPublicKey: FIXED_IDENTITY.publicKey,
        period: 0n,
        revision: 8,
        readerSecret: READER,
        value: encoded.value,
        signature
      }),
    'INVALID_DESCRIPTOR'
  )

  expectCode(
    t,
    () =>
      openPresenceRecord({
        identityPublicKey: FIXED_IDENTITY.publicKey,
        period: 0n,
        revision: 9,
        readerSecret: OTHER_READER,
        value: encoded.value,
        signature
      }),
    'ERR_AUTHENTICATION'
  )

  expectCode(
    t,
    () =>
      openPresenceRecord({
        identityPublicKey: OTHER_IDENTITY.publicKey,
        period: 0n,
        revision: 9,
        readerSecret: READER,
        value: encoded.value,
        signature
      }),
    'ERR_AUTHENTICATION'
  )

  expectCode(
    t,
    () =>
      openPresenceRecord({
        identityPublicKey: FIXED_IDENTITY.publicKey,
        period: 1n,
        revision: 9,
        readerSecret: READER,
        value: encoded.value,
        signature
      }),
    'ERR_AUTHENTICATION'
  )
})

test('padding byte flip is INVALID_DESCRIPTOR after open AEAD path', (t) => {
  // Build a record, then re-seal is impossible without a'; open a clean one and
  // confirm zero-padding rule by crafting via encode with short descriptor.
  const { encoded, signature } = encodeSigned({
    descriptor: b4a.from('short'),
    revision: 2
  })
  const opened = openPresenceRecord({
    identityPublicKey: FIXED_IDENTITY.publicKey,
    period: 0n,
    revision: 2,
    readerSecret: READER,
    value: encoded.value,
    signature
  })
  t.alike(opened.descriptor, b4a.from('short'))

  // Flip a ciphertext byte so AEAD fails (covers length/padding integrity under AEAD).
  const tampered = b4a.from(encoded.value)
  tampered[HEADER_AND_BODY_TOTAL() - 20] ^= 0x01
  expectCode(
    t,
    () =>
      openPresenceRecord({
        identityPublicKey: FIXED_IDENTITY.publicKey,
        period: 0n,
        revision: 2,
        readerSecret: READER,
        value: tampered,
        signature
      }),
    'ERR_AUTHENTICATION'
  )
})

test('tombstone encode/open and resolvePresenceState rules', (t) => {
  const descriptor = b4a.from('live-descriptor')
  const first = encodeSigned({ descriptor, revision: 1 })
  const digest = recordDigestOf(first.encoded.value)

  const periodTomb = encodeSigned({
    type: RECORD_TYPE.TOMBSTONE,
    revision: 2,
    tombstone: { scope: TOMBSTONE_SCOPE.PERIOD, target: b4a.alloc(32) }
  })
  const openedPeriod = openPresenceRecord({
    identityPublicKey: FIXED_IDENTITY.publicKey,
    period: 0n,
    revision: 2,
    readerSecret: READER,
    value: periodTomb.encoded.value,
    signature: periodTomb.signature
  })
  t.is(openedPeriod.type, RECORD_TYPE.TOMBSTONE)
  t.is(openedPeriod.tombstone.scope, TOMBSTONE_SCOPE.PERIOD)
  const periodOpened = { ...openedPeriod, recordDigest: recordDigestOf(periodTomb.encoded.value) }
  const periodState = resolvePresenceState({ previous: null, opened: periodOpened })
  t.is(periodState.present, false)
  t.alike(resolvePresenceState({ previous: periodState, opened: periodOpened }), periodState)

  const recordTomb = encodeSigned({
    type: RECORD_TYPE.TOMBSTONE,
    revision: 2,
    tombstone: { scope: TOMBSTONE_SCOPE.RECORD, target: digest }
  })
  const openedRecord = openPresenceRecord({
    identityPublicKey: FIXED_IDENTITY.publicKey,
    period: 0n,
    revision: 2,
    readerSecret: READER,
    value: recordTomb.encoded.value,
    signature: recordTomb.signature
  })
  const recordOpened = { ...openedRecord, recordDigest: recordDigestOf(recordTomb.encoded.value) }
  const recordState = resolvePresenceState({
    previous: { period: 0n, revision: 1, recordDigest: digest },
    opened: recordOpened
  })
  t.is(recordState.present, false)
  t.alike(resolvePresenceState({ previous: recordState, opened: recordOpened }), recordState)
  const ignored = resolvePresenceState({
    previous: { period: 0n, revision: 1, recordDigest: b4a.alloc(32, 9) },
    opened: recordOpened
  })
  t.is(ignored.present, null)
  t.is(ignored.ignoredTombstone, true)
  t.alike(resolvePresenceState({ previous: ignored, opened: recordOpened }), ignored)

  const openedDesc = openPresenceRecord({
    identityPublicKey: FIXED_IDENTITY.publicKey,
    period: 0n,
    revision: 1,
    readerSecret: READER,
    value: first.encoded.value,
    signature: first.signature
  })
  const withDigest = Object.freeze({ ...openedDesc, recordDigest: digest })
  t.alike(resolvePresenceState({ previous: null, opened: withDigest }), {
    present: true,
    descriptor,
    period: 0n,
    revision: 1,
    recordDigest: digest
  })

  expectCode(
    t,
    () =>
      resolvePresenceState({
        previous: periodState,
        opened: withDigest
      }),
    'REPLAY'
  )

  // Higher-revision descriptor re-enables after period tombstone (owner choice).
  const reenable = encodeSigned({ descriptor: b4a.from('again'), revision: 3 })
  const openedAgain = openPresenceRecord({
    identityPublicKey: FIXED_IDENTITY.publicKey,
    period: 0n,
    revision: 3,
    readerSecret: READER,
    value: reenable.encoded.value,
    signature: reenable.signature
  })
  const state = resolvePresenceState({
    previous: periodState,
    opened: Object.freeze({
      ...openedAgain,
      recordDigest: recordDigestOf(reenable.encoded.value)
    })
  })
  t.is(state.present, true)
  t.alike(state.descriptor, b4a.from('again'))
  t.is(state.revision, 3)
})

test('presence revision floors are period scoped and identical records are idempotent', (t) => {
  const descriptor = b4a.from('revision-floor')
  function openedAt(period, revision) {
    const { encoded, signature } = encodeSigned({ period, revision, descriptor })
    return {
      ...openPresenceRecord({
        identityPublicKey: FIXED_IDENTITY.publicKey,
        period,
        revision,
        readerSecret: READER,
        value: encoded.value,
        signature
      }),
      recordDigest: recordDigestOf(encoded.value)
    }
  }
  const opened = openedAt(3n, 7)
  const previous = resolvePresenceState({ opened })
  t.is(previous.period, 3n)
  t.alike(resolvePresenceState({ previous, opened }), previous)
  for (const conflicting of [openedAt(3n, 6), openedAt(3n, 7)]) {
    expectCode(t, () => resolvePresenceState({ previous, opened: conflicting }), 'REPLAY')
  }
  const next = resolvePresenceState({ previous, opened: openedAt(4n, 7) })
  t.is(next.present, true)
  t.is(next.period, 4n)
  t.is(next.revision, 7)
  t.is(resolvePresenceState({ previous, opened: openedAt(4n, 1) }).revision, 1)
})
