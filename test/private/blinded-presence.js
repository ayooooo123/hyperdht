'use strict'

const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-universal')

const {
  BLIND_FACTOR_DOMAIN,
  STORAGE_ADDR_DOMAIN,
  DESCRIPTOR_KEY_DOMAIN,
  DESCRIPTOR_CIPHER_DOMAIN,
  ED25519_L,
  deriveBlindingScalar,
  blindPublicKey,
  blindSecretKey,
  deriveStorageKey,
  signPresenceDescriptor,
  verifyPresenceDescriptor,
  encryptPresenceDescriptor,
  decryptPresenceDescriptor,
  createPresenceRecord,
  verifyAndDecryptPresenceRecord
} = require('../../lib/private/blinded-presence')

function expectCode(t, fn, code) {
  let error = null
  try {
    fn()
  } catch (err) {
    error = err
  }
  t.ok(error, `expected throw with code ${code}`)
  t.is(error && error.code, code)
}

function testKeyPair(seedByte = 1) {
  const seed = b4a.alloc(32, seedByte)
  const pk = b4a.alloc(32)
  const sk = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(pk, sk, seed)
  return { publicKey: pk, secretKey: sk }
}

test('deterministic blinding scalar derivation mod L', (t) => {
  const kp = testKeyPair(0x42)
  const epoch = 100n

  const h1 = deriveBlindingScalar(kp.publicKey, epoch)
  const h2 = deriveBlindingScalar(kp.publicKey, epoch)

  t.is(h1.byteLength, 32)
  t.alike(h1, h2, 'blinding scalar is deterministic for same key and epoch')

  const hDifferentEpoch = deriveBlindingScalar(kp.publicKey, 101n)
  t.not(b4a.equals(h1, hDifferentEpoch), 'different epoch produces distinct blinding scalar')

  const kp2 = testKeyPair(0x43)
  const hDifferentKey = deriveBlindingScalar(kp2.publicKey, epoch)
  t.not(b4a.equals(h1, hDifferentKey), 'different identity produces distinct blinding scalar')
})

test('mathematical equality: A_prime = h * A equals a_prime * B', (t) => {
  const kp = testKeyPair(0x55)
  const epoch = 42n
  const h = deriveBlindingScalar(kp.publicKey, epoch)

  const blindedPk = blindPublicKey(kp.publicKey, h)
  const blindedSk = blindSecretKey(kp.secretKey, h)

  // Verify that blindedSk multiplied by Ed25519 base point B equals blindedPk
  const expectedPk = b4a.alloc(32)
  sodium.crypto_scalarmult_ed25519_base_noclamp(expectedPk, blindedSk)

  t.alike(blindedPk, expectedPk, 'A_prime = h*A strictly equals a_prime*B')
  t.is(blindedPk.byteLength, 32)
  t.is(blindedSk.byteLength, 32)
})

test('blinded signing and verification under blinded public key', (t) => {
  const kp = testKeyPair(0x77)
  const epoch = 500n
  const h = deriveBlindingScalar(kp.publicKey, epoch)

  const blindedPk = blindPublicKey(kp.publicKey, h)
  const blindedSk = blindSecretKey(kp.secretKey, h)

  const descriptor = b4a.from('hyperdht-private-service-descriptor-payload')
  const signature = signPresenceDescriptor(blindedSk, blindedPk, descriptor)

  t.is(signature.byteLength, 64)
  t.is(
    verifyPresenceDescriptor(blindedPk, descriptor, signature),
    true,
    'valid signature verifies under A_prime'
  )

  // Unblinded public key MUST fail verification
  t.is(
    verifyPresenceDescriptor(kp.publicKey, descriptor, signature),
    false,
    'signature fails under unblinded key'
  )

  // Tampered descriptor MUST fail verification
  const tamperedDescriptor = b4a.from('tampered-service-descriptor-payload')
  t.is(
    verifyPresenceDescriptor(blindedPk, tamperedDescriptor, signature),
    false,
    'tampered message fails'
  )

  // Tampered signature MUST fail verification
  const tamperedSig = b4a.from(signature)
  tamperedSig[0] ^= 0xff
  t.is(
    verifyPresenceDescriptor(blindedPk, descriptor, tamperedSig),
    false,
    'tampered signature fails'
  )
})

test('storage address key derivation and domain separation', (t) => {
  const kp = testKeyPair(0x88)
  const epoch1 = 1n
  const epoch2 = 2n

  const h1 = deriveBlindingScalar(kp.publicKey, epoch1)
  const h2 = deriveBlindingScalar(kp.publicKey, epoch2)

  const blindedPk1 = blindPublicKey(kp.publicKey, h1)
  const blindedPk2 = blindPublicKey(kp.publicKey, h2)

  const storageKey1 = deriveStorageKey(blindedPk1, epoch1)
  const storageKey2 = deriveStorageKey(blindedPk2, epoch2)

  t.is(storageKey1.byteLength, 32)
  t.is(storageKey2.byteLength, 32)
  t.not(b4a.equals(storageKey1, storageKey2), 'storage keys in different epochs are distinct')
  t.not(b4a.equals(storageKey1, kp.publicKey), 'storage key does not leak stable public key')
})

test('unlinkability across epochs by a storage node', (t) => {
  const kp = testKeyPair(0x99)
  const records = []

  for (let e = 1n; e <= 5n; e++) {
    const record = createPresenceRecord({
      keyPair: kp,
      epoch: e,
      descriptor: b4a.from(`route-descriptor-epoch-${e}`)
    })
    records.push(record)
  }

  for (let i = 0; i < records.length; i++) {
    for (let j = i + 1; j < records.length; j++) {
      t.not(
        b4a.equals(records[i].storageKey, records[j].storageKey),
        `storage keys for epoch ${i + 1} and ${j + 1} are orthogonal`
      )
      t.not(
        b4a.equals(records[i].blindedPublicKey, records[j].blindedPublicKey),
        `blinded public keys for epoch ${i + 1} and ${j + 1} are orthogonal`
      )
    }
  }
})

test('presence descriptor encryption and reader access control', (t) => {
  const readerSecret = b4a.alloc(32, 0x11)
  const descriptor = b4a.from('confidential-opaque-destination-descriptor')

  const encrypted = encryptPresenceDescriptor(readerSecret, descriptor)
  t.ok(encrypted.byteLength > descriptor.byteLength, 'ciphertext carries nonce and MAC')
  t.not(
    b4a.equals(encrypted.subarray(24, 24 + descriptor.byteLength), descriptor),
    'ciphertext does not leak plaintext'
  )

  const decrypted = decryptPresenceDescriptor(readerSecret, encrypted)
  t.alike(decrypted, descriptor, 'authorized reader recovers descriptor exactly')

  // Unauthorized reader secret MUST fail decryption
  const wrongSecret = b4a.alloc(32, 0x22)
  expectCode(t, () => decryptPresenceDescriptor(wrongSecret, encrypted), 'ERR_AUTHENTICATION')

  // Tampered ciphertext MUST fail decryption
  const tampered = b4a.from(encrypted)
  tampered[tampered.length - 1] ^= 0x01
  expectCode(t, () => decryptPresenceDescriptor(readerSecret, tampered), 'ERR_AUTHENTICATION')
})

test('end-to-end presence record publication, verification, and resolution', (t) => {
  const serviceKeyPair = testKeyPair(0xaa)
  const readerSecret = b4a.alloc(32, 0xbb)
  const epoch = 1337n
  const descriptor = b4a.from('opaque-route-entrypoint-tuple')

  // 1. Service creates presence record
  const record = createPresenceRecord({
    keyPair: serviceKeyPair,
    readerSecret,
    epoch,
    descriptor
  })

  t.is(record.epoch, 1337n)
  t.is(record.storageKey.byteLength, 32)
  t.is(record.blindedPublicKey.byteLength, 32)
  t.is(record.signature.byteLength, 64)
  t.ok(record.payload.byteLength > descriptor.byteLength)

  // 2. Client resolves and decrypts record
  const resolved = verifyAndDecryptPresenceRecord({
    publicKey: serviceKeyPair.publicKey,
    readerSecret,
    record
  })

  t.ok(resolved !== null, 'valid record resolves successfully')
  t.is(resolved.valid, true)
  t.is(resolved.epoch, 1337n)
  t.alike(resolved.descriptor, descriptor, 'recovered descriptor matches published original')

  // 3. Client without readerSecret gets authenticated ciphertext but cannot read body
  const uncredentialedResolve = verifyAndDecryptPresenceRecord({
    publicKey: serviceKeyPair.publicKey,
    record
  })
  t.ok(uncredentialedResolve !== null)
  t.alike(
    uncredentialedResolve.descriptor,
    record.payload,
    'uncredentialed looker gets authenticated payload'
  )

  // 4. Incorrect service public key fails verification
  const wrongService = testKeyPair(0xcc)
  const wrongResolve = verifyAndDecryptPresenceRecord({
    publicKey: wrongService.publicKey,
    readerSecret,
    record
  })
  t.is(wrongResolve, null, 'wrong service key rejects record verification')
})

test('tamper detection on high-level presence records', (t) => {
  const kp = testKeyPair(0xdd)
  const readerSecret = b4a.alloc(32, 0xee)
  const epoch = 42n
  const descriptor = b4a.from('target-route-service')

  const baseRecord = createPresenceRecord({
    keyPair: kp,
    readerSecret,
    epoch,
    descriptor
  })

  // Tamper signature
  const badSigRecord = { ...baseRecord, signature: b4a.alloc(64) }
  t.is(
    verifyAndDecryptPresenceRecord({ publicKey: kp.publicKey, readerSecret, record: badSigRecord }),
    null
  )

  // Tamper blinded public key
  const badPkRecord = { ...baseRecord, blindedPublicKey: b4a.alloc(32, 0x99) }
  t.is(
    verifyAndDecryptPresenceRecord({ publicKey: kp.publicKey, readerSecret, record: badPkRecord }),
    null
  )

  // Tamper payload
  const badPayloadRecord = { ...baseRecord, payload: b4a.from(baseRecord.payload) }
  badPayloadRecord.payload[badPayloadRecord.payload.length - 1] ^= 0xff
  t.is(
    verifyAndDecryptPresenceRecord({
      publicKey: kp.publicKey,
      readerSecret,
      record: badPayloadRecord
    }),
    null
  )

  // Epoch mismatch
  const badEpochRecord = { ...baseRecord, epoch: 43n }
  t.is(
    verifyAndDecryptPresenceRecord({
      publicKey: kp.publicKey,
      readerSecret,
      record: badEpochRecord
    }),
    null
  )
})

test('fail-closed input validation on all blinded presence APIs', (t) => {
  const kp = testKeyPair(0x12)
  const scalar = deriveBlindingScalar(kp.publicKey, 1n)

  // deriveBlindingScalar
  expectCode(t, () => deriveBlindingScalar(null, 1n), 'INVALID_KEY')
  expectCode(t, () => deriveBlindingScalar(b4a.alloc(16), 1n), 'INVALID_KEY')
  expectCode(t, () => deriveBlindingScalar(kp.publicKey, -1n), 'INVALID_KEY')
  expectCode(t, () => deriveBlindingScalar(kp.publicKey, '1'), 'INVALID_KEY')

  // blindPublicKey
  expectCode(t, () => blindPublicKey(null, scalar), 'INVALID_KEY')
  expectCode(t, () => blindPublicKey(b4a.alloc(16), scalar), 'INVALID_KEY')
  expectCode(t, () => blindPublicKey(kp.publicKey, b4a.alloc(16)), 'INVALID_KEY')

  // blindSecretKey
  expectCode(t, () => blindSecretKey(null, scalar), 'INVALID_KEY')
  expectCode(t, () => blindSecretKey(b4a.alloc(32), scalar), 'INVALID_KEY')
  expectCode(t, () => blindSecretKey(kp.secretKey, b4a.alloc(16)), 'INVALID_KEY')

  // deriveStorageKey
  expectCode(t, () => deriveStorageKey(null, 1n), 'INVALID_KEY')
  expectCode(t, () => deriveStorageKey(b4a.alloc(16), 1n), 'INVALID_KEY')
  expectCode(t, () => deriveStorageKey(kp.publicKey, 0x1_0000_0000_0000_0000n), 'INVALID_KEY')

  // signPresenceDescriptor
  expectCode(t, () => signPresenceDescriptor(null, kp.publicKey, b4a.alloc(10)), 'INVALID_KEY')
  expectCode(t, () => signPresenceDescriptor(b4a.alloc(32), null, b4a.alloc(10)), 'INVALID_KEY')
  expectCode(t, () => signPresenceDescriptor(b4a.alloc(32), kp.publicKey, null), 'INVALID_KEY')

  // verifyPresenceDescriptor returns false on invalid shapes without throwing
  t.is(verifyPresenceDescriptor(null, b4a.alloc(10), b4a.alloc(64)), false)
  t.is(verifyPresenceDescriptor(kp.publicKey, null, b4a.alloc(64)), false)
  t.is(verifyPresenceDescriptor(kp.publicKey, b4a.alloc(10), b4a.alloc(32)), false)

  // encryptPresenceDescriptor / decryptPresenceDescriptor
  expectCode(t, () => encryptPresenceDescriptor(null, b4a.alloc(10)), 'INVALID_KEY')
  expectCode(t, () => encryptPresenceDescriptor(b4a.alloc(16), b4a.alloc(10)), 'INVALID_KEY')
  expectCode(t, () => encryptPresenceDescriptor(b4a.alloc(32), null), 'INVALID_KEY')
  expectCode(t, () => encryptPresenceDescriptor(b4a.alloc(32), b4a.alloc(5000)), 'INVALID_KEY')
  expectCode(t, () => decryptPresenceDescriptor(null, b4a.alloc(50)), 'INVALID_KEY')
  expectCode(t, () => decryptPresenceDescriptor(b4a.alloc(16), b4a.alloc(50)), 'INVALID_KEY')
  expectCode(t, () => decryptPresenceDescriptor(b4a.alloc(32), b4a.alloc(10)), 'ERR_AUTHENTICATION')
})

test('deterministic test vector', (t) => {
  const seed = b4a.alloc(32, 0x01)
  const pk = b4a.alloc(32)
  const sk = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(pk, sk, seed)

  const epoch = 1n
  const h = deriveBlindingScalar(pk, epoch)
  const blindedPk = blindPublicKey(pk, h)
  const blindedSk = blindSecretKey(sk, h)
  const storageKey = deriveStorageKey(blindedPk, epoch)

  t.is(b4a.toString(pk, 'hex'), '8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c')
  t.is(h.byteLength, 32)
  t.is(blindedPk.byteLength, 32)
  t.is(blindedSk.byteLength, 32)
  t.is(storageKey.byteLength, 32)

  const descriptor = b4a.from('vector-test')
  const sig = signPresenceDescriptor(blindedSk, blindedPk, descriptor)
  t.is(verifyPresenceDescriptor(blindedPk, descriptor, sig), true)
})
