'use strict'

const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-universal')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { PrivateRouteError } = require('../../lib/private/errors')
const presence = require('../../lib/private/blinded-presence')

function keyPair(byte) {
  return cryptoSuite.keyPair(b4a.alloc(32, byte))
}

function expectCode(t, fn, code) {
  let error = null
  try {
    fn()
  } catch (err) {
    error = err
  }
  t.ok(error instanceof PrivateRouteError, 'expected PrivateRouteError')
  t.is(error && error.code, code)
}

test('Tor v3 blinding vector: A prime = h times A reproduces the published bytes', (t) => {
  // tor/src/test/test_hs_common.c test_blinding_basics
  const identityPublicKey = b4a.from(
    '833990B085C1A688C1D4C8B1F6B56AFAF5A2ECA674449E1D704F83765CCB7BC6',
    'hex'
  )
  // build_blinded_key_param output for period 1234 with period length 1440
  const param = b4a.from('379E50DB31FEE6775ABD0AF6FB7C371E060308F4F847DB09FE4CFE13AF602287', 'hex')
  const blinded = presence.blindPublicKey(identityPublicKey, param)
  t.alike(
    b4a.toString(blinded, 'hex').toUpperCase(),
    '3A50BF210E8F9EE955AE0014F7A6917FB65EBF098A86305ABB508D1A7291B6D5'
  )
  t.ok(sodium.crypto_core_ed25519_is_valid_point(blinded))
})

test('deriveEpochBlindingParam clamps exactly like the Tor spec', (t) => {
  const identity = keyPair(1)
  const param = presence.deriveEpochBlindingParam(identity.publicKey, 42n)
  t.is(param.byteLength, 32)
  t.is(param[0] & 7, 0)
  t.is(param[31] >> 6, 1)
  t.is(param[31] & 128, 0)
})

test('blinded public key is a valid point and epoch dependent', (t) => {
  const identity = keyPair(2)
  const first = presence.blindPublicKey(
    identity.publicKey,
    presence.deriveEpochBlindingParam(identity.publicKey, 1n)
  )
  const second = presence.blindPublicKey(
    identity.publicKey,
    presence.deriveEpochBlindingParam(identity.publicKey, 2n)
  )
  t.ok(sodium.crypto_core_ed25519_is_valid_point(first))
  t.ok(sodium.crypto_core_ed25519_is_valid_point(second))
  t.is(b4a.equals(first, second), false)
  t.is(b4a.equals(first, identity.publicKey), false)
})

test('storage address key separates epoch and identity and hides the stable key', (t) => {
  const identity = keyPair(3)
  const other = keyPair(4)
  const first = presence.deriveEpochAddressKey(identity.publicKey, 1n)
  const second = presence.deriveEpochAddressKey(identity.publicKey, 2n)
  const otherAddress = presence.deriveEpochAddressKey(other.publicKey, 1n)
  t.is(first.byteLength, 32)
  t.is(b4a.equals(first, second), false)
  t.is(b4a.equals(first, otherAddress), false)
  t.is(b4a.equals(first, identity.publicKey), false)
  expectCode(t, () => presence.deriveEpochAddressKey(b4a.alloc(31), 1n), 'INVALID_KEY')
})

test('epoch key pairs are deterministic per epoch and never reused', (t) => {
  const identity = keyPair(5)
  const first = presence.deriveEpochKeyPair(identity.secretKey, 1n)
  const again = presence.deriveEpochKeyPair(identity.secretKey, 1n)
  const next = presence.deriveEpochKeyPair(identity.secretKey, 2n)
  t.alike(first.publicKey, again.publicKey)
  t.is(b4a.equals(first.publicKey, next.publicKey), false)
  t.is(b4a.equals(first.publicKey, identity.publicKey), false)
  const cleared = cryptoSuite.keyPair(first.publicKey)
  t.is(cleared.publicKey.byteLength, 32)
})

test('epoch certificate verifies under the stable identity and binds the descriptor', (t) => {
  const identity = keyPair(6)
  const epochKeyPair = presence.deriveEpochKeyPair(identity.secretKey, 7n)
  const address = presence.deriveEpochAddressKey(identity.publicKey, 7n)
  const digest = cryptoSuite.hash([b4a.from('descriptor')])
  const signature = presence.epochCertificate(identity, epochKeyPair, 7n, address, digest)
  t.is(signature.byteLength, 64)
  t.ok(
    presence.verifyEpochCertificate(
      identity.publicKey,
      epochKeyPair,
      7n,
      address,
      digest,
      signature
    )
  )
  const wrongDigest = cryptoSuite.hash([b4a.from('other-descriptor')])
  t.is(
    presence.verifyEpochCertificate(
      identity.publicKey,
      epochKeyPair,
      7n,
      address,
      wrongDigest,
      signature
    ),
    false
  )
  t.is(
    presence.verifyEpochCertificate(
      identity.publicKey,
      epochKeyPair,
      8n,
      address,
      digest,
      signature
    ),
    false
  )
  const stranger = keyPair(9)
  t.is(
    presence.verifyEpochCertificate(
      stranger.publicKey,
      epochKeyPair,
      7n,
      address,
      digest,
      signature
    ),
    false
  )
})

test('presence record is exactly 1023 bytes with canonical zero padding', (t) => {
  const identity = keyPair(10)
  const reader = b4a.alloc(32, 0xcc)
  const descriptor = b4a.from('presence-descriptor-payload')
  const record = presence.createPresenceRecord({
    identityKeyPair: identity,
    epoch: 42n,
    descriptor,
    readerSecret: reader
  })
  t.is(record.record.byteLength, presence.RECORD_SIZE)
  t.is(record.storageKey.byteLength, 32)
  t.is(record.epoch, 42n)
  t.alike(record.record.subarray(9, 40), b4a.alloc(31))
  t.is(record.record[0], 1)
  const headerEpoch = record.record.readBigUInt64BE(1)
  t.is(headerEpoch, 42n)
})

test('resolve returns the exact descriptor bytes the host published', (t) => {
  const identity = keyPair(11)
  const reader = b4a.alloc(32, 0xd1)
  const descriptor = b4a.from('exact-own-snapshot-descriptor')
  const record = presence.createPresenceRecord({
    identityKeyPair: identity,
    epoch: 43n,
    descriptor,
    readerSecret: reader
  })
  const resolved = presence.resolvePresenceRecord({
    publicKey: identity.publicKey,
    epoch: 43n,
    record: record.record,
    readerSecret: reader
  })
  t.alike(resolved.descriptor, descriptor)
  t.is(resolved.epoch, 43n)
  t.alike(resolved.storageKey, record.storageKey)
  t.ok(sodium.crypto_core_ed25519_is_valid_point(resolved.epochPublicKey))
})

test('reader credential is mandatory and wrong credentials fail closed', (t) => {
  const identity = keyPair(12)
  const reader = b4a.alloc(32, 0xe1)
  const record = presence.createPresenceRecord({
    identityKeyPair: identity,
    epoch: 1n,
    descriptor: b4a.from('secret-descriptor'),
    readerSecret: reader
  })
  expectCode(
    t,
    () =>
      presence.resolvePresenceRecord({
        publicKey: identity.publicKey,
        epoch: 1n,
        record: record.record,
        readerSecret: b4a.alloc(32, 0xe2)
      }),
    'ERR_AUTHENTICATION'
  )
  expectCode(
    t,
    () =>
      presence.createPresenceRecord({
        identityKeyPair: identity,
        epoch: 1n,
        descriptor: b4a.from('x'),
        readerSecret: b4a.alloc(31)
      }),
    'INVALID_KEY'
  )
})

test('tampered record bytes fail authentication before any state changes', (t) => {
  const identity = keyPair(13)
  const reader = b4a.alloc(32, 0xf1)
  const record = presence.createPresenceRecord({
    identityKeyPair: identity,
    epoch: 5n,
    descriptor: b4a.from('tamper-target'),
    readerSecret: reader
  })
  for (const offset of [0, 3, 40, 71, 72, 100, 1022]) {
    const tampered = b4a.from(record.record)
    tampered[offset] ^= 0x01
    expectCode(
      t,
      () =>
        presence.resolvePresenceRecord({
          publicKey: identity.publicKey,
          epoch: 5n,
          record: tampered,
          readerSecret: reader
        }),
      offset === 0 ? 'INVALID_DESCRIPTOR' : 'ERR_AUTHENTICATION'
    )
  }
})

test('a record for one epoch is a replay in another', (t) => {
  const identity = keyPair(14)
  const reader = b4a.alloc(32, 0xf2)
  const record = presence.createPresenceRecord({
    identityKeyPair: identity,
    epoch: 9n,
    descriptor: b4a.from('replay-target'),
    readerSecret: reader
  })
  expectCode(
    t,
    () =>
      presence.resolvePresenceRecord({
        publicKey: identity.publicKey,
        epoch: 10n,
        record: record.record,
        readerSecret: reader
      }),
    'REPLAY'
  )
})

test('a reader credential cannot mint an owned record', (t) => {
  const identity = keyPair(15)
  const reader = b4a.alloc(32, 0xf3)
  const record = presence.createPresenceRecord({
    identityKeyPair: identity,
    epoch: 11n,
    descriptor: b4a.from('original-descriptor'),
    readerSecret: reader
  })
  const header = b4a.from(record.record.subarray(0, 72))
  const noncePrefix = b4a.from(record.record.subarray(72, 88))
  const ciphertext = b4a.from(record.record.subarray(96))
  const plaintext = cryptoSuite.open({
    key: reader,
    noncePrefix,
    counter: 0n,
    associatedData: header,
    ciphertext
  })
  t.ok(plaintext !== null)
  // The credential holder re-encrypts a modified payload under the same
  // header and nonce. The certificate no longer matches the descriptor, so
  // resolution must fail.
  plaintext[plaintext.byteLength - 1] ^= 1
  const forgedCiphertext = cryptoSuite.seal({
    key: reader,
    noncePrefix,
    counter: 0n,
    associatedData: header,
    plaintext
  })
  const forged = b4a.concat([header, noncePrefix, b4a.alloc(8), forgedCiphertext])
  expectCode(
    t,
    () =>
      presence.resolvePresenceRecord({
        publicKey: identity.publicKey,
        epoch: 11n,
        record: forged,
        readerSecret: reader
      }),
    'ERR_AUTHENTICATION'
  )
})

test('tombstones override descriptors by exact digest or for the whole epoch', (t) => {
  const identity = keyPair(16)
  const reader = b4a.alloc(32, 0xf4)
  const descriptor = b4a.from('tombstone-target')
  const record = presence.createPresenceRecord({
    identityKeyPair: identity,
    epoch: 21n,
    descriptor,
    readerSecret: reader
  })
  const epochTombstone = presence.createPresenceTombstone({
    identityKeyPair: identity,
    epoch: 21n,
    digest: b4a.alloc(32),
    readerSecret: reader
  })
  t.is(epochTombstone.record[0], 2)
  t.is(
    presence.resolvePresence({
      publicKey: identity.publicKey,
      epoch: 21n,
      record: record.record,
      tombstone: epochTombstone.record,
      readerSecret: reader
    }),
    null
  )
  const specificTombstone = presence.createPresenceTombstone({
    identityKeyPair: identity,
    epoch: 21n,
    digest: cryptoSuite.hash([record.record]),
    readerSecret: reader
  })
  t.is(
    presence.resolvePresence({
      publicKey: identity.publicKey,
      epoch: 21n,
      record: record.record,
      tombstone: specificTombstone.record,
      readerSecret: reader
    }),
    null
  )
  // A tombstone for a different record leaves this one alive.
  const otherRecord = presence.createPresenceRecord({
    identityKeyPair: identity,
    epoch: 21n,
    descriptor: b4a.from('survivor'),
    readerSecret: reader
  })
  const survivor = presence.resolvePresence({
    publicKey: identity.publicKey,
    epoch: 21n,
    record: otherRecord.record,
    tombstone: specificTombstone.record,
    readerSecret: reader
  })
  t.ok(survivor !== null)
  t.alike(survivor.descriptor, b4a.from('survivor'))
})

test('a tombstone made by a stranger cannot kill an owned record', (t) => {
  const identity = keyPair(17)
  const stranger = keyPair(18)
  const reader = b4a.alloc(32, 0xf5)
  const record = presence.createPresenceRecord({
    identityKeyPair: identity,
    epoch: 31n,
    descriptor: b4a.from('owner-record'),
    readerSecret: reader
  })
  const forgedTombstone = presence.createPresenceTombstone({
    identityKeyPair: stranger,
    epoch: 31n,
    digest: b4a.alloc(32),
    readerSecret: reader
  })
  const resolved = presence.resolvePresence({
    publicKey: identity.publicKey,
    epoch: 31n,
    record: record.record,
    tombstone: forgedTombstone.record,
    readerSecret: reader
  })
  t.ok(resolved !== null)
  t.alike(resolved.descriptor, b4a.from('owner-record'))
})

test('records bound to a different identity never resolve', (t) => {
  const identity = keyPair(19)
  const other = keyPair(20)
  const reader = b4a.alloc(32, 0xf6)
  const record = presence.createPresenceRecord({
    identityKeyPair: identity,
    epoch: 41n,
    descriptor: b4a.from('identity-binding'),
    readerSecret: reader
  })
  expectCode(
    t,
    () =>
      presence.resolvePresenceRecord({
        publicKey: other.publicKey,
        epoch: 41n,
        record: record.record,
        readerSecret: reader
      }),
    'ERR_AUTHENTICATION'
  )
})

test('descriptor size is bounded by the canonical record', (t) => {
  const identity = keyPair(21)
  const reader = b4a.alloc(32, 0xf7)
  expectCode(
    t,
    () =>
      presence.createPresenceRecord({
        identityKeyPair: identity,
        epoch: 1n,
        descriptor: b4a.alloc(presence.MAX_DESCRIPTOR_BYTES + 1),
        readerSecret: reader
      }),
    'INVALID_DESCRIPTOR'
  )
  const exact = presence.createPresenceRecord({
    identityKeyPair: identity,
    epoch: 1n,
    descriptor: b4a.alloc(presence.MAX_DESCRIPTOR_BYTES, 7),
    readerSecret: reader
  })
  const resolved = presence.resolvePresenceRecord({
    publicKey: identity.publicKey,
    epoch: 1n,
    record: exact.record,
    readerSecret: reader
  })
  t.is(resolved.descriptor.byteLength, presence.MAX_DESCRIPTOR_BYTES)
})

test('epoch windows follow the Tor overlap pattern', (t) => {
  const week = Number(presence.EPOCH_MS)
  const day = Number(presence.OVERLAP_MS)
  t.is(presence.currentEpoch(week * 5 + 1), 5n)
  t.alike(presence.announceEpochs(week * 5 + 1), [5n, 6n])
  t.alike(presence.lookupEpochs(week * 5 + 1), [5n, 4n])
  t.alike(presence.lookupEpochs(0), [0n])
  t.ok(day < week, 'overlap is shorter than an epoch')
  expectCode(t, () => presence.currentEpoch(-1), 'INVALID_DESCRIPTOR')
})

test('records are byte-stable across seal and open with fixed credentials', (t) => {
  const identity = keyPair(22)
  const reader = b4a.alloc(32, 0xf8)
  const first = presence.createPresenceRecord({
    identityKeyPair: identity,
    epoch: 77n,
    descriptor: b4a.from('stability'),
    readerSecret: reader
  })
  const second = presence.createPresenceRecord({
    identityKeyPair: identity,
    epoch: 77n,
    descriptor: b4a.from('stability'),
    readerSecret: reader
  })
  // Nonce prefix is random, so ciphertext differs, but the header and the
  // storage address are canonical and must be byte-equal.
  t.alike(first.record.subarray(0, 72), second.record.subarray(0, 72))
  t.alike(first.storageKey, second.storageKey)
  const firstResolved = presence.resolvePresenceRecord({
    publicKey: identity.publicKey,
    epoch: 77n,
    record: first.record,
    readerSecret: reader
  })
  const secondResolved = presence.resolvePresenceRecord({
    publicKey: identity.publicKey,
    epoch: 77n,
    record: second.record,
    readerSecret: reader
  })
  t.alike(firstResolved.descriptor, secondResolved.descriptor)
})
