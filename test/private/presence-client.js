'use strict'

const test = require('brittle')
const b4a = require('b4a')
const crypto = require('hypercore-crypto')

const {
  PERIOD_MS,
  OVERLAP_MS,
  TOMBSTONE_SCOPE,
  deriveBlindedPublicKey,
  recordDigestOf
} = require('../../lib/private/blinded-presence')
const { createPresenceClient } = require('../../lib/private/presence-client')

const IDENTITY = crypto.keyPair(b4a.alloc(32, 0x31))
const READER = b4a.alloc(32, 0x51)

function createFakeController() {
  const store = new Map()
  const calls = []

  return {
    calls,
    async mutablePut(keyPair, value, opts = {}) {
      const seq = opts.seq || 0
      const signMutable = opts.signMutable
      const signature = await signMutable(seq, value, keyPair)
      const key = b4a.toString(keyPair.publicKey, 'hex')
      const existing = store.get(key)
      if (existing && existing.seq === seq && !b4a.equals(existing.value, value)) {
        const err = new Error('record conflict')
        err.code = 'ERR_RECORD_CONFLICT'
        throw err
      }
      if (existing && existing.seq > seq) {
        const err = new Error('record conflict')
        err.code = 'ERR_RECORD_CONFLICT'
        throw err
      }
      store.set(key, {
        seq,
        value: b4a.from(value),
        signature: b4a.from(signature)
      })
      calls.push({
        op: 'put',
        publicKey: b4a.from(keyPair.publicKey),
        seq,
        value: b4a.from(value)
      })
      return Object.freeze({
        publicKey: b4a.from(keyPair.publicKey),
        seq,
        signature: b4a.from(signature)
      })
    },
    async mutableGet(publicKey, opts = {}) {
      calls.push({ op: 'get', publicKey: b4a.from(publicKey), opts })
      const record = store.get(b4a.toString(publicKey, 'hex'))
      if (!record) return null
      return Object.freeze({
        seq: record.seq,
        value: b4a.from(record.value),
        signature: b4a.from(record.signature)
      })
    }
  }
}

function clientFor(controller, wallMs) {
  return createPresenceClient({
    controller,
    identityKeyPair: IDENTITY,
    readerSecret: READER,
    now: () => wallMs
  })
}

test('publishPresence puts under derived A prime with seq equal revision', async (t) => {
  const controller = createFakeController()
  const wallMs = Number(PERIOD_MS) + 10_000
  const client = clientFor(controller, wallMs)
  const descriptor = b4a.from('presence-body')
  const published = await client.publishPresence({ descriptor, revision: 4 })

  t.is(published.length, 1)
  t.is(published[0].period, 1n)
  t.is(published[0].revision, 4)
  t.alike(published[0].publicKey, deriveBlindedPublicKey(IDENTITY.publicKey, 1n))
  t.is(controller.calls.length, 1)
  t.is(controller.calls[0].op, 'put')
  t.is(controller.calls[0].seq, 4)
  t.alike(controller.calls[0].publicKey, published[0].publicKey)
  t.is(controller.calls[0].value.byteLength, 895)
  t.alike(published[0].recordDigest, recordDigestOf(controller.calls[0].value))
})

test('publishPresence covers current and next period inside overlap', async (t) => {
  const controller = createFakeController()
  const wallMs = Number(PERIOD_MS) - Number(OVERLAP_MS)
  const client = clientFor(controller, wallMs)
  const published = await client.publishPresence({
    descriptor: b4a.from('overlap'),
    revision: 1
  })
  t.is(published.length, 2)
  t.is(published[0].period, 0n)
  t.is(published[1].period, 1n)
  t.is(controller.calls.length, 2)
})

test('signMutable from encode refuses foreign seq through controller put', async (t) => {
  const controller = createFakeController()
  const client = clientFor(controller, 1_000)
  // Intercept put to force a foreign seq into signMutable.
  const original = controller.mutablePut.bind(controller)
  controller.mutablePut = async (keyPair, value, opts) => {
    try {
      opts.signMutable(opts.seq + 1, value, keyPair)
      t.fail('foreign seq should throw')
    } catch (err) {
      t.is(err.code, 'UNAUTHORIZED')
    }
    try {
      opts.signMutable(opts.seq, value, {
        publicKey: deriveBlindedPublicKey(IDENTITY.publicKey, 9n)
      })
      t.fail('foreign key should throw')
    } catch (err) {
      t.is(err.code, 'UNAUTHORIZED')
    }
    return original(keyPair, value, opts)
  }
  await client.publishPresence({ descriptor: b4a.from('x'), revision: 2 })
})

test('resolvePresence opens the first available lookup period', async (t) => {
  const controller = createFakeController()
  const wallMs = Number(PERIOD_MS) + 1_000
  const publisher = clientFor(controller, wallMs)
  await publisher.publishPresence({ descriptor: b4a.from('found'), revision: 5 })

  const reader = createPresenceClient({
    controller,
    identityPublicKey: IDENTITY.publicKey,
    readerSecret: READER,
    now: () => wallMs
  })
  const resolved = await reader.resolvePresence()
  t.is(resolved.present, true)
  t.is(resolved.period, 1n)
  t.is(resolved.revision, 5)
  t.alike(resolved.descriptor, b4a.from('found'))
})

test('revokePresence PERIOD clears presence; higher descriptor re-enables', async (t) => {
  const controller = createFakeController()
  const wallMs = 5_000
  const client = clientFor(controller, wallMs)
  const published = await client.publishPresence({
    descriptor: b4a.from('before'),
    revision: 1
  })
  const previous = {
    revision: 1,
    recordDigest: published[0].recordDigest
  }

  await client.revokePresence({ revision: 2, scope: TOMBSTONE_SCOPE.PERIOD })
  const revoked = await client.resolvePresence({ previous })
  t.is(revoked.present, false)

  await client.publishPresence({ descriptor: b4a.from('after'), revision: 3 })
  const again = await client.resolvePresence({
    previous: { revision: 2, recordDigest: published[0].recordDigest }
  })
  t.is(again.present, true)
  t.alike(again.descriptor, b4a.from('after'))
  t.is(again.revision, 3)
})

test('ERR_RECORD_CONFLICT surfaces from one period', async (t) => {
  const controller = createFakeController()
  const client = clientFor(controller, 1_000)
  await client.publishPresence({ descriptor: b4a.from('a'), revision: 1 })
  try {
    await client.publishPresence({ descriptor: b4a.from('b'), revision: 1 })
    t.fail('expected conflict')
  } catch (err) {
    t.is(err && err.code, 'ERR_RECORD_CONFLICT')
  }
})
