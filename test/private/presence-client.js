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
  await client.publishPresence({
    descriptor: b4a.from('before'),
    revision: 1
  })
  const previous = await client.resolvePresence()

  await client.revokePresence({ revision: 2, scope: TOMBSTONE_SCOPE.PERIOD })
  const revoked = await client.resolvePresence({ previous })
  t.is(revoked.present, false)

  await client.publishPresence({ descriptor: b4a.from('after'), revision: 3 })
  const again = await client.resolvePresence({ previous: revoked })
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

for (const scope of [TOMBSTONE_SCOPE.PERIOD, TOMBSTONE_SCOPE.RECORD]) {
  test('retained tombstone blocks stale storage and survives polling: ' + scope, async (t) => {
    const controller = createFakeController()
    const client = clientFor(controller, 10_000)
    const published = await client.publishPresence({ descriptor: b4a.from('live'), revision: 1 })
    const stale = await controller.mutableGet(published[0].publicKey)
    const previous = await client.resolvePresence()
    await client.revokePresence({
      revision: 2,
      scope,
      targets: new Map(published.map(({ period, recordDigest }) => [period, recordDigest]))
    })
    const revoked = await client.resolvePresence({ previous })
    t.is(revoked.present, false)
    t.is(revoked.revision, 2)
    t.is(revoked.period, previous.period)
    t.alike(await client.resolvePresence({ previous: revoked }), revoked)
    const get = controller.mutableGet.bind(controller)
    controller.mutableGet = async () => stale
    try {
      await client.resolvePresence({ previous: revoked })
      t.fail('stale descriptor must not restore revoked presence')
    } catch (err) {
      t.is(err.code, 'REPLAY')
    }
    controller.mutableGet = get
    await client.publishPresence({ descriptor: b4a.from('restored'), revision: 3 })
    const restored = await client.resolvePresence({ previous: revoked })
    t.is(restored.present, true)
    t.alike(restored.descriptor, b4a.from('restored'))
  })
}

test('overlap records can be polled and revoked on both sides of midnight', async (t) => {
  const controller = createFakeController()
  const before = clientFor(controller, Number(PERIOD_MS) - Number(OVERLAP_MS))
  const after = clientFor(controller, Number(PERIOD_MS) + 1_000)
  const published = await before.publishPresence({ descriptor: b4a.from('overlap'), revision: 7 })
  const oldState = await before.resolvePresence()
  t.alike(await before.resolvePresence({ previous: oldState }), oldState)
  const newState = await after.resolvePresence({ previous: oldState })
  t.is(newState.period, 1n)
  t.is(newState.present, true)
  t.alike(await after.resolvePresence({ previous: newState }), newState)
  await before.revokePresence({
    revision: 8,
    scope: TOMBSTONE_SCOPE.RECORD,
    targets: new Map(published.map(({ period, recordDigest }) => [period, recordDigest]))
  })
  for (const [client, previous] of [
    [before, oldState],
    [after, newState]
  ]) {
    const revoked = await client.resolvePresence({ previous })
    t.is(revoked.present, false)
    t.is(revoked.revision, 8)
    t.alike(await client.resolvePresence({ previous: revoked }), revoked)
  }
})

test('missing overlap revocation target fails before publishing either tombstone', async (t) => {
  const controller = createFakeController()
  const client = clientFor(controller, Number(PERIOD_MS) - Number(OVERLAP_MS))
  const published = await client.publishPresence({ descriptor: b4a.from('keep'), revision: 1 })
  try {
    await client.revokePresence({
      revision: 2,
      scope: TOMBSTONE_SCOPE.RECORD,
      targets: new Map([[published[0].period, published[0].recordDigest]])
    })
    t.fail('missing target must fail')
  } catch (err) {
    t.is(err.code, 'INVALID_DESCRIPTOR')
  }
  for (const { publicKey } of published) {
    t.is((await controller.mutableGet(publicKey)).seq, 1)
  }
})

test('zero overlap revocation target fails before the first write', async (t) => {
  const controller = createFakeController()
  const client = clientFor(controller, Number(PERIOD_MS) - Number(OVERLAP_MS))
  const published = await client.publishPresence({ descriptor: b4a.from('keep'), revision: 1 })
  const targets = new Map(published.map(({ period, recordDigest }) => [period, recordDigest]))
  targets.set(published[1].period, b4a.alloc(32))
  controller.calls.length = 0
  try {
    await client.revokePresence({ revision: 2, scope: TOMBSTONE_SCOPE.RECORD, targets })
    t.fail('zero target must fail')
  } catch (err) {
    t.is(err.code, 'INVALID_DESCRIPTOR')
  }
  t.is(controller.calls.length, 0, 'invalid overlap targets cause no mutable writes')
  for (const { publicKey } of published) {
    t.is((await controller.mutableGet(publicKey)).seq, 1, 'published descriptor is unchanged')
  }
})

test('a controller cannot obtain a presence signature for substituted record bytes', async (t) => {
  for (const mutateInPlace of [false, true]) {
    let signatures = 0
    const controller = {
      async mutablePut(keyPair, value, options) {
        const substituted = mutateInPlace ? value : b4a.from(value)
        substituted[100] ^= 1
        await options.signMutable(options.seq, substituted, keyPair)
        signatures++
      },
      async mutableGet() {
        return null
      }
    }
    const client = clientFor(controller, 0)
    try {
      await client.publishPresence({ descriptor: b4a.from('original'), revision: 1 })
      t.fail('substituted bytes must not receive an owner signature')
    } catch (err) {
      t.is(err.code, 'UNAUTHORIZED')
    }
    t.is(signatures, 0, 'neither copied nor in-place substitutions are signed')
  }
})

for (const scope of [TOMBSTONE_SCOPE.PERIOD, TOMBSTONE_SCOPE.RECORD]) {
  test('new-period tombstone blocks stale old-period fallback: ' + scope, async (t) => {
    const controller = createFakeController()
    const before = clientFor(controller, Number(PERIOD_MS) - Number(OVERLAP_MS))
    const after = clientFor(controller, Number(PERIOD_MS) + 1_000)
    const published = await before.publishPresence({ descriptor: b4a.from('old'), revision: 7 })
    const oldState = await before.resolvePresence()
    const stale = await controller.mutableGet(published[0].publicKey)
    await before.revokePresence({
      revision: 8,
      scope,
      targets: new Map(published.map(({ period, recordDigest }) => [period, recordDigest]))
    })
    const tombstone = await after.resolvePresence({ previous: oldState })
    t.is(tombstone.period, 1n)
    t.is(tombstone.revision, 8)
    t.is(tombstone.present, scope === TOMBSTONE_SCOPE.PERIOD ? false : null)
    t.alike(await after.resolvePresence({ previous: tombstone }), tombstone)
    controller.mutableGet = async (publicKey) =>
      b4a.equals(publicKey, published[0].publicKey) ? stale : null
    try {
      await after.resolvePresence({ previous: tombstone })
      t.fail('an older period must not restore presence after observing a newer tombstone')
    } catch (err) {
      t.is(err.code, 'REPLAY')
    }
  })
}
