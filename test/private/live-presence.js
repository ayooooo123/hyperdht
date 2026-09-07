'use strict'

const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-universal')
const c = require('compact-encoding')
const DHT = require('dht-rpc')
const crypto = require('hypercore-crypto')

const { COMMANDS } = require('../../lib/constants')
const m = require('../../lib/messages')
const {
  RECORD_TYPE,
  TOMBSTONE_SCOPE,
  createBlindedSigner,
  deriveBlindedPublicKey,
  encodePresenceRecord,
  openPresenceRecord,
  recordDigestOf,
  resolvePresenceState
} = require('../../lib/private/blinded-presence')
const { createPresenceClient } = require('../../lib/private/presence-client')
const { createQueryContexts } = require('../../lib/private/query-context')
const { RoutedDHTIO } = require('../../lib/private/routed-dht-io')
const { LiveRouteAuthority } = require('../../lib/private/live-route-authority')
const {
  closeLiveAuthorityHarness,
  dhtResponseFor,
  liveAuthorityHarness,
  waitFor
} = require('./routed-dht-traversal')

const IDENTITY = crypto.keyPair(b4a.alloc(32, 0x61))
const READER = b4a.alloc(32, 0x71)

function queryOptions(context) {
  return {
    transportContext: context,
    concurrency: 1,
    retries: 1
  }
}

async function waitForSend(fakeSocket, target) {
  let index = -1
  await waitFor(() => {
    index = fakeSocket.sends.findIndex((send) => b4a.includes(send.packet, target))
    return index !== -1
  })
  return index
}

function createMemoryController() {
  const store = new Map()
  return {
    async mutablePut(keyPair, value, opts = {}) {
      const seq = opts.seq || 0
      const signature = await opts.signMutable(seq, value, keyPair)
      store.set(b4a.toString(keyPair.publicKey, 'hex'), {
        seq,
        value: b4a.from(value),
        signature: b4a.from(signature)
      })
      return Object.freeze({
        publicKey: b4a.from(keyPair.publicKey),
        seq,
        signature: b4a.from(signature)
      })
    },
    async mutableGet(publicKey) {
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

test('live client publish then resolve then revoke then resolve', async (t) => {
  const controller = createMemoryController()
  const client = createPresenceClient({
    controller,
    identityKeyPair: IDENTITY,
    readerSecret: READER,
    now: () => 10_000
  })

  const published = await client.publishPresence({
    descriptor: b4a.from('live-route-descriptor'),
    revision: 1
  })
  t.is(published.length, 1)

  const resolved = await client.resolvePresence()
  t.is(resolved.present, true)
  t.alike(resolved.descriptor, b4a.from('live-route-descriptor'))
  t.is(resolved.revision, 1)

  await client.revokePresence({
    revision: 2,
    scope: TOMBSTONE_SCOPE.PERIOD
  })
  const revoked = await client.resolvePresence({
    previous: resolved
  })
  t.is(revoked.present, false)

  await client.publishPresence({
    descriptor: b4a.from('reenabled'),
    revision: 3
  })
  const again = await client.resolvePresence({
    previous: revoked
  })
  t.is(again.present, true)
  t.alike(again.descriptor, b4a.from('reenabled'))
})

test('live mutable get on lookup branch returns a real presence record', async (t) => {
  // Harness pattern copied from test/private/live-mutable-and-put.js.
  // Announce-branch mutable put is not exercised end-to-end here: the live
  // FakeDhtSocket harness stubs put success without durable storage, and
  // PrivateRoutingController READY bootstrap is outside this gate's OWN set.
  // Publish is performed with the real codec/signer; resolve goes through the
  // live lookup branch and openPresenceRecord.
  const harness = await liveAuthorityHarness((manager) => manager)
  const authority = new LiveRouteAuthority({ routeManager: harness.manager })
  t.teardown(async () => {
    try {
      await closeLiveAuthorityHarness(harness)
    } catch {}
  })

  const period = 0n
  const revision = 11
  const signer = createBlindedSigner(IDENTITY, period)
  let encoded
  let signature
  try {
    encoded = encodePresenceRecord({
      signer,
      period,
      revision,
      readerSecret: READER,
      type: RECORD_TYPE.DESCRIPTOR,
      descriptor: b4a.from('routed-presence')
    })
    signature = encoded.signMutable(revision, encoded.value, { publicKey: encoded.publicKey })
  } finally {
    signer.destroy()
  }

  const publicKey = encoded.publicKey
  const target = b4a.alloc(32)
  sodium.crypto_generichash(target, publicKey)
  const payload = c.encode(m.mutableGetResponse, {
    seq: revision,
    value: encoded.value,
    signature
  })

  const contexts = createQueryContexts()
  const routed = new RoutedDHTIO({
    authority,
    contexts,
    now: () => Number(harness.topology.clock.monotonicNow()),
    randomBytes(buffer) {
      buffer.fill(0x55)
    }
  })
  const dht = new DHT({
    outboundPolicy: 'transport-only',
    requestTransport: routed,
    requestTimeout: 1_000,
    concurrency: 1
  })

  const upstream = (async () => {
    const requestIndex = await waitForSend(harness.fakeSocket, target)
    const valueWire = c.encode(c.buffer, payload)
    harness.fakeSocket.message(
      dhtResponseFor(harness.fakeSocket.sends[requestIndex].packet, 0x10, valueWire),
      {
        host: '8.8.8.8',
        port: 49737
      }
    )
  })()

  const query = dht.query(
    { target, command: COMMANDS.MUTABLE_GET, value: c.encode(c.uint, 0) },
    queryOptions(contexts.mutableGet.lookup)
  )
  const replies = []
  for await (const reply of query) replies.push(reply)
  await upstream

  t.ok(replies.length >= 1)
  const hit = replies.find((reply) => reply.value)
  t.ok(hit)
  t.alike(hit.value, payload)
  const decoded = c.decode(m.mutableGetResponse, hit.value)
  t.is(decoded.seq, revision)
  t.alike(decoded.value, encoded.value)

  const opened = openPresenceRecord({
    identityPublicKey: IDENTITY.publicKey,
    period,
    revision: decoded.seq,
    readerSecret: READER,
    value: decoded.value,
    signature: decoded.signature
  })
  t.is(opened.type, RECORD_TYPE.DESCRIPTOR)
  t.alike(opened.descriptor, b4a.from('routed-presence'))
  t.alike(publicKey, deriveBlindedPublicKey(IDENTITY.publicKey, period))

  await dht.destroy()
  await routed.destroy()
})

test('live record-scope tombstone ignores mismatched digest then clears on match', async (t) => {
  const controller = createMemoryController()
  const client = createPresenceClient({
    controller,
    identityKeyPair: IDENTITY,
    readerSecret: READER,
    now: () => 20_000
  })

  await client.publishPresence({
    descriptor: b4a.from('to-tombstone'),
    revision: 1
  })
  const previous = await client.resolvePresence()

  await client.revokePresence({
    revision: 2,
    scope: TOMBSTONE_SCOPE.RECORD,
    targets: new Map([[previous.period, b4a.alloc(32, 0xee)]])
  })
  const ignored = await client.resolvePresence({ previous })
  t.is(ignored.present, null)
  t.is(ignored.ignoredTombstone, true)

  await client.revokePresence({
    revision: 3,
    scope: TOMBSTONE_SCOPE.RECORD,
    targets: new Map([[previous.period, previous.recordDigest]])
  })
  const cleared = await client.resolvePresence({ previous })
  t.is(cleared.present, false)

  // Direct state helper still rejects replay of the original descriptor.
  const signer = createBlindedSigner(IDENTITY, 0n)
  try {
    const encoded = encodePresenceRecord({
      signer,
      period: 0n,
      revision: 1,
      readerSecret: READER,
      type: RECORD_TYPE.DESCRIPTOR,
      descriptor: b4a.from('to-tombstone')
    })
    t.is(recordDigestOf(encoded.value).byteLength, 32)
    t.exception(() =>
      resolvePresenceState({
        previous: cleared,
        opened: {
          type: RECORD_TYPE.DESCRIPTOR,
          period: 0n,
          revision: 1,
          descriptor: b4a.from('to-tombstone'),
          recordDigest: recordDigestOf(encoded.value)
        }
      })
    )
  } finally {
    signer.destroy()
  }
})
