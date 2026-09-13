'use strict'

const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-universal')
const c = require('compact-encoding')
const DHT = require('dht-rpc')

const { COMMANDS } = require('../../lib/constants')
const m = require('../../lib/messages')
const { IMMUTABLE_GET_POLICIES, encodeDHTRequest } = require('../../lib/private/dht-command-policy')
const { createQueryContexts } = require('../../lib/private/query-context')
const { RoutedDHTIO } = require('../../lib/private/routed-dht-io')
const { LiveRouteAuthority } = require('../../lib/private/live-route-authority')
const {
  closeLiveAuthorityHarness,
  dhtResponseFor,
  liveAuthorityHarness,
  waitFor
} = require('./routed-dht-traversal')

function queryOptions(context) {
  return {
    transportContext: context,
    concurrency: 1,
    retries: 1
  }
}

// The exit's first sends are seed probes whose count depends on prior harness
// state, so locate the routed request by the target it carries.
async function waitForSend(fakeSocket, target) {
  let index = -1
  await waitFor(() => {
    index = fakeSocket.sends.findIndex((send) => b4a.includes(send.packet, target))
    return index !== -1
  })
  return index
}

test('live mutable get on lookup branch forwards raw response bytes', async (t) => {
  // A bare harness reuses the shared route material, whose payload nonce
  // domain is already claimed by the traversal suite in this process.
  const harness = await liveAuthorityHarness((manager) => manager)
  const authority = new LiveRouteAuthority({ routeManager: harness.manager })
  t.teardown(async () => {
    try {
      await closeLiveAuthorityHarness(harness)
    } catch {}
  })
  const contexts = createQueryContexts()
  const publicKey = b4a.alloc(32, 0x77)
  const target = b4a.alloc(32)
  sodium.crypto_generichash(target, publicKey)
  const payload = c.encode(m.mutableGetResponse, {
    seq: 2,
    value: b4a.from('mutable-live'),
    signature: b4a.alloc(64, 0x88)
  })
  const routed = new RoutedDHTIO({
    authority,
    contexts,
    now: () => Number(harness.topology.clock.monotonicNow()),
    randomBytes(buffer) {
      buffer.fill(0x56)
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

  await dht.destroy()
  await routed.destroy()
})

test('findPeer lookup announce remain unsupported through query contexts', (t) => {
  const contexts = createQueryContexts()
  const cases = [
    () => contexts.classify({}),
    () => contexts.classify(contexts.immutablePut.lookup),
    () => contexts.classify(contexts.mutablePut.lookup),
    () =>
      encodeDHTRequest(IMMUTABLE_GET_POLICIES.lookup, {
        command: COMMANDS.FIND_PEER,
        target: b4a.alloc(32),
        value: null
      }),
    () =>
      encodeDHTRequest(IMMUTABLE_GET_POLICIES.lookup, {
        command: COMMANDS.LOOKUP,
        target: b4a.alloc(32),
        value: null
      }),
    () =>
      encodeDHTRequest(IMMUTABLE_GET_POLICIES.lookup, {
        command: COMMANDS.ANNOUNCE,
        target: b4a.alloc(32),
        value: null
      })
  ]
  for (const run of cases) {
    let error = null
    try {
      run()
    } catch (err) {
      error = err
    }
    t.is(error && error.code, 'ERR_PRIVATE_COMMAND_UNSUPPORTED')
  }
})

test('Gate 3B query contexts expose put and mutable maps', (t) => {
  const contexts = createQueryContexts()
  t.alike(Object.keys(contexts), [
    'immutableGet',
    'immutablePut',
    'mutableGet',
    'mutablePut',
    'classify'
  ])
  t.ok(contexts.immutablePut.announce)
  t.ok(contexts.mutableGet.lookup)
  t.ok(contexts.mutableGet.announce)
  t.ok(contexts.mutablePut.announce)
  t.is(contexts.immutablePut.lookup, undefined)
  t.is(contexts.mutablePut.lookup, undefined)
})
