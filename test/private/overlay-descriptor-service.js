'use strict'

const test = require('brittle')
const b4a = require('b4a')
const HyperDHT = require('../..')
const { periodOf } = require('../../lib/private/blinded-presence')
const {
  OverlayDescriptorService,
  descriptorTarget,
  encodeDescriptor
} = require('../../lib/private/overlay-descriptor-service')

function createService(t, now) {
  const service = new OverlayDescriptorService(
    {
      register: (name, plugin) => plugin.onregister({}),
      session: () => ({ destroy() {} })
    },
    null,
    () => now
  )
  t.teardown(() => service.destroy())
  return service
}

function replies(values, closestReplies = values) {
  return {
    closestReplies,
    destroy() {},
    async *[Symbol.asyncIterator]() {
      for (const value of values) yield value
    }
  }
}

test('descriptor publication survives fast nonclosest storage replies and resolves from a disjoint vantage', async (t) => {
  const now = Date.now()
  const destinationKeyPair = HyperDHT.keyPair()
  const wire = encodeDescriptor({
    destinationKeyPair,
    entryRelayPublicKey: HyperDHT.keyPair().publicKey,
    destinationGuardPublicKey: HyperDHT.keyPair().publicKey,
    routeToken: b4a.alloc(32, 0x39),
    seq: BigInt(now),
    expiresAt: BigInt(now + 60_000),
    period: periodOf(now)
  })
  const writer = createService(t, now)
  const reader = createService(t, now)
  const storage = new Map()
  const fast = []
  const closest = []
  for (let port = 1; port <= 11; port++) {
    const row = { from: { host: '127.0.0.1', port }, token: b4a.alloc(32, port) }
    storage.set(port, { service: createService(t, now), accepts: port > 8 })
    ;(port <= 8 ? fast : closest).push(row)
  }
  const putPeers = []
  const readbackPeers = []
  function request(message, from) {
    const node = storage.get(from.port)
    if (message.command === 1) {
      putPeers.push(from.port)
      if (!node.accepts) return Promise.resolve({ from, value: null })
    } else {
      readbackPeers.push(from.port)
    }
    return new Promise((resolve, reject) => {
      let replied = false
      node.service.plugin.onrequest(message, {
        target: message.target,
        token: message.token,
        reply(value) {
          replied = true
          resolve({ from, value })
        }
      })
      if (!replied) reject(new Error('Storage did not acknowledge the request'))
    })
  }
  writer.plugin.query = () => replies([...fast, ...closest], closest)
  writer.plugin.request = request
  reader.plugin.query = (message) => ({
    destroy() {},
    async *[Symbol.asyncIterator]() {
      for (const row of closest) yield await request(message, row.from)
    }
  })

  let failure = null
  let stored = null
  try {
    stored = await writer.put(wire)
  } catch (error) {
    failure = error.code
  }
  t.is(failure, null, 'early acknowledgements cannot displace the actual closest storage nodes')
  t.is(stored, 3)
  t.alike(putPeers, [9, 10, 11], 'publication uses the completed lookup closest set')
  t.alike(readbackPeers, [9, 10, 11], 'publication reads back from the same closest storage nodes')
  if (failure === null) {
    const resolved = await reader.get(destinationKeyPair.publicKey)
    t.alike(resolved.wire, wire, 'an independent lookup vantage retrieves the published route')
  }
})

test('blinded-target resolution rejects a valid descriptor for another target', async (t) => {
  const now = Date.now()
  const period = periodOf(now)
  const identity = HyperDHT.keyPair()
  const wire = encodeDescriptor({
    destinationKeyPair: identity,
    entryRelayPublicKey: HyperDHT.keyPair().publicKey,
    destinationGuardPublicKey: HyperDHT.keyPair().publicKey,
    routeToken: b4a.alloc(32, 0x18),
    seq: BigInt(now),
    expiresAt: BigInt(now + 60_000),
    period
  })
  const reader = createService(t, now)
  reader.plugin.query = () => replies([{ value: wire }, { value: wire }])
  const correct = descriptorTarget(identity.publicKey, period)
  const wrong = descriptorTarget(HyperDHT.keyPair().publicKey, period)
  const resolved = await reader.getByTarget(correct, period)
  t.alike(resolved.wire, wire)
  let failure = null
  try {
    await reader.getByTarget(wrong, period)
  } catch (error) {
    failure = error.code
  }
  t.is(failure, 'INVALID_ROUTE', 'a signature quorum does not authorize a different target')
})
