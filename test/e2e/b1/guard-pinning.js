'use strict'

const test = require('../helpers/pending')
const b4a = require('b4a')
const network = require('../helpers/network')
const { closePair, deadline } = network
const { exchange } = require('../helpers/traffic')
const { decodeDescriptor } = require('../../../lib/private/overlay-descriptor-service')

test('B1 E6: ten refreshes retain healthy guards and loss selects the pinned alternate', async (t) => {
  const h = await network(t)
  const server = await h.listen()
  const guards = []
  const sourceGuards = []
  for (let i = 0; i <= 10; i++) {
    if (i) await server.controller._publish(server)
    guards.push(b4a.toString(decodeDescriptor(server._descriptor).destinationGuardPublicKey, 'hex'))
    const pair = await h.pair(server)
    sourceGuards.push(b4a.toString(pair.client.rawStream.link.rawStream.remotePublicKey, 'hex'))
    await exchange(pair.client, pair.remote, { up: 1027, down: 2053, seed: i + 1 })
    await closePair(pair)
  }
  t.is(new Set(guards).size, 1, 'healthy destination guard remains pinned across ten refreshes')
  t.is(new Set(sourceGuards).size, 1, 'healthy source guard remains pinned across connections')
  if (!h.scope.hasSeam) {
    t.fail('B1 read-only pinned alternate state is not installed')
    return
  }
  const snapshot = h.scope
    .guards(h.destination)
    .destinations.find((row) => b4a.equals(row.publicKey, server.publicKey))
  t.ok(
    snapshot && snapshot.current && snapshot.alternates.length > 0,
    'a validated current guard and ordered failover candidates are observable'
  )
  if (!snapshot || !snapshot.current || !snapshot.alternates.length) return
  const expected = snapshot.alternates[0].publicKey
  const selected = h.relays.find((node) =>
    b4a.equals(h.controller(node).relayKeyPair.publicKey, snapshot.current.publicKey)
  )
  const republished = new Promise((resolve) => {
    const stop = h.observe((event) => {
      if (event.type !== 'descriptor-published') return
      stop()
      resolve(event)
    })
  })
  await selected.destroy({ force: true })
  await deadline(republished, 'immediate publication after guard loss')
  const replacement = h.scope
    .guards(h.destination)
    .destinations.find((row) => b4a.equals(row.publicKey, server.publicKey))
  t.alike(
    replacement.current.publicKey,
    expected,
    'failover uses the previously pinned first alternate'
  )
  const pair = await h.pair(server)
  t.alike(await exchange(pair.client, pair.remote), { up: 49157, down: 32771 })
})
