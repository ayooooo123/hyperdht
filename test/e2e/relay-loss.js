'use strict'

const test = require('brittle')
const b4a = require('b4a')
const network = require('./helpers/network')
const { DHT, closed, deadline } = network
const { exchange } = require('./helpers/traffic')

test('relay-loss: relay shutdown closes its session without disrupting ordinary traffic', async (t) => {
  const h = await network(t)
  const server = await h.listen()
  const pair = await h.pair(server)
  await exchange(pair.client, pair.remote)
  const relayKey = pair.client.rawStream.link.rawStream.remotePublicKey
  const selected = h.relays.find((relay) =>
    b4a.equals(h.controller(relay).relayKeyPair.publicKey, relayKey)
  )
  t.ok(selected, 'fault targets the actual source-adjacent relay')
  const otherSource = h.create()
  const otherDestination = h.create()
  await Promise.all([otherSource.privateRouting.ready(), otherDestination.privateRouting.ready()])
  const directServer = await h.listen({}, otherDestination, DHT.keyPair(), true)
  const direct = await h.pair(directServer, {}, otherSource, true)
  const closes = Promise.all([closed(pair.client), closed(pair.remote)])
  await deadline(selected.destroy({ force: true }), 'selected relay shutdown')
  await deadline(closes, 'failed route closure')
  t.alike(await exchange(direct.client, direct.remote), { up: 49157, down: 32771 })
  const retry = h.track(h.source.privateRouting.connect(server.publicKey))
  const ok = await deadline(retry.opened, 'explicit reconnect', 60000)
  if (ok) {
    t.absent(
      b4a.equals(retry.rawStream.link.rawStream.remotePublicKey, relayKey),
      'new connection excludes the destroyed relay'
    )
  } else {
    t.ok(
      h.errors.get(retry).some((error) => error.code === 'ERR_PRIVACY_UNAVAILABLE'),
      'explicit reconnect fails with the documented unavailable error'
    )
  }
  h.oracle.assertNoDirect(h.source, h.destination)
  t.pass('relay loss never enables direct destination fallback')
})
