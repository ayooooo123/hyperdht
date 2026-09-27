'use strict'

const test = require('brittle')
const b4a = require('b4a')
const network = require('./helpers/network')
const { DHT, closed, closePair, deadline } = network
const { exchange } = require('./helpers/traffic')

test('no-direct: ephemeral endpoints remain separated through setup, refresh, retry and resume', async (t) => {
  const h = await network(t)
  t.is(h.source.ephemeral, true)
  t.is(h.destination.ephemeral, true)
  t.is(h.source._persistent, null)
  t.is(h.destination._persistent, null)
  const server = await h.listen()
  const initial = await h.pair(server)
  await exchange(initial.client, initial.remote)
  await closePair(initial)
  h.oracle.phase('refresh')
  await server.controller._publish(server)
  const refreshed = await h.pair(server)
  await exchange(refreshed.client, refreshed.remote)
  h.oracle.phase('route-loss')
  const lost = closed(refreshed.client)
  server._route.link.rawStream.destroy()
  await deadline(lost, 'route-loss close')
  await server.controller._publish(server)
  const retry = await h.pair(server)
  await exchange(retry.client, retry.remote)
  h.oracle.phase('suspend')
  await Promise.all([h.source.suspend(), h.destination.suspend()])
  h.oracle.phase('resume')
  await Promise.all([h.source.resume(), h.destination.resume()])
  const resumed = await h.pair(server)
  await exchange(resumed.client, resumed.remote)
  h.oracle.phase('teardown')
  await h.destroy()
  t.alike(
    h.oracle.forbidden(h.source, h.destination),
    [],
    'all socket generations and native associations avoid every destination-owned tuple'
  )
  h.oracle.assertNoDirect(h.source, h.destination)
})

test('no-direct negative control: an explicit datagram trips the same detector', async (t) => {
  const h = await network(t)
  h.oracle.assertNoDirect(h.source, h.destination)
  h.oracle.phase('direct-datagram-control')
  const address = h.destination.io.serverSocket.address()
  await h.source.io.serverSocket.send(b4a.from('negative-control'), address.port, '127.0.0.1')
  t.exception(
    () => h.oracle.assertNoDirect(h.source, h.destination),
    /Forbidden destination UDP attempts/
  )
  t.ok(h.oracle.forbidden(h.source, h.destination).some((row) => row.method === 'send'))
})

test('no-direct negative control: an ordinary connection with data trips native-stream detection', async (t) => {
  const h = await network(t)
  h.oracle.assertNoDirect(h.source, h.destination)
  h.oracle.phase('direct-stream-control')
  const server = await h.listen({}, h.destination, DHT.keyPair(), true)
  const pair = await h.pair(server, {}, h.source, true)
  t.alike(await exchange(pair.client, pair.remote), { up: 49157, down: 32771 })
  t.exception(
    () => h.oracle.assertNoDirect(h.source, h.destination),
    /Forbidden destination UDP attempts/
  )
  t.ok(h.oracle.forbidden(h.source, h.destination).some((row) => row.method === 'connect'))
  t.ok(h.oracle.forbidden(h.source, h.destination).some((row) => row.method === 'stream._writev'))
})
