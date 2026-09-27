'use strict'

const test = require('brittle')
const network = require('./helpers/network')
const { closed, deadline } = network
const { exchange } = require('./helpers/traffic')

test('multiplex-isolation: local reset leaves a live sibling and later sessions usable', async (t) => {
  const h = await network(t)
  const server = await h.listen()
  const first = await h.pair(server)
  const firstId = Array.from(server._route.streams.keys())[0]
  const sibling = await h.pair(server)
  await exchange(first.client, first.remote, { id: 'first' })
  const closes = closed(first.client)
  first.client.destroy()
  await deadline(closes, 'reset propagation')
  t.alike(await exchange(sibling.client, sibling.remote, { id: 'sibling-before-late' }), {
    up: 49157,
    down: 32771
  })
  const next = await h.pair(server)
  t.ok(next.remote.rawStream.streamId > firstId, 'later connection receives a new stream ID')
  t.alike(await exchange(next.client, next.remote, { id: 'next' }), { up: 49157, down: 32771 })
})
