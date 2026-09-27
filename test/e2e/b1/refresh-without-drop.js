'use strict'

const test = require('../helpers/pending')
const b4a = require('b4a')
const network = require('../helpers/network')
const { exchange } = require('../helpers/traffic')

test('B1 refresh-without-drop: admitted streams survive make-before-break publication', async (t) => {
  const h = await network(t)
  const server = await h.listen()
  const originalRoute = server._route
  const descriptor = b4a.from(server._descriptor)
  const live = await h.pair(server)
  await exchange(live.client, live.remote, { id: 'before-refresh' })
  await server.controller._publish(server)
  t.absent(
    b4a.equals(server._descriptor, descriptor),
    'refresh publishes a new authenticated descriptor'
  )
  t.not(server._route, originalRoute, 'new admissions use the new route generation')
  t.absent(originalRoute.closed, 'the old route remains alive for admitted sessions')
  t.alike(await exchange(live.client, live.remote, { id: 'after-refresh' }), {
    up: 49157,
    down: 32771
  })
  const newcomer = await h.pair(server)
  t.alike(await exchange(newcomer.client, newcomer.remote, { id: 'new-generation' }), {
    up: 49157,
    down: 32771
  })
  h.oracle.assertNoDirect(h.source, h.destination)
})
