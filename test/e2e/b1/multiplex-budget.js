'use strict'

const test = require('../helpers/pending')
const network = require('../helpers/network')
const { closePair } = network
const { exchange, observeFlow } = require('../helpers/traffic')

test('B1 multiplex-isolation: seventy sequential sessions do not exhaust a live sibling route', async (t) => {
  const h = await network(t)
  const flow = observeFlow(h)
  t.teardown(() => flow.close())
  const server = await h.listen()
  const sibling = await h.pair(server)
  const ids = new Set()
  for (let i = 0; i < 70; i++) {
    const pair = await h.pair(server)
    for (const id of server._route.streams.keys()) ids.add(id)
    await exchange(pair.client, pair.remote, { up: 259, down: 131, id: 'sequential-' + i })
    await closePair(pair)
  }
  t.is(ids.size, 71, 'live generation does not recycle lifetime stream identifiers')
  t.alike(await exchange(sibling.client, sibling.remote, { id: 'surviving-sibling' }), {
    up: 49157,
    down: 32771
  })
  flow.assertBounds(t, { streamCredit: false })
})
