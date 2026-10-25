'use strict'

const test = require('../helpers/pending')
const network = require('../helpers/network')
const { deadline } = network
const { pattern, receiver, exchange, observeFlow } = require('../helpers/traffic')

test('B1 multiplex-isolation: a paused bulk reader preserves sibling traffic and backpressure', async (t) => {
  const h = await network(t)
  const flow = observeFlow(h)
  t.teardown(() => flow.close())
  const server = await h.listen()
  const slow = await h.pair(server)
  const sibling = await h.pair(server)
  const bytes = pattern(1048576, 191)
  const received = receiver(slow.remote, bytes)
  slow.remote.pause()
  const accepted = slow.client.write(bytes)
  t.is(accepted, false, 'bulk application writes expose backpressure')
  await deadline(flow.whenSaturated(), 'paused reader exhausts its 512-cell raw stream window')
  const independent = exchange(sibling.client, sibling.remote, { id: 'independent-reader' }).then(
    (result) => {
      t.alike(result, { up: 49157, down: 32771 })
      t.ok(
        flow.counts.controlWhileSaturated > 0,
        'control traffic reaches an endpoint while the paused stream has exhausted its DATA credit'
      )
      slow.remote.resume()
    }
  )
  const result = await deadline(Promise.all([received, independent]), 'slow reader isolation')
  t.is(result[0], bytes.length, 'resuming the reader delivers every buffered byte exactly once')
  flow.assertBounds(t)
})
