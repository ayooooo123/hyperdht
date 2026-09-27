'use strict'

const test = require('../helpers/pending')
const b4a = require('b4a')
const network = require('../helpers/network')
const { closed, deadline } = network
const { exchange, pattern } = require('../helpers/traffic')

test('B1 R5: source reset reaches the peer, retires its ID, and late frames cannot affect siblings', async (t) => {
  const h = await network(t)
  const server = await h.listen()
  const first = await h.pair(server)
  const firstId = Array.from(server._route.streams.keys())[0]
  const sourceId = first.client.rawStream.streamId
  const sibling = await h.pair(server)
  let resets = 0
  let started
  const sending = new Promise((resolve) => {
    started = resolve
  })
  h.observe((event) => {
    if (
      event.type === 'route-cell-sealed' &&
      event.label === 'source-endpoint' &&
      event.plaintext[4] === 0 &&
      event.plaintext.readUInt32BE(0) === sourceId
    )
      started()
    if (
      event.type === 'route-cell-opened' &&
      event.label === 'destination-endpoint' &&
      event.plaintext[4] === 3 &&
      event.plaintext.readUInt32BE(0) === firstId
    )
      resets++
  })
  first.remote.resume()
  t.absent(
    first.client.write(pattern(65536)),
    'the reset interrupts a backpressured application write'
  )
  await deadline(sending, 'first in-flight DATA cell')
  const closes = Promise.all([closed(first.client), closed(first.remote)])
  first.client.destroy()
  await deadline(closes, 'reset propagation')
  t.is(resets, 1, 'one local destroy delivers exactly one destination RESET')
  t.ok(server._route.retiredStreams.has(firstId), 'the peer retires the reset stream')
  t.alike(await exchange(sibling.client, sibling.remote, { id: 'sibling-before-late' }), {
    up: 49157,
    down: 32771
  })
  for (const flag of [3, 0]) {
    const late = b4a.alloc(flag === 0 ? 6 : 5)
    late.writeUInt32BE(firstId, 0)
    late[4] = flag
    await server._route.link.send(late)
  }
  t.alike(await exchange(sibling.client, sibling.remote, { id: 'sibling-after-late' }), {
    up: 49157,
    down: 32771
  })
  t.absent(server._route.streams.has(firstId), 'late data does not revive the retired source')
  const next = await h.pair(server)
  t.ok(
    Array.from(server._route.streams.keys()).every((id) => id > firstId),
    'later connections never reuse the retired stream ID'
  )
  t.alike(await exchange(next.client, next.remote, { id: 'next' }), { up: 49157, down: 32771 })
})
