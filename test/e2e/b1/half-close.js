'use strict'

const test = require('../helpers/pending')
const network = require('../helpers/network')
const { closed, deadline } = network
const { pattern, receiver, event } = require('../helpers/traffic')

test('B1 R5: one-sided EOF reaches the peer while reverse traffic continues', async (t) => {
  const h = await network(t)
  const upload = pattern(4099, 21)
  const download = pattern(8197, 64)
  const server = await h.listen()
  let remoteStream = null
  let fins = 0
  h.observe((event) => {
    if (
      event.type === 'route-cell-opened' &&
      event.label === 'destination-endpoint' &&
      event.plaintext[4] === 2
    )
      fins++
  })
  const incoming = new Promise((resolve, reject) =>
    server.once('connection', (remote) => {
      remoteStream = remote
      const ended = event(remote, 'end')
      Promise.all([receiver(remote, upload), ended]).then(() => {
        t.ok(
          server._route.streams.has(remote.rawStream.streamId),
          'source EOF does not retire a still-writable reverse direction'
        )
        remote.end(download)
        resolve()
      }, reject)
    })
  )
  const client = h.track(h.source.privateRouting.connect(server.publicKey))
  const received = receiver(client, download)
  client.end(upload)
  const result = await deadline(
    Promise.all([client.opened, received, incoming]),
    'half-close exchange'
  )
  t.is(result[0], true)
  t.is(result[1], download.length, 'reverse bytes arrive after the destination observes source EOF')
  await deadline(Promise.all([closed(client), closed(remoteStream)]), 'two-sided EOF join')
  t.is(fins, 1, 'one local end delivers exactly one destination FIN')
  t.absent(
    server._route.streams.has(remoteStream.rawStream.streamId),
    'the ID retires after both directions finish'
  )
})
