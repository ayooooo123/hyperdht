'use strict'

const test = require('brittle')
const network = require('./helpers/network')
const { DHT, deadline } = network
const { pattern, receiver, exchange } = require('./helpers/traffic')

test('private-streams: unequal full-duplex payloads preserve exact bytes and sequence', async (t) => {
  const h = await network(t)
  const server = await h.listen()
  const { client, remote } = await h.pair(server, { keyPair: DHT.keyPair() })
  t.alike(await exchange(client, remote, { up: 65537, down: 32771 }), { up: 65537, down: 32771 })
  t.alike(client.remotePublicKey, server.publicKey, 'Noise authenticates the expected service key')
})

test('private-streams: writes before open retain their exact bytes', async (t) => {
  const h = await network(t)
  const upload = pattern(4099, 21)
  const download = pattern(8197, 64)
  const server = await h.listen()
  const incoming = new Promise((resolve, reject) =>
    server.once('connection', (remote) => {
      receiver(remote, upload).then(() => {
        remote.write(download)
        resolve()
      }, reject)
    })
  )
  const client = h.track(h.source.privateRouting.connect(server.publicKey))
  const received = receiver(client, download)
  client.write(upload)
  const result = await deadline(
    Promise.all([client.opened, received, incoming]),
    'pre-open write exchange'
  )
  t.is(result[0], true)
  t.is(result[1], download.length, 'independent reverse bytes arrive after the pre-open write')
})
