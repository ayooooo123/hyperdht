'use strict'

const test = require('brittle')
const b4a = require('b4a')
const network = require('./helpers/network')
const { DHT, closed, deadline } = network
const { exchange } = require('./helpers/traffic')

test('firewall: only authenticated application identities reach admission', async (t) => {
  const h = await network(t)
  const allowed = DHT.keyPair()
  const refused = DHT.keyPair()
  const identities = []
  let accepted = 0
  let applicationBytes = 0
  const server = await h.listen({
    firewall(key) {
      identities.push(b4a.from(key))
      return !b4a.equals(key, allowed.publicKey)
    }
  })
  server.on('connection', (stream) => {
    accepted++
    stream.on('data', (chunk) => {
      applicationBytes += chunk.length
    })
  })
  const denied = h.track(h.source.privateRouting.connect(server.publicKey, { keyPair: refused }))
  const denialClosed = closed(denied)
  denied.write(b4a.from('must not reach the application'))
  await deadline(denialClosed, 'firewall rejection')
  t.is(accepted, 0)
  t.is(applicationBytes, 0)
  t.alike(identities, [refused.publicKey], 'refused identity is the application Noise key')
  const { client, remote } = await h.pair(server, { keyPair: allowed })
  t.alike(await exchange(client, remote), { up: 49157, down: 32771 })
  t.is(accepted, 1)
  t.alike(identities, [refused.publicKey, allowed.publicKey])
  for (const relay of h.relays) {
    t.absent(
      identities.some((key) => b4a.equals(key, h.controller(relay).relayKeyPair.publicKey)),
      'relay identity never substitutes for application identity'
    )
  }
})
