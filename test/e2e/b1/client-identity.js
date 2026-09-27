'use strict'

const test = require('../helpers/pending')
const b4a = require('b4a')
const network = require('../helpers/network')
const { DHT, closePair } = network
const { exchange } = require('../helpers/traffic')

test('B1 E5: destination and firewall see fresh application identities unless explicitly supplied', async (t) => {
  const h = await network(t)
  const seen = []
  const server = await h.listen({
    firewall(key) {
      seen.push(b4a.from(key))
      return false
    }
  })
  const keys = []
  for (let i = 0; i < 3; i++) {
    const pair = await h.pair(server)
    keys.push(b4a.from(pair.remote.remotePublicKey))
    await exchange(pair.client, pair.remote, { id: 'identity-' + i })
    await closePair(pair)
  }
  t.is(new Set(keys.map((key) => b4a.toString(key, 'hex'))).size, 3)
  t.absent(
    keys.some((key) => b4a.equals(key, h.source.defaultKeyPair.publicKey)),
    'the node default key is never used implicitly'
  )
  t.alike(seen, keys)
  const explicit = DHT.keyPair()
  const pair = await h.pair(server, { keyPair: explicit })
  t.alike(pair.remote.remotePublicKey, explicit.publicKey)
  t.alike(seen[3], explicit.publicKey)
})

test('B1 public-contract: private listeners require an explicit service key', async (t) => {
  const h = await network(t)
  const server = h.destination.privateRouting.createServer()
  t.teardown(() => server.close())
  let code = null
  try {
    await server.listen()
  } catch (error) {
    code = error.code
  }
  t.is(code, 'INVALID_ROUTE')
  t.ok(server._route === null, 'missing service identity never publishes a route')
})
