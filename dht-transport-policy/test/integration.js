const test = require('brittle')
const net = require('net')
const createTestnet = require('hyperdht/testnet')
const DHT = require('hyperdht')
const RelayedDHT = require('@hyperswarm/dht-relay')
const { relay } = require('@hyperswarm/dht-relay')
const { wrap } = require('dht-relay-tor')
const { TrustList, TransportRouter } = require('..')

// The whole reconciliation, end to end: one app reaches a trusted peer over the
// direct (holepunched) transport and an untrusted peer over the masked (relayed)
// transport, chosen purely by the trust list. The relayed leg uses localhost TCP
// in place of Tor — the same code path a real Tor client takes.
test('routes trusted peers direct and untrusted peers masked, both connect', async (t) => {
  const testnet = await createTestnet(4, t.teardown)
  const { bootstrap } = testnet

  const echo = (prefix) => (conn) => {
    conn.on('error', () => {})
    conn.on('data', (d) => conn.write(Buffer.concat([Buffer.from(prefix), d])))
  }

  // Two service peers on the swarm.
  const dhtA = new DHT({ bootstrap })
  const serverA = dhtA.createServer(echo('A:'))
  await serverA.listen()

  const dhtB = new DHT({ bootstrap })
  const serverB = dhtB.createServer(echo('B:'))
  await serverB.listen()

  // Direct transport: an ordinary hyperdht client.
  const direct = new DHT({ bootstrap })

  // Masked transport: a relay node + a relayed client over it.
  const relayDHT = new DHT({ bootstrap })
  const tcp = net.createServer((socket) => {
    const stream = wrap(false, socket)
    relay(relayDHT, stream)
    stream.on('error', () => {})
  })
  await new Promise((r) => tcp.listen(0, '127.0.0.1', r))
  const relaySocket = net.connect(tcp.address().port, '127.0.0.1')
  const masked = new RelayedDHT(wrap(true, relaySocket))
  await masked.ready()

  // Trust only peer A -> A goes direct, B goes masked.
  const trust = new TrustList([serverA.publicKey])
  const router = new TransportRouter({ direct, masked, trust })

  t.is(router.mode(serverA.publicKey), 'direct')
  t.is(router.mode(serverB.publicKey), 'masked')

  const roundtrip = (conn, msg) =>
    new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('timed out')), 20000)
      conn.on('error', reject)
      conn.on('open', () => conn.write(Buffer.from(msg)))
      conn.on('data', (d) => {
        clearTimeout(timer)
        resolve(d.toString())
      })
    })

  const connA = router.connect(serverA.publicKey)
  const connB = router.connect(serverB.publicKey)
  const [replyA, replyB] = await Promise.all([roundtrip(connA, 'hi'), roundtrip(connB, 'hi')])

  t.is(replyA, 'A:hi', 'trusted peer reached over the direct transport')
  t.is(replyB, 'B:hi', 'untrusted peer reached over the masked transport')

  connA.destroy()
  connB.destroy()
  await masked.destroy().catch(() => {})
  relaySocket.destroy()
  await new Promise((r) => tcp.close(r))
  await router.destroy()
  await direct.destroy()
  await relayDHT.destroy()
  await serverA.close()
  await dhtA.destroy()
  await serverB.close()
  await dhtB.destroy()
})
