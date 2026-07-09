const test = require('brittle')
const net = require('net')
const createTestnet = require('hyperdht/testnet')
const DHT = require('hyperdht')
const RelayedDHT = require('@hyperswarm/dht-relay')
const { relay } = require('@hyperswarm/dht-relay')
const { wrap } = require('..')

// Exercises the exact path a Tor-masked client uses — the relay protocol over
// the transport's secret-stream Duplex — without needing Tor. The relayed client
// reaches the relay over localhost TCP; swapping that for socks5Connect (i.e.
// index.connect) is the only difference for real Tor.
test('relayed client connects to a swarm peer over the transport', async (t) => {
  const testnet = await createTestnet(4, t.teardown)
  const { bootstrap } = testnet

  // A normal peer offering a service on the swarm (full UDP presence).
  const serverDHT = new DHT({ bootstrap })
  const server = serverDHT.createServer((conn) => {
    conn.on('error', () => {})
    conn.on('data', (d) => conn.write(Buffer.concat([Buffer.from('echo:'), d])))
  })
  await server.listen()

  // The relay node: full UDP presence + a local TCP endpoint bridged in.
  const relayDHT = new DHT({ bootstrap })
  const tcp = net.createServer((socket) => {
    const stream = wrap(false, socket)
    relay(relayDHT, stream)
    stream.on('error', () => {})
  })
  await new Promise((r) => tcp.listen(0, '127.0.0.1', r))

  // The masked client: no UDP socket of its own; speaks the DHT over the stream.
  const socket = net.connect(tcp.address().port, '127.0.0.1')
  const clientDHT = new RelayedDHT(wrap(true, socket))
  await clientDHT.ready()

  const conn = clientDHT.connect(server.publicKey)
  const reply = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timed out')), 20000)
    conn.on('error', reject)
    conn.on('open', () => conn.write(Buffer.from('hi')))
    conn.on('data', (d) => {
      clearTimeout(timer)
      resolve(d.toString())
    })
  })

  t.is(reply, 'echo:hi', 'connection established through the relayed transport')

  conn.destroy()
  await clientDHT.destroy().catch(() => {})
  socket.destroy()
  await new Promise((r) => tcp.close(r))
  await relayDHT.destroy()
  await server.close()
  await serverDHT.destroy()
})
