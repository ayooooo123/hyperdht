'use strict'

// End-to-end verification of the masked-transport seam, WITHOUT needing Tor.
//
// It stands up a self-contained local swarm and exercises the exact code path a
// Tor-masked client would use — the relay protocol running over a secret-stream
// Duplex — differing only in that the client reaches the relay over localhost
// TCP instead of a Tor circuit. If this passes, the Tor variant is just a
// socket-swap (see lib/tor-transport.js `connect`).
//
//   plain server peer  <— DHT holepunch —>  relay node  <— secret-stream —>  masked client
//        (on swarm)                          (on swarm)         (localhost TCP)
//
// The masked client never joins the UDP swarm; the relay node does it on its
// behalf. Run: `node demo-local.js`

const net = require('net')
const createTestnet = require('hyperdht/testnet')
const DHT = require('hyperdht')
const RelayedDHT = require('@hyperswarm/dht-relay')
const { relay } = require('@hyperswarm/dht-relay')
const { wrap } = require('./lib/tor-transport')

function log (...a) { console.log('[demo]', ...a) }

async function main () {
  const testnet = await createTestnet(4)
  const bootstrap = testnet.bootstrap
  log('local testnet up, bootstrap =', bootstrap.map(b => b.host + ':' + b.port).join(','))

  // 1) A normal peer that offers a service on the swarm (full UDP presence).
  const serverDHT = new DHT({ bootstrap })
  const server = serverDHT.createServer((conn) => {
    conn.on('data', (d) => conn.write(Buffer.concat([Buffer.from('echo:'), d])))
    conn.on('error', () => {})
  })
  await server.listen()
  const serverKey = server.publicKey
  log('service peer listening, publicKey =', serverKey.toString('hex').slice(0, 16) + '…')

  // 2) The relay node: full UDP presence + a local TCP endpoint bridging into it.
  const relayDHT = new DHT({ bootstrap })
  const tcp = net.createServer((socket) => {
    const stream = wrap(false, socket) // isInitiator=false on the relay side
    relay(relayDHT, stream)
    stream.on('error', () => {})
  })
  await new Promise((r) => tcp.listen(0, '127.0.0.1', r))
  const relayPort = tcp.address().port
  log('relay node bridging on tcp://127.0.0.1:' + relayPort)

  // 3) The masked client. It reaches the relay over a socket and speaks the
  //    relay protocol over secret-stream. *** This is the Tor seam. ***
  //    For the real thing you'd replace these two lines with:
  //        const stream = await require('./lib/tor-transport').connect({ onion, port })
  const socket = net.connect(relayPort, '127.0.0.1')
  const stream = wrap(true, socket) // isInitiator=true on the client side
  const clientDHT = new RelayedDHT(stream)
  await clientDHT.ready()
  log('masked client ready — it has a DHT handle but no UDP socket of its own')

  // 4) The masked client connects to the service peer THROUGH the relayed DHT.
  const conn = clientDHT.connect(serverKey)
  const got = await new Promise((resolve, reject) => {
    const to = setTimeout(() => reject(new Error('timed out waiting for echo')), 20000)
    conn.on('open', () => conn.write(Buffer.from('hello-over-masked-transport')))
    conn.on('data', (d) => { clearTimeout(to); resolve(d.toString()) })
    conn.on('error', reject)
  })

  log('round-trip reply from service peer:', JSON.stringify(got))
  const ok = got === 'echo:hello-over-masked-transport'
  log(ok ? 'PASS ✅  connection established over the relayed transport' : 'FAIL ❌  unexpected reply')

  // teardown
  conn.destroy()
  await clientDHT.destroy().catch(() => {})
  socket.destroy()
  await new Promise((r) => tcp.close(r))
  await relayDHT.destroy()
  await server.close()
  await serverDHT.destroy()
  await testnet.destroy()

  process.exit(ok ? 0 : 1)
}

main().catch((err) => {
  console.error('[demo] error:', err)
  process.exit(1)
})
