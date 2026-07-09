'use strict'

const RelayedDHT = require('@hyperswarm/dht-relay')
const { connect } = require('./lib/tor-transport')

// A real masked client: reaches the relay's Tor hidden service over Tor, then
// drives an ordinary hyperdht API through it. Requires a running Tor daemon
// (SOCKS proxy on 127.0.0.1:9050) — e.g. `tor` from the tor package, or the
// Tor Browser's bundled daemon.
//
// Usage:
//   node masked-client.js <relay-onion-address> [onionPort] [targetPublicKeyHex]
//
// If a target public key is given, it connects to that peer and echoes a line;
// otherwise it just proves the relayed DHT came up and prints its node address.

async function main () {
  const onion = process.argv[2]
  const port = Number(process.argv[3]) || 8080
  const targetHex = process.argv[4]

  if (!onion) {
    console.error('usage: node masked-client.js <relay-onion> [port] [targetPublicKeyHex]')
    process.exit(1)
  }

  console.log('dialing relay', onion + ':' + port, 'through Tor (127.0.0.1:9050)…')
  const stream = await connect({ onion, port })
  const dht = new RelayedDHT(stream)
  await dht.ready()
  console.log('relayed DHT ready — local IP was never exposed to the swarm')

  if (!targetHex) {
    console.log('no target given; exiting. Pass a peer public key to open a connection.')
    await dht.destroy().catch(() => {})
    return
  }

  const key = Buffer.from(targetHex, 'hex')
  const conn = dht.connect(key)
  conn.on('open', () => conn.write(Buffer.from('hello from a Tor-masked peer')))
  conn.on('data', (d) => {
    console.log('reply:', d.toString())
    conn.destroy()
  })
  conn.on('close', () => dht.destroy().catch(() => {}))
  conn.on('error', (err) => {
    console.error('connection error:', err.message)
    dht.destroy().catch(() => {})
  })
}

main().catch((err) => {
  console.error('error:', err)
  process.exit(1)
})
