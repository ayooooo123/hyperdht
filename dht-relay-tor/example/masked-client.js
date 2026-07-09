const RelayedDHT = require('@hyperswarm/dht-relay')
const Stream = require('..')

// A masked client: reaches the relay's Tor hidden service over Tor, then drives
// an ordinary hyperdht API through it. Requires a running Tor daemon with a
// SOCKS proxy on 127.0.0.1:9050.
//
//   node example/masked-client.js <relay-onion> [port] [targetPublicKeyHex]

async function main() {
  const onion = process.argv[2]
  const port = Number(process.argv[3]) || 8080
  const targetHex = process.argv[4]

  if (!onion) {
    console.error('usage: node example/masked-client.js <relay-onion> [port] [targetPublicKeyHex]')
    process.exit(1)
  }

  console.log('dialing relay', onion + ':' + port, 'through Tor (127.0.0.1:9050)...')
  const dht = new RelayedDHT(await Stream.connect({ onion, port }))
  await dht.ready()
  console.log('relayed DHT ready - local IP was never exposed to the swarm')

  if (!targetHex) {
    await dht.destroy().catch(() => {})
    return
  }

  const conn = dht.connect(Buffer.from(targetHex, 'hex'))
  conn.on('open', () => conn.write(Buffer.from('hello from a Tor-masked peer')))
  conn.on('data', (d) => {
    console.log('reply:', d.toString())
    conn.destroy()
  })
  conn.on('error', (err) => {
    console.error('connection error:', err.message)
    dht.destroy().catch(() => {})
  })
  conn.on('close', () => dht.destroy().catch(() => {}))
}

main().catch((err) => {
  console.error('error:', err)
  process.exit(1)
})
