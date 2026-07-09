const fs = require('fs')
const DHT = require('hyperdht')
const RelayedDHT = require('@hyperswarm/dht-relay')
const TorStream = require('dht-relay-tor')
const { TrustList, TransportRouter } = require('..')

// Wires the full stack: a direct hyperdht, a Tor-masked relayed DHT, and a
// trust list that decides per peer. Trusted peers (imported from a UI or a JSON
// file) get fast direct connections; everyone else is routed over Tor.
//
//   node example/policy-swarm.js <relay-onion> [trust.json] [targetPublicKeyHex]
//
// The trust list is the UI seam: `trust.on('update', render)` for live changes,
// `trust.import(peers)` when the user adds someone, `trust.toJSON()` to persist.

async function main() {
  const onion = process.argv[2]
  const trustFile = process.argv[3]
  const targetHex = process.argv[4]

  if (!onion) {
    console.error('usage: node example/policy-swarm.js <relay-onion> [trust.json] [targetHex]')
    process.exit(1)
  }

  // Load a persisted trust list (what a UI would export via trust.toJSON()).
  const seed =
    trustFile && fs.existsSync(trustFile) ? JSON.parse(fs.readFileSync(trustFile, 'utf8')) : []
  const trust = TrustList.fromJSON(seed)

  // Persist back whenever the UI changes the list.
  if (trustFile) {
    trust.on('update', () => fs.writeFileSync(trustFile, JSON.stringify(trust.toJSON(), null, 2)))
  }

  const direct = new DHT()
  const masked = new RelayedDHT(await TorStream.connect({ onion }))
  await masked.ready()

  const router = new TransportRouter({ direct, masked, trust })
  router.on('connection', ({ id, mode }) => console.log('connecting to', id, 'via', mode))

  if (!targetHex) {
    console.log(
      'ready. trusted peers:',
      trust.list().map((e) => e.id)
    )
    console.log('add one with trust.add(<key>) and connections to it will go direct.')
    return
  }

  const key = Buffer.from(targetHex, 'hex')
  console.log(router.describe(key))
  const conn = router.connect(key)
  conn.on('open', () => conn.write(Buffer.from('hello')))
  conn.on('data', (d) => {
    console.log('reply:', d.toString())
    conn.destroy()
  })
  conn.on('close', async () => {
    await router.destroy()
    await direct.destroy()
  })
  conn.on('error', (err) => console.error('error:', err.message))
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
