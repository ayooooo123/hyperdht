'use strict'

// A peer that holds itself open for a fixed span and echoes whatever the pinned
// prober sends. Run it on a CI runner to get a real remote peer on the public
// DHT for that span, then measure against it from a workstation.
//
//   REMOTE_PEER_SECRET=<hex> REMOTE_PEER_RUN_ID=<id> \
//     REMOTE_PEER_COORDINATOR_KEY=<hex public key> \
//     node test/remote-peer/serve.js --index 1 --seconds 300
//
// Options: --index (default 1), --seconds (default 300),
//          --bootstrap host:port (repeatable, for a local DHT instead of the
//          public one), --host, --port.

const b4a = require('b4a')
const DHT = require('../..')
const { peerKeyPair, coordinatorPublicKey } = require('./identity')

function parse(argv) {
  const options = { index: 1, seconds: 300, bootstrap: [], host: null, port: 0 }
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i]
    const value = argv[i + 1]
    if (flag === '--index') options.index = Number(value)
    else if (flag === '--seconds') options.seconds = Number(value)
    else if (flag === '--host') options.host = value
    else if (flag === '--port') options.port = Number(value)
    else if (flag === '--bootstrap') {
      const [host, port] = String(value).split(':')
      options.bootstrap.push({ host, port: Number(port) })
    } else continue
    i++
  }
  if (!Number.isInteger(options.index) || options.index < 1) throw new Error('bad --index')
  if (!Number.isFinite(options.seconds) || options.seconds <= 0) throw new Error('bad --seconds')
  return options
}

function emit(event) {
  // One JSON object per line: the runner log stays greppable and a wrapper can
  // parse it without scraping prose.
  console.log(JSON.stringify({ remotePeer: event.event, ...event }))
}

async function main() {
  const options = parse(process.argv.slice(2))
  const secret = process.env.REMOTE_PEER_SECRET
  const runId = process.env.REMOTE_PEER_RUN_ID || process.env.GITHUB_RUN_ID
  // The prober's public key is supplied, not derived. This peer holds the shared
  // run secret, so anything derivable from it is derivable here, and a firewall
  // pinned to a key this host could mint is not a firewall at all.
  const coordinatorKey = process.env.REMOTE_PEER_COORDINATOR_KEY
  if (!secret) throw new Error('REMOTE_PEER_SECRET is required')
  if (!runId) throw new Error('REMOTE_PEER_RUN_ID or GITHUB_RUN_ID is required')
  if (!coordinatorKey) {
    throw new Error(
      'REMOTE_PEER_COORDINATOR_KEY is required: the hex public key of the prober ' +
        'that is allowed to connect, from scripts/remote-peer.sh secret'
    )
  }

  const keyPair = peerKeyPair(secret, runId, options.index)
  const prober = coordinatorPublicKey(coordinatorKey)
  const node = new DHT({
    bootstrap: options.bootstrap.length > 0 ? options.bootstrap : undefined,
    host: options.host || undefined,
    port: options.port || 0
  })

  let accepted = 0
  let rejected = 0
  let echoed = 0

  const server = node.createServer(
    {
      // Only the pinned prober may connect. A leaked peer key is then useless on
      // its own, and so is this host's copy of the shared run secret.
      firewall(remotePublicKey) {
        const allowed = b4a.equals(remotePublicKey, prober)
        if (!allowed) rejected++
        return !allowed
      }
    },
    (socket) => {
      accepted++
      emit({ event: 'accept', index: options.index, accepted })
      socket.on('error', () => {})
      socket.on('data', (data) => {
        echoed += data.byteLength
        socket.write(data)
      })
    }
  )

  await server.listen(keyPair)

  // The reachability facts a failed run needs: whether the host is firewalled,
  // what address the DHT settled on, and how punches and relay attempts go.
  emit({
    event: 'ready',
    index: options.index,
    runId,
    publicKey: b4a.toString(keyPair.publicKey, 'hex'),
    seconds: options.seconds,
    address: node.address(),
    firewalled: node.firewalled,
    punches: node.stats.punches,
    relaying: node.stats.relaying
  })

  const heartbeat = setInterval(() => {
    emit({
      event: 'alive',
      index: options.index,
      accepted,
      rejected,
      echoed,
      firewalled: node.firewalled,
      punches: node.stats.punches,
      relaying: node.stats.relaying
    })
  }, 15_000)

  await new Promise((resolve) => setTimeout(resolve, options.seconds * 1000))

  clearInterval(heartbeat)
  emit({
    event: 'done',
    index: options.index,
    accepted,
    rejected,
    echoed,
    punches: node.stats.punches,
    relaying: node.stats.relaying
  })

  await server.close()
  await node.destroy()
}

main().catch((err) => {
  emit({ event: 'error', message: err.message })
  process.exit(1)
})
