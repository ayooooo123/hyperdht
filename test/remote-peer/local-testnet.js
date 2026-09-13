'use strict'

// A throwaway DHT for exercising the remote-peer harness without the public
// network or a CI runner. Prints one JSON line with the bootstrap list, then
// stays up until killed.
//
//   node test/remote-peer/local-testnet.js --size 8
//
// Feed the printed list to both sides:
//   node test/remote-peer/serve.js --bootstrap 127.0.0.1:PORT ...
//   REMOTE_PEER_BOOTSTRAP=127.0.0.1:PORT brittle-node test/remote-peer/probe.js

const createTestnet = require('../../testnet')

async function main() {
  const argv = process.argv.slice(2)
  const sizeFlag = argv.indexOf('--size')
  const size = sizeFlag === -1 ? 8 : Number(argv[sizeFlag + 1])
  if (!Number.isInteger(size) || size < 3) throw new Error('bad --size')

  const testnet = await createTestnet(size)
  const bootstrap = testnet.bootstrap.map((node) => `${node.host}:${node.port}`).join(',')

  console.log(JSON.stringify({ remotePeer: 'testnet', event: 'testnet', size, bootstrap }))

  const close = async () => {
    await testnet.destroy()
    process.exit(0)
  }
  process.on('SIGINT', close)
  process.on('SIGTERM', close)
}

main().catch((err) => {
  console.log(JSON.stringify({ remotePeer: 'error', event: 'error', message: err.message }))
  process.exit(1)
})
