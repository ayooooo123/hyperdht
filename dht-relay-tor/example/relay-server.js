const net = require('net')
const DHT = require('hyperdht')
const { relay } = require('@hyperswarm/dht-relay')
const { wrap } = require('..')

// The relay node: an ordinary hyperdht node (full UDP presence on the swarm)
// plus a local TCP endpoint bridged into it. Do not expose this port publicly —
// publish it as a Tor v3 hidden service (see README) so relayed clients reach it
// over Tor and their IP is hidden from this node and from the swarm.

function startRelay({ port = 8080, host = '127.0.0.1', bootstrap } = {}) {
  const dht = new DHT({ bootstrap })

  const server = net.createServer((socket) => {
    const stream = wrap(false, socket)
    relay(dht, stream)
    stream.on('error', () => {}) // clients come and go; keep the relay alive
  })

  return new Promise((resolve) => {
    server.listen(port, host, () => resolve({ dht, server, address: server.address() }))
  })
}

module.exports = startRelay

if (require.main === module) {
  const port = Number(process.argv[2]) || 8080
  startRelay({ port }).then(({ address }) => {
    console.log('relay listening on tcp://127.0.0.1:' + address.port)
    console.log('publish this port as a Tor hidden service to accept masked clients')
  })
}
