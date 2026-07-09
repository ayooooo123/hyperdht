'use strict'

const net = require('net')
const DHT = require('hyperdht')
const { relay } = require('@hyperswarm/dht-relay')
const { wrap } = require('./lib/tor-transport')

// The relay node.
//
// This is an ordinary hyperdht node with a full UDP presence on the swarm — it
// is the machine whose IP the swarm sees. It exposes a local TCP listener; each
// incoming connection is wrapped in secret-stream and handed to `relay()`, which
// bridges that stream to the real DHT.
//
// In a real deployment you do NOT expose this TCP port publicly. You publish it
// as a Tor v3 hidden service (see README) so relayed clients reach it over Tor.
// The client's IP is therefore hidden from this node *and* from the swarm.

module.exports = function startRelay ({ port = 8080, host = '127.0.0.1', bootstrap } = {}) {
  const dht = new DHT({ bootstrap })

  const server = net.createServer((socket) => {
    // isInitiator=false on the relay side, mirroring the TCP transport docs.
    const stream = wrap(false, socket)
    relay(dht, stream)
    stream.on('error', () => {}) // clients come and go; don't crash the relay
  })

  return new Promise((resolve) => {
    server.listen(port, host, () => {
      resolve({ dht, server, address: server.address() })
    })
  })
}

// CLI: `node relay-server.js [port]`
if (require.main === module) {
  const port = Number(process.argv[2]) || 8080
  startRelay({ port }).then(({ address }) => {
    console.log('relay listening on tcp://127.0.0.1:' + address.port)
    console.log('publish this port as a Tor hidden service to accept masked clients')
  })
}
