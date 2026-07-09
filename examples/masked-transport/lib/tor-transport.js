'use strict'

const SecretStream = require('@hyperswarm/secret-stream')
const socks5Connect = require('./socks5')

// A dht-relay transport that carries the relay protocol over a Tor circuit.
//
// dht-relay's built-in TCP transport (`@hyperswarm/dht-relay/tcp`) is literally
// `@hyperswarm/secret-stream` wrapping a `net.Socket`. secret-stream provides
// the framing + encryption that protomux (and therefore the relay protocol)
// expects. We reuse that exact wrapper; the *only* thing we change is that the
// underlying socket is dialed through Tor's SOCKS5 proxy instead of directly.
//
// Result: `new DHT(await connect(...))` gives you a fully-featured relayed DHT
// handle whose source IP never touches the public swarm. QUIC/holepunch happens
// at the *relay node*, not at your machine, so your NAT/IP is never exposed.

// Client side: dial the relay's onion address through Tor and wrap it.
// Returns a secret-stream Duplex ready to pass to `new DHT(stream)`.
async function connect (opts = {}) {
  const {
    onion, // e.g. "abcd...xyz.onion" (the relay's hidden service)
    port = 8080,
    proxyHost = '127.0.0.1',
    proxyPort = 9050,
    timeout = 30000,
    keyPair,
    autoStart
  } = opts

  if (!onion) throw new Error('onion (relay hidden-service address) is required')

  const socket = await socks5Connect({
    proxyHost,
    proxyPort,
    destHost: onion,
    destPort: port,
    timeout
  })

  return wrap(true, socket, { keyPair, autoStart })
}

// Wrap an already-connected socket (Tor, or plain TCP for local testing) in the
// same secret-stream the built-in TCP transport uses. `isInitiator` mirrors the
// TCP wrapper's first argument: true on the relayed client, false on the relay.
function wrap (isInitiator, socket, opts = {}) {
  return new SecretStream(isInitiator, socket, opts)
}

module.exports = { connect, wrap }
