const SecretStream = require('@hyperswarm/secret-stream')
const socks5Connect = require('./lib/socks5')

// dht-relay's built-in TCP transport (@hyperswarm/dht-relay/tcp) is a re-export
// of @hyperswarm/secret-stream, which supplies the framing + encryption the
// relay protocol (protomux) expects. This package mirrors that: the default
// export is the same Stream you construct with (isInitiator, socket). The only
// thing added is connect(), which obtains the socket by dialing the relay's Tor
// hidden service through Tor's SOCKS5 proxy instead of dialing it directly.
//
//   const DHT = require('@hyperswarm/dht-relay')
//   const Stream = require('dht-relay-tor')
//   const dht = new DHT(await Stream.connect({ onion }))

module.exports = SecretStream

// Relayed (client) side: dial the relay's onion over Tor and return a Stream
// ready for `new DHT(stream)`. Extra options are forwarded to secret-stream.
module.exports.connect = async function connect(opts = {}) {
  const {
    onion,
    port = 8080,
    proxyHost = '127.0.0.1',
    proxyPort = 9050,
    timeout = 30000,
    ...streamOptions
  } = opts

  if (!onion) throw new Error('onion (relay hidden-service address) is required')

  const socket = await socks5Connect({
    proxyHost,
    proxyPort,
    destHost: onion,
    destPort: port,
    timeout
  })

  return new SecretStream(true, socket, streamOptions)
}

// Wrap an already-connected socket in the transport Stream. isInitiator is true
// on the relayed client, false on the relay. Used by the relay server, by tests,
// and by callers who dial the socket themselves (e.g. a different overlay).
module.exports.wrap = function wrap(isInitiator, socket, options) {
  return new SecretStream(isInitiator, socket, options)
}
