const Stream = require('.')

// Bundled Tor: start embedded Arti (no external `tor` daemon) and dial the
// relay's onion over it. Requires the optional `bare-arti` module, which ships
// the embedded Arti (Rust Tor) proxy.
//
//   const { connect } = require('dht-relay-tor/arti')
//   const DHT = require('@hyperswarm/dht-relay')
//   const dht = new DHT(await connect({ onion: '<relay>.onion' }))
//
// This is the zero-dependency-on-a-daemon path: bare-arti boots Tor in the
// background and exposes a local SOCKS5 port, which is exactly what the standard
// Stream.connect() consumes — so nothing else changes.

module.exports.connect = async function connect(opts = {}) {
  let arti
  try {
    arti = require('bare-arti')
  } catch {
    throw new Error(
      'bundled Tor requires the optional dependency `bare-arti` (embedded Arti) to be installed'
    )
  }

  const tor = await arti.start({ timeout: opts.bootstrapTimeout })

  let stream
  try {
    stream = await Stream.connect({
      ...opts,
      proxyHost: '127.0.0.1',
      proxyPort: tor.port
    })
  } catch (err) {
    tor.stop()
    throw err
  }

  // Tear the embedded proxy down when the transport stream closes.
  stream.once('close', () => {
    try {
      tor.stop()
    } catch {}
  })

  return stream
}
