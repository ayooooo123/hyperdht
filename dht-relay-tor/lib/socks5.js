const b4a = require('b4a')
const defaultTCP = require('./tcp')

// Minimal SOCKS5 CONNECT client (RFC 1928, no authentication).
//
// This is the only Tor-specific code in the package. It dials a TCP connection
// to a destination *through* a SOCKS5 proxy — Tor's SOCKS port, default
// 127.0.0.1:9050 — sending the destination as a domain name so Tor performs the
// resolution (essential for .onion addresses). The caller's real IP therefore
// never appears on the wire to the relay or the swarm.
//
// It is written buffer-free (b4a + byte indexing, no Buffer/DataView) so it runs
// unchanged on Bare and Node. The returned socket is a plain, connected socket;
// from dht-relay's point of view it is indistinguishable from a direct dial, so
// it goes straight into the same secret-stream wrapper the built-in TCP
// transport uses.

const SOCKS_VERSION = 0x05
const CMD_CONNECT = 0x01
const RSV = 0x00
const ATYP_IPV4 = 0x01
const ATYP_DOMAIN = 0x03
const ATYP_IPV6 = 0x04

const REPLY = {
  0x00: 'succeeded',
  0x01: 'general SOCKS server failure',
  0x02: 'connection not allowed by ruleset',
  0x03: 'network unreachable',
  0x04: 'host unreachable',
  0x05: 'connection refused',
  0x06: 'TTL expired',
  0x07: 'command not supported',
  0x08: 'address type not supported'
}

module.exports = function socks5Connect(opts = {}) {
  const {
    proxyHost = '127.0.0.1',
    proxyPort = 9050,
    destHost,
    destPort,
    timeout = 30000,
    tcp = defaultTCP
  } = opts

  if (!destHost || !destPort) throw new Error('destHost and destPort are required')

  return new Promise((resolve, reject) => {
    let stage = 'greeting'
    let settled = false
    let buf = b4a.alloc(0)
    let need = 2

    const socket = tcp.connect(proxyPort, proxyHost, onconnect)
    const timer = setTimeout(() => fail(new Error('SOCKS5 handshake timed out')), timeout)

    socket.on('error', fail)
    socket.on('data', ondata)

    function onconnect() {
      // Greeting: version, 1 method, "no authentication required".
      socket.write(b4a.from([SOCKS_VERSION, 0x01, 0x00]))
    }

    function ondata(data) {
      buf = b4a.concat([buf, data])

      while (buf.length >= need) {
        if (stage === 'greeting') {
          if (buf[0] !== SOCKS_VERSION) return fail(new Error('bad SOCKS version in greeting'))
          if (buf[1] !== 0x00) return fail(new Error('SOCKS5 proxy requires authentication'))
          buf = buf.subarray(2)

          socket.write(connectRequest(destHost, destPort))

          stage = 'reply'
          need = 4 // enough to read VER, REP, RSV, ATYP; then we learn addr length
          continue
        }

        if (stage === 'reply') {
          if (buf[0] !== SOCKS_VERSION) return fail(new Error('bad SOCKS version in reply'))
          const rep = buf[1]
          if (rep !== 0x00)
            return fail(new Error('SOCKS5 CONNECT failed: ' + (REPLY[rep] || 'code ' + rep)))

          const atyp = buf[3]
          let addrLen
          if (atyp === ATYP_IPV4) addrLen = 4
          else if (atyp === ATYP_IPV6) addrLen = 16
          else if (atyp === ATYP_DOMAIN) addrLen = 1 + buf[4]
          else return fail(new Error('unknown ATYP in reply'))

          const total = 4 + addrLen + 2
          if (buf.length < total) {
            need = total
            break
          }

          return succeed(buf.subarray(total))
        }
      }
    }

    function connectRequest(host, port) {
      const name = b4a.from(host)
      const req = b4a.alloc(4 + 1 + name.length + 2)
      let o = 0
      req[o++] = SOCKS_VERSION
      req[o++] = CMD_CONNECT
      req[o++] = RSV
      req[o++] = ATYP_DOMAIN
      req[o++] = name.length
      b4a.copy(name, req, o)
      o += name.length
      req[o++] = (port >> 8) & 0xff
      req[o++] = port & 0xff
      return req
    }

    function cleanup() {
      clearTimeout(timer)
      socket.removeListener('data', ondata)
      socket.removeListener('error', fail)
    }

    function succeed(leftover) {
      if (settled) return
      settled = true
      cleanup()
      // With Tor + secret-stream the initiator speaks first, so the relay never
      // sends bytes before our handshake — leftover is essentially always empty.
      // Push any back if the runtime supports it.
      if (leftover.length && typeof socket.unshift === 'function') socket.unshift(leftover)
      resolve(socket)
    }

    function fail(err) {
      if (settled) return
      settled = true
      cleanup()
      socket.destroy()
      reject(err)
    }
  })
}
