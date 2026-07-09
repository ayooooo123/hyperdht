'use strict'

const net = require('net')

// Minimal SOCKS5 CONNECT client (RFC 1928), no auth.
//
// This is the *only* Tor-specific piece of the whole prototype: it dials a
// TCP connection to a destination *through* a SOCKS5 proxy (Tor's SOCKS port,
// default 127.0.0.1:9050). Tor resolves and routes the destination — which is
// typically an `.onion` address — so our real IP never appears on the wire to
// the relay or to the swarm.
//
// The returned socket is a plain, connected `net.Socket`. From dht-relay's
// point of view it is indistinguishable from `net.connect(port, host)`; we
// hand it straight to the same secret-stream wrapper the built-in TCP
// transport uses. That is the entire trick: swap *how the socket is obtained*,
// reuse everything above it.

const SOCKS_VERSION = 0x05
const CMD_CONNECT = 0x01
const ATYP_IPV4 = 0x01
const ATYP_DOMAIN = 0x03
const ATYP_IPV6 = 0x04
const RSV = 0x00

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

module.exports = function socks5Connect (opts) {
  const {
    proxyHost = '127.0.0.1',
    proxyPort = 9050, // Tor's default SOCKS port
    destHost,
    destPort,
    timeout = 30000
  } = opts

  if (!destHost || !destPort) {
    throw new Error('destHost and destPort are required')
  }

  return new Promise((resolve, reject) => {
    const socket = net.connect(proxyPort, proxyHost)

    let stage = 'greeting'
    let settled = false

    const timer = setTimeout(() => fail(new Error('SOCKS5 handshake timed out')), timeout)

    const chunks = []
    let need = 2 // greeting reply is 2 bytes

    socket.on('error', fail)
    socket.once('connect', () => {
      // Greeting: version, 1 method, "no authentication"
      socket.write(Buffer.from([SOCKS_VERSION, 0x01, 0x00]))
    })

    socket.on('data', onData)

    function onData (data) {
      chunks.push(data)
      let buf = Buffer.concat(chunks)

      while (buf.length >= need) {
        if (stage === 'greeting') {
          if (buf[0] !== SOCKS_VERSION) return fail(new Error('bad SOCKS version in greeting'))
          if (buf[1] !== 0x00) return fail(new Error('SOCKS5 proxy requires authentication'))
          buf = buf.subarray(2)
          chunks.length = 0
          if (buf.length) chunks.push(buf)

          // Send CONNECT request for destHost:destPort as a domain name so Tor
          // performs the resolution (essential for .onion addresses).
          const host = Buffer.from(destHost)
          const req = Buffer.alloc(4 + 1 + host.length + 2)
          let o = 0
          req[o++] = SOCKS_VERSION
          req[o++] = CMD_CONNECT
          req[o++] = RSV
          req[o++] = ATYP_DOMAIN
          req[o++] = host.length
          host.copy(req, o); o += host.length
          req.writeUInt16BE(destPort, o)
          socket.write(req)

          stage = 'reply'
          need = 4 // first 4 bytes of the reply, then we learn the addr length
          buf = Buffer.concat(chunks)
          continue
        }

        if (stage === 'reply') {
          if (buf[0] !== SOCKS_VERSION) return fail(new Error('bad SOCKS version in reply'))
          const rep = buf[1]
          if (rep !== 0x00) {
            return fail(new Error('SOCKS5 CONNECT failed: ' + (REPLY[rep] || ('code ' + rep))))
          }
          const atyp = buf[3]
          let addrLen
          if (atyp === ATYP_IPV4) addrLen = 4
          else if (atyp === ATYP_IPV6) addrLen = 16
          else if (atyp === ATYP_DOMAIN) addrLen = 1 + buf[4]
          else return fail(new Error('unknown ATYP in reply'))

          const total = 4 + addrLen + 2
          if (buf.length < total) { need = total; break }

          // Handshake complete. Detach our listeners and hand back a clean,
          // connected socket. Any bytes past the reply are pushed back.
          succeed(socket, buf.subarray(total))
          return
        }
      }
    }

    function cleanup () {
      clearTimeout(timer)
      socket.removeListener('data', onData)
      socket.removeListener('error', fail)
    }

    function succeed (sock, leftover) {
      if (settled) return
      settled = true
      cleanup()
      if (leftover && leftover.length) sock.unshift(leftover)
      resolve(sock)
    }

    function fail (err) {
      if (settled) return
      settled = true
      cleanup()
      socket.destroy()
      reject(err)
    }
  })
}
