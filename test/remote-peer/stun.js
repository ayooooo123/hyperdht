'use strict'

// Just enough STUN to ask "what address does the world see for this socket?".
//
// A runner cannot know its own mapped port: it binds 50098 and the NAT rewrites
// it to something else. Route cells are dialled at the endpoint bound into a
// signed capability, so the value that goes into that capability has to be the
// mapped one, and only a reflector outside the NAT can report it.
//
// Two servers are queried on purpose. If one socket gets the same mapped port
// from both, the NAT's mapping is address independent, and a mapped port learned
// once is usable by any peer. If the ports differ, the mapping is per
// destination, and no peer can ever be told a usable port: that difference is the
// whole design question for distributing routes, so it is measured, not assumed.

const b4a = require('b4a')
const dns = require('dns').promises

const MAGIC_COOKIE = 0x2112a442
const BINDING_REQUEST = 0x0001
const BINDING_SUCCESS = 0x0101
const XOR_MAPPED_ADDRESS = 0x0020
const MAPPED_ADDRESS = 0x0001
const HEADER_BYTES = 20

// Two different operators, because the whole point is two different destination
// addresses. Both Google names resolve to one address, which would prove nothing.
const DEFAULT_SERVERS = Object.freeze([
  { host: 'stun.l.google.com', port: 19302 },
  { host: 'stun.cloudflare.com', port: 3478 }
])

function request(transactionId) {
  const packet = b4a.alloc(HEADER_BYTES)
  packet.writeUInt16BE(BINDING_REQUEST, 0)
  packet.writeUInt16BE(0, 2)
  packet.writeUInt32BE(MAGIC_COOKIE, 4)
  packet.set(transactionId, 8)
  return packet
}

function parse(packet, transactionId) {
  if (!b4a.isBuffer(packet) || packet.byteLength < HEADER_BYTES) return null
  if (packet.readUInt16BE(0) !== BINDING_SUCCESS) return null
  if (packet.readUInt32BE(4) !== MAGIC_COOKIE) return null
  if (!b4a.equals(packet.subarray(8, 20), transactionId)) return null

  const length = packet.readUInt16BE(2)
  let offset = HEADER_BYTES
  const end = Math.min(packet.byteLength, HEADER_BYTES + length)
  while (offset + 4 <= end) {
    const type = packet.readUInt16BE(offset)
    const size = packet.readUInt16BE(offset + 2)
    const body = packet.subarray(offset + 4, offset + 4 + size)
    if ((type === XOR_MAPPED_ADDRESS || type === MAPPED_ADDRESS) && size >= 8 && body[1] === 0x01) {
      const xor = type === XOR_MAPPED_ADDRESS
      const port = body.readUInt16BE(2) ^ (xor ? MAGIC_COOKIE >>> 16 : 0)
      const raw = body.readUInt32BE(4) ^ (xor ? MAGIC_COOKIE : 0)
      const host = [(raw >>> 24) & 0xff, (raw >>> 16) & 0xff, (raw >>> 8) & 0xff, raw & 0xff].join(
        '.'
      )
      return { host, port }
    }
    // Attributes are padded to four bytes.
    offset += 4 + size + ((4 - (size % 4)) % 4)
  }
  return null
}

// Uses a socket the caller already owns, because the point is to learn the
// mapping of that exact socket, not of a fresh one.
function discoverMapping(socket, server, timeoutMs = 4000) {
  return new Promise((resolve) => {
    let settled = false
    const transactionId = b4a.allocUnsafeSlow(12)
    for (let i = 0; i < 12; i++) transactionId[i] = Math.floor(Math.random() * 256)

    const onMessage = (message, from) => {
      if (settled) return
      if (from.host !== server.address || from.port !== server.port) return
      const mapped = parse(message, transactionId)
      if (mapped === null) return
      settled = true
      cleanup()
      resolve(mapped)
    }

    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      cleanup()
      resolve(null)
    }, timeoutMs)

    function cleanup() {
      clearTimeout(timer)
      socket.removeListener('message', onMessage)
    }

    socket.on('message', onMessage)
    const packet = request(transactionId)
    // Three sends: UDP to a public reflector is not reliable, and a lost request
    // would read as "no mapping" and be mistaken for a blocked NAT.
    for (const delay of [0, 300, 900]) {
      setTimeout(() => {
        if (settled) return
        try {
          socket.send(packet, server.port, server.address)
        } catch {
          // Reported as a null mapping.
        }
      }, delay)
    }
  })
}

async function resolveServers(servers = DEFAULT_SERVERS) {
  const resolved = []
  for (const server of servers) {
    try {
      const { address } = await dns.lookup(server.host, { family: 4 })
      resolved.push({ ...server, address })
    } catch {
      // A reflector that will not resolve is simply skipped.
    }
  }
  return resolved
}

module.exports = { DEFAULT_SERVERS, discoverMapping, resolveServers }
