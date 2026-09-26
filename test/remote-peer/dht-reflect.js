'use strict'

// Asks the DHT what address it sees for a socket the caller owns.
//
// hyperdht already does this for its own socket: every dht-rpc reply carries a
// `to` field with the responder's view of the sender, dht-rpc feeds it to a
// NatSampler (node_modules/dht-rpc/index.js:885) and exposes the result as
// dht.host, dht.port and remoteAddress(). None of that describes a second socket,
// though, and a NAT mapping belongs to a socket, not to a host: the socket
// lib/private/udx-cell-endpoint.js binds for route cells gets its own mapping.
//
// So this reflects that socket off DHT nodes instead of an external STUN service:
// same question, same answer, no third party, and the request is built by this
// repository's own client packet codec in lib/private/dht-exit-wire.js.
//
// Two different bootstrap nodes are queried on purpose. Equal answers mean the
// mapping does not depend on the destination, so one value is publishable to any
// peer, which is what a signed capability needs. Different answers mean there is
// no publishable value at all.

const c = require('compact-encoding')
const dns = require('dns').promises
const { BOOTSTRAP_NODES } = require('../../lib/constants')
const {
  TEST_ONLY_DHT_EXIT_WIRE_RESERVATION,
  encodeDhtExitRequest
} = require('../../lib/private/dht-exit-wire')

const RESPONSE_ID = 0x13
const PING = 0

// decodeDhtExitReply rejects a reply whose `to` differs from the local tuple,
// which is exactly the case being measured here, so the three fields ahead of it
// are skipped by hand: response byte, flags, transaction id.
function readObservedAddress(packet) {
  if (!Buffer.isBuffer(packet) && !(packet instanceof Uint8Array)) return null
  if (packet.byteLength < 10 || packet[0] !== RESPONSE_ID) return null
  const state = { start: 1, end: packet.byteLength, buffer: packet }
  try {
    c.uint.decode(state)
    c.uint16.decode(state)
    // Same codec the wire module uses for this field, rather than assuming a
    // layout: lib/private/dht-exit-wire.js:82 wraps c.ipv4Address.
    const to = c.ipv4Address.decode(state)
    return to && to.port > 0 ? { host: to.host, port: to.port } : null
  } catch {
    return null
  }
}

function pingPacket(remote, tid) {
  const reservation = TEST_ONLY_DHT_EXIT_WIRE_RESERVATION.create({
    // Exactly host and port: the wire codec rejects any other own property, and a
    // reflector record also carries its name.
    remote: { host: remote.host, port: remote.port },
    local: { host: '0.0.0.0', port: 1 },
    tid
  })
  return encodeDhtExitRequest(reservation, {
    tid,
    token: null,
    internal: true,
    command: PING,
    target: null,
    value: null
  })
}

// Uses a socket the caller already owns, because the point is the mapping of that
// exact socket.
function reflect(socket, remote, timeoutMs = 4000) {
  return new Promise((resolve) => {
    let settled = false
    const tid = 1 + Math.floor(Math.random() * 0xfffe)

    const onMessage = (message, from) => {
      if (settled) return
      if (from.host !== remote.host || from.port !== remote.port) return
      const observed = readObservedAddress(message)
      if (observed === null) return
      settled = true
      finish()
      resolve(observed)
    }

    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      finish()
      resolve(null)
    }, timeoutMs)

    function finish() {
      clearTimeout(timer)
      socket.removeListener('message', onMessage)
    }

    socket.on('message', onMessage)
    let packet = null
    try {
      packet = pingPacket(remote, tid)
    } catch {
      settled = true
      finish()
      return resolve(null)
    }
    // Three sends: a lost UDP request would otherwise read as "no mapping" and be
    // mistaken for a blocked NAT.
    for (const delay of [0, 300, 900]) {
      setTimeout(() => {
        if (settled) return
        try {
          socket.send(packet, remote.port, remote.host)
        } catch {
          // Reported as a null observation.
        }
      }, delay)
    }
  })
}

// The bootstrap list is "id@host:port"; the id is irrelevant for a PING.
async function resolveReflectors(nodes = BOOTSTRAP_NODES) {
  const resolved = []
  for (const entry of nodes) {
    const address = entry.includes('@') ? entry.split('@')[1] : entry
    const [host, port] = address.split(':')
    try {
      const looked = await dns.lookup(host, { family: 4 })
      resolved.push({ name: host, host: looked.address, port: Number(port) })
    } catch {
      // A reflector that will not resolve is skipped.
    }
  }
  return resolved
}

module.exports = { reflect, resolveReflectors, readObservedAddress }
