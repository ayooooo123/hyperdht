'use strict'

const test = require('brittle')
const b4a = require('b4a')
const { createPeerCandidateLocator } = require('../../lib/private/peer-capability')
const {
  createPeerCandidateDirectTransport,
  takePeerDirectRequesterTransport,
  destroyPeerDirectRequesterTransport
} = require('../../lib/private/udx-cell-endpoint')
const { UDX_ENDPOINT_RESERVATION_STATS } = require('../../lib/private/udx-adapter')
const { PEER_MESSAGE_ID, encodePeerObject } = require('../../lib/private/peer-protocol')
const { fakeClock, setupNativePoolPreflight } = require('./peer-native-fixture')

async function turns() {
  for (let i = 0; i < 20; i++) await Promise.resolve()
}

function query() {
  const body = b4a.alloc(110)
  body.writeUInt32BE(11, 0)
  body[68] = 1
  const wire = encodePeerObject({ messageId: PEER_MESSAGE_ID.PEER_CAPS_QUERY_V2, body })
  const packet = b4a.alloc(1200)
  packet.writeUInt16BE(0xd301, 0)
  packet.writeUInt16BE(wire.byteLength, 2)
  packet.set(wire, 4)
  return packet
}

function requester(f) {
  const transport = createPeerCandidateDirectTransport(
    f.localEndpoint,
    createPeerCandidateLocator(f.localRelayOwner, f.verifiedAd)
  )
  return { transport, capability: takePeerDirectRequesterTransport(transport) }
}

function hold(socket) {
  const sends = []
  socket.send = (packet) => new Promise((resolve) => sends.push({ packet, resolve }))
  return sends
}

for (const cancel of ['destroy', 'deadline']) {
  test(`native direct ${cancel} bounds caller wait without releasing native ownership`, async (t) => {
    const clock = fakeClock()
    const f = await setupNativePoolPreflight({ t, clock, localPort: 48901, peerPort: 48902 })
    const { transport, capability } = requester(f)
    const held = hold(f.localSocket)
    let result = null
    const sending = capability.send(query()).then(
      () => {
        result = 'sent'
      },
      (err) => {
        result = err.code
      }
    )
    await turns()
    const bytes = b4a.from(held[0].packet)
    if (cancel === 'destroy') destroyPeerDirectRequesterTransport(transport)
    else clock.advance(1000)
    await turns()
    t.is(result, 'ROUTE_UNAVAILABLE', 'caller settles before native flush')
    t.alike(held[0].packet, bytes, 'native backing bytes stay intact')
    t.alike(f.localEndpoint[UDX_ENDPOINT_RESERVATION_STATS](), { packets: 1, bytes: 1200 })
    held[0].resolve(true)
    await sending
    await turns()
    t.is(result, 'ROUTE_UNAVAILABLE', 'late success cannot reenter the caller')
    t.alike(held[0].packet, b4a.alloc(1200), 'flush erases backing bytes')
    t.alike(f.localEndpoint[UDX_ENDPOINT_RESERVATION_STATS](), { packets: 0, bytes: 0 })
    destroyPeerDirectRequesterTransport(transport)
  })
}

test('native endpoint close publishes its join before callback reentry', async (t) => {
  const f = await setupNativePoolPreflight({
    t,
    clock: fakeClock(),
    localPort: 48903,
    peerPort: 48904
  })
  const off = f.localSocket.off.bind(f.localSocket)
  let reentered = null
  f.localSocket.off = (...args) => {
    f.localSocket.off = off
    reentered = f.localEndpoint.close()
    off(...args)
  }
  const closing = f.localEndpoint.close()
  t.is(reentered, closing, 'reentrant close joins the same completion')
  await closing
  t.is(f.localSocket.closeCalls, 1, 'one native close owner')
})
