'use strict'

const test = require('brittle')
const b4a = require('b4a')
const UDX = require('udx-native')

const { BOOTSTRAP_CLASS, BOOTSTRAP_SIZE } = require('../../lib/private/bootstrap-envelope')
const { CELL_CLASS, PROTOCOL_VERSION } = require('../../lib/private/protocol')
const {
  blackholeRouteCells,
  isRouteCellDatagram,
  routeCellBlackholeAdapterFactory,
  routeCellBlackholeSnapshot
} = require('./process/route-cell-blackhole')

const HOST = '127.0.0.1'
// An arrival that is going to happen is waited for, not slept on, so a loaded machine costs
// this test time rather than a false failure. A DROP is the only thing that has to be
// time-boxed, and that window is safe to keep short: a datagram the adapter discarded cannot
// turn up later, so the window bounds how long a REGRESSION could hide, not how long a
// correct implementation needs.
const ARRIVAL_MS = 10_000
const DROP_WINDOW_MS = 250

function datagram(first, second) {
  const packet = b4a.alloc(BOOTSTRAP_SIZE, 0x5a)
  packet[0] = first
  packet[1] = second
  return packet
}

function settle(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

async function waitForCount(list, count, ms) {
  const deadline = Date.now() + ms
  while (list.length < count && Date.now() < deadline) await settle(5)
  return list.length
}

function nextMessage(socket, ms) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      socket.off('message', onMessage)
      resolve(null)
    }, ms)
    function onMessage(packet) {
      clearTimeout(timer)
      socket.off('message', onMessage)
      resolve(b4a.from(packet))
    }
    socket.on('message', onMessage)
  })
}

test('route cell classification separates cells from every other datagram on the socket', (t) => {
  for (const cellClass of [CELL_CLASS.CONTROL, CELL_CLASS.STREAM, CELL_CLASS.DATAGRAM]) {
    t.is(isRouteCellDatagram(datagram(PROTOCOL_VERSION, cellClass)), true)
  }
  t.is(isRouteCellDatagram(datagram(PROTOCOL_VERSION, BOOTSTRAP_CLASS)), false)
  // A direct caps request is the one datagram on this socket that does not carry
  // PROTOCOL_VERSION in byte 0; byte 1 alone would misread it as a STREAM cell.
  t.is(isRouteCellDatagram(datagram(0xd3, 0x01)), false)
  t.is(isRouteCellDatagram(datagram(PROTOCOL_VERSION, 3)), false)
  t.is(isRouteCellDatagram(b4a.alloc(BOOTSTRAP_SIZE - 1)), false)
  t.is(isRouteCellDatagram(null), false)
})

// One test, because arming is deliberately one-shot and process-wide: a dead host does not
// come back mid-scenario. The pass-through assertions therefore have to precede the armed
// ones inside a single body rather than rely on file ordering.
test('blackhole drops route cells both ways and leaves everything else alive', async (t) => {
  const adapter = routeCellBlackholeAdapterFactory().create()
  const local = adapter.createSocket()
  const peer = new UDX().createSocket()
  local.bind(0, HOST)
  peer.bind(0, HOST)
  const localPort = local.address().port
  const peerPort = peer.address().port
  const inbound = []
  local.on('message', (packet) => inbound.push(b4a.from(packet)))
  t.teardown(async () => {
    await local.close()
    await peer.close()
  })

  const cell = datagram(PROTOCOL_VERSION, CELL_CLASS.STREAM)
  const bootstrap = datagram(PROTOCOL_VERSION, BOOTSTRAP_CLASS)

  t.is(routeCellBlackholeSnapshot().armed, false)
  t.is(await local.send(cell, peerPort, HOST), true)
  t.ok(await nextMessage(peer, ARRIVAL_MS), 'an unarmed adapter forwards a route cell')
  await peer.send(cell, localPort, HOST)
  t.is(
    await waitForCount(inbound, 1, ARRIVAL_MS),
    1,
    'an unarmed adapter delivers an inbound route cell'
  )

  t.is(blackholeRouteCells(), true)
  t.is(blackholeRouteCells(), false, 'the verb refuses replay')

  // Outbound: the send resolves true, because anything else is a send failure that reports a
  // branch loss, which is the detected failure this verb exists to avoid producing.
  t.is(await local.send(cell, peerPort, HOST), true)
  t.absent(await nextMessage(peer, DROP_WINDOW_MS), 'an armed adapter drops an outbound route cell')
  t.is(await local.send(bootstrap, peerPort, HOST), true)
  t.ok(await nextMessage(peer, ARRIVAL_MS), 'an armed adapter still forwards a bootstrap envelope')

  // Ordered on one socket pair, so the bootstrap arriving is also evidence the cell sent
  // before it was dropped rather than merely still in flight.
  await peer.send(cell, localPort, HOST)
  await peer.send(bootstrap, localPort, HOST)
  t.is(
    await waitForCount(inbound, 2, ARRIVAL_MS),
    2,
    'an armed adapter swallows the inbound cell and delivers the rest'
  )
  t.is(inbound[1][1], BOOTSTRAP_CLASS)

  const snapshot = routeCellBlackholeSnapshot()
  t.is(snapshot.armed, true)
  t.is(snapshot.droppedOutbound, 1)
  t.is(snapshot.droppedInbound, 1)

  // Nothing was destroyed and nothing was unbound: that is the whole difference between this
  // verb and the two local-destroy verbs beside it. The bootstrap round trip above is the
  // behavioural half of that - a closed or unbound socket carries neither direction.
  t.is(local.address().port, localPort)
})
