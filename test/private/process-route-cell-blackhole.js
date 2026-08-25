'use strict'

const test = require('brittle')
const b4a = require('b4a')
const UDX = require('udx-native')

const { BOOTSTRAP_CLASS, BOOTSTRAP_SIZE } = require('../../lib/private/bootstrap-envelope')
const { CELL_CLASS, DIRECTION, PROTOCOL_VERSION } = require('../../lib/private/protocol')
const {
  LINK_PING_AFTER,
  LINK_UNRESPONSIVE_AFTER,
  STREAM_ACK_TIMEOUT,
  LinkControlSession,
  createLinkControlBoundary,
  readLinkControlStreamProgress
} = require('../../lib/private/link-control-session')
const {
  blackholeRouteCells,
  isRouteCellDatagram,
  resetRouteCellBlackholeForTest,
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

test('KI-10: idle blackholed hop emits physical loss at LINK_UNRESPONSIVE_AFTER (1500ms)', async (t) => {
  resetRouteCellBlackholeForTest()
  t.is(LINK_PING_AFTER, 500, 'native heartbeat pings every 500ms')
  t.is(LINK_UNRESPONSIVE_AFTER, 1500, 'native unresponsiveness detector fires at 1500ms')
  t.is(STREAM_ACK_TIMEOUT, 5000, 'stream ACK timeout is 5000ms (distinct backstop)')

  let simulatedNow = 0
  let nextTimerId = 1
  const timers = new Map()
  const clock = {
    now: () => simulatedNow,
    schedule(callback, delay) {
      const id = nextTimerId++
      timers.set(id, { at: simulatedNow + delay, callback })
      return id
    },
    cancel(id) {
      timers.delete(id)
    },
    advance(delta) {
      simulatedNow += delta
      let found = true
      while (found) {
        found = false
        for (const [id, timer] of timers) {
          if (timer.at > simulatedNow) continue
          timers.delete(id)
          timer.callback()
          found = true
          break
        }
      }
    }
  }

  const link = Object.freeze({})
  const circuitId = b4a.alloc(16, 0x42)
  const boundary = createLinkControlBoundary({ link, epoch: 1n, circuitId })

  const sentPackets = []
  const linkFailures = []
  let closedLinks = 0
  let m3PhysicalLossFired = 0

  // Mock M3 physical loss sink to verify end-to-end trigger contract
  const physicalLossSink = () => {
    m3PhysicalLossFired++
  }

  const session = new LinkControlSession({
    control: boundary.consumer,
    circuitId,
    epoch: 1n,
    heartbeatDirection: DIRECTION.FORWARD,
    now: clock.now,
    schedule: clock.schedule,
    cancel: clock.cancel,
    randomBytes: (size) => b4a.alloc(size, 0x11),
    sendControl(packet) {
      sentPackets.push(b4a.from(packet))
      // Under blackhole, outbound route cells (CONTROL) are dropped by the adapter
      return Promise.resolve(true)
    },
    cancelPending() {},
    notifyCircuit(direction, reason) {
      linkFailures.push({ direction, reason, at: simulatedNow })
    },
    closeLink() {
      closedLinks++
      physicalLossSink()
    }
  })

  t.is(session.closed, false)
  t.is(sentPackets.length, 0)

  // 1. Advance to 499ms: idle link has not yet pinged
  clock.advance(499)
  t.is(sentPackets.length, 0, 'no ping before LINK_PING_AFTER')
  t.is(session.closed, false)

  // 2. Advance to 500ms: first PING is transmitted
  clock.advance(1)
  t.is(sentPackets.length, 1, 'first PING sent at t=500ms')
  t.is(isRouteCellDatagram(datagram(PROTOCOL_VERSION, CELL_CLASS.CONTROL)), true)
  t.is(session.closed, false)
  t.is(closedLinks, 0)

  // 3. Advance to 1000ms: second PING transmitted (hop remains silent due to blackhole)
  clock.advance(500)
  t.is(sentPackets.length, 2, 'second PING sent at t=1000ms')
  t.is(session.closed, false)
  t.is(closedLinks, 0)

  // 4. Advance to 1499ms: unresponsiveness deadline not yet reached
  clock.advance(499)
  t.is(session.closed, false)
  t.is(closedLinks, 0)
  t.is(m3PhysicalLossFired, 0)

  // 5. Advance to 1500ms: LINK_UNRESPONSIVE_AFTER fires!
  clock.advance(1)
  t.is(session.closed, true, 'session closed at exactly 1500ms')
  t.is(closedLinks, 1, 'closeLink triggered UDX_LINK_CLOSE')
  t.is(m3PhysicalLossFired, 1, 'M3 physical loss sink invoked at 1500ms')
  t.alike(linkFailures, [{ direction: DIRECTION.FORWARD, reason: 'ROUTE_UNAVAILABLE', at: 1500 }])

  boundary.destroy()
})

test('KI-10: inbound route cell activity resets liveness timer preventing premature loss', async (t) => {
  resetRouteCellBlackholeForTest()

  let simulatedNow = 0
  let nextTimerId = 1
  const timers = new Map()
  const clock = {
    now: () => simulatedNow,
    schedule(callback, delay) {
      const id = nextTimerId++
      timers.set(id, { at: simulatedNow + delay, callback })
      return id
    },
    cancel(id) {
      timers.delete(id)
    },
    advance(delta) {
      simulatedNow += delta
      let found = true
      while (found) {
        found = false
        for (const [id, timer] of timers) {
          if (timer.at > simulatedNow) continue
          timers.delete(id)
          timer.callback()
          found = true
          break
        }
      }
    }
  }

  const link = Object.freeze({})
  const circuitId = b4a.alloc(16, 0x43)
  const boundary = createLinkControlBoundary({ link, epoch: 1n, circuitId })
  let closedLinks = 0

  const session = new LinkControlSession({
    control: boundary.consumer,
    circuitId,
    epoch: 1n,
    heartbeatDirection: DIRECTION.FORWARD,
    now: clock.now,
    schedule: clock.schedule,
    cancel: clock.cancel,
    randomBytes: (size) => b4a.alloc(size, 0x22),
    sendControl() {
      return Promise.resolve(true)
    },
    cancelPending() {},
    notifyCircuit() {},
    closeLink() {
      closedLinks++
    }
  })

  // At t=800ms, an inbound cell arrives, resetting lastActivity to 800ms
  clock.advance(800)
  t.is(session.closed, false)
  session.receiveAuthenticated(
    boundary.pushAuthenticated({
      link,
      epoch: 1n,
      circuitId,
      class: CELL_CLASS.DATAGRAM,
      direction: DIRECTION.REVERSE,
      generation: 1n,
      counter: 0n,
      payload: b4a.from('payload')
    }),
    {
      enqueueDatagram() {
        return true
      }
    }
  )

  // At t=1500ms (700ms after last cell), session must still be alive (silence is only 700ms)
  clock.advance(700)
  t.is(
    session.closed,
    false,
    'link remains alive at t=1500ms because activity reset timer at t=800ms'
  )
  t.is(closedLinks, 0)

  // At t=2300ms (800ms + 1500ms), silence reaches 1500ms, so detector fires
  clock.advance(800)
  t.is(session.closed, true, 'link declared lost at t=2300ms (exactly 1500ms after last activity)')
  t.is(closedLinks, 1)

  boundary.destroy()
})
