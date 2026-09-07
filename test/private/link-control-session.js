'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { PrivateRouteError } = require('../../lib/private/errors')
const { CELL_CLASS, DIRECTION, PROTOCOL_VERSION } = require('../../lib/private/protocol')
const {
  LINK_PING_AFTER,
  LINK_CIRCUIT_TEARDOWN_TIMEOUT,
  LINK_UNRESPONSIVE_AFTER,
  STREAM_ACK_TIMEOUT,
  LinkCircuitTeardown,
  LinkControlSession,
  createOpenCircuitDirectionCapability,
  createLinkControlBoundary,
  readLinkControlStreamProgress,
  TEST_ONLY_LINK_CIRCUIT_TEARDOWN_OBSERVER,
  TEST_ONLY_LINK_CONTROL_SESSION_OBSERVER
} = require('../../lib/private/link-control-session')

// Adapted from the reviewed private-routes prototype at commit
// 0305df915b6a767093f9e75e6c06bc0a35da6169 and narrowed to Gate 3B1.

function clock() {
  let now = 0
  let next = 1
  const timers = new Map()
  const scheduled = []
  const run = () => {
    let found = true
    while (found) {
      found = false
      for (const [id, timer] of timers) {
        if (timer.at > now) continue
        timers.delete(id)
        timer.callback()
        found = true
        break
      }
    }
  }
  return {
    now: () => now,
    schedule(callback, delay) {
      scheduled.push(delay)
      const id = next++
      timers.set(id, { at: now + delay, callback })
      return id
    },
    cancel(id) {
      timers.delete(id)
    },
    advance(delta) {
      now += delta
      run()
    },
    pending: () => timers.size,
    scheduled
  }
}

function fixture(overrides = {}) {
  const time = clock()
  const link = Object.freeze({})
  const circuitId = b4a.alloc(16, 0x51)
  const boundary = createLinkControlBoundary({ link, epoch: 7n, circuitId })
  const sent = []
  let closed = 0
  const session = new LinkControlSession({
    control: boundary.consumer,
    circuitId,
    epoch: 7n,
    heartbeatDirection: DIRECTION.FORWARD,
    now: time.now,
    schedule: time.schedule,
    cancel: time.cancel,
    randomBytes: (size) => b4a.alloc(size, 0x61),
    sendControl(packet) {
      sent.push(b4a.from(packet))
      return Promise.resolve(true)
    },
    cancelPending() {},
    notifyCircuit() {},
    closeLink() {
      closed++
    },
    ...overrides
  })
  const event = (value) =>
    boundary.pushAuthenticated({
      link,
      epoch: 7n,
      circuitId,
      class: CELL_CLASS.DATAGRAM,
      direction: DIRECTION.FORWARD,
      generation: 1n,
      counter: 0n,
      payload: b4a.from('x'),
      ...value
    })
  return { time, link, circuitId, boundary, session, sent, event, closed: () => closed }
}

function expectCode(t, operation, expected) {
  let error = null
  try {
    operation()
  } catch (err) {
    error = err
  }
  t.ok(error instanceof PrivateRouteError)
  t.is(error && error.code, expected)
}

function writeU64(buffer, value, offset) {
  for (let index = offset + 7; index >= offset; index--) {
    buffer[index] = Number(value & 0xffn)
    value >>= 8n
  }
}

function ackPacket(circuitId, generation, counter) {
  const packet = b4a.alloc(45)
  packet[0] = 0
  packet[1] = PROTOCOL_VERSION
  packet[2] = 2
  packet[3] = 0
  packet[4] = DIRECTION.REVERSE
  b4a.copy(circuitId, packet, 5)
  writeU64(packet, generation, 21)
  writeU64(packet, counter, 29)
  return packet
}

test('control session enforces STREAM order and drops authenticated DATAGRAM replay', (t) => {
  const f = fixture()
  const streams = []
  t.is(
    f.session.receiveAuthenticated(
      f.event({ class: CELL_CLASS.STREAM, counter: 0n, payload: b4a.from('a') }),
      { enqueueStream: (payload) => (streams.push(b4a.from(payload)), true) }
    ),
    true
  )
  expectCode(
    t,
    () =>
      f.session.receiveAuthenticated(
        f.event({ class: CELL_CLASS.STREAM, counter: 2n, payload: b4a.from('gap') }),
        { enqueueStream: () => true }
      ),
    'COUNTER_GAP'
  )
  t.alike(streams, [b4a.from('a')])

  const replay = fixture()
  let datagrams = 0
  t.is(
    replay.session.receiveAuthenticated(replay.event({ deliver: false }), {
      enqueueDatagram() {
        datagrams++
        return true
      }
    }),
    true
  )
  t.is(datagrams, 0)
  replay.session.close()
  replay.boundary.destroy()
})

test('control session bounds ACK state and exposes generation progress', (t) => {
  const f = fixture({ maxPendingStreams: 2, maxPendingBytes: 10 })
  t.is(f.session.trackStream(DIRECTION.FORWARD, 1n, 0n, 4), true)
  t.is(f.session.trackStream(DIRECTION.FORWARD, 1n, 1n, 6), true)
  t.alike(readLinkControlStreamProgress(f.session, DIRECTION.FORWARD, 1n), {
    highestSent: 1n,
    highestAck: null,
    pendingStreams: 2,
    pendingBytes: 10
  })
  expectCode(t, () => f.session.trackStream(DIRECTION.FORWARD, 1n, 2n, 1), 'CIRCUIT_LIMIT')
  t.ok(f.session.closed)
})

test('control session accepts exact cumulative ACK once and rejects replay or malformed padding', (t) => {
  const accepted = fixture()
  accepted.session.trackStream(DIRECTION.FORWARD, 1n, 0n, 4)
  accepted.session.trackStream(DIRECTION.FORWARD, 1n, 1n, 6)
  t.is(
    accepted.session.receiveAuthenticated(
      accepted.event({
        class: CELL_CLASS.CONTROL,
        direction: DIRECTION.REVERSE,
        generation: 0n,
        counter: 0n,
        payload: ackPacket(accepted.circuitId, 1n, 1n)
      })
    ),
    true
  )
  t.alike(readLinkControlStreamProgress(accepted.session, DIRECTION.FORWARD, 1n), {
    highestSent: 1n,
    highestAck: 1n,
    pendingStreams: 0,
    pendingBytes: 0
  })
  expectCode(
    t,
    () =>
      accepted.session.receiveAuthenticated(
        accepted.event({
          class: CELL_CLASS.CONTROL,
          direction: DIRECTION.REVERSE,
          generation: 0n,
          counter: 1n,
          payload: ackPacket(accepted.circuitId, 1n, 1n)
        })
      ),
    'ROUTE_UNAVAILABLE'
  )
  t.is(accepted.session.closed, true)
  accepted.boundary.destroy()

  const malformed = fixture()
  malformed.session.trackStream(DIRECTION.FORWARD, 1n, 0n, 1)
  const packet = ackPacket(malformed.circuitId, 1n, 0n)
  packet[37] = 1
  expectCode(
    t,
    () =>
      malformed.session.receiveAuthenticated(
        malformed.event({
          class: CELL_CLASS.CONTROL,
          direction: DIRECTION.REVERSE,
          generation: 0n,
          counter: 0n,
          payload: packet
        })
      ),
    'INVALID_ROUTE'
  )
  t.is(malformed.session.closed, true)
  malformed.boundary.destroy()
})

test('control session pings at 500ms, closes at 1500ms, and clears timers', async (t) => {
  const f = fixture()
  t.is(LINK_PING_AFTER, 500)
  t.is(LINK_UNRESPONSIVE_AFTER, 1500)
  t.is(STREAM_ACK_TIMEOUT, 5000)
  f.time.advance(499)
  t.is(f.sent.length, 0)
  f.time.advance(1)
  await Promise.resolve()
  t.is(f.sent.length, 1)
  t.is(f.session.closed, false)
  f.time.advance(1000)
  t.is(f.session.closed, true)
  t.is(f.closed(), 1)
  t.is(f.time.pending(), 0)
  t.alike(f.session[TEST_ONLY_LINK_CONTROL_SESSION_OBSERVER](), {
    retainedReferences: 0,
    streams: 0,
    inboundStreams: 0,
    pendingSends: 0,
    closed: true
  })
  f.boundary.destroy()
})

test('control session fails closed at counter exhaustion and arms exact five-second teardown', async (t) => {
  const exhausted = fixture()
  expectCode(
    t,
    () => exhausted.session.trackStream(DIRECTION.FORWARD, 1n, 0xffff_ffff_ffff_ffffn, 1),
    'COUNTER_EXHAUSTED'
  )
  t.is(exhausted.session.closed, true)
  exhausted.boundary.destroy()

  let settleDestroy
  const destroying = fixture({
    sendControl() {
      return new Promise((resolve) => {
        settleDestroy = resolve
      })
    }
  })
  const teardown = new LinkCircuitTeardown({
    now: destroying.time.now,
    schedule: destroying.time.schedule,
    cancel: destroying.time.cancel
  })
  const capability = createOpenCircuitDirectionCapability({
    link: destroying.link,
    direction: DIRECTION.FORWARD,
    session: destroying.session
  })
  t.is(teardown.add(capability), true)
  t.is(teardown.fail(destroying.link, DIRECTION.FORWARD), true)
  t.is(teardown.fail(destroying.link, DIRECTION.FORWARD), true)
  t.is(
    destroying.time.scheduled.filter((delay) => delay === LINK_CIRCUIT_TEARDOWN_TIMEOUT).length,
    1,
    'repeat fail does not replace the armed teardown timer'
  )
  t.ok(destroying.time.scheduled.includes(LINK_CIRCUIT_TEARDOWN_TIMEOUT))
  t.is(LINK_CIRCUIT_TEARDOWN_TIMEOUT, 5000)
  settleDestroy(true)
  await Promise.resolve()
  await teardown.close()
  t.alike(teardown[TEST_ONLY_LINK_CIRCUIT_TEARDOWN_OBSERVER](), {
    records: 0,
    timers: 0,
    retainedCallbacks: 0,
    closed: true
  })
  destroying.boundary.destroy()
})

test('throwing timer cancellation cannot retain ACK or circuit teardown state', async (t) => {
  let ackTime = null
  const acknowledging = fixture({
    cancel(id) {
      ackTime.cancel(id)
      throw new Error('injected ACK cancel failure')
    }
  })
  ackTime = acknowledging.time
  acknowledging.session.trackStream(DIRECTION.FORWARD, 1n, 0n, 4)
  t.is(
    acknowledging.session.receiveAuthenticated(
      acknowledging.event({
        class: CELL_CLASS.CONTROL,
        direction: DIRECTION.REVERSE,
        generation: 0n,
        counter: 0n,
        payload: ackPacket(acknowledging.circuitId, 1n, 0n)
      })
    ),
    true
  )
  t.alike(readLinkControlStreamProgress(acknowledging.session, DIRECTION.FORWARD, 1n), {
    highestSent: 0n,
    highestAck: 0n,
    pendingStreams: 0,
    pendingBytes: 0
  })
  acknowledging.session.close()
  t.is(acknowledging.time.pending(), 0)
  t.alike(acknowledging.session[TEST_ONLY_LINK_CONTROL_SESSION_OBSERVER](), {
    retainedReferences: 0,
    streams: 0,
    inboundStreams: 0,
    pendingSends: 0,
    closed: true
  })
  acknowledging.boundary.destroy()

  let settleDestroy = null
  const destroying = fixture({
    sendControl() {
      return new Promise((resolve) => {
        settleDestroy = resolve
      })
    }
  })
  const teardown = new LinkCircuitTeardown({
    now: destroying.time.now,
    schedule: destroying.time.schedule,
    cancel(id) {
      destroying.time.cancel(id)
      throw new Error('injected teardown cancel failure')
    }
  })
  teardown.add(
    createOpenCircuitDirectionCapability({
      link: destroying.link,
      direction: DIRECTION.FORWARD,
      session: destroying.session
    })
  )
  teardown.fail(destroying.link, DIRECTION.FORWARD)
  settleDestroy(true)
  await Promise.resolve()
  await Promise.resolve()
  await teardown.close()
  t.is(destroying.time.pending(), 0)
  t.alike(teardown[TEST_ONLY_LINK_CIRCUIT_TEARDOWN_OBSERVER](), {
    records: 0,
    timers: 0,
    retainedCallbacks: 0,
    closed: true
  })
  destroying.boundary.destroy()
})

test('control close rejects and clears a pending authenticated send before releasing callbacks', async (t) => {
  let settle
  let owned = null
  const pending = new Promise((resolve) => {
    settle = resolve
  })
  const f = fixture({
    sendControl(packet) {
      owned = packet
      return pending
    }
  })
  const destroying = f.session.destroy()
  t.is(f.session.pendingSends, 1)
  t.is(f.session.close(), true)
  t.is(f.session.pendingSends, 0)
  t.ok(
    owned.every((byte) => byte === 0),
    'pending authenticated control bytes are zeroed'
  )
  t.alike(f.session[TEST_ONLY_LINK_CONTROL_SESSION_OBSERVER](), {
    retainedReferences: 0,
    streams: 0,
    inboundStreams: 0,
    pendingSends: 0,
    closed: true
  })
  settle(true)
  await t.exception(destroying)
  f.boundary.destroy()
})
