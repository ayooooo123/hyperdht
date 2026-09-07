'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { PrivateRouteError } = require('../../lib/private/errors')
const { DIRECTION } = require('../../lib/private/protocol')
const {
  MAX_RELAY_CIRCUITS,
  MAX_RELAY_CIRCUITS_PER_NEIGHBOR,
  MAX_RELAY_CIRCUIT_QUEUE,
  MAX_RELAY_GLOBAL_QUEUE,
  RELAY_FORWARD_DEADLINE,
  RelayService,
  TEST_ONLY_RELAY_SERVICE_OBSERVER
} = require('../../lib/private/relay-service')

function seed(byte, size) {
  return b4a.alloc(size, byte)
}

function clock() {
  let now = 0
  let nextHandle = 1
  const timers = new Map()
  return {
    now: () => now,
    schedule(callback, delay) {
      const handle = nextHandle++
      timers.set(handle, { callback, at: now + delay, delay })
      return handle
    },
    cancel(handle) {
      timers.delete(handle)
    },
    advance(delta) {
      now += delta
      let matched = true
      while (matched) {
        matched = false
        for (const [handle, timer] of timers) {
          if (timer.at > now) continue
          timers.delete(handle)
          timer.callback()
          matched = true
          break
        }
      }
    },
    pending: () => timers.size,
    delays: () => Array.from(timers.values(), (timer) => timer.delay)
  }
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

function hop(log, name, onDestroy) {
  return {
    sendAuthenticated(payload, metadata) {
      log.push({ name, payload: b4a.from(payload), metadata })
      return true
    },
    destroy(reason) {
      if (onDestroy) onDestroy(reason)
    }
  }
}

function fixture(overrides = {}) {
  const time = clock()
  const sent = []
  const events = []
  const relay = new RelayService({
    now: time.now,
    schedule: time.schedule,
    cancel: time.cancel,
    onEvent(event) {
      events.push(event)
    },
    ...overrides
  })
  return { time, sent, events, relay }
}

function reserve(relay, index, overrides = {}) {
  const peerId = overrides.peerId || seed(0x40 + (index % 64), 32)
  const circuitId = overrides.circuitId || seed(index + 1, 16)
  relay.reserveCircuit({
    peerId,
    circuitId,
    previousHop: overrides.previousHop || hop([], 'previous'),
    nextHop: overrides.nextHop || hop([], 'next'),
    generation: overrides.generation === undefined ? 7n : overrides.generation,
    limits: overrides.limits
  })
  return { peerId, circuitId }
}

test('RelayService freezes canonical quota defaults', (t) => {
  t.is(MAX_RELAY_CIRCUITS, 128)
  t.is(MAX_RELAY_CIRCUITS_PER_NEIGHBOR, 32)
  t.is(MAX_RELAY_CIRCUIT_QUEUE, 256 * 1024)
  t.is(MAX_RELAY_GLOBAL_QUEUE, 8 * 1024 * 1024)
  t.is(RELAY_FORWARD_DEADLINE, 5_000)
})

test('RelayService enforces global and per-neighbor circuit quotas', (t) => {
  const samePeer = fixture()
  const peerId = seed(0x31, 32)
  for (let i = 0; i < MAX_RELAY_CIRCUITS_PER_NEIGHBOR; i++) reserve(samePeer.relay, i, { peerId })
  expectCode(t, () => reserve(samePeer.relay, 40, { peerId }), 'ERR_BUSY')
  t.is(samePeer.relay[TEST_ONLY_RELAY_SERVICE_OBSERVER]().circuits, 32)

  const global = fixture()
  for (let i = 0; i < MAX_RELAY_CIRCUITS; i++) {
    reserve(global.relay, i, { peerId: seed(0x10 + Math.floor(i / 16), 32) })
  }
  expectCode(t, () => reserve(global.relay, 129, { peerId: seed(0xf1, 32) }), 'ERR_QUOTA_EXCEEDED')
  t.is(global.relay[TEST_ONLY_RELAY_SERVICE_OBSERVER]().circuits, 128)
})

test('RelayService negotiates queue limits only downward', (t) => {
  const raised = fixture()
  const raisedCircuit = reserve(raised.relay, 1, {
    limits: { maxQueuedBytesPerCircuit: MAX_RELAY_CIRCUIT_QUEUE * 2 }
  })
  expectCode(
    t,
    () =>
      raised.relay.trySend(
        raisedCircuit.circuitId,
        DIRECTION.FORWARD,
        seed(0x61, MAX_RELAY_CIRCUIT_QUEUE + 1)
      ),
    'ERR_QUOTA_EXCEEDED'
  )

  const lowered = fixture()
  const loweredCircuit = reserve(lowered.relay, 2, { limits: { maxQueuedBytesPerCircuit: 4 } })
  t.is(lowered.relay.trySend(loweredCircuit.circuitId, DIRECTION.FORWARD, seed(0x62, 4)), true)
  expectCode(
    t,
    () => lowered.relay.trySend(loweredCircuit.circuitId, DIRECTION.FORWARD, seed(0x63, 1)),
    'ERR_QUOTA_EXCEEDED'
  )
  t.is(lowered.relay[TEST_ONLY_RELAY_SERVICE_OBSERVER]().globalBytes, 4)
})

test('RelayService admits queues atomically before copying payloads', (t) => {
  const f = fixture({
    allocate() {
      throw new Error('alloc failure')
    }
  })
  const circuit = reserve(f.relay, 1)
  expectCode(
    t,
    () => f.relay.trySend(circuit.circuitId, DIRECTION.FORWARD, seed(0x64, 8)),
    'ROUTE_UNAVAILABLE'
  )
  const observed = f.relay[TEST_ONLY_RELAY_SERVICE_OBSERVER]()
  t.is(observed.globalBytes, 0)
  t.is(observed.records[0].queuedBytes, 0)
})

test('RelayService allocation failure does not burn replay counter', (t) => {
  let fail = true
  const f = fixture({
    allocate(size) {
      if (fail) throw new Error('alloc failure')
      return b4a.allocUnsafeSlow(size)
    }
  })
  const circuit = reserve(f.relay, 1)
  expectCode(
    t,
    () => f.relay.trySend(circuit.circuitId, DIRECTION.FORWARD, seed(0x65, 8), { counter: 2n }),
    'ROUTE_UNAVAILABLE'
  )
  fail = false
  t.is(f.relay.trySend(circuit.circuitId, DIRECTION.FORWARD, seed(0x66, 8), { counter: 2n }), true)
})

test('RelayService callback failure rolls back queue and replay counter', (t) => {
  let fail = true
  const f = fixture({
    onEvent(event) {
      if (fail && event.type === 'queued') throw new Error('observer failure')
    }
  })
  const circuit = reserve(f.relay, 1)
  expectCode(
    t,
    () => f.relay.trySend(circuit.circuitId, DIRECTION.FORWARD, seed(0x67, 8), { counter: 3n }),
    'ROUTE_UNAVAILABLE'
  )
  t.is(f.relay[TEST_ONLY_RELAY_SERVICE_OBSERVER]().globalBytes, 0)
  fail = false
  t.is(f.relay.trySend(circuit.circuitId, DIRECTION.FORWARD, seed(0x68, 8), { counter: 3n }), true)
})

test('RelayService forwards cells in circuit round-robin order', (t) => {
  const f = fixture()
  const firstLog = []
  const secondLog = []
  const first = reserve(f.relay, 1, { generation: 11n, nextHop: hop(firstLog, 'first-next') })
  const second = reserve(f.relay, 2, { generation: 12n, nextHop: hop(secondLog, 'second-next') })

  t.is(f.relay.trySend(first.circuitId, DIRECTION.FORWARD, b4a.from('a0')), true)
  t.is(f.relay.trySend(first.circuitId, DIRECTION.FORWARD, b4a.from('a1')), true)
  t.is(f.relay.trySend(second.circuitId, DIRECTION.FORWARD, b4a.from('b0')), true)
  t.is(f.relay.trySend(first.circuitId, DIRECTION.FORWARD, b4a.from('a2')), true)
  t.is(f.relay.dispatch(4), 4)
  t.alike(
    firstLog.map((entry) => b4a.toString(entry.payload)),
    ['a0', 'a1', 'a2']
  )
  t.alike(
    secondLog.map((entry) => b4a.toString(entry.payload)),
    ['b0']
  )
  t.alike(
    f.events.filter((event) => event.type === 'sent').map((event) => event.circuitId[0]),
    [2, 3, 2, 2]
  )
  t.alike(
    firstLog.map((entry) => entry.metadata.generation),
    [11n, 11n, 11n]
  )
  t.alike(
    secondLog.map((entry) => entry.metadata.generation),
    [12n]
  )
})

test('RelayService destroys and tombstones on adjacent link loss', (t) => {
  const f = fixture()
  const nextHop = {
    sendAuthenticated() {
      return false
    }
  }
  const circuit = reserve(f.relay, 1, { nextHop })
  t.is(f.relay.trySend(circuit.circuitId, DIRECTION.FORWARD, b4a.from('drop')), true)
  t.is(f.relay.dispatch(1), 1)
  t.is(f.relay.status(circuit.circuitId).state, 'DESTROYED')
  t.is(f.relay.status(circuit.circuitId).tombstone.reason, 'UNAVAILABLE')
  expectCode(
    t,
    () => f.relay.trySend(circuit.circuitId, DIRECTION.FORWARD, b4a.from('late')),
    'ERR_DESTROYED'
  )
})

test('RelayService expires one route generation without touching another', (t) => {
  const f = fixture()
  const first = reserve(f.relay, 1, { generation: 21n })
  const second = reserve(f.relay, 2, { generation: 22n })
  t.is(f.relay.trySend(first.circuitId, DIRECTION.FORWARD, b4a.from('first')), true)
  t.is(f.relay.trySend(second.circuitId, DIRECTION.FORWARD, b4a.from('second')), true)
  t.is(f.relay.expireGeneration(21n), 1)
  t.is(f.relay.status(first.circuitId).state, 'DESTROYED')
  t.is(f.relay.status(first.circuitId).tombstone.reason, 'GENERATION_EXPIRED')
  t.is(f.relay.status(second.circuitId).state, 'OPEN')
  t.is(f.relay[TEST_ONLY_RELAY_SERVICE_OBSERVER]().globalBytes, 6)
})

test('RelayService tracks replay tombstones and five-second expiry', (t) => {
  const f = fixture()
  const circuit = reserve(f.relay, 1)
  t.alike(f.time.delays(), [RELAY_FORWARD_DEADLINE])
  t.is(
    f.relay.trySend(circuit.circuitId, DIRECTION.FORWARD, b4a.from('once'), { counter: 1n }),
    true
  )
  expectCode(
    t,
    () => f.relay.trySend(circuit.circuitId, DIRECTION.FORWARD, b4a.from('twice'), { counter: 1n }),
    'ERR_REPLAY'
  )
  f.time.advance(RELAY_FORWARD_DEADLINE - 1)
  t.is(f.relay.status(circuit.circuitId).state, 'OPEN')
  f.time.advance(1)
  t.is(f.relay.status(circuit.circuitId).state, 'DESTROYED')
  expectCode(
    t,
    () => f.relay.trySend(circuit.circuitId, DIRECTION.FORWARD, b4a.from('late')),
    'ERR_DESTROYED'
  )
})

test('RelayService destroy clears routing state before closing capabilities', (t) => {
  const f = fixture()
  const circuitId = seed(0x71, 16)
  let statusDuringClose = null
  let sendDuringClose = null
  const previousHop = hop([], 'previous', () => {
    statusDuringClose = f.relay.status(circuitId).state
    try {
      f.relay.trySend(circuitId, DIRECTION.FORWARD, b4a.from('reenter'))
    } catch (err) {
      sendDuringClose = err.code
    }
  })
  reserve(f.relay, 1, { circuitId, previousHop })
  t.is(f.relay.trySend(circuitId, DIRECTION.FORWARD, b4a.from('queued')), true)
  const payload = f.relay.destroy()
  t.is(payload.globalBytes, 6)
  t.is(payload.circuits.length, 1)
  t.is(statusDuringClose, 'DESTROYED')
  t.is(sendDuringClose, 'ERR_DESTROYED')
  t.is(f.relay[TEST_ONLY_RELAY_SERVICE_OBSERVER]().destroyed, true)
  t.is(f.time.pending(), 0)
})

test('RelayService cancel and duplicate destroy leave one tombstone', (t) => {
  const f = fixture()
  const circuit = reserve(f.relay, 1)
  t.is(f.relay.cancelCircuit(circuit.circuitId, 'REQUESTED'), true)
  t.is(f.relay.status(circuit.circuitId).state, 'DESTROYED')
  expectCode(t, () => f.relay.cancelCircuit(circuit.circuitId), 'ERR_DESTROYED')
  t.is(f.relay.destroy().circuits.length, 0)
  t.is(f.relay.destroy(), false)
  t.is(f.relay[TEST_ONLY_RELAY_SERVICE_OBSERVER]().tombstones, 1)
})
