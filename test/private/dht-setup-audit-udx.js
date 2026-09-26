'use strict'

const test = require('brittle')
const b4a = require('b4a')
const c = require('compact-encoding')
const { EventEmitter } = require('events')

const { PROCESS_PLANS } = require('./process/topology-fixture')
const {
  AUDIT_CLASSES,
  AUDIT_PHASES,
  TEST_ONLY_AUDIT_CONTEXT_ISSUER
} = require('./process/audit-event')
const {
  armSetupDhtAudit,
  createDhtSetupAuditController,
  destroyDhtSetupAuditController,
  drainDhtSetupAuditEvents
} = require('./process/dht-setup-audit-udx')

const SOURCE = Object.freeze({ host: '127.64.10.1', port: 42_010 })
const DESTINATION = Object.freeze({ host: '127.64.11.1', port: 42_011 })

function encodePacket({
  command,
  internal = false,
  target = null,
  tid,
  to = null,
  value = null,
  response = false
}) {
  const flags = (internal ? 4 : 0) | (target === null ? 0 : 8) | (value === null ? 0 : 16)
  const state = { start: 0, end: 1 + 1 + 2 + 6, buffer: null }
  if (!response) c.uint.preencode(state, command)
  if (target !== null) state.end += 32
  if (value !== null) c.buffer.preencode(state, value)
  state.buffer = b4a.allocUnsafeSlow(state.end)
  state.buffer[state.start++] = response ? 0x13 : 0x03
  state.buffer[state.start++] = flags
  c.uint16.encode(state, tid)
  c.ipv4Address.encode(state, to === null ? (response ? SOURCE : DESTINATION) : to)
  if (!response) c.uint.encode(state, command)
  if (target !== null) c.fixed32.encode(state, target)
  if (value !== null) c.buffer.encode(state, value)
  return state.buffer
}

class FakeSocket extends EventEmitter {
  constructor() {
    super()
    this.bound = false
    this.closed = false
    this.calls = []
    this.local = null
  }

  bind(port, host) {
    this.bound = true
    this.local = { host, port }
  }

  address() {
    return this.local
  }

  trySend(buffer, port, host, ttl) {
    this.calls.push({ buffer, host, port, ttl })
    return true
  }

  close() {
    this.closed = true
    return Promise.resolve()
  }
}

class FakeUDX {
  constructor() {
    this.interfaces = Object.freeze({ marker: true })
    this.sockets = []
  }

  watchNetworkInterfaces() {
    return this.interfaces
  }

  createSocket() {
    const socket = new FakeSocket()
    this.sockets.push(socket)
    return socket
  }
}

function fixture() {
  const udx = new FakeUDX()
  const events = []
  const failures = []
  let now = 1_000n
  let nonce = 0
  const key = b4a.alloc(32, 7)
  const controller = createDhtSetupAuditController({
    auditContext: TEST_ONLY_AUDIT_CONTEXT_ISSUER.context({
      destinationRoleIndex: 11,
      phase: AUDIT_PHASES.DHT_SETUP,
      plan: PROCESS_PLANS.PORTABLE_LOOPBACK,
      roleIndex: 10
    }),
    emit(event) {
      events.push(event)
    },
    onFailure(err) {
      failures.push(err)
    },
    generation: 1n,
    destination: DESTINATION,
    key,
    maximumCorrelations: 64,
    maximumEvents: 16,
    monotonicNow() {
      return now
    },
    phaseSequence() {
      return 3n
    },
    randomBytes(size) {
      return b4a.alloc(size, ++nonce)
    },
    source: SOURCE,
    udx
  })
  return {
    controller,
    events,
    failures,
    socket() {
      const socket = controller.udx.createSocket()
      socket.bind(SOURCE.port, SOURCE.host)
      return socket
    },
    tick(ms) {
      now += BigInt(ms)
    },
    udx
  }
}

function zeroDigest() {
  return b4a.alloc(32)
}

function throwsCode(t, fn, expected, message) {
  let code = null
  try {
    fn()
  } catch (err) {
    code = err && err.code
  }
  t.is(code, expected, message)
}

test('direct dht request packet is observed only at native trySend with its assigned TID', (t) => {
  const f = fixture()
  const socket = f.socket()
  const target = b4a.alloc(32, 9)
  armSetupDhtAudit(f.controller, {
    class: AUDIT_CLASSES.SETUP_STORE_TOKEN,
    command: 9,
    destination: DESTINATION,
    target,
    valueDigest: zeroDigest()
  })
  t.is(f.events.length, 0)
  const packet = encodePacket({ command: 9, target, tid: 321 })
  socket.trySend(packet, DESTINATION.port, DESTINATION.host, 0)
  t.is(f.events.length, 1)
  t.is(f.events[0].transactionId, 321)
  t.is(f.events[0].class, AUDIT_CLASSES.SETUP_STORE_TOKEN)
  t.is(f.udx.sockets[0].calls.length, 1)
  t.is(f.udx.sockets[0].calls[0].buffer, packet)
  destroyDhtSetupAuditController(f.controller)
})

test('setup observing UDX correlates swapped reply before forwarding unchanged', (t) => {
  const f = fixture()
  const socket = f.socket()
  const target = b4a.alloc(32, 5)
  const received = []
  socket.on('message', (buffer, from) => received.push({ buffer, from }))
  armSetupDhtAudit(f.controller, {
    class: AUDIT_CLASSES.SETUP_STORE_TOKEN,
    command: 9,
    destination: DESTINATION,
    target,
    valueDigest: zeroDigest()
  })
  const request = encodePacket({ command: 9, target, tid: 44 })
  socket.trySend(request, DESTINATION.port, DESTINATION.host, 0)
  const reply = encodePacket({ command: 0, tid: 44, response: true, value: b4a.from('value') })
  const from = {
    host: DESTINATION.host,
    port: DESTINATION.port,
    family: 4,
    nativeSize: 16
  }
  f.udx.sockets[0].emit('message', reply, from)
  t.is(f.events.length, 2)
  t.is(f.events[0].type, 'audit-open')
  t.is(f.events[1].type, 'audit-close')
  t.is(received.length, 1)
  t.is(received[0].buffer, reply)
  t.alike(received[0].from, { host: DESTINATION.host, port: DESTINATION.port })
  t.absent(received[0].from === from, 'native source metadata is not forwarded')
  t.is(f.failures.length, 0)
  destroyDhtSetupAuditController(f.controller)
})

test('setup observing UDX rejects unarmed, mismatched, tid-reuse, forged and post-destroy traffic', (t) => {
  const f = fixture()
  const socket = f.socket()
  const target = b4a.alloc(32, 6)
  const packet = encodePacket({ command: 9, target, tid: 10 })
  t.exception(() => socket.trySend(packet, DESTINATION.port, DESTINATION.host, 0))
  armSetupDhtAudit(f.controller, {
    class: AUDIT_CLASSES.SETUP_STORE_TOKEN,
    command: 9,
    destination: DESTINATION,
    target,
    valueDigest: zeroDigest()
  })
  t.exception(() => socket.trySend(packet, DESTINATION.port, '127.64.9.1', 0))
  socket.trySend(packet, DESTINATION.port, DESTINATION.host, 0)
  const colliding = encodePacket({ command: 9, target, tid: 10, value: b4a.from('extra') })
  throwsCode(
    t,
    () => socket.trySend(colliding, DESTINATION.port, DESTINATION.host, 0),
    'PROCESS_DHT_SETUP_REPLAY',
    'different bytes reusing an outstanding tid are a replay'
  )
  const forged = encodePacket({ command: 0, tid: 11, response: true })
  t.is(
    f.udx.sockets[0].emit('message', forged, {
      host: DESTINATION.host,
      port: DESTINATION.port,
      nativeSize: 16
    }),
    true
  )
  t.is(f.failures.length, 1)
  t.is(f.failures[0].code, 'PROCESS_DHT_SETUP_FORGED_RESPONSE')
  t.is(f.udx.sockets[0].closed, true)
  destroyDhtSetupAuditController(f.controller)
  t.exception(() => socket.trySend(packet, DESTINATION.port, DESTINATION.host, 0))
})

test('setup observing UDX delegates network watches and passes internal request/reply byte-identically', (t) => {
  const f = fixture()
  t.is(f.controller.udx.watchNetworkInterfaces(), f.udx.interfaces)
  const socket = f.socket()
  const packet = encodePacket({ command: 0, internal: true, tid: 88 })
  socket.trySend(packet, DESTINATION.port, DESTINATION.host, 3)
  t.is(f.udx.sockets[0].calls.length, 1)
  t.is(f.udx.sockets[0].calls[0].buffer, packet)
  const reply = encodePacket({ command: 0, tid: 88, response: true })
  const from = { host: DESTINATION.host, port: DESTINATION.port }
  f.udx.sockets[0].emit('message', reply, from)
  t.is(f.events.length, 0)
  destroyDhtSetupAuditController(f.controller)
})

test('setup observing UDX forwards an identical setup retransmission against one record', (t) => {
  const f = fixture()
  const socket = f.socket()
  const target = b4a.alloc(32, 4)
  armSetupDhtAudit(f.controller, {
    class: AUDIT_CLASSES.SETUP_STORE_TOKEN,
    command: 9,
    destination: DESTINATION,
    target,
    valueDigest: zeroDigest()
  })
  const request = encodePacket({ command: 9, target, tid: 77 })
  socket.trySend(request, DESTINATION.port, DESTINATION.host, 0)
  // dht-rpc resends the same buffer object; the copy proves the audit compares
  // bytes rather than buffer identity.
  socket.trySend(b4a.from(request), DESTINATION.port, DESTINATION.host, 0)
  socket.trySend(request, DESTINATION.port, DESTINATION.host, 0)
  t.is(f.udx.sockets[0].calls.length, 3, 'every copy reaches the wire')
  t.is(f.events.length, 1, 'no second audit record is opened')
  t.is(f.events[0].type, 'audit-open')
  t.is(f.failures.length, 0)
  const reply = encodePacket({ command: 0, tid: 77, response: true, value: b4a.from('value') })
  f.udx.sockets[0].emit('message', reply, { host: DESTINATION.host, port: DESTINATION.port })
  t.is(f.events.length, 2, 'the first reply closes the single record')
  t.is(f.events[1].type, 'audit-close')
  const drained = drainDhtSetupAuditEvents(f.controller)
  t.is(drained.length, 2)
  t.is(drained.retransmissions, 2, 'both retransmissions are counted')
  // closeSetup deleted the correlation, so a request replayed afterwards is
  // judged by the arm check exactly as it is today.
  throwsCode(
    t,
    () => socket.trySend(request, DESTINATION.port, DESTINATION.host, 0),
    'PROCESS_DHT_SETUP_UNARMED',
    'a request replayed after closeSetup finds no correlation'
  )
  destroyDhtSetupAuditController(f.controller)
})

test('setup observing UDX accepts an internal retransmission and one reply per copy', (t) => {
  const f = fixture()
  const socket = f.socket()
  const received = []
  socket.on('message', (buffer) => received.push(buffer))
  const request = encodePacket({ command: 0, internal: true, tid: 91 })
  socket.trySend(request, DESTINATION.port, DESTINATION.host, 3)
  socket.trySend(b4a.from(request), DESTINATION.port, DESTINATION.host, 3)
  t.is(f.udx.sockets[0].calls.length, 2, 'both copies reach the wire')
  t.is(f.failures.length, 0)
  const colliding = encodePacket({ command: 1, internal: true, tid: 91 })
  throwsCode(
    t,
    () => socket.trySend(colliding, DESTINATION.port, DESTINATION.host, 3),
    'PROCESS_DHT_SETUP_REPLAY',
    'a different internal request on the same tid is a replay'
  )
  const reply = encodePacket({ command: 0, tid: 91, response: true })
  const from = { host: DESTINATION.host, port: DESTINATION.port }
  f.udx.sockets[0].emit('message', reply, from)
  f.udx.sockets[0].emit('message', reply, from)
  t.is(received.length, 2, 'each copy may be answered')
  t.is(f.failures.length, 0)
  t.is(drainDhtSetupAuditEvents(f.controller).retransmissions, 1)
  f.udx.sockets[0].emit('message', reply, from)
  t.is(f.failures.length, 1, 'a reply beyond the copies sent is uncorrelated')
  t.is(f.failures[0].code, 'PROCESS_DHT_SETUP_FORGED_RESPONSE')
  destroyDhtSetupAuditController(f.controller)
})

test('setup observing UDX accepts an inbound request retransmission and one reply per copy', (t) => {
  const f = fixture()
  const socket = f.socket()
  const received = []
  socket.on('message', (buffer) => received.push(buffer))
  const request = encodePacket({ command: 9, target: b4a.alloc(32, 3), tid: 55, to: SOURCE })
  const from = { host: DESTINATION.host, port: DESTINATION.port }
  f.udx.sockets[0].emit('message', request, from)
  f.udx.sockets[0].emit('message', b4a.from(request), from)
  t.is(received.length, 2, 'both copies reach the node')
  t.is(f.failures.length, 0)
  const reply = encodePacket({ command: 0, tid: 55, response: true, to: DESTINATION })
  socket.trySend(reply, DESTINATION.port, DESTINATION.host, 0)
  socket.trySend(reply, DESTINATION.port, DESTINATION.host, 0)
  t.is(f.udx.sockets[0].calls.length, 2, 'each received copy may be answered')
  throwsCode(
    t,
    () => socket.trySend(reply, DESTINATION.port, DESTINATION.host, 0),
    'PROCESS_DHT_SETUP_UNCLASSIFIED',
    'a third reply has no received request left to answer'
  )
  t.is(drainDhtSetupAuditEvents(f.controller).retransmissions, 1)
  const colliding = encodePacket({ command: 9, target: b4a.alloc(32, 8), tid: 55, to: SOURCE })
  f.udx.sockets[0].emit('message', request, from)
  f.udx.sockets[0].emit('message', colliding, from)
  t.is(f.failures.length, 1)
  t.is(f.failures[0].code, 'PROCESS_DHT_SETUP_REPLAY')
  destroyDhtSetupAuditController(f.controller)
})
