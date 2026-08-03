'use strict'

const test = require('brittle')
const b4a = require('b4a')

const {
  AUDIT_CLASSES,
  AUDIT_OUTCOMES,
  AUDIT_PHASES,
  TEST_ONLY_AUDIT_CONTEXT_ISSUER,
  createAuditEventStream,
  createAuditEventVerifier,
  digestAuditRecord,
  digestPayload
} = require('./process/audit-event')
const { AUDIT_VECTOR } = require('./process/codec-vectors')
const { PROCESS_PLANS } = require('./process/topology-fixture')

function throwsCode(t, fn, code = 'PROCESS_AUDIT_INVALID') {
  let error = null
  try {
    fn()
  } catch (err) {
    error = err
  }
  t.ok(error)
  t.is(error && error.code, code)
}

function projectedTuple(roleIndex) {
  const value = b4a.alloc(19)
  const port = 42_000 + roleIndex
  value[0] = 4
  value[13] = 127
  value[14] = 64
  value[15] = roleIndex
  value[16] = 1
  value[17] = port >>> 8
  value[18] = port
  return value
}

function auditContext(roleIndex = 4, destinationRoleIndex = 9, phase = AUDIT_PHASES.READY) {
  return TEST_ONLY_AUDIT_CONTEXT_ISSUER.context({
    destinationRoleIndex,
    phase,
    plan: PROCESS_PLANS.PORTABLE_LOOPBACK,
    roleIndex
  })
}

function capturedReply(request, overrides = {}) {
  return {
    destination: b4a.from(request.source),
    payload: b4a.from(AUDIT_VECTOR.replyPayload, 'hex'),
    source: b4a.from(request.destination),
    transactionId: request.transactionId,
    ...overrides
  }
}

function record(overrides = {}) {
  return {
    class: AUDIT_CLASSES.ORDINARY_DHT_REQUEST,
    command: 9,
    destination: b4a.from(AUDIT_VECTOR.destination, 'hex'),
    generation: 7n,
    nonce: b4a.from(AUDIT_VECTOR.nonce, 'hex'),
    openingPhaseSequence: 11n,
    outboundPayload: b4a.from(AUDIT_VECTOR.outboundPayload, 'hex'),
    recordSequence: 1n,
    source: b4a.from(AUDIT_VECTOR.source, 'hex'),
    transactionId: 0x1234,
    ...overrides
  }
}

function streamFixture(options = {}) {
  const key = b4a.alloc(32, 0x5a)
  return {
    key,
    stream: createAuditEventStream({
      context: auditContext(),
      key,
      maximumRecords: 8,
      ...options
    })
  }
}

test('audit class and outcome byte registries are exact and frozen', (t) => {
  t.alike(AUDIT_CLASSES, {
    EXIT_VALIDATION_PROBE: 0x01,
    ORDINARY_DHT_REQUEST: 0x02,
    SETUP_STORE_TOKEN: 0x03,
    SETUP_STORE_PUT: 0x04,
    SETUP_STORE_READBACK: 0x05
  })
  t.alike(AUDIT_OUTCOMES, { SUCCESS: 0, TIMEOUT: 1, CANCELLED: 2, ERROR: 3 })
  t.ok(Object.isFrozen(AUDIT_CLASSES))
  t.ok(Object.isFrozen(AUDIT_OUTCOMES))
})

test('audit phase registry and projected context capabilities are exact and frozen', (t) => {
  t.alike(AUDIT_PHASES, {
    CAPTURE_START: 0x00,
    DHT_SETUP: 0x01,
    BOOTSTRAPPING: 0x02,
    GUARD_PINNED: 0x03,
    BUILDING: 0x04,
    READY: 0x05,
    ROTATING: 0x06,
    SUSPENDED: 0x07,
    RESUME_BUILDING: 0x08,
    UNAVAILABLE: 0x09,
    TEARDOWN: 0x0a,
    DESTROYED: 0x0b,
    CAPTURE_STOP: 0x0c
  })
  t.ok(Object.isFrozen(AUDIT_PHASES))
  throwsCode(t, () =>
    TEST_ONLY_AUDIT_CONTEXT_ISSUER.context({
      destinationRoleIndex: 11,
      phase: AUDIT_PHASES.READY,
      plan: PROCESS_PLANS.PORTABLE_LOOPBACK,
      roleIndex: 10
    })
  )
  throwsCode(t, () =>
    TEST_ONLY_AUDIT_CONTEXT_ISSUER.context({
      destinationRoleIndex: 9,
      phase: AUDIT_PHASES.READY,
      plan: { name: 'portable-loopback' },
      roleIndex: 4
    })
  )
})

test('record digest freezes the exact BLAKE2b-256 byte vector', (t) => {
  const value = record()
  const outbound = b4a.from(value.outboundPayload)
  const source = b4a.from(value.source)
  const destination = b4a.from(value.destination)
  t.is(b4a.toString(digestPayload(value.outboundPayload), 'hex'), AUDIT_VECTOR.outboundDigest)
  t.is(b4a.toString(digestAuditRecord(value), 'hex'), AUDIT_VECTOR.recordDigest)
  t.alike(value.outboundPayload, outbound, 'caller payload is borrowed, not destroyed')
  t.alike(value.source, source)
  t.alike(value.destination, destination)
})

test('setup audit classes are exact referral to value DHT_SETUP operations only', (t) => {
  const context = auditContext(10, 11, AUDIT_PHASES.DHT_SETUP)
  const source = projectedTuple(10)
  const destination = projectedTuple(11)
  const setup = [
    [AUDIT_CLASSES.SETUP_STORE_TOKEN, 9],
    [AUDIT_CLASSES.SETUP_STORE_PUT, 8],
    [AUDIT_CLASSES.SETUP_STORE_READBACK, 9]
  ]
  const { stream } = streamFixture({ context })
  const verifier = createAuditEventVerifier({
    context,
    key: b4a.alloc(32, 0x5a),
    maximumRecords: 8
  })
  for (let index = 0; index < setup.length; index++) {
    const [auditClass, command] = setup[index]
    const value = record({
      class: auditClass,
      command,
      destination: b4a.from(destination),
      nonce: b4a.alloc(16, index + 1),
      recordSequence: BigInt(index + 1),
      source: b4a.from(source),
      transactionId: 0x2000 + index
    })
    const open = stream.open(value)
    t.is(verifier.verifyOpen(open, value), true)
    t.is(open.class, auditClass)
    t.is(Reflect.ownKeys(open).includes('source'), false)
    t.is(Reflect.ownKeys(open).includes('destination'), false)
  }
  verifier.destroy()
  stream.destroy()
  for (const mutation of [
    { class: AUDIT_CLASSES.ORDINARY_DHT_REQUEST, command: 9 },
    { class: AUDIT_CLASSES.EXIT_VALIDATION_PROBE, command: 0 },
    { class: AUDIT_CLASSES.SETUP_STORE_TOKEN, command: 8 },
    { class: AUDIT_CLASSES.SETUP_STORE_PUT, command: 9 },
    { class: AUDIT_CLASSES.SETUP_STORE_READBACK, command: 8 },
    { class: AUDIT_CLASSES.SETUP_STORE_TOKEN, command: 9, source: projectedTuple(9) },
    {
      class: AUDIT_CLASSES.SETUP_STORE_TOKEN,
      command: 9,
      destination: projectedTuple(10)
    }
  ]) {
    const { stream } = streamFixture({ context })
    throwsCode(t, () => stream.open(record({ destination, source, ...mutation })))
    stream.destroy()
  }
  const { stream: ordinary } = streamFixture()
  throwsCode(t, () =>
    ordinary.open(
      record({
        class: AUDIT_CLASSES.SETUP_STORE_TOKEN,
        command: 9
      })
    )
  )
  ordinary.destroy()
})

test('DHT_SETUP stream and verifier enforce one TOKEN PUT READBACK sequence', (t) => {
  const context = auditContext(10, 11, AUDIT_PHASES.DHT_SETUP)
  const source = projectedTuple(10)
  const destination = projectedTuple(11)
  const setup = [
    [AUDIT_CLASSES.SETUP_STORE_TOKEN, 9],
    [AUDIT_CLASSES.SETUP_STORE_PUT, 8],
    [AUDIT_CLASSES.SETUP_STORE_READBACK, 9]
  ]
  const setupRecord = (index, overrides = {}) =>
    record({
      class: setup[index][0],
      command: setup[index][1],
      destination: b4a.from(destination),
      nonce: b4a.alloc(16, index + 1),
      recordSequence: BigInt(index + 1),
      source: b4a.from(source),
      transactionId: 0x2000 + index,
      ...overrides
    })
  const key = b4a.alloc(32, 0x5a)
  const stream = createAuditEventStream({ context, key, maximumRecords: 8 })
  const verifier = createAuditEventVerifier({ context, key, maximumRecords: 8 })
  for (let index = 0; index < setup.length; index++) {
    const value = setupRecord(index)
    t.is(verifier.verifyOpen(stream.open(value), value), true)
  }
  throwsCode(t, () =>
    stream.open(
      setupRecord(0, {
        nonce: b4a.alloc(16, 4),
        recordSequence: 4n,
        transactionId: 0x2004
      })
    )
  )

  for (const index of [1, 2]) {
    const outOfOrder = createAuditEventStream({ context, key, maximumRecords: 8 })
    throwsCode(t, () => outOfOrder.open(setupRecord(index)))
    outOfOrder.destroy()
  }

  const skip = createAuditEventStream({ context, key, maximumRecords: 8 })
  skip.open(setupRecord(0))
  throwsCode(t, () => skip.open(setupRecord(2)))
  skip.destroy()

  const repeat = createAuditEventStream({ context, key, maximumRecords: 8 })
  repeat.open(setupRecord(0))
  throwsCode(t, () =>
    repeat.open(
      setupRecord(0, {
        nonce: b4a.alloc(16, 2),
        recordSequence: 2n,
        transactionId: 0x2001
      })
    )
  )
  repeat.destroy()

  const producer = createAuditEventStream({ context, key, maximumRecords: 8 })
  const valid = setup.map((_, index) => {
    const value = setupRecord(index)
    return { event: producer.open(value), value }
  })
  const putFirstVerifier = createAuditEventVerifier({ context, key, maximumRecords: 8 })
  throwsCode(t, () => putFirstVerifier.verifyOpen(valid[1].event, valid[1].value))
  putFirstVerifier.destroy()
  const skipVerifier = createAuditEventVerifier({ context, key, maximumRecords: 8 })
  t.is(skipVerifier.verifyOpen(valid[0].event, valid[0].value), true)
  throwsCode(t, () => skipVerifier.verifyOpen(valid[2].event, valid[2].value))
  skipVerifier.destroy()
  producer.destroy()

  const repeatedProducer = createAuditEventStream({ context, key, maximumRecords: 8 })
  const repeatedValue = setupRecord(0, {
    nonce: b4a.alloc(16, 2),
    recordSequence: 2n,
    transactionId: 0x2001
  })
  const repeatedEvent = repeatedProducer.open(repeatedValue)
  const repeatedVerifier = createAuditEventVerifier({ context, key, maximumRecords: 8 })
  t.is(repeatedVerifier.verifyOpen(valid[0].event, valid[0].value), true)
  throwsCode(t, () => repeatedVerifier.verifyOpen(repeatedEvent, repeatedValue))
  repeatedVerifier.destroy()
  repeatedProducer.destroy()

  const completedProducer = createAuditEventStream({ context, key, maximumRecords: 8 })
  const completedValue = setupRecord(0, {
    nonce: b4a.alloc(16, 4),
    recordSequence: 4n,
    transactionId: 0x2004
  })
  const completedEvent = completedProducer.open(completedValue)
  throwsCode(t, () => verifier.verifyOpen(completedEvent, completedValue))
  completedProducer.destroy()

  stream.destroy()
  verifier.destroy()
})

test('audit close correlates captured replies only for SUCCESS outcomes', (t) => {
  for (const outcome of [AUDIT_OUTCOMES.TIMEOUT, AUDIT_OUTCOMES.CANCELLED, AUDIT_OUTCOMES.ERROR]) {
    const context = auditContext()
    const { stream } = streamFixture({ context })
    const verifier = createAuditEventVerifier({
      context,
      key: b4a.alloc(32, 0x5a),
      maximumRecords: 8
    })
    const request = record()
    const open = stream.open(request)
    t.is(verifier.verifyOpen(open, request), true)
    const close = stream.close({
      closingPhaseSequence: 12n,
      outcome,
      recordNonce: request.nonce,
      recordSequence: request.recordSequence,
      replyPayload: b4a.alloc(0)
    })
    t.alike(close.replyDigest, b4a.alloc(32))
    throwsCode(t, () => verifier.verifyClose(close, capturedReply(request)))
    t.is(verifier.verifyClose(close), true)
    stream.destroy()
    verifier.destroy()

    const fabricated = streamFixture({ context }).stream
    fabricated.open(request)
    throwsCode(t, () =>
      fabricated.close({
        closingPhaseSequence: 12n,
        outcome,
        recordNonce: request.nonce,
        recordSequence: request.recordSequence,
        replyPayload: b4a.from(AUDIT_VECTOR.replyPayload, 'hex')
      })
    )
    fabricated.destroy()
  }

  const context = auditContext()
  const { stream } = streamFixture({ context })
  const verifier = createAuditEventVerifier({
    context,
    key: b4a.alloc(32, 0x5a),
    maximumRecords: 8
  })
  const request = record()
  const open = stream.open(request)
  t.is(verifier.verifyOpen(open, request), true)
  const close = stream.close({
    closingPhaseSequence: 12n,
    outcome: AUDIT_OUTCOMES.SUCCESS,
    recordNonce: request.nonce,
    recordSequence: request.recordSequence,
    replyPayload: b4a.from(AUDIT_VECTOR.replyPayload, 'hex')
  })
  throwsCode(t, () => verifier.verifyClose(close))
  t.is(verifier.verifyClose(close, capturedReply(request)), true)
  stream.destroy()
  verifier.destroy()
})

test('audit stream emits only exact sanitized open and close fields with strict MAC vectors', (t) => {
  const { stream } = streamFixture()
  const open = stream.open(record())
  t.alike(Reflect.ownKeys(open), [
    'class',
    'eventMAC',
    'generation',
    'openingPhaseSequence',
    'recordDigest',
    'recordNonce',
    'recordSequence',
    'roleIndex',
    'transactionId'
  ])
  t.is(b4a.toString(open.recordDigest, 'hex'), AUDIT_VECTOR.recordDigest)
  t.is(b4a.toString(open.eventMAC, 'hex'), AUDIT_VECTOR.openMAC)
  t.ok(Object.isFrozen(open))

  const close = stream.close({
    closingPhaseSequence: 12n,
    outcome: AUDIT_OUTCOMES.SUCCESS,
    recordNonce: b4a.from(AUDIT_VECTOR.nonce, 'hex'),
    recordSequence: 1n,
    replyPayload: b4a.from(AUDIT_VECTOR.replyPayload, 'hex')
  })
  t.alike(Reflect.ownKeys(close), [
    'class',
    'closingPhaseSequence',
    'eventMAC',
    'generation',
    'openingPhaseSequence',
    'outcome',
    'recordDigest',
    'recordNonce',
    'recordSequence',
    'replyDigest',
    'roleIndex',
    'transactionId'
  ])
  t.is(b4a.toString(close.replyDigest, 'hex'), AUDIT_VECTOR.replyDigest)
  t.is(b4a.toString(close.eventMAC, 'hex'), AUDIT_VECTOR.closeMAC)
  t.ok(Object.isFrozen(close))
  stream.destroy()
})

test('audit stream enforces nonzero monotonic sequence fresh nonce and one close', (t) => {
  const { stream } = streamFixture()
  throwsCode(t, () => stream.open(record({ recordSequence: 0n })))
  stream.open(record())
  throwsCode(t, () => stream.open(record({ recordSequence: 1n })), 'PROCESS_AUDIT_REPLAY')
  throwsCode(
    t,
    () => stream.open(record({ recordSequence: 2n, transactionId: 0x1235 })),
    'PROCESS_AUDIT_REPLAY'
  )
  stream.open(record({ nonce: b4a.alloc(16, 9), recordSequence: 2n, transactionId: 0x1235 }))
  stream.close({
    closingPhaseSequence: 12n,
    outcome: AUDIT_OUTCOMES.TIMEOUT,
    recordNonce: b4a.from(AUDIT_VECTOR.nonce, 'hex'),
    recordSequence: 1n,
    replyPayload: b4a.alloc(0)
  })
  throwsCode(
    t,
    () =>
      stream.close({
        closingPhaseSequence: 12n,
        outcome: AUDIT_OUTCOMES.TIMEOUT,
        recordNonce: b4a.from(AUDIT_VECTOR.nonce, 'hex'),
        recordSequence: 1n,
        replyPayload: b4a.alloc(0)
      }),
    'PROCESS_AUDIT_REPLAY'
  )
  stream.destroy()
})

test('coordinator verifier rejects decreasing fresh record sequences', (t) => {
  const context = auditContext()
  const firstStream = streamFixture({ context }).stream
  const secondStream = streamFixture({ context }).stream
  const verifier = createAuditEventVerifier({
    context,
    key: b4a.alloc(32, 0x5a),
    maximumRecords: 8
  })
  const second = record({ nonce: b4a.alloc(16, 2), recordSequence: 2n })
  const first = record({ nonce: b4a.alloc(16, 1), recordSequence: 1n })
  t.is(verifier.verifyOpen(firstStream.open(second), second), true)
  throwsCode(t, () => verifier.verifyOpen(secondStream.open(first), first), 'PROCESS_AUDIT_REPLAY')
  firstStream.destroy()
  secondStream.destroy()
  verifier.destroy()
})

test('audit close requires matching nonce later phase valid outcome and correlated reply', (t) => {
  for (const changed of [
    { recordNonce: b4a.alloc(16, 7) },
    { closingPhaseSequence: 10n },
    { outcome: 0xff },
    { recordSequence: 2n }
  ]) {
    const { stream } = streamFixture()
    stream.open(record())
    throwsCode(t, () =>
      stream.close({
        closingPhaseSequence: 12n,
        outcome: AUDIT_OUTCOMES.SUCCESS,
        recordNonce: b4a.from(AUDIT_VECTOR.nonce, 'hex'),
        recordSequence: 1n,
        replyPayload: b4a.from(AUDIT_VECTOR.replyPayload, 'hex'),
        ...changed
      })
    )
    stream.destroy()
  }
})

test('coordinator verifier binds captured reply tuple TID payload and rejects replay', (t) => {
  const context = auditContext()
  const { stream } = streamFixture({ context })
  const verifier = createAuditEventVerifier({
    context,
    key: b4a.alloc(32, 0x5a),
    maximumRecords: 8
  })
  const request = record()
  const open = stream.open(request)
  t.is(verifier.verifyOpen(open, request), true)
  throwsCode(t, () => verifier.verifyOpen(open, request), 'PROCESS_AUDIT_REPLAY')

  const replyPayload = b4a.from(AUDIT_VECTOR.replyPayload, 'hex')
  const close = stream.close({
    closingPhaseSequence: 12n,
    outcome: AUDIT_OUTCOMES.SUCCESS,
    recordNonce: request.nonce,
    recordSequence: request.recordSequence,
    replyPayload
  })
  const captured = capturedReply(request)
  const forged = { ...close, replyDigest: b4a.alloc(32, 9) }
  throwsCode(t, () => verifier.verifyClose(forged, captured))
  for (const mutation of [
    { source: b4a.from(request.source) },
    { destination: b4a.from(request.destination) },
    { transactionId: request.transactionId + 1 },
    { payload: b4a.from('incomplete') }
  ]) {
    throwsCode(t, () => verifier.verifyClose(close, capturedReply(request, mutation)))
  }
  t.is(verifier.verifyClose(close, captured), true)
  throwsCode(t, () => verifier.verifyClose(close, captured), 'PROCESS_AUDIT_REPLAY')
  stream.destroy()
  verifier.destroy()
})

test('audit records reject noncanonical tuples shapes ranges and ambient fields', (t) => {
  const bad = [
    { class: 0 },
    { command: 0x1_0000 },
    { destination: b4a.alloc(18) },
    { generation: -1n },
    { nonce: b4a.alloc(15) },
    { openingPhaseSequence: 0n },
    { outboundPayload: 'packet' },
    { recordSequence: 0n },
    { source: b4a.alloc(19) },
    { transactionId: 0x1_0000 }
  ]
  for (const mutation of bad) throwsCode(t, () => digestAuditRecord(record(mutation)))
  throwsCode(t, () =>
    digestAuditRecord({ ...record(), tuple: { host: '127.64.9.1', port: 42009 } })
  )

  const accessor = record()
  let reads = 0
  Object.defineProperty(accessor, 'source', {
    enumerable: true,
    get() {
      reads++
      return b4a.from(AUDIT_VECTOR.source, 'hex')
    }
  })
  throwsCode(t, () => digestAuditRecord(accessor))
  t.is(reads, 0)
  throwsCode(t, () => digestAuditRecord(new Proxy(record(), {})))
})

test('destroy clears every owned audit key and open record and closes APIs', (t) => {
  const original = b4a.allocUnsafeSlow
  const allocations = []
  b4a.allocUnsafeSlow = (size) => {
    const value = original(size)
    if (size === 32) allocations.push(value)
    return value
  }
  let stream = null
  let verifier = null
  try {
    const context = auditContext()
    stream = createAuditEventStream({
      context,
      key: b4a.alloc(32, 0x5a),
      maximumRecords: 8
    })
    verifier = createAuditEventVerifier({
      context,
      key: b4a.alloc(32, 0x5a),
      maximumRecords: 8
    })
    stream.open(record())
  } finally {
    b4a.allocUnsafeSlow = original
  }
  const ownedKeys = allocations.filter((value) => value.every((byte) => byte === 0x5a))
  t.is(ownedKeys.length, 2)
  stream.destroy()
  stream.destroy()
  verifier.destroy()
  verifier.destroy()
  for (const key of ownedKeys) t.alike(key, b4a.alloc(32))
  throwsCode(t, () => stream.open(record()), 'PROCESS_AUDIT_CLOSED')
  throwsCode(t, () => verifier.verifyOpen({}, record()), 'PROCESS_AUDIT_CLOSED')
})
