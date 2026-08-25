'use strict'

const test = require('brittle')
const b4a = require('b4a')

const {
  COMMANDS,
  EVENTS,
  MAX_BODY_BYTES,
  MAX_BUFFERED_BYTES,
  TEST_ONLY_CONTROL_AUTHORITY_ISSUER,
  TEST_ONLY_CONTROL_BUFFER_OBSERVER,
  ControlFrameDecoder,
  decodeCanonicalBody,
  decodeControlFrame,
  encodeCanonicalBody,
  encodeControlFrame,
  validateControlMessage
} = require('./process/control-channel')
const {
  CANONICAL_BODY_HEX,
  CANONICAL_FRAME_HEX,
  canonicalValue
} = require('./process/codec-vectors')
const {
  PROCESS_PLANS,
  TEST_ONLY_PROCESS_TOPOLOGY_ISSUER,
  createLiveProcessTopology
} = require('./process/topology-fixture')

const ROLES = Object.freeze([
  'endpoint',
  'guard',
  'lookup-middle-a',
  'lookup-exit-a',
  'lookup-middle-b',
  'lookup-exit-b',
  'announce-middle',
  'announce-exit',
  'dht-seed',
  'dht-referral',
  'dht-value'
])

function throwsCode(t, fn, code = 'PROCESS_PROTOCOL_INVALID') {
  let error = null
  try {
    fn()
  } catch (err) {
    error = err
  }
  t.ok(error)
  t.is(error && error.code, code)
}

function base(type, role = 'endpoint', roleIndex = 1) {
  return { generation: 7n, phaseSequence: 11n, role, roleIndex, type }
}

function context(direction, role = 'endpoint', roleIndex = 1, overrides = {}) {
  return {
    direction,
    generation: 7n,
    phaseSequence: 11n,
    projection: 'production',
    role,
    roleIndex,
    ...overrides
  }
}

function validCommand(type) {
  switch (type) {
    case 'configure':
      return {
        ...base(type),
        codecVectorDigest: b4a.alloc(32, 1),
        projection: b4a.from('role-projection-v1'),
        run: b4a.alloc(16, 2),
        runtime: 'node',
        runtimeVersion: '22.19.0'
      }
    case 'isolated-grant':
      return {
        ...base(type, 'lookup-exit-a', 4),
        grant: b4a.alloc(137, 2),
        requestSequence: 3n,
        tupleDigest: b4a.alloc(32, 4)
      }
    case 'store-immutable':
      return { ...base(type, 'dht-referral', 10), value: b4a.from('immutable') }
    case 'immutable-get':
      return { ...base(type), target: b4a.alloc(32, 5) }
    case 'cancel':
      return { ...base(type), operationSequence: 2n }
    case 'rotate':
      return { ...base(type, 'lookup-middle-a', 3), nextGeneration: 8n }
    case 'blackhole':
      return base(type, 'lookup-middle-a', 3)
    case 'guard-loss':
      return base(type, 'guard', 2)
    case 'phase-ack':
      return { ...base(type), acknowledgedPhaseSequence: 11n }
    default:
      return base(type)
  }
}

function validEvent(type) {
  switch (type) {
    case 'isolated-grant-request':
      return {
        ...base(type, 'lookup-exit-a', 4),
        requestSequence: 3n,
        run: b4a.alloc(16, 6),
        tupleDigest: b4a.alloc(32, 4)
      }
    case 'stored':
      return {
        ...base(type, 'dht-referral', 10),
        setupAuditDigests: [b4a.alloc(32, 1), b4a.alloc(32, 2), b4a.alloc(32, 3)],
        setupAuditSequences: [1n, 2n, 3n],
        valueDigest: b4a.alloc(32, 4)
      }
    case 'phase':
      return { ...base(type), state: 'READY' }
    case 'phase-pending':
      return { ...base(type), pendingPhaseSequence: 12n }
    case 'audit-open':
      return {
        ...base(type, 'lookup-exit-a', 4),
        class: 2,
        eventMAC: b4a.alloc(32, 1),
        openingPhaseSequence: 11n,
        recordDigest: b4a.alloc(32, 2),
        recordNonce: b4a.alloc(16, 3),
        recordSequence: 1n,
        transactionId: 0x1234
      }
    case 'audit-close':
      return {
        ...validEvent('audit-open'),
        closingPhaseSequence: 12n,
        eventMAC: b4a.alloc(32, 4),
        outcome: 0,
        replyDigest: b4a.alloc(32, 5),
        type
      }
    case 'ready':
      // base() builds an endpoint event, and the endpoint owns no DHT node, so
      // zero is the honest count here as well as the only one the codec accepts
      // from a non-DHT role.
      return { ...base(type), answeredRequestCount: 0, state: 'READY' }
    case 'value':
      return { ...base(type), target: b4a.alloc(32, 6), value: b4a.from('value') }
    case 'cancelled':
      return { ...base(type), operationSequence: 2n }
    case 'rotated':
      return { ...base(type), previousGeneration: 6n }
    case 'unavailable':
      return { ...base(type), reason: 'NETWORK_CHANGE' }
    case 'snapshot':
      return {
        ...base(type),
        activeOperations: 0,
        activeExitOperations: 0,
        announceGeneration: 1n,
        controllerGeneration: 1n,
        endpointSockets: 1,
        guardOnly: true,
        lookupGeneration: 1n,
        openLinks: 0,
        ordinaryRequestCount: 0,
        pendingGrantRequests: 0,
        pendingLinks: 0,
        pendingPackets: 0,
        referralProbeCount: 0,
        tableEntryCount: 0,
        openResources: 1,
        queuedBytes: 0,
        state: 'READY',
        summaryDigest: b4a.alloc(32, 7)
      }
    case 'error':
      return { ...base(type), code: 'ERR_PRIVATE_ROUTE_UNAVAILABLE' }
    default:
      return base(type)
  }
}

function messageContext(direction, message, overrides = {}) {
  return context(direction, message.role, message.roleIndex, {
    generation: message.generation,
    phaseSequence: message.phaseSequence,
    ...overrides
  })
}

function phaseTopology(plan = PROCESS_PLANS.LINUX_NAMESPACE, seed = 31) {
  return createLiveProcessTopology({
    clocks: TEST_ONLY_PROCESS_TOPOLOGY_ISSUER.clocks({
      monotonicNow: () => 10_000n,
      wallNow: () => 1_000_000n
    }),
    entropy: TEST_ONLY_PROCESS_TOPOLOGY_ISSUER.entropy(b4a.alloc(32, seed)),
    plan
  })
}

test('canonical process codec freezes exact body and frame vectors', (t) => {
  const value = canonicalValue()
  const body = encodeCanonicalBody(value)
  const frame = encodeControlFrame(value)
  t.is(b4a.toString(body, 'hex'), CANONICAL_BODY_HEX)
  t.is(b4a.toString(frame, 'hex'), CANONICAL_FRAME_HEX)
  t.alike(decodeCanonicalBody(body), value)
  t.alike(decodeControlFrame(frame), value)
  t.is(frame.readUInt32BE(0), body.byteLength)
})

test('codec supports only canonical owned scalar/container values', (t) => {
  const value = {
    array: [null, false, true, -9, 9, 0xffff_ffff_ffff_ffffn, 'π'],
    bytes: b4a.from([0, 1, 2])
  }
  const frame = encodeControlFrame(value)
  const decoded = decodeControlFrame(frame)
  t.alike(decoded, value)
  t.ok(decoded.bytes !== value.bytes)
  frame.fill(0)
  t.alike(decoded.bytes, b4a.from([0, 1, 2]))

  for (const invalid of [
    undefined,
    1.5,
    Number.MAX_SAFE_INTEGER + 1,
    -1n,
    0x1_0000_0000_0000_0000n
  ]) {
    throwsCode(t, () => encodeCanonicalBody(invalid))
  }
  for (const invalid of [new Date(), new Map(), new Set(), /x/, Symbol('x'), () => {}]) {
    throwsCode(t, () => encodeCanonicalBody(invalid))
  }
})

test('codec rejects hostile containers without invoking accessors or proxy traps', (t) => {
  let reads = 0
  const accessor = { a: 1 }
  Object.defineProperty(accessor, 'b', {
    enumerable: true,
    get() {
      reads++
      return 2
    }
  })
  throwsCode(t, () => encodeCanonicalBody(accessor))
  t.is(reads, 0)

  const inherited = Object.create({ a: 1 })
  inherited.b = 2
  throwsCode(t, () => encodeCanonicalBody(inherited))
  throwsCode(t, () => encodeCanonicalBody(new Proxy({ a: 1 }, {})))

  const cyclic = {}
  cyclic.self = cyclic
  throwsCode(t, () => encodeCanonicalBody(cyclic))
  const sparse = []
  sparse[1] = true
  throwsCode(t, () => encodeCanonicalBody(sparse))
})

test('encoder bounds nested container work before materializing chunks', (t) => {
  const leaf = []
  const branch = Array(4096).fill(leaf)
  const hostile = Array(4096).fill(branch)
  const original = b4a.allocUnsafeSlow
  const tripwire = new Error('allocation tripwire')
  let allocations = 0
  b4a.allocUnsafeSlow = (size) => {
    allocations++
    if (allocations >= 8) throw tripwire
    return original(size)
  }
  let error = null
  try {
    encodeCanonicalBody(hostile)
  } catch (err) {
    error = err
  } finally {
    b4a.allocUnsafeSlow = original
  }
  t.ok(error)
  t.is(error && error.code, 'PROCESS_PROTOCOL_INVALID')
  t.ok(allocations < 8)
})

test('decoder rejects duplicate forbidden unordered and malformed canonical bodies', (t) => {
  const duplicate = b4a.from('06000000020001610100016102', 'hex')
  const forbidden = b4a.concat([b4a.from('060000000100095f5f70726f746f5f5f', 'hex'), b4a.from([0])])
  const unordered = b4a.from('06000000020001620200016101', 'hex')
  const invalidUtf8 = b4a.from('0400000002c080', 'hex')
  const overlongBigInt = b4a.from('07023031', 'hex')
  for (const body of [duplicate, forbidden, unordered, invalidUtf8, overlongBigInt]) {
    throwsCode(t, () => decodeCanonicalBody(body))
  }
  throwsCode(t, () => decodeCanonicalBody(b4a.concat([encodeCanonicalBody(null), b4a.from([0])])))
})

test('decoder enforces the encoder canonical node and container-work budget', (t) => {
  const sharedLeaf = [null]
  const rejectedByEncoder = Array(4096).fill(sharedLeaf)
  throwsCode(t, () => encodeCanonicalBody(rejectedByEncoder))

  const body = b4a.allocUnsafe(5 + 6 * 4096)
  body[0] = 5
  body.writeUInt32BE(4096, 1)
  for (let index = 0, offset = 5; index < 4096; index++, offset += 6) {
    body[offset] = 5
    body.writeUInt32BE(1, offset + 1)
    body[offset + 5] = 0
  }
  throwsCode(t, () => decodeCanonicalBody(body))

  const deep = b4a.allocUnsafe(5 * 65 + 1)
  for (let offset = 0; offset < deep.byteLength - 1; offset += 5) {
    deep[offset] = 5
    deep.writeUInt32BE(1, offset + 1)
  }
  deep[deep.byteLength - 1] = 0
  throwsCode(t, () => decodeCanonicalBody(deep))
})

test('decoder clears copied byte values when a later canonical node fails', (t) => {
  const malformed = b4a.from('050000000308000000046c65616b08000000046d6f7265ff', 'hex')
  const successful = encodeCanonicalBody([b4a.from('kept')])
  const original = b4a.allocUnsafeSlow
  const allocations = []
  b4a.allocUnsafeSlow = (size) => {
    const value = original(size)
    allocations.push(value)
    return value
  }
  try {
    throwsCode(t, () => decodeCanonicalBody(malformed))
    t.is(allocations.length, 2)
    for (const allocation of allocations) t.alike(allocation, b4a.alloc(4))

    allocations.length = 0
    const decoded = decodeCanonicalBody(successful)
    t.is(allocations.length, 1)
    t.ok(decoded[0] === allocations[0])
    successful.fill(0)
    t.alike(decoded, [b4a.from('kept')])
  } finally {
    b4a.allocUnsafeSlow = original
  }
})
test('stream decoder copies a byte-at-time maximum frame with linear owned work', (t) => {
  const payload = b4a.alloc(MAX_BODY_BYTES - 5, 0x5a)
  const frame = encodeControlFrame(payload)
  const values = []
  const observed = []
  let ownedBytes = 0
  const tripwire = new Error('nonlinear decoder buffering')
  const decoder = new ControlFrameDecoder((value) => values.push(value), {
    [TEST_ONLY_CONTROL_BUFFER_OBSERVER](buffer) {
      observed.push(buffer)
      ownedBytes += buffer.byteLength
      if (observed.length > 4 || ownedBytes > frame.byteLength + 4) throw tripwire
    }
  })
  let error = null
  try {
    for (let index = 0; index < frame.byteLength; index++) {
      decoder.push(frame.subarray(index, index + 1))
    }
  } catch (err) {
    error = err
  }
  t.is(error, null)
  t.is(observed.length, 2)
  t.is(ownedBytes, frame.byteLength)
  t.alike(values, [payload])
  for (const buffer of observed) t.alike(buffer, b4a.alloc(buffer.byteLength))
  decoder.destroy()
})

test('stream decoder handles multiple frames and a partial next prefix in one chunk', (t) => {
  const values = []
  const observed = []
  const first = encodeControlFrame(null)
  const second = encodeControlFrame({ a: 7 })
  const third = encodeControlFrame(b4a.from('next'))
  const decoder = new ControlFrameDecoder((value) => values.push(value), {
    [TEST_ONLY_CONTROL_BUFFER_OBSERVER](buffer) {
      observed.push(buffer)
    }
  })
  t.is(decoder.push(b4a.concat([first, second, third.subarray(0, 3)])), true)
  t.alike(values, [null, { a: 7 }])
  t.is(decoder.push(third.subarray(3)), true)
  t.alike(values, [null, { a: 7 }, b4a.from('next')])
  t.is(observed.length, 4)
  for (const buffer of observed) t.alike(buffer, b4a.alloc(buffer.byteLength))
  decoder.destroy()

  const prefixObserved = []
  const partial = new ControlFrameDecoder(() => {}, {
    [TEST_ONLY_CONTROL_BUFFER_OBSERVER](buffer) {
      prefixObserved.push(buffer)
    }
  })
  partial.push(first.subarray(0, 3))
  partial.destroy()
  t.is(prefixObserved.length, 1)
  t.alike(prefixObserved[0], b4a.alloc(4))
})

test('stream decoder clears its exact body after canonical budget rejection', (t) => {
  const body = b4a.allocUnsafe(5 + 6 * 4096)
  body[0] = 5
  body.writeUInt32BE(4096, 1)
  for (let index = 0, offset = 5; index < 4096; index++, offset += 6) {
    body[offset] = 5
    body.writeUInt32BE(1, offset + 1)
    body[offset + 5] = 0
  }
  const frame = b4a.allocUnsafe(4 + body.byteLength)
  frame.writeUInt32BE(body.byteLength, 0)
  frame.set(body, 4)
  const observed = []
  const decoder = new ControlFrameDecoder(() => {}, {
    [TEST_ONLY_CONTROL_BUFFER_OBSERVER](buffer) {
      observed.push(buffer)
    }
  })
  throwsCode(t, () => decoder.push(frame))
  t.is(decoder.destroyed, true)
  t.is(observed.length, 2)
  for (const buffer of observed) t.alike(buffer, b4a.alloc(buffer.byteLength))
})

test('stream decoder enforces the exact aggregate undecoded-byte ceiling before push', (t) => {
  const exactPayload = b4a.alloc(MAX_BODY_BYTES - 9, 0x31)
  const exactFrame = encodeControlFrame(exactPayload)
  const exactChunk = b4a.concat([exactFrame, exactFrame])
  t.is(exactChunk.byteLength, MAX_BUFFERED_BYTES)
  const values = []
  const exact = new ControlFrameDecoder((value) => values.push(value))
  t.is(exact.push(exactChunk), true)
  t.is(values.length, 2)
  t.is(values[0].byteLength, exactPayload.byteLength)
  t.is(values[1].byteLength, exactPayload.byteLength)
  exact.destroy()

  const maximumFrame = encodeControlFrame(b4a.alloc(MAX_BODY_BYTES - 5, 0x32))
  const oversizedChunk = b4a.concat([maximumFrame, maximumFrame])
  t.ok(oversizedChunk.byteLength > MAX_BUFFERED_BYTES)
  let dispatches = 0
  const oversizedObserved = []
  const oversized = new ControlFrameDecoder(() => dispatches++, {
    [TEST_ONLY_CONTROL_BUFFER_OBSERVER](buffer) {
      oversizedObserved.push(buffer)
    }
  })
  throwsCode(t, () => oversized.push(oversizedChunk))
  t.is(dispatches, 0)
  t.is(oversized.destroyed, true)
  for (const buffer of oversizedObserved) t.alike(buffer, b4a.alloc(buffer.byteLength))

  const partialObserved = []
  const partial = new ControlFrameDecoder(() => dispatches++, {
    [TEST_ONLY_CONTROL_BUFFER_OBSERVER](buffer) {
      partialObserved.push(buffer)
    }
  })
  partial.push(maximumFrame.subarray(0, 104))
  throwsCode(t, () => partial.push(b4a.alloc(MAX_BUFFERED_BYTES - 100 + 1)))
  t.is(dispatches, 0)
  t.is(partial.destroyed, true)
  for (const buffer of partialObserved) t.alike(buffer, b4a.alloc(buffer.byteLength))
})

test('frame limits reject oversized body trailing data and partial-prefix overflow', (t) => {
  t.is(MAX_BODY_BYTES, 65_536)
  t.is(MAX_BUFFERED_BYTES, 131_072)
  throwsCode(t, () => encodeControlFrame(b4a.alloc(MAX_BODY_BYTES)))
  const frame = encodeControlFrame(null)
  throwsCode(t, () => decodeControlFrame(b4a.concat([frame, b4a.from([0])])))

  const oversized = b4a.alloc(4)
  oversized.writeUInt32BE(MAX_BODY_BYTES + 1, 0)
  const decoder = new ControlFrameDecoder(() => {})
  throwsCode(t, () => decoder.push(oversized))
  t.is(decoder.destroyed, true)
})

test('stream decoder clears complete and partial owned backing buffers', (t) => {
  const observed = []
  const values = []
  const frame = encodeControlFrame({ a: b4a.from('owned') })
  const decoder = new ControlFrameDecoder((value) => values.push(value), {
    [TEST_ONLY_CONTROL_BUFFER_OBSERVER](buffer) {
      observed.push(buffer)
    }
  })
  decoder.push(frame.subarray(0, 5))
  t.is(values.length, 0)
  decoder.push(frame.subarray(5))
  t.alike(values, [{ a: b4a.from('owned') }])
  t.ok(observed.length >= 2)
  for (const buffer of observed) t.alike(buffer, b4a.alloc(buffer.byteLength))

  const partial = new ControlFrameDecoder(() => {}, {
    [TEST_ONLY_CONTROL_BUFFER_OBSERVER](buffer) {
      observed.push(buffer)
    }
  })
  partial.push(frame.subarray(0, 7))
  const owned = observed[observed.length - 1]
  partial.destroy()
  partial.destroy()
  t.alike(owned, b4a.alloc(owned.byteLength))
  throwsCode(t, () => partial.push(frame), 'PROCESS_PROTOCOL_CLOSED')
})

test('physical lifecycle commands are bound only to their failing link owners', (t) => {
  const middleRotate = {
    ...base('rotate', 'lookup-middle-a', 3),
    nextGeneration: 8n
  }
  t.alike(
    validateControlMessage(middleRotate, messageContext('command', middleRotate)),
    middleRotate
  )
  const middleRotateB = {
    ...base('rotate', 'lookup-middle-b', 5),
    nextGeneration: 8n
  }
  t.alike(
    validateControlMessage(middleRotateB, messageContext('command', middleRotateB)),
    middleRotateB
  )
  const wrongRole = {
    ...base('rotate', 'lookup-exit-a', 4),
    nextGeneration: 8n
  }
  throwsCode(t, () => validateControlMessage(wrongRole, messageContext('command', wrongRole)))
  const endpointRotate = { ...base('rotate'), nextGeneration: 8n }
  throwsCode(t, () =>
    validateControlMessage(endpointRotate, messageContext('command', endpointRotate))
  )
  const middleBlackhole = base('blackhole', 'lookup-middle-a', 3)
  t.alike(
    validateControlMessage(middleBlackhole, messageContext('command', middleBlackhole)),
    middleBlackhole
  )
  const wrongBlackhole = base('blackhole', 'lookup-middle-b', 5)
  throwsCode(t, () =>
    validateControlMessage(wrongBlackhole, messageContext('command', wrongBlackhole))
  )

  const guardLoss = base('guard-loss', 'guard', 2)
  t.alike(validateControlMessage(guardLoss, messageContext('command', guardLoss)), guardLoss)
  const wrongGuard = base('guard-loss', 'lookup-middle-a', 3)
  throwsCode(t, () => validateControlMessage(wrongGuard, messageContext('command', wrongGuard)))
  const endpointGuard = base('guard-loss')
  throwsCode(t, () =>
    validateControlMessage(endpointGuard, messageContext('command', endpointGuard))
  )
})

test('exact command and event registries are frozen and all schemas reject extras', (t) => {
  t.alike(COMMANDS, [
    'configure',
    'prepare',
    'isolated-grant',
    'store-immutable',
    'activate',
    'immutable-get',
    'cancel',
    'rotate',
    'blackhole',
    'suspend',
    'resume',
    'network-change',
    'guard-loss',
    'phase-ack',
    'snapshot',
    'stop'
  ])
  t.alike(EVENTS, [
    'configured',
    'prepared',
    'isolated-grant-request',
    'stored',
    'phase',
    'phase-pending',
    'audit-open',
    'audit-close',
    'ready',
    'value',
    'cancelled',
    'rotated',
    'suspended',
    'resumed',
    'unavailable',
    'snapshot',
    'closed',
    'error'
  ])
  t.ok(Object.isFrozen(COMMANDS))
  t.ok(Object.isFrozen(EVENTS))

  for (const type of COMMANDS) {
    if (type === 'phase-ack') continue
    const message = validCommand(type)
    const overrides = {}
    if (type === 'isolated-grant') {
      overrides.coordinator = true
      overrides.projection = 'portable-loopback'
      overrides.pendingGrant = TEST_ONLY_CONTROL_AUTHORITY_ISSUER.pendingGrant({
        generation: message.generation,
        requestSequence: message.requestSequence,
        role: message.role,
        tupleDigest: message.tupleDigest
      })
    }
    t.alike(validateControlMessage(message, messageContext('command', message, overrides)), message)
    throwsCode(t, () =>
      validateControlMessage(
        { ...message, tuple: { host: '127.0.0.1', port: 1 } },
        messageContext('command', message, overrides)
      )
    )
  }

  for (const type of EVENTS) {
    if (type === 'phase-pending') continue
    const message = validEvent(type)
    t.alike(validateControlMessage(message, messageContext('event', message)), message)
    throwsCode(t, () =>
      validateControlMessage(
        { ...message, log: 'hidden route dump' },
        messageContext('event', message)
      )
    )
  }
})

test('stored audit arrays require three own ordered data entries without traps', (t) => {
  const stored = validEvent('stored')
  const sparseDigests = [b4a.alloc(32, 1), , b4a.alloc(32, 3)]
  throwsCode(t, () =>
    validateControlMessage(
      { ...stored, setupAuditDigests: sparseDigests },
      messageContext('event', stored)
    )
  )
  let reads = 0
  const accessorSequences = [1n, 2n, 3n]
  Object.defineProperty(accessorSequences, '1', {
    enumerable: true,
    get() {
      reads++
      return 2n
    }
  })
  throwsCode(t, () =>
    validateControlMessage(
      { ...stored, setupAuditSequences: accessorSequences },
      messageContext('event', stored)
    )
  )
  t.is(reads, 0)
  throwsCode(t, () =>
    validateControlMessage(
      { ...stored, setupAuditDigests: new Proxy(stored.setupAuditDigests, {}) },
      messageContext('event', stored)
    )
  )
})

test('control validation binds exact role index generation phase and special authority', (t) => {
  for (let index = 0; index < ROLES.length; index++) {
    const message = base('prepare', ROLES[index], index + 1)
    t.alike(validateControlMessage(message, messageContext('command', message)), message)
    throwsCode(t, () =>
      validateControlMessage(
        { ...message, roleIndex: ((index + 1) % ROLES.length) + 1 },
        messageContext('command', message)
      )
    )
  }

  const request = validEvent('isolated-grant-request')
  t.alike(validateControlMessage(request, messageContext('event', request)), request)
  throwsCode(t, () =>
    validateControlMessage(
      { ...request, role: 'guard', roleIndex: 2 },
      messageContext('event', request)
    )
  )
  throwsCode(t, () =>
    validateControlMessage({ ...request, run: b4a.alloc(15) }, messageContext('event', request))
  )

  const grant = validCommand('isolated-grant')
  const makeGrantContext = (projection = 'portable-loopback') =>
    messageContext('command', grant, {
      coordinator: true,
      pendingGrant: TEST_ONLY_CONTROL_AUTHORITY_ISSUER.pendingGrant({
        generation: grant.generation,
        requestSequence: grant.requestSequence,
        role: grant.role,
        tupleDigest: grant.tupleDigest
      }),
      projection
    })
  const grantContext = makeGrantContext()
  t.alike(validateControlMessage(grant, grantContext), grant)
  throwsCode(t, () => validateControlMessage(grant, grantContext), 'PROCESS_PROTOCOL_REPLAY')
  throwsCode(t, () => validateControlMessage(grant, makeGrantContext('production')))
  throwsCode(t, () =>
    validateControlMessage({ ...grant, grant: b4a.alloc(136) }, makeGrantContext())
  )

  t.is(TEST_ONLY_CONTROL_AUTHORITY_ISSUER.phaseGate, undefined)
  const portable = phaseTopology(PROCESS_PLANS.PORTABLE_LOOPBACK, 32)
  t.is(portable.projections[0].phaseGate, undefined)
  portable.stop()

  const linux = phaseTopology(PROCESS_PLANS.LINUX_NAMESPACE, 33)
  const ack = { ...validCommand('phase-ack'), generation: 1n }
  const phaseGate = linux.projections[0].phaseGate
  t.ok(phaseGate)
  for (let index = 1; index < linux.projections.length; index++)
    t.is(linux.projections[index].phaseGate, undefined)
  const ackContext = (overrides = {}) =>
    messageContext('command', ack, {
      phaseGate,
      projection: 'linux-namespace',
      run: linux.oracle.run,
      ...overrides
    })
  throwsCode(t, () => validateControlMessage(ack, messageContext('command', ack)))
  throwsCode(t, () => validateControlMessage(ack, ackContext({ projection: 'production' })))
  throwsCode(t, () => validateControlMessage(ack, ackContext({ projection: 'portable-loopback' })))
  throwsCode(t, () => validateControlMessage(ack, ackContext({ run: b4a.alloc(16, 0xff) })))
  const wrongGeneration = { ...ack, generation: 2n }
  throwsCode(t, () =>
    validateControlMessage(
      wrongGeneration,
      messageContext('command', wrongGeneration, {
        phaseGate,
        projection: 'linux-namespace',
        run: linux.oracle.run
      })
    )
  )
  const wrongRole = { ...ack, role: 'guard', roleIndex: 2 }
  throwsCode(t, () =>
    validateControlMessage(
      wrongRole,
      messageContext('command', wrongRole, {
        phaseGate,
        projection: 'linux-namespace',
        run: linux.oracle.run
      })
    )
  )
  t.alike(validateControlMessage(ack, ackContext()), ack)
  throwsCode(t, () => validateControlMessage(ack, ackContext()), 'PROCESS_PROTOCOL_REPLAY')
  linux.stop()

  const pendingTopology = phaseTopology(PROCESS_PLANS.LINUX_NAMESPACE, 34)
  const pending = { ...validEvent('phase-pending'), generation: 1n }
  const pendingContext = messageContext('event', pending, {
    phaseGate: pendingTopology.projections[0].phaseGate,
    projection: 'linux-namespace',
    run: pendingTopology.oracle.run
  })
  throwsCode(t, () => validateControlMessage({ ...pending, log: 'extra' }, pendingContext))
  t.alike(validateControlMessage(pending, pendingContext), pending)
  pendingTopology.stop()
})

test('snapshot state exposes only sanitized post-setup DHT value state', (t) => {
  const value = {
    ...validEvent('snapshot'),
    role: 'dht-value',
    roleIndex: 11,
    storedValueCount: 1,
    storedValueDigest: b4a.alloc(32, 8)
  }
  t.alike(validateControlMessage(value, messageContext('event', value)), value)
  const exit = {
    ...validEvent('snapshot'),
    activeExitOperations: 1,
    announceGeneration: null,
    controllerGeneration: null,
    endpointSockets: 0,
    guardOnly: false,
    lookupGeneration: null,
    openLinks: 1,
    ordinaryRequestCount: 2,
    pendingGrantRequests: 0,
    pendingLinks: 0,
    pendingPackets: 1,
    referralProbeCount: 1,
    role: 'lookup-exit-a',
    roleIndex: 4,
    tableEntryCount: 2
  }
  t.alike(validateControlMessage(exit, messageContext('event', exit)), exit)

  const referral = {
    ...validEvent('snapshot'),
    role: 'dht-referral',
    roleIndex: 10,
    storedValueCount: 0,
    transientValueBytes: 0
  }
  t.alike(validateControlMessage(referral, messageContext('event', referral)), referral)
  throwsCode(t, () =>
    validateControlMessage(
      { ...referral, transientValueBytes: 1 },
      messageContext('event', referral)
    )
  )
  throwsCode(t, () =>
    validateControlMessage({ ...referral, storedValueCount: 1 }, messageContext('event', referral))
  )

  const seed = {
    ...validEvent('snapshot'),
    role: 'dht-seed',
    roleIndex: 9,
    storedValueCount: 0
  }
  t.alike(validateControlMessage(seed, messageContext('event', seed)), seed)
  throwsCode(t, () =>
    validateControlMessage({ ...seed, storedValueCount: 1 }, messageContext('event', seed))
  )
  throwsCode(t, () =>
    validateControlMessage(
      { ...value, value: b4a.from('raw immutable') },
      messageContext('event', value)
    )
  )
})

test('ready answered-request count is bounded and denied to roles that own no DHT', (t) => {
  // The count exists so a DHT role cannot report readiness on a network where
  // nothing answered it. A role that owns no DHT node has nothing that could
  // have been answered, so any count but zero from one is a shape fault.
  const endpoint = validEvent('ready')
  t.alike(validateControlMessage(endpoint, messageContext('event', endpoint)), endpoint)
  throwsCode(t, () =>
    validateControlMessage(
      { ...endpoint, answeredRequestCount: 1 },
      messageContext('event', endpoint)
    )
  )

  const referral = {
    ...validEvent('ready'),
    answeredRequestCount: 2,
    role: 'dht-referral',
    roleIndex: 10,
    state: 'DHT_SETUP'
  }
  t.alike(validateControlMessage(referral, messageContext('event', referral)), referral)
  // Zero is the value a deaf DHT reports. The codec must carry it rather than
  // reject it, because rejecting it here would turn a failing assertion in the
  // eleven-role suite into a protocol error and hide what it is measuring.
  const deaf = { ...referral, answeredRequestCount: 0 }
  t.alike(validateControlMessage(deaf, messageContext('event', deaf)), deaf)
  for (const bad of [-1, 1.5, 4097, Number.NaN, '2', null]) {
    throwsCode(t, () =>
      validateControlMessage(
        { ...referral, answeredRequestCount: bad },
        messageContext('event', referral)
      )
    )
  }
})

test('events cannot smuggle ambient network or secret authority', (t) => {
  const forbidden = [
    'advertisement',
    'hostname',
    'log',
    'path',
    'rawTable',
    'routeKey',
    'secret',
    'tuple'
  ]
  for (const name of forbidden) {
    const message = validEvent('ready')
    message[name] = name === 'tuple' ? { host: '127.0.0.1', port: 1 } : 'forbidden'
    throwsCode(t, () => validateControlMessage(message, messageContext('event', message)))
  }
})
