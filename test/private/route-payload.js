'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { CellCodec, CELL_SIZE } = require('../../lib/private/cell-codec')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  DatagramReplayWindow,
  OrderedReceiver,
  SenderCounter
} = require('../../lib/private/counters')
const { PrivateRouteError } = require('../../lib/private/errors')
const { CELL_CLASS, DIRECTION } = require('../../lib/private/protocol')
const {
  MAX_ROUTE_PAYLOAD,
  ROUTE_CIPHERTEXT_SIZE,
  ROUTE_COUNTER_SIZE,
  ROUTE_ENDPOINT,
  ROUTE_FRAME_SIZE,
  ROUTE_PAYLOAD_BINDING,
  ROUTE_PLAINTEXT_SIZE,
  RoutePayloadCodec,
  TEST_ONLY_RECEIVERS,
  TEST_ONLY_NONCE_REGISTRY,
  createTestNonceRegistry,
  destroyCreatedRoutePayloadContext,
  mintCreatedRoutePayloadContext
} = require('../../lib/private/route-payload')

// Adapted from the reviewed private-routes prototype at commit
// 0305df915b6a767093f9e75e6c06bc0a35da6169. The fragment integration
// case is intentionally deferred to Gate 3A Task 6.

const DESCRIPTOR_ID = b4a.alloc(32, 0x31)
const CIRCUIT_ID = b4a.alloc(16, 0x41)
let sequence = 0

function expectCode(t, operation, code) {
  let error = null
  try {
    operation()
  } catch (err) {
    error = err
  }
  t.ok(error instanceof PrivateRouteError)
  t.is(error && error.code, code)
}

function keys() {
  sequence++
  return cryptoSuite.deriveKeys(b4a.alloc(32, 0x46), b4a.from(`route-${sequence}`))
}

function rawContext(overrides = {}) {
  return {
    endpointRole: ROUTE_ENDPOINT.SOURCE,
    descriptorId: DESCRIPTOR_ID,
    circuitId: CIRCUIT_ID,
    ...keys(),
    ...overrides
  }
}

function rawContextForRegistry(registry, overrides = {}) {
  return rawContext({ [TEST_ONLY_NONCE_REGISTRY]: registry, ...overrides })
}

function route(overrides = {}) {
  const {
    context,
    endpointRole = ROUTE_ENDPOINT.SOURCE,
    descriptorId = DESCRIPTOR_ID,
    circuitId = CIRCUIT_ID,
    routeKeys = keys(),
    forwardKey = routeKeys.forwardKey,
    forwardNoncePrefix = routeKeys.forwardNoncePrefix,
    reverseKey = routeKeys.reverseKey,
    reverseNoncePrefix = routeKeys.reverseNoncePrefix,
    receivers,
    ...rest
  } = overrides
  const created =
    context === undefined
      ? mintCreatedRoutePayloadContext({
          endpointRole,
          descriptorId,
          circuitId,
          forwardKey,
          forwardNoncePrefix,
          reverseKey,
          reverseNoncePrefix
        })
      : context
  return new RoutePayloadCodec({
    crypto: cryptoSuite,
    context: created,
    window: 8,
    gapTimeout: 100,
    now: () => 0,
    padding: (size) => b4a.alloc(size),
    ...(receivers === undefined ? {} : { [TEST_ONLY_RECEIVERS]: receivers }),
    ...rest
  })
}

function pair(source = {}, destination = {}) {
  const routeKeys = keys()
  return {
    source: route({ routeKeys, endpointRole: ROUTE_ENDPOINT.SOURCE, ...source }),
    destination: route({ routeKeys, endpointRole: ROUTE_ENDPOINT.DESTINATION, ...destination }),
    keys: routeKeys
  }
}

function seal(codec, overrides = {}) {
  return codec.seal({
    direction: DIRECTION.FORWARD,
    class: CELL_CLASS.STREAM,
    payload: b4a.from('private payload'),
    ...overrides
  })
}

function open(codec, frame, overrides = {}) {
  return codec.open({ direction: DIRECTION.FORWARD, ...overrides }, frame)
}

function receivingRoute(routeKeys, overrides = {}) {
  const outbound = keys()
  return route({
    endpointRole: ROUTE_ENDPOINT.DESTINATION,
    forwardKey: routeKeys.forwardKey,
    forwardNoncePrefix: routeKeys.forwardNoncePrefix,
    reverseKey: outbound.reverseKey,
    reverseNoncePrefix: outbound.reverseNoncePrefix,
    ...overrides
  })
}

test('route frame dimensions and payload maximum lock the fixed format', (t) => {
  t.is(ROUTE_FRAME_SIZE, 1100)
  t.is(ROUTE_COUNTER_SIZE, 8)
  t.is(ROUTE_CIPHERTEXT_SIZE, 1092)
  t.is(ROUTE_PLAINTEXT_SIZE, 1076)
  t.is(MAX_ROUTE_PAYLOAD, 1073)
  t.is(ROUTE_COUNTER_SIZE + ROUTE_CIPHERTEXT_SIZE, ROUTE_FRAME_SIZE)
  t.is(ROUTE_PLAINTEXT_SIZE + 16, ROUTE_CIPHERTEXT_SIZE)
})

test('only a one-use authenticated-created context can construct a codec', (t) => {
  const raw = rawContext()
  const common = {
    crypto: cryptoSuite,
    window: 8,
    gapTimeout: 100,
    now: () => 0,
    padding: (size) => b4a.alloc(size)
  }
  expectCode(t, () => new RoutePayloadCodec({ ...common, ...raw }), 'INVALID_ROUTE')
  expectCode(t, () => new RoutePayloadCodec({ ...common, context: {} }), 'INVALID_ROUTE')
  const context = mintCreatedRoutePayloadContext(raw)
  t.alike(Reflect.ownKeys(context), [])
  t.is(Object.isFrozen(context), true)
  const codec = new RoutePayloadCodec({ ...common, context })
  t.is(codec.stats.destroyed, false)
  expectCode(t, () => new RoutePayloadCodec({ ...common, context }), 'INVALID_ROUTE')
})

test('unconsumed contexts release nonce claims and zero their owned copies', (t) => {
  const raw = rawContext()
  const allocations = []
  const original = b4a.allocUnsafeSlow
  b4a.allocUnsafeSlow = (size) => {
    const value = original(size)
    if (size === 16 || size === 32) allocations.push(value)
    return value
  }
  let context
  try {
    context = mintCreatedRoutePayloadContext(raw)
  } finally {
    b4a.allocUnsafeSlow = original
  }
  t.is(allocations.length, 6)
  destroyCreatedRoutePayloadContext(context)
  destroyCreatedRoutePayloadContext(context)
  for (const value of allocations) t.alike(value, b4a.alloc(value.byteLength))
  expectCode(t, () => route({ context }), 'INVALID_ROUTE')
})

test('nonce-domain claims are unique before use and remain spent after destroy', (t) => {
  const raw = rawContext()
  const pending = mintCreatedRoutePayloadContext(raw)
  expectCode(t, () => mintCreatedRoutePayloadContext(raw), 'INVALID_ROUTE')
  destroyCreatedRoutePayloadContext(pending)
  const active = route({ context: mintCreatedRoutePayloadContext(raw) })
  expectCode(t, () => mintCreatedRoutePayloadContext(raw), 'INVALID_ROUTE')
  active.destroy()
  expectCode(t, () => mintCreatedRoutePayloadContext(raw), 'INVALID_ROUTE')
})

test('isolated nonce registry has a stable fail-closed capacity contract', (t) => {
  const registry = createTestNonceRegistry({ capacity: 2 })
  const firstRaw = rawContextForRegistry(registry)
  const secondRaw = rawContextForRegistry(registry)
  const overflowRaw = rawContextForRegistry(registry)
  const first = mintCreatedRoutePayloadContext(firstRaw)
  const second = mintCreatedRoutePayloadContext(secondRaw)

  t.ok(first)
  t.ok(second, 'the last in-capacity claim is admitted')
  expectCode(t, () => mintCreatedRoutePayloadContext(firstRaw), 'INVALID_ROUTE')
  expectCode(t, () => mintCreatedRoutePayloadContext(overflowRaw), 'CIRCUIT_LIMIT')

  destroyCreatedRoutePayloadContext(second)
  const replacement = mintCreatedRoutePayloadContext(overflowRaw)
  t.ok(replacement, 'releasing a pending claim restores capacity')
  destroyCreatedRoutePayloadContext(replacement)
  destroyCreatedRoutePayloadContext(first)

  const spentRegistry = createTestNonceRegistry({ capacity: 1 })
  const spentRaw = rawContextForRegistry(spentRegistry)
  const active = route({ context: mintCreatedRoutePayloadContext(spentRaw) })
  active.destroy()
  expectCode(
    t,
    () => mintCreatedRoutePayloadContext(rawContextForRegistry(spentRegistry)),
    'CIRCUIT_LIMIT'
  )
})

test('test nonce registry configuration is own-data-only and deep-import-only', (t) => {
  const publicHyperDHT = require('../../index')
  t.is(typeof TEST_ONLY_NONCE_REGISTRY, 'symbol')
  t.is(typeof createTestNonceRegistry, 'function')
  t.is('TEST_ONLY_NONCE_REGISTRY' in publicHyperDHT, false)
  t.is('createTestNonceRegistry' in publicHyperDHT, false)
  for (const capacity of [0, -1, 1.5, 4097, 1n]) {
    expectCode(t, () => createTestNonceRegistry({ capacity }), 'INVALID_ROUTE')
  }
  let accesses = 0
  const accessor = {}
  Object.defineProperty(accessor, 'capacity', {
    get() {
      accesses++
      return 1
    }
  })
  expectCode(t, () => createTestNonceRegistry(accessor), 'INVALID_ROUTE')
  t.is(accesses, 0)
  expectCode(t, () => createTestNonceRegistry(Object.create({ capacity: 1 })), 'INVALID_ROUTE')
})

test('complementary roles own opposite direction domains', (t) => {
  const { source, destination } = pair()
  const forward = seal(source, { payload: b4a.from('forward') })
  const reverse = seal(destination, {
    direction: DIRECTION.REVERSE,
    payload: b4a.from('reverse')
  })
  t.alike(open(destination, forward)[0].payload, b4a.from('forward'))
  t.alike(open(source, reverse, { direction: DIRECTION.REVERSE })[0].payload, b4a.from('reverse'))
  expectCode(t, () => seal(source, { direction: DIRECTION.REVERSE }), 'INVALID_ROUTE')
  expectCode(t, () => seal(destination), 'INVALID_ROUTE')
  expectCode(t, () => open(source, forward), 'INVALID_ROUTE')
})

test('route frames remain opaque through a fixed relay cell', (t) => {
  const { source, destination } = pair()
  const plaintext = b4a.from('private payload')
  const frame = seal(source, { payload: plaintext })
  const cell = new CellCodec({
    crypto: cryptoSuite,
    cellSize: CELL_SIZE,
    padding: (n) => b4a.alloc(n)
  })
  const key = b4a.alloc(32, 0x91)
  const noncePrefix = b4a.alloc(16, 0x92)
  const packet = cell.seal({
    key,
    noncePrefix,
    senderCounter: new SenderCounter(),
    class: CELL_CLASS.STREAM,
    direction: DIRECTION.FORWARD,
    epoch: 1n,
    circuitId: CIRCUIT_ID,
    payload: frame
  })
  const relayed = cell.open(
    {
      key,
      noncePrefix,
      receiver: new OrderedReceiver({ window: 8, gapTimeout: 100, now: () => 0 }),
      expectedClass: CELL_CLASS.STREAM,
      expectedDirection: DIRECTION.FORWARD,
      expectedEpoch: 1n,
      expectedCircuitId: CIRCUIT_ID
    },
    packet
  )[0]
  t.alike(relayed, frame)
  t.is(relayed.indexOf(plaintext), -1)
  t.alike(open(destination, relayed)[0].payload, plaintext)
})

test('stream and datagram use disjoint ordered/replay counter namespaces', (t) => {
  const { source, destination } = pair()
  const stream0 = seal(source, { payload: b4a.from('s0') })
  const datagram0 = seal(source, { class: CELL_CLASS.DATAGRAM, payload: b4a.from('d0') })
  const stream1 = seal(source, { payload: b4a.from('s1') })
  const datagram1 = seal(source, { class: CELL_CLASS.DATAGRAM, payload: b4a.from('d1') })
  t.is(b4a.toString(stream0.subarray(0, 8), 'hex'), '0000000000000000')
  t.is(b4a.toString(datagram0.subarray(0, 8), 'hex'), '0000000000000001')
  t.is(b4a.toString(stream1.subarray(0, 8), 'hex'), '0000000000000002')
  t.is(b4a.toString(datagram1.subarray(0, 8), 'hex'), '0000000000000003')
  t.alike(open(destination, stream0)[0].payload, b4a.from('s0'))
  t.alike(open(destination, datagram1).payload, b4a.from('d1'))
  t.alike(open(destination, stream1)[0].payload, b4a.from('s1'))
  t.alike(open(destination, datagram0).payload, b4a.from('d0'))
  expectCode(t, () => open(destination, datagram0), 'REPLAY')
})

test('route payload padding fills only the authenticated hidden tail', (t) => {
  let plaintext = null
  let paddingCalls = 0
  const source = route({
    padding(size) {
      paddingCalls++
      return b4a.alloc(size, 0xa5)
    },
    crypto: {
      ...cryptoSuite,
      seal(options) {
        plaintext = b4a.from(options.plaintext)
        return cryptoSuite.seal(options)
      }
    }
  })
  const frame = seal(source, { payload: b4a.from('pad') })
  t.is(frame.byteLength, ROUTE_FRAME_SIZE)
  t.is(paddingCalls, 1)
  t.is(plaintext[0], CELL_CLASS.STREAM)
  t.is((plaintext[1] << 8) | plaintext[2], 3)
  t.alike(plaintext.subarray(3, 6), b4a.from('pad'))
  t.alike(plaintext.subarray(6), b4a.alloc(MAX_ROUTE_PAYLOAD - 3, 0xa5))
  plaintext.fill(0)
})

test('descriptor, circuit, direction, counter, class, and key substitutions fail pre-state', (t) => {
  const sourceKeys = keys()
  const source = route({ routeKeys: sourceKeys })
  const frame = seal(source)
  const cases = [
    { destination: receivingRoute(sourceKeys, { descriptorId: b4a.alloc(32, 0x32) }) },
    { destination: receivingRoute(sourceKeys, { circuitId: b4a.alloc(16, 0x42) }) },
    { destination: receivingRoute(sourceKeys, { forwardKey: b4a.alloc(32, 0x55) }) },
    { destination: receivingRoute(sourceKeys, { forwardNoncePrefix: b4a.alloc(16, 0x55) }) }
  ]
  for (const current of cases) {
    const before = current.destination.stats.forward.orderedNext
    expectCode(t, () => open(current.destination, frame), 'INVALID_ROUTE')
    t.is(current.destination.stats.forward.orderedNext, before)
  }
  const destination = receivingRoute(sourceKeys)
  for (const offset of [0, 7, ROUTE_COUNTER_SIZE, ROUTE_FRAME_SIZE - 1]) {
    const forged = b4a.from(frame)
    forged[offset] ^= 1
    const before = destination.stats.forward.orderedNext
    expectCode(t, () => open(destination, forged), 'INVALID_ROUTE')
    t.is(destination.stats.forward.orderedNext, before)
  }
  expectCode(t, () => open(destination, frame, { direction: DIRECTION.REVERSE }), 'INVALID_ROUTE')
  t.alike(open(destination, frame)[0].payload, b4a.from('private payload'))
})

test('authenticated class must match the public counter namespace bit', (t) => {
  let plaintext = null
  let calls = 0
  const destination = route({
    endpointRole: ROUTE_ENDPOINT.DESTINATION,
    crypto: {
      ...cryptoSuite,
      open() {
        plaintext = b4a.alloc(ROUTE_PLAINTEXT_SIZE)
        plaintext[0] = CELL_CLASS.DATAGRAM
        return plaintext
      }
    },
    receivers: {
      forwardOrdered: new OrderedReceiver({ window: 8, gapTimeout: 100, now: () => 0 }),
      forwardDatagram: { acceptAuthenticated: () => calls++ },
      reverseOrdered: new OrderedReceiver({ window: 8, gapTimeout: 100, now: () => 0 }),
      reverseDatagram: new DatagramReplayWindow({ window: 8 })
    }
  })
  expectCode(t, () => open(destination, b4a.alloc(ROUTE_FRAME_SIZE)), 'INVALID_ROUTE')
  t.is(calls, 0)
  t.alike(plaintext, b4a.alloc(ROUTE_PLAINTEXT_SIZE))
})

test('bounds reject before reservation and each class accepts uint63 max once', (t) => {
  const source = route()
  const before = source.stats
  for (const payload of [null, {}, b4a.alloc(MAX_ROUTE_PAYLOAD + 1)]) {
    expectCode(t, () => seal(source, { payload }), 'INVALID_ROUTE')
  }
  expectCode(t, () => seal(source, { class: CELL_CLASS.CONTROL }), 'INVALID_ROUTE')
  t.alike(source.stats, before)

  const maximum = (1n << 63n) - 1n
  const exhausted = pair({ senderInitial: maximum }, { receiverInitial: maximum })
  const stream = seal(exhausted.source)
  const datagram = seal(exhausted.source, { class: CELL_CLASS.DATAGRAM })
  t.is(b4a.toString(stream.subarray(0, 8), 'hex'), 'fffffffffffffffe')
  t.is(b4a.toString(datagram.subarray(0, 8), 'hex'), 'ffffffffffffffff')
  t.alike(open(exhausted.destination, stream)[0].payload, b4a.from('private payload'))
  t.alike(open(exhausted.destination, datagram).payload, b4a.from('private payload'))
  expectCode(t, () => seal(exhausted.source), 'COUNTER_EXHAUSTED')
  expectCode(t, () => seal(exhausted.source, { class: CELL_CLASS.DATAGRAM }), 'COUNTER_EXHAUSTED')
})

test('padding happens before reservation and unexpected crypto errors propagate after it', (t) => {
  const paddingFailure = route({
    padding: () => {
      throw new Error('padding')
    }
  })
  expectCode(t, () => seal(paddingFailure), 'INVALID_ROUTE')
  t.is(paddingFailure.stats.forward.senderNext, 0n)

  const sentinel = new Error('unexpected crypto programming error')
  const cryptoFailure = route({
    crypto: {
      ...cryptoSuite,
      seal: () => {
        throw sentinel
      }
    }
  })
  let error = null
  try {
    seal(cryptoFailure)
  } catch (err) {
    error = err
  }
  t.is(error, sentinel)
  t.is(cryptoFailure.stats.forward.senderNext, 1n)

  const sourceKeys = keys()
  const frame = seal(route({ routeKeys: sourceKeys }))
  const openSentinel = new Error('unexpected open programming error')
  const destination = receivingRoute(sourceKeys, {
    crypto: {
      ...cryptoSuite,
      open: () => {
        throw openSentinel
      }
    }
  })
  let openError = null
  try {
    open(destination, frame)
  } catch (err) {
    openError = err
  }
  t.is(openError, openSentinel)
  t.is(destination.stats.forward.orderedNext, 0n)
})

test('temporary plaintext and encoded deliveries are zeroed on success and failure', (t) => {
  const observed = []
  const pairValue = pair(
    {},
    {
      crypto: {
        ...cryptoSuite,
        open(options) {
          const value = cryptoSuite.open(options)
          observed.push(value)
          return value
        }
      }
    }
  )
  t.alike(
    open(pairValue.destination, seal(pairValue.source))[0].payload,
    b4a.from('private payload')
  )
  t.is(observed.length, 1)
  t.alike(observed[0], b4a.alloc(ROUTE_PLAINTEXT_SIZE))

  let malformed = null
  let calls = 0
  const destination = route({
    endpointRole: ROUTE_ENDPOINT.DESTINATION,
    crypto: {
      ...cryptoSuite,
      open() {
        malformed = b4a.alloc(ROUTE_PLAINTEXT_SIZE, 0xaa)
        malformed[0] = CELL_CLASS.CONTROL
        return malformed
      }
    },
    receivers: {
      forwardOrdered: {
        next: 0n,
        buffered: 0,
        needsRotation: false,
        pushAuthenticated: () => calls++
      },
      forwardDatagram: new DatagramReplayWindow({ window: 8 }),
      reverseOrdered: new OrderedReceiver({ window: 8, gapTimeout: 100, now: () => 0 }),
      reverseDatagram: new DatagramReplayWindow({ window: 8 })
    }
  })
  expectCode(t, () => open(destination, b4a.alloc(ROUTE_FRAME_SIZE)), 'INVALID_ROUTE')
  t.is(calls, 0)
  t.alike(malformed, b4a.alloc(ROUTE_PLAINTEXT_SIZE))
})

test('route open rejects caller-frame plaintext aliases without clearing caller bytes', (t) => {
  let calls = 0
  let frame = null
  const destination = route({
    endpointRole: ROUTE_ENDPOINT.DESTINATION,
    crypto: {
      ...cryptoSuite,
      open() {
        return frame.subarray(24)
      }
    },
    receivers: {
      forwardOrdered: {
        next: 0n,
        buffered: 0,
        needsRotation: false,
        pushAuthenticated: () => calls++
      },
      forwardDatagram: new DatagramReplayWindow({ window: 8 }),
      reverseOrdered: new OrderedReceiver({ window: 8, gapTimeout: 100, now: () => 0 }),
      reverseDatagram: new DatagramReplayWindow({ window: 8 })
    }
  })
  frame = b4a.alloc(ROUTE_FRAME_SIZE, 0x7a)
  frame.fill(0, 0, 8)
  frame[24] = CELL_CLASS.STREAM
  frame[25] = 0
  frame[26] = 0
  const snapshot = b4a.from(frame)

  expectCode(t, () => open(destination, frame), 'INVALID_ROUTE')
  t.alike(frame, snapshot)
  t.is(calls, 0)
  t.is(destination.stats.forward.orderedNext, 0n)
})

test('route open rejects plaintext overlapping long-lived owned context', (t) => {
  const raw = rawContext({ endpointRole: ROUTE_ENDPOINT.DESTINATION })
  const backing = b4a.allocUnsafeSlow(2048)
  const sizes = [32, 16, 32, 16, 32, 16]
  const original = b4a.allocUnsafeSlow
  let offset = 0
  let allocation = 0
  b4a.allocUnsafeSlow = (size) => {
    if (allocation < sizes.length) {
      t.is(size, sizes[allocation++])
      const value = backing.subarray(offset, offset + size)
      offset += size
      return value
    }
    return original(size)
  }
  let context
  try {
    context = mintCreatedRoutePayloadContext(raw)
  } finally {
    b4a.allocUnsafeSlow = original
  }
  t.is(allocation, sizes.length)
  const candidate = backing.subarray(0, ROUTE_PLAINTEXT_SIZE)
  candidate.fill(0)
  candidate[0] = CELL_CLASS.STREAM
  const snapshot = b4a.from(backing)
  const destination = route({
    context,
    crypto: { ...cryptoSuite, open: () => candidate }
  })

  expectCode(t, () => open(destination, b4a.alloc(ROUTE_FRAME_SIZE)), 'INVALID_ROUTE')
  t.alike(backing, snapshot)
  t.is(destination.stats.forward.orderedNext, 0n)
})

test('route crypto adapters receive disposable key and nonce snapshots', (t) => {
  let sealKey = null
  let sealPrefix = null
  let openKey = null
  let openPrefix = null
  const routeKeys = keys()
  const source = route({
    routeKeys,
    crypto: {
      ...cryptoSuite,
      seal(options) {
        sealKey = options.key
        sealPrefix = options.noncePrefix
        const ciphertext = cryptoSuite.seal(options)
        options.key.fill(0)
        options.noncePrefix.fill(0)
        return ciphertext
      }
    }
  })
  const destination = route({
    routeKeys,
    endpointRole: ROUTE_ENDPOINT.DESTINATION,
    crypto: {
      ...cryptoSuite,
      open(options) {
        openKey = options.key
        openPrefix = options.noncePrefix
        const plaintext = cryptoSuite.open(options)
        options.key.fill(0)
        options.noncePrefix.fill(0)
        return plaintext
      }
    }
  })
  const first = seal(source, { payload: b4a.from('first') })
  t.alike(open(destination, first)[0].payload, b4a.from('first'))
  const second = seal(source, { payload: b4a.from('second') })
  t.alike(open(destination, second)[0].payload, b4a.from('second'))
  for (const snapshot of [sealKey, sealPrefix, openKey, openPrefix]) {
    t.alike(snapshot, b4a.alloc(snapshot.byteLength))
  }
})

test('route key snapshot allocation is transactional before counter and receiver state', (t) => {
  const original = b4a.allocUnsafeSlow
  const source = route()
  let partial = null
  let firstSnapshot = null
  b4a.allocUnsafeSlow = (size) => {
    if (size === 32) {
      firstSnapshot = original(size)
      return firstSnapshot
    }
    if (size === 16) {
      partial = original(15)
      partial.fill(0xaa)
      return partial
    }
    return original(size)
  }
  try {
    expectCode(t, () => seal(source), 'INVALID_ROUTE')
  } finally {
    b4a.allocUnsafeSlow = original
  }
  t.is(source.stats.forward.senderNext, 0n)
  t.alike(firstSnapshot, b4a.alloc(32))
  t.alike(partial, b4a.alloc(15))

  const pairValue = pair()
  const frame = seal(pairValue.source)
  b4a.allocUnsafeSlow = (size) => {
    if (size === 16) return original(15)
    return original(size)
  }
  try {
    expectCode(t, () => open(pairValue.destination, frame), 'INVALID_ROUTE')
  } finally {
    b4a.allocUnsafeSlow = original
  }
  t.is(pairValue.destination.stats.forward.orderedNext, 0n)
})

test('reentrant destroy during route crypto snapshots prevents adapter entry', (t) => {
  const original = b4a.allocUnsafeSlow
  let sealCalls = 0
  let source = null
  source = route({
    crypto: {
      ...cryptoSuite,
      seal: (options) => {
        sealCalls++
        return cryptoSuite.seal(options)
      }
    }
  })
  let triggered = false
  let sealSnapshot = null
  b4a.allocUnsafeSlow = (size) => {
    const value = original(size)
    if (!triggered && size === 32) {
      sealSnapshot = value
      triggered = true
      source.destroy()
    }
    return value
  }
  try {
    expectCode(t, () => seal(source), 'CIRCUIT_STATE')
  } finally {
    b4a.allocUnsafeSlow = original
  }
  t.is(sealCalls, 0)
  t.is(source.stats.destroyed, true)
  t.alike(sealSnapshot, b4a.alloc(32))

  let openCalls = 0
  let destination = null
  const pairValue = pair(
    {},
    {
      crypto: {
        ...cryptoSuite,
        open: (options) => {
          openCalls++
          return cryptoSuite.open(options)
        }
      }
    }
  )
  destination = pairValue.destination
  const frame = seal(pairValue.source)
  triggered = false
  let openSnapshot = null
  b4a.allocUnsafeSlow = (size) => {
    const value = original(size)
    if (!triggered && size === 32) {
      openSnapshot = value
      triggered = true
      destination.destroy()
    }
    return value
  }
  try {
    expectCode(t, () => open(destination, frame), 'CIRCUIT_STATE')
  } finally {
    b4a.allocUnsafeSlow = original
  }
  t.is(openCalls, 0)
  t.is(destination.stats.destroyed, true)
  t.alike(openSnapshot, b4a.alloc(32))
})

test('receiver failures expose only counter codes', (t) => {
  const routeKeys = keys()
  const frame = seal(route({ routeKeys }))
  for (const [failure, code] of [
    [PrivateRouteError.REPLAY(), 'REPLAY'],
    [PrivateRouteError.COUNTER_INVALID(), 'COUNTER_INVALID'],
    [PrivateRouteError.COUNTER_GAP(), 'COUNTER_GAP'],
    [PrivateRouteError.COUNTER_EXHAUSTED(), 'COUNTER_EXHAUSTED'],
    [PrivateRouteError.UNAUTHORIZED(), 'INVALID_ROUTE'],
    [new TypeError('private receiver detail'), 'INVALID_ROUTE']
  ]) {
    const destination = receivingRoute(routeKeys, {
      receivers: {
        forwardOrdered: {
          pushAuthenticated: () => {
            throw failure
          }
        },
        forwardDatagram: new DatagramReplayWindow({ window: 8 }),
        reverseOrdered: new OrderedReceiver({ window: 8, gapTimeout: 100, now: () => 0 }),
        reverseDatagram: new DatagramReplayWindow({ window: 8 })
      }
    })
    expectCode(t, () => open(destination, frame), code)
  }
})

test('partial route allocations are zeroed and never returned', (t) => {
  const original = b4a.allocUnsafeSlow
  const source = route()
  let partialFrame = null
  b4a.allocUnsafeSlow = (size) => {
    if (size === ROUTE_FRAME_SIZE) {
      partialFrame = original(size - 1)
      partialFrame.fill(0xaa)
      return partialFrame
    }
    return original(size)
  }
  try {
    expectCode(t, () => seal(source), 'INVALID_ROUTE')
  } finally {
    b4a.allocUnsafeSlow = original
  }
  t.alike(partialFrame, b4a.alloc(ROUTE_FRAME_SIZE - 1))
  t.is(source.stats.forward.senderNext, 1n)

  const pairValue = pair()
  const datagram = seal(pairValue.source, {
    class: CELL_CLASS.DATAGRAM,
    payload: b4a.from('1234567')
  })
  let partialCopy = null
  b4a.allocUnsafeSlow = (size) => {
    if (size === 7) {
      partialCopy = original(size - 1)
      partialCopy.fill(0xbb)
      return partialCopy
    }
    return original(size)
  }
  try {
    expectCode(t, () => open(pairValue.destination, datagram), 'INVALID_ROUTE')
  } finally {
    b4a.allocUnsafeSlow = original
  }
  t.alike(partialCopy, b4a.alloc(6))
})

test('own-data snapshots reject inherited/accessor/revoked config without invoking getters', (t) => {
  let accesses = 0
  const inherited = Object.create(rawContext())
  expectCode(t, () => mintCreatedRoutePayloadContext(inherited), 'INVALID_ROUTE')
  const accessor = rawContext()
  Object.defineProperty(accessor, 'descriptorId', {
    get() {
      accesses++
      return DESCRIPTOR_ID
    }
  })
  expectCode(t, () => mintCreatedRoutePayloadContext(accessor), 'INVALID_ROUTE')
  t.is(accesses, 0)
  const nullPrototype = Object.assign(Object.create(null), rawContext())
  const context = mintCreatedRoutePayloadContext(nullPrototype)
  destroyCreatedRoutePayloadContext(context)

  const revoked = Proxy.revocable({}, {})
  revoked.revoke()
  expectCode(t, () => mintCreatedRoutePayloadContext(revoked.proxy), 'INVALID_ROUTE')
  expectCode(t, () => route().seal(revoked.proxy), 'INVALID_ROUTE')
  const trapped = new Proxy(rawContext(), {
    getOwnPropertyDescriptor() {
      throw new Error('descriptor trap')
    }
  })
  expectCode(t, () => mintCreatedRoutePayloadContext(trapped), 'INVALID_ROUTE')
  const hasTrap = new Proxy(
    {},
    {
      has() {
        throw new Error('has trap')
      }
    }
  )
  expectCode(t, () => mintCreatedRoutePayloadContext(hasTrap), 'INVALID_ROUTE')

  const revokedBuffer = Proxy.revocable(b4a.alloc(32), {})
  revokedBuffer.revoke()
  expectCode(
    t,
    () => mintCreatedRoutePayloadContext(rawContext({ descriptorId: revokedBuffer.proxy })),
    'INVALID_ROUTE'
  )
})

test('intrinsic route slicing ignores shadowed instance methods and byteLength', (t) => {
  let calls = 0
  const hostile = () => {
    calls++
    throw new Error('instance method called')
  }
  const payload = b4a.from('x')
  Object.defineProperties(payload, {
    byteLength: { value: MAX_ROUTE_PAYLOAD },
    subarray: { value: hostile },
    set: { value: hostile },
    fill: { value: hostile }
  })
  const { source, destination } = pair()
  const frame = seal(source, { payload })
  Object.defineProperty(frame, 'subarray', { value: hostile })
  t.alike(open(destination, frame)[0].payload, b4a.from('x'))
  t.is(calls, 0)
})

test('reentrant destroy from seal and open callbacks fails closed and clears state', (t) => {
  let source = null
  source = route({
    padding(size) {
      source.destroy()
      return b4a.alloc(size)
    }
  })
  expectCode(t, () => seal(source), 'CIRCUIT_STATE')
  t.is(source.stats.destroyed, true)
  t.is(source.stats.forward.senderNext, 0n)

  let destination = null
  const pairValue = pair(
    {},
    {
      crypto: {
        ...cryptoSuite,
        open(options) {
          const result = cryptoSuite.open(options)
          destination.destroy()
          return result
        }
      }
    }
  )
  destination = pairValue.destination
  expectCode(t, () => open(destination, seal(pairValue.source)), 'CIRCUIT_STATE')
  t.is(destination.stats.destroyed, true)
  t.is(destination.stats.forward.orderedBuffered, 0)
})

test('destroy clears bindings, keys, counters, and replay state', (t) => {
  const codec = route()
  const binding = codec[ROUTE_PAYLOAD_BINDING]()
  seal(codec)
  seal(codec, { class: CELL_CLASS.DATAGRAM })
  codec.destroy()
  codec.destroy()
  t.is(codec.stats.destroyed, true)
  t.is(codec.stats.forward.senderNext, 0n)
  t.is(codec.stats.forward.senderClosed, true)
  t.is(codec.stats.forward.datagramSenderNext, 0n)
  t.is(codec.stats.forward.datagramSenderClosed, true)
  expectCode(t, () => seal(codec), 'CIRCUIT_STATE')
  expectCode(t, () => codec[ROUTE_PAYLOAD_BINDING](), 'CIRCUIT_STATE')
  binding.descriptorId.fill(0)
  binding.circuitId.fill(0)
})

test('binding copy is transactional on allocation failure', (t) => {
  const original = b4a.allocUnsafeSlow
  const codec = route()
  const owned = []
  b4a.allocUnsafeSlow = (size) => {
    if (size === 32) {
      const value = original(size)
      owned.push(value)
      return value
    }
    if (size === 16) {
      const value = original(15)
      value.fill(0xaa)
      owned.push(value)
      return value
    }
    return original(size)
  }
  try {
    expectCode(t, () => codec[ROUTE_PAYLOAD_BINDING](), 'INVALID_ROUTE')
  } finally {
    b4a.allocUnsafeSlow = original
  }
  t.is(codec.stats.destroyed, false)
  t.is(owned.length, 2)
  for (const value of owned) t.alike(value, b4a.alloc(value.byteLength))
})

test('binding copy fails closed on reentrant destroy during either allocation', (t) => {
  for (const triggerSize of [32, 16]) {
    const original = b4a.allocUnsafeSlow
    const codec = route()
    const owned = []
    let triggered = false
    b4a.allocUnsafeSlow = (size) => {
      const value = original(size)
      if (size === 32 || size === 16) owned.push(value)
      if (!triggered && size === triggerSize) {
        triggered = true
        codec.destroy()
      }
      return value
    }
    try {
      expectCode(t, () => codec[ROUTE_PAYLOAD_BINDING](), 'CIRCUIT_STATE')
    } finally {
      b4a.allocUnsafeSlow = original
    }
    t.is(codec.stats.destroyed, true)
    t.ok(owned.length >= 1)
    for (const value of owned) t.alike(value, b4a.alloc(value.byteLength))
  }
})

test('100 generated route frames preserve bytes and reject bit substitution', (t) => {
  let state = 0x9e3779b9
  function random() {
    state ^= state << 13
    state ^= state >>> 17
    state ^= state << 5
    return state >>> 0
  }
  const { source, destination } = pair()
  for (let index = 0; index < 100; index++) {
    const length = index % 17 === 0 ? MAX_ROUTE_PAYLOAD : random() % (MAX_ROUTE_PAYLOAD + 1)
    const payload = b4a.alloc(length)
    for (let offset = 0; offset < length; offset++) payload[offset] = random()
    const cellClass = index % 2 === 0 ? CELL_CLASS.STREAM : CELL_CLASS.DATAGRAM
    const frame = seal(source, { class: cellClass, payload })
    const forged = b4a.from(frame)
    forged[random() % ROUTE_FRAME_SIZE] ^= 1 << (random() % 8)
    const before = destination.stats.forward
    expectCode(t, () => open(destination, forged), 'INVALID_ROUTE')
    t.alike(destination.stats.forward, before)
    const opened = open(destination, frame)
    t.alike(cellClass === CELL_CLASS.STREAM ? opened[0].payload : opened.payload, payload)
  }
})
