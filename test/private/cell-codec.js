'use strict'

const test = require('brittle')
const b4a = require('b4a')

const {
  AEAD_TAG_BYTES,
  CELL_BODY_SIZE,
  CELL_HEADER_SIZE,
  CELL_SIZE,
  CellCodec,
  MAX_CELL_PAYLOAD,
  TEST_ONLY_CELL_ALLOCATOR
} = require('../../lib/private/cell-codec')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  DatagramReplayWindow,
  OrderedReceiver,
  SenderCounter
} = require('../../lib/private/counters')
const { PrivateRouteError } = require('../../lib/private/errors')
const { CELL_CLASS, DIRECTION, DOMAIN } = require('../../lib/private/protocol')

// Adapted from the reviewed private-routes prototype at commit
// 0305df915b6a767093f9e75e6c06bc0a35da6169.

const KEY = b4a.from('3976601ef753f92f19e4d544d6a80526635bd8af0dd09efd18e224493d44fb04', 'hex')
const NONCE_PREFIX = b4a.from('a4300237c95a17d6b7b5c1eb5d0bf837', 'hex')
const CIRCUIT_ID = b4a.alloc(16, 0x11)

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

function zeroPadding(size) {
  return b4a.alloc(size)
}

function codec(overrides = {}) {
  return new CellCodec({
    crypto: cryptoSuite,
    cellSize: CELL_SIZE,
    padding: zeroPadding,
    ...overrides
  })
}

function sealOptions(overrides = {}) {
  return {
    key: KEY,
    noncePrefix: NONCE_PREFIX,
    senderCounter: new SenderCounter({ initial: 3n }),
    class: CELL_CLASS.STREAM,
    direction: DIRECTION.FORWARD,
    epoch: 8n,
    circuitId: CIRCUIT_ID,
    payload: b4a.from('hello'),
    ...overrides
  }
}

function orderedSpy() {
  return {
    calls: [],
    pushAuthenticated(counter, payload) {
      this.calls.push({ counter, payload })
      return payload
    }
  }
}

function openOptions(receiver, overrides = {}) {
  return {
    key: KEY,
    noncePrefix: NONCE_PREFIX,
    receiver,
    expectedClass: CELL_CLASS.STREAM,
    expectedDirection: DIRECTION.FORWARD,
    expectedEpoch: 8n,
    expectedCircuitId: CIRCUIT_ID,
    ...overrides
  }
}

function tracker() {
  const owned = new Map()
  const released = []
  let current = 0
  let highWater = 0
  return {
    allocator: {
      allocate(size) {
        const value = b4a.allocUnsafeSlow(size)
        owned.set(value, size)
        current += size
        highWater = Math.max(highWater, current)
        return value
      },
      release(value) {
        released.push(b4a.from(value))
        current -= owned.get(value)
        owned.delete(value)
      }
    },
    released,
    get current() {
      return current
    },
    get highWater() {
      return highWater
    }
  }
}

test('cell layout and normative vector lock the fixed format', (t) => {
  t.is(CELL_SIZE, 1200)
  t.is(CELL_HEADER_SIZE, 36)
  t.is(CELL_BODY_SIZE, 1148)
  t.is(MAX_CELL_PAYLOAD, 1146)
  t.is(AEAD_TAG_BYTES, 16)
  t.is(CELL_HEADER_SIZE + CELL_BODY_SIZE + AEAD_TAG_BYTES, CELL_SIZE)
  const packet = codec().seal(sealOptions())
  t.is(
    b4a.toString(packet.subarray(0, CELL_HEADER_SIZE), 'hex'),
    '000100000000000000000008111111111111111111111111111111110000000000000003'
  )
  t.is(
    b4a.toString(cryptoSuite.hash(packet), 'hex'),
    '85cef0e1ccb809ab4a305568aa6a7ee9cd570289353be0a6f554de4287857e27'
  )
})

test('cell round trips empty, ordinary, and maximum payloads', (t) => {
  for (const payload of [b4a.alloc(0), b4a.from('hello'), b4a.alloc(MAX_CELL_PAYLOAD, 0x5a)]) {
    const sender = new SenderCounter()
    const packet = codec().seal(sealOptions({ senderCounter: sender, payload }))
    const receiver = orderedSpy()
    t.alike(codec().open(openOptions(receiver), packet), payload)
    t.is(packet.byteLength, CELL_SIZE)
    t.is(sender.value, 1n)
    t.is(receiver.calls.length, 1)
  }
})

test('default padding is random while payload length remains hidden', (t) => {
  const random = new CellCodec({ crypto: cryptoSuite, cellSize: CELL_SIZE })
  const first = random.seal(sealOptions({ senderCounter: new SenderCounter() }))
  const second = random.seal(sealOptions({ senderCounter: new SenderCounter() }))
  t.unlike(first, second)
  t.is(first.indexOf(b4a.from('hello')), -1)
  t.is(second.indexOf(b4a.from('hello')), -1)
})

test('scratch ownership is bounded and every temporary is zeroed', (t) => {
  const observed = tracker()
  const cell = codec({ [TEST_ONLY_CELL_ALLOCATOR]: observed.allocator })
  const packet = cell.seal(sealOptions())
  t.alike(cell.open(openOptions(orderedSpy()), packet), b4a.from('hello'))
  t.is(observed.current, 0)
  t.ok(observed.highWater < 4096)
  t.is(observed.released.length, 4)
  for (const released of observed.released) t.alike(released, b4a.alloc(released.byteLength))
})

test('header, key, nonce, circuit, class, direction, epoch, and ciphertext substitution fail pre-state', (t) => {
  const packet = codec().seal(sealOptions())
  const cases = [
    { mutate: (value) => (value[0] ^= 1) },
    {
      mutate: (value) => (value[1] = CELL_CLASS.DATAGRAM),
      open: { expectedClass: CELL_CLASS.DATAGRAM }
    },
    {
      mutate: (value) => (value[2] = DIRECTION.REVERSE),
      open: { expectedDirection: DIRECTION.REVERSE }
    },
    { mutate: (value) => (value[3] = 1) },
    { mutate: (value) => (value[11] ^= 1), open: { expectedEpoch: 9n } },
    {
      mutate: (value) => (value[12] ^= 1),
      open: { expectedCircuitId: b4a.alloc(16, 0x11) }
    },
    { mutate: (value) => (value[35] ^= 1) },
    { mutate: (value) => (value[CELL_HEADER_SIZE] ^= 1) },
    { mutate: (value) => (value[CELL_SIZE - 1] ^= 1) },
    { open: { key: b4a.alloc(32, 0x44) } },
    { open: { noncePrefix: b4a.alloc(16, 0x44) } }
  ]
  for (const current of cases) {
    const forged = b4a.from(packet)
    if (current.mutate) current.mutate(forged)
    const receiver = orderedSpy()
    expectCode(t, () => codec().open(openOptions(receiver, current.open), forged), 'CELL_INVALID')
    t.is(receiver.calls.length, 0)
  }
})

test('authentication happens before receiver lookup and replay state advance', (t) => {
  const packet = codec().seal(
    sealOptions({ senderCounter: new SenderCounter(), class: CELL_CLASS.DATAGRAM })
  )
  const forged = b4a.from(packet)
  forged[CELL_HEADER_SIZE + 9] ^= 1
  let getterCalls = 0
  const receiver = {}
  Object.defineProperty(receiver, 'acceptAuthenticated', {
    get() {
      getterCalls++
      return () => true
    }
  })
  expectCode(
    t,
    () => codec().open(openOptions(receiver, { expectedClass: CELL_CLASS.DATAGRAM }), forged),
    'CELL_INVALID'
  )
  t.is(getterCalls, 0)

  const replay = new DatagramReplayWindow({ window: 8 })
  const options = openOptions(replay, { expectedClass: CELL_CLASS.DATAGRAM })
  expectCode(t, () => codec().open(options, forged), 'CELL_INVALID')
  t.is(replay.highest, null)
  t.alike(codec().open(options, packet), b4a.from('hello'))
  t.is(replay.highest, 0n)
})

test('ordered and datagram counter namespaces preserve receiver behavior', (t) => {
  const cell = codec()
  const later = cell.seal(
    sealOptions({ senderCounter: new SenderCounter({ initial: 1n }), payload: b4a.from('b') })
  )
  const first = cell.seal(
    sealOptions({ senderCounter: new SenderCounter(), payload: b4a.from('a') })
  )
  const ordered = new OrderedReceiver({ window: 4, gapTimeout: 50, now: () => 0 })
  t.alike(cell.open(openOptions(ordered), later), [])
  t.alike(cell.open(openOptions(ordered), first), [b4a.from('a'), b4a.from('b')])

  const datagram = new DatagramReplayWindow({ window: 8 })
  const packet = cell.seal(
    sealOptions({ senderCounter: new SenderCounter(), class: CELL_CLASS.DATAGRAM })
  )
  const options = openOptions(datagram, { expectedClass: CELL_CLASS.DATAGRAM })
  t.alike(cell.open(options, packet), b4a.from('hello'))
  expectCode(t, () => cell.open(options, packet), 'REPLAY')
})

test('bounds reject before reservation while post-reservation crypto failure burns once', (t) => {
  for (const payload of [null, {}, b4a.alloc(MAX_CELL_PAYLOAD + 1)]) {
    const sender = new SenderCounter()
    expectCode(
      t,
      () => codec().seal(sealOptions({ senderCounter: sender, payload })),
      'CELL_INVALID'
    )
    t.is(sender.value, 0n)
  }
  const sender = new SenderCounter()
  const sentinel = new Error('unexpected seal failure')
  const broken = codec({
    crypto: {
      ...cryptoSuite,
      seal: () => {
        throw sentinel
      }
    }
  })
  let error = null
  try {
    broken.seal(sealOptions({ senderCounter: sender }))
  } catch (err) {
    error = err
  }
  t.is(error, sentinel)
  t.is(sender.value, 1n)

  const valid = codec().seal(sealOptions())
  const openSentinel = new Error('unexpected open failure')
  let openError = null
  try {
    codec({
      crypto: {
        ...cryptoSuite,
        open: () => {
          throw openSentinel
        }
      }
    }).open(openOptions(orderedSpy()), valid)
  } catch (err) {
    openError = err
  }
  t.is(openError, openSentinel)
})

test('option snapshots reject inherited, accessor, revoked, and trap-backed config', (t) => {
  let accesses = 0
  const inherited = Object.create(sealOptions())
  expectCode(t, () => codec().seal(inherited), 'CELL_INVALID')
  const accessor = { ...sealOptions() }
  Object.defineProperty(accessor, 'payload', {
    get() {
      accesses++
      return b4a.from('bad')
    }
  })
  expectCode(t, () => codec().seal(accessor), 'CELL_INVALID')
  t.is(accesses, 0)

  const nullPrototype = Object.assign(Object.create(null), sealOptions())
  t.is(codec().seal(nullPrototype).byteLength, CELL_SIZE)

  const revoked = Proxy.revocable({}, {})
  revoked.revoke()
  expectCode(t, () => codec().seal(revoked.proxy), 'CELL_INVALID')
  const trapped = new Proxy(sealOptions(), {
    getOwnPropertyDescriptor() {
      throw new Error('descriptor trap')
    }
  })
  expectCode(t, () => codec().seal(trapped), 'CELL_INVALID')
  const hasTrap = new Proxy(
    {},
    {
      has() {
        throw new Error('has trap')
      }
    }
  )
  expectCode(t, () => codec().seal(hasTrap), 'CELL_INVALID')

  const revokedBuffer = Proxy.revocable(b4a.alloc(1), {})
  revokedBuffer.revoke()
  expectCode(t, () => codec().seal(sealOptions({ payload: revokedBuffer.proxy })), 'CELL_INVALID')
})

test('intrinsic buffer operations ignore shadowed instance methods and byteLength', (t) => {
  let calls = 0
  const hostile = () => {
    calls++
    throw new Error('instance method called')
  }
  const payload = b4a.from('x')
  Object.defineProperties(payload, {
    byteLength: { value: MAX_CELL_PAYLOAD },
    subarray: { value: hostile },
    set: { value: hostile },
    fill: { value: hostile }
  })
  const packet = codec().seal(sealOptions({ payload }))
  Object.defineProperty(packet, 'subarray', { value: hostile })
  t.alike(codec().open(openOptions(orderedSpy()), packet), b4a.from('x'))
  t.is(calls, 0)
})

test('malformed authenticated body is cleared and rejected before receiver', (t) => {
  let plaintext = null
  let calls = 0
  const cell = codec({
    crypto: {
      ...cryptoSuite,
      open() {
        plaintext = b4a.alloc(CELL_BODY_SIZE, 0xa5)
        plaintext[0] = 0xff
        plaintext[1] = 0xff
        return plaintext
      }
    }
  })
  const packet = codec().seal(sealOptions())
  expectCode(
    t,
    () => cell.open(openOptions({ pushAuthenticated: () => calls++ }), packet),
    'CELL_INVALID'
  )
  t.is(calls, 0)
  t.alike(plaintext, b4a.alloc(CELL_BODY_SIZE))
})

test('receiver failures expose only counter codes and clear rejected payloads', (t) => {
  const packet = codec().seal(sealOptions())
  for (const [failure, code] of [
    [PrivateRouteError.REPLAY(), 'REPLAY'],
    [PrivateRouteError.COUNTER_INVALID(), 'COUNTER_INVALID'],
    [PrivateRouteError.COUNTER_GAP(), 'COUNTER_GAP'],
    [PrivateRouteError.COUNTER_EXHAUSTED(), 'COUNTER_EXHAUSTED'],
    [PrivateRouteError.UNAUTHORIZED(), 'CELL_INVALID'],
    [new TypeError('private receiver detail'), 'CELL_INVALID']
  ]) {
    let payload = null
    const receiver = {
      pushAuthenticated(counter, value) {
        t.is(counter, 3n)
        payload = value
        throw failure
      }
    }
    expectCode(t, () => codec().open(openOptions(receiver), packet), code)
    t.alike(payload, b4a.alloc(5))
  }
})

test('partial packet allocation is cleared after the counter reservation', (t) => {
  const original = b4a.allocUnsafeSlow
  const sender = new SenderCounter()
  let partial = null
  b4a.allocUnsafeSlow = (size) => {
    if (size === CELL_SIZE) {
      partial = original(size - 1)
      partial.fill(0xaa)
      return partial
    }
    return original(size)
  }
  try {
    expectCode(t, () => codec().seal(sealOptions({ senderCounter: sender })), 'CELL_INVALID')
  } finally {
    b4a.allocUnsafeSlow = original
  }
  t.is(sender.value, 1n)
  t.alike(partial, b4a.alloc(CELL_SIZE - 1))
})

test('scratch release failure clears a completed packet and precedes receiver lookup', (t) => {
  const original = b4a.allocUnsafeSlow
  let packet = null
  b4a.allocUnsafeSlow = (size) => {
    const value = original(size)
    if (size === CELL_SIZE) packet = value
    return value
  }
  const failing = {
    allocate: (size) => original(size),
    release() {
      throw new Error('release failed')
    }
  }
  try {
    expectCode(
      t,
      () => codec({ [TEST_ONLY_CELL_ALLOCATOR]: failing }).seal(sealOptions()),
      'CELL_INVALID'
    )
  } finally {
    b4a.allocUnsafeSlow = original
  }
  t.alike(packet, b4a.alloc(CELL_SIZE))

  const valid = codec().seal(sealOptions())
  let receiverCalls = 0
  expectCode(
    t,
    () =>
      codec({ [TEST_ONLY_CELL_ALLOCATOR]: failing }).open(
        openOptions({ pushAuthenticated: () => receiverCalls++ }),
        valid
      ),
    'CELL_INVALID'
  )
  t.is(receiverCalls, 0)
})

test('200 seeded cell cases round trip and reject one-bit substitution', (t) => {
  let state = 0x12345678
  function random() {
    state ^= state << 13
    state ^= state >>> 17
    state ^= state << 5
    return state >>> 0
  }
  for (let index = 0; index < 200; index++) {
    const length = index % 31 === 0 ? MAX_CELL_PAYLOAD : random() % (MAX_CELL_PAYLOAD + 1)
    const payload = b4a.alloc(length)
    for (let offset = 0; offset < length; offset++) payload[offset] = random()
    const packet = codec().seal(
      sealOptions({ senderCounter: new SenderCounter(), class: CELL_CLASS.DATAGRAM, payload })
    )
    const receiver = new DatagramReplayWindow({ window: 8 })
    const options = openOptions(receiver, { expectedClass: CELL_CLASS.DATAGRAM })
    t.alike(codec().open(options, packet), payload)
    const forged = b4a.from(packet)
    forged[random() % CELL_SIZE] ^= 1 << (random() % 8)
    expectCode(
      t,
      () =>
        codec().open(
          openOptions(new DatagramReplayWindow({ window: 8 }), {
            expectedClass: CELL_CLASS.DATAGRAM
          }),
          forged
        ),
      'CELL_INVALID'
    )
  }
})
