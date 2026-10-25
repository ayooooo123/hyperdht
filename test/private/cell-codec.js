'use strict'

const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-universal')

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

test('cell open rejects caller-packet plaintext aliases without clearing caller bytes', (t) => {
  let packet = null
  let calls = 0
  const cell = codec({
    crypto: {
      ...cryptoSuite,
      open() {
        return packet.subarray(CELL_HEADER_SIZE, CELL_HEADER_SIZE + CELL_BODY_SIZE)
      }
    }
  })
  packet = codec().seal(sealOptions())
  packet.fill(0, CELL_HEADER_SIZE, CELL_HEADER_SIZE + CELL_BODY_SIZE)
  const snapshot = b4a.from(packet)

  expectCode(
    t,
    () => cell.open(openOptions({ pushAuthenticated: () => calls++ }), packet),
    'CELL_INVALID'
  )
  t.alike(packet, snapshot)
  t.is(calls, 0)
})

test('cell open rejects plaintext overlapping caller key storage', (t) => {
  const backing = b4a.allocUnsafeSlow(2048)
  const key = backing.subarray(0, 32)
  const noncePrefix = backing.subarray(1500, 1516)
  key.fill(0x51)
  noncePrefix.fill(0x52)
  const candidate = backing.subarray(0, CELL_BODY_SIZE)
  candidate.fill(0)
  const snapshot = b4a.from(backing)
  const packet = codec().seal(sealOptions())
  const cell = codec({ crypto: { ...cryptoSuite, open: () => candidate } })

  expectCode(
    t,
    () => cell.open(openOptions(orderedSpy(), { key, noncePrefix }), packet),
    'CELL_INVALID'
  )
  t.alike(backing, snapshot)
})

test('cell crypto adapters receive disposable key and nonce snapshots', (t) => {
  const key = b4a.from(KEY)
  const noncePrefix = b4a.from(NONCE_PREFIX)
  const keySnapshot = b4a.from(key)
  const prefixSnapshot = b4a.from(noncePrefix)
  let sealKey = null
  let sealPrefix = null
  let openKey = null
  let openPrefix = null
  const sealing = codec({
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
  const packet = sealing.seal(sealOptions({ key, noncePrefix }))
  t.alike(key, keySnapshot)
  t.alike(noncePrefix, prefixSnapshot)

  const opening = codec({
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
  t.alike(opening.open(openOptions(orderedSpy(), { key, noncePrefix }), packet), b4a.from('hello'))
  t.alike(key, keySnapshot)
  t.alike(noncePrefix, prefixSnapshot)
  for (const snapshot of [sealKey, sealPrefix, openKey, openPrefix]) {
    t.alike(snapshot, b4a.alloc(snapshot.byteLength))
  }
})

test('cell key snapshot allocation is transactional before counter or crypto', (t) => {
  const original = b4a.allocUnsafeSlow
  let sealCalls = 0
  const cell = codec({
    crypto: {
      ...cryptoSuite,
      seal(options) {
        sealCalls++
        return cryptoSuite.seal(options)
      }
    }
  })
  const sender = new SenderCounter()
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
    expectCode(t, () => cell.seal(sealOptions({ senderCounter: sender })), 'CELL_INVALID')
  } finally {
    b4a.allocUnsafeSlow = original
  }
  t.is(sealCalls, 0)
  t.is(sender.value, 0n)
  t.alike(firstSnapshot, b4a.alloc(32))
  t.alike(partial, b4a.alloc(15))

  const valid = codec().seal(sealOptions())
  let openCalls = 0
  const opening = codec({
    crypto: {
      ...cryptoSuite,
      open(options) {
        openCalls++
        return cryptoSuite.open(options)
      }
    }
  })
  b4a.allocUnsafeSlow = (size) => (size === 16 ? original(15) : original(size))
  try {
    expectCode(t, () => opening.open(openOptions(orderedSpy()), valid), 'CELL_INVALID')
  } finally {
    b4a.allocUnsafeSlow = original
  }
  t.is(openCalls, 0)
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

function reusableSealOptions(overrides = {}) {
  const options = sealOptions({ paddingInto: (output) => output.fill(0), ...overrides })
  delete options.payload
  return options
}

function reusableOpenOptions(overrides = {}) {
  const options = openOptions(null, overrides)
  delete options.receiver
  return options
}

test('reusable cells match allocating wire bytes across geometry and counter boundaries', (t) => {
  for (const cellClass of [CELL_CLASS.CONTROL, CELL_CLASS.STREAM, CELL_CLASS.DATAGRAM]) {
    for (const direction of [DIRECTION.FORWARD, DIRECTION.REVERSE]) {
      for (const initial of [0n, 0x0102_0304_0506_0708n, 0xffff_ffff_ffff_ffffn]) {
        for (const length of [0, 1, MAX_CELL_PAYLOAD - 1, MAX_CELL_PAYLOAD]) {
          const payload = b4a.alloc(length, 0x9b)
          const options = { class: cellClass, direction, epoch: 0xffff_ffff_ffff_ffffn }
          const expected = codec().seal(
            sealOptions({ ...options, senderCounter: new SenderCounter({ initial }), payload })
          )
          const sealer = codec().createSealer(
            reusableSealOptions({ ...options, senderCounter: new SenderCounter({ initial }) })
          )
          const opener = codec().createOpener(
            reusableOpenOptions({
              expectedClass: cellClass,
              expectedDirection: direction,
              expectedEpoch: options.epoch
            })
          )
          const packet = b4a.alloc(CELL_SIZE)
          const body = b4a.alloc(CELL_BODY_SIZE)
          t.is(sealer.sealInto(packet, payload), CELL_SIZE)
          t.alike(packet, expected)
          t.is(opener.counter, null)
          t.is(opener.openInto(packet, body), length)
          t.is(opener.counter, initial)
          t.is((body[0] << 8) | body[1], length)
          t.alike(body.subarray(2, 2 + length), payload)
          sealer.destroy()
          opener.destroy()
          t.is(opener.counter, null)
          t.alike(packet, expected, 'destroy does not own the caller packet')
          t.alike(body.subarray(2, 2 + length), payload, 'destroy does not own caller plaintext')
        }
      }
    }
  }
})

test('reusable slab outputs and decoded bodies retain independent caller ownership', (t) => {
  const sealer = codec().createSealer(reusableSealOptions())
  const opener = codec().createOpener(reusableOpenOptions())
  const slab = b4a.alloc(3 * CELL_SIZE, 0x7d)
  const payloads = [b4a.from('first'), b4a.from('second')]
  const bodies = [b4a.alloc(CELL_BODY_SIZE), b4a.alloc(CELL_BODY_SIZE)]
  sealer.sealInto(slab, payloads[0], CELL_SIZE)
  const first = b4a.from(slab.subarray(CELL_SIZE, 2 * CELL_SIZE))
  sealer.sealInto(slab, payloads[1], 2 * CELL_SIZE)
  t.alike(slab.subarray(0, CELL_SIZE), b4a.alloc(CELL_SIZE, 0x7d))
  t.alike(slab.subarray(CELL_SIZE, 2 * CELL_SIZE), first)
  t.is(opener.openInto(first, bodies[0]), payloads[0].byteLength)
  t.is(opener.counter, 3n)
  t.is(opener.openInto(slab.subarray(2 * CELL_SIZE), bodies[1]), payloads[1].byteLength)
  t.is(opener.counter, 4n)
  t.alike(bodies[0].subarray(2, 7), payloads[0])
  t.alike(bodies[1].subarray(2, 8), payloads[1])
  bodies[1].fill(0)
  t.alike(bodies[0].subarray(2, 7), payloads[0])
  sealer.destroy()
  opener.destroy()
})

test('reusable decoding leaves replay and ordering decisions to the existing receiver', (t) => {
  const sealer = codec().createSealer(reusableSealOptions({ senderCounter: new SenderCounter() }))
  const opener = codec().createOpener(reusableOpenOptions())
  const receiver = new OrderedReceiver({ window: 8, gapTimeout: 100, now: () => 0 })
  const packets = [b4a.alloc(CELL_SIZE), b4a.alloc(CELL_SIZE)]
  const body = b4a.alloc(CELL_BODY_SIZE)
  sealer.sealInto(packets[0], b4a.from('zero'))
  sealer.sealInto(packets[1], b4a.from('one'))
  let length = opener.openInto(packets[1], body)
  const queued = b4a.from(body.subarray(2, 2 + length))
  t.alike(receiver.pushAuthenticated(opener.counter, queued), [])
  length = opener.openInto(packets[0], body)
  const delivery = receiver.pushAuthenticated(
    opener.counter,
    b4a.from(body.subarray(2, 2 + length))
  )
  body.fill(0)
  t.alike(delivery, [b4a.from('zero'), b4a.from('one')])
  t.is(opener.openInto(packets[0], body), 4, 'authentication alone permits the duplicate')
  expectCode(
    t,
    () => receiver.pushAuthenticated(opener.counter, b4a.from(body.subarray(2, 6))),
    'REPLAY'
  )
  sealer.destroy()
  opener.destroy()
  receiver.destroy()
})

test('reusable contexts snapshot keys, nonces and routing inputs without modifying callers', (t) => {
  const key = b4a.from(KEY)
  const noncePrefix = b4a.from(NONCE_PREFIX)
  const circuitId = b4a.from(CIRCUIT_ID)
  const options = reusableSealOptions({ key, noncePrefix, circuitId })
  const sealer = codec().createSealer(options)
  const opener = codec().createOpener(
    reusableOpenOptions({ key, noncePrefix, expectedCircuitId: circuitId })
  )
  key.fill(1)
  noncePrefix.fill(2)
  circuitId.fill(3)
  options.epoch = 99n
  const payload = b4a.from('static snapshots')
  const packet = b4a.alloc(CELL_SIZE)
  const body = b4a.alloc(CELL_BODY_SIZE)
  sealer.sealInto(packet, payload)
  t.alike(packet, codec().seal(sealOptions({ payload })))
  t.is(opener.openInto(packet, body), payload.byteLength)
  t.alike(body.subarray(2, 2 + payload.byteLength), payload)
  sealer.destroy()
  opener.destroy()
  t.alike(key, b4a.alloc(32, 1))
  t.alike(noncePrefix, b4a.alloc(16, 2))
  t.alike(circuitId, b4a.alloc(16, 3))
})

test('reusable decoding wipes outputs and retires on invalid headers, tags and body lengths', (t) => {
  const valid = codec().seal(sealOptions())
  const malformedLength = b4a.from(valid)
  const badBody = b4a.alloc(CELL_BODY_SIZE)
  badBody[0] = (MAX_CELL_PAYLOAD + 1) >>> 8
  badBody[1] = (MAX_CELL_PAYLOAD + 1) & 0xff
  const ciphertext = cryptoSuite.seal({
    key: KEY,
    noncePrefix: NONCE_PREFIX,
    counter: 3n,
    associatedData: b4a.concat([DOMAIN.CELL_HEADER, valid.subarray(0, CELL_HEADER_SIZE)]),
    plaintext: badBody
  })
  malformedLength.set(ciphertext, CELL_HEADER_SIZE)
  const invalidPackets = [malformedLength, valid.subarray(1), b4a.alloc(CELL_SIZE + 1)]
  for (const offset of [0, 1, 2, 3, 4, 12, 28, CELL_HEADER_SIZE, CELL_SIZE - 1]) {
    const packet = b4a.from(valid)
    packet[offset] ^= 1
    invalidPackets.push(packet)
  }
  for (const packet of invalidPackets) {
    const opener = codec().createOpener(reusableOpenOptions())
    const output = b4a.alloc(CELL_BODY_SIZE, 0xaa)
    t.is(opener.openInto(valid, output), 5)
    t.is(opener.counter, 3n)
    const snapshot = b4a.from(packet)
    expectCode(t, () => opener.openInto(packet, output), 'CELL_INVALID')
    t.is(opener.counter, null)
    t.alike(output, b4a.alloc(CELL_BODY_SIZE))
    t.alike(packet, snapshot)
    output.fill(0xaa)
    expectCode(t, () => opener.openInto(valid, output), 'CELL_INVALID')
    t.alike(output, b4a.alloc(CELL_BODY_SIZE))
    opener.destroy()
  }
  for (const overrides of [
    { key: b4a.alloc(32, 9) },
    { noncePrefix: b4a.alloc(16, 9) },
    { expectedCircuitId: b4a.alloc(16, 9) }
  ]) {
    const opener = codec().createOpener(reusableOpenOptions(overrides))
    const output = b4a.alloc(CELL_BODY_SIZE, 0xaa)
    expectCode(t, () => opener.openInto(valid, output), 'CELL_INVALID')
    t.alike(output, b4a.alloc(CELL_BODY_SIZE))
    for (const value of Object.values(overrides)) t.alike(value, b4a.alloc(value.byteLength, 9))
  }
})

test('reusable codecs reject overlapping output without erasing input, key or nonce storage', (t) => {
  const packet = codec().seal(sealOptions())
  const snapshot = b4a.from(packet)
  const opener = codec().createOpener(reusableOpenOptions())
  expectCode(t, () => opener.openInto(packet, packet.subarray(0, CELL_BODY_SIZE)), 'CELL_INVALID')
  t.alike(packet, snapshot)
  const sealer = codec().createSealer(reusableSealOptions())
  expectCode(t, () => sealer.sealInto(packet, packet.subarray(100, 105)), 'CELL_INVALID')
  t.alike(packet, snapshot)

  for (const name of ['key', 'noncePrefix', 'circuitId']) {
    const storage = b4a.alloc(CELL_SIZE, 0x5e)
    const size = name === 'key' ? 32 : 16
    const input = storage.subarray(9, 9 + size)
    const overrides = { [name]: input }
    const sealing = codec().createSealer(reusableSealOptions(overrides))
    const opening = codec().createOpener(
      reusableOpenOptions({ [name === 'circuitId' ? 'expectedCircuitId' : name]: input })
    )
    expectCode(t, () => sealing.sealInto(storage, b4a.from('x')), 'CELL_INVALID')
    t.alike(storage, b4a.alloc(CELL_SIZE, 0x5e))
    expectCode(
      t,
      () => opening.openInto(packet, storage.subarray(0, CELL_BODY_SIZE)),
      'CELL_INVALID'
    )
    t.alike(storage, b4a.alloc(CELL_SIZE, 0x5e))
  }
})

test('reusable buffers use intrinsic lengths and reject malformed inputs before counter use', (t) => {
  let calls = 0
  const hostile = () => {
    calls++
    throw new Error('unexpected getter or method')
  }
  const payload = b4a.from('hello')
  const packet = b4a.alloc(CELL_SIZE)
  const body = b4a.alloc(CELL_BODY_SIZE)
  for (const value of [payload, packet, body]) {
    Object.defineProperties(value, {
      byteLength: { get: hostile },
      subarray: { value: hostile },
      set: { value: hostile },
      fill: { value: hostile }
    })
  }
  const sealer = codec().createSealer(reusableSealOptions())
  const opener = codec().createOpener(reusableOpenOptions())
  sealer.sealInto(packet, payload)
  t.is(opener.openInto(packet, body), 5)
  t.is(body[2], payload[0])
  t.is(body[6], payload[4])
  t.is(calls, 0)
  sealer.destroy()
  opener.destroy()

  const short = b4a.alloc(CELL_SIZE - 1, 0xaa)
  Object.defineProperty(short, 'byteLength', { value: CELL_SIZE })
  const revoked = Proxy.revocable(b4a.alloc(1), {})
  revoked.revoke()
  for (const badPayload of [null, {}, revoked.proxy, b4a.alloc(MAX_CELL_PAYLOAD + 1)]) {
    const senderCounter = new SenderCounter()
    const sealing = codec().createSealer(reusableSealOptions({ senderCounter }))
    const output = b4a.alloc(CELL_SIZE, 0xaa)
    expectCode(t, () => sealing.sealInto(output, badPayload), 'CELL_INVALID')
    t.is(senderCounter.value, 0n)
    t.alike(output, b4a.alloc(CELL_SIZE))
  }
  const senderCounter = new SenderCounter()
  const sealing = codec().createSealer(reusableSealOptions({ senderCounter }))
  expectCode(t, () => sealing.sealInto(short, payload), 'CELL_INVALID')
  t.is(senderCounter.value, 0n)
  t.is(short[0], 0)
  t.is(short[CELL_SIZE - 2], 0)
  for (const offset of [-1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER]) {
    const output = b4a.alloc(CELL_SIZE, 0xaa)
    const context = codec().createSealer(reusableSealOptions())
    expectCode(t, () => context.sealInto(output, payload, offset), 'CELL_INVALID')
    t.alike(output, b4a.alloc(CELL_SIZE, 0xaa), 'invalid ranges do not erase unrelated slab cells')
  }
  const opening = codec().createOpener(reusableOpenOptions())
  const shortBody = b4a.alloc(CELL_BODY_SIZE - 1, 0xaa)
  expectCode(t, () => opening.openInto(packet, shortBody), 'CELL_INVALID')
  t.alike(shortBody, b4a.alloc(CELL_BODY_SIZE - 1))
  if (typeof SharedArrayBuffer === 'function') {
    const shared = new Uint8Array(new SharedArrayBuffer(CELL_SIZE))
    const sharedContext = codec().createSealer(reusableSealOptions())
    expectCode(t, () => sharedContext.sealInto(shared, payload), 'CELL_INVALID')
  }
})

test('reusable factories reject accessors, inherited options and untrusted providers', (t) => {
  let accesses = 0
  for (const [factory, options] of [
    ['createSealer', reusableSealOptions()],
    ['createOpener', reusableOpenOptions()]
  ]) {
    const sealing = factory === 'createSealer'
    for (const malformed of [
      { key: b4a.alloc(31) },
      { noncePrefix: b4a.alloc(15) },
      { [sealing ? 'circuitId' : 'expectedCircuitId']: b4a.alloc(15) },
      { [sealing ? 'class' : 'expectedClass']: 255 },
      { [sealing ? 'direction' : 'expectedDirection']: 255 },
      { [sealing ? 'epoch' : 'expectedEpoch']: -1n },
      { [sealing ? 'epoch' : 'expectedEpoch']: 1n << 64n }
    ]) {
      expectCode(t, () => codec()[factory]({ ...options, ...malformed }), 'CELL_INVALID')
    }
    for (const name of Object.keys(options)) {
      const accessor = { ...options }
      Object.defineProperty(accessor, name, { get: () => accesses++ })
      expectCode(t, () => codec()[factory](accessor), 'CELL_INVALID')
    }
    expectCode(t, () => codec()[factory](Object.create(options)), 'CELL_INVALID')
    const revoked = Proxy.revocable(options, {})
    revoked.revoke()
    expectCode(t, () => codec()[factory](revoked.proxy), 'CELL_INVALID')
    const trapped = new Proxy(options, {
      getOwnPropertyDescriptor() {
        throw new Error('descriptor trap')
      }
    })
    expectCode(t, () => codec()[factory](trapped), 'CELL_INVALID')
    const arbitrary = codec({ crypto: { ...cryptoSuite } })
    expectCode(t, () => arbitrary[factory](options), 'CELL_INVALID')
  }
  t.is(accesses, 0)
  const allocatingPadding = reusableSealOptions()
  delete allocatingPadding.paddingInto
  expectCode(t, () => codec().createSealer(allocatingPadding), 'CELL_INVALID')
})

test('reusable padding receives cleared non-plaintext scratch and defaults to secure random fill', (t) => {
  const seen = []
  const sealer = codec().createSealer(
    reusableSealOptions({
      paddingInto(output) {
        seen.push(b4a.from(output))
        output.fill(0x61)
      }
    })
  )
  const packet = b4a.alloc(CELL_SIZE)
  sealer.sealInto(packet, b4a.alloc(300, 0xb7))
  sealer.sealInto(packet, b4a.alloc(700, 0xc8))
  for (const before of seen) t.alike(before, b4a.alloc(MAX_CELL_PAYLOAD))
  const expected = codec({ padding: (size) => b4a.alloc(size, 0x61) }).seal(
    sealOptions({
      senderCounter: new SenderCounter({ initial: 4n }),
      payload: b4a.alloc(700, 0xc8)
    })
  )
  t.alike(packet, expected)
  sealer.destroy()

  const cell = codec({ padding: undefined })
  const options = reusableSealOptions()
  delete options.paddingInto
  const random = cell.createSealer(options)
  const opener = cell.createOpener(reusableOpenOptions())
  const body = b4a.alloc(CELL_BODY_SIZE)
  random.sealInto(packet, b4a.from('x'))
  opener.openInto(packet, body)
  const firstPadding = b4a.from(body.subarray(3))
  random.sealInto(packet, b4a.from('x'))
  opener.openInto(packet, body)
  t.absent(b4a.equals(firstPadding, body.subarray(3)))
  t.is(body[2], 0x78)
  random.destroy()
  opener.destroy()
})

test('reentrant padding, counter callbacks and destroy retire the active sealer', (t) => {
  for (const mode of ['padding-reenter', 'padding-destroy', 'counter-reenter', 'counter-destroy']) {
    const allocations = []
    const cell = codec({
      [TEST_ONLY_CELL_ALLOCATOR]: {
        allocate(size) {
          const value = b4a.allocUnsafeSlow(size)
          allocations.push(value)
          return value
        },
        release() {}
      }
    })
    const output = b4a.alloc(CELL_SIZE, 0xaa)
    const nested = b4a.alloc(CELL_SIZE, 0xbb)
    const payload = b4a.from('reentrancy')
    let sealer
    function interrupt() {
      if (mode.endsWith('destroy')) sealer.destroy()
      else expectCode(t, () => sealer.sealInto(nested, payload), 'CELL_INVALID')
    }
    sealer = cell.createSealer(
      reusableSealOptions({
        paddingInto(output) {
          output.fill(0)
          if (mode.startsWith('padding')) interrupt()
        },
        senderCounter: {
          next() {
            if (mode.startsWith('counter')) interrupt()
            return 3n
          }
        }
      })
    )
    expectCode(t, () => sealer.sealInto(output, payload), 'CELL_INVALID')
    t.alike(output, b4a.alloc(CELL_SIZE))
    if (mode.endsWith('reenter')) t.alike(nested, b4a.alloc(CELL_SIZE))
    for (const value of allocations) t.alike(value, b4a.alloc(value.byteLength))
    expectCode(t, () => sealer.sealInto(output, payload), 'CELL_INVALID')
    sealer.destroy()
  }
})

test('reentrant decrypt and destroy never publish authenticated plaintext', (t) => {
  const original = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt
  const packet = codec().seal(sealOptions())
  for (const reenter of [false, true]) {
    const opener = codec().createOpener(reusableOpenOptions())
    const output = b4a.alloc(CELL_BODY_SIZE, 0xaa)
    const nested = b4a.alloc(CELL_BODY_SIZE, 0xbb)
    sodium.crypto_aead_xchacha20poly1305_ietf_decrypt = (...args) => {
      const result = original(...args)
      if (reenter) expectCode(t, () => opener.openInto(packet, nested), 'CELL_INVALID')
      else opener.destroy()
      return result
    }
    try {
      expectCode(t, () => opener.openInto(packet, output), 'CELL_INVALID')
    } finally {
      sodium.crypto_aead_xchacha20poly1305_ietf_decrypt = original
    }
    t.alike(output, b4a.alloc(CELL_BODY_SIZE))
    t.is(opener.counter, null)
    if (reenter) t.alike(nested, b4a.alloc(CELL_BODY_SIZE))
    opener.destroy()
  }
})

test('reusable context setup is transactional and rejects allocator aliases', (t) => {
  for (const factory of ['createSealer', 'createOpener']) {
    const options = factory === 'createSealer' ? reusableSealOptions() : reusableOpenOptions()
    const owned = []
    let calls = 0
    const cell = codec({
      [TEST_ONLY_CELL_ALLOCATOR]: {
        allocate(size) {
          const value = b4a.allocUnsafeSlow(++calls === 3 ? size - 1 : size)
          value.fill(0x8e)
          owned.push(value)
          return value
        },
        release() {}
      }
    })
    expectCode(t, () => cell[factory](options), 'CELL_INVALID')
    for (const value of owned) t.alike(value, b4a.alloc(value.byteLength))
    const key = b4a.from(KEY)
    const aliased = codec({
      [TEST_ONLY_CELL_ALLOCATOR]: {
        allocate() {
          return key
        },
        release() {
          t.fail('caller-owned key must not be released')
        }
      }
    })
    expectCode(t, () => aliased[factory]({ ...options, key }), 'CELL_INVALID')
    t.alike(key, KEY)
  }
})

test('repeated reusable production crypto uses no new cryptographic backing allocations', (t) => {
  let scratchAllocations = 0
  const owned = []
  const cell = codec({
    padding: undefined,
    [TEST_ONLY_CELL_ALLOCATOR]: {
      allocate(size) {
        scratchAllocations++
        const value = b4a.allocUnsafeSlow(size)
        owned.push(value)
        return value
      },
      release() {}
    }
  })
  const options = reusableSealOptions()
  delete options.paddingInto
  const sealer = cell.createSealer(options)
  const opener = cell.createOpener(reusableOpenOptions())
  const before = scratchAllocations
  const slab = b4a.alloc(64 * CELL_SIZE)
  const packets = Array.from({ length: 64 }, (_, i) =>
    slab.subarray(i * CELL_SIZE, (i + 1) * CELL_SIZE)
  )
  const output = b4a.alloc(CELL_BODY_SIZE)
  const payload = b4a.alloc(17, 0x71)
  const saved = new Map()
  let backingCalls = 0
  let matched = true
  // Instrument only the synchronous hot loop; assertions may allocate freely.
  for (const name of ['alloc', 'allocUnsafe', 'allocUnsafeSlow', 'from', 'concat']) {
    const original = b4a[name]
    saved.set(name, original)
    b4a[name] = (...args) => {
      backingCalls++
      return original(...args)
    }
  }
  try {
    for (let i = 0; i < 64; i++) {
      sealer.sealInto(slab, payload, i * CELL_SIZE)
      const length = opener.openInto(packets[i], output)
      if (length !== 17 || opener.counter !== BigInt(i + 3)) matched = false
      for (let j = 0; j < 17; j++) {
        if (output[2 + j] !== 0x71) matched = false
      }
    }
  } finally {
    for (const [name, original] of saved) b4a[name] = original
  }
  t.ok(matched)
  t.is(backingCalls, 0)
  t.is(scratchAllocations, before)
  sealer.destroy()
  opener.destroy()
  for (const value of owned) t.alike(value, b4a.alloc(value.byteLength))
})

test('reusable crypto failures wipe owned secrets and burn only reserved counters', (t) => {
  const original = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt
  const owned = []
  const cell = codec({
    [TEST_ONLY_CELL_ALLOCATOR]: {
      allocate(size) {
        const value = b4a.allocUnsafeSlow(size)
        owned.push(value)
        return value
      },
      release() {}
    }
  })
  const senderCounter = new SenderCounter()
  const sealer = cell.createSealer(reusableSealOptions({ senderCounter }))
  const output = b4a.alloc(2 * CELL_SIZE, 0xaa)
  const sentinel = new Error('native encryption failed after reservation')
  sodium.crypto_aead_xchacha20poly1305_ietf_encrypt = (...args) => {
    original(...args)
    throw sentinel
  }
  let error = null
  try {
    sealer.sealInto(output, b4a.from('payload'), CELL_SIZE)
  } catch (err) {
    error = err
  } finally {
    sodium.crypto_aead_xchacha20poly1305_ietf_encrypt = original
  }
  t.is(error, sentinel)
  t.is(senderCounter.value, 1n)
  t.alike(output.subarray(0, CELL_SIZE), b4a.alloc(CELL_SIZE, 0xaa))
  t.alike(output.subarray(CELL_SIZE), b4a.alloc(CELL_SIZE))
  for (const value of owned) t.alike(value, b4a.alloc(value.byteLength))
  expectCode(t, () => sealer.sealInto(output, b4a.from('retry')), 'CELL_INVALID')
  t.is(senderCounter.value, 1n)

  const exhausted = new SenderCounter({ maximum: 0n })
  exhausted.next()
  const closed = codec().createSealer(reusableSealOptions({ senderCounter: exhausted }))
  expectCode(t, () => closed.sealInto(output, b4a.from('x')), 'COUNTER_EXHAUSTED')
  t.alike(output.subarray(0, CELL_SIZE), b4a.alloc(CELL_SIZE))
})
