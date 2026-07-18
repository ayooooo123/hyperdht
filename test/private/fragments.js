const test = require('brittle')
const b4a = require('b4a')

const {
  FRAGMENT_HEADER_SIZE,
  MAX_FRAGMENT_DATA,
  MAX_FRAGMENTS,
  MAX_MESSAGE_DATA_BYTES,
  MAX_ENCODED_MESSAGE_BYTES,
  MAX_MESSAGES,
  MAX_BUFFERED_FRAGMENTS,
  MAX_BUFFERED_ENCODED_BYTES,
  MAX_COMPLETED_IDS,
  MESSAGE_TIMEOUT,
  Reassembler,
  TEST_ONLY_FRAGMENT_OBSERVER,
  fragment
} = require('../../lib/private/fragments')
const { PrivateRouteError } = require('../../lib/private/errors')

// Adapted from the reviewed private-routes prototype at commit
// 0305df915b6a767093f9e75e6c06bc0a35da6169. Gate 3A constrains the
// prototype's obsolete 16 MiB ceiling to eight route payloads: 8,424 data
// bytes become 8,584 encoded bytes after eight 20-byte fragment headers.

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

function id(value) {
  return b4a.alloc(16, value)
}

function frame(messageId, index, total, data = b4a.alloc(0)) {
  const value = b4a.alloc(FRAGMENT_HEADER_SIZE + data.byteLength)
  Uint8Array.prototype.set.call(value, messageId, 0)
  value[16] = index >>> 8
  value[17] = index
  value[18] = total >>> 8
  value[19] = total
  Uint8Array.prototype.set.call(value, data, FRAGMENT_HEADER_SIZE)
  return value
}

function receiver(overrides = {}) {
  return new Reassembler({
    now: () => 0,
    epochExpiresAt: 100_000,
    ...overrides
  })
}

function totalEncoded(frames) {
  let total = 0
  for (const value of frames) total += value.byteLength
  return total
}

function replace(object, name, descriptor, saved) {
  saved.push([object, name, Object.getOwnPropertyDescriptor(object, name)])
  Object.defineProperty(object, name, descriptor)
}

function poisonCollections() {
  const saved = []
  const iteratorPrototype = Object.getPrototypeOf(new Map().values())
  const throwing = {
    configurable: true,
    writable: true,
    value() {
      throw new Error('mutable collection intrinsic ran')
    }
  }
  for (const name of ['get', 'has', 'set', 'delete', 'clear', 'values']) {
    replace(Map.prototype, name, throwing, saved)
  }
  replace(
    Map.prototype,
    'size',
    {
      configurable: true,
      get() {
        throw new Error('mutable map size getter ran')
      }
    },
    saved
  )
  for (const name of ['has', 'add', 'delete', 'clear', 'values']) {
    replace(Set.prototype, name, throwing, saved)
  }
  replace(
    Set.prototype,
    'size',
    {
      configurable: true,
      get() {
        throw new Error('mutable set size getter ran')
      }
    },
    saved
  )
  replace(iteratorPrototype, 'next', throwing, saved)
  replace(globalThis, 'Map', throwing, saved)
  replace(globalThis, 'Set', throwing, saved)
  replace(Reflect, 'apply', throwing, saved)

  return function restore() {
    for (let index = saved.length - 1; index >= 0; index--) {
      const [object, name, descriptor] = saved[index]
      Object.defineProperty(object, name, descriptor)
    }
  }
}

test('fragment constants lock the reviewed Gate 3A ceilings', (t) => {
  t.is(FRAGMENT_HEADER_SIZE, 20)
  t.is(MAX_FRAGMENT_DATA, 1053)
  t.is(MAX_FRAGMENTS, 8)
  t.is(MAX_MESSAGE_DATA_BYTES, 8424)
  t.is(MAX_ENCODED_MESSAGE_BYTES, 8584)
  t.is(MAX_MESSAGES, 8)
  t.is(MAX_BUFFERED_FRAGMENTS, 8)
  t.is(MAX_BUFFERED_ENCODED_BYTES, 8584)
  t.is(MAX_COMPLETED_IDS, 64)
  t.is(MESSAGE_TIMEOUT, 5000)
})

test('fragment emits one through eight canonical frames', (t) => {
  for (let count = 1; count <= MAX_FRAGMENTS; count++) {
    const length = count === 1 ? 1 : (count - 1) * MAX_FRAGMENT_DATA + count
    const message = b4a.alloc(length, count)
    const frames = fragment(message, { messageId: id(count) })

    t.is(frames.length, count)
    for (let index = 0; index < frames.length; index++) {
      const value = frames[index]
      t.is((value[16] << 8) | value[17], index)
      t.is((value[18] << 8) | value[19], count)
      if (index < count - 1) t.is(value.byteLength, 1073)
    }
    const reassembler = receiver()
    let output = null
    for (const value of frames) output = reassembler.pushAuthenticated(value)
    t.alike(output, message)
  }
})

test('8,424 data bytes occupy exactly eight full 1,073-byte payloads', (t) => {
  const message = b4a.alloc(MAX_MESSAGE_DATA_BYTES, 0x5c)
  const frames = fragment(message, { messageId: id(36) })

  t.is(frames.length, MAX_FRAGMENTS)
  t.is(totalEncoded(frames), MAX_ENCODED_MESSAGE_BYTES)
  for (const value of frames) t.is(value.byteLength, 1073)

  const reassembler = receiver()
  for (let i = 0; i < frames.length - 1; i++) {
    t.is(reassembler.pushAuthenticated(frames[i]), null)
  }
  t.alike(reassembler.pushAuthenticated(frames[7]), message)
})

test('8,425 data bytes fail before ID generation or allocation', (t) => {
  let randomCalls = 0
  let allocations = 0
  const allocate = b4a.allocUnsafeSlow
  b4a.allocUnsafeSlow = (size) => {
    allocations++
    return allocate(size)
  }
  try {
    expectCode(
      t,
      () =>
        fragment(b4a.alloc(MAX_MESSAGE_DATA_BYTES + 1), {
          randomBytes() {
            randomCalls++
            return id(1)
          }
        }),
      'INVALID_ROUTE'
    )
  } finally {
    b4a.allocUnsafeSlow = allocate
  }
  t.is(randomCalls, 0)
  t.is(allocations, 0)
})

test('random callback cannot mutate fragmentation arithmetic or buffer validation', (t) => {
  const ceil = Math.ceil
  const min = Math.min
  const max = Math.max
  const safeInteger = Number.isSafeInteger
  const isBuffer = b4a.isBuffer
  let frames
  try {
    frames = fragment(b4a.alloc(MAX_MESSAGE_DATA_BYTES, 0x5d), {
      randomBytes() {
        Math.ceil = () => 1
        Math.min = () => 0
        Math.max = () => 65_535
        Number.isSafeInteger = () => false
        b4a.isBuffer = () => false
        return id(37)
      }
    })
  } finally {
    Math.ceil = ceil
    Math.min = min
    Math.max = max
    Number.isSafeInteger = safeInteger
    b4a.isBuffer = isBuffer
  }
  t.is(frames.length, MAX_FRAGMENTS)
  t.is(totalEncoded(frames), MAX_ENCODED_MESSAGE_BYTES)
  for (const value of frames) {
    t.is(value.byteLength, FRAGMENT_HEADER_SIZE + MAX_FRAGMENT_DATA)
  }
})

test('fragment copies the message and identifier and supports empty data', (t) => {
  const message = b4a.from('owned output')
  const messageId = id(2)
  const frames = fragment(message, { messageId })
  message.fill(0)
  messageId.fill(0)

  t.alike(receiver().pushAuthenticated(frames[0]), b4a.from('owned output'))
  const empty = fragment(b4a.alloc(0), { messageId: id(3) })
  t.is(empty.length, 1)
  t.is(empty[0].byteLength, FRAGMENT_HEADER_SIZE)
  t.alike(receiver().pushAuthenticated(empty[0]), b4a.alloc(0))
})

test('fragment options are own data properties and hostile inputs fail stably', (t) => {
  const inherited = Object.create({ messageId: id(4) })
  const accessor = {}
  let reads = 0
  Object.defineProperty(accessor, 'messageId', {
    get() {
      reads++
      return id(5)
    }
  })
  const trapped = new Proxy(
    {},
    {
      getOwnPropertyDescriptor() {
        throw new Error('descriptor trap')
      }
    }
  )
  const hasTrap = new Proxy(
    {},
    {
      has() {
        throw new Error('has trap')
      }
    }
  )
  const revoked = Proxy.revocable({}, {})
  revoked.revoke()

  for (const options of [inherited, accessor, trapped, hasTrap, revoked.proxy, null, []]) {
    expectCode(t, () => fragment(b4a.from('x'), options), 'INVALID_ROUTE')
  }
  t.is(reads, 0)

  const own = Object.create(null)
  own.messageId = id(6)
  t.is(fragment(b4a.from('x'), own).length, 1)
})

test('fragment rejects zero, short, long, forged, and revoked identifiers', (t) => {
  const forged = Object.create(Uint8Array.prototype)
  const revoked = Proxy.revocable(b4a.alloc(16), {})
  revoked.revoke()
  for (const messageId of [b4a.alloc(0), b4a.alloc(15), b4a.alloc(17), forged, revoked.proxy]) {
    expectCode(t, () => fragment(b4a.from('x'), { messageId }), 'INVALID_ROUTE')
  }
})

test('fragment bypasses shadowed byteLength, subarray, set, and fill', (t) => {
  let calls = 0
  const hostile = () => {
    calls++
    throw new Error('instance method must not run')
  }
  const message = b4a.alloc(MAX_FRAGMENT_DATA + 1, 0x4a)
  Object.defineProperties(message, {
    byteLength: { value: 1 },
    subarray: { value: hostile },
    set: { value: hostile },
    fill: { value: hostile }
  })
  const allocate = b4a.allocUnsafeSlow
  b4a.allocUnsafeSlow = (size) => {
    const value = allocate(size)
    Object.defineProperties(value, {
      subarray: { value: hostile },
      set: { value: hostile },
      fill: { value: hostile }
    })
    return value
  }
  let frames
  try {
    frames = fragment(message, { messageId: id(7) })
  } finally {
    b4a.allocUnsafeSlow = allocate
  }
  const reassembler = receiver()
  t.is(reassembler.pushAuthenticated(frames[0]), null)
  t.alike(reassembler.pushAuthenticated(frames[1]), b4a.alloc(MAX_FRAGMENT_DATA + 1, 0x4a))
  t.is(calls, 0)
})

test('fragment allocation failures clear every partial owned frame', (t) => {
  const message = b4a.alloc(MAX_FRAGMENT_DATA + 1, 0x5a)
  const allocate = b4a.allocUnsafeSlow
  const owned = []
  let calls = 0
  b4a.allocUnsafeSlow = (size) => {
    calls++
    if (calls === 2) {
      const partial = allocate(size - 1)
      partial.fill(0xcc)
      owned.push(partial)
      return partial
    }
    const value = allocate(size)
    value.fill(0xbb)
    owned.push(value)
    return value
  }
  try {
    expectCode(t, () => fragment(message, { messageId: id(8) }), 'INVALID_ROUTE')
  } finally {
    b4a.allocUnsafeSlow = allocate
  }
  t.is(owned.length, 2)
  for (const value of owned) t.alike(value, b4a.alloc(value.byteLength))
})

test('out-of-order fragments complete once and transfer an owned output', (t) => {
  const message = b4a.alloc(3 * MAX_FRAGMENT_DATA + 7, 0x5a)
  const frames = fragment(message, { messageId: id(9) })
  const accepted = []
  const reassembler = receiver({
    [TEST_ONLY_FRAGMENT_OBSERVER](value) {
      accepted.push(value)
    }
  })

  t.is(reassembler.pushAuthenticated(frames[2]), null)
  t.is(reassembler.pushAuthenticated(frames[0]), null)
  t.is(reassembler.pushAuthenticated(frames[3]), null)
  const output = reassembler.pushAuthenticated(frames[1])
  t.alike(output, message)
  for (const value of accepted) t.alike(value, b4a.alloc(value.byteLength))
  frames[0].fill(0)
  t.alike(output, message)
  t.alike(reassembler.stats, {
    destroyed: false,
    messages: 0,
    bufferedFragments: 0,
    bufferedDataBytes: 0,
    bufferedEncodedBytes: 0,
    completedIds: 1
  })
})

test('malformed structural bounds fail before clock, allocation, or observer callbacks', (t) => {
  let clockCalls = 0
  let observerCalls = 0
  let allocations = 0
  const allocate = b4a.allocUnsafeSlow
  const reassembler = receiver({
    now() {
      clockCalls++
      return 0
    },
    [TEST_ONLY_FRAGMENT_OBSERVER]() {
      observerCalls++
    }
  })
  b4a.allocUnsafeSlow = (size) => {
    allocations++
    return allocate(size)
  }
  const cases = [
    b4a.alloc(0),
    b4a.alloc(15),
    b4a.alloc(19),
    frame(id(10), 0, 0),
    frame(id(11), 1, 1),
    frame(id(12), 8, 9),
    frame(id(13), 0, 2, b4a.alloc(MAX_FRAGMENT_DATA - 1)),
    frame(id(14), 1, 2),
    frame(id(15), 0, 1, b4a.alloc(MAX_FRAGMENT_DATA + 1))
  ]
  try {
    for (const value of cases) {
      expectCode(t, () => reassembler.pushAuthenticated(value), 'INVALID_ROUTE')
    }
  } finally {
    b4a.allocUnsafeSlow = allocate
  }
  t.is(clockCalls, 0)
  t.is(observerCalls, 0)
  t.is(allocations, 0)
})

test('identical duplicates are replay while conflicting duplicates clear only their message', (t) => {
  const owned = []
  const reassembler = receiver({
    [TEST_ONLY_FRAGMENT_OBSERVER](value) {
      owned.push(value)
    }
  })
  const first = fragment(b4a.alloc(MAX_FRAGMENT_DATA + 1, 1), { messageId: id(16) })
  const other = fragment(b4a.alloc(MAX_FRAGMENT_DATA + 1, 2), { messageId: id(17) })
  reassembler.pushAuthenticated(first[0])
  reassembler.pushAuthenticated(other[0])

  expectCode(t, () => reassembler.pushAuthenticated(b4a.from(first[0])), 'REPLAY')
  t.is(reassembler.stats.messages, 2)
  const conflict = b4a.from(first[0])
  conflict[20] ^= 1
  expectCode(t, () => reassembler.pushAuthenticated(conflict), 'INVALID_ROUTE')
  t.alike(owned[0], b4a.alloc(owned[0].byteLength))
  t.is(reassembler.stats.messages, 1)
  t.alike(reassembler.pushAuthenticated(other[1]), b4a.alloc(MAX_FRAGMENT_DATA + 1, 2))
})

test('conflicting total, index, and noncanonical lengths clean only the affected message', (t) => {
  const malformed = [
    frame(id(18), 1, 3, b4a.from('x')),
    frame(id(19), 2, 2, b4a.from('x')),
    frame(id(20), 1, 2),
    frame(id(21), 1, 2, b4a.alloc(MAX_FRAGMENT_DATA + 1))
  ]
  for (const bad of malformed) {
    const messageId = Uint8Array.prototype.subarray.call(bad, 0, 16)
    const good = fragment(b4a.alloc(MAX_FRAGMENT_DATA + 1, 3), { messageId })
    const unrelated = fragment(b4a.alloc(MAX_FRAGMENT_DATA + 1, 4), { messageId: id(bad[0] + 90) })
    const reassembler = receiver()
    reassembler.pushAuthenticated(good[0])
    reassembler.pushAuthenticated(unrelated[0])
    expectCode(t, () => reassembler.pushAuthenticated(bad), 'INVALID_ROUTE')
    t.is(reassembler.stats.messages, 1)
    t.alike(reassembler.pushAuthenticated(unrelated[1]), b4a.alloc(MAX_FRAGMENT_DATA + 1, 4))
  }
})

test('short and oversized values identify and clear only an active message', (t) => {
  for (let length = 16; length < 20; length++) {
    const active = fragment(b4a.alloc(MAX_FRAGMENT_DATA + 1), { messageId: id(30 + length) })
    const other = fragment(b4a.alloc(MAX_FRAGMENT_DATA + 1, 2), { messageId: id(40 + length) })
    const reassembler = receiver()
    reassembler.pushAuthenticated(active[0])
    reassembler.pushAuthenticated(other[0])
    const short = b4a.alloc(length)
    short.set(id(30 + length))
    expectCode(t, () => reassembler.pushAuthenticated(short), 'INVALID_ROUTE')
    t.is(reassembler.stats.messages, 1)
    t.alike(reassembler.pushAuthenticated(other[1]), b4a.alloc(MAX_FRAGMENT_DATA + 1, 2))
  }

  const frames = fragment(b4a.alloc(MAX_FRAGMENT_DATA + 1), { messageId: id(50) })
  const reassembler = receiver()
  reassembler.pushAuthenticated(frames[0])
  expectCode(
    t,
    () => reassembler.pushAuthenticated(frame(id(50), 1, 2, b4a.alloc(1054))),
    'INVALID_ROUTE'
  )
  t.is(reassembler.stats.messages, 0)
})

test('completed identifiers are bounded sticky replay tombstones', (t) => {
  const reassembler = receiver()
  const complete = fragment(b4a.from('done'), { messageId: id(51) })[0]
  t.alike(reassembler.pushAuthenticated(complete), b4a.from('done'))
  expectCode(t, () => reassembler.pushAuthenticated(b4a.from(complete)), 'REPLAY')
  expectCode(
    t,
    () => reassembler.pushAuthenticated(frame(id(51), 0, 1, b4a.from('changed'))),
    'REPLAY'
  )
  t.is(reassembler.stats.completedIds, 1)
})

test('five-second expiry is exact and monotonic', (t) => {
  let now = 10
  const owned = []
  const reassembler = receiver({
    now: () => now,
    [TEST_ONLY_FRAGMENT_OBSERVER](value) {
      owned.push(value)
    }
  })
  const frames = fragment(b4a.alloc(MAX_FRAGMENT_DATA + 1), { messageId: id(52) })
  reassembler.pushAuthenticated(frames[0])
  now += MESSAGE_TIMEOUT - 1
  t.is(reassembler.expire(), 0)
  now++
  t.is(reassembler.expire(), 1)
  t.alike(owned[0], b4a.alloc(owned[0].byteLength))
  t.is(reassembler.stats.messages, 0)

  now--
  expectCode(t, () => reassembler.expire(), 'INVALID_ROUTE')
  t.is(reassembler.stats.destroyed, true)
})

test('epoch expiry clears messages and replay tombstones and closes the receiver', (t) => {
  let now = 0
  const reassembler = receiver({ now: () => now, epochExpiresAt: 100 })
  const pending = fragment(b4a.alloc(MAX_FRAGMENT_DATA + 1), { messageId: id(53) })
  reassembler.pushAuthenticated(pending[0])
  reassembler.pushAuthenticated(fragment(b4a.from('done'), { messageId: id(54) })[0])
  now = 100

  expectCode(t, () => reassembler.expire(), 'CIRCUIT_STATE')
  t.alike(reassembler.stats, {
    destroyed: true,
    messages: 0,
    bufferedFragments: 0,
    bufferedDataBytes: 0,
    bufferedEncodedBytes: 0,
    completedIds: 0
  })
  expectCode(t, () => reassembler.pushAuthenticated(pending[1]), 'CIRCUIT_STATE')
})

test('configured limits accept smaller own-data values and reject every invalid boundary', (t) => {
  const own = Object.create(null)
  own.now = () => 0
  own.epochExpiresAt = 100
  own.maxMessageBytes = 1054
  own.maxMessages = 1
  own.maxBufferedFragments = 2
  own.maxBufferedEncodedBytes = 1094
  own.maxCompletedIds = 1
  own.messageTimeout = 1
  const configured = new Reassembler(own)
  const frames = fragment(b4a.alloc(1054), { messageId: id(55) })
  configured.pushAuthenticated(frames[0])
  t.alike(configured.pushAuthenticated(frames[1]), b4a.alloc(1054))
  t.ok(receiver({ messageTimeout: 0 }))

  const boundaries = {
    maxMessageBytes: [0, -1, 1.5, NaN, Infinity, MAX_MESSAGE_DATA_BYTES + 1],
    maxMessages: [0, -1, 1.5, NaN, Infinity, MAX_MESSAGES + 1],
    maxBufferedFragments: [0, -1, 1.5, NaN, Infinity, MAX_BUFFERED_FRAGMENTS + 1],
    maxBufferedEncodedBytes: [0, -1, 1.5, NaN, Infinity, MAX_BUFFERED_ENCODED_BYTES + 1],
    maxCompletedIds: [0, -1, 1.5, NaN, Infinity, MAX_COMPLETED_IDS + 1],
    messageTimeout: [-1, 0.5, NaN, Infinity, MESSAGE_TIMEOUT + 1],
    epochExpiresAt: [-1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]
  }
  for (const [name, values] of Object.entries(boundaries)) {
    for (const value of values) expectCode(t, () => receiver({ [name]: value }), 'INVALID_ROUTE')
  }
})

test('receiver options reject inherited, accessor, descriptor, has, and revoked traps', (t) => {
  const inherited = Object.create({ now: () => 0 })
  inherited.epochExpiresAt = 100
  const accessor = { epochExpiresAt: 100 }
  let reads = 0
  Object.defineProperty(accessor, 'now', {
    get() {
      reads++
      return () => 0
    }
  })
  const descriptorTrap = new Proxy(
    {},
    {
      getOwnPropertyDescriptor() {
        throw new Error('descriptor trap')
      }
    }
  )
  const hasTrap = new Proxy(
    {},
    {
      getOwnPropertyDescriptor() {
        return undefined
      },
      has() {
        throw new Error('has trap')
      }
    }
  )
  const revoked = Proxy.revocable({}, {})
  revoked.revoke()
  for (const options of [inherited, accessor, descriptorTrap, hasTrap, revoked.proxy, null, []]) {
    expectCode(t, () => new Reassembler(options), 'INVALID_ROUTE')
  }
  t.is(reads, 0)
})

test('message and aggregate ceilings are enforced before copying', (t) => {
  const small = receiver({ maxMessageBytes: MAX_FRAGMENT_DATA })
  expectCode(
    t,
    () => small.pushAuthenticated(frame(id(56), 0, 2, b4a.alloc(MAX_FRAGMENT_DATA))),
    'CIRCUIT_LIMIT'
  )
  t.is(small.stats.messages, 0)

  const aggregate = receiver()
  for (let i = 0; i < MAX_BUFFERED_FRAGMENTS; i++) {
    aggregate.pushAuthenticated(frame(id(60 + i), 0, 2, b4a.alloc(MAX_FRAGMENT_DATA, i)))
  }
  t.is(aggregate.stats.messages, 8)
  t.is(aggregate.stats.bufferedFragments, 8)
  t.is(aggregate.stats.bufferedEncodedBytes, MAX_ENCODED_MESSAGE_BYTES)
  expectCode(
    t,
    () => aggregate.pushAuthenticated(frame(id(80), 0, 2, b4a.alloc(MAX_FRAGMENT_DATA))),
    'CIRCUIT_LIMIT'
  )
  t.is(aggregate.stats.messages, 8)
})

test('max messages, fragments, and encoded bytes preserve admitted state on BUSY', (t) => {
  const a = fragment(b4a.alloc(MAX_FRAGMENT_DATA + 1, 1), { messageId: id(81) })
  const b = fragment(b4a.alloc(MAX_FRAGMENT_DATA + 1, 2), { messageId: id(82) })
  const cases = [
    { value: receiver({ maxMessages: 1 }), completes: true },
    { value: receiver({ maxBufferedFragments: 1 }), completes: false },
    { value: receiver({ maxBufferedEncodedBytes: 1073 }), completes: false }
  ]
  for (const { value: reassembler, completes } of cases) {
    reassembler.pushAuthenticated(a[0])
    expectCode(t, () => reassembler.pushAuthenticated(b[0]), 'CIRCUIT_LIMIT')
    t.is(reassembler.stats.messages, 1)
    if (completes) {
      t.alike(reassembler.pushAuthenticated(a[1]), b4a.alloc(MAX_FRAGMENT_DATA + 1, 1))
    } else {
      reassembler.destroy()
      t.is(reassembler.stats.messages, 0)
    }
  }
})

test('exact eight-fragment aggregate is visible before atomic completion', (t) => {
  const message = b4a.alloc(MAX_MESSAGE_DATA_BYTES, 0x6d)
  const frames = fragment(message, { messageId: id(83) })
  let observed = null
  let reassembler = null
  reassembler = receiver({
    [TEST_ONLY_FRAGMENT_OBSERVER]() {
      if (reassembler.stats.bufferedFragments === 8) observed = reassembler.stats
    }
  })
  for (let i = 0; i < 7; i++) reassembler.pushAuthenticated(frames[i])
  t.alike(reassembler.pushAuthenticated(frames[7]), message)
  t.is(observed.bufferedFragments, 8)
  t.is(observed.bufferedDataBytes, MAX_MESSAGE_DATA_BYTES)
  t.is(observed.bufferedEncodedBytes, MAX_ENCODED_MESSAGE_BYTES)
})

test('completed-ID ceiling of 64 never evicts and rejects before copy', (t) => {
  const reassembler = receiver()
  for (let i = 0; i < MAX_COMPLETED_IDS; i++) {
    const messageId = b4a.alloc(16)
    messageId[15] = i
    reassembler.pushAuthenticated(frame(messageId, 0, 1, b4a.from('x')))
  }
  t.is(reassembler.stats.completedIds, MAX_COMPLETED_IDS)

  let allocations = 0
  const allocate = b4a.allocUnsafeSlow
  b4a.allocUnsafeSlow = (size) => {
    allocations++
    return allocate(size)
  }
  try {
    expectCode(
      t,
      () => reassembler.pushAuthenticated(frame(id(0xff), 0, 1, b4a.from('y'))),
      'CIRCUIT_LIMIT'
    )
    expectCode(
      t,
      () => reassembler.pushAuthenticated(frame(id(0xfe), 0, 2, b4a.alloc(MAX_FRAGMENT_DATA))),
      'CIRCUIT_LIMIT'
    )
  } finally {
    b4a.allocUnsafeSlow = allocate
  }
  t.is(allocations, 0)
  expectCode(t, () => reassembler.pushAuthenticated(frame(b4a.alloc(16), 0, 1)), 'REPLAY')
})

test('tombstone exhaustion transactionally clears a completing affected message', (t) => {
  const reassembler = receiver({ maxCompletedIds: 1 })
  const pending = fragment(b4a.alloc(MAX_FRAGMENT_DATA + 1, 1), { messageId: id(84) })
  reassembler.pushAuthenticated(pending[0])
  reassembler.pushAuthenticated(fragment(b4a.from('done'), { messageId: id(85) })[0])
  expectCode(t, () => reassembler.pushAuthenticated(pending[1]), 'CIRCUIT_LIMIT')
  t.is(reassembler.stats.messages, 0)
  t.is(reassembler.stats.bufferedFragments, 0)
})

test('partial copy and completion allocation failures zero every affected owned buffer', (t) => {
  const accepted = []
  const reassembler = receiver({
    [TEST_ONLY_FRAGMENT_OBSERVER](value) {
      accepted.push(value)
    }
  })
  const frames = fragment(b4a.alloc(MAX_FRAGMENT_DATA + 2, 7), { messageId: id(86) })
  reassembler.pushAuthenticated(frames[0])
  const allocate = b4a.allocUnsafeSlow
  let partial = null
  b4a.allocUnsafeSlow = (size) => {
    if (size === 2) {
      partial = allocate(1)
      partial.fill(0xcc)
      return partial
    }
    return allocate(size)
  }
  try {
    expectCode(t, () => reassembler.pushAuthenticated(frames[1]), 'INVALID_ROUTE')
  } finally {
    b4a.allocUnsafeSlow = allocate
  }
  t.alike(partial, b4a.alloc(1))
  t.alike(accepted[0], b4a.alloc(accepted[0].byteLength))
  t.is(reassembler.stats.messages, 0)

  const assembled = []
  const other = receiver({
    [TEST_ONLY_FRAGMENT_OBSERVER](value) {
      assembled.push(value)
    }
  })
  const two = fragment(b4a.alloc(MAX_FRAGMENT_DATA + 1, 8), { messageId: id(87) })
  other.pushAuthenticated(two[0])
  b4a.allocUnsafeSlow = (size) => {
    if (size === MAX_FRAGMENT_DATA + 1) {
      const value = allocate(size - 1)
      value.fill(0xdd)
      return value
    }
    return allocate(size)
  }
  try {
    expectCode(t, () => other.pushAuthenticated(two[1]), 'INVALID_ROUTE')
  } finally {
    b4a.allocUnsafeSlow = allocate
  }
  for (const value of assembled) t.alike(value, b4a.alloc(value.byteLength))
  t.is(other.stats.messages, 0)
})

test('destroy is idempotent and clears every owned fragment', (t) => {
  const accepted = []
  const reassembler = receiver({
    [TEST_ONLY_FRAGMENT_OBSERVER](value) {
      accepted.push(value)
    }
  })
  const frames = fragment(b4a.alloc(MAX_FRAGMENT_DATA + 1), { messageId: id(88) })
  reassembler.pushAuthenticated(frames[0])
  reassembler.destroy()
  reassembler.destroy()
  t.alike(accepted[0], b4a.alloc(accepted[0].byteLength))
  t.is(reassembler.stats.destroyed, true)
  expectCode(t, () => reassembler.pushAuthenticated(frames[1]), 'CIRCUIT_STATE')
})

test('observer and clock reentrant destroy fail closed without returning payloads', (t) => {
  let observedOwned = null
  let observed = null
  observed = receiver({
    [TEST_ONLY_FRAGMENT_OBSERVER](value) {
      observedOwned = value
      observed.destroy()
    }
  })
  expectCode(
    t,
    () => observed.pushAuthenticated(fragment(b4a.from('secret'), { messageId: id(89) })[0]),
    'INVALID_ROUTE'
  )
  t.alike(observedOwned, b4a.alloc(observedOwned.byteLength))
  t.is(observed.stats.destroyed, true)

  let clocked = null
  clocked = receiver({
    now() {
      clocked.destroy()
      return 0
    }
  })
  expectCode(
    t,
    () => clocked.pushAuthenticated(frame(id(90), 0, 1, b4a.from('secret'))),
    'INVALID_ROUTE'
  )
  t.is(clocked.stats.destroyed, true)
  t.is(clocked.stats.completedIds, 0)
})

test('observer exceptions and nonmonotonic or exceptional clocks fail closed stably', (t) => {
  const observer = receiver({
    [TEST_ONLY_FRAGMENT_OBSERVER]() {
      throw new Error('observer sentinel')
    }
  })
  expectCode(
    t,
    () => observer.pushAuthenticated(frame(id(91), 0, 1, b4a.from('x'))),
    'INVALID_ROUTE'
  )
  t.is(observer.stats.destroyed, true)

  const exceptional = receiver({
    now() {
      throw new Error('clock sentinel')
    }
  })
  expectCode(
    t,
    () => exceptional.pushAuthenticated(frame(id(92), 0, 1, b4a.from('x'))),
    'INVALID_ROUTE'
  )
  t.is(exceptional.stats.destroyed, true)
})

test('observer and clock operation reentrancy fail closed', (t) => {
  let observed = null
  observed = receiver({
    [TEST_ONLY_FRAGMENT_OBSERVER]() {
      observed.pushAuthenticated(frame(id(94), 0, 1, b4a.from('nested')))
    }
  })
  expectCode(
    t,
    () => observed.pushAuthenticated(frame(id(95), 0, 1, b4a.from('outer'))),
    'INVALID_ROUTE'
  )
  t.is(observed.stats.destroyed, true)

  let clocked = null
  clocked = receiver({
    now() {
      clocked.expire(0)
      return 0
    }
  })
  expectCode(
    t,
    () => clocked.pushAuthenticated(frame(id(96), 0, 1, b4a.from('outer'))),
    'INVALID_ROUTE'
  )
  t.is(clocked.stats.destroyed, true)
})

test('caught observer and clock reentrancy still destroy and clear state', (t) => {
  let observedOwned = null
  let observed = null
  observed = receiver({
    [TEST_ONLY_FRAGMENT_OBSERVER](value) {
      observedOwned = value
      try {
        observed.expire(0)
      } catch {
        // The outer operation must notice the caught nested call.
      }
    }
  })
  expectCode(
    t,
    () => observed.pushAuthenticated(frame(id(97), 0, 1, b4a.from('outer'))),
    'INVALID_ROUTE'
  )
  t.is(observed.stats.destroyed, true)
  t.alike(observedOwned, b4a.alloc(observedOwned.byteLength))

  let clocked = null
  clocked = receiver({
    now() {
      try {
        clocked.pushAuthenticated(frame(id(98), 0, 1, b4a.from('nested')))
      } catch {
        // The outer operation must notice the caught nested call.
      }
      return 0
    }
  })
  expectCode(
    t,
    () => clocked.pushAuthenticated(frame(id(99), 0, 1, b4a.from('outer'))),
    'INVALID_ROUTE'
  )
  t.is(clocked.stats.destroyed, true)
  t.is(clocked.stats.messages, 0)
})

test('clock replacing Map.prototype.set cannot orphan an accepted fragment', (t) => {
  let poison = true
  let originalSet = null
  const owned = []
  const reassembler = receiver({
    now() {
      if (poison) {
        originalSet = Map.prototype.set
        Map.prototype.set = function () {
          return this
        }
      }
      return 0
    },
    [TEST_ONLY_FRAGMENT_OBSERVER](value) {
      owned.push(value)
    }
  })
  const frames = fragment(b4a.alloc(MAX_FRAGMENT_DATA + 1, 0x61), {
    messageId: id(100)
  })
  let first
  try {
    first = reassembler.pushAuthenticated(frames[0])
  } finally {
    Map.prototype.set = originalSet
  }
  t.is(first, null)
  t.is(reassembler.stats.messages, 1)
  t.is(reassembler.stats.bufferedFragments, 1)
  poison = false
  t.alike(reassembler.pushAuthenticated(frames[1]), b4a.alloc(MAX_FRAGMENT_DATA + 1, 0x61))
  t.alike(owned[0], b4a.alloc(owned[0].byteLength))
})

test('collection prototype mutation across clock and observer callbacks stays transactional', (t) => {
  const frames = fragment(b4a.alloc(MAX_FRAGMENT_DATA + 1, 0x62), {
    messageId: id(101)
  })
  let poisonClock = false
  let restore = null
  const owned = []
  const reassembler = receiver({
    now() {
      if (poisonClock) restore = poisonCollections()
      return 0
    },
    [TEST_ONLY_FRAGMENT_OBSERVER](value) {
      owned.push(value)
    }
  })
  reassembler.pushAuthenticated(frames[0])
  poisonClock = true
  let output
  try {
    output = reassembler.pushAuthenticated(frames[1])
  } finally {
    restore()
  }
  t.alike(output, b4a.alloc(MAX_FRAGMENT_DATA + 1, 0x62))
  for (const value of owned) t.alike(value, b4a.alloc(value.byteLength))

  let poisonObserver = false
  restore = null
  const observed = receiver({
    [TEST_ONLY_FRAGMENT_OBSERVER]() {
      if (poisonObserver) restore = poisonCollections()
    }
  })
  const observedFrames = fragment(b4a.alloc(MAX_FRAGMENT_DATA + 1, 0x63), {
    messageId: id(102)
  })
  observed.pushAuthenticated(observedFrames[0])
  poisonObserver = true
  try {
    output = observed.pushAuthenticated(observedFrames[1])
  } finally {
    restore()
  }
  t.alike(output, b4a.alloc(MAX_FRAGMENT_DATA + 1, 0x63))
})

test('collection prototype mutation cannot break replay, expiry, or destroy cleanup', (t) => {
  let mutate = false
  let restore = null
  let now = 0
  const expiredOwned = []
  const expiring = receiver({
    now() {
      if (mutate) restore = poisonCollections()
      return now
    },
    [TEST_ONLY_FRAGMENT_OBSERVER](value) {
      expiredOwned.push(value)
    }
  })
  const pending = fragment(b4a.alloc(MAX_FRAGMENT_DATA + 1), { messageId: id(103) })
  expiring.pushAuthenticated(pending[0])
  mutate = true
  now = MESSAGE_TIMEOUT
  let expired
  try {
    expired = expiring.expire()
  } finally {
    restore()
  }
  t.is(expired, 1)
  t.alike(expiredOwned[0], b4a.alloc(expiredOwned[0].byteLength))

  mutate = false
  const completed = receiver({
    now() {
      if (mutate) restore = poisonCollections()
      return 0
    }
  })
  const complete = fragment(b4a.from('done'), { messageId: id(104) })[0]
  completed.pushAuthenticated(complete)
  mutate = true
  let secondOutput
  try {
    secondOutput = completed.pushAuthenticated(
      fragment(b4a.from('second'), { messageId: id(106) })[0]
    )
  } finally {
    restore()
  }
  t.alike(secondOutput, b4a.from('second'))
  mutate = false
  expectCode(t, () => completed.pushAuthenticated(complete), 'REPLAY')

  const destroyedOwned = []
  const destroyed = receiver({
    [TEST_ONLY_FRAGMENT_OBSERVER](value) {
      destroyedOwned.push(value)
    }
  })
  destroyed.pushAuthenticated(fragment(b4a.alloc(MAX_FRAGMENT_DATA + 1), { messageId: id(105) })[0])
  restore = poisonCollections()
  try {
    destroyed.destroy()
  } finally {
    restore()
  }
  t.is(destroyed.stats.destroyed, true)
  t.alike(destroyedOwned[0], b4a.alloc(destroyedOwned[0].byteLength))
})

test('hostile, forged, revoked, and shadowed fragment buffers fail safely', (t) => {
  const forged = Object.create(Uint8Array.prototype)
  const revoked = Proxy.revocable(b4a.alloc(20), {})
  revoked.revoke()
  for (const value of [null, [], {}, forged, revoked.proxy]) {
    expectCode(t, () => receiver().pushAuthenticated(value), 'INVALID_ROUTE')
  }

  const valid = fragment(b4a.from('safe'), { messageId: id(93) })[0]
  let calls = 0
  const hostile = () => {
    calls++
    throw new Error('shadowed method')
  }
  Object.defineProperties(valid, {
    byteLength: { value: 0 },
    subarray: { value: hostile },
    set: { value: hostile },
    fill: { value: hostile }
  })
  t.alike(receiver().pushAuthenticated(valid), b4a.from('safe'))
  t.is(calls, 0)
})

test('test observer is deep-only and explicitly not an access-control boundary', (t) => {
  t.is(typeof TEST_ONLY_FRAGMENT_OBSERVER, 'symbol')
  t.comment('deep test hook observes owned buffers; it is not an access-control boundary')
})

test('300 deterministic generated valid and malformed fragment cases stay bounded', (t) => {
  const seed = 0x6d2b79f5
  const cases = 300
  let state = seed
  function random() {
    state ^= state << 13
    state ^= state >>> 17
    state ^= state << 5
    return state >>> 0
  }

  function generatedId(caseIndex, salt = 0) {
    const value = b4a.alloc(16)
    value[12] = caseIndex >>> 8
    value[13] = caseIndex
    value[14] = salt >>> 8
    value[15] = salt
    return value
  }

  t.comment(`base seed=${seed} generated cases=${cases}`)
  for (let caseIndex = 0; caseIndex < cases; caseIndex++) {
    const mode = caseIndex % 6
    const message = b4a.alloc(MAX_FRAGMENT_DATA + 1)
    for (let index = 0; index < message.length; index++) message[index] = random()
    const frames = fragment(message, { messageId: generatedId(caseIndex) })
    const reassembler = mode === 5 ? receiver({ maxMessageBytes: MAX_FRAGMENT_DATA }) : receiver()

    if (mode === 0) {
      const length = random() % (MAX_MESSAGE_DATA_BYTES + 1)
      const valid = b4a.alloc(length)
      for (let index = 0; index < valid.length; index++) valid[index] = random()
      const validFrames = fragment(valid, { messageId: generatedId(caseIndex, 1) })
      const order = Array.from({ length: validFrames.length }, (_, index) => index)
      for (let index = order.length - 1; index > 0; index--) {
        const at = random() % (index + 1)
        const swap = order[index]
        order[index] = order[at]
        order[at] = swap
      }
      let output = null
      let completions = 0
      for (const index of order) {
        const value = reassembler.pushAuthenticated(validFrames[index])
        if (value === null) continue
        output = value
        completions++
      }
      t.is(completions, 1, `case=${caseIndex} shuffled completion`)
      t.alike(output, valid, `case=${caseIndex} shuffled bytes`)
      t.ok(validFrames.length <= MAX_FRAGMENTS, `case=${caseIndex} fragment bound`)
      t.ok(
        totalEncoded(validFrames) <= MAX_ENCODED_MESSAGE_BYTES,
        `case=${caseIndex} encoded bound`
      )
    } else if (mode === 1) {
      reassembler.pushAuthenticated(frames[0])
      expectCode(t, () => reassembler.pushAuthenticated(b4a.from(frames[0])), 'REPLAY')
      t.is(reassembler.stats.messages, 1, `case=${caseIndex} duplicate preserves state`)
      t.alike(
        reassembler.pushAuthenticated(frames[1]),
        message,
        `case=${caseIndex} duplicate still completes`
      )
    } else if (mode === 2) {
      const other = fragment(message, { messageId: generatedId(caseIndex, 2) })
      reassembler.pushAuthenticated(frames[0])
      reassembler.pushAuthenticated(other[0])
      const conflict = b4a.from(frames[0])
      conflict[20] ^= 1
      expectCode(t, () => reassembler.pushAuthenticated(conflict), 'INVALID_ROUTE')
      t.is(reassembler.stats.messages, 1, `case=${caseIndex} conflict clears affected only`)
      t.alike(
        reassembler.pushAuthenticated(other[1]),
        message,
        `case=${caseIndex} unrelated conflict state completes`
      )
    } else if (mode === 3) {
      const outOfRange = b4a.from(frames[0])
      outOfRange[16] = outOfRange[18]
      outOfRange[17] = outOfRange[19]
      expectCode(t, () => reassembler.pushAuthenticated(outOfRange), 'INVALID_ROUTE')
      t.is(reassembler.stats.messages, 0, `case=${caseIndex} out-of-range retains nothing`)
    } else if (mode === 4) {
      const other = fragment(message, { messageId: generatedId(caseIndex, 3) })
      reassembler.pushAuthenticated(frames[0])
      reassembler.pushAuthenticated(other[0])
      const inconsistent = frame(generatedId(caseIndex), 1, 3, b4a.alloc(MAX_FRAGMENT_DATA))
      expectCode(t, () => reassembler.pushAuthenticated(inconsistent), 'INVALID_ROUTE')
      t.is(
        reassembler.stats.messages,
        1,
        `case=${caseIndex} inconsistent total clears affected only`
      )
      t.alike(
        reassembler.pushAuthenticated(other[1]),
        message,
        `case=${caseIndex} unrelated total state completes`
      )
    } else {
      expectCode(t, () => reassembler.pushAuthenticated(frames[0]), 'CIRCUIT_LIMIT')
      t.is(reassembler.stats.messages, 0, `case=${caseIndex} over-limit retains nothing`)
    }

    t.ok(
      reassembler.stats.bufferedFragments <= MAX_BUFFERED_FRAGMENTS,
      `case=${caseIndex} buffered fragment bound`
    )
    t.ok(
      reassembler.stats.bufferedEncodedBytes <= MAX_BUFFERED_ENCODED_BYTES,
      `case=${caseIndex} buffered byte bound`
    )
    reassembler.destroy()
    t.is(reassembler.stats.messages, 0, `case=${caseIndex} teardown messages`)
    t.is(reassembler.stats.bufferedEncodedBytes, 0, `case=${caseIndex} teardown bytes`)
  }
})
