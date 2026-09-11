'use strict'

const test = require('brittle')
const b4a = require('b4a')
const { Duplex, Writable, getStreamError } = require('streamx')
const SecretStream = require('@hyperswarm/secret-stream')

const NoiseWrap = require('../../lib/noise-wrap')
const { PrivateRouteError } = require('../../lib/private/errors')
const {
  PeerRecordAdapter,
  createPeerPlaintextDuplex
} = require('../../lib/private/peer-record-adapter')
const PREFIX_BYTES = 3
const HEADER_BODY_BYTES = 56
const SECRETSTREAM_ABYTES = 17
const MAX_BODY_BYTES = 0xffffff
const MAX_RAW_RECORD_BYTES = PREFIX_BYTES + MAX_BODY_BYTES
const MAX_PLAINTEXT_BYTES = MAX_BODY_BYTES - SECRETSTREAM_ABYTES
const MAX_DATA_FRAGMENT_BYTES = 977
const MAX_SETTLE_TURNS = 144

const INVALID_ROUTE = Object.freeze({
  constructor: PrivateRouteError,
  code: 'INVALID_ROUTE'
})
const AUTHENTICATION_ERROR = Object.freeze({
  constructor: PrivateRouteError,
  code: 'ERR_AUTHENTICATION'
})
const RECORDS_UNAVAILABLE = Object.freeze({
  constructor: PrivateRouteError,
  code: 'ERR_PRIVATE_RECORDS_UNAVAILABLE'
})
const QUOTA_ERROR = Object.freeze({
  constructor: PrivateRouteError,
  code: 'ERR_QUOTA_EXCEEDED'
})

function recordWeight() {
  return 1
}

function writeUint24LE(buffer, value) {
  buffer[0] = value
  buffer[1] = value >>> 8
  buffer[2] = value >>> 16
}

function headerRecord(value = 0x31) {
  const record = b4a.alloc(PREFIX_BYTES + HEADER_BODY_BYTES, value)
  writeUint24LE(record, HEADER_BODY_BYTES)
  return record
}

function applicationRecordOfSize(size, value = 0x41) {
  const bodyBytes = size + SECRETSTREAM_ABYTES
  const record = b4a.alloc(PREFIX_BYTES + bodyBytes, value)
  writeUint24LE(record, bodyBytes)
  return record
}

function applicationRecord(payload, value = 0x51) {
  const record = applicationRecordOfSize(payload.byteLength, value)
  b4a.copy(payload, record, PREFIX_BYTES + 1)
  return record
}

function prefixFor(bodyBytes) {
  const prefix = b4a.alloc(PREFIX_BYTES)
  writeUint24LE(prefix, bodyBytes)
  return prefix
}

function noop() {}

async function waitFor(predicate, label) {
  for (let turn = 0; turn < MAX_SETTLE_TURNS; turn++) {
    if (predicate()) return
    await Promise.resolve()
  }
  if (!predicate()) throw new Error('Did not settle: ' + label)
}

function readOne(stream) {
  return new Promise(function (resolve, reject) {
    let settled = false

    function cleanup() {
      stream.removeListener('readable', onReadable)
      stream.removeListener('end', onEnd)
      stream.removeListener('error', onError)
      stream.removeListener('close', onClose)
    }

    function finish(error, value) {
      if (settled) return
      settled = true
      cleanup()
      if (error) reject(error)
      else resolve(value)
    }

    function onReadable() {
      const value = stream.read()
      if (value !== null) finish(null, value)
    }

    function onEnd() {
      finish(null, null)
    }

    function onError(error) {
      finish(error)
    }

    function onClose() {
      if (!settled) finish(new Error('Stream closed before a record was readable'))
    }

    stream.on('readable', onReadable)
    stream.on('end', onEnd)
    stream.on('error', onError)
    stream.on('close', onClose)

    const value = stream.read()
    if (value !== null) finish(null, value)
  })
}

function onceEvent(stream, name) {
  return new Promise(function (resolve, reject) {
    function cleanup() {
      stream.removeListener(name, onEvent)
      if (name !== 'error') stream.removeListener('error', onError)
    }
    function onEvent(value) {
      cleanup()
      resolve(value)
    }
    function onError(error) {
      cleanup()
      reject(error)
    }
    stream.once(name, onEvent)
    if (name !== 'error') stream.once('error', onError)
  })
}

function onceClose(stream) {
  return new Promise(function (resolve) {
    stream.once('close', resolve)
  })
}

class DeferredScheduler {
  constructor() {
    this.tasks = []
  }

  defer(callback) {
    const task = { callback, cancelled: false, fired: false }
    this.tasks.push(task)
    return function cancel() {
      task.cancelled = true
    }
  }

  get pending() {
    let count = 0
    for (const task of this.tasks) {
      if (!task.cancelled && !task.fired) count++
    }
    return count
  }

  flushOne() {
    for (const task of this.tasks) {
      if (task.cancelled || task.fired) continue
      task.fired = true
      task.callback()
      return true
    }
    return false
  }

  flushAll() {
    while (this.flushOne()) {}
  }
}

function createHarness(overrides = {}) {
  const scheduler = overrides.scheduler || new DeferredScheduler()
  const state = {
    outboundRecords: [],
    inboundAcquires: [],
    inboundReleases: [],
    outboundAcquires: [],
    outboundReleases: [],
    inboundCapacity: 0,
    failures: [],
    errors: []
  }

  const adapter = new PeerRecordAdapter({
    onOutboundRecord(record) {
      state.outboundRecords.push(record)
      if (overrides.onOutboundRecord) return overrides.onOutboundRecord(record, state)
    },
    onInboundCapacity() {
      state.inboundCapacity++
      if (overrides.onInboundCapacity) overrides.onInboundCapacity(state)
    },
    onFailure(error) {
      state.failures.push(error)
      if (overrides.onFailure) overrides.onFailure(error, state)
    },
    defer(callback) {
      return scheduler.defer(callback)
    },
    acquireInbound(rawBytes, kind) {
      state.inboundAcquires.push({ rawBytes, kind })
      if (overrides.acquireInbound) overrides.acquireInbound(rawBytes, kind, state)
    },
    releaseInbound(rawBytes, kind) {
      state.inboundReleases.push({ rawBytes, kind })
      if (overrides.releaseInbound) overrides.releaseInbound(rawBytes, kind, state)
    },
    acquireOutbound(rawBytes, kind) {
      state.outboundAcquires.push({ rawBytes, kind })
      if (overrides.acquireOutbound) overrides.acquireOutbound(rawBytes, kind, state)
    },
    releaseOutbound(rawBytes, kind) {
      state.outboundReleases.push({ rawBytes, kind })
      if (overrides.releaseOutbound) overrides.releaseOutbound(rawBytes, kind, state)
    }
  })
  adapter.on('error', function (error) {
    state.errors.push(error)
  })
  return { adapter, scheduler, state }
}

class FakeSecretStream extends Duplex {
  constructor(rawStream, options = {}) {
    super({
      highWaterMark: 0,
      byteLengthReadable: recordWeight,
      byteLengthWritable: recordWeight
    })
    this.rawStream = rawStream
    this.opened = options.opened || Promise.resolve(true)
    this.keepAlive = 0
    this.copyPlaintext = options.copyPlaintext === true
    this.inboundRecords = []
    this.writeInputs = []
    this.destroyInvocations = 0
    this.destroyExecutions = 0

    this._onRawDataBound = this._onRawData.bind(this)
    this._onRawEndBound = this._onRawEnd.bind(this)
    this._onRawErrorBound = this._onRawError.bind(this)
    rawStream.on('data', this._onRawDataBound)
    rawStream.on('end', this._onRawEndBound)
    rawStream.on('error', this._onRawErrorBound)

    if (options.outboundHeader !== false) rawStream.write(headerRecord(0x71))
  }

  flush() {
    return Writable.drained(this).then((drained) => {
      if (!drained) return false
      return this.rawStream.flush()
    })
  }

  destroy(error) {
    this.destroyInvocations++
    super.destroy(error)
    return this
  }

  _read(callback) {
    this.rawStream.resume()
    callback(null)
  }

  _write(data, callback) {
    this.writeInputs.push(data)
    const record = applicationRecord(data, 0x61)
    this.rawStream.write(record)
    this.rawStream.flush().then(
      (drained) => callback(drained ? null : new Error('Raw stream did not drain')),
      callback
    )
  }

  _final(callback) {
    this.rawStream.end()
    callback(null)
  }

  _predestroy() {
    const error = getStreamError(this)
    if (!this.rawStream.destroying && !this.rawStream.destroyed) this.rawStream.destroy(error)
  }

  _destroy(callback) {
    this.destroyExecutions++
    this.rawStream.removeListener('data', this._onRawDataBound)
    this.rawStream.removeListener('end', this._onRawEndBound)
    this.rawStream.removeListener('error', this._onRawErrorBound)
    callback(null)
  }

  _onRawData(record) {
    const index = this.inboundRecords.length
    this.inboundRecords.push(record)
    if (index === 0) return

    let plain = record.subarray(PREFIX_BYTES + 1, record.byteLength - (SECRETSTREAM_ABYTES - 1))
    if (this.copyPlaintext) plain = b4a.from(plain)
    if (this.push(plain) === false) this.rawStream.pause()
  }

  _onRawEnd() {
    this.push(null)
  }

  _onRawError(error) {
    if (!this.destroying && !this.destroyed) this.destroy(error)
  }
}

class HoldingSink extends Writable {
  constructor() {
    super({ highWaterMark: 1, byteLengthWritable: recordWeight })
    this.records = []
    this.callbacks = []
    this.on('error', noop)
  }

  _write(data, callback) {
    this.records.push(data)
    this.callbacks.push(callback)
  }

  _predestroy() {
    while (this.callbacks.length > 0) this.callbacks.shift()(new Error('Sink destroyed'))
  }

  _destroy(callback) {
    callback(null)
  }
}

function createBound(options = {}) {
  const harness = createHarness(options.adapter || {})
  const secret = new FakeSecretStream(harness.adapter, options.secret || {})
  const facade = createPeerPlaintextDuplex(secret, harness.adapter)
  const facadeErrors = []
  facade.on('error', function (error) {
    facadeErrors.push(error)
  })
  return { ...harness, secret, facade, facadeErrors }
}

function teardownAdapter(t, harness) {
  t.teardown(function () {
    harness.adapter.destroy()
  })
}

function teardownBound(t, bound) {
  t.teardown(function () {
    bound.facade.destroy()
    bound.secret.destroy()
    bound.adapter.destroy()
  })
}

async function primeInboundHeader(bound) {
  const before = bound.secret.inboundRecords.length
  const header = headerRecord(0x22)
  const consumed = bound.adapter.consumeCiphertext(header)
  if (consumed !== header.byteLength) throw new Error('Header was not consumed atomically')
  await waitFor(
    function () {
      return bound.secret.inboundRecords.length === before + 1
    },
    'inbound header delivery'
  )
  await waitFor(
    function () {
      return bound.state.inboundReleases.some(function (entry) {
        return entry.kind === 'header'
      })
    },
    'inbound header release'
  )
}

function feedRecord(adapter, record) {
  let offset = 0
  while (offset < record.byteLength) {
    const end = Math.min(record.byteLength, offset + MAX_DATA_FRAGMENT_BYTES)
    const consumed = adapter.consumeCiphertext(record.subarray(offset, end))
    if (consumed <= 0) throw new Error('Record admission became blocked while assembling one record')
    offset += consumed
  }
  return offset
}

test('PeerRecordAdapter requires the exact eight own callback fields', async function (t) {
  const harness = createHarness()
  teardownAdapter(t, harness)
  t.ok(harness.adapter instanceof PeerRecordAdapter)

  const inherited = Object.create({
    onOutboundRecord: noop,
    onInboundCapacity: noop,
    onFailure: noop,
    defer: function () {
      return noop
    },
    acquireInbound: noop,
    releaseInbound: noop,
    acquireOutbound: noop,
    releaseOutbound: noop
  })
  await t.exception(function () {
    return new PeerRecordAdapter(inherited)
  }, INVALID_ROUTE)

  const exact = {
    onOutboundRecord: noop,
    onInboundCapacity: noop,
    onFailure: noop,
    defer: function () {
      return noop
    },
    acquireInbound: noop,
    releaseInbound: noop,
    acquireOutbound: noop,
    releaseOutbound: noop,
    extra: noop
  }
  await t.exception(function () {
    return new PeerRecordAdapter(exact)
  }, INVALID_ROUTE)
})

test('inbound prefix 1+1+1 validates before slot acquisition and allocation', async function (t) {
  const harness = createHarness()
  teardownAdapter(t, harness)
  const records = []
  harness.adapter.on('data', function (record) {
    records.push(record)
  })

  const header = headerRecord(0x33)
  t.is(harness.adapter.consumeCiphertext(header.subarray(0, 1)), 1)
  t.is(harness.state.inboundAcquires.length, 0)
  t.is(harness.adapter.consumeCiphertext(header.subarray(1, 2)), 1)
  t.is(harness.state.inboundAcquires.length, 0)
  t.is(harness.adapter.consumeCiphertext(header.subarray(2, 3)), 1)
  t.alike(harness.state.inboundAcquires, [{ rawBytes: 59, kind: 'header' }])
  t.is(harness.adapter.consumeCiphertext(header.subarray(3)), HEADER_BODY_BYTES)

  await waitFor(function () {
    return records.length === 1 && harness.state.inboundReleases.length === 1
  }, 'fragmented header consumption')
  t.alike(records[0], header)
  t.not(records[0].buffer, header.buffer, 'adapter owns a fresh backing')
  t.is(harness.state.inboundCapacity, 0, 'capacity callback is deferred')
  t.is(harness.scheduler.pending, 1, 'only one capacity callback is queued')
  harness.scheduler.flushAll()
  t.is(harness.state.inboundCapacity, 1)
})

test('malformed first and application lengths fail before a new slot is acquired', async function (t) {
  const first = createHarness()
  teardownAdapter(t, first)
  await t.exception(function () {
    return first.adapter.consumeCiphertext(prefixFor(HEADER_BODY_BYTES - 1))
  }, AUTHENTICATION_ERROR)
  t.is(first.state.inboundAcquires.length, 0)
  t.is(first.state.failures.length, 1)

  const later = createBound({ secret: { outboundHeader: false } })
  teardownBound(t, later)
  await primeInboundHeader(later)
  const acquiredBefore = later.state.inboundAcquires.length
  await t.exception(function () {
    return later.adapter.consumeCiphertext(prefixFor(SECRETSTREAM_ABYTES - 1))
  }, AUTHENTICATION_ERROR)
  t.is(later.state.inboundAcquires.length, acquiredBefore)
  t.is(later.secret.inboundRecords.length, 1, 'malformed body never reaches the parser')
})

test('complete records reach the raw consumer once and application plaintext keeps the same backing', async function (t) {
  const bound = createBound({ secret: { outboundHeader: false } })
  teardownBound(t, bound)
  await primeInboundHeader(bound)

  const reading = readOne(bound.facade)
  const payload = b4a.from('same backing')
  const incoming = applicationRecord(payload)
  t.is(bound.adapter.consumeCiphertext(incoming), incoming.byteLength)
  const plain = await reading
  const ownedRaw = bound.secret.inboundRecords[1]

  t.alike(plain, payload)
  t.is(plain.buffer, ownedRaw.buffer)
  t.is(plain.byteOffset, ownedRaw.byteOffset + PREFIX_BYTES + 1)
  t.is(plain.byteLength, payload.byteLength)
  t.not(ownedRaw.buffer, incoming.buffer, 'producer backing was not borrowed as endpoint storage')
})

test('record-boundary crossing returns a charged remainder until the facade transfers ownership', async function (t) {
  const bound = createBound({ secret: { outboundHeader: false } })
  teardownBound(t, bound)
  await primeInboundHeader(bound)

  const firstPayload = b4a.from([0xa1])
  const secondPayload = b4a.from([0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7])
  const firstRecord = applicationRecord(firstPayload)
  const secondRecord = applicationRecord(secondPayload)
  const frame = b4a.concat([firstRecord, secondRecord])

  const firstReading = readOne(bound.facade)
  const firstConsumed = bound.adapter.consumeCiphertext(frame)
  t.is(firstConsumed, firstRecord.byteLength)
  const firstPlain = await firstReading
  const retained = b4a.from(firstPlain)

  t.is(bound.adapter.consumeCiphertext(frame.subarray(firstConsumed)), 0)
  t.is(
    bound.state.inboundAcquires.filter(function (entry) {
      return entry.kind === 'application'
    }).length,
    1
  )

  const secondReading = readOne(bound.facade)
  await waitFor(function () {
    return bound.state.inboundReleases.filter(function (entry) {
      return entry.kind === 'application'
    }).length === 1
  }, 'first plaintext ownership transfer')

  const secondConsumed = bound.adapter.consumeCiphertext(frame.subarray(firstConsumed))
  t.is(secondConsumed, secondRecord.byteLength)
  const secondPlain = await secondReading
  t.alike(secondPlain, secondPayload)
  t.alike(firstPlain, retained, 'caller-retained bytes remain unchanged')
  t.not(firstPlain.buffer, secondPlain.buffer, 'successive records have fresh backing stores')
})

test('zero, tiny, and maximum inbound records retain per-record weight and exact backing', async function (t) {
  const bound = createBound({ secret: { outboundHeader: false } })
  teardownBound(t, bound)
  await primeInboundHeader(bound)

  const zeroReading = readOne(bound.facade)
  const zeroRecord = applicationRecordOfSize(0, 0x72)
  t.is(feedRecord(bound.adapter, zeroRecord), zeroRecord.byteLength)
  const zero = await zeroReading
  t.is(zero.byteLength, 0)
  t.is(zero.buffer.byteLength, zeroRecord.byteLength)

  const tinyReading = readOne(bound.facade)
  await waitFor(function () {
    return bound.state.inboundReleases.filter(function (entry) {
      return entry.kind === 'application'
    }).length === 1
  }, 'zero-record ownership transfer')

  const tinyRecord = applicationRecordOfSize(1, 0x73)
  t.is(feedRecord(bound.adapter, tinyRecord), tinyRecord.byteLength)
  const tiny = await tinyReading
  t.is(tiny.byteLength, 1)
  t.is(tiny[0], 0x73)
  t.not(tiny.buffer, zero.buffer)

  const maxReading = readOne(bound.facade)
  await waitFor(function () {
    return bound.state.inboundReleases.filter(function (entry) {
      return entry.kind === 'application'
    }).length === 2
  }, 'tiny-record ownership transfer')

  const maximum = applicationRecordOfSize(MAX_PLAINTEXT_BYTES, 0x6d)
  t.is(maximum.byteLength, MAX_RAW_RECORD_BYTES)
  t.is(feedRecord(bound.adapter, maximum), MAX_RAW_RECORD_BYTES)
  const plain = await maxReading
  t.is(plain.byteLength, MAX_PLAINTEXT_BYTES)
  t.is(plain[0], 0x6d)
  t.is(plain[plain.byteLength - 1], 0x6d)
  t.is(plain.buffer, bound.secret.inboundRecords[3].buffer)
  t.not(plain.buffer, zero.buffer)
  t.not(plain.buffer, tiny.buffer)
})

test('capacity notification is deferred until the caller records a boundary offset', async function (t) {
  let frame = null
  let outerReturned = false
  let firstConsumed = 0
  let callbackConsumed = 0
  const harness = createHarness({
    onInboundCapacity() {
      t.is(outerReturned, true, 'outer DATA drain updated its offset first')
      callbackConsumed = harness.adapter.consumeCiphertext(frame.subarray(firstConsumed))
    }
  })
  teardownAdapter(t, harness)
  harness.adapter.on('data', noop)

  const header = headerRecord(0x42)
  const application = applicationRecordOfSize(1, 0x52)
  frame = b4a.concat([header, application])
  firstConsumed = harness.adapter.consumeCiphertext(frame)
  outerReturned = true
  t.is(firstConsumed, header.byteLength)

  await waitFor(function () {
    return harness.scheduler.pending === 1
  }, 'deferred capacity task')
  t.is(callbackConsumed, 0)
  harness.scheduler.flushOne()
  t.is(callbackConsumed, application.byteLength)
  t.is(harness.state.inboundCapacity, 1)
})

test('blocked pipe retention remains stable after fresh admission and terminal destroy', async function (t) {
  const bound = createBound({ secret: { outboundHeader: false } })
  teardownBound(t, bound)
  const sink = new HoldingSink()
  t.teardown(function () {
    sink.destroy()
  })
  await primeInboundHeader(bound)
  bound.facade.pipe(sink)
  bound.facade.resume()

  const firstRecord = applicationRecord(b4a.from('blocked sink payload'))
  t.is(feedRecord(bound.adapter, firstRecord), firstRecord.byteLength)
  await waitFor(function () {
    return sink.records.length === 1
  }, 'blocked sink write')
  const retained = sink.records[0]
  const expected = b4a.from(retained)

  await waitFor(function () {
    return bound.state.inboundReleases.filter(function (entry) {
      return entry.kind === 'application'
    }).length === 1
  }, 'capacity transfer while sink callback is pending')
  t.is(sink.callbacks.length, 1)

  const secondRecord = applicationRecord(b4a.from('fresh second payload'))
  t.is(feedRecord(bound.adapter, secondRecord), secondRecord.byteLength)
  await waitFor(function () {
    return bound.secret.inboundRecords.length === 3
  }, 'fresh record reaches SecretStream')
  t.alike(retained, expected)
  t.not(retained.buffer, bound.secret.inboundRecords[2].buffer)

  bound.facade.destroy(new Error('terminal test destroy'))
  t.alike(retained, expected, 'destroy never erases caller-visible backing')
})

test('destroy from inside a data callback never erases the delivered plaintext', async function (t) {
  const bound = createBound({ secret: { outboundHeader: false } })
  teardownBound(t, bound)
  await primeInboundHeader(bound)

  let retained = null
  let expected = null
  let failureCount = 0
  const originalFailures = bound.state.failures
  bound.state.failures = new Proxy(originalFailures, {
    set(target, prop, value) {
      if (prop !== 'length') failureCount++
      target[prop] = value
      return true
    }
  })

  bound.facade.on('data', function (data) {
    retained = data
    expected = b4a.from(data)
    bound.facade.destroy(new Error('destroyed inside data callback'))
  })

  const record = applicationRecord(b4a.from('visible during destroy'))
  t.is(feedRecord(bound.adapter, record), record.byteLength)
  await waitFor(function () {
    return retained !== null && bound.state.failures.length === 1
  }, 'destroy from data callback')
  t.alike(retained, expected)
  t.is(bound.state.inboundReleases.filter(function (entry) {
    return entry.kind === 'application'
  }).length, 1)
  t.is(bound.state.failures.length, 1, 'failure callback called exactly once')
  t.is(failureCount, 1, 'no duplicate failure invocation occurred')
})

test('destroy from inside an end callback never causes duplicate read callback or failure', async function (t) {
  const bound = createBound({ secret: { outboundHeader: false } })
  teardownBound(t, bound)
  await primeInboundHeader(bound)

  let endSeen = false
  let failureCount = 0
  const originalFailures = bound.state.failures
  bound.state.failures = new Proxy(originalFailures, {
    set(target, prop, value) {
      if (prop !== 'length') failureCount++
      target[prop] = value
      return true
    }
  })

  bound.facade.on('end', function () {
    endSeen = true
    bound.facade.destroy(new Error('destroyed inside end callback'))
  })
  bound.facade.resume()

  t.is(bound.adapter.endCiphertext(), true)
  await waitFor(function () {
    return endSeen && bound.state.failures.length === 1
  }, 'destroy from end callback')
  t.is(bound.state.failures.length, 1, 'failure callback called exactly once on end teardown')
  t.is(failureCount, 1, 'no duplicate failure invocation on end teardown')
})

test('outbound raw records are borrowed serially and each slot releases once', async function (t) {
  const harness = createHarness()
  teardownAdapter(t, harness)
  const header = headerRecord(0x81)
  const application = applicationRecordOfSize(7, 0x82)

  t.is(harness.adapter.write(header), false)
  t.is(await harness.adapter.flush(), true)
  t.is(harness.adapter.write(application), false)
  t.is(await harness.adapter.flush(), true)

  t.is(harness.state.outboundRecords[0], header)
  t.is(harness.state.outboundRecords[1], application)
  t.alike(harness.state.outboundAcquires, [
    { rawBytes: 59, kind: 'header' },
    { rawBytes: application.byteLength, kind: 'application' }
  ])
  t.alike(harness.state.outboundReleases, harness.state.outboundAcquires)
})

test('destroy rejects a pending raw transfer and ignores its late completion', async function (t) {
  let completeTransfer = null
  const transfer = new Promise(function (resolve) {
    completeTransfer = resolve
  })
  const harness = createHarness({
    onOutboundRecord() {
      return transfer
    }
  })
  teardownAdapter(t, harness)

  const closed = onceClose(harness.adapter)
  harness.adapter.write(headerRecord(0x91))
  await waitFor(function () {
    return harness.state.outboundRecords.length === 1
  }, 'pending outbound publication')
  harness.adapter.destroy(new Error('revoked while pending'))
  await closed

  t.is(harness.state.outboundReleases.length, 1)
  t.is(harness.state.failures.length, 1)
  completeTransfer()
  await Promise.resolve()
  await Promise.resolve()
  t.is(harness.state.outboundReleases.length, 1, 'late completion cannot release reused capacity')
  t.is(harness.state.outboundRecords.length, 1, 'late completion cannot publish')
})

test('thrown and rejected outbound callbacks release once and fail once', async function (t) {
  const thrown = createHarness({
    onOutboundRecord() {
      throw new Error('synchronous transfer failure')
    }
  })
  teardownAdapter(t, thrown)
  const thrownClosed = onceClose(thrown.adapter)
  thrown.adapter.write(headerRecord(0xa1))
  await thrownClosed
  t.is(thrown.state.outboundReleases.length, 1)
  t.is(thrown.state.failures.length, 1)

  const rejected = createHarness({
    onOutboundRecord() {
      return Promise.reject(new Error('asynchronous transfer failure'))
    }
  })
  teardownAdapter(t, rejected)
  const rejectedClosed = onceClose(rejected.adapter)
  rejected.adapter.write(headerRecord(0xa2))
  await rejectedClosed
  t.is(rejected.state.outboundReleases.length, 1)
  t.is(rejected.state.failures.length, 1)
})

test('plaintext writes accept the exact maximum and reject one byte more before encryption', async function (t) {
  const maximum = createBound()
  teardownBound(t, maximum)
  t.is(await maximum.adapter.flush(), true, 'outbound header transferred')

  const maxPlaintext = b4a.alloc(MAX_PLAINTEXT_BYTES, 0x4d)
  t.is(maximum.facade.write(maxPlaintext), false)
  t.is(await Writable.drained(maximum.facade), true)
  t.is(maximum.secret.writeInputs.length, 1)
  t.is(maximum.secret.writeInputs[0], maxPlaintext, 'facade preserves borrowed plaintext identity')
  t.is(maximum.state.outboundRecords[1].byteLength, MAX_RAW_RECORD_BYTES)

  const oversized = createBound()
  teardownBound(t, oversized)
  t.is(await oversized.adapter.flush(), true, 'second outbound header transferred')
  const error = onceEvent(oversized.facade, 'error')
  oversized.facade.write(b4a.alloc(MAX_PLAINTEXT_BYTES + 1))
  const rejected = await error
  t.is(rejected instanceof PrivateRouteError, true)
  t.is(rejected.code, QUOTA_ERROR.code)
  t.is(oversized.secret.writeInputs.length, 0, 'oversized plaintext never reaches SecretStream.write')
})

test('copied or offset-shifted plaintext fails the ownership binding', async function (t) {
  const bound = createBound({
    secret: { outboundHeader: false, copyPlaintext: true }
  })
  teardownBound(t, bound)
  await primeInboundHeader(bound)

  const reading = readOne(bound.facade)
  const record = applicationRecord(b4a.from('must stay in place'))
  t.is(feedRecord(bound.adapter, record), record.byteLength)
  await t.exception(reading, RECORDS_UNAVAILABLE)
  t.is(bound.state.failures.length, 1)
  t.is(bound.state.inboundReleases.filter(function (entry) {
    return entry.kind === 'application'
  }).length, 1)
})

test('binding is exact, private to one SecretStream/raw pair, and one-shot', async function (t) {
  const harness = createHarness()
  teardownAdapter(t, harness)
  const foreignRaw = createHarness()
  teardownAdapter(t, foreignRaw)
  const wrong = new FakeSecretStream(foreignRaw.adapter, { outboundHeader: false })
  wrong.on('error', noop)
  t.teardown(function () {
    wrong.destroy()
  })

  await t.exception(function () {
    return createPeerPlaintextDuplex(wrong, harness.adapter)
  }, INVALID_ROUTE)

  const secret = new FakeSecretStream(harness.adapter, { outboundHeader: false })
  secret.on('error', noop)
  t.teardown(function () {
    secret.destroy()
  })
  const facade = createPeerPlaintextDuplex(secret, harness.adapter)
  facade.on('error', noop)
  t.teardown(function () {
    facade.destroy()
  })
  await t.exception(function () {
    return createPeerPlaintextDuplex(secret, harness.adapter)
  }, INVALID_ROUTE)
})

test('endCiphertext accepts exact boundaries and rejects truncated prefix or body', async function (t) {
  const boundary = createHarness()
  teardownAdapter(t, boundary)
  boundary.adapter.resume()
  t.is(boundary.adapter.endCiphertext(), true)
  t.is(boundary.adapter.endCiphertext(), false)

  const prefix = createHarness()
  teardownAdapter(t, prefix)
  t.is(prefix.adapter.consumeCiphertext(b4a.from([HEADER_BODY_BYTES])), 1)
  await t.exception(function () {
    return prefix.adapter.endCiphertext()
  }, AUTHENTICATION_ERROR)
  t.is(prefix.state.inboundAcquires.length, 0)

  const body = createHarness()
  teardownAdapter(t, body)
  const partial = headerRecord(0xb1).subarray(0, PREFIX_BYTES + 1)
  t.is(body.adapter.consumeCiphertext(partial), partial.byteLength)
  await t.exception(function () {
    return body.adapter.endCiphertext()
  }, AUTHENTICATION_ERROR)
  t.alike(body.state.inboundAcquires, [{ rawBytes: 59, kind: 'header' }])
  t.alike(body.state.inboundReleases, [{ rawBytes: 59, kind: 'header' }])
})

test('remote ciphertext EOF ends only facade readable and reverse writes still drain', async function (t) {
  const bound = createBound()
  teardownBound(t, bound)
  const facadeClosed = onceClose(bound.facade)
  const secretClosed = onceClose(bound.secret)
  const adapterClosed = onceClose(bound.adapter)
  await bound.adapter.flush()
  await primeInboundHeader(bound)

  const ended = onceEvent(bound.facade, 'end')
  bound.facade.resume()
  t.is(bound.adapter.endCiphertext(), true)
  await ended

  const reverse = b4a.from('reverse after incoming EOF')
  t.is(bound.facade.write(reverse), false)
  t.is(await Writable.drained(bound.facade), true)
  t.is(bound.secret.writeInputs.at(-1), reverse)
  t.is(bound.state.failures.length, 0)

  const finished = onceEvent(bound.facade, 'finish')
  bound.facade.end()
  await finished
  await facadeClosed
  await secretClosed
  await adapterClosed
  t.is(bound.state.failures.length, 0, 'graceful two-half completion is not a failure')
})

test('local facade end leaves the readable half able to receive later plaintext', async function (t) {
  const bound = createBound()
  teardownBound(t, bound)
  await bound.adapter.flush()

  const finished = onceEvent(bound.facade, 'finish')
  bound.facade.end()
  await finished
  t.is(bound.state.failures.length, 0)

  await primeInboundHeader(bound)
  const reading = readOne(bound.facade)
  const payload = b4a.from('arrived after local finish')
  const record = applicationRecord(payload)
  t.is(feedRecord(bound.adapter, record), record.byteLength)
  t.alike(await reading, payload)
  t.is(bound.state.failures.length, 0)
})

test('terminal teardown rejects pending facade work once and late open cannot publish', async function (t) {
  let resolveOpened = null
  const opened = new Promise(function (resolve) {
    resolveOpened = resolve
  })
  const bound = createBound({
    secret: { outboundHeader: false, opened }
  })
  teardownBound(t, bound)

  bound.facade.read()
  bound.facade.write(b4a.from('waiting for open'))
  await Promise.resolve()
  await Promise.resolve()

  const closed = onceClose(bound.facade)
  bound.facade.destroy(new Error('terminal facade destroy'))
  await closed
  t.is(bound.state.failures.length, 1)
  t.is(bound.secret.destroyInvocations, 1)

  resolveOpened(true)
  await Promise.resolve()
  await Promise.resolve()
  t.is(bound.secret.writeInputs.length, 0, 'late open cannot publish plaintext')
  t.is(bound.state.failures.length, 1, 'failure callback stays exactly once')
})

function createRealNativePair(adapterOverrides = {}) {
  const harness = createHarness(adapterOverrides)
  const keyA = SecretStream.keyPair()
  const keyB = SecretStream.keyPair()
  const wrapA = new NoiseWrap(keyA, keyB.publicKey)
  const wrapB = new NoiseWrap(keyB)
  const payload = { error: 0, firewall: 0 }
  const req = wrapA.send(payload)
  wrapB.recv(req)
  const rep = wrapB.send(payload)
  wrapA.recv(rep)

  const peerOutbound = []
  const rawA = new Duplex({
    highWaterMark: 0,
    byteLengthReadable: recordWeight,
    byteLengthWritable: recordWeight,
    read(cb) {
      cb(null)
    },
    write(data, cb) {
      peerOutbound.push(data)
      cb(null)
    }
  })

  const peer = new SecretStream(true, rawA, { handshake: wrapA.final() })
  const secret = new SecretStream(false, harness.adapter, { handshake: wrapB.final() })
  const facade = createPeerPlaintextDuplex(secret, harness.adapter)
  const facadeErrors = []
  facade.on('error', (error) => facadeErrors.push(error))

  return { ...harness, peer, secret, rawA, facade, facadeErrors, peerOutbound }
}

async function openRealNativePair(pair) {
  await waitFor(function () {
    return pair.peerOutbound.length >= 1
  }, 'peer outbound header')
  const headerA = pair.peerOutbound[0]
  const consumedA = pair.adapter.consumeCiphertext(headerA)
  if (consumedA !== headerA.byteLength) throw new Error('Peer header was not consumed atomically')

  await waitFor(function () {
    return pair.state.outboundRecords.length >= 1
  }, 'secret outbound header')
  const headerB = pair.state.outboundRecords[0]
  pair.rawA.push(headerB)

  await Promise.all([pair.peer.opened, pair.secret.opened])
  await waitFor(function () {
    return pair.state.inboundReleases.some(function (entry) {
      return entry.kind === 'header'
    })
  }, 'inbound header released')
}

function teardownNativePair(t, pair) {
  t.teardown(function () {
    pair.facade.destroy()
    pair.secret.destroy()
    pair.peer.destroy()
    pair.rawA.destroy()
    pair.adapter.destroy()
  })
}

async function sendPeerToFacade(pair, plaintext) {
  const beforeLen = pair.peerOutbound.length
  pair.peer.write(plaintext)
  await pair.peer.flush()
  await waitFor(function () {
    return pair.peerOutbound.length > beforeLen
  }, 'peer application record emitted')
  const rawRecord = pair.peerOutbound[beforeLen]
  const consumed = feedRecord(pair.adapter, rawRecord)
  if (consumed !== rawRecord.byteLength) throw new Error('Application record was not consumed atomically')
  return rawRecord
}

async function sendFacadeToPeer(pair, plaintext) {
  const beforeOutbound = pair.state.outboundRecords.length
  pair.facade.write(plaintext)
  await Writable.drained(pair.facade)
  await waitFor(function () {
    return pair.state.outboundRecords.length > beforeOutbound
  }, 'facade outbound record emitted')
  const rawRecord = pair.state.outboundRecords[beforeOutbound]
  pair.rawA.push(rawRecord)
  return rawRecord
}

test('native SecretStream + NoiseWrap handshake establishes real 59-byte header exchange through PeerRecordAdapter', async function (t) {
  const pair = createRealNativePair()
  teardownNativePair(t, pair)
  await openRealNativePair(pair)

  t.is(pair.peerOutbound[0].byteLength, 59)
  t.is(pair.state.outboundRecords[0].byteLength, 59)
  t.is(await pair.peer.opened, true)
  t.is(await pair.secret.opened, true)
  t.alike(pair.state.inboundAcquires[0], { rawBytes: 59, kind: 'header' })
  t.alike(pair.state.inboundReleases[0], { rawBytes: 59, kind: 'header' })
  t.alike(pair.state.outboundAcquires[0], { rawBytes: 59, kind: 'header' })
  t.alike(pair.state.outboundReleases[0], { rawBytes: 59, kind: 'header' })
})

test('native SecretStream roundtrip application records with exact unpooled backing and backpressure', async function (t) {
  const pair = createRealNativePair()
  teardownNativePair(t, pair)
  await openRealNativePair(pair)

  const payload1 = b4a.from('first native message for private route')
  const reading1 = readOne(pair.facade)
  await sendPeerToFacade(pair, payload1)
  const plain1 = await reading1

  t.alike(plain1, payload1)
  t.is(plain1.byteOffset, 4)
  t.is(plain1.buffer.byteLength, payload1.byteLength + 20)
  const backing1 = plain1.buffer

  // Backpressure: feeding a second record while plain1 is held by caller must return 0
  const payload2 = b4a.from('second native message under backpressure')
  pair.peer.write(payload2)
  await pair.peer.flush()
  await waitFor(function () {
    return pair.peerOutbound.length >= 3
  }, 'second record emitted by peer')
  const raw2 = pair.peerOutbound[2]
  t.is(pair.adapter.consumeCiphertext(raw2.subarray(0, 50)), 0, 'admission blocked while prior plaintext is held')

  // Next read demand transfers capacity and admits second record on fresh backing
  const reading2 = readOne(pair.facade)
  await waitFor(function () {
    return pair.state.inboundReleases.filter(function (entry) {
      return entry.kind === 'application'
    }).length === 1
  }, 'prior plaintext capacity transferred')

  t.is(feedRecord(pair.adapter, raw2), raw2.byteLength)
  const plain2 = await reading2
  t.alike(plain2, payload2)
  t.is(plain2.byteOffset, 4)
  t.not(plain2.buffer, backing1, 'fresh separate unpooled backing allocated')
  t.alike(plain1, payload1, 'retained prior plaintext remains completely intact')
})

test('native SecretStream bidirectional transfer with reverse half-duplex closing', async function (t) {
  const pair = createRealNativePair()
  teardownNativePair(t, pair)
  await openRealNativePair(pair)

  const forwardPayload = b4a.from('forward direction test')
  const forwardReading = readOne(pair.facade)
  await sendPeerToFacade(pair, forwardPayload)
  t.alike(await forwardReading, forwardPayload)

  const reversePayload = b4a.from('reverse direction test')
  const reverseReading = readOne(pair.peer)
  await sendFacadeToPeer(pair, reversePayload)
  t.alike(await reverseReading, reversePayload)

  // Remote peer ends: EOF propagates to facade readable half
  const facadeEnded = onceEvent(pair.facade, 'end')
  pair.facade.resume()
  pair.peer.end()
  pair.adapter.endCiphertext()
  await facadeEnded

  // Reverse writes from facade still drain cleanly after readable EOF
  const reversePayload2 = b4a.from('reverse message after remote EOF')
  const reverseReading2 = readOne(pair.peer)
  await sendFacadeToPeer(pair, reversePayload2)
  t.alike(await reverseReading2, reversePayload2)

  const facadeFinished = onceEvent(pair.facade, 'finish')
  pair.facade.end()
  await facadeFinished
  t.is(pair.state.failures.length, 0, 'orderly half-duplex close completes without failure')
})

test('native SecretStream destroy while holding plaintext preserves caller-retained buffer', async function (t) {
  const pair = createRealNativePair()
  teardownNativePair(t, pair)
  await openRealNativePair(pair)

  const payload = b4a.from('preserve this native backing on destroy')
  const reading = readOne(pair.facade)
  await sendPeerToFacade(pair, payload)
  const plain = await reading
  const snapshot = b4a.from(plain)

  const failure = new Error('native teardown test')
  pair.facade.destroy(failure)
  await waitFor(function () {
    return pair.facade.destroyed && pair.state.failures.length === 1
  }, 'facade destroyed')

  t.alike(plain, snapshot, 'caller-visible backing is never zeroed or mutated on destroy')
  t.alike(pair.facadeErrors, [failure], 'native teardown reports the original facade error once')
  t.is(pair.state.inboundReleases.filter(function (entry) {
    return entry.kind === 'application'
  }).length, 1)
})

test('native empty and maximum records transfer capacity without reusing retained backing', async function (t) {
  const sizes = [0, MAX_PLAINTEXT_BYTES]

  for (const size of sizes) {
    const pair = createRealNativePair()
    teardownNativePair(t, pair)
    await openRealNativePair(pair)

    // Generate test payload
    const payload1 = b4a.alloc(size, 0x5a)
    if (size > 1) {
      payload1[0] = 0x12
      payload1[size - 1] = 0x34
    }

    const reading1 = readOne(pair.facade)
    await sendPeerToFacade(pair, payload1)
    const plain1 = await reading1

    t.alike(plain1, payload1)
    const backing1 = plain1.buffer
    const snapshot1 = b4a.from(plain1)

    // Second payload
    const payload2 = b4a.alloc(size, 0x6b)
    if (size > 1) {
      payload2[0] = 0x78
      payload2[size - 1] = 0x9a
    }

    const reading2 = readOne(pair.facade)
    await waitFor(function () {
      return pair.state.inboundReleases.filter(function (entry) {
        return entry.kind === 'application'
      }).length >= 1
    }, 'first record capacity transferred')

    await sendPeerToFacade(pair, payload2)
    const plain2 = await reading2

    t.alike(plain2, payload2)
    t.not(plain2.buffer, backing1, 'the next record has fresh backing')

    pair.facade.destroy()
    t.alike(plain1, snapshot1, 'next-record delivery and destroy preserve the retained bytes')
  }

})
