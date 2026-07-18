'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { COMMANDS } = require('../../lib/constants')
const { createQueryContexts } = require('../../lib/private/query-context')
const { RoutedDHTIO } = require('../../lib/private/routed-dht-io')
const {
  decodeDestinationRef,
  decodeRoutedRequest,
  encodeDestinationRef,
  clearRoutedRequest
} = require('../../lib/private/routed-dht')
const { BRANCH_CLASS, M3_MESSAGE_ID } = require('../../lib/private/protocol')
const { FakeRouteAuthority } = require('./fake-route-authority')

function bytes(byte, size) {
  return b4a.alloc(size, byte)
}

function allZero(value) {
  for (const byte of value) {
    if (byte !== 0) return false
  }
  return true
}

function record(byte) {
  const id = bytes(byte, 32)
  return { id, destinationRef: encodeDestinationRef({ id, handle: bytes(byte + 1, 130) }) }
}

function fixture(overrides = {}) {
  const authority = overrides.authority || new FakeRouteAuthority()
  const contexts = overrides.contexts || createQueryContexts()
  const retained = []
  const io = new RoutedDHTIO({
    authority,
    contexts,
    now: overrides.now || (() => 1_000),
    randomBytes:
      overrides.randomBytes ||
      ((buffer) => {
        buffer.fill(0x44)
        retained.push(buffer)
      })
  })
  return { io, authority, contexts, retained }
}

function message(to, context, overrides = {}) {
  return {
    to,
    token: null,
    internal: false,
    command: COMMANDS.IMMUTABLE_GET,
    target: bytes(0x31, 32),
    value: null,
    context,
    attempt: 1,
    ...overrides
  }
}

function expectCode(t, operation, code) {
  let error = null
  try {
    operation()
  } catch (err) {
    error = err
  }
  t.is(error && error.code, code)
}

async function expectRejectCode(t, promise, code) {
  let error = null
  try {
    await promise
  } catch (err) {
    error = err
  }
  t.is(error && error.code, code)
}

test('routed DHT IO implements all nine methods and delegates lifecycle', async (t) => {
  const { io, authority, contexts } = fixture()
  for (const name of [
    'ready',
    'suspend',
    'resume',
    'destroy',
    'bootstrap',
    'closest',
    'key',
    'id',
    'request'
  ]) {
    t.is(typeof io[name], 'function')
  }

  await io.ready()
  await io.resume()
  t.is(authority.calls.ready, 1)
  t.is(authority.calls.resume, 1)

  authority.lookup = [record(1)]
  const [destination] = io.closest({
    target: bytes(2, 32),
    limit: 1,
    context: contexts.immutableGet.lookup
  })
  await io.suspend()
  expectCode(t, () => io.id(destination), 'ERR_DESTROYED')
  await io.destroy()
  await io.destroy()
  t.is(authority.calls.suspend, 1)
  t.is(authority.calls.destroy, 1)
})

test('candidate discovery issues opaque branch-bound destinations', async (t) => {
  const { io, authority, contexts } = fixture()
  authority.lookup = [record(3), record(4)]
  authority.announce = [record(5)]

  const lookup = io.closest({
    target: bytes(6, 32),
    limit: 2,
    context: contexts.immutableGet.lookup
  })
  const announce = await io.bootstrap({
    target: bytes(7, 32),
    limit: 1,
    context: contexts.immutableGet.announce
  })

  t.is(lookup.length, 2)
  t.is(announce.length, 1)
  for (const destination of [...lookup, ...announce]) {
    t.ok(Object.isFrozen(destination))
    t.alike(Object.keys(destination), [])
    t.is(io.id(destination).byteLength, 32)
    t.is(typeof io.key(destination), 'string')
  }
  t.is(io.key(lookup[0]), io.key(lookup[0]))
  t.not(io.key(lookup[0]), io.key(announce[0]))

  const id = io.id(lookup[0])
  id.fill(0)
  t.not(io.id(lookup[0]), id)
  t.alike(io.id(lookup[0]), bytes(3, 32))
  t.alike(authority.lookup[0].id, bytes(3, 32))
})

test('candidate discovery authenticates contexts and records before authority effects escape', async (t) => {
  const { io, authority, contexts } = fixture()
  const before = authority.calls.closest
  const invalid = [null, {}, { host: '127.0.0.1', port: 1 }]
  for (const context of invalid) {
    expectCode(
      t,
      () => io.closest({ target: bytes(1, 32), limit: 1, context }),
      'ERR_PRIVATE_COMMAND_UNSUPPORTED'
    )
  }
  t.is(authority.calls.closest, before)

  authority.lookup = [record(8), { id: bytes(9, 32), destinationRef: bytes(9, 172) }]
  expectCode(
    t,
    () =>
      io.closest({
        target: bytes(1, 32),
        limit: 2,
        context: contexts.immutableGet.lookup
      }),
    'INVALID_ROUTE'
  )
  t.is(authority.calls.closest, before + 1)
})

test('candidate discovery passes one owned target snapshot and clears it synchronously', async (t) => {
  const authority = new FakeRouteAuthority()
  const retained = []
  const snapshots = []
  authority.closest = ({ target }) => {
    retained.push(target)
    snapshots.push(b4a.from(target))
    return []
  }
  authority.bootstrap = ({ target }) => {
    retained.push(target)
    snapshots.push(b4a.from(target))
    return Promise.resolve([])
  }
  const { io, contexts } = fixture({ authority })
  const closestTarget = bytes(0x71, 32)
  const bootstrapTarget = bytes(0x72, 32)
  io.closest({
    target: closestTarget,
    limit: 0,
    context: contexts.immutableGet.lookup
  })
  const bootstrap = io.bootstrap({
    target: bootstrapTarget,
    limit: 0,
    context: contexts.immutableGet.announce
  })
  t.alike(snapshots, [closestTarget, bootstrapTarget])
  t.ok(retained.every(allZero))
  t.alike(closestTarget, bytes(0x71, 32))
  t.alike(bootstrapTarget, bytes(0x72, 32))
  await bootstrap
})

test('request emits exact immutable-get routed bytes and normalizes logical reply', async (t) => {
  const { io, authority, contexts, retained } = fixture()
  const destinationRecord = record(10)
  const closer = record(11)
  authority.lookup = [destinationRecord]
  authority.response = {
    rtt: 12,
    from: destinationRecord,
    to: null,
    token: null,
    closerNodes: [closer],
    error: 0,
    value: bytes(0x55, 32)
  }
  const [to] = io.closest({
    target: bytes(1, 32),
    limit: 1,
    context: contexts.immutableGet.lookup
  })
  const operation = io.request(message(to, contexts.immutableGet.lookup))

  t.alike(Object.keys(operation), ['promise', 'cancel'])
  t.is(authority.calls.request, 1)
  const copiedRequest = authority.requests[0].encodedRequest
  const decoded = decodeRoutedRequest(copiedRequest)
  t.is(decoded.operationClass, BRANCH_CLASS.LOOKUP)
  t.is(decoded.commandId, M3_MESSAGE_ID.IMMUTABLE_GET_V1)
  t.alike(decoded.encodedBody, bytes(0x31, 32))
  t.alike(decoded.requestId, bytes(0x44, 16))
  t.is(decoded.absoluteDeadlineMs, 4_000n)
  t.alike(decoded.destinationEncoded, destinationRecord.destinationRef)
  clearRoutedRequest(decoded)

  const reply = await operation.promise
  t.alike(Object.keys(reply), ['rtt', 'from', 'to', 'token', 'closerNodes', 'error', 'value'])
  t.is(reply.rtt, 12)
  t.is(reply.to, null)
  t.is(reply.token, null)
  t.is(reply.error, 0)
  t.alike(reply.value, bytes(0x55, 32))
  t.ok(Object.isFrozen(reply.from))
  t.ok(Object.isFrozen(reply.closerNodes[0]))
  t.ok(allZero(copiedRequest))
  t.ok(retained.every((buffer) => buffer.every((byte) => byte === 0)))
})

test('announce capability emits only the announce branch', async (t) => {
  const { io, authority, contexts } = fixture()
  const destinationRecord = record(0x73)
  authority.announce = [destinationRecord]
  authority.response = {
    rtt: 1,
    from: destinationRecord,
    to: null,
    token: null,
    closerNodes: [],
    error: 0,
    value: null
  }
  const [to] = await io.bootstrap({
    target: bytes(1, 32),
    limit: 1,
    context: contexts.immutableGet.announce
  })
  const operation = io.request(message(to, contexts.immutableGet.announce))
  const decoded = decodeRoutedRequest(authority.requests[0].encodedRequest)
  t.is(decoded.operationClass, BRANCH_CLASS.ANNOUNCE)
  t.is(authority.requests[0].branch, BRANCH_CLASS.ANNOUNCE)
  clearRoutedRequest(decoded)
  const reply = await operation.promise
  t.alike(io.id(reply.from), bytes(0x73, 32))
})

test('request rejects wrong commands, branches, raw addresses, and stale destinations before authority', (t) => {
  const first = fixture()
  const second = fixture()
  first.authority.lookup = [record(12)]
  const [to] = first.io.closest({
    target: bytes(1, 32),
    limit: 1,
    context: first.contexts.immutableGet.lookup
  })
  const invalid = [
    [
      message(to, first.contexts.immutableGet.lookup, { command: COMMANDS.IMMUTABLE_PUT }),
      'ERR_PRIVATE_COMMAND_UNSUPPORTED'
    ],
    [message(to, first.contexts.immutableGet.announce), 'ERR_AUTHENTICATION'],
    [
      message({ host: '127.0.0.1', port: 49737 }, first.contexts.immutableGet.lookup),
      'INVALID_ROUTE'
    ],
    [message(to, second.contexts.immutableGet.lookup), 'ERR_PRIVATE_COMMAND_UNSUPPORTED']
  ]
  for (const [value, code] of invalid) expectCode(t, () => first.io.request(value), code)
  t.is(first.authority.calls.request, 0)
})

test('request cancellation and settlement clear ownership exactly once', async (t) => {
  const { io, authority, contexts, retained } = fixture()
  authority.lookup = [record(13)]
  const [to] = io.closest({
    target: bytes(1, 32),
    limit: 1,
    context: contexts.immutableGet.lookup
  })
  let resolve = null
  authority.requestHook = (options, state) => ({
    promise: new Promise((done) => {
      resolve = done
    }),
    cancel(reason) {
      if (state.cancelled) return
      state.cancelled = true
      state.cancelReason = reason
      state.encodedRequest.fill(0)
      state.destinationRef.fill(0)
      authority.calls.cancel++
    }
  })

  const operation = io.request(message(to, contexts.immutableGet.lookup))
  operation.promise.catch(() => {})
  operation.cancel(new Error('timeout'))
  operation.cancel(new Error('again'))
  t.is(authority.calls.cancel, 1)
  t.is(authority.requests[0].cancelReason.message, 'timeout')
  t.ok(allZero(authority.requests[0].encodedRequest))
  t.ok(retained.every((buffer) => buffer.every((byte) => byte === 0)))
  resolve(authority.response)
  await Promise.resolve()
  t.is(authority.calls.cancel, 1)
})

test('request fails closed on sync throw, malformed operation, rejection, malformed reply, and expiry', async (t) => {
  for (const mode of ['throw', 'operation', 'reject', 'reply', 'expired']) {
    let time = 1_000
    const current = fixture({ now: () => time })
    current.authority.lookup = [record(14)]
    const [to] = current.io.closest({
      target: bytes(1, 32),
      limit: 1,
      context: current.contexts.immutableGet.lookup
    })
    if (mode === 'throw')
      current.authority.requestHook = () => {
        throw new Error('route failed')
      }
    if (mode === 'operation') current.authority.requestHook = () => ({ promise: Promise.resolve() })
    if (mode === 'reject') {
      current.authority.requestHook = () => ({
        promise: Promise.reject(new Error('route rejected')),
        cancel() {}
      })
    }
    if (mode === 'reply') current.authority.response = { rtt: -1 }
    if (mode === 'expired') {
      current.authority.response = {
        rtt: 1,
        from: record(14),
        to: null,
        token: null,
        closerNodes: [],
        error: 0,
        value: null
      }
    }

    let operation = null
    try {
      operation = current.io.request(message(to, current.contexts.immutableGet.lookup))
    } catch (error) {
      t.ok(mode === 'throw' || mode === 'operation')
    }
    if (mode === 'expired') time = 4_001
    if (operation !== null) {
      const expected =
        mode === 'reject'
          ? 'ROUTE_UNAVAILABLE'
          : mode === 'reply'
            ? 'INVALID_ROUTE'
            : 'ERR_AUTHENTICATION'
      await expectRejectCode(t, operation.promise, expected)
    }
    t.ok(current.retained.every((buffer) => buffer.every((byte) => byte === 0)))
  }
})

test('constructor and callbacks reject accessors, proxies, SAB views, and invalid clock/random', (t) => {
  const contexts = createQueryContexts()
  const authority = new FakeRouteAuthority()
  for (const name of ['host', 'port', 'socket', 'extra']) {
    const options = { authority, contexts }
    Object.defineProperty(options, name, {
      get() {
        throw new Error('must not run')
      }
    })
    t.exception(() => new RoutedDHTIO(options))
  }

  let authorityGetters = 0
  Object.defineProperty(authority, 'ready', {
    get() {
      authorityGetters++
      return () => {}
    }
  })
  t.exception(() => new RoutedDHTIO({ authority, contexts }))
  t.is(authorityGetters, 0)

  const poisoned = fixture({
    randomBytes(buffer) {
      buffer.fill(1)
      return buffer
    }
  })
  poisoned.authority.lookup = [record(15)]
  const [to] = poisoned.io.closest({
    target: bytes(1, 32),
    limit: 1,
    context: poisoned.contexts.immutableGet.lookup
  })
  t.exception(() => poisoned.io.request(message(to, poisoned.contexts.immutableGet.lookup)))

  if (typeof SharedArrayBuffer === 'function') {
    const shared = new Uint8Array(new SharedArrayBuffer(32))
    expectCode(
      t,
      () =>
        poisoned.io.closest({
          target: shared,
          limit: 1,
          context: poisoned.contexts.immutableGet.lookup
        }),
      'INVALID_ROUTE'
    )
  } else {
    t.pass('SharedArrayBuffer unavailable')
  }
})

test('opaque destinations authenticate copied bytes, factories, and a fixed key vector', async (t) => {
  const first = fixture()
  const second = fixture()
  const source = record(3)
  first.authority.lookup = [source]
  const [destination] = first.io.closest({
    target: bytes(1, 32),
    limit: 1,
    context: first.contexts.immutableGet.lookup
  })

  t.is(
    first.io.key(destination),
    'bd06e16462ead79ae13d1c1f3dcaddebdf6cda8375079d89d8dad9cd68c878e6'
  )
  source.id.fill(0)
  source.destinationRef.fill(0)
  t.alike(first.io.id(destination), bytes(3, 32))
  expectCode(t, () => first.io.key({}), 'INVALID_ROUTE')
  expectCode(t, () => second.io.key(destination), 'INVALID_ROUTE')
  expectCode(t, () => first.io.id(new Proxy(destination, {})), 'INVALID_ROUTE')

  const mismatched = record(4)
  mismatched.id[0] ^= 1
  first.authority.lookup = [mismatched]
  expectCode(
    t,
    () =>
      first.io.closest({
        target: bytes(1, 32),
        limit: 1,
        context: first.contexts.immutableGet.lookup
      }),
    'INVALID_ROUTE'
  )
  await first.io.suspend()
  expectCode(t, () => first.io.key(destination), 'ERR_DESTROYED')
})

test('closest and bootstrap consume bounded synchronous and asynchronous iterables', async (t) => {
  const authority = new FakeRouteAuthority()
  let closestRecords = [record(20), record(21)]
  authority.closest = () => new Set(closestRecords)
  authority.bootstrap = () => ({
    async *[Symbol.asyncIterator]() {
      yield record(22)
      yield record(23)
    }
  })
  const { io, contexts } = fixture({ authority })
  const closest = io.closest({
    target: bytes(1, 32),
    limit: 2,
    context: contexts.immutableGet.lookup
  })
  const bootstrap = await io.bootstrap({
    target: bytes(1, 32),
    limit: 2,
    context: contexts.immutableGet.announce
  })
  t.alike(
    closest.map((destination) => io.id(destination)),
    [bytes(20, 32), bytes(21, 32)]
  )
  t.alike(
    bootstrap.map((destination) => io.id(destination)),
    [bytes(22, 32), bytes(23, 32)]
  )

  closestRecords = [record(24), record(25)]
  expectCode(
    t,
    () =>
      io.closest({
        target: bytes(1, 32),
        limit: 1,
        context: contexts.immutableGet.lookup
      }),
    'INVALID_ROUTE'
  )
})

test('discovery rejects address fields and hostile record descriptors transactionally', (t) => {
  const { io, authority, contexts } = fixture()
  authority.lookup = [record(30)]
  const [existing] = io.closest({
    target: bytes(1, 32),
    limit: 1,
    context: contexts.immutableGet.lookup
  })

  for (const name of ['host', 'hostname', 'port', 'socket']) {
    const options = {
      context: contexts.immutableGet.lookup,
      target: bytes(1, 32),
      limit: 1,
      [name]: name
    }
    expectCode(t, () => io.closest(options), 'INVALID_ROUTE')
  }

  let getterCalls = 0
  const hostile = record(31)
  Object.defineProperty(hostile, 'destinationRef', {
    get() {
      getterCalls++
      throw new Error('must not run')
    }
  })
  authority.lookup = [hostile]
  expectCode(
    t,
    () =>
      io.closest({
        target: bytes(1, 32),
        limit: 1,
        context: contexts.immutableGet.lookup
      }),
    'INVALID_ROUTE'
  )
  t.is(getterCalls, 0)
  t.alike(io.id(existing), bytes(30, 32))
})

test('request validates exact address-free shape before route authority IO', (t) => {
  const { io, authority, contexts } = fixture()
  authority.lookup = [record(32)]
  const [to] = io.closest({
    target: bytes(1, 32),
    limit: 1,
    context: contexts.immutableGet.lookup
  })
  for (const name of ['host', 'hostname', 'port', 'socket']) {
    expectCode(
      t,
      () => io.request(message(to, contexts.immutableGet.lookup, { [name]: name })),
      'INVALID_ROUTE'
    )
  }
  expectCode(
    t,
    () => io.request(message(to, contexts.immutableGet.lookup, { internal: true })),
    'ERR_PRIVATE_COMMAND_UNSUPPORTED'
  )
  expectCode(
    t,
    () => io.request(message(to, contexts.immutableGet.lookup, { attempt: 5 })),
    'INVALID_ROUTE'
  )
  t.is(authority.calls.request, 0)
})

test('logical reply validation is exact, bounded, defensive, and branch preserving', async (t) => {
  const malformed = [
    { rtt: -1 },
    {
      rtt: 1,
      from: { ...record(40), host: '127.0.0.1' },
      to: null,
      token: null,
      closerNodes: [],
      error: 0,
      value: null
    },
    {
      rtt: 1,
      from: record(40),
      to: {},
      token: null,
      closerNodes: [],
      error: 0,
      value: null
    },
    {
      rtt: 1,
      from: record(40),
      to: null,
      token: null,
      closerNodes: new Array(21).fill(record(41)),
      error: 0,
      value: null
    },
    {
      rtt: 1,
      from: record(40),
      to: null,
      token: null,
      closerNodes: [],
      error: 0,
      value: bytes(1, 4707)
    }
  ]

  for (const response of malformed) {
    const current = fixture()
    current.authority.lookup = [record(40)]
    current.authority.response = response
    const [to] = current.io.closest({
      target: bytes(1, 32),
      limit: 1,
      context: current.contexts.immutableGet.lookup
    })
    const operation = current.io.request(message(to, current.contexts.immutableGet.lookup))
    await expectRejectCode(t, operation.promise, 'INVALID_ROUTE')
    t.is(current.authority.calls.request, 1)
  }

  const current = fixture()
  const from = record(42)
  const closer = record(43)
  const value = bytes(44, 64)
  current.authority.lookup = [from]
  current.authority.response = {
    rtt: 1,
    from,
    to: null,
    token: null,
    closerNodes: [closer],
    error: 0,
    value
  }
  const [to] = current.io.closest({
    target: bytes(1, 32),
    limit: 1,
    context: current.contexts.immutableGet.lookup
  })
  const reply = await current.io.request(message(to, current.contexts.immutableGet.lookup)).promise
  from.id.fill(0)
  closer.id.fill(0)
  value.fill(0)
  t.alike(current.io.id(reply.from), bytes(42, 32))
  t.alike(current.io.id(reply.closerNodes[0]), bytes(43, 32))
  t.alike(reply.value, bytes(44, 64))
})

test('suspend and destroy revoke active operations before lifecycle delegation', async (t) => {
  for (const lifecycle of ['suspend', 'destroy']) {
    const current = fixture()
    current.authority.lookup = [record(50)]
    const [to] = current.io.closest({
      target: bytes(1, 32),
      limit: 1,
      context: current.contexts.immutableGet.lookup
    })
    current.authority.requestHook = (options, state) => ({
      promise: new Promise(() => {}),
      cancel(reason) {
        if (state.cancelled) return
        state.cancelled = true
        state.cancelReason = reason
        state.encodedRequest.fill(0)
        state.destinationRef.fill(0)
        current.authority.calls.cancel++
      }
    })
    const operation = current.io.request(message(to, current.contexts.immutableGet.lookup))
    operation.promise.catch(() => {})
    await current.io[lifecycle]()
    if (lifecycle === 'destroy') await current.io.destroy()
    t.is(current.authority.calls.cancel, 1)
    t.is(current.authority.calls[lifecycle], 1)
    expectCode(t, () => current.io.id(to), 'ERR_DESTROYED')
    t.ok(current.retained.every((buffer) => buffer.every((byte) => byte === 0)))
  }
})

test('lifecycle delegate failure leaves private state revoked and resume fail-closed', async (t) => {
  const authority = new FakeRouteAuthority()
  authority.suspend = () => {
    authority.calls.suspend++
    throw new Error('suspend failed')
  }
  authority.resume = () => {
    authority.calls.resume++
    throw new Error('resume failed')
  }
  const current = fixture({ authority })
  authority.lookup = [record(51)]
  const [destination] = current.io.closest({
    target: bytes(1, 32),
    limit: 1,
    context: current.contexts.immutableGet.lookup
  })
  await t.exception(async () => current.io.suspend())
  expectCode(t, () => current.io.id(destination), 'ERR_DESTROYED')
  await t.exception(async () => current.io.resume())
  expectCode(
    t,
    () =>
      current.io.closest({
        target: bytes(1, 32),
        limit: 1,
        context: current.contexts.immutableGet.lookup
      }),
    'ERR_DESTROYED'
  )
})

test('authority operation fields accept prototype data and reject accessors without invoking them', async (t) => {
  class Operation {
    constructor(response) {
      this.promise = Promise.resolve(response)
      this.cancelled = 0
    }

    cancel() {
      this.cancelled++
    }
  }

  const current = fixture()
  const source = record(52)
  current.authority.lookup = [source]
  current.authority.response = {
    rtt: 1,
    from: source,
    to: null,
    token: null,
    closerNodes: [],
    error: 0,
    value: null
  }
  current.authority.requestHook = () => new Operation(current.authority.response)
  const [to] = current.io.closest({
    target: bytes(1, 32),
    limit: 1,
    context: current.contexts.immutableGet.lookup
  })
  t.is(
    (await current.io.request(message(to, current.contexts.immutableGet.lookup)).promise).error,
    0
  )

  let getters = 0
  current.authority.requestHook = () => {
    const operation = { cancel() {} }
    Object.defineProperty(operation, 'promise', {
      get() {
        getters++
        return Promise.resolve()
      }
    })
    return operation
  }
  expectCode(
    t,
    () => current.io.request(message(to, current.contexts.immutableGet.lookup)),
    'INVALID_ROUTE'
  )
  t.is(getters, 0)
})

test('clock, random, and authority reentry fail closed before request delivery', (t) => {
  for (const now of [
    -1,
    1.5,
    Number.MAX_SAFE_INTEGER + 1,
    -1n,
    0xffff_ffff_ffff_ffffn,
    0x1_0000_0000_0000_0000n
  ]) {
    const current = fixture({ now: () => now })
    current.authority.lookup = [record(60)]
    const [to] = current.io.closest({
      target: bytes(1, 32),
      limit: 1,
      context: current.contexts.immutableGet.lookup
    })
    expectCode(
      t,
      () => current.io.request(message(to, current.contexts.immutableGet.lookup)),
      'INVALID_ROUTE'
    )
    t.is(current.authority.calls.request, 0)
  }

  let io = null
  let contexts = null
  const authority = new FakeRouteAuthority()
  contexts = createQueryContexts()
  authority.lookup = [record(61)]
  io = new RoutedDHTIO({
    authority,
    contexts,
    now: () => 1_000,
    randomBytes(buffer) {
      buffer.fill(1)
      try {
        io.ready()
      } catch {}
    }
  })
  const [to] = io.closest({
    target: bytes(1, 32),
    limit: 1,
    context: contexts.immutableGet.lookup
  })
  expectCode(t, () => io.request(message(to, contexts.immutableGet.lookup)), 'INVALID_ROUTE')
  t.is(authority.calls.request, 0)
})

test('random callback cannot redirect captured mutable intrinsics', async (t) => {
  const authority = new FakeRouteAuthority()
  const contexts = createQueryContexts()
  const source = record(62)
  const response = {
    rtt: 1,
    from: source,
    to: null,
    token: null,
    closerNodes: [],
    error: 0,
    value: null
  }
  const authorityPromise = Promise.resolve(response)
  authority.lookup = [source]
  authority.requestHook = () => ({ promise: authorityPromise, cancel() {} })

  const originals = [
    [Array.prototype, 'indexOf', Array.prototype.indexOf],
    [Set.prototype, 'add', Set.prototype.add],
    [Set.prototype, 'delete', Set.prototype.delete],
    [Object, 'getOwnPropertyDescriptor', Object.getOwnPropertyDescriptor],
    [Promise.prototype, 'then', Promise.prototype.then]
  ]
  let poisoned = false
  const io = new RoutedDHTIO({
    authority,
    contexts,
    now: () => 1_000,
    randomBytes(buffer) {
      buffer.fill(0x77)
      for (const [target, name] of originals) {
        target[name] = () => {
          throw new Error('mutable intrinsic ran')
        }
      }
      poisoned = true
    }
  })
  const [to] = io.closest({
    target: bytes(1, 32),
    limit: 1,
    context: contexts.immutableGet.lookup
  })

  let operation = null
  try {
    operation = io.request(message(to, contexts.immutableGet.lookup))
  } finally {
    for (const [target, name, value] of originals) target[name] = value
  }
  t.ok(poisoned)
  t.is((await operation.promise).error, 0)
})
