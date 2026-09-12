'use strict'

const test = require('brittle')
const b4a = require('b4a')
const c = require('compact-encoding')
const UDX = require('udx-native')
const DHT = require('dht-rpc')
const HyperDHT = require('../..')
const Persistent = require('../../lib/persistent')
const m = require('../../lib/messages')
const { COMMANDS } = require('../../lib/constants')
const { BRANCH_CLASS } = require('../../lib/private/protocol')
const authorityModule = require('../../lib/private/endpoint-bootstrap-authority')
const controllerModule = require('../../lib/private/private-routing-controller')
const issuer = controllerModule.TEST_ONLY_PRIVATE_ROUTING_CONTROLLER_ISSUER
const { moduleCacheKey } = require('./module-cache')
const {
  closeLiveAuthorityHarness,
  dhtResponseFor,
  liveAuthorityHarness
} = require('./routed-dht-traversal')
const { installNativeReconnectResponder } = require('./live-immutable-get')
const { TEST_ONLY_ROUTE_MANAGER_FACTORY_ISSUER } = require('../../lib/private/route-manager')

let nextPort = 49100

function options() {
  return {
    release: 'alpha',
    acknowledgeAlpha: true,
    mode: 'required',
    bootstrapEndpoints: [{ host: '127.0.0.1', port: nextPort++ }],
    host: '127.0.0.1',
    port: nextPort++
  }
}

async function code(operation) {
  try {
    await operation()
    return null
  } catch (err) {
    return err.code
  }
}

async function until(check) {
  for (let attempt = 0; attempt < 2000; attempt++) {
    if (check()) return
    await new Promise((resolve) => setTimeout(resolve, 1))
  }
  throw new Error('public routing condition not reached')
}

function forbidDirectDHT(t) {
  const original = DHT.prototype._bootstrap
  let attempts = 0
  DHT.prototype._bootstrap = function () {
    if (this.outboundPolicy === 'direct') {
      attempts++
      throw new Error('public private routing attempted direct DHT bootstrap')
    }
    return original.call(this)
  }
  t.teardown(() => {
    DHT.prototype._bootstrap = original
    if (attempts !== 0) throw new Error('direct DHT bootstrap attempted')
  })
}

// Observe only resources created by the public constructor. Fixture relay/exit
// resources are separate owners. The native send path still runs unmodified.
function constructObserved(opts) {
  const sends = []
  let interfaces = null
  const watchNetworkInterfaces = UDX.prototype.watchNetworkInterfaces
  UDX.prototype.watchNetworkInterfaces = function (...args) {
    interfaces = watchNetworkInterfaces.apply(this, args)
    return interfaces
  }
  const createSocket = UDX.prototype.createSocket
  UDX.prototype.createSocket = function (...args) {
    const socket = createSocket.apply(this, args)
    for (const method of ['send', 'trySend']) {
      const original = socket[method]
      socket[method] = function (packet, port, host, ...rest) {
        sends.push({ port, host })
        return original.call(this, packet, port, host, ...rest)
      }
    }
    return socket
  }
  try {
    return { dht: new HyperDHT(opts), sends, interfaces }
  } finally {
    UDX.prototype.createSocket = createSocket
    UDX.prototype.watchNetworkInterfaces = watchNetworkInterfaces
  }
}

// Existing test-only issuers supply OPEN/seed readiness. The public constructor
// still creates and consumes the real bootstrap authority and real controller;
// no injection option or authority reader is added to production.
function fixtureConstructor(clock, attach) {
  const authorityCache =
    require.cache[
      moduleCacheKey(
        require.cache,
        require.resolve('../../lib/private/endpoint-bootstrap-authority')
      )
    ]
  const controllerCache =
    require.cache[
      moduleCacheKey(require.cache, require.resolve('../../lib/private/private-routing-controller'))
    ]
  const previousAuthority = authorityCache.exports
  const previousController = controllerCache.exports
  authorityCache.exports = {
    ...authorityModule,
    createEndpointBootstrapAuthority(opts) {
      return authorityModule.createEndpointBootstrapAuthority({
        ...opts,
        wallNow: clock.wallNow,
        monotonicNow: clock.monotonicNow
      })
    }
  }
  controllerCache.exports = {
    ...controllerModule,
    createPrivateRoutingController(opts) {
      const controller = controllerModule.createPrivateRoutingController(opts)
      attach(controller)
      return controller
    }
  }
  try {
    return constructObserved({ privateRouting: options() })
  } finally {
    authorityCache.exports = previousAuthority
    controllerCache.exports = previousController
  }
}

async function readyFixture(serviceBranch = BRANCH_CLASS.LOOKUP) {
  let dht = null
  let routing = null
  let sends = null
  const harness = await liveAuthorityHarness(
    (manager, topology) => {
      let builder
      const publicNode = fixtureConstructor(topology.clock, (controller) => {
        routing = controller
        builder = issuer.registerManager(controller, manager)
      })
      dht = publicNode.dht
      sends = publicNode.sends
      return {
        publishInitialPair: (handoffs) => issuer.publishInitialPair(routing, builder, handoffs),
        createDhtSeedAdmission: (branchClass, owner) =>
          issuer.createDhtSeedAdmission(routing, builder, branchClass, owner),
        publishInitialSeedPair: (readiness) =>
          issuer.publishInitialSeedPair(routing, builder, readiness)
      }
    },
    null,
    { serviceBranch }
  )
  await dht.ready()
  return {
    dht,
    routing,
    harness,
    sends,
    async close() {
      await dht.destroy()
      await closeLiveAuthorityHarness(harness)
    }
  }
}

function serveRecords(harness, records) {
  const socket = harness.fakeSocket
  const original = socket.send
  const requests = []
  const control = { blocked: false, requests }
  socket.send = function (packet, port, host) {
    original.call(this, packet, port, host)
    const flags = packet[1]
    const state = { start: 10, end: packet.byteLength, buffer: packet }
    if (flags & 2) c.fixed32.decode(state)
    const command = c.uint.decode(state)
    const target = flags & 8 ? c.fixed32.decode(state) : null
    const value = flags & 16 ? c.buffer.decode(state) : null
    requests.push(command)
    if (control.blocked) return true
    const key = target && b4a.toString(target, 'hex')
    let response = null
    let token = false
    if (!(flags & 4)) {
      switch (command) {
        case COMMANDS.IMMUTABLE_PUT:
          records.set(key, b4a.from(value))
          break
        case COMMANDS.MUTABLE_PUT: {
          const record = c.decode(m.mutablePutRequest, value)
          if (
            !Persistent.verifyMutable(record.signature, record.seq, record.value, record.publicKey)
          ) {
            throw new Error('exit received invalid mutable signature')
          }
          records.set(key, c.encode(m.mutableGetResponse, record))
          break
        }
        case COMMANDS.IMMUTABLE_GET:
        case COMMANDS.MUTABLE_GET:
          response = records.get(key) || null
          token = true
          break
        default:
          throw new Error('unexpected routed command')
      }
    }
    const suffix = b4a.concat([
      token ? b4a.alloc(32, 0x41) : b4a.alloc(0),
      response ? c.encode(c.buffer, response) : b4a.alloc(0)
    ])
    queueMicrotask(() =>
      socket.message(dhtResponseFor(packet, (token ? 2 : 0) | (response ? 16 : 0), suffix), {
        host,
        port
      })
    )
    return true
  }
  return control
}

const unsupported = [
  'lookup',
  'announce',
  'unannounce',
  'lookupAndUnannounce',
  'findPeer',
  'connect',
  'createServer',
  'pool',
  'createRawStream',
  'query',
  'request',
  'findNode',
  'ping',
  'delayedPing',
  'validateLocalAddresses',
  'register'
]

test('public alpha constructor rejects ambiguous policy without invoking accessors', async (t) => {
  forbidDirectDHT(t)
  let reads = 0
  const accessor = {
    get() {
      reads++
      throw new Error('getter ran')
    }
  }
  const bad = [
    undefined,
    null,
    false,
    'required',
    {},
    Object.create(null),
    { ...options(), release: 'beta' },
    { ...options(), acknowledgeAlpha: 1 },
    { ...options(), mode: 'off' },
    { ...options(), allowLegacyEgress: false },
    { ...options(), endpointBootstrapAuthority: {} },
    { ...options(), bootstrapEndpoints: [] },
    { ...options(), advertisedHost: '127.0.0.1' },
    { ...options(), advertisedHost: undefined, advertisedPort: undefined },
    { ...options(), host: 'localhost' },
    { ...options(), port: 0 },
    { ...options(), bootstrapEndpoints: [{ host: 'localhost', port: 49737 }] },
    { ...options(), bootstrapEndpoints: [{ host: '127.0.0.1', port: 0 }] },
    Object.assign(Object.create(options()), {})
  ]
  const symbolOption = options()
  symbolOption[Symbol('hidden policy')] = true
  bad.push(symbolOption)
  const fieldAccessor = options()
  Object.defineProperty(fieldAccessor, 'release', accessor)
  bad.push(fieldAccessor)
  const endpointAccessor = options()
  Object.defineProperty(endpointAccessor.bootstrapEndpoints[0], 'host', accessor)
  bad.push(endpointAccessor)
  const arrayAccessor = options()
  Object.defineProperty(arrayAccessor.bootstrapEndpoints, '0', accessor)
  bad.push(arrayAccessor)
  for (const privateRouting of bad) {
    t.is(await code(() => new HyperDHT({ privateRouting })), 'INVALID_ROUTE')
  }
  t.is(
    await code(() => new HyperDHT(Object.create({ privateRouting: options() }))),
    'INVALID_ROUTE'
  )
  t.is(
    await code(() => new HyperDHT(Object.defineProperty({}, 'privateRouting', accessor))),
    'INVALID_ROUTE'
  )
  t.is(
    await code(() => HyperDHT.bootstrapper(49737, '127.0.0.1', { privateRouting: options() })),
    'ERR_PRIVATE_COMMAND_UNSUPPORTED'
  )
  t.is(reads, 0, 'no policy getters executed')
})

test('public alpha preserves caller keys and rejects authority or legacy escape hatches', async (t) => {
  forbidDirectDHT(t)
  const keyPair = HyperDHT.keyPair()
  const secret = b4a.from(keyPair.secretKey)
  const privateRouting = options()
  privateRouting.advertisedHost = '127.0.0.1'
  privateRouting.advertisedPort = privateRouting.port
  const opts = { keyPair }
  Object.defineProperty(opts, 'privateRouting', { value: privateRouting })
  const { dht, sends } = constructObserved(opts)
  t.teardown(() => dht.destroy())
  const api = dht.privateRouting
  dht._onnetworkchange([])
  t.is(api.release, 'alpha')
  t.is(api.mode, 'required')
  t.alike(Object.keys(api).sort(), ['exposureReport', 'mode', 'ready', 'release', 'status'])
  await t.exception.all(() => {
    dht.privateRouting = {}
  }, TypeError)
  await t.exception.all(() => {
    api.mode = 'off'
  }, TypeError)
  await t.exception.all(
    () => Object.defineProperty(dht, 'privateRouting', { value: null }),
    TypeError
  )
  t.alike(keyPair.secretKey, secret)
  t.is(await code(() => api.ready()), 'ERR_PRIVACY_UNAVAILABLE')
  await dht.destroy()
  t.is(api.status(), 'DESTROYED')
  t.alike(keyPair.secretKey, secret)
  t.alike(sends, [], 'destroy-before-start never contacts an endpoint')
  t.is(
    await code(
      () =>
        new HyperDHT({
          keyPair,
          privateRouting: { ...options(), bootstrapEndpoints: [{ host: 'not-an-ip', port: 1 }] }
        })
    ),
    'INVALID_ROUTE'
  )
  t.alike(keyPair.secretKey, secret, 'constructor rollback never erases caller secret')
})

test('public required mode suppresses direct options and unsupported operations before readiness', async (t) => {
  forbidDirectDHT(t)
  let directReads = 0
  const opts = { privateRouting: options() }
  for (const name of [
    'bootstrap',
    'nodes',
    'host',
    'port',
    'udx',
    'udxFactory',
    'socket',
    'outboundPolicy',
    'requestTransport'
  ]) {
    Object.defineProperty(opts, name, {
      get() {
        directReads++
        throw new Error('direct option accessed')
      }
    })
  }
  const { dht, sends } = constructObserved(opts)
  t.teardown(() => dht.destroy())
  for (const method of unsupported) {
    t.is(await code(() => dht[method]()), 'ERR_PRIVATE_COMMAND_UNSUPPORTED', method)
  }
  const keyPair = HyperDHT.keyPair()
  for (const operation of [
    () => dht.immutableGet(keyPair.publicKey),
    () => dht.immutablePut(b4a.from('value')),
    () => dht.mutableGet(keyPair.publicKey),
    () => dht.mutablePut(keyPair, b4a.from('value'))
  ])
    t.is(await code(operation), 'ERR_PRIVACY_UNAVAILABLE')
  t.is(directReads, 0)
  t.is(dht.udx, null)
  t.is(dht.socket, null)
  t.alike(dht.bootstrapNodes, [])
  await dht.destroy()
  t.ok(
    sends.every(
      (to) =>
        to.host === opts.privateRouting.bootstrapEndpoints[0].host &&
        to.port === opts.privateRouting.bootstrapEndpoints[0].port
    ),
    'only explicitly configured private bootstrap contacts'
  )
  for (const method of unsupported)
    t.is(
      await code(() => dht[method]()),
      'ERR_PRIVATE_COMMAND_UNSUPPORTED',
      method + ' after destroy'
    )
  t.is(await code(() => dht.ready()), 'ERR_DESTROYED')
  t.is(await code(() => dht.fullyBootstrapped()), 'ERR_DESTROYED')
  t.is(await code(() => dht.suspend()), 'ERR_DESTROYED')
  t.is(await code(() => dht.resume()), 'ERR_DESTROYED')
  t.is(await code(() => dht.immutableGet(keyPair.publicKey)), 'ERR_DESTROYED')
})

for (const promiseLike of [false, true]) {
  test(`public destroy joins native watcher close with a ${promiseLike ? 'promise-like' : 'synchronous'} return`, async (t) => {
    forbidDirectDHT(t)
    const { dht, sends, interfaces } = constructObserved({ privateRouting: options() })
    const destroyInterfaces = interfaces.destroy
    let allowClose
    const allowed = new Promise((resolve) => {
      allowClose = resolve
    })
    let closing = null
    interfaces.destroy = function () {
      closing = allowed.then(() => destroyInterfaces.call(this))
      return promiseLike ? { then: closing.then.bind(closing) } : undefined
    }
    t.teardown(async () => {
      allowClose()
      if (closing) await closing
      else await destroyInterfaces.call(interfaces)
      await dht.destroy()
    })
    let watcherClosed = false
    interfaces.once('close', () => {
      watcherClosed = true
    })
    let parentCloses = 0
    dht.on('close', () => {
      parentCloses++
    })
    const completions = []
    const first = dht.destroy().then(() => {
      completions.push([watcherClosed, parentCloses])
    })
    const second = dht.destroy({ force: true }).then(() => {
      completions.push([watcherClosed, parentCloses])
    })
    try {
      await until(() => dht.privateRouting.status() === 'DESTROYED')
      t.alike(completions, [], 'neither caller completes while the native watcher is open')
    } finally {
      allowClose()
    }
    await Promise.all([first, second])
    t.alike(
      completions,
      [
        [true, 1],
        [true, 1]
      ],
      'both callers join the real watcher close and parent close event'
    )
    await dht.destroy()
    t.is(parentCloses, 1, 'later destroy calls retain the completed teardown')
    t.alike(sends, [], 'destroy-before-start never contacts an endpoint')
  })
}

test('public readiness waits for private bootstrap and network change retains only redacted exposure', async (t) => {
  forbidDirectDHT(t)
  const config = options()
  const { dht, sends } = constructObserved({ privateRouting: config })
  t.teardown(() => dht.destroy())
  let readyEvents = 0
  dht.on('ready', () => readyEvents++)
  const waiting = code(() => dht.ready())
  await until(() => sends.length > 0 && dht.privateRouting.exposureReport().length > 0)
  t.is(readyEvents, 0, 'socket bind does not publish ready')
  const report = dht.privateRouting.exposureReport()
  t.is(report[0].attemptCount, 1)
  t.alike(Object.keys(report[0]).sort(), [
    'attemptCount',
    'contactCategory',
    'firstAttemptMs',
    'lastAttemptMs',
    'outcome',
    'phase',
    'redactedEndpoint'
  ])
  t.ok(/^[0-9a-f]{24}$/.test(report[0].redactedEndpoint))
  await t.exception.all(() => report.push({ host: config.host }), TypeError)
  await t.exception.all(() => {
    report[0].redactedEndpoint = config.host
  }, TypeError)
  dht._onnetworkchange([])
  t.ok(await waiting, 'pending readiness rejects on network change')
  t.is(dht.privateRouting.status(), 'UNAVAILABLE')
  t.is(await code(() => dht.ready()), 'ERR_PRIVACY_UNAVAILABLE')
  t.is(await code(() => dht.resume()), 'ERR_PRIVACY_UNAVAILABLE')
  await Promise.all([dht.destroy(), dht.destroy({ force: true })])
  t.is(dht.destroyed, true)
  t.is(dht.privateRouting.status(), 'DESTROYED')
  t.alike(dht.privateRouting.exposureReport(), report)
  t.ok(
    sends.every(
      (to) =>
        to.host === config.bootstrapEndpoints[0].host &&
        to.port === config.bootstrapEndpoints[0].port
    ),
    'zero direct DHT or peer contacts'
  )
})

test('public bind failure cannot report readiness or fall back to direct DHT', async (t) => {
  forbidDirectDHT(t)
  const occupied = new UDX().createSocket()
  occupied.bind(0, '127.0.0.1')
  const config = { ...options(), port: occupied.address().port }
  const { dht, sends } = constructObserved({ privateRouting: config })
  t.teardown(async () => {
    await dht.destroy()
    await occupied.close()
  })
  t.ok(await code(() => dht.ready()), 'occupied bind rejects private readiness')
  t.is(dht.privateRouting.status(), 'UNAVAILABLE')
  t.alike(sends, [])
  t.alike(dht.privateRouting.exposureReport(), [])
})

test('public record API performs routed immutable and signed mutable round trips', async (t) => {
  forbidDirectDHT(t)
  const records = new Map()
  const value = b4a.from('alpha routed record')
  const keyPair = HyperDHT.keyPair()
  const writer = await readyFixture(BRANCH_CLASS.ANNOUNCE)
  t.teardown(() => writer.close())
  const writes = serveRecords(writer.harness, records)
  t.is(writer.dht.privateRouting.status(), 'READY')
  const immutable = await writer.dht.immutablePut(value)
  const mutable = await writer.dht.mutablePut(keyPair, value, { seq: 7 })
  t.alike(immutable.hash, HyperDHT.hash(value))
  t.is(mutable.seq, 7)
  t.ok(Persistent.verifyMutable(mutable.signature, 7, value, keyPair.publicKey))
  t.ok(writes.requests.includes(COMMANDS.IMMUTABLE_PUT))
  t.ok(writes.requests.includes(COMMANDS.MUTABLE_PUT))
  const before = writer.harness.fakeSocket.sends.length
  t.is(
    await code(() => writer.dht.immutablePut(b4a.alloc(1024))),
    'ERR_PRIVATE_COMMAND_UNSUPPORTED'
  )
  t.is(
    await code(() => writer.dht.mutablePut(keyPair, b4a.alloc(896))),
    'ERR_PRIVATE_COMMAND_UNSUPPORTED'
  )
  t.is(writer.harness.fakeSocket.sends.length, before, 'oversize records emit no exit request')
  const reader = await readyFixture()
  t.teardown(() => reader.close())
  serveRecords(reader.harness, records)
  const gotImmutable = await reader.dht.immutableGet(immutable.hash)
  const gotMutable = await reader.dht.mutableGet(keyPair.publicKey)
  t.alike(gotImmutable.value, value)
  t.alike(gotMutable.value, value)
  t.is(gotMutable.seq, 7)
  t.alike(gotMutable.signature, mutable.signature)
  t.absent(gotImmutable.from.host, 'opaque routed result has no dial host')
  t.absent(gotMutable.from.port, 'opaque routed result has no dial port')
  for (const method of unsupported)
    t.is(
      await code(() => reader.dht[method]()),
      'ERR_PRIVATE_COMMAND_UNSUPPORTED',
      method + ' while READY'
    )
  t.alike(writer.sends, [], 'writer never sends direct packets')
  t.alike(reader.sends, [], 'reader never sends direct packets')
})

test('public network change cancels pending routed queries and cannot reuse cached ready', async (t) => {
  forbidDirectDHT(t)
  const fixture = await readyFixture()
  t.teardown(() => fixture.close())
  const { dht, harness, routing } = fixture
  const server = serveRecords(harness, new Map())
  server.blocked = true
  const pending = code(() => dht.immutableGet(b4a.alloc(32, 1)))
  await until(() => server.requests.length > 0)
  dht._onnetworkchange([])
  t.ok(await pending, 'generation-owned in-flight read rejects')
  t.is(dht.privateRouting.status(), 'UNAVAILABLE')
  t.is(await code(() => dht.ready()), 'ERR_PRIVACY_UNAVAILABLE')
  t.is(await code(() => dht.fullyBootstrapped()), 'ERR_PRIVACY_UNAVAILABLE')
  t.is(await code(() => dht.privateRouting.ready()), 'ERR_PRIVACY_UNAVAILABLE')
  await dht.destroy()
  t.is(routing.snapshot().activeQueries, 0)
  t.is(routing.snapshot().endpointSockets, 0)
  t.is(routing.snapshot().secretBytes, 0)
  t.alike(fixture.sends, [])
})

test('public suspend revokes work and network change permanently cancels resume authority', async (t) => {
  forbidDirectDHT(t)
  const fixture = await readyFixture()
  t.teardown(() => fixture.close())
  const { dht, harness } = fixture
  let suspended = 0
  dht.on('suspend', () => suspended++)
  const suspending = dht.suspend()
  t.is(await code(() => dht.immutableGet(b4a.alloc(32, 1))), 'ERR_PRIVACY_UNAVAILABLE')
  await suspending
  t.is(suspended, 1)
  t.is(dht.suspended, true)
  t.is(dht.privateRouting.status(), 'SUSPENDED')
  t.is(await code(() => dht.ready()), 'ERR_PRIVACY_UNAVAILABLE')
  const before = harness.fakeSocket.sends.length
  t.is(await code(() => dht.immutablePut(b4a.from('suspended'))), 'ERR_PRIVACY_UNAVAILABLE')
  dht._onnetworkchange([])
  t.is(await code(() => dht.resume()), 'ERR_PRIVACY_UNAVAILABLE')
  t.is(harness.fakeSocket.sends.length, before)
  await dht.destroy()
  t.is(dht.privateRouting.status(), 'DESTROYED')
  t.alike(fixture.sends, [])
})

test('public resume waits for fresh private route generations and restores record service', async (t) => {
  forbidDirectDHT(t)
  const fixture = await readyFixture()
  const closeResponder = installNativeReconnectResponder(fixture.harness)
  const managers = []
  const stopObserving = TEST_ONLY_ROUTE_MANAGER_FACTORY_ISSUER.observe((manager) =>
    managers.push(manager)
  )
  let fresh = null
  t.teardown(async () => {
    stopObserving()
    await fixture.dht.destroy()
    await closeResponder()
    if (fresh) await closeLiveAuthorityHarness(fresh)
    await closeLiveAuthorityHarness(fixture.harness)
  })
  const { dht, routing } = fixture
  const prior = routing.snapshot()
  let resumedEvents = 0
  dht.on('resume', () => resumedEvents++)
  await dht.suspend()
  const resumed = dht.resume()
  void resumed.catch(() => {})
  await until(() => managers.length === 1)
  t.is(dht.privateRouting.status(), 'BUILDING')
  t.is(resumedEvents, 0, 'resume event waits for private route readiness')
  fresh = await liveAuthorityHarness(null, {
    manager: managers[0],
    topology: fixture.harness.topology
  })
  await resumed
  await dht.privateRouting.ready()
  t.is(dht.suspended, false)
  t.is(resumedEvents, 1)
  t.is(dht.privateRouting.status(), 'READY')
  t.ok(routing.snapshot().lookupGeneration > prior.lookupGeneration)
  t.ok(routing.snapshot().announceGeneration > prior.announceGeneration)
  const value = b4a.from('resumed alpha record')
  const hash = HyperDHT.hash(value)
  serveRecords(fresh, new Map([[b4a.toString(hash, 'hex'), value]]))
  t.alike((await dht.immutableGet(hash)).value, value)
  t.alike(fixture.sends, [], 'public constructor retains no direct socket authority after resume')
})

test('public failed resume rejects concurrent readiness before and after destroy', async (t) => {
  forbidDirectDHT(t)
  const fixture = await readyFixture()
  t.teardown(() => fixture.close())
  const { dht, harness } = fixture
  // No reconnect responder: the real guard reconnect deadline must reject.
  await dht.suspend()
  const before = harness.fakeSocket.sends.length
  const resumed = code(() => dht.resume())
  const readiness = Promise.all([
    code(() => dht.ready()),
    code(() => dht.fullyBootstrapped()),
    code(() => dht.privateRouting.ready())
  ])
  t.is(dht.privateRouting.status(), 'BOOTSTRAPPING')
  t.is(await resumed, 'ERR_PRIVATE_GUARD_UNAVAILABLE')
  t.is(dht.privateRouting.status(), 'UNAVAILABLE')
  let timer
  try {
    const outcome = await Promise.race([
      readiness,
      new Promise((resolve) => {
        timer = setTimeout(() => resolve('pending'), 500)
      })
    ])
    t.alike(
      outcome,
      [
        'ERR_PRIVATE_GUARD_UNAVAILABLE',
        'ERR_PRIVATE_GUARD_UNAVAILABLE',
        'ERR_PRIVATE_GUARD_UNAVAILABLE'
      ],
      'every public readiness waiter rejects with the reconnect failure'
    )
  } finally {
    clearTimeout(timer)
  }
  await dht.destroy()
  t.is(dht.privateRouting.status(), 'DESTROYED')
  t.is(await code(() => dht.ready()), 'ERR_DESTROYED')
  t.is(harness.fakeSocket.sends.length, before, 'failed resume never falls back to a DHT query')
  t.alike(fixture.sends, [], 'failed resume retains no direct endpoint send authority')
})
