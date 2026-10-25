'use strict'

const test = require('brittle')
const network = require('./helpers/network')
const { DHT, privateRouting } = network
const observeUDP = require('./helpers/udp-oracle')
const { exchange } = require('./helpers/traffic')

function errorCode(fn) {
  try {
    fn()
    return null
  } catch (error) {
    return error.code
  }
}

test('public-contract: invalid option shapes allocate no sockets and invoke no accessors', (t) => {
  const oracle = observeUDP()
  t.teardown(() => oracle.restore())
  let getterCalls = 0
  const accessor = privateRouting()
  Object.defineProperty(accessor, 'profile', {
    get() {
      getterCalls++
      return 'spliced'
    }
  })
  const inherited = Object.assign(Object.create({ profile: 'spliced' }), privateRouting())
  delete inherited.profile
  const symbol = privateRouting()
  symbol[Symbol('unknown')] = true
  for (const privateOptions of [
    accessor,
    inherited,
    symbol,
    { ...privateRouting(), unknown: true },
    { ...privateRouting(), acknowledgeAlpha: false },
    { ...privateRouting(), profile: 'unsupported' },
    { ...privateRouting(), profile: 'native-v2' },
    { ...privateRouting(true), profile: 'native-v2' },
    { ...privateRouting(), relay: 1 },
    { ...privateRouting(), mode: 'required' }
  ]) {
    t.is(
      errorCode(() => new DHT({ bootstrap: [], privateRouting: privateOptions })),
      'INVALID_ROUTE'
    )
  }
  const outer = { bootstrap: [] }
  Object.defineProperty(outer, 'privateRouting', {
    get() {
      getterCalls++
      return privateRouting()
    }
  })
  t.is(
    errorCode(() => new DHT(outer)),
    'INVALID_ROUTE'
  )
  t.is(
    errorCode(() => new DHT(Object.create({ privateRouting: privateRouting() }))),
    'INVALID_ROUTE'
  )
  t.is(
    errorCode(() => DHT.bootstrapper(0, '127.0.0.1', { privateRouting: privateRouting() })),
    'ERR_PRIVATE_COMMAND_UNSUPPORTED'
  )
  t.is(getterCalls, 0, 'configuration accessors never execute')
  t.is(oracle.sockets.length, 0, 'rejected options cannot start networking')
  t.is(oracle.attempts.length, 0)
})

test('public-contract: frozen optional facade preserves ordinary direct connections and spliced streams', async (t) => {
  const h = await network(t)
  t.ok(Object.isFrozen(h.source.privateRouting))
  t.is(h.source.privateRouting.status(), 'READY')
  t.is(h.source.privateRouting.relay, false)

  const splicedNode = new DHT({
    bootstrap: [],
    host: '127.0.0.1',
    anyPort: true,
    privateRouting: {
      release: 'alpha',
      acknowledgeAlpha: true,
      mode: 'optional',
      profile: 'spliced',
      relay: false
    }
  })
  t.teardown(() => splicedNode.destroy({ force: true }))
  t.is(splicedNode.privateRouting.profile, 'spliced')
  t.is(splicedNode.privateRouting.status(), 'BOOTSTRAPPING')

  const server = await h.listen({}, h.destination, DHT.keyPair(), true)
  const { client, remote } = await h.pair(server, {}, h.source, true)
  t.alike(await exchange(client, remote), { up: 49157, down: 32771 })
  t.ok(
    h.oracle.forbidden(h.source, h.destination).some((row) => row.method === 'connect'),
    'ordinary connect still uses the native direct path'
  )
})

test('public-contract: spliced client survives cached descriptor refresh, string writes, and dead pinned guards', async (t) => {
  t.timeout(120000)
  const boot = new DHT({
    bootstrap: [],
    host: '127.0.0.1',
    port: 0,
    ephemeral: false,
    firewalled: false
  })
  await boot.ready()
  const bootstrap = [{ host: '127.0.0.1', port: boot.address().port }]
  const opts = (relay) => ({
    release: 'alpha',
    acknowledgeAlpha: true,
    mode: 'optional',
    profile: 'spliced',
    relay
  })
  const nodes = [false, false, true, true, true, true, true, true, true].map(
    (relay) =>
      new DHT({
        bootstrap,
        host: '127.0.0.1',
        port: 0,
        ephemeral: false,
        firewalled: false,
        privateRouting: opts(relay)
      })
  )
  t.teardown(async () => {
    await Promise.allSettled(nodes.map((n) => n.destroy({ force: true })))
    await boot.destroy({ force: true })
  })
  await Promise.all(nodes.map((n) => n.ready()))
  await Promise.all(nodes.map((n) => n.privateRouting.ready()))

  const [source, destination, ...relays] = nodes
  const server = destination.privateRouting.createServer((socket) => {
    socket.on('error', () => {})
    socket.pipe(socket)
  })
  t.teardown(() => server.close())
  await server.listen(DHT.keyPair())

  // First connection populates source's 45s descriptorCache and stays open so old EntryCircuit stays live
  const first = source.privateRouting.connect(server.publicKey)
  first.on('error', () => {})
  t.teardown(() => first.destroy())
  t.is(await first.opened, true)
  const echoed1 = new Promise((resolve) => first.once('data', (d) => resolve(d.toString())))
  first.write('private peer payload')
  t.is(await echoed1, 'private peer payload', 'string payload echoes intact over spliced route')

  // Refresh listener onto a new generation while `first` still holds the retired generation open
  await server.controller._publish(server)

  // Same client reconnects immediately while stale descriptor is still in descriptorCache
  const second = source.privateRouting.connect(server.publicKey)
  second.on('error', () => {})
  t.teardown(() => second.destroy())
  t.is(await second.opened, true, 'first reconnect after server refresh succeeds without failing')
  const echoed2 = new Promise((resolve) => second.once('data', (d) => resolve(d.toString())))
  second.write('post-refresh payload')
  t.is(await echoed2, 'post-refresh payload')

  // Destroy all 3 pinned source guards and verify immediate fallback onto remaining live relays
  const srcCtrl = server.controller.constructor
    ? first.rawStream?.link?.controller || source.privateRouting.createServer().controller
    : null
  const pinnedKeys = new Set(
    srcCtrl.sourceGuards.candidates().map((g) => g.publicKey.toString('hex'))
  )
  first.destroy()
  second.destroy()
  await Promise.all(
    relays
      .filter((r) => pinnedKeys.has(r.plugins.get('private-route').relayPublicKey.toString('hex')))
      .map((r) => r.destroy({ force: true }))
  )
  await server.controller._publish(server)
  const third = source.privateRouting.connect(server.publicKey)
  third.on('error', () => {})
  t.teardown(() => third.destroy())
  t.is(await third.opened, true, 'source recovers automatically when all 3 pinned guards die')
  t.is(source.privateRouting.exposureReport().directDestinationSends, 0)
})
