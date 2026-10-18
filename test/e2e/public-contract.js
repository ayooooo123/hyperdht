'use strict'

const test = require('brittle')
const createTestnet = require('../../testnet')
const DHT = require('../..')
const observeUDP = require('./helpers/udp-oracle')
const { exchange } = require('./helpers/traffic')
const { endpoint, grant, sourceOptions } = require('../private/helpers/native-config')
const { TOPOLOGY_ROLE } = require('../../lib/private/protocol')

function privateRouting(relay = false) {
  return { ...sourceOptions(), relay }
}

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
      return 'native-v2'
    }
  })
  const inherited = Object.assign(Object.create({ profile: 'native-v2' }), privateRouting())
  delete inherited.profile
  const symbol = privateRouting()
  symbol[Symbol('unknown')] = true
  for (const privateOptions of [
    accessor,
    inherited,
    symbol,
    { ...privateRouting(), unknown: true },
    { ...privateRouting(), acknowledgeAlpha: false },
    { ...privateRouting(), profile: 'standard' },
    { ...privateRouting(), profile: 'unsupported' },
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
  t.is(getterCalls, 0, 'configuration accessors never execute')
  t.is(oracle.sockets.length, 0, 'rejected options cannot start networking')
  t.is(oracle.attempts.length, 0)
})

test('public-contract: frozen optional facade preserves ordinary direct connections', async (t) => {
  const oracle = observeUDP()
  t.teardown(() => oracle.restore())
  const net = await createTestnet(4, { host: '127.0.0.1' })
  const nodes = []
  t.teardown(async () => {
    for (let i = nodes.length - 1; i >= 0; i--) await nodes[i].destroy().catch(() => {})
    await net.destroy()
  })
  const bootstrap = [
    `${net.nodes[0].host}:${net.nodes[0].port}`,
    `${net.nodes[1].host}:${net.nodes[1].port}`
  ]
  const probe1 = new DHT({ host: '127.0.0.1', bootstrap })
  const probe2 = new DHT({ host: '127.0.0.1', bootstrap })
  await Promise.all([probe1.ready(), probe2.ready()])
  const port1 = probe1.address().port
  const port2 = probe2.address().port
  await Promise.all([probe1.destroy(), probe2.destroy()])

  const r1 = endpoint(port1, TOPOLOGY_ROLE.SAFETY_GUARD)
  const r2 = endpoint(port2, TOPOLOGY_ROLE.SAFETY_FINAL)
  const edge = grant(r1, r2)
  for (const [r, port] of [
    [r1, port1],
    [r2, port2]
  ]) {
    const relay = new DHT({
      host: '127.0.0.1',
      port,
      bootstrap,
      ephemeral: false,
      firewalled: false,
      privateRouting: {
        ...sourceOptions(),
        relay: true,
        relayConfig: {
          identityKeyPair: r.identity,
          authorityPublicKeys: [r.authority.publicKey],
          epoch: 7n,
          runId32: Buffer.alloc(32, 0x52),
          grants: [edge]
        }
      }
    })
    nodes.push(relay)
    await relay.ready()
  }
  await Promise.all(nodes.map((n) => n.privateRouting.ready()))

  const source = new DHT({
    host: '127.0.0.1',
    bootstrap,
    ephemeral: false,
    firewalled: false,
    privateRouting: sourceOptions()
  })
  const destination = new DHT({
    host: '127.0.0.1',
    bootstrap,
    ephemeral: false,
    firewalled: false,
    privateRouting: sourceOptions()
  })
  nodes.push(source, destination)
  await Promise.all([source.ready(), destination.ready()])
  await Promise.all([source.privateRouting.ready(), destination.privateRouting.ready()])

  t.ok(Object.isFrozen(source.privateRouting))
  t.is(source.privateRouting.profile, 'native-v2')
  t.is(source.privateRouting.status(), 'ready')
  t.is(source.privateRouting.relay, false)

  const keyPair = DHT.keyPair()
  let remote
  const accepted = new Promise((resolve) => {
    remote = resolve
  })
  const server = destination.createServer((sock) => {
    sock.on('error', () => {})
    remote(sock)
  })
  await server.listen(keyPair)
  const client = source.connect(keyPair.publicKey)
  client.on('error', () => {})
  t.is(await client.opened, true)
  const serverSock = await accepted
  t.alike(await exchange(client, serverSock), { up: 49157, down: 32771 })
  t.ok(
    oracle.forbidden(source, destination).some((row) => row.method === 'connect'),
    'ordinary connect still uses the native direct path'
  )
  client.destroy()
  serverSock.destroy()
  await server.close()
})
