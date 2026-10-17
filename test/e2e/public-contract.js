'use strict'

const test = require('brittle')
const { DHT, privateRouting } = require('./helpers/network')
const network = require('./helpers/network')
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
      return 'standard'
    }
  })
  const inherited = Object.assign(Object.create({ profile: 'standard' }), privateRouting())
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
  const h = await network(t)
  t.ok(Object.isFrozen(h.source.privateRouting))
  t.is(h.source.privateRouting.status(), 'READY')
  t.is(h.source.privateRouting.relay, false)
  const server = await h.listen({}, h.destination, DHT.keyPair(), true)
  const { client, remote } = await h.pair(server, {}, h.source, true)
  t.alike(await exchange(client, remote), { up: 49157, down: 32771 })
  t.ok(
    h.oracle.forbidden(h.source, h.destination).some((row) => row.method === 'connect'),
    'ordinary connect still uses the native direct path'
  )
})
