'use strict'

const test = require('../helpers/pending')
const b4a = require('b4a')
const network = require('../helpers/network')
const { closePair, deadline } = network
const { exchange } = require('../helpers/traffic')
const { decodeDescriptor } = require('../../../lib/private/overlay-descriptor-service')
const { createAdvancingClock } = require('../support/private-peer')

const hex = (bytes) => b4a.toString(bytes, 'hex')
const guardOrder = (snapshot) =>
  [snapshot.current, ...snapshot.alternates].map((guard) => hex(guard.publicKey))

function assertRoute(t, pair, route) {
  if (!route) throw new Error('Missing source-route-selected observation')
  t.alike(
    pair.client.rawStream.link.rawStream.remotePublicKey,
    route.firstSafetyRelayPublicKey,
    'per-circuit usage matches the authenticated first adjacency'
  )
  t.is(
    new Set(
      [
        route.firstSafetyRelayPublicKey,
        route.secondSafetyRelayPublicKey,
        route.entryRelayPublicKey,
        route.destinationGuardPublicKey
      ].map(hex)
    ).size,
    4,
    'the actual circuit has four distinct relay roles'
  )
}

test('B1 E6: refreshes and role collisions preserve policy while actual primary failure promotes', async (t) => {
  const clock = createAdvancingClock({ rate: 4 })
  let route = null
  const h = await network(t, {
    clock,
    observer(event) {
      if (event.type === 'source-route-selected') route = event
    }
  })
  const server = await h.listen()
  const original = decodeDescriptor(server._descriptor, { now: clock.now() })
  const source = h.controller(h.source)
  // Seed policy from real fixture identities; observations never choose the route.
  source.sourceGuards.ensure(
    h.relays
      .map((node) => h.controller(node).relayKeyPair.publicKey)
      .filter(
        (key) =>
          !b4a.equals(key, original.entryRelayPublicKey) &&
          !b4a.equals(key, original.destinationGuardPublicKey)
      ),
    clock.now()
  )
  const pinned = h.scope.guards(h.source).source
  const originalOrder = guardOrder(pinned)
  const primary = pinned.current.publicKey
  const alternate = pinned.alternates[0].publicKey
  let seed = 0

  async function connect(expectedFirst = null, healthy = true) {
    route = null
    const pair = await h.pair(server)
    assertRoute(t, pair, route)
    const compatible = [pinned.current, ...pinned.alternates].find(
      (guard) =>
        !b4a.equals(guard.publicKey, route.entryRelayPublicKey) &&
        !b4a.equals(guard.publicKey, route.destinationGuardPublicKey)
    )
    t.alike(
      route.firstSafetyRelayPublicKey,
      expectedFirst || compatible.publicKey,
      'the circuit uses the first role-compatible pinned guard'
    )
    if (healthy) {
      t.alike(
        guardOrder(h.scope.guards(h.source).source),
        originalOrder,
        'healthy connections and role collisions do not promote or reorder policy'
      )
    }
    t.alike(await exchange(pair.client, pair.remote, { up: 1027, down: 2053, seed: ++seed }), {
      up: 1027,
      down: 2053
    })
    await closePair(pair)
  }

  await connect(primary)
  await server.controller._publishThroughGuard(server, server._guards.current, primary)
  t.alike(
    decodeDescriptor(server._descriptor, { now: clock.now() }).entryRelayPublicKey,
    primary,
    'the published destination entry actually collides with the source primary'
  )
  await connect(alternate)
  await server.controller._publishThroughGuard(
    server,
    server._guards.current,
    original.entryRelayPublicKey
  )
  await connect(primary)

  for (let i = 0; i < 10; i++) {
    await server.controller._publish(server)
    t.alike(
      decodeDescriptor(server._descriptor, { now: clock.now() }).destinationGuardPublicKey,
      original.destinationGuardPublicKey,
      'a healthy destination primary stays pinned across refreshes'
    )
    await connect()
  }

  // Keep destination roles compatible so this case isolates actual source failure.
  await server.controller._publishThroughGuard(
    server,
    server._guards.current,
    original.entryRelayPublicKey
  )
  const failed = h.relays.find((node) =>
    b4a.equals(h.controller(node).relayKeyPair.publicKey, primary)
  )
  await failed.destroy({ force: true })
  await connect(alternate, false)
  t.alike(
    h.scope.guards(h.source).source.current.publicKey,
    alternate,
    'actual primary failure promotes the next pinned alternate'
  )
})

test('B1 E6: destination guard loss republishes its pinned alternate within twenty seconds', async (t) => {
  const clock = createAdvancingClock({ rate: 4 })
  let route = null
  const h = await network(t, {
    clock,
    observer(event) {
      if (event.type === 'source-route-selected') route = event
    }
  })
  const server = await h.listen()
  const snapshot = h.scope
    .guards(h.destination)
    .destinations.find((row) => b4a.equals(row.publicKey, server.publicKey))
  const descriptor = decodeDescriptor(server._descriptor, { now: clock.now() })
  t.alike(snapshot.current.publicKey, descriptor.destinationGuardPublicKey)
  const expected = snapshot.alternates[0].publicKey
  const selected = h.relays.find((node) =>
    b4a.equals(h.controller(node).relayKeyPair.publicKey, snapshot.current.publicKey)
  )
  let stop
  const republished = new Promise((resolve) => {
    stop = h.observe((event) => {
      if (event.type === 'descriptor-published') resolve(event)
    })
  })
  try {
    await selected.destroy({ force: true })
    await deadline(republished, 'immediate publication after guard loss', 20000)
  } finally {
    stop()
  }
  const replacement = h.scope
    .guards(h.destination)
    .destinations.find((row) => b4a.equals(row.publicKey, server.publicKey))
  t.alike(
    replacement.current.publicKey,
    expected,
    'destination failure promotes its first alternate'
  )
  t.alike(
    decodeDescriptor(server._descriptor, { now: clock.now() }).destinationGuardPublicKey,
    expected,
    'the replacement descriptor publishes the promoted guard'
  )
  route = null
  const pair = await h.pair(server)
  assertRoute(t, pair, route)
  t.alike(route.destinationGuardPublicKey, expected)
  t.alike(await exchange(pair.client, pair.remote), { up: 49157, down: 32771 })
  await closePair(pair)
})
