'use strict'

const test = require('brittle')
const b4a = require('b4a')
const HyperDHT = require('../..')
const createTestnet = require('../../testnet')
const { createPrivatePeerTestScope } = require('./helpers/private-peer')
const peer = require('../../lib/private/private-peer-controller')
const { decodeDescriptor } = require('../../lib/private/overlay-descriptor-service')

const hex = (bytes) => b4a.toString(bytes, 'hex')

async function network(t, observer = null) {
  const net = await createTestnet(1, { bootstrap: [] })
  const scope = createPrivatePeerTestScope()
  t.teardown(async () => {
    try {
      await Promise.allSettled(net.nodes.map((node) => node.destroy({ force: true })))
    } finally {
      scope.close()
    }
  })
  const controllers = new Map()
  const original = peer.createPrivatePeerController
  peer.createPrivatePeerController = (options) => {
    const controller = original(options)
    controllers.set(options.dht, controller)
    return controller
  }
  let nodes
  try {
    nodes = [false, false, true, true, true, true, true, true].map((relay) =>
      scope.create(
        () =>
          net.createNode({
            ephemeral: false,
            firewalled: false,
            privateRouting: {
              release: 'alpha',
              acknowledgeAlpha: true,
              mode: 'optional',
              profile: 'standard',
              relay
            }
          }),
        { observer }
      )
    )
  } finally {
    peer.createPrivatePeerController = original
  }
  await Promise.all(nodes.map((node) => node.privateRouting.ready()))
  return { nodes, controllers, scope }
}

function readByte(stream) {
  return new Promise((resolve, reject) => {
    stream.once('data', resolve)
    stream.once('error', reject)
  })
}

test('healthy source and destination guards remain pinned and fail over to their ordered alternates', async (t) => {
  t.timeout(180_000)
  const sourceGuards = []
  const { nodes, controllers } = await network(t, (event) => {
    if (event.type === 'source-route-selected')
      sourceGuards.push(hex(event.firstSafetyRelayPublicKey))
  })
  const [source, destination] = nodes
  const server = destination.privateRouting.createServer((stream) => {
    stream.on('error', () => {})
    stream.pipe(stream)
  })
  t.teardown(() => server.close())
  await server.listen(HyperDHT.keyPair())
  const destinationGuards = [hex(decodeDescriptor(server._descriptor).destinationGuardPublicKey)]
  for (let i = 0; i < 10; i++) {
    await server.controller._publish(server)
    destinationGuards.push(hex(decodeDescriptor(server._descriptor).destinationGuardPublicKey))
  }
  t.is(new Set(destinationGuards).size, 1, 'ten refreshes retain the healthy destination guard')
  const initialTail = decodeDescriptor(server._descriptor)
  controllers.get(source).sourceGuards.ensure(
    nodes
      .slice(2)
      .map((node) => controllers.get(node).relayKeyPair.publicKey)
      .filter(
        (publicKey) =>
          !b4a.equals(publicKey, initialTail.destinationGuardPublicKey) &&
          !b4a.equals(publicKey, initialTail.entryRelayPublicKey)
      ),
    controllers.get(source).clock.now()
  )
  for (let i = 0; i < 10; i++) {
    const client = source.privateRouting.connect(server.publicKey)
    client.on('error', () => {})
    const opened = await client.opened
    t.is(opened, true)
    if (!opened) {
      client.destroy()
      continue
    }
    const echoed = readByte(client)
    client.write(b4a.from([i]))
    t.alike(await echoed, b4a.from([i]))
    client.destroy()
  }
  t.is(new Set(sourceGuards).size, 1, 'ten connections retain the healthy source guard')

  const sourcePinned = controllers.get(source).sourceGuards
  t.ok(
    sourcePinned && sourcePinned.alternates.length > 0,
    'source failover has preselected alternates'
  )
  if (!sourcePinned || sourcePinned.alternates.length === 0) return
  const sourcePrimary = hex(sourcePinned.current.publicKey)
  let sourceAlternate = null
  for (let i = 0; i < 20; i++) {
    const descriptor = decodeDescriptor(server._descriptor)
    if (hex(descriptor.entryRelayPublicKey) !== sourcePrimary) {
      sourceAlternate = sourcePinned.alternates.find(
        (guard) =>
          !b4a.equals(guard.publicKey, descriptor.entryRelayPublicKey) &&
          !b4a.equals(guard.publicKey, descriptor.destinationGuardPublicKey)
      )
      if (sourceAlternate) break
    }
    await server.controller._publish(server)
  }
  t.ok(sourceAlternate, 'the failure scenario has an eligible pinned source alternate')
  if (!sourceAlternate) return
  const expectedSource = hex(sourceAlternate.publicKey)
  const failedSource = nodes.find((node) => {
    const controller = controllers.get(node)
    return controller.relayKeyPair && hex(controller.relayKeyPair.publicKey) === sourcePrimary
  })
  await failedSource.destroy({ force: true })
  const client = source.privateRouting.connect(server.publicKey)
  client.on('error', () => {})
  t.teardown(() => client.destroy())
  t.is(await client.opened, true)
  t.is(
    sourceGuards[sourceGuards.length - 1],
    expectedSource,
    'source failover uses the next eligible pinned guard'
  )

  const pinned = server._guards
  t.ok(pinned && pinned.alternates.length > 0, 'destination failover has preselected alternates')
  const primary = hex(pinned.current.publicKey)
  const alternate = pinned.alternates.find((guard) => hex(guard.publicKey) !== sourcePrimary)
  t.ok(alternate)
  const expectedDestination = hex(alternate.publicKey)
  const failedDestination = nodes.find((node) => {
    const controller = controllers.get(node)
    return controller.relayKeyPair && hex(controller.relayKeyPair.publicKey) === primary
  })
  await failedDestination.destroy({ force: true })
  await server.controller._publish(server)
  t.is(
    hex(decodeDescriptor(server._descriptor).destinationGuardPublicKey),
    expectedDestination,
    'destination failover uses the next live pinned guard'
  )
})

test('an absent destination exposes the source to at most three circuit-build attempts', async (t) => {
  t.timeout(120_000)
  const { nodes, controllers } = await network(t)
  const source = nodes[0]
  const controller = controllers.get(source)
  const dial = controller.connectDirect
  const attempts = []
  controller.connectDirect = function (publicKey, options) {
    attempts.push(hex(publicKey))
    return dial.call(this, publicKey, options)
  }
  const missing = HyperDHT.keyPair().publicKey
  const client = source.privateRouting.connect(missing)
  client.on('error', () => {})
  t.teardown(() => client.destroy())
  t.is(await client.opened, false, 'an absent private destination fails closed')
  t.ok(attempts.length > 0 && attempts.length <= 3, 'first-safety dials have a per-connect bound')
  t.is(attempts.includes(hex(missing)), false, 'there is no direct destination fallback')
})

test('destination role collisions cannot change persistent source guard policy', async (t) => {
  t.timeout(180_000)
  let route
  const { nodes, controllers, scope } = await network(t, (event) => {
    if (event.type === 'source-route-selected') route = event
  })
  const [source, destination] = nodes
  const accepted = []
  const server = destination.privateRouting.createServer((stream) => {
    stream.on('error', () => {})
    accepted.push(stream)
    stream.pipe(stream)
  })
  t.teardown(() => server.close())
  await server.listen(HyperDHT.keyPair())
  const descriptor = decodeDescriptor(server._descriptor)
  const sourceController = controllers.get(source)
  const eligible = nodes
    .slice(2)
    .map((node) => controllers.get(node).relayKeyPair.publicKey)
    .filter(
      (publicKey) =>
        !b4a.equals(publicKey, descriptor.destinationGuardPublicKey) &&
        !b4a.equals(publicKey, descriptor.entryRelayPublicKey)
    )
  // Seed a legitimate pinned set from actual fixture relays so the destination
  // can deterministically impose a circuit-specific collision, without a gate.
  sourceController.sourceGuards.ensure(eligible, sourceController.clock.now())
  const pinned = scope.guards(source).source
  const primary = pinned.current.publicKey
  const alternate = pinned.alternates[0].publicKey
  const order = (snapshot) =>
    [snapshot.current, ...snapshot.alternates].map((guard) => hex(guard.publicKey))
  const originalOrder = order(pinned)
  async function probe() {
    const client = source.privateRouting.connect(server.publicKey)
    client.on('error', () => {})
    t.teardown(() => client.destroy())
    if (!(await client.opened)) throw new Error('Private stream did not authenticate')
    const remote = accepted[accepted.length - 1]
    const response = readByte(client)
    client.write(b4a.from('pinned route'))
    t.alike(await response, b4a.from('pinned route'))
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
      'the actual circuit has four distinct roles'
    )
    t.alike(client.rawStream.link.rawStream.remotePublicKey, route.firstSafetyRelayPublicKey)
    const closes = Promise.all([
      new Promise((resolve) => client.once('close', resolve)),
      new Promise((resolve) => remote.once('close', resolve))
    ])
    client.destroy()
    await closes
    return route.firstSafetyRelayPublicKey
  }
  t.alike(await probe(), primary, 'the initial compatible circuit prefers the primary')
  await server.controller._publishThroughGuard(server, server._guards.current, primary)
  t.alike(
    decodeDescriptor(server._descriptor).entryRelayPublicKey,
    primary,
    'the destination actually published the colliding entry'
  )
  t.alike(await probe(), alternate, 'the colliding circuit uses the first compatible alternate')
  t.alike(
    order(scope.guards(source).source),
    originalOrder,
    'a destination-controlled collision cannot reorder persistent guards'
  )
  await server.controller._publishThroughGuard(
    server,
    server._guards.current,
    descriptor.entryRelayPublicKey
  )
  t.alike(await probe(), primary, 'the next non-colliding circuit returns to the primary')
  t.alike(order(scope.guards(source).source), originalOrder)
  const primaryNode = nodes
    .slice(2)
    .find((node) => b4a.equals(controllers.get(node).relayKeyPair.publicKey, primary))
  await primaryNode.destroy({ force: true })
  t.alike(await probe(), alternate, 'actual primary failure uses the next alternate')
  t.alike(
    scope.guards(source).source.current.publicKey,
    alternate,
    'actual failure, unlike a collision, promotes the alternate'
  )
})
