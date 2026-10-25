'use strict'

const test = require('brittle')
const b4a = require('b4a')
const HyperDHT = require('../..')
const createTestnet = require('../../testnet')
const peer = require('../../lib/private/private-peer-controller')
const { decodeDescriptor } = require('../../lib/private/overlay-descriptor-service')
const { createAdvancingClock, createPrivatePeerTestScope } = require('./helpers/private-peer')

const DAY = 86_400_000

async function network(t, options = {}) {
  const net = await createTestnet(1, { bootstrap: [] })
  const scope = createPrivatePeerTestScope()
  const controllers = new Map()
  t.teardown(async () => {
    try {
      await Promise.allSettled(net.nodes.map((node) => node.destroy({ force: true })))
    } finally {
      scope.close()
    }
  })
  const createNode = (relay) => {
    const original = peer.createPrivatePeerController
    peer.createPrivatePeerController = (configuration) => {
      const controller = original(configuration)
      controllers.set(configuration.dht, controller)
      return controller
    }
    try {
      return scope.create(
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
        options
      )
    } finally {
      peer.createPrivatePeerController = original
    }
  }
  const nodes = [false, false, true, true, true, true, true, true].map(createNode)
  await Promise.all(nodes.map((node) => node.privateRouting.ready()))
  return { nodes, controllers, createNode }
}

async function until(predicate, milliseconds = 10_000) {
  const deadline = Date.now() + milliseconds
  while (!predicate()) {
    if (Date.now() >= deadline) return false
    await new Promise((resolve) => setTimeout(resolve, 5))
  }
  return true
}

function connect(t, source, server) {
  const stream = source.privateRouting.connect(server.publicKey)
  stream.on('error', () => {})
  t.teardown(() => stream.destroy())
  return stream
}

function exchange(stream, value, milliseconds = 5_000) {
  if (stream.destroying || stream.destroyed) return Promise.resolve(false)
  const expected = typeof value === 'string' ? b4a.from(value) : value
  return new Promise((resolve) => {
    let bytes = 0
    let intact = true
    const timer = setTimeout(() => finish(false), milliseconds)
    const data = (chunk) => {
      intact = intact && b4a.equals(chunk, expected.subarray(bytes, bytes + chunk.byteLength))
      bytes += chunk.byteLength
      if (bytes >= expected.byteLength) finish(intact && bytes === expected.byteLength)
    }
    const failed = () => finish(false)
    function finish(result) {
      clearTimeout(timer)
      stream.removeListener('data', data)
      stream.removeListener('error', failed)
      stream.removeListener('close', failed)
      resolve(result)
    }
    stream.on('data', data)
    stream.once('error', failed)
    stream.once('close', failed)
    stream.write(expected)
  })
}

async function listen(t, destination) {
  const accepted = []
  const live = new Set()
  const server = destination.privateRouting.createServer((stream) => {
    stream.on('error', () => {})
    stream.on('data', (data) => stream.write(data))
    stream.on('end', () => stream.end())
    stream.once('close', () => live.delete(stream))
    accepted.push(stream)
    live.add(stream)
  })
  t.teardown(() => server.close())
  await server.listen(HyperDHT.keyPair())
  return { server, accepted, live }
}

function entryCircuit(controllers, server) {
  const descriptor = decodeDescriptor(server._descriptor, { now: server.controller.clock.now() })
  const owner = [...controllers.values()].find(
    (controller) =>
      controller.relayKeyPair &&
      b4a.equals(controller.relayKeyPair.publicKey, descriptor.entryRelayPublicKey)
  )
  return owner.entryCircuits.get(b4a.toString(descriptor.routeToken, 'hex'))
}

async function finish(stream, remote) {
  if (stream.destroyed && remote.destroyed) return true
  stream.resume()
  stream.end()
  return until(() => stream.destroyed && remote.destroyed)
}

test('refresh across a blinded period preserves a backpressured stream beyond the old admission expiry', async (t) => {
  t.timeout(120_000)
  const origin = (Math.floor(Date.now() / DAY) + 1) * DAY - 5 * 60_000
  const clock = createAdvancingClock({ now: origin, rate: 40 })
  const publications = []
  const {
    nodes: [source, destination]
  } = await network(t, {
    clock,
    observer(event) {
      if (event.type === 'descriptor-published') publications.push(event)
    }
  })
  const { server, accepted } = await listen(t, destination)
  const original = server._route
  const descriptor = decodeDescriptor(server._descriptor, { now: clock.now() })
  t.is(
    descriptor.period,
    BigInt(Math.floor(origin / DAY)),
    'the fixture publishes before the period boundary'
  )
  const client = connect(t, source, server)
  t.is(await client.opened, true, 'the original application stream authenticates')
  t.is(await exchange(client, 'before the period boundary'), true)
  const remote = accepted[0]
  remote.rawStream.pause()
  const resumed = exchange(client, b4a.alloc(1024 * 1024, 0x6b), 45_000)
  t.ok(
    await until(() => client.rawStream.sendCredit === 0 && client.rawStream.creditWaiter !== null),
    'the old reader exhausts its writer stream window'
  )
  t.ok(
    await until(
      () =>
        server._route !== original &&
        publications.some((event) => event.period > descriptor.period),
      30_000
    ),
    'automatic refresh publishes in the next blinded period'
  )
  t.is(original.closed, false, 'publication does not destroy the still-active old route')
  t.ok(
    await until(() => BigInt(clock.now()) > descriptor.expiresAt, 20_000),
    'the original admission interval expires'
  )
  t.is(original.closed, false, 'admission expiry does not destroy buffered application data')
  remote.rawStream.resume()
  t.is(await resumed, true, 'the complete backpressured record resumes on its original route')
  t.is(
    await exchange(client, 'old stream after expiry'),
    true,
    'the old authenticated stream remains bidirectional'
  )
  const newcomer = connect(t, source, server)
  t.is(await newcomer.opened, true, 'a new connection uses the replacement publication')
  t.is(await exchange(newcomer, 'new period stream'), true)
  await finish(client, remote)
  t.ok(
    await until(() => original.closed),
    'the retired route is reclaimed after its last application stream closes'
  )
  t.is(await exchange(newcomer, 'new stream after old-route reclamation'), true)
})

test('seventy sequential streams reuse a live route budget without reusing retired identifiers', async (t) => {
  t.timeout(180_000)
  const {
    nodes: [source, destination],
    controllers
  } = await network(t)
  const { server, accepted } = await listen(t, destination)
  const original = server._route
  const entry = entryCircuit(controllers, server)
  const identifiers = new Set()
  let completed = 0
  for (let index = 0; index < 70; index++) {
    const client = connect(t, source, server)
    if (!(await client.opened)) break
    const remote = accepted[accepted.length - 1]
    identifiers.add(remote.rawStream.streamId)
    if (!(await exchange(client, 'sequential ' + index))) break
    if (!(await finish(client, remote))) break
    if (!(await until(() => entry.sources.size === 0))) break
    completed++
  }
  t.is(completed, 70, 'all seventy sequential application sessions complete')
  t.is(identifiers.size, 70, 'closed stream IDs are never reused')
  t.is(server._route, original, 'the route is not replaced to hide a lifetime admission limit')
  t.is(original.streams.size, 0, 'all destination stream reservations return after close')
  t.is(entry.sources.size, 0, 'all entry stream reservations return after close')

  const sibling = connect(t, source, server)
  t.is(await sibling.opened, true, 'a subsequent sibling can still authenticate')
  if (sibling.destroyed || sibling.destroying) return
  // Reach the final legal wire identifier without allocating billions of sessions.
  entry.nextStreamId = 0xffff_fffe
  const last = connect(t, source, server)
  t.is(await last.opened, true, 'the final even uint32 identifier remains usable')
  t.is(accepted[accepted.length - 1].rawStream.streamId, 0xffff_fffe)
  const exhausted = connect(t, source, server)
  t.is(
    await exhausted.opened,
    false,
    'identifier exhaustion cannot wrap into a retired ID or the circuit scope'
  )
  t.is(
    await exchange(last, 'last identifier'),
    true,
    'exhaustion leaves its existing stream usable'
  )
  t.is(
    await exchange(sibling, 'sibling at identifier exhaustion'),
    true,
    'exhaustion does not close a sibling'
  )
})

test('overlapping destination routes share one sixty-four-session admission budget', async (t) => {
  t.timeout(180_000)
  const {
    nodes: [source, destination]
  } = await network(t)
  const { server, accepted, live } = await listen(t, destination)
  const clients = []
  for (let index = 0; index < 63; index++) {
    const client = connect(t, source, server)
    if (!(await client.opened))
      throw new Error('Overlap fixture could not authenticate its original streams')
    clients.push(client)
  }
  const original = server._route
  const originalPeer = accepted[0]
  await server.controller._publish(server)
  t.not(server._route, original, 'refresh installs another admission route')
  const next = connect(t, source, server)
  t.is(await next.opened, true, 'the last available slot can be used on the replacement route')
  t.is(live.size, 64, 'the original and replacement routes coexist at the shared limit')
  t.is(await exchange(clients[0], 'old route at shared capacity'), true)
  const overflow = connect(t, source, server)
  const overflowOpened = await overflow.opened
  t.is(
    overflowOpened,
    false,
    'a sixty-fifth simultaneous session is refused without a route-wide reset'
  )
  if (overflowOpened) {
    const overflowPeer = accepted[accepted.length - 1]
    overflow.destroy()
    overflowPeer.destroy()
    await until(() => !live.has(overflowPeer))
  }
  t.is(await exchange(next, 'replacement route after refusal'), true)
  await finish(clients[0], originalPeer)
  t.ok(
    await until(() => !live.has(originalPeer)),
    'closing an old-route session releases its shared reservation'
  )
  const replacement = connect(t, source, server)
  t.is(await replacement.opened, true, 'the freed reservation can be admitted on the new route')
  t.is(await exchange(replacement, 'reused reservation'), true)
  t.is(live.size, 64, 'reusing a reservation does not increase the concurrent ceiling')
})

test('destination guard loss republishes within twenty real seconds without an application refresh call', async (t) => {
  t.timeout(120_000)
  const {
    nodes: [source, destination, ...relays],
    controllers,
    createNode
  } = await network(t)
  const { server } = await listen(t, destination)
  const client = connect(t, source, server)
  t.is(await client.opened, true)
  t.is(await exchange(client, 'before guard loss'), true)
  const original = server._route
  const guard = decodeDescriptor(server._descriptor).destinationGuardPublicKey
  const failed = relays.find((node) =>
    b4a.equals(controllers.get(node).relayKeyPair.publicKey, guard)
  )
  const started = Date.now()
  const stopped = failed.destroy({ force: true })
  stopped.catch(() => {})
  t.teardown(() => stopped)
  const republished = await until(
    () => server._route && server._route !== original && !server._route.closed,
    20_000
  )
  t.ok(republished, 'the listener publishes a replacement within the existing real deadline')
  if (!republished) return
  t.ok(
    Date.now() - started < 20_000,
    'recovery includes detection, guard replacement and publication'
  )
  const descriptor = decodeDescriptor(server._descriptor)
  t.not(
    b4a.toString(descriptor.destinationGuardPublicKey, 'hex'),
    b4a.toString(guard, 'hex'),
    'the replacement does not select the failed guard'
  )
  t.not(
    b4a.toString(descriptor.entryRelayPublicKey, 'hex'),
    b4a.toString(guard, 'hex'),
    'the failed guard is not immediately retried as an entry'
  )
  await stopped
  const newcomer = createNode(false)
  await newcomer.privateRouting.ready()
  const replacement = connect(t, newcomer, server)
  t.is(
    await replacement.opened,
    true,
    'a fresh caller can authenticate through the recovered listener'
  )
  t.is(await exchange(replacement, 'after guard loss'), true)

  const policy = controllers.get(source).sourceGuards
  const pin = (publicKey) => ({
    publicKey: b4a.from(publicKey),
    diversityKey: null,
    unreachable: false
  })
  // This allowed pinned set has no healthy source guard distinct from both
  // destination roles. Recovery must not bypass the caller's guard policy.
  policy.current = pin(descriptor.destinationGuardPublicKey)
  policy.alternates = [pin(descriptor.entryRelayPublicKey), pin(guard)]
  policy.rotateAt = controllers.get(source).clock.now() + DAY
  const exhausted = connect(t, source, server)
  t.is(await exhausted.opened, false, 'an exhausted pinned set fails closed')
  t.alike(
    policy.current.publicKey,
    descriptor.destinationGuardPublicKey,
    'a role collision does not replace a healthy pinned primary'
  )
})
