'use strict'

const test = require('brittle')
const b4a = require('b4a')
const HyperDHT = require('../..')
const createTestnet = require('../../testnet')
const { decodeDescriptor } = require('../../lib/private/overlay-descriptor-service')
const { createAdvancingClock, createPrivatePeerTestScope } = require('./helpers/private-peer')

const DAY = 86_400_000
const privateRouting = (relay) => ({
  release: 'alpha',
  acknowledgeAlpha: true,
  mode: 'optional',
  profile: 'standard',
  relay
})

async function network(t, { clock, observe = () => null } = {}) {
  const net = await createTestnet(1, { bootstrap: [] })
  const scope = createPrivatePeerTestScope()
  t.teardown(async () => {
    try {
      await net.destroy()
    } finally {
      scope.close()
    }
  })
  const nodes = [false, false, true, true, true, true, true, true].map((relay, index) =>
    scope.create(
      () =>
        net.createNode({
          ephemeral: false,
          firewalled: false,
          privateRouting: privateRouting(relay)
        }),
      { clock, observer: observe(index) }
    )
  )
  await Promise.all(nodes.map((node) => node.privateRouting.ready()))
  return { net, scope, nodes }
}

async function echo(t, source, server, value) {
  const stream = source.privateRouting.connect(server.publicKey)
  stream.on('error', () => {})
  t.teardown(() => stream.destroy())
  if (!(await stream.opened)) throw new Error('Private stream did not authenticate')
  const received = new Promise((resolve, reject) => {
    stream.once('data', resolve)
    stream.once('error', reject)
  })
  stream.write(value)
  t.alike(await received, value)
  return stream
}

test('scoped observations cannot mutate or gate routing and do not observe unrelated controllers', async (t) => {
  t.timeout(120_000)
  const kinds = new Set()
  const sourceSelections = []
  let mutableEvents = 0
  let calls = 0
  const never = new Promise(() => {})
  const {
    net,
    scope,
    nodes: [source, destination]
  } = await network(t, {
    observe() {
      return (event) => {
        calls++
        kinds.add(event.type)
        if (!Object.isFrozen(event)) mutableEvents++
        if (event.type === 'source-route-selected') {
          sourceSelections.push(b4a.from(event.firstSafetyRelayPublicKey))
        }
        for (const value of Object.values(event)) {
          if (b4a.isBuffer(value)) value.fill(0)
        }
        if (event.type === 'route-cell-sealed') throw new Error('Observer exception')
        if (event.type === 'control-write') return Promise.reject(new Error('Observer rejection'))
        if (event.type === 'route-transform') return never
      }
    }
  })
  const server = destination.privateRouting.createServer((stream) => {
    stream.on('error', () => {})
    stream.pipe(stream)
  })
  t.teardown(() => server.close())
  await server.listen(HyperDHT.keyPair())
  await echo(t, source, server, b4a.from('read-only scoped observation'))
  t.alike(
    kinds,
    new Set([
      'control-read',
      'control-write',
      'route-cell-sealed',
      'route-cell-opened',
      'route-transform',
      'source-route-selected',
      'descriptor-published'
    ])
  )
  t.is(mutableEvents, 0, 'callbacks receive frozen event records')
  const guards = scope.guards(source)
  const pinned = b4a.from(guards.source.current.publicKey)
  const alternates = guards.source.alternates.map((guard) => b4a.from(guard.publicKey))
  guards.source.current.publicKey.fill(0)
  for (const alternate of guards.source.alternates) alternate.publicKey.fill(0)
  await echo(t, source, server, b4a.from('snapshot mutation cannot redirect the next connection'))
  const afterMutation = scope.guards(source).source
  t.alike(
    afterMutation.current.publicKey,
    pinned,
    'snapshot mutation cannot replace the policy primary'
  )
  t.alike(
    afterMutation.alternates.map((guard) => guard.publicKey),
    alternates,
    'snapshot mutation cannot reorder alternates'
  )
  t.alike(
    sourceSelections[1],
    sourceSelections[0],
    'snapshot mutation cannot redirect the compatible circuit guard'
  )

  const unrelated = net.createNode({
    ephemeral: false,
    firewalled: false,
    privateRouting: privateRouting(false)
  })
  await unrelated.privateRouting.ready()
  await echo(
    t,
    unrelated,
    server,
    b4a.from('ordinary construction does not inherit a scoped observer')
  )
  t.is(
    sourceSelections.length,
    2,
    'no scoped observer receives the unrelated source controller event'
  )
  const beforeClose = calls
  scope.close()
  await echo(t, source, server, b4a.from('closing observation does not close the private context'))
  t.is(calls, beforeClose, 'scope close detaches every owned observer')
  t.exception(() => scope.guards(source), /closed/)
  t.exception(() => scope.create(() => unrelated), /closed/)
})

test('an advancing controller clock drives wall-clock revisions and jittered refresh before route expiry', async (t) => {
  t.timeout(150_000)
  const origin = (Math.floor(Date.now() / DAY) + 2) * DAY + DAY / 2
  const clock = createAdvancingClock({ now: origin, rate: 20 })
  const publications = []
  let resolvePublications
  const refreshed = new Promise((resolve) => {
    resolvePublications = resolve
  })
  const {
    nodes: [, destination]
  } = await network(t, {
    clock,
    observe(index) {
      if (index !== 1) return null
      return (event) => {
        if (event.type !== 'descriptor-published') return
        publications.push({ event, now: clock.now() })
        if (publications.length === 4) resolvePublications(true)
      }
    }
  })
  const server = destination.privateRouting.createServer()
  t.teardown(() => server.close())
  const before = BigInt(clock.now())
  await server.listen(HyperDHT.keyPair())
  const sequence = server._descriptor.readBigUInt64BE(137)
  const clockApplied = sequence >= before && sequence <= BigInt(clock.now())
  t.is(
    clockApplied,
    true,
    'the revision uses this controller clock rather than process-global time'
  )
  t.ok(Date.now() < origin - DAY, 'ordinary wall time remains independent')
  if (!clockApplied) return
  let timer
  const observed = await Promise.race([
    refreshed,
    new Promise((resolve) => {
      timer = setTimeout(() => resolve(false), 75_000)
    })
  ])
  clearTimeout(timer)
  t.is(observed, true, 'four publications occur without manual refresh or another application call')
  await server.close()
  if (!observed) return
  for (let index = 0; index < publications.length; index++) {
    const { event, now } = publications[index]
    const descriptor = decodeDescriptor(event.wire, { now })
    t.is(event.role, 'endpoint')
    t.is(event.relayPublicKey, null)
    t.is(descriptor.seq, event.seq)
    t.ok(
      event.refreshDelayMs > 0 && BigInt(event.refreshDelayMs) < event.expiresAt - BigInt(now),
      'refresh precedes this published route expiry'
    )
    if (index !== 0)
      t.ok(event.seq > publications[index - 1].event.seq, 'successive refreshes remain monotone')
  }
  t.ok(
    new Set(publications.map(({ event }) => event.refreshDelayMs)).size > 1,
    'refreshes do not retain a fixed correlating schedule'
  )
})
