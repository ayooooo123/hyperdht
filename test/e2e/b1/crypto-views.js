'use strict'

const test = require('../helpers/pending')
const network = require('../helpers/network')
const { DHT, closePair } = network
const { exchange } = require('../helpers/traffic')
const relayViews = require('../support/relay-views')

test('B1 E1: no relay receives the stable destination key across twenty connects and five refreshes', async (t) => {
  const h = await network(t)
  const identity = DHT.keyPair()
  const views = relayViews(h, identity.publicKey)
  t.teardown(() => views.close())
  const server = await h.listen({}, h.destination, identity)
  for (let i = 0; i < 20; i++) {
    const pair = await h.pair(server)
    await exchange(pair.client, pair.remote, { up: 4099, down: 8197, seed: i + 1 })
    await closePair(pair)
    if ((i + 1) % 4 === 0) await server.controller._publish(server)
  }
  const counts = views.counts()
  t.alike(Array.from(views.errors), [], 'relay observations decode without namespace confusion')
  t.ok(
    counts.reads >= 20 && counts.writes >= 20 && counts.plaintexts >= 20,
    'all three relay observation surfaces were exercised'
  )
  t.is(
    views.leaks.length,
    0,
    'stable key is absent from control reads, writes and opened cell plaintext'
  )
  if (views.leaks.length) t.comment('First disclosure: ' + JSON.stringify(views.leaks[0]))
})

test('B1 E3: link epochs and counters are unrelated for the same forwarded frame', async (t) => {
  const h = await network(t)
  const identity = DHT.keyPair()
  const views = relayViews(h, identity.publicKey)
  t.teardown(() => views.close())
  const server = await h.listen({}, h.destination, identity)
  const pair = await h.pair(server)
  await exchange(pair.client, pair.remote, { up: 1048583, down: 524309 })
  t.alike(Array.from(views.errors), [], 'DATA and flow-control frames decode independently')
  for (const scope of ['stream', 'circuit']) {
    t.ok(
      views.headers.some((header) => header.type === 'credit' && header.scope === scope),
      scope + ' CREDIT is identified separately from application DATA'
    )
  }
  const groups = new Map()
  for (const header of views.headers) {
    if (header.type !== 'data' || header.payload.length < 64) continue
    const id = header.direction + ':' + header.payload
    if (!groups.has(id)) groups.set(id, new Map())
    groups.get(id).set(header.view, header)
  }
  const sameFrame = Array.from(groups.values()).find((links) => links.size >= 3)
  t.ok(sameFrame, 'one authenticated frame is observed on at least three links')
  if (!sameFrame) return
  const headers = Array.from(sameFrame.values())
  t.is(new Set(headers.map((header) => header.epoch.toString())).size, headers.length)
  t.is(
    new Set(headers.map((header) => header.counter.toString())).size,
    headers.length,
    'same-frame counters do not align across links'
  )
  t.absent(
    headers.some((header) => Math.abs(Number(header.epoch >> 16n) - header.at) < 60000),
    'epochs do not expose circuit creation wall time'
  )
  const first = new Map()
  for (const header of views.headers) {
    const id = header.view
    if (!first.has(id)) first.set(id, header.counter.toString())
  }
  t.is(
    new Set(first.values()).size,
    first.size,
    'first counter origins are independent across directed links'
  )
  t.ok(
    views.headers.every((header) => header.cellBytes === 1200),
    'all observed authenticated cells retain fixed 1200-byte framing'
  )
})
