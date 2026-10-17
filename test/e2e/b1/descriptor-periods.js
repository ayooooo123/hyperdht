'use strict'

const test = require('../helpers/pending')
const b4a = require('b4a')
const network = require('../helpers/network')
const { createAdvancingClock } = require('../support/private-peer')
const { decodeDescriptor } = require('../../../lib/private/overlay-descriptor-service')
const { exchange } = require('../helpers/traffic')

function coalition(h) {
  const records = new Map()
  for (const node of h.net.nodes) {
    const plugin = node.plugins.get('private-route')
    if (!plugin) continue
    for (const [target, record] of plugin.records)
      records.set(target, {
        seq: record.seq,
        period: record.period,
        key: b4a.from(record.blindedPublicKey)
      })
  }
  return records
}

test('B1 E4: storage coalition cannot link consecutive periods by sequence continuity', async (t) => {
  const day = 86400000
  const boundary = Math.ceil(Date.now() / day) * day
  const clock = createAdvancingClock({ now: boundary - 40000, rate: 4 })
  const publications = []
  const h = await network(t, {
    clock,
    observer(event) {
      if (event.type === 'descriptor-published') publications.push(event)
    }
  })
  function published(server) {
    const event = publications.findLast((row) => b4a.equals(row.wire, server._descriptor))
    if (!event) throw new Error('Missing descriptor-published view for the created listener')
    return decodeDescriptor(event.wire, { now: clock.now() })
  }
  const servers = [await h.listen(), await h.listen()]
  const before = servers.map(published)
  const oldView = coalition(h)
  t.ok(
    before.every((record) => record.period === BigInt(boundary / day - 1)),
    'both services publish before the period boundary'
  )
  const live = await h.pair(servers[0])
  await exchange(live.client, live.remote, { id: 'period-before' })
  await new Promise((resolve) =>
    clock.setTimeout(resolve, Math.max(1, boundary + 20 - clock.now()))
  )
  for (const server of servers) await server.controller._publish(server)
  const after = servers.map(published)
  const newView = coalition(h)
  for (let i = 0; i < servers.length; i++) {
    t.is(after[i].period, before[i].period + 1n)
    t.absent(b4a.equals(before[i].blindedPublicKey, after[i].blindedPublicKey))
    t.not(
      after[i].seq,
      before[i].seq + 1n,
      'cross-period revision is not the old service counter plus one'
    )
    t.ok(
      Array.from(oldView.values()).some((row) => b4a.equals(row.key, before[i].blindedPublicKey))
    )
    t.ok(Array.from(newView.values()).some((row) => b4a.equals(row.key, after[i].blindedPublicKey)))
  }
  const links = []
  for (const old of oldView.values())
    for (const next of newView.values()) {
      if (next.period === old.period + 1n && next.seq === old.seq + 1n)
        links.push([old.key, next.key])
    }
  t.is(links.length, 0, 'the seq-plus-one coalition linker has no match')
  t.alike(await exchange(live.client, live.remote, { id: 'period-after' }), {
    up: 49157,
    down: 32771
  })
  const newcomer = await h.pair(servers[0])
  t.alike(await exchange(newcomer.client, newcomer.remote, { id: 'period-newcomer' }), {
    up: 49157,
    down: 32771
  })
})
