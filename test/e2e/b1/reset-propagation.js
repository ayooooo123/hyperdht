'use strict'

const test = require('../helpers/pending')
const b4a = require('b4a')
const network = require('../helpers/network')
const { closed, deadline } = network
const { exchange, pattern } = require('../helpers/traffic')
const { decodeDescriptor } = require('../../../lib/private/overlay-descriptor-service')

async function reserveInjectedData(pool) {
  const expires = Date.now() + 10_000
  // Do not release a sibling's unused grant: that changes its demand-rate
  // state before the immediate echo. Wait for genuinely unallocated credit.
  while (!pool.closed && pool.available < 1 && Date.now() < expires) {
    await new Promise((resolve) => setTimeout(resolve, 5))
  }
  if (pool.closed || pool.available < 1)
    throw new Error('No circuit credit available for hostile DATA fixture')
  // This fixture bypasses the ordinary writer, so it must also own its debit.
  // Retired DATA is discarded by the receiver but still returns circuit credit.
  pool.available--
  pool.inFlight++
}

function poolTotal(pool) {
  let total = pool.available + pool.inFlight
  for (const leg of pool.legs.values()) total += leg.granted
  return total
}

test('B1 R5: source reset reaches the peer, retires its ID, and late frames cannot affect siblings', async (t) => {
  const h = await network(t)
  const server = await h.listen()
  const first = await h.pair(server)
  const firstId = Array.from(server._route.streams.keys())[0]
  const sourceId = first.client.rawStream.streamId
  const sibling = await h.pair(server)
  let resets = 0
  let started
  const sending = new Promise((resolve) => {
    started = resolve
  })
  h.observe((event) => {
    if (
      event.type === 'route-cell-sealed' &&
      event.label === 'source-endpoint' &&
      event.plaintext[4] === 0 &&
      event.plaintext.readUInt32BE(0) === sourceId
    )
      started()
    if (
      event.type === 'route-cell-opened' &&
      event.label === 'destination-endpoint' &&
      event.plaintext[4] === 3 &&
      event.plaintext.readUInt32BE(0) === firstId
    )
      resets++
  })
  first.remote.resume()
  t.absent(
    first.client.write(pattern(65536)),
    'the reset interrupts a backpressured application write'
  )
  await deadline(sending, 'first in-flight DATA cell')
  const closes = Promise.all([closed(first.client), closed(first.remote)])
  first.client.destroy()
  await deadline(closes, 'reset propagation')
  t.is(resets, 1, 'one local destroy delivers exactly one destination RESET')
  t.ok(
    firstId <= server._route.lastStreamId && !server._route.streams.has(firstId),
    'the peer retires the reset stream below its admission watermark'
  )
  t.alike(await exchange(sibling.client, sibling.remote, { id: 'sibling-before-late' }), {
    up: 49157,
    down: 32771
  })
  const descriptor = decodeDescriptor(server._descriptor)
  const entryNode = h.relays.find((node) =>
    b4a.equals(h.controller(node).relayKeyPair.publicKey, descriptor.entryRelayPublicKey)
  )
  const entry = h
    .controller(entryNode)
    .entryCircuits.get(b4a.toString(descriptor.routeToken, 'hex'))
  const injections = [
    [server._route.link, server._route.sendPool, 'entry-destination'],
    [entry.link, entry.forwardPool, 'destination-endpoint']
  ]
  for (const [link, pool, label] of injections) {
    for (const flag of [3, 0]) {
      const late = b4a.alloc(flag === 0 ? 6 : 5)
      late.writeUInt32BE(firstId, 0)
      late[4] = flag
      let stop
      const received = new Promise((resolve) => {
        stop = h.observe((event) => {
          if (
            event.type === 'route-cell-opened' &&
            event.label === label &&
            b4a.equals(event.plaintext, late)
          )
            resolve()
        })
      })
      try {
        if (flag === 0) await reserveInjectedData(pool)
        await link.send(late)
        await deadline(received, 'authenticated late frame at ' + label)
      } finally {
        stop()
      }
    }
  }
  t.alike(await exchange(sibling.client, sibling.remote, { id: 'sibling-after-late' }), {
    up: 49157,
    down: 32771
  })
  for (const [, pool, label] of injections) {
    t.is(
      poolTotal(pool),
      2048,
      label + ' conserves credit after late frames and the immediate sibling echo'
    )
  }
  t.absent(server._route.streams.has(firstId), 'late data does not revive the retired source')
  const next = await h.pair(server)
  t.ok(
    Array.from(server._route.streams.keys()).every((id) => id > firstId),
    'later connections never reuse the retired stream ID'
  )
  t.alike(await exchange(next.client, next.remote, { id: 'next' }), { up: 49157, down: 32771 })
})
