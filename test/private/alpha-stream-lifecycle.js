'use strict'

const test = require('brittle')
const b4a = require('b4a')
const process = require('process')
const { Writable } = require('streamx')
const HyperDHT = require('../..')
const createTestnet = require('../../testnet')
const peer = require('../../lib/private/private-peer-controller')
const { CELL_SIZE, MAX_CELL_PAYLOAD } = require('../../lib/private/cell-codec')
const { decodeDescriptor } = require('../../lib/private/overlay-descriptor-service')
const { createPrivatePeerTestScope } = require('./helpers/private-peer')

const DATA = 0
const FIN = 2
const RESET = 3
const CIRCUIT_WINDOW = 2048

function deferred() {
  let resolve
  const promise = new Promise((done) => {
    resolve = done
  })
  return { promise, resolve }
}

async function within(promise, milliseconds = 10_000) {
  let timer
  try {
    return await Promise.race([
      promise,
      new Promise((resolve) => {
        timer = setTimeout(() => resolve(false), milliseconds)
      })
    ])
  } finally {
    clearTimeout(timer)
  }
}

async function until(predicate, label, milliseconds = 10_000) {
  const end = Date.now() + milliseconds
  while (!predicate()) {
    if (Date.now() >= end) throw new Error(label)
    await new Promise((resolve) => setTimeout(resolve, 5))
  }
}

function closed(stream) {
  if (stream.destroyed) return Promise.resolve(true)
  return new Promise((resolve) => stream.once('close', () => resolve(true)))
}

async function network(t, observer) {
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
  // The hostile-frame fixture owns its relay links; the observation API exposes
  // neither those links nor a callback that can postpone forwarding.
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
  return { net, nodes, controllers }
}

async function connect(t, source, server) {
  const stream = source.privateRouting.connect(server.publicKey)
  stream.on('error', () => {})
  t.teardown(() => stream.destroy())
  if (!(await stream.opened)) throw new Error('Private stream did not authenticate')
  return stream
}

async function echo(t, stream, text) {
  const value = b4a.from(text)
  const response = new Promise((resolve) => stream.once('data', resolve))
  stream.write(value)
  t.alike(await within(response), value)
}

function logicalFrame(streamId, flags, data = b4a.alloc(0)) {
  const frame = b4a.alloc(5 + data.byteLength)
  frame.writeUInt32BE(streamId, 0)
  frame[4] = flags
  data.copy(frame, 5)
  return frame
}

function poolTotal(pool) {
  let total = pool.available + pool.inFlight
  for (const leg of pool.legs.values()) total += leg.granted
  return total
}

test('private FIN completes one read direction while reverse traffic and sibling streams remain live', async (t) => {
  t.timeout(120_000)
  const controls = []
  const {
    nodes: [source, destination]
  } = await network(t, (event) => {
    if (
      (event.type === 'route-cell-sealed' || event.type === 'route-cell-opened') &&
      (event.label === 'source-endpoint' || event.label === 'destination-endpoint') &&
      event.plaintext.byteLength === 5 &&
      event.plaintext[4] >= FIN
    ) {
      controls.push({
        type: event.type,
        label: event.label,
        flag: event.plaintext[4],
        id: event.plaintext.readUInt32BE(0)
      })
    }
  })
  const accepted = []
  const uploadChunks = []
  const peerEnded = deferred()
  let peerEndCount = 0
  const server = destination.privateRouting.createServer((stream) => {
    stream.on('error', () => {})
    accepted.push(stream)
    if (accepted.length !== 1) {
      stream.on('data', (data) => stream.write(data))
      return
    }
    stream.on('data', (data) => uploadChunks.push(data))
    stream.on('end', () => {
      peerEndCount++
      peerEnded.resolve(true)
    })
  })
  t.teardown(() => server.close())
  await server.listen(HyperDHT.keyPair())
  const client = await connect(t, source, server)
  const sibling = await connect(t, source, server)
  await echo(t, sibling, 'sibling before graceful close')
  const firstId = accepted[0].rawStream.streamId
  const route = server._route
  const clientClosed = closed(client)
  const peerClosed = closed(accepted[0])
  const clientEnded = deferred()
  const reverseChunks = []
  let clientEndCount = 0
  client.on('data', (data) => reverseChunks.push(data))
  client.on('end', () => {
    clientEndCount++
    clientEnded.resolve(true)
  })

  const upload = b4a.alloc(16 * 1024, 0x53)
  client.end(upload)
  const ended = await within(peerEnded.promise)
  t.alike(b4a.concat(uploadChunks), upload, 'the upload reaches the peer before EOF')
  t.is(
    controls.filter(
      (row) =>
        row.type === 'route-cell-sealed' && row.label === 'source-endpoint' && row.flag === FIN
    ).length,
    1,
    'source seals exactly one FIN'
  )
  t.is(
    controls.filter(
      (row) =>
        row.type === 'route-cell-opened' &&
        row.label === 'destination-endpoint' &&
        row.flag === FIN &&
        row.id === firstId
    ).length,
    1,
    'the destination authenticates exactly one FIN'
  )
  t.is(ended, true, 'FIN completes the peer readable side')
  if (!ended) return
  t.is(peerEndCount, 1)
  t.is(route.streams.has(firstId), true, 'a half-closed stream ID is still live')
  t.is(accepted[0].destroyed, false)

  const reverse = b4a.alloc(12 * 1024, 0x72)
  const reverseReceived = new Promise((resolve) => client.once('data', resolve))
  accepted[0].write(reverse)
  t.alike(await within(reverseReceived), reverse, 'reverse writes remain usable after peer EOF')
  await echo(t, sibling, 'sibling during half-close')
  const final = b4a.from('final reverse bytes')
  accepted[0].end(final)
  t.is(await within(clientEnded.promise), true)
  t.alike(b4a.concat(reverseChunks), b4a.concat([reverse, final]))
  t.is(await within(Promise.all([clientClosed, peerClosed]).then(() => true)), true)
  t.is(clientEndCount, 1)
  t.is(peerEndCount, 1)
  t.is(route.streams.has(firstId), false, 'retirement follows completion of both directions')
  await echo(t, sibling, 'sibling after graceful close')
  t.is(
    controls.filter(
      (row) =>
        row.type === 'route-cell-sealed' &&
        row.label === 'destination-endpoint' &&
        row.flag === FIN &&
        row.id === firstId
    ).length,
    1
  )
  t.is(
    controls.filter(
      (row) =>
        row.type === 'route-cell-opened' && row.label === 'source-endpoint' && row.flag === FIN
    ).length,
    1
  )
  t.is(
    controls.filter((row) => row.flag === RESET).length,
    0,
    'graceful completion does not emit an abrupt reset'
  )
})

test('private RESET preserves the baseline under backpressure and isolates retired IDs', async (t) => {
  t.timeout(120_000)
  const firstData = deferred()
  const destinationReset = deferred()
  const waiters = []
  let armed = false
  let firstId = null
  let resetCount = 0
  const {
    nodes: [source, destination],
    controllers
  } = await network(t, (event) => {
    if (
      armed &&
      event.type === 'route-cell-sealed' &&
      event.label === 'source-endpoint' &&
      event.plaintext.byteLength === MAX_CELL_PAYLOAD &&
      event.plaintext[4] === DATA &&
      event.plaintext.readUInt32BE(0) === 0
    )
      firstData.resolve(true)
    if (event.type !== 'route-cell-opened') return
    if (
      event.label === 'destination-endpoint' &&
      event.plaintext.byteLength === 5 &&
      event.plaintext[4] === RESET &&
      event.plaintext.readUInt32BE(0) === firstId
    ) {
      resetCount++
      destinationReset.resolve(true)
    }
    for (const waiter of waiters) {
      if (event.label === waiter.label && b4a.equals(event.plaintext, waiter.frame))
        waiter.seen.resolve(true)
    }
  })
  const accepted = []
  const server = destination.privateRouting.createServer((stream) => {
    stream.on('error', () => {})
    accepted.push(stream)
    if (accepted.length !== 1) stream.on('data', (data) => stream.write(data))
    else stream.on('data', () => {})
  })
  t.teardown(() => server.close())
  await server.listen(HyperDHT.keyPair())
  const client = await connect(t, source, server)
  const sibling = await connect(t, source, server)
  firstId = accepted[0].rawStream.streamId
  t.is(client.rawStream.streamId, 0)
  t.is(firstId, 2, 'the entry translates source ID zero to destination ID two')
  await echo(t, sibling, 'sibling before reset')
  const clientClosed = closed(client)
  const peerClosed = closed(accepted[0])
  armed = true
  t.is(
    client.write(b4a.alloc(64 * 1024, 0x64)),
    false,
    'the pending upload applies write backpressure'
  )
  const sealed = await within(firstData.promise)
  t.is(sealed, true, 'a full source DATA cell was actually sealed before destroy')
  if (!sealed) return
  client.destroy()
  t.is(
    await within(
      Promise.all([clientClosed, peerClosed, destinationReset.promise]).then(() => true)
    ),
    true
  )
  t.is(server._route.streams.has(firstId), false)
  await echo(t, sibling, 'sibling after reset')
  t.is(resetCount, 1, 'exactly one reset reaches the destination for this destroy')

  const descriptor = decodeDescriptor(server._descriptor)
  const entryController = Array.from(controllers.values()).find(
    (controller) =>
      controller.relayKeyPair &&
      b4a.equals(controller.relayKeyPair.publicKey, descriptor.entryRelayPublicKey)
  )
  const entry = entryController.entryCircuits.get(b4a.toString(descriptor.routeToken, 'hex'))
  for (const [link, label, pool] of [
    [server._route.link, 'entry-destination', server._route.sendPool],
    [entry.link, 'destination-endpoint', entry.forwardPool]
  ]) {
    for (const flag of [RESET, DATA]) {
      if (flag === DATA) {
        // Reserve only available capacity. Forcing the live sibling to release
        // a fresh grant would make its next write renew before the demand limit.
        await until(() => pool.available > 0, 'Idle circuit credit was not reclaimed')
        // Retired-ID DATA still consumes credit until its receiver discards it.
        pool.available--
        pool.inFlight++
      }
      const frame = logicalFrame(
        firstId,
        flag,
        flag === DATA ? b4a.from('late authenticated data') : b4a.alloc(0)
      )
      const seen = deferred()
      waiters.push({ label, frame, seen })
      await link.send(frame)
      t.is(
        await within(seen.promise),
        true,
        'the retired-ID frame reached its actual authenticated opener'
      )
    }
  }
  await echo(t, sibling, 'sibling after late DATA and RESET in both directions')
  t.is(resetCount, 2, 'only the one deliberately injected late reset adds another received reset')
  await until(
    () => entry.forwardPool.inFlight === 0 && server._route.sendPool.inFlight === 0,
    'Consumed circuit credit was stranded after retired-ID DATA'
  )
  t.is(
    poolTotal(entry.forwardPool),
    CIRCUIT_WINDOW,
    'retired-ID DATA returns forward circuit capacity without expanding the pool'
  )
  t.is(
    poolTotal(server._route.sendPool),
    CIRCUIT_WINDOW,
    'retired-ID DATA returns reverse circuit capacity without expanding the pool'
  )
  const next = await connect(t, source, server)
  t.ok(
    accepted[2].rawStream.streamId > accepted[1].rawStream.streamId &&
      accepted[2].rawStream.streamId > firstId,
    'a retired ID is never reused'
  )
  await echo(t, next, 'new stream after retirement')
})

test('queued cell, logical, control and close writes settle safely when their live link is destroyed', async (t) => {
  t.timeout(120_000)
  const {
    net,
    nodes: [source, destination],
    controllers
  } = await network(t, null)
  const accepted = []
  const server = destination.privateRouting.createServer((stream) => {
    stream.on('error', () => {})
    accepted.push(stream)
    stream.on('data', (data) => stream.write(data))
  })
  t.teardown(() => server.close())
  await server.listen(HyperDHT.keyPair())
  const client = await connect(t, source, server)
  await echo(t, client, 'healthy application traffic before queued teardown')
  const remote = accepted[0]
  const link = server._route.link
  const remoteErrors = []
  const clientErrors = []
  remote.on('error', (error) => remoteErrors.push(error))
  client.on('error', (error) => clientErrors.push(error))
  const escaped = []
  const onUnhandled = (error) =>
    escaped.push({ type: 'unhandledRejection', code: error && error.code })
  const onUncaught = (error) =>
    escaped.push({ type: 'uncaughtException', code: error && error.code })
  process.on('unhandledRejection', onUnhandled)
  process.on('uncaughtException', onUncaught)
  const turn = () => new Promise((resolve) => setImmediate(resolve))
  try {
    // Hold the fixture-owned real transport, not an observer return value.
    link.rawStream.cork()
    const frames = []
    const pending = []
    for (let i = 0; i < 8; i++) {
      const frame = logicalFrame(remote.rawStream.streamId, DATA, b4a.alloc(32, i + 1))
      frames.push(frame)
      pending.push(link.send(frame))
    }
    const finish = logicalFrame(remote.rawStream.streamId, FIN)
    frames.push(finish)
    pending.push(link.send(finish))
    pending.push(
      controllers.get(destination)._writeControl(link.rawStream, b4a.from([0]), 0, 'status')
    )
    // Every fixture promise is observed before failure. Any rejection event is
    // therefore from an unowned production branch, not an ignored test send.
    const settled = Promise.allSettled(pending)
    remote.end(b4a.alloc(64 * 1024, 0x57))
    const clientClosed = closed(client)
    const remoteClosed = closed(remote)
    await turn()
    const logicalDrained = Writable.drained(remote.rawStream).then(() => true)
    t.ok(link.pendingSends >= 9, 'several cell sends and an explicit FIN remain queued')
    link.destroy(new Error('internal transport failure detail'))
    const outcomes = await within(settled)
    t.ok(Array.isArray(outcomes), 'every queued send promise settles')
    if (Array.isArray(outcomes)) {
      t.is(outcomes.length, pending.length)
      t.ok(
        outcomes.every(
          (outcome) =>
            outcome.status === 'rejected' && outcome.reason.code === 'ERR_PRIVACY_UNAVAILABLE'
        ),
        'queued failures have the sanitized privacy error'
      )
    }
    t.is(await within(logicalDrained), true, 'the active logical writer settles during teardown')
    t.is(await within(Promise.all([clientClosed, remoteClosed]).then(() => true)), true)
    t.is(remoteErrors.length, 1, 'the local application stream receives one failure')
    t.is(remoteErrors[0] && remoteErrors[0].code, 'ERR_PRIVACY_UNAVAILABLE')
    t.is(clientErrors.length, 1, 'the remote application stream receives one failure')
    t.is(clientErrors[0] && clientErrors[0].code, 'ERR_PRIVACY_UNAVAILABLE')
    for (const frame of frames) frame.fill(0)
  } finally {
    await server.close()
    await net.destroy()
    await turn()
    await turn()
    process.removeListener('unhandledRejection', onUnhandled)
    process.removeListener('uncaughtException', onUncaught)
  }
  t.alike(escaped, [], 'full link and network teardown emits no unhandled rejection or exception')
})

test('the cell receive cursor preserves encrypted traffic across split and coalesced reads', async (t) => {
  t.timeout(120_000)
  const {
    nodes: [source, destination]
  } = await network(t, null)
  const server = destination.privateRouting.createServer((stream) => {
    stream.on('error', () => {})
    stream.pipe(stream)
  })
  t.teardown(() => server.close())
  await server.listen(HyperDHT.keyPair())
  const client = await connect(t, source, server)
  await echo(t, client, 'authenticate before transport rechunking')
  const link = server._route.link
  const receive = link._receive.bind(link)
  const chunks = []
  let buffered = 0
  let coalesced = false
  link._receive = (chunk) => {
    if (coalesced) {
      const split = Math.min(17, chunk.byteLength)
      receive(chunk.subarray(0, split))
      if (split < chunk.byteLength) receive(chunk.subarray(split))
      return
    }
    chunks.push(b4a.from(chunk))
    buffered += chunk.byteLength
    if (buffered < 128 * CELL_SIZE) return
    coalesced = true
    const joined = b4a.concat(chunks)
    for (const part of chunks) part.fill(0)
    chunks.length = 0
    // The real authenticated bytes retain their order, but no read boundary is
    // assumed to coincide with a cell boundary or a sender's batch size.
    receive(joined.subarray(0, 11))
    receive(joined.subarray(11))
    joined.fill(0)
  }
  const expected = b4a.alloc(192 * 1024)
  for (let i = 0; i < expected.byteLength; i++) expected[i] = i % 251
  const echoed = new Promise((resolve) => {
    let length = 0
    const output = []
    function finish(value) {
      client.removeListener('data', ondata)
      client.removeListener('error', onfailure)
      client.removeListener('close', onfailure)
      resolve(value)
    }
    function ondata(data) {
      length += data.byteLength
      output.push(b4a.from(data))
      if (length >= expected.byteLength) finish(b4a.concat(output))
    }
    function onfailure() {
      finish(null)
    }
    client.on('data', ondata)
    client.once('error', onfailure)
    client.once('close', onfailure)
  })
  client.write(expected)
  const result = await within(echoed)
  if (!b4a.isBuffer(result)) {
    t.fail('the live route closed or stalled while receiving the coalesced batch')
    return
  }
  t.alike(result, expected, 'split and oversized coalesced reads preserve every application byte')
  await echo(t, client, 'the route remains usable after the coalesced batch')
})
