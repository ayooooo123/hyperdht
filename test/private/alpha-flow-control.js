'use strict'

const test = require('brittle')
const b4a = require('b4a')
const { Writable } = require('streamx')
const HyperDHT = require('../..')
const createTestnet = require('../../testnet')
const peer = require('../../lib/private/private-peer-controller')
const { decodeDescriptor } = require('../../lib/private/overlay-descriptor-service')
const { createPrivatePeerTestScope } = require('./helpers/private-peer')

const MIB = 1024 * 1024
const CIRCUIT_WINDOW = 2048
const STREAM_WINDOW = 512

async function network(t) {
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
  const original = peer.createPrivatePeerController
  peer.createPrivatePeerController = (options) => {
    const controller = original(options)
    controllers.set(options.dht, controller)
    return controller
  }
  let nodes
  try {
    nodes = [false, false, true, true, true, true, true, true].map((relay) =>
      scope.create(() =>
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
        })
      )
    )
  } finally {
    peer.createPrivatePeerController = original
  }
  await Promise.all(nodes.map((node) => node.privateRouting.ready()))
  return { nodes, controllers }
}

async function until(predicate, label, milliseconds = 10_000) {
  const end = Date.now() + milliseconds
  while (!predicate()) {
    if (Date.now() >= end) throw new Error(label)
    await new Promise((resolve) => setTimeout(resolve, 5))
  }
}

async function connect(t, source, server) {
  const stream = source.privateRouting.connect(server.publicKey)
  stream.on('error', () => {})
  t.teardown(() => stream.destroy())
  if (!(await stream.opened)) throw new Error('Private stream did not authenticate')
  return stream
}

function entryCircuit(controllers, server) {
  const descriptor = decodeDescriptor(server._descriptor)
  const controller = [...controllers.values()].find(
    (candidate) =>
      candidate.relayKeyPair &&
      b4a.equals(candidate.relayKeyPair.publicKey, descriptor.entryRelayPublicKey)
  )
  return controller.entryCircuits.get(b4a.toString(descriptor.routeToken, 'hex'))
}

function poolTotal(pool) {
  let total = pool.available + pool.inFlight
  for (const leg of pool.legs.values()) total += leg.granted
  return total
}

function receive(stream, length, value) {
  let bytes = 0
  let intact = true
  let resolve
  const promise = new Promise((done) => {
    resolve = done
  })
  const data = (chunk) => {
    for (const byte of chunk) if (byte !== value) intact = false
    bytes += chunk.byteLength
    if (bytes >= length) finish({ bytes, intact })
  }
  const failure = (error) => finish({ error: (error && error.code) || 'CLOSED', bytes, intact })
  function finish(result) {
    stream.removeListener('data', data)
    stream.removeListener('error', failure)
    stream.removeListener('close', failure)
    resolve(result)
  }
  stream.on('data', data)
  stream.once('error', failure)
  stream.once('close', failure)
  return promise
}

async function send(stream, length, value) {
  const chunk = b4a.alloc(64 * 1024, value)
  for (let sent = 0; sent < length; sent += chunk.byteLength) {
    stream.write(chunk.subarray(0, Math.min(chunk.byteLength, length - sent)))
    if (!(await Writable.drained(stream)) || stream.destroying || stream.destroyed) {
      return { error: 'WRITE_FAILED', sent }
    }
  }
  return { sent: length }
}

async function transfer(t, writer, reader, length, value, label) {
  const receiving = receive(reader, length, value)
  const sending = send(writer, length, value)
  const [written, read] = await Promise.all([sending, receiving])
  t.alike(written, { sent: length }, label + ' writer completes')
  t.alike(read, { bytes: length, intact: true }, label + ' arrives intact')
}

async function echo(stream, text) {
  const expected = b4a.from(text)
  const response = new Promise((resolve, reject) => {
    const data = (chunk) => {
      cleanup()
      resolve(chunk)
    }
    const error = (cause) => {
      cleanup()
      reject(cause)
    }
    function cleanup() {
      stream.removeListener('data', data)
      stream.removeListener('error', error)
    }
    stream.once('data', data)
    stream.once('error', error)
  })
  response.catch(() => {})
  stream.write(expected)
  if (!b4a.equals(await response, expected)) throw new Error('Sibling echo was corrupted')
}

test('dual credit bounds a slow reader while sibling close, resumed bulk and concurrent duplex traffic complete', async (t) => {
  t.timeout(240_000)
  const {
    nodes: [source, destination],
    controllers
  } = await network(t)
  const accepted = []
  const server = destination.privateRouting.createServer((stream) => {
    stream.on('error', () => {})
    accepted.push(stream)
  })
  t.teardown(() => server.close())
  await server.listen(HyperDHT.keyPair())
  const bulk = await connect(t, source, server)
  const sibling = await connect(t, source, server)
  const sink = accepted[0]
  const echoSink = accepted[1]
  echoSink.on('data', (data) => echoSink.write(data))
  echoSink.on('end', () => echoSink.end())
  const entry = entryCircuit(controllers, server)
  const route = server._route
  const receiving = receive(sink, 4 * MIB, 0x61)
  sink.pause()
  let settled = false
  const writing = send(bulk, 4 * MIB, 0x61).then((result) => {
    settled = true
    return result
  })
  await until(
    () => bulk.rawStream.creditWaiter !== null && bulk.rawStream.sendCredit === 0,
    'Bulk writer did not reach its stream-credit boundary'
  )
  t.is(settled, false, 'the paused reader propagates backpressure to the application writer')
  t.ok(
    sink.rawStream.receivedOutstanding <= STREAM_WINDOW,
    'the stream retains at most 512 unconsumed cells'
  )
  t.ok(
    sink.rawStream.queueLength + Number(sink.rawStream.delivered) <= STREAM_WINDOW,
    'queued and prefetched cells share the stream window'
  )
  t.is(
    poolTotal(entry.forwardPool),
    CIRCUIT_WINDOW,
    'forward grants and in-flight cells share one 2048-cell pool'
  )
  t.is(
    poolTotal(route.sendPool),
    CIRCUIT_WINDOW,
    'reverse grants and in-flight cells share one 2048-cell pool'
  )
  for (const link of [
    entry.link,
    route.link,
    bulk.rawStream.link,
    ...[...entry.sources.values()].map((record) => record.link)
  ]) {
    t.ok(
      link.pendingData <= CIRCUIT_WINDOW && link.pendingControl <= 256,
      'DATA and reserved control queues remain independently bounded'
    )
  }
  await echo(sibling, 'interactive sibling while bulk is paused')
  t.pass('a sibling exchanges authenticated application data while the bulk stream has no credit')
  sibling.end()
  await until(
    () => sibling.destroyed && echoSink.destroyed,
    'Sibling FIN was starved by exhausted DATA credit'
  )
  t.is(settled, false, 'sibling FIN completes before the paused bulk writer resumes')
  sink.resume()
  const [written, read] = await Promise.all([writing, receiving])
  t.alike(written, { sent: 4 * MIB }, 'the paused bulk writer resumes successfully')
  t.alike(read, { bytes: 4 * MIB, intact: true }, 'all resumed bulk bytes arrive intact')
  await transfer(t, bulk, sink, 16 * MIB, 0x62, '16 MiB upload')
  await transfer(t, sink, bulk, 16 * MIB, 0x63, '16 MiB download')
  const clients = [bulk]
  const remotes = [sink]
  for (let i = 0; i < 3; i++) {
    const before = accepted.length
    clients.push(await connect(t, source, server))
    remotes.push(accepted[before])
  }
  await Promise.all(
    clients.flatMap((client, index) => [
      transfer(t, client, remotes[index], 4 * MIB, 0x70 + index, 'concurrent upload ' + index),
      transfer(t, remotes[index], client, 4 * MIB, 0x80 + index, 'concurrent download ' + index)
    ])
  )
  await until(
    () => entry.forwardPool.inFlight === 0 && route.sendPool.inFlight === 0,
    'Consumed circuit credit was stranded'
  )
  t.is(
    poolTotal(entry.forwardPool),
    CIRCUIT_WINDOW,
    'forward pool is conserved after bulk and concurrent transfers'
  )
  t.is(
    poolTotal(route.sendPool),
    CIRCUIT_WINDOW,
    'reverse pool is conserved after bulk and concurrent transfers'
  )
  await until(
    () =>
      [...entry.forwardPool.legs.values()].every((leg) => leg.granted === 0) &&
      [...route.sendPool.legs.values()].every((leg) => leg.granted === 0),
    'Idle writers did not release unused grants'
  )
  t.is(
    entry.forwardPool.available,
    CIRCUIT_WINDOW,
    'source idle release restores the entire circuit pool'
  )
  t.is(
    route.sendPool.available,
    CIRCUIT_WINDOW,
    'destination idle release restores the entire circuit pool'
  )
})

test('sixty-four source legs share one bounded circuit pool and a reset reclaims capacity under saturation', async (t) => {
  t.timeout(240_000)
  const {
    nodes: [source, destination],
    controllers
  } = await network(t)
  const accepted = []
  const server = destination.privateRouting.createServer((stream) => {
    stream.on('error', () => {})
    accepted.push(stream)
  })
  t.teardown(() => server.close())
  await server.listen(HyperDHT.keyPair())
  const clients = []
  for (let i = 0; i < 64; i++) clients.push(await connect(t, source, server))
  await Promise.all(accepted.map((stream) => stream.opened))
  await new Promise((resolve) => setImmediate(resolve))
  for (const stream of accepted) stream.rawStream.pause()
  const entry = entryCircuit(controllers, server)
  const route = server._route
  const before = clients.map((stream) => stream.rawStream.sentFrames)
  const sending = clients.map((stream, index) => send(stream, MIB, 0x40 + index))
  await until(
    () =>
      accepted.reduce((total, stream) => total + stream.rawStream.receivedOutstanding, 0) ===
      CIRCUIT_WINDOW,
    'The sixty-four paused legs did not saturate the shared circuit'
  )
  t.is(entry.forwardPool.legs.size, 64, 'all sixty-four source legs participate in the same pool')
  t.is(
    poolTotal(entry.forwardPool),
    CIRCUIT_WINDOW,
    'allocated and transmitted credit never becomes sixty-four separate circuit windows'
  )
  t.is(entry.forwardPool.inFlight, CIRCUIT_WINDOW, 'aggregate unconsumed DATA stops at 2048 cells')
  t.is(entry.forwardPool.available, 0)
  t.ok(
    clients.every((stream, index) => stream.rawStream.sentFrames > before[index]),
    'every demanding source makes progress rather than being starved by the first bulk source'
  )
  t.ok(
    accepted.every((stream) => stream.rawStream.receivedOutstanding <= STREAM_WINDOW),
    'the circuit cap does not replace the independent per-stream cap'
  )
  const retired = accepted[0].rawStream.streamId
  clients[0].destroy()
  await until(
    () => clients[0].destroyed && accepted[0].destroyed && !entry.sources.has(retired),
    'RESET could not pass the saturated DATA window'
  )
  t.is(
    entry.forwardPool.legs.size,
    63,
    'closing a leg removes its outstanding demand and unused grant'
  )
  t.is(
    poolTotal(entry.forwardPool),
    CIRCUIT_WINDOW,
    'discarded queued cells restore circuit credit instead of leaking it'
  )
  const receiving = accepted.slice(1).map((stream, index) => {
    const pending = receive(stream, MIB, 0x41 + index)
    stream.rawStream.resume()
    stream.resume()
    return pending
  })
  const results = await Promise.all(sending)
  const received = await Promise.all(receiving)
  t.is(
    results[0].error,
    'WRITE_FAILED',
    'the canceled producer settles rather than hanging on credit'
  )
  t.ok(
    results.slice(1).every((result) => result.sent === MIB),
    'all sixty-three surviving writers complete'
  )
  t.ok(
    received.every((result) => result.bytes === MIB && result.intact === true && !result.error),
    'all surviving receivers authenticate the complete payload'
  )
  for (const client of clients) client.destroy()
  await until(
    () =>
      entry.sources.size === 0 &&
      route.streams.size === 0 &&
      entry.forwardPool.inFlight === 0 &&
      route.sendPool.inFlight === 0,
    'Closing all legs left circuit credit outstanding'
  )
  t.is(
    entry.forwardPool.available,
    CIRCUIT_WINDOW,
    'close and reset reclaim the complete forward pool'
  )
  t.is(
    route.sendPool.available,
    CIRCUIT_WINDOW,
    'close and reset reclaim the complete reverse pool'
  )
})

function control(flag, amount, streamId = 0xffffffff) {
  const frame = b4a.alloc(7)
  frame.writeUInt32BE(streamId, 0)
  frame[4] = flag
  frame.writeUInt16BE(amount, 5)
  return frame
}

async function silentLeg(t, source, server, accepted, entry) {
  const index = accepted.length
  const client = await connect(t, source, server)
  const record = entry.sources.get(accepted[index].rawStream.streamId)
  await until(() => {
    const leg = entry.forwardPool.legs.get(record)
    return leg && leg.granted === 0 && leg.wanted === 0 && record.reverseInFlight === 0
  }, 'The hostile peer did not finish its initial legitimate credit exchange')
  // This fixture owns the transport and deliberately stops processing incoming
  // grants, modeling a peer that demands capacity but never uses or returns it.
  client.rawStream.link.removeAllListeners('payload')
  return { client, record }
}

test('malformed credit is isolated and silent or duplicate demand cannot retain the shared pool', async (t) => {
  t.timeout(120_000)
  const {
    nodes: [source, destination],
    controllers
  } = await network(t)
  const accepted = []
  const server = destination.privateRouting.createServer((stream) => {
    stream.on('error', () => {})
    stream.on('data', (data) => stream.write(data))
    accepted.push(stream)
  })
  t.teardown(() => server.close())
  await server.listen(HyperDHT.keyPair())
  const healthy = await connect(t, source, server)
  const entry = entryCircuit(controllers, server)
  for (const [label, frame] of [
    ['zero CREDIT', control(4, 0)],
    ['oversized circuit CREDIT', control(4, 2049)],
    ['circuit CREDIT underflow', control(4, 1)],
    ['unused-grant RELEASE underflow', control(6, 1)],
    ['oversized DEMAND', control(5, 2049)],
    ['unknown flag', control(7, 1)],
    ['stream CREDIT overflow', control(4, 512, 0)],
    ['truncated count', control(4, 1).subarray(0, 6)]
  ]) {
    const { client, record } = await silentLeg(t, source, server, accepted, entry)
    const errors = []
    client.on('error', (error) => errors.push(error.code))
    await client.rawStream.link.send(frame).catch(() => {})
    await until(
      () => client.destroyed && !entry.sources.has(record.streamId),
      label + ' was not rejected'
    )
    t.alike(
      errors,
      ['ERR_PRIVACY_UNAVAILABLE'],
      label + ' closes only the offending leg with one sanitized error'
    )
    await echo(healthy, 'healthy sibling after ' + label)
    t.pass(label + ' does not close or corrupt the sibling')
  }
  const rapid = await silentLeg(t, source, server, accepted, entry)
  const rapidErrors = []
  rapid.client.on('error', (error) => rapidErrors.push(error.code))
  // Releasing a grant does not earn another demand without DATA progress or
  // the idle interval. The queued grant must also settle when this leg closes.
  await Promise.allSettled([
    rapid.client.rawStream.link.send(control(5, 1)),
    rapid.client.rawStream.link.send(control(6, 1)),
    rapid.client.rawStream.link.send(control(5, 1))
  ])
  await until(
    () => rapid.client.destroyed && !entry.sources.has(rapid.record.streamId),
    'A rapid demand/release loop bypassed the demand rate bound'
  )
  t.alike(
    rapidErrors,
    ['ERR_PRIVACY_UNAVAILABLE'],
    'rapid demand/release cannot amplify the control queue'
  )
  await echo(healthy, 'healthy sibling after demand rate rejection')
  t.pass('queued grant teardown and rate rejection preserve the sibling')
  const first = await silentLeg(t, source, server, accepted, entry)
  const duplicate = await silentLeg(t, source, server, accepted, entry)
  await first.client.rawStream.link.send(control(5, CIRCUIT_WINDOW))
  await until(
    () => entry.forwardPool.legs.get(first.record).granted === CIRCUIT_WINDOW,
    'A single active demander could not reserve the available circuit pool'
  )
  const grantedAt = Date.now()
  t.is(
    poolTotal(entry.forwardPool),
    CIRCUIT_WINDOW,
    'one full grant never increases the circuit window'
  )
  await duplicate.client.rawStream.link.send(control(5, 32))
  await until(
    () => entry.forwardPool.legs.get(duplicate.record).wanted === 32,
    'Demand was not queued behind the full grant'
  )
  await duplicate.client.rawStream.link.send(control(5, 32)).catch(() => {})
  await until(() => duplicate.client.destroyed, 'Duplicate outstanding demand was not rejected')
  t.is(
    entry.forwardPool.legs.has(duplicate.record),
    false,
    'duplicate demand is removed rather than amplified'
  )
  const progress = echo(healthy, 'healthy sibling after idle grant reclamation').then(
    () => true,
    () => false
  )
  await until(
    () => first.client.destroyed,
    'A silent grant holder exceeded the enforced idle deadline',
    7500
  )
  t.ok(
    Date.now() - grantedAt < 7500,
    'the relay enforces the idle deadline without trusting voluntary RELEASE'
  )
  t.is(
    entry.forwardPool.legs.has(first.record),
    false,
    'idle close reclaims the unused grant and demand'
  )
  t.is(
    await progress,
    true,
    'a waiting sibling obtains the reclaimed credit and completes its exchange'
  )
  t.is(
    poolTotal(entry.forwardPool),
    CIRCUIT_WINDOW,
    'the circuit pool remains conserved after hostile peers close'
  )
})

test('partial circuit grants crossing a stream-credit boundary preserve a legitimate bulk writer', async (t) => {
  t.timeout(120_000)
  const {
    nodes: [source, destination],
    controllers
  } = await network(t)
  let remote
  const server = destination.privateRouting.createServer((stream) => {
    stream.on('error', () => {})
    remote = stream
  })
  t.teardown(() => server.close())
  await server.listen(HyperDHT.keyPair())
  const client = await connect(t, source, server)
  const entry = entryCircuit(controllers, server)
  const record = entry.sources.get(remote.rawStream.streamId)
  const raw = client.rawStream
  await until(
    () => entry.forwardPool.available === CIRCUIT_WINDOW,
    'Handshake credit did not return before the boundary scenario'
  )
  // Model a paced upstream writer so the five receiver refills arrive before
  // the deliberately chosen boundary, rather than an unrelated earlier stall.
  const finishBatch = raw.link._finishBatch
  let pace = true
  raw.link._finishBatch = function (batch, error) {
    if (!pace || error || this.destroyed) return finishBatch.call(this, batch, error)
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        try {
          resolve(finishBatch.call(this, batch, error))
        } catch (cause) {
          reject(cause)
        }
      }, 50)
    })
  }
  const firstGrant = raw.sendCredit + 5 * 128 - 31
  const baseFrames = raw.sentFrames
  let delayedGrant = 0
  const grant = entry.forwardPool.onGrant
  entry.forwardPool.onGrant = (owner, amount) => {
    entry.forwardPool.onGrant = grant
    if (owner !== record || amount !== CIRCUIT_WINDOW)
      throw new Error('Unexpected initial circuit grant')
    delayedGrant = amount - firstGrant
    owner.link.send(control(4, firstGrant))
  }
  // Hold the reader after five ordinary stream-credit returns. The sender can
  // consume the first partial circuit grant but still has 31 stream cells.
  const refill = remote.rawStream._read
  let returned = 0
  remote.rawStream._read = function (callback) {
    const returning = this.delivered && this.streamReturnPending === 127
    refill.call(this, callback)
    if (returning && ++returned === 5) this.pause()
  }
  const receiving = receive(remote, 4 * MIB, 0x5a)
  client.write(b4a.alloc(4 * MIB, 0x5a))
  const writing = Writable.drained(client).then(
    (value) => value && !client.destroying && !client.destroyed
  )
  await until(
    () =>
      delayedGrant !== 0 &&
      raw.creditWaiter !== null &&
      raw.circuitCredit === 0 &&
      raw.sentFrames - baseFrames === firstGrant,
    'The initial partial circuit grant was not consumed'
  )
  t.is(raw.sendCredit, 31, 'the two independent credit boundaries are deliberately misaligned')
  pace = false
  await record.link.send(control(4, delayedGrant))
  await until(
    () =>
      raw.sendCredit === 0 &&
      raw.creditWaiter !== null &&
      !entry.forwardPool.legs.get(record).demandOpen &&
      entry.forwardPool.legs.get(record).granted === 0,
    'The stream did not withdraw its next demand at the stream-credit boundary'
  )
  remote.rawStream.resume()
  const [written, received] = await Promise.all([writing, receiving])
  t.is(written, true, 'credit renewal after the short boundary interval keeps the writer alive')
  t.alike(
    received,
    { bytes: 4 * MIB, intact: true },
    'the complete atomic application record arrives intact'
  )
  t.is(poolTotal(entry.forwardPool), CIRCUIT_WINDOW, 'renewal does not expand the circuit pool')
})
