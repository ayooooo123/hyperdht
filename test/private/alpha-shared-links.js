'use strict'

const test = require('brittle')
const b4a = require('b4a')
const { Writable } = require('streamx')
const HyperDHT = require('../..')
const createTestnet = require('../../testnet')
const peer = require('../../lib/private/private-peer-controller')
const { decodeDescriptor } = require('../../lib/private/overlay-descriptor-service')
const { chargePeerLedger, readPeerLedger } = require('../../lib/private/peer-ledger')
const { createPrivatePeerTestScope } = require('./helpers/private-peer')

const MIB = 1024 * 1024
const CELL_SIZE = 1200

async function network(t, observer = null) {
  const net = await createTestnet(1, { bootstrap: [] })
  const scope = createPrivatePeerTestScope()
  const controllers = new Map()
  t.teardown(async () => {
    try {
      await net.destroy()
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
  return { nodes, controllers }
}

async function until(predicate, milliseconds = 10_000) {
  const deadline = Date.now() + milliseconds
  while (!predicate()) {
    if (Date.now() >= deadline) return false
    await new Promise((resolve) => setTimeout(resolve, 5))
  }
  return true
}

async function listen(t, destination, echo = true) {
  const accepted = []
  const server = destination.privateRouting.createServer((stream) => {
    stream.on('error', () => {})
    if (echo) stream.on('data', (data) => stream.write(data))
    stream.on('end', () => stream.end())
    accepted.push(stream)
  })
  t.teardown(() => server.close())
  await server.listen(HyperDHT.keyPair())
  return { server, accepted }
}

function connect(t, source, server) {
  const stream = source.privateRouting.connect(server.publicKey)
  stream.on('error', () => {})
  t.teardown(() => stream.destroy())
  return stream
}

function entryCircuit(controllers, server) {
  const descriptor = decodeDescriptor(server._descriptor)
  const owner = [...controllers.values()].find(
    (controller) =>
      controller.relayKeyPair &&
      b4a.equals(controller.relayKeyPair.publicKey, descriptor.entryRelayPublicKey)
  )
  return owner.entryCircuits.get(b4a.toString(descriptor.routeToken, 'hex'))
}

function receive(stream, length, value, milliseconds = 30_000) {
  if (stream.destroying || stream.destroyed) return Promise.resolve(false)
  return new Promise((resolve) => {
    let bytes = 0
    let intact = true
    let finished = false
    const timer = setTimeout(() => finish(false), milliseconds)
    const data = (chunk) => {
      for (const byte of chunk) if (byte !== value) intact = false
      bytes += chunk.byteLength
      if (bytes >= length) finish(intact && bytes === length)
    }
    const failed = () => finish(false)
    function finish(result) {
      if (finished) return
      finished = true
      clearTimeout(timer)
      stream.removeListener('data', data)
      stream.removeListener('error', failed)
      stream.removeListener('close', failed)
      resolve(result)
    }
    stream.on('data', data)
    stream.once('error', failed)
    stream.once('close', failed)
  })
}

async function send(stream, length, value) {
  const chunk = b4a.alloc(64 * 1024, value)
  try {
    for (let sent = 0; sent < length; sent += chunk.byteLength) {
      stream.write(chunk.subarray(0, Math.min(chunk.byteLength, length - sent)))
      if (!(await Writable.drained(stream)) || stream.destroying || stream.destroyed) return false
    }
    return true
  } catch {
    return false
  }
}

async function exchange(stream, length, value) {
  if (stream.destroying || stream.destroyed) return false
  const receiving = receive(stream, length, value)
  const sending = send(stream, length, value)
  const results = await Promise.all([sending, receiving])
  return results.every(Boolean)
}

function spendTo(ledger, remaining) {
  const snapshot = readPeerLedger(ledger)
  const cells = snapshot.cellsRemaining - remaining
  if (cells < 0) throw new Error('The fixture ledger has insufficient unspent capacity')
  chargePeerLedger(ledger, { cells, bytes: BigInt(cells * CELL_SIZE), commands: cells })
}

async function finish(stream, remote) {
  stream.end()
  return until(() => stream.destroyed && remote.destroyed)
}

test('new admissions fund an almost-spent shared link without renewing an existing source quota', async (t) => {
  t.timeout(120_000)
  const {
    nodes: [source, destination],
    controllers
  } = await network(t)
  const { server, accepted } = await listen(t, destination)
  const original = connect(t, source, server)
  t.is(await original.opened, true)
  t.is(await exchange(original, 64, 0x41), true)
  const route = server._route
  const entry = entryCircuit(controllers, server)
  await until(
    () =>
      route.link.pendingSends === 0 &&
      entry.link.pendingSends === 0 &&
      original.rawStream.link.pendingSends === 0
  )
  await new Promise((resolve) => setTimeout(resolve, 100))

  // Pre-spend the real ledgers to reach the lifetime boundary without sending
  // several GiB. No ledger is replaced, and new traffic still crosses the network.
  spendTo(original.rawStream.link.sendLedger, 64)
  for (const link of [route.link, entry.link]) {
    spendTo(link.sendLedger, 128)
    spendTo(link.receiveLedger, 128)
  }
  const newcomer = connect(t, source, server)
  t.is(await newcomer.opened, true, 'the next authenticated admission remains possible')
  t.is(
    await exchange(newcomer, 2 * MIB, 0x62),
    true,
    'newly admitted bidirectional traffic has funded capacity'
  )
  t.ok(
    server._route === route && !route.closed,
    'funding does not replace or terminate the shared route'
  )
  t.is(await exchange(original, 64, 0x43), true, 'the existing sibling remains usable')
  if (newcomer.destroyed || original.destroyed) return

  const limited = exchange(original, MIB, 0x64)
  t.is(await limited, false, 'a new admission does not renew the already admitted source quota')
  t.ok(
    await until(() => original.destroyed && accepted[0].destroyed),
    'quota exhaustion retires only its source stream'
  )
  t.is(
    await exchange(newcomer, 64, 0x45),
    true,
    'the sibling survives independent source quota exhaustion'
  )
})

test('one published route carries more than sixty-four MiB in each direction across sequential sessions', async (t) => {
  t.timeout(240_000)
  const {
    nodes: [source, destination]
  } = await network(t)
  const { server, accepted } = await listen(t, destination)
  const route = server._route
  for (let i = 0; i < 5; i++) {
    const client = connect(t, source, server)
    if (!(await client.opened)) {
      t.fail('the next sequential session did not authenticate')
      return
    }
    t.is(
      await exchange(client, 16 * MIB, 0x50 + i),
      true,
      'session ' + (i + 1) + ' transfers sixteen MiB in both directions'
    )
    if (!(await finish(client, accepted[i]))) {
      t.fail('the sequential session did not release its admission')
      return
    }
  }
  t.ok(
    server._route === route && !route.closed,
    'eighty MiB per direction does not require route replacement'
  )
  const sibling = connect(t, source, server)
  t.is(await sibling.opened, true)
  t.is(
    await exchange(sibling, 64, 0x69),
    true,
    'the same published route still admits useful traffic'
  )
})

function pacedSharedWriter(t, link, bulkIds, pingId, sealed) {
  const originalSend = link.send
  const originalWrite = link.rawStream.write
  const delayed = new Map()
  const state = { bulk: 0, queuedAt: null, ahead: null, active: true, delay: 200 }
  link.send = function (payload, ...args) {
    if (
      payload.byteLength >= 5 &&
      payload[4] === 0 &&
      payload.readUInt32BE(0) === pingId &&
      state.queuedAt === null
    ) {
      state.queuedAt = state.bulk
    }
    return originalSend.call(this, payload, ...args)
  }
  link.rawStream.write = function (buffer, callback) {
    for (let offset = 0; offset < buffer.byteLength; offset += CELL_SIZE) {
      const id = b4a.toString(buffer.subarray(offset, offset + 36), 'hex')
      const frame = sealed.get(id)
      if (!frame) throw new Error('An outgoing cell had no scoped observation')
      sealed.delete(id)
      if (frame.flag !== 0) continue
      if (bulkIds.has(frame.streamId)) state.bulk++
      if (frame.streamId === pingId && state.queuedAt !== null && state.ahead === null) {
        state.ahead = state.bulk - state.queuedAt
      }
    }
    return originalWrite.call(this, buffer, (error) => {
      if (!state.active || state.delay === 0) {
        callback(error)
        return
      }
      const timer = setTimeout(() => {
        delayed.delete(timer)
        callback(error)
      }, state.delay)
      delayed.set(timer, () => callback(error))
    })
  }
  state.restore = () => {
    if (!state.active) return
    state.active = false
    link.send = originalSend
    link.rawStream.write = originalWrite
    for (const [timer, complete] of delayed) {
      clearTimeout(timer)
      complete()
    }
    delayed.clear()
  }
  t.teardown(state.restore)
  return state
}

test('shared-link scheduling bounds an interactive stream behind bulk in both directions', async (t) => {
  t.timeout(180_000)
  let watched = null
  const sealed = new Map()
  const observer = (event) => {
    if (!watched || event.type !== 'route-cell-sealed' || event.label !== watched.label) return
    const payload = event.plaintext
    sealed.set(b4a.toString(event.cell.subarray(0, 36), 'hex'), {
      streamId: payload.readUInt32BE(0),
      flag: payload[4]
    })
  }
  const {
    nodes: [source, destination],
    controllers
  } = await network(t, observer)
  const { server, accepted } = await listen(t, destination, false)
  const bulk = []
  for (let i = 0; i < 4; i++) {
    const stream = connect(t, source, server)
    t.is(await stream.opened, true)
    bulk.push(stream)
  }
  const ping = connect(t, source, server)
  t.is(await ping.opened, true)
  await until(() => accepted.length === 5)
  await Promise.all(accepted.map((stream) => stream.opened))
  // Match the accepted endpoint by a real application exchange rather than by
  // assuming concurrent handshakes arrive in invocation order.
  for (const stream of accepted) stream.on('data', identify)
  let pingRemote = null
  function identify(data) {
    if (data.byteLength === 1 && data[0] === 0x2a) {
      pingRemote = this
      this.write(data)
    }
  }
  t.is(await exchange(ping, 1, 0x2a), true)
  for (const stream of accepted) stream.removeListener('data', identify)
  const bulkRemote = accepted.filter((stream) => stream !== pingRemote)
  const bulkIds = new Set(bulkRemote.map((stream) => stream.rawStream.streamId))
  pingRemote.on('data', (data) => pingRemote.write(data))
  const entry = entryCircuit(controllers, server)
  const route = server._route

  for (const direction of ['forward', 'reverse']) {
    const link = direction === 'forward' ? entry.link : route.link
    const writers = direction === 'forward' ? bulk : bulkRemote
    const readers = direction === 'forward' ? bulkRemote : bulk
    if (!(await until(() => link.pendingSends === 0)))
      throw new Error('The shared link did not become idle before pacing')
    watched = link
    const paced = pacedSharedWriter(t, link, bulkIds, pingRemote.rawStream.streamId, sealed)
    const receiving = Promise.all(readers.map((reader) => receive(reader, 4 * MIB, 0x70)))
    const sending = Promise.all(writers.map((writer) => send(writer, 4 * MIB, 0x70)))
    let peakPending = 0
    const backlogged = await until(() => {
      peakPending = Math.max(peakPending, link.pendingData)
      return link.pendingData >= 160
    }, 5000)
    if (!backlogged) t.comment(direction + ' maximum pending DATA: ' + peakPending)
    t.ok(backlogged, direction + ' bulk produces a real bounded shared-link backlog')
    const started = Date.now()
    const echoed = await exchange(ping, 64, 0x71)
    const elapsed = Date.now() - started
    t.is(echoed, true, direction + ' interactive echo completes while bulk remains in flight')
    t.comment(direction + ' bulk cells ahead after interactive enqueue: ' + paced.ahead)
    t.ok(
      paced.ahead !== null && paced.ahead <= 16,
      direction +
        ' interactive DATA waits for at most sixteen newly transmitted bulk cells after enqueue'
    )
    t.ok(elapsed < 2000, direction + ' interactive work has a bounded real completion time')
    paced.delay = 0
    t.ok((await sending).every(Boolean), direction + ' every bulk writer completes')
    t.ok(
      (await receiving).every(Boolean),
      direction + ' every bulk stream remains byte-exact after scheduling'
    )
    await until(() => link.pendingSends === 0)
    paced.restore()
    watched = null
    sealed.clear()
  }
})
