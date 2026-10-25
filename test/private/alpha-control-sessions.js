'use strict'

const test = require('brittle')
const b4a = require('b4a')
const { Writable } = require('streamx')
const HyperDHT = require('../..')
const createTestnet = require('../../testnet')
const peer = require('../../lib/private/private-peer-controller')
const { createAdvancingClock, createPrivatePeerTestScope } = require('./helpers/private-peer')
const sodium = require('sodium-universal')
const { COMMANDS } = require('../../lib/constants')
const { CellCodec, CELL_SIZE } = require('../../lib/private/cell-codec')
const { SenderCounter } = require('../../lib/private/counters')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { CELL_CLASS, DIRECTION } = require('../../lib/private/protocol')
const {
  decodeDescriptor,
  descriptorTarget
} = require('../../lib/private/overlay-descriptor-service')

const VERSION = 7
const BUILD_DESTINATION = 3
const BUILD_SOURCE = 5
const EXTEND_SOURCE = 7
const PER_PEER = 8
const GLOBAL = 64

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds))
}

async function until(predicate, milliseconds = 2000) {
  const end = Date.now() + milliseconds
  while (!predicate()) {
    if (Date.now() >= end) return false
    await delay(5)
  }
  return true
}

async function network(t, options = {}) {
  const net = await createTestnet(1, { bootstrap: [] })
  const scope = createPrivatePeerTestScope()
  const controllers = new Map()
  const incoming = new Map()
  t.teardown(async () => {
    try {
      await Promise.allSettled(net.nodes.map((node) => node.destroy({ force: true })))
    } finally {
      scope.close()
    }
  })
  function createNode(relay = false) {
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
        {
          controlLimits: {
            maxSessions: GLOBAL,
            maxPeerSessions: PER_PEER,
            opcodeTimeoutMs: 2000,
            readTimeoutMs: 5000,
            sessionTimeoutMs: 10000
          },
          ...options
        }
      )
    } finally {
      peer.createPrivatePeerController = original
    }
  }
  const nodes = [false, false, true, true, true, true, true, true].map(createNode)
  await Promise.all(nodes.map((node) => node.privateRouting.ready()))
  for (const node of nodes) {
    const controller = controllers.get(node)
    if (!controller.relayServer) continue
    controller.relayServer.on('connection', (stream) => {
      incoming.set(b4a.toString(stream.remotePublicKey, 'hex'), stream)
    })
  }
  return { net, nodes, controllers, incoming, createNode }
}

async function control(t, fixture, node, relay, keyPair = HyperDHT.keyPair()) {
  const controller = fixture.controllers.get(relay)
  const stream = node.connect(controller.relayKeyPair.publicKey, { keyPair })
  const chunks = []
  let bytes = 0
  let ended = false
  stream.on('error', () => {})
  stream.on('data', (chunk) => {
    chunks.push(b4a.from(chunk))
    bytes += chunk.byteLength
  })
  stream.once('end', () => {
    ended = true
  })
  stream.once('close', () => {
    ended = true
  })
  t.teardown(() => stream.destroy())
  if (!(await stream.opened)) throw new Error('Control transport did not authenticate')
  const id = b4a.toString(keyPair.publicKey, 'hex')
  if (!(await until(() => fixture.incoming.has(id)))) {
    throw new Error('Relay did not accept the authenticated control transport')
  }
  const accepted = fixture.incoming.get(id)
  return {
    stream,
    accepted,
    startedAt: Date.now(),
    async read(size, milliseconds = 2000) {
      if (!(await until(() => bytes >= size || ended, milliseconds)) || bytes < size) return null
      const all = b4a.concat(chunks)
      const result = b4a.from(all.subarray(0, size))
      chunks.length = 0
      if (all.byteLength > size) chunks.push(b4a.from(all.subarray(size)))
      bytes -= size
      return result
    }
  }
}

async function admission(t, fixture, node, relay, keyPair) {
  const session = await control(t, fixture, node, relay, keyPair)
  session.stream.write(b4a.from([VERSION, BUILD_DESTINATION]))
  return { session, response: await session.read(33) }
}

async function cancel(sessions) {
  for (const session of sessions) session.stream.destroy()
  return until(() => sessions.every((session) => session.accepted.destroyed))
}

async function echo(stream, value, milliseconds = 5000) {
  const expected = b4a.from(value)
  return new Promise((resolve) => {
    let offset = 0
    let intact = true
    const timer = setTimeout(() => finish(false), milliseconds)
    const ondata = (data) => {
      intact = intact && b4a.equals(data, expected.subarray(offset, offset + data.byteLength))
      offset += data.byteLength
      if (offset >= expected.byteLength) finish(intact && offset === expected.byteLength)
    }
    const onclose = () => finish(false)
    function finish(result) {
      clearTimeout(timer)
      stream.removeListener('data', ondata)
      stream.removeListener('error', onclose)
      stream.removeListener('close', onclose)
      resolve(result)
    }
    stream.on('data', ondata)
    stream.once('error', onclose)
    stream.once('close', onclose)
    if (stream.destroying || stream.destroyed) finish(false)
    else stream.write(expected)
  })
}

async function listener(t, destination) {
  const accepted = []
  const server = destination.privateRouting.createServer((stream) => {
    stream.on('error', () => {})
    stream.on('data', (data) => stream.write(data))
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

function resolverCell(context, period, target) {
  const origin = b4a.alloc(32)
  sodium.crypto_generichash(
    origin,
    b4a.from('hyperdht/private-peer/counter-origin/v1'),
    context.subarray(24, 56)
  )
  let initial = 0n
  for (let index = 0; index < 8; index++) initial = (initial << 8n) | BigInt(origin[index])
  origin.fill(0)
  const sender = new SenderCounter({ initial: (initial & 0x7fffffffffffffffn) + 1n })
  const request = b4a.alloc(41)
  request[0] = 1
  for (let index = 8; index > 0; index--) {
    request[index] = Number(period & 0xffn)
    period >>= 8n
  }
  target.copy(request, 9)
  try {
    return new CellCodec({ crypto: cryptoSuite, cellSize: CELL_SIZE }).seal({
      key: context.subarray(24, 56),
      noncePrefix: context.subarray(56, 72),
      senderCounter: sender,
      class: CELL_CLASS.STREAM,
      direction: DIRECTION.FORWARD,
      epoch: 9n,
      circuitId: context.subarray(0, 16),
      payload: request
    })
  } finally {
    sender.destroy()
    request.fill(0)
  }
}

test('a cancelled relay resolver drains descriptor requests before its admission slot is reused', async (t) => {
  t.timeout(90_000)
  let resolvedWrites = 0
  const fixture = await network(t, {
    observer(event) {
      if (event.type === 'control-write' && event.label === 'source-resolved') resolvedWrites++
    }
  })
  const [source, destination, relay] = fixture.nodes
  const controller = fixture.controllers.get(relay)
  const { server } = await listener(t, destination)
  const descriptor = decodeDescriptor(server._descriptor)
  const target = descriptorTarget(server.publicKey, descriptor.period)
  const held = []
  let deferred = true
  const restores = []
  function release() {
    deferred = false
    for (const respond of held.splice(0)) respond()
  }
  t.teardown(
    () => {
      release()
      for (const restore of restores) restore()
      target.fill(0)
      for (const value of Object.values(descriptor)) if (b4a.isBuffer(value)) value.fill(0)
    },
    { force: true, order: -1 }
  )
  for (const peerController of fixture.controllers.values()) {
    const plugin = peerController.descriptors.plugin
    const respond = plugin.onrequest
    plugin.onrequest = function (request, outer) {
      if (
        deferred &&
        (request.command === 0 || request.command === 3) &&
        outer.target &&
        b4a.equals(outer.target, target)
      ) {
        held.push(() => respond.call(this, request, outer))
      } else respond.call(this, request, outer)
    }
    restores.push(() => {
      plugin.onrequest = respond
    })
  }
  const liveRequests = () =>
    relay.io.inflight.filter(
      (request) =>
        request.command === COMMANDS.PLUGIN && request.target && b4a.equals(request.target, target)
    )
  const holders = []
  for (let index = 0; index < PER_PEER - 1; index++) {
    const admitted = await admission(t, fixture, source, relay)
    if (!admitted.response || admitted.response[0] !== 0)
      throw new Error('Fixture admission failed')
    holders.push(admitted.session)
  }
  const resolver = await control(t, fixture, source, relay)
  const context = b4a.alloc(120)
  sodium.randombytes_buf(context)
  context.fill(0, 16, 24)
  context[23] = 9
  resolver.stream.write(b4a.concat([b4a.from([VERSION, EXTEND_SOURCE]), context]))
  t.alike(
    await resolver.read(1),
    b4a.from([0]),
    'the actual second-safety resolver enters cell control'
  )
  const cell = resolverCell(context, descriptor.period, target)
  resolver.stream.write(cell)
  if (!(await Writable.drained(resolver.stream))) throw new Error('Resolver cell write failed')
  cell.fill(0)
  context.fill(0)
  t.ok(
    await until(() => held.length >= 2 && liveRequests().length >= 2, 10000),
    'its encrypted request creates real deferred descriptor RPCs'
  )
  const overflow = await control(t, fixture, source, relay)
  t.alike(
    await overflow.read(1),
    b4a.from([1]),
    'the resolver occupies the eighth unfinished admission slot'
  )
  resolver.stream.destroy()
  t.ok(
    await until(
      () => resolver.accepted.destroyed && controller.controlSessions.size === PER_PEER - 1,
      1000
    ),
    'peer cancellation joins its descriptor work before releasing the slot'
  )
  t.is(
    liveRequests().length,
    0,
    'all resolver requests leave native IO while storage replies are still withheld'
  )
  const replacementKey = HyperDHT.keyPair()
  let requestsAtAdmission = -1
  const observeAdmission = (stream) => {
    if (b4a.equals(stream.remotePublicKey, replacementKey.publicKey))
      requestsAtAdmission = liveRequests().length
  }
  controller.relayServer.on('connection', observeAdmission)
  let replacement
  try {
    replacement = await admission(t, fixture, source, relay, replacementKey)
  } finally {
    controller.relayServer.removeListener('connection', observeAdmission)
  }
  t.is(
    replacement.response && replacement.response[0],
    0,
    'the released slot admits another real setup'
  )
  t.is(
    requestsAtAdmission,
    0,
    'no cancelled descriptor request is alive when the replacement is admitted'
  )
  holders.push(replacement.session)
  release()
  await delay(50)
  t.is(resolvedWrites, 0, 'late valid replies cannot advance the cancelled resolver')
  t.is(
    controller.resolverStreams.has(resolver.accepted),
    false,
    'the cancelled resolver no longer owns its transport'
  )
  await cancel(holders)
  const client = connect(t, source, server)
  t.is(await client.opened, true, 'an independent application still authenticates')
  t.is(
    await echo(client, 'after cancelled descriptor resolution'),
    true,
    'the independent route carries real bytes'
  )
})

test('relay opcode deadline uses elapsed time and reclaims a partial header', async (t) => {
  t.timeout(60_000)
  const fixture = await network(t, { clock: createAdvancingClock({ rate: 20 }) })
  const [source, , relay] = fixture.nodes
  const session = await control(t, fixture, source, relay)
  session.stream.write(b4a.from([VERSION]))
  await delay(1000)
  t.is(session.accepted.destroyed, false, 'accelerated protocol time does not expire the header')
  const closed = await until(() => session.accepted.destroyed, 2500)
  const elapsed = Date.now() - session.startedAt
  t.ok(closed, 'the incomplete opcode closes without waiting for the old fifteen-second read')
  t.ok(elapsed >= 1500 && elapsed < 3500, 'the opcode deadline is approximately two real seconds')
})

test('all five relay opcodes and the encrypted resolver inbox have bounded silent reads', async (t) => {
  t.timeout(60_000)
  const fixture = await network(t)
  const [source, , relay] = fixture.nodes
  const sessions = await Promise.all(
    [3, 4, 5, 6, 7].map(async (opcode) => {
      const session = await control(t, fixture, source, relay)
      session.stream.write(b4a.from([VERSION, opcode]))
      return session
    })
  )
  const inbox = await control(t, fixture, source, relay)
  inbox.stream.write(b4a.concat([b4a.from([VERSION, EXTEND_SOURCE]), b4a.alloc(120, 0x31)]))
  t.alike(await inbox.read(1), b4a.from([0]), 'the second safety enters its cell-control stage')
  sessions.push(inbox)
  await delay(3000)
  t.ok(
    sessions.every((session) => !session.accepted.destroyed),
    'valid headers leave time for each stage'
  )
  t.ok(
    await until(() => sessions.every((session) => session.accepted.destroyed), 3500),
    'every silent setup stage, including the cell inbox, closes near five seconds'
  )
})

test('progress across setup fields cannot renew the whole-session deadline', async (t) => {
  t.timeout(60_000)
  const fixture = await network(t)
  const [source, , relay, second] = fixture.nodes
  const session = await control(t, fixture, source, relay)
  session.stream.write(b4a.from([VERSION, BUILD_SOURCE]))
  await delay(3500)
  session.stream.write(fixture.controllers.get(second).relayKeyPair.publicKey)
  await delay(3500)
  session.stream.write(b4a.alloc(120, 0x42))
  await delay(1500)
  t.is(session.accepted.destroyed, false, 'each completed field stays inside its five-second read')
  session.stream.write(b4a.alloc(60, 0x43))
  t.ok(
    await until(() => session.accepted.destroyed, 3000),
    'a partial next field cannot extend setup beyond ten seconds'
  )
  const elapsed = Date.now() - session.startedAt
  t.ok(elapsed >= 9000 && elapsed < 11_500, 'one real deadline covers the entire setup')
})

test('per-peer setup admission resists identity churn and recovers without disrupting honest traffic', async (t) => {
  t.timeout(90_000)
  const fixture = await network(t)
  const [source, destination, relay] = fixture.nodes
  const attacker = fixture.createNode()
  await attacker.privateRouting.ready()
  const { server } = await listener(t, destination)
  const admitted = await Promise.all(
    Array.from({ length: PER_PEER }, () => admission(t, fixture, attacker, relay))
  )
  t.ok(
    admitted.every(({ response }) => response && response[0] === 0),
    'eight independent authenticated setup streams are admitted'
  )
  const holders = admitted.map(({ session }) => session)
  const overflow = await control(t, fixture, attacker, relay)
  t.alike(
    await overflow.read(1, 1000),
    b4a.from([1]),
    'a fresh identity at the same observed peer is rejected before sending an opcode'
  )
  t.ok(
    holders.every((session) => !session.accepted.destroyed),
    'overload does not evict existing sessions'
  )
  const honest = connect(t, source, server)
  t.is(await honest.opened, true, 'an unrelated peer still builds a private application route')
  t.is(await echo(honest, 'honest traffic during setup saturation'), true)
  t.ok(await cancel(holders), 'peer cancellation closes every admitted incoming stream')
  overflow.stream.destroy()
  const recovered = await Promise.all(
    Array.from({ length: PER_PEER }, () => admission(t, fixture, attacker, relay))
  )
  t.ok(
    recovered.every(({ response }) => response && response[0] === 0),
    'all peer admission slots become reusable after cancellation'
  )
  await cancel(recovered.map(({ session }) => session))
  t.is(await echo(honest, 'honest traffic after cancellation'), true)
})

test('global setup admission rejects the sixty-fifth stream and releases every cancelled slot', async (t) => {
  t.timeout(90_000)
  const fixture = await network(t)
  const [, , relay] = fixture.nodes
  const attackers = Array.from({ length: GLOBAL / PER_PEER }, () => fixture.createNode())
  const outsider = fixture.createNode()
  await Promise.all([...attackers, outsider].map((node) => node.privateRouting.ready()))
  const admitted = await Promise.all(
    attackers.flatMap((node) =>
      Array.from({ length: PER_PEER }, () => admission(t, fixture, node, relay))
    )
  )
  t.ok(
    admitted.every(({ response }) => response && response[0] === 0),
    'sixty-four unfinished real control sessions are admitted'
  )
  const holders = admitted.map(({ session }) => session)
  const overflow = await control(t, fixture, outsider, relay)
  t.alike(
    await overflow.read(1, 1000),
    b4a.from([1]),
    'an unrelated sixty-fifth session receives prompt unavailability'
  )
  t.ok(
    holders.every((session) => !session.accepted.destroyed),
    'global overload leaves admitted peers alone'
  )
  t.ok(await cancel(holders), 'cancelling the sixty-four streams closes their remote resources')
  overflow.stream.destroy()
  const recovered = await Promise.all(
    attackers.flatMap((node) =>
      Array.from({ length: PER_PEER }, () => admission(t, fixture, node, relay))
    )
  )
  t.ok(
    recovered.every(({ response }) => response && response[0] === 0),
    'all global admission slots are reusable'
  )
  await cancel(recovered.map(({ session }) => session))
})

test('setup cancellation closes owned outgoing dials and stalled incoming streams on suspend and destroy', async (t) => {
  t.timeout(90_000)
  const fixture = await network(t)
  const [source, blockedNode, relay] = fixture.nodes
  const controller = fixture.controllers.get(relay)
  const outgoing = []
  const original = controller.connectDirect
  controller.connectDirect = (...args) => {
    const stream = original(...args)
    outgoing.push(stream)
    return stream
  }
  t.teardown(() => {
    controller.connectDirect = original
  })
  const decisions = []
  let closing = false
  const blockedServer = blockedNode.createServer({
    firewall() {
      if (closing) return true
      return new Promise((resolve) => decisions.push(resolve))
    }
  })
  t.teardown(
    async () => {
      closing = true
      for (const resolve of decisions) resolve(true)
      decisions.length = 0
      for (const stream of outgoing) stream.destroy()
      await blockedServer.close()
    },
    { order: -1, force: true }
  )
  await blockedServer.listen(HyperDHT.keyPair())
  async function pendingDial() {
    const session = await control(t, fixture, source, relay)
    const before = outgoing.length
    const waiting = decisions.length
    session.stream.write(
      b4a.concat([b4a.from([VERSION, BUILD_SOURCE]), blockedServer.publicKey, b4a.alloc(240, 0x55)])
    )
    if (!(await until(() => outgoing.length > before && decisions.length > waiting))) {
      throw new Error('The real outgoing handshake did not reach the deferred firewall')
    }
    t.is(
      outgoing[before].connected,
      false,
      'the remote firewall holds the real dial before establishment'
    )
    return { session, dial: outgoing[before] }
  }
  const first = await pendingDial()
  first.session.stream.destroy()
  t.ok(
    await until(() => first.dial.destroyed),
    'peer cancellation destroys a still-opening outgoing dial rather than detaching it'
  )
  const second = await pendingDial()
  const silent = await control(t, fixture, source, relay)
  await controller.suspend()
  t.ok(
    await until(
      () => second.session.accepted.destroyed && second.dial.destroyed && silent.accepted.destroyed
    ),
    'suspend cancels both raw control reads and their unfinished outgoing dials'
  )
  await controller.resume()
  const resumed = await admission(t, fixture, source, relay)
  t.alike(
    resumed.response && resumed.response.subarray(0, 1),
    b4a.from([0]),
    'resume admits a fresh control session'
  )
  const third = await pendingDial()
  await controller.destroy()
  t.ok(
    await until(
      () =>
        third.dial.destroyed &&
        third.session.accepted.destroyed &&
        resumed.session.accepted.destroyed
    ),
    'destroy closes every incoming setup and owned outgoing dial'
  )
})

test('established and paused application streams outlive every relay setup deadline', async (t) => {
  t.timeout(90_000)
  const fixture = await network(t)
  const [source, destination] = fixture.nodes
  const { server, accepted } = await listener(t, destination)
  const client = connect(t, source, server)
  t.is(
    await client.opened,
    true,
    'the application authenticates through all five control operations'
  )
  t.is(await echo(client, 'before setup timer expiry'), true)
  const remote = accepted[0]
  remote.rawStream.pause()
  const pending = echo(client, 'paused across setup timer expiry', 20_000)
  await delay(11_500)
  t.is(client.destroyed, false, 'setup timers do not own an established application stream')
  t.is(remote.destroyed, false, 'a paused established destination remains live')
  remote.rawStream.resume()
  t.is(await pending, true, 'paused traffic resumes intact beyond the setup deadline')
  t.is(
    await echo(client, 'after setup timer expiry'),
    true,
    'the original route remains bidirectional'
  )
})
