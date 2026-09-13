'use strict'

const test = require('brittle')
const b4a = require('b4a')

const HyperDHT = require('../..')
const { hash } = require('../../lib/crypto')
const { periodOf } = require('../../lib/private/blinded-presence')
const {
  decodeDescriptor,
  descriptorTarget
} = require('../../lib/private/overlay-descriptor-service')
const peerController = require('../../lib/private/private-peer-controller')
const { TEST_ONLY_PRIVATE_PEER_OBSERVER } = peerController

const OP_RESOLVE = 2
const OP_ENTRY_REGISTER = 4
const STATUS_UNAVAILABLE = 1
const ROUTE_CONTEXT_BYTES = 120
const LOGICAL_DATA = 0
const LOGICAL_RESET = 3
const LOGICAL_HEADER_BYTES = 5

let nextPort = 49300

function privateRouting(relay = false) {
  return { release: 'alpha', acknowledgeAlpha: true, mode: 'optional', relay }
}

async function network(t, roles = [false, false, true, true, true]) {
  const boot = new HyperDHT({
    bootstrap: [],
    host: '127.0.0.1',
    port: nextPort++,
    ephemeral: false,
    firewalled: false
  })
  await boot.ready()
  const bootstrap = [{ host: '127.0.0.1', port: boot.address().port }]
  const nodes = roles.map(
    (relay) =>
      new HyperDHT({
        bootstrap,
        host: '127.0.0.1',
        port: nextPort++,
        ephemeral: false,
        firewalled: false,
        privateRouting: privateRouting(relay)
      })
  )
  t.teardown(async () => {
    await Promise.allSettled(nodes.reverse().map((node) => node.destroy({ force: true })))
    await boot.destroy({ force: true })
  })
  await Promise.all(nodes.map((node) => node.ready()))
  await Promise.all(nodes.map((node) => node.privateRouting.ready()))
  return nodes
}

function readBytes(stream, expected) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let length = 0
    function cleanup() {
      stream.removeListener('data', ondata)
      stream.removeListener('error', onerror)
      stream.removeListener('end', onend)
    }
    function ondata(chunk) {
      chunks.push(b4a.from(chunk))
      length += chunk.byteLength
      if (length < expected) return
      cleanup()
      resolve(b4a.concat(chunks))
    }
    function onerror(error) {
      cleanup()
      reject(error)
    }
    function onend() {
      cleanup()
      reject(new Error('Private peer stream ended early'))
    }
    stream.on('data', ondata)
    stream.once('error', onerror)
    stream.once('end', onend)
  })
}

function code(operation) {
  try {
    const result = operation()
    if (result && typeof result.then === 'function') {
      return result.then(
        () => null,
        (error) => error.code
      )
    }
    return Promise.resolve(null)
  } catch (error) {
    return Promise.resolve(error.code)
  }
}

test('private routing is an optional context on an ordinary HyperDHT node', async (t) => {
  const valid = privateRouting()
  const invalid = [
    undefined,
    null,
    false,
    {},
    { ...valid, release: 'beta' },
    { ...valid, acknowledgeAlpha: false },
    { ...valid, mode: 'required' },
    { ...valid, relay: 'yes' },
    { ...valid, bootstrapEndpoints: [{ host: '127.0.0.1', port: 49737 }] }
  ]
  for (const value of invalid) {
    t.is(await code(() => new HyperDHT({ privateRouting: value })), 'INVALID_ROUTE')
  }

  const [source, destination, relay] = await network(t)
  t.is(source.outboundPolicy, 'direct', 'ordinary DHT participation remains direct')
  t.ok(source.udx, 'ordinary UDX and routing-table discovery remain active')
  t.is(source.privateRouting.release, 'alpha')
  t.is(source.privateRouting.mode, 'optional')
  t.is(source.privateRouting.relay, false)
  t.is(relay.privateRouting.relay, true)
  t.is(await code(() => relay.privateRouting.createServer()), 'ERR_PRIVACY_UNAVAILABLE')
  t.is(
    await code(() => relay.privateRouting.connect(HyperDHT.keyPair().publicKey)),
    'ERR_PRIVACY_UNAVAILABLE'
  )

  const directServer = destination.createServer((socket) => {
    socket.on('error', () => {})
    socket.on('data', (data) => socket.write(data))
  })
  t.teardown(() => directServer.close())
  await directServer.listen()
  const socket = source.connect(directServer.publicKey)
  socket.on('error', () => {})
  t.is(
    await socket.opened,
    true,
    'normal connect remains direct when private routing is configured'
  )
  const echoed = readBytes(socket, 6)
  socket.write('direct')
  t.alike((await echoed).subarray(0, 6), b4a.from('direct'))
  socket.end()
})

test('private context multiplexes end-to-end Noise streams over transformed route cells', async (t) => {
  let lastSourceOpened = null
  const transformProof = { inbound: null, outbound: null, plaintext: null }
  let latePayload = null
  let lateLogicalFrame = null
  let holdLateFrame = false
  let resolveDestinationReset
  let resolveLateFrameHeld
  let resolveLateFrameReceived
  let releaseLateFrame
  const destinationResetSeen = new Promise((resolve) => {
    resolveDestinationReset = resolve
  })
  const lateFrameHeld = new Promise((resolve) => {
    resolveLateFrameHeld = resolve
  })
  const lateFrameReceived = new Promise((resolve) => {
    resolveLateFrameReceived = resolve
  })
  const lateFrameGate = new Promise((resolve) => {
    releaseLateFrame = resolve
  })
  const restoreObserver = peerController[TEST_ONLY_PRIVATE_PEER_OBSERVER]((event) => {
    if (
      holdLateFrame &&
      event.type === 'route-transform' &&
      event.from === 'guard-destination' &&
      event.to === 'guard-entry' &&
      event.plaintext.byteLength > LOGICAL_HEADER_BYTES &&
      event.plaintext[4] === LOGICAL_DATA
    ) {
      holdLateFrame = false
      lateLogicalFrame = b4a.from(event.plaintext)
      resolveLateFrameHeld()
      return lateFrameGate
    }
    if (
      event.type === 'route-cell-opened' &&
      event.label === 'entry-destination' &&
      lateLogicalFrame !== null &&
      b4a.equals(event.plaintext, lateLogicalFrame)
    ) {
      resolveLateFrameReceived()
      return
    }
    if (
      event.type === 'route-cell-opened' &&
      event.label === 'destination-endpoint' &&
      event.plaintext.byteLength === 5 &&
      event.plaintext[4] === LOGICAL_RESET
    ) {
      resolveDestinationReset()
      return
    }
    if (event.type === 'route-cell-opened' && event.label === 'guard-source') {
      lastSourceOpened = event
      return
    }
    if (
      transformProof.inbound === null &&
      event.type === 'route-transform' &&
      event.from === 'guard-source' &&
      event.to === 'guard-entry-source' &&
      lastSourceOpened !== null &&
      b4a.equals(lastSourceOpened.plaintext, event.plaintext)
    ) {
      transformProof.inbound = b4a.from(lastSourceOpened.cell)
      transformProof.plaintext = b4a.from(event.plaintext)
      return
    }
    if (
      transformProof.inbound !== null &&
      transformProof.outbound === null &&
      event.type === 'route-cell-sealed' &&
      event.label === 'guard-entry-source' &&
      b4a.equals(transformProof.plaintext, event.plaintext)
    ) {
      transformProof.outbound = b4a.from(event.cell)
    }
  })
  t.teardown(restoreObserver)
  t.teardown(() => releaseLateFrame())

  const nodes = await network(t)
  const source = nodes[0]
  const destination = nodes[1]
  const serverKeyPair = HyperDHT.keyPair()
  const accepted = []
  const server = destination.privateRouting.createServer((socket) => {
    socket.on('error', () => {})
    accepted.push(socket)
    socket.on('data', (data) => socket.write(data))
  })
  t.teardown(() => server.close())
  await server.listen(serverKeyPair)

  let destinationDiscovered = false
  for await (const result of source.findPeer(server.publicKey)) {
    destinationDiscovered = true
    t.absent(result)
  }
  t.is(destinationDiscovered, false, 'application key has no public peer record')

  const direct = source.connect(server.publicKey)
  direct.on('error', () => {})
  t.is(await direct.opened, false, 'ordinary connect does not silently enter a private route')
  t.is(accepted.length, 0, 'a direct dial never reaches the private server')

  const descriptor = decodeDescriptor(server._descriptor)
  t.is(
    b4a.equals(descriptor.entryRelayPublicKey, descriptor.destinationGuardPublicKey),
    false,
    'destination guard and entry roles are distinct'
  )
  const period = periodOf(Date.now())
  const currentTarget = descriptorTarget(server.publicKey, period)
  const nextTarget = descriptorTarget(server.publicKey, period + 1n)
  const stableTarget = hash(server.publicKey)
  t.is(
    b4a.equals(currentTarget, stableTarget),
    false,
    'descriptor storage does not expose the stable application-key hash'
  )
  t.is(
    b4a.equals(currentTarget, nextTarget),
    false,
    'descriptor storage target rotates with the blinded period'
  )
  currentTarget.fill(0)
  nextTarget.fill(0)
  stableTarget.fill(0)
  const overlappingResolver = source.connect(descriptor.destinationGuardPublicKey, {
    keyPair: HyperDHT.keyPair()
  })
  overlappingResolver.on('error', () => {})
  t.is(await overlappingResolver.opened, true)
  const resolverStatus = readBytes(overlappingResolver, 1)
  overlappingResolver.write(b4a.from([OP_RESOLVE]))
  t.is(
    (await resolverStatus)[0],
    STATUS_UNAVAILABLE,
    'destination guard rejects resolver role before the destination key is sent'
  )
  overlappingResolver.destroy()

  const forgedRegistration = source.connect(descriptor.entryRelayPublicKey, {
    keyPair: HyperDHT.keyPair()
  })
  forgedRegistration.on('error', () => {})
  t.is(await forgedRegistration.opened, true)
  const registrationStatus = readBytes(forgedRegistration, 1)
  forgedRegistration.write(
    b4a.concat([
      b4a.from([OP_ENTRY_REGISTER]),
      descriptor.wire,
      b4a.alloc(ROUTE_CONTEXT_BYTES, 0x7b)
    ])
  )
  t.is(
    (await registrationStatus)[0],
    STATUS_UNAVAILABLE,
    'entry rejects registration outside the authenticated destination-guard identity'
  )
  forgedRegistration.destroy()

  const payloads = [b4a.alloc(64 * 1024, 0x5a), b4a.alloc(48 * 1024, 0xa5)]
  const sockets = payloads.map(() => source.privateRouting.connect(server.publicKey))
  for (const socket of sockets) socket.on('error', () => {})
  t.alike(
    await Promise.all(sockets.map((socket) => socket.opened)),
    [true, true],
    'both logical sessions complete end-to-end Noise authentication'
  )
  for (const socket of sockets) t.alike(socket.remotePublicKey, serverKeyPair.publicKey)

  const echoes = sockets.map((socket, index) => readBytes(socket, payloads[index].byteLength))
  sockets.forEach((socket, index) => socket.write(payloads[index]))
  const received = await Promise.all(echoes)
  received.forEach((data, index) => {
    t.alike(data.subarray(0, payloads[index].byteLength), payloads[index])
  })
  t.is(accepted.length, 2, 'one destination circuit accepts two independent logical streams')
  for (const socket of accepted) t.alike(socket.remotePublicKey, source.defaultKeyPair.publicKey)
  latePayload = b4a.from('late response crosses reset')
  holdLateFrame = true
  sockets[0].write(latePayload)
  await lateFrameHeld
  const firstClosed = new Promise((resolve) => sockets[0].once('close', resolve))
  sockets[0].destroy()
  await Promise.all([firstClosed, destinationResetSeen])
  releaseLateFrame()
  await lateFrameReceived

  const survivorPayload = b4a.from('sibling stream survives late peer data')
  const survivorEcho = readBytes(sockets[1], survivorPayload.byteLength)
  sockets[1].write(survivorPayload)
  t.alike(
    (await survivorEcho).subarray(0, survivorPayload.byteLength),
    survivorPayload,
    'late data for a reset stream cannot retire its sibling'
  )

  t.ok(transformProof.inbound, 'source guard opens a fixed authenticated route cell')
  t.ok(transformProof.outbound, 'source guard reseals the payload for the next hop')
  t.is(transformProof.inbound.byteLength, 1200)
  t.is(transformProof.outbound.byteLength, 1200)
  t.is(
    b4a.equals(transformProof.inbound, transformProof.outbound),
    false,
    'relay transformation changes on-wire bytes per hop'
  )
  t.alike(source.privateRouting.exposureReport(), {
    overlayParticipation: 'direct-compatible',
    relayService: 'disabled',
    relayDiscovery: 'hyperdht-routing-table',
    descriptorAddressing: 'period-blinded',
    descriptorOperations: 'source-safety-routed',
    peerPayload: 'm3-hop-transformed-noise-secretstream',
    directDestinationSends: 0
  })

  for (const socket of sockets) if (!socket.destroyed) socket.end()
})

test('same-key private server restart advances the blinded descriptor sequence', async (t) => {
  const nodes = await network(t)
  const source = nodes[0]
  const destination = nodes[1]
  const serverKeyPair = HyperDHT.keyPair()
  const first = destination.privateRouting.createServer()
  await first.listen(serverKeyPair)
  const firstDescriptor = decodeDescriptor(first._descriptor)
  await first.close()

  let accepted = false
  const second = destination.privateRouting.createServer((socket) => {
    socket.on('error', () => {})
    accepted = true
    socket.end()
  })
  t.teardown(() => second.close())
  await second.listen(serverKeyPair)
  const secondDescriptor = decodeDescriptor(second._descriptor)
  t.ok(secondDescriptor.seq > firstDescriptor.seq, 'replacement descriptor wins sequence ordering')

  const socket = source.privateRouting.connect(serverKeyPair.publicKey)
  socket.on('error', () => {})
  t.is(await socket.opened, true, 'clients resolve the replacement route capability')
  t.alike(socket.remotePublicKey, serverKeyPair.publicKey)
  t.is(accepted, true, 'recreated server accepts the private stream')
  socket.end()
})

test('private context fails closed for absent destinations and insufficient relay diversity', async (t) => {
  const nodes = await network(t)
  const source = nodes[0]
  const socket = source.privateRouting.connect(HyperDHT.keyPair().publicKey)
  socket.on('error', () => {})
  t.is(await socket.opened, false)
  t.is(source.privateRouting.exposureReport().directDestinationSends, 0)

  const sparse = await network(t, [false, false, true, true])
  const server = sparse[1].privateRouting.createServer()
  t.teardown(() => server.close())
  await server.listen(HyperDHT.keyPair())
  const diversityFailure = sparse[0].privateRouting.connect(server.publicKey)
  diversityFailure.on('error', () => {})
  t.is(await diversityFailure.opened, false, 'source guard cannot reuse destination route roles')
})
