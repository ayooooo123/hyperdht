'use strict'

const test = require('brittle')
const b4a = require('b4a')
const { Writable } = require('streamx')

const HyperDHT = require('../..')
const { hash } = require('../../lib/crypto')
const { periodOf } = require('../../lib/private/blinded-presence')
const {
  OverlayDescriptorService,
  decodeDescriptor,
  descriptorTarget,
  encodeDescriptor
} = require('../../lib/private/overlay-descriptor-service')
const peerController = require('../../lib/private/private-peer-controller')
const { TEST_ONLY_PRIVATE_PEER_OBSERVER, TEST_ONLY_PRIVATE_PEER_WRITE_ALL } = peerController

const OP_RESOLVE = 2
const OP_ENTRY_REGISTER = 4
const STATUS_OK = 0
const STATUS_UNAVAILABLE = 1
const ROUTE_CONTEXT_BYTES = 120
const LOGICAL_DATA = 0
const LOGICAL_RESET = 3
const LOGICAL_HEADER_BYTES = 5
const DESCRIPTOR_COMMAND_GET = 0
const DESCRIPTOR_COMMAND_PUT = 1
const DESCRIPTOR_PLUGIN_NAME = 'private-route'

let nextPort = 49300

function privateRouting(relay = false) {
  return {
    release: 'alpha',
    acknowledgeAlpha: true,
    mode: 'optional',
    profile: 'standard',
    relay
  }
}

async function network(t, roles = [false, false, true, true, true, true]) {
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
function trapDescriptorTraffic(t, node) {
  const traffic = { get: 0, put: 0 }
  const plugin = node.plugins.get(DESCRIPTOR_PLUGIN_NAME)
  const query = plugin.query
  const request = plugin.request
  plugin.query = function (message, ...args) {
    if (message.command === DESCRIPTOR_COMMAND_GET) traffic.get++
    return query.call(this, message, ...args)
  }
  plugin.request = function (message, ...args) {
    if (message.command === DESCRIPTOR_COMMAND_PUT) traffic.put++
    return request.call(this, message, ...args)
  }
  t.teardown(() => {
    plugin.query = query
    plugin.request = request
  })
  return traffic
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
function containsSequence(haystack, needle) {
  outer: for (let offset = 0; offset <= haystack.byteLength - needle.byteLength; offset++) {
    for (let index = 0; index < needle.byteLength; index++) {
      if (haystack[offset + index] !== needle[index]) continue outer
    }
    return true
  }

  return false
}
function turn() {
  return new Promise((resolve) => setTimeout(resolve, 0))
}

test('private cell writes retain queued buffers until transport completion', async (t) => {
  const writes = []
  const callbacks = []
  const stream = new Writable({
    write(data, callback) {
      writes.push(data)
      callbacks.push(callback)
    }
  })
  const first = b4a.alloc(1200, 0x11)
  const second = b4a.alloc(1200, 0x22)
  const send = peerController[TEST_ONLY_PRIVATE_PEER_WRITE_ALL]
  const firstSending = send(stream, first).finally(() => first.fill(0))
  const secondSending = send(stream, second).finally(() => second.fill(0))
  await turn()
  t.is(writes.length, 1, 'downstream drain holds the second write in Streamx')
  t.is(writes[0], first, 'Streamx retains the original first buffer')
  t.is(first[0], 0x11)
  t.is(second[0], 0x22, 'queued cell remains intact while the first write is held')
  callbacks.shift()(null)
  await firstSending
  await turn()
  t.is(first[0], 0)
  t.is(writes.length, 2)
  t.is(writes[1], second, 'queued write reaches transport before caller erases it')
  t.is(second[0], 0x22)
  callbacks.shift()(null)
  await secondSending
  t.is(second[0], 0)
  stream.destroy()
})

test('pending entry commit excludes resolver admission', async (t) => {
  let entryRelayPublicKey = null
  let releaseCommit
  let resolveCommitHeld
  const commitHeld = new Promise((resolve) => {
    resolveCommitHeld = resolve
  })
  const commitGate = new Promise((resolve) => {
    releaseCommit = resolve
  })
  let holdCommit = true
  const restoreObserver = peerController[TEST_ONLY_PRIVATE_PEER_OBSERVER]((event) => {
    if (holdCommit && event.type === 'entry-commit-pending') {
      holdCommit = false
      entryRelayPublicKey = b4a.from(event.entryRelayPublicKey)
      resolveCommitHeld()
      return commitGate
    }
  })
  t.teardown(restoreObserver)
  t.teardown(() => releaseCommit())

  const nodes = await network(t)
  const source = nodes[0]
  const destination = nodes[1]
  const server = destination.privateRouting.createServer((socket) => socket.destroy())
  t.teardown(() => server.close())
  const listening = server.listen(HyperDHT.keyPair())
  await commitHeld

  const resolver = source.connect(entryRelayPublicKey, { keyPair: HyperDHT.keyPair() })
  resolver.on('error', () => {})
  t.is(await resolver.opened, true)
  const response = readBytes(resolver, 1)
  resolver.write(b4a.from([OP_RESOLVE]))
  t.is(
    (await response)[0],
    STATUS_UNAVAILABLE,
    'entry reservation rejects resolver before destination-key input'
  )
  resolver.destroy()

  releaseCommit()
  await listening
  t.ok(server.listening)
})
function asyncReplies(values) {
  return {
    destroy() {},
    async *[Symbol.asyncIterator]() {
      for (const value of values) yield value
    }
  }
}

test('blinded descriptors require quorum storage and exact readback', async (t) => {
  const now = 3 * 86_400_000 + 2 * 60 * 60 * 1000
  const period = periodOf(now)
  const destinationKeyPair = HyperDHT.keyPair()
  const wire = encodeDescriptor({
    destinationKeyPair,
    entryRelayPublicKey: HyperDHT.keyPair().publicKey,
    destinationGuardPublicKey: HyperDHT.keyPair().publicKey,
    routeToken: b4a.alloc(32, 0x69),
    seq: 3n,
    expiresAt: BigInt(now + 60_000),
    period
  })
  t.is(containsSequence(wire, destinationKeyPair.publicKey), false)
  t.is(
    decodeDescriptor(wire, {
      expectedDestinationPublicKey: destinationKeyPair.publicKey,
      expectedPeriod: period,
      now
    }).seq,
    3n
  )
  t.exception(() =>
    decodeDescriptor(wire, {
      expectedDestinationPublicKey: HyperDHT.keyPair().publicKey,
      expectedPeriod: period,
      now
    })
  )

  const dht = {
    register(name, plugin) {
      plugin.onregister(this)
    }
  }
  const descriptors = new OverlayDescriptorService(dht, null, () => now)
  t.teardown(() => descriptors.plugin.destroy())

  descriptors.plugin.query = () => asyncReplies([{ value: wire }])
  t.is(
    await code(() => descriptors.get(destinationKeyPair.publicKey)),
    'ERR_PRIVACY_UNAVAILABLE',
    'one storage reply cannot select route state'
  )
  descriptors.plugin.query = () => asyncReplies([{ value: wire }, { value: wire }])
  t.is((await descriptors.get(destinationKeyPair.publicKey)).seq, 3n)

  const storageCandidates = [1, 2, 3].map((port) => ({
    from: { host: '127.0.0.1', port },
    token: b4a.alloc(32, port)
  }))
  descriptors.plugin.query = () => asyncReplies(storageCandidates.slice(0, 2))
  t.is(
    await code(() => descriptors.put(wire)),
    'ERR_PRIVACY_UNAVAILABLE',
    'fewer than three storage candidates cannot publish route state'
  )

  let requests = 0
  descriptors.plugin.query = () => asyncReplies(storageCandidates)
  descriptors.plugin.request = async () => {
    requests++
    if (requests === 3) throw new Error('withheld replica')
  }
  t.is(
    await code(() => descriptors.put(wire)),
    'ERR_PRIVACY_UNAVAILABLE',
    'fewer than three stored replicas cannot publish route state'
  )

  let queries = 0
  descriptors.plugin.query = () => {
    queries++
    return queries === 1
      ? asyncReplies(storageCandidates)
      : asyncReplies([{ value: wire }, { value: wire }])
  }
  descriptors.plugin.request = async () => {}
  t.is(await descriptors.put(wire), 3)
  wire.fill(0)
})

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
    { ...valid, profile: 'high' },
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
  t.is(source.privateRouting.profile, 'standard')
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
  let selectedSourceRoute = null
  let latePayload = null
  let lateLogicalFrame = null
  let holdLateFrame = false
  let clientLogicalFrame = null
  let holdClientFrame = false
  let forcedDestinationGuard = null
  let rejectedAdmissionRemoteKey = null
  let rejectedIdentitySends = 0
  let rejectedIdentityReceives = 0
  let resolveHeldResolverReleased
  let resolveDestinationReset
  let resolveLateFrameHeld
  let resolveLateFrameReceived
  let resolveClientFrameHeld
  let resolveClientFrameReceived
  let releaseLateFrame
  let releaseClientFrame
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
  const clientFrameHeld = new Promise((resolve) => {
    resolveClientFrameHeld = resolve
  })
  const clientFrameReceived = new Promise((resolve) => {
    resolveClientFrameReceived = resolve
  })
  const clientFrameGate = new Promise((resolve) => {
    releaseClientFrame = resolve
  })
  const heldResolverReleased = new Promise((resolve) => {
    resolveHeldResolverReleased = resolve
  })
  const restoreObserver = peerController[TEST_ONLY_PRIVATE_PEER_OBSERVER]((event) => {
    if (event.type === 'source-route-selected') {
      selectedSourceRoute = event
      return
    }
    if (event.type === 'destination-relay-candidates' && forcedDestinationGuard !== null) {
      return forcedDestinationGuard
    }
    if (
      forcedDestinationGuard !== null &&
      event.guardPublicKey &&
      b4a.equals(event.guardPublicKey, forcedDestinationGuard)
    ) {
      if (event.type === 'destination-admission-attempt') {
        rejectedAdmissionRemoteKey = b4a.from(event.remotePublicKey)
      } else if (event.type === 'destination-identity-sent') {
        rejectedIdentitySends++
      } else if (event.type === 'destination-identity-received') {
        rejectedIdentityReceives++
      }
    }
    if (
      event.type === 'resolver-released' &&
      forcedDestinationGuard !== null &&
      b4a.equals(event.guardPublicKey, forcedDestinationGuard)
    ) {
      resolveHeldResolverReleased()
      return
    }
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
      holdClientFrame &&
      event.type === 'route-transform' &&
      event.from === 'guard-entry' &&
      event.to === 'guard-destination' &&
      event.plaintext.byteLength > LOGICAL_HEADER_BYTES &&
      event.plaintext[4] === LOGICAL_DATA
    ) {
      holdClientFrame = false
      clientLogicalFrame = b4a.from(event.plaintext)
      resolveClientFrameHeld()
      return clientFrameGate
    }
    if (
      event.type === 'route-cell-opened' &&
      event.label === 'destination-endpoint' &&
      clientLogicalFrame !== null &&
      b4a.equals(event.plaintext, clientLogicalFrame)
    ) {
      resolveClientFrameReceived()
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
    if (event.type === 'route-cell-opened' && event.label === 'source-safety-1-in') {
      lastSourceOpened = event
      return
    }
    if (
      transformProof.inbound === null &&
      event.type === 'route-transform' &&
      event.from === 'source-safety-1-in' &&
      event.to === 'source-safety-1-out' &&
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
      event.label === 'source-safety-1-out' &&
      b4a.equals(transformProof.plaintext, event.plaintext)
    ) {
      transformProof.outbound = b4a.from(event.cell)
    }
  })
  t.teardown(restoreObserver)
  t.teardown(() => releaseLateFrame())
  t.teardown(() => releaseClientFrame())

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
  t.is(
    containsSequence(descriptor.wire, server.publicKey),
    false,
    'stored descriptor bytes do not disclose the stable destination identity'
  )
  t.is(
    b4a.equals(descriptor.blindedPublicKey, server.publicKey),
    false,
    'descriptor signature key rotates independently from the stable destination identity'
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
  const relayKeys = await server.controller.descriptors.discoverRelays()
  const reverseOverlapRelay = relayKeys.find(
    (relay) =>
      !b4a.equals(relay, descriptor.destinationGuardPublicKey) &&
      !b4a.equals(relay, descriptor.entryRelayPublicKey)
  )
  if (!reverseOverlapRelay) throw new Error('Missing reverse-overlap relay')
  const heldResolver = source.connect(reverseOverlapRelay, {
    keyPair: HyperDHT.keyPair()
  })
  heldResolver.on('error', () => {})
  t.is(await heldResolver.opened, true)
  const heldResolverStatus = readBytes(heldResolver, 1)
  heldResolver.write(b4a.from([OP_RESOLVE]))
  t.is((await heldResolverStatus)[0], STATUS_OK, 'resolver admission remains held before lookup')

  forcedDestinationGuard = reverseOverlapRelay
  t.is(
    await code(() => server.controller._publish(server)),
    'ERR_PRIVACY_UNAVAILABLE',
    'admitted resolver rejects destination admission'
  )
  t.ok(rejectedAdmissionRemoteKey)
  t.is(
    b4a.equals(rejectedAdmissionRemoteKey, server.publicKey),
    false,
    'rejected destination admission authenticates only an ephemeral Noise identity'
  )
  t.is(rejectedIdentitySends, 0, 'rejection sends no destination identity bytes')
  t.is(rejectedIdentityReceives, 0, 'resolver receives no destination identity bytes')
  const heldResolverClosed = new Promise((resolve) => heldResolver.once('close', resolve))
  heldResolver.destroy()
  await Promise.all([heldResolverClosed, heldResolverReleased])
  forcedDestinationGuard = null
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
  t.ok(selectedSourceRoute, 'source route selection is observable to the test oracle')
  const compiledRelays = [
    selectedSourceRoute.firstSafetyRelayPublicKey,
    selectedSourceRoute.secondSafetyRelayPublicKey,
    selectedSourceRoute.entryRelayPublicKey,
    selectedSourceRoute.destinationGuardPublicKey
  ]
  t.is(
    new Set(compiledRelays.map((publicKey) => b4a.toString(publicKey, 'hex'))).size,
    4,
    'standard profile compiles two source-selected and two destination-selected relays'
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
  const third = source.privateRouting.connect(server.publicKey)
  third.on('error', () => {})
  sockets.push(third)
  t.is(await third.opened, true, 'replacement logical stream opens on the surviving circuit')
  t.is(accepted.length, 3)
  const clientLatePayload = b4a.from('late client data crosses server reset')
  holdClientFrame = true
  third.write(clientLatePayload)
  await clientFrameHeld
  const thirdClosed = new Promise((resolve) => third.once('close', resolve))
  accepted[2].destroy()
  await thirdClosed
  releaseClientFrame()
  await clientFrameReceived

  const reverseSurvivorPayload = b4a.from('sibling survives late client data')
  const reverseSurvivorEcho = readBytes(sockets[1], reverseSurvivorPayload.byteLength)
  sockets[1].write(reverseSurvivorPayload)
  t.alike(
    (await reverseSurvivorEcho).subarray(0, reverseSurvivorPayload.byteLength),
    reverseSurvivorPayload,
    'late client data for a server-retired stream cannot retire its sibling'
  )

  let firewallCalls = 0
  let rejectedConnections = 0
  const rejectedServer = destination.privateRouting.createServer(
    {
      firewall(remotePublicKey) {
        firewallCalls++
        t.alike(remotePublicKey, source.defaultKeyPair.publicKey)
        return true
      }
    },
    () => rejectedConnections++
  )
  t.teardown(() => rejectedServer.close())
  await rejectedServer.listen(HyperDHT.keyPair())
  const rejected = source.privateRouting.connect(rejectedServer.publicKey)
  rejected.on('error', () => {})
  const rejectedClosed = new Promise((resolve) => rejected.once('close', resolve))
  t.is(await rejected.opened, true, 'server policy runs against an authenticated private peer')
  await rejectedClosed
  t.is(firewallCalls, 1, 'private server firewall runs once after Noise authentication')
  t.is(rejectedConnections, 0, 'firewalled peers are never emitted to the server')

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
    privacyProfile: 'standard',
    safetyRelays: 2,
    privateRelays: 2,
    descriptorAddressing: 'period-blinded',
    descriptorIdentity: 'rotating-blinded-key',
    descriptorState: 'destination-signed-quorum-readback',
    descriptorOperations: 'source-safety-routed',
    peerPayload: 'bounded-m3-hop-transformed-noise-secretstream',
    directDestinationSends: 0
  })

  for (const socket of sockets) if (!socket.destroyed) socket.end()
})

test('same-key private server restart advances the blinded descriptor sequence', async (t) => {
  const nodes = await network(t)
  const source = nodes[0]
  const destination = nodes[1]
  const serverKeyPair = HyperDHT.keyPair()
  const positivePlugin = {
    query() {
      return 'query-forwarded'
    },
    request() {
      return 'request-forwarded'
    }
  }
  const positiveNode = {
    plugins: new Map([[DESCRIPTOR_PLUGIN_NAME, positivePlugin]])
  }
  const positiveTraffic = trapDescriptorTraffic(t, positiveNode)
  t.alike(
    [
      positivePlugin.query({ command: DESCRIPTOR_COMMAND_GET }),
      positivePlugin.request({ command: DESCRIPTOR_COMMAND_PUT }),
      positiveTraffic
    ],
    ['query-forwarded', 'request-forwarded', { get: 1, put: 1 }],
    'descriptor traffic trap observes GET query and PUT request paths'
  )
  const initialTraffic = trapDescriptorTraffic(t, destination)
  const first = destination.privateRouting.createServer()
  await first.listen(serverKeyPair)
  const firstDescriptor = decodeDescriptor(first._descriptor)
  t.alike(
    initialTraffic,
    { get: 0, put: 0 },
    'initial listen sends no descriptor storage traffic from the destination'
  )
  await first.close()

  const replacement = new HyperDHT({
    bootstrap: [{ host: '127.0.0.1', port: nodes[2].address().port }],
    host: '127.0.0.1',
    port: nextPort++,
    ephemeral: false,
    firewalled: false,
    privateRouting: privateRouting(false)
  })
  t.teardown(() => replacement.destroy({ force: true }))
  await replacement.ready()
  await replacement.privateRouting.ready()
  const replacementTraffic = trapDescriptorTraffic(t, replacement)
  let accepted = false
  const second = replacement.privateRouting.createServer((socket) => {
    socket.on('error', () => {})
    accepted = true
    socket.end()
  })
  t.teardown(() => second.close())
  await second.listen(serverKeyPair)
  const secondDescriptor = decodeDescriptor(second._descriptor)
  t.ok(
    secondDescriptor.seq > firstDescriptor.seq,
    'replacement controller recovers and advances the signed descriptor sequence'
  )
  t.alike(
    replacementTraffic,
    { get: 0, put: 0 },
    'restart sends no descriptor GET or PUT from the destination'
  )

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
