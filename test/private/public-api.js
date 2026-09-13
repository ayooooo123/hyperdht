'use strict'

const test = require('brittle')
const b4a = require('b4a')

const HyperDHT = require('../..')
const directConnect = require('../../lib/connect')
const {
  decodeDescriptor,
  encodeDescriptor
} = require('../../lib/private/overlay-descriptor-service')

let nextPort = 49300

function privateRouting() {
  return { release: 'alpha', acknowledgeAlpha: true, mode: 'required' }
}

async function network(t, count = 5) {
  const boot = new HyperDHT({
    bootstrap: [],
    host: '127.0.0.1',
    port: nextPort++,
    ephemeral: false,
    firewalled: false
  })
  await boot.ready()
  const bootstrap = [{ host: '127.0.0.1', port: boot.address().port }]
  const nodes = Array.from(
    { length: count },
    () =>
      new HyperDHT({
        bootstrap,
        host: '127.0.0.1',
        port: nextPort++,
        ephemeral: false,
        firewalled: false,
        privateRouting: privateRouting()
      })
  )
  t.teardown(async () => {
    await Promise.allSettled(nodes.reverse().map((node) => node.destroy({ force: true })))
    await boot.destroy({ force: true })
  })
  await Promise.all(nodes.map((node) => node.ready()))
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

function relayStatus(stream) {
  return new Promise((resolve) => {
    let settled = false
    function finish(status) {
      if (settled) return
      settled = true
      stream.removeListener('data', ondata)
      stream.removeListener('error', onunavailable)
      stream.removeListener('close', onunavailable)
      resolve(status)
    }
    function ondata(chunk) {
      finish(chunk[0])
    }
    function onunavailable() {
      finish(1)
    }
    stream.once('data', ondata)
    stream.once('error', onunavailable)
    stream.once('close', onunavailable)
  })
}

function code(operation) {
  try {
    const result = operation()
    if (result && typeof result.then === 'function')
      return result.then(
        () => null,
        (error) => error.code
      )
    return Promise.resolve(null)
  } catch (error) {
    return Promise.resolve(error.code)
  }
}

test('private routing opts select overlay-native peer routing without bootstrap endpoints', async (t) => {
  const valid = privateRouting()
  const invalid = [
    undefined,
    null,
    false,
    {},
    { ...valid, release: 'beta' },
    { ...valid, acknowledgeAlpha: false },
    { ...valid, mode: 'optional' },
    { ...valid, bootstrapEndpoints: [{ host: '127.0.0.1', port: 49737 }] },
    { ...valid, host: '127.0.0.1' },
    { ...valid, port: 49737 }
  ]
  for (const value of invalid) {
    t.is(await code(() => new HyperDHT({ privateRouting: value })), 'INVALID_ROUTE')
  }

  const dht = new HyperDHT({
    bootstrap: [],
    host: '127.0.0.1',
    port: nextPort++,
    ephemeral: false,
    firewalled: false,
    privateRouting: valid
  })
  t.teardown(() => dht.destroy({ force: true }))
  t.is(dht.outboundPolicy, 'direct', 'node remains an ordinary HyperDHT participant')
  t.ok(dht.udx, 'normal HyperDHT bootstrap and routing-table discovery remain active')
  t.is(dht.privateRouting.release, 'alpha')
  t.is(dht.privateRouting.mode, 'required')
  await dht.destroy({ force: true })
  t.is(dht.privateRouting.status(), 'DESTROYED')
})

test('private connect compiles safety and destination routes around fixed cells', async (t) => {
  const nodes = await network(t)
  const source = nodes[0]
  const destination = nodes[1]
  const serverKeyPair = HyperDHT.keyPair()
  const payload = b4a.alloc(64 * 1024, 0x5a)
  let accepted = null
  const server = destination.createServer((socket) => {
    socket.on('error', () => {})
    accepted = socket
    socket.on('data', (data) => socket.write(data))
  })
  t.teardown(() => server.close())
  await server.listen(serverKeyPair)

  let destinationDiscovered = false
  for await (const result of source.findPeer(server.publicKey)) {
    destinationDiscovered = true
    t.absent(result, 'destination application key has no public peer record')
  }
  t.is(destinationDiscovered, false, 'destination endpoint is not publicly discoverable')
  const directDestination = directConnect(source, server.publicKey, {
    keyPair: HyperDHT.keyPair()
  })
  directDestination.on('error', () => {})
  t.is(
    await directDestination.opened,
    false,
    'destination application key cannot be dialed directly'
  )

  const descriptor = decodeDescriptor(server._descriptor)
  const forgedRouteEntry = HyperDHT.keyPair().publicKey
  const forgedAttachmentDescriptor = encodeDescriptor({
    destinationKeyPair: serverKeyPair,
    routeEntry: forgedRouteEntry,
    entryRelayPublicKey: descriptor.entryRelayPublicKey,
    seq: descriptor.seq + 1n,
    expiresAt: descriptor.expiresAt
  })
  const wrongAttachment = directConnect(source, descriptor.entryRelayPublicKey, {
    keyPair: HyperDHT.keyPair()
  })
  wrongAttachment.on('error', () => {})
  t.is(await wrongAttachment.opened, true, 'descriptor holder can reach the entry relay')
  const attachRequest = b4a.allocUnsafe(1 + forgedAttachmentDescriptor.byteLength)
  attachRequest[0] = 4
  forgedAttachmentDescriptor.copy(attachRequest, 1)
  const attachStatus = relayStatus(wrongAttachment)
  wrongAttachment.write(attachRequest)
  t.is(await attachStatus, 1, 'unused route entry is rejected under the wrong outer Noise key')
  let routeEntryDiscovered = false
  for await (const result of source.findPeer(descriptor.routeEntry)) {
    routeEntryDiscovered = true
    t.absent(result, 'opaque route entry has no public peer record')
  }
  t.is(routeEntryDiscovered, false, 'descriptor route entry is not publicly discoverable')
  const direct = directConnect(source, descriptor.routeEntry, {
    keyPair: HyperDHT.keyPair()
  })
  direct.on('error', () => {})
  t.is(await direct.opened, false, 'descriptor holder cannot dial the destination attachment')
  t.is(accepted, null, 'direct route-entry dial never reaches the destination server')

  const socket = source.connect(server.publicKey)
  socket.on('error', () => {})
  t.is(await socket.opened, true, 'end-to-end Noise and secret-stream authenticate')
  t.alike(socket.remotePublicKey, serverKeyPair.publicKey)
  const echoed = readBytes(socket, payload.byteLength)
  socket.write(payload)
  t.alike(
    (await echoed).subarray(0, payload.byteLength),
    payload,
    'payload crosses fixed route cells'
  )
  t.ok(accepted, 'destination accepts the private stream')
  t.alike(accepted.remotePublicKey, source.defaultKeyPair.publicKey)
  t.alike(source.privateRouting.exposureReport(), {
    overlayParticipation: 'direct',
    relayDiscovery: 'hyperdht-routing-table',
    descriptorOperations: 'safety-routed',
    peerPayload: 'noise-secretstream-end-to-end',
    directDestinationSends: 0
  })
  socket.end()
})

test('same-key private server restart advances the published route immediately', async (t) => {
  const nodes = await network(t)
  const source = nodes[0]
  const destination = nodes[1]
  const serverKeyPair = HyperDHT.keyPair()
  const first = destination.createServer()
  await first.listen(serverKeyPair)
  const firstDescriptor = decodeDescriptor(first._descriptor)
  await first.close()

  let accepted = false
  const second = destination.createServer((socket) => {
    socket.on('error', () => {})
    accepted = true
    socket.end()
  })
  t.teardown(() => second.close())
  await second.listen(serverKeyPair)
  const secondDescriptor = decodeDescriptor(second._descriptor)
  t.ok(secondDescriptor.seq > firstDescriptor.seq, 'replacement descriptor wins sequence ordering')

  const socket = source.connect(serverKeyPair.publicKey)
  socket.on('error', () => {})
  t.is(await socket.opened, true, 'clients resolve the replacement attachment')
  t.alike(socket.remotePublicKey, serverKeyPair.publicKey)
  t.is(accepted, true, 'recreated server accepts the private stream')
  socket.end()
})

test('private connect fails closed without a published destination route', async (t) => {
  const nodes = await network(t, 4)
  const source = nodes[0]
  const socket = source.connect(HyperDHT.keyPair().publicKey)
  socket.on('error', () => {})
  t.is(await socket.opened, false)
  t.is(source.privateRouting.exposureReport().directDestinationSends, 0)
})
