'use strict'

const test = require('brittle')
const b4a = require('b4a')

const HyperDHT = require('../..')

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

test('private connect fails closed without a published destination route', async (t) => {
  const nodes = await network(t, 4)
  const source = nodes[0]
  const socket = source.connect(HyperDHT.keyPair().publicKey)
  socket.on('error', () => {})
  t.is(await socket.opened, false)
  t.is(source.privateRouting.exposureReport().directDestinationSends, 0)
})
