'use strict'

const test = require('brittle')
const b4a = require('b4a')
const HyperDHT = require('../..')
const createTestnet = require('../../testnet')
const { createPrivatePeerTestScope } = require('./helpers/private-peer')
const { createBlindedSigner } = require('../../lib/private/blinded-presence')
const {
  decodeDescriptor,
  descriptorTarget
} = require('../../lib/private/overlay-descriptor-service')

function privateRouting(relay) {
  return { release: 'alpha', acknowledgeAlpha: true, mode: 'optional', profile: 'standard', relay }
}

async function network(t, observer = null) {
  const net = await createTestnet(1, { bootstrap: [] })
  const scope = createPrivatePeerTestScope()
  t.teardown(async () => {
    try {
      await net.destroy()
    } finally {
      scope.close()
    }
  })
  const nodes = [false, false, true, true, true, true, true, true].map((relay) =>
    scope.create(
      () =>
        net.createNode({
          ephemeral: false,
          firewalled: false,
          privateRouting: privateRouting(relay)
        }),
      { observer }
    )
  )
  await Promise.all(nodes.map((node) => node.privateRouting.ready()))
  return nodes
}

function readExactly(stream, size) {
  return new Promise((resolve, reject) => {
    const result = b4a.alloc(size)
    let offset = 0
    function cleanup() {
      stream.removeListener('data', ondata)
      stream.removeListener('error', onerror)
      stream.removeListener('end', onend)
    }
    function onerror(error) {
      cleanup()
      reject(error)
    }
    function onend() {
      onerror(new Error('Stream ended before the expected payload'))
    }
    function ondata(data) {
      if (offset + data.byteLength > size) return onerror(new Error('Unexpected trailing bytes'))
      result.set(data, offset)
      offset += data.byteLength
      if (offset !== size) return
      cleanup()
      resolve(result)
    }
    stream.on('data', ondata)
    stream.once('error', onerror)
    stream.once('end', onend)
  })
}

function uint64(bytes, offset) {
  return (BigInt(bytes.readUInt32BE(offset)) << 32n) | BigInt(bytes.readUInt32BE(offset + 4))
}

test('private application identities and route headers do not reuse direct identity or clock origins', async (t) => {
  t.timeout(90_000)
  const firstCells = new Map()
  const [source, destination] = await network(t, (event) => {
    if (event.type !== 'route-cell-sealed') return
    const id = b4a.toString(event.cell.subarray(12, 28), 'hex') + ':' + event.direction
    if (!firstCells.has(id)) firstCells.set(id, b4a.from(event.cell))
  })
  const accepted = []
  const server = destination.privateRouting.createServer((stream) => {
    stream.on('error', () => {})
    accepted.push(stream)
    stream.pipe(stream)
  })
  t.teardown(() => server.close())
  const beforePublish = Date.now()
  await server.listen(HyperDHT.keyPair())
  const firstDescriptor = decodeDescriptor(server._descriptor)
  t.ok(
    firstDescriptor.seq >= BigInt(beforePublish),
    'the public record revision is not a per-service publication count'
  )
  const explicit = HyperDHT.keyPair()
  const clients = []
  t.teardown(() => {
    for (const stream of clients) stream.destroy()
  })
  for (let i = 0; i < 3; i++) {
    const stream = source.privateRouting.connect(
      server.publicKey,
      i === 2 ? { keyPair: explicit } : {}
    )
    clients.push(stream)
    stream.on('error', () => {})
    t.is(await stream.opened, true)
    const payload = b4a.alloc(128 + i, 0x31 + i)
    const received = readExactly(stream, payload.byteLength)
    stream.write(payload)
    t.alike(await received, payload)
  }
  t.is(accepted.length, 3)
  t.is(b4a.equals(accepted[0].remotePublicKey, source.defaultKeyPair.publicKey), false)
  t.is(b4a.equals(accepted[1].remotePublicKey, source.defaultKeyPair.publicKey), false)
  t.is(b4a.equals(accepted[0].remotePublicKey, accepted[1].remotePublicKey), false)
  t.alike(
    accepted[2].remotePublicKey,
    explicit.publicKey,
    'explicit peer authentication is retained'
  )

  const epochs = new Set()
  const origins = new Set()
  const now = BigInt(Date.now())
  for (const cell of firstCells.values()) {
    const epoch = uint64(cell, 4)
    const origin = uint64(cell, 28)
    epochs.add(epoch.toString())
    origins.add(origin.toString())
    t.ok(epoch >> 16n < BigInt(beforePublish - 60_000) || epoch >> 16n > now + 60_000n)
    t.not(origin, 0n, 'each direction starts at a key-derived counter origin')
  }
  t.ok(epochs.size >= 5, 'separate route contexts do not share an epoch')
  t.is(origins.size, firstCells.size, 'different directed links do not share a counter origin')

  for (const stream of clients) stream.destroy()
  await server.controller._publish(server)
  const replacement = decodeDescriptor(server._descriptor)
  t.ok(
    replacement.seq > firstDescriptor.seq,
    'refresh remains monotone within one descriptor target'
  )
})

test('private listeners require an explicit application identity', async (t) => {
  const node = new HyperDHT({
    bootstrap: [],
    host: '127.0.0.1',
    privateRouting: privateRouting(false)
  })
  t.teardown(() => node.destroy({ force: true }))
  const server = node.privateRouting.createServer()
  t.teardown(() => server.close())
  let error = null
  try {
    await server.listen()
  } catch (cause) {
    error = cause.code
  }
  t.is(error, 'INVALID_ROUTE', 'omitted identity is rejected before relay discovery')
})

test('only safety relay two resolves the locally blinded destination target', async (t) => {
  t.timeout(90_000)
  const reads = []
  let selected = null
  const [source, destination] = await network(t, (event) => {
    if (event.type === 'source-route-selected') selected = event
    if (event.type === 'control-read' && event.role === 'relay') reads.push(event)
  })
  const server = destination.privateRouting.createServer((stream) => {
    stream.on('error', () => {})
    stream.pipe(stream)
  })
  t.teardown(() => server.close())
  await server.listen(HyperDHT.keyPair())
  const client = source.privateRouting.connect(server.publicKey)
  client.on('error', () => {})
  t.teardown(() => client.destroy())
  t.is(await client.opened, true)
  const payload = b4a.from('blinded resolution through the second safety relay')
  const received = readExactly(client, payload.byteLength)
  client.write(payload)
  t.alike(await received, payload)
  t.ok(selected)
  if (selected === null) return
  const descriptor = decodeDescriptor(server._descriptor)
  const target = descriptorTarget(server.publicKey, descriptor.period)
  const firstReads = reads.filter((row) =>
    b4a.equals(row.relayPublicKey, selected.firstSafetyRelayPublicKey)
  )
  const secondReads = reads.filter((row) =>
    b4a.equals(row.relayPublicKey, selected.secondSafetyRelayPublicKey)
  )
  t.is(
    firstReads.some((row) => row.bytes.includes(server.publicKey)),
    false,
    'the source-adjacent relay never resolves the stable destination key'
  )
  t.ok(
    secondReads.some(
      (row) =>
        row.label === 'source-resolve' &&
        uint64(row.bytes, 1) === descriptor.period &&
        b4a.equals(row.bytes.subarray(9), target)
    ),
    'the second safety relay queries the locally blinded target'
  )
})

test('destination guard admission uses a blinded signer and rejects replayed proofs', async (t) => {
  t.timeout(90_000)
  const guardReads = []
  const controls = []
  const [source, destination] = await network(t, (event) => {
    if (event.opcode !== 3) return
    if (event.type === 'control-write' && event.role === 'endpoint') controls.push(event.bytes)
    if (event.type === 'control-read' && event.role === 'relay') guardReads.push(event)
  })
  const server = destination.privateRouting.createServer((stream) => {
    stream.on('error', () => {})
    stream.pipe(stream)
  })
  t.teardown(() => server.close())
  await server.listen(HyperDHT.keyPair())
  const descriptor = decodeDescriptor(server._descriptor)
  t.is(
    controls.some((bytes) => bytes.includes(server.publicKey)),
    false,
    'the stable service key is absent from destination control writes'
  )
  t.is(
    guardReads.some(
      (row) =>
        b4a.equals(row.relayPublicKey, descriptor.destinationGuardPublicKey) &&
        row.bytes.includes(server.publicKey)
    ),
    false,
    'the guard receives the blinded admission rather than the stable service identity'
  )
  const client = source.privateRouting.connect(server.publicKey)
  client.on('error', () => {})
  t.teardown(() => client.destroy())
  t.is(await client.opened, true)
  const payload = b4a.from('blinded admission preserves end-to-end authentication')
  const echoed = readExactly(client, payload.byteLength)
  client.write(payload)
  t.alike(await echoed, payload)

  const replay = source.connect(descriptor.destinationGuardPublicKey, {
    keyPair: HyperDHT.keyPair()
  })
  replay.on('error', () => {})
  t.teardown(() => replay.destroy())
  t.is(await replay.opened, true)
  const challenge = readExactly(replay, 33)
  replay.write(controls[0])
  t.is((await challenge)[0], 0)
  const rejected = readExactly(replay, 1)
  replay.write(controls[1])
  t.is(
    (await rejected)[0],
    1,
    'a captured admission proof cannot authorize a new transport and challenge'
  )

  const transport = HyperDHT.keyPair()
  const other = source.connect(descriptor.destinationGuardPublicKey, { keyPair: transport })
  other.on('error', () => {})
  t.is(await other.opened, true)
  t.teardown(() => other.destroy())
  const otherChallenge = readExactly(other, 33)
  other.write(controls[0])
  const challengeBytes = await otherChallenge
  t.is(challengeBytes[0], 0)
  const signer = createBlindedSigner(HyperDHT.keyPair(), descriptor.period)
  const identity = b4a.alloc(40)
  identity.writeBigUInt64BE(descriptor.period)
  signer.publicKey.copy(identity, 8)
  const input = b4a.concat([
    b4a.from('hyperdht/private-peer/destination-admission/v4'),
    challengeBytes.subarray(1),
    transport.publicKey,
    descriptor.destinationGuardPublicKey,
    identity
  ])
  let signature
  try {
    signature = signer.sign(input)
  } finally {
    signer.destroy()
    input.fill(0)
  }
  const recovery = readExactly(other, 2)
  other.write(b4a.concat([identity, signature]))
  signature.fill(0)
  t.alike(
    await recovery,
    b4a.from([0, 0]),
    'a different valid blinded signer can authenticate only itself'
  )
  const wrongDescriptor = readExactly(other, 1)
  other.write(descriptor.wire)
  t.is(
    (await wrongDescriptor)[0],
    1,
    "blinded admission cannot register another signer's valid descriptor"
  )
})
