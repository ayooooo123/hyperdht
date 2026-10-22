'use strict'

const test = require('brittle')
const b4a = require('b4a')
const createTestnet = require('../../../testnet')
const HyperDHT = require('../../..')
const { cryptoSuite } = require('../../../lib/private/crypto-suite')
const { LINK_OPERATION, TOPOLOGY_ROLE } = require('../../../lib/private/protocol')
const { createPeerNativeRuntime } = require('../../../lib/private/peer-native-runtime')
const {
  createPeerNativeRuntimeConfig,
  peerNativeProfile,
  peerNativeBuildLimits
} = require('../../../lib/private/peer-native-config')
const { endpoint, grant, sourceOptions } = require('../../private/helpers/native-config')
const { analyze } = require('./capture/analyzer')

function deferred() {
  let resolve
  let reject
  const promise = new Promise((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

function closed(stream) {
  if (stream.destroyed) return Promise.resolve()
  return new Promise((resolve) => stream.once('close', resolve))
}

function receiveExact(stream, expectedBytes) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let received = 0
    function onData(chunk) {
      chunks.push(b4a.from(chunk))
      received += chunk.byteLength
      if (received >= expectedBytes) {
        cleanup()
        resolve(b4a.concat(chunks))
      }
    }
    function onEnd() {
      cleanup()
      resolve(b4a.concat(chunks))
    }
    function onError(err) {
      cleanup()
      reject(err)
    }
    function cleanup() {
      stream.removeListener('data', onData)
      stream.removeListener('end', onEnd)
      stream.removeListener('error', onError)
    }
    stream.on('data', onData)
    stream.once('end', onEnd)
    stream.once('error', onError)
  })
}

function writeBuffer(stream, payload, chunkSize = 65536) {
  return new Promise((resolve, reject) => {
    let offset = 0
    function onError(err) {
      cleanup()
      reject(err)
    }
    function cleanup() {
      stream.removeListener('drain', pump)
      stream.removeListener('error', onError)
    }
    function pump() {
      while (offset < payload.byteLength) {
        const end = Math.min(offset + chunkSize, payload.byteLength)
        const slice = payload.subarray(offset, end)
        offset = end
        const ok = stream.write(slice)
        if (!ok && offset < payload.byteLength) {
          stream.once('drain', pump)
          return
        }
      }
      cleanup()
      resolve()
    }
    stream.once('error', onError)
    pump()
  })
}

async function nativeTopology(t, { legacyEgress = false } = {}) {
  const network = await createTestnet(10, { host: '127.0.0.1' })
  const nodes = []
  t.teardown(async () => {
    for (let i = nodes.length - 1; i >= 0; i--) {
      await nodes[i].destroy().catch(() => {})
    }
    await network.destroy()
  })

  const bootstrap = [
    `${network.nodes[0].host}:${network.nodes[0].port}`,
    `${network.nodes[1].host}:${network.nodes[1].port}`
  ]

  const relayPorts = []
  for (let i = 0; i < 4; i++) {
    const probe = new HyperDHT({ host: '127.0.0.1', bootstrap })
    await probe.ready()
    relayPorts.push(probe.address().port)
    await probe.destroy()
  }

  const relays = relayPorts.map((port) => ({
    ...endpoint(port, TOPOLOGY_ROLE.SAFETY_GUARD),
    grants: []
  }))

  function addEdge(left, right) {
    const wire = grant(
      { ...left, role: TOPOLOGY_ROLE.SAFETY_GUARD },
      { ...right, role: TOPOLOGY_ROLE.SAFETY_FINAL }
    )
    left.grants.push(wire)
    right.grants.push(wire)
  }

  addEdge(relays[0], relays[1])
  addEdge(relays[1], relays[2])
  addEdge(relays[2], relays[0])
  for (const relay of relays.slice(0, 3)) addEdge(relay, relays[3])

  const relayNodes = []
  for (let i = 0; i < relays.length; i++) {
    const relay = relays[i]
    const dht = new HyperDHT({
      host: '127.0.0.1',
      port: relay.port,
      bootstrap,
      ephemeral: false,
      firewalled: false,
      privateRouting: {
        ...sourceOptions(),
        relay: true,
        relayConfig: {
          identityKeyPair: relay.identity,
          authorityPublicKeys: [relay.authority.publicKey],
          epoch: 7n,
          runId32: b4a.alloc(32, 0x52),
          grants: relay.grants,
          ...(i === 3 && legacyEgress ? { legacyEgress: true } : {})
        }
      }
    })
    nodes.push(dht)
    relayNodes.push(dht)
    await dht.ready()
  }
  await Promise.all(relayNodes.map((dht) => dht.privateRouting.ready()))

  async function createSource() {
    const dht = new HyperDHT({
      host: '127.0.0.1',
      bootstrap,
      ephemeral: false,
      firewalled: false,
      privateRouting: sourceOptions()
    })
    nodes.push(dht)
    await dht.ready()
    await dht.privateRouting.ready()
    return dht
  }

  return { network, bootstrap, relays, relayNodes, createSource }
}

test('C2 native: one private stream transfers 16 MiB in each direction byte-exact', async (t) => {
  t.timeout(180_000)
  const fixture = await nativeTopology(t)
  const clientNode = await fixture.createSource()
  const serverNode = await fixture.createSource()

  const serverKey = cryptoSuite.keyPair()
  const size = 16 * 1024 * 1024
  const forwardPayload = b4a.alloc(size)
  const reversePayload = b4a.alloc(size)
  for (let i = 0; i < size; i += 4096) {
    forwardPayload[i] = (i >>> 12) & 0xff
    reversePayload[i] = ((i >>> 12) ^ 0xa5) & 0xff
  }

  const serverDone = deferred()
  serverDone.promise.catch(() => {})
  const server = serverNode.privateRouting.createServer((socket) => {
    socket.on('error', () => {})
    Promise.all([receiveExact(socket, size), writeBuffer(socket, reversePayload)])
      .then(([received]) => {
        socket.end()
        serverDone.resolve(received)
      })
      .catch((err) => serverDone.reject(err))
  })
  await server.listen(serverKey)

  const client = clientNode.privateRouting.connect(serverKey.publicKey)
  client.on('error', () => {})
  t.is(await client.opened, true, 'native private stream opens for 16 MiB duplex transfer')

  const [clientReceived, serverReceived] = await Promise.all([
    receiveExact(client, size),
    serverDone.promise,
    writeBuffer(client, forwardPayload).then(() => client.end())
  ])

  t.is(serverReceived.byteLength, size, 'server receives full 16 MiB forward transfer')
  t.is(clientReceived.byteLength, size, 'client receives full 16 MiB reverse transfer')
  t.is(b4a.equals(serverReceived, forwardPayload), true, 'forward 16 MiB bytes are exact')
  t.is(b4a.equals(clientReceived, reversePayload), true, 'reverse 16 MiB bytes are exact')

  await Promise.all([closed(client), server.close()])
})

test('C2 native: 16 concurrent streams from four sources and make-before-break refresh', async (t) => {
  t.timeout(240_000)
  const fixture = await nativeTopology(t)
  const serverNode = await fixture.createSource()
  const sources = []
  for (let i = 0; i < 4; i++) sources.push(await fixture.createSource())

  const serverKey = cryptoSuite.keyPair()
  const accepted = []
  const server = serverNode.privateRouting.createServer((socket) => {
    socket.on('error', () => {})
    accepted.push(socket)
    socket.on('data', (chunk) => socket.write(chunk))
  })
  await server.listen(serverKey)

  const clients = []
  for (let s = 0; s < 4; s++) {
    for (let c = 0; c < 4; c++) {
      const index = s * 4 + c
      const stream = sources[s].privateRouting.connect(serverKey.publicKey)
      stream.on('error', () => {})
      clients.push({ index, stream })
    }
  }

  const openedAll = await Promise.all(clients.map((item) => item.stream.opened))
  t.alike(openedAll, Array(16).fill(true), 'all 16 concurrent streams across 4 sources open')

  const echoes = await Promise.all(
    clients.map(async ({ index, stream }) => {
      const msg = b4a.from(`stream-${index}`)
      const reading = receiveExact(stream, msg.byteLength)
      stream.write(msg)
      return b4a.equals(await reading, msg)
    })
  )
  t.alike(echoes, Array(16).fill(true), 'all 16 concurrent streams echo exact bytes')

  // Keep stream 0 alive across the registration exhaustion make-before-break refresh.
  const survivor = clients[0].stream
  await Promise.all(
    clients.slice(1).map(({ stream }) => {
      const done = closed(stream)
      stream.destroy()
      return done
    })
  )
  await server.refresh().catch(() => {})
  const freshNode = await fixture.createSource()
  const freshClient = freshNode.privateRouting.connect(serverKey.publicKey)
  freshClient.on('error', () => {})
  t.is(
    await freshClient.opened,
    true,
    '17th application connection succeeds after make-before-break registration refresh'
  )
  const refreshMsg = b4a.from('post-refresh-client')
  const readingFresh = receiveExact(freshClient, refreshMsg.byteLength)
  freshClient.write(refreshMsg)
  t.alike(await readingFresh, refreshMsg, 'new client communicates on refreshed registration')

  const survivorMsg = b4a.from('survivor-still-live')
  const readingSurvivor = receiveExact(survivor, survivorMsg.byteLength)
  survivor.write(survivorMsg)
  t.alike(await readingSurvivor, survivorMsg, 'admitted stream on prior registration survives')

  survivor.destroy()
  freshClient.destroy()
  await Promise.all([closed(survivor), closed(freshClient)])
  for (const sock of accepted) sock.destroy()
  await server.close()
})

test('C2 native: live send-owner capture reconciles every UDP datagram with zero violations', async (t) => {
  t.timeout(120_000)
  const network = await createTestnet(5, { host: '127.0.0.1' })
  const runtimes = []
  t.teardown(async () => {
    for (let i = runtimes.length - 1; i >= 0; i--) {
      await runtimes[i].destroy().catch(() => {})
    }
    await network.destroy()
  })

  const relays = network.nodes.slice(1, 4).map((dht) => ({
    ...endpoint(dht.port, TOPOLOGY_ROLE.SAFETY_GUARD),
    dht,
    grants: []
  }))
  for (let i = 0; i < 2; i++) {
    const wire = grant(
      { ...relays[i], role: TOPOLOGY_ROLE.SAFETY_GUARD, operations: LINK_OPERATION.INITIATE },
      { ...relays[i + 1], role: TOPOLOGY_ROLE.SAFETY_FINAL, operations: LINK_OPERATION.ACCEPT }
    )
    relays[i].grants.push(wire)
    relays[i + 1].grants.push(wire)
  }

  let clockMicros = 100
  const nextAt = () => {
    clockMicros += 10
    return clockMicros
  }

  const input = {
    version: 2,
    maxCaptureDelayMicros: 1000,
    leases: [],
    links: [],
    allowances: [],
    events: [],
    captures: [],
    captureLosses: []
  }

  function attachCapture(nodeId, dht, runtime) {
    const local = { host: '127.0.0.1', port: dht.port }
    const scope = { node: nodeId, runtime: 'rt-' + nodeId, lease: 'lease-1' }
    input.leases.push({
      ...scope,
      socketGeneration: 1,
      local,
      start: 0,
      end: 1_000_000_000
    })

    const socket = dht.io.serverSocket
    const origSend = socket.send.bind(socket)
    let packetSeq = 0
    let currentAttemptAt = 0
    let expectPrivateSend = false
    socket.send = function (buffer, port, host, ...rest) {
      const payload = b4a.from(buffer)
      if (expectPrivateSend) {
        expectPrivateSend = false
        input.captures.push({
          ...scope,
          id: `${nodeId}-pkt-${++packetSeq}`,
          tap: 'egress',
          at: currentAttemptAt + 1,
          local,
          remote: { host: host || '127.0.0.1', port },
          payload: b4a.toString(payload, 'hex'),
          duplicateOf: null
        })
      }
      return origSend(buffer, port, host, ...rest)
    }
    t.teardown(() => {
      socket.send = origSend
    })

    runtime.observeSendAttempts((event) => {
      if (event.kind === 'attempt') {
        const at = nextAt()
        currentAttemptAt = at
        expectPrivateSend = true
        const charged = event.owner.charged
        input.events.push({ ...scope, at, event })
        input.links.push({
          ...scope,
          local: { ...event.local },
          remote: { ...event.remote },
          start: at - 1,
          end: at + 3,
          class: event.owner.class,
          requiresCharge: charged
        })
      } else {
        expectPrivateSend = false
        input.events.push({ ...scope, at: currentAttemptAt + 2, event })
      }
    })
  }

  for (let i = 0; i < relays.length; i++) {
    const relay = relays[i]
    const config = createPeerNativeRuntimeConfig(
      {
        ...sourceOptions(),
        relay: true,
        relayConfig: {
          identityKeyPair: relay.identity,
          authorityPublicKeys: [relay.authority.publicKey],
          epoch: 7n,
          runId32: b4a.alloc(32, 0x52),
          grants: relay.grants
        }
      },
      relay.dht
    )
    const rt = createPeerNativeRuntime({ dht: relay.dht, config })
    attachCapture(`relay-${i}`, relay.dht, rt)
    runtimes.push(rt)
  }

  const incomingWait = deferred()
  runtimes[2].onIncomingFinal((lease) => incomingWait.resolve(lease))
  await Promise.all(runtimes.map((rt) => rt.ready()))

  const srcDht = network.nodes[0]
  const srcRt = createPeerNativeRuntime({
    dht: srcDht,
    config: createPeerNativeRuntimeConfig(sourceOptions(), srcDht, [
      { host: '127.0.0.1', port: relays[0].port }
    ])
  })
  attachCapture('source', srcDht, srcRt)
  runtimes.push(srcRt)
  await srcRt.ready()

  const profiles = peerNativeProfile()
  const digest = cryptoSuite.randomBytes(32)
  digest[0] |= 1
  const lease = await srcRt.buildTail({
    ...peerNativeBuildLimits(profiles.source, profiles.limits.idleTimeoutMs),
    payloadParametersDigest: digest,
    terminal: null
  })
  const terminalLease = await incomingWait.promise
  await Promise.all([lease.revoke(), terminalLease.revoke()])

  const report = analyze(input)
  t.alike(report.differences, [], 'live native send-owner reconciliation has zero differences')
  t.is(report.completeCapture, true, 'every live private send event matched a captured UDP packet')
  t.is(report.completeCompletions, true, 'every live attempt recorded its completion event')
  t.is(report.completeLinkClassification, true, 'every live attempt classified its link')
  t.ok(report.totals.circuit.observed > 0, 'circuit category traffic recorded')
  t.ok(report.totals.service.observed > 0, 'neighbor service category traffic recorded')
  t.ok(report.totals.bootstrap.observed > 0, 'guard bootstrap category traffic recorded')
  t.is(
    report.totals.circuit.observed +
      report.totals.service.observed +
      report.totals.bootstrap.observed +
      report.totals.traversal.observed +
      report.totals['v1-routed'].observed,
    report.totals.sum.observed,
    'category subtotals equal sum'
  )
})

test('C2 native: explicit legacy egress to unchanged server and opt-out refusal', async (t) => {
  t.timeout(120_000)
  const optOutFixture = await nativeTopology(t, { legacyEgress: false })
  const optOutSource = await optOutFixture.createSource()

  const probeDht = new HyperDHT({ host: '127.0.0.1', bootstrap: optOutFixture.bootstrap })
  await probeDht.ready()
  await probeDht.fullyBootstrapped()
  const profiles = peerNativeProfile()
  const probeRt = createPeerNativeRuntime({
    dht: probeDht,
    config: createPeerNativeRuntimeConfig(
      sourceOptions(),
      probeDht,
      optOutFixture.relays.slice(0, 3).map((r) => ({ host: r.host, port: r.port }))
    )
  })
  const digest = cryptoSuite.randomBytes(32)
  digest[0] |= 1
  const lease = await probeRt.buildTail({
    ...peerNativeBuildLimits(profiles.source, profiles.limits.idleTimeoutMs),
    payloadParametersDigest: digest,
    terminal: null
  })
  const optOutAd = b4a.from(lease.consume().terminalAdvertisement260)
  await lease.revoke()
  await probeRt.destroy()
  await probeDht.destroy()

  const directNode = new HyperDHT({ host: '127.0.0.1', bootstrap: optOutFixture.bootstrap })
  t.teardown(() => directNode.destroy())
  await directNode.ready()
  await directNode.fullyBootstrapped()
  const directKey = cryptoSuite.keyPair()
  let directAccepts = 0
  const incoming = deferred()
  const directServer = directNode.createServer((socket) => {
    directAccepts++
    socket.on('error', () => {})
    incoming.resolve(socket)
  })
  await directServer.listen(directKey)

  const refused = optOutSource.privateRouting.connect(directKey.publicKey, {
    legacy: true,
    terminal: { advertisement260: optOutAd }
  })
  refused.on('error', () => {})
  t.is(await refused.opened, false, 'opt-out terminal refuses legacy egress before remote contact')
  await closed(refused)
  t.is(directAccepts, 0, 'unchanged server never sees connection from opt-out terminal')

  const fixture = await nativeTopology(t, { legacyEgress: true })
  const source = await fixture.createSource()
  const probeDht2 = new HyperDHT({ host: '127.0.0.1', bootstrap: fixture.bootstrap })
  await probeDht2.ready()
  await probeDht2.fullyBootstrapped()
  const probeRt2 = createPeerNativeRuntime({
    dht: probeDht2,
    config: createPeerNativeRuntimeConfig(
      sourceOptions(),
      probeDht2,
      fixture.relays.slice(0, 3).map((r) => ({ host: r.host, port: r.port }))
    )
  })
  const lease2 = await probeRt2.buildTail({
    ...peerNativeBuildLimits(profiles.source, profiles.limits.idleTimeoutMs),
    payloadParametersDigest: digest,
    terminal: null
  })
  const optedAd = b4a.from(lease2.consume().terminalAdvertisement260)
  await lease2.revoke()
  await probeRt2.destroy()
  await probeDht2.destroy()

  const directNode2 = new HyperDHT({ host: '127.0.0.1', bootstrap: fixture.bootstrap })
  t.teardown(() => directNode2.destroy())
  await directNode2.ready()
  await directNode2.fullyBootstrapped()
  const incoming2 = deferred()
  const directServer2 = directNode2.createServer((socket) => {
    socket.on('error', () => {})
    incoming2.resolve(socket)
    socket.on('data', (chunk) => socket.write(chunk))
  })
  await directServer2.listen(directKey)

  const client = source.privateRouting.connect(directKey.publicKey, {
    legacy: true,
    terminal: { advertisement260: optedAd }
  })
  client.on('error', () => {})
  t.is(await client.opened, true, 'opted-in terminal opens explicit legacy egress to direct server')
  const remote = await incoming2.promise
  const largeRecord = b4a.alloc(70_000, 0x5a)
  const readingLarge = receiveExact(client, largeRecord.byteLength)
  client.write(largeRecord)
  t.alike(await readingLarge, largeRecord, 'legacy egress preserves >64 KiB atomic records')

  client.destroy()
  remote.destroy()
  await Promise.all([closed(client), closed(remote)])
  await directServer.close()
  await directServer2.close()
})
