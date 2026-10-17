'use strict'

const test = require('brittle')
const b4a = require('b4a')
const createTestnet = require('../../testnet')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { hashPeer } = require('../../lib/private/peer-crypto')
const { TOPOLOGY_ROLE } = require('../../lib/private/protocol')
const { createPrivateNativeController } = require('../../lib/private/private-native-controller')
const { endpoint, grant, sourceOptions } = require('./helpers/native-config')
const { createPeerNativeRuntime } = require('../../lib/private/peer-native-runtime')
const {
  createPeerNativeRuntimeConfig,
  peerNativeProfile,
  peerNativePurposeLimits,
  peerNativeBuildLimits
} = require('../../lib/private/peer-native-config')
const { createPeerPurposeSource } = require('../../lib/private/peer-purpose-owner')
const { createPeerSemanticServices } = require('../../lib/private/peer-semantic-services')

function deferred() {
  let resolve
  let reject
  const promise = new Promise((yes, no) => {
    resolve = yes
    reject = no
  })
  promise.catch(() => {})
  return { promise, resolve, reject }
}

function closed(stream) {
  if (stream.destroyed) return Promise.resolve()
  return new Promise((resolve) => stream.once('close', resolve))
}

function received(stream, length) {
  return new Promise((resolve, reject) => {
    const buffers = []
    let bytes = 0
    const cleanup = () => {
      stream.off('data', ondata)
      stream.off('error', onerror)
      stream.off('close', onclose)
    }
    const onerror = (error) => {
      cleanup()
      reject(error)
    }
    const onclose = () => onerror(new Error('Stream closed before the expected bytes arrived'))
    const ondata = (buffer) => {
      buffers.push(b4a.from(buffer))
      bytes += buffer.length
      if (bytes !== length) {
        if (bytes > length) onerror(new Error('Received more bytes than expected'))
        return
      }
      cleanup()
      resolve(b4a.concat(buffers))
    }
    stream.on('data', ondata)
    stream.once('error', onerror)
    stream.once('close', onclose)
  })
}

async function exchange(left, right, text) {
  const value = b4a.from(text)
  const pending = received(right, value.length)
  left.write(value)
  return pending
}

async function topology(t) {
  // Three mask-9 relays all have a granted safety and terminal successor. Every
  // ordinary-directory guard choice can form a distinct three-hop native route.
  const network = await createTestnet(10, { host: '127.0.0.1' })
  const controllers = []
  t.teardown(async () => {
    for (let index = controllers.length - 1; index >= 0; index--) await controllers[index].destroy()
    await network.destroy()
  })
  const relays = network.nodes.slice(1, 5).map((dht) => ({
    ...endpoint(dht.address().port, TOPOLOGY_ROLE.SAFETY_GUARD),
    dht,
    grants: []
  }))
  function edge(left, right) {
    const wire = grant(
      { ...left, role: TOPOLOGY_ROLE.SAFETY_GUARD },
      { ...right, role: TOPOLOGY_ROLE.SAFETY_FINAL }
    )
    left.grants.push(wire)
    right.grants.push(wire)
  }
  edge(relays[0], relays[1])
  edge(relays[1], relays[2])
  edge(relays[2], relays[0])
  for (const relay of relays.slice(0, 3)) edge(relay, relays[3])
  for (const relay of relays) {
    const controller = createPrivateNativeController({
      dht: relay.dht,
      baseReady: () => relay.dht.fullyBootstrapped(),
      config: {
        ...sourceOptions(),
        relay: true,
        relayConfig: {
          identityKeyPair: relay.identity,
          authorityPublicKeys: [relay.authority.publicKey],
          epoch: 7n,
          runId32: b4a.alloc(32, 0x52),
          grants: relay.grants
        }
      }
    })
    controllers.push(controller)
  }
  await Promise.all(controllers.map((controller) => controller.ready()))

  async function source() {
    const dht = network.createNode()
    const controller = createPrivateNativeController({
      dht,
      baseReady: () => dht.fullyBootstrapped(),
      config: sourceOptions()
    })
    controllers.push(controller)
    await controller.ready()
    return { dht, controller }
  }

  return { network, relays, controllers, source }
}

async function connected(client, server, publicKey, options) {
  const incoming = deferred()
  server.once('connection', incoming.resolve)
  const stream = client.connect(publicKey, options)
  stream.on('error', () => {})
  if (!(await stream.opened)) throw new Error('Native private connection did not authenticate')
  const remote = await incoming.promise
  remote.on('error', () => {})
  return { stream, remote }
}

test('native controller publishes real guard tuples and authenticates guarded early writes', async (t) => {
  t.timeout(120_000)
  const fixture = await topology(t)
  const topic = hashPeer('hyperdht-private-routes/native/guard-locators/v1', [])
  const query = fixture.network.nodes[0].lookup(topic)
  const found = new Set()
  for await (const reply of query) {
    for (const peer of reply.peers) {
      for (const address of peer.relayAddresses) found.add(address.host + ':' + address.port)
    }
  }
  for (const relay of fixture.relays.slice(0, 3))
    t.ok(
      found.has('127.0.0.1:' + relay.port),
      'the topic returns the announced guard tuple, not a storage tuple'
    )
  t.absent(
    found.has('127.0.0.1:' + fixture.relays[3].port),
    'terminal-only relay does not advertise as a guard'
  )

  const destination = await fixture.source()
  const source = await fixture.source()
  const listenerKey = cryptoSuite.keyPair()
  const applicationKey = cryptoSuite.keyPair()
  const originalSecret = b4a.from(listenerKey.secretKey)
  const incoming = deferred()
  const server = destination.controller.createServer({}, incoming.resolve)
  await server.listen(listenerKey)
  t.alike(server.address(), { publicKey: listenerKey.publicKey, host: null, port: 0 })
  const stream = source.controller.connect(listenerKey.publicKey, { keyPair: applicationKey })
  stream.on('error', () => {})
  const first = b4a.from('queued before route readiness')
  stream.write(first)
  t.ok(await stream.opened, 'the immediate guarded facade authenticates')
  const remote = await incoming.promise
  remote.on('error', () => {})
  t.alike(
    await received(remote, first.length),
    first,
    'early write crosses the real native and Noise path'
  )
  t.alike(stream.remotePublicKey, listenerKey.publicKey)
  t.alike(remote.remotePublicKey, applicationKey.publicKey)
  t.alike(stream.publicKey, applicationKey.publicKey)
  t.is(stream.isInitiator, true)
  t.is(remote.isInitiator, false)

  const eof = new Promise((resolve) => remote.once('end', resolve))
  stream.end()
  remote.resume()
  await eof
  t.alike(
    await exchange(remote, stream, 'reply after half-close'),
    b4a.from('reply after half-close')
  )
  const closures = Promise.all([closed(stream), closed(remote)])
  remote.end()
  stream.resume()
  await closures
  await server.close()
  t.alike(
    listenerKey.secretKey,
    originalSecret,
    'controller teardown does not erase caller-owned keys'
  )
  t.ok(
    source.dht.io.serverSocket.bound,
    'private teardown leaves ordinary DHT socket ownership intact'
  )
  t.ok(await source.dht.ping(fixture.network.bootstrap[0]), 'ordinary DHT traffic still works')
})

test('native reader policy separates cached presence and firewall denies authenticated identities', async (t) => {
  t.timeout(180_000)
  const fixture = await topology(t)
  const destination = await fixture.source()
  const source = await fixture.source()
  const identity = cryptoSuite.keyPair()
  const allowed = cryptoSuite.keyPair()
  const denied = cryptoSuite.keyPair()
  const readerSecret = cryptoSuite.randomBytes(32)
  const observed = []
  let emitted = 0
  let rejectFirewall = false
  const server = destination.controller.createServer(
    {
      readerSecret,
      async firewall(publicKey) {
        observed.push(b4a.from(publicKey))
        if (rejectFirewall) throw new Error('Policy refused the peer')
        return !b4a.equals(publicKey, allowed.publicKey)
      }
    },
    () => emitted++
  )
  await server.listen(identity)
  const pair = await connected(source.controller, server, identity.publicKey, {
    readerSecret,
    keyPair: allowed
  })
  t.alike(observed[0], allowed.publicKey, 'policy receives authenticated end-to-end identity')
  const endings = Promise.all([closed(pair.stream), closed(pair.remote)])
  pair.stream.destroy()
  await endings

  const wrongReader = source.controller.connect(identity.publicKey, { keyPair: allowed })
  wrongReader.on('error', () => {})
  t.is(
    await wrongReader.opened,
    false,
    'a public-reader lookup cannot reuse the capability-reader cache'
  )
  await closed(wrongReader)
  t.is(emitted, 1)

  const refused = source.controller.connect(identity.publicKey, { readerSecret, keyPair: denied })
  refused.on('error', () => {})
  await closed(refused)
  t.alike(observed[1], denied.publicKey)
  t.is(emitted, 1, 'a refused authenticated stream is not emitted')
  rejectFirewall = true
  const rejected = source.controller.connect(identity.publicKey, { readerSecret, keyPair: allowed })
  rejected.on('error', () => {})
  await closed(rejected)
  t.is(emitted, 1, 'a rejected firewall promise denies instead of accepting')
  await server.close()
})

test('native registration replacement preserves an admitted stream and publishes a new route', async (t) => {
  t.timeout(180_000)
  const fixture = await topology(t)
  const destination = await fixture.source()
  const firstClient = await fixture.source()
  const secondClient = await fixture.source()
  const identity = cryptoSuite.keyPair()
  const server = destination.controller.createServer()
  await server.listen(identity)
  const first = await connected(firstClient.controller, server, identity.publicKey)
  const oldIdentity = b4a.from(first.stream.publicKey)
  await server.refresh()
  t.is(
    destination.controller.snapshot().circuits,
    2,
    'the old admitted registration overlaps the published replacement'
  )
  t.alike(
    await exchange(first.stream, first.remote, 'old registration remains live'),
    b4a.from('old registration remains live')
  )
  const second = await connected(secondClient.controller, server, identity.publicKey)
  t.absent(
    b4a.equals(second.stream.publicKey, oldIdentity),
    'default application identities are fresh per connect'
  )
  t.absent(
    b4a.equals(second.stream.publicKey, secondClient.dht.defaultKeyPair.publicKey),
    'default application identity is not the DHT identity'
  )
  t.alike(
    await exchange(second.remote, second.stream, 'replacement registration'),
    b4a.from('replacement registration')
  )
  const firstClosed = Promise.all([closed(first.stream), closed(first.remote)])
  first.stream.destroy()
  await firstClosed
  t.alike(
    await exchange(second.stream, second.remote, 'sibling survives retirement'),
    b4a.from('sibling survives retirement')
  )
  const secondClosed = Promise.all([closed(second.stream), closed(second.remote)])
  await server.close()
  await secondClosed
  const freshClient = await fixture.source()
  const absent = freshClient.controller.connect(identity.publicKey)
  absent.on('error', () => {})
  t.is(
    await absent.opened,
    false,
    'close withdraws discovery through authenticated native presence'
  )
})

test('native controller joins stream cancellation and socket suspend before republishing on resume', async (t) => {
  t.timeout(180_000)
  const fixture = await topology(t)
  const destination = await fixture.source()
  const source = await fixture.source()
  const identity = cryptoSuite.keyPair()
  const server = destination.controller.createServer()
  await server.listen(identity)
  const pair = await connected(source.controller, server, identity.publicKey)
  const closures = Promise.all([closed(pair.stream), closed(pair.remote)])
  await destination.controller.suspend()
  await closures
  t.is(destination.controller.snapshot().state, 'suspended')
  t.is(destination.controller.snapshot().occupiedSlots, 0)
  t.is(destination.controller.snapshot().circuits, 0)
  t.ok(
    destination.dht.io.serverSocket.bound,
    'private suspension joins before base socket suspension'
  )
  await destination.dht.suspend()
  await destination.dht.resume()
  await destination.controller.resume()
  t.ok(server.listening)
  const nextSource = await fixture.source()
  const next = await connected(nextSource.controller, server, identity.publicKey)
  t.alike(
    await exchange(next.stream, next.remote, 'new socket generation'),
    b4a.from('new socket generation')
  )
  const closing = Promise.all([closed(next.stream), closed(next.remote)])
  await destination.controller.destroy()
  await closing
  t.is(destination.controller.snapshot().state, 'destroyed')
  t.ok(
    destination.dht.io.serverSocket.bound,
    'controller destroy does not close the resumed DHT socket'
  )
})

test('native resume recovers after a transient readiness failure', async (t) => {
  t.timeout(180_000)
  const fixture = await topology(t)
  const destination = await fixture.source()
  const identity = cryptoSuite.keyPair()
  const server = destination.controller.createServer()
  await server.listen(identity)
  const dht = fixture.network.createNode()
  const interrupted = new Error('Bootstrap readiness was interrupted')
  let rejectReadiness = false
  const source = createPrivateNativeController({
    dht,
    config: sourceOptions(),
    baseReady: async () => {
      await dht.fullyBootstrapped()
      if (rejectReadiness) throw interrupted
    }
  })
  fixture.controllers.push(source)
  await source.ready()
  await source.suspend()
  rejectReadiness = true
  let failure = null
  try {
    await source.resume()
  } catch (error) {
    failure = error
  }
  t.is(failure, interrupted)
  t.is(source.snapshot().state, 'suspended', 'failed resume remains retryable')
  t.is(source.snapshot().occupiedSlots, 0)
  rejectReadiness = false
  await source.resume()
  const pair = await connected(source, server, identity.publicKey)
  t.alike(
    await exchange(pair.stream, pair.remote, 'after failed resume'),
    b4a.from('after failed resume')
  )
  const closures = Promise.all([closed(pair.stream), closed(pair.remote)])
  pair.stream.destroy()
  await closures
  await source.destroy()
  t.ok(await dht.ping(fixture.network.bootstrap[0]), 'ordinary DHT survives recovered teardown')
})

test('native pending cancellation cannot construct a late private route after base readiness', async (t) => {
  t.timeout(60_000)
  const network = await createTestnet(4, { host: '127.0.0.1' })
  const base = deferred()
  const dht = network.createNode()
  await dht.fullyBootstrapped()
  const controller = createPrivateNativeController({
    dht,
    config: sourceOptions(),
    baseReady: async () => {
      await dht.fullyBootstrapped()
      await base.promise
    }
  })
  t.teardown(async () => {
    base.resolve()
    await controller.destroy()
    await network.destroy()
  })
  const stream = controller.connect(cryptoSuite.keyPair().publicKey)
  stream.on('error', () => {})
  stream.write(b4a.from('must not survive cancellation'))
  const closure = closed(stream)
  stream.destroy()
  await closure
  t.is(await stream.opened, false)
  const destroying = controller.destroy()
  base.resolve()
  await destroying
  t.is(controller.snapshot().circuits, 0, 'late base readiness cannot install a circuit')
  t.is(controller.snapshot().occupiedSlots, 0)
  t.ok(dht.io.serverSocket.bound)
})

test('native public options reject accessors and mismatched keypairs without private startup', async (t) => {
  const network = await createTestnet(4, { host: '127.0.0.1' })
  const dht = network.createNode()
  const controller = createPrivateNativeController({
    dht,
    config: sourceOptions(),
    baseReady: () => dht.fullyBootstrapped()
  })
  t.teardown(async () => {
    await controller.destroy()
    await network.destroy()
  })
  const key = cryptoSuite.keyPair()
  let accessorCalls = 0
  t.exception(
    () =>
      controller.connect(key.publicKey, {
        get readerSecret() {
          accessorCalls++
          return cryptoSuite.randomBytes(32)
        }
      }),
    /invalid/i
  )
  t.exception(() => controller.createServer({ clock: Date.now }), /invalid/i)
  t.exception(
    () =>
      controller.connect(key.publicKey, {
        keyPair: { publicKey: key.publicKey, secretKey: cryptoSuite.keyPair().secretKey }
      }),
    /invalid/i
  )
  for (const value of [new Uint16Array(16), new Uint32Array(8), new Float64Array(4)]) {
    for (const invoke of [
      () => controller.connect(value),
      () => controller.connect(key.publicKey, { readerSecret: value }),
      () => controller.createServer({ readerSecret: value })
    ]) {
      let code = null
      try {
        invoke()
      } catch (error) {
        code = error.code
      }
      t.is(code, 'INVALID_ROUTE', 'cryptographic inputs reject non-byte typed arrays')
    }
  }
  const server = controller.createServer()
  await t.exception(server.listen(), /invalid/i)
  t.is(accessorCalls, 0, 'option validation never invokes caller accessors')
  t.is(controller.snapshot().state, 'idle', 'invalid inputs never initiate native startup')
  await server.close()
})

test('native pre-admission queue is bounded and canceled writes release their admission', async (t) => {
  t.timeout(60_000)
  const network = await createTestnet(4, { host: '127.0.0.1' })
  const dht = network.createNode()
  await dht.fullyBootstrapped()
  const base = deferred()
  const controller = createPrivateNativeController({
    dht,
    config: sourceOptions(),
    baseReady: async () => {
      await base.promise
    }
  })
  t.teardown(async () => {
    base.resolve()
    await controller.destroy()
    await network.destroy()
  })
  const destination = cryptoSuite.keyPair().publicKey
  const streams = []
  const capacity = controller.snapshot().sourceSlots + 16
  for (let index = 0; index < capacity; index++) {
    const stream = controller.connect(destination)
    stream.on('error', () => {})
    stream.write(b4a.from('bounded pre-admission write'))
    streams.push(stream)
  }
  t.exception(
    () => controller.connect(destination),
    /unavailable/i,
    'the pending bound rejects before another facade is retained'
  )
  const closures = streams.map(closed)
  for (const stream of streams) stream.destroy()
  await Promise.all(closures)
  const stopping = controller.destroy()
  base.resolve()
  await stopping
  t.is(controller.snapshot().occupiedSlots, 0)
  t.is(controller.snapshot().circuits, 0)
  t.ok(dht.io.serverSocket.bound)
})

test('native terminal refuses authenticated routes below the fixed reviewed profile', async (t) => {
  t.timeout(180_000)
  const fixture = await topology(t)
  const profile = peerNativeProfile()
  const source = profile.source
  for (const change of ['receive window', 'forward work']) {
    const dht = fixture.network.createNode()
    await dht.fullyBootstrapped()
    const runtime = createPeerNativeRuntime({
      dht,
      config: createPeerNativeRuntimeConfig(
        sourceOptions(),
        dht,
        fixture.relays.slice(0, 3).map((relay) => ({ host: relay.host, port: relay.port }))
      )
    })
    fixture.controllers.push(runtime)
    const transport = peerNativeBuildLimits(source, profile.limits.idleTimeoutMs)
    const lease = await runtime.buildTail({
      ...transport,
      payloadParametersDigest: cryptoSuite.randomBytes(32),
      terminal: null
    })
    const material = lease.consume()
    const ephemeral = cryptoSuite.encryptionKeyPair()
    const limits = peerNativePurposeLimits(source, material.parentWireExpiresAt)
    if (change === 'receive window') {
      limits.receiveFrames = 1
      limits.receiveBytes = 977
    } else {
      limits.forwardCells--
      limits.forwardBytes -= 1200n
    }
    const failure = deferred()
    const services = createPeerSemanticServices({
      maxStreams: source.maxStreams,
      maxFrames: profile.sourceDataFrames
    })
    const owner = createPeerPurposeSource({
      ...material,
      purpose: 2,
      routeId: cryptoSuite.randomBytes(16),
      queryNonce: cryptoSuite.randomBytes(32),
      clientEphemeralPublicKey: ephemeral.publicKey,
      clientEphemeralSecret: ephemeral.secretKey,
      terminalRoutePublicKey: material.purposeTerminalPublicKey,
      randomBytes: cryptoSuite.randomBytes,
      limits,
      streamCallbacks: {
        ...services.streamCallbacks,
        onFailure(error) {
          services.streamCallbacks.onFailure(error)
          failure.resolve(error)
        }
      }
    })
    const cleanup = {
      async destroy() {
        services.destroy()
        owner.destroy()
        await Promise.all([lease.revoke(), owner.whenClosed()])
        for (const value of Object.values(material)) if (b4a.isBuffer(value)) value.fill(0)
        for (const value of Object.values(material.finalizeKeys)) value.fill(0)
        ephemeral.publicKey.fill(0)
        ephemeral.secretKey.fill(0)
      }
    }
    fixture.controllers.push(cleanup)
    services.attachOwner(owner).catch(failure.resolve)
    owner.start()
    await failure.promise
    t.exception(
      () => owner.route(),
      /destroyed/i,
      change + ' cannot acquire native application authority'
    )
    t.is(
      fixture.controllers[3].snapshot().circuits,
      0,
      'the terminal releases the ineligible route'
    )
    t.ok(
      runtime.diagnostics().guardPinned,
      'profile refusal does not demote or replace the healthy guard'
    )
    await cleanup.destroy()
    await runtime.destroy()
  }
})

test('native listener refresh and application admission share the source circuit ceiling', async (t) => {
  t.timeout(180_000)
  const fixture = await topology(t)
  const source = await fixture.source()
  const destination = await fixture.source()
  const localServer = source.controller.createServer()
  const remoteServer = destination.controller.createServer()
  const destinationKey = cryptoSuite.keyPair()
  await localServer.listen(cryptoSuite.keyPair())
  await remoteServer.listen(destinationKey)
  const first = await connected(source.controller, remoteServer, destinationKey.publicKey)
  const remotes = [first.remote]
  remoteServer.on('connection', (stream) => {
    stream.on('error', () => {})
    remotes.push(stream)
  })
  const capacity = source.controller.snapshot().sourceSlots
  const pending = []
  for (let index = 1; index < capacity; index++) {
    const stream = source.controller.connect(destinationKey.publicKey)
    stream.on('error', () => {})
    pending.push(stream)
  }
  await new Promise((resolve) => setImmediate(resolve))
  t.ok(
    source.controller.snapshot().pendingConnections > 0,
    'a live listener prevents treating every source slot as an application slot'
  )
  await localServer.refresh()
  t.ok(
    source.controller.snapshot().occupiedSlots <= capacity,
    'replacement registration and publication stay inside the same ceiling'
  )
  t.alike(
    await exchange(first.stream, first.remote, 'application survives local listener refresh'),
    b4a.from('application survives local listener refresh')
  )
  await localServer.close()
  t.alike(
    await Promise.all(pending.map((stream) => stream.opened)),
    Array(capacity - 1).fill(true),
    'pending applications can use the slots after listener management releases them'
  )
  t.is(source.controller.snapshot().servers, 0)
  t.is(source.controller.snapshot().occupiedSlots, capacity)
  t.alike(
    await exchange(first.remote, first.stream, 'reverse traffic survives shared-pool admission'),
    b4a.from('reverse traffic survives shared-pool admission')
  )
  const streams = [first.stream, ...pending, ...remotes]
  const closures = Promise.all(streams.map(closed))
  for (const stream of streams) stream.destroy()
  await closures
  await remoteServer.close()
})
