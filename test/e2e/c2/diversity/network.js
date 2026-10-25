'use strict'

const b4a = require('b4a')
const DHT = require('../../../..')
const createTestnet = require('../../../../testnet')
const { OverlayDescriptorService } = require('../../../../lib/private/overlay-descriptor-service')
const { createScope } = require('../../support/private-peer')
const { exchange } = require('../../helpers/traffic')
const { prefix } = require('./topology')

async function deadline(promise, label, ms = 45000) {
  let timer
  try {
    return await Promise.race([
      promise,
      new Promise((resolve, reject) => {
        timer = setTimeout(() => reject(new Error(label + ' exceeded ' + ms + ' ms')), ms)
      })
    ])
  } finally {
    clearTimeout(timer)
  }
}

function closed(stream) {
  return stream.destroyed
    ? Promise.resolve()
    : new Promise((resolve) => stream.once('close', resolve))
}

function hex(value) {
  return b4a.toString(value, 'hex')
}

function tuple(t, stream) {
  const raw = stream.rawStream
  t.ok(stream.connected && raw, 'an established Noise stream must expose its raw stream')
  prefix(raw.remoteHost)
  t.ok(Number.isInteger(raw.remotePort) && raw.remotePort > 0 && raw.remotePort <= 65535)
  return { host: raw.remoteHost, port: raw.remotePort }
}

// This harness never creates the C1 UDP oracle: that oracle intentionally rejects
// non-loopback traffic. Only its deadline/join pattern and shared byte protocol
// are reused. Direct readiness traffic is separate from private tuple evidence.
module.exports = async function createNetwork(t, hosts) {
  const net = await createTestnet(0)
  const scope = createScope()
  const streams = new Set()
  const servers = new Set()
  const errors = new Map()
  const names = new Map()
  const restores = []
  const observations = []
  const observationErrors = []
  const selections = []
  const storage = []
  const relays = []
  let source
  let destination
  let stopping = false
  let privateAccepts = 0

  function patch(object, name, replacement) {
    const descriptor = Object.getOwnPropertyDescriptor(object, name)
    object[name] = replacement
    restores.push(() => {
      if (descriptor) Object.defineProperty(object, name, descriptor)
      else delete object[name]
    })
  }

  function track(stream) {
    if (streams.has(stream)) return stream
    streams.add(stream)
    errors.set(stream, [])
    stream.on('error', (error) => errors.get(stream).push(error))
    // A timeout may race an outstanding dial. Do not let late arrivals escape teardown.
    if (stopping) stream.destroy()
    return stream
  }

  function controller(node) {
    const result = scope.controllers.get(node)
    t.ok(result, 'scoped controller capture is required')
    return result
  }

  function create(host, name, relay) {
    if (stopping) throw new Error('cannot create a node during teardown')
    const node = scope.create(
      () =>
        net.createNode({
          host,
          port: [0, 0],
          ephemeral: !relay,
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
        observer(event) {
          if (event.type !== 'source-route-selected') return
          try {
            selections.push({
              node: name,
              first: hex(event.firstSafetyRelayPublicKey),
              second: hex(event.secondSafetyRelayPublicKey),
              entry: hex(event.entryRelayPublicKey),
              guard: hex(event.destinationGuardPublicKey)
            })
          } catch (error) {
            observationErrors.push(error)
          }
          // No observer return chooses a candidate or delays forwarding/commit.
        }
      }
    )
    names.set(node, name)
    const owner = controller(node)
    const connect = owner._connectRelay
    t.is(typeof connect, 'function', 'C6 must retain the observable relay-dial seam')
    patch(owner, '_connectRelay', async function (...args) {
      const stream = await connect.apply(this, args)
      track(stream)
      try {
        observations.push({
          from: name,
          requested: hex(args[0]),
          authenticated: hex(stream.remotePublicKey),
          remote: tuple(t, stream),
          stream
        })
      } catch (error) {
        // Observation cannot veto a production dial; assert the evidence afterward.
        observationErrors.push(error)
      }
      return stream
    })
    return node
  }

  function assertBound(node, host) {
    const address = node.address()
    t.ok(address, 'node has a bound UDP socket')
    t.is(address.host, host, 'node is bound to its actual assigned non-loopback address')
    prefix(address.host)
    t.ok(address.port > 0 && address.port <= 65535)
    return { host: address.host, port: address.port }
  }

  async function start() {
    for (let i = 0; i < hosts.storage.length; i++) {
      if (stopping) throw new Error('cannot bootstrap a node during teardown')
      const node = net.createNode({
        host: hosts.storage[i],
        port: [0, 0],
        ephemeral: false,
        firewalled: false
      })
      storage.push(node)
      names.set(node, 'storage-' + i)
      // Install on every plain storage node, including the nonpersistent first
      // root. Otherwise descriptor RPCs can silently stall on bootstrap peers.
      new OverlayDescriptorService(node)
      await deadline(node.fullyBootstrapped(), 'storage bootstrap')
      const address = assertBound(node, hosts.storage[i])
      if (i === 0) net.bootstrap.push(address)
    }
    for (let i = 0; i < hosts.relays.length; i++) {
      relays.push(create(hosts.relays[i], 'relay-' + i, true))
    }
    source = create(hosts.source, 'source', false)
    destination = create(hosts.destination, 'destination', false)
    await deadline(
      Promise.all([...relays, source, destination].map((node) => node.privateRouting.ready())),
      'private readiness and relay announcements'
    )
    for (let i = 0; i < relays.length; i++) assertBound(relays[i], hosts.relays[i])
    assertBound(source, hosts.source)
    assertBound(destination, hosts.destination)
    t.is(new Set(relays.map((node) => hex(controller(node).relayKeyPair.publicKey))).size, 8)
  }

  function server(node, direct = false) {
    if (stopping) throw new Error('cannot create a listener during teardown')
    const listener = (direct ? node : node.privateRouting).createServer({}, (stream) => {
      if (!direct) privateAccepts++
      track(stream)
    })
    servers.add(listener)
    return listener
  }

  async function listen(node = destination, direct = false, keyPair = DHT.keyPair()) {
    const listener = server(node, direct)
    // Explicit service identity, never the missing-key shorthand.
    await deadline(listener.listen(keyPair), direct ? 'direct listen' : 'private publication')
    return listener
  }

  async function pair(listener, direct = false) {
    let accept
    const accepted = new Promise((resolve) => {
      accept = resolve
    })
    listener.once('connection', accept)
    const client = track((direct ? source : source.privateRouting).connect(listener.publicKey))
    try {
      if (!(await deadline(client.opened, 'client open'))) {
        throw errors.get(client)[0] || new Error('client closed without opening')
      }
      const remote = await deadline(accepted, 'listener accept')
      t.ok(await deadline(remote.opened, 'accepted Noise handshake'))
      return { client, remote }
    } finally {
      listener.removeListener('connection', accept)
    }
  }

  async function closePair(pair) {
    const joins = Promise.all([closed(pair.client), closed(pair.remote)])
    pair.client.destroy()
    pair.remote.destroy()
    await deadline(joins, 'pair cleanup')
  }

  async function liveness() {
    const live = []
    // These are ordinary direct authenticated connections to the real relay
    // service keys, not _connectRelay observations and not private route success.
    for (const relay of relays) {
      const publicKey = controller(relay).relayKeyPair.publicKey
      const stream = track(source.connect(publicKey))
      try {
        t.ok(await deadline(stream.opened, 'direct relay identity liveness'))
        t.is(hex(stream.remotePublicKey), hex(publicKey))
        const remote = tuple(t, stream)
        t.is(remote.host, relay.address().host)
        live.push({ publicKey: hex(publicKey), remote, prefix: prefix(remote.host) })
      } finally {
        const joined = closed(stream)
        stream.destroy()
        await deadline(joined, 'direct relay probe cleanup')
      }
    }
    const listener = await listen(destination, true)
    const connected = await pair(listener, true)
    let bytes
    try {
      bytes = await exchange(connected.client, connected.remote, { id: 'ordinary-direct-liveness' })
    } finally {
      await closePair(connected)
      await listener.close()
    }
    t.is(privateAccepts, 0, 'ordinary liveness never counted as a private accept')
    return { relayHandshakes: live, directPayload: bytes }
  }

  function assertPath(after) {
    t.alike(observationErrors, [], 'tuple and selection observers produced usable evidence')
    const selected = selections
      .slice(after)
      .filter((row) => row.node === 'source')
      .at(-1)
    t.ok(selected, 'successful application stream has a source-route-selected event')
    const keys = [selected.first, selected.second, selected.entry, selected.guard]
    t.is(new Set(keys).size, 4, 'all four relay identities differ')
    const relayByKey = new Map(
      relays.map((node) => [hex(controller(node).relayKeyPair.publicKey), node])
    )
    function established(from, publicKey) {
      const relay = relayByKey.get(publicKey)
      t.ok(relay, 'selected key belongs to a real fixture relay')
      const candidates = observations.filter(
        (row) =>
          row.from === from &&
          row.requested === publicKey &&
          !row.stream.destroyed &&
          !row.stream.destroying
      )
      t.ok(candidates.length, 'live established adjacency ' + from + ' -> ' + publicKey)
      const row = candidates.at(-1)
      t.is(row.authenticated, publicKey, 'Noise authenticates the selected relay identity')
      const current = tuple(t, row.stream)
      t.alike(current, row.remote, 'established tuple has not changed during the transfer')
      t.is(current.host, relay.address().host, 'remote tuple is a real bound fixture host')
      return { from, publicKey, remote: current, prefix: prefix(current.host) }
    }
    const first = established('source', selected.first)
    const second = established(names.get(relayByKey.get(selected.first)), selected.second)
    const entry = established(names.get(relayByKey.get(selected.second)), selected.entry)
    const guard = established('destination', selected.guard)
    const guardEntry = established(names.get(relayByKey.get(selected.guard)), selected.entry)
    t.is(guardEntry.prefix, entry.prefix, 'both actual entry adjacencies agree on its prefix')
    const path = [first, second, entry, guard]
    t.is(
      new Set(path.map((row) => row.prefix)).size,
      4,
      'C6: first safety, second safety, entry and destination guard need distinct established /24s'
    )
    return { path, guardEntry }
  }

  async function destroy() {
    stopping = true
    const failures = []
    async function join(work, label) {
      try {
        await deadline(work, label)
      } catch (error) {
        failures.push(error)
      }
    }
    try {
      const joins = Array.from(streams, closed)
      for (const stream of streams) stream.destroy()
      await join(Promise.all(joins), 'stream teardown')
      const closing = Array.from(servers, (listener) => listener.close())
      // Force-destroy cancels pending bootstrap, publication and dial operations.
      const destroying = net.nodes.map((node) => node.destroy({ force: true }))
      const outcomes = await deadline(
        Promise.allSettled([...closing, ...destroying]),
        'node teardown'
      )
      for (const outcome of outcomes)
        if (outcome.status === 'rejected') failures.push(outcome.reason)
    } catch (error) {
      failures.push(error)
    } finally {
      for (const restore of restores.reverse()) restore()
      scope.close()
    }
    if (failures.length)
      throw new AggregateError(failures, 'Linux diversity network cleanup failed')
  }

  return {
    net,
    storage,
    relays,
    names,
    scope,
    observations,
    selections,
    observationErrors,
    errors,
    start,
    controller,
    patch,
    track,
    listen,
    pair,
    closePair,
    liveness,
    assertPath,
    destroy,
    get source() {
      return source
    },
    get destination() {
      return destination
    },
    get privateAccepts() {
      return privateAccepts
    }
  }
}

module.exports.deadline = deadline
module.exports.hex = hex
module.exports.exchange = exchange
