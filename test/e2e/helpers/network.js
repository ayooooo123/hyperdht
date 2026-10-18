'use strict'

const DHT = require('../../..')
const createTestnet = require('../../../testnet')
const { OverlayDescriptorService } = require('../../../lib/private/overlay-descriptor-service')
const { createScope } = require('../support/private-peer')
const observeUDP = require('./udp-oracle')

function privateRouting(relay = false) {
  return { release: 'alpha', acknowledgeAlpha: true, mode: 'optional', profile: 'standard', relay }
}

async function deadline(promise, label, ms = 20000) {
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

async function closePair({ client, remote }) {
  const joins = Promise.all([closed(client), closed(remote)])
  client.destroy()
  remote.destroy()
  await deadline(joins, 'explicit pair cleanup')
}

module.exports = async function network(t, options = {}) {
  t.timeout(120000)
  const oracle = observeUDP()
  const scope = createScope()
  const streams = new Set()
  const servers = new Set()
  const errors = new Map()
  const observers = new Set(options.observer ? [options.observer] : [])
  let net = null
  let joined = false

  function track(stream) {
    if (streams.has(stream)) return stream
    streams.add(stream)
    const seen = []
    errors.set(stream, seen)
    stream.on('error', (error) => seen.push(error))
    return stream
  }

  async function destroy() {
    if (joined) return
    joined = true
    const closing = Array.from(streams, closed)
    for (const stream of streams) stream.destroy()
    await Promise.all(closing)
    for (const server of servers) await server.close()
    if (net) await Promise.all(net.nodes.map((node) => node.destroy({ force: true })))
  }

  t.teardown(async () => {
    try {
      await deadline(destroy(), 'network teardown')
    } finally {
      scope.close()
      oracle.restore()
    }
  })

  net = await createTestnet(options.storage || 8, { bootstrap: [] })
  const storage = net.nodes.slice()
  // Plain bootstrap nodes otherwise ignore descriptor RPCs and force timeouts.
  for (const node of storage)
    new OverlayDescriptorService(node, null, options.clock ? options.clock.now : Date.now)

  function create(relay = false, extra = {}) {
    return scope.create(
      () =>
        net.createNode({
          ephemeral: !relay,
          firewalled: false,
          privateRouting: privateRouting(relay),
          ...extra
        }),
      {
        observer: (event) => {
          for (const observer of observers) observer(event)
        },
        clock: options.clock,
        spliced: options.spliced !== false
      }
    )
  }

  const relays = Array.from({ length: options.relays === undefined ? 6 : options.relays }, () =>
    create(true)
  )
  const destination = create()
  const source = create()
  await deadline(
    Promise.all([...relays, destination, source].map((node) => node.privateRouting.ready())),
    'local private readiness'
  )

  async function listen(
    serverOptions = {},
    node = destination,
    keyPair = DHT.keyPair(),
    direct = false
  ) {
    const server = (direct ? node : node.privateRouting).createServer(serverOptions, track)
    servers.add(server)
    await deadline(server.listen(keyPair), 'listener publication')
    return server
  }

  async function pair(server, connectOptions = {}, node = source, direct = false) {
    let onconnection
    const accepted = new Promise((resolve) => {
      onconnection = resolve
      server.once('connection', onconnection)
    })
    const client = track(
      (direct ? node : node.privateRouting).connect(server.publicKey, connectOptions)
    )
    try {
      if (!(await deadline(client.opened, 'client open'))) {
        throw errors.get(client)[0] || new Error('Private connection did not open')
      }
      const remote = await deadline(accepted, 'server accept')
      if (!(await deadline(remote.opened, 'server open')))
        throw new Error('Server Noise handshake failed')
      return { client, remote }
    } finally {
      server.removeListener('connection', onconnection)
    }
  }

  return {
    net,
    storage,
    relays,
    source,
    destination,
    scope,
    oracle,
    errors,
    streams,
    create,
    listen,
    pair,
    track,
    destroy,
    controller: (node) => scope.controllers.get(node),
    observe(observer) {
      observers.add(observer)
      if (typeof observer === 'function' && observer.toString().includes('route-cell-')) {
        for (const controller of scope.controllers.values()) {
          if (controller) controller.spliced = false
        }
      }
      return () => observers.delete(observer)
    }
  }
}

module.exports.DHT = DHT
module.exports.privateRouting = privateRouting
module.exports.deadline = deadline
module.exports.closed = closed
module.exports.closePair = closePair
