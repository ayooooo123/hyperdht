'use strict'

const test = require('brittle')
const { EventEmitter } = require('events')
const b4a = require('b4a')
const HyperDHT = require('../..')
const { OverlayDescriptorService } = require('../../lib/private/overlay-descriptor-service')
const { createAdvancingClock } = require('./helpers/advancing-clock')

const hex = (bytes) => b4a.toString(bytes, 'hex')

function replies(values) {
  return {
    destroy() {},
    async *[Symbol.asyncIterator]() {
      for (const value of values) yield value
    }
  }
}

test('relay discovery samples independent targets and coalesces cached lookups', async (t) => {
  const honest = Array.from({ length: 6 }, () => HyperDHT.keyPair().publicKey)
  const unrelated = Array.from({ length: 24 }, () => HyperDHT.keyPair().publicKey)
  const targets = []
  let poisonedTarget = null
  const service = new OverlayDescriptorService({
    register(name, plugin) {
      plugin.onregister({})
    },
    lookup(target) {
      const id = hex(target)
      targets.push(id)
      if (poisonedTarget === null) poisonedTarget = id
      return replies([
        { peers: (id === poisonedTarget ? unrelated : honest).map((publicKey) => ({ publicKey })) }
      ])
    }
  })
  t.teardown(() => service.plugin.destroy())
  const [first, second] = await Promise.all([service.discoverRelays(), service.discoverRelays()])
  t.ok(new Set(targets).size > 1, 'one directory position does not determine the candidate set')
  t.is(targets.length, new Set(targets).size, 'simultaneous callers share the same lookup flight')
  const found = new Set(first.map(hex))
  t.ok(
    honest.every((publicKey) => found.has(hex(publicKey))),
    'honest sampled targets survive one poisoned target'
  )
  t.alike(new Set(second.map(hex)), found)
  const queried = targets.length
  await service.discoverRelays()
  t.is(targets.length, queried, 'a fresh cached directory does not cause another lookup')
})

test('relay directory refresh uses its owned advancing timer rather than the next connection', async (t) => {
  t.timeout(10_000)
  const clock = createAdvancingClock({ rate: 1000 })
  const relay = HyperDHT.keyPair().publicKey
  let observedInitial = false
  let resolveRefreshed
  const refreshed = new Promise((resolve) => {
    resolveRefreshed = resolve
  })
  const service = new OverlayDescriptorService(
    {
      register(name, plugin) {
        plugin.onregister({})
      },
      lookup() {
        if (observedInitial) resolveRefreshed()
        return replies([{ peers: [{ publicKey: relay }] }])
      }
    },
    null,
    clock.now,
    clock
  )
  t.teardown(() => service.plugin.destroy())
  await service.discoverRelays()
  observedInitial = true
  let timeout
  const result = await Promise.race([
    refreshed.then(() => true),
    new Promise((resolve) => {
      timeout = setTimeout(() => resolve(false), 1500)
    })
  ])
  clearTimeout(timeout)
  t.is(result, true, 'the existing cache refreshes without another application call')
})

class ObservedConnection extends EventEmitter {
  constructor(remoteHost, remotePort) {
    super()
    this.rawStream = { remoteHost, remotePort }
    this.remoteHost = '198.51.100.10'
    this.remotePort = 9999
    this.opened = Promise.resolve(true)
    this.destroyed = false
  }

  destroy() {
    this.destroyed = true
    this.emit('close')
  }
}

async function controller(t, host) {
  const node = new HyperDHT({
    bootstrap: [],
    host,
    firewalled: false,
    privateRouting: {
      release: 'alpha',
      acknowledgeAlpha: true,
      mode: 'optional',
      profile: 'standard',
      relay: false
    }
  })
  t.teardown(() => node.destroy({ force: true }))
  await node.privateRouting.ready()
  return node.privateRouting.createServer().controller
}

async function dialObserved(controller, host, port = 31001) {
  const connection = new ObservedConnection(host, port)
  const original = controller.connectDirect
  controller.connectDirect = () => connection
  try {
    await controller._connectRelay(HyperDHT.keyPair().publicKey)
    return connection
  } finally {
    controller.connectDirect = original
  }
}

test('non-loopback contexts reject loopback and missing established relay addresses', async (t) => {
  const owner = await controller(t, '0.0.0.0')
  for (const host of [
    '127.0.0.1',
    '127.31.4.2',
    '::1',
    '::ffff:127.0.0.1',
    undefined,
    'relay.example'
  ]) {
    let failure = null
    try {
      const connection = await dialObserved(owner, host)
      connection.destroy()
    } catch (error) {
      failure = error.code
    }
    t.is(failure, 'ERR_PRIVACY_UNAVAILABLE', 'unusable established address fails closed: ' + host)
  }
  let failure = null
  try {
    await dialObserved(owner, '192.0.2.1', 0)
  } catch (error) {
    failure = error.code
  }
  t.is(failure, 'ERR_PRIVACY_UNAVAILABLE', 'an absent established port cannot establish diversity')
})

test('post-dial diversity normalizes IPv4-mapped IPv6 and applies the documented prefix and loopback rules', async (t) => {
  const owner = await controller(t, '127.0.0.1')
  async function key(host, port) {
    const connection = await dialObserved(owner, host, port)
    const value = owner._relayDiversityKey(connection)
    connection.destroy()
    return value
  }
  const v4 = await key('192.0.2.1', 31001)
  t.is(
    await key('192.0.2.250', 31002),
    v4,
    'distinct identities and ports in one /24 are not diverse'
  )
  t.not(await key('192.0.3.1', 31001), v4)
  t.is(await key('::ffff:192.0.2.9', 31001), v4)
  t.is(await key('0:0:0:0:0:ffff:c000:209', 31001), v4)
  const v6 = await key('2001:db8:1234:1::1', 31001)
  t.is(
    await key('2001:0db8:1234:ffff::2', 31002),
    v6,
    'IPv6 addresses share their /48 diversity key'
  )
  t.not(await key('2001:db8:1235::1', 31001), v6)
  const local = await key('127.0.0.1', 31001)
  t.is(await key('::ffff:127.0.0.1', 31001), local)
  t.not(await key('127.0.0.1', 31002), local, 'loopback-bound contexts compare actual ports')
  t.not(await key('127.0.0.2', 31001), local, 'loopback addresses remain part of the comparison')
  t.not(await key('::1', 31001), await key('::1', 31002))
})
