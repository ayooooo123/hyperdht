const test = require('brittle')
const { EventEmitter } = require('events')
const b4a = require('b4a')
const DHT = require('dht-rpc')
const HyperDHT = require('../..')

test('transport-only preserves one opaque context without direct authority', async (t) => {
  const context = Object.freeze({ route: 'private-test-route' })
  const destination = Object.freeze({ ref: 'private-test-destination' })
  const id = b4a.alloc(32, 1)
  const calls = {
    closest: [],
    bootstrap: [],
    request: [],
    destroy: 0
  }
  let udxFactoryCalls = 0

  const requestTransport = {
    ready() {
      return Promise.resolve()
    },
    suspend() {
      return Promise.resolve()
    },
    resume() {
      return Promise.resolve()
    },
    destroy() {
      calls.destroy++
      return Promise.resolve()
    },
    bootstrap(opts) {
      calls.bootstrap.push(opts)
      return Promise.resolve([destination])
    },
    closest(opts) {
      calls.closest.push(opts)
      return [destination]
    },
    key(to) {
      return to.ref
    },
    id() {
      return id
    },
    request(message) {
      calls.request.push(message)
      return {
        promise: Promise.resolve({
          rtt: 1,
          from: destination,
          to: null,
          token: null,
          closerNodes: null,
          error: 0,
          value: null
        }),
        cancel() {}
      }
    }
  }

  const dht = new DHT({
    outboundPolicy: 'transport-only',
    requestTransport,
    udxFactory() {
      udxFactoryCalls++
      throw new Error('transport-only constructed direct UDX authority')
    }
  })
  t.teardown(() => dht.destroy())

  t.is(dht.outboundPolicy, 'transport-only')
  t.is(dht.udx, null)
  t.is(dht.table, null)
  t.is(udxFactoryCalls, 0)

  const query = dht.query(
    { target: b4a.alloc(32), command: 7, value: null },
    { concurrency: 1, transportContext: context }
  )
  await query.finished()

  t.is(calls.closest.length, 1)
  t.is(calls.closest[0].context, context)
  t.is(calls.bootstrap.length, 1)
  t.is(calls.bootstrap[0].context, context)
  t.ok(calls.request.length > 0)
  for (const message of calls.request) t.is(message.context, context)

  await Promise.all([dht.destroy(), dht.destroy()])
  t.is(calls.destroy, 1)
})

test('HyperDHT keeps direct outbound routing as the default', async (t) => {
  const dht = new HyperDHT({ bootstrap: [], udx: new InertUDX() })
  t.teardown(() => dht.destroy())

  t.is(dht.outboundPolicy, 'direct')
  t.ok(dht.udx)

  await dht.destroy()
})

class InertUDX {
  watchNetworkInterfaces() {
    const watcher = new EventEmitter()
    watcher.destroy = () => {}
    return watcher
  }

  createSocket() {
    return new InertSocket()
  }
}

class InertSocket extends EventEmitter {
  constructor() {
    super()
    this.bound = false
    this._port = 0
  }

  bind(port) {
    this.bound = true
    this._port = port || 1
  }

  address() {
    return { host: '127.0.0.1', port: this._port }
  }

  trySend() {}

  close() {
    this.bound = false
    return Promise.resolve()
  }
}
