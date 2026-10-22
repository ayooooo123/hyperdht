'use strict'
// Local loopback reproduction for commit 3ea467edfe338a29e0e48bd1b7a15668eef9dc2c.
// Reuses only the fixture preamble from the repository's native-controller test.
// Does not register the original tests or modify repository sources.
const fs = require('fs')
const path = require('path')
const Module = require('module')
if (!process.argv[2])
  throw new Error('Usage: node ' + path.basename(__filename) + ' /path/to/hyperdht-checkout')
const repo = path.resolve(process.argv[2])
const fixturePath = path.join(repo, 'test/private/private-native-controller.js')
const sourceText = fs.readFileSync(fixturePath, 'utf8')
const prefix = sourceText.slice(0, sourceText.indexOf("test('native controller publishes"))
const fixture = new Module(fixturePath, module)
fixture.filename = fixturePath
fixture.paths = Module._nodeModulePaths(path.dirname(fixturePath))
fixture._compile(
  prefix +
    '\nmodule.exports = {topology, connected, closed, cryptoSuite, createPrivateNativeController, sourceOptions};\n',
  fixturePath
)
const { topology, connected, closed, cryptoSuite, createPrivateNativeController, sourceOptions } =
  fixture.exports
const cleanup = []
const watchdog = setTimeout(() => {
  console.error('REPRO_TIMEOUT')
  process.exit(2)
}, 180000)
;(async () => {
  const f = await topology({ teardown: (cb) => cleanup.push(cb) })
  const destination = await f.source()
  const identity = cryptoSuite.keyPair()
  const server = destination.controller.createServer((s) => s.on('error', () => {}))
  await server.listen(identity)
  const dht = f.network.createNode()
  await dht.fullyBootstrapped()
  const realLookup = dht.lookup.bind(dht)
  let discoveryCalls = 0
  let stale = true
  const oldTuple = f.network.nodes[0].address()
  dht.lookup = (...args) => {
    discoveryCalls++
    if (!stale) return realLookup(...args)
    return {
      async *[Symbol.asyncIterator]() {
        yield { peers: [{ relayAddresses: [{ host: '127.0.0.1', port: oldTuple.port }] }] }
      },
      destroy() {},
      finished() {
        return Promise.resolve()
      }
    }
  }
  const source = createPrivateNativeController({
    dht,
    config: sourceOptions(),
    baseReady: () => dht.fullyBootstrapped()
  })
  f.controllers.push(source)
  await source.ready()
  stale = false
  console.log('directory now healthy', { discoveryCalls, status: source.snapshot().state })
  for (let attempt = 1; attempt <= 2; attempt++) {
    await source.ready()
    const s = source.connect(identity.publicKey)
    let error = null
    s.on('error', (e) => {
      error = e.code || e.message
    })
    const opened = await s.opened
    if (opened) s.destroy()
    await closed(s)
    console.log('reconnect', {
      attempt,
      opened,
      error,
      discoveryCalls,
      status: source.snapshot().state
    })
  }
  await source.suspend()
  await source.resume()
  const healthy = await connected(source, server, identity.publicKey)
  console.log('after explicit suspend/resume', {
    opened: await healthy.stream.opened,
    discoveryCalls,
    status: source.snapshot().state
  })
  healthy.stream.destroy()
  await Promise.all([closed(healthy.stream), closed(healthy.remote)])
  await server.close()
})()
  .catch((e) => {
    console.error(e.stack)
    process.exitCode = 1
  })
  .finally(async () => {
    for (const cb of cleanup.reverse()) await cb()
    clearTimeout(watchdog)
  })
