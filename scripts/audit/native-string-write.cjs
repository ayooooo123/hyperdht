'use strict'

// Reproduces a confirmed audit finding at commit
// 3ea467edfe338a29e0e48bd1b7a15668eef9dc2c. Uses loopback only.
const fs = require('fs')
const path = require('path')
const Module = require('module')
const assert = require('assert/strict')
if (!process.argv[2])
  throw new Error('Usage: node ' + path.basename(__filename) + ' /path/to/hyperdht-checkout')
const repo = path.resolve(process.argv[2])
const filename = path.join(repo, 'test/private/private-native-controller.js')
const fixture = new Module(filename, module)
fixture.filename = filename
fixture.paths = Module._nodeModulePaths(path.dirname(filename))
const source = fs.readFileSync(filename, 'utf8')
const boundary = source.indexOf("test('native controller publishes")
assert(boundary > 0)
fixture._compile(
  source.slice(0, boundary) +
    '\nmodule.exports = {topology, connected, closed, cryptoSuite, sourceOptions};',
  filename
)
const { topology, connected, closed, cryptoSuite, sourceOptions } = fixture.exports
const cleanup = []
const watchdog = setTimeout(() => {
  console.error('REPRO_TIMEOUT')
  process.exit(2)
}, 180000)
;(async () => {
  const f = await topology({ teardown: (cb) => cleanup.push(cb) })
  const destination = f.network.createNode({ privateRouting: sourceOptions() })
  const source = f.network.createNode({ privateRouting: sourceOptions() })
  await Promise.all([destination.privateRouting.ready(), source.privateRouting.ready()])
  const identity = cryptoSuite.keyPair()
  const server = destination.privateRouting.createServer()
  await server.listen(identity)
  for (const value of [Buffer.from('private peer payload'), 'private peer payload']) {
    const pair = await connected(source.privateRouting, server, identity.publicKey)
    let error = null
    const received = []
    pair.stream.on('error', (e) => {
      error = e.code
    })
    pair.remote.on('data', (b) => received.push(Buffer.from(b)))
    const outcome = new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Write outcome timed out')), 5000)
      const settle = () => {
        clearTimeout(timer)
        resolve()
      }
      pair.stream.once('error', settle)
      pair.remote.once('data', settle)
    })
    pair.stream.write(value)
    await outcome
    const text = Buffer.concat(received).toString()
    console.log(
      JSON.stringify({
        inputType: typeof value,
        opened: await pair.stream.opened,
        error,
        received: text
      })
    )
    if (typeof value === 'string') {
      assert.equal(error, 'INVALID_ROUTE')
      assert.equal(text, '')
    } else {
      assert.equal(error, null)
      assert.equal(text, 'private peer payload')
    }
    const closure = Promise.all([closed(pair.stream), closed(pair.remote)])
    pair.stream.destroy()
    await closure
  }
  await server.close()
})()
  .catch((e) => {
    console.error(e)
    process.exitCode = 1
  })
  .finally(async () => {
    for (const cb of cleanup.reverse()) await cb()
    clearTimeout(watchdog)
  })
