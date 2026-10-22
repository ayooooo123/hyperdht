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
const source = fs.readFileSync(fixturePath, 'utf8')
const prefix = source.slice(0, source.indexOf("test('native controller publishes"))
const fixture = new Module(fixturePath, module)
fixture.filename = fixturePath
fixture.paths = Module._nodeModulePaths(path.dirname(fixturePath))
fixture._compile(
  prefix + '\nmodule.exports = {topology, connected, closed, cryptoSuite};\n',
  fixturePath
)
const { topology, connected, closed, cryptoSuite } = fixture.exports
const cleanup = []
const watchdog = setTimeout(() => {
  console.error('REPRO_TIMEOUT')
  process.exit(2)
}, 150000)
;(async () => {
  const f = await topology({ teardown: (cb) => cleanup.push(cb) })
  const destination = await f.source()
  const source = await f.source()
  const identity = cryptoSuite.keyPair()
  const server = destination.controller.createServer()
  await server.listen(identity)
  const pair = await connected(source.controller, server, identity.publicKey)
  console.log('initial connection opened', await pair.stream.opened)
  const closing = Promise.all([closed(pair.stream), closed(pair.remote)])
  pair.stream.destroy()
  await closing
  const began = Date.now()
  await server.refresh()
  console.log('server refreshed', { elapsedMs: Date.now() - began, listening: server.listening })
  let incoming = 0
  server.on('connection', (s) => {
    incoming++
    s.on('error', () => {})
  })
  for (let attempt = 1; attempt <= 2; attempt++) {
    const s = source.controller.connect(identity.publicKey)
    let error = null
    s.on('error', (e) => {
      error = e.code || e.message
    })
    const opened = await s.opened
    if (opened) s.destroy()
    await closed(s)
    console.log('reconnect', { attempt, opened, error, incoming })
  }
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
