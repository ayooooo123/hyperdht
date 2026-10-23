'use strict'

// Reproduces a confirmed audit finding at commit
// 3ea467edfe338a29e0e48bd1b7a15668eef9dc2c. Uses loopback only.
const assert = require('assert/strict')
const path = require('path')
if (!process.argv[2])
  throw new Error('Usage: node ' + path.basename(__filename) + ' /path/to/hyperdht-checkout')
const DHT = require(path.resolve(process.argv[2]))
const { setTimeout: delay } = require('timers/promises')
const options = {
  release: 'alpha',
  acknowledgeAlpha: true,
  mode: 'optional',
  profile: 'native-v2',
  relay: false
}
const dht = new DHT({ bootstrap: [], host: '127.0.0.1', anyPort: true, privateRouting: options })
let release
let entered = false
const blocked = new Promise((resolve) => {
  release = resolve
})
const original = dht.fullyBootstrapped.bind(dht)
// Hold the per-instance bootstrap promise after real loopback socket readiness.
// The facade deliberately calls the dht-rpc prototype method, so overriding
// dht.fullyBootstrapped would not exercise this path.
const streams = []
const watchdog = setTimeout(() => {
  console.error('REPRO_TIMEOUT')
  process.exit(2)
}, 10000)
;(async () => {
  await original()
  dht._bootstrapping = {
    then(resolve, reject) {
      entered = true
      return blocked.then(resolve, reject)
    }
  }
  for (let i = 0; i < 32; i++) streams.push(dht.privateRouting.connect(DHT.keyPair().publicKey))
  for (let i = 0; i < 100 && !entered; i++) await delay(10)
  assert(entered)
  const closures = streams.map((s) => new Promise((resolve) => s.once('close', resolve)))
  let closeCount = 0
  for (const closure of closures) closure.then(() => closeCount++)
  for (const s of streams) s.destroy()
  assert.equal(await streams[0].opened, false)
  await delay(150)
  let code = null
  try {
    const next = dht.privateRouting.connect(DHT.keyPair().publicKey)
    next.destroy()
  } catch (e) {
    code = e.code
  }
  console.log(
    JSON.stringify({
      bootstrapEntered: entered,
      cancelled: streams.length,
      closedBeforeBootstrapRelease: closeCount,
      replacementError: code,
      status: dht.privateRouting.status()
    })
  )
  assert.equal(closeCount, 0)
  assert.equal(code, 'ROUTE_UNAVAILABLE')
  const destroying = dht.destroy()
  release()
  await Promise.all([...closures, destroying])
  console.log(
    JSON.stringify({ closedAfterBootstrapRelease: closeCount, status: dht.privateRouting.status() })
  )
  assert.equal(closeCount, 32)
})()
  .catch((e) => {
    console.error(e)
    process.exitCode = 1
  })
  .finally(async () => {
    release()
    await dht.destroy()
    clearTimeout(watchdog)
  })
