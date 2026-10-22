#!/usr/bin/env node

const process = require('process')

if (require.main === module) {
  main().catch(() => {
    console.error('DHT startup failed')
    process.exitCode = 1
  })
}

async function main() {
  if (process.argv[2] === 'grant') return runGrantTool(process.argv.slice(3))
  const HyperDHT = require('./')
  const bootstrap = arg('bootstrap')
  const nodes = arg('node') ? '' : arg('nodes')
  const isBootstrap = bootstrap === '' || (bootstrap !== null && bootstrap.startsWith('--'))
  const configFile = arg('private-routing-config')
  let privateRouting = null

  if (configFile !== null) {
    try {
      if (
        isBootstrap ||
        (Number(nodes) || 1) !== 1 ||
        process.argv.filter((value) => value === '--private-routing-config').length !== 1
      )
        throw new Error()
      privateRouting = loadPrivateRoutingConfig(configFile)
    } catch {
      console.error('Invalid private routing configuration')
      process.exitCode = 1
      return
    }
  }

  if (isBootstrap) {
    const port = Number(arg('port') || '0') || 49737
    const host = arg('host')
    if (!host) throw new Error('You need to specify --host <node ip>')
    await startBootstrapNode(HyperDHT, port, host)
  } else {
    await startNodes(
      HyperDHT,
      Number(nodes) || 1,
      bootstrap ? bootstrap.split(',') : undefined,
      privateRouting
    )
  }
}

function loadPrivateRoutingConfig(path) {
  const { PrivateRouteError } = require('./lib/private/errors')
  try {
    if (typeof path !== 'string' || path.length === 0 || path.startsWith('--')) throw new Error()
    const { decodePeerNativeConfig } = require('./lib/private/peer-native-config')
    return decodePeerNativeConfig(require('fs').readFileSync(path, 'utf8'))
  } catch {
    throw PrivateRouteError.INVALID_ROUTE()
  }
}

// Experimental: offline two-authority topology grants for native relay
// neighbors. See docs/superpowers/specs/2026-09-25-*-neighbor-admission-design.md.
function runGrantTool(argv) {
  const fs = require('fs')
  const { GrantToolError, run } = require('./lib/private/grant-tool')
  try {
    console.log(run(argv, { readFile: (path) => fs.readFileSync(path, 'utf8') }))
  } catch (err) {
    if (err instanceof GrantToolError) console.error(err.message)
    else console.error(err && err.code ? err.code : err)
    process.exitCode = 1
  }
}

function arg(name) {
  const i = process.argv.indexOf('--' + name)
  if (i === -1) return null
  return i < process.argv.length - 1 ? process.argv[i + 1] : ''
}

async function startBootstrapNode(HyperDHT, port, host) {
  console.log('Starting DHT bootstrap node...')

  const node = HyperDHT.bootstrapper(port, host)
  await node.ready()

  node.on('close', function () {
    console.log('Bootstrap node closed')
  })

  console.log('Bootstrap node bound to', node.address())
  console.log('Fully started Hyperswarm DHT bootstrap node')

  process.once('SIGINT', function () {
    node.destroy()
  })
}

async function startNodes(HyperDHT, cnt, bootstrap, privateRouting) {
  console.log('Booting DHT nodes...')

  const port = Number(arg('port') || '0') || 0
  const host = arg('host') || undefined
  const all = []

  if (port && cnt !== 1) throw new Error('--port is only valid when running a single node')

  try {
    while (all.length < cnt) {
      const options = { host, port, anyPort: !port, bootstrap }
      if (privateRouting) {
        options.privateRouting = privateRouting
        options.ephemeral = false
      }
      const node = new HyperDHT(options)
      const id = all.push(node) - 1
      await node.ready()
      if (privateRouting) await node.privateRouting.ready()
      console.log('Node #' + id + ' bound to', node.address())

      node.on('ephemeral', function () {
        console.log('Node #' + id + ' is ephemeral', node.address())
      })

      node.on('persistent', function () {
        console.log('Node #' + id + ' is persistent, joining remote routing tables', node.address())
      })

      node.on('close', function () {
        console.log('Node #' + id + ' closed')
      })
    }
  } catch (error) {
    await Promise.allSettled(all.map((node) => node.destroy({ force: true })))
    throw error
  } finally {
    if (privateRouting) privateRouting.relayConfig.identityKeyPair.secretKey.fill(0)
  }

  console.log('Fully started ' + cnt + ' Hyperswarm DHT node' + (cnt === 1 ? '' : 's'))

  process.once('SIGINT', function () {
    console.log('Shutting down nodes...')

    for (const node of all) {
      node.destroy()
    }
  })
}

module.exports = { loadPrivateRoutingConfig }
