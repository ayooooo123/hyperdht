#!/usr/bin/env node

if (process.argv[2] === 'grant') {
  runGrantTool(process.argv.slice(3))
} else {
  const HyperDHT = require('./')

  const bootstrap = arg('bootstrap')
  const nodes = arg('node') ? '' : arg('nodes')

  const isBootstrap = bootstrap === '' || (bootstrap !== null && bootstrap.startsWith('--'))

  if (isBootstrap) {
    const port = Number(arg('port') || '0') || 49737
    const host = arg('host')
    if (!host) throw new Error('You need to specify --host <node ip>')
    startBootstrapNode(HyperDHT, port, host)
  } else {
    startNodes(HyperDHT, Number(nodes) || 1, bootstrap ? bootstrap.split(',') : undefined)
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

async function startNodes(HyperDHT, cnt, bootstrap) {
  console.log('Booting DHT nodes...')

  const port = Number(arg('port') || '0') || 0
  const host = arg('host') || undefined
  const all = []

  if (port && cnt !== 1) throw new Error('--port is only valid when running a single node')

  while (all.length < cnt) {
    const node = new HyperDHT({ host, port, anyPort: !port, bootstrap })
    await node.ready()

    const id = all.push(node) - 1
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

  console.log('Fully started ' + cnt + ' Hyperswarm DHT node' + (cnt === 1 ? '' : 's'))

  process.once('SIGINT', function () {
    console.log('Shutting down nodes...')

    for (const node of all) {
      node.destroy()
    }
  })
}
