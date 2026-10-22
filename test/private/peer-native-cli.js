'use strict'

const test = require('brittle')
const fs = require('fs')
const os = require('os')
const path = require('path')
const process = require('process')
const { spawn } = require('child_process')
const { loadPrivateRoutingConfig } = require('../../bin')
const { PrivateRouteError } = require('../../lib/private/errors')
const { validatePeerNativeOptions } = require('../../lib/private/peer-native-config')
const { fixture, jsonOptions } = require('./helpers/native-config')
const createTestnet = require('../../testnet')
const HyperDHT = require('../..')
const { endpoint, grant, sourceOptions } = require('./helpers/native-config')
const { TOPOLOGY_ROLE } = require('../../lib/private/protocol')

function configFile(t, text) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hyperdht-native-config-'))
  const file = path.join(directory, 'relay.json')
  fs.writeFileSync(file, text, { mode: 0o600 })
  t.teardown(() => {
    fs.unlinkSync(file)
    fs.rmdirSync(directory)
  })
  return file
}

function cli(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.resolve(__dirname, '../../bin.js'), ...args], {
      stdio: ['ignore', 'pipe', 'pipe']
    })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString()
    })
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString()
    })
    child.once('error', reject)
    child.once('close', (code) => resolve({ code, stdout, stderr }))
  })
}

test('relay config files decode to independently validated public options', (t) => {
  const { options } = fixture()
  options.relayConfig.legacyEgress = true
  const file = configFile(t, JSON.stringify(jsonOptions(options), null, 2))
  t.alike(loadPrivateRoutingConfig(file), validatePeerNativeOptions(options))
  for (const invalid of ['', '--host', path.join(path.dirname(file), 'missing.json')]) {
    t.exception(() => loadPrivateRoutingConfig(invalid), PrivateRouteError.INVALID_ROUTE())
  }
})

test('relay CLI rejects malformed configuration before startup without printing secrets', async (t) => {
  const secret = 'confidential-config-content'
  const file = configFile(t, '{"identityKeyPair":"' + secret + '",')
  const result = await cli(['--private-routing-config', file])
  t.is(result.code, 1)
  t.is(result.stdout, '', 'no node is started')
  t.is(result.stderr.includes(secret), false)
  t.is(result.stderr.includes(file), false, 'diagnostics do not reveal the secret file path')
  t.ok(result.stderr.includes('Invalid private routing configuration'))
})

test('relay CLI requires one config value and one non-bootstrap node', async (t) => {
  const { options } = fixture()
  const file = configFile(t, JSON.stringify(jsonOptions(options)))
  for (const args of [
    ['--private-routing-config'],
    ['--private-routing-config', '--host', '127.0.0.1'],
    ['--private-routing-config', file, '--private-routing-config', file],
    ['--private-routing-config', file, '--nodes', '2'],
    ['--private-routing-config', file, '--bootstrap', '--host', '127.0.0.1']
  ]) {
    const result = await cli(args)
    t.is(result.code, 1)
    t.is(result.stdout, '', 'invalid invocation never binds a node')
    t.ok(result.stderr.includes('Invalid private routing configuration'))
  }
})

test('HyperDHT selects native-v2 controller and relay CLI boots a live native relay', async (t) => {
  const network = await createTestnet(3, { host: '127.0.0.1' })
  t.teardown(() => network.destroy())
  const bootstrapList = [
    `${network.nodes[0].host}:${network.nodes[0].port}`,
    `${network.nodes[1].host}:${network.nodes[1].port}`
  ]
  const bootstrap = bootstrapList.join(',')

  const probe = new HyperDHT({ host: '127.0.0.1', bootstrap: bootstrapList })
  await probe.ready()
  const relayPort = probe.address().port
  await probe.destroy()

  const peerProbe = new HyperDHT({ host: '127.0.0.1', bootstrap: bootstrapList })
  await peerProbe.ready()
  const peerPort = peerProbe.address().port
  await peerProbe.destroy()

  const local = endpoint(relayPort, TOPOLOGY_ROLE.SAFETY_GUARD)
  const peer = endpoint(peerPort, TOPOLOGY_ROLE.SAFETY_FINAL)
  const edge = grant(local, peer)
  const { options } = fixture()
  const peerRelay = new HyperDHT({
    host: '127.0.0.1',
    port: peerPort,
    bootstrap: bootstrapList,
    ephemeral: false,
    firewalled: false,
    privateRouting: {
      ...options,
      relayConfig: {
        ...options.relayConfig,
        identityKeyPair: peer.identity,
        authorityPublicKeys: [peer.authority.publicKey],
        grants: [edge]
      }
    }
  })
  t.teardown(() => peerRelay.destroy())
  await peerRelay.ready()
  const peerReady = peerRelay.privateRouting.ready()

  options.relayConfig.identityKeyPair = local.identity
  options.relayConfig.authorityPublicKeys = [local.authority.publicKey]
  options.relayConfig.grants = [edge]
  const file = configFile(t, JSON.stringify(jsonOptions(options)))
  const child = spawn(
    process.execPath,
    [
      path.resolve(__dirname, '../../bin.js'),
      '--host',
      '127.0.0.1',
      '--port',
      String(relayPort),
      '--bootstrap',
      bootstrap,
      '--private-routing-config',
      file
    ],
    { stdio: ['ignore', 'pipe', 'pipe'] }
  )
  t.teardown(() => {
    if (child.exitCode === null) child.kill('SIGINT')
  })
  const bound = await new Promise((resolve, reject) => {
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString()
      if (stdout.includes('Node #0 bound to')) resolve(stdout)
    })
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString()
    })
    child.once('error', reject)
    child.once('close', (code) => {
      if (!stdout.includes('Node #0 bound to')) {
        reject(new Error(`CLI exited early (${code}): ${stderr}`))
      }
    })
  })
  t.ok(bound.includes('Node #0 bound to'), 'CLI relay completes native-v2 readiness')

  const client = new HyperDHT({
    host: '127.0.0.1',
    bootstrap: bootstrapList,
    ephemeral: false,
    firewalled: false,
    privateRouting: sourceOptions()
  })
  t.teardown(() => client.destroy())
  t.is(client.privateRouting.profile, 'native-v2')
  t.is(client.privateRouting.relay, false)
  await client.ready()
  await client.privateRouting.ready()
  t.is(client.privateRouting.status(), 'ready')
  await client.destroy()

  child.kill('SIGINT')
  await new Promise((resolve) => child.once('close', resolve))
})
