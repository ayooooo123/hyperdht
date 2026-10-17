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
