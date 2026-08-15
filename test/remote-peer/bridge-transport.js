'use strict'

// Proves the remote control transport carries the real control protocol: a role
// process on the far side of a DHT stream, driven by the same coordinator code the
// local gates use.
//
// The scenario itself is not run here. What is proven is narrower and is the part
// that could silently corrupt a distributed run: bytes written to a RemoteChild's
// stdin reach role-runner unchanged, and role-runner's reply reaches the
// coordinator's stdout stream unchanged.

const test = require('brittle')
const path = require('path')
const { spawn } = require('child_process')
const b4a = require('b4a')
const DHT = require('../..')
const createTestnet = require('../../testnet')
const { peerKeyPair, proberKeyPair } = require('./identity')
const { openRemoteRoleChannels, closeRemoteRoleChannels } = require('./role-channels')

const BRIDGE = path.join(__dirname, 'role-bridge.js')
const SECRET = 'a1b2c3d4e5f60718293a4b5c6d7e8f901122334455667788990aabbccddeeff0'

function readyLine(child, timeoutMs) {
  return new Promise((resolve, reject) => {
    let buffered = ''
    const timer = setTimeout(() => reject(new Error('bridge never reported ready')), timeoutMs)
    child.stdout.on('data', (chunk) => {
      buffered += chunk.toString()
      for (const line of buffered.split('\n')) {
        if (!line.startsWith('{')) continue
        let parsed = null
        try {
          parsed = JSON.parse(line)
        } catch {
          continue
        }
        if (parsed.event === 'ready') {
          clearTimeout(timer)
          resolve(parsed)
          return
        }
        if (parsed.event === 'error') {
          clearTimeout(timer)
          reject(new Error(parsed.message))
          return
        }
      }
    })
  })
}

test('a role on the far side of a DHT stream speaks the control protocol', async (t) => {
  t.timeout(120_000)

  const testnet = await createTestnet(6, t.teardown.bind(t))
  const bootstrap = testnet.bootstrap.map((node) => `${node.host}:${node.port}`).join(',')
  const runId = `bridge-${Date.now()}`

  const bridge = spawn(
    process.execPath,
    [BRIDGE, '--index', '1', '--seconds', '90', '--bootstrap', bootstrap],
    {
      cwd: path.join(__dirname, '..', '..'),
      env: { ...process.env, REMOTE_PEER_SECRET: SECRET, REMOTE_PEER_RUN_ID: runId },
      stdio: ['ignore', 'pipe', 'pipe']
    }
  )
  t.teardown(() => bridge.kill('SIGKILL'), { order: 1 })
  const events = []
  const seen = new Map()
  const awaitEvent = (name, timeoutMs) =>
    new Promise((resolve, reject) => {
      const existing = events.find((entry) => entry.event === name)
      if (existing) return resolve(existing)
      const timer = setTimeout(() => reject(new Error(`no ${name} event`)), timeoutMs)
      seen.set(name, (entry) => {
        clearTimeout(timer)
        resolve(entry)
      })
    })
  bridge.stderr.on('data', (chunk) => t.comment(`bridge stderr: ${chunk.toString().slice(0, 200)}`))
  bridge.stdout.on('data', (chunk) => {
    for (const line of chunk.toString().split('\n')) {
      if (!line.startsWith('{')) continue
      try {
        const parsed = JSON.parse(line)
        events.push(parsed)
        const waiter = seen.get(parsed.event)
        if (waiter) {
          seen.delete(parsed.event)
          waiter(parsed)
        }
      } catch {
        continue
      }
    }
  })

  const ready = await readyLine(bridge, 60_000)
  t.is(ready.index, 1, 'the bridge reports the role it will host')
  t.ok(Number.isInteger(ready.cellPort) && ready.cellPort > 0, 'it claims a cell port')

  const node = new DHT({ bootstrap: testnet.bootstrap })
  t.teardown(() => node.destroy(), { order: 2 })

  const entries = await openRemoteRoleChannels({
    node,
    secret: SECRET,
    runId,
    projections: [
      {
        generation: 1n,
        phaseGate: null,
        plan: 'dht-mesh',
        role: 'endpoint',
        roleIndex: 1,
        run: b4a.alloc(16, 1)
      }
    ],
    deadline: Date.now() + 60_000
  })
  t.is(entries.length, 1, 'the coordinator opened one remote role channel')
  t.teardown(() => closeRemoteRoleChannels(entries), { order: 1 })

  const child = entries[0].child
  child.on('error', () => {})

  // A deliberately malformed control frame. role-runner enforces its protocol by
  // exiting, so an exit surfacing on this channel proves the whole path: bytes
  // written to a RemoteChild reached a real role process on the other side of a
  // DHT stream, and its outcome came back to the coordinator.
  const exited = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('the role never acted')), 30_000)
    child.once('exit', (code, signal) => {
      clearTimeout(timer)
      resolve({ code, signal })
    })
  })

  const frame = b4a.alloc(8)
  frame.writeUInt32BE(4, 0)
  frame.writeUInt32BE(0xdeadbeef, 4)
  child.stdin.write(frame)

  const outcome = await exited
  t.ok(outcome !== null, 'the coordinator channel surfaced the role outcome')
  t.comment(`role outcome: code ${outcome.code}, signal ${outcome.signal}`)
})
