'use strict'

// The eleven-role scenario with every role on a different host.
//
// Nothing about the scenario changes. This supplies only the two things a
// distributed run needs and a local one does not. First the addresses, asked of
// each role over the DHT, because a role behind a NAT is the only party that can
// discover what the world sees for its own socket. Then the control channels,
// which are DHT streams dressed as child processes so
// test/private/process/coordinator.js drives them unchanged.
//
//   REMOTE_PEER_SECRET=<hex> REMOTE_PEER_RUN_ID=<id> \
//     brittle-node test/remote-peer/live-route.js
//
// Skips with a stated reason when no run is configured.

const test = require('brittle')
const DHT = require('../..')
const registerLiveProcessSuite = require('../private/live-process-suite')
const { PROCESS_PLANS, ROLES } = require('../private/process/topology-fixture')
const {
  closeRemoteRoleChannels,
  openRemoteRoleChannels,
  requestRoleEndpoints
} = require('./role-channels')

function config() {
  const secret = process.env.REMOTE_PEER_SECRET
  const runId = process.env.REMOTE_PEER_RUN_ID
  const waitMs = Number(process.env.REMOTE_PEER_WAIT_SECONDS || 900) * 1000
  const bootstrap = (process.env.REMOTE_PEER_BOOTSTRAP || '')
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0)
    .map((entry) => {
      const [host, port] = entry.split(':')
      return { host, port: Number(port) }
    })
  if (!secret || !runId) return null
  return { secret, runId, waitMs, bootstrap }
}

const options = config()

if (options === null) {
  test('a live private route across eleven hosts', (t) => {
    t.comment('skipped: set REMOTE_PEER_SECRET and REMOTE_PEER_RUN_ID to drive remote roles')
    t.pass('no distributed run configured')
  })
} else {
  registerLiveProcessSuite({
    runtime: 'node',
    runtimeVersion: process.version,
    plan: PROCESS_PLANS.DHT_MESH,
    label: 'eleven remote hosts',
    async prepare(t) {
      // Roles queue, install and reflect before they answer, so the window is
      // minutes rather than the default thirty seconds.
      t.timeout(options.waitMs + 300_000)

      const node = new DHT({
        bootstrap: options.bootstrap.length > 0 ? options.bootstrap : undefined
      })
      t.teardown(() => node.destroy(), { order: Infinity })
      await node.ready()

      const deadline = Date.now() + options.waitMs
      const endpoints = await requestRoleEndpoints({
        node,
        secret: options.secret,
        runId: options.runId,
        count: ROLES.length,
        deadline
      })

      for (let index = 0; index < endpoints.length; index++) {
        const entry = endpoints[index]
        t.comment(
          `${ROLES[index]}: binds ${entry.bind.host}:${entry.bind.port}, ` +
            `reachable at ${entry.reachable.host}:${entry.reachable.port}`
        )
      }

      return {
        endpoints,
        async openChannels(projections) {
          const entries = await openRemoteRoleChannels({
            node,
            secret: options.secret,
            runId: options.runId,
            projections,
            deadline
          })
          t.teardown(() => closeRemoteRoleChannels(entries), { order: 1 })
          return entries
        }
      }
    }
  })
}
