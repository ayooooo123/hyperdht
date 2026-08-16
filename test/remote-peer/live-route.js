'use strict'

// The eleven-role scenario with every role on a different host.
//
// This is the driver for both distributed paths, and there is deliberately no
// second one. scripts/live-route-rehearsal.sh points it at a throwaway testnet
// with eleven local bridges; the coordinator job in
// .github/workflows/live-route.yml points this same file at the public DHT with
// eleven bridges on eleven runners. All that differs is the bootstrap and how far
// apart the roles come up, and both of those are environment.
//
// Nothing about the scenario changes. This supplies only the two things a
// distributed run needs and a local one does not. First the addresses, asked of
// each role over the DHT, because a role behind a NAT is the only party that can
// discover what the world sees for its own socket. Then the control channels,
// which are DHT streams dressed as child processes so
// test/private/process/coordinator.js drives them unchanged.
//
//   REMOTE_PEER_SECRET=<hex> REMOTE_PEER_RUN_ID=<id> \
//     REMOTE_PEER_COORDINATOR_SECRET=<hex> \
//     brittle-node test/remote-peer/live-route.js
//
// Skips with a stated reason when no run is configured, except inside GitHub
// Actions, where an unconfigured coordinator is a fault rather than a skip.

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
  // GITHUB_RUN_ID as a fallback exactly as role-bridge.js takes it: the roles and
  // the coordinator must derive the same keys, so they must not be able to end up
  // scoped to different run ids.
  const runId = process.env.REMOTE_PEER_RUN_ID || process.env.GITHUB_RUN_ID
  // The coordinator's own secret, which no role host has. The roles pin only its
  // public key, so this is the one piece of material that makes the bridges'
  // firewalls mean anything.
  const coordinatorSecret = process.env.REMOTE_PEER_COORDINATOR_SECRET
  const waitMs = Number(process.env.REMOTE_PEER_WAIT_SECONDS || 900) * 1000
  const bootstrap = (process.env.REMOTE_PEER_BOOTSTRAP || '')
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0)
    .map((entry) => {
      const [host, port] = entry.split(':')
      return { host, port: Number(port) }
    })
  if (!secret || !runId) {
    // A skip is honest on a workstation with nothing dispatched, which is how
    // `brittle-node test/remote-peer/live-route.js` is reached by hand. It is
    // never honest inside Actions: the coordinator job exists only to drive a
    // run, so a missing secret there is an unset repository secret, and a pass
    // reported for it would make the whole eleven-runner dispatch mean nothing.
    if (process.env.GITHUB_ACTIONS === 'true') {
      throw new Error(
        'REMOTE_PEER_SECRET and a run id are required in GitHub Actions: set the ' +
          'REMOTE_PEER_SECRET repository secret with scripts/remote-peer.sh secret --push'
      )
    }
    return null
  }
  // A run is configured, so a missing coordinator secret is a fault rather than
  // an unconfigured harness: skipping here would report a pass for a run that
  // never happened.
  if (!coordinatorSecret) {
    throw new Error(
      'REMOTE_PEER_COORDINATOR_SECRET is required alongside REMOTE_PEER_SECRET: ' +
        'the workstation-only secret whose public key the role bridges pin, ' +
        'from scripts/remote-peer.sh secret'
    )
  }
  return { secret, coordinatorSecret, runId, waitMs, bootstrap }
}

// validatePathDiversity requires the guard and all four branch positions to differ
// by endpoint subnet, /24 for IPv4 (KI-5). Eleven loopback addresses under one
// rehearsal prefix always satisfy it and eleven separate hosts usually do, but two
// runners inside one provider block do not, and the run then stops during route
// construction with nothing naming the addresses that caused it. So sharing is
// named here, from the answers themselves, before the topology is minted from them.
// IPv4 only: a reflected address is one, and carrying a second /48 rule here for a
// case that has never occurred would be a rule to keep in step with lib/ for
// nothing.
function sharedSubnets(endpoints) {
  const groups = new Map()
  for (let index = 0; index < endpoints.length; index++) {
    const octets = endpoints[index].reachable.host.split('.')
    if (octets.length !== 4) continue
    const prefix = `${octets[0]}.${octets[1]}.${octets[2]}.0/24`
    const roles = groups.get(prefix)
    if (roles === undefined) groups.set(prefix, [ROLES[index]])
    else roles.push(ROLES[index])
  }
  const shared = []
  for (const [prefix, roles] of groups) {
    if (roles.length > 1) shared.push(`${prefix} holds ${roles.join(' and ')}`)
  }
  return shared
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
        coordinatorSecret: options.coordinatorSecret,
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

      for (const collision of sharedSubnets(endpoints)) {
        t.comment(`path diversity refuses roles sharing a subnet (KI-5): ${collision}`)
      }

      return {
        endpoints,
        async openChannels(projections) {
          const entries = await openRemoteRoleChannels({
            node,
            secret: options.secret,
            coordinatorSecret: options.coordinatorSecret,
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
