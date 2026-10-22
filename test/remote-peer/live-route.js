'use strict'

// The eleven-role scenario with every role on a different host.
//
// This is the driver for every distributed path and there is deliberately no
// second one. scripts/live-route-rehearsal.sh points it at a throwaway testnet
// with eleven local bridges; scripts/live-route.sh points this same file at the
// public DHT with the roles wherever that dispatch put them, on runners, on this
// machine, or split between the two. It cannot tell which, and nothing here asks:
// a role is discovered by key and answers with the address the world sees for it.
// All that differs between the paths is the bootstrap and how far apart the roles
// come up, and both of those are environment.
//
// Nothing about the scenario changes. This supplies only the three things a
// distributed run needs and a local one does not. First the addresses, asked of
// each role over the DHT, because a role behind a NAT is the only party that can
// discover what the world sees for its own socket. Then a punch round, because the
// roles dial each other's sockets directly and two NAT'd hosts cannot open a path
// either one can open alone: this process is the only party holding all eleven
// addresses, so it distributes them and every role punches at once. Then the control
// channels, which are DHT streams dressed as child processes so
// test/private/process/coordinator.js drives them unchanged.
//
//   REMOTE_PEER_SECRET=<hex> REMOTE_PEER_RUN_ID=<id> \
//     REMOTE_PEER_COORDINATOR_SECRET=<hex> \
//     brittle-node test/remote-peer/live-route.js
//
// Skips with a stated reason when no run is configured.

const test = require('brittle')
const b4a = require('b4a')
const DHT = require('../..')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { BOOTSTRAP_NODES } = require('../../lib/constants')
const registerLiveProcessSuite = require('../private/live-process-suite')
const { PROCESS_PLANS, ROLES } = require('../private/process/topology-fixture')
const { resolveReflectors } = require('./dht-reflect')
const {
  closeRemoteRoleChannels,
  openRemoteRoleChannels,
  punchRoleEndpoints,
  requestRoleEndpoints
} = require('./role-channels')

function config() {
  const secret = process.env.REMOTE_PEER_SECRET
  // GITHUB_RUN_ID as a fallback exactly as role-bridge.js takes it: the roles and
  // the coordinator must derive the same keys, so they must not be able to end up
  // scoped to different run ids. It is the only thing in this file that names a CI
  // variable, and it names it as a run label rather than as a place.
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
  // Nothing is dispatched, which is what `brittle-node test/remote-peer/live-route.js`
  // by hand looks like. Every caller that means to drive a run supplies both, and a
  // half-configured one is caught below.
  if (!secret || !runId) return null
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
const productionEndpointPunch = process.env.REMOTE_PEER_PRODUCTION_ENDPOINT_PUNCH === '1'

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
    label: productionEndpointPunch
      ? 'eleven remote hosts with production endpoint punch'
      : 'eleven remote hosts',
    productionEndpointPunch,
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
        deadline,
        comment: (message) => t.comment(message)
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

      // The punch round, before a single role is attached. Every role's cell socket
      // and every exit's DHT socket at 43000+index gets a datagram from every other
      // role, so each side's NAT holds a mapping for the other before any role
      // process exists. Without it the plan's DHT edges are one-way - seed to
      // referral to value, topology-fixture.js:1073-1087, with nothing pointing back
      // - and the referral's setup store to role 11 dies as a dht-rpc
      // REQUEST_TIMEOUT with nothing naming the address that was unreachable.
      //
      // An unanswered pair does NOT fail the run here. It is named instead, on its
      // own comment line, so the scenario's own verdict stands and the cause is in
      // the output above it rather than eight assertions downstream.
      //
      // Production endpoint punch owns endpoint<->guard, so the harness punch omits
      // the endpoint role on both sides of the cross-product.
      const punches = await punchRoleEndpoints({
        node,
        secret: options.secret,
        coordinatorSecret: options.coordinatorSecret,
        runId: options.runId,
        endpoints,
        deadline,
        comment: (message) => t.comment(message),
        ...(productionEndpointPunch ? { excludeIndexes: [1] } : {})
      })

      let arrived = 0
      let possible = 0
      let silentPairs = 0
      for (const report of punches.sort((a, b) => a.index - b.index)) {
        arrived += report.heardFrom.length
        possible += report.targets
        silentPairs += report.silent.length
        t.comment(
          `${ROLES[report.index - 1]} punched from [${report.from.join(', ')}] to ` +
            `${report.targets} sockets in ${report.rounds} rounds ` +
            `(${report.sent} sent, ${report.refused} refused, ${report.elapsedMs}ms): ` +
            `heard back from ${report.heardFrom.length}/${report.targets}`
        )
        if (report.silent.length > 0) {
          t.comment(
            `${ROLES[report.index - 1]} heard NOTHING from ${report.silent.join(', ')} ` +
              `- those directed pairs have no mapping and a request across one will time out`
          )
        }
        for (const failure of report.bindErrors) {
          t.comment(
            `${ROLES[report.index - 1]} could not re-bind ${failure.kind} port ${failure.port} ` +
              `to punch (${failure.message}), so it punched from no such socket`
          )
        }
      }
      t.comment(
        `punch matrix ${arrived}/${possible} directed pairs arrived across ` +
          `${punches.length} roles, ${silentPairs} silent`
      )
      // Nothing refreshes these mappings for the rest of the run: see the limits
      // documented at runPunchPhase in role-bridge.js. A pair the scenario leaves
      // idle past its NAT's UDP timeout loses its mapping with nothing reopening it.
      let natTraversal = null
      if (productionEndpointPunch) {
        // Same two public bootstrap reflectors the bridge uses. identity32 is a
        // stable label (hash of host:port), not an authenticated identity.
        const resolved = (await resolveReflectors(BOOTSTRAP_NODES)).slice(0, 2)
        if (resolved.length < 2) {
          throw new Error('production endpoint punch needs two bootstrap reflectors')
        }
        natTraversal = {
          reflectors: resolved.map((entry) => ({
            host: entry.host,
            identity32: cryptoSuite.hash([b4a.from(`${entry.host}:${entry.port}`)]),
            port: entry.port
          }))
        }
        t.comment(
          `production reflectors ${natTraversal.reflectors
            .map((entry) => `${entry.host}:${entry.port}`)
            .join(', ')}`
        )
      }
      return {
        endpoints,
        ...(natTraversal === null ? {} : { natTraversal }),
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
