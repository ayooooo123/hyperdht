'use strict'

// Privileged sub-gate: realize the namespace projection and prove the isolation
// it describes is actually enforced by the kernel, and that the capture harness
// used by the leak oracles can see traffic when traffic exists.
//
// Requires Linux and non-interactive root. Run with `npm run test:private:namespace`.

const test = require('brittle')
const b4a = require('b4a')
const { execFile, execFileSync } = require('child_process')
const path = require('path')

const {
  PROCESS_PLANS,
  ROLES,
  TEST_ONLY_PROCESS_TOPOLOGY_ISSUER,
  createLiveProcessTopology
} = require('./process/topology-fixture')
const {
  namespaceProvisioningAvailable,
  provisionNamespaceProjection
} = require('./process/namespace-provisioner')
const { contains, readPcap } = require('./process/pcap')

const PROBE = path.join(__dirname, 'process', 'namespace-probe.js')
const ENDPOINT = 1
const GUARD = 2
const LOOKUP_EXIT_A = 4

function hostFor(roleIndex) {
  return `10.203.${roleIndex}.2`
}

function portFor(roleIndex) {
  return 42_000 + roleIndex
}

function probeArgs(provision, roleIndex, args) {
  const entered = provision.enter(roleIndex, process.execPath, [PROBE, ...args])
  return entered
}

function sendProbe(provision, roleIndex, target, payload) {
  const { args, command } = probeArgs(provision, roleIndex, [
    'send',
    hostFor(roleIndex),
    String(portFor(roleIndex)),
    hostFor(target),
    String(portFor(target)),
    payload.toString('hex')
  ])
  try {
    execFileSync(command, args, { stdio: ['ignore', 'ignore', 'pipe'], timeout: 5000 })
    return true
  } catch {
    // A denied destination can surface as an ICMP-driven send error rather than
    // silence; either way the datagram did not arrive, which `receiveProbe`
    // decides independently.
    return false
  }
}

function receiveProbe(provision, roleIndex, timeoutMs) {
  const { args, command } = probeArgs(provision, roleIndex, [
    'recv',
    hostFor(roleIndex),
    String(portFor(roleIndex)),
    String(timeoutMs)
  ])
  return new Promise((resolve) => {
    execFile(command, args, { timeout: timeoutMs + 5000 }, (err, stdout) => {
      if (err) return resolve(null)
      resolve(Buffer.from(String(stdout).trim(), 'hex'))
    })
  })
}

function markerProbe(provision, key, args) {
  return Object.freeze({
    args: [
      '-n',
      'ip',
      'netns',
      'exec',
      provision.markerNamespace(key),
      process.execPath,
      PROBE,
      ...args
    ],
    command: 'sudo'
  })
}

function namespaceList() {
  const output = execFileSync('sudo', ['-n', 'ip', 'netns', 'list'], { encoding: 'utf8' })
  return output
    .split('\n')
    .map((line) => line.split(' ')[0].trim())
    .filter(Boolean)
}

function settle(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

test('namespace projection is enforced by the kernel and observable by capture', async (t) => {
  if (!namespaceProvisioningAvailable()) {
    t.comment(
      `skipped: needs Linux with non-interactive sudo and tcpdump (platform ${process.platform})`
    )
    t.pass('namespace provisioning unavailable on this host')
    return
  }

  const topology = createLiveProcessTopology({
    plan: PROCESS_PLANS.LINUX_NAMESPACE,
    ...capabilitiesForNamespaceRun()
  })

  const suffix = b4a.toString(topology.oracle.run.subarray(0, 2), 'hex')
  const provision = provisionNamespaceProjection(topology.oracle.namespace, { suffix })

  try {
    const live = namespaceList()
    for (let roleIndex = 1; roleIndex <= ROLES.length; roleIndex++) {
      t.ok(
        live.includes(provision.namespaceFor(roleIndex)),
        `${ROLES[roleIndex - 1]} has its own namespace`
      )
    }
    t.ok(live.includes(provision.markerNamespace('auditor')), 'auditor namespace exists')
    t.ok(live.includes(provision.markerNamespace('decoy')), 'decoy namespace exists')

    // The endpoint's routing table names exactly one peer: its guard. Every
    // other role is not merely disallowed, it has no route.
    const endpointRoutes = execFileSync(
      'sudo',
      ['-n', 'ip', '-n', provision.namespaceFor(ENDPOINT), 'route', 'show'],
      { encoding: 'utf8' }
    )
    t.ok(endpointRoutes.includes(`${hostFor(GUARD)} `), 'endpoint routes to the guard')
    t.absent(
      endpointRoutes.includes(`${hostFor(LOOKUP_EXIT_A)} `),
      'endpoint has no route to a lookup exit'
    )
    t.absent(endpointRoutes.includes('default'), 'endpoint has no default route')

    provision.startCapture()

    // Positive control: the auditor/decoy pair is adjacent by construction, so
    // a capture that sees nothing here is a broken harness, not a private route.
    const controlPayload = b4a.from(topology.oracle.decoyMarkerKey.subarray(0, 16))
    const decoy = markerProbe(provision, 'decoy', ['recv', '10.204.2.2', '42991', '4000'])
    const decoyReceive = new Promise((resolve) => {
      execFile(decoy.command, decoy.args, { timeout: 9000 }, (err, stdout) =>
        resolve(err ? null : Buffer.from(String(stdout).trim(), 'hex'))
      )
    })
    await settle(250)
    const auditor = markerProbe(provision, 'auditor', [
      'send',
      '10.204.1.2',
      '42990',
      '10.204.2.2',
      '42991',
      controlPayload.toString('hex')
    ])
    execFileSync(auditor.command, auditor.args, { stdio: 'ignore', timeout: 5000 })
    const controlReceived = await decoyReceive
    t.ok(controlReceived !== null, 'control datagram crosses the auditor edge')
    t.alike(controlReceived, controlPayload, 'control datagram arrives unchanged')

    // Allowed edge: endpoint to guard.
    const allowedPayload = Buffer.from('a1'.repeat(24), 'hex')
    const guardReceive = receiveProbe(provision, GUARD, 4000)
    await settle(250)
    sendProbe(provision, ENDPOINT, GUARD, allowedPayload)
    const guardReceived = await guardReceive
    t.ok(guardReceived !== null, 'endpoint reaches its guard')
    t.alike(guardReceived, allowedPayload, 'guard receives the endpoint datagram')

    // Denied edge: endpoint straight to a lookup exit, which is the exact shape
    // a route bypass would take.
    const deniedPayload = Buffer.from('b2'.repeat(24), 'hex')
    const exitReceive = receiveProbe(provision, LOOKUP_EXIT_A, 2500)
    await settle(250)
    sendProbe(provision, ENDPOINT, LOOKUP_EXIT_A, deniedPayload)
    const exitReceived = await exitReceive
    t.is(exitReceived, null, 'endpoint cannot reach a lookup exit directly')

    const captures = provision.stopCapture()
    const byKey = new Map(captures.map((capture) => [capture.key, capture.file]))

    const auditorCapture = readPcap(byKey.get('a'))
    t.ok(
      auditorCapture.datagrams.some((datagram) => contains(datagram.payload, controlPayload)),
      'capture observes the control datagram'
    )

    const guardCapture = readPcap(byKey.get(String(GUARD)))
    t.ok(
      guardCapture.datagrams.some((datagram) => contains(datagram.payload, allowedPayload)),
      'capture observes the allowed endpoint-to-guard datagram'
    )

    const exitCapture = readPcap(byKey.get(String(LOOKUP_EXIT_A)))
    t.absent(
      exitCapture.datagrams.some((datagram) => contains(datagram.payload, deniedPayload)),
      'no denied datagram reaches the lookup exit device'
    )
    t.absent(
      exitCapture.datagrams.some((datagram) => datagram.source === hostFor(ENDPOINT)),
      'the lookup exit never observes the endpoint address'
    )
  } finally {
    t.is(provision.teardown(), true, 'provisioning is removed')
    topology.stop()
  }

  const remaining = namespaceList().filter((name) => name.startsWith('pr-ns-'))
  t.alike(remaining, [], 'no namespaces survive teardown')
})

function capabilitiesForNamespaceRun() {
  return {
    clocks: TEST_ONLY_PROCESS_TOPOLOGY_ISSUER.clocks({
      monotonicNow: () => BigInt(Date.now()),
      wallNow: () => BigInt(Date.now())
    }),
    entropy: TEST_ONLY_PROCESS_TOPOLOGY_ISSUER.entropy(b4a.alloc(32, 0x51))
  }
}
