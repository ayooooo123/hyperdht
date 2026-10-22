'use strict'

// A local native network for runtime tests: guard, safety and terminal relays on one
// testnet, each with its own identity, operator authority and real DHT socket, and a
// source on the testnet's first node.

const b4a = require('b4a')

const createTestnet = require('../../testnet')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  LINK_OPERATION,
  PROTOCOL_VERSION,
  ROLE,
  TOPOLOGY_ROLE,
  roleForIdentity
} = require('../../lib/private/protocol')
const {
  encodeUnsignedTopologyGrantV1,
  decodeUnsignedTopologyGrantV1,
  signTopologyGrantV1,
  assembleTopologyGrantV1
} = require('../../lib/private/topology-grant')
const { createPeerNativeRuntime } = require('../../lib/private/peer-native-runtime')

const EPOCH = 11n

// Relay topology roles are bound to the identity: relays use safety-role identities.
function relayIdentity() {
  for (;;) {
    const pair = cryptoSuite.keyPair()
    if (roleForIdentity(pair.publicKey) === ROLE.SAFETY) return pair
  }
}

function otherRoleIdentity() {
  for (;;) {
    const pair = cryptoSuite.keyPair()
    if (roleForIdentity(pair.publicKey) !== ROLE.SAFETY) return pair
  }
}

// A format-1 grant signed independently by each endpoint's own operator authority.
function twoAuthorityGrant({ initiator, acceptor, runId32, expiresAt }) {
  const side = (end, operations) => ({
    identity32: end.identity.publicKey,
    role: end.role,
    host: '127.0.0.1',
    port: end.dht.port,
    operations,
    authority32: end.operator.publicKey
  })
  const unsigned = encodeUnsignedTopologyGrantV1({
    version: PROTOCOL_VERSION,
    format: 1,
    grantId32: cryptoSuite.randomBytes(32),
    endpointA: side(initiator, LINK_OPERATION.INITIATE),
    endpointB: side(acceptor, LINK_OPERATION.ACCEPT),
    epoch: EPOCH,
    notBefore: 0n,
    expiresAt,
    runId32
  })
  const decoded = decodeUnsignedTopologyGrantV1(unsigned)
  const signer = (authority32) =>
    b4a.equals(authority32, initiator.operator.publicKey) ? initiator.operator : acceptor.operator
  return assembleTopologyGrantV1(
    unsigned,
    signTopologyGrantV1(unsigned, signer(decoded.endpointA.authority32)),
    signTopologyGrantV1(unsigned, signer(decoded.endpointB.authority32))
  )
}

// Relay limits of the ruled production profile's concurrency (R36): twenty-four circuits at
// once, each funded by its own branches' authority. Tests that need a tighter relay pass an
// explicit override.
const LIMITS = Object.freeze({
  maxConcurrentCircuits: 24,
  capacityClass: 1,
  maxCells: 200,
  maxBytes: 240000,
  maxCommands: 100,
  idleTimeoutMs: 30000,
  maxQueuedBytes: 524288
})

// A relay's capability mask follows from its grants: a guard or safety is upstream in some
// grant (mask 9), a terminal only ever downstream (mask 11).
function relayConfig(node, grants) {
  return {
    role: 'relay',
    memoryBytes: 1 << 20,
    identity: node.identity,
    relay: {
      reachable: { host: '127.0.0.1', port: node.dht.port },
      limits: LIMITS,
      lifetimeMs: 600_000,
      epoch: EPOCH,
      admission: {
        authorityPublicKeys: [node.operator.publicKey],
        runId32: node.runId32,
        grants,
        maxNeighbors: 4
      }
    }
  }
}

// Guard, safety and terminal relays on one local DHT, each with its own identity,
// operator authority and real socket; guard↔safety and safety↔terminal are granted. Nodes
// past the fourth only serve the DHT.
async function relayTopology(t, size = 4) {
  const testnet = await createTestnet(size, { host: '127.0.0.1' })
  t.teardown(() => testnet.destroy())
  const runId32 = cryptoSuite.randomBytes(32)
  const expiresAt = BigInt(Date.now()) + 3_600_000n
  const [, guard, safety, terminal] = testnet.nodes.map((dht) => ({
    dht,
    identity: relayIdentity(),
    operator: cryptoSuite.keyPair(),
    runId32,
    role: null
  }))
  const guardSafety = twoAuthorityGrant({
    initiator: { ...guard, role: TOPOLOGY_ROLE.SAFETY_GUARD },
    acceptor: { ...safety, role: TOPOLOGY_ROLE.SAFETY_FINAL },
    runId32,
    expiresAt
  })
  const safetyTerminal = twoAuthorityGrant({
    initiator: { ...safety, role: TOPOLOGY_ROLE.SAFETY_GUARD },
    acceptor: { ...terminal, role: TOPOLOGY_ROLE.SAFETY_FINAL },
    runId32,
    expiresAt
  })
  return {
    testnet,
    guard: { node: guard, config: relayConfig(guard, [guardSafety]) },
    safety: { node: safety, config: relayConfig(safety, [guardSafety, safetyTerminal]) },
    terminal: { node: terminal, config: relayConfig(terminal, [safetyTerminal]) }
  }
}

async function until(predicate, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs
  while (!predicate()) {
    if (Date.now() > deadline) return false
    await new Promise((resolve) => setTimeout(resolve, 20))
  }
  return true
}

// Starts the three relays, with an optional config override per relay, and a source on
// the testnet's first node.
async function nativeNetwork(t, overrides = {}, size = 4) {
  const topology = await relayTopology(t, size)
  const runtimes = {}
  for (const name of ['guard', 'safety', 'terminal']) {
    const base = topology[name].config
    const config = overrides[name] ? overrides[name](base) : base
    runtimes[name] = createPeerNativeRuntime({ dht: topology[name].node.dht, config })
    t.teardown(() => runtimes[name].destroy())
  }
  const arrived = []
  runtimes.terminal.onIncomingFinal((lease) => arrived.push(lease))
  await Promise.all(['terminal', 'safety', 'guard'].map((name) => runtimes[name].ready()))
  const source = createPeerNativeRuntime({
    dht: topology.testnet.nodes[0],
    config: {
      role: 'source',
      memoryBytes: 1 << 20,
      source: { guards: [{ host: '127.0.0.1', port: topology.guard.node.dht.port }] }
    }
  })
  t.teardown(() => source.destroy())
  const limits = { maxCells: 60, maxCommands: 30, idleTimeoutMs: 30_000 }
  const build = async () => {
    const before = arrived.length
    const lease = await source
      .buildTail({
        forwardLimits: limits,
        reverseLimits: limits,
        payloadParametersDigest: cryptoSuite.randomBytes(32),
        terminal: null
      })
      .catch((err) => {
        console.error(
          'BUILDERR',
          err && err.code,
          ((err && err.stack) || '').split('\n').slice(1, 3).join(' | ')
        )
        throw err
      })
    await until(() => arrived.length > before)
    const terminalLease = arrived[arrived.length - 1]
    const sourceView = lease.consume()
    const terminalView = terminalLease.consume()
    lease.revoke()
    terminalLease.revoke()
    return b4a.equals(
      sourceView.tailControlTranscriptDigest,
      terminalView.tailControlTranscriptDigest
    )
  }
  return { topology, runtimes, source, build, arrived }
}

const allLive = (runtime) => {
  const { neighbors } = runtime.diagnostics()
  return neighbors.length > 0 && neighbors.every((state) => state === 'live')
}

// A relay config override advertising `count` concurrent circuits.
function circuitsAt(count) {
  return (config) => ({
    ...config,
    relay: { ...config.relay, limits: { ...config.relay.limits, maxConcurrentCircuits: count } }
  })
}

// True once no relay holds a live circuit branch: every closed branch has run its closure
// duty to completion and retired.
function branchesQuiet(runtimes) {
  return ['guard', 'safety', 'terminal'].every(
    (name) => runtimes[name].diagnostics().branches.live === 0
  )
}

module.exports = {
  EPOCH,
  LIMITS,
  allLive,
  branchesQuiet,
  circuitsAt,
  nativeNetwork,
  otherRoleIdentity,
  relayConfig,
  relayIdentity,
  relayTopology,
  twoAuthorityGrant,
  until
}
