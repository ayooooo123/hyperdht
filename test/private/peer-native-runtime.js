'use strict'

const test = require('brittle')
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
const {
  createPeerNativeRuntime,
  isPeerNativeRuntime,
  readNativeConfig
} = require('../../lib/private/peer-native-runtime')

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

const LIMITS = Object.freeze({
  maxConcurrentCircuits: 4,
  capacityClass: 1,
  maxCells: 200,
  maxBytes: 240000,
  maxCommands: 100,
  idleTimeoutMs: 30000,
  maxQueuedBytes: 524288
})

function relayConfig(node, mask, grants) {
  return {
    role: 'relay',
    memoryBytes: 1 << 20,
    identity: node.identity,
    relay: {
      capabilityMask: mask,
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
// operator authority and real socket; guard↔safety and safety↔terminal are granted.
async function relayTopology(t) {
  const testnet = await createTestnet(4, { host: '127.0.0.1' })
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
    guard: { node: guard, config: relayConfig(guard, 9, [guardSafety]) },
    safety: { node: safety, config: relayConfig(safety, 9, [guardSafety, safetyTerminal]) },
    terminal: { node: terminal, config: relayConfig(terminal, 11, [safetyTerminal]) }
  }
}

test('native config validation rejects incomplete relay configuration before any send', (t) => {
  const identity = relayIdentity()
  const base = {
    role: 'relay',
    memoryBytes: 4096,
    identity,
    relay: {
      capabilityMask: 9,
      reachable: { host: '127.0.0.1', port: 4000 },
      limits: LIMITS,
      lifetimeMs: 1000,
      epoch: 1n,
      admission: {
        authorityPublicKeys: [cryptoSuite.keyPair().publicKey],
        runId32: b4a.alloc(32, 1),
        grants: [b4a.alloc(8, 1)]
      }
    }
  }
  t.ok(readNativeConfig(base), 'a complete relay configuration validates')
  const variants = [
    { ...base, role: 'exit' },
    { ...base, memoryBytes: 0 },
    { ...base, identity: { publicKey: identity.publicKey, secretKey: b4a.alloc(32) } },
    { ...base, identity: otherRoleIdentity() },
    { ...base, relay: { ...base.relay, capabilityMask: 10 } },
    { ...base, relay: { ...base.relay, epoch: 1 } },
    { ...base, relay: { ...base.relay, limits: { ...LIMITS, maxCells: 10 } } },
    { ...base, relay: { ...base.relay, admission: { ...base.relay.admission, grants: [] } } },
    // A guard-hosting relay's v1 advertisement needs a non-zero epoch, a lifetime of at
    // most 30 minutes and an IPv4 tuple.
    { ...base, relay: { ...base.relay, epoch: 0n } },
    { ...base, relay: { ...base.relay, lifetimeMs: 1_800_001 } },
    { ...base, relay: { ...base.relay, reachable: { host: '::1', port: 4000 } } }
  ]
  for (const config of variants) {
    t.exception(() => readNativeConfig(config), /invalid/i)
  }
  const copied = readNativeConfig(base)
  base.identity.secretKey.fill(0)
  t.absent(b4a.equals(copied.identity.secretKey, b4a.alloc(64)), 'configuration is copied')
})

test('native source configuration names one to three guard tuples', (t) => {
  const guard = { host: '127.0.0.1', port: 4000 }
  const base = { role: 'source', memoryBytes: 4096, source: { guards: [guard] } }
  const config = readNativeConfig(base)
  t.is(config.source.maxProspectiveGuards, 3, 'a source tries up to three guards by default')
  t.alike(config.source.guards, [guard])
  const variants = [
    { ...base, source: undefined },
    { ...base, source: { guards: [] } },
    { ...base, source: { guards: [guard, guard, guard, guard] } },
    { ...base, source: { guards: [{ host: '', port: 4000 }] } },
    { ...base, source: { guards: [guard], maxProspectiveGuards: 4 } }
  ]
  for (const variant of variants) {
    t.exception(() => readNativeConfig(variant), /invalid/i)
  }
})

test('node-pool reservations are bounded by the pool and returned on release', async (t) => {
  // Reservations need no socket; a DHT stand-in is enough to construct the runtime.
  const dht = { io: {}, on() {}, off() {} }
  const runtime = createPeerNativeRuntime({
    dht,
    config: {
      role: 'source',
      memoryBytes: 4096,
      source: { guards: [{ host: '127.0.0.1', port: 1 }] }
    }
  })
  t.teardown(() => runtime.destroy())
  const first = runtime.reserve('record', 3000)
  t.exception(() => runtime.reserve('registration', 2000), /limit/i, 'the pool bounds the sum')
  t.is(runtime.release(first), true)
  t.is(runtime.release(first), false, 'a reservation is released once')
  t.ok(runtime.reserve('registration', 2000), 'released capacity is reusable')
  t.exception(() => runtime.reserve('circuit', 1), /invalid/i, 'only named node work is reserved')
  t.exception(() => runtime.reserve('semantic', 0), /invalid/i)
  t.is(runtime.release(Object.freeze({})), false, 'a foreign handle releases nothing')
})

for (const order of ['acceptors first', 'dialers first']) {
  test(`relay runtimes on real DHT sockets admit their granted neighbors (${order})`, async (t) => {
    const topology = await relayTopology(t)
    const runtimes = {}
    for (const name of ['guard', 'safety', 'terminal']) {
      runtimes[name] = createPeerNativeRuntime({
        dht: topology[name].node.dht,
        config: topology[name].config
      })
      t.ok(isPeerNativeRuntime(runtimes[name]))
      t.teardown(() => runtimes[name].destroy())
    }
    const starts =
      order === 'acceptors first'
        ? ['terminal', 'safety', 'guard']
        : ['guard', 'safety', 'terminal']
    await Promise.all(starts.map((name) => runtimes[name].ready()))

    t.alike(runtimes.guard.diagnostics().neighbors, ['live'], 'guard admits its safety')
    t.alike(runtimes.safety.diagnostics().neighbors, ['live', 'live'], 'safety admits both')
    t.alike(runtimes.terminal.diagnostics().neighbors, ['live'], 'terminal admits its safety')
    t.ok(runtimes.guard.diagnostics().leased, 'the guard leases its DHT socket')

    const guardDht = topology.guard.node.dht
    t.ok(
      await topology.safety.node.dht.ping({ host: '127.0.0.1', port: guardDht.port }),
      'ordinary DHT RPC works beside private admission'
    )
    await runtimes.guard.destroy()
    t.is(guardDht.io.serverSocket.bound, true, 'destroy leaves the DHT socket to the DHT')
    t.absent(runtimes.guard.diagnostics().leased, 'destroy ends the lease')
    t.ok(
      await topology.safety.node.dht.ping({ host: '127.0.0.1', port: guardDht.port }),
      'ordinary DHT RPC continues after the private runtime ends'
    )
    await t.exception(runtimes.guard.ready(), /destroyed/i)
  })
}

test('the runtime send observer attributes admission traffic to neighbor service ledgers', async (t) => {
  const topology = await relayTopology(t)
  const runtimes = {}
  for (const name of ['guard', 'safety', 'terminal']) {
    runtimes[name] = createPeerNativeRuntime({
      dht: topology[name].node.dht,
      config: topology[name].config
    })
    t.teardown(() => runtimes[name].destroy())
  }
  const events = []
  const stop = runtimes.safety.observeSendAttempts((event) => events.push(event))
  await Promise.all(['terminal', 'safety', 'guard'].map((name) => runtimes[name].ready()))
  await new Promise((resolve) => setTimeout(resolve, 20))
  const attempts = events.filter((event) => event.kind === 'attempt')
  t.ok(attempts.length > 0, 'the safety sends during admission are observed')
  t.ok(
    attempts.every((event) => event.owner.category === 'service'),
    'admission traffic is service traffic, never circuit traffic'
  )
  t.ok(
    attempts.every((event) =>
      event.owner.charged
        ? event.owner.ledger !== null && event.owner.ordinal > 0 && event.owner.governor === null
        : event.owner.ledger === null &&
          event.owner.ordinal === null &&
          event.owner.governor !== null
    ),
    'charged owners name ledger and ordinal; uncharged owners name their governor'
  )
  t.ok(
    attempts.some((event) => event.owner.kind === 'neighbor-discovery'),
    'grant-pinned discovery is charged to the neighbor service reservation'
  )
  t.ok(
    attempts.every(
      (event, index) => index === 0 || event.attemptId > attempts[index - 1].attemptId
    ),
    'attempt identifiers increase for the runtime'
  )
  const ports = new Set(attempts.map((event) => event.remote.port))
  t.ok(
    [...ports].every(
      (port) => port === topology.guard.node.dht.port || port === topology.terminal.node.dht.port
    ),
    'the safety only sends to its granted neighbors'
  )
  t.ok(
    attempts.every((event) => event.local.port === topology.safety.node.dht.port),
    'every private send leaves the leased DHT socket'
  )
  t.is(stop(), true)
})

test('destroy during startup fails the pending ready and leaves the DHT socket bound', async (t) => {
  const topology = await relayTopology(t)
  const safety = createPeerNativeRuntime({
    dht: topology.safety.node.dht,
    config: topology.safety.config
  })
  // The safety's neighbors never start, so its admission is still settling when the
  // destroy lands.
  const starting = safety.ready()
  await new Promise((resolve) => setTimeout(resolve, 20))
  await safety.destroy()
  await t.exception(starting, /destroyed|unavailable/i, 'the pending start fails')
  t.absent(safety.diagnostics().leased, 'no lease survives the destroy')
  t.is(topology.safety.node.dht.io.serverSocket.bound, true, 'the DHT socket stays bound')
  t.ok(
    await topology.guard.node.dht.ping({ host: '127.0.0.1', port: topology.safety.node.dht.port }),
    'ordinary DHT RPC still reaches the node'
  )
})

test('a source builds one native circuit to a terminal over real DHT sockets', async (t) => {
  const {
    verifyPeerAdvertisement,
    readVerifiedPeerAdvertisement
  } = require('../../lib/private/peer-capability')
  const topology = await relayTopology(t)
  const runtimes = {}
  for (const name of ['guard', 'safety', 'terminal']) {
    runtimes[name] = createPeerNativeRuntime({
      dht: topology[name].node.dht,
      config: topology[name].config
    })
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
  const events = []
  source.observeSendAttempts((event) => events.push(event))
  const limits = { maxCells: 60, maxCommands: 30, idleTimeoutMs: 30_000 }
  const lease = await source.buildTail({
    forwardLimits: limits,
    reverseLimits: limits,
    payloadParametersDigest: cryptoSuite.randomBytes(32),
    terminal: null
  })
  for (let turn = 0; turn < 100 && arrived.length === 0; turn++) {
    await new Promise((resolve) => setTimeout(resolve, 10))
  }
  t.is(arrived.length, 1, 'the terminal receives exactly one final tail')

  const sourceView = lease.consume()
  const terminalView = arrived[0].consume()
  t.exception(() => lease.consume(), 'a final tail lease is consumed once')
  t.is(sourceView.role, 'source')
  t.is(terminalView.role, 'terminal')
  t.alike(sourceView.circuitId, terminalView.circuitId, 'both ends name the terminal hop circuit')
  t.is(sourceView.generation, terminalView.generation)
  t.alike(
    sourceView.tailControlTranscriptDigest,
    terminalView.tailControlTranscriptDigest,
    'both ends hold one tail-control transcript'
  )
  t.alike(
    sourceView.purposeTerminalPublicKey,
    terminalView.purposeTerminalPublicKey,
    'both ends derive one purpose key pair'
  )
  t.is(sourceView.purposeTerminalSecretKey, null, 'the source never holds the terminal secret')
  t.ok(b4a.isBuffer(terminalView.purposeTerminalSecretKey), 'the terminal holds its secret')
  for (const name of ['finalizeForwardKey', 'finalizeReverseKey']) {
    t.alike(sourceView.finalizeKeys[name], terminalView.finalizeKeys[name], `${name} matches`)
  }
  const reached = readVerifiedPeerAdvertisement(
    verifyPeerAdvertisement(sourceView.terminalAdvertisement260, {})
  )
  t.alike(
    reached.advertisementDigest32,
    sourceView.terminalAdvertisementDigest,
    'the source names the terminal it reached'
  )

  const attempts = events.filter((event) => event.kind === 'attempt')
  const kinds = new Set(attempts.map((event) => event.owner.kind))
  for (const kind of ['bootstrap-request', 'link-setup', 'circuit-discovery', 'circuit']) {
    t.ok(kinds.has(kind), `the source sends ${kind}`)
  }
  t.ok(
    attempts.every(
      (event) => event.owner.class === 'guard-bootstrap' || event.owner.class === 'circuit'
    ),
    'a source sends only guard-bootstrap and circuit traffic'
  )
  t.ok(
    attempts.every((event) =>
      event.owner.charged
        ? event.owner.ledger !== null && event.owner.ordinal > 0
        : event.owner.governor !== null
    ),
    'every source send names its ledger and ordinal'
  )
  lease.revoke()
  arrived[0].revoke()
})

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
async function nativeNetwork(t, overrides = {}) {
  const topology = await relayTopology(t)
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
    const lease = await source.buildTail({
      forwardLimits: limits,
      reverseLimits: limits,
      payloadParametersDigest: cryptoSuite.randomBytes(32),
      terminal: null
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
  return { topology, runtimes, source, build }
}

const allLive = (runtime) => {
  const { neighbors } = runtime.diagnostics()
  return neighbors.length > 0 && neighbors.every((state) => state === 'live')
}

test('a relay renews its generation before expiry and still carries circuits', async (t) => {
  // The safety's advertisements live 4 s, so it renews 1 s before they expire.
  const { runtimes, build } = await nativeNetwork(t, {
    safety: (config) => ({ ...config, relay: { ...config.relay, lifetimeMs: 4_000 } })
  })
  t.is(runtimes.safety.diagnostics().generations, 1)
  t.ok(
    await until(() => runtimes.safety.diagnostics().generations === 2),
    'the safety provisions its next generation'
  )
  t.ok(
    await until(() => allLive(runtimes.safety) && allLive(runtimes.guard)),
    'its neighbors admit the new generation'
  )
  t.is(runtimes.safety.diagnostics().lastError, null)
  t.ok(await build(), 'a circuit crosses the renewed safety')
})

test('a relay follows its DHT through suspend and resume to the next socket', async (t) => {
  const { topology, runtimes, source, build } = await nativeNetwork(t)
  const guardDht = topology.guard.node.dht
  t.ok(await build(), 'a circuit is built before suspension')

  // An owner suspends the runtime before the DHT, as HyperDHT does for its controller.
  const suspending = runtimes.guard.suspend()
  t.is(runtimes.guard.suspend(), suspending, 'suspend is one idempotent join')
  await suspending
  await guardDht.suspend()
  t.alike(
    {
      suspended: runtimes.guard.diagnostics().suspended,
      leased: runtimes.guard.diagnostics().leased
    },
    { suspended: true, leased: false },
    'a suspended relay holds no lease'
  )
  await t.exception(runtimes.guard.ready(), /unavailable/i)

  // The DHT's resume event resumes the runtime on the DHT's next socket generation.
  await guardDht.resume()
  t.ok(
    await until(
      () => runtimes.guard.diagnostics().socketGeneration === 2 && allLive(runtimes.guard)
    ),
    'the relay resumes on socket generation 2 with its neighbors'
  )
  t.is(runtimes.guard.diagnostics().suspended, false)
  // The source's guard link to the suspended generation ends once its link control stops
  // hearing from it; the next build then pins the resumed guard afresh.
  t.ok(await until(() => !source.diagnostics().guardPinned), 'the source drops its lost pin')
  t.ok(await build(), 'a circuit is built through the resumed guard')
  t.ok(source.diagnostics().guardPinned, 'the source holds a live pin again')
})
