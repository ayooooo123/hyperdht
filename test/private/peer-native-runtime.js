'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { TOPOLOGY_ROLE } = require('../../lib/private/protocol')
const {
  createPeerNativeRuntime,
  isPeerNativeRuntime,
  readNativeConfig
} = require('../../lib/private/peer-native-runtime')
const {
  LIMITS,
  allLive,
  branchesQuiet,
  circuitsAt,
  nativeNetwork,
  otherRoleIdentity,
  relayIdentity,
  relayTopology,
  twoAuthorityGrant,
  until
} = require('./peer-native-network')

test('native config validation rejects incomplete relay configuration before any send', (t) => {
  const end = (role, identity = relayIdentity()) => ({
    identity,
    operator: cryptoSuite.keyPair(),
    role,
    dht: { port: 4000 }
  })
  const local = end(TOPOLOGY_ROLE.SAFETY_GUARD)
  const grant = (initiator, acceptor) =>
    twoAuthorityGrant({
      initiator,
      acceptor,
      runId32: b4a.alloc(32, 1),
      expiresAt: BigInt(Date.now()) + 3_600_000n
    })
  const identity = local.identity
  const base = {
    role: 'relay',
    memoryBytes: 4096,
    identity,
    relay: {
      reachable: { host: '127.0.0.1', port: 4000 },
      limits: LIMITS,
      lifetimeMs: 1000,
      epoch: 1n,
      admission: {
        authorityPublicKeys: [local.operator.publicKey],
        runId32: b4a.alloc(32, 1),
        grants: [grant(local, end(TOPOLOGY_ROLE.SAFETY_FINAL))]
      }
    }
  }
  t.is(readNativeConfig(base).relay.capabilityMask, 9, 'an upstream relay forwards circuits')
  const downstream = {
    ...base,
    relay: {
      ...base.relay,
      epoch: 0n,
      reachable: { host: '::1', port: 4000 },
      admission: {
        ...base.relay.admission,
        grants: [
          grant(end(TOPOLOGY_ROLE.SAFETY_GUARD), { ...local, role: TOPOLOGY_ROLE.SAFETY_FINAL })
        ]
      }
    }
  }
  t.is(
    readNativeConfig(downstream).relay.capabilityMask,
    11,
    'a relay that is only ever downstream is a terminal and hosts no guard'
  )
  const variants = [
    { ...base, role: 'exit' },
    { ...base, memoryBytes: 0 },
    { ...base, identity: { publicKey: identity.publicKey, secretKey: b4a.alloc(32) } },
    { ...base, identity: otherRoleIdentity() },
    // The mask is derived and never configured.
    { ...base, relay: { ...base.relay, capabilityMask: 9 } },
    // Grants must decode, name this relay, and pair SAFETY_GUARD with SAFETY_FINAL.
    {
      ...base,
      relay: { ...base.relay, admission: { ...base.relay.admission, grants: [b4a.alloc(8, 1)] } }
    },
    {
      ...base,
      relay: {
        ...base.relay,
        admission: {
          ...base.relay.admission,
          grants: [grant(end(TOPOLOGY_ROLE.SAFETY_GUARD), end(TOPOLOGY_ROLE.SAFETY_FINAL))]
        }
      }
    },
    {
      ...base,
      relay: {
        ...base.relay,
        admission: {
          ...base.relay.admission,
          grants: [grant(end(TOPOLOGY_ROLE.SOURCE, otherRoleIdentity()), local)]
        }
      }
    },
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

test('native config normalizes legacyEgress only for a grant-derived terminal', (t) => {
  const end = (role, identity = relayIdentity()) => ({
    identity,
    operator: cryptoSuite.keyPair(),
    role,
    dht: { port: 4000 }
  })
  const local = end(TOPOLOGY_ROLE.SAFETY_GUARD)
  const grant = (initiator, acceptor) =>
    twoAuthorityGrant({
      initiator,
      acceptor,
      runId32: b4a.alloc(32, 1),
      expiresAt: BigInt(Date.now()) + 3_600_000n
    })
  const base = {
    role: 'relay',
    memoryBytes: 4096,
    identity: local.identity,
    relay: {
      reachable: { host: '127.0.0.1', port: 4000 },
      limits: LIMITS,
      lifetimeMs: 1000,
      epoch: 1n,
      admission: {
        authorityPublicKeys: [local.operator.publicKey],
        runId32: b4a.alloc(32, 1),
        grants: [grant(local, end(TOPOLOGY_ROLE.SAFETY_FINAL))]
      }
    }
  }
  const terminal = {
    ...base,
    relay: {
      ...base.relay,
      epoch: 0n,
      reachable: { host: '::1', port: 4000 },
      admission: {
        ...base.relay.admission,
        grants: [
          grant(end(TOPOLOGY_ROLE.SAFETY_GUARD), { ...local, role: TOPOLOGY_ROLE.SAFETY_FINAL })
        ]
      }
    }
  }
  t.is(readNativeConfig(base).relay.capabilityMask, 9, 'the upstream relay forwards')
  t.is(readNativeConfig(terminal).relay.capabilityMask, 11, 'the downstream relay terminates')

  t.is(readNativeConfig(base).relay.legacyEgress, false, 'absent means false')
  t.is(readNativeConfig(terminal).relay.legacyEgress, false, 'a terminal defaults to false')
  t.is(
    readNativeConfig({
      ...terminal,
      relay: { ...terminal.relay, legacyEgress: false }
    }).relay.legacyEgress,
    false,
    'an explicit false stays false'
  )
  t.is(
    readNativeConfig({ ...terminal, relay: { ...terminal.relay, legacyEgress: true } }).relay
      .legacyEgress,
    true,
    'a grant-derived terminal opts in'
  )
  t.exception(
    () => readNativeConfig({ ...base, relay: { ...base.relay, legacyEgress: true } }),
    /invalid/i,
    'a forwarding relay cannot enable legacy egress'
  )
  for (const value of [1, 'true', null]) {
    t.exception(
      () => readNativeConfig({ ...terminal, relay: { ...terminal.relay, legacyEgress: value } }),
      /invalid/i,
      'non-boolean values reject instead of coercing'
    )
  }
  t.exception(
    () =>
      readNativeConfig({
        ...terminal,
        relay: Object.defineProperty({ ...terminal.relay }, 'legacyEgress', { get: () => true })
      }),
    /invalid/i,
    'a getter is not own data'
  )
  const inherited = Object.assign(Object.create({ legacyEgress: true }), terminal.relay)
  t.is(
    readNativeConfig({ ...terminal, relay: inherited }).relay.legacyEgress,
    false,
    'an inherited value does not count'
  )
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

// A relay's hosted tails are its live circuit sessions. Whichever path ends a session, its
// forwarder ending with its legs at a guard or safety or its delivery at a terminal, the
// relay stops counting it, and a later circuit is counted afresh.
test('a relay stops counting a hosted tail once its circuit ends', async (t) => {
  const { runtimes, build } = await nativeNetwork(t)
  const relays = ['guard', 'safety', 'terminal']
  const idle = () => relays.every((name) => runtimes[name].diagnostics().hostedTails === 0)
  for (let circuit = 0; circuit < 3; circuit++) {
    t.ok(await build(), `circuit ${circuit} is built and both ends are revoked`)
    t.ok(await until(idle), `no relay counts a tail after circuit ${circuit} ends`)
  }
  t.alike(
    relays.map((name) => runtimes[name].diagnostics().hostedTails),
    [0, 0, 0]
  )
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

// Four circuits build at once from a fresh source through one guard: the source shares
// the pin still being created, each relay funds both branches of every circuit it
// forwards, and each relay's D1/D2 queries to one neighbor run side by side. Every relay
// charges that discovery to the circuit it serves, so its node-service ledger moves only
// by its own neighbor sends and its neighbor links keep their funding.
test('a fresh source builds four circuits at once through one guard, each paying its own discovery', async (t) => {
  const { runtimes, source, arrived } = await nativeNetwork(t)
  const relays = ['guard', 'safety']
  const events = { guard: [], safety: [] }
  const stops = relays.map((name) =>
    runtimes[name].observeSendAttempts((event) => {
      if (event.kind === 'attempt') events[name].push(event)
    })
  )
  const before = {}
  for (const name of relays) before[name] = runtimes[name].diagnostics().neighborService

  const circuits = 4
  const limits = { maxCells: 60, maxCommands: 30, idleTimeoutMs: 30_000 }
  const leases = await Promise.all(
    Array.from({ length: circuits }, () =>
      source.buildTail({
        forwardLimits: limits,
        reverseLimits: limits,
        payloadParametersDigest: cryptoSuite.randomBytes(32),
        terminal: null
      })
    )
  )
  t.is(leases.length, circuits, 'every build completes')
  t.ok(await until(() => arrived.length >= circuits), 'the terminal receives every circuit')
  const after = {}
  for (const name of relays) after[name] = runtimes[name].diagnostics().neighborService
  for (const stop of stops) stop()
  const sourceDigests = leases.map((lease) =>
    b4a.toString(lease.consume().tailControlTranscriptDigest, 'hex')
  )
  const terminalDigests = arrived.map((lease) =>
    b4a.toString(lease.consume().tailControlTranscriptDigest, 'hex')
  )
  t.alike(sourceDigests.sort(), terminalDigests.sort(), 'each circuit ends at the terminal')

  for (const name of relays) {
    const discovery = events[name].filter((event) => event.owner.kind === 'circuit-discovery')
    const service = events[name].filter((event) => event.owner.class === 'neighbor')
    const ordinals = new Map()
    for (const event of discovery) {
      if (!ordinals.has(event.owner.ledger)) ordinals.set(event.owner.ledger, [])
      ordinals.get(event.owner.ledger).push(event.owner.ordinal)
    }
    t.ok(
      discovery.every((event) => event.owner.class === 'circuit' && event.owner.charged),
      `${name}: discovery is charged circuit traffic`
    )
    t.ok(ordinals.size >= circuits, `${name}: every circuit discovery names its own ledger`)
    t.ok(
      [...ordinals.values()].every((list) => list.every((ordinal, index) => ordinal === index + 1)),
      `${name}: each discovery ledger counts only its own sends`
    )
    t.is(
      after[name].cellsSpent - before[name].cellsSpent,
      service.length,
      `${name}: the neighbor-service ledger moves only by neighbor sends`
    )
  }
  t.ok(allLive(runtimes.guard) && allLive(runtimes.safety), 'neighbor links stay live')
  for (const lease of leases) lease.revoke()
  for (const lease of arrived) lease.revoke()
})

// A native pin carries up to sixteen circuits at once, each spending its own branch ledgers,
// and the seventeenth finds no slot. A closing circuit keeps its pin slot until its closure
// has completed; only then does the slot admit the next circuit.
test(
  'one native pin carries sixteen concurrent circuits and refuses a seventeenth',
  { timeout: 180_000 },
  async (t) => {
    const { runtimes, source, arrived } = await nativeNetwork(t)
    const events = []
    source.observeSendAttempts((event) => {
      if (event.kind === 'attempt') events.push(event)
    })
    const limits = { maxCells: 60, maxCommands: 30, idleTimeoutMs: 30_000 }
    const build = () =>
      source.buildTail({
        forwardLimits: limits,
        reverseLimits: limits,
        payloadParametersDigest: cryptoSuite.randomBytes(32),
        terminal: null
      })
    const refusal = () =>
      build().then(
        (lease) => {
          lease.revoke()
          return null
        },
        (err) => err.code
      )
    const leases = await Promise.all(Array.from({ length: 16 }, build))
    t.is(leases.length, 16, 'sixteen circuits build at once through one pin')
    t.ok(await until(() => arrived.length >= 16), 'the terminal receives all sixteen')
    t.is(await refusal(), 'ERR_QUOTA_EXCEEDED', 'a seventeenth circuit finds no slot')
    const ledgers = new Map()
    for (const event of events) {
      if (event.owner.kind !== 'circuit') continue
      if (!ledgers.has(event.owner.ledger)) ledgers.set(event.owner.ledger, [])
      ledgers.get(event.owner.ledger).push(event.owner.ordinal)
    }
    t.ok(ledgers.size >= 16, 'each circuit spends its own branch ledger')
    t.ok(
      [...ledgers.values()].every((list) => list.every((ordinal, index) => ordinal === index + 1)),
      'each branch ledger counts only its own sends'
    )
    leases.shift().revoke()
    t.is(
      await refusal(),
      'ERR_QUOTA_EXCEEDED',
      'the revoked circuit keeps its pin slot while its closure runs'
    )
    // Each hop of the closed circuit retires its branches once its closure has completed;
    // until then its successor also holds its neighbor link's transfer.
    const retiredAt = { guard: 30, safety: 30, terminal: 15 }
    t.ok(
      await until(
        () =>
          source.diagnostics().branches.live === 15 &&
          Object.entries(retiredAt).every(
            ([name, live]) => runtimes[name].diagnostics().branches.live === live
          ),
        10_000
      ),
      'every hop retires the closed circuit branches once its closure completes'
    )
    leases.push(await build())
    t.is(leases.length, 16, 'the freed slot admits the next circuit')
    for (const lease of leases) lease.revoke()
    for (const lease of arrived) lease.revoke()
  }
)

test(
  'the guard advertised circuit limit caps a native pin below its sixteen slots',
  { timeout: 180_000 },
  async (t) => {
    const { source, arrived } = await nativeNetwork(t, { guard: circuitsAt(5) })
    const limits = { maxCells: 60, maxCommands: 30, idleTimeoutMs: 30_000 }
    const outcomes = await Promise.allSettled(
      Array.from({ length: 6 }, () =>
        source.buildTail({
          forwardLimits: limits,
          reverseLimits: limits,
          payloadParametersDigest: cryptoSuite.randomBytes(32),
          terminal: null
        })
      )
    )
    const built = outcomes.filter((outcome) => outcome.status === 'fulfilled')
    t.is(built.length, 5, 'the guard admits exactly its advertised five circuits')
    for (const outcome of built) outcome.value.revoke()
    for (const lease of arrived) lease.revoke()
  }
)

// A relay generation funds circuits through branch slots, not a lifetime pool. With four
// concurrent circuits it has eight branch slots, and in one unrenewed generation it serves
// ten circuits in turn, each on fresh authority once the one before has fully closed. Every
// retired branch keeps what it spent: its closure's DESTROY duty or receipt, exactly once.
test(
  'a four-circuit relay generation serves more than twice its limit in sequence',
  { timeout: 180_000 },
  async (t) => {
    const low = circuitsAt(4)
    const { runtimes, build } = await nativeNetwork(t, { guard: low, safety: low, terminal: low })
    const circuits = 10
    for (let circuit = 0; circuit < circuits; circuit++) {
      t.ok(await build().catch(() => false), `circuit ${circuit} is built`)
      t.ok(await until(() => branchesQuiet(runtimes), 10_000), `circuit ${circuit} fully closes`)
    }
    // This fixture's build() revokes both consumed leases (peer-native-network.js), so the
    // terminal's local abrupt destroy originates the physical-loss duty: one 8-attempt
    // DESTROY train on its own send partition per circuit, charged to it, with no echo to
    // receive. The guard and safety each receive their successor's DESTROY (one command per
    // accepted branch) and run their own duty onward. Nothing in this exercised path sends
    // closure traffic toward the terminal, so its receive partition stays unspent.
    const expected = {
      guard: { retired: 20, sendClosure: 10, receiveClosure: 10 },
      safety: { retired: 20, sendClosure: 10, receiveClosure: 10 },
      terminal: { retired: 10, sendClosure: 10, receiveClosure: 0 }
    }
    for (const [name, want] of Object.entries(expected)) {
      const { generations, branches } = runtimes[name].diagnostics()
      t.is(generations, 1, `${name} served every circuit from one unrenewed generation`)
      t.alike([branches.capacity, branches.live], [8, 0], `${name} has eight slots, none held`)
      t.is(branches.retired, want.retired, `${name} retired every branch it admitted`)
      t.alike(
        [branches.reserved.teardownSendLedger.cells, branches.reserved.teardownReceiveLedger.cells],
        [0, 0],
        `${name} holds no closure authority once quiet`
      )
      t.is(
        branches.spent.teardownSendLedger.commands,
        want.sendClosure,
        `${name}: each closing branch spent its one closure command`
      )
      // Each duty sends at most eight DESTROY attempts (packet §8.1); a duty cut short
      // when the peer's loss lands mid-retry spends fewer, and a refused dispatch is
      // never charged, so only the per-duty bounds are invariant.
      t.ok(
        branches.spent.teardownSendLedger.cells >= want.sendClosure &&
          branches.spent.teardownSendLedger.cells <= 8 * want.sendClosure,
        `${name}: each duty spent between its first and its eighth DESTROY cell`
      )
      t.is(
        branches.spent.teardownReceiveLedger.commands,
        want.receiveClosure,
        `${name}: each accepted branch spent one command on the DESTROY it received`
      )
    }
  }
)

// Branch slots are storage, not circuit admission: a terminal with two advertised circuits
// holds four branch slots and still admits only two circuits.
test(
  'a terminal admits its advertised circuits, not its branch slots',
  { timeout: 120_000 },
  async (t) => {
    const { runtimes, source, arrived } = await nativeNetwork(t, { terminal: circuitsAt(2) })
    t.is(runtimes.terminal.diagnostics().branches.capacity, 4)
    const limits = { maxCells: 60, maxCommands: 30, idleTimeoutMs: 30_000 }
    const outcomes = await Promise.allSettled(
      Array.from({ length: 4 }, () =>
        source.buildTail({
          forwardLimits: limits,
          reverseLimits: limits,
          payloadParametersDigest: cryptoSuite.randomBytes(32),
          terminal: null
        })
      )
    )
    const built = outcomes.filter((outcome) => outcome.status === 'fulfilled')
    t.is(built.length, 2, 'the terminal admits exactly its two advertised circuits')
    t.is(runtimes.terminal.diagnostics().branches.live, 2, 'and holds one branch for each')
    for (const outcome of built) outcome.value.revoke()
    for (const lease of arrived) lease.revoke()
    t.ok(await until(() => branchesQuiet(runtimes), 10_000), 'every branch retires')
  }
)

// A guard with one advertised circuit has two branch slots. After a circuit ends, its
// successor branch runs its DESTROY duty and keeps its slot, so the next circuit cannot
// extend past the guard; the refused circuit's own branches are cleaned up, and once every
// closure has completed the slots admit a new circuit.
test(
  'a closing branch keeps its slot until its closure completes, then admits anew',
  { timeout: 120_000 },
  async (t) => {
    const { runtimes, build } = await nativeNetwork(t, { guard: circuitsAt(1) })
    const guardBranches = () => runtimes.guard.diagnostics().branches
    t.ok(await build(), 'the first circuit is built and both ends are revoked')
    t.ok(
      await until(() => guardBranches().live === 1),
      'the guard retires the accepted branch; its successor keeps its slot while closing'
    )
    t.alike(
      [
        guardBranches().reserved.teardownSendLedger.cells,
        guardBranches().spent.teardownSendLedger.commands
      ],
      [10, 1],
      'the closing successor holds its closure partition and has spent its closure command'
    )
    t.is(
      await build().catch((err) => err.code),
      'ERR_PRIVACY_UNAVAILABLE',
      'no slot for a successor'
    )
    t.ok(await until(() => branchesQuiet(runtimes), 10_000), 'every closure and the refusal settle')
    const settled = guardBranches()
    t.alike([settled.live, settled.reserved.sendLedger.cells], [0, 0], 'nothing is left reserved')
    t.ok(await build(), 'freed slots admit a new circuit with new authority')
  }
)

// Closing one circuit neither ends nor funds a concurrent sibling: each runs on its own
// branches, and the sibling's carrier stays live after the first circuit has retired.
test('closing one circuit leaves its concurrent sibling live', { timeout: 120_000 }, async (t) => {
  const { runtimes, source, arrived } = await nativeNetwork(t)
  const limits = { maxCells: 60, maxCommands: 30, idleTimeoutMs: 30_000 }
  const build = () =>
    source.buildTail({
      forwardLimits: limits,
      reverseLimits: limits,
      payloadParametersDigest: cryptoSuite.randomBytes(32),
      terminal: null
    })
  const [first, second] = await Promise.all([build(), build()])
  t.ok(await until(() => arrived.length >= 2), 'the terminal receives both circuits')
  const views = arrived.map((lease) => lease.consume())
  first.revoke()
  t.ok(
    await until(() => runtimes.guard.diagnostics().branches.live === 2, 10_000),
    'the guard keeps exactly the sibling circuit branches once the first retires'
  )
  const live = views.filter((view) => {
    try {
      view.carrier.cancelReceive(view.carrier.reserveReceive())
      return true
    } catch {
      return false
    }
  })
  t.is(live.length, 1, 'exactly the sibling terminal carrier is still live')
  second.revoke()
  for (const lease of arrived) lease.revoke()
  t.ok(await until(() => branchesQuiet(runtimes), 10_000), 'every branch retires')
})

// A generation close must not retire a hosted final carrier's branch while that carrier
// still has native work in flight: the carrier's runtime moved out of the generation's
// runtime set at delivery, so closing has to await the lease's real join before pool
// retirement. The branch roots stay readable until the true native completion joins.
test(
  'a shutting-down terminal keeps a final carrier branch occupied until its native send joins',
  { timeout: 120_000 },
  async (t) => {
    const NativeUDX = require('udx-native')
    const { chargePeerLedger } = require('../../lib/private/peer-ledger')
    let armed = false
    let terminalPort = -1
    let releaseNative = null
    const createSocket = NativeUDX.prototype.createSocket
    NativeUDX.prototype.createSocket = function (options) {
      const socket = createSocket.call(this, options)
      const send = socket.send
      socket.send = function (packet, port, host) {
        if (
          armed &&
          releaseNative === null &&
          socket.address()?.port === terminalPort &&
          b4a.isBuffer(packet) &&
          packet.byteLength === 1200 &&
          packet[0] === 0 &&
          (packet[1] === 1 || packet[1] === 2)
        ) {
          return new Promise((resolve) => {
            releaseNative = resolve
          })
        }
        return send.call(this, packet, port, host)
      }
      return socket
    }
    let net = null
    try {
      net = await nativeNetwork(t)
    } finally {
      NativeUDX.prototype.createSocket = createSocket
    }
    const { runtimes, source, arrived, topology } = net
    terminalPort = topology.terminal.node.dht.port
    const limits = { maxCells: 60, maxCommands: 30, idleTimeoutMs: 30_000 }
    const before = arrived.length
    let lease = null
    try {
      lease = await source.buildTail({
        forwardLimits: limits,
        reverseLimits: limits,
        payloadParametersDigest: cryptoSuite.randomBytes(32),
        terminal: null
      })
    } catch (err) {
      lease = err
    }
    t.ok(lease && !lease.code, 'the circuit builds for this test')
    t.ok(await until(() => arrived.length > before), 'the terminal received the circuit')
    const sourceView = lease.consume()
    const terminalLease = arrived[arrived.length - 1]
    const terminalView = terminalLease.consume()
    t.teardown(() => {
      sourceView
      lease.revoke()
      terminalLease.revoke()
    })

    // The final carrier's own route send is held at the terminal's socket: its native
    // completion stays outstanding while the generation closes.
    armed = true
    const sending = terminalView.carrier.sendFrame(b4a.alloc(1100))
    void sending.catch(() => {})
    for (let i = 0; i < 40 && releaseNative === null; i++) {
      await new Promise((resolve) => setImmediate(resolve))
    }
    t.ok(releaseNative !== null, 'the carrier send is dispatched and held')

    const closing = runtimes.terminal.destroy()
    void closing.catch(() => {})
    // Admission is revoked at once even though the carrier's send has not joined.
    const refused = await source
      .buildTail({
        forwardLimits: limits,
        reverseLimits: limits,
        payloadParametersDigest: cryptoSuite.randomBytes(32),
        terminal: null
      })
      .then(
        () => 'admitted',
        (err) => String(err.code || err)
      )
    t.not(refused, 'admitted', 'a closing generation admits nothing new')
    // A zero-cell charge is the admission check every dispatch performs: it passes only
    // while the branch's authority is live. Probe through the whole close: a retirement
    // before the native join would show here.
    const probe = () =>
      chargePeerLedger(terminalView.sendLedger, { cells: 0, bytes: 0n, commands: 0 })
    let earlyRelease = false
    const probeDeadline = Date.now() + 4000
    while (Date.now() < probeDeadline) {
      try {
        probe()
      } catch {
        earlyRelease = true
        break
      }
      await new Promise((resolve) => setTimeout(resolve, 25))
    }
    t.is(
      earlyRelease,
      false,
      "the carrier's branch roots stay live while its native send is outstanding"
    )

    // Join: the held completion settles, the carrier's duty finishes, and only then may
    // the branch retire.
    releaseNative(true)
    releaseNative = null
    await closing
    let retired = null
    try {
      probe()
    } catch (err) {
      retired = err
    }
    t.ok(retired !== null, 'the branch retired exactly once, at the true join')
    t.ok(
      await until(
        () => ['guard', 'safety'].every((name) => runtimes[name].diagnostics().branches.live === 0),
        30_000
      ),
      'every surviving relay branch retires'
    )
  }
)

// The carrier's abrupt destroy runs its bounded DESTROY duty on real timers after the
// first attempt settles: the attempts still armed are its native work too, so the
// generation close must keep the branch's authority live until the duty has joined.
test(
  'a shutting-down terminal retires a final carrier branch only after its closure duty joins',
  { timeout: 120_000 },
  async (t) => {
    const { chargePeerLedger } = require('../../lib/private/peer-ledger')
    const { runtimes, source, arrived } = await nativeNetwork(t)
    const limits = { maxCells: 60, maxCommands: 30, idleTimeoutMs: 30_000 }
    const before = arrived.length
    let lease = null
    try {
      lease = await source.buildTail({
        forwardLimits: limits,
        reverseLimits: limits,
        payloadParametersDigest: cryptoSuite.randomBytes(32),
        terminal: null
      })
    } catch (err) {
      lease = err
    }
    t.ok(lease && !lease.code, 'the circuit builds for this test')
    t.ok(await until(() => arrived.length > before), 'the terminal received the circuit')
    const sourceView = lease.consume()
    const terminalLease = arrived[arrived.length - 1]
    const terminalView = terminalLease.consume()
    t.teardown(() => {
      sourceView
      lease.revoke()
      terminalLease.revoke()
    })

    const probe = () =>
      chargePeerLedger(terminalView.sendLedger, { cells: 0, bytes: 0n, commands: 0 })
    const closing = runtimes.terminal.destroy()
    void closing.catch(() => {})
    // While the duty's later attempts sit armed on their timers, the branch's authority
    // must stay live: a pool retirement here would cut the duty's own funding.
    let earlyRelease = false
    const probeDeadline = Date.now() + 2500
    while (Date.now() < probeDeadline) {
      try {
        probe()
      } catch {
        earlyRelease = true
        break
      }
      await new Promise((resolve) => setTimeout(resolve, 25))
    }
    t.is(earlyRelease, false, 'the branch authority stays live while its closure duty is armed')
    await closing
    let retired = null
    try {
      probe()
    } catch (err) {
      retired = err
    }
    t.ok(retired !== null, 'the branch retired after the duty joined')
    t.ok(
      await until(
        () => ['guard', 'safety'].every((name) => runtimes[name].diagnostics().branches.live === 0),
        30_000
      ),
      'every surviving relay branch retires'
    )
  }
)
// A purpose partition larger than the branch's admitted residual refuses at reservation,
// before any effect: nothing is charged, nothing is bound, and the carrier still accepts
// a partition that fits, with the closure partitions never touched.
test(
  'a purpose partition larger than the branch residual refuses before any effect',
  { timeout: 120_000 },
  async (t) => {
    const {
      computePeerRouteBudget,
      createPeerLedger,
      reservePeerLedger,
      readPeerLedger
    } = require('../../lib/private/peer-ledger')
    const { source, arrived } = await nativeNetwork(t)
    const limits = { maxCells: 60, maxCommands: 30, idleTimeoutMs: 30_000 }
    const before = arrived.length
    let lease = null
    try {
      lease = await source.buildTail({
        forwardLimits: limits,
        reverseLimits: limits,
        payloadParametersDigest: cryptoSuite.randomBytes(32),
        terminal: null
      })
    } catch (err) {
      lease = err
    }
    t.ok(lease && !lease.code, 'the circuit builds for this test')
    t.ok(await until(() => arrived.length > before), 'the terminal received the circuit')
    const terminalLease = arrived[arrived.length - 1]
    const sourceView = lease.consume()
    t.teardown(() => {
      lease.revoke()
      terminalLease.revoke()
    })

    // The production purpose-3 M17 rows want 14,024 cells each way; this branch's row is
    // sixty cells less its closure partition and what setup already spent.
    const app = {
      forwardFrames: 24,
      reverseFrames: 24,
      forwardBytes: 23448n,
      reverseBytes: 23448n,
      forwardWindow: 1,
      reverseWindow: 1
    }
    const budget = computePeerRouteBudget({
      purpose: 3,
      maxStreams: 17,
      applications: Array.from({ length: 16 }, () => ({ ...app }))
    })
    t.is(budget.purpose.forward.cells, 14024, 'the production purpose row is as profiled')
    const sendBefore = readPeerLedger(sourceView.sendLedger)
    t.exception(
      () => reservePeerLedger(sourceView.sendLedger, budget.purpose.forward),
      /invalid/i,
      'the oversized purpose partition refuses at reservation'
    )
    t.alike(
      readPeerLedger(sourceView.sendLedger),
      sendBefore,
      'no reservation, charge or binding happened'
    )
    t.is(
      source.diagnostics().branches.spent.teardownSendLedger.cells,
      0,
      'the closure partition is intact'
    )

    // The carrier was never bound: a partition that fits still binds and carries, charged
    // exactly once to itself.
    const sendPartition = reservePeerLedger(sourceView.sendLedger, {
      cells: 4,
      bytes: 4800n,
      commands: 0
    })
    const receivePartition = reservePeerLedger(sourceView.receiveLedger, {
      cells: 4,
      bytes: 4800n,
      commands: 0
    })
    t.is(
      sourceView.carrier.bindLedgers({
        sendLedger: sendPartition,
        receiveLedger: receivePartition
      }),
      true,
      'a fitting partition binds'
    )
    await sourceView.carrier.sendFrame(b4a.alloc(1100))
    t.is(readPeerLedger(sendPartition).cellsSpent, 1, 'the frame charged the partition once')
    t.is(
      readPeerLedger(sourceView.sendLedger).cellsSpent,
      sendBefore.cellsSpent + 1,
      'the branch root counts exactly the one bound charge'
    )
    t.exception(
      () =>
        sourceView.carrier.bindLedgers({
          sendLedger: sendPartition,
          receiveLedger: receivePartition
        }),
      /replay/i,
      'a second binding refuses'
    )
    // A partition that is not below the branch's own ledger cannot bind at all.
    const terminalView = terminalLease.consume()
    const foreign = createPeerLedger({ cells: 4, bytes: 4800n, commands: 0 })
    t.exception(
      () =>
        terminalView.carrier.bindLedgers({
          sendLedger: foreign,
          receiveLedger: receivePartition
        }),
      /invalid/i,
      'a partition outside the branch cannot bind'
    )
  }
)
