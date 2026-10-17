'use strict'

const test = require('brittle')
const b4a = require('b4a')
const createTestnet = require('../../testnet')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { LINK_OPERATION, TOPOLOGY_ROLE } = require('../../lib/private/protocol')
const { PRESENCE_PARAMETERS_DIGEST } = require('../../lib/private/peer-presence')
const { createPeerNativeRuntime } = require('../../lib/private/peer-native-runtime')
const {
  createPeerNativeRuntimeConfig,
  peerNativeProfile,
  peerNativePurposeLimits,
  peerNativeBuildLimits
} = require('../../lib/private/peer-native-config')
const {
  createPeerPurposeSource,
  createPeerPurposeTerminal
} = require('../../lib/private/peer-purpose-owner')
const { readPeerLedger } = require('../../lib/private/peer-ledger')
const { createPeerSemanticServices } = require('../../lib/private/peer-semantic-services')
const { createPeerEndpointController } = require('../../lib/private/peer-endpoint-controller')
const {
  verifyPeerAdvertisement,
  readVerifiedPeerAdvertisement
} = require('../../lib/private/peer-capability')
const { hashPeer } = require('../../lib/private/peer-crypto')
const { decodePeerTransport } = require('../../lib/private/peer-transport-wire')
const { PEER_MESSAGE_ID: ID } = require('../../lib/private/peer-protocol')
const { endpoint, grant, sourceOptions } = require('./helpers/native-config')

function erase(value) {
  if (!value) return
  for (const bytes of Object.values(value)) if (b4a.isBuffer(bytes)) bytes.fill(0)
}

function privateParameters() {
  for (;;) {
    const digest = cryptoSuite.randomBytes(32)
    if (digest.some((byte) => byte !== 0) && !b4a.equals(digest, PRESENCE_PARAMETERS_DIGEST))
      return digest
    digest.fill(0)
  }
}

async function nativeChain(t) {
  const network = await createTestnet(4, { host: '127.0.0.1' })
  const runtimes = []
  const leases = new Set()
  const owners = new Set()
  const services = new Set()
  const endpoints = new Set()
  const materials = []
  const attempts = { source: [], terminal: [] }
  const observers = []
  t.teardown(async () => {
    for (const service of services) service.destroy()
    for (const endpoint of endpoints) endpoint.destroy()
    for (const owner of owners) owner.destroy()
    await Promise.all([
      ...Array.from(leases, (lease) => lease.revoke()),
      ...Array.from(owners, (owner) => owner.whenClosed()),
      ...Array.from(endpoints, (endpoint) => endpoint.finished())
    ])
    for (const stop of observers) stop()
    for (const material of materials) {
      erase(material)
      erase(material.finalizeKeys)
    }
    await Promise.all(runtimes.map((runtime) => runtime.destroy()))
    await network.destroy()
  })
  const relays = network.nodes.slice(1).map((dht) => ({
    ...endpoint(dht.port, TOPOLOGY_ROLE.SAFETY_GUARD),
    dht,
    grants: []
  }))
  for (let index = 0; index < 2; index++) {
    const left = relays[index]
    const right = relays[index + 1]
    const wire = grant(
      { ...left, role: TOPOLOGY_ROLE.SAFETY_GUARD, operations: LINK_OPERATION.INITIATE },
      { ...right, role: TOPOLOGY_ROLE.SAFETY_FINAL, operations: LINK_OPERATION.ACCEPT }
    )
    left.grants.push(wire)
    right.grants.push(wire)
  }
  for (const relay of relays) {
    const config = createPeerNativeRuntimeConfig(
      {
        ...sourceOptions(),
        relay: true,
        relayConfig: {
          identityKeyPair: relay.identity,
          authorityPublicKeys: [relay.authority.publicKey],
          epoch: 7n,
          runId32: b4a.alloc(32, 0x52),
          grants: relay.grants
        }
      },
      relay.dht
    )
    try {
      runtimes.push(createPeerNativeRuntime({ dht: relay.dht, config }))
    } finally {
      erase(config.identity)
    }
  }
  const incoming = []
  const waiters = []
  runtimes[2].onIncomingFinal((lease) => {
    leases.add(lease)
    const waiter = waiters.shift()
    if (waiter) waiter(lease)
    else incoming.push(lease)
  })
  await Promise.all(runtimes.map((runtime) => runtime.ready()))
  const source = createPeerNativeRuntime({
    dht: network.nodes[0],
    config: createPeerNativeRuntimeConfig(sourceOptions(), network.nodes[0], [
      { host: '127.0.0.1', port: relays[0].port }
    ])
  })
  runtimes.push(source)
  observers.push(
    source.observeSendAttempts((event) => {
      if (event.kind === 'attempt') attempts.source.push(event)
    }),
    runtimes[2].observeSendAttempts((event) => {
      if (event.kind === 'attempt') attempts.terminal.push(event)
    })
  )
  return {
    source,
    leases,
    attempts,
    owners,
    services,
    endpoints,
    materials,
    entry: null,
    incoming() {
      if (incoming.length) return Promise.resolve(incoming.shift())
      return new Promise((resolve) => waiters.push(resolve))
    }
  }
}

function purposeOptions(material, limits) {
  return {
    carrier: material.carrier,
    circuitId: material.circuitId,
    generation: material.generation,
    parentWireExpiresAt: material.parentWireExpiresAt,
    parentLocalDeadline: material.parentLocalDeadline,
    clockIdentity: material.clockIdentity,
    tailControlTranscriptDigest: material.tailControlTranscriptDigest,
    terminalAdvertisementDigest: material.terminalAdvertisementDigest,
    terminalRoutePublicKey: material.purposeTerminalPublicKey,
    finalizeKeys: material.finalizeKeys,
    sendLedger: material.sendLedger,
    receiveLedger: material.receiveLedger,
    memoryPool: material.memoryPool,
    limits,
    randomBytes: (length) => cryptoSuite.randomBytes(length)
  }
}

async function preparePurpose(t, chain, purpose, options = {}) {
  const profiles = peerNativeProfile()
  const profile = purpose === 2 ? profiles.source : profiles.registration
  const digest = privateParameters()
  let lease
  try {
    lease = await chain.source.buildTail({
      ...peerNativeBuildLimits(profile, profiles.limits.idleTimeoutMs),
      payloadParametersDigest: digest,
      terminal: chain.entry ? { advertisement260: chain.entry.advertisement } : null
    })
  } finally {
    digest.fill(0)
  }
  chain.leases.add(lease)
  const terminalLease = await chain.incoming()
  const sourceMaterial = lease.consume()
  const terminalMaterial = terminalLease.consume()
  chain.materials.push(sourceMaterial, terminalMaterial)
  const advertisement = readVerifiedPeerAdvertisement(
    verifyPeerAdvertisement(sourceMaterial.terminalAdvertisement260, {
      expectedCapabilityMask: 11,
      expectedRole: 2
    })
  )
  t.alike(advertisement.advertisementDigest32, sourceMaterial.terminalAdvertisementDigest)
  t.is(
    advertisement.maxCommands,
    profiles.limits.maxCommands,
    'the signed producer advertises the helper-derived maximum'
  )
  t.is(advertisement.maxCommands, 52)
  if (!chain.entry) {
    const advertisementWire = b4a.from(sourceMaterial.terminalAdvertisement260)
    chain.materials.push({ advertisementWire })
    chain.entry = {
      advertisement: advertisementWire,
      identity: b4a.from(advertisement.relayIdentity32),
      epoch: advertisement.epoch,
      verifyAdvertisement(wire) {
        const candidate = hashPeer(
          'hyperdht-private-routes/m3/capability-advertisement-digest/v2',
          [wire]
        )
        const valid = b4a.equals(candidate, sourceMaterial.terminalAdvertisementDigest)
        candidate.fill(0)
        return valid
      }
    }
    chain.materials.push(chain.entry)
  }
  erase(advertisement)
  const requested = peerNativePurposeLimits(profile, sourceMaterial.parentWireExpiresAt)
  const maximum = peerNativePurposeLimits(
    profiles.registration,
    terminalMaterial.parentWireExpiresAt
  )
  const sourceMaximum = peerNativePurposeLimits(
    profiles.source,
    terminalMaterial.parentWireExpiresAt
  )
  for (const name of Object.keys(maximum))
    if (sourceMaximum[name] > maximum[name]) maximum[name] = sourceMaximum[name]
  if (options.terminalLimits) Object.assign(maximum, options.terminalLimits)
  for (const material of [sourceMaterial, terminalMaterial]) {
    for (const direction of ['forward', 'reverse']) {
      const sending = (material.role === 'source') === (direction === 'forward')
      const budget = readPeerLedger(material[sending ? 'sendLedger' : 'receiveLedger'])
      t.ok(
        budget.cellsRemaining >= requested[direction + 'Cells'],
        direction + ' real residual cells fund their own child'
      )
      t.ok(
        budget.bytesRemaining >= requested[direction + 'Bytes'],
        direction + ' real residual bytes fund their own child'
      )
      t.ok(
        budget.commandsRemaining >= requested[direction + 'Commands'],
        direction + ' real residual commands fund their own child'
      )
    }
  }
  const pair = {
    sourceMaterial,
    terminalMaterial,
    profile,
    sourceBefore: readPeerLedger(sourceMaterial.sendLedger),
    terminalBefore: readPeerLedger(terminalMaterial.sendLedger),
    sourceReceivedBefore: readPeerLedger(sourceMaterial.receiveLedger),
    terminalReceivedBefore: readPeerLedger(terminalMaterial.receiveLedger),
    replay: [],
    sourceServices: null,
    terminalServices: null
  }
  const callbacks = (source) => {
    if (!options.services) return undefined
    const maxFrames =
      source && purpose === 2 ? profiles.sourceDataFrames : profiles.registrationDataFrames
    const service = createPeerSemanticServices({
      entry: chain.entry,
      maxFrames,
      maxBytes: BigInt(maxFrames) * 977n,
      maxApplicationFrames: Math.min(maxFrames, profiles.sourceDataFrames),
      applicationFrameFloor: profiles.applicationFrameFloor,
      maxStreams: source ? profile.maxStreams : profiles.registration.maxStreams,
      idleMs: profiles.limits.idleTimeoutMs,
      onSession: source && options.onSession ? (session) => options.onSession(pair, session) : null
    })
    chain.services.add(service)
    pair[source ? 'sourceServices' : 'terminalServices'] = service
    if (!source || !options.captureReplay) return service.streamCallbacks
    const wrapped = { ...service.streamCallbacks }
    for (const method of ['onAdmit', 'onDeliver']) {
      wrapped[method] = (meta, nested) => {
        const decoded = decodePeerTransport(nested)
        if (
          decoded.fields.common.streamId === 2n &&
          (decoded.messageId === ID.PEER_OPEN_V2 || decoded.messageId === ID.PEER_HANDSHAKE_V2)
        ) {
          pair.replay.push({
            method,
            meta: { ...meta, nestedDigest: b4a.from(meta.nestedDigest) },
            nested: b4a.from(nested)
          })
        }
        return service.streamCallbacks[method](meta, nested)
      }
    }
    return wrapped
  }
  const terminalCallbacks = callbacks(false)
  pair.terminal = createPeerPurposeTerminal({
    ...purposeOptions(terminalMaterial, maximum),
    terminalRouteSecretKey: terminalMaterial.purposeTerminalSecretKey,
    ...(terminalCallbacks ? { streamCallbacks: terminalCallbacks } : {})
  })
  chain.owners.add(pair.terminal)
  const ephemeral = cryptoSuite.encryptionKeyPair()
  const sourceCallbacks = callbacks(true)
  const sourceInput = {
    ...purposeOptions(sourceMaterial, requested),
    purpose,
    routeId: cryptoSuite.randomBytes(16),
    queryNonce: cryptoSuite.randomBytes(32),
    clientEphemeralPublicKey: ephemeral.publicKey,
    clientEphemeralSecret: ephemeral.secretKey,
    ...(sourceCallbacks ? { streamCallbacks: sourceCallbacks } : {})
  }
  try {
    pair.source = createPeerPurposeSource(sourceInput)
    chain.owners.add(pair.source)
  } finally {
    erase(ephemeral)
    sourceInput.routeId.fill(0)
    sourceInput.queryNonce.fill(0)
  }
  pair.activate = async () => {
    const active = [
      pair.source.whenActive(),
      pair.terminal.whenActive(),
      ...(pair.sourceServices
        ? [
            pair.sourceServices.attachOwner(pair.source),
            pair.terminalServices.attachOwner(pair.terminal)
          ]
        : [])
    ]
    pair.terminal.start()
    pair.source.start()
    await Promise.all(active)
  }
  pair.close = async () => {
    if (pair.sourceServices) pair.sourceServices.destroy()
    if (pair.terminalServices) pair.terminalServices.destroy()
    pair.source.destroy()
    pair.terminal.destroy()
    await Promise.all([
      pair.source.whenClosed(),
      pair.terminal.whenClosed(),
      lease.revoke(),
      terminalLease.revoke()
    ])
    for (const row of pair.replay) {
      row.meta.nestedDigest.fill(0)
      row.nested.fill(0)
    }
    pair.replay.length = 0
  }
  return pair
}

for (const purpose of [2, 3]) {
  test(`native production purpose${purpose} admits its first OFFER through three real relays`, async (t) => {
    t.timeout(120_000)
    const chain = await nativeChain(t)
    const pair = await preparePurpose(t, chain, purpose)
    await pair.activate()
    const sourceRoute = pair.source.route()
    const terminalRoute = pair.terminal.route()
    try {
      t.is(terminalRoute.purpose, purpose, 'terminal learns purpose from the authenticated OFFER')
      t.alike(sourceRoute.routeId, terminalRoute.routeId)
      t.alike(sourceRoute.purposeDigest, terminalRoute.purposeDigest)
      t.alike(sourceRoute.finalTranscriptDigest, terminalRoute.finalTranscriptDigest)
      t.alike(sourceRoute.limits, terminalRoute.limits, 'both ends admit identical limits')
      t.alike(
        sourceRoute.limits,
        peerNativePurposeLimits(pair.profile, sourceRoute.wireExpiresAt),
        'the complete production profile survives negotiation without downsizing'
      )
      t.is(
        readPeerLedger(pair.sourceMaterial.sendLedger).commandsSpent,
        pair.sourceBefore.commandsSpent
      )
      t.is(
        readPeerLedger(pair.terminalMaterial.sendLedger).commandsSpent,
        pair.terminalBefore.commandsSpent + 1
      )
      t.is(
        readPeerLedger(pair.terminalMaterial.receiveLedger).commandsSpent,
        pair.terminalReceivedBefore.commandsSpent
      )
      t.is(
        readPeerLedger(pair.sourceMaterial.receiveLedger).commandsSpent,
        pair.sourceReceivedBefore.commandsSpent
      )
    } finally {
      erase(sourceRoute)
      erase(terminalRoute)
      await pair.close()
    }
  })
}

test('native M17 real services admit all sixteen OPEN/ACTIVATE pairs and fund lifetime closure', async (t) => {
  t.timeout(120_000)
  const chain = await nativeChain(t)
  const profiles = peerNativeProfile()
  const keyPair = cryptoSuite.keyPair()
  chain.materials.push(keyPair)
  const destinations = []
  const registration = await preparePurpose(t, chain, 3, {
    services: true,
    captureReplay: true,
    onSession(pair, session) {
      const endpoint = createPeerEndpointController({ owner: pair.source, session, keyPair })
      chain.endpoints.add(endpoint)
      destinations.push(endpoint)
    }
  })
  await registration.activate()
  const handle = registration.sourceServices.register({
    destinationNoiseKey: keyPair.publicKey,
    advertisement: registration.sourceMaterial.terminalAdvertisement260,
    maxFrames: profiles.registrationDataFrames,
    maxBytes: BigInt(profiles.registrationDataFrames) * 977n,
    idleMs: profiles.limits.idleTimeoutMs
  })
  const descriptor = await handle.whenRegistered()
  chain.materials.push({ descriptor })
  let allocationCommands = 0
  for (let index = 0; index < 16; index++) {
    const pair = await preparePurpose(t, chain, 2, { services: true })
    await pair.activate()
    const before = readPeerLedger(registration.sourceMaterial.sendLedger).commandsSpent
    const session = pair.sourceServices.openSession({
      descriptor,
      maxFrames: profiles.applicationFrameFloor,
      maxBytes: BigInt(profiles.applicationFrameFloor) * 977n,
      idleMs: profiles.limits.idleTimeoutMs
    })
    const applicationKey = cryptoSuite.keyPair()
    const client = createPeerEndpointController({
      owner: pair.source,
      session,
      keyPair: applicationKey,
      remotePublicKey: keyPair.publicKey
    })
    erase(applicationKey)
    chain.endpoints.add(client)
    await client.whenOpen()
    const destination = destinations[index]
    await destination.whenOpen()
    const after = readPeerLedger(registration.sourceMaterial.sendLedger).commandsSpent
    t.is(after - before, 2, 'actual incoming OPEN and PRIVATE_ACTIVATE each allocate once')
    allocationCommands += after - before
    if (index === 0) {
      // Replay only bytes/meta previously delivered by the authentic owner. This proves
      // semantic/reliable identity-cache handling, not an injected UDP retransmission.
      for (const row of registration.replay)
        registration.sourceServices.streamCallbacks[row.method](row.meta, row.nested)
      t.is(readPeerLedger(registration.sourceMaterial.sendLedger).commandsSpent, after)
      t.is(destinations.length, 1, 'exact accepted retries do not allocate another application')
    }
    const received = [[], []]
    client.stream.on('data', (data) => received[0].push(b4a.from(data)))
    destination.stream.on('data', (data) => received[1].push(b4a.from(data)))
    const forward = b4a.alloc(73 + index, index + 1)
    const reverse = b4a.alloc(109 + index, index + 31)
    client.stream.end(forward)
    destination.stream.end(reverse)
    await Promise.all([client.finished(), destination.finished()])
    t.alike(b4a.concat(received[0]), reverse)
    t.alike(b4a.concat(received[1]), forward)
    t.is(
      readPeerLedger(registration.sourceMaterial.sendLedger).commandsSpent,
      after + 1,
      'the first application tombstone is funded once'
    )
    client.destroy()
    destination.destroy()
    t.is(readPeerLedger(registration.sourceMaterial.sendLedger).commandsSpent, after + 1)
    await pair.close()
  }
  t.is(allocationCommands, 32)
  t.is(destinations.length, 16)
  t.is(registration.sourceServices.diagnostics().registration.remainingStreams, 0)
  t.is(
    readPeerLedger(registration.sourceMaterial.receiveLedger).commandsSpent,
    registration.sourceReceivedBefore.commandsSpent,
    'destination allocations never debit the incoming branch'
  )
  const closureStart = {
    source: chain.attempts.source.length,
    terminal: chain.attempts.terminal.length
  }
  await registration.close()
  t.is(
    readPeerLedger(registration.sourceMaterial.sendLedger).commandsSpent,
    registration.sourceBefore.commandsSpent + profiles.registration.budget.purpose.forward.commands,
    'purpose50 funds all17 stream tombstones and the route tombstone'
  )
  t.is(
    readPeerLedger(registration.terminalMaterial.sendLedger).commandsSpent,
    registration.terminalBefore.commandsSpent +
      profiles.registration.budget.purpose.reverse.commands
  )
  t.is(
    registration.sourceBefore.commandsAllocated + 1,
    profiles.limits.maxCommands,
    'the borrowed ordinary parent excludes the native sibling closure partition'
  )
  for (const side of ['source', 'terminal']) {
    const ordinary = new Set(
      chain.attempts[side]
        .slice(0, closureStart[side])
        .filter((event) => event.owner.kind === 'circuit')
        .map((event) => event.owner.ledger)
    )
    const closure = chain.attempts[side]
      .slice(closureStart[side])
      .filter((event) => event.owner.kind === 'closure')
    t.alike(
      closure[0] && {
        charged: closure[0].owner.charged,
        ordinal: closure[0].owner.ordinal,
        bytes: closure[0].bytes
      },
      { charged: true, ordinal: 1, bytes: 1200 },
      side + ' physically closes through a genuinely charged native partition'
    )
    for (const event of closure) {
      t.absent(
        ordinary.has(event.owner.ledger),
        'physical closure cannot debit a purpose partition'
      )
      t.ok(event.owner.ordinal <= 10, 'physical closure stays inside its native cell reservation')
    }
  }
  const spent = readPeerLedger(registration.sourceMaterial.sendLedger).commandsSpent
  t.exception(() => registration.source.admitOperation(ID.PEER_CLOSE_V2), { code: 'ERR_DESTROYED' })
  t.is(readPeerLedger(registration.sourceMaterial.sendLedger).commandsSpent, spent)
})

for (const direction of ['forward', 'reverse']) {
  test(`native purpose rejects underfunded ${direction} admission before registration or application effects`, async (t) => {
    t.timeout(120_000)
    const chain = await nativeChain(t)
    const budget = peerNativeProfile().registration.budget.purpose
    let applications = 0
    const pair = await preparePurpose(t, chain, 3, {
      services: true,
      terminalLimits: { [direction + 'Commands']: budget[direction].commands - 1 },
      onSession() {
        applications++
      }
    })
    await t.exception(pair.activate(), /authentication|quota|unavailable|destroyed/i)
    t.is(applications, 0)
    t.is(pair.sourceServices.diagnostics().streams, 0)
    t.is(pair.terminalServices.diagnostics().registration, null)
    await pair.close()
    t.is(
      readPeerLedger(pair.terminalMaterial.sendLedger).commandsSpent,
      pair.terminalBefore.commandsSpent,
      'rejection allocates no purpose or semantics; native closure has separate authority'
    )
  })
}
