'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { PrivateRouteError } = require('../../lib/private/errors')
const {
  BRANCH_CLASS,
  CAPACITY_CLASS,
  RELAY_CAPABILITY,
  ROLE,
  roleForIdentity
} = require('../../lib/private/protocol')
const {
  deriveM3DhtNodeId,
  digestRelayCapabilityAdvertisement,
  encodeCanonicalEndpoint,
  encodeRelayCapabilityAdvertisement,
  providerServicePolicyForCapabilities,
  signRelayCapabilityAdvertisement
} = require('../../lib/private/relay-capability')
const {
  MAX_RELAY_CANDIDATE_IDENTITIES,
  RelayCandidateDirectory,
  abortRelayPathReservation,
  commitRelayPathReservation,
  consumeSealedRelayCandidateDirectory,
  consumeSelectedRelayEvidence,
  createRelayCandidateDirectorySink,
  destroySealedRelayCandidateDirectory,
  kInspectRelayCandidateDirectory,
  revokeRelayCandidateDirectorySink,
  sealRelayCandidateDirectorySink,
  splitRelayPathReservation,
  takeRelayPathReservation
} = require('../../lib/private/relay-candidate-directory')

const NOW = 1_000_000n

function expectCode(t, fn, code) {
  let error = null
  try {
    fn()
  } catch (err) {
    error = err
  }
  t.ok(error instanceof PrivateRouteError)
  t.is(error && error.code, code)
}

function trackedDirectoryModule() {
  const modulePath = require.resolve('../../lib/private/relay-candidate-directory')
  const moduleCacheKey =
    require.cache[modulePath] === undefined
      ? Object.keys(require.cache).find((key) => key.endsWith(modulePath))
      : modulePath
  const cached = require.cache[moduleCacheKey]
  const BufferConstructor = b4a.alloc(0).constructor
  const originalB4a = b4a.allocUnsafeSlow
  const originalBuffer = BufferConstructor.allocUnsafeSlow
  const allocations = []
  let tracking = false
  let allocation = 0
  let failAt = null
  const allocate = (size) => {
    if (tracking) allocation++
    if (tracking && allocation === failAt) throw new Error('injected allocation failure')
    const value = Reflect.apply(originalBuffer, BufferConstructor, [size])
    if (tracking) allocations.push(value)
    return value
  }
  b4a.allocUnsafeSlow = allocate
  BufferConstructor.allocUnsafeSlow = allocate
  let fresh
  try {
    delete require.cache[moduleCacheKey]
    fresh = require(modulePath)
  } finally {
    b4a.allocUnsafeSlow = originalB4a
    BufferConstructor.allocUnsafeSlow = originalBuffer
    delete require.cache[moduleCacheKey]
    if (cached) require.cache[moduleCacheKey] = cached
  }
  return {
    fresh,
    start(position) {
      allocations.length = 0
      allocation = 0
      failAt = position
      tracking = true
    },
    take() {
      tracking = false
      failAt = null
      return allocations.splice(0)
    }
  }
}

function countedVerificationDirectoryModule() {
  const modulePath = require.resolve('../../lib/private/relay-candidate-directory')
  const relayPath = require.resolve('../../lib/private/relay-capability')
  const cacheKey = (path) =>
    require.cache[path] === undefined
      ? Object.keys(require.cache).find((key) => key.endsWith(path))
      : path
  const moduleCacheKey = cacheKey(modulePath)
  const relayCacheKey = cacheKey(relayPath)
  const cached = require.cache[moduleCacheKey]
  const relayCache = require.cache[relayCacheKey]
  const originalRelay = relayCache.exports
  let decodeCalls = 0
  let digestCalls = 0
  relayCache.exports = {
    ...originalRelay,
    decodeRelayCapabilityAdvertisement(...args) {
      decodeCalls++
      return originalRelay.decodeRelayCapabilityAdvertisement(...args)
    },
    digestRelayCapabilityAdvertisement(...args) {
      digestCalls++
      return originalRelay.digestRelayCapabilityAdvertisement(...args)
    }
  }
  let fresh
  try {
    delete require.cache[moduleCacheKey]
    fresh = require(modulePath)
  } finally {
    relayCache.exports = originalRelay
    delete require.cache[moduleCacheKey]
    if (cached) require.cache[moduleCacheKey] = cached
  }
  return {
    fresh,
    counts: () => ({ decodeCalls, digestCalls })
  }
}

function seed(value) {
  return b4a.alloc(32, value)
}

function identityFor(role, ordinal) {
  let found = -1
  for (let value = 1; value < 256; value++) {
    const pair = cryptoSuite.keyPair(seed(value))
    if (roleForIdentity(pair.publicKey) !== role) continue
    found++
    if (found === ordinal) return pair
  }
  throw new Error('missing deterministic identity')
}

function endpoint(index, port = 40_000 + index) {
  return encodeCanonicalEndpoint({
    addressFamily: 4,
    addressBytes: b4a.from([198, 18, index, 1]),
    port
  })
}

function candidate(role, ordinal, index, overrides = {}) {
  const {
    endpointBytes = endpoint(index),
    validationNow = NOW,
    ...advertisementOverrides
  } = overrides
  const signer = identityFor(role, ordinal)
  const route = cryptoSuite.encryptionKeyPair(seed(128 + index))
  const reachableEndpoint = endpointBytes
  const capabilityMask =
    role === ROLE.SAFETY
      ? RELAY_CAPABILITY.CIRCUIT_RELAY_V1
      : RELAY_CAPABILITY.CIRCUIT_RELAY_V1 | RELAY_CAPABILITY.DHT_EXIT_V1
  const value = {
    relayIdentity: signer.publicKey,
    currentDhtNodeId: deriveM3DhtNodeId(reachableEndpoint),
    reachableEndpoint,
    routeEncryptionPublicKey: route.publicKey,
    capabilityMask,
    minimumProtocolVersion: 1,
    maximumProtocolVersion: 1,
    cellSize: 1200,
    maxCellPayload: 1146,
    contextEnvelopeSize: 1101,
    routeFrameSize: 1100,
    maxRoutePayload: 1073,
    datagramReplayWindow: 64,
    maxConcurrentCircuits: 32,
    capacityClass: CAPACITY_CLASS.MEDIUM,
    maxCellsPerCircuit: 10_000,
    maxBytesPerCircuit: 10_000_000,
    maxCommandsPerCircuit: 256,
    idleTimeoutMs: 30_000,
    maxQueuedBytes: 262_144,
    epoch: 1n,
    issuedAtMs: NOW,
    expiresAtMs: NOW + 30_000n,
    providerServicePolicyEntries: providerServicePolicyForCapabilities(capabilityMask),
    ...advertisementOverrides
  }
  const signed = signRelayCapabilityAdvertisement(value, signer.secretKey)
  const canonicalBytes = encodeRelayCapabilityAdvertisement(signed)
  return {
    canonicalBytes,
    digest: digestRelayCapabilityAdvertisement(canonicalBytes, { now: validationNow }),
    identity: b4a.from(value.relayIdentity),
    canonicalEndpointBytes: b4a.from(value.reachableEndpoint),
    routePublicKey: b4a.from(value.routeEncryptionPublicKey),
    role,
    capabilityMask,
    epoch: value.epoch,
    issuedAt: value.issuedAtMs,
    expiresAt: value.expiresAtMs
  }
}

function fakeClock(start = NOW) {
  let wall = start
  let monotonic = 0n
  return {
    wallNow: () => wall,
    monotonicNow: () => monotonic,
    advance(value) {
      wall += BigInt(value)
      monotonic += BigInt(value)
    },
    jumpWall(value) {
      wall += BigInt(value)
    }
  }
}

function callbackClock(start = NOW) {
  let wall = start
  let monotonic = 0n
  let callback = null
  return {
    wallNow: () => wall,
    monotonicNow() {
      const current = callback
      callback = null
      if (current !== null) current()
      return monotonic
    },
    setCallback(value) {
      callback = value
    },
    setWall(value) {
      wall = BigInt(value)
    }
  }
}

function fixture(extraSafety = 1, extraExits = 1, clock = fakeClock()) {
  const guard = candidate(ROLE.SAFETY, 0, 1)
  const records = []
  for (let i = 0; i < 2 + extraSafety; i++) records.push(candidate(ROLE.SAFETY, i + 1, i + 2))
  for (let i = 0; i < 2 + extraExits; i++) records.push(candidate(ROLE.PRIVATE, i, i + 40))
  const scope = {
    guardIdentity: guard.identity,
    guardEndpoint: guard.canonicalEndpointBytes,
    guardAdvertisementDigest: guard.digest,
    guardEpoch: guard.epoch,
    guardExpiresAt: guard.expiresAt
  }
  return { clock, guard, records, scope }
}

function longFixture(expiresAt, extraSafety = 2, extraExits = 1, clock = fakeClock()) {
  const advertisementTime = { expiresAtMs: expiresAt }
  const guard = candidate(ROLE.SAFETY, 0, 1, advertisementTime)
  const records = []
  for (let i = 0; i < 2 + extraSafety; i++) {
    records.push(candidate(ROLE.SAFETY, i + 1, i + 2, advertisementTime))
  }
  for (let i = 0; i < 2 + extraExits; i++) {
    records.push(candidate(ROLE.PRIVATE, i, i + 40, advertisementTime))
  }
  return {
    clock,
    guard,
    records,
    scope: {
      guardIdentity: guard.identity,
      guardEndpoint: guard.canonicalEndpointBytes,
      guardAdvertisementDigest: guard.digest,
      guardEpoch: guard.epoch,
      guardExpiresAt: guard.expiresAt
    }
  }
}

function install(input) {
  const sink = createRelayCandidateDirectorySink({
    wallNow: input.clock.wallNow,
    monotonicNow: input.clock.monotonicNow
  })
  const token = sealRelayCandidateDirectorySink(sink, input.records, input.scope)
  return consumeSealedRelayCandidateDirectory(token)
}

function consumeInitial(transaction, split, generations = [1n, 1n]) {
  return [
    consumeSelectedRelayEvidence(split.lookup.middle, {
      transaction,
      branchClass: BRANCH_CLASS.LOOKUP,
      position: 'middle',
      generation: generations[0]
    }),
    consumeSelectedRelayEvidence(split.lookup.exit, {
      transaction,
      branchClass: BRANCH_CLASS.LOOKUP,
      position: 'exit',
      generation: generations[0]
    }),
    consumeSelectedRelayEvidence(split.announce.middle, {
      transaction,
      branchClass: BRANCH_CLASS.ANNOUNCE,
      position: 'middle',
      generation: generations[1]
    }),
    consumeSelectedRelayEvidence(split.announce.exit, {
      transaction,
      branchClass: BRANCH_CLASS.ANNOUNCE,
      position: 'exit',
      generation: generations[1]
    })
  ]
}

function installInitial(directory, generations = [1n, 1n]) {
  const transaction = takeRelayPathReservation(
    directory.reserveInitialPair({
      lookupGeneration: generations[0],
      announceGeneration: generations[1]
    })
  )
  const evidence = consumeInitial(transaction, splitRelayPathReservation(transaction), generations)
  commitRelayPathReservation(transaction)
  return evidence
}

test('candidate transfer owns bytes and never reads dialing authority getters', (t) => {
  const input = fixture()
  const reads = []
  for (const record of input.records) {
    for (const name of ['host', 'port', 'send', 'socket', 'discover']) {
      Object.defineProperty(record, name, {
        enumerable: true,
        get() {
          reads.push(name)
          throw new Error('dialing getter was read')
        }
      })
    }
  }
  const original = b4a.from(input.records[0].canonicalBytes)
  const directory = install(input)
  input.records[0].canonicalBytes.fill(0)
  input.records[0].digest.fill(0)
  t.alike(reads, [])
  t.ok(Object.isFrozen(directory))
  t.alike(Object.keys(directory), [])
  t.alike(Object.getOwnPropertyNames(RelayCandidateDirectory.prototype).sort(), [
    'constructor',
    'destroy',
    'reserveInitialPair',
    'reserveReplacement',
    'resume',
    'retainForSuspend'
  ])
  const reservation = directory.reserveInitialPair({
    lookupGeneration: 1n,
    announceGeneration: 1n
  })
  const transaction = takeRelayPathReservation(reservation)
  const split = splitRelayPathReservation(transaction)
  const evidence = consumeInitial(transaction, split)
  t.ok(evidence.some((entry) => b4a.equals(entry.canonicalAdvertisement, original)))
  for (const entry of evidence) {
    t.alike(
      Object.keys(entry).sort(),
      [
        'advertisementDigest',
        'branchClass',
        'canonicalAdvertisement',
        'generation',
        'position',
        'role'
      ].sort()
    )
    t.absent('host' in entry)
    t.absent('port' in entry)
    t.absent('send' in entry)
    t.absent('socket' in entry)
  }
  commitRelayPathReservation(transaction)
  t.ok(evidence.every((entry) => entry.canonicalAdvertisement.every((byte) => byte === 0)))
  directory.destroy()
})

test('sink and sealed token are opaque, one-shot, bounded, and failure-atomic', (t) => {
  const input = fixture()
  const sink = createRelayCandidateDirectorySink({
    wallNow: input.clock.wallNow,
    monotonicNow: input.clock.monotonicNow
  })
  t.ok(Object.isFrozen(sink))
  t.alike(Reflect.ownKeys(sink), [])
  const token = sealRelayCandidateDirectorySink(sink, input.records, input.scope)
  t.ok(Object.isFrozen(token))
  t.alike(Reflect.ownKeys(token), [])
  expectCode(t, () => sealRelayCandidateDirectorySink(sink, [], input.scope), 'ERR_REPLAY')
  const directory = consumeSealedRelayCandidateDirectory(token)
  expectCode(t, () => consumeSealedRelayCandidateDirectory(token), 'ERR_REPLAY')
  directory.destroy()

  const revoked = createRelayCandidateDirectorySink({
    wallNow: input.clock.wallNow,
    monotonicNow: input.clock.monotonicNow
  })
  revokeRelayCandidateDirectorySink(revoked)
  expectCode(t, () => sealRelayCandidateDirectorySink(revoked, [], input.scope), 'ERR_REPLAY')

  const doomed = createRelayCandidateDirectorySink({
    wallNow: input.clock.wallNow,
    monotonicNow: input.clock.monotonicNow
  })
  const doomedToken = sealRelayCandidateDirectorySink(doomed, input.records, input.scope)
  destroySealedRelayCandidateDirectory(doomedToken)
  expectCode(t, () => consumeSealedRelayCandidateDirectory(doomedToken), 'ERR_REPLAY')

  const tooMany = []
  for (let i = 0; i < MAX_RELAY_CANDIDATE_IDENTITIES + 1; i++) {
    tooMany.push(candidate(i & 1 ? ROLE.PRIVATE : ROLE.SAFETY, i >> 1, 70 + i))
  }
  const overfull = createRelayCandidateDirectorySink({
    wallNow: input.clock.wallNow,
    monotonicNow: input.clock.monotonicNow
  })
  expectCode(t, () => sealRelayCandidateDirectorySink(overfull, tooMany, input.scope), 'ERR_REPLAY')
  t.ok(tooMany.every((record) => record.identity.some((byte) => byte !== 0)))
})

test('initial reservation is atomic, exactly bound, abortable, and committed once', (t) => {
  const directory = install(fixture())
  expectCode(
    t,
    () => directory.reserveInitialPair({ lookupGeneration: 0n, announceGeneration: 1n }),
    'ERR_INCOMPATIBLE_RELAY'
  )
  const reservation = directory.reserveInitialPair({
    lookupGeneration: 7n,
    announceGeneration: 9n
  })
  t.alike(Reflect.ownKeys(reservation), [])
  expectCode(
    t,
    () => directory.reserveInitialPair({ lookupGeneration: 8n, announceGeneration: 10n }),
    'ERR_REPLAY'
  )
  const transaction = takeRelayPathReservation(reservation)
  t.alike(Reflect.ownKeys(transaction), [])
  expectCode(t, () => takeRelayPathReservation(reservation), 'ERR_REPLAY')
  const split = splitRelayPathReservation(transaction)
  t.ok(Object.isFrozen(split))
  t.ok(Object.isFrozen(split.lookup.middle))
  expectCode(t, () => splitRelayPathReservation(transaction), 'ERR_REPLAY')
  expectCode(
    t,
    () =>
      consumeSelectedRelayEvidence(split.lookup.middle, {
        transaction,
        branchClass: BRANCH_CLASS.ANNOUNCE,
        position: 'middle',
        generation: 7n
      }),
    'ERR_REPLAY'
  )
  const evidence = consumeInitial(transaction, split, [7n, 9n])
  expectCode(
    t,
    () =>
      consumeSelectedRelayEvidence(split.lookup.middle, {
        transaction,
        branchClass: BRANCH_CLASS.LOOKUP,
        position: 'middle',
        generation: 7n
      }),
    'ERR_REPLAY'
  )
  abortRelayPathReservation(transaction)
  t.ok(evidence.every((entry) => entry.advertisementDigest.every((byte) => byte === 0)))
  expectCode(t, () => abortRelayPathReservation(transaction), 'ERR_REPLAY')

  const retry = directory.reserveInitialPair({ lookupGeneration: 7n, announceGeneration: 9n })
  const retryTransaction = takeRelayPathReservation(retry)
  consumeInitial(retryTransaction, splitRelayPathReservation(retryTransaction), [7n, 9n])
  commitRelayPathReservation(retryTransaction)
  expectCode(
    t,
    () => directory.reserveInitialPair({ lookupGeneration: 7n, announceGeneration: 10n }),
    'ERR_REPLAY'
  )
  directory.destroy()
})

test('commit requires every evidence capability and replacement excludes both live paths', (t) => {
  // Only one spare middle/exit pair remains after the two live branches.
  const directory = install(fixture())
  const initial = takeRelayPathReservation(
    directory.reserveInitialPair({ lookupGeneration: 1n, announceGeneration: 1n })
  )
  const selections = splitRelayPathReservation(initial)
  consumeSelectedRelayEvidence(selections.lookup.middle, {
    transaction: initial,
    branchClass: BRANCH_CLASS.LOOKUP,
    position: 'middle',
    generation: 1n
  })
  expectCode(t, () => commitRelayPathReservation(initial), 'ERR_REPLAY')
  consumeSelectedRelayEvidence(selections.lookup.exit, {
    transaction: initial,
    branchClass: BRANCH_CLASS.LOOKUP,
    position: 'exit',
    generation: 1n
  })
  consumeSelectedRelayEvidence(selections.announce.middle, {
    transaction: initial,
    branchClass: BRANCH_CLASS.ANNOUNCE,
    position: 'middle',
    generation: 1n
  })
  consumeSelectedRelayEvidence(selections.announce.exit, {
    transaction: initial,
    branchClass: BRANCH_CLASS.ANNOUNCE,
    position: 'exit',
    generation: 1n
  })
  commitRelayPathReservation(initial)

  const replacement = takeRelayPathReservation(
    directory.reserveReplacement({ branchClass: BRANCH_CLASS.LOOKUP, generation: 2n })
  )
  const selected = splitRelayPathReservation(replacement)
  t.is(selected.branchClass, BRANCH_CLASS.LOOKUP)
  consumeSelectedRelayEvidence(selected.middle, {
    transaction: replacement,
    branchClass: BRANCH_CLASS.LOOKUP,
    position: 'middle',
    generation: 2n
  })
  consumeSelectedRelayEvidence(selected.exit, {
    transaction: replacement,
    branchClass: BRANCH_CLASS.LOOKUP,
    position: 'exit',
    generation: 2n
  })
  commitRelayPathReservation(replacement)
  expectCode(
    t,
    () => directory.reserveReplacement({ branchClass: BRANCH_CLASS.LOOKUP, generation: 2n }),
    'ERR_REPLAY'
  )
  directory.destroy()
})

test('identity, endpoint /24, role, capability, and cross-branch diversity fail closed', (t) => {
  const input = fixture(0, 0)
  const sameSubnet = encodeCanonicalEndpoint({
    addressFamily: 4,
    addressBytes: b4a.from([198, 18, 2, 2]),
    port: 49_999
  })
  input.records[1] = candidate(ROLE.SAFETY, 2, 30, { endpointBytes: sameSubnet })
  const directory = install(input)
  expectCode(
    t,
    () => directory.reserveInitialPair({ lookupGeneration: 1n, announceGeneration: 1n }),
    'ERR_INCOMPATIBLE_RELAY'
  )
  directory.destroy()
})

test('suspend retains only sealed evidence and resume revalidates exact expiry', (t) => {
  const input = fixture()
  const directory = install(input)
  directory.retainForSuspend()
  expectCode(
    t,
    () => directory.reserveInitialPair({ lookupGeneration: 1n, announceGeneration: 1n }),
    'ERR_INCOMPATIBLE_RELAY'
  )
  directory.resume()
  const reservation = directory.reserveInitialPair({
    lookupGeneration: 1n,
    announceGeneration: 1n
  })
  abortRelayPathReservation(takeRelayPathReservation(reservation))
  directory.retainForSuspend()
  input.clock.advance(30_000)
  expectCode(t, () => directory.resume(), 'ERR_INCOMPATIBLE_RELAY')
  const observed = directory[kInspectRelayCandidateDirectory]()
  t.is(observed.identityCount, 0)
  directory.destroy()
})

test('wall rollback clears directory ownership and no generation or callback survives destroy', (t) => {
  const input = fixture()
  const directory = install(input)
  input.clock.advance(40_000)
  // Forward expiry clears on the next operation before any reservation publishes.
  expectCode(
    t,
    () => directory.reserveInitialPair({ lookupGeneration: 1n, announceGeneration: 1n }),
    'ERR_INCOMPATIBLE_RELAY'
  )
  directory.destroy()
  const observed = directory[kInspectRelayCandidateDirectory]()
  t.alike(observed, {
    destroyed: true,
    identityCount: 0,
    byteBufferCount: 0,
    digestCount: 0,
    timerCount: 0,
    callbackCount: 0,
    generationRecordCount: 0,
    quarantineCount: 0,
    pendingCount: 0
  })

  const rollback = fixture(1, 1, fakeClock(NOW + 100_000n))
  for (const record of rollback.records) {
    record.issuedAt = NOW + 100_000n
    record.expiresAt = NOW + 130_000n
  }
  // Use freshly signed records valid at the later clock.
  rollback.records = [
    candidate(ROLE.SAFETY, 1, 2, {
      issuedAtMs: NOW + 100_000n,
      expiresAtMs: NOW + 130_000n,
      validationNow: NOW + 100_000n
    }),
    candidate(ROLE.SAFETY, 2, 3, {
      issuedAtMs: NOW + 100_000n,
      expiresAtMs: NOW + 130_000n,
      validationNow: NOW + 100_000n
    }),
    candidate(ROLE.SAFETY, 3, 4, {
      issuedAtMs: NOW + 100_000n,
      expiresAtMs: NOW + 130_000n,
      validationNow: NOW + 100_000n
    }),
    candidate(ROLE.PRIVATE, 0, 40, {
      issuedAtMs: NOW + 100_000n,
      expiresAtMs: NOW + 130_000n,
      validationNow: NOW + 100_000n
    }),
    candidate(ROLE.PRIVATE, 1, 41, {
      issuedAtMs: NOW + 100_000n,
      expiresAtMs: NOW + 130_000n,
      validationNow: NOW + 100_000n
    }),
    candidate(ROLE.PRIVATE, 2, 42, {
      issuedAtMs: NOW + 100_000n,
      expiresAtMs: NOW + 130_000n,
      validationNow: NOW + 100_000n
    })
  ]
  rollback.scope.guardExpiresAt = NOW + 130_000n
  const rolled = install(rollback)
  rollback.clock.jumpWall(-30_001)
  expectCode(
    t,
    () => rolled.reserveInitialPair({ lookupGeneration: 1n, announceGeneration: 1n }),
    'ERR_INCOMPATIBLE_RELAY'
  )
  t.is(rolled[kInspectRelayCandidateDirectory]().identityCount, 0)
  rolled.destroy()
})

test('same-identity higher epoch replaces old evidence and equivocation removes it', (t) => {
  const input = fixture()
  const old = input.records[0]
  const replacement = candidate(ROLE.SAFETY, 1, 20, { epoch: 2n })
  input.records.push(replacement)
  const directory = install(input)
  const transaction = takeRelayPathReservation(
    directory.reserveInitialPair({ lookupGeneration: 1n, announceGeneration: 1n })
  )
  const evidence = consumeInitial(transaction, splitRelayPathReservation(transaction))
  t.ok(evidence.some((entry) => b4a.equals(entry.advertisementDigest, replacement.digest)))
  t.absent(evidence.some((entry) => b4a.equals(entry.advertisementDigest, old.digest)))
  abortRelayPathReservation(transaction)
  directory.destroy()

  const conflictInput = fixture(0, 0)
  conflictInput.records.push(candidate(ROLE.SAFETY, 1, 21, { epoch: 1n }))
  const conflicted = install(conflictInput)
  expectCode(
    t,
    () => conflicted.reserveInitialPair({ lookupGeneration: 1n, announceGeneration: 1n }),
    'ERR_INCOMPATIBLE_RELAY'
  )
  conflicted.destroy()
})

test('partial allocation and reentrant or throwing clocks clear without publication', (t) => {
  const tracked = trackedDirectoryModule()
  const input = fixture()
  const source = b4a.from(input.records[0].canonicalBytes)
  const scopeStart = input.records.length * 4
  for (const failureAt of [2, 3, 4, scopeStart + 2, scopeStart + 3]) {
    const sink = tracked.fresh.createRelayCandidateDirectorySink({
      wallNow: input.clock.wallNow,
      monotonicNow: input.clock.monotonicNow
    })
    tracked.start(failureAt)
    expectCode(
      t,
      () => tracked.fresh.sealRelayCandidateDirectorySink(sink, input.records, input.scope),
      'ERR_REPLAY'
    )
    const allocations = tracked.take()
    t.ok(allocations.length > 0)
    t.ok(allocations.every((value) => value.every((byte) => byte === 0)))
    t.alike(input.records[0].canonicalBytes, source)
    expectCode(
      t,
      () => tracked.fresh.sealRelayCandidateDirectorySink(sink, input.records, input.scope),
      'ERR_REPLAY'
    )
  }

  let reentrantSink = null
  reentrantSink = tracked.fresh.createRelayCandidateDirectorySink({
    wallNow() {
      tracked.fresh.sealRelayCandidateDirectorySink(reentrantSink, input.records, input.scope)
      return NOW
    },
    monotonicNow: input.clock.monotonicNow
  })
  expectCode(
    t,
    () => tracked.fresh.sealRelayCandidateDirectorySink(reentrantSink, input.records, input.scope),
    'ERR_REPLAY'
  )
  t.alike(input.records[0].canonicalBytes, source)

  let directory = null
  const reentrantClock = fakeClock()
  const hostile = fixture(1, 1, {
    wallNow() {
      if (directory !== null) directory.destroy()
      return reentrantClock.wallNow()
    },
    monotonicNow: reentrantClock.monotonicNow
  })
  directory = install(hostile)
  expectCode(
    t,
    () => directory.reserveInitialPair({ lookupGeneration: 1n, announceGeneration: 1n }),
    'ERR_INCOMPATIBLE_RELAY'
  )
  t.is(directory[kInspectRelayCandidateDirectory]().identityCount, 0)

  let throwNow = false
  const throwingBase = fakeClock()
  const throwing = fixture(1, 1, {
    wallNow() {
      if (throwNow) throw new Error('injected clock failure')
      return throwingBase.wallNow()
    },
    monotonicNow: throwingBase.monotonicNow
  })
  const throwingDirectory = install(throwing)
  throwingDirectory.retainForSuspend()
  throwNow = true
  expectCode(t, () => throwingDirectory.resume(), 'ERR_INCOMPATIBLE_RELAY')
  t.is(throwingDirectory[kInspectRelayCandidateDirectory]().identityCount, 0)
  throwingDirectory.destroy()
})

test('concurrent opposite replacements revalidate diversity at commit', (t) => {
  const directory = install(fixture())
  installInitial(directory)

  const lookup = takeRelayPathReservation(
    directory.reserveReplacement({ branchClass: BRANCH_CLASS.LOOKUP, generation: 2n })
  )
  const announce = takeRelayPathReservation(
    directory.reserveReplacement({ branchClass: BRANCH_CLASS.ANNOUNCE, generation: 2n })
  )
  const lookupSelections = splitRelayPathReservation(lookup)
  const announceSelections = splitRelayPathReservation(announce)
  const lookupEvidence = [
    consumeSelectedRelayEvidence(lookupSelections.middle, {
      transaction: lookup,
      branchClass: BRANCH_CLASS.LOOKUP,
      position: 'middle',
      generation: 2n
    }),
    consumeSelectedRelayEvidence(lookupSelections.exit, {
      transaction: lookup,
      branchClass: BRANCH_CLASS.LOOKUP,
      position: 'exit',
      generation: 2n
    })
  ]
  const announceEvidence = [
    consumeSelectedRelayEvidence(announceSelections.middle, {
      transaction: announce,
      branchClass: BRANCH_CLASS.ANNOUNCE,
      position: 'middle',
      generation: 2n
    }),
    consumeSelectedRelayEvidence(announceSelections.exit, {
      transaction: announce,
      branchClass: BRANCH_CLASS.ANNOUNCE,
      position: 'exit',
      generation: 2n
    })
  ]
  t.alike(
    lookupEvidence.map((entry) => entry.advertisementDigest),
    announceEvidence.map((entry) => entry.advertisementDigest)
  )
  commitRelayPathReservation(lookup)
  expectCode(t, () => commitRelayPathReservation(announce), 'ERR_INCOMPATIBLE_RELAY')
  t.ok(announceEvidence.every((entry) => entry.canonicalAdvertisement.every((byte) => byte === 0)))

  let retry = null
  let retryError = null
  try {
    retry = takeRelayPathReservation(
      directory.reserveReplacement({ branchClass: BRANCH_CLASS.ANNOUNCE, generation: 2n })
    )
  } catch (err) {
    retryError = err
  }
  t.absent(retryError)
  if (retry !== null) abortRelayPathReservation(retry)
  directory.destroy()
})

test('sealed transfer revalidates expiry, rollback, and hostile clocks before publication', (t) => {
  const expired = fixture()
  const tracked = trackedDirectoryModule()
  const expiredSink = tracked.fresh.createRelayCandidateDirectorySink({
    wallNow: expired.clock.wallNow,
    monotonicNow: expired.clock.monotonicNow
  })
  tracked.start(null)
  const expiredToken = tracked.fresh.sealRelayCandidateDirectorySink(
    expiredSink,
    expired.records,
    expired.scope
  )
  const sealedAllocations = tracked.take()
  expired.clock.advance(30_000)
  expectCode(
    t,
    () => tracked.fresh.consumeSealedRelayCandidateDirectory(expiredToken),
    'ERR_REPLAY'
  )
  t.ok(sealedAllocations.length > 0)
  t.ok(sealedAllocations.every((value) => value.every((byte) => byte === 0)))
  expectCode(
    t,
    () => tracked.fresh.consumeSealedRelayCandidateDirectory(expiredToken),
    'ERR_REPLAY'
  )

  const rollback = fixture()
  const rollbackSink = createRelayCandidateDirectorySink({
    wallNow: rollback.clock.wallNow,
    monotonicNow: rollback.clock.monotonicNow
  })
  const rollbackToken = sealRelayCandidateDirectorySink(
    rollbackSink,
    rollback.records,
    rollback.scope
  )
  rollback.clock.jumpWall(-30_001)
  expectCode(t, () => consumeSealedRelayCandidateDirectory(rollbackToken), 'ERR_REPLAY')
  expectCode(t, () => consumeSealedRelayCandidateDirectory(rollbackToken), 'ERR_REPLAY')

  const base = fakeClock()
  let throwClock = false
  const throwing = fixture(1, 1, {
    wallNow() {
      if (throwClock) throw new Error('injected sealed clock failure')
      return base.wallNow()
    },
    monotonicNow: base.monotonicNow
  })
  const throwingSink = createRelayCandidateDirectorySink({
    wallNow: throwing.clock.wallNow,
    monotonicNow: throwing.clock.monotonicNow
  })
  const throwingToken = sealRelayCandidateDirectorySink(
    throwingSink,
    throwing.records,
    throwing.scope
  )
  throwClock = true
  expectCode(t, () => consumeSealedRelayCandidateDirectory(throwingToken), 'ERR_REPLAY')
  expectCode(t, () => consumeSealedRelayCandidateDirectory(throwingToken), 'ERR_REPLAY')

  let reenter = false
  let reentrantToken = null
  const reentrant = fixture(1, 1, {
    wallNow() {
      if (reenter) destroySealedRelayCandidateDirectory(reentrantToken)
      return NOW
    },
    monotonicNow: () => 0n
  })
  const reentrantSink = createRelayCandidateDirectorySink({
    wallNow: reentrant.clock.wallNow,
    monotonicNow: reentrant.clock.monotonicNow
  })
  reentrantToken = sealRelayCandidateDirectorySink(
    reentrantSink,
    reentrant.records,
    reentrant.scope
  )
  reenter = true
  expectCode(t, () => consumeSealedRelayCandidateDirectory(reentrantToken), 'ERR_REPLAY')
  expectCode(t, () => consumeSealedRelayCandidateDirectory(reentrantToken), 'ERR_REPLAY')
})

test('caught nested replay irreversibly poisons active seal and consume transfers', (t) => {
  for (const operation of ['seal', 'revoke']) {
    const input = fixture()
    let sink = null
    let active = false
    let nestedCode = null
    let clockCalls = 0
    const wallNow = () => {
      clockCalls++
      if (active) {
        active = false
        try {
          if (operation === 'seal') {
            sealRelayCandidateDirectorySink(sink, input.records, input.scope)
          } else {
            revokeRelayCandidateDirectorySink(sink)
          }
        } catch (err) {
          nestedCode = err && err.code
        }
      }
      return NOW
    }
    sink = createRelayCandidateDirectorySink({ wallNow, monotonicNow: () => 0n })
    active = true
    let token = null
    let outerCode = null
    try {
      token = sealRelayCandidateDirectorySink(sink, input.records, input.scope)
    } catch (err) {
      outerCode = err && err.code
    }
    t.is(nestedCode, 'ERR_REPLAY', `${operation} nested replay`)
    t.is(outerCode, 'ERR_REPLAY', `${operation} outer replay`)
    t.is(token, null, `${operation} publishes no token`)
    const callsAfterFailure = clockCalls
    expectCode(
      t,
      () => sealRelayCandidateDirectorySink(sink, input.records, input.scope),
      'ERR_REPLAY'
    )
    t.is(clockCalls, callsAfterFailure, `${operation} retains no clock authority`)
    if (token !== null) destroySealedRelayCandidateDirectory(token)
  }

  for (const operation of ['consume', 'destroy']) {
    const tracked = trackedDirectoryModule()
    const input = fixture()
    let token = null
    let active = false
    let nestedCode = null
    let clockCalls = 0
    const wallNow = () => {
      clockCalls++
      if (active) {
        active = false
        try {
          if (operation === 'consume') {
            tracked.fresh.consumeSealedRelayCandidateDirectory(token)
          } else {
            tracked.fresh.destroySealedRelayCandidateDirectory(token)
          }
        } catch (err) {
          nestedCode = err && err.code
        }
      }
      return NOW
    }
    const sink = tracked.fresh.createRelayCandidateDirectorySink({
      wallNow,
      monotonicNow: () => 0n
    })
    tracked.start(null)
    token = tracked.fresh.sealRelayCandidateDirectorySink(sink, input.records, input.scope)
    const transferAllocations = tracked.take()
    active = true
    let directory = null
    let outerCode = null
    try {
      directory = tracked.fresh.consumeSealedRelayCandidateDirectory(token)
    } catch (err) {
      outerCode = err && err.code
    }
    t.is(nestedCode, 'ERR_REPLAY', `${operation} nested replay`)
    t.is(outerCode, 'ERR_REPLAY', `${operation} outer replay`)
    t.is(directory, null, `${operation} publishes no directory`)
    t.ok(
      transferAllocations.every((value) => value.every((byte) => byte === 0)),
      `${operation} clears owned transfer bytes`
    )
    const callsAfterFailure = clockCalls
    expectCode(t, () => tracked.fresh.consumeSealedRelayCandidateDirectory(token), 'ERR_REPLAY')
    t.is(clockCalls, callsAfterFailure, `${operation} retains no clock authority`)
    if (directory !== null) directory.destroy()
  }

  const uncaught = fixture()
  let uncaughtSink = null
  let uncaughtActive = false
  uncaughtSink = createRelayCandidateDirectorySink({
    wallNow() {
      if (uncaughtActive) {
        uncaughtActive = false
        sealRelayCandidateDirectorySink(uncaughtSink, uncaught.records, uncaught.scope)
      }
      return NOW
    },
    monotonicNow: () => 0n
  })
  uncaughtActive = true
  expectCode(
    t,
    () => sealRelayCandidateDirectorySink(uncaughtSink, uncaught.records, uncaught.scope),
    'ERR_REPLAY'
  )
})

test('evidence and commit reject transaction or directory reentry from wall clock', (t) => {
  let action = null
  const base = fakeClock()
  const input = fixture(1, 1, {
    wallNow() {
      const current = action
      action = null
      if (current !== null) current()
      return base.wallNow()
    },
    monotonicNow: base.monotonicNow
  })
  const directory = install(input)
  const reservation = directory.reserveInitialPair({
    lookupGeneration: 1n,
    announceGeneration: 1n
  })
  const transaction = takeRelayPathReservation(reservation)
  const selections = splitRelayPathReservation(transaction)
  action = () => abortRelayPathReservation(transaction)
  expectCode(
    t,
    () =>
      consumeSelectedRelayEvidence(selections.lookup.middle, {
        transaction,
        branchClass: BRANCH_CLASS.LOOKUP,
        position: 'middle',
        generation: 1n
      }),
    'ERR_REPLAY'
  )
  const retry = takeRelayPathReservation(
    directory.reserveInitialPair({ lookupGeneration: 1n, announceGeneration: 1n })
  )
  abortRelayPathReservation(retry)

  const commitReservation = directory.reserveInitialPair({
    lookupGeneration: 1n,
    announceGeneration: 1n
  })
  const commitTransaction = takeRelayPathReservation(commitReservation)
  const evidence = consumeInitial(commitTransaction, splitRelayPathReservation(commitTransaction))
  action = () => directory.destroy()
  expectCode(t, () => commitRelayPathReservation(commitTransaction), 'ERR_INCOMPATIBLE_RELAY')
  t.ok(evidence.every((entry) => entry.advertisementDigest.every((byte) => byte === 0)))
  t.alike(directory[kInspectRelayCandidateDirectory](), {
    destroyed: true,
    identityCount: 0,
    byteBufferCount: 0,
    digestCount: 0,
    timerCount: 0,
    callbackCount: 0,
    generationRecordCount: 0,
    quarantineCount: 0,
    pendingCount: 0
  })
})

test('same-epoch equivocation quarantine cannot be bypassed by later transfer records', (t) => {
  const expiresAt = NOW + 180_000n
  const input = longFixture(expiresAt)
  const original = candidate(ROLE.SAFETY, 1, 2, { expiresAtMs: NOW + 60_000n })
  input.records[0] = original
  const conflicting = candidate(ROLE.SAFETY, 1, 20, {
    epoch: original.epoch,
    expiresAtMs: NOW + 120_000n
  })
  const higher = candidate(ROLE.SAFETY, 1, 21, {
    epoch: original.epoch + 1n,
    expiresAtMs: expiresAt
  })
  input.records.push(conflicting, higher)
  const directory = install(input)
  t.is(directory[kInspectRelayCandidateDirectory]().quarantineCount, 1)
  const transaction = takeRelayPathReservation(
    directory.reserveInitialPair({ lookupGeneration: 1n, announceGeneration: 1n })
  )
  const evidence = consumeInitial(transaction, splitRelayPathReservation(transaction))
  for (const rejected of [original, conflicting, higher]) {
    t.absent(evidence.some((entry) => b4a.equals(entry.advertisementDigest, rejected.digest)))
  }
  abortRelayPathReservation(transaction)

  directory.retainForSuspend()
  input.clock.advance(119_999)
  directory.resume()
  t.is(directory[kInspectRelayCandidateDirectory]().quarantineCount, 1)
  directory.retainForSuspend()
  input.clock.advance(1)
  directory.resume()
  t.is(directory[kInspectRelayCandidateDirectory]().quarantineCount, 0)
  directory.destroy()

  const bounded = fixture()
  const conflicts = []
  for (let i = 0; i < MAX_RELAY_CANDIDATE_IDENTITIES + 1; i++) {
    const role = i & 1 ? ROLE.PRIVATE : ROLE.SAFETY
    const ordinal = i >> 1
    conflicts.push(candidate(role, ordinal, 80 + i * 2))
    conflicts.push(candidate(role, ordinal, 81 + i * 2))
  }
  const sink = createRelayCandidateDirectorySink({
    wallNow: bounded.clock.wallNow,
    monotonicNow: bounded.clock.monotonicNow
  })
  let token = null
  let error = null
  try {
    token = sealRelayCandidateDirectorySink(sink, conflicts, bounded.scope)
  } catch (err) {
    error = err
  }
  t.is(error && error.code, 'ERR_REPLAY')
  if (token !== null) destroySealedRelayCandidateDirectory(token)
})

test('fresh wall after monotonic rejects exact guard and candidate expiry on every handoff', (t) => {
  const makeInput = () => {
    const clock = callbackClock()
    const input = fixture(1, 1, clock)
    const guard = candidate(ROLE.SAFETY, 0, 1, { expiresAtMs: NOW + 60_000n })
    input.guard = guard
    input.scope = {
      guardIdentity: guard.identity,
      guardEndpoint: guard.canonicalEndpointBytes,
      guardAdvertisementDigest: guard.digest,
      guardEpoch: guard.epoch,
      guardExpiresAt: guard.expiresAt
    }
    return input
  }

  const initial = makeInput()
  const initialDirectory = install(initial)
  initial.clock.setCallback(() => initial.clock.setWall(NOW + 30_000n))
  expectCode(
    t,
    () => initialDirectory.reserveInitialPair({ lookupGeneration: 1n, announceGeneration: 1n }),
    'ERR_INCOMPATIBLE_RELAY'
  )
  t.is(initialDirectory[kInspectRelayCandidateDirectory]().pendingCount, 0)
  initialDirectory.destroy()

  const replacement = makeInput()
  const replacementDirectory = install(replacement)
  installInitial(replacementDirectory)
  replacement.clock.setCallback(() => replacement.clock.setWall(NOW + 30_000n))
  expectCode(
    t,
    () =>
      replacementDirectory.reserveReplacement({
        branchClass: BRANCH_CLASS.LOOKUP,
        generation: 2n
      }),
    'ERR_INCOMPATIBLE_RELAY'
  )
  t.is(replacementDirectory[kInspectRelayCandidateDirectory]().pendingCount, 0)
  replacementDirectory.destroy()

  const resumed = makeInput()
  const resumedDirectory = install(resumed)
  resumedDirectory.retainForSuspend()
  resumed.clock.setCallback(() => resumed.clock.setWall(NOW + 30_000n))
  expectCode(t, () => resumedDirectory.resume(), 'ERR_INCOMPATIBLE_RELAY')
  t.is(resumedDirectory[kInspectRelayCandidateDirectory]().pendingCount, 0)
  resumedDirectory.destroy()

  const sealed = makeInput()
  const sink = createRelayCandidateDirectorySink({
    wallNow: sealed.clock.wallNow,
    monotonicNow: sealed.clock.monotonicNow
  })
  const token = sealRelayCandidateDirectorySink(sink, sealed.records, sealed.scope)
  sealed.clock.setCallback(() => sealed.clock.setWall(NOW + 30_000n))
  expectCode(t, () => consumeSealedRelayCandidateDirectory(token), 'ERR_REPLAY')
  expectCode(t, () => consumeSealedRelayCandidateDirectory(token), 'ERR_REPLAY')

  const guardExpired = makeInput()
  const expiringGuard = candidate(ROLE.SAFETY, 0, 1)
  guardExpired.scope = {
    guardIdentity: expiringGuard.identity,
    guardEndpoint: expiringGuard.canonicalEndpointBytes,
    guardAdvertisementDigest: expiringGuard.digest,
    guardEpoch: expiringGuard.epoch,
    guardExpiresAt: expiringGuard.expiresAt
  }
  guardExpired.guard = expiringGuard
  for (let i = 0; i < guardExpired.records.length; i++) {
    const role = i < 3 ? ROLE.SAFETY : ROLE.PRIVATE
    const ordinal = role === ROLE.SAFETY ? i + 1 : i - 3
    guardExpired.records[i] = candidate(role, ordinal, 100 + i, {
      expiresAtMs: NOW + 60_000n
    })
  }
  const guardDirectory = install(guardExpired)
  guardExpired.clock.setCallback(() => guardExpired.clock.setWall(NOW + 30_000n))
  expectCode(
    t,
    () => guardDirectory.reserveInitialPair({ lookupGeneration: 1n, announceGeneration: 1n }),
    'ERR_INCOMPATIBLE_RELAY'
  )
  t.is(guardDirectory[kInspectRelayCandidateDirectory]().identityCount, 0)
  guardDirectory.destroy()
})

test('monotonic callback destruction cannot resurrect directory state', (t) => {
  const run = (operation) => {
    const clock = callbackClock()
    const input = fixture(1, 1, clock)
    const directory = install(input)
    if (operation === 'replacement') installInitial(directory)
    if (operation === 'resume') directory.retainForSuspend()
    clock.setCallback(() => directory.destroy())
    expectCode(
      t,
      () => {
        if (operation === 'initial') {
          directory.reserveInitialPair({ lookupGeneration: 1n, announceGeneration: 1n })
        } else if (operation === 'replacement') {
          directory.reserveReplacement({ branchClass: BRANCH_CLASS.LOOKUP, generation: 2n })
        } else if (operation === 'retain') {
          directory.retainForSuspend()
        } else {
          directory.resume()
        }
      },
      'ERR_INCOMPATIBLE_RELAY'
    )
    const observed = directory[kInspectRelayCandidateDirectory]()
    t.ok(observed.destroyed, `${operation} remains destroyed`)
    t.is(observed.identityCount, 0, `${operation} resurrects no records`)
    t.is(observed.pendingCount, 0, `${operation} publishes no claim`)
  }
  for (const operation of ['initial', 'replacement', 'retain', 'resume']) run(operation)

  const clock = callbackClock()
  const input = fixture(1, 1, clock)
  let token = null
  const sink = createRelayCandidateDirectorySink({
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow
  })
  token = sealRelayCandidateDirectorySink(sink, input.records, input.scope)
  clock.setCallback(() => {
    try {
      destroySealedRelayCandidateDirectory(token)
    } catch {}
  })
  expectCode(t, () => consumeSealedRelayCandidateDirectory(token), 'ERR_REPLAY')
  expectCode(t, () => consumeSealedRelayCandidateDirectory(token), 'ERR_REPLAY')
})

test('transfer record work is rejected before ownership or advertisement crypto', (t) => {
  const counted = countedVerificationDirectoryModule()
  const input = fixture()
  const records = []
  for (let i = 0; i < 16; i++) {
    const role = i & 1 ? ROLE.PRIVATE : ROLE.SAFETY
    records.push(candidate(role, i >> 1, 130 + i))
    records.push(records[records.length - 1])
  }
  records.push(records[0])
  const sink = counted.fresh.createRelayCandidateDirectorySink({
    wallNow: input.clock.wallNow,
    monotonicNow: input.clock.monotonicNow
  })
  expectCode(
    t,
    () => counted.fresh.sealRelayCandidateDirectorySink(sink, records, input.scope),
    'ERR_REPLAY'
  )
  t.alike(counted.counts(), { decodeCalls: 0, digestCalls: 0 })

  const countedBytes = countedVerificationDirectoryModule()
  const oversized = records.slice(0, 32)
  oversized[0] = {
    ...oversized[0],
    canonicalBytes: b4a.alloc(389)
  }
  const byteSink = countedBytes.fresh.createRelayCandidateDirectorySink({
    wallNow: input.clock.wallNow,
    monotonicNow: input.clock.monotonicNow
  })
  expectCode(
    t,
    () => countedBytes.fresh.sealRelayCandidateDirectorySink(byteSink, oversized, input.scope),
    'ERR_REPLAY'
  )
  t.alike(countedBytes.counts(), { decodeCalls: 0, digestCalls: 0 })

  const boundary = countedVerificationDirectoryModule()
  const boundarySink = boundary.fresh.createRelayCandidateDirectorySink({
    wallNow: input.clock.wallNow,
    monotonicNow: input.clock.monotonicNow
  })
  const token = boundary.fresh.sealRelayCandidateDirectorySink(
    boundarySink,
    records.slice(0, 32),
    input.scope
  )
  t.alike(boundary.counts(), { decodeCalls: 32, digestCalls: 32 })
  boundary.fresh.destroySealedRelayCandidateDirectory(token)
})
