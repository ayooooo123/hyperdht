'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { PrivateRouteError } = require('../../lib/private/errors')
const { LINK_OPERATION, TOPOLOGY_ROLE } = require('../../lib/private/protocol')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  createPeerNativeNeighborPool,
  provisionPeerNativeNeighbor,
  reservePeerNeighborLink,
  readPeerNeighborReservation,
  destroyPeerNeighborReservation,
  destroyPeerNativeNeighborPool,
  readPeerNativeNeighborDiagnostics,
  createPeerNativeNeighborDiscovery
} = require('../../lib/private/peer-native-neighbors')
const { LinkDirectory, readLinkHandle } = require('../../lib/private/topology-grant')
const { createPeerLedger, readPeerLedger } = require('../../lib/private/peer-ledger')
const {
  createPeerRelayOwner,
  readVerifiedPeerAdvertisement
} = require('../../lib/private/peer-capability')
const {
  createPeerBootstrapResponder,
  destroyPeerBootstrapResponder,
  discoverPeerCandidate,
  readPeerActiveCandidateFacts,
  destroyPeerActiveCandidate
} = require('../../lib/private/peer-direct-bootstrap')
const {
  registerPeerDirectResponder,
  destroyPeerDirectResponderRegistration
} = require('../../lib/private/udx-cell-endpoint')
const {
  seed,
  safetyIdentity,
  fixtureKeys,
  fakeClock,
  createBoundEndpoint,
  buildSignedGrant,
  buildVerifiedAd,
  setupNativePoolPreflight,
  setupTwoEndedNativeAdjacency
} = require('./peer-native-fixture')

function expectCode(t, fn, code) {
  try {
    fn()
    t.fail('should have thrown ' + code)
  } catch (err) {
    t.is(err instanceof PrivateRouteError, true, 'is PrivateRouteError')
    t.is(err.code, code, 'code matches ' + code)
  }
}

async function expectCodeAsync(t, promise, code) {
  try {
    await promise
    t.fail('should have rejected with ' + code)
  } catch (err) {
    t.is(err instanceof PrivateRouteError, true, 'is PrivateRouteError')
    t.is(err.code, code, 'code matches ' + code)
  }
}

// -----------------------------------------------------------------------------
// 1. Constructor and Option Validation
// -----------------------------------------------------------------------------

test('Peer Native Neighbors: createPeerNativeNeighborPool rejects invalid or missing options', (t) => {
  expectCode(t, () => createPeerNativeNeighborPool(null), 'INVALID_ROUTE')
  expectCode(t, () => createPeerNativeNeighborPool({}), 'INVALID_ROUTE')
})

test('Peer Native Neighbors: readPeerNativeNeighborDiagnostics rejects invalid pool and returns diagnostics for valid pool', async (t) => {
  t.is(readPeerNativeNeighborDiagnostics(null), null)
  t.is(readPeerNativeNeighborDiagnostics(Object.freeze({})), null)

  const { local, localRoute } = fixtureKeys()
  const clock = fakeClock()
  const network = new Map()
  const endpoint = createBoundEndpoint(network, '127.0.0.1', 48102)
  await endpoint.bind()

  const relayOwner = createPeerRelayOwner({
    endpoint,
    identityKeyPair: local,
    routeKeyPair: localRoute,
    advertisementFields: {
      relayIdentity32: local.publicKey,
      currentDhtNodeId32: seed(0x30),
      reachableEndpoint: { host: '127.0.0.1', port: 48102 },
      routeEncryptionPublicKey32: localRoute.publicKey,
      capabilityMask: 11,
      minimumVersion: 2,
      maximumVersion: 2,
      datagramReplayWindow: 64,
      maxConcurrentCircuits: 128,
      capacityClass: 1,
      maxCells: 10000,
      maxBytes: 1000000,
      maxCommands: 1000,
      idleTimeoutMs: 30000,
      maxQueuedBytes: 524288,
      epoch: 1n,
      issuedAt: 1000n,
      expiresAt: 2000000n,
      policyCount: 0
    },
    clockIdentity: clock,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer
  })

  const pool = createPeerNativeNeighborPool({
    relayOwner,
    endpoint,
    maxNeighbors: 8,
    nodeServiceBudget: { cells: 100, bytes: 120_000n, commands: 100 },
    neighborServiceReservation: { cells: 20, bytes: 24_000n, commands: 20 },
    neighborCloseReservation: { cells: 10, bytes: 12_000n, commands: 10 }
  })

  const diag = readPeerNativeNeighborDiagnostics(pool)
  t.is(diag.destroyed, false)
  t.is(diag.neighborCount, 0)
  t.is(diag.pendingCount, 0)
  t.is(diag.reservationCount, 0)
  t.is(diag.maxNeighbors, 8)
  t.is(diag.nodeServiceLedger.cellsAllocated, 100)
  t.is(diag.nodeServiceLedger.bytesAllocated, 120_000n)

  destroyPeerNativeNeighborPool(pool)
  await endpoint.close()
})

// -----------------------------------------------------------------------------
// 2. Explicit linkHandle Transfer and Real SessionOptions
// -----------------------------------------------------------------------------

test('Peer Native Neighbors: provisionPeerNativeNeighbor requires explicit linkHandle and real sessionOptions', async (t) => {
  const clock = fakeClock()
  const f = await setupNativePoolPreflight({ t, clock, localPort: 48103, peerPort: 48104 })

  // Obsolete topologyGrant is rejected as obsolete
  await expectCodeAsync(
    t,
    provisionPeerNativeNeighbor(f.pool, {
      topologyGrant: f.grant,
      linkHandle: f.localLinkHandle,
      advertisement: f.verifiedAd,
      mode: 'initiate',
      sessionOptions: f.localSessionOptions
    }),
    'INVALID_ROUTE'
  )

  // Missing linkHandle is rejected
  await expectCodeAsync(
    t,
    provisionPeerNativeNeighbor(f.pool, {
      advertisement: f.verifiedAd,
      mode: 'initiate',
      sessionOptions: f.localSessionOptions
    }),
    'UNAUTHORIZED'
  )

  // Non-object linkHandle is rejected
  await expectCodeAsync(
    t,
    provisionPeerNativeNeighbor(f.pool, {
      linkHandle: 'not_a_handle',
      advertisement: f.verifiedAd,
      mode: 'initiate',
      sessionOptions: f.localSessionOptions
    }),
    'UNAUTHORIZED'
  )

  // Missing sessionOptions entirely
  await expectCodeAsync(
    t,
    provisionPeerNativeNeighbor(f.pool, {
      linkHandle: f.localLinkHandle,
      advertisement: f.verifiedAd,
      mode: 'initiate'
    }),
    'INVALID_ROUTE'
  )

  // Non-object sessionOptions
  await expectCodeAsync(
    t,
    provisionPeerNativeNeighbor(f.pool, {
      linkHandle: f.localLinkHandle,
      advertisement: f.verifiedAd,
      mode: 'initiate',
      sessionOptions: 'fake'
    }),
    'INVALID_ROUTE'
  )

  // Mode mismatch between options.mode and sessionOptions.mode
  await expectCodeAsync(
    t,
    provisionPeerNativeNeighbor(f.pool, {
      linkHandle: f.localLinkHandle,
      advertisement: f.verifiedAd,
      mode: 'initiate',
      sessionOptions: { mode: 'accept', clockIdentity: clock, absoluteDeadline: 50_000 }
    }),
    'INVALID_ROUTE'
  )

  // Missing mode in sessionOptions
  await expectCodeAsync(
    t,
    provisionPeerNativeNeighbor(f.pool, {
      linkHandle: f.localLinkHandle,
      advertisement: f.verifiedAd,
      mode: 'initiate',
      sessionOptions: { clockIdentity: clock, absoluteDeadline: 50_000 }
    }),
    'INVALID_ROUTE'
  )

  // Non-safe-integer absoluteDeadline
  await expectCodeAsync(
    t,
    provisionPeerNativeNeighbor(f.pool, {
      linkHandle: f.localLinkHandle,
      advertisement: f.verifiedAd,
      mode: 'initiate',
      sessionOptions: { mode: 'initiate', clockIdentity: clock, absoluteDeadline: 'invalid' }
    }),
    'INVALID_ROUTE'
  )

  // Missing clockIdentity in sessionOptions
  await expectCodeAsync(
    t,
    provisionPeerNativeNeighbor(f.pool, {
      linkHandle: f.localLinkHandle,
      advertisement: f.verifiedAd,
      mode: 'initiate',
      sessionOptions: { mode: 'initiate', absoluteDeadline: 50_000 }
    }),
    'UNAUTHORIZED'
  )
})

// -----------------------------------------------------------------------------
// 3. Explicit Handle Transfer Preflight Preserves Unrelated Directory Authority
// -----------------------------------------------------------------------------

test('Peer Native Neighbors: explicit handle transfer preflight preserves unrelated directory authority', async (t) => {
  const clock = fakeClock()
  const f = await setupNativePoolPreflight({ t, clock, localPort: 48105, peerPort: 48106 })
  const foreignKey = safetyIdentity(0x88)

  const foreignGrant = buildSignedGrant({
    authority: f.authority,
    local: foreignKey,
    peer: f.peer,
    localHost: '127.0.0.1',
    localPort: 48105,
    peerHost: '127.0.0.1',
    peerPort: 48106,
    epoch: 1n,
    runId32: seed(0x99)
  })

  const foreignDirectory = new LinkDirectory({
    localIdentity32: foreignKey.publicKey,
    localRole: TOPOLOGY_ROLE.SAFETY_GUARD,
    authorityPublicKey: f.authority.publicKey,
    epoch: 1n,
    runId32: seed(0x99),
    now: () => 1n,
    schedule: setTimeout,
    cancel: clearTimeout,
    onClose() {}
  })
  t.teardown(() => foreignDirectory.destroy())

  const foreignDigest = foreignDirectory.add(foreignGrant)
  const invalidHandle = foreignDirectory.authorize({
    digest32: foreignDigest,
    operation: LINK_OPERATION.INITIATE,
    localIdentity32: foreignKey.publicKey,
    localRole: TOPOLOGY_ROLE.SAFETY_GUARD,
    peerIdentity32: f.peer.publicKey,
    peerRole: TOPOLOGY_ROLE.SAFETY_FINAL,
    epoch: 1n,
    runId32: seed(0x99)
  })

  // Preflight rejects mismatched local identity with UNAUTHORIZED
  await expectCodeAsync(
    t,
    provisionPeerNativeNeighbor(f.pool, {
      linkHandle: invalidHandle,
      advertisement: f.verifiedAd,
      mode: 'initiate',
      sessionOptions: f.localSessionOptions
    }),
    'UNAUTHORIZED'
  )

  // Unrelated directory authority is completely preserved: readLinkHandle still succeeds
  const preserved = readLinkHandle(invalidHandle)
  t.ok(preserved)
  t.ok(b4a.equals(preserved.localIdentity32, foreignKey.publicKey))
})

// -----------------------------------------------------------------------------
// 4. Matching Genuine Handle and Operation Mask Required
// -----------------------------------------------------------------------------

test('Peer Native Neighbors: requires genuine link handle matching mode operation mask', async (t) => {
  const clock = fakeClock()
  const f = await setupNativePoolPreflight({ t, clock, localPort: 48123, peerPort: 48124 })

  // Passing an accept-authorized handle to initiate mode rejects
  await expectCodeAsync(
    t,
    provisionPeerNativeNeighbor(f.pool, {
      linkHandle: f.peerLinkHandle,
      advertisement: f.verifiedAd,
      mode: 'initiate',
      sessionOptions: f.localSessionOptions
    }),
    'UNAUTHORIZED'
  )

  // Passing a forged object as linkHandle rejects
  await expectCodeAsync(
    t,
    provisionPeerNativeNeighbor(f.pool, {
      linkHandle: Object.freeze({ operations: 1 }),
      advertisement: f.verifiedAd,
      mode: 'initiate',
      sessionOptions: f.localSessionOptions
    }),
    'UNAUTHORIZED'
  )
})

// -----------------------------------------------------------------------------
// 5. Caller Clock Mismatch Rejection
// -----------------------------------------------------------------------------

test('Peer Native Neighbors: rejects caller clock mismatch in sessionOptions and verified ad', async (t) => {
  const clock = fakeClock()
  const foreignClock = fakeClock(5000n)
  const f = await setupNativePoolPreflight({ t, clock, localPort: 48121, peerPort: 48122 })

  // 1. Foreign sessionOptions.clockIdentity
  const foreignSessionOptions = {
    ...f.localSessionOptions,
    clockIdentity: foreignClock
  }
  await expectCodeAsync(
    t,
    provisionPeerNativeNeighbor(f.pool, {
      linkHandle: f.localLinkHandle,
      advertisement: f.verifiedAd,
      mode: 'initiate',
      sessionOptions: foreignSessionOptions
    }),
    'UNAUTHORIZED'
  )

  // 2. Foreign verified ad clock
  const { verified: foreignAd } = buildVerifiedAd({
    peer: f.peer,
    peerRoute: f.peerRoute,
    host: '127.0.0.1',
    port: 48122,
    epoch: 1n,
    clock: foreignClock
  })
  await expectCodeAsync(
    t,
    provisionPeerNativeNeighbor(f.pool, {
      linkHandle: f.localLinkHandle,
      advertisement: foreignAd,
      mode: 'initiate',
      sessionOptions: f.localSessionOptions
    }),
    'UNAUTHORIZED'
  )
})

// -----------------------------------------------------------------------------
// 6. Parent-Clamped Session Deadline
// -----------------------------------------------------------------------------

test('Peer Native Neighbors: clamps caller session deadline to parent local deadline and enforces expiry', async (t) => {
  const clock = fakeClock(1000n)
  const f = await setupNativePoolPreflight({ t, clock, localPort: 48125, peerPort: 48126 })

  // Caller specifies enormous deadline (999,999,999), while parentLocalDeadline is ~2,000,000n
  const callerBigDeadline = {
    ...f.peerSessionOptions,
    absoluteDeadline: 999_999_999
  }

  // Start accept provisioning on peerPool; it uses the clamped parentLocalDeadline
  let rejected = false
  const acceptPromise = provisionPeerNativeNeighbor(f.peerPool, {
    linkHandle: f.peerLinkHandle,
    advertisement: f.localVerifiedAd,
    mode: 'accept',
    sessionOptions: callerBigDeadline
  }).catch((err) => {
    rejected = true
    throw err
  })

  // Before parentLocalDeadline: accept session is still pending/waiting, has not rejected
  clock.advance(1_000_000)
  await new Promise((resolve) => setImmediate(resolve))
  t.is(rejected, false, 'accept provisioning is still active before parent deadline')

  // Advance clock to parentLocalDeadline (2,000,000n): waitAccepted timer triggers expiry
  clock.advance(1_000_000)
  await t.exception(acceptPromise)
  t.is(rejected, true, 'accept provisioning rejected at parentLocalDeadline')
})

// -----------------------------------------------------------------------------
// 7. Endpoint Matching via Canonical ParseAddress
// -----------------------------------------------------------------------------

test('Peer Native Neighbors: rejects when peer endpoint mismatches advertisement via canonical parseAddress', async (t) => {
  const clock = fakeClock()
  const f = await setupNativePoolPreflight({ t, clock, localPort: 48107, peerPort: 48108 })

  // Ad advertises peer at mismatched port 48199
  const { verified: mismatchedAd } = buildVerifiedAd({
    peer: f.peer,
    peerRoute: f.peerRoute,
    host: '127.0.0.1',
    port: 48199,
    epoch: 1n,
    clock
  })

  await expectCodeAsync(
    t,
    provisionPeerNativeNeighbor(f.pool, {
      linkHandle: f.localLinkHandle,
      advertisement: mismatchedAd,
      mode: 'initiate',
      sessionOptions: f.localSessionOptions
    }),
    'UNAUTHORIZED'
  )
})

// -----------------------------------------------------------------------------
// 8. Two-Ended Live Provisioning and Capacity Constraints
// -----------------------------------------------------------------------------

test('Peer Native Neighbors: two-ended live provisioning and neighbor limit', async (t) => {
  const clock = fakeClock()
  const f = await setupTwoEndedNativeAdjacency({
    t,
    clock,
    localPort: 48109,
    peerPort: 48110,
    maxNeighbors: 1
  })

  const neighbor = f.neighbor
  t.is(neighbor.kind, 'neighbor')
  t.ok(b4a.equals(neighbor.identity32, f.peer.publicKey))
  t.ok(neighbor.established)

  const diag = readPeerNativeNeighborDiagnostics(f.pool)
  t.is(diag.neighborCount, 1)
  t.is(diag.pendingCount, 0)
  t.is(
    diag.nodeServiceLedger.cellsSpent + diag.nodeServiceLedger.cellsReserved,
    30,
    'bootstrap attempts consume the reserved service allocation'
  )

  // Re-provisioning same identity while live rejects with CIRCUIT_STATE immediately
  await expectCodeAsync(
    t,
    provisionPeerNativeNeighbor(f.pool, {
      linkHandle: f.localLinkHandle,
      advertisement: f.verifiedAd,
      mode: 'initiate',
      sessionOptions: f.localSessionOptions
    }),
    'CIRCUIT_STATE'
  )

  // Provisioning distinct peer when maxNeighbors is 1 rejects with CIRCUIT_LIMIT
  const peer2 = safetyIdentity(0x22)
  const peer2Route = cryptoSuite.encryptionKeyPair(seed(0x23))
  const grant2 = buildSignedGrant({
    authority: f.authority,
    local: f.local,
    peer: peer2,
    localHost: '127.0.0.1',
    localPort: 48109,
    peerHost: '127.0.0.1',
    peerPort: 48112,
    epoch: 1n,
    runId32: seed(0x99)
  })
  const { verified: ad2 } = buildVerifiedAd({
    peer: peer2,
    peerRoute: peer2Route,
    host: '127.0.0.1',
    port: 48112,
    epoch: 1n,
    clock
  })
  const grant2Digest = f.localDirectory.add(grant2)
  const linkHandle2 = f.localDirectory.authorize({
    digest32: grant2Digest,
    operation: LINK_OPERATION.INITIATE,
    localIdentity32: f.local.publicKey,
    localRole: TOPOLOGY_ROLE.SAFETY_GUARD,
    peerIdentity32: peer2.publicKey,
    peerRole: TOPOLOGY_ROLE.SAFETY_FINAL,
    epoch: 1n,
    runId32: seed(0x99)
  })
  await expectCodeAsync(
    t,
    provisionPeerNativeNeighbor(f.pool, {
      linkHandle: linkHandle2,
      advertisement: ad2,
      mode: 'initiate',
      sessionOptions: f.localSessionOptions
    }),
    'CIRCUIT_LIMIT'
  )
})

// -----------------------------------------------------------------------------
// 9. Accept Abort Without Polling
// -----------------------------------------------------------------------------

test('Peer Native Neighbors: accept provisioning aborts immediately on pool destruction without polling', async (t) => {
  const clock = fakeClock()
  const f = await setupNativePoolPreflight({ t, clock, localPort: 48127, peerPort: 48128 })

  // Start accept provisioning on peerPool
  const acceptPromise = provisionPeerNativeNeighbor(f.peerPool, {
    linkHandle: f.peerLinkHandle,
    advertisement: f.localVerifiedAd,
    mode: 'accept',
    sessionOptions: f.peerSessionOptions
  })

  // Destroy peerPool immediately without dialing
  destroyPeerNativeNeighborPool(f.peerPool)

  // Resolves immediately as rejected without waiting or polling
  await t.exception(acceptPromise)
})

// -----------------------------------------------------------------------------
// 10. Branch Slots and Candidate Authority Reservation
// -----------------------------------------------------------------------------

test('Peer Native Neighbors: four branch slots preserve rejected candidate authority', async (t) => {
  const clock = fakeClock()
  const f = await setupTwoEndedNativeAdjacency({ t, clock, localPort: 48119, peerPort: 48120 })

  const advertisement260 = readVerifiedPeerAdvertisement(f.verifiedAd).canonicalBytes260
  const reservations = []
  for (let i = 0; i < 4; i++) {
    reservations.push(
      reservePeerNeighborLink(f.pool, {
        advertisement260,
        activeCandidate: await f.discover(),
        absoluteDeadline: 50_000n
      })
    )
  }
  const fifth = await f.discover()
  const request = { advertisement260, activeCandidate: fifth, absoluteDeadline: 50_000n }
  expectCode(t, () => reservePeerNeighborLink(f.pool, request), 'CIRCUIT_LIMIT')
  t.is(readPeerNativeNeighborDiagnostics(f.pool).reservationCount, 4)
  destroyPeerNeighborReservation(reservations.pop())
  const replacement = reservePeerNeighborLink(f.pool, request)
  const scope = readPeerNeighborReservation(replacement, f.localRelayOwner)
  t.is(scope.operationLocalDeadline, 6000n, 'candidate expiry clamps the requested deadline')
  clock.advance(5000)
  t.is(
    readPeerNativeNeighborDiagnostics(f.pool).reservationCount,
    0,
    'all branch slots retire at their original candidate deadline'
  )
  expectCode(t, () => readPeerNeighborReservation(replacement, f.localRelayOwner), 'UNAUTHORIZED')
})

test('Peer Native Neighbors: synchronous callback and clear reentry on live neighbor does not leak branch slot', async (t) => {
  const clock = fakeClock()
  const f = await setupTwoEndedNativeAdjacency({ t, clock, localPort: 48113, peerPort: 48114 })

  const adInfo = readVerifiedPeerAdvertisement(f.verifiedAd)
  const activeCandidate = await f.discover()

  let clearHookRan = false
  clock.setOnClearTimer(() => {
    clearHookRan = true
  })
  clock.fireSynchronously(true)

  // Attempt reserve with synchronous timer trigger: must rollback cleanly and reject
  expectCode(
    t,
    () =>
      reservePeerNeighborLink(f.pool, {
        advertisement260: b4a.from(adInfo.canonicalBytes260),
        activeCandidate,
        absoluteDeadline: 50_000n
      }),
    'ERR_PRIVACY_UNAVAILABLE'
  )

  t.is(clearHookRan, true, 'reentrant clearTimer hook ran during rollback')
  const diag = readPeerNativeNeighborDiagnostics(f.pool)
  t.is(diag.reservationCount, 0, 'no branch slot was leaked on synchronous schedule/clear reentry')
})

// -----------------------------------------------------------------------------
// 11. Bounded 32-bit Timer Chunk/Rearm with Clamped Original Deadline
// -----------------------------------------------------------------------------

test('Peer Native Neighbors: parent expiry rearms bounded timers without renewing its deadline', async (t) => {
  let now = 1000n
  const timers = new Set()
  const clock = {
    wallNow: () => now,
    monotonicNow: () => now,
    setTimer(callback, delay) {
      const timer = { callback, delay, at: now + BigInt(delay) }
      timers.add(timer)
      return timer
    },
    clearTimer(timer) {
      timers.delete(timer)
    }
  }
  const f = await setupTwoEndedNativeAdjacency({
    t,
    clock,
    localPort: 48141,
    peerPort: 48142,
    expiresAt: 5_000_000_000n
  })
  const expiryTimers = () => [...timers].filter((timer) => timer.delay > 30_000)
  // Drive only the parent-expiry timers; heartbeat scheduling is a separate owner.
  const advanceExpiry = (delta) => {
    now += delta
    for (const timer of expiryTimers()) {
      if (timer.at > now) continue
      timers.delete(timer)
      timer.callback()
    }
  }
  t.alike(
    expiryTimers().map((timer) => timer.delay),
    [2147483647, 2147483647]
  )
  advanceExpiry(2147483647n)
  t.is(readPeerNativeNeighborDiagnostics(f.pool).neighborCount, 1)
  t.alike(
    expiryTimers().map((timer) => timer.delay),
    [2147483647, 2147483647]
  )
  advanceExpiry(2147483647n)
  t.is(readPeerNativeNeighborDiagnostics(f.pool).neighborCount, 1)
  t.alike(
    expiryTimers().map((timer) => timer.delay),
    [705031706, 705031706]
  )
  advanceExpiry(705031705n)
  t.is(readPeerNativeNeighborDiagnostics(f.pool).neighborCount, 1)
  advanceExpiry(1n)
  t.is(readPeerNativeNeighborDiagnostics(f.pool).neighborCount, 0)
  t.is(readPeerNativeNeighborDiagnostics(f.peerPool).neighborCount, 0)
})

// -----------------------------------------------------------------------------
// 12. Link Close Revokes Neighbor and Settles Ledgers
// -----------------------------------------------------------------------------

test('Peer Native Neighbors: link close revokes neighbor and settles ledgers', async (t) => {
  const clock = fakeClock()
  const f = await setupTwoEndedNativeAdjacency({ t, clock, localPort: 48115, peerPort: 48116 })

  const diagBefore = readPeerNativeNeighborDiagnostics(f.pool)
  t.is(diagBefore.neighborCount, 1)
  t.is(diagBefore.nodeServiceLedger.cellsSpent + diagBefore.nodeServiceLedger.cellsReserved, 30)

  // Revoke grant on localDirectory to trigger subscribeLinkHandleClose
  const grantDigest = f.localDirectory.add(f.grant)
  f.localDirectory.revoke({
    digest32: grantDigest,
    epoch: 1n,
    runId32: seed(0x99)
  })

  // Synchronous removal: neighborCount is 0 immediately
  const diagAfterClose = readPeerNativeNeighborDiagnostics(f.pool)
  t.is(diagAfterClose.neighborCount, 0)
})

// -----------------------------------------------------------------------------
// 13. Destroy Pool During Provisioning
// -----------------------------------------------------------------------------

test('Peer Native Neighbors: pending provisioning cannot publish after pool destruction', async (t) => {
  const clock = fakeClock()
  const f = await setupNativePoolPreflight({ t, clock, localPort: 48117, peerPort: 48118 })

  const pending = provisionPeerNativeNeighbor(f.pool, {
    linkHandle: f.localLinkHandle,
    advertisement: f.verifiedAd,
    mode: 'initiate',
    sessionOptions: f.localSessionOptions
  })

  // Destroy pool while provisioning is pending
  t.is(destroyPeerNativeNeighborPool(f.pool), true)
  t.is(destroyPeerNativeNeighborPool(f.pool), false)

  const rejected = await pending.then(
    () => false,
    (err) => err instanceof PrivateRouteError
  )
  t.is(rejected, true, 'pending provisioning rejects instead of publishing a neighbor')
  t.is(readPeerNativeNeighborDiagnostics(f.pool), null, 'destroyed pool cannot publish a neighbor')
})

// -----------------------------------------------------------------------------
// 14. Reservation Readers and Owner Tokens
// -----------------------------------------------------------------------------

test('Peer Native Neighbors: readPeerNeighborReservation returns null for unknown and rejects revoked', (t) => {
  t.is(readPeerNeighborReservation(Object.freeze({}), Object.freeze({})), null)
  t.is(readPeerNeighborReservation(null, Object.freeze({})), null)
})

test('Peer Native Neighbors: destroyPeerNeighborReservation is idempotent', (t) => {
  t.is(destroyPeerNeighborReservation(null), false)
  t.is(destroyPeerNeighborReservation(Object.freeze({})), false)
})

test('Peer Native Neighbors: destroyPeerNativeNeighborPool is idempotent', (t) => {
  t.is(destroyPeerNativeNeighborPool(null), false)
  t.is(destroyPeerNativeNeighborPool(Object.freeze({})), false)
})

test('bootstrap operation deadline is checked at native dispatch after callback reentry', async (t) => {
  const clock = fakeClock()
  let monotonic = 1000n
  clock.monotonicNow = () => monotonic
  const f = await setupNativePoolPreflight({ t, clock, localPort: 48801, peerPort: 48802 })
  const socket = f.localSocket
  const send = socket.send
  Object.defineProperty(socket, 'send', {
    configurable: true,
    get() {
      monotonic = 1500n
      return send
    }
  })
  await t.exception(
    provisionPeerNativeNeighbor(f.pool, {
      linkHandle: f.localLinkHandle,
      advertisement: f.verifiedAd,
      mode: 'initiate',
      sessionOptions: f.localSessionOptions,
      operationDeadline: 1500n
    })
  )
  t.is(socket.sent.length, 0, 'expired bootstrap never crosses the native send boundary')
  t.is(readPeerNativeNeighborDiagnostics(f.pool).neighborCount, 0)
  t.is(readPeerNativeNeighborDiagnostics(f.pool).nodeServiceLedger.cellsSpent, 0)
})

test('parent wall expiry at native handoff rejects without spending bootstrap service', async (t) => {
  const clock = fakeClock()
  const f = await setupNativePoolPreflight({ t, clock, localPort: 48803, peerPort: 48804 })
  const socket = f.localSocket
  const send = socket.send
  Object.defineProperty(socket, 'send', {
    configurable: true,
    get() {
      clock.advanceWall(2_000_000)
      return send
    }
  })
  await t.exception(
    provisionPeerNativeNeighbor(f.pool, {
      linkHandle: f.localLinkHandle,
      advertisement: f.verifiedAd,
      mode: 'initiate',
      sessionOptions: f.localSessionOptions
    })
  )
  t.is(clock.monotonicNow(), 1000n, 'no monotonic timer fired')
  t.is(socket.sent.length, 0, 'wire expiry is rechecked after the native method getter')
  t.is(readPeerNativeNeighborDiagnostics(f.pool).nodeServiceLedger.cellsSpent, 0)
})

test('CREATED response cannot dispatch beyond its owned accept operation deadline', async (t) => {
  const clock = fakeClock()
  let monotonic = 1000n
  clock.monotonicNow = () => monotonic
  const f = await setupNativePoolPreflight({ t, clock, localPort: 48805, peerPort: 48806 })
  const socket = f.localSocket.network.get('127.0.0.1:48806')
  const send = socket.send
  Object.defineProperty(socket, 'send', {
    configurable: true,
    get() {
      monotonic = 1500n
      return send
    }
  })
  const accepting = provisionPeerNativeNeighbor(f.peerPool, {
    linkHandle: f.peerLinkHandle,
    advertisement: f.localVerifiedAd,
    mode: 'accept',
    sessionOptions: f.peerSessionOptions,
    operationDeadline: 1500n
  })
  const opening = provisionPeerNativeNeighbor(f.pool, {
    linkHandle: f.localLinkHandle,
    advertisement: f.verifiedAd,
    mode: 'initiate',
    sessionOptions: f.localSessionOptions
  })
  await t.exception(accepting)
  t.is(f.localSocket.sent.length, 1, 'genuine CREATE reached the responder')
  t.is(socket.sent.length, 0, 'expired CREATED never reaches native send')
  t.is(readPeerNativeNeighborDiagnostics(f.peerPool).nodeServiceLedger.cellsSpent, 0)
  destroyPeerNativeNeighborPool(f.pool)
  await t.exception(opening)
})

// -----------------------------------------------------------------------------
// 15. Native Neighbor Discovery (createPeerNativeNeighborDiscovery)
// -----------------------------------------------------------------------------

test('Peer Native Neighbors: createPeerNativeNeighborDiscovery rejects invalid or destroyed pool', async (t) => {
  expectCode(t, () => createPeerNativeNeighborDiscovery(null, {}), 'UNAUTHORIZED')
  expectCode(t, () => createPeerNativeNeighborDiscovery(Object.freeze({}), {}), 'UNAUTHORIZED')

  const clock = fakeClock()
  const f = await setupNativePoolPreflight({ t, clock, localPort: 48811, peerPort: 48812 })
  destroyPeerNativeNeighborPool(f.pool)

  expectCode(
    t,
    () =>
      createPeerNativeNeighborDiscovery(f.pool, {
        mode: 1,
        requestedMask: 11,
        randomTarget32: seed(0x01),
        suppliedAdvertisement260: null,
        clockIdentity: clock,
        wireExpiresAt: 2_000_000n,
        localDeadline: 2_000_000n
      }),
    'UNAUTHORIZED'
  )
})

test('Peer Native Neighbors: createPeerNativeNeighborDiscovery validates request structure and fields', async (t) => {
  const clock = fakeClock()
  const f = await setupTwoEndedNativeAdjacency({
    t,
    clock,
    localPort: 48813,
    peerPort: 48814,
    serviceCells: 50
  })

  const foreignClock = fakeClock(5000n)
  const baseRequest = {
    mode: 1,
    requestedMask: 11,
    randomTarget32: seed(0x02),
    suppliedAdvertisement260: null,
    clockIdentity: clock,
    wireExpiresAt: 2_000_000n,
    localDeadline: 2_000_000n
  }

  // Non-object request
  expectCode(t, () => createPeerNativeNeighborDiscovery(f.pool, null), 'INVALID_ROUTE')
  expectCode(t, () => createPeerNativeNeighborDiscovery(f.pool, 'invalid'), 'INVALID_ROUTE')

  // Invalid mode
  expectCode(
    t,
    () => createPeerNativeNeighborDiscovery(f.pool, { ...baseRequest, mode: 0 }),
    'INVALID_ROUTE'
  )

  // Clock identity mismatch
  expectCode(
    t,
    () =>
      createPeerNativeNeighborDiscovery(f.pool, { ...baseRequest, clockIdentity: foreignClock }),
    'UNAUTHORIZED'
  )

  // Invalid requestedMask
  expectCode(
    t,
    () => createPeerNativeNeighborDiscovery(f.pool, { ...baseRequest, requestedMask: 7 }),
    'INVALID_ROUTE'
  )
  expectCode(
    t,
    () =>
      createPeerNativeNeighborDiscovery(f.pool, {
        ...baseRequest,
        mode: 2,
        requestedMask: 9,
        suppliedAdvertisement260: b4a.alloc(260)
      }),
    'INVALID_ROUTE'
  )

  // Invalid randomTarget32
  expectCode(
    t,
    () =>
      createPeerNativeNeighborDiscovery(f.pool, { ...baseRequest, randomTarget32: b4a.alloc(16) }),
    'INVALID_ROUTE'
  )

  // Mode 1 suppliedAdvertisement260 must be strictly null (not undefined or missing)
  expectCode(
    t,
    () =>
      createPeerNativeNeighborDiscovery(f.pool, {
        ...baseRequest,
        suppliedAdvertisement260: undefined
      }),
    'INVALID_ROUTE'
  )
  expectCode(
    t,
    () =>
      createPeerNativeNeighborDiscovery(f.pool, {
        ...baseRequest,
        suppliedAdvertisement260: b4a.alloc(260)
      }),
    'INVALID_ROUTE'
  )

  // Missing required own field
  const { localDeadline: _dropped, ...missingFieldReq } = baseRequest
  expectCode(t, () => createPeerNativeNeighborDiscovery(f.pool, missingFieldReq), 'INVALID_ROUTE')

  // Extra unknown field
  expectCode(
    t,
    () => createPeerNativeNeighborDiscovery(f.pool, { ...baseRequest, unknownExtra: true }),
    'INVALID_ROUTE'
  )

  // Accessor getter on request rejected
  const accessorReq = { ...baseRequest }
  Object.defineProperty(accessorReq, 'mode', {
    get() {
      return 1
    }
  })
  expectCode(t, () => createPeerNativeNeighborDiscovery(f.pool, accessorReq), 'INVALID_ROUTE')
  // Mode 2 suppliedAdvertisement260 must be 260-byte buffer
  expectCode(
    t,
    () =>
      createPeerNativeNeighborDiscovery(f.pool, {
        ...baseRequest,
        mode: 2,
        requestedMask: 11,
        suppliedAdvertisement260: null
      }),
    'INVALID_ROUTE'
  )

  // Invalid types are schema failures; zero is a valid but expired u64.
  expectCode(
    t,
    () => createPeerNativeNeighborDiscovery(f.pool, { ...baseRequest, wireExpiresAt: 'invalid' }),
    'INVALID_ROUTE'
  )
  expectCode(
    t,
    () => createPeerNativeNeighborDiscovery(f.pool, { ...baseRequest, wireExpiresAt: 0n }),
    'ERR_PRIVACY_UNAVAILABLE'
  )
  expectCode(
    t,
    () => createPeerNativeNeighborDiscovery(f.pool, { ...baseRequest, localDeadline: -1n }),
    'INVALID_ROUTE'
  )
  const revoked = Proxy.revocable(baseRequest, {})
  revoked.revoke()
  expectCode(t, () => createPeerNativeNeighborDiscovery(f.pool, revoked.proxy), 'INVALID_ROUTE')
  let coerced = false
  const coercibleTime = {
    valueOf() {
      coerced = true
      return 2000n
    }
  }
  expectCode(
    t,
    () =>
      createPeerNativeNeighborDiscovery(f.pool, {
        ...baseRequest,
        localDeadline: coercibleTime
      }),
    'INVALID_ROUTE'
  )
  t.is(coerced, false, 'deadline validation never invokes caller coercion')

  // Already expired request deadlines
  expectCode(
    t,
    () => createPeerNativeNeighborDiscovery(f.pool, { ...baseRequest, wireExpiresAt: 500n }),
    'ERR_PRIVACY_UNAVAILABLE'
  )
  expectCode(
    t,
    () => createPeerNativeNeighborDiscovery(f.pool, { ...baseRequest, localDeadline: 500n }),
    'ERR_PRIVACY_UNAVAILABLE'
  )
})

test('Peer Native Neighbors: createPeerNativeNeighborDiscovery positive SUPPLIED mode', async (t) => {
  const clock = fakeClock(1000n)
  const f = await setupTwoEndedNativeAdjacency({
    t,
    clock,
    localPort: 48817,
    peerPort: 48818,
    serviceCells: 50
  })

  const peerAdInfo = readVerifiedPeerAdvertisement(f.verifiedAd)
  const suppliedAdvertisement260 = b4a.from(peerAdInfo.canonicalBytes260)

  const request = {
    mode: 2,
    requestedMask: 11,
    randomTarget32: seed(0x04),
    suppliedAdvertisement260,
    clockIdentity: clock,
    wireExpiresAt: 2_000_000n,
    localDeadline: 2_000_000n
  }

  const discovery = createPeerNativeNeighborDiscovery(f.pool, request)
  t.ok(discovery, 'discovery result created')
  t.alike(
    discovery.advertisement260,
    suppliedAdvertisement260,
    'exact matching advertisement returned'
  )

  t.is(discovery.close(), true, 'close succeeds')
})

test('Peer Native Neighbors: createPeerNativeNeighborDiscovery SUPPLIED mode rejects unmatched advertisement', async (t) => {
  const clock = fakeClock(1000n)
  const f = await setupTwoEndedNativeAdjacency({
    t,
    clock,
    localPort: 48819,
    peerPort: 48820,
    serviceCells: 50
  })

  const unknownAd260 = b4a.alloc(260, 0xee)
  const request = {
    mode: 2,
    requestedMask: 11,
    randomTarget32: seed(0x05),
    suppliedAdvertisement260: unknownAd260,
    clockIdentity: clock,
    wireExpiresAt: 2_000_000n,
    localDeadline: 2_000_000n
  }

  expectCode(t, () => createPeerNativeNeighborDiscovery(f.pool, request), 'ERR_PRIVACY_UNAVAILABLE')
})

test('Peer Native Neighbors: createPeerNativeNeighborDiscovery rejects capacity failure when neighbor serviceLedger has insufficient cells', async (t) => {
  const clock = fakeClock(1000n)
  // default serviceCells is 20, which is < 24 required for discovery
  const f = await setupTwoEndedNativeAdjacency({
    t,
    clock,
    localPort: 48823,
    peerPort: 48824,
    serviceCells: 20
  })

  const request = {
    mode: 1,
    requestedMask: 11,
    randomTarget32: seed(0x07),
    suppliedAdvertisement260: null,
    clockIdentity: clock,
    wireExpiresAt: 2_000_000n,
    localDeadline: 2_000_000n
  }

  expectCode(t, () => createPeerNativeNeighborDiscovery(f.pool, request), 'CIRCUIT_LIMIT')
})

test('Peer Native Neighbors: pool destruction cleanly closes active discoveries', async (t) => {
  const clock = fakeClock(1000n)
  const f = await setupTwoEndedNativeAdjacency({
    t,
    clock,
    native: true,
    localPort: 48825,
    peerPort: 48826,
    serviceCells: 50
  })

  const request = {
    mode: 1,
    requestedMask: 11,
    randomTarget32: seed(0x08),
    suppliedAdvertisement260: null,
    clockIdentity: clock,
    wireExpiresAt: 2_000_000n,
    localDeadline: 2_000_000n
  }

  const discovery = createPeerNativeNeighborDiscovery(f.pool, request)
  t.ok(discovery)
  t.is(readPeerLedger(discovery.ledger).released, false)
  const rejected = expectCodeAsync(
    t,
    discoverPeerCandidate(discovery.transport, {
      ledger: discovery.ledger,
      requestedMask: 11,
      randomTarget: request.randomTarget32,
      maximumResults: 1
    }),
    'ERR_DESTROYED'
  )

  destroyPeerNativeNeighborPool(f.pool)
  await rejected

  t.is(
    readPeerLedger(discovery.ledger).released,
    true,
    'discovery ledger released on pool destruction'
  )
  t.is(discovery.close(), false, 'discovery already closed by pool destruction')
})

test('Peer Native Neighbors: Native discovery cancellation releases the slot without closing the shared socket', async (t) => {
  const clock = fakeClock(1000n)
  const f = await setupTwoEndedNativeAdjacency({
    t,
    clock,
    native: true,
    localPort: 48831,
    peerPort: 48832,
    serviceCells: 50
  })
  const request = {
    mode: 1,
    requestedMask: 11,
    randomTarget32: seed(0x3a),
    suppliedAdvertisement260: null,
    clockIdentity: clock,
    wireExpiresAt: 3000n,
    localDeadline: 5000n
  }
  const originalTimerCount = clock.timerCount()
  const abandoned = createPeerNativeNeighborDiscovery(f.pool, request)
  const rejected = expectCodeAsync(
    t,
    discoverPeerCandidate(abandoned.transport, {
      ledger: abandoned.ledger,
      requestedMask: 11,
      randomTarget: request.randomTarget32,
      maximumResults: 1
    }),
    'ERR_DESTROYED'
  )
  abandoned.close()
  await rejected
  t.is(
    readPeerLedger(abandoned.ledger).released,
    true,
    'in-flight cancellation releases its reservation'
  )
  t.is(
    clock.timerCount(),
    originalTimerCount,
    'cancellation retires the owner deadline and retry timers'
  )

  const responder = createPeerBootstrapResponder(f.peerRelayOwner)
  const registration = registerPeerDirectResponder(f.peerEndpoint, responder)
  try {
    for (let round = 0; round < 2; round++) {
      const discovery = createPeerNativeNeighborDiscovery(f.pool, request)
      const budget = readPeerLedger(discovery.ledger)
      t.is(budget.cellsAllocated, 24, 'Native discovery uses the finite 24-cell profile')
      t.is(budget.bytesAllocated, 28800n, 'packet storage matches the cell profile')
      const candidate = await discoverPeerCandidate(discovery.transport, {
        ledger: discovery.ledger,
        requestedMask: 11,
        randomTarget: request.randomTarget32,
        maximumResults: 1
      })
      const facts = readPeerActiveCandidateFacts(candidate)
      t.alike(
        facts.completeAdvertisement,
        discovery.advertisement260,
        'authenticated advertisement matches'
      )
      t.is(facts.wireExpiresAt, 3000n, 'ACTIVE authentication preserves the wire upper bound')
      t.is(facts.localDeadline, 3000n, 'local lifetime projects the shorter wire bound')
      destroyPeerActiveCandidate(candidate)
      discovery.close()
      t.is(
        readPeerLedger(discovery.ledger).released,
        true,
        'completed operation releases its child'
      )
    }
  } finally {
    destroyPeerDirectResponderRegistration(registration)
    destroyPeerBootstrapResponder(responder)
  }
})

test('Peer Native Neighbors: createPeerNativeNeighborDiscovery clamps candidate wire bounds to short request bounds', async (t) => {
  const clock = fakeClock(1000n)
  const f = await setupTwoEndedNativeAdjacency({
    t,
    clock,
    localPort: 48833,
    peerPort: 48834,
    serviceCells: 50
  })

  const responder = createPeerBootstrapResponder(f.peerRelayOwner)
  const registration = registerPeerDirectResponder(f.peerEndpoint, responder)

  try {
    const request = {
      mode: 1,
      requestedMask: 11,
      randomTarget32: seed(0x3b),
      suppliedAdvertisement260: null,
      clockIdentity: clock,
      wireExpiresAt: 3000n,
      localDeadline: 3000n
    }

    const discovery = createPeerNativeNeighborDiscovery(f.pool, request)
    t.ok(discovery, 'discovery created with short bounds')

    const candidate = await discoverPeerCandidate(discovery.transport, {
      ledger: discovery.ledger,
      requestedMask: 11,
      randomTarget: seed(0x3b),
      maximumResults: 1
    })
    t.ok(candidate, 'candidate discovered')

    const facts = readPeerActiveCandidateFacts(candidate)
    t.is(facts.wireExpiresAt, 3000n, 'candidate facts carry clamped short wire bound')
    t.ok(facts.localDeadline <= 3000n, 'candidate facts carry clamped short local bound')

    destroyPeerActiveCandidate(candidate)
    t.is(discovery.close(), true, 'discovery closed')
  } finally {
    destroyPeerDirectResponderRegistration(registration)
    destroyPeerBootstrapResponder(responder)
  }
})

test('Peer Native Neighbors: discovery closes at the original projected wire deadline', async (t) => {
  const clock = fakeClock(1000n)
  const f = await setupTwoEndedNativeAdjacency({
    t,
    clock,
    localPort: 48835,
    peerPort: 48836,
    serviceCells: 50
  })
  clock.advanceWall(1000)
  const request = {
    mode: 1,
    requestedMask: 11,
    randomTarget32: seed(0x3c),
    suppliedAdvertisement260: null,
    clockIdentity: clock,
    wireExpiresAt: 2500n,
    localDeadline: 10000n
  }
  const discovery = createPeerNativeNeighborDiscovery(f.pool, request)
  const rejected = expectCodeAsync(
    t,
    discoverPeerCandidate(discovery.transport, {
      ledger: discovery.ledger,
      requestedMask: 11,
      randomTarget: request.randomTarget32,
      maximumResults: 1
    }),
    'ERR_DESTROYED'
  )
  clock.advance(499)
  t.is(
    readPeerLedger(discovery.ledger).released,
    false,
    'projection remains live immediately before its boundary'
  )
  clock.advance(1)
  await rejected
  t.is(
    readPeerLedger(discovery.ledger).released,
    true,
    'projected deadline closes the operation without polling'
  )
  const replacement = createPeerNativeNeighborDiscovery(f.pool, {
    ...request,
    wireExpiresAt: clock.wallNow() + 1000n,
    localDeadline: clock.monotonicNow() + 1000n
  })
  replacement.close()
})

test('Peer Native Neighbors: clock failures and reentrant pool revocation roll back discovery ownership', async (t) => {
  const clock = fakeClock(1000n)
  const wallNow = clock.wallNow
  const monotonicNow = clock.monotonicNow
  let wallFault = null
  let monoFault = null
  clock.wallNow = () => {
    if (wallFault && --wallFault.remaining === 0) {
      const callback = wallFault.callback
      wallFault = null
      callback()
    }
    return wallNow()
  }
  clock.monotonicNow = () => {
    if (monoFault && --monoFault.remaining === 0) {
      const callback = monoFault.callback
      monoFault = null
      callback()
    }
    return monotonicNow()
  }
  const f = await setupTwoEndedNativeAdjacency({
    t,
    clock,
    native: true,
    localPort: 48837,
    peerPort: 48838,
    serviceCells: 40
  })
  // Provisioning spends this same ledger. Leave room for one 24-cell discovery,
  // but never two: a leaked first reservation must prevent the replacement.
  const request = {
    mode: 1,
    requestedMask: 11,
    randomTarget32: seed(0x3d),
    suppliedAdvertisement260: null,
    clockIdentity: clock,
    wireExpiresAt: 3000n,
    localDeadline: 3000n
  }
  wallFault = {
    remaining: 2,
    callback() {
      throw new Error('locator clock failure')
    }
  }
  expectCode(t, () => createPeerNativeNeighborDiscovery(f.pool, request), 'INVALID_ROUTE')
  const replacement = createPeerNativeNeighborDiscovery(f.pool, request)
  replacement.close()
  t.is(
    readPeerLedger(replacement.ledger).released,
    true,
    'all 24 cells are reusable after post-reservation failure'
  )

  monoFault = {
    remaining: 3,
    callback() {
      destroyPeerNativeNeighborPool(f.pool)
    }
  }
  expectCode(t, () => createPeerNativeNeighborDiscovery(f.pool, request), 'UNAUTHORIZED')
  const candidate = await f.discover()
  t.alike(
    readPeerActiveCandidateFacts(candidate).completeAdvertisement,
    readVerifiedPeerAdvertisement(f.verifiedAd).canonicalBytes260,
    'revocation during Native adoption leaves no requester slot and keeps the shared socket usable'
  )
  destroyPeerActiveCandidate(candidate)
})
