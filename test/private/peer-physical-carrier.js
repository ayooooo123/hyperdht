'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { PrivateRouteError } = require('../../lib/private/errors')
const { CELL_CLASS, DIRECTION, PROTOCOL_VERSION } = require('../../lib/private/protocol')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  UdxCellEndpoint,
  registerSharedGuardPeerBranchResponder,
  exchangeSharedGuardPeerBranch,
  registerPeerM3CellLinkTransfer,
  createPeerPinnedGuardDirectTransport,
  createPeerCandidateDirectTransport,
  takePeerDirectRequesterTransport,
  registerPeerDirectResponder,
  destroyPeerDirectResponderRegistration
} = require('../../lib/private/udx-cell-endpoint')

const {
  createGuardLease,
  createPeerGuardPhysicalReservation,
  exchangePeerGuardLink,
  takePeerGuardPhysicalIssuer,
  destroyPeerGuardPhysicalReservation,
  readPeerGuardPhysicalReservation,
  createPeerGuardBootstrapTransport
} = require('../../lib/private/guard-lease')
const { createPeerLedger } = require('../../lib/private/peer-ledger')

const {
  takeM3RouteTransport,
  sendM3RouteFrame,
  reserveM3RouteFrame,
  receiveReservedM3RouteFrame,
  cancelM3RouteFrameReservation,
  readM3RouteTransportDiagnostics,
  destroyM3RouteTransport,
  beginM3RouteTeardown,
  registerM3RouteTeardownHandler
} = require('../../lib/private/m3-adjacency-runtime')

function fakeEstablishedHandle() {
  return Object.freeze({})
}

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

test('Physical Carrier: forged issuer cannot mint a peer transfer', (t) => {
  const fakeIssuer = Object.freeze({})
  const binding = {
    receiveEpoch: 1n,
    receiveCircuitId: b4a.alloc(16),
    receiveDirection: DIRECTION.FORWARD,
    sendEpoch: 1n,
    sendCircuitId: b4a.alloc(16),
    sendDirection: DIRECTION.REVERSE
  }
  t.is(registerPeerM3CellLinkTransfer(fakeIssuer, binding), null)
})

test('Physical Carrier: direct transport creation requires authenticated facts without fallbacks', (t) => {
  const established = fakeEstablishedHandle()
  const forgedClockOwner = Object.freeze({})
  expectCode(
    t,
    () => createPeerPinnedGuardDirectTransport(established, forgedClockOwner),
    'UNAUTHORIZED'
  )
  expectCode(t, () => createPeerCandidateDirectTransport({}, {}), 'UNAUTHORIZED')
})

test('Physical Carrier: one-shot physical issuer take and reservation teardown', (t) => {
  const fakeReservation = Object.freeze({})
  expectCode(t, () => takePeerGuardPhysicalIssuer(fakeReservation), 'UNAUTHORIZED')
  const sendLedger = createPeerLedger({ cells: 10, bytes: 12000n, commands: 10 })
  expectCode(
    t,
    () => exchangePeerGuardLink(fakeReservation, { offer: b4a.alloc(10), generation: 1n, sendLedger }),
    'UNAUTHORIZED'
  )
  t.is(destroyPeerGuardPhysicalReservation(fakeReservation), false)
})

test('Physical Carrier: v2 carrier adoption in m3-adjacency-runtime and v1 teardown rejection', async (t) => {
  const owner = Object.freeze({})
  expectCode(t, () => takeM3RouteTransport(owner), 'INVALID_ROUTE')
  const invalidCarrier = Object.freeze({ sendFrame() {} })
  expectCode(t, () => takeM3RouteTransport({ [Symbol.for('test-carrier')]: invalidCarrier }), 'INVALID_ROUTE')
})
test('Physical Carrier: direct candidate requester transport provenance variant', (t) => {
  const fakeLocator = Object.freeze({})
  expectCode(t, () => createPeerCandidateDirectTransport({}, fakeLocator), 'UNAUTHORIZED')
})

test('Physical Carrier: direct requester capability disjoint provenance fields', (t) => {
  const clockIdentity = Object.freeze({ wallNow: () => 1n, monotonicNow: () => 1n })
  const guardCap = Object.freeze({
    kind: 'guard',
    identity32: b4a.alloc(32, 1),
    endpoint19: b4a.alloc(19, 2),
    epoch: 1n,
    grantDigest: b4a.alloc(32, 3),
    runId: b4a.alloc(32, 4),
    operations: 1,
    clockIdentity,
    wallNow: clockIdentity.wallNow,
    monotonicNow: clockIdentity.monotonicNow,
    wireExpiresAt: 1000n,
    localDeadline: 1000n
  })

  t.is(guardCap.kind, 'guard')
  t.is(b4a.isBuffer(guardCap.grantDigest), true)
  t.is(b4a.isBuffer(guardCap.runId), true)
  t.is(typeof guardCap.operations, 'number')
  t.is(guardCap.advertisementDigest, undefined)
  t.is(guardCap.completeAdvertisement, undefined)

  const candidateCap = Object.freeze({
    kind: 'candidate',
    identity32: b4a.alloc(32, 1),
    endpoint19: b4a.alloc(19, 2),
    epoch: 1n,
    advertisementDigest: b4a.alloc(32, 5),
    completeAdvertisement: b4a.alloc(260, 6),
    clockIdentity,
    wallNow: clockIdentity.wallNow,
    monotonicNow: clockIdentity.monotonicNow,
    wireExpiresAt: 1000n,
    localDeadline: 1000n
  })

  t.is(candidateCap.kind, 'candidate')
  t.is(b4a.isBuffer(candidateCap.advertisementDigest), true)
  t.is(b4a.isBuffer(candidateCap.completeAdvertisement), true)
  t.is(candidateCap.grantDigest, undefined)
  t.is(candidateCap.runId, undefined)
  t.is(candidateCap.operations, undefined)
})

test('Physical Carrier: forged clock owner and foreign locator cannot mint direct transports', (t) => {
  expectCode(
    t,
    () => createPeerPinnedGuardDirectTransport(fakeEstablishedHandle(), Object.freeze({})),
    'UNAUTHORIZED'
  )
  expectCode(t, () => createPeerCandidateDirectTransport(Object.freeze({}), Object.freeze({})), 'UNAUTHORIZED')
  expectCode(t, () => takePeerDirectRequesterTransport(Object.freeze({})), 'UNAUTHORIZED')
  expectCode(t, () => registerPeerDirectResponder(Object.freeze({}), Object.freeze({})), 'UNAUTHORIZED')
  t.is(destroyPeerDirectResponderRegistration(Object.freeze({})), false)
})

test('Physical Carrier: exchangePeerGuardLink rejects foreign reservation without stranding', (t) => {
  const fakeReservation = Object.freeze({})
  const sendLedger = createPeerLedger({ cells: 10, bytes: 12000n, commands: 10 })
  expectCode(
    t,
    () => exchangePeerGuardLink(fakeReservation, { offer: b4a.alloc(16), generation: 1n, sendLedger }),
    'UNAUTHORIZED'
  )
  // Second call still unauthorized (not permanently exchanging on missing state).
  expectCode(
    t,
    () => exchangePeerGuardLink(fakeReservation, { offer: b4a.alloc(16), generation: 1n, sendLedger }),
    'UNAUTHORIZED'
  )
  // Rejects missing sendLedger
  expectCode(
    t,
    () => exchangePeerGuardLink(fakeReservation, { offer: b4a.alloc(16), generation: 1n }),
    'UNAUTHORIZED'
  )
})

test('Physical Carrier: readPeerGuardPhysicalReservation returns null for unknown and rejects revoked', (t) => {
  const fakeReservation = Object.freeze({})
  const fakeOwner = Object.freeze({})
  t.is(readPeerGuardPhysicalReservation(fakeReservation, fakeOwner), null)
  t.is(readPeerGuardPhysicalReservation(null, fakeOwner), null)
})

test('Physical Carrier: createPeerGuardBootstrapTransport rejects foreign lease', (t) => {
  expectCode(t, () => createPeerGuardBootstrapTransport(Object.freeze({})), 'UNAUTHORIZED')
})

