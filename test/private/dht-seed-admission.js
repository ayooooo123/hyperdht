'use strict'

const test = require('brittle')
const b4a = require('b4a')

const activation = require('../../lib/private/final-exit-activation')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { encodeDestinationRef } = require('../../lib/private/destination-ref')
const { PrivateRouteError } = require('../../lib/private/errors')
const { BRANCH_CLASS, DESTINATION_VALIDATION_CLASS } = require('../../lib/private/protocol')
const { encodeDhtExitSeeds, signDhtExitSeeds } = require('../../lib/private/dht-exit-seeds')
const {
  abortDhtSeedAdmission,
  commitDhtSeedAdmission,
  consumeBranchSeedReady,
  createDhtSeedAdmissionAuthority,
  createLiveOpaqueDestinations,
  destroyLiveOpaqueDestinations,
  revokeDhtSeedAdmissionAuthority,
  sealDhtSeedAdmission,
  stageDhtSeedAdmission
} = require('../../lib/private/opaque-destination')

const TEST_ONLY_ENDPOINT_DHT_EXIT_OPEN_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-endpoint-dht-exit-open-issuer'
)

function seed(value, size = 32) {
  return b4a.alloc(size, value)
}

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

function fixture(options = {}) {
  const exit = cryptoSuite.keyPair(seed(0x70))
  const wallNow = options.wallNow || (() => 1_000n)
  const monotonicNow = options.monotonicNow || (() => 1_000n)
  const owner = createLiveOpaqueDestinations({
    branch: BRANCH_CLASS.LOOKUP,
    circuitId: seed(0x12, 16),
    generation: 7n,
    expiresAt: 20_000n,
    wallNow,
    monotonicNow
  })
  const endpointOpenAuthority = activation[TEST_ONLY_ENDPOINT_DHT_EXIT_OPEN_ISSUER].create({
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: seed(0x11, 16),
    circuitId: seed(0x12, 16),
    generation: 7n,
    exitIdentity: exit.publicKey,
    finalTranscriptDigest: seed(0x14),
    expiresAt: 20_000n,
    absoluteDeadline: options.absoluteDeadline || 5_000n,
    controlKey: seed(0x15),
    controlNoncePrefix: seed(0x16, 16)
  })
  const destinationRef = encodeDestinationRef({
    id: seed(0x31),
    handle: b4a.concat([
      b4a.from([1, DESTINATION_VALIDATION_CLASS.DHT_NODE_HANDLE]),
      seed(0x41, 128)
    ])
  })
  const verifiedSeeds = encodeDhtExitSeeds(
    signDhtExitSeeds(
      {
        branchClass: BRANCH_CLASS.LOOKUP,
        branchId: seed(0x11, 16),
        circuitId: seed(0x12, 16),
        generation: 7n,
        exitIdentity: exit.publicKey,
        seedSetNonce: seed(0x50),
        destinationRefs: [destinationRef]
      },
      exit.secretKey
    )
  )
  return { owner, endpointOpenAuthority, verifiedSeeds }
}

test('DHT seed admission publishes destinations atomically and yields branch readiness', (t) => {
  t.is(typeof createDhtSeedAdmissionAuthority, 'function')
  t.is(typeof stageDhtSeedAdmission, 'function')
  const { owner, endpointOpenAuthority, verifiedSeeds } = fixture()
  const authority = createDhtSeedAdmissionAuthority(owner, endpointOpenAuthority)
  t.alike(Reflect.ownKeys(authority), [])
  t.is(stageDhtSeedAdmission(authority, verifiedSeeds), true)
  const admission = sealDhtSeedAdmission(authority)
  const committed = commitDhtSeedAdmission(admission)
  t.alike(Object.keys(committed), ['destinations', 'branchSeedReady'])
  t.is(committed.destinations.length, 1)
  t.alike(Reflect.ownKeys(committed.destinations[0]), [])
  t.alike(Reflect.ownKeys(committed.branchSeedReady), [])
  const ready = consumeBranchSeedReady(committed.branchSeedReady)
  t.is(ready.branchClass, BRANCH_CLASS.LOOKUP)
  t.is(ready.generation, 7n)
  expectCode(t, () => consumeBranchSeedReady(committed.branchSeedReady), 'ERR_REPLAY')
  t.is(destroyLiveOpaqueDestinations(owner), undefined)
})

test('DHT seed admission revoke and abort publish nothing', (t) => {
  const first = fixture()
  const authority = createDhtSeedAdmissionAuthority(first.owner, first.endpointOpenAuthority)
  t.is(revokeDhtSeedAdmissionAuthority(authority), true)
  expectCode(t, () => stageDhtSeedAdmission(authority, first.verifiedSeeds), 'INVALID_ROUTE')
  destroyLiveOpaqueDestinations(first.owner)

  const second = fixture()
  const staged = createDhtSeedAdmissionAuthority(second.owner, second.endpointOpenAuthority)
  stageDhtSeedAdmission(staged, second.verifiedSeeds)
  const admission = sealDhtSeedAdmission(staged)
  t.is(abortDhtSeedAdmission(admission), true)
  expectCode(t, () => commitDhtSeedAdmission(admission), 'INVALID_ROUTE')
  destroyLiveOpaqueDestinations(second.owner)
})

test('DHT seed admission owner destroy revokes every pending capability', (t) => {
  const first = fixture()
  const staged = createDhtSeedAdmissionAuthority(first.owner, first.endpointOpenAuthority)
  stageDhtSeedAdmission(staged, first.verifiedSeeds)
  destroyLiveOpaqueDestinations(first.owner)
  expectCode(t, () => sealDhtSeedAdmission(staged), 'INVALID_ROUTE')

  const second = fixture()
  const authority = createDhtSeedAdmissionAuthority(second.owner, second.endpointOpenAuthority)
  stageDhtSeedAdmission(authority, second.verifiedSeeds)
  const admission = sealDhtSeedAdmission(authority)
  destroyLiveOpaqueDestinations(second.owner)
  expectCode(t, () => commitDhtSeedAdmission(admission), 'INVALID_ROUTE')

  const third = fixture()
  const committing = createDhtSeedAdmissionAuthority(third.owner, third.endpointOpenAuthority)
  stageDhtSeedAdmission(committing, third.verifiedSeeds)
  const committed = commitDhtSeedAdmission(sealDhtSeedAdmission(committing))
  destroyLiveOpaqueDestinations(third.owner)
  expectCode(t, () => consumeBranchSeedReady(committed.branchSeedReady), 'ERR_REPLAY')
})

test('DHT seed admission rejects unsigned objects and late sealed commits', (t) => {
  const unsigned = fixture()
  const unsignedAuthority = createDhtSeedAdmissionAuthority(
    unsigned.owner,
    unsigned.endpointOpenAuthority
  )
  expectCode(t, () => stageDhtSeedAdmission(unsignedAuthority, {}), 'INVALID_ROUTE')
  destroyLiveOpaqueDestinations(unsigned.owner)

  let monotonic = 1_000n
  const late = fixture({ monotonicNow: () => monotonic })
  const lateAuthority = createDhtSeedAdmissionAuthority(late.owner, late.endpointOpenAuthority)
  stageDhtSeedAdmission(lateAuthority, late.verifiedSeeds)
  const admission = sealDhtSeedAdmission(lateAuthority)
  monotonic = 5_000n
  expectCode(t, () => commitDhtSeedAdmission(admission), 'ERR_DESTROYED')
  const boundary = fixture({ monotonicNow: () => 5_000n })
  expectCode(
    t,
    () => createDhtSeedAdmissionAuthority(boundary.owner, boundary.endpointOpenAuthority),
    'ERR_AUTHENTICATION'
  )
  destroyLiveOpaqueDestinations(boundary.owner)

  destroyLiveOpaqueDestinations(late.owner)
})
