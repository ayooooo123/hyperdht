const b4a = require('b4a')
const test = require('brittle')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { deriveM3CellIds } = require('../../lib/private/m3-adjacency-runtime')
const {
  consumeSealedRelayCandidateDirectory,
  createRelayCandidateDirectorySink,
  sealRelayCandidateDirectorySink,
  splitRelayPathReservation,
  takeRelayPathReservation
} = require('../../lib/private/relay-candidate-directory')
const {
  CAPACITY_CLASS,
  BRANCH_CLASS,
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
  RouteExtensionSession,
  createRouteExtensionLimits,
  createRouteExtensionSessionRequest,
  takeRouteExtensionTransfer
} = require('../../lib/private/route-extension')

const OFFER_DIGEST = b4a.from(Array.from({ length: 32 }, (_, index) => index))
const NOW = 1_000n

function identityFor(role, ordinal) {
  let found = -1
  for (let value = 1; value < 256; value++) {
    const pair = cryptoSuite.keyPair(b4a.alloc(32, value))
    if (roleForIdentity(pair.publicKey) !== role) continue
    found++
    if (found === ordinal) return pair
  }
  throw new Error('missing deterministic identity')
}

function candidate(role, ordinal, index) {
  const identity = identityFor(role, ordinal)
  const route = cryptoSuite.encryptionKeyPair(b4a.alloc(32, 128 + index))
  const endpoint = encodeCanonicalEndpoint({
    addressFamily: 4,
    addressBytes: b4a.from([198, 18, index, 1]),
    port: 40_000 + index
  })
  const capabilityMask =
    role === ROLE.SAFETY
      ? RELAY_CAPABILITY.CIRCUIT_RELAY_V1
      : RELAY_CAPABILITY.CIRCUIT_RELAY_V1 | RELAY_CAPABILITY.DHT_EXIT_V1
  const signed = signRelayCapabilityAdvertisement(
    {
      relayIdentity: identity.publicKey,
      currentDhtNodeId: deriveM3DhtNodeId(endpoint),
      reachableEndpoint: endpoint,
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
      providerServicePolicyEntries: providerServicePolicyForCapabilities(capabilityMask)
    },
    identity.secretKey
  )
  const canonicalBytes = encodeRelayCapabilityAdvertisement(signed)
  return {
    canonicalBytes,
    digest: digestRelayCapabilityAdvertisement(canonicalBytes, { now: NOW }),
    identity: b4a.from(identity.publicKey),
    canonicalEndpointBytes: b4a.from(endpoint),
    routePublicKey: b4a.from(route.publicKey),
    role,
    capabilityMask,
    epoch: 1n,
    issuedAt: NOW,
    expiresAt: NOW + 30_000n
  }
}

function selectedMiddle() {
  const guard = candidate(ROLE.SAFETY, 0, 1)
  const records = [
    candidate(ROLE.SAFETY, 1, 2),
    candidate(ROLE.SAFETY, 2, 3),
    candidate(ROLE.PRIVATE, 0, 40),
    candidate(ROLE.PRIVATE, 1, 41)
  ]
  const sink = createRelayCandidateDirectorySink({ wallNow: () => NOW, monotonicNow: () => 0n })
  const directory = consumeSealedRelayCandidateDirectory(
    sealRelayCandidateDirectorySink(sink, records, {
    guardIdentity: guard.identity,
    guardEndpoint: guard.canonicalEndpointBytes,
    guardAdvertisementDigest: guard.digest,
    guardEpoch: guard.epoch,
    guardExpiresAt: guard.expiresAt
    })
  )
  const transaction = takeRelayPathReservation(
    directory.reserveInitialPair({ lookupGeneration: 1n, announceGeneration: 1n })
  )
  const split = splitRelayPathReservation(transaction)
  return { transaction, selection: split.lookup.middle }
}

test('M3 adjacency runtime derives exact actor-local cell IDs', (t) => {
  const ids = deriveM3CellIds(OFFER_DIGEST, { crypto: cryptoSuite })
  t.alike(ids.initiatorCellId, b4a.from('c78d0f017fe9b907995002a35ff0d9ef', 'hex'))
  t.alike(ids.responderCellId, b4a.from('1b59923d31c99d089e85e64671f7ce71', 'hex'))

  t.exception(() => deriveM3CellIds(b4a.alloc(31), { crypto: cryptoSuite }))
  t.exception(() => deriveM3CellIds(OFFER_DIGEST, { crypto: { hash: () => b4a.alloc(32) } }))
  t.exception(() =>
    deriveM3CellIds(OFFER_DIGEST, { crypto: { hash: () => b4a.alloc(32, 0x5a) } })
  )
})

test('route extension limits clamp to one exact five-second deadline', (t) => {
  t.alike(createRouteExtensionLimits(Object.freeze({}), () => 1_000n, 9_000n), {
    cellSize: 1200,
    maxCells: 64,
    maxBytes: 65_536,
    maxCommands: 10,
    idleTimeoutMs: 5_000,
    expiresAtMs: 6_000n
  })
  t.is(
    createRouteExtensionLimits(Object.freeze({ maxCommands: 2 }), () => 1_000n, 4_000n)
      .expiresAtMs,
    4_000n
  )
  t.exception(() => createRouteExtensionLimits(Object.freeze({}), () => 1_000n, 1_000n))
})

test('selected evidence opens only EXTEND, EXTENDED, and TAIL_READY', async (t) => {
  const selected = selectedMiddle()
  const trace = []
  const completion = Object.freeze({})
  const nextTail = Object.freeze({ destroy() {} })
  const frames = [b4a.alloc(494, 0x22), b4a.alloc(282, 0x33)]
  const tailControl = {
    sealExtend(options) {
      trace.push('EXTEND_REQUEST_V1')
      t.ok(options.advertisement.byteLength >= 260)
      t.is(options.extensionIndex, 1)
      return b4a.alloc(466, 0x11)
    },
    openExtended(frame) {
      trace.push('EXTENDED_V1')
      t.is(frame.byteLength, 494)
      return completion
    },
    completeClientExtension(value, frame) {
      trace.push('TAIL_READY_V1')
      t.is(value, completion)
      t.is(frame.byteLength, 282)
      return nextTail
    },
    abortClientExtension() {},
    destroy() {}
  }
  const transport = {
    async send() {},
    async receive() { return frames.shift() },
    destroy() {}
  }
  let handle = null
  const request = createRouteExtensionSessionRequest({
    transaction: selected.transaction,
    selection: selected.selection,
    branchClass: BRANCH_CLASS.LOOKUP,
    position: 'middle',
    generation: 1n,
    extensionIndex: 1,
    limits: Object.freeze({}),
    absoluteDeadline: 9_000n,
    signedExpiry: 8_000n,
    now: () => NOW,
    randomBytes: (size) => b4a.alloc(size, 0x44),
    schedule(callback, delay) { handle = { callback, delay }; return handle },
    cancelScheduled(value) { t.is(value, handle) },
    cancel() {},
    tailControl,
    tailControlTransportFactory() { return transport }
  })
  const session = new RouteExtensionSession(request)
  const transfer = await session.open()
  t.alike(trace, ['EXTEND_REQUEST_V1', 'EXTENDED_V1', 'TAIL_READY_V1'])
  const moved = takeRouteExtensionTransfer(transfer)
  t.is(moved.tailControl, nextTail)
  t.is(moved.transport, transport)
})
