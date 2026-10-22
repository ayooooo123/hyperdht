'use strict'

const test = require('brittle')
const b4a = require('b4a')
const crypto = require('hypercore-crypto')
const sodium = require('sodium-universal')

const { PrivateRouteError } = require('../../lib/private/errors')
const {
  openPeerGuardLink,
  openPeerNeighborLink,
  createPeerLinkResponder,
  destroyPeerLinkResponder,
  takePeerLinkResponderBinding,
  takePeerLinkReplyAttempt,
  takePeerEstablishedLink,
  takePeerEstablishedProof,
  destroyPeerEstablishedLink,
  destroyTakenPeerEstablishedLink,
  takePeerM3AuthenticatedBranchBinding
} = require('../../lib/private/peer-guard-link')
const {
  encodePeerTransport,
  decodePeerTransport,
  encodePeerLinkReply,
  decodePeerLinkReply
} = require('../../lib/private/peer-transport-wire')
const { digestPeerLimits } = require('../../lib/private/peer-crypto')
const {
  chargePeerLedger,
  createPeerBranchSlots,
  readPeerBranchSlots
} = require('../../lib/private/peer-ledger')
const {
  PEER_MESSAGE_ID,
  PEER_BRANCH_CLASS,
  PEER_LINK_ROLE,
  PEER_PROTOCOL_VERSION,
  encodePeerObject
} = require('../../lib/private/peer-protocol')
const { createPeerRelayOwner, readPeerRelayOwner } = require('../../lib/private/peer-capability')
const {
  UdxCellEndpoint,
  TEST_ONLY_UDX_ADAPTER_ISSUER,
  createM3CellLinkTransferIssuer,
  registerSharedGuardPeerBranchResponder
} = require('../../lib/private/udx-cell-endpoint')
const { LinkDirectory, signTopologyGrant } = require('../../lib/private/topology-grant')
const { BootstrapEnvelopeCodec } = require('../../lib/private/bootstrap-envelope')
const { createLinkSetupAuthority } = require('../../lib/private/link-setup')
const { PROTOCOL_VERSION, LINK_OPERATION, TOPOLOGY_ROLE } = require('../../lib/private/protocol')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  createPeerM3AdjacencyAuthority,
  adoptPeerEstablishedLink,
  isPeerM3Runtime,
  beginPeerM3BranchTeardown
} = require('../../lib/private/peer-m3-adjacency-runtime')
const { destroyGuardLease } = require('../../lib/private/guard-lease')
const { fakeClock, slotPool, peerGuardFixture } = require('./peer-native-fixture')

const seed = (val) => b4a.alloc(32, val)

function createFakeNetwork() {
  const network = new Map()
  class FakeSocket {
    constructor() {
      this.network = network
      this.port = null
      this.host = null
      this.listeners = new Map()
      this.closed = false
    }
    on(event, cb) {
      if (!this.listeners.has(event)) this.listeners.set(event, [])
      this.listeners.get(event).push(cb)
    }
    emit(event, ...args) {
      const cbs = this.listeners.get(event) || []
      for (const cb of cbs) cb(...args)
    }
    bind(port, host) {
      this.port = port
      this.host = host
      this.network.set(`${host}:${port}`, this)
      return true
    }
    send(packet, port, host) {
      const out = b4a.from(packet)
      const peer = this.network.get(`${host}:${port}`)
      if (!peer) return true
      queueMicrotask(() =>
        peer.emit('message', b4a.from(out), { host: this.host, port: this.port })
      )
      return true
    }
    close() {
      this.closed = true
      this.network.delete(`${this.host}:${this.port}`)
      return true
    }
  }
  const adapterIssuer = require('../../lib/private/udx-cell-endpoint')[TEST_ONLY_UDX_ADAPTER_ISSUER]
  const fakeFactory = () => ({
    create() {
      return {
        createSocket() {
          return new FakeSocket()
        }
      }
    }
  })
  return { adapterIssuer, fakeFactory }
}

function buildSignatureInput(messageId, label, body) {
  const labelLen = label.byteLength
  const bodyLen = body.byteLength
  const headerOffset = 2 + labelLen
  const input = b4a.allocUnsafe(headerOffset + 8 + bodyLen)
  input.writeUInt16BE(labelLen, 0)
  input.set(label, 2)
  input.writeUInt32BE(PEER_PROTOCOL_VERSION, headerOffset)
  input.writeUInt16BE(messageId, headerOffset + 4)
  input.writeUInt16BE(bodyLen, headerOffset + 6)
  input.set(body, headerOffset + 8)
  return input
}

test('responder binding.accept and takePeerLinkReplyAttempt produce genuine 695-byte v3 packet with R/F/C proof and verified sendLedger', async (t) => {
  const { adapterIssuer, fakeFactory } = createFakeNetwork()

  let leftSession = null
  let rightSession = null

  const leftEndpoint = adapterIssuer.createUdxCellEndpointForTest(
    {
      host: '127.0.0.1',
      port: 48001,
      onBootstrap(packet) {
        if (leftSession) void leftSession.receive(packet)
      },
      onCell() {
        return true
      },
      onLinkFailure() {}
    },
    adapterIssuer.createTestUdxAdapterAuthority(fakeFactory)
  )

  const rightEndpoint = adapterIssuer.createUdxCellEndpointForTest(
    {
      host: '127.0.0.1',
      port: 48002,
      onBootstrap(packet) {
        if (rightSession) void rightSession.receive(packet)
      },
      onCell() {
        return true
      },
      onLinkFailure() {}
    },
    adapterIssuer.createTestUdxAdapterAuthority(fakeFactory)
  )

  await leftEndpoint.bind()
  await rightEndpoint.bind()

  const authority = cryptoSuite.keyPair(seed(0x01))
  const leftKey = cryptoSuite.keyPair(seed(0x02))
  const rightKey = cryptoSuite.keyPair(seed(0x03))
  const rightRouteKey = cryptoSuite.encryptionKeyPair(seed(0x04))
  const runId32 = seed(0x05)

  const grant = signTopologyGrant(
    {
      version: PROTOCOL_VERSION,
      format: 0,
      grantId32: seed(0x06),
      endpointA: {
        identity32: leftKey.publicKey,
        role: TOPOLOGY_ROLE.SAFETY_GUARD,
        host: '127.0.0.1',
        port: 48001,
        operations: LINK_OPERATION.INITIATE
      },
      endpointB: {
        identity32: rightKey.publicKey,
        role: TOPOLOGY_ROLE.SAFETY_FINAL,
        host: '127.0.0.1',
        port: 48002,
        operations: LINK_OPERATION.ACCEPT
      },
      epoch: 1n,
      notBefore: 0n,
      expiresAt: 60_000n,
      runId32
    },
    authority.secretKey
  )

  function makeDirectory(local, localRole) {
    const dir = new LinkDirectory({
      localIdentity32: local.publicKey,
      localRole,
      authorityPublicKey: authority.publicKey,
      epoch: 1n,
      runId32,
      now: () => 1n,
      schedule: setTimeout,
      cancel: clearTimeout,
      onClose() {}
    })
    return dir
  }

  const leftDir = makeDirectory(leftKey, TOPOLOGY_ROLE.SAFETY_GUARD)
  const rightDir = makeDirectory(rightKey, TOPOLOGY_ROLE.SAFETY_FINAL)
  const leftDigest = leftDir.add(grant)
  const rightDigest = rightDir.add(grant)

  const leftHandle = leftDir.authorize({
    digest32: leftDigest,
    operation: LINK_OPERATION.INITIATE,
    localIdentity32: leftKey.publicKey,
    localRole: TOPOLOGY_ROLE.SAFETY_GUARD,
    peerIdentity32: rightKey.publicKey,
    peerRole: TOPOLOGY_ROLE.SAFETY_FINAL,
    epoch: 1n,
    runId32
  })

  const rightHandle = rightDir.authorize({
    digest32: rightDigest,
    operation: LINK_OPERATION.ACCEPT,
    localIdentity32: rightKey.publicKey,
    localRole: TOPOLOGY_ROLE.SAFETY_FINAL,
    peerIdentity32: leftKey.publicKey,
    peerRole: TOPOLOGY_ROLE.SAFETY_GUARD,
    epoch: 1n,
    runId32
  })

  const staticPair = cryptoSuite.encryptionKeyPair(seed(0x07))
  let started = Date.now()
  const now = () => Date.now() - started

  function linkOptions(handle, mode) {
    const initiate = mode === 'initiate'
    const common = {
      circuitId: b4a.alloc(16, 0x11),
      epoch: 1n,
      initiatorIdentity: leftKey.publicKey,
      responderIdentity: rightKey.publicKey,
      initiatorLocalId: b4a.alloc(16, 0x12),
      responderLocalId: b4a.alloc(16, 0x13),
      expiresAt: 60_000n
    }
    return {
      mode,
      codec: new BootstrapEnvelopeCodec({
        linkHandle: handle,
        localIdentitySecretKey: initiate ? leftKey.secretKey : rightKey.secretKey,
        padding: (size) => b4a.alloc(size, 0)
      }),
      linkSetup: createLinkSetupAuthority({ now, randomBytes: (size) => b4a.alloc(size, 1) }),
      setup: initiate
        ? {
            ...common,
            responderStaticKey: staticPair.publicKey,
            initiatorIdentitySecretKey: leftKey.secretKey
          }
        : {
            ...common,
            responderStaticSecretKey: staticPair.secretKey,
            responderIdentitySecretKey: rightKey.secretKey
          },
      now,
      schedule: setTimeout,
      cancel: clearTimeout,
      randomBytes: (size) => b4a.alloc(size, 2),
      absoluteDeadline: now() + 10_000,
      signedExpiry: 60_000,
      authorizedExpiry: 60_000
    }
  }

  rightSession = rightEndpoint.openLink(rightHandle, linkOptions(rightHandle, 'accept'))
  leftSession = leftEndpoint.openLink(leftHandle, linkOptions(leftHandle, 'initiate'))
  const leftEstablished = await leftSession.open()
  t.ok(leftEstablished, 'initiator session opened')

  const rightEstablished = rightSession.established
  t.ok(rightEstablished, 'responder session opened and established handle present')

  const clock = fakeClock()
  const clockIdentity = Object.freeze({})

  const rightRelayOwner = createPeerRelayOwner({
    endpoint: rightEndpoint,
    identityKeyPair: rightKey,
    routeKeyPair: rightRouteKey,
    advertisementFields: {
      relayIdentity32: rightKey.publicKey,
      currentDhtNodeId32: crypto.hash(rightKey.publicKey),
      reachableEndpoint: { host: '127.0.0.1', port: 48002 },
      routeEncryptionPublicKey32: rightRouteKey.publicKey,
      capabilityMask: 9,
      minimumVersion: 3,
      maximumVersion: 3,
      datagramReplayWindow: 64,
      maxConcurrentCircuits: 2,
      capacityClass: 1,
      maxCells: 20,
      maxBytes: 24000,
      maxCommands: 11,
      idleTimeoutMs: 30000,
      maxQueuedBytes: 524288,
      epoch: 1n,
      issuedAt: 1000n,
      expiresAt: 2_000_000n,
      policyCount: 0
    },
    clockIdentity,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer
  })

  // Two admitted branches at once, each taking its own slot with fresh authority.
  const branchSlots = createPeerBranchSlots(2)
  const spent = (kind) => readPeerBranchSlots(branchSlots).spent[kind]

  const adoptedRuntimes = []
  const responder = createPeerLinkResponder(rightRelayOwner, {
    onEstablished(handle) {
      const runtime = adoptPeerEstablishedLink(responderAuthority, handle)
      adoptedRuntimes.push(runtime)
      return runtime
    },
    branchSlots
  })
  t.ok(responder, 'responder created')

  registerSharedGuardPeerBranchResponder(rightEstablished, responder)
  const binding = takePeerLinkResponderBinding(responder, rightEstablished, rightEndpoint)
  t.ok(binding, 'responder binding taken')

  const rightOwnerInfo = readPeerRelayOwner(rightRelayOwner, rightEndpoint)
  const responderAuthority = createPeerM3AdjacencyAuthority(rightOwnerInfo)
  t.teardown(() => responderAuthority.destroy())

  const reverseLimits = {
    cellSize: 1200,
    maxCells: 20,
    maxBytes: 24000,
    maxCommands: 11,
    idleTimeoutMs: 30000,
    expiresAt: 50_000n
  }
  const forwardLimits = {
    cellSize: 1200,
    maxCells: 21,
    maxBytes: 25200,
    maxCommands: 12,
    idleTimeoutMs: 31000,
    expiresAt: 50_000n
  }

  const candidateAuthorityCommitment = b4a.alloc(32, 0x55)
  const offerFields = {
    advertisementDigest: rightOwnerInfo.advertisementDigest32,
    initiatorIdentity: leftKey.publicKey,
    responderIdentity: rightKey.publicKey,
    initiatorRole: PEER_LINK_ROLE.SAFETY_RELAY,
    responderRole: PEER_LINK_ROLE.SAFETY_RELAY,
    branchClass: PEER_BRANCH_CLASS.PEER,
    branchId: b4a.alloc(16, 0x61),
    circuitId: b4a.alloc(16, 0x62),
    generation: 1n,
    extensionIndex: 1,
    initiatorLinkEphemeralPublicKey: b4a.alloc(32, 0x63),
    clientTailEphemeralPublicKey: b4a.alloc(32, 0x64),
    clientNonce: b4a.alloc(32, 0x65),
    payloadParametersDigest: b4a.alloc(32, 0x66),
    requestedLimits: reverseLimits,
    offerDeadline: 3000n,
    initiatorForwardLimits: forwardLimits,
    candidateAuthorityCommitment
  }

  function signOffer(fields) {
    const unsigned = encodePeerTransport(PEER_MESSAGE_ID.PEER_LINK_OFFER_V2, fields, b4a.alloc(64))
    const input = buildSignatureInput(
      PEER_MESSAGE_ID.PEER_LINK_OFFER_V2,
      b4a.from('hyperdht-private-routes/m3/link-offer/v2'),
      unsigned.subarray(8, 368)
    )
    const signature = b4a.alloc(64)
    sodium.crypto_sign_detached(signature, input, leftKey.secretKey)
    return encodePeerTransport(PEER_MESSAGE_ID.PEER_LINK_OFFER_V2, fields, signature)
  }
  let physicalReservations = 0
  const reservePhysical = () => {
    physicalReservations++
    return createM3CellLinkTransferIssuer(rightEndpoint, rightEstablished, { sharedGuard: true })
  }
  const rejection = (fn) => {
    try {
      fn()
      return null
    } catch (err) {
      return err.code
    }
  }
  t.is(
    rejection(() => createPeerLinkResponder(rightRelayOwner, { branchSlots })),
    'INVALID_ROUTE',
    'a responder requires an owner that synchronously adopts each established link'
  )
  const invalidProfiles = [
    ['reverse cells', 'requestedLimits', { ...reverseLimits, maxCells: 21, maxBytes: 25200 }],
    ['reverse bytes', 'requestedLimits', { ...reverseLimits, maxBytes: 24001 }],
    ['reverse commands', 'requestedLimits', { ...reverseLimits, maxCommands: 12 }],
    ['reverse idle', 'requestedLimits', { ...reverseLimits, idleTimeoutMs: 30001 }],
    ['reverse parent expiry', 'requestedLimits', { ...reverseLimits, expiresAt: 60001n }],
    [
      'forward setup and closure floor',
      'initiatorForwardLimits',
      { ...forwardLimits, maxCells: 17, maxBytes: 20400 }
    ],
    ['forward byte geometry', 'initiatorForwardLimits', { ...forwardLimits, maxBytes: 25199 }],
    ['forward allocation command', 'initiatorForwardLimits', { ...forwardLimits, maxCommands: 1 }],
    ['forward parent expiry', 'initiatorForwardLimits', { ...forwardLimits, expiresAt: 60001n }]
  ]
  for (const [name, field, limits] of invalidProfiles) {
    t.is(
      rejection(() =>
        binding.accept({
          offer: signOffer({ ...offerFields, [field]: limits }),
          established: rightEstablished,
          reservePhysical
        })
      ),
      'UNAUTHORIZED',
      name
    )
  }
  t.is(physicalReservations, 0, 'invalid authenticated profiles do not reserve Native capacity')
  const completeOffer432 = signOffer(offerFields)

  const replyToken = binding.accept({
    offer: completeOffer432,
    established: rightEstablished,
    reservePhysical
  })
  t.ok(replyToken, 'offer accepted by responder')
  t.is(physicalReservations, 1, 'the larger asymmetric forward partition is admitted locally')

  const attempt = takePeerLinkReplyAttempt(replyToken, rightEstablished)
  t.ok(attempt, 'reply attempt produced')
  t.is(attempt.packet.byteLength, 695, 'packet is genuine 695-byte v3 reply cell')

  const { accept285, proofWire } = decodePeerLinkReply(attempt.packet, 1)
  t.is(accept285.byteLength, 285, 'accept component is 285 bytes')
  t.is(proofWire.byteLength, 410, 'proof component is 410 bytes')

  const decodedProof = decodePeerTransport(proofWire)
  t.is(decodedProof.messageId, PEER_MESSAGE_ID.PEER_REDACTED_RESPONDER_PROOF_V2)
  t.is(decodedProof.fields.extensionIndex, 1)
  t.is(decodedProof.fields.expiresAt, reverseLimits.expiresAt)
  t.alike(
    decodedProof.fields.responderLinkEphemeralPublicKey,
    decodePeerTransport(accept285).fields.responderLinkEphemeralPublicKey,
    'the proof names the link ephemeral the signed ACCEPT carries'
  )

  const expectedLimitsDigest = digestPeerLimits(
    accept285.subarray(155, 181),
    completeOffer432.subarray(310, 336),
    candidateAuthorityCommitment
  )
  t.alike(
    decodedProof.fields.admittedLimitsDigest,
    expectedLimitsDigest,
    'admittedLimitsDigest is digestPeerLimits(R26, F26, C32)'
  )

  // The admitted branch holds exactly its offered rows less closure: its send partition is
  // the requested reverse row and its receive partition the initiator's forward row.
  t.alike(
    readPeerBranchSlots(branchSlots).reserved,
    {
      sendLedger: { cells: 10, bytes: 12000n, commands: 10 },
      receiveLedger: { cells: 11, bytes: 13200n, commands: 11 },
      teardownSendLedger: { cells: 10, bytes: 12000n, commands: 1 },
      teardownReceiveLedger: { cells: 10, bytes: 12000n, commands: 1 }
    },
    'the admitted branch holds its exact rows and two disjoint closure partitions'
  )
  const successorFields = {
    ...offerFields,
    branchId: b4a.alloc(16, 0x71),
    circuitId: b4a.alloc(16, 0x72),
    initiatorForwardLimits: reverseLimits,
    clientNonce: b4a.alloc(32, 0x73)
  }
  const otherBinding = takePeerLinkResponderBinding(responder, rightEstablished, rightEndpoint)
  const successorReply = otherBinding.accept({
    offer: signOffer(successorFields),
    established: rightEstablished,
    reservePhysical
  })
  const successorAttempt = takePeerLinkReplyAttempt(successorReply, rightEstablished)
  chargePeerLedger(successorAttempt.sendLedger, { cells: 1, bytes: 1200n, commands: 0 })
  const thirdFields = {
    ...successorFields,
    branchId: b4a.alloc(16, 0x81),
    circuitId: b4a.alloc(16, 0x82),
    clientNonce: b4a.alloc(32, 0x83)
  }
  const beforeCap = physicalReservations
  t.is(
    rejection(() =>
      otherBinding.accept({
        offer: signOffer(thirdFields),
        established: rightEstablished,
        reservePhysical
      })
    ),
    'ERR_PRIVACY_UNAVAILABLE',
    'signed concurrency is shared across responder bindings'
  )
  t.is(physicalReservations, beforeCap, 'the signed concurrency cap precedes Native reservation')

  for (let received = 1; received < 8; received++) {
    binding.accept({ offer: completeOffer432, established: rightEstablished, reservePhysical })
  }
  t.is(
    rejection(() =>
      binding.accept({
        offer: completeOffer432,
        established: rightEstablished,
        reservePhysical
      })
    ),
    'UNAUTHORIZED',
    'the ninth authenticated OFFER ends its original setup owner'
  )
  t.is(isPeerM3Runtime(adoptedRuntimes[0]), false, 'ninth OFFER revokes its adopted runtime')
  t.is(isPeerM3Runtime(adoptedRuntimes[1]), true, 'the independent sibling is still live')
  t.is(
    spent('receiveLedger').cells,
    10,
    'nine first-branch arrivals and one sibling arrival are retained'
  )
  t.is(spent('receiveLedger').commands, 2, 'retransmissions allocate no new command')
  t.is(
    rejection(() =>
      binding.accept({
        offer: completeOffer432,
        established: rightEstablished,
        reservePhysical
      })
    ),
    'UNAUTHORIZED',
    'the retired digest cannot allocate a replacement'
  )
  t.is(physicalReservations, beforeCap, 'replays never reserve a new physical issuer')
  t.is(
    rejection(() =>
      otherBinding.accept({
        offer: signOffer({ ...successorFields, clientNonce: b4a.alloc(32, 0x99) }),
        established: rightEstablished,
        reservePhysical
      })
    ),
    'UNAUTHORIZED',
    'a signed changed OFFER cannot replace its logical branch'
  )
  t.is(
    isPeerM3Runtime(adoptedRuntimes[1]),
    false,
    'changed OFFER revokes its original adopted runtime'
  )
  t.is(
    spent('receiveLedger').cells,
    11,
    'the changed OFFER is charged to the original owner before a third admission'
  )
  t.is(
    rejection(() =>
      binding.accept({
        offer: signOffer(successorFields),
        established: rightEstablished,
        reservePhysical
      })
    ),
    'UNAUTHORIZED',
    'logical conflict retains the spent tombstone across bindings'
  )
  t.is(physicalReservations, beforeCap, 'neither logical conflict allocates a replacement')
  t.is(
    rejection(() =>
      otherBinding.accept({
        offer: signOffer(thirdFields),
        established: rightEstablished,
        reservePhysical
      })
    ),
    'ERR_PRIVACY_UNAVAILABLE',
    'adopted Native closure owners retain both admission slots'
  )

  for (let elapsed = 0; elapsed < 5000; elapsed += 250) {
    clock.advance(250)
    await new Promise((resolve) => setImmediate(resolve))
  }
  const thirdOffer = signOffer({
    ...thirdFields,
    offerDeadline: clock.wallNow() + 2000n
  })
  const thirdReply = otherBinding.accept({
    offer: thirdOffer,
    established: rightEstablished,
    reservePhysical
  })
  t.is(
    physicalReservations,
    beforeCap + 1,
    'completed Native closure returns capacity for a fresh setup deadline'
  )
  clock.advance(2001)
  t.is(
    rejection(() =>
      otherBinding.accept({
        offer: thirdOffer,
        established: rightEstablished,
        reservePhysical
      })
    ),
    'UNAUTHORIZED',
    'the original deadline ends reply authority'
  )
  t.is(
    spent('receiveLedger').cells,
    13,
    'the first late authenticated arrival is accounted before retirement'
  )
  t.is(
    rejection(() => takePeerLinkReplyAttempt(thirdReply, rightEstablished)),
    'UNAUTHORIZED'
  )

  const bindingSlots = slotPool()
  let bindingRuntime = null
  const bindingResponder = createPeerLinkResponder(rightRelayOwner, {
    ...bindingSlots,
    onEstablished(handle) {
      bindingRuntime = adoptPeerEstablishedLink(responderAuthority, handle)
      revokedBinding.destroy()
      return bindingRuntime
    }
  })
  t.teardown(() => destroyPeerLinkResponder(bindingResponder))
  const revokedBinding = takePeerLinkResponderBinding(
    bindingResponder,
    rightEstablished,
    rightEndpoint
  )
  t.is(
    rejection(() =>
      revokedBinding.accept({
        offer: signOffer({
          ...successorFields,
          branchId: b4a.alloc(16, 0x91),
          circuitId: b4a.alloc(16, 0x92),
          clientNonce: b4a.alloc(32, 0x93),
          offerDeadline: clock.wallNow() + 2000n
        }),
        established: rightEstablished,
        reservePhysical
      })
    ),
    'UNAUTHORIZED',
    'destroying only the binding prevents row publication'
  )
  t.ok(
    bindingRuntime,
    'the callback adopted the authenticated branch before destroying its binding'
  )
  t.is(isPeerM3Runtime(bindingRuntime), false, 'binding destruction revokes the adopted runtime')
  t.is(
    isPeerM3Runtime(adoptedRuntimes[2]),
    true,
    'binding destruction preserves the established sibling'
  )

  destroyPeerLinkResponder(responder)
  responderAuthority.destroy()
  await leftSession.close()
  await rightSession.close()
  await leftEndpoint.close()
  await rightEndpoint.close()
  await new Promise((resolve) => setImmediate(resolve))
  t.is(readPeerBranchSlots(branchSlots).live, 0, 'every admitted branch has retired')
  t.is(readPeerBranchSlots(bindingSlots.branchSlots).live, 0)
  t.is(spent('sendLedger').cells, 1, 'closing adopted owners never refunds spent work')
  t.is(spent('sendLedger').commands, 3, 'released admissions never refund allocation commands')
  leftDir.destroy()
  rightDir.destroy()
})

// Hop zero takes consuming custody of the caller's client tail ephemeral secret. Once admitted,
// openPeerGuardLink erases it in place as soon as both tail agreements exist, and on every
// failure, timeout or cancellation. A refusal before admission leaves it with the caller.
test('A0 erases an admitted client tail ephemeral on every outcome and leaves a refused one with its caller', async (t) => {
  const setup = await peerGuardFixture(t, 47711, 47712)
  const erased = (buffer) => buffer.every((byte) => byte === 0)
  const tail = () => {
    const pair = cryptoSuite.encryptionKeyPair()
    return {
      secretKey: pair.secretKey,
      overrides: {
        clientTailEphemeralPublicKey: pair.publicKey,
        clientTailSecretKey: pair.secretKey
      }
    }
  }
  const outcome = (promise) =>
    promise.then(
      (handle) => ({ handle }),
      (error) => ({ error })
    )

  // Refused before admission: the candidate and the secret stay with the caller.
  const candidate = await setup.discover()
  const refused = tail()
  const retained = b4a.from(refused.secretKey)
  let error = null
  try {
    await setup.open(candidate, { ...refused.overrides, extensionIndex: 1 })
  } catch (err) {
    error = err
  }
  t.is(error && error.code, 'INVALID_ROUTE', 'a malformed A0 is refused before admission')
  t.alike(refused.secretKey, retained, 'a refusal before admission leaves the secret intact')

  // Success: the same candidate still admits, and the secret is gone once the link exists.
  const opened = tail()
  const runtime = adoptPeerEstablishedLink(
    setup.localAuthority,
    await setup.open(candidate, opened.overrides)
  )
  t.ok(erased(opened.secretKey), 'an established A0 has erased the secret')
  t.is(await beginPeerM3BranchTeardown(runtime, b4a.alloc(16, 0x91)), true)

  // A genuine ACCEPT that names another predecessor endpoint is refused after the exchange.
  const misdirected = tail()
  const refusedAccept = await outcome(
    setup.open(await setup.discover(), {
      ...misdirected.overrides,
      relayOwner: setup.sourceOwnerAdvertising(47713)
    })
  )
  t.is(refusedAccept.error && refusedAccept.error.code, 'UNAUTHORIZED', 'the ACCEPT is refused')
  t.ok(erased(misdirected.secretKey), 'a refused ACCEPT erases the secret')

  // The static tail agreement succeeds and the ephemeral one fails.
  const failing = tail()
  const scalarmult = sodium.crypto_scalarmult
  let agreements = 0
  sodium.crypto_scalarmult = function (output, secretKey, publicKey) {
    if (secretKey === failing.secretKey && ++agreements === 2) {
      throw new Error('second tail agreement failure')
    }
    return scalarmult.call(this, output, secretKey, publicKey)
  }
  let failedAgreement = null
  try {
    failedAgreement = await outcome(setup.open(await setup.discover(), failing.overrides))
  } finally {
    sodium.crypto_scalarmult = scalarmult
  }
  t.is(agreements, 2, 'the first tail agreement succeeded before the second failed')
  t.is(failedAgreement.error && failedAgreement.error.code, 'INVALID_ROUTE')
  t.ok(erased(failing.secretKey), 'a failed second agreement erases the secret')

  // Timeout: every guard reply is lost until the A0 deadline passes.
  const socket = setup.fixture.rightObserver.socket
  const send = socket.send
  const late = tail()
  const lateCandidate = await setup.discover()
  socket.send = () => true
  let timedOut = null
  try {
    const pending = outcome(setup.open(lateCandidate, late.overrides))
    for (let step = 0; step < 10; step++) {
      setup.clock.advance(250)
      await new Promise(setImmediate)
    }
    timedOut = await pending
  } finally {
    socket.send = send
  }
  t.ok(timedOut.error instanceof PrivateRouteError, 'an A0 without an ACCEPT fails at its deadline')
  t.ok(erased(late.secretKey), 'a timed-out A0 erases the secret')

  // Cancellation: destroying the guard lease ends a pending A0 before its deadline.
  const doomed = tail()
  const doomedCandidate = await setup.discover()
  socket.send = () => true
  let cancelled = null
  try {
    const pending = outcome(setup.open(doomedCandidate, doomed.overrides))
    await new Promise(setImmediate)
    destroyGuardLease(setup.lease)
    cancelled = await Promise.race([
      pending,
      new Promise((resolve) => setTimeout(() => resolve({ stalled: true }), 1000))
    ])
  } finally {
    socket.send = send
  }
  t.ok(cancelled.error instanceof PrivateRouteError, 'destroying the lease ends the pending A0')
  t.ok(erased(doomed.secretKey), 'a cancelled A0 erases the secret')
})
