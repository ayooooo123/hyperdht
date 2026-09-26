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
  createPeerLedger,
  readPeerLedger,
  chargePeerLedger
} = require('../../lib/private/peer-ledger')
const {
  PEER_MESSAGE_ID,
  PEER_BRANCH_CLASS,
  PEER_LINK_ROLE,
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
  isPeerM3Runtime
} = require('../../lib/private/peer-m3-adjacency-runtime')
const { fakeClock, ledgers } = require('./peer-native-fixture')

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
  input.writeUInt32BE(2, headerOffset)
  input.writeUInt16BE(messageId, headerOffset + 4)
  input.writeUInt16BE(bodyLen, headerOffset + 6)
  input.set(body, headerOffset + 8)
  return input
}

test('responder binding.accept and takePeerLinkReplyAttempt produce genuine 663-byte packet with R/F/C proof and verified sendLedger', async (t) => {
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
      minimumVersion: 2,
      maximumVersion: 2,
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

  const sendLedger = createPeerLedger({ cells: 60, bytes: 72000n, commands: 60 })
  const teardownSendLedger = createPeerLedger({ cells: 30, bytes: 36000n, commands: 3 })
  const receiveLedger = createPeerLedger({ cells: 60, bytes: 72000n, commands: 60 })
  const teardownReceiveLedger = createPeerLedger({ cells: 30, bytes: 36000n, commands: 3 })

  const adoptedRuntimes = []
  const responder = createPeerLinkResponder(rightRelayOwner, {
    onEstablished(handle) {
      const runtime = adoptPeerEstablishedLink(responderAuthority, handle)
      adoptedRuntimes.push(runtime)
      return runtime
    },
    sendLedger,
    teardownSendLedger,
    receiveLedger,
    teardownReceiveLedger
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
    rejection(() =>
      createPeerLinkResponder(rightRelayOwner, {
        sendLedger,
        receiveLedger,
        teardownSendLedger,
        teardownReceiveLedger
      })
    ),
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
  t.is(attempt.packet.byteLength, 663, 'packet is genuine 663-byte reply cell')

  const { accept285, proof378 } = decodePeerLinkReply(attempt.packet, 1)
  t.is(accept285.byteLength, 285, 'accept component is 285 bytes')
  t.is(proof378.byteLength, 378, 'proof component is 378 bytes')

  const decodedProof = decodePeerTransport(proof378)
  t.is(decodedProof.messageId, PEER_MESSAGE_ID.PEER_REDACTED_RESPONDER_PROOF_V2)
  t.is(decodedProof.fields.extensionIndex, 1)
  t.is(decodedProof.fields.expiresAt, reverseLimits.expiresAt)

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

  const parents = [sendLedger, receiveLedger, teardownSendLedger, teardownReceiveLedger]
  const before = parents.map(readPeerLedger)
  const successorFields = {
    ...offerFields,
    branchId: b4a.alloc(16, 0x71),
    circuitId: b4a.alloc(16, 0x72),
    initiatorForwardLimits: reverseLimits,
    clientNonce: b4a.alloc(32, 0x73)
  }
  const otherBinding = takePeerLinkResponderBinding(responder, rightEstablished, rightEndpoint)
  const oversizedForwardCells = readPeerLedger(receiveLedger).cellsRemaining + 11
  let admissionError = null
  try {
    binding.accept({
      offer: signOffer({
        ...successorFields,
        initiatorForwardLimits: {
          ...forwardLimits,
          maxCells: oversizedForwardCells,
          maxBytes: oversizedForwardCells * 1200
        }
      }),
      established: rightEstablished,
      reservePhysical
    })
  } catch (err) {
    admissionError = err
  }
  t.is(
    admissionError && admissionError.code,
    'INVALID_ROUTE',
    'insufficient receive capacity rejects admission after reserving send capacity'
  )
  t.alike(
    parents.map(readPeerLedger),
    before,
    'partial admission returns every unspent reservation'
  )
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
    readPeerLedger(receiveLedger).cellsSpent,
    10,
    'nine first-branch arrivals and one sibling arrival are retained'
  )
  t.is(readPeerLedger(receiveLedger).commandsSpent, 2, 'retransmissions allocate no new command')
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
    readPeerLedger(receiveLedger).cellsSpent,
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
    readPeerLedger(receiveLedger).cellsSpent,
    13,
    'the first late authenticated arrival is accounted before retirement'
  )
  t.is(
    rejection(() => takePeerLinkReplyAttempt(thirdReply, rightEstablished)),
    'UNAUTHORIZED'
  )

  const bindingParents = ledgers()
  let bindingRuntime = null
  const bindingResponder = createPeerLinkResponder(rightRelayOwner, {
    ...bindingParents,
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
  for (const parent of parents) t.is(readPeerLedger(parent).cellsReserved, 0)
  for (const parent of Object.values(bindingParents)) t.is(readPeerLedger(parent).cellsReserved, 0)
  t.is(readPeerLedger(sendLedger).cellsSpent, 1, 'closing adopted owners never refunds spent work')
  t.is(
    readPeerLedger(sendLedger).commandsSpent,
    3,
    'released admissions never refund allocation commands'
  )
  leftDir.destroy()
  rightDir.destroy()
})
