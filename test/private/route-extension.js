'use strict'

const b4a = require('b4a')
const test = require('brittle')
const { BootstrapEnvelopeCodec } = require('../../lib/private/bootstrap-envelope')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { digestPayloadParameters } = require('../../lib/private/link-parameters')
const {
  M3AdjacencyAuthority,
  TEST_ONLY_M3_ADJACENCY_OBSERVER
} = require('../../lib/private/m3-adjacency-runtime')
const {
  BRANCH_CLASS,
  CAPACITY_CLASS,
  CELL_CLASS,
  CONTEXT_CLASS,
  M3_MESSAGE_ID,
  LINK_OPERATION,
  RELAY_CAPABILITY,
  PROTOCOL_VERSION,
  ROLE,
  TOPOLOGY_ROLE,
  DIRECTION,
  encodeM3Object,
  roleForIdentity
} = require('../../lib/private/protocol')
const {
  consumeSealedRelayCandidateDirectory,
  createRelayCandidateDirectorySink,
  sealRelayCandidateDirectorySink,
  splitRelayPathReservation,
  takeRelayPathReservation
} = require('../../lib/private/relay-candidate-directory')
const {
  decodeRelayCapabilityAdvertisement,
  deriveM3DhtNodeId,
  digestRelayCapabilityAdvertisement,
  encodeCanonicalEndpoint,
  encodeRelayCapabilityAdvertisement,
  providerServicePolicyForCapabilities,
  signRelayCapabilityAdvertisement
} = require('../../lib/private/relay-capability')
const { signRedactedResponderProof } = require('../../lib/private/redacted-responder-proof')
const { createLinkSetupAuthority } = require('../../lib/private/link-setup')
const { LinkDirectory, signTopologyGrant } = require('../../lib/private/topology-grant')
const {
  RouteExtensionSession,
  createRouteExtensionFactory,
  createRouteExtensionSessionRequest,
  openRouteExtension,
  takeRouteExtensionTransfer
} = require('../../lib/private/route-extension')
const {
  completeIndexZeroGuardLink,
  createIndexZeroGuardLinkOffer,
  createIndexZeroGuardLinkResponder
} = require('../../lib/private/guard-link')
const {
  admitTailExtend,
  borrowTailControlTransport,
  createTailControlResponderAuthority,
  createTailControlSession,
  decodeExtendRequest,
  digestAdmittedLimits,
  encodeExtended,
  encodeTailControlTranscript,
  destroyTailControlResponderAuthority,
  destroyTailControlSession
} = require('../../lib/private/tail-control')
const endpointModule = require('../../lib/private/udx-cell-endpoint')
const { TEST_ONLY_UDX_ADAPTER_ISSUER, createM3CellLinkTransferIssuer } = endpointModule

const NOW = 1_000n
const TAIL_READY_DOMAIN = b4a.from('hyperdht-private-routes/m3/tail-ready/v1')
const TAIL_READY_TRANSCRIPT_DOMAIN = b4a.from(
  'hyperdht-private-routes/m3/tail-control/transcript-digest/v1'
)

function seed(value, size = 32) {
  return b4a.alloc(size, value)
}

function writeUint16(target, value, offset) {
  target[offset] = value >>> 8
  target[offset + 1] = value
}

function writeUint32(target, value, offset) {
  target[offset] = value >>> 24
  target[offset + 1] = value >>> 16
  target[offset + 2] = value >>> 8
  target[offset + 3] = value
}

function writeUint64(target, value, offset) {
  for (let index = 7; index >= 0; index--) {
    target[offset + index] = Number(value & 0xffn)
    value >>= 8n
  }
}

function signatureInput(domain, messageId, body) {
  const input = b4a.alloc(10 + domain.byteLength + body.byteLength)
  writeUint16(input, domain.byteLength, 0)
  input.set(domain, 2)
  writeUint32(input, 1, 2 + domain.byteLength)
  writeUint16(input, messageId, 6 + domain.byteLength)
  writeUint16(input, body.byteLength, 8 + domain.byteLength)
  input.set(body, 10 + domain.byteLength)
  return input
}

function tailControlEnvelope(encoded) {
  const frame = b4a.alloc(1100)
  frame.set(encoded)
  return require('../../lib/private/m3-context').encodeM3ContextEnvelope({
    contextClass: CONTEXT_CLASS.TAIL_CONTROL_ORDERED,
    frame
  })
}

function tailReady(extended, request, signer, transcriptDigest, expiresAtMs) {
  const body = b4a.alloc(210)
  body[0] = extended.branchClass
  body.set(extended.branchId, 1)
  body.set(extended.circuitId, 17)
  writeUint64(body, extended.generation, 33)
  body[41] = extended.extensionIndex
  body.set(transcriptDigest, 42)
  body.set(signer.publicKey, 74)

  body.set(extended.responderAdvertisementDigest, 106)
  body.set(request.clientNonce, 138)
  body.set(seed(0xb4), 170)
  writeUint64(body, expiresAtMs, 202)
  return encodeM3Object({
    messageId: M3_MESSAGE_ID.TAIL_READY_V1,
    body,
    authSuffix: cryptoSuite.sign(
      signatureInput(TAIL_READY_DOMAIN, M3_MESSAGE_ID.TAIL_READY_V1, body),
      signer.secretKey
    )
  })
}

function safetyIdentity(start = 92) {
  for (let value = start; value < 256; value++) {
    const pair = cryptoSuite.keyPair(seed(value))
    if (roleForIdentity(pair.publicKey) === ROLE.SAFETY) return pair
  }
  throw new Error('missing safety identity')
}

function identityFor(role, ordinal) {
  let found = -1
  for (let value = 1; value < 256; value++) {
    const pair = cryptoSuite.keyPair(seed(value))
    if (roleForIdentity(pair.publicKey) !== role) continue
    found++
    if (found === ordinal) return pair
  }
  throw new Error('missing deterministic role identity')
}

function candidate(role, ordinal, index) {
  const identity = identityFor(role, ordinal)
  const route = cryptoSuite.encryptionKeyPair(seed(128 + index))
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
  const digest = digestRelayCapabilityAdvertisement(canonicalBytes, { now: NOW })
  return {
    record: Object.freeze({
      canonicalBytes,
      digest,
      identity: b4a.from(identity.publicKey),
      canonicalEndpointBytes: b4a.from(endpoint),
      routePublicKey: b4a.from(route.publicKey),
      role,
      capabilityMask,
      epoch: 1n,
      issuedAt: NOW,
      expiresAt: NOW + 30_000n
    }),
    identity,
    route
  }
}

function routeClock() {
  let nextHandle = 0
  const timers = new Map()
  return {
    wallNow() {
      return NOW
    },
    monotonicNow() {
      return 10_000n
    },
    schedule(callback, delay) {
      const handle = ++nextHandle
      timers.set(handle, { callback, delay })
      return handle
    },
    cancelScheduled(handle) {
      timers.delete(handle)
    },
    fire(handle) {
      const timer = timers.get(handle)
      if (!timer) return false
      timers.delete(handle)
      timer.callback()
      return true
    },
    handles() {
      return [...timers.keys()]
    },
    pending() {
      return timers.size
    }
  }
}

function linkPair(hostA, portA, hostB, portB) {
  const authority = cryptoSuite.keyPair(seed(0x5a))
  const a = cryptoSuite.keyPair(seed(0x5b))
  const b = safetyIdentity(0x5c)
  const runId32 = seed(0x5d)
  const grant = signTopologyGrant(
    {
      version: PROTOCOL_VERSION,
      format: 0,
      grantId32: seed(0x5e),
      endpointA: {
        identity32: a.publicKey,
        role: TOPOLOGY_ROLE.SOURCE,
        host: hostA,
        port: portA,
        operations: LINK_OPERATION.INITIATE
      },
      endpointB: {
        identity32: b.publicKey,
        role: TOPOLOGY_ROLE.SAFETY_GUARD,
        host: hostB,
        port: portB,
        operations: LINK_OPERATION.ACCEPT
      },
      epoch: 7n,
      notBefore: 0n,
      expiresAt: 60_000n,
      runId32
    },
    authority.secretKey
  )
  const make = (local, peer, localRole, peerRole, operation) => {
    const directory = new LinkDirectory({
      localIdentity32: local.publicKey,
      localRole,
      authorityPublicKey: authority.publicKey,
      epoch: 7n,
      runId32,
      now: () => 1n,
      schedule: setTimeout,
      cancel: clearTimeout,
      onClose() {}
    })
    const digest32 = directory.add(grant)
    const handle = directory.authorize({
      digest32,
      operation,
      localIdentity32: local.publicKey,
      localRole,
      peerIdentity32: peer.publicKey,
      peerRole,
      epoch: 7n,
      runId32
    })
    return { directory, handle }
  }
  return {
    left: make(a, b, TOPOLOGY_ROLE.SOURCE, TOPOLOGY_ROLE.SAFETY_GUARD, LINK_OPERATION.INITIATE),
    right: make(b, a, TOPOLOGY_ROLE.SAFETY_GUARD, TOPOLOGY_ROLE.SOURCE, LINK_OPERATION.ACCEPT),
    a,
    b
  }
}

class FakeSocket {
  constructor(network) {
    this.network = network
    this.listeners = new Map()
    this.host = null
    this.port = null
  }

  on(name, listener) {
    const values = this.listeners.get(name) || new Set()
    values.add(listener)
    this.listeners.set(name, values)
  }

  off(name, listener) {
    const values = this.listeners.get(name)
    if (values) values.delete(listener)
  }

  emit(name, ...args) {
    for (const listener of this.listeners.get(name) || []) listener(...args)
  }

  bind(port, host) {
    this.port = port
    this.host = host
    this.network.set(`${host}:${port}`, this)
    return true
  }

  send(packet, port, host) {
    const peer = this.network.get(`${host}:${port}`)
    if (!peer) return false
    const message = { peer, packet: b4a.from(packet), source: { host: this.host, port: this.port } }
    if (this.network.reorderNextPair) {
      const held = this.network.heldMessage
      if (!held) {
        this.network.heldMessage = message
        return true
      }
      this.network.heldMessage = null
      this.network.reorderNextPair = false
      queueMicrotask(() => message.peer.emit('message', message.packet, message.source))
      queueMicrotask(() => held.peer.emit('message', held.packet, held.source))
      return true
    }
    queueMicrotask(() => message.peer.emit('message', message.packet, message.source))
    return true
  }

  close() {
    this.network.delete(`${this.host}:${this.port}`)
    return true
  }
}

function fakeFactory(network) {
  return () => ({
    create() {
      return {
        createSocket() {
          return new FakeSocket(network)
        }
      }
    }
  })
}

function endpointOptions(host, port, receive) {
  return {
    host,
    port,
    onBootstrap(packet) {
      if (receive.session) void receive.session.receive(packet)
    },
    onCell(packet, handle, metadata) {
      if (receive.cells)
        receive.cells.push({
          packet: b4a.isBuffer(packet) ? b4a.from(packet) : packet,
          handle,
          metadata
        })
      return true
    },
    onLinkFailure() {}
  }
}

function sequence(first) {
  let value = first
  return (size) => b4a.alloc(size, value++)
}

function linkSessionOptions(links, side) {
  const now = () => 1
  const responderStatic = cryptoSuite.encryptionKeyPair(seed(0x62))
  const common = {
    circuitId: seed(0x51, 16),
    epoch: 7n,
    initiatorIdentity: links.a.publicKey,
    responderIdentity: links.b.publicKey,
    initiatorLocalId: seed(0x52, 16),
    responderLocalId: seed(0x53, 16),
    expiresAt: 60_000n
  }
  const initiate = side === 'left'
  const linkHandle = initiate ? links.left.handle : links.right.handle
  return {
    mode: initiate ? 'initiate' : 'accept',
    codec: new BootstrapEnvelopeCodec({
      linkHandle,
      localIdentitySecretKey: initiate ? links.a.secretKey : links.b.secretKey,
      padding: sequence(initiate ? 0x81 : 0x91)
    }),
    linkSetup: createLinkSetupAuthority({
      now,
      randomBytes: sequence(initiate ? 0x61 : 0x71)
    }),
    setup: initiate
      ? {
          ...common,
          responderStaticKey: responderStatic.publicKey,
          initiatorIdentitySecretKey: links.a.secretKey
        }
      : {
          ...common,
          responderStaticSecretKey: responderStatic.secretKey,
          responderIdentitySecretKey: links.b.secretKey
        },
    now,
    schedule: setTimeout,
    cancel: clearTimeout,
    randomBytes: sequence(initiate ? 1 : 11),
    absoluteDeadline: 10_000,
    signedExpiry: 60_000,
    authorizedExpiry: 60_000
  }
}

async function settles() {
  await Promise.resolve()
  await Promise.resolve()
}

async function nativeM3TransferPair(basePort) {
  const network = new Map()
  const issuer = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER]
  const leftReceive = { session: null, cells: [] }
  const rightReceive = { session: null, cells: [] }
  const left = issuer.createUdxCellEndpointForTest(
    endpointOptions('127.0.0.1', basePort, leftReceive),
    issuer.createTestUdxAdapterAuthority(fakeFactory(network))
  )
  const right = issuer.createUdxCellEndpointForTest(
    endpointOptions('127.0.0.2', basePort + 1, rightReceive),
    issuer.createTestUdxAdapterAuthority(fakeFactory(network))
  )
  await left.bind()
  await right.bind()
  const links = linkPair('127.0.0.1', basePort, '127.0.0.2', basePort + 1)
  const leftSession = left.openLink(links.left.handle, linkSessionOptions(links, 'left'))
  const rightSession = right.openLink(links.right.handle, linkSessionOptions(links, 'right'))
  leftReceive.session = leftSession
  rightReceive.session = rightSession
  const leftEstablished = await leftSession.open()
  await settles()
  const rightEstablished = rightSession.established
  if (!rightEstablished) throw new Error('responder UDX OPEN did not establish')
  return {
    left,
    right,
    leftEstablished,
    rightEstablished,
    initiatorChannel: createM3CellLinkTransferIssuer(left, leftEstablished),
    responderChannel: createM3CellLinkTransferIssuer(right, rightEstablished),
    leftCells: leftReceive.cells,
    rightCells: rightReceive.cells,
    reorderNextPair() {
      if (network.heldMessage) throw new Error('reorder already has a held message')
      network.reorderNextPair = true
    },
    async destroy() {
      const operations = [
        () => leftSession.close(),
        () => rightSession.close(),
        () => left.close(),
        () => right.close(),
        () => links.left.directory.destroy(),
        () => links.right.directory.destroy()
      ]
      for (const operation of operations) {
        try {
          await operation()
        } catch {}
      }
    }
  }
}

function selectedPath(guard, middle, exit) {
  const sink = createRelayCandidateDirectorySink({
    wallNow: () => NOW,
    monotonicNow: () => 10_000n
  })
  const alternateMiddle = candidate(ROLE.SAFETY, 2, 3)
  const alternateExit = candidate(ROLE.PRIVATE, 1, 41)
  const directory = consumeSealedRelayCandidateDirectory(
    sealRelayCandidateDirectorySink(
      sink,
      [middle.record, alternateMiddle.record, exit.record, alternateExit.record],
      {
        guardIdentity: guard.identity.publicKey,
        guardEndpoint: guard.record.canonicalEndpointBytes,
        guardAdvertisementDigest: guard.record.digest,
        guardEpoch: guard.record.epoch,
        guardExpiresAt: guard.record.expiresAt
      }
    )
  )
  const transaction = takeRelayPathReservation(
    directory.reserveInitialPair({ lookupGeneration: 1n, announceGeneration: 1n })
  )
  const split = splitRelayPathReservation(transaction)
  return { transaction, middle: split.lookup.middle, exit: split.lookup.exit }
}

function requestedLimits() {
  return Object.freeze({
    cellSize: 1200,
    maxCells: 64,
    maxBytes: 65_536,
    maxCommands: 10,
    idleTimeoutMs: 5_000,
    expiresAtMs: 6_000n
  })
}

function setupValues(client) {
  return {
    branchClass: BRANCH_CLASS.LOOKUP,
    branchId: seed(0x41, 16),
    circuitId: seed(0x42, 16),
    generation: 1n,
    clientCircuitIdentity: client,
    clientTailEphemeral: cryptoSuite.encryptionKeyPair(seed(0x43)),
    requestedLimits: requestedLimits()
  }
}

async function createInitialTail(guard, clock, options = {}) {
  const client = identityFor(ROLE.SAFETY, 70)
  const setup = setupValues(client)
  const decoded = decodeRelayCapabilityAdvertisement(guard.record.canonicalBytes)
  setup.payloadParametersDigest = digestPayloadParameters(decoded)
  const transcript = encodeTailControlTranscript({
    branchClass: setup.branchClass,
    branchId: setup.branchId,
    circuitId: setup.circuitId,
    generation: setup.generation,
    extensionIndex: 0,
    clientTailEphemeralPublicKey: setup.clientTailEphemeral.publicKey,
    advertisedTailRouteEncryptionPublicKey: guard.route.publicKey,
    candidateAdvertisementDigest: guard.record.digest,
    clientNonce: seed(0x44),
    tailIdentity: guard.identity.publicKey,
    admittedLimitsDigest: digestAdmittedLimits(setup.requestedLimits)
  })
  const initiated = createIndexZeroGuardLinkOffer({
    advertisement: guard.record.canonicalBytes,
    now: NOW,
    randomBytes: (() => {
      const values = [seed(0x45), seed(0x44)]
      return () => values.shift()
    })(),
    ...setup
  })
  const native = await nativeM3TransferPair(48201)
  const responder = createIndexZeroGuardLinkResponder({
    advertisement: guard.record.canonicalBytes,
    responderIdentitySecretKey: guard.identity.secretKey,
    responderRouteEncryptionSecretKey: guard.route.secretKey,
    now: () => NOW,
    receiveOffer: () =>
      Object.freeze({
        offer: initiated.offer,
        observedPredecessorEndpoint: encodeCanonicalEndpoint({
          addressFamily: 4,
          addressBytes: b4a.from([203, 0, 113, 1]),
          port: 41_000
        }),
        physicalChannel: native.responderChannel
      }),
    randomBytes: (() => {
      const values = [seed(0x46), seed(0x47)]
      return () => values.shift()
    })()
  })
  const accepted = responder.accept()
  const established = completeIndexZeroGuardLink(initiated.pending, accepted.accept, {
    advertisement: guard.record.canonicalBytes,
    physicalChannel: native.initiatorChannel,
    now: NOW
  })
  const authorityOptions = {
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled,
    crypto: cryptoSuite
  }
  if (typeof options.observe === 'function') {
    authorityOptions[TEST_ONLY_M3_ADJACENCY_OBSERVER] = options.observe
  }
  const authority = new M3AdjacencyAuthority(authorityOptions)
  const initiator = authority.adopt(established)
  const acceptedResponder = authority.adopt(accepted.established)
  const initiatorSession = createTailControlSession(initiator.tail, {
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled,
    absoluteDeadline: 15_000n,
    crypto: cryptoSuite
  })
  const responderSession = createTailControlSession(acceptedResponder.tail, {
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled,
    crypto: cryptoSuite
  })
  return {
    authority,
    initiatorSession,
    responderSession,
    responderToken: acceptedResponder.responderToken,
    transcript,
    native,
    initiatorRuntime: initiator.runtime,
    responderRuntime: acceptedResponder.runtime
  }
}
async function answerOneExtension(
  clock,
  responderSession,
  responderToken,
  target,
  transcript,
  trace,
  beforeResponse = null,
  beforeReady = null
) {
  const responderAuthority = createTailControlResponderAuthority(responderSession, responderToken, {
    adjacencyAdopter: Object.freeze({}),
    extensionCommitter: Object.freeze({}),
    adjacentLinkFactory: Object.freeze({}),
    tailReadySigner: Object.freeze({}),
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    randomBytes: () => seed(0xb1),
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled
  })
  try {
    const received = await borrowTailControlTransport(responderSession).receive()
    const admitted = admitTailExtend(responderAuthority, received)
    trace.push('EXTEND_REQUEST_V1')
    const taken = require('../../lib/private/tail-control').takeAdmittedExtendRequest(admitted)
    const request = taken.request
    const responderAdvertisementDigest = digestRelayCapabilityAdvertisement(request.advertisement)
    const proofExpiresAt = request.requestedLimits.expiresAtMs
    const proof = signRedactedResponderProof(
      {
        responderAdvertisementDigest,
        initiatorIdentity: taken.currentTailIdentity,
        responderIdentity: target.identity.publicKey,
        branchClass: request.branchClass,
        branchId: request.branchId,
        circuitId: request.circuitId,
        generation: request.generation,
        extensionIndex: request.extensionIndex,
        clientTailEphemeralPublicKey: request.clientTailEphemeralPublicKey,
        clientNonce: request.clientNonce,
        advertisedRouteEncryptionPublicKey: target.route.publicKey,
        admittedLimitsDigest: digestAdmittedLimits(request.requestedLimits),
        expiresAtMs: proofExpiresAt,
        responderProofNonce: seed(0xb2)
      },
      target.identity.secretKey
    )
    const extended = {
      branchClass: request.branchClass,
      branchId: request.branchId,
      circuitId: request.circuitId,
      generation: request.generation,
      extensionIndex: request.extensionIndex,
      responderAdvertisementDigest,
      redactedProof: proof,
      extensionNonce: request.extensionNonce
    }
    trace.push('EXTENDED_V1')
    if (beforeResponse) beforeResponse()
    await borrowTailControlTransport(responderSession).send(
      tailControlEnvelope(encodeExtended(extended))
    )
    if (beforeReady && beforeReady() === false) return
    trace.push('TAIL_READY_V1')
    await borrowTailControlTransport(responderSession).send(
      tailControlEnvelope(
        tailReady(
          extended,
          request,
          target.identity,
          cryptoSuite.hash([TAIL_READY_TRANSCRIPT_DOMAIN, transcript]),
          proofExpiresAt
        )
      )
    )
  } finally {
    destroyTailControlResponderAuthority(responderAuthority)
  }
}

test('route extension request rejects structural tail-control borrowers before selected evidence moves', (t) => {
  const guard = candidate(ROLE.SAFETY, 0, 1)
  const middle = candidate(ROLE.SAFETY, 1, 2)
  const exit = candidate(ROLE.PRIVATE, 0, 40)
  const selected = selectedPath(guard, middle, exit)
  const structural = Object.freeze({
    sealExtend() {},
    openExtended() {},
    completeClientExtension() {},
    abortClientExtension() {},
    takeFinalExitHandoff() {}
  })
  t.exception(
    () =>
      createRouteExtensionSessionRequest({
        transaction: selected.transaction,
        selection: selected.middle,
        branchClass: BRANCH_CLASS.LOOKUP,
        position: 'middle',
        generation: 1n,
        extensionIndex: 1,
        limits: Object.freeze({}),
        absoluteDeadline: 15_000n,
        signedExpiry: 15_000n,
        wallNow: () => NOW,
        monotonicNow: () => 10_000n,
        randomBytes: () => seed(0x60),
        schedule: () => Object.freeze({}),
        cancelScheduled() {},
        cancel() {},
        tailControl: structural
      }),
    'structural tail-control is not a production borrower'
  )
})

test('route extension uses registered M3 tail-control envelopes from a real index-zero guard link', async (t) => {
  const clock = routeClock()
  const guard = candidate(ROLE.SAFETY, 0, 1)
  const middle = candidate(ROLE.SAFETY, 1, 2)
  const exit = candidate(ROLE.PRIVATE, 0, 40)
  const selected = selectedPath(guard, middle, exit)
  let tail = null
  let moved = null
  try {
    tail = await createInitialTail(guard, clock)
    const trace = []
    const extensionFactory = createRouteExtensionFactory({
      wallNow: clock.wallNow,
      monotonicNow: clock.monotonicNow,
      randomBytes: (() => {
        const values = [seed(0x70), seed(0x71), seed(0x72)]
        return () => values.shift()
      })(),
      schedule: clock.schedule,
      cancelScheduled: clock.cancelScheduled
    })
    const opening = openRouteExtension(extensionFactory, {
      transaction: selected.transaction,
      selection: selected.middle,
      branchClass: BRANCH_CLASS.LOOKUP,
      position: 'middle',
      generation: 1n,
      extensionIndex: 1,
      limits: Object.freeze({}),
      absoluteDeadline: 15_000n,
      signedExpiry: 6_000n,
      cancel() {},
      tailControl: tail.initiatorSession
    })
    await answerOneExtension(
      clock,
      tail.responderSession,
      tail.responderToken,
      middle,
      tail.transcript,
      trace,
      () => tail.native.reorderNextPair()
    )
    const transfer = await opening
    moved = takeRouteExtensionTransfer(transfer)
    t.is(moved.tailControl, tail.initiatorSession)
    t.alike(trace, ['EXTEND_REQUEST_V1', 'EXTENDED_V1', 'TAIL_READY_V1'])
    t.is(
      clock.pending(),
      4,
      'both M3 runtimes and TailControl lifetimes remain armed after logical transfer'
    )
  } finally {
    if (moved) destroyTailControlSession(moved.tailControl)
    if (tail) {
      destroyTailControlSession(tail.initiatorSession)
      destroyTailControlSession(tail.responderSession)
      tail.initiatorRuntime.destroy()
      tail.responderRuntime.destroy()
      await tail.native.destroy()
    }
  }
  t.is(clock.pending(), 0, 'route extension leaves no timers after cleanup')
})

test('registered M3 transfer destroy consumes its native established channel', async (t) => {
  const clock = routeClock()
  const guard = candidate(ROLE.SAFETY, 0, 1)
  const tail = await createInitialTail(guard, clock)
  try {
    t.is(tail.initiatorRuntime.destroy(), true)
    t.exception(
      () => createM3CellLinkTransferIssuer(tail.native.left, tail.native.leftEstablished),
      'destroyed transfer tombstones the native established handle'
    )
  } finally {
    destroyTailControlSession(tail.initiatorSession)
    destroyTailControlSession(tail.responderSession)
    tail.responderRuntime.destroy()
    await tail.native.destroy()
  }
  t.is(clock.pending(), 0, 'transfer destroy cleanup leaves no route-extension timers')
})

test('registered M3 tail transfer does not consume application stream cells', async (t) => {
  const clock = routeClock()
  const guard = candidate(ROLE.SAFETY, 0, 1)
  const tail = await createInitialTail(guard, clock)
  let envelope = null
  try {
    const responderTransport = borrowTailControlTransport(tail.responderSession)
    let tailReceived = false
    const waiting = responderTransport.receive().then((value) => {
      tailReceived = true
      return value
    })
    const payload = seed(0x7a, 24)
    await endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER].sendEstablishedForTest(
      tail.native.left,
      tail.native.leftEstablished,
      {
        class: CELL_CLASS.STREAM,
        direction: DIRECTION.FORWARD,
        generation: 1n,
        payload
      }
    )
    await settles()
    t.is(tailReceived, false, 'tail-control receive ignores established STREAM traffic')
    t.is(tail.native.rightCells.length, 1, 'application stream is dispatched once')
    t.alike(tail.native.rightCells[0].packet, payload)
    const control = seed(0x7b, 1101)
    await borrowTailControlTransport(tail.initiatorSession).send(control)
    envelope = await waiting
    t.alike(envelope, control)
    t.is(responderTransport.release(envelope), true)
    envelope = null
  } finally {
    if (envelope) {
      try {
        borrowTailControlTransport(tail.responderSession).release(envelope)
      } catch {}
    }
    destroyTailControlSession(tail.initiatorSession)
    destroyTailControlSession(tail.responderSession)
    tail.initiatorRuntime.destroy()
    tail.responderRuntime.destroy()
    await tail.native.destroy()
  }
  t.is(clock.pending(), 0, 'application stream transfer cleanup leaves no route-extension timers')
})

test('route extension deadline rejects before a responder answer arrives', async (t) => {
  const clock = routeClock()
  const guard = candidate(ROLE.SAFETY, 0, 1)
  const middle = candidate(ROLE.SAFETY, 1, 2)
  const exit = candidate(ROLE.PRIVATE, 0, 40)
  const selected = selectedPath(guard, middle, exit)
  let tail = null
  try {
    tail = await createInitialTail(guard, clock)
    const beforeHandles = new Set(clock.handles())
    const request = createRouteExtensionSessionRequest({
      transaction: selected.transaction,
      selection: selected.middle,
      branchClass: BRANCH_CLASS.LOOKUP,
      position: 'middle',
      generation: 1n,
      extensionIndex: 1,
      limits: Object.freeze({}),
      absoluteDeadline: 15_000n,
      signedExpiry: 6_000n,
      wallNow: clock.wallNow,
      monotonicNow: clock.monotonicNow,
      randomBytes: (() => {
        const values = [seed(0x73), seed(0x74), seed(0x75)]
        return () => values.shift()
      })(),
      schedule: clock.schedule,
      cancelScheduled: clock.cancelScheduled,
      cancel() {},
      tailControl: tail.initiatorSession
    })
    const session = new RouteExtensionSession(request)
    const opening = session.open()
    const responderAuthority = createTailControlResponderAuthority(
      tail.responderSession,
      tail.responderToken,
      {
        adjacencyAdopter: Object.freeze({}),
        extensionCommitter: Object.freeze({}),
        adjacentLinkFactory: Object.freeze({}),
        tailReadySigner: Object.freeze({}),
        wallNow: clock.wallNow,
        monotonicNow: clock.monotonicNow,
        randomBytes: () => seed(0xb1),
        schedule: clock.schedule,
        cancelScheduled: clock.cancelScheduled
      }
    )
    const unansweredRequest = await borrowTailControlTransport(tail.responderSession).receive()
    admitTailExtend(responderAuthority, unansweredRequest)
    await Promise.resolve()
    const timer = clock.handles().find((handle) => !beforeHandles.has(handle))
    t.ok(timer, 'open arms a route-extension deadline')
    t.ok(clock.fire(timer), 'deadline callback is reachable')
    let code = null
    try {
      await opening
    } catch (err) {
      code = err && err.code
    }
    t.is(code, 'ERR_PRIVACY_UNAVAILABLE', 'deadline rejects the unanswered extension')
  } finally {
    if (tail) {
      destroyTailControlSession(tail.initiatorSession)
      destroyTailControlSession(tail.responderSession)
      tail.initiatorRuntime.destroy()
      tail.responderRuntime.destroy()
      await tail.native.destroy()
    }
  }
  t.is(clock.pending(), 0, 'deadline cleanup leaves no route-extension timers')
})
