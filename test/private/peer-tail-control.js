'use strict'

const test = require('brittle')
const b4a = require('b4a')
const NativeUDX = require('udx-native')

const { PrivateRouteError } = require('../../lib/private/errors')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { CELL_CLASS } = require('../../lib/private/protocol')
const { sealPeerContextFrame, openPeerContextFrame } = require('../../lib/private/peer-m3-context')
const {
  takeM3RouteTransport,
  sendM3RouteFrame,
  sendM3FinalizeFrame,
  activateM3RouteTransport,
  readM3RouteTransportClock,
  reserveM3RouteFrame,
  receiveReservedM3RouteFrame,
  receiveReservedM3RouteEnvelope,
  scheduleM3RouteTransportTimer,
  destroyM3RouteTransport
} = require('../../lib/private/m3-adjacency-runtime')
const {
  createPeerTailControl,
  readPeerTailControl,
  destroyPeerTailControl,
  discoverPeerTailCandidate,
  extendPeerTail,
  createPeerFinalExitHandoff,
  takePeerTailFinalRuntime,
  isPeerTailControlOwner,
  isPeerTailFinalExitHandoff,
  takePeerFinalCarrierAuthorization
} = require('../../lib/private/peer-tail-control')
const {
  adoptPeerEstablishedLink,
  isPeerM3Runtime,
  takePeerM3TailMaterial,
  destroyPeerM3Runtime,
  sendPeerM3Payload,
  receivePeerM3Payload,
  issuePeerM3RouteCarrier,
  takePeerM3RouteCarrier
} = require('../../lib/private/peer-m3-adjacency-runtime')
const {
  createPeerRelayOwner,
  destroyPeerRelayOwner,
  readVerifiedPeerAdvertisement
} = require('../../lib/private/peer-capability')
const {
  claimFinalExitActivation,
  createFinalExitActivationClaim,
  consumeFinalExitActivationOwner,
  destroyFinalExitActivationOwner
} = require('../../lib/private/final-exit-activation')
const {
  createPeerMemoryPool,
  readPeerMemory,
  releasePeerMemory,
  reservePeerMemory
} = require('../../lib/private/peer-ledger')
const {
  fakeClock,
  authenticatedPeer,
  setupFourNodeNativeFixture,
  seed,
  safetyIdentity
} = require('./peer-native-fixture')

async function interceptNativeMessages(onMessage, setup) {
  const createSocket = NativeUDX.prototype.createSocket
  NativeUDX.prototype.createSocket = function (options) {
    const socket = createSocket.call(this, options)
    const emit = socket.emit
    socket.emit = function (event, ...args) {
      if (event === 'message' && onMessage(socket, args, emit) === false) return true
      return emit.call(this, event, ...args)
    }
    return socket
  }
  try {
    return await setup()
  } finally {
    NativeUDX.prototype.createSocket = createSocket
  }
}

test('weak brand predicates: isPeerTailControlOwner and isPeerTailFinalExitHandoff track provenance across stages', async (t) => {
  t.is(isPeerTailControlOwner(null), false)
  t.is(isPeerTailControlOwner({}), false)
  t.is(isPeerTailFinalExitHandoff(null), false)
  t.is(isPeerTailFinalExitHandoff({}), false)

  const fixture = await authenticatedPeer(t, 49501, 2)
  const memoryPool = createPeerMemoryPool(4096)
  const responderSession = createPeerTailControl(fixture.peerRuntime, {
    relayOwner: fixture.f.peerRelayOwner,
    neighborPool: fixture.f.peerPool,
    runtimeAuthority: fixture.peerAuthority,
    memoryPool
  })

  t.is(isPeerTailControlOwner(responderSession), true)
  destroyPeerTailControl(responderSession)
  t.is(
    isPeerTailControlOwner(responderSession),
    true,
    'destroyed session retains peer brand provenance'
  )
})

test('createPeerTailControl rejects non-runtime, invalid options, and requires options.memoryPool', (t) => {
  t.exception(() => {
    createPeerTailControl({})
  }, 'non-runtime rejected')
  t.exception(() => {
    createPeerTailControl(null)
  }, 'null runtime rejected')
  t.exception(() => {
    createPeerTailControl('invalid')
  }, 'string runtime rejected')

  const mockRuntime = Object.freeze({
    [Symbol.for('hyperdht-private-routes/peer-m3-runtime')]: true
  })
  t.exception(() => {
    createPeerTailControl(mockRuntime, {})
  }, 'missing memoryPool option rejected')
})

test('createPeerTailControl: transactional cleanup destroys runtime on setup failure', async (t) => {
  const fixture = await authenticatedPeer(t, 49511, 2)
  const peerRuntime = fixture.peerRuntime
  t.ok(isPeerM3Runtime(peerRuntime))

  const memoryPool = createPeerMemoryPool(4096)
  t.exception(() => {
    createPeerTailControl(peerRuntime, { memoryPool })
  }, 'missing relayOwner throws')

  t.exception(() => {
    takePeerM3TailMaterial(peerRuntime)
  }, 'runtime was consumed and destroyed')
})

test('readPeerTailControl returns nonsecret descriptor, keeps secrets private, and throws when destroyed', async (t) => {
  const fixture = await authenticatedPeer(t, 49521, 2)
  const peerRuntime = fixture.peerRuntime
  const memoryPool = createPeerMemoryPool(4096)

  const responderSession = createPeerTailControl(peerRuntime, {
    relayOwner: fixture.f.peerRelayOwner,
    neighborPool: fixture.f.peerPool,
    runtimeAuthority: fixture.peerAuthority,
    memoryPool
  })
  t.ok(responderSession, 'responder tail control created')

  const desc = readPeerTailControl(responderSession)
  t.is(desc.initiator, false)
  t.is(desc.protocolVersion, 2)
  t.is(desc.branchClass, 2)
  t.is(desc.extensionIndex, 2)
  t.is(desc.tailSharedSecret, undefined, 'tailSharedSecret is never exposed in descriptor')
  t.is(desc.keys, undefined, 'keys are never exposed in descriptor')
  t.ok(b4a.isBuffer(desc.tailIdentity))
  t.is(desc.tailIdentity.byteLength, 32)
  t.ok(b4a.isBuffer(desc.tailAdvertisementDigest))
  t.is(desc.tailAdvertisementDigest.byteLength, 32)
  t.ok(b4a.isBuffer(desc.tailControlTranscriptDigest))
  t.is(desc.tailControlTranscriptDigest.byteLength, 32)
  t.ok(b4a.isBuffer(desc.advertisement))
  t.is(desc.advertisement.byteLength, 260)

  desc.tailIdentity[0] ^= 0xff
  const desc2 = readPeerTailControl(responderSession)
  t.not(
    desc2.tailIdentity[0],
    desc.tailIdentity[0],
    'modifying returned descriptor does not mutate session'
  )

  t.is(destroyPeerTailControl(responderSession), true)
  t.is(destroyPeerTailControl(responderSession), false, 'idempotent destruction')
  t.exception(() => readPeerTailControl(responderSession), 'read throws on destroyed session')
})

test('pure carrier authorization CAS and atomic route carrier transfer contract', async (t) => {
  const fixture = await authenticatedPeer(t, 49551, 2)
  const initiatorRuntime = adoptPeerEstablishedLink(fixture.localAuthority, fixture.handle)

  t.exception(() => {
    takePeerFinalCarrierAuthorization(null, initiatorRuntime)
  }, 'unauthorized on null auth')

  t.exception(() => {
    takePeerFinalCarrierAuthorization({}, initiatorRuntime)
  }, 'unauthorized on unbranded auth')

  destroyPeerM3Runtime(initiatorRuntime)
})

test('two-extension v2 tail control and one-shot final handoff complete flow over genuine Native carriage', async (t) => {
  let terminalSession = null
  let holdNextTerminalPacket = false
  let releaseHeldTail = null
  let signalHeldTail
  const heldTail = new Promise(resolve => { signalHeldTail = resolve })
  t.teardown(() => { if (releaseHeldTail) releaseHeldTail() })
  const f = await interceptNativeMessages((socket, args, emit) => {
    if (holdNextTerminalPacket && socket.address()?.port === 48303 &&
        args[0].byteLength === 1200 && args[0][1] === CELL_CLASS.DATAGRAM) {
      holdNextTerminalPacket = false
      const packet = b4a.from(args[0])
      let released = false
      releaseHeldTail = () => {
        if (released) return false
        released = true
        try {
          emit.call(socket, 'message', packet, ...args.slice(1))
        } finally {
          packet.fill(0)
        }
        return true
      }
      signalHeldTail()
      return false
    }
  }, () => setupFourNodeNativeFixture({
    t,
    native: true,
    basePort: 48300,
    poolCapacity: 4096,
    onTerminalFinalReady(session) {
      terminalSession = session
    }
  }))

  // Assert Guard, Safety, and Terminal identities are pairwise distinct
  t.not(
    b4a.equals(f.guard.identity32, f.safety.identity32),
    true,
    'Guard and Safety identities differ'
  )
  t.not(
    b4a.equals(f.safety.identity32, f.terminal.identity32),
    true,
    'Safety and Terminal identities differ'
  )
  t.not(
    b4a.equals(f.guard.identity32, f.terminal.identity32),
    true,
    'Guard and Terminal identities differ'
  )

  // Open A0 from source to guard
  const { sourceTailSession, limits } = await f.openSourceA0()
  t.ok(sourceTailSession, 'source tail session established at extension 0')
  const desc0 = readPeerTailControl(sourceTailSession)
  t.is(desc0.extensionIndex, 0, 'source extensionIndex is 0')
  t.is(desc0.phase, 'TAIL_READY', 'source phase is TAIL_READY')
  t.is(desc0.initiator, true, 'source initiator is true')

  // Step 1: Discover candidate 1 (Safety Relay) via mode 1 DIRECTORY
  const candidate1 = await discoverPeerTailCandidate(sourceTailSession, {
    mode: 1,
    requestedMask: 9,
    randomTarget32: seed(0x21),
    expiresAt: 50000n
  })
  t.ok(candidate1, 'candidate 1 (Safety) discovered via Native carriage')

  // Step 2: Extend tail to candidate 1 (Safety Relay)
  await extendPeerTail(sourceTailSession, {
    candidate: candidate1,
    forwardLimits: limits,
    reverseLimits: limits,
    payloadParametersDigest: seed(0x41)
  })

  const desc1 = readPeerTailControl(sourceTailSession)
  t.is(desc1.extensionIndex, 1, 'extension 1 complete')
  t.alike(desc1.tailIdentity, f.safety.identity32, 'tailIdentity updated to Safety')
  await f.safety.tailStarted

  // Step 3: Discover candidate 2 (Terminal) via mode 2 SUPPLIED
  const terminalAdBytes = readVerifiedPeerAdvertisement(f.terminal.verifiedAd).canonicalBytes260
  const candidate2 = await discoverPeerTailCandidate(sourceTailSession, {
    mode: 2,
    requestedMask: 11,
    randomTarget32: seed(0x71),
    suppliedAdvertisement260: terminalAdBytes,
    expiresAt: 50000n
  })
  t.ok(candidate2, 'candidate 2 (Terminal) discovered via Native carriage')

  // Step 4: Extend tail to candidate 2 (Terminal)
  await extendPeerTail(sourceTailSession, {
    candidate: candidate2,
    forwardLimits: limits,
    reverseLimits: limits,
    payloadParametersDigest: seed(0x91)
  })

  const desc2 = readPeerTailControl(sourceTailSession)
  t.is(desc2.extensionIndex, 2, 'extension 2 complete')
  t.is(desc2.phase, 'FINAL_EXIT_READY', 'phase is FINAL_EXIT_READY')
  t.alike(desc2.tailIdentity, f.terminal.identity32, 'tailIdentity updated to Terminal')
  t.ok(terminalSession, 'terminal onFinalReady callback published the ready session')
  const terminalTailSession = await f.terminal.tailStarted
  t.is(terminalSession, terminalTailSession, 'terminal session matches started tail session')

  // Step 5: Final handoff creation on Source
  const handoff = createPeerFinalExitHandoff(sourceTailSession)
  t.ok(handoff, 'final exit handoff created')
  t.is(isPeerTailFinalExitHandoff(handoff), true, 'issued handoff is branded')
  t.exception(
    () => createPeerFinalExitHandoff(sourceTailSession),
    'one-shot handoff creation throws on replay'
  )

  // Step 6: Claim the genuine registered activation owner on Source.
  const activationOwner = claimFinalExitActivation(handoff, createFinalExitActivationClaim(handoff))
  t.teardown(() => destroyFinalExitActivationOwner(activationOwner))
  const sourceMaterial = consumeFinalExitActivationOwner(activationOwner)
  const circuitId = b4a.from(sourceMaterial.tailControlTranscript.subarray(73, 89))
  t.is(Object.keys(sourceMaterial).length, 12, 'source activation retains exactly 12 material keys')
  t.is(isPeerTailFinalExitHandoff(handoff), true, 'consumed handoff keeps v2 routing provenance')
  t.exception(
    () => claimFinalExitActivation(handoff, createFinalExitActivationClaim(handoff)),
    'generic activation cannot reclaim the spent v2 handoff'
  )
  const finalizeCounters = [0n, 0n]

  // Step 7: takePeerTailFinalRuntime on Source
  const finalResult = takePeerTailFinalRuntime(sourceTailSession, activationOwner)
  t.ok(finalResult.runtime, 'source final runtime taken')
  t.ok(finalResult.authorization, 'source carrier authorization returned')
  t.is(finalResult.generation, 1n, 'source generation is 1n')
  t.ok(finalResult.clockIdentity, 'source clockIdentity present')
  t.ok(finalResult.parentLocalDeadline > 0n, 'source parentLocalDeadline valid')
  t.ok(finalResult.wireExpiresAt > 0n, 'source wireExpiresAt valid')
  t.ok(finalResult.localDeadline > 0n, 'source localDeadline valid')
  t.exception(
    () => takePeerTailFinalRuntime(sourceTailSession, activationOwner),
    'second take throws replay'
  )
  // Claim the terminal activation before exercising the two untransferred runtimes.
  const termHandoff = createPeerFinalExitHandoff(terminalTailSession)
  t.ok(termHandoff, 'terminal final exit handoff created')
  t.is(isPeerTailFinalExitHandoff(termHandoff), true, 'terminal handoff is branded')
  t.exception(
    () => createPeerFinalExitHandoff(terminalTailSession),
    'second terminal handoff throws replay'
  )

  const terminalActivationOwner = claimFinalExitActivation(
    termHandoff,
    createFinalExitActivationClaim(termHandoff)
  )
  t.teardown(() => destroyFinalExitActivationOwner(terminalActivationOwner))
  const terminalMaterial = consumeFinalExitActivationOwner(terminalActivationOwner)
  t.is(
    Object.keys(terminalMaterial).length,
    12,
    'terminal activation retains exactly 12 material keys'
  )

  const termResult = takePeerTailFinalRuntime(terminalTailSession, terminalActivationOwner)
  t.ok(termResult.runtime, 'terminal final runtime taken')
  t.ok(termResult.authorization, 'terminal carrier authorization returned')
  t.is(termResult.generation, 1n, 'terminal generation matches')
  t.ok(termResult.clockIdentity, 'terminal clockIdentity present')
  t.ok(termResult.parentLocalDeadline > 0n, 'terminal parentLocalDeadline valid')
  t.ok(termResult.wireExpiresAt > 0n, 'terminal wireExpiresAt valid')
  t.ok(termResult.localDeadline > 0n, 'terminal localDeadline valid')
  t.exception(
    () => takePeerTailFinalRuntime(terminalTailSession, terminalActivationOwner),
    'second terminal take throws replay'
  )

  const obsoleteTailEnvelope = b4a.alloc(1101, 0)
  obsoleteTailEnvelope[0] = 1
  const pendingRawRead = receivePeerM3Payload(termResult.runtime)
  let waiterError = null
  try {
    issuePeerM3RouteCarrier(termResult.runtime, termResult.authorization)
  } catch (err) {
    waiterError = err.code
  }
  t.is(
    waiterError,
    'ERR_BUSY',
    'a live reader prevents transfer even with genuine final authorization'
  )
  await sendPeerM3Payload(finalResult.runtime, obsoleteTailEnvelope)
  const pendingRawPayload = await pendingRawRead
  t.alike(
    pendingRawPayload,
    obsoleteTailEnvelope,
    'refused transfer leaves the original reader usable'
  )
  pendingRawPayload.fill(0)

  const prematureRouteEnvelope = b4a.alloc(1101, 0)
  prematureRouteEnvelope[0] = 6
  for (const [payload, authorization, expectedError] of [
    [prematureRouteEnvelope, termResult.authorization, 'ERR_BUSY'],
    [obsoleteTailEnvelope, Object.freeze({}), 'UNAUTHORIZED']
  ]) {
    await sendPeerM3Payload(finalResult.runtime, { class: CELL_CLASS.DATAGRAM, payload })
    await new Promise((resolve) => setTimeout(resolve, 10))
    let error = null
    try {
      issuePeerM3RouteCarrier(termResult.runtime, authorization)
    } catch (err) {
      error = err.code
    }
    t.is(error, expectedError, 'premature context or forged authorization cannot move the runtime')
    const retained = await receivePeerM3Payload(termResult.runtime)
    t.alike(retained, payload, 'failed transfer neither drains nor erases the queued envelope')
    retained.fill(0)
  }
  await sendPeerM3Payload(finalResult.runtime, obsoleteTailEnvelope)
  holdNextTerminalPacket = true
  await sendPeerM3Payload(finalResult.runtime, obsoleteTailEnvelope)
  await heldTail
  obsoleteTailEnvelope.fill(0)
  prematureRouteEnvelope.fill(0)

  // Transfer the source first, allowing finalization to arrive before the terminal take.
  const carrier = issuePeerM3RouteCarrier(finalResult.runtime, finalResult.authorization)
  t.ok(carrier, 'source route carrier issued')
  const routeCarrier = takeM3RouteTransport(carrier)
  t.teardown(() => destroyM3RouteTransport(routeCarrier))
  t.ok(routeCarrier, 'source route carrier taken')
  t.exception(() => takePeerM3RouteCarrier(carrier), 'replay on taken carrier throws')
  t.exception(
    () => takePeerFinalCarrierAuthorization(finalResult.authorization, finalResult.runtime),
    'spent authorization throws replay on direct call'
  )
  const earlyPayloads = [
    b4a.from('first finalization queued before terminal carrier take'),
    b4a.from('second finalization queued before terminal carrier take')
  ]
  const earlyCounter = finalizeCounters[0]
  for (const payload of earlyPayloads) {
    const earlyFrame = sealPeerContextFrame({
      contextClass: 5,
      circuitId,
      generation: 1n,
      direction: 0,
      counter: finalizeCounters[0]++,
      key: sourceMaterial.finalizeForwardKey,
      noncePrefix: sourceMaterial.finalizeForwardNoncePrefix,
      payload
    })
    await sendM3RouteFrame(routeCarrier, earlyFrame)
    earlyFrame.fill(0)
  }
  await new Promise((resolve) => setTimeout(resolve, 10))

  const termCarrier = issuePeerM3RouteCarrier(termResult.runtime, termResult.authorization)
  t.ok(termCarrier, 'terminal route carrier issued')
  const termRouteCarrier = takeM3RouteTransport(termCarrier)
  t.teardown(() => destroyM3RouteTransport(termRouteCarrier))
  t.ok(termRouteCarrier, 'terminal route carrier taken')
  t.exception(() => takePeerM3RouteCarrier(termCarrier), 'terminal replay on taken carrier throws')
  t.exception(
    () => takePeerFinalCarrierAuthorization(termResult.authorization, termResult.runtime),
    'spent terminal authorization throws replay'
  )

  t.alike(
    sourceMaterial.tailControlTranscript,
    terminalMaterial.tailControlTranscript,
    'both final owners retain the identical authenticated extension2 transcript'
  )
  for (let i = 0; i < earlyPayloads.length; i++) {
    const queuedFrame = await receiveReservedM3RouteFrame(reserveM3RouteFrame(termRouteCarrier))
    const queuedOpened = openPeerContextFrame(
      {
        contextClass: 5,
        circuitId,
        generation: 1n,
        direction: 0,
        counter: earlyCounter + BigInt(i),
        key: terminalMaterial.finalizeForwardKey,
        noncePrefix: terminalMaterial.finalizeForwardNoncePrefix
      },
      queuedFrame
    )
    t.alike(
      queuedOpened.payload,
      earlyPayloads[i],
      'early finalization survives transfer in arrival order'
    )
    queuedOpened.plaintext.fill(0)
    queuedFrame.fill(0)
  }
  for (const direction of [0, 1]) {
    const sender = direction === 0 ? routeCarrier : termRouteCarrier
    const receiver = direction === 0 ? termRouteCarrier : routeCarrier
    const senderMaterial = direction === 0 ? sourceMaterial : terminalMaterial
    const receiverMaterial = direction === 0 ? terminalMaterial : sourceMaterial
    const keyName = direction === 0 ? 'finalizeForwardKey' : 'finalizeReverseKey'
    const nonceName = direction === 0 ? 'finalizeForwardNoncePrefix' : 'finalizeReverseNoncePrefix'
    const payload = b4a.from(`native final-carrier direction ${direction}`)
    const counter = finalizeCounters[direction]++
    const frame = sealPeerContextFrame({
      contextClass: 5,
      circuitId,
      generation: 1n,
      direction,
      counter,
      key: senderMaterial[keyName],
      noncePrefix: senderMaterial[nonceName],
      payload
    })
    const received = receiveReservedM3RouteFrame(reserveM3RouteFrame(receiver))
    if (direction === 0) {
      t.is(releaseHeldTail(), true, 'an actual Native tail packet resumes after transfer with a carrier reader pending')
    }
    await sendM3RouteFrame(sender, frame)
    const receivedFrame = await received
    const opened = openPeerContextFrame(
      {
        contextClass: 5,
        circuitId,
        generation: 1n,
        direction,
        counter,
        key: receiverMaterial[keyName],
        noncePrefix: receiverMaterial[nonceName]
      },
      receivedFrame
    )
    t.alike(opened.payload, payload, 'finalize-key payload traverses both Native extensions')
    opened.plaintext.fill(0)
    frame.fill(0)
    receivedFrame.fill(0)
  }

  // Separate test-only route AEAD material exercises carriage, not purpose negotiation.
  async function exchangeClassifiedFrame(direction, contextClass, finalize = false) {
    const sender = direction === 0 ? routeCarrier : termRouteCarrier
    const receiver = direction === 0 ? termRouteCarrier : routeCarrier
    const senderMaterial = direction === 0 ? sourceMaterial : terminalMaterial
    const receiverMaterial = direction === 0 ? terminalMaterial : sourceMaterial
    const keyName = direction === 0 ? 'finalizeForwardKey' : 'finalizeReverseKey'
    const nonceName = direction === 0 ? 'finalizeForwardNoncePrefix' : 'finalizeReverseNoncePrefix'
    const key = contextClass === 6 ? seed(0xd0 + direction) : senderMaterial[keyName]
    const noncePrefix =
      contextClass === 6 ? b4a.alloc(16, 0xd4 + direction) : senderMaterial[nonceName]
    const parameters = {
      contextClass,
      circuitId,
      routeId: b4a.alloc(16, 0x93),
      purpose: 1,
      generation: 1n,
      direction,
      counter: contextClass === 5 ? finalizeCounters[direction]++ : 0n,
      key,
      noncePrefix
    }
    const payload = b4a.from(`classified Native ${contextClass}/${direction}`)
    const frame = sealPeerContextFrame({ ...parameters, payload })
    const reservation = reserveM3RouteFrame(receiver)
    const receiving = receiveReservedM3RouteEnvelope(reservation)
    await (finalize ? sendM3FinalizeFrame(sender, frame) : sendM3RouteFrame(sender, frame))
    const received = await receiving
    const opened = openPeerContextFrame(
      {
        ...parameters,
        contextClass: received.contextClass,
        key: contextClass === 6 ? key : receiverMaterial[keyName],
        noncePrefix: contextClass === 6 ? noncePrefix : receiverMaterial[nonceName]
      },
      received.frame
    )
    t.alike(
      opened.payload,
      payload,
      'authenticated context remains distinct across Native carriage'
    )
    opened.plaintext.fill(0)
    received.frame.fill(0)
    frame.fill(0)
    if (contextClass === 6) {
      key.fill(0)
      noncePrefix.fill(0)
    }
    return reservation
  }

  activateM3RouteTransport(routeCarrier)
  const spentReceive = await exchangeClassifiedFrame(0, 6)
  await exchangeClassifiedFrame(1, 5) // Receiving class6 did not promote the terminal.
  await exchangeClassifiedFrame(0, 5, true) // Explicit class5 retry survives local promotion.
  activateM3RouteTransport(termRouteCarrier)
  await exchangeClassifiedFrame(1, 6)
  let replayCode = null
  try {
    receiveReservedM3RouteFrame(spentReceive)
  } catch (error) {
    replayCode = error.code
  }
  t.is(replayCode, 'ERR_REPLAY', 'class-aware receive consumes the shared reservation exactly once')
  t.exception(
    () => activateM3RouteTransport(termRouteCarrier),
    'local promotion cannot be replayed'
  )

  let timerCalls = 0
  scheduleM3RouteTransportTimer(routeCarrier, 100, () => {
    timerCalls++
  })
  f.clock.advance(100)
  t.is(timerCalls, 1, 'carrier timers run on the borrowed Native clock')
  const parentClock = readM3RouteTransportClock(termRouteCarrier)
  const remaining = Number(parentClock.localDeadline - parentClock.monotonicNow())
  scheduleM3RouteTransportTimer(termRouteCarrier, remaining + 1, () => {
    timerCalls++
  })
  const pendingReceive = receiveReservedM3RouteEnvelope(reserveM3RouteFrame(termRouteCarrier)).then(
    () => null,
    (error) => error.code
  )
  f.clock.advance(remaining)
  t.is(await pendingReceive, 'ERR_DESTROYED', 'original carrier expiry settles an owned receive')
  t.is(timerCalls, 1, 'a scheduled callback cannot survive its carrier deadline')
})

test('regression: responder tail rejects a signer unrelated to its authenticated runtime', async (t) => {
  // Safety responder signs with an unrelated relay identity
  const clock = fakeClock(1000n)
  const unrelatedIdentity = safetyIdentity(220)
  const unrelatedRoute = cryptoSuite.encryptionKeyPair(seed(221))
  const dummyEndpoint = new (require('../../lib/private/udx-cell-endpoint').UdxCellEndpoint)({
    host: '127.0.0.1',
    port: 48999,
    onBootstrap() {},
    onCell() {
      return true
    },
    onLinkFailure() {}
  })
  const wrongRelayOwner = createPeerRelayOwner({
    endpoint: dummyEndpoint,
    identityKeyPair: unrelatedIdentity,
    routeKeyPair: unrelatedRoute,
    advertisementFields: {
      relayIdentity32: unrelatedIdentity.publicKey,
      currentDhtNodeId32: seed(0x99),
      reachableEndpoint: { host: '127.0.0.1', port: 48999 },
      routeEncryptionPublicKey32: unrelatedRoute.publicKey,
      capabilityMask: 9,
      minimumVersion: 2,
      maximumVersion: 2,
      datagramReplayWindow: 64,
      maxConcurrentCircuits: 8,
      capacityClass: 0,
      maxCells: 100,
      maxBytes: 120000,
      maxCommands: 100,
      idleTimeoutMs: 30000,
      maxQueuedBytes: 65536,
      epoch: 7n,
      issuedAt: 1000n,
      expiresAt: 60000n,
      policyCount: 0
    },
    clockIdentity: clock,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer
  })

  const f = await setupFourNodeNativeFixture({
    t,
    clock,
    native: true,
    basePort: 48350,
    poolCapacity: 4096,
    safetyRelayOwnerOverride: wrongRelayOwner
  })
  t.teardown(async () => {
    destroyPeerRelayOwner(wrongRelayOwner)
    await dummyEndpoint.close()
  })

  const { sourceTailSession, limits } = await f.openSourceA0()

  const candidate1 = await discoverPeerTailCandidate(sourceTailSession, {
    mode: 1,
    requestedMask: 9,
    randomTarget32: seed(0x21),
    expiresAt: 50000n
  })

  const localFailure = f.safety.tailStarted.then(
    () => t.fail('unrelated tail signer must reject before READY'),
    (err) =>
      t.is(err.code, 'UNAUTHORIZED', 'local signer binding rejects independently of clock identity')
  )
  const sourceFailure = extendPeerTail(sourceTailSession, {
    candidate: candidate1,
    forwardLimits: limits,
    reverseLimits: limits,
    payloadParametersDigest: seed(0x41)
  }).then(
    () => t.fail('source cannot publish an extension without authenticated READY'),
    (err) =>
      t.ok(err instanceof PrivateRouteError, 'source operation rejects within its owned lifetime')
  )
  await localFailure
  clock.advance(2000)
  await sourceFailure
})

test('regression: readiness exhaustion times out and does not hang when TAIL_READY is suppressed', async (t) => {
  const c = fakeClock(1000n)
  const f = await setupFourNodeNativeFixture({
    t,
    clock: c,
    native: true,
    basePort: 48400,
    poolCapacity: 4096,
    suppressSafetyTailReady: true
  })
  const { sourceTailSession, limits } = await f.openSourceA0()

  const candidate1 = await discoverPeerTailCandidate(sourceTailSession, {
    mode: 1,
    requestedMask: 9,
    randomTarget32: seed(0x21),
    expiresAt: 50000n
  })

  // Start extend: Guard opens A1 to Safety, Safety establishes link, Guard sends EXTENDED
  const failure = extendPeerTail(sourceTailSession, {
    candidate: candidate1,
    forwardLimits: limits,
    reverseLimits: limits,
    payloadParametersDigest: seed(0x41)
  }).then(
    () => t.fail('EXTENDED without READY must expire'),
    (err) =>
      t.ok(err instanceof PrivateRouteError, 'owned readiness deadline rejects the extension')
  )

  // Yield until Safety's link is established and Guard has sent EXTENDED to Source
  await f.safety.tailStarted
  await new Promise((resolve) => setImmediate(resolve))
  await new Promise((resolve) => setImmediate(resolve))

  // Source received EXTENDED and is now waiting for TAIL_READY with exhaustion timer
  // The original two-second window remains live after EXTENDED stops request retries.
  for (let i = 0; i < 8; i++) {
    c.advance(250)
    await new Promise((resolve) => setImmediate(resolve))
  }

  await failure

  // Session is destroyed after readiness exhaustion; read throws
  t.exception(
    () => readPeerTailControl(sourceTailSession),
    'session destroyed after readiness exhaustion'
  )
})

test('regression: destroy during in-flight discovery cancels operations without wedging', async (t) => {
  const f = await setupFourNodeNativeFixture({
    t,
    native: true,
    basePort: 48450,
    poolCapacity: 4096
  })
  const { sourceTailSession } = await f.openSourceA0()

  const discoverPromise = discoverPeerTailCandidate(sourceTailSession, {
    mode: 1,
    requestedMask: 9,
    randomTarget32: seed(0x21),
    expiresAt: 50000n
  })

  // Destroy session immediately while discovery is in-flight
  t.is(destroyPeerTailControl(sourceTailSession), true, 'session destroyed')

  let caught = false
  try {
    await discoverPromise
  } catch (err) {
    caught = true
    t.is(err.code, 'ERR_DESTROYED', 'in-flight discover rejects with ERR_DESTROYED')
  }
  t.is(caught, true, 'in-flight discover caught rejection')

  // readPeerTailControl throws on destroyed session per contract
  t.exception(() => readPeerTailControl(sourceTailSession), 'read throws on destroyed session')

  // Subsequent discover also throws ERR_DESTROYED
  t.exception(() => {
    discoverPeerTailCandidate(sourceTailSession, {
      mode: 1,
      requestedMask: 9,
      randomTarget32: seed(0x21),
      expiresAt: 50000n
    })
  }, 'subsequent discover on destroyed session throws')
})

test('regression: legal asymmetric forward and reverse expiry bounds succeed in real native flow', async (t) => {
  const f = await setupFourNodeNativeFixture({
    t,
    native: true,
    basePort: 48500,
    poolCapacity: 4096
  })
  const { sourceTailSession } = await f.openSourceA0()

  const candidate1 = await discoverPeerTailCandidate(sourceTailSession, {
    mode: 1,
    requestedMask: 9,
    randomTarget32: seed(0x21),
    expiresAt: 50000n
  })

  // Legally asymmetric limits: forward 45000n vs reverse 50000n
  const forwardLimits = {
    cellSize: 1200,
    maxCells: 30,
    maxBytes: 36000,
    maxCommands: 21,
    idleTimeoutMs: 30000,
    expiresAt: 45000n
  }
  const reverseLimits = {
    cellSize: 1200,
    maxCells: 30,
    maxBytes: 36000,
    maxCommands: 21,
    idleTimeoutMs: 30000,
    expiresAt: 50000n
  }

  await extendPeerTail(sourceTailSession, {
    candidate: candidate1,
    forwardLimits,
    reverseLimits,
    payloadParametersDigest: seed(0x41)
  })

  const desc = readPeerTailControl(sourceTailSession)
  t.is(desc.extensionIndex, 1, 'asymmetric expiry extension succeeds over real Native carriage')
})

test('regression: real tail ownership releases finite storage after failure and destruction', async (t) => {
  const tinyPool = createPeerMemoryPool(32)
  const fixture = await authenticatedPeer(t, 49571, 2, true)
  t.exception(
    () =>
      createPeerTailControl(fixture.peerRuntime, {
        relayOwner: fixture.f.peerRelayOwner,
        neighborPool: fixture.f.peerPool,
        runtimeAuthority: fixture.peerAuthority,
        memoryPool: tinyPool
      }),
    'insufficient retained storage rejects genuine runtime adoption'
  )
  t.is(readPeerMemory(tinyPool).reservedBytes, 0, 'failed admission releases partial reservations')

  const second = await authenticatedPeer(t, 49573, 2, true)
  const pool = createPeerMemoryPool(64000)
  const session = createPeerTailControl(second.peerRuntime, {
    relayOwner: second.f.peerRelayOwner,
    neighborPool: second.f.peerPool,
    runtimeAuthority: second.peerAuthority,
    memoryPool: pool
  })
  t.exception(
    () => reservePeerMemory(pool, 'competing-owner', 64000),
    'live tail ownership prevents another owner from reserving its bytes'
  )
  destroyPeerTailControl(session)
  await new Promise((resolve) => setImmediate(resolve))
  await new Promise((resolve) => setImmediate(resolve))
  const reclaimed = reservePeerMemory(pool, 'replacement-owner', 64000)
  releasePeerMemory(reclaimed)
  t.is(
    readPeerMemory(pool).reservedBytes,
    0,
    'destruction and actual Native completion return the complete pool to another owner'
  )
})

test('regression: duplicate and retry request retransmission from cached responder response', async (t) => {
  const c = fakeClock(1000n)
  const f = await setupFourNodeNativeFixture({
    t,
    clock: c,
    native: false,
    basePort: 48550,
    poolCapacity: 4096
  })
  const { sourceTailSession } = await f.openSourceA0()

  // Intercept Guard socket to drop only the first discover response
  const socket = f.fixture.rightObserver.socket
  t.ok(socket, 'guard socket available for packet interception in non-native mode')
  const send = socket.send
  let droppedFirstResponse = false

  socket.send = function (packet, port, host) {
    if (!droppedFirstResponse) {
      droppedFirstResponse = true
      return true // drop first discover response packet to trigger retransmission
    }
    return send.call(socket, packet, port, host)
  }

  const req = {
    mode: 1,
    requestedMask: 9,
    randomTarget32: seed(0x21),
    expiresAt: 50000n
  }

  const discoverPromise = discoverPeerTailCandidate(sourceTailSession, req)

  // Yield to let the initial request be processed and the first response dropped
  await new Promise((resolve) => setImmediate(resolve))
  await new Promise((resolve) => setImmediate(resolve))
  t.is(droppedFirstResponse, true, 'first discover response was dropped')

  // Advance fake clock past the 250ms retry interval so Source retransmits the frozen request/nonce
  c.advance(300)
  await new Promise((resolve) => setImmediate(resolve))
  await new Promise((resolve) => setImmediate(resolve))

  // Responder recognizes identical request/nonce and re-sends cached response
  const candidate = await discoverPromise
  t.ok(candidate, 'discover resolves on retry from cached response without wedging')

  socket.send = send
})

test('lost EXTENDED reply is recovered after its old tail has become a forwarder', async (t) => {
  const clock = fakeClock(1000n)
  const f = await setupFourNodeNativeFixture({
    t,
    clock,
    native: false,
    basePort: 48600,
    poolCapacity: 4096
  })
  const { sourceTailSession, limits } = await f.openSourceA0()
  const candidate = await discoverPeerTailCandidate(sourceTailSession, {
    mode: 1,
    requestedMask: 9,
    randomTarget32: seed(0x21),
    expiresAt: 50000n
  })
  const socket = f.fixture.rightObserver.socket
  const send = socket.send
  let dropped = false
  socket.send = function (packet, port, host) {
    if (!dropped && port === 48600 && packet.length === 1200) {
      dropped = true
      return true
    }
    return send.call(socket, packet, port, host)
  }
  t.teardown(() => {
    socket.send = send
  })
  let outcome = null
  const extending = extendPeerTail(sourceTailSession, {
    candidate,
    forwardLimits: limits,
    reverseLimits: limits,
    payloadParametersDigest: seed(0x41)
  }).then(
    () => {
      outcome = { success: true }
    },
    (error) => {
      outcome = { error }
    }
  )
  await f.safety.tailStarted
  await new Promise((resolve) => setImmediate(resolve))
  await new Promise((resolve) => setImmediate(resolve))
  t.is(dropped, true, 'first upstream EXTENDED datagram was lost')
  t.is(
    readPeerTailControl(f.guard.tailSession).phase,
    'FORWARDING',
    'old tail transferred its Native receive pump before retransmission'
  )
  for (let attempt = 0; attempt < 8 && outcome === null; attempt++) {
    clock.advance(250)
    await new Promise((resolve) => setImmediate(resolve))
    await new Promise((resolve) => setImmediate(resolve))
  }
  await extending
  if (outcome.error) throw outcome.error
  t.is(
    readPeerTailControl(sourceTailSession).extensionIndex,
    1,
    'cached old-key reply and successor READY complete the original extension'
  )
  const pulse = setInterval(() => clock.advance(25), 5)
  t.teardown(() => clearInterval(pulse))
  const terminalCandidate = await discoverPeerTailCandidate(sourceTailSession, {
    mode: 2,
    requestedMask: 11,
    randomTarget32: seed(0x71),
    suppliedAdvertisement260: readVerifiedPeerAdvertisement(f.terminal.verifiedAd)
      .canonicalBytes260,
    expiresAt: 50000n
  })
  await extendPeerTail(sourceTailSession, {
    candidate: terminalCandidate,
    forwardLimits: limits,
    reverseLimits: limits,
    payloadParametersDigest: seed(0x91)
  })
  t.is(
    readPeerTailControl(sourceTailSession).phase,
    'FINAL_EXIT_READY',
    'new-key traffic still crosses the same forwarder through extension two'
  )
})

for (const [index, delay] of [250, 2000].entries()) {
  test(`tail rejects a synchronous ${delay}ms timer registration without retaining its late handle`, async (t) => {
    const clock = fakeClock(1000n)
    const setTimer = clock.setTimer
    let inject = false
    let stale = null
    clock.setTimer = (callback, ms) => {
      const handle = setTimer(callback, ms)
      if (inject && ms === delay) {
        inject = false
        stale = callback
        callback()
      }
      return handle
    }
    const f = await setupFourNodeNativeFixture({
      t,
      clock,
      native: false,
      basePort: 48610 + index * 10,
      poolCapacity: 4096
    })
    const { sourceTailSession } = await f.openSourceA0()
    inject = true
    let outcome = null
    const discovering = discoverPeerTailCandidate(sourceTailSession, {
      mode: 1,
      requestedMask: 9,
      randomTarget32: seed(0x21),
      expiresAt: 50000n
    }).then(
      (candidate) => {
        outcome = { candidate }
      },
      (error) => {
        outcome = { error }
      }
    )
    for (let attempt = 0; attempt <= 8 && outcome === null; attempt++) {
      await new Promise((resolve) => setImmediate(resolve))
      await new Promise((resolve) => setImmediate(resolve))
      if (outcome === null) clock.advance(250)
    }
    await discovering
    t.ok(stale, 'the scheduler invoked the selected registration inline')
    t.is(
      outcome.error && outcome.error.code,
      'ERR_PRIVACY_UNAVAILABLE',
      'invalid scheduling cannot publish an admitted candidate'
    )
    const timers = clock.timerCount()
    if (stale) stale()
    t.is(clock.timerCount(), timers, 'a late callback cannot recreate retired timers')
    await f.close()
    for (let attempt = 0; attempt < 8; attempt++) {
      clock.advance(500)
      await new Promise((resolve) => setImmediate(resolve))
    }
    t.is(clock.timerCount(), 0, 'tail handles and bounded Native closure duties retire')
    t.is(readPeerMemory(f.source.memoryPool).reservedBytes, 0)
    t.is(readPeerMemory(f.guard.memoryPool).reservedBytes, 0)
  })
}

test('authenticated READY cannot beat an expired operation by preceding its delayed timer callback', async (t) => {
  const clock = fakeClock(1000n)
  const monotonicNow = clock.monotonicNow
  let elapsedWithoutTimers = 0n
  clock.monotonicNow = () => monotonicNow() + elapsedWithoutTimers
  const f = await setupFourNodeNativeFixture({
    t,
    clock,
    native: false,
    basePort: 48630,
    poolCapacity: 4096
  })
  const { sourceTailSession, limits } = await f.openSourceA0()
  const candidate = await discoverPeerTailCandidate(sourceTailSession, {
    mode: 1,
    requestedMask: 9,
    randomTarget32: seed(0x21),
    expiresAt: 50000n
  })
  const socket = f.fixture.rightObserver.socket
  const send = socket.send
  let upstreamFrames = 0
  let releaseReady = null
  socket.send = function (packet, port, host) {
    if (port === 48630 && packet.length === 1200 && ++upstreamFrames === 2) {
      const held = b4a.from(packet)
      releaseReady = () => {
        send.call(socket, held, port, host)
        held.fill(0)
      }
      return true
    }
    return send.call(socket, packet, port, host)
  }
  t.teardown(() => {
    socket.send = send
  })
  const deadline = clock.monotonicNow() + 2000n
  const extending = extendPeerTail(sourceTailSession, {
    candidate,
    forwardLimits: limits,
    reverseLimits: limits,
    payloadParametersDigest: seed(0x41)
  }).then(
    () => null,
    (error) => error
  )
  await f.safety.tailStarted
  for (let attempt = 0; attempt < 7 && !releaseReady; attempt++) {
    await new Promise((resolve) => setImmediate(resolve))
    await new Promise((resolve) => setImmediate(resolve))
    if (!releaseReady) clock.advance(250)
  }
  t.ok(releaseReady, 'successor READY is held after authenticated EXTENDED delivery')
  elapsedWithoutTimers = deadline - monotonicNow()
  if (releaseReady) releaseReady()
  else clock.advance(2000)
  const failure = await extending
  t.is(
    failure && failure.code,
    'ERR_PRIVACY_UNAVAILABLE',
    'the original deadline governs the receive continuation, not timer dispatch order'
  )
})

test('terminal carrier retains its original Native READY2 duty after the tail owner closes', async (t) => {
  const clock = fakeClock()
  let countFinalSourcePackets = false
  let finalSourcePackets = 0
  let droppedReady = 0
  let terminalActivation = null
  let terminalMaterial = null
  let terminalCarrier = null
  let terminalFailure = null
  const f = await interceptNativeMessages((socket, args) => {
    if (countFinalSourcePackets && socket.address()?.port === 48720 &&
        args[0].byteLength === 1200 && args[0][1] === CELL_CLASS.DATAGRAM) {
      if (++finalSourcePackets === 2) {
        droppedReady++
        return false
      }
    }
  }, () => setupFourNodeNativeFixture({
    t, clock, native: true, basePort: 48720, poolCapacity: 4096,
    onTerminalFinalReady(session) {
      try {
        const handoff = createPeerFinalExitHandoff(session)
        terminalActivation = claimFinalExitActivation(handoff, createFinalExitActivationClaim(handoff))
        terminalMaterial = consumeFinalExitActivationOwner(terminalActivation)
        const taken = takePeerTailFinalRuntime(session, terminalActivation)
        terminalCarrier = takeM3RouteTransport(issuePeerM3RouteCarrier(taken.runtime, taken.authorization))
        destroyPeerTailControl(session)
      } catch (err) {
        terminalFailure = err
        throw err
      }
    }
  }))
  t.teardown(() => {
    if (terminalCarrier) destroyM3RouteTransport(terminalCarrier)
    if (terminalActivation) destroyFinalExitActivationOwner(terminalActivation)
  })
  const { sourceTailSession, limits } = await f.openSourceA0()
  const safety = await discoverPeerTailCandidate(sourceTailSession, {
    mode: 1, requestedMask: 9, randomTarget32: seed(0x31), expiresAt: 50000n
  })
  await extendPeerTail(sourceTailSession, {
    candidate: safety, forwardLimits: limits, reverseLimits: limits, payloadParametersDigest: seed(0x51)
  })
  const terminal = await discoverPeerTailCandidate(sourceTailSession, {
    mode: 2, requestedMask: 11, randomTarget32: seed(0x61), expiresAt: 50000n,
    suppliedAdvertisement260: readVerifiedPeerAdvertisement(f.terminal.verifiedAd).canonicalBytes260
  })
  countFinalSourcePackets = true
  let outcome = null
  const extending = extendPeerTail(sourceTailSession, {
    candidate: terminal, forwardLimits: limits, reverseLimits: limits, payloadParametersDigest: seed(0x71)
  }).then(() => { outcome = 'FINAL_EXIT_READY' }, err => { outcome = err.code })
  for (let i = 0; i < 40 && !terminalCarrier && !terminalFailure; i++) {
    await new Promise(resolve => setTimeout(resolve, 5))
  }
  t.is(terminalFailure, null, 'terminal transfers immediately on its first READY2 dispatch')
  t.ok(terminalCarrier, 'terminal carrier exists before source completion')
  t.is(outcome, null, 'first lost READY2 has not completed the source')
  const materialBytes = Object.values(terminalMaterial).reduce(
    (sum, value) => sum + (b4a.isBuffer(value) ? value.byteLength : 0), 0
  )
  let spare = null
  let refused = false
  try {
    spare = reservePeerMemory(f.terminal.memoryPool, 'pending-readiness-capacity-probe', 4096 - materialBytes)
  } catch {
    refused = true
  } finally {
    if (spare) releasePeerMemory(spare)
  }
  t.is(refused, true, 'retired tail cannot free storage still owned by its residual READY2 duty')
  for (let i = 0; i < 9; i++) {
    clock.advance(250)
    await new Promise(resolve => setTimeout(resolve, 5))
  }
  await extending
  t.is(droppedReady, 1, 'exactly the first Native READY2 was lost upstream')
  t.is(outcome, 'FINAL_EXIT_READY', 'original remaining READY2 attempts complete source verification')
  const reclaimed = reservePeerMemory(f.terminal.memoryPool, 'finished-readiness-capacity-probe', 4096 - materialBytes)
  releasePeerMemory(reclaimed)
  destroyFinalExitActivationOwner(terminalActivation)
  terminalActivation = null
  t.is(readPeerMemory(f.terminal.memoryPool).reservedBytes, 0,
    'residual duty and moved final material release all terminal tail storage')
})
