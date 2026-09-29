'use strict'

const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-universal')
const NativeUDX = require('udx-native')

const { PrivateRouteError } = require('../../lib/private/errors')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { CELL_CLASS, DOMAIN } = require('../../lib/private/protocol')
const { PEER_PROTOCOL_VERSION, PEER_MESSAGE_ID } = require('../../lib/private/peer-protocol')
const { sealPeerContextFrame, openPeerContextFrame } = require('../../lib/private/peer-m3-context')
const { sealPeerSourceLayers } = require('../../lib/private/peer-crypto')
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
  takePeerFinalCarrierAuthorization,
  readPeerFinalCarrierLayers
} = require('../../lib/private/peer-tail-control')
const {
  adoptPeerEstablishedLink,
  isPeerM3Runtime,
  takePeerM3TailMaterial,
  destroyPeerM3Runtime,
  sendPeerM3Payload,
  receivePeerM3Payload,
  issuePeerM3RouteCarrier,
  takePeerM3RouteCarrier,
  beginPeerM3BranchTeardown
} = require('../../lib/private/peer-m3-adjacency-runtime')
const { readPeerNativeNeighborDiagnostics } = require('../../lib/private/peer-native-neighbors')
const {
  createPeerRelayOwner,
  destroyPeerRelayOwner,
  readPeerRelayOwner,
  readVerifiedPeerAdvertisement
} = require('../../lib/private/peer-capability')
const {
  encodePeerTransport,
  decodePeerTransport
} = require('../../lib/private/peer-transport-wire')
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

function transcriptU64(transcript, offset) {
  let value = 0n
  for (let i = offset; i < offset + 8; i++) value = (value << 8n) | BigInt(transcript[i])
  return value
}

// The first six bytes of every version 3 peer object: version u32 and message id u16.
function peerObjectHeader(messageId) {
  return b4a.from([0, 0, 0, PEER_PROTOCOL_VERSION, messageId >> 8, messageId & 0xff])
}

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

// The send-side mirror of interceptNativeMessages: onSend may return a substitute send
// result (for example a deferred promise) to govern one dispatch deterministically,
// or nothing to let the real datagram through.
async function interceptNativeSends(onSend, setup) {
  const createSocket = NativeUDX.prototype.createSocket
  NativeUDX.prototype.createSocket = function (options) {
    const socket = createSocket.call(this, options)
    const send = socket.send
    socket.send = function (buffer, port, host) {
      const substitute = onSend(socket, buffer, port, host)
      if (substitute !== undefined) return substitute
      return send.call(this, buffer, port, host)
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
  t.is(desc.protocolVersion, PEER_PROTOCOL_VERSION)
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

test('peer final-exit commit rejects material changed after prepare', async (t) => {
  const peerTailControlModule = require('../../lib/private/peer-tail-control')
  const scenarios = [
    ['localDeadline', (material) => (material.localDeadline += 1n)],
    ['tailControl', (material) => (material.tailControl = Object.freeze({}))],
    ['clockIdentity', (material) => (material.clockIdentity = Object.freeze({}))]
  ]

  for (let index = 0; index < scenarios.length; index++) {
    const [field, mutate] = scenarios[index]
    const fixture = await authenticatedPeer(t, 49620 + index * 4, 2, true)
    const session = createPeerTailControl(fixture.peerRuntime, {
      relayOwner: fixture.f.peerRelayOwner,
      neighborPool: fixture.f.peerPool,
      runtimeAuthority: fixture.peerAuthority,
      memoryPool: createPeerMemoryPool(4096)
    })
    const handoff = createPeerFinalExitHandoff(session)
    const originalPrepare = peerTailControlModule.prepareTailControlFinalExitActivation
    let material = null
    let original = null

    peerTailControlModule.prepareTailControlFinalExitActivation = (...args) => {
      const prepared = originalPrepare(...args)
      material = prepared.material
      original = { ...material }
      mutate(material)
      return prepared
    }
    try {
      t.exception(
        () => claimFinalExitActivation(handoff, createFinalExitActivationClaim(handoff)),
        `${field} substitution cannot cross the prepare/commit boundary`
      )
    } finally {
      peerTailControlModule.prepareTailControlFinalExitActivation = originalPrepare
      if (material && original) Object.assign(material, original)
      destroyPeerTailControl(session)
    }
  }
})

test('two-extension v2 tail control and one-shot final handoff complete flow over genuine Native carriage', async (t) => {
  let terminalSession = null
  let holdNextTerminalPacket = false
  let releaseHeldTail = null
  let signalHeldTail
  const heldTail = new Promise((resolve) => {
    signalHeldTail = resolve
  })
  t.teardown(() => {
    if (releaseHeldTail) releaseHeldTail()
  })
  const f = await interceptNativeMessages(
    (socket, args, emit) => {
      if (
        holdNextTerminalPacket &&
        socket.address()?.port === 48303 &&
        args[0].byteLength === 1200 &&
        args[0][1] === CELL_CLASS.DATAGRAM
      ) {
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
    },
    () =>
      setupFourNodeNativeFixture({
        t,
        native: true,
        basePort: 48300,
        poolCapacity: 8192,
        onTerminalFinalReady(session) {
          terminalSession = session
        }
      })
  )

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

  // Version 3: every hop carries its own identifiers. The source now tracks the terminal's,
  // and no relay's own tuple repeats a value of another relay's own tuple. What each relay
  // can see beyond its own tuple is inventoried in its own test below.
  const hopDescriptors = [
    readPeerTailControl(await f.guard.tailStarted),
    readPeerTailControl(await f.safety.tailStarted),
    readPeerTailControl(terminalTailSession)
  ]
  const terminalDesc = hopDescriptors[2]
  t.alike(desc2.branchId, terminalDesc.branchId, 'source tracks the terminal branch identifier')
  t.alike(desc2.circuitId, terminalDesc.circuitId, 'source tracks the terminal circuit identifier')
  t.is(desc2.generation, terminalDesc.generation, 'source tracks the terminal generation')
  for (const [a, b, label] of [
    [0, 1, 'guard and safety'],
    [1, 2, 'safety and terminal'],
    [0, 2, 'guard and terminal']
  ]) {
    const left = hopDescriptors[a]
    const right = hopDescriptors[b]
    t.absent(b4a.equals(left.branchId, right.branchId), `${label} own branch identifiers differ`)
    t.absent(b4a.equals(left.circuitId, right.circuitId), `${label} own circuit identifiers differ`)
    t.not(left.generation, right.generation, `${label} own generations differ`)
  }

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
  // Finalization frames carry the terminal hop's generation from the same transcript.
  const finalGeneration = transcriptU64(sourceMaterial.tailControlTranscript, 89)
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
  t.is(finalResult.generation, 1n, 'source runtime generation is the guard link generation')
  // The source removes the guard's and safety's layers; raw injections below are wrapped
  // the same way so both forwarders deliver them unchanged to the terminal.
  const sourceLayers = readPeerFinalCarrierLayers(finalResult.authorization, finalResult.runtime)
  t.is(sourceLayers.length, 2, 'the source holds one layer key set per forwarding hop')
  const layered = (envelope) => sealPeerSourceLayers(sourceLayers, b4a.from(envelope))
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
  t.is(
    termResult.generation,
    terminalDesc.generation,
    "terminal runtime generation is the terminal hop's own generation"
  )
  t.not(termResult.generation, finalResult.generation, 'guard and terminal links differ')
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
  await sendPeerM3Payload(finalResult.runtime, layered(obsoleteTailEnvelope))
  const pendingRawPayload = await pendingRawRead
  t.alike(
    pendingRawPayload,
    obsoleteTailEnvelope,
    'refused transfer leaves the original reader usable'
  )
  pendingRawPayload.fill(0)

  await sendPeerM3Payload(finalResult.runtime, {
    class: CELL_CLASS.DATAGRAM,
    payload: layered(obsoleteTailEnvelope)
  })
  await new Promise((resolve) => setTimeout(resolve, 10))
  let forgedError = null
  try {
    issuePeerM3RouteCarrier(termResult.runtime, Object.freeze({}))
  } catch (err) {
    forgedError = err.code
  }
  t.is(forgedError, 'UNAUTHORIZED', 'a forged authorization cannot move the runtime')
  const retained = await receivePeerM3Payload(termResult.runtime)
  t.alike(retained, obsoleteTailEnvelope, 'failed transfer neither drains nor erases the queue')
  retained.fill(0)
  // Class-6 bytes cannot be authentic before purpose negotiation. Queued before the take,
  // they no longer block it: the take drops them, and the terminal reader below sees only
  // the authentic early finalization, in order.
  const prematureRouteEnvelope = b4a.alloc(1101, 0)
  prematureRouteEnvelope[0] = 6
  await sendPeerM3Payload(finalResult.runtime, {
    class: CELL_CLASS.DATAGRAM,
    payload: layered(prematureRouteEnvelope)
  })
  await sendPeerM3Payload(finalResult.runtime, layered(obsoleteTailEnvelope))
  holdNextTerminalPacket = true
  await sendPeerM3Payload(finalResult.runtime, layered(obsoleteTailEnvelope))
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
      generation: finalGeneration,
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
        generation: finalGeneration,
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
      generation: finalGeneration,
      direction,
      counter,
      key: senderMaterial[keyName],
      noncePrefix: senderMaterial[nonceName],
      payload
    })
    const received = receiveReservedM3RouteFrame(reserveM3RouteFrame(receiver))
    if (direction === 0) {
      t.is(
        releaseHeldTail(),
        true,
        'an actual Native tail packet resumes after transfer with a carrier reader pending'
      )
    }
    await sendM3RouteFrame(sender, frame)
    const receivedFrame = await received
    const opened = openPeerContextFrame(
      {
        contextClass: 5,
        circuitId,
        generation: finalGeneration,
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
      generation: finalGeneration,
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
  // Before its own route readiness the terminal cannot hold route keys, so a class-6 frame
  // that reaches it then is noise: it is dropped, and the terminal's next reader below
  // receives the class-5 retry instead.
  const earlyRouteFrame = sealPeerContextFrame({
    contextClass: 6,
    circuitId,
    routeId: b4a.alloc(16, 0x93),
    purpose: 1,
    generation: finalGeneration,
    direction: 0,
    counter: 0n,
    key: seed(0xd8),
    noncePrefix: b4a.alloc(16, 0xd9),
    payload: b4a.from('route frame before terminal readiness')
  })
  await sendM3RouteFrame(routeCarrier, earlyRouteFrame)
  await new Promise((resolve) => setTimeout(resolve, 20))
  earlyRouteFrame.fill(0)
  await exchangeClassifiedFrame(1, 5) // A dropped class6 did not promote the terminal.
  await exchangeClassifiedFrame(0, 5, true) // Explicit class5 retry survives local promotion.
  activateM3RouteTransport(termRouteCarrier)
  const spentReceive = await exchangeClassifiedFrame(0, 6)
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

test('admitted relay neighbors carry both tail extensions to a ready terminal', async (t) => {
  let terminalSession = null
  // guard↔safety and safety↔terminal come from per-node admission owners and
  // two-authority grants: no shared topology authority, fixed session keys,
  // or hand-paired provisioning.
  const f = await setupFourNodeNativeFixture({
    t,
    native: true,
    basePort: 48760,
    poolCapacity: 8192,
    admission: true,
    onTerminalFinalReady(session) {
      terminalSession = session
    }
  })
  const { sourceTailSession, limits } = await f.openSourceA0()

  const candidate1 = await discoverPeerTailCandidate(sourceTailSession, {
    mode: 1,
    requestedMask: 9,
    randomTarget32: seed(0x21),
    expiresAt: 50000n
  })
  await extendPeerTail(sourceTailSession, {
    candidate: candidate1,
    forwardLimits: limits,
    reverseLimits: limits,
    payloadParametersDigest: seed(0x41)
  })
  t.alike(
    readPeerTailControl(sourceTailSession).tailIdentity,
    f.safety.identity32,
    'guard directory discovery picks its admitted safety neighbor'
  )
  await f.safety.tailStarted

  const candidate2 = await discoverPeerTailCandidate(sourceTailSession, {
    mode: 2,
    requestedMask: 11,
    randomTarget32: seed(0x71),
    suppliedAdvertisement260: readVerifiedPeerAdvertisement(f.terminal.verifiedAd)
      .canonicalBytes260,
    expiresAt: 50000n
  })
  await extendPeerTail(sourceTailSession, {
    candidate: candidate2,
    forwardLimits: limits,
    reverseLimits: limits,
    payloadParametersDigest: seed(0x91)
  })
  const final = readPeerTailControl(sourceTailSession)
  t.is(final.extensionIndex, 2)
  t.is(final.phase, 'FINAL_EXIT_READY')
  t.alike(final.tailIdentity, f.terminal.identity32)
  t.ok(terminalSession, 'terminal published its ready tail session')
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
      minimumVersion: 3,
      maximumVersion: 3,
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
    poolCapacity: 8192,
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
    poolCapacity: 8192,
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
    poolCapacity: 8192
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

test('expired discovery candidates release same-tail admission without shortening an admitted branch', async (t) => {
  const clock = fakeClock()
  const f = await setupFourNodeNativeFixture({
    t,
    clock,
    native: true,
    basePort: 49220,
    poolCapacity: 8192
  })
  const { sourceTailSession } = await f.openSourceA0()
  const expiredCandidate = await discoverPeerTailCandidate(sourceTailSession, {
    mode: 1,
    requestedMask: 9,
    randomTarget32: seed(0x21),
    expiresAt: 1100n
  })

  clock.advance(100)
  const replacement = await discoverPeerTailCandidate(sourceTailSession, {
    mode: 1,
    requestedMask: 9,
    randomTarget32: seed(0x22),
    expiresAt: 1200n
  })
  const limits = {
    cellSize: 1200,
    maxCells: 60,
    maxBytes: 72000,
    maxCommands: 21,
    idleTimeoutMs: 30000,
    expiresAt: 45000n
  }
  const request = {
    candidate: expiredCandidate,
    forwardLimits: limits,
    reverseLimits: limits,
    payloadParametersDigest: seed(0x41)
  }
  t.exception(
    () => extendPeerTail(sourceTailSession, request),
    'retired candidate cannot consume its replacement'
  )

  await extendPeerTail(sourceTailSession, { ...request, candidate: replacement })
  const admitted = readPeerTailControl(sourceTailSession)
  t.is(admitted.extensionIndex, 1, 'replacement completes a genuine Native extension')
  t.is(admitted.wireExpiresAt, 45000n, 'discovery expiry bounds admission, not branch lifetime')
  clock.advance(100)
  const surviving = readPeerTailControl(sourceTailSession)
  t.is(surviving.phase, 'TAIL_READY', 'admitted tail remains usable at candidate expiry')
  t.is(surviving.localDeadline, admitted.localDeadline, 'candidate expiry does not rebase the tail')
})

test('regression: legal asymmetric forward and reverse expiry bounds succeed in real native flow', async (t) => {
  const f = await setupFourNodeNativeFixture({
    t,
    native: true,
    basePort: 48500,
    poolCapacity: 8192
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
    maxCells: 60,
    maxBytes: 72000,
    maxCommands: 21,
    idleTimeoutMs: 30000,
    expiresAt: 45000n
  }
  const reverseLimits = {
    cellSize: 1200,
    maxCells: 60,
    maxBytes: 72000,
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
    poolCapacity: 8192
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
    poolCapacity: 8192
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
      poolCapacity: 8192
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
    poolCapacity: 8192
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
  const poolCapacity = 8192
  let countFinalSourcePackets = false
  let finalSourcePackets = 0
  let droppedReady = 0
  let terminalActivation = null
  let terminalMaterial = null
  let terminalCarrier = null
  let terminalFailure = null
  const f = await interceptNativeMessages(
    (socket, args) => {
      if (
        countFinalSourcePackets &&
        socket.address()?.port === 48720 &&
        args[0].byteLength === 1200 &&
        args[0][1] === CELL_CLASS.DATAGRAM
      ) {
        if (++finalSourcePackets === 2) {
          droppedReady++
          return false
        }
      }
    },
    () =>
      setupFourNodeNativeFixture({
        t,
        clock,
        native: true,
        basePort: 48720,
        poolCapacity,
        onTerminalFinalReady(session) {
          try {
            const handoff = createPeerFinalExitHandoff(session)
            terminalActivation = claimFinalExitActivation(
              handoff,
              createFinalExitActivationClaim(handoff)
            )
            terminalMaterial = consumeFinalExitActivationOwner(terminalActivation)
            const taken = takePeerTailFinalRuntime(session, terminalActivation)
            terminalCarrier = takeM3RouteTransport(
              issuePeerM3RouteCarrier(taken.runtime, taken.authorization)
            )
            destroyPeerTailControl(session)
          } catch (err) {
            terminalFailure = err
            throw err
          }
        }
      })
  )
  t.teardown(() => {
    if (terminalCarrier) destroyM3RouteTransport(terminalCarrier)
    if (terminalActivation) destroyFinalExitActivationOwner(terminalActivation)
  })
  const { sourceTailSession, limits } = await f.openSourceA0()
  const safety = await discoverPeerTailCandidate(sourceTailSession, {
    mode: 1,
    requestedMask: 9,
    randomTarget32: seed(0x31),
    expiresAt: 50000n
  })
  await extendPeerTail(sourceTailSession, {
    candidate: safety,
    forwardLimits: limits,
    reverseLimits: limits,
    payloadParametersDigest: seed(0x51)
  })
  const terminal = await discoverPeerTailCandidate(sourceTailSession, {
    mode: 2,
    requestedMask: 11,
    randomTarget32: seed(0x61),
    expiresAt: 50000n,
    suppliedAdvertisement260: readVerifiedPeerAdvertisement(f.terminal.verifiedAd).canonicalBytes260
  })
  countFinalSourcePackets = true
  let outcome = null
  const extending = extendPeerTail(sourceTailSession, {
    candidate: terminal,
    forwardLimits: limits,
    reverseLimits: limits,
    payloadParametersDigest: seed(0x71)
  }).then(
    () => {
      outcome = 'FINAL_EXIT_READY'
    },
    (err) => {
      outcome = err.code
    }
  )
  for (let i = 0; i < 40 && !terminalCarrier && !terminalFailure; i++) {
    await new Promise((resolve) => setTimeout(resolve, 5))
  }
  t.is(terminalFailure, null, 'terminal transfers immediately on its first READY2 dispatch')
  t.ok(terminalCarrier, 'terminal carrier exists before source completion')
  t.is(outcome, null, 'first lost READY2 has not completed the source')
  const materialBytes = Object.values(terminalMaterial).reduce(
    (sum, value) => sum + (b4a.isBuffer(value) ? value.byteLength : 0),
    0
  )
  let spare = null
  let refused = false
  try {
    spare = reservePeerMemory(
      f.terminal.memoryPool,
      'pending-readiness-capacity-probe',
      poolCapacity - materialBytes
    )
  } catch {
    refused = true
  } finally {
    if (spare) releasePeerMemory(spare)
  }
  t.is(refused, true, 'retired tail cannot free storage still owned by its residual READY2 duty')
  for (let i = 0; i < 9; i++) {
    clock.advance(250)
    await new Promise((resolve) => setTimeout(resolve, 5))
  }
  await extending
  t.is(droppedReady, 1, 'exactly the first Native READY2 was lost upstream')
  t.is(
    outcome,
    'FINAL_EXIT_READY',
    'original remaining READY2 attempts complete source verification'
  )
  const reclaimed = reservePeerMemory(
    f.terminal.memoryPool,
    'finished-readiness-capacity-probe',
    poolCapacity - materialBytes
  )
  releasePeerMemory(reclaimed)
  destroyFinalExitActivationOwner(terminalActivation)
  terminalActivation = null
  t.is(
    readPeerMemory(f.terminal.memoryPool).reservedBytes,
    0,
    'residual duty and moved final material release all terminal tail storage'
  )
})

// READY duties are response-less: a responder's TAIL_READY expects no authenticated
// reply, so its two-second deadline ends only the duty's sending, and only when its
// first attempt succeeded and every dispatched attempt has settled. A timer that
// fires past the deadline sends nothing and never touches the tail; a failed or
// late-rejected dispatch still fails the duty (regressions for the deadline-closure
// rules of section 4.1).
//
// All retry timers live on the fixture clock, so a signal that merely fires late
// would sit next to them: the 1500ms link-liveness rule would close the quiet link
// first. holdRetryTimers captures only the timers armed by tail control itself
// (retry trains and operation deadlines; duplicate-response caches keep their own
// natural expiry), and lets every other duty keep time, so one late retry can be
// replayed while its neighbours still tick.
function holdRetryTimers(clock) {
  const setTimer = clock.setTimer
  const held = []
  clock.setTimer = (cb, ms) => {
    const stack = new Error().stack || ''
    if (!stack.includes('/private/peer-tail-control.js') || stack.includes('armDeadlineOnly')) {
      return setTimer(cb, ms)
    }
    const entry = { cb, timer: null, consumed: false, ran: false }
    entry.timer = setTimer(() => {
      entry.consumed = true
    }, ms)
    if (entry.consumed) entry.ran = true
    held.push(entry)
    return entry.timer
  }
  return {
    // Runs every captured callback whose natural fire time has passed, once each.
    // Returns how many fired.
    fireAll() {
      let fired = 0
      for (const entry of held) {
        if (!entry.consumed || entry.ran) continue
        entry.ran = true
        fired++
        entry.cb()
      }
      return fired
    }
  }
}

test('regression: a delayed READY1 timer closes sending at the deadline without ending the circuit', async (t) => {
  const basePort = 48900
  const clock = fakeClock()
  const retryTimers = holdRetryTimers(clock)
  const settle = () => new Promise((resolve) => setTimeout(resolve, 10))
  let readyArrivals = 0
  const f = await interceptNativeMessages(
    (socket, args) => {
      const packet = args[0]
      if (
        socket.address()?.port === basePort + 1 &&
        args[1] &&
        args[1].port === basePort + 2 &&
        b4a.isBuffer(packet) &&
        packet.byteLength === 1200 &&
        packet[1] === CELL_CLASS.DATAGRAM
      ) {
        readyArrivals++
      }
    },
    () => setupFourNodeNativeFixture({ t, clock, native: true, basePort, poolCapacity: 8192 })
  )
  const { sourceTailSession, limits } = await f.openSourceA0()
  const safety = await discoverPeerTailCandidate(sourceTailSession, {
    mode: 1,
    requestedMask: 9,
    randomTarget32: seed(0x23),
    expiresAt: 50000n
  })
  await extendPeerTail(sourceTailSession, {
    candidate: safety,
    forwardLimits: limits,
    reverseLimits: limits,
    payloadParametersDigest: seed(0x43)
  })
  const readyTail = await f.safety.tailStarted
  // The first READY1 completed the extension. The captured retry timer ticks past in
  // silence while every other duty keeps the circuit warm.
  readyArrivals = 0
  for (let i = 0; i < 3; i++) {
    clock.advance(250)
    await settle()
  }
  t.is(readyArrivals, 0, 'no retry goes out while its timer signal is held back')
  // The signal arrives 1500ms late, still before the deadline: one attempt, nothing more.
  t.ok(retryTimers.fireAll() > 0, 'the delayed retry signal eventually fires')
  await settle()
  t.is(readyArrivals, 1, 'a late retry sends exactly one READY1')
  for (let i = 0; i < 2; i++) {
    clock.advance(250)
    await settle()
  }
  t.is(readyArrivals, 1, 'only the late attempt joined the counted traffic')
  // Now the armed deadline signal fires exactly at the cutoff: sending closes, no attempt.
  clock.advance(750)
  await settle()
  t.ok(retryTimers.fireAll() > 0, 'the deadline signal fires at the cutoff')
  await settle()
  t.is(readyArrivals, 1, 'no READY1 attempt is dispatched at or past its deadline')
  t.execution(() => readPeerTailControl(readyTail), 'the tail outlives its completed READY1 duty')
  // The circuit still carries traffic: a fresh extension crosses the surviving tail.
  const terminal = await discoverPeerTailCandidate(sourceTailSession, {
    mode: 2,
    requestedMask: 11,
    randomTarget32: seed(0x63),
    expiresAt: 50000n,
    suppliedAdvertisement260: readVerifiedPeerAdvertisement(f.terminal.verifiedAd).canonicalBytes260
  })
  let outcome = null
  extendPeerTail(sourceTailSession, {
    candidate: terminal,
    forwardLimits: limits,
    reverseLimits: limits,
    payloadParametersDigest: seed(0x73)
  }).then(
    () => {
      outcome = 'ready'
    },
    (err) => {
      outcome = String(err.code || err)
    }
  )
  for (let i = 0; i < 40 && outcome === null; i++) await settle()
  t.is(outcome, 'ready', 'the circuit carries a second extension after the READY1 deadline')
})

test('regression: a READY1 dispatch refusal ends the tail immediately', async (t) => {
  const basePort = 48905
  const clock = fakeClock()
  const settle = () => new Promise((resolve) => setTimeout(resolve, 10))
  let refuseArmed = false
  let seen = 0
  let refused = 0
  const f = await interceptNativeSends(
    (socket, buffer, port) => {
      // The first datagram the safety sends during the extension is its link-accept
      // vector; the second is the first READY1 of its just-created tail.
      if (
        refuseArmed &&
        socket.address()?.port === basePort + 2 &&
        port === basePort + 1 &&
        b4a.isBuffer(buffer) &&
        buffer.byteLength === 1200 &&
        buffer[1] === CELL_CLASS.DATAGRAM
      ) {
        seen++
        if (seen === 2) {
          refuseArmed = false
          refused++
          return false
        }
      }
    },
    () => setupFourNodeNativeFixture({ t, clock, native: true, basePort, poolCapacity: 8192 })
  )
  const { sourceTailSession, limits } = await f.openSourceA0()
  const safety = await discoverPeerTailCandidate(sourceTailSession, {
    mode: 1,
    requestedMask: 9,
    randomTarget32: seed(0x29),
    expiresAt: 50000n
  })
  refuseArmed = true
  let outcome = null
  extendPeerTail(sourceTailSession, {
    candidate: safety,
    forwardLimits: limits,
    reverseLimits: limits,
    payloadParametersDigest: seed(0x49)
  }).then(
    () => {
      outcome = 'ready'
    },
    (err) => {
      outcome = err instanceof PrivateRouteError ? 'owned-failure' : String(err)
    }
  )
  for (let i = 0; i < 10 && refused === 0; i++) await settle()
  t.is(refused, 1, 'the first READY1 dispatch was refused')
  // No READY reaches the source, so its extension expires as an owned failure
  // while the refused responder duty destroys its own tail.
  for (let i = 0; i < 8; i++) {
    clock.advance(250)
    await settle()
  }
  for (let i = 0; i < 10 && outcome === null; i++) await settle()
  t.is(outcome, 'owned-failure', 'the source extension expires with an owned error')
  const readyTail = await f.safety.tailStarted
  t.exception(() => readPeerTailControl(readyTail), 'the refused duty destroyed its tail')
})

test('regression: an in-flight READY1 attempt at the deadline holds the duty until it settles', async (t) => {
  for (const [attemptSettles, expected] of [
    [true, 'the survived duty retires at settlement and the tail lives on'],
    [false, 'the late refusal fails the duty and destroys the tail']
  ]) {
    t.comment(`in-flight attempt settles ${attemptSettles}: ${expected}`)
  }
  const run = async (t, attemptSettles, basePort) => {
    const clock = fakeClock()
    const settle = () => new Promise((resolve) => setTimeout(resolve, 10))
    let holdNext = false
    let held = null
    let heldSend = null
    const f = await interceptNativeSends(
      (socket, buffer, port) => {
        if (
          holdNext &&
          socket.address()?.port === basePort + 2 &&
          port === basePort + 1 &&
          b4a.isBuffer(buffer) &&
          buffer.byteLength === 1200 &&
          buffer[1] === CELL_CLASS.DATAGRAM
        ) {
          holdNext = false
          heldSend = new Promise((resolve) => {
            held = resolve
          })
          return heldSend
        }
      },
      () => setupFourNodeNativeFixture({ t, clock, native: true, basePort, poolCapacity: 8192 })
    )
    t.teardown(() => {
      if (held) held(false)
    })
    const { sourceTailSession, limits } = await f.openSourceA0()
    const safety = await discoverPeerTailCandidate(sourceTailSession, {
      mode: 1,
      requestedMask: 9,
      randomTarget32: seed(0x33),
      expiresAt: 50000n
    })
    await extendPeerTail(sourceTailSession, {
      candidate: safety,
      forwardLimits: limits,
      reverseLimits: limits,
      payloadParametersDigest: seed(0x53)
    })
    const readyTail = await f.safety.tailStarted
    // Attempts two through seven go out on their nominal 250ms schedule, keeping every
    // link's acknowledgement lanes warm; the eighth and last is then dispatched and held
    // in flight at the socket, so the stall never starves an ack window.
    for (let i = 0; i < 6; i++) {
      clock.advance(250)
      await settle()
    }
    holdNext = true
    clock.advance(250)
    for (let i = 0; i < 10 && held === null; i++) await settle()
    t.ok(held !== null, 'the eighth READY1 attempt stays in flight')
    // The deadline passes with the final attempt unsettled.
    clock.advance(250)
    await settle()
    t.execution(
      () => readPeerTailControl(readyTail),
      'a pending attempt is no success, so the duty stays open past its deadline'
    )
    held(attemptSettles)
    held = null
    await settle()
    if (attemptSettles) {
      t.execution(
        () => readPeerTailControl(readyTail),
        'the fulfilled attempt lets the deadline-complete duty keep its tail'
      )
      const terminal = await discoverPeerTailCandidate(sourceTailSession, {
        mode: 2,
        requestedMask: 11,
        randomTarget32: seed(0x71),
        expiresAt: 50000n,
        suppliedAdvertisement260: readVerifiedPeerAdvertisement(f.terminal.verifiedAd)
          .canonicalBytes260
      })
      let outcome = null
      extendPeerTail(sourceTailSession, {
        candidate: terminal,
        forwardLimits: limits,
        reverseLimits: limits,
        payloadParametersDigest: seed(0x79)
      }).then(
        () => {
          outcome = 'ready'
        },
        (err) => {
          outcome = String(err.code || err)
        }
      )
      for (let i = 0; i < 40 && outcome === null; i++) await settle()
      t.is(outcome, 'ready', 'the circuit still carries an extension after the late settlement')
    } else {
      t.exception(
        () => readPeerTailControl(readyTail),
        'the attempt refused after the deadline still fails the duty'
      )
    }
  }
  await run(t, true, 48910)
  await run(t, false, 48915)
})

test('regression: a delayed READY2 timer completes the transferred duty and keeps the terminal carrier', async (t) => {
  const basePort = 48920
  const clock = fakeClock()
  const retryTimers = holdRetryTimers(clock)
  const settle = () => new Promise((resolve) => setTimeout(resolve, 10))
  const poolCapacity = 8192
  let readyRetries = 0
  let terminalActivation = null
  let terminalMaterial = null
  let terminalCarrier = null
  let terminalFailure = null
  const f = await interceptNativeSends(
    (socket, buffer, port) => {
      if (
        terminalCarrier !== null &&
        socket.address()?.port === basePort + 3 &&
        port === basePort + 2 &&
        b4a.isBuffer(buffer) &&
        buffer.byteLength === 1200 &&
        buffer[1] === CELL_CLASS.DATAGRAM
      ) {
        readyRetries++
      }
    },
    () =>
      setupFourNodeNativeFixture({
        t,
        clock,
        native: true,
        basePort,
        poolCapacity,
        onTerminalFinalReady(session) {
          try {
            const handoff = createPeerFinalExitHandoff(session)
            terminalActivation = claimFinalExitActivation(
              handoff,
              createFinalExitActivationClaim(handoff)
            )
            terminalMaterial = consumeFinalExitActivationOwner(terminalActivation)
            const taken = takePeerTailFinalRuntime(session, terminalActivation)
            terminalCarrier = takePeerM3RouteCarrier(
              issuePeerM3RouteCarrier(taken.runtime, taken.authorization)
            )
            destroyPeerTailControl(session)
          } catch (err) {
            terminalFailure = err
            throw err
          }
        }
      })
  )
  t.teardown(() => {
    if (terminalCarrier) terminalCarrier.destroy()
    if (terminalActivation) destroyFinalExitActivationOwner(terminalActivation)
  })
  const { sourceTailSession, limits } = await f.openSourceA0()
  const safety = await discoverPeerTailCandidate(sourceTailSession, {
    mode: 1,
    requestedMask: 9,
    randomTarget32: seed(0x31),
    expiresAt: 50000n
  })
  await extendPeerTail(sourceTailSession, {
    candidate: safety,
    forwardLimits: limits,
    reverseLimits: limits,
    payloadParametersDigest: seed(0x51)
  })
  // The held READY signals would starve every link of traffic, so the captured guard
  // and safety trains are replayed once mid-window to keep liveness, while the terminal
  // does not exist yet and its READY2 duty stays untouched.
  for (let i = 0; i < 3; i++) {
    clock.advance(250)
    await settle()
  }
  t.ok(retryTimers.fireAll() > 0, 'the relay readiness trains fire once, late')
  await settle()
  clock.advance(250)
  await settle()
  const terminal = await discoverPeerTailCandidate(sourceTailSession, {
    mode: 2,
    requestedMask: 11,
    randomTarget32: seed(0x61),
    expiresAt: 50000n,
    suppliedAdvertisement260: readVerifiedPeerAdvertisement(f.terminal.verifiedAd).canonicalBytes260
  })
  await extendPeerTail(sourceTailSession, {
    candidate: terminal,
    forwardLimits: limits,
    reverseLimits: limits,
    payloadParametersDigest: seed(0x71)
  })
  for (let i = 0; i < 40 && terminalCarrier === null && terminalFailure === null; i++) {
    await settle()
  }
  t.is(terminalFailure, null, 'the terminal transfers its READY2 duty with its first dispatch')
  t.ok(terminalCarrier, 'the terminal carrier exists')
  const materialBytes = Object.values(terminalMaterial).reduce(
    (sum, value) => sum + (b4a.isBuffer(value) ? value.byteLength : 0),
    0
  )
  let spare = null
  let refused = false
  try {
    spare = reservePeerMemory(
      f.terminal.memoryPool,
      'open-readiness-duty-probe',
      poolCapacity - materialBytes
    )
  } catch {
    refused = true
  } finally {
    if (spare) releasePeerMemory(spare)
  }
  t.is(refused, true, 'an open READY2 duty retains its tail storage')
  // The relay trains reach their deadlines first and expire; the terminal's captured
  // signal then fires exactly one late READY2 retry, still before its own cutoff.
  for (let i = 0; i < 4; i++) {
    clock.advance(250)
    await settle()
  }
  t.ok(retryTimers.fireAll() > 0, 'the delayed READY2 signal fires before its cutoff')
  await settle()
  await settle()
  t.is(readyRetries, 1, 'exactly one late READY2 retry goes out before the deadline')
  // Now the READY2 deadline passes with the retry signal consumed in silence.
  for (let i = 0; i < 4; i++) {
    clock.advance(250)
    await settle()
  }
  t.ok(retryTimers.fireAll() > 0, 'the deadline signal fires at the READY2 cutoff')
  await settle()
  await settle()
  t.is(readyRetries, 1, 'no READY2 attempt is dispatched at or past its deadline')
  t.ok(
    terminalCarrier.diagnostics().active,
    'the terminal carrier survives its deadline-completed READY2 duty'
  )
  const reclaimed = reservePeerMemory(
    f.terminal.memoryPool,
    'completed-readiness-duty-probe',
    poolCapacity - materialBytes
  )
  releasePeerMemory(reclaimed)
})

test('regression: a source that never receives an authenticated READY times out alone', async (t) => {
  const basePort = 48925
  const clock = fakeClock()
  const settle = () => new Promise((resolve) => setTimeout(resolve, 10))
  // READY1s leave the safety on schedule, but every forwarded copy is lost between the
  // guard and the source: the guard's first datagram after the extend begins is
  // EXTENDED1 (forwarding publishes only after its dispatch settles), and everything
  // after it is dropped with a clean send settlement.
  let dropping = false
  let seen = 0
  let dropped = 0
  const f = await interceptNativeSends(
    (socket, buffer, port) => {
      if (
        dropping &&
        socket.address()?.port === basePort + 1 &&
        port === basePort &&
        b4a.isBuffer(buffer) &&
        buffer.byteLength === 1200 &&
        buffer[1] === CELL_CLASS.DATAGRAM
      ) {
        seen++
        if (seen > 1) {
          dropped++
          return true
        }
      }
    },
    () => setupFourNodeNativeFixture({ t, clock, native: true, basePort, poolCapacity: 8192 })
  )
  const { sourceTailSession, limits } = await f.openSourceA0()
  const safety = await discoverPeerTailCandidate(sourceTailSession, {
    mode: 1,
    requestedMask: 9,
    randomTarget32: seed(0x27),
    expiresAt: 50000n
  })
  dropping = true
  let outcome = null
  extendPeerTail(sourceTailSession, {
    candidate: safety,
    forwardLimits: limits,
    reverseLimits: limits,
    payloadParametersDigest: seed(0x47)
  }).then(
    () => {
      outcome = 'ready'
    },
    (err) => {
      outcome = err instanceof PrivateRouteError ? 'owned-failure' : String(err)
    }
  )
  for (let i = 0; i < 6; i++) {
    clock.advance(250)
    await settle()
  }
  const readyTail = await f.safety.tailStarted
  t.is(outcome, null, 'the source is still inside its own deadline')
  t.execution(
    () => readPeerTailControl(readyTail),
    'the safety duty ran its full schedule and its tail lives'
  )
  for (let i = 0; i < 2; i++) {
    clock.advance(250)
    await settle()
  }
  for (let i = 0; i < 10 && outcome === null; i++) await settle()
  t.ok(seen >= 1, 'the extension progressed past EXTENDED1')
  t.ok(dropped >= 1, 'every READY1 copy was lost upstream')
  t.is(outcome, 'owned-failure', 'the source extension expires on its own deadline')
  t.exception(
    () => readPeerTailControl(sourceTailSession),
    'only the unanswered source ends; no READY was ever admitted'
  )
  t.exception(() => readPeerTailControl(readyTail), 'the branch unwinds after the source gives up')
})

test('runtime clock reentrancy cannot return a retired runtime as usable', async (t) => {
  const baseClock = fakeClock()
  let onClockRead = null
  const clock = {
    ...baseClock,
    monotonicNow() {
      const callback = onClockRead
      onClockRead = null
      if (callback) callback()
      return baseClock.monotonicNow()
    }
  }
  const f = await setupFourNodeNativeFixture({
    t,
    clock,
    native: true,
    basePort: 49260,
    poolCapacity: 8192
  })
  const { sourceRuntime } = await f.openSourceA0()
  onClockRead = () => destroyPeerM3Runtime(sourceRuntime)
  t.exception(
    () => sourceRuntime.diagnostics(),
    { code: 'ERR_DESTROYED' },
    'destruction inside the owned clock revokes the current operation'
  )
})

// Stale control from a forwarding relay carries fewer layers than the source removes, so the
// source over-peels it into bytes with an arbitrary prefix. Unauthenticated bytes that read as
// class 5 or 6 must neither block the source's take nor reach its reader, before or after the
// take, and a real guard control cell held across the take is dropped the same way. Authentic
// finalization still arrives, and class 6 reaches a reader only after local route readiness.
test('unauthenticated class-5 or class-6 bytes and a held relay cell never block the source take or reach its reader', async (t) => {
  const basePort = 48760
  let holdGuardPacket = false
  let held = null
  const f = await interceptNativeMessages(
    (socket, args, emit) => {
      if (
        holdGuardPacket &&
        socket.address()?.port === basePort &&
        args[0].byteLength === 1200 &&
        args[0][1] === CELL_CLASS.DATAGRAM
      ) {
        holdGuardPacket = false
        const packet = b4a.from(args[0])
        const rest = args.slice(1)
        held = () => emit.call(socket, 'message', packet, ...rest)
        return false
      }
    },
    () => setupFourNodeNativeFixture({ t, native: true, basePort, poolCapacity: 8192 })
  )

  const { sourceTailSession, limits } = await f.openSourceA0()
  const candidate1 = await discoverPeerTailCandidate(sourceTailSession, {
    mode: 1,
    requestedMask: 9,
    randomTarget32: seed(0x22),
    expiresAt: 50000n
  })
  // Hold the guard's first own reply to EXTEND: a real, authentic guard control cell. The
  // source's retry then draws the guard's cached reply and the build goes on.
  holdGuardPacket = true
  const extending = extendPeerTail(sourceTailSession, {
    candidate: candidate1,
    forwardLimits: limits,
    reverseLimits: limits,
    payloadParametersDigest: seed(0x42)
  })
  let extended = false
  extending.then(() => {
    extended = true
  })
  for (let turn = 0; turn < 40 && !extended; turn++) {
    await new Promise((resolve) => setTimeout(resolve, 5))
    if (held) f.clock.advance(250)
  }
  await extending
  t.ok(held, 'a real guard control cell is held across the build')
  await f.safety.tailStarted
  const terminalAdBytes = readVerifiedPeerAdvertisement(f.terminal.verifiedAd).canonicalBytes260
  const candidate2 = await discoverPeerTailCandidate(sourceTailSession, {
    mode: 2,
    requestedMask: 11,
    randomTarget32: seed(0x72),
    suppliedAdvertisement260: terminalAdBytes,
    expiresAt: 50000n
  })
  await extendPeerTail(sourceTailSession, {
    candidate: candidate2,
    forwardLimits: limits,
    reverseLimits: limits,
    payloadParametersDigest: seed(0x92)
  })
  const terminalTailSession = await f.terminal.tailStarted

  const handoff = createPeerFinalExitHandoff(sourceTailSession)
  const activationOwner = claimFinalExitActivation(handoff, createFinalExitActivationClaim(handoff))
  t.teardown(() => destroyFinalExitActivationOwner(activationOwner))
  const sourceMaterial = consumeFinalExitActivationOwner(activationOwner)
  const circuitId = b4a.from(sourceMaterial.tailControlTranscript.subarray(73, 89))
  const generation = transcriptU64(sourceMaterial.tailControlTranscript, 89)
  const finalResult = takePeerTailFinalRuntime(sourceTailSession, activationOwner)

  const termHandoff = createPeerFinalExitHandoff(terminalTailSession)
  const terminalActivationOwner = claimFinalExitActivation(
    termHandoff,
    createFinalExitActivationClaim(termHandoff)
  )
  t.teardown(() => destroyFinalExitActivationOwner(terminalActivationOwner))
  const terminalMaterial = consumeFinalExitActivationOwner(terminalActivationOwner)
  const termResult = takePeerTailFinalRuntime(terminalTailSession, terminalActivationOwner)

  // Unauthenticated envelope bytes with the wanted prefix. Sent from the terminal they reach
  // the source exactly as over-peeled relay control does: prefix set, content not authentic.
  const noise = (prefix) => {
    const envelope = cryptoSuite.randomBytes(1101)
    envelope[0] = prefix
    return envelope
  }

  // Before the take: bytes reading as class 6 and class 5 are queued at the source.
  for (const prefix of [6, 5]) {
    await sendPeerM3Payload(termResult.runtime, {
      class: CELL_CLASS.DATAGRAM,
      payload: noise(prefix)
    })
  }
  await new Promise((resolve) => setTimeout(resolve, 20))
  const carrier = issuePeerM3RouteCarrier(finalResult.runtime, finalResult.authorization)
  t.ok(carrier, 'queued class-5 and class-6 bytes do not block the source take')
  const routeCarrier = takeM3RouteTransport(carrier)
  t.teardown(() => destroyM3RouteTransport(routeCarrier))
  const termRouteCarrier = takeM3RouteTransport(
    issuePeerM3RouteCarrier(termResult.runtime, termResult.authorization)
  )
  t.teardown(() => destroyM3RouteTransport(termRouteCarrier))

  // After the take: a waiting source reader sees neither class-5 nor class-6 noise, nor the
  // real guard cell released now, and stays usable for the next authentic frame.
  let delivered = null
  const reading = receiveReservedM3RouteEnvelope(reserveM3RouteFrame(routeCarrier)).then(
    (envelope) => {
      delivered = envelope
      return envelope
    }
  )
  await sendM3RouteFrame(termRouteCarrier, cryptoSuite.randomBytes(1100))
  activateM3RouteTransport(termRouteCarrier)
  await sendM3RouteFrame(termRouteCarrier, cryptoSuite.randomBytes(1100))
  held()
  await new Promise((resolve) => setTimeout(resolve, 20))
  t.is(delivered, null, 'no noise and no stale relay cell reaches the source reader')

  const finalize = (counter, payload) =>
    sealPeerContextFrame({
      contextClass: 5,
      circuitId,
      generation,
      direction: 1,
      counter,
      key: terminalMaterial.finalizeReverseKey,
      noncePrefix: terminalMaterial.finalizeReverseNoncePrefix,
      payload
    })
  const openFinalize = (frame, counter) =>
    openPeerContextFrame(
      {
        contextClass: 5,
        circuitId,
        generation,
        direction: 1,
        counter,
        key: sourceMaterial.finalizeReverseKey,
        noncePrefix: sourceMaterial.finalizeReverseNoncePrefix
      },
      frame
    )
  const payload = b4a.from('authentic finalization after noise')
  await sendM3FinalizeFrame(termRouteCarrier, finalize(0n, payload))
  const first = await reading
  t.is(first.contextClass, 5)
  t.alike(openFinalize(first.frame, 0n).payload, payload, 'the pending reader gets the real frame')

  // A byte-identical canonical retry under a fresh finalize counter is authentic and delivered;
  // replay protection belongs to its owner, which sees the same bytes twice in order.
  const retry = receiveReservedM3RouteEnvelope(reserveM3RouteFrame(routeCarrier))
  await sendM3FinalizeFrame(termRouteCarrier, finalize(1n, payload))
  t.alike(openFinalize((await retry).frame, 1n).payload, payload, 'the retry arrives intact')

  // Class 6 reaches a reader only after local route readiness. A route frame that fails its
  // AEAD is then reported as ERR_AUTHENTICATION, which an owner drops as noise.
  activateM3RouteTransport(routeCarrier)
  const routeRead = receiveReservedM3RouteEnvelope(reserveM3RouteFrame(routeCarrier))
  await sendM3RouteFrame(termRouteCarrier, cryptoSuite.randomBytes(1100))
  const routeNoise = await routeRead
  t.is(routeNoise.contextClass, 6, 'after readiness class 6 reaches the reader')
  t.exception(
    () =>
      openPeerContextFrame(
        {
          contextClass: 6,
          circuitId,
          routeId: b4a.alloc(16, 0x93),
          purpose: 2,
          generation,
          direction: 1,
          counter: transcriptU64(routeNoise.frame, 0),
          key: seed(0xe1),
          noncePrefix: b4a.alloc(16, 0xe2)
        },
        routeNoise.frame
      ),
    { code: 'ERR_AUTHENTICATION' },
    'unauthenticated route bytes fail authentication, never a contract error'
  )
})

// A forwarding tail keeps nothing a forwarder does not need: its tail secret, transcript and
// finalize keys go at publication, and the whole owner retires when forwarding ends. After
// physical loss, a graceful teardown or expiry, the guard's storage returns to zero and its
// tail owner is gone, before any explicit destroy or fixture cleanup.
for (const [end, basePort] of [
  ['physical loss', 48790],
  ['graceful teardown', 48794],
  ['expiry', 48798]
]) {
  test(`a forwarding tail retires with its forwarder after ${end}`, async (t) => {
    const f = await setupFourNodeNativeFixture({ t, native: true, basePort, poolCapacity: 8192 })
    const { sourceTailSession, limits } = await f.openSourceA0()
    for (const [mode, requestedMask, supplied, fill] of [
      [1, 9, null, 0x23],
      [2, 11, readVerifiedPeerAdvertisement(f.terminal.verifiedAd).canonicalBytes260, 0x73]
    ]) {
      const candidate = await discoverPeerTailCandidate(sourceTailSession, {
        mode,
        requestedMask,
        randomTarget32: seed(fill),
        ...(supplied ? { suppliedAdvertisement260: supplied } : {}),
        expiresAt: 50000n
      })
      await extendPeerTail(sourceTailSession, {
        candidate,
        forwardLimits: limits,
        reverseLimits: limits,
        payloadParametersDigest: seed(fill + 1)
      })
    }
    const guardSession = await f.guard.tailStarted
    t.is(readPeerTailControl(guardSession).phase, 'FORWARDING', 'the guard forwards')
    t.ok(readPeerMemory(f.guard.memoryPool).reservedBytes > 0, 'a live forwarder holds storage')

    if (end === 'physical loss') {
      await f.guard.endpoint.close()
    } else if (end === 'graceful teardown') {
      const handoff = createPeerFinalExitHandoff(sourceTailSession)
      const activation = claimFinalExitActivation(handoff, createFinalExitActivationClaim(handoff))
      t.teardown(() => destroyFinalExitActivationOwner(activation))
      consumeFinalExitActivationOwner(activation)
      const finalResult = takePeerTailFinalRuntime(sourceTailSession, activation)
      t.is(
        await beginPeerM3BranchTeardown(finalResult.runtime, b4a.alloc(16, 0x5a)),
        true,
        'the source tears the circuit down gracefully'
      )
    } else {
      for (let step = 0; step < 120; step++) {
        f.clock.advance(500)
        await new Promise((resolve) => setImmediate(resolve))
      }
    }
    for (let turn = 0; turn < 100 && readPeerMemory(f.guard.memoryPool).reservedBytes > 0; turn++) {
      await new Promise((resolve) => setTimeout(resolve, 10))
    }
    t.is(readPeerMemory(f.guard.memoryPool).reservedBytes, 0, 'no guard storage survives')
    t.is(readPeerMemory(f.guard.memoryPool).takenBytes, 0, 'no guard buffer is still taken')
    t.exception(() => readPeerTailControl(guardSession), 'the guard tail owner is gone')
  })
}

// Version 3 relay views, packet §4.5.2. Every identifier-bearing object of a complete build and
// teardown is captured where it is signed or sealed and attributed to the relays that can read
// it: a signed object to its signer and the relays it names, a tail-control, finalize or route
// frame to the hop whose identifiers its AD binds, and a link cell to the two sockets it passed
// between. The guard then holds its own tuple and the safety's, the safety its own and the
// terminal's, and the terminal only its own.
test('relay-visible identifiers: each relay holds its own tuple and its successor tuple only', async (t) => {
  const basePort = 48866
  const relayAt = {
    [basePort]: 'source',
    [basePort + 1]: 'guard',
    [basePort + 2]: 'safety',
    [basePort + 3]: 'terminal'
  }
  const received = []
  const f = await interceptNativeMessages(
    (socket, args) => {
      const packet = args[0]
      if (!b4a.isBuffer(packet) || packet.byteLength !== 1200) return
      received.push({
        to: relayAt[socket.address()?.port] || null,
        from: relayAt[args[1] && args[1].port] || null,
        header: b4a.from(packet.subarray(0, 36))
      })
    },
    () => setupFourNodeNativeFixture({ t, native: true, basePort, poolCapacity: 8192 })
  )

  const signed = []
  const sealed = []
  const sign = sodium.crypto_sign_detached
  const encrypt = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt
  const restore = () => {
    sodium.crypto_sign_detached = sign
    sodium.crypto_aead_xchacha20poly1305_ietf_encrypt = encrypt
  }
  t.teardown(restore)
  sodium.crypto_sign_detached = function (signature, message, secretKey) {
    signed.push({ signer: b4a.from(secretKey.subarray(32, 64)), message: b4a.from(message) })
    return sign.call(this, signature, message, secretKey)
  }
  sodium.crypto_aead_xchacha20poly1305_ietf_encrypt = function (output, message, ad, ...rest) {
    sealed.push({ ad: ad ? b4a.from(ad) : b4a.alloc(0), plaintext: b4a.from(message) })
    return encrypt.call(this, output, message, ad, ...rest)
  }

  const random = (size) => {
    const bytes = b4a.alloc(size)
    sodium.randombytes_buf(bytes)
    return bytes
  }
  // Hop 0 gets random identifiers too, so no pattern below can match a constant.
  let a0Generation = 0n
  for (const byte of random(8)) a0Generation = (a0Generation << 8n) | BigInt(byte)
  const { sourceTailSession, limits } = await f.openSourceA0({
    branchId: random(16),
    circuitId: random(16),
    generation: a0Generation || 1n
  })
  for (const [mode, requestedMask, supplied, fill] of [
    [1, 9, null, 0x23],
    [2, 11, readVerifiedPeerAdvertisement(f.terminal.verifiedAd).canonicalBytes260, 0x73]
  ]) {
    const candidate = await discoverPeerTailCandidate(sourceTailSession, {
      mode,
      requestedMask,
      randomTarget32: seed(fill),
      ...(supplied ? { suppliedAdvertisement260: supplied } : {}),
      expiresAt: 50000n
    })
    await extendPeerTail(sourceTailSession, {
      candidate,
      forwardLimits: limits,
      reverseLimits: limits,
      payloadParametersDigest: seed(fill + 1)
    })
  }
  const names = ['guard', 'safety', 'terminal']
  const hops = []
  for (const name of names) hops.push(readPeerTailControl(await f[name].tailStarted))

  // Closure objects: a graceful teardown from the source crosses every link.
  const handoff = createPeerFinalExitHandoff(sourceTailSession)
  const activation = claimFinalExitActivation(handoff, createFinalExitActivationClaim(handoff))
  t.teardown(() => destroyFinalExitActivationOwner(activation))
  consumeFinalExitActivationOwner(activation)
  const finalResult = takePeerTailFinalRuntime(sourceTailSession, activation)
  t.is(await beginPeerM3BranchTeardown(finalResult.runtime, random(16)), true)
  for (let turn = 0; turn < 20; turn++) await new Promise((resolve) => setTimeout(resolve, 10))
  restore()

  const u64be = (value) => {
    const bytes = b4a.alloc(8)
    for (let index = 7; index >= 0; index--, value >>= 8n) bytes[index] = Number(value & 0xffn)
    return bytes
  }
  const patterns = hops.map((hop) => [hop.branchId, hop.circuitId, u64be(hop.generation)])
  // The hops (0 guard, 1 safety, 2 terminal) any of whose identifier values occur in parts.
  const tuplesIn = (...parts) => {
    const found = new Set()
    patterns.forEach((values, hop) => {
      for (const part of parts) {
        for (const value of values) if (b4a.indexOf(part, value) !== -1) found.add(hop)
      }
    })
    return found
  }
  const identities = {
    source: f.source.identity32,
    guard: f.guard.identity32,
    safety: f.safety.identity32,
    terminal: f.terminal.identity32
  }
  const relayOf = (publicKey) =>
    Object.keys(identities).find((name) => b4a.equals(identities[name], publicKey)) || null
  const kinds = [
    ['offer', PEER_MESSAGE_ID.PEER_LINK_OFFER_V2],
    ['proof', PEER_MESSAGE_ID.PEER_REDACTED_RESPONDER_PROOF_V2],
    ['extend request', PEER_MESSAGE_ID.PEER_EXTEND_REQUEST_V2],
    ['extended', PEER_MESSAGE_ID.PEER_EXTENDED_V2],
    ['tail ready', PEER_MESSAGE_ID.PEER_TAIL_READY_V2],
    ['destroy', PEER_MESSAGE_ID.PEER_BRANCH_DESTROY_V2],
    ['teardown', PEER_MESSAGE_ID.PEER_BRANCH_TEARDOWN_V2],
    ['teardown ack', PEER_MESSAGE_ID.PEER_BRANCH_TEARDOWN_ACK_V2]
  ]
  // An object is named by the first peer object header it contains, so an EXTENDED that
  // carries a proof is an EXTENDED.
  const kindOf = (bytes) => {
    let kind = 'other'
    let first = Infinity
    for (const [name, id] of kinds) {
      const at = b4a.indexOf(bytes, peerObjectHeader(id))
      if (at !== -1 && at < first) {
        first = at
        kind = name
      }
    }
    return kind
  }

  const views = { guard: new Set(), safety: new Set(), terminal: new Set() }
  const inventory = []
  const unattributed = []
  const note = (kind, holders, tuples) => {
    const item = { kind, holders: [...holders].sort(), tuples: [...tuples].sort() }
    inventory.push(item)
    for (const holder of holders) {
      if (views[holder]) for (const hop of tuples) views[holder].add(hop)
    }
  }
  names.forEach((name, hop) => {
    note('tail descriptor', [name], tuplesIn(hops[hop].branchId, hops[hop].circuitId))
  })
  for (const { signer, message } of signed) {
    const tuples = tuplesIn(message)
    if (tuples.size === 0) continue
    const labelLength = (message[0] << 8) | message[1]
    const idAt = 2 + labelLength + 4
    const id = (message[idAt] << 8) | message[idAt + 1]
    const kind = kinds.find(([, value]) => value === id)
    const holders = new Set([relayOf(signer)])
    for (const name of Object.keys(identities)) {
      if (b4a.indexOf(message, identities[name]) !== -1) holders.add(name)
    }
    note(kind ? kind[0] : `signed 0x${id.toString(16)}`, holders, tuples)
  }
  const cellDomain = DOMAIN.CELL_HEADER
  for (const { ad, plaintext } of sealed) {
    const cell =
      ad.byteLength === cellDomain.byteLength + 36 &&
      b4a.equals(ad.subarray(0, cellDomain.byteLength), cellDomain)
    if (cell) {
      const header = ad.subarray(cellDomain.byteLength)
      const tuples = tuplesIn(header, plaintext)
      if (tuples.size === 0) continue
      const holders = new Set()
      for (const delivered of received) {
        if (!b4a.equals(delivered.header, header)) continue
        holders.add(delivered.to)
        holders.add(delivered.from)
      }
      // A cell nobody received exposes nothing beyond what its sender already held.
      if (holders.size > 0) note(`cell ${kindOf(plaintext)}`, holders, tuples)
      continue
    }
    const bound = tuplesIn(ad)
    const carried = tuplesIn(plaintext)
    if (bound.size === 0) {
      if (carried.size > 0) unattributed.push({ kind: kindOf(plaintext), carried: [...carried] })
      continue
    }
    note(
      `frame ${kindOf(plaintext)}`,
      [...bound].map((hop) => names[hop]),
      new Set([...bound, ...carried])
    )
  }

  const same = (left, right) => left.length === right.length && left.every((v, i) => v === right[i])
  const has = (kind, holders, tuples) =>
    inventory.some(
      (item) => item.kind === kind && same(item.holders, holders) && same(item.tuples, tuples)
    )
  t.alike(unattributed, [], 'every frame carrying identifiers binds a hop in its AD')
  for (const [hop, name] of names.entries()) {
    t.ok(has('tail descriptor', [name], [hop]), `the ${name} tail descriptor holds its own tuple`)
  }
  t.ok(has('offer', ['guard', 'source'], [0]), 'the A0 offer carries only the guard tuple')
  t.ok(has('offer', ['guard', 'safety'], [1]), 'the guard signs only the safety tuple')
  t.ok(has('offer', ['safety', 'terminal'], [2]), 'the safety signs only the terminal tuple')
  t.ok(has('proof', ['guard', 'safety'], [1]), 'the safety proof carries only its own tuple')
  t.ok(has('proof', ['safety', 'terminal'], [2]), 'the terminal proof carries only its own tuple')
  t.ok(has('frame extend request', ['guard'], [0, 1]), 'the guard reads the safety tuple')
  t.ok(has('frame extend request', ['safety'], [1, 2]), 'the safety reads the terminal tuple')
  t.ok(has('frame extended', ['guard'], [0, 1]), 'the guard returns the safety tuple')
  t.ok(has('frame extended', ['safety'], [1, 2]), 'the safety returns the terminal tuple')
  t.ok(has('frame tail ready', ['safety'], [1]), 'the safety readiness carries its own tuple')
  t.ok(has('frame tail ready', ['terminal'], [2]), 'the terminal readiness carries its own tuple')
  t.ok(
    has('cell teardown', ['guard', 'source'], [0]),
    'the source teardown carries only the guard link tuple'
  )
  const mixed = inventory.filter(
    (item) => item.kind.startsWith('cell ') && item.tuples.length !== 1
  )
  t.alike(mixed, [], 'no link cell carries identifiers of two hops')
  const closures = inventory.filter((item) =>
    ['cell destroy', 'cell teardown', 'cell teardown ack'].includes(item.kind)
  )
  const linkEnds = [
    ['guard', 'source'],
    ['guard', 'safety'],
    ['safety', 'terminal']
  ]
  t.ok(
    closures.every((item) => same(item.holders, linkEnds[item.tuples[0]])),
    'every closure object carries the tuple of the link it crosses'
  )
  t.alike([...views.guard].sort(), [0, 1], 'the guard holds its own and the safety tuple')
  t.alike([...views.safety].sort(), [1, 2], 'the safety holds its own and the terminal tuple')
  t.alike([...views.terminal].sort(), [2], 'the terminal holds only its own tuple')
})

// A current tail discards an authenticated EXTEND_REQUEST that names one of its own
// identifiers for the successor, before it touches its stored candidate: the successor
// authority stays unconsumed, no extension storage is reserved and no LINK_OFFER leaves.
for (const [field, basePort] of [
  ['branch identifier', 48850],
  ['circuit identifier', 48854],
  ['generation', 48862]
]) {
  test(`a current tail refuses a successor request that reuses its own ${field}`, async (t) => {
    const f = await setupFourNodeNativeFixture({ t, native: true, basePort, poolCapacity: 8192 })
    const branches = (pool) => {
      const { neighborCount, pendingCount, reservationCount } =
        readPeerNativeNeighborDiagnostics(pool)
      return { neighborCount, pendingCount, reservationCount }
    }
    const { sourceTailSession, limits } = await f.openSourceA0()
    const guardSession = await f.guard.tailStarted
    const own = readPeerTailControl(guardSession)
    const candidate = await discoverPeerTailCandidate(sourceTailSession, {
      mode: 1,
      requestedMask: 9,
      randomTarget32: seed(0x21),
      expiresAt: 50000n
    })
    const guardPool = branches(f.guard.pool)
    const guardMemory = readPeerMemory(f.guard.memoryPool).reservedBytes
    const safetyPool = branches(f.safety.pool)
    let safetyStarted = false
    f.safety.tailStarted.then(
      () => {
        safetyStarted = true
      },
      () => {}
    )

    // The source draws the successor identifiers inside extendPeerTail as standalone buffers:
    // 16 bytes for the branch, 16 for the circuit, then 8 for the generation. One of them is
    // replaced with the guard's own value; the request is still sealed under genuine keys.
    const randombytes = sodium.randombytes_buf
    let identifiers = 0
    sodium.randombytes_buf = function (buffer) {
      randombytes.call(this, buffer)
      if (buffer.byteOffset !== 0 || buffer.buffer.byteLength !== buffer.byteLength) return
      if (buffer.byteLength === 16) {
        identifiers++
        if (field === 'branch identifier' && identifiers === 1) buffer.set(own.branchId)
        if (field === 'circuit identifier' && identifiers === 2) buffer.set(own.circuitId)
      } else if (buffer.byteLength === 8 && field === 'generation') {
        let value = own.generation
        for (let index = 7; index >= 0; index--, value >>= 8n) buffer[index] = Number(value & 0xffn)
      }
    }
    let extending = null
    try {
      extending = extendPeerTail(sourceTailSession, {
        candidate,
        forwardLimits: limits,
        reverseLimits: limits,
        payloadParametersDigest: seed(0x41)
      }).then(
        () => ({}),
        (error) => ({ error })
      )
    } finally {
      sodium.randombytes_buf = randombytes
    }
    t.is(identifiers, 2, 'the source drew both successor identifiers')

    // Every attempt reaches the guard and is discarded there.
    for (let turn = 0; turn < 10; turn++) await new Promise((resolve) => setTimeout(resolve, 10))
    t.alike(branches(f.guard.pool), guardPool, 'the guard keeps its stored candidate authority')
    t.is(
      readPeerMemory(f.guard.memoryPool).reservedBytes,
      guardMemory,
      'the guard reserves no extension storage'
    )
    t.alike(branches(f.safety.pool), safetyPool, 'the safety admits no branch')
    t.is(safetyStarted, false, 'no LINK_OFFER reached the safety')

    let outcome = null
    for (let step = 0; step < 40 && outcome === null; step++) {
      f.clock.advance(250)
      outcome = await Promise.race([
        extending,
        new Promise((resolve) => setImmediate(() => resolve(null)))
      ])
    }
    t.ok(outcome && outcome.error instanceof PrivateRouteError, 'the source extension fails')
    t.is(safetyStarted, false, 'the safety never started a tail')
  })
}

// The source takes the successor's link ephemeral from the signed proof alone. The current
// tail is the one party holding both the ACCEPT and the proof, and it refuses a reply whose two
// members name different ephemerals even when the successor validly signed both: it adopts no
// successor link, the source sees no EXTENDED, and every ephemeral secret of the attempt is
// erased once it fails.
for (const [member, basePort] of [
  ['proof', 48874],
  ['ACCEPT', 48886]
]) {
  test(`a current tail refuses a validly signed ${member} that names another link ephemeral`, async (t) => {
    const f = await setupFourNodeNativeFixture({ t, native: true, basePort, poolCapacity: 8192 })
    const { sourceTailSession, limits } = await f.openSourceA0()
    const guardSession = await f.guard.tailStarted
    const candidate = await discoverPeerTailCandidate(sourceTailSession, {
      mode: 1,
      requestedMask: 9,
      randomTarget32: seed(0x21),
      expiresAt: 50000n
    })
    const guardPhase = readPeerTailControl(guardSession).phase
    const successor = readPeerRelayOwner(f.safety.relayOwner, f.safety.endpoint)
    const otherEphemeral = cryptoSuite.encryptionKeyPair().publicKey
    const ACCEPT = PEER_MESSAGE_ID.PEER_LINK_ACCEPT_V2
    const PROOF = PEER_MESSAGE_ID.PEER_REDACTED_RESPONDER_PROOF_V2
    // The successor itself signs the substituted member, so both members stay authentic.
    const resign = (wire, messageId, bodyBytes) => {
      const fields = {
        ...decodePeerTransport(wire).fields,
        responderLinkEphemeralPublicKey: otherEphemeral
      }
      const body = encodePeerTransport(messageId, fields, b4a.alloc(64)).subarray(8, 8 + bodyBytes)
      return encodePeerTransport(messageId, fields, successor.signPeerObject(messageId, body))
    }

    const secrets = []
    let substituted = 0
    const keyPair = sodium.crypto_box_keypair
    const encrypt = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt
    const restore = () => {
      sodium.crypto_box_keypair = keyPair
      sodium.crypto_aead_xchacha20poly1305_ietf_encrypt = encrypt
    }
    t.teardown(restore)
    sodium.crypto_box_keypair = function (publicKey, secretKey) {
      const result = keyPair.call(this, publicKey, secretKey)
      secrets.push(secretKey)
      return result
    }
    sodium.crypto_aead_xchacha20poly1305_ietf_encrypt = function (output, message, ad, ...rest) {
      const acceptAt = b4a.indexOf(message, peerObjectHeader(ACCEPT))
      if (acceptAt === -1 || b4a.indexOf(message, peerObjectHeader(PROOF)) !== acceptAt + 285) {
        return encrypt.call(this, output, message, ad, ...rest)
      }
      const altered = b4a.from(message)
      if (member === 'proof') {
        altered.set(
          resign(message.subarray(acceptAt + 285, acceptAt + 695), PROOF, 338),
          acceptAt + 285
        )
      } else {
        altered.set(resign(message.subarray(acceptAt, acceptAt + 285), ACCEPT, 213), acceptAt)
      }
      substituted++
      return encrypt.call(this, output, altered, ad, ...rest)
    }

    const extending = extendPeerTail(sourceTailSession, {
      candidate,
      forwardLimits: limits,
      reverseLimits: limits,
      payloadParametersDigest: seed(0x41)
    }).then(
      () => ({}),
      (error) => ({ error })
    )
    for (let turn = 0; turn < 10; turn++) await new Promise((resolve) => setTimeout(resolve, 10))
    t.ok(substituted > 0, 'the successor sent its reply with the substituted member')
    t.is(readPeerTailControl(guardSession).phase, guardPhase, 'the guard adopts no successor link')
    t.is(readPeerTailControl(sourceTailSession).extensionIndex, 0, 'the source has not extended')
    const clientTailSecret = secrets[0]
    t.absent(
      clientTailSecret.every((byte) => byte === 0),
      'the source still waits for a proof: no EXTENDED reached it'
    )

    let outcome = null
    for (let step = 0; step < 40 && outcome === null; step++) {
      f.clock.advance(250)
      outcome = await Promise.race([
        extending,
        new Promise((resolve) => setImmediate(() => resolve(null)))
      ])
    }
    restore()
    t.ok(outcome && outcome.error instanceof PrivateRouteError, 'the source extension fails')
    // In order: the source's client tail ephemeral, the guard's link ephemeral for its OFFER
    // and the successor's link ephemeral for its reply.
    t.ok(secrets.length >= 3, 'the source, the guard and the successor each drew an ephemeral')
    for (const [index, holder] of [
      'source client tail',
      'guard link',
      'successor link'
    ].entries()) {
      t.ok(
        secrets[index].every((byte) => byte === 0),
        `the ${holder} ephemeral secret of the refused attempt is erased`
      )
    }
  })
}
