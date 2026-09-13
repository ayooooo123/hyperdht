'use strict'
const b4a = require('b4a')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  createExtensionOfferReceiver,
  createExtensionResponseReceiver
} = require('../../lib/private/extension-setup-channel')
const guardLinks = require('../../lib/private/guard-link')
const {
  createExtensionAdjacentLinkFactory,
  createExtensionLinkResponder,
  createRelayAdjacentDialAuthority,
  takeAcceptedExtensionAdjacencyTransfer,
  takeExtensionResponderAdjacency
} = guardLinks
const { encodeM3ContextEnvelope } = require('../../lib/private/m3-context')
const {
  M3AdjacencyAuthority,
  beginM3Install,
  commitM3Install,
  createM3RelayForwardingFacade,
  validateM3Install
} = require('../../lib/private/m3-adjacency-runtime')
const { CONTEXT_CLASS } = require('../../lib/private/protocol')
const {
  createRedactedResponderProofAuthority
} = require('../../lib/private/redacted-responder-proof')
const {
  createExtensionResponderSigner,
  createLinkOfferSigner,
  createRelayIdentitySigningAuthority,
  createTailReadySigner
} = require('../../lib/private/relay-identity-signer')
const { createTailExtensionCommitter } = require('../../lib/private/tail-extension-committer')
const {
  admitTailExtend,
  borrowTailControlTransport,
  completeTailExtend,
  createSuccessorTailReadyContext,
  createTailControlResponderAuthority,
  createTailControlSession,
  openTailAdjacentLink,
  sealSuccessorTailReady
} = require('../../lib/private/tail-control')
const TAKE_OFFER = Symbol.for('hyperdht-private-routes/relay-adjacent-staged-offer-taker')
function envelope(encoded) {
  const frame = b4a.alloc(1100)
  frame.set(encoded)
  return encodeM3ContextEnvelope({ contextClass: CONTEXT_CLASS.TAIL_CONTROL_ORDERED, frame })
}
function readU64(bytes, offset) {
  let value = 0n
  for (let i = 0; i < 8; i++) value = (value << 8n) | BigInt(bytes[offset + i])
  return value
}
function authority(clocks) {
  return new M3AdjacencyAuthority({
    wallNow: clocks.wallNow,
    monotonicNow: clocks.monotonicNow,
    schedule: clocks.schedule,
    cancelScheduled: clocks.cancelScheduled,
    crypto: cryptoSuite
  })
}
function createHostedTailResponder({
  adjacency,
  adjacencyAuthority,
  identity,
  clocks,
  plan,
  resources
}) {
  const tail = createTailControlSession(adjacency.tail, {
    wallNow: clocks.wallNow,
    monotonicNow: clocks.monotonicNow,
    schedule: clocks.schedule,
    cancelScheduled: clocks.cancelScheduled,
    crypto: cryptoSuite
  })
  const transport = borrowTailControlTransport(tail)
  const identityOwner = createRelayIdentitySigningAuthority({
    identitySecretKey: identity.secretKey
  })
  let responderAuthority = null,
    successor = null,
    replayOwner = null,
    linkResponder = null,
    dialFailure = null,
    forwarding = null
  const record = {
    tail,
    transport,
    identity,
    identityOwner,
    serve,
    destroy,
    get authority() {
      return responderAuthority
    },
    get adjacency() {
      return adjacency
    },
    get forwarding() {
      return forwarding
    }
  }
  resources.push(record)
  if (plan === null) {
    responderAuthority = createTailControlResponderAuthority(tail, adjacency.responderToken, {
      tailReadySigner: createTailReadySigner(identityOwner),
      wallNow: clocks.wallNow,
      monotonicNow: clocks.monotonicNow,
      randomBytes: (size) => b4a.alloc(size, 0xee),
      schedule: clocks.schedule,
      cancelScheduled: clocks.cancelScheduled
    })
    return record
  }
  const nextAuthority = authority(clocks)
  const proof = createRedactedResponderProofAuthority({ now: clocks.wallNow })
  const dialAuthority = createRelayAdjacentDialAuthority({
    socketOwner: plan.pair,
    allowedRole: plan.role,
    async dial(owner, endpoint) {
      try {
        const offer = guardLinks[TAKE_OFFER](owner, endpoint)
        const target = plan.resolveEndpoint(endpoint)
        const object = require('../../lib/private/protocol').decodeM3Object(offer)
        const channels = await target.pair.open({
          circuitId: object.body.subarray(115, 131),
          generation: readU64(object.body, 131)
        })
        const inbound = [offer, null],
          outbound = []
        const receiver = createExtensionOfferReceiver({
          observedPredecessorEndpoint: target.predecessorEndpoint,
          receiveObject: () => inbound.shift(),
          takePhysicalChannel: () => channels.responder,
          sendObject: (value) => outbound.push(b4a.from(value)),
          finish: () => outbound.push(null),
          destroy() {}
        })
        linkResponder = createExtensionLinkResponder({
          advertisement: target.advertisement,
          adjacencyAdopter: nextAuthority.responderAdopter(),
          extensionResponderSigner: createExtensionResponderSigner(target.identityOwner),
          responderRouteEncryptionSecretKey: target.route.secretKey,
          wallNow: clocks.wallNow,
          monotonicNow: clocks.monotonicNow,
          schedule: clocks.schedule,
          cancelScheduled: clocks.cancelScheduled,
          offerReceiver: receiver,
          randomBytes: (size) => b4a.alloc(size, 0xed)
        })
        const accepted = linkResponder.accept()
        const moved = takeAcceptedExtensionAdjacencyTransfer(
          takeExtensionResponderAdjacency(linkResponder, accepted.accepted)
        )
        replayOwner = moved.replayOwner
        successor = createHostedTailResponder({
          adjacency: moved.adjacency,
          adjacencyAuthority: nextAuthority,
          identity: target.identity,
          clocks,
          plan: target.next,
          resources
        })
        return createExtensionResponseReceiver({
          receiveObject: () => outbound.shift(),
          takePhysicalChannel: () => channels.initiator,
          destroy() {}
        })
      } catch (err) {
        dialFailure = err
        throw err
      }
    },
    destroy() {}
  })
  const factory = createExtensionAdjacentLinkFactory({
    dialAuthority,
    linkOfferSigner: createLinkOfferSigner(identityOwner),
    proofVerifier: proof.verifier,
    proofConsumer: proof.consumer,
    wallNow: clocks.wallNow,
    monotonicNow: clocks.monotonicNow,
    randomBytes: (size) => b4a.alloc(size, 0xec),
    schedule: clocks.schedule,
    cancelScheduled: clocks.cancelScheduled,
    destroy() {}
  })
  const sends = []
  const committer = createTailExtensionCommitter({
    enqueue(value) {
      sends.push(transport.send(value))
    },
    install(nextRuntime, expiresAt) {
      forwarding = createM3RelayForwardingFacade(adjacency.runtime, nextRuntime, {
        releaseDownstream: async () => {},
        releaseUpstream: async () => {},
        monotonicNow: clocks.monotonicNow,
        schedule: clocks.schedule,
        cancelScheduled: clocks.cancelScheduled
      })
      const install = beginM3Install(adjacency.runtime, nextRuntime)
      validateM3Install(install, identity.publicKey, 128, clocks.wallNow())
      return commitM3Install(install, expiresAt, forwarding)
    },
    destroy() {}
  })
  responderAuthority = createTailControlResponderAuthority(tail, adjacency.responderToken, {
    adjacencyAdopter: adjacencyAuthority.responderAdopter(),
    extensionCommitter: committer,
    adjacentLinkFactory: factory,
    tailReadySigner: createTailReadySigner(identityOwner),
    wallNow: clocks.wallNow,
    monotonicNow: clocks.monotonicNow,
    randomBytes: (size) => b4a.alloc(size, 0xeb),
    schedule: clocks.schedule,
    cancelScheduled: clocks.cancelScheduled
  })
  async function serve() {
    try {
      const admitted = admitTailExtend(responderAuthority, await transport.receive())
      const readyContext = createSuccessorTailReadyContext(responderAuthority, admitted)
      const completion = await openTailAdjacentLink(responderAuthority, admitted)
      completeTailExtend(responderAuthority, completion)
      await Promise.all(sends)
      const ready = sealSuccessorTailReady(successor.authority, readyContext)
      await successor.transport.send(envelope(ready))
      return successor
    } catch (err) {
      throw dialFailure || err
    }
  }
  function destroy() {
    try {
      if (responderAuthority)
        require('../../lib/private/tail-control').destroyTailControlResponderAuthority(
          responderAuthority
        )
    } catch {}
    try {
      require('../../lib/private/tail-control').destroyTailControlSession(tail)
    } catch {}
    try {
      adjacency.runtime.destroy()
    } catch {}
    try {
      if (linkResponder) linkResponder.destroy()
    } catch {}
    try {
      if (replayOwner) guardLinks.destroyAcceptedExtensionAdjacencyOwner(replayOwner)
    } catch {}
    try {
      require('../../lib/private/relay-identity-signer').destroyRelayIdentitySigningAuthority(
        identityOwner
      )
    } catch {}
  }
  return record
}
module.exports = { createHostedTailResponder }
