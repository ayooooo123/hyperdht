'use strict'

const b4a = require('b4a')
const crypto = require('hypercore-crypto')
const sodium = require('sodium-universal')

const { PrivateRouteError } = require('./errors')
const { SenderCounter, DatagramReplayWindow, OrderedReceiver } = require('./counters')
const {
  PEER_MESSAGE_ID,
  PEER_BRANCH_CLASS,
  PEER_LINK_ROLE,
  encodePeerObject,
  decodePeerObject
} = require('./peer-protocol')
const {
  encodePeerTransport,
  decodePeerTransport,
  encodePeerLimits,
  decodePeerLimits,
  encodePeerLinkReply,
  decodePeerLinkReply
} = require('./peer-transport-wire')
const {
  hashPeer,
  derivePeerAdjacencyKeys,
  clearPeerAdjacencyKeys,
  digestPeerLimits,
  createPeerTailTranscript
} = require('./peer-crypto')
const {
  readPeerRelayOwner,
  verifyPeerAdvertisement,
  readVerifiedPeerAdvertisement
} = require('./peer-capability')
const {
  createPeerGuardPhysicalReservation,
  readPeerGuardPhysicalReservation,
  exchangePeerGuardLink,
  takePeerGuardPhysicalIssuer,
  destroyPeerGuardPhysicalReservation
} = require('./guard-lease')
const { takePeerActiveCandidate } = require('./peer-direct-bootstrap')
const {
  readPeerLedger,
  reservePeerLedger,
  releasePeerLedger,
  chargePeerLedger
} = require('./peer-ledger')

const INITIATOR_CELL_ID_DOMAIN = 'hyperdht-private-routes/m3/cell-id/initiator/v2'
const RESPONDER_CELL_ID_DOMAIN = 'hyperdht-private-routes/m3/cell-id/responder/v2'
const LINK_OFFER_DIGEST_DOMAIN = 'hyperdht-private-routes/m3/link-offer-digest/v2'
const LINK_ACCEPT_DIGEST_DOMAIN = 'hyperdht-private-routes/m3/link-accept-digest/v2'

const LINK_OFFER_LABEL = b4a.from('hyperdht-private-routes/m3/link-offer/v2')
const LINK_ACCEPT_LABEL = b4a.from('hyperdht-private-routes/m3/link-accept/v2')
const REDACTED_PROOF_LABEL = b4a.from('hyperdht-private-routes/m3/redacted-responder-proof/v2')
const DUMMY_AUTH_64 = b4a.alloc(64)

const MAX_U64 = 0xffff_ffff_ffff_ffffn
const MAX_RESPONDER_ROWS = 4096
const MAX_ATTEMPTS = 8
const MAX_ATTEMPT_WINDOW_MS = 2000n

const RESPONDERS = new WeakMap()
const OWNER_ADMISSIONS = new WeakMap()
const RESPONDER_BINDINGS = new WeakMap()
const REPLY_TOKENS = new WeakMap()

const ESTABLISHED_LINKS = new WeakMap()
const TAKEN_ESTABLISHED_HANDLES = new WeakSet()
const DESTROYED_ESTABLISHED_HANDLES = new WeakSet()

const TAKEN_ESTABLISHED_STATES = new WeakMap()
const DESTROYED_TAKEN_ESTABLISHED_STATES = new WeakSet()

const M3_AUTHENTICATED_BRANCH_BINDINGS = new WeakMap()
const SPENT_M3_AUTHENTICATED_BRANCH_BINDINGS = new WeakSet()

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function unauthorized() {
  throw PrivateRouteError.UNAUTHORIZED()
}

function replay() {
  throw PrivateRouteError.REPLAY()
}

function destroyed() {
  throw PrivateRouteError.ERR_DESTROYED()
}

function unavailable() {
  throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
}

function isObject(val) {
  return val !== null && typeof val === 'object' && !Array.isArray(val)
}

function own(obj, key) {
  if (!isObject(obj)) invalid()
  const desc = Object.getOwnPropertyDescriptor(obj, key)
  if (!desc || !Object.prototype.hasOwnProperty.call(desc, 'value')) invalid()
  return desc.value
}

function bufferLength(buf) {
  try {
    return b4a.isBuffer(buf) ? buf.byteLength : -1
  } catch {
    return -1
  }
}

function copy(src, expectedLen) {
  if (!b4a.isBuffer(src) || src.byteLength !== expectedLen) invalid()
  const dst = b4a.allocUnsafe(expectedLen)
  dst.set(src)
  return dst
}

function clear(buf) {
  if (b4a.isBuffer(buf)) {
    buf.fill(0)
  }
}

function memcmp(a, b) {
  if (!b4a.isBuffer(a) || !b4a.isBuffer(b) || a.byteLength !== b.byteLength) return false
  return b4a.equals(a, b)
}

function isZero32(buf) {
  if (!b4a.isBuffer(buf) || buf.byteLength !== 32) return false
  for (let i = 0; i < 32; i++) {
    if (buf[i] !== 0) return false
  }
  return true
}

function isNonZero32(buf) {
  if (!b4a.isBuffer(buf) || buf.byteLength !== 32) return false
  for (let i = 0; i < 32; i++) {
    if (buf[i] !== 0) return true
  }
  return false
}

function generateX25519KeyPair() {
  const publicKey = b4a.allocUnsafe(32)
  const secretKey = b4a.allocUnsafe(32)
  sodium.crypto_box_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

function diffieHellman(secretKey, remotePublicKey) {
  if (
    !b4a.isBuffer(secretKey) ||
    secretKey.byteLength !== 32 ||
    !b4a.isBuffer(remotePublicKey) ||
    remotePublicKey.byteLength !== 32
  ) {
    invalid()
  }
  if (isZero32(remotePublicKey)) invalid()
  const out = b4a.allocUnsafe(32)
  try {
    sodium.crypto_scalarmult(out, secretKey, remotePublicKey)
  } catch {
    clear(out)
    invalid()
  }
  if (isZero32(out)) {
    clear(out)
    invalid()
  }
  return out
}

function writeU16BE(buf, val, offset) {
  buf[offset] = (val >>> 8) & 0xff
  buf[offset + 1] = val & 0xff
}

function writeU32BE(buf, val, offset) {
  buf[offset] = (val >>> 24) & 0xff
  buf[offset + 1] = (val >>> 16) & 0xff
  buf[offset + 2] = (val >>> 8) & 0xff
  buf[offset + 3] = val & 0xff
}

function deriveCellIds(completeOfferDigest32) {
  const initiatorCellId = hashPeer(INITIATOR_CELL_ID_DOMAIN, [completeOfferDigest32]).subarray(
    0,
    16
  )
  const responderCellId = hashPeer(RESPONDER_CELL_ID_DOMAIN, [completeOfferDigest32]).subarray(
    0,
    16
  )
  return {
    initiatorCellId: copy(initiatorCellId, 16),
    responderCellId: copy(responderCellId, 16)
  }
}

function createContextPair(cellClass, txKey, txNoncePrefix, rxKey, rxNoncePrefix, now) {
  const tx = {
    key: copy(txKey, 32),
    noncePrefix: copy(txNoncePrefix, 16),
    counter: new SenderCounter({ maximum: MAX_U64 - 1n })
  }
  const rx = {
    key: copy(rxKey, 32),
    noncePrefix: copy(rxNoncePrefix, 16),
    counter:
      cellClass === 2
        ? new DatagramReplayWindow({ window: 256, maximum: MAX_U64 - 1n })
        : new OrderedReceiver({
            window: 256,
            gapTimeout: 5000,
            now: () => Number(now()),
            maximum: MAX_U64 - 1n
          })
  }
  return { tx, rx }
}

function clearContexts(contexts) {
  if (!contexts) return
  for (const c of [contexts[0], contexts[2]]) {
    if (c) {
      if (c.tx) {
        clear(c.tx.key)
        clear(c.tx.noncePrefix)
      }
      if (c.rx) {
        clear(c.rx.key)
        clear(c.rx.noncePrefix)
      }
    }
  }
}

function buildSignatureInput(messageId, label, body) {
  const labelLen = bufferLength(label)
  const bodyLen = bufferLength(body)
  if (labelLen <= 0 || bodyLen < 0) invalid()
  const headerOffset = 2 + labelLen
  const input = b4a.allocUnsafe(headerOffset + 8 + bodyLen)
  writeU16BE(input, labelLen, 0)
  input.set(label, 2)
  writeU32BE(input, 2, headerOffset)
  writeU16BE(input, messageId, headerOffset + 4)
  writeU16BE(input, bodyLen, headerOffset + 6)
  input.set(body, headerOffset + 8)
  return input
}

function encodeCanonicalBody(messageId, fields) {
  const wire = encodePeerTransport(messageId, fields, DUMMY_AUTH_64)
  return wire.subarray(8, wire.byteLength - 64)
}

function authenticatePeerLinkReply(accept, proof, identity) {
  try {
    if (
      accept.messageId !== PEER_MESSAGE_ID.PEER_LINK_ACCEPT_V2 ||
      !sodium.crypto_sign_verify_detached(
        accept.authSuffix,
        buildSignatureInput(PEER_MESSAGE_ID.PEER_LINK_ACCEPT_V2, LINK_ACCEPT_LABEL, accept.body),
        identity
      )
    )
      return false
    return (
      proof === null ||
      (proof.messageId === PEER_MESSAGE_ID.PEER_REDACTED_RESPONDER_PROOF_V2 &&
        sodium.crypto_sign_verify_detached(
          proof.authSuffix,
          buildSignatureInput(
            PEER_MESSAGE_ID.PEER_REDACTED_RESPONDER_PROOF_V2,
            REDACTED_PROOF_LABEL,
            proof.body
          ),
          identity
        ))
    )
  } catch {
    return false
  }
}

function validateLedger(ledger) {
  if (!ledger) unauthorized()
  let info = null
  try {
    info = readPeerLedger(ledger)
  } catch {
    unauthorized()
  }
  if (!info || info.released) unauthorized()
  return ledger
}

function releaseBranchLedgers(ledgers) {
  if (!ledgers) return
  if (ledgers.sendLedger) releasePeerLedger(ledgers.sendLedger)
  if (ledgers.receiveLedger) releasePeerLedger(ledgers.receiveLedger)
  if (ledgers.teardownSendLedger) releasePeerLedger(ledgers.teardownSendLedger)
  if (ledgers.teardownReceiveLedger) releasePeerLedger(ledgers.teardownReceiveLedger)
}

function reserveBranchLedgers(parents, sendLimits, receiveLimits) {
  const ledgers = {}
  const closure = { cells: 10, bytes: 12000n, commands: 1 }
  try {
    ledgers.sendLedger = reservePeerLedger(parents.sendLedger, {
      cells: sendLimits.maxCells - closure.cells,
      bytes: BigInt(sendLimits.maxBytes) - closure.bytes,
      commands: sendLimits.maxCommands - closure.commands
    })
    ledgers.receiveLedger = reservePeerLedger(parents.receiveLedger, {
      cells: receiveLimits.maxCells - closure.cells,
      bytes: BigInt(receiveLimits.maxBytes) - closure.bytes,
      commands: receiveLimits.maxCommands - closure.commands
    })
    ledgers.teardownSendLedger = reservePeerLedger(parents.teardownSendLedger, closure)
    ledgers.teardownReceiveLedger = reservePeerLedger(parents.teardownReceiveLedger, closure)
    return Object.freeze(ledgers)
  } catch (err) {
    releaseBranchLedgers(ledgers)
    throw err
  }
}

function createSetupFailureOwner(admissions, admission) {
  let active = true
  let released = false
  let sink = null
  return Object.freeze({
    install(next) {
      if (!active || sink || typeof next !== 'function') unauthorized()
      sink = next
    },
    fail() {
      if (!active) return false
      active = false
      const current = sink
      sink = null
      if (current) current()
      return true
    },
    release() {
      if (released) return
      active = false
      released = true
      sink = null
      admissions.delete(admission)
      admissions = null
      admission = null
    },
    isReleased() {
      return released
    }
  })
}

function createM3AuthenticatedBranchBinding(state, issuer, ownedLedgers, setupFailure) {
  const binding = Object.freeze({})
  const receiveCircuitId = copy(state.localId, 16)
  const sendCircuitId = copy(state.peerLocalId, 16)
  M3_AUTHENTICATED_BRANCH_BINDINGS.set(binding, {
    issuer,
    receiveEpoch: state.generation,
    receiveCircuitId,
    receiveDirection: state.initiator ? 1 : 0, // DIRECTION: FORWARD=0, REVERSE=1
    sendEpoch: state.generation,
    sendCircuitId,
    sendDirection: state.initiator ? 0 : 1,
    sendLedger: state.sendLedger,
    teardownSendLedger: state.teardownSendLedger,
    ownedLedgers,
    setupFailure
  })
  return binding
}

function takePeerM3AuthenticatedBranchBinding(binding, issuer) {
  const state = isObject(binding) ? M3_AUTHENTICATED_BRANCH_BINDINGS.get(binding) : null
  if (!state) {
    if (isObject(binding) && SPENT_M3_AUTHENTICATED_BRANCH_BINDINGS.has(binding)) {
      replay()
    }
    unauthorized()
  }
  M3_AUTHENTICATED_BRANCH_BINDINGS.delete(binding)
  SPENT_M3_AUTHENTICATED_BRANCH_BINDINGS.add(binding)
  if (state.issuer !== issuer) {
    clear(state.receiveCircuitId)
    clear(state.sendCircuitId)
    releaseBranchLedgers(state.ownedLedgers)
    if (state.setupFailure) state.setupFailure.release()
    unauthorized()
  }
  return state
}

function createEstablishedState(fields) {
  const contexts = Object.freeze({
    0: Object.freeze(fields.contexts[0]),
    2: Object.freeze(fields.contexts[2])
  })

  const internalState = {
    initiator: fields.initiator,
    branchClass: 2,
    generation: fields.generation,
    extensionIndex: fields.extensionIndex,
    contexts,
    completeOfferDigest: copy(fields.completeOfferDigest, 32),
    localId: copy(fields.localId, 16),
    peerLocalId: copy(fields.peerLocalId, 16),
    localIdentity: copy(fields.localIdentity, 32),
    peerIdentity: copy(fields.peerIdentity, 32),
    branchId: copy(fields.branchId, 16),
    circuitId: copy(fields.circuitId, 16),
    responderAdvertisementDigest: copy(fields.responderAdvertisementDigest, 32),
    physicalChannel: fields.physicalChannel,
    m3BranchBinding: null,
    tailSharedSecret: fields.tailSharedSecret ? copy(fields.tailSharedSecret, 32) : null,
    tailAdvertisement260: fields.tailSharedSecret ? copy(fields.tailAdvertisement260, 260) : null,
    tailControlTranscript: fields.tailControlTranscript
      ? copy(fields.tailControlTranscript, 290)
      : null,
    successorProof378: fields.successorProof378 ? copy(fields.successorProof378, 378) : null,
    forwardLimits: copy(fields.forwardLimits, 26),
    reverseLimits: copy(fields.reverseLimits, 26),
    sendLedger: fields.sendLedger,
    receiveLedger: fields.receiveLedger,
    teardownSendLedger: fields.teardownSendLedger,
    teardownReceiveLedger: fields.teardownReceiveLedger,
    clockIdentity: fields.clockIdentity,
    wallNow: fields.wallNow,
    monotonicNow: fields.monotonicNow,
    setTimer: fields.setTimer,
    clearTimer: fields.clearTimer,
    wireExpiresAt: fields.wireExpiresAt,
    localDeadline: fields.localDeadline,
    timers: new Set(),
    destroyed: false
  }

  const binding = createM3AuthenticatedBranchBinding(
    internalState,
    fields.physicalChannel,
    fields.ownedLedgers || null,
    fields.setupFailure || null
  )
  internalState.m3BranchBinding = binding

  const handle = Object.freeze({ kind: 'peerEstablishedLink' })
  ESTABLISHED_LINKS.set(handle, internalState)
  return handle
}

function takePeerEstablishedLink(handle) {
  const internalState = isObject(handle) ? ESTABLISHED_LINKS.get(handle) : null
  if (!internalState) {
    if (isObject(handle) && TAKEN_ESTABLISHED_HANDLES.has(handle)) replay()
    invalid()
  }
  if (internalState.destroyed) destroyed()

  ESTABLISHED_LINKS.delete(handle)
  TAKEN_ESTABLISHED_HANDLES.add(handle)

  const takenState = Object.freeze({
    initiator: internalState.initiator,
    branchClass: 2,
    generation: internalState.generation,
    extensionIndex: internalState.extensionIndex,
    contexts: internalState.contexts,
    completeOfferDigest: internalState.completeOfferDigest,
    localId: internalState.localId,
    peerLocalId: internalState.peerLocalId,
    localIdentity: internalState.localIdentity,
    peerIdentity: internalState.peerIdentity,
    branchId: internalState.branchId,
    circuitId: internalState.circuitId,
    responderAdvertisementDigest: internalState.responderAdvertisementDigest,
    physicalChannel: internalState.physicalChannel,
    m3BranchBinding: internalState.m3BranchBinding,
    tailSharedSecret: internalState.tailSharedSecret,
    tailAdvertisement260: internalState.tailAdvertisement260,
    tailControlTranscript: internalState.tailControlTranscript,
    successorProof378: internalState.successorProof378,
    forwardLimits: internalState.forwardLimits,
    reverseLimits: internalState.reverseLimits,
    sendLedger: internalState.sendLedger,
    receiveLedger: internalState.receiveLedger,
    teardownSendLedger: internalState.teardownSendLedger,
    teardownReceiveLedger: internalState.teardownReceiveLedger,
    clockIdentity: internalState.clockIdentity,
    wallNow: internalState.wallNow,
    monotonicNow: internalState.monotonicNow,
    setTimer: internalState.setTimer,
    clearTimer: internalState.clearTimer,
    wireExpiresAt: internalState.wireExpiresAt,
    localDeadline: internalState.localDeadline
  })

  TAKEN_ESTABLISHED_STATES.set(takenState, internalState)
  return takenState
}

function takePeerEstablishedProof(takenState) {
  const internalState = isObject(takenState) ? TAKEN_ESTABLISHED_STATES.get(takenState) : null
  if (!internalState || internalState.destroyed) unauthorized()
  if (
    !internalState.initiator ||
    (internalState.extensionIndex !== 1 && internalState.extensionIndex !== 2)
  ) {
    unauthorized()
  }
  const proof = internalState.successorProof378
  if (!proof || !b4a.isBuffer(proof) || proof.byteLength !== 378) unauthorized()
  internalState.successorProof378 = null
  return proof
}
function destroyInternalEstablishedState(internalState) {
  if (!internalState || internalState.destroyed) return true
  internalState.destroyed = true

  clearContexts(internalState.contexts)
  clear(internalState.completeOfferDigest)
  clear(internalState.localId)
  clear(internalState.peerLocalId)
  clear(internalState.localIdentity)
  clear(internalState.peerIdentity)
  clear(internalState.branchId)
  clear(internalState.circuitId)
  clear(internalState.responderAdvertisementDigest)
  clear(internalState.tailSharedSecret)
  clear(internalState.tailAdvertisement260)
  clear(internalState.tailControlTranscript)
  clear(internalState.successorProof378)
  clear(internalState.forwardLimits)
  clear(internalState.reverseLimits)

  if (internalState.m3BranchBinding) {
    const binding = M3_AUTHENTICATED_BRANCH_BINDINGS.get(internalState.m3BranchBinding)
    M3_AUTHENTICATED_BRANCH_BINDINGS.delete(internalState.m3BranchBinding)
    SPENT_M3_AUTHENTICATED_BRANCH_BINDINGS.add(internalState.m3BranchBinding)
    if (binding) {
      clear(binding.receiveCircuitId)
      clear(binding.sendCircuitId)
      releaseBranchLedgers(binding.ownedLedgers)
      if (binding.setupFailure) binding.setupFailure.release()
    }
    internalState.m3BranchBinding = null
  }

  if (internalState.timers && internalState.clearTimer) {
    for (const t of internalState.timers) {
      try {
        internalState.clearTimer(t)
      } catch {}
    }
    internalState.timers.clear()
  }

  if (
    internalState.physicalChannel &&
    typeof internalState.physicalChannel.destroy === 'function'
  ) {
    try {
      internalState.physicalChannel.destroy()
    } catch {}
    internalState.physicalChannel = null
  }

  return true
}

function destroyTakenPeerEstablishedLink(state) {
  if (!isObject(state)) return false
  if (DESTROYED_TAKEN_ESTABLISHED_STATES.has(state)) return true

  const internalState = TAKEN_ESTABLISHED_STATES.get(state)
  if (!internalState) return false

  TAKEN_ESTABLISHED_STATES.delete(state)
  DESTROYED_TAKEN_ESTABLISHED_STATES.add(state)
  return destroyInternalEstablishedState(internalState)
}

function destroyPeerEstablishedLink(handle) {
  if (!isObject(handle)) return false
  if (DESTROYED_ESTABLISHED_HANDLES.has(handle)) return true

  const internalState = ESTABLISHED_LINKS.get(handle)
  if (!internalState) return false

  ESTABLISHED_LINKS.delete(handle)
  DESTROYED_ESTABLISHED_HANDLES.add(handle)
  return destroyInternalEstablishedState(internalState)
}

function openPeerGuardLink(options) {
  if (!isObject(options)) invalid()

  const guardLease = own(options, 'guardLease')
  const activeCandidate = own(options, 'activeCandidate')
  const relayOwner = own(options, 'relayOwner')
  const advertisement = own(options, 'advertisement')
  const branchId = own(options, 'branchId')
  const circuitId = own(options, 'circuitId')
  const generation = own(options, 'generation')
  const extensionIndex = own(options, 'extensionIndex')
  const clientTailEphemeralPublicKey = own(options, 'clientTailEphemeralPublicKey')
  const clientNonce = own(options, 'clientNonce')
  const payloadParametersDigest = own(options, 'payloadParametersDigest')
  const forwardLimits = own(options, 'forwardLimits')
  const reverseLimits = own(options, 'reverseLimits')
  const candidateAuthorityCommitment = own(options, 'candidateAuthorityCommitment32')
  const sendLedger = validateLedger(own(options, 'sendLedger'))
  const teardownSendLedger = validateLedger(own(options, 'teardownSendLedger'))
  const receiveLedger = validateLedger(own(options, 'receiveLedger'))
  const teardownReceiveLedger = validateLedger(own(options, 'teardownReceiveLedger'))
  const operationDeadline = own(options, 'operationDeadline')

  if (extensionIndex !== 0) invalid()
  if (!bufferLength(candidateAuthorityCommitment) || !isZero32(candidateAuthorityCommitment)) {
    invalid()
  }
  if (bufferLength(branchId) !== 16 || bufferLength(circuitId) !== 16) invalid()
  if (typeof generation !== 'bigint' || generation < 1n || generation > MAX_U64) invalid()
  if (bufferLength(clientTailEphemeralPublicKey) !== 32) invalid()
  if (bufferLength(clientNonce) !== 32) invalid()
  if (bufferLength(payloadParametersDigest) !== 32) invalid()
  if (typeof operationDeadline !== 'bigint' || operationDeadline <= 0n) invalid()

  const clientTailSecretKey = options.clientTailSecretKey

  const owner = readPeerRelayOwner(relayOwner)

  const forwardLimitsBuf = encodePeerLimits(forwardLimits)
  const reverseLimitsBuf = encodePeerLimits(reverseLimits)

  const ephemeralKeys = generateX25519KeyPair()

  let reservation = null
  let branchLedgers = null
  let completeOffer432 = null
  let acceptWire285 = null
  let sharedAdjacencySecret = null
  let tailSharedSecret = null

  const cleanup = () => {
    releaseBranchLedgers(branchLedgers)
    branchLedgers = null
    clear(ephemeralKeys.secretKey)
    clear(sharedAdjacencySecret)
    clear(tailSharedSecret)
  }

  try {
    reservation = createPeerGuardPhysicalReservation(guardLease, {
      absoluteDeadline: operationDeadline
    })

    const resMetadata = readPeerGuardPhysicalReservation(reservation, relayOwner)
    if (!resMetadata) throw PrivateRouteError.UNAUTHORIZED()

    const candidate = takePeerActiveCandidate(activeCandidate, {
      expectedKind: 'guard',
      expectedIdentity32: resMetadata.peerIdentity32,
      expectedEndpoint19: resMetadata.peerEndpoint19,
      expectedEpoch: resMetadata.nativeEpoch,
      expectedAdvertisement260: advertisement,
      expectedGrantDigest: resMetadata.grantDigest32,
      expectedRunId: resMetadata.runId32,
      expectedOperations: resMetadata.operations,
      clockIdentity: resMetadata.clockIdentity
    })
    const verifiedAd = verifyPeerAdvertisement(advertisement, {
      expectedIdentity32: resMetadata.peerIdentity32,
      expectedRole: 1,
      clockIdentity: resMetadata.clockIdentity,
      wallNow: resMetadata.wallNow,
      monotonicNow: resMetadata.monotonicNow
    })
    const adInfo = readVerifiedPeerAdvertisement(verifiedAd)
    const effectiveDeadline =
      candidate.localDeadline < resMetadata.operationLocalDeadline
        ? candidate.localDeadline
        : resMetadata.operationLocalDeadline
    const wall = BigInt(resMetadata.wallNow())
    const mono = BigInt(resMetadata.monotonicNow())
    if (effectiveDeadline <= mono || candidate.wireExpiresAt <= wall) unavailable()
    const projectedOfferDeadline = wall + (effectiveDeadline - mono)
    const wireOfferDeadline =
      candidate.wireExpiresAt < projectedOfferDeadline
        ? candidate.wireExpiresAt
        : projectedOfferDeadline
    validateDirectionalLimits(forwardLimits, wall, resMetadata.parentWireExpiresAt)
    validateAdvertisedLimits(reverseLimits, adInfo, wall, resMetadata.parentWireExpiresAt)
    branchLedgers = reserveBranchLedgers(
      { sendLedger, receiveLedger, teardownSendLedger, teardownReceiveLedger },
      forwardLimits,
      reverseLimits
    )

    const offerFields = {
      advertisementDigest: adInfo.advertisementDigest32,
      initiatorIdentity: owner.relayIdentity32,
      responderIdentity: candidate.identity32,
      initiatorRole: PEER_LINK_ROLE.CLIENT,
      responderRole: PEER_LINK_ROLE.SAFETY_RELAY,
      branchClass: PEER_BRANCH_CLASS.PEER,
      branchId,
      circuitId,
      generation,
      extensionIndex: 0,
      initiatorLinkEphemeralPublicKey: ephemeralKeys.publicKey,
      clientTailEphemeralPublicKey,
      clientNonce,
      payloadParametersDigest,
      requestedLimits: decodePeerLimits(reverseLimitsBuf),
      offerDeadline: wireOfferDeadline,
      initiatorForwardLimits: decodePeerLimits(forwardLimitsBuf),
      candidateAuthorityCommitment
    }

    const offerCanonicalBody = encodeCanonicalBody(PEER_MESSAGE_ID.PEER_LINK_OFFER_V2, offerFields)
    const offerSignature = owner.signPeerObject(
      PEER_MESSAGE_ID.PEER_LINK_OFFER_V2,
      offerCanonicalBody
    )

    completeOffer432 = encodePeerTransport(
      PEER_MESSAGE_ID.PEER_LINK_OFFER_V2,
      offerFields,
      offerSignature
    )

    const exchangePromise = exchangePeerGuardLink(reservation, {
      offer: completeOffer432,
      generation,
      absoluteDeadline: effectiveDeadline,
      sendLedger: branchLedgers.sendLedger,
      receiveLedger: branchLedgers.receiveLedger
    })

    return Promise.resolve(exchangePromise)
      .then(
        (acceptBytes) => {
          let physicalChannel = null
          let contexts = null
          let establishedHandle = null
          try {
            const decodedReply = decodePeerLinkReply(acceptBytes, 0)
            acceptWire285 = decodedReply.accept285
            if (decodedReply.proof378 !== null) invalid()
            if (bufferLength(acceptWire285) !== 285) invalid()

            const decodedAccept = decodePeerTransport(acceptWire285)
            if (decodedAccept.messageId !== PEER_MESSAGE_ID.PEER_LINK_ACCEPT_V2) invalid()

            const acceptFields = decodedAccept.fields
            const offerDigest = hashPeer(LINK_OFFER_DIGEST_DOMAIN, [completeOffer432])
            if (!memcmp(acceptFields.offerDigest, offerDigest)) unauthorized()
            if (!memcmp(acceptFields.advertisementDigest, adInfo.advertisementDigest32)) {
              unauthorized()
            }
            if (!memcmp(acceptFields.responderIdentity, candidate.identity32)) unauthorized()

            if (
              !memcmp(
                acceptFields.observedPredecessorEndpoint,
                owner.parsedAdvertisement.reachableEndpoint19
              )
            ) {
              unauthorized()
            }
            if (!bufferLength(acceptFields.acceptNonce) || isZero32(acceptFields.acceptNonce)) {
              unauthorized()
            }

            const currWall = BigInt(resMetadata.wallNow())
            const currMono = BigInt(resMetadata.monotonicNow())
            if (currMono >= effectiveDeadline || currWall >= wireOfferDeadline) unavailable()

            const acceptedExpiresAt = acceptFields.admittedLimits.expiresAt
            if (acceptedExpiresAt !== offerFields.requestedLimits.expiresAt) unauthorized()
            if (acceptedExpiresAt <= currWall) unauthorized()

            if (
              acceptFields.acceptedAt > currWall ||
              acceptFields.acceptedAt >= acceptedExpiresAt ||
              acceptFields.acceptedAt > wireOfferDeadline
            ) {
              unauthorized()
            }

            if (!authenticatePeerLinkReply(decodedAccept, null, candidate.identity32))
              unauthorized()

            const admittedLimitsBuf = encodePeerLimits(acceptFields.admittedLimits)
            if (!b4a.equals(admittedLimitsBuf, reverseLimitsBuf)) unauthorized()

            sharedAdjacencySecret = diffieHellman(
              ephemeralKeys.secretKey,
              acceptFields.responderLinkEphemeralPublicKey
            )

            if (clientTailSecretKey) {
              tailSharedSecret = diffieHellman(
                clientTailSecretKey,
                adInfo.routeEncryptionPublicKey32
              )
            }

            let keysControl = null
            let keysDatagram = null
            try {
              keysControl = derivePeerAdjacencyKeys(
                sharedAdjacencySecret,
                completeOffer432,
                acceptWire285,
                0
              )
              keysDatagram = derivePeerAdjacencyKeys(
                sharedAdjacencySecret,
                completeOffer432,
                acceptWire285,
                2
              )

              contexts = {}
              contexts[0] = createContextPair(
                0,
                keysControl.forwardKey,
                keysControl.forwardNoncePrefix,
                keysControl.reverseKey,
                keysControl.reverseNoncePrefix,
                resMetadata.monotonicNow
              )
              contexts[2] = createContextPair(
                2,
                keysDatagram.forwardKey,
                keysDatagram.forwardNoncePrefix,
                keysDatagram.reverseKey,
                keysDatagram.reverseNoncePrefix,
                resMetadata.monotonicNow
              )
            } finally {
              if (keysControl) {
                clearPeerAdjacencyKeys(keysControl)
                keysControl = null
              }
              if (keysDatagram) {
                clearPeerAdjacencyKeys(keysDatagram)
                keysDatagram = null
              }
            }

            const tailControlTranscript = createPeerTailTranscript({
              branchId,
              circuitId,
              generation,
              extensionIndex: 0,
              clientTailEphemeralPublicKey,
              advertisedTailRouteEncryptionPublicKey: adInfo.routeEncryptionPublicKey32,
              candidateAdvertisementDigest: adInfo.advertisementDigest32,
              clientNonce,
              tailIdentity: candidate.identity32,
              reverseLimits: reverseLimitsBuf,
              forwardLimits: forwardLimitsBuf,
              candidateAuthorityCommitment
            })

            const cellIdPair = deriveCellIds(offerDigest)

            const directionalExpiresAt =
              offerFields.initiatorForwardLimits.expiresAt < acceptedExpiresAt
                ? offerFields.initiatorForwardLimits.expiresAt
                : acceptedExpiresAt
            if (directionalExpiresAt <= currWall) unauthorized()
            const wireExpiresAt =
              resMetadata.parentWireExpiresAt &&
              resMetadata.parentWireExpiresAt < directionalExpiresAt
                ? resMetadata.parentWireExpiresAt
                : directionalExpiresAt

            const projectedDeadline = currMono + (wireExpiresAt - currWall)
            const localDeadline =
              resMetadata.parentLocalDeadline && resMetadata.parentLocalDeadline < projectedDeadline
                ? resMetadata.parentLocalDeadline
                : projectedDeadline

            physicalChannel = takePeerGuardPhysicalIssuer(reservation)

            establishedHandle = createEstablishedState({
              initiator: true,
              generation,
              extensionIndex: 0,
              contexts,
              completeOfferDigest: offerDigest,
              localId: cellIdPair.initiatorCellId,
              peerLocalId: cellIdPair.responderCellId,
              localIdentity: owner.relayIdentity32,
              peerIdentity: candidate.identity32,
              branchId,
              circuitId,
              responderAdvertisementDigest: adInfo.advertisementDigest32,
              tailAdvertisement260: adInfo.canonicalBytes260,
              physicalChannel,
              tailSharedSecret,
              tailControlTranscript,
              successorProof378: null,
              forwardLimits: forwardLimitsBuf,
              reverseLimits: admittedLimitsBuf,
              ...branchLedgers,
              ownedLedgers: branchLedgers,
              clockIdentity: resMetadata.clockIdentity,
              wallNow: resMetadata.wallNow,
              monotonicNow: resMetadata.monotonicNow,
              setTimer: resMetadata.setTimer,
              clearTimer: resMetadata.clearTimer,
              wireExpiresAt,
              localDeadline
            })
            branchLedgers = null
            return establishedHandle
          } catch (err) {
            if (establishedHandle) {
              try {
                destroyPeerEstablishedLink(establishedHandle)
              } catch {}
              establishedHandle = null
            } else {
              if (physicalChannel && typeof physicalChannel.destroy === 'function') {
                try {
                  physicalChannel.destroy()
                } catch {}
                physicalChannel = null
              }
              if (contexts) {
                clearContexts(contexts)
                contexts = null
              }
              if (reservation) {
                try {
                  destroyPeerGuardPhysicalReservation(reservation)
                } catch {}
              }
            }
            throw err
          }
        },
        (err) => {
          if (reservation) {
            try {
              destroyPeerGuardPhysicalReservation(reservation)
            } catch {}
          }
          throw err
        }
      )
      .finally(cleanup)
  } catch (err) {
    cleanup()
    if (reservation) {
      try {
        destroyPeerGuardPhysicalReservation(reservation)
      } catch {}
    }
    throw err
  }
}

function openPeerNeighborLink(options) {
  if (!isObject(options)) invalid()

  const neighborPool = own(options, 'neighborPool')
  const activeCandidate = own(options, 'activeCandidate')
  const relayOwner = own(options, 'relayOwner')
  const advertisement = own(options, 'advertisement')
  const branchId = own(options, 'branchId')
  const circuitId = own(options, 'circuitId')
  const generation = own(options, 'generation')
  const extensionIndex = own(options, 'extensionIndex')
  const clientTailEphemeralPublicKey = own(options, 'clientTailEphemeralPublicKey')
  const clientNonce = own(options, 'clientNonce')
  const payloadParametersDigest = own(options, 'payloadParametersDigest')
  const forwardLimits = own(options, 'forwardLimits')
  const reverseLimits = own(options, 'reverseLimits')
  const candidateAuthorityCommitment = own(options, 'candidateAuthorityCommitment32')
  const sendLedger = validateLedger(own(options, 'sendLedger'))
  const teardownSendLedger = validateLedger(own(options, 'teardownSendLedger'))
  const receiveLedger = validateLedger(own(options, 'receiveLedger'))
  const teardownReceiveLedger = validateLedger(own(options, 'teardownReceiveLedger'))
  const operationDeadline = own(options, 'operationDeadline')

  if (extensionIndex !== 1 && extensionIndex !== 2) invalid()
  if (!bufferLength(candidateAuthorityCommitment) || !isNonZero32(candidateAuthorityCommitment)) {
    invalid()
  }
  if (bufferLength(branchId) !== 16 || bufferLength(circuitId) !== 16) invalid()
  if (typeof generation !== 'bigint' || generation < 1n || generation > MAX_U64) invalid()
  if (bufferLength(clientTailEphemeralPublicKey) !== 32) invalid()
  if (bufferLength(clientNonce) !== 32) invalid()
  if (bufferLength(payloadParametersDigest) !== 32) invalid()
  if (typeof operationDeadline !== 'bigint' || operationDeadline <= 0n) invalid()

  const owner = readPeerRelayOwner(relayOwner)

  const verifiedAd = verifyPeerAdvertisement(advertisement, {
    expectedRole: extensionIndex === 2 ? 2 : 1,
    clockIdentity: owner.clockIdentity,
    wallNow: owner.wallNow,
    monotonicNow: owner.monotonicNow
  })
  const adInfo = readVerifiedPeerAdvertisement(verifiedAd)

  if (memcmp(owner.relayIdentity32, adInfo.relayIdentity32)) invalid()

  const forwardLimitsBuf = encodePeerLimits(forwardLimits)
  const reverseLimitsBuf = encodePeerLimits(reverseLimits)

  const ephemeralKeys = generateX25519KeyPair()

  let reservation = null
  let branchLedgers = null
  let completeOffer432 = null
  let acceptWire285 = null
  let proofWire378 = null
  let sharedAdjacencySecret = null

  const cleanup = () => {
    releaseBranchLedgers(branchLedgers)
    branchLedgers = null
    clear(ephemeralKeys.secretKey)
    clear(sharedAdjacencySecret)
    if (proofWire378) {
      clear(proofWire378)
      proofWire378 = null
    }
  }

  try {
    const neighborModule = require('./peer-native-neighbors')
    reservation = neighborModule.reservePeerNeighborLink(neighborPool, {
      advertisement260: adInfo.canonicalBytes260,
      activeCandidate,
      absoluteDeadline: operationDeadline
    })

    const resMetadata = neighborModule.readPeerNeighborReservation(reservation, relayOwner)
    if (!resMetadata) throw PrivateRouteError.UNAUTHORIZED()
    if (!memcmp(adInfo.relayIdentity32, resMetadata.peerIdentity32)) {
      throw PrivateRouteError.UNAUTHORIZED()
    }

    const wall = BigInt(resMetadata.wallNow())
    const mono = BigInt(resMetadata.monotonicNow())
    if (operationDeadline <= mono) unavailable()
    const wireOfferDeadline = wall + (operationDeadline - mono)
    validateAdvertisedLimits(
      forwardLimits,
      owner.parsedAdvertisement,
      wall,
      resMetadata.parentWireExpiresAt
    )
    validateAdvertisedLimits(reverseLimits, adInfo, wall, resMetadata.parentWireExpiresAt)
    branchLedgers = reserveBranchLedgers(
      { sendLedger, receiveLedger, teardownSendLedger, teardownReceiveLedger },
      forwardLimits,
      reverseLimits
    )

    const offerFields = {
      advertisementDigest: adInfo.advertisementDigest32,
      initiatorIdentity: owner.relayIdentity32,
      responderIdentity: adInfo.relayIdentity32,
      initiatorRole: PEER_LINK_ROLE.SAFETY_RELAY,
      responderRole: extensionIndex === 1 ? PEER_LINK_ROLE.SAFETY_RELAY : PEER_LINK_ROLE.TERMINAL,
      branchClass: PEER_BRANCH_CLASS.PEER,
      branchId,
      circuitId,
      generation,
      extensionIndex,
      initiatorLinkEphemeralPublicKey: ephemeralKeys.publicKey,
      clientTailEphemeralPublicKey,
      clientNonce,
      payloadParametersDigest,
      requestedLimits: decodePeerLimits(reverseLimitsBuf),
      offerDeadline: wireOfferDeadline,
      initiatorForwardLimits: decodePeerLimits(forwardLimitsBuf),
      candidateAuthorityCommitment
    }

    const offerCanonicalBody = encodeCanonicalBody(PEER_MESSAGE_ID.PEER_LINK_OFFER_V2, offerFields)
    const offerSignature = owner.signPeerObject(
      PEER_MESSAGE_ID.PEER_LINK_OFFER_V2,
      offerCanonicalBody
    )

    completeOffer432 = encodePeerTransport(
      PEER_MESSAGE_ID.PEER_LINK_OFFER_V2,
      offerFields,
      offerSignature
    )

    const exchangePromise = neighborModule.exchangePeerNeighborLink(reservation, {
      offer: completeOffer432,
      generation,
      sendLedger: branchLedgers.sendLedger,
      receiveLedger: branchLedgers.receiveLedger
    })

    return Promise.resolve(exchangePromise)
      .then(
        (replyBytes) => {
          let physicalChannel = null
          let contexts = null
          let establishedHandle = null
          try {
            const decodedReply = decodePeerLinkReply(replyBytes, extensionIndex)
            acceptWire285 = decodedReply.accept285
            proofWire378 = decodedReply.proof378
            if (!proofWire378 || bufferLength(proofWire378) !== 378) invalid()
            if (bufferLength(acceptWire285) !== 285) invalid()

            const decodedAccept = decodePeerTransport(acceptWire285)
            if (decodedAccept.messageId !== PEER_MESSAGE_ID.PEER_LINK_ACCEPT_V2) invalid()

            const acceptFields = decodedAccept.fields
            const offerDigest = hashPeer(LINK_OFFER_DIGEST_DOMAIN, [completeOffer432])
            if (!memcmp(acceptFields.offerDigest, offerDigest)) unauthorized()
            if (!memcmp(acceptFields.advertisementDigest, adInfo.advertisementDigest32)) {
              unauthorized()
            }
            if (!memcmp(acceptFields.responderIdentity, adInfo.relayIdentity32)) unauthorized()

            if (
              !memcmp(
                acceptFields.observedPredecessorEndpoint,
                owner.parsedAdvertisement.reachableEndpoint19
              )
            ) {
              unauthorized()
            }
            if (!bufferLength(acceptFields.acceptNonce) || isZero32(acceptFields.acceptNonce)) {
              unauthorized()
            }

            const currWall = BigInt(resMetadata.wallNow())
            const currMono = BigInt(resMetadata.monotonicNow())

            const acceptedExpiresAt = acceptFields.admittedLimits.expiresAt
            if (acceptedExpiresAt !== offerFields.requestedLimits.expiresAt) unauthorized()
            if (acceptedExpiresAt <= currWall) unauthorized()

            if (
              acceptFields.acceptedAt > currWall ||
              acceptFields.acceptedAt >= acceptedExpiresAt ||
              acceptFields.acceptedAt > wireOfferDeadline
            ) {
              unauthorized()
            }

            const decodedProof = decodePeerTransport(proofWire378)
            if (!authenticatePeerLinkReply(decodedAccept, decodedProof, adInfo.relayIdentity32)) {
              unauthorized()
            }
            const admittedLimitsBuf = encodePeerLimits(acceptFields.admittedLimits)
            if (!memcmp(admittedLimitsBuf, reverseLimitsBuf)) unauthorized()

            if (decodedProof.messageId !== PEER_MESSAGE_ID.PEER_REDACTED_RESPONDER_PROOF_V2) {
              invalid()
            }

            const proofFields = decodedProof.fields
            if (!memcmp(proofFields.responderAdvertisementDigest, adInfo.advertisementDigest32)) {
              unauthorized()
            }
            if (!memcmp(proofFields.initiatorIdentity, owner.relayIdentity32)) unauthorized()
            if (!memcmp(proofFields.responderIdentity, adInfo.relayIdentity32)) unauthorized()
            if (proofFields.branchClass !== PEER_BRANCH_CLASS.PEER) unauthorized()
            if (!memcmp(proofFields.branchId, branchId)) unauthorized()
            if (!memcmp(proofFields.circuitId, circuitId)) unauthorized()
            if (proofFields.generation !== generation) unauthorized()
            if (proofFields.extensionIndex !== extensionIndex) unauthorized()
            if (!memcmp(proofFields.clientTailEphemeralPublicKey, clientTailEphemeralPublicKey)) {
              unauthorized()
            }
            if (!memcmp(proofFields.clientNonce, clientNonce)) unauthorized()
            if (
              !memcmp(
                proofFields.advertisedRouteEncryptionPublicKey,
                adInfo.routeEncryptionPublicKey32
              )
            ) {
              unauthorized()
            }

            const expectedAdmittedLimitsDigest = digestPeerLimits(
              reverseLimitsBuf,
              forwardLimitsBuf,
              candidateAuthorityCommitment
            )
            if (!memcmp(proofFields.admittedLimitsDigest, expectedAdmittedLimitsDigest)) {
              unauthorized()
            }

            if (proofFields.expiresAt !== acceptFields.admittedLimits.expiresAt) unauthorized()
            if (proofFields.expiresAt !== offerFields.requestedLimits.expiresAt) unauthorized()

            if (
              !bufferLength(proofFields.responderProofNonce) ||
              isZero32(proofFields.responderProofNonce)
            ) {
              unauthorized()
            }

            sharedAdjacencySecret = diffieHellman(
              ephemeralKeys.secretKey,
              acceptFields.responderLinkEphemeralPublicKey
            )

            let keysControl = null
            let keysDatagram = null
            try {
              keysControl = derivePeerAdjacencyKeys(
                sharedAdjacencySecret,
                completeOffer432,
                acceptWire285,
                0
              )
              keysDatagram = derivePeerAdjacencyKeys(
                sharedAdjacencySecret,
                completeOffer432,
                acceptWire285,
                2
              )

              contexts = {}
              contexts[0] = createContextPair(
                0,
                keysControl.forwardKey,
                keysControl.forwardNoncePrefix,
                keysControl.reverseKey,
                keysControl.reverseNoncePrefix,
                resMetadata.monotonicNow
              )
              contexts[2] = createContextPair(
                2,
                keysDatagram.forwardKey,
                keysDatagram.forwardNoncePrefix,
                keysDatagram.reverseKey,
                keysDatagram.reverseNoncePrefix,
                resMetadata.monotonicNow
              )
            } finally {
              if (keysControl) {
                clearPeerAdjacencyKeys(keysControl)
                keysControl = null
              }
              if (keysDatagram) {
                clearPeerAdjacencyKeys(keysDatagram)
                keysDatagram = null
              }
            }

            const tailControlTranscript = createPeerTailTranscript({
              branchId,
              circuitId,
              generation,
              extensionIndex,
              clientTailEphemeralPublicKey,
              advertisedTailRouteEncryptionPublicKey: adInfo.routeEncryptionPublicKey32,
              candidateAdvertisementDigest: adInfo.advertisementDigest32,
              clientNonce,
              tailIdentity: adInfo.relayIdentity32,
              reverseLimits: reverseLimitsBuf,
              forwardLimits: forwardLimitsBuf,
              candidateAuthorityCommitment
            })

            const cellIdPair = deriveCellIds(offerDigest)

            const directionalExpiresAt =
              offerFields.initiatorForwardLimits.expiresAt < acceptedExpiresAt
                ? offerFields.initiatorForwardLimits.expiresAt
                : acceptedExpiresAt
            if (directionalExpiresAt <= currWall) unauthorized()
            const wireExpiresAt =
              resMetadata.parentWireExpiresAt &&
              resMetadata.parentWireExpiresAt < directionalExpiresAt
                ? resMetadata.parentWireExpiresAt
                : directionalExpiresAt

            const projectedDeadline = currMono + (wireExpiresAt - currWall)
            const localDeadline =
              resMetadata.parentLocalDeadline && resMetadata.parentLocalDeadline < projectedDeadline
                ? resMetadata.parentLocalDeadline
                : projectedDeadline

            physicalChannel = neighborModule.takePeerNeighborPhysicalIssuer(reservation)

            establishedHandle = createEstablishedState({
              initiator: true,
              generation,
              extensionIndex,
              contexts,
              completeOfferDigest: offerDigest,
              localId: cellIdPair.initiatorCellId,
              peerLocalId: cellIdPair.responderCellId,
              localIdentity: owner.relayIdentity32,
              peerIdentity: adInfo.relayIdentity32,
              branchId,
              circuitId,
              responderAdvertisementDigest: adInfo.advertisementDigest32,
              tailAdvertisement260: adInfo.canonicalBytes260,
              physicalChannel,
              tailSharedSecret: null,
              tailControlTranscript,
              successorProof378: proofWire378,
              forwardLimits: forwardLimitsBuf,
              reverseLimits: admittedLimitsBuf,
              ...branchLedgers,
              ownedLedgers: branchLedgers,
              clockIdentity: resMetadata.clockIdentity,
              wallNow: resMetadata.wallNow,
              monotonicNow: resMetadata.monotonicNow,
              setTimer: resMetadata.setTimer,
              clearTimer: resMetadata.clearTimer,
              wireExpiresAt,
              localDeadline
            })
            branchLedgers = null
            clear(proofWire378)
            proofWire378 = null
            return establishedHandle
          } catch (err) {
            if (proofWire378) {
              clear(proofWire378)
              proofWire378 = null
            }
            if (establishedHandle) {
              try {
                destroyPeerEstablishedLink(establishedHandle)
              } catch {}
              establishedHandle = null
            } else {
              if (physicalChannel && typeof physicalChannel.destroy === 'function') {
                try {
                  physicalChannel.destroy()
                } catch {}
                physicalChannel = null
              }
              if (contexts) {
                clearContexts(contexts)
                contexts = null
              }
              if (
                reservation &&
                typeof neighborModule.destroyPeerNeighborReservation === 'function'
              ) {
                try {
                  neighborModule.destroyPeerNeighborReservation(reservation)
                } catch {}
              }
            }
            throw err
          }
        },
        (err) => {
          if (reservation && typeof neighborModule.destroyPeerNeighborReservation === 'function') {
            try {
              neighborModule.destroyPeerNeighborReservation(reservation)
            } catch {}
          }
          throw err
        }
      )
      .finally(cleanup)
  } catch (err) {
    cleanup()
    if (reservation) {
      try {
        const neighborModule = require('./peer-native-neighbors')
        if (typeof neighborModule.destroyPeerNeighborReservation === 'function') {
          neighborModule.destroyPeerNeighborReservation(reservation)
        }
      } catch {}
    }
    throw err
  }
}

function createPeerLinkResponder(relayOwner, options) {
  const owner = readPeerRelayOwner(relayOwner)
  if (!isObject(options)) invalid()
  const onEstablished = own(options, 'onEstablished')
  if (typeof onEstablished !== 'function') invalid()

  const sendLedger = validateLedger(own(options, 'sendLedger'))
  const teardownSendLedger = validateLedger(own(options, 'teardownSendLedger'))
  const receiveLedger = validateLedger(own(options, 'receiveLedger'))
  const teardownReceiveLedger = validateLedger(own(options, 'teardownReceiveLedger'))

  const rows = new Map()
  let admittedLinks = OWNER_ADMISSIONS.get(relayOwner)
  if (!admittedLinks) {
    admittedLinks = new Set()
    OWNER_ADMISSIONS.set(relayOwner, admittedLinks)
  }

  const responderState = {
    destroyed: false,
    relayOwner,
    owner,
    options: {
      ...options,
      onEstablished,
      sendLedger,
      receiveLedger,
      teardownSendLedger,
      teardownReceiveLedger
    },
    rows,
    logicalRows: new WeakMap(),
    bindings: new Set(),
    admittedLinks
  }

  const responderHandle = Object.freeze({ kind: 'peerLinkResponder' })
  RESPONDERS.set(responderHandle, responderState)
  return responderHandle
}

function destroyResponderRow(row, setupViolation = false) {
  row.expired = true
  if (setupViolation && row.failSetup) row.failSetup()
  row.failSetup = null
  clear(row.replyPacket)
  row.replyPacket = null
  if (row.physicalIssuer) {
    try {
      row.physicalIssuer.destroy()
    } catch {}
    row.physicalIssuer = null
  }
  clear(row.sharedAdjacencySecret)
  clear(row.ephemeralSecretKey)
  if (row.establishedHandle) {
    destroyPeerEstablishedLink(row.establishedHandle)
    row.establishedHandle = null
  }
}

function validateDirectionalLimits(limits, nowWall, parentWireExpiresAt) {
  if (
    limits.cellSize !== 1200 ||
    limits.maxCells < 18 ||
    limits.maxBytes !== limits.maxCells * 1200 ||
    limits.maxCommands < 2 ||
    limits.idleTimeoutMs < 1 ||
    limits.expiresAt <= nowWall ||
    limits.expiresAt > parentWireExpiresAt
  )
    unauthorized()
}

function validateAdvertisedLimits(limits, advertisement, nowWall, parentWireExpiresAt) {
  validateDirectionalLimits(limits, nowWall, parentWireExpiresAt)
  if (
    limits.maxCells > advertisement.maxCells ||
    limits.maxBytes > advertisement.maxBytes ||
    limits.maxCommands > advertisement.maxCommands ||
    limits.idleTimeoutMs > advertisement.idleTimeoutMs ||
    limits.expiresAt > advertisement.expiresAt
  )
    unauthorized()
}

function destroyPeerLinkResponder(responder) {
  const state = isObject(responder) ? RESPONDERS.get(responder) : null
  if (!state || state.destroyed) return false
  state.destroyed = true

  for (const binding of Array.from(state.bindings)) {
    const bState = RESPONDER_BINDINGS.get(binding)
    if (bState) {
      bState.destroyed = true
      RESPONDER_BINDINGS.delete(binding)
    }
  }
  state.bindings.clear()

  for (const row of state.rows.values()) destroyResponderRow(row)
  state.rows.clear()
  RESPONDERS.delete(responder)
  return true
}

function takePeerLinkResponderBinding(responder, established, endpoint) {
  const rState = isObject(responder) ? RESPONDERS.get(responder) : null
  if (!rState || rState.destroyed) unauthorized()

  const endpointModule = require('./udx-cell-endpoint')
  const nativeBinding = endpointModule.readPeerEstablishedLinkBinding(
    established,
    rState.relayOwner
  )

  const bindingState = {
    responderState: rState,
    established,
    endpoint,
    nativeBinding,
    destroyed: false
  }

  const binding = Object.freeze({
    accept(args) {
      if (bindingState.destroyed || rState.destroyed) unauthorized()
      if (!isObject(args)) invalid()

      const offerWire432 = own(args, 'offer')
      const targetEstablished = own(args, 'established')
      const reservePhysical = own(args, 'reservePhysical')

      if (targetEstablished !== established) unauthorized()
      if (typeof reservePhysical !== 'function') unauthorized()
      if (bufferLength(offerWire432) !== 432) invalid()

      const offerDigest = hashPeer(LINK_OFFER_DIGEST_DOMAIN, [offerWire432])
      const offerKey = b4a.toString(offerDigest, 'hex')

      const existingRow = rState.rows.get(offerKey)
      if (existingRow) {
        if (existingRow.expired || existingRow.established !== established) unauthorized()
        const now = BigInt(nativeBinding.monotonicNow())
        if (rState.destroyed || bindingState.destroyed || existingRow.expired) unauthorized()
        try {
          chargePeerLedger(existingRow.receiveLedger, { cells: 1, bytes: 1200n, commands: 0 })
          existingRow.receivedOffers++
          if (existingRow.receivedOffers > MAX_ATTEMPTS) unauthorized()
        } catch (err) {
          destroyResponderRow(existingRow, true)
          throw err
        }
        if (now >= existingRow.deadline) {
          destroyResponderRow(existingRow)
          unauthorized()
        }
        const replyToken = Object.freeze({
          kind: 'peerLinkReplyToken'
        })
        REPLY_TOKENS.set(replyToken, {
          row: existingRow,
          established,
          consumed: false
        })
        return replyToken
      }

      const decodedOffer = decodePeerTransport(offerWire432)
      if (decodedOffer.messageId !== PEER_MESSAGE_ID.PEER_LINK_OFFER_V2) invalid()

      const offerFields = decodedOffer.fields

      if (!memcmp(offerFields.initiatorIdentity, nativeBinding.peerIdentity32)) unauthorized()
      if (!memcmp(offerFields.responderIdentity, nativeBinding.localIdentity32)) unauthorized()
      if (!memcmp(offerFields.responderIdentity, rState.owner.relayIdentity32)) unauthorized()

      if (offerFields.extensionIndex === 0) {
        if (
          offerFields.initiatorRole !== PEER_LINK_ROLE.CLIENT ||
          offerFields.responderRole !== PEER_LINK_ROLE.SAFETY_RELAY ||
          !bufferLength(offerFields.candidateAuthorityCommitment) ||
          !isZero32(offerFields.candidateAuthorityCommitment)
        ) {
          unauthorized()
        }
      } else if (offerFields.extensionIndex === 1) {
        if (
          offerFields.initiatorRole !== PEER_LINK_ROLE.SAFETY_RELAY ||
          offerFields.responderRole !== PEER_LINK_ROLE.SAFETY_RELAY ||
          !bufferLength(offerFields.candidateAuthorityCommitment) ||
          !isNonZero32(offerFields.candidateAuthorityCommitment)
        ) {
          unauthorized()
        }
      } else if (offerFields.extensionIndex === 2) {
        if (
          offerFields.initiatorRole !== PEER_LINK_ROLE.SAFETY_RELAY ||
          offerFields.responderRole !== PEER_LINK_ROLE.TERMINAL ||
          !bufferLength(offerFields.candidateAuthorityCommitment) ||
          !isNonZero32(offerFields.candidateAuthorityCommitment)
        ) {
          unauthorized()
        }
      } else {
        unauthorized()
      }

      if (offerFields.branchClass !== PEER_BRANCH_CLASS.PEER) unauthorized()

      if (!memcmp(offerFields.advertisementDigest, rState.owner.advertisementDigest32)) {
        unauthorized()
      }

      const offerSigInput = buildSignatureInput(
        PEER_MESSAGE_ID.PEER_LINK_OFFER_V2,
        LINK_OFFER_LABEL,
        decodedOffer.body
      )

      const verifySig = sodium.crypto_sign_verify_detached(
        decodedOffer.authSuffix,
        offerSigInput,
        offerFields.initiatorIdentity
      )
      if (!verifySig) unauthorized()

      const nowWall = BigInt(nativeBinding.wallNow())
      const nowMono = BigInt(nativeBinding.monotonicNow())
      if (rState.destroyed || bindingState.destroyed) unauthorized()
      let logicalRows = rState.logicalRows.get(established)
      const logicalKey = `${offerFields.generation}:${offerFields.extensionIndex}:${b4a.toString(offerFields.branchId, 'hex')}:${b4a.toString(offerFields.circuitId, 'hex')}`
      if (logicalRows && logicalRows.has(logicalKey)) {
        const existing = logicalRows.get(logicalKey)
        if (existing && !existing.expired) {
          try {
            chargePeerLedger(existing.receiveLedger, { cells: 1, bytes: 1200n, commands: 0 })
            existing.receivedOffers++
          } finally {
            destroyResponderRow(existing, true)
          }
        }
        unauthorized()
      }
      if (offerFields.offerDeadline <= nowWall) unauthorized()
      if (offerFields.requestedLimits.expiresAt <= nowWall) unauthorized()
      validateAdvertisedLimits(
        offerFields.requestedLimits,
        rState.owner.parsedAdvertisement,
        nowWall,
        nativeBinding.parentWireExpiresAt
      )
      validateDirectionalLimits(
        offerFields.initiatorForwardLimits,
        nowWall,
        nativeBinding.parentWireExpiresAt
      )

      const offerProjected = nowMono + (offerFields.offerDeadline - nowWall)
      const reverseExpiryProjected = nowMono + (offerFields.requestedLimits.expiresAt - nowWall)
      let localDeadline =
        offerProjected < reverseExpiryProjected ? offerProjected : reverseExpiryProjected
      if (nativeBinding.parentLocalDeadline && nativeBinding.parentLocalDeadline < localDeadline) {
        localDeadline = nativeBinding.parentLocalDeadline
      }

      if (nowMono >= localDeadline) unauthorized()

      const directionalExpiresAt =
        offerFields.initiatorForwardLimits.expiresAt < offerFields.requestedLimits.expiresAt
          ? offerFields.initiatorForwardLimits.expiresAt
          : offerFields.requestedLimits.expiresAt
      const wireExpiresAt =
        nativeBinding.parentWireExpiresAt < directionalExpiresAt
          ? nativeBinding.parentWireExpiresAt
          : directionalExpiresAt
      const establishedProjection = nowMono + (wireExpiresAt - nowWall)
      if (wireExpiresAt <= nowWall || establishedProjection > MAX_U64) unauthorized()
      const establishedLocalDeadline =
        nativeBinding.parentLocalDeadline < establishedProjection
          ? nativeBinding.parentLocalDeadline
          : establishedProjection
      if (establishedLocalDeadline < localDeadline) localDeadline = establishedLocalDeadline

      if (rState.admittedLinks.size >= rState.owner.parsedAdvertisement.maxConcurrentCircuits) {
        unavailable()
      }
      if (rState.rows.size >= MAX_RESPONDER_ROWS) {
        let retired = null
        for (const candidate of rState.rows.values()) {
          if (nowMono >= candidate.deadline && candidate.setupReleased()) {
            retired = candidate
            break
          }
        }
        if (!retired) unavailable()
        destroyResponderRow(retired)
        rState.rows.delete(retired.offerKey)
        retired.logicalRows.delete(retired.logicalKey)
      }
      if (!logicalRows) {
        logicalRows = new Map()
        rState.logicalRows.set(established, logicalRows)
      }
      logicalRows.set(logicalKey, null)
      const admission = Object.freeze({})
      rState.admittedLinks.add(admission)
      const setupFailure = createSetupFailureOwner(rState.admittedLinks, admission)
      let bindingOwnsAdmission = false
      let committed = false
      try {
        const physicalIssuer = reservePhysical()
        if (!physicalIssuer) unauthorized()

        let ephemeralKeys = null
        let sharedAdjacencySecret = null
        let tailSharedSecret = null
        let contexts = null
        let establishedHandle = null
        let row = null
        let branchLedgers = null

        try {
          branchLedgers = reserveBranchLedgers(
            rState.options,
            offerFields.requestedLimits,
            offerFields.initiatorForwardLimits
          )
          const receiveLedger = branchLedgers.receiveLedger
          chargePeerLedger(branchLedgers.sendLedger, { cells: 0, bytes: 0n, commands: 1 })
          chargePeerLedger(receiveLedger, { cells: 1, bytes: 1200n, commands: 1 })
          ephemeralKeys = generateX25519KeyPair()
          sharedAdjacencySecret = diffieHellman(
            ephemeralKeys.secretKey,
            offerFields.initiatorLinkEphemeralPublicKey
          )

          tailSharedSecret = rState.owner.agreeRoute(offerFields.clientTailEphemeralPublicKey)

          const acceptedAt = BigInt(nativeBinding.wallNow())
          const acceptNonce = b4a.allocUnsafe(32)
          sodium.randombytes_buf(acceptNonce)

          const reverseLimitsBuf = encodePeerLimits(offerFields.requestedLimits)
          const forwardLimitsBuf = encodePeerLimits(offerFields.initiatorForwardLimits)

          const acceptFields = {
            offerDigest,
            advertisementDigest: rState.owner.advertisementDigest32,
            responderIdentity: rState.owner.relayIdentity32,
            observedPredecessorEndpoint: nativeBinding.peerEndpoint19,
            responderLinkEphemeralPublicKey: ephemeralKeys.publicKey,
            admittedLimits: offerFields.requestedLimits,
            acceptedAt,
            acceptNonce
          }

          const acceptCanonicalBody = encodeCanonicalBody(
            PEER_MESSAGE_ID.PEER_LINK_ACCEPT_V2,
            acceptFields
          )
          const acceptSignature = rState.owner.signPeerObject(
            PEER_MESSAGE_ID.PEER_LINK_ACCEPT_V2,
            acceptCanonicalBody
          )

          const acceptWire285 = encodePeerTransport(
            PEER_MESSAGE_ID.PEER_LINK_ACCEPT_V2,
            acceptFields,
            acceptSignature
          )

          let replyPacket = null
          let proofWire378 = null

          if (offerFields.extensionIndex === 0) {
            replyPacket = encodePeerLinkReply(acceptWire285, null, 0)
          } else {
            const admittedLimitsDigest = digestPeerLimits(
              reverseLimitsBuf,
              forwardLimitsBuf,
              offerFields.candidateAuthorityCommitment
            )
            const responderProofNonce = b4a.allocUnsafe(32)
            sodium.randombytes_buf(responderProofNonce)

            const proofFields = {
              responderAdvertisementDigest: rState.owner.advertisementDigest32,
              initiatorIdentity: offerFields.initiatorIdentity,
              responderIdentity: rState.owner.relayIdentity32,
              branchClass: PEER_BRANCH_CLASS.PEER,
              branchId: offerFields.branchId,
              circuitId: offerFields.circuitId,
              generation: offerFields.generation,
              extensionIndex: offerFields.extensionIndex,
              clientTailEphemeralPublicKey: offerFields.clientTailEphemeralPublicKey,
              clientNonce: offerFields.clientNonce,
              advertisedRouteEncryptionPublicKey: rState.owner.routeEncryptionPublicKey32,
              admittedLimitsDigest,
              expiresAt: acceptFields.admittedLimits.expiresAt,
              responderProofNonce
            }

            const proofCanonicalBody = encodeCanonicalBody(
              PEER_MESSAGE_ID.PEER_REDACTED_RESPONDER_PROOF_V2,
              proofFields
            )
            const proofSignature = rState.owner.signPeerObject(
              PEER_MESSAGE_ID.PEER_REDACTED_RESPONDER_PROOF_V2,
              proofCanonicalBody
            )

            proofWire378 = encodePeerTransport(
              PEER_MESSAGE_ID.PEER_REDACTED_RESPONDER_PROOF_V2,
              proofFields,
              proofSignature
            )

            replyPacket = encodePeerLinkReply(
              acceptWire285,
              proofWire378,
              offerFields.extensionIndex
            )
          }
          let keysControl = null
          let keysDatagram = null
          try {
            keysControl = derivePeerAdjacencyKeys(
              sharedAdjacencySecret,
              offerWire432,
              acceptWire285,
              0
            )
            keysDatagram = derivePeerAdjacencyKeys(
              sharedAdjacencySecret,
              offerWire432,
              acceptWire285,
              2
            )

            contexts = {}
            contexts[0] = createContextPair(
              0,
              keysControl.reverseKey,
              keysControl.reverseNoncePrefix,
              keysControl.forwardKey,
              keysControl.forwardNoncePrefix,
              nativeBinding.monotonicNow
            )
            contexts[2] = createContextPair(
              2,
              keysDatagram.reverseKey,
              keysDatagram.reverseNoncePrefix,
              keysDatagram.forwardKey,
              keysDatagram.forwardNoncePrefix,
              nativeBinding.monotonicNow
            )
          } finally {
            if (keysControl) {
              clearPeerAdjacencyKeys(keysControl)
              keysControl = null
            }
            if (keysDatagram) {
              clearPeerAdjacencyKeys(keysDatagram)
              keysDatagram = null
            }
          }

          const tailControlTranscript = createPeerTailTranscript({
            branchId: offerFields.branchId,
            circuitId: offerFields.circuitId,
            generation: offerFields.generation,
            extensionIndex: offerFields.extensionIndex,
            clientTailEphemeralPublicKey: offerFields.clientTailEphemeralPublicKey,
            advertisedTailRouteEncryptionPublicKey: rState.owner.routeEncryptionPublicKey32,
            candidateAdvertisementDigest: rState.owner.advertisementDigest32,
            clientNonce: offerFields.clientNonce,
            tailIdentity: rState.owner.relayIdentity32,
            reverseLimits: reverseLimitsBuf,
            forwardLimits: forwardLimitsBuf,
            candidateAuthorityCommitment: offerFields.candidateAuthorityCommitment
          })

          const cellIdPair = deriveCellIds(offerDigest)

          establishedHandle = createEstablishedState({
            initiator: false,
            generation: offerFields.generation,
            extensionIndex: offerFields.extensionIndex,
            contexts,
            completeOfferDigest: offerDigest,
            localId: cellIdPair.responderCellId,
            peerLocalId: cellIdPair.initiatorCellId,
            localIdentity: rState.owner.relayIdentity32,
            peerIdentity: offerFields.initiatorIdentity,
            branchId: offerFields.branchId,
            setupFailure,
            circuitId: offerFields.circuitId,
            responderAdvertisementDigest: rState.owner.advertisementDigest32,
            tailAdvertisement260: rState.owner.canonicalAdvertisement260,
            physicalChannel: physicalIssuer,
            tailSharedSecret,
            tailControlTranscript,
            successorProof378: null,
            forwardLimits: forwardLimitsBuf,
            reverseLimits: reverseLimitsBuf,
            ...branchLedgers,
            ownedLedgers: branchLedgers,
            clockIdentity: nativeBinding.clockIdentity,
            wallNow: nativeBinding.wallNow,
            monotonicNow: nativeBinding.monotonicNow,
            setTimer: nativeBinding.setTimer,
            clearTimer: nativeBinding.clearTimer,
            wireExpiresAt,
            localDeadline: establishedLocalDeadline
          })
          bindingOwnsAdmission = true
          const sendLedger = branchLedgers.sendLedger
          branchLedgers = null

          const runtime = rState.options.onEstablished(establishedHandle)
          const { isPeerM3RuntimeForLink } = require('./peer-m3-adjacency-runtime')
          if (
            rState.destroyed ||
            bindingState.destroyed ||
            !isPeerM3RuntimeForLink(runtime, establishedHandle)
          )
            unauthorized()

          row = {
            established,
            offerKey,
            offerDigest,
            offerWire432,
            replyPacket,
            acceptWire285: replyPacket.subarray(0, 285),
            offerFields,
            acceptFields,
            physicalIssuer,
            ephemeralSecretKey: ephemeralKeys.secretKey,
            sharedAdjacencySecret,
            reverseLimitsBuf,
            forwardLimitsBuf,
            nativeBinding,
            responderState: rState,
            sendLedger,
            receiveLedger,
            receivedOffers: 1,
            logicalRows,
            logicalKey,
            failSetup: setupFailure.fail,
            setupReleased: setupFailure.isReleased,
            attempts: 0,
            firstAttemptAt: 0n,
            unadmitted: false,
            establishedHandle,
            expired: false,
            deadline: localDeadline
          }
        } catch (err) {
          if (setupFailure) setupFailure.fail()
          releaseBranchLedgers(branchLedgers)
          if (establishedHandle) {
            try {
              destroyPeerEstablishedLink(establishedHandle)
            } catch {}
            establishedHandle = null
          } else {
            if (physicalIssuer && typeof physicalIssuer.destroy === 'function') {
              try {
                physicalIssuer.destroy()
              } catch {}
            }
            if (contexts) clearContexts(contexts)
            if (ephemeralKeys) clear(ephemeralKeys.secretKey)
            clear(sharedAdjacencySecret)
            clear(tailSharedSecret)
          }
          throw err
        } finally {
          if (ephemeralKeys) clear(ephemeralKeys.secretKey)
          clear(sharedAdjacencySecret)
          clear(tailSharedSecret)
        }

        rState.rows.set(offerKey, row)
        logicalRows.set(logicalKey, row)
        committed = true

        const replyToken = Object.freeze({
          kind: 'peerLinkReplyToken'
        })
        REPLY_TOKENS.set(replyToken, {
          row,
          established,
          consumed: false
        })
        return replyToken
      } finally {
        if (!committed) {
          logicalRows.delete(logicalKey)
          if (!bindingOwnsAdmission) setupFailure.release()
        }
      }
    },
    destroy() {
      if (bindingState.destroyed) return false
      bindingState.destroyed = true
      rState.bindings.delete(binding)
      RESPONDER_BINDINGS.delete(binding)
      return true
    }
  })

  RESPONDER_BINDINGS.set(binding, bindingState)
  rState.bindings.add(binding)
  return binding
}

function takePeerLinkReplyAttempt(reply, established) {
  const tokenState = isObject(reply) ? REPLY_TOKENS.get(reply) : null
  if (!tokenState || tokenState.consumed) unauthorized()
  if (tokenState.established !== established) unauthorized()
  const row = tokenState.row
  if (!row || row.expired || !row.replyPacket) unauthorized()
  const rState = row.responderState
  if (!rState || rState.destroyed) unauthorized()

  tokenState.consumed = true
  const nativeBinding = row.nativeBinding

  const nowMono = BigInt(nativeBinding.monotonicNow())
  if (
    nowMono >= row.deadline ||
    (nativeBinding.parentLocalDeadline && nowMono >= nativeBinding.parentLocalDeadline)
  ) {
    unauthorized()
  }

  row.attempts++
  if (row.attempts > MAX_ATTEMPTS) unauthorized()

  if (row.firstAttemptAt === 0n) {
    row.firstAttemptAt = nowMono
  } else if (nowMono - row.firstAttemptAt > MAX_ATTEMPT_WINDOW_MS) {
    unauthorized()
  }

  let completed = false
  const complete = (success) => {
    if (completed) return
    completed = true
  }

  const localDeadline =
    nativeBinding.parentLocalDeadline && nativeBinding.parentLocalDeadline < row.deadline
      ? nativeBinding.parentLocalDeadline
      : row.deadline

  const sendLedger = validateLedger(row.sendLedger)

  return Object.freeze({
    packet: row.replyPacket,
    sendLedger,
    clockIdentity: nativeBinding.clockIdentity,
    monotonicNow: nativeBinding.monotonicNow,
    localDeadline,
    complete
  })
}

module.exports = {
  authenticatePeerLinkReply,
  openPeerGuardLink,
  openPeerNeighborLink,
  createPeerLinkResponder,
  destroyPeerLinkResponder,
  takePeerLinkResponderBinding,
  takePeerLinkReplyAttempt,
  takePeerEstablishedLink,
  destroyPeerEstablishedLink,
  destroyTakenPeerEstablishedLink,
  takePeerEstablishedProof,
  takePeerM3AuthenticatedBranchBinding
}
