'use strict'

const b4a = require('b4a')
const sodium = require('sodium-universal')
const EMPTY_BUFFER = b4a.alloc(0)

const { PrivateRouteError } = require('./errors')
const { PEER_MESSAGE_ID, PEER_BRANCH_CLASS, PEER_PROTOCOL_VERSION } = require('./peer-protocol')
const {
  encodePeerTransport,
  decodePeerTransport,
  encodePeerLimits
} = require('./peer-transport-wire')
const {
  hashPeer,
  createPeerTailTranscript,
  derivePeerTailKeys,
  clearTailKeys,
  digestPeerLimits
} = require('./peer-crypto')
const {
  readPeerRelayOwner,
  verifyPeerAdvertisement,
  readVerifiedPeerAdvertisement
} = require('./peer-capability')
const {
  sealPeerContextFrame,
  openPeerContextFrame,
  encodePeerContextEnvelope,
  decodePeerContextEnvelope
} = require('./peer-m3-context')
const {
  isPeerM3Runtime,
  takePeerM3TailMaterial,
  takePeerM3ExtensionProof,
  sendPeerM3Payload,
  receivePeerM3Payload,
  adoptPeerEstablishedLink,
  createPeerM3ForwardingOwner,
  sendPeerM3ForwardingTailControl,
  destroyPeerM3ForwardingOwner,
  destroyPeerM3Runtime,
  authorizePeerM3FinalCarrierTake
} = require('./peer-m3-adjacency-runtime')
const { openPeerNeighborLink, destroyPeerEstablishedLink } = require('./peer-guard-link')
const {
  createFinalExitHandoff,
  consumeFinalExitHandoff,
  revokeFinalExitHandoff
} = require('./final-exit-handoff')
const {
  readPeerActiveCandidateFacts,
  discoverPeerCandidate,
  destroyPeerActiveCandidate
} = require('./peer-direct-bootstrap')
const {
  readPeerLedger,
  reservePeerMemory,
  takePeerMemory,
  releasePeerMemory
} = require('./peer-ledger')

const ADVERTISEMENT_DIGEST_DOMAIN = 'hyperdht-private-routes/m3/capability-advertisement-digest/v2'
const TAIL_CONTROL_TRANSCRIPT_DIGEST_DOMAIN =
  'hyperdht-private-routes/m3/tail-control/transcript-digest/v2'
const DISCOVER_REQUEST_DIGEST_DOMAIN = 'hyperdht-private-routes/m3/peer-discover-request-digest/v2'
const ROUTED_CANDIDATE_AUTHORITY_DOMAIN = 'hyperdht-private-routes/m3/routed-candidate-authority/v2'
const TAIL_READY_LABEL = b4a.from('hyperdht-private-routes/m3/tail-ready/v2')
const REDACTED_PROOF_LABEL = b4a.from('hyperdht-private-routes/m3/redacted-responder-proof/v2')

// Ratified setup owners: eight byte-identical attempts including the first, 250ms apart,
// clamped by the stored operation deadline (transport sections 3.3, 8.2, 9).
const MAX_ATTEMPTS = 8
const RETRY_INTERVAL_MS = 250
const OPERATION_TIMEOUT_MS = 2000n
// Owned timers are armed in bounded chunks; a long stored deadline rearms against the
// original deadline instead of overflowing one delay.
const MAX_TIMER_DELAY_MS = 2147483647n

const TAIL_CONTROL_CONTEXT_CLASS = 1
const DIRECTION_FORWARD = 0
const DIRECTION_REVERSE = 1

// Canonical tail-control transcript offsets (transport section 4.4, T290).
const T_TAIL_ROUTE_PUBLIC = 130
const T_ADVERTISEMENT_DIGEST = 162
const T_CLIENT_NONCE = 194
const T_TAIL_IDENTITY = 226

// Exact retained-byte geometry. Every entry is one auditable reservation kind; the
// role totals below are the exact sums this module reserves; a supplied pool that lacks
// capacity rejects at creation. Nothing here touches
// the separate fixed 680,000-byte listener startup pool.
const MEM = Object.freeze({
  // caller-pool reservations that survive session storage release
  MATERIAL: 32 + 290 + 2 * 32 + 2 * 16, // sharedSecret32 + T290 + finalize keys/prefixes = 418
  ADVERTISEMENT: 260, // adopted current-tail advertisement
  // caller-pool reservation for the moved branch/circuit identity buffers
  BRANCH_IDENTITY: 16 + 16,
  // session child-pool leaves
  CONTROL_KEYS: 2 * 32 + 2 * 16,
  DIGESTS: 3 * 32, // tailIdentity + tailAdvertisementDigest + tailControlTranscriptDigest
  CLIENT_NONCE: 32,
  // Only bytes retained across calls or async boundaries are accounted here. Imported
  // seal/open/hash/sign helpers own and erase their synchronous scratch internally.
  // readPeerRelayOwner copies: four top-level buffers plus its parsed advertisement
  // copies. Held only across owner validation, then cleared and released.
  RELAY_OWNER: 32 + 32 + 260 + 32 + (32 + 32 + 19 + 32),
  // responder readiness: readyNonce32 + frozen envelope1101. The canonical 282-byte wire
  // is erased inside the same call and is never retained.
  READINESS: 32 + 1101,
  // responder discover operation and its cached response: canonical request347 + nonce32 +
  // the imported candidate facts copies (advertisement260 + activeResponseDigest32 +
  // identity32 + endpoint19) live only across commit + frozen response envelope1101
  RESPONDER_DISCOVER: 347 + 32 + (260 + 32 + 32 + 19) + 1101,
  // the committed one-use candidate authority, retained under its own discover deadline
  // after the response owner has closed: advertisement260 + activeResponseDigest32 +
  // identity32 + endpoint19 + advertisement digest32 + authority nonce32 + commitment32
  RESPONDER_CANDIDATE: 260 + 32 + 32 + 19 + 32 + 32 + 32,
  // responder extend operation: canonical request524 + nonce32 + moved proof378 + frozen
  // EXTENDED envelope1101
  RESPONDER_EXTEND: 524 + 32 + 378 + 1101,
  // source discover operation: frozen request wire347 + nonce32 + frozen envelope1101 +
  // imported verified-advertisement copies407
  SOURCE_DISCOVER: 347 + 32 + 1101 + (260 + 32 + 32 + 32 + 19 + 32),
  // retained source candidate authority
  SOURCE_CANDIDATE: 260 + 32 + 32 + 32 + 32,
  // source extend operation: frozen request524 + frozen envelope1101 + ephemeral pair64 +
  // clientNonce32 + extensionNonce32 + both limits52 + successor digests96
  SOURCE_EXTEND: 524 + 1101 + 64 + 32 + 32 + 26 + 26 + 32 + 32 + 32
})

const SESSION_BASE_BYTES = MEM.CONTROL_KEYS + MEM.DIGESTS + MEM.CLIENT_NONCE

// Working capacity is the real lifecycle peak of concurrently held regions, never the sum
// of mutually exclusive owners. Source: discovery storage is released before extension
// begins, while the candidate authority spans both. Responder: the relay-owner scratch is
// released after owner validation and readiness is released on the first authenticated
// inbound frame, so only the discover cache, candidate authority and extension overlap.
const SOURCE_WORKING_BYTES =
  SESSION_BASE_BYTES + MEM.SOURCE_CANDIDATE + Math.max(MEM.SOURCE_DISCOVER, MEM.SOURCE_EXTEND)

// Responder: the relay-owner scratch closes after owner validation, readiness closes on
// the first authenticated inbound frame, and the discover response owner retires as soon
// as an EXTEND authenticates against its committed authority. Only the authority itself
// spans both operations.
const RESPONDER_WORKING_BYTES =
  SESSION_BASE_BYTES +
  Math.max(
    MEM.RELAY_OWNER,
    MEM.READINESS,
    MEM.RESPONDER_DISCOVER + MEM.RESPONDER_CANDIDATE,
    MEM.RESPONDER_CANDIDATE + MEM.RESPONDER_EXTEND
  )

// Required caller-pool capacity, derived from the exact regions this module reserves:
//   source   = SOURCE_WORKING_BYTES + BRANCH_IDENTITY + 2 * (MATERIAL + ADVERTISEMENT)
//   responder = RESPONDER_WORKING_BYTES + BRANCH_IDENTITY + MATERIAL + ADVERTISEMENT
// A source holds two material/advertisement sets across one atomic extension swap; a
// responder holds exactly one. The geometry stays private to this module: a short pool
// rejects at creation instead of silently growing.

const SESSIONS = new WeakMap()
const CANDIDATE_HANDLES = new WeakMap()

// Weak brands: provenance across stages (including spent/destroyed)
const TAIL_OWNERS = new WeakSet()
const DESTROYED_TAIL_OWNERS = new WeakSet()
const ISSUED_HANDOFFS = new WeakSet()
const SPENT_HANDOFFS = new WeakSet()

// Handoff tracking
const FINAL_EXIT_HANDOFFS = new WeakMap()
const FINAL_EXIT_HANDOFF_OWNERS = new WeakMap()
const FINAL_EXIT_TRANSFERS = new WeakMap()
const FINAL_EXIT_ACTIVATIONS = new WeakMap()
const FINAL_EXIT_PREPARE_CONSUMES = new WeakSet()

// Carrier authorizations
const CARRIER_AUTH_FACTS = new WeakMap()
const SPENT_CARRIER_AUTHS = new WeakSet()

const bufferByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
const bufferFill = Uint8Array.prototype.fill

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function unauthorized() {
  throw PrivateRouteError.UNAUTHORIZED()
}

function replay() {
  throw PrivateRouteError.ERR_REPLAY()
}

function authentication() {
  throw PrivateRouteError.ERR_AUTHENTICATION()
}

function destroyed() {
  throw PrivateRouteError.ERR_DESTROYED()
}

function unavailable() {
  throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
}

function safeObject(val) {
  return val !== null && typeof val === 'object' && !Array.isArray(val)
}

function bufferLength(val) {
  try {
    return b4a.isBuffer(val) ? bufferByteLength.call(val) : -1
  } catch {
    return -1
  }
}

function fixed(val, size) {
  return bufferLength(val) === size
}

function isZero32(buffer) {
  try {
    if (typeof sodium.sodium_is_zero === 'function') {
      return sodium.sodium_is_zero(buffer)
    }
  } catch {}
  for (let i = 0; i < 32; i++) {
    if (buffer[i] !== 0) return false
  }
  return true
}

function clear(buf) {
  try {
    if (b4a.isBuffer(buf)) bufferFill.call(buf, 0)
  } catch {}
}

function copy(buf) {
  const len = bufferLength(buf)
  if (len < 0) invalid()
  const out = b4a.allocUnsafeSlow(len)
  out.set(buf, 0)
  return out
}

function randomBytes(size) {
  const buf = b4a.allocUnsafeSlow(size)
  sodium.randombytes_buf(buf)
  return buf
}

function generateX25519KeyPair() {
  const publicKey = b4a.allocUnsafeSlow(32)
  const secretKey = b4a.allocUnsafeSlow(32)
  sodium.crypto_box_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

function diffieHellman(secretKey, remotePublicKey) {
  if (!fixed(secretKey, 32) || !fixed(remotePublicKey, 32)) invalid()
  if (isZero32(remotePublicKey)) invalid()
  const out = b4a.allocUnsafeSlow(32)
  try {
    sodium.crypto_scalarmult(out, secretKey, remotePublicKey)
    if (isZero32(out)) invalid()
    return out
  } catch (err) {
    clear(out)
    invalid()
  }
}

function u64be(value) {
  const buf = b4a.allocUnsafeSlow(8)
  for (let i = 7; i >= 0; i--) {
    buf[i] = Number(value & 0xffn)
    value >>= 8n
  }
  return buf
}

function minBigInt(a, b) {
  return a < b ? a : b
}

function buildSignatureInput(messageId, label, body) {
  const labelLen = bufferLength(label)
  const bodyLen = bufferLength(body)
  if (labelLen <= 0 || bodyLen < 0) invalid()
  const headerOffset = 2 + labelLen
  const input = b4a.allocUnsafe(headerOffset + 8 + bodyLen)
  input[0] = labelLen >>> 8
  input[1] = labelLen & 0xff
  input.set(label, 2)
  input[headerOffset] = 0
  input[headerOffset + 1] = 0
  input[headerOffset + 2] = 0
  input[headerOffset + 3] = PEER_PROTOCOL_VERSION
  input[headerOffset + 4] = messageId >>> 8
  input[headerOffset + 5] = messageId & 0xff
  input[headerOffset + 6] = bodyLen >>> 8
  input[headerOffset + 7] = bodyLen & 0xff
  input.set(body, headerOffset + 8)
  return input
}

function computeCandidateCommitment(
  tailControlTranscriptDigest,
  discoverRequestWire,
  completeAdvertisement,
  activeResponseDigest,
  candidateAuthorityNonce,
  verifiedAt,
  expiresAt
) {
  const discoverRequestDigest = hashPeer(DISCOVER_REQUEST_DIGEST_DOMAIN, [discoverRequestWire])
  const advertisementDigest = hashPeer(ADVERTISEMENT_DIGEST_DOMAIN, [completeAdvertisement])
  try {
    return hashPeer(ROUTED_CANDIDATE_AUTHORITY_DOMAIN, [
      tailControlTranscriptDigest,
      discoverRequestDigest,
      advertisementDigest,
      activeResponseDigest,
      candidateAuthorityNonce,
      u64be(verifiedAt),
      u64be(expiresAt)
    ])
  } finally {
    clear(discoverRequestDigest)
    clear(advertisementDigest)
  }
}

function validateParentLedger(ledger) {
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

// Erases every byte copy readPeerRelayOwner returned, including its parsed advertisement
// copies, so no imported metadata outlives its reservation.
function clearRelayOwnerFacts(ownerInfo) {
  if (!safeObject(ownerInfo)) return
  clear(ownerInfo.relayIdentity32)
  clear(ownerInfo.routeEncryptionPublicKey32)
  clear(ownerInfo.canonicalAdvertisement260)
  clear(ownerInfo.advertisementDigest32)
  const parsed = ownerInfo.parsedAdvertisement
  if (!safeObject(parsed)) return
  clear(parsed.relayIdentity32)
  clear(parsed.currentDhtNodeId32)
  clear(parsed.reachableEndpoint19)
  clear(parsed.routeEncryptionPublicKey32)
}

// Ratified role/mask pairing: v2 advertisements carry mask9 for guard/safety and mask11
// for terminal (transport section 1.7). A tail at extensionIndex0 discovers the safety
// role, a tail at extensionIndex1 discovers the terminal role, and supplied mode is the
// safety tail's private-terminal path only (section 3.1). The mask is therefore derived
// from the owned extension index, not accepted as a caller-selected {9,11} whitelist.
function requiredSuccessorMask(extensionIndex) {
  if (extensionIndex === 0) return 9
  if (extensionIndex === 1) return 11
  invalid()
}

function requiredSuccessorRole(extensionIndex) {
  if (extensionIndex === 0) return 1
  if (extensionIndex === 1) return 2
  invalid()
}

function validateDiscoverShape(extensionIndex, mode, requestedMask, suppliedAdvertisement260) {
  if (mode !== 1 && mode !== 2) return false
  if (requestedMask !== requiredSuccessorMask(extensionIndex)) return false
  if (mode === 1) {
    if (suppliedAdvertisement260 !== null) return false
  } else {
    // supplied mode exists only for the safety tail's private terminal selection
    if (extensionIndex !== 1) return false
    if (!fixed(suppliedAdvertisement260, 260)) return false
  }
  return true
}

// Brand predicates: provenance across stages (including spent/destroyed)
function isPeerTailControlOwner(owner) {
  return safeObject(owner) && (TAIL_OWNERS.has(owner) || DESTROYED_TAIL_OWNERS.has(owner))
}

function isPeerTailFinalExitHandoff(handoff) {
  return safeObject(handoff) && (ISSUED_HANDOFFS.has(handoff) || SPENT_HANDOFFS.has(handoff))
}

// ---------------------------------------------------------------------------
// Finite storage accounting
// ---------------------------------------------------------------------------

function reserveRegion(pool, kind, bytes) {
  return reservePeerMemory(pool, kind, bytes)
}

function releaseRegion(handle) {
  if (!handle) return false
  try {
    return releasePeerMemory(handle)
  } catch {
    return false
  }
}

function releaseSessionRegions(state) {
  const regions = state.regions
  if (!regions) return
  for (const name of Object.keys(regions)) {
    if (regions[name]) {
      releaseRegion(regions[name])
      regions[name] = null
    }
  }
}

// ---------------------------------------------------------------------------
// Ordered tail-control frame carriage (context class 1)
// ---------------------------------------------------------------------------

function controlKeyFor(keys, direction) {
  return direction === DIRECTION_FORWARD ? keys.tailControlForwardKey : keys.tailControlReverseKey
}

function controlNoncePrefixFor(keys, direction) {
  return direction === DIRECTION_FORWARD
    ? keys.tailControlForwardNoncePrefix
    : keys.tailControlReverseNoncePrefix
}

// Freezes one canonical envelope for one logical counter. Ordered tail-control retries
// resend these exact bytes; they never reseal under a fresh counter (section 9: the
// fresh-wrapper-counter rule belongs to finalization class5 only).
function sealControlEnvelope(state, keys, direction, counter, payload) {
  let frame = null
  try {
    frame = sealPeerContextFrame({
      contextClass: TAIL_CONTROL_CONTEXT_CLASS,
      branchId: state.branchId,
      circuitId: state.circuitId,
      generation: state.generation,
      direction,
      counter,
      key: controlKeyFor(keys, direction),
      noncePrefix: controlNoncePrefixFor(keys, direction),
      payload
    })
    return encodePeerContextEnvelope(TAIL_CONTROL_CONTEXT_CLASS, frame)
  } finally {
    clear(frame)
  }
}

// Returns an owned canonical wire copy, or null when the envelope is not an
// authenticated tail-control frame at the exact expected logical counter. A null result
// leaves every receive/replay counter unchanged, so duplicates and foreign frames are
// dropped without consuming the ordered slot.
function openControlEnvelope(state, keys, direction, counter, envelope) {
  let decoded = null
  let opened = null
  try {
    decoded = decodePeerContextEnvelope(envelope)
    if (decoded.contextClass !== TAIL_CONTROL_CONTEXT_CLASS) return null
    opened = openPeerContextFrame(
      {
        contextClass: TAIL_CONTROL_CONTEXT_CLASS,
        branchId: state.branchId,
        circuitId: state.circuitId,
        generation: state.generation,
        direction,
        counter,
        key: controlKeyFor(keys, direction),
        noncePrefix: controlNoncePrefixFor(keys, direction)
      },
      decoded.frame
    )
    return copy(opened.payload)
  } catch {
    return null
  } finally {
    if (decoded) clear(decoded.frame)
    if (opened) clear(opened.plaintext)
  }
}

// ---------------------------------------------------------------------------
// Owned send trains
// ---------------------------------------------------------------------------

// One setup object, one frozen envelope, one eight-attempt counter, one timer train and
// one stored deadline. `auto` drives the timer train (requests and responder readiness);
// duplicate-triggered caches spend the same counter through attempt() without creating a
// timer (sections 3.2 and 9).
function createSendTrain(state, envelope, deadline, options = {}) {
  const auto = options.auto === true

  const train = {
    envelope,
    deadline,
    attemptsRemaining: MAX_ATTEMPTS,
    settled: false,
    // terminal closure cause. 'attempts' means every one of the eight byte-identical
    // attempts was dispatched AND every dispatch actually settled successfully; any
    // rejection, deadline, or stop wins instead.
    closedBy: null,
    timerId: null,
    expired: null,
    // first attempt's dispatch promise, so an owner can gate publication on it
    first: null,
    // resolves exactly once, when this frozen owner's bounded window closes
    drained: null,
    attempt: null,
    stop: null,
    sendAfterTake: null,
    holdDeadline: null
  }
  const retired = () => train.settled || (state.destroyed && train.sendAfterTake === null)

  // every dispatched-but-unsettled attempt; an earlier overlapping send may still reject
  const pendingAttempts = new Set()
  let resolveDrained = null
  let drainSettled = false
  train.drained = new Promise((resolve) => {
    resolveDrained = resolve
  })

  const settleDrain = (cause) => {
    if (drainSettled) return
    drainSettled = true
    train.closedBy = cause
    const resolve = resolveDrained
    resolveDrained = null
    if (resolve) resolve()
  }

  // 'attempts' closure requires the whole window spent and every dispatch fulfilled
  const drainIfSpent = () => {
    if (drainSettled || train.attemptsRemaining > 0 || pendingAttempts.size > 0) return
    settleDrain('attempts')
  }

  let rejectExpiry = null
  train.expired = new Promise((_, reject) => {
    rejectExpiry = reject
  })
  // never surfaces as an unhandled rejection when nobody races it
  train.expired.catch(() => {})

  const clearTimer = () => {
    if (train.timerId !== null) {
      const timer = train.timerId
      train.timerId = null
      try {
        state.clearTimer(timer)
      } catch {}
    }
  }

  const expire = () => {
    if (train.settled) return
    train.settled = true
    clearTimer()
    settleDrain('expired')
    if (rejectExpiry) {
      const reject = rejectExpiry
      rejectExpiry = null
      reject(PrivateRouteError.ERR_PRIVACY_UNAVAILABLE())
    }
  }

  const fail = () => {
    // a late rejection from an already-transferred or retired owner never tears down the
    // session it no longer owns
    if (train.settled) return
    settleDrain('failed')
    expire()
  }

  // Spends exactly one of the eight attempts and returns that attempt's send promise, so
  // an owner can gate publication on actual dispatch. Failed or uncertain sends stay
  // spent. Returns null when no attempt was available.
  train.attempt = () => {
    if (
      retired() ||
      (!state.runtime &&
        train.sendAfterTake === null &&
        !(options.forwarding === true && state.forwardingOwner))
    )
      return null
    if (train.attemptsRemaining <= 0) return null
    let now = 0n
    try {
      now = state.monotonicNow()
    } catch (err) {
      fail(err)
      return null
    }
    if (now >= train.deadline) {
      expire()
      return null
    }
    train.attemptsRemaining--
    let pending = null
    try {
      pending =
        train.sendAfterTake !== null
          ? train.sendAfterTake()
          : options.forwarding === true && state.forwardingOwner
            ? sendPeerM3ForwardingTailControl(state.forwardingOwner, train.envelope)
            : sendPeerM3Payload(state.runtime, train.envelope)
    } catch (err) {
      fail(err)
      return null
    }
    const settled = Promise.resolve(pending).then((sent) => {
      if (sent !== true) unavailable()
      return true
    })
    pendingAttempts.add(settled)
    settled.then(
      () => {
        pendingAttempts.delete(settled)
        drainIfSpent()
      },
      (err) => {
        pendingAttempts.delete(settled)
        fail(err)
      }
    )
    if (!train.first) train.first = settled
    return settled
  }

  const arm = (delayMs, deadlineOnly = false) => {
    if (retired()) return
    clearTimer()
    if (retired()) return
    let arming = true
    let firedSynchronously = false
    let timer = null
    try {
      timer = state.setTimer(() => {
        if (arming) {
          firedSynchronously = true
          return
        }
        if (train.timerId !== timer) return
        train.timerId = null
        if (retired()) return
        if (deadlineOnly) {
          armDeadlineOnly()
          return
        }
        let now = 0n
        try {
          now = state.monotonicNow()
        } catch (err) {
          fail(err)
          return
        }
        if (now >= train.deadline) {
          expire()
          return
        }
        if (train.attemptsRemaining > 0) train.attempt()
        schedule()
      }, delayMs)
    } catch (err) {
      arming = false
      fail(err)
      return
    }
    arming = false
    if (firedSynchronously || retired() || timer == null) {
      if (timer != null) {
        try {
          state.clearTimer(timer)
        } catch {}
      }
      fail()
      return
    }
    train.timerId = timer
  }

  // After the eighth attempt the owner keeps its stored deadline armed so the full
  // response window is honoured before exhaustion (blocker 2).
  function schedule() {
    if (train.settled) return
    let now = 0n
    try {
      now = state.monotonicNow()
    } catch (err) {
      fail(err)
      return
    }
    if (now >= train.deadline) {
      expire()
      return
    }
    // the window's attempts are all dispatched: closure waits for their settlement while
    // the stored deadline keeps guarding the response
    drainIfSpent()
    const remaining = train.deadline - now
    const interval = train.attemptsRemaining > 0 ? BigInt(RETRY_INTERVAL_MS) : remaining
    const waitMs = Number(minBigInt(minBigInt(remaining, interval), MAX_TIMER_DELAY_MS))
    if (waitMs <= 0) {
      expire()
      return
    }
    arm(waitMs)
  }

  // Deadline-only owner for duplicate-triggered caches: no retry is ever generated, but
  // the frozen envelope still expires on its stored deadline instead of living forever.
  function armDeadlineOnly() {
    if (train.settled) return
    let now = 0n
    try {
      now = state.monotonicNow()
    } catch (err) {
      fail(err)
      return
    }
    if (now >= train.deadline) {
      expire()
      return
    }
    const remaining = train.deadline - now
    const waitMs = Number(minBigInt(remaining, MAX_TIMER_DELAY_MS))
    if (waitMs <= 0) {
      expire()
      return
    }
    arm(waitMs, true)
  }

  train.stop = () => {
    if (train.settled) return false
    train.settled = true
    clearTimer()
    settleDrain('stopped')
    rejectExpiry = null
    return true
  }

  // Stops retransmission but keeps the stored deadline as the surviving expiry owner.
  train.holdDeadline = () => {
    if (train.settled) return false
    train.attemptsRemaining = 0
    schedule()
    return true
  }

  if (auto) {
    train.first = train.attempt()
    schedule()
  } else {
    // duplicate-triggered cache: no retry timer is created, but the stored deadline still
    // owns this frozen envelope's expiry
    armDeadlineOnly()
  }

  return train
}

// ---------------------------------------------------------------------------
// Session construction
// ---------------------------------------------------------------------------

function splitTailKeys(derived) {
  return {
    control: {
      tailControlForwardKey: derived.tailControlForwardKey,
      tailControlReverseKey: derived.tailControlReverseKey,
      tailControlForwardNoncePrefix: derived.tailControlForwardNoncePrefix,
      tailControlReverseNoncePrefix: derived.tailControlReverseNoncePrefix
    },
    finalize: {
      finalizeForwardKey: derived.finalizeForwardKey,
      finalizeReverseKey: derived.finalizeReverseKey,
      finalizeForwardNoncePrefix: derived.finalizeForwardNoncePrefix,
      finalizeReverseNoncePrefix: derived.finalizeReverseNoncePrefix
    }
  }
}

function createPeerTailControl(runtime, options = {}) {
  if (!isPeerM3Runtime(runtime)) invalid()
  if (!safeObject(options)) invalid()

  const pool = options.memoryPool
  // Mandatory finite live peer memory pool: no auto-created or unbounded fallback.
  if (!pool) invalid()

  let adoptionReservation = null
  let identityReservation = null
  let adoptionPool = null
  let advertisementReservation = null
  let materialReservation = null
  let signPeerObject = null
  let ownerInfo = null
  let sessionReservation = null
  let sessionPool = null
  let tailMaterial = null
  let derivedKeys = null
  let state = null
  let published = false

  try {
    // Storage for every byte this owner adopts or derives is reserved before the move.
    adoptionReservation = reserveRegion(pool, 'peer-tail-control/adoption', MEM.MATERIAL)
    adoptionPool = takePeerMemory(adoptionReservation)
    reserveRegion(adoptionPool, 'peer-tail-control/shared-secret', 32)
    reserveRegion(adoptionPool, 'peer-tail-control/tail-transcript', 290)
    reserveRegion(adoptionPool, 'peer-tail-control/finalize-keys', MEM.CONTROL_KEYS)
    materialReservation = adoptionReservation
    identityReservation = reserveRegion(
      pool,
      'peer-tail-control/adoption-identity',
      MEM.BRANCH_IDENTITY
    )
    advertisementReservation = reserveRegion(
      pool,
      'peer-tail-control/tail-advertisement',
      MEM.ADVERTISEMENT
    )

    tailMaterial = takePeerM3TailMaterial(runtime)
    if (!tailMaterial) invalid()
    if (
      !fixed(tailMaterial.tailSharedSecret, 32) ||
      !fixed(tailMaterial.tailControlTranscript, 290) ||
      !fixed(tailMaterial.tailAdvertisement260, 260) ||
      tailMaterial.branchClass !== PEER_BRANCH_CLASS.PEER
    ) {
      invalid()
    }

    const initiator = tailMaterial.initiator === true
    const extensionIndex = tailMaterial.extensionIndex
    if (extensionIndex !== 0 && extensionIndex !== 1 && extensionIndex !== 2) invalid()
    if (initiator && extensionIndex !== 0) unauthorized()

    sessionReservation = reserveRegion(
      pool,
      'peer-tail-control/session',
      initiator ? SOURCE_WORKING_BYTES : RESPONDER_WORKING_BYTES
    )
    sessionPool = takePeerMemory(sessionReservation)

    const regions = {
      controlKeys: reserveRegion(sessionPool, 'peer-tail-control/control-keys', MEM.CONTROL_KEYS),
      digests: reserveRegion(sessionPool, 'peer-tail-control/tail-digests', MEM.DIGESTS),
      clientNonce: reserveRegion(sessionPool, 'peer-tail-control/client-nonce', MEM.CLIENT_NONCE),
      relayOwner: null,
      readiness: null,
      discover: null,
      candidate: null,
      extend: null
    }

    const transcript = tailMaterial.tailControlTranscript
    const tailIdentity = copy(transcript.subarray(T_TAIL_IDENTITY, T_TAIL_IDENTITY + 32))
    const clientNonce = copy(transcript.subarray(T_CLIENT_NONCE, T_CLIENT_NONCE + 32))
    const tailAdvertisementDigest = hashPeer(ADVERTISEMENT_DIGEST_DOMAIN, [
      tailMaterial.tailAdvertisement260
    ])
    const transcriptDigest = hashPeer(TAIL_CONTROL_TRANSCRIPT_DIGEST_DOMAIN, [transcript])

    // The transcript binds the current tail's own advertisement digest; a transcript that
    // does not match the authenticated advertisement moved out of the runtime is not this
    // adjacency's tail material.
    if (
      !b4a.equals(
        transcript.subarray(T_ADVERTISEMENT_DIGEST, T_ADVERTISEMENT_DIGEST + 32),
        tailAdvertisementDigest
      )
    ) {
      authentication()
    }

    if (!initiator) {
      const relayOwner = options.relayOwner
      if (!relayOwner) invalid()
      regions.relayOwner = reserveRegion(
        sessionPool,
        'peer-tail-control/relay-owner',
        MEM.RELAY_OWNER
      )
      ownerInfo = readPeerRelayOwner(relayOwner)

      // Blocker 9: a genuine but unrelated relay owner cannot sign this branch's
      // readiness or discovery. Identity, advertisement, digest and clock domain must all
      // match the consumed runtime metadata before any signature is produced.
      if (
        !b4a.equals(ownerInfo.relayIdentity32, tailIdentity) ||
        !b4a.equals(
          ownerInfo.routeEncryptionPublicKey32,
          transcript.subarray(T_TAIL_ROUTE_PUBLIC, T_TAIL_ROUTE_PUBLIC + 32)
        ) ||
        !b4a.equals(ownerInfo.canonicalAdvertisement260, tailMaterial.tailAdvertisement260) ||
        !b4a.equals(ownerInfo.advertisementDigest32, tailAdvertisementDigest)
      ) {
        unauthorized()
      }
      if (!ownerInfo.clockIdentity || ownerInfo.clockIdentity !== tailMaterial.clockIdentity) {
        unauthorized()
      }

      // Only the callback-free signer is retained; every imported byte copy is erased and
      // its reservation released here. Identity and digests already live in the
      // separately reserved session regions.
      signPeerObject = ownerInfo.signPeerObject
      clearRelayOwnerFacts(ownerInfo)
      ownerInfo = null
      releaseRegion(regions.relayOwner)
      regions.relayOwner = null

      if (extensionIndex < 2) {
        if (!options.neighborPool || !options.runtimeAuthority) invalid()
        validateParentLedger(options.sendLedger)
        validateParentLedger(options.receiveLedger)
        validateParentLedger(options.teardownSendLedger)
        validateParentLedger(options.teardownReceiveLedger)
      }
    }

    derivedKeys = derivePeerTailKeys(tailMaterial.tailSharedSecret, transcript)
    const split = splitTailKeys(derivedKeys)

    const session = Object.freeze({})
    TAIL_OWNERS.add(session)

    state = {
      session,
      runtime,
      initiator,
      branchClass: tailMaterial.branchClass,
      generation: tailMaterial.generation,
      extensionIndex,
      // adopted identity buffers are moved, never re-copied
      circuitId: tailMaterial.circuitId,
      branchId: tailMaterial.branchId,
      originalParentLocalDeadline: tailMaterial.localDeadline,
      wireExpiresAt: tailMaterial.wireExpiresAt,
      localDeadline: tailMaterial.localDeadline,
      clockIdentity: tailMaterial.clockIdentity,
      wallNow: tailMaterial.wallNow,
      monotonicNow: tailMaterial.monotonicNow,
      setTimer: tailMaterial.setTimer,
      clearTimer: tailMaterial.clearTimer,

      // exactly one live material set per session
      sharedSecret: tailMaterial.tailSharedSecret,
      transcript,
      controlKeys: split.control,
      finalizeKeys: split.finalize,
      tailIdentity,
      clientNonce,
      tailAdvertisement260: tailMaterial.tailAdvertisement260,
      tailAdvertisementDigest,
      transcriptDigest,

      phase: 'TAIL_READY',
      txCounter: 0n,
      rxCounter: 0n,

      pool,
      sessionReservation,
      sessionPool,
      materialReservation,
      identityReservation,
      advertisementReservation,
      regions,

      issuedHandoff: null,
      finalRuntimeTaken: false,
      finalExitStage: null,
      finalExitActivationOwner: null,
      finalExitActivationMaterial: null,
      finalExitGeneration: 0,

      pendingCandidate: null,
      pendingExtend: null,
      installing: false,
      destroyed: false,

      relayOwner: options.relayOwner || null,
      signPeerObject,
      neighborPool: options.neighborPool || null,
      runtimeAuthority: options.runtimeAuthority || null,
      onFinalReady: typeof options.onFinalReady === 'function' ? options.onFinalReady : null,
      ledgers: {
        sendLedger: options.sendLedger || null,
        receiveLedger: options.receiveLedger || null,
        teardownSendLedger: options.teardownSendLedger || null,
        teardownReceiveLedger: options.teardownReceiveLedger || null
      },

      readinessTrain: null,
      transferredReadinessTrain: null,
      readyNonce: null,
      forwardingOwner: null,
      pumping: false,
      discoverOperation: null,
      extendOperation: null,
      storedCandidate: null,
      pendingCandidateHandle: null
    }

    SESSIONS.set(session, state)
    published = true

    if (!initiator) {
      if (extensionIndex === 2) {
        // terminal: no further tail extension exists, its tail material is the final
        // material and the ownership chain starts at FINAL_EXIT_READY
        state.phase = 'FINAL_EXIT_READY'
        state.finalExitStage = 'FINAL_EXIT_READY'
      }

      if (extensionIndex === 1 || extensionIndex === 2) {
        startResponderReadiness(state)
      }

      if (extensionIndex < 2) {
        startResponderReceivePump(state)
      }
    }

    return session
  } catch (err) {
    // imported relay-owner copies never outlive this call, on any path
    clearRelayOwnerFacts(ownerInfo)
    ownerInfo = null
    if (published && state) {
      destroyPeerTailControl(state.session)
    } else {
      if (derivedKeys) clearTailKeys(derivedKeys)
      if (tailMaterial) {
        clear(tailMaterial.tailSharedSecret)
        clear(tailMaterial.tailControlTranscript)
        clear(tailMaterial.tailAdvertisement260)
        clear(tailMaterial.circuitId)
        clear(tailMaterial.branchId)
      }
      if (sessionPool) releaseRegion(sessionPool)
      else releaseRegion(sessionReservation)
      if (adoptionPool) releaseRegion(adoptionPool)
      else releaseRegion(adoptionReservation)
      releaseRegion(identityReservation)
      releaseRegion(advertisementReservation)
    }
    try {
      destroyPeerM3Runtime(runtime)
    } catch {}
    throw err
  }
}

// ---------------------------------------------------------------------------
// Responder readiness (owned eight-attempt train)
// ---------------------------------------------------------------------------

function buildReadyEnvelope(state) {
  const readyNonce = randomBytes(32)
  let readyWire = null
  let signature = null
  try {
    const bodyFields = {
      branchClass: PEER_BRANCH_CLASS.PEER,
      branchId: state.branchId,
      circuitId: state.circuitId,
      generation: state.generation,
      extensionIndex: state.extensionIndex,
      tailControlTranscriptDigest: state.transcriptDigest,
      tailIdentity: state.tailIdentity,
      tailAdvertisementDigest: state.tailAdvertisementDigest,
      clientNonce: state.clientNonce,
      readyNonce,
      expiresAt: state.wireExpiresAt
    }

    readyWire = encodePeerTransport(PEER_MESSAGE_ID.PEER_TAIL_READY_V2, bodyFields, b4a.alloc(64))
    const canonicalBody = readyWire.subarray(8, readyWire.byteLength - 64)
    signature = state.signPeerObject(PEER_MESSAGE_ID.PEER_TAIL_READY_V2, canonicalBody)
    readyWire.set(signature, readyWire.byteLength - 64)

    // readiness is the first reverse frame under this tail's own keys
    const envelope = sealControlEnvelope(
      state,
      state.controlKeys,
      DIRECTION_REVERSE,
      state.txCounter,
      readyWire
    )
    state.txCounter++
    state.readyNonce = readyNonce
    return envelope
  } catch (err) {
    clear(readyNonce)
    throw err
  } finally {
    clear(readyWire)
    clear(signature)
  }
}

// TAIL_READY answers no tail-control request and cannot be duplicate-triggered: the
// predecessor's forwarding publication opens asynchronously, so readiness owns a real
// eight-attempt/250ms train bounded by the stored local deadline (section 8.2 budgets
// TAIL_READY1 8 and TAIL_READY2 8).
function startResponderReadiness(state) {
  state.regions.readiness = reserveRegion(
    state.sessionPool,
    'peer-tail-control/readiness',
    MEM.READINESS
  )

  const envelope = buildReadyEnvelope(state)
  let train = null
  try {
    // Clock and scheduler hooks may retire the owner before its train is published.
    const deadline = minBigInt(state.localDeadline, state.monotonicNow() + OPERATION_TIMEOUT_MS)
    if (state.destroyed) return
    train = createSendTrain(state, envelope, deadline, { auto: true })
  } finally {
    if (state.destroyed || train === null) {
      if (train) train.stop()
      clear(envelope)
    }
  }
  if (state.destroyed) return
  state.readinessTrain = train
  train.releaseReadiness = () => {
    const region = train.readinessRegion
    const parentPool = train.readinessParentPool
    train.readinessRegion = null
    train.readinessParentPool = null
    clear(train.envelope)
    train.envelope = null
    clear(train.readinessNonce)
    train.readinessNonce = null
    if (state.transferredReadinessTrain === train) state.transferredReadinessTrain = null
    train.stop()
    releaseRegion(region)
    releaseRegion(parentPool)
  }

  // Before transfer, the tail owns readiness failure. After transfer, Native owns the
  // unchanged train and its failure/expiry cleanup; this former owner cannot revoke it.
  train.expired.catch(() => {
    if (state.destroyed || state.readinessTrain !== train) return
    destroyPeerTailControl(state.session)
  })

  // a readiness owner that could not dispatch its first attempt is already dead: no
  // extension index may keep a live session behind it
  if (!train.first) {
    destroyPeerTailControl(state.session)
    return
  }

  if (state.extensionIndex !== 2 || !state.onFinalReady) return

  // the terminal's host is told only after readiness actually dispatched and this exact
  // owner is still live; a rejected first attempt fails ownership instead of publishing
  train.first.then(
    () => {
      if (state.destroyed || state.readinessTrain !== train || !state.runtime) return
      notifyFinalReady(state)
    },
    () => {
      destroyPeerTailControl(state.session)
    }
  )
}

// Blocker 8: the callback is owned. Rechecked liveness before notification, thenable
// results adopted, and failures surface as owner destruction instead of a swallowed
// rejection.
function notifyFinalReady(state) {
  const callback = state.onFinalReady
  state.onFinalReady = null
  if (!callback || state.destroyed) return

  let result = null
  try {
    result = callback(state.session)
  } catch {
    destroyPeerTailControl(state.session)
    return
  }

  if (result && typeof result.then === 'function') {
    Promise.resolve(result).catch(() => {
      destroyPeerTailControl(state.session)
    })
  }
}

function stopResponderReadiness(state) {
  const train = state.readinessTrain
  const nonce = state.readyNonce
  const region = state.regions.readiness
  state.readinessTrain = null
  state.readyNonce = null
  state.regions.readiness = null
  if (train) {
    train.stop()
    clear(train.envelope)
    train.envelope = null
  }
  clear(nonce)
  releaseRegion(region)
}

// ---------------------------------------------------------------------------
// Responder receive pump
// ---------------------------------------------------------------------------

function startResponderReceivePump(state) {
  if (state.pumping) return
  state.pumping = true

  const pump = () => {
    if (state.destroyed || !state.runtime || state.forwardingOwner || state.installing) {
      state.pumping = false
      return
    }
    receivePeerM3Payload(state.runtime)
      .then((envelope) => {
        try {
          if (state.destroyed) {
            state.pumping = false
            return
          }
          handleResponderIncomingEnvelope(state, envelope)
        } finally {
          clear(envelope)
        }
        if (state.forwardingOwner || state.destroyed || !state.runtime || state.installing) {
          state.pumping = false
          return
        }
        pump()
      })
      .catch(() => {
        state.pumping = false
        // runtime loss or expiry ends this owner; forwarding publication owns its own legs
        if (!state.destroyed && !state.forwardingOwner) {
          destroyPeerTailControl(state.session)
        }
      })
  }

  pump()
}

function handleResponderIncomingEnvelope(state, envelope) {
  let canonicalWire = openControlEnvelope(
    state,
    state.controlKeys,
    DIRECTION_FORWARD,
    state.rxCounter,
    envelope
  )
  let duplicate = false
  if (canonicalWire === null && state.rxCounter > 0n) {
    canonicalWire = openControlEnvelope(
      state,
      state.controlKeys,
      DIRECTION_FORWARD,
      state.rxCounter - 1n,
      envelope
    )
    duplicate = canonicalWire !== null
    if (duplicate) {
      const previous = state.discoverOperation || state.extendOperation
      if (!previous || !b4a.equals(previous.canonicalRequestBytes, canonicalWire)) {
        clear(canonicalWire)
        return
      }
    }
  }
  // Only the exact retained previous request may spend its original reply attempts.
  if (canonicalWire === null) return

  let obj = null
  try {
    obj = decodePeerTransport(canonicalWire)
  } catch {
    clear(canonicalWire)
    // authenticated frame occupying the expected ordered slot with non-canonical bytes
    destroyPeerTailControl(state.session)
    return
  }

  if (!duplicate) {
    state.rxCounter++
    // Authenticated forward traffic acknowledges this tail's readiness.
    stopResponderReadiness(state)
  }

  if (obj.messageId === PEER_MESSAGE_ID.PEER_DISCOVER_REQUEST_V2) {
    handleResponderDiscoverRequest(state, obj.fields, canonicalWire)
  } else if (obj.messageId === PEER_MESSAGE_ID.PEER_EXTEND_REQUEST_V2) {
    handleResponderExtendRequest(state, obj.fields, canonicalWire)
  } else {
    clear(canonicalWire)
    destroyPeerTailControl(state.session)
  }
}

// ---------------------------------------------------------------------------
// Responder DISCOVER
// ---------------------------------------------------------------------------

function retireStoredCandidate(state, destroyHandle) {
  const candidate = state.storedCandidate
  if (!candidate) return
  state.storedCandidate = null
  candidate.retired = true
  clearOperationDeadline(state, candidate)
  if (destroyHandle && candidate.handle) {
    // idempotent: a handle already taken by the successor link simply reports false
    try {
      destroyPeerActiveCandidate(candidate.handle)
    } catch {}
  }
  clear(candidate.completeAdvertisement)
  clear(candidate.activeResponseDigest)
  clear(candidate.identity32)
  clear(candidate.endpoint19)
  clear(candidate.advertisementDigest)
  clear(candidate.candidateAuthorityNonce)
  clear(candidate.candidateAuthorityCommitment)
  if (state.regions.candidate) {
    releaseRegion(state.regions.candidate)
    state.regions.candidate = null
  }
}

// One stored-deadline owner per responder operation or candidate authority: a host
// callback that never completes cannot retain ownership past its stored deadline. Returns
// false when the owner already expired synchronously, so the caller aborts instead of
// continuing with retired state.
function armOperationDeadline(state, operation, deadline, onExpiry) {
  operation.deadline = deadline
  const tick = () => {
    if (state.destroyed || operation.retired) return
    let now = 0n
    try {
      now = state.monotonicNow()
    } catch {
      onExpiry()
      return
    }
    if (state.destroyed || operation.retired) return
    if (now >= deadline) {
      onExpiry()
      return
    }
    const waitMs = Number(minBigInt(deadline - now, MAX_TIMER_DELAY_MS))
    if (waitMs <= 0) {
      onExpiry()
      return
    }
    let arming = true
    let firedSynchronously = false
    let timer = null
    try {
      timer = state.setTimer(() => {
        if (arming) {
          firedSynchronously = true
          return
        }
        if (operation.deadlineTimer !== timer) return
        operation.deadlineTimer = null
        tick()
      }, waitMs)
    } catch {
      arming = false
      onExpiry()
      return
    }
    arming = false
    if (firedSynchronously || operation.retired || state.destroyed || timer == null) {
      if (timer != null) {
        try {
          state.clearTimer(timer)
        } catch {}
      }
      if (!operation.retired && !state.destroyed) onExpiry()
      return
    }
    operation.deadlineTimer = timer
  }
  tick()
  return operation.deadlineTimer !== null && !operation.retired && !state.destroyed
}

function clearOperationDeadline(state, operation) {
  if (!operation || operation.deadlineTimer === null || operation.deadlineTimer === undefined) {
    return
  }
  const timer = operation.deadlineTimer
  operation.deadlineTimer = null
  try {
    state.clearTimer(timer)
  } catch {}
}

// The one-shot closer for an adopted external discovery operation. Retirement, expiry and
// normal settlement all route through it, so the requester operation closes exactly once
// even when the session is destroyed while the callback never settles.
function closeDiscoverOperation(operation) {
  if (!operation) return
  const pending = operation.discovery
  operation.discovery = null
  if (pending && typeof pending.close === 'function') {
    try {
      pending.close()
    } catch {}
  }
}

// Blocker 6: every non-commit path retires the operation instead of wedging a permanent
// PENDING owner, and a dead owner destroys the actual stored candidate.
function retireDiscoverOperation(state) {
  const operation = state.discoverOperation
  if (!operation) return
  operation.retired = true
  clearOperationDeadline(state, operation)
  if (operation.train) operation.train.stop()
  closeDiscoverOperation(operation)
  clear(operation.canonicalRequestBytes)
  clear(operation.requestNonce)
  clear(operation.responseEnvelope)
  operation.canonicalRequestBytes = null
  operation.requestNonce = null
  operation.responseEnvelope = null
  operation.train = null
  state.discoverOperation = null
  if (state.regions.discover) {
    releaseRegion(state.regions.discover)
    state.regions.discover = null
  }
}

function handleResponderDiscoverRequest(state, req, rawWire) {
  let adopted = false
  try {
    if (state.extensionIndex >= 2 || state.forwardingOwner) return
    // one operation at a time: an in-flight or committed extension owns this branch
    if (state.extendOperation || state.installing) return
    if (!fixed(req.requestNonce, 32) || isZero32(req.requestNonce)) return
    if (
      !validateDiscoverShape(
        state.extensionIndex,
        req.mode,
        req.requestedMask,
        req.mode === 2 ? req.suppliedAdvertisement : null
      )
    ) {
      return
    }
    if (req.suppliedAdvertisementLength !== (req.mode === 2 ? 260 : 0)) return
    if (!fixed(req.randomTarget, 32)) return
    if (typeof req.expiresAt !== 'bigint' || req.expiresAt <= 0n) return

    const previous = state.discoverOperation
    if (previous) {
      if (previous.status === 'PENDING') return
      if (b4a.equals(previous.requestNonce, req.requestNonce)) {
        // exact replay reuses the stored response and its remaining original attempts;
        // changed bytes conflict without resampling or extending the operation
        if (
          previous.status === 'COMMITTED' &&
          b4a.equals(previous.canonicalRequestBytes, rawWire) &&
          previous.train
        ) {
          previous.train.attempt()
        }
        return
      }
    }

    // A live one-use authority is never churned by a different request, including after
    // its response owner has already closed on the bounded setup window.
    if (state.storedCandidate && !state.storedCandidate.consumed) return

    // first admission: one paired sample proving the request fits the authenticated bound
    const wall = state.wallNow()
    const mono = state.monotonicNow()
    const admissionWireExpiresAt = minBigInt(req.expiresAt, state.wireExpiresAt)
    if (
      wall >= req.expiresAt ||
      req.expiresAt > state.wireExpiresAt ||
      mono >= state.localDeadline
    ) {
      return
    }
    // stored once at admission and never resampled: the setup owner's window is the
    // request projection clamped by the parent deadline and this owner's 2s operation bound
    const admissionLocalDeadline = minBigInt(
      state.localDeadline,
      mono + (admissionWireExpiresAt - wall)
    )
    const operationLocalDeadline = minBigInt(admissionLocalDeadline, mono + OPERATION_TIMEOUT_MS)

    const neighborDiscoveryModule = require('./peer-native-neighbors')
    if (typeof neighborDiscoveryModule.createPeerNativeNeighborDiscovery !== 'function') return

    if (state.discoverOperation) retireDiscoverOperation(state)
    retireStoredCandidate(state, true)

    // storage is reserved before this owner adopts a discovery operation
    state.regions.discover = reserveRegion(
      state.sessionPool,
      'peer-tail-control/responder-discover',
      MEM.RESPONDER_DISCOVER
    )

    let discovery = null
    try {
      discovery = neighborDiscoveryModule.createPeerNativeNeighborDiscovery(state.neighborPool, {
        mode: req.mode,
        requestedMask: req.requestedMask,
        randomTarget32: req.randomTarget,
        suppliedAdvertisement260: req.mode === 2 ? req.suppliedAdvertisement : null,
        clockIdentity: state.clockIdentity,
        wireExpiresAt: admissionWireExpiresAt,
        localDeadline: operationLocalDeadline
      })
    } catch {
      releaseRegion(state.regions.discover)
      state.regions.discover = null
      return
    }

    const operation = {
      status: 'PENDING',
      requestNonce: copy(req.requestNonce),
      canonicalRequestBytes: rawWire,
      requestedMask: req.requestedMask,
      requestExpiresAt: req.expiresAt,
      admissionLocalDeadline,
      operationLocalDeadline,
      responseEnvelope: null,
      train: null,
      discovery,
      retired: false,
      deadlineTimer: null,
      deadline: 0n
    }
    state.discoverOperation = operation
    adopted = true

    // the stored request deadline owns this operation even if the discovery callback never
    // completes. A committed one-use authority is NOT retired here: its own stored
    // discover deadline governs its later EXTEND validity.
    if (
      !armOperationDeadline(state, operation, operationLocalDeadline, () => {
        if (state.discoverOperation !== operation) {
          closeDiscoverOperation(operation)
          return
        }
        if (operation.status === 'PENDING') retireStoredCandidate(state, true)
        retireDiscoverOperation(state)
      })
    ) {
      // retirement already closed the adopted discovery operation
      return
    }

    Promise.resolve()
      .then(() =>
        discoverPeerCandidate(discovery.transport, {
          ledger: discovery.ledger,
          requestedMask: operation.requestedMask,
          randomTarget: req.randomTarget,
          maximumResults: 1
        })
      )
      .then(
        (candidateHandle) => {
          if (
            state.destroyed ||
            state.discoverOperation !== operation ||
            operation.status !== 'PENDING' ||
            state.forwardingOwner
          ) {
            try {
              destroyPeerActiveCandidate(candidateHandle)
            } catch {}
            if (state.discoverOperation === operation) {
              retireDiscoverOperation(state)
            }
            return
          }

          commitResponderDiscover(state, operation, candidateHandle)
        },
        () => {
          if (state.discoverOperation === operation) {
            retireDiscoverOperation(state)
          }
        }
      )
      .catch(() => {
        if (state.discoverOperation === operation) {
          retireDiscoverOperation(state)
        }
      })
      .finally(() => closeDiscoverOperation(operation))
  } finally {
    if (!adopted) clear(rawWire)
  }
}

// Blocker 4: owned clocks are sampled after the actual authenticated discovery; the
// commitment, wire expiry and local deadline all derive from that one paired sample and
// the real candidate facts.
function commitResponderDiscover(state, operation, candidateHandle) {
  let facts = null
  let candidateAuthorityNonce = null
  let respWire = null
  let stored = null

  try {
    facts = readPeerActiveCandidateFacts(candidateHandle)

    const wall = state.wallNow()
    const mono = state.monotonicNow()

    const expiresAt = minBigInt(
      minBigInt(operation.requestExpiresAt, facts.wireExpiresAt),
      state.wireExpiresAt
    )
    if (wall >= expiresAt) unavailable()

    const projected = mono + (expiresAt - wall)
    const discoverLocalDeadline = minBigInt(
      minBigInt(state.localDeadline, operation.admissionLocalDeadline),
      minBigInt(facts.localDeadline, projected)
    )
    if (mono >= discoverLocalDeadline) unavailable()

    if (facts.kind !== 'candidate') unauthorized()
    if (facts.clockIdentity !== state.clockIdentity) unauthorized()

    // the committed authority is accounted before any authority byte is allocated, and
    // separately from the response owner, because it stays valid for EXTEND after the
    // response window closes
    state.regions.candidate = reserveRegion(
      state.sessionPool,
      'peer-tail-control/responder-candidate',
      MEM.RESPONDER_CANDIDATE
    )

    const verifiedAt = wall
    candidateAuthorityNonce = randomBytes(32)
    const advertisementDigest = hashPeer(ADVERTISEMENT_DIGEST_DOMAIN, [facts.completeAdvertisement])
    const candidateAuthorityCommitment = computeCandidateCommitment(
      state.transcriptDigest,
      operation.canonicalRequestBytes,
      facts.completeAdvertisement,
      facts.activeResponseDigest,
      candidateAuthorityNonce,
      verifiedAt,
      expiresAt
    )

    stored = {
      handle: candidateHandle,
      completeAdvertisement: copy(facts.completeAdvertisement),
      activeResponseDigest: copy(facts.activeResponseDigest),
      identity32: copy(facts.identity32),
      endpoint19: copy(facts.endpoint19),
      epoch: facts.epoch,
      advertisementDigest,
      candidateAuthorityNonce,
      candidateAuthorityCommitment,
      verifiedAt,
      expiresAt,
      discoverLocalDeadline,
      consumed: false,
      retired: false,
      deadlineTimer: null,
      deadline: 0n
    }

    respWire = encodePeerTransport(PEER_MESSAGE_ID.PEER_DISCOVER_RESPONSE_V2, {
      requestNonce: operation.requestNonce,
      currentTailIdentity: state.tailIdentity,
      completeAdvertisement: stored.completeAdvertisement,
      activeResponseDigest: stored.activeResponseDigest,
      candidateAuthorityNonce,
      verifiedAt,
      expiresAt,
      candidateAuthorityCommitment
    })

    const envelope = sealControlEnvelope(
      state,
      state.controlKeys,
      DIRECTION_REVERSE,
      state.txCounter,
      respWire
    )
    state.txCounter++

    // commit the one-use authority and the frozen cached response before attempt one
    operation.responseEnvelope = envelope
    operation.status = 'COMMITTED'
    state.storedCandidate = stored
    const committedCandidate = stored
    candidateAuthorityNonce = null
    stored = null

    // the one-use authority lives under its own stored discover deadline, independent of
    // the response owner's bounded retry window
    if (
      !armOperationDeadline(state, committedCandidate, discoverLocalDeadline, () => {
        if (state.storedCandidate !== committedCandidate) return
        retireStoredCandidate(state, true)
      })
    ) {
      // the authority expired before it could be answered for
      retireDiscoverOperation(state)
      return
    }

    // duplicate-triggered cache: one frozen envelope under one eight-attempt counter and
    // this owner's stored setup window
    operation.train = createSendTrain(
      state,
      envelope,
      minBigInt(discoverLocalDeadline, operation.operationLocalDeadline)
    )
    // an unsent cache is never treated as a committed response
    if (!operation.train.attempt()) invalid()
  } catch {
    if (stored) {
      clear(stored.completeAdvertisement)
      clear(stored.activeResponseDigest)
      clear(stored.identity32)
      clear(stored.endpoint19)
      clear(stored.advertisementDigest)
      clear(stored.candidateAuthorityCommitment)
    }
    clear(candidateAuthorityNonce)
    try {
      destroyPeerActiveCandidate(candidateHandle)
    } catch {}
    // an uncommitted authority never keeps its reservation
    if (!state.storedCandidate && state.regions.candidate) {
      releaseRegion(state.regions.candidate)
      state.regions.candidate = null
    }
    if (state.storedCandidate) retireStoredCandidate(state, false)
    retireDiscoverOperation(state)
  } finally {
    if (facts) {
      clear(facts.completeAdvertisement)
      clear(facts.activeResponseDigest)
      clear(facts.identity32)
      clear(facts.endpoint19)
    }
    clear(respWire)
  }
}

// ---------------------------------------------------------------------------
// Responder EXTEND
// ---------------------------------------------------------------------------

function retireExtendOperation(state) {
  const operation = state.extendOperation
  if (!operation) return
  operation.retired = true
  clearOperationDeadline(state, operation)
  if (operation.train) operation.train.stop()
  clear(operation.canonicalRequestBytes)
  clear(operation.extensionNonce)
  clear(operation.extendedEnvelope)
  operation.canonicalRequestBytes = null
  operation.extensionNonce = null
  operation.extendedEnvelope = null
  operation.train = null
  state.extendOperation = null
  if (state.regions.extend) {
    releaseRegion(state.regions.extend)
    state.regions.extend = null
  }
  if (!state.destroyed && !state.installing && state.runtime && !state.forwardingOwner) {
    startResponderReceivePump(state)
  }
}

function handleResponderExtendRequest(state, req, rawWire) {
  let adopted = false
  try {
    if (state.extensionIndex >= 2 || state.forwardingOwner || state.installing) return
    if (req.branchClass !== PEER_BRANCH_CLASS.PEER) return
    if (!b4a.equals(req.branchId, state.branchId)) return
    if (!b4a.equals(req.circuitId, state.circuitId)) return
    if (req.generation !== state.generation) return
    if (req.extensionIndex !== state.extensionIndex + 1) return
    if (req.advertisementLength !== 260) return

    const previous = state.extendOperation
    if (previous) {
      if (previous.status === 'PENDING') return
      if (b4a.equals(previous.extensionNonce, req.extensionNonce)) {
        if (
          previous.status === 'COMMITTED' &&
          b4a.equals(previous.canonicalRequestBytes, rawWire) &&
          previous.train
        ) {
          previous.train.attempt()
        }
        return
      }
      return
    }

    const candidate = state.storedCandidate
    if (!candidate || candidate.consumed) return

    const wall = state.wallNow()
    const mono = state.monotonicNow()
    if (wall >= candidate.expiresAt || mono >= candidate.discoverLocalDeadline) {
      retireStoredCandidate(state, true)
      retireDiscoverOperation(state)
      return
    }

    if (!b4a.equals(req.advertisement, candidate.completeAdvertisement)) return
    if (!b4a.equals(req.candidateAuthorityCommitment, candidate.candidateAuthorityCommitment)) {
      return
    }
    if (isZero32(req.candidateAuthorityCommitment)) return

    // the committed authority has been spent by an authenticated EXTEND: the discover
    // response owner retires before extension storage is reserved
    retireDiscoverOperation(state)

    state.regions.extend = reserveRegion(
      state.sessionPool,
      'peer-tail-control/responder-extend',
      MEM.RESPONDER_EXTEND
    )

    // stored once at admission: the candidate/request lifetime clamped by this owner's
    // bounded setup window. Never resampled after asynchronous establishment.
    const extendLocalDeadline = minBigInt(
      candidate.discoverLocalDeadline,
      mono + OPERATION_TIMEOUT_MS
    )

    const operation = {
      status: 'PENDING',
      extensionNonce: copy(req.extensionNonce),
      canonicalRequestBytes: rawWire,
      extendedEnvelope: null,
      train: null,
      localDeadline: extendLocalDeadline,
      retired: false,
      deadlineTimer: null,
      deadline: 0n
    }
    state.extendOperation = operation
    adopted = true
    state.installing = true

    // the stored extension deadline owns this operation even if the neighbour-link
    // callback never completes
    if (
      !armOperationDeadline(state, operation, extendLocalDeadline, () => {
        if (state.extendOperation !== operation) return
        state.installing = false
        retireStoredCandidate(state, operation.status === 'PENDING')
        retireExtendOperation(state)
      })
    ) {
      // expiry already destroyed the authority and retired this operation
      return
    }

    // the one-use routed authority is consumed before successor LINK_OFFER
    candidate.consumed = true

    // A synchronous rejection from this boundary is owned exactly like an asynchronous
    // one: the consumed authority is destroyed and the operation retires.
    // Owned failure path, scoped to this exact operation: a late rejection can never
    // retire a newer admission.
    const failExtension = () => {
      if (state.extendOperation !== operation) return
      state.installing = false
      retireStoredCandidate(state, true)
      retireExtendOperation(state)
    }

    let linking = null
    try {
      linking = openPeerNeighborLink({
        neighborPool: state.neighborPool,
        activeCandidate: candidate.handle,
        relayOwner: state.relayOwner,
        advertisement: candidate.completeAdvertisement,
        branchId: req.branchId,
        circuitId: req.circuitId,
        generation: req.generation,
        extensionIndex: req.extensionIndex,
        clientTailEphemeralPublicKey: req.clientTailEphemeralPublicKey,
        clientNonce: req.clientNonce,
        payloadParametersDigest: req.payloadParametersDigest,
        forwardLimits: req.currentTailForwardLimits,
        reverseLimits: req.successorReverseLimits,
        candidateAuthorityCommitment32: req.candidateAuthorityCommitment,
        sendLedger: state.ledgers.sendLedger,
        receiveLedger: state.ledgers.receiveLedger,
        teardownSendLedger: state.ledgers.teardownSendLedger,
        teardownReceiveLedger: state.ledgers.teardownReceiveLedger,
        operationDeadline: operation.localDeadline
      })
    } catch (err) {
      failExtension(err)
      return
    }

    Promise.resolve(linking).then(
      (establishedHandle) =>
        publishResponderExtension(state, operation, candidate, establishedHandle),
      failExtension
    )
  } finally {
    if (!adopted) clear(rawWire)
  }
}

// Blocker 5: late completion and every post-adoption failure close the actual handle,
// runtime and forwarder exactly once and never touch the unrelated predecessor sibling.
function publishResponderExtension(state, operation, candidate, establishedHandle) {
  if (
    state.destroyed ||
    state.extendOperation !== operation ||
    operation.status !== 'PENDING' ||
    !state.runtime
  ) {
    try {
      destroyPeerEstablishedLink(establishedHandle)
    } catch {}
    state.installing = false
    if (state.extendOperation === operation) retireExtendOperation(state)
    return
  }

  let successorRuntime = null
  let proofResult = null
  let extendedWire = null
  let envelope = null

  try {
    successorRuntime = adoptPeerEstablishedLink(state.runtimeAuthority, establishedHandle)
    proofResult = takePeerM3ExtensionProof(successorRuntime)
    if (!fixed(proofResult.successorProof378, 378)) invalid()

    extendedWire = encodePeerTransport(PEER_MESSAGE_ID.PEER_EXTENDED_V2, {
      branchClass: PEER_BRANCH_CLASS.PEER,
      branchId: state.branchId,
      circuitId: state.circuitId,
      generation: state.generation,
      extensionIndex: state.extensionIndex + 1,
      responderAdvertisementDigest: candidate.advertisementDigest,
      proofLength: 378,
      completeProof: proofResult.successorProof378,
      extensionNonce: operation.extensionNonce
    })

    envelope = sealControlEnvelope(
      state,
      state.controlKeys,
      DIRECTION_REVERSE,
      state.txCounter,
      extendedWire
    )
    state.txCounter++
  } catch (err) {
    if (successorRuntime) {
      try {
        destroyPeerM3Runtime(successorRuntime)
      } catch {}
    } else {
      try {
        destroyPeerEstablishedLink(establishedHandle)
      } catch {}
    }
    if (proofResult) clear(proofResult.successorProof378)
    clear(extendedWire)
    clear(envelope)
    state.installing = false
    retireStoredCandidate(state, false)
    retireExtendOperation(state)
    return
  } finally {
    if (proofResult) clear(proofResult.successorProof378)
    clear(extendedWire)
  }

  operation.extendedEnvelope = envelope
  operation.status = 'COMMITTED'

  // Every post-adoption step stays inside one owned failure path: the successor runtime is
  // closed exactly once and the predecessor sibling is preserved.
  let train = null
  let dispatched = null
  try {
    // The first EXTENDED dispatch precedes forwarding. Its remaining frozen retries
    // retain the original deadline and send through the moved predecessor owner.
    const responseDeadline = operation.localDeadline
    train = createSendTrain(state, envelope, responseDeadline, { forwarding: true })
    operation.train = train
    dispatched = train.attempt()
    if (!dispatched) throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  } catch {
    if (train) train.stop()
    try {
      destroyPeerM3Runtime(successorRuntime)
    } catch {}
    state.installing = false
    retireStoredCandidate(state, false)
    retireExtendOperation(state)
    return
  }

  return dispatched.then(
    () => {
      // Only an observed dispatch may publish the successor.
      let beforeDeadline = false
      try {
        const now = state.monotonicNow()
        beforeDeadline = typeof now === 'bigint' && now < operation.localDeadline
      } catch {}
      if (
        !beforeDeadline ||
        state.destroyed ||
        state.extendOperation !== operation ||
        !state.runtime
      ) {
        try {
          destroyPeerM3Runtime(successorRuntime)
        } catch {}
        state.installing = false
        retireStoredCandidate(state, false)
        if (state.extendOperation === operation) retireExtendOperation(state)
        return
      }

      let forwardingOwner = null
      try {
        forwardingOwner = createPeerM3ForwardingOwner(state.runtime, successorRuntime, {
          onPreviousPayload: (payload) => {
            const pending = state.extendOperation
            if (state.destroyed || !pending || pending.status !== 'COMMITTED') return false
            const request = openControlEnvelope(
              state,
              state.controlKeys,
              DIRECTION_FORWARD,
              state.rxCounter - 1n,
              payload
            )
            if (request === null) return false
            try {
              if (pending.train && b4a.equals(request, pending.canonicalRequestBytes)) {
                pending.train.attempt()
              }
              return true
            } finally {
              clear(request)
            }
          }
        })
      } catch {
        // Failure may precede the move; retire both still-owned runtimes as well.
        state.installing = false
        try {
          destroyPeerM3Runtime(successorRuntime)
        } catch {}
        retireStoredCandidate(state, false)
        retireExtendOperation(state)
        destroyPeerTailControl(state.session)
        return
      }

      state.forwardingOwner = forwardingOwner
      state.runtime = null
      state.installing = false
      state.phase = 'FORWARDING'
      // The forwarder owns carriage; this owner retains only its bounded cached reply.
      stopResponderReadiness(state)
      retireStoredCandidate(state, false)
    },
    () => {
      // dispatch failed while the predecessor is still owned: close the successor exactly
      // once and leave no forwarder behind
      try {
        destroyPeerM3Runtime(successorRuntime)
      } catch {}
      state.installing = false
      retireStoredCandidate(state, false)
      if (state.extendOperation === operation) retireExtendOperation(state)
    }
  )
}

// ---------------------------------------------------------------------------
// Descriptor and teardown
// ---------------------------------------------------------------------------

function readPeerTailControl(session) {
  const state = safeObject(session) ? SESSIONS.get(session) : null
  if (!state || state.destroyed) destroyed()

  return Object.freeze({
    initiator: state.initiator,
    phase: state.phase,
    protocolVersion: PEER_PROTOCOL_VERSION,
    branchClass: PEER_BRANCH_CLASS.PEER,
    branchId: copy(state.branchId),
    circuitId: copy(state.circuitId),
    generation: state.generation,
    extensionIndex: state.extensionIndex,
    tailIdentity: copy(state.tailIdentity),
    tailAdvertisementDigest: copy(state.tailAdvertisementDigest),
    tailControlTranscriptDigest: copy(state.transcriptDigest),
    wireExpiresAt: state.wireExpiresAt,
    localDeadline: state.localDeadline,
    clockIdentity: state.clockIdentity,
    advertisement: copy(state.tailAdvertisement260),
    wallNow: state.wallNow,
    monotonicNow: state.monotonicNow,
    setTimer: state.setTimer,
    clearTimer: state.clearTimer
  })
}

function destroyPeerTailControl(session) {
  const state = safeObject(session) ? SESSIONS.get(session) : null
  if (!state || state.destroyed) return false

  state.destroyed = true
  DESTROYED_TAIL_OWNERS.add(session)
  SESSIONS.delete(session)

  stopResponderReadiness(state)
  clear(state.readyNonce)
  state.readyNonce = null

  retireDiscoverOperation(state)
  retireExtendOperation(state)
  retireStoredCandidate(state, true)

  // an issued but unconsumed handoff is revoked through the shared owner so its moved
  // material is erased and its reservation released instead of outliving this session
  if (state.issuedHandoff && FINAL_EXIT_HANDOFFS.has(state.issuedHandoff)) {
    try {
      revokeFinalExitHandoff(session)
    } catch {}
  }

  retireSourceCandidate(state, state.pendingCandidateHandle)

  if (state.forwardingOwner) {
    try {
      destroyPeerM3ForwardingOwner(state.forwardingOwner)
    } catch {}
    state.forwardingOwner = null
    state.runtime = null
  }

  // material still owned here (no handoff moved it out) is erased and its reservation
  // released; material already moved into a handoff/activation stays accounted there
  if (state.materialReservation) {
    clearTailKeys(state.finalizeKeys)
    clear(state.sharedSecret)
    clear(state.transcript)
    releaseRegion(state.materialReservation)
    state.materialReservation = null
  }
  state.sharedSecret = null
  state.transcript = null
  state.finalizeKeys = null

  clearTailKeys(state.controlKeys)
  state.controlKeys = null
  clear(state.tailAdvertisement260)
  clear(state.tailIdentity)
  clear(state.tailAdvertisementDigest)
  clear(state.transcriptDigest)
  clear(state.clientNonce)
  clear(state.circuitId)
  clear(state.branchId)

  releaseSessionRegions(state)
  if (state.sessionPool) {
    const readiness = state.transferredReadinessTrain
    if (readiness && readiness.sendAfterTake !== null) {
      // All other session leaves are cleared above. Keep their parent reservation
      // behind the moved readiness leaf until Native discharges that final duty.
      readiness.readinessParentPool = state.sessionPool
    } else {
      releaseRegion(state.sessionPool)
    }
    state.sessionPool = null
    state.sessionReservation = null
  }
  if (state.identityReservation) {
    releaseRegion(state.identityReservation)
    state.identityReservation = null
  }
  if (state.advertisementReservation) {
    releaseRegion(state.advertisementReservation)
    state.advertisementReservation = null
  }

  if (state.runtime) {
    try {
      destroyPeerM3Runtime(state.runtime)
    } catch {}
    state.runtime = null
  }

  return true
}

// ---------------------------------------------------------------------------
// Source DISCOVER
// ---------------------------------------------------------------------------

// Waits for one authenticated tail-control frame at the exact expected ordered counter.
// Frames that do not authenticate at that counter are duplicates/foreign traffic and are
// dropped with state unchanged; an authenticated frame carrying the wrong object is a
// fatal protocol conflict for the caller to handle.
function awaitControlObject(state, keys, direction, counter, expectedMessageId, train) {
  const attempt = () => {
    let claimed = false
    const receiving = receivePeerM3Payload(state.runtime).then((envelope) => {
      if (claimed) {
        clear(envelope)
        return null
      }
      claimed = true
      return envelope
    })
    const expiry = train.expired.catch((err) => {
      claimed = true
      throw err
    })
    return Promise.race([receiving, expiry]).then((envelope) => {
      let canonicalWire = null
      try {
        if (state.destroyed) destroyed()
        let now
        try {
          now = state.monotonicNow()
        } catch {
          unavailable()
        }
        if (state.destroyed) destroyed()
        if (typeof now !== 'bigint' || now >= train.deadline || train.settled) unavailable()
        canonicalWire = openControlEnvelope(state, keys, direction, counter, envelope)
      } finally {
        clear(envelope)
      }
      if (canonicalWire === null) return attempt()

      let obj = null
      try {
        obj = decodePeerTransport(canonicalWire)
      } catch (err) {
        clear(canonicalWire)
        authentication()
      }
      if (obj.messageId !== expectedMessageId) {
        clear(canonicalWire)
        authentication()
      }
      return { canonicalWire, obj }
    })
  }

  return attempt()
}

// One live source candidate authority per session. Retirement erases every retained copy,
// drops the handle, cancels its deadline owner and releases its reservation.
function retireSourceCandidate(state, handle) {
  const record = safeObject(handle) ? CANDIDATE_HANDLES.get(handle) : null
  if (record) {
    CANDIDATE_HANDLES.delete(handle)
    record.retired = true
    clearOperationDeadline(state, record)
    clear(record.advertisement)
    clear(record.advertisementDigest)
    clear(record.relayIdentity32)
    clear(record.routeEncryptionPublicKey32)
    clear(record.candidateAuthorityCommitment)
  }
  if (state.pendingCandidateHandle === handle) state.pendingCandidateHandle = null
  if (state.regions.candidate) {
    releaseRegion(state.regions.candidate)
    state.regions.candidate = null
  }
  return !!record
}

function discoverPeerTailCandidate(session, request) {
  const state = safeObject(session) ? SESSIONS.get(session) : null
  if (!state || state.destroyed || !state.initiator) invalid()
  if (state.extensionIndex >= 2 || state.phase !== 'TAIL_READY') invalid()
  if (state.pendingCandidate !== null || state.pendingExtend !== null) invalid()
  // exactly one live candidate authority: a second discovery would orphan the first
  if (state.pendingCandidateHandle !== null) invalid()
  if (state.installing) invalid()
  if (!safeObject(request)) invalid()

  const { mode, requestedMask, randomTarget32, suppliedAdvertisement260, expiresAt } = request
  const supplied =
    suppliedAdvertisement260 === undefined || suppliedAdvertisement260 === null
      ? null
      : suppliedAdvertisement260
  if (!validateDiscoverShape(state.extensionIndex, mode, requestedMask, supplied)) invalid()
  if (!fixed(randomTarget32, 32)) invalid()
  if (typeof expiresAt !== 'bigint' || expiresAt <= 0n) invalid()

  const wall = state.wallNow()
  const mono = state.monotonicNow()
  if (
    wall >= expiresAt ||
    expiresAt > state.wireExpiresAt ||
    wall >= state.wireExpiresAt ||
    mono >= state.localDeadline
  ) {
    invalid()
  }

  state.regions.discover = reserveRegion(
    state.sessionPool,
    'peer-tail-control/source-discover',
    MEM.SOURCE_DISCOVER
  )

  const requestNonce = randomBytes(32)
  let reqWire = null
  let envelope = null
  try {
    reqWire = encodePeerTransport(PEER_MESSAGE_ID.PEER_DISCOVER_REQUEST_V2, {
      requestNonce,
      mode,
      requestedMask,
      randomTarget: randomTarget32,
      expiresAt,
      suppliedAdvertisementLength: mode === 2 ? 260 : 0,
      suppliedAdvertisement: mode === 2 ? supplied : EMPTY_BUFFER
    })
    envelope = sealControlEnvelope(
      state,
      state.controlKeys,
      DIRECTION_FORWARD,
      state.txCounter,
      reqWire
    )
    state.txCounter++
  } catch (err) {
    clear(requestNonce)
    clear(reqWire)
    clear(envelope)
    releaseRegion(state.regions.discover)
    state.regions.discover = null
    throw err
  }

  state.pendingCandidate = true

  const operationDeadline = minBigInt(state.localDeadline, mono + OPERATION_TIMEOUT_MS)
  const train = createSendTrain(state, envelope, operationDeadline, { auto: true })

  const cleanup = () => {
    train.stop()
    clear(requestNonce)
    clear(reqWire)
    clear(envelope)
    if (state.regions.discover) {
      releaseRegion(state.regions.discover)
      state.regions.discover = null
    }
  }

  return awaitControlObject(
    state,
    state.controlKeys,
    DIRECTION_REVERSE,
    state.rxCounter,
    PEER_MESSAGE_ID.PEER_DISCOVER_RESPONSE_V2,
    train
  )
    .then(({ canonicalWire, obj }) => {
      try {
        state.rxCounter++
        state.pendingCandidate = null

        const fields = obj.fields
        if (!b4a.equals(fields.requestNonce, requestNonce)) authentication()
        if (!b4a.equals(fields.currentTailIdentity, state.tailIdentity)) authentication()
        if (isZero32(fields.candidateAuthorityCommitment)) authentication()

        const expectedCommitment = computeCandidateCommitment(
          state.transcriptDigest,
          reqWire,
          fields.completeAdvertisement,
          fields.activeResponseDigest,
          fields.candidateAuthorityNonce,
          fields.verifiedAt,
          fields.expiresAt
        )
        let commitmentMatch = false
        try {
          commitmentMatch = b4a.equals(fields.candidateAuthorityCommitment, expectedCommitment)
        } finally {
          clear(expectedCommitment)
        }
        if (!commitmentMatch) authentication()

        if (mode === 2 && !b4a.equals(fields.completeAdvertisement, supplied)) authentication()

        let verifiedAd = null
        let adInfo = null
        let candidateRecord = null
        try {
          verifiedAd = verifyPeerAdvertisement(fields.completeAdvertisement, {
            expectedRole: requiredSuccessorRole(state.extensionIndex),
            expectedCapabilityMask: requestedMask,
            clockIdentity: state.clockIdentity,
            wallNow: state.wallNow,
            monotonicNow: state.monotonicNow
          })
          adInfo = readVerifiedPeerAdvertisement(verifiedAd)

          const currWall = state.wallNow()
          const currMono = state.monotonicNow()
          const maxExpiresAt = minBigInt(
            minBigInt(expiresAt, adInfo.expiresAt),
            state.wireExpiresAt
          )
          if (
            fields.verifiedAt >= fields.expiresAt ||
            fields.expiresAt > maxExpiresAt ||
            currWall >= fields.expiresAt
          ) {
            authentication()
          }

          const projected = currMono + (fields.expiresAt - currWall)
          const candidateLocalDeadline = minBigInt(state.localDeadline, projected)
          if (currMono >= candidateLocalDeadline) unavailable()

          state.regions.candidate = reserveRegion(
            state.sessionPool,
            'peer-tail-control/source-candidate',
            MEM.SOURCE_CANDIDATE
          )

          candidateRecord = {
            session,
            advertisement: copy(fields.completeAdvertisement),
            advertisementDigest: copy(adInfo.advertisementDigest32),
            relayIdentity32: copy(adInfo.relayIdentity32),
            routeEncryptionPublicKey32: copy(adInfo.routeEncryptionPublicKey32),
            candidateAuthorityCommitment: copy(fields.candidateAuthorityCommitment),
            advertisementExpiresAt: adInfo.expiresAt,
            verifiedAt: fields.verifiedAt,
            expiresAt: fields.expiresAt,
            candidateLocalDeadline,
            consumed: false,
            handle: null,
            retired: false,
            deadlineTimer: null,
            deadline: 0n
          }
        } finally {
          if (adInfo) {
            clear(adInfo.canonicalBytes260)
            clear(adInfo.advertisementDigest32)
            clear(adInfo.relayIdentity32)
            clear(adInfo.currentDhtNodeId32)
            clear(adInfo.reachableEndpoint19)
            clear(adInfo.routeEncryptionPublicKey32)
          }
        }

        const candidateHandle = Object.freeze({})
        CANDIDATE_HANDLES.set(candidateHandle, candidateRecord)
        candidateRecord.handle = candidateHandle
        state.pendingCandidateHandle = candidateHandle
        // an abandoned authority never outlives its own projected deadline
        if (
          !armOperationDeadline(
            state,
            candidateRecord,
            candidateRecord.candidateLocalDeadline,
            () => {
              retireSourceCandidate(state, candidateHandle)
            }
          )
        ) {
          // expiry already erased and released this authority: never hand out a dead handle
          unavailable()
        }
        return candidateHandle
      } finally {
        clear(canonicalWire)
      }
    })
    .then(
      (candidateHandle) => {
        cleanup()
        return candidateHandle
      },
      (err) => {
        cleanup()
        state.pendingCandidate = null
        destroyPeerTailControl(session)
        throw err
      }
    )
}

// ---------------------------------------------------------------------------
// Source EXTEND
// ---------------------------------------------------------------------------

function extendPeerTail(session, request) {
  const state = safeObject(session) ? SESSIONS.get(session) : null
  if (!state || state.destroyed || !state.initiator) invalid()
  if (state.extensionIndex >= 2 || state.phase !== 'TAIL_READY') invalid()
  if (state.pendingCandidate !== null || state.pendingExtend !== null) invalid()
  if (state.installing) invalid()
  if (!safeObject(request)) invalid()

  const candidateRecord = safeObject(request.candidate)
    ? CANDIDATE_HANDLES.get(request.candidate)
    : null
  if (!candidateRecord || candidateRecord.session !== session || candidateRecord.consumed) {
    invalid()
  }
  if (!safeObject(request.forwardLimits) || !safeObject(request.reverseLimits)) invalid()
  if (!fixed(request.payloadParametersDigest, 32)) invalid()

  const currWall = state.wallNow()
  const currMono = state.monotonicNow()
  if (currWall >= candidateRecord.expiresAt || currMono >= candidateRecord.candidateLocalDeadline) {
    invalid()
  }

  // Blocker 7: forward and reverse partitions are separate ratified directional bounds.
  // Each must fit its own parent/candidate bound; they are never required to be equal.
  const forwardExpiresAt = request.forwardLimits.expiresAt
  const reverseExpiresAt = request.reverseLimits.expiresAt
  if (typeof forwardExpiresAt !== 'bigint' || typeof reverseExpiresAt !== 'bigint') invalid()
  // The short-lived candidate authorizes admission, not the admitted branch lifetime.
  const reverseBound = minBigInt(state.wireExpiresAt, candidateRecord.advertisementExpiresAt)
  if (
    forwardExpiresAt > state.wireExpiresAt ||
    reverseExpiresAt > reverseBound ||
    currWall >= forwardExpiresAt ||
    currWall >= reverseExpiresAt
  ) {
    invalid()
  }

  state.regions.extend = reserveRegion(
    state.sessionPool,
    'peer-tail-control/source-extend',
    MEM.SOURCE_EXTEND
  )
  // successor material storage is reserved before any successor byte is derived
  let successorMaterialReservation = reserveRegion(
    state.pool,
    'peer-tail-control/final-material',
    MEM.MATERIAL
  )
  let successorAdvertisementReservation = null

  const nextExtensionIndex = state.extensionIndex + 1
  let ephemeralKeys = null
  let clientNonce = null
  let extensionNonce = null
  let reqWire = null
  let envelope = null
  let forwardLimitsBuf = null
  let reverseLimitsBuf = null
  let successorTranscript = null
  let successorSharedSecret = null
  let successorDerived = null
  let successorKeys = null
  let successorTranscriptDigest = null

  const releaseSuccessor = () => {
    if (successorDerived) clearTailKeys(successorDerived)
    clear(successorSharedSecret)
    clear(successorTranscript)
    clear(successorTranscriptDigest)
    clear(forwardLimitsBuf)
    clear(reverseLimitsBuf)
    clear(reqWire)
    clear(envelope)
    clear(clientNonce)
    clear(extensionNonce)
    if (ephemeralKeys) {
      clear(ephemeralKeys.publicKey)
      clear(ephemeralKeys.secretKey)
    }
    releaseRegion(successorMaterialReservation)
    releaseRegion(successorAdvertisementReservation)
    if (state.regions.extend) {
      releaseRegion(state.regions.extend)
      state.regions.extend = null
    }
  }

  try {
    ephemeralKeys = generateX25519KeyPair()
    clientNonce = randomBytes(32)
    extensionNonce = randomBytes(32)
    forwardLimitsBuf = encodePeerLimits(request.forwardLimits)
    reverseLimitsBuf = encodePeerLimits(request.reverseLimits)

    reqWire = encodePeerTransport(PEER_MESSAGE_ID.PEER_EXTEND_REQUEST_V2, {
      branchClass: PEER_BRANCH_CLASS.PEER,
      branchId: state.branchId,
      circuitId: state.circuitId,
      generation: state.generation,
      extensionIndex: nextExtensionIndex,
      advertisementLength: 260,
      advertisement: candidateRecord.advertisement,
      clientTailEphemeralPublicKey: ephemeralKeys.publicKey,
      clientNonce,
      payloadParametersDigest: request.payloadParametersDigest,
      successorReverseLimits: request.reverseLimits,
      extensionNonce,
      currentTailForwardLimits: request.forwardLimits,
      candidateAuthorityCommitment: candidateRecord.candidateAuthorityCommitment
    })

    successorTranscript = createPeerTailTranscript({
      branchId: state.branchId,
      circuitId: state.circuitId,
      generation: state.generation,
      extensionIndex: nextExtensionIndex,
      clientTailEphemeralPublicKey: ephemeralKeys.publicKey,
      advertisedTailRouteEncryptionPublicKey: candidateRecord.routeEncryptionPublicKey32,
      candidateAdvertisementDigest: candidateRecord.advertisementDigest,
      clientNonce,
      tailIdentity: candidateRecord.relayIdentity32,
      reverseLimits: reverseLimitsBuf,
      forwardLimits: forwardLimitsBuf,
      candidateAuthorityCommitment: candidateRecord.candidateAuthorityCommitment
    })
    successorTranscriptDigest = hashPeer(TAIL_CONTROL_TRANSCRIPT_DIGEST_DOMAIN, [
      successorTranscript
    ])
    successorSharedSecret = diffieHellman(
      ephemeralKeys.secretKey,
      candidateRecord.routeEncryptionPublicKey32
    )
    clear(ephemeralKeys.secretKey)
    successorDerived = derivePeerTailKeys(successorSharedSecret, successorTranscript)
    successorKeys = splitTailKeys(successorDerived)

    envelope = sealControlEnvelope(
      state,
      state.controlKeys,
      DIRECTION_FORWARD,
      state.txCounter,
      reqWire
    )
    state.txCounter++
  } catch (err) {
    releaseSuccessor()
    throw err
  }

  // This operation owns the verified proof across both asynchronous response phases.
  const verified = { proofExpiresAt: 0n }
  candidateRecord.consumed = true
  candidateRecord.retired = true
  clearOperationDeadline(state, candidateRecord)
  CANDIDATE_HANDLES.delete(request.candidate)
  state.pendingCandidateHandle = null
  state.pendingExtend = verified

  const operationDeadline = minBigInt(
    minBigInt(state.localDeadline, candidateRecord.candidateLocalDeadline),
    currMono + OPERATION_TIMEOUT_MS
  )
  const train = createSendTrain(state, envelope, operationDeadline, { auto: true })

  const finish = () => {
    train.stop()
    clear(reqWire)
    clear(envelope)
    clear(forwardLimitsBuf)
    clear(reverseLimitsBuf)
    clear(clientNonce)
    clear(extensionNonce)
    if (ephemeralKeys) {
      clear(ephemeralKeys.publicKey)
      clear(ephemeralKeys.secretKey)
    }
    clear(successorTranscriptDigest)
    if (state.regions.extend) {
      releaseRegion(state.regions.extend)
      state.regions.extend = null
    }
    if (state.regions.candidate) {
      releaseRegion(state.regions.candidate)
      state.regions.candidate = null
    }
    clear(candidateRecord.advertisement)
    clear(candidateRecord.advertisementDigest)
    clear(candidateRecord.relayIdentity32)
    clear(candidateRecord.routeEncryptionPublicKey32)
    clear(candidateRecord.candidateAuthorityCommitment)
  }

  return awaitControlObject(
    state,
    state.controlKeys,
    DIRECTION_REVERSE,
    state.rxCounter,
    PEER_MESSAGE_ID.PEER_EXTENDED_V2,
    train
  )
    .then(({ canonicalWire, obj }) => {
      try {
        state.rxCounter++

        const fields = obj.fields
        if (
          fields.branchClass !== PEER_BRANCH_CLASS.PEER ||
          !b4a.equals(fields.branchId, state.branchId) ||
          !b4a.equals(fields.circuitId, state.circuitId) ||
          fields.generation !== state.generation ||
          fields.extensionIndex !== nextExtensionIndex ||
          fields.proofLength !== 378 ||
          !b4a.equals(fields.extensionNonce, extensionNonce) ||
          !b4a.equals(fields.responderAdvertisementDigest, candidateRecord.advertisementDigest)
        ) {
          authentication()
        }

        const proofObj = decodePeerTransport(fields.completeProof)
        if (proofObj.messageId !== PEER_MESSAGE_ID.PEER_REDACTED_RESPONDER_PROOF_V2) {
          authentication()
        }

        let proofSigInput = null
        try {
          proofSigInput = buildSignatureInput(
            PEER_MESSAGE_ID.PEER_REDACTED_RESPONDER_PROOF_V2,
            REDACTED_PROOF_LABEL,
            proofObj.body
          )
          if (
            !sodium.crypto_sign_verify_detached(
              proofObj.authSuffix,
              proofSigInput,
              candidateRecord.relayIdentity32
            )
          ) {
            authentication()
          }
        } finally {
          clear(proofSigInput)
        }

        const proofFields = proofObj.fields
        let expectedAdmittedLimitsDigest = null
        let limitsMatch = false
        try {
          expectedAdmittedLimitsDigest = digestPeerLimits(
            reverseLimitsBuf,
            forwardLimitsBuf,
            candidateRecord.candidateAuthorityCommitment
          )
          limitsMatch = b4a.equals(proofFields.admittedLimitsDigest, expectedAdmittedLimitsDigest)
        } finally {
          clear(expectedAdmittedLimitsDigest)
        }

        if (
          !limitsMatch ||
          !b4a.equals(
            proofFields.responderAdvertisementDigest,
            candidateRecord.advertisementDigest
          ) ||
          !b4a.equals(proofFields.initiatorIdentity, state.tailIdentity) ||
          !b4a.equals(proofFields.responderIdentity, candidateRecord.relayIdentity32) ||
          proofFields.branchClass !== PEER_BRANCH_CLASS.PEER ||
          !b4a.equals(proofFields.branchId, state.branchId) ||
          !b4a.equals(proofFields.circuitId, state.circuitId) ||
          proofFields.generation !== state.generation ||
          proofFields.extensionIndex !== nextExtensionIndex ||
          !b4a.equals(proofFields.clientTailEphemeralPublicKey, ephemeralKeys.publicKey) ||
          !b4a.equals(proofFields.clientNonce, clientNonce) ||
          !b4a.equals(
            proofFields.advertisedRouteEncryptionPublicKey,
            candidateRecord.routeEncryptionPublicKey32
          )
        ) {
          authentication()
        }

        // proof expiry is byte-equal to the accepted reverse partition (section 2)
        if (proofFields.expiresAt !== reverseExpiresAt) authentication()
        if (proofFields.expiresAt > candidateRecord.advertisementExpiresAt) authentication()
        if (
          !fixed(proofFields.responderProofNonce, 32) ||
          isZero32(proofFields.responderProofNonce)
        ) {
          authentication()
        }

        verified.proofExpiresAt = proofFields.expiresAt
      } finally {
        clear(canonicalWire)
      }

      // Blocker 2: retransmission stops, the original finite deadline owner survives so
      // an EXTENDED without READY expires instead of waiting forever.
      train.holdDeadline()

      return awaitControlObject(
        state,
        successorKeys.control,
        DIRECTION_REVERSE,
        0n,
        PEER_MESSAGE_ID.PEER_TAIL_READY_V2,
        train
      )
    })
    .then(({ canonicalWire, obj }) => {
      try {
        const readyFields = obj.fields
        let readySigInput = null
        try {
          readySigInput = buildSignatureInput(
            PEER_MESSAGE_ID.PEER_TAIL_READY_V2,
            TAIL_READY_LABEL,
            obj.body
          )
          if (
            !sodium.crypto_sign_verify_detached(
              obj.authSuffix,
              readySigInput,
              candidateRecord.relayIdentity32
            )
          ) {
            authentication()
          }
        } finally {
          clear(readySigInput)
        }

        if (
          readyFields.branchClass !== PEER_BRANCH_CLASS.PEER ||
          !b4a.equals(readyFields.branchId, state.branchId) ||
          !b4a.equals(readyFields.circuitId, state.circuitId) ||
          readyFields.generation !== state.generation ||
          readyFields.extensionIndex !== nextExtensionIndex ||
          !b4a.equals(readyFields.tailControlTranscriptDigest, successorTranscriptDigest) ||
          !b4a.equals(readyFields.tailIdentity, candidateRecord.relayIdentity32) ||
          !b4a.equals(readyFields.tailAdvertisementDigest, candidateRecord.advertisementDigest) ||
          !b4a.equals(readyFields.clientNonce, clientNonce)
        ) {
          authentication()
        }
        if (!fixed(readyFields.readyNonce, 32) || isZero32(readyFields.readyNonce)) {
          authentication()
        }
        if (readyFields.expiresAt !== minBigInt(forwardExpiresAt, verified.proofExpiresAt)) {
          authentication()
        }

        const runtime = state.runtime
        const wallNow = state.wallNow()
        const monoNow = state.monotonicNow()
        if (
          state.destroyed ||
          SESSIONS.get(session) !== state ||
          state.runtime !== runtime ||
          !isPeerM3Runtime(runtime) ||
          state.pendingExtend !== verified
        )
          destroyed()
        if (typeof monoNow !== 'bigint' || monoNow >= train.deadline || train.settled) unavailable()
        if (wallNow >= readyFields.expiresAt) authentication()

        successorAdvertisementReservation = reserveRegion(
          state.pool,
          'peer-tail-control/tail-advertisement',
          MEM.ADVERTISEMENT
        )

        state.installing = true
        try {
          const nextAdvertisement = copy(candidateRecord.advertisement)
          const nextTailIdentity = copy(candidateRecord.relayIdentity32)
          const nextAdvertisementDigest = copy(candidateRecord.advertisementDigest)
          const nextTranscriptDigest = copy(successorTranscriptDigest)

          // atomic replacement: old tail material is erased only after readiness verified
          clearTailKeys(state.controlKeys)
          clearTailKeys(state.finalizeKeys)
          clear(state.sharedSecret)
          clear(state.transcript)
          clear(state.tailAdvertisement260)
          clear(state.tailIdentity)
          clear(state.tailAdvertisementDigest)
          clear(state.transcriptDigest)

          releaseRegion(state.materialReservation)
          releaseRegion(state.advertisementReservation)

          state.materialReservation = successorMaterialReservation
          state.advertisementReservation = successorAdvertisementReservation
          state.sharedSecret = successorSharedSecret
          state.transcript = successorTranscript
          state.controlKeys = successorKeys.control
          state.finalizeKeys = successorKeys.finalize
          state.tailAdvertisement260 = nextAdvertisement
          state.tailIdentity = nextTailIdentity
          state.tailAdvertisementDigest = nextAdvertisementDigest
          state.transcriptDigest = nextTranscriptDigest
          state.extensionIndex = nextExtensionIndex

          state.wireExpiresAt = minBigInt(state.wireExpiresAt, readyFields.expiresAt)
          state.localDeadline = minBigInt(
            state.localDeadline,
            monoNow + (state.wireExpiresAt - wallNow)
          )

          // successor material owns fresh ordered counters; readiness consumed reverse 0
          state.txCounter = 0n
          state.rxCounter = 1n

          successorSharedSecret = null
          successorTranscript = null
          successorDerived = null
          // storage ownership has moved into session state
          successorMaterialReservation = null
          successorAdvertisementReservation = null

          if (nextExtensionIndex === 2) {
            state.phase = 'FINAL_EXIT_READY'
            state.finalExitStage = 'FINAL_EXIT_READY'
            // no further ordered tail-control traffic exists at the source
            clearTailKeys(state.controlKeys)
          } else {
            state.phase = 'TAIL_READY'
          }
        } finally {
          state.installing = false
        }

        if (monoNow >= state.localDeadline) unavailable()
        state.pendingExtend = null
        return session
      } finally {
        clear(canonicalWire)
      }
    })
    .then(
      (result) => {
        finish()
        return result
      },
      (err) => {
        state.pendingExtend = null
        finish()
        releaseSuccessor()
        destroyPeerTailControl(session)
        throw err
      }
    )
}

// ---------------------------------------------------------------------------
// Final exit ownership chain
// ---------------------------------------------------------------------------

function createPeerFinalExitHandoff(session) {
  const state = safeObject(session) ? SESSIONS.get(session) : null
  if (!state || state.destroyed) invalid()
  if (state.extensionIndex !== 2 || state.phase !== 'FINAL_EXIT_READY') invalid()
  if (state.finalExitStage !== 'FINAL_EXIT_READY') invalid()
  if (state.issuedHandoff !== null) replay()
  if (!state.sharedSecret || !state.transcript || !state.finalizeKeys) invalid()
  if (state.pendingCandidate !== null || state.pendingExtend !== null || state.installing) invalid()

  const currWall = state.wallNow()
  const currMono = state.monotonicNow()
  if (currWall >= state.wireExpiresAt || currMono >= state.localDeadline) {
    invalid()
  }

  // Exactly the twelve ratified material keys. The exact extension-2 buffers move once;
  // their existing reservation moves with them instead of allocating a second set.
  const material = {
    clockIdentity: state.clockIdentity,
    expiresAt: state.wireExpiresAt,
    finalizeForwardKey: state.finalizeKeys.finalizeForwardKey,
    finalizeForwardNoncePrefix: state.finalizeKeys.finalizeForwardNoncePrefix,
    finalizeReverseKey: state.finalizeKeys.finalizeReverseKey,
    finalizeReverseNoncePrefix: state.finalizeKeys.finalizeReverseNoncePrefix,
    initiator: state.initiator,
    localDeadline: state.localDeadline,
    sharedSecret: state.sharedSecret,
    tailControl: session,
    tailControlTranscript: state.transcript,
    wireExpiresAt: state.wireExpiresAt
  }

  const materialReservation = state.materialReservation
  const handoff = createFinalExitHandoff(session, material)

  state.sharedSecret = null
  state.transcript = null
  state.finalizeKeys = null
  state.materialReservation = null
  state.issuedHandoff = handoff
  state.finalExitStage = 'FINAL_EXIT_HANDOFF'
  ISSUED_HANDOFFS.add(handoff)

  FINAL_EXIT_HANDOFFS.set(handoff, {
    owner: session,
    state,
    material,
    materialReservation,
    claiming: false
  })
  FINAL_EXIT_HANDOFF_OWNERS.set(session, handoff)

  return handoff
}

// Callback-free branded CAS. Validates the exact live session/runtime/activation/parent
// tuple, authorizes the pending native take with those same facts, and only then retires
// this owner's runtime reference. No clock read or callback happens after commit.
function takePeerFinalCarrierAuthorization(auth, runtime) {
  if (!safeObject(auth) || !isPeerM3Runtime(runtime)) unauthorized()
  if (SPENT_CARRIER_AUTHS.has(auth)) replay()
  const facts = CARRIER_AUTH_FACTS.get(auth)
  if (!facts || facts.runtime !== runtime) unauthorized()

  const state = facts.state
  if (
    !state ||
    state.destroyed ||
    state.finalExitStage !== 'FINAL_EXIT_TRANSPORT_TAKING' ||
    state.runtime !== runtime ||
    state.finalExitActivationOwner !== facts.activationOwner ||
    FINAL_EXIT_ACTIVATIONS.get(facts.activationOwner) !== facts.activationRecord ||
    state.pendingCandidate !== null ||
    state.pendingExtend !== null ||
    state.installing ||
    state.pumping ||
    state.forwardingOwner !== null ||
    state.readinessTrain !== facts.readinessTrain
  ) {
    unauthorized()
  }

  if (
    facts.clockIdentity !== state.clockIdentity ||
    facts.generation !== state.generation ||
    facts.parentLocalDeadline !== state.originalParentLocalDeadline ||
    facts.wireExpiresAt !== state.wireExpiresAt ||
    facts.localDeadline !== state.localDeadline
  ) {
    unauthorized()
  }

  if (
    authorizePeerM3FinalCarrierTake(
      runtime,
      facts.clockIdentity,
      facts.generation,
      facts.parentLocalDeadline,
      facts.wireExpiresAt,
      facts.localDeadline,
      facts.readinessTrain
    ) !== true
  ) {
    unauthorized()
  }

  if (facts.readinessTrain) {
    const train = facts.readinessTrain
    train.readinessRegion = state.regions.readiness
    train.readinessNonce = state.readyNonce
    train.readinessParentPool = null
    state.transferredReadinessTrain = train
    state.regions.readiness = null
    state.readyNonce = null
    state.readinessTrain = null
  }
  CARRIER_AUTH_FACTS.delete(auth)
  SPENT_CARRIER_AUTHS.add(auth)
  state.runtime = null
  state.finalExitStage = 'PURPOSE_CONFIRMING'

  return Object.freeze({
    clockIdentity: facts.clockIdentity,
    generation: facts.generation,
    parentLocalDeadline: facts.parentLocalDeadline,
    wireExpiresAt: facts.wireExpiresAt,
    localDeadline: facts.localDeadline
  })
}

function takePeerTailFinalRuntime(session, activationOwner) {
  const state = safeObject(session) ? SESSIONS.get(session) : null
  if (!state || state.destroyed) invalid()
  // both ends of the completed circuit own a final runtime: source and terminal
  if (state.extensionIndex !== 2) invalid()
  if (state.finalRuntimeTaken) replay()

  if (state.finalExitStage !== 'FINAL_EXIT_ACTIVATION' || !state.finalExitActivationOwner) {
    authentication()
  }
  if (!safeObject(activationOwner) || state.finalExitActivationOwner !== activationOwner) {
    authentication()
  }
  const activationRecord = FINAL_EXIT_ACTIVATIONS.get(activationOwner)
  if (
    !activationRecord ||
    activationRecord.owner !== session ||
    activationRecord.state !== state ||
    activationRecord.material !== state.finalExitActivationMaterial
  ) {
    authentication()
  }

  if (!state.runtime) invalid()
  if (state.installing || state.pendingCandidate !== null || state.pendingExtend !== null) {
    invalid()
  }
  // no receive consumer may be pending on the runtime that is about to move
  if (state.pumping || state.forwardingOwner) invalid()

  const runtime = state.runtime
  const readinessTrain = state.readinessTrain
  const currWall = state.wallNow()
  const currMono = state.monotonicNow()
  if (
    state.destroyed ||
    SESSIONS.get(session) !== state ||
    state.runtime !== runtime ||
    !isPeerM3Runtime(runtime) ||
    state.readinessTrain !== readinessTrain ||
    state.finalRuntimeTaken ||
    state.finalExitStage !== 'FINAL_EXIT_ACTIVATION' ||
    state.finalExitActivationOwner !== activationOwner ||
    FINAL_EXIT_ACTIVATIONS.get(activationOwner) !== activationRecord ||
    activationRecord.material !== state.finalExitActivationMaterial
  )
    authentication()
  if (currWall >= state.wireExpiresAt || currMono >= state.localDeadline) {
    invalid()
  }
  if (readinessTrain && (readinessTrain.settled || currMono >= readinessTrain.deadline)) {
    unavailable()
  }

  // No callback boundary remains between the liveness recheck and authorization minting.
  if (state.controlKeys) clearTailKeys(state.controlKeys)

  state.finalExitStage = 'FINAL_EXIT_TRANSPORT_TAKING'

  const auth = Object.freeze({})
  CARRIER_AUTH_FACTS.set(auth, {
    auth,
    runtime: state.runtime,
    state,
    readinessTrain,
    activationOwner,
    activationRecord,
    clockIdentity: state.clockIdentity,
    generation: state.generation,
    parentLocalDeadline: state.originalParentLocalDeadline,
    wireExpiresAt: state.wireExpiresAt,
    localDeadline: state.localDeadline
  })

  state.finalRuntimeTaken = true

  return Object.freeze({
    runtime: state.runtime,
    authorization: auth,
    clockIdentity: state.clockIdentity,
    generation: state.generation,
    parentLocalDeadline: state.originalParentLocalDeadline,
    wireExpiresAt: state.wireExpiresAt,
    localDeadline: state.localDeadline
  })
}

// Generic activation hooks: real functions on this module, matching the shared closed
// v1/v2 final-exit dispatch contract.
function prepareTailControlFinalExitActivation(handoff, activationOwner) {
  if (!isPeerTailFinalExitHandoff(handoff)) authentication()
  if (SPENT_HANDOFFS.has(handoff)) replay()
  const record = safeObject(handoff) ? FINAL_EXIT_HANDOFFS.get(handoff) : null
  if (!record || !safeObject(activationOwner)) authentication()
  const state = record.state
  const material = record.material
  if (
    !state ||
    !material ||
    record.claiming ||
    state.destroyed ||
    state.finalExitStage !== 'FINAL_EXIT_HANDOFF' ||
    material.tailControl !== record.owner
  ) {
    invalid()
  }

  record.claiming = true
  const {
    reserveFinalExitActivationOwner,
    revokeFinalExitActivationOwnerReservation
  } = require('./final-exit-activation')

  let reservation = null
  let consumed = null
  let complete = false
  try {
    const current = state.monotonicNow()
    if (current >= state.localDeadline) invalid()
    reservation = reserveFinalExitActivationOwner(activationOwner)
    FINAL_EXIT_PREPARE_CONSUMES.add(handoff)
    try {
      consumed = consumeFinalExitHandoff(handoff)
    } finally {
      FINAL_EXIT_PREPARE_CONSUMES.delete(handoff)
    }
    FINAL_EXIT_HANDOFF_OWNERS.delete(record.owner)
    SPENT_HANDOFFS.add(handoff)
    if (consumed !== material) authentication()
    FINAL_EXIT_HANDOFFS.delete(handoff)
    const transfer = Object.freeze({})
    FINAL_EXIT_TRANSFERS.set(transfer, {
      owner: record.owner,
      state,
      handoff,
      activationOwner,
      reservation,
      material,
      materialReservation: record.materialReservation,
      generation: ++state.finalExitGeneration,
      committed: false
    })
    complete = true
    return Object.freeze({ transfer, material })
  } finally {
    if (!complete) {
      record.claiming = false
      if (reservation) revokeFinalExitActivationOwnerReservation(reservation)
    }
  }
}

function commitTailControlFinalExitActivation(transfer, activationOwner) {
  const record = safeObject(transfer) ? FINAL_EXIT_TRANSFERS.get(transfer) : null
  if (!record || record.committed || record.activationOwner !== activationOwner) authentication()
  const state = record.state
  const material = record.material
  if (!state || !material || state.destroyed || state.finalExitStage !== 'FINAL_EXIT_HANDOFF') {
    invalid()
  }

  const current = state.monotonicNow()
  if (current >= state.localDeadline) invalid()
  const { consumeFinalExitActivationOwnerReservation } = require('./final-exit-activation')
  const consumed = consumeFinalExitActivationOwnerReservation(record.reservation, activationOwner)
  if (consumed !== material) authentication()

  FINAL_EXIT_TRANSFERS.delete(transfer)
  record.committed = true
  state.finalExitActivationOwner = activationOwner
  state.finalExitActivationMaterial = material
  state.finalExitStage = 'FINAL_EXIT_ACTIVATION'
  FINAL_EXIT_ACTIVATIONS.set(activationOwner, {
    owner: record.owner,
    state,
    material,
    materialReservation: record.materialReservation
  })
  return true
}

function revokeTailControlFinalExitActivation(transfer) {
  const record = safeObject(transfer) ? FINAL_EXIT_TRANSFERS.get(transfer) : null
  if (!record || record.committed) return false
  FINAL_EXIT_TRANSFERS.delete(transfer)
  if (record.reservation) {
    try {
      const { revokeFinalExitActivationOwnerReservation } = require('./final-exit-activation')
      revokeFinalExitActivationOwnerReservation(record.reservation)
    } catch {}
  }
  // the moved material is destroyed by the shared dispatch; its storage ends here
  releaseRegion(record.materialReservation)
  record.materialReservation = null
  return true
}

function destroyTailControlFinalExitActivation(tailOwner, activationOwner) {
  const record = safeObject(activationOwner) ? FINAL_EXIT_ACTIVATIONS.get(activationOwner) : null
  if (!record || record.owner !== tailOwner) return false
  FINAL_EXIT_ACTIVATIONS.delete(activationOwner)
  releaseRegion(record.materialReservation)
  record.materialReservation = null
  const state = record.state
  if (state && state.finalExitActivationOwner === activationOwner) {
    state.finalExitActivationOwner = null
    state.finalExitActivationMaterial = null
    state.finalExitStage = null
  }
  return true
}

function rejectTailControlFinalExitHandoffConsume(owner) {
  const handoff = safeObject(owner) ? FINAL_EXIT_HANDOFF_OWNERS.get(owner) : null
  const record = handoff ? FINAL_EXIT_HANDOFFS.get(handoff) : null
  return !!(record && record.claiming && !FINAL_EXIT_PREPARE_CONSUMES.has(handoff))
}

function destroyTailControlFinalExitHandoffOwner(owner) {
  const handoff = safeObject(owner) ? FINAL_EXIT_HANDOFF_OWNERS.get(owner) : null
  const record = handoff ? FINAL_EXIT_HANDOFFS.get(handoff) : null
  if (!record) return false
  // this owner's own prepare is mid-consume: the shared dispatch must not treat that as
  // an external destruction, or it would erase the material it is about to move
  if (FINAL_EXIT_PREPARE_CONSUMES.has(handoff)) return false
  FINAL_EXIT_HANDOFF_OWNERS.delete(owner)
  FINAL_EXIT_HANDOFFS.delete(handoff)
  releaseRegion(record.materialReservation)
  record.materialReservation = null
  return true
}

module.exports = {
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
  prepareTailControlFinalExitActivation,
  commitTailControlFinalExitActivation,
  revokeTailControlFinalExitActivation,
  destroyTailControlFinalExitActivation,
  rejectTailControlFinalExitHandoffConsume,
  destroyTailControlFinalExitHandoffOwner
}
