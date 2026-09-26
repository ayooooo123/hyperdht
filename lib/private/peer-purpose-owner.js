'use strict'

const b4a = require('b4a')

const { PrivateRouteError } = require('./errors')
const { DatagramReplayWindow, SenderCounter } = require('./counters')
const {
  clearPeerPurposeKeys,
  createPeerPurposeDigest,
  createPeerPurposeFinalTranscript,
  createPeerPurposePreTranscript,
  createPeerPurposeTranscript,
  derivePeerPurposeKeys,
  derivePeerPurposeSharedSecret,
  digestPeerPurposeAccept,
  digestPeerPurposeConfirmation,
  digestPeerPurposeOffer,
  computePeerPurposeMac,
  verifyPeerPurposeMac
} = require('./peer-crypto')
const {
  computePeerQueuedBytes,
  computePeerSemanticOwnedBytes,
  narrowPeerReservations,
  releasePeerLedger,
  chargePeerLedger,
  releasePeerMemory,
  reservePeerLedger,
  reservePeerMemory,
  takePeerMemory
} = require('./peer-ledger')
const { PEER_MESSAGE_ID } = require('./peer-protocol')
const { decodePeerTransport, encodePeerTransport } = require('./peer-transport-wire')
const { PeerReliableLanes } = require('./peer-reliable-lanes')
const { openPeerContextFrame, sealPeerContextFrame } = require('./peer-m3-context')

const MAX_U64 = 0xffff_ffff_ffff_ffffn
const MAX_COUNTER = MAX_U64 - 1n
const MAX_ATTEMPTS = 8
const RETRY_INTERVAL_MS = 250
const OPERATION_TIMEOUT_MS = 2000n
const PURPOSE_MAC_BYTES = 16
const ZERO16 = b4a.alloc(16)
const ZERO3 = b4a.alloc(3)
const CARRIER_BRAND = Symbol('peer-purpose-carrier')
const STREAM_CALLBACK_NAMES = Object.freeze([
  'onAdmit',
  'onDeliver',
  'onAcknowledged',
  'onConflict',
  'onWritable',
  'onFailure'
])
class PeerPurposeSealFailure extends Error {
  constructor(cause) {
    super('purpose frame sealing failed')
    this.cause = cause
  }
}

class PeerPurposeTransportFailure extends Error {
  constructor(cause) {
    super('purpose frame transport failed')
    this.cause = cause
  }
}
class PeerPurposeLedgerFailure extends Error {
  constructor(cause) {
    super('purpose ledger charge failed')
    this.cause = cause
  }
}
const STATES = new WeakMap()
const DESTROYED = new WeakSet()

const LIMIT_NAMES = Object.freeze([
  'forwardCells',
  'forwardBytes',
  'forwardCommands',
  'reverseCells',
  'reverseBytes',
  'reverseCommands',
  'maxStreams',
  'receiveFrames',
  'receiveBytes',
  'semanticOwnedBytes',
  'maxQueuedBytes',
  'expiresAt'
])

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function unauthorized() {
  throw PrivateRouteError.UNAUTHORIZED()
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

function replay() {
  throw PrivateRouteError.ERR_REPLAY()
}

function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function own(value, name) {
  if (!object(value)) invalid()
  const descriptor = Object.getOwnPropertyDescriptor(value, name)
  if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) invalid()
  return descriptor.value
}
function optional(value, name) {
  if (!object(value)) invalid()
  const descriptor = Object.getOwnPropertyDescriptor(value, name)
  if (descriptor === undefined) return undefined
  if (!Object.prototype.hasOwnProperty.call(descriptor, 'value')) invalid()
  return descriptor.value
}
function snapshotStreamCallbacks(value) {
  if (value === null || value === undefined) return null
  if (!object(value)) invalid()

  let keys
  try {
    keys = Reflect.ownKeys(value)
    for (const key of keys) {
      if (typeof key !== 'string' || !STREAM_CALLBACK_NAMES.includes(key)) invalid()
    }

    const snapshot = Object.create(null)
    for (const name of STREAM_CALLBACK_NAMES) {
      const descriptor = Object.getOwnPropertyDescriptor(value, name)
      if (descriptor === undefined) continue
      if (
        !Object.prototype.hasOwnProperty.call(descriptor, 'value') ||
        typeof descriptor.value !== 'function'
      )
        invalid()
      snapshot[name] = descriptor.value
    }
    return Object.freeze(snapshot)
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function copy(value, size = null) {
  if (!b4a.isBuffer(value) || (size !== null && value.byteLength !== size)) invalid()
  return b4a.from(value)
}

function clear(value) {
  if (b4a.isBuffer(value)) value.fill(0)
}

function erasePreShared(state) {
  if (!state.preShared) return
  clear(state.preShared)
  state.preShared = null
}

function fixed(value, size) {
  return b4a.isBuffer(value) && value.byteLength === size
}

function zero(value) {
  if (!b4a.isBuffer(value)) return false
  for (const byte of value) if (byte !== 0) return false
  return true
}

function u16(value, nonzero = false) {
  return Number.isSafeInteger(value) && value >= (nonzero ? 1 : 0) && value <= 0xffff
}

function u32(value, nonzero = false) {
  return Number.isSafeInteger(value) && value >= (nonzero ? 1 : 0) && value <= 0xffff_ffff
}

function u64(value, nonzero = false) {
  return typeof value === 'bigint' && value >= (nonzero ? 1n : 0n) && value <= MAX_U64
}

function minBigInt(left, right) {
  return left < right ? left : right
}

function addU64(left, right) {
  const result = left + right
  if (result > MAX_U64) invalid()
  return result
}

function identity(options) {
  let routeId = null
  let circuitId = null
  let committed = false
  try {
    routeId = copy(own(options, 'routeId'), 16)
    circuitId = copy(own(options, 'circuitId'), 16)
    const generation = own(options, 'generation')
    const purpose = own(options, 'purpose')
    if (!u64(generation, true) || !u16(purpose, true) || purpose > 3) invalid()
    committed = true
    return { routeId, circuitId, generation, purpose }
  } finally {
    if (!committed) {
      clear(routeId)
      clear(circuitId)
    }
  }
}

function limits(value) {
  if (!object(value)) invalid()
  const result = {}
  for (const name of LIMIT_NAMES) {
    const current = own(value, name)
    if (name === 'forwardBytes' || name === 'reverseBytes' || name === 'expiresAt') {
      if (!u64(current, true)) invalid()
    } else if (name === 'maxStreams' || name === 'receiveFrames') {
      if (!u16(current, true)) invalid()
    } else if (!u32(current, true)) {
      invalid()
    }
    result[name] = current
  }
  return result
}

function validateLimits(value, routeIdentity, initiator) {
  const result = limits(value)
  const semanticFloor = computePeerSemanticOwnedBytes({
    purpose: routeIdentity.purpose,
    isInitiator: initiator,
    maxStreams: result.maxStreams
  })
  if (result.semanticOwnedBytes < semanticFloor) invalid()
  if (result.maxQueuedBytes < computePeerQueuedBytes(result)) invalid()
  return result
}

function reservationBytes(value) {
  const bytes = computePeerQueuedBytes(value)
  if (!u32(bytes, true)) invalid()
  return bytes
}

function carrier(value) {
  if (!object(value) || value[CARRIER_BRAND] !== true) unauthorized()
  for (const name of [
    'sendFinalizeFrame',
    'sendFrame',
    'reserveReceive',
    'receiveEnvelope',
    'cancelReceive',
    'activate',
    'schedule',
    'destroy'
  ]) {
    if (typeof value[name] !== 'function') unauthorized()
  }
  if (!object(value.clock)) unauthorized()
  if (typeof value.clock.wallNow !== 'function' || typeof value.clock.monotonicNow !== 'function') {
    unauthorized()
  }
  return value
}

function finalKeys(value) {
  if (!object(value)) invalid()
  const result = {}
  let committed = false
  try {
    for (const name of [
      'finalizeForwardKey',
      'finalizeForwardNoncePrefix',
      'finalizeReverseKey',
      'finalizeReverseNoncePrefix'
    ]) {
      const size = name.endsWith('Key') ? 32 : 16
      result[name] = copy(own(value, name), size)
    }
    committed = true
    return result
  } finally {
    if (!committed) clearFinalKeys(result)
  }
}

function clearFinalKeys(value) {
  if (!value) return
  for (const part of Object.values(value)) clear(part)
}

function scheduleState(value) {
  const clock = value.clock
  let wallNow
  let monotonicNow
  try {
    wallNow = clock.wallNow()
    monotonicNow = clock.monotonicNow()
  } catch {
    unavailable()
  }
  if (!u64(wallNow) || !u64(monotonicNow)) unavailable()
  if (wallNow >= value.wireExpiresAt || monotonicNow >= value.parentLocalDeadline) unavailable()
  const projected = addU64(monotonicNow, value.wireExpiresAt - wallNow)
  value.localDeadline = minBigInt(value.parentLocalDeadline, projected)
}

function reserveResources(options, value) {
  const ledger = own(options, 'ledger')
  const memoryPool = own(options, 'memoryPool')
  const forward = reservePeerLedger(ledger, {
    cells: value.forwardCells,
    bytes: value.forwardBytes,
    commands: value.forwardCommands
  })
  let reverse = null
  let memory = null
  try {
    reverse = reservePeerLedger(ledger, {
      cells: value.reverseCells,
      bytes: value.reverseBytes,
      commands: value.reverseCommands
    })
    memory = reservePeerMemory(memoryPool, 'peer-purpose/pending', reservationBytes(value))
    return { forward, reverse, memory, memoryOwner: null }
  } catch (err) {
    if (memory) releasePeerMemory(memory)
    if (reverse) releasePeerLedger(reverse)
    releasePeerLedger(forward)
    throw err
  }
}

function narrowResources(state, value) {
  narrowPeerReservations({
    ledgers: [
      {
        ledger: state.resources.forward,
        cells: value.forwardCells,
        bytes: value.forwardBytes,
        commands: value.forwardCommands
      },
      {
        ledger: state.resources.reverse,
        cells: value.reverseCells,
        bytes: value.reverseBytes,
        commands: value.reverseCommands
      }
    ],
    memory: [{ reservation: state.resources.memory, capacityBytes: reservationBytes(value) }]
  })
}

function releaseResources(state) {
  if (!state.resources) return
  if (state.resources.memoryOwner) releasePeerMemory(state.resources.memoryOwner)
  else releasePeerMemory(state.resources.memory)
  releasePeerLedger(state.resources.forward)
  releasePeerLedger(state.resources.reverse)
  state.resources = null
}

function randomBytes(state, name, size) {
  const configured = state.config[name]
  const value = configured === undefined ? state.randomBytes(size) : configured
  if (!fixed(value, size) || zero(value)) invalid()
  return copy(value)
}

function makeUnsigned(messageId, fields) {
  return encodePeerTransport(messageId, fields, ZERO16)
}

function makeMacWire(messageId, fields, key16) {
  let wire = null
  let mac = null
  try {
    wire = makeUnsigned(messageId, fields)
    mac = computePeerPurposeMac(key16, wire.subarray(0, wire.byteLength - PURPOSE_MAC_BYTES))
    wire.set(mac, wire.byteLength - PURPOSE_MAC_BYTES)
    return wire
  } catch (err) {
    clear(wire)
    throw err
  } finally {
    clear(mac)
  }
}

function decodeWire(payload) {
  try {
    return decodePeerTransport(payload)
  } catch {
    authentication()
  }
}

function ackFields(id) {
  return {
    routeId: id.routeId,
    generation: id.generation,
    dataCumulative: MAX_U64,
    dataBitmap: 0n,
    controlCumulative: MAX_U64,
    controlBitmap: 0n,
    ackSnapshot: 0,
    reservedZero: 0
  }
}

function sentinel(decoded, id) {
  const fields = decoded.fields
  return (
    decoded.messageId === PEER_MESSAGE_ID.PEER_RELIABLE_ACK_V2 &&
    b4a.equals(fields.routeId, id.routeId) &&
    fields.generation === id.generation &&
    fields.dataCumulative === MAX_U64 &&
    fields.dataBitmap === 0n &&
    fields.controlCumulative === MAX_U64 &&
    fields.controlBitmap === 0n &&
    fields.ackSnapshot === 0 &&
    fields.reservedZero === 0
  )
}

function offerLimits(fields) {
  return {
    forwardCells: fields.forwardCells,
    forwardBytes: fields.forwardBytes,
    forwardCommands: fields.forwardCommands,
    reverseCells: fields.reverseCells,
    reverseBytes: fields.reverseBytes,
    reverseCommands: fields.reverseCommands,
    maxStreams: fields.maxStreams,
    receiveFrames: fields.receiveFrames,
    receiveBytes: fields.receiveBytes,
    semanticOwnedBytes: fields.semanticOwnedBytes,
    maxQueuedBytes: fields.maxQueuedBytes,
    expiresAt: fields.expiresAt
  }
}

function acceptLimits(fields) {
  return {
    forwardCells: fields.admittedForwardCells,
    forwardBytes: fields.admittedForwardBytes,
    forwardCommands: fields.admittedForwardCommands,
    reverseCells: fields.admittedReverseCells,
    reverseBytes: fields.admittedReverseBytes,
    reverseCommands: fields.admittedReverseCommands,
    maxStreams: fields.admittedMaxStreams,
    receiveFrames: fields.admittedReceiveFrames,
    receiveBytes: fields.admittedReceiveBytes,
    semanticOwnedBytes: fields.admittedSemanticOwnedBytes,
    maxQueuedBytes: fields.admittedMaxQueuedBytes,
    expiresAt: fields.expiresAt
  }
}

function chargeSend(state, direction) {
  let ledger = null
  if (state.resources) {
    ledger = direction === 0 ? state.resources.forward : state.resources.reverse
  } else if (state.status === 'TERMINAL_REJECT' && direction === 1) {
    ledger = state.resourceOptions.ledger
  }
  if (!ledger) return
  try {
    chargePeerLedger(ledger, {
      cells: 1,
      bytes: 1200n,
      commands: 0
    })
  } catch (error) {
    throw new PeerPurposeLedgerFailure(error)
  }
}

function down(from, to) {
  return (
    to.forwardCells <= from.forwardCells &&
    to.forwardBytes <= from.forwardBytes &&
    to.forwardCommands <= from.forwardCommands &&
    to.reverseCells <= from.reverseCells &&
    to.reverseBytes <= from.reverseBytes &&
    to.reverseCommands <= from.reverseCommands &&
    to.maxStreams <= from.maxStreams &&
    to.receiveFrames <= from.receiveFrames &&
    to.receiveBytes <= from.receiveBytes &&
    to.semanticOwnedBytes <= from.semanticOwnedBytes &&
    to.maxQueuedBytes <= from.maxQueuedBytes &&
    to.expiresAt <= from.expiresAt
  )
}

function same(value, other) {
  return b4a.equals(value, other)
}

function dummyPurposeTranscript(preTranscript, offerWire) {
  const acceptBody = b4a.alloc(260)
  try {
    return createPeerPurposeTranscript(preTranscript, offerWire, acceptBody)
  } finally {
    clear(acceptBody)
  }
}

function preKeys(shared, preTranscript, offerWire) {
  const transcript = dummyPurposeTranscript(preTranscript, offerWire)
  try {
    return derivePeerPurposeKeys(shared, preTranscript, transcript)
  } finally {
    clear(transcript)
  }
}

function purposeDigest(
  state,
  value,
  acceptDigest = state.acceptDigest,
  acceptNonce = state.acceptNonce
) {
  return createPeerPurposeDigest({
    tailControlTranscriptDigest: state.tailControlTranscriptDigest,
    terminalAdvertisementDigest: state.terminalAdvertisementDigest,
    routeId: state.id.routeId,
    circuitId: state.id.circuitId,
    generation: state.id.generation,
    purpose: state.id.purpose,
    sourceDirection: 0,
    offerDigest: state.offerDigest,
    acceptDigest,
    admittedForwardCells: value.forwardCells,
    admittedForwardBytes: value.forwardBytes,
    admittedForwardCommands: value.forwardCommands,
    admittedReverseCells: value.reverseCells,
    admittedReverseBytes: value.reverseBytes,
    admittedReverseCommands: value.reverseCommands,
    admittedMaxStreams: value.maxStreams,
    admittedReceiveFrames: value.receiveFrames,
    admittedReceiveBytes: value.receiveBytes,
    admittedSemanticOwnedBytes: value.semanticOwnedBytes,
    admittedMaxQueuedBytes: value.maxQueuedBytes,
    offerNonce: state.offerNonce,
    acceptNonce
  })
}

function preTranscript(state, offerBody) {
  return createPeerPurposePreTranscript({
    tailControlTranscriptDigest: state.tailControlTranscriptDigest,
    terminalAdvertisementDigest: state.terminalAdvertisementDigest,
    queryNonce: state.queryNonce,
    clientEphemeralPublicKey: state.clientEphemeralPublicKey,
    terminalRoutePublicKey: state.terminalRoutePublicKey,
    offerBody
  })
}

function createOwner(role, options) {
  if (!object(options)) invalid()
  let configuredOfferNonce
  let configuredAcceptNonce
  let configuredRejectNonce
  let id = null
  let routeCarrier = null
  let localLimits = null
  let parentWireExpiresAt = null
  let parentLocalDeadline = null
  let clockIdentity = null
  let random = null
  let tailControlTranscriptDigest = null
  let terminalAdvertisementDigest = null
  let queryNonce = null
  let terminalRoutePublicKey = null
  let clientEphemeralPublicKey = null
  let clientEphemeralSecret = null
  let terminalRouteSecretKey = null
  let finalKeySet = null
  let streamCallbacks = null
  let timing = null
  let resourceOptions = null
  let resources = null
  let owner = null
  let state = null
  try {
    configuredOfferNonce = optional(options, 'offerNonce')
    configuredAcceptNonce = optional(options, 'acceptNonce')
    configuredRejectNonce = optional(options, 'rejectNonce')
    id = identity(options)
    routeCarrier = carrier(own(options, 'carrier'))
    localLimits = validateLimits(own(options, 'limits'), id, role === 'source')
    parentWireExpiresAt = own(options, 'parentWireExpiresAt')
    parentLocalDeadline = own(options, 'parentLocalDeadline')
    if (!u64(parentWireExpiresAt, true) || !u64(parentLocalDeadline, true)) invalid()
    if (localLimits.expiresAt > parentWireExpiresAt) invalid()

    clockIdentity = own(options, 'clockIdentity')
    if (!object(clockIdentity)) invalid()
    random = own(options, 'randomBytes')
    if (typeof random !== 'function') invalid()

    tailControlTranscriptDigest = copy(own(options, 'tailControlTranscriptDigest'), 32)
    terminalAdvertisementDigest = copy(own(options, 'terminalAdvertisementDigest'), 32)
    queryNonce = copy(own(options, 'queryNonce'), 32)
    terminalRoutePublicKey = copy(own(options, 'terminalRoutePublicKey'), 32)
    clientEphemeralPublicKey = copy(own(options, 'clientEphemeralPublicKey'), 32)
    clientEphemeralSecret =
      role === 'source' ? copy(own(options, 'clientEphemeralSecret'), 32) : null
    terminalRouteSecretKey =
      role === 'terminal' ? copy(own(options, 'terminalRouteSecretKey'), 32) : null
    finalKeySet = finalKeys(own(options, 'finalizeKeys'))
    const streamCallbacksDescriptor = Object.getOwnPropertyDescriptor(options, 'streamCallbacks')
    let streamCallbacksValue = null
    if (streamCallbacksDescriptor !== undefined) {
      if (!Object.prototype.hasOwnProperty.call(streamCallbacksDescriptor, 'value')) invalid()
      streamCallbacksValue = streamCallbacksDescriptor.value
    }
    streamCallbacks = snapshotStreamCallbacks(streamCallbacksValue)

    timing = {
      wireExpiresAt: localLimits.expiresAt,
      localDeadline: parentLocalDeadline
    }
    const provisional = {
      carrier: routeCarrier,
      clock: routeCarrier.clock,
      wireExpiresAt: timing.wireExpiresAt,
      parentLocalDeadline
    }
    scheduleState(provisional)
    timing.localDeadline = provisional.localDeadline

    resourceOptions = {
      ledger: own(options, 'ledger'),
      memoryPool: own(options, 'memoryPool')
    }
    resources = role === 'source' ? reserveResources(resourceOptions, localLimits) : null
    owner = Object.freeze({})
    let activeResolve
    let activeReject
    const active = new Promise((resolve, reject) => {
      activeResolve = resolve
      activeReject = reject
    })
    active.catch(() => {})
    state = {
      role,
      owner,
      config: {
        offerNonce: configuredOfferNonce,
        acceptNonce: configuredAcceptNonce,
        rejectNonce: configuredRejectNonce
      },
      id,
      resourceOptions,
      carrier: routeCarrier,
      clock: routeCarrier.clock,
      clockIdentity,
      activeResolved: false,
      parentLocalDeadline,
      parentWireExpiresAt,
      wireExpiresAt: timing.wireExpiresAt,
      localDeadline: timing.localDeadline,
      randomBytes: random,
      streamCallbacks,
      tailControlTranscriptDigest,
      terminalAdvertisementDigest,
      queryNonce,
      terminalRoutePublicKey,
      clientEphemeralPublicKey,
      clientEphemeralSecret,
      terminalRouteSecretKey,
      finalKeys: finalKeySet,
      localLimits,
      acceptedLimits: null,
      resources,
      status: role === 'source' ? 'OFFER_PENDING' : 'WAITING_OFFER',
      started: false,
      destroyed: false,
      activated: false,
      receiveToken: null,
      pumpPromise: null,
      pumpPaused: false,
      pumpRestart: false,
      operationTrain: null,
      deadlineCancel: null,
      sentinelTrain: null,
      sentinelWire: null,
      finalizationTx: {
        source: new SenderCounter({ maximum: MAX_COUNTER }),
        terminal: new SenderCounter({ maximum: MAX_COUNTER })
      },
      finalizationRx: {
        source: new DatagramReplayWindow({ window: 64, maximum: MAX_COUNTER }),
        terminal: new DatagramReplayWindow({ window: 64, maximum: MAX_COUNTER })
      },
      routeTx: null,
      routeRx: null,
      lanes: null,
      streamTransport: null,
      preShared: null,
      preTranscript: null,
      keys: null,
      offerWire: null,
      offerBody: null,
      offerDigest: null,
      offerNonce: null,
      responseWire: null,
      acceptWire: null,
      acceptBody: null,
      acceptDigest: null,
      acceptNonce: null,
      purposeDigest: null,
      sourceConfirmDigest: null,
      terminalConfirmDigest: null,
      finalTranscriptDigest: null,
      active,
      activeResolve,
      activeReject
    }
    if (role === 'source') prepareSource(state)
    STATES.set(owner, state)
    return facade(owner)
  } catch (err) {
    if (owner) STATES.delete(owner)
    if (state) {
      erasePreShared(state)
      clear(state.preTranscript)
      clear(state.offerWire)
      clear(state.offerBody)
      clear(state.offerDigest)
      clear(state.offerNonce)
      clear(state.responseWire)
      clear(state.acceptWire)
      clear(state.acceptBody)
      clear(state.acceptDigest)
      clear(state.acceptNonce)
      clear(state.purposeDigest)
      clear(state.sourceConfirmDigest)
      clear(state.terminalConfirmDigest)
      clear(state.finalTranscriptDigest)
      clearPeerPurposeKeys(state.keys)
      clear(state.id.routeId)
      clear(state.id.circuitId)
    } else if (id) {
      clear(id.routeId)
      clear(id.circuitId)
    }
    if (resources) {
      releasePeerMemory(resources.memory)
      releasePeerLedger(resources.forward)
      releasePeerLedger(resources.reverse)
    }
    clearFinalKeys(finalKeySet)
    for (const value of [
      tailControlTranscriptDigest,
      terminalAdvertisementDigest,
      queryNonce,
      terminalRoutePublicKey,
      clientEphemeralPublicKey,
      clientEphemeralSecret,
      terminalRouteSecretKey
    ])
      clear(value)
    throw err
  }
}

function prepareSource(state) {
  const offerNonce = randomBytes(state, 'offerNonce', 16)
  const fields = {
    routeId: state.id.routeId,
    circuitId: state.id.circuitId,
    generation: state.id.generation,
    purpose: state.id.purpose,
    sourceDirection: 0,
    flags: 0,
    expiresAt: state.localLimits.expiresAt,
    terminalAdvertisementDigest: state.terminalAdvertisementDigest,
    queryNonce: state.queryNonce,
    clientEphemeralPublicKey: state.clientEphemeralPublicKey,
    forwardCells: state.localLimits.forwardCells,
    forwardBytes: state.localLimits.forwardBytes,
    forwardCommands: state.localLimits.forwardCommands,
    reverseCells: state.localLimits.reverseCells,
    reverseBytes: state.localLimits.reverseBytes,
    reverseCommands: state.localLimits.reverseCommands,
    maxStreams: state.localLimits.maxStreams,
    receiveFrames: state.localLimits.receiveFrames,
    receiveBytes: state.localLimits.receiveBytes,
    semanticOwnedBytes: state.localLimits.semanticOwnedBytes,
    maxQueuedBytes: state.localLimits.maxQueuedBytes,
    offerNonce
  }
  let unsigned = null
  let shared = null
  let transcript = null
  let keys = null
  let body = null
  try {
    unsigned = makeUnsigned(PEER_MESSAGE_ID.PEER_ROUTE_OFFER_V2, fields)
    body = copy(unsigned.subarray(8, 8 + 212))
    transcript = preTranscript(state, body)
    shared = derivePeerPurposeSharedSecret(
      state.clientEphemeralSecret,
      state.terminalRoutePublicKey
    )
    keys = preKeys(shared, transcript, unsigned)
    const wire = makeMacWire(PEER_MESSAGE_ID.PEER_ROUTE_OFFER_V2, fields, keys.preSourceMacKey)
    state.offerWire = wire
    state.offerBody = body
    body = null
    state.offerDigest = digestPeerPurposeOffer(wire)
    state.offerNonce = copy(offerNonce)
    state.preShared = shared
    state.preTranscript = transcript
    state.status = 'OFFER_PENDING'
    shared = null
    transcript = null
    keys = null
  } finally {
    clear(unsigned)
    clear(offerNonce)
    clear(shared)
    clear(transcript)
    clear(body)
    clearPeerPurposeKeys(keys)
  }
}

function facade(owner) {
  return Object.freeze({
    start() {
      return start(owner)
    },
    whenActive() {
      return live(owner).active
    },
    diagnostics() {
      const state = live(owner)
      return Object.freeze({
        role: state.role,
        status: state.status,
        attempts: state.operationTrain ? state.operationTrain.attempts : 0,
        sentinelAttempts: state.sentinelTrain ? state.sentinelTrain.attempts : 0,
        wireExpiresAt: state.wireExpiresAt,
        localDeadline: state.localDeadline,
        activated: state.activated,
        active: state.status === 'ACTIVE'
      })
    },
    route() {
      return route(owner)
    },
    transport() {
      const state = live(owner)
      if (state.status !== 'ACTIVE') throw PrivateRouteError.CIRCUIT_STATE()
      ensureLanes(state)
      return state.streamTransport
    },
    destroy(error) {
      return destroyOwner(owner, error)
    }
  })
}

function live(owner) {
  const state = STATES.get(owner)
  if (!state || state.destroyed || DESTROYED.has(owner)) destroyed()
  return state
}

function start(owner) {
  const state = live(owner)
  if (state.started) replay()
  state.started = true
  if (state.role === 'source') {
    state.status = 'OFFER_SENT'
    state.operationTrain = train(
      state,
      'offer',
      () => sendFinalize(state, state.offerWire, 'source'),
      () => fail(state)
    )
    state.operationTrain.attempt()
  }
  startPump(state)
  return true
}
function startPump(state) {
  if (state.destroyed || state.status === 'TERMINAL_SENTINEL_PENDING') return
  if (state.pumpPromise) {
    state.pumpRestart = true
    return
  }
  state.pumpPaused = false
  state.pumpRestart = false
  const promise = pump(state)
  state.pumpPromise = promise
  promise.then(
    () => {
      if (state.pumpPromise !== promise) return
      state.pumpPromise = null
      if (state.pumpRestart && !state.destroyed) {
        state.pumpRestart = false
        startPump(state)
      }
    },
    (error) => {
      if (state.pumpPromise !== promise) return
      state.pumpPromise = null
      if (!state.destroyed) destroyOwner(state.owner, error)
    }
  )
}

async function pump(state) {
  while (!state.destroyed && state.status !== 'TERMINAL_SENTINEL_PENDING') {
    let token = null
    try {
      token = state.carrier.reserveReceive()
      state.receiveToken = token
      const envelope = await state.carrier.receiveEnvelope(token)
      state.receiveToken = null
      await processEnvelope(state, envelope)
    } catch (error) {
      if (state.destroyed) return
      if (error instanceof PrivateRouteError && error.code === 'ERR_REPLAY') continue
      destroyOwner(state.owner, error)
      return
    } finally {
      if (token !== null && state.receiveToken === token) {
        state.receiveToken = null
        try {
          state.carrier.cancelReceive(token)
        } catch {}
      }
    }
  }
  if (!state.destroyed && state.status === 'TERMINAL_SENTINEL_PENDING') state.pumpPaused = true
}

async function processEnvelope(state, envelope) {
  if (!object(envelope)) invalid()
  const contextClass = own(envelope, 'contextClass')
  const frame = own(envelope, 'frame')
  if (!fixed(frame, 1100)) invalid()
  if (contextClass === 5) return processFinalize(state, frame)
  if (contextClass === 6) return processRoute(state, frame)
  invalid()
}

function frameCounter(frame) {
  if (typeof frame.readBigUInt64BE !== 'function') invalid()
  return frame.readBigUInt64BE(0)
}

function processFinalize(state, frame) {
  const remote = state.role === 'source' ? 'terminal' : 'source'
  const direction = state.role === 'source' ? 1 : 0
  const key =
    direction === 0 ? state.finalKeys.finalizeForwardKey : state.finalKeys.finalizeReverseKey
  const noncePrefix =
    direction === 0
      ? state.finalKeys.finalizeForwardNoncePrefix
      : state.finalKeys.finalizeReverseNoncePrefix
  const counter = frameCounter(frame)
  const opened = openPeerContextFrame(
    {
      contextClass: 5,
      circuitId: state.id.circuitId,
      generation: state.id.generation,
      direction,
      counter,
      key,
      noncePrefix
    },
    frame
  )
  try {
    state.finalizationRx[remote].acceptAuthenticated(opened.counter)
    const payload = copy(opened.payload)
    let decoded = null
    try {
      decoded = decodeWire(payload)
      if (state.role === 'terminal') handleOffer(state, decoded, payload)
      else handleAccept(state, decoded, payload)
    } finally {
      if (decoded) {
        clear(decoded.body)
        clear(decoded.authSuffix)
      }
      clear(payload)
    }
  } finally {
    clear(opened.plaintext)
  }
}
function streamHook(state, name) {
  const callbacks = state.streamCallbacks
  if (!callbacks) return null
  const descriptor = Object.getOwnPropertyDescriptor(callbacks, name)
  if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) return null
  return typeof descriptor.value === 'function' ? descriptor.value : null
}

function callStreamHook(state, name, args) {
  const hook = streamHook(state, name)
  if (!hook) return undefined
  try {
    return hook(...args)
  } catch {
    return undefined
  }
}

function ensureLanes(state) {
  if (state.lanes) return
  if (!streamHook(state, 'onAdmit') || !streamHook(state, 'onDeliver')) invalid()
  const lanes = new PeerReliableLanes({
    routeId: state.id.routeId,
    generation: state.id.generation,
    purpose: state.id.purpose,
    localDirection: state.role === 'source' ? 0 : 1,
    clockIdentity: state.clockIdentity,
    monotonicNow: state.clock.monotonicNow,
    schedule: (delay, callback) => state.carrier.schedule(delay, callback),
    localDeadline: state.localDeadline,
    onTransmit: (payload) => sendRoute(state, payload, state.role),
    onAdmit: (meta, nested) => callStreamHook(state, 'onAdmit', [meta, nested]) === true,
    onDeliver: (meta, nested) => callStreamHook(state, 'onDeliver', [meta, nested]) === true,
    onAcknowledged: (meta) => {
      callStreamHook(state, 'onAcknowledged', [meta])
    },
    onConflict: (meta) => {
      callStreamHook(state, 'onConflict', [meta])
    },
    onFailure: (error) => {
      callStreamHook(state, 'onFailure', [error])
      if (!state.destroyed) destroyOwner(state.owner, error)
    },
    onWritable: () => {
      callStreamHook(state, 'onWritable', [])
    }
  })
  state.lanes = lanes
  state.streamTransport = Object.freeze({
    trySend(nested) {
      const current = live(state.owner)
      if (current.status !== 'ACTIVE') throw PrivateRouteError.CIRCUIT_STATE()
      return current.lanes.trySend(nested)
    },
    drain() {
      const current = live(state.owner)
      current.lanes.drain()
    },
    isCumulativelyAcknowledged(lane, sequence) {
      const current = live(state.owner)
      return current.lanes.isCumulativelyAcknowledged(lane, sequence)
    },
    releaseRegistrationControlReservation() {
      const current = live(state.owner)
      current.lanes.releaseRegistrationControlReservation()
    },
    destroy(error) {
      const current = live(state.owner)
      current.lanes.destroy(error)
    }
  })
}

function processRoute(state, frame) {
  if (!state.keys || !state.routeRx) authentication()
  const direction = state.role === 'source' ? 1 : 0
  const key = direction === 0 ? state.keys.forwardKey : state.keys.reverseKey
  const noncePrefix =
    direction === 0 ? state.keys.forwardNoncePrefix : state.keys.reverseNoncePrefix
  const counter = frameCounter(frame)
  const opened = openPeerContextFrame(
    {
      contextClass: 6,
      routeId: state.id.routeId,
      circuitId: state.id.circuitId,
      generation: state.id.generation,
      purpose: state.id.purpose,
      direction,
      counter,
      key,
      noncePrefix
    },
    frame
  )
  try {
    state.routeRx.acceptAuthenticated(opened.counter)
    const payload = copy(opened.payload)
    let decoded = null
    try {
      decoded = decodeWire(payload)
      const isSentinel =
        decoded.messageId === PEER_MESSAGE_ID.PEER_RELIABLE_ACK_V2 && sentinel(decoded, state.id)
      if (
        !isSentinel &&
        (decoded.messageId === PEER_MESSAGE_ID.PEER_RELIABLE_PACKET_V2 ||
          decoded.messageId === PEER_MESSAGE_ID.PEER_RELIABLE_ACK_V2)
      ) {
        if (state.status !== 'ACTIVE') replay()
        if (
          decoded.messageId === PEER_MESSAGE_ID.PEER_RELIABLE_ACK_V2 &&
          decoded.fields.ackSnapshot === 0
        )
          authentication()
        if (!state.lanes) authentication()
        state.lanes.receive(payload)
        return
      }
      if (!isSentinel) authentication()
      if (state.role === 'source') {
        if (state.status !== 'SOURCE_SENTINEL') replay()
        state.terminalConfirmDigest = digestPeerPurposeConfirmation('terminal', decoded.body)
        erasePreShared(state)
        stop(state.sentinelTrain)
        complete(state)
      } else {
        if (state.status !== 'TERMINAL_WAIT_SOURCE') replay()
        state.sourceConfirmDigest = digestPeerPurposeConfirmation('source', decoded.body)
        erasePreShared(state)
        sendTerminalSentinel(state)
      }
    } finally {
      if (decoded) {
        clear(decoded.body)
        clear(decoded.authSuffix)
      }
      clear(payload)
    }
  } finally {
    clear(opened.plaintext)
  }
}

function verifyOfferIdentity(state, fields) {
  if (
    !same(fields.routeId, state.id.routeId) ||
    !same(fields.circuitId, state.id.circuitId) ||
    fields.generation !== state.id.generation ||
    fields.purpose !== state.id.purpose ||
    fields.sourceDirection !== 0 ||
    !same(fields.terminalAdvertisementDigest, state.terminalAdvertisementDigest) ||
    !same(fields.queryNonce, state.queryNonce) ||
    !same(fields.clientEphemeralPublicKey, state.clientEphemeralPublicKey)
  )
    authentication()
}

function handleOffer(state, decoded, payload) {
  if (decoded.messageId !== PEER_MESSAGE_ID.PEER_ROUTE_OFFER_V2) authentication()
  if (state.offerWire) {
    if (same(state.offerWire, payload)) {
      if (state.operationTrain) state.operationTrain.attempt()
      return
    }
    destroyOwner(state.owner, PrivateRouteError.ERR_REPLAY())
    replay()
  }
  if (state.status !== 'WAITING_OFFER') replay()
  verifyOfferIdentity(state, decoded.fields)

  let offerWire = null
  let offerBody = null
  let shared = null
  let transcript = null
  let pre = null
  let acceptNonce = null
  let acceptUnsigned = null
  let purpose = null
  let keys = null
  let acceptWire = null
  let pendingResources = null
  try {
    offerWire = copy(payload)
    offerBody = copy(decoded.body)
    shared = derivePeerPurposeSharedSecret(
      state.terminalRouteSecretKey,
      state.clientEphemeralPublicKey
    )
    transcript = preTranscript(state, offerBody)
    pre = preKeys(shared, transcript, offerWire)
    if (
      !verifyPeerPurposeMac(
        pre.preSourceMacKey,
        payload.subarray(0, payload.byteLength - 16),
        decoded.authSuffix
      )
    ) {
      authentication()
    }

    const offered = offerLimits(decoded.fields)
    let accepted
    try {
      accepted = chooseAccepted(state, offered)
    } catch (error) {
      if (!(error instanceof PrivateRouteError)) throw error
      cacheReject(state, offerWire, offerBody, decoded.fields, pre.preTerminalMacKey, 1)
      return
    }

    try {
      pendingResources = reserveResources(state.resourceOptions, accepted)
    } catch (error) {
      if (!(error instanceof PrivateRouteError)) throw error
      cacheReject(state, offerWire, offerBody, decoded.fields, pre.preTerminalMacKey, 2)
      return
    }

    acceptNonce = randomBytes(state, 'acceptNonce', 16)
    const fields = {
      routeId: decoded.fields.routeId,
      circuitId: decoded.fields.circuitId,
      generation: decoded.fields.generation,
      purpose: decoded.fields.purpose,
      sourceDirection: 0,
      flags: 0,
      expiresAt: accepted.expiresAt,
      terminalAdvertisementDigest: decoded.fields.terminalAdvertisementDigest,
      queryNonce: decoded.fields.queryNonce,
      clientEphemeralPublicKey: decoded.fields.clientEphemeralPublicKey,
      offerDigest: digestPeerPurposeOffer(offerWire),
      admittedForwardCells: accepted.forwardCells,
      admittedForwardBytes: accepted.forwardBytes,
      admittedForwardCommands: accepted.forwardCommands,
      admittedReverseCells: accepted.reverseCells,
      admittedReverseBytes: accepted.reverseBytes,
      admittedReverseCommands: accepted.reverseCommands,
      admittedMaxStreams: accepted.maxStreams,
      admittedReceiveFrames: accepted.receiveFrames,
      admittedReceiveBytes: accepted.receiveBytes,
      admittedSemanticOwnedBytes: accepted.semanticOwnedBytes,
      admittedMaxQueuedBytes: accepted.maxQueuedBytes,
      offerNonce: decoded.fields.offerNonce,
      acceptNonce
    }
    acceptUnsigned = makeUnsigned(PEER_MESSAGE_ID.PEER_ROUTE_ACCEPT_V2, fields)
    purpose = createPeerPurposeTranscript(
      transcript,
      offerWire,
      acceptUnsigned.subarray(8, acceptUnsigned.byteLength - 16)
    )
    keys = derivePeerPurposeKeys(shared, transcript, purpose)
    acceptWire = makeMacWire(PEER_MESSAGE_ID.PEER_ROUTE_ACCEPT_V2, fields, keys.preTerminalMacKey)

    chargePeerLedger(pendingResources.forward, { cells: 0, bytes: 0n, commands: 1 })
    state.resources = pendingResources
    pendingResources = null
    state.wireExpiresAt = accepted.expiresAt
    scheduleState(state)
    state.offerWire = copy(offerWire)
    state.offerBody = copy(offerBody)
    state.offerDigest = digestPeerPurposeOffer(offerWire)
    state.offerNonce = copy(decoded.fields.offerNonce)
    state.preShared = copy(shared)
    state.preTranscript = copy(transcript)
    state.acceptWire = acceptWire
    acceptWire = null
    state.acceptBody = copy(acceptUnsigned.subarray(8, acceptUnsigned.byteLength - 16))
    state.acceptDigest = digestPeerPurposeAccept(state.acceptWire)
    state.acceptNonce = copy(acceptNonce)
    state.acceptedLimits = accepted
    state.purposeDigest = purposeDigest(state, accepted)
    state.keys = keys
    keys = null
    state.routeTx = new SenderCounter({ maximum: MAX_COUNTER })
    state.routeRx = new DatagramReplayWindow({ window: 64, maximum: MAX_COUNTER })
    state.status = 'TERMINAL_WAIT_SOURCE'
    state.operationTrain = train(
      state,
      'accept',
      () => sendFinalize(state, state.acceptWire, 'terminal'),
      () => fail(state)
    )
    state.operationTrain.attempt()
  } finally {
    if (pendingResources) {
      releasePeerMemory(pendingResources.memory)
      releasePeerLedger(pendingResources.forward)
      releasePeerLedger(pendingResources.reverse)
    }
    clear(offerWire)
    clear(offerBody)
    clear(shared)
    clear(transcript)
    clear(acceptNonce)
    clear(acceptUnsigned)
    clear(purpose)
    clear(acceptWire)
    clearPeerPurposeKeys(pre)
    clearPeerPurposeKeys(keys)
  }
}
function handleReject(state, decoded, payload) {
  if (
    !same(decoded.fields.routeId, state.id.routeId) ||
    decoded.fields.generation !== state.id.generation ||
    decoded.fields.purpose !== state.id.purpose ||
    !zero(decoded.fields.reserved3) ||
    !same(decoded.fields.offerNonce, state.offerNonce)
  )
    authentication()
  const pre = preKeys(state.preShared, state.preTranscript, state.offerWire)
  try {
    if (
      !verifyPeerPurposeMac(
        pre.preTerminalMacKey,
        payload.subarray(0, payload.byteLength - PURPOSE_MAC_BYTES),
        decoded.authSuffix
      )
    )
      authentication()
    const error =
      decoded.fields.reason === 2
        ? PrivateRouteError.ERR_QUOTA_EXCEEDED()
        : PrivateRouteError.ERR_AUTHENTICATION()
    destroyOwner(state.owner, error)
  } finally {
    clearPeerPurposeKeys(pre)
  }
}

function cacheReject(state, offerWire, offerBody, fields, macKey, reason) {
  let rejectNonce = null
  let rejectWire = null
  try {
    rejectNonce = randomBytes(state, 'rejectNonce', 16)
    rejectWire = makeMacWire(
      PEER_MESSAGE_ID.PEER_ROUTE_REJECT_V2,
      {
        routeId: fields.routeId,
        generation: fields.generation,
        purpose: fields.purpose,
        reserved3: ZERO3,
        offerNonce: fields.offerNonce,
        reason,
        reserved: 0,
        rejectNonce
      },
      macKey
    )
    state.offerWire = copy(offerWire)
    state.offerBody = copy(offerBody)
    state.offerDigest = digestPeerPurposeOffer(offerWire)
    state.offerNonce = copy(fields.offerNonce)
    state.responseWire = rejectWire
    rejectWire = null
    state.status = 'TERMINAL_REJECT'
    state.operationTrain = train(
      state,
      'reject',
      () => sendFinalize(state, state.responseWire, 'terminal'),
      () => fail(state)
    )
    state.operationTrain.attempt()
  } finally {
    clear(rejectNonce)
    clear(rejectWire)
  }
}

function chooseAccepted(state, offered) {
  const accepted = {}
  for (const name of LIMIT_NAMES) {
    if (name !== 'forwardBytes' && name !== 'reverseBytes' && name !== 'expiresAt') {
      accepted[name] = Math.min(offered[name], state.localLimits[name])
    }
  }
  accepted.expiresAt = minBigInt(offered.expiresAt, state.localLimits.expiresAt)
  accepted.forwardBytes = minBigInt(offered.forwardBytes, state.localLimits.forwardBytes)
  accepted.reverseBytes = minBigInt(offered.reverseBytes, state.localLimits.reverseBytes)
  validateLimits(accepted, state.id, false)
  if (!down(offered, accepted) || !down(state.localLimits, accepted)) invalid()
  return accepted
}

function verifyAcceptIdentity(state, fields) {
  if (
    !same(fields.routeId, state.id.routeId) ||
    !same(fields.circuitId, state.id.circuitId) ||
    fields.generation !== state.id.generation ||
    fields.purpose !== state.id.purpose ||
    fields.sourceDirection !== 0 ||
    !same(fields.terminalAdvertisementDigest, state.terminalAdvertisementDigest) ||
    !same(fields.queryNonce, state.queryNonce) ||
    !same(fields.clientEphemeralPublicKey, state.clientEphemeralPublicKey) ||
    !same(fields.offerNonce, state.offerNonce) ||
    !same(fields.offerDigest, state.offerDigest)
  )
    authentication()
}

function handleAccept(state, decoded, payload) {
  if (decoded.messageId === PEER_MESSAGE_ID.PEER_ROUTE_REJECT_V2)
    return handleReject(state, decoded, payload)
  if (decoded.messageId !== PEER_MESSAGE_ID.PEER_ROUTE_ACCEPT_V2) authentication()
  if (state.acceptWire) {
    if (same(state.acceptWire, payload)) {
      if (state.sentinelTrain) state.sentinelTrain.attempt()
      return
    }
    destroyOwner(state.owner, PrivateRouteError.ERR_REPLAY())
    replay()
  }
  if (state.status !== 'OFFER_SENT') replay()
  verifyAcceptIdentity(state, decoded.fields)
  const accepted = acceptLimits(decoded.fields)
  if (!down(state.localLimits, accepted)) invalid()
  validateLimits(accepted, state.id, true)
  let acceptBody = null
  let acceptWire = null
  let purpose = null
  let keys = null
  let acceptDigest = null
  let acceptNonce = null
  let acceptedPurposeDigest = null
  let routeTx = null
  let routeRx = null
  try {
    acceptBody = copy(decoded.body)
    acceptWire = copy(payload)
    purpose = createPeerPurposeTranscript(state.preTranscript, state.offerWire, acceptBody)
    keys = derivePeerPurposeKeys(state.preShared, state.preTranscript, purpose)
    if (
      !verifyPeerPurposeMac(
        keys.preTerminalMacKey,
        payload.subarray(0, payload.byteLength - 16),
        decoded.authSuffix
      )
    ) {
      authentication()
    }
    narrowResources(state, accepted)
    state.wireExpiresAt = accepted.expiresAt
    scheduleState(state)
    acceptDigest = digestPeerPurposeAccept(acceptWire)
    acceptNonce = copy(decoded.fields.acceptNonce)
    acceptedPurposeDigest = purposeDigest(state, accepted, acceptDigest, acceptNonce)
    routeTx = new SenderCounter({ maximum: MAX_COUNTER })
    routeRx = new DatagramReplayWindow({ window: 64, maximum: MAX_COUNTER })
    state.acceptWire = acceptWire
    acceptWire = null
    state.acceptBody = acceptBody
    acceptBody = null
    state.acceptDigest = acceptDigest
    acceptDigest = null
    state.acceptNonce = acceptNonce
    acceptNonce = null
    state.acceptedLimits = accepted
    state.purposeDigest = acceptedPurposeDigest
    acceptedPurposeDigest = null
    state.keys = keys
    keys = null
    state.routeTx = routeTx
    routeTx = null
    state.routeRx = routeRx
    routeRx = null
    state.status = 'SOURCE_SENTINEL'
    stop(state.operationTrain)
    sendSourceSentinel(state)
  } catch (error) {
    clear(acceptWire)
    clear(acceptBody)
    clear(acceptDigest)
    clear(acceptNonce)
    clear(acceptedPurposeDigest)
    clearPeerPurposeKeys(keys)
    throw error
  } finally {
    clear(purpose)
  }
}

function requireTransportAcceptance(value) {
  if (value !== true)
    throw new PeerPurposeTransportFailure(PrivateRouteError.ERR_PRIVACY_UNAVAILABLE())
  return true
}

function sendFinalize(state, payload, sender) {
  const direction = sender === 'source' ? 0 : 1
  const key =
    direction === 0 ? state.finalKeys.finalizeForwardKey : state.finalKeys.finalizeReverseKey
  const noncePrefix =
    direction === 0
      ? state.finalKeys.finalizeForwardNoncePrefix
      : state.finalKeys.finalizeReverseNoncePrefix
  let frame = null
  try {
    const counter = state.finalizationTx[sender].next()
    frame = sealPeerContextFrame({
      contextClass: 5,
      circuitId: state.id.circuitId,
      generation: state.id.generation,
      direction,
      counter,
      key,
      noncePrefix,
      payload
    })
  } catch (error) {
    clear(frame)
    throw new PeerPurposeSealFailure(error)
  }
  try {
    chargeSend(state, direction)
  } catch (error) {
    clear(frame)
    throw error
  }
  try {
    const result = state.carrier.sendFinalizeFrame(frame)
    return Promise.resolve(result)
      .then(requireTransportAcceptance)
      .finally(() => clear(frame))
  } catch (error) {
    clear(frame)
    throw new PeerPurposeTransportFailure(error)
  }
}

function activate(state) {
  if (state.activated) return
  state.carrier.activate()
  state.activated = true
}

function sendSourceSentinel(state) {
  state.sentinelWire = encodePeerTransport(
    PEER_MESSAGE_ID.PEER_RELIABLE_ACK_V2,
    ackFields(state.id)
  )
  state.sourceConfirmDigest = digestPeerPurposeConfirmation(
    'source',
    state.sentinelWire.subarray(8)
  )
  activate(state)
  state.sentinelTrain = train(
    state,
    'source-sentinel',
    () => sendRoute(state, state.sentinelWire, 'source'),
    () => {
      if (state.status !== 'ACTIVE') fail(state)
    }
  )
  state.sentinelTrain.attempt()
}

function sendTerminalSentinel(state) {
  stop(state.operationTrain)
  state.sentinelWire = encodePeerTransport(
    PEER_MESSAGE_ID.PEER_RELIABLE_ACK_V2,
    ackFields(state.id)
  )
  state.terminalConfirmDigest = digestPeerPurposeConfirmation(
    'terminal',
    state.sentinelWire.subarray(8)
  )
  complete(state, false)
  state.status = 'TERMINAL_SENTINEL_PENDING'
  if (state.destroyed) return
  try {
    activate(state)
  } catch (error) {
    destroyOwner(state.owner, error)
    return
  }
  state.sentinelTrain = train(
    state,
    'terminal-sentinel',
    () => sendRoute(state, state.sentinelWire, 'terminal'),
    () => {
      if (!state.activeResolved && !state.destroyed) fail(state)
    },
    () => {
      if (!state.activeResolved && !state.destroyed) publishActive(state, true)
    }
  )
  state.sentinelTrain.attempt()
}
function sendRoute(state, payload, sender) {
  const direction = sender === 'source' ? 0 : 1
  const key = direction === 0 ? state.keys.forwardKey : state.keys.reverseKey
  const noncePrefix =
    direction === 0 ? state.keys.forwardNoncePrefix : state.keys.reverseNoncePrefix
  let frame = null
  try {
    const counter = state.routeTx.next()
    frame = sealPeerContextFrame({
      contextClass: 6,
      routeId: state.id.routeId,
      circuitId: state.id.circuitId,
      generation: state.id.generation,
      purpose: state.id.purpose,
      direction,
      counter,
      key,
      noncePrefix,
      payload
    })
  } catch (error) {
    clear(frame)
    throw new PeerPurposeSealFailure(error)
  }
  try {
    chargeSend(state, direction)
  } catch (error) {
    clear(frame)
    throw error
  }
  try {
    const result = state.carrier.sendFrame(frame)
    return Promise.resolve(result)
      .then(requireTransportAcceptance)
      .finally(() => clear(frame))
  } catch (error) {
    clear(frame)
    throw new PeerPurposeTransportFailure(error)
  }
}

function train(state, name, send, exhausted, onSent = null) {
  const value = {
    name,
    attempts: 0,
    remaining: MAX_ATTEMPTS,
    startedAt: null,
    deadline: null,
    timerCancel: null,
    settled: false,
    lastSent: false,
    lastError: null,
    attempt() {
      if (value.settled) return false
      let now
      try {
        now = state.clock.monotonicNow()
      } catch {
        value.settled = true
        exhausted()
        return false
      }
      if (!u64(now) || now >= state.localDeadline) {
        value.settled = true
        exhausted()
        return false
      }
      if (value.startedAt === null) {
        value.startedAt = now
        value.deadline = minBigInt(state.localDeadline, addU64(now, OPERATION_TIMEOUT_MS))
      }
      if (value.remaining === 0 || now >= value.deadline) {
        value.settled = true
        exhausted()
        return false
      }
      value.attempts++
      value.remaining--
      value.lastSent = false
      const accepted = () => {
        if (
          value.settled ||
          state.destroyed ||
          (state.operationTrain !== value && state.sentinelTrain !== value)
        )
          return
        value.lastSent = true
        if (!onSent) return
        try {
          onSent()
        } catch (error) {
          value.lastError = error.cause || error
          value.settled = true
          exhausted()
        }
      }
      try {
        const result = send(value.attempts === 1)
        if (result && typeof result.then === 'function') {
          Promise.resolve(result).then(accepted, (error) => {
            if (
              value.settled ||
              state.destroyed ||
              (state.operationTrain !== value && state.sentinelTrain !== value)
            )
              return
            value.lastError = error.cause || error
          })
        } else {
          accepted()
        }
      } catch (error) {
        value.lastError = error.cause || error
        if (error instanceof PeerPurposeLedgerFailure) {
          value.settled = true
          destroyOwner(
            state.owner,
            error.cause instanceof PrivateRouteError
              ? error.cause
              : PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
          )
          return false
        }
        if (error instanceof PeerPurposeSealFailure) {
          value.settled = true
          exhausted()
          return false
        }
      }
      if (state.destroyed || value.settled) return false
      if (value.remaining === 0) return armDeadline(state, value, exhausted)
      return armRetry(state, value, exhausted)
    },
    stop() {
      if (value.settled) return false
      value.settled = true
      if (value.timerCancel) {
        try {
          value.timerCancel()
        } catch {}
        value.timerCancel = null
      }
      return true
    }
  }
  return value
}

function armRetry(state, value, exhausted) {
  if (value.timerCancel) {
    try {
      value.timerCancel()
    } catch {}
    value.timerCancel = null
  }
  let fired = false
  let cancel = null
  try {
    cancel = state.carrier.schedule(RETRY_INTERVAL_MS, () => {
      fired = true
      value.timerCancel = null
      if (!state.destroyed && !value.settled) value.attempt()
    })
  } catch (error) {
    value.settled = true
    destroyOwner(state.owner, error)
    return false
  }
  if (fired || state.destroyed || value.settled) {
    if ((state.destroyed || value.settled) && typeof cancel === 'function') {
      try {
        cancel()
      } catch {}
    }
    return !state.destroyed && !value.settled
  }
  value.timerCancel = cancel
  return true
}

function armDeadline(state, value, exhausted) {
  const remaining = value.deadline - state.clock.monotonicNow()
  if (remaining <= 0n) {
    value.settled = true
    exhausted()
    return false
  }
  if (value.timerCancel) {
    try {
      value.timerCancel()
    } catch {}
    value.timerCancel = null
  }
  let fired = false
  let cancel = null
  try {
    cancel = state.carrier.schedule(Number(remaining), () => {
      fired = true
      value.timerCancel = null
      if (value.settled) return
      value.settled = true
      exhausted()
    })
  } catch (error) {
    value.settled = true
    destroyOwner(state.owner, error)
    return false
  }
  if (fired || state.destroyed || value.settled) {
    if ((state.destroyed || value.settled) && typeof cancel === 'function') {
      try {
        cancel()
      } catch {}
    }
    return !state.destroyed && !value.settled
  }
  value.timerCancel = cancel
  return true
}

function stop(value) {
  if (value) value.stop()
}

function fail(state) {
  if (!state.destroyed) destroyOwner(state.owner, PrivateRouteError.ERR_PRIVACY_UNAVAILABLE())
}

function complete(state, resolve = true) {
  if (state.status === 'ACTIVE' || state.destroyed) return
  if (!state.sourceConfirmDigest || !state.terminalConfirmDigest) return
  state.finalTranscriptDigest = createPeerPurposeFinalTranscript({
    tailControlTranscriptDigest: state.tailControlTranscriptDigest,
    purposeDigest: state.purposeDigest,
    offerDigest: state.offerDigest,
    acceptDigest: state.acceptDigest,
    sourceConfirmDigest: state.sourceConfirmDigest,
    terminalConfirmDigest: state.terminalConfirmDigest
  })
  if (!state.resources.memoryOwner)
    state.resources.memoryOwner = takePeerMemory(state.resources.memory)
  if (state.streamCallbacks) ensureLanes(state)
  if (resolve) publishActive(state)
}

function publishActive(state, resumePump = false) {
  if (state.destroyed || state.status === 'ACTIVE') return
  if (!armActiveDeadline(state)) return
  if (state.destroyed) return
  state.status = 'ACTIVE'
  if (resumePump) startPump(state)
  state.activeResolved = true
  state.activeResolve(route(state.owner))
}

function armActiveDeadline(state) {
  if (state.deadlineCancel) {
    try {
      state.deadlineCancel()
    } catch {}
    state.deadlineCancel = null
  }
  const remaining = state.localDeadline - state.clock.monotonicNow()
  if (remaining <= 0n) {
    destroyOwner(state.owner, PrivateRouteError.ERR_PRIVACY_UNAVAILABLE())
    return false
  }
  if (remaining > BigInt(Number.MAX_SAFE_INTEGER)) invalid()
  let cancel
  try {
    cancel = state.carrier.schedule(Number(remaining), () => {
      state.deadlineCancel = null
      if (!state.destroyed) destroyOwner(state.owner, PrivateRouteError.ERR_PRIVACY_UNAVAILABLE())
    })
  } catch (error) {
    destroyOwner(state.owner, error)
    return false
  }
  if (state.destroyed) {
    try {
      cancel()
    } catch {}
    return false
  }
  state.deadlineCancel = cancel
  return true
}
function route(owner) {
  const state = live(owner)
  if (state.status !== 'ACTIVE') throw PrivateRouteError.CIRCUIT_STATE()
  return Object.freeze({
    routeOwner: owner,
    role: state.role,
    routeId: copy(state.id.routeId),
    circuitId: copy(state.id.circuitId),
    generation: state.id.generation,
    purpose: state.id.purpose,
    purposeDigest: copy(state.purposeDigest),
    finalTranscriptDigest: copy(state.finalTranscriptDigest),
    wireExpiresAt: state.wireExpiresAt,
    localDeadline: state.localDeadline,
    clockIdentity: state.clockIdentity,
    limits: Object.freeze({ ...state.acceptedLimits }),
    schedule: (delay, callback) => state.carrier.schedule(delay, callback),
    wallNow: state.clock.wallNow,
    monotonicNow: state.clock.monotonicNow
  })
}

function destroyOwner(owner, error = PrivateRouteError.ERR_DESTROYED()) {
  const state = STATES.get(owner)
  if (!state || state.destroyed) return false
  state.destroyed = true
  state.status = 'DESTROYED'
  stop(state.operationTrain)
  stop(state.sentinelTrain)
  if (state.deadlineCancel) {
    try {
      state.deadlineCancel()
    } catch {}
    state.deadlineCancel = null
  }
  if (state.receiveToken !== null) {
    try {
      state.carrier.cancelReceive(state.receiveToken)
    } catch {}
    state.receiveToken = null
  }
  if (state.lanes) state.lanes.destroy(error)
  else callStreamHook(state, 'onFailure', [error])
  try {
    state.carrier.destroy()
  } catch {}
  erasePreShared(state)
  clear(state.preTranscript)
  clear(state.offerWire)
  clear(state.offerBody)
  clear(state.offerDigest)
  clear(state.offerNonce)
  clear(state.responseWire)
  clear(state.acceptWire)
  clear(state.acceptBody)
  clear(state.acceptDigest)
  clear(state.acceptNonce)
  clear(state.purposeDigest)
  clear(state.sourceConfirmDigest)
  clear(state.terminalConfirmDigest)
  clear(state.finalTranscriptDigest)
  clearPeerPurposeKeys(state.keys)
  clearFinalKeys(state.finalKeys)
  for (const value of [
    state.id.routeId,
    state.id.circuitId,
    state.tailControlTranscriptDigest,
    state.terminalAdvertisementDigest,
    state.queryNonce,
    state.terminalRoutePublicKey,
    state.clientEphemeralPublicKey,
    state.clientEphemeralSecret,
    state.terminalRouteSecretKey
  ])
    clear(value)
  releaseResources(state)
  STATES.delete(owner)
  DESTROYED.add(owner)
  state.activeReject(
    error instanceof PrivateRouteError ? error : PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  )
  return true
}

function createPeerPurposeSource(options) {
  return createOwner('source', options)
}

function createPeerPurposeTerminal(options) {
  return createOwner('terminal', options)
}

module.exports = Object.freeze({
  CARRIER_BRAND,
  TEST_ONLY_PEER_PURPOSE_CARRIER_BRAND: CARRIER_BRAND,
  createPeerPurposeSource,
  createPeerPurposeTerminal,
  destroyPeerPurposeOwner: destroyOwner
})
