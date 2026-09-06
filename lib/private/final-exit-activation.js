const b4a = require('b4a')
const { PrivateRouteError } = require('./errors')
function clear(value) {
  if (b4a.isBuffer(value)) value.fill(0)
}
function encodeActivationRouteFrame(envelope) {
  const { decodeM3ContextEnvelope } = require('./m3-context')
  const { CONTEXT_CLASS } = require('./protocol')
  const decoded = decodeM3ContextEnvelope(envelope)
  if (
    decoded.contextClass !== CONTEXT_CLASS.TAIL_FINALIZE_DATAGRAM &&
    decoded.contextClass !== CONTEXT_CLASS.FINAL_EXIT_FINALIZE_DATAGRAM
  )
    invalid()
  return b4a.from(decoded.frame)
}

function decodeActivationRouteFrame(frame, contextClass) {
  if (frame === null || typeof frame !== 'object' || frame.byteLength !== 1100) invalid()
  const { encodeM3ContextEnvelope } = require('./m3-context')
  return encodeM3ContextEnvelope({ contextClass, frame })
}

const CLAIMS = new WeakMap()
const HANDOFF_CLAIMS = new WeakMap()
const SPENT_CLAIMS = new WeakSet()
const OWNERS = new WeakMap()
const DESTROYED_OWNERS = new WeakSet()
const RESERVATIONS = new WeakMap()
const FINAL_EXIT_FACTORIES = new WeakMap()
const FINAL_EXIT_DRIVER_STATES = new WeakMap()
const FINAL_EXIT_DRIVERS = new WeakMap()
const SPENT_RESERVATIONS = new WeakSet()
const FINAL_EXIT_FACTORY_KEYS = Object.freeze([
  'wallNow',
  'monotonicNow',
  'randomBytes',
  'schedule',
  'cancelScheduled'
])
const FINAL_EXIT_OPEN_KEYS = Object.freeze([
  'crypto',
  'handoff',
  'payloadParameters',
  'readySigner'
])
const TEST_ENDPOINT_DHT_EXIT_OPEN_KEYS = Object.freeze([
  'branchClass',
  'branchId',
  'circuitId',
  'generation',
  'exitIdentity',
  'finalTranscriptDigest',
  'expiresAt',
  'absoluteDeadline',
  'controlKey',
  'controlNoncePrefix'
])
const TEST_ONLY_ENDPOINT_DHT_EXIT_OPEN_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-endpoint-dht-exit-open-issuer'
)

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function authentication() {
  throw PrivateRouteError.ERR_AUTHENTICATION()
}

function replay() {
  throw PrivateRouteError.ERR_REPLAY()
}

function object(value) {
  try {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
  } catch {
    return false
  }
}

function exactObject(value, expected) {
  if (!object(value)) invalid()
  const keys = Reflect.ownKeys(value)
  if (keys.length !== expected.length) invalid()
  for (const key of expected) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) invalid()
  }
}

function createFinalExitActivationFactory(options) {
  exactObject(options, FINAL_EXIT_FACTORY_KEYS)
  const { wallNow, monotonicNow, randomBytes, schedule, cancelScheduled } = options
  if (
    typeof wallNow !== 'function' ||
    typeof monotonicNow !== 'function' ||
    typeof randomBytes !== 'function' ||
    typeof schedule !== 'function' ||
    typeof cancelScheduled !== 'function'
  ) {
    invalid()
  }
  const factory = Object.freeze({})
  FINAL_EXIT_FACTORIES.set(factory, {
    wallNow,
    monotonicNow,
    randomBytes,
    schedule,
    cancelScheduled
  })
  return factory
}

function readFinalExitActivationFactory(factory) {
  const state = object(factory) ? FINAL_EXIT_FACTORIES.get(factory) : null
  if (!state) authentication()
  return state
}

function createFinalExitActivationClaim(handoff) {
  if (!object(handoff) || HANDOFF_CLAIMS.has(handoff)) invalid()
  const claim = Object.freeze({})
  CLAIMS.set(claim, { handoff })
  HANDOFF_CLAIMS.set(handoff, claim)
  return claim
}

function revokeFinalExitActivationClaim(claim) {
  if (!object(claim)) return false
  const record = CLAIMS.get(claim)
  if (!record) return false
  CLAIMS.delete(claim)
  HANDOFF_CLAIMS.delete(record.handoff)
  SPENT_CLAIMS.add(claim)
  record.handoff = null
  return true
}

function claimFinalExitActivation(handoff, claim) {
  const record = object(claim) ? CLAIMS.get(claim) : null
  if (!record) {
    if (object(claim) && SPENT_CLAIMS.has(claim)) replay()
    authentication()
  }
  if (!object(handoff) || record.handoff !== handoff || HANDOFF_CLAIMS.get(handoff) !== claim) {
    authentication()
  }
  CLAIMS.delete(claim)
  HANDOFF_CLAIMS.delete(handoff)
  SPENT_CLAIMS.add(claim)
  record.handoff = null
  let prepared = null
  let owner = null
  let complete = false
  try {
    owner = Object.freeze({})
    OWNERS.set(owner, {
      material: null,
      reservation: null,
      consumed: false,
      sessionConsumed: false,
      destroyed: false
    })
    const {
      prepareTailControlFinalExitActivation,
      commitTailControlFinalExitActivation
    } = require('./tail-control')
    prepared = prepareTailControlFinalExitActivation(handoff, owner)
    OWNERS.get(owner).material = prepared.material
    commitTailControlFinalExitActivation(prepared.transfer, owner)
    complete = true
    return owner
  } finally {
    if (!complete) {
      if (prepared) {
        const { revokeTailControlFinalExitActivation } = require('./tail-control')
        revokeTailControlFinalExitActivation(prepared.transfer)
      }
      if (owner) destroyFinalExitActivationOwner(owner)
    }
  }
}

function reserveFinalExitActivationOwner(owner) {
  const record = object(owner) ? OWNERS.get(owner) : null
  if (!record || record.destroyed || record.consumed || DESTROYED_OWNERS.has(owner)) invalid()
  if (record.reservation !== null) replay()
  const reservation = Object.freeze({})
  const reservationState = {
    reservation,
    owner,
    record,
    destroyed: false
  }
  record.reservation = reservationState
  RESERVATIONS.set(reservation, reservationState)
  return reservation
}

function consumeFinalExitActivationOwnerReservation(reservation, owner) {
  const reservationState = object(reservation) ? RESERVATIONS.get(reservation) : null
  if (!reservationState) {
    if (object(reservation) && SPENT_RESERVATIONS.has(reservation)) replay()
    authentication()
  }
  const record = object(owner) ? OWNERS.get(owner) : null
  if (
    !record ||
    record.destroyed ||
    record.consumed ||
    DESTROYED_OWNERS.has(owner) ||
    reservationState.destroyed ||
    reservationState.owner !== owner ||
    reservationState.record !== record ||
    record.reservation !== reservationState
  ) {
    authentication()
  }
  RESERVATIONS.delete(reservation)
  SPENT_RESERVATIONS.add(reservation)
  reservationState.reservation = null
  reservationState.destroyed = true
  record.reservation = null
  record.consumed = true
  return record.material
}

function revokeFinalExitActivationOwnerReservation(reservation) {
  const reservationState = object(reservation) ? RESERVATIONS.get(reservation) : null
  if (!reservationState || reservationState.destroyed) return false
  RESERVATIONS.delete(reservation)
  SPENT_RESERVATIONS.add(reservation)
  reservationState.destroyed = true
  if (reservationState.record && reservationState.record.reservation === reservationState) {
    reservationState.record.reservation = null
  }
  reservationState.reservation = null
  reservationState.owner = null
  reservationState.record = null
  return true
}

function destroyFinalExitActivationOwner(owner) {
  const record = object(owner) ? OWNERS.get(owner) : null
  if (!record || record.destroyed || DESTROYED_OWNERS.has(owner)) return false
  OWNERS.delete(owner)
  DESTROYED_OWNERS.add(owner)
  record.destroyed = true
  const material = record.material
  if (material && object(material.tailControl)) {
    try {
      const { destroyTailControlFinalExitActivation } = require('./tail-control')
      destroyTailControlFinalExitActivation(material.tailControl, owner)
    } catch {}
  }
  record.material = null
  if (record.reservation !== null) {
    const reservationState = record.reservation
    RESERVATIONS.delete(reservationState.reservation)
    SPENT_RESERVATIONS.add(reservationState.reservation)
    reservationState.destroyed = true
    reservationState.reservation = null
    reservationState.owner = null
    reservationState.record = null
    record.reservation = null
  }
  const { destroyFinalExitHandoffMaterial } = require('./final-exit-handoff')
  destroyFinalExitHandoffMaterial(material)
  return true
}

const finalExitActivationRuntime = (() => {
  const b4a = require('b4a')
  const { DatagramReplayWindow, SenderCounter } = require('./counters')
  const {
    DHT_EXIT_ACTIVATE_SIZE,
    DHT_EXIT_OPEN_SIZE,
    DHT_EXIT_READY_SIZE,
    DHT_EXIT_ORIGIN_SERVICE_POLICY,
    DHT_EXIT_READY_ACK_SIZE,
    decodeDhtExitActivate,
    decodeDhtExitOpen,
    decodeDhtExitReady,
    decodeDhtExitReadyAck,
    deriveFinalExitTestVector,
    dhtExitReadySignatureInput,
    digestDhtExitReady,
    digestDhtExitReadyAck,
    digestFinalExitTranscript,
    digestExitOriginServicePolicy,
    digestPayloadParameters,
    encodeDhtExitActivate,
    encodeDhtExitOpen,
    encodeDhtExitReady,
    encodeDhtExitReadyAck,
    encodeDhtExitReadyBody,
    encodeFinalExitTranscript
  } = require('./final-exit')
  const {
    decodeM3ContextEnvelope,
    encodeM3ContextAD,
    encodeM3ContextEnvelope
  } = require('./m3-context')
  const { CELL_CLASS, CONTEXT_CLASS, DIRECTION, BRANCH_CLASS } = require('./protocol')
  const { decodeTailControlTranscript, digestTailControlTranscript } = require('./tail-control')
  const { destroyFinalExitHandoffMaterial } = require('./final-exit-handoff')
  const { destroyDhtExitReadySigner, signDhtExitReady } = require('./relay-identity-signer')
  const { createDhtExitOpenAuthority } = require('./dht-exit-reservation')

  const OPEN_HANDOFFS = new WeakMap()
  const OPEN_OWNER_HANDOFFS = new WeakMap()
  const SPENT_OPEN_HANDOFFS = new WeakSet()
  const ENDPOINT_OPEN_AUTHORITIES = new WeakMap()
  const SPENT_ENDPOINT_OPEN_AUTHORITIES = new WeakSet()
  const DESTROYED_OPEN_MATERIAL = new WeakSet()
  const OPEN_MATERIAL_KEYS = Object.freeze([
    'initiator',
    'expiresAt',
    'branchClass',
    'branchId',
    'circuitId',
    'generation',
    'exitIdentity',
    'policyDigest',
    'payloadDigest',
    'payloadForwardKey',
    'payloadReverseKey',
    'payloadForwardNoncePrefix',
    'payloadReverseNoncePrefix',
    'controlForwardKey',
    'controlReverseKey',
    'controlForwardNoncePrefix',
    'controlReverseNoncePrefix',
    'endpointOpenAuthority'
  ])
  const OPEN_BUFFER_FIELDS = Object.freeze({
    branchId: 16,
    circuitId: 16,
    exitIdentity: 32,
    policyDigest: 32,
    payloadDigest: 32,
    payloadForwardKey: 32,
    payloadReverseKey: 32,
    payloadForwardNoncePrefix: 16,
    payloadReverseNoncePrefix: 16,
    controlForwardKey: 32,
    controlReverseKey: 32,
    controlForwardNoncePrefix: 16,
    controlReverseNoncePrefix: 16
  })
  function validOpenMaterial(owner, material) {
    try {
      const keys = Reflect.ownKeys(material)
      return (
        owner !== null &&
        typeof owner === 'object' &&
        material !== null &&
        typeof material === 'object' &&
        !Array.isArray(material) &&
        keys.length === OPEN_MATERIAL_KEYS.length &&
        keys.every((key) => typeof key === 'string' && OPEN_MATERIAL_KEYS.includes(key)) &&
        typeof material.initiator === 'boolean' &&
        typeof material.expiresAt === 'bigint' &&
        material.expiresAt > 0n &&
        (material.branchClass === BRANCH_CLASS.LOOKUP ||
          material.branchClass === BRANCH_CLASS.ANNOUNCE) &&
        typeof material.generation === 'bigint' &&
        material.generation >= 0n &&
        Object.entries(OPEN_BUFFER_FIELDS).every(
          ([name, size]) => b4a.isBuffer(material[name]) && material[name].byteLength === size
        ) &&
        (material.endpointOpenAuthority === null ||
          ENDPOINT_OPEN_AUTHORITIES.has(material.endpointOpenAuthority))
      )
    } catch {
      return false
    }
  }
  function issueOpenRouteHandoff(owner, material) {
    if (!validOpenMaterial(owner, material) || OPEN_OWNER_HANDOFFS.has(owner)) invalid()
    const handoff = Object.freeze({})
    OPEN_HANDOFFS.set(handoff, { owner, material })
    OPEN_OWNER_HANDOFFS.set(owner, handoff)
    return handoff
  }
  function consumeOpenRouteHandoff(handoff) {
    const record =
      handoff !== null && typeof handoff === 'object' ? OPEN_HANDOFFS.get(handoff) : null
    if (!record) {
      if (handoff !== null && typeof handoff === 'object' && SPENT_OPEN_HANDOFFS.has(handoff))
        throw PrivateRouteError.ERR_REPLAY()
      throw PrivateRouteError.ERR_AUTHENTICATION()
    }
    const ownerRecord =
      record.owner && typeof record.owner === 'object' ? OWNERS.get(record.owner) : null
    if (!ownerRecord || ownerRecord.destroyed || DESTROYED_OWNERS.has(record.owner)) {
      OPEN_HANDOFFS.delete(handoff)
      OPEN_OWNER_HANDOFFS.delete(record.owner)
      SPENT_OPEN_HANDOFFS.add(handoff)
      destroyOpenRouteMaterial(record.material)
      throw PrivateRouteError.ERR_AUTHENTICATION()
    }
    OPEN_HANDOFFS.delete(handoff)
    OPEN_OWNER_HANDOFFS.delete(record.owner)
    SPENT_OPEN_HANDOFFS.add(handoff)
    return record.material
  }
  function revokeOpenRouteHandoff(handoff) {
    if (handoff === null || typeof handoff !== 'object') return false
    const record = OPEN_HANDOFFS.get(handoff)
    if (!record) return false
    OPEN_OWNER_HANDOFFS.delete(record.owner)
    OPEN_HANDOFFS.delete(handoff)
    SPENT_OPEN_HANDOFFS.add(handoff)
    destroyOpenRouteMaterial(record.material)
    return true
  }
  function destroyOpenRouteMaterial(material) {
    if (material === null || typeof material !== 'object' || DESTROYED_OPEN_MATERIAL.has(material))
      return false
    DESTROYED_OPEN_MATERIAL.add(material)
    for (const name of Object.keys(OPEN_BUFFER_FIELDS)) {
      let value = null
      try {
        value = material[name]
        material[name] = null
      } catch {}
      try {
        if (b4a.isBuffer(value)) value.fill(0)
      } catch {}
    }
    try {
      destroyEndpointDhtExitOpenAuthority(material.endpointOpenAuthority)
      material.endpointOpenAuthority = null
    } catch {}
    try {
      material.initiator = false
      material.expiresAt = 0n
      material.branchClass = 0
      material.generation = 0n
    } catch {}
    return true
  }
  function consumeFinalExitActivationOwner(owner) {
    const record = owner !== null && typeof owner === 'object' ? OWNERS.get(owner) : null
    if (
      !record ||
      record.destroyed ||
      record.sessionConsumed ||
      DESTROYED_OWNERS.has(owner) ||
      !record.material
    ) {
      authentication()
    }
    const material = record.material
    record.sessionConsumed = true
    return material
  }
  const ROUTE_FRAME_SIZE = 1100
  const ROUTE_PLAINTEXT_SIZE = 1076
  const MAX_ROUTE_PAYLOAD = 1073
  const AEAD_TAG_SIZE = 16
  const FINALIZATION_TIMEOUT_MS = 5_000n
  const MAX_UINT64 = 0xffff_ffff_ffff_ffffn
  const RETRY_OFFSETS = Object.freeze([0n, 250n, 750n, 1_750n, 3_750n])
  const RETRY_DELAY_ERROR = Symbol('retryDelayError')
  const byteLengthGetter = Object.getOwnPropertyDescriptor(
    Object.getPrototypeOf(Uint8Array.prototype),
    'byteLength'
  ).get
  const fillIntrinsic = Uint8Array.prototype.fill
  const setIntrinsic = Uint8Array.prototype.set
  const subarrayIntrinsic = Uint8Array.prototype.subarray

  function invalid() {
    throw PrivateRouteError.INVALID_ROUTE()
  }

  function authentication() {
    throw PrivateRouteError.ERR_AUTHENTICATION()
  }

  function object(value) {
    try {
      if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid()
      return value
    } catch (err) {
      if (err instanceof PrivateRouteError) throw err
      invalid()
    }
  }

  function retryDelayUnavailable() {
    const err = PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    err[RETRY_DELAY_ERROR] = true
    return err
  }

  function retryUnavailable(err) {
    return (
      err instanceof PrivateRouteError &&
      err.code === 'ERR_PRIVACY_UNAVAILABLE' &&
      err[RETRY_DELAY_ERROR] === true
    )
  }

  function option(value, name) {
    try {
      return value[name]
    } catch {
      invalid()
    }
  }

  function length(value) {
    try {
      return b4a.isBuffer(value) ? byteLengthGetter.call(value) : -1
    } catch {
      return -1
    }
  }

  function fixed(value, size) {
    return length(value) === size
  }

  function clear(value) {
    try {
      if (b4a.isBuffer(value)) fillIntrinsic.call(value, 0)
    } catch {}
  }

  function set(target, source, offset = 0) {
    try {
      setIntrinsic.call(target, source, offset)
    } catch {
      invalid()
    }
  }

  function subarray(value, start, end) {
    try {
      return subarrayIntrinsic.call(value, start, end)
    } catch {
      invalid()
    }
  }

  function copy(value) {
    let output = null
    try {
      if (length(value) < 0) invalid()
      output = b4a.allocUnsafeSlow(length(value))
      set(output, value)
      return output
    } catch (err) {
      clear(output)
      if (err instanceof PrivateRouteError) throw err
      invalid()
    }
  }

  function same(left, right) {
    try {
      return fixed(left, length(right)) && b4a.equals(left, right)
    } catch {
      return false
    }
  }

  function nowValue(now) {
    let value
    try {
      value = now()
    } catch {
      invalid()
    }
    if (Number.isSafeInteger(value) && value >= 0) value = BigInt(value)
    if (typeof value !== 'bigint' || value < 0n || value > MAX_UINT64) invalid()
    return value
  }

  function random(randomBytes, size) {
    let value = null
    try {
      value = randomBytes(size)
      if (!fixed(value, size)) invalid()
      return copy(value)
    } finally {
      clear(value)
    }
  }

  function writeUint16(target, value, offset) {
    target[offset] = value >>> 8
    target[offset + 1] = value
  }

  function readUint16(target, offset) {
    return (target[offset] << 8) | target[offset + 1]
  }

  function writeUint64(target, value, offset = 0) {
    for (let index = offset + 7; index >= offset; index--) {
      target[index] = Number(value & 0xffn)
      value >>= 8n
    }
  }

  function readUint64(target, offset = 0) {
    let value = 0n
    for (let index = offset; index < offset + 8; index++) {
      value = (value << 8n) | BigInt(target[index])
    }
    return value
  }

  function associatedData(state, counter, contextClass, direction) {
    return encodeM3ContextAD({
      contextClass,
      branchId: state.transcript.branchId,
      circuitId: state.transcript.circuitId,
      generation: state.transcript.generation,
      direction,
      innerCounter: counter
    })
  }

  function datagramState(state, contextClass, direction, sending) {
    const final = contextClass === CONTEXT_CLASS.FINAL_EXIT_FINALIZE_DATAGRAM
    if (!final && contextClass !== CONTEXT_CLASS.TAIL_FINALIZE_DATAGRAM) invalid()
    const material = final ? state.finalMaterial : state.material
    if (!material) authentication()
    if (direction === DIRECTION.FORWARD) {
      return {
        counter: sending
          ? final
            ? state.finalForwardTx
            : state.forwardTx
          : final
            ? state.finalForwardRx
            : state.forwardRx,
        key: material.finalizeForwardKey,
        noncePrefix: material.finalizeForwardNoncePrefix
      }
    }
    if (direction === DIRECTION.REVERSE) {
      return {
        counter: sending
          ? final
            ? state.finalReverseTx
            : state.reverseTx
          : final
            ? state.finalReverseRx
            : state.reverseRx,
        key: material.finalizeReverseKey,
        noncePrefix: material.finalizeReverseNoncePrefix
      }
    }
    invalid()
  }

  function sealFrame(state, encoded, randomBytes, contextClass, direction) {
    const selected = datagramState(state, contextClass, direction, true)
    if (!selected.counter) authentication()
    const counter = selected.counter.next()
    let ad = null
    let plaintext = null
    let padding = null
    let ciphertext = null
    let frame = null
    try {
      ad = associatedData(state, counter, contextClass, direction)
      plaintext = b4a.allocUnsafeSlow(ROUTE_PLAINTEXT_SIZE)
      plaintext[0] = CELL_CLASS.DATAGRAM
      writeUint16(plaintext, encoded.byteLength, 1)
      set(plaintext, encoded, 3)
      padding = random(randomBytes, MAX_ROUTE_PAYLOAD - encoded.byteLength)
      set(plaintext, padding, 3 + encoded.byteLength)
      ciphertext = state.crypto.seal({
        key: selected.key,
        noncePrefix: selected.noncePrefix,
        counter,
        associatedData: ad,
        plaintext
      })
      if (!fixed(ciphertext, ROUTE_PLAINTEXT_SIZE + AEAD_TAG_SIZE)) invalid()
      frame = b4a.allocUnsafeSlow(ROUTE_FRAME_SIZE)
      writeUint64(frame, counter)
      set(frame, ciphertext, 8)
      return encodeM3ContextEnvelope({
        contextClass,
        frame
      })
    } finally {
      clear(ad)
      clear(plaintext)
      clear(padding)
      clear(ciphertext)
      clear(frame)
    }
  }

  function openFrame(state, envelope, contextClass, direction, expectedSize) {
    let decoded = null
    let ad = null
    let plaintext = null
    let encoded = null
    try {
      decoded = decodeM3ContextEnvelope(envelope)
      if (decoded.contextClass !== contextClass) invalid()
      const selected = datagramState(state, contextClass, direction, false)
      if (!selected.counter) authentication()
      const counter = readUint64(decoded.frame)
      ad = associatedData(state, counter, contextClass, direction)
      plaintext = state.crypto.open({
        key: selected.key,
        noncePrefix: selected.noncePrefix,
        counter,
        associatedData: ad,
        ciphertext: subarray(decoded.frame, 8, ROUTE_FRAME_SIZE)
      })
      if (!fixed(plaintext, ROUTE_PLAINTEXT_SIZE) || plaintext[0] !== CELL_CLASS.DATAGRAM) invalid()
      const payloadLength = readUint16(plaintext, 1)
      if (payloadLength !== expectedSize) invalid()
      encoded = copy(subarray(plaintext, 3, 3 + payloadLength))
      try {
        selected.counter.acceptAuthenticated(counter)
      } catch (err) {
        if (err instanceof PrivateRouteError && err.code === 'REPLAY') {
          clear(encoded)
          encoded = null
          return null
        }
        throw err
      }
      const result = encoded
      encoded = null
      return result
    } finally {
      if (decoded) clear(decoded.frame)
      clear(ad)
      clear(plaintext)
      clear(encoded)
    }
  }

  function clearTranscript(transcript) {
    if (!transcript) return
    for (const name of [
      'branchId',
      'circuitId',
      'clientTailEphemeralPublicKey',
      'advertisedTailRouteEncryptionPublicKey',
      'candidateAdvertisementDigest',
      'clientNonce',
      'tailIdentity',
      'admittedLimitsDigest'
    ]) {
      clear(transcript[name])
    }
  }

  function clearActivation(activation) {
    if (!activation) return
    clear(activation.clientActivationNonce)
    clear(activation.exitOriginCommandPolicyDigest)
    clear(activation.payloadParametersDigest)
  }

  function activationProjection(activation) {
    return Object.freeze({
      clientActivationNonce: copy(activation.clientActivationNonce),
      exitOriginCommandPolicyDigest: copy(activation.exitOriginCommandPolicyDigest),
      payloadParametersDigest: copy(activation.payloadParametersDigest)
    })
  }

  function clearReady(ready) {
    if (!ready) return
    for (const value of Object.values(ready)) clear(value)
  }

  function readyProjection(ready) {
    return Object.freeze({
      branchClass: ready.branchClass,
      branchId: copy(ready.branchId),
      circuitId: copy(ready.circuitId),
      generation: ready.generation,
      exitIdentity: copy(ready.exitIdentity),
      clientActivationNonce: copy(ready.clientActivationNonce),
      exitOriginCommandPolicyDigest: copy(ready.exitOriginCommandPolicyDigest),
      payloadParametersDigest: copy(ready.payloadParametersDigest),
      finalExitTranscriptDigest: copy(ready.finalExitTranscriptDigest),
      readyNonce: copy(ready.readyNonce)
    })
  }

  function clearAck(ack) {
    if (!ack) return
    for (const value of Object.values(ack)) clear(value)
  }

  function clearOpen(open) {
    if (!open) return
    for (const value of Object.values(open)) clear(value)
  }

  function openProjection(open) {
    return Object.freeze({
      branchClass: open.branchClass,
      branchId: copy(open.branchId),
      circuitId: copy(open.circuitId),
      generation: open.generation,
      ackDigest: copy(open.ackDigest),
      clientActivationNonce: copy(open.clientActivationNonce),
      exitOriginCommandPolicyDigest: copy(open.exitOriginCommandPolicyDigest),
      payloadParametersDigest: copy(open.payloadParametersDigest)
    })
  }

  function clearFinalMaterial(material) {
    if (!material) return
    for (const value of Object.values(material)) clear(value)
  }

  function destroyCounter(state, name) {
    const counter = state[name]
    state[name] = null
    try {
      if (counter) counter.destroy()
    } catch {}
  }

  function clearMaterialField(material, name) {
    if (!material) return
    let value = null
    try {
      value = material[name]
      material[name] = null
    } catch {}
    clear(value)
  }

  function eraseOrderedTailControl(state) {
    const tailControl = state.material && state.material.tailControl
    if (state.material) state.material.tailControl = null
    try {
      if (tailControl) tailControl.destroy()
    } catch {}
    clearMaterialField(state.material, 'sharedSecret')
  }

  function installRetiredFinalizationState(state) {
    eraseOrderedTailControl(state)
    if (state.initiator) {
      destroyCounter(state, 'forwardTx')
      destroyCounter(state, 'finalForwardTx')
      clearMaterialField(state.material, 'finalizeForwardKey')
      clearMaterialField(state.material, 'finalizeForwardNoncePrefix')
      clearMaterialField(state.finalMaterial, 'finalizeForwardKey')
      clearMaterialField(state.finalMaterial, 'finalizeForwardNoncePrefix')
    } else {
      destroyCounter(state, 'reverseTx')
      clearMaterialField(state.material, 'finalizeReverseKey')
      clearMaterialField(state.material, 'finalizeReverseNoncePrefix')
    }
  }

  function eraseRetiredFinalizationState(state) {
    for (const name of [
      'forwardTx',
      'forwardRx',
      'reverseTx',
      'reverseRx',
      'finalForwardTx',
      'finalForwardRx',
      'finalReverseTx',
      'finalReverseRx'
    ]) {
      destroyCounter(state, name)
    }
    for (const name of [
      'finalizeForwardKey',
      'finalizeForwardNoncePrefix',
      'finalizeReverseKey',
      'finalizeReverseNoncePrefix'
    ]) {
      clearMaterialField(state.material, name)
      clearMaterialField(state.finalMaterial, name)
    }
    clear(state.activationEncoded)
    clearActivation(state.activation)
    clear(state.readyEncoded)
    clearReady(state.ready)
    clear(state.ackEncoded)
    clearAck(state.ack)
    clear(state.openEncoded)
    clearOpen(state.open)
    state.activationEncoded = null
    state.activation = null
    state.readyEncoded = null
    state.ready = null
    state.ackEncoded = null
    state.ack = null
    state.openEncoded = null
    state.open = null
    state.graceDeadline = null
    state.graceRetired = true
  }

  function buildOpenRouteMaterial(state) {
    const material = {}
    let complete = false
    try {
      material.initiator = state.initiator
      material.expiresAt = state.material.expiresAt
      material.branchClass = state.transcript.branchClass
      material.branchId = copy(state.transcript.branchId)
      material.circuitId = copy(state.transcript.circuitId)
      material.generation = state.transcript.generation
      material.exitIdentity = copy(state.transcript.tailIdentity)
      material.policyDigest = copy(state.policyDigest)
      material.payloadDigest = copy(state.payloadDigest)
      for (const name of [
        'payloadForwardKey',
        'payloadReverseKey',
        'payloadForwardNoncePrefix',
        'payloadReverseNoncePrefix',
        'controlForwardKey',
        'controlReverseKey',
        'controlForwardNoncePrefix',
        'controlReverseNoncePrefix'
      ]) {
        material[name] = copy(state.finalMaterial[name])
      }
      material.endpointOpenAuthority =
        state.initiator && state.endpointDhtExitOpenAuthority
          ? state.endpointDhtExitOpenAuthority
          : null
      complete = true
      return material
    } finally {
      if (!complete) destroyOpenRouteMaterial(material)
    }
  }

  function buildDhtExitOpenAuthorityMaterial(state, exitSide) {
    const forward = exitSide ? 'Reverse' : 'Forward'
    // KI-17. The grace deadline bounds finalization retransmits, not the open
    // route: it is OPEN + FINALIZATION_TIMEOUT_MS, so carrying it here as the
    // exit's absolute deadline refused every routed request whose budget reached
    // past five seconds after OPEN, which is every request made two seconds after
    // readiness. The route's own local deadline is the only bound on the data path.
    const deadline = state.material.localDeadline
    return {
      branchClass: state.transcript.branchClass,
      branchId: copy(state.transcript.branchId),
      circuitId: copy(state.transcript.circuitId),
      generation: state.transcript.generation,
      exitIdentity: copy(state.transcript.tailIdentity),
      finalTranscriptDigest: copy(state.finalTranscriptDigest),
      expiresAt: state.material.expiresAt,
      absoluteDeadline: deadline,
      controlKey: copy(state.finalMaterial['control' + forward + 'Key']),
      controlNoncePrefix: copy(state.finalMaterial['control' + forward + 'NoncePrefix'])
    }
  }

  function buildFinalTranscript(state, activation) {
    let tailDigest = null
    let encoded = null
    let digest = null
    let complete = false
    try {
      tailDigest = digestTailControlTranscript(state.material.tailControlTranscript)
      encoded = encodeFinalExitTranscript({
        branchClass: state.transcript.branchClass,
        branchId: state.transcript.branchId,
        circuitId: state.transcript.circuitId,
        generation: state.transcript.generation,
        tailControlTranscriptDigest: tailDigest,
        exitAdvertisementDigest: state.transcript.candidateAdvertisementDigest,
        exitIdentity: state.transcript.tailIdentity,
        clientActivationNonce: activation.clientActivationNonce,
        exitOriginCommandPolicyDigest: activation.exitOriginCommandPolicyDigest,
        payloadParametersDigest: activation.payloadParametersDigest
      })
      digest = digestFinalExitTranscript(encoded)
      complete = true
      return { encoded, digest }
    } finally {
      clear(tailDigest)
      if (!complete) {
        clear(encoded)
        clear(digest)
      }
    }
  }

  function installFinalMaterial(state, transcript) {
    if (state.finalMaterial || state.finalTranscript || state.finalTranscriptDigest) invalid()
    const material = deriveFinalExitTestVector(state.material.sharedSecret, transcript.encoded)
    state.finalMaterial = material
    state.finalTranscript = transcript.encoded
    state.finalTranscriptDigest = transcript.digest
    transcript.encoded = null
    transcript.digest = null
  }

  class FinalExitActivationSession {
    #state

    constructor(handoff, options) {
      let material = null
      let tailControl = null
      let transcript = null
      let policyDigest = null
      let payloadDigest = null
      let readySigner = null
      let routeTransport = null
      try {
        material = consumeFinalExitActivationOwner(handoff)
        tailControl = material.tailControl
        options = object(options)
        const now = option(options, 'now')
        const monotonicNow = option(options, 'monotonicNow') || now
        const crypto = option(options, 'crypto')
        readySigner = option(options, 'readySigner')
        const schedule = option(options, 'schedule')
        const cancelScheduled = option(options, 'cancelScheduled')
        if (
          typeof now !== 'function' ||
          typeof monotonicNow !== 'function' ||
          !object(crypto) ||
          typeof crypto.seal !== 'function' ||
          typeof crypto.open !== 'function' ||
          typeof crypto.verify !== 'function' ||
          typeof schedule !== 'function' ||
          typeof cancelScheduled !== 'function'
        ) {
          invalid()
        }
        if (material.initiator ? readySigner !== undefined : readySigner === undefined) invalid()
        const current = nowValue(monotonicNow)
        if (current >= material.localDeadline) throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
        transcript = decodeTailControlTranscript(material.tailControlTranscript)
        if (transcript.extensionIndex !== 2) authentication()
        policyDigest = digestExitOriginServicePolicy(DHT_EXIT_ORIGIN_SERVICE_POLICY)
        payloadDigest = digestPayloadParameters(option(options, 'payloadParameters'))
        const { takeTailControlRouteTransport } = require('./tail-control')
        routeTransport = takeTailControlRouteTransport(tailControl, handoff)
        this.#state = {
          ack: null,
          ackEncoded: null,
          activation: null,
          activationOwner: handoff,
          activationEncoded: null,
          activationTransport: routeTransport,
          crypto,
          deadline: null,
          destroyed: false,
          finalMaterial: null,
          finalForwardRx: material.initiator ? null : new DatagramReplayWindow({ window: 64 }),
          finalForwardTx: material.initiator ? new SenderCounter() : null,
          finalReverseRx: material.initiator ? new DatagramReplayWindow({ window: 64 }) : null,
          finalReverseTx: material.initiator ? null : new SenderCounter(),
          finalTranscript: null,
          finalTranscriptDigest: null,
          forwardRx: material.initiator ? null : new DatagramReplayWindow({ window: 64 }),
          forwardTx: material.initiator ? new SenderCounter() : null,
          graceDeadline: null,
          graceRetired: false,
          initiator: material.initiator,
          material,
          mutating: false,
          monotonicNow,
          now,
          open: null,
          openEncoded: null,
          openHandoff: null,
          dhtExitOpenAuthority: null,
          endpointDhtExitOpenAuthority: null,
          payloadDigest,
          policyDigest,
          ready: null,
          readySigner,
          readyEncoded: null,
          reverseRx: material.initiator ? new DatagramReplayWindow({ window: 64 }) : null,
          reverseTx: material.initiator ? null : new SenderCounter(),
          state: 'TAIL_READY',
          transcript,
          tailControlOwner: tailControl,
          violated: false,
          cancelScheduled,
          retryOrdinal: { activate: 0, ready: 0, ack: 0, open: 0 },
          retryHandles: { activate: [], ready: [], ack: [], open: [] },
          retryStartedAt: { activate: null, ready: null, ack: null, open: null },
          schedule
        }
        routeTransport = null
        FINAL_EXIT_DRIVER_STATES.set(this, this.#state)
        material = null
        tailControl = null
        transcript = null
        policyDigest = null
        payloadDigest = null
        Object.freeze(this)
      } catch (err) {
        if (routeTransport) {
          try {
            const { destroyM3RouteTransport } = require('./m3-adjacency-runtime')
            destroyM3RouteTransport(routeTransport)
          } catch {}
        }
        if (handoff && typeof handoff === 'object') {
          destroyFinalExitActivationOwner(handoff)
        } else {
          destroyFinalExitHandoffMaterial(material)
        }
        if (readySigner) destroyDhtExitReadySigner(readySigner)
        clearTranscript(transcript)
        clear(policyDigest)
        clear(payloadDigest)
        if (err instanceof PrivateRouteError) throw err
        invalid()
      }
    }

    sealActivate(options) {
      const state = this.#begin()
      let nonce = null
      let encoded = null
      try {
        if (!state.initiator || state.state !== 'TAIL_READY') authentication()
        this.#checkDeadline(state, true)
        const randomBytes = option(object(options), 'randomBytes')
        if (typeof randomBytes !== 'function') invalid()
        nonce = random(randomBytes, 32)
        this.#assertLive(state)
        encoded = encodeDhtExitActivate({
          clientActivationNonce: nonce,
          exitOriginCommandPolicyDigest: state.policyDigest,
          payloadParametersDigest: state.payloadDigest
        })
        const envelope = sealFrame(
          state,
          encoded,
          randomBytes,
          CONTEXT_CLASS.TAIL_FINALIZE_DATAGRAM,
          DIRECTION.FORWARD
        )
        this.#assertLive(state)
        state.activationEncoded = copy(encoded)
        state.activation = Object.freeze({
          clientActivationNonce: copy(nonce),
          exitOriginCommandPolicyDigest: copy(state.policyDigest),
          payloadParametersDigest: copy(state.payloadDigest)
        })
        state.state = 'ACTIVATING'
        this.#startRetry(state, 'activate')
        return envelope
      } catch (err) {
        this.#terminate()
        if (err instanceof PrivateRouteError) throw err
        invalid()
      } finally {
        state.mutating = false
        clear(nonce)
        clear(encoded)
      }
    }

    retryActivate(options) {
      const state = this.#begin()
      try {
        if (!state.initiator || state.state !== 'ACTIVATING') authentication()
        const randomBytes = option(object(options), 'randomBytes')
        if (typeof randomBytes !== 'function') invalid()
        this.#checkDeadline(state)
        this.#consumeRetry(state, 'activate')
        const envelope = sealFrame(
          state,
          state.activationEncoded,
          randomBytes,
          CONTEXT_CLASS.TAIL_FINALIZE_DATAGRAM,
          DIRECTION.FORWARD
        )
        this.#assertLive(state)
        return envelope
      } catch (err) {
        if (retryUnavailable(err)) throw err
        this.#terminate()
        if (err instanceof PrivateRouteError) throw err
        invalid()
      } finally {
        state.mutating = false
      }
    }

    openActivate(envelope) {
      const state = this.#begin()
      let encoded = null
      let activation = null
      try {
        if (state.initiator || (state.state !== 'TAIL_READY' && state.state !== 'FINALIZING')) {
          authentication()
        }
        this.#checkDeadline(state, state.state === 'TAIL_READY')
        encoded = openFrame(
          state,
          envelope,
          CONTEXT_CLASS.TAIL_FINALIZE_DATAGRAM,
          DIRECTION.FORWARD,
          DHT_EXIT_ACTIVATE_SIZE
        )
        this.#assertLive(state)
        if (encoded === null) return null
        activation = decodeDhtExitActivate(encoded)
        if (
          !same(activation.exitOriginCommandPolicyDigest, state.policyDigest) ||
          !same(activation.payloadParametersDigest, state.payloadDigest)
        ) {
          authentication()
        }
        if (state.activationEncoded && !same(encoded, state.activationEncoded)) authentication()
        if (!state.activationEncoded) {
          state.activationEncoded = copy(encoded)
          state.activation = Object.freeze({
            clientActivationNonce: copy(activation.clientActivationNonce),
            exitOriginCommandPolicyDigest: copy(activation.exitOriginCommandPolicyDigest),
            payloadParametersDigest: copy(activation.payloadParametersDigest)
          })
          const finalTranscript = buildFinalTranscript(state, state.activation)
          try {
            installFinalMaterial(state, finalTranscript)
          } finally {
            clear(finalTranscript.encoded)
            clear(finalTranscript.digest)
          }
          state.state = 'FINALIZING'
        }
        return activationProjection(state.activation)
      } catch (err) {
        this.#terminate()
        if (err instanceof PrivateRouteError) throw err
        invalid()
      } finally {
        state.mutating = false
        clear(encoded)
        clearActivation(activation)
      }
    }

    sealReady(options) {
      const state = this.#begin()
      let readyNonce = null
      let body = null
      let input = null
      let signature = null
      let encoded = null
      let ready = null
      try {
        if (
          state.initiator ||
          state.state !== 'FINALIZING' ||
          state.readyEncoded ||
          !state.finalTranscriptDigest
        ) {
          authentication()
        }
        this.#checkDeadline(state)
        options = object(options)
        const randomBytes = option(options, 'randomBytes')
        if (typeof randomBytes !== 'function') invalid()
        readyNonce = random(randomBytes, 32)
        this.#assertLive(state)
        body = encodeDhtExitReadyBody({
          branchClass: state.transcript.branchClass,
          branchId: state.transcript.branchId,
          circuitId: state.transcript.circuitId,
          generation: state.transcript.generation,
          exitIdentity: state.transcript.tailIdentity,
          clientActivationNonce: state.activation.clientActivationNonce,
          exitOriginCommandPolicyDigest: state.policyDigest,
          payloadParametersDigest: state.payloadDigest,
          finalExitTranscriptDigest: state.finalTranscriptDigest,
          readyNonce
        })
        input = dhtExitReadySignatureInput(body)
        signature = signDhtExitReady(state.readySigner, body, state.transcript.tailIdentity)
        this.#assertLive(state)
        if (
          !fixed(signature, 64) ||
          !state.crypto.verify(input, signature, state.transcript.tailIdentity)
        ) {
          invalid()
        }
        this.#assertLive(state)
        encoded = encodeDhtExitReady({
          branchClass: state.transcript.branchClass,
          branchId: state.transcript.branchId,
          circuitId: state.transcript.circuitId,
          generation: state.transcript.generation,
          exitIdentity: state.transcript.tailIdentity,
          clientActivationNonce: state.activation.clientActivationNonce,
          exitOriginCommandPolicyDigest: state.policyDigest,
          payloadParametersDigest: state.payloadDigest,
          finalExitTranscriptDigest: state.finalTranscriptDigest,
          readyNonce,
          signature
        })
        const envelope = sealFrame(
          state,
          encoded,
          randomBytes,
          CONTEXT_CLASS.TAIL_FINALIZE_DATAGRAM,
          DIRECTION.REVERSE
        )
        this.#assertLive(state)
        ready = decodeDhtExitReady(encoded)
        state.readyEncoded = copy(encoded)
        state.ready = ready
        destroyDhtExitReadySigner(state.readySigner)
        state.readySigner = null
        ready = null
        this.#startRetry(state, 'ready')
        return envelope
      } catch (err) {
        this.#terminate()
        if (err instanceof PrivateRouteError) throw err
        invalid()
      } finally {
        state.mutating = false
        clear(readyNonce)
        clear(body)
        clear(input)
        clear(signature)
        clear(encoded)
        clearReady(ready)
      }
    }

    retryReady(options) {
      const state = this.#begin()
      try {
        if (state.initiator || state.state !== 'FINALIZING' || !state.readyEncoded) {
          authentication()
        }
        const randomBytes = option(object(options), 'randomBytes')
        if (typeof randomBytes !== 'function') invalid()
        this.#checkDeadline(state)
        this.#consumeRetry(state, 'ready')
        const envelope = sealFrame(
          state,
          state.readyEncoded,
          randomBytes,
          CONTEXT_CLASS.TAIL_FINALIZE_DATAGRAM,
          DIRECTION.REVERSE
        )
        this.#assertLive(state)
        return envelope
      } catch (err) {
        if (retryUnavailable(err)) throw err
        this.#terminate()
        if (err instanceof PrivateRouteError) throw err
        invalid()
      } finally {
        state.mutating = false
      }
    }

    openReady(envelope) {
      const state = this.#begin()
      let encoded = null
      let ready = null
      let input = null
      let finalTranscript = null
      try {
        if (
          !state.initiator ||
          (state.state !== 'ACTIVATING' && state.state !== 'ACKING' && state.state !== 'OPEN')
        ) {
          authentication()
        }
        const retired = state.state === 'OPEN'
        if (retired) {
          if (!this.#checkGrace(state)) return null
        } else {
          this.#checkDeadline(state)
        }
        encoded = openFrame(
          state,
          envelope,
          CONTEXT_CLASS.TAIL_FINALIZE_DATAGRAM,
          DIRECTION.REVERSE,
          DHT_EXIT_READY_SIZE
        )
        this.#assertLive(state)
        if (encoded === null) return null
        if (state.readyEncoded) {
          if (!same(encoded, state.readyEncoded)) authentication()
          if (retired) return null
          return readyProjection(state.ready)
        }
        ready = decodeDhtExitReady(encoded)
        input = dhtExitReadySignatureInput(ready.body)
        const signatureValid = state.crypto.verify(
          input,
          ready.signature,
          state.transcript.tailIdentity
        )
        this.#assertLive(state)
        if (!signatureValid) authentication()
        finalTranscript = buildFinalTranscript(state, state.activation)
        if (
          ready.branchClass !== state.transcript.branchClass ||
          !same(ready.branchId, state.transcript.branchId) ||
          !same(ready.circuitId, state.transcript.circuitId) ||
          ready.generation !== state.transcript.generation ||
          !same(ready.exitIdentity, state.transcript.tailIdentity) ||
          !same(ready.clientActivationNonce, state.activation.clientActivationNonce) ||
          !same(ready.exitOriginCommandPolicyDigest, state.policyDigest) ||
          !same(ready.payloadParametersDigest, state.payloadDigest) ||
          !same(ready.finalExitTranscriptDigest, finalTranscript.digest)
        ) {
          authentication()
        }
        installFinalMaterial(state, finalTranscript)
        state.readyEncoded = copy(encoded)
        state.ready = ready
        ready = null
        this.#cancelRetry(state, 'activate')
        state.state = 'ACKING'
        return readyProjection(state.ready)
      } catch (err) {
        this.#terminate()
        if (err instanceof PrivateRouteError) throw err
        invalid()
      } finally {
        state.mutating = false
        clear(encoded)
        clearReady(ready)
        clear(input)
        if (finalTranscript) {
          clear(finalTranscript.encoded)
          clear(finalTranscript.digest)
        }
      }
    }

    sealAck(options) {
      const state = this.#begin()
      let readyDigest = null
      let encoded = null
      let ack = null
      try {
        if (!state.initiator || state.state !== 'ACKING' || state.ackEncoded) {
          authentication()
        }
        const randomBytes = option(object(options), 'randomBytes')
        if (typeof randomBytes !== 'function') invalid()
        this.#checkDeadline(state)
        readyDigest = digestDhtExitReady(state.readyEncoded)
        encoded = encodeDhtExitReadyAck({
          branchClass: state.transcript.branchClass,
          branchId: state.transcript.branchId,
          circuitId: state.transcript.circuitId,
          generation: state.transcript.generation,
          clientActivationNonce: state.activation.clientActivationNonce,
          readyDigest
        })
        const envelope = sealFrame(
          state,
          encoded,
          randomBytes,
          CONTEXT_CLASS.FINAL_EXIT_FINALIZE_DATAGRAM,
          DIRECTION.FORWARD
        )
        this.#assertLive(state)
        ack = decodeDhtExitReadyAck(encoded)
        state.ackEncoded = copy(encoded)
        state.ack = ack
        ack = null
        this.#startRetry(state, 'ack')
        return envelope
      } catch (err) {
        this.#terminate()
        if (err instanceof PrivateRouteError) throw err
        invalid()
      } finally {
        state.mutating = false
        clear(readyDigest)
        clear(encoded)
        clearAck(ack)
      }
    }

    retryAck(options) {
      const state = this.#begin()
      try {
        if (!state.initiator || state.state !== 'ACKING' || !state.ackEncoded) {
          authentication()
        }
        const randomBytes = option(object(options), 'randomBytes')
        if (typeof randomBytes !== 'function') invalid()
        this.#checkDeadline(state)
        this.#consumeRetry(state, 'ack')
        const envelope = sealFrame(
          state,
          state.ackEncoded,
          randomBytes,
          CONTEXT_CLASS.FINAL_EXIT_FINALIZE_DATAGRAM,
          DIRECTION.FORWARD
        )
        this.#assertLive(state)
        return envelope
      } catch (err) {
        if (retryUnavailable(err)) throw err
        this.#terminate()
        if (err instanceof PrivateRouteError) throw err
        invalid()
      } finally {
        state.mutating = false
      }
    }

    openRetiredActivate(envelope, options) {
      const state = this.#begin()
      let encoded = null
      try {
        if (state.initiator || state.state !== 'OPEN') authentication()
        if (!this.#checkGrace(state)) return null
        const randomBytes = option(object(options), 'randomBytes')
        if (typeof randomBytes !== 'function') invalid()
        encoded = openFrame(
          state,
          envelope,
          CONTEXT_CLASS.TAIL_FINALIZE_DATAGRAM,
          DIRECTION.FORWARD,
          DHT_EXIT_ACTIVATE_SIZE
        )
        this.#assertLive(state)
        if (encoded === null) return null
        if (!same(encoded, state.activationEncoded)) authentication()
        const response = sealFrame(
          state,
          state.openEncoded,
          randomBytes,
          CONTEXT_CLASS.FINAL_EXIT_FINALIZE_DATAGRAM,
          DIRECTION.REVERSE
        )
        this.#assertLive(state)
        return response
      } catch (err) {
        this.#terminate()
        if (err instanceof PrivateRouteError) throw err
        invalid()
      } finally {
        state.mutating = false
        clear(encoded)
      }
    }

    openAck(envelope, options) {
      const state = this.#begin()
      let encoded = null
      let ack = null
      let readyDigest = null
      let ackDigest = null
      let openEncoded = null
      let open = null
      try {
        if (state.initiator || (state.state !== 'FINALIZING' && state.state !== 'OPEN')) {
          authentication()
        }
        const retired = state.state === 'OPEN'
        if (retired && !this.#checkGrace(state)) return null
        const randomBytes = option(object(options), 'randomBytes')
        if (typeof randomBytes !== 'function') invalid()
        if (!retired) this.#checkDeadline(state)
        encoded = openFrame(
          state,
          envelope,
          CONTEXT_CLASS.FINAL_EXIT_FINALIZE_DATAGRAM,
          DIRECTION.FORWARD,
          DHT_EXIT_READY_ACK_SIZE
        )
        this.#assertLive(state)
        if (encoded === null) return null
        ack = decodeDhtExitReadyAck(encoded)
        readyDigest = digestDhtExitReady(state.readyEncoded)
        if (
          ack.branchClass !== state.transcript.branchClass ||
          !same(ack.branchId, state.transcript.branchId) ||
          !same(ack.circuitId, state.transcript.circuitId) ||
          ack.generation !== state.transcript.generation ||
          !same(ack.clientActivationNonce, state.activation.clientActivationNonce) ||
          !same(ack.readyDigest, readyDigest) ||
          (state.ackEncoded && !same(encoded, state.ackEncoded))
        ) {
          authentication()
        }
        if (!state.ackEncoded) {
          ackDigest = digestDhtExitReadyAck(encoded)
          openEncoded = encodeDhtExitOpen({
            branchClass: state.transcript.branchClass,
            branchId: state.transcript.branchId,
            circuitId: state.transcript.circuitId,
            generation: state.transcript.generation,
            ackDigest,
            clientActivationNonce: state.activation.clientActivationNonce,
            exitOriginCommandPolicyDigest: state.policyDigest,
            payloadParametersDigest: state.payloadDigest
          })
          open = decodeDhtExitOpen(openEncoded)
        }
        const semanticOpen = state.openEncoded || openEncoded
        this.#cancelRetry(state, 'ready')
        const response = sealFrame(
          state,
          semanticOpen,
          randomBytes,
          CONTEXT_CLASS.FINAL_EXIT_FINALIZE_DATAGRAM,
          DIRECTION.REVERSE
        )
        this.#assertLive(state)
        if (!state.ackEncoded) {
          state.ackEncoded = copy(encoded)
          state.ack = ack
          ack = null
          state.openEncoded = copy(openEncoded)
          state.open = open
          open = null
          this.#enterOpen(state)
          this.#startRetry(state, 'open')
        }
        return response
      } catch (err) {
        this.#terminate()
        if (err instanceof PrivateRouteError) throw err
        invalid()
      } finally {
        state.mutating = false
        clear(encoded)
        clearAck(ack)
        clear(readyDigest)
        clear(ackDigest)
        clear(openEncoded)
        clearOpen(open)
      }
    }

    retryOpen(options) {
      const state = this.#begin()
      try {
        if (state.initiator || state.state !== 'OPEN' || !state.openEncoded) {
          authentication()
        }
        if (!this.#checkGrace(state)) return null
        const randomBytes = option(object(options), 'randomBytes')
        if (typeof randomBytes !== 'function') invalid()
        this.#consumeRetry(state, 'open')
        const envelope = sealFrame(
          state,
          state.openEncoded,
          randomBytes,
          CONTEXT_CLASS.FINAL_EXIT_FINALIZE_DATAGRAM,
          DIRECTION.REVERSE
        )
        this.#assertLive(state)
        return envelope
      } catch (err) {
        if (retryUnavailable(err)) throw err
        this.#terminate()
        if (err instanceof PrivateRouteError) throw err
        invalid()
      } finally {
        state.mutating = false
      }
    }

    openOpen(envelope) {
      const state = this.#begin()
      let encoded = null
      let open = null
      let ackDigest = null
      try {
        if (!state.initiator || (state.state !== 'ACKING' && state.state !== 'OPEN')) {
          authentication()
        }
        const retired = state.state === 'OPEN'
        if (retired) {
          if (!this.#checkGrace(state)) return null
        } else {
          this.#checkDeadline(state)
        }
        if (!state.ackEncoded) authentication()
        encoded = openFrame(
          state,
          envelope,
          CONTEXT_CLASS.FINAL_EXIT_FINALIZE_DATAGRAM,
          DIRECTION.REVERSE,
          DHT_EXIT_OPEN_SIZE
        )
        this.#assertLive(state)
        if (encoded === null) return null
        if (state.openEncoded) {
          if (!same(encoded, state.openEncoded)) authentication()
          return null
        }
        open = decodeDhtExitOpen(encoded)
        ackDigest = digestDhtExitReadyAck(state.ackEncoded)
        if (
          open.branchClass !== state.transcript.branchClass ||
          !same(open.branchId, state.transcript.branchId) ||
          !same(open.circuitId, state.transcript.circuitId) ||
          open.generation !== state.transcript.generation ||
          !same(open.ackDigest, ackDigest) ||
          !same(open.clientActivationNonce, state.activation.clientActivationNonce) ||
          !same(open.exitOriginCommandPolicyDigest, state.policyDigest) ||
          !same(open.payloadParametersDigest, state.payloadDigest)
        ) {
          authentication()
        }
        state.openEncoded = copy(encoded)
        state.open = open
        open = null
        this.#cancelRetry(state, 'ack')
        this.#enterOpen(state)
        return openProjection(state.open)
      } catch (err) {
        this.#terminate()
        if (err instanceof PrivateRouteError) throw err
        invalid()
      } finally {
        state.mutating = false
        clear(encoded)
        clearOpen(open)
        clear(ackDigest)
      }
    }

    expireGrace() {
      const state = this.#begin()
      try {
        if (state.state !== 'OPEN' || state.graceRetired) return false
        if (this.#checkGrace(state)) return false
        return true
      } catch (err) {
        this.#terminate()
        if (err instanceof PrivateRouteError) throw err
        invalid()
      } finally {
        state.mutating = false
      }
    }

    takeDhtExitOpenAuthority(...args) {
      if (args.length !== 0) invalid()
      const state = this.#begin()
      let transport = null
      try {
        if (state.dhtExitOpenAuthority) throw PrivateRouteError.ERR_REPLAY()
        if (state.initiator || state.state !== 'OPEN' || !state.finalMaterial) authentication()
        transport = state.activationTransport
        if (transport === null) throw PrivateRouteError.ERR_REPLAY()
        state.activationTransport = null
        const authority = createDhtExitOpenAuthority(
          buildDhtExitOpenAuthorityMaterial(state, true),
          {
            transport,
            payloadDigest: state.payloadDigest,
            payloadForwardKey: state.finalMaterial.payloadForwardKey,
            payloadReverseKey: state.finalMaterial.payloadReverseKey,
            payloadForwardNoncePrefix: state.finalMaterial.payloadForwardNoncePrefix,
            payloadReverseNoncePrefix: state.finalMaterial.payloadReverseNoncePrefix
          }
        )
        transport = null
        state.dhtExitOpenAuthority = authority
        return authority
      } catch (err) {
        if (transport) {
          try {
            const { destroyM3RouteTransport } = require('./m3-adjacency-runtime')
            destroyM3RouteTransport(transport)
          } catch {}
        }
        if (!(err instanceof PrivateRouteError && err.code === 'ERR_REPLAY')) this.#terminate()
        if (err instanceof PrivateRouteError) throw err
        invalid()
      } finally {
        state.mutating = false
      }
    }

    takeEndpointDhtExitOpenAuthority(...args) {
      if (args.length !== 0) invalid()
      const state = this.#begin()
      try {
        if (state.endpointDhtExitOpenAuthority) throw PrivateRouteError.ERR_REPLAY()
        if (!state.initiator || state.state !== 'OPEN' || !state.finalMaterial) authentication()
        const authority = Object.freeze({})
        ENDPOINT_OPEN_AUTHORITIES.set(
          authority,
          Object.freeze({ material: buildDhtExitOpenAuthorityMaterial(state, false) })
        )
        state.endpointDhtExitOpenAuthority = authority
        return authority
      } catch (err) {
        if (!(err instanceof PrivateRouteError && err.code === 'ERR_REPLAY')) this.#terminate()
        if (err instanceof PrivateRouteError) throw err
        invalid()
      } finally {
        state.mutating = false
      }
    }

    takeOpenHandoff(...args) {
      if (args.length !== 0) invalid()
      const state = this.#begin()
      let material = null
      let transport = null
      let transportBound = false
      let handoff = null
      try {
        if (state.openHandoff) throw PrivateRouteError.ERR_REPLAY()
        if (state.state !== 'OPEN' || !state.finalMaterial) authentication()
        material = buildOpenRouteMaterial(state)
        if (state.initiator) {
          transport = state.activationTransport
          if (transport === null) throw PrivateRouteError.ERR_REPLAY()
          state.activationTransport = null
          const { bindOpenRouteTransport } = require('./live-route-authority')
          bindOpenRouteTransport(material, {
            transport,
            finalTranscriptDigest: state.finalTranscriptDigest
          })
          transportBound = true
          transport = null
        }
        handoff = issueOpenRouteHandoff(state.activationOwner, material)
        material = null
        state.openHandoff = handoff
        return handoff
      } catch (err) {
        if (transportBound && material) {
          try {
            const { destroyOpenRouteTransport } = require('./live-route-authority')
            destroyOpenRouteTransport(material)
          } catch {}
        } else if (transport) {
          try {
            const { destroyM3RouteTransport } = require('./m3-adjacency-runtime')
            destroyM3RouteTransport(transport)
          } catch {}
        }
        destroyOpenRouteMaterial(material)
        if (!(err instanceof PrivateRouteError && err.code === 'ERR_REPLAY')) this.#terminate()
        if (err instanceof PrivateRouteError) throw err
        invalid()
      } finally {
        state.mutating = false
      }
    }

    diagnostics() {
      const state = this.#state
      return Object.freeze({ state: !state || state.destroyed ? 'DESTROYED' : state.state })
    }

    destroy() {
      const state = this.#state
      if (!state || state.destroyed) return false
      this.#terminate()
      return true
    }

    #begin() {
      const state = this.#state
      if (!state || state.destroyed) throw PrivateRouteError.ERR_DESTROYED()
      if (state.mutating) {
        state.violated = true
        throw PrivateRouteError.ERR_BUSY()
      }
      state.mutating = true
      state.violated = false
      return state
    }

    #assertLive(state) {
      if (state.destroyed) throw PrivateRouteError.ERR_DESTROYED()
      const owner = state.activationOwner
      const record = owner && typeof owner === 'object' ? OWNERS.get(owner) : null
      if (!record || record.destroyed || DESTROYED_OWNERS.has(owner) || !record.sessionConsumed) {
        throw PrivateRouteError.ERR_DESTROYED()
      }
      if (state.violated) invalid()
    }
    #startRetry(state, phase) {
      this.#cancelRetry(state, phase)
      state.retryStartedAt[phase] = nowValue(state.monotonicNow)
      state.retryOrdinal[phase] = 1
      this.#armRetry(state, phase)
    }

    #armRetry(state, phase) {
      const ordinal = state.retryOrdinal[phase]
      if (!Number.isInteger(ordinal) || ordinal <= 0 || ordinal >= RETRY_OFFSETS.length) return
      const startedAt = state.retryStartedAt[phase]
      if (startedAt === null) invalid()
      const current = nowValue(state.monotonicNow)
      if (current < startedAt) invalid()
      const elapsed = current - startedAt
      const target = RETRY_OFFSETS[ordinal]
      const delay = elapsed >= target ? 0 : Number(target - elapsed)
      const handle = state.schedule(() => {}, delay)
      if (handle === undefined || handle === null) invalid()
      state.retryHandles[phase].push(handle)
    }

    #cancelRetry(state, phase = null) {
      const phases = phase === null ? Object.keys(state.retryHandles) : [phase]
      for (const name of phases) {
        const handles = state.retryHandles[name]
        while (handles.length > 0) {
          const handle = handles.pop()
          try {
            state.cancelScheduled(handle)
          } catch {}
        }
      }
    }

    #consumeRetry(state, phase) {
      const ordinal = state.retryOrdinal[phase]
      if (!Number.isInteger(ordinal) || ordinal <= 0 || ordinal >= RETRY_OFFSETS.length) invalid()
      const startedAt = state.retryStartedAt[phase]
      if (startedAt === null) invalid()
      const current = nowValue(state.monotonicNow)
      if (current < startedAt || current - startedAt < RETRY_OFFSETS[ordinal]) {
        throw retryDelayUnavailable()
      }
      state.retryOrdinal[phase] = ordinal + 1
      this.#cancelRetry(state, phase)
      this.#armRetry(state, phase)
    }

    #checkDeadline(state, start = false) {
      this.#assertLive(state)
      const current = nowValue(state.monotonicNow)
      this.#assertLive(state)
      if (state.deadline === null) {
        if (!start) invalid()
        const finalizationDeadline =
          current > MAX_UINT64 - FINALIZATION_TIMEOUT_MS
            ? MAX_UINT64
            : current + FINALIZATION_TIMEOUT_MS
        state.deadline =
          finalizationDeadline < state.material.localDeadline
            ? finalizationDeadline
            : state.material.localDeadline
      }
      if (current >= state.deadline) {
        throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
      }
    }

    #enterOpen(state) {
      this.#assertLive(state)
      const current = nowValue(state.monotonicNow)
      this.#assertLive(state)
      const retentionDeadline =
        current > MAX_UINT64 - FINALIZATION_TIMEOUT_MS
          ? MAX_UINT64
          : current + FINALIZATION_TIMEOUT_MS
      let graceDeadline = retentionDeadline < state.deadline ? retentionDeadline : state.deadline
      if (state.material.localDeadline < graceDeadline) graceDeadline = state.material.localDeadline
      state.graceDeadline = graceDeadline
      state.state = 'OPEN'
      installRetiredFinalizationState(state)
    }

    #checkGrace(state) {
      this.#assertLive(state)
      if (state.graceRetired || state.graceDeadline === null) return false
      const current = nowValue(state.monotonicNow)
      this.#assertLive(state)
      if (current < state.graceDeadline) return true
      eraseRetiredFinalizationState(state)
      this.#cancelRetry(state, 'open')
      return false
    }

    #terminate() {
      const state = this.#state
      if (!state || state.destroyed) return false
      state.destroyed = true
      FINAL_EXIT_DRIVER_STATES.delete(this)
      this.#cancelRetry(state)
      const activationOwner = state.activationOwner
      if (state.readySigner) {
        destroyDhtExitReadySigner(state.readySigner)
        state.readySigner = null
      }
      if (state.activationTransport) {
        try {
          const { destroyM3RouteTransport } = require('./m3-adjacency-runtime')
          destroyM3RouteTransport(state.activationTransport)
        } catch {}
        state.activationTransport = null
      }
      revokeOpenRouteHandoff(state.openHandoff)
      try {
        const { destroyDhtExitOpenAuthority } = require('./dht-exit-reservation')
        destroyDhtExitOpenAuthority(state.dhtExitOpenAuthority)
      } catch {}
      destroyEndpointDhtExitOpenAuthority(state.endpointDhtExitOpenAuthority)
      if (activationOwner && typeof activationOwner === 'object') {
        destroyFinalExitActivationOwner(activationOwner)
      } else {
        destroyFinalExitHandoffMaterial(state.material)
      }
      state.material = null
      for (const counter of [
        state.forwardTx,
        state.forwardRx,
        state.reverseTx,
        state.reverseRx,
        state.finalForwardTx,
        state.finalForwardRx,
        state.finalReverseTx,
        state.finalReverseRx
      ]) {
        try {
          if (counter) counter.destroy()
        } catch {}
      }
      clearTranscript(state.transcript)
      clear(state.policyDigest)
      clear(state.payloadDigest)
      clear(state.activationEncoded)
      clearActivation(state.activation)
      clear(state.readyEncoded)
      clearReady(state.ready)
      clear(state.ackEncoded)
      clearAck(state.ack)
      clear(state.openEncoded)
      clearOpen(state.open)
      clear(state.finalTranscript)
      clear(state.finalTranscriptDigest)
      clearFinalMaterial(state.finalMaterial)
      state.transcript = null
      state.policyDigest = null
      state.payloadDigest = null
      state.activationEncoded = null
      state.activation = null
      state.activationOwner = null
      state.tailControlOwner = null
      state.readyEncoded = null
      state.ready = null
      state.ackEncoded = null
      state.ack = null
      state.openEncoded = null
      state.open = null
      state.openHandoff = null
      state.finalTranscript = null
      state.finalTranscriptDigest = null
      state.finalMaterial = null
      state.deadline = null
      state.graceDeadline = null
      state.graceRetired = true
      state.crypto = null
      state.cancelScheduled = null
      state.now = null
      state.retryHandles = null
      state.retryOrdinal = null
      state.retryStartedAt = null
      state.schedule = null
      state.initiator = false
      state.forwardTx = null
      state.forwardRx = null
      state.reverseTx = null
      state.reverseRx = null
      state.finalForwardTx = null
      state.finalForwardRx = null
      state.finalReverseTx = null
      state.finalReverseRx = null
      state.state = 'DESTROYED'
      return true
    }
  }

  return {
    FinalExitActivationSession,
    consumeOpenRouteHandoff,
    revokeOpenRouteHandoff,
    destroyOpenRouteMaterial,
    ENDPOINT_OPEN_AUTHORITIES,
    SPENT_ENDPOINT_OPEN_AUTHORITIES
  }
})()

const {
  FinalExitActivationSession,
  consumeOpenRouteHandoff,
  revokeOpenRouteHandoff,
  destroyOpenRouteMaterial
} = finalExitActivationRuntime

function openFinalExit(factory, options) {
  const clock = readFinalExitActivationFactory(factory)
  exactObject(options, FINAL_EXIT_OPEN_KEYS)
  const session = new FinalExitActivationSession(options.handoff, {
    now: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    crypto: options.crypto,
    readySigner: options.readySigner,
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled,
    payloadParameters: options.payloadParameters
  })
  const noArgs = (args) => {
    if (args.length !== 0) invalid()
  }
  const facade = Object.freeze({
    sealActivate(...args) {
      noArgs(args)
      return session.sealActivate({ randomBytes: clock.randomBytes })
    },
    retryActivate(...args) {
      noArgs(args)
      return session.retryActivate({ randomBytes: clock.randomBytes })
    },
    openActivate(envelope) {
      return session.openActivate(envelope)
    },
    sealReady(...args) {
      noArgs(args)
      return session.sealReady({ randomBytes: clock.randomBytes })
    },
    retryReady(...args) {
      noArgs(args)
      return session.retryReady({ randomBytes: clock.randomBytes })
    },
    openReady(envelope) {
      return session.openReady(envelope)
    },
    sealAck(...args) {
      noArgs(args)
      return session.sealAck({ randomBytes: clock.randomBytes })
    },
    retryAck(...args) {
      noArgs(args)
      return session.retryAck({ randomBytes: clock.randomBytes })
    },
    openRetiredActivate(envelope, ...args) {
      noArgs(args)
      return session.openRetiredActivate(envelope, { randomBytes: clock.randomBytes })
    },
    openAck(envelope, ...args) {
      noArgs(args)
      return session.openAck(envelope, { randomBytes: clock.randomBytes })
    },
    retryOpen(...args) {
      noArgs(args)
      return session.retryOpen({ randomBytes: clock.randomBytes })
    },
    openOpen(envelope) {
      return session.openOpen(envelope)
    },
    takeOpenHandoff(...args) {
      noArgs(args)
      return session.takeOpenHandoff()
    },
    takeDhtExitOpenAuthority(...args) {
      noArgs(args)
      return session.takeDhtExitOpenAuthority()
    },
    takeEndpointDhtExitOpenAuthority(...args) {
      noArgs(args)
      return session.takeEndpointDhtExitOpenAuthority()
    },
    diagnostics() {
      return session.diagnostics()
    },
    destroy() {
      return session.destroy()
    }
  })
  const state = FINAL_EXIT_DRIVER_STATES.get(session)
  if (state) FINAL_EXIT_DRIVERS.set(facade, { session, state, spent: false })
  return facade
}
async function driveEndpointFinalExit(facade) {
  const record = facade && typeof facade === 'object' ? FINAL_EXIT_DRIVERS.get(facade) : null
  if (!record || record.spent) authentication()
  const { session, state } = record
  if (
    FINAL_EXIT_DRIVER_STATES.get(session) !== state ||
    state.destroyed ||
    !state.initiator ||
    state.activationTransport === null
  ) {
    authentication()
  }
  record.spent = true
  FINAL_EXIT_DRIVERS.delete(facade)
  const { CONTEXT_CLASS } = require('./protocol')
  const { receiveM3RouteFrame, sendM3RouteFrame } = require('./m3-adjacency-runtime')
  let outbound = null
  let inbound = null
  try {
    let envelope = facade.sealActivate()
    outbound = encodeActivationRouteFrame(envelope)
    clear(envelope)
    await sendM3RouteFrame(state.activationTransport, outbound)
    clear(outbound)
    outbound = null
    inbound = await receiveM3RouteFrame(state.activationTransport)
    envelope = decodeActivationRouteFrame(inbound, CONTEXT_CLASS.TAIL_FINALIZE_DATAGRAM)
    clear(inbound)
    inbound = null
    facade.openReady(envelope)
    clear(envelope)
    envelope = facade.sealAck()
    outbound = encodeActivationRouteFrame(envelope)
    clear(envelope)
    await sendM3RouteFrame(state.activationTransport, outbound)
    clear(outbound)
    outbound = null
    inbound = await receiveM3RouteFrame(state.activationTransport)
    envelope = decodeActivationRouteFrame(inbound, CONTEXT_CLASS.FINAL_EXIT_FINALIZE_DATAGRAM)
    clear(inbound)
    inbound = null
    facade.openOpen(envelope)
    clear(envelope)
    facade.takeEndpointDhtExitOpenAuthority()
    return facade.takeOpenHandoff()
  } catch (err) {
    facade.destroy()
    throw err instanceof PrivateRouteError ? err : PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  } finally {
    clear(outbound)
    clear(inbound)
  }
}
async function driveDhtExitFinalExit(facade) {
  const record = facade && typeof facade === 'object' ? FINAL_EXIT_DRIVERS.get(facade) : null
  if (!record || record.spent) authentication()
  const { session, state } = record
  if (
    FINAL_EXIT_DRIVER_STATES.get(session) !== state ||
    state.destroyed ||
    state.initiator ||
    state.activationTransport === null
  ) {
    authentication()
  }
  record.spent = true
  FINAL_EXIT_DRIVERS.delete(facade)
  const { receiveM3RouteFrame, sendM3RouteFrame } = require('./m3-adjacency-runtime')
  const { CONTEXT_CLASS } = require('./protocol')
  let outbound = null
  let inbound = null
  try {
    inbound = await receiveM3RouteFrame(state.activationTransport)
    let envelope = decodeActivationRouteFrame(inbound, CONTEXT_CLASS.TAIL_FINALIZE_DATAGRAM)
    clear(inbound)
    inbound = null
    facade.openActivate(envelope)
    clear(envelope)
    envelope = facade.sealReady()
    outbound = encodeActivationRouteFrame(envelope)
    clear(envelope)
    await sendM3RouteFrame(state.activationTransport, outbound)
    clear(outbound)
    outbound = null
    inbound = await receiveM3RouteFrame(state.activationTransport)
    envelope = decodeActivationRouteFrame(inbound, CONTEXT_CLASS.FINAL_EXIT_FINALIZE_DATAGRAM)
    clear(inbound)
    inbound = null
    envelope = facade.openAck(envelope)
    outbound = encodeActivationRouteFrame(envelope)
    clear(envelope)
    await sendM3RouteFrame(state.activationTransport, outbound)
    clear(outbound)
    outbound = null
    return facade.takeDhtExitOpenAuthority()
  } catch (err) {
    facade.destroy()
    throw err instanceof PrivateRouteError ? err : PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  } finally {
    clear(outbound)
    clear(inbound)
  }
}

function takeDhtExitOpenAuthority(session) {
  if (!session || typeof session.takeDhtExitOpenAuthority !== 'function') authentication()
  return session.takeDhtExitOpenAuthority()
}

function clearEndpointDhtExitOpenMaterial(material) {
  if (material === null || typeof material !== 'object') return
  for (const name of [
    'branchId',
    'circuitId',
    'exitIdentity',
    'finalTranscriptDigest',
    'controlKey',
    'controlNoncePrefix'
  ]) {
    try {
      if (b4a.isBuffer(material[name])) material[name].fill(0)
      material[name] = null
    } catch {}
  }
  try {
    material.generation = 0n
    material.expiresAt = 0n
    material.absoluteDeadline = 0n
  } catch {}
}

function createTestEndpointDhtExitOpenAuthority(value) {
  exactObject(value, TEST_ENDPOINT_DHT_EXIT_OPEN_KEYS)
  const { BRANCH_CLASS } = require('./protocol')
  if (
    (value.branchClass !== BRANCH_CLASS.LOOKUP && value.branchClass !== BRANCH_CLASS.ANNOUNCE) ||
    typeof value.generation !== 'bigint' ||
    value.generation < 0n ||
    typeof value.expiresAt !== 'bigint' ||
    value.expiresAt <= 0n ||
    typeof value.absoluteDeadline !== 'bigint' ||
    value.absoluteDeadline <= 0n ||
    value.absoluteDeadline > value.expiresAt
  ) {
    invalid()
  }
  const sizes = {
    branchId: 16,
    circuitId: 16,
    exitIdentity: 32,
    finalTranscriptDigest: 32,
    controlKey: 32,
    controlNoncePrefix: 16
  }
  const material = {
    branchClass: value.branchClass,
    generation: value.generation,
    expiresAt: value.expiresAt,
    absoluteDeadline: value.absoluteDeadline
  }
  for (const [name, size] of Object.entries(sizes)) {
    if (!b4a.isBuffer(value[name]) || value[name].byteLength !== size) invalid()
    material[name] = b4a.from(value[name])
  }
  const authority = Object.freeze({})
  finalExitActivationRuntime.ENDPOINT_OPEN_AUTHORITIES.set(authority, Object.freeze({ material }))
  return authority
}

function consumeEndpointDhtExitOpenAuthority(authority) {
  const record =
    authority !== null && typeof authority === 'object'
      ? finalExitActivationRuntime.ENDPOINT_OPEN_AUTHORITIES.get(authority)
      : null
  if (!record) {
    if (
      authority !== null &&
      typeof authority === 'object' &&
      finalExitActivationRuntime.SPENT_ENDPOINT_OPEN_AUTHORITIES.has(authority)
    ) {
      throw PrivateRouteError.ERR_REPLAY()
    }
    throw PrivateRouteError.ERR_AUTHENTICATION()
  }
  finalExitActivationRuntime.ENDPOINT_OPEN_AUTHORITIES.delete(authority)
  finalExitActivationRuntime.SPENT_ENDPOINT_OPEN_AUTHORITIES.add(authority)
  return record.material
}

function destroyEndpointDhtExitOpenAuthority(authority) {
  if (authority === null || typeof authority !== 'object') return false
  const record = finalExitActivationRuntime.ENDPOINT_OPEN_AUTHORITIES.get(authority)
  if (!record) return false
  finalExitActivationRuntime.ENDPOINT_OPEN_AUTHORITIES.delete(authority)
  finalExitActivationRuntime.SPENT_ENDPOINT_OPEN_AUTHORITIES.add(authority)
  clearEndpointDhtExitOpenMaterial(record.material)
  return true
}

function takeEndpointDhtExitOpenAuthority(session) {
  if (!session || typeof session.takeEndpointDhtExitOpenAuthority !== 'function') authentication()
  return session.takeEndpointDhtExitOpenAuthority()
}

module.exports = {
  claimFinalExitActivation,
  FinalExitActivationSession,
  consumeOpenRouteHandoff,
  destroyOpenRouteMaterial,
  consumeFinalExitActivationOwnerReservation,
  createFinalExitActivationFactory,
  createFinalExitActivationClaim,
  destroyFinalExitActivationOwner,
  reserveFinalExitActivationOwner,
  revokeFinalExitActivationClaim,
  revokeFinalExitActivationOwnerReservation,
  openFinalExit,
  driveEndpointFinalExit,
  driveDhtExitFinalExit,
  readFinalExitActivationFactory,
  takeDhtExitOpenAuthority,
  takeEndpointDhtExitOpenAuthority,
  consumeEndpointDhtExitOpenAuthority,
  destroyEndpointDhtExitOpenAuthority,
  [TEST_ONLY_ENDPOINT_DHT_EXIT_OPEN_ISSUER]: Object.freeze({
    create: createTestEndpointDhtExitOpenAuthority
  }),
  revokeOpenRouteHandoff
}
