'use strict'

// Adapted from guard-revalidation-io.js in the reviewed private-routes
// prototype at commit 0305df915b6a767093f9e75e6c06bc0a35da6169.

const b4a = require('b4a')

const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')
const {
  abortIndexZeroGuardLink,
  completeIndexZeroGuardLink,
  createIndexZeroGuardLinkOffer,
  destroyM3EstablishedLink,
  readM3EstablishedLink
} = require('./guard-link')
const { digestPayloadParameters } = require('./link-parameters')
const { BRANCH_CLASS, RELAY_CAPABILITY, ROLE, roleForIdentity } = require('./protocol')
const {
  MAX_CAPABILITY_ADVERTISEMENTS,
  RelayCapabilityVerifier,
  createActiveChallengeSendAuthority,
  decodeCanonicalEndpoint,
  decodeRelayCapabilityAdvertisement,
  digestRelayCapabilityAdvertisement
} = require('./relay-capability')

const RECONNECT_DEADLINE = 5_000n
const MAX_U64 = 0xffff_ffff_ffff_ffffn
const FIELDS = Object.freeze([
  'guardIdentity',
  'guardEndpoint',
  'advertisement',
  'advertisementDigest',
  'epoch',
  'expiresAt',
  'localIdentity',
  'localSecretKey',
  'reconnectDatagrams',
  'wallNow',
  'monotonicNow',
  'setTimer',
  'clearTimer'
])
const RESPONSE_FIELDS = Object.freeze({
  activeChallenge: ['bytes'],
  link: ['accept', 'physicalChannel']
})
const CAPS_QUERY_RESPONSE_FIELDS = Object.freeze([
  'sourceEndpoint',
  'cookieExpiresAtMs',
  'returnRoutabilityCookie',
  'advertisements'
])

const byteLengthGetter = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
const bufferFill = Uint8Array.prototype.fill
const bufferSet = Uint8Array.prototype.set
const objectFreeze = Object.freeze
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectGetOwnPropertyNames = Object.getOwnPropertyNames
const objectGetOwnPropertySymbols = Object.getOwnPropertySymbols
const objectGetPrototypeOf = Object.getPrototypeOf
const reflectApply = Reflect.apply

const states = new WeakMap()
const inFlights = new WeakMap()

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function unavailable() {
  throw PrivateRouteError.ERR_PRIVATE_GUARD_UNAVAILABLE()
}

function destroyed() {
  throw PrivateRouteError.ERR_DESTROYED()
}

function replay() {
  throw PrivateRouteError.ERR_REPLAY()
}

function length(value) {
  try {
    return b4a.isBuffer(value) ? reflectApply(byteLengthGetter, value, []) : -1
  } catch {
    return -1
  }
}

function fixed(value, size) {
  return length(value) === size
}

function clear(value) {
  try {
    if (length(value) >= 0) reflectApply(bufferFill, value, [0])
  } catch {}
}

function copy(value, size = length(value)) {
  if (!fixed(value, size)) invalid()
  const output = b4a.allocUnsafeSlow(size)
  try {
    reflectApply(bufferSet, output, [value, 0])
    return output
  } catch {
    clear(output)
    invalid()
  }
}

function same(left, right) {
  try {
    return length(left) === length(right) && b4a.equals(left, right)
  } catch {
    return false
  }
}

function createPrivateAbortController() {
  const signal = { aborted: false }
  return {
    signal,
    abort() {
      signal.aborted = true
    }
  }
}

function exactObject(value, fields) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid()
    const prototype = objectGetPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) invalid()
    if (objectGetOwnPropertySymbols(value).length !== 0) invalid()
    const names = objectGetOwnPropertyNames(value)
    if (names.length !== fields.length) invalid()
    for (const field of fields) {
      const descriptor = objectGetOwnPropertyDescriptor(value, field)
      if (!descriptor || !('value' in descriptor)) invalid()
    }
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function own(value, name) {
  let descriptor
  try {
    descriptor = objectGetOwnPropertyDescriptor(value, name)
  } catch {
    invalid()
  }
  if (!descriptor || !('value' in descriptor)) invalid()
  return descriptor.value
}

function u64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= MAX_U64
}

function tuple(encoded) {
  const endpoint = decodeCanonicalEndpoint(encoded)
  try {
    const family = endpoint[0]
    const port = endpoint[17] * 0x100 + endpoint[18]
    if (family === 4) {
      return objectFreeze({
        host: `${endpoint[13]}.${endpoint[14]}.${endpoint[15]}.${endpoint[16]}`,
        port
      })
    }
    const words = []
    for (let offset = 1; offset < 17; offset += 2) {
      words.push(((endpoint[offset] << 8) | endpoint[offset + 1]).toString(16))
    }
    return objectFreeze({ host: words.join(':'), port })
  } finally {
    clear(endpoint)
  }
}

function clearDecoded(value) {
  if (!value) return
  clear(value.relayIdentity)
  clear(value.currentDhtNodeId)
  clear(value.reachableEndpoint)
  clear(value.routeEncryptionPublicKey)
  clear(value.signature)
}

function sample(state, name) {
  if (state.sampling || typeof state[name] !== 'function') {
    destroyed()
  }
  state.sampling = true
  let value
  try {
    value = state[name]()
  } catch {
    invalid()
  } finally {
    state.sampling = false
  }
  if (!u64(value)) {
    invalid()
  }
  return value
}

function clearOwnedState(state) {
  if (!state) return
  clear(state.guardIdentity)
  clear(state.guardEndpoint)
  clear(state.advertisement)
  clear(state.advertisementDigest)
  clear(state.localIdentity)
  clear(state.localSecretKey)
  state.guardIdentity = null
  state.guardEndpoint = null
  state.advertisement = null
  state.advertisementDigest = null
  state.localIdentity = null
  state.localSecretKey = null
}

function clearOwnedTimer(state) {
  if (!state) return
  const timer = state.timer
  state.timer = null
  if (timer === null) return
  try {
    state.clearTimer(timer)
  } catch {}
}

function destroyOwnedTransport(state) {
  if (!state) return
  const transport = state.transport
  state.transport = null
  state.transportFactory = null
  try {
    if (transport && typeof transport.destroy === 'function') transport.destroy()
  } catch {}
}

function clearOperation(operation) {
  if (!operation) return
  clearOwnedTimer(operation)
  destroyOwnedTransport(operation)
  clearOwnedState(operation)
  operation.deadlinePromise = null
  operation.reject = null
}

function terminateOperation(authority, operation, code) {
  if (!operation || operation.status !== 'ACTIVE') return false
  operation.status = code === 'ERR_DESTROYED' ? 'REVOKED' : 'EXPIRED'
  try {
    operation.abortController.abort()
  } catch {}
  const reject = operation.reject
  operation.reject = null
  if (reject) {
    try {
      reject(
        code === 'ERR_DESTROYED'
          ? PrivateRouteError.ERR_DESTROYED()
          : PrivateRouteError.ERR_PRIVATE_GUARD_UNAVAILABLE()
      )
    } catch {}
  }
  clearOperation(operation)
  return true
}

function revokeState(authority, state) {
  if (!state || state.status === 'REVOKED') return false
  state.status = 'REVOKED'
  state.generation = null
  clearOwnedTimer(state)
  const operation = inFlights.get(authority)
  if (operation) terminateOperation(authority, operation, 'ERR_DESTROYED')
  destroyOwnedTransport(state)
  clearOwnedState(state)
  return true
}

function deadlineCheck(operation) {
  if (operation.status === 'REVOKED') destroyed()
  if (operation.status !== 'ACTIVE') unavailable()
  const monotonic = sample(operation, 'monotonicNow')
  const wall = sample(operation, 'wallNow')
  if (operation.status === 'REVOKED') destroyed()
  if (
    operation.status !== 'ACTIVE' ||
    monotonic < operation.startedAt ||
    monotonic >= operation.deadlineAt ||
    wall >= operation.deadlineWall
  ) {
    unavailable()
  }
  return wall
}

function exactResponse(value, kind) {
  exactObject(value, RESPONSE_FIELDS[kind])
  return value
}

function exactEmptyResponse(value) {
  exactObject(value, [])
  return value
}

function capsQuery(randomTarget, queryNonce) {
  return objectFreeze({
    kind: 'caps-query',
    requestedCapabilityMask: RELAY_CAPABILITY.CIRCUIT_RELAY_V1,
    randomTarget,
    queryNonce,
    maximumResults: MAX_CAPABILITY_ADVERTISEMENTS
  })
}

function capsRetry(session, advertisement) {
  return objectFreeze({
    kind: 'caps-retry',
    sourceEndpoint: session.sourceEndpoint,
    requestedCapabilityMask: RELAY_CAPABILITY.CIRCUIT_RELAY_V1,
    randomTarget: session.randomTarget,
    queryNonce: session.queryNonce,
    maximumResults: MAX_CAPABILITY_ADVERTISEMENTS,
    cookieExpiresAtMs: session.cookieExpiresAtMs,
    returnRoutabilityCookie: session.returnRoutabilityCookie,
    advertisement
  })
}

function bytesMessage(kind, bytes) {
  return objectFreeze({ kind, bytes })
}

async function send(operation, value) {
  deadlineCheck(operation)
  const transport = operation.transport
  if (!transport || typeof transport.send !== 'function') destroyed()
  const response = await Promise.race([
    transport.send(
      operation.tuple.host,
      operation.tuple.port,
      value,
      operation.abortController.signal
    ),
    operation.deadlinePromise
  ])
  deadlineCheck(operation)
  return response
}

function clearSession(session) {
  if (!session) return
  clear(session.sourceEndpoint)
  clear(session.randomTarget)
  clear(session.queryNonce)
  clear(session.returnRoutabilityCookie)
}

async function authenticateCaps(operation) {
  let randomTarget = null
  let queryNonce = null
  let sourceEndpoint = null
  let returnRoutabilityCookie = null
  let verifier = null
  try {
    randomTarget = cryptoSuite.randomBytes(32)
    queryNonce = cryptoSuite.randomBytes(32)
    const response = await send(operation, capsQuery(randomTarget, queryNonce))
    exactObject(response, CAPS_QUERY_RESPONSE_FIELDS)
    sourceEndpoint = copy(own(response, 'sourceEndpoint'), 19)
    const decodedSource = decodeCanonicalEndpoint(sourceEndpoint)
    clear(decodedSource.addressBytes)
    const cookieExpiresAtMs = own(response, 'cookieExpiresAtMs')
    returnRoutabilityCookie = copy(own(response, 'returnRoutabilityCookie'), 32)
    const advertisements = own(response, 'advertisements')
    const now = deadlineCheck(operation)
    if (
      !u64(cookieExpiresAtMs) ||
      cookieExpiresAtMs <= now ||
      cookieExpiresAtMs > now + RECONNECT_DEADLINE ||
      !Array.isArray(advertisements) ||
      advertisements.length < 1 ||
      advertisements.length > MAX_CAPABILITY_ADVERTISEMENTS
    ) {
      unavailable()
    }
    let selected = null
    for (const advertisement of advertisements) {
      if (same(advertisement, operation.advertisement)) {
        if (selected !== null) unavailable()
        selected = advertisement
      }
    }
    if (selected === null) unavailable()
    verifier = new RelayCapabilityVerifier({
      wallNow: operation.wallNow,
      monotonicNow: operation.monotonicNow,
      setTimer: () => objectFreeze({}),
      clearTimer() {},
      onInvalidated() {}
    })
    const projection = verifier.accept(selected, {
      expectedRole: ROLE.SAFETY,
      expectedCapabilityMask: RELAY_CAPABILITY.CIRCUIT_RELAY_V1
    })
    if (
      !same(projection.identity, operation.guardIdentity) ||
      !same(projection.canonicalEndpointBytes, operation.guardEndpoint) ||
      !same(projection.digest, operation.advertisementDigest) ||
      projection.epoch !== operation.epoch ||
      projection.expiresAt !== operation.signedExpiresAt
    ) {
      unavailable()
    }
    const session = {
      sourceEndpoint,
      randomTarget,
      queryNonce,
      cookieExpiresAtMs,
      returnRoutabilityCookie
    }
    sourceEndpoint = null
    randomTarget = null
    queryNonce = null
    returnRoutabilityCookie = null
    try {
      await send(operation, capsRetry(session, projection.canonicalBytes)).then(exactEmptyResponse)
      const authority = createActiveChallengeSendAuthority({
        capsBinding: {
          advertisement: projection,
          sourceEndpoint: session.sourceEndpoint,
          queryNonce: session.queryNonce,
          cookieExpiresAtMs: session.cookieExpiresAtMs,
          returnRoutabilityCookie: session.returnRoutabilityCookie,
          advertisementDigest: projection.digest,
          relayIdentity: projection.identity
        },
        async send(challenge) {
          const challenged = exactResponse(
            await send(operation, bytesMessage('active-challenge', challenge)),
            'activeChallenge'
          )
          return own(challenged, 'bytes')
        }
      })
      await verifier.beginChallenge(projection, authority)
    } finally {
      clearSession(session)
    }
  } finally {
    if (verifier) verifier.destroy()
    clear(sourceEndpoint)
    clear(randomTarget)
    clear(queryNonce)
    clear(returnRoutabilityCookie)
  }
}

async function reconnect(authority, operation) {
  let pending = null
  let established = null
  let physicalChannel = null
  let decoded = null
  let identitySeed = null
  let identity = null
  let tailSeed = null
  let tail = null
  let branchId = null
  let circuitId = null
  try {
    await authenticateCaps(operation)
    const now = deadlineCheck(operation)
    decoded = decodeRelayCapabilityAdvertisement(operation.advertisement, { now })
    identitySeed = copy(operation.localSecretKey.subarray(0, 32), 32)
    identity = cryptoSuite.keyPair(identitySeed)
    clear(identitySeed)
    identitySeed = null
    if (!same(identity.publicKey, operation.localIdentity)) unavailable()
    tailSeed = cryptoSuite.randomBytes(32)
    tail = cryptoSuite.encryptionKeyPair(tailSeed)
    clear(tailSeed)
    tailSeed = null
    branchId = cryptoSuite.randomBytes(16)
    circuitId = cryptoSuite.randomBytes(16)
    const initiated = createIndexZeroGuardLinkOffer({
      advertisement: operation.advertisement,
      now,
      randomBytes: cryptoSuite.randomBytes,
      branchClass: BRANCH_CLASS.LOOKUP,
      branchId,
      circuitId,
      generation: 1n,
      clientCircuitIdentity: identity,
      clientTailEphemeral: tail,
      payloadParametersDigest: digestPayloadParameters(decoded),
      requestedLimits: {
        cellSize: 1200,
        maxCells: decoded.maxCellsPerCircuit,
        maxBytes: decoded.maxBytesPerCircuit,
        maxCommands: decoded.maxCommandsPerCircuit,
        idleTimeoutMs: decoded.idleTimeoutMs,
        expiresAtMs: decoded.expiresAtMs
      }
    })
    pending = initiated.pending
    const linked = exactResponse(
      await send(operation, bytesMessage('link', initiated.offer)),
      'link'
    )
    physicalChannel = own(linked, 'physicalChannel')
    if (
      physicalChannel === null ||
      typeof physicalChannel !== 'object' ||
      typeof physicalChannel.destroy !== 'function'
    ) {
      invalid()
    }
    const moved = physicalChannel
    physicalChannel = null
    established = completeIndexZeroGuardLink(pending, own(linked, 'accept'), {
      advertisement: operation.advertisement,
      physicalChannel: moved,
      now: deadlineCheck(operation)
    })
    pending = null
    const link = readM3EstablishedLink(established)
    if (!same(link.peerIdentity, operation.guardIdentity)) unavailable()
    clearOperation(operation)
    const current = states.get(authority)
    if (
      !current ||
      current.status !== 'SPENT' ||
      current.generation !== operation.generation ||
      operation.status !== 'ACTIVE' ||
      inFlights.get(authority) !== operation
    ) {
      destroyed()
    }
    operation.status = 'COMPLETE'
    current.status = 'COMPLETE'
    current.generation = null
    inFlights.delete(authority)
    const result = established
    established = null
    return result
  } catch (err) {
    if (pending) abortIndexZeroGuardLink(pending)
    if (established) destroyM3EstablishedLink(established)
    if (physicalChannel) {
      try {
        physicalChannel.destroy()
      } catch {}
    }
    const revoked = operation.status === 'REVOKED'
    if (operation.status === 'ACTIVE') terminateOperation(authority, operation, 'EXPIRED')
    else clearOperation(operation)
    if (inFlights.get(authority) === operation) inFlights.delete(authority)
    if (revoked || (err instanceof PrivateRouteError && err.code === 'ERR_DESTROYED')) throw err
    unavailable()
  } finally {
    clearDecoded(decoded)
    clear(identitySeed)
    if (identity) {
      clear(identity.publicKey)
      clear(identity.secretKey)
    }
    clear(tailSeed)
    if (tail) {
      clear(tail.publicKey)
      clear(tail.secretKey)
    }
    clear(branchId)
    clear(circuitId)
  }
}

function createGuardReconnectAuthority(options) {
  exactObject(options, FIELDS)
  let guardIdentity = null
  let guardEndpoint = null
  let advertisement = null
  let advertisementDigest = null
  let localIdentity = null
  let localSecretKey = null
  let decoded = null
  let computedDigest = null
  let timer = null
  let state = null
  try {
    guardIdentity = copy(own(options, 'guardIdentity'), 32)
    guardEndpoint = copy(own(options, 'guardEndpoint'), 19)
    advertisement = copy(own(options, 'advertisement'))
    advertisementDigest = copy(own(options, 'advertisementDigest'), 32)
    localIdentity = copy(own(options, 'localIdentity'), 32)
    localSecretKey = copy(own(options, 'localSecretKey'), 64)
    const epoch = own(options, 'epoch')
    const expiresAt = own(options, 'expiresAt')
    const reconnectTransport = own(options, 'reconnectDatagrams')
    const wallNow = own(options, 'wallNow')
    const monotonicNow = own(options, 'monotonicNow')
    const setTimer = own(options, 'setTimer')
    const clearTimerFn = own(options, 'clearTimer')
    if (
      !u64(epoch) ||
      epoch === 0n ||
      !u64(expiresAt) ||
      (typeof reconnectTransport !== 'function' &&
        (reconnectTransport === null ||
          typeof reconnectTransport !== 'object' ||
          typeof reconnectTransport.send !== 'function' ||
          typeof reconnectTransport.destroy !== 'function')) ||
      typeof wallNow !== 'function' ||
      typeof monotonicNow !== 'function' ||
      typeof setTimer !== 'function' ||
      typeof clearTimerFn !== 'function'
    )
      invalid()
    const now = wallNow()
    if (!u64(now) || expiresAt <= now) invalid()
    decoded = decodeRelayCapabilityAdvertisement(advertisement, { now })
    computedDigest = digestRelayCapabilityAdvertisement(advertisement, { now })
    if (
      !same(decoded.relayIdentity, guardIdentity) ||
      !same(decoded.reachableEndpoint, guardEndpoint) ||
      !same(computedDigest, advertisementDigest) ||
      decoded.epoch !== epoch ||
      decoded.expiresAtMs < expiresAt ||
      decoded.capabilityMask !== RELAY_CAPABILITY.CIRCUIT_RELAY_V1 ||
      roleForIdentity(decoded.relayIdentity) !== ROLE.SAFETY
    )
      unavailable()
    const boundTuple = tuple(guardEndpoint)
    const authority = objectFreeze({
      reconnect: function reconnectOperation() {
        if (arguments.length !== 0) invalid()
        const current = states.get(authority)
        if (!current || current.status === 'REVOKED') destroyed()
        if (current.status !== 'READY') replay()
        current.status = 'SPENT'
        clearOwnedTimer(current)
        let operation = null
        let ownedGuardIdentity = null
        let ownedGuardEndpoint = null
        let ownedAdvertisement = null
        let ownedAdvertisementDigest = null
        let ownedLocalIdentity = null
        let ownedLocalSecretKey = null
        let createdTransport = null
        try {
          const startedWall = sample(current, 'wallNow')
          const startedAt = sample(current, 'monotonicNow')
          if (current.status !== 'SPENT') destroyed()
          const deadlineWall = [
            startedWall + RECONNECT_DEADLINE,
            current.signedExpiresAt,
            current.expiresAt
          ].reduce((minimum, value) => (value < minimum ? value : minimum))
          if (deadlineWall <= startedWall) unavailable()
          ownedGuardIdentity = copy(current.guardIdentity, 32)
          ownedGuardEndpoint = copy(current.guardEndpoint, 19)
          ownedAdvertisement = copy(current.advertisement)
          ownedAdvertisementDigest = copy(current.advertisementDigest, 32)
          ownedLocalIdentity = copy(current.localIdentity, 32)
          ownedLocalSecretKey = copy(current.localSecretKey, 64)
          let transport = current.transport
          if (transport === null) {
            const factory = current.transportFactory
            if (typeof factory !== 'function') unavailable()
            transport = factory()
            createdTransport = transport
            if (
              transport === null ||
              typeof transport !== 'object' ||
              typeof transport.send !== 'function' ||
              typeof transport.destroy !== 'function'
            )
              unavailable()
          }
          operation = {
            status: 'ACTIVE',
            generation: current.generation,
            guardIdentity: ownedGuardIdentity,
            guardEndpoint: ownedGuardEndpoint,
            advertisement: ownedAdvertisement,
            advertisementDigest: ownedAdvertisementDigest,
            epoch: current.epoch,
            expiresAt: current.expiresAt,
            signedExpiresAt: current.signedExpiresAt,
            localIdentity: ownedLocalIdentity,
            localSecretKey: ownedLocalSecretKey,
            tuple: current.tuple,
            transport,
            wallNow: current.wallNow,
            monotonicNow: current.monotonicNow,
            setTimer: current.setTimer,
            clearTimer: current.clearTimer,
            timer: null,
            abortController: createPrivateAbortController(),
            deadlinePromise: null,
            reject: null,
            startedAt,
            deadlineAt: startedAt + (deadlineWall - startedWall),
            deadlineWall,
            sampling: false
          }
          createdTransport = null
          ownedGuardIdentity = null
          ownedGuardEndpoint = null
          ownedAdvertisement = null
          ownedAdvertisementDigest = null
          ownedLocalIdentity = null
          ownedLocalSecretKey = null
          operation.deadlinePromise = new Promise((resolve, reject) => {
            operation.reject = reject
          })
          void operation.deadlinePromise.catch(() => {})
          inFlights.set(authority, operation)
          current.transport = null
          current.transportFactory = null
          clearOwnedState(current)
          operation.timer = operation.setTimer(
            () => terminateOperation(authority, operation, 'EXPIRED'),
            Number(deadlineWall - startedWall)
          )
          if (operation.status !== 'ACTIVE' || inFlights.get(authority) !== operation) destroyed()
          return reconnect(authority, operation)
        } catch (err) {
          clear(ownedGuardIdentity)
          clear(ownedGuardEndpoint)
          clear(ownedAdvertisement)
          clear(ownedAdvertisementDigest)
          clear(ownedLocalIdentity)
          clear(ownedLocalSecretKey)
          try {
            if (createdTransport && typeof createdTransport.destroy === 'function')
              createdTransport.destroy()
          } catch {}
          if (operation) {
            if (operation.status === 'ACTIVE') terminateOperation(authority, operation, 'EXPIRED')
            else clearOperation(operation)
            if (inFlights.get(authority) === operation) inFlights.delete(authority)
          }
          revokeState(authority, current)
          throw err
        }
      }
    })
    state = {
      guardIdentity,
      guardEndpoint,
      advertisement,
      advertisementDigest,
      epoch,
      expiresAt,
      signedExpiresAt: decoded.expiresAtMs,
      localIdentity,
      localSecretKey,
      tuple: boundTuple,
      transport: typeof reconnectTransport === 'function' ? null : reconnectTransport,
      transportFactory: typeof reconnectTransport === 'function' ? reconnectTransport : null,
      wallNow,
      monotonicNow,
      setTimer,
      clearTimer: clearTimerFn,
      timer: null,
      sampling: false,
      generation: objectFreeze({}),
      status: 'READY'
    }
    states.set(authority, state)
    guardIdentity = null
    guardEndpoint = null
    advertisement = null
    advertisementDigest = null
    localIdentity = null
    localSecretKey = null
    timer = setTimer(() => revokeState(authority, state), Number(expiresAt - now))
    if (state.status !== 'READY') destroyed()
    state.timer = timer
    timer = null
    return authority
  } catch (err) {
    if (timer !== null && state) {
      try {
        state.clearTimer(timer)
      } catch {}
    }
    if (state) revokeState(null, state)
    clear(guardIdentity)
    clear(guardEndpoint)
    clear(advertisement)
    clear(advertisementDigest)
    clear(localIdentity)
    clear(localSecretKey)
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    clearDecoded(decoded)
    clear(computedDigest)
  }
}

function revokeGuardReconnectAuthority(authority, reason) {
  void reason
  const state = authority !== null && typeof authority === 'object' ? states.get(authority) : null
  if (!state) replay()
  if (!revokeState(authority, state)) replay()
  return true
}

module.exports = {
  createGuardReconnectAuthority,
  revokeGuardReconnectAuthority
}
