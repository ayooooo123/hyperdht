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
  caps: ['advertisement'],
  challenge: ['advertisementDigest'],
  link: ['accept', 'physicalChannel']
})

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
    revokeState(state)
    destroyed()
  }
  state.sampling = true
  let value
  try {
    value = state[name]()
  } catch {
    revokeState(state)
    invalid()
  } finally {
    state.sampling = false
  }
  if (!u64(value)) {
    revokeState(state)
    invalid()
  }
  return value
}

function clearTimer(state) {
  const timer = state.timer
  state.timer = null
  if (timer !== null) {
    try {
      state.clearTimer(timer)
    } catch {}
  }
}

function destroyTransport(state) {
  const transport = state.transport
  state.transport = null
  try {
    if (transport && typeof transport.destroy === 'function') transport.destroy()
  } catch {}
}

function revokeState(state) {
  if (!state || state.status === 'REVOKED') return false
  state.status = 'REVOKED'
  state.inFlight = false
  clearTimer(state)
  if (state.abortController) {
    try {
      state.abortController.abort()
    } catch {}
  }
  if (state.reject) {
    try {
      state.reject(PrivateRouteError.ERR_DESTROYED())
    } catch {}
  }
  destroyTransport(state)
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
  return true
}

function deadlineCheck(state) {
  if (state.status !== 'SPENT' || !state.inFlight) destroyed()
  const monotonic = sample(state, 'monotonicNow')
  const wall = sample(state, 'wallNow')
  if (
    monotonic < state.startedAt ||
    monotonic - state.startedAt >= RECONNECT_DEADLINE ||
    wall >= state.expiresAt
  )
    unavailable()
  return wall
}

function exactResponse(value, kind) {
  exactObject(value, RESPONSE_FIELDS[kind])
  return value
}

function message(kind, bytes = null) {
  return objectFreeze(bytes === null ? { kind } : { kind, bytes })
}

async function send(state, value) {
  deadlineCheck(state)
  const transport = state.transport
  if (!transport || typeof transport.send !== 'function') destroyed()
  const response = await Promise.race([
    transport.send(state.tuple.host, state.tuple.port, value, state.abortController.signal),
    state.deadlinePromise
  ])
  deadlineCheck(state)
  return response
}

async function reconnect(state) {
  let pending = null
  let established = null
  let physicalChannel = null
  let decoded = null
  try {
    const caps = exactResponse(await send(state, message('caps')), 'caps')
    const capsAdvertisement = copy(own(caps, 'advertisement'))
    try {
      if (!same(capsAdvertisement, state.advertisement)) unavailable()
    } finally {
      clear(capsAdvertisement)
    }
    const challenge = exactResponse(
      await send(state, message('challenge', state.advertisement)),
      'challenge'
    )
    if (!same(own(challenge, 'advertisementDigest'), state.advertisementDigest)) unavailable()
    const now = deadlineCheck(state)
    decoded = decodeRelayCapabilityAdvertisement(state.advertisement, { now })
    const identitySeed = copy(state.localSecretKey.subarray(0, 32), 32)
    const identity = cryptoSuite.keyPair(identitySeed)
    clear(identitySeed)
    if (!same(identity.publicKey, state.localIdentity)) unavailable()
    const tailSeed = cryptoSuite.randomBytes(32)
    const tail = cryptoSuite.encryptionKeyPair(tailSeed)
    clear(tailSeed)
    const branchId = cryptoSuite.randomBytes(16)
    const circuitId = cryptoSuite.randomBytes(16)
    try {
      const initiated = createIndexZeroGuardLinkOffer({
        advertisement: state.advertisement,
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
      const linked = exactResponse(await send(state, message('link', initiated.offer)), 'link')
      physicalChannel = own(linked, 'physicalChannel')
      if (
        physicalChannel === null ||
        typeof physicalChannel !== 'object' ||
        typeof physicalChannel.destroy !== 'function'
      )
        invalid()
      const moved = physicalChannel
      physicalChannel = null
      established = completeIndexZeroGuardLink(pending, own(linked, 'accept'), {
        advertisement: state.advertisement,
        physicalChannel: moved,
        now: deadlineCheck(state)
      })
      pending = null
      const link = readM3EstablishedLink(established)
      if (!same(link.peerIdentity, state.guardIdentity)) unavailable()
      const result = established
      established = null
      state.inFlight = false
      state.reject = null
      clearTimer(state)
      destroyTransport(state)
      clear(state.guardIdentity)
      clear(state.guardEndpoint)
      clear(state.advertisement)
      clear(state.advertisementDigest)
      clear(state.localIdentity)
      clear(state.localSecretKey)
      return result
    } finally {
      clear(identity.publicKey)
      clear(identity.secretKey)
      clear(tail.publicKey)
      clear(tail.secretKey)
      clear(branchId)
      clear(circuitId)
    }
  } catch (err) {
    if (pending) abortIndexZeroGuardLink(pending)
    if (established) destroyM3EstablishedLink(established)
    if (physicalChannel) {
      try {
        physicalChannel.destroy()
      } catch {}
    }
    revokeState(state)
    if (err instanceof PrivateRouteError && err.code === 'ERR_DESTROYED') throw err
    unavailable()
  } finally {
    clearDecoded(decoded)
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
    const transport = own(options, 'reconnectDatagrams')
    const wallNow = own(options, 'wallNow')
    const monotonicNow = own(options, 'monotonicNow')
    const setTimer = own(options, 'setTimer')
    const clearTimerFn = own(options, 'clearTimer')
    if (
      !u64(epoch) ||
      epoch === 0n ||
      !u64(expiresAt) ||
      transport === null ||
      typeof transport !== 'object' ||
      typeof transport.send !== 'function' ||
      typeof transport.destroy !== 'function' ||
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
      decoded.expiresAtMs !== expiresAt ||
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
        current.inFlight = true
        clearTimer(current)
        current.startedAt = sample(current, 'monotonicNow')
        current.abortController = createPrivateAbortController()
        current.deadlinePromise = new Promise((resolve, reject) => {
          current.reject = reject
        })
        void current.deadlinePromise.catch(() => {})
        let deadlineTimer = null
        try {
          deadlineTimer = current.setTimer(() => {
            current.timer = null
            if (current.reject) current.reject(PrivateRouteError.ERR_PRIVATE_GUARD_UNAVAILABLE())
          }, Number(RECONNECT_DEADLINE))
          if (current.status !== 'SPENT' || !current.inFlight) destroyed()
          current.timer = deadlineTimer
        } catch {
          if (deadlineTimer !== null) {
            try {
              current.clearTimer(deadlineTimer)
            } catch {}
          }
          revokeState(current)
          destroyed()
        }
        return reconnect(current)
      }
    })
    state = {
      guardIdentity,
      guardEndpoint,
      advertisement,
      advertisementDigest,
      epoch,
      expiresAt,
      localIdentity,
      localSecretKey,
      tuple: boundTuple,
      transport,
      wallNow,
      monotonicNow,
      setTimer,
      clearTimer: clearTimerFn,
      timer: null,
      abortController: null,
      deadlinePromise: null,
      reject: null,
      startedAt: null,
      sampling: false,
      inFlight: false,
      status: 'READY'
    }
    states.set(authority, state)
    guardIdentity = null
    guardEndpoint = null
    advertisement = null
    advertisementDigest = null
    localIdentity = null
    localSecretKey = null
    timer = setTimer(() => revokeState(state), Number(expiresAt - now))
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
    if (state) revokeState(state)
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
  if (!revokeState(state)) replay()
  return true
}

module.exports = {
  createGuardReconnectAuthority,
  revokeGuardReconnectAuthority
}
