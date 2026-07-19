'use strict'

// Cold-start authority narrowed from the reviewed private-routes prototype at
// commit 0305df915b6a767093f9e75e6c06bc0a35da6169 for Gate 3B1.

const b4a = require('b4a')
const sodium = require('sodium-universal')

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
  encodeCanonicalEndpoint
} = require('./relay-capability')
const {
  consumeSealedRelayCandidateDirectory,
  destroySealedRelayCandidateDirectory,
  revokeRelayCandidateDirectorySink,
  sealRelayCandidateDirectorySink
} = require('./relay-candidate-directory')
const {
  createBootstrapGuardLeaseMaterial,
  createLocalIdentitySecretCapability,
  destroyGuardLeaseMaterial,
  destroyLocalIdentitySecretCapability,
  isGuardLeaseMaterial
} = require('./udx-cell-endpoint')

const BOOTSTRAP_BUDGET = 10_000n
const MAX_CANDIDATES = 16
const MAX_GUARD_CHALLENGES = 3
const MAX_EXPOSURE_ENTRIES = 6
const MAX_U64 = 0xffff_ffff_ffff_ffffn
const REDACTION_DOMAIN = b4a.from('hyperdht-private-routes/bootstrap-exposure/v1')
const OPTION_FIELDS = Object.freeze([
  'endpoints',
  'localIdentity',
  'localSecretKey',
  'datagrams',
  'wallNow',
  'monotonicNow',
  'randomBytes',
  'candidateDirectorySink'
])
const ENDPOINT_FIELDS = Object.freeze(['host', 'port'])
const RESPONSE_FIELDS = Object.freeze({
  activeChallenge: ['bytes'],
  link: ['accept', 'physicalChannel']
})
const TEST_HOOK_FIELDS = Object.freeze(['setTimeout', 'clearTimeout', 'deferDispatch'])

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
const arrayIsArray = Array.isArray
const arrayPush = Array.prototype.push
const reflectApply = Reflect.apply
const setTimer = setTimeout
const clearTimer = clearTimeout

const states = new WeakMap()
const transfers = new WeakMap()
const TEST_ONLY_BOOTSTRAP_IO_OBSERVER = Symbol('test-only-bootstrap-io-observer')
const CAPS_QUERY_RESPONSE_FIELDS = Object.freeze([
  'sourceEndpoint',
  'cookieExpiresAtMs',
  'returnRoutabilityCookie',
  'advertisements'
])

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function unavailable() {
  throw PrivateRouteError.ERR_PRIVATE_GUARD_UNAVAILABLE()
}

function replay() {
  throw PrivateRouteError.ERR_REPLAY()
}

function destroyed() {
  throw PrivateRouteError.ERR_DESTROYED()
}

function bufferLength(value) {
  try {
    return b4a.isBuffer(value) ? reflectApply(byteLengthGetter, value, []) : -1
  } catch {
    return -1
  }
}

function fixed(value, size) {
  return bufferLength(value) === size
}

function clear(value) {
  try {
    if (bufferLength(value) >= 0) reflectApply(bufferFill, value, [0])
  } catch {}
}

function copy(value, size = bufferLength(value)) {
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

function exactObject(value, fields) {
  try {
    if (value === null || typeof value !== 'object' || arrayIsArray(value)) invalid()
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

function same(left, right) {
  try {
    return bufferLength(left) === bufferLength(right) && b4a.equals(left, right)
  } catch {
    return false
  }
}

function ipv4(host) {
  if (typeof host !== 'string' || host.length < 7 || host.length > 15) return null
  const parts = host.split('.')
  if (parts.length !== 4) return null
  const bytes = b4a.allocUnsafeSlow(4)
  for (let index = 0; index < 4; index++) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(parts[index])) return null
    const value = Number(parts[index])
    if (value > 255) return null
    bytes[index] = value
  }
  if (bytes[0] === 0 || bytes[0] >= 224 || bytes.every((value) => value === 255)) return null
  return bytes
}

function ipv6(host) {
  if (typeof host !== 'string' || host.length < 2 || host.length > 45 || host.includes('%')) {
    return null
  }
  if ((host.match(/::/g) || []).length > 1) return null
  const split = host.split('::')
  const left = split[0] === '' ? [] : split[0].split(':')
  const right = split.length === 1 || split[1] === '' ? [] : split[1].split(':')
  if (left.some((part) => !/^[0-9a-fA-F]{1,4}$/.test(part))) return null
  if (right.some((part) => !/^[0-9a-fA-F]{1,4}$/.test(part))) return null
  const missing = 8 - left.length - right.length
  if ((split.length === 1 && missing !== 0) || (split.length === 2 && missing < 1)) return null
  const words = [...left, ...Array(missing).fill('0'), ...right]
  if (words.length !== 8) return null
  const bytes = b4a.allocUnsafeSlow(16)
  for (let index = 0; index < 8; index++) {
    const word = Number.parseInt(words[index], 16)
    bytes[index * 2] = word >>> 8
    bytes[index * 2 + 1] = word
  }
  let nonzero = false
  for (const byte of bytes) nonzero ||= byte !== 0
  if (!nonzero || bytes[0] === 0xff) return null
  return bytes
}

function ownEndpoint(value) {
  exactObject(value, ENDPOINT_FIELDS)
  const host = own(value, 'host')
  const port = own(value, 'port')
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) invalid()
  let addressBytes = ipv4(host)
  let addressFamily = 4
  if (addressBytes === null) {
    addressBytes = ipv6(host)
    addressFamily = 6
  }
  if (addressBytes === null) invalid()
  let canonical = null
  try {
    canonical = encodeCanonicalEndpoint({ addressFamily, addressBytes, port })
    return { host, port, canonical }
  } finally {
    clear(addressBytes)
  }
}

function ownEndpoints(values) {
  if (!arrayIsArray(values) || values.length < 1) invalid()
  const endpoints = []
  const seen = new Set()
  try {
    for (const value of values) {
      const endpoint = ownEndpoint(value)
      const key = b4a.toString(endpoint.canonical, 'hex')
      if (seen.has(key)) {
        clear(endpoint.canonical)
        continue
      }
      seen.add(key)
      reflectApply(arrayPush, endpoints, [endpoint])
      if (endpoints.length > 3) invalid()
    }
    if (endpoints.length < 1) invalid()
    return endpoints
  } catch (err) {
    for (const endpoint of endpoints) clear(endpoint.canonical)
    throw err
  }
}

function sample(state, name) {
  if (state.sampling || typeof state[name] !== 'function') {
    stop(state)
    destroyed()
  }
  state.sampling = true
  let value
  try {
    value = state[name]()
  } catch {
    stop(state)
    invalid()
  } finally {
    state.sampling = false
  }
  if (!u64(value)) {
    stop(state)
    invalid()
  }
  return value
}

function checkBudget(state) {
  if (!state.live || state.destroyed) destroyed()
  const now = sample(state, 'monotonicNow')
  if (now < state.startedAt || now - state.startedAt >= BOOTSTRAP_BUDGET) unavailable()
  const wall = sample(state, 'wallNow')
  if (state.lastWall !== null && wall + 30_000n < state.lastWall) unavailable()
  state.lastWall = wall
  return wall
}

function random(state, size) {
  let source = null
  try {
    source = state.randomBytes(size)
    if (!state.live) destroyed()
    return copy(source, size)
  } finally {
    clear(source)
  }
}

function exactResponse(value, kind) {
  exactObject(value, RESPONSE_FIELDS[kind])
  return value
}

function exactEmptyResponse(value) {
  exactObject(value, [])
  return value
}

function capsQueryRequest(randomTarget, queryNonce) {
  return objectFreeze({
    kind: 'caps-query',
    requestedCapabilityMask: RELAY_CAPABILITY.CIRCUIT_RELAY_V1,
    randomTarget,
    queryNonce,
    maximumResults: MAX_CAPABILITY_ADVERTISEMENTS
  })
}

function capsRetryRequest(session, advertisement) {
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

function bytesRequest(kind, bytes) {
  return objectFreeze({ kind, bytes })
}

function deferDispatch(callback) {
  return Promise.resolve().then(callback)
}

function activeDispatch(owner, state, generation, transport, deadline, token) {
  return (
    states.get(owner) === state &&
    state.live &&
    !state.stopping &&
    !state.destroyed &&
    state.owner === owner &&
    state.generation === generation &&
    state.datagrams === transport &&
    state.deadlinePromise === deadline &&
    state.deadlineArmed &&
    state.activeDispatchToken === token
  )
}

async function send(state, endpoint, message) {
  checkBudget(state)
  const owner = state.owner
  const operationGeneration = state.generation
  const transport = state.datagrams
  const deadline = state.deadlinePromise
  const defer = state.deferDispatch
  const transportSend = transport && transport.send
  const dispatchToken = objectFreeze({})
  if (
    states.get(owner) !== state ||
    !state.live ||
    state.stopping ||
    state.destroyed ||
    state.generation !== operationGeneration ||
    state.datagrams !== transport ||
    typeof defer !== 'function' ||
    typeof transportSend !== 'function' ||
    deadline === null ||
    state.deadlinePromise !== deadline ||
    !state.deadlineArmed ||
    state.activeDispatchToken !== null
  ) {
    destroyed()
  }
  state.activeDispatchToken = dispatchToken
  try {
    const response = await Promise.race([
      defer(() => {
        if (!activeDispatch(owner, state, operationGeneration, transport, deadline, dispatchToken))
          destroyed()
        const currentTransportSend = transport.send
        if (
          currentTransportSend !== transportSend ||
          !activeDispatch(owner, state, operationGeneration, transport, deadline, dispatchToken)
        )
          destroyed()
        return reflectApply(currentTransportSend, transport, [
          endpoint.host,
          endpoint.port,
          message
        ])
      }),
      deadline
    ])
    checkBudget(state)
    return response
  } finally {
    if (state.activeDispatchToken === dispatchToken) state.activeDispatchToken = null
  }
}

function clearDeadlineTimer(cancelTimer, armed, timer) {
  if (!armed) return
  try {
    cancelTimer(timer)
  } catch {}
}

function armDeadline(state, operationGeneration) {
  let arming = true
  let firedSynchronously = false
  let timer = null
  const scheduleTimer = state.deadlineSetTimer
  const cancelTimer = state.deadlineClearTimer
  const expired = () => {
    if (arming) {
      firedSynchronously = true
      return
    }
    if (
      !state.live ||
      state.destroyed ||
      state.generation !== operationGeneration ||
      !state.deadlineArmed
    ) {
      return
    }
    state.deadlineArmed = false
    state.deadlineTimer = null
    const reject = state.deadlineReject
    state.deadlineReject = null
    stop(state)
    if (reject) reject(PrivateRouteError.ERR_PRIVATE_GUARD_UNAVAILABLE())
  }
  try {
    timer = scheduleTimer(expired, Number(BOOTSTRAP_BUDGET))
  } catch {
    arming = false
    stop(state)
    unavailable()
  }
  arming = false
  if (
    firedSynchronously ||
    !state.live ||
    state.destroyed ||
    state.generation !== operationGeneration
  ) {
    clearDeadlineTimer(cancelTimer, true, timer)
    stop(state)
    unavailable()
  }
  state.deadlineTimer = timer
  state.deadlineArmed = true
}

function begin(io, state, operationGeneration) {
  state.startedAt = sample(state, 'monotonicNow')
  if (!state.live || state.destroyed || state.generation !== operationGeneration) unavailable()
  state.deadlinePromise = new Promise((resolve, reject) => {
    state.deadlineReject = reject
  })
  void state.deadlinePromise.catch(() => {})
  armDeadline(state, operationGeneration)
  return run(io, state, operationGeneration)
}

function clearCapsSession(session) {
  if (!session) return
  clear(session.sourceEndpoint)
  clear(session.randomTarget)
  clear(session.queryNonce)
  clear(session.returnRoutabilityCookie)
  session.sourceEndpoint = null
  session.randomTarget = null
  session.queryNonce = null
  session.returnRoutabilityCookie = null
}

async function queryCaps(state, endpoint) {
  let randomTarget = null
  let queryNonce = null
  let sourceEndpoint = null
  let returnRoutabilityCookie = null
  try {
    randomTarget = random(state, 32)
    queryNonce = random(state, 32)
    const response = await send(state, endpoint, capsQueryRequest(randomTarget, queryNonce))
    exactObject(response, CAPS_QUERY_RESPONSE_FIELDS)
    sourceEndpoint = copy(own(response, 'sourceEndpoint'), 19)
    const decodedSource = decodeCanonicalEndpoint(sourceEndpoint)
    clear(decodedSource.addressBytes)
    const cookieExpiresAtMs = own(response, 'cookieExpiresAtMs')
    returnRoutabilityCookie = copy(own(response, 'returnRoutabilityCookie'), 32)
    const advertisements = own(response, 'advertisements')
    const now = checkBudget(state)
    if (
      !u64(cookieExpiresAtMs) ||
      cookieExpiresAtMs <= now ||
      cookieExpiresAtMs > now + 5_000n ||
      !arrayIsArray(advertisements) ||
      advertisements.length < 1 ||
      advertisements.length > MAX_CANDIDATES
    ) {
      unavailable()
    }
    const session = {
      sourceEndpoint,
      randomTarget,
      queryNonce,
      cookieExpiresAtMs,
      returnRoutabilityCookie,
      advertisements
    }
    sourceEndpoint = null
    randomTarget = null
    queryNonce = null
    returnRoutabilityCookie = null
    return session
  } finally {
    clear(sourceEndpoint)
    clear(randomTarget)
    clear(queryNonce)
    clear(returnRoutabilityCookie)
  }
}

function newVerifier(state) {
  return new RelayCapabilityVerifier({
    wallNow: state.wallNow,
    monotonicNow: state.monotonicNow,
    setTimer,
    clearTimer,
    onInvalidated() {}
  })
}

function acceptProjection(verifier, encoded, now) {
  let decoded = null
  try {
    decoded = decodeRelayCapabilityAdvertisement(encoded, { now })
    const role = roleForIdentity(decoded.relayIdentity)
    const capabilityMask = decoded.capabilityMask
    if (
      (role !== ROLE.SAFETY || capabilityMask !== RELAY_CAPABILITY.CIRCUIT_RELAY_V1) &&
      (role !== ROLE.PRIVATE ||
        capabilityMask !== (RELAY_CAPABILITY.CIRCUIT_RELAY_V1 | RELAY_CAPABILITY.DHT_EXIT_V1))
    ) {
      unavailable()
    }
    return verifier.accept(encoded, {
      expectedRole: role,
      expectedCapabilityMask: capabilityMask
    })
  } finally {
    clearDecoded(decoded)
  }
}

async function challengeProjection(state, endpoint, verifier, projection, session) {
  await send(state, endpoint, capsRetryRequest(session, projection.canonicalBytes)).then(
    exactEmptyResponse
  )
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
      const response = exactResponse(
        await send(state, endpoint, bytesRequest('active-challenge', challenge)),
        'activeChallenge'
      )
      return own(response, 'bytes')
    }
  })
  return verifier.beginChallenge(projection, authority)
}

function clearDecoded(value) {
  if (!value) return
  clear(value.relayIdentity)
  clear(value.currentDhtNodeId)
  clear(value.reachableEndpoint)
  clear(value.routeEncryptionPublicKey)
  clear(value.signature)
}

function recordForProjection(projection) {
  let canonicalBytes = null
  let digest = null
  let identity = null
  let canonicalEndpointBytes = null
  let routePublicKey = null
  try {
    canonicalBytes = copy(projection.canonicalBytes)
    digest = copy(projection.digest, 32)
    identity = copy(projection.identity, 32)
    canonicalEndpointBytes = copy(projection.canonicalEndpointBytes, 19)
    routePublicKey = copy(projection.routePublicKey, 32)
    const result = {
      canonicalBytes,
      digest,
      identity,
      canonicalEndpointBytes,
      routePublicKey,
      role: projection.role,
      capabilityMask: projection.capabilityMask,
      epoch: projection.epoch,
      issuedAt: projection.issuedAt,
      expiresAt: projection.expiresAt
    }
    canonicalBytes = null
    digest = null
    identity = null
    canonicalEndpointBytes = null
    routePublicKey = null
    return result
  } finally {
    clear(canonicalBytes)
    clear(digest)
    clear(identity)
    clear(canonicalEndpointBytes)
    clear(routePublicKey)
  }
}

function clearRecord(record) {
  if (!record) return
  clear(record.canonicalBytes)
  clear(record.digest)
  clear(record.identity)
  clear(record.canonicalEndpointBytes)
  clear(record.routePublicKey)
}

function copyReport(report) {
  return objectFreeze(report.map((entry) => objectFreeze({ ...entry })))
}

function expose(state, phase, category, endpoint, outcome) {
  let digest = null
  let input = null
  try {
    input = b4a.concat([REDACTION_DOMAIN, state.exposureKey, endpoint.canonical])
    digest = cryptoSuite.hash([input])
    const redactedEndpoint = b4a.toString(digest, 'hex').slice(0, 24)
    const now = sample(state, 'monotonicNow')
    const existing = state.exposure.find(
      (entry) => entry.phase === phase && entry.redactedEndpoint === redactedEndpoint
    )
    if (existing) {
      existing.lastAttemptMs = now
      existing.attemptCount++
      existing.outcome = outcome
    } else if (state.exposure.length < MAX_EXPOSURE_ENTRIES) {
      state.exposure.push({
        phase,
        contactCategory: category,
        redactedEndpoint,
        firstAttemptMs: now,
        lastAttemptMs: now,
        attemptCount: 1,
        outcome
      })
    }
  } finally {
    clear(input)
    clear(digest)
  }
}

function stop(state) {
  if (!state || state.destroyed || state.stopping) return false
  state.stopping = true
  state.live = false
  state.destroyed = true
  state.generation = null
  state.owner = null
  state.activeDispatchToken = null
  const deadlineArmed = state.deadlineArmed
  const deadlineTimer = state.deadlineTimer
  const deadlineReject = state.deadlineReject
  const deadlineClearTimer = state.deadlineClearTimer
  state.deadlineArmed = false
  state.deadlineTimer = null
  state.deadlineReject = null
  state.deadlinePromise = null
  clearDeadlineTimer(deadlineClearTimer, deadlineArmed, deadlineTimer)
  if (deadlineReject) deadlineReject(PrivateRouteError.ERR_DESTROYED())
  const datagrams = state.datagrams
  state.datagrams = null
  try {
    if (datagrams && typeof datagrams.destroy === 'function') datagrams.destroy()
  } catch {}
  for (const endpoint of state.endpoints) clear(endpoint.canonical)
  state.endpoints.length = 0
  for (const record of state.records) clearRecord(record)
  state.records.length = 0
  state.recordKeys.clear()
  state.challengedGuards.clear()
  clear(state.localIdentity)
  clear(state.localSecretKey)
  clear(state.exposureKey)
  state.localIdentity = null
  state.localSecretKey = null
  state.exposureKey = null
  state.wallNow = null
  state.monotonicNow = null
  state.randomBytes = null
  state.deferDispatch = null
  state.deadlineSetTimer = null
  state.deadlineClearTimer = null
  return true
}

function destroyLease(material) {
  return destroyGuardLeaseMaterial(material)
}

function clearPinnedGuard(pinnedGuard) {
  if (!pinnedGuard) return
  clear(pinnedGuard.identity)
  clear(pinnedGuard.canonicalEndpoint)
  clear(pinnedGuard.advertisementDigest)
}

function destroyTransferState(state) {
  if (!state) return
  const lease = state.guardLeaseMaterial
  const sealedDirectory = state.sealedDirectory
  state.guardLeaseMaterial = null
  state.sealedDirectory = null
  if (lease) destroyLease(lease)
  if (sealedDirectory) {
    try {
      destroySealedRelayCandidateDirectory(sealedDirectory)
    } catch {}
  }
  clearPinnedGuard(state.pinnedGuard)
}

function consumeBootstrapGuardPin(transfer) {
  const state = transfer !== null && typeof transfer === 'object' ? transfers.get(transfer) : null
  if (!state) replay()
  if (state.status !== 'READY') {
    if (state.status === 'CONSUMING') {
      state.status = 'POISONED'
      transfers.delete(transfer)
      destroyTransferState(state)
    }
    replay()
  }
  state.status = 'CONSUMING'
  let candidateDirectory = null
  let lease = state.guardLeaseMaterial
  let identity = null
  let canonicalEndpoint = null
  let advertisementDigest = null
  let pinnedGuard = null
  try {
    if (!isGuardLeaseMaterial(lease)) replay()
    candidateDirectory = consumeSealedRelayCandidateDirectory(state.sealedDirectory)
    if (state.status !== 'CONSUMING' || transfers.get(transfer) !== state) replay()
    identity = copy(state.pinnedGuard.identity, 32)
    canonicalEndpoint = copy(state.pinnedGuard.canonicalEndpoint, 19)
    advertisementDigest = copy(state.pinnedGuard.advertisementDigest, 32)
    pinnedGuard = objectFreeze({
      identity,
      canonicalEndpoint,
      advertisementDigest,
      epoch: state.pinnedGuard.epoch,
      expiresAt: state.pinnedGuard.expiresAt
    })
    identity = null
    canonicalEndpoint = null
    advertisementDigest = null
    const result = objectFreeze({
      guardLeaseMaterial: lease,
      candidateDirectory,
      pinnedGuard,
      exposureReport: copyReport(state.exposureReport)
    })
    if (state.status !== 'CONSUMING' || transfers.get(transfer) !== state) replay()
    state.status = 'SPENT'
    transfers.delete(transfer)
    state.guardLeaseMaterial = null
    state.sealedDirectory = null
    lease = null
    candidateDirectory = null
    pinnedGuard = null
    return result
  } catch (err) {
    if (transfers.get(transfer) === state) transfers.delete(transfer)
    state.status = 'POISONED'
    if (lease) destroyLease(lease)
    if (state.sealedDirectory) {
      try {
        destroySealedRelayCandidateDirectory(state.sealedDirectory)
      } catch {}
    }
    if (candidateDirectory && typeof candidateDirectory.destroy === 'function') {
      try {
        candidateDirectory.destroy()
      } catch {}
    }
    clear(identity)
    clear(canonicalEndpoint)
    clear(advertisementDigest)
    clearPinnedGuard(pinnedGuard)
    throw err
  } finally {
    clearPinnedGuard(state.pinnedGuard)
    state.guardLeaseMaterial = null
    state.sealedDirectory = null
  }
}

function revokeBootstrapGuardPin(transfer) {
  const state = transfer !== null && typeof transfer === 'object' ? transfers.get(transfer) : null
  if (!state) replay()
  if (state.status === 'CONSUMING') {
    state.status = 'POISONED'
    transfers.delete(transfer)
    destroyTransferState(state)
    return true
  }
  if (state.status !== 'READY') replay()
  state.status = 'POISONED'
  transfers.delete(transfer)
  destroyTransferState(state)
  return true
}

function sameRecordProjection(record, projection) {
  return (
    same(record.canonicalBytes, projection.canonicalBytes) &&
    same(record.digest, projection.digest) &&
    same(record.identity, projection.identity) &&
    same(record.canonicalEndpointBytes, projection.canonicalEndpointBytes) &&
    record.role === projection.role &&
    record.capabilityMask === projection.capabilityMask &&
    record.epoch === projection.epoch &&
    record.expiresAt === projection.expiresAt
  )
}

function recordAttemptKey(record) {
  return `${b4a.toString(record.identity, 'hex')}:${b4a.toString(
    record.canonicalEndpointBytes,
    'hex'
  )}`
}

function sameRecords(left, right) {
  return (
    same(left.canonicalBytes, right.canonicalBytes) &&
    same(left.digest, right.digest) &&
    same(left.identity, right.identity) &&
    same(left.canonicalEndpointBytes, right.canonicalEndpointBytes) &&
    same(left.routePublicKey, right.routePublicKey) &&
    left.role === right.role &&
    left.capabilityMask === right.capabilityMask &&
    left.epoch === right.epoch &&
    left.issuedAt === right.issuedAt &&
    left.expiresAt === right.expiresAt
  )
}

function collectVerifiedRecords(state, session) {
  const verifier = newVerifier(state)
  const records = []
  const keys = new Map()
  try {
    for (const encoded of session.advertisements) {
      if (records.length >= MAX_CANDIDATES) unavailable()
      const projection = acceptProjection(verifier, encoded, checkBudget(state))
      const record = recordForProjection(projection)
      const key = recordAttemptKey(record)
      const prior = keys.get(key)
      if (prior) {
        if (!sameRecords(prior, record)) unavailable()
        clearRecord(record)
        continue
      }
      keys.set(key, record)
      records.push(record)
    }
    if (records.length < 1) unavailable()
    return records
  } catch (err) {
    for (const record of records) clearRecord(record)
    throw err
  } finally {
    verifier.destroy()
  }
}

function retainVerifiedRecords(state, records) {
  const retained = []
  let additions = 0
  for (const record of records) {
    const key = recordAttemptKey(record)
    const prior = state.recordKeys.get(key)
    if (prior) {
      if (!sameRecords(prior, record)) unavailable()
      retained.push(prior)
    } else {
      additions++
      retained.push(record)
    }
  }
  if (state.records.length + additions > MAX_CANDIDATES) unavailable()
  for (let index = 0; index < records.length; index++) {
    const record = records[index]
    const key = recordAttemptKey(record)
    const prior = state.recordKeys.get(key)
    if (prior) {
      clearRecord(record)
      records[index] = null
      continue
    }
    state.recordKeys.set(key, record)
    state.records.push(record)
    records[index] = null
  }
  return retained
}

async function authenticateProspectiveGuard(state, record, endpoint) {
  let session = null
  let verifier = null
  state.challengeInFlight++
  if (state.challengeInFlight !== 1) unavailable()
  try {
    session = await queryCaps(state, endpoint)
    verifier = newVerifier(state)
    let projection = null
    for (const encoded of session.advertisements) {
      const candidate = acceptProjection(verifier, encoded, checkBudget(state))
      if (!same(candidate.digest, record.digest)) continue
      if (projection !== null || !sameRecordProjection(record, candidate)) unavailable()
      projection = candidate
    }
    if (projection === null) unavailable()
    const validated = await challengeProjection(state, endpoint, verifier, projection, session)
    if (!sameRecordProjection(record, validated)) unavailable()
    expose(state, 'challenge', 'prospective-guard', endpoint, 'authenticated')
    return true
  } catch (err) {
    expose(state, 'challenge', 'prospective-guard', endpoint, 'rejected')
    throw err
  } finally {
    if (verifier) verifier.destroy()
    clearCapsSession(session)
    state.challengeInFlight--
  }
}

async function establishGuardLink(state, record, endpoint) {
  let identitySeed = null
  let identity = null
  let tailSeed = null
  let tail = null
  let branchId = null
  let circuitId = null
  let decoded = null
  let pending = null
  let physicalChannel = null
  try {
    const now = checkBudget(state)
    identitySeed = copy(state.localSecretKey.subarray(0, 32), 32)
    identity = cryptoSuite.keyPair(identitySeed)
    clear(identitySeed)
    identitySeed = null
    if (!same(identity.publicKey, state.localIdentity)) unavailable()
    tailSeed = random(state, 32)
    tail = cryptoSuite.encryptionKeyPair(tailSeed)
    clear(tailSeed)
    tailSeed = null
    branchId = random(state, 16)
    circuitId = random(state, 16)
    decoded = decodeRelayCapabilityAdvertisement(record.canonicalBytes, { now })
    const initiated = createIndexZeroGuardLinkOffer({
      advertisement: record.canonicalBytes,
      now,
      randomBytes: (size) => random(state, size),
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
    const linkResponse = exactResponse(
      await send(state, endpoint, bytesRequest('link', initiated.offer)),
      'link'
    )
    const channel = own(linkResponse, 'physicalChannel')
    if (channel === null || typeof channel !== 'object' || typeof channel.destroy !== 'function') {
      invalid()
    }
    physicalChannel = channel
    const accept = own(linkResponse, 'accept')
    const movedChannel = physicalChannel
    physicalChannel = null
    const established = completeIndexZeroGuardLink(pending, accept, {
      advertisement: record.canonicalBytes,
      physicalChannel: movedChannel,
      now: checkBudget(state)
    })
    pending = null
    const link = readM3EstablishedLink(established)
    if (!same(link.peerIdentity, record.identity)) {
      destroyM3EstablishedLink(established)
      unavailable()
    }
    expose(state, 'link', 'pinned-guard', endpoint, 'established')
    return established
  } finally {
    if (pending) abortIndexZeroGuardLink(pending)
    if (physicalChannel) {
      try {
        physicalChannel.destroy()
      } catch {}
    }
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
    clearDecoded(decoded)
  }
}

async function run(io, state, operationGeneration) {
  let chosen = null
  let established = null
  let sealedDirectory = null
  let lease = null
  let transfer = null
  let localSecretCapability = null
  let pinnedIdentity = null
  let pinnedEndpoint = null
  let pinnedDigest = null
  let pinnedGuard = null
  try {
    state.exposureKey = random(state, 32)
    for (const endpoint of state.endpoints) {
      if (state.challengeCount >= MAX_GUARD_CHALLENGES) break
      let session = null
      let records = null
      try {
        checkBudget(state)
        session = await queryCaps(state, endpoint)
        records = collectVerifiedRecords(state, session)
        const candidates = retainVerifiedRecords(state, records)
        expose(state, 'bootstrap', 'configured-bootstrap', endpoint, 'verified')
        for (let pass = 0; pass < 2 && established === null; pass++) {
          for (const candidate of candidates) {
            if (state.challengeCount >= MAX_GUARD_CHALLENGES) break
            if (
              candidate.role !== ROLE.SAFETY ||
              candidate.capabilityMask !== RELAY_CAPABILITY.CIRCUIT_RELAY_V1 ||
              (pass === 0 && !same(candidate.canonicalEndpointBytes, endpoint.canonical))
            ) {
              continue
            }
            const key = recordAttemptKey(candidate)
            if (state.challengedGuards.has(key)) continue
            state.challengedGuards.add(key)
            state.challengeCount++
            const guardEndpoint = endpointForRecord(candidate)
            if (guardEndpoint === null) continue
            let attemptEstablished = null
            try {
              await authenticateProspectiveGuard(state, candidate, guardEndpoint)
              attemptEstablished = await establishGuardLink(state, candidate, guardEndpoint)
              chosen = { record: candidate, endpoint: guardEndpoint }
              established = attemptEstablished
              attemptEstablished = null
              break
            } catch (err) {
              if (!state.live || state.destroyed) destroyed()
              try {
                expose(state, 'link', 'prospective-guard', guardEndpoint, 'rejected')
              } catch {}
            } finally {
              if (attemptEstablished) destroyM3EstablishedLink(attemptEstablished)
            }
          }
        }
        if (established) break
        unavailable()
      } catch (err) {
        if (!state.live || state.destroyed) destroyed()
        try {
          expose(state, 'bootstrap', 'configured-bootstrap', endpoint, 'rejected')
        } catch {}
      } finally {
        clearCapsSession(session)
        if (records) for (const record of records) clearRecord(record)
      }
    }
    if (!chosen || !established) unavailable()
    const directoryRecords = state.records
      .filter((record) => record !== chosen.record)
      .map((record) => ({
        canonicalBytes: record.canonicalBytes,
        digest: record.digest,
        identity: record.identity,
        canonicalEndpointBytes: record.canonicalEndpointBytes,
        routePublicKey: record.routePublicKey,
        role: record.role,
        capabilityMask: record.capabilityMask,
        epoch: record.epoch,
        issuedAt: record.issuedAt,
        expiresAt: record.expiresAt
      }))
    sealedDirectory = sealRelayCandidateDirectorySink(
      state.candidateDirectorySink,
      directoryRecords,
      {
        guardIdentity: chosen.record.identity,
        guardEndpoint: chosen.record.canonicalEndpointBytes,
        guardAdvertisementDigest: chosen.record.digest,
        guardEpoch: chosen.record.epoch,
        guardExpiresAt: chosen.record.expiresAt
      }
    )
    state.sinkOwned = false
    pinnedIdentity = copy(chosen.record.identity, 32)
    pinnedEndpoint = copy(chosen.record.canonicalEndpointBytes, 19)
    pinnedDigest = copy(chosen.record.digest, 32)
    pinnedGuard = {
      identity: pinnedIdentity,
      canonicalEndpoint: pinnedEndpoint,
      advertisementDigest: pinnedDigest,
      epoch: chosen.record.epoch,
      expiresAt: chosen.record.expiresAt
    }
    pinnedIdentity = null
    pinnedEndpoint = null
    pinnedDigest = null
    localSecretCapability = createLocalIdentitySecretCapability({
      localIdentity: state.localIdentity,
      localSecretKey: state.localSecretKey
    })
    lease = createBootstrapGuardLeaseMaterial(established, localSecretCapability)
    localSecretCapability = null
    established = null
    // Generic direct-send authority is terminally revoked before either opaque
    // post-bootstrap capability is published.
    stop(state)
    if (state.generation !== null || state.datagrams !== null) destroyed()
    transfer = objectFreeze({})
    transfers.set(transfer, {
      status: 'READY',
      guardLeaseMaterial: lease,
      sealedDirectory,
      pinnedGuard,
      exposureReport: copyReport(state.exposure)
    })
    pinnedGuard = null
    lease = null
    sealedDirectory = null
    return transfer
  } catch (err) {
    clear(pinnedIdentity)
    clear(pinnedEndpoint)
    clear(pinnedDigest)
    clearPinnedGuard(pinnedGuard)
    if (established) destroyM3EstablishedLink(established)
    if (localSecretCapability) destroyLocalIdentitySecretCapability(localSecretCapability)
    if (lease) destroyLease(lease)
    if (sealedDirectory) {
      try {
        destroySealedRelayCandidateDirectory(sealedDirectory)
      } catch {}
    }
    if (state.sinkOwned) {
      state.sinkOwned = false
      try {
        revokeRelayCandidateDirectorySink(state.candidateDirectorySink)
      } catch {}
    }
    stop(state)
    if (err instanceof PrivateRouteError && err.code === 'ERR_PRIVATE_GUARD_UNAVAILABLE') throw err
    unavailable()
  }
}

function endpointForRecord(record) {
  const endpoint = record.canonicalEndpointBytes
  if (!fixed(endpoint, 19)) return null
  const port = endpoint[17] * 0x100 + endpoint[18]
  if (endpoint[0] === 4) {
    return {
      host: `${endpoint[13]}.${endpoint[14]}.${endpoint[15]}.${endpoint[16]}`,
      port,
      canonical: endpoint
    }
  }
  if (endpoint[0] !== 6) return null
  const words = []
  for (let offset = 1; offset < 17; offset += 2) {
    words.push(((endpoint[offset] << 8) | endpoint[offset + 1]).toString(16))
  }
  return { host: words.join(':'), port, canonical: endpoint }
}

class BootstrapIO {
  constructor(options) {
    exactObject(options, OPTION_FIELDS)
    const endpoints = ownEndpoints(own(options, 'endpoints'))
    let localIdentity = null
    let localSecretKey = null
    try {
      localIdentity = copy(own(options, 'localIdentity'), 32)
      localSecretKey = copy(own(options, 'localSecretKey'), 64)
      const datagrams = own(options, 'datagrams')
      const wallNow = own(options, 'wallNow')
      const monotonicNow = own(options, 'monotonicNow')
      const randomBytes = own(options, 'randomBytes')
      const candidateDirectorySink = own(options, 'candidateDirectorySink')
      if (
        datagrams === null ||
        typeof datagrams !== 'object' ||
        typeof datagrams.send !== 'function' ||
        typeof datagrams.destroy !== 'function' ||
        typeof wallNow !== 'function' ||
        typeof monotonicNow !== 'function' ||
        typeof randomBytes !== 'function' ||
        candidateDirectorySink === null ||
        typeof candidateDirectorySink !== 'object'
      )
        invalid()
      states.set(this, {
        owner: this,
        endpoints,
        localIdentity,
        localSecretKey,
        datagrams,
        wallNow,
        monotonicNow,
        randomBytes,
        candidateDirectorySink,
        sinkOwned: true,
        records: [],
        recordKeys: new Map(),
        exposure: [],
        exposureKey: null,
        startedAt: null,
        lastWall: null,
        sampling: false,
        challengeInFlight: 0,
        challengeCount: 0,
        challengedGuards: new Set(),
        generation: objectFreeze({}),
        startPromise: null,
        deadlinePromise: null,
        deadlineReject: null,
        deadlineTimer: null,
        deadlineArmed: false,
        deadlineSetTimer: setTimer,
        deadlineClearTimer: clearTimer,
        deferDispatch,
        activeDispatchToken: null,
        stopping: false,
        live: true,
        destroyed: false
      })
      localIdentity = null
      localSecretKey = null
    } catch (err) {
      for (const endpoint of endpoints) clear(endpoint.canonical)
      clear(localIdentity)
      clear(localSecretKey)
      throw err
    }
  }

  start() {
    const state = states.get(this)
    if (!state || state.destroyed || !state.live) destroyed()
    if (state.startPromise !== null) replay()
    const generation = state.generation
    state.startPromise = Promise.resolve().then(() => begin(this, state, generation))
    return state.startPromise
  }

  cancel() {
    const state = states.get(this)
    if (!state || state.destroyed) return false
    if (state.sinkOwned) {
      state.sinkOwned = false
      try {
        revokeRelayCandidateDirectorySink(state.candidateDirectorySink)
      } catch {}
    }
    return stop(state)
  }

  destroy() {
    return this.cancel()
  }

  [TEST_ONLY_BOOTSTRAP_IO_OBSERVER](testTimers) {
    const state = states.get(this)
    if (!state) invalid()
    if (testTimers !== undefined) {
      if (state.startPromise !== null || state.destroyed || !state.live) invalid()
      exactObject(testTimers, TEST_HOOK_FIELDS)
      const testSetTimer = own(testTimers, 'setTimeout')
      const testClearTimer = own(testTimers, 'clearTimeout')
      const testDeferDispatch = own(testTimers, 'deferDispatch')
      if (
        typeof testSetTimer !== 'function' ||
        typeof testClearTimer !== 'function' ||
        typeof testDeferDispatch !== 'function'
      )
        invalid()
      state.deadlineSetTimer = testSetTimer
      state.deadlineClearTimer = testClearTimer
      state.deferDispatch = testDeferDispatch
    }
    return objectFreeze({
      destroyed: state.destroyed,
      endpointCount: state.endpoints.length,
      candidateCount: state.records.length,
      recordKeyCount: state.recordKeys.size,
      challengeInFlight: state.challengeInFlight,
      exposureReport: copyReport(state.exposure)
    })
  }
}

module.exports = {
  TEST_ONLY_BOOTSTRAP_IO_OBSERVER,
  BootstrapIO,
  consumeBootstrapGuardPin,
  revokeBootstrapGuardPin
}
