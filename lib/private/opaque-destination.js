'use strict'

const b4a = require('b4a')
const sodium = require('sodium-universal')

const { PrivateRouteError } = require('./errors')
const { BRANCH_CLASS, DESTINATION_VALIDATION_CLASS } = require('./protocol')
const { DESTINATION_REF_SIZE, decodeDestinationRef } = require('./destination-ref')
const { consumeEndpointDhtExitOpenAuthority } = require('./final-exit-activation')
const { clearDhtExitSeeds, verifyDhtExitSeeds } = require('./dht-exit-seeds')

const ID_SIZE = 32
const HEX = '0123456789abcdef'

const Uint8ArrayConstructor = Uint8Array
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype)
const bufferByteLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get
const bufferBuffer = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'buffer').get
const bufferTag = Object.getOwnPropertyDescriptor(typedArrayPrototype, Symbol.toStringTag).get
const arrayBufferByteLength = Object.getOwnPropertyDescriptor(
  ArrayBuffer.prototype,
  'byteLength'
).get
const bufferFill = Uint8Array.prototype.fill
const bufferSet = Uint8Array.prototype.set
const stringCharCodeAt = String.prototype.charCodeAt
const trustedBufferConstructor = b4a.alloc(0).constructor
function OwnedBufferConstructor() {}
OwnedBufferConstructor.prototype = trustedBufferConstructor.prototype
const WeakMapConstructor = WeakMap
const weakMapGet = WeakMap.prototype.get
const weakMapSet = WeakMap.prototype.set
const MapConstructor = Map
const mapHas = Map.prototype.has
const mapSet = Map.prototype.set
const mapClear = Map.prototype.clear
const ArrayConstructor = Array
const arrayPush = Array.prototype.push
const SetConstructor = Set
const setAdd = Set.prototype.add
const setHas = Set.prototype.has
const setDelete = Set.prototype.delete
const setClear = Set.prototype.clear
const setValues = Set.prototype.values
const setIteratorPrototype = Object.getPrototypeOf(new Set().values())
const setIteratorNext = setIteratorPrototype.next
const objectFreeze = Object.freeze
const arrayIsArray = Array.isArray
const objectCreate = Object.create
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectHasOwnProperty = Object.prototype.hasOwnProperty
const reflectOwnKeys = Reflect.ownKeys
const reflectApply = Reflect.apply
const reflectConstruct = Reflect.construct
const reflectHas = Reflect.has
const cryptoHash = sodium.crypto_generichash
const invalidRouteError = PrivateRouteError.INVALID_ROUTE
const destroyedRouteError = PrivateRouteError.ERR_DESTROYED
const authenticationRouteError = PrivateRouteError.ERR_AUTHENTICATION
const replayRouteError = PrivateRouteError.ERR_REPLAY
const KEY_DOMAIN = ascii('hyperdht-private-routes/routed-dht/opaque-destination-key/v1')
const MAX_UINT64 = 0xffff_ffff_ffff_ffffn
const TEST_ONLY_AUTHENTICATED_REPLY_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-authenticated-reply-issuer'
)
const AUTHENTICATED_REPLY_FIELDS = objectFreeze([
  'branch',
  'branchId',
  'circuitId',
  'generation',
  'finalTranscriptDigest',
  'requestId',
  'fromEncoded',
  'deadline',
  'encodedReply'
])
const OWNER_SESSION_FIELDS = objectFreeze(['branchId', 'finalTranscriptDigest'])
const TEST_BRANCH_SEED_READY_FIELDS = objectFreeze([
  'branchClass',
  'branchId',
  'circuitId',
  'generation',
  'exitIdentity',
  'expiresAt'
])
const TEST_ONLY_BRANCH_SEED_READY_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-branch-seed-ready-issuer'
)

const liveOwnerRecords = new WeakMapConstructor()
const liveDestinationRecords = new WeakMapConstructor()
const referralAuthorityRecords = new WeakMapConstructor()
const admissionRecords = new WeakMapConstructor()
const seedAdmissionAuthorityRecords = new WeakMapConstructor()
const spentSeedAdmissionAuthorities = new WeakSet()
const seedAdmissionRecords = new WeakMapConstructor()
const branchSeedReadyRecords = new WeakMapConstructor()
const spentBranchSeedReadiness = new WeakSet()
const authenticatedReplyAuthorityRecords = new WeakMapConstructor()
const spentAuthenticatedReplyAuthorities = new WeakSet()
const spentReferralAuthorities = new WeakSet()

function invalid() {
  throw reflectApply(invalidRouteError, PrivateRouteError, [])
}

function destroyed() {
  throw reflectApply(destroyedRouteError, PrivateRouteError, [])
}

function authentication() {
  throw reflectApply(authenticationRouteError, PrivateRouteError, [])
}

function replay() {
  throw reflectApply(replayRouteError, PrivateRouteError, [])
}

function isArray(value) {
  try {
    return reflectApply(arrayIsArray, null, [value])
  } catch {
    invalid()
  }
}

function bufferLength(value) {
  try {
    if (reflectApply(bufferTag, value, []) !== 'Uint8Array') return -1
    const backing = reflectApply(bufferBuffer, value, [])
    reflectApply(arrayBufferByteLength, backing, [])
    return reflectApply(bufferByteLength, value, [])
  } catch {
    return -1
  }
}

function clear(value) {
  try {
    if (bufferLength(value) >= 0) reflectApply(bufferFill, value, [0])
  } catch {
    // Best effort for an owned allocation that cannot escape this module.
  }
}

function allocate(size) {
  let output = null
  try {
    output = reflectConstruct(Uint8ArrayConstructor, [size], OwnedBufferConstructor)
    if (bufferLength(output) !== size) invalid()
    return output
  } catch (error) {
    clear(output)
    if (error instanceof PrivateRouteError) throw error
    invalid()
  }
}

function copy(value, size) {
  let output = null
  try {
    if (bufferLength(value) !== size) invalid()
    output = allocate(size)
    reflectApply(bufferSet, output, [value, 0])
    return output
  } catch (error) {
    clear(output)
    if (error instanceof PrivateRouteError) throw error
    invalid()
  }
}

function same(left, right) {
  if (bufferLength(left) !== bufferLength(right)) return false
  let difference = 0
  for (let index = 0; index < bufferLength(left); index++) difference |= left[index] ^ right[index]
  return difference === 0
}

function branch(value) {
  if (value !== BRANCH_CLASS.LOOKUP && value !== BRANCH_CLASS.ANNOUNCE) invalid()
  return value
}

function uint64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= MAX_UINT64
}

function ascii(value) {
  const output = new Uint8ArrayConstructor(value.length)
  for (let index = 0; index < value.length; index++) {
    output[index] = reflectApply(stringCharCodeAt, value, [index])
  }
  return output
}

function ownData(value, name) {
  if (value === null || typeof value !== 'object') invalid()
  let descriptor
  try {
    descriptor = objectGetOwnPropertyDescriptor(value, name)
  } catch {
    invalid()
  }
  if (descriptor === undefined) {
    try {
      reflectApply(reflectHas, null, [value, name])
    } catch {
      invalid()
    }
    invalid()
  }
  if (!reflectApply(objectHasOwnProperty, descriptor, ['value'])) invalid()
  return descriptor.value
}

function exactFields(value, names) {
  if (value === null || typeof value !== 'object' || isArray(value)) invalid()
  let keys
  try {
    keys = reflectApply(reflectOwnKeys, null, [value])
  } catch {
    invalid()
  }
  if (keys.length !== names.length) invalid()
  for (let index = 0; index < keys.length; index++) {
    let known = false
    for (let nameIndex = 0; nameIndex < names.length; nameIndex++) {
      if (keys[index] === names[nameIndex]) known = true
    }
    if (!known) invalid()
  }
  const result = objectCreate(null)
  for (let index = 0; index < names.length; index++) {
    result[names[index]] = ownData(value, names[index])
  }
  return result
}

function exactIssue(value) {
  let keys
  try {
    keys = reflectApply(reflectOwnKeys, null, [value])
  } catch {
    invalid()
  }
  if (keys.length !== 3) invalid()
  let branchField = false
  let idField = false
  let destinationRefField = false
  for (let index = 0; index < keys.length; index++) {
    if (keys[index] === 'branch') branchField = true
    else if (keys[index] === 'id') idField = true
    else if (keys[index] === 'destinationRef') destinationRefField = true
    else invalid()
  }
  if (!branchField || !idField || !destinationRefField) invalid()
  return {
    branch: ownData(value, 'branch'),
    id: ownData(value, 'id'),
    destinationRef: ownData(value, 'destinationRef')
  }
}

function keyFor(operationClass, destinationRef) {
  let input = null
  let digest = null
  try {
    input = allocate(KEY_DOMAIN.length + 1 + DESTINATION_REF_SIZE)
    reflectApply(bufferSet, input, [KEY_DOMAIN, 0])
    input[KEY_DOMAIN.length] = operationClass
    reflectApply(bufferSet, input, [destinationRef, KEY_DOMAIN.length + 1])
    digest = allocate(32)
    reflectApply(cryptoHash, sodium, [digest, input])
    let key = ''
    for (let index = 0; index < 32; index++) {
      key += HEX[digest[index] >>> 4] + HEX[digest[index] & 15]
    }
    return key
  } catch (error) {
    if (error instanceof PrivateRouteError) throw error
    invalid()
  } finally {
    clear(input)
    clear(digest)
  }
}

function hexForId(id) {
  let key = ''
  for (let index = 0; index < ID_SIZE; index++) {
    key += HEX[id[index] >>> 4] + HEX[id[index] & 15]
  }
  return key
}

function liveOwner(owner) {
  if ((typeof owner !== 'object' && typeof owner !== 'function') || owner === null) invalid()
  let state
  try {
    state = reflectApply(weakMapGet, liveOwnerRecords, [owner])
  } catch {
    invalid()
  }
  if (state === undefined) invalid()
  if (!state.active) destroyed()
  return state
}

function clockNow(state, name) {
  if (state.clockActive) {
    state.clockReentered = true
    invalid()
  }
  state.clockActive = true
  let current
  let failed = false
  try {
    current = reflectApply(state[name], null, [])
  } catch {
    failed = true
  } finally {
    state.clockActive = false
  }
  const reentered = state.clockReentered
  state.clockReentered = false
  if (failed || reentered) invalid()
  if (!state.active) destroyed()
  if (!uint64(current)) invalid()
  return current
}

function wallNow(state) {
  const current = clockNow(state, 'wallNow')
  if (current >= state.expiresAt) destroyed()
  return current
}

function monotonicNow(state) {
  return clockNow(state, 'monotonicNow')
}

function liveDestination(value) {
  if ((typeof value !== 'object' && typeof value !== 'function') || value === null) invalid()
  let state
  try {
    state = reflectApply(weakMapGet, liveDestinationRecords, [value])
  } catch {
    invalid()
  }
  if (state === undefined) invalid()
  if (!state.active || !state.owner.active) destroyed()
  wallNow(state.owner)
  return state
}

function clearLiveRecord(record) {
  if (!record.active) return
  record.active = false
  clear(record.id)
  clear(record.destinationRef)
}

function clearStaged(records) {
  for (let index = 0; index < records.length; index++) {
    clear(records[index].id)
    clear(records[index].destinationRef)
  }
  records.length = 0
}

function createLiveOpaqueDestinations(value) {
  const fields = exactFields(value, [
    'branch',
    'circuitId',
    'generation',
    'expiresAt',
    'wallNow',
    'monotonicNow'
  ])
  const operationClass = branch(fields.branch)
  let circuitId = null
  try {
    circuitId = copy(fields.circuitId, 16)
    if (!uint64(fields.generation) || !uint64(fields.expiresAt)) invalid()
    if (typeof fields.wallNow !== 'function' || typeof fields.monotonicNow !== 'function') invalid()
    const state = {
      active: true,
      ownerCapability: null,
      branch: operationClass,
      circuitId,
      generation: fields.generation,
      expiresAt: fields.expiresAt,
      wallNow: fields.wallNow,
      monotonicNow: fields.monotonicNow,
      clockActive: false,
      clockReentered: false,
      byId: new MapConstructor(),
      destinations: new SetConstructor(),
      authorities: new SetConstructor(),
      admissions: new SetConstructor(),
      seedAuthorities: new SetConstructor(),
      seedAdmissions: new SetConstructor(),
      seedReadiness: new SetConstructor(),
      branchId: null,
      finalTranscriptDigest: null,
      replyAuthorities: new SetConstructor()
    }
    wallNow(state)
    monotonicNow(state)
    circuitId = null
    const owner = objectFreeze({})
    state.ownerCapability = owner
    reflectApply(weakMapSet, liveOwnerRecords, [owner, state])
    return owner
  } finally {
    clear(circuitId)
  }
}

function issueLiveOpaqueDestination(owner, value) {
  const ownerState = liveOwner(owner)
  wallNow(ownerState)
  const fields = exactFields(value, ['id', 'destinationRef'])
  let id = null
  let destinationRef = null
  let decoded = null
  try {
    id = copy(fields.id, ID_SIZE)
    destinationRef = copy(fields.destinationRef, DESTINATION_REF_SIZE)
    decoded = decodeDestinationRef(destinationRef)
    if (!same(decoded.id, id)) invalid()
    const idKey = hexForId(id)
    if (reflectApply(mapHas, ownerState.byId, [idKey])) invalid()
    const state = {
      active: true,
      owner: ownerState,
      capability: null,
      branch: ownerState.branch,
      circuitId: ownerState.circuitId,
      generation: ownerState.generation,
      expiresAt: ownerState.expiresAt,
      destinationValidationClass: DESTINATION_VALIDATION_CLASS.DHT_NODE_HANDLE,
      id,
      destinationRef,
      idKey,
      key: keyFor(ownerState.branch, destinationRef)
    }
    id = null
    destinationRef = null
    const capability = objectFreeze({})
    state.capability = capability
    reflectApply(weakMapSet, liveDestinationRecords, [capability, state])
    reflectApply(mapSet, ownerState.byId, [idKey, state])
    reflectApply(setAdd, ownerState.destinations, [state])
    return capability
  } finally {
    clear(id)
    clear(destinationRef)
    if (decoded !== null) {
      clear(decoded.id)
      clear(decoded.handle)
    }
  }
}
function isLiveOpaqueDestinationOwnedBy(owner, destination) {
  const ownerState = liveOwner(owner)
  const destinationState = liveDestination(destination)
  return destinationState.owner === ownerState
}

function snapshotLiveOpaqueDestination(value) {
  const state = liveDestination(value)
  return {
    branch: state.branch,
    id: copy(state.id, ID_SIZE),
    destinationRef: copy(state.destinationRef, DESTINATION_REF_SIZE),
    circuitId: copy(state.circuitId, 16),
    generation: state.generation
  }
}

function snapshotLiveOpaqueDestinations(owner, limit) {
  const state = liveOwner(owner)
  if (!Number.isSafeInteger(limit) || limit < 0 || limit > 20) invalid()
  const records = []
  for (const destination of state.destinations) {
    if (records.length >= limit) break
    if (!destination.active) continue
    records.push(
      objectFreeze({
        id: copy(destination.id, ID_SIZE),
        destinationRef: copy(destination.destinationRef, DESTINATION_REF_SIZE)
      })
    )
  }
  return objectFreeze(records)
}

function findLiveOpaqueDestination(owner, value) {
  const state = liveOwner(owner)
  const fields = exactFields(value, ['id', 'destinationRef'])
  const id = copy(fields.id, ID_SIZE)
  const destinationRef = copy(fields.destinationRef, DESTINATION_REF_SIZE)
  try {
    const found = state.byId.get(hexForId(id))
    if (!found || !found.active || !same(found.destinationRef, destinationRef)) return null
    return found.capability
  } finally {
    clear(id)
    clear(destinationRef)
  }
}

function keyLiveOpaqueDestination(value) {
  return liveDestination(value).key
}

function idLiveOpaqueDestination(value) {
  return copy(liveDestination(value).id, ID_SIZE)
}
function createRoutedReplyReferralAuthorityForDestination(owner, destination, value) {
  const ownerState = liveOwner(owner)
  const state = liveDestination(destination)
  if (state.owner !== ownerState) authentication()
  const fields = exactFields(value, ['target', 'requestId', 'deadline'])
  return createRoutedReplyReferralAuthority(owner, {
    from: destination,
    target: fields.target,
    requestId: fields.requestId,
    deadline: fields.deadline
  })
}

function revokeLiveOpaqueDestination(value) {
  const state = liveDestination(value)
  state.active = false
  reflectApply(setDelete, state.owner.destinations, [state])
  state.owner.byId.delete(state.idKey)
  clear(state.id)
  clear(state.destinationRef)
  return true
}
function bindLiveOpaqueDestinationOwnerSession(owner, value) {
  const state = liveOwner(owner)
  const fields = exactFields(value, OWNER_SESSION_FIELDS)
  let branchId = null
  let finalTranscriptDigest = null
  try {
    if (state.branchId !== null || state.finalTranscriptDigest !== null) {
      if (
        state.branchId !== null &&
        state.finalTranscriptDigest !== null &&
        same(state.branchId, fields.branchId) &&
        same(state.finalTranscriptDigest, fields.finalTranscriptDigest)
      ) {
        return true
      }
      replay()
    }
    branchId = copy(fields.branchId, 16)
    finalTranscriptDigest = copy(fields.finalTranscriptDigest, 32)
    state.branchId = branchId
    state.finalTranscriptDigest = finalTranscriptDigest
    branchId = null
    finalTranscriptDigest = null
    return true
  } finally {
    clear(branchId)
    clear(finalTranscriptDigest)
  }
}

function digestAuthenticatedReply(encodedReply) {
  const length = bufferLength(encodedReply)
  if (length < 0) invalid()
  const encoded = copy(encodedReply, length)
  const digest = allocate(32)
  try {
    reflectApply(cryptoHash, sodium, [digest, encoded])
    return digest
  } finally {
    clear(encoded)
  }
}

function createAuthenticatedRoutedReplyAuthority(owner, value) {
  const ownerState = liveOwner(owner)
  const fields = exactFields(value, AUTHENTICATED_REPLY_FIELDS)
  const state = {
    active: true,
    owner: ownerState,
    branch: branch(fields.branch),
    generation: fields.generation,
    deadline: fields.deadline,
    branchId: null,
    circuitId: null,
    finalTranscriptDigest: null,
    requestId: null,
    fromEncoded: null,
    replyDigest: null,
    authority: null
  }
  try {
    if (!uint64(state.generation) || !uint64(state.deadline)) invalid()
    state.branchId = copy(fields.branchId, 16)
    state.circuitId = copy(fields.circuitId, 16)
    state.finalTranscriptDigest = copy(fields.finalTranscriptDigest, 32)
    state.requestId = copy(fields.requestId, 16)
    state.fromEncoded = copy(fields.fromEncoded, DESTINATION_REF_SIZE)
    state.replyDigest = digestAuthenticatedReply(fields.encodedReply)
    const authority = objectFreeze({})
    state.authority = authority
    reflectApply(weakMapSet, authenticatedReplyAuthorityRecords, [authority, state])
    reflectApply(setAdd, ownerState.replyAuthorities, [state])
    return authority
  } catch (err) {
    clearAuthenticatedReplyState(state)
    throw err
  }
}

function clearAuthenticatedReplyState(state) {
  if (!state) return
  state.active = false
  clear(state.branchId)
  clear(state.circuitId)
  clear(state.finalTranscriptDigest)
  clear(state.requestId)
  clear(state.fromEncoded)
  clear(state.replyDigest)
  state.branchId = null
  state.circuitId = null
  state.finalTranscriptDigest = null
  state.requestId = null
  state.fromEncoded = null
  state.replyDigest = null
}

function revokeAuthenticatedReplyAuthority(authority) {
  const state =
    authority !== null && (typeof authority === 'object' || typeof authority === 'function')
      ? reflectApply(weakMapGet, authenticatedReplyAuthorityRecords, [authority])
      : undefined
  if (state === undefined) {
    if (
      authority !== null &&
      (typeof authority === 'object' || typeof authority === 'function') &&
      spentAuthenticatedReplyAuthorities.has(authority)
    ) {
      return false
    }
    invalid()
  }
  authenticatedReplyAuthorityRecords.delete(authority)
  spentAuthenticatedReplyAuthorities.add(authority)
  reflectApply(setDelete, state.owner.replyAuthorities, [state])
  clearAuthenticatedReplyState(state)
  return true
}

function revokeReferralState(authority, state) {
  if (!state || !state.active) return false
  referralAuthorityRecords.delete(authority)
  spentReferralAuthorities.add(authority)
  state.active = false
  reflectApply(setDelete, state.owner.authorities, [state])
  clear(state.fromEncoded)
  clear(state.target)
  clear(state.requestId)
  clearStaged(state.staged)
  reflectApply(setClear, state.stagedIds, [])
  return true
}

function bindAuthenticatedRoutedReply(
  referralAuthority,
  authenticatedReplyAuthority,
  encodedReply
) {
  const referral =
    referralAuthority !== null &&
    (typeof referralAuthority === 'object' || typeof referralAuthority === 'function')
      ? reflectApply(weakMapGet, referralAuthorityRecords, [referralAuthority])
      : undefined
  const authenticated =
    authenticatedReplyAuthority !== null &&
    (typeof authenticatedReplyAuthority === 'object' ||
      typeof authenticatedReplyAuthority === 'function')
      ? reflectApply(weakMapGet, authenticatedReplyAuthorityRecords, [authenticatedReplyAuthority])
      : undefined
  if (referral === undefined || authenticated === undefined) {
    if (referral !== undefined) revokeReferralState(referralAuthority, referral)
    if (authenticated !== undefined) revokeAuthenticatedReplyAuthority(authenticatedReplyAuthority)
    if (
      (referralAuthority !== null &&
        (typeof referralAuthority === 'object' || typeof referralAuthority === 'function') &&
        spentReferralAuthorities.has(referralAuthority)) ||
      (authenticatedReplyAuthority !== null &&
        (typeof authenticatedReplyAuthority === 'object' ||
          typeof authenticatedReplyAuthority === 'function') &&
        spentAuthenticatedReplyAuthorities.has(authenticatedReplyAuthority))
    ) {
      replay()
    }
    authentication()
  }
  let replyDigest = null
  let complete = false
  try {
    replyDigest = digestAuthenticatedReply(encodedReply)
    const owner = referral.owner
    const current = monotonicNow(owner)
    if (
      !referral.active ||
      !authenticated.active ||
      !owner.active ||
      authenticated.owner !== owner ||
      owner.branch !== BRANCH_CLASS.LOOKUP ||
      authenticated.branch !== owner.branch ||
      authenticated.generation !== owner.generation ||
      !same(authenticated.branchId, owner.branchId) ||
      !same(authenticated.circuitId, owner.circuitId) ||
      !same(authenticated.finalTranscriptDigest, owner.finalTranscriptDigest) ||
      !same(authenticated.requestId, referral.requestId) ||
      !same(authenticated.fromEncoded, referral.fromEncoded) ||
      authenticated.deadline !== referral.deadline ||
      current > referral.deadline ||
      !same(authenticated.replyDigest, replyDigest)
    ) {
      authentication()
    }
    referralAuthorityRecords.delete(referralAuthority)
    spentReferralAuthorities.add(referralAuthority)
    authenticatedReplyAuthorityRecords.delete(authenticatedReplyAuthority)
    spentAuthenticatedReplyAuthorities.add(authenticatedReplyAuthority)
    reflectApply(setDelete, authenticated.owner.replyAuthorities, [authenticated])
    clearAuthenticatedReplyState(authenticated)
    referral.bound = true
    const bound = objectFreeze({})
    reflectApply(weakMapSet, referralAuthorityRecords, [bound, referral])
    complete = true
    return bound
  } finally {
    clear(replyDigest)
    if (!complete) {
      revokeReferralState(referralAuthority, referral)
      revokeAuthenticatedReplyAuthority(authenticatedReplyAuthority)
    }
  }
}

function createRoutedReplyReferralAuthority(owner, value) {
  const ownerState = liveOwner(owner)
  const fields = exactFields(value, ['from', 'target', 'requestId', 'deadline'])
  const from = liveDestination(fields.from)
  if (from.owner !== ownerState) invalid()
  let target = null
  let requestId = null
  let fromEncoded = null
  try {
    target = copy(fields.target, ID_SIZE)
    requestId = copy(fields.requestId, 16)
    fromEncoded = copy(from.destinationRef, DESTINATION_REF_SIZE)
    const wallCurrent = wallNow(ownerState)
    const monotonicCurrent = monotonicNow(ownerState)
    const remaining = ownerState.expiresAt > wallCurrent ? ownerState.expiresAt - wallCurrent : 0n
    const localExpiry =
      monotonicCurrent > MAX_UINT64 - remaining ? MAX_UINT64 : monotonicCurrent + remaining
    if (
      !uint64(fields.deadline) ||
      fields.deadline < monotonicCurrent ||
      fields.deadline > localExpiry
    ) {
      invalid()
    }
    const state = {
      active: true,
      owner: ownerState,
      from,
      generation: ownerState.generation,
      fromEncoded,
      target,
      requestId,
      deadline: fields.deadline,
      staged: [],
      stagedIds: new SetConstructor()
    }
    fromEncoded = null
    target = null
    requestId = null
    const authority = objectFreeze({})
    reflectApply(weakMapSet, referralAuthorityRecords, [authority, state])
    reflectApply(setAdd, ownerState.authorities, [state])
    return authority
  } finally {
    clear(fromEncoded)
    clear(target)
    clear(requestId)
  }
}

function referralAuthority(value) {
  if ((typeof value !== 'object' && typeof value !== 'function') || value === null) invalid()
  let state
  try {
    state = reflectApply(weakMapGet, referralAuthorityRecords, [value])
  } catch {
    invalid()
  }
  if (state === undefined) {
    if (spentReferralAuthorities.has(value)) replay()
    invalid()
  }
  if (!state.active) invalid()
  if (!state.owner.active || !state.from.active) destroyed()
  const current = monotonicNow(state.owner)
  if (!state.active) invalid()
  if (!state.owner.active || !state.from.active) destroyed()
  if (
    state.owner.generation !== state.generation ||
    state.from.owner !== state.owner ||
    state.from.generation !== state.generation
  ) {
    invalid()
  }
  if (current > state.deadline) destroyed()
  return state
}

function verifyRoutedReplyReferralAuthority(authority, value) {
  const state = referralAuthority(authority)
  const fields = exactFields(value, [
    'fromEncoded',
    'target',
    'requestId',
    'branch',
    'circuitId',
    'generation',
    'now'
  ])
  if (
    fields.branch !== BRANCH_CLASS.LOOKUP ||
    state.owner.branch !== fields.branch ||
    !uint64(fields.generation) ||
    state.owner.generation !== fields.generation ||
    !uint64(fields.now) ||
    fields.now > state.deadline ||
    !same(fields.circuitId, state.owner.circuitId) ||
    !same(fields.fromEncoded, state.fromEncoded) ||
    !same(fields.target, state.target) ||
    !same(fields.requestId, state.requestId) ||
    state.from.destinationValidationClass !== DESTINATION_VALIDATION_CLASS.DHT_NODE_HANDLE
  ) {
    invalid()
  }
}

function stageRoutedReplyReferral(authority, value) {
  const state = referralAuthority(authority)
  const fields = exactFields(value, ['encoded', 'decoded'])
  let encoded = null
  let decodedId = null
  let decodedHandle = null
  let canonical = null
  try {
    encoded = copy(fields.encoded, DESTINATION_REF_SIZE)
    const decodedFields = exactFields(fields.decoded, ['id', 'handle'])
    decodedId = copy(decodedFields.id, ID_SIZE)
    decodedHandle = copy(decodedFields.handle, 130)
    canonical = decodeDestinationRef(encoded)
    if (!same(canonical.id, decodedId) || !same(canonical.handle, decodedHandle)) invalid()
    const idKey = hexForId(decodedId)
    if (
      reflectApply(mapHas, state.owner.byId, [idKey]) ||
      reflectApply(setHas, state.stagedIds, [idKey])
    ) {
      invalid()
    }
    const record = {
      id: decodedId,
      destinationRef: encoded,
      idKey,
      key: keyFor(state.owner.branch, encoded)
    }
    decodedId = null
    encoded = null
    reflectApply(setAdd, state.stagedIds, [idKey])
    reflectApply(arrayPush, state.staged, [record])
  } finally {
    clear(encoded)
    clear(decodedId)
    clear(decodedHandle)
    if (canonical !== null) {
      clear(canonical.id)
      clear(canonical.handle)
    }
  }
}

function sealRoutedReplyAdmission(authority) {
  const state = referralAuthority(authority)
  referralAuthorityRecords.delete(authority)
  spentReferralAuthorities.add(authority)
  state.active = false
  reflectApply(setDelete, state.owner.authorities, [state])
  clear(state.fromEncoded)
  clear(state.target)
  clear(state.requestId)
  const admissionState = {
    active: true,
    owner: state.owner,
    records: state.staged
  }
  state.staged = []
  reflectApply(setClear, state.stagedIds, [])
  const admission = objectFreeze({})
  reflectApply(weakMapSet, admissionRecords, [admission, admissionState])
  reflectApply(setAdd, state.owner.admissions, [admissionState])
  return admission
}

function admission(value) {
  if ((typeof value !== 'object' && typeof value !== 'function') || value === null) invalid()
  let state
  try {
    state = reflectApply(weakMapGet, admissionRecords, [value])
  } catch {
    invalid()
  }
  if (state === undefined || !state.active) invalid()
  if (!state.owner.active) destroyed()
  wallNow(state.owner)
  return state
}

function commitRoutedReplyAdmission(value) {
  const state = admission(value)
  for (let index = 0; index < state.records.length; index++) {
    if (reflectApply(mapHas, state.owner.byId, [state.records[index].idKey])) invalid()
  }
  const capabilities = new ArrayConstructor(state.records.length)
  const destinationStates = new ArrayConstructor(state.records.length)
  for (let index = 0; index < state.records.length; index++) {
    const record = state.records[index]
    const destinationState = {
      active: true,
      owner: state.owner,
      capability: null,
      branch: state.owner.branch,
      circuitId: state.owner.circuitId,
      generation: state.owner.generation,
      expiresAt: state.owner.expiresAt,
      destinationValidationClass: DESTINATION_VALIDATION_CLASS.DHT_NODE_HANDLE,
      id: record.id,
      destinationRef: record.destinationRef,
      idKey: record.idKey,
      key: record.key
    }
    const capability = objectFreeze({})
    destinationState.capability = capability
    capabilities[index] = capability
    destinationStates[index] = destinationState
  }
  for (let index = 0; index < capabilities.length; index++) {
    const destinationState = destinationStates[index]
    reflectApply(weakMapSet, liveDestinationRecords, [capabilities[index], destinationState])
    reflectApply(mapSet, state.owner.byId, [destinationState.idKey, destinationState])
    reflectApply(setAdd, state.owner.destinations, [destinationState])
  }
  state.records = []
  state.active = false
  reflectApply(setDelete, state.owner.admissions, [state])
  return objectFreeze(capabilities)
}

function abortRoutedReplyAdmission(value) {
  const state = admission(value)
  state.active = false
  reflectApply(setDelete, state.owner.admissions, [state])
  clearStaged(state.records)
}

function revokeRoutedReplyReferralAuthority(value) {
  let state
  try {
    state = reflectApply(weakMapGet, referralAuthorityRecords, [value])
  } catch {
    invalid()
  }
  if (state === undefined) {
    if (spentReferralAuthorities.has(value)) return false
    invalid()
  }
  return revokeReferralState(value, state)
}

function clearEndpointOpenMaterial(material) {
  if (material === null || typeof material !== 'object') return
  for (const name of [
    'branchId',
    'circuitId',
    'exitIdentity',
    'finalTranscriptDigest',
    'controlKey',
    'controlNoncePrefix'
  ]) {
    clear(material[name])
  }
}

function createDhtSeedAdmissionAuthority(owner, endpointOpenAuthority) {
  const ownerState = liveOwner(owner)
  const wallCurrent = wallNow(ownerState)
  const monotonicCurrent = monotonicNow(ownerState)
  const material = consumeEndpointDhtExitOpenAuthority(endpointOpenAuthority)
  try {
    if (
      material.branchClass !== ownerState.branch ||
      material.generation !== ownerState.generation ||
      material.expiresAt !== ownerState.expiresAt ||
      material.expiresAt < wallCurrent ||
      material.absoluteDeadline <= monotonicCurrent ||
      !same(material.circuitId, ownerState.circuitId)
    ) {
      authentication()
    }
    const state = {
      active: true,
      owner: ownerState,
      branchClass: material.branchClass,
      branchId: copy(material.branchId, 16),
      circuitId: copy(material.circuitId, 16),
      generation: material.generation,
      exitIdentity: copy(material.exitIdentity, 32),
      expiresAt: material.expiresAt,
      absoluteDeadline: material.absoluteDeadline,
      records: null
    }
    const authority = objectFreeze({})
    state.authority = authority
    reflectApply(weakMapSet, seedAdmissionAuthorityRecords, [authority, state])
    reflectApply(setAdd, ownerState.seedAuthorities, [state])
    return authority
  } finally {
    clearEndpointOpenMaterial(material)
  }
}

function seedAdmissionAuthority(authority) {
  if ((typeof authority !== 'object' && typeof authority !== 'function') || authority === null) {
    invalid()
  }
  const state = reflectApply(weakMapGet, seedAdmissionAuthorityRecords, [authority])
  if (state === undefined || !state.active) invalid()
  if (!state.owner.active) destroyed()
  wallNow(state.owner)
  if (monotonicNow(state.owner) >= state.absoluteDeadline) destroyed()
  return state
}

function stageDhtSeedAdmission(authority, encodedSeeds) {
  const state = seedAdmissionAuthority(authority)
  if (state.records !== null) invalid()
  let verifiedSeeds = null
  const records = []
  const stagedIds = new SetConstructor()
  try {
    verifiedSeeds = verifyDhtExitSeeds(encodedSeeds, state, wallNow(state.owner))
    const destinationRefs = ownData(verifiedSeeds, 'destinationRefs')
    if (!isArray(destinationRefs) || destinationRefs.length < 1 || destinationRefs.length > 3) {
      authentication()
    }
    for (let index = 0; index < destinationRefs.length; index++) {
      let destinationRef = null
      let decoded = null
      try {
        destinationRef = copy(destinationRefs[index], DESTINATION_REF_SIZE)
        decoded = decodeDestinationRef(destinationRef)
        if (
          bufferLength(decoded.handle) !== 130 ||
          decoded.handle[0] !== 1 ||
          decoded.handle[1] !== DESTINATION_VALIDATION_CLASS.DHT_NODE_HANDLE
        ) {
          invalid()
        }
        const idKey = hexForId(decoded.id)
        if (
          reflectApply(mapHas, state.owner.byId, [idKey]) ||
          reflectApply(setHas, stagedIds, [idKey])
        ) {
          invalid()
        }
        const record = {
          id: copy(decoded.id, ID_SIZE),
          destinationRef,
          idKey,
          key: keyFor(state.owner.branch, destinationRef)
        }
        reflectApply(setAdd, stagedIds, [idKey])
        reflectApply(arrayPush, records, [record])
        destinationRef = null
      } finally {
        clear(destinationRef)
        if (decoded !== null) {
          clear(decoded.id)
          clear(decoded.handle)
        }
      }
    }
    state.records = records
    return true
  } catch (err) {
    clearStaged(records)
    throw err
  } finally {
    clearDhtExitSeeds(verifiedSeeds)
  }
}

function sealDhtSeedAdmission(authority) {
  const state = seedAdmissionAuthority(authority)
  if (state.records === null) invalid()
  state.active = false
  spentSeedAdmissionAuthorities.add(authority)
  reflectApply(setDelete, state.owner.seedAuthorities, [state])
  const admissionState = {
    active: true,
    owner: state.owner,
    branchClass: state.branchClass,
    branchId: state.branchId,
    circuitId: state.circuitId,
    generation: state.generation,
    exitIdentity: state.exitIdentity,
    expiresAt: state.expiresAt,
    absoluteDeadline: state.absoluteDeadline,
    records: state.records
  }
  state.records = null
  const admission = objectFreeze({})
  admissionState.admission = admission
  reflectApply(weakMapSet, seedAdmissionRecords, [admission, admissionState])
  reflectApply(setAdd, state.owner.seedAdmissions, [admissionState])
  return admission
}

function seedAdmission(admission) {
  if ((typeof admission !== 'object' && typeof admission !== 'function') || admission === null) {
    invalid()
  }
  const state = reflectApply(weakMapGet, seedAdmissionRecords, [admission])
  if (state === undefined || !state.active) invalid()
  if (!state.owner.active) destroyed()
  wallNow(state.owner)
  if (monotonicNow(state.owner) >= state.absoluteDeadline) destroyed()
  return state
}

function commitDhtSeedAdmission(admission) {
  const state = seedAdmission(admission)
  for (const record of state.records) {
    if (reflectApply(mapHas, state.owner.byId, [record.idKey])) invalid()
  }
  const capabilities = new ArrayConstructor(state.records.length)
  const destinationStates = new ArrayConstructor(state.records.length)
  for (let index = 0; index < state.records.length; index++) {
    const record = state.records[index]
    const destinationState = {
      active: true,
      owner: state.owner,
      capability: null,
      branch: state.owner.branch,
      circuitId: state.owner.circuitId,
      generation: state.owner.generation,
      expiresAt: state.owner.expiresAt,
      destinationValidationClass: DESTINATION_VALIDATION_CLASS.DHT_NODE_HANDLE,
      id: record.id,
      destinationRef: record.destinationRef,
      idKey: record.idKey,
      key: record.key
    }
    capabilities[index] = objectFreeze({})
    destinationState.capability = capabilities[index]
    destinationStates[index] = destinationState
  }
  for (let index = 0; index < capabilities.length; index++) {
    const destinationState = destinationStates[index]
    reflectApply(weakMapSet, liveDestinationRecords, [capabilities[index], destinationState])
    reflectApply(mapSet, state.owner.byId, [destinationState.idKey, destinationState])
    reflectApply(setAdd, state.owner.destinations, [destinationState])
  }
  const readyState = {
    owner: state.owner,
    branchClass: state.branchClass,
    branchId: state.branchId,
    circuitId: state.circuitId,
    generation: state.generation,
    exitIdentity: state.exitIdentity,
    expiresAt: state.expiresAt
  }
  const branchSeedReady = objectFreeze({})
  readyState.authority = branchSeedReady
  reflectApply(weakMapSet, branchSeedReadyRecords, [branchSeedReady, readyState])
  reflectApply(setAdd, state.owner.seedReadiness, [readyState])
  state.records = []
  state.active = false
  reflectApply(setDelete, state.owner.seedAdmissions, [state])
  return objectFreeze({
    destinations: objectFreeze(capabilities),
    branchSeedReady
  })
}

function abortDhtSeedAdmission(admission) {
  const state = seedAdmission(admission)
  state.active = false
  reflectApply(setDelete, state.owner.seedAdmissions, [state])
  clearStaged(state.records)
  state.records = []
  clear(state.branchId)
  clear(state.circuitId)
  clear(state.exitIdentity)
  return true
}

function revokeDhtSeedAdmissionAuthority(authority) {
  const state = reflectApply(weakMapGet, seedAdmissionAuthorityRecords, [authority])
  if (state === undefined || !state.active) return false
  state.active = false
  spentSeedAdmissionAuthorities.add(authority)
  reflectApply(setDelete, state.owner.seedAuthorities, [state])
  if (state.records !== null) clearStaged(state.records)
  clear(state.branchId)
  clear(state.circuitId)
  clear(state.exitIdentity)

  return true
}
function createTestBranchSeedReady(value) {
  const fields = exactFields(value, TEST_BRANCH_SEED_READY_FIELDS)
  if (!uint64(fields.generation) || !uint64(fields.expiresAt)) invalid()
  const state = {
    owner: null,
    branchClass: branch(fields.branchClass),
    branchId: copy(fields.branchId, 16),
    circuitId: copy(fields.circuitId, 16),
    generation: fields.generation,
    exitIdentity: copy(fields.exitIdentity, 32),
    expiresAt: fields.expiresAt
  }
  const authority = objectFreeze({})
  state.authority = authority
  reflectApply(weakMapSet, branchSeedReadyRecords, [authority, state])
  return authority
}

function revokeBranchSeedReady(authority) {
  const state =
    authority !== null && (typeof authority === 'object' || typeof authority === 'function')
      ? reflectApply(weakMapGet, branchSeedReadyRecords, [authority])
      : undefined
  if (state === undefined) return false
  branchSeedReadyRecords.delete(authority)
  spentBranchSeedReadiness.add(authority)
  if (state.owner !== null) reflectApply(setDelete, state.owner.seedReadiness, [state])
  clear(state.branchId)
  clear(state.circuitId)
  clear(state.exitIdentity)
  return true
}

function consumeBranchSeedReady(authority) {
  const state =
    authority !== null && (typeof authority === 'object' || typeof authority === 'function')
      ? reflectApply(weakMapGet, branchSeedReadyRecords, [authority])
      : undefined
  if (state === undefined) {
    if (
      authority !== null &&
      (typeof authority === 'object' || typeof authority === 'function') &&
      spentBranchSeedReadiness.has(authority)
    ) {
      replay()
    }
    authentication()
  }
  if (state.owner !== null) {
    if (!state.owner.active) destroyed()
    wallNow(state.owner)
  }
  branchSeedReadyRecords.delete(authority)
  spentBranchSeedReadiness.add(authority)
  if (state.owner !== null) reflectApply(setDelete, state.owner.seedReadiness, [state])
  const result = objectFreeze({
    branchClass: state.branchClass,
    branchId: copy(state.branchId, 16),
    circuitId: copy(state.circuitId, 16),
    generation: state.generation,
    exitIdentity: copy(state.exitIdentity, 32),
    expiresAt: state.expiresAt
  })
  clear(state.branchId)
  clear(state.circuitId)
  clear(state.exitIdentity)
  return result
}

function destroyLiveOpaqueDestinations(owner) {
  let state
  try {
    state = reflectApply(weakMapGet, liveOwnerRecords, [owner])
  } catch {
    invalid()
  }
  if (state === undefined) invalid()
  if (!state.active) return
  state.active = false
  const destinations = reflectApply(setValues, state.destinations, [])
  while (true) {
    const next = reflectApply(setIteratorNext, destinations, [])
    if (next.done) break
    clearLiveRecord(next.value)
  }
  const authorities = reflectApply(setValues, state.authorities, [])
  while (true) {
    const next = reflectApply(setIteratorNext, authorities, [])
    if (next.done) break
    const authority = next.value
    authority.active = false
    clear(authority.fromEncoded)
    clear(authority.target)
    clear(authority.requestId)
    clearStaged(authority.staged)
    reflectApply(setClear, authority.stagedIds, [])
  }
  const admissions = reflectApply(setValues, state.admissions, [])
  while (true) {
    const next = reflectApply(setIteratorNext, admissions, [])
    if (next.done) break
    next.value.active = false
    clearStaged(next.value.records)
  }
  for (const authority of state.seedAuthorities) {
    authority.active = false
    seedAdmissionAuthorityRecords.delete(authority.authority)
    spentSeedAdmissionAuthorities.add(authority.authority)
    if (authority.records !== null) clearStaged(authority.records)
    clear(authority.branchId)
    clear(authority.circuitId)
    clear(authority.exitIdentity)
  }
  for (const admission of state.seedAdmissions) {
    admission.active = false
    seedAdmissionRecords.delete(admission.admission)
    clearStaged(admission.records)
    clear(admission.branchId)
    clear(admission.circuitId)
    clear(admission.exitIdentity)
  }
  for (const readiness of state.seedReadiness) {
    branchSeedReadyRecords.delete(readiness.authority)
    spentBranchSeedReadiness.add(readiness.authority)
    clear(readiness.branchId)
    clear(readiness.circuitId)
    clear(readiness.exitIdentity)
  }
  for (const authority of state.replyAuthorities) {
    authenticatedReplyAuthorityRecords.delete(authority.authority)
    spentAuthenticatedReplyAuthorities.add(authority.authority)
    clearAuthenticatedReplyState(authority)
  }
  clear(state.branchId)
  clear(state.finalTranscriptDigest)
  clear(state.circuitId)
  reflectApply(mapClear, state.byId, [])
  reflectApply(setClear, state.destinations, [])
  reflectApply(setClear, state.authorities, [])
  reflectApply(setClear, state.admissions, [])
  reflectApply(setClear, state.seedAuthorities, [])
  reflectApply(setClear, state.seedAdmissions, [])
  reflectApply(setClear, state.seedReadiness, [])
  reflectApply(setClear, state.replyAuthorities, [])
}

function createOpaqueDestinations() {
  const records = new WeakMapConstructor()
  const owned = new SetConstructor()

  function issue(value) {
    let id = null
    let destinationRef = null
    let decoded = null
    try {
      const fields = exactIssue(value)
      const operationClass = branch(fields.branch)
      id = copy(fields.id, ID_SIZE)
      destinationRef = copy(fields.destinationRef, DESTINATION_REF_SIZE)
      decoded = decodeDestinationRef(destinationRef)
      if (!same(decoded.id, id)) invalid()
      const state = {
        active: true,
        branch: operationClass,
        id,
        destinationRef,
        key: keyFor(operationClass, destinationRef)
      }
      id = null
      destinationRef = null
      const capability = objectFreeze({})
      reflectApply(weakMapSet, records, [capability, state])
      reflectApply(setAdd, owned, [state])
      return capability
    } finally {
      clear(id)
      clear(destinationRef)
      if (decoded !== null) {
        clear(decoded.id)
        clear(decoded.handle)
      }
    }
  }

  function state(value) {
    if ((typeof value !== 'object' && typeof value !== 'function') || value === null) invalid()
    let record
    try {
      record = reflectApply(weakMapGet, records, [value])
    } catch {
      invalid()
    }
    if (record === undefined) invalid()
    if (!record.active) destroyed()
    return record
  }

  function snapshot(value) {
    const record = state(value)
    return {
      branch: record.branch,
      id: copy(record.id, ID_SIZE),
      destinationRef: copy(record.destinationRef, DESTINATION_REF_SIZE)
    }
  }

  function key(value) {
    return state(value).key
  }

  function id(value) {
    return copy(state(value).id, ID_SIZE)
  }

  function clearAll() {
    const iterator = reflectApply(setValues, owned, [])
    while (true) {
      const next = reflectApply(setIteratorNext, iterator, [])
      if (next.done) break
      const record = next.value
      if (!record.active) continue
      record.active = false
      clear(record.id)
      clear(record.destinationRef)
    }
    reflectApply(setClear, owned, [])
  }

  objectFreeze(issue)
  objectFreeze(snapshot)
  objectFreeze(key)
  objectFreeze(id)
  objectFreeze(clearAll)
  return objectFreeze({ issue, snapshot, key, id, clear: clearAll })
}

objectFreeze(createOpaqueDestinations)

module.exports = objectFreeze({
  abortDhtSeedAdmission,
  abortRoutedReplyAdmission,
  bindAuthenticatedRoutedReply,
  bindLiveOpaqueDestinationOwnerSession,
  commitRoutedReplyAdmission,
  commitDhtSeedAdmission,
  consumeBranchSeedReady,
  createDhtSeedAdmissionAuthority,
  createLiveOpaqueDestinations,
  createOpaqueDestinations,
  createRoutedReplyReferralAuthorityForDestination,
  createAuthenticatedRoutedReplyAuthority,
  createRoutedReplyReferralAuthority,
  destroyLiveOpaqueDestinations,
  issueLiveOpaqueDestination,
  idLiveOpaqueDestination,
  findLiveOpaqueDestination,
  keyLiveOpaqueDestination,
  revokeDhtSeedAdmissionAuthority,
  snapshotLiveOpaqueDestinations,
  isLiveOpaqueDestinationOwnedBy,
  revokeAuthenticatedReplyAuthority,
  revokeRoutedReplyReferralAuthority,
  revokeLiveOpaqueDestination,
  revokeBranchSeedReady,
  sealRoutedReplyAdmission,
  sealDhtSeedAdmission,
  stageDhtSeedAdmission,
  stageRoutedReplyReferral,
  snapshotLiveOpaqueDestination,
  [TEST_ONLY_BRANCH_SEED_READY_ISSUER]: objectFreeze({
    create: createTestBranchSeedReady
  }),
  [TEST_ONLY_AUTHENTICATED_REPLY_ISSUER]: objectFreeze({
    bindOwner: bindLiveOpaqueDestinationOwnerSession,
    create: createAuthenticatedRoutedReplyAuthority
  }),
  verifyRoutedReplyReferralAuthority
})
