'use strict'

const b4a = require('b4a')
const sodium = require('sodium-universal')

const { PrivateRouteError } = require('./errors')
const { BRANCH_CLASS, DESTINATION_VALIDATION_CLASS } = require('./protocol')
const { DESTINATION_REF_SIZE, decodeDestinationRef } = require('./destination-ref')

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
const KEY_DOMAIN = ascii('hyperdht-private-routes/routed-dht/opaque-destination-key/v1')
const MAX_UINT64 = 0xffff_ffff_ffff_ffffn

const liveOwnerRecords = new WeakMapConstructor()
const liveDestinationRecords = new WeakMapConstructor()
const referralAuthorityRecords = new WeakMapConstructor()
const admissionRecords = new WeakMapConstructor()

function invalid() {
  throw reflectApply(invalidRouteError, PrivateRouteError, [])
}

function destroyed() {
  throw reflectApply(destroyedRouteError, PrivateRouteError, [])
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

function wallNow(state) {
  if (state.clockActive) {
    state.clockReentered = true
    invalid()
  }
  state.clockActive = true
  let current
  let failed = false
  try {
    current = reflectApply(state.wallNow, null, [])
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
  if (current > state.expiresAt) destroyed()
  return current
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
  const fields = exactFields(value, ['branch', 'circuitId', 'generation', 'expiresAt', 'wallNow'])
  const operationClass = branch(fields.branch)
  let circuitId = null
  try {
    circuitId = copy(fields.circuitId, 16)
    if (!uint64(fields.generation) || !uint64(fields.expiresAt)) invalid()
    if (typeof fields.wallNow !== 'function') invalid()
    const state = {
      active: true,
      branch: operationClass,
      circuitId,
      generation: fields.generation,
      expiresAt: fields.expiresAt,
      wallNow: fields.wallNow,
      clockActive: false,
      clockReentered: false,
      byId: new MapConstructor(),
      destinations: new SetConstructor(),
      authorities: new SetConstructor(),
      admissions: new SetConstructor()
    }
    wallNow(state)
    circuitId = null
    const owner = objectFreeze({})
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
    const current = wallNow(ownerState)
    if (
      !uint64(fields.deadline) ||
      fields.deadline < current ||
      fields.deadline > ownerState.expiresAt
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
  if (state === undefined || !state.active) invalid()
  if (!state.owner.active || !state.from.active) destroyed()
  const current = wallNow(state.owner)
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
    fields.now > state.owner.expiresAt ||
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
  if (state === undefined) invalid()
  if (!state.active) return
  state.active = false
  reflectApply(setDelete, state.owner.authorities, [state])
  clear(state.fromEncoded)
  clear(state.target)
  clear(state.requestId)
  clearStaged(state.staged)
  reflectApply(setClear, state.stagedIds, [])
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
  clear(state.circuitId)
  reflectApply(mapClear, state.byId, [])
  reflectApply(setClear, state.destinations, [])
  reflectApply(setClear, state.authorities, [])
  reflectApply(setClear, state.admissions, [])
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
  abortRoutedReplyAdmission,
  commitRoutedReplyAdmission,
  createLiveOpaqueDestinations,
  createOpaqueDestinations,
  createRoutedReplyReferralAuthority,
  destroyLiveOpaqueDestinations,
  issueLiveOpaqueDestination,
  revokeRoutedReplyReferralAuthority,
  sealRoutedReplyAdmission,
  stageRoutedReplyReferral,
  verifyRoutedReplyReferralAuthority
})
