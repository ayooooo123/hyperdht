'use strict'

const b4a = require('b4a')
const sodium = require('sodium-universal')

const { PrivateRouteError } = require('./errors')
const { BRANCH_CLASS } = require('./protocol')
const { DESTINATION_REF_SIZE, decodeDestinationRef } = require('./routed-dht')

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
const SetConstructor = Set
const setAdd = Set.prototype.add
const setClear = Set.prototype.clear
const setValues = Set.prototype.values
const setIteratorPrototype = Object.getPrototypeOf(new Set().values())
const setIteratorNext = setIteratorPrototype.next
const objectFreeze = Object.freeze
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectHasOwnProperty = Object.prototype.hasOwnProperty
const reflectOwnKeys = Reflect.ownKeys
const reflectApply = Reflect.apply
const reflectConstruct = Reflect.construct
const reflectHas = Reflect.has
const cryptoHash = sodium.crypto_generichash
const KEY_DOMAIN = ascii('hyperdht-private-routes/routed-dht/opaque-destination-key/v1')

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function destroyed() {
  throw PrivateRouteError.ERR_DESTROYED()
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

module.exports = objectFreeze({ createOpaqueDestinations })
