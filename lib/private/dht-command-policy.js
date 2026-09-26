'use strict'

const b4a = require('b4a')
const c = require('compact-encoding')
const sodium = require('sodium-universal')

const { COMMANDS } = require('../constants')
const m = require('../messages')
const { BRANCH_CLASS, M3_MESSAGE_ID } = require('./protocol')

const UNSUPPORTED_CODE = 'ERR_PRIVATE_COMMAND_UNSUPPORTED'
const UNSUPPORTED_MESSAGE = 'Private DHT command is unsupported'
const ABSENT = Object.freeze({})
const IMMUTABLE_GET_COMMAND = COMMANDS.IMMUTABLE_GET
const IMMUTABLE_PUT_COMMAND = COMMANDS.IMMUTABLE_PUT
const MUTABLE_GET_COMMAND = COMMANDS.MUTABLE_GET
const MUTABLE_PUT_COMMAND = COMMANDS.MUTABLE_PUT
const IMMUTABLE_GET_MAX_VALUE = 1023
const MUTABLE_PUT_MAX_VALUE = 895
const PUT_BODY_VERSION = 1

const ErrorConstructor = Error
const Uint8ArrayConstructor = Uint8Array
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype)
const bufferByteLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get
const bufferTag = Object.getOwnPropertyDescriptor(typedArrayPrototype, Symbol.toStringTag).get
const bufferFill = Uint8Array.prototype.fill
const bufferSet = Uint8Array.prototype.set
const objectDefineProperties = Object.defineProperties
const objectFreeze = Object.freeze
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectHasOwnProperty = Object.prototype.hasOwnProperty
const numberIsSafeInteger = Number.isSafeInteger
const reflectApply = Reflect.apply
const reflectConstruct = Reflect.construct
const reflectHas = Reflect.has

const trustedBufferConstructor = b4a.alloc(0).constructor
function OwnedBufferConstructor() {}
OwnedBufferConstructor.prototype = trustedBufferConstructor.prototype

function unsupportedCommand() {
  const error = new ErrorConstructor(UNSUPPORTED_MESSAGE)
  objectDefineProperties(error, {
    name: {
      configurable: false,
      enumerable: false,
      writable: false,
      value: 'PrivateCommandUnsupportedError'
    },
    code: {
      configurable: false,
      enumerable: true,
      writable: false,
      value: UNSUPPORTED_CODE
    }
  })
  return objectFreeze(error)
}

function unsupported() {
  throw unsupportedCommand()
}

function bufferLength(value) {
  try {
    if (reflectApply(bufferTag, value, []) !== 'Uint8Array') return -1
    return reflectApply(bufferByteLength, value, [])
  } catch {
    return -1
  }
}

function clear(value) {
  try {
    if (bufferLength(value) >= 0) reflectApply(bufferFill, value, [0])
  } catch {
    // Best-effort clearing of an allocation that was not returned.
  }
}

function allocate(size) {
  let output = null
  try {
    output = reflectConstruct(Uint8ArrayConstructor, [size], OwnedBufferConstructor)
    if (bufferLength(output) !== size) unsupported()
    return output
  } catch {
    clear(output)
    unsupported()
  }
}

function ownData(value, name, required) {
  let descriptor
  try {
    descriptor = objectGetOwnPropertyDescriptor(value, name)
  } catch {
    unsupported()
  }

  if (descriptor === undefined) {
    let inherited = false
    try {
      inherited = reflectApply(reflectHas, null, [value, name])
    } catch {
      unsupported()
    }
    if (required || inherited) unsupported()
    return ABSENT
  }

  if (!reflectApply(objectHasOwnProperty, descriptor, ['value'])) unsupported()
  return descriptor.value
}

function writeUint16(target, value, offset) {
  target[offset] = value >>> 8
  target[offset + 1] = value
}

function writeUint64(target, value, offset) {
  let remaining = BigInt(value)
  for (let index = offset + 7; index >= offset; index--) {
    target[index] = Number(remaining & 0xffn)
    remaining >>= 8n
  }
}

function same32(left, right) {
  if (bufferLength(left) !== 32 || bufferLength(right) !== 32) return false
  let difference = 0
  for (let index = 0; index < 32; index++) difference |= left[index] ^ right[index]
  return difference === 0
}

function policy(branch, command, commandId) {
  return objectFreeze({
    branch,
    command,
    commandId,
    encode: encodeDHTRequest
  })
}

const IMMUTABLE_GET_POLICIES = objectFreeze({
  lookup: policy(BRANCH_CLASS.LOOKUP, IMMUTABLE_GET_COMMAND, M3_MESSAGE_ID.IMMUTABLE_GET_V1),
  announce: policy(BRANCH_CLASS.ANNOUNCE, IMMUTABLE_GET_COMMAND, M3_MESSAGE_ID.IMMUTABLE_GET_V1)
})

const IMMUTABLE_PUT_POLICIES = objectFreeze({
  announce: policy(BRANCH_CLASS.ANNOUNCE, IMMUTABLE_PUT_COMMAND, M3_MESSAGE_ID.IMMUTABLE_PUT_V1)
})

const MUTABLE_GET_POLICIES = objectFreeze({
  lookup: policy(BRANCH_CLASS.LOOKUP, MUTABLE_GET_COMMAND, M3_MESSAGE_ID.MUTABLE_GET_V1),
  announce: policy(BRANCH_CLASS.ANNOUNCE, MUTABLE_GET_COMMAND, M3_MESSAGE_ID.MUTABLE_GET_V1)
})

const MUTABLE_PUT_POLICIES = objectFreeze({
  announce: policy(BRANCH_CLASS.ANNOUNCE, MUTABLE_PUT_COMMAND, M3_MESSAGE_ID.MUTABLE_PUT_V1)
})

const KNOWN_POLICIES = objectFreeze([
  IMMUTABLE_GET_POLICIES.lookup,
  IMMUTABLE_GET_POLICIES.announce,
  IMMUTABLE_PUT_POLICIES.announce,
  MUTABLE_GET_POLICIES.lookup,
  MUTABLE_GET_POLICIES.announce,
  MUTABLE_PUT_POLICIES.announce
])

function isKnownPolicy(value) {
  for (let index = 0; index < KNOWN_POLICIES.length; index++) {
    if (KNOWN_POLICIES[index] === value) return true
  }
  return false
}

function encodeImmutableGet(message) {
  const token = ownData(message, 'token', false)
  const value = ownData(message, 'value', true)

  if ((token !== ABSENT && token !== null) || value !== null) {
    unsupported()
  }

  const target = ownData(message, 'target', true)
  if (bufferLength(target) !== 32) unsupported()

  let output = null
  try {
    output = allocate(32)
    reflectApply(bufferSet, output, [target, 0])
    if (bufferLength(output) !== 32) unsupported()
    return output
  } catch {
    clear(output)
    unsupported()
  }
}

function encodeImmutablePut(message) {
  const token = ownData(message, 'token', true)
  const value = ownData(message, 'value', true)
  const target = ownData(message, 'target', true)
  const tokenBytes = bufferLength(token)
  const valueBytes = bufferLength(value)
  if (tokenBytes !== 32 || bufferLength(target) !== 32) unsupported()
  if (valueBytes < 0 || valueBytes > IMMUTABLE_GET_MAX_VALUE) unsupported()

  let output = null
  try {
    output = allocate(67 + valueBytes)
    reflectApply(bufferSet, output, [token, 0])
    reflectApply(bufferSet, output, [target, 32])
    output[64] = PUT_BODY_VERSION
    writeUint16(output, valueBytes, 65)
    if (valueBytes > 0) reflectApply(bufferSet, output, [value, 67])
    if (bufferLength(output) !== 67 + valueBytes) unsupported()
    return output
  } catch {
    clear(output)
    unsupported()
  }
}

function encodeMutableGet(message) {
  const token = ownData(message, 'token', false)
  if (token !== ABSENT && token !== null) unsupported()

  const target = ownData(message, 'target', true)
  const value = ownData(message, 'value', true)
  if (bufferLength(target) !== 32 || bufferLength(value) < 1) unsupported()

  let seq = null
  try {
    const state = { start: 0, end: bufferLength(value), buffer: value }
    seq = c.uint.decode(state)
    if (state.start !== state.end) unsupported()
  } catch {
    unsupported()
  }
  if (!numberIsSafeInteger(seq) || seq < 0) unsupported()

  let output = null
  try {
    output = allocate(40)
    reflectApply(bufferSet, output, [target, 0])
    writeUint64(output, seq, 32)
    if (bufferLength(output) !== 40) unsupported()
    return output
  } catch {
    clear(output)
    unsupported()
  }
}

function encodeMutablePut(message) {
  const token = ownData(message, 'token', true)
  const value = ownData(message, 'value', true)
  const target = ownData(message, 'target', true)
  if (bufferLength(token) !== 32 || bufferLength(target) !== 32 || bufferLength(value) < 1) {
    unsupported()
  }

  let decoded = null
  let publicKey = null
  let signature = null
  let recordValue = null
  let digest = null
  let output = null
  try {
    const state = { start: 0, end: bufferLength(value), buffer: value }
    decoded = m.mutablePutRequest.decode(state)
    if (state.start !== state.end) unsupported()
    publicKey = decoded.publicKey
    signature = decoded.signature
    recordValue = decoded.value
    const seq = decoded.seq
    if (bufferLength(publicKey) !== 32 || bufferLength(signature) !== 64) unsupported()
    if (!numberIsSafeInteger(seq) || seq < 0) unsupported()
    const valueBytes = bufferLength(recordValue)
    if (valueBytes < 0 || valueBytes > MUTABLE_PUT_MAX_VALUE) unsupported()
    digest = allocate(32)
    sodium.crypto_generichash(digest, publicKey)
    if (!same32(digest, target)) unsupported()

    output = allocate(171 + valueBytes)
    reflectApply(bufferSet, output, [token, 0])
    reflectApply(bufferSet, output, [target, 32])
    reflectApply(bufferSet, output, [publicKey, 64])
    writeUint64(output, seq, 96)
    output[104] = PUT_BODY_VERSION
    writeUint16(output, valueBytes, 105)
    if (valueBytes > 0) reflectApply(bufferSet, output, [recordValue, 107])
    reflectApply(bufferSet, output, [signature, 107 + valueBytes])
    if (bufferLength(output) !== 171 + valueBytes) unsupported()
    return output
  } catch {
    clear(output)
    unsupported()
  } finally {
    clear(digest)
  }
}

function encodeDHTRequest(policy, message) {
  if (!isKnownPolicy(policy)) unsupported()

  const command = ownData(message, 'command', true)
  if (command !== policy.command) unsupported()

  if (policy.command === IMMUTABLE_GET_COMMAND) return encodeImmutableGet(message)
  if (policy.command === IMMUTABLE_PUT_COMMAND) return encodeImmutablePut(message)
  if (policy.command === MUTABLE_GET_COMMAND) return encodeMutableGet(message)
  if (policy.command === MUTABLE_PUT_COMMAND) return encodeMutablePut(message)
  unsupported()
}

objectFreeze(encodeDHTRequest)
objectFreeze(unsupportedCommand)

module.exports = objectFreeze({
  IMMUTABLE_GET_MAX_VALUE,
  MUTABLE_PUT_MAX_VALUE,
  IMMUTABLE_GET_POLICIES,
  IMMUTABLE_PUT_POLICIES,
  MUTABLE_GET_POLICIES,
  MUTABLE_PUT_POLICIES,
  encodeDHTRequest,
  unsupportedCommand
})
