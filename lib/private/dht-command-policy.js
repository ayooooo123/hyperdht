'use strict'

const b4a = require('b4a')

const { COMMANDS } = require('../constants')
const { BRANCH_CLASS, M3_MESSAGE_ID } = require('./protocol')

const UNSUPPORTED_CODE = 'ERR_PRIVATE_COMMAND_UNSUPPORTED'
const UNSUPPORTED_MESSAGE = 'Private DHT command is unsupported'
const ABSENT = Object.freeze({})
const IMMUTABLE_GET_COMMAND = COMMANDS.IMMUTABLE_GET

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

function policy(branch) {
  return objectFreeze({
    branch,
    command: IMMUTABLE_GET_COMMAND,
    commandId: M3_MESSAGE_ID.IMMUTABLE_GET_V1,
    encode: encodeDHTRequest
  })
}

const IMMUTABLE_GET_POLICIES = objectFreeze({
  lookup: policy(BRANCH_CLASS.LOOKUP),
  announce: policy(BRANCH_CLASS.ANNOUNCE)
})

// Expanding this table requires a reviewed exact request-body codec, a reviewed
// routed-reply codec, a matching exit implementation, and adversarial vectors.
// Gate 3A therefore maps only immutable get and fails every other command closed.
function encodeDHTRequest(policy, message) {
  if (policy !== IMMUTABLE_GET_POLICIES.lookup && policy !== IMMUTABLE_GET_POLICIES.announce) {
    unsupported()
  }

  const command = ownData(message, 'command', true)
  if (command !== IMMUTABLE_GET_COMMAND) unsupported()

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

objectFreeze(encodeDHTRequest)
objectFreeze(unsupportedCommand)

module.exports = objectFreeze({
  IMMUTABLE_GET_POLICIES,
  encodeDHTRequest,
  unsupportedCommand
})
