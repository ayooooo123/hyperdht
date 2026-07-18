'use strict'

const b4a = require('b4a')
const crypto = require('hypercore-crypto')

const { DatagramReplayWindow, OrderedReceiver, SenderCounter } = require('./counters')
const { PrivateRouteError } = require('./errors')
const { CELL_CLASS, DIRECTION } = require('./protocol')

// Ported from the reviewed private-routes prototype at commit
// 0305df915b6a767093f9e75e6c06bc0a35da6169.

const ROUTE_FRAME_SIZE = 1100
const ROUTE_COUNTER_SIZE = 8
const ROUTE_CIPHERTEXT_SIZE = 1092
const ROUTE_PLAINTEXT_SIZE = 1076
const MAX_ROUTE_PAYLOAD = 1073

const TEST_ONLY_RECEIVERS = Symbol('test-only-route-payload-receivers')
const ROUTE_PAYLOAD_BINDING = Symbol('route-payload-binding')
const ROUTE_ENDPOINT = Object.freeze({ SOURCE: 0, DESTINATION: 1 })

const CREATED_CONTEXTS = new WeakMap()
const CREATED_CONTEXT_TOKENS = new WeakSet()
const NONCE_DOMAIN_CLAIMS = new Map()
const MAX_UINT64 = (1n << 64n) - 1n
const MAX_LOGICAL_COUNTER = (1n << 63n) - 1n
const MAX_NONCE_DOMAIN_CLAIMS = 4096
const NONCE_DOMAIN_CLAIM = b4a.from('hyperdht-private-routes/nonce-domain/v0')
const RECEIVER_CODES = new Set(['REPLAY', 'COUNTER_INVALID', 'COUNTER_GAP', 'COUNTER_EXHAUSTED'])
const bufferByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
const bufferFill = Uint8Array.prototype.fill
const bufferSet = Uint8Array.prototype.set
const bufferSubarray = Uint8Array.prototype.subarray
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectGetPrototypeOf = Object.getPrototypeOf
const objectHasOwnProperty = Object.prototype.hasOwnProperty
const reflectApply = Reflect.apply

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function optionsObject(options) {
  try {
    if (options === null || typeof options !== 'object' || Array.isArray(options)) invalid()
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
  return options
}

function option(options, name, required = true) {
  let descriptor
  try {
    descriptor = objectGetOwnPropertyDescriptor(options, name)
  } catch {
    invalid()
  }
  if (descriptor === undefined) {
    let inherited = false
    try {
      inherited = name in options
    } catch {
      invalid()
    }
    if (required || inherited) invalid()
    return undefined
  }
  if (!objectHasOwnProperty.call(descriptor, 'value')) invalid()
  return descriptor.value
}

function dataMethod(target, name) {
  if (target === null || (typeof target !== 'object' && typeof target !== 'function')) invalid()
  let current = target
  for (let depth = 0; depth < 8 && current !== null; depth++) {
    let descriptor
    try {
      descriptor = objectGetOwnPropertyDescriptor(current, name)
    } catch {
      invalid()
    }
    if (descriptor !== undefined) {
      if (
        !objectHasOwnProperty.call(descriptor, 'value') ||
        typeof descriptor.value !== 'function'
      ) {
        invalid()
      }
      const method = descriptor.value
      return (...args) => reflectApply(method, target, args)
    }
    try {
      current = objectGetPrototypeOf(current)
    } catch {
      invalid()
    }
  }
  invalid()
}

function optionalDataMethod(target, name) {
  if (target === undefined) return null
  let current = target
  for (let depth = 0; depth < 8 && current !== null; depth++) {
    let descriptor
    try {
      descriptor = objectGetOwnPropertyDescriptor(current, name)
    } catch {
      invalid()
    }
    if (descriptor !== undefined) {
      if (!objectHasOwnProperty.call(descriptor, 'value')) invalid()
      if (descriptor.value === undefined) return null
      if (typeof descriptor.value !== 'function') invalid()
      const method = descriptor.value
      return (...args) => reflectApply(method, target, args)
    }
    try {
      current = objectGetPrototypeOf(current)
    } catch {
      invalid()
    }
  }
  return null
}

function bufferLength(value) {
  try {
    return b4a.isBuffer(value) ? bufferByteLength.call(value) : -1
  } catch {
    return -1
  }
}

function isBuffer(value, size) {
  return bufferLength(value) === size
}

function clear(value) {
  try {
    if (bufferLength(value) >= 0) bufferFill.call(value, 0)
  } catch {
    // Best-effort zeroization only.
  }
}

function allocate(size) {
  let owned = null
  try {
    owned = b4a.allocUnsafeSlow(size)
    if (!isBuffer(owned, size)) invalid()
    return owned
  } catch (err) {
    clear(owned)
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function subarray(value, start, end) {
  try {
    return bufferSubarray.call(value, start, end)
  } catch {
    invalid()
  }
}

function set(target, source, offset = 0) {
  try {
    bufferSet.call(target, source, offset)
  } catch {
    invalid()
  }
}

function copy(value) {
  const length = bufferLength(value)
  if (length < 0) invalid()
  let owned = null
  try {
    owned = allocate(length)
    set(owned, value)
    return owned
  } catch (err) {
    clear(owned)
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function equal(left, right) {
  const length = bufferLength(left)
  if (length < 0 || length !== bufferLength(right)) return false
  let difference = 0
  for (let i = 0; i < length; i++) difference |= left[i] ^ right[i]
  return difference === 0
}

function directionValue(value) {
  if (value !== DIRECTION.FORWARD && value !== DIRECTION.REVERSE) invalid()
  return value
}

function endpointRoleValue(value) {
  if (value !== ROUTE_ENDPOINT.SOURCE && value !== ROUTE_ENDPOINT.DESTINATION) invalid()
  return value
}

function sendDirection(endpointRole) {
  return endpointRole === ROUTE_ENDPOINT.SOURCE ? DIRECTION.FORWARD : DIRECTION.REVERSE
}

function routeClass(value) {
  if (value !== CELL_CLASS.STREAM && value !== CELL_CLASS.DATAGRAM) invalid()
  return value
}

function uint64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= MAX_UINT64
}

function wireCounter(logical, cellClass) {
  if (typeof logical !== 'bigint' || logical < 0n || logical > MAX_LOGICAL_COUNTER) invalid()
  return (logical << 1n) | (cellClass === CELL_CLASS.DATAGRAM ? 1n : 0n)
}

function logicalCounter(wire, cellClass) {
  const expected = cellClass === CELL_CLASS.DATAGRAM ? 1n : 0n
  if ((wire & 1n) !== expected) invalid()
  return wire >> 1n
}

function writeUint64BE(buffer, value, offset) {
  for (let i = offset + 7; i >= offset; i--) {
    buffer[i] = Number(value & 0xffn)
    value >>= 8n
  }
}

function readUint64BE(buffer, offset) {
  let value = 0n
  for (let i = offset; i < offset + 8; i++) value = (value << 8n) | BigInt(buffer[i])
  return value
}

function writeUint16BE(buffer, value, offset) {
  buffer[offset] = value >>> 8
  buffer[offset + 1] = value
}

function associatedData(descriptorId, circuitId, direction, counter) {
  let data = null
  try {
    data = allocate(57)
    set(data, descriptorId)
    set(data, circuitId, 32)
    data[48] = direction
    writeUint64BE(data, counter, 49)
    return data
  } catch (err) {
    clear(data)
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function privateRouteCode(err, allowed) {
  try {
    if (!(err instanceof PrivateRouteError)) return null
    const descriptor = objectGetOwnPropertyDescriptor(err, 'code')
    if (!descriptor || !objectHasOwnProperty.call(descriptor, 'value')) return null
    return allowed.has(descriptor.value) ? descriptor.value : null
  } catch {
    return null
  }
}

function invokeReceiver(operation) {
  try {
    return operation()
  } catch (err) {
    const code = privateRouteCode(err, RECEIVER_CODES)
    if (code !== null) throw new PrivateRouteError(code)
    invalid()
  }
}

function directionState(receivers, name, defaults) {
  const ordered = receivers === undefined ? defaults.ordered : option(receivers, `${name}Ordered`)
  const datagram =
    receivers === undefined ? defaults.datagram : option(receivers, `${name}Datagram`)
  return Object.freeze({
    key: defaults.key,
    noncePrefix: defaults.noncePrefix,
    streamSender: defaults.streamSender,
    datagramSender: defaults.datagramSender,
    ordered,
    datagram,
    pushAuthenticated: dataMethod(ordered, 'pushAuthenticated'),
    acceptAuthenticated: dataMethod(datagram, 'acceptAuthenticated'),
    destroyStreamSender: optionalDataMethod(defaults.streamSender, 'destroy'),
    destroyDatagramSender: optionalDataMethod(defaults.datagramSender, 'destroy'),
    destroyOrdered: optionalDataMethod(ordered, 'destroy'),
    destroyDatagram: optionalDataMethod(datagram, 'destroy')
  })
}

function clearOperationResult(result) {
  try {
    if (bufferLength(result) >= 0) return clear(result)
    if (Array.isArray(result)) {
      for (const value of result) clear(value && value.payload)
      return
    }
    clear(result && result.payload)
  } catch {
    // Teardown continues through hostile adapter results.
  }
}

function decodeDelivery(value) {
  const length = bufferLength(value)
  if (length < 1 || length > MAX_ROUTE_PAYLOAD + 1) invalid()
  return Object.freeze({ class: routeClass(value[0]), payload: copy(subarray(value, 1)) })
}

function decodeDeliveries(deliveries) {
  let values
  try {
    if (!Array.isArray(deliveries)) invalid()
    values = Array.from(deliveries)
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
  const decoded = []
  let complete = false
  try {
    for (const delivery of values) decoded.push(decodeDelivery(delivery))
    complete = true
    return decoded
  } finally {
    for (const delivery of values) clear(delivery)
    if (!complete) for (const value of decoded) clear(value.payload)
  }
}

function contextFields(options) {
  options = optionsObject(options)
  const endpointRole = endpointRoleValue(option(options, 'endpointRole'))
  const descriptorId = option(options, 'descriptorId')
  const circuitId = option(options, 'circuitId')
  const forwardKey = option(options, 'forwardKey')
  const forwardNoncePrefix = option(options, 'forwardNoncePrefix')
  const reverseKey = option(options, 'reverseKey')
  const reverseNoncePrefix = option(options, 'reverseNoncePrefix')
  if (
    !isBuffer(descriptorId, 32) ||
    !isBuffer(circuitId, 16) ||
    !isBuffer(forwardKey, 32) ||
    !isBuffer(forwardNoncePrefix, 16) ||
    !isBuffer(reverseKey, 32) ||
    !isBuffer(reverseNoncePrefix, 16) ||
    equal(forwardKey, reverseKey) ||
    equal(forwardNoncePrefix, reverseNoncePrefix)
  ) {
    invalid()
  }
  return {
    endpointRole,
    descriptorId,
    circuitId,
    forwardKey,
    forwardNoncePrefix,
    reverseKey,
    reverseNoncePrefix
  }
}

function nonceDomainClaim(owned) {
  const direction = sendDirection(owned.endpointRole)
  const key = direction === DIRECTION.FORWARD ? owned.forwardKey : owned.reverseKey
  const prefix =
    direction === DIRECTION.FORWARD ? owned.forwardNoncePrefix : owned.reverseNoncePrefix
  let digest = null
  let claimKey
  try {
    digest = crypto.hash([NONCE_DOMAIN_CLAIM, key, prefix])
    claimKey = b4a.toString(digest, 'hex')
  } catch {
    invalid()
  } finally {
    clear(digest)
  }
  if (NONCE_DOMAIN_CLAIMS.has(claimKey) || NONCE_DOMAIN_CLAIMS.size >= MAX_NONCE_DOMAIN_CLAIMS) {
    invalid()
  }
  const claim = { key: claimKey, state: 'pending' }
  NONCE_DOMAIN_CLAIMS.set(claimKey, claim)
  return claim
}

function releasePendingClaim(owned) {
  const claim = owned && owned.claim
  if (!claim || claim.state !== 'pending') return
  if (NONCE_DOMAIN_CLAIMS.get(claim.key) === claim) NONCE_DOMAIN_CLAIMS.delete(claim.key)
  claim.state = 'released'
}

function activateClaim(owned) {
  const claim = owned && owned.claim
  if (!claim || claim.state !== 'pending' || NONCE_DOMAIN_CLAIMS.get(claim.key) !== claim) invalid()
  claim.state = 'active'
  return claim
}

function clearCreatedContext(owned) {
  if (!owned) return
  for (const name of [
    'descriptorId',
    'circuitId',
    'forwardKey',
    'forwardNoncePrefix',
    'reverseKey',
    'reverseNoncePrefix'
  ]) {
    clear(owned[name])
  }
}

function mintCreatedRoutePayloadContext(options) {
  const fields = contextFields(options)
  const owned = { endpointRole: fields.endpointRole, claim: null }
  try {
    for (const name of [
      'descriptorId',
      'circuitId',
      'forwardKey',
      'forwardNoncePrefix',
      'reverseKey',
      'reverseNoncePrefix'
    ]) {
      owned[name] = copy(fields[name])
    }
    owned.claim = nonceDomainClaim(owned)
    const context = Object.freeze(Object.create(null))
    CREATED_CONTEXTS.set(context, owned)
    CREATED_CONTEXT_TOKENS.add(context)
    return context
  } catch (err) {
    releasePendingClaim(owned)
    clearCreatedContext(owned)
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function destroyCreatedRoutePayloadContext(context) {
  let known
  let owned
  try {
    known = CREATED_CONTEXT_TOKENS.has(context)
    owned = CREATED_CONTEXTS.get(context)
  } catch {
    invalid()
  }
  if (!known) invalid()
  if (!owned) return
  CREATED_CONTEXTS.delete(context)
  releasePendingClaim(owned)
  clearCreatedContext(owned)
}

function takeCreatedContext(context) {
  let known
  let owned
  try {
    known = CREATED_CONTEXT_TOKENS.has(context)
    owned = CREATED_CONTEXTS.get(context)
  } catch {
    invalid()
  }
  if (!known || !owned) invalid()
  CREATED_CONTEXTS.delete(context)
  return owned
}

class RoutePayloadCodec {
  #sealCrypto
  #openCrypto
  #padding
  #descriptorId
  #circuitId
  #forward
  #reverse
  #endpointRole
  #sendDirection
  #receiveDirection
  #nonceDomainClaim
  #destroyed
  #mutating
  #destroyRequested

  constructor(options) {
    options = optionsObject(options)
    const cryptoAdapter = option(options, 'crypto')
    const context = option(options, 'context')
    const window = option(options, 'window')
    const gapTimeout = option(options, 'gapTimeout')
    const now = option(options, 'now')
    const configuredPadding = option(options, 'padding', false)
    const senderInitial = option(options, 'senderInitial', false)
    const receiverInitial = option(options, 'receiverInitial', false)
    const receivers = option(options, TEST_ONLY_RECEIVERS, false)
    if (receivers !== undefined) optionsObject(receivers)

    const sealCrypto = dataMethod(cryptoAdapter, 'seal')
    const openCrypto = dataMethod(cryptoAdapter, 'open')
    const padding =
      configuredPadding === undefined
        ? dataMethod(cryptoAdapter, 'randomBytes')
        : typeof configuredPadding === 'function'
          ? configuredPadding
          : invalid()
    const counterOptions = { initial: senderInitial, maximum: MAX_LOGICAL_COUNTER }
    const receiverOptions = {
      window,
      gapTimeout,
      now,
      initial: receiverInitial,
      maximum: MAX_LOGICAL_COUNTER
    }
    let created = null
    try {
      created = takeCreatedContext(context)
      const forwardDefaults = {
        key: created.forwardKey,
        noncePrefix: created.forwardNoncePrefix,
        streamSender: new SenderCounter(counterOptions),
        datagramSender: new SenderCounter(counterOptions),
        ordered: new OrderedReceiver(receiverOptions),
        datagram: new DatagramReplayWindow({ window, maximum: MAX_LOGICAL_COUNTER })
      }
      const reverseDefaults = {
        key: created.reverseKey,
        noncePrefix: created.reverseNoncePrefix,
        streamSender: new SenderCounter(counterOptions),
        datagramSender: new SenderCounter(counterOptions),
        ordered: new OrderedReceiver(receiverOptions),
        datagram: new DatagramReplayWindow({ window, maximum: MAX_LOGICAL_COUNTER })
      }
      this.#sealCrypto = sealCrypto
      this.#openCrypto = openCrypto
      this.#padding = padding
      this.#descriptorId = created.descriptorId
      this.#circuitId = created.circuitId
      this.#endpointRole = created.endpointRole
      this.#sendDirection = sendDirection(created.endpointRole)
      this.#receiveDirection =
        this.#sendDirection === DIRECTION.FORWARD ? DIRECTION.REVERSE : DIRECTION.FORWARD
      this.#forward = directionState(receivers, 'forward', forwardDefaults)
      this.#reverse = directionState(receivers, 'reverse', reverseDefaults)
      this.#nonceDomainClaim = activateClaim(created)
      this.#destroyed = false
      this.#mutating = false
      this.#destroyRequested = false
    } catch (err) {
      releasePendingClaim(created)
      clearCreatedContext(created)
      if (err instanceof PrivateRouteError) throw PrivateRouteError.INVALID_ROUTE()
      invalid()
    }
  }

  get stats() {
    return Object.freeze({
      destroyed: this.#destroyed,
      forward: this.#directionStats(this.#forward),
      reverse: this.#directionStats(this.#reverse)
    })
  }

  #directionStats(state) {
    return Object.freeze({
      senderNext: state.streamSender.value,
      senderClosed: state.streamSender.closed,
      senderNeedsRotation: state.streamSender.needsRotation,
      datagramSenderNext: state.datagramSender.value,
      datagramSenderClosed: state.datagramSender.closed,
      datagramSenderNeedsRotation: state.datagramSender.needsRotation,
      orderedNext: state.ordered.next,
      orderedBuffered: state.ordered.buffered,
      orderedNeedsRotation: state.ordered.needsRotation,
      datagramHighest: state.datagram.highest,
      datagramNeedsRotation: state.datagram.needsRotation
    })
  }

  [ROUTE_PAYLOAD_BINDING]() {
    if (this.#destroyed || this.#destroyRequested) throw PrivateRouteError.CIRCUIT_STATE()
    return Object.freeze({
      endpointRole: this.#endpointRole,
      descriptorId: copy(this.#descriptorId),
      circuitId: copy(this.#circuitId),
      sendDirection: this.#sendDirection,
      receiveDirection: this.#receiveDirection
    })
  }

  seal(options) {
    return this.#mutate(() => this.#seal(options))
  }

  #seal(options) {
    options = optionsObject(options)
    const direction = directionValue(option(options, 'direction'))
    const cellClass = routeClass(option(options, 'class'))
    const payload = option(options, 'payload')
    const payloadLength = bufferLength(payload)
    if (
      direction !== this.#sendDirection ||
      payloadLength < 0 ||
      payloadLength > MAX_ROUTE_PAYLOAD
    ) {
      invalid()
    }

    const state = direction === DIRECTION.FORWARD ? this.#forward : this.#reverse
    const sender = cellClass === CELL_CLASS.STREAM ? state.streamSender : state.datagramSender
    let plaintext = null
    let padding = null
    let data = null
    let ciphertext = null
    let frame = null
    let transferred = false
    try {
      plaintext = allocate(ROUTE_PLAINTEXT_SIZE)
      plaintext[0] = cellClass
      writeUint16BE(plaintext, payloadLength, 1)
      set(plaintext, payload, 3)
      const paddingSize = MAX_ROUTE_PAYLOAD - payloadLength
      if (paddingSize > 0) {
        try {
          padding = this.#padding(paddingSize)
        } catch {
          invalid()
        }
        if (!isBuffer(padding, paddingSize)) invalid()
        set(plaintext, padding, 3 + payloadLength)
      }

      let logical
      try {
        logical = sender.next()
      } catch (err) {
        const code = privateRouteCode(err, RECEIVER_CODES)
        if (code !== null) throw new PrivateRouteError(code)
        invalid()
      }
      const counter = wireCounter(logical, cellClass)
      data = associatedData(this.#descriptorId, this.#circuitId, direction, counter)
      ciphertext = this.#sealCrypto({
        key: state.key,
        noncePrefix: state.noncePrefix,
        counter,
        associatedData: data,
        plaintext
      })
      if (!isBuffer(ciphertext, ROUTE_CIPHERTEXT_SIZE)) invalid()
      frame = allocate(ROUTE_FRAME_SIZE)
      writeUint64BE(frame, counter, 0)
      set(frame, ciphertext, ROUTE_COUNTER_SIZE)
      transferred = true
      return frame
    } finally {
      if (!transferred) clear(frame)
      clear(plaintext)
      clear(data)
      // Padding and ciphertext are adapter-owned public outputs.
    }
  }

  open(options, frame) {
    return this.#mutate(() => this.#open(options, frame))
  }

  #open(options, frame) {
    if (!isBuffer(frame, ROUTE_FRAME_SIZE)) invalid()
    options = optionsObject(options)
    const direction = directionValue(option(options, 'direction'))
    if (direction !== this.#receiveDirection) invalid()
    const state = direction === DIRECTION.FORWARD ? this.#forward : this.#reverse
    const counter = readUint64BE(frame, 0)
    let data = null
    let plaintext = null
    let delivery = null
    try {
      data = associatedData(this.#descriptorId, this.#circuitId, direction, counter)
      plaintext = this.#openCrypto({
        key: state.key,
        noncePrefix: state.noncePrefix,
        counter,
        associatedData: data,
        ciphertext: subarray(frame, ROUTE_COUNTER_SIZE)
      })
      if (plaintext === null || !isBuffer(plaintext, ROUTE_PLAINTEXT_SIZE)) invalid()
      const cellClass = routeClass(plaintext[0])
      const logical = logicalCounter(counter, cellClass)
      const payloadLength = (plaintext[1] << 8) | plaintext[2]
      if (payloadLength > MAX_ROUTE_PAYLOAD) invalid()

      if (cellClass === CELL_CLASS.DATAGRAM) {
        if (invokeReceiver(() => state.acceptAuthenticated(logical)) !== true) invalid()
        return Object.freeze({
          class: cellClass,
          payload: copy(subarray(plaintext, 3, 3 + payloadLength))
        })
      }

      delivery = allocate(payloadLength + 1)
      delivery[0] = cellClass
      set(delivery, subarray(plaintext, 3, 3 + payloadLength), 1)
      return decodeDeliveries(invokeReceiver(() => state.pushAuthenticated(logical, delivery)))
    } finally {
      clear(data)
      clear(plaintext)
      clear(delivery)
    }
  }

  destroy() {
    if (this.#destroyed || this.#destroyRequested) return
    if (this.#mutating) {
      this.#destroyRequested = true
      return
    }
    this.#destroyNow()
  }

  #mutate(operation) {
    if (this.#destroyed) throw PrivateRouteError.CIRCUIT_STATE()
    if (this.#mutating) {
      this.#destroyRequested = true
      invalid()
    }
    this.#mutating = true
    let result = null
    let failure = null
    let failed = false
    let teardown = false
    try {
      result = operation()
    } catch (err) {
      failed = true
      failure = err
    } finally {
      teardown = this.#destroyRequested || this.#destroyed
      if (teardown) {
        clearOperationResult(result)
        result = null
      }
      this.#mutating = false
      if (this.#destroyRequested) this.#destroyNow()
    }
    if (teardown) throw PrivateRouteError.CIRCUIT_STATE()
    if (failed) throw failure
    return result
  }

  #destroyNow() {
    if (this.#destroyed) return
    this.#destroyed = true
    this.#destroyRequested = false
    for (const state of [this.#forward, this.#reverse]) {
      for (const destroy of [
        state.destroyStreamSender,
        state.destroyDatagramSender,
        state.destroyOrdered,
        state.destroyDatagram
      ]) {
        try {
          if (destroy) destroy()
        } catch {
          // Key and identifier cleanup must continue through hostile test state.
        }
      }
    }
    clear(this.#forward.key)
    clear(this.#forward.noncePrefix)
    clear(this.#reverse.key)
    clear(this.#reverse.noncePrefix)
    clear(this.#descriptorId)
    clear(this.#circuitId)
    if (this.#nonceDomainClaim && this.#nonceDomainClaim.state === 'active') {
      this.#nonceDomainClaim.state = 'spent'
    }
  }
}

module.exports = {
  MAX_ROUTE_PAYLOAD,
  ROUTE_CIPHERTEXT_SIZE,
  ROUTE_COUNTER_SIZE,
  ROUTE_ENDPOINT,
  ROUTE_FRAME_SIZE,
  ROUTE_PAYLOAD_BINDING,
  ROUTE_PLAINTEXT_SIZE,
  RoutePayloadCodec,
  TEST_ONLY_RECEIVERS,
  destroyCreatedRoutePayloadContext,
  mintCreatedRoutePayloadContext
}
