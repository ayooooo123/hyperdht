'use strict'

const b4a = require('b4a')
const sodium = require('sodium-universal')

const { PrivateRouteError } = require('./errors')
const { unsupportedCommand } = require('./dht-command-policy')
const { createOpaqueDestinations } = require('./opaque-destination')
const { encodeRoutedRequest, decodeDestinationRef } = require('./routed-dht')

const REQUEST_ID_SIZE = 16
const ID_SIZE = 32
const DESTINATION_REF_SIZE = 172
const MAX_CANDIDATES = 20
const TIMEOUT_MS = 3000n
const MAX_RESPONSE_BYTES = 4706
const MAX_UINT64 = 0xffff_ffff_ffff_ffffn
const ALLOWED_OPTIONS = Object.freeze(['authority', 'contexts', 'now', 'randomBytes'])
const AUTHORITY_METHODS = Object.freeze([
  'ready',
  'suspend',
  'resume',
  'destroy',
  'bootstrap',
  'closest',
  'request'
])
const RESPONSE_FIELDS = Object.freeze([
  'rtt',
  'from',
  'to',
  'token',
  'closerNodes',
  'error',
  'value'
])
const DISCOVERY_FIELDS = Object.freeze(['context', 'target', 'limit'])
const REQUEST_FIELDS = Object.freeze([
  'context',
  'command',
  'to',
  'token',
  'internal',
  'target',
  'value',
  'attempt'
])

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
const trustedBufferConstructor = b4a.alloc(0).constructor
function OwnedBufferConstructor() {}
OwnedBufferConstructor.prototype = trustedBufferConstructor.prototype
const ArrayConstructor = Array
const arrayIsArray = Array.isArray
const arrayIndexOf = Array.prototype.indexOf
const arrayPush = Array.prototype.push
const SetConstructor = Set
const setAdd = Set.prototype.add
const setDelete = Set.prototype.delete
const setClear = Set.prototype.clear
const setValues = Set.prototype.values
const setIteratorNext = Object.getPrototypeOf(new Set().values()).next
const PromiseConstructor = Promise
const promiseThen = Promise.prototype.then
const promiseResolve = Promise.resolve
const DateNow = Date.now
const BigIntConstructor = BigInt
const StringConstructor = String
const numberIsSafeInteger = Number.isSafeInteger
const objectCreate = Object.create
const objectDefineProperty = Object.defineProperty
const objectFreeze = Object.freeze
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectGetPrototypeOf = Object.getPrototypeOf
const objectHasOwnProperty = Object.prototype.hasOwnProperty
const reflectApply = Reflect.apply
const reflectConstruct = Reflect.construct
const reflectHas = Reflect.has
const reflectOwnKeys = Reflect.ownKeys
const randombytesBuf = sodium.randombytes_buf
const invalidRouteError = PrivateRouteError.INVALID_ROUTE
const routeUnavailableError = PrivateRouteError.ROUTE_UNAVAILABLE
const authenticationError = PrivateRouteError.ERR_AUTHENTICATION
const destroyedRouteError = PrivateRouteError.ERR_DESTROYED

function invalid() {
  throw reflectApply(invalidRouteError, PrivateRouteError, [])
}

function unavailable(cause) {
  const error = reflectApply(routeUnavailableError, PrivateRouteError, [])
  if (cause !== undefined) {
    objectDefineProperty(error, 'cause', {
      configurable: true,
      enumerable: false,
      writable: true,
      value: cause
    })
  }
  return error
}

function authentication() {
  throw reflectApply(authenticationError, PrivateRouteError, [])
}

function destroyed() {
  throw reflectApply(destroyedRouteError, PrivateRouteError, [])
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
    // Best effort for an owned allocation that never leaves this adapter.
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

function copy(value, size = bufferLength(value)) {
  let output = null
  try {
    if (size < 0 || bufferLength(value) !== size) invalid()
    output = allocate(size)
    reflectApply(bufferSet, output, [value, 0])
    return output
  } catch (error) {
    clear(output)
    if (error instanceof PrivateRouteError) throw error
    invalid()
  }
}

function ownData(value, name, required = true) {
  if (value === null || (typeof value !== 'object' && typeof value !== 'function')) invalid()
  let descriptor
  try {
    descriptor = objectGetOwnPropertyDescriptor(value, name)
  } catch {
    invalid()
  }
  if (descriptor === undefined) {
    let inherited = false
    try {
      inherited = reflectApply(reflectHas, null, [value, name])
    } catch {
      invalid()
    }
    if (required || inherited) invalid()
    return undefined
  }
  if (!reflectApply(objectHasOwnProperty, descriptor, ['value'])) invalid()
  return descriptor.value
}

function exactOwnData(value, allowed, required = allowed) {
  if (value === null || typeof value !== 'object' || arrayIsArray(value)) invalid()
  let keys
  try {
    keys = reflectApply(reflectOwnKeys, null, [value])
  } catch {
    invalid()
  }
  for (let index = 0; index < keys.length; index++) {
    if (
      typeof keys[index] !== 'string' ||
      reflectApply(arrayIndexOf, allowed, [keys[index]]) === -1
    ) {
      invalid()
    }
  }
  const result = objectCreate(null)
  for (let index = 0; index < allowed.length; index++) {
    const name = allowed[index]
    const isRequired = reflectApply(arrayIndexOf, required, [name]) !== -1
    const field = ownData(value, name, isRequired)
    if (field !== undefined || isRequired) {
      objectDefineProperty(result, name, {
        configurable: false,
        enumerable: true,
        writable: false,
        value: field
      })
    }
  }
  return result
}

function resolveDataMethod(value, name) {
  const method = resolveOptionalDataMethod(value, name)
  if (method === null) invalid()
  return method
}

function resolveOptionalDataMethod(value, name) {
  if (value === null || (typeof value !== 'object' && typeof value !== 'function')) invalid()
  let cursor = value
  try {
    while (cursor !== null) {
      const descriptor = objectGetOwnPropertyDescriptor(cursor, name)
      if (descriptor !== undefined) {
        if (!reflectApply(objectHasOwnProperty, descriptor, ['value'])) invalid()
        if (typeof descriptor.value !== 'function') invalid()
        return descriptor.value
      }
      cursor = objectGetPrototypeOf(cursor)
    }
  } catch (error) {
    if (error instanceof PrivateRouteError) throw error
    invalid()
  }
  return null
}

function bridgePromise(value) {
  if (value === null || (typeof value !== 'object' && typeof value !== 'function')) invalid()
  let resolveBridge = null
  let rejectBridge = null
  const bridge = new PromiseConstructor((resolve, reject) => {
    resolveBridge = resolve
    rejectBridge = reject
  })
  objectDefineProperty(bridge, 'constructor', {
    configurable: false,
    enumerable: false,
    writable: false,
    value: PromiseConstructor
  })
  try {
    reflectApply(promiseThen, value, [resolveBridge, rejectBridge])
  } catch {
    invalid()
  }
  return bridge
}

function normalizedNow(value) {
  if (numberIsSafeInteger(value) && value >= 0) value = BigIntConstructor(value)
  if (typeof value !== 'bigint' || value < 0n || value > MAX_UINT64) invalid()
  return value
}

function recordSnapshot(value) {
  const fields = exactOwnData(value, ['id', 'destinationRef'])
  let id = null
  let destinationRef = null
  let decoded = null
  try {
    id = copy(fields.id, ID_SIZE)
    destinationRef = copy(fields.destinationRef, DESTINATION_REF_SIZE)
    decoded = decodeDestinationRef(destinationRef)
    let difference = 0
    for (let index = 0; index < ID_SIZE; index++) difference |= decoded.id[index] ^ id[index]
    if (difference !== 0) invalid()
    return { id, destinationRef }
  } catch (error) {
    clear(id)
    clear(destinationRef)
    throw error
  } finally {
    if (decoded !== null) {
      clear(decoded.id)
      clear(decoded.handle)
    }
  }
}

function clearRecord(record) {
  if (record === null) return
  clear(record.id)
  clear(record.destinationRef)
}

class RoutedDHTIO {
  constructor(options) {
    const fields = exactOwnData(options, ALLOWED_OPTIONS, ['authority', 'contexts'])
    const authority = fields.authority
    const contexts = fields.contexts
    const methods = {}
    for (let index = 0; index < AUTHORITY_METHODS.length; index++) {
      const name = AUTHORITY_METHODS[index]
      methods[name] = resolveDataMethod(authority, name)
    }
    const classify = resolveDataMethod(contexts, 'classify')
    if (fields.now !== undefined && typeof fields.now !== 'function') invalid()
    if (fields.randomBytes !== undefined && typeof fields.randomBytes !== 'function') invalid()

    // Gate 3A accepts only this reviewed, trusted in-process test boundary. A
    // live or remote authority is forbidden until Gate 3B adds reply codecs.
    this._authority = authority
    this._methods = objectFreeze(methods)
    this._contexts = contexts
    this._classify = classify
    this._now = fields.now || DateNow
    this._randomBytes =
      fields.randomBytes || ((buffer) => reflectApply(randombytesBuf, sodium, [buffer]))
    this._destinations = createOpaqueDestinations()
    this._active = new SetConstructor()
    this._epoch = 0
    this._destroyed = false
    this._suspended = false
    this._desiredSuspended = false
    this._destroying = null
    this._guard = null
    this._transitionTail = reflectApply(promiseResolve, PromiseConstructor, [undefined])
    this._stateOperation = null
  }

  ready() {
    this._assertNoReentry()
    this._assertLive()
    return this._enqueueLifecycle('ready')
  }

  suspend() {
    this._assertNoReentry()
    this._assertLive()
    if (this._desiredSuspended && this._stateOperation !== null) return this._stateOperation
    this._epoch++
    this._desiredSuspended = true
    this._suspended = true
    this._teardown(unavailable())
    this._stateOperation = this._enqueueLifecycle('suspend')
    return this._stateOperation
  }

  resume() {
    this._assertNoReentry()
    this._assertLive()
    if (!this._desiredSuspended && this._stateOperation !== null) return this._stateOperation
    this._desiredSuspended = false
    this._stateOperation = this._enqueueLifecycle('resume', () => {
      if (!this._destroyed && !this._desiredSuspended) this._suspended = false
    })
    return this._stateOperation
  }

  destroy() {
    this._assertNoReentry()
    if (this._destroying !== null) return this._destroying
    this._epoch++
    this._destroyed = true
    this._suspended = true
    this._desiredSuspended = true
    this._teardown(destroyedError())
    this._destroying = this._enqueueLifecycle('destroy')
    return this._destroying
  }

  bootstrap(options) {
    this._assertNoReentry()
    const epoch = this._epoch
    let discovery = null
    let returned
    this._withGuard(() => {
      discovery = this._discoveryOptions(options)
      try {
        returned = this._callAuthority('bootstrap', [
          { target: discovery.target, limit: discovery.limit, branch: discovery.policy.branch }
        ])
      } finally {
        clear(discovery.target)
      }
    })
    let promise
    let promised = false
    try {
      promise = this._withGuard(() => bridgePromise(returned))
      promised = true
    } catch {
      promise = reflectApply(promiseResolve, PromiseConstructor, [undefined])
    }
    return reflectApply(promiseThen, promise, [
      (records) => {
        this._assertEpoch(epoch)
        return this._collectAsync(
          promised ? records : returned,
          discovery.limit,
          discovery.policy.branch,
          epoch
        )
      }
    ])
  }

  closest(options) {
    this._assertNoReentry()
    const epoch = this._epoch
    return this._withGuard(() => {
      const discovery = this._discoveryOptions(options)
      let returned
      try {
        returned = this._callAuthority('closest', [
          { target: discovery.target, limit: discovery.limit, branch: discovery.policy.branch }
        ])
      } finally {
        clear(discovery.target)
      }
      this._assertEpoch(epoch)
      return this._collectSync(returned, discovery.limit, discovery.policy.branch, epoch)
    })
  }

  key(destination) {
    this._assertNoReentry()
    this._assertUsable()
    return this._destinations.key(destination)
  }

  id(destination) {
    this._assertNoReentry()
    this._assertUsable()
    return this._destinations.id(destination)
  }

  request(message) {
    this._assertNoReentry()
    this._assertUsable()
    const epoch = this._epoch
    let fields = null
    let policy = null
    let destination = null
    let target = null
    let encodedBody = null
    let requestId = null
    let encodedRequest = null
    let active = null
    try {
      this._withGuard(() => {
        fields = exactOwnData(message, REQUEST_FIELDS)
        policy = this._classifyContext(fields.context)
        if (fields.command !== policy.command) throw unsupportedCommand()
        if (fields.internal !== false) throw unsupportedCommand()
        destination = this._destinations.snapshot(fields.to)
        if (destination.branch !== policy.branch) authentication()
        if (!numberIsSafeInteger(fields.attempt) || fields.attempt < 1 || fields.attempt > 4) {
          invalid()
        }
        target = copy(fields.target, ID_SIZE)
      })
      encodedBody = policy.encode(policy, {
        command: fields.command,
        target,
        token: fields.token,
        value: fields.value
      })
      const current = this._clock()
      if (current > MAX_UINT64 - TIMEOUT_MS) invalid()
      const deadline = current + TIMEOUT_MS
      requestId = allocate(REQUEST_ID_SIZE)
      const result = this._callCallback(this._randomBytes, null, [requestId])
      if (result !== undefined || bufferLength(requestId) !== REQUEST_ID_SIZE) invalid()
      encodedRequest = encodeRoutedRequest({
        requestId,
        operationClass: policy.branch,
        commandId: policy.commandId,
        absoluteDeadlineMs: deadline,
        destination: destination.destinationRef,
        encodedBody
      })
      let operation
      try {
        operation = this._callAuthority('request', [
          {
            branch: policy.branch,
            destinationRef: destination.destinationRef,
            encodedRequest,
            attempt: fields.attempt
          }
        ])
      } catch (cause) {
        throw unavailable(cause)
      } finally {
        clear(encodedRequest)
        encodedRequest = null
      }
      const operationFields = this._operationFields(operation)
      try {
        this._assertEpoch(epoch)
        this._assertUsable()
      } catch (error) {
        try {
          this._callCallback(operationFields.cancel, null, [error])
        } catch {
          // Preserve the lifecycle error after revoking returned authority state.
        }
        throw error
      }
      active = {
        requestId,
        deadline,
        epoch,
        branch: policy.branch,
        authorityCancel: operationFields.cancel,
        active: true,
        cancelled: false
      }
      requestId = null
      try {
        reflectApply(setAdd, this._active, [active])
        const authorityPromise = operationFields.promise
        const promise = reflectApply(promiseThen, authorityPromise, [
          (response) => this._deliverResponse(active, response),
          (error) => {
            throw unavailable(error)
          }
        ])
        const settled = reflectApply(promiseThen, promise, [
          (value) => {
            this._finishActive(active)
            return value
          },
          (error) => {
            this._finishActive(active)
            throw error
          }
        ])
        const cancelOperation = (reason) => this._cancelActive(active, reason)
        return { promise: settled, cancel: cancelOperation }
      } catch (error) {
        try {
          this._cancelActive(active, error)
        } catch {
          // Preserve the primary subscription error after transactional cleanup.
        }
        throw error
      }
    } finally {
      if (active === null) clear(requestId)
      clear(encodedRequest)
      clear(encodedBody)
      clear(target)
      clearRecord(destination)
    }
  }

  _assertLive() {
    if (this._destroyed) destroyed()
  }

  _assertNoReentry() {
    if (this._guard === null) return
    this._guard.reentered = true
    invalid()
  }

  _assertUsable() {
    this._assertLive()
    if (this._suspended) destroyed()
  }

  _withGuard(operation) {
    if (this._guard !== null) {
      const guard = this._guard
      try {
        const result = operation()
        if (guard.reentered) invalid()
        return result
      } catch (error) {
        if (guard.reentered) invalid()
        throw error
      }
    }
    const guard = { reentered: false }
    this._guard = guard
    try {
      const result = operation()
      if (guard.reentered) invalid()
      return result
    } catch (error) {
      if (guard.reentered) invalid()
      throw error
    } finally {
      this._guard = null
    }
  }

  _callCallback(method, receiver, args) {
    return this._withGuard(() => reflectApply(method, receiver, args))
  }

  _callAuthority(name, args) {
    return this._callCallback(this._methods[name], this._authority, args)
  }

  _classifyContext(context) {
    return this._callCallback(this._classify, this._contexts, [context])
  }

  _clock() {
    return normalizedNow(this._callCallback(this._now, null, []))
  }

  _enqueueLifecycle(name, onSuccess = noop) {
    const settled = reflectApply(promiseThen, this._transitionTail, [noop, noop])
    const delegated = reflectApply(promiseThen, settled, [
      () =>
        this._withGuard(() => {
          const returned = this._callAuthority(name, [])
          if (returned === undefined) return undefined
          return bridgePromise(returned)
        })
    ])
    const operation = reflectApply(promiseThen, delegated, [
      (value) => {
        onSuccess()
        return value
      }
    ])
    this._transitionTail = operation
    return operation
  }

  _assertEpoch(epoch) {
    if (this._destroyed || this._epoch !== epoch) destroyed()
  }

  _discoveryOptions(options) {
    this._assertUsable()
    const fields = exactOwnData(options, DISCOVERY_FIELDS)
    const policy = this._classifyContext(fields.context)
    const target = copy(fields.target, ID_SIZE)
    const limit = fields.limit
    if (!numberIsSafeInteger(limit) || limit < 0 || limit > MAX_CANDIDATES) {
      clear(target)
      invalid()
    }
    return { policy, target, limit }
  }

  _collectSync(records, limit, branch, epoch) {
    const snapshots = []
    let iterator = null
    let iteratorReturn = null
    let complete = false
    try {
      if (arrayIsArray(records)) {
        this._snapshotArray(records, limit, snapshots)
      } else {
        const iteratorMethod = resolveDataMethod(records, Symbol.iterator)
        iterator = this._callCallback(iteratorMethod, records, [])
        const next = resolveDataMethod(iterator, 'next')
        iteratorReturn = resolveOptionalDataMethod(iterator, 'return')
        for (let count = 0; ; count++) {
          const result = this._callCallback(next, iterator, [])
          const done = ownData(result, 'done')
          if (typeof done !== 'boolean') invalid()
          if (done) break
          if (count >= limit) invalid()
          reflectApply(arrayPush, snapshots, [recordSnapshot(ownData(result, 'value'))])
          this._assertEpoch(epoch)
        }
      }
      this._assertEpoch(epoch)
      this._assertUsable()
      const destinations = this._issueSnapshots(snapshots, branch)
      complete = true
      return destinations
    } finally {
      if (!complete && iterator !== null && iteratorReturn !== null) {
        try {
          this._callCallback(iteratorReturn, iterator, [])
        } catch {
          // Preserve the primary validation or lifecycle error.
        }
      }
      for (let index = 0; index < snapshots.length; index++) clearRecord(snapshots[index])
    }
  }

  async _collectAsync(records, limit, branch, epoch) {
    if (arrayIsArray(records)) {
      this._assertEpoch(epoch)
      return this._withGuard(() => this._collectSync(records, limit, branch, epoch))
    }
    const snapshots = []
    let iterator = null
    let iteratorReturn = null
    let asynchronous = false
    let complete = false
    try {
      let next = null
      this._withGuard(() => {
        let iteratorMethod = resolveOptionalDataMethod(records, Symbol.asyncIterator)
        asynchronous = true
        if (iteratorMethod === null) {
          iteratorMethod = resolveDataMethod(records, Symbol.iterator)
          asynchronous = false
        }
        iterator = this._callCallback(iteratorMethod, records, [])
        next = resolveDataMethod(iterator, 'next')
        iteratorReturn = resolveOptionalDataMethod(iterator, 'return')
      })
      for (let count = 0; ; count++) {
        let result = this._withGuard(() => this._callCallback(next, iterator, []))
        if (asynchronous) {
          result = await this._withGuard(() => bridgePromise(result))
          this._assertEpoch(epoch)
        }
        let done
        let value
        this._withGuard(() => {
          done = ownData(result, 'done')
          if (typeof done !== 'boolean') invalid()
          if (!done) value = ownData(result, 'value')
        })
        if (done) break
        if (count >= limit) invalid()
        this._withGuard(() => {
          reflectApply(arrayPush, snapshots, [recordSnapshot(value)])
        })
        this._assertEpoch(epoch)
      }
      this._assertEpoch(epoch)
      this._assertUsable()
      const destinations = this._issueSnapshots(snapshots, branch)
      complete = true
      return destinations
    } finally {
      if (!complete && iterator !== null && iteratorReturn !== null) {
        try {
          let returned = this._withGuard(() => this._callCallback(iteratorReturn, iterator, []))
          if (asynchronous) {
            returned = this._withGuard(() => bridgePromise(returned))
            await returned
          }
        } catch {
          // Preserve the primary validation or lifecycle error.
        }
      }
      for (let index = 0; index < snapshots.length; index++) clearRecord(snapshots[index])
    }
  }

  _snapshotArray(records, limit, snapshots) {
    const length = ownData(records, 'length')
    if (!numberIsSafeInteger(length) || length < 0 || length > limit) invalid()
    for (let index = 0; index < length; index++) {
      reflectApply(arrayPush, snapshots, [
        recordSnapshot(ownData(records, StringConstructor(index)))
      ])
    }
  }

  _issueSnapshots(snapshots, branch) {
    const destinations = new ArrayConstructor(snapshots.length)
    for (let index = 0; index < snapshots.length; index++) {
      destinations[index] = this._destinations.issue({ branch, ...snapshots[index] })
    }
    return destinations
  }

  _operationFields(operation) {
    let cancel = null
    try {
      return this._withGuard(() => {
        const cancelMethod = dataMethodField(operation, 'cancel', true)
        cancel = (reason) => reflectApply(cancelMethod, operation, [reason])
        const promiseValue = dataMethodField(operation, 'promise', false)
        return { promise: bridgePromise(promiseValue), cancel }
      })
    } catch (error) {
      if (cancel !== null) {
        try {
          this._callCallback(cancel, null, [error])
        } catch {
          // Preserve the primary operation-validation error.
        }
      }
      throw error
    }
  }

  _deliverResponse(active, response) {
    if (!active.active) throw unavailable()
    this._assertEpoch(active.epoch)
    this._assertUsable()
    const snapshot = this._snapshotResponse(response)
    try {
      if (!active.active) throw unavailable()
      this._assertEpoch(active.epoch)
      this._assertUsable()
      if (this._clock() > active.deadline) {
        this._cancelActive(active, reflectApply(authenticationError, PrivateRouteError, []))
        authentication()
      }
      if (!active.active) throw unavailable()
      this._assertEpoch(active.epoch)
      this._assertUsable()
    } catch (error) {
      clearResponseSnapshot(snapshot)
      throw error
    }
    return this._publishResponse(snapshot, active.branch)
  }

  _snapshotResponse(response) {
    const snapshots = []
    let value = null
    try {
      return this._withGuard(() => {
        const fields = exactOwnData(response, RESPONSE_FIELDS)
        if (!numberIsSafeInteger(fields.rtt) || fields.rtt < 0) invalid()
        if (!numberIsSafeInteger(fields.error) || fields.error < 0) invalid()
        if (fields.to !== null || fields.token !== null) invalid()
        if (!arrayIsArray(fields.closerNodes)) invalid()
        const closerLength = ownData(fields.closerNodes, 'length')
        if (
          !numberIsSafeInteger(closerLength) ||
          closerLength < 0 ||
          closerLength > MAX_CANDIDATES
        ) {
          invalid()
        }
        if (fields.value !== null && bufferLength(fields.value) < 0) invalid()
        if (fields.value !== null && bufferLength(fields.value) > MAX_RESPONSE_BYTES) invalid()

        // Own the value before later record reflection can mutate caller bytes.
        if (fields.value !== null) value = copy(fields.value)
        reflectApply(arrayPush, snapshots, [recordSnapshot(fields.from)])
        for (let index = 0; index < closerLength; index++) {
          reflectApply(arrayPush, snapshots, [
            recordSnapshot(ownData(fields.closerNodes, StringConstructor(index)))
          ])
        }
        return {
          rtt: fields.rtt,
          error: fields.error,
          records: snapshots,
          value
        }
      })
    } catch (error) {
      clear(value)
      for (let index = 0; index < snapshots.length; index++) clearRecord(snapshots[index])
      throw error
    }
  }

  _publishResponse(snapshot, branch) {
    try {
      const from = this._destinations.issue({ branch, ...snapshot.records[0] })
      const closerNodes = new ArrayConstructor(snapshot.records.length - 1)
      for (let index = 1; index < snapshot.records.length; index++) {
        closerNodes[index - 1] = this._destinations.issue({ branch, ...snapshot.records[index] })
      }
      const result = {
        rtt: snapshot.rtt,
        from,
        to: null,
        token: null,
        closerNodes,
        error: snapshot.error,
        value: snapshot.value
      }
      snapshot.value = null
      return result
    } finally {
      clearResponseSnapshot(snapshot)
      // A native allocation failure after issuance can leave only unreachable
      // capabilities in the private registry; exact rollback is Gate 3B work.
    }
  }

  _cancelActive(active, reason) {
    if (!active.active || active.cancelled) return
    active.cancelled = true
    try {
      if (active.authorityCancel !== null)
        this._callCallback(active.authorityCancel, null, [reason])
    } catch (error) {
      if (error instanceof PrivateRouteError) throw error
      throw unavailable(error)
    } finally {
      this._finishActive(active)
    }
  }

  _finishActive(active) {
    if (!active.active) return
    active.active = false
    reflectApply(setDelete, this._active, [active])
    clear(active.requestId)
  }

  _teardown(reason) {
    const iterator = reflectApply(setValues, this._active, [])
    const pending = []
    while (true) {
      const next = reflectApply(setIteratorNext, iterator, [])
      if (next.done) break
      reflectApply(arrayPush, pending, [next.value])
    }
    for (let index = 0; index < pending.length; index++) {
      try {
        this._cancelActive(pending[index], reason)
      } catch {
        // Every operation is still invalidated before lifecycle delegation.
      }
    }
    reflectApply(setClear, this._active, [])
    this._destinations.clear()
  }
}

function dataMethodField(value, name, method) {
  if (value === null || (typeof value !== 'object' && typeof value !== 'function')) invalid()
  let cursor = value
  try {
    while (cursor !== null) {
      const descriptor = objectGetOwnPropertyDescriptor(cursor, name)
      if (descriptor !== undefined) {
        if (!reflectApply(objectHasOwnProperty, descriptor, ['value'])) invalid()
        if (method && typeof descriptor.value !== 'function') invalid()
        return descriptor.value
      }
      cursor = objectGetPrototypeOf(cursor)
    }
  } catch {
    // Authority-controlled reflection cannot select an adapter error identity.
    invalid()
  }
  invalid()
}

function clearResponseSnapshot(snapshot) {
  if (snapshot === null) return
  clear(snapshot.value)
  snapshot.value = null
  for (let index = 0; index < snapshot.records.length; index++) {
    clearRecord(snapshot.records[index])
  }
}

function destroyedError() {
  return reflectApply(destroyedRouteError, PrivateRouteError, [])
}

function noop() {}

module.exports = { RoutedDHTIO }
