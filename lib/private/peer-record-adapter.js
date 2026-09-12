'use strict'

const b4a = require('b4a')
const { Duplex, Writable, getStreamError, isEnded, isFinished, isFinishing } = require('streamx')

const { PrivateRouteError } = require('./errors')

const PREFIX_BYTES = 3
const SECRETSTREAM_ID_BYTES = 32
const SECRETSTREAM_HEADER_BYTES = 24
const HEADER_BODY_BYTES = SECRETSTREAM_ID_BYTES + SECRETSTREAM_HEADER_BYTES
const SECRETSTREAM_ABYTES = 17
const MAX_BODY_BYTES = 0xffffff
const MAX_RAW_RECORD_BYTES = PREFIX_BYTES + MAX_BODY_BYTES
const MAX_PLAINTEXT_BYTES = MAX_BODY_BYTES - SECRETSTREAM_ABYTES
const MAX_DATA_FRAGMENT_BYTES = 977
const PLAINTEXT_OFFSET = PREFIX_BYTES + 1

const OPTION_FIELDS = Object.freeze([
  'onOutboundRecord',
  'onInboundCapacity',
  'onFailure',
  'defer',
  'acquireInbound',
  'releaseInbound',
  'acquireOutbound',
  'releaseOutbound'
])

const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectHasOwnProperty = Object.prototype.hasOwnProperty
const reflectApply = Reflect.apply
const reflectOwnKeys = Reflect.ownKeys
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype)
const typedArrayBuffer = objectGetOwnPropertyDescriptor(typedArrayPrototype, 'buffer').get
const typedArrayByteLength = objectGetOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get
const typedArrayByteOffset = objectGetOwnPropertyDescriptor(typedArrayPrototype, 'byteOffset').get
const typedArrayFill = Uint8Array.prototype.fill
const typedArraySet = Uint8Array.prototype.set
const typedArraySubarray = Uint8Array.prototype.subarray

function invalidRoute() {
  return PrivateRouteError.INVALID_ROUTE()
}

function destroyedError() {
  return PrivateRouteError.ERR_DESTROYED()
}

function authenticationError() {
  return PrivateRouteError.ERR_AUTHENTICATION()
}

function recordsUnavailableError() {
  return PrivateRouteError.ERR_PRIVATE_RECORDS_UNAVAILABLE()
}

function quotaError() {
  return PrivateRouteError.ERR_QUOTA_EXCEEDED()
}

function asError(value, fallback) {
  return value instanceof Error ? value : fallback()
}

function ownData(target, name) {
  let descriptor
  try {
    descriptor = objectGetOwnPropertyDescriptor(target, name)
  } catch {
    throw invalidRoute()
  }
  if (descriptor === undefined || !objectHasOwnProperty.call(descriptor, 'value')) {
    throw invalidRoute()
  }
  return descriptor.value
}

function callbacksFrom(options) {
  try {
    if (options === null || typeof options !== 'object' || Array.isArray(options)) {
      throw invalidRoute()
    }
    const keys = reflectOwnKeys(options)
    if (keys.length !== OPTION_FIELDS.length) throw invalidRoute()
    const expected = new Set(OPTION_FIELDS)
    for (const key of keys) {
      if (typeof key !== 'string' || !expected.has(key)) throw invalidRoute()
    }
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    throw invalidRoute()
  }

  const callbacks = {}
  for (const name of OPTION_FIELDS) {
    const callback = ownData(options, name)
    if (typeof callback !== 'function') throw invalidRoute()
    callbacks[name] = callback
  }
  return callbacks
}

function invoke(callback, args = []) {
  return reflectApply(callback, null, args)
}

function bufferInfo(value) {
  try {
    if (!b4a.isBuffer(value)) return null
    return {
      buffer: reflectApply(typedArrayBuffer, value, []),
      byteLength: reflectApply(typedArrayByteLength, value, []),
      byteOffset: reflectApply(typedArrayByteOffset, value, [])
    }
  } catch {
    return null
  }
}

function freshBuffer(byteLength) {
  const backing = new ArrayBuffer(byteLength)
  const buffer = b4a.from(backing)
  const info = bufferInfo(buffer)
  if (
    info === null ||
    info.buffer !== backing ||
    info.byteOffset !== 0 ||
    info.byteLength !== byteLength ||
    backing.byteLength !== byteLength
  ) {
    throw recordsUnavailableError()
  }
  return buffer
}

function clearBuffer(buffer) {
  if (bufferInfo(buffer) === null) return
  try {
    reflectApply(typedArrayFill, buffer, [0])
  } catch {
    // Best effort for owned, unexposed bytes during teardown.
  }
}

function copyBytes(target, targetOffset, source, sourceStart, sourceEnd) {
  const view = reflectApply(typedArraySubarray, source, [sourceStart, sourceEnd])
  reflectApply(typedArraySet, target, [view, targetOffset])
}

function readUint24LE(buffer) {
  return buffer[0] + buffer[1] * 0x100 + buffer[2] * 0x10000
}

function recordWeight() {
  return 1
}

function recordKind(recordCount) {
  return recordCount === 0 ? 'header' : 'application'
}

function validBodyBytes(kind, bodyBytes) {
  if (kind === 'header') return bodyBytes === HEADER_BODY_BYTES
  return bodyBytes >= SECRETSTREAM_ABYTES && bodyBytes <= MAX_BODY_BYTES
}

function validateRawRecord(record, recordCount) {
  const info = bufferInfo(record)
  if (info === null || info.byteLength < PREFIX_BYTES || info.byteLength > MAX_RAW_RECORD_BYTES) {
    throw recordsUnavailableError()
  }
  const bodyBytes = readUint24LE(record)
  const kind = recordKind(recordCount)
  if (!validBodyBytes(kind, bodyBytes) || bodyBytes + PREFIX_BYTES !== info.byteLength) {
    throw recordsUnavailableError()
  }
  return { bodyBytes, kind, rawBytes: info.byteLength }
}

function validateSecretStream(secretStream, recordAdapter) {
  if (secretStream === null || typeof secretStream !== 'object') throw invalidRoute()
  if (secretStream.rawStream !== recordAdapter) throw invalidRoute()
  for (const name of ['read', 'write', 'flush', 'end', 'destroy', 'on', 'once', 'removeListener']) {
    if (typeof secretStream[name] !== 'function') throw invalidRoute()
  }
  if (
    secretStream.opened === null ||
    (typeof secretStream.opened !== 'object' && typeof secretStream.opened !== 'function') ||
    typeof secretStream.opened.then !== 'function'
  ) {
    throw invalidRoute()
  }
}

class PeerRecordAdapter extends Duplex {
  constructor(options) {
    const callbacks = callbacksFrom(options)
    super({
      highWaterMark: 0,
      byteLengthReadable: recordWeight,
      byteLengthWritable: recordWeight
    })

    this._onOutboundRecord = callbacks.onOutboundRecord
    this._onInboundCapacity = callbacks.onInboundCapacity
    this._onFailure = callbacks.onFailure
    this._defer = callbacks.defer
    this._acquireInbound = callbacks.acquireInbound
    this._releaseInbound = callbacks.releaseInbound
    this._acquireOutbound = callbacks.acquireOutbound
    this._releaseOutbound = callbacks.releaseOutbound

    this._prefix = freshBuffer(PREFIX_BYTES)
    this._prefixBytes = 0
    this._inbound = null
    this._inboundRecordCount = 0
    this._outbound = null
    this._outboundRecordCount = 0
    this._outboundGate = false

    this._capacityTask = null
    this._capacityEpoch = 0
    this._lifetime = 1

    this._ciphertextEnded = false
    this._rawGracefulClosed = false
    this._retired = false
    this._revoked = false
    this._failureNotified = false

    this._boundOnce = false
    this._secretStream = null
    this._facade = null
    this._nativeDestroyIssued = false
  }

  consumeCiphertext(fragment) {
    if (this._revoked || this.destroying) throw destroyedError()
    if (this._ciphertextEnded) {
      const error = authenticationError()
      this.destroy(error)
      throw error
    }

    const fragmentInfo = bufferInfo(fragment)
    if (
      fragmentInfo === null ||
      fragmentInfo.byteLength < 1 ||
      fragmentInfo.byteLength > MAX_DATA_FRAGMENT_BYTES
    ) {
      const error = invalidRoute()
      this.destroy(error)
      throw error
    }

    if (this._inbound !== null && this._inbound.complete) return 0

    let offset = 0
    try {
      const cancelError = this._cancelCapacityTask(false)
      if (cancelError !== null) throw cancelError

      if (this._inbound === null) {
        const needed = PREFIX_BYTES - this._prefixBytes
        const available = fragmentInfo.byteLength - offset
        const take = needed < available ? needed : available
        copyBytes(this._prefix, this._prefixBytes, fragment, offset, offset + take)
        this._prefixBytes += take
        offset += take

        if (this._prefixBytes < PREFIX_BYTES) return offset

        const bodyBytes = readUint24LE(this._prefix)
        const kind = recordKind(this._inboundRecordCount)
        if (!validBodyBytes(kind, bodyBytes)) {
          clearBuffer(this._prefix)
          this._prefixBytes = 0
          throw authenticationError()
        }

        const rawBytes = bodyBytes + PREFIX_BYTES
        if (rawBytes > MAX_RAW_RECORD_BYTES) {
          clearBuffer(this._prefix)
          this._prefixBytes = 0
          throw authenticationError()
        }

        let acquired = false
        let record = null
        try {
          invoke(this._acquireInbound, [rawBytes, kind])
          acquired = true
          record = freshBuffer(rawBytes)
          copyBytes(record, 0, this._prefix, 0, PREFIX_BYTES)
        } catch (err) {
          if (acquired) {
            try {
              invoke(this._releaseInbound, [rawBytes, kind])
            } catch (releaseError) {
              err = releaseError
            }
          }
          throw asError(err, recordsUnavailableError)
        } finally {
          clearBuffer(this._prefix)
          this._prefixBytes = 0
        }

        this._inbound = {
          record,
          plain: null,
          rawBytes,
          bodyBytes,
          kind,
          filled: PREFIX_BYTES,
          complete: false,
          phase: 'assembling',
          exposed: false,
          acquired: true
        }
      }

      const current = this._inbound
      const missing = current.rawBytes - current.filled
      const available = fragmentInfo.byteLength - offset
      const take = missing < available ? missing : available
      if (take > 0) {
        copyBytes(current.record, current.filled, fragment, offset, offset + take)
        current.filled += take
        offset += take
      }

      if (current.filled === current.rawBytes) {
        current.complete = true
        current.phase = 'raw-queued'
        this._inboundRecordCount++
        this.push(current.record)
      }

      // A DATA frame may cross a record boundary. Stop at that boundary even if
      // a flowing raw consumer releases capacity synchronously during push().
      return offset
    } catch (err) {
      const error = asError(err, recordsUnavailableError)
      this.destroy(error)
      throw error
    }
  }

  endCiphertext() {
    if (this._revoked || this.destroying) throw destroyedError()
    if (this._ciphertextEnded) return false
    if (this._prefixBytes !== 0 || (this._inbound !== null && this._inbound.complete === false)) {
      const error = authenticationError()
      this.destroy(error)
      throw error
    }
    this._ciphertextEnded = true
    const cancelError = this._cancelCapacityTask(false)
    if (cancelError !== null) {
      this.destroy(cancelError)
      throw cancelError
    }
    this.push(null)
    return true
  }

  flush() {
    return Writable.drained(this)
  }

  write(record) {
    if (this._revoked || this.destroying || isFinishing(this)) {
      if (!this._revoked) this.destroy(destroyedError())
      return false
    }
    if (this._outboundGate) {
      this.destroy(recordsUnavailableError())
      return false
    }

    let metadata
    try {
      metadata = validateRawRecord(record, this._outboundRecordCount)
      invoke(this._acquireOutbound, [metadata.rawBytes, metadata.kind])
    } catch (err) {
      this.destroy(asError(err, recordsUnavailableError))
      return false
    }

    const entry = {
      record,
      rawBytes: metadata.rawBytes,
      bodyBytes: metadata.bodyBytes,
      kind: metadata.kind,
      callback: null,
      lifetime: this._lifetime,
      acquired: true,
      settled: false
    }
    this._outbound = entry
    this._outboundGate = true

    try {
      return super.write(record)
    } catch (err) {
      this._outbound = null
      this._outboundGate = false
      entry.record = null
      const releaseError = this._releaseOutboundEntry(entry)
      const error = releaseError || asError(err, recordsUnavailableError)
      this.destroy(error)
      return false
    }
  }

  destroy(error) {
    if (this.destroyed) {
      if (!this._revoked && !this._retired && error !== null && error !== undefined) {
        this._revoke(asError(error, destroyedError))
      }
      return this
    }
    super.destroy(error)
    return this
  }

  _read(callback) {
    let error = null
    const current = this._inbound
    if (current !== null && current.complete) {
      if (current.kind === 'header') {
        error = this._releaseInboundEntry(current, false, !this._ciphertextEnded)
      } else if (current.phase === 'raw-queued') {
        current.phase = 'raw-consumed'
      }
    }
    callback(error)
  }

  _write(record, callback) {
    const entry = this._outbound
    if (
      entry === null ||
      entry.record !== record ||
      entry.callback !== null ||
      entry.settled ||
      entry.lifetime !== this._lifetime
    ) {
      const error = recordsUnavailableError()
      callback(error)
      this.destroy(error)
      return
    }

    entry.callback = callback
    let transfer
    try {
      transfer = invoke(this._onOutboundRecord, [record])
    } catch (err) {
      this._completeOutbound(entry, asError(err, recordsUnavailableError))
      return
    }

    Promise.resolve(transfer).then(
      () => this._completeOutbound(entry, null),
      (err) => this._completeOutbound(entry, asError(err, recordsUnavailableError))
    )
  }

  _final(callback) {
    callback(null)
  }

  _predestroy() {
    const visibleError = getStreamError(this)
    if (visibleError === null && isEnded(this) && isFinished(this)) {
      this._rawGracefulClosed = true
      return
    }
    const error = visibleError === null ? destroyedError() : asError(visibleError, destroyedError)
    this._revoke(error)
  }

  _destroy(callback) {
    if (!this._revoked) {
      this._rawGracefulClosed = true
      if (this._facade === null) this._retireGracefully()
    }
    callback(null)
  }

  _completeOutbound(entry, error) {
    if (
      entry.settled ||
      entry !== this._outbound ||
      entry.lifetime !== this._lifetime ||
      this._revoked
    ) {
      return
    }

    entry.settled = true
    const callback = entry.callback
    entry.callback = null
    entry.record = null

    const releaseError = this._releaseOutboundEntry(entry)
    if (error === null && releaseError !== null) error = releaseError
    if (error === null) this._outboundRecordCount++

    this._outbound = null
    this._outboundGate = false

    if (callback !== null) callback(error)
    if (error !== null && !this.destroying) this.destroy(error)
  }

  _releaseOutboundEntry(entry) {
    if (!entry.acquired) return null
    entry.acquired = false
    try {
      invoke(this._releaseOutbound, [entry.rawBytes, entry.kind])
      return null
    } catch (err) {
      return asError(err, recordsUnavailableError)
    }
  }

  _releaseInboundEntry(entry, erase, notify) {
    if (entry !== this._inbound) return null
    this._inbound = null

    if (erase && !entry.exposed) {
      clearBuffer(entry.record)
      clearBuffer(entry.plain)
    }
    entry.record = null
    entry.plain = null

    let error = null
    if (entry.acquired) {
      entry.acquired = false
      try {
        invoke(this._releaseInbound, [entry.rawBytes, entry.kind])
      } catch (err) {
        error = asError(err, recordsUnavailableError)
      }
    }

    if (error === null && notify && !this._revoked) {
      error = this._scheduleCapacityNotification()
    }
    if (error !== null && !this.destroying) this.destroy(error)
    return error
  }

  _scheduleCapacityNotification() {
    if (this._revoked || this._ciphertextEnded || this._capacityTask !== null) return null

    const task = {
      lifetime: this._lifetime,
      epoch: ++this._capacityEpoch,
      armed: false,
      early: false,
      cancel: null
    }
    this._capacityTask = task

    let cancel
    try {
      cancel = invoke(this._defer, [
        () => {
          if (!task.armed) {
            task.early = true
            return
          }
          this._runCapacityNotification(task)
        }
      ])
    } catch (err) {
      this._capacityTask = null
      return asError(err, recordsUnavailableError)
    }

    if (typeof cancel !== 'function' || task.early) {
      if (typeof cancel === 'function') {
        try {
          invoke(cancel)
        } catch {}
      }
      if (this._capacityTask === task) this._capacityTask = null
      return recordsUnavailableError()
    }

    task.cancel = cancel
    task.armed = true
    return null
  }

  _runCapacityNotification(task) {
    if (this._capacityTask !== task) return
    this._capacityTask = null
    task.cancel = null
    if (
      this._revoked ||
      this._ciphertextEnded ||
      task.lifetime !== this._lifetime ||
      task.epoch !== this._capacityEpoch
    ) {
      return
    }
    try {
      invoke(this._onInboundCapacity)
    } catch (err) {
      this.destroy(asError(err, recordsUnavailableError))
    }
  }

  _cancelCapacityTask(teardown) {
    const task = this._capacityTask
    if (task === null) return null
    this._capacityTask = null
    this._capacityEpoch++
    const cancel = task.cancel
    task.cancel = null
    if (typeof cancel !== 'function') return teardown ? null : recordsUnavailableError()
    try {
      invoke(cancel)
      return null
    } catch (err) {
      return teardown ? null : asError(err, recordsUnavailableError)
    }
  }

  _bind(secretStream, facade) {
    if (this._boundOnce || this._revoked || this.destroying || this.destroyed) throw invalidRoute()
    validateSecretStream(secretStream, this)
    this._boundOnce = true
    this._secretStream = secretStream
    this._facade = facade
  }

  _claimPlaintext(plain) {
    const current = this._inbound
    const plainInfo = bufferInfo(plain)
    const recordInfo = current === null ? null : bufferInfo(current.record)
    if (
      current === null ||
      current.kind !== 'application' ||
      !current.complete ||
      current.exposed ||
      (current.phase !== 'raw-queued' && current.phase !== 'raw-consumed') ||
      plainInfo === null ||
      recordInfo === null ||
      plainInfo.buffer !== recordInfo.buffer ||
      plainInfo.byteOffset !== recordInfo.byteOffset + PLAINTEXT_OFFSET ||
      plainInfo.byteLength !== current.bodyBytes - SECRETSTREAM_ABYTES
    ) {
      throw recordsUnavailableError()
    }

    current.exposed = true
    current.phase = 'facade-held'
    current.plain = plain
    current.record = null
    return current
  }

  _releasePlaintext(entry, teardown) {
    if (entry !== this._inbound) return false
    if (!entry.exposed || entry.phase !== 'facade-held') throw recordsUnavailableError()
    const error = this._releaseInboundEntry(
      entry,
      false,
      !teardown && !this._ciphertextEnded && !this._revoked
    )
    if (error !== null) throw error
    return true
  }

  _facadeClosed(facade, secretStream) {
    if (this._facade !== facade || this._secretStream !== secretStream) return
    let error = null
    if (!this._revoked && this._inbound !== null) {
      error = this._releaseInboundEntry(this._inbound, !this._inbound.exposed, false)
    }
    if (error !== null && !this._revoked) this._revoke(error)
    this._facade = null
    this._secretStream = null
    if (this._rawGracefulClosed && !this._revoked) this._retireGracefully()
  }

  _retireGracefully() {
    if (this._retired || this._revoked) return

    this._cancelCapacityTask(true)
    if (this._inbound !== null) {
      const error = this._releaseInboundEntry(this._inbound, !this._inbound.exposed, false)
      if (error !== null) {
        this._revoke(error)
        return
      }
    }

    this._retired = true
    this._lifetime++
    this._ciphertextEnded = true
    clearBuffer(this._prefix)
    this._prefix = null
    this._prefixBytes = 0
    this._onOutboundRecord = null
    this._onInboundCapacity = null
    this._onFailure = null
    this._defer = null
    this._acquireInbound = null
    this._releaseInbound = null
    this._acquireOutbound = null
    this._releaseOutbound = null
  }

  _destroyNative(error) {
    if (this._nativeDestroyIssued || this._secretStream === null) return
    this._nativeDestroyIssued = true
    const secretStream = this._secretStream
    if (!secretStream.destroying && !secretStream.destroyed) {
      try {
        secretStream.destroy(error)
      } catch {
        // The adapter is already revoked; no callback may revive it.
      }
    }
  }

  _revoke(initialError) {
    if (this._revoked) return
    this._revoked = true
    this._lifetime++
    this._ciphertextEnded = true

    let error = asError(initialError, destroyedError)
    this._cancelCapacityTask(true)
    clearBuffer(this._prefix)
    this._prefix = null
    this._prefixBytes = 0

    if (this._inbound !== null) {
      const releaseError = this._releaseInboundEntry(this._inbound, !this._inbound.exposed, false)
      if (releaseError !== null) error = releaseError
    }

    const outbound = this._outbound
    if (outbound !== null) {
      outbound.settled = true
      const callback = outbound.callback
      outbound.callback = null
      outbound.record = null
      const releaseError = this._releaseOutboundEntry(outbound)
      if (releaseError !== null) error = releaseError
      this._outbound = null
      this._outboundGate = false
      if (callback !== null) {
        try {
          callback(error)
        } catch {}
      }
    }

    if (!this._failureNotified) {
      this._failureNotified = true
      try {
        invoke(this._onFailure, [error])
      } catch {}
    }

    const facade = this._facade
    if (facade !== null && !facade.destroying && !facade.destroyed) facade.destroy(error)
    this._destroyNative(error)

    this._onOutboundRecord = null
    this._onInboundCapacity = null
    this._onFailure = null
    this._defer = null
    this._acquireInbound = null
    this._releaseInbound = null
    this._acquireOutbound = null
    this._releaseOutbound = null
  }
}

class PeerPlaintextDuplex extends Duplex {
  constructor(secretStream, recordAdapter) {
    super({
      highWaterMark: 0,
      byteLengthReadable: recordWeight,
      byteLengthWritable: recordWeight
    })

    this._secretStream = secretStream
    this._recordAdapter = recordAdapter
    this._pendingRead = null
    this._pendingWrite = null
    this._pendingFinal = null
    this._heldPlaintext = null
    this._secretEnded = false
    this._secretFinished = false
    this._secretClosed = false
    this._pumping = false
    this._pumpAgain = false
    this._terminal = false
    this._lifetime = 1

    this._onSecretReadableBound = this._onSecretReadable.bind(this)
    this._onSecretEndBound = this._onSecretEnd.bind(this)
    this._onSecretFinishBound = this._onSecretFinish.bind(this)
    this._onSecretErrorBound = this._onSecretError.bind(this)
    const facade = this
    this._onSecretCloseBound = function () {
      facade._onSecretClose(this)
    }

    recordAdapter._bind(secretStream, this)
    secretStream.on('readable', this._onSecretReadableBound)
    secretStream.on('end', this._onSecretEndBound)
    secretStream.on('finish', this._onSecretFinishBound)
    secretStream.on('error', this._onSecretErrorBound)
    secretStream.on('close', this._onSecretCloseBound)
  }

  _read(callback) {
    if (this._pendingRead !== null) {
      callback(recordsUnavailableError())
      return
    }

    const operation = { callback, lifetime: this._lifetime, settled: false }
    this._pendingRead = operation

    if (this._heldPlaintext !== null) {
      const held = this._heldPlaintext
      this._heldPlaintext = null
      try {
        this._recordAdapter._releasePlaintext(held, false)
      } catch (err) {
        this._completeRead(operation, asError(err, recordsUnavailableError))
        return
      }
    }

    this._pump()
  }

  _write(data, callback) {
    const info = bufferInfo(data)
    if (info === null) {
      callback(invalidRoute())
      return
    }
    if (info.byteLength > MAX_PLAINTEXT_BYTES) {
      callback(quotaError())
      return
    }
    if (this._pendingWrite !== null) {
      callback(recordsUnavailableError())
      return
    }

    const operation = {
      callback,
      lifetime: this._lifetime,
      settled: false,
      data
    }
    this._pendingWrite = operation
    this._runWrite(operation)
  }

  _final(callback) {
    if (this._pendingFinal !== null) {
      callback(recordsUnavailableError())
      return
    }
    const operation = {
      callback,
      lifetime: this._lifetime,
      settled: false,
      onFinish: null,
      onError: null,
      onClose: null
    }
    this._pendingFinal = operation
    this._runFinal(operation)
  }

  _predestroy() {
    if (this._terminal) return
    this._terminal = true
    this._lifetime++
    const visibleError = getStreamError(this)
    const graceful = visibleError === null && isEnded(this) && isFinished(this)
    let error = graceful
      ? null
      : visibleError === null
        ? destroyedError()
        : asError(visibleError, destroyedError)

    if (this._heldPlaintext !== null) {
      const held = this._heldPlaintext
      this._heldPlaintext = null
      try {
        this._recordAdapter._releasePlaintext(held, true)
      } catch (err) {
        error = asError(err, recordsUnavailableError)
      }
    }

    if (error === null && this._pendingRead !== null) error = recordsUnavailableError()
    if (error === null && this._pendingWrite !== null) error = recordsUnavailableError()
    if (error === null && this._pendingFinal !== null) error = recordsUnavailableError()

    if (this._pendingRead !== null) this._completeRead(this._pendingRead, error)
    if (this._pendingWrite !== null) this._completeWrite(this._pendingWrite, error)
    if (this._pendingFinal !== null) this._completeFinal(this._pendingFinal, error)

    if (error !== null) {
      this._recordAdapter.destroy(error)
      if (
        this._secretStream !== null &&
        !this._secretStream.destroying &&
        !this._secretStream.destroyed
      ) {
        try {
          this._secretStream.destroy(error)
        } catch {}
      }
    }
  }

  _destroy(callback) {
    let error = null
    if (!this._terminal) {
      this._terminal = true
      this._lifetime++
      if (this._heldPlaintext !== null) {
        const held = this._heldPlaintext
        this._heldPlaintext = null
        try {
          this._recordAdapter._releasePlaintext(held, true)
        } catch (err) {
          error = asError(err, recordsUnavailableError)
        }
      }
    }
    const recordAdapter = this._recordAdapter
    const secretStream = this._secretStream
    if (error !== null) {
      if (recordAdapter !== null) recordAdapter.destroy(error)
      if (secretStream !== null && !secretStream.destroying && !secretStream.destroyed) {
        try {
          secretStream.destroy(error)
        } catch {}
      }
    }
    if (recordAdapter !== null) recordAdapter._facadeClosed(this, secretStream)
    this._removeSecretListeners()
    this._recordAdapter = null
    this._secretStream = null
    callback(error)
  }

  async _runWrite(operation) {
    try {
      const opened = await this._secretStream.opened
      if (!this._operationActive(operation, this._pendingWrite)) return
      if (opened !== true) throw recordsUnavailableError()

      const adapterDrained = await this._recordAdapter.flush()
      if (!this._operationActive(operation, this._pendingWrite)) return
      if (adapterDrained === false) throw destroyedError()

      const data = operation.data
      this._secretStream.write(data)
      operation.data = null

      const flushed = await this._secretStream.flush()
      if (!this._operationActive(operation, this._pendingWrite)) return
      if (flushed === false) throw destroyedError()
      this._completeWrite(operation, null)
    } catch (err) {
      operation.data = null
      this._completeWrite(operation, asError(err, recordsUnavailableError))
    }
  }

  async _runFinal(operation) {
    try {
      const opened = await this._secretStream.opened
      if (!this._operationActive(operation, this._pendingFinal)) return
      if (opened !== true) throw recordsUnavailableError()

      const adapterDrained = await this._recordAdapter.flush()
      if (!this._operationActive(operation, this._pendingFinal)) return
      if (adapterDrained === false) throw destroyedError()

      if (isFinished(this._secretStream)) {
        this._secretFinished = true
        this._completeFinal(operation, null)
        return
      }

      operation.onFinish = () => this._completeFinal(operation, null)
      operation.onError = (err) =>
        this._completeFinal(operation, asError(err, recordsUnavailableError))
      operation.onClose = () => {
        if (!isFinished(this._secretStream)) {
          this._completeFinal(operation, destroyedError())
        }
      }
      this._secretStream.once('finish', operation.onFinish)
      this._secretStream.once('error', operation.onError)
      this._secretStream.once('close', operation.onClose)
      this._secretStream.end()
    } catch (err) {
      this._completeFinal(operation, asError(err, recordsUnavailableError))
    }
  }

  _pump() {
    if (this._pumping) {
      this._pumpAgain = true
      return
    }
    if (this._pendingRead === null || this._terminal) return

    this._pumping = true
    try {
      do {
        this._pumpAgain = false
        const operation = this._pendingRead
        if (operation === null || !this._operationActive(operation, this._pendingRead)) break

        let plain
        try {
          plain = this._secretStream.read()
        } catch (err) {
          this._completeRead(operation, asError(err, recordsUnavailableError))
          break
        }

        if (plain !== null) {
          let entry = null
          let error = null
          try {
            entry = this._recordAdapter._claimPlaintext(plain)
            this._heldPlaintext = entry
            this.push(plain)
          } catch (err) {
            error = asError(err, recordsUnavailableError)
            if (entry !== null) {
              this._heldPlaintext = null
              try {
                this._recordAdapter._releasePlaintext(entry, true)
              } catch (releaseError) {
                error = asError(releaseError, recordsUnavailableError)
              }
            }
          }
          if (error !== null) {
            this._completeRead(operation, error)
            break
          }
          if (!this._operationActive(operation, this._pendingRead)) {
            break
          }
          this._completeRead(operation, null)
          break
        }

        if (this._secretEnded) {
          try {
            this.push(null)
          } catch (err) {
            this._completeRead(operation, asError(err, recordsUnavailableError))
            break
          }
          if (!this._operationActive(operation, this._pendingRead)) {
            break
          }
          this._completeRead(operation, null)
          break
        }
      } while (this._pumpAgain && this._pendingRead !== null && !this._terminal)
    } finally {
      this._pumping = false
    }
  }

  _completeRead(operation, error) {
    if (operation.settled || this._pendingRead !== operation) return
    operation.settled = true
    this._pendingRead = null
    const callback = operation.callback
    operation.callback = null
    callback(error)
  }

  _completeWrite(operation, error) {
    if (operation.settled || this._pendingWrite !== operation) return
    operation.settled = true
    operation.data = null
    this._pendingWrite = null
    const callback = operation.callback
    operation.callback = null
    callback(error)
  }

  _completeFinal(operation, error) {
    if (operation.settled || this._pendingFinal !== operation) return
    operation.settled = true
    this._removeFinalListeners(operation)
    this._pendingFinal = null
    const callback = operation.callback
    operation.callback = null
    callback(error)
  }

  _operationActive(operation, current) {
    return (
      !operation.settled &&
      !this._terminal &&
      operation === current &&
      operation.lifetime === this._lifetime
    )
  }

  _removeFinalListeners(operation) {
    if (operation.onFinish !== null) {
      this._secretStream.removeListener('finish', operation.onFinish)
      operation.onFinish = null
    }
    if (operation.onError !== null) {
      this._secretStream.removeListener('error', operation.onError)
      operation.onError = null
    }
    if (operation.onClose !== null) {
      this._secretStream.removeListener('close', operation.onClose)
      operation.onClose = null
    }
  }

  _onSecretReadable() {
    this._pump()
  }

  _onSecretEnd() {
    this._secretEnded = true
    this._pump()
  }

  _onSecretFinish() {
    this._secretFinished = true
  }

  _onSecretError(error) {
    if (!this._terminal && !this.destroying && !this.destroyed) {
      this.destroy(asError(error, recordsUnavailableError))
    }
  }

  _onSecretClose(secretStream) {
    this._secretClosed = true
    if (
      !this._terminal &&
      !this.destroying &&
      !this.destroyed &&
      (!this._secretEnded || !this._secretFinished)
    ) {
      this.destroy(destroyedError())
    }
    this._removeSecretListeners(secretStream)
  }

  _removeSecretListeners(secretStream = this._secretStream) {
    if (secretStream === null) return
    secretStream.removeListener('readable', this._onSecretReadableBound)
    secretStream.removeListener('end', this._onSecretEndBound)
    secretStream.removeListener('finish', this._onSecretFinishBound)
    // Facade cleanup can precede native error/close delivery.
    if (this._secretClosed) {
      secretStream.removeListener('error', this._onSecretErrorBound)
      secretStream.removeListener('close', this._onSecretCloseBound)
    }
  }
}

function createPeerPlaintextDuplex(secretStream, recordAdapter) {
  if (!(recordAdapter instanceof PeerRecordAdapter)) throw invalidRoute()
  validateSecretStream(secretStream, recordAdapter)
  return new PeerPlaintextDuplex(secretStream, recordAdapter)
}

module.exports = {
  PeerRecordAdapter,
  createPeerPlaintextDuplex
}
