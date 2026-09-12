'use strict'

const b4a = require('b4a')
const SecretStream = require('@hyperswarm/secret-stream')
const { getStreamError, isEnded, isFinished } = require('streamx')
const NoiseWrap = require('../noise-wrap')
const { PrivateRouteError } = require('./errors')
const { PeerRecordAdapter, PeerPlaintextDuplex } = require('./peer-record-adapter')

const MAX_FRAGMENT_BYTES = 977
const MAX_RECORD_BYTES = 16777218
const PRIVATE_PROFILE = Object.freeze({
  error: 0,
  firewall: 0,
  secretStream: Object.freeze({ version: 1 })
})
const LEASE_METHODS = [
  'sendHandshake',
  'confirmHandshake',
  'trySendCiphertext',
  'finish',
  'reset',
  'revoke',
  'whenOpen',
  'finished',
  'diagnostics',
  'drain'
]

function invalid() {
  return PrivateRouteError.INVALID_ROUTE()
}

function authentication() {
  return PrivateRouteError.ERR_AUTHENTICATION()
}

function destroyed() {
  return PrivateRouteError.ERR_DESTROYED()
}

function clear(value) {
  if (b4a.isBuffer(value)) value.fill(0)
}

function deferred() {
  let resolve
  let reject
  const promise = new Promise((yes, no) => {
    resolve = yes
    reject = no
  })
  promise.catch(() => {})
  return { promise, resolve, reject }
}

function own(value, name) {
  if (value === null || typeof value !== 'object') throw invalid()
  const property = Object.getOwnPropertyDescriptor(value, name)
  if (!property || !Object.prototype.hasOwnProperty.call(property, 'value')) throw invalid()
  return property.value
}

function copyKey(value, length) {
  if (!b4a.isBuffer(value) || value.byteLength !== length) throw invalid()
  return b4a.from(value)
}

function privateProfile(payload) {
  return (
    payload.version === 1 &&
    payload.error === 0 &&
    payload.firewall === 0 &&
    payload.secretStream !== null &&
    payload.secretStream.version === 1 &&
    payload.udx === null &&
    payload.holepunch === null &&
    payload.relayThrough === null &&
    payload.addresses4.length === 0 &&
    payload.addresses6.length === 0 &&
    (payload.relayAddresses === null || payload.relayAddresses.length === 0)
  )
}

// NoiseWrap and secret-stream do not expose erasure APIs. These fields are the
// pinned dependencies' owned cryptographic buffers, never the caller's keypair.
function eraseNoise(noise) {
  if (!noise) return
  const handshake = noise.handshake
  if (handshake) {
    for (const name of [
      's',
      'e',
      'rs',
      're',
      'hash',
      'tx',
      'rx',
      'digest',
      'chainingKey',
      'key',
      'nonce'
    ]) {
      const value = handshake[name]
      clear(value)
      if (value && typeof value === 'object' && !b4a.isBuffer(value)) {
        clear(value.publicKey)
        clear(value.secretKey)
      }
    }
  }
  clear(noise.keyPair.publicKey)
  clear(noise.keyPair.secretKey)
  clear(noise.remotePublicKey)
}

function eraseBinding(binding) {
  if (!binding) return
  for (const name of [
    'publicKey',
    'remotePublicKey',
    'hash',
    'rx',
    'tx',
    'remoteId',
    'holepunchSecret'
  ])
    clear(binding[name])
}

function eraseSecret(secret) {
  if (!secret) return
  for (const name of ['_encrypt', '_decrypt']) {
    const state = secret[name]
    if (state) {
      clear(state.key)
      clear(state.state)
      clear(state.header)
      secret[name] = null
    }
  }
  for (const name of ['_sendState', '_outgoingWrapped', '_message', 'handshakeHash']) {
    clear(secret[name])
    secret[name] = null
  }
  secret._outgoingPlain = null
}

// No second plaintext buffer/queue: the existing facade retains the adapter's
// one in-place record until the application asks for its next record.
class EndpointDuplex extends PeerPlaintextDuplex {
  constructor(controller, secret, adapter) {
    super(secret, adapter)
    this._controller = controller
  }

  _final(callback) {
    super._final((error) => {
      if (error) return callback(error)
      this._controller._finish().then(() => callback(null), callback)
    })
  }

  _predestroy() {
    const error = getStreamError(this)
    const graceful = error === null && isEnded(this) && isFinished(this)
    this._controller._shutdown(graceful ? null : error || destroyed())
    super._predestroy()
  }

  _destroy(callback) {
    // Streamx's automatic graceful close enters _destroy without _predestroy.
    this._predestroy()
    super._destroy((error) => {
      this._controller._closed.promise.then(() => callback(error))
    })
  }
}

class PeerEndpointController {
  constructor(options) {
    const owner = own(options, 'owner')
    const session = own(options, 'session')
    const keyPair = own(options, 'keyPair')
    if (
      !owner ||
      typeof owner.diagnostics !== 'function' ||
      owner.diagnostics().status !== 'ACTIVE'
    )
      throw invalid()
    if (!session || typeof session.attachEndpoint !== 'function') throw invalid()
    const remote = Object.getOwnPropertyDescriptor(options, 'remotePublicKey')
    if (remote && !Object.prototype.hasOwnProperty.call(remote, 'value')) throw invalid()

    this._lease = null
    this._noise = null
    this._binding = null
    this._secret = null
    this._adapter = null
    this._outbound = null
    this._confirming = null
    this._finishPromise = null
    this._opened = deferred()
    this._closed = deferred()
    this._appClosed = deferred()
    this._aborted = deferred()
    this._rawFinished = deferred()
    this._finished = Promise.all([this._closed.promise, this._appClosed.promise]).then(() => {})
    this._remoteFin = false
    this._closing = false
    this._authenticated = false
    this._creditReady = false
    this._confirmed = false
    this._started = false
    this._receivedHandshake = false
    this._pumping = false
    this._pumpAgain = false
    this._inboundHeld = false
    this._outboundHeld = false
    this._isInitiator = !!(remote && remote.value)
    this.stream = null

    const local = { publicKey: null, secretKey: null }
    let expected = null
    try {
      local.publicKey = copyKey(own(keyPair, 'publicKey'), 32)
      local.secretKey = copyKey(own(keyPair, 'secretKey'), 64)
      expected = this._isInitiator ? copyKey(remote.value, 32) : null
      this._noise = new NoiseWrap(local, expected)
      const hooks = Object.freeze({
        onHandshake: (bytes) => this._onHandshake(bytes),
        onAuthenticatedOpen: () => {
          if (this._closing) return
          this._authenticated = true
          this._start()
        },
        onCiphertext: (bytes) => this._onCiphertext(bytes),
        onRemoteFin: () => this._onRemoteFin(),
        onReset: (error) => this._shutdown(error instanceof Error ? error : destroyed(), false),
        onWritable: () => this._pumpOutbound()
      })
      this._lease = session.attachEndpoint(hooks)
      for (const name of LEASE_METHODS) if (typeof this._lease[name] !== 'function') throw invalid()
      Promise.resolve(this._lease.whenOpen()).then(
        () => {
          if (this._closing) return
          this._creditReady = true
          this._start()
        },
        (error) => this._shutdown(error)
      )
      Promise.resolve(this._lease.finished()).then(
        () => {
          if (!this._closing && !(this._finishPromise && this._remoteFin))
            this._shutdown(destroyed(), false)
        },
        (error) => this._shutdown(error, false)
      )
      if (this._isInitiator) {
        const bytes = this._noise.send(PRIVATE_PROFILE)
        try {
          this._lease.sendHandshake(bytes)
        } finally {
          clear(bytes)
        }
      }
    } catch (error) {
      clear(local.publicKey)
      clear(local.secretKey)
      clear(expected)
      this._shutdown(error)
      throw error
    }
  }

  whenOpen() {
    return this._opened.promise
  }

  finished() {
    return this._finished
  }

  destroy(error = destroyed()) {
    this._shutdown(error)
    return this._finished
  }

  diagnostics() {
    return Object.freeze({
      status: this._closing ? 'CLOSED' : this._started ? 'OPEN' : 'AUTHENTICATING',
      authenticated: this._authenticated,
      creditReady: this._creditReady
    })
  }

  _onHandshake(bytes) {
    if (this._closing) return false
    let flight = null
    let confirming = null
    try {
      if (
        this._receivedHandshake ||
        !b4a.isBuffer(bytes) ||
        bytes.byteLength !== (this._isInitiator ? 53 : 101)
      )
        throw authentication()
      this._receivedHandshake = true
      // Noise's final() erases its remote-ephemeral view into the input flight.
      // Never lend it semantic-owned canonical/cache bytes.
      flight = b4a.from(bytes)
      if (!privateProfile(this._noise.recv(flight))) throw authentication()
      if (!this._isInitiator) {
        const reply = this._noise.send(PRIVATE_PROFILE)
        try {
          this._lease.sendHandshake(reply)
        } finally {
          clear(reply)
        }
      }
      if (this._closing) return false
      const final = this._noise.final()
      this._binding = {
        isInitiator: final.isInitiator,
        publicKey: b4a.from(final.publicKey),
        remotePublicKey: b4a.from(final.remotePublicKey),
        hash: b4a.from(final.hash),
        rx: b4a.from(final.rx),
        tx: b4a.from(final.tx)
      }
      clear(final.remoteId)
      clear(final.holepunchSecret)
      eraseNoise(this._noise)
      this._noise = null
      // Install the join before lending keys: confirmation may reset inline.
      confirming = deferred()
      this._confirming = confirming.promise
      confirming.resolve(this._lease.confirmHandshake(this._binding))
      this._confirming.then(
        () => {
          if (this._closing) return
          this._confirmed = true
          this._start()
        },
        (error) => this._shutdown(error)
      )
      return true
    } catch (error) {
      if (confirming) confirming.reject(error)
      this._shutdown(error)
      return false
    } finally {
      clear(flight)
    }
  }

  _start() {
    if (
      this._closing ||
      this._started ||
      !this._confirmed ||
      !this._authenticated ||
      !this._creditReady
    )
      return
    this._started = true
    try {
      this._adapter = new PeerRecordAdapter({
        onOutboundRecord: (record) => this._sendRecord(record),
        onInboundCapacity: () => {
          if (!this._closing) this._lease.drain()
        },
        onFailure: (error) => this._shutdown(error),
        defer: (callback) => {
          const timer = setImmediate(callback)
          return () => clearImmediate(timer)
        },
        acquireInbound: () => {
          if (this._inboundHeld) throw PrivateRouteError.ERR_PRIVATE_RECORDS_UNAVAILABLE()
          this._inboundHeld = true
        },
        releaseInbound: () => {
          this._inboundHeld = false
        },
        acquireOutbound: () => {
          if (this._outboundHeld) throw PrivateRouteError.ERR_PRIVATE_RECORDS_UNAVAILABLE()
          this._outboundHeld = true
        },
        releaseOutbound: () => {
          this._outboundHeld = false
        }
      })
      this._adapter.on('error', (error) => this._shutdown(error))
      this._adapter.once('finish', () => this._rawFinished.resolve())
      this._adapter.once('close', () => {
        if (!isFinished(this._adapter)) this._rawFinished.reject(destroyed())
      })
      this._secret = new SecretStream(this._isInitiator, this._adapter, {
        handshake: this._binding,
        enableSend: false
      })
      this._secret.on('error', (error) => this._shutdown(error))
      this.stream = new EndpointDuplex(this, this._secret, this._adapter)
      this.stream.on('error', () => {})
      this.stream.once('close', () => this._appClosed.resolve())
      this._secret.opened
        .then((opened) => {
          if (this._closing) return
          if (!opened) return this._shutdown(authentication())
          this._opened.resolve(this.stream)
          this._lease.drain()
        })
        .catch((error) => this._shutdown(error))
    } catch (error) {
      this._shutdown(error)
    }
  }

  _sendRecord(record) {
    if (this._closing) return Promise.reject(destroyed())
    if (this._outbound || record.byteLength > MAX_RECORD_BYTES) throw invalid()
    const pending = deferred()
    this._outbound = { record, offset: 0, ...pending }
    this._pumpOutbound()
    return pending.promise
  }

  _pumpOutbound() {
    if (this._closing || !this._started) return
    if (this._pumping) {
      this._pumpAgain = true
      return
    }
    this._pumping = true
    try {
      do {
        this._pumpAgain = false
        const pending = this._outbound
        if (!pending) break
        while (!this._closing && pending.offset < pending.record.byteLength) {
          const end = Math.min(pending.offset + MAX_FRAGMENT_BYTES, pending.record.byteLength)
          const accepted = this._lease.trySendCiphertext(
            pending.record.subarray(pending.offset, end)
          )
          if (accepted !== true && accepted !== false) throw invalid()
          if (this._closing) break
          if (!accepted) break
          pending.offset = end
        }
        if (!this._closing && pending.offset === pending.record.byteLength) {
          this._outbound = null
          clear(pending.record)
          pending.record = null
          pending.resolve()
        }
      } while (this._pumpAgain && !this._closing)
    } catch (error) {
      this._shutdown(error)
    } finally {
      this._pumping = false
    }
  }

  _onCiphertext(bytes) {
    if (this._closing) return 0
    if (!this._started) {
      this._shutdown(authentication())
      return 0
    }
    try {
      return this._adapter.consumeCiphertext(bytes)
    } catch (error) {
      this._shutdown(error)
      return 0
    }
  }

  _onRemoteFin() {
    if (this._closing) return
    try {
      if (!this._started || this._remoteFin) throw authentication()
      this._remoteFin = true
      this._adapter.endCiphertext()
    } catch (error) {
      this._shutdown(error)
    }
  }

  _finish() {
    if (!this._finishPromise) {
      this._finishPromise = Promise.race([
        (async () => {
          await this._rawFinished.promise
          if (this._closing) throw destroyed()
          await this._lease.finish()
        })(),
        this._aborted.promise
      ])
      this._finishPromise.catch((error) => this._shutdown(error))
    }
    return this._finishPromise
  }

  _shutdown(error, reset = true) {
    if (this._closing) return
    this._closing = true
    error = error === null ? null : error instanceof Error ? error : destroyed()
    const lease = this._lease
    // Publish terminal authority before revoke/reset can reenter user code.
    try {
      if (lease) lease.revoke(error)
    } catch (failure) {
      error = error || failure
    }
    if (error !== null && reset) {
      try {
        if (lease) lease.reset(error)
      } catch {}
    }
    this._opened.reject(error || destroyed())
    this._aborted.reject(error || destroyed())
    this._rawFinished.reject(error || destroyed())
    const pending = this._outbound
    this._outbound = null
    if (pending) {
      clear(pending.record)
      pending.record = null
      pending.reject(error || destroyed())
    }
    const streams = [this._secret, this._adapter]
    const closing = streams.filter(Boolean).map(
      (stream) =>
        new Promise((resolve) => {
          if (stream.destroyed) return resolve()
          stream.once('close', resolve)
          stream.destroy(error)
        })
    )
    if (this.stream) {
      if (!this.stream.destroying && !this.stream.destroyed) this.stream.destroy(error)
    } else {
      this._appClosed.resolve()
    }
    // A semantic verifier may still be borrowing the final keys. Revoke must
    // settle that borrow; erasure and the join wait until it has returned.
    closing.push(Promise.resolve(this._confirming).catch(() => {}))
    if (lease) {
      try {
        closing.push(Promise.resolve(lease.finished()).catch(() => {}))
      } catch {}
    }
    Promise.all(closing).then(() => {
      eraseNoise(this._noise)
      eraseBinding(this._binding)
      eraseSecret(this._secret)
      this._noise = this._binding = this._secret = this._adapter = this._lease = null
      this._closed.resolve()
    })
  }
}

function createPeerEndpointController(options) {
  return new PeerEndpointController(options)
}

module.exports = { createPeerEndpointController }
