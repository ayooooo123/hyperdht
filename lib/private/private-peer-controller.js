'use strict'

const { EventEmitter } = require('events')
const { Duplex } = require('streamx')
const b4a = require('b4a')
const sodium = require('sodium-universal')
const safetyCatch = require('safety-catch')
const NoiseSecretStream = require('@hyperswarm/secret-stream')
const HyperDHTAddress = require('hyperdht-address')
const { decode } = require('hypercore-id-encoding')

const { createKeyPair } = require('../crypto')
const Announcer = require('../announcer')
const { PrivateRouteError } = require('./errors')
const {
  DESCRIPTOR_BYTES,
  MAX_LIFETIME_MS,
  OverlayDescriptorService,
  RELAY_TARGET,
  decodeDescriptor,
  encodeDescriptor
} = require('./overlay-descriptor-service')

const OP_SESSION = 1
const OP_FORWARD = 2
const OP_PUBLISH = 3
const OP_TUNNEL = 4
const STATUS_OK = 0
const STATUS_UNAVAILABLE = 1
const CONTROL_TIMEOUT_MS = 15000
const READ_BUFFERS = new WeakMap()
const ROUTE_LIFETIME_MS = Math.min(MAX_LIFETIME_MS, 10 * 60 * 1000)
const ROUTE_CELL_BYTES = 1200
const ROUTE_CELL_PAYLOAD_BYTES = ROUTE_CELL_BYTES - 2

function unavailable() {
  return PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
}

function invalid() {
  return PrivateRouteError.INVALID_ROUTE()
}

function key(value) {
  return b4a.toString(value, 'hex')
}

function same(a, b) {
  return b4a.isBuffer(a) && b4a.isBuffer(b) && b4a.equals(a, b)
}

function peerKey(value) {
  const decoded = HyperDHTAddress.decode(b4a.isBuffer(value) ? value : decode(value))
  if (!decoded || !b4a.isBuffer(decoded.key) || decoded.key.byteLength !== 32) throw invalid()
  return b4a.from(decoded.key)
}

function opened(stream) {
  return new Promise((resolve, reject) => {
    let settled = false
    const timer = setTimeout(() => finish(unavailable()), CONTROL_TIMEOUT_MS)
    function finish(error) {
      if (settled) return
      settled = true
      clearTimeout(timer)
      stream.removeListener('error', onerror)
      if (error) reject(error)
      else resolve(stream)
    }
    function onerror(error) {
      finish(error)
    }
    stream.once('error', onerror)
    Promise.resolve(stream.opened).then(
      (ok) => finish(ok === false ? unavailable() : null),
      (error) => finish(error)
    )
  })
}

function readExactly(stream, size) {
  if (!Number.isSafeInteger(size) || size < 1) return Promise.reject(invalid())
  let state = READ_BUFFERS.get(stream)
  if (!state) {
    state = { buffered: null, reading: false }
    READ_BUFFERS.set(stream, state)
  }
  if (state.reading) return Promise.reject(invalid())
  state.reading = true
  return new Promise((resolve, reject) => {
    const output = b4a.allocUnsafe(size)
    let offset = 0
    let settled = false
    const timer = setTimeout(() => finish(unavailable()), CONTROL_TIMEOUT_MS)

    function cleanup() {
      clearTimeout(timer)
      state.reading = false
      stream.removeListener('readable', onreadable)
      stream.removeListener('error', onerror)
      stream.removeListener('end', onend)
      stream.removeListener('close', onclose)
    }
    function finish(error) {
      if (settled) return
      settled = true
      cleanup()
      if (error) reject(error)
      else resolve(output)
    }
    function onerror(error) {
      finish(error)
    }
    function onend() {
      finish(unavailable())
    }
    function onclose() {
      finish(unavailable())
    }
    function consume(chunk) {
      const remaining = size - offset
      const consumed = Math.min(remaining, chunk.byteLength)
      chunk.copy(output, offset, 0, consumed)
      offset += consumed
      state.buffered = consumed < chunk.byteLength ? b4a.from(chunk.subarray(consumed)) : null
    }
    function onreadable() {
      while (offset < size) {
        if (state.buffered !== null) {
          const buffered = state.buffered
          state.buffered = null
          consume(buffered)
          continue
        }
        const chunk = stream.read()
        if (chunk === null) return
        consume(chunk)
      }
      finish(null)
    }

    stream.on('readable', onreadable)
    stream.once('error', onerror)
    stream.once('end', onend)
    stream.once('close', onclose)
    onreadable()
  })
}

async function writeAll(stream, value) {
  if (stream.destroying || stream.destroyed) throw unavailable()
  if (stream.write(value)) return
  await new Promise((resolve, reject) => {
    function cleanup() {
      stream.removeListener('drain', ondrain)
      stream.removeListener('error', onerror)
      stream.removeListener('close', onclose)
    }
    function ondrain() {
      cleanup()
      resolve()
    }
    function onerror(error) {
      cleanup()
      reject(error)
    }
    function onclose() {
      cleanup()
      reject(unavailable())
    }
    stream.once('drain', ondrain)
    stream.once('error', onerror)
    stream.once('close', onclose)
  })
}

function joinStreams(left, right) {
  let closed = false
  function close(error) {
    if (closed) return
    closed = true
    if (!left.destroyed) left.destroy(error)
    if (!right.destroyed) right.destroy(error)
  }
  left.once('error', close)
  right.once('error', close)
  left.once('close', () => {
    if (!right.destroyed) right.destroy()
  })
  right.once('close', () => {
    if (!left.destroyed) left.destroy()
  })
  left.pipe(right)
  right.pipe(left)
}

class RouteCellStream extends Duplex {
  constructor(rawStream) {
    super()
    this.rawStream = rawStream
    this._incoming = b4a.alloc(0)
    this._ondata = (chunk) => this._receive(chunk)
    this._onend = () => {
      if (this._incoming.byteLength !== 0) this.destroy(invalid())
      else this.push(null)
    }
    this._onerror = (error) => this.destroy(error)
    this._onclose = () => {
      if (!this.destroyed) this.destroy()
    }
    rawStream.on('data', this._ondata)
    rawStream.once('end', this._onend)
    rawStream.once('error', this._onerror)
    rawStream.once('close', this._onclose)
  }

  _write(data, callback) {
    let offset = 0
    const pump = () => {
      try {
        while (offset < data.byteLength) {
          const length = Math.min(ROUTE_CELL_PAYLOAD_BYTES, data.byteLength - offset)
          const cell = b4a.allocUnsafe(ROUTE_CELL_BYTES)
          cell.writeUInt16BE(length, 0)
          data.copy(cell, 2, offset, offset + length)
          if (length < ROUTE_CELL_PAYLOAD_BYTES) sodium.randombytes_buf(cell.subarray(2 + length))
          offset += length
          if (!this.rawStream.write(cell)) {
            this.rawStream.once('drain', pump)
            return
          }
        }
        callback(null)
      } catch (error) {
        callback(error)
      }
    }
    pump()
  }

  _final(callback) {
    this.rawStream.end()
    callback(null)
  }

  _destroy(callback) {
    this.rawStream.removeListener('data', this._ondata)
    this.rawStream.removeListener('end', this._onend)
    this.rawStream.removeListener('error', this._onerror)
    this.rawStream.removeListener('close', this._onclose)
    this._incoming = b4a.alloc(0)
    if (!this.rawStream.destroyed) this.rawStream.destroy()
    callback(null)
  }

  _read() {
    this._drainIncoming()
  }

  _receive(chunk) {
    this._incoming =
      this._incoming.byteLength === 0 ? b4a.from(chunk) : b4a.concat([this._incoming, chunk])
    this._drainIncoming()
  }

  _drainIncoming() {
    while (this._incoming.byteLength >= ROUTE_CELL_BYTES) {
      const cell = this._incoming.subarray(0, ROUTE_CELL_BYTES)
      const length = cell.readUInt16BE(0)
      if (length < 1 || length > ROUTE_CELL_PAYLOAD_BYTES) {
        this.destroy(invalid())
        return
      }
      const payload = b4a.from(cell.subarray(2, 2 + length))
      this._incoming = b4a.from(this._incoming.subarray(ROUTE_CELL_BYTES))
      if (!this.push(payload)) return
    }
  }
}

class PrivatePeerServer extends EventEmitter {
  constructor(controller, options = {}) {
    super()
    this.controller = controller
    this.options = options || {}
    this.closed = false
    this.suspended = false
    this._listening = null
    this._closing = null
    this._keyPair = null
    this._transportServer = null
    this._descriptor = null
    this._entryRelayPublicKey = null
    this._seq = 0n
  }

  get listening() {
    return this._listening !== null && !this.closed
  }

  get publicKey() {
    return this._keyPair && this._keyPair.publicKey
  }

  get relayAddresses() {
    return []
  }

  address() {
    if (!this._keyPair) return null
    return { publicKey: this._keyPair.publicKey, host: null, port: 0 }
  }

  async listen(keyPair = this.controller.keyPair) {
    if (this._listening !== null) throw invalid()
    this._listening = this.controller._listen(this, keyPair)
    await this._listening
    return this
  }

  close() {
    if (this._closing) return this._closing
    this._closing = this.controller._closeServer(this)
    return this._closing
  }

  async suspend() {
    this.suspended = true
    if (this._transportServer) await this._transportServer.suspend()
  }

  async resume() {
    if (this.closed) return
    this.suspended = false
    if (this._transportServer) await this._transportServer.resume()
    await this.controller._publish(this)
  }

  refresh() {
    if (!this.closed && !this.suspended) void this.controller._publish(this).catch(safetyCatch)
  }

  notifyOnline() {
    this.refresh()
  }
}

class PrivatePeerController {
  constructor(options) {
    this.dht = options.dht
    this.keyPair = options.keyPair
    this.createDirectServer = options.createDirectServer
    this.connectDirect = options.connectDirect
    this.baseReady = options.baseReady
    this.relayKeyPair = createKeyPair()
    this.descriptors = new OverlayDescriptorService(this.dht, this.relayKeyPair.publicKey)
    this.relayServer = null
    this.relayAnnouncer = null
    this.servers = new Set()
    this.destroyed = false
    this.suspended = false
    this.state = 'BOOTSTRAPPING'
    this.directDestinationSends = 0
    this.directDestinationKeys = new Map()
    this._ready = this._start()
    this._ready.catch(() => {})
  }

  ready() {
    return this._ready
  }

  snapshot() {
    return Object.freeze({ state: this.state })
  }

  exposureReport() {
    return Object.freeze({
      overlayParticipation: 'direct',
      relayDiscovery: 'hyperdht-routing-table',
      descriptorOperations: 'safety-routed',
      peerPayload: 'noise-secretstream-end-to-end',
      directDestinationSends: this.directDestinationSends
    })
  }

  createServer(options, onconnection) {
    const server = new PrivatePeerServer(this, options)
    if (onconnection) server.on('connection', onconnection)
    return server
  }

  connect(remotePublicKey, options = {}) {
    const destinationPublicKey = peerKey(remotePublicKey)
    const destinationKey = key(destinationPublicKey)
    this.directDestinationKeys.set(
      destinationKey,
      (this.directDestinationKeys.get(destinationKey) || 0) + 1
    )
    const keyPair = options.keyPair || this.keyPair
    const createSecretStream = options.createSecretStream || defaultCreateSecretStream
    const stream = createSecretStream(true, null, {
      publicKey: keyPair.publicKey,
      remotePublicKey: destinationPublicKey,
      autoStart: false,
      keepAlive: this.dht.connectionKeepAlive
    })
    Promise.resolve()
      .then(async () => {
        const tunnel = await this._openSession(destinationPublicKey)
        if (stream.destroying || stream.destroyed) {
          tunnel.destroy()
          return
        }
        stream.start(new RouteCellStream(tunnel), {
          keyPair,
          remotePublicKey: destinationPublicKey
        })
      })
      .catch((error) => stream.destroy(error))
      .finally(() => {
        const active = this.directDestinationKeys.get(destinationKey)
        if (active === 1) this.directDestinationKeys.delete(destinationKey)
        else if (active > 1) this.directDestinationKeys.set(destinationKey, active - 1)
      })
    return stream
  }

  async suspend() {
    if (this.destroyed || this.suspended) return
    this.suspended = true
    this.state = 'SUSPENDED'
    if (this.relayAnnouncer) await this.relayAnnouncer.suspend()
  }

  async resume() {
    if (this.destroyed || !this.suspended) return
    this.suspended = false
    if (this.relayAnnouncer) this.relayAnnouncer.resume()
    this.state = 'READY'
    for (const server of this.servers) await this._publish(server)
  }

  async destroy() {
    if (this.destroyed) return
    this.destroyed = true
    this.state = 'DESTROYED'
    if (this.relayAnnouncer) await this.relayAnnouncer.stop()
    this.relayAnnouncer = null
    await Promise.allSettled(Array.from(this.servers, (server) => server.close()))
    this.servers.clear()
    if (this.relayServer) await this.relayServer.close()
    this.relayServer = null
  }

  async _start() {
    await this.baseReady()
    if (this.destroyed) throw unavailable()
    const relayServer = this.createDirectServer({ firewall: () => false })
    relayServer.on('connection', (stream) => this._onRelayConnection(stream))
    this.relayServer = relayServer
    await relayServer.listen(this.relayKeyPair)
    this.relayAnnouncer = new Announcer(this.dht, this.relayKeyPair, RELAY_TARGET)
    await this.relayAnnouncer.start()
    if (this.destroyed) throw unavailable()
    this.state = 'READY'
  }

  async _listen(server, keyPair) {
    await this.ready()
    if (this.destroyed || server.closed) throw unavailable()
    if (
      !keyPair ||
      !b4a.isBuffer(keyPair.publicKey) ||
      keyPair.publicKey.byteLength !== 32 ||
      !b4a.isBuffer(keyPair.secretKey) ||
      keyPair.secretKey.byteLength !== 64
    ) {
      throw invalid()
    }
    const transportKeyPair = createKeyPair()
    const transportServer = this.createDirectServer({ firewall: () => false })
    transportServer.on('connection', (stream) => this._onDestinationConnection(server, stream))
    await transportServer.listen(transportKeyPair)
    server._keyPair = keyPair
    server._transportServer = transportServer
    server._transportKeyPair = transportKeyPair
    this.servers.add(server)
    try {
      await this._publish(server)
    } catch (error) {
      this.servers.delete(server)
      await transportServer.close()
      server._transportServer = null
      server._transportKeyPair = null
      server._keyPair = null
      throw error
    }
  }

  async _closeServer(server) {
    if (server.closed) return
    server.closed = true
    this.servers.delete(server)
    if (server._transportServer) await server._transportServer.close()
    server._transportServer = null
    server._transportKeyPair = null
    server._descriptor = null
    server._entryRelayPublicKey = null
    server._keyPair = null
    server.emit('close')
  }

  async _publish(server) {
    if (this.destroyed || this.suspended || server.closed || !server._transportServer)
      throw unavailable()
    const relays = await this.descriptors.discoverRelays([this.relayKeyPair.publicKey])
    if (relays.length < 2) throw unavailable()
    const entryRelayPublicKey = relays[0]
    const publisherRelayPublicKey = relays.find(
      (candidate) => !same(candidate, entryRelayPublicKey)
    )
    if (!publisherRelayPublicKey) throw unavailable()
    const now = BigInt(Date.now())
    const descriptor = encodeDescriptor({
      destinationKeyPair: server._keyPair,
      transportPublicKey: server._transportKeyPair.publicKey,
      entryRelayPublicKey,
      seq: ++server._seq,
      expiresAt: now + BigInt(ROUTE_LIFETIME_MS)
    })
    const connection = await this._connectRelay(publisherRelayPublicKey)
    try {
      const request = b4a.allocUnsafe(1 + DESCRIPTOR_BYTES)
      request[0] = OP_PUBLISH
      descriptor.copy(request, 1)
      await writeAll(connection, request)
      const response = await readExactly(connection, 1)
      if (response[0] !== STATUS_OK) throw unavailable()
      server._descriptor = descriptor
      server._entryRelayPublicKey = b4a.from(entryRelayPublicKey)
    } finally {
      connection.end()
    }
  }

  async _openSession(destinationPublicKey) {
    await this.ready()
    if (this.destroyed || this.suspended) throw unavailable()
    const relays = await this.descriptors.discoverRelays([this.relayKeyPair.publicKey])
    for (const safetyRelayPublicKey of relays) {
      let connection = null
      try {
        connection = await this._connectRelay(safetyRelayPublicKey)
        const request = b4a.allocUnsafe(33)
        request[0] = OP_SESSION
        destinationPublicKey.copy(request, 1)
        await writeAll(connection, request)
        const response = await readExactly(connection, 1 + DESCRIPTOR_BYTES)
        if (response[0] !== STATUS_OK) throw unavailable()
        const descriptor = decodeDescriptor(response.subarray(1), {
          expectedDestinationPublicKey: destinationPublicKey
        })
        if (same(descriptor.entryRelayPublicKey, safetyRelayPublicKey)) throw unavailable()
        return connection
      } catch {
        if (connection && !connection.destroyed) connection.destroy()
      }
    }
    throw unavailable()
  }

  async _connectRelay(publicKey) {
    if (this.directDestinationKeys.has(key(publicKey))) {
      this.directDestinationSends++
      throw unavailable()
    }
    const stream = this.connectDirect(publicKey, { keyPair: createKeyPair() })
    stream.on('error', noop)
    await opened(stream)
    return stream
  }

  _onRelayConnection(stream) {
    stream.on('error', noop)
    this._handleRelayConnection(stream).catch(async () => {
      try {
        if (!stream.destroyed) await writeAll(stream, b4a.from([STATUS_UNAVAILABLE]))
      } catch {}
      stream.destroy()
    })
  }

  async _handleRelayConnection(stream) {
    const opcode = (await readExactly(stream, 1))[0]
    if (opcode === OP_SESSION) return this._handleSession(stream)
    if (opcode === OP_FORWARD) return this._handleForward(stream)
    if (opcode === OP_PUBLISH) return this._handlePublish(stream)
    throw invalid()
  }

  async _handlePublish(stream) {
    const wire = await readExactly(stream, DESCRIPTOR_BYTES)
    await this.descriptors.put(wire)
    await writeAll(stream, b4a.from([STATUS_OK]))
    stream.end()
  }

  async _handleSession(stream) {
    const destinationPublicKey = await readExactly(stream, 32)
    const descriptor = await this.descriptors.get(destinationPublicKey)
    if (same(descriptor.entryRelayPublicKey, this.relayKeyPair.publicKey)) throw unavailable()
    const next = await this._connectRelay(descriptor.entryRelayPublicKey)
    try {
      const request = b4a.allocUnsafe(1 + DESCRIPTOR_BYTES)
      request[0] = OP_FORWARD
      descriptor.wire.copy(request, 1)
      await writeAll(next, request)
      const status = await readExactly(next, 1)
      if (status[0] !== STATUS_OK) throw unavailable()
      const response = b4a.allocUnsafe(1 + DESCRIPTOR_BYTES)
      response[0] = STATUS_OK
      descriptor.wire.copy(response, 1)
      await writeAll(stream, response)
      joinStreams(stream, next)
    } catch (error) {
      next.destroy()
      throw error
    }
  }

  async _handleForward(stream) {
    const wire = await readExactly(stream, DESCRIPTOR_BYTES)
    const descriptor = decodeDescriptor(wire)
    if (!same(descriptor.entryRelayPublicKey, this.relayKeyPair.publicKey)) throw invalid()
    const destination = this.connectDirect(descriptor.transportPublicKey, {
      keyPair: createKeyPair()
    })
    try {
      await opened(destination)
      await writeAll(destination, b4a.from([OP_TUNNEL]))
      const status = await readExactly(destination, 1)
      if (status[0] !== STATUS_OK) throw unavailable()
      await writeAll(stream, b4a.from([STATUS_OK]))
      joinStreams(stream, destination)
    } catch (error) {
      destination.destroy()
      throw error
    }
  }

  _onDestinationConnection(server, stream) {
    stream.on('error', noop)
    Promise.resolve()
      .then(async () => {
        const opcode = (await readExactly(stream, 1))[0]
        if (opcode !== OP_TUNNEL || server.closed || server.suspended) throw unavailable()
        await writeAll(stream, b4a.from([STATUS_OK]))
        const cells = new RouteCellStream(stream)
        const createSecretStream = server.options.createSecretStream || defaultCreateSecretStream
        const encrypted = createSecretStream(false, cells, {
          keyPair: server._keyPair,
          keepAlive: this.dht.connectionKeepAlive
        })
        server.emit('connection', encrypted)
      })
      .catch((error) => stream.destroy(error))
  }
}

function defaultCreateSecretStream(isInitiator, rawStream, options) {
  return new NoiseSecretStream(isInitiator, rawStream, options)
}

function noop() {}

function createPrivatePeerController(options) {
  return new PrivatePeerController(options)
}

module.exports = { createPrivatePeerController }
