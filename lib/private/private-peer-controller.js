'use strict'

const { EventEmitter } = require('events')
const { Duplex, Writable } = require('streamx')
const b4a = require('b4a')
const sodium = require('sodium-universal')
const safetyCatch = require('safety-catch')
const NoiseSecretStream = require('@hyperswarm/secret-stream')
const HyperDHTAddress = require('hyperdht-address')
const { decode } = require('hypercore-id-encoding')

const { createKeyPair } = require('../crypto')
const Announcer = require('../announcer')
const { CellCodec, CELL_SIZE, MAX_CELL_PAYLOAD } = require('./cell-codec')
const { SenderCounter, OrderedReceiver, MAX_COUNTER } = require('./counters')
const { cryptoSuite } = require('./crypto-suite')
const { CELL_CLASS, DIRECTION } = require('./protocol')
const { PrivateRouteError } = require('./errors')
const { createPeerLedger, chargePeerLedger, releasePeerLedger } = require('./peer-ledger')
const {
  DESCRIPTOR_BYTES,
  MAX_LIFETIME_MS,
  OverlayDescriptorService,
  RELAY_TARGET,
  decodeDescriptor,
  encodeDescriptor
} = require('./overlay-descriptor-service')

const OP_PUBLISH = 1
const OP_RESOLVE = 2
const OP_BUILD_DESTINATION = 3
const OP_ENTRY_REGISTER = 4
const OP_BUILD_SOURCE = 5
const OP_ENTRY_ACTIVATE = 6
const OP_EXTEND_SOURCE = 7
const ENTRY_COMMIT = 0xa5
const STATUS_OK = 0
const STATUS_UNAVAILABLE = 1
const CONTROL_TIMEOUT_MS = 15000
const ROUTE_LIFETIME_MS = Math.min(MAX_LIFETIME_MS, 10 * 60 * 1000)
const ROUTE_CONTEXT_BYTES = 120
const RECOVERY_ABSENT = 0
const RECOVERY_PRESENT = 1
const DESTINATION_ADMISSION_CHALLENGE_BYTES = 32
const DESTINATION_ADMISSION_SIGNATURE_BYTES = 64
const DESTINATION_ADMISSION_IDENTITY_BYTES = 96
const DESTINATION_ADMISSION_DOMAIN = b4a.from('hyperdht/private-peer/destination-admission/v3')
const LOGICAL_HEADER_BYTES = 5
const MAX_LOGICAL_PAYLOAD = MAX_CELL_PAYLOAD - LOGICAL_HEADER_BYTES
const TEST_ONLY_PRIVATE_PEER_WRITE_ALL = Symbol('test-only-private-peer-write-all')
let testObserver = null
const LOGICAL_DATA = 0
const LOGICAL_OPEN = 1
const LOGICAL_FIN = 2
const LOGICAL_RESET = 3
const MAX_ROUTE_STREAMS = 64
const MAX_STREAM_BYTES = 64 * 1024 * 1024
const MAX_STREAM_DATA_FRAMES = Math.ceil(MAX_STREAM_BYTES / MAX_LOGICAL_PAYLOAD)
const MAX_ROUTE_CELLS = MAX_STREAM_DATA_FRAMES + 4 * MAX_ROUTE_STREAMS
const MAX_PENDING_CELLS = 64
const MAX_LINK_BUFFER_BYTES = CELL_SIZE * MAX_PENDING_CELLS
const READ_BUFFERS = new WeakMap()
const TEST_ONLY_PRIVATE_PEER_OBSERVER = Symbol('test-only-private-peer-observer')

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

function fixed(value, size) {
  return b4a.isBuffer(value) && value.byteLength === size
}

function random(size) {
  const value = b4a.allocUnsafe(size)
  sodium.randombytes_buf(value)
  return value
}
function destinationAdmissionInput(
  challenge,
  remotePublicKey,
  guardPublicKey,
  destinationPublicKey
) {
  if (
    !fixed(challenge, DESTINATION_ADMISSION_CHALLENGE_BYTES) ||
    !fixed(remotePublicKey, 32) ||
    !fixed(guardPublicKey, 32) ||
    !fixed(destinationPublicKey, 32)
  ) {
    throw invalid()
  }
  return b4a.concat([
    DESTINATION_ADMISSION_DOMAIN,
    challenge,
    remotePublicKey,
    guardPublicKey,
    destinationPublicKey
  ])
}

function signDestinationAdmission(destinationKeyPair, challenge, remotePublicKey, guardPublicKey) {
  const input = destinationAdmissionInput(
    challenge,
    remotePublicKey,
    guardPublicKey,
    destinationKeyPair.publicKey
  )
  const signature = b4a.allocUnsafe(DESTINATION_ADMISSION_SIGNATURE_BYTES)
  try {
    sodium.crypto_sign_detached(signature, input, destinationKeyPair.secretKey)
    return signature
  } finally {
    input.fill(0)
  }
}

function verifyDestinationAdmission(
  destinationPublicKey,
  signature,
  challenge,
  remotePublicKey,
  guardPublicKey
) {
  if (!fixed(signature, DESTINATION_ADMISSION_SIGNATURE_BYTES)) return false
  const input = destinationAdmissionInput(
    challenge,
    remotePublicKey,
    guardPublicKey,
    destinationPublicKey
  )
  try {
    return sodium.crypto_sign_verify_detached(signature, input, destinationPublicKey)
  } finally {
    input.fill(0)
  }
}

function readU32(buffer, offset = 0) {
  return buffer.readUInt32BE(offset)
}

function writeU32(buffer, value, offset = 0) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) throw invalid()
  buffer.writeUInt32BE(value, offset)
}

function readU64(buffer, offset = 0) {
  let value = 0n
  for (let i = offset; i < offset + 8; i++) value = (value << 8n) | BigInt(buffer[i])
  return value
}

function writeU64(buffer, value, offset = 0) {
  if (typeof value !== 'bigint' || value < 0n || value > 0xffffffffffffffffn) throw invalid()
  for (let i = offset + 7; i >= offset; i--) {
    buffer[i] = Number(value & 0xffn)
    value >>= 8n
  }
}

function peerKey(value) {
  const decoded = HyperDHTAddress.decode(b4a.isBuffer(value) ? value : decode(value))
  if (!decoded || !fixed(decoded.key, 32)) throw invalid()
  return b4a.from(decoded.key)
}

function observe(controller, event) {
  if (!controller.observer) return null
  try {
    return controller.observer(Object.freeze(event))
  } catch {
    return null
  }
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
      if (error) {
        output.fill(0)
        if (state.buffered) state.buffered.fill(0)
        state.buffered = null
        READ_BUFFERS.delete(stream)
        reject(error)
      } else {
        resolve(output)
      }
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
          buffered.fill(0)
          continue
        }
        const chunk = stream.read()
        if (chunk === null) return
        consume(chunk)
        chunk.fill(0)
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

function takeBuffered(stream) {
  const state = READ_BUFFERS.get(stream)
  if (!state || state.reading) throw invalid()
  const buffered = state.buffered
  state.buffered = null
  READ_BUFFERS.delete(stream)
  return buffered
}

async function writeAll(stream, value) {
  if (stream.destroying || stream.destroyed) throw unavailable()
  stream.write(value)
  if (!(await Writable.drained(stream))) throw unavailable()
}

function status(stream, value = STATUS_OK) {
  return writeAll(stream, b4a.from([value]))
}

function createRouteContext() {
  let epoch = BigInt(Date.now())
  epoch = (epoch << 16n) | BigInt(random(2).readUInt16BE(0))
  return {
    circuitId: random(16),
    epoch,
    forwardKey: random(32),
    forwardNonce: random(16),
    reverseKey: random(32),
    reverseNonce: random(16)
  }
}

function encodeRouteContext(context) {
  const wire = b4a.allocUnsafe(ROUTE_CONTEXT_BYTES)
  context.circuitId.copy(wire, 0)
  writeU64(wire, context.epoch, 16)
  context.forwardKey.copy(wire, 24)
  context.forwardNonce.copy(wire, 56)
  context.reverseKey.copy(wire, 72)
  context.reverseNonce.copy(wire, 104)
  return wire
}

function decodeRouteContext(wire) {
  if (!fixed(wire, ROUTE_CONTEXT_BYTES)) throw invalid()
  return {
    circuitId: b4a.from(wire.subarray(0, 16)),
    epoch: readU64(wire, 16),
    forwardKey: b4a.from(wire.subarray(24, 56)),
    forwardNonce: b4a.from(wire.subarray(56, 72)),
    reverseKey: b4a.from(wire.subarray(72, 104)),
    reverseNonce: b4a.from(wire.subarray(104, 120))
  }
}
function clearDescriptor(descriptor) {
  if (!descriptor || typeof descriptor !== 'object') return
  for (const value of Object.values(descriptor)) {
    if (b4a.isBuffer(value)) value.fill(0)
  }
}

function clearRouteContext(context) {
  if (!context) return
  for (const value of Object.values(context)) if (b4a.isBuffer(value)) value.fill(0)
}

function encodeLogical(streamId, flags, data = b4a.alloc(0)) {
  if (
    !Number.isSafeInteger(streamId) ||
    streamId < 0 ||
    streamId > 0xffffffff ||
    !Number.isSafeInteger(flags) ||
    flags < LOGICAL_DATA ||
    flags > LOGICAL_RESET ||
    !b4a.isBuffer(data) ||
    data.byteLength > MAX_LOGICAL_PAYLOAD ||
    (flags !== LOGICAL_DATA && data.byteLength !== 0)
  ) {
    throw invalid()
  }
  const frame = b4a.allocUnsafe(LOGICAL_HEADER_BYTES + data.byteLength)
  writeU32(frame, streamId)
  frame[4] = flags
  data.copy(frame, LOGICAL_HEADER_BYTES)
  return frame
}

function decodeLogical(frame) {
  if (!b4a.isBuffer(frame) || frame.byteLength < LOGICAL_HEADER_BYTES) throw invalid()
  const streamId = readU32(frame)
  const flags = frame[4]
  if (flags > LOGICAL_RESET || (flags !== LOGICAL_DATA && frame.byteLength !== 5)) throw invalid()
  return { streamId, flags, data: b4a.from(frame.subarray(LOGICAL_HEADER_BYTES)) }
}

class CircuitLink extends EventEmitter {
  constructor(controller, rawStream, context, initiator, label) {
    super()
    this.controller = controller
    this.rawStream = rawStream
    this.context = context
    this.initiator = initiator
    this.label = label
    this.codec = new CellCodec({ crypto: cryptoSuite, cellSize: CELL_SIZE })
    this.sender = new SenderCounter({ maximum: MAX_COUNTER })
    this.receiver = new OrderedReceiver({
      window: 64,
      gapTimeout: CONTROL_TIMEOUT_MS,
      now: Date.now,
      maximum: MAX_COUNTER
    })
    const allocation = {
      cells: MAX_ROUTE_CELLS,
      bytes: BigInt(MAX_ROUTE_CELLS * CELL_SIZE),
      commands: MAX_ROUTE_CELLS
    }
    this.sendLedger = createPeerLedger(allocation)
    this.receiveLedger = createPeerLedger(allocation)
    this.incoming = b4a.alloc(0)
    this.sending = Promise.resolve()
    this.pendingSends = 0
    this.destroyed = false
    this._ondata = (chunk) => this._receive(chunk)
    this._onend = () => this.destroy()
    this._onerror = (error) => this.destroy(error)
    this._onclose = () => this.destroy()
    rawStream.on('data', this._ondata)
    rawStream.once('end', this._onend)
    rawStream.once('error', this._onerror)
    rawStream.once('close', this._onclose)
    const buffered = takeBuffered(rawStream)
    if (buffered) {
      this._receive(buffered)
      buffered.fill(0)
    }
  }

  send(payload) {
    if (this.destroyed || this.pendingSends >= MAX_PENDING_CELLS) {
      const error = unavailable()
      this.destroy(error)
      return Promise.reject(error)
    }
    const context = this.context
    const direction = this.initiator ? DIRECTION.FORWARD : DIRECTION.REVERSE
    let cell
    try {
      chargePeerLedger(this.sendLedger, {
        cells: 1,
        bytes: BigInt(CELL_SIZE),
        commands: 1
      })
      cell = this.codec.seal({
        key: direction === DIRECTION.FORWARD ? context.forwardKey : context.reverseKey,
        noncePrefix: direction === DIRECTION.FORWARD ? context.forwardNonce : context.reverseNonce,
        senderCounter: this.sender,
        class: CELL_CLASS.STREAM,
        direction,
        epoch: context.epoch,
        circuitId: context.circuitId,
        payload
      })
    } catch (error) {
      this.destroy(error)
      return Promise.reject(error)
    }
    observe(this.controller, {
      type: 'route-cell-sealed',
      label: this.label,
      direction,
      plaintext: b4a.from(payload),
      cell: b4a.from(cell)
    })
    this.pendingSends++
    const sending = this.sending.then(() => writeAll(this.rawStream, cell))
    this.sending = sending.catch(() => {})
    sending
      .catch((error) => this.destroy(error))
      .finally(() => {
        this.pendingSends--
        cell.fill(0)
      })
    return sending
  }

  _receive(chunk) {
    if (this.destroyed) return
    if (
      !b4a.isBuffer(chunk) ||
      chunk.byteLength === 0 ||
      this.incoming.byteLength + chunk.byteLength > MAX_LINK_BUFFER_BYTES
    ) {
      this.destroy(unavailable())
      return
    }
    this.incoming =
      this.incoming.byteLength === 0 ? b4a.from(chunk) : b4a.concat([this.incoming, chunk])
    try {
      while (this.incoming.byteLength >= CELL_SIZE) {
        chargePeerLedger(this.receiveLedger, {
          cells: 1,
          bytes: BigInt(CELL_SIZE),
          commands: 1
        })
        const cell = b4a.from(this.incoming.subarray(0, CELL_SIZE))
        this.incoming = b4a.from(this.incoming.subarray(CELL_SIZE))
        const direction = this.initiator ? DIRECTION.REVERSE : DIRECTION.FORWARD
        const payloads = this.codec.open(
          {
            key:
              direction === DIRECTION.FORWARD ? this.context.forwardKey : this.context.reverseKey,
            noncePrefix:
              direction === DIRECTION.FORWARD
                ? this.context.forwardNonce
                : this.context.reverseNonce,
            expectedClass: CELL_CLASS.STREAM,
            expectedDirection: direction,
            expectedEpoch: this.context.epoch,
            expectedCircuitId: this.context.circuitId,
            receiver: this.receiver
          },
          cell
        )
        for (const payload of payloads) {
          observe(this.controller, {
            type: 'route-cell-opened',
            label: this.label,
            direction,
            plaintext: b4a.from(payload),
            cell
          })
          this.emit('payload', payload)
        }
      }
    } catch (error) {
      this.destroy(error)
    }
  }

  destroy(error) {
    if (this.destroyed) return false
    this.destroyed = true
    this.rawStream.removeListener('data', this._ondata)
    this.rawStream.removeListener('end', this._onend)
    this.rawStream.removeListener('error', this._onerror)
    this.rawStream.removeListener('close', this._onclose)
    this.sender.destroy()
    this.receiver.destroy()
    releasePeerLedger(this.sendLedger)
    releasePeerLedger(this.receiveLedger)
    this.incoming.fill(0)
    this.incoming = b4a.alloc(0)
    clearRouteContext(this.context)
    if (!this.rawStream.destroyed) this.rawStream.destroy(error)
    this.emit('close', error || null)
    return true
  }
}

function transformBridge(controller, left, right, onclose = null) {
  let closed = false
  let pendingForwards = 0
  const bridge = { destroy: close }
  function close(error) {
    if (closed) return
    closed = true
    controller.bridges.delete(bridge)
    if (onclose) onclose(bridge)
    left.destroy(error)
    right.destroy(error)
  }
  function forward(payload, from, to) {
    const pending = observe(controller, {
      type: 'route-transform',
      from: from.label,
      to: to.label,
      plaintext: b4a.from(payload)
    })
    if (pending && typeof pending.then === 'function') {
      pendingForwards++
      if (pendingForwards > MAX_PENDING_CELLS) {
        pendingForwards--
        payload.fill(0)
        close(unavailable())
        return
      }
      Promise.resolve(pending)
        .then(() => to.send(payload))
        .catch(close)
        .finally(() => {
          pendingForwards--
          payload.fill(0)
        })
      return
    }
    const sending = to.send(payload)
    payload.fill(0)
    sending.catch(close)
  }
  left.on('payload', (payload) => forward(payload, left, right))
  right.on('payload', (payload) => forward(payload, right, left))
  left.once('close', close)
  right.once('close', close)
  return bridge
}

class LogicalRouteStream extends Duplex {
  constructor(link, streamId, onclose) {
    super()
    this.link = link
    this.streamId = streamId
    this.onclose = onclose
    this.remoteEnded = false
    this.localEnded = false
    this.sentBytes = 0
    this.receivedBytes = 0
    this.sentFrames = 0
    this.receivedFrames = 0
    this.queuedBytes = 0
    this.queue = []
    this.remoteResetReceived = false
  }

  _write(data, callback) {
    if (this.localEnded || this.link.destroyed) return callback(unavailable())
    let offset = 0
    const send = async () => {
      while (offset < data.byteLength) {
        const length = Math.min(MAX_LOGICAL_PAYLOAD, data.byteLength - offset)
        this.sentBytes += length
        this.sentFrames++
        if (this.sentBytes > MAX_STREAM_BYTES || this.sentFrames > MAX_STREAM_DATA_FRAMES) {
          throw unavailable()
        }
        const frame = encodeLogical(
          this.streamId,
          LOGICAL_DATA,
          b4a.from(data.subarray(offset, offset + length))
        )
        offset += length
        try {
          await this.link.send(frame)
        } finally {
          frame.fill(0)
        }
      }
    }
    send().then(() => callback(null), callback)
  }

  _read() {
    this._drain()
  }

  _final(callback) {
    this.localEnded = true
    const frame = encodeLogical(this.streamId, LOGICAL_FIN)
    this.link.send(frame).then(
      () => {
        frame.fill(0)
        callback(null)
      },
      (error) => {
        frame.fill(0)
        callback(error)
      }
    )
  }

  _destroy(callback) {
    if (!this.localEnded && !this.remoteResetReceived && !this.link.destroyed) {
      const frame = encodeLogical(this.streamId, LOGICAL_RESET)
      this.link
        .send(frame)
        .catch(() => {})
        .finally(() => frame.fill(0))
    }
    for (const data of this.queue) data.fill(0)
    this.queue.length = 0
    this.queuedBytes = 0
    if (this.onclose) this.onclose(this)
    callback(null)
  }

  receive(data) {
    if (this.destroyed || this.remoteEnded) {
      data.fill(0)
      return
    }
    this.receivedBytes += data.byteLength
    this.receivedFrames++
    this.queuedBytes += data.byteLength
    if (
      this.receivedBytes > MAX_STREAM_BYTES ||
      this.receivedFrames > MAX_STREAM_DATA_FRAMES ||
      this.queuedBytes > MAX_STREAM_BYTES
    ) {
      data.fill(0)
      this.destroy(unavailable())
      return
    }
    this.queue.push(data)
    this._drain()
  }

  remoteFin() {
    if (this.remoteEnded) return
    this.remoteEnded = true
    this._drain()
  }

  _drain() {
    while (this.queue.length > 0) {
      const data = this.queue.shift()
      this.queuedBytes -= data.byteLength
      if (!this.push(data)) return
    }
    if (this.remoteEnded) this.push(null)
  }

  remoteReset() {
    if (this.destroyed) return
    this.remoteResetReceived = true
    this.destroy(unavailable())
  }
}

class DestinationCircuit {
  constructor(controller, server, rawStream, context, expiresAt) {
    this.controller = controller
    this.server = server
    this.link = new CircuitLink(controller, rawStream, context, true, 'destination-endpoint')
    this.streams = new Map()
    this.retiredStreams = new Set()
    this.acceptedStreams = 0
    this.lastStreamId = 0
    this.closed = false
    this.expiry = setTimeout(
      () => this.destroy(unavailable()),
      Math.max(1, Number(expiresAt - BigInt(Date.now())))
    )
    if (this.expiry.unref) this.expiry.unref()
    this.link.on('payload', (payload) => this._receive(payload))
    this.link.once('close', (error) => this.destroy(error || unavailable()))
  }

  _receive(payload) {
    let message
    try {
      message = decodeLogical(payload)
      if (message.streamId === 0) throw invalid()
      if (message.flags === LOGICAL_OPEN) return this._open(message.streamId)
      const stream = this.streams.get(message.streamId)
      if (this.retiredStreams.has(message.streamId)) return
      if (!stream) {
        if (message.flags === LOGICAL_FIN || message.flags === LOGICAL_RESET) return
        throw invalid()
      }
      if (message.flags === LOGICAL_DATA) stream.receive(message.data)
      else if (message.flags === LOGICAL_FIN) stream.remoteFin()
      else stream.remoteReset()
    } catch (error) {
      this.destroy(error)
    } finally {
      payload.fill(0)
    }
  }

  _open(streamId) {
    if (
      streamId % 2 !== 0 ||
      streamId <= this.lastStreamId ||
      this.streams.has(streamId) ||
      this.retiredStreams.has(streamId) ||
      this.acceptedStreams >= MAX_ROUTE_STREAMS
    ) {
      throw invalid()
    }
    this.lastStreamId = streamId
    this.acceptedStreams++
    const raw = new LogicalRouteStream(this.link, streamId, () => {
      if (this.streams.get(streamId) !== raw) return
      this.streams.delete(streamId)
      this.retiredStreams.add(streamId)
    })
    this.streams.set(streamId, raw)
    const createSecretStream = this.server.options.createSecretStream || defaultCreateSecretStream
    const encrypted = createSecretStream(false, raw, {
      keyPair: this.server._keyPair,
      keepAlive: this.controller.dht.connectionKeepAlive
    })
    const firewall = this.server.options.firewall
    if (typeof firewall !== 'function') {
      this.server.emit('connection', encrypted)
      return
    }
    encrypted.on('error', noop)
    void this._admit(encrypted, firewall)
  }

  async _admit(encrypted, firewall) {
    try {
      if ((await encrypted.opened) !== true) {
        encrypted.destroy()
        return
      }
      let firewalled = false
      try {
        firewalled = await firewall(encrypted.remotePublicKey, null, null)
      } catch (error) {
        safetyCatch(error)
      }
      if (firewalled || this.closed || this.server.closed || this.server.suspended) {
        encrypted.destroy()
        return
      }
      encrypted.removeListener('error', noop)
      this.server.emit('connection', encrypted)
    } catch {
      encrypted.destroy()
    }
  }

  destroy(error) {
    if (this.closed) return false
    this.closed = true
    clearTimeout(this.expiry)
    for (const stream of this.streams.values()) stream.destroy(error)
    this.streams.clear()
    this.retiredStreams.clear()
    this.link.destroy(error)
    if (this.server._route === this) this.server._route = null
    return true
  }
}

class EntryCircuit {
  constructor(controller, descriptor, stream, context) {
    this.controller = controller
    this.descriptor = descriptor
    this.link = new CircuitLink(controller, stream, context, false, 'entry-destination')
    this.sources = new Map()
    this.retiredSources = new Set()
    this.nextStreamId = 2
    this.acceptedStreams = 0
    this.closed = false
    this.expiry = setTimeout(
      () => this.destroy(unavailable()),
      Math.max(1, Number(descriptor.expiresAt - BigInt(Date.now())))
    )
    if (this.expiry.unref) this.expiry.unref()
    this.link.on('payload', (payload) => this._receive(payload))
    this.link.once('close', (error) => this.destroy(error || unavailable()))
  }

  activate(stream, context) {
    if (this.closed || this.acceptedStreams >= MAX_ROUTE_STREAMS) throw unavailable()
    const streamId = this.nextStreamId
    this.nextStreamId += 2
    this.acceptedStreams++
    const link = new CircuitLink(this.controller, stream, context, false, 'entry-source')
    const record = {
      streamId,
      link,
      sentBytes: 0,
      sentFrames: 0,
      receivedBytes: 0,
      receivedFrames: 0
    }
    this.sources.set(streamId, record)
    link.on('payload', (payload) => this._fromSource(record, payload))
    link.once('close', () => {
      if (this.sources.get(streamId) === record) {
        this.sources.delete(streamId)
        this.retiredSources.add(streamId)
      }
      const frame = encodeLogical(streamId, LOGICAL_RESET)
      this.link
        .send(frame)
        .catch(() => {})
        .finally(() => frame.fill(0))
    })
    const opened = encodeLogical(streamId, LOGICAL_OPEN)
    this.link
      .send(opened)
      .catch((error) => link.destroy(error))
      .finally(() => opened.fill(0))
    return streamId
  }

  _fromSource(record, payload) {
    let message
    try {
      message = decodeLogical(payload)
      if (message.streamId !== 0 || message.flags === LOGICAL_OPEN) throw invalid()
      if (message.flags === LOGICAL_DATA) {
        record.sentBytes += message.data.byteLength
        record.sentFrames++
        if (record.sentBytes > MAX_STREAM_BYTES || record.sentFrames > MAX_STREAM_DATA_FRAMES) {
          throw unavailable()
        }
      }
      const frame = encodeLogical(record.streamId, message.flags, message.data)
      this.link
        .send(frame)
        .catch((error) => record.link.destroy(error))
        .finally(() => frame.fill(0))
    } catch (error) {
      record.link.destroy(error)
    } finally {
      if (message) message.data.fill(0)
      payload.fill(0)
    }
  }

  _receive(payload) {
    let message
    try {
      message = decodeLogical(payload)
      const record = this.sources.get(message.streamId)
      if (this.retiredSources.has(message.streamId)) return
      if (!record) {
        if (message.flags === LOGICAL_FIN || message.flags === LOGICAL_RESET) return
        throw invalid()
      }
      if (message.flags === LOGICAL_OPEN) throw invalid()
      if (message.flags === LOGICAL_DATA) {
        record.receivedBytes += message.data.byteLength
        record.receivedFrames++
        if (
          record.receivedBytes > MAX_STREAM_BYTES ||
          record.receivedFrames > MAX_STREAM_DATA_FRAMES
        ) {
          throw unavailable()
        }
      }
      const frame = encodeLogical(0, message.flags, message.data)
      record.link
        .send(frame)
        .catch((error) => record.link.destroy(error))
        .finally(() => frame.fill(0))
    } catch (error) {
      this.destroy(error)
    } finally {
      if (message) message.data.fill(0)
      payload.fill(0)
    }
  }

  destroy(error) {
    if (this.closed) return false
    this.closed = true
    clearTimeout(this.expiry)
    for (const record of this.sources.values()) record.link.destroy(error)
    this.sources.clear()
    this.retiredSources.clear()
    this.link.destroy(error)
    clearDescriptor(this.descriptor)
    this.descriptor = null
    return true
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
    this._descriptor = null
    this._route = null
    this._publishing = null
    this._refreshTimer = null
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
    this.controller._clearServerRoute(this)
  }

  async resume() {
    if (this.closed) return
    this.suspended = false
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
    this.profile = options.profile
    this.keyPair = options.keyPair
    this.relay = options.relay === true
    this.createDirectServer = options.createDirectServer
    this.connectDirect = options.connectDirect
    this.baseReady = options.baseReady
    this.observer = options[TEST_ONLY_PRIVATE_PEER_OBSERVER] || testObserver
    if (this.observer !== null && typeof this.observer !== 'function') throw invalid()
    this.relayKeyPair = this.relay ? createKeyPair() : null
    this.descriptors = new OverlayDescriptorService(
      this.dht,
      this.relayKeyPair ? this.relayKeyPair.publicKey : null
    )
    this.relayServer = null
    this.relayAnnouncer = null
    this.servers = new Set()
    this.entryCircuits = new Map()
    this.pendingEntryRegistrations = new Map()
    this.lastSequences = new Map()
    this.destinationBridges = new Set()
    this.destinationRoleReservations = new Set()
    this.resolverStreams = new Set()
    this.bridges = new Set()
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
    return Object.freeze({
      state: this.state,
      profile: this.profile,
      relay: this.relay,
      entryCircuits: this.entryCircuits.size,
      pendingEntryRegistrations: this.pendingEntryRegistrations.size,
      bridges: this.bridges.size,
      destinationBridges: this.destinationBridges.size,
      resolverStreams: this.resolverStreams.size
    })
  }

  exposureReport() {
    return Object.freeze({
      overlayParticipation: 'direct-compatible',
      relayService: this.relay ? 'explicit' : 'disabled',
      relayDiscovery: 'hyperdht-routing-table',
      privacyProfile: this.profile,
      safetyRelays: 2,
      privateRelays: 2,
      descriptorAddressing: 'period-blinded',
      descriptorIdentity: 'rotating-blinded-key',
      descriptorState: 'destination-signed-quorum-readback',
      descriptorOperations: 'source-safety-routed',
      peerPayload: 'bounded-m3-hop-transformed-noise-secretstream',
      directDestinationSends: this.directDestinationSends
    })
  }

  createServer(options, onconnection) {
    if (this.relay) throw unavailable()
    const server = new PrivatePeerServer(this, options)
    if (onconnection) server.on('connection', onconnection)
    return server
  }

  connect(remotePublicKey, options = {}) {
    if (this.relay) throw unavailable()
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
        const route = await this._openSession(destinationPublicKey)
        if (stream.destroying || stream.destroyed) {
          route.destroy()
          return
        }
        stream.start(route, { keyPair, remotePublicKey: destinationPublicKey })
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
    for (const server of this.servers) this._clearServerRoute(server)
    for (const entry of this.entryCircuits.values()) entry.destroy(unavailable())
    this.entryCircuits.clear()
    for (const stream of this.pendingEntryRegistrations.values()) stream.destroy(unavailable())
    this.pendingEntryRegistrations.clear()
    for (const stream of this.resolverStreams) stream.destroy(unavailable())
    this.resolverStreams.clear()
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
    for (const entry of this.entryCircuits.values()) entry.destroy(unavailable())
    this.entryCircuits.clear()
    for (const stream of this.pendingEntryRegistrations.values()) stream.destroy(unavailable())
    this.pendingEntryRegistrations.clear()
    for (const bridge of this.bridges) bridge.destroy(unavailable())
    this.bridges.clear()
    this.destinationBridges.clear()
    this.destinationRoleReservations.clear()
    for (const stream of this.resolverStreams) stream.destroy(unavailable())
    this.resolverStreams.clear()
    if (this.relayServer) await this.relayServer.close()
    this.relayServer = null
    if (this.relayKeyPair) {
      this.relayKeyPair.publicKey.fill(0)
      this.relayKeyPair.secretKey.fill(0)
      this.relayKeyPair = null
    }
    this.directDestinationKeys.clear()
  }

  async _start() {
    await this.baseReady()
    if (this.destroyed) throw unavailable()
    if (this.relay) {
      const relayServer = this.createDirectServer({ firewall: () => false })
      relayServer.on('connection', (stream) => this._onRelayConnection(stream))
      this.relayServer = relayServer
      await relayServer.listen(this.relayKeyPair)
      this.relayAnnouncer = new Announcer(this.dht, this.relayKeyPair, RELAY_TARGET)
      await this.relayAnnouncer.start()
    }
    if (this.destroyed) throw unavailable()
    this.state = 'READY'
  }

  async _listen(server, keyPair) {
    await this.ready()
    if (this.destroyed || this.suspended || server.closed || this.relay) throw unavailable()
    if (!keyPair || !fixed(keyPair.publicKey, 32) || !fixed(keyPair.secretKey, 64)) {
      throw invalid()
    }
    server._keyPair = keyPair
    this.servers.add(server)
    try {
      await this._publish(server)
    } catch (error) {
      this.servers.delete(server)
      this._clearServerRoute(server)
      server._keyPair = null
      throw error
    }
  }

  async _closeServer(server) {
    if (server.closed) return
    server.closed = true
    this.servers.delete(server)
    this._clearServerRoute(server)
    if (server._publishing) await Promise.allSettled([server._publishing])
    if (server._descriptor) server._descriptor.fill(0)
    server._descriptor = null
    server._keyPair = null
    server.emit('close')
  }

  _clearServerRoute(server) {
    clearTimeout(server._refreshTimer)
    server._refreshTimer = null
    const route = server._route
    server._route = null
    if (route) route.destroy(unavailable())
  }

  async _publish(server) {
    if (server._publishing) return server._publishing
    const publishing = this._publishNow(server)
    server._publishing = publishing
    try {
      return await publishing
    } finally {
      if (server._publishing === publishing) server._publishing = null
    }
  }

  _nextDescriptorSequence(server, remote) {
    const id = key(server._keyPair.publicKey)
    let previous = this.lastSequences.get(id) || server._seq
    if (remote && remote.seq > previous) previous = remote.seq
    if (previous === 0xffffffffffffffffn) throw unavailable()
    const next = previous + 1n
    this.lastSequences.set(id, next)
    server._seq = next
    return next
  }

  async _publishNow(server) {
    if (this.destroyed || this.suspended || server.closed || server.suspended || !server._keyPair) {
      throw unavailable()
    }
    const relays = shuffle(await this.descriptors.discoverRelays())
    if (this.observer) {
      const preferred = observe(this, {
        type: 'destination-relay-candidates',
        relays: Object.freeze(relays.map((relay) => b4a.from(relay)))
      })
      if (fixed(preferred, 32)) {
        const index = relays.findIndex((relay) => same(relay, preferred))
        if (index > 0) [relays[0], relays[index]] = [relays[index], relays[0]]
      }
    }
    if (relays.length < 2) throw unavailable()
    const destinationGuardPublicKey = relays[0]
    const entryRelayPublicKey = relays.find(
      (candidate) => !same(candidate, destinationGuardPublicKey)
    )
    if (!entryRelayPublicKey) throw unavailable()
    const routeToken = random(32)
    const localContext = createRouteContext()
    const downstreamContext = createRouteContext()
    const admissionKeyPair = createKeyPair()
    let connection = null
    let descriptor = null
    try {
      connection = await this._connectRelay(destinationGuardPublicKey, admissionKeyPair)
      await writeAll(connection, b4a.from([OP_BUILD_DESTINATION]))
      if ((await readExactly(connection, 1))[0] !== STATUS_OK) throw unavailable()
      const challenge = await readExactly(connection, DESTINATION_ADMISSION_CHALLENGE_BYTES)
      const proof = signDestinationAdmission(
        server._keyPair,
        challenge,
        admissionKeyPair.publicKey,
        destinationGuardPublicKey
      )
      const identity = b4a.concat([server._keyPair.publicKey, proof])
      try {
        observe(this, {
          type: 'destination-identity-sent',
          guardPublicKey: b4a.from(destinationGuardPublicKey),
          destinationPublicKey: b4a.from(server._keyPair.publicKey)
        })
        await writeAll(connection, identity)
      } finally {
        challenge.fill(0)
        proof.fill(0)
        identity.fill(0)
      }
      const recovery = await readExactly(connection, 2)
      if (recovery[0] !== STATUS_OK) throw unavailable()
      let previous = null
      if (recovery[1] === RECOVERY_PRESENT) {
        previous = decodeDescriptor(await readExactly(connection, DESCRIPTOR_BYTES), {
          expectedDestinationPublicKey: server._keyPair.publicKey
        })
      } else if (recovery[1] !== RECOVERY_ABSENT) {
        throw invalid()
      }
      let seq
      try {
        seq = this._nextDescriptorSequence(server, previous)
      } finally {
        clearDescriptor(previous)
      }
      const now = BigInt(Date.now())
      const expiresAt = now + BigInt(ROUTE_LIFETIME_MS)
      descriptor = encodeDescriptor({
        destinationKeyPair: server._keyPair,
        entryRelayPublicKey,
        destinationGuardPublicKey,
        routeToken,
        seq,
        expiresAt
      })
      const request = b4a.concat([
        descriptor,
        encodeRouteContext(localContext),
        encodeRouteContext(downstreamContext)
      ])
      await writeAll(connection, request)
      const response = await readExactly(connection, 1)
      if (response[0] !== STATUS_OK) throw unavailable()
      if (this.destroyed || this.suspended || server.closed || server.suspended) throw unavailable()
      this._clearServerRoute(server)
      if (server._descriptor) server._descriptor.fill(0)
      server._descriptor = b4a.from(descriptor)
      server._route = new DestinationCircuit(this, server, connection, localContext, expiresAt)
      connection = null
      clearRouteContext(downstreamContext)
      server._refreshTimer = setTimeout(
        () => {
          if (!server.closed && !server.suspended) void this._publish(server).catch(safetyCatch)
        },
        Math.floor(ROUTE_LIFETIME_MS / 2)
      )
      if (server._refreshTimer.unref) server._refreshTimer.unref()
    } finally {
      routeToken.fill(0)
      admissionKeyPair.publicKey.fill(0)
      admissionKeyPair.secretKey.fill(0)
      if (descriptor) descriptor.fill(0)
      if (connection && !connection.destroyed) connection.destroy()
      if (connection) clearRouteContext(localContext)
      clearRouteContext(downstreamContext)
    }
  }

  async _resolveThrough(safetyRelayPublicKey, destinationPublicKey) {
    const connection = await this._connectRelay(safetyRelayPublicKey)
    let response = null
    try {
      await writeAll(connection, b4a.from([OP_RESOLVE]))
      if ((await readExactly(connection, 1))[0] !== STATUS_OK) throw unavailable()
      await writeAll(connection, destinationPublicKey)
      response = await readExactly(connection, 1 + DESCRIPTOR_BYTES)
      if (response[0] !== STATUS_OK) throw unavailable()
      return decodeDescriptor(response.subarray(1), {
        expectedDestinationPublicKey: destinationPublicKey
      })
    } finally {
      if (response) response.fill(0)
      connection.end()
    }
  }

  async _openSession(destinationPublicKey) {
    await this.ready()
    if (this.destroyed || this.suspended || this.relay) throw unavailable()
    const relays = shuffle(await this.descriptors.discoverRelays())
    for (const firstSafetyRelayPublicKey of relays) {
      let connection = null
      let localContext = null
      let middleContext = null
      let entryContext = null
      let descriptor = null
      let request = null
      try {
        descriptor = await this._resolveThrough(firstSafetyRelayPublicKey, destinationPublicKey)
        if (
          same(firstSafetyRelayPublicKey, descriptor.entryRelayPublicKey) ||
          same(firstSafetyRelayPublicKey, descriptor.destinationGuardPublicKey)
        ) {
          continue
        }
        const secondSafetyRelayPublicKey = relays.find(
          (candidate) =>
            !same(candidate, firstSafetyRelayPublicKey) &&
            !same(candidate, descriptor.entryRelayPublicKey) &&
            !same(candidate, descriptor.destinationGuardPublicKey)
        )
        if (!secondSafetyRelayPublicKey) continue
        observe(this, {
          type: 'source-route-selected',
          firstSafetyRelayPublicKey: b4a.from(firstSafetyRelayPublicKey),
          secondSafetyRelayPublicKey: b4a.from(secondSafetyRelayPublicKey),
          entryRelayPublicKey: b4a.from(descriptor.entryRelayPublicKey),
          destinationGuardPublicKey: b4a.from(descriptor.destinationGuardPublicKey)
        })
        connection = await this._connectRelay(firstSafetyRelayPublicKey)
        localContext = createRouteContext()
        middleContext = createRouteContext()
        entryContext = createRouteContext()
        request = b4a.concat([
          b4a.from([OP_BUILD_SOURCE]),
          descriptor.wire,
          secondSafetyRelayPublicKey,
          encodeRouteContext(localContext),
          encodeRouteContext(middleContext),
          encodeRouteContext(entryContext)
        ])
        await writeAll(connection, request)
        const response = await readExactly(connection, 1)
        if (response[0] !== STATUS_OK) throw unavailable()
        const link = new CircuitLink(this, connection, localContext, true, 'source-endpoint')
        const route = new LogicalRouteStream(link, 0, () => link.destroy())
        link.on('payload', (payload) => {
          try {
            const message = decodeLogical(payload)
            if (message.streamId !== 0 || message.flags === LOGICAL_OPEN) throw invalid()
            if (message.flags === LOGICAL_DATA) route.receive(message.data)
            else if (message.flags === LOGICAL_FIN) route.remoteFin()
            else route.remoteReset()
          } catch (error) {
            route.destroy(error)
          } finally {
            payload.fill(0)
          }
        })
        link.once('close', (error) => {
          if (!route.destroyed) route.destroy(error || unavailable())
        })
        connection = null
        localContext = null
        clearRouteContext(middleContext)
        clearRouteContext(entryContext)
        return route
      } catch {
        if (connection && !connection.destroyed) connection.destroy()
        clearRouteContext(localContext)
        clearRouteContext(middleContext)
        clearRouteContext(entryContext)
      } finally {
        if (request) request.fill(0)
        clearDescriptor(descriptor)
      }
    }
    throw unavailable()
  }

  async _connectRelay(publicKey, keyPair = createKeyPair()) {
    if (this.directDestinationKeys.has(key(publicKey))) {
      this.directDestinationSends++
      throw unavailable()
    }
    const stream = this.connectDirect(publicKey, { keyPair })
    stream.on('error', noop)
    await opened(stream)
    return stream
  }

  _onRelayConnection(stream) {
    stream.on('error', noop)
    this._handleRelayConnection(stream).catch(async () => {
      try {
        if (stream.destroyed) return
        await status(stream, STATUS_UNAVAILABLE)
        stream.end()
      } catch {
        stream.destroy()
      }
    })
  }

  async _handleRelayConnection(stream) {
    if (!this.relay || this.destroyed || this.suspended) throw unavailable()
    const opcode = (await readExactly(stream, 1))[0]
    if (opcode === OP_PUBLISH) return this._handlePublish(stream)
    if (opcode === OP_RESOLVE) return this._handleResolve(stream)
    if (opcode === OP_BUILD_DESTINATION) return this._handleBuildDestination(stream)
    if (opcode === OP_ENTRY_REGISTER) return this._handleEntryRegister(stream)
    if (opcode === OP_BUILD_SOURCE) return this._handleBuildSource(stream)
    if (opcode === OP_EXTEND_SOURCE) return this._handleExtendSource(stream)
    if (opcode === OP_ENTRY_ACTIVATE) return this._handleEntryActivate(stream)
    throw invalid()
  }

  async _handlePublish(stream) {
    const descriptor = decodeDescriptor(await readExactly(stream, DESCRIPTOR_BYTES))
    try {
      await this.descriptors.put(descriptor.wire)
      await status(stream)
      stream.end()
    } finally {
      clearDescriptor(descriptor)
    }
  }

  async _handleResolve(stream) {
    if (
      this.entryCircuits.size > 0 ||
      this.pendingEntryRegistrations.size > 0 ||
      this.destinationBridges.size > 0 ||
      this.destinationRoleReservations.size > 0
    ) {
      await status(stream, STATUS_UNAVAILABLE)
      stream.end()
      return
    }
    this.resolverStreams.add(stream)
    let descriptor = null
    let response = null
    try {
      await status(stream)
      const destinationPublicKey = await readExactly(stream, 32)
      descriptor = await this.descriptors.get(destinationPublicKey)
      response = b4a.allocUnsafe(1 + DESCRIPTOR_BYTES)
      response[0] = STATUS_OK
      descriptor.wire.copy(response, 1)
      await writeAll(stream, response)
      stream.end()
    } finally {
      if (response) response.fill(0)
      clearDescriptor(descriptor)
      this.resolverStreams.delete(stream)
      observe(this, {
        type: 'resolver-released',
        guardPublicKey: b4a.from(this.relayKeyPair.publicKey)
      })
    }
  }

  async _handleBuildDestination(stream) {
    observe(this, {
      type: 'destination-admission-attempt',
      guardPublicKey: b4a.from(this.relayKeyPair.publicKey),
      remotePublicKey: b4a.from(stream.remotePublicKey)
    })
    if (this.resolverStreams.size > 0) throw unavailable()
    this.destinationRoleReservations.add(stream)
    const challenge = random(DESTINATION_ADMISSION_CHALLENGE_BYTES)
    let localContext = null
    let downstreamContext = null
    let next = null
    let descriptor = null
    let previous = null
    let recovery = null
    let request = null
    try {
      await writeAll(stream, b4a.concat([b4a.from([STATUS_OK]), challenge]))
      const identity = await readExactly(stream, DESTINATION_ADMISSION_IDENTITY_BYTES)
      const destinationPublicKey = b4a.from(identity.subarray(0, 32))
      const signature = identity.subarray(32)
      const admitted = verifyDestinationAdmission(
        destinationPublicKey,
        signature,
        challenge,
        stream.remotePublicKey,
        this.relayKeyPair.publicKey
      )
      identity.fill(0)
      if (!admitted) throw invalid()
      observe(this, {
        type: 'destination-identity-received',
        guardPublicKey: b4a.from(this.relayKeyPair.publicKey),
        destinationPublicKey: b4a.from(destinationPublicKey)
      })

      try {
        previous = await this.descriptors.get(destinationPublicKey)
      } catch {}
      recovery = b4a.allocUnsafe(2 + (previous ? DESCRIPTOR_BYTES : 0))
      recovery[0] = STATUS_OK
      recovery[1] = previous ? RECOVERY_PRESENT : RECOVERY_ABSENT
      if (previous) previous.wire.copy(recovery, 2)
      await writeAll(stream, recovery)

      descriptor = decodeDescriptor(await readExactly(stream, DESCRIPTOR_BYTES), {
        expectedDestinationPublicKey: destinationPublicKey
      })
      if (!same(descriptor.destinationGuardPublicKey, this.relayKeyPair.publicKey)) throw invalid()
      localContext = decodeRouteContext(await readExactly(stream, ROUTE_CONTEXT_BYTES))
      downstreamContext = decodeRouteContext(await readExactly(stream, ROUTE_CONTEXT_BYTES))
      next = await this._connectRelay(descriptor.entryRelayPublicKey, this.relayKeyPair)
      request = b4a.concat([
        b4a.from([OP_ENTRY_REGISTER]),
        descriptor.wire,
        encodeRouteContext(downstreamContext)
      ])
      await writeAll(next, request)
      if ((await readExactly(next, 1))[0] !== STATUS_OK) throw unavailable()
      await this.descriptors.put(descriptor.wire)
      const commitGate = observe(this, {
        type: 'entry-commit-pending',
        entryRelayPublicKey: b4a.from(descriptor.entryRelayPublicKey),
        destinationGuardPublicKey: b4a.from(descriptor.destinationGuardPublicKey)
      })
      if (commitGate && typeof commitGate.then === 'function') await commitGate
      await writeAll(next, b4a.from([ENTRY_COMMIT]))
      if ((await readExactly(next, 1))[0] !== STATUS_OK) throw unavailable()
      await status(stream)
      const left = new CircuitLink(this, stream, localContext, false, 'guard-destination')
      const right = new CircuitLink(this, next, downstreamContext, true, 'guard-entry')
      const bridge = transformBridge(this, left, right, (closed) =>
        this.destinationBridges.delete(closed)
      )
      this.bridges.add(bridge)
      this.destinationBridges.add(bridge)
    } catch (error) {
      clearRouteContext(localContext)
      clearRouteContext(downstreamContext)
      if (next) next.destroy()
      throw error
    } finally {
      challenge.fill(0)
      if (request) request.fill(0)
      if (recovery) recovery.fill(0)
      clearDescriptor(previous)
      clearDescriptor(descriptor)
      this.destinationRoleReservations.delete(stream)
    }
  }

  async _handleEntryRegister(stream) {
    let descriptor = null
    let context = null
    let token = null
    try {
      descriptor = decodeDescriptor(await readExactly(stream, DESCRIPTOR_BYTES))
      if (!same(descriptor.entryRelayPublicKey, this.relayKeyPair.publicKey)) throw invalid()
      if (!same(stream.remotePublicKey, descriptor.destinationGuardPublicKey)) throw invalid()
      context = decodeRouteContext(await readExactly(stream, ROUTE_CONTEXT_BYTES))
      if (this.resolverStreams.size > 0) throw unavailable()
      token = key(descriptor.routeToken)
      if (this.entryCircuits.has(token) || this.pendingEntryRegistrations.has(token)) {
        throw invalid()
      }
      this.pendingEntryRegistrations.set(token, stream)
      await status(stream)
      if ((await readExactly(stream, 1))[0] !== ENTRY_COMMIT) throw invalid()
      const entry = new EntryCircuit(this, descriptor, stream, context)
      descriptor = null
      context = null
      this.entryCircuits.set(token, entry)
      entry.link.once('close', () => {
        if (this.entryCircuits.get(token) === entry) this.entryCircuits.delete(token)
      })
      await status(stream)
    } finally {
      if (token !== null && this.pendingEntryRegistrations.get(token) === stream) {
        this.pendingEntryRegistrations.delete(token)
      }
      clearRouteContext(context)
      clearDescriptor(descriptor)
    }
  }

  async _handleBuildSource(stream) {
    let descriptor = null
    let localContext = null
    let downstreamContext = null
    let entryContext = null
    let next = null
    let request = null
    try {
      descriptor = decodeDescriptor(await readExactly(stream, DESCRIPTOR_BYTES))
      const secondSafetyRelayPublicKey = await readExactly(stream, 32)
      if (
        same(this.relayKeyPair.publicKey, descriptor.entryRelayPublicKey) ||
        same(this.relayKeyPair.publicKey, descriptor.destinationGuardPublicKey) ||
        same(secondSafetyRelayPublicKey, this.relayKeyPair.publicKey) ||
        same(secondSafetyRelayPublicKey, descriptor.entryRelayPublicKey) ||
        same(secondSafetyRelayPublicKey, descriptor.destinationGuardPublicKey)
      ) {
        throw invalid()
      }
      localContext = decodeRouteContext(await readExactly(stream, ROUTE_CONTEXT_BYTES))
      downstreamContext = decodeRouteContext(await readExactly(stream, ROUTE_CONTEXT_BYTES))
      entryContext = decodeRouteContext(await readExactly(stream, ROUTE_CONTEXT_BYTES))
      next = await this._connectRelay(secondSafetyRelayPublicKey, this.relayKeyPair)
      request = b4a.concat([
        b4a.from([OP_EXTEND_SOURCE]),
        descriptor.wire,
        encodeRouteContext(downstreamContext),
        encodeRouteContext(entryContext)
      ])
      await writeAll(next, request)
      if ((await readExactly(next, 1))[0] !== STATUS_OK) throw unavailable()
      await status(stream)
      const left = new CircuitLink(this, stream, localContext, false, 'source-safety-1-in')
      localContext = null
      const right = new CircuitLink(this, next, downstreamContext, true, 'source-safety-1-out')
      downstreamContext = null
      next = null
      const bridge = transformBridge(this, left, right)
      this.bridges.add(bridge)
    } finally {
      if (request) request.fill(0)
      clearDescriptor(descriptor)
      clearRouteContext(localContext)
      clearRouteContext(downstreamContext)
      clearRouteContext(entryContext)
      if (next) next.destroy()
    }
  }

  async _handleExtendSource(stream) {
    let descriptor = null
    let localContext = null
    let downstreamContext = null
    let next = null
    let request = null
    try {
      descriptor = decodeDescriptor(await readExactly(stream, DESCRIPTOR_BYTES))
      if (
        same(this.relayKeyPair.publicKey, descriptor.entryRelayPublicKey) ||
        same(this.relayKeyPair.publicKey, descriptor.destinationGuardPublicKey) ||
        same(stream.remotePublicKey, descriptor.entryRelayPublicKey) ||
        same(stream.remotePublicKey, descriptor.destinationGuardPublicKey) ||
        same(stream.remotePublicKey, this.relayKeyPair.publicKey)
      ) {
        throw invalid()
      }
      localContext = decodeRouteContext(await readExactly(stream, ROUTE_CONTEXT_BYTES))
      downstreamContext = decodeRouteContext(await readExactly(stream, ROUTE_CONTEXT_BYTES))
      next = await this._connectRelay(descriptor.entryRelayPublicKey, this.relayKeyPair)
      request = b4a.concat([
        b4a.from([OP_ENTRY_ACTIVATE]),
        descriptor.wire,
        encodeRouteContext(downstreamContext)
      ])
      await writeAll(next, request)
      if ((await readExactly(next, 1))[0] !== STATUS_OK) throw unavailable()
      await status(stream)
      const left = new CircuitLink(this, stream, localContext, false, 'source-safety-2-in')
      const right = new CircuitLink(this, next, downstreamContext, true, 'source-safety-2-out')
      const bridge = transformBridge(this, left, right)
      this.bridges.add(bridge)
      localContext = null
      downstreamContext = null
      next = null
    } finally {
      if (request) request.fill(0)
      clearDescriptor(descriptor)
      clearRouteContext(localContext)
      clearRouteContext(downstreamContext)
      if (next) next.destroy()
    }
  }

  async _handleEntryActivate(stream) {
    let descriptor = null
    let context = null
    try {
      descriptor = decodeDescriptor(await readExactly(stream, DESCRIPTOR_BYTES))
      if (
        !same(descriptor.entryRelayPublicKey, this.relayKeyPair.publicKey) ||
        same(stream.remotePublicKey, descriptor.destinationGuardPublicKey) ||
        same(stream.remotePublicKey, this.relayKeyPair.publicKey)
      ) {
        throw invalid()
      }
      context = decodeRouteContext(await readExactly(stream, ROUTE_CONTEXT_BYTES))
      const entry = this.entryCircuits.get(key(descriptor.routeToken))
      if (!entry || !same(entry.descriptor.wire, descriptor.wire)) throw unavailable()
      await status(stream)
      entry.activate(stream, context)
      context = null
    } finally {
      clearRouteContext(context)
      clearDescriptor(descriptor)
    }
  }
}
function shuffle(values) {
  const copy = values.map((value) => b4a.from(value))
  for (let index = copy.length - 1; index > 0; index--) {
    const candidate = random(4).readUInt32BE(0) % (index + 1)
    ;[copy[index], copy[candidate]] = [copy[candidate], copy[index]]
  }
  return copy
}

function defaultCreateSecretStream(isInitiator, rawStream, options) {
  return new NoiseSecretStream(isInitiator, rawStream, options)
}

function noop() {}

function createPrivatePeerController(options) {
  return new PrivatePeerController(options)
}

module.exports = {
  TEST_ONLY_PRIVATE_PEER_OBSERVER,
  TEST_ONLY_PRIVATE_PEER_WRITE_ALL,
  [TEST_ONLY_PRIVATE_PEER_OBSERVER](observer) {
    if (observer !== null && typeof observer !== 'function') throw invalid()
    testObserver = observer
    return () => {
      if (testObserver === observer) testObserver = null
    }
  },
  [TEST_ONLY_PRIVATE_PEER_WRITE_ALL](stream, value) {
    return writeAll(stream, value)
  },
  createPrivatePeerController
}
