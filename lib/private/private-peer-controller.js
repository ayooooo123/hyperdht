'use strict'

const { EventEmitter } = require('events')
const { Duplex, Writable } = require('streamx')
const b4a = require('b4a')
const sodium = require('sodium-universal')
const safetyCatch = require('safety-catch')
const NoiseSecretStream = require('@hyperswarm/secret-stream')
const HyperDHTAddress = require('hyperdht-address')
const { decode } = require('hypercore-id-encoding')
const UDX = require('udx-native')

const { createKeyPair, hash } = require('../crypto')
const Announcer = require('../announcer')
const { CellCodec, CELL_SIZE, CELL_BODY_SIZE, MAX_CELL_PAYLOAD } = require('./cell-codec')
const { SenderCounter, OrderedReceiver, MAX_COUNTER } = require('./counters')
const { cryptoSuite } = require('./crypto-suite')
const { CELL_CLASS, DIRECTION } = require('./protocol')
const { PrivateRouteError } = require('./errors')
const {
  createPeerLedger,
  chargePeerLedger,
  readPeerLedger,
  releasePeerLedger
} = require('./peer-ledger')
const { createBlindedSigner, lookupPeriods, periodOf } = require('./blinded-presence')
const {
  DESCRIPTOR_BYTES,
  MAX_LIFETIME_MS,
  OverlayDescriptorService,
  RELAY_TARGETS,
  decodeDescriptor,
  descriptorTarget,
  encodeDescriptor
} = require('./overlay-descriptor-service')

const CONTROL_VERSION = 7
const SOURCE_RESOLVE = 1
const SOURCE_ACTIVATE = 2
const MAX_CONTROL_CELLS = 16
const MAX_SOURCE_ATTEMPTS = 3
const OP_BUILD_DESTINATION = 3
const OP_ENTRY_REGISTER = 4
const OP_BUILD_SOURCE = 5
const OP_ENTRY_ACTIVATE = 6
const OP_EXTEND_SOURCE = 7
const ENTRY_COMMIT = 0xa5
const STATUS_OK = 0
const STATUS_UNAVAILABLE = 1
const CONTROL_TIMEOUT_MS = 60000
const CONTROL_SESSION_TIMEOUT_MS = 60000
const CONTROL_READ_TIMEOUT_MS = 30000
const CONTROL_OPCODE_TIMEOUT_MS = 10000
const MAX_CONTROL_SESSIONS = 256
const MAX_PEER_CONTROL_SESSIONS = 32
const ROUTE_LIFETIME_MS = MAX_LIFETIME_MS
const GUARD_SET_SIZE = 3
const GUARD_LIFETIME_MS = 28 * 24 * 60 * 60 * 1000
const ROUTE_CONTEXT_BYTES = 120
const RECOVERY_ABSENT = 0
const RECOVERY_PRESENT = 1
const DESTINATION_ADMISSION_CHALLENGE_BYTES = 32
const DESTINATION_ADMISSION_SIGNATURE_BYTES = 64
const DESTINATION_ADMISSION_IDENTITY_BYTES = 8 + 32 + DESTINATION_ADMISSION_SIGNATURE_BYTES
const DESTINATION_ADMISSION_DOMAIN = b4a.from('hyperdht/private-peer/destination-admission/v4')
const COUNTER_ORIGIN_DOMAIN = b4a.from('hyperdht/private-peer/counter-origin/v1')
const DIVERSITY_DOMAIN = 'hyperdht/private-peer/relay-diversity/v1/'
const LOGICAL_HEADER_BYTES = 5
const MAX_LOGICAL_PAYLOAD = MAX_CELL_PAYLOAD - LOGICAL_HEADER_BYTES
const LOGICAL_DATA = 0
const LOGICAL_OPEN = 1
const LOGICAL_FIN = 2
const LOGICAL_RESET = 3
const LOGICAL_CREDIT = 4
const LOGICAL_DEMAND = 5
const LOGICAL_RELEASE = 6
const LOGICAL_SPLICE_OPEN = 7
const LOGICAL_SPLICE_READY = 8
const SPLICE_IDLE_POLL_MS = 5000
const CIRCUIT_STREAM_ID = 0xffffffff
const STREAM_WINDOW = 512
const CIRCUIT_WINDOW = 2048
const STREAM_CREDIT_BATCH = 128
const CIRCUIT_CREDIT_BATCH = 32
const CONTROL_RESERVE = 256
const SEND_BATCH_CELLS = 64
const SEND_PIPELINE_BATCHES = 2
const SEND_QUANTUM_BYTES = 4 * CELL_SIZE
const CREDIT_IDLE_MS = 50
const CREDIT_GRANT_IDLE_MS = 5000
const DEMAND_PROGRESS = 32
const MAX_ROUTE_STREAMS = 64
const MAX_STREAM_BYTES = 32 * 1024 * 1024 * 1024
const MAX_STREAM_DATA_FRAMES = Math.ceil(MAX_STREAM_BYTES / MAX_LOGICAL_PAYLOAD)
const MAX_STREAM_CELLS = 2 * MAX_STREAM_DATA_FRAMES + 4 * MAX_CONTROL_CELLS
const CELL_CHARGE = Object.freeze({ cells: 1, bytes: BigInt(CELL_SIZE), commands: 1 })
const READ_BUFFERS = new WeakMap()
// Protocol lifetimes are controller-owned; transport deadlines use real time.
const SYSTEM_CLOCK = Object.freeze({ now: Date.now, setTimeout, clearTimeout })

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

function normalizedIP(host) {
  const family = typeof host === 'string' ? UDX.isIP(host) : 0
  if (family === 4) return { family, bytes: b4a.from(host.split('.').map(Number)) }
  if (family !== 6) return null
  if (host.includes('.')) {
    const split = host.lastIndexOf(':')
    const parts = host
      .slice(split + 1)
      .split('.')
      .map(Number)
    host =
      host.slice(0, split + 1) +
      ((parts[0] << 8) | parts[1]).toString(16) +
      ':' +
      ((parts[2] << 8) | parts[3]).toString(16)
  }
  const halves = host.split('::')
  const before = halves[0] ? halves[0].split(':') : []
  const after = halves.length === 2 && halves[1] ? halves[1].split(':') : []
  const words =
    halves.length === 2
      ? before.concat(Array(8 - before.length - after.length).fill('0'), after)
      : before
  if (words.length !== 8) return null
  const bytes = b4a.allocUnsafe(16)
  for (let i = 0; i < words.length; i++) bytes.writeUInt16BE(parseInt(words[i], 16), i * 2)
  if (
    bytes.subarray(0, 10).every((value) => value === 0) &&
    bytes[10] === 255 &&
    bytes[11] === 255
  ) {
    return { family: 4, bytes: bytes.subarray(12) }
  }
  return { family, bytes }
}

function isLoopback(address) {
  if (!address) return false
  return address.family === 4
    ? address.bytes[0] === 127
    : address.bytes[15] === 1 && address.bytes.subarray(0, 15).every((value) => value === 0)
}

function relayDiversityKey(host, port, allowLoopback) {
  const address = normalizedIP(host)
  if (!address || !Number.isInteger(port) || port <= 0 || port > 65535) throw unavailable()
  if (
    address.bytes.every((value) => value === 0) ||
    (address.family === 4 ? address.bytes[0] >= 224 : address.bytes[0] === 255)
  ) {
    throw unavailable()
  }
  if (isLoopback(address)) {
    if (!allowLoopback) throw unavailable()
    return 'loopback:' + address.family + ':' + key(address.bytes) + ':' + port
  }
  return address.family === 4
    ? 'ipv4/24:' + key(address.bytes.subarray(0, 3))
    : 'ipv6/48:' + key(address.bytes.subarray(0, 6))
}

function requireDiverse(...values) {
  for (let i = 0; i < values.length; i++) {
    if (!fixed(values[i], 32)) throw invalid()
    for (let j = 0; j < i; j++) {
      if (same(values[i], values[j])) throw unavailable()
    }
  }
}

function random(size) {
  const value = b4a.allocUnsafe(size)
  sodium.randombytes_buf(value)
  return value
}
function destinationAdmissionInput(challenge, remotePublicKey, guardPublicKey, blindedIdentity) {
  if (
    !fixed(challenge, DESTINATION_ADMISSION_CHALLENGE_BYTES) ||
    !fixed(remotePublicKey, 32) ||
    !fixed(guardPublicKey, 32) ||
    !fixed(blindedIdentity, 40)
  ) {
    throw invalid()
  }
  return b4a.concat([
    DESTINATION_ADMISSION_DOMAIN,
    challenge,
    remotePublicKey,
    guardPublicKey,
    blindedIdentity
  ])
}

function signDestinationAdmission(
  destinationKeyPair,
  period,
  challenge,
  remotePublicKey,
  guardPublicKey
) {
  const signer = createBlindedSigner(destinationKeyPair, period)
  const identity = b4a.allocUnsafe(DESTINATION_ADMISSION_IDENTITY_BYTES)
  let input = null
  let signature = null
  try {
    writeU64(identity, period)
    signer.publicKey.copy(identity, 8)
    input = destinationAdmissionInput(
      challenge,
      remotePublicKey,
      guardPublicKey,
      identity.subarray(0, 40)
    )
    signature = signer.sign(input)
    signature.copy(identity, 40)
    return identity
  } catch (error) {
    identity.fill(0)
    throw error
  } finally {
    signer.destroy()
    signer.publicKey.fill(0)
    if (input) input.fill(0)
    if (signature) signature.fill(0)
  }
}

function verifyDestinationAdmission(identity, challenge, remotePublicKey, guardPublicKey) {
  if (!fixed(identity, DESTINATION_ADMISSION_IDENTITY_BYTES)) return false
  const input = destinationAdmissionInput(
    challenge,
    remotePublicKey,
    guardPublicKey,
    identity.subarray(0, 40)
  )
  try {
    return sodium.crypto_sign_verify_detached(
      identity.subarray(40),
      input,
      identity.subarray(8, 40)
    )
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
  if (!controller.observer) return
  const snapshot = {
    role: controller.relay ? 'relay' : 'endpoint',
    relayPublicKey: controller.relayKeyPair ? b4a.from(controller.relayKeyPair.publicKey) : null
  }
  for (const [name, value] of Object.entries(event)) {
    snapshot[name] = b4a.isBuffer(value) ? b4a.from(value) : value
  }
  try {
    const result = controller.observer(Object.freeze(snapshot))
    if (result && typeof result.then === 'function') Promise.resolve(result).catch(noop)
  } catch {}
}

function opened(stream, timeout = CONTROL_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    let settled = false
    const timer = setTimeout(() => finish(unavailable()), timeout)
    function finish(error) {
      if (settled) return
      settled = true
      clearTimeout(timer)
      stream.removeListener('error', onerror)
      stream.removeListener('close', onclose)
      if (error) reject(error)
      else resolve(stream)
    }
    function onerror(error) {
      finish(error)
    }
    function onclose() {
      finish(unavailable())
    }
    stream.once('error', onerror)
    stream.once('close', onclose)
    if (stream.destroying || stream.destroyed) {
      finish(unavailable())
      return
    }
    Promise.resolve(stream.opened).then(
      (ok) => finish(ok === false ? unavailable() : null),
      (error) => finish(error)
    )
  })
}

function readExactly(stream, size, timeout = CONTROL_TIMEOUT_MS) {
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
    const timer = setTimeout(() => finish(unavailable()), timeout)

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

function rejectedWrite(error) {
  const pending = Promise.reject(error)
  pending.catch(noop)
  return pending
}

function writeAll(stream, value) {
  const pending = new Promise((resolve, reject) => {
    if (stream.destroying || stream.destroyed) {
      reject(unavailable())
      return
    }
    try {
      stream.write(value)
      Writable.drained(stream).then(
        (drained) => {
          if (!drained || stream.destroying || stream.destroyed) reject(unavailable())
          else resolve()
        },
        () => reject(unavailable())
      )
    } catch {
      reject(unavailable())
    }
  })
  // Transport completion owns this rejection even if a caller closes before
  // adopting the returned promise. The caller still receives the failure.
  pending.catch(noop)
  return pending
}

class ControlSession {
  constructor(controller, stream, peerKeys) {
    this.controller = controller
    this.stream = stream
    this.peerKeys = peerKeys
    this.resources = new Set()
    this.streams = new Set()
    this.cancelled = false
    this.finished = false
    this.failure = null
    this._onclose = () => this.cancel()
    this.timer = setTimeout(() => this.cancel(), CONTROL_SESSION_TIMEOUT_MS)
    controller.controlSessions.add(this)
    for (const peer of peerKeys) {
      controller.controlPeers.set(peer, (controller.controlPeers.get(peer) || 0) + 1)
    }
    this.ownStream(stream)
    stream.once('end', this._onclose)
    stream.once('error', this._onclose)
    stream.once('close', this._onclose)
  }

  check() {
    if (this.cancelled || this.finished || this.controller.destroyed || this.controller.suspended) {
      if (!this.failure) this.failure = unavailable()
      throw this.failure
    }
  }

  track(resource) {
    try {
      this.check()
    } catch (error) {
      resource.destroy(error)
      throw error
    }
    this.resources.add(resource)
    return () => this.resources.delete(resource)
  }

  ownStream(stream) {
    this.track(stream)
    this.streams.add(stream)
    this.controller.controlStreams.set(stream, this)
  }

  cancel() {
    if (this.cancelled || this.finished) return
    this.cancelled = true
    if (!this.failure) this.failure = unavailable()
    clearTimeout(this.timer)
    for (const stream of this.streams) {
      const state = READ_BUFFERS.get(stream)
      if (state && state.buffered) state.buffered.fill(0)
      if (state) state.buffered = null
      READ_BUFFERS.delete(stream)
    }
    for (const resource of this.resources) resource.destroy(this.failure)
  }

  finish() {
    if (this.finished) return
    this.finished = true
    clearTimeout(this.timer)
    this.stream.removeListener('end', this._onclose)
    this.stream.removeListener('error', this._onclose)
    this.stream.removeListener('close', this._onclose)
    for (const stream of this.streams) this.controller.controlStreams.delete(stream)
    this.streams.clear()
    this.resources.clear()
    this.controller.controlSessions.delete(this)
    for (const peer of this.peerKeys) {
      const remaining = this.controller.controlPeers.get(peer) - 1
      if (remaining === 0) this.controller.controlPeers.delete(peer)
      else this.controller.controlPeers.set(peer, remaining)
    }
  }
}

function controlHeader(opcode) {
  return b4a.from([CONTROL_VERSION, opcode])
}

function createRouteContext() {
  const epochBytes = random(8)
  const epoch = readU64(epochBytes)
  epochBytes.fill(0)
  return {
    circuitId: random(16),
    epoch,
    forwardKey: random(32),
    forwardNonce: random(16),
    reverseKey: random(32),
    reverseNonce: random(16)
  }
}

function counterOrigin(key) {
  const digest = b4a.allocUnsafe(32)
  try {
    sodium.crypto_generichash(digest, COUNTER_ORIGIN_DOMAIN, key)
    // Leave at least half the counter space available before exhaustion.
    return (readU64(digest) & 0x7fffffffffffffffn) + 1n
  } finally {
    digest.fill(0)
  }
}

function refreshDelay() {
  const entropy = random(4)
  const fraction = entropy.readUInt32BE(0) / 0x100000000
  entropy.fill(0)
  return Math.floor(ROUTE_LIFETIME_MS * (0.4 + 0.2 * fraction))
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

function validLogicalPayload(streamId, flags, data) {
  if (!b4a.isBuffer(data) || data.byteLength > MAX_LOGICAL_PAYLOAD) return false
  if (flags === LOGICAL_SPLICE_OPEN || flags === LOGICAL_SPLICE_READY) {
    return streamId !== CIRCUIT_STREAM_ID && data.byteLength === 4 && readU32(data) !== 0
  }
  if (flags < LOGICAL_CREDIT) {
    return streamId !== CIRCUIT_STREAM_ID && (flags === LOGICAL_DATA || data.byteLength === 0)
  }
  if (flags > LOGICAL_RELEASE || data.byteLength !== 2) return false
  if (flags !== LOGICAL_CREDIT && streamId !== CIRCUIT_STREAM_ID) return false
  const amount = (data[0] << 8) | data[1]
  const maximum = streamId === CIRCUIT_STREAM_ID ? CIRCUIT_WINDOW : STREAM_WINDOW
  return amount <= maximum && (amount !== 0 || flags === LOGICAL_DEMAND)
}

function encodeLogical(streamId, flags, data = b4a.alloc(0)) {
  if (
    !Number.isSafeInteger(streamId) ||
    streamId < 0 ||
    streamId > 0xffffffff ||
    !Number.isSafeInteger(flags) ||
    flags < LOGICAL_DATA ||
    flags > LOGICAL_SPLICE_READY ||
    !validLogicalPayload(streamId, flags, data)
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
  if (!validLogicalPayload(streamId, flags, frame.subarray(LOGICAL_HEADER_BYTES))) throw invalid()
  return { streamId, flags, data: b4a.from(frame.subarray(LOGICAL_HEADER_BYTES)) }
}

function sendLogical(link, streamId, flags, data) {
  return link.send(encodeLogical(streamId, flags, data), true)
}

function sendCredit(link, streamId, flags, amount) {
  const data = b4a.allocUnsafe(2)
  data[0] = amount >>> 8
  data[1] = amount & 0xff
  return sendLogical(link, streamId, flags, data)
}

function scheduleCreditReturn(owner, flush) {
  if (owner.returnTimer !== null) return
  owner.returnTimer = setTimeout(() => {
    owner.returnTimer = null
    try {
      flush()
    } catch {
      owner.link.destroy(unavailable())
    }
  }, CREDIT_IDLE_MS)
  if (owner.returnTimer.unref) owner.returnTimer.unref()
}

class CircuitLink extends EventEmitter {
  constructor(controller, rawStream, context, initiator, label, maxStreams = 1) {
    super()
    this.controller = controller
    this.rawStream = rawStream
    this.context = context
    this.initiator = initiator
    this.label = label
    this.codec = new CellCodec({ crypto: cryptoSuite, cellSize: CELL_SIZE })
    this.sender = new SenderCounter({
      initial: counterOrigin(initiator ? context.forwardKey : context.reverseKey),
      maximum: MAX_COUNTER
    })
    this.receiver = new OrderedReceiver({
      initial: counterOrigin(initiator ? context.reverseKey : context.forwardKey),
      window: 64,
      gapTimeout: CONTROL_TIMEOUT_MS,
      now: Date.now,
      maximum: MAX_COUNTER
    })
    const receiveDirection = initiator ? DIRECTION.REVERSE : DIRECTION.FORWARD
    this.openOptions = {
      key: receiveDirection === DIRECTION.FORWARD ? context.forwardKey : context.reverseKey,
      noncePrefix:
        receiveDirection === DIRECTION.FORWARD ? context.forwardNonce : context.reverseNonce,
      expectedClass: CELL_CLASS.STREAM,
      expectedDirection: receiveDirection,
      expectedEpoch: context.epoch,
      expectedCircuitId: context.circuitId,
      receiver: this.receiver
    }
    const sendDirection = initiator ? DIRECTION.FORWARD : DIRECTION.REVERSE
    this.sealOptions = {
      key: sendDirection === DIRECTION.FORWARD ? context.forwardKey : context.reverseKey,
      noncePrefix:
        sendDirection === DIRECTION.FORWARD ? context.forwardNonce : context.reverseNonce,
      senderCounter: this.sender,
      class: CELL_CLASS.STREAM,
      direction: sendDirection,
      epoch: context.epoch,
      circuitId: context.circuitId,
      payload: null
    }
    this.sealer = this.codec.createSealer(this.sealOptions)
    this.opener = this.codec.createOpener(this.openOptions)
    this.openedBody = b4a.alloc(CELL_BODY_SIZE)
    this.freeBatches = Array.from({ length: SEND_PIPELINE_BATCHES }, () => ({
      jobs: [],
      buffer: b4a.allocUnsafe(SEND_BATCH_CELLS * CELL_SIZE),
      output: null
    }))
    this.multiplexed = maxStreams > 1
    this.admissionFrontier = 0
    this.ledgerLimit = maxStreams * MAX_STREAM_CELLS + MAX_CONTROL_CELLS
    const cells = this.multiplexed ? MAX_CONTROL_CELLS : this.ledgerLimit
    const allocation = {
      cells,
      bytes: BigInt(cells * CELL_SIZE),
      commands: cells
    }
    this.sendLedger = createPeerLedger(allocation)
    this.receiveLedger = createPeerLedger(allocation)
    this.incoming = null
    this.incomingBytes = 0
    this.sendQueues = new Map()
    this.sendHead = null
    this.sendTail = null
    this.queuedSends = 0
    this.inflight = new Set()
    this.flushScheduled = false
    this.pendingData = 0
    this.pendingControl = 0
    this.failure = null
    this.pendingSends = 0
    this.destroyed = false
    this.started = false
    this._ondata = (chunk) => this._receive(chunk)
    this._onend = () => this.destroy()
    this._onerror = (error) => this.destroy(error)
    this._onclose = () => this.destroy()
    rawStream.once('end', this._onend)
    rawStream.once('error', this._onerror)
    rawStream.once('close', this._onclose)
  }

  start() {
    if (this.started || this.destroyed) return
    this.started = true
    const buffered = takeBuffered(this.rawStream)
    if (buffered) {
      this._receive(buffered)
      buffered.fill(0)
    }
    if (!this.destroyed) this.rawStream.on('data', this._ondata)
  }

  _fundAdmission(payload) {
    if (
      !this.multiplexed ||
      !(
        (payload.byteLength === LOGICAL_HEADER_BYTES && payload[4] === LOGICAL_OPEN) ||
        (payload.byteLength === LOGICAL_HEADER_BYTES + 4 && payload[4] === LOGICAL_SPLICE_OPEN)
      )
    )
      return
    const streamId = readU32(payload)
    if (streamId === 0 || streamId % 2 !== 0 || streamId <= this.admissionFrontier) return
    this.admissionFrontier = streamId
    // A fresh monotone admission contributes one finite source allowance. Only
    // unspent capacity carries forward, capped by the concurrent route limit;
    // closing or replaying an old stream cannot refill either direction.
    for (const name of ['sendLedger', 'receiveLedger']) {
      const previous = this[name]
      const remaining = readPeerLedger(previous)
      const available = Math.min(
        remaining.cellsRemaining,
        remaining.commandsRemaining,
        Number(remaining.bytesRemaining / BigInt(CELL_SIZE))
      )
      const cells = Math.min(this.ledgerLimit, available + MAX_STREAM_CELLS)
      this[name] = createPeerLedger({ cells, bytes: BigInt(cells * CELL_SIZE), commands: cells })
      releasePeerLedger(previous)
    }
  }

  send(payload, owned = false) {
    const valid = b4a.isBuffer(payload) && payload.byteLength <= MAX_CELL_PAYLOAD
    const isData =
      valid && payload.byteLength >= LOGICAL_HEADER_BYTES && payload[4] === LOGICAL_DATA
    if (
      !valid ||
      this.destroyed ||
      (isData ? this.pendingData >= CIRCUIT_WINDOW : this.pendingControl >= CONTROL_RESERVE)
    ) {
      if (owned && b4a.isBuffer(payload)) payload.fill(0)
      this.destroy(unavailable())
      return rejectedWrite(this.failure)
    }
    const streamId =
      this.multiplexed && payload.byteLength >= LOGICAL_HEADER_BYTES ? readU32(payload) : 0
    const job = {
      payload: owned ? payload : b4a.from(payload),
      isData,
      resolve: null,
      reject: null,
      settled: false,
      next: null
    }
    const pending = new Promise((resolve, reject) => {
      job.resolve = resolve
      job.reject = reject
    })
    // The link owns queued plaintext until selection, and owns each rejection
    // even if its caller closes before adopting the returned promise.
    pending.catch(noop)
    this.pendingSends++
    if (isData) this.pendingData++
    else this.pendingControl++
    let queue = this.sendQueues.get(streamId)
    if (!queue) {
      queue = { streamId, head: null, tail: null, deficit: 0, next: null }
      this.sendQueues.set(streamId, queue)
      if (this.sendTail) this.sendTail.next = queue
      else this.sendHead = queue
      this.sendTail = queue
    }
    if (queue.tail) queue.tail.next = job
    else queue.head = job
    queue.tail = job
    this.queuedSends++
    this._scheduleSends()
    return pending
  }

  _nextSend() {
    const queue = this.sendHead
    if (queue.deficit === 0) queue.deficit = SEND_QUANTUM_BYTES
    const job = queue.head
    queue.head = job.next
    job.next = null
    queue.deficit -= CELL_SIZE
    this.queuedSends--
    if (!queue.head) {
      this.sendQueues.delete(queue.streamId)
      this.sendHead = queue.next
      if (this.sendTail === queue) this.sendTail = null
    } else if (queue.deficit === 0 && this.sendTail !== queue) {
      this.sendHead = queue.next
      queue.next = null
      this.sendTail.next = queue
      this.sendTail = queue
    }
    return job
  }

  _settleSend(job, error) {
    if (job.settled) return
    job.settled = true
    this.pendingSends--
    if (job.isData) this.pendingData--
    else this.pendingControl--
    if (error) job.reject(error)
    else job.resolve()
  }

  _scheduleSends() {
    if (this.destroyed || this.flushScheduled || this.queuedSends === 0) return
    this.flushScheduled = true
    Promise.resolve()
      .then(() => {
        this.flushScheduled = false
        this._flushSends()
      })
      .catch((error) => this.destroy(error))
  }

  _flushSends() {
    while (
      !this.destroyed &&
      this.inflight.size < SEND_PIPELINE_BATCHES &&
      this.queuedSends !== 0
    ) {
      const count = Math.min(SEND_BATCH_CELLS, this.queuedSends)
      const batch = this.freeBatches.pop()
      batch.jobs.length = 0
      batch.output = batch.buffer.subarray(0, count * CELL_SIZE)
      // Register the batch before sealing: an observer can synchronously close
      // the link, and that must settle even the currently selected job.
      this.inflight.add(batch)
      for (let i = 0; i < count && !this.destroyed; i++) {
        const job = this._nextSend()
        batch.jobs.push(job)
        try {
          this.controller._assertRelayAddress(this.rawStream)
          this._fundAdmission(job.payload)
          chargePeerLedger(this.sendLedger, CELL_CHARGE)
          // Assign counters only after DRR selection. Reordering already sealed
          // cells would violate the authenticated per-link counter sequence.
          this.sealer.sealInto(batch.buffer, job.payload, i * CELL_SIZE)
          if (this.controller.observer) {
            observe(this.controller, {
              type: 'route-cell-sealed',
              label: this.label,
              direction: this.sealOptions.direction,
              plaintext: job.payload,
              cell: batch.output.subarray(i * CELL_SIZE, (i + 1) * CELL_SIZE)
            })
          }
        } catch (error) {
          this.destroy(error)
        } finally {
          job.payload.fill(0)
          job.payload = null
        }
      }
      if (this.destroyed) {
        batch.buffer.fill(0)
        batch.output = null
        this.inflight.delete(batch)
        break
      }
      writeAll(this.rawStream, batch.output)
        .then(
          () => this._finishBatch(batch, null),
          (error) => this._finishBatch(batch, error)
        )
        .catch((error) => this.destroy(error))
    }
  }

  _finishBatch(batch, error) {
    // Teardown settles jobs immediately, but an in-flight write keeps exclusive
    // ownership of its batched bytes until transport completion.
    batch.buffer.fill(0)
    batch.output = null
    this.inflight.delete(batch)
    if (error) this.destroy(error)
    for (const job of batch.jobs) this._settleSend(job, this.failure)
    batch.jobs.length = 0
    if (!this.destroyed) this.freeBatches.push(batch)
    this._scheduleSends()
  }

  _receive(chunk) {
    if (this.destroyed) return
    if (!b4a.isBuffer(chunk) || chunk.byteLength === 0) {
      this.destroy(unavailable())
      return
    }
    try {
      this.controller._assertRelayAddress(this.rawStream)
      let offset = 0
      if (this.incomingBytes !== 0) {
        const length = Math.min(CELL_SIZE - this.incomingBytes, chunk.byteLength)
        chunk.copy(this.incoming, this.incomingBytes, 0, length)
        offset = length
        this.incomingBytes += length
        if (this.incomingBytes !== CELL_SIZE) return
        const cell = this.incoming
        this.incomingBytes = 0
        this._openCell(cell)
        cell.fill(0)
      }
      // Consume complete cells in place. Only the final incomplete cell needs
      // owned storage, independent of how many cells arrive in one read.
      while (!this.destroyed && offset + CELL_SIZE <= chunk.byteLength) {
        this._openCell(chunk.subarray(offset, offset + CELL_SIZE))
        offset += CELL_SIZE
      }
      if (!this.destroyed && offset < chunk.byteLength) {
        if (this.incoming === null) this.incoming = b4a.allocUnsafe(CELL_SIZE)
        chunk.copy(this.incoming, 0, offset)
        this.incomingBytes = chunk.byteLength - offset
      }
    } catch (error) {
      this.destroy(error)
    }
  }

  _openCell(cell) {
    chargePeerLedger(this.receiveLedger, CELL_CHARGE)
    let payload = null
    let payloads = null
    try {
      const length = this.opener.openInto(cell, this.openedBody)
      // The decoder scratch is borrowed. The ordering receiver and forwarding
      // queues retain independently owned bytes beyond this synchronous call.
      payload = b4a.from(this.openedBody.subarray(2, 2 + length))
      payloads = this.receiver.pushAuthenticated(this.opener.counter, payload)
      if (!payloads.includes(payload)) payload.fill(0)
    } catch (error) {
      if (payload) payload.fill(0)
      throw error
    } finally {
      this.openedBody.fill(0)
    }
    for (const payload of payloads) {
      if (this.destroyed) {
        payload.fill(0)
        continue
      }
      try {
        this._fundAdmission(payload)
      } catch (error) {
        payload.fill(0)
        throw error
      }
      if (this.controller.observer) {
        observe(this.controller, {
          type: 'route-cell-opened',
          label: this.label,
          direction: this.openOptions.expectedDirection,
          plaintext: payload,
          cell
        })
      }
      if (this.destroyed) payload.fill(0)
      else this.emit('payload', payload)
    }
  }

  destroy(error) {
    if (this.destroyed) return false
    this.destroyed = true
    this.failure = unavailable()
    const failure = error ? this.failure : null
    for (const batch of this.inflight) {
      for (const job of batch.jobs) this._settleSend(job, this.failure)
    }
    for (const queue of this.sendQueues.values()) {
      for (let job = queue.head; job; job = job.next) {
        this._settleSend(job, this.failure)
        job.payload.fill(0)
      }
    }
    this.sendQueues.clear()
    this.sendHead = null
    this.sendTail = null
    this.queuedSends = 0
    this.rawStream.removeListener('data', this._ondata)
    this.rawStream.removeListener('end', this._onend)
    this.rawStream.removeListener('error', this._onerror)
    this.rawStream.removeListener('close', this._onclose)
    this.sender.destroy()
    this.receiver.destroy()
    this.sealer.destroy()
    this.opener.destroy()
    this.openedBody.fill(0)
    for (const batch of this.freeBatches) batch.buffer.fill(0)
    this.freeBatches.length = 0
    releasePeerLedger(this.sendLedger)
    releasePeerLedger(this.receiveLedger)
    if (this.incoming) this.incoming.fill(0)
    this.incoming = null
    this.incomingBytes = 0
    clearRouteContext(this.context)
    if (!this.rawStream.destroyed) this.rawStream.destroy(failure)
    this.emit('close', failure)
    return true
  }
}

class ControlInbox {
  constructor(link, timeout = CONTROL_TIMEOUT_MS) {
    this.link = link
    this.timeout = timeout
    this.queue = []
    this.waiting = null
    this.closed = false
    this._onpayload = (payload) => {
      if (this.waiting) {
        const { resolve, timer } = this.waiting
        this.waiting = null
        clearTimeout(timer)
        resolve(payload)
      } else if (this.queue.length < MAX_CONTROL_CELLS) {
        this.queue.push(payload)
      } else {
        payload.fill(0)
        link.destroy(invalid())
      }
    }
    this._onclose = (error) => this.destroy(error || unavailable())
    link.on('payload', this._onpayload)
    link.once('close', this._onclose)
    link.start()
  }

  read() {
    if (this.closed || this.waiting) return Promise.reject(unavailable())
    if (this.queue.length) return Promise.resolve(this.queue.shift())
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.link.destroy(unavailable()), this.timeout)
      this.waiting = { resolve, reject, timer }
    })
  }

  detach() {
    if (this.closed || this.waiting) throw invalid()
    this.closed = true
    this.link.removeListener('payload', this._onpayload)
    this.link.removeListener('close', this._onclose)
    const queued = this.queue
    this.queue = []
    return queued
  }

  destroy(error = unavailable()) {
    if (this.closed) return
    if (this.waiting) {
      const { reject, timer } = this.waiting
      this.waiting = null
      clearTimeout(timer)
      reject(error)
    }
    for (const payload of this.detach()) payload.fill(0)
  }
}

function watchSplicedPair(controller, up, down, onDestroy = null) {
  let destroyed = false
  let lastRx = 0
  let lastActiveAt = controller.clock.now()
  const timer = setInterval(() => {
    if (destroyed) return
    const rx = (up.bytesReceived || 0) + (down.bytesReceived || 0)
    const now = controller.clock.now()
    if (rx > lastRx) {
      lastRx = rx
      lastActiveAt = now
    } else if (now - lastActiveAt >= ROUTE_LIFETIME_MS) {
      close(unavailable())
    }
  }, SPLICE_IDLE_POLL_MS)
  if (timer.unref) timer.unref()
  function close(error) {
    if (destroyed) return
    destroyed = true
    clearInterval(timer)
    if (onDestroy) onDestroy()
    if (!up.destroyed) up.destroy(error)
    if (!down.destroyed) down.destroy(error)
  }
  up.once('close', () => close())
  down.once('close', () => close())
  return { up, down, active: false, close }
}

function transformBridge(controller, left, right, onclose = null) {
  let closed = false
  const splices = new Map()
  const bridge = { destroy: close }
  function close(error) {
    if (closed) return
    closed = true
    controller.bridges.delete(bridge)
    for (const pair of splices.values()) pair.close(error)
    splices.clear()
    if (onclose) onclose(bridge)
    left.destroy(error)
    right.destroy(error)
  }
  function forward(payload, from, to) {
    if (controller.observer) {
      observe(controller, {
        type: 'route-transform',
        from: from.label,
        to: to.label,
        plaintext: payload
      })
    }
    if (payload.byteLength >= LOGICAL_HEADER_BYTES) {
      const streamId = readU32(payload)
      const flags = payload[4]
      if (flags === LOGICAL_SPLICE_OPEN && payload.byteLength === LOGICAL_HEADER_BYTES + 4) {
        try {
          if (splices.has(streamId) || splices.size >= MAX_ROUTE_STREAMS) throw invalid()
          const prevUdxId = readU32(payload.subarray(LOGICAL_HEADER_BYTES))
          const fromRaw = from.rawStream.rawStream
          const toRaw = to.rawStream.rawStream
          const up = controller._createSpliceStream(fromRaw)
          const down = controller._createSpliceStream(toRaw)
          const pair = watchSplicedPair(controller, up, down, () => splices.delete(streamId))
          splices.set(streamId, pair)
          up.connect(fromRaw.socket, prevUdxId, fromRaw.remotePort, fromRaw.remoteHost)
          const out = b4a.from(payload)
          writeU32(out.subarray(LOGICAL_HEADER_BYTES), down.id)
          payload.fill(0)
          to.send(out, true).catch(close)
        } catch (err) {
          payload.fill(0)
          close(err)
        }
        return
      }
      if (flags === LOGICAL_SPLICE_READY && payload.byteLength === LOGICAL_HEADER_BYTES + 4) {
        try {
          const pair = splices.get(streamId)
          if (!pair || pair.active) throw invalid()
          pair.active = true
          const nextUdxId = readU32(payload.subarray(LOGICAL_HEADER_BYTES))
          const fromRaw = from.rawStream.rawStream
          pair.down.connect(fromRaw.socket, nextUdxId, fromRaw.remotePort, fromRaw.remoteHost)
          pair.up.relayTo(pair.down)
          pair.down.relayTo(pair.up)
          const out = b4a.from(payload)
          writeU32(out.subarray(LOGICAL_HEADER_BYTES), pair.up.id)
          payload.fill(0)
          to.send(out, true).catch(close)
        } catch (err) {
          payload.fill(0)
          close(err)
        }
        return
      }
      if (flags === LOGICAL_RESET && payload.byteLength === LOGICAL_HEADER_BYTES) {
        const pair = splices.get(streamId)
        if (pair) {
          splices.delete(streamId)
          pair.close(unavailable())
        }
      }
    }
    to.send(payload, true).catch(close)
  }
  left.on('payload', (payload) => forward(payload, left, right))
  right.on('payload', (payload) => forward(payload, right, left))
  left.once('close', close)
  right.once('close', close)
  left.start()
  right.start()
  return bridge
}

class CircuitCreditPool {
  constructor(onGrant, onIdle) {
    this.onGrant = onGrant
    this.onIdle = onIdle
    this.available = CIRCUIT_WINDOW
    this.inFlight = 0
    this.legs = new Map()
    this.pending = []
    this.distributing = false
    this.closed = false
  }

  add(owner) {
    if (this.closed || this.legs.size >= MAX_ROUTE_STREAMS || this.legs.has(owner))
      throw unavailable()
    this.legs.set(owner, {
      owner,
      granted: 0,
      wanted: 0,
      demandOpen: false,
      lastDemandAt: 0,
      progress: DEMAND_PROGRESS,
      lastActivity: 0,
      idleTimer: null
    })
  }

  demand(owner, amount, rateLimited = false) {
    const leg = this.legs.get(owner)
    if (!leg || this.closed || !Number.isInteger(amount) || amount < 0 || amount > CIRCUIT_WINDOW)
      throw invalid()
    if (amount === 0) {
      if (!leg.demandOpen) throw invalid()
      this.cancel(owner)
      return
    }
    if (leg.wanted !== 0 || leg.granted + amount > CIRCUIT_WINDOW) throw invalid()
    const now = Date.now()
    // Keep at most two DATA-earned renewals so a partial circuit grant crossing
    // the independent stream boundary does not discard already earned progress.
    // Idle legs still get one demand per interval; pending demand cannot repeat.
    if (rateLimited && leg.progress < DEMAND_PROGRESS && now - leg.lastDemandAt < CREDIT_IDLE_MS)
      throw invalid()
    leg.lastDemandAt = now
    leg.progress = Math.max(0, leg.progress - DEMAND_PROGRESS)
    leg.demandOpen = true
    leg.wanted = amount
    this.pending.push(leg)
    this._distribute()
  }

  sent(owner, amount = 1) {
    const leg = this.legs.get(owner)
    if (!leg || this.closed || !Number.isInteger(amount) || amount < 1 || amount > leg.granted)
      throw invalid()
    leg.granted -= amount
    leg.progress = Math.min(2 * DEMAND_PROGRESS, leg.progress + amount)
    this.inFlight += amount
    leg.lastActivity = Date.now()
    if (leg.granted === 0) this._clearIdle(leg)
  }

  returned(amount) {
    if (this.closed || !Number.isInteger(amount) || amount < 1 || amount > this.inFlight)
      throw invalid()
    this.inFlight -= amount
    this.available += amount
    this._distribute()
  }

  release(owner, amount) {
    const leg = this.legs.get(owner)
    if (!leg || this.closed || !Number.isInteger(amount) || amount < 1 || amount > leg.granted)
      throw invalid()
    leg.granted -= amount
    if (leg.granted === 0) this._clearIdle(leg)
    this.available += amount
    this._distribute()
  }

  cancel(owner) {
    const leg = this.legs.get(owner)
    if (!leg) return
    leg.wanted = 0
    leg.demandOpen = false
    this.pending = this.pending.filter((candidate) => candidate !== leg)
  }

  remove(owner) {
    const leg = this.legs.get(owner)
    if (!leg) return
    this.cancel(owner)
    this._clearIdle(leg)
    this.legs.delete(owner)
    this.available += leg.granted
    leg.granted = 0
    this._distribute()
  }

  _distribute() {
    if (this.closed || this.distributing) return
    this.distributing = true
    try {
      // Max-min water filling among queued demanders. Scarce credit is handed
      // out in rotating one-cell shares, so new arrivals cannot starve older
      // demand. A sole demander can reserve the whole pool. At every step:
      // available + sum(unspent grants) + inFlight === CIRCUIT_WINDOW.
      while (this.available > 0 && this.pending.length > 0) {
        const count = this.pending.length
        const share = Math.max(1, Math.floor(this.available / count))
        for (let i = 0; i < count && this.available > 0 && this.pending.length > 0; i++) {
          const leg = this.pending.shift()
          if (this.legs.get(leg.owner) !== leg || leg.wanted === 0) continue
          const amount = Math.min(share, leg.wanted, this.available)
          this.available -= amount
          leg.granted += amount
          leg.wanted -= amount
          if (leg.wanted > 0) this.pending.push(leg)
          if (leg.idleTimer === null) {
            leg.lastActivity = Date.now()
            this._watchIdle(leg, CREDIT_GRANT_IDLE_MS)
          }
          this.onGrant(leg.owner, amount)
        }
      }
    } finally {
      this.distributing = false
    }
  }

  _watchIdle(leg, delay) {
    leg.idleTimer = setTimeout(() => {
      leg.idleTimer = null
      if (this.closed || this.legs.get(leg.owner) !== leg || leg.granted === 0) return
      const remaining = CREDIT_GRANT_IDLE_MS - (Date.now() - leg.lastActivity)
      if (remaining > 0) this._watchIdle(leg, remaining)
      else this.onIdle(leg.owner)
    }, delay)
    if (leg.idleTimer.unref) leg.idleTimer.unref()
  }

  _clearIdle(leg) {
    clearTimeout(leg.idleTimer)
    leg.idleTimer = null
  }

  destroy() {
    this.closed = true
    this.pending.length = 0
    for (const leg of this.legs.values()) this._clearIdle(leg)
    this.legs.clear()
    this.available = 0
    this.inFlight = 0
  }
}

class LogicalRouteStream extends Duplex {
  constructor(link, streamId, onclose, circuit = null) {
    super({ highWaterMark: 1 })
    this.link = link
    this.streamId = streamId
    this.onclose = onclose
    this.circuit = circuit
    this.remoteEnded = false
    this.localEnded = false
    this.sentBytes = 0
    this.receivedBytes = 0
    this.sentFrames = 0
    this.receivedFrames = 0
    this.sendCredit = STREAM_WINDOW
    this.receiveCredit = STREAM_WINDOW
    this.streamReturnPending = 0
    this.circuitCredit = 0
    this.circuitRequested = 0
    this.circuitCanceling = false
    this.circuitReceiveCredit = CIRCUIT_WINDOW
    this.circuitReturnPending = 0
    this.creditWaiter = null
    this.writing = false
    this.idleTimer = null
    this.returnTimer = null
    this.queuedBytes = 0
    this.queue = new Array(STREAM_WINDOW)
    this.queueHead = 0
    this.queueLength = 0
    this.receivedOutstanding = 0
    this.delivered = false
    this.wantRead = false
    this.remoteResetReceived = false
    if (circuit) circuit.sendPool.add(this)
    // This internal transport can fail before Noise has attached its listener.
    this.on('error', noop)
  }

  _write(data, callback) {
    if (this.localEnded || this.link.destroyed) return callback(unavailable())
    this._sendData(data)
      .then(
        () => callback(null),
        () => callback(unavailable())
      )
      .catch(() => this.destroy(unavailable()))
  }

  async _sendData(data) {
    this.writing = true
    clearTimeout(this.idleTimer)
    this.idleTimer = null
    let offset = 0
    try {
      while (offset < data.byteLength) {
        if (this.destroying || this.link.destroyed) throw unavailable()
        if (this.sendCredit === 0) this._releaseCircuit()
        else this._requestCircuit()
        if (this.sendCredit === 0 || this.circuitCredit === 0) {
          await this._waitCredit()
          continue
        }
        const count = Math.min(
          SEND_BATCH_CELLS,
          this.sendCredit,
          this.circuitCredit,
          Math.ceil((data.byteLength - offset) / MAX_LOGICAL_PAYLOAD)
        )
        const sending = []
        for (let i = 0; i < count; i++) {
          const length = Math.min(MAX_LOGICAL_PAYLOAD, data.byteLength - offset)
          this.sentBytes += length
          this.sentFrames++
          if (this.sentBytes > MAX_STREAM_BYTES || this.sentFrames > MAX_STREAM_DATA_FRAMES)
            throw unavailable()
          this.sendCredit--
          this.circuitCredit--
          if (this.circuit) this.circuit.sendPool.sent(this)
          sending.push(
            sendLogical(
              this.link,
              this.streamId,
              LOGICAL_DATA,
              data.subarray(offset, offset + length)
            )
          )
          offset += length
        }
        await Promise.all(sending)
      }
    } finally {
      this.writing = false
      this._scheduleIdle()
    }
  }

  _waitCredit() {
    if (this.destroying || this.link.destroyed) return rejectedWrite(unavailable())
    const pending = new Promise((resolve, reject) => {
      this.creditWaiter = { resolve, reject }
    })
    pending.catch(noop)
    return pending
  }

  _wakeWriter() {
    if (!this.creditWaiter || this.sendCredit === 0 || this.circuitCredit === 0) return
    const waiter = this.creditWaiter
    this.creditWaiter = null
    waiter.resolve()
  }

  _requestCircuit() {
    if (
      this.destroying ||
      this.localEnded ||
      this.link.destroyed ||
      this.sendCredit === 0 ||
      this.circuitCanceling ||
      this.circuitRequested !== 0 ||
      this.circuitCredit > CIRCUIT_WINDOW / 2
    )
      return
    const amount = CIRCUIT_WINDOW - this.circuitCredit
    this.circuitRequested = amount
    if (this.circuit) this.circuit.sendPool.demand(this, amount)
    else sendCredit(this.link, CIRCUIT_STREAM_ID, LOGICAL_DEMAND, amount)
  }

  grantCircuit(amount) {
    if (this.destroying) return
    if (
      amount < 1 ||
      amount > this.circuitRequested ||
      this.circuitCredit + amount > CIRCUIT_WINDOW
    )
      throw invalid()
    this.circuitRequested -= amount
    this.circuitCredit += amount
    if (this.sendCredit === 0 || this.localEnded) this._releaseCircuit()
    else this._wakeWriter()
    if (!this.writing) this._scheduleIdle()
  }

  cancelCircuit() {
    if (this.destroying) return
    if (this.circuit || !this.circuitCanceling) throw invalid()
    // The acknowledgement follows every earlier grant on the ordered return
    // leg, so only the unfulfilled portion of the old demand is canceled here.
    this.circuitCanceling = false
    this.circuitRequested = 0
    if (!this.writing || this.sendCredit === 0 || this.localEnded) this._releaseCircuit()
    else this._requestCircuit()
    this._wakeWriter()
  }

  _releaseCircuit() {
    if (this.link.destroyed) return
    if (this.circuit) {
      this.circuit.sendPool.cancel(this)
      this.circuitRequested = 0
      if (this.circuitCredit !== 0) {
        const amount = this.circuitCredit
        this.circuitCredit = 0
        this.circuit.sendPool.release(this, amount)
      }
      return
    }
    if (this.circuitRequested !== 0 && !this.circuitCanceling) {
      this.circuitCanceling = true
      sendCredit(this.link, CIRCUIT_STREAM_ID, LOGICAL_DEMAND, 0)
    }
    if (this.circuitCredit !== 0) {
      const amount = this.circuitCredit
      this.circuitCredit = 0
      sendCredit(this.link, CIRCUIT_STREAM_ID, LOGICAL_RELEASE, amount)
    }
  }

  _scheduleIdle() {
    if (
      this.destroying ||
      this.link.destroyed ||
      this.idleTimer !== null ||
      (this.circuitCredit === 0 && this.circuitRequested === 0)
    )
      return
    this.idleTimer = setTimeout(() => {
      this.idleTimer = null
      if (!this.writing && !this.destroying) {
        try {
          this._releaseCircuit()
        } catch {
          this.destroy(unavailable())
        }
      }
    }, CREDIT_IDLE_MS)
    if (this.idleTimer.unref) this.idleTimer.unref()
  }

  grantStream(amount) {
    if (this.destroying) return
    if (amount < 1 || this.sendCredit + amount > STREAM_WINDOW) throw invalid()
    this.sendCredit += amount
    if (this.writing) this._requestCircuit()
    this._wakeWriter()
  }

  _read(callback) {
    try {
      // With a one-cell readable high-water mark, the next refill happens only
      // after SecretStream consumes the previously delivered encrypted bytes.
      if (this.delivered) {
        this.delivered = false
        this.receivedOutstanding--
        this.streamReturnPending++
        if (this.streamReturnPending >= STREAM_CREDIT_BATCH) {
          const amount = this.streamReturnPending
          this.streamReturnPending = 0
          this.receiveCredit += amount
          sendCredit(this.link, this.streamId, LOGICAL_CREDIT, amount)
        }
        this._returnCircuit(1)
      }
      this.wantRead = true
      this._drain()
      callback(null)
    } catch {
      callback(unavailable())
    }
  }

  _returnCircuit(amount, flush = false) {
    if (this.circuit) {
      this.circuit.consumed(amount, flush)
      return
    }
    if (this.link.destroyed) return
    this.circuitReturnPending += amount
    if (this.circuitReturnPending === 0) return
    if (!flush && this.circuitReturnPending < CIRCUIT_CREDIT_BATCH) {
      scheduleCreditReturn(this, () => this._returnCircuit(0, true))
      return
    }
    clearTimeout(this.returnTimer)
    this.returnTimer = null
    const returned = this.circuitReturnPending
    this.circuitReturnPending = 0
    this.circuitReceiveCredit += returned
    if (this.circuitReceiveCredit > CIRCUIT_WINDOW) throw invalid()
    sendCredit(this.link, CIRCUIT_STREAM_ID, LOGICAL_CREDIT, returned)
  }

  _final(callback) {
    this.localEnded = true
    try {
      this._releaseCircuit()
    } catch {
      return callback(unavailable())
    }
    sendLogical(this.link, this.streamId, LOGICAL_FIN)
      .then(
        () => callback(null),
        () => callback(unavailable())
      )
      .catch(() => this.destroy(unavailable()))
  }

  _predestroy() {
    clearTimeout(this.idleTimer)
    this.idleTimer = null
    clearTimeout(this.returnTimer)
    this.returnTimer = null
    if (this.creditWaiter) {
      const waiter = this.creditWaiter
      this.creditWaiter = null
      waiter.reject(unavailable())
    }
  }

  _destroy(callback) {
    let reset = null
    if (
      !(this.localEnded && this.remoteEnded) &&
      !this.remoteResetReceived &&
      !this.link.destroyed
    ) {
      reset = sendLogical(this.link, this.streamId, LOGICAL_RESET)
    }
    if (this.circuit) this.circuit.sendPool.remove(this)
    for (const data of this.queue) if (data) data.fill(0)
    this.queue.length = 0
    this.queueLength = 0
    this.queuedBytes = 0
    const discarded = this.receivedOutstanding
    this.receivedOutstanding = 0
    this._returnCircuit(discarded, true)
    const finish = () => {
      if (this.onclose) this.onclose(this)
      callback(null)
    }
    // A batched RESET must reach its writer before the source's close callback
    // destroys the physical leg; teardown still settles a failed send promptly.
    if (reset) reset.then(finish, finish).catch(() => this.link.destroy(unavailable()))
    else finish()
  }

  receive(data) {
    if (!this.circuit && --this.circuitReceiveCredit < 0) {
      data.fill(0)
      this.destroy(unavailable())
      return
    }
    if (this.destroying || this.remoteEnded) {
      data.fill(0)
      this._returnCircuit(1)
      if (!this.destroying) this.destroy(unavailable())
      return
    }
    this.receivedBytes += data.byteLength
    this.receivedFrames++
    this.receivedOutstanding++
    this.receiveCredit--
    if (
      this.receivedBytes > MAX_STREAM_BYTES ||
      this.receivedFrames > MAX_STREAM_DATA_FRAMES ||
      this.receiveCredit < 0 ||
      this.queueLength >= STREAM_WINDOW
    ) {
      data.fill(0)
      this.destroy(unavailable())
      return
    }
    this.queuedBytes += data.byteLength
    this.queue[(this.queueHead + this.queueLength) % STREAM_WINDOW] = data
    this.queueLength++
    this._drain()
  }

  remoteFin() {
    if (this.remoteEnded) return
    this.remoteEnded = true
    this._drain()
  }

  _drain() {
    if (this.destroying) return
    if (this.wantRead && this.queueLength > 0) {
      const data = this.queue[this.queueHead]
      this.queue[this.queueHead] = null
      this.queueHead = (this.queueHead + 1) % STREAM_WINDOW
      this.queueLength--
      this.queuedBytes -= data.byteLength
      this.wantRead = false
      this.delivered = true
      this.push(data)
    }
    if (this.remoteEnded && this.queueLength === 0 && !this.delivered) {
      this.wantRead = false
      this.push(null)
    }
  }

  remoteReset() {
    if (this.destroying) return
    this.remoteResetReceived = true
    this.destroy(unavailable())
  }
}

class DestinationCircuit {
  constructor(controller, server, rawStream, context, expiresAt) {
    this.controller = controller
    this.server = server
    this.link = new CircuitLink(
      controller,
      rawStream,
      context,
      true,
      'destination-endpoint',
      MAX_ROUTE_STREAMS
    )
    this.streams = new Map()
    this.lastStreamId = 0
    this.closed = false
    this.retired = false
    this.receiveCredit = CIRCUIT_WINDOW
    this.returnPending = 0
    this.returnTimer = null
    this.sendPool = new CircuitCreditPool(
      (raw, amount) => raw.grantCircuit(amount),
      (raw) => raw._releaseCircuit()
    )
    this.expiry = controller.clock.setTimeout(
      () => this.retire(),
      Math.max(1, Number(expiresAt - BigInt(controller.clock.now())))
    )
    if (this.expiry.unref) this.expiry.unref()
    this.link.on('payload', (payload) => this._receive(payload))
    this.link.once('close', (error) => this.destroy(error || unavailable()))
  }

  start() {
    this.link.start()
  }

  _receive(payload) {
    let message
    let stream
    try {
      message = decodeLogical(payload)
      if (message.streamId === CIRCUIT_STREAM_ID) {
        if (message.flags !== LOGICAL_CREDIT) throw invalid()
        this.sendPool.returned(message.data.readUInt16BE(0))
        return
      }
      if (message.streamId === 0) throw invalid()
      if (message.flags === LOGICAL_OPEN) return this._open(message.streamId)
      if (message.flags === LOGICAL_SPLICE_OPEN) {
        return this._openSpliced(message.streamId, readU32(message.data))
      }
      if (message.flags === LOGICAL_DATA) {
        if (this.receiveCredit === 0) throw invalid()
        this.receiveCredit--
      }
      stream = this.streams.get(message.streamId)
      if (!stream) {
        if (message.streamId % 2 === 0 && message.streamId <= this.lastStreamId) {
          if (message.flags === LOGICAL_DATA) this.consumed(1)
          return
        }
        if (message.flags === LOGICAL_FIN || message.flags === LOGICAL_RESET) return
        throw invalid()
      }
      if (message.flags === LOGICAL_DATA) {
        const data = message.data
        message.data = null
        stream.receive(data)
      } else if (message.flags === LOGICAL_FIN) {
        if (typeof stream.remoteFin === 'function') stream.remoteFin()
      } else if (message.flags === LOGICAL_RESET) {
        if (typeof stream.remoteReset === 'function') stream.remoteReset()
        else {
          stream._remoteReset = true
          stream.destroy(unavailable())
        }
      } else if (message.flags === LOGICAL_CREDIT) {
        if (typeof stream.grantStream === 'function')
          stream.grantStream(message.data.readUInt16BE(0))
      } else throw invalid()
    } catch (error) {
      if (stream) stream.destroy(unavailable())
      else this.destroy(error)
    } finally {
      if (message && message.data) message.data.fill(0)
      payload.fill(0)
    }
  }

  consumed(amount, flush = false) {
    if (this.closed) return
    this.returnPending += amount
    if (this.returnPending === 0) return
    if (!flush && this.returnPending < CIRCUIT_CREDIT_BATCH) {
      scheduleCreditReturn(this, () => this.consumed(0, true))
      return
    }
    clearTimeout(this.returnTimer)
    this.returnTimer = null
    const returned = this.returnPending
    this.returnPending = 0
    this.receiveCredit += returned
    if (this.receiveCredit > CIRCUIT_WINDOW) throw invalid()
    sendCredit(this.link, CIRCUIT_STREAM_ID, LOGICAL_CREDIT, returned)
  }

  _open(streamId) {
    if (streamId % 2 !== 0 || streamId <= this.lastStreamId) throw invalid()
    this.lastStreamId = streamId
    if (this.retired || this.server._activeStreams >= MAX_ROUTE_STREAMS) {
      sendLogical(this.link, streamId, LOGICAL_RESET)
      return
    }
    this.server._activeStreams++
    const raw = new LogicalRouteStream(
      this.link,
      streamId,
      () => {
        if (this.streams.get(streamId) !== raw) return
        this.streams.delete(streamId)
        this.server._activeStreams--
        if (this.retired && this.streams.size === 0) this.destroy()
      },
      this
    )
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

  _openSpliced(streamId, guardDownId) {
    if (streamId % 2 !== 0 || streamId <= this.lastStreamId || guardDownId === 0) throw invalid()
    this.lastStreamId = streamId
    if (this.retired || this.server._activeStreams >= MAX_ROUTE_STREAMS) {
      sendLogical(this.link, streamId, LOGICAL_RESET)
      return
    }
    const guardRaw = this.link.rawStream.rawStream
    if (!guardRaw || !guardRaw.socket || guardRaw.socket.closing) {
      sendLogical(this.link, streamId, LOGICAL_RESET)
      return
    }
    this.server._activeStreams++
    const raw = this.controller._createSpliceStream(guardRaw)
    raw.link = this.link
    raw.streamId = streamId
    let cleaned = false
    const cleanup = () => {
      if (cleaned) return
      cleaned = true
      if (this.streams.get(streamId) === raw) {
        this.streams.delete(streamId)
        this.server._activeStreams--
      }
      if (!raw._remoteReset && !this.closed && !this.link.destroyed) {
        sendLogical(this.link, streamId, LOGICAL_RESET).catch(noop)
      }
      if (this.retired && this.streams.size === 0) this.destroy()
    }
    raw.once('close', cleanup)
    this.streams.set(streamId, raw)
    raw.connect(guardRaw.socket, guardDownId, guardRaw.remotePort, guardRaw.remoteHost)
    const readyData = b4a.allocUnsafe(4)
    writeU32(readyData, raw.id)
    sendLogical(this.link, streamId, LOGICAL_SPLICE_READY, readyData).catch(() => {
      raw.destroy(unavailable())
    })
    const createSecretStream = this.server.options.createSecretStream || defaultCreateSecretStream
    const encrypted = createSecretStream(false, raw, {
      keyPair: this.server._keyPair,
      keepAlive: this.controller.dht.connectionKeepAlive
    })
    encrypted.once('close', () => {
      if (!raw.destroyed) raw.destroy()
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

  retire() {
    if (this.closed || this.retired) return false
    this.retired = true
    this.controller.clock.clearTimeout(this.expiry)
    this.controller._destinationUnavailable(this.server, this)
    if (this.streams.size === 0) this.destroy()
    return true
  }

  destroy(error) {
    if (this.closed) return false
    this.closed = true
    this.controller.clock.clearTimeout(this.expiry)
    clearTimeout(this.returnTimer)
    this.sendPool.destroy()
    for (const [id, stream] of this.streams) {
      this.streams.delete(id)
      this.server._activeStreams--
      stream.destroy(error)
    }
    this.link.destroy(error)
    this.server._routes.delete(this)
    this.controller._destinationUnavailable(this.server, this)
    return true
  }
}

class EntryCircuit {
  constructor(controller, descriptor, stream, context, diversity) {
    this.controller = controller
    this.descriptor = descriptor
    this.diversity = diversity
    this.link = new CircuitLink(
      controller,
      stream,
      context,
      false,
      'entry-destination',
      MAX_ROUTE_STREAMS
    )
    this.sources = new Map()
    this.nextStreamId = 2
    this.closed = false
    this.retired = false
    this.reverseReceiveCredit = CIRCUIT_WINDOW
    this.reverseReturnPending = 0
    this.returnTimer = null
    this.forwardPool = new CircuitCreditPool(
      (record, amount) => sendCredit(record.link, CIRCUIT_STREAM_ID, LOGICAL_CREDIT, amount),
      (record) => record.link.destroy(unavailable())
    )
    this.expiry = controller.clock.setTimeout(
      () => {
        // Stop new admission without discarding a destination reader's queued data.
        this.retired = true
      },
      Math.max(1, Number(descriptor.expiresAt - BigInt(controller.clock.now())))
    )
    if (this.expiry.unref) this.expiry.unref()
    this.link.on('payload', (payload) => this._receive(payload))
    this.link.once('close', (error) => this.destroy(error || unavailable()))
    this.link.start()
  }

  activate(stream, context) {
    if (
      this.closed ||
      this.retired ||
      this.sources.size >= MAX_ROUTE_STREAMS ||
      this.nextStreamId >= CIRCUIT_STREAM_ID
    )
      throw unavailable()
    const streamId = this.nextStreamId
    this.nextStreamId += 2
    const link = new CircuitLink(this.controller, stream, context, false, 'entry-source')
    const record = {
      streamId,
      link,
      splice: null,
      sourceEnded: false,
      destinationEnded: false,
      resetReceived: false,
      sentBytes: 0,
      sentFrames: 0,
      receivedBytes: 0,
      receivedFrames: 0,
      sendCredit: STREAM_WINDOW,
      receiveCredit: STREAM_WINDOW,
      reverseInFlight: 0
    }
    this.sources.set(streamId, record)
    this.forwardPool.add(record)
    link.on('payload', (payload) => this._fromSource(record, payload))
    link.once('close', () => {
      if (this.sources.get(streamId) !== record) return
      this.sources.delete(streamId)
      if (record.splice) {
        const s = record.splice
        record.splice = null
        s.close(unavailable())
      }
      this.forwardPool.remove(record)
      this._returnReverse(record.reverseInFlight, true)
      record.reverseInFlight = 0
      if (this.closed || record.resetReceived || (record.sourceEnded && record.destinationEnded))
        return
      sendLogical(this.link, streamId, LOGICAL_RESET)
    })
    if (!this.controller.spliced) {
      sendLogical(this.link, streamId, LOGICAL_OPEN).catch((error) => link.destroy(error))
    }
    link.start()
    return streamId
  }

  _fromSource(record, payload) {
    let message
    try {
      message = decodeLogical(payload)
      if (message.streamId === CIRCUIT_STREAM_ID) {
        const amount = message.data.readUInt16BE(0)
        if (message.flags === LOGICAL_CREDIT) {
          if (amount > record.reverseInFlight) throw invalid()
          record.reverseInFlight -= amount
          this._returnReverse(amount)
        } else if (message.flags === LOGICAL_DEMAND) {
          if (amount !== 0 && record.sourceEnded) throw invalid()
          this.forwardPool.demand(record, amount, true)
          if (amount === 0) sendCredit(record.link, CIRCUIT_STREAM_ID, LOGICAL_DEMAND, 0)
        } else if (message.flags === LOGICAL_RELEASE) {
          this.forwardPool.release(record, amount)
        } else throw invalid()
        return
      }
      if (message.streamId !== 0) throw invalid()
      if (message.flags === LOGICAL_OPEN) {
        if (!this.controller.spliced || record.splice) throw invalid()
        sendLogical(this.link, record.streamId, LOGICAL_OPEN).catch((error) =>
          record.link.destroy(error)
        )
        return
      }
      if (message.flags === LOGICAL_SPLICE_OPEN) {
        if (record.splice) throw invalid()
        const prevUdxId = readU32(message.data)
        const s2Raw = record.link.rawStream.rawStream
        const guardRaw = this.link.rawStream.rawStream
        const up = this.controller._createSpliceStream(s2Raw)
        const down = this.controller._createSpliceStream(guardRaw)
        record.splice = watchSplicedPair(this.controller, up, down, () => {
          if (record.splice && record.splice.up === up) record.splice = null
        })
        up.connect(s2Raw.socket, prevUdxId, s2Raw.remotePort, s2Raw.remoteHost)
        const outData = b4a.allocUnsafe(4)
        writeU32(outData, down.id)
        sendLogical(this.link, record.streamId, LOGICAL_SPLICE_OPEN, outData).catch((error) =>
          record.link.destroy(error)
        )
        return
      }
      if (message.flags === LOGICAL_FIN) record.sourceEnded = true
      if (message.flags === LOGICAL_RESET) {
        record.resetReceived = true
        if (record.splice) {
          const s = record.splice
          record.splice = null
          s.close(unavailable())
        }
      }
      if (message.flags === LOGICAL_DATA) {
        if (record.sourceEnded || record.sendCredit === 0) throw invalid()
        record.sentBytes += message.data.byteLength
        record.sentFrames++
        if (record.sentBytes > MAX_STREAM_BYTES || record.sentFrames > MAX_STREAM_DATA_FRAMES) {
          throw unavailable()
        }
        this.forwardPool.sent(record)
        record.sendCredit--
      } else if (message.flags === LOGICAL_CREDIT) {
        const amount = message.data.readUInt16BE(0)
        if (record.receiveCredit + amount > STREAM_WINDOW) throw invalid()
        record.receiveCredit += amount
      }
      sendLogical(this.link, record.streamId, message.flags, message.data).catch((error) =>
        record.link.destroy(error)
      )
    } catch (error) {
      record.link.destroy(error)
    } finally {
      if (message) message.data.fill(0)
      payload.fill(0)
    }
  }

  _receive(payload) {
    let message
    let record
    let charged = false
    try {
      message = decodeLogical(payload)
      if (message.streamId === CIRCUIT_STREAM_ID) {
        if (message.flags !== LOGICAL_CREDIT) throw invalid()
        this.forwardPool.returned(message.data.readUInt16BE(0))
        return
      }
      if (message.flags === LOGICAL_DATA) {
        if (this.reverseReceiveCredit === 0) throw invalid()
        this.reverseReceiveCredit--
        charged = true
      }
      record = this.sources.get(message.streamId)
      if (!record) {
        if (
          message.streamId > 0 &&
          message.streamId % 2 === 0 &&
          message.streamId < this.nextStreamId
        ) {
          if (charged) this._returnReverse(1)
          return
        }
        if (message.flags === LOGICAL_FIN || message.flags === LOGICAL_RESET) return
        throw invalid()
      }
      if (message.flags === LOGICAL_OPEN || message.flags === LOGICAL_SPLICE_OPEN) throw invalid()
      if (message.flags === LOGICAL_SPLICE_READY) {
        if (!record.splice || record.splice.active) throw invalid()
        record.splice.active = true
        const nextUdxId = readU32(message.data)
        const guardRaw = this.link.rawStream.rawStream
        record.splice.down.connect(
          guardRaw.socket,
          nextUdxId,
          guardRaw.remotePort,
          guardRaw.remoteHost
        )
        record.splice.up.relayTo(record.splice.down)
        record.splice.down.relayTo(record.splice.up)
        const outData = b4a.allocUnsafe(4)
        writeU32(outData, record.splice.up.id)
        sendLogical(record.link, 0, LOGICAL_SPLICE_READY, outData).catch((error) =>
          record.link.destroy(error)
        )
        return
      }
      if (message.flags === LOGICAL_FIN) record.destinationEnded = true
      if (message.flags === LOGICAL_RESET) {
        record.resetReceived = true
        if (record.splice) {
          const s = record.splice
          record.splice = null
          s.close(unavailable())
        }
      }
      if (message.flags === LOGICAL_DATA) {
        record.reverseInFlight++
        charged = false
        if (record.destinationEnded || record.receiveCredit === 0) throw invalid()
        record.receivedBytes += message.data.byteLength
        record.receivedFrames++
        if (
          record.receivedBytes > MAX_STREAM_BYTES ||
          record.receivedFrames > MAX_STREAM_DATA_FRAMES
        ) {
          throw unavailable()
        }
        record.receiveCredit--
      } else if (message.flags === LOGICAL_CREDIT) {
        const amount = message.data.readUInt16BE(0)
        if (record.sendCredit + amount > STREAM_WINDOW) throw invalid()
        record.sendCredit += amount
      }
      sendLogical(record.link, 0, message.flags, message.data).catch((error) =>
        record.link.destroy(error)
      )
    } catch (error) {
      if (charged && record) this._returnReverse(1)
      if (record) record.link.destroy(error)
      else this.destroy(error)
    } finally {
      if (message) message.data.fill(0)
      payload.fill(0)
    }
  }

  _returnReverse(amount, flush = false) {
    if (this.closed) return
    this.reverseReturnPending += amount
    if (this.reverseReturnPending === 0) return
    if (!flush && this.reverseReturnPending < CIRCUIT_CREDIT_BATCH) {
      scheduleCreditReturn(this, () => this._returnReverse(0, true))
      return
    }
    clearTimeout(this.returnTimer)
    this.returnTimer = null
    const returned = this.reverseReturnPending
    this.reverseReturnPending = 0
    this.reverseReceiveCredit += returned
    if (this.reverseReceiveCredit > CIRCUIT_WINDOW) throw invalid()
    sendCredit(this.link, CIRCUIT_STREAM_ID, LOGICAL_CREDIT, returned)
  }

  destroy(error) {
    if (this.closed) return false
    this.closed = true
    this.controller.clock.clearTimeout(this.expiry)
    clearTimeout(this.returnTimer)
    this.forwardPool.destroy()
    for (const record of this.sources.values()) {
      if (record.splice) {
        const s = record.splice
        record.splice = null
        s.close(error)
      }
      record.link.destroy(error)
    }
    this.sources.clear()
    this.link.destroy(error)
    clearDescriptor(this.descriptor)
    this.descriptor = null
    return true
  }
}

class PinnedGuards {
  constructor() {
    this.current = null
    this.alternates = []
    this.rotateAt = 0
  }

  ensure(relays, now) {
    if (this.current && now < this.rotateAt && !this.candidates().every((g) => g.unreachable))
      return
    const seen = new Set()
    const guards = []
    for (const publicKey of relays) {
      const id = key(publicKey)
      if (seen.has(id)) continue
      seen.add(id)
      guards.push({ publicKey: b4a.from(publicKey), diversityKey: null, unreachable: false })
      if (guards.length === GUARD_SET_SIZE) break
    }
    this.current = guards.shift() || null
    this.alternates = guards
    this.rotateAt = now + GUARD_LIFETIME_MS
  }

  candidates() {
    return this.current ? [this.current, ...this.alternates] : []
  }

  isUnavailable(publicKey) {
    if (this.current && this.current.unreachable && same(this.current.publicKey, publicKey)) {
      return true
    }
    for (const guard of this.alternates) {
      if (guard.unreachable && same(guard.publicKey, publicKey)) return true
    }
    return false
  }

  select(guard) {
    guard.unreachable = false
    const candidates = this.candidates()
    if (!candidates.includes(guard)) return
    this.current = guard
    this.alternates = candidates.filter((candidate) => candidate !== guard)
  }

  failed(guard) {
    guard.unreachable = true
    if (guard !== this.current) return
    const candidates = this.candidates().filter((candidate) => candidate !== guard)
    candidates.push(guard)
    this.current = candidates.shift()
    this.alternates = candidates
  }

  clear() {
    this.current = null
    this.alternates = []
    this.rotateAt = 0
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
    this._routes = new Set()
    this._activeStreams = 0
    this._republishAfter = false
    this._publishing = null
    this._refreshTimer = null
    this._seq = 0n
    this._guards = null
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

  async listen(keyPair) {
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
    this.observer = options.observer === undefined ? null : options.observer
    this.clock = options.clock || SYSTEM_CLOCK
    if (this.observer !== null && typeof this.observer !== 'function') throw invalid()
    this.spliced =
      options.spliced !== undefined
        ? Boolean(options.spliced)
        : options.profile === 'spliced' || this.observer === null
    this.relayKeyPair = this.relay ? this.keyPair || createKeyPair() : null
    this.descriptors = new OverlayDescriptorService(
      this.dht,
      this.relayKeyPair ? this.relayKeyPair.publicKey : null,
      this.clock.now,
      this.clock
    )
    this.relayServer = null
    this.relayAnnouncers = []
    this.relayAddresses = new WeakMap()
    this.servers = new Set()
    this.entryCircuits = new Map()
    this.pendingEntryRegistrations = new Map()
    this.lastSequences = new Map()
    this.sourceGuards = new PinnedGuards()
    this.destinationGuards = new Map()
    this.destinationBridges = new Set()
    this.resolverStreams = new Set()
    this.controlSessions = new Set()
    this.controlPeers = new Map()
    this.controlStreams = new WeakMap()
    this.controlTasks = new Map()
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
    const keyPair = options.keyPair || createKeyPair()
    const createSecretStream = options.createSecretStream || defaultCreateSecretStream
    const stream = createSecretStream(true, null, {
      publicKey: keyPair.publicKey,
      remotePublicKey: destinationPublicKey,
      autoStart: false,
      keepAlive: this.dht.connectionKeepAlive
    })
    if (!options.keyPair) stream.once('close', () => keyPair.secretKey.fill(0))
    const start = async () => {
      let route = null
      try {
        const useSpliced = this.spliced && !options.createSecretStream
        route = await this._openSession(destinationPublicKey, useSpliced)
        if (stream.destroying || stream.destroyed) {
          route.destroy()
          return
        }
        stream.start(route, { keyPair, remotePublicKey: destinationPublicKey })
      } catch {
        if (route) route.destroy(unavailable())
        stream.destroy(unavailable())
      } finally {
        const active = this.directDestinationKeys.get(destinationKey)
        if (active === 1) this.directDestinationKeys.delete(destinationKey)
        else if (active > 1) this.directDestinationKeys.set(destinationKey, active - 1)
      }
    }
    void start()
    return stream
  }

  async suspend() {
    if (this.destroyed || this.suspended) return
    this.suspended = true
    this.state = 'SUSPENDED'
    const controlsClosing = this._cancelControlSessions()
    await Promise.all([controlsClosing, this.descriptors.suspend()])
    await Promise.all(this.relayAnnouncers.map((announcer) => announcer.suspend()))
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
    await this.descriptors.resume()
    for (const announcer of this.relayAnnouncers) announcer.resume()
    this.state = 'READY'
    for (const server of this.servers) await this._publish(server)
  }

  async destroy() {
    if (this.destroyed) return
    this.destroyed = true
    this.observer = null
    this.state = 'DESTROYED'
    const controlsClosing = this._cancelControlSessions()
    const serversClosing = Promise.allSettled(Array.from(this.servers, (server) => server.close()))
    this.servers.clear()
    for (const entry of this.entryCircuits.values()) entry.destroy(unavailable())
    this.entryCircuits.clear()
    for (const stream of this.pendingEntryRegistrations.values()) stream.destroy(unavailable())
    this.pendingEntryRegistrations.clear()
    for (const bridge of this.bridges) bridge.destroy(unavailable())
    this.bridges.clear()
    this.destinationBridges.clear()
    for (const stream of this.resolverStreams) stream.destroy(unavailable())
    this.resolverStreams.clear()
    const relayClosing = this.relayServer ? this.relayServer.close() : null
    this.relayServer = null
    await Promise.all([
      controlsClosing,
      serversClosing,
      relayClosing,
      this.descriptors.destroy(),
      ...this.relayAnnouncers.map((announcer) => announcer.stop())
    ])
    this.relayAnnouncers = []
    if (this.relayKeyPair) {
      this.relayKeyPair.publicKey.fill(0)
      this.relayKeyPair.secretKey.fill(0)
      this.relayKeyPair = null
    }
    this.directDestinationKeys.clear()
    this.sourceGuards.clear()
    for (const guards of this.destinationGuards.values()) guards.clear()
    this.destinationGuards.clear()
  }

  async _start() {
    await this.baseReady()
    if (this.destroyed) throw unavailable()
    if (this.relay) {
      const relayServer = this.createDirectServer({ firewall: () => false })
      relayServer.on('connection', (stream) => this._onRelayConnection(stream))
      this.relayServer = relayServer
      await relayServer.listen(this.relayKeyPair)
      this.relayAnnouncers = RELAY_TARGETS.map(
        (target) => new Announcer(this.dht, this.relayKeyPair, target)
      )
      await Promise.all(this.relayAnnouncers.map((announcer) => announcer.start()))
    }
    await this.descriptors.ready()
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
    const identity = key(keyPair.publicKey)
    let guards = this.destinationGuards.get(identity)
    if (!guards) {
      guards = new PinnedGuards()
      this.destinationGuards.set(identity, guards)
    }
    server._guards = guards
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
    this.clock.clearTimeout(server._refreshTimer)
    server._refreshTimer = null
    server._route = null
    server._republishAfter = false
    for (const route of server._routes) route.destroy(unavailable())
  }

  _destinationUnavailable(server, route) {
    if (server._route !== route) return
    server._route = null
    this.clock.clearTimeout(server._refreshTimer)
    server._refreshTimer = null
    if (this.destroyed || this.suspended || server.closed || server.suspended) return
    if (server._publishing) server._republishAfter = true
    else void this._publish(server).catch(safetyCatch)
  }

  async _publish(server) {
    if (server._publishing) return server._publishing
    const publishing = this._publishNow(server)
    server._publishing = publishing
    try {
      return await publishing
    } finally {
      if (server._publishing === publishing) {
        server._publishing = null
        const retry = server._republishAfter && !server._route
        server._republishAfter = false
        if (retry && !this.destroyed && !this.suspended && !server.closed && !server.suspended) {
          void this._publish(server).catch(safetyCatch)
        }
      }
    }
  }

  _nextDescriptorSequence(server, remote) {
    const id = key(server._keyPair.publicKey)
    let previous = this.lastSequences.get(id) || server._seq
    if (remote && remote.seq > previous) previous = remote.seq
    if (previous === 0xffffffffffffffffn) throw unavailable()
    const now = BigInt(this.clock.now())
    const next = now > previous ? now : previous + 1n
    this.lastSequences.set(id, next)
    server._seq = next
    return next
  }

  async _publishNow(server) {
    if (this.destroyed || this.suspended || server.closed || server.suspended || !server._keyPair) {
      throw unavailable()
    }
    const relays = shuffle(await this.descriptors.discoverRelays())
    if (relays.length < 2) throw unavailable()
    server._guards.ensure(relays, this.clock.now())
    let failure = unavailable()
    const failedGuards = new Set()
    const pinned = server._guards.candidates()
    const pinnedSet = new Set(pinned.map((g) => key(g.publicKey)))
    const guardCandidates = [
      ...pinned,
      ...relays
        .filter((pk) => !pinnedSet.has(key(pk)))
        .map((pk) => ({ publicKey: pk, diversityKey: null, unreachable: false }))
    ]
    for (const guard of guardCandidates) {
      for (const entryRelayPublicKey of relays) {
        if (
          same(entryRelayPublicKey, guard.publicKey) ||
          failedGuards.has(key(entryRelayPublicKey))
        )
          continue
        try {
          await this._publishThroughGuard(server, guard, entryRelayPublicKey)
          server._guards.select(guard)
          return
        } catch (error) {
          failure = error
          if (this.destroyed || this.suspended || server.closed || server.suspended) throw error
          if (guard.unreachable) {
            failedGuards.add(key(guard.publicKey))
            break
          }
        }
      }
    }
    throw failure
  }

  async _publishThroughGuard(server, guard, entryRelayPublicKey) {
    const destinationGuardPublicKey = guard.publicKey
    const routeToken = random(32)
    const localContext = createRouteContext()
    const downstreamContext = createRouteContext()
    const admissionKeyPair = createKeyPair()
    let connection = null
    let descriptor = null
    try {
      try {
        connection = await this._connectRelay(destinationGuardPublicKey, admissionKeyPair)
        guard.unreachable = false
        guard.diversityKey = this._relayDiversityKey(connection)
      } catch (error) {
        server._guards.failed(guard)
        throw error
      }
      await this._writeControl(
        connection,
        controlHeader(OP_BUILD_DESTINATION),
        OP_BUILD_DESTINATION,
        'header'
      )
      if ((await this._readControl(connection, 1, OP_BUILD_DESTINATION, 'status'))[0] !== STATUS_OK)
        throw unavailable()
      const challenge = await this._readControl(
        connection,
        DESTINATION_ADMISSION_CHALLENGE_BYTES,
        OP_BUILD_DESTINATION,
        'destination-admission'
      )
      const period = periodOf(this.clock.now())
      let identity = null
      try {
        identity = signDestinationAdmission(
          server._keyPair,
          period,
          challenge,
          admissionKeyPair.publicKey,
          destinationGuardPublicKey
        )
        await this._writeControl(
          connection,
          identity,
          OP_BUILD_DESTINATION,
          'destination-admission'
        )
      } finally {
        challenge.fill(0)
        if (identity) identity.fill(0)
      }
      const recovery = await this._readControl(
        connection,
        2,
        OP_BUILD_DESTINATION,
        'destination-recovery'
      )
      if (recovery[0] !== STATUS_OK) throw unavailable()
      let previous = null
      if (recovery[1] === RECOVERY_PRESENT) {
        previous = decodeDescriptor(
          await this._readControl(
            connection,
            DESCRIPTOR_BYTES,
            OP_BUILD_DESTINATION,
            'destination-recovery'
          ),
          {
            now: this.clock.now(),
            expectedDestinationPublicKey: server._keyPair.publicKey,
            expectedPeriod: period
          }
        )
      } else if (recovery[1] !== RECOVERY_ABSENT) {
        throw invalid()
      }
      let seq
      try {
        seq = this._nextDescriptorSequence(server, previous)
      } finally {
        clearDescriptor(previous)
      }
      const now = BigInt(this.clock.now())
      const expiresAt = now + BigInt(ROUTE_LIFETIME_MS)
      descriptor = encodeDescriptor({
        destinationKeyPair: server._keyPair,
        entryRelayPublicKey,
        destinationGuardPublicKey,
        routeToken,
        seq,
        expiresAt,
        period
      })
      const request = b4a.concat([
        descriptor,
        encodeRouteContext(localContext),
        encodeRouteContext(downstreamContext),
        this._relayDiversityDigest(connection)
      ])
      await this._writeControl(connection, request, OP_BUILD_DESTINATION, 'destination-build')
      const response = await this._readControl(connection, 1, OP_BUILD_DESTINATION, 'status')
      if (response[0] !== STATUS_OK) throw unavailable()
      const entryDiversity = await this._readControl(
        connection,
        32,
        OP_BUILD_DESTINATION,
        'destination-build'
      )
      requireDiverse(this._relayDiversityDigest(connection), entryDiversity)
      if (this.destroyed || this.suspended || server.closed || server.suspended) throw unavailable()
      const route = new DestinationCircuit(this, server, connection, localContext, expiresAt)
      connection = null
      this.clock.clearTimeout(server._refreshTimer)
      server._refreshTimer = null
      if (server._descriptor) server._descriptor.fill(0)
      server._descriptor = b4a.from(descriptor)
      server._route = route
      server._routes.add(route)
      route.start()
      if (route.closed) throw unavailable()
      for (const previous of server._routes) {
        if (previous !== route) previous.retire()
      }
      clearRouteContext(downstreamContext)
      const refreshDelayMs = refreshDelay()
      server._refreshTimer = this.clock.setTimeout(() => {
        if (!server.closed && !server.suspended) void this._publish(server).catch(safetyCatch)
      }, refreshDelayMs)
      if (server._refreshTimer.unref) server._refreshTimer.unref()
      if (this.observer) {
        observe(this, {
          type: 'descriptor-published',
          wire: descriptor,
          period,
          seq,
          expiresAt,
          refreshDelayMs
        })
      }
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

  async _resolveThrough(inbox, destinationPublicKey) {
    for (const period of lookupPeriods(this.clock.now())) {
      const target = descriptorTarget(destinationPublicKey, period)
      const request = b4a.allocUnsafe(41)
      request[0] = SOURCE_RESOLVE
      writeU64(request, period, 1)
      target.copy(request, 9)
      let response = null
      try {
        this._observeControl(
          'control-write',
          inbox.link.rawStream,
          SOURCE_RESOLVE,
          'source-resolve',
          request
        )
        await inbox.link.send(request)
        response = await inbox.read()
        this._observeControl(
          'control-read',
          inbox.link.rawStream,
          SOURCE_RESOLVE,
          'source-resolved',
          response
        )
        if (response.byteLength === 1 && response[0] === STATUS_UNAVAILABLE) continue
        if (response.byteLength !== 1 + DESCRIPTOR_BYTES || response[0] !== STATUS_OK) {
          throw invalid()
        }
        return decodeDescriptor(response.subarray(1), {
          now: this.clock.now(),
          expectedDestinationPublicKey: destinationPublicKey,
          expectedPeriod: period
        })
      } finally {
        request.fill(0)
        target.fill(0)
        if (response) response.fill(0)
      }
    }
    throw unavailable()
  }

  _createSpliceStream(peerRaw) {
    if (!peerRaw || !peerRaw.socket || peerRaw.socket.closing) throw unavailable()
    const expectedHost = peerRaw.remoteHost
    const expectedPort = peerRaw.remotePort
    let stream = this.dht.createRawStream({
      framed: true,
      firewall(socket, port, host) {
        return port !== expectedPort || host !== expectedHost
      }
    })
    while (stream.id === 0) {
      stream.destroy()
      stream = this.dht.createRawStream({
        framed: true,
        firewall(socket, port, host) {
          return port !== expectedPort || host !== expectedHost
        }
      })
    }
    stream.on('error', noop)
    return stream
  }

  async _openSession(destinationPublicKey, useSpliced = this.spliced) {
    await this.ready()
    if (this.destroyed || this.suspended || this.relay) throw unavailable()
    const relays = shuffle(await this.descriptors.discoverRelays())
    this.sourceGuards.ensure(relays, this.clock.now())
    let descriptor = null
    let resolveAttempts = 0
    let entryDiversity = null
    let guardDiversity = null
    const knownDiversity = new Map()
    const ConflictWithDescriptor = (div) =>
      Boolean(
        div &&
        ((entryDiversity && b4a.equals(div, entryDiversity)) ||
          (guardDiversity && b4a.equals(div, guardDiversity)))
      )
    const pinnedCandidates = this.sourceGuards.candidates()
    const pinnedIds = new Set(pinnedCandidates.map((g) => key(g.publicKey)))
    const extraCandidates = relays
      .filter((pk) => !pinnedIds.has(key(pk)))
      .map((pk) => ({ publicKey: pk, diversityKey: null, unreachable: false, ephemeral: true }))
    const allFirstCandidates = [...pinnedCandidates, ...extraCandidates]
    try {
      for (const guard of allFirstCandidates) {
        if (guard.ephemeral && !descriptor) break
        const firstSafetyRelayPublicKey = guard.publicKey
        const attemptedSeconds = new Set()
        while (resolveAttempts < MAX_SOURCE_ATTEMPTS) {
          if (
            descriptor &&
            (same(firstSafetyRelayPublicKey, descriptor.entryRelayPublicKey) ||
              same(firstSafetyRelayPublicKey, descriptor.destinationGuardPublicKey) ||
              ConflictWithDescriptor(knownDiversity.get(key(firstSafetyRelayPublicKey))))
          ) {
            break
          }
          const firstKnownDiv = knownDiversity.get(key(firstSafetyRelayPublicKey))
          const secondSafetyRelayPublicKey = relays.find((candidate) => {
            const cid = key(candidate)
            const cDiv = knownDiversity.get(cid)
            return (
              !same(candidate, firstSafetyRelayPublicKey) &&
              !attemptedSeconds.has(cid) &&
              !this.sourceGuards.isUnavailable(candidate) &&
              !(firstKnownDiv && cDiv && b4a.equals(firstKnownDiv, cDiv)) &&
              !ConflictWithDescriptor(cDiv) &&
              (!descriptor ||
                (!same(candidate, descriptor.entryRelayPublicKey) &&
                  !same(candidate, descriptor.destinationGuardPublicKey)))
            )
          })
          if (!secondSafetyRelayPublicKey) break
          attemptedSeconds.add(key(secondSafetyRelayPublicKey))
          let connection = null
          let localContext = null
          let middleContext = null
          let entryContext = null
          let link = null
          let inbox = null
          let request = null
          let firstConnected = false
          let countedResolve = false
          try {
            if (!descriptor) {
              resolveAttempts++
              countedResolve = true
            }
            connection = await this._connectRelay(firstSafetyRelayPublicKey)
            firstConnected = true
            guard.unreachable = false
            guard.diversityKey = this._relayDiversityKey(connection)
            const firstDiversity = this._relayDiversityDigest(connection)
            knownDiversity.set(key(firstSafetyRelayPublicKey), b4a.from(firstDiversity))
            if (ConflictWithDescriptor(firstDiversity)) {
              throw unavailable()
            }
            localContext = createRouteContext()
            middleContext = createRouteContext()
            request = b4a.concat([
              controlHeader(OP_BUILD_SOURCE),
              secondSafetyRelayPublicKey,
              encodeRouteContext(localContext),
              encodeRouteContext(middleContext)
            ])
            await this._writeControl(connection, request, OP_BUILD_SOURCE, 'source-build')
            request.fill(0)
            request = null
            if (
              (await this._readControl(connection, 1, OP_BUILD_SOURCE, 'status'))[0] !== STATUS_OK
            )
              throw unavailable()
            const secondDiversity = await this._readControl(
              connection,
              32,
              OP_BUILD_SOURCE,
              'source-build'
            )
            knownDiversity.set(key(secondSafetyRelayPublicKey), b4a.from(secondDiversity))
            if (b4a.equals(firstDiversity, secondDiversity)) {
              if (countedResolve && !descriptor) resolveAttempts--
              throw unavailable()
            }
            requireDiverse(firstDiversity, secondDiversity)
            link = new CircuitLink(this, connection, localContext, true, 'source-endpoint')
            connection = null
            localContext = null
            inbox = new ControlInbox(link)
            if (!descriptor) {
              const resolved = await this._resolveThrough(inbox, destinationPublicKey)
              clearDescriptor(descriptor)
              descriptor = resolved
            }
            if (
              same(firstSafetyRelayPublicKey, descriptor.entryRelayPublicKey) ||
              same(firstSafetyRelayPublicKey, descriptor.destinationGuardPublicKey) ||
              same(secondSafetyRelayPublicKey, descriptor.entryRelayPublicKey) ||
              same(secondSafetyRelayPublicKey, descriptor.destinationGuardPublicKey)
            ) {
              continue
            }
            entryContext = createRouteContext()
            request = b4a.concat([
              b4a.from([SOURCE_ACTIVATE]),
              descriptor.wire,
              encodeRouteContext(entryContext),
              firstDiversity,
              secondDiversity
            ])
            this._observeControl(
              'control-write',
              link.rawStream,
              SOURCE_ACTIVATE,
              'source-extend',
              request
            )
            await link.send(request)
            const response = await inbox.read()
            this._observeControl(
              'control-read',
              link.rawStream,
              SOURCE_ACTIVATE,
              'source-extend',
              response
            )
            try {
              if (response.byteLength !== 65 || response[0] !== STATUS_OK) throw unavailable()
              entryDiversity = b4a.from(response.subarray(1, 33))
              guardDiversity = b4a.from(response.subarray(33, 65))
              requireDiverse(firstDiversity, secondDiversity, entryDiversity, guardDiversity)
            } finally {
              response.fill(0)
            }
            if (this.observer) {
              observe(this, {
                type: 'source-route-selected',
                firstSafetyRelayPublicKey,
                secondSafetyRelayPublicKey,
                entryRelayPublicKey: descriptor.entryRelayPublicKey,
                destinationGuardPublicKey: descriptor.destinationGuardPublicKey
              })
            }
            const routeLink = link
            if (useSpliced) {
              const s1Raw = routeLink.rawStream.rawStream
              const cUdx = this._createSpliceStream(s1Raw)
              cUdx.link = routeLink
              cUdx.streamId = 0
              let spliceSettled = false
              try {
                const openData = b4a.allocUnsafe(4)
                writeU32(openData, cUdx.id)
                await sendLogical(routeLink, 0, LOGICAL_SPLICE_OPEN, openData)
                const replyPayload = await inbox.read()
                let replyMsg
                try {
                  replyMsg = decodeLogical(replyPayload)
                } finally {
                  replyPayload.fill(0)
                }
                if (replyMsg.streamId !== 0 || replyMsg.flags !== LOGICAL_SPLICE_READY) {
                  replyMsg.data.fill(0)
                  throw invalid()
                }
                const s1UpId = readU32(replyMsg.data)
                replyMsg.data.fill(0)
                cUdx.connect(s1Raw.socket, s1UpId, s1Raw.remotePort, s1Raw.remoteHost)
                spliceSettled = true
              } finally {
                if (!spliceSettled) cUdx.destroy()
              }
              const queued = inbox.detach()
              inbox = null
              const receiveSplice = (payload) => {
                try {
                  const message = decodeLogical(payload)
                  if (message && message.data) message.data.fill(0)
                  if (message.streamId === 0 && message.flags === LOGICAL_RESET) {
                    cUdx._remoteReset = true
                    cUdx.destroy(unavailable())
                  }
                } catch {
                  cUdx.destroy(unavailable())
                } finally {
                  payload.fill(0)
                }
              }
              routeLink.on('payload', receiveSplice)
              routeLink.once('close', (error) => {
                if (!cUdx.destroyed) cUdx.destroy(error || unavailable())
              })
              cUdx.once('close', () => {
                if (!cUdx._remoteReset && !routeLink.destroyed) {
                  sendLogical(routeLink, 0, LOGICAL_RESET)
                    .then(
                      () => routeLink.destroy(),
                      () => routeLink.destroy()
                    )
                    .catch(() => routeLink.destroy())
                } else {
                  routeLink.destroy()
                }
              })
              for (const payload of queued) receiveSplice(payload)
              link = null
              return cUdx
            }
            if (this.spliced) {
              await sendLogical(routeLink, 0, LOGICAL_OPEN)
            }
            const route = new LogicalRouteStream(routeLink, 0, () => routeLink.destroy())
            const receive = (payload) => {
              let message
              try {
                message = decodeLogical(payload)
                if (message.streamId === CIRCUIT_STREAM_ID) {
                  if (message.flags === LOGICAL_CREDIT)
                    route.grantCircuit(message.data.readUInt16BE(0))
                  else if (message.flags === LOGICAL_DEMAND && message.data.readUInt16BE(0) === 0)
                    route.cancelCircuit()
                  else throw invalid()
                  return
                }
                if (message.streamId !== 0 || message.flags === LOGICAL_OPEN) throw invalid()
                if (message.flags === LOGICAL_DATA) {
                  const data = message.data
                  message.data = null
                  route.receive(data)
                } else if (message.flags === LOGICAL_FIN) route.remoteFin()
                else if (message.flags === LOGICAL_RESET) route.remoteReset()
                else if (message.flags === LOGICAL_CREDIT)
                  route.grantStream(message.data.readUInt16BE(0))
                else throw invalid()
              } catch {
                route.destroy(unavailable())
              } finally {
                if (message && message.data) message.data.fill(0)
                payload.fill(0)
              }
            }
            const queued = inbox.detach()
            inbox = null
            routeLink.on('payload', receive)
            routeLink.once('close', (error) => {
              if (!route.destroyed) route.destroy(error || unavailable())
            })
            for (const payload of queued) receive(payload)
            link = null
            return route
          } catch {
            if (!firstConnected) {
              this.sourceGuards.failed(guard)
              if (!guard.ephemeral) {
                break
              }
            }
          } finally {
            if (inbox) inbox.destroy()
            if (link) link.destroy()
            if (connection) connection.destroy()
            if (request) request.fill(0)
            clearRouteContext(localContext)
            clearRouteContext(middleContext)
            clearRouteContext(entryContext)
          }
        }
      }
    } finally {
      clearDescriptor(descriptor)
    }
    throw unavailable()
  }

  async _connectRelay(publicKey, keyPair = createKeyPair(), session = null) {
    if (session) session.check()
    if (this.directDestinationKeys.has(key(publicKey))) {
      this.directDestinationSends++
      throw unavailable()
    }
    const stream = this.connectDirect(publicKey, { keyPair })
    stream.on('error', noop)
    try {
      if (session) session.ownStream(stream)
      await opened(stream, 8000)
      if (session) session.check()
      this._relayDiversityKey(stream)
      return stream
    } catch (error) {
      stream.destroy(error)
      throw error
    }
  }

  _relayDiversityKey(stream) {
    const raw = stream.rawStream
    if (!raw) throw unavailable()
    const { remoteHost, remotePort } = raw
    let observed = this.relayAddresses.get(stream)
    if (observed && observed.host === remoteHost && observed.port === remotePort)
      return observed.key
    const allowLoopback = observed
      ? observed.allowLoopback
      : isLoopback(normalizedIP(this.dht.socket.address().host))
    const value = relayDiversityKey(remoteHost, remotePort, allowLoopback)
    if (observed) {
      if (observed.key !== value) throw unavailable()
      observed.host = remoteHost
      observed.port = remotePort
    } else {
      const digest = b4a.allocUnsafe(32)
      sodium.crypto_generichash(digest, b4a.from(DIVERSITY_DOMAIN + value))
      observed = { host: remoteHost, port: remotePort, key: value, digest, allowLoopback }
      this.relayAddresses.set(stream, observed)
    }
    return value
  }

  _relayDiversityDigest(stream) {
    this._relayDiversityKey(stream)
    return this.relayAddresses.get(stream).digest
  }

  _assertRelayAddress(stream) {
    if (this.relayAddresses.has(stream)) this._relayDiversityKey(stream)
  }

  _observeControl(type, stream, opcode, label, bytes) {
    if (!this.observer) return
    observe(this, {
      type,
      opcode,
      label,
      remotePublicKey: fixed(stream.remotePublicKey, 32) ? stream.remotePublicKey : null,
      bytes
    })
  }

  async _readControl(stream, size, opcode, label) {
    const session = this.controlStreams.get(stream)
    if (session) session.check()
    const timeout = session
      ? label === 'header'
        ? CONTROL_OPCODE_TIMEOUT_MS
        : CONTROL_READ_TIMEOUT_MS
      : CONTROL_TIMEOUT_MS
    const bytes = await readExactly(stream, size, timeout)
    try {
      if (session) session.check()
      this._observeControl(
        'control-read',
        stream,
        opcode === null ? bytes[1] : opcode,
        label,
        bytes
      )
      this._assertRelayAddress(stream)
      return bytes
    } catch (error) {
      bytes.fill(0)
      throw error
    }
  }

  _writeControl(stream, bytes, opcode, label) {
    const session = this.controlStreams.get(stream)
    if (session) session.check()
    this._assertRelayAddress(stream)
    this._observeControl('control-write', stream, opcode, label, bytes)
    return writeAll(stream, bytes)
  }

  _writeStatus(stream, opcode, value = STATUS_OK, label = 'status') {
    return this._writeControl(stream, b4a.from([value]), opcode, label)
  }

  _admitControlSession(stream) {
    if (!this.relay || this.destroyed || this.suspended) return null
    if (this.controlSessions.size >= MAX_CONTROL_SESSIONS) return null
    if (!fixed(stream.remotePublicKey, 32)) return null
    // Count identities and observed address buckets independently: rotating keys
    // or ports cannot bypass a public /24 or /48 bucket. As in route diversity,
    // locally bound loopback uses host+port so independent local nodes can coexist.
    // The observed address is an admission heuristic, not an authenticated IP.
    const peers = [
      'key:' + key(stream.remotePublicKey),
      'address:' + this._relayDiversityKey(stream)
    ]
    if (peers.some((peer) => (this.controlPeers.get(peer) || 0) >= MAX_PEER_CONTROL_SESSIONS)) {
      return null
    }
    return new ControlSession(this, stream, peers)
  }

  _cancelControlSessions() {
    for (const session of this.controlSessions) session.cancel()
    for (const stream of this.controlTasks.keys()) stream.destroy(unavailable())
    return Promise.allSettled(this.controlTasks.values())
  }

  async _rejectControl(stream) {
    if (stream.destroying || stream.destroyed) return
    const timer = setTimeout(() => stream.destroy(unavailable()), CONTROL_OPCODE_TIMEOUT_MS)
    try {
      await this._writeStatus(stream, 0, STATUS_UNAVAILABLE)
      stream.end()
      // Native acknowledgement must precede destruction or the status can be lost.
      await stream.flush()
    } catch {
    } finally {
      clearTimeout(timer)
      stream.destroy(unavailable())
    }
  }

  async _runControlSession(stream, session) {
    try {
      await this._handleRelayConnection(stream, session)
      session.check()
      // All handler-owned work has settled, and the route/bridge now owns streams.
    } catch {
      try {
        await this._rejectControl(stream)
      } finally {
        session.cancel()
      }
    } finally {
      // Cancellation does not release quota until descriptor operations and dials
      // have unwound their awaited work, including the service's owner tracking.
      session.finish()
    }
  }

  _onRelayConnection(stream) {
    stream.on('error', noop)
    let session = null
    try {
      session = this._admitControlSession(stream)
    } catch {}
    const pending = session ? this._runControlSession(stream, session) : this._rejectControl(stream)
    this.controlTasks.set(stream, pending)
    pending
      .then(
        () => this.controlTasks.delete(stream),
        () => {
          this.controlTasks.delete(stream)
          stream.destroy(unavailable())
        }
      )
      .catch(noop)
  }

  async _handleRelayConnection(stream, session) {
    if (!this.relay || this.destroyed || this.suspended) throw unavailable()
    const header = await this._readControl(stream, 2, null, 'header')
    if (header[0] !== CONTROL_VERSION) throw invalid()
    const opcode = header[1]
    if (opcode === OP_BUILD_DESTINATION) return this._handleBuildDestination(stream, session)
    if (opcode === OP_ENTRY_REGISTER) return this._handleEntryRegister(stream)
    if (opcode === OP_BUILD_SOURCE) return this._handleBuildSource(stream, session)
    if (opcode === OP_EXTEND_SOURCE) return this._handleExtendSource(stream, session)
    if (opcode === OP_ENTRY_ACTIVATE) return this._handleEntryActivate(stream)
    throw invalid()
  }

  async _handleBuildDestination(stream, session) {
    const challenge = random(DESTINATION_ADMISSION_CHALLENGE_BYTES)
    let localContext = null
    let downstreamContext = null
    let next = null
    let descriptor = null
    let previous = null
    let recovery = null
    let request = null
    let blindedPublicKey = null
    let target = null
    try {
      await this._writeControl(
        stream,
        b4a.concat([b4a.from([STATUS_OK]), challenge]),
        OP_BUILD_DESTINATION,
        'destination-admission'
      )
      const identity = await this._readControl(
        stream,
        DESTINATION_ADMISSION_IDENTITY_BYTES,
        OP_BUILD_DESTINATION,
        'destination-admission'
      )
      const period = readU64(identity)
      blindedPublicKey = b4a.from(identity.subarray(8, 40))
      const admitted =
        lookupPeriods(this.clock.now()).includes(period) &&
        verifyDestinationAdmission(
          identity,
          challenge,
          stream.remotePublicKey,
          this.relayKeyPair.publicKey
        )
      identity.fill(0)
      if (!admitted) throw invalid()
      target = hash(blindedPublicKey)

      try {
        previous = await this.descriptors.getByTarget(target, period, { owner: session })
      } catch (error) {
        if (error.code !== 'ERR_PRIVACY_UNAVAILABLE') throw error
      }
      session.check()
      recovery = b4a.allocUnsafe(2 + (previous ? DESCRIPTOR_BYTES : 0))
      recovery[0] = STATUS_OK
      recovery[1] = previous ? RECOVERY_PRESENT : RECOVERY_ABSENT
      if (previous) previous.wire.copy(recovery, 2)
      await this._writeControl(stream, recovery, OP_BUILD_DESTINATION, 'destination-recovery')

      descriptor = decodeDescriptor(
        await this._readControl(
          stream,
          DESCRIPTOR_BYTES,
          OP_BUILD_DESTINATION,
          'destination-build'
        ),
        {
          now: this.clock.now(),
          expectedPeriod: period
        }
      )
      if (!same(descriptor.blindedPublicKey, blindedPublicKey)) throw invalid()
      if (!same(descriptor.destinationGuardPublicKey, this.relayKeyPair.publicKey)) throw invalid()
      localContext = decodeRouteContext(
        await this._readControl(
          stream,
          ROUTE_CONTEXT_BYTES,
          OP_BUILD_DESTINATION,
          'destination-build'
        )
      )
      downstreamContext = decodeRouteContext(
        await this._readControl(
          stream,
          ROUTE_CONTEXT_BYTES,
          OP_BUILD_DESTINATION,
          'destination-build'
        )
      )
      const guardDiversity = await this._readControl(
        stream,
        32,
        OP_BUILD_DESTINATION,
        'destination-build'
      )
      next = await this._connectRelay(descriptor.entryRelayPublicKey, this.relayKeyPair, session)
      const entryDiversity = this._relayDiversityDigest(next)
      requireDiverse(guardDiversity, entryDiversity)
      request = b4a.concat([
        controlHeader(OP_ENTRY_REGISTER),
        descriptor.wire,
        encodeRouteContext(downstreamContext),
        guardDiversity,
        entryDiversity
      ])
      await this._writeControl(next, request, OP_ENTRY_REGISTER, 'entry-register')
      if ((await this._readControl(next, 1, OP_ENTRY_REGISTER, 'status'))[0] !== STATUS_OK)
        throw unavailable()
      await this.descriptors.put(descriptor.wire, { owner: session })
      await this._writeControl(next, b4a.from([ENTRY_COMMIT]), OP_ENTRY_REGISTER, 'entry-commit')
      if ((await this._readControl(next, 1, OP_ENTRY_REGISTER, 'entry-commit'))[0] !== STATUS_OK)
        throw unavailable()
      await this._writeControl(
        stream,
        b4a.concat([b4a.from([STATUS_OK]), entryDiversity]),
        OP_BUILD_DESTINATION,
        'destination-build'
      )
      const left = new CircuitLink(
        this,
        stream,
        localContext,
        false,
        'guard-destination',
        MAX_ROUTE_STREAMS
      )
      const right = new CircuitLink(
        this,
        next,
        downstreamContext,
        true,
        'guard-entry',
        MAX_ROUTE_STREAMS
      )
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
      if (blindedPublicKey) blindedPublicKey.fill(0)
      if (target) target.fill(0)
      if (request) request.fill(0)
      if (recovery) recovery.fill(0)
      clearDescriptor(previous)
      clearDescriptor(descriptor)
    }
  }

  async _handleEntryRegister(stream) {
    let descriptor = null
    let context = null
    let token = null
    try {
      descriptor = decodeDescriptor(
        await this._readControl(stream, DESCRIPTOR_BYTES, OP_ENTRY_REGISTER, 'entry-register'),
        { now: this.clock.now() }
      )
      if (!same(descriptor.entryRelayPublicKey, this.relayKeyPair.publicKey)) throw invalid()
      if (!same(stream.remotePublicKey, descriptor.destinationGuardPublicKey)) throw invalid()
      context = decodeRouteContext(
        await this._readControl(stream, ROUTE_CONTEXT_BYTES, OP_ENTRY_REGISTER, 'entry-register')
      )
      const guardDiversity = await this._readControl(
        stream,
        32,
        OP_ENTRY_REGISTER,
        'entry-register'
      )
      const entryDiversity = await this._readControl(
        stream,
        32,
        OP_ENTRY_REGISTER,
        'entry-register'
      )
      requireDiverse(guardDiversity, entryDiversity)
      if (!same(guardDiversity, this._relayDiversityDigest(stream))) throw unavailable()
      token = key(descriptor.routeToken)
      if (this.entryCircuits.has(token) || this.pendingEntryRegistrations.has(token)) {
        throw invalid()
      }
      this.pendingEntryRegistrations.set(token, stream)
      await this._writeStatus(stream, OP_ENTRY_REGISTER)
      if (
        (await this._readControl(stream, 1, OP_ENTRY_REGISTER, 'entry-commit'))[0] !== ENTRY_COMMIT
      )
        throw invalid()
      const entry = new EntryCircuit(
        this,
        descriptor,
        stream,
        context,
        b4a.concat([guardDiversity, entryDiversity])
      )
      descriptor = null
      context = null
      this.entryCircuits.set(token, entry)
      entry.link.once('close', () => {
        if (this.entryCircuits.get(token) === entry) this.entryCircuits.delete(token)
      })
      await this._writeStatus(stream, OP_ENTRY_REGISTER, STATUS_OK, 'entry-commit')
    } finally {
      if (token !== null && this.pendingEntryRegistrations.get(token) === stream) {
        this.pendingEntryRegistrations.delete(token)
      }
      clearRouteContext(context)
      clearDescriptor(descriptor)
    }
  }

  async _handleBuildSource(stream, session) {
    let localContext = null
    let downstreamContext = null
    let next = null
    let request = null
    try {
      const secondSafetyRelayPublicKey = await this._readControl(
        stream,
        32,
        OP_BUILD_SOURCE,
        'source-build'
      )
      if (same(secondSafetyRelayPublicKey, this.relayKeyPair.publicKey)) throw invalid()
      localContext = decodeRouteContext(
        await this._readControl(stream, ROUTE_CONTEXT_BYTES, OP_BUILD_SOURCE, 'source-build')
      )
      downstreamContext = decodeRouteContext(
        await this._readControl(stream, ROUTE_CONTEXT_BYTES, OP_BUILD_SOURCE, 'source-build')
      )
      next = await this._connectRelay(secondSafetyRelayPublicKey, this.relayKeyPair, session)
      request = b4a.concat([controlHeader(OP_EXTEND_SOURCE), encodeRouteContext(downstreamContext)])
      await this._writeControl(next, request, OP_EXTEND_SOURCE, 'source-build')
      if ((await this._readControl(next, 1, OP_EXTEND_SOURCE, 'status'))[0] !== STATUS_OK)
        throw unavailable()
      await this._writeControl(
        stream,
        b4a.concat([b4a.from([STATUS_OK]), this._relayDiversityDigest(next)]),
        OP_BUILD_SOURCE,
        'source-build'
      )
      const left = new CircuitLink(this, stream, localContext, false, 'source-safety-1-in')
      localContext = null
      const right = new CircuitLink(this, next, downstreamContext, true, 'source-safety-1-out')
      downstreamContext = null
      next = null
      const bridge = transformBridge(this, left, right)
      this.bridges.add(bridge)
    } finally {
      if (request) request.fill(0)
      clearRouteContext(localContext)
      clearRouteContext(downstreamContext)
      if (next) next.destroy()
    }
  }

  async _handleExtendSource(stream, session) {
    let descriptor = null
    let localContext = null
    let downstreamContext = null
    let left = null
    let inbox = null
    let next = null
    let request = null
    let sourceDiversity = null
    this.resolverStreams.add(stream)
    try {
      if (same(stream.remotePublicKey, this.relayKeyPair.publicKey)) throw invalid()
      localContext = decodeRouteContext(
        await this._readControl(stream, ROUTE_CONTEXT_BYTES, OP_EXTEND_SOURCE, 'source-build')
      )
      await this._writeStatus(stream, OP_EXTEND_SOURCE)
      left = new CircuitLink(this, stream, localContext, false, 'source-safety-2-in')
      localContext = null
      // This is still setup: resolution and activation must share the original
      // session deadline even though the transport already carries sealed cells.
      inbox = new ControlInbox(left, CONTROL_READ_TIMEOUT_MS)
      const resolvedPeriods = new Set()
      for (;;) {
        const command = await inbox.read()
        const opcode = command.byteLength === 0 ? 0 : command[0]
        this._observeControl(
          'control-read',
          stream,
          opcode,
          opcode === SOURCE_RESOLVE ? 'source-resolve' : 'source-extend',
          command
        )
        try {
          if (command[0] === SOURCE_RESOLVE) {
            if (command.byteLength !== 41 || resolvedPeriods.size >= 3) throw invalid()
            const period = readU64(command, 1)
            if (resolvedPeriods.has(period) || !lookupPeriods(this.clock.now()).includes(period)) {
              throw invalid()
            }
            resolvedPeriods.add(period)
            let resolved = null
            let response = null
            try {
              try {
                resolved = await this.descriptors.getByTarget(command.subarray(9), period, {
                  owner: session
                })
              } catch (error) {
                if (error.code !== 'ERR_PRIVACY_UNAVAILABLE') throw error
              }
              session.check()
              response = resolved
                ? b4a.concat([b4a.from([STATUS_OK]), resolved.wire])
                : b4a.from([STATUS_UNAVAILABLE])
              this._observeControl(
                'control-write',
                stream,
                SOURCE_RESOLVE,
                'source-resolved',
                response
              )
              await left.send(response)
            } finally {
              if (response) response.fill(0)
              clearDescriptor(resolved)
            }
            continue
          }
          if (
            command[0] !== SOURCE_ACTIVATE ||
            command.byteLength !== 1 + DESCRIPTOR_BYTES + ROUTE_CONTEXT_BYTES + 64
          ) {
            throw invalid()
          }
          descriptor = decodeDescriptor(command.subarray(1, 1 + DESCRIPTOR_BYTES), {
            now: this.clock.now()
          })
          if (
            same(this.relayKeyPair.publicKey, descriptor.entryRelayPublicKey) ||
            same(this.relayKeyPair.publicKey, descriptor.destinationGuardPublicKey) ||
            same(stream.remotePublicKey, descriptor.entryRelayPublicKey) ||
            same(stream.remotePublicKey, descriptor.destinationGuardPublicKey)
          ) {
            throw invalid()
          }
          const contextEnd = 1 + DESCRIPTOR_BYTES + ROUTE_CONTEXT_BYTES
          downstreamContext = decodeRouteContext(command.subarray(1 + DESCRIPTOR_BYTES, contextEnd))
          sourceDiversity = b4a.from(command.subarray(contextEnd))
          requireDiverse(sourceDiversity.subarray(0, 32), sourceDiversity.subarray(32))
          if (!same(sourceDiversity.subarray(0, 32), this._relayDiversityDigest(stream))) {
            throw unavailable()
          }
          break
        } finally {
          command.fill(0)
        }
      }
      next = await this._connectRelay(descriptor.entryRelayPublicKey, this.relayKeyPair, session)
      request = b4a.concat([
        controlHeader(OP_ENTRY_ACTIVATE),
        descriptor.wire,
        encodeRouteContext(downstreamContext),
        sourceDiversity
      ])
      await this._writeControl(next, request, OP_ENTRY_ACTIVATE, 'entry-activate')
      if ((await this._readControl(next, 1, OP_ENTRY_ACTIVATE, 'status'))[0] !== STATUS_OK)
        throw unavailable()
      const diversity = await this._readControl(next, 64, OP_ENTRY_ACTIVATE, 'entry-activate')
      if (!same(diversity.subarray(32), this._relayDiversityDigest(next))) throw unavailable()
      requireDiverse(
        sourceDiversity.subarray(0, 32),
        sourceDiversity.subarray(32),
        diversity.subarray(0, 32),
        diversity.subarray(32)
      )
      const activation = b4a.concat([b4a.from([STATUS_OK]), diversity])
      this._observeControl('control-write', stream, SOURCE_ACTIVATE, 'source-extend', activation)
      await left.send(activation)
      const queued = inbox.detach()
      inbox = null
      const right = new CircuitLink(this, next, downstreamContext, true, 'source-safety-2-out')
      downstreamContext = null
      next = null
      const bridge = transformBridge(this, left, right)
      this.bridges.add(bridge)
      for (const payload of queued) left.emit('payload', payload)
      left = null
    } finally {
      this.resolverStreams.delete(stream)
      if (inbox) inbox.destroy()
      if (left) left.destroy()
      if (request) request.fill(0)
      if (sourceDiversity) sourceDiversity.fill(0)
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
      descriptor = decodeDescriptor(
        await this._readControl(stream, DESCRIPTOR_BYTES, OP_ENTRY_ACTIVATE, 'entry-activate'),
        { now: this.clock.now() }
      )
      if (
        !same(descriptor.entryRelayPublicKey, this.relayKeyPair.publicKey) ||
        same(stream.remotePublicKey, descriptor.destinationGuardPublicKey) ||
        same(stream.remotePublicKey, this.relayKeyPair.publicKey)
      ) {
        throw invalid()
      }
      context = decodeRouteContext(
        await this._readControl(stream, ROUTE_CONTEXT_BYTES, OP_ENTRY_ACTIVATE, 'entry-activate')
      )
      const sourceDiversity = await this._readControl(
        stream,
        64,
        OP_ENTRY_ACTIVATE,
        'entry-activate'
      )
      const entry = this.entryCircuits.get(key(descriptor.routeToken))
      if (!entry || !same(entry.descriptor.wire, descriptor.wire)) throw unavailable()
      if (!same(sourceDiversity.subarray(32), this._relayDiversityDigest(stream)))
        throw unavailable()
      requireDiverse(
        sourceDiversity.subarray(0, 32),
        sourceDiversity.subarray(32),
        entry.diversity.subarray(0, 32),
        entry.diversity.subarray(32)
      )
      await this._writeControl(
        stream,
        b4a.concat([b4a.from([STATUS_OK]), entry.diversity]),
        OP_ENTRY_ACTIVATE,
        'entry-activate'
      )
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
  createPrivatePeerController
}
