'use strict'

// Native presence (design packet §4.6, version 3 amendment). A source looks up, publishes
// and revokes blinded presence records through a presence terminal at the end of a native
// circuit. The terminal runs each request as one Gate D mutable get or put on the DHT. It
// sees the blinded public key and the sealed record only, never the identity, the reader
// secret or the descriptor.
//
// One circuit carries one operation: its source sends a single class5 request, retried at
// 0, 250, 500 and 750 ms and then every second up to 16 attempts, and takes the first
// authentic reply that names the request's nonce.

const b4a = require('b4a')
const c = require('compact-encoding')
const sodium = require('sodium-universal')

const { COMMANDS } = require('../constants')
const m = require('../messages')
const Persistent = require('../persistent')
const { PrivateRouteError } = require('./errors')
const { DatagramReplayWindow } = require('./counters')
const { hashPeer } = require('./peer-crypto')
const { PEER_CONTEXT_CLASS, PEER_MESSAGE_ID } = require('./peer-protocol')
const { encodePeerSemantic, decodePeerSemantic } = require('./peer-semantic-wire')
const { sealPeerContextFrame, openPeerContextFrame } = require('./peer-m3-context')
const { chargePeerLedger } = require('./peer-ledger')
const {
  encodeDHTRequest,
  MUTABLE_GET_POLICIES,
  MUTABLE_PUT_POLICIES
} = require('./dht-command-policy')
const {
  PRESENCE_RECORD_SIZE,
  PRESENCE_RECORD_VERSION,
  RECORD_TYPE,
  TOMBSTONE_SCOPE,
  createBlindedSigner,
  deriveBlindedPublicKey,
  encodePresenceRecord,
  openPresenceRecord,
  isRecordTombstoneTarget,
  publishPeriods,
  lookupPeriods,
  recordDigestOf,
  resolvePresenceState
} = require('./blinded-presence')

const PUBLIC_READER_DOMAIN = 'hyperdht-private-routes/presence/public-reader/v1'
// A presence circuit names this digest as its terminal hop's payload parameters, so the
// terminal hands the circuit to its presence service instead of a route purpose owner. Only
// the terminal receives it; the guard and the safety receive independent random digests.
const PRESENCE_PARAMETERS_DIGEST = hashPeer('hyperdht-private-routes/presence/parameters/v1', [])

const FINALIZE = PEER_CONTEXT_CLASS.PEER_TAIL_FINALIZE_DATAGRAM
const SOURCE_TO_TERMINAL = 0
const TERMINAL_TO_SOURCE = 1
const REPLAY_WINDOW = 64
const MAX_ATTEMPTS = 16
const FAST_RETRY_MS = 250
const FAST_ATTEMPTS = 4
const SLOW_RETRY_MS = 1000
// A request's last attempt leaves this long for its reply before the operation fails.
const FINAL_WAIT_MS = 1000
const MIN_WRITE_QUORUM = 3
const MIN_READ_QUORUM = 2
// Each circuit direction carries the build's own minimum (closure, discovery and both
// extension exchanges: 50 cells) plus one cell for every request or reply attempt.
const PRESENCE_CIRCUIT_LIMITS = Object.freeze({
  maxCells: 50 + MAX_ATTEMPTS,
  maxCommands: 4,
  idleTimeoutMs: 30_000
})
const DEFAULT_TERMINAL_POLICY = Object.freeze({
  maxConcurrent: 32,
  maxOperationsPerCircuit: 4,
  minOperationIntervalMs: 250
})
// A terminal circuit that hears no request for this long after its last reply ends.
const TERMINAL_IDLE_MS = 15_000
// Each operation allocates at the terminal once, in its outgoing direction; every reply
// attempt is one physical cell the carrier charges to the circuit's own send ledger.
const LOOKUP_CHARGE = Object.freeze({ cells: 0, bytes: 0n, commands: 1 })
const STORE_CHARGE = Object.freeze({ cells: 0, bytes: 0n, commands: 2 })

const REPLIES = new Map([
  [
    PEER_MESSAGE_ID.PRESENCE_LOOKUP_V2,
    new Set([
      PEER_MESSAGE_ID.PRESENCE_RECORD_V2,
      PEER_MESSAGE_ID.PRESENCE_ABSENT_V2,
      PEER_MESSAGE_ID.PRESENCE_UNAVAILABLE_V2
    ])
  ],
  [
    PEER_MESSAGE_ID.PRESENCE_STORE_V2,
    new Set([PEER_MESSAGE_ID.PRESENCE_STORED_V2, PEER_MESSAGE_ID.PRESENCE_UNAVAILABLE_V2])
  ]
])

function unavailable() {
  return PrivateRouteError.ROUTE_UNAVAILABLE()
}

function fixed(value, size) {
  return b4a.isBuffer(value) && value.byteLength === size
}

function clear(value) {
  if (b4a.isBuffer(value)) value.fill(0)
}

function isObject(value) {
  return value !== null && typeof value === 'object'
}

function isRevision(value) {
  return Number.isInteger(value) && value >= 0 && value <= 0xffffffff
}

function isPeriod(value) {
  return typeof value === 'bigint' && value >= 0n && value < 1n << 64n
}

function readU32(buffer, offset) {
  return (
    buffer[offset] * 0x1000000 +
    ((buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | buffer[offset + 3])
  )
}

function frameCounter(frame) {
  let value = 0n
  for (let index = 0; index < 8; index++) value = (value << 8n) | BigInt(frame[index])
  return value
}

function randomNonce() {
  const nonce = b4a.allocUnsafeSlow(16)
  do sodium.randombytes_buf(nonce)
  while (nonce.every((byte) => byte === 0))
  return nonce
}

function blindedTarget(publicKey) {
  const target = b4a.allocUnsafeSlow(32)
  sodium.crypto_generichash(target, publicKey)
  return target
}

// Reads an options object with exactly the named keys, each an own data property.
function readOptions(options, names) {
  if (!isObject(options)) throw PrivateRouteError.INVALID_DESCRIPTOR()
  const result = {}
  for (const key of Object.keys(options)) {
    if (!names.includes(key)) throw PrivateRouteError.INVALID_DESCRIPTOR()
  }
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(options, name)
    if (descriptor && !Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
      throw PrivateRouteError.INVALID_DESCRIPTOR()
    }
    result[name] = descriptor ? descriptor.value : undefined
  }
  return result
}

function readKeyPair(value) {
  if (!isObject(value) || !fixed(value.publicKey, 32) || !fixed(value.secretKey, 64)) {
    throw PrivateRouteError.INVALID_KEY()
  }
  return value
}

// A reader secret is either the caller's own or the public one every reader can derive
// from the identity; the operation works on a copy and erases it.
function readerSecretFor(readerSecret, publicKey) {
  if (readerSecret === undefined || readerSecret === null) {
    return derivePublicReaderSecret(publicKey)
  }
  if (!fixed(readerSecret, 32)) throw PrivateRouteError.INVALID_KEY()
  return b4a.from(readerSecret)
}

function readClock(now) {
  if (now === undefined) return Date.now
  if (typeof now !== 'function') throw PrivateRouteError.INVALID_DESCRIPTOR()
  return now
}

// The public reader secret: anyone who knows the identity can read a record sealed under
// it, so the record hides its descriptor only from those who do not.
function derivePublicReaderSecret(publicKey) {
  if (!fixed(publicKey, 32)) throw PrivateRouteError.INVALID_KEY()
  return hashPeer(PUBLIC_READER_DOMAIN, [publicKey])
}

// The view a final-tail lease hands out stays owned by whoever consumed it. Its ledgers
// belong to the circuit's branch and are never released here.
function eraseView(view) {
  clear(view.circuitId)
  clear(view.tailControlTranscriptDigest)
  clear(view.terminalAdvertisementDigest)
  for (const value of Object.values(view.finalizeKeys)) clear(value)
  clear(view.purposeTerminalPublicKey)
  clear(view.purposeTerminalSecretKey)
  clear(view.terminalAdvertisement260)
}

function sealFinalize(view, direction, counter, payload) {
  const keys = view.finalizeKeys
  return sealPeerContextFrame({
    contextClass: FINALIZE,
    circuitId: view.circuitId,
    generation: view.generation,
    direction,
    counter,
    key: direction === SOURCE_TO_TERMINAL ? keys.finalizeForwardKey : keys.finalizeReverseKey,
    noncePrefix:
      direction === SOURCE_TO_TERMINAL
        ? keys.finalizeForwardNoncePrefix
        : keys.finalizeReverseNoncePrefix,
    payload
  })
}

// Opens one class5 envelope sent in `direction`, admits its counter to the replay window
// and returns a copy of its payload; anything else is null.
function openFinalize(view, direction, window, envelope) {
  if (!isObject(envelope) || envelope.contextClass !== FINALIZE) return null
  const keys = view.finalizeKeys
  let opened = null
  try {
    opened = openPeerContextFrame(
      {
        contextClass: FINALIZE,
        circuitId: view.circuitId,
        generation: view.generation,
        direction,
        counter: frameCounter(envelope.frame),
        key: direction === SOURCE_TO_TERMINAL ? keys.finalizeForwardKey : keys.finalizeReverseKey,
        noncePrefix:
          direction === SOURCE_TO_TERMINAL
            ? keys.finalizeForwardNoncePrefix
            : keys.finalizeReverseNoncePrefix
      },
      envelope.frame
    )
    window.acceptAuthenticated(opened.counter)
    return b4a.from(opened.payload)
  } catch {
    return null
  } finally {
    if (opened) clear(opened.plaintext)
    clear(envelope.frame)
  }
}

// ---------------------------------------------------------------------------
// Source: one circuit per operation
// ---------------------------------------------------------------------------

// Sends the request until an authentic reply to it arrives, the attempts run out or the
// circuit ends. Resolves the decoded reply; its fields are copies the caller erases.
function exchangeOnCircuit(view, request) {
  const carrier = view.carrier
  const window = new DatagramReplayWindow({ window: REPLAY_WINDOW })
  const accepted = REPLIES.get(request.messageId)
  let counter = 0n
  let attempts = 0
  let settled = false
  let cancelTimer = null

  return new Promise((resolve, reject) => {
    const finish = (err, reply) => {
      if (settled) return
      settled = true
      if (cancelTimer) cancelTimer()
      window.destroy()
      if (err) reject(err)
      else resolve(reply)
    }

    const arm = (delayMs, callback) => {
      try {
        cancelTimer = carrier.schedule(delayMs, callback)
      } catch {
        finish(unavailable())
      }
    }

    const attempt = () => {
      if (settled) return
      if (attempts === MAX_ATTEMPTS) {
        finish(unavailable())
        return
      }
      attempts++
      let frame = null
      try {
        frame = sealFinalize(view, SOURCE_TO_TERMINAL, counter++, request.wire)
        carrier.sendFinalizeFrame(frame).catch(() => {})
      } catch {
        finish(unavailable())
        return
      } finally {
        clear(frame)
      }
      if (attempts === MAX_ATTEMPTS) arm(FINAL_WAIT_MS, attempt)
      else arm(attempts < FAST_ATTEMPTS ? FAST_RETRY_MS : SLOW_RETRY_MS, attempt)
    }

    const receive = () => {
      if (settled) return
      let reservation = null
      try {
        reservation = carrier.reserveReceive()
      } catch {
        finish(unavailable())
        return
      }
      carrier.receiveEnvelope(reservation).then(
        (envelope) => {
          const payload = openFinalize(view, TERMINAL_TO_SOURCE, window, envelope)
          if (payload !== null) {
            let decoded = null
            try {
              decoded = decodePeerSemantic(payload)
              if (
                accepted.has(decoded.messageId) &&
                b4a.equals(decoded.fields.requestNonce, request.nonce)
              ) {
                const fields = {}
                for (const [name, value] of Object.entries(decoded.fields)) {
                  fields[name] = b4a.isBuffer(value) ? b4a.from(value) : value
                }
                finish(null, { messageId: decoded.messageId, fields })
              }
            } catch {
              // An authentic frame that is not a reply to this request is dropped.
            } finally {
              if (decoded) clear(decoded.body)
              clear(payload)
            }
          }
          receive()
        },
        () => finish(unavailable())
      )
    }

    receive()
    attempt()
  })
}

function eraseReply(reply) {
  if (!reply) return
  for (const value of Object.values(reply.fields)) clear(value)
}

async function presenceExchange(runtime, request) {
  if (!isObject(runtime) || typeof runtime.buildTail !== 'function') {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  const lease = await runtime.buildTail({
    forwardLimits: PRESENCE_CIRCUIT_LIMITS,
    reverseLimits: PRESENCE_CIRCUIT_LIMITS,
    payloadParametersDigest: PRESENCE_PARAMETERS_DIGEST,
    terminal: null
  })
  let view = null
  try {
    view = lease.consume()
    return await exchangeOnCircuit(view, request)
  } finally {
    if (view) eraseView(view)
    await Promise.resolve(lease.revoke()).catch(() => {})
  }
}

function presenceRequest(messageId, fields) {
  const nonce = randomNonce()
  return {
    messageId,
    nonce,
    wire: encodePeerSemantic(messageId, { requestNonce: nonce, ...fields })
  }
}

function eraseRequest(request) {
  clear(request.nonce)
  clear(request.wire)
}

// Looks a presence record up for `publicKey`, the current period first. The first period
// that holds a record decides; a period with no record falls through to the next one.
async function lookupPresence(runtime, options) {
  const fields = readOptions(options, ['publicKey', 'readerSecret', 'period', 'previous', 'now'])
  if (!fixed(fields.publicKey, 32)) throw PrivateRouteError.INVALID_KEY()
  if (fields.period !== undefined && fields.period !== null && !isPeriod(fields.period)) {
    throw PrivateRouteError.INVALID_DESCRIPTOR()
  }
  const now = readClock(fields.now)
  const previous = fields.previous === undefined ? null : fields.previous
  const publicKey = b4a.from(fields.publicKey)
  const readerSecret = readerSecretFor(fields.readerSecret, publicKey)
  try {
    const periods =
      fields.period === undefined || fields.period === null ? lookupPeriods(now()) : [fields.period]
    for (const period of periods) {
      const blindedPublicKey = deriveBlindedPublicKey(publicKey, period)
      const request = presenceRequest(PEER_MESSAGE_ID.PRESENCE_LOOKUP_V2, { blindedPublicKey })
      let reply = null
      let opened = null
      try {
        reply = await presenceExchange(runtime, request)
        if (reply.messageId === PEER_MESSAGE_ID.PRESENCE_ABSENT_V2) continue
        if (reply.messageId !== PEER_MESSAGE_ID.PRESENCE_RECORD_V2) throw unavailable()
        opened = openPresenceRecord({
          identityPublicKey: publicKey,
          period,
          revision: reply.fields.revision,
          readerSecret,
          value: reply.fields.value,
          signature: reply.fields.signature
        })
        return resolvePresenceState({
          previous,
          opened: { ...opened, recordDigest: recordDigestOf(reply.fields.value) }
        })
      } finally {
        if (opened) {
          for (const value of Object.values(opened)) clear(value)
          if (opened.tombstone) clear(opened.tombstone.target)
        }
        eraseReply(reply)
        eraseRequest(request)
        clear(blindedPublicKey)
      }
    }
    return null
  } finally {
    clear(readerSecret)
    clear(publicKey)
  }
}

// Stores one record per publish period, each through its own circuit, and returns what
// was stored. A period whose terminal cannot confirm its write fails the whole operation.
async function storeRecords(runtime, fields, record) {
  const signerKeyPair = readKeyPair(fields.signerKeyPair)
  if (!isRevision(fields.revision)) throw PrivateRouteError.INVALID_DESCRIPTOR()
  const now = readClock(fields.now)
  const readerSecret = readerSecretFor(fields.readerSecret, signerKeyPair.publicKey)
  const results = []
  try {
    const periods = publishPeriods(now())
    let targets = null
    if (record.type === RECORD_TYPE.TOMBSTONE && record.scope === TOMBSTONE_SCOPE.RECORD) {
      if (!(record.targets instanceof Map)) throw PrivateRouteError.INVALID_DESCRIPTOR()
      targets = new Map()
      for (const period of periods) {
        const target = record.targets.get(period)
        if (!isRecordTombstoneTarget(target)) throw PrivateRouteError.INVALID_DESCRIPTOR()
        targets.set(period, b4a.from(target))
      }
    }
    for (const period of periods) {
      const signer = createBlindedSigner(signerKeyPair, period)
      let encoded = null
      let signature = null
      let request = null
      let reply = null
      try {
        encoded =
          record.type === RECORD_TYPE.DESCRIPTOR
            ? encodePresenceRecord({
                signer,
                period,
                revision: fields.revision,
                readerSecret,
                type: RECORD_TYPE.DESCRIPTOR,
                descriptor: record.descriptor
              })
            : encodePresenceRecord({
                signer,
                period,
                revision: fields.revision,
                readerSecret,
                type: RECORD_TYPE.TOMBSTONE,
                tombstone: {
                  scope: record.scope,
                  target: targets ? targets.get(period) : b4a.alloc(32)
                }
              })
        signature = encoded.signMutable(fields.revision, encoded.value, {
          publicKey: encoded.publicKey
        })
        request = presenceRequest(PEER_MESSAGE_ID.PRESENCE_STORE_V2, {
          blindedPublicKey: encoded.publicKey,
          revision: fields.revision,
          signature,
          value: encoded.value
        })
        reply = await presenceExchange(runtime, request)
        if (
          reply.messageId !== PEER_MESSAGE_ID.PRESENCE_STORED_V2 ||
          reply.fields.revision !== fields.revision ||
          reply.fields.written < MIN_WRITE_QUORUM ||
          reply.fields.confirmed < MIN_READ_QUORUM
        ) {
          throw unavailable()
        }
        results.push(
          Object.freeze({
            period,
            blindedPublicKey: b4a.from(encoded.publicKey),
            revision: fields.revision,
            recordDigest: recordDigestOf(encoded.value)
          })
        )
      } finally {
        signer.destroy()
        clear(signature)
        eraseReply(reply)
        if (request) eraseRequest(request)
      }
    }
    return results
  } catch (err) {
    for (const result of results) {
      clear(result.blindedPublicKey)
      clear(result.recordDigest)
    }
    throw err
  } finally {
    clear(readerSecret)
  }
}

async function publishPresence(runtime, options) {
  const fields = readOptions(options, [
    'signerKeyPair',
    'readerSecret',
    'descriptor',
    'revision',
    'now'
  ])
  if (!b4a.isBuffer(fields.descriptor)) throw PrivateRouteError.INVALID_DESCRIPTOR()
  return storeRecords(runtime, fields, {
    type: RECORD_TYPE.DESCRIPTOR,
    descriptor: fields.descriptor
  })
}

async function revokePresence(runtime, options) {
  const fields = readOptions(options, [
    'signerKeyPair',
    'readerSecret',
    'revision',
    'scope',
    'targets',
    'now'
  ])
  const scope = fields.scope === undefined ? TOMBSTONE_SCOPE.PERIOD : fields.scope
  if (scope !== TOMBSTONE_SCOPE.PERIOD && scope !== TOMBSTONE_SCOPE.RECORD) {
    throw PrivateRouteError.INVALID_DESCRIPTOR()
  }
  return storeRecords(runtime, fields, {
    type: RECORD_TYPE.TOMBSTONE,
    scope,
    targets: fields.targets === undefined ? null : fields.targets
  })
}

// ---------------------------------------------------------------------------
// Terminal: Gate D mutable get and put on the DHT
// ---------------------------------------------------------------------------

// Gate D: the terminal issues only requests the mutable get and put policies encode.
function gate(policy, request) {
  clear(encodeDHTRequest(policy, request))
}

// One DHT reply as a verified presence record for `publicKey`, or null.
function presenceRecordOf(reply, publicKey) {
  if (!isObject(reply) || !b4a.isBuffer(reply.value)) return null
  let record = null
  try {
    record = c.decode(m.mutableGetResponse, reply.value)
  } catch {
    return null
  }
  if (
    !isRevision(record.seq) ||
    !fixed(record.value, PRESENCE_RECORD_SIZE) ||
    record.value[0] !== PRESENCE_RECORD_VERSION ||
    readU32(record.value, 1) !== record.seq ||
    !fixed(record.signature, 64) ||
    !Persistent.verifyMutable(record.signature, record.seq, record.value, publicKey)
  ) {
    return null
  }
  return record
}

async function readPresenceRecord(dht, publicKey) {
  const target = blindedTarget(publicKey)
  const request = { command: COMMANDS.MUTABLE_GET, target, value: c.encode(c.uint, 0) }
  try {
    gate(MUTABLE_GET_POLICIES.lookup, request)
    let best = null
    for await (const reply of dht.query(request)) {
      const record = presenceRecordOf(reply, publicKey)
      if (record !== null && (best === null || record.seq > best.seq)) best = record
    }
    return best
  } finally {
    clear(target)
  }
}

// Commits the signed record to the closest nodes, then reads it back. The write counts
// only with at least three committed puts and two exact copies read back, and a newer
// revision seen on readback supersedes it.
async function writePresenceRecord(dht, fields) {
  const { blindedPublicKey: publicKey, revision, value, signature } = fields
  const target = blindedTarget(publicKey)
  const signed = c.encode(m.mutablePutRequest, { publicKey, seq: revision, value, signature })
  const request = { command: COMMANDS.MUTABLE_GET, target, value: c.encode(c.uint, 0) }
  let written = 0
  try {
    gate(MUTABLE_GET_POLICIES.announce, request)
    const query = dht.query(request, {
      commit(reply, node) {
        const put = { token: reply.token, target, command: COMMANDS.MUTABLE_PUT, value: signed }
        try {
          gate(MUTABLE_PUT_POLICIES.announce, put)
        } catch (err) {
          return Promise.reject(err)
        }
        return node.request(put, reply.from).then(() => {
          written++
        })
      }
    })
    try {
      await query.finished()
    } catch {}
    if (written < MIN_WRITE_QUORUM) return null
    let confirmed = 0
    let superseded = false
    for await (const reply of dht.query(request)) {
      const record = presenceRecordOf(reply, publicKey)
      if (record === null) continue
      if (record.seq > revision) superseded = true
      else if (
        record.seq === revision &&
        b4a.equals(record.value, value) &&
        b4a.equals(record.signature, signature)
      ) {
        confirmed++
      }
    }
    if (superseded || confirmed < MIN_READ_QUORUM) return null
    return { written: Math.min(written, 0xff), confirmed: Math.min(confirmed, 0xff) }
  } finally {
    clear(target)
    clear(signed)
  }
}

async function executeRequest(dht, decoded) {
  const fields = decoded.fields
  const requestNonce = fields.requestNonce
  if (decoded.messageId === PEER_MESSAGE_ID.PRESENCE_LOOKUP_V2) {
    const record = await readPresenceRecord(dht, fields.blindedPublicKey)
    if (record === null) {
      return encodePeerSemantic(PEER_MESSAGE_ID.PRESENCE_ABSENT_V2, { requestNonce })
    }
    return encodePeerSemantic(PEER_MESSAGE_ID.PRESENCE_RECORD_V2, {
      requestNonce,
      revision: record.seq,
      signature: record.signature,
      value: record.value
    })
  }
  // The codec has already bound the record's header to the request's revision.
  if (
    !Persistent.verifyMutable(
      fields.signature,
      fields.revision,
      fields.value,
      fields.blindedPublicKey
    )
  ) {
    return encodePeerSemantic(PEER_MESSAGE_ID.PRESENCE_UNAVAILABLE_V2, { requestNonce })
  }
  const stored = await writePresenceRecord(dht, fields)
  if (stored === null) {
    return encodePeerSemantic(PEER_MESSAGE_ID.PRESENCE_UNAVAILABLE_V2, { requestNonce })
  }
  return encodePeerSemantic(PEER_MESSAGE_ID.PRESENCE_STORED_V2, {
    requestNonce,
    revision: fields.revision,
    written: stored.written,
    confirmed: stored.confirmed
  })
}

function readTerminalPolicy(value) {
  if (value === undefined) return DEFAULT_TERMINAL_POLICY
  if (value === false) return null
  if (!isObject(value)) throw PrivateRouteError.INVALID_ROUTE()
  const keys = Object.keys(value)
  const names = ['maxConcurrent', 'maxOperationsPerCircuit', 'minOperationIntervalMs']
  if (keys.length !== names.length || !names.every((name) => keys.includes(name))) {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  const { maxConcurrent, maxOperationsPerCircuit, minOperationIntervalMs } = value
  if (
    !Number.isInteger(maxConcurrent) ||
    maxConcurrent < 1 ||
    maxConcurrent > 1024 ||
    !Number.isInteger(maxOperationsPerCircuit) ||
    maxOperationsPerCircuit < 1 ||
    maxOperationsPerCircuit > MAX_ATTEMPTS ||
    !Number.isInteger(minOperationIntervalMs) ||
    minOperationIntervalMs < 0 ||
    minOperationIntervalMs > 60_000
  ) {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  return Object.freeze({ maxConcurrent, maxOperationsPerCircuit, minOperationIntervalMs })
}

// The terminal side: serves presence circuits handed over by the relay runtime. Each
// circuit runs at most `maxOperationsPerCircuit` operations, one at a time and at least
// `minOperationIntervalMs` apart, and answers an exact repeat of its current request from
// the cached reply, at most 16 times in all.
function createPresenceTerminal(options) {
  if (!isObject(options) || !isObject(options.dht) || typeof options.dht.query !== 'function') {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  const dht = options.dht
  const policy = options.policy
  const circuits = new Set()
  let served = 0
  let refused = 0
  let closed = false

  function end(circuit) {
    if (circuit.ended) return
    circuit.ended = true
    circuits.delete(circuit)
    if (circuit.cancelIdle) circuit.cancelIdle()
    circuit.window.destroy()
    if (circuit.cached) {
      clear(circuit.cached.request)
      clear(circuit.cached.reply)
      circuit.cached = null
    }
    const join = circuit.lease.revoke()
    eraseView(circuit.view)
    return join
  }

  function armIdle(circuit) {
    if (circuit.cancelIdle) circuit.cancelIdle()
    try {
      circuit.cancelIdle = circuit.view.carrier.schedule(TERMINAL_IDLE_MS, () => end(circuit))
    } catch {
      end(circuit)
    }
  }

  function sendReply(circuit, reply) {
    let frame = null
    try {
      frame = sealFinalize(circuit.view, TERMINAL_TO_SOURCE, circuit.counter++, reply)
      circuit.view.carrier.sendFinalizeFrame(frame).catch(() => {})
    } catch {
      end(circuit)
    } finally {
      clear(frame)
    }
  }

  function refuse(circuit, requestNonce) {
    const reply = encodePeerSemantic(PEER_MESSAGE_ID.PRESENCE_UNAVAILABLE_V2, { requestNonce })
    try {
      sendReply(circuit, reply)
    } finally {
      clear(reply)
    }
  }

  function handle(circuit, payload) {
    let decoded = null
    try {
      decoded = decodePeerSemantic(payload)
    } catch {
      return
    }
    try {
      const charge =
        decoded.messageId === PEER_MESSAGE_ID.PRESENCE_LOOKUP_V2
          ? LOOKUP_CHARGE
          : decoded.messageId === PEER_MESSAGE_ID.PRESENCE_STORE_V2
            ? STORE_CHARGE
            : null
      if (charge === null) return
      const cached = circuit.cached
      if (cached && b4a.equals(cached.request, payload)) {
        if (cached.reply && cached.attempts < MAX_ATTEMPTS) {
          cached.attempts++
          sendReply(circuit, cached.reply)
        }
        return
      }
      // A different request waits until the current one is answered, and a request that
      // comes too soon after the last one waits for its source's next attempt.
      if (circuit.inFlight) return
      const mono = Number(circuit.view.carrier.clock.monotonicNow())
      if (circuit.lastStart !== null && mono - circuit.lastStart < policy.minOperationIntervalMs) {
        return
      }
      if (circuit.operations >= policy.maxOperationsPerCircuit) {
        refuse(circuit, decoded.fields.requestNonce)
        return
      }
      try {
        chargePeerLedger(circuit.view.sendLedger, charge)
      } catch {
        refuse(circuit, decoded.fields.requestNonce)
        return
      }
      if (cached) {
        clear(cached.request)
        clear(cached.reply)
      }
      const current = { request: b4a.from(payload), reply: null, attempts: 0 }
      circuit.cached = current
      circuit.operations++
      circuit.inFlight = true
      circuit.lastStart = mono
      if (circuit.cancelIdle) circuit.cancelIdle()
      circuit.cancelIdle = null
      const request = {
        messageId: decoded.messageId,
        fields: Object.fromEntries(
          Object.entries(decoded.fields).map(([name, value]) => [
            name,
            b4a.isBuffer(value) ? b4a.from(value) : value
          ])
        )
      }
      executeRequest(dht, request)
        .catch(() =>
          encodePeerSemantic(PEER_MESSAGE_ID.PRESENCE_UNAVAILABLE_V2, {
            requestNonce: request.fields.requestNonce
          })
        )
        .then((reply) => {
          for (const value of Object.values(request.fields)) clear(value)
          circuit.inFlight = false
          if (circuit.ended || circuit.cached !== current) {
            clear(reply)
            return
          }
          served++
          current.reply = reply
          current.attempts = 1
          sendReply(circuit, reply)
          if (!circuit.ended) armIdle(circuit)
        })
    } finally {
      clear(decoded.body)
    }
  }

  function receive(circuit) {
    if (circuit.ended) return
    let reservation = null
    try {
      reservation = circuit.view.carrier.reserveReceive()
    } catch {
      end(circuit)
      return
    }
    circuit.view.carrier.receiveEnvelope(reservation).then(
      (envelope) => {
        const payload = openFinalize(circuit.view, SOURCE_TO_TERMINAL, circuit.window, envelope)
        if (payload !== null) {
          try {
            handle(circuit, payload)
          } finally {
            clear(payload)
          }
        }
        receive(circuit)
      },
      () => end(circuit)
    )
  }

  return Object.freeze({
    // Takes a terminal final-tail lease and revokes it when the circuit ends.
    serve(lease) {
      if (closed || circuits.size >= policy.maxConcurrent) {
        refused++
        lease.revoke()
        return false
      }
      const view = lease.consume()
      const circuit = {
        view,
        lease,
        window: new DatagramReplayWindow({ window: REPLAY_WINDOW }),
        counter: 0n,
        operations: 0,
        inFlight: false,
        lastStart: null,
        cached: null,
        cancelIdle: null,
        ended: false
      }
      circuits.add(circuit)
      armIdle(circuit)
      receive(circuit)
      return true
    },

    diagnostics() {
      return Object.freeze({ active: circuits.size, served, refused })
    },

    close() {
      closed = true
      // Each circuit's carrier joins here: every revoke settles only when that carrier's
      // duty and native completions have, so a shutting-down runtime can await them all.
      return Promise.all(
        Array.from(circuits, (circuit) => Promise.resolve(end(circuit)).catch(() => {}))
      ).then(() => {})
    }
  })
}

module.exports = {
  PRESENCE_CIRCUIT_LIMITS,
  PRESENCE_PARAMETERS_DIGEST,
  TOMBSTONE_SCOPE,
  createPresenceTerminal,
  derivePublicReaderSecret,
  lookupPresence,
  publishPresence,
  readTerminalPolicy,
  revokePresence
}
