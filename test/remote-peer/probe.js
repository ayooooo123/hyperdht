'use strict'

// Times a workstation against the remote peers of one run. Skips with a stated
// reason when no run is configured, so it is safe in any suite.
//
//   REMOTE_PEER_SECRET=<hex> REMOTE_PEER_RUN_ID=<id> REMOTE_PEER_COUNT=3 \
//     brittle-node test/remote-peer/probe.js
//
// Every peer is measured at the same time, on purpose: concurrent connects are
// what shakes out shared-socket and holepunch contention, which one at a time
// never shows.

const test = require('brittle')
const b4a = require('b4a')
const DHT = require('../..')
const crypto = require('hypercore-crypto')
const { peerKeyPair, proberKeyPair } = require('./identity')

const PING_SAMPLES = 64
const ECHO_BYTES = 1024 * 1024
const CONNECT_ATTEMPT_MS = 20_000
const PING_TIMEOUT_MS = 15_000
const BULK_TIMEOUT_MS = 60_000

function config() {
  const secret = process.env.REMOTE_PEER_SECRET
  const runId = process.env.REMOTE_PEER_RUN_ID
  const count = Number(process.env.REMOTE_PEER_COUNT || 1)
  const waitMs = Number(process.env.REMOTE_PEER_WAIT_SECONDS || 300) * 1000
  const bootstrap = (process.env.REMOTE_PEER_BOOTSTRAP || '')
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0)
    .map((entry) => {
      const [host, port] = entry.split(':')
      return { host, port: Number(port) }
    })
  // REMOTE_PEER_INDEXES targets specific peers, for example when only one job of
  // a matrix is still alive. Otherwise every index from 1 to the count is timed.
  const listed = (process.env.REMOTE_PEER_INDEXES || '')
    .split(',')
    .map((entry) => Number(entry.trim()))
    .filter((entry) => Number.isInteger(entry) && entry > 0)
  const indexes = []
  if (listed.length > 0) indexes.push(...listed)
  else for (let index = 1; index <= count; index++) indexes.push(index)
  if (!secret || !runId) return null
  return { secret, runId, indexes, waitMs, bootstrap }
}

class Framed {
  constructor(socket) {
    this.chunks = []
    this.length = 0
    this.want = 0
    this.resolve = null
    socket.on('data', (data) => {
      this.chunks.push(data)
      this.length += data.byteLength
      this._settle()
    })
  }

  _settle() {
    if (this.resolve === null || this.length < this.want) return
    const joined = b4a.concat(this.chunks)
    const taken = joined.subarray(0, this.want)
    const rest = joined.subarray(this.want)
    this.chunks = rest.byteLength > 0 ? [rest] : []
    this.length = rest.byteLength
    const resolve = this.resolve
    this.resolve = null
    this.want = 0
    resolve(taken)
  }

  read(bytes) {
    return new Promise((resolve) => {
      this.want = bytes
      this.resolve = resolve
      this._settle()
    })
  }
}

function percentile(sorted, fraction) {
  const index = Math.min(sorted.length - 1, Math.floor(sorted.length * fraction))
  return sorted[index]
}

function connectOnce(node, keyPair, publicKey) {
  return new Promise((resolve, reject) => {
    const socket = node.connect(publicKey, { keyPair })
    const timer = setTimeout(() => {
      socket.destroy()
      reject(new Error('connect timed out'))
    }, CONNECT_ATTEMPT_MS)
    socket.once('open', () => {
      clearTimeout(timer)
      resolve(socket)
    })
    socket.once('error', (err) => {
      clearTimeout(timer)
      reject(err)
    })
  })
}

async function connectWithRetry(node, keyPair, publicKey, deadline) {
  let attempts = 0
  let lastError = null
  while (Date.now() < deadline) {
    attempts++
    const started = Date.now()
    try {
      const socket = await connectOnce(node, keyPair, publicKey)
      return { socket, attempts, connectMs: Date.now() - started }
    } catch (err) {
      lastError = err
      await new Promise((resolve) => setTimeout(resolve, 2000))
    }
  }
  throw new Error(
    `peer never answered after ${attempts} attempts: ${lastError && lastError.message}`
  )
}

// A peer that accepts and then stalls is the failure the local happy path never
// shows, so every read is bounded and names the phase it died in.
function withTimeout(promise, ms, label) {
  let timer = null
  const guard = new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms)
  })
  return Promise.race([promise, guard]).finally(() => clearTimeout(timer))
}

async function measure(node, keyPair, publicKey, index, deadline) {
  const { socket, attempts, connectMs } = await connectWithRetry(node, keyPair, publicKey, deadline)
  const framed = new Framed(socket)
  socket.on('error', () => {})

  // A stalled or mismatched peer must not leave its stream open: one hung socket
  // per peer would otherwise outlive the failure and hold the node alive.
  try {
    const ping = b4a.allocUnsafeSlow(8)
    const samples = []
    for (let i = 0; i < PING_SAMPLES; i++) {
      ping.writeUInt32BE(index, 0)
      ping.writeUInt32BE(i, 4)
      const started = process.hrtime.bigint()
      socket.write(ping)
      const back = await withTimeout(framed.read(8), PING_TIMEOUT_MS, `ping ${i}`)
      samples.push(Number(process.hrtime.bigint() - started) / 1e6)
      if (!b4a.equals(back, ping)) throw new Error('echo mismatch')
    }

    const payload = b4a.alloc(ECHO_BYTES, index & 0xff)
    const bulkStarted = process.hrtime.bigint()
    socket.write(payload)
    const bulk = await withTimeout(framed.read(ECHO_BYTES), BULK_TIMEOUT_MS, 'bulk echo')
    const bulkMs = Number(process.hrtime.bigint() - bulkStarted) / 1e6

    const sorted = samples.slice().sort((left, right) => left - right)
    return {
      index,
      attempts,
      connectMs,
      rttP50: percentile(sorted, 0.5),
      rttP95: percentile(sorted, 0.95),
      rttMin: sorted[0],
      echoMbps: (ECHO_BYTES * 2 * 8) / (bulkMs / 1000) / 1e6,
      bulkOk: b4a.equals(bulk, payload),
      remoteHost: socket.rawStream ? socket.rawStream.remoteHost : null,
      remotePort: socket.rawStream ? socket.rawStream.remotePort : null
    }
  } finally {
    socket.destroy()
  }
}

test('remote peers answer and their timings are recorded', async (t) => {
  const options = config()
  if (options === null) {
    t.comment('skipped: set REMOTE_PEER_SECRET and REMOTE_PEER_RUN_ID to time a run')
    t.pass('no remote peer run configured')
    return
  }

  // The wait window is minutes, not the default 30s: a peer may still be
  // booting on the runner when the probe starts.
  t.timeout(options.waitMs + 120_000)

  const keyPair = proberKeyPair(options.secret, options.runId)
  const node = new DHT({
    bootstrap: options.bootstrap.length > 0 ? options.bootstrap : undefined
  })
  t.teardown(() => node.destroy(), { order: Infinity })

  await node.ready()
  // Recorded on both sides: a cross-NAT failure is only diagnosable when the
  // prober's own firewall verdict and punch counters are in the output too.
  t.comment(
    `prober: firewalled ${node.firewalled}, address ` +
      `${node.address() && node.address().host}:${node.address() && node.address().port}`
  )
  const deadline = Date.now() + options.waitMs
  const settled = await Promise.allSettled(
    options.indexes.map((index) =>
      measure(
        node,
        keyPair,
        peerKeyPair(options.secret, options.runId, index).publicKey,
        index,
        deadline
      )
    )
  )

  const results = []
  for (const outcome of settled) {
    if (outcome.status === 'fulfilled') results.push(outcome.value)
    else t.comment(`peer failed: ${outcome.reason && outcome.reason.message}`)
  }

  t.comment(
    `prober punches: open ${node.stats.punches.open}, consistent ${node.stats.punches.consistent}, ` +
      `random ${node.stats.punches.random}; relaying attempts ${node.stats.relaying.attempts}, ` +
      `successes ${node.stats.relaying.successes}, aborts ${node.stats.relaying.aborts}`
  )

  for (const result of results) {
    t.comment(
      `peer ${result.index}: connect ${result.connectMs}ms in ${result.attempts} attempt(s), ` +
        `rtt min ${result.rttMin.toFixed(1)}ms p50 ${result.rttP50.toFixed(1)}ms ` +
        `p95 ${result.rttP95.toFixed(1)}ms, echo ${result.echoMbps.toFixed(1)}Mbit/s, ` +
        `remote ${result.remoteHost}:${result.remotePort}`
    )
  }

  t.is(results.length, options.indexes.length, 'every configured peer answered')
  for (const result of results) {
    t.ok(result.bulkOk, `peer ${result.index} echoed the bulk payload byte for byte`)
    t.ok(result.rttP50 > 0, `peer ${result.index} reported a round trip`)
  }

  if (results.length > 1) {
    const connects = results.map((result) => result.connectMs).sort((a, b) => a - b)
    const rtts = results.map((result) => result.rttP50).sort((a, b) => a - b)
    t.comment(
      `${results.length} concurrent peers: connect ${connects[0]}..${connects[connects.length - 1]}ms, ` +
        `rtt p50 ${rtts[0].toFixed(1)}..${rtts[rtts.length - 1].toFixed(1)}ms`
    )
  }
})

test('a peer refuses anyone but the derived prober', async (t) => {
  const options = config()
  if (options === null) {
    t.comment('skipped: set REMOTE_PEER_SECRET and REMOTE_PEER_RUN_ID to time a run')
    t.pass('no remote peer run configured')
    return
  }

  t.timeout(120_000)

  const node = new DHT({
    bootstrap: options.bootstrap.length > 0 ? options.bootstrap : undefined
  })
  t.teardown(() => node.destroy(), { order: Infinity })

  // A stranger who knows the peer key but not the secret has no matching prober
  // key, so the peer firewall must never hand it a stream.
  const stranger = crypto.keyPair()
  const target = peerKeyPair(options.secret, options.runId, options.indexes[0]).publicKey
  const socket = node.connect(target, { keyPair: stranger })
  socket.on('error', () => {})

  const opened = await new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), 15_000)
    socket.once('open', () => {
      clearTimeout(timer)
      resolve(true)
    })
    socket.once('error', () => {
      clearTimeout(timer)
      resolve(false)
    })
  })

  socket.destroy()
  t.absent(opened, 'an unpinned key never opens a stream to the peer')
})
