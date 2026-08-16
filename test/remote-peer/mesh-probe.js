'use strict'

// Collects every mesh member's report and prints the pairwise matrix. This is the
// prerequisite for distributing private routes across runners: a route needs
// guard-to-middle and middle-to-exit links, so peer-to-peer reachability between
// NAT'd runners has to be measured before any route topology is built on it.
//
//   REMOTE_PEER_SECRET=<hex> REMOTE_PEER_RUN_ID=<id> REMOTE_PEER_COUNT=10 \
//     REMOTE_PEER_COORDINATOR_SECRET=<hex> \
//     brittle-node test/remote-peer/mesh-probe.js

const test = require('brittle')
const b4a = require('b4a')
const DHT = require('../..')
const { peerKeyPair, coordinatorKeyPair } = require('./identity')
const { OP, writeFrame, FrameReader } = require('./frames')

const CONNECT_ATTEMPT_MS = 20_000
const REPORT_TIMEOUT_MS = 30_000

function config() {
  const secret = process.env.REMOTE_PEER_SECRET
  const runId = process.env.REMOTE_PEER_RUN_ID
  // The collector's own secret. Members hold the shared run secret and pin only
  // this key's public half, so a member cannot pose as the collector.
  const coordinatorSecret = process.env.REMOTE_PEER_COORDINATOR_SECRET
  const count = Number(process.env.REMOTE_PEER_COUNT || 0)
  const waitMs = Number(process.env.REMOTE_PEER_WAIT_SECONDS || 600) * 1000
  const bootstrap = (process.env.REMOTE_PEER_BOOTSTRAP || '')
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0)
    .map((entry) => {
      const [host, port] = entry.split(':')
      return { host, port: Number(port) }
    })
  // Full mesh by default. REMOTE_PEER_MIN_PAIR_RATIO and REMOTE_PEER_MIN_DEGREE
  // exist so an exploratory run can record a partial matrix instead of stopping
  // at the first failed pair.
  const minPairRatio = Number(process.env.REMOTE_PEER_MIN_PAIR_RATIO || 1)
  const minDegree = Number(
    process.env.REMOTE_PEER_MIN_DEGREE === undefined
      ? count - 1
      : process.env.REMOTE_PEER_MIN_DEGREE
  )
  if (!secret || !runId || !Number.isInteger(count) || count < 2) return null
  // A run is configured, so a missing collector secret is a fault rather than an
  // unconfigured harness: skipping here would report a pass for a matrix nobody
  // could have collected.
  if (!coordinatorSecret) {
    throw new Error(
      'REMOTE_PEER_COORDINATOR_SECRET is required alongside REMOTE_PEER_SECRET: ' +
        'the workstation-only secret whose public key the members pin, ' +
        'from scripts/remote-peer.sh secret'
    )
  }
  return { secret, coordinatorSecret, runId, count, waitMs, bootstrap, minPairRatio, minDegree }
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

// Members become ready minutes apart on CI and each waits out its own settle
// window before dialling, so a single early report says nothing. Keep asking
// until the member has a result for every higher index, or the deadline hits,
// and return the last report either way so a partial matrix is still reported.
async function collect(node, keyPair, publicKey, index, count, deadline) {
  const expectedDials = count - index
  let lastError = null
  let lastReport = null
  while (Date.now() < deadline) {
    let socket = null
    try {
      socket = await connectOnce(node, keyPair, publicKey)
      const reader = new FrameReader(socket)
      socket.write(writeFrame(OP.REPORT, null))
      const frame = await reader.next(REPORT_TIMEOUT_MS)
      if (frame.op !== OP.REPORT) throw new Error('unexpected frame')
      lastReport = JSON.parse(b4a.toString(frame.payload, 'utf8'))
      // The member cannot see its own public address; this stream can. It is what
      // a signed capability would have to carry for a cross-runner route.
      lastReport.observedHost = socket.rawStream ? socket.rawStream.remoteHost : null
      socket.destroy()
      if (Object.keys(lastReport.dialed || {}).length >= expectedDials) return lastReport
    } catch (err) {
      if (socket) socket.destroy()
      lastError = err
    }
    await new Promise((resolve) => setTimeout(resolve, 5000))
  }
  if (lastReport !== null) return lastReport
  throw new Error(`no report: ${lastError && (lastError.code || lastError.message)}`)
}

// Fire one frame and leave. Used for the plan: every member must punch at roughly
// the same moment, so the collector must not wait for a reply in between.
async function push(node, keyPair, publicKey, op, payload) {
  const socket = await connectOnce(node, keyPair, publicKey)
  socket.on('error', () => {})
  socket.write(writeFrame(op, payload))
  await new Promise((resolve) => setTimeout(resolve, 250))
  socket.destroy()
  return true
}

// Ask for one frame and return its parsed body.
async function request(node, keyPair, publicKey, op) {
  const socket = await connectOnce(node, keyPair, publicKey)
  socket.on('error', () => {})
  try {
    const reader = new FrameReader(socket)
    socket.write(writeFrame(op, null))
    const frame = await reader.next(REPORT_TIMEOUT_MS)
    if (frame.op !== op) throw new Error('unexpected frame')
    return JSON.parse(b4a.toString(frame.payload, 'utf8'))
  } finally {
    socket.destroy()
  }
}

function median(values) {
  if (values.length === 0) return null
  const sorted = values.slice().sort((left, right) => left - right)
  return sorted[Math.floor(sorted.length / 2)]
}

test('mesh members reach each other and report the pairwise matrix', async (t) => {
  const options = config()
  if (options === null) {
    t.comment('skipped: set REMOTE_PEER_SECRET, REMOTE_PEER_RUN_ID and REMOTE_PEER_COUNT >= 2')
    t.pass('no mesh run configured')
    return
  }

  t.timeout(options.waitMs + 180_000)

  const keyPair = coordinatorKeyPair(options.coordinatorSecret)
  const node = new DHT({
    bootstrap: options.bootstrap.length > 0 ? options.bootstrap : undefined
  })
  t.teardown(() => node.destroy(), { order: Infinity })
  await node.ready()

  const deadline = Date.now() + options.waitMs
  const settled = await Promise.allSettled(
    Array.from({ length: options.count }, (unused, offset) =>
      collect(
        node,
        keyPair,
        peerKeyPair(options.secret, options.runId, offset + 1).publicKey,
        offset + 1,
        options.count,
        deadline
      )
    )
  )

  const reports = new Map()
  for (let offset = 0; offset < settled.length; offset++) {
    const outcome = settled[offset]
    if (outcome.status === 'fulfilled') reports.set(outcome.value.index, outcome.value)
    else t.comment(`member ${offset + 1} unreachable: ${outcome.reason.message}`)
  }

  t.comment(`reports collected: ${reports.size}/${options.count}`)
  for (const report of [...reports.values()].sort((a, b) => a.index - b.index)) {
    t.comment(
      `member ${report.index}: ${report.address && report.address.host}, firewalled ` +
        `${report.firewalled}, inbound from [${report.inboundFrom.join(',')}], punches ` +
        `open ${report.punches.open} consistent ${report.punches.consistent} random ${report.punches.random}`
    )
  }

  // Second phase: can the sockets that carry route cells reach each other? The
  // DHT links above cannot answer that, because the DHT punches its own socket.
  // The plan carries each member's mapped address, learned by the member itself
  // from public reflectors: a local port is only correct when the NAT preserves
  // ports, which the first ten-runner attempt showed it does not.
  const plan = {}
  let independentMappings = 0
  for (const report of reports.values()) {
    if (report.mappingIndependent) independentMappings++
    if (report.cellMapped && Number.isInteger(report.cellMapped.port)) {
      plan[report.index] = { host: report.cellMapped.host, cellPort: report.cellMapped.port }
    } else if (report.observedHost && Number.isInteger(report.cellPort)) {
      plan[report.index] = { host: report.observedHost, cellPort: report.cellPort }
    }
  }
  for (const report of [...reports.values()].sort((a, b) => a.index - b.index)) {
    t.comment(
      `member ${report.index} cell socket: local ${report.cellPort}, mapped ` +
        `${report.cellMapped ? `${report.cellMapped.host}:${report.cellMapped.port}` : 'unknown'}` +
        `, mapping independent of destination: ${report.mappingIndependent}`
    )
  }
  t.comment(`${independentMappings}/${reports.size} members have a destination-independent mapping`)

  // Whether a discovered mapping survives closing a socket and rebinding the same
  // local port. If it does, a role can discover its endpoint, have it minted into
  // a signed capability, and only then let the production cell endpoint bind.
  let stableRebinds = 0
  for (const report of [...reports.values()].sort((a, b) => a.index - b.index)) {
    const rebind = report.rebind
    if (!rebind) continue
    if (rebind.stable) stableRebinds++
    t.comment(
      `member ${report.index} rebind of local ${rebind.localPort}: rebound ${rebind.rebound}, ` +
        `${rebind.before ? `${rebind.before.host}:${rebind.before.port}` : 'unknown'} then ` +
        `${rebind.after ? `${rebind.after.host}:${rebind.after.port}` : 'unknown'}, stable ${rebind.stable}`
    )
  }
  t.comment(`${stableRebinds}/${reports.size} members kept their mapping across a rebind`)
  const planBytes = b4a.from(JSON.stringify(plan))
  const planned = await Promise.allSettled(
    [...reports.keys()].map((index) =>
      push(
        node,
        keyPair,
        peerKeyPair(options.secret, options.runId, index).publicKey,
        OP.PLAN,
        planBytes
      )
    )
  )
  t.comment(
    `cell plan pushed to ${planned.filter((entry) => entry.status === 'fulfilled').length}/` +
      `${reports.size} members, plan covers ${Object.keys(plan).length}`
  )

  // Punches repeat over three seconds, so give them time before asking.
  await new Promise((resolve) => setTimeout(resolve, 8000))

  const cellSettled = await Promise.allSettled(
    [...reports.keys()].map((index) =>
      request(
        node,
        keyPair,
        peerKeyPair(options.secret, options.runId, index).publicKey,
        OP.CELL_REPORT
      )
    )
  )

  const cellReports = new Map()
  for (const outcome of cellSettled) {
    if (outcome.status === 'fulfilled') cellReports.set(outcome.value.index, outcome.value)
  }

  let cellArrivals = 0
  let portPreserved = 0
  let portTranslated = 0
  for (const report of [...cellReports.values()].sort((a, b) => a.index - b.index)) {
    const from = new Map()
    for (const packet of report.observed || []) {
      if (!from.has(packet.claimedIndex)) from.set(packet.claimedIndex, packet)
    }
    cellArrivals += from.size
    for (const [claimed, packet] of from) {
      const expected = plan[claimed]
      if (expected && expected.cellPort === packet.port) portPreserved++
      else portTranslated++
    }
    t.comment(
      `member ${report.index} cell socket ${report.cellPort}: heard from ` +
        `[${[...from.keys()].join(',')}] of ${report.planSize - 1} peers`
    )
  }

  const cellPairsPossible = reports.size * (reports.size - 1)
  t.comment(
    `cell arrivals ${cellArrivals}/${cellPairsPossible} directed pairs; source port ` +
      `preserved ${portPreserved}, translated ${portTranslated}`
  )

  // One row per dialling member: each pair is dialled once, by the lower index.
  const pairs = []
  for (const report of reports.values()) {
    for (const [to, result] of Object.entries(report.dialed || {})) {
      pairs.push({ from: report.index, to: Number(to), ...result })
    }
  }

  const ok = pairs.filter((pair) => pair.ok)
  const failed = pairs.filter((pair) => !pair.ok)

  for (const pair of pairs.sort((a, b) => a.from - b.from || a.to - b.to)) {
    if (pair.ok) {
      t.comment(
        `link ${pair.from}->${pair.to}: connect ${pair.connectMs}ms in ${pair.attempts} attempt(s), ` +
          `rtt ${pair.rttMs.toFixed(1)}ms, reconnect ${pair.reconnectMs}ms, echo ${pair.echoOk}`
      )
    } else {
      t.comment(`link ${pair.from}->${pair.to}: FAILED after ${pair.attempts} (${pair.errors})`)
    }
  }

  const expectedPairs = (options.count * (options.count - 1)) / 2
  t.comment(
    `pairs ${ok.length}/${pairs.length} ok of ${expectedPairs} possible; connect p50 ` +
      `${median(ok.map((pair) => pair.connectMs))}ms, rtt p50 ` +
      `${median(ok.map((pair) => pair.rttMs))}ms, reconnect p50 ` +
      `${median(ok.map((pair) => pair.reconnectMs))}ms`
  )

  t.is(reports.size, options.count, 'every mesh member reported')
  t.is(pairs.length, expectedPairs, 'every pair was attempted exactly once')
  // A mesh that carries private routes needs enough links for two endpoints plus
  // candidate guards, middles and exits, so the bar is a link ratio and a minimum
  // per-member degree, not "something connected". Both default to a full mesh;
  // lower them only for an exploratory run, and say so when reporting it.
  const degrees = new Map([...reports.keys()].map((index) => [index, 0]))
  for (const pair of ok) {
    degrees.set(pair.from, (degrees.get(pair.from) || 0) + 1)
    degrees.set(pair.to, (degrees.get(pair.to) || 0) + 1)
  }
  const worstDegree = Math.min(...degrees.values())
  t.comment(
    `degrees: ${[...degrees.entries()]
      .sort((a, b) => a[0] - b[0])
      .map(([index, degree]) => `${index}:${degree}`)
      .join(' ')}`
  )

  const ratio = pairs.length === 0 ? 0 : ok.length / pairs.length
  t.ok(
    ratio >= options.minPairRatio,
    `link ratio ${(ratio * 100).toFixed(0)}% meets the required ` +
      `${(options.minPairRatio * 100).toFixed(0)}% (${ok.length} ok, ${failed.length} failed)`
  )
  t.ok(
    worstDegree >= options.minDegree,
    `every member holds at least ${options.minDegree} link(s); worst is ${worstDegree}`
  )
  for (const pair of ok) {
    t.ok(pair.echoOk, `link ${pair.from}->${pair.to} echoed`)
    t.ok(pair.reconnectMs >= 0, `link ${pair.from}->${pair.to} reconnected`)
  }
})
