'use strict'

// Collects every mesh member's report and prints the pairwise matrix. This is the
// prerequisite for distributing private routes across runners: a route needs
// guard-to-middle and middle-to-exit links, so peer-to-peer reachability between
// NAT'd runners has to be measured before any route topology is built on it.
//
//   REMOTE_PEER_SECRET=<hex> REMOTE_PEER_RUN_ID=<id> REMOTE_PEER_COUNT=10 \
//     brittle-node test/remote-peer/mesh-probe.js

const test = require('brittle')
const b4a = require('b4a')
const DHT = require('../..')
const { peerKeyPair, proberKeyPair } = require('./identity')
const { OP, writeFrame, FrameReader } = require('./frames')

const CONNECT_ATTEMPT_MS = 20_000
const REPORT_TIMEOUT_MS = 30_000

function config() {
  const secret = process.env.REMOTE_PEER_SECRET
  const runId = process.env.REMOTE_PEER_RUN_ID
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
  return { secret, runId, count, waitMs, bootstrap, minPairRatio, minDegree }
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

async function collect(node, keyPair, publicKey, deadline) {
  let lastError = null
  while (Date.now() < deadline) {
    let socket = null
    try {
      socket = await connectOnce(node, keyPair, publicKey)
      const reader = new FrameReader(socket)
      socket.write(writeFrame(OP.REPORT, null))
      const frame = await reader.next(REPORT_TIMEOUT_MS)
      if (frame.op !== OP.REPORT) throw new Error('unexpected frame')
      const report = JSON.parse(b4a.toString(frame.payload, 'utf8'))
      socket.destroy()
      return report
    } catch (err) {
      if (socket) socket.destroy()
      lastError = err
      await new Promise((resolve) => setTimeout(resolve, 3000))
    }
  }
  throw new Error(`no report: ${lastError && (lastError.code || lastError.message)}`)
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

  const keyPair = proberKeyPair(options.secret, options.runId)
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
