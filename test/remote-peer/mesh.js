'use strict'

// One member of a mesh of runner peers. Every member can derive every other
// member's key from the shared secret and the run id, so the mesh needs no
// coordinator to discover itself: member i dials every member j > i, records
// what happened, and answers a report request from the prober.
//
// This measures the thing private routes depend on and the single-prober harness
// cannot see: whether peer-to-peer links form between two NAT'd runners, how
// long they take, and whether they come back after a drop.
//
//   REMOTE_PEER_SECRET=<hex> REMOTE_PEER_RUN_ID=<id> \
//     node test/remote-peer/mesh.js --index 3 --count 10 --seconds 420

const b4a = require('b4a')
const DHT = require('../..')
const UDX = require('udx-native')
const { peerKeyPair, proberKeyPair } = require('./identity')
const { OP, writeFrame, FrameReader } = require('./frames')
const { discoverMapping, resolveServers } = require('./stun')

const DIAL_TIMEOUT_MS = 25_000
const DIAL_RETRIES = 3
const RECONNECT_DELAY_MS = 500

function parse(argv) {
  const options = { index: 1, count: 2, seconds: 420, settle: 20, bootstrap: [] }
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i]
    const value = argv[i + 1]
    if (flag === '--index') options.index = Number(value)
    else if (flag === '--count') options.count = Number(value)
    else if (flag === '--seconds') options.seconds = Number(value)
    else if (flag === '--settle') options.settle = Number(value)
    else if (flag === '--bootstrap') {
      const [host, port] = String(value).split(':')
      options.bootstrap.push({ host, port: Number(port) })
    } else continue
    i++
  }
  for (const key of ['index', 'count', 'seconds', 'settle']) {
    if (!Number.isFinite(options[key]) || options[key] < 0) throw new Error(`bad --${key}`)
  }
  if (options.index < 1 || options.index > options.count) throw new Error('index outside count')
  return options
}

function emit(event) {
  console.log(JSON.stringify({ remotePeer: event.event, ...event }))
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function openStream(node, keyPair, publicKey) {
  return new Promise((resolve, reject) => {
    const socket = node.connect(publicKey, { keyPair })
    const timer = setTimeout(() => {
      socket.destroy()
      reject(new Error('dial timed out'))
    }, DIAL_TIMEOUT_MS)
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

// A member dials once, times a round trip, drops the stream, then dials again:
// the second dial is the reconnect measurement route rotation will depend on.
async function dialPeer(node, keyPair, target, index) {
  const attemptErrors = []
  for (let attempt = 1; attempt <= DIAL_RETRIES; attempt++) {
    const startedAt = Date.now()
    let socket = null
    try {
      socket = await openStream(node, keyPair, target)
      const reader = new FrameReader(socket)
      const connectMs = Date.now() - startedAt
      const ping = b4a.alloc(8, index & 0xff)
      const rttStarted = process.hrtime.bigint()
      socket.write(writeFrame(OP.ECHO, ping))
      const echoed = await reader.next(DIAL_TIMEOUT_MS)
      const rttMs = Number(process.hrtime.bigint() - rttStarted) / 1e6
      const echoOk = echoed.op === OP.ECHO && b4a.equals(echoed.payload, ping)
      socket.destroy()

      await sleep(RECONNECT_DELAY_MS)
      const reconnectStarted = Date.now()
      const second = await openStream(node, keyPair, target)
      const reconnectMs = Date.now() - reconnectStarted
      second.destroy()

      return { ok: true, attempts: attempt, connectMs, rttMs, echoOk, reconnectMs }
    } catch (err) {
      if (socket) socket.destroy()
      attemptErrors.push(err.code || err.message)
      await sleep(1000)
    }
  }
  return { ok: false, attempts: DIAL_RETRIES, errors: attemptErrors }
}

async function main() {
  const options = parse(process.argv.slice(2))
  const secret = process.env.REMOTE_PEER_SECRET
  const runId = process.env.REMOTE_PEER_RUN_ID || process.env.GITHUB_RUN_ID
  if (!secret) throw new Error('REMOTE_PEER_SECRET is required')
  if (!runId) throw new Error('REMOTE_PEER_RUN_ID or GITHUB_RUN_ID is required')

  const keyPair = peerKeyPair(secret, runId, options.index)
  const prober = proberKeyPair(secret, runId).publicKey
  const members = []
  for (let index = 1; index <= options.count; index++) {
    members.push({ index, publicKey: peerKeyPair(secret, runId, index).publicKey })
  }
  const allowed = new Map(members.map((m) => [b4a.toString(m.publicKey, 'hex'), m.index]))

  const node = new DHT({
    bootstrap: options.bootstrap.length > 0 ? options.bootstrap : undefined
  })
  const inbound = []
  const dialed = new Map()
  // A second socket, of the kind lib/private/udx-cell-endpoint.js binds for route
  // cells. The DHT stream above cannot answer whether cells could travel directly
  // between two runners, because the DHT punches its own socket. This one is
  // punched by hand from the collector's plan, which is what a signed capability
  // would have to describe.
  const cellUdx = new UDX()
  const cellSocket = cellUdx.createSocket()
  const cellObserved = []
  cellSocket.on('message', (message, from) => {
    cellObserved.push({
      claimedIndex: message.byteLength > 0 ? message[0] : null,
      host: from.host,
      port: from.port,
      at: Date.now()
    })
  })
  const bindResult = cellSocket.bind(0)
  if (bindResult && typeof bindResult.then === 'function') await bindResult
  const cellPort = cellSocket.address().port

  // The mapped address of this exact socket, from two different reflectors. A
  // capability for a cross-runner route would have to carry the mapped value, and
  // if the two reflectors disagree the mapping is per destination and no single
  // value could ever be published.
  const cellMappings = []
  for (const server of await resolveServers()) {
    const mapped = await discoverMapping(cellSocket, server)
    cellMappings.push({ server: server.host, mapped })
  }
  const usable = cellMappings.filter((entry) => entry.mapped !== null)
  const mappingIndependent =
    usable.length > 1 &&
    usable.every(
      (entry) =>
        entry.mapped.host === usable[0].mapped.host && entry.mapped.port === usable[0].mapped.port
    )
  const cellMapped = usable.length > 0 ? usable[0].mapped : null
  let cellPlan = null

  // Repeats on purpose: a first packet out of a NAT usually only creates the
  // mapping, and the peer's first packet is often already in flight against a
  // mapping that does not exist yet. Six spread over three seconds separates
  // "never arrives" from "arrives once both mappings exist".
  function punchAll(plan) {
    const payload = b4a.alloc(1, options.index & 0xff)
    let round = 0
    const timer = setInterval(() => {
      round++
      for (const [index, target] of Object.entries(plan)) {
        if (Number(index) === options.index) continue
        if (!target || typeof target.host !== 'string' || !Number.isInteger(target.cellPort)) {
          continue
        }
        try {
          cellSocket.send(payload, target.cellPort, target.host)
        } catch {
          // A refused send is data too: the report will show nothing arrived.
        }
      }
      if (round >= 6) clearInterval(timer)
    }, 500)
  }
  let cellPunchedAt = null

  const server = node.createServer(
    {
      // Mesh members and the prober only: the derived key set is the whole
      // access list, so a stranger cannot join the mesh.
      firewall(remotePublicKey) {
        const hex = b4a.toString(remotePublicKey, 'hex')
        return !(allowed.has(hex) || b4a.equals(remotePublicKey, prober))
      }
    },
    (socket) => {
      const from = allowed.get(b4a.toString(socket.remotePublicKey, 'hex')) || null
      if (from !== null) inbound.push({ from, at: Date.now() })
      socket.on('error', () => {})
      const reader = new FrameReader(socket)
      reader.on('frame', (frame) => {
        if (frame.op === OP.ECHO) socket.write(writeFrame(OP.ECHO, frame.payload))
        else if (frame.op === OP.REPORT) {
          socket.write(
            writeFrame(
              OP.REPORT,
              b4a.from(
                JSON.stringify({
                  index: options.index,
                  address: node.address(),
                  firewalled: node.firewalled,
                  punches: node.stats.punches,
                  relaying: node.stats.relaying,
                  inboundFrom: inbound.map((entry) => entry.from),
                  dialed: Object.fromEntries(dialed),
                  cellPort,
                  cellMapped,
                  cellMappings,
                  mappingIndependent
                })
              )
            )
          )
        } else if (frame.op === OP.PLAN) {
          // Every member punches the moment the plan lands, so the sends cross in
          // flight. That is the only way two NAT'd hosts open a path neither can
          // open alone.
          cellPlan = JSON.parse(b4a.toString(frame.payload, 'utf8'))
          cellPunchedAt = Date.now()
          punchAll(cellPlan)
        } else if (frame.op === OP.CELL_REPORT) {
          socket.write(
            writeFrame(
              OP.CELL_REPORT,
              b4a.from(
                JSON.stringify({
                  index: options.index,
                  cellPort,
                  cellMapped,
                  mappingIndependent,
                  punchedAt: cellPunchedAt,
                  planSize: cellPlan === null ? 0 : Object.keys(cellPlan).length,
                  observed: cellObserved
                })
              )
            )
          )
        }
      })
    }
  )

  await server.listen(keyPair)
  emit({
    event: 'ready',
    index: options.index,
    count: options.count,
    runId,
    address: node.address(),
    firewalled: node.firewalled
  })

  // Everyone binds before anyone dials, otherwise early dials fail on peers that
  // simply have not announced yet and the matrix measures start-up skew.
  await sleep(options.settle * 1000)

  // Only the lower index dials, so each pair is measured once and both sides see
  // one inbound or one outbound for it.
  for (const member of members) {
    if (member.index <= options.index) continue
    const result = await dialPeer(node, keyPair, member.publicKey, options.index)
    dialed.set(String(member.index), result)
    emit({ event: 'dial', index: options.index, to: member.index, ...result })
  }

  emit({
    event: 'dialled-all',
    index: options.index,
    dialed: Object.fromEntries(dialed),
    inboundFrom: inbound.map((entry) => entry.from)
  })

  const heartbeat = setInterval(() => {
    emit({
      event: 'alive',
      index: options.index,
      inbound: inbound.length,
      punches: node.stats.punches,
      relaying: node.stats.relaying
    })
  }, 30_000)

  await sleep(options.seconds * 1000)
  clearInterval(heartbeat)

  emit({
    event: 'done',
    index: options.index,
    inboundFrom: inbound.map((entry) => entry.from),
    dialed: Object.fromEntries(dialed),
    cellPort,
    cellObserved,
    punches: node.stats.punches,
    relaying: node.stats.relaying
  })

  await server.close()
  await node.destroy()
  await cellSocket.close()
}

main().catch((err) => {
  emit({ event: 'error', message: err.message })
  process.exit(1)
})
