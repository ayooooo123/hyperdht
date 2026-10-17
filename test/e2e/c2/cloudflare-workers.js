'use strict'

const test = require('brittle')
const b4a = require('b4a')
const fs = require('fs')
const os = require('os')
const path = require('path')
const process = require('process')
const { spawn } = require('child_process')
const createTestnet = require('../../../testnet')
const HyperDHT = require('../../..')
const { cryptoSuite } = require('../../../lib/private/crypto-suite')
const { TOPOLOGY_ROLE } = require('../../../lib/private/protocol')
const { endpoint, grant, sourceOptions } = require('../../private/helpers/native-config')

function deferred() {
  let resolve
  let reject
  const promise = new Promise((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

function closed(stream) {
  if (stream.destroyed) return Promise.resolve()
  return new Promise((resolve) => stream.once('close', resolve))
}

function runCommand(cmd, args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString()
    })
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString()
    })
    child.once('error', reject)
    child.once('close', (code) => {
      if (code === 0) resolve({ stdout, stderr })
      else reject(new Error(`${cmd} ${args.join(' ')} exited ${code}: ${stderr || stdout}`))
    })
  })
}

function createWorkerSource(role, runId, sharedSecretHex, forbiddenHexList) {
  return `const ROLE = ${JSON.stringify(role)}
const RUN_ID = ${JSON.stringify(runId)}
const SECRET_HEX = ${JSON.stringify(sharedSecretHex)}
const FORBIDDEN = ${JSON.stringify(forbiddenHexList)}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length >>> 1)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

function bytesToHex(bytes) {
  let out = ''
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0')
  }
  return out
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return bytesToHex(new Uint8Array(digest))
}

let cachedKey = null
async function hmacHex(message) {
  if (!cachedKey) {
    cachedKey = await crypto.subtle.importKey(
      'raw',
      hexToBytes(SECRET_HEX),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    )
  }
  const sig = await crypto.subtle.sign('HMAC', cachedKey, new TextEncoder().encode(message))
  return bytesToHex(new Uint8Array(sig))
}

export default {
  async fetch(request) {
    const url = new URL(request.url)
    const colo = (request.cf && request.cf.colo) || 'CF_EDGE'
    if (url.pathname === '/health') {
      return Response.json({ ok: true, role: ROLE, runId: RUN_ID, colo })
    }
    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 })
    }
    const body = await request.json()
    const packetHex = String(body.packetHex || '').toLowerCase()
    const packet = hexToBytes(packetHex)
    const packetDigest = await sha256Hex(packet)
    const isCell = packet.byteLength === 1200 && packet[0] === 0
    const envelopeDigest = isCell ? await sha256Hex(packet.subarray(99, 1200)) : null
    const isRelay = ROLE === 'guard' || ROLE === 'safety' || ROLE === 'terminal'
    let leakDetected = false
    if (isRelay) {
      for (const needle of FORBIDDEN) {
        if (needle && packetHex.includes(needle.toLowerCase())) {
          leakDetected = true
          break
        }
      }
    }
    if (url.pathname === '/egress') {
      const sig = await hmacHex(
        \`\${RUN_ID}:egress:\${ROLE}:\${body.seq}:\${body.fromPort}:\${body.toPort}:\${packetDigest}\`
      )
      return Response.json({
        ok: true,
        phase: 'egress',
        role: ROLE,
        runId: RUN_ID,
        colo,
        seq: body.seq,
        bytes: packet.byteLength,
        isCell,
        packetHex,
        packetDigest,
        envelopeDigest,
        leakDetected,
        sig
      })
    }
    if (url.pathname === '/ingress') {
      const expectedEgress = await hmacHex(
        \`\${RUN_ID}:egress:\${body.fromRole}:\${body.seq}:\${body.fromPort}:\${body.toPort}:\${packetDigest}\`
      )
      if (expectedEgress !== body.egressSig) {
        return Response.json({ ok: false, error: 'BAD_EGRESS_SIG' }, { status: 403 })
      }
      const ingressSig = await hmacHex(
        \`\${RUN_ID}:ingress:\${ROLE}:\${body.seq}:\${body.fromRole}:\${packetDigest}\`
      )
      return Response.json({
        ok: true,
        phase: 'ingress',
        role: ROLE,
        runId: RUN_ID,
        colo,
        seq: body.seq,
        bytes: packet.byteLength,
        isCell,
        packetHex,
        packetDigest,
        envelopeDigest,
        leakDetected,
        ingressSig
      })
    }
    return new Response('Not Found', { status: 404 })
  }
}
`
}

async function fetchJson(url, options = {}, maxAttempts = 40) {
  let lastErr = null
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const res = await fetch(url, options)
      const text = await res.text()
      if (res.status === 200 && text.trim().startsWith('{')) {
        return JSON.parse(text)
      }
      lastErr = new Error(`HTTP ${res.status} from ${url}: ${text.slice(0, 120)}`)
    } catch (err) {
      lastErr = err
    }
    await new Promise((resolve) => setTimeout(resolve, 500))
  }
  throw lastErr
}

async function deployTempWorkers(t, roles, runId, sharedSecretHex, forbiddenHexList) {
  const repoRoot = path.resolve(__dirname, '../../..')
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), `hyperdht-cf-e2e-${runId}-`))
  const deployed = new Map()

  t.teardown(async () => {
    await Promise.allSettled(
      Array.from(deployed.values(), (worker) =>
        runCommand('npx', ['wrangler', 'delete', '--name', worker.name, '--force'], repoRoot)
      )
    )
    try {
      fs.rmSync(tempRoot, { recursive: true, force: true })
    } catch {}
  })

  for (const role of roles) {
    const name = `hyperdht-e2e-${role}-${runId}`
    const dir = path.join(tempRoot, role)
    fs.mkdirSync(dir, { recursive: true })
    const entryFile = path.join(dir, 'worker.mjs')
    const configFile = path.join(dir, 'wrangler.toml')
    fs.writeFileSync(entryFile, createWorkerSource(role, runId, sharedSecretHex, forbiddenHexList))
    fs.writeFileSync(
      configFile,
      `name = "${name}"\nmain = "worker.mjs"\ncompatibility_date = "2026-09-01"\nworkers_dev = true\n`
    )
    let url = null
    for (let deployTry = 0; deployTry < 3; deployTry++) {
      const { stdout } = await runCommand(
        'npx',
        ['wrangler', 'deploy', '--config', configFile],
        repoRoot
      )
      const match = stdout.match(/https:\/\/[a-z0-9-]+\.[a-z0-9-]+\.workers\.dev/i)
      if (!match) {
        throw new Error(`Failed to parse workers.dev URL for ${name} from:\n${stdout}`)
      }
      url = match[0]
      deployed.set(role, { role, name, url })
      try {
        await fetchJson(`${url}/health`, {}, 12)
        break
      } catch (err) {
        if (deployTry === 2) throw err
      }
    }
  }
  return deployed
}

test('Cloudflare Workers E2E: temporary edge workers route native-v2 private circuits and verify onion layers', async (t) => {
  t.timeout(300_000)

  const runId = b4a.toString(cryptoSuite.randomBytes(3), 'hex')
  const sharedSecretHex = b4a.toString(cryptoSuite.randomBytes(32), 'hex')
  const serverKey = cryptoSuite.keyPair()
  const forwardPlaintext = 'cloudflare-worker-e2e-forward-secret-payload'
  const reversePlaintext = 'cloudflare-worker-e2e-reverse-secret-payload'
  const forbiddenHexList = [
    b4a.toString(serverKey.publicKey, 'hex'),
    b4a.toString(b4a.from(forwardPlaintext), 'hex'),
    b4a.toString(b4a.from(reversePlaintext), 'hex')
  ]

  const roles = ['source', 'guard', 'safety', 'terminal', 'dest']
  const workers = await deployTempWorkers(t, roles, runId, sharedSecretHex, forbiddenHexList)
  t.is(workers.size, 5, 'deployed 5 temporary Cloudflare Workers for all private routing roles')

  // Verify health and live Cloudflare edge colos on all 5 temporary Workers.
  const healthChecks = await Promise.all(
    roles.map((role) => fetchJson(`${workers.get(role).url}/health`))
  )
  for (const h of healthChecks) {
    t.is(h.ok, true, `Cloudflare Worker ${h.role} is live at colo ${h.colo}`)
  }

  const network = await createTestnet(8, { host: '127.0.0.1' })
  const nodes = []
  t.teardown(async () => {
    for (let i = nodes.length - 1; i >= 0; i--) {
      await nodes[i].destroy().catch(() => {})
    }
    await network.destroy()
  })

  const bootstrap = [
    `${network.nodes[0].host}:${network.nodes[0].port}`,
    `${network.nodes[1].host}:${network.nodes[1].port}`
  ]

  const relayPorts = []
  for (let i = 0; i < 4; i++) {
    const probe = new HyperDHT({ host: '127.0.0.1', bootstrap })
    await probe.ready()
    relayPorts.push(probe.address().port)
    await probe.destroy()
  }

  const relays = relayPorts.map((port) => ({
    ...endpoint(port, TOPOLOGY_ROLE.SAFETY_GUARD),
    grants: []
  }))

  function addEdge(left, right) {
    const wire = grant(
      { ...left, role: TOPOLOGY_ROLE.SAFETY_GUARD },
      { ...right, role: TOPOLOGY_ROLE.SAFETY_FINAL }
    )
    left.grants.push(wire)
    right.grants.push(wire)
  }

  addEdge(relays[0], relays[1])
  addEdge(relays[1], relays[2])
  addEdge(relays[2], relays[0])
  for (const relay of relays.slice(0, 3)) addEdge(relay, relays[3])

  const relayRoleNames = ['guard', 'safety', 'guard', 'terminal']
  const portToNode = new Map()
  const edgeReceipts = []
  const pendingEdgeTasks = new Set()
  let packetSeq = 0
  let captureActive = true
  let inBandWorkerRouting = false
  let inBandDeliveries = 0
  const pairCounts = new Map()

  async function routeThroughCloudflareWorkers(seq, role, target, fromPort, toPort, packetHex) {
    const senderWorker = workers.get(role)
    const receiverWorker = workers.get(target.role)

    const egress = await fetchJson(`${senderWorker.url}/egress`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ seq, fromPort, toPort, packetHex })
    })
    if (!egress || !egress.ok) {
      throw new Error(`Cloudflare egress Worker (${role}) rejected packet #${seq}`)
    }

    const ingress = await fetchJson(`${receiverWorker.url}/ingress`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        seq,
        fromRole: role,
        fromPort,
        toPort,
        packetHex: egress.packetHex,
        egressSig: egress.sig
      })
    })
    if (!ingress || !ingress.ok) {
      throw new Error(`Cloudflare ingress Worker (${target.role}) rejected packet #${seq}`)
    }

    edgeReceipts.push({
      seq,
      fromRole: role,
      toRole: target.role,
      fromPort,
      toPort,
      bytes: egress.bytes,
      isCell: egress.isCell,
      packetDigest: egress.packetDigest,
      envelopeDigest: egress.envelopeDigest,
      egressColo: egress.colo,
      ingressColo: ingress.colo,
      leakDetected: egress.leakDetected || ingress.leakDetected
    })
    return ingress.packetHex
  }

  function bindCloudflareWorkerSocket(role, dht) {
    const socket = dht.io.serverSocket
    const fromPort = dht.address().port
    portToNode.set(fromPort, { role, dht, socket })
    const origSend = socket.send.bind(socket)

    socket.send = async function (buffer, toPort, toHost, ttl) {
      const payload = b4a.from(buffer)
      const target = portToNode.get(toPort)
      const isPrivatePacket =
        (payload.byteLength === 1200 || payload.byteLength === 256) &&
        (payload[0] === 0x00 || payload[0] === 0xd3)
      if (!captureActive || !target || !isPrivatePacket) {
        return origSend(buffer, toPort, toHost, ttl)
      }

      const pairKey = `${role}->${target.role}`
      const seen = pairCounts.get(pairKey) || 0
      if (!inBandWorkerRouting && seen >= 6) {
        return origSend(buffer, toPort, toHost, ttl)
      }
      pairCounts.set(pairKey, seen + 1)
      const seq = ++packetSeq
      const packetHex = b4a.toString(payload, 'hex')
      if (inBandWorkerRouting && payload.byteLength === 1200 && payload[0] === 0x00) {
        inBandDeliveries++
      }
      const task = routeThroughCloudflareWorkers(seq, role, target, fromPort, toPort, packetHex)
      pendingEdgeTasks.add(task)
      task.finally(() => pendingEdgeTasks.delete(task))
      return origSend(buffer, toPort, toHost, ttl)
    }

    t.teardown(() => {
      socket.send = origSend
    })
  }

  const relayNodes = []
  for (let i = 0; i < relays.length; i++) {
    const relay = relays[i]
    const dht = new HyperDHT({
      host: '127.0.0.1',
      port: relay.port,
      bootstrap,
      ephemeral: false,
      firewalled: false,
      privateRouting: {
        ...sourceOptions(),
        relay: true,
        relayConfig: {
          identityKeyPair: relay.identity,
          authorityPublicKeys: [relay.authority.publicKey],
          epoch: 7n,
          runId32: b4a.alloc(32, 0x52),
          grants: relay.grants
        }
      }
    })
    nodes.push(dht)
    relayNodes.push(dht)
    await dht.ready()
    bindCloudflareWorkerSocket(relayRoleNames[i], dht)
  }
  await Promise.all(relayNodes.map((dht) => dht.privateRouting.ready()))

  async function createEdgeSource(role) {
    const dht = new HyperDHT({
      host: '127.0.0.1',
      bootstrap,
      ephemeral: false,
      firewalled: false,
      privateRouting: sourceOptions()
    })
    nodes.push(dht)
    await dht.ready()
    bindCloudflareWorkerSocket(role, dht)
    await dht.privateRouting.ready()
    return dht
  }

  const destNode = await createEdgeSource('dest')
  const sourceNode = await createEdgeSource('source')

  const serverReceivedWait = deferred()
  const server = destNode.privateRouting.createServer((socket) => {
    socket.on('error', () => {})
    const chunks = []
    socket.on('data', (chunk) => {
      chunks.push(b4a.from(chunk))
      const combined = b4a.concat(chunks)
      if (combined.byteLength >= forwardPlaintext.length) {
        serverReceivedWait.resolve(combined)
        socket.end(b4a.from(reversePlaintext))
      }
    })
  })
  await server.listen(serverKey)

  const client = sourceNode.privateRouting.connect(serverKey.publicKey)
  client.on('error', () => {})
  t.is(
    await client.opened,
    true,
    'native-v2 private stream opens across temporary Cloudflare Worker nodes'
  )
  inBandWorkerRouting = true
  const clientChunks = []
  const clientReceivedWait = deferred()
  client.on('data', (chunk) => {
    clientChunks.push(b4a.from(chunk))
    const combined = b4a.concat(clientChunks)
    if (combined.byteLength >= reversePlaintext.length) {
      clientReceivedWait.resolve(combined)
    }
  })
  client.end(b4a.from(forwardPlaintext))

  const [srvBytes, cliBytes] = await Promise.all([
    serverReceivedWait.promise,
    clientReceivedWait.promise
  ])
  inBandWorkerRouting = false
  captureActive = false
  await Promise.all(Array.from(pendingEdgeTasks))
  t.alike(srvBytes, b4a.from(forwardPlaintext), 'forward payload arrives intact over CF Workers')
  t.alike(cliBytes, b4a.from(reversePlaintext), 'reverse payload arrives intact over CF Workers')
  t.ok(inBandDeliveries > 0, `delivered ${inBandDeliveries} circuit cells in-band via CF Workers`)

  await Promise.all([closed(client), server.close()])
  // Verify Cloudflare Worker edge audit receipts
  t.ok(
    edgeReceipts.length > 40,
    `routed ${edgeReceipts.length} private UDP datagrams via CF Workers`
  )
  for (const role of roles) {
    const count = edgeReceipts.filter((r) => r.fromRole === role || r.toRole === role).length
    t.ok(count > 0, `Cloudflare Worker role ${role} processed ${count} private routing datagrams`)
  }
  const cellReceipts = edgeReceipts.filter((r) => r.isCell)
  t.ok(cellReceipts.length > 20, `audited ${cellReceipts.length} fixed 1200-byte cells on CF edge`)
  t.is(
    cellReceipts.every((r) => r.bytes === 1200),
    true,
    'every circuit cell audited on Cloudflare Workers is exactly 1200 bytes'
  )
  t.is(
    edgeReceipts.every((r) => r.leakDetected === false),
    true,
    'zero Cloudflare Worker relay hops observed destination public key or plaintext'
  )

  // Verify N-1 per-hop LIONESS onion transformation across guard -> safety vs safety -> terminal
  const guardToSafetyEnvelopes = new Set(
    cellReceipts
      .filter((r) => r.fromRole === 'guard' && r.toRole === 'safety' && r.envelopeDigest)
      .map((r) => r.envelopeDigest)
  )
  const safetyToTerminalEnvelopes = new Set(
    cellReceipts
      .filter((r) => r.fromRole === 'safety' && r.toRole === 'terminal' && r.envelopeDigest)
      .map((r) => r.envelopeDigest)
  )
  let sharedEnvelopes = 0
  for (const env of guardToSafetyEnvelopes) {
    if (safetyToTerminalEnvelopes.has(env)) sharedEnvelopes++
  }
  t.is(
    sharedEnvelopes,
    0,
    'N-1 LIONESS onion layers ensure zero identical 1101-byte envelopes across CF Worker hops'
  )
})
