'use strict'

const fs = require('fs')
const os = require('os')
const path = require('path')
const { spawn } = require('child_process')
const test = require('brittle')
const b4a = require('b4a')

const HyperDHT = require('../..')
const { CELL_SIZE } = require('../../lib/private/cell-codec')
const { TOPOLOGY_ROLE } = require('../../lib/private/protocol')
const { endpoint, grant, sourceOptions } = require('./helpers/native-config')
const { readPcap, contains } = require('./process/pcap')

const PORT = 49400
const HOSTS = Object.freeze([
  '127.70.1.1',
  '127.70.2.1',
  '127.70.3.1',
  '127.70.4.1',
  '127.70.5.1',
  '127.70.6.1',
  '127.70.7.1'
])

function waitForCapture(child) {
  return new Promise((resolve, reject) => {
    let stderr = ''
    const timer = setTimeout(() => finish(new Error('PEER_CAPTURE_START_TIMEOUT')), 5000)
    function cleanup() {
      clearTimeout(timer)
      child.stderr.removeListener('data', ondata)
      child.removeListener('error', onerror)
      child.removeListener('exit', onexit)
    }
    function finish(error) {
      cleanup()
      if (error) reject(error)
      else resolve()
    }
    function ondata(chunk) {
      stderr += chunk.toString()
      if (stderr.includes('listening on')) finish(null)
    }
    function onerror(error) {
      finish(error)
    }
    function onexit(code) {
      finish(new Error(`PEER_CAPTURE_EARLY_EXIT:${code}`))
    }
    child.stderr.on('data', ondata)
    child.once('error', onerror)
    child.once('exit', onexit)
  })
}

function stopCapture(child) {
  return new Promise((resolve, reject) => {
    child.once('error', reject)
    child.once('exit', () => resolve())
    child.kill('SIGINT')
  })
}

function readBytes(stream, expected) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let length = 0
    function cleanup() {
      stream.removeListener('data', ondata)
      stream.removeListener('error', onerror)
      stream.removeListener('end', onend)
    }
    function ondata(chunk) {
      chunks.push(b4a.from(chunk))
      length += chunk.byteLength
      if (length < expected) return
      cleanup()
      resolve(b4a.concat(chunks))
    }
    function onerror(error) {
      cleanup()
      reject(error)
    }
    function onend() {
      cleanup()
      reject(new Error('PEER_CAPTURE_STREAM_ENDED'))
    }
    stream.on('data', ondata)
    stream.once('error', onerror)
    stream.once('end', onend)
  })
}
if (process.platform !== 'linux') {
  test.skip('peer v3 Linux packet capture', () => {})
} else {
  test('peer v3 Linux packet capture', { timeout: 120000 }, async (t) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hyperdht-peer-v3-'))
    const captureFile = path.join(directory, 'peer-v3.pcap')
    const retainCapture = process.env.PR_RETAIN_CAPTURE === '1'
    const nodes = []
    let capture = null

    try {
      const boot = new HyperDHT({
        bootstrap: [],
        host: HOSTS[0],
        port: PORT,
        ephemeral: false,
        firewalled: false
      })
      nodes.push(boot)
      await boot.ready()
      const bootstrap = [{ host: HOSTS[0], port: PORT }]
      const relays = HOSTS.slice(3).map((host) => ({
        ...endpoint(PORT, TOPOLOGY_ROLE.SAFETY_GUARD),
        host,
        grants: []
      }))
      function edge(left, right) {
        const wire = grant(
          { ...left, role: TOPOLOGY_ROLE.SAFETY_GUARD },
          { ...right, role: TOPOLOGY_ROLE.SAFETY_FINAL }
        )
        left.grants.push(wire)
        right.grants.push(wire)
      }
      edge(relays[0], relays[1])
      edge(relays[1], relays[2])
      edge(relays[2], relays[0])
      for (const relay of relays.slice(0, 3)) edge(relay, relays[3])

      for (let index = 1; index < 3; index++) {
        nodes.push(
          new HyperDHT({
            bootstrap,
            host: HOSTS[index],
            port: PORT,
            ephemeral: false,
            firewalled: true,
            privateRouting: sourceOptions()
          })
        )
      }
      for (const relay of relays) {
        nodes.push(
          new HyperDHT({
            bootstrap,
            host: relay.host,
            port: PORT,
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
        )
      }
      await Promise.all(nodes.slice(1).map((node) => node.ready()))
      await Promise.all(nodes.slice(1).map((node) => node.privateRouting.ready()))
      const source = nodes[1]
      const destination = nodes[2]
      const serverKeyPair = HyperDHT.keyPair()
      const server = destination.privateRouting.createServer((socket) => {
        socket.on('error', () => {})
        socket.pipe(socket)
      })
      await server.listen(serverKeyPair)
      const captureArguments = [
        'tcpdump',
        '-i',
        'lo',
        '-U',
        '-n',
        '-s',
        '0',
        '-w',
        captureFile,
        'udp',
        'and',
        'port',
        String(PORT)
      ]
      const captureCommand = process.getuid() === 0 ? captureArguments.shift() : 'sudo'
      if (captureCommand === 'sudo') captureArguments.unshift('-n', '--')
      capture = spawn(captureCommand, captureArguments)
      await waitForCapture(capture)

      const sentinel = b4a.from('peer-v3-linux-capture-plaintext-9b42f1')
      const payload = b4a.alloc(64 * 1024, 0x5a)
      sentinel.copy(payload, 8192)
      const socket = source.privateRouting.connect(server.publicKey)
      socket.on('error', () => {})
      t.is(await socket.opened, true, 'private session opens in the captured Linux topology')
      const echo = readBytes(socket, payload.byteLength)
      socket.write(payload)
      t.alike((await echo).subarray(0, payload.byteLength), payload)
      const closed = new Promise((resolve) => socket.once('close', resolve))
      socket.destroy()
      await closed
      await new Promise((resolve) => setTimeout(resolve, 100))
      await stopCapture(capture)
      capture = null

      const report = source.privateRouting.exposureReport()
      t.is(report.directDestinationSends, 0, 'private controller never dials the destination key')
      const parsed = readPcap(captureFile)
      t.is(parsed.otherFrames, 0)
      t.ok(parsed.datagrams.length > 0, 'capture contains live UDP traffic')
      const direct = parsed.datagrams.filter(
        (datagram) =>
          (datagram.source === HOSTS[1] && datagram.destination === HOSTS[2]) ||
          (datagram.source === HOSTS[2] && datagram.destination === HOSTS[1])
      )
      t.is(
        parsed.datagrams.some((datagram) => contains(datagram.payload, sentinel)),
        false,
        'captured UDP payloads hide application plaintext'
      )
      t.is(
        parsed.datagrams.some((datagram) => contains(datagram.payload, serverKeyPair.publicKey)),
        false,
        'captured UDP payloads hide the stable destination identity'
      )
      t.is(
        direct.some((datagram) => contains(datagram.payload, sentinel)),
        false,
        'ordinary DHT traffic sharing endpoint addresses carries no private plaintext'
      )
      t.is(
        direct.some((datagram) => contains(datagram.payload, serverKeyPair.publicKey)),
        false,
        'ordinary DHT traffic sharing endpoint addresses carries no stable destination key'
      )

      const relayHosts = new Set(HOSTS.slice(3))
      const guardHosts = new Set(HOSTS.slice(3, 6))
      const terminalHost = HOSTS[6]
      const cellDatagrams = parsed.datagrams.filter(
        (datagram) =>
          datagram.payload.byteLength === CELL_SIZE &&
          (relayHosts.has(datagram.source) || relayHosts.has(datagram.destination))
      )
      t.ok(cellDatagrams.length > 0, 'capture records fixed 1200-byte peer-v3 cells')
      const sourceToGuard = cellDatagrams.filter(
        (datagram) =>
          (datagram.source === HOSTS[1] || datagram.source === HOSTS[2]) &&
          guardHosts.has(datagram.destination)
      )
      const guardToSafety = cellDatagrams.filter(
        (datagram) =>
          guardHosts.has(datagram.source) &&
          guardHosts.has(datagram.destination) &&
          datagram.source !== datagram.destination
      )
      const safetyToTerminal = cellDatagrams.filter(
        (datagram) => guardHosts.has(datagram.source) && datagram.destination === terminalHost
      )
      t.ok(sourceToGuard.length > 0, 'source -> guard fixed cells are captured')
      t.ok(guardToSafety.length > 0, 'guard -> safety fixed cells are captured')
      t.ok(safetyToTerminal.length > 0, 'safety -> terminal fixed cells are captured')
      const envelopeHex = (datagram) =>
        b4a.toString(datagram.payload.subarray(99, CELL_SIZE), 'hex')
      const sourceEnvelopes = new Set(sourceToGuard.map(envelopeHex))
      const guardEnvelopes = new Set(guardToSafety.map(envelopeHex))
      const safetyEnvelopes = new Set(safetyToTerminal.map(envelopeHex))
      t.is(
        guardToSafety.some((datagram) => sourceEnvelopes.has(envelopeHex(datagram))),
        false,
        'guard changes 1101-byte LIONESS envelope before forwarding to safety'
      )
      t.is(
        safetyToTerminal.some((datagram) => guardEnvelopes.has(envelopeHex(datagram))),
        false,
        'safety changes 1101-byte LIONESS envelope before forwarding to terminal'
      )
      t.is(
        sourceToGuard.some((datagram) => safetyEnvelopes.has(envelopeHex(datagram))),
        false,
        'no source envelope matches a terminal-bound envelope'
      )

      sentinel.fill(0)
      payload.fill(0)
      await server.close()
    } finally {
      try {
        if (capture && capture.exitCode === null && capture.signalCode === null) {
          const exited = new Promise((resolve) => capture.once('exit', resolve))
          capture.kill('SIGKILL')
          await exited
        }
      } finally {
        const destroyed = await Promise.allSettled(
          nodes.reverse().map((node) => node.destroy({ force: true }))
        )
        // All nodes torn down
        if (retainCapture) t.comment(`peer capture retained at ${captureFile}`)
        else fs.rmSync(directory, { recursive: true, force: true })
        const failures = destroyed.filter((result) => result.status === 'rejected')
        if (failures.length)
          throw new AggregateError(
            failures.map((result) => result.reason),
            'peer capture node cleanup failed'
          )
      }
    }
  })
}
