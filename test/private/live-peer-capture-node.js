'use strict'

const fs = require('fs')
const os = require('os')
const path = require('path')
const { spawn } = require('child_process')
const test = require('brittle')
const b4a = require('b4a')

const HyperDHT = require('../..')
const { CELL_SIZE } = require('../../lib/private/cell-codec')
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

function privateRouting(relay) {
  return {
    release: 'alpha',
    acknowledgeAlpha: true,
    mode: 'optional',
    profile: 'standard',
    relay
  }
}

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
  const { createPrivatePeerTestScope } = require('./helpers/private-peer')

  test('peer v3 Linux packet capture', { timeout: 120000 }, async (t) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hyperdht-peer-v3-'))
    const captureFile = path.join(directory, 'peer-v3.pcap')
    const retainCapture = process.env.PR_RETAIN_CAPTURE === '1'
    const nodes = []
    let capture = null
    const openedCells = new Map()
    const sealedCells = new Map()
    const awaitingTransform = []
    const transforms = []
    const observationErrors = []
    const scope = createPrivatePeerTestScope()
    function recordCell(views, event, relay) {
      const circuitId = b4a.toString(event.cell.subarray(12, 28), 'hex')
      const key = [relay, event.label, circuitId, event.direction].join(':')
      if (!views.has(key)) {
        views.set(key, {
          relay,
          label: event.label,
          circuitId,
          direction: event.direction,
          cells: []
        })
      }
      const view = views.get(key)
      view.cells.push(event.cell)
      return view
    }
    const observer = (event) => {
      if (event.role !== 'relay') return
      const relay = b4a.toString(event.relayPublicKey, 'hex')
      if (event.type === 'route-cell-opened') {
        const view = recordCell(openedCells, event, relay)
        awaitingTransform.push({ relay, view, event })
        return
      }
      if (event.type === 'route-transform') {
        const matches = awaitingTransform.filter(
          (row) =>
            row.relay === relay &&
            row.view.label === event.from &&
            b4a.equals(row.event.plaintext, event.plaintext)
        )
        if (matches.length !== 1) {
          observationErrors.push('ambiguous or missing opened view for ' + relay + ':' + event.from)
          return
        }
        const row = matches[0]
        awaitingTransform.splice(awaitingTransform.indexOf(row), 1)
        transforms.push({
          relay,
          from: event.from,
          to: event.to,
          inbound: row.event.cell,
          inboundView: row.view,
          plaintext: event.plaintext,
          outbound: null
        })
        return
      }
      if (event.type === 'route-cell-sealed') {
        const view = recordCell(sealedCells, event, relay)
        const matches = transforms.filter(
          (row) =>
            row.outbound === null &&
            row.relay === relay &&
            row.to === event.label &&
            b4a.equals(row.plaintext, event.plaintext)
        )
        if (matches.length > 1) {
          observationErrors.push('ambiguous transform for ' + relay + ':' + event.label)
        } else if (matches.length === 1) {
          matches[0].outbound = event.cell
          matches[0].outboundView = view
        }
      }
    }

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
      for (let index = 1; index < HOSTS.length; index++) {
        const relay = index >= 3
        const node = scope.create(
          () =>
            new HyperDHT({
              bootstrap,
              host: HOSTS[index],
              port: PORT,
              ephemeral: false,
              firewalled: !relay,
              privateRouting: privateRouting(relay)
            }),
          { observer }
        )
        nodes.push(node)
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

      t.alike(observationErrors, [], 'forwarding observations identify unambiguous relay views')
      const bridgePairs = [
        ['source-safety-1-in', 'source-safety-1-out'],
        ['source-safety-2-in', 'source-safety-2-out'],
        ['guard-entry', 'guard-destination']
      ]
      for (const [from, to] of bridgePairs) {
        const proof = transforms.find(
          (transform) =>
            transform.from === from && transform.to === to && transform.outbound !== null
        )
        t.ok(proof, `${from} -> ${to} is observed`)
        t.is(proof.inbound.byteLength, CELL_SIZE)
        t.is(proof.outbound.byteLength, CELL_SIZE)
        t.is(
          b4a.equals(proof.inbound, proof.outbound),
          false,
          `${from} -> ${to} changes route-cell bytes`
        )
      }
      const entryInbound = Array.from(openedCells.values()).filter(
        (view) => view.label === 'entry-source'
      )
      const entryOutbound = Array.from(sealedCells.values()).filter(
        (view) => view.label === 'entry-destination'
      )
      t.ok(
        entryInbound.length > 0 && entryOutbound.length > 0,
        'entry opens and reseals route cells'
      )
      for (const inbound of entryInbound) {
        const outbound = entryOutbound.filter((view) => view.relay === inbound.relay)
        t.ok(outbound.length > 0, 'the same entry relay has a destination-leg view')
        const outboundKeys = new Set(
          outbound.flatMap((view) => view.cells.map((cell) => b4a.toString(cell, 'hex')))
        )
        t.is(
          inbound.cells.some((cell) => outboundKeys.has(b4a.toString(cell, 'hex'))),
          false,
          'entry never forwards an unchanged route cell'
        )
      }

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
        scope.close()
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
