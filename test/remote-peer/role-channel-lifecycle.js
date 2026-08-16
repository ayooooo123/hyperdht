'use strict'

// Pins the child-process semantics RemoteChild promises the coordinator.
//
// test/remote-peer/bridge-transport.js proves the whole path with a real role on
// the far side. This file removes the role: the far side is a bare server in the
// test that plays the part of role-bridge.js, so every event a RemoteChild can
// raise is provoked on purpose rather than waited for. What is pinned is the
// lifecycle the coordinator depends on and cannot see the transport behind:
// bytes both ways, a silent stderr, one 'exit' per channel, the difference
// between a graceful far-side close and a broken one, kill(), and what a write
// after the far side is gone reports.
//
// Everything runs on one testnet over real DHT streams: the encoding, framing and
// half-close rules of the transport are exactly what a distributed run uses.

const test = require('brittle')
const b4a = require('b4a')
const DHT = require('../..')
const createTestnet = require('../../testnet')
const { peerKeyPair, proberKeyPair } = require('./identity')
const { MODE, RemoteChild } = require('./role-channels')

const SECRET = 'c0ffee0123456789abcdef0123456789abcdef0123456789abcdef0123456789'
// Far past a udx packet, so assertion 1 crosses many of them.
const BIG_BYTES = 256 * 1024
const SETTLE_MS = 500

function pattern(bytes, seed) {
  const out = b4a.allocUnsafe(bytes)
  for (let i = 0; i < bytes; i++) out[i] = (i * 31 + seed) & 0xff
  return out
}

function deferred() {
  let resolve = null
  let reject = null
  const promise = new Promise((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

async function waitFor(predicate, timeoutMs, what) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (predicate()) return true
    await delay(25)
  }
  throw new Error(`timed out waiting for ${what}`)
}

// The far side of one channel, as role-bridge.js sees it: a mode byte, then the
// role's bytes.
class FarSide {
  constructor(socket) {
    this.socket = socket
    this.mode = null
    this.received = []
    this.bytes = 0
    this.ended = false
    this.closed = false

    socket.on('error', () => {})
    socket.once('end', () => {
      this.ended = true
    })
    socket.once('close', () => {
      this.closed = true
    })
    const onData = (chunk) => {
      if (this.mode === null) {
        this.mode = chunk[0]
        chunk = chunk.subarray(1)
        if (chunk.byteLength === 0) return
      }
      this.received.push(chunk)
      this.bytes += chunk.byteLength
    }
    socket.on('data', onData)
  }

  payload() {
    return b4a.concat(this.received)
  }
}

// One server standing in for every role's bridge, plus the coordinator's node.
// Each attach() is a fresh channel on the same pair of nodes, which is how a real
// run reaches eleven roles: one prober key, many connections.
async function harness(t) {
  const testnet = await createTestnet(6, t.teardown.bind(t))
  const runId = `lifecycle-${Date.now()}`
  const hostKeyPair = peerKeyPair(SECRET, runId, 1)
  const coordinatorKeyPair = proberKeyPair(SECRET, runId)

  const host = new DHT({ bootstrap: testnet.bootstrap })
  const coordinator = new DHT({ bootstrap: testnet.bootstrap })

  const pending = []
  const waiting = []
  const server = host.createServer(
    { firewall: (remotePublicKey) => !b4a.equals(remotePublicKey, coordinatorKeyPair.publicKey) },
    (socket) => {
      const far = new FarSide(socket)
      const waiter = waiting.shift()
      if (waiter) waiter.resolve(far)
      else pending.push(far)
    }
  )
  await server.listen(hostKeyPair)

  const children = []
  const fars = []

  t.teardown(
    async () => {
      for (const child of children) {
        if (!child.killed) child.kill()
      }
      for (const far of fars) far.socket.destroy()
      await server.close()
      await coordinator.destroy()
      await host.destroy()
    },
    { order: 1 }
  )

  let next = 1
  return {
    async attach() {
      const accepted = pending.length > 0 ? Promise.resolve(pending.shift()) : null
      const gate = accepted === null ? deferred() : null
      if (gate) waiting.push(gate)

      const socket = coordinator.connect(hostKeyPair.publicKey, { keyPair: coordinatorKeyPair })
      socket.on('error', () => {})
      await new Promise((resolve, reject) => {
        socket.once('open', resolve)
        socket.once('error', reject)
      })

      const child = new RemoteChild(socket, next++)
      // The coordinator attaches one on every record; a stdin write that fails has
      // to be reported through the callback, not thrown at the process.
      const stdinErrors = []
      child.stdin.on('error', (err) => stdinErrors.push(err))
      children.push(child)

      const exits = []
      const errors = []
      const firstExit = deferred()
      child.on('exit', (code, signal) => {
        // Captured synchronously. Whether the stream had already closed when the
        // exit fired is the whole difference between reading the far side's 'end'
        // and waiting for a 'close' that a half-open stream never reaches.
        const outcome = { code, signal, streamClosed: child._socket.destroyed }
        exits.push(outcome)
        firstExit.resolve(outcome)
      })

      const far = await (accepted || gate.promise)
      fars.push(far)
      await waitFor(() => far.mode !== null, 20_000, 'the mode byte')

      return {
        child,
        far,
        exits,
        errors,
        stdinErrors,
        // Attaching 'error' is optional for the coordinator, so it is optional here:
        // assertion 5 needs both shapes.
        listenForErrors() {
          child.on('error', (err) => errors.push(err))
        },
        exit(timeoutMs) {
          return Promise.race([
            firstExit.promise,
            delay(timeoutMs).then(() => {
              throw new Error(`role ${child.index} never exited`)
            })
          ])
        }
      }
    }
  }
}

test('a remote role channel behaves like a child process', async (t) => {
  t.timeout(180_000)

  const remote = await harness(t)

  // 1 + 2 + 3: the bytes, both ways, on one channel.
  const io = await remote.attach()
  t.is(io.far.mode, MODE.ATTACH, 'the channel announced itself as a role attachment')

  const upstream = pattern(BIG_BYTES, 7)
  io.child.stdin.write(upstream)
  await waitFor(() => io.far.bytes >= upstream.byteLength, 60_000, 'the far side to read stdin')
  t.alike(
    io.far.payload(),
    upstream,
    'bytes written to stdin reach the far side unchanged, across many packets'
  )

  let stderrBytes = 0
  io.child.stderr.on('data', (chunk) => {
    stderrBytes += chunk.byteLength
  })

  const downstream = pattern(BIG_BYTES, 19)
  const collected = []
  let collectedBytes = 0
  io.child.stdout.on('data', (chunk) => {
    collected.push(chunk)
    collectedBytes += chunk.byteLength
  })
  io.far.socket.write(downstream)
  await waitFor(() => collectedBytes >= downstream.byteLength, 60_000, 'stdout to catch up')
  t.alike(
    b4a.concat(collected),
    downstream,
    'bytes sent by the far side arrive on stdout unchanged'
  )

  await delay(SETTLE_MS)
  t.is(stderrBytes, 0, 'stderr carries no bytes: the bridge reports role stderr out of band')

  // 4: a graceful far-side close. role-bridge.js:242 ends the stream for a role
  // that exited zero, so this is what the coordinator sees when a role finishes
  // its work, and live-process-suite.js expects an exit with code 0 for it.
  //
  // The end has to be the exit by itself. This side stays open, so the stream
  // never closes, and a channel that waits for 'close' burns the coordinator's
  // thirty-second scenario deadline instead. Five seconds is far more than a
  // half-close needs and far less than that deadline, so a pass here means the
  // exit came from 'end'.
  const graceful = await remote.attach()
  graceful.listenForErrors()
  graceful.far.socket.end()
  let gracefulExit = null
  try {
    gracefulExit = await graceful.exit(5000)
  } catch (err) {
    gracefulExit = { failure: err.message }
  }
  t.alike(
    { exits: graceful.exits.length, outcome: gracefulExit },
    { exits: 1, outcome: { code: 0, signal: null, streamClosed: false } },
    'a graceful far-side end exits exactly once with code 0, without waiting for the stream to close'
  )
  await delay(SETTLE_MS)
  t.is(
    graceful.exits.length,
    1,
    'the close that follows the graceful end does not exit a second time'
  )

  // 5: a broken far side. role-bridge.js:243 destroys the stream for a role that
  // exited non-zero, and the transport itself fails this way too.
  const broken = await remote.attach()
  broken.listenForErrors()
  broken.far.socket.destroy()
  const brokenExit = await broken.exit(20_000)
  await delay(SETTLE_MS)
  t.alike(
    {
      exits: broken.exits.length,
      failed: brokenExit.code !== 0 || brokenExit.signal !== null,
      errors: broken.errors.length > 0
    },
    { exits: 1, failed: true, errors: true },
    'a destroyed far side exits once as a failure and hands the error to a listener'
  )

  // The same break with nothing listening for 'error'. Reaching the assertion at
  // all is half of it: an unheard 'error' event throws out of EventEmitter and
  // would take this process down before the next line ran.
  const unheard = await remote.attach()
  unheard.far.socket.destroy()
  const unheardExit = await unheard.exit(20_000)
  await delay(SETTLE_MS)
  t.alike(
    {
      exits: unheard.exits.length,
      failed: unheardExit.code !== 0 || unheardExit.signal !== null,
      errors: unheard.errors.length
    },
    { exits: 1, failed: true, errors: 0 },
    'a destroyed far side with no error listener exits once as a failure and does not crash the process'
  )

  // 6: kill() is the coordinator's only lever on a remote role.
  const killed = await remote.attach()
  killed.listenForErrors()
  t.is(killed.child.kill(), true, 'kill reports that it acted')
  await waitFor(() => killed.far.closed, 20_000, 'the far side to see the close')
  await killed.exit(20_000)
  t.ok(
    killed.child.killed && killed.far.closed && killed.child._socket.destroyed,
    'kill closes the stream and the far side observes it'
  )

  // 7: the coordinator writes control frames without knowing whether the role is
  // still there, and a failed write must come back through the callback.
  const gone = await remote.attach()
  gone.listenForErrors()
  gone.far.socket.destroy()
  await gone.exit(20_000)
  const write = deferred()
  const thrown = []
  try {
    gone.child.stdin.write(b4a.from([1, 2, 3, 4]), (err) => write.resolve(err || null))
  } catch (err) {
    thrown.push(err)
    write.resolve(err)
  }
  const writeError = await Promise.race([
    write.promise,
    delay(5000).then(() => {
      throw new Error('the write never called back')
    })
  ])
  t.ok(
    writeError instanceof Error && thrown.length === 0,
    'a write after the far side is gone reports an error to the caller instead of throwing'
  )

  // Two more lifecycle facts, reported rather than asserted: they are what
  // RemoteChild does today, and pinning them here would fight whoever fixes them.
  //
  // A local child that is killed reports code null with a signal. kill() here
  // destroys the stream, and the destroy arrives as the same exit a finished role
  // gets, so a role the coordinator had to kill is indistinguishable from one that
  // stopped on its own.
  t.comment(`kill() surfaced exit ${JSON.stringify(killed.exits[0])}`)

  // coordinator.js:549 ends a role's stdin to stop it. A local role reads that as
  // EOF; here the Writable's final() only calls back, so the far side is told
  // nothing and role-bridge.js never gives its role process an EOF either.
  const eof = await remote.attach()
  eof.child.stdin.end()
  await delay(1500)
  t.comment(
    `after stdin.end() the far side saw ended=${eof.far.ended} closed=${eof.far.closed}, and the channel exited=${eof.child.exited}`
  )
})
