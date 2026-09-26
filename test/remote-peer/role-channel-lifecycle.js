'use strict'

// Pins the child-process semantics RemoteChild promises the coordinator.
//
// test/remote-peer/bridge-transport.js proves the whole path with a real role on
// the far side. This file removes the role: the far side is a bare server in the
// test that plays the part of role-bridge.js, so every event a RemoteChild can
// raise is provoked on purpose rather than waited for. What is pinned is the
// lifecycle the coordinator depends on and cannot see the transport behind:
// bytes both ways, a silent stderr, one 'exit' per channel, the outcome a channel
// settles for a clean end, a broken stream and a killed role, and what a write
// after the far side is gone reports.
//
// The outcome is the part a stream cannot carry. An 'end' and a 'close' say only
// that a role is gone, so the channel asks the far side for a terminal status
// record and settles from that; the far side here serves one per channel, or
// refuses to, which is how the fail-closed path is provoked.
//
// Everything runs on one testnet over real DHT streams: the encoding, framing and
// half-close rules of the transport are exactly what a distributed run uses.

const test = require('brittle')
const b4a = require('b4a')
const DHT = require('../..')
const createTestnet = require('../../testnet')
const { peerKeyPair, coordinatorKeyPair: deriveCoordinatorKeyPair } = require('./identity')
const { OP, writeFrame } = require('./frames')
const { MODE, RemoteChild } = require('./role-channels')

const SECRET = 'c0ffee0123456789abcdef0123456789abcdef0123456789abcdef0123456789'
// The coordinator's own secret. A role host never holds this, only the matching
// public key, so this file holds both halves precisely because it plays both sides.
const COORDINATOR_SECRET = 'facade00112233445566778899aabbccddeeff00112233445566778899aabbcc'
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
// role's bytes. The mode byte is read by the server, which has to route a status
// request away from the channel before either sees the other's bytes.
class FarSide {
  constructor(socket, first) {
    this.socket = socket
    this.mode = first[0]
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
    socket.on('data', (chunk) => {
      this.received.push(chunk)
      this.bytes += chunk.byteLength
    })
    const rest = first.subarray(1)
    if (rest.byteLength > 0) {
      this.received.push(rest)
      this.bytes += rest.byteLength
    }
  }

  payload() {
    return b4a.concat(this.received)
  }
}

// role-bridge.js's terminal status record, with the clean outcome as the default so
// each case states only what it is about. A far side that serves no record at all is
// a bridge that died with its role, which the coordinator must read as a failure.
function statusFrame(index, status) {
  return writeFrame(
    OP.REPORT,
    b4a.from(
      JSON.stringify({
        index,
        attached: true,
        exited: true,
        code: null,
        signal: null,
        stderrBytes: 0,
        stderrSample: '',
        ...status
      })
    )
  )
}

// The coordinator's node, plus one server per channel. A role's terminal status
// lives behind that role's own key on a real bridge, so each attach() takes its own
// role key pair and serves both the channel and the status behind it; the
// coordinator's key is one for all of them, exactly as a run of eleven roles has it.
async function harness(t) {
  const testnet = await createTestnet(6, t.teardown.bind(t))
  const runId = `lifecycle-${Date.now()}`
  const coordinatorKeyPair = deriveCoordinatorKeyPair(COORDINATOR_SECRET)

  const host = new DHT({ bootstrap: testnet.bootstrap })
  const coordinator = new DHT({ bootstrap: testnet.bootstrap })

  const children = []
  const fars = []
  const servers = []

  t.teardown(
    async () => {
      for (const child of children) {
        if (!child.killed) child.kill()
      }
      for (const far of fars) far.socket.destroy()
      for (const server of servers) await server.close()
      await coordinator.destroy()
      await host.destroy()
    },
    { order: 1 }
  )

  let next = 1
  return {
    // status is what a MODE.STATUS connection will be answered with, merged over a
    // clean record. Passing none means this far side serves no status at all.
    async attach({ status = null } = {}) {
      const index = next++
      const hostKeyPair = peerKeyPair(SECRET, runId, index)
      const statusRequests = []
      const gate = deferred()

      const server = host.createServer(
        {
          firewall: (remotePublicKey) => !b4a.equals(remotePublicKey, coordinatorKeyPair.publicKey)
        },
        (socket) => {
          socket.on('error', () => {})
          socket.once('data', (chunk) => {
            if (chunk[0] === MODE.STATUS) {
              statusRequests.push(Date.now())
              if (status === null) return socket.destroy()
              socket.write(statusFrame(index, status))
              setTimeout(() => socket.destroy(), 100)
              return
            }
            gate.resolve(new FarSide(socket, chunk))
          })
        }
      )
      servers.push(server)
      await server.listen(hostKeyPair)

      const socket = coordinator.connect(hostKeyPair.publicKey, { keyPair: coordinatorKeyPair })
      socket.on('error', () => {})
      await new Promise((resolve, reject) => {
        socket.once('open', resolve)
        socket.once('error', reject)
      })

      const child = new RemoteChild(socket, index, {
        node: coordinator,
        keyPair: coordinatorKeyPair,
        publicKey: hostKeyPair.publicKey,
        // Inside every wait below: a status that cannot be fetched has to fail the
        // channel promptly, not stall the run that is waiting on the exit.
        statusTimeoutMs: 8000
      })
      // The coordinator attaches one on every record; a stdin write that fails has
      // to be reported through the callback, not thrown at the process.
      const stdinErrors = []
      child.stdin.on('error', (err) => stdinErrors.push(err))
      children.push(child)

      // Role stderr exists only in the terminal status, and RemoteChild replays it
      // here. Whether it landed before the exit is the whole point: the coordinator
      // fails a run on the stderr chunk, so an exit that overtook it would report the
      // wrong reason.
      const stderrChunks = []
      child.stderr.on('data', (chunk) => stderrChunks.push(chunk))
      const stderrBytes = () => stderrChunks.reduce((total, chunk) => total + chunk.byteLength, 0)

      const exits = []
      const errors = []
      const firstExit = deferred()
      child.on('exit', (code, signal) => {
        // Captured synchronously, stderr included: what the coordinator had already
        // seen when the exit fired is not recoverable afterwards.
        const outcome = { code, signal, stderrBytes: stderrBytes() }
        exits.push(outcome)
        firstExit.resolve(outcome)
      })

      const far = await gate.promise
      fars.push(far)

      return {
        child,
        far,
        exits,
        errors,
        statusRequests,
        stdinErrors,
        stderr() {
          return b4a.toString(b4a.concat(stderrChunks), 'utf8')
        },
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
  t.is(
    io.stderr().length,
    0,
    'stderr carries nothing while the channel is live: role stderr never rides the control stream'
  )

  // 4: a graceful far-side close. role-bridge.js ends the stream for a role that
  // exited zero, so this is what the coordinator sees when a role finishes its work,
  // and live-process-suite.js expects an exit with code 0 for it.
  //
  // The end has to start the settle by itself, and the settle costs one status round
  // trip. This side stays open until then, so a channel that instead waited for
  // 'close' would burn the coordinator's thirty-second scenario deadline. Ten seconds
  // is far more than an end plus a status fetch needs and far less than that deadline,
  // so a pass here means the exit came from the 'end'. Exactly one status is asked
  // for: the close that follows must not fetch a second one.
  const graceful = await remote.attach({ status: { code: 0, signal: null } })
  graceful.listenForErrors()
  graceful.far.socket.end()
  let gracefulExit = null
  try {
    gracefulExit = await graceful.exit(10_000)
  } catch (err) {
    gracefulExit = { failure: err.message }
  }
  t.alike(
    {
      exits: graceful.exits.length,
      outcome: gracefulExit,
      statuses: graceful.statusRequests.length
    },
    { exits: 1, outcome: { code: 0, signal: null, stderrBytes: 0 }, statuses: 1 },
    'a graceful far-side end exits exactly once with code 0, taken from the status the far side served'
  )
  await delay(SETTLE_MS)
  t.is(
    graceful.exits.length,
    1,
    'the close that follows the graceful end does not exit a second time'
  )

  // 5: a broken far side that can no longer be asked how it went. role-bridge.js
  // destroys the stream for a role that exited non-zero, and the transport itself
  // fails this way too; here the far side also refuses the status, which is a bridge
  // that died with its role. Nothing establishes an outcome, so the channel must
  // report a failure.
  const broken = await remote.attach()
  broken.listenForErrors()
  broken.far.socket.destroy()
  const brokenExit = await broken.exit(20_000)
  await delay(SETTLE_MS)
  t.alike(
    {
      exits: broken.exits.length,
      failed: brokenExit.code !== 0 || brokenExit.signal !== null,
      asked: broken.statusRequests.length > 0,
      errors: broken.errors.length > 0
    },
    { exits: 1, failed: true, asked: true, errors: true },
    'a destroyed far side with no status exits once as a failure and hands the error to a listener'
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

  // 6: kill() is the coordinator's only lever on a remote role, and the one settle
  // that consults no status: the coordinator chose the signal, so it already knows
  // the outcome. A local child that is killed reports code null and the signal, and
  // this has to match, or a role that had to be cut down would be indistinguishable
  // from one that finished its work. The far side here would happily serve a clean
  // zero, and must not be asked.
  const killed = await remote.attach({ status: { code: 0, signal: null } })
  killed.listenForErrors()
  t.is(killed.child.kill(), true, 'kill reports that it acted')
  await waitFor(() => killed.far.closed, 20_000, 'the far side to see the close')
  const killedExit = await killed.exit(20_000)
  await delay(SETTLE_MS)
  t.ok(
    killed.child.killed && killed.far.closed && killed.child._socket.destroyed,
    'kill closes the stream and the far side observes it'
  )
  t.alike(
    {
      exits: killed.exits.length,
      code: killedExit.code,
      signal: killedExit.signal,
      statuses: killed.statusRequests.length
    },
    { exits: 1, code: null, signal: 'SIGTERM', statuses: 0 },
    'kill exits once with no code and the signal it was given, without asking for a status'
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

  // 8: a role that failed behind a stream that ended cleanly. This is the case no
  // stream event can express: an 'end' used to mean zero, so a role that exited 7
  // arrived at the coordinator as a clean finish. Only the status record carries the
  // code, and no 'error' may accompany it -- a spawned child that exits non-zero
  // emits 'exit' alone, and the coordinator would otherwise report
  // PROCESS_CHILD_ERROR where a local run reports PROCESS_EARLY_EXIT.
  const failedCode = await remote.attach({ status: { code: 7, signal: null } })
  failedCode.listenForErrors()
  failedCode.far.socket.end()
  const failedCodeExit = await failedCode.exit(20_000)
  await delay(SETTLE_MS)
  t.alike(
    {
      exits: failedCode.exits.length,
      code: failedCodeExit.code,
      signal: failedCodeExit.signal,
      errors: failedCode.errors.length
    },
    { exits: 1, code: 7, signal: null, errors: 0 },
    'a far side reporting a non-zero code exits with that code rather than with zero'
  )

  // 9: a role the far side had to kill, reached through a stream that was destroyed
  // rather than ended. A spawned child reports code null with the signal, and the
  // record is what makes that reachable at all.
  const signalled = await remote.attach({ status: { code: null, signal: 'SIGKILL' } })
  signalled.listenForErrors()
  signalled.far.socket.destroy()
  const signalledExit = await signalled.exit(20_000)
  await delay(SETTLE_MS)
  t.alike(
    {
      exits: signalled.exits.length,
      code: signalledExit.code,
      signal: signalledExit.signal,
      errors: signalled.errors.length
    },
    { exits: 1, code: null, signal: 'SIGKILL', errors: 0 },
    'a far side reporting a signal exits with that signal and no code'
  )

  // 10: fail closed. The stream ends exactly the way a finished role's does and the
  // far side serves no status at all. Reporting zero here is the confusion this
  // protocol exists to prevent, so the channel reports a failure instead, and inside
  // its own bounded window rather than hanging on the coordinator's deadline.
  const noStatus = await remote.attach()
  noStatus.listenForErrors()
  noStatus.far.socket.end()
  const startedAt = Date.now()
  const noStatusExit = await noStatus.exit(20_000)
  const elapsed = Date.now() - startedAt
  t.alike(
    {
      exits: noStatus.exits.length,
      failed: noStatusExit.code !== 0 || noStatusExit.signal !== null,
      asked: noStatus.statusRequests.length > 0,
      errors: noStatus.errors.length > 0
    },
    { exits: 1, failed: true, asked: true, errors: true },
    'a clean far-side end with no status available exits as a failure, never as a success'
  )
  t.ok(elapsed < 15_000, `the unavailable status failed inside its window, in ${elapsed}ms`)

  // 11: role stderr. The bridge counts it and hands back a bounded sample, and the
  // channel replays that into its own stderr before settling, so coordinator.js:279
  // fails a remote run on stderr exactly as it fails a local one. The count captured
  // when 'exit' fired is what proves the order: an exit that overtook the bytes would
  // have the coordinator report the wrong reason for the same fault.
  const noisy = await remote.attach({
    status: { code: 0, signal: null, stderrBytes: 11, stderrSample: 'role noise\n' }
  })
  noisy.listenForErrors()
  noisy.far.socket.end()
  const noisyExit = await noisy.exit(20_000)
  await delay(SETTLE_MS)
  t.alike(
    { text: noisy.stderr(), atExit: noisyExit.stderrBytes, code: noisyExit.code },
    { text: 'role noise\n', atExit: 11, code: 0 },
    'stderr reported in the status reaches child.stderr, and lands before the exit'
  )

  // coordinator.js:549 stops a role by ending its stdin, and a spawned role reads
  // that as EOF. The channel half-closes its stream so the bridge can pass the same
  // EOF to its role, and like a spawned child that has not chosen to exit yet, the
  // channel does not exit on it.
  const eof = await remote.attach({ status: { code: 0, signal: null } })
  eof.child.stdin.end()
  await waitFor(() => eof.far.ended, 20_000, 'the far side to see the half-close')
  await delay(SETTLE_MS)
  t.alike(
    { ended: eof.far.ended, exited: eof.child.exited },
    { ended: true, exited: false },
    'ending stdin half-closes the stream so the far side sees EOF, and does not exit the channel'
  )
})
