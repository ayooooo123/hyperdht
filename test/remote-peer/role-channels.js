'use strict'

// Presents remote roles to the existing coordinator as if they were local child
// processes.
//
// test/private/process/coordinator.js drives roles through child.stdin,
// child.stdout, child.stderr, child.kill() and an 'exit' event. Nothing in it
// cares that a child is a process, so a role reached over the DHT can be handed
// to createProcessControl unchanged: the scenario, the control protocol and the
// auditing all stay exactly as the local gates exercise them.

const { PassThrough, Writable } = require('stream')
const EventEmitter = require('events')
const b4a = require('b4a')
const { peerKeyPair, coordinatorKeyPair } = require('./identity')
const { OP, FrameReader, writeFrame } = require('./frames')

// Mirrors role-bridge.js: one byte says whether a connection asks for addresses,
// carries a punch plan, carries a role's control stream, or asks for a role's
// terminal status.
const MODE = Object.freeze({ REPORT: 1, ATTACH: 2, STATUS: 3, PUNCH: 4 })

// A punch round is six datagrams over three seconds plus a drain, so a role answers
// in about five seconds; the rest of this is DHT latency between eleven hosts.
const PUNCH_REPORT_TIMEOUT_MS = 60_000
const PUNCH_CONNECT_TIMEOUT_MS = 30_000
const PUNCH_RETRY_MS = 5_000

const CONNECT_TIMEOUT_MS = 30_000
// A stream event says a role is gone; it never says how it went. The bridge's
// status record is the only place the exit code, the signal and anything the role
// wrote to stderr exist, so it is fetched on its own connection once the control
// stream is over. The fetch is bounded in attempts and in time, and a record that
// cannot be reached fails the channel: a crashed or killed role must never arrive
// as a clean finish.
//
// Each attempt is bounded separately so one hung connect cannot eat the whole
// window and leave no retry. Latency matters beyond the bound: a role that dies
// mid-command races the coordinator's own five-second command deadline
// (coordinator.js:16), and the fetch has to win that race for the run to be told
// "the role exited with code N" rather than "the role did not answer". Both fail,
// so nothing is hidden either way, but only one of them names the cause.
const STATUS_TIMEOUT_MS = 15_000
const STATUS_CONNECT_TIMEOUT_MS = 5_000
const STATUS_FRAME_TIMEOUT_MS = 5_000
const STATUS_ATTEMPTS = 3
const STATUS_RETRY_MS = 500

class RemoteChild extends EventEmitter {
  // options carries what a status fetch needs: the coordinator's node and key pair,
  // and this role's public key. openRemoteRoleChannels holds all three at the point
  // it dials the control stream, so nothing else has to derive them.
  constructor(socket, index, options = {}) {
    super()
    this.index = index
    this.killed = false
    this.exited = false
    this.stdout = new PassThrough()
    // Nothing arrives here while the channel is live: role stderr on the control
    // stream would corrupt it, so the bridge counts the bytes and keeps a bounded
    // sample, and _replayStderr writes that sample in before the exit. The
    // coordinator's own stderr check (coordinator.js:279) then fires for a remote
    // role exactly as it does for a spawned one.
    this.stderr = new PassThrough()
    this._socket = socket
    this._statusEndpoint = {
      node: options.node || null,
      keyPair: options.keyPair || null,
      publicKey: options.publicKey || null,
      timeoutMs: options.statusTimeoutMs || STATUS_TIMEOUT_MS
    }
    this._transportError = null
    this._finishing = false

    const self = this
    this.stdin = new Writable({
      write(chunk, encoding, callback) {
        if (self.exited) return callback(new Error('role has exited'))
        socket.write(chunk)
        callback()
      },
      final(callback) {
        // The coordinator stops a role by ending its stdin (coordinator.js:549) and a
        // spawned child sees EOF. Half-closing this stream is how the far side learns
        // to do the same, so a role that waits for EOF is not left running.
        try {
          socket.end()
        } catch {
          // A stream already gone needs no half-close.
        }
        callback()
      }
    })

    // The bridge needs to know this stream carries a role before any control byte
    // arrives.
    socket.write(b4a.from([MODE.ATTACH]))
    socket.on('data', (chunk) => this.stdout.write(chunk))
    // A role that finished its work exits zero and its bridge ends the stream; a
    // role that failed has its stream destroyed, and that can arrive as a close with
    // no error at all. Neither event carries an outcome, so all three start the same
    // bounded status fetch and the exit is settled from what it returns. Waiting for
    // 'close' alone would also wait forever on a half-open stream, which is why the
    // 'end' is acted on immediately.
    socket.on('end', () => {
      if (typeof socket.end === 'function') socket.end()
      this._finish(null)
    })
    socket.on('error', (err) => this._finish(err))
    socket.once('close', () => this._finish(null))
  }

  // The control stream is over. What the role did lives in the bridge's status
  // record, so it is fetched here and the exit settled from it; an unreachable
  // record settles a failure.
  _finish(err) {
    if (err && this._transportError === null) this._transportError = err
    if (this.exited || this._finishing) return
    this._finishing = true
    this._fetchStatus().then(
      (record) => this._settleFromStatus(record),
      (failure) => this._settle(1, null, this._transportError || failure)
    )
  }

  async _settleFromStatus(record) {
    if (this.exited) return
    if (this._replayStderr(record)) {
      // The exit must not overtake the bytes. The coordinator fails a run on the
      // stderr chunk itself, and one that saw the exit first would report the wrong
      // reason for the same fault.
      await new Promise((resolve) => setImmediate(resolve))
      if (this.exited) return
    }
    const exited = record !== null && typeof record === 'object' && record.exited === true
    const code = exited && Number.isInteger(record.code) ? record.code : null
    const signal =
      exited && typeof record.signal === 'string' && record.signal.length > 0 ? record.signal : null
    if (code === null && signal === null) {
      // Fail closed. The far side is gone and nothing establishes that the role
      // finished, so the channel reports a failure rather than the zero a bare
      // stream event used to produce.
      this._settle(
        1,
        null,
        this._transportError || new Error(`role ${this.index} reported no terminal status`)
      )
      return
    }
    // A transport error alongside a definite outcome is the protocol working: the
    // bridge destroys a failed role's stream on purpose. A spawned child that exits
    // non-zero emits 'exit' alone, and this must too, or the coordinator would see
    // PROCESS_CHILD_ERROR where a local run sees PROCESS_EARLY_EXIT.
    this._settle(code, signal, null)
  }

  // Whatever the role wrote to stderr, replayed into the stream the coordinator
  // subscribed to. A count with no sample still has to arrive: what matters is that
  // a role which wrote stderr fails the run, not that the text survived.
  _replayStderr(record) {
    if (record === null || typeof record !== 'object') return false
    const bytes = Number.isInteger(record.stderrBytes) ? record.stderrBytes : 0
    const sample = typeof record.stderrSample === 'string' ? record.stderrSample : ''
    if (bytes === 0 && sample.length === 0) return false
    const text = sample.length > 0 ? sample : `role ${this.index} wrote ${bytes} stderr bytes\n`
    this.stderr.write(b4a.from(text, 'utf8'))
    return true
  }

  async _fetchStatus() {
    const { node, keyPair, publicKey, timeoutMs } = this._statusEndpoint
    if (node === null || keyPair === null || publicKey === null) {
      throw new Error(`role ${this.index} has no status endpoint`)
    }
    const deadline = Date.now() + timeoutMs
    let lastError = null
    for (let attempt = 1; attempt <= STATUS_ATTEMPTS; attempt++) {
      const remaining = deadline - Date.now()
      if (remaining <= 0) break
      let socket = null
      try {
        socket = await connect(
          node,
          keyPair,
          publicKey,
          Math.min(STATUS_CONNECT_TIMEOUT_MS, remaining)
        )
        socket.on('error', () => {})
        const reader = new FrameReader(socket)
        // A stream that died between the open and here raises no further event, so
        // the reader would sit out its timeout for nothing.
        if (socket.destroyed) throw new Error('status stream closed before the request')
        socket.write(b4a.from([MODE.STATUS]))
        const frame = await reader.next(
          Math.max(1000, Math.min(STATUS_FRAME_TIMEOUT_MS, deadline - Date.now()))
        )
        if (frame.op !== OP.REPORT) throw new Error(`unexpected status frame ${frame.op}`)
        const record = JSON.parse(b4a.toString(frame.payload, 'utf8'))
        socket.destroy()
        return record
      } catch (err) {
        if (socket !== null) socket.destroy()
        lastError = err
        if (attempt === STATUS_ATTEMPTS || Date.now() + STATUS_RETRY_MS >= deadline) break
        await new Promise((resolve) => setTimeout(resolve, STATUS_RETRY_MS))
      }
    }
    throw new Error(
      `role ${this.index} terminal status unavailable: ${lastError && lastError.message}`
    )
  }

  _settle(code, signal, err) {
    if (this.exited) return
    this.exited = true
    // Only when someone is listening: an unheard 'error' event throws, and the
    // transport failure is already visible as an exit.
    if (err && this.listenerCount('error') > 0) this.emit('error', err)
    this.emit('exit', code, signal)
  }

  kill(signal = 'SIGTERM') {
    // A killed child reports no exit code and the signal that killed it. Reporting a
    // zero exit here would make a role that was cut down indistinguishable from one
    // that finished its work, which is exactly the confusion a green run must not
    // hide. This is the one settle that needs no status record: the coordinator asked
    // for the signal, so it already knows the outcome.
    this.killed = true
    const settled = this.exited
    this._settle(null, typeof signal === 'string' ? signal : 'SIGTERM', null)
    if (!settled) this._socket.destroy()
    return true
  }
}

function connect(node, keyPair, publicKey, timeoutMs = CONNECT_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const socket = node.connect(publicKey, { keyPair })
    const timer = setTimeout(() => {
      socket.destroy()
      reject(new Error('role did not accept in time'))
    }, timeoutMs)
    socket.once('open', () => {
      clearTimeout(timer)
      resolve(socket)
    })
    socket.once('error', (err) => {
      clearTimeout(timer)
      reject(err)
    })
    // A far side that closes without an error would otherwise hold this open for the
    // whole timeout. After the open resolved this is a no-op.
    socket.once('close', () => {
      clearTimeout(timer)
      reject(new Error('role closed the connection before it opened'))
    })
  })
}

// Each role's own addresses, asked for before the topology that will contain them
// is minted. Retried until the deadline because roles come up minutes apart on CI.
async function requestRoleEndpoints(options) {
  const { node, secret, coordinatorSecret, runId, count, deadline, comment } = options
  if (!coordinatorSecret) {
    throw new Error('coordinatorSecret is required: roles pin only its public key')
  }
  const keyPair = coordinatorKeyPair(coordinatorSecret)
  const endpoints = []
  for (let index = 1; index <= count; index++) {
    const target = peerKeyPair(secret, runId, index).publicKey
    let report = null
    let lastError = null
    while (report === null && Date.now() < deadline) {
      let socket = null
      try {
        socket = await connect(node, keyPair, target)
        socket.on('error', () => {})
        const reader = new FrameReader(socket)
        socket.write(b4a.from([MODE.REPORT]))
        const frame = await reader.next(20_000)
        if (frame.op !== OP.REPORT) throw new Error('unexpected frame')
        report = JSON.parse(b4a.toString(frame.payload, 'utf8'))
        socket.destroy()
      } catch (err) {
        if (socket) socket.destroy()
        lastError = err
        await new Promise((resolve) => setTimeout(resolve, 5000))
      }
    }
    if (report === null) {
      throw new Error(`role ${index} never reported: ${lastError && lastError.message}`)
    }
    if (report.index !== index) throw new Error(`role ${index} reported as ${report.index}`)
    if (!report.reachable) throw new Error(`role ${index} has no reachable address`)
    const entry = { bind: report.bind, reachable: report.reachable }
    // Only an exit reports one, and the topology requires it from exactly those
    // roles.
    if (report.dhtExit) entry.dhtExit = report.dhtExit
    // Reported through the caller's comment hook rather than attached anywhere: the
    // topology fixture validates each record with exactObject AND the array itself
    // with exactArrayValues, which rejects any own key beyond the indices and length.
    // So neither the entry nor the array can carry a diagnostic.
    if (report.dhtExit && report.dhtExitStable === false && typeof comment === 'function') {
      comment(
        `role ${index}: reflectors disagreed on its DHT socket ` +
          `${report.dhtExit.host}:${report.dhtExit.port}, so peers may not reach it`
      )
    }
    endpoints.push(entry)
  }
  return endpoints
}

// The punch round, between learning the addresses and attaching the roles.
//
// A role cannot punch until it knows the other ten addresses, and this coordinator is
// the only party that knows them, so the list has to be distributed before any role
// can open anything. Simultaneity is the whole mechanism: each side's OUTBOUND packet
// is what opens its own NAT for the other, so the sends have to cross in flight, and
// a role that punches ten seconds after its peer punches into a mapping that does not
// exist yet.
//
// So the connections are opened FIRST, all eleven of them, and only then is the plan
// written to every one of them in a single synchronous pass. Doing it role by role
// would spread the punches across eleven DHT connects, which on the public DHT is
// seconds apart - the staggering this round exists to avoid. This is the closest to
// simultaneous the harness can get without a clock the roles share.
//
// Returns one report per role that answered. Deliberately does NOT throw on an
// unanswered pair: a partial matrix may still carry the scenario, and failing here
// would replace the run's own verdict with a new failure mode. The reports name every
// missing directed pair instead, which is what the caller comments.
async function punchRoleEndpoints(options) {
  const {
    node,
    secret,
    coordinatorSecret,
    runId,
    endpoints,
    deadline,
    comment,
    excludeIndexes = []
  } = options
  if (!coordinatorSecret) {
    throw new Error('coordinatorSecret is required: roles pin only its public key')
  }
  if (!Array.isArray(endpoints) || endpoints.length === 0) {
    throw new Error('endpoints are required')
  }
  const excluded = new Set(
    (Array.isArray(excludeIndexes) ? excludeIndexes : []).map((value) => Number(value))
  )
  const keyPair = coordinatorKeyPair(coordinatorSecret)
  const say = typeof comment === 'function' ? comment : () => {}

  // Every socket a role owns, keyed by role index. The exits' DHT socket is carried
  // separately because it is a second socket with its own mapping, dialled directly
  // by other roles: a plan naming only cell ports would open half the paths and move
  // the failure rather than fix it. Production endpoint punch excludes the endpoint
  // role (index 1) so the bilateral NAT path owns that edge alone.
  const plan = {}
  for (let offset = 0; offset < endpoints.length; offset++) {
    const index = offset + 1
    if (excluded.has(index)) continue
    const entry = endpoints[offset]
    plan[index] = {
      host: entry.reachable.host,
      cellPort: entry.reachable.port,
      ...(entry.dhtExit ? { dhtHost: entry.dhtExit.host, dhtPort: entry.dhtExit.port } : {})
    }
  }
  const planBytes = writeFrame(OP.PLAN, b4a.from(JSON.stringify(plan)))
  const entries = Object.values(plan)
  const exitSockets = entries.filter((entry) => Number.isInteger(entry.dhtPort)).length
  say(
    `punch plan covers ${entries.length} roles over ${entries.length + exitSockets} sockets ` +
      `(${entries.length} cell, ${exitSockets} exit-DHT)`
  )

  // Phase one: every connection open before any punch is asked for.
  const opened = await Promise.all(
    Object.keys(plan).map(async (key) => {
      const index = Number(key)
      const target = peerKeyPair(secret, runId, index).publicKey
      let lastError = null
      while (Date.now() < deadline) {
        try {
          const socket = await connect(node, keyPair, target, PUNCH_CONNECT_TIMEOUT_MS)
          socket.on('error', () => {})
          return { index, socket, reader: new FrameReader(socket) }
        } catch (err) {
          lastError = err
          await new Promise((resolve) => setTimeout(resolve, PUNCH_RETRY_MS))
        }
      }
      return { index, socket: null, reader: null, error: lastError }
    })
  )

  const live = opened.filter((entry) => entry.socket !== null)
  for (const entry of opened) {
    if (entry.socket === null) {
      say(
        `role ${entry.index} could not be reached to punch: ` +
          `${entry.error && entry.error.message}; it has no NAT mapping for any peer`
      )
    }
  }

  // Phase two: one synchronous pass, so eleven punch rounds start together.
  for (const entry of live) {
    try {
      entry.socket.write(b4a.concat([b4a.from([MODE.PUNCH]), planBytes]))
    } catch (err) {
      say(`role ${entry.index} punch plan could not be written: ${err && err.message}`)
    }
  }

  // Phase three: collect. Each role answers once its own rounds are finished and its
  // probes are closed, which is also the signal that its ports are free for the role
  // process to bind.
  const settled = await Promise.allSettled(
    live.map(async (entry) => {
      try {
        const frame = await entry.reader.next(PUNCH_REPORT_TIMEOUT_MS)
        if (frame.op !== OP.CELL_REPORT) throw new Error(`unexpected punch frame ${frame.op}`)
        return JSON.parse(b4a.toString(frame.payload, 'utf8'))
      } finally {
        entry.socket.destroy()
      }
    })
  )

  const reports = []
  for (let offset = 0; offset < settled.length; offset++) {
    const outcome = settled[offset]
    if (outcome.status === 'fulfilled') reports.push(outcome.value)
    else {
      say(
        `role ${live[offset].index} never reported its punch: ` +
          `${outcome.reason && outcome.reason.message}`
      )
    }
  }
  return reports
}

// projections must be in ROLES order, exactly as spawnRoleProcesses returns them,
// so the coordinator's records line up with the roles the topology describes.
async function openRemoteRoleChannels(options) {
  const { node, secret, coordinatorSecret, runId, projections, deadline } = options
  if (!Array.isArray(projections) || projections.length === 0) {
    throw new Error('projections are required')
  }
  if (!coordinatorSecret) {
    throw new Error('coordinatorSecret is required: roles pin only its public key')
  }
  const keyPair = coordinatorKeyPair(coordinatorSecret)
  const entries = []
  for (let offset = 0; offset < projections.length; offset++) {
    const projection = projections[offset]
    const index = offset + 1
    const target = peerKeyPair(secret, runId, index).publicKey
    let socket = null
    let lastError = null
    // Roles come up minutes apart on CI, so a role that is not listening yet is
    // retried until the deadline rather than failing the run.
    while (socket === null && Date.now() < deadline) {
      try {
        socket = await connect(node, keyPair, target)
      } catch (err) {
        lastError = err
        await new Promise((resolve) => setTimeout(resolve, 5000))
      }
    }
    if (socket === null) {
      throw new Error(
        `role ${index} (${projection.role}) never attached: ${lastError && lastError.message}`
      )
    }
    entries.push(
      Object.freeze({
        child: new RemoteChild(socket, index, { node, keyPair, publicKey: target }),
        generation: projection.generation,
        phaseGate: projection.phaseGate || null,
        phaseSequence: 1n,
        plan: projection.plan,
        role: projection.role,
        roleIndex: projection.roleIndex,
        run: projection.run
      })
    )
  }
  return Object.freeze(entries)
}

function closeRemoteRoleChannels(entries) {
  for (const entry of entries) {
    if (!entry.child.killed) entry.child.kill()
  }
  return true
}

module.exports = {
  MODE,
  openRemoteRoleChannels,
  closeRemoteRoleChannels,
  punchRoleEndpoints,
  requestRoleEndpoints,
  RemoteChild
}
