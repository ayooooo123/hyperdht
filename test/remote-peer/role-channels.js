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
const { peerKeyPair, proberKeyPair } = require('./identity')
const { OP, FrameReader } = require('./frames')

// Mirrors role-bridge.js: one byte says whether a connection asks for addresses or
// carries a role's control stream.
const MODE = Object.freeze({ REPORT: 1, ATTACH: 2 })

const CONNECT_TIMEOUT_MS = 30_000

class RemoteChild extends EventEmitter {
  constructor(socket, index) {
    super()
    this.index = index
    this.killed = false
    this.exited = false
    this.stdout = new PassThrough()
    // A remote role's stderr never carries bytes: the bridge reports role stderr
    // out of band. The stream exists because the coordinator subscribes to it.
    this.stderr = new PassThrough()
    this._socket = socket

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
    // A role that finished its work exits zero and its bridge ends the stream. That
    // half-close is the exit: waiting for 'close' instead can wait forever, because
    // a stream only closes once both sides have ended. The suite requires an exit
    // with code zero here, so the mapping has to be end means finished.
    socket.on('end', () => {
      if (typeof socket.end === 'function') socket.end()
      this._settle(0, null, null)
    })
    socket.on('error', (err) => this._settle(1, null, err))
    socket.once('close', () => this._settle(0, null, null))
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
    // hide.
    this.killed = true
    const settled = this.exited
    this._settle(null, typeof signal === 'string' ? signal : 'SIGTERM', null)
    if (!settled) this._socket.destroy()
    return true
  }
}

function connect(node, keyPair, publicKey) {
  return new Promise((resolve, reject) => {
    const socket = node.connect(publicKey, { keyPair })
    const timer = setTimeout(() => {
      socket.destroy()
      reject(new Error('role did not accept in time'))
    }, CONNECT_TIMEOUT_MS)
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

// Each role's own addresses, asked for before the topology that will contain them
// is minted. Retried until the deadline because roles come up minutes apart on CI.
async function requestRoleEndpoints(options) {
  const { node, secret, runId, count, deadline } = options
  const keyPair = proberKeyPair(secret, runId)
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
    endpoints.push(entry)
  }
  return endpoints
}

// projections must be in ROLES order, exactly as spawnRoleProcesses returns them,
// so the coordinator's records line up with the roles the topology describes.
async function openRemoteRoleChannels(options) {
  const { node, secret, runId, projections, deadline } = options
  if (!Array.isArray(projections) || projections.length === 0) {
    throw new Error('projections are required')
  }
  const keyPair = proberKeyPair(secret, runId)
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
        child: new RemoteChild(socket, index),
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
  requestRoleEndpoints,
  RemoteChild
}
