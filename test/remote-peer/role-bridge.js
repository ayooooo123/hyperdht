'use strict'

// Runs one topology role on this host and hands its control channel to a remote
// coordinator over the DHT.
//
// The role process is unchanged: test/private/process/role-runner.js already
// speaks the binary control protocol on stdin and stdout, so this bridge only
// moves those bytes. The coordinator dials in with a key this host cannot derive,
// spawns the role, and the two streams are joined. Keeping role-runner untouched
// matters: it is what the local gates exercise, and a distributed run must not be
// a different program.
//
//   REMOTE_PEER_SECRET=<hex> REMOTE_PEER_RUN_ID=<id> \
//     REMOTE_PEER_COORDINATOR_KEY=<hex public key> \
//     node test/remote-peer/role-bridge.js --index 3 --runtime node --seconds 900

const path = require('path')
const { spawn } = require('child_process')
const b4a = require('b4a')
const DHT = require('../..')
const { peerKeyPair, coordinatorPublicKey } = require('./identity')
const { reflect, resolveReflectors } = require('./dht-reflect')
const { OP, writeFrame } = require('./frames')

// A role binds a socket it owns; peers dial the address the world sees for it.
const BIND_HOST = '0.0.0.0'
// One byte on a fresh connection says what it is for: addresses, a role's control
// stream, or the role's terminal status.
const MODE = Object.freeze({ REPORT: 1, ATTACH: 2, STATUS: 3 })
// An exit binds a second socket for reaching DHT nodes, at 43000 + roleIndex; see
// role-runner.js:360. Behind a NAT it carries its own mapping, so it has to be
// discovered separately.
const EXIT_ROLE_INDEXES = Object.freeze([4, 6, 8])
const EXIT_DHT_PORT_BASE = 43_000

// A role must be silent on stderr. What one writes anyway is evidence the
// coordinator has to see, so the count is exact and a bounded prefix is kept to
// hand back with the terminal status. Nothing beyond that prefix is ever buffered,
// however loud a role gets.
const STDERR_SAMPLE_CHARS = 400
const STDERR_SAMPLE_BYTES = 4 * STDERR_SAMPLE_CHARS

const ROLE_RUNNER = path.join(__dirname, '..', 'private', 'process', 'role-runner.js')
const REPO_ROOT = path.join(__dirname, '..', '..')

// Diagnostics only, off unless PR_BRIDGE_TRACE names a file: one JSON object per
// line recording every control frame, the stream lifecycle and the role's exit, so
// a teardown that hangs can be read back as an ordered sequence. This is the ROLE
// side only: nothing writes a coordinator half, so a hang that is invisible from
// here needs instrumenting on the coordinator separately. `t` is epoch milliseconds
// taken from the high-resolution clock, so lines from several role processes on one
// host sort into one timeline.
const TRACE_PATH = process.env.PR_BRIDGE_TRACE || null
const TRACING = TRACE_PATH !== null
const { performance: clock } = require('perf_hooks')

function trace(event) {
  if (TRACE_PATH === null) return
  try {
    require('fs').appendFileSync(
      TRACE_PATH,
      `${JSON.stringify({
        t: clock.timeOrigin + clock.now(),
        side: 'bridge',
        pid: process.pid,
        ...event
      })}\n`
    )
  } catch {}
}

// Names the frames in a control stream without touching the bytes passing through:
// the sniffer is handed every chunk and reports the type of each complete frame. It
// disables itself on the first decode error, so a diagnostic can never break a pipe.
function frameSniffer(index, direction) {
  if (TRACE_PATH === null) return () => {}
  let decoder = null
  try {
    const { ControlFrameDecoder } = require('../private/process/control-channel')
    decoder = new ControlFrameDecoder((message) => {
      trace({
        event: 'frame',
        index,
        direction,
        type: typeof message.type === 'string' ? message.type : null,
        generation: typeof message.generation === 'bigint' ? String(message.generation) : null,
        phaseSequence:
          typeof message.phaseSequence === 'bigint' ? String(message.phaseSequence) : null
      })
    })
  } catch {
    return () => {}
  }
  return (chunk) => {
    if (decoder === null) return
    try {
      decoder.push(chunk)
    } catch (err) {
      decoder = null
      trace({ event: 'frame-undecodable', index, direction, message: err && err.message })
    }
  }
}

function parse(argv) {
  const options = {
    index: 1,
    runtime: 'node',
    seconds: 900,
    cellPort: 0,
    bootstrap: [],
    reachableHost: null,
    bindHost: null
  }
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i]
    const value = argv[i + 1]
    if (flag === '--index') options.index = Number(value)
    else if (flag === '--runtime') options.runtime = String(value)
    else if (flag === '--seconds') options.seconds = Number(value)
    else if (flag === '--cell-port') options.cellPort = Number(value)
    else if (flag === '--reachable-host') options.reachableHost = String(value)
    else if (flag === '--bind-host') options.bindHost = String(value)
    else if (flag === '--bootstrap') {
      const [host, port] = String(value).split(':')
      options.bootstrap.push({ host, port: Number(port) })
    } else continue
    i++
  }
  if (!Number.isInteger(options.index) || options.index < 1) throw new Error('bad --index')
  if (options.runtime !== 'node' && options.runtime !== 'bare') throw new Error('bad --runtime')
  if (!Number.isFinite(options.seconds) || options.seconds <= 0) throw new Error('bad --seconds')
  if (!Number.isInteger(options.cellPort) || options.cellPort < 0)
    throw new Error('bad --cell-port')
  return options
}

function emit(event) {
  console.log(JSON.stringify({ roleBridge: event.event, ...event }))
}

function roleCommand(runtime) {
  if (runtime === 'bare') return { command: require('bare-runtime')('bare'), args: [ROLE_RUNNER] }
  return { command: process.execPath, args: [ROLE_RUNNER] }
}

// The role's own environment stays empty, exactly as the local coordinator runs
// it, except for the opt-in fatal trace path.
function roleEnvironment() {
  const env = Object.create(null)
  const fatalLog = process.env.PR_ROLE_FATAL_LOG
  if (typeof fatalLog === 'string' && fatalLog.length > 0) env.PR_ROLE_FATAL_LOG = fatalLog
  return env
}

async function main() {
  const options = parse(process.argv.slice(2))
  const secret = process.env.REMOTE_PEER_SECRET
  const runId = process.env.REMOTE_PEER_RUN_ID || process.env.GITHUB_RUN_ID
  // Supplied, not derived. This host holds the shared run secret, so a pin on
  // anything derived from it would be a pin on a key this host could mint, and any
  // role could then pass any other role's firewall and take its one ATTACH.
  const coordinatorKey = process.env.REMOTE_PEER_COORDINATOR_KEY
  if (!secret) throw new Error('REMOTE_PEER_SECRET is required')
  if (!runId) throw new Error('REMOTE_PEER_RUN_ID or GITHUB_RUN_ID is required')
  if (!coordinatorKey) {
    throw new Error(
      'REMOTE_PEER_COORDINATOR_KEY is required: the hex public key of the coordinator ' +
        'that is allowed to attach, from scripts/remote-peer.sh secret'
    )
  }

  const keyPair = peerKeyPair(secret, runId, options.index)
  const coordinator = coordinatorPublicKey(coordinatorKey)
  const node = new DHT({
    bootstrap: options.bootstrap.length > 0 ? options.bootstrap : undefined
  })

  // The address this role will publish for route cells. The port is claimed here,
  // reflected, then released, so the role's own cell endpoint can bind the same
  // local port and be reachable at the address the coordinator mints into its
  // capability. Ten-runner measurements showed the mapping survives that rebind.
  const cellUdx = new (require('udx-native'))()
  const probe = cellUdx.createSocket()
  const probeBind = probe.bind(options.cellPort)
  if (probeBind && typeof probeBind.then === 'function') await probeBind
  const cellPort = probe.address().port
  const reflectors = (await resolveReflectors()).slice(0, 2)
  const observations = []
  for (const reflector of reflectors) {
    observations.push(await reflect(probe, reflector))
  }
  await probe.close()

  // The same claim-reflect-release for the exit's DHT socket. Its local port is
  // fixed by the role, so the probe binds exactly that port and the mapping it
  // learns is the one the role will own once it binds.
  //
  // Reflected off BOTH reflectors and required to agree, exactly as the cell socket
  // is. Taking the first success would confirm the mapping once and never
  // cross-check it, and under a NAT that maps per destination the published address
  // would then be the mapping for that one reflector rather than the one other
  // roles see - which is indistinguishable from a correct address until requests to
  // it time out. Peers dial this socket directly, so it needs the same evidence the
  // cell socket needs.
  let dhtExit = null
  let dhtExitStable = false
  if (EXIT_ROLE_INDEXES.includes(options.index)) {
    const exitProbe = cellUdx.createSocket()
    const exitPort = EXIT_DHT_PORT_BASE + options.index
    const exitBind = exitProbe.bind(exitPort)
    if (exitBind && typeof exitBind.then === 'function') await exitBind
    if (options.reachableHost !== null) {
      dhtExit = { host: options.reachableHost, port: exitPort }
      dhtExitStable = true
    } else {
      const exitObservations = []
      for (const reflector of reflectors) {
        exitObservations.push(await reflect(exitProbe, reflector))
      }
      const exitUsable = exitObservations.filter((entry) => entry !== null)
      dhtExit = exitUsable.length > 0 ? exitUsable[0] : null
      dhtExitStable =
        exitUsable.length > 1 &&
        exitUsable.every(
          (entry) => entry.host === exitUsable[0].host && entry.port === exitUsable[0].port
        )
    }
    await exitProbe.close()
  }

  const usable = observations.filter((entry) => entry !== null)
  // A rehearsal on one host has no translation to discover, so the reachable host
  // can be stated. On a runner it is always the reflected value.
  const endpoint =
    options.reachableHost !== null
      ? { host: options.reachableHost, port: cellPort }
      : usable.length > 0
        ? usable[0]
        : null
  const endpointStable =
    usable.length > 1 &&
    usable.every((entry) => entry.host === usable[0].host && entry.port === usable[0].port)

  let role = null
  let attached = false

  // What no stream event can carry: whether the role exited, with what code or
  // signal, and what it said on stderr. A failed role's control stream is destroyed,
  // and a destroyed stream can reach the coordinator as a bare close, so the outcome
  // has to be answerable on a second connection or a crash reads as a clean finish.
  const status = {
    exited: false,
    code: null,
    signal: null,
    stderrBytes: 0,
    stderrHead: b4a.alloc(0)
  }
  const statusRecord = () => ({
    index: options.index,
    attached,
    exited: status.exited,
    code: status.code,
    signal: status.signal,
    stderrBytes: status.stderrBytes,
    stderrSample: b4a.toString(status.stderrHead, 'utf8').slice(0, STDERR_SAMPLE_CHARS)
  })

  const server = node.createServer(
    {
      // Only the coordinator may drive a role, and this host cannot derive its key:
      // it is handed the public half and nothing else.
      firewall(remotePublicKey) {
        const allowed = b4a.equals(remotePublicKey, coordinator)
        if (!allowed) {
          emit({
            event: 'denied',
            index: options.index,
            saw: b4a.toString(remotePublicKey.subarray(0, 6), 'hex'),
            expected: b4a.toString(coordinator.subarray(0, 6), 'hex')
          })
        }
        return !allowed
      }
    },
    (socket) => {
      socket.on('error', () => {})

      // One byte decides what this connection is for. The coordinator has to learn
      // a role's addresses before it can mint the topology those addresses appear
      // in, so it asks first and attaches later, on a second connection.
      let mode = null
      const onFirstByte = (chunk) => {
        if (mode !== null) return
        mode = chunk[0]
        const rest = chunk.subarray(1)

        if (mode === MODE.REPORT) {
          socket.write(
            writeFrame(
              OP.REPORT,
              b4a.from(
                JSON.stringify({
                  index: options.index,
                  runtime: options.runtime,
                  bind: { host: options.bindHost || BIND_HOST, port: cellPort },
                  reachable: endpoint,
                  dhtExit,
                  dhtExitStable,
                  endpointStable
                })
              )
            )
          )
          // The answer is the whole purpose of this connection.
          setTimeout(() => socket.destroy(), 250)
          return
        }

        // The terminal status, asked for on a fresh connection once the control
        // stream is over. Answered whether or not a role was ever attached, and after
        // the role has gone: the record outlives it.
        if (mode === MODE.STATUS) {
          const record = statusRecord()
          trace({ event: 'status-served', ...record })
          socket.write(writeFrame(OP.REPORT, b4a.from(JSON.stringify(record))))
          // The answer is the whole purpose of this connection.
          setTimeout(() => socket.destroy(), 250)
          return
        }

        if (mode !== MODE.ATTACH || attached) {
          socket.destroy()
          return
        }
        attached = true
        emit({ event: 'attached', index: options.index })
        trace({ event: 'attached', index: options.index, firstChunkBytes: chunk.byteLength })

        const launch = roleCommand(options.runtime)
        role = spawn(launch.command, launch.args, {
          cwd: REPO_ROOT,
          env: roleEnvironment(),
          stdio: ['pipe', 'pipe', 'pipe']
        })
        trace({ event: 'role-spawn', index: options.index, rolePid: role.pid })

        const inbound = frameSniffer(options.index, 'coordinator->role')
        const outbound = frameSniffer(options.index, 'role->coordinator')

        // Control frames both ways, untouched. Anything that arrived alongside the
        // mode byte belongs to the role.
        if (rest.byteLength > 0) {
          if (TRACING) {
            trace({
              event: 'socket-data',
              index: options.index,
              bytes: rest.byteLength,
              withMode: true
            })
          }
          inbound(rest)
          role.stdin.write(rest)
        }
        // The per-chunk sites are guarded rather than left to trace(): the argument
        // object would otherwise be built for every chunk on a stream that is not
        // being traced.
        socket.on('data', (data) => {
          const writable = !!(role && role.stdin && !role.stdin.destroyed)
          if (TRACING) {
            trace({
              event: 'socket-data',
              index: options.index,
              bytes: data.byteLength,
              stdinWritable: writable
            })
            inbound(data)
          }
          if (writable) role.stdin.write(data)
        })
        role.stdout.on('data', (data) => {
          if (TRACING) {
            trace({ event: 'role-stdout', index: options.index, bytes: data.byteLength })
            outbound(data)
          }
          socket.write(data)
        })

        // Which side closed the role's stdin, and whether the far side half-closed or
        // reset, is what a hanging teardown turns on. Both are recorded.
        role.stdin.once('close', () => trace({ event: 'role-stdin-close', index: options.index }))
        role.stdin.on('error', (err) =>
          trace({ event: 'role-stdin-error', index: options.index, message: err && err.message })
        )
        socket.once('end', () => trace({ event: 'socket-end', index: options.index }))

        // A role must be silent on stderr, and forwarding its bytes as data would
        // corrupt the control stream. So they are counted, a bounded prefix is kept,
        // and both travel back with the terminal status: the coordinator replays the
        // sample into the channel's stderr and its own check fires, exactly as it
        // does for a spawned role. The log line keeps the evidence here as well.
        role.stderr.on('data', (data) => {
          status.stderrBytes += data.byteLength
          if (status.stderrHead.byteLength < STDERR_SAMPLE_BYTES) {
            const room = STDERR_SAMPLE_BYTES - status.stderrHead.byteLength
            const slice = data.byteLength > room ? data.subarray(0, room) : data
            status.stderrHead =
              status.stderrHead.byteLength === 0
                ? b4a.from(slice)
                : b4a.concat([status.stderrHead, slice])
          }
          emit({
            event: 'role-stderr',
            index: options.index,
            bytes: data.byteLength,
            total: status.stderrBytes,
            text: b4a.toString(data, 'utf8').slice(0, STDERR_SAMPLE_CHARS)
          })
        })

        role.once('exit', (code, signal) => {
          status.exited = true
          status.code = typeof code === 'number' ? code : null
          status.signal = typeof signal === 'string' ? signal : null
          emit({ event: 'role-exit', index: options.index, code, signal })
          trace({
            event: 'role-exit',
            index: options.index,
            code,
            signal,
            killedByBridge: role.killed,
            stdinDestroyed: role.stdin.destroyed
          })
          // A role that finished its work exits zero, and the coordinator must see
          // that as a closed channel rather than a reset: ending the stream says the
          // far side is done, destroying it says something broke.
          if (code === 0) {
            trace({ event: 'socket-end-called', index: options.index })
            socket.end()
          } else {
            trace({ event: 'socket-destroy-called', index: options.index })
            socket.destroy()
          }
        })
        // The coordinator stops a role by ending its stdin, and a spawned role sees
        // EOF. The coordinator's half-close arrives here, so pass the EOF on rather
        // than leaving the role waiting for a signal.
        socket.on('end', () => {
          trace({ event: 'socket-end-received', index: options.index })
          if (role && role.stdin && role.stdin.writable && !role.stdin.destroyed) {
            role.stdin.end()
          }
        })
        socket.once('close', () => {
          trace({
            event: 'socket-close',
            index: options.index,
            roleExitCode: role ? role.exitCode : null
          })
          if (role && !role.killed) role.kill('SIGTERM')
        })
      }
      socket.once('data', onFirstByte)
    }
  )

  await server.listen(keyPair)
  emit({
    event: 'ready',
    index: options.index,
    runtime: options.runtime,
    runId,
    cellPort,
    endpoint,
    dhtExit,
    dhtExitStable,
    endpointStable,
    observations
  })

  await new Promise((resolve) => setTimeout(resolve, options.seconds * 1000))
  emit({ event: 'done', index: options.index, attached })
  if (role && !role.killed) role.kill('SIGKILL')
  await server.close()
  await node.destroy()
}

main().catch((err) => {
  emit({ event: 'error', message: err.message })
  process.exit(1)
})
