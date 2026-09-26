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
const { OP, HEADER_BYTES, MAX_FRAME_BYTES, writeFrame } = require('./frames')

// A role binds a socket it owns; peers dial the address the world sees for it.
const BIND_HOST = '0.0.0.0'
// One byte on a fresh connection says what it is for: addresses, a punch round, a
// role's control stream, or the role's terminal status.
const MODE = Object.freeze({ REPORT: 1, ATTACH: 2, STATUS: 3, PUNCH: 4 })
// An exit binds a second socket for reaching DHT nodes, at 43000 + roleIndex; see
// role-runner.js:360. Behind a NAT it carries its own mapping, so it has to be
// discovered separately.
const EXIT_ROLE_INDEXES = Object.freeze([4, 6, 8])
const EXIT_DHT_PORT_BASE = 43_000

// A punch datagram. The tag exists so a reply that is not a punch cannot be counted
// as one: a reflector's own STUN-shaped response arrives on these same sockets, and
// without a tag its first byte would read as a peer index. The two trailing bytes
// are the sending role's index and which of its sockets sent it.
const PUNCH_TAG = b4a.from('pr-role-punch/1\n')
const PUNCH_KIND = Object.freeze({ CELL: 1, EXIT_DHT: 2 })
const PUNCH_KIND_NAME = Object.freeze({ 1: 'cell', 2: 'exit-dht' })
const PUNCH_BYTES = PUNCH_TAG.byteLength + 2
// Repeats on purpose: a first packet out of a NAT often only creates the mapping,
// and the peer's first packet is already in flight against a mapping that does not
// exist yet. Six over three seconds separates "never arrives" from "arrives once
// both mappings exist". Same shape as test/remote-peer/mesh.js.
const PUNCH_ROUNDS = 6
const PUNCH_INTERVAL_MS = 500
// After the last round, keep listening: a peer that got its plan a moment later is
// still punching, and closing here would report its packets as never sent.
const PUNCH_DRAIN_MS = 2_000
const PUNCH_PLAN_TIMEOUT_MS = 20_000

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

// One complete length-prefixed frame, given whatever already arrived alongside the
// mode byte. FrameReader cannot be used here: it only sees data that arrives after
// it subscribes, and the punch plan can share a chunk with the mode byte that
// selected it, so those leading bytes have to be fed in by hand.
function readFrame(socket, initial, timeoutMs) {
  return new Promise((resolve, reject) => {
    let buffered = initial
    let settled = false
    const finish = (err, frame) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.off('data', onData)
      socket.off('error', onError)
      socket.off('close', onClose)
      if (err) reject(err)
      else resolve(frame)
    }
    const drain = () => {
      if (buffered.byteLength < HEADER_BYTES) return
      const length = buffered.readUInt32BE(1)
      if (length > MAX_FRAME_BYTES) return finish(new Error('frame too large'))
      if (buffered.byteLength < HEADER_BYTES + length) return
      finish(null, {
        op: buffered[0],
        payload: b4a.from(buffered.subarray(HEADER_BYTES, HEADER_BYTES + length))
      })
    }
    const onData = (data) => {
      buffered = buffered.byteLength === 0 ? data : b4a.concat([buffered, data])
      drain()
    }
    const onError = (err) => finish(err)
    const onClose = () => finish(new Error('stream closed before the frame arrived'))
    const timer = setTimeout(
      () => finish(new Error(`frame timed out after ${timeoutMs}ms`)),
      timeoutMs
    )
    socket.on('data', onData)
    socket.on('error', onError)
    socket.once('close', onClose)
    drain()
  })
}

// WHAT A PUNCH DOES, AND WHAT IT DOES NOT DO.
//
// Each role sends a datagram from the socket it will later use to every address it
// may later have to reach. The content is irrelevant; the send is the whole point. It
// makes THIS host's NAT create an outbound mapping for that destination, so the
// peer's datagram - crossing in flight, which is why the coordinator makes every role
// punch at the same moment - arrives at a mapping that already exists instead of
// being dropped by a NAT that has never seen the destination. Neither side can open
// that path alone, which is the entire reason this round exists.
//
// It does NOT make an unreachable peer reachable in general:
//
//   - PORT-SENSITIVE FILTERING. A NAT that filters on source port as well as source
//     address only admits the peer if the punch went to the exact port the peer sends
//     from, from the exact port the peer sends to. That is why every punch leaves the
//     same local port the role will own - claim-reflect-release releases it above and
//     the probes here re-bind it - and is addressed to the peer's reflected port. A
//     mapping opened by any other socket is a mapping for another port and buys
//     nothing. Under a symmetric NAT, which picks a fresh external port per
//     destination, the reflected address is not the address a peer will see at all
//     and no punch from here can repair that.
//
//   - NOTHING KEEPS THESE MAPPINGS ALIVE. Said plainly because it is not assumed:
//     there is no keepalive anywhere in this harness. The punch is six datagrams over
//     three seconds, sent before any role is attached, and the remaining ~900 seconds
//     of a run are carried entirely by scenario traffic. A pair the scenario keeps
//     busy refreshes its own mapping as a side effect. A pair that goes idle for
//     longer than its NAT's UDP idle timeout - commonly 30 to 120 seconds - loses the
//     mapping, and nothing here reopens it. That is the first thing to suspect if a
//     long run fails late having passed its early phases.
//
// A stray punch that lands after the probes are gone is inert, so a slow peer cannot
// corrupt a role: the cell endpoint drops any datagram whose length is not
// BOOTSTRAP_SIZE (udx-cell-endpoint.js:1207, 1200 bytes against these 18), and
// dht-rpc drops any whose first byte is neither its request nor its response id
// (dht-rpc/lib/io.js:91-106; this tag begins 'p').
async function runPunchPhase(options) {
  const { plan, index, cellPort, exitPort, udx } = options
  const observed = []
  const probes = []
  const bindErrors = []

  // Punched FROM the role's own ports, one probe per socket the role will own. A
  // mapping belongs to a port, so a probe on any other port would open a mapping the
  // role never uses.
  const openProbe = async (port, kind) => {
    const socket = udx.createSocket()
    socket.on('message', (message, from) => {
      if (message.byteLength !== PUNCH_BYTES) return
      if (!b4a.equals(message.subarray(0, PUNCH_TAG.byteLength), PUNCH_TAG)) return
      observed.push({
        from: message[PUNCH_TAG.byteLength],
        fromKind: message[PUNCH_TAG.byteLength + 1],
        arrivedOn: kind,
        host: from.host,
        port: from.port,
        at: Date.now()
      })
    })
    try {
      const bound = socket.bind(port)
      if (bound && typeof bound.then === 'function') await bound
    } catch (err) {
      // A port that cannot be re-bound means no punch can be sent from the address
      // peers were told to use. Reported rather than silently punched from a random
      // port, which would look like a punch and open the wrong mapping.
      bindErrors.push({ port, kind: PUNCH_KIND_NAME[kind], message: err && err.message })
      try {
        await socket.close()
      } catch {}
      return
    }
    probes.push({
      socket,
      kind,
      port,
      payload: b4a.concat([PUNCH_TAG, b4a.from([index & 0xff, kind])])
    })
  }

  await openProbe(cellPort, PUNCH_KIND.CELL)
  if (exitPort !== null) await openProbe(exitPort, PUNCH_KIND.EXIT_DHT)

  // Every socket in the plan except this role's own. Deliberately the full cross
  // product rather than the scenario's actual edge set: which role talks to which is
  // topology-fixture.js's business, and a second copy of that knowledge here would be
  // a copy that drifts. Punching everything cannot under-cover, and 13 destinations
  // times 6 rounds is nothing.
  const targets = []
  for (const [key, entry] of Object.entries(plan)) {
    if (!entry || Number(key) === index) continue
    if (typeof entry.host === 'string' && Number.isInteger(entry.cellPort)) {
      targets.push({
        index: Number(key),
        kind: PUNCH_KIND.CELL,
        host: entry.host,
        port: entry.cellPort
      })
    }
    // An exit's DHT socket is dialled directly by other roles, so it needs its own
    // mapping. A punch that opened cell sockets alone would move the failure here.
    if (typeof entry.dhtHost === 'string' && Number.isInteger(entry.dhtPort)) {
      targets.push({
        index: Number(key),
        kind: PUNCH_KIND.EXIT_DHT,
        host: entry.dhtHost,
        port: entry.dhtPort
      })
    }
  }

  let sent = 0
  let refused = 0
  const startedAt = Date.now()
  for (let round = 1; round <= PUNCH_ROUNDS; round++) {
    for (const probe of probes) {
      for (const target of targets) {
        try {
          probe.socket.send(probe.payload, target.port, target.host)
          sent++
        } catch {
          // A refused send is data too: the report will show nothing arrived.
          refused++
        }
      }
    }
    if (round < PUNCH_ROUNDS) {
      await new Promise((resolve) => setTimeout(resolve, PUNCH_INTERVAL_MS))
    }
  }
  await new Promise((resolve) => setTimeout(resolve, PUNCH_DRAIN_MS))

  // The probes must be gone before the role is attached: the role binds these exact
  // ports, and a probe still holding one would fail its bind.
  for (const probe of probes) {
    try {
      await probe.socket.close()
    } catch {}
  }

  // Which peers were heard from, and which were not. A punch is mutual, so hearing
  // peer P's punch on kind K is the evidence that P's packets reach this host from
  // that socket. Silence names a directed pair, which is what a later
  // REQUEST_TIMEOUT never does.
  const heard = new Set(observed.map((entry) => `${entry.from}:${entry.fromKind}`))
  const heardFrom = []
  const silent = []
  for (const target of targets) {
    const label = `${target.index}/${PUNCH_KIND_NAME[target.kind]}`
    if (heard.has(`${target.index}:${target.kind}`)) heardFrom.push(label)
    else silent.push(label)
  }

  return {
    index,
    cellPort,
    exitPort,
    from: probes.map((probe) => `${PUNCH_KIND_NAME[probe.kind]}:${probe.port}`),
    rounds: PUNCH_ROUNDS,
    targets: targets.length,
    sent,
    refused,
    bindErrors,
    elapsedMs: Date.now() - startedAt,
    heardFrom,
    silent,
    observed
  }
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
  // The local port, hoisted: the punch round has to re-bind this exact port, because
  // a mapping opened from any other port is a mapping for another socket.
  const exitLocalPort = EXIT_ROLE_INDEXES.includes(options.index)
    ? EXIT_DHT_PORT_BASE + options.index
    : null
  if (exitLocalPort !== null) {
    const exitProbe = cellUdx.createSocket()
    const exitPort = exitLocalPort
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
  let punching = false

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
      // in, so it asks first, punches on a third connection once it knows all eleven
      // addresses, and attaches last.
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

        // The punch round. A role cannot punch until it knows the other ten
        // addresses and the coordinator is the only party that knows them, so it
        // pushes the whole list here and every role punches at once. Necessarily
        // before the attach: the probes re-bind the ports the role itself will bind.
        if (mode === MODE.PUNCH) {
          if (attached || punching) {
            socket.destroy()
            return
          }
          punching = true
          void (async () => {
            try {
              const frame = await readFrame(socket, rest, PUNCH_PLAN_TIMEOUT_MS)
              if (frame.op !== OP.PLAN) throw new Error(`unexpected punch frame ${frame.op}`)
              const plan = JSON.parse(b4a.toString(frame.payload, 'utf8'))
              emit({
                event: 'punch-start',
                index: options.index,
                peers: Object.keys(plan).length,
                cellPort,
                exitPort: exitLocalPort
              })
              const report = await runPunchPhase({
                plan,
                index: options.index,
                cellPort,
                exitPort: exitLocalPort,
                udx: cellUdx
              })
              emit({
                event: 'punch',
                index: options.index,
                from: report.from,
                rounds: report.rounds,
                targets: report.targets,
                sent: report.sent,
                refused: report.refused,
                heardFrom: report.heardFrom,
                elapsedMs: report.elapsedMs
              })
              // Named on its own line so an unanswered pair is greppable. Every entry
              // here is a directed pair with no mapping, which is the failure that
              // would otherwise surface as a dht-rpc REQUEST_TIMEOUT much later with
              // nothing pointing at an address.
              if (report.silent.length > 0) {
                emit({
                  event: 'punch-unanswered',
                  index: options.index,
                  silent: report.silent,
                  of: report.targets
                })
              }
              if (report.bindErrors.length > 0) {
                emit({
                  event: 'punch-unbound',
                  index: options.index,
                  bindErrors: report.bindErrors
                })
              }
              trace({ event: 'punched', index: options.index, silent: report.silent.length })
              socket.write(writeFrame(OP.CELL_REPORT, b4a.from(JSON.stringify(report))))
              // The answer is the whole purpose of this connection.
              setTimeout(() => socket.destroy(), 250)
            } catch (err) {
              emit({ event: 'punch-failed', index: options.index, message: err && err.message })
              socket.destroy()
            } finally {
              punching = false
            }
          })()
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

// Always true when a bridge is launched, which is the only way this file is used in a
// run: `node test/remote-peer/role-bridge.js --index N`. The guard exists so the punch
// round can be driven directly by a provocation harness, which is the only
// pre-dispatch coverage the punch reporting has - a rehearsal on loopback answers
// every punch, so the unanswered path never runs there.
if (require.main === module) {
  main().catch((err) => {
    emit({ event: 'error', message: err.message })
    process.exit(1)
  })
}

module.exports = { MODE, PUNCH_KIND, PUNCH_TAG, PUNCH_BYTES, runPunchPhase }
