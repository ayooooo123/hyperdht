'use strict'

// Runs one topology role on this host and hands its control channel to a remote
// coordinator over the DHT.
//
// The role process is unchanged: test/private/process/role-runner.js already
// speaks the binary control protocol on stdin and stdout, so this bridge only
// moves those bytes. The coordinator dials in with a derived key, the bridge
// spawns the role, and the two streams are joined. Keeping role-runner untouched
// matters: it is what the local gates exercise, and a distributed run must not be
// a different program.
//
//   REMOTE_PEER_SECRET=<hex> REMOTE_PEER_RUN_ID=<id> \
//     node test/remote-peer/role-bridge.js --index 3 --runtime node --seconds 900

const path = require('path')
const { spawn } = require('child_process')
const b4a = require('b4a')
const DHT = require('../..')
const { peerKeyPair, proberKeyPair } = require('./identity')
const { reflect, resolveReflectors } = require('./dht-reflect')
const { OP, writeFrame } = require('./frames')

// A role binds a socket it owns; peers dial the address the world sees for it.
const BIND_HOST = '0.0.0.0'
const MODE = Object.freeze({ REPORT: 1, ATTACH: 2 })
// An exit binds a second socket for reaching DHT nodes, at 43000 + roleIndex; see
// role-runner.js:360. Behind a NAT it carries its own mapping, so it has to be
// discovered separately.
const EXIT_ROLE_INDEXES = Object.freeze([4, 6, 8])
const EXIT_DHT_PORT_BASE = 43_000

const ROLE_RUNNER = path.join(__dirname, '..', 'private', 'process', 'role-runner.js')
const REPO_ROOT = path.join(__dirname, '..', '..')

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
  if (!secret) throw new Error('REMOTE_PEER_SECRET is required')
  if (!runId) throw new Error('REMOTE_PEER_RUN_ID or GITHUB_RUN_ID is required')

  const keyPair = peerKeyPair(secret, runId, options.index)
  const coordinator = proberKeyPair(secret, runId).publicKey
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
  let dhtExit = null
  if (EXIT_ROLE_INDEXES.includes(options.index)) {
    const exitProbe = cellUdx.createSocket()
    const exitPort = EXIT_DHT_PORT_BASE + options.index
    const exitBind = exitProbe.bind(exitPort)
    if (exitBind && typeof exitBind.then === 'function') await exitBind
    if (options.reachableHost !== null) {
      dhtExit = { host: options.reachableHost, port: exitPort }
    } else {
      for (const reflector of reflectors) {
        const observed = await reflect(exitProbe, reflector)
        if (observed !== null) {
          dhtExit = observed
          break
        }
      }
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

  const server = node.createServer(
    {
      // Only the coordinator may drive a role.
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
                  endpointStable
                })
              )
            )
          )
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

        const launch = roleCommand(options.runtime)
        role = spawn(launch.command, launch.args, {
          cwd: REPO_ROOT,
          env: roleEnvironment(),
          stdio: ['pipe', 'pipe', 'pipe']
        })

        // Control frames both ways, untouched. Anything that arrived alongside the
        // mode byte belongs to the role.
        if (rest.byteLength > 0) role.stdin.write(rest)
        socket.on('data', (data) => {
          if (role && role.stdin && !role.stdin.destroyed) role.stdin.write(data)
        })
        role.stdout.on('data', (data) => socket.write(data))

        // A role must be silent on stderr; forwarding it as data would corrupt the
        // control stream, so it is reported here and the run fails on the missing
        // reply rather than on garbage.
        role.stderr.on('data', (data) => {
          emit({
            event: 'role-stderr',
            index: options.index,
            text: b4a.toString(data, 'utf8').slice(0, 400)
          })
        })

        role.once('exit', (code, signal) => {
          emit({ event: 'role-exit', index: options.index, code, signal })
          // A role that finished its work exits zero, and the coordinator must see
          // that as a closed channel rather than a reset: ending the stream says the
          // far side is done, destroying it says something broke.
          if (code === 0) socket.end()
          else socket.destroy()
        })
        socket.once('close', () => {
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
