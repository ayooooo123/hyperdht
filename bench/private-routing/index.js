'use strict'

const process = require('process')
const { fork } = require('child_process')
const fs = require('fs')
const path = require('path')
const os = require('os')
const createTestnet = require('../../testnet')
const { MIB, CHUNK, deferred, deadline, milliseconds } = require('./protocol')
const summarize = require('./summarize')
const { METHOD, CAP_BYTES, CAP_WRITES } = require('./delay')

const CASES = [
  { name: 'probe', size: 64, streams: 1, delayMs: 0 },
  { name: 'ping', size: 64, streams: 1, delayMs: 0, ping: true },
  { name: '1mib', size: MIB, streams: 1, delayMs: 0 },
  { name: '16mib', size: 16 * MIB, streams: 1, delayMs: 0 },
  { name: '4x4mib', size: 4 * MIB, streams: 4, delayMs: 0 },
  { name: 'ping', size: 64, streams: 1, delayMs: 5, ping: true },
  { name: 'delay4mib', size: 4 * MIB, streams: 1, delayMs: 5 }
]
const RELAYS = 6

function options() {
  const out = {
    reps: 3,
    timeout: 120000,
    modes: ['direct', 'alpha'],
    directions: ['up', 'down'],
    delays: [0, 5],
    cases: ['probe', 'ping', '1mib', '16mib', '4x4mib', 'delay4mib'],
    method: 'application',
    netem: 0,
    netemlimit: 100000,
    out: null
  }
  for (const arg of process.argv.slice(2)) {
    if (arg === '--help') return null
    const match = /^--([a-z]+)=(.+)$/.exec(arg)
    if (!match || !Object.hasOwn(out, match[1])) throw new Error('unknown argument: ' + arg)
    const [, key, value] = match
    if (['reps', 'timeout', 'netem', 'netemlimit'].includes(key)) out[key] = Number(value)
    else if (key === 'out') out.out = path.resolve(value)
    else if (key === 'method') out.method = value
    else out[key] = value.split(',').map((entry) => (key === 'delays' ? Number(entry) : entry))
  }
  for (const key of ['reps', 'timeout']) {
    if (!Number.isSafeInteger(out[key]) || out[key] < 1) throw new Error('invalid --' + key)
  }
  for (const [key, allowed] of [
    ['modes', ['direct', 'alpha']],
    ['directions', ['up', 'down']],
    ['delays', [0, 5]],
    ['cases', CASES.map((spec) => spec.name)]
  ]) {
    if (new Set(out[key]).size !== out[key].length || out[key].some((v) => !allowed.includes(v))) {
      throw new Error('invalid --' + key)
    }
  }
  if (!['application', 'netem'].includes(out.method)) throw new Error('invalid --method')
  if (
    !Number.isFinite(out.netem) ||
    out.netem < 0 ||
    !Number.isSafeInteger(out.netemlimit) ||
    out.netemlimit < 1
  ) {
    throw new Error('invalid netem parameters')
  }
  if (out.method === 'netem') {
    if (
      process.platform !== 'linux' ||
      process.env.PR_BENCH_NETEM_ACTIVE !== out.netem + '/' + out.netemlimit ||
      out.delays.length !== 1 ||
      out.delays[0] !== 0
    ) {
      throw new Error('use bench/private-routing/netem.sh for packet-level delay')
    }
  } else if (out.netem !== 0) throw new Error('--netem requires --method=netem')
  return out
}

function launch(role, bootstrap, delayMs, timeout) {
  const child = fork(
    path.join(__dirname, 'worker.js'),
    [JSON.stringify({ role, bootstrap, delayMs, timeout })],
    { stdio: ['ignore', 'inherit', 'inherit', 'ipc'], execArgv: [] }
  )
  const hello = deferred()
  const closed = deferred()
  const pending = new Map()
  let nextId = 0
  let exited = false
  child.on('message', (message) => {
    if (message.hello) return hello.resolve()
    const request = pending.get(message.id)
    if (!request) return
    if (message.error) request.reject(new Error(role + ': ' + message.error))
    else request.resolve(message.result)
  })
  child.on('error', fail)
  child.once('close', (code, signal) => {
    exited = true
    fail(new Error(role + ' exited: ' + code + ' / ' + signal))
    closed.resolve({ code, signal })
  })

  function fail(error) {
    hello.reject(error)
    for (const request of pending.values()) request.reject(error)
  }

  async function call(op, args = {}, limit = timeout + 1000) {
    if (exited || !child.connected) throw new Error(role + ' is not running')
    const id = ++nextId
    const request = deferred()
    pending.set(id, request)
    try {
      child.send({ id, op, args }, (error) => {
        if (error) request.reject(error)
      })
      return await deadline(request.promise, limit, role + ' ' + op)
    } finally {
      pending.delete(id)
    }
  }

  return {
    role,
    child,
    ready: hello.promise,
    call,
    async stop() {
      let forced = false
      let error = null
      if (!exited) {
        try {
          await call('stop', {}, 5000)
          await deadline(closed.promise, 5000, role + ' exit')
        } catch (err) {
          error = err.message
          if (!exited) {
            forced = true
            child.kill('SIGKILL')
          }
        }
      }
      const exit = await closed.promise
      return { role, pid: child.pid, forced, error, ...exit }
    }
  }
}

function sample(spec, mode, direction, rep) {
  return {
    kind: 'sample',
    scenario: spec.name,
    mode,
    direction,
    rep,
    size: spec.size,
    streams: spec.streams,
    delayMs: spec.delayMs,
    ok: false,
    builds: [],
    firstByteMs: null,
    pingMs: null,
    mibPerSecond: null,
    relayCpuMsPerMiB: null,
    errors: []
  }
}

async function measure(row, spec, source, destination, relays, id) {
  const trial = { ...spec, id, mode: row.mode, direction: row.direction }
  let measuring = false
  try {
    row.phase = 'prepare'
    const [, address] = await Promise.all([
      source.call('prepare', trial),
      destination.call('prepare', trial)
    ])
    row.phase = 'connect'
    const opened = await source.call('connect', address)
    row.builds = opened.builds
    if (!opened.ready) throw new Error('one or more benchmark streams did not become ready')
    row.phase = 'transfer'
    await Promise.all(relays.map((relay) => relay.call('cpuBegin')))
    measuring = true
    const endpoints = await Promise.allSettled([source.call('run'), destination.call('collect')])
    if (endpoints[0].status === 'fulfilled') row.source = endpoints[0].value
    if (endpoints[1].status === 'fulfilled') row.destination = endpoints[1].value
    const rejected = endpoints.find((result) => result.status === 'rejected')
    if (rejected) throw rejected.reason
    row.ok =
      row.source.length === spec.streams &&
      row.destination.streams.length === spec.streams &&
      row.destination.errors.length === 0 &&
      row.source.every((result) => result.ok && result.bytes === spec.size) &&
      row.destination.streams.every((result) => result.ok && result.bytes === spec.size)
    for (const result of [...row.source, ...row.destination.streams]) {
      if (!result.ok) row.errors.push(result.error)
    }
    row.errors.push(...row.destination.errors)
    if (row.ok) {
      const sender = row.direction === 'up' ? row.source : row.destination.streams
      const receiver = row.direction === 'up' ? row.destination.streams : row.source
      const starts = sender.map((result) => BigInt(result.startNs))
      const ends = receiver.map((result) => BigInt(result.lastNs))
      row.firstByteMs = receiver.map((result, index) => milliseconds(starts[index], result.firstNs))
      if (row.firstByteMs.some((ms) => ms < 0)) {
        throw new Error('inconsistent local monotonic timestamps')
      }
      if (spec.ping) {
        row.pingMs = milliseconds(sender[0].startNs, sender[0].lastNs)
        if (row.pingMs <= 0) throw new Error('inconsistent ping timestamps')
      } else {
        const start = starts.reduce((a, b) => (a < b ? a : b))
        const end = ends.reduce((a, b) => (a > b ? a : b))
        row.elapsedMs = milliseconds(start, end)
        if (row.elapsedMs <= 0) {
          throw new Error('inconsistent local monotonic timestamps')
        }
        row.mibPerSecond = (spec.size * spec.streams) / MIB / (row.elapsedMs / 1000)
      }
    }
  } catch (error) {
    row.ok = false
    row.errors.push(error.message)
  } finally {
    if (measuring) {
      const cpu = await Promise.allSettled(relays.map((relay) => relay.call('cpuEnd')))
      row.relayCpu = cpu.map((result, index) =>
        result.status === 'fulfilled'
          ? { relay: index, ...result.value }
          : { relay: index, error: result.reason.message }
      )
      if (row.ok && cpu.every((result) => result.status === 'fulfilled')) {
        const sum = row.relayCpu.reduce((total, result) => total + result.ms, 0)
        row.relayCpuMsPerMiB = sum / ((spec.size * spec.streams) / MIB)
      }
    }
    if (!row.ok) {
      row.firstByteMs = null
      row.pingMs = null
      row.mibPerSecond = null
      row.relayCpuMsPerMiB = null
    }
    const cleanup = await Promise.allSettled([source.call('abort'), destination.call('abort')])
    row.cleanupErrors = cleanup
      .filter((result) => result.status === 'rejected')
      .map((result) => result.reason.message)
    row.endpointDelay = await Promise.all(
      [source, destination].map(async (worker) => {
        try {
          return { role: worker.role, ...(await worker.call('delayStats')) }
        } catch (error) {
          return { role: worker.role, error: error.message }
        }
      })
    )
  }
  return row
}

async function main() {
  const opts = options()
  if (opts === null) {
    console.log('Usage: node bench/private-routing/index.js [--out=/scratch/results.jsonl]')
    console.log(
      '  --reps=3 --timeout=120000 --modes=direct,alpha --directions=up,down --delays=0,5'
    )
    console.log('  --cases=probe,ping,1mib,16mib,4x4mib,delay4mib')
    console.log(
      'Packet-level variant: bash bench/private-routing/netem.sh [same benchmark options]'
    )
    console.log('  PR_NETEM_DELAY_MS=5 PR_NETEM_LIMIT=100000 (dedicated Linux network namespace)')
    console.log('Output files must not already exist. No output file is created without --out.')
    return
  }
  const specs = CASES.filter(
    (spec) => opts.cases.includes(spec.name) && opts.delays.includes(spec.delayMs)
  )
  if (specs.length === 0) throw new Error('no benchmark cases selected')
  const fd = opts.out === null ? null : fs.openSync(opts.out, 'wx')
  const rows = []
  const workers = new Set()
  let interrupted = false
  let id = 0
  const interrupt = () => {
    interrupted = true
    for (const worker of workers) worker.child.kill('SIGTERM')
  }
  process.once('SIGINT', interrupt)
  process.once('SIGTERM', interrupt)

  function emit(row) {
    row.delayMethod = opts.method === 'netem' ? 'packet-tc-netem-v1' : METHOD
    row.delayParameters = {
      injectionDelayMs: row.delayMs === undefined ? opts.delays : row.delayMs,
      admission: 'immediate-ack-owned-copy',
      zeroInjection: 'native-passthrough',
      capBytes: CAP_BYTES,
      capWrites: CAP_WRITES,
      overflow: 'reject-new-and-destroy-stream',
      packetOneWayMs: opts.method === 'netem' ? opts.netem : 0,
      packetLinkRttMs: opts.method === 'netem' ? 2 * opts.netem : 0,
      packetQueueLimit: opts.method === 'netem' ? opts.netemlimit : null,
      packetScope: opts.method === 'netem' ? 'all-loopback-egress-in-dedicated-netns' : 'none'
    }
    rows.push(row)
    if (fd !== null) fs.writeSync(fd, JSON.stringify(row) + '\n')
  }

  try {
    emit({
      kind: 'environment',
      schema: 2,
      node: process.version,
      platform: process.platform,
      arch: process.arch,
      cpus: os.cpus().length,
      chunkBytes: CHUNK,
      relays: RELAYS,
      options: opts,
      productionPatches: false,
      bootstrapStorage: 'three non-relay nodes with the production privateRouting service enabled',
      clock: 'same-host process.hrtime.bigint monotonic timestamps',
      delay:
        opts.method === 'netem'
          ? 'packet-level netem on every namespace loopback egress, including discovery and ACKs'
          : 'bounded immediate-ack application/UDX injection delay; not WAN RTT',
      cpu: 'sum of separate relay processes, including background work and measurement IPC'
    })
    for (const delayMs of opts.delays) {
      const selected = specs.filter((spec) => spec.delayMs === delayMs)
      if (selected.length === 0) continue
      let net = null
      let source = null
      let destination = null
      const relays = []
      let setupError = null
      try {
        // Bootstrap/storage nodes use the normal public configuration so private
        // descriptor requests receive replies rather than unsupported-plugin timeouts.
        net = await createTestnet(0, { bootstrap: [], host: '127.0.0.1' })
        for (let i = 0; i < 3; i++) {
          const bootstrap = net.createNode({
            host: '127.0.0.1',
            ephemeral: false,
            firewalled: false,
            privateRouting: {
              release: 'alpha',
              acknowledgeAlpha: true,
              profile: 'standard',
              mode: 'optional',
              relay: false
            }
          })
          await deadline(bootstrap.fullyBootstrapped(), opts.timeout, 'testnet bootstrap')
          await deadline(
            bootstrap.privateRouting.ready(),
            opts.timeout,
            'bootstrap private service'
          )
          if (i === 0) net.bootstrap.push({ host: '127.0.0.1', port: bootstrap.address().port })
        }
        for (let i = 0; i < RELAYS; i++) {
          relays.push(launch('relay', net.bootstrap, delayMs, opts.timeout))
        }
        source = launch('source', net.bootstrap, delayMs, opts.timeout)
        destination = launch('destination', net.bootstrap, delayMs, opts.timeout)
        for (const worker of [...relays, source, destination]) workers.add(worker)
        await Promise.all(
          [...relays, source, destination].map((worker) =>
            deadline(worker.ready, opts.timeout, worker.role + ' ready')
          )
        )
        const relayInfo = await Promise.all(relays.map((relay) => relay.call('start')))
        const endpoints = await Promise.all([source.call('start'), destination.call('start')])
        emit({ kind: 'network', delayMs, bootstrap: net.bootstrap, relays: relayInfo, endpoints })
      } catch (error) {
        setupError = error.message
      }
      try {
        for (const spec of selected) {
          for (const direction of opts.directions) {
            for (let rep = 1; rep <= opts.reps; rep++) {
              // Alternate ordering to avoid assigning all later samples to alpha.
              const modes = rep % 2 === 1 ? opts.modes : opts.modes.slice().reverse()
              for (const mode of modes) {
                if (interrupted) throw new Error('benchmark interrupted')
                const row = sample(spec, mode, direction, rep)
                if (setupError) {
                  row.phase = 'setup'
                  row.errors.push(setupError)
                } else {
                  await measure(row, spec, source, destination, relays, ++id)
                }
                emit(row)
              }
            }
          }
        }
      } finally {
        const exits = await Promise.all([...workers].map((worker) => worker.stop()))
        emit({ kind: 'cleanup', delayMs, workers: exits })
        workers.clear()
        if (net) await net.destroy()
      }
    }
  } finally {
    process.removeListener('SIGINT', interrupt)
    process.removeListener('SIGTERM', interrupt)
    if (fd !== null) fs.closeSync(fd)
    summarize(rows)
  }
  if (
    rows.some(
      (row) =>
        (row.kind === 'sample' &&
          (!row.ok ||
            (row.cleanupErrors || []).length > 0 ||
            (row.relayCpu || []).some((cpu) => cpu.error))) ||
        (row.kind === 'cleanup' &&
          row.workers.some((worker) => worker.forced || worker.code !== 0 || worker.error))
    )
  ) {
    process.exitCode = 1
  }
}

main().catch((error) => {
  console.error(error.stack || error.message)
  process.exitCode = 1
})
