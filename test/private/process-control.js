'use strict'

const test = require('brittle')
const { EventEmitter } = require('events')
const { PassThrough } = require('stream')

const { encodeControlFrame } = require('./process/control-channel')
const {
  COMMAND_TIMEOUT_MS,
  REMOTE_ACTIVATE_TIMEOUT_MS,
  SCENARIO_TIMEOUT_MS,
  STDERR_LIMIT_BYTES,
  TERMINATION_GRACE_MS,
  createProcessControl,
  resolveRuntimeLaunch,
  spawnRuntimeProcess
} = require('./process/coordinator')
const { PROCESS_PLANS } = require('./process/topology-fixture')

class FakeChild extends EventEmitter {
  constructor() {
    super()
    this.stdin = new PassThrough()
    this.stdout = new PassThrough()
    this.stderr = new PassThrough()
    this.exitCode = null
    this.signalCode = null
    this.kills = []
    this.stdinClosed = false
    this.stdin.on('finish', () => {
      this.stdinClosed = true
    })
  }

  kill(signal) {
    this.kills.push(signal)
    if (signal === 'SIGTERM') {
      this.exitCode = 0
      queueMicrotask(() => this.emit('exit', 0, signal))
    }
    return true
  }
}

function configured(role, roleIndex, generation = 1n) {
  return {
    generation,
    phaseSequence: 1n,
    role,
    roleIndex,
    type: 'configured'
  }
}

function fixture() {
  const endpoint = new FakeChild()
  const guard = new FakeChild()
  const control = createProcessControl({
    children: [
      {
        child: endpoint,
        generation: 1n,
        phaseSequence: 1n,
        role: 'endpoint',
        roleIndex: 1
      },
      {
        child: guard,
        generation: 1n,
        phaseSequence: 1n,
        role: 'guard',
        roleIndex: 2
      }
    ]
  })
  return { control, endpoint, guard }
}

function grantFixture() {
  const run = Buffer.alloc(16, 7)
  const first = new FakeChild()
  const second = new FakeChild()
  const control = createProcessControl({
    children: [
      {
        child: first,
        generation: 1n,
        phaseSequence: 1n,
        role: 'lookup-exit-a',
        roleIndex: 4,
        run
      },
      {
        child: second,
        generation: 1n,
        phaseSequence: 1n,
        role: 'lookup-exit-b',
        roleIndex: 6,
        run
      }
    ]
  })
  return { control, first, run, second }
}

function isolatedGrantRequest(run) {
  return {
    generation: 1n,
    phaseSequence: 1n,
    requestSequence: 1n,
    role: 'lookup-exit-a',
    roleIndex: 4,
    run,
    tupleDigest: Buffer.alloc(32, 8),
    type: 'isolated-grant-request'
  }
}

function rejectsControlCode(t, fn, code = 'PROCESS_CONTROL_INVALID') {
  let error = null
  try {
    fn()
  } catch (err) {
    error = err
  }
  t.is(error && error.code, code)
}

test('process control freezes exact lifecycle bounds', (t) => {
  t.is(COMMAND_TIMEOUT_MS, 5_000)
  t.is(SCENARIO_TIMEOUT_MS, 30_000)
  t.is(STDERR_LIMIT_BYTES, 4_096)
  t.is(TERMINATION_GRACE_MS, 2_000)
})
test('process control keeps scenario command and termination deadlines referenced', async (t) => {
  const originalSetTimeout = global.setTimeout
  const references = new Map()
  global.setTimeout = (callback, delay, ...args) => {
    const timer = originalSetTimeout(callback, delay === TERMINATION_GRACE_MS ? 0 : delay, ...args)
    if (
      delay === SCENARIO_TIMEOUT_MS ||
      delay === COMMAND_TIMEOUT_MS ||
      delay === TERMINATION_GRACE_MS
    ) {
      queueMicrotask(() => {
        const values = references.get(delay) || []
        values.push(timer.hasRef())
        references.set(delay, values)
      })
    }
    return timer
  }
  const child = new FakeChild()
  child.kill = function kill(signal) {
    this.kills.push(signal)
    if (signal === 'SIGKILL') queueMicrotask(() => this.emit('exit', 1, signal))
    return true
  }
  let control = null
  try {
    control = createProcessControl({
      children: [
        {
          child,
          generation: 1n,
          phaseSequence: 1n,
          role: 'endpoint',
          roleIndex: 1
        }
      ]
    })
    control.expect('endpoint', 'configured', 1n)
    await Promise.resolve()
    t.alike(references.get(SCENARIO_TIMEOUT_MS), [true], 'scenario timer keeps process alive')
    t.alike(references.get(COMMAND_TIMEOUT_MS), [true], 'command timer keeps process alive')
    await control.cancel('DEADLINE')
    await Promise.resolve()
    t.alike(references.get(TERMINATION_GRACE_MS), [true], 'termination timer keeps process alive')
  } finally {
    global.setTimeout = originalSetTimeout
    if (control !== null) await control.close()
  }
})

// The dht-mesh plan ships its own bound for the `ready` reply to `activate`; every
// other event keeps the loopback command wait, and loopback plans are untouched.
test('process control binds the remote activate reply by plan, other steps by the command wait', async (t) => {
  const originalSetTimeout = global.setTimeout
  const delays = []
  global.setTimeout = (callback, delay, ...args) => {
    delays.push(delay)
    return originalSetTimeout(callback, delay, ...args)
  }
  let control = null
  try {
    const child = new FakeChild()
    control = createProcessControl({
      plan: PROCESS_PLANS.DHT_MESH,
      children: [{ child, generation: 1n, phaseSequence: 1n, role: 'endpoint', roleIndex: 1 }]
    })
    delays.length = 0
    control.expect('endpoint', 'ready', 1n).catch(() => {})
    t.alike(delays, [REMOTE_ACTIVATE_TIMEOUT_MS], 'remote ready waits the plan bound')
    delays.length = 0
    control.expect('endpoint', 'snapshot', 1n).catch(() => {})
    t.alike(delays, [COMMAND_TIMEOUT_MS], 'other remote steps keep the command wait')
    await control.close()

    const loopback = new FakeChild()
    control = createProcessControl({
      children: [
        { child: loopback, generation: 1n, phaseSequence: 1n, role: 'endpoint', roleIndex: 1 }
      ]
    })
    delays.length = 0
    control.expect('endpoint', 'ready', 1n).catch(() => {})
    t.alike(delays, [COMMAND_TIMEOUT_MS], 'loopback ready keeps the command wait')
  } finally {
    global.setTimeout = originalSetTimeout
    if (control !== null) await control.close()
  }
  t.ok(REMOTE_ACTIVATE_TIMEOUT_MS > COMMAND_TIMEOUT_MS)
  rejectsControlCode(t, () =>
    createProcessControl({
      plan: { name: 'dht-mesh' },
      children: [
        {
          child: new FakeChild(),
          generation: 1n,
          phaseSequence: 1n,
          role: 'endpoint',
          roleIndex: 1
        }
      ]
    })
  )
})

test('process control preserves a sanitized configuration audit failure', async (t) => {
  const endpoint = new FakeChild()
  const control = createProcessControl({
    auditor: {
      auditEvent() {
        throw Object.assign(new Error('forbidden detail'), { code: 'PROCESS_CONFIG_INVALID' })
      },
      destroy() {
        return true
      }
    },
    children: [
      {
        child: endpoint,
        generation: 1n,
        phaseSequence: 1n,
        role: 'endpoint',
        roleIndex: 1
      }
    ]
  })
  let unhandled = null
  const observeUnhandled = (err) => {
    unhandled = err
  }
  process.on('unhandledRejection', observeUnhandled)
  control.expect('endpoint', 'ready', 1n)
  const waiting = control.expect('endpoint', 'configured', 1n)
  endpoint.stdout.write(encodeControlFrame(configured('endpoint', 1)))
  let waiterCode = null
  try {
    await waiting
  } catch (err) {
    waiterCode = err && err.code
  }
  t.is(waiterCode, 'PROCESS_CONFIG_INVALID')
  t.alike(await control.failed(), {
    code: 'PROCESS_CONFIG_INVALID',
    detail: null,
    phase: 'CONTROL',
    role: 'endpoint'
  })
  await new Promise((resolve) => setImmediate(resolve))
  process.removeListener('unhandledRejection', observeUnhandled)
  t.absent(unhandled, 'unawaited raced waiter remains internally observed')
  await control.close()
})

test('process control decodes partial frames for one exact waiter', async (t) => {
  const { control, endpoint } = fixture()
  const waiting = control.expect('endpoint', 'configured', 1n)
  const frame = encodeControlFrame(configured('endpoint', 1))
  endpoint.stdout.write(frame.subarray(0, 2))
  endpoint.stdout.write(frame.subarray(2, 9))
  endpoint.stdout.write(frame.subarray(9))
  const event = await waiting
  t.is(event.type, 'configured')
  t.is(event.role, 'endpoint')
  await control.close()
})

test('process control rejects duplicate and unexpected events then reaps every child', async (t) => {
  const { control, endpoint, guard } = fixture()
  const waiting = control.expect('endpoint', 'configured', 1n)
  const frame = encodeControlFrame(configured('endpoint', 1))
  endpoint.stdout.write(frame)
  await waiting
  endpoint.stdout.write(frame)
  const failure = await control.failed()
  t.alike(failure, {
    code: 'PROCESS_UNEXPECTED_EVENT',
    detail: null,
    phase: 'CONTROL',
    role: 'endpoint'
  })
  t.ok(endpoint.stdin.writableEnded)
  t.ok(guard.stdin.writableEnded)
  t.alike(endpoint.kills, ['SIGTERM'])
  t.alike(guard.kills, ['SIGTERM'])
  await control.close()
})

test('process control rejects stdout flood, any stderr, and early exit with sanitized errors', async (t) => {
  for (const [kind, trigger, expected] of [
    [
      'stdout',
      (child) => child.stdout.write(Buffer.alloc(131_073, 1)),
      {
        code: 'PROCESS_STDOUT_FLOOD',
        detail: null,
        phase: 'CONTROL',
        role: 'endpoint'
      }
    ],
    [
      'stderr',
      (child) => child.stderr.write('forbidden'),
      {
        code: 'PROCESS_STDERR',
        detail: 'forbidden',
        phase: 'CONTROL',
        role: 'endpoint'
      }
    ],
    [
      'exit',
      (child) => child.emit('exit', 7, null),
      {
        code: 'PROCESS_EARLY_EXIT',
        detail: 'exit code 7 signal null',
        phase: 'CONTROL',
        role: 'endpoint'
      }
    ]
  ]) {
    const { control, endpoint } = fixture()
    trigger(endpoint)
    t.alike(await control.failed(), expected, kind)
    await control.close()
  }
})

test('process control arms a natural transition without writing a trigger command', async (t) => {
  const { control, endpoint } = fixture()
  let writes = 0
  endpoint.stdin.on('data', () => writes++)
  const waiting = control.expectEvent('endpoint', 'rotated', 2n, 2n)
  endpoint.stdout.write(
    encodeControlFrame({
      generation: 2n,
      phaseSequence: 2n,
      previousGeneration: 1n,
      role: 'endpoint',
      roleIndex: 1,
      type: 'rotated'
    })
  )
  t.is((await waiting).previousGeneration, 1n)
  t.is(writes, 0, 'arming a natural transition sends no control command')
  await control.close()
})

test('process control cancellation closes stdin and sends SIGTERM exactly once', async (t) => {
  const { control, endpoint, guard } = fixture()
  await control.cancel('ACTIVATION')
  await control.cancel('ACTIVATION')
  t.alike(endpoint.kills, ['SIGTERM'])
  t.alike(guard.kills, ['SIGTERM'])
  t.ok(endpoint.stdin.writableEnded)
  t.ok(guard.stdin.writableEnded)
  t.alike(await control.failed(), {
    code: 'PROCESS_CANCELLED',
    detail: null,
    phase: 'ACTIVATION',
    role: 'coordinator'
  })
  await control.close()
})

test('isolated grant response consumes only its exact observed request before send', async (t) => {
  const { control, first, run } = grantFixture()
  let writes = 0
  first.stdin.on('data', () => writes++)
  const waiting = control.expect('lookup-exit-a', 'isolated-grant-request', 1n)
  first.stdout.write(encodeControlFrame(isolatedGrantRequest(run)))
  const request = await waiting
  const grant = Buffer.alloc(137, 9)

  rejectsControlCode(t, () => control.respondIsolatedGrant('lookup-exit-a', { ...request }, grant))
  rejectsControlCode(t, () => control.respondIsolatedGrant('lookup-exit-b', request, grant))
  t.is(writes, 0, 'unknown and cross-role responses fail before child input')

  t.is(await control.respondIsolatedGrant('lookup-exit-a', request, grant), true)
  t.is(writes, 1, 'matching response is sent exactly once')
  rejectsControlCode(t, () => control.respondIsolatedGrant('lookup-exit-a', request, grant))
  t.is(writes, 1, 'replay fails before child input')
  await control.close()

  const rotated = grantFixture()
  let rotatedWrites = 0
  rotated.first.stdin.on('data', () => rotatedWrites++)
  const rotatedWaiting = rotated.control.expect('lookup-exit-a', 'isolated-grant-request', 1n)
  rotated.first.stdout.write(encodeControlFrame(isolatedGrantRequest(rotated.run)))
  const stale = await rotatedWaiting
  rotated.control.setPhase('lookup-exit-a', 2n, 1n)
  rejectsControlCode(t, () => rotated.control.respondIsolatedGrant('lookup-exit-a', stale, grant))
  t.is(rotatedWrites, 0, 'cross-generation response fails before child input')
  await rotated.control.close()
})

test('process control contains EPIPE and preserves the child early-exit failure', async (t) => {
  const { control, first, second, run } = grantFixture()
  let unhandled = null
  const observeUnhandled = (err) => {
    unhandled = err
  }
  process.on('unhandledRejection', observeUnhandled)
  control.expect('lookup-exit-b', 'configured', 1n)
  const waiting = control.expect('lookup-exit-a', 'isolated-grant-request', 1n)
  first.stdout.write(encodeControlFrame(isolatedGrantRequest(run)))
  const request = await waiting
  const originalWrite = first.stdin.write
  first.stdin.write = (frame, callback) => {
    queueMicrotask(() => {
      const err = Object.assign(new Error('forbidden detail'), { code: 'EPIPE' })
      first.stdin.emit('error', err)
      callback(err)
      first.emit('exit', 7, null)
    })
    return false
  }

  let sendCode = null
  try {
    await control.respondIsolatedGrant('lookup-exit-a', request, Buffer.alloc(137, 9))
  } catch (err) {
    sendCode = err && err.code
  }
  t.is(sendCode, 'PROCESS_EARLY_EXIT')
  t.alike(await control.failed(), {
    code: 'PROCESS_EARLY_EXIT',
    detail: 'exit code 7 signal null',
    phase: 'CONTROL',
    role: 'lookup-exit-a'
  })
  t.alike(first.kills, [], 'already-exited child is not signalled')
  t.alike(await control.expectExit('lookup-exit-a'), { code: 7, signal: null })
  t.alike(second.kills, ['SIGTERM'], 'peer is reaped after the write failure')
  await new Promise((resolve) => setImmediate(resolve))
  process.removeListener('unhandledRejection', observeUnhandled)
  t.absent(unhandled, 'unobserved configured waiter rejection is internally contained')
  await control.close()
  first.stdin.write = originalWrite
})

test('process control failure rejects a pending control write without an unhandled rejection', async (t) => {
  const { control, first, run } = grantFixture()
  const waiting = control.expect('lookup-exit-a', 'isolated-grant-request', 1n)
  first.stdout.write(encodeControlFrame(isolatedGrantRequest(run)))
  const request = await waiting
  const originalWrite = first.stdin.write
  first.stdin.write = () => false
  let unhandled = null
  const observeUnhandled = (err) => {
    unhandled = err
  }
  process.on('unhandledRejection', observeUnhandled)
  const sending = control.respondIsolatedGrant('lookup-exit-a', request, Buffer.alloc(137, 9))
  first.stderr.write('forbidden role detail')
  const outcome = await Promise.race([
    sending.then(
      () => ({ code: null }),
      (err) => ({ code: err && err.code })
    ),
    new Promise((resolve) => setTimeout(resolve, 20, { code: 'PENDING' }))
  ])
  t.is(outcome.code, 'PROCESS_STDERR', 'first sanitized child failure rejects the blocked send')
  t.alike(await control.failed(), {
    code: 'PROCESS_STDERR',
    detail: 'forbidden role detail',
    phase: 'CONTROL',
    role: 'lookup-exit-a'
  })
  await control.close()
  await new Promise((resolve) => setImmediate(resolve))
  process.removeListener('unhandledRejection', observeUnhandled)
  t.absent(unhandled)
  first.stdin.write = originalWrite
})

test('Bare runtime uses pinned package spawn helper for a non-executable prebuild', async (t) => {
  const launch = resolveRuntimeLaunch('bare')
  t.is(launch.command, require('bare-runtime')('bare'))
  let stdout = ''
  let stderr = ''
  const child = spawnRuntimeProcess(launch, ['--version'], {
    cwd: process.cwd()
  })
  child.stdout.on('data', (chunk) => {
    stdout += chunk
  })
  child.stderr.on('data', (chunk) => {
    stderr += chunk
  })
  const result = await new Promise((resolve) => {
    child.once('exit', (code, signal) => resolve({ code, signal }))
  })
  t.alike(result, { code: 0, signal: null })
  t.is(stderr, '')
  t.is(stdout.trim(), 'v1.30.3')
})
