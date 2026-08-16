'use strict'

const fs = require('fs')
const path = require('path')
const { spawn } = require('child_process')
const b4a = require('b4a')

const {
  MAX_BUFFERED_BYTES,
  ControlFrameDecoder,
  encodeControlFrame,
  TEST_ONLY_CONTROL_AUTHORITY_ISSUER,
  validateControlMessage
} = require('./control-channel')

const COMMAND_TIMEOUT_MS = 5_000
const SCENARIO_TIMEOUT_MS = 30_000

// Diagnostics only, and deliberately NOT reachable from a caller. A stalled step cannot
// be watched past the deadline that kills it, so an operator debugging one may raise a
// deadline from outside; but the shipped literals above never move, so the guard in
// createProcessControl still rejects any caller that supplies its own deadlines, which
// is the invariant it was written for. The override is loud on purpose: container gates
// inherit the environment through `docker -e`, and a run at non-shipped deadlines must
// never be mistakable for a canonical one whose assertion counts mean something. The
// coordinator is not a role, so its stderr is free; a role's is not.
function overriddenDeadline(name, shipped) {
  const raw = process.env[name]
  if (typeof raw !== 'string' || !/^[1-9][0-9]{0,6}$/.test(raw)) return shipped
  const value = Number(raw)
  if (value === shipped) return shipped
  process.stderr.write(
    `coordinator: ${name} overrides the shipped ${shipped}ms with ${value}ms; this is not a canonical run\n`
  )
  return value
}
const STDERR_LIMIT_BYTES = 4_096
const TERMINATION_GRACE_MS = 2_000
const HARD_KILL = process.platform === 'win32' ? 'SIGKILL' : 'SIGKILL'

class ProcessControlError extends Error {
  constructor(code) {
    super(code)
    this.code = code
  }
}

function sanitizeDetail(value) {
  if (value === null || value === undefined) return null
  const text = typeof value === 'string' ? value : String(value)
  const cleaned = text
    .replace(/[^\x20-\x7e]/g, ' ')
    .trim()
    .slice(0, 200)
  return cleaned.length === 0 ? null : cleaned
}

function safeFailure(role, phase, code, detail) {
  const known = /^PROCESS_[A-Z0-9_]{1,60}$/.test(code)
  return Object.freeze({
    code: known ? code : 'PROCESS_FAILURE',
    // Normalising an unrecognised code to PROCESS_FAILURE loses the only
    // description of what actually went wrong, which is precisely what a
    // failing run needs. Keep a bounded, character-restricted copy.
    detail: sanitizeDetail(detail !== undefined ? detail : known ? null : code),
    phase: typeof phase === 'string' && /^[A-Z][A-Z0-9_]{0,31}$/.test(phase) ? phase : 'CONTROL',
    role:
      role === 'coordinator' ||
      [
        'endpoint',
        'guard',
        'lookup-middle-a',
        'lookup-exit-a',
        'lookup-middle-b',
        'lookup-exit-b',
        'announce-middle',
        'announce-exit',
        'dht-seed',
        'dht-referral',
        'dht-value'
      ].includes(role)
        ? role
        : 'coordinator'
  })
}

// The code alone is often not enough to act on. Attach the role that failed and
// any preserved detail so a failing run names its own cause.
function describeFailure(failure) {
  const error = new ProcessControlError(failure.code)
  error.role = failure.role
  error.phase = failure.phase
  error.detail = failure.detail
  error.message = failure.detail
    ? `${failure.code} (${failure.role}/${failure.phase}): ${failure.detail}`
    : `${failure.code} (${failure.role}/${failure.phase})`
  return error
}

function roleEnvironment() {
  const env = Object.create(null)
  const fatalLog = process.env.PR_ROLE_FATAL_LOG
  if (typeof fatalLog === 'string' && fatalLog.length > 0) env.PR_ROLE_FATAL_LOG = fatalLog
  return env
}

function deferred() {
  let resolve
  let reject
  const promise = new Promise((res, rej) => {
    resolve = res
    reject = rej
  })
  void promise.catch(() => false)
  return { promise, reject, resolve }
}

function timeout(ms, value) {
  let timer = null
  const promise = new Promise((resolve) => {
    timer = setTimeout(resolve, ms, value)
  })
  return {
    promise,
    cancel() {
      if (timer === null) return false
      clearTimeout(timer)
      timer = null
      return true
    }
  }
}

function createProcessControl(options) {
  if (!options || !Array.isArray(options.children) || options.children.length === 0) {
    throw new ProcessControlError('PROCESS_CONTROL_INVALID')
  }
  const commandTimeoutMs = options.commandTimeoutMs || COMMAND_TIMEOUT_MS
  const scenarioTimeoutMs = options.scenarioTimeoutMs || SCENARIO_TIMEOUT_MS
  const terminationGraceMs = options.terminationGraceMs || TERMINATION_GRACE_MS
  const auditor = options.auditor || null
  if (
    commandTimeoutMs !== COMMAND_TIMEOUT_MS ||
    scenarioTimeoutMs !== SCENARIO_TIMEOUT_MS ||
    terminationGraceMs !== TERMINATION_GRACE_MS
  ) {
    throw new ProcessControlError('PROCESS_CONTROL_INVALID')
  }
  // Resolved only after the guard above has had its say, and only from the environment,
  // so the caller-facing invariant is untouched by the diagnostic path.
  const effectiveCommandTimeoutMs = overriddenDeadline('PR_COMMAND_TIMEOUT_MS', commandTimeoutMs)
  const effectiveScenarioTimeoutMs = overriddenDeadline('PR_SCENARIO_TIMEOUT_MS', scenarioTimeoutMs)

  const records = new Map()
  const waiters = new Map()
  const isolatedGrantRequests = new WeakMap()
  const failed = deferred()
  const failureSignal = deferred()
  let failure = null
  let closing = null
  let closed = false

  function raceFailure(promise) {
    const raced = Promise.race([promise, failureSignal.promise])
    void raced.catch(() => false)
    return raced
  }

  const scenarioTimer = setTimeout(() => {
    fail('coordinator', 'SCENARIO', 'PROCESS_SCENARIO_DEADLINE')
  }, effectiveScenarioTimeoutMs)

  function scheduleStdinFailure(record) {
    if (
      closed ||
      failure !== null ||
      record.exited ||
      record.exitExpected ||
      record.stdinFailureTimer !== null
    ) {
      return
    }
    record.stdinFailureTimer = setImmediate(() => {
      record.stdinFailureTimer = null
      if (closed || failure !== null || record.exitExpected) return
      if (record.exited) {
        fail(record.role, 'CONTROL', 'PROCESS_EARLY_EXIT')
        return
      }
      fail(record.role, 'CONTROL', 'PROCESS_CHILD_STDIN')
    })
  }

  function writeFrame(record, frame) {
    if (closed || failure !== null || record.exited) {
      frame.fill(0)
      if (record.exited) fail(record.role, 'CONTROL', 'PROCESS_EARLY_EXIT')
      return Promise.resolve(false)
    }
    return new Promise((resolve) => {
      const stdin = record.child.stdin
      let callbackComplete = false
      let drainComplete = true
      let settled = false
      let writeFailed = false
      const finish = () => {
        if (settled || !callbackComplete || !drainComplete) return
        settled = true
        stdin.removeListener('close', onUnavailable)
        stdin.removeListener('error', onUnavailable)
        stdin.removeListener('drain', onDrain)
        frame.fill(0)
        resolve(!writeFailed && failure === null && !record.exited)
      }
      const onDrain = () => {
        drainComplete = true
        finish()
      }
      const onUnavailable = () => {
        writeFailed = true
        callbackComplete = true
        drainComplete = true
        scheduleStdinFailure(record)
        finish()
      }
      const onWrite = (err) => {
        callbackComplete = true
        if (err) {
          writeFailed = true
          drainComplete = true
          scheduleStdinFailure(record)
        }
        finish()
      }
      stdin.once('close', onUnavailable)
      stdin.once('error', onUnavailable)
      try {
        drainComplete = stdin.write(frame, onWrite)
        if (!drainComplete) stdin.once('drain', onDrain)
      } catch {
        onUnavailable()
      }
    })
  }

  for (const input of options.children) {
    if (
      !input ||
      !input.child ||
      typeof input.role !== 'string' ||
      records.has(input.role) ||
      typeof input.generation !== 'bigint' ||
      typeof input.phaseSequence !== 'bigint'
    ) {
      clearTimeout(scenarioTimer)
      throw new ProcessControlError('PROCESS_CONTROL_INVALID')
    }
    const record = {
      child: input.child,
      decoder: null,
      exited: false,
      exitExpected: false,
      exitResult: null,
      exitWaiter: deferred(),
      generation: input.generation,
      phaseGate: input.phaseGate || null,
      phaseSequence: input.phaseSequence,
      plan: input.plan || 'portable-loopback',
      role: input.role,
      roleIndex: input.roleIndex,
      run: input.run || null,
      stderrBytes: 0,
      stdoutBytes: 0,
      termSent: false,
      hardSent: false,
      stdinFailureTimer: null,
      writeChain: Promise.resolve()
    }
    record.decoder = new ControlFrameDecoder((message) => dispatch(record, message))
    records.set(record.role, record)
    input.child.stdin.on('error', () => {
      scheduleStdinFailure(record)
    })
    input.child.stdin.on('close', () => {
      scheduleStdinFailure(record)
    })

    input.child.stdout.on('data', (chunk) => {
      if (closed || failure !== null) return
      record.stdoutBytes += chunk.byteLength
      if (chunk.byteLength > MAX_BUFFERED_BYTES || record.stdoutBytes > MAX_BUFFERED_BYTES) {
        fail(record.role, 'CONTROL', 'PROCESS_STDOUT_FLOOD')
        return
      }
      try {
        record.decoder.push(chunk)
        record.stdoutBytes = 0
      } catch {
        fail(record.role, 'CONTROL', 'PROCESS_MALFORMED_FRAME')
      }
    })
    input.child.stderr.on('data', (chunk) => {
      if (closed || failure !== null || chunk.byteLength === 0) return
      record.stderrBytes += chunk.byteLength
      fail(
        record.role,
        'CONTROL',
        record.stderrBytes > STDERR_LIMIT_BYTES ? 'PROCESS_STDERR_FLOOD' : 'PROCESS_STDERR',
        b4a.toString(chunk, 'utf8')
      )
    })
    input.child.once('exit', (code, signal) => {
      record.exited = true
      record.exitResult = Object.freeze({ code, signal })
      record.exitWaiter.resolve(record.exitResult)
      if (!closed && failure === null && !record.exitExpected) {
        fail(record.role, 'CONTROL', 'PROCESS_EARLY_EXIT', `exit code ${code} signal ${signal}`)
      }
    })
    input.child.once('error', (err) => {
      fail(record.role, 'CONTROL', 'PROCESS_CHILD_ERROR', err && err.message)
    })
  }

  function key(role, event, generation) {
    return `${role}\u0000${event}\u0000${generation.toString(10)}`
  }

  function dispatch(record, message) {
    if (closed || failure !== null) return
    try {
      validateControlMessage(message, {
        direction: 'event',
        generation: record.generation,
        phaseGate: record.phaseGate,
        phaseSequence: record.phaseSequence,
        projection: record.plan,
        role: record.role,
        roleIndex: record.roleIndex,
        run: record.run
      })
      if (auditor !== null) auditor.auditEvent(record.role, message)
    } catch (err) {
      const code =
        err && err.code === 'PROCESS_CONFIG_INVALID'
          ? 'PROCESS_CONFIG_INVALID'
          : 'PROCESS_PHASE_MISMATCH'
      fail(record.role, 'CONTROL', code)
      return
    }
    if (message.type === 'error') {
      fail(record.role, 'CONTROL', message.code)
      return
    }
    const waiterKey = key(record.role, message.type, message.generation)
    const waiter = waiters.get(waiterKey)
    if (!waiter) {
      fail(record.role, 'CONTROL', 'PROCESS_UNEXPECTED_EVENT')
      return
    }
    if (message.type === 'isolated-grant-request') {
      isolatedGrantRequests.set(message, {
        generation: message.generation,
        phaseSequence: message.phaseSequence,
        requestSequence: message.requestSequence,
        role: message.role,
        roleIndex: message.roleIndex,
        tupleDigest: b4a.from(message.tupleDigest)
      })
    }
    waiter.messages.push(message)
    waiter.remaining--
    if (waiter.remaining > 0) return
    waiters.delete(waiterKey)
    clearTimeout(waiter.timer)
    waiter.resolve(waiter.many ? Object.freeze(waiter.messages) : message)
  }

  function expect(role, event, generation) {
    return expectMany(role, event, generation, 1, false)
  }

  function expectMany(role, event, generation, count, many = true) {
    if (closed || failure !== null) {
      return raceFailure(Promise.reject(new ProcessControlError('PROCESS_CONTROL_CLOSED')))
    }
    const record = records.get(role)
    if (
      !record ||
      record.generation !== generation ||
      !Number.isSafeInteger(count) ||
      count < 1 ||
      count > 16
    ) {
      return raceFailure(Promise.reject(new ProcessControlError('PROCESS_CONTROL_INVALID')))
    }
    const waiterKey = key(role, event, generation)
    if (waiters.has(waiterKey)) {
      return raceFailure(Promise.reject(new ProcessControlError('PROCESS_DUPLICATE_WAITER')))
    }
    const pending = deferred()
    const timer = setTimeout(() => {
      waiters.delete(waiterKey)
      pending.reject(new ProcessControlError('PROCESS_COMMAND_DEADLINE'))
      fail(role, 'COMMAND', 'PROCESS_COMMAND_DEADLINE')
    }, effectiveCommandTimeoutMs)
    waiters.set(waiterKey, {
      ...pending,
      many,
      messages: [],
      remaining: count,
      timer
    })
    return raceFailure(pending.promise)
  }

  // A role may raise an event the scenario tolerates but cannot schedule, such as an
  // exit asking for a learned-closer grant whenever its branch is rebuilt. Those need
  // a standing waiter: unlike `expect` it carries no command deadline, and the caller
  // cancels it when the step that tolerates the event is over.
  function expectOptional(role, event, generation) {
    if (closed || failure !== null) throw new ProcessControlError('PROCESS_CONTROL_CLOSED')
    const record = records.get(role)
    if (!record || record.generation !== generation) {
      throw new ProcessControlError('PROCESS_CONTROL_INVALID')
    }
    const waiterKey = key(role, event, generation)
    if (waiters.has(waiterKey)) throw new ProcessControlError('PROCESS_DUPLICATE_WAITER')
    const pending = deferred()
    waiters.set(waiterKey, {
      ...pending,
      many: false,
      messages: [],
      remaining: 1,
      timer: null
    })
    return Object.freeze({
      promise: raceFailure(pending.promise),
      cancel() {
        const current = waiters.get(waiterKey)
        if (!current || current.resolve !== pending.resolve) return false
        waiters.delete(waiterKey)
        pending.reject(new ProcessControlError('PROCESS_CONTROL_CLOSED'))
        return true
      }
    })
  }

  function setPhase(role, generation, phaseSequence) {
    const record = records.get(role)
    if (
      !record ||
      typeof generation !== 'bigint' ||
      typeof phaseSequence !== 'bigint' ||
      generation < record.generation ||
      phaseSequence <= 0n
    ) {
      throw new ProcessControlError('PROCESS_CONTROL_INVALID')
    }
    record.generation = generation
    record.phaseSequence = phaseSequence
  }

  function expectEvent(role, event, generation, phaseSequence) {
    setPhase(role, generation, phaseSequence)
    return expect(role, event, generation)
  }

  function send(role, message, authorities = {}) {
    if (closed || failure !== null) throw new ProcessControlError('PROCESS_CONTROL_CLOSED')
    const record = records.get(role)
    if (!record) throw new ProcessControlError('PROCESS_CONTROL_INVALID')
    let frame
    try {
      validateControlMessage(message, {
        coordinator: true,
        direction: 'command',
        generation: record.generation,
        pendingGrant: authorities.pendingGrant || null,
        phaseGate: authorities.phaseGate || record.phaseGate,
        phaseSequence: record.phaseSequence,
        projection: record.plan,
        role: record.role,
        roleIndex: record.roleIndex,
        run: record.run
      })
      frame = encodeControlFrame(message)
    } catch (err) {
      fail(role, 'CONTROL', 'PROCESS_COMMAND_INVALID')
      throw err
    }
    const writing = record.writeChain.then(() => writeFrame(record, frame))
    record.writeChain = writing
    return raceFailure(writing)
  }

  function respondIsolatedGrant(role, request, grant) {
    if (closed || failure !== null || !request || request.type !== 'isolated-grant-request') {
      throw new ProcessControlError('PROCESS_CONTROL_INVALID')
    }
    const record = records.get(role)
    const observed = isolatedGrantRequests.get(request)
    if (
      !record ||
      !observed ||
      request.role !== observed.role ||
      request.roleIndex !== observed.roleIndex ||
      request.generation !== observed.generation ||
      request.phaseSequence !== observed.phaseSequence ||
      request.requestSequence !== observed.requestSequence ||
      !b4a.isBuffer(request.tupleDigest) ||
      !b4a.equals(request.tupleDigest, observed.tupleDigest) ||
      observed.role !== record.role ||
      observed.roleIndex !== record.roleIndex ||
      observed.generation !== record.generation ||
      observed.phaseSequence !== record.phaseSequence
    ) {
      throw new ProcessControlError('PROCESS_CONTROL_INVALID')
    }
    isolatedGrantRequests.delete(request)
    const pendingGrant = TEST_ONLY_CONTROL_AUTHORITY_ISSUER.pendingGrant({
      generation: observed.generation,
      requestSequence: observed.requestSequence,
      role: observed.role,
      tupleDigest: observed.tupleDigest
    })
    let written
    try {
      written = send(
        role,
        {
          generation: observed.generation,
          phaseSequence: observed.phaseSequence,
          role: observed.role,
          roleIndex: observed.roleIndex,
          type: 'isolated-grant',
          grant,
          requestSequence: observed.requestSequence,
          tupleDigest: observed.tupleDigest
        },
        { pendingGrant }
      )
    } finally {
      observed.tupleDigest.fill(0)
    }
    return written
  }

  function expectExit(role) {
    const record = records.get(role)
    if (!record) {
      return raceFailure(Promise.reject(new ProcessControlError('PROCESS_CONTROL_INVALID')))
    }
    record.exitExpected = true
    return raceFailure(
      record.exited ? Promise.resolve(record.exitResult) : record.exitWaiter.promise
    )
  }

  function fail(role, phase, code, detail) {
    if (failure !== null || closed) return
    failure = safeFailure(role, phase, code, detail)
    failureSignal.reject(describeFailure(failure))
    shutdown().then(
      () => failed.resolve(failure),
      () => failed.resolve(failure)
    )
  }

  async function terminateRecord(record) {
    if (record.exited) return record.exitResult
    if (record.child.stdin && !record.child.stdin.destroyed) record.child.stdin.end()
    if (!record.termSent) {
      record.termSent = true
      try {
        record.child.kill('SIGTERM')
      } catch {}
    }
    const grace = timeout(terminationGraceMs, null)
    let result
    try {
      result = await Promise.race([record.exitWaiter.promise, grace.promise])
    } finally {
      grace.cancel()
    }
    if (result !== null || record.exited) return record.exitResult
    if (!record.hardSent) {
      record.hardSent = true
      try {
        record.child.kill(HARD_KILL)
      } catch {}
    }
    return record.exitWaiter.promise
  }

  async function shutdown() {
    if (closing !== null) return closing
    closing = (async () => {
      clearTimeout(scenarioTimer)
      for (const waiter of waiters.values()) {
        clearTimeout(waiter.timer)
        waiter.reject(new ProcessControlError(failure ? failure.code : 'PROCESS_CONTROL_CLOSED'))
      }
      waiters.clear()
      const exits = []
      for (const record of records.values()) exits.push(terminateRecord(record))
      await Promise.all(exits)
      for (const record of records.values()) record.decoder.destroy()
      if (auditor !== null && typeof auditor.destroy === 'function') auditor.destroy()
      closed = true
    })()
    return closing
  }

  async function cancel(phase = 'CONTROL') {
    fail('coordinator', phase, 'PROCESS_CANCELLED')
    await shutdown()
  }

  return Object.freeze({
    cancel,
    close: shutdown,
    expect,
    expectEvent,
    expectOptional,
    expectMany,
    expectExit,
    failed() {
      return failed.promise
    },
    get closed() {
      return closed
    },
    respondIsolatedGrant,
    send,
    setPhase
  })
}

function resolveRuntimeLaunch(runtime, options = {}) {
  const roleRunner = options.roleRunner || path.join(__dirname, 'role-runner.js')
  if (runtime === 'node') {
    return Object.freeze({
      args: [roleRunner],
      command: options.nodePath || process.execPath,
      runtime,
      version: process.version
    })
  }
  if (runtime === 'bare') {
    const command = require('bare-runtime')('bare')
    return Object.freeze({ args: [roleRunner], command, runtime, version: 'v1.30.3' })
  }
  throw new ProcessControlError('PROCESS_RUNTIME_INVALID')
}

function resolveExecution(launch, args) {
  if (launch.runtime === 'bare') {
    const bin = require('bare-runtime')('bare')
    if (launch.command !== bin) throw new ProcessControlError('PROCESS_RUNTIME_INVALID')
    try {
      fs.accessSync(bin, fs.constants.X_OK)
    } catch {
      fs.chmodSync(bin, 0o755)
    }
    return { args, command: bin }
  }
  if (launch.runtime === 'node') return { args, command: launch.command }
  throw new ProcessControlError('PROCESS_RUNTIME_INVALID')
}

function spawnRuntimeProcess(launch, args = launch.args, options = {}) {
  const { enter = null, ...rest } = options
  const resolved = resolveExecution(launch, args)
  // `enter` wraps the resolved command so the role runs somewhere else, such as
  // inside a network namespace. It never changes which runtime is executed.
  const placed = enter === null ? resolved : enter(resolved.command, resolved.args)
  if (!placed || typeof placed.command !== 'string' || !Array.isArray(placed.args)) {
    throw new ProcessControlError('PROCESS_CONTROL_INVALID')
  }
  return spawn(placed.command, placed.args, {
    ...rest,
    stdio: rest.stdio || ['pipe', 'pipe', 'pipe']
  })
}

function spawnRoleProcesses(runtime, projections, options = {}) {
  if (!Array.isArray(projections) || projections.length !== 11) {
    throw new ProcessControlError('PROCESS_CONTROL_INVALID')
  }
  if (options.enter !== undefined && typeof options.enter !== 'function') {
    throw new ProcessControlError('PROCESS_CONTROL_INVALID')
  }
  const launch = resolveRuntimeLaunch(runtime, options)
  return Object.freeze(
    projections.map((projection) => {
      const child = spawnRuntimeProcess(launch, launch.args, {
        cwd: options.cwd || path.join(__dirname, '..', '..', '..'),
        enter: options.enter
          ? (command, argv) => options.enter(projection.roleIndex, command, argv)
          : null,
        // Roles run with an empty environment on purpose. The one exception is
        // the opt-in fatal trace path, forwarded by name so a diagnostic run
        // does not become a hole for arbitrary inherited configuration.
        env: roleEnvironment(),
        stdio: ['pipe', 'pipe', 'pipe']
      })
      return Object.freeze({
        child,
        generation: projection.generation,
        phaseGate: projection.phaseGate || null,
        phaseSequence: 1n,
        plan: projection.plan,
        role: projection.role,
        roleIndex: projection.roleIndex,
        run: projection.run
      })
    })
  )
}

module.exports = Object.freeze({
  COMMAND_TIMEOUT_MS,
  HARD_KILL,
  SCENARIO_TIMEOUT_MS,
  STDERR_LIMIT_BYTES,
  TERMINATION_GRACE_MS,
  ProcessControlError,
  createProcessControl,
  resolveRuntimeLaunch,
  safeFailure,
  spawnRuntimeProcess,
  spawnRoleProcesses
})
