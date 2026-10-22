'use strict'

// Provocation harness for KI-11, deliberately NOT registered in test/private-routing.js:
// it answers one question on demand, and its assertions must not move the aggregate's
// counts. Run it directly:
//
//   node test/private/process/teardown-phase-window-probe.js
//   PR_BRIDGE_TRACE=/tmp/ki11.jsonl node test/private/process/teardown-phase-window-probe.js
//
// THE QUESTION. KI-11's leading explanation is that a role-initiated event still unread
// when the teardown loop advances that role's expected phase arrives carrying the OLD
// phase, fails the phase equality in `baseMessage` (control-channel.js:964), and is
// reported as PROCESS_PHASE_MISMATCH by the catch-all in `dispatch`
// (coordinator.js:343-348). That is a structural question - can it happen - so it is
// answered by holding one real `isolated-grant-request` frame across one real phase
// advance, not by hunting a 1-in-64 rate.
//
// WHAT IS REAL HERE AND WHAT IS MODELLED. The coordinator is the real one, the frames are
// real encoded control frames, and the phase gate is the shipped gate. The role is a
// synthetic child: a pair of streams that speaks the control protocol well enough to
// answer `snapshot` and `stop`. The one thing modelled explicitly is the pipe itself.
// `outbound` holds bytes that have LEFT the role and that the coordinator has not read
// yet, and `deliver()` models the coordinator's next read of that pipe. A frame's phase
// is stamped when the role emits it, which is what makes a delayed frame stale; whether
// the byte physically landed a microsecond before or after the coordinator advanced its
// expected phase is invisible to the coordinator, so emitting at the old phase and
// delivering after the advance is a faithful in-flight frame and not a contrivance.
//
// THE ARMS differ only in where the coordinator's read falls relative to the advance,
// which is exactly the difference the fix in live-process-suite.js introduces:
//
//   stale   - advance the phase, then read.  This is the shipped teardown order at
//             live-process-suite.js:430-437, and it is run with NO grant ever answered,
//             i.e. with the learned-grant responders already stopped. It therefore also
//             tests the "stop the responders before the loop" shape on its own.
//   drained - round trip at the role's CURRENT phase first, so the pipe is read while
//             the old phase is still in force, and only then advance. This is the fixed
//             order.

const { EventEmitter } = require('events')
const { PassThrough } = require('stream')
const b4a = require('b4a')

const { ControlFrameDecoder, ROLES, encodeControlFrame } = require('./control-channel')
const { createProcessControl } = require('./coordinator')

const ROLE = 'lookup-exit-a'
const ROLE_INDEX = ROLES.indexOf(ROLE) + 1
const GENERATION = 7n
const START_PHASE = 5n
const STOP_PHASE = START_PHASE + 1n

const TRACE_PATH = process.env.PR_BRIDGE_TRACE || null
const { performance: clock } = require('perf_hooks')
const traced = []

// Same JSON-per-line shape as `frameSniffer` in test/remote-peer/role-bridge.js,
// so a probe line and a real dispatch line sort into one timeline and read the same way.
function trace(event) {
  const line = {
    t: clock.timeOrigin + clock.now(),
    side: 'probe',
    pid: process.pid,
    ...event
  }
  traced.push(line)
  const text = `${JSON.stringify(line)}\n`
  process.stdout.write(text)
  if (TRACE_PATH === null) return
  try {
    require('fs').appendFileSync(TRACE_PATH, text)
  } catch {}
}

function base(type, phaseSequence) {
  return {
    generation: GENERATION,
    phaseSequence,
    role: ROLE,
    roleIndex: ROLE_INDEX,
    type
  }
}

function grantRequest(phaseSequence, requestSequence) {
  return {
    ...base('isolated-grant-request', phaseSequence),
    requestSequence,
    run: b4a.alloc(16, 0x5a),
    tupleDigest: b4a.alloc(32, 0x11)
  }
}

function snapshot(phaseSequence, state) {
  return {
    ...base('snapshot', phaseSequence),
    activeOperations: 0,
    activeExitOperations: 0,
    announceGeneration: null,
    controllerGeneration: null,
    endpointSockets: 0,
    guardOnly: false,
    lookupGeneration: null,
    openLinks: 0,
    isolatedGrantRequestCount: 1,
    openResources: state === 'CLOSED' ? 0 : 1,
    ordinaryRequestCount: 2,
    pendingGrantRequests: 0,
    pendingLinks: 0,
    pendingPackets: 0,
    queuedBytes: 0,
    referralProbeCount: 1,
    state,
    summaryDigest: b4a.alloc(32, 0x22),
    tableEntryCount: 2
  }
}

// A role that is a pair of streams. It adopts whatever phase a command carries, exactly
// as role-runner.js:968 does, so a command re-sent at the phase already in force is
// legal here for the same reason it is legal there.
function createSyntheticRole() {
  const child = new EventEmitter()
  child.stdin = new PassThrough()
  child.stdout = new PassThrough()
  child.stderr = new PassThrough()

  const outbound = []
  let phaseSequence = START_PHASE
  let state = 'READY'
  let exited = false

  // Bytes the coordinator has not read yet. Nothing here can overtake anything else:
  // one stream, delivered in order, which is the whole basis of the drain.
  function deliver() {
    while (outbound.length > 0) child.stdout.write(outbound.shift())
  }

  function emit(message) {
    trace({
      event: 'frame',
      direction: 'role->coordinator',
      type: message.type,
      generation: String(message.generation),
      phaseSequence: String(message.phaseSequence),
      queued: true
    })
    outbound.push(encodeControlFrame(message))
  }

  const decoder = new ControlFrameDecoder((message) => {
    trace({
      event: 'frame',
      direction: 'coordinator->role',
      type: message.type,
      generation: String(message.generation),
      phaseSequence: String(message.phaseSequence)
    })
    phaseSequence = message.phaseSequence
    if (message.type === 'snapshot') {
      emit(snapshot(phaseSequence, state))
      deliver()
      return
    }
    if (message.type === 'stop') {
      state = 'CLOSED'
      emit(snapshot(phaseSequence, 'CLOSED'))
      emit(base('closed', phaseSequence))
      deliver()
      exit(0)
    }
  })
  child.stdin.on('data', (chunk) => decoder.push(chunk))

  function exit(code) {
    if (exited) return
    exited = true
    setImmediate(() => child.emit('exit', code, null))
  }

  child.kill = () => exit(0)

  return {
    child,
    deliver,
    emit,
    input: {
      child,
      generation: GENERATION,
      phaseSequence: START_PHASE,
      plan: 'portable-loopback',
      role: ROLE,
      roleIndex: ROLE_INDEX,
      run: b4a.alloc(16, 0x5a)
    }
  }
}

function settle(turns = 6) {
  let chain = Promise.resolve()
  for (let index = 0; index < turns; index++) {
    chain = chain.then(() => new Promise((resolve) => setImmediate(resolve)))
  }
  return chain
}

// One arm. `order` is:
//   'stale'    the shipped teardown order at live-process-suite.js:430-437, with one
//              grant request held in the pipe across the advance
//   'drained'  the fixed order: read at the current phase first, then advance
//   'control'  the shipped order with NO frame in flight, which isolates the cause -
//              if this arm is clean then the advance itself is harmless and the stale
//              frame is what fails
// Returns the failure the coordinator reported, or null.
async function runArm(order) {
  trace({ event: 'arm-start', order })
  const role = createSyntheticRole()
  const control = createProcessControl({ children: [role.input] })
  let failure = null
  let lateResponse = null

  // The suite keeps a standing waiter per exit precisely because a grant request can
  // arrive at a moment the scenario does not drive (live-process-suite.js:245). Without
  // it a tolerated event would fail as PROCESS_UNEXPECTED_EVENT instead, which would
  // measure the wrong thing.
  const standing = control.expectOptional(ROLE, 'isolated-grant-request', GENERATION)
  let delivered = null
  standing.promise.then(
    (request) => {
      delivered = request
    },
    () => {}
  )

  // The exit emits a learned-closer grant request on its own schedule. It is stamped
  // with the phase in force NOW, and no grant is ever answered in any arm.
  if (order !== 'control') role.emit(grantRequest(START_PHASE, 1n))

  try {
    if (order === 'drained') {
      // The fix: a round trip at the CURRENT phase. The role's stream is FIFO, so once
      // this snapshot has been dispatched every frame the role emitted earlier has been
      // dispatched too, under the phase it was emitted with.
      const drained = control.expect(ROLE, 'snapshot', GENERATION)
      await control.send(ROLE, base('snapshot', START_PHASE))
      await drained
      trace({ event: 'drained', phaseSequence: String(START_PHASE) })
    }

    const closedEvent = control.expect(ROLE, 'closed', GENERATION)
    const finalSnapshot = control.expect(ROLE, 'snapshot', GENERATION)
    const exiting = control.expectExit(ROLE)
    control.setPhase(ROLE, GENERATION, STOP_PHASE)
    trace({ event: 'phase-advanced', from: String(START_PHASE), to: String(STOP_PHASE) })

    // The second hazard in the same window, and the reason the responder stop is worth
    // having even though it cannot close the window on its own: a grant answered after
    // the advance never reaches the wire, because coordinator.js:516 rejects
    // `observed.phaseSequence !== record.phaseSequence`. It throws SYNCHRONOUSLY, so the
    // suite's `await control.respondIsolatedGrant(...).catch(noop)` cannot catch it and
    // the throw escapes the responder's `.then(onFulfilled, noop)` as an unhandled
    // rejection - a worse failure than the mismatch it accompanies.
    if (delivered !== null) {
      try {
        control.respondIsolatedGrant(ROLE, delivered, b4a.alloc(137, 0x33))
        lateResponse = 'accepted'
      } catch (err) {
        lateResponse = (err && err.code) || 'threw'
      }
      trace({ event: 'late-grant-response', outcome: lateResponse })
    }

    await control.send(ROLE, base('stop', STOP_PHASE))
    // Models the coordinator's next read of the pipe. In the stale arm the held frame
    // has not been read until here; in the drained arm it was read above.
    role.deliver()
    await finalSnapshot
    await closedEvent
    await exiting
  } catch (err) {
    failure = err
  }

  await settle()
  await control.close().catch(() => {})
  trace({
    event: 'arm-end',
    order,
    failure: failure === null ? null : failure.message,
    deliveredRequest: delivered === null ? null : String(delivered.phaseSequence)
  })
  return { failure, delivered, lateResponse }
}

async function main() {
  const results = {}
  for (const order of ['control', 'stale', 'drained']) {
    results[order] = await runArm(order)
  }

  const staleFailure = results.stale.failure
  const drainedFailure = results.drained.failure
  const staleReproduced =
    staleFailure !== null &&
    /^PROCESS_PHASE_MISMATCH \(lookup-exit-a\/CONTROL\)/.test(staleFailure.message)

  const stale = traced.find(
    (line) =>
      line.event === 'frame' &&
      line.direction === 'role->coordinator' &&
      line.type === 'isolated-grant-request'
  )

  process.stdout.write(
    [
      '',
      `control arm : ${results.control.failure === null ? 'no failure' : results.control.failure.message}`,
      `stale arm   : ${staleFailure === null ? 'no failure' : staleFailure.message}`,
      `drained arm : ${drainedFailure === null ? 'no failure' : drainedFailure.message}`,
      `stale frame : ${JSON.stringify(stale)}`,
      `request delivered in drained arm at phase ${results.drained.delivered === null ? 'never' : String(results.drained.delivered.phaseSequence)}`,
      `grant answered after the advance: ${results.drained.lateResponse}`,
      '',
      `CONTROL ARM ${results.control.failure === null ? 'CLEAN, so the advance alone is harmless' : 'DIRTY, so this probe proves nothing'}`,
      `PROVOCATION ${staleReproduced ? 'REPRODUCED' : 'DID NOT REPRODUCE'} on the shipped order`,
      `FIXED ORDER ${drainedFailure === null && results.drained.delivered !== null ? 'CLEAN' : 'NOT CLEAN'}`,
      ''
    ].join('\n')
  )

  if (!staleReproduced) process.exitCode = 2
  else if (drainedFailure !== null || results.drained.delivered === null) process.exitCode = 3
}

main().then(
  () => {},
  (err) => {
    process.stderr.write(`${(err && err.stack) || String(err)}\n`)
    process.exitCode = 1
  }
)
