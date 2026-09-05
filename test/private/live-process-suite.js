'use strict'

const test = require('brittle')
const { hrtime } = require('process')
const b4a = require('b4a')
const { digestTestIsolatedAddressTuple } = require('../../lib/private/dht-exit-test-topology-grant')
const { deriveDhtExitPeerId } = require('../../lib/private/dht-exit-destination-table')

const { createCoherentTestClock } = require('./coherent-clock')
const { createProcessConfigAuditor } = require('./process/config-auditor')
const { CODEC_VECTOR_DIGEST_HEX } = require('./process/codec-vectors')
const { createProcessControl, spawnRoleProcesses } = require('./process/coordinator')
const { LINK_UNRESPONSIVE_AFTER } = require('../../lib/private/link-control-session')
const {
  PROCESS_PLANS,
  ROLES,
  TEST_ONLY_PROCESS_TOPOLOGY_ISSUER,
  createLiveProcessTopology
} = require('./process/topology-fixture')

const HEALTHY_SILENCE_MS = LINK_UNRESPONSIVE_AFTER + 500
const BLACKHOLE_ROTATION_BOUND_MS = LINK_UNRESPONSIVE_AFTER + 3_500

function capabilities(seed) {
  return {
    clocks: TEST_ONLY_PROCESS_TOPOLOGY_ISSUER.clocks(createCoherentTestClock()),
    entropy: TEST_ONLY_PROCESS_TOPOLOGY_ISSUER.entropy(b4a.alloc(32, seed))
  }
}

function base(projection, type, phaseSequence, generation = projection.generation) {
  return {
    generation,
    phaseSequence,
    role: projection.role,
    roleIndex: projection.roleIndex,
    type
  }
}

function noop() {}

// A role's reachable address: the one peers dial, and the one every isolated-address
// digest is keyed on, because a closer is discovered over the wire and a peer appears
// there at the address it published. topology-fixture.js:1030 mints the learned-grant
// pools from exactly this tuple. A derived plan binds what it publishes, so the two are
// the same address there; a discovered topology carries the published tuples in the
// projection because no role can compute another's.
function reachableTupleFor(projection) {
  if (!projection.meshPeers) return projection.bind
  return projection.meshPeers.tuples[projection.roleIndex - 1]
}

function registerLiveProcessSuite(launch) {
  if (
    !launch ||
    (launch.runtime !== 'node' && launch.runtime !== 'bare') ||
    typeof launch.runtimeVersion !== 'string'
  ) {
    throw new Error('invalid runtime launch record')
  }

  // `launch.placement` lets a caller run the same scenario somewhere other than
  // portable loopback, such as one network namespace per role, and inspect what
  // crossed the wire afterwards. Portable runs pass `null` and are unaffected.
  const plan = launch.plan || PROCESS_PLANS.PORTABLE_LOOPBACK
  const label = launch.label ? ` on ${launch.label}` : ''

  test(`live private route lifecycle in eleven ${launch.runtime} role processes${label}`, async (t) => {
    // `launch.prepare` lets the roles live somewhere this process cannot spawn
    // them. It returns the addresses each role discovered for itself, which the
    // topology is then minted from, and a way to open their control channels. The
    // scenario below is identical either way: same protocol, same auditing.
    const prepared = launch.prepare ? await launch.prepare(t) : null
    const candidateOrder = process.env.PR_CANDIDATE_ORDER || 'normal'
    const topology = createLiveProcessTopology({
      candidateOrder,
      plan,
      ...(prepared && prepared.endpoints ? { endpoints: prepared.endpoints } : {}),
      ...capabilities(launch.runtime === 'node' ? 0x31 : 0x32)
    })
    const placement = launch.createPlacement ? launch.createPlacement(topology) : null
    const auditor = createProcessConfigAuditor(topology.oracle)
    auditor.auditAll(topology.projections)
    const children =
      prepared && prepared.openChannels
        ? await prepared.openChannels(topology.projections)
        : spawnRoleProcesses(launch.runtime, topology.projections, {
            enter: placement ? placement.enter : undefined,
            nodePath: launch.nodePath
          })
    const control = createProcessControl({ auditor, children })
    const phases = new Map(ROLES.map((role) => [role, 1n]))
    const generations = new Map(
      topology.projections.map((projection) => [projection.role, projection.generation])
    )
    const projectionFor = (role) => topology.projections[ROLES.indexOf(role)]
    const codecVectorDigest = b4a.from(CODEC_VECTOR_DIGEST_HEX, 'hex')

    function nextPhase(role) {
      const value = phases.get(role) + 1n
      phases.set(role, value)
      return value
    }

    function command(role, type, phaseSequence, fields = {}) {
      const projection = projectionFor(role)
      return {
        ...base(projection, type, phaseSequence, generations.get(role)),
        ...fields
      }
    }

    async function sendAndWait(role, type, eventType, fields = {}, phase = null) {
      const generation = generations.get(role)
      const phaseSequence = phase === null ? nextPhase(role) : phase
      phases.set(role, phaseSequence)
      control.setPhase(role, generation, phaseSequence)
      const waiting = control.expect(role, eventType, generation)
      await control.send(role, command(role, type, phaseSequence, fields))
      return waiting
    }

    const middleRoles = ROLES.filter((role) => role.includes('-middle'))
    const exitRoles = ROLES.filter((role) => role.includes('-exit'))

    async function routingSnapshots() {
      const snapshots = new Map()
      for (const role of [...middleRoles, ...exitRoles]) {
        snapshots.set(role, await sendAndWait(role, 'snapshot', 'snapshot'))
      }
      return snapshots
    }

    function deriveRoutingState(snapshots, previousExitCounts = null) {
      const activePairs = []
      for (const middleRole of middleRoles) {
        const middle = snapshots.get(middleRole)
        if (middle.selectedExitRoleIndex === null) continue
        const exitRole = ROLES[middle.selectedExitRoleIndex - 1]
        const exit = snapshots.get(exitRole)
        t.is(
          exit.selectedMiddleRoleIndex,
          middle.roleIndex,
          `${middleRole} and ${exitRole} report a reciprocal active relationship`
        )
        activePairs.push({ exitRole, middleRole })
      }
      const lookupPair = activePairs.find(({ exitRole }) => {
        const count = snapshots.get(exitRole).ordinaryRequestCount
        return previousExitCounts === null ? count > 0 : count > previousExitCounts.get(exitRole)
      })
      if (lookupPair === undefined) throw new Error('active lookup pair unavailable')
      const announcePair = activePairs.find((pair) => pair !== lookupPair)
      if (announcePair === undefined) throw new Error('active announce pair unavailable')
      return {
        activePairs,
        announcePair,
        lookupPair,
        standbyExits: exitRoles.filter(
          (role) => !activePairs.some((pair) => pair.exitRole === role)
        ),
        standbyMiddles: middleRoles.filter(
          (role) => !activePairs.some((pair) => pair.middleRole === role)
        )
      }
    }

    function assertOptionalGrantUsage(snapshot, role, stage) {
      const responder = learnedGrantResponders.find((candidate) => candidate.role === role)
      const observed = responder === undefined ? -1 : responder.observedCount()
      const count = snapshot.isolatedGrantRequestCount
      t.ok(
        Number.isSafeInteger(count) && count === observed && count >= 0 && count <= 18,
        `${role} matches coordinator-observed grant requests during ${stage}`
      )
      t.is(snapshot.pendingGrantRequests, 0, `${role} leaves no grant request pending`)
      t.ok(snapshot.ordinaryRequestCount >= 1, `${role} sends the immutable request`)
    }

    let learnedGrantResponders = []

    try {
      const configured = []
      for (let index = 0; index < topology.projections.length; index++) {
        const projection = topology.projections[index]
        const waiting = control.expect(projection.role, 'configured', projection.generation)
        await control.send(projection.role, {
          ...base(projection, 'configure', 1n),
          codecVectorDigest,
          projection: topology.oracle.projectionBytes[index],
          run: projection.run,
          runtime: launch.runtime,
          runtimeVersion: launch.runtimeVersion
        })
        configured.push(waiting)
      }
      const configuredEvents = await Promise.all(configured)
      t.is(configuredEvents.length, 11, 'all roles attest runtime, UDX and codec vector')

      const prepared = await Promise.all(
        ROLES.map((role) => sendAndWait(role, 'prepare', 'prepared'))
      )
      t.is(prepared.length, 11, 'all roles bind before ordered DHT setup')

      // t.is(ready.state, ...) alone is not a gate: role-runner sets that state
      // unconditionally after dht.ready(), and dht.ready() resolves on a network
      // where nothing was ever answered - a bootstrap query counts a request
      // timeout and continues, and _bootstrapping is additionally caught. So also
      // require a request to have been ANSWERED, for the roles that must have had
      // one. Activation runs value first, then referral, then seed, which is the
      // reverse of the fixture's one-way DHT edges (topology-fixture.js gives seed
      // nodes:[referral], referral nodes:[value], value nodes:[] with bootstrap
      // pointing at value's OWN tuple): each of referral and seed activates after
      // the single peer it dials is up, so each MUST have been answered by it, and
      // measures 0 answered with 1 timeout when that peer is deaf.
      //
      // dht-value is deliberately NOT asserted. It activates first, with nothing
      // else running, and its only bootstrap address is itself - so it answers its
      // own query and reports a non-zero count on a completely dead network.
      // Asserting it would re-add exactly the assertion-that-cannot-fail this
      // replaces.
      const mustBeAnswered = new Set(['dht-referral', 'dht-seed'])
      for (const role of ['dht-value', 'dht-referral', 'dht-seed']) {
        const ready = await sendAndWait(role, 'activate', 'ready')
        t.is(ready.state, 'DHT_SETUP', `${role} binds in ordered DHT setup`)
        if (mustBeAnswered.has(role)) {
          t.ok(
            ready.answeredRequestCount > 0,
            `${role} had a DHT request answered in ordered DHT setup`
          )
        }
      }

      const preStoreSnapshots = []
      for (const role of ['dht-seed', 'dht-referral', 'dht-value']) {
        const snapshot = await sendAndWait(role, 'snapshot', 'snapshot')
        preStoreSnapshots.push(snapshot)
        t.is(snapshot.storedValueCount, 0, `${role} has no value before setup store`)
      }
      t.is(preStoreSnapshots[1].transientValueBytes, 0)
      t.ok(preStoreSnapshots[2].storedValueDigest.equals(b4a.alloc(32)))

      const referral = projectionFor('dht-referral')
      const referralGeneration = generations.get('dht-referral')
      const setupPhase = nextPhase('dht-referral')
      phases.set('dht-referral', setupPhase)
      control.setPhase('dht-referral', referralGeneration, setupPhase)
      const opens = control.expectMany('dht-referral', 'audit-open', referralGeneration, 3)
      const closes = control.expectMany('dht-referral', 'audit-close', referralGeneration, 3)
      const stored = control.expect('dht-referral', 'stored', referralGeneration)
      await control.send('dht-referral', {
        ...base(referral, 'store-immutable', setupPhase, referralGeneration),
        value: topology.oracle.immutableValue
      })
      const [openEvents, closeEvents, storedEvent] = await Promise.all([opens, closes, stored])
      t.alike(
        openEvents.map((entry) => entry.class),
        [3, 4, 5],
        'setup opens token, put and readback only'
      )
      t.alike(
        closeEvents.map((entry) => entry.class),
        [3, 4, 5],
        'setup closes token, put and readback only'
      )
      t.ok(storedEvent.valueDigest.equals(topology.oracle.targetHash))
      t.alike(
        storedEvent.setupAuditSequences,
        closeEvents.map((entry) => entry.recordSequence)
      )
      t.alike(
        storedEvent.setupAuditDigests,
        closeEvents.map((entry) => entry.recordDigest)
      )

      const afterStore = []
      for (const role of ['dht-seed', 'dht-referral', 'dht-value']) {
        afterStore.push(await sendAndWait(role, 'snapshot', 'snapshot'))
      }
      t.is(afterStore[0].storedValueCount, 0, 'seed stores no value')
      t.is(afterStore[1].storedValueCount, 0, 'referral stores no value')
      t.is(afterStore[1].transientValueBytes, 0, 'referral clears transient value bytes')
      t.is(afterStore[2].storedValueCount, 1, 'value role stores exactly one value')
      t.ok(afterStore[2].storedValueDigest.equals(topology.oracle.targetHash))

      // An exit MAY ask for a learned-closer grant when discovery returns an isolated
      // candidate. Real DHT ordering can also return the value directly, in which case
      // no request exists. Keep a standing responder for requests that do arrive, but
      // never make an optional discovery event a prerequisite for scenario progress.
      learnedGrantResponders = ['lookup-exit-a', 'lookup-exit-b', 'announce-exit'].map((role) => {
        const exitProjection = projectionFor(role)
        const learnedCandidates = [
          ['dht-referral', exitProjection.learnedReferralGrants],
          ['dht-value', exitProjection.learnedValueGrants],
          ['dht-seed', exitProjection.learnedSeedGrants]
        ].map(([candidateRole, pools]) => {
          const candidateProjection = projectionFor(candidateRole)
          const candidateTuple = reachableTupleFor(candidateProjection)
          const id = deriveDhtExitPeerId(candidateTuple)
          const digestForGen = (gen) =>
            digestTestIsolatedAddressTuple({
              tuple: candidateTuple,
              id,
              exitRole: exitProjection.roleIndex,
              generation: BigInt(gen)
            })
          const candidatesByGen = {}
          for (const [gen, grants] of Object.entries(pools)) {
            candidatesByGen[gen] = { candidateRole, digest: digestForGen(gen), grants, used: 0 }
          }
          id.fill(0)
          // Each grant is one-shot and a rebuilt branch rediscovers the same closer,
          // so every request for this digest spends the next grant in the pool. The
          // exit derives the candidate id from its tuple, so a rediscovered seed has a
          // different digest than the configured `initialSeedGrant` it already holds.
          return candidatesByGen
        })
        const seedDigest = digestTestIsolatedAddressTuple({
          tuple: exitProjection.dhtSeed,
          id: exitProjection.dhtSeedId,
          exitRole: exitProjection.roleIndex,
          generation: exitProjection.generation
        })
        const state = {
          granting: true,
          observedCount: 0,
          stopped: false,
          waiter: null
        }
        const arm = () => {
          if (state.stopped || control.closed) return
          let waiter
          try {
            waiter = control.expectOptional(
              role,
              'isolated-grant-request',
              exitProjection.generation
            )
          } catch {
            return
          }
          state.waiter = waiter
          waiter.promise.then(async (request) => {
            state.waiter = null
            const allCandidates = learnedCandidates.flatMap((pools) => Object.values(pools))
            const learned = allCandidates.find(
              (candidate) =>
                candidate.candidateRole !== 'dht-seed' &&
                request.tupleDigest.equals(candidate.digest)
            )
            const granted = allCandidates.find((candidate) =>
              request.tupleDigest.equals(candidate.digest)
            )
            const expectedSequence = BigInt(state.observedCount + 1)
            const valid =
              request.requestSequence === expectedSequence &&
              granted !== undefined &&
              !request.tupleDigest.equals(seedDigest) &&
              (state.observedCount !== 0 || learned !== undefined)
            if (!valid) {
              arm()
              return
            }
            state.observedCount++
            arm()
            if (!state.granting || granted.used >= granted.grants.length) return
            const grant = granted.grants[granted.used++]
            // `respondIsolatedGrant` throws SYNCHRONOUSLY when the role's expected phase
            // has moved since the request was observed, coordinator.js:516. A `.catch` on
            // its return value never sees that throw, and the throw then escapes this
            // handler - `.then(onFulfilled, noop)` handles the SOURCE promise's rejection,
            // not its own handler's - so it lands as an unhandled rejection and takes the
            // whole run down. `stopGranting()` removes the reachable case; this keeps a
            // future one from being fatal.
            try {
              await control.respondIsolatedGrant(role, request, grant)
            } catch {}
          }, noop)
        }
        arm()
        return {
          role,
          observedCount() {
            return state.observedCount
          },
          // Stops ANSWERING, and deliberately not listening. The standing waiter has to
          // stay armed so a request that still arrives is tolerated rather than becoming
          // PROCESS_UNEXPECTED_EVENT, and `state.stopped` is what disarms re-arming, so
          // it stays with `stop()`.
          stopGranting() {
            state.granting = false
          },
          stop() {
            state.stopped = true
            state.granting = false
            for (const pools of learnedCandidates) {
              for (const candidate of Object.values(pools)) candidate.digest.fill(0)
            }
            seedDigest.fill(0)
          }
        }
      })

      for (const role of ROLES.slice(0, 8).reverse()) {
        const ready = await sendAndWait(role, 'activate', 'ready')
        t.is(ready.state, 'READY', `${role} activates after DHT setup`)
      }
      const readyEndpointSnapshot = await sendAndWait('endpoint', 'snapshot', 'snapshot')
      t.is(readyEndpointSnapshot.guardOnly, true, 'endpoint semantic edge is guard-only')
      t.is(
        readyEndpointSnapshot.endpointSockets,
        0,
        'endpoint retains no bootstrap socket after guard pinning transfers it to the route'
      )
      t.ok(readyEndpointSnapshot.lookupGeneration !== null)
      t.ok(readyEndpointSnapshot.announceGeneration !== null)

      const endpointGeneration = generations.get('endpoint')
      const valueWaiting = control.expect('endpoint', 'value', endpointGeneration)
      await control.send(
        'endpoint',
        command('endpoint', 'immutable-get', phases.get('endpoint'), {
          target: topology.oracle.targetHash
        })
      )
      const firstValue = await valueWaiting
      t.ok(firstValue.target.equals(topology.oracle.targetHash))
      t.ok(firstValue.value.equals(topology.oracle.immutableValue), 'first immutable get is exact')
      const firstRoutingSnapshots = await routingSnapshots()
      const initialRouting = deriveRoutingState(firstRoutingSnapshots)
      const initialLookupExit = firstRoutingSnapshots.get(initialRouting.lookupPair.exitRole)
      assertOptionalGrantUsage(
        initialLookupExit,
        initialRouting.lookupPair.exitRole,
        'initial lookup'
      )
      t.comment(
        `candidate-order=${candidateOrder} initial lookup=${initialRouting.lookupPair.middleRole}->${initialRouting.lookupPair.exitRole} ` +
          `announce=${initialRouting.announcePair.middleRole}->${initialRouting.announcePair.exitRole}`
      )
      const firstExitCounts = new Map(
        exitRoles.map((role) => [role, firstRoutingSnapshots.get(role).ordinaryRequestCount])
      )
      t.is(initialRouting.standbyExits.length, 1, 'one exit is inactive standby')
      t.is(initialRouting.standbyMiddles.length, 1, 'one middle is inactive standby')
      const cancelPhase = nextPhase('endpoint')
      phases.set('endpoint', cancelPhase)
      control.setPhase('endpoint', endpointGeneration, cancelPhase)
      await control.send(
        'endpoint',
        command('endpoint', 'immutable-get', cancelPhase, { target: topology.oracle.targetHash })
      )
      const cancelled = control.expect('endpoint', 'cancelled', endpointGeneration)
      await control.send(
        'endpoint',
        command('endpoint', 'cancel', cancelPhase, { operationSequence: 2n })
      )
      t.is((await cancelled).operationSequence, 2n, 'delayed lookup cancels without retry')

      const healthyGeneration = readyEndpointSnapshot.lookupGeneration
      await new Promise((resolve) => setTimeout(resolve, HEALTHY_SILENCE_MS))
      const healthySnapshot = await sendAndWait('endpoint', 'snapshot', 'snapshot')
      t.is(
        healthySnapshot.lookupGeneration,
        healthyGeneration,
        'healthy silent lookup branch survives the native detector window'
      )
      t.is(
        healthySnapshot.announceGeneration,
        readyEndpointSnapshot.announceGeneration,
        'healthy silent announce branch survives the native detector window'
      )

      const rotatePhase = nextPhase('endpoint')
      phases.set('endpoint', rotatePhase)
      generations.set('endpoint', 2n)
      const rotationEvent = control.expectEvent('endpoint', 'rotated', 2n, rotatePhase)
      const blackholeStartedAt = hrtime.bigint()
      const faultAcknowledged = await sendAndWait(
        initialRouting.lookupPair.middleRole,
        'blackhole',
        'ready'
      )
      t.is(
        faultAcknowledged.state,
        'READY',
        `${initialRouting.lookupPair.middleRole} silently drops route cells`
      )
      const rotated = await rotationEvent
      t.is(rotated.previousGeneration, endpointGeneration)
      t.ok(
        hrtime.bigint() - blackholeStartedAt <= BigInt(BLACKHOLE_ROTATION_BOUND_MS) * 1_000_000n,
        'native detector rotates the blackholed branch within the process deadline'
      )
      const secondValueWaiting = control.expect('endpoint', 'value', 2n)
      await control.send(
        'endpoint',
        command('endpoint', 'immutable-get', rotatePhase, { target: topology.oracle.targetHash })
      )
      t.ok((await secondValueWaiting).value.equals(topology.oracle.immutableValue))
      const rotatedRoutingSnapshots = await routingSnapshots()
      const rotatedRouting = deriveRoutingState(rotatedRoutingSnapshots, firstExitCounts)
      t.comment(
        `candidate-order=${candidateOrder} rotated lookup=${rotatedRouting.lookupPair.middleRole}->${rotatedRouting.lookupPair.exitRole} ` +
          `announce=${rotatedRouting.announcePair.middleRole}->${rotatedRouting.announcePair.exitRole}`
      )
      t.not(
        `${rotatedRouting.lookupPair.middleRole}->${rotatedRouting.lookupPair.exitRole}`,
        `${initialRouting.lookupPair.middleRole}->${initialRouting.lookupPair.exitRole}`,
        'rotation changes the active lookup pair'
      )
      assertOptionalGrantUsage(
        rotatedRoutingSnapshots.get(rotatedRouting.lookupPair.exitRole),
        rotatedRouting.lookupPair.exitRole,
        'lookup after rotation'
      )
      for (const role of [initialRouting.lookupPair.exitRole, rotatedRouting.lookupPair.exitRole]) {
        const snapshot = rotatedRoutingSnapshots.get(role)
        t.ok(
          (snapshot.ordinaryRequestCount === 0 &&
            snapshot.tableEntryCount === 0 &&
            snapshot.referralProbeCount === 0) ||
            (snapshot.ordinaryRequestCount >= 1 && snapshot.tableEntryCount >= 1),
          `${role} is either retired cleanly or retains admitted request state`
        )
      }
      const announceSnapshot = rotatedRoutingSnapshots.get(rotatedRouting.announcePair.exitRole)
      const announceGrantResponder = learnedGrantResponders.find(
        (responder) => responder.role === rotatedRouting.announcePair.exitRole
      )
      t.is(
        announceGrantResponder.observedCount(),
        0,
        'coordinator observes no grant request on the state-derived announce exit'
      )
      t.is(announceSnapshot.isolatedGrantRequestCount, 0, 'announce reports no grant request')
      t.is(announceSnapshot.ordinaryRequestCount, 0, 'announce transports no application request')
      t.is(announceSnapshot.referralProbeCount, 0, 'announce probes no application referral')
      t.is(rotatedRouting.standbyExits.length, 1, 'rotation leaves one inactive exit standby')
      t.is(rotatedRouting.standbyMiddles.length, 1, 'rotation leaves one inactive middle standby')
      const rotatedEndpointSnapshot = await sendAndWait('endpoint', 'snapshot', 'snapshot')
      t.is(rotatedEndpointSnapshot.guardOnly, true)
      t.ok(
        rotatedEndpointSnapshot.lookupGeneration > readyEndpointSnapshot.lookupGeneration,
        `physical ${initialRouting.lookupPair.middleRole} fault publishes a fresh lookup generation`
      )
      t.is(
        rotatedEndpointSnapshot.announceGeneration,
        healthySnapshot.announceGeneration,
        'blackholed lookup replacement preserves the healthy announce generation'
      )

      const suspended = await sendAndWait('endpoint', 'suspend', 'suspended')
      t.is(suspended.type, 'suspended')
      const suspendedSnapshot = await sendAndWait('endpoint', 'snapshot', 'snapshot')
      t.is(suspendedSnapshot.activeOperations, 0)
      t.is(suspendedSnapshot.queuedBytes, 0)
      t.is(suspendedSnapshot.endpointSockets, 0, 'suspend closes endpoint socket ownership')
      t.is(suspendedSnapshot.guardOnly, false, 'suspend has no send-capable guard edge')
      const resumed = await sendAndWait('endpoint', 'resume', 'resumed')
      t.is(resumed.type, 'resumed')

      const resumedSnapshot = await sendAndWait('endpoint', 'snapshot', 'snapshot')
      t.is(resumedSnapshot.guardOnly, true, 'resume restores only the pinned guard edge')
      t.is(
        resumedSnapshot.endpointSockets,
        0,
        'resume transfers the reconnected bootstrap socket to the route'
      )
      t.ok(
        resumedSnapshot.lookupGeneration > rotatedEndpointSnapshot.lookupGeneration,
        'resume installs a fresh lookup generation'
      )
      t.ok(
        resumedSnapshot.announceGeneration > rotatedEndpointSnapshot.announceGeneration,
        'resume installs a fresh announce generation'
      )
      const resumedValueWaiting = control.expect('endpoint', 'value', 2n)
      await control.send(
        'endpoint',
        command('endpoint', 'immutable-get', phases.get('endpoint'), {
          target: topology.oracle.targetHash
        })
      )
      t.ok((await resumedValueWaiting).value.equals(topology.oracle.immutableValue))

      const unavailable = await sendAndWait('endpoint', 'network-change', 'unavailable')
      t.is(unavailable.reason, 'NETWORK_CHANGE')
      const networkChangedSnapshot = await sendAndWait('endpoint', 'snapshot', 'snapshot')
      t.is(networkChangedSnapshot.endpointSockets, 0, 'network change leaves no endpoint socket')
      t.is(networkChangedSnapshot.guardOnly, false, 'network change installs no fallback edge')
      // We cannot test guard-loss after network-change because network-change is terminal.
      // KI-11. Advancing a role's expected phase while one of that role's own events is
      // still unread makes the event stale: `baseMessage` compares the two phases for
      // exact equality, control-channel.js:964, and `dispatch` reports any validation
      // failure as PROCESS_PHASE_MISMATCH, coordinator.js:343-348. The exits are the only
      // roles that still speak unprompted by the time we get here - every other event in
      // the scenario answers a command, and the endpoint's autonomous `rotated` and
      // `unavailable` both need state READY, which the terminal network-change above left
      // as UNAVAILABLE - so the window is an `isolated-grant-request` overtaking the loop
      // below. Provoked deliberately, and shown closed, by
      // test/private/process/teardown-phase-window-probe.js.
      //
      // Stop ANSWERING first. This is hygiene, not the fix: the request is emitted by the
      // exit on its own schedule, so nothing done on this side can unsend a frame already
      // in the pipe. It earns its place for a different reason - a grant answered after
      // the advance throws synchronously out of `respondIsolatedGrant`, see the responder
      // above - and because an exit handed a grant mid-teardown restarts the very
      // discovery that emits the next request. Nothing below needs a grant responder:
      // the role snapshots above prove no request is pending, and the six grants per
      // pool cover any optional discovery during the completed lifecycle.
      // An unanswered request is expected on the role side too, `stopOwners` rejects a
      // pending one with PROCESS_CANCELLED before destroying the exit service,
      // role-runner.js:816-821, so it cannot wedge the stop below.
      for (const responder of learnedGrantResponders) responder.stopGranting()
      const exits = []
      const snapshots = []
      const closed = []
      for (const role of ROLES) {
        // The fix: a round trip at the phase already in force, which the runner accepts
        // because it adopts whatever phase a command carries, role-runner.js:968 - the
        // same reuse the two `immutable-get`s above rely on. A role's events reach us as
        // one FIFO stream decoded in order, so once this snapshot has been dispatched
        // every frame that role emitted earlier has been dispatched too, under the phase
        // it was emitted with. Only then is the phase advanced. What remains is one round
        // trip wide instead of the whole loop wide, and with granting stopped an exit that
        // does emit inside it cannot be given a grant and so cannot emit a second.
        await sendAndWait(role, 'snapshot', 'snapshot', {}, phases.get(role))
        const generation = generations.get(role)
        const stopPhase = nextPhase(role)
        control.setPhase(role, generation, stopPhase)
        snapshots.push(control.expect(role, 'snapshot', generation))
        closed.push(control.expect(role, 'closed', generation))
        exits.push(control.expectExit(role))
        await control.send(role, command(role, 'stop', stopPhase))
      }
      const finalSnapshots = await Promise.all(snapshots)
      await Promise.all(closed)
      const exitResults = await Promise.all(exits)
      for (const snapshot of finalSnapshots) {
        t.is(snapshot.state, 'CLOSED')
        t.is(snapshot.activeOperations, 0)
        t.is(snapshot.openResources, 0)
        t.is(snapshot.queuedBytes, 0)
      }
      for (const result of exitResults) t.is(result.code, 0)
      await control.close()
      // Every role has exited, so the capture is complete and the wire record
      // covers the whole lifecycle including the failure paths.
      if (placement) await placement.audit(t)
    } catch (err) {
      t.fail(err && err.message ? err.message : String(err))
    } finally {
      for (const responder of learnedGrantResponders) responder.stop()
      if (!control.closed) await control.cancel('TEARDOWN').catch(() => {})
      if (placement) placement.teardown()
      topology.stop()
    }
  })
}

module.exports = registerLiveProcessSuite
