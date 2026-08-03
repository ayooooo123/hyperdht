'use strict'

const test = require('brittle')
const b4a = require('b4a')
const { digestTestIsolatedAddressTuple } = require('../../lib/private/dht-exit-test-topology-grant')
const { deriveDhtExitPeerId } = require('../../lib/private/dht-exit-destination-table')

const { createProcessConfigAuditor } = require('./process/config-auditor')
const { CODEC_VECTOR_DIGEST_HEX } = require('./process/codec-vectors')
const { createProcessControl, spawnRoleProcesses } = require('./process/coordinator')
const {
  PROCESS_PLANS,
  ROLES,
  TEST_ONLY_PROCESS_TOPOLOGY_ISSUER,
  createLiveProcessTopology
} = require('./process/topology-fixture')

function capabilities(seed) {
  return {
    clocks: TEST_ONLY_PROCESS_TOPOLOGY_ISSUER.clocks({
      monotonicNow: () => BigInt(Date.now()),
      wallNow: () => BigInt(Date.now())
    }),
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
    const topology = createLiveProcessTopology({
      plan,
      ...capabilities(launch.runtime === 'node' ? 0x31 : 0x32)
    })
    const placement = launch.createPlacement ? launch.createPlacement(topology) : null
    const auditor = createProcessConfigAuditor(topology.oracle)
    auditor.auditAll(topology.projections)
    const children = spawnRoleProcesses(launch.runtime, topology.projections, {
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

      for (const role of ['dht-value', 'dht-referral', 'dht-seed']) {
        const ready = await sendAndWait(role, 'activate', 'ready')
        t.is(ready.state, 'DHT_SETUP', `${role} binds in ordered DHT setup`)
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

      // Every exit asks for a learned-closer grant whenever it discovers an isolated
      // candidate, and a branch rebuild can repeat that at a moment the scenario does
      // not drive. Keep a standing responder per exit: it answers with the grant that
      // matches the requested digest and asserts the lookup exits' first request.
      learnedGrantResponders = ['lookup-exit-a', 'lookup-exit-b', 'announce-exit'].map((role) => {
        const exitProjection = projectionFor(role)
        const learnedCandidates = [
          ['dht-referral', exitProjection.learnedReferralGrants],
          ['dht-value', exitProjection.learnedValueGrants],
          ['dht-seed', exitProjection.learnedSeedGrants]
        ].map(([candidateRole, pools]) => {
          const candidateProjection = projectionFor(candidateRole)
          const id = deriveDhtExitPeerId(candidateProjection.bind)
          const digestForGen = (gen) =>
            digestTestIsolatedAddressTuple({
              tuple: candidateProjection.bind,
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
        const state = { first: null, resolveFirst: null, stopped: false, waiter: null }
        state.firstRequest = new Promise((resolve) => {
          state.resolveFirst = resolve
        })
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
            arm()
            const allCandidates = learnedCandidates.flatMap((pools) => Object.values(pools))
            const learned = allCandidates.find(
              (candidate) =>
                candidate.candidateRole !== 'dht-seed' &&
                request.tupleDigest.equals(candidate.digest)
            )
            const granted = allCandidates.find((candidate) =>
              request.tupleDigest.equals(candidate.digest)
            )
            if (state.first === null) {
              state.first = request
              t.ok(
                learned !== undefined,
                `${role} requests a learned closer discovered through its configured seed`
              )
              t.absent(
                request.tupleDigest.equals(seedDigest),
                `${role} does not request its configured seed grant`
              )
              t.is(request.requestSequence, 1n, `${role} configured seed used no grant request`)
              state.resolveFirst(request)
            }
            if (granted === undefined || granted.used >= granted.grants.length) return
            const grant = granted.grants[granted.used++]
            await control.respondIsolatedGrant(role, request, grant).catch(noop)
          }, noop)
        }
        arm()
        return {
          role,
          firstRequest: state.firstRequest,
          stop() {
            state.stopped = true
            for (const pools of learnedCandidates) {
              for (const candidate of Object.values(pools)) candidate.digest.fill(0)
            }
            seedDigest.fill(0)
          }
        }
      })
      const isolatedGrantResponses = new Map(
        learnedGrantResponders.map((responder) => [responder.role, responder.firstRequest])
      )

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
      t.is(
        (await isolatedGrantResponses.get('lookup-exit-a')).requestSequence,
        1n,
        'lookup A consumes one learned closer grant'
      )

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

      const rotatePhase = nextPhase('endpoint')
      phases.set('endpoint', rotatePhase)
      generations.set('endpoint', 2n)
      const rotationEvent = control.expectEvent('endpoint', 'rotated', 2n, rotatePhase)
      const faultAcknowledged = await sendAndWait('lookup-middle-a', 'rotate', 'ready', {
        nextGeneration: 2n
      })
      t.is(faultAcknowledged.state, 'READY', 'lookup A physical link fault is acknowledged')
      const rotated = await rotationEvent
      t.is(rotated.previousGeneration, endpointGeneration)
      const secondValueWaiting = control.expect('endpoint', 'value', 2n)
      await control.send(
        'endpoint',
        command('endpoint', 'immutable-get', rotatePhase, { target: topology.oracle.targetHash })
      )
      t.ok((await secondValueWaiting).value.equals(topology.oracle.immutableValue))
      t.is(
        (await isolatedGrantResponses.get('lookup-exit-b')).requestSequence,
        1n,
        'lookup B consumes one learned closer grant after physical rotation'
      )
      const exitSnapshots = new Map()
      for (const role of ['lookup-exit-a', 'lookup-exit-b', 'announce-exit']) {
        exitSnapshots.set(role, await sendAndWait(role, 'snapshot', 'snapshot'))
      }
      for (const role of ['lookup-exit-a', 'lookup-exit-b']) {
        const snapshot = exitSnapshots.get(role)
        t.ok(snapshot.referralProbeCount >= 1, `${role} probes an admitted referral`)
        t.ok(snapshot.ordinaryRequestCount >= 2, `${role} sends seed and referral requests`)
        t.ok(snapshot.tableEntryCount >= 2, `${role} retains seed and admitted referral`)
      }
      const announceSnapshot = exitSnapshots.get('announce-exit')
      t.is(announceSnapshot.ordinaryRequestCount, 0, 'announce transports no application request')
      t.is(announceSnapshot.referralProbeCount, 0, 'announce probes no application referral')
      const rotatedEndpointSnapshot = await sendAndWait('endpoint', 'snapshot', 'snapshot')
      t.is(rotatedEndpointSnapshot.guardOnly, true)
      t.ok(
        rotatedEndpointSnapshot.lookupGeneration > readyEndpointSnapshot.lookupGeneration,
        'physical lookup A fault publishes a fresh lookup B generation'
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
      const exits = []
      const snapshots = []
      const closed = []
      for (const role of ROLES) {
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
      t.fail(err && typeof err.code === 'string' ? err.code : String(err))
    } finally {
      for (const responder of learnedGrantResponders) responder.stop()
      if (!control.closed) await control.cancel('TEARDOWN').catch(() => {})
      if (placement) placement.teardown()
      topology.stop()
    }
  })
}

module.exports = registerLiveProcessSuite
