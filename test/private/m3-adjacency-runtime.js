'use strict'

const test = require('brittle')
const b4a = require('b4a')

const {
  DatagramReplayWindow,
  OrderedReceiver,
  SenderCounter
} = require('../../lib/private/counters')
const guardLinks = require('../../lib/private/guard-link')
const { BRANCH_CLASS, CELL_CLASS } = require('../../lib/private/protocol')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  M3AdjacencyAuthority,
  TEST_ONLY_M3_ADJACENCY_OBSERVER,
  abortM3Install,
  beginM3Install,
  commitM3Install,
  consumeTailResponderToken,
  deriveM3CellIds,
  revokeM3TailCapability,
  revokeTailResponderToken,
  takeM3TailCapability,
  validateM3Install
} = require('../../lib/private/m3-adjacency-runtime')

function fakeClock({ wall = 1_000n, monotonic = 10_000n } = {}) {
  let currentWall = wall
  let currentMonotonic = monotonic
  let wallSamples = 0
  let monotonicSamples = 0
  let nextHandle = 0
  const delays = []
  const timers = new Map()
  const clock = {
    wallNow() {
      wallSamples++
      return currentWall
    },
    monotonicNow() {
      monotonicSamples++
      return currentMonotonic
    },
    schedule(callback, delay) {
      delays.push(delay)
      const handle = ++nextHandle
      timers.set(handle, { callback, at: currentMonotonic + BigInt(delay) })
      return handle
    },
    cancelScheduled(handle) {
      timers.delete(handle)
    },
    setWall(value) {
      currentWall = value
    },
    setMonotonic(value) {
      currentMonotonic = value
    },
    pending() {
      return timers.size
    },
    fireNext() {
      let selected = null
      for (const [handle, timer] of timers) {
        if (selected === null || timer.at < selected.timer.at) selected = { handle, timer }
      }
      if (selected === null) return false
      timers.delete(selected.handle)
      currentMonotonic = selected.timer.at
      selected.timer.callback()
      return true
    },
    get delays() {
      return delays
    },
    get wallSamples() {
      return wallSamples
    },
    get monotonicSamples() {
      return monotonicSamples
    }
  }
  return clock
}

function authority(clock, overrides = {}) {
  return new M3AdjacencyAuthority({
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled,
    crypto: cryptoSuite,
    ...overrides
  })
}

const TEST_ONLY_M3_ESTABLISHED_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-m3-established-issuer'
)
const OFFER_DIGEST = b4a.from(Array.from({ length: 32 }, (_, index) => index))

const MAX_TIMER_DELAY = 0x7fff_ffff
function channel() {
  let destroys = 0
  return {
    value: Object.freeze({
      destroy() {
        destroys++
      }
    }),
    get destroys() {
      return destroys
    }
  }
}

function forwardingFacade(destroy = () => {}) {
  return Object.freeze({
    diagnostics: () => Object.freeze({ state: 'FORWARDING' }),
    destroy
  })
}

function contexts(initiator) {
  const values = {}
  for (const cellClass of [CELL_CLASS.CONTROL, CELL_CLASS.STREAM, CELL_CLASS.DATAGRAM]) {
    const forwardKey = b4a.alloc(32, 0x10 + cellClass)
    const reverseKey = b4a.alloc(32, 0x20 + cellClass)
    const forwardNonce = b4a.alloc(16, 0x30 + cellClass)
    const reverseNonce = b4a.alloc(16, 0x40 + cellClass)
    values[cellClass] = {
      tx: {
        key: initiator ? forwardKey : reverseKey,
        noncePrefix: initiator ? forwardNonce : reverseNonce,
        counter: new SenderCounter()
      },
      rx: {
        key: initiator ? reverseKey : forwardKey,
        noncePrefix: initiator ? reverseNonce : forwardNonce,
        counter:
          cellClass === CELL_CLASS.DATAGRAM
            ? new DatagramReplayWindow({ window: 256 })
            : new OrderedReceiver({ window: 256, gapTimeout: 5_000, now: () => 1_000 })
      }
    }
  }
  return values
}

function syntheticLink(overrides = {}) {
  const initiator = overrides.initiator === undefined ? true : overrides.initiator
  const completeOfferDigest = b4a.from(overrides.completeOfferDigest || OFFER_DIGEST)
  const ids = deriveM3CellIds(completeOfferDigest, { crypto: cryptoSuite })
  const ownedChannel = overrides.channel || channel()
  const state = {
    initiator,
    completeOfferDigest,
    localId: initiator ? ids.initiatorCellId : ids.responderCellId,
    peerLocalId: initiator ? ids.responderCellId : ids.initiatorCellId,
    branchClass: overrides.branchClass === undefined ? BRANCH_CLASS.LOOKUP : overrides.branchClass,
    branchId: b4a.from(overrides.branchId || b4a.alloc(16, 0x41)),
    circuitId: b4a.from(overrides.circuitId || b4a.alloc(16, 0x42)),
    generation: overrides.generation === undefined ? 7n : overrides.generation,
    extensionIndex:
      overrides.extensionIndex === undefined ? (initiator ? 2 : 1) : overrides.extensionIndex,
    localIdentity: b4a.from(overrides.localIdentity || b4a.alloc(32, 0x51)),
    peerIdentity: b4a.from(overrides.peerIdentity || b4a.alloc(32, 0x52)),
    expiresAt: overrides.wireExpiresAt === undefined ? 10_000n : overrides.wireExpiresAt,
    contexts: contexts(initiator),
    physicalChannel: ownedChannel.value,
    clientTailEphemeralSecretKey: initiator ? b4a.alloc(32, 0x63) : null,
    tailControlTranscript: b4a.alloc(290, 0x64)
  }
  return {
    handle: guardLinks[TEST_ONLY_M3_ESTABLISHED_ISSUER].issue(state),
    channel: ownedChannel,
    state
  }
}

test('M3 authority requires separate wall, monotonic, scheduler, and canceller capabilities', (t) => {
  const clock = fakeClock()
  const owner = authority(clock)

  t.alike(owner.diagnostics(), { activeRuntimes: 0, maxRuntimes: 128 })
  t.is(clock.pending(), 0, 'construction does not arm a timer before a runtime exists')
  for (const name of ['wallNow', 'monotonicNow', 'schedule', 'cancelScheduled']) {
    t.exception(() => authority(clock, { [name]: null }), `${name} is exact and mandatory`)
  }
  t.exception(
    () => new M3AdjacencyAuthority({ now: clock.wallNow, crypto: cryptoSuite }),
    'the ambiguous single-clock option is rejected'
  )
})

test('adoption projects wire expiry once and moves one frozen actor-local deadline', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const transfer = syntheticLink({ wireExpiresAt: 1_250n })

  const adopted = owner.adopt(transfer.handle)
  t.is(clock.wallSamples, 1, 'wire expiry samples the adopting wall clock once')
  t.is(
    clock.monotonicSamples,
    2,
    'projection and publication liveness sample the monotonic clock once each'
  )
  t.alike(clock.delays, [250], 'the projected interval arms before adoption returns')
  t.is(clock.pending(), 1)

  const moved = takeM3TailCapability(adopted.tail, {
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow
  })
  t.ok(Object.isFrozen(moved.deadline))
  t.alike(Object.keys(moved.deadline).sort(), ['clockIdentity', 'localDeadline', 'wireExpiresAt'])
  t.is(moved.deadline.wireExpiresAt, 1_250n)
  t.is(moved.deadline.localDeadline, 10_250n)
  t.is(moved.deadline.clockIdentity.wallNow, clock.wallNow)
  t.is(moved.deadline.clockIdentity.monotonicNow, clock.monotonicNow)
  t.is(clock.wallSamples, 1, 'moving the tail never reprojects wall expiry')
  t.is(clock.monotonicSamples, 2, 'moving the tail adds no monotonic sample')

  adopted.runtime.destroy()
  revokeM3TailCapability(adopted.tail)
})

test('projection rejects invalid intervals, regressing clocks, and alternate identities', (t) => {
  for (const [name, clock, wireExpiresAt] of [
    ['non-positive interval', fakeClock(), 1_000n],
    ['local deadline overflow', fakeClock({ monotonic: 0xffff_ffff_ffff_ffffn }), 1_001n]
  ]) {
    const transfer = syntheticLink({ wireExpiresAt })
    t.exception(() => authority(clock).adopt(transfer.handle), name)
    t.is(transfer.channel.destroys, 1, `${name} destroys transferred state`)
    t.is(clock.pending(), 0, `${name} publishes no handle`)
  }

  const backwardWall = fakeClock()
  const wallOwner = authority(backwardWall)
  const firstWall = wallOwner.adopt(syntheticLink({ wireExpiresAt: 2_000n }).handle)
  firstWall.runtime.destroy()
  backwardWall.setWall(999n)
  const regressedWall = syntheticLink({ wireExpiresAt: 2_000n })
  t.exception(() => wallOwner.adopt(regressedWall.handle), 'backward wall time fails closed')
  t.is(regressedWall.channel.destroys, 1)

  const backwardMonotonic = fakeClock()
  const monotonicOwner = authority(backwardMonotonic)
  const firstMonotonic = monotonicOwner.adopt(syntheticLink({ wireExpiresAt: 2_000n }).handle)
  firstMonotonic.runtime.destroy()
  backwardMonotonic.setWall(1_001n)
  backwardMonotonic.setMonotonic(9_999n)
  const regressedMonotonic = syntheticLink({ wireExpiresAt: 2_000n })
  t.exception(
    () => monotonicOwner.adopt(regressedMonotonic.handle),
    'non-monotonic local time fails closed'
  )
  t.is(regressedMonotonic.channel.destroys, 1)

  for (const [name, clocks] of [
    [
      'an alternate wall clock identity is rejected',
      (clock) => ({ wallNow: () => 1_000n, monotonicNow: clock.monotonicNow })
    ],
    [
      'an alternate monotonic clock identity is rejected',
      (clock) => ({ wallNow: clock.wallNow, monotonicNow: () => 10_000n })
    ]
  ]) {
    const exactClock = fakeClock()
    const adopted = authority(exactClock).adopt(syntheticLink({ wireExpiresAt: 2_000n }).handle)
    t.exception(() => takeM3TailCapability(adopted.tail, clocks(exactClock)), name)
    t.exception(
      () =>
        takeM3TailCapability(adopted.tail, {
          wallNow: exactClock.wallNow,
          monotonicNow: exactClock.monotonicNow
        }),
      `${name} consumes the mismatched capability`
    )
    adopted.runtime.destroy()
  }

  const exactClock = fakeClock()
  const adopted = authority(exactClock).adopt(syntheticLink({ wireExpiresAt: 2_000n }).handle)
  let nestedTake = null
  const reentrantClocks = {
    get wallNow() {
      try {
        nestedTake = takeM3TailCapability(adopted.tail, {
          wallNow: exactClock.wallNow,
          monotonicNow: exactClock.monotonicNow
        })
      } catch {}
      return exactClock.wallNow
    },
    monotonicNow: exactClock.monotonicNow
  }
  t.exception(
    () => takeM3TailCapability(adopted.tail, reentrantClocks),
    'accessor-backed clocks fail closed'
  )
  t.is(nestedTake, null, 'clock accessors cannot reenter one-shot tail consumption')
  adopted.runtime.destroy()
})

test('installed pair expiry consumes forwarding owner once and cancels both handles', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const previousLink = syntheticLink({ initiator: false, wireExpiresAt: 2_000n })
  const nextLink = syntheticLink({
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0x77),
    peerIdentity: b4a.alloc(32, 0x78),
    wireExpiresAt: 2_000n
  })
  const previous = owner.adopt(previousLink.handle)
  const next = owner.adopt(nextLink.handle)
  let destroys = 0
  const forwarding = forwardingFacade(() => {
    destroys++
  })
  const plan = beginM3Install(previous.runtime, next.runtime)
  t.ok(Object.isFrozen(plan), 'the install plan is opaque and frozen')
  t.alike(Object.keys(plan), [], 'the install plan exposes no runtime records')
  validateM3Install(plan, previousLink.state.localIdentity, 128, 1_000n)
  const installed = commitM3Install(plan, 2_000n, forwarding)
  t.ok(Object.isFrozen(installed), 'the installed facade is frozen')
  t.alike(Object.keys(installed), ['diagnostics', 'destroy'])

  t.is(clock.pending(), 2, 'both actor-local handles own the installed pair')
  t.is(clock.fireNext(), true, 'the first projected expiry fires')
  t.is(destroys, 1, 'the forwarding owner is consumed once')
  t.is(clock.pending(), 0, 'the first expiry cancels the sibling handle')
  t.is(previousLink.channel.destroys, 1)
  t.is(nextLink.channel.destroys, 1)
  t.is(clock.fireNext(), false, 'the cancelled sibling callback cannot fire')
  t.is(destroys, 1, 'a cancelled sibling cannot consume the owner again')
})

test('M3 authority rejects extra and accessor-backed capabilities before retention', (t) => {
  const clock = fakeClock()
  const options = {
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled,
    crypto: cryptoSuite
  }

  t.exception(
    () => new M3AdjacencyAuthority({ ...options, extra: true }),
    'extra capabilities are rejected'
  )

  let reads = 0
  const accessorOptions = {
    monotonicNow: clock.monotonicNow,
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled,
    crypto: cryptoSuite
  }
  Object.defineProperty(accessorOptions, 'wallNow', {
    enumerable: true,
    get() {
      reads++
      return clock.wallNow
    }
  })
  t.exception(
    () => new M3AdjacencyAuthority(accessorOptions),
    'accessor-backed capabilities are rejected'
  )
  t.is(reads, 0, 'the rejected accessor is never invoked')
})

test('adoption fails closed when timer publication cannot complete', (t) => {
  for (const mode of ['throw', 'missing', 'synchronous', 'reentrant-cancel']) {
    const clock = fakeClock()
    const transfer = syntheticLink({ wireExpiresAt: 2_000n })
    const secret = transfer.state.clientTailEphemeralSecretKey
    const transcript = transfer.state.tailControlTranscript
    let callback = null
    const overrides = {
      schedule(onExpiry) {
        callback = onExpiry
        if (mode === 'throw') throw new Error('injected schedule failure')
        if (mode === 'missing') return null
        if (mode === 'synchronous' || mode === 'reentrant-cancel') onExpiry()
        return 1
      },
      cancelScheduled() {
        if (mode === 'reentrant-cancel') callback()
      }
    }

    t.exception(() => authority(clock, overrides).adopt(transfer.handle), mode)
    t.is(transfer.channel.destroys, 1, `${mode} destroys unpublished state`)
    t.ok(b4a.equals(secret, b4a.alloc(secret.byteLength)), `${mode} clears the tail secret`)
    t.ok(
      b4a.equals(transcript, b4a.alloc(transcript.byteLength)),
      `${mode} clears the tail transcript`
    )
  }
})

test('a proactive actor-local expiry destroys an unpublished runtime and tail', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const transfer = syntheticLink({ wireExpiresAt: 1_250n })
  const adopted = authority(clock).adopt(transfer.handle)

  t.is(clock.pending(), 1)
  t.is(clock.fireNext(), true)
  t.is(clock.pending(), 0)
  t.is(transfer.channel.destroys, 1)
  t.is(adopted.runtime.destroy(), false, 'the expired runtime is already destroyed')
  t.is(revokeM3TailCapability(adopted.tail), false, 'expiry revokes the paired tail')
})

test('committing a shorter authenticated expiry rearms both installed runtimes', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const owner = authority(clock)
  const previousLink = syntheticLink({ initiator: false, wireExpiresAt: 2_000n })
  const nextLink = syntheticLink({
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0x79),
    peerIdentity: b4a.alloc(32, 0x7a),
    wireExpiresAt: 2_000n
  })
  const previous = owner.adopt(previousLink.handle)
  const next = owner.adopt(nextLink.handle)
  const forwarding = forwardingFacade()
  const plan = beginM3Install(previous.runtime, next.runtime)
  validateM3Install(plan, previousLink.state.localIdentity, 128, 1_000n)
  const installed = commitM3Install(plan, 1_500n, forwarding)

  t.alike(clock.delays, [1_000, 1_000, 500, 500], 'the shorter bound rearms both handles')
  t.is(clock.pending(), 2)
  t.is(clock.fireNext(), true)
  t.is(clock.pending(), 0)
  t.is(previousLink.channel.destroys, 1)
  t.is(nextLink.channel.destroys, 1)
})

test('long projected expiries are armed in platform-safe chunks', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const interval = BigInt(MAX_TIMER_DELAY) + 10n
  const transfer = syntheticLink({ wireExpiresAt: 1_000n + interval })
  const adopted = authority(clock).adopt(transfer.handle)

  t.alike(clock.delays, [MAX_TIMER_DELAY])
  t.is(clock.fireNext(), true)
  t.is(transfer.channel.destroys, 0, 'the first chunk does not expire early')
  t.alike(clock.delays, [MAX_TIMER_DELAY, 10])
  t.is(clock.pending(), 1)
  t.is(clock.fireNext(), true)
  t.is(transfer.channel.destroys, 1)
  t.is(adopted.runtime.destroy(), false)

  const hugeClock = fakeClock({ wall: 0n, monotonic: 0n })
  const hugeInterval = BigInt(Number.MAX_SAFE_INTEGER) + 1n
  const hugeTransfer = syntheticLink({ wireExpiresAt: hugeInterval })
  const huge = authority(hugeClock).adopt(hugeTransfer.handle)
  t.is(hugeClock.delays[0], MAX_TIMER_DELAY, 'u64-safe intervals above MAX_SAFE are chunked')
  huge.runtime.destroy()
  revokeM3TailCapability(huge.tail)
})

test('install rejects later, invalid, and already-consumed forwarding bounds', (t) => {
  const forwarding = forwardingFacade()
  const cases = [
    ['later wire expiry', 2_001n],
    ['zero wire expiry', 0n],
    ['non-integer wire expiry', 1_500]
  ]

  for (let index = 0; index < cases.length; index++) {
    const [name, expiresAt] = cases[index]
    const clock = fakeClock()
    const owner = authority(clock)
    const previousLink = syntheticLink({
      initiator: false,
      completeOfferDigest: b4a.alloc(32, 0x80 + index * 2),
      peerIdentity: b4a.alloc(32, 0x90 + index * 2),
      wireExpiresAt: 2_000n
    })
    const nextLink = syntheticLink({
      initiator: true,
      completeOfferDigest: b4a.alloc(32, 0x81 + index * 2),
      peerIdentity: b4a.alloc(32, 0x91 + index * 2),
      wireExpiresAt: 2_000n
    })
    const previous = owner.adopt(previousLink.handle)
    const next = owner.adopt(nextLink.handle)
    const plan = beginM3Install(previous.runtime, next.runtime)
    validateM3Install(plan, previousLink.state.localIdentity, 128, 1_000n)

    t.exception(() => commitM3Install(plan, expiresAt, forwarding), name)
    abortM3Install(plan)
    previous.runtime.destroy()
    next.runtime.destroy()
  }

  const clock = fakeClock()
  const owner = authority(clock)
  const firstPreviousLink = syntheticLink({ initiator: false, wireExpiresAt: 2_000n })
  const firstNextLink = syntheticLink({
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0xa0),
    peerIdentity: b4a.alloc(32, 0xa1),
    wireExpiresAt: 2_000n
  })
  const firstPrevious = owner.adopt(firstPreviousLink.handle)
  const firstNext = owner.adopt(firstNextLink.handle)
  let destroys = 0
  const consumedForwarding = forwardingFacade(() => {
    destroys++
  })
  const firstPlan = beginM3Install(firstPrevious.runtime, firstNext.runtime)
  validateM3Install(firstPlan, firstPreviousLink.state.localIdentity, 128, 1_000n)
  commitM3Install(firstPlan, 2_000n, consumedForwarding)
  clock.fireNext()
  t.is(destroys, 1)

  const secondPreviousLink = syntheticLink({
    initiator: false,
    completeOfferDigest: b4a.alloc(32, 0xa2),
    peerIdentity: b4a.alloc(32, 0xa3),
    wireExpiresAt: 2_000n
  })
  const secondNextLink = syntheticLink({
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0xa4),
    peerIdentity: b4a.alloc(32, 0xa5),
    wireExpiresAt: 2_000n
  })
  const secondPrevious = owner.adopt(secondPreviousLink.handle)
  const secondNext = owner.adopt(secondNextLink.handle)
  const secondPlan = beginM3Install(secondPrevious.runtime, secondNext.runtime)
  validateM3Install(secondPlan, secondPreviousLink.state.localIdentity, 128, 1_000n)
  let reused = null
  try {
    reused = commitM3Install(secondPlan, 2_000n, consumedForwarding)
  } catch {}
  t.is(reused, null, 'a consumed forwarding owner cannot install another pair')
  if (reused) reused.destroy()
  else {
    abortM3Install(secondPlan)
    secondPrevious.runtime.destroy()
    secondNext.runtime.destroy()
  }
})

test('install reserves plan and forwarding ownership before reentrant clocks', (t) => {
  const clock = fakeClock()
  let reenter = null
  const wallNow = () => {
    if (reenter) {
      const callback = reenter
      reenter = null
      callback()
    }
    return clock.wallNow()
  }
  const owner = new M3AdjacencyAuthority({
    wallNow,
    monotonicNow: clock.monotonicNow,
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled,
    crypto: cryptoSuite
  })
  const links = [0xb0, 0xb4].map((base) => {
    const previousLink = syntheticLink({
      initiator: false,
      completeOfferDigest: b4a.alloc(32, base),
      peerIdentity: b4a.alloc(32, base + 1)
    })
    const nextLink = syntheticLink({
      initiator: true,
      completeOfferDigest: b4a.alloc(32, base + 2),
      peerIdentity: b4a.alloc(32, base + 3)
    })
    const previous = owner.adopt(previousLink.handle)
    const next = owner.adopt(nextLink.handle)
    const plan = beginM3Install(previous.runtime, next.runtime)
    validateM3Install(plan, previousLink.state.localIdentity, 128, 1_000n)
    return { previousLink, nextLink, previous, next, plan }
  })
  const forwarding = forwardingFacade()
  let nested = null
  reenter = () => {
    try {
      nested = commitM3Install(links[1].plan, 2_000n, forwarding)
    } catch {}
  }
  const installed = commitM3Install(links[0].plan, 2_000n, forwarding)

  t.is(nested, null, 'a reentrant clock cannot install the same forwarding facade twice')
  installed.destroy()
  abortM3Install(links[1].plan)
  links[1].previous.runtime.destroy()
  links[1].next.runtime.destroy()
})

test('throwing forwarding teardown cannot retain an expired installed pair', (t) => {
  const clock = fakeClock()
  const owner = authority(clock)
  const previousLink = syntheticLink({ initiator: false })
  const nextLink = syntheticLink({
    initiator: true,
    completeOfferDigest: b4a.alloc(32, 0xc0),
    peerIdentity: b4a.alloc(32, 0xc1)
  })
  const previous = owner.adopt(previousLink.handle)
  const next = owner.adopt(nextLink.handle)
  const plan = beginM3Install(previous.runtime, next.runtime)
  validateM3Install(plan, previousLink.state.localIdentity, 128, 1_000n)
  commitM3Install(
    plan,
    2_000n,
    forwardingFacade(() => {
      throw new Error('teardown failure')
    })
  )

  t.is(clock.fireNext(), true)
  t.is(clock.pending(), 0)
  t.is(previousLink.channel.destroys, 1)
  t.is(nextLink.channel.destroys, 1)
})

test('initiator adoption publishes no responder token', (t) => {
  const clock = fakeClock()
  const adopted = authority(clock).adopt(syntheticLink({ initiator: true }).handle)

  t.alike(Object.keys(adopted).sort(), ['runtime', 'tail'])
  t.absent(adopted.responderToken)
  adopted.runtime.destroy()
  revokeM3TailCapability(adopted.tail)
})

test('responder adoption publishes one opaque frozen token', (t) => {
  const clock = fakeClock()
  const adopted = authority(clock).adopt(syntheticLink({ initiator: false }).handle)

  t.alike(Object.keys(adopted).sort(), ['responderToken', 'runtime', 'tail'])
  t.ok(Object.isFrozen(adopted))
  t.ok(Object.isFrozen(adopted.responderToken))
  t.alike(Reflect.ownKeys(adopted.responderToken), [])
  adopted.runtime.destroy()
  revokeM3TailCapability(adopted.tail)
})

test('responder tail and token move the same opaque binding', (t) => {
  const clock = fakeClock()
  const adopted = authority(clock).adopt(syntheticLink({ initiator: false }).handle)
  const tailState = takeM3TailCapability(adopted.tail, {
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow
  })
  const tokenBinding = consumeTailResponderToken(adopted.responderToken)

  t.ok(Object.isFrozen(tokenBinding))
  t.alike(Reflect.ownKeys(tokenBinding), [])
  t.is(tailState.binding, tokenBinding)
  adopted.runtime.destroy()
})

test('responder binding owns the exact transcript, identity, role, and deadline fields', (t) => {
  const clock = fakeClock({ wall: 1_000n, monotonic: 10_000n })
  const transfer = syntheticLink({
    initiator: false,
    localIdentity: b4a.alloc(32, 0x71),
    wireExpiresAt: 1_250n
  })
  const transcript = b4a.from(transfer.state.tailControlTranscript)
  const expectedDigest = cryptoSuite.hash([transcript])
  let observed = null
  const owner = authority(clock, {
    [TEST_ONLY_M3_ADJACENCY_OBSERVER](event) {
      if (event.type === 'responder-binding') observed = event
    }
  })

  const adopted = owner.adopt(transfer.handle)
  const fields = observed ? observed.bindingFields : {}
  const deadline = fields.deadline || { clockIdentity: {} }
  t.ok(observed, 'the owned test hook observes only non-secret binding copies')
  t.alike(Object.keys(fields).sort(), [
    'deadline',
    'initiator',
    'localIdentity',
    'transcriptDigest',
    'wireExpiresAt'
  ])
  t.alike(fields.transcriptDigest, expectedDigest)
  t.alike(fields.localIdentity, b4a.alloc(32, 0x71))
  t.is(fields.initiator, false)
  t.is(fields.wireExpiresAt, 1_250n)
  t.is(deadline.wireExpiresAt, 1_250n)
  t.is(deadline.localDeadline, 10_250n)
  t.is(deadline.clockIdentity.wallNow, clock.wallNow)
  t.is(deadline.clockIdentity.monotonicNow, clock.monotonicNow)

  adopted.runtime.destroy()
  revokeM3TailCapability(adopted.tail)
  b4a.fill(transcript, 0)
  b4a.fill(expectedDigest, 0)
})

test('token consumption repeats every hidden binding-field validation', (t) => {
  for (const field of [
    'transcriptDigest',
    'localIdentity',
    'initiator',
    'wireExpiresAt',
    'deadline'
  ]) {
    const clock = fakeClock()
    let observed = null
    const owner = authority(clock, {
      [TEST_ONLY_M3_ADJACENCY_OBSERVER](event) {
        if (event.type === 'responder-binding') observed = event
      }
    })
    const adopted = owner.adopt(syntheticLink({ initiator: false }).handle)
    const bindingDigest = observed.bindingFields.transcriptDigest
    const bindingIdentity = observed.bindingFields.localIdentity
    const tokenDigest = observed.tokenFields.transcriptDigest
    const tokenIdentity = observed.tokenFields.localIdentity

    observed.corruptToken(field)
    t.exception(
      () => consumeTailResponderToken(adopted.responderToken),
      `${field} is revalidated at consumption`
    )
    t.absent(revokeM3TailCapability(adopted.tail), `${field} mismatch revokes the paired tail`)
    t.alike(bindingDigest, b4a.alloc(32), `${field} mismatch clears the binding digest`)
    t.alike(bindingIdentity, b4a.alloc(32), `${field} mismatch clears the binding identity`)
    t.alike(tokenDigest, b4a.alloc(32), `${field} mismatch clears the token digest`)
    t.alike(tokenIdentity, b4a.alloc(32), `${field} mismatch clears the token identity`)
    adopted.runtime.destroy()
  }
})

test('responder token is one-shot and bindings are unique per tail', (t) => {
  const clock = fakeClock()
  const owner = authority(clock)
  const first = owner.adopt(syntheticLink({ initiator: false }).handle)
  const second = owner.adopt(
    syntheticLink({
      initiator: false,
      completeOfferDigest: b4a.alloc(32, 0xd0),
      peerIdentity: b4a.alloc(32, 0xd1)
    }).handle
  )
  const firstBinding = consumeTailResponderToken(first.responderToken)
  const secondBinding = consumeTailResponderToken(second.responderToken)

  t.not(firstBinding, secondBinding, 'different authenticated tails never share a binding')
  t.exception(() => consumeTailResponderToken(first.responderToken), 'a consumed token is replay')
  t.is(
    revokeTailResponderToken(first.responderToken),
    true,
    'authority destroy can clear a consumed token binding'
  )
  t.is(revokeTailResponderToken(first.responderToken), false)
  first.runtime.destroy()
  second.runtime.destroy()
})

test('revoking a consumed token zeroizes its moved binding', (t) => {
  const clock = fakeClock()
  let observed = null
  const owner = authority(clock, {
    [TEST_ONLY_M3_ADJACENCY_OBSERVER](event) {
      if (event.type === 'responder-binding') observed = event
    }
  })
  const adopted = owner.adopt(syntheticLink({ initiator: false }).handle)
  const bindingDigest = observed.bindingFields.transcriptDigest
  const bindingIdentity = observed.bindingFields.localIdentity

  consumeTailResponderToken(adopted.responderToken)
  t.is(revokeTailResponderToken(adopted.responderToken), true)
  t.alike(bindingDigest, b4a.alloc(32))
  t.alike(bindingIdentity, b4a.alloc(32))
  t.absent(revokeM3TailCapability(adopted.tail))
  t.is(revokeTailResponderToken(adopted.responderToken), false)
  adopted.runtime.destroy()
})

test('token revocation clears both repeated records and revokes the paired tail', (t) => {
  const clock = fakeClock()
  let observed = null
  const owner = authority(clock, {
    [TEST_ONLY_M3_ADJACENCY_OBSERVER](event) {
      if (event.type === 'responder-binding') observed = event
    }
  })
  const adopted = owner.adopt(syntheticLink({ initiator: false }).handle)
  const bindingDigest = observed.bindingFields.transcriptDigest
  const bindingIdentity = observed.bindingFields.localIdentity
  const tokenDigest = observed.tokenFields.transcriptDigest
  const tokenIdentity = observed.tokenFields.localIdentity

  t.is(revokeTailResponderToken(adopted.responderToken), true)
  t.is(revokeTailResponderToken(adopted.responderToken), false, 'revocation is one-shot')
  t.is(revokeM3TailCapability(adopted.tail), false, 'revocation consumes the paired tail')
  t.alike(bindingDigest, b4a.alloc(32))
  t.alike(bindingIdentity, b4a.alloc(32))
  t.alike(tokenDigest, b4a.alloc(32))
  t.alike(tokenIdentity, b4a.alloc(32))
  adopted.runtime.destroy()
})

test('runtime expiry proactively revokes and clears its responder token', (t) => {
  const clock = fakeClock()
  let observed = null
  const owner = authority(clock, {
    [TEST_ONLY_M3_ADJACENCY_OBSERVER](event) {
      if (event.type === 'responder-binding') observed = event
    }
  })
  const adopted = owner.adopt(syntheticLink({ initiator: false, wireExpiresAt: 1_250n }).handle)
  const bindingDigest = observed.bindingFields.transcriptDigest
  const tokenDigest = observed.tokenFields.transcriptDigest

  t.is(clock.fireNext(), true)
  t.exception(() => consumeTailResponderToken(adopted.responderToken))
  t.is(revokeM3TailCapability(adopted.tail), false)
  t.alike(bindingDigest, b4a.alloc(32))
  t.alike(tokenDigest, b4a.alloc(32))
  t.is(adopted.runtime.destroy(), false)
})

test('tail-first and token-first transfer failures destroy the paired binding', (t) => {
  for (const order of ['tail-first', 'token-first']) {
    const clock = fakeClock()
    let observed = null
    const owner = authority(clock, {
      [TEST_ONLY_M3_ADJACENCY_OBSERVER](event) {
        if (event.type === 'responder-binding') observed = event
      }
    })
    const adopted = owner.adopt(
      syntheticLink({
        initiator: false,
        completeOfferDigest: b4a.alloc(32, order === 'tail-first' ? 0xe0 : 0xe2),
        peerIdentity: b4a.alloc(32, order === 'tail-first' ? 0xe1 : 0xe3)
      }).handle
    )
    const bindingDigest = observed.bindingFields.transcriptDigest
    const bindingIdentity = observed.bindingFields.localIdentity
    const tokenDigest = observed.tokenFields.transcriptDigest
    const tokenIdentity = observed.tokenFields.localIdentity

    if (order === 'token-first') consumeTailResponderToken(adopted.responderToken)
    t.exception(() =>
      takeM3TailCapability(adopted.tail, {
        wallNow: () => 1_000n,
        monotonicNow: clock.monotonicNow
      })
    )
    if (order === 'tail-first') {
      t.exception(() => consumeTailResponderToken(adopted.responderToken))
    }
    t.alike(bindingDigest, b4a.alloc(32), `${order} clears the binding digest`)
    t.alike(bindingIdentity, b4a.alloc(32), `${order} clears the binding identity`)
    t.alike(tokenDigest, b4a.alloc(32), `${order} clears the token digest`)
    t.alike(tokenIdentity, b4a.alloc(32), `${order} clears the token identity`)
    adopted.runtime.destroy()
  }
})

test('responder token hash reentry cannot publish an expired adoption', (t) => {
  const clock = fakeClock()
  const transfer = syntheticLink({ initiator: false, wireExpiresAt: 2_000n })
  let owner = null
  let reentered = false
  const crypto = Object.freeze({
    ...cryptoSuite,
    hash(inputs) {
      if (!reentered && inputs.length === 1 && inputs[0].byteLength === 290) {
        reentered = true
        clock.setMonotonic(11_000n)
        owner.diagnostics()
      }
      return cryptoSuite.hash(inputs)
    }
  })
  owner = authority(clock, { crypto })
  let adopted = null

  t.exception(() => {
    adopted = owner.adopt(transfer.handle)
  }, 'an expired unpublished runtime cannot be returned after hash reentry')
  t.is(transfer.channel.destroys, 1)
  t.is(clock.pending(), 0)
  t.alike(owner.diagnostics(), {
    activeRuntimes: 0,
    maxRuntimes: 128
  })
  if (adopted) {
    revokeTailResponderToken(adopted.responderToken)
    revokeM3TailCapability(adopted.tail)
    adopted.runtime.destroy()
  }
})

test('reserved-observer reentry cannot publish an expired initiator adoption', (t) => {
  const clock = fakeClock()
  const transfer = syntheticLink({ initiator: true, wireExpiresAt: 2_000n })
  const owner = authority(clock, {
    [TEST_ONLY_M3_ADJACENCY_OBSERVER](event) {
      if (event.type === 'reserved') clock.setMonotonic(11_000n)
    }
  })
  let adopted = null

  t.exception(() => {
    adopted = owner.adopt(transfer.handle)
  }, 'an expired initiator cannot be published after reserved-observer reentry')
  t.is(transfer.channel.destroys, 1)
  t.is(clock.pending(), 0)
  t.alike(owner.diagnostics(), {
    activeRuntimes: 0,
    maxRuntimes: 128
  })
  if (adopted) {
    revokeM3TailCapability(adopted.tail)
    adopted.runtime.destroy()
  }
})
