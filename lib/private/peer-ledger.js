'use strict'

const { PrivateRouteError } = require('./errors')
const { PEER_RECORD_LIMITS, PEER_RECORD_PREFIX_BYTES } = require('./peer-protocol')

const MAX_U32 = 0xffff_ffff
const MAX_U64 = 0xffff_ffff_ffff_ffffn
const CELL_SIZE = 1200

const ledgers = new WeakMap()
const pools = new WeakMap()
const reservations = new WeakMap()

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function isObject(val) {
  return val !== null && typeof val === 'object' && !Array.isArray(val)
}

function ownProp(obj, prop) {
  if (!isObject(obj)) invalid()
  let desc
  try {
    desc = Object.getOwnPropertyDescriptor(obj, prop)
  } catch {
    invalid()
  }
  if (!desc || !('value' in desc)) invalid()
  return desc.value
}

// A reservation helper names every option it reads, so a misspelled or unknown option
// fails loudly instead of silently selecting a default floor.
function exactKeys(obj, names) {
  if (!isObject(obj)) invalid()
  let keys
  try {
    keys = Reflect.ownKeys(obj)
  } catch {
    invalid()
  }
  if (keys.length !== names.length || keys.some((key) => !names.includes(key))) invalid()
}

function ownIndex(arr, index) {
  if (!Array.isArray(arr)) invalid()
  let desc
  try {
    desc = Object.getOwnPropertyDescriptor(arr, String(index))
  } catch {
    invalid()
  }
  if (!desc || !('value' in desc)) invalid()
  return desc.value
}

function checkU32(val) {
  if (typeof val !== 'number' || !Number.isInteger(val) || val < 0 || val > MAX_U32) invalid()
  return val
}

function checkU64(val) {
  if (typeof val !== 'bigint' || val < 0n || val > MAX_U64) invalid()
  return val
}

function checkBool(val) {
  if (typeof val !== 'boolean') invalid()
  return val
}

// Canonical semantic cache bytes per lifetime stream (semantic §8.2): C1(M)=9620*M,
// C2(M)=2049*M, C3(M)=726+1921*(M-1).
const LEGACY_CACHE_BYTES = 9620
const PRIVATE_SOURCE_CACHE_BYTES = 2049
const REGISTRATION_CACHE_BYTES = 726
const PRIVATE_DESTINATION_CACHE_BYTES = 1921
// Two disjoint 4,096-byte contiguous Noise flights per purpose1 lifetime stream.
const LEGACY_NOISE_SCRATCH_BYTES = 8192
// One 528-byte confirmation arena per private endpoint application stream.
const PRIVATE_CONFIRMATION_BYTES = 528
// The one legacy egress pre-OPEN ingress slot: header 59 + record 16,777,218 + guard 3.
const LEGACY_PRE_OPEN_BYTES = 16_777_280

// requiredSemanticOwnedBytes (packet §7.3, semantic §8.2): canonical caches, legacy Noise
// scratch, private confirmation arenas, one outbound and one inbound record slot plus the
// prefix guard per local endpoint application stream, and the legacy pre-OPEN slot. The
// record slot follows the purpose's record limit, so a private endpoint stream owns
// 2*65,556+3 bytes and a legacy one 2*16,777,218+3.
function computePeerSemanticOwnedBytes(options) {
  exactKeys(options, ['purpose', 'isInitiator', 'maxStreams'])
  const p = checkU32(ownProp(options, 'purpose'))
  const init = checkBool(ownProp(options, 'isInitiator'))
  const m = checkU32(ownProp(options, 'maxStreams'))

  if (p < 1 || p > 3 || m < 1) invalid()

  const recordSlotBytes = 2 * PEER_RECORD_LIMITS[p].raw + PEER_RECORD_PREFIX_BYTES
  let cache = 0
  let endpointStreams = 0
  let scratch = 0
  let legacyEgress = 0
  if (p === 1) {
    cache = LEGACY_CACHE_BYTES * m
    endpointStreams = init ? m : 0
    scratch = LEGACY_NOISE_SCRATCH_BYTES * m
    legacyEgress = init ? 0 : LEGACY_PRE_OPEN_BYTES
  } else if (p === 2) {
    cache = PRIVATE_SOURCE_CACHE_BYTES * m
    endpointStreams = init ? m : 0
    scratch = PRIVATE_CONFIRMATION_BYTES * endpointStreams
  } else {
    cache = REGISTRATION_CACHE_BYTES + PRIVATE_DESTINATION_CACHE_BYTES * (m - 1)
    endpointStreams = init ? m - 1 : 0
    scratch = PRIVATE_CONFIRMATION_BYTES * endpointStreams
  }
  const result = cache + scratch + recordSlotBytes * endpointStreams + legacyEgress

  if (!Number.isSafeInteger(result) || result < 0 || result > MAX_U32) invalid()

  return result
}

function computePeerQueuedBytes(options) {
  if (!isObject(options)) invalid()
  const m = checkU32(ownProp(options, 'maxStreams'))
  const r = checkU32(ownProp(options, 'receiveBytes'))
  const s = checkU32(ownProp(options, 'semanticOwnedBytes'))

  const total = 157200 + 1073 * m + r + s
  if (total > MAX_U32) invalid()
  return total
}

function computePeerRouteBudget(options) {
  exactKeys(options, ['purpose', 'maxStreams', 'applications'])
  const p = checkU32(ownProp(options, 'purpose'))
  const m = checkU32(ownProp(options, 'maxStreams'))
  const apps = ownProp(options, 'applications')

  if (p < 1 || p > 3 || m < 1) invalid()
  if (!Array.isArray(apps)) invalid()

  const expectedAppCount = p === 3 ? m - 1 : m
  if (apps.length !== expectedAppCount) invalid()

  let Pf = 0
  let Pr = 0

  if (p === 1) {
    Pf = 13 * m
    Pr = 13 * m
  } else if (p === 2) {
    Pf = 5 * m
    Pr = 5 * m
  } else {
    Pf = 3 + 4 * (m - 1)
    Pr = 1 + 5 * (m - 1)
  }

  let sumQf = 0
  let sumQr = 0
  let sumGsr = 0
  let sumGsf = 0
  let appFinF = 0
  let appFinR = 0

  for (let i = 0; i < apps.length; i++) {
    const app = ownIndex(apps, i)
    exactKeys(app, [
      'forwardFrames',
      'reverseFrames',
      'forwardBytes',
      'reverseBytes',
      'forwardWindow',
      'reverseWindow'
    ])
    const Qf = checkU32(ownProp(app, 'forwardFrames'))
    const Qr = checkU32(ownProp(app, 'reverseFrames'))
    const Bf = checkU64(ownProp(app, 'forwardBytes'))
    const Br = checkU64(ownProp(app, 'reverseBytes'))
    const Wf = checkU32(ownProp(app, 'forwardWindow'))
    const Wr = checkU32(ownProp(app, 'reverseWindow'))

    if (Qf < 1 || Qr < 1) invalid()
    if (Bf < 59n || Bf > BigInt(977 * Qf)) invalid()
    if (Br < 59n || Br > BigInt(977 * Qr)) invalid()
    if (Wf < 1 || Wf > Math.min(24, Qf)) invalid()
    if (Wr < 1 || Wr > Math.min(24, Qr)) invalid()

    sumQf += Qf
    sumQr += Qr
    const Gsf = 1 + (Qf - Wf)
    const Gsr = 1 + (Qr - Wr)
    sumGsf += Gsf
    sumGsr += Gsr
    appFinF += 1
    appFinR += 1
  }

  const F = Pf + sumQf + sumGsr + appFinF
  const R = Pr + sumQr + sumGsf + appFinR
  const N = F + R

  const a0fCmds = 1 + (p === 3 ? 2 * (m - 1) : 0) + 0 + m + 2
  const a0rCmds = 2 + 0 + 0 + m + 2
  const a1fCmds = 1 + 0 + 0 + m + 2
  const a1rCmds = 2 + 0 + 0 + m + 2
  const a2fCmds = 1 + 0 + 0 + m + 2
  const terminalCf = p === 1 ? 3 * m : p === 2 ? 2 * m : 2
  const a2rCmds = 1 + terminalCf + 1 + m + 2

  const setupAttempts = [
    { Sif: 40, Sir: 56, fCmds: a0fCmds, rCmds: a0rCmds },
    { Sif: 24, Sir: 40, fCmds: a1fCmds, rCmds: a1rCmds },
    { Sif: 8, Sir: 16, fCmds: a2fCmds, rCmds: a2rCmds }
  ]

  const adjacencies = []
  let totalAdjacencyCells = 0

  for (let i = 0; i < 3; i++) {
    const { Sif, Sir, fCmds, rCmds } = setupAttempts[i]
    const fCells = Sif + 8 * N + 16 * m + 34
    const rCells = Sir + 8 * N + 16 * m + 34
    const fBytes = BigInt(fCells) * BigInt(CELL_SIZE)
    const rBytes = BigInt(rCells) * BigInt(CELL_SIZE)

    if (fCells > MAX_U32 || rCells > MAX_U32) invalid()
    if (fCmds > MAX_U32 || rCmds > MAX_U32) invalid()

    adjacencies.push(
      Object.freeze({
        forward: Object.freeze({ cells: fCells, bytes: fBytes, commands: fCmds }),
        reverse: Object.freeze({ cells: rCells, bytes: rBytes, commands: rCmds })
      })
    )

    totalAdjacencyCells += fCells + rCells
  }

  const directDiscovery = Object.freeze([
    Object.freeze({
      forward: Object.freeze({ cells: 24, bytes: 28800n, commands: 0 }),
      reverse: Object.freeze({ cells: 24, bytes: 28800n, commands: 1 })
    }),
    Object.freeze({
      forward: Object.freeze({ cells: 24, bytes: 28800n, commands: 0 }),
      reverse: Object.freeze({ cells: 24, bytes: 28800n, commands: 1 })
    }),
    Object.freeze({
      forward: Object.freeze({ cells: 24, bytes: 28800n, commands: 0 }),
      reverse: Object.freeze({ cells: 24, bytes: 28800n, commands: 1 })
    })
  ])

  const totalCells = totalAdjacencyCells + 144
  const totalBytes = BigInt(totalCells) * BigInt(CELL_SIZE)

  if (totalCells > MAX_U32) invalid()

  // The purpose route's own rows, the same in every adjacency it crosses (§8.1, §8.3): the
  // reliable work and its ACKs (8N), every lifetime stream's forced close (16M), and the
  // purpose OFFER or ACCEPT, the sentinel and the route close (8 each). The commands are
  // the ones the purpose owner allocates in its own outgoing direction: at the source the
  // allocations that terminate there, M stream closes and the route close; at the terminal
  // its allocations, the purpose OFFER, M stream closes and the route close. Setup, direct
  // discovery and physical branch closure stay with the adjacency owners.
  const purposeCells = 8 * N + 16 * m + 24
  if (purposeCells > MAX_U32) invalid()
  const purposeBytes = BigInt(purposeCells) * BigInt(CELL_SIZE)
  const purpose = Object.freeze({
    forward: Object.freeze({
      cells: purposeCells,
      bytes: purposeBytes,
      commands: (p === 3 ? 2 * (m - 1) : 0) + m + 1
    }),
    reverse: Object.freeze({
      cells: purposeCells,
      bytes: purposeBytes,
      commands: terminalCf + 1 + m + 1
    })
  })

  return Object.freeze({
    reliablePackets: N,
    adjacencies: Object.freeze(adjacencies),
    directDiscovery,
    purpose,
    totalCells,
    totalBytes
  })
}

function createPeerLedger(options) {
  if (!isObject(options)) invalid()
  const c = checkU32(ownProp(options, 'cells'))
  const b = checkU64(ownProp(options, 'bytes'))
  const cmd = checkU32(ownProp(options, 'commands'))

  const handle = Object.freeze({})
  const state = {
    cellsAllocated: c,
    bytesAllocated: b,
    commandsAllocated: cmd,
    cellsSpent: 0,
    bytesSpent: 0n,
    commandsSpent: 0,
    cellsReserved: 0,
    bytesReserved: 0n,
    commandsReserved: 0,
    released: false,
    children: new Set()
  }

  ledgers.set(handle, state)
  return handle
}

function reservePeerLedger(parentHandle, options) {
  const parentState = ledgers.get(parentHandle)
  if (!parentState || parentState.released) invalid()

  if (!isObject(options)) invalid()
  const reqC = checkU32(ownProp(options, 'cells'))
  const reqB = checkU64(ownProp(options, 'bytes'))
  const reqCmd = checkU32(ownProp(options, 'commands'))

  const remC = parentState.cellsAllocated - parentState.cellsSpent - parentState.cellsReserved
  const remB = parentState.bytesAllocated - parentState.bytesSpent - parentState.bytesReserved
  const remCmd =
    parentState.commandsAllocated - parentState.commandsSpent - parentState.commandsReserved

  if (reqC > remC || reqB > remB || reqCmd > remCmd) invalid()

  parentState.cellsReserved += reqC
  parentState.bytesReserved += reqB
  parentState.commandsReserved += reqCmd

  const childHandle = Object.freeze({})
  const childState = {
    parentHandle,
    parentState,
    cellsAllocated: reqC,
    bytesAllocated: reqB,
    commandsAllocated: reqCmd,
    cellsSpent: 0,
    bytesSpent: 0n,
    commandsSpent: 0,
    cellsReserved: 0,
    bytesReserved: 0n,
    commandsReserved: 0,
    released: false,
    children: new Set()
  }

  parentState.children.add(childHandle)
  ledgers.set(childHandle, childState)
  return childHandle
}

function chargePeerLedger(handle, options) {
  const state = ledgers.get(handle)
  if (!state || state.released) invalid()

  if (!isObject(options)) invalid()
  const c = checkU32(ownProp(options, 'cells'))
  const b = checkU64(ownProp(options, 'bytes'))
  const cmd = checkU32(ownProp(options, 'commands'))

  const remC = state.cellsAllocated - state.cellsSpent - state.cellsReserved
  const remB = state.bytesAllocated - state.bytesSpent - state.bytesReserved
  const remCmd = state.commandsAllocated - state.commandsSpent - state.commandsReserved

  if (c > remC || b > remB || cmd > remCmd) invalid()

  // Charge local ledger spent
  state.cellsSpent += c
  state.bytesSpent += b
  state.commandsSpent += cmd

  // For each ancestor: reserved is reduced by the charge AND spent is increased by the charge
  let current = state.parentState
  while (current) {
    current.cellsReserved -= c
    current.bytesReserved -= b
    current.commandsReserved -= cmd

    current.cellsSpent += c
    current.bytesSpent += b
    current.commandsSpent += cmd

    current = current.parentState
  }
}

function releasePeerLedger(handle) {
  const state = ledgers.get(handle)
  if (!state) invalid()
  if (state.released) return false

  state.released = true

  for (const childHandle of Array.from(state.children)) {
    releasePeerLedger(childHandle)
  }
  state.children.clear()

  if (state.parentState) {
    const unspentCells = state.cellsAllocated - state.cellsSpent
    const unspentBytes = state.bytesAllocated - state.bytesSpent
    const unspentCmds = state.commandsAllocated - state.commandsSpent

    state.parentState.cellsReserved -= unspentCells
    state.parentState.bytesReserved -= unspentBytes
    state.parentState.commandsReserved -= unspentCmds

    state.parentState.children.delete(handle)
  }

  return true
}

function readPeerLedger(handle) {
  const state = ledgers.get(handle)
  if (!state) invalid()

  const remC = state.cellsAllocated - state.cellsSpent - state.cellsReserved
  const remB = state.bytesAllocated - state.bytesSpent - state.bytesReserved
  const remCmd = state.commandsAllocated - state.commandsSpent - state.commandsReserved

  return Object.freeze({
    cellsAllocated: state.cellsAllocated,
    bytesAllocated: state.bytesAllocated,
    commandsAllocated: state.commandsAllocated,
    cellsSpent: state.cellsSpent,
    bytesSpent: state.bytesSpent,
    commandsSpent: state.commandsSpent,
    cellsReserved: state.cellsReserved,
    bytesReserved: state.bytesReserved,
    commandsReserved: state.commandsReserved,
    cellsRemaining: remC,
    bytesRemaining: remB,
    commandsRemaining: remCmd,
    released: state.released
  })
}

// True when `ledger` is live and reserved, directly or further down, below the live
// `ancestor`: a charge to it is also a charge to the ancestor, never beside it.
function isPeerLedgerWithin(ledger, ancestor) {
  const state = isObject(ledger) ? ledgers.get(ledger) : null
  const root = isObject(ancestor) ? ledgers.get(ancestor) : null
  if (!state || !root || state.released || root.released) return false
  for (let current = state.parentState; current; current = current.parentState) {
    if (current === root) return true
  }
  return false
}

function createPeerMemoryPool(capacityBytes) {
  const cap = checkU32(capacityBytes)

  const handle = Object.freeze({})
  const state = {
    capacityBytes: cap,
    reservedBytes: 0,
    takenBytes: 0,
    released: false,
    reservations: new Set(),
    parentReservationState: null
  }

  pools.set(handle, state)
  return handle
}

function reservePeerMemory(poolHandle, kind, capacityBytes) {
  const poolState = pools.get(poolHandle)
  if (!poolState || poolState.released) invalid()

  if (typeof kind !== 'string' || kind.length === 0) invalid()
  const cap = checkU32(capacityBytes)

  const rem = poolState.capacityBytes - poolState.reservedBytes
  if (cap > rem) invalid()

  poolState.reservedBytes += cap

  const resHandle = Object.freeze({})
  const resState = {
    handle: resHandle,
    poolHandle,
    poolState,
    kind,
    capacityBytes: cap,
    taken: false,
    childPoolHandle: null,
    childPoolState: null,
    released: false
  }

  poolState.reservations.add(resHandle)
  reservations.set(resHandle, resState)
  return resHandle
}

function takePeerMemory(resHandle) {
  const resState = reservations.get(resHandle)
  if (!resState || resState.released || resState.taken) invalid()

  resState.taken = true
  resState.poolState.takenBytes += resState.capacityBytes

  const childPoolHandle = Object.freeze({})
  const childPoolState = {
    capacityBytes: resState.capacityBytes,
    reservedBytes: 0,
    takenBytes: 0,
    released: false,
    reservations: new Set(),
    parentReservationState: resState
  }

  resState.childPoolHandle = childPoolHandle
  resState.childPoolState = childPoolState
  pools.set(childPoolHandle, childPoolState)
  return childPoolHandle
}

function _releaseReservation(resState) {
  if (resState.released) return false
  resState.released = true

  resState.poolState.reservations.delete(resState.handle)
  resState.poolState.reservedBytes -= resState.capacityBytes

  if (resState.taken) {
    resState.poolState.takenBytes -= resState.capacityBytes
    if (resState.childPoolState && !resState.childPoolState.released) {
      resState.childPoolState.released = true
      for (const childResHandle of resState.childPoolState.reservations) {
        const childResState = reservations.get(childResHandle)
        if (childResState) {
          _releaseReservation(childResState)
        }
      }
      resState.childPoolState.reservations.clear()
    }
  }

  return true
}

function releasePeerMemory(handle) {
  const poolState = pools.get(handle)
  if (poolState) {
    if (poolState.released) return false
    poolState.released = true

    for (const resHandle of Array.from(poolState.reservations)) {
      const resState = reservations.get(resHandle)
      if (resState) {
        _releaseReservation(resState)
      }
    }
    poolState.reservations.clear()

    if (poolState.parentReservationState) {
      _releaseReservation(poolState.parentReservationState)
    }

    return true
  }

  const resState = reservations.get(handle)
  if (resState) {
    return _releaseReservation(resState)
  }

  invalid()
}

function readPeerMemory(handle) {
  const poolState = pools.get(handle)
  if (poolState) {
    return Object.freeze({
      type: 'pool',
      capacityBytes: poolState.capacityBytes,
      reservedBytes: poolState.reservedBytes,
      takenBytes: poolState.takenBytes,
      remainingBytes: poolState.capacityBytes - poolState.reservedBytes,
      released: poolState.released
    })
  }

  const resState = reservations.get(handle)
  if (resState) {
    return Object.freeze({
      type: 'reservation',
      kind: resState.kind,
      capacityBytes: resState.capacityBytes,
      taken: resState.taken,
      released: resState.released
    })
  }

  invalid()
}

function narrowPeerReservations(options) {
  const ledgerPlans = []
  const memoryPlans = []
  try {
    const ledgerRows = ownProp(options, 'ledgers')
    const memoryRows = ownProp(options, 'memory')
    if (!Array.isArray(ledgerRows) || !Array.isArray(memoryRows)) invalid()
    const ledgerCount = checkU32(ownIndex(ledgerRows, 'length'))
    const memoryCount = checkU32(ownIndex(memoryRows, 'length'))

    // Finish reading caller-owned descriptors before consulting any live state.
    // A Proxy descriptor trap can release or revoke an earlier or later handle.
    for (let i = 0; i < ledgerCount; i++) {
      const row = ownIndex(ledgerRows, i)
      ledgerPlans.push({
        handle: ownProp(row, 'ledger'),
        cells: checkU32(ownProp(row, 'cells')),
        bytes: checkU64(ownProp(row, 'bytes')),
        commands: checkU32(ownProp(row, 'commands'))
      })
    }
    for (let i = 0; i < memoryCount; i++) {
      const row = ownIndex(memoryRows, i)
      memoryPlans.push({
        handle: ownProp(row, 'reservation'),
        capacityBytes: checkU32(ownProp(row, 'capacityBytes'))
      })
    }
  } catch {
    invalid()
  }
  const seen = new Set()

  const returnedToParent = new Map()
  for (const plan of ledgerPlans) {
    const state = ledgers.get(plan.handle)
    if (!state || state.released || seen.has(plan.handle)) invalid()
    seen.add(plan.handle)
    if (
      plan.cells > state.cellsAllocated ||
      plan.bytes > state.bytesAllocated ||
      plan.commands > state.commandsAllocated
    )
      invalid()
    plan.state = state
    plan.cellsReturned = state.cellsAllocated - plan.cells
    plan.bytesReturned = state.bytesAllocated - plan.bytes
    plan.commandsReturned = state.commandsAllocated - plan.commands
    if (state.parentState) {
      let returned = returnedToParent.get(state.parentState)
      if (!returned) {
        returned = { cells: 0, bytes: 0n, commands: 0 }
        returnedToParent.set(state.parentState, returned)
      }
      returned.cells += plan.cellsReturned
      returned.bytes += plan.bytesReturned
      returned.commands += plan.commandsReturned
    }
  }
  for (const plan of ledgerPlans) {
    const state = plan.state
    const returned = returnedToParent.get(state)
    if (
      plan.cells < state.cellsSpent + state.cellsReserved - (returned ? returned.cells : 0) ||
      plan.bytes < state.bytesSpent + state.bytesReserved - (returned ? returned.bytes : 0n) ||
      plan.commands <
        state.commandsSpent + state.commandsReserved - (returned ? returned.commands : 0)
    )
      invalid()
  }
  for (const plan of memoryPlans) {
    const state = reservations.get(plan.handle)
    if (!state || state.released || seen.has(plan.handle)) invalid()
    seen.add(plan.handle)
    if (plan.capacityBytes > state.capacityBytes) invalid()
    // Taken capacity may already back live buffers; only pending reservations
    // can return excess without replacing or revoking their storage owner.
    if (state.taken && plan.capacityBytes !== state.capacityBytes) invalid()
    plan.state = state
    plan.bytesReturned = state.capacityBytes - plan.capacityBytes
  }

  // No callbacks or fallible allocation after validation: publish the entire
  // downward negotiation together, preserving every original handle.
  for (const plan of ledgerPlans) {
    const state = plan.state
    state.cellsAllocated = plan.cells
    state.bytesAllocated = plan.bytes
    state.commandsAllocated = plan.commands
    if (state.parentState) {
      state.parentState.cellsReserved -= plan.cellsReturned
      state.parentState.bytesReserved -= plan.bytesReturned
      state.parentState.commandsReserved -= plan.commandsReturned
    }
  }
  for (const plan of memoryPlans) {
    plan.state.capacityBytes = plan.capacityBytes
    plan.state.poolState.reservedBytes -= plan.bytesReturned
  }
}

// ---------------------------------------------------------------------------
// Branch slots
// ---------------------------------------------------------------------------

// A branch-slot pool is a storage ceiling: at most `capacity` native branches hold
// authority at once. The pool's admission owner takes a slot together with a fresh branch
// authority, four root ledgers of exactly the branch's admitted rows: its ordinary send and
// receive partitions and its send and receive closure partitions. Spending inside a branch
// is final. Releasing the authority retires the branch for good and frees its slot for a
// new branch with new authority; nothing a branch spent is ever returned. The pool keeps its
// retired branches' spending as totals, so the evidence outlives the branches.
const BRANCH_KINDS = Object.freeze([
  'sendLedger',
  'receiveLedger',
  'teardownSendLedger',
  'teardownReceiveLedger'
])
const ROW_FIELDS = Object.freeze(['cells', 'bytes', 'commands'])
const branchSlotPools = new WeakMap()
const branchAuthorities = new WeakMap()

function emptySpent() {
  const spent = {}
  for (const kind of BRANCH_KINDS) spent[kind] = { cells: 0, bytes: 0n, commands: 0 }
  return spent
}

function addSpent(total, state) {
  total.cells += state.cellsSpent
  total.bytes += state.bytesSpent
  total.commands += state.commandsSpent
}

function createPeerBranchSlots(capacity) {
  if (checkU32(capacity) < 1) invalid()
  const handle = Object.freeze({})
  branchSlotPools.set(handle, {
    capacity,
    live: new Set(),
    retired: 0,
    closed: false,
    retiredSpent: emptySpent()
  })
  return handle
}

// All four rows are read and checked before the pool is consulted, and the slot and its
// roots are published together: a refused take changes nothing.
function takePeerBranchAuthority(slotsHandle, rows) {
  const pool = isObject(slotsHandle) ? branchSlotPools.get(slotsHandle) : null
  if (!pool) invalid()
  exactKeys(rows, BRANCH_KINDS)
  const plan = BRANCH_KINDS.map((kind) => {
    const row = ownProp(rows, kind)
    exactKeys(row, ROW_FIELDS)
    return {
      kind,
      cells: checkU32(ownProp(row, 'cells')),
      bytes: checkU64(ownProp(row, 'bytes')),
      commands: checkU32(ownProp(row, 'commands'))
    }
  })
  if (pool.closed) invalid()
  if (pool.live.size >= pool.capacity) throw PrivateRouteError.ERR_QUOTA_EXCEEDED()
  const authority = {}
  for (const { kind, cells, bytes, commands } of plan) {
    authority[kind] = createPeerLedger({ cells, bytes, commands })
  }
  Object.freeze(authority)
  pool.live.add(authority)
  branchAuthorities.set(authority, { pool, released: false, joinDeferred: false })
  return authority
}

// Marks a branch whose logical owner has retired while its native duties are still in
// flight: the slot stays occupied and closing the pool will not free it; only the join
// barrier (releasePeerBranchAuthority at the last native completion) retires it.
function deferPeerBranchAuthorityJoin(authority) {
  const state = isObject(authority) ? branchAuthorities.get(authority) : null
  if (!state || state.released) invalid()
  if (state.joinDeferred) return false
  state.joinDeferred = true
  return true
}

// Retires a branch: its roots and everything reserved below them are released, what they
// spent joins the pool's retired totals, and the slot is free. Idempotent.
function releasePeerBranchAuthority(authority) {
  const state = isObject(authority) ? branchAuthorities.get(authority) : null
  if (!state) invalid()
  if (state.released) return false
  state.released = true
  for (const kind of BRANCH_KINDS) {
    addSpent(state.pool.retiredSpent[kind], ledgers.get(authority[kind]))
    releasePeerLedger(authority[kind])
  }
  state.pool.live.delete(authority)
  state.pool.retired++
  return true
}

// Closes the pool to new branches and revokes every live one whose native work has
// joined. A branch deferred to its join barrier keeps its slot after close: closing stops
// admission, it never frees capacity that unjoined native duties still back. Idempotent.
function closePeerBranchSlots(slotsHandle) {
  const pool = isObject(slotsHandle) ? branchSlotPools.get(slotsHandle) : null
  if (!pool) invalid()
  if (pool.closed) return false
  pool.closed = true
  for (const authority of Array.from(pool.live)) {
    const state = branchAuthorities.get(authority)
    if (state && state.joinDeferred) continue
    releasePeerBranchAuthority(authority)
  }
  return true
}

// `reserved` is what live branches, closing ones included, hold as authority now; `spent` is
// what every branch of the pool has spent, retired or live.
function readPeerBranchSlots(slotsHandle) {
  const pool = isObject(slotsHandle) ? branchSlotPools.get(slotsHandle) : null
  if (!pool) invalid()
  const reserved = {}
  const spent = {}
  for (const kind of BRANCH_KINDS) {
    const held = { cells: 0, bytes: 0n, commands: 0 }
    const total = { ...pool.retiredSpent[kind] }
    for (const authority of pool.live) {
      const state = ledgers.get(authority[kind])
      held.cells += state.cellsAllocated
      held.bytes += state.bytesAllocated
      held.commands += state.commandsAllocated
      addSpent(total, state)
    }
    reserved[kind] = Object.freeze(held)
    spent[kind] = Object.freeze(total)
  }
  return Object.freeze({
    capacity: pool.capacity,
    live: pool.live.size,
    retired: pool.retired,
    closed: pool.closed,
    reserved: Object.freeze(reserved),
    spent: Object.freeze(spent)
  })
}

module.exports = Object.freeze({
  computePeerSemanticOwnedBytes,
  computePeerQueuedBytes,
  computePeerRouteBudget,
  createPeerLedger,
  reservePeerLedger,
  chargePeerLedger,
  releasePeerLedger,
  readPeerLedger,
  isPeerLedgerWithin,
  createPeerMemoryPool,
  reservePeerMemory,
  takePeerMemory,
  releasePeerMemory,
  readPeerMemory,
  narrowPeerReservations,
  createPeerBranchSlots,
  takePeerBranchAuthority,
  deferPeerBranchAuthorityJoin,
  releasePeerBranchAuthority,
  closePeerBranchSlots,
  readPeerBranchSlots
})
