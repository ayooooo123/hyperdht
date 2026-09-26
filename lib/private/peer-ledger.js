'use strict'

const { PrivateRouteError } = require('./errors')

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

function computePeerSemanticOwnedBytes(options) {
  if (!isObject(options)) invalid()
  const p = checkU32(ownProp(options, 'purpose'))
  const init = checkBool(ownProp(options, 'isInitiator'))
  const m = checkU32(ownProp(options, 'maxStreams'))

  if (p < 1 || p > 3 || m < 1) invalid()

  let result = 0
  if (p === 1) {
    result = init ? 33572251 * m : 17812 * m + 16777280
  } else if (p === 2) {
    result = init ? 33557016 * m : 2049 * m
  } else {
    result = init ? 726 + 33556888 * (m - 1) : 726 + 1921 * (m - 1)
  }

  if (typeof result !== 'number' || !Number.isInteger(result) || result < 0 || result > MAX_U32) {
    invalid()
  }

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
  if (!isObject(options)) invalid()
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
    if (!isObject(app)) invalid()
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

  return Object.freeze({
    reliablePackets: N,
    adjacencies: Object.freeze(adjacencies),
    directDiscovery,
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

module.exports = Object.freeze({
  computePeerSemanticOwnedBytes,
  computePeerQueuedBytes,
  computePeerRouteBudget,
  createPeerLedger,
  reservePeerLedger,
  chargePeerLedger,
  releasePeerLedger,
  readPeerLedger,
  createPeerMemoryPool,
  reservePeerMemory,
  takePeerMemory,
  releasePeerMemory,
  readPeerMemory,
  narrowPeerReservations
})
