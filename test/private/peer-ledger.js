'use strict'

const test = require('brittle')
const { PrivateRouteError } = require('../../lib/private/errors')
const {
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
  narrowPeerReservations,
  readPeerMemory
} = require('../../lib/private/peer-ledger')

function expectInvalid(t, fn) {
  let err = null
  try {
    fn()
  } catch (e) {
    err = e
  }
  t.ok(err instanceof PrivateRouteError)
  t.is(err && err.code, 'INVALID_ROUTE')
}

test('computePeerSemanticOwnedBytes exact owner floors and u32 bounds', (t) => {
  t.is(computePeerSemanticOwnedBytes({ purpose: 1, isInitiator: true, maxStreams: 1 }), 33572251)
  t.is(computePeerSemanticOwnedBytes({ purpose: 1, isInitiator: true, maxStreams: 2 }), 67144502)
  t.is(
    computePeerSemanticOwnedBytes({ purpose: 1, isInitiator: false, maxStreams: 1 }),
    17812 + 16777280
  )

  t.is(computePeerSemanticOwnedBytes({ purpose: 2, isInitiator: true, maxStreams: 1 }), 33557016)
  t.is(computePeerSemanticOwnedBytes({ purpose: 2, isInitiator: false, maxStreams: 1 }), 2049)

  t.is(computePeerSemanticOwnedBytes({ purpose: 3, isInitiator: true, maxStreams: 1 }), 726)
  t.is(
    computePeerSemanticOwnedBytes({ purpose: 3, isInitiator: true, maxStreams: 2 }),
    726 + 33556888
  )

  expectInvalid(t, () =>
    computePeerSemanticOwnedBytes({ purpose: 1, isInitiator: true, maxStreams: 128 })
  )

  const getterObj = {}
  Object.defineProperty(getterObj, 'purpose', {
    get() {
      return 1
    },
    enumerable: true
  })
  getterObj.isInitiator = true
  getterObj.maxStreams = 1
  expectInvalid(t, () => computePeerSemanticOwnedBytes(getterObj))
})

test('computePeerQueuedBytes calculation and boundary', (t) => {
  t.is(
    computePeerQueuedBytes({ maxStreams: 1, receiveBytes: 1000, semanticOwnedBytes: 2000 }),
    157200 + 1073 + 1000 + 2000
  )
  expectInvalid(t, () =>
    computePeerQueuedBytes({
      maxStreams: 1,
      receiveBytes: 0xffffffff,
      semanticOwnedBytes: 0xffffffff
    })
  )
})

test('computePeerRouteBudget baseline totals, directDiscovery shape, and command mappings', (t) => {
  const app0 = {
    forwardFrames: 1,
    reverseFrames: 1,
    forwardBytes: 59n,
    reverseBytes: 59n,
    forwardWindow: 1,
    reverseWindow: 1
  }

  // Purpose 3 reg only (M=1, 0 apps) -> 820 cells
  const b1 = computePeerRouteBudget({ purpose: 3, maxStreams: 1, applications: [] })
  t.is(b1.totalCells, 820)

  // directDiscovery shape & immutability assertions
  t.ok(Object.isFrozen(b1.directDiscovery))
  t.is(b1.directDiscovery.length, 3)
  for (let i = 0; i < 3; i++) {
    const pair = b1.directDiscovery[i]
    t.ok(Object.isFrozen(pair))
    t.ok(Object.isFrozen(pair.forward))
    t.ok(Object.isFrozen(pair.reverse))
    t.is(pair.forward.cells, 24)
    t.is(pair.forward.bytes, 28800n)
    t.is(pair.forward.commands, 0)
    t.is(pair.reverse.cells, 24)
    t.is(pair.reverse.bytes, 28800n)
    t.is(pair.reverse.commands, 1)
  }

  // Command mappings:
  // A0 Forward (source): 1 + 0 + 1 + 2 = 4
  // A2 Reverse (terminal): 1 + 2 + 1 + 1 + 2 = 7
  t.is(b1.adjacencies[0].forward.commands, 4)
  t.is(b1.adjacencies[2].reverse.commands, 7)

  // Purpose 2 (M=1, 1 app) -> 1396 cells
  const b2 = computePeerRouteBudget({ purpose: 2, maxStreams: 1, applications: [app0] })
  t.is(b2.totalCells, 1396)
  t.is(b2.adjacencies[0].forward.commands, 4)
  t.is(b2.adjacencies[2].reverse.commands, 7)

  // Purpose 3 (M=2, 1 app) -> 1636 cells
  const b3 = computePeerRouteBudget({ purpose: 3, maxStreams: 2, applications: [app0] })
  t.is(b3.totalCells, 1636)
  t.is(b3.adjacencies[0].forward.commands, 7)
  t.is(b3.adjacencies[2].reverse.commands, 8)

  // Purpose 1 (M=1, 1 app) -> 2164 cells
  const b4 = computePeerRouteBudget({ purpose: 1, maxStreams: 1, applications: [app0] })
  t.is(b4.totalCells, 2164)
  t.is(b4.adjacencies[0].forward.commands, 4)
  t.is(b4.adjacencies[2].reverse.commands, 8)
})

test('computePeerRouteBudget array index getter trap rejection', (t) => {
  const app0 = {
    forwardFrames: 1,
    reverseFrames: 1,
    forwardBytes: 59n,
    reverseBytes: 59n,
    forwardWindow: 1,
    reverseWindow: 1
  }
  const apps = []
  Object.defineProperty(apps, '0', {
    get() {
      return app0
    },
    enumerable: true
  })
  expectInvalid(t, () => computePeerRouteBudget({ purpose: 2, maxStreams: 1, applications: apps }))
})

test('createPeerLedger non-equal cells vs bytes reservation release', (t) => {
  const parent = createPeerLedger({ cells: 100, bytes: 120000n, commands: 10 })
  const child = reservePeerLedger(parent, { cells: 10, bytes: 50000n, commands: 2 })

  let snap = readPeerLedger(parent)
  t.is(snap.cellsReserved, 10)
  t.is(snap.bytesReserved, 50000n)
  t.is(snap.commandsReserved, 2)

  t.ok(releasePeerLedger(child))

  snap = readPeerLedger(parent)
  t.is(snap.cellsReserved, 0)
  t.is(snap.bytesReserved, 0n)
  t.is(snap.commandsReserved, 0)
})

test('live-child sibling reservation while child is active across cells, bytes, and commands', (t) => {
  const root = createPeerLedger({ cells: 100, bytes: 120000n, commands: 10 })
  const child1 = reservePeerLedger(root, { cells: 40, bytes: 48000n, commands: 4 })

  let rootSnap = readPeerLedger(root)
  t.is(rootSnap.cellsRemaining, 60)
  t.is(rootSnap.bytesRemaining, 72000n)
  t.is(rootSnap.commandsRemaining, 6)
  t.is(rootSnap.cellsReserved, 40)
  t.is(rootSnap.bytesReserved, 48000n)
  t.is(rootSnap.commandsReserved, 4)
  t.is(rootSnap.cellsSpent, 0)
  t.is(rootSnap.bytesSpent, 0n)
  t.is(rootSnap.commandsSpent, 0)

  // Child 1 charges 10 cells, 12000n bytes, 1 command
  chargePeerLedger(child1, { cells: 10, bytes: 12000n, commands: 1 })

  rootSnap = readPeerLedger(root)
  t.is(rootSnap.cellsRemaining, 60) // Extra 60 cells / 72000n bytes / 6 commands remain reservable!
  t.is(rootSnap.bytesRemaining, 72000n)
  t.is(rootSnap.commandsRemaining, 6)
  t.is(rootSnap.cellsReserved, 30)
  t.is(rootSnap.bytesReserved, 36000n)
  t.is(rootSnap.commandsReserved, 3)
  t.is(rootSnap.cellsSpent, 10)
  t.is(rootSnap.bytesSpent, 12000n)
  t.is(rootSnap.commandsSpent, 1)

  const child1Snap = readPeerLedger(child1)
  t.is(child1Snap.cellsRemaining, 30)
  t.is(child1Snap.bytesRemaining, 36000n)
  t.is(child1Snap.commandsRemaining, 3)
  t.is(child1Snap.cellsSpent, 10)
  t.is(child1Snap.bytesSpent, 12000n)
  t.is(child1Snap.commandsSpent, 1)

  // Reserve Sibling (Child 2) for exact remaining 60 cells / 72000n bytes / 6 commands while Child 1 is live
  const child2 = reservePeerLedger(root, { cells: 60, bytes: 72000n, commands: 6 })

  rootSnap = readPeerLedger(root)
  t.is(rootSnap.cellsRemaining, 0)
  t.is(rootSnap.bytesRemaining, 0n)
  t.is(rootSnap.commandsRemaining, 0)
  t.is(rootSnap.cellsReserved, 90) // 30 (child1 unspent) + 60 (child2)
  t.is(rootSnap.bytesReserved, 108000n)
  t.is(rootSnap.commandsReserved, 9)
  t.is(rootSnap.cellsSpent, 10)

  // Release Child 1 (unspent 30 cells / 36000n bytes / 3 commands return to root)
  t.ok(releasePeerLedger(child1))

  rootSnap = readPeerLedger(root)
  t.is(rootSnap.cellsRemaining, 30)
  t.is(rootSnap.bytesRemaining, 36000n)
  t.is(rootSnap.commandsRemaining, 3)
  t.is(rootSnap.cellsReserved, 60)
  t.is(rootSnap.bytesReserved, 72000n)
  t.is(rootSnap.commandsReserved, 6)
  t.is(rootSnap.cellsSpent, 10)

  // Release Child 2
  t.ok(releasePeerLedger(child2))

  rootSnap = readPeerLedger(root)
  t.is(rootSnap.cellsRemaining, 90)
  t.is(rootSnap.bytesRemaining, 108000n)
  t.is(rootSnap.commandsRemaining, 9)
  t.is(rootSnap.cellsReserved, 0)
  t.is(rootSnap.bytesReserved, 0n)
  t.is(rootSnap.commandsReserved, 0)
  t.is(rootSnap.cellsSpent, 10)
  t.is(rootSnap.bytesSpent, 12000n)
  t.is(rootSnap.commandsSpent, 1)
})

test('peer ledger insufficient capacity leaves parent snapshot unchanged', (t) => {
  const parent = createPeerLedger({ cells: 100, bytes: 120000n, commands: 10 })
  const before = readPeerLedger(parent)

  expectInvalid(t, () => reservePeerLedger(parent, { cells: 101, bytes: 120000n, commands: 10 }))
  expectInvalid(t, () => reservePeerLedger(parent, { cells: 100, bytes: 120001n, commands: 10 }))
  expectInvalid(t, () => reservePeerLedger(parent, { cells: 100, bytes: 120000n, commands: 11 }))

  const after = readPeerLedger(parent)
  t.alike(after, before)
})

test('fully reserved grandparent-parent-child chain with unequal charges, remaining=0, and exact post-release state', (t) => {
  const grandparent = createPeerLedger({ cells: 100, bytes: 120000n, commands: 10 })
  const parent = reservePeerLedger(grandparent, { cells: 100, bytes: 120000n, commands: 10 })
  const child = reservePeerLedger(parent, { cells: 100, bytes: 120000n, commands: 10 })

  // Verify before charge: all remaining are 0 for ancestors
  let gpSnap = readPeerLedger(grandparent)
  let pSnap = readPeerLedger(parent)
  let cSnap = readPeerLedger(child)

  t.is(gpSnap.cellsRemaining, 0)
  t.is(gpSnap.bytesRemaining, 0n)
  t.is(gpSnap.commandsRemaining, 0)

  t.is(pSnap.cellsRemaining, 0)
  t.is(pSnap.bytesRemaining, 0n)
  t.is(pSnap.commandsRemaining, 0)

  t.is(cSnap.cellsRemaining, 100)
  t.is(cSnap.bytesRemaining, 120000n)
  t.is(cSnap.commandsRemaining, 10)

  // Charge unequal 7 cells, 9600n bytes, 2 commands
  chargePeerLedger(child, { cells: 7, bytes: 9600n, commands: 2 })

  // Assert before release: both ancestors' cells/bytes/commands remaining are 0
  // and reserved are 93 / 110400n / 8
  gpSnap = readPeerLedger(grandparent)
  pSnap = readPeerLedger(parent)
  cSnap = readPeerLedger(child)

  t.is(gpSnap.cellsRemaining, 0)
  t.is(gpSnap.bytesRemaining, 0n)
  t.is(gpSnap.commandsRemaining, 0)
  t.is(gpSnap.cellsReserved, 93)
  t.is(gpSnap.bytesReserved, 110400n)
  t.is(gpSnap.commandsReserved, 8)
  t.is(gpSnap.cellsSpent, 7)
  t.is(gpSnap.bytesSpent, 9600n)
  t.is(gpSnap.commandsSpent, 2)

  t.is(pSnap.cellsRemaining, 0)
  t.is(pSnap.bytesRemaining, 0n)
  t.is(pSnap.commandsRemaining, 0)
  t.is(pSnap.cellsReserved, 93)
  t.is(pSnap.bytesReserved, 110400n)
  t.is(pSnap.commandsReserved, 8)
  t.is(pSnap.cellsSpent, 7)
  t.is(pSnap.bytesSpent, 9600n)
  t.is(pSnap.commandsSpent, 2)

  t.is(cSnap.cellsRemaining, 93)
  t.is(cSnap.bytesRemaining, 110400n)
  t.is(cSnap.commandsRemaining, 8)
  t.is(cSnap.cellsSpent, 7)
  t.is(cSnap.bytesSpent, 9600n)
  t.is(cSnap.commandsSpent, 2)

  // Release child
  t.ok(releasePeerLedger(child))

  gpSnap = readPeerLedger(grandparent)
  pSnap = readPeerLedger(parent)

  t.is(pSnap.cellsReserved, 0)
  t.is(pSnap.bytesReserved, 0n)
  t.is(pSnap.commandsReserved, 0)
  t.is(pSnap.cellsSpent, 7)
  t.is(pSnap.bytesSpent, 9600n)
  t.is(pSnap.commandsSpent, 2)
  t.is(pSnap.cellsRemaining, 93)
  t.is(pSnap.bytesRemaining, 110400n)
  t.is(pSnap.commandsRemaining, 8)

  t.is(gpSnap.cellsReserved, 93)
  t.is(gpSnap.bytesReserved, 110400n)
  t.is(gpSnap.commandsReserved, 8)

  // Release parent
  t.ok(releasePeerLedger(parent))

  gpSnap = readPeerLedger(grandparent)

  t.is(gpSnap.cellsReserved, 0)
  t.is(gpSnap.bytesReserved, 0n)
  t.is(gpSnap.commandsReserved, 0)
  t.is(gpSnap.cellsSpent, 7)
  t.is(gpSnap.bytesSpent, 9600n)
  t.is(gpSnap.commandsSpent, 2)
  t.is(gpSnap.cellsRemaining, 93)
  t.is(gpSnap.bytesRemaining, 110400n)
  t.is(gpSnap.commandsRemaining, 8)
})

test('memory pool double-take and idempotent release', (t) => {
  const pool = createPeerMemoryPool(10000)
  const res = reservePeerMemory(pool, 'canonical-cache', 4000)

  const childPool = takePeerMemory(res)
  expectInvalid(t, () => takePeerMemory(res))

  t.ok(releasePeerMemory(childPool))
  t.is(releasePeerMemory(childPool), false)

  t.is(releasePeerMemory(res), false)

  const ledger = createPeerLedger({ cells: 10, bytes: 12000n, commands: 1 })
  t.ok(releasePeerLedger(ledger))
  t.is(releasePeerLedger(ledger), false)
})

test('pending purpose narrowing returns only excess and retains spent and nested ownership', (t) => {
  const root = createPeerLedger({ cells: 100, bytes: 120000n, commands: 10 })
  const parent = reservePeerLedger(root, { cells: 80, bytes: 96000n, commands: 8 })
  const child = reservePeerLedger(parent, { cells: 60, bytes: 72000n, commands: 6 })
  chargePeerLedger(child, { cells: 10, bytes: 12000n, commands: 1 })
  const pool = createPeerMemoryPool(1000)
  const pending = reservePeerMemory(pool, 'pending-purpose', 800)

  narrowPeerReservations({
    ledgers: [
      { ledger: parent, cells: 40, bytes: 48000n, commands: 4 },
      { ledger: child, cells: 30, bytes: 36000n, commands: 3 }
    ],
    memory: [{ reservation: pending, capacityBytes: 500 }]
  })
  t.is(readPeerLedger(root).cellsRemaining, 60)
  t.is(readPeerLedger(parent).cellsRemaining, 10)
  t.is(readPeerLedger(child).cellsRemaining, 20)
  t.is(readPeerMemory(pool).remainingBytes, 500)
  const sibling = reservePeerLedger(root, { cells: 60, bytes: 72000n, commands: 6 })
  const siblingMemory = reservePeerMemory(pool, 'sibling-purpose', 500)
  chargePeerLedger(child, { cells: 20, bytes: 24000n, commands: 2 })
  expectInvalid(t, () => chargePeerLedger(child, { cells: 1, bytes: 1200n, commands: 0 }))
  const activePool = takePeerMemory(pending)
  const buffer = reservePeerMemory(activePool, 'active-storage', 500)
  expectInvalid(t, () => reservePeerMemory(activePool, 'overflow', 1))
  releasePeerLedger(parent)
  releasePeerMemory(pending)
  t.is(readPeerLedger(root).cellsSpent, 30)
  t.is(readPeerLedger(root).cellsReserved, 60)
  t.is(readPeerMemory(pool).reservedBytes, 500)
  t.is(readPeerMemory(buffer).released, true)
  chargePeerLedger(sibling, { cells: 60, bytes: 72000n, commands: 6 })
  t.is(readPeerLedger(root).cellsSpent, 90)
  t.is(readPeerMemory(siblingMemory).released, false)
  releasePeerLedger(sibling)
  releasePeerMemory(siblingMemory)
  t.is(readPeerMemory(pool).reservedBytes, 0)
})

test('failed purpose narrowing never partially returns directional or storage quota', (t) => {
  const root = createPeerLedger({ cells: 100, bytes: 120000n, commands: 10 })
  const forward = reservePeerLedger(root, { cells: 50, bytes: 60000n, commands: 5 })
  const reverse = reservePeerLedger(root, { cells: 50, bytes: 60000n, commands: 5 })
  chargePeerLedger(reverse, { cells: 30, bytes: 36000n, commands: 3 })
  const pool = createPeerMemoryPool(1000)
  const pending = reservePeerMemory(pool, 'pending-purpose', 500)
  const taken = reservePeerMemory(pool, 'live-storage', 500)
  takePeerMemory(taken)
  const snapshot = () => [
    readPeerLedger(root),
    readPeerLedger(forward),
    readPeerLedger(reverse),
    readPeerMemory(pool),
    readPeerMemory(pending),
    readPeerMemory(taken)
  ]
  const before = snapshot()
  expectInvalid(t, () =>
    narrowPeerReservations({
      ledgers: [
        { ledger: forward, cells: 20, bytes: 24000n, commands: 2 },
        { ledger: reverse, cells: 20, bytes: 24000n, commands: 2 }
      ],
      memory: [{ reservation: pending, capacityBytes: 200 }]
    })
  )
  t.alike(snapshot(), before)
  expectInvalid(t, () =>
    narrowPeerReservations({
      ledgers: [{ ledger: forward, cells: 20, bytes: 24000n, commands: 2 }],
      memory: [
        { reservation: pending, capacityBytes: 200 },
        { reservation: taken, capacityBytes: 200 }
      ]
    })
  )
  t.alike(snapshot(), before)
  expectInvalid(t, () =>
    narrowPeerReservations({
      ledgers: [
        { ledger: forward, cells: 20, bytes: 24000n, commands: 2 },
        { ledger: forward, cells: 20, bytes: 24000n, commands: 2 }
      ],
      memory: []
    })
  )
  t.alike(snapshot(), before)
  releasePeerLedger(root)
  releasePeerMemory(pool)
})

test('pending narrowing uses descriptor-only arrays and rejects failed snapshots atomically', (t) => {
  const root = createPeerLedger({ cells: 100, bytes: 120000n, commands: 10 })
  const child = reservePeerLedger(root, { cells: 60, bytes: 72000n, commands: 6 })
  const rows = new Proxy([{ ledger: child, cells: 30, bytes: 36000n, commands: 3 }], {
    get() {
      throw new Error('ordinary property access is not authorized')
    }
  })
  narrowPeerReservations({ ledgers: rows, memory: [] })
  t.is(readPeerLedger(root).cellsRemaining, 70)
  t.is(readPeerLedger(child).cellsAllocated, 30)
  const before = [readPeerLedger(root), readPeerLedger(child)]
  expectInvalid(t, () =>
    narrowPeerReservations({
      ledgers: [{ ledger: child, cells: 20, bytes: 24000n, commands: 2 }],
      memory: new Proxy([], {
        getOwnPropertyDescriptor() {
          throw new Error('snapshot failed')
        }
      })
    })
  )
  t.alike([readPeerLedger(root), readPeerLedger(child)], before)
  const later = Proxy.revocable({ ledger: child, cells: 20, bytes: 24000n, commands: 2 }, {})
  const earlier = new Proxy(
    { ledger: child, cells: 20, bytes: 24000n, commands: 2 },
    {
      getOwnPropertyDescriptor(target, key) {
        later.revoke()
        return Reflect.getOwnPropertyDescriptor(target, key)
      }
    }
  )
  expectInvalid(t, () => narrowPeerReservations({ ledgers: [earlier, later.proxy], memory: [] }))
  t.alike([readPeerLedger(root), readPeerLedger(child)], before)
  releasePeerLedger(root)
})
