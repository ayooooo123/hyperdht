'use strict'

// The discovered-endpoint plan. Roles on separate hosts learn their own reachable
// address, so the topology has to be minted from those values instead of the
// derived 127.64.x.1 tuples, and nothing about the derived plans may shift.

const test = require('brittle')
const b4a = require('b4a')

const { createCoherentTestClock } = require('./coherent-clock')
const {
  PROCESS_PLANS,
  ROLES,
  TEST_ONLY_PROCESS_TOPOLOGY_ISSUER,
  createLiveProcessTopology
} = require('./process/topology-fixture')

function capabilities(seed) {
  return {
    clocks: TEST_ONLY_PROCESS_TOPOLOGY_ISSUER.clocks(createCoherentTestClock()),
    entropy: TEST_ONLY_PROCESS_TOPOLOGY_ISSUER.entropy(b4a.alloc(32, seed))
  }
}

// Two tuples per role: what the role binds locally, and what peers must dial. On
// separate hosts these differ, which is the whole reason the plan exists.
const EXIT_INDEXES = [4, 6, 8]

function endpoints(overrides = {}) {
  const list = ROLES.map((role, index) => {
    const entry = {
      bind: { host: '0.0.0.0', port: 42_000 + index + 1 },
      reachable: { host: `203.0.113.${index + 1}`, port: 52_000 + index + 1 }
    }
    // Only an exit owns a second socket for reaching DHT nodes, and behind a NAT it
    // has its own mapping, so only an exit publishes one.
    if (EXIT_INDEXES.includes(index + 1)) {
      entry.dhtExit = { host: `203.0.113.${index + 1}`, port: 62_000 + index + 1 }
    }
    return entry
  })
  for (const [index, value] of Object.entries(overrides)) list[Number(index)] = value
  return list
}

function throws(t, fn, message) {
  let threw = false
  try {
    fn()
  } catch {
    threw = true
  }
  t.ok(threw, message)
}

test('a discovered-endpoint topology binds exactly the endpoints it was given', (t) => {
  const supplied = endpoints()
  const topology = createLiveProcessTopology({
    plan: PROCESS_PLANS.DHT_MESH,
    endpoints: supplied,
    ...capabilities(0x41)
  })

  t.is(topology.projections.length, ROLES.length, 'every role is projected')
  t.alike(
    topology.oracle.tuples.map((tuple) => ({ host: tuple.host, port: tuple.port })),
    supplied.map((entry) => entry.reachable),
    'the published tuples are the reachable addresses, not the bind addresses'
  )
  const exitDht = supplied
    .filter((entry, index) => EXIT_INDEXES.includes(index + 1))
    .map((entry) => entry.dhtExit)
  t.alike(
    topology.projections[0].meshPeers.exitDht,
    exitDht,
    'every projection carries the exits DHT-exit addresses, which no role can derive'
  )
  t.alike(
    topology.projections[0].meshPeers.tuples,
    supplied.map((entry) => entry.reachable),
    'and the reachable address of every role'
  )
  t.is(
    topology.oracle.endpointAddress,
    supplied[0].reachable.host,
    'the leak oracle watches the reachable endpoint address'
  )
  for (let index = 0; index < ROLES.length; index++) {
    const projection = topology.projections[index]
    t.is(projection.role, ROLES[index], `role ${index + 1} keeps its position`)
    t.alike(
      { host: projection.bind.host, port: projection.bind.port },
      supplied[index].bind,
      `role ${index + 1} binds its own local address`
    )
  }
})

test('the derived plans keep their own addresses and reject endpoints', (t) => {
  const derived = createLiveProcessTopology({
    plan: PROCESS_PLANS.PORTABLE_LOOPBACK,
    ...capabilities(0x42)
  })
  t.alike(
    { host: derived.projections[0].bind.host, port: derived.projections[0].bind.port },
    { host: '127.64.1.1', port: 42_001 },
    'portable loopback still derives 127.64.1.1'
  )

  throws(
    t,
    () =>
      createLiveProcessTopology({
        plan: PROCESS_PLANS.PORTABLE_LOOPBACK,
        endpoints: endpoints(),
        ...capabilities(0x43)
      }),
    'a derived plan refuses supplied endpoints'
  )
  throws(
    t,
    () => createLiveProcessTopology({ plan: PROCESS_PLANS.DHT_MESH, ...capabilities(0x44) }),
    'the discovered plan refuses to be built without endpoints'
  )
})

test('endpoint lists are validated before anything is minted', (t) => {
  const cases = [
    [
      'a duplicate reachable address',
      endpoints({
        1: {
          bind: { host: '0.0.0.0', port: 42_002 },
          reachable: { host: '203.0.113.1', port: 52_001 }
        }
      })
    ],
    [
      'a name instead of an address',
      endpoints({
        0: {
          bind: { host: '0.0.0.0', port: 42_001 },
          reachable: { host: 'example.com', port: 52_001 }
        }
      })
    ],
    [
      'an octet above 255',
      endpoints({
        0: {
          bind: { host: '0.0.0.0', port: 42_001 },
          reachable: { host: '203.0.113.256', port: 52_001 }
        }
      })
    ],
    [
      'port zero',
      endpoints({
        0: { bind: { host: '0.0.0.0', port: 0 }, reachable: { host: '203.0.113.1', port: 52_001 } }
      })
    ],
    [
      'a port above 65535',
      endpoints({
        0: {
          bind: { host: '0.0.0.0', port: 42_001 },
          reachable: { host: '203.0.113.1', port: 65_536 }
        }
      })
    ],
    [
      'a missing bind tuple',
      endpoints({ 0: { reachable: { host: '203.0.113.1', port: 52_001 } } })
    ],
    [
      'an extra field',
      endpoints({
        0: {
          bind: { host: '0.0.0.0', port: 42_001 },
          reachable: { host: '203.0.113.1', port: 52_001 },
          family: 4
        }
      })
    ],
    ['too few entries', endpoints().slice(1)],
    [
      'too many entries',
      [
        ...endpoints(),
        {
          bind: { host: '0.0.0.0', port: 42_099 },
          reachable: { host: '203.0.113.99', port: 52_099 }
        }
      ]
    ],
    ['not an array', { 0: endpoints()[0] }],
    [
      'an exit without its DHT-exit address',
      endpoints({
        3: {
          bind: { host: '0.0.0.0', port: 42_004 },
          reachable: { host: '203.0.113.4', port: 52_004 }
        }
      })
    ],
    [
      'a non-exit carrying a DHT-exit address',
      endpoints({
        0: {
          bind: { host: '0.0.0.0', port: 42_001 },
          reachable: { host: '203.0.113.1', port: 52_001 },
          dhtExit: { host: '203.0.113.1', port: 62_001 }
        }
      })
    ]
  ]

  let seed = 0x50
  for (const [label, value] of cases) {
    throws(
      t,
      () =>
        createLiveProcessTopology({
          plan: PROCESS_PLANS.DHT_MESH,
          endpoints: value,
          ...capabilities(seed++)
        }),
      `${label} is refused`
    )
  }
})

test('the network authority covers the supplied endpoints', (t) => {
  const supplied = endpoints()
  const authority = TEST_ONLY_PROCESS_TOPOLOGY_ISSUER.authority(PROCESS_PLANS.DHT_MESH, supplied)
  t.ok(authority, 'an authority is issued for the discovered plan')
  throws(
    t,
    () => TEST_ONLY_PROCESS_TOPOLOGY_ISSUER.authority(PROCESS_PLANS.DHT_MESH),
    'the discovered plan has no authority without endpoints'
  )
})
