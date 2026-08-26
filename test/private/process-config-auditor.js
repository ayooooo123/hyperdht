'use strict'

const test = require('brittle')
const b4a = require('b4a')

const HyperDHT = require('../..')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { decodeTopologyGrant, verifyTopologyGrant } = require('../../lib/private/topology-grant')
const {
  ALLOW_EDGES,
  PROCESS_PLANS,
  ROLES,
  TEST_ONLY_PROCESS_TOPOLOGY_ISSUER,
  createLiveProcessTopology,
  validateNamespaceProjection
} = require('./process/topology-fixture')
const { createProcessConfigAuditor } = require('./process/config-auditor')

function throwsCode(t, fn, code = 'PROCESS_CONFIG_INVALID') {
  let error = null
  try {
    fn()
  } catch (err) {
    error = err
  }
  t.ok(error)
  t.is(error && error.code, code)
}

function capabilities(seed = 7) {
  const clocks = TEST_ONLY_PROCESS_TOPOLOGY_ISSUER.clocks({
    monotonicNow: () => 10_000n,
    wallNow: () => 1_000_000n
  })
  const entropy = TEST_ONLY_PROCESS_TOPOLOGY_ISSUER.entropy(b4a.alloc(32, seed))
  return { clocks, entropy }
}

function topology(plan = PROCESS_PLANS.PORTABLE_LOOPBACK, seed = 7, candidateOrder = 'normal') {
  return createLiveProcessTopology({ candidateOrder, plan, ...capabilities(seed) })
}

function clone(value, seen = new Map()) {
  if (b4a.isBuffer(value)) return b4a.from(value)
  if (value === null || typeof value !== 'object') return value
  if (seen.has(value)) return seen.get(value)
  if (Array.isArray(value)) {
    const out = []
    seen.set(value, out)
    for (const entry of value) out.push(clone(entry, seen))
    return out
  }
  if (value instanceof Map) {
    const out = new Map()
    seen.set(value, out)
    for (const [key, entry] of value) out.set(clone(key, seen), clone(entry, seen))
    return out
  }
  if (value instanceof Set) {
    const out = new Set()
    seen.set(value, out)
    for (const entry of value) out.add(clone(entry, seen))
    return out
  }
  const out = {}
  seen.set(value, out)
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    if (descriptor && 'value' in descriptor) out[key] = clone(descriptor.value, seen)
  }
  return out
}

function collectTuplePaths(value, path = [], out = []) {
  if (value === null || typeof value !== 'object' || b4a.isBuffer(value)) return out
  if (
    Object.getPrototypeOf(value) === Object.prototype &&
    Reflect.ownKeys(value).length === 2 &&
    Object.prototype.hasOwnProperty.call(value, 'host') &&
    Object.prototype.hasOwnProperty.call(value, 'port')
  ) {
    out.push(path)
    return out
  }
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index++)
      collectTuplePaths(value[index], [...path, index], out)
    return out
  }
  for (const key of Reflect.ownKeys(value)) collectTuplePaths(value[key], [...path, key], out)
  return out
}

function replaceAtPath(value, path, replacement) {
  let target = value
  for (let index = 0; index < path.length - 1; index++) target = target[path[index]]
  target[path[path.length - 1]] = replacement
}

test('process topology freezes exact role order plans and numeric tuples', (t) => {
  t.alike(ROLES, [
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
  ])
  t.ok(Object.isFrozen(ROLES))
  t.ok(Object.isFrozen(PROCESS_PLANS.PORTABLE_LOOPBACK))
  t.ok(Object.isFrozen(PROCESS_PLANS.LINUX_NAMESPACE))

  for (const [plan, prefix] of [
    [PROCESS_PLANS.PORTABLE_LOOPBACK, '127.64'],
    [PROCESS_PLANS.LINUX_NAMESPACE, '10.203']
  ]) {
    const fixture = topology(plan)
    t.is(fixture.projections.length, 11)
    for (let index = 0; index < fixture.projections.length; index++) {
      const projection = fixture.projections[index]
      t.is(projection.role, ROLES[index])
      t.is(projection.roleIndex, index + 1)
      t.alike(projection.bind, {
        host: `${prefix}.${index + 1}.${plan === PROCESS_PLANS.PORTABLE_LOOPBACK ? 1 : 2}`,
        port: 42_001 + index
      })
      t.ok(Object.isFrozen(projection))
      t.ok(Object.isFrozen(projection.bind))
    }
    fixture.stop()
  }
})

test('topology accepts only trusted exact frozen plan clock and entropy capabilities', (t) => {
  const { clocks, entropy } = capabilities()
  throwsCode(t, () =>
    createLiveProcessTopology({ plan: { name: 'portable-loopback' }, clocks, entropy })
  )
  throwsCode(t, () =>
    createLiveProcessTopology({ plan: PROCESS_PLANS.PORTABLE_LOOPBACK, clocks: {}, entropy })
  )
  throwsCode(t, () =>
    createLiveProcessTopology({ plan: PROCESS_PLANS.PORTABLE_LOOPBACK, clocks, entropy: {} })
  )
  throwsCode(t, () =>
    createLiveProcessTopology({
      plan: PROCESS_PLANS.PORTABLE_LOOPBACK,
      clocks,
      entropy,
      fallback: true
    })
  )

  throwsCode(t, () => TEST_ONLY_PROCESS_TOPOLOGY_ISSUER.authority({ name: 'portable-loopback' }))
  throwsCode(t, () => TEST_ONLY_PROCESS_TOPOLOGY_ISSUER.authority([]))
})

test('topology authority derives only the exact plan tuples and allow edges', (t) => {
  for (const plan of [PROCESS_PLANS.PORTABLE_LOOPBACK, PROCESS_PLANS.LINUX_NAMESPACE]) {
    const authority = TEST_ONLY_PROCESS_TOPOLOGY_ISSUER.authority(plan)
    const fixture = topology(plan)
    for (const [left, right] of ALLOW_EDGES) {
      t.is(
        authority.permits(fixture.projections[left - 1].bind, fixture.projections[right - 1].bind),
        true
      )
      t.is(
        authority.permits(fixture.projections[right - 1].bind, fixture.projections[left - 1].bind),
        true
      )
    }
    t.is(authority.permits(fixture.projections[0].bind, fixture.projections[2].bind), false)
    t.is(authority.permits(fixture.projections[0].bind, fixture.projections[3].bind), false)
    t.is(
      authority.permits(fixture.projections[0].bind, {
        host: fixture.projections[1].bind.host,
        port: fixture.projections[1].bind.port + 1
      }),
      false
    )
    fixture.stop()
  }
})

test('topology freezes full middle-exit matrix and reorder-safe candidate records', (t) => {
  const normal = topology(PROCESS_PLANS.PORTABLE_LOOPBACK, 7, 'normal')
  const reverse = topology(PROCESS_PLANS.PORTABLE_LOOPBACK, 8, 'reverse')
  for (const fixture of [normal, reverse]) {
    for (const middle of fixture.projections.filter((projection) =>
      /-middle/.test(projection.role)
    )) {
      t.is(middle.adjacencies.length, 4)
      t.is(middle.grants.length, 4)
    }
    for (const exit of fixture.projections.filter((projection) => /-exit/.test(projection.role))) {
      t.is(exit.middleAdjacencies.length, 3)
      t.is(exit.middleGrants.length, 3)
    }
    const records = fixture.projections[1].candidateAdvertisements
    t.alike(
      records.map((record) => record.roleIndex).sort((left, right) => left - right),
      [3, 4, 5, 6, 7, 8]
    )
    t.ok(records.every((record) => b4a.isBuffer(record.advertisement)))
  }
  t.unlike(
    normal.projections[1].candidateAdvertisements.map((record) => record.roleIndex),
    reverse.projections[1].candidateAdvertisements.map((record) => record.roleIndex)
  )
  normal.stop()
  reverse.stop()
})

test('topology freezes DHT referral layout', (t) => {
  const fixture = topology()
  const seed = fixture.projections[8]
  const referral = fixture.projections[9]
  const value = fixture.projections[10]
  t.alike(seed.dhtOptions, {
    anyPort: false,
    bootstrap: [],
    ephemeral: false,
    firewalled: false,
    host: '127.64.9.1',
    nodes: [{ host: '127.64.10.1', port: 42_010 }],
    port: 42_009
  })
  t.alike(referral.dhtOptions.nodes, [{ host: '127.64.11.1', port: 42_011 }])
  t.alike(referral.dhtOptions.bootstrap, [])
  t.alike(value.dhtOptions.bootstrap, [{ host: '127.64.11.1', port: 42_011 }])
  t.ok(Object.isFrozen(value.dhtOptions.bootstrap[0]))
  t.alike(value.dhtOptions.nodes, [])
  for (const projection of [seed, referral, value]) t.ok(Object.isFrozen(projection.dhtOptions))
  t.is(referral.storedValue, undefined)
  t.is(value.storedValue, undefined)
  fixture.stop()
})

test('allow graph contains only frozen exact bidirectional role edges', (t) => {
  t.alike(ALLOW_EDGES, [
    [1, 2],
    [2, 3],
    [2, 5],
    [2, 7],
    [3, 4],
    [3, 6],
    [3, 8],
    [4, 5],
    [4, 7],
    [5, 6],
    [5, 8],
    [6, 7],
    [7, 8],
    [4, 9],
    [4, 10],
    [4, 11],
    [6, 9],
    [6, 10],
    [6, 11],
    [8, 9],
    [8, 10],
    [8, 11],
    [9, 10],
    [9, 11],
    [10, 11]
  ])
  t.ok(Object.isFrozen(ALLOW_EDGES))
  for (const edge of ALLOW_EDGES) t.ok(Object.isFrozen(edge))

  const fixture = topology()
  for (const [left, right] of ALLOW_EDGES) {
    t.is(
      fixture.oracle.networkAuthority.permits(
        fixture.projections[left - 1].bind,
        fixture.projections[right - 1].bind
      ),
      true
    )
    t.is(
      fixture.oracle.networkAuthority.permits(
        fixture.projections[right - 1].bind,
        fixture.projections[left - 1].bind
      ),
      true
    )
  }
  t.is(
    fixture.oracle.networkAuthority.permits(
      fixture.projections[0].bind,
      fixture.projections[3].bind
    ),
    false
  )
  fixture.stop()
})

test('namespace projection freezes role and bidirectional marker route authority', (t) => {
  const portable = topology(PROCESS_PLANS.PORTABLE_LOOPBACK, 12)
  t.is(portable.oracle.namespace, null)
  portable.stop()

  const fixture = topology(PROCESS_PLANS.LINUX_NAMESPACE)
  const namespace = fixture.oracle.namespace
  t.is(validateNamespaceProjection(namespace), true)
  for (const role of namespace.roles) {
    t.is(role.gateway, `10.203.${role.roleIndex}.1`)
    t.is(role.prefix, 24)
    for (const route of role.routes) {
      t.ok(route.destination.endsWith('.2/32'))
      t.is(route.gateway, role.gateway)
    }
  }
  t.alike(namespace.marker, {
    auditor: {
      device: 'pr-veth-auditor',
      gateway: '10.204.1.1',
      host: '10.204.1.2',
      port: 42_990,
      routes: [
        {
          destination: '10.204.2.2/32',
          device: 'pr-veth-auditor',
          gateway: '10.204.1.1'
        }
      ]
    },
    decoy: {
      device: 'pr-veth-decoy',
      gateway: '10.204.2.1',
      host: '10.204.2.2',
      port: 42_991,
      routes: [
        {
          destination: '10.204.1.2/32',
          device: 'pr-veth-decoy',
          gateway: '10.204.2.1'
        }
      ]
    }
  })
  const markerRules = namespace.firewall.filter((rule) => rule.source.startsWith('10.204.'))
  t.alike(markerRules, [
    {
      destination: '10.204.2.2',
      destinationPort: 42_991,
      egress: 'pr-veth-decoy',
      ingress: 'pr-veth-auditor',
      protocol: 'udp',
      source: '10.204.1.2',
      sourcePort: 42_990
    },
    {
      destination: '10.204.1.2',
      destinationPort: 42_990,
      egress: 'pr-veth-auditor',
      ingress: 'pr-veth-decoy',
      protocol: 'udp',
      source: '10.204.2.2',
      sourcePort: 42_991
    }
  ])
  t.is(namespace.firewall.length, ALLOW_EDGES.length * 2 + 2)
  for (const rule of namespace.firewall) {
    t.is(rule.protocol, 'udp')
    t.ok(rule.ingress.startsWith('pr-veth-'))
    t.ok(rule.egress.startsWith('pr-veth-'))
  }

  const missing = clone(namespace)
  missing.roles[1].routes.shift()
  throwsCode(t, () => validateNamespaceProjection(missing))
  const defaultRoute = clone(namespace)
  defaultRoute.roles[0].routes.push({
    destination: '0.0.0.0/0',
    device: 'pr-veth-1',
    gateway: '10.203.1.1'
  })
  throwsCode(t, () => validateNamespaceProjection(defaultRoute))
  const broad = clone(namespace)
  broad.roles[0].routes.push({
    destination: '10.203.0.0/16',
    device: 'pr-veth-1',
    gateway: '10.203.1.1'
  })
  throwsCode(t, () => validateNamespaceProjection(broad))
  const cross = clone(namespace)
  cross.firewall.push({
    destination: '10.203.4.2',
    destinationPort: 42_004,
    egress: 'pr-veth-4',
    ingress: 'pr-veth-1',
    protocol: 'udp',
    source: '10.203.1.2',
    sourcePort: 42_001
  })
  throwsCode(t, () => validateNamespaceProjection(cross))
  const noReply = clone(namespace)
  noReply.firewall.pop()
  throwsCode(t, () => validateNamespaceProjection(noReply))
  const noMarkerRoute = clone(namespace)
  noMarkerRoute.marker.auditor.routes.length = 0
  throwsCode(t, () => validateNamespaceProjection(noMarkerRoute))
  const outsidePair = clone(namespace)
  outsidePair.firewall[outsidePair.firewall.length - 1].destination = '10.203.1.2'
  throwsCode(t, () => validateNamespaceProjection(outsidePair))
  const extra = clone(namespace)
  extra.marker.auditor.extra = true
  throwsCode(t, () => validateNamespaceProjection(extra))
  const symbol = clone(namespace)
  symbol.marker.decoy[Symbol('hidden')] = true
  throwsCode(t, () => validateNamespaceProjection(symbol))
  const accessor = clone(namespace)
  let reads = 0
  Object.defineProperty(accessor.marker.auditor, 'host', {
    enumerable: true,
    get() {
      reads++
      return '10.204.1.2'
    }
  })
  throwsCode(t, () => validateNamespaceProjection(accessor))
  t.is(reads, 0)
  fixture.stop()
})

test('all eleven role projections pass exact ambient-authority policy', (t) => {
  const fixture = topology()
  const auditor = createProcessConfigAuditor(fixture.oracle)
  for (const projection of fixture.projections) t.is(auditor.auditProjection(projection), true)
  t.is(auditor.auditAll(fixture.projections), true)
  auditor.destroy()
  fixture.stop()
})

test('endpoint owns the exact Ed25519 identity secret and no other role can receive it', (t) => {
  const fixture = topology()
  const auditor = createProcessConfigAuditor(fixture.oracle)
  const endpoint = fixture.projections[0]
  const secret = endpoint.localIdentitySecretKey
  t.ok(b4a.isBuffer(secret))
  t.is(secret.byteLength, 64)
  const derived = cryptoSuite.keyPair(secret.subarray(0, 32))
  try {
    t.alike(derived.publicKey, endpoint.identityPublicKey)
  } finally {
    derived.secretKey.fill(0)
  }
  for (const projection of fixture.projections.slice(1))
    t.is(projection.localIdentitySecretKey, undefined)

  const mutated = clone(endpoint)
  mutated.localIdentitySecretKey = b4a.alloc(64, 0xff)
  throwsCode(t, () => auditor.auditProjection(mutated))
  for (const projection of fixture.projections.slice(1)) {
    const leaked = clone(projection)
    leaked.localIdentitySecretKey = b4a.from(secret)
    throwsCode(t, () => auditor.auditProjection(leaked))
  }
  throwsCode(t, () => auditor.auditEvent('guard', { localIdentitySecretKey: b4a.from(secret) }))
  auditor.destroy()
  fixture.stop()
})

test('link-grant roles own exact topology verification context only', (t) => {
  const fixture = topology()
  const auditor = createProcessConfigAuditor(fixture.oracle)
  const linkRoles = fixture.projections.slice(0, 8)
  const dhtRoles = fixture.projections.slice(8)
  for (const projection of linkRoles) {
    t.is(projection.topologyAuthoritySecretKey, undefined)
    t.is(projection.topologyAuthorityPublicKey.byteLength, 32)
    t.is(projection.topologyRunId.byteLength, 32)
    t.is(projection.topologyEpoch, 1n)
    const grants = []
    for (const name of ['guardGrant', 'middleGrant']) {
      if (projection[name]) grants.push(projection[name])
    }
    for (const name of ['middleGrants', 'grants']) {
      if (projection[name]) grants.push(...projection[name])
    }
    t.ok(grants.length > 0)
    for (const grant of grants) {
      const decoded = decodeTopologyGrant(grant)
      t.alike(decoded.runId32, projection.topologyRunId)
      t.is(decoded.epoch, projection.topologyEpoch)
      t.ok(
        verifyTopologyGrant(grant, projection.topologyAuthorityPublicKey, {
          localIdentity32: projection.identityPublicKey,
          now: 1_000_000n
        })
      )
    }
    for (const [name, value] of [
      ['topologyAuthorityPublicKey', b4a.alloc(32, 0xff)],
      ['topologyRunId', b4a.alloc(32, 0xff)],
      ['topologyEpoch', 2n]
    ]) {
      const mutated = clone(projection)
      mutated[name] = value
      throwsCode(t, () => auditor.auditProjection(mutated))
    }
  }
  for (const projection of dhtRoles) {
    t.is(projection.topologyAuthorityPublicKey, undefined)
    t.is(projection.topologyRunId, undefined)
    t.is(projection.topologyEpoch, undefined)
    const mutated = clone(projection)
    mutated.topologyAuthorityPublicKey = b4a.alloc(32)
    throwsCode(t, () => auditor.auditProjection(mutated))
  }
  auditor.destroy()
  fixture.stop()
})

test('topology stop zeroes and revokes every coordinator projection encoding', (t) => {
  const fixture = topology(PROCESS_PLANS.LINUX_NAMESPACE, 13)
  const aliases = fixture.oracle.projectionBytes.slice()
  const topologyContextAliases = fixture.projections
    .slice(0, 8)
    .flatMap((projection) => [projection.topologyAuthorityPublicKey, projection.topologyRunId])
  const endpointSecret = fixture.projections[0].localIdentitySecretKey
  const oracleSecret = fixture.oracle.eventForbiddenBytes.find((value) =>
    b4a.equals(value, endpointSecret)
  )
  t.is(aliases.length, 11)
  t.ok(aliases.every((value) => value.some((byte) => byte !== 0)))
  t.ok(topologyContextAliases.every((value) => value.some((byte) => byte !== 0)))
  t.ok(endpointSecret.some((byte) => byte !== 0))
  t.ok(oracleSecret)
  t.ok(fixture.projections[0].phaseGate)
  for (let index = 1; index < fixture.projections.length; index++)
    t.is(fixture.projections[index].phaseGate, undefined)
  fixture.stop()
  for (const value of aliases) t.alike(value, b4a.alloc(value.byteLength))
  for (const value of topologyContextAliases) t.alike(value, b4a.alloc(32))
  t.alike(endpointSecret, b4a.alloc(64))
  t.alike(oracleSecret, b4a.alloc(64))
  t.is(fixture.oracle.projectionBytes.length, 0)
})

test('auditor rejects every mutated role contact edge', (t) => {
  const fixture = topology()
  const auditor = createProcessConfigAuditor(fixture.oracle)
  let mutations = 0
  for (const projection of fixture.projections) {
    const paths = collectTuplePaths(projection)
    for (const path of paths) {
      const mutated = clone(projection)
      replaceAtPath(mutated, path, { host: '127.64.99.1', port: 42_099 })
      throwsCode(t, () => auditor.auditProjection(mutated))
      mutations++
    }
  }
  t.ok(mutations >= 30, 'every bind/bootstrap/adjacency/DHT node tuple is mutated')
  auditor.destroy()
  fixture.stop()
})

test('role policies keep endpoint, relay, exit and DHT authority disjoint', (t) => {
  const fixture = topology()
  const byRole = Object.fromEntries(
    fixture.projections.map((projection) => [projection.role, projection])
  )
  const endpoint = byRole.endpoint
  t.ok(b4a.isBuffer(endpoint.localIdentitySecretKey))
  t.ok(b4a.isBuffer(endpoint.targetHash))
  t.alike(endpoint.guardBootstrap, byRole.guard.bind)
  for (const name of ['dhtOptions', 'immutableValue', 'middleAdjacencies', 'terminalKeys'])
    t.is(endpoint[name], undefined)

  const guard = byRole.guard
  t.is(guard.middleAdjacencies.length, 3)
  t.is(guard.endpointApplicationBytes, undefined)
  for (const role of ['lookup-middle-a', 'lookup-middle-b', 'announce-middle']) {
    t.is(byRole[role].adjacencies.length, 4)
    t.is(byRole[role].grants.length, 4)
    t.is(byRole[role].dhtOptions, undefined)
  }
  for (const role of ['lookup-exit-a', 'lookup-exit-b', 'announce-exit']) {
    const exit = byRole[role]
    t.alike(exit.dhtSeed, byRole['dht-seed'].bind)
    t.is(exit.referral, undefined)
    t.is(exit.value, undefined)
    t.ok(b4a.isBuffer(exit.isolatedGrantVerifier.publicKey))
    t.ok(b4a.isBuffer(exit.initialSeedGrant))
    for (const pool of [
      exit.learnedReferralGrants,
      exit.learnedValueGrants,
      exit.learnedSeedGrants
    ]) {
      t.ok(pool !== null && typeof pool === 'object')
      for (const [gen, grants] of Object.entries(pool)) {
        t.ok(Number(gen) >= 1 && Number(gen) <= 5)
        t.ok(Array.isArray(grants))
        t.ok(grants.every((grant) => b4a.isBuffer(grant)))
        t.is(
          new Set(grants.map((grant) => b4a.toString(grant, 'hex'))).size,
          grants.length,
          'every learned grant in the pool is distinct'
        )
        t.absent(
          grants.some((grant) => b4a.equals(grant, exit.initialSeedGrant)),
          'configured seed and learned grants are distinct'
        )
      }
    }
  }
  t.is(byRole['lookup-exit-a'].immutableGetAuthority, true)
  t.is(byRole['lookup-exit-b'].immutableGetAuthority, true)
  t.is(byRole['announce-exit'].immutableGetAuthority, true)

  for (const role of ['dht-seed', 'dht-referral', 'dht-value']) {
    const dht = byRole[role]
    t.is(dht.endpointIdentity, undefined)
    t.is(dht.leakSentinel, undefined)
    t.is(dht.socketFactory, undefined)
  }
  fixture.stop()
})

test('auditor traverses hidden containers and backing memory without invoking accessors', (t) => {
  const fixture = topology()
  const auditor = createProcessConfigAuditor(fixture.oracle)
  const sentinel = fixture.oracle.leakSentinel
  const endpoint = fixture.projections[0]
  const hostileValues = [
    [b4a.from(sentinel)],
    new Map([['hidden', b4a.from(sentinel)]]),
    new Set([b4a.from(sentinel)]),
    Object.assign(new Error('hidden'), { bytes: b4a.from(sentinel) }),
    { [Symbol('hidden')]: b4a.from(sentinel) }
  ]
  const backing = new ArrayBuffer(96)
  new Uint8Array(backing, 32, 32).set(sentinel)
  hostileValues.push(new DataView(backing, 0, 1), new Uint16Array(backing, 0, 1), backing)
  for (const hidden of hostileValues) throwsCode(t, () => auditor.auditEvent('guard', { hidden }))

  let reads = 0
  const accessor = {}
  Object.defineProperty(accessor, 'secret', {
    enumerable: true,
    get() {
      reads++
      return endpoint.localIdentitySecretKey
    }
  })
  throwsCode(t, () => auditor.auditEvent('guard', accessor))
  t.is(reads, 0)
  const hostilePrototype = Object.create({ hidden: b4a.from(sentinel) })
  hostilePrototype.ok = true
  throwsCode(t, () => auditor.auditEvent('guard', hostilePrototype))
  throwsCode(t, () => auditor.auditEvent('guard', new Proxy({}, {})))
  for (const container of [new Map(), new Set()]) {
    Object.defineProperty(container, 'hidden', {
      value: b4a.from(sentinel)
    })
    throwsCode(t, () => auditor.auditEvent('guard', { container }))
  }
  for (const container of [new Map(), new Set()]) {
    Object.defineProperty(container, Symbol('hidden'), {
      value: b4a.from(sentinel)
    })
    throwsCode(t, () => auditor.auditEvent('guard', { container }))
  }
  for (const container of [new Map(), new Set()]) {
    Object.defineProperty(container, 'hidden', {
      get() {
        reads++
        return b4a.from(sentinel)
      }
    })
    throwsCode(t, () => auditor.auditEvent('guard', { container }))
  }
  t.is(reads, 0)
  auditor.destroy()
  fixture.stop()
})

test('auditor accepts only sanitized relationship indexes for relay snapshots', (t) => {
  const fixture = topology()
  const auditor = createProcessConfigAuditor(fixture.oracle)
  const snapshot = (role, selectedExitRoleIndex, selectedMiddleRoleIndex) => ({
    role,
    selectedExitRoleIndex,
    selectedMiddleRoleIndex,
    type: 'snapshot'
  })
  t.is(auditor.auditEvent('lookup-middle-a', snapshot('lookup-middle-a', 6, null)), true)
  t.is(auditor.auditEvent('announce-exit', snapshot('announce-exit', null, 5)), true)
  for (const event of [
    snapshot('lookup-middle-a', 5, null),
    snapshot('lookup-middle-a', b4a.alloc(32), null),
    snapshot('lookup-exit-a', 4, 3),
    snapshot('guard', 4, null)
  ]) {
    throwsCode(t, () => auditor.auditEvent(event.role, event))
  }
  auditor.destroy()
  fixture.stop()
})
test('auditor rejects ambient names hosts subnets protocols endpoint material and secrets in events', (t) => {
  const fixture = topology()

  const auditor = createProcessConfigAuditor(fixture.oracle)
  const invalid = [
    { path: '/tmp/private-route' },
    { host: 'localhost' },
    { dns: ['8.8.8.8'] },
    { tcp: true },
    { route: '0.0.0.0/0' },
    { subnet: '10.203.0.0/16' },
    { role: 'operator' },
    { address: fixture.projections[0].bind.host },
    { sentinel: b4a.from(fixture.oracle.leakSentinel) },
    { secret: b4a.from(fixture.projections[1].identitySecretKey) },
    { secret: b4a.from(fixture.projections[0].localIdentitySecretKey) }
  ]
  for (const event of invalid) throwsCode(t, () => auditor.auditEvent('dht-seed', event))
  t.is(
    auditor.auditEvent('endpoint', { code: 'ERR_PRIVATE_ROUTE_UNAVAILABLE', state: 'READY' }),
    true
  )
  auditor.destroy()
  fixture.stop()
})

test('auditor binds sanitized post-setup DHT value state to the topology oracle', (t) => {
  const fixture = topology()
  const auditor = createProcessConfigAuditor(fixture.oracle)
  const snapshot = (role, roleIndex, storage, state = 'DHT_SETUP') => ({
    activeExitOperations: 0,
    activeOperations: 0,
    announceGeneration: null,
    controllerGeneration: null,
    endpointSockets: 0,
    generation: 1n,
    guardOnly: false,
    lookupGeneration: null,
    selectedExitRoleIndex: null,
    selectedMiddleRoleIndex: null,
    openLinks: 0,
    isolatedGrantRequestCount: 0,
    openResources: state === 'CLOSED' ? 0 : 1,
    ordinaryRequestCount: 0,
    pendingGrantRequests: 0,
    pendingLinks: 0,
    pendingPackets: 0,
    phaseSequence: 4n,
    queuedBytes: 0,
    referralProbeCount: 0,
    role,
    roleIndex,
    state,
    summaryDigest: b4a.alloc(32, 7),
    tableEntryCount: 0,
    type: 'snapshot',
    ...storage
  })
  const seedSnapshot = snapshot('dht-seed', 9, { storedValueCount: 0 })
  t.is(auditor.auditEvent('dht-seed', seedSnapshot), true)
  for (const mutation of [
    { activeOperations: 1 },
    { controllerGeneration: 1n },
    { endpointSockets: 1 },
    { guardOnly: true },
    { openLinks: 1 },
    { isolatedGrantRequestCount: 1 },
    { openResources: 0 },
    { storedValueCount: 1 }
  ]) {
    throwsCode(t, () => auditor.auditEvent('dht-seed', { ...seedSnapshot, ...mutation }))
  }
  const emptyValueSnapshot = snapshot('dht-value', 11, {
    storedValueCount: 0,
    storedValueDigest: b4a.alloc(32)
  })
  t.is(auditor.auditEvent('dht-value', emptyValueSnapshot), true)
  throwsCode(t, () =>
    auditor.auditEvent('dht-value', {
      ...emptyValueSnapshot,
      storedValueDigest: b4a.from(fixture.oracle.targetHash)
    })
  )
  t.is(
    auditor.auditEvent(
      'dht-value',
      snapshot('dht-value', 11, {
        storedValueCount: 1,
        storedValueDigest: b4a.from(fixture.oracle.targetHash)
      })
    ),
    true
  )
  throwsCode(t, () => auditor.auditEvent('dht-value', emptyValueSnapshot))
  t.is(
    auditor.auditEvent(
      'dht-value',
      snapshot('dht-value', 11, { storedValueCount: 0, storedValueDigest: b4a.alloc(32) }, 'CLOSED')
    ),
    true
  )
  t.is(
    auditor.auditEvent('dht-value', {
      storedValueCount: 1,
      storedValueDigest: b4a.from(fixture.oracle.targetHash)
    }),
    true
  )
  t.is(
    auditor.auditEvent('dht-referral', {
      storedValueCount: 0,
      transientValueBytes: 0
    }),
    true
  )
  t.is(auditor.auditEvent('dht-seed', { storedValueCount: 0 }), true)
  t.is(
    auditor.auditEvent('endpoint', {
      target: b4a.from(fixture.oracle.targetHash),
      value: b4a.from(fixture.oracle.immutableValue)
    }),
    true
  )
  throwsCode(t, () =>
    auditor.auditEvent('dht-value', {
      storedValueCount: 1,
      storedValueDigest: b4a.alloc(32, 0xff)
    })
  )
  throwsCode(t, () =>
    auditor.auditEvent('dht-value', {
      storedValueCount: 0,
      storedValueDigest: b4a.from(fixture.oracle.targetHash)
    })
  )
  throwsCode(t, () =>
    auditor.auditEvent('dht-referral', {
      storedValueCount: 1,
      transientValueBytes: 0
    })
  )
  throwsCode(t, () =>
    auditor.auditEvent('dht-referral', {
      storedValueCount: 0,
      transientValueBytes: 1
    })
  )
  throwsCode(t, () => auditor.auditEvent('dht-seed', { storedValueCount: 1 }))
  throwsCode(t, () =>
    auditor.auditEvent('dht-referral', {
      storedValueCount: 0,
      transientValueBytes: 0,
      value: b4a.from(fixture.oracle.immutableValue)
    })
  )
  auditor.destroy()
  fixture.stop()
})

test('auditor rejects every role and coordinator MAC key by bytes without banning valid MAC fields', (t) => {
  const fixture = topology()
  const auditor = createProcessConfigAuditor(fixture.oracle)
  const keys = [
    ...fixture.projections.map((projection) => projection.controlAuditMacKey),
    ...fixture.oracle.roleMacKeys
  ]
  for (let index = 0; index < keys.length; index++) {
    const hidden =
      index % 2 === 0
        ? { digest: [b4a.from(keys[index])] }
        : { digest: new Map([['value', b4a.from(keys[index])]]) }
    throwsCode(t, () => auditor.auditEvent('endpoint', hidden))
  }
  t.is(
    auditor.auditEvent('lookup-exit-a', {
      eventMAC: b4a.alloc(32, 0xcc),
      recordDigest: b4a.alloc(32, 0xdd)
    }),
    true
  )
  auditor.destroy()
  fixture.stop()
})

test('role and coordinator event MAC key copies are independent and zeroed on stop', (t) => {
  const fixture = topology()
  const roleKeys = fixture.projections.map((projection) => projection.controlAuditMacKey)
  const oracleKeys = fixture.oracle.roleMacKeys
  t.is(roleKeys.length, 11)
  t.is(oracleKeys.length, 11)
  for (let index = 0; index < 11; index++) {
    t.ok(roleKeys[index] !== oracleKeys[index])
    t.alike(roleKeys[index], oracleKeys[index])
    for (let other = index + 1; other < 11; other++)
      t.not(b4a.equals(roleKeys[index], roleKeys[other]))
  }
  for (const projection of fixture.projections) {
    t.is(projection.auditorMarkerKey, undefined)
    t.is(projection.decoyMarkerKey, undefined)
  }
  fixture.stop()
  fixture.stop()
  for (const key of [...roleKeys, ...oracleKeys]) t.alike(key, b4a.alloc(32))
})

test('Task16 test infrastructure does not change root production exports', (t) => {
  t.alike(Object.getOwnPropertyNames(HyperDHT).sort(), [
    'BOOTSTRAP',
    'DEFAULTS',
    'FIREWALL',
    'connectRawStream',
    'hash',
    'keyPair',
    'length',
    'name',
    'prototype'
  ])
})
