'use strict'

const b4a = require('b4a')
const { payloadDigest } = require('./analyzer')

module.exports = function fixture() {
  const input = {
    version: 2,
    maxCaptureDelayMicros: 5,
    leases: [],
    links: [],
    allowances: [],
    events: [],
    captures: [],
    captureLosses: []
  }
  const counts = new Map()
  for (const node of ['a', 'b'])
    input.leases.push({
      node,
      runtime: 'runtime',
      lease: 'lease-1',
      socketGeneration: 1,
      local: { host: node === 'a' ? '10.20.0.1' : '10.21.0.1', port: 4100 },
      start: 0,
      end: 10000
    })
  function send(
    node,
    kind,
    category,
    ownerClass,
    ownerId,
    at,
    value,
    bytes = 1200,
    obligation = null,
    cells = 4
  ) {
    const charged = ['circuit', 'neighbor', 'guard-bootstrap'].includes(ownerClass)
    const lease = input.leases.find((row) => row.node === node)
    const scope = { node, runtime: lease.runtime, lease: lease.lease }
    const attemptId = (counts.get(node) || 0) + 1
    counts.set(node, attemptId)
    const ledger = charged ? ownerId : null
    const governor = charged ? null : ownerId
    const earlier = input.events.filter(
      (row) =>
        row.node === node &&
        row.event.kind === 'attempt' &&
        row.event.owner.ledger === ledger &&
        row.event.owner.governor === governor
    )
    const allowance = input.allowances.find(
      (row) => row.node === node && row.ledger === ledger && row.governor === governor
    )
    if (!allowance)
      input.allowances.push({
        ...scope,
        ledger,
        governor,
        kinds: [kind],
        datagrams: cells,
        bytes: (charged ? 1200 : bytes) * cells,
        sizes: [bytes]
      })
    else {
      if (!allowance.kinds.includes(kind)) allowance.kinds.push(kind)
      if (!allowance.sizes.includes(bytes)) allowance.sizes.push(bytes)
    }
    const packet = b4a.alloc(bytes, value)
    const event = {
      kind: 'attempt',
      attemptId,
      socketGeneration: 1,
      local: { ...lease.local },
      remote: { host: '10.22.0.1', port: 4200 },
      bytes,
      digest: payloadDigest(packet),
      owner: {
        kind,
        class: ownerClass,
        category,
        charged,
        ledger,
        ordinal: charged ? earlier.length + 1 : null,
        governor
      },
      obligation
    }
    input.events.push(
      { ...scope, at, event },
      { ...scope, at: at + 2, event: { kind: 'completion', attemptId, outcome: 'sent' } }
    )
    input.captures.push({
      ...scope,
      id: 'p-' + attemptId,
      tap: 'egress',
      at: at + 1,
      local: { ...event.local },
      remote: { ...event.remote },
      payload: b4a.toString(packet, 'hex'),
      duplicateOf: null
    })
    input.links.push({
      ...scope,
      local: { ...event.local },
      remote: { ...event.remote },
      start: at - 1,
      end: at + 3,
      class: kind === 'routed-branch' ? 'guard-bootstrap' : ownerClass,
      requiresCharge: charged
    })
  }
  send('a', 'circuit', 'circuit', 'circuit', 1, 100, 1, 1200, 101)
  send('a', 'circuit', 'circuit', 'circuit', 1, 120, 1, 1200, 101)
  send('a', 'closure', 'circuit', 'circuit', 2, 200, 2)
  send('a', 'circuit-discovery', 'circuit', 'circuit', 3, 300, 3)
  send('a', 'neighbor-service', 'service', 'neighbor', 4, 400, 4)
  send('a', 'neighbor-close', 'service', 'neighbor', 5, 500, 5)
  send('a', 'neighbor-discovery', 'service', 'neighbor', 6, 600, 6)
  send('a', 'discovery-response', 'service', 'responder-cache', 101, 700, 7)
  send('a', 'bootstrap-request', 'bootstrap', 'guard-bootstrap', 7, 800, 8, 256, null, 7285)
  send('a', 'link-setup', 'bootstrap', 'guard-bootstrap', 7, 900, 9, 1200, null, 7285)
  send('a', 'link-control', 'bootstrap', 'guard-bootstrap', 7, 1000, 10, 1200, null, 7285)
  send('a', 'routed-branch', 'v1-routed', 'v1-routed-branch', 105, 1100, 11)
  send('a', 'nat-reflection', 'traversal', 'nat-traversal', 106, 1200, 12, 128)
  send('a', 'nat-punch', 'traversal', 'nat-traversal', 107, 1300, 13, 96)
  send('b', 'neighbor-service', 'service', 'neighbor', 1, 1400, 14)
  send('b', 'bootstrap-response', 'bootstrap', 'responder-cache', 108, 1500, 15, 256)
  send('b', 'link-setup', 'bootstrap', 'guard-bootstrap', 2, 1600, 16, 1200, null, 7232)
  send('b', 'link-control', 'bootstrap', 'guard-bootstrap', 2, 1700, 17, 1200, null, 7232)
  input.captures.push({
    ...input.captures[0],
    local: { ...input.captures[0].local },
    id: 'copy-data',
    tap: 'second-tap',
    duplicateOf: 'p-1'
  })
  return input
}
