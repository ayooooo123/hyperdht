'use strict'

const UDX = require('udx-native')
const b4a = require('b4a')
const sodium = require('sodium-universal')

const LINK_CLASSES = new Set([
  'circuit',
  'neighbor',
  'guard-bootstrap',
  'responder-cache',
  'v1-routed-branch',
  'nat-traversal'
])
const CHARGED_LINK_CLASSES = new Set(['circuit', 'neighbor', 'guard-bootstrap'])
const KINDS = new Map(
  [
    ['circuit', 'circuit', 'circuit'],
    ['closure', 'circuit', 'circuit'],
    ['circuit-discovery', 'circuit', 'circuit'],
    ['neighbor-service', 'neighbor', 'service'],
    ['neighbor-close', 'neighbor', 'service'],
    ['neighbor-discovery', 'neighbor', 'service'],
    ['discovery-response', 'responder-cache', 'service'],
    ['bootstrap-request', 'guard-bootstrap', 'bootstrap'],
    ['link-setup', 'guard-bootstrap', 'bootstrap'],
    ['link-control', 'guard-bootstrap', 'bootstrap'],
    ['bootstrap-response', 'responder-cache', 'bootstrap'],
    ['routed-branch', 'v1-routed-branch', 'v1-routed'],
    ['nat-reflection', 'nat-traversal', 'traversal'],
    ['nat-punch', 'nat-traversal', 'traversal']
  ].map(([kind, ownerClass, category]) => [
    kind,
    { class: ownerClass, category, charged: CHARGED_LINK_CLASSES.has(ownerClass) }
  ])
)

function fail(code, detail) {
  const error = new Error(code + ': ' + detail)
  error.code = code
  throw error
}

function integer(value, field, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) fail('INVALID_INPUT', field)
  return value
}

function text(value, field) {
  if (typeof value !== 'string' || value.length === 0) fail('INVALID_INPUT', field)
  return value
}

function key(...parts) {
  return JSON.stringify(parts)
}
function leaseKey(row) {
  return key(row.node, row.runtime, row.lease)
}
function ownerKey(lease, charged, id) {
  return key(lease.key, charged ? 'ledger' : 'governor', id)
}

function address(host) {
  text(host, 'host')
  const family = UDX.isIP(host)
  if (family === 4) return host
  if (family !== 6) fail('INVALID_INPUT', 'numeric IP required')
  const [literal, zone] = host.split('%')
  let ip = literal.toLowerCase()
  if (ip.includes('.')) {
    const colon = ip.lastIndexOf(':')
    const octets = ip
      .slice(colon + 1)
      .split('.')
      .map(Number)
    ip =
      ip.slice(0, colon + 1) +
      ((octets[0] << 8) | octets[1]).toString(16) +
      ':' +
      ((octets[2] << 8) | octets[3]).toString(16)
  }
  const sides = ip.split('::')
  const left = sides[0] ? sides[0].split(':') : []
  const right = sides.length === 2 && sides[1] ? sides[1].split(':') : []
  const groups =
    sides.length === 2
      ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right]
      : left
  const words = groups.map((word) => parseInt(word, 16))
  if (!zone && words.slice(0, 5).every((word) => word === 0) && words[5] === 0xffff) {
    return [words[6] >> 8, words[6] & 255, words[7] >> 8, words[7] & 255].join('.')
  }
  return (
    words.map((word) => word.toString(16).padStart(4, '0')).join(':') + (zone ? '%' + zone : '')
  )
}

function tuple(value) {
  if (!value || typeof value !== 'object') fail('INVALID_INPUT', 'tuple')
  const port = integer(value.port, 'port', 1)
  if (port > 65535) fail('INVALID_INPUT', 'port range')
  return key(address(value.host), port)
}

function payloadDigest(packet) {
  const digest = b4a.allocUnsafe(32)
  sodium.crypto_generichash(digest, packet)
  return b4a.toString(digest, 'hex')
}

function wire(lease, local, remote, bytes, digest) {
  integer(bytes, 'bytes', 1)
  if (bytes > 65527 || typeof digest !== 'string' || !/^[0-9a-f]{64}$/.test(digest)) {
    fail('INVALID_INPUT', 'UDP length or BLAKE2b-256 digest')
  }
  return key(lease.key, lease.socketGeneration, tuple(local), tuple(remote), bytes, digest)
}

function metrics() {
  return {
    attempted: 0,
    attemptedBytes: 0,
    chargedCells: 0,
    chargedBytes: 0,
    observed: 0,
    observedBytes: 0,
    unobserved: 0,
    unobservedBytes: 0,
    sent: 0,
    refused: 0,
    failed: 0,
    unresolved: 0,
    captureLoss: 0,
    retransmissions: 0
  }
}

function count(attempt, field, amount = 1) {
  attempt.owner.counts[field] += amount
  attempt.owner.byKind.get(attempt.event.owner.kind)[field] += amount
}

function add(total, counts) {
  for (const field of Object.keys(counts)) {
    total[field] += counts[field]
    if (!Number.isSafeInteger(total[field])) fail('COUNTER_OVERFLOW', field)
  }
}

function totals() {
  return {
    circuit: metrics(),
    service: metrics(),
    bootstrap: metrics(),
    traversal: metrics(),
    'v1-routed': metrics(),
    charged: metrics(),
    uncharged: metrics(),
    sum: metrics(),
    byKind: Array.from(KINDS, ([kind]) => ({ kind, counts: metrics() }))
  }
}

function accumulate(total, owner) {
  add(total.sum, owner.counts)
  add(total[owner.charged ? 'charged' : 'uncharged'], owner.counts)
  for (const [kind, counts] of owner.byKind) {
    add(total[KINDS.get(kind).category], counts)
    add(total.byKind.find((row) => row.kind === kind).counts, counts)
  }
}

// Runtime events remain unmodified. Lease identity and calibrated timestamps are
// test-collector metadata, not invented fields on observeSendAttempts events.
function analyze(input) {
  if (!input || input.version !== 2) fail('INVALID_INPUT', 'analysis schema version must be 2')
  const delay = integer(input.maxCaptureDelayMicros, 'maxCaptureDelayMicros')
  for (const field of ['leases', 'events', 'captures', 'captureLosses']) {
    if (!Array.isArray(input[field])) fail('INVALID_INPUT', field)
  }
  const leases = new Map()
  const generations = new Set()
  for (const row of input.leases) {
    text(row.node, 'node')
    text(row.runtime, 'runtime')
    text(row.lease, 'lease')
    integer(row.socketGeneration, 'socketGeneration', 1)
    integer(row.start, 'lease.start')
    integer(row.end, 'lease.end')
    const id = leaseKey(row)
    const generation = key(row.node, row.runtime, row.socketGeneration)
    if (row.start >= row.end || leases.has(id) || generations.has(generation))
      fail('SOCKET_GENERATION', id)
    generations.add(generation)
    leases.set(id, { ...row, key: id, tuple: tuple(row.local) })
  }
  function leaseFor(row) {
    const lease = leases.get(leaseKey(row))
    if (!lease) fail('SOCKET_GENERATION', leaseKey(row))
    return lease
  }
  function active(lease, at) {
    integer(at, 'timestamp')
    if (at < lease.start || at >= lease.end) fail('SOCKET_GENERATION', lease.key)
  }
  const links = new Map()
  if (input.links !== undefined && !Array.isArray(input.links)) fail('INVALID_INPUT', 'links')
  for (const row of input.links || []) {
    const lease = leaseFor(row)
    if (!LINK_CLASSES.has(row.class)) fail('UNSUPPORTED_LINK_CLASS', row.class)
    integer(row.start, 'link start')
    integer(row.end, 'link end')
    if (row.start >= row.end || typeof row.requiresCharge !== 'boolean')
      fail('INVALID_INPUT', 'link policy')
    if (tuple(row.local) !== lease.tuple) fail('SOCKET_GENERATION', 'link local tuple')
    const id = key(lease.key, tuple(row.local), tuple(row.remote))
    if (!links.has(id)) links.set(id, [])
    links.get(id).push(row)
  }
  function classifyLink(lease, event, at) {
    const candidates = links.get(key(lease.key, tuple(event.local), tuple(event.remote))) || []
    let found = null
    for (const link of candidates) {
      if (at < link.start || at >= link.end) continue
      if (found) fail('AMBIGUOUS_LINK_CLASS', lease.key)
      found = link
    }
    return found
  }
  const allowances = new Map()
  if (input.allowances !== undefined && !Array.isArray(input.allowances))
    fail('INVALID_INPUT', 'allowances')
  for (const row of input.allowances || []) {
    const lease = leaseFor(row)
    const charged = row.ledger !== null
    if (charged && row.governor !== null) fail('INVALID_INPUT', 'allowance owner')
    const id = ownerKey(
      lease,
      charged,
      integer(charged ? row.ledger : row.governor, 'allowance owner', 1)
    )
    if (
      !Array.isArray(row.kinds) ||
      row.kinds.length === 0 ||
      row.kinds.some((kind) => !KINDS.has(kind))
    ) {
      fail('UNSUPPORTED_OWNER', id)
    }
    if (row.kinds.some((kind) => KINDS.get(kind).charged !== charged)) fail('CATEGORY_MISMATCH', id)
    if (new Set(row.kinds.map((kind) => KINDS.get(kind).class)).size !== 1)
      fail('CLASS_MISMATCH', id)
    if (allowances.has(id)) fail('DUPLICATE_OWNER', id)
    integer(row.datagrams, 'allowance datagrams')
    integer(row.bytes, 'allowance bytes')
    if (!Array.isArray(row.sizes) || row.sizes.length === 0)
      fail('INVALID_INPUT', 'allowance sizes')
    for (const size of row.sizes) integer(size, 'allowed size', 1)
    allowances.set(id, row)
  }
  const attempts = new Map()
  const owners = new Map()
  const buckets = new Map()
  const completions = []
  const ordered = new Map()
  const runtimeAttempts = new Set()
  let unclassifiedAttempts = 0
  const linkEvidence = []
  for (const envelope of input.events) {
    const lease = leaseFor(envelope)
    integer(envelope.at, 'event timestamp')
    const event = envelope.event
    if (!event || !['attempt', 'completion'].includes(event.kind))
      fail('INVALID_INPUT', 'event kind')
    integer(event.attemptId, 'attemptId', 1)
    const id = key(lease.key, event.attemptId)
    if (event.kind === 'completion') {
      completions.push({ id, at: envelope.at, event })
      continue
    }
    active(lease, envelope.at)
    if (event.socketGeneration !== lease.socketGeneration || tuple(event.local) !== lease.tuple) {
      fail('SOCKET_GENERATION', id)
    }
    if (attempts.has(id)) fail('DUPLICATE_OWNER', id)
    if (!event.owner || !KINDS.has(event.owner.kind)) fail('UNSUPPORTED_OWNER', id)
    const rule = KINDS.get(event.owner.kind)
    if (!LINK_CLASSES.has(event.owner.class)) fail('INVALID_OWNER_CLASS', id)
    if (event.owner.class !== rule.class) fail('CLASS_MISMATCH', id)
    if (event.owner.category !== rule.category || event.owner.charged !== rule.charged)
      fail('CATEGORY_MISMATCH', id)
    if (rule.charged) {
      if (
        !Number.isSafeInteger(event.owner.ledger) ||
        event.owner.ledger < 1 ||
        !Number.isSafeInteger(event.owner.ordinal) ||
        event.owner.ordinal < 1 ||
        event.owner.governor !== null
      )
        fail('UNCHARGED_SEND', id)
    } else if (
      event.owner.ledger !== null ||
      event.owner.ordinal !== null ||
      !Number.isSafeInteger(event.owner.governor) ||
      event.owner.governor < 1
    ) {
      fail('MISSING_GOVERNOR', id)
    }
    const runtime = key(lease.node, lease.runtime)
    const runtimeAttempt = key(runtime, event.attemptId)
    if (runtimeAttempts.has(runtimeAttempt)) fail('DUPLICATE_OWNER', id)
    runtimeAttempts.add(runtimeAttempt)
    const link = classifyLink(lease, event, envelope.at)
    if (!link) unclassifiedAttempts++
    // R10 explicitly permits governed v1 branches over a shared A0 link.
    // This does not exempt native A0 control or override a stricter fixture rule.
    const sharedV1 =
      link && link.class === 'guard-bootstrap' && event.owner.class === 'v1-routed-branch'
    const requiresCharge =
      link && (link.requiresCharge || (CHARGED_LINK_CLASSES.has(link.class) && !sharedV1))
    if (requiresCharge && !event.owner.charged)
      fail('UNCHARGED_REQUIRED_LINK', id + ': ' + link.class)
    linkEvidence.push({
      node: lease.node,
      runtime: lease.runtime,
      lease: lease.lease,
      attemptId: event.attemptId,
      class: link ? link.class : null,
      ownerClass: event.owner.class,
      requiresCharge: link ? !!requiresCharge : null,
      charged: event.owner.charged
    })
    if (event.obligation !== null) integer(event.obligation, 'obligation', 1)
    const identity = wire(lease, event.local, event.remote, event.bytes, event.digest)
    const ownerId = ownerKey(
      lease,
      event.owner.charged,
      event.owner.charged ? event.owner.ledger : event.owner.governor
    )
    const allowance = allowances.get(ownerId)
    if (allowance && !allowance.kinds.includes(event.owner.kind)) fail('CATEGORY_MISMATCH', id)
    if (allowance && !allowance.sizes.includes(event.bytes)) fail('DATAGRAM_SIZE', id)
    if (!owners.has(ownerId))
      owners.set(ownerId, {
        key: ownerId,
        lease,
        charged: event.owner.charged,
        class: event.owner.class,
        ledger: event.owner.ledger,
        governor: event.owner.governor,
        byKind: new Map(),
        allowance,
        counts: metrics(),
        attempts: []
      })
    const owner = owners.get(ownerId)
    if (owner.class !== event.owner.class) fail('OWNER_CLASS_CHANGE', id)
    if (!owner.byKind.has(event.owner.kind)) owner.byKind.set(event.owner.kind, metrics())
    const attempt = { id, event, at: envelope.at, owner, lease, outcome: null, matched: false }
    attempts.set(id, attempt)
    owner.attempts.push(attempt)
    if (!ordered.has(runtime)) ordered.set(runtime, [])
    ordered.get(runtime).push(attempt)
    if (!buckets.has(identity)) buckets.set(identity, { rows: [], cursor: 0 })
    buckets.get(identity).rows.push(attempt)
    count(attempt, 'attempted')
    count(attempt, 'attemptedBytes', event.bytes)
    if (rule.charged) {
      count(attempt, 'chargedCells')
      count(attempt, 'chargedBytes', 1200)
    }
  }
  for (const rows of ordered.values()) {
    rows.sort((a, b) => a.at - b.at || a.event.attemptId - b.event.attemptId)
    for (let i = 1; i < rows.length; i++) {
      if (rows[i].event.attemptId <= rows[i - 1].event.attemptId) fail('ATTEMPT_ORDER', rows[i].id)
    }
  }
  for (const completion of completions) {
    const attempt = attempts.get(completion.id)
    if (!attempt) fail('MISSING_ATTEMPT', completion.id)
    if (attempt.outcome !== null) fail('DUPLICATE_COMPLETION', completion.id)
    if (completion.at < attempt.at) fail('COMPLETION_BEFORE_ATTEMPT', completion.id)
    if (!['sent', 'refused', 'failed'].includes(completion.event.outcome))
      fail('INVALID_INPUT', 'completion outcome')
    attempt.outcome = completion.event.outcome
    count(attempt, attempt.outcome)
  }
  for (const owner of owners.values()) {
    owner.attempts.sort((a, b) => a.at - b.at || a.event.attemptId - b.event.attemptId)
    const obligations = new Set()
    for (let i = 0; i < owner.attempts.length; i++) {
      const row = owner.attempts[i]
      if (owner.charged && row.event.owner.ordinal !== i + 1) fail('UNCHARGED_RETRY', row.id)
      if (row.outcome === null) count(row, 'unresolved')
      if (row.event.obligation !== null) {
        if (obligations.has(row.event.obligation)) count(row, 'retransmissions')
        obligations.add(row.event.obligation)
      }
    }
    if (
      owner.allowance &&
      (owner.counts.attempted > owner.allowance.datagrams ||
        (owner.charged ? owner.counts.chargedBytes : owner.counts.attemptedBytes) >
          owner.allowance.bytes)
    )
      fail('ALLOWANCE_EXCEEDED', owner.key)
  }
  for (const bucket of buckets.values())
    bucket.rows.sort((a, b) => a.at - b.at || a.event.attemptId - b.event.attemptId)

  const observations = new Map()
  const packets = []
  const copies = new Set()
  for (const row of input.captures) {
    const lease = leaseFor(row)
    active(lease, row.at)
    text(row.id, 'capture id')
    text(row.tap, 'tap')
    if (tuple(row.local) !== lease.tuple) fail('SOCKET_GENERATION', row.id)
    if (
      typeof row.payload !== 'string' ||
      row.payload.length === 0 ||
      row.payload.length > 131054 ||
      row.payload.length % 2 ||
      /[^0-9a-f]/.test(row.payload)
    )
      fail('INVALID_INPUT', 'capture UDP payload hex')
    const packet = b4a.from(row.payload, 'hex')
    const id = key(lease.key, row.id)
    if (observations.has(id)) fail('DUPLICATE_CAPTURE', id)
    observations.set(id, {
      ...row,
      key: id,
      lease,
      bytes: packet.byteLength,
      wire: wire(lease, row.local, row.remote, packet.byteLength, payloadDigest(packet))
    })
  }
  for (const row of observations.values()) {
    if (row.duplicateOf === null) {
      packets.push(row)
      continue
    }
    const original = observations.get(key(row.lease.key, row.duplicateOf))
    if (
      !original ||
      original.duplicateOf !== null ||
      original.wire !== row.wire ||
      original.at !== row.at ||
      original.tap === row.tap
    )
      fail('INVALID_CAPTURE_COPY', row.key)
    const copy = key(original.key, row.tap)
    if (copies.has(copy)) fail('DUPLICATE_CAPTURE', row.key)
    copies.add(copy)
  }
  packets.sort((a, b) => a.at - b.at || a.key.localeCompare(b.key))
  const joins = []
  for (const packet of packets) {
    const bucket = buckets.get(packet.wire)
    if (!bucket) fail('MISSING_OWNER', packet.key)
    while (
      bucket.cursor < bucket.rows.length &&
      (bucket.rows[bucket.cursor].matched || packet.at - bucket.rows[bucket.cursor].at > delay)
    )
      bucket.cursor++
    let attempt = null
    let rejected = false
    let after = false
    for (let i = bucket.cursor; i < bucket.rows.length; i++) {
      const row = bucket.rows[i]
      if (row.matched) continue
      if (row.at > packet.at) {
        after = true
        break
      }
      if (row.outcome === 'refused' || row.outcome === 'failed') {
        rejected = true
        continue
      }
      if (attempt && attempt.owner !== row.owner) fail('DUPLICATE_OWNER', packet.key)
      if (!attempt) attempt = row
    }
    if (!attempt)
      fail(
        rejected ? 'FAILED_SEND_OBSERVED' : after ? 'CHARGE_AFTER_SEND' : 'MISSING_OWNER',
        packet.key
      )
    attempt.matched = true
    count(attempt, 'observed')
    count(attempt, 'observedBytes', packet.bytes)
    joins.push({
      node: packet.node,
      runtime: packet.runtime,
      lease: packet.lease.lease,
      socketGeneration: packet.lease.socketGeneration,
      captureId: packet.id,
      attemptId: attempt.event.attemptId,
      kind: attempt.event.owner.kind,
      class: attempt.event.owner.class,
      category: attempt.event.owner.category,
      charged: attempt.event.owner.charged,
      ledger: attempt.event.owner.ledger,
      ordinal: attempt.event.owner.ordinal,
      governor: attempt.event.owner.governor,
      obligation: attempt.event.obligation
    })
  }
  const losses = new Map()
  for (const row of input.captureLosses) {
    const lease = leaseFor(row)
    text(row.reason, 'loss reason')
    text(row.evidence, 'loss evidence')
    const id = key(lease.key, integer(row.attemptId, 'loss attemptId', 1))
    if (losses.has(id)) fail('DUPLICATE_LOSS', id)
    losses.set(id, row)
  }
  const differences = []
  for (const row of attempts.values()) {
    const loss = losses.get(row.id)
    if (loss && (row.matched || row.outcome !== 'sent')) fail('INVALID_CAPTURE_LOSS', row.id)
    if (row.matched) continue
    if (row.outcome === 'sent' && !loss) fail('MISSING_CAPTURE', row.id)
    count(row, 'unobserved')
    count(row, 'unobservedBytes', row.event.bytes)
    if (loss) count(row, 'captureLoss')
    differences.push({
      node: row.lease.node,
      runtime: row.lease.runtime,
      lease: row.lease.lease,
      attemptId: row.event.attemptId,
      class: row.event.owner.class,
      ledger: row.event.owner.ledger,
      governor: row.event.owner.governor,
      reason: loss ? 'capture-loss' : row.outcome || 'unresolved',
      evidence: loss ? loss.evidence : null
    })
  }
  for (const id of losses.keys()) if (!attempts.has(id)) fail('INVALID_CAPTURE_LOSS', id)
  const total = totals()
  const nodes = new Map()
  const leaseTotals = new Map()
  const ledgers = []
  const governors = []
  for (const owner of owners.values()) {
    accumulate(total, owner)
    if (!nodes.has(owner.lease.node)) nodes.set(owner.lease.node, totals())
    accumulate(nodes.get(owner.lease.node), owner)
    if (!leaseTotals.has(owner.lease.key))
      leaseTotals.set(owner.lease.key, { lease: owner.lease, totals: totals() })
    accumulate(leaseTotals.get(owner.lease.key).totals, owner)
    const rows = owner.charged ? ledgers : governors
    rows.push({
      node: owner.lease.node,
      runtime: owner.lease.runtime,
      lease: owner.lease.lease,
      socketGeneration: owner.lease.socketGeneration,
      class: owner.class,
      ledger: owner.ledger,
      governor: owner.governor,
      byKind: Array.from(owner.byKind, ([kind, counts]) => ({ kind, ...counts })),
      allowance: owner.allowance
        ? {
            datagrams: owner.allowance.datagrams,
            bytes: owner.allowance.bytes,
            sizes: owner.allowance.sizes.slice(),
            kinds: owner.allowance.kinds.slice()
          }
        : null,
      ...owner.counts
    })
  }
  return {
    version: 2,
    completeCapture: differences.every((row) => ['refused', 'failed'].includes(row.reason)),
    completeCompletions: total.sum.unresolved === 0,
    completeAllowanceCoverage: [...ledgers, ...governors].every((row) => row.allowance !== null),
    completeLinkClassification: unclassifiedAttempts === 0,
    unclassifiedAttempts,
    observations: observations.size,
    deduplicatedCopies: copies.size,
    datagrams: packets.length,
    totals: total,
    nodes: Array.from(nodes, ([node, totals]) => ({ node, totals })),
    leases: Array.from(leaseTotals.values(), ({ lease, totals }) => ({
      node: lease.node,
      runtime: lease.runtime,
      lease: lease.lease,
      socketGeneration: lease.socketGeneration,
      totals
    })),
    ledgers,
    governors,
    joins,
    differences,
    linkEvidence
  }
}

module.exports = { analyze, payloadDigest }
