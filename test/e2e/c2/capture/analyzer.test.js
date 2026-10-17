'use strict'

const test = require('brittle')
const b4a = require('b4a')
const { analyze, payloadDigest } = require('./analyzer')
const fixture = require('./fixture')
const clone = (value) => JSON.parse(JSON.stringify(value))

function attempt(input, id, node = 'a') {
  return input.events.find(
    (row) => row.node === node && row.event.kind === 'attempt' && row.event.attemptId === id
  )
}
function completion(input, id) {
  return input.events.find(
    (row) => row.node === 'a' && row.event.kind === 'completion' && row.event.attemptId === id
  )
}
function removePacket(input, id) {
  input.captures = input.captures.filter(
    (row) => row.node !== 'a' || (row.id !== 'p-' + id && row.duplicateOf !== 'p-' + id)
  )
}
function rejects(t, input, code) {
  let caught = null
  try {
    analyze(input)
  } catch (error) {
    caught = error
  }
  t.is(caught && caught.code, code)
}

test('A2 capture: BLAKE2b-256 hashes the independently captured UDP bytes', (t) => {
  t.is(
    payloadDigest(b4a.alloc(0)),
    '0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8'
  )
  const input = fixture()
  input.captures[1].payload = 'ff' + input.captures[1].payload.slice(2)
  rejects(t, input, 'MISSING_OWNER')
})

test('A2 capture: fourteen kinds reconcile into five categories and their sum', (t) => {
  const report = analyze(fixture())
  t.is(report.datagrams, 18)
  t.is(report.observations, 19)
  t.is(report.deduplicatedCopies, 1)
  t.is(report.totals.circuit.observedBytes, 4800)
  t.is(report.totals.service.observedBytes, 6000)
  t.is(report.totals.bootstrap.observedBytes, 5312)
  t.is(report.totals.traversal.observedBytes, 224)
  t.is(report.totals['v1-routed'].observedBytes, 1200)
  t.is(report.totals.sum.observedBytes, 17536)
  t.is(report.totals.charged.observedBytes, 14656)
  t.is(report.totals.uncharged.observedBytes, 2880)
  t.is(report.totals.sum.chargedCells, 13)
  t.is(report.totals.sum.chargedBytes, 15600)
  t.alike(
    report.totals.byKind.map((row) => [row.kind, row.counts.observedBytes]),
    [
      ['circuit', 2400],
      ['closure', 1200],
      ['circuit-discovery', 1200],
      ['neighbor-service', 2400],
      ['neighbor-close', 1200],
      ['neighbor-discovery', 1200],
      ['discovery-response', 1200],
      ['bootstrap-request', 256],
      ['link-setup', 2400],
      ['link-control', 2400],
      ['bootstrap-response', 256],
      ['routed-branch', 1200],
      ['nat-reflection', 128],
      ['nat-punch', 96]
    ]
  )
  t.is(report.nodes.find((row) => row.node === 'a').totals.sum.observedBytes, 13680)
  t.is(report.nodes.find((row) => row.node === 'b').totals.sum.observedBytes, 3856)
  t.ok(report.completeCapture)
  t.ok(report.completeCompletions)
  t.ok(report.completeAllowanceCoverage)
  t.ok(report.completeLinkClassification)
})

test('R10 capture: guard bootstrap kinds share finite charged funding, not a governor', (t) => {
  const report = analyze(fixture())
  t.is(report.ledgers.length, 9)
  t.is(report.governors.length, 5)
  const ledger = report.ledgers.find((row) => row.node === 'a' && row.ledger === 7)
  t.is(ledger.governor, null)
  t.is(ledger.observedBytes, 2656)
  t.is(ledger.chargedCells, 3)
  t.is(ledger.chargedBytes, 3600)
  t.alike(
    ledger.byKind.map((row) => [row.kind, row.observedBytes]),
    [
      ['bootstrap-request', 256],
      ['link-setup', 1200],
      ['link-control', 1200]
    ]
  )
})

test('A2 capture negative control: missing owner', (t) => {
  const input = fixture()
  input.events = input.events.filter((row) => row.node !== 'a' || row.event.attemptId !== 14)
  rejects(t, input, 'MISSING_OWNER')
})

test('A2 capture negative control: a packet cannot satisfy competing charged owners', (t) => {
  const input = fixture()
  for (const row of input.events)
    if (row.node === 'a' && row.event.attemptId >= 2) row.event.attemptId++
  const duplicate = clone(attempt(input, 1))
  duplicate.event.attemptId = 2
  duplicate.event.owner.ledger = 99
  duplicate.event.obligation = 999
  input.events.push(duplicate, {
    node: 'a',
    runtime: 'runtime',
    lease: 'lease-1',
    at: 102,
    event: { kind: 'completion', attemptId: 2, outcome: 'sent' }
  })
  input.allowances.push({ ...input.allowances[0], ledger: 99 })
  rejects(t, input, 'DUPLICATE_OWNER')
})

test('A2 capture negative control: circuit discovery cannot claim neighbor funding', (t) => {
  const input = fixture()
  // The expected circuit-discovery allowance is fixture provenance, not inferred
  // from the event's category claim or from the datagram's appearance.
  const owner = attempt(input, 4).event.owner
  owner.kind = 'neighbor-discovery'
  owner.category = 'service'
  owner.class = 'neighbor'
  rejects(t, input, 'CATEGORY_MISMATCH')
})

test('A2 capture negative control: retry needs its own event and charged ordinal', (t) => {
  const noEvent = fixture()
  noEvent.events = noEvent.events.filter((row) => row.node !== 'a' || row.event.attemptId !== 2)
  rejects(t, noEvent, 'MISSING_OWNER')
  const reused = fixture()
  attempt(reused, 2).event.owner.ordinal = 1
  rejects(t, reused, 'UNCHARGED_RETRY')
})

test('A2 capture negative control: owner notification after packet emission', (t) => {
  const input = fixture()
  attempt(input, 1).at = 102
  rejects(t, input, 'CHARGE_AFTER_SEND')
})

test('A2 capture: kind fixes category and charged status; undocumented kinds are rejected', (t) => {
  for (const kind of ['direct', 'direct-response', 'ordinary-dht']) {
    const input = fixture()
    attempt(input, 9).event.owner.kind = kind
    rejects(t, input, 'UNSUPPORTED_OWNER')
  }
  for (const [field, value] of [
    ['category', 'service'],
    ['charged', false]
  ]) {
    const input = fixture()
    attempt(input, 1).event.owner[field] = value
    rejects(t, input, 'CATEGORY_MISMATCH')
  }
})

test('A2 capture: charged kinds require a ledger and ordinal, not a governor', (t) => {
  for (const [field, value] of [
    ['ledger', null],
    ['ordinal', null],
    ['governor', 77]
  ]) {
    const input = fixture()
    attempt(input, 1).event.owner[field] = value
    rejects(t, input, 'UNCHARGED_SEND')
  }
})

test('A2 capture: every uncharged kind requires a bounded governor identity', (t) => {
  for (const [field, value] of [
    ['governor', null],
    ['ledger', 1],
    ['ordinal', 1]
  ]) {
    const input = fixture()
    attempt(input, 13).event.owner[field] = value
    rejects(t, input, 'MISSING_GOVERNOR')
  }
})

test('R10 capture: governed sends cannot enter circuit, neighbor or guard-bootstrap links', (t) => {
  for (const id of [8, 12, 13]) {
    for (const linkClass of ['circuit', 'neighbor', 'guard-bootstrap']) {
      if (id === 12 && linkClass === 'guard-bootstrap') continue
      const input = fixture()
      const row = attempt(input, id)
      const link = input.links.find(
        (link) => link.node === 'a' && row.at >= link.start && row.at < link.end
      )
      link.class = linkClass
      link.requiresCharge = false // Required classes cannot be weakened by metadata.
      rejects(t, input, 'UNCHARGED_REQUIRED_LINK')
    }
  }
})

test('M4 capture: explicit charging rules apply beyond class names and missing classification is visible', (t) => {
  const required = fixture()
  required.links.find((row) => row.node === 'a' && row.start === 1099).requiresCharge = true
  rejects(t, required, 'UNCHARGED_REQUIRED_LINK')
  const unknown = fixture()
  delete unknown.links
  const report = analyze(unknown)
  t.absent(report.completeLinkClassification)
  t.is(report.unclassifiedAttempts, 18)
})

test('A2 capture: retries preserve obligation identity and packet multiplicity', (t) => {
  const input = fixture()
  const report = analyze(input)
  t.is(report.totals.circuit.retransmissions, 1)
  t.alike(
    report.joins
      .filter((row) => row.node === 'a' && row.ledger === 1)
      .map((row) => [row.attemptId, row.ordinal, row.obligation]),
    [
      [1, 1, 101],
      [2, 2, 101]
    ]
  )
  input.captures[1].duplicateOf = 'p-1'
  rejects(t, input, 'INVALID_CAPTURE_COPY')
})

test('A2 capture: same-time same-tap packets are not deduplicated', (t) => {
  const input = fixture()
  attempt(input, 2).at = 100
  completion(input, 2).at = 102
  input.captures[1].at = 101
  t.is(analyze(input).totals.circuit.observed, 4)
})

test('A2 capture: refused, failed and absent completions do not imply false equality', (t) => {
  const input = fixture()
  completion(input, 3).event.outcome = 'refused'
  completion(input, 5).event.outcome = 'failed'
  input.events = input.events.filter(
    (row) => !(row.node === 'a' && row.event.kind === 'completion' && row.event.attemptId === 9)
  )
  for (const id of [3, 5, 9]) removePacket(input, id)
  const report = analyze(input)
  t.is(report.totals.sum.attempted, 18)
  t.is(report.totals.sum.observed, 15)
  t.is(report.totals.sum.unobservedBytes, 2656)
  t.is(report.totals.sum.chargedBytes, 15600)
  t.is(report.totals.sum.refused, 1)
  t.is(report.totals.sum.failed, 1)
  t.is(report.totals.sum.unresolved, 1)
  t.absent(report.completeCapture)
  t.absent(report.completeCompletions)
  t.alike(
    report.differences.map((row) => row.reason),
    ['refused', 'failed', 'unresolved']
  )
})

test('A2 capture: successful unobserved native sends require specific loss evidence', (t) => {
  const input = fixture()
  removePacket(input, 9)
  rejects(t, input, 'MISSING_CAPTURE')
  input.captureLosses.push({
    node: 'a',
    runtime: 'runtime',
    lease: 'lease-1',
    attemptId: 9,
    reason: 'capture buffer overrun',
    evidence: 'tcpdump-drop-report-1'
  })
  const report = analyze(input)
  t.is(report.totals.bootstrap.captureLoss, 1)
  t.is(report.totals.sum.attempted, 18)
  t.is(report.totals.sum.observed, 17)
  t.absent(report.completeCapture)
  t.is(report.differences[0].evidence, 'tcpdump-drop-report-1')
})

test('A2 capture: loss declarations cannot excuse captured or unknown attempts', (t) => {
  for (const attemptId of [1, 999]) {
    const input = fixture()
    input.captureLosses.push({
      node: 'a',
      runtime: 'runtime',
      lease: 'lease-1',
      attemptId,
      reason: 'drop',
      evidence: 'counter-1'
    })
    rejects(t, input, 'INVALID_CAPTURE_LOSS')
  }
})

test('A2 capture: circuit and closure can share an actual ledger but not create another allowance', (t) => {
  const input = fixture()
  input.allowances[0].kinds.push('closure')
  attempt(input, 3).event.owner.ledger = 1
  attempt(input, 3).event.owner.ordinal = 3
  const ledger = analyze(input).ledgers.find((row) => row.node === 'a' && row.ledger === 1)
  t.is(ledger.observed, 3)
  t.alike(
    ledger.byKind.map((row) => [row.kind, row.observedBytes]),
    [
      ['circuit', 2400],
      ['closure', 1200]
    ]
  )
  input.allowances[0].datagrams = 2
  rejects(t, input, 'ALLOWANCE_EXCEEDED')
})

test('A2 capture: declared limits are independent, optional and never synthesized from sends', (t) => {
  const input = fixture()
  delete input.allowances
  const report = analyze(input)
  t.is(report.totals.sum.observedBytes, 17536)
  t.absent(report.completeAllowanceCoverage)
  for (const [field, value] of [
    ['datagrams', 1],
    ['bytes', 2399]
  ]) {
    const limited = fixture()
    limited.allowances[0][field] = value
    rejects(t, limited, 'ALLOWANCE_EXCEEDED')
  }
})

test('A2 capture: generations isolate ledger lifetimes while runtime attempt IDs stay unique', (t) => {
  const input = fixture()
  const original = clone(attempt(input, 1))
  input.leases[0].end = 2000
  input.leases.push({
    ...input.leases[0],
    lease: 'lease-2',
    socketGeneration: 2,
    start: 2000,
    end: 10000
  })
  input.allowances.push({ ...input.allowances[0], lease: 'lease-2', datagrams: 1, bytes: 1200 })
  input.links.push({ ...input.links[0], lease: 'lease-2', start: 2000, end: 2004 })
  original.lease = 'lease-2'
  original.at = 2001
  original.event.attemptId = 15
  original.event.socketGeneration = 2
  input.events.push(original, {
    node: 'a',
    runtime: 'runtime',
    lease: 'lease-2',
    at: 2003,
    event: { kind: 'completion', attemptId: 15, outcome: 'sent' }
  })
  input.captures.push({ ...input.captures[0], lease: 'lease-2', id: 'p-renew', at: 2002 })
  const report = analyze(input)
  t.alike(
    report.ledgers
      .filter((row) => row.node === 'a' && row.ledger === 1)
      .map((row) => [row.lease, row.attempted]),
    [
      ['lease-1', 2],
      ['lease-2', 1]
    ]
  )
  original.event.attemptId = 1
  rejects(t, input, 'DUPLICATE_OWNER')
  original.event.attemptId = 15
  input.captures[input.captures.length - 1].lease = 'lease-1'
  rejects(t, input, 'SOCKET_GENERATION')
})

test('A2 capture: completion cannot predate or duplicate its attempt', (t) => {
  const early = fixture()
  completion(early, 1).at = 99
  rejects(t, early, 'COMPLETION_BEFORE_ATTEMPT')
  const duplicate = fixture()
  duplicate.events.push(clone(completion(duplicate, 1)))
  rejects(t, duplicate, 'DUPLICATE_COMPLETION')
})

test('A2 capture: native refusal cannot own an independently captured packet', (t) => {
  const input = fixture()
  completion(input, 3).event.outcome = 'refused'
  rejects(t, input, 'FAILED_SEND_OBSERVED')
})

test('A2 capture: size and maximum capture delay remain strict boundaries', (t) => {
  const size = fixture()
  attempt(size, 1).event.bytes = 1199
  rejects(t, size, 'DATAGRAM_SIZE')
  const late = fixture()
  late.captures[1].at = 126
  rejects(t, late, 'MISSING_OWNER')
})

test('A2 capture: IPv4-mapped and equivalent IPv6 tuples normalize without DNS', (t) => {
  const input = fixture()
  input.captures[0].local.host = '::ffff:10.20.0.1'
  input.captures[input.captures.length - 1].local.host = '0:0:0:0:0:ffff:a14:1'
  input.leases[1].local.host = '2001:db8::1'
  for (const row of input.events)
    if (row.node === 'b' && row.event.kind === 'attempt')
      row.event.local.host = '2001:0db8:0:0:0:0:0:1'
  for (const row of input.captures) if (row.node === 'b') row.local.host = '2001:db8:0::1'
  for (const row of input.links) if (row.node === 'b') row.local.host = '2001:db8::1'
  t.is(analyze(input).datagrams, 18)
})

test('R10 capture: the former uncharged A0 fallback is no longer a valid owner', (t) => {
  for (const id of [9, 10, 11]) {
    const input = fixture()
    const owner = attempt(input, id).event.owner
    owner.charged = false
    owner.ledger = null
    owner.ordinal = null
    owner.governor = 300
    rejects(t, input, 'CATEGORY_MISMATCH')
  }
})

test('M4 capture: ambiguous independent link windows cannot choose an exemption', (t) => {
  const input = fixture()
  const window = input.links.find((row) => row.node === 'a' && row.start === 1099)
  input.links.push({ ...window, class: 'circuit', requiresCharge: true })
  rejects(t, input, 'AMBIGUOUS_LINK_CLASS')
})

test('R10 capture: native class is required and cannot be inferred from funding', (t) => {
  for (const value of [undefined, 'a0']) {
    const input = fixture()
    attempt(input, 1).event.owner.class = value
    rejects(t, input, 'INVALID_OWNER_CLASS')
  }
  const wrong = fixture()
  attempt(wrong, 1).event.owner.class = 'neighbor'
  rejects(t, wrong, 'CLASS_MISMATCH')
})

test('R10 capture: one ledger cannot change its creating class', (t) => {
  const input = fixture()
  delete input.allowances
  attempt(input, 9).event.owner.ledger = 1
  attempt(input, 9).event.owner.ordinal = 3
  rejects(t, input, 'OWNER_CLASS_CHANGE')
})

test('R10 capture: short charged requests still debit 1200 bytes before native send', (t) => {
  const input = fixture()
  const allowance = input.allowances.find((row) => row.node === 'a' && row.ledger === 7)
  allowance.bytes = 3600
  t.is(analyze(input).totals.bootstrap.chargedBytes, 6000)
  allowance.bytes--
  rejects(t, input, 'ALLOWANCE_EXCEEDED')
})

test('R10 capture: phase-zero replies remain governed without consuming bootstrap charges', (t) => {
  const report = analyze(fixture())
  const reply = report.governors.find((row) => row.node === 'b' && row.governor === 108)
  t.is(reply.class, 'responder-cache')
  t.is(reply.observedBytes, 256)
  t.is(reply.chargedBytes, 0)
  t.is(report.totals.bootstrap.chargedCells, 5)
})

test('R10 capture: shared A0 v1 traffic is separate from native bootstrap funding', (t) => {
  const input = fixture()
  const report = analyze(input)
  const link = report.linkEvidence.find((row) => row.node === 'a' && row.attemptId === 12)
  t.is(link.class, 'guard-bootstrap')
  t.is(link.ownerClass, 'v1-routed-branch')
  t.is(report.totals['v1-routed'].chargedBytes, 0)
  attempt(input, 12).event.owner.category = 'circuit'
  rejects(t, input, 'CATEGORY_MISMATCH')
})
