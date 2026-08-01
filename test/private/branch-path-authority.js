'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { PrivateRouteError } = require('../../lib/private/errors')
const { BRANCH_CLASS } = require('../../lib/private/protocol')
const { kInspectRelayCandidateDirectory } = require('../../lib/private/relay-candidate-directory')
const {
  commitInitialBranchDrafts,
  createInitialBranchDrafts,
  destroyInitialBranchDrafts,
  inspectInitialBranchDrafts
} = require('../../lib/private/branch-path-authority')
const { issueGuardLeaseM3CellLinkTransferIssuer } = require('../../lib/private/guard-lease')
const { liveTopologyFixture } = require('./live-topology-fixture')

function expectCode(t, fn, code) {
  let error = null
  try {
    fn()
  } catch (err) {
    error = err
  }
  t.ok(error instanceof PrivateRouteError)
  t.is(error && error.code, code)
}

function draftOptions(fixture, seed) {
  return {
    guardLease: fixture.guardLease,
    candidateDirectory: fixture.directory,
    lookupGeneration: 1n,
    announceGeneration: 1n,
    lookupBranchId: b4a.alloc(16, seed),
    announceBranchId: b4a.alloc(16, seed + 1),
    lookupCircuitId: b4a.alloc(16, seed + 2),
    announceCircuitId: b4a.alloc(16, seed + 3),
    absoluteDeadline: fixture.clock.monotonicNow() + 5_000n
  }
}

test('InitialBranchDrafts reserve both branches and abort without commit', async (t) => {
  const fixture = await liveTopologyFixture(47407, 47408)
  const drafts = createInitialBranchDrafts(draftOptions(fixture, 0x51))
  const observed = inspectInitialBranchDrafts(drafts)

  t.is(observed.committed, false)
  t.is(observed.issuerCount, 4)
  t.is(observed.lookup.branchClass, BRANCH_CLASS.LOOKUP)
  t.is(observed.announce.branchClass, BRANCH_CLASS.ANNOUNCE)
  t.is(fixture.directory[kInspectRelayCandidateDirectory]().pendingCount, 2)
  expectCode(
    t,
    () => issueGuardLeaseM3CellLinkTransferIssuer(fixture.guardLease),
    'ERR_QUOTA_EXCEEDED'
  )

  t.is(destroyInitialBranchDrafts(drafts), true)
  t.is(destroyInitialBranchDrafts(drafts), false)
  t.is(fixture.directory[kInspectRelayCandidateDirectory]().pendingCount, 0)
  const replacement = issueGuardLeaseM3CellLinkTransferIssuer(fixture.guardLease)
  t.is(replacement.destroy(), true)
  await fixture.close()
})

test('InitialBranchDrafts commit exactly once and reject replay', async (t) => {
  const fixture = await liveTopologyFixture(47409, 47410)
  const drafts = createInitialBranchDrafts(draftOptions(fixture, 0x61))

  t.is(commitInitialBranchDrafts(drafts), true)
  expectCode(t, () => commitInitialBranchDrafts(drafts), 'ERR_REPLAY')
  t.is(fixture.directory[kInspectRelayCandidateDirectory]().pendingCount, 0)
  t.is(fixture.directory[kInspectRelayCandidateDirectory]().generationRecordCount, 2)
  t.is(destroyInitialBranchDrafts(drafts), true)
  await fixture.close()
})
