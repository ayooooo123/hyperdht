const b4a = require('b4a')
const test = require('brittle')

const {
  createFinalExitHandoff,
  consumeFinalExitHandoff
} = require('../../lib/private/final-exit-handoff')
const {
  FinalExitActivationSession,
  claimFinalExitActivation,
  createFinalExitActivationClaim,
  revokeFinalExitActivationClaim
} = require('../../lib/private/final-exit-activation')

function material(owner, fill = 1) {
  return {
    clockIdentity: owner,
    expiresAt: 5_000n,
    finalizeForwardKey: b4a.alloc(32, fill),
    finalizeForwardNoncePrefix: b4a.alloc(16, fill + 1),
    finalizeReverseKey: b4a.alloc(32, fill + 2),
    finalizeReverseNoncePrefix: b4a.alloc(16, fill + 3),
    initiator: true,
    localDeadline: 4_000n,
    sharedSecret: b4a.alloc(32, fill + 4),
    tailControl: owner,
    tailControlTranscript: b4a.alloc(290, fill + 5),
    wireExpiresAt: 5_000n
  }
}

test('final-exit activation rejects handoffs outside the tail-control bridge', (t) => {
  const owner = Object.freeze({})
  const handoff = createFinalExitHandoff(owner, material(owner))
  const claim = createFinalExitActivationClaim(handoff)
  const alternateOwner = Object.freeze({})
  const alternate = createFinalExitHandoff(alternateOwner, material(alternateOwner, 9))

  t.exception(() => claimFinalExitActivation(alternate, claim), 'claim is bound to its handoff')
  t.is(consumeFinalExitHandoff(alternate).tailControl, alternateOwner)
  t.exception(() => claimFinalExitActivation(handoff, claim), 'raw handoff has no tail bridge')
  t.is(consumeFinalExitHandoff(handoff).tailControl, owner)
  t.exception(() => claimFinalExitActivation(handoff, claim), 'claim is spent')
})

test('final-exit activation claim revoke preserves raw handoff for a fresh claim', (t) => {
  const owner = Object.freeze({})
  const handoff = createFinalExitHandoff(owner, material(owner))
  const claim = createFinalExitActivationClaim(handoff)

  t.is(revokeFinalExitActivationClaim(claim), true)
  t.exception(() => claimFinalExitActivation(handoff, claim), 'revoked claim is spent')

  const replacement = createFinalExitActivationClaim(handoff)
  t.exception(
    () => claimFinalExitActivation(handoff, replacement),
    'raw replacement handoff has no tail bridge'
  )
  t.is(consumeFinalExitHandoff(handoff).tailControl, owner)
})

test('FinalExitActivationSession rejects unclaimed owners before takeOpenHandoff is reachable', (t) => {
  t.is(typeof FinalExitActivationSession, 'function')
  t.is(typeof FinalExitActivationSession.prototype.takeOpenHandoff, 'function')
  const owner = Object.freeze({})
  t.exception(
    () =>
      new FinalExitActivationSession(owner, {
        now: () => 1_000n,
        crypto: {
          seal() {},
          open() {},
          sign() {},
          verify() {}
        },
        payloadParameters: {
          cellSize: 1200,
          maxCellPayload: 1146,
          contextEnvelopeSize: 1101,
          routeFrameSize: 1100,
          maxRoutePayload: 1073,
          datagramReplayWindow: 64,
          maxQueuedBytes: 65_536,
          idleTimeoutMs: 5_000
        }
      }),
    'unclaimed opaque owner cannot reach OPEN handoff issuance'
  )
})
