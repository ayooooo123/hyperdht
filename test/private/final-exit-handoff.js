const b4a = require('b4a')
const test = require('brittle')

const {
  consumeFinalExitHandoff,
  createFinalExitHandoff,
  destroyFinalExitHandoffMaterial,
  revokeFinalExitHandoff
} = require('../../lib/private/final-exit-handoff')

function material(owner) {
  return {
    clockIdentity: owner,
    expiresAt: 5_000n,
    finalizeForwardKey: b4a.alloc(32, 1),
    finalizeForwardNoncePrefix: b4a.alloc(16, 2),
    finalizeReverseKey: b4a.alloc(32, 3),
    finalizeReverseNoncePrefix: b4a.alloc(16, 4),
    initiator: true,
    localDeadline: 4_000n,
    sharedSecret: b4a.alloc(32, 5),
    tailControl: owner,
    tailControlTranscript: b4a.alloc(290, 6),
    wireExpiresAt: 5_000n
  }
}

test('final-exit handoff moves once and revoke erases all owned secrets', (t) => {
  const owner = Object.freeze({})
  const firstMaterial = material(owner)
  const first = createFinalExitHandoff(owner, firstMaterial)
  t.alike(Object.keys(first), [])
  t.is(consumeFinalExitHandoff(first), firstMaterial)
  t.exception(() => consumeFinalExitHandoff(first))
  t.is(destroyFinalExitHandoffMaterial(firstMaterial), true)
  t.is(firstMaterial.sharedSecret, null)
  t.is(firstMaterial.tailControlTranscript, null)

  const secondMaterial = material(owner)
  const second = createFinalExitHandoff(owner, secondMaterial)
  t.is(revokeFinalExitHandoff(owner), true)
  t.exception(() => consumeFinalExitHandoff(second))
  t.is(secondMaterial.tailControl, null)
  t.is(secondMaterial.finalizeForwardKey, null)
  t.is(revokeFinalExitHandoff(owner), false)
})
