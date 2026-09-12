'use strict'

// Review-only fault injection. Never load this from application code.
// Usage: node activation-material-probe.cjs /path/to/extracted/code
// A failing final assertion demonstrates acceptance of changed material.
const assert = require('node:assert/strict')
const Module = require('node:module')
const path = require('node:path')
const root = path.resolve(process.argv[2] || process.cwd())
const activationPath = path.join(root, 'lib/private/final-exit-activation.js')
const marker = '    commitTailControlFinalExitActivation(prepared.transfer, owner)'
const hookKey = Symbol('activation-material-review-only')
const originalCompile = Module.prototype._compile
let installed = 0
let hook = null

globalThis[hookKey] = (prepared) => hook(prepared)
// The injected expression uses a unique, non-enumerable module-local binding.
Module.prototype._compile = function (source, filename) {
  if (filename === activationPath) {
    assert.equal(source.split(marker).length, 2, 'exactly one claim commit boundary')
    installed++
    source = source.replace(marker, '    module.__reviewMaterialHook(prepared)\n' + marker)
    Object.defineProperty(this, '__reviewMaterialHook', {
      value: (prepared) => globalThis[hookKey](prepared)
    })
  }
  return originalCompile.call(this, source, filename)
}

async function main() {
  let fixtureModule, tail, activation, ledger
  try {
    fixtureModule = require(path.join(root, 'test/private/peer-native-fixture'))
    tail = require(path.join(root, 'lib/private/peer-tail-control'))
    activation = require(activationPath)
    ledger = require(path.join(root, 'lib/private/peer-ledger'))
  } finally {
    Module.prototype._compile = originalCompile
  }
  assert.equal(installed, 1, 'only activation claim orchestration instrumented')

  const scenarios = [
    ['unchanged', () => {}],
    [
      'localDeadline',
      (material) => {
        material.localDeadline += 1000n
      }
    ],
    [
      'tailControl',
      (material) => {
        material.tailControl = Object.freeze({})
      }
    ],
    [
      'clockIdentity',
      (material) => {
        material.clockIdentity = Object.freeze({})
      }
    ]
  ]
  const results = []
  for (let index = 0; index < scenarios.length; index++) {
    const [field, mutate] = scenarios[index]
    const cleanup = []
    const harness = { teardown: (fn) => cleanup.push(fn) }
    let session = null
    let owner = null
    let material = null
    let original = null
    let hookCalls = 0
    let result = null
    try {
      const fixture = await fixtureModule.authenticatedPeer(harness, 49120 + index * 4, 2, true)
      session = tail.createPeerTailControl(fixture.peerRuntime, {
        relayOwner: fixture.f.peerRelayOwner,
        neighborPool: fixture.f.peerPool,
        runtimeAuthority: fixture.peerAuthority,
        memoryPool: ledger.createPeerMemoryPool(4096)
      })
      const handoff = tail.createPeerFinalExitHandoff(session)
      hook = (prepared) => {
        hookCalls++
        material = prepared.material
        original = { ...material }
        mutate(material)
      }
      try {
        owner = activation.claimFinalExitActivation(
          handoff,
          activation.createFinalExitActivationClaim(handoff)
        )
        result = {
          field,
          accepted: true,
          materialFrozen: Object.isFrozen(material),
          fieldChanged: field !== 'unchanged' && material[field] !== original[field]
        }
      } catch (error) {
        result = { field, accepted: false, error: error.code || error.message }
      }
      assert.equal(hookCalls, 1, 'genuine prepare completed before mutation')
      results.push(result)
    } finally {
      hook = null
      // Restore metadata only after observing commit, so normal cleanup owns it.
      if (material && original) Object.assign(material, original)
      if (owner) activation.destroyFinalExitActivationOwner(owner)
      if (session) tail.destroyPeerTailControl(session)
      for (const close of cleanup.reverse()) await close()
    }
  }
  console.log(
    JSON.stringify(
      {
        instrumentation:
          'one hook between genuine prepare and commit; no authority fabrication; no disk source edits',
        transport: 'actual udx-native sockets; fixture fake clock',
        limitation:
          'internal fault-injection proof; not evidence that an ordinary caller can intercept this synchronous boundary',
        results
      },
      null,
      2
    )
  )
  assert.equal(results[0].accepted, true, 'unchanged control must commit')
  assert.equal(
    results.slice(1).every((result) => !result.accepted),
    true,
    'commit must reject material whose parent deadline, owner or clock identity changed after prepare'
  )
}

main()
  .catch((error) => {
    console.error(error)
    process.exitCode = 1
  })
  .finally(() => {
    Module.prototype._compile = originalCompile
    delete globalThis[hookKey]
  })
