const b4a = require('b4a')
const test = require('brittle')

const {
  createTailExtensionCommitter,
  destroyTailExtensionCommitter,
  enqueueTailExtended,
  installTailExtension
} = require('../../lib/private/tail-extension-committer')
const { M3_CONTEXT_ENVELOPE_SIZE } = require('../../lib/private/m3-context')

function expectCode(t, operation, code, message) {
  let error = null
  try {
    operation()
  } catch (err) {
    error = err
  }
  t.is(error && error.code, code, message)
}

function forwarding(onDestroy = () => {}) {
  let live = true
  return Object.freeze({
    diagnostics() {
      if (!live) throw new Error('destroyed')
      return Object.freeze({ state: 'CREATE', expiresAt: 5_000n })
    },
    destroy() {
      if (!live) return false
      live = false
      onDestroy()
      return true
    }
  })
}

test('tail extension committer enforces enqueue before one atomic runtime install', (t) => {
  const events = []
  const envelope = b4a.alloc(M3_CONTEXT_ENVELOPE_SIZE, 0x11)
  const nextRuntime = Object.freeze({})
  const installed = forwarding()
  const expiresAt = 10n
  const committer = createTailExtensionCommitter({
    enqueue(value) {
      events.push(['enqueue', value])
    },
    install(value, expiry) {
      events.push(['install', value, expiry])
      return installed
    },
    destroy() {
      events.push(['destroy'])
    }
  })

  expectCode(t, () => installTailExtension(committer, nextRuntime, expiresAt), 'ERR_REPLAY')
  t.is(enqueueTailExtended(committer, envelope), true)
  expectCode(t, () => enqueueTailExtended(committer, envelope), 'ERR_REPLAY')
  t.is(installTailExtension(committer, nextRuntime, expiresAt), installed)
  t.alike(events, [
    ['enqueue', envelope],
    ['install', nextRuntime, expiresAt]
  ])
  expectCode(t, () => installTailExtension(committer, nextRuntime, expiresAt), 'ERR_REPLAY')
  t.is(destroyTailExtensionCommitter(committer), false)
})

test('caught enqueue reentry poisons the committer before runtime installation', (t) => {
  const envelope = b4a.alloc(M3_CONTEXT_ENVELOPE_SIZE, 0x21)
  let committer = null
  let nestedCode = null
  let installs = 0
  let destroys = 0
  committer = createTailExtensionCommitter({
    enqueue() {
      try {
        enqueueTailExtended(committer, envelope)
      } catch (err) {
        nestedCode = err && err.code
      }
    },
    install() {
      installs++
      return forwarding()
    },
    destroy() {
      destroys++
    }
  })

  expectCode(t, () => enqueueTailExtended(committer, envelope), 'INVALID_ROUTE')
  t.is(nestedCode, 'ERR_BUSY')
  t.is(installs, 0)
  t.is(destroys, 1)
  t.is(destroyTailExtensionCommitter(committer), false)
})

test('caught install reentry destroys an unpublished forwarding record and branch owner', (t) => {
  const envelope = b4a.alloc(M3_CONTEXT_ENVELOPE_SIZE, 0x31)
  const nextRuntime = Object.freeze({})
  const expiresAt = 20n
  let committer = null
  let nestedCode = null
  let forwardingDestroys = 0
  let branchDestroys = 0
  committer = createTailExtensionCommitter({
    enqueue() {},
    install() {
      try {
        installTailExtension(committer, nextRuntime, expiresAt)
      } catch (err) {
        nestedCode = err && err.code
      }
      return forwarding(() => forwardingDestroys++)
    },
    destroy() {
      branchDestroys++
    }
  })
  enqueueTailExtended(committer, envelope)

  expectCode(t, () => installTailExtension(committer, nextRuntime, expiresAt), 'INVALID_ROUTE')
  t.is(nestedCode, 'ERR_BUSY')
  t.is(forwardingDestroys, 1)
  t.is(branchDestroys, 1)
  t.is(destroyTailExtensionCommitter(committer), false)
})
