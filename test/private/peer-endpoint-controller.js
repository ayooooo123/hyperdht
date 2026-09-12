'use strict'

const test = require('brittle')
const b4a = require('b4a')
const { Writable } = require('streamx')
const SecretStream = require('@hyperswarm/secret-stream')
const NoiseWrap = require('../../lib/noise-wrap')
const { PrivateRouteError } = require('../../lib/private/errors')
const { createPeerEndpointController } = require('../../lib/private/peer-endpoint-controller')

const PROFILE = { error: 0, firewall: 0, secretStream: { version: 1 } }
const ACTIVE_OWNER = { diagnostics: () => ({ status: 'ACTIVE' }) }
const AUTHENTICATION = { code: 'ERR_AUTHENTICATION' }
const DESTROYED = { code: 'ERR_DESTROYED' }

function deferred() {
  let resolve
  let reject
  const promise = new Promise((yes, no) => {
    resolve = yes
    reject = no
  })
  promise.catch(() => {})
  return { promise, resolve, reject }
}

function turn() {
  return new Promise((resolve) => setImmediate(resolve))
}

async function waitFor(predicate) {
  for (let i = 0; i < 100; i++) {
    if (predicate()) return
    await turn()
  }
  throw new Error('Endpoint operation did not settle')
}

function readOne(stream) {
  return new Promise((resolve, reject) => {
    function cleanup() {
      stream.removeListener('readable', onReadable)
      stream.removeListener('end', onEnd)
      stream.removeListener('error', onError)
      stream.removeListener('close', onClose)
    }
    function finish(error, value) {
      cleanup()
      if (error) reject(error)
      else resolve(value)
    }
    function onReadable() {
      const value = stream.read()
      if (value !== null) finish(null, value)
    }
    function onEnd() {
      finish(null, null)
    }
    function onError(error) {
      finish(error)
    }
    function onClose() {
      finish(new Error('Closed before the next record'))
    }
    stream.on('readable', onReadable)
    stream.on('end', onEnd)
    stream.on('error', onError)
    stream.on('close', onClose)
    onReadable()
  })
}

// A semantic-lease fixture, not a second protocol implementation. Only the
// ratified endpoint methods cross into the controller; transport and credits
// remain here. Noise and secret-stream are the actual pinned dependencies.
function createSession(options = {}) {
  const opened = deferred()
  const closed = deferred()
  const confirmation = deferred()
  const fin = deferred()
  const authenticated = deferred()
  const state = {
    peer: null,
    hooks: null,
    attached: false,
    revoked: false,
    ready: false,
    incoming: [],
    handshakes: [],
    fragments: [],
    resets: [],
    events: [],
    binding: null,
    budget: Infinity,
    timer: null,
    finishCalls: 0,
    opened,
    closed,
    confirmation,
    fin,
    onConfirm: null,
    onSend: null,
    onRevoke: null
  }

  function schedule() {
    if (state.revoked || state.timer !== null) return
    state.timer = setImmediate(() => {
      state.timer = null
      drain()
    })
  }

  function drain() {
    if (state.revoked || state.hooks === null) return
    while (!state.revoked && state.incoming.length) {
      const event = state.incoming[0]
      if (event.kind === 'ciphertext') {
        if (!state.ready) break
        const consumed = state.hooks.onCiphertext(event.bytes.subarray(event.offset))
        if (consumed === 0) break
        if (
          !Number.isInteger(consumed) ||
          consumed < 0 ||
          consumed > event.bytes.byteLength - event.offset
        ) {
          throw new Error('Invalid ciphertext consumption')
        }
        event.offset += consumed
        if (event.offset < event.bytes.byteLength) break
        state.incoming.shift()
      } else {
        state.incoming.shift()
        if (event.kind === 'handshake') state.hooks.onHandshake(event.bytes)
        else if (event.kind === 'fin') state.hooks.onRemoteFin()
        else state.hooks.onReset(event.error)
      }
    }
  }

  state.enqueue = (event) => {
    if (state.revoked) return
    state.incoming.push(event)
    schedule()
  }
  state.authenticate = () => {
    if (state.revoked) return
    state.hooks.onAuthenticatedOpen()
    authenticated.resolve()
  }
  state.writable = () => {
    if (!state.revoked) state.hooks.onWritable()
  }
  state.receive = (bytes) => state.enqueue({ kind: 'ciphertext', bytes, offset: 0 })
  Promise.all([confirmation.promise, authenticated.promise, opened.promise]).then(
    () => {
      state.ready = true
      schedule()
    },
    () => {}
  )

  const lease = Object.freeze({
    sendHandshake(bytes) {
      if (state.revoked) throw PrivateRouteError.ERR_DESTROYED()
      const copy = b4a.from(bytes)
      state.handshakes.push(copy)
      if (state.peer) state.peer.enqueue({ kind: 'handshake', bytes: copy })
    },
    confirmHandshake(binding) {
      state.binding = binding
      if (state.onConfirm) state.onConfirm(binding)
      if (!options.holdConfirmation) confirmation.resolve()
      if (!options.holdAuthentication) state.authenticate()
      if (!options.holdCredit) opened.resolve()
      return confirmation.promise
    },
    trySendCiphertext(bytes) {
      if (state.revoked) throw PrivateRouteError.ERR_DESTROYED()
      if (state.onSend) {
        const result = state.onSend(bytes)
        if (result !== undefined) return result
      }
      if (state.budget === 0) return false
      if (bytes.byteLength < 1 || bytes.byteLength > 977) throw new Error('Invalid fragment size')
      state.budget--
      const copy = b4a.from(bytes)
      state.fragments.push(copy)
      if (state.peer) state.peer.receive(copy)
      return true
    },
    drain() {
      if (options.drainError) throw options.drainError
      schedule()
    },
    finish() {
      state.finishCalls++
      state.events.push('finish')
      if (state.peer) state.peer.enqueue({ kind: 'fin' })
      if (!options.holdFinish) fin.resolve()
      return fin.promise
    },
    reset(error) {
      state.resets.push(error)
      state.events.push('reset')
      if (state.peer) state.peer.enqueue({ kind: 'reset', error })
    },
    revoke(error) {
      if (state.revoked) return
      state.revoked = true
      state.events.push('revoke')
      clearImmediate(state.timer)
      state.timer = null
      state.incoming.length = 0
      if (state.onRevoke) state.onRevoke(error)
      if (!options.holdClose) closed.resolve()
    },
    whenOpen: () => opened.promise,
    finished: () => closed.promise,
    diagnostics: () => ({ status: state.revoked ? 'CLOSED' : 'ACTIVE' })
  })

  state.session = Object.freeze({
    attachEndpoint(hooks) {
      if (state.attached) throw PrivateRouteError.INVALID_ROUTE()
      state.attached = true
      state.hooks = hooks
      schedule()
      return lease
    }
  })
  return state
}

function createPair(t, optionsA, optionsB) {
  const a = createSession(optionsA)
  const b = createSession(optionsB)
  a.peer = b
  b.peer = a
  const keyA = SecretStream.keyPair()
  const keyB = SecretStream.keyPair()
  const originalA = { publicKey: b4a.from(keyA.publicKey), secretKey: b4a.from(keyA.secretKey) }
  const originalB = { publicKey: b4a.from(keyB.publicKey), secretKey: b4a.from(keyB.secretKey) }
  b.controller = createPeerEndpointController({
    owner: ACTIVE_OWNER,
    session: b.session,
    keyPair: keyB
  })
  a.controller = createPeerEndpointController({
    owner: ACTIVE_OWNER,
    session: a.session,
    keyPair: keyA,
    remotePublicKey: keyB.publicKey
  })
  t.teardown(async () => {
    for (const side of [a, b]) {
      side.confirmation.resolve()
      side.closed.resolve()
      side.fin.resolve()
    }
    await Promise.all([a.controller.destroy(), b.controller.destroy()])
  })
  return { a, b, keyA, keyB, originalA, originalB }
}

async function openPair(pair) {
  return Promise.all([pair.a.controller.whenOpen(), pair.b.controller.whenOpen()])
}

function createResponder(t, options) {
  const state = createSession(options)
  const keyPair = SecretStream.keyPair()
  const remote = new NoiseWrap(SecretStream.keyPair(), keyPair.publicKey)
  state.controller = createPeerEndpointController({
    owner: ACTIVE_OWNER,
    session: state.session,
    keyPair
  })
  state.remote = remote
  t.teardown(async () => {
    state.confirmation.resolve()
    state.closed.resolve()
    state.fin.resolve()
    await state.controller.destroy()
  })
  return state
}

test('endpoint waits for confirmation, authentication and semantic credit before publishing plaintext', async function (t) {
  const pair = createPair(
    t,
    { holdConfirmation: true, holdAuthentication: true, holdCredit: true },
    { holdCredit: true }
  )
  const { a, b } = pair
  let published = false
  a.controller.whenOpen().then(() => {
    published = true
  })
  await waitFor(() => a.binding !== null && b.binding !== null)
  t.is(a.controller.stream, null)
  t.is(published, false)
  a.opened.resolve()
  await turn()
  t.is(a.controller.stream, null, 'credit alone cannot publish')
  a.authenticate()
  await turn()
  t.is(a.controller.stream, null, 'verification must also settle')
  a.confirmation.resolve()
  b.opened.resolve()
  const [left, right] = await openPair(pair)
  t.is(left, a.controller.stream)
  t.is(right, b.controller.stream)
  t.alike(a.controller.diagnostics(), { status: 'OPEN', authenticated: true, creditReady: true })
  t.is(a.handshakes[0].byteLength, 101)
  t.is(b.handshakes[0].byteLength, 53)
  t.alike(a.binding.remotePublicKey, pair.keyB.publicKey)
  t.alike(b.binding.remotePublicKey, pair.keyA.publicKey)
  t.alike(a.binding.tx, b.binding.rx, 'Noise directions agree')
})

test('endpoint native records retain backing under fragment backpressure and reverse writes', async function (t) {
  const pair = createPair(t)
  const { a, b } = pair
  const [left, right] = await openPair(pair)
  const payload = b4a.alloc(977 * 3, 0x31)
  const reading = readOne(right)
  const before = a.fragments.length
  a.budget = 1
  left.write(payload)
  let drained = false
  const writing = Writable.drained(left).then((ok) => {
    drained = true
    return ok
  })
  await waitFor(() => a.fragments.length > before)
  t.is(drained, false, 'blocked record retains the plaintext write')
  a.budget = Infinity
  a.writable()
  t.is(await writing, true)
  const first = await reading
  t.alike(first, payload)
  t.is(first.byteOffset, 4)
  t.is(first.buffer.byteLength, payload.byteLength + 20)
  t.alike(
    a.fragments.slice(before).map((bytes) => bytes.byteLength),
    [977, 977, 977, 20]
  )

  const second = b4a.from('next record after retained plaintext')
  left.write(second)
  await Writable.drained(left)
  await turn()
  t.ok(
    b.incoming.some((event) => event.kind === 'ciphertext'),
    'semantic queue retains the next record'
  )
  const next = await readOne(right)
  t.alike(next, second)
  t.not(next.buffer, first.buffer)
  t.alike(first, payload)

  const reply = b4a.from('reverse direction')
  const reverse = readOne(left)
  right.write(reply)
  t.is(await Writable.drained(right), true)
  t.alike(await reverse, reply)
  await Promise.all([a.controller.destroy(), b.controller.destroy()])
  t.alike(first, payload, 'teardown preserves application-owned plaintext')
  t.alike(pair.keyA, pair.originalA)
  t.alike(pair.keyB, pair.originalB, 'caller identity keys were not erased')
})

test('endpoint half-close waits for semantic FIN completion and permits reverse traffic', async function (t) {
  const pair = createPair(t, { holdFinish: true })
  const { a, b } = pair
  const [left, right] = await openPair(pair)
  const eof = readOne(right)
  let finished = false
  left.once('finish', () => {
    finished = true
  })
  left.end()
  t.is(await eof, null)
  t.is(a.finishCalls, 1)
  t.is(finished, false, 'local finish is joined to semantic FIN')
  const reverse = readOne(left)
  right.write(b4a.from('still writable after remote EOF'))
  await Writable.drained(right)
  t.alike(await reverse, b4a.from('still writable after remote EOF'))
  a.fin.resolve()
  await waitFor(() => finished)
  const reverseEof = readOne(left)
  right.end()
  t.is(await reverseEof, null)
  await Promise.all([a.controller.finished(), b.controller.finished()])
  t.alike(a.resets, [], 'graceful close does not reset the session')
  t.alike(b.resets, [])
  t.ok(left.destroyed && right.destroyed)
})

test('endpoint attachment is one-shot without revoking the existing controller', async function (t) {
  const pair = createPair(t)
  t.exception(
    () =>
      createPeerEndpointController({
        owner: ACTIVE_OWNER,
        session: pair.a.session,
        keyPair: SecretStream.keyPair()
      }),
    { code: 'INVALID_ROUTE' }
  )
  const [left, right] = await openPair(pair)
  const reading = readOne(right)
  left.write(b4a.from('original attachment remains usable'))
  await Writable.drained(left)
  t.alike(await reading, b4a.from('original attachment remains usable'))
  t.is(pair.a.revoked, false)
})

test('endpoint rejects inactive owners and accessor-backed identity before attaching', async function (t) {
  const state = createSession()
  const keyPair = SecretStream.keyPair()
  t.exception(
    () =>
      createPeerEndpointController({
        owner: { diagnostics: () => ({ status: 'CLOSED' }) },
        session: state.session,
        keyPair
      }),
    { code: 'INVALID_ROUTE' }
  )
  let reads = 0
  t.exception(
    () =>
      createPeerEndpointController({
        owner: ACTIVE_OWNER,
        session: state.session,
        keyPair: {
          publicKey: keyPair.publicKey,
          get secretKey() {
            reads++
            return keyPair.secretKey
          }
        }
      }),
    { code: 'INVALID_ROUTE' }
  )
  t.is(reads, 0)
  t.is(state.attached, false)
})

test('endpoint rejects a wrong expected Noise identity', async function (t) {
  const state = createResponder(t)
  const wrong = new NoiseWrap(SecretStream.keyPair(), SecretStream.keyPair().publicKey)
  t.is(state.hooks.onHandshake(wrong.send(PROFILE)), false)
  await t.exception(state.controller.whenOpen())
  await state.controller.finished()
  t.is(state.revoked, true)
  t.is(state.resets.length, 1)
})

test('endpoint rejects non-private Noise payloads before confirming', async function (t) {
  const state = createResponder(t)
  const flight = state.remote.send({ ...PROFILE, firewall: 1 })
  t.is(state.hooks.onHandshake(flight), false)
  await t.exception(state.controller.whenOpen(), AUTHENTICATION)
  await state.controller.finished()
  t.is(state.binding, null)
  t.is(state.handshakes.length, 0)
})

test('endpoint owns handshake scratch but leaves semantic canonical bytes intact', async function (t) {
  const state = createResponder(t, { holdConfirmation: true })
  const flight = state.remote.send(PROFILE)
  const original = b4a.from(flight)
  t.is(state.hooks.onHandshake(flight), true)
  t.alike(flight, original)
  t.alike(state.remote.recv(state.handshakes[0]).secretStream, { version: 1 })
  t.is(state.hooks.onHandshake(flight), false, 'duplicate delivery fails closed')
  await t.exception(state.controller.whenOpen(), AUTHENTICATION)
  state.confirmation.resolve()
  await state.controller.finished()
  t.alike(flight, original, 'canonical bytes survive terminal erasure')
})

test('endpoint rejects ciphertext and FIN before authentication', async function (t) {
  const earlyData = createResponder(t)
  t.is(earlyData.hooks.onCiphertext(b4a.alloc(1)), 0)
  await t.exception(earlyData.controller.whenOpen(), AUTHENTICATION)
  const earlyFin = createResponder(t)
  earlyFin.hooks.onRemoteFin()
  await t.exception(earlyFin.controller.whenOpen(), AUTHENTICATION)
  await Promise.all([earlyData.controller.finished(), earlyFin.controller.finished()])
  t.alike(earlyData.events, ['revoke', 'reset'])
  t.alike(earlyFin.events, ['revoke', 'reset'])
})

test('endpoint authenticates ciphertext and revokes before application error callbacks', async function (t) {
  const pair = createPair(t)
  const [left, right] = await openPair(pair)
  await waitFor(() => pair.a.fragments.length === 1 && pair.b.fragments.length === 1)
  await turn()
  const failure = deferred()
  right.once('error', (error) => {
    t.is(pair.b.revoked, true)
    failure.resolve(error)
  })
  const raw = b4a.alloc(20)
  raw[0] = 17
  pair.b.receive(raw)
  await failure.promise
  await pair.b.controller.finished()
  t.is(pair.b.resets.length, 1)
  t.alike(pair.b.events, ['revoke', 'reset'])
  t.ok(right.destroyed)
  await pair.a.controller.finished()
  t.ok(left.destroyed, 'semantic reset reaches the remote plaintext stream')
  t.alike(pair.a.resets, [], 'remote reset is not echoed')
})

test('endpoint rejects truncated records at remote FIN', async function (t) {
  const pair = createPair(t)
  await openPair(pair)
  await turn()
  t.is(pair.b.hooks.onCiphertext(b4a.from([17, 0])), 2)
  pair.b.hooks.onRemoteFin()
  await pair.b.controller.finished()
  t.is(pair.b.resets[0].code, 'ERR_AUTHENTICATION')
})

test('endpoint destroy gates reentrant callbacks and joins verifier and lease closure', async function (t) {
  const state = createResponder(t, { holdConfirmation: true, holdClose: true })
  const flight = state.remote.send(PROFILE)
  state.hooks.onHandshake(flight)
  const binding = state.binding
  const snapshot = b4a.from(binding.tx)
  let complete = false
  state.controller.finished().then(() => {
    complete = true
  })
  state.onRevoke = () => {
    t.is(state.hooks.onHandshake(flight), false)
    t.is(state.hooks.onCiphertext(b4a.alloc(1)), 0)
    state.hooks.onAuthenticatedOpen()
    state.hooks.onRemoteFin()
    state.hooks.onWritable()
    state.hooks.onReset(new Error('late reset'))
  }
  state.controller.destroy()
  t.is(state.revoked, true)
  await t.exception(state.controller.whenOpen(), DESTROYED)
  await turn()
  t.is(complete, false)
  t.alike(binding.tx, snapshot, 'verifier retains its borrowed keys until it returns')
  state.confirmation.resolve()
  await turn()
  t.is(complete, false, 'semantic closure also participates in the join')
  state.closed.resolve()
  await state.controller.finished()
  t.alike(binding.tx, b4a.alloc(32))
  t.is(state.controller.stream, null)
  t.alike(state.events, ['revoke', 'reset'])
})

test('endpoint joins verification even when confirmHandshake synchronously resets', async function (t) {
  const state = createResponder(t, { holdConfirmation: true })
  state.onConfirm = () => state.hooks.onReset(PrivateRouteError.ERR_AUTHENTICATION())
  state.hooks.onHandshake(state.remote.send(PROFILE))
  const binding = state.binding
  const snapshot = b4a.from(binding.tx)
  let complete = false
  state.controller.finished().then(() => {
    complete = true
  })
  await t.exception(state.controller.whenOpen(), AUTHENTICATION)
  await turn()
  t.is(complete, false, 'synchronous reset must not skip the borrow join')
  t.alike(binding.tx, snapshot)
  state.confirmation.resolve()
  await state.controller.finished()
  t.alike(binding.tx, b4a.alloc(32))
  t.alike(state.resets, [], 'remote reset is not echoed')
})

test('endpoint cancels a blocked plaintext write and ignores late writable notifications', async function (t) {
  const pair = createPair(t)
  const [left] = await openPair(pair)
  const errors = []
  left.on('error', (error) => errors.push(error.code))
  pair.a.budget = 0
  left.write(b4a.alloc(2000, 0x61))
  const writing = Writable.drained(left)
  await turn()
  const before = pair.a.fragments.length
  await pair.a.controller.destroy()
  await writing
  t.alike(errors, ['ERR_DESTROYED'])
  t.ok(left.destroyed)
  pair.a.budget = Infinity
  pair.a.hooks.onWritable()
  pair.a.hooks.onAuthenticatedOpen()
  await turn()
  t.is(pair.a.fragments.length, before)
  t.alike(pair.a.events, ['revoke', 'reset'])
})

test('endpoint rejects non-boolean ciphertext acceptance', async function (t) {
  const pair = createPair(t)
  const [left] = await openPair(pair)
  pair.a.onSend = () => 1
  left.write(b4a.from('not accepted'))
  await Writable.drained(left)
  await pair.a.controller.finished()
  t.is(pair.a.resets[0].code, 'INVALID_ROUTE')
  t.ok(left.destroyed)
})

test('endpoint handles reentrant writable notifications without duplicating fragments', async function (t) {
  const pair = createPair(t)
  const [left, right] = await openPair(pair)
  pair.a.onSend = () => {
    pair.a.writable()
  }
  const reading = readOne(right)
  const payload = b4a.alloc(2000, 0x62)
  left.write(payload)
  t.is(await Writable.drained(left), true)
  t.alike(await reading, payload)
  t.alike(
    pair.a.fragments.slice(1).map((bytes) => bytes.byteLength),
    [977, 977, 66]
  )
})

test('endpoint joins synchronous and asynchronous semantic verification failures', async function (t) {
  const sync = createResponder(t)
  const failure = PrivateRouteError.ERR_AUTHENTICATION()
  sync.onConfirm = () => {
    throw failure
  }
  t.is(sync.hooks.onHandshake(sync.remote.send(PROFILE)), false)
  await t.exception(sync.controller.whenOpen(), AUTHENTICATION)
  await sync.controller.finished()
  t.alike(sync.resets, [failure])
  t.is(sync.controller.stream, null)

  const async = createResponder(t, { holdConfirmation: true })
  async.hooks.onHandshake(async.remote.send(PROFILE))
  async.confirmation.reject(failure)
  await t.exception(async.controller.whenOpen(), AUTHENTICATION)
  await async.controller.finished()
  t.alike(async.resets, [failure])
  t.is(async.controller.stream, null)
})

test('endpoint fails closed when the semantic lease cannot drain after native open', async function (t) {
  const failure = PrivateRouteError.ERR_DESTROYED()
  const state = createResponder(t, { drainError: failure })
  state.hooks.onHandshake(state.remote.send(PROFILE))
  await state.controller.finished()
  t.alike(state.events, ['revoke', 'reset'])
  t.alike(state.resets, [failure])
  t.ok(state.controller.stream.destroyed)
})
