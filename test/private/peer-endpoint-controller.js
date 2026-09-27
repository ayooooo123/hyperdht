'use strict'

const test = require('brittle')
const b4a = require('b4a')
const { Writable } = require('streamx')
const SecretStream = require('@hyperswarm/secret-stream')
const NoiseWrap = require('../../lib/noise-wrap')
const { PrivateRouteError } = require('../../lib/private/errors')
const {
  createPeerEndpointController,
  createPeerConnectingStream
} = require('../../lib/private/peer-endpoint-controller')

const PROFILE = { error: 0, firewall: 0, secretStream: { version: 1 } }
const ACTIVE_OWNER = { diagnostics: () => ({ status: 'ACTIVE' }), route: () => ({ purpose: 2 }) }
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
    const maxFrames = options.maxFrames === undefined ? 1000000 : options.maxFrames
    state.hooks.onAuthenticatedOpen({
      maxFrames,
      maxBytes: options.maxBytes === undefined ? BigInt(maxFrames) * 977n : options.maxBytes
    })
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

function createPair(t, optionsA = {}, optionsB = {}) {
  const a = createSession(optionsA)
  const b = createSession(optionsB)
  a.peer = b
  b.peer = a
  const keyA = SecretStream.keyPair()
  const keyB = SecretStream.keyPair()
  const originalA = { publicKey: b4a.from(keyA.publicKey), secretKey: b4a.from(keyA.secretKey) }
  const originalB = { publicKey: b4a.from(keyB.publicKey), secretKey: b4a.from(keyB.secretKey) }
  b.controller = createPeerEndpointController({
    owner: { ...ACTIVE_OWNER, route: () => ({ purpose: optionsB.purpose || 3 }) },
    session: b.session,
    keyPair: keyB
  })
  a.controller = createPeerEndpointController({
    owner: { ...ACTIVE_OWNER, route: () => ({ purpose: optionsA.purpose || 2 }) },
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
        owner: { ...ACTIVE_OWNER, diagnostics: () => ({ status: 'CLOSED' }) },
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

test('endpoint rejects invalid ciphertext framing and revokes before application error callbacks', async function (t) {
  const pair = createPair(t)
  const [left, right] = await openPair(pair)
  await waitFor(() => pair.a.fragments.length === 1 && pair.b.fragments.length === 1)
  await turn()
  const failure = deferred()
  right.once('error', (error) => {
    t.is(pair.b.revoked, true)
    failure.resolve(error)
  })
  const raw = b4a.alloc(3)
  raw[0] = 16
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
  const consuming = t.exception(readOne(right))
  const raw = b4a.alloc(20)
  raw[0] = 17
  pair.b.receive(raw)
  await Promise.all([failure.promise, consuming])
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
  left.write(b4a.alloc(65536 * 3 + 1, 0x61))
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

test('endpoint validates admitted own-data purpose before identity or session work', function (t) {
  const state = createSession()
  let reads = 0
  const keyPair = {
    get publicKey() {
      reads++
      throw new Error('Identity must not be read')
    }
  }
  const routes = [undefined, null, 0, 4, -1, 2.5, '2', true, NaN].map((purpose) => ({
    purpose
  }))
  routes.push({})
  routes.push(Object.create({ purpose: 2 }))
  routes.push({
    get purpose() {
      reads++
      return 2
    }
  })
  for (const route of routes) {
    t.exception(
      () =>
        createPeerEndpointController({
          owner: { ...ACTIVE_OWNER, route: () => route },
          session: state.session,
          keyPair
        }),
      { code: 'INVALID_ROUTE' }
    )
  }
  const owners = [
    { diagnostics: ACTIVE_OWNER.diagnostics },
    Object.assign(Object.create({ route: ACTIVE_OWNER.route }), {
      diagnostics: ACTIVE_OWNER.diagnostics
    }),
    {
      diagnostics: ACTIVE_OWNER.diagnostics,
      get route() {
        reads++
        return ACTIVE_OWNER.route
      }
    }
  ]
  for (const owner of owners) {
    t.exception(() => createPeerEndpointController({ owner, session: state.session, keyPair }), {
      code: 'INVALID_ROUTE'
    })
  }
  t.is(reads, 0)
  t.is(state.attached, false)
  t.alike(state.handshakes, [])
  t.alike(state.fragments, [])
})

test('endpoint fragments large private writes with credit backpressure and half-close continuation', async function (t) {
  const pair = createPair(t)
  const [left, right] = await openPair(pair)
  const payload = b4a.alloc(65536 * 3 + 1)
  for (let i = 0; i < payload.byteLength; i++) payload[i] = (i + Math.floor(i / 65536)) & 255
  const firstRecord = readOne(right)
  const before = pair.a.fragments.length
  pair.a.budget = 1
  left.write(payload)
  let drained = false
  const writing = Writable.drained(left).then((ok) => {
    drained = true
    return ok
  })
  await waitFor(() => pair.a.fragments.length === before + 1)
  await turn()
  t.is(drained, false)
  pair.a.budget = Infinity
  pair.a.writable()
  const retained = await firstRecord
  t.alike(retained, payload.subarray(0, 65536))
  t.is(retained.buffer.byteLength, 65556)
  t.is(retained.byteOffset, 4)
  for (let offset = 65536; offset < payload.byteLength; offset += 65536) {
    const plain = await readOne(right)
    const end = Math.min(payload.byteLength, offset + 65536)
    t.alike(plain, payload.subarray(offset, end))
    t.is(plain.buffer.byteLength, end - offset + 20)
    t.not(plain.buffer, retained.buffer)
  }
  t.is(await writing, true)
  const ciphertext = b4a.concat(pair.a.fragments.slice(before))
  const lengths = []
  let offset = 0
  while (offset < ciphertext.byteLength) {
    const body = ciphertext[offset] + ciphertext[offset + 1] * 256 + ciphertext[offset + 2] * 65536
    lengths.push(body)
    offset += body + 3
  }
  t.alike(lengths, [65553, 65553, 65553, 18])
  t.is(offset, ciphertext.byteLength)
  const eof = readOne(right)
  left.end()
  t.is(await eof, null)
  const reply = b4a.alloc(65537, 0x39)
  const firstReply = readOne(left)
  right.write(reply)
  t.alike(await firstReply, reply.subarray(0, 65536))
  t.alike(await readOne(left), reply.subarray(65536))
  t.is(await Writable.drained(right), true)
  const reverseEof = readOne(left)
  right.end()
  t.is(await reverseEof, null)
  await Promise.all([pair.a.controller.finished(), pair.b.controller.finished()])
  t.alike(pair.a.resets, [])
  t.alike(pair.b.resets, [])
  t.alike(retained, payload.subarray(0, 65536), 'public backing survives graceful cleanup')
  t.ok(left.destroyed && right.destroyed)
})

test('endpoint rejects above-cap private body prefix without waiting for ciphertext', async function (t) {
  const pair = createPair(t)
  const [, right] = await openPair(pair)
  await waitFor(() => pair.b.controller._adapter._inboundRecordCount === 1)
  const adapter = pair.b.controller._adapter
  t.is(pair.b.controller._inboundHeld, false)
  const failure = deferred()
  right.once('error', (error) => failure.resolve(error))
  pair.b.receive(b4a.from([0x12, 0x00, 0x01]))
  t.is((await failure.promise).code, AUTHENTICATION.code)
  await pair.b.controller.finished()
  t.is(adapter._inboundRecordCount, 1, 'oversized body never reaches SecretStream')
  t.is(adapter._inbound, null)
  t.alike(pair.b.events, ['revoke', 'reset'])
  t.ok(right.destroyed)
})

test('legacy endpoint purpose preserves records larger than 64 KiB', async function (t) {
  const pair = createPair(t, { purpose: 1 }, { purpose: 1 })
  const [left, right] = await openPair(pair)
  const payload = b4a.alloc(65537, 0x53)
  const reading = readOne(right)
  left.write(payload)
  const plain = await reading
  t.is(await Writable.drained(left), true)
  t.alike(plain, payload)
  t.is(plain.buffer.byteLength, 65557, 'legacy plaintext stays in one atomic record')
  await Promise.all([pair.a.controller.destroy(), pair.b.controller.destroy()])
  t.alike(plain, payload)
})

test('endpoint rejects a whole write before exceeding its admitted raw-byte quota', async (t) => {
  const pair = createPair(t, { maxFrames: 10, maxBytes: 90n })
  const [left, right] = await openPair(pair)
  const failed = deferred()
  const remoteFailed = deferred()
  left.once('error', failed.resolve)
  right.once('error', remoteFailed.resolve)
  const before = pair.a.fragments.length
  left.write(b4a.alloc(12, 1))
  t.is((await failed.promise).code, 'ERR_QUOTA_EXCEEDED')
  t.is((await remoteFailed.promise).code, 'ERR_QUOTA_EXCEEDED')
  await Promise.all([pair.a.controller.finished(), pair.b.controller.finished()])
  t.is(pair.a.fragments.length, before, 'no prefix or partial record crosses the byte boundary')
  t.is(await Writable.drained(left), false)
})

test('endpoint preflights all fragments of a write rather than truncating its final record', async (t) => {
  const pair = createPair(t, { maxFrames: 69 })
  const [left] = await openPair(pair)
  const failed = deferred()
  left.once('error', failed.resolve)
  const before = pair.a.fragments.length
  left.write(b4a.alloc(65537, 2))
  t.is((await failed.promise).code, 'ERR_QUOTA_EXCEEDED')
  await pair.a.controller.finished()
  t.is(
    pair.a.fragments.length,
    before,
    'a write requiring seventy DATA frames emits neither record'
  )
})

test('exact DATA-frame exhaustion still permits FIN and reverse continuation', async (t) => {
  const pair = createPair(t, { maxFrames: 2 })
  const [left, right] = await openPair(pair)
  const reading = readOne(right)
  left.write(b4a.alloc(957, 3))
  const received = await reading
  t.alike(received, b4a.alloc(957, 3))
  t.is(await Writable.drained(left), true)
  const eof = readOne(right)
  left.end()
  t.is(await eof, null)
  const reply = readOne(left)
  right.write(b4a.from('reply after the final DATA frame'))
  t.alike(await reply, b4a.from('reply after the final DATA frame'))
  const reverseEof = readOne(left)
  right.end()
  t.is(await reverseEof, null)
  await Promise.all([pair.a.controller.finished(), pair.b.controller.finished()])
  t.alike(pair.a.resets, [])
  t.alike(pair.b.resets, [])
  t.alike(received, b4a.alloc(957, 3))
})

test('connecting facade retains early writes through real Noise and guarded binding', async (t) => {
  const a = createSession()
  const b = createSession()
  a.peer = b
  b.peer = a
  const keyA = SecretStream.keyPair()
  const keyB = SecretStream.keyPair()
  const server = createPeerEndpointController({
    owner: ACTIVE_OWNER,
    session: b.session,
    keyPair: keyB
  })
  const starting = deferred()
  let client = null
  const stream = createPeerConnectingStream(
    async (connecting) => {
      await starting.promise
      client = createPeerEndpointController({
        owner: ACTIVE_OWNER,
        session: a.session,
        keyPair: keyA,
        remotePublicKey: keyB.publicKey,
        stream: connecting
      })
      await client.whenOpen()
    },
    (error) => starting.reject(error || PrivateRouteError.ERR_DESTROYED())
  )
  t.teardown(async () => {
    starting.reject(PrivateRouteError.ERR_DESTROYED())
    stream.destroy()
    await Promise.all([server.destroy(), client ? client.destroy() : Promise.resolve()])
  })
  const bytes = b4a.alloc(65537, 4)
  stream.write(bytes)
  starting.resolve()
  const incoming = await server.whenOpen()
  t.is(await stream.opened, true)
  t.alike(stream.publicKey, keyA.publicKey)
  t.alike(stream.remotePublicKey, keyB.publicKey)
  t.alike(incoming.remotePublicKey, keyA.publicKey)
  t.alike(await readOne(incoming), bytes.subarray(0, 65536))
  t.alike(await readOne(incoming), bytes.subarray(65536))
  t.is(await Writable.drained(stream), true)
  const eof = readOne(incoming)
  stream.end()
  t.is(await eof, null)
  const reverseEof = readOne(stream)
  incoming.end()
  t.is(await reverseEof, null)
  await Promise.all([client.finished(), server.finished()])
})

test('connecting cancellation joins its pending setup without binding a late endpoint', async (t) => {
  const starting = deferred()
  let entered = false
  let canceled = null
  const stream = createPeerConnectingStream(
    async () => {
      entered = true
      await starting.promise
    },
    (error) => {
      canceled = error
      starting.reject(error)
    }
  )
  const closed = new Promise((resolve) => stream.once('close', resolve))
  stream.write(b4a.alloc(65537, 5))
  await waitFor(() => entered)
  stream.destroy()
  await closed
  t.is(canceled.code, 'ERR_DESTROYED')
  t.is(await stream.opened, false)
  t.is(await Writable.drained(stream), false)
  t.is(stream.destroyed, true)
})

test('connecting facade authenticates before any application reads or writes', async (t) => {
  t.timeout(5000)
  const a = createSession()
  const b = createSession()
  a.peer = b
  b.peer = a
  const local = SecretStream.keyPair()
  const remote = SecretStream.keyPair()
  const server = createPeerEndpointController({
    owner: ACTIVE_OWNER,
    session: b.session,
    keyPair: remote
  })
  let client = null
  const stream = createPeerConnectingStream(
    async (connecting) => {
      client = createPeerEndpointController({
        owner: ACTIVE_OWNER,
        session: a.session,
        keyPair: local,
        remotePublicKey: remote.publicKey,
        stream: connecting
      })
      await client.whenOpen()
    },
    (error) => {
      if (client) client.destroy(error)
    }
  )
  t.teardown(async () => {
    stream.destroy()
    await Promise.all([server.destroy(), client ? client.destroy() : Promise.resolve()])
  })
  t.is(await stream.opened, true)
  const incoming = await server.whenOpen()
  t.alike(stream.remotePublicKey, remote.publicKey)
  t.alike(incoming.remotePublicKey, local.publicKey)
  const reading = readOne(incoming)
  stream.write(b4a.from('first write after readiness'))
  t.alike(await reading, b4a.from('first write after readiness'))
  t.is(await Writable.drained(stream), true)
})
