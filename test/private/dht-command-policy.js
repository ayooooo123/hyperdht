const test = require('brittle')
const b4a = require('b4a')

const { COMMANDS } = require('../../lib/constants')
const { IMMUTABLE_GET_POLICIES, encodeDHTRequest } = require('../../lib/private/dht-command-policy')
const { createQueryContexts } = require('../../lib/private/query-context')
const { BRANCH_CLASS, M3_MESSAGE_ID } = require('../../lib/private/protocol')

function expectUnsupported(t, operation) {
  let error = null
  try {
    operation()
  } catch (err) {
    error = err
  }

  t.is(error && error.name, 'PrivateCommandUnsupportedError')
  t.is(error && error.code, 'ERR_PRIVATE_COMMAND_UNSUPPORTED')
  t.is(error && error.message, 'Private DHT command is unsupported')
  t.ok(Object.isFrozen(error))
}

function request(target = b4a.alloc(32, 7)) {
  return { command: COMMANDS.IMMUTABLE_GET, target, value: null }
}

test('query capabilities bind exact immutable-get policies', (t) => {
  const contexts = createQueryContexts()
  const { lookup, announce } = contexts.immutableGet
  const lookupPolicy = contexts.classify(lookup)
  const announcePolicy = contexts.classify(announce)

  t.is(lookupPolicy, IMMUTABLE_GET_POLICIES.lookup)
  t.is(announcePolicy, IMMUTABLE_GET_POLICIES.announce)
  t.alike(Object.keys(lookupPolicy), ['branch', 'command', 'commandId', 'encode'])
  t.is(lookupPolicy.branch, BRANCH_CLASS.LOOKUP)
  t.is(announcePolicy.branch, BRANCH_CLASS.ANNOUNCE)
  t.is(lookupPolicy.command, COMMANDS.IMMUTABLE_GET)
  t.is(announcePolicy.command, COMMANDS.IMMUTABLE_GET)
  t.is(lookupPolicy.commandId, M3_MESSAGE_ID.IMMUTABLE_GET_V1)
  t.is(announcePolicy.commandId, M3_MESSAGE_ID.IMMUTABLE_GET_V1)
  t.is(lookupPolicy.encode, encodeDHTRequest)
  t.is(announcePolicy.encode, encodeDHTRequest)

  t.alike(Object.keys(contexts), ['immutableGet', 'classify'])
  t.alike(Object.keys(contexts.immutableGet), ['lookup', 'announce'])
  t.alike(Object.keys(lookup), [])
  t.alike(Object.keys(announce), [])
  t.ok(Object.isFrozen(contexts))
  t.ok(Object.isFrozen(contexts.immutableGet))
  t.ok(Object.isFrozen(contexts.classify))
  t.ok(Object.isFrozen(lookup))
  t.ok(Object.isFrozen(announce))
  t.ok(Object.isFrozen(IMMUTABLE_GET_POLICIES))
  t.ok(Object.isFrozen(lookupPolicy))
  t.ok(Object.isFrozen(announcePolicy))
  t.ok(Object.isFrozen(lookupPolicy.encode))
})

test('query capabilities are per-instance and cannot be forged', (t) => {
  const first = createQueryContexts()
  const second = createQueryContexts()
  const capability = first.immutableGet.lookup
  const rejected = [
    null,
    undefined,
    true,
    0,
    'lookup',
    Symbol('lookup'),
    {},
    Object.freeze({}),
    { ...capability },
    second.immutableGet.lookup,
    new Proxy(capability, {})
  ]

  for (const value of rejected) {
    expectUnsupported(t, () => first.classify(value))
  }

  let traps = 0
  const hostile = new Proxy(capability, {
    get() {
      traps++
      throw new Error('proxy get trap ran')
    },
    getPrototypeOf() {
      traps++
      throw new Error('proxy prototype trap ran')
    }
  })
  expectUnsupported(t, () => first.classify(hostile))
  t.is(traps, 0)

  const revocable = Proxy.revocable(capability, {})
  revocable.revoke()
  expectUnsupported(t, () => first.classify(revocable.proxy))
})

test('immutable get encodes one defensive exact target snapshot', (t) => {
  const contexts = createQueryContexts()
  const policies = [
    contexts.classify(contexts.immutableGet.lookup),
    contexts.classify(contexts.immutableGet.announce)
  ]

  for (const policy of policies) {
    const target = b4a.alloc(32, policy.branch + 3)
    const snapshot = b4a.from(target)
    const encoded = policy.encode(policy, request(target))

    t.ok(b4a.isBuffer(encoded))
    t.is(encoded.byteLength, 32)
    t.alike(encoded, snapshot)
    t.not(encoded, target)
    target.fill(0)
    t.alike(encoded, snapshot)
    encoded.fill(1)
    t.alike(target, b4a.alloc(32))
  }
})

test('immutable get accepts only the exact HyperDHT request shape', (t) => {
  const policy = IMMUTABLE_GET_POLICIES.lookup
  const target = b4a.alloc(32)

  t.alike(encodeDHTRequest(policy, request(target)), target)
  t.alike(
    encodeDHTRequest(policy, {
      command: COMMANDS.IMMUTABLE_GET,
      target,
      token: null,
      value: null
    }),
    target
  )

  const invalid = [
    {},
    { command: COMMANDS.IMMUTABLE_GET, value: null },
    { command: COMMANDS.IMMUTABLE_GET, target: null, value: null },
    { command: COMMANDS.IMMUTABLE_GET, target: b4a.alloc(31), value: null },
    { command: COMMANDS.IMMUTABLE_GET, target: b4a.alloc(33), value: null },
    { command: COMMANDS.IMMUTABLE_GET, target, token: b4a.alloc(0), value: null },
    { command: COMMANDS.IMMUTABLE_GET, target, token: undefined, value: null },
    { command: COMMANDS.IMMUTABLE_GET, target, value: undefined },
    { command: COMMANDS.IMMUTABLE_GET, target, value: b4a.alloc(0) }
  ]

  for (const message of invalid) {
    expectUnsupported(t, () => encodeDHTRequest(policy, message))
  }

  for (const name of ['command', 'target', 'token', 'value']) {
    const hostile = { command: COMMANDS.IMMUTABLE_GET, target, value: null }
    Object.defineProperty(hostile, name, {
      configurable: true,
      get() {
        throw new Error(`accessor ${name} ran`)
      }
    })
    expectUnsupported(t, () => encodeDHTRequest(policy, hostile))
  }

  for (const name of ['command', 'target', 'token', 'value']) {
    const inherited = Object.create({ [name]: name === 'value' ? null : target })
    if (name !== 'command') inherited.command = COMMANDS.IMMUTABLE_GET
    if (name !== 'target') inherited.target = target
    if (name !== 'value') inherited.value = null
    expectUnsupported(t, () => encodeDHTRequest(policy, inherited))
  }

  expectUnsupported(t, () =>
    encodeDHTRequest(
      policy,
      new Proxy(request(target), {
        getOwnPropertyDescriptor() {
          throw new Error('hostile descriptor trap ran')
        }
      })
    )
  )
})

test('immutable get snapshots each semantic own-data field once', (t) => {
  const policy = IMMUTABLE_GET_POLICIES.lookup
  const fields = { command: 0, target: 0, token: 0, value: 0 }
  const message = new Proxy(
    {
      command: COMMANDS.IMMUTABLE_GET,
      target: b4a.alloc(32, 6),
      token: null,
      value: null
    },
    {
      getOwnPropertyDescriptor(target, name) {
        if (Object.prototype.hasOwnProperty.call(fields, name)) fields[name]++
        return Object.getOwnPropertyDescriptor(target, name)
      }
    }
  )

  t.alike(encodeDHTRequest(policy, message), b4a.alloc(32, 6))
  t.alike(fields, { command: 1, target: 1, token: 1, value: 1 })
})

test('immutable get snapshots scalar fields before copying the target', (t) => {
  const policy = IMMUTABLE_GET_POLICIES.lookup
  const target = b4a.alloc(32, 4)
  const order = []
  const message = new Proxy(
    {
      command: COMMANDS.IMMUTABLE_GET,
      target,
      token: null,
      value: null
    },
    {
      getOwnPropertyDescriptor(object, name) {
        order.push(name)
        if (name === 'value') target.fill(9)
        if (name === 'target') target.fill(1)
        return Object.getOwnPropertyDescriptor(object, name)
      }
    }
  )

  const encoded = encodeDHTRequest(policy, message)
  t.alike(order, ['command', 'token', 'value', 'target'])
  t.alike(encoded, b4a.alloc(32, 1))

  let targetReads = 0
  expectUnsupported(t, () =>
    encodeDHTRequest(
      policy,
      new Proxy(
        {
          command: COMMANDS.IMMUTABLE_GET,
          target,
          token: null,
          value: null
        },
        {
          getOwnPropertyDescriptor(object, name) {
            if (name === 'target') targetReads++
            if (name === 'value') throw new Error('late scalar snapshot failed')
            return Object.getOwnPropertyDescriptor(object, name)
          }
        }
      )
    )
  )
  t.is(targetReads, 0)
})

test('immutable get uses intrinsic Uint8Array branding', (t) => {
  const policy = IMMUTABLE_GET_POLICIES.lookup
  const valid = [b4a.alloc(32, 2), new Uint8Array(32)]
  if (typeof SharedArrayBuffer === 'function') {
    valid.push(new Uint8Array(new SharedArrayBuffer(32)))
  }

  for (const target of valid) {
    t.alike(Array.from(encodeDHTRequest(policy, request(target))), Array.from(target))
  }

  const forged = new Uint16Array(16)
  Object.setPrototypeOf(forged, Uint8Array.prototype)
  const invalid = [
    new Uint16Array(16),
    new Int8Array(32),
    new Uint8ClampedArray(32),
    new DataView(new ArrayBuffer(32)),
    new ArrayBuffer(32),
    new Proxy(new Uint8Array(32), {}),
    Object.create(Uint8Array.prototype),
    forged
  ]

  for (const target of invalid) {
    expectUnsupported(t, () => encodeDHTRequest(policy, request(target)))
  }
})

test('immutable get branding ignores poisoned constructors and prototypes', (t) => {
  const policy = IMMUTABLE_GET_POLICIES.announce
  const target = b4a.alloc(32, 3)
  const invalid = new Uint16Array(16)
  const BufferConstructor = b4a.alloc(0).constructor
  const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype)
  const saved = [
    [globalThis, 'Uint8Array', Object.getOwnPropertyDescriptor(globalThis, 'Uint8Array')],
    [
      Uint8Array,
      Symbol.hasInstance,
      Object.getOwnPropertyDescriptor(Uint8Array, Symbol.hasInstance)
    ],
    [
      Uint8Array.prototype,
      'constructor',
      Object.getOwnPropertyDescriptor(Uint8Array.prototype, 'constructor')
    ],
    [Uint8Array, Symbol.species, Object.getOwnPropertyDescriptor(Uint8Array, Symbol.species)],
    [
      typedArrayPrototype,
      Symbol.toStringTag,
      Object.getOwnPropertyDescriptor(typedArrayPrototype, Symbol.toStringTag)
    ],
    [BufferConstructor, 'isBuffer', Object.getOwnPropertyDescriptor(BufferConstructor, 'isBuffer')]
  ]
  let encoded = null
  let invalidError = null

  try {
    Object.defineProperty(Uint8Array, Symbol.hasInstance, {
      configurable: true,
      value: () => true
    })
    Object.defineProperty(Uint8Array.prototype, 'constructor', {
      configurable: true,
      value: Uint16Array
    })
    Object.defineProperty(Uint8Array, Symbol.species, {
      configurable: true,
      value: Uint16Array
    })
    Object.defineProperty(typedArrayPrototype, Symbol.toStringTag, {
      configurable: true,
      get() {
        throw new Error('mutable typed-array tag getter ran')
      }
    })
    Object.defineProperty(BufferConstructor, 'isBuffer', {
      configurable: true,
      value: () => true
    })
    Object.defineProperty(globalThis, 'Uint8Array', {
      configurable: true,
      writable: true,
      value: function PoisonedUint8Array() {
        throw new Error('mutable Uint8Array constructor ran')
      }
    })

    encoded = encodeDHTRequest(policy, {
      command: 9,
      target,
      value: null
    })
    try {
      encodeDHTRequest(policy, {
        command: 9,
        target: invalid,
        value: null
      })
    } catch (err) {
      invalidError = err
    }
  } finally {
    for (let index = saved.length - 1; index >= 0; index--) {
      const [object, name, descriptor] = saved[index]
      if (descriptor === undefined) delete object[name]
      else Object.defineProperty(object, name, descriptor)
    }
  }

  t.ok(b4a.isBuffer(encoded))
  t.alike(encoded, b4a.alloc(32, 3))
  t.is(invalidError && invalidError.code, 'ERR_PRIVATE_COMMAND_UNSUPPORTED')
})

test('unsupported commands and descriptors fail before authority IO', (t) => {
  const contexts = createQueryContexts()
  const policy = contexts.classify(contexts.immutableGet.lookup)
  let closestCalls = 0
  let bootstrapCalls = 0
  let requestCalls = 0

  function route(context, message) {
    const selected = contexts.classify(context)
    const body = selected.encode(selected, message)
    closestCalls++
    bootstrapCalls++
    requestCalls++
    return body
  }

  const unsupported = [
    ...Object.values(COMMANDS).filter((command) => command !== COMMANDS.IMMUTABLE_GET),
    ...Object.values(M3_MESSAGE_ID).filter((command) => command !== COMMANDS.IMMUTABLE_GET),
    -1,
    11,
    0x7fffffff,
    1.5,
    NaN,
    Infinity,
    9n,
    '9',
    Symbol('command')
  ]

  for (const command of unsupported) {
    expectUnsupported(t, () => route(contexts.immutableGet.lookup, requestWith(command)))
    t.is(closestCalls, 0)
    t.is(bootstrapCalls, 0)
    t.is(requestCalls, 0)
  }

  const forged = [
    { ...policy },
    Object.freeze({ ...policy }),
    { branch: policy.branch, command: policy.command, commandId: policy.commandId },
    null,
    9
  ]
  for (const descriptor of forged) {
    expectUnsupported(t, () => encodeDHTRequest(descriptor, request()))
    t.is(closestCalls, 0)
    t.is(bootstrapCalls, 0)
    t.is(requestCalls, 0)
  }

  expectUnsupported(t, () => route({}, request()))
  t.is(closestCalls, 0)
  t.is(bootstrapCalls, 0)
  t.is(requestCalls, 0)

  function requestWith(command) {
    return { command, target: b4a.alloc(32), value: null }
  }
})

test('input snapshot and output allocation ignore later caller and intrinsic mutation', (t) => {
  const policy = IMMUTABLE_GET_POLICIES.announce
  const backing = new SharedArrayBuffer(64)
  const target = new Uint8Array(backing, 16, 32)
  target.fill(5)
  const message = request(target)
  const encoded = encodeDHTRequest(policy, message)
  target.fill(9)
  t.alike(encoded, b4a.alloc(32, 5))

  const saved = [
    [b4a, 'alloc', b4a.alloc],
    [b4a, 'isBuffer', b4a.isBuffer],
    [Uint8Array.prototype, 'set', Uint8Array.prototype.set],
    [Object, 'getOwnPropertyDescriptor', Object.getOwnPropertyDescriptor],
    [COMMANDS, 'IMMUTABLE_GET', COMMANDS.IMMUTABLE_GET]
  ]
  const secondInput = b4a.from(encoded)
  let hardened = null
  try {
    b4a.alloc = () => {
      throw new Error('mutable b4a allocator ran')
    }
    b4a.isBuffer = () => {
      throw new Error('mutable b4a predicate ran')
    }
    Uint8Array.prototype.set = function () {
      throw new Error('mutable set ran')
    }
    Object.getOwnPropertyDescriptor = () => {
      throw new Error('mutable descriptor intrinsic ran')
    }
    COMMANDS.IMMUTABLE_GET = -1
    hardened = encodeDHTRequest(policy, {
      command: 9,
      target: secondInput,
      value: null
    })
  } finally {
    for (const [object, name, value] of saved) object[name] = value
  }
  t.alike(Array.from(hardened), Array(32).fill(5))
})

test('query context operations capture mutable WeakMap and freeze intrinsics', (t) => {
  const saved = [
    [WeakMap.prototype, 'get', WeakMap.prototype.get],
    [WeakMap.prototype, 'set', WeakMap.prototype.set],
    [Object, 'freeze', Object.freeze]
  ]
  let contexts = null
  let policy = null
  try {
    WeakMap.prototype.get = function () {
      throw new Error('mutable WeakMap.get ran')
    }
    WeakMap.prototype.set = function () {
      throw new Error('mutable WeakMap.set ran')
    }
    Object.freeze = () => {
      throw new Error('mutable Object.freeze ran')
    }
    contexts = createQueryContexts()
    policy = contexts.classify(contexts.immutableGet.lookup)
  } finally {
    for (const [object, name, value] of saved) object[name] = value
  }

  t.is(policy, IMMUTABLE_GET_POLICIES.lookup)
  t.ok(Object.isFrozen(contexts))
  t.ok(Object.isFrozen(contexts.immutableGet.lookup))
})
