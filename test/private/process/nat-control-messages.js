'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { validateControlMessage } = require('./control-channel')

function throwsCode(t, fn, code = 'PROCESS_PROTOCOL_INVALID') {
  let error = null
  try {
    fn()
  } catch (err) {
    error = err
  }
  t.ok(error)
  t.is(error && error.code, code)
}

function base(type, role = 'endpoint', roleIndex = 1) {
  return { generation: 7n, phaseSequence: 11n, role, roleIndex, type }
}

function messageContext(direction, message, overrides = {}) {
  return {
    direction,
    generation: message.generation,
    phaseSequence: message.phaseSequence,
    projection: 'production',
    role: message.role,
    roleIndex: message.roleIndex,
    ...overrides
  }
}

const OFFER = b4a.alloc(334, 7)
const COUNTER = b4a.alloc(398, 8)
const PLAN = b4a.alloc(462, 9)

test('nat commands accept endpoint and guard shapes only', (t) => {
  for (const type of ['nat-reflect', 'nat-offer', 'nat-start']) {
    for (const [role, roleIndex] of [
      ['endpoint', 1],
      ['guard', 2]
    ]) {
      const message = base(type, role, roleIndex)
      t.alike(validateControlMessage(message, messageContext('command', message)), message)
    }
    const middle = base(type, 'lookup-middle-a', 3)
    throwsCode(t, () => validateControlMessage(middle, messageContext('command', middle)))
  }

  const counter = { ...base('nat-counter', 'guard', 2), offer: b4a.from(OFFER) }
  t.alike(validateControlMessage(counter, messageContext('command', counter)), counter)
  throwsCode(t, () =>
    validateControlMessage(
      { ...counter, role: 'lookup-exit-a', roleIndex: 4 },
      messageContext('command', { ...counter, role: 'lookup-exit-a', roleIndex: 4 })
    )
  )
  throwsCode(t, () =>
    validateControlMessage({ ...counter, offer: b4a.alloc(0) }, messageContext('command', counter))
  )
  throwsCode(t, () =>
    validateControlMessage(
      { ...counter, offer: b4a.alloc(487, 1) },
      messageContext('command', counter)
    )
  )

  const planCmd = { ...base('nat-plan', 'endpoint', 1), counter: b4a.from(COUNTER) }
  t.alike(validateControlMessage(planCmd, messageContext('command', planCmd)), planCmd)
  throwsCode(t, () =>
    validateControlMessage(
      { ...planCmd, counter: undefined },
      messageContext('command', { ...planCmd, counter: undefined })
    )
  )

  const arm = { ...base('nat-arm', 'guard', 2), plan: b4a.from(PLAN) }
  t.alike(validateControlMessage(arm, messageContext('command', arm)), arm)
  throwsCode(t, () =>
    validateControlMessage({ ...arm, extra: true }, messageContext('command', arm))
  )
})

test('nat events accept exact fields and reject wrong role generation and missing bytes', (t) => {
  const reflected = {
    ...base('nat-reflected', 'endpoint', 1),
    expiresAt: 15_000n,
    observed: '203.0.113.10:42001'
  }
  t.alike(validateControlMessage(reflected, messageContext('event', reflected)), reflected)
  throwsCode(t, () =>
    validateControlMessage(
      { ...reflected, role: 'dht-seed', roleIndex: 9 },
      messageContext('event', { ...reflected, role: 'dht-seed', roleIndex: 9 })
    )
  )
  throwsCode(t, () =>
    validateControlMessage({ ...reflected, port: 0 }, messageContext('event', reflected))
  )
  throwsCode(t, () =>
    validateControlMessage({ ...reflected, expiresAt: 0n }, messageContext('event', reflected))
  )
  throwsCode(t, () =>
    validateControlMessage(
      { ...reflected, generation: 8n },
      messageContext('event', reflected, { generation: 7n })
    )
  )

  const offer = { ...base('nat-offer', 'endpoint', 1), offer: b4a.from(OFFER) }
  t.alike(validateControlMessage(offer, messageContext('event', offer)), offer)
  throwsCode(t, () =>
    validateControlMessage({ ...offer, offer: b4a.alloc(0) }, messageContext('event', offer))
  )

  const counter = { ...base('nat-counter', 'guard', 2), counter: b4a.from(COUNTER) }
  t.alike(validateControlMessage(counter, messageContext('event', counter)), counter)

  const plan = { ...base('nat-plan', 'endpoint', 1), plan: b4a.from(PLAN) }
  t.alike(validateControlMessage(plan, messageContext('event', plan)), plan)

  const armed = base('nat-armed', 'guard', 2)
  t.alike(validateControlMessage(armed, messageContext('event', armed)), armed)
  throwsCode(t, () =>
    validateControlMessage(
      { ...armed, role: 'announce-middle', roleIndex: 7 },
      messageContext('event', { ...armed, role: 'announce-middle', roleIndex: 7 })
    )
  )

  const started = {
    ...base('nat-started', 'endpoint', 1),
    firstOwnedSend: true,
    received: 1,
    refused: 0,
    sent: 3,
    strayReceived: 0
  }
  t.alike(validateControlMessage(started, messageContext('event', started)), started)
  throwsCode(t, () =>
    validateControlMessage(
      { ...started, firstOwnedSend: 1 },
      messageContext('event', { ...started, firstOwnedSend: 1 })
    )
  )
  throwsCode(t, () =>
    validateControlMessage({ ...started, sent: -1 }, messageContext('event', started))
  )
  throwsCode(t, () =>
    validateControlMessage(
      { ...started, phaseSequence: 12n },
      messageContext('event', started, { phaseSequence: 11n })
    )
  )
})
