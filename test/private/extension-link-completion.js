const test = require('brittle')

const { createExtensionLinkCompletion, destroyExtensionLinkCompletion, destroyTakenExtensionLinkCompletion, takeExtensionLinkCompletion } = require('../../lib/private/extension-link-completion')
const {
  adoptM3ResponderLink,
  createM3ResponderAdopter,
  destroyM3ResponderLink,
  takeM3ResponderLink
} = require('../../lib/private/m3-adjacency-adopter')

function expectCode(t, operation, code) {
  let error = null
  try {
    operation()
  } catch (err) {
    error = err
  }
  t.is(error && error.code, code)
}

test('responder adjacency adoption transfers or destroys exactly once', (t) => {
  const established = Object.freeze({ id: 1 })
  const adopted = Object.freeze({ id: 2 })
  const destroyed = []
  const adopter = createM3ResponderAdopter(
    (value) => {
      t.is(value, established)
      return adopted
    },
    (value) => destroyed.push(value)
  )

  const first = adoptM3ResponderLink(adopter, established)
  t.is(takeM3ResponderLink(first), adopted)
  expectCode(t, () => takeM3ResponderLink(first), 'ERR_REPLAY')
  t.is(destroyM3ResponderLink(first), false)

  const second = adoptM3ResponderLink(adopter, established)
  t.is(destroyM3ResponderLink(second), true)
  t.alike(destroyed, [adopted])
  expectCode(t, () => takeM3ResponderLink(second), 'ERR_REPLAY')
})

test('extension completion moves once and retains cleanup through the internal take', (t) => {
  const material = {}
  let cleaned = 0
  const completion = createExtensionLinkCompletion(material, (value) => {
    t.is(value, material)
    cleaned++
  })

  t.ok(Object.isFrozen(completion))
  t.alike(Object.keys(completion), [])
  t.is(takeExtensionLinkCompletion(completion), material)
  expectCode(t, () => takeExtensionLinkCompletion(completion), 'ERR_REPLAY')
  t.is(destroyExtensionLinkCompletion(completion), false)
  t.is(destroyTakenExtensionLinkCompletion(material), true)
  t.is(cleaned, 1)
  t.is(destroyTakenExtensionLinkCompletion(material), false)
})

test('aborting an untaken extension completion invokes cleanup exactly once', (t) => {
  let cleaned = 0
  const completion = createExtensionLinkCompletion({}, () => cleaned++)

  t.is(destroyExtensionLinkCompletion(completion), true)
  t.is(destroyExtensionLinkCompletion(completion), false)
  expectCode(t, () => takeExtensionLinkCompletion(completion), 'ERR_REPLAY')
  t.is(cleaned, 1)
})
