'use strict'

const { IMMUTABLE_GET_POLICIES, unsupportedCommand } = require('./dht-command-policy')

const WeakMapConstructor = WeakMap
const weakMapGet = WeakMap.prototype.get
const weakMapSet = WeakMap.prototype.set
const objectFreeze = Object.freeze
const reflectApply = Reflect.apply

function createQueryContexts() {
  const policies = new WeakMapConstructor()
  const lookup = objectFreeze({})
  const announce = objectFreeze({})

  reflectApply(weakMapSet, policies, [lookup, IMMUTABLE_GET_POLICIES.lookup])
  reflectApply(weakMapSet, policies, [announce, IMMUTABLE_GET_POLICIES.announce])

  const immutableGet = objectFreeze({ lookup, announce })

  function classify(value) {
    if ((typeof value !== 'object' && typeof value !== 'function') || value === null) {
      throw unsupportedCommand()
    }

    let policy
    try {
      policy = reflectApply(weakMapGet, policies, [value])
    } catch {
      throw unsupportedCommand()
    }
    if (policy === undefined) throw unsupportedCommand()
    return policy
  }

  objectFreeze(classify)
  return objectFreeze({ immutableGet, classify })
}

objectFreeze(createQueryContexts)

module.exports = objectFreeze({ createQueryContexts })
