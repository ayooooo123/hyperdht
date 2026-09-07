'use strict'

const {
  IMMUTABLE_GET_POLICIES,
  IMMUTABLE_PUT_POLICIES,
  MUTABLE_GET_POLICIES,
  MUTABLE_PUT_POLICIES,
  unsupportedCommand
} = require('./dht-command-policy')

const WeakMapConstructor = WeakMap
const weakMapGet = WeakMap.prototype.get
const weakMapSet = WeakMap.prototype.set
const objectFreeze = Object.freeze
const reflectApply = Reflect.apply

function createQueryContexts() {
  const policies = new WeakMapConstructor()
  const immutableGetLookup = objectFreeze({})
  const immutableGetAnnounce = objectFreeze({})
  const immutablePutAnnounce = objectFreeze({})
  const mutableGetLookup = objectFreeze({})
  const mutableGetAnnounce = objectFreeze({})
  const mutablePutAnnounce = objectFreeze({})

  reflectApply(weakMapSet, policies, [immutableGetLookup, IMMUTABLE_GET_POLICIES.lookup])
  reflectApply(weakMapSet, policies, [immutableGetAnnounce, IMMUTABLE_GET_POLICIES.announce])
  reflectApply(weakMapSet, policies, [immutablePutAnnounce, IMMUTABLE_PUT_POLICIES.announce])
  reflectApply(weakMapSet, policies, [mutableGetLookup, MUTABLE_GET_POLICIES.lookup])
  reflectApply(weakMapSet, policies, [mutableGetAnnounce, MUTABLE_GET_POLICIES.announce])
  reflectApply(weakMapSet, policies, [mutablePutAnnounce, MUTABLE_PUT_POLICIES.announce])

  const immutableGet = objectFreeze({
    lookup: immutableGetLookup,
    announce: immutableGetAnnounce
  })
  const immutablePut = objectFreeze({ announce: immutablePutAnnounce })
  const mutableGet = objectFreeze({
    lookup: mutableGetLookup,
    announce: mutableGetAnnounce
  })
  const mutablePut = objectFreeze({ announce: mutablePutAnnounce })

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
  return objectFreeze({ immutableGet, immutablePut, mutableGet, mutablePut, classify })
}

objectFreeze(createQueryContexts)

module.exports = objectFreeze({ createQueryContexts })
