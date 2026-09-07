'use strict'

// Gate D production caller: publish / revoke / resolve private presence records
// through a controller that exposes mutablePut / mutableGet only.
//
// readerSecret is never retained across calls. Per-record reader keys are
// derived inside the codec and erased there.

const b4a = require('b4a')

const {
  RECORD_TYPE,
  TOMBSTONE_SCOPE,
  createBlindedSigner,
  deriveBlindedPublicKey,
  encodePresenceRecord,
  openPresenceRecord,
  publishPeriods,
  lookupPeriods,
  recordDigestOf,
  resolvePresenceState
} = require('./blinded-presence')
const { PrivateRouteError } = require('./errors')

function isFixed(value, size) {
  return b4a.isBuffer(value) && value.byteLength === size
}

function createPresenceClient(options) {
  if (!options || typeof options !== 'object') throw PrivateRouteError.INVALID_KEY()
  const controller = options.controller
  if (
    !controller ||
    typeof controller.mutablePut !== 'function' ||
    typeof controller.mutableGet !== 'function'
  ) {
    throw PrivateRouteError.INVALID_KEY()
  }

  const now = typeof options.now === 'function' ? options.now : () => Date.now()
  const readerSecret = options.readerSecret
  if (!isFixed(readerSecret, 32)) throw PrivateRouteError.INVALID_KEY()

  const identityKeyPair = options.identityKeyPair || null
  const identityPublicKey = options.identityPublicKey
    ? b4a.from(options.identityPublicKey)
    : identityKeyPair
      ? b4a.from(identityKeyPair.publicKey)
      : null

  if (!isFixed(identityPublicKey, 32)) throw PrivateRouteError.INVALID_KEY()
  if (
    identityKeyPair &&
    (!isFixed(identityKeyPair.publicKey, 32) || !isFixed(identityKeyPair.secretKey, 64))
  ) {
    throw PrivateRouteError.INVALID_KEY()
  }

  function requireOwner() {
    if (!identityKeyPair) throw PrivateRouteError.UNAUTHORIZED()
  }

  async function publishForPeriods({ type, revision, descriptor, scope, targets }) {
    requireOwner()
    if (!Number.isInteger(revision) || revision < 0) throw PrivateRouteError.INVALID_DESCRIPTOR()

    const periods = publishPeriods(now())
    if (type === RECORD_TYPE.TOMBSTONE && scope === TOMBSTONE_SCOPE.RECORD) {
      if (!(targets instanceof Map)) throw PrivateRouteError.INVALID_DESCRIPTOR()
      const snapshot = new Map()
      for (const period of periods) {
        const target = targets.get(period)
        if (!isFixed(target, 32)) throw PrivateRouteError.INVALID_DESCRIPTOR()
        snapshot.set(period, b4a.from(target))
      }
      targets = snapshot
    }
    const results = []

    for (const period of periods) {
      const signer = createBlindedSigner(identityKeyPair, period)
      try {
        const encoded =
          type === RECORD_TYPE.DESCRIPTOR
            ? encodePresenceRecord({
                signer,
                period,
                revision,
                readerSecret,
                type,
                descriptor
              })
            : encodePresenceRecord({
                signer,
                period,
                revision,
                readerSecret,
                type,
                tombstone: {
                  scope,
                  target: scope === TOMBSTONE_SCOPE.RECORD ? targets.get(period) : b4a.alloc(32)
                }
              })

        await controller.mutablePut({ publicKey: encoded.publicKey }, encoded.value, {
          seq: revision,
          signMutable: encoded.signMutable
        })

        results.push(
          Object.freeze({
            period,
            publicKey: b4a.from(encoded.publicKey),
            revision,
            recordDigest: recordDigestOf(encoded.value)
          })
        )
      } finally {
        signer.destroy()
      }
    }

    return results
  }

  async function publishPresence({ descriptor, revision }) {
    if (!b4a.isBuffer(descriptor)) throw PrivateRouteError.INVALID_DESCRIPTOR()
    return publishForPeriods({
      type: RECORD_TYPE.DESCRIPTOR,
      revision,
      descriptor
    })
  }

  async function revokePresence({ revision, scope, targets }) {
    if (scope !== TOMBSTONE_SCOPE.PERIOD && scope !== TOMBSTONE_SCOPE.RECORD) {
      throw PrivateRouteError.INVALID_DESCRIPTOR()
    }
    return publishForPeriods({
      type: RECORD_TYPE.TOMBSTONE,
      revision,
      scope,
      targets
    })
  }

  async function resolvePresence({ previous } = {}) {
    const periods = lookupPeriods(now())

    for (const period of periods) {
      const publicKey = deriveBlindedPublicKey(identityPublicKey, period)
      const record = await controller.mutableGet(publicKey, { latest: true })
      if (record === null || record === undefined) continue

      const opened = openPresenceRecord({
        identityPublicKey,
        period,
        revision: record.seq,
        readerSecret,
        value: record.value,
        signature: record.signature
      })

      const withDigest = Object.freeze({
        ...opened,
        recordDigest: recordDigestOf(record.value)
      })

      return resolvePresenceState({ previous: previous || null, opened: withDigest })
    }

    return null
  }

  return Object.freeze({
    publishPresence,
    revokePresence,
    resolvePresence
  })
}

module.exports = {
  createPresenceClient
}
