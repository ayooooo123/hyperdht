'use strict'

// Both sides of a remote-peer run derive the same keys from a shared secret and
// the CI run id, so the DHT is the only rendezvous needed: the prober never has
// to read a runner log to learn where a peer is. The secret stays in CI secrets
// and in a local file, never in a workflow input, because dispatch inputs are
// visible to anyone who can read the repository.

const b4a = require('b4a')
const sodium = require('sodium-universal')
const crypto = require('hypercore-crypto')

const DOMAIN = b4a.from('hyperdht/remote-peer/v1\n')

function secretKey(secret) {
  const key = typeof secret === 'string' ? b4a.from(secret.trim(), 'hex') : secret
  if (!b4a.isBuffer(key) || key.byteLength < 16 || key.byteLength > 64) {
    throw new Error('remote peer secret must be 16 to 64 bytes of hex')
  }
  return key
}

function seedFor(secret, label) {
  const seed = b4a.allocUnsafeSlow(32)
  sodium.crypto_generichash(seed, b4a.concat([DOMAIN, b4a.from(label)]), secretKey(secret))
  return seed
}

function keyPairFor(secret, label) {
  const seed = seedFor(secret, label)
  try {
    return crypto.keyPair(seed)
  } finally {
    seed.fill(0)
  }
}

// One key per peer index, so a run of three peers is three independent servers.
function peerKeyPair(secret, runId, index) {
  return keyPairFor(secret, `peer/${runId}/${index}`)
}

// The prober's key is derived too, which lets every peer pin its firewall to
// exactly that key: a stranger who guesses a peer key still cannot connect.
function proberKeyPair(secret, runId) {
  return keyPairFor(secret, `prober/${runId}`)
}

module.exports = { peerKeyPair, proberKeyPair }
