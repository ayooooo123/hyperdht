'use strict'

// Key derivation for a remote-peer run, deliberately split in two so the two
// sides of a run hold different material.
//
// Role and peer hosts derive their own server keys from a shared run secret and
// the CI run id, so the DHT is the only rendezvous needed: the coordinator never
// has to read a runner log to learn where a peer is. That shared secret stays in
// CI secrets and in a local file, never in a workflow input, because dispatch
// inputs are visible to anyone who can read the repository.
//
// The coordinator's key is not derived from that shared secret, and that is the
// whole point of this file. Every role host holds the shared secret, so anything
// derived from it is derivable by every role host: one compromised role could
// mint the coordinator's key, pass any other role's firewall and take that
// role's single allowed ATTACH connection. The coordinator therefore keeps a
// second secret on the workstation and never ships it. Roles are handed only the
// matching public key, which is all a firewall pin needs, and a public key is
// safe to carry as a workflow input.

const b4a = require('b4a')
const sodium = require('sodium-universal')
const crypto = require('hypercore-crypto')

const DOMAIN = b4a.from('hyperdht/remote-peer/v1\n')

const COORDINATOR_KEY_HEX = /^[0-9a-fA-F]{64}$/

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

// The coordinator's key, from a secret only the workstation holds. It is not
// bound to a run id on purpose: a role host has to be told the pinned public key
// when the run is dispatched, and that is before GitHub has assigned the run id
// which scopes the roles' own keys.
function coordinatorKeyPair(secret) {
  return keyPairFor(secret, 'coordinator/v1')
}

// What a role host is given instead of the material above. Parsed strictly,
// because a firewall pinned to a truncated or mistyped key is a firewall pinned
// to nothing and b4a.from(hex, 'hex') would quietly accept both.
function coordinatorPublicKey(hex) {
  const trimmed = typeof hex === 'string' ? hex.trim() : ''
  if (!COORDINATOR_KEY_HEX.test(trimmed)) {
    throw new Error('coordinator public key must be 64 hex characters')
  }
  return b4a.from(trimmed, 'hex')
}

module.exports = { peerKeyPair, coordinatorKeyPair, coordinatorPublicKey }

// `node test/remote-peer/identity.js` prints the coordinator public key for
// REMOTE_PEER_COORDINATOR_SECRET. Every shell entry point needs that pin in
// order to dispatch a run, and this keeps key handling out of all of them.
if (require.main === module) {
  const secret = process.env.REMOTE_PEER_COORDINATOR_SECRET
  if (!secret) {
    console.error('REMOTE_PEER_COORDINATOR_SECRET is required')
    process.exit(69)
  }
  process.stdout.write(b4a.toString(coordinatorKeyPair(secret).publicKey, 'hex'))
}
