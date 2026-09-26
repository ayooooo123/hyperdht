'use strict'

// Operator tool for two-authority topology grants (format 1). Grants are
// exchanged out of band: one operator drafts the unsigned grant, each
// operator signs it with their own authority key, and either one assembles
// the two signatures. Nothing here touches the network.

const b4a = require('b4a')

const { cryptoSuite } = require('./crypto-suite')
const { DOMAIN, LINK_OPERATION, PROTOCOL_VERSION, TOPOLOGY_ROLE } = require('./protocol')
const {
  assembleTopologyGrantV1,
  decodeTopologyGrantV1,
  decodeUnsignedTopologyGrantV1,
  encodeUnsignedTopologyGrantV1,
  signTopologyGrantV1
} = require('./topology-grant')

const USAGE = `Experimental: offline two-authority topology grants for native relay neighbors.

Usage:
  hyperdht grant draft  --local-identity <hex> --local-role <role> --local-host <ip>
                        --local-port <n> --local-ops <ops> --local-authority <hex>
                        --peer-identity <hex> --peer-role <role> --peer-host <ip>
                        --peer-port <n> --peer-ops <ops> --peer-authority <hex>
                        --epoch <n> --run-id <hex> --expires <unix ms>
                        [--not-before <unix ms>] [--grant-id <hex>]
  hyperdht grant sign     --grant <hex> --key <file>
  hyperdht grant assemble --grant <hex> --signature <hex> --signature <hex>
  hyperdht grant inspect  --grant <hex>

Roles: source, safety-guard, safety-final, private-entry, private-middle,
private-final, destination. Ops: initiate, accept, both.
A key file holds a 64-byte Ed25519 secret key or a 32-byte seed, in hex.`

const ROLE_NAMES = Object.freeze({
  source: TOPOLOGY_ROLE.SOURCE,
  'safety-guard': TOPOLOGY_ROLE.SAFETY_GUARD,
  'safety-final': TOPOLOGY_ROLE.SAFETY_FINAL,
  'private-entry': TOPOLOGY_ROLE.PRIVATE_ENTRY,
  'private-middle': TOPOLOGY_ROLE.PRIVATE_MIDDLE,
  'private-final': TOPOLOGY_ROLE.PRIVATE_FINAL,
  destination: TOPOLOGY_ROLE.DESTINATION
})

const OPERATION_NAMES = Object.freeze({
  initiate: LINK_OPERATION.INITIATE,
  accept: LINK_OPERATION.ACCEPT,
  both: LINK_OPERATION.KNOWN
})

class GrantToolError extends Error {}

function fail(message) {
  throw new GrantToolError(message)
}

function hex(value, size, name) {
  if (typeof value !== 'string' || !/^([0-9a-f]{2})+$/i.test(value)) fail(`${name} must be hex`)
  const bytes = b4a.from(value, 'hex')
  if (size !== null && bytes.byteLength !== size) fail(`${name} must be ${size} bytes`)
  return bytes
}

function bigint(value, name) {
  if (typeof value !== 'string' || !/^[0-9]+$/.test(value)) fail(`${name} must be an integer`)
  return BigInt(value)
}

function lookup(table, value, name) {
  if (!Object.prototype.hasOwnProperty.call(table, value)) {
    fail(`${name} must be one of: ${Object.keys(table).join(', ')}`)
  }
  return table[value]
}

function endpoint(args, prefix) {
  const port = Number(args[`${prefix}-port`])
  if (!Number.isInteger(port) || port < 1 || port > 0xffff) fail(`--${prefix}-port is invalid`)
  return {
    identity32: hex(args[`${prefix}-identity`], 32, `--${prefix}-identity`),
    role: lookup(ROLE_NAMES, args[`${prefix}-role`], `--${prefix}-role`),
    host: args[`${prefix}-host`],
    port,
    operations: lookup(OPERATION_NAMES, args[`${prefix}-ops`], `--${prefix}-ops`),
    authority32: hex(args[`${prefix}-authority`], 32, `--${prefix}-authority`)
  }
}

function draftGrant(args) {
  const expiresAt = bigint(args.expires, '--expires')
  const notBefore =
    args['not-before'] === undefined
      ? BigInt(Date.now())
      : bigint(args['not-before'], '--not-before')
  return encodeUnsignedTopologyGrantV1({
    version: PROTOCOL_VERSION,
    format: 1,
    grantId32:
      args['grant-id'] === undefined
        ? cryptoSuite.randomBytes(32)
        : hex(args['grant-id'], 32, '--grant-id'),
    endpointA: endpoint(args, 'local'),
    endpointB: endpoint(args, 'peer'),
    epoch: bigint(args.epoch, '--epoch'),
    notBefore,
    expiresAt,
    runId32: hex(args['run-id'], 32, '--run-id')
  })
}

function keyPairFromFile(text) {
  const bytes = hex(text.trim(), null, 'key file')
  if (bytes.byteLength === 32) return cryptoSuite.keyPair(bytes)
  if (bytes.byteLength === 64) {
    return { publicKey: b4a.from(bytes.subarray(32)), secretKey: bytes }
  }
  fail('key file must hold a 32-byte seed or a 64-byte secret key')
}

// Signatures may arrive in either order; each is matched to the endpoint
// whose authority it verifies under.
function assembleGrant(unsigned, signatures) {
  if (signatures.length !== 2) fail('assemble needs exactly two --signature values')
  const decoded = decodeUnsignedTopologyGrantV1(unsigned)
  const digest = cryptoSuite.hash([DOMAIN.TOPOLOGY_GRANT_V1, unsigned])
  const signs = (signature, authority32) => cryptoSuite.verify(digest, signature, authority32)
  const [first, second] = signatures
  const a = decoded.endpointA.authority32
  const b = decoded.endpointB.authority32
  if (signs(first, a) && signs(second, b)) return assembleTopologyGrantV1(unsigned, first, second)
  if (signs(second, a) && signs(first, b)) return assembleTopologyGrantV1(unsigned, second, first)
  fail('the signatures do not cover both endpoint authorities')
}

function describe(value) {
  const describeEndpoint = (end) => ({
    identity: b4a.toString(end.identity32, 'hex'),
    role: Object.keys(ROLE_NAMES).find((name) => ROLE_NAMES[name] === end.role),
    host: end.host,
    port: end.port,
    ops: Object.keys(OPERATION_NAMES).find((name) => OPERATION_NAMES[name] === end.operations),
    authority: b4a.toString(end.authority32, 'hex')
  })
  return {
    grantId: b4a.toString(value.grantId32, 'hex'),
    endpointA: describeEndpoint(value.endpointA),
    endpointB: describeEndpoint(value.endpointB),
    epoch: value.epoch.toString(),
    runId: b4a.toString(value.runId32, 'hex'),
    notBefore: value.notBefore.toString(),
    expires: value.expiresAt.toString()
  }
}

function inspectGrant(bytes) {
  let decoded = null
  try {
    decoded = decodeTopologyGrantV1(bytes)
  } catch {}
  if (decoded === null) return { signed: false, ...describe(decodeUnsignedTopologyGrantV1(bytes)) }
  let signaturesValid = true
  try {
    assembleTopologyGrantV1(
      b4a.from(bytes.subarray(0, bytes.byteLength - 128)),
      decoded.signatureA,
      decoded.signatureB
    )
  } catch {
    signaturesValid = false
  }
  return { signed: true, signaturesValid, ...describe(decoded) }
}

function parseArgs(argv) {
  const args = { _: [], signature: [] }
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i]
    if (!token.startsWith('--')) {
      args._.push(token)
      continue
    }
    const name = token.slice(2)
    const value = argv[i + 1]
    if (value === undefined || value.startsWith('--')) fail(`--${name} needs a value`)
    i++
    if (name === 'signature') args.signature.push(value)
    else args[name] = value
  }
  return args
}

function run(argv, io) {
  const args = parseArgs(argv)
  const command = args._[0]
  if (command === 'draft') return b4a.toString(draftGrant(args), 'hex')
  if (command === 'sign') {
    if (args.key === undefined) fail('--key is required')
    const unsigned = hex(args.grant, null, '--grant')
    return b4a.toString(
      signTopologyGrantV1(unsigned, keyPairFromFile(io.readFile(args.key))),
      'hex'
    )
  }
  if (command === 'assemble') {
    const unsigned = hex(args.grant, null, '--grant')
    const signatures = args.signature.map((value) => hex(value, 64, '--signature'))
    return b4a.toString(assembleGrant(unsigned, signatures), 'hex')
  }
  if (command === 'inspect') {
    return JSON.stringify(inspectGrant(hex(args.grant, null, '--grant')), null, 2)
  }
  fail(USAGE)
}

module.exports = { GrantToolError, USAGE, run }
