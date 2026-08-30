'use strict'

const b4a = require('b4a')

const { BootstrapIO } = require('./bootstrap-io')
const { PrivateRouteError } = require('./errors')
const {
  createRelayCandidateDirectorySink,
  revokeRelayCandidateDirectorySink
} = require('./relay-candidate-directory')
const {
  UdxCellEndpoint,
  createBootstrapUdxAuthority,
  createLocalIdentitySecretCapability,
  destroyBootstrapUdxAuthority,
  destroyLocalIdentitySecretCapability
} = require('./udx-cell-endpoint')

const OPTION_FIELDS = Object.freeze([
  'bootstrapEndpoints',
  'localIdentity',
  'localSecretKey',
  'host',
  'port',
  'wallNow',
  'monotonicNow',
  'schedule',
  'cancelScheduled',
  'randomBytes'
])

// Only meaningful where a translation sits in front of this host: the address peers
// reach the endpoint at, as distinct from the one it binds. Stated as a pair or not
// at all, so the two lists are the only accepted shapes.
const ADVERTISED_OPTION_FIELDS = Object.freeze([
  ...OPTION_FIELDS,
  'advertisedHost',
  'advertisedPort'
])

const AUTHORITIES = new WeakMap()
const REGISTRATIONS = new WeakMap()
const SPENT_REGISTRATIONS = new WeakSet()

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function unauthorized() {
  throw PrivateRouteError.UNAUTHORIZED()
}

function replay() {
  throw PrivateRouteError.ERR_REPLAY()
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function exactObject(value, fields) {
  if (!isObject(value) || Object.getPrototypeOf(value) !== Object.prototype) invalid()
  const names = Object.getOwnPropertyNames(value)
  const symbols = Object.getOwnPropertySymbols(value)
  if (symbols.length !== 0 || names.length !== fields.length) invalid()
  for (const name of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name)
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) invalid()
  }
}

function clear(value) {
  if (!b4a.isBuffer(value)) return
  value.fill(0)
}

function destroyRecord(record) {
  if (!record || record.status === 'DESTROYED' || record.status === 'SPENT') return false
  record.status = 'DESTROYED'
  if (record.registration) {
    REGISTRATIONS.delete(record.registration)
    SPENT_REGISTRATIONS.add(record.registration)
    record.registration = null
  }
  const bootstrapIO = record.bootstrapIO
  const bootstrapUdxAuthority = record.bootstrapUdxAuthority
  const endpoint = record.endpoint
  const candidateDirectorySink = record.candidateDirectorySink
  const localSecretCapability = record.localSecretCapability
  record.bootstrapIO = null
  record.bootstrapUdxAuthority = null
  record.endpoint = null
  record.candidateDirectorySink = null
  record.localSecretCapability = null
  try {
    if (bootstrapIO) bootstrapIO.destroy()
  } catch {}
  try {
    if (bootstrapUdxAuthority) destroyBootstrapUdxAuthority(bootstrapUdxAuthority)
  } catch {}
  try {
    if (endpoint) void endpoint.close().catch(() => {})
  } catch {}
  try {
    if (candidateDirectorySink) revokeRelayCandidateDirectorySink(candidateDirectorySink)
  } catch {}
  try {
    if (localSecretCapability) destroyLocalIdentitySecretCapability(localSecretCapability)
  } catch {}
  return true
}

function createEndpointBootstrapAuthority(options) {
  const advertised =
    Object.prototype.hasOwnProperty.call(options, 'advertisedHost') ||
    Object.prototype.hasOwnProperty.call(options, 'advertisedPort')
  exactObject(options, advertised ? ADVERTISED_OPTION_FIELDS : OPTION_FIELDS)
  const {
    bootstrapEndpoints,
    localIdentity,
    localSecretKey,
    host,
    port,
    wallNow,
    monotonicNow,
    schedule,
    cancelScheduled,
    randomBytes
  } = options
  let candidateDirectorySink = null
  let localSecretCapability = null
  let endpoint = null
  let bootstrapUdxAuthority = null
  let bootstrapIO = null
  try {
    if (
      !b4a.isBuffer(localIdentity) ||
      localIdentity.byteLength !== 32 ||
      !b4a.isBuffer(localSecretKey) ||
      localSecretKey.byteLength !== 64 ||
      typeof wallNow !== 'function' ||
      typeof monotonicNow !== 'function' ||
      typeof schedule !== 'function' ||
      typeof cancelScheduled !== 'function' ||
      typeof randomBytes !== 'function'
    ) {
      invalid()
    }
    candidateDirectorySink = createRelayCandidateDirectorySink({
      wallNow,
      monotonicNow,
      randomBytes
    })
    localSecretCapability = createLocalIdentitySecretCapability({
      localIdentity,
      localSecretKey
    })
    endpoint = new UdxCellEndpoint({
      host,
      port,
      ...(advertised
        ? { advertisedHost: options.advertisedHost, advertisedPort: options.advertisedPort }
        : {}),
      onBootstrap() {
        unauthorized()
      },
      onCell() {
        unauthorized()
      },
      onLinkFailure() {
        unauthorized()
      }
    })
    bootstrapUdxAuthority = createBootstrapUdxAuthority({
      endpoint,
      configuredEndpoints: bootstrapEndpoints,
      localSecretCapability,
      maxProspectiveGuards: 3,
      monotonicDeadline: monotonicNow
    })
    localSecretCapability = null
    bootstrapIO = new BootstrapIO({
      endpoints: bootstrapEndpoints,
      localIdentity,
      localSecretKey,
      datagrams: bootstrapUdxAuthority,
      wallNow,
      monotonicNow,
      randomBytes,
      candidateDirectorySink
    })
    const authority = Object.freeze({})
    AUTHORITIES.set(authority, {
      status: 'READY',
      authority,
      registration: null,
      bootstrapIO,
      endpoint,
      bootstrapUdxAuthority,
      candidateDirectorySink,
      localSecretCapability: null,
      wallNow,
      monotonicNow,
      schedule,
      cancelScheduled,
      randomBytes
    })
    bootstrapIO = null
    endpoint = null
    bootstrapUdxAuthority = null
    candidateDirectorySink = null
    return authority
  } catch (err) {
    try {
      if (bootstrapIO) bootstrapIO.destroy()
    } catch {}
    try {
      if (bootstrapUdxAuthority) destroyBootstrapUdxAuthority(bootstrapUdxAuthority)
    } catch {}
    try {
      if (endpoint) void endpoint.close().catch(() => {})
    } catch {}
    try {
      if (candidateDirectorySink) revokeRelayCandidateDirectorySink(candidateDirectorySink)
    } catch {}
    try {
      if (localSecretCapability) destroyLocalIdentitySecretCapability(localSecretCapability)
    } catch {}
    throw err
  } finally {
    clear(localSecretKey)
  }
}

function registerEndpointBootstrapController(authority, controller) {
  const record = isObject(authority) ? AUTHORITIES.get(authority) : null
  if (!record) unauthorized()
  if (record.status !== 'READY' || record.registration !== null) replay()
  if (!isObject(controller) || !Object.isFrozen(controller)) invalid()
  const registration = Object.freeze({})
  record.registration = registration
  REGISTRATIONS.set(registration, { authority, controller, record })
  return registration
}

function consumeEndpointBootstrapAuthority(authority, controllerRegistration) {
  const record = isObject(authority) ? AUTHORITIES.get(authority) : null
  if (!record) unauthorized()
  if (record.status === 'DESTROYED' || record.status === 'SPENT') replay()
  const registration = isObject(controllerRegistration)
    ? REGISTRATIONS.get(controllerRegistration)
    : null
  if (
    !registration ||
    registration.authority !== authority ||
    registration.record !== record ||
    record.registration !== controllerRegistration ||
    record.status !== 'READY'
  ) {
    destroyRecord(record)
    unauthorized()
  }
  record.status = 'CONSUMING'
  REGISTRATIONS.delete(controllerRegistration)
  SPENT_REGISTRATIONS.add(controllerRegistration)
  const result = Object.freeze({
    controller: registration.controller,
    bootstrapIO: record.bootstrapIO,
    endpoint: record.endpoint,
    bootstrapUdxAuthority: record.bootstrapUdxAuthority,
    wallNow: record.wallNow,
    monotonicNow: record.monotonicNow,
    schedule: record.schedule,
    cancelScheduled: record.cancelScheduled,
    randomBytes: record.randomBytes
  })
  record.bootstrapIO = null
  record.endpoint = null
  record.bootstrapUdxAuthority = null
  record.candidateDirectorySink = null
  record.registration = null
  record.wallNow = null
  record.monotonicNow = null
  record.schedule = null
  record.cancelScheduled = null
  record.randomBytes = null
  record.status = 'SPENT'
  return result
}

function inspectEndpointBootstrapAuthority(authority) {
  const record = isObject(authority) ? AUTHORITIES.get(authority) : null
  if (!record) unauthorized()
  return Object.freeze({
    status: record.status,
    bootstrapIO: record.bootstrapIO !== null,
    endpoint: record.endpoint !== null,
    bootstrapUdxAuthority: record.bootstrapUdxAuthority !== null,
    registration: record.registration !== null,
    secretBytes: 0
  })
}

module.exports = Object.freeze({
  consumeEndpointBootstrapAuthority,
  createEndpointBootstrapAuthority,
  inspectEndpointBootstrapAuthority,
  registerEndpointBootstrapController
})
