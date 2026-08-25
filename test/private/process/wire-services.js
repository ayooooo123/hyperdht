'use strict'

const b4a = require('b4a')
const DHT = require('dht-rpc')
const { COMMANDS } = require('../../../lib/constants')

const { BootstrapEnvelopeCodec } = require('../../../lib/private/bootstrap-envelope')
const { CapsResponder } = require('../../../lib/private/caps-responder')
const {
  createExtensionOfferReceiver,
  createExtensionResponseReceiver
} = require('../../../lib/private/extension-setup-channel')
const {
  createDhtExitDestinationTableForTest,
  destroyDhtExitDestinationTable,
  deriveDhtExitPeerId,
  reserveConfiguredBootstrapProbe,
  reserveTestTopologyReferralProbe,
  snapshotDhtExitDestinationTable,
  settleExitDhtReservation
} = require('../../../lib/private/dht-exit-destination-table')
const {
  TEST_ONLY_DHT_EXIT_IO_STATE,
  destroyDhtExitIO,
  createDhtExitIO,
  installDhtExitRoute,
  sendDhtExitSeeds,
  sendReservedExitDhtPacket,
  waitDhtExitIOReady
} = require('../../../lib/private/dht-exit-io')
const {
  createDhtExitReservationChannel,
  consumeDhtExitReservationIOConsumer
} = require('../../../lib/private/dht-exit-reservation')
const { createDhtExitSeedsDeliveryAuthority } = require('../../../lib/private/dht-exit-seeds')
const {
  TEST_ONLY_DHT_EXIT_TOPOLOGY_ISSUER,
  consumeTestDhtExitReferralGrant,
  createTestDhtExitReferralGrant,
  decodeTestIsolatedAddressGrant,
  digestTestIsolatedAddressTuple
} = require('../../../lib/private/dht-exit-test-topology-grant')
const { cryptoSuite } = require('../../../lib/private/crypto-suite')
const { PrivateRouteError } = require('../../../lib/private/errors')
const {
  claimFinalExitActivation,
  createFinalExitActivationClaim,
  createFinalExitActivationFactory,
  driveDhtExitFinalExit,
  openFinalExit
} = require('../../../lib/private/final-exit-activation')
const { createLinkSetupAuthority } = require('../../../lib/private/link-setup')
const guardLinks = require('../../../lib/private/guard-link')
const {
  M3AdjacencyAuthority,
  beginM3Install,
  commitM3Install,
  createM3RelayForwardingFacade,
  validateM3Install
} = require('../../../lib/private/m3-adjacency-runtime')
const { encodeM3ContextEnvelope } = require('../../../lib/private/m3-context')
const {
  CONTEXT_CLASS,
  LINK_OPERATION,
  ROLE,
  decodeM3Object
} = require('../../../lib/private/protocol')
const {
  createRedactedResponderProofAuthority
} = require('../../../lib/private/redacted-responder-proof')
const {
  decodeRelayCapabilityAdvertisement,
  encodeCanonicalEndpoint
} = require('../../../lib/private/relay-capability')
const {
  createDhtExitReadySigner,
  createExtensionResponderSigner,
  createLinkOfferSigner,
  createRelayIdentitySigningAuthority,
  createTailReadySigner,
  destroyRelayIdentitySigningAuthority
} = require('../../../lib/private/relay-identity-signer')
const {
  TEST_ONLY_LIVE_ROUTE_AUTHORITY_ISSUER
} = require('../../../lib/private/live-route-authority')
const { createQueryContexts } = require('../../../lib/private/query-context')
const { RoutedDHTIO } = require('../../../lib/private/routed-dht-io')
const { createTailExtensionCommitter } = require('../../../lib/private/tail-extension-committer')
const {
  admitTailExtend,
  borrowTailControlTransport,
  completeTailExtend,
  createSuccessorTailReadyContext,
  createTailControlResponderAuthority,
  createTailControlSession,
  destroyTailControlResponderAuthority,
  destroyTailControlSession,
  encodeSuccessorTailReadyContext,
  importSuccessorTailReadyContext,
  openTailAdjacentLink,
  readAdmittedTailSelection,
  sealSuccessorTailReady
} = require('../../../lib/private/tail-control')
const { LinkDirectory, decodeTopologyGrant } = require('../../../lib/private/topology-grant')
const endpointModule = require('../../../lib/private/udx-cell-endpoint')
const sessionModule = require('../../../lib/private/link-bootstrap-session')
// The role's cell endpoint and the silent-death verb that rides its UDX adapter. Re-exported
// here so a role runner only ever imports transport wiring from this module.
const { blackholeRouteCells, createProjectedCellEndpoint } = require('./route-cell-blackhole')

const createDynamicResponderSetup =
  sessionModule[Symbol.for('hyperdht-private-routes/dynamic-responder-setup-factory')]
const LINK_DEADLINE_MS = 5_000
const EXTENSION_INSTALLED_ACK = b4a.from('hyperdht-private-routes/process-extension-installed/v1')

function same(left, right) {
  return b4a.isBuffer(left) && b4a.isBuffer(right) && b4a.equals(left, right)
}

function numberNow(fn) {
  const value = fn()
  const result = typeof value === 'bigint' ? Number(value) : value
  if (!Number.isSafeInteger(result) || result < 0) throw PrivateRouteError.INVALID_ROUTE()
  return result
}

// The same shape lib/private/dht-exit-io.js:92 accepts for the address it binds, so a
// tuple this file forwards cannot be looser than the one the consumer enforces.
function numericTuple(value) {
  if (!value || typeof value !== 'object') return false
  const { host, port } = value
  if (typeof host !== 'string') return false
  if (!/^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$/.test(host)) return false
  if (!host.split('.').every((part) => Number(part) <= 255)) return false
  return Number.isSafeInteger(port) && port >= 0 && port <= 0xffff
}

function createProjectedLinkService(options) {
  if (!options || typeof options !== 'object') throw PrivateRouteError.INVALID_ROUTE()
  const {
    endpoint,
    authorityPublicKey,
    epoch,
    localIdentity,
    localIdentitySecretKey,
    localRouteSecretKey,
    runId32,
    wallNow,
    monotonicNow,
    schedule,
    cancelScheduled,
    onCell = null,
    onLinkFailure = null
  } = options
  if (
    !endpoint ||
    !same(localIdentitySecretKey.subarray(32), localIdentity) ||
    !b4a.isBuffer(authorityPublicKey) ||
    authorityPublicKey.byteLength !== 32 ||
    typeof epoch !== 'bigint' ||
    !b4a.isBuffer(runId32) ||
    runId32.byteLength !== 32 ||
    typeof wallNow !== 'function' ||
    typeof monotonicNow !== 'function' ||
    typeof schedule !== 'function' ||
    typeof cancelScheduled !== 'function' ||
    (onCell !== null && typeof onCell !== 'function') ||
    (onLinkFailure !== null && typeof onLinkFailure !== 'function')
  ) {
    throw PrivateRouteError.INVALID_ROUTE()
  }

  let localRole = null
  let current = null
  let destroyed = false
  // A `LinkDirectory` keeps one link handle per grant for as long as it lives, and
  // `UdxCellEndpoint.openLink` refuses a handle it already consumed. A rebuilt branch
  // reuses the same signed grant, so each authorization gets its own directory and
  // releases it when that link closes; `consumed` still rejects a second live link on
  // one grant.
  const consumed = new Set()
  const sessions = new Set()
  const links = new Set()
  // Faulting one adjacent link needs the session that owns it: closing that session
  // invalidates the UDX record and reports a real physical loss to the M3 runtime,
  // which is what makes a relay emit BRANCH_DESTROY upstream.
  const linkSessions = new Map()
  const sessionGrants = new Map()

  function assertLive() {
    if (destroyed) throw PrivateRouteError.ERR_DESTROYED()
  }

  function endpoints(encoded) {
    const decoded = decodeTopologyGrant(encoded)
    const local = same(decoded.endpointA.identity32, localIdentity)
      ? decoded.endpointA
      : same(decoded.endpointB.identity32, localIdentity)
        ? decoded.endpointB
        : null
    if (local === null) throw PrivateRouteError.UNAUTHORIZED()
    const peer = local === decoded.endpointA ? decoded.endpointB : decoded.endpointA
    if (localRole === null) localRole = local.role
    else if (local.role !== localRole) throw PrivateRouteError.UNAUTHORIZED()
    return { decoded, local, peer }
  }

  function createDirectory() {
    return new LinkDirectory({
      authorityPublicKey,
      cancel: cancelScheduled,
      epoch,
      localIdentity32: localIdentity,
      localRole,
      now: wallNow,
      onClose() {
        return false
      },
      onError() {
        if (onLinkFailure !== null) onLinkFailure(null, 'BOTH', 'GRANT')
      },
      runId32,
      schedule
    })
  }

  function releaseGrant(session) {
    const record = sessionGrants.get(session)
    if (!record) return false
    sessionGrants.delete(session)
    consumed.delete(record.key)
    try {
      record.directory.destroy()
    } catch {}
    return true
  }

  function authorize(encoded, operation) {
    assertLive()
    const { decoded, local, peer } = endpoints(encoded)
    const directory = createDirectory()
    let digest32 = null
    try {
      digest32 = directory.add(encoded)
      const key = `${b4a.toString(digest32, 'hex')}:${operation}`
      if (consumed.has(key)) throw PrivateRouteError.ERR_REPLAY()
      const handle = directory.authorize({
        digest32,
        epoch,
        localIdentity32: localIdentity,
        localRole: local.role,
        operation,
        peerIdentity32: peer.identity32,
        peerRole: peer.role,
        runId32
      })
      consumed.add(key)
      return { decoded, directory, handle, key, local, peer }
    } catch (err) {
      try {
        directory.destroy()
      } catch {}
      throw err
    } finally {
      if (digest32 !== null) digest32.fill(0)
    }
  }

  function sessionOptions(authorized, mode, setup) {
    const now = numberNow(monotonicNow)
    let padding = 0
    const randomBytes = (size) => {
      const value = cryptoSuite.randomBytes(size)
      padding++
      return value
    }
    const signedExpiry = Number(authorized.decoded.expiresAt)
    if (!Number.isSafeInteger(signedExpiry)) throw PrivateRouteError.INVALID_ROUTE()
    return {
      mode,
      codec: new BootstrapEnvelopeCodec({
        linkHandle: authorized.handle,
        localIdentitySecretKey,
        padding: randomBytes
      }),
      linkSetup: createLinkSetupAuthority({ now: () => numberNow(wallNow), randomBytes }),
      setup,
      now: () => numberNow(monotonicNow),
      schedule,
      cancel: cancelScheduled,
      randomBytes,
      absoluteDeadline: now + LINK_DEADLINE_MS,
      signedExpiry,
      authorizedExpiry: signedExpiry
    }
  }

  function installSession(session, authorized, mode, resolve = null, reject = null) {
    if (current !== null) throw PrivateRouteError.CIRCUIT_STATE()
    current = { mode, reject, resolve, session }
    sessions.add(session)
    sessionGrants.set(session, { directory: authorized.directory, key: authorized.key })
  }

  function opened(session) {
    const established = session.established
    if (!established) throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    const result = Object.freeze({ established })
    links.add(result)
    return result
  }

  function releaseAuthorization(authorized) {
    if (!authorized) return false
    consumed.delete(authorized.key)
    try {
      authorized.directory.destroy()
    } catch {}
    return true
  }

  // A dead session still holds its grant, and only this role can tell that the link is
  // gone: the peer's close is silent on the wire. Sweeping on every failure notice
  // frees exactly the grants whose sessions are tombstoned, leaving live links alone.
  function sweepClosedLinks() {
    for (const [link, session] of linkSessions) {
      if (session.state !== 'TOMBSTONE' && session.established !== null) continue
      linkSessions.delete(link)
      sessions.delete(session)
      links.delete(link)
      releaseGrant(session)
    }
  }

  function prearmAccept(encoded) {
    assertLive()
    if (!b4a.isBuffer(localRouteSecretKey) || localRouteSecretKey.byteLength !== 32) {
      return Promise.reject(PrivateRouteError.UNAUTHORIZED())
    }
    let session = null
    let authorized = null
    try {
      authorized = authorize(encoded, LINK_OPERATION.ACCEPT)
      session = endpoint.openLink(
        authorized.handle,
        sessionOptions(
          authorized,
          'accept',
          createDynamicResponderSetup({
            responderStaticSecretKey: localRouteSecretKey,
            responderIdentitySecretKey: localIdentitySecretKey
          })
        )
      )
      const pending = new Promise((resolve, reject) =>
        installSession(session, authorized, 'accept', resolve, reject)
      )
      void pending.catch(() => {})
      return pending
    } catch (err) {
      if (session) void session.close().catch(() => {})
      if (session === null || !sessionGrants.has(session)) releaseAuthorization(authorized)
      else releaseGrant(session)
      return Promise.reject(err)
    }
  }

  async function initiate(encoded, values) {
    assertLive()
    if (
      !values ||
      typeof values !== 'object' ||
      !b4a.isBuffer(values.circuitId) ||
      values.circuitId.byteLength !== 16 ||
      typeof values.generation !== 'bigint' ||
      !b4a.isBuffer(values.responderStaticKey) ||
      values.responderStaticKey.byteLength !== 32
    ) {
      throw PrivateRouteError.INVALID_ROUTE()
    }
    const authorized = authorize(encoded, LINK_OPERATION.INITIATE)
    const expiresAt = authorized.decoded.expiresAt
    const setup = {
      circuitId: b4a.from(values.circuitId),
      epoch,
      initiatorIdentity: b4a.from(localIdentity),
      responderIdentity: b4a.from(authorized.peer.identity32),
      initiatorLocalId: cryptoSuite.randomBytes(16),
      responderLocalId: cryptoSuite.randomBytes(16),
      expiresAt,
      responderStaticKey: b4a.from(values.responderStaticKey),
      initiatorIdentitySecretKey: b4a.from(localIdentitySecretKey)
    }
    let session = null
    try {
      session = endpoint.openLink(authorized.handle, sessionOptions(authorized, 'initiate', setup))
      installSession(session, authorized, 'initiate')
      const established = await session.open()
      if (current && current.session === session) current = null
      const result = Object.freeze({ established })
      links.add(result)
      linkSessions.set(result, session)
      return result
    } catch (err) {
      if (current && current.session === session) current = null
      if (session) await session.close().catch(() => {})
      if (session === null || !sessionGrants.has(session)) releaseAuthorization(authorized)
      else releaseGrant(session)
      throw err
    } finally {
      for (const value of Object.values(setup)) if (b4a.isBuffer(value)) value.fill(0)
    }
  }

  async function receiveBootstrap(packet) {
    if (destroyed || current === null) return false
    const operation = current
    const result = await operation.session.receive(packet)
    if (operation.mode === 'accept' && operation.session.established) {
      current = null
      const value = opened(operation.session)
      operation.resolve(value)
    }
    return result
  }

  function receiveCell(packet, handle, metadata) {
    if (destroyed) return false
    return onCell === null ? false : onCell(packet, handle, metadata)
  }

  function receiveLinkFailure(handle, direction, reason) {
    if (destroyed) return
    sweepClosedLinks()
    if (onLinkFailure !== null) onLinkFailure(handle, direction, reason)
  }

  function openSetupTransport(link) {
    assertLive()
    if (!links.has(link)) throw PrivateRouteError.UNAUTHORIZED()
    const transport = endpointModule.createExtensionSetupTransport(link.established)
    let state = 'OPEN'
    return Object.freeze({
      send(payload) {
        if (state === 'CLOSED') return Promise.reject(PrivateRouteError.ERR_DESTROYED())
        return transport.send(payload)
      },
      receive() {
        if (state === 'CLOSED') return Promise.reject(PrivateRouteError.ERR_DESTROYED())
        return transport.receive()
      },
      takePhysicalChannel() {
        if (state !== 'OPEN') throw PrivateRouteError.ERR_REPLAY()
        state = 'TRANSFERRED'
        return transport.takePhysicalChannel()
      },
      finish() {
        if (state !== 'TRANSFERRED') throw PrivateRouteError.UNAUTHORIZED()
        state = 'CLOSED'
        links.delete(link)
        return transport.finish()
      },
      destroy() {
        if (state === 'CLOSED') return false
        state = 'CLOSED'
        links.delete(link)
        return transport.destroy()
      }
    })
  }

  function takeChannel(link) {
    assertLive()
    if (!links.has(link)) throw PrivateRouteError.UNAUTHORIZED()
    links.delete(link)
    return endpointModule.createM3CellLinkTransferIssuer(endpoint, link.established)
  }

  async function faultLink(link) {
    if (destroyed) return false
    const session = linkSessions.get(link)
    if (!session) return false
    linkSessions.delete(link)
    sessions.delete(session)
    links.delete(link)
    await session.close().catch(() => {})
    releaseGrant(session)
    return true
  }

  async function faultPhysicalLink() {
    if (destroyed) return false
    const closing = []
    const closingSessions = Array.from(sessions)
    for (const session of closingSessions) closing.push(session.close())
    sessions.clear()
    links.clear()
    linkSessions.clear()
    if (current && current.reject) current.reject(PrivateRouteError.ERR_PRIVACY_UNAVAILABLE())
    current = null
    await Promise.allSettled(closing)
    for (const session of closingSessions) releaseGrant(session)
    return closing.length > 0
  }

  async function destroy() {
    if (destroyed) return false
    destroyed = true
    if (current && current.reject) current.reject(PrivateRouteError.ERR_DESTROYED())
    current = null
    const closing = []
    const closingSessions = Array.from(sessions)
    for (const session of closingSessions) closing.push(session.close())
    sessions.clear()
    links.clear()
    linkSessions.clear()
    await Promise.allSettled(closing)
    for (const session of closingSessions) releaseGrant(session)
    consumed.clear()
    return true
  }

  return Object.freeze({
    destroy,
    faultLink,
    faultPhysicalLink,
    initiate,
    openSetupTransport,
    prearmAccept,
    receiveBootstrap,
    receiveCell,
    receiveLinkFailure,
    snapshot() {
      return Object.freeze({ openLinks: links.size, pending: current === null ? 0 : 1 })
    },
    takeChannel
  })
}

const TAKE_STAGED_OFFER = Symbol.for('hyperdht-private-routes/relay-adjacent-staged-offer-taker')

function tailEnvelope(encoded) {
  const frame = b4a.alloc(1100)
  frame.set(encoded)
  return encodeM3ContextEnvelope({ contextClass: CONTEXT_CLASS.TAIL_CONTROL_ORDERED, frame })
}

function readU64(input, offset) {
  let value = 0n
  for (let index = offset; index < offset + 8; index++) {
    value = (value << 8n) | BigInt(input[index])
  }
  return value
}

function clearSelection(selection) {
  if (!selection) return
  for (const value of Object.values(selection)) if (b4a.isBuffer(value)) value.fill(0)
}

function createTailRelayActor(options) {
  const {
    adjacency,
    adjacencyAuthority,
    advertisement,
    identityPublicKey,
    identitySecretKey,
    clocks,
    outgoing = null,
    incomingPhysicalChannel: initialIncomingPhysicalChannel = null,
    attachments = []
  } = options
  if (
    !adjacency ||
    !adjacencyAuthority ||
    !b4a.isBuffer(advertisement) ||
    !same(identitySecretKey.subarray(32), identityPublicKey) ||
    !clocks ||
    typeof clocks.wallNow !== 'function' ||
    typeof clocks.monotonicNow !== 'function' ||
    typeof clocks.schedule !== 'function' ||
    typeof clocks.cancelScheduled !== 'function'
  ) {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  const tail = createTailControlSession(adjacency.tail, {
    wallNow: clocks.wallNow,
    monotonicNow: clocks.monotonicNow,
    schedule: clocks.schedule,
    cancelScheduled: clocks.cancelScheduled,
    crypto: cryptoSuite
  })
  const transport = borrowTailControlTransport(tail)
  const identityOwner = createRelayIdentitySigningAuthority({ identitySecretKey })
  let authority = null
  let nextAuthority = null
  let proofAuthority = null
  let dialAuthority = null
  let adjacentFactory = null
  let committer = null
  let forwarding = null
  let readyContext = null
  let pendingSetup = null
  let selection = null
  let selectedOutgoing = null
  let served = false
  let outgoingPhysicalChannel = null
  let outgoingLink = null
  let outgoingLinkService = null
  let incomingPhysicalChannel = initialIncomingPhysicalChannel
  let destroyed = false
  const sends = []

  if (outgoing === null) {
    authority = createTailControlResponderAuthority(tail, adjacency.responderToken, {
      tailReadySigner: createTailReadySigner(identityOwner),
      wallNow: clocks.wallNow,
      monotonicNow: clocks.monotonicNow,
      randomBytes: cryptoSuite.randomBytes,
      schedule: clocks.schedule,
      cancelScheduled: clocks.cancelScheduled
    })
  } else {
    nextAuthority = new M3AdjacencyAuthority({
      wallNow: clocks.wallNow,
      monotonicNow: clocks.monotonicNow,
      schedule: clocks.schedule,
      cancelScheduled: clocks.cancelScheduled,
      crypto: cryptoSuite
    })
    proofAuthority = createRedactedResponderProofAuthority({ now: clocks.wallNow })
    const socketOwner = Object.freeze({})
    dialAuthority = guardLinks.createRelayAdjacentDialAuthority({
      socketOwner,
      allowedRole: outgoing.allowedRole,
      async dial(owner, endpoint) {
        if (
          destroyed ||
          readyContext === null ||
          selection === null ||
          !same(endpoint, selection.reachableEndpoint) ||
          !selectedOutgoing ||
          !same(selection.relayIdentity, selectedOutgoing.peerIdentity)
        ) {
          throw PrivateRouteError.ERR_AUTHENTICATION()
        }
        const offer = guardLinks[TAKE_STAGED_OFFER](owner, endpoint)
        const decoded = decodeM3Object(offer)
        const circuitId = b4a.from(decoded.body.subarray(115, 131))
        const branchGeneration = readU64(decoded.body, 131)
        let setup = null
        try {
          const opened = await selectedOutgoing.linkService.initiate(selectedOutgoing.grant, {
            circuitId,
            generation: branchGeneration,
            responderStaticKey: selection.routeEncryptionPublicKey
          })
          outgoingLink = opened
          outgoingLinkService = selectedOutgoing.linkService
          setup = selectedOutgoing.linkService.openSetupTransport(opened)
          await setup.send(offer)
          const accept = await setup.receive()
          const proof = await setup.receive()
          const context = encodeSuccessorTailReadyContext(readyContext)
          try {
            await setup.send(context)
          } finally {
            context.fill(0)
          }
          const inbound = [accept, proof, null]
          return createExtensionResponseReceiver({
            receiveObject: () => inbound.shift(),
            takePhysicalChannel() {
              const channel = setup.takePhysicalChannel()
              outgoingPhysicalChannel = channel
              pendingSetup = setup
              setup = null
              return channel
            },
            destroy() {
              if (setup) setup.destroy()
              setup = null
            }
          })
        } catch (err) {
          if (setup) setup.destroy()
          throw err
        } finally {
          circuitId.fill(0)
          decoded.body.fill(0)
          decoded.authSuffix.fill(0)
        }
      },
      destroy() {}
    })
    adjacentFactory = guardLinks.createExtensionAdjacentLinkFactory({
      dialAuthority,
      linkOfferSigner: createLinkOfferSigner(identityOwner),
      proofVerifier: proofAuthority.verifier,
      proofConsumer: proofAuthority.consumer,
      wallNow: clocks.wallNow,
      monotonicNow: clocks.monotonicNow,
      randomBytes: cryptoSuite.randomBytes,
      schedule: clocks.schedule,
      cancelScheduled: clocks.cancelScheduled,
      destroy() {}
    })
    committer = createTailExtensionCommitter({
      enqueue(value) {
        sends.push(transport.send(value))
      },
      install(nextRuntime, expiresAt) {
        forwarding = createM3RelayForwardingFacade(adjacency.runtime, nextRuntime)
        const install = beginM3Install(adjacency.runtime, nextRuntime)
        validateM3Install(install, identityPublicKey, 128, clocks.wallNow())
        return commitM3Install(install, expiresAt, forwarding)
      },
      destroy() {}
    })
    authority = createTailControlResponderAuthority(tail, adjacency.responderToken, {
      adjacencyAdopter: adjacencyAuthority.responderAdopter(),
      extensionCommitter: committer,
      adjacentLinkFactory: adjacentFactory,
      tailReadySigner: createTailReadySigner(identityOwner),
      wallNow: clocks.wallNow,
      monotonicNow: clocks.monotonicNow,
      randomBytes: cryptoSuite.randomBytes,
      schedule: clocks.schedule,
      cancelScheduled: clocks.cancelScheduled
    })
  }

  async function serve() {
    if (destroyed || served || outgoing === null) throw PrivateRouteError.CIRCUIT_STATE()
    served = true
    const admitted = admitTailExtend(authority, await transport.receive())
    selection = readAdmittedTailSelection(authority, admitted)
    selectedOutgoing =
      typeof outgoing.resolve === 'function' ? outgoing.resolve(selection) : outgoing
    if (
      !selectedOutgoing ||
      selection.extensionIndex !== selectedOutgoing.extensionIndex ||
      !same(selection.relayIdentity, selectedOutgoing.peerIdentity) ||
      (selectedOutgoing.advertisementDigest &&
        !same(selection.advertisementDigest, selectedOutgoing.advertisementDigest))
    ) {
      clearSelection(selection)
      selection = null
      throw PrivateRouteError.ERR_AUTHENTICATION()
    }
    readyContext = createSuccessorTailReadyContext(authority, admitted)
    const completion = await openTailAdjacentLink(authority, admitted)
    completeTailExtend(authority, completion)
    await Promise.all(sends.splice(0))
    if (pendingSetup === null) throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    await pendingSetup.send(EXTENSION_INSTALLED_ACK)
    pendingSetup.finish()
    pendingSetup = null
    clearSelection(selection)
    selection = null
    selectedOutgoing = null
    return true
  }

  function importReady(encoded) {
    if (destroyed) throw PrivateRouteError.ERR_DESTROYED()
    return importSuccessorTailReadyContext(authority, encoded)
  }

  async function sendReady(capability) {
    if (destroyed) throw PrivateRouteError.ERR_DESTROYED()
    const ready = sealSuccessorTailReady(authority, capability)
    await transport.send(tailEnvelope(ready))
    ready.fill(0)
  }

  function faultIncomingPhysicalLink() {
    if (destroyed || !incomingPhysicalChannel) return false
    const channel = incomingPhysicalChannel
    incomingPhysicalChannel = null
    channel.destroy()
    return true
  }

  function faultOutgoingPhysicalLink() {
    // The M3 install replaces the taken issuer with its own transfer, so destroying
    // the issuer is a no-op. Closing the owning link session invalidates the UDX
    // record, which reports a physical loss and makes this relay emit BRANCH_DESTROY.
    if (destroyed || outgoingLink === null || outgoingLinkService === null) return false
    const link = outgoingLink
    const service = outgoingLinkService
    outgoingLink = null
    outgoingLinkService = null
    outgoingPhysicalChannel = null
    void service.faultLink(link).catch(() => {})
    return true
  }

  function destroy() {
    selectedOutgoing = null
    if (destroyed) return false
    destroyed = true
    incomingPhysicalChannel = null
    outgoingPhysicalChannel = null
    // The dialed link belongs to this circuit. Releasing it frees the grant so the
    // same adjacency can be authorized again when the branch is rebuilt.
    if (outgoingLink !== null && outgoingLinkService !== null) {
      const link = outgoingLink
      const service = outgoingLinkService
      outgoingLink = null
      outgoingLinkService = null
      void service.faultLink(link).catch(() => {})
    }
    clearSelection(selection)
    selection = null
    if (pendingSetup) {
      pendingSetup.destroy()
      pendingSetup = null
    }
    for (const attachment of attachments) {
      try {
        attachment.destroy()
      } catch {}
    }
    try {
      destroyTailControlResponderAuthority(authority)
    } catch {}
    try {
      destroyTailControlSession(tail)
    } catch {}
    try {
      adjacency.runtime.destroy()
    } catch {}
    try {
      if (adjacentFactory) guardLinks.destroyExtensionAdjacentLinkFactory(adjacentFactory)
    } catch {}
    try {
      destroyRelayIdentitySigningAuthority(identityOwner)
    } catch {}
    return true
  }

  return Object.freeze({
    authority,
    destroy,
    faultIncomingPhysicalLink,
    faultOutgoingPhysicalLink,
    get forwarding() {
      return forwarding
    },
    importReady,
    serve,
    sendReady,
    tail,
    transport
  })
}

async function acceptProjectedExtension(options) {
  const {
    accepted,
    advertisement,
    clocks,
    identityPublicKey,
    identitySecretKey,
    linkService,
    observedPredecessorEndpoint,
    outgoing = null,
    routeSecretKey
  } = options
  const opened = await accepted
  let setup = linkService.openSetupTransport(opened)
  let linkResponder = null
  let replayOwner = null
  let signingOwner = null
  let actor = null
  let incomingPhysicalChannel = null
  const adjacencyAuthority = new M3AdjacencyAuthority({
    wallNow: clocks.wallNow,
    monotonicNow: clocks.monotonicNow,
    schedule: clocks.schedule,
    cancelScheduled: clocks.cancelScheduled,
    crypto: cryptoSuite
  })
  try {
    const offer = await setup.receive()
    const inbound = [offer, null]
    const outbound = []
    const receiver = createExtensionOfferReceiver({
      observedPredecessorEndpoint,
      receiveObject: () => inbound.shift(),
      takePhysicalChannel: () => {
        incomingPhysicalChannel = setup.takePhysicalChannel()
        return incomingPhysicalChannel
      },
      sendObject: (value) => outbound.push(b4a.from(value)),
      finish: () => outbound.push(null),
      destroy() {
        if (setup) setup.destroy()
      }
    })
    signingOwner = createRelayIdentitySigningAuthority({ identitySecretKey })
    linkResponder = guardLinks.createExtensionLinkResponder({
      advertisement,
      adjacencyAdopter: adjacencyAuthority.responderAdopter(),
      extensionResponderSigner: createExtensionResponderSigner(signingOwner),
      responderRouteEncryptionSecretKey: routeSecretKey,
      wallNow: clocks.wallNow,
      monotonicNow: clocks.monotonicNow,
      schedule: clocks.schedule,
      cancelScheduled: clocks.cancelScheduled,
      offerReceiver: receiver,
      randomBytes: cryptoSuite.randomBytes
    })
    const linked = linkResponder.accept()
    for (const value of outbound) {
      if (value === null) break
      await setup.send(value)
      value.fill(0)
    }
    const encodedContext = await setup.receive()
    const installed = await setup.receive()
    if (!same(installed, EXTENSION_INSTALLED_ACK)) {
      installed.fill(0)
      encodedContext.fill(0)
      throw PrivateRouteError.ERR_AUTHENTICATION()
    }
    installed.fill(0)
    setup.finish()
    setup = null
    const moved = guardLinks.takeAcceptedExtensionAdjacencyTransfer(
      guardLinks.takeExtensionResponderAdjacency(linkResponder, linked.accepted)
    )
    replayOwner = moved.replayOwner
    actor = createTailRelayActor({
      adjacency: moved.adjacency,
      adjacencyAuthority,
      advertisement,
      identityPublicKey,
      identitySecretKey,
      clocks,
      outgoing,
      incomingPhysicalChannel,
      attachments: [
        {
          destroy() {
            if (linkResponder) linkResponder.destroy()
            linkResponder = null
            if (replayOwner) guardLinks.destroyAcceptedExtensionAdjacencyOwner(replayOwner)
            replayOwner = null
            if (signingOwner) destroyRelayIdentitySigningAuthority(signingOwner)
            signingOwner = null
          }
        }
      ]
    })
    const readyCapability = actor.importReady(encodedContext)
    encodedContext.fill(0)
    await actor.sendReady(readyCapability)
    return actor
  } catch (err) {
    if (setup) setup.destroy()
    if (actor) actor.destroy()
    if (linkResponder) linkResponder.destroy()
    if (replayOwner) guardLinks.destroyAcceptedExtensionAdjacencyOwner(replayOwner)
    if (signingOwner) destroyRelayIdentitySigningAuthority(signingOwner)
    throw err
  }
}
async function createEndpointFinalRouteActor(openHandoff, options) {
  if (
    !openHandoff ||
    !options ||
    typeof options.wallNow !== 'function' ||
    typeof options.monotonicNow !== 'function' ||
    typeof options.randomBytes !== 'function'
  ) {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  const authority = await TEST_ONLY_LIVE_ROUTE_AUTHORITY_ISSUER.open(openHandoff, {
    wallNow: options.wallNow,
    monotonicNow: options.monotonicNow,
    randomBytes: options.randomBytes
  })
  const contexts = createQueryContexts()
  const routed = new RoutedDHTIO({
    authority,
    contexts,
    now: () => Number(options.monotonicNow()),
    randomBytes(buffer) {
      const random = options.randomBytes(buffer.byteLength)
      if (!b4a.isBuffer(random) || random.byteLength !== buffer.byteLength) {
        throw PrivateRouteError.INVALID_ROUTE()
      }
      buffer.set(random)
      random.fill(0)
    }
  })
  let dht = null
  try {
    await routed.ready()
    dht = new DHT({
      outboundPolicy: 'transport-only',
      requestTransport: routed,
      requestTimeout: 3_000,
      concurrency: 1
    })
  } catch (err) {
    await routed.destroy().catch(() => {})
    throw err
  }
  let destroyed = false
  return Object.freeze({
    async immutableGet(target) {
      if (destroyed || !b4a.isBuffer(target) || target.byteLength !== 32) {
        throw PrivateRouteError.ERR_DESTROYED()
      }
      const query = dht.query(
        { target, command: COMMANDS.IMMUTABLE_GET, value: null },
        {
          transportContext: contexts.immutableGet.lookup,
          concurrency: 1,
          retries: 1
        }
      )
      for await (const response of query) {
        if (!response || !b4a.isBuffer(response.value)) continue
        const digest = cryptoSuite.hash([response.value])
        try {
          if (!same(digest, target)) throw PrivateRouteError.ERR_AUTHENTICATION()
          return Object.freeze({ value: b4a.from(response.value) })
        } finally {
          digest.fill(0)
        }
      }
      throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    },
    async destroy() {
      if (destroyed) return false
      destroyed = true
      await routed.destroy().catch(() => {})
      return true
    }
  })
}

async function activateFinalExitActor(options) {
  const {
    actor,
    advertisement,
    identityPublicKey,
    identitySecretKey,
    clocks,
    local,
    // `local` binds the DHT-exit socket. On separate hosts a DHT node observes that
    // socket at a translated address, and the reply it sends back echoes the address
    // it saw, which the reservation compares against its own local tuple
    // (lib/private/dht-exit-reservation.js:403, lib/private/dht-exit-wire.js:164).
    // So the table has to hold the observed pair while the socket still binds the
    // bound one. Omitted, they are the same address, as on one host they are.
    advertised,
    dhtSeed,
    dhtSeedId,
    exitRole,
    generation,
    initialSeedGrant,
    isolatedGrantVerifier,
    requestIsolatedGrant
  } = options
  if (
    !actor ||
    !b4a.isBuffer(advertisement) ||
    !same(identitySecretKey.subarray(32), identityPublicKey) ||
    !Number.isSafeInteger(exitRole) ||
    typeof generation !== 'bigint' ||
    typeof requestIsolatedGrant !== 'function' ||
    !numericTuple(local) ||
    (advertised !== undefined && !numericTuple(advertised))
  ) {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  // What the reservation calls its local address, which a peer's reply must echo.
  const observedLocal = advertised === undefined ? local : advertised
  const tupleDigest = digestTestIsolatedAddressTuple({
    tuple: dhtSeed,
    id: dhtSeedId,
    exitRole,
    generation
  })
  // A role process keeps at most one isolated-address grant request outstanding, so a
  // second concurrent isolated candidate has no reservation capacity right now. Report
  // that as an exhausted counter, which lets the DHT operation keep probing with the
  // candidate that did obtain a grant instead of cancelling the whole request. A later
  // candidate, such as one discovered after a branch rebuild, may request again.
  let isolatedGrantOutstanding = false
  let signingOwner = null
  let responder = null
  let table = null
  let io = null
  let decodedAdvertisement = null
  try {
    const decodedGrant = decodeTestIsolatedAddressGrant(initialSeedGrant)
    try {
      if (!same(decodedGrant.tupleDigest, tupleDigest)) {
        throw PrivateRouteError.ERR_AUTHENTICATION()
      }
    } finally {
      decodedGrant.runNonce.fill(0)
      decodedGrant.tupleDigest.fill(0)
      decodedGrant.signature.fill(0)
    }
    const grantAuthority = TEST_ONLY_DHT_EXIT_TOPOLOGY_ISSUER.referralGrant(
      initialSeedGrant,
      isolatedGrantVerifier.publicKey,
      {
        runNonce: isolatedGrantVerifier.run,
        exitRole,
        generation,
        tupleDigest,
        now: clocks.wallNow()
      }
    )
    consumeTestDhtExitReferralGrant(grantAuthority, {
      tuple: dhtSeed,
      id: dhtSeedId,
      exitRole,
      generation
    })

    const handoff = actor.tail.takeFinalExitHandoff()
    const claim = createFinalExitActivationClaim(handoff)
    const activationOwner = claimFinalExitActivation(handoff, claim)
    signingOwner = createRelayIdentitySigningAuthority({ identitySecretKey })
    const factory = createFinalExitActivationFactory({
      wallNow: clocks.wallNow,
      monotonicNow: clocks.monotonicNow,
      randomBytes: cryptoSuite.randomBytes,
      schedule: clocks.schedule,
      cancelScheduled: clocks.cancelScheduled
    })
    decodedAdvertisement = decodeRelayCapabilityAdvertisement(advertisement, {
      now: clocks.wallNow()
    })
    responder = openFinalExit(factory, {
      handoff: activationOwner,
      crypto: cryptoSuite,
      payloadParameters: decodedAdvertisement,
      readySigner: createDhtExitReadySigner(signingOwner)
    })
    const openAuthority = await driveDhtExitFinalExit(responder)
    const channel = createDhtExitReservationChannel(openAuthority)
    table = createDhtExitDestinationTableForTest(
      channel.tableIssuer,
      {
        local: observedLocal,
        configuredBootstrap: [dhtSeed],
        monotonicNow: clocks.monotonicNow,
        randomBytes: cryptoSuite.randomBytes
      },
      TEST_ONLY_DHT_EXIT_TOPOLOGY_ISSUER.create([dhtSeed])
    )
    const replies = []
    const waiters = []
    io = createDhtExitIO(consumeDhtExitReservationIOConsumer(channel.ioConsumer), {
      host: local.host,
      port: local.port,
      monotonicNow: clocks.monotonicNow,
      schedule: clocks.schedule,
      cancelScheduled: clocks.cancelScheduled,
      onReply(replyAuthority) {
        const waiter = waiters.shift()
        if (waiter) waiter(replyAuthority)
        else replies.push(replyAuthority)
      }
    })
    await waitDhtExitIOReady(io)
    const waitReply = () => {
      const ready = replies.shift()
      if (ready) return Promise.resolve(ready)
      return new Promise((resolve, reject) => {
        const timer = clocks.schedule(
          () => reject(PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()),
          LINK_DEADLINE_MS
        )
        waiters.push((value) => {
          clocks.cancelScheduled(timer)
          resolve(value)
        })
      })
    }
    const probe = reserveConfiguredBootstrapProbe(table, 0, clocks.monotonicNow() + 1_000n)
    await sendReservedExitDhtPacket(io, probe.sendAuthority)
    settleExitDhtReservation(probe.settlementAuthority, await waitReply())
    installDhtExitRoute(io, table, {
      async reserveReferralCandidate({ candidate, referralReplyAuthority, absoluteDeadline }) {
        if (isolatedGrantOutstanding) throw PrivateRouteError.COUNTER_EXHAUSTED()
        isolatedGrantOutstanding = true
        let candidateId = null
        let candidateDigest = null
        let grant = null
        let decodedGrant = null
        try {
          candidateId = deriveDhtExitPeerId(candidate)
          candidateDigest = digestTestIsolatedAddressTuple({
            tuple: candidate,
            id: candidateId,
            exitRole,
            generation: snapshotDhtExitDestinationTable(table).generation
          })
          grant = await requestIsolatedGrant(candidateDigest)
          decodedGrant = decodeTestIsolatedAddressGrant(grant)
          if (!same(decodedGrant.tupleDigest, candidateDigest)) {
            throw PrivateRouteError.ERR_AUTHENTICATION()
          }
          const authority = TEST_ONLY_DHT_EXIT_TOPOLOGY_ISSUER.referralGrant(
            grant,
            isolatedGrantVerifier.publicKey,
            {
              runNonce: isolatedGrantVerifier.run,
              exitRole,
              generation: snapshotDhtExitDestinationTable(table).generation,
              tupleDigest: candidateDigest,
              now: clocks.wallNow()
            }
          )
          return reserveTestTopologyReferralProbe(
            table,
            referralReplyAuthority,
            {
              id: candidateId,
              host: candidate.host,
              port: candidate.port
            },
            absoluteDeadline,
            authority,
            exitRole
          )
        } finally {
          isolatedGrantOutstanding = false
          if (decodedGrant) {
            decodedGrant.runNonce.fill(0)
            decodedGrant.tupleDigest.fill(0)
            decodedGrant.signature.fill(0)
          }
          if (grant) grant.fill(0)
          if (candidateDigest) candidateDigest.fill(0)
          if (candidateId) candidateId.fill(0)
        }
      }
    })
    await sendDhtExitSeeds(
      io,
      createDhtExitSeedsDeliveryAuthority(table),
      cryptoSuite.randomBytes(32),
      identitySecretKey
    )
    return Object.freeze({
      io,
      responder,
      table,
      snapshot() {
        const ioState = TEST_ONLY_DHT_EXIT_IO_STATE.snapshot(io)
        const tableState = snapshotDhtExitDestinationTable(table)
        return Object.freeze({
          activeOperations: ioState.activeOperations,
          ordinaryRequestCount: ioState.ordinaryRequestCount,
          pendingPackets: ioState.pendingPackets,
          referralProbeCount: ioState.referralProbeCount,
          tableEntryCount: tableState.destinationRefs.length
        })
      },
      async destroy() {
        await destroyDhtExitIO(io)
        destroyDhtExitDestinationTable(table)
        responder.destroy()
        destroyRelayIdentitySigningAuthority(signingOwner)
      }
    })
  } catch (err) {
    if (io) await destroyDhtExitIO(io)
    if (table) destroyDhtExitDestinationTable(table)
    if (responder) responder.destroy()
    if (signingOwner) destroyRelayIdentitySigningAuthority(signingOwner)
    throw err
  } finally {
    tupleDigest.fill(0)
    if (decodedAdvertisement) {
      decodedAdvertisement.relayIdentity.fill(0)
      decodedAdvertisement.currentDhtNodeId.fill(0)
      decodedAdvertisement.reachableEndpoint.fill(0)
      decodedAdvertisement.routeEncryptionPublicKey.fill(0)
      decodedAdvertisement.signature.fill(0)
    }
  }
}

function canonicalEndpoint(tuple) {
  return encodeCanonicalEndpoint({
    addressFamily: 4,
    addressBytes: b4a.from(tuple.host.split('.').map(Number)),
    port: tuple.port
  })
}

function createGuardProcessService(options) {
  const {
    endpoint,
    advertisement,
    candidateAdvertisements,
    endpointTuple,
    identityPublicKey,
    identitySecretKey,
    routeSecretKey,
    linkService,
    middleRoutes,
    clocks,
    onActor,
    onFailure
  } = options
  if (
    !endpoint ||
    !b4a.isBuffer(advertisement) ||
    !Array.isArray(candidateAdvertisements) ||
    !Array.isArray(middleRoutes) ||
    !same(identitySecretKey.subarray(32), identityPublicKey) ||
    !b4a.isBuffer(routeSecretKey) ||
    routeSecretKey.byteLength !== 32 ||
    typeof onActor !== 'function' ||
    typeof onFailure !== 'function'
  ) {
    throw PrivateRouteError.INVALID_ROUTE()
  }
  const caps = new CapsResponder({
    now: clocks.wallNow,
    advertisement,
    identitySecretKey,
    routeEncryptionSecretKey: routeSecretKey,
    selectAdvertisements: () => [advertisement, ...candidateAdvertisements]
  })
  const takeBootstrapAccept = require('../../../lib/private/caps-responder')[
    Symbol.for('hyperdht-private-routes/bootstrap-accept-authority-taker')
  ]
  const createBootstrapAcceptHandle =
    endpointModule[Symbol.for('hyperdht-private-routes/bootstrap-accept-handle-factory')]
  const endpointBytes = canonicalEndpoint(endpointTuple)
  const actors = new Set()
  const branchResponders = new Set()
  let authority = null
  let bootstrapSession = null
  // A resumed endpoint reconnects over a fresh bootstrap link, so the branch responder
  // is registered per established handle rather than once per guard.
  let registeredEstablished = null
  let destroyed = false

  function randomBytes(size) {
    return cryptoSuite.randomBytes(size)
  }

  function resolveMiddle(selection) {
    const route = middleRoutes.find(
      (candidate) =>
        same(candidate.peerIdentity, selection.relayIdentity) &&
        same(candidate.endpoint, selection.reachableEndpoint)
    )
    if (!route) throw PrivateRouteError.ERR_AUTHENTICATION()
    return route
  }

  function registerGuardBranches(established) {
    if (registeredEstablished === established) return
    registeredEstablished = established
    endpointModule.registerSharedGuardBranchResponder(
      established,
      Object.freeze({
        accept(exchange) {
          if (destroyed) throw PrivateRouteError.ERR_DESTROYED()
          const responder = guardLinks.createIndexZeroGuardLinkResponder({
            advertisement,
            responderIdentitySecretKey: identitySecretKey,
            responderRouteEncryptionSecretKey: routeSecretKey,
            now: clocks.wallNow,
            receiveOffer: () =>
              Object.freeze({
                offer: exchange.offer,
                observedPredecessorEndpoint: endpointBytes,
                physicalChannel: exchange.physicalChannel
              }),
            randomBytes
          })
          branchResponders.add(responder)
          const accepted = responder.accept()
          const adjacencyAuthority = new M3AdjacencyAuthority({
            wallNow: clocks.wallNow,
            monotonicNow: clocks.monotonicNow,
            schedule: clocks.schedule,
            cancelScheduled: clocks.cancelScheduled,
            crypto: cryptoSuite
          })
          const adjacency = adjacencyAuthority.adopt(accepted.established)
          const actor = createTailRelayActor({
            adjacency,
            adjacencyAuthority,
            advertisement,
            identityPublicKey,
            identitySecretKey,
            clocks,
            outgoing: {
              allowedRole: ROLE.SAFETY,
              resolve: resolveMiddle
            },
            attachments: [
              {
                destroy() {
                  branchResponders.delete(responder)
                  responder.destroy()
                }
              }
            ]
          })
          actors.add(actor)
          onActor(actor)
          // Destroying just this actor releases the grant for its dialed middle, so a
          // rebuilt branch can authorize that adjacency again while the guard's other
          // branches stay live.
          void actor.serve().catch((err) => {
            actors.delete(actor)
            try {
              actor.destroy()
            } catch {}
            onFailure(err)
          })
          return accepted.accept
        }
      })
    )
  }

  async function start() {
    if (destroyed || authority) throw PrivateRouteError.CIRCUIT_STATE()
    const deadline = numberNow(clocks.monotonicNow) + 30_000
    authority = endpointModule.createBootstrapUdxAuthority({
      endpoint,
      configuredEndpoints: [endpointTuple],
      localSecretCapability: endpointModule.createLocalIdentitySecretCapability({
        localIdentity: identityPublicKey,
        localSecretKey: identitySecretKey
      }),
      maxProspectiveGuards: 1,
      monotonicDeadline: deadline
    })
    endpointModule.bindBootstrapUdxOperation(
      authority,
      deadline,
      Object.freeze({}),
      clocks.monotonicNow,
      clocks.monotonicNow()
    )
    return true
  }

  async function receiveBootstrap(packet) {
    if (destroyed) return false
    if (packet[0] === 0xd3 && packet[1] === 0x01) {
      const bytes = (packet[2] << 8) | packet[3]
      const decoded = decodeM3Object(packet.subarray(4, 4 + bytes))
      const responses = caps.receive(packet, endpointBytes)
      if (decoded.messageId === 4) {
        const handle = createBootstrapAcceptHandle(takeBootstrapAccept(caps))
        const monotonic = numberNow(clocks.monotonicNow)
        bootstrapSession = endpoint.openLink(handle, {
          mode: 'accept',
          codec: new BootstrapEnvelopeCodec({
            linkHandle: handle,
            localIdentitySecretKey: identitySecretKey,
            padding: randomBytes
          }),
          linkSetup: createLinkSetupAuthority({
            now: () => numberNow(clocks.wallNow),
            randomBytes
          }),
          setup: createDynamicResponderSetup({
            responderStaticSecretKey: routeSecretKey,
            responderIdentitySecretKey: identitySecretKey
          }),
          now: () => numberNow(clocks.monotonicNow),
          schedule: clocks.schedule,
          cancel: clocks.cancelScheduled,
          randomBytes,
          absoluteDeadline: monotonic + 30_000,
          signedExpiry: numberNow(clocks.wallNow) + 60_000,
          authorizedExpiry: numberNow(clocks.wallNow) + 60_000
        })
      }
      decoded.body.fill(0)
      decoded.authSuffix.fill(0)
      for (const response of responses) {
        await endpointModule.sendConfigured(authority, 0, response)
        response.fill(0)
      }
      return true
    }
    if (bootstrapSession && !bootstrapSession.established) {
      const result = await bootstrapSession.receive(packet)
      if (bootstrapSession.established) registerGuardBranches(bootstrapSession.established)
      return result
    }
    return linkService.receiveBootstrap(packet)
  }

  function receiveCell(packet, handle, metadata) {
    return linkService.receiveCell(packet, handle, metadata)
  }

  function receiveLinkFailure(handle, direction, reason) {
    linkService.receiveLinkFailure(handle, direction, reason)
    onFailure(PrivateRouteError.ERR_PRIVACY_UNAVAILABLE())
  }

  async function destroy() {
    if (destroyed) return false
    destroyed = true
    for (const actor of actors) actor.destroy()
    actors.clear()
    for (const responder of branchResponders) responder.destroy()
    branchResponders.clear()
    caps.destroy()
    if (bootstrapSession) await bootstrapSession.close().catch(() => {})
    bootstrapSession = null
    if (authority) endpointModule.destroyBootstrapUdxAuthority(authority)
    authority = null
    endpointBytes.fill(0)
    return true
  }

  return Object.freeze({
    destroy,
    receiveBootstrap,
    receiveCell,
    receiveLinkFailure,
    start
  })
}

module.exports = Object.freeze({
  acceptProjectedExtension,
  activateFinalExitActor,
  blackholeRouteCells,
  createEndpointFinalRouteActor,
  createGuardProcessService,
  createProjectedCellEndpoint,
  createProjectedLinkService,
  createTailRelayActor
})
