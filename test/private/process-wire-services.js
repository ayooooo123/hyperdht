'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  LINK_OPERATION,
  PROTOCOL_VERSION,
  ROLE,
  TOPOLOGY_ROLE,
  roleForIdentity
} = require('../../lib/private/protocol')
const { signTopologyGrant } = require('../../lib/private/topology-grant')
const { UdxCellEndpoint } = require('../../lib/private/udx-cell-endpoint')
const { createProjectedLinkService } = require('./process/wire-services')

const HOST = '127.0.0.1'
let nextPort = 49_600

function identityFor(role, value) {
  for (let index = value; index < value + 512; index++) {
    const pair = cryptoSuite.keyPair(b4a.alloc(32, index & 0xff))
    if (roleForIdentity(pair.publicKey) === role) return pair
    pair.secretKey.fill(0)
    pair.publicKey.fill(0)
  }
  throw new Error('identity role unavailable')
}

function grantFixture() {
  const left = identityFor(ROLE.SAFETY, 0x11)
  const right = identityFor(ROLE.PRIVATE, 0x71)
  const authority = cryptoSuite.keyPair(b4a.alloc(32, 0xa1))
  const route = cryptoSuite.encryptionKeyPair(b4a.alloc(32, 0xa2))
  const runId32 = b4a.alloc(32, 0xa3)
  const leftPort = nextPort++
  const rightPort = nextPort++
  const grant = signTopologyGrant(
    {
      version: PROTOCOL_VERSION,
      format: 0,
      grantId32: b4a.alloc(32, 0xa4),
      endpointA: {
        identity32: left.publicKey,
        role: TOPOLOGY_ROLE.SAFETY_FINAL,
        host: HOST,
        port: leftPort,
        operations: LINK_OPERATION.KNOWN
      },
      endpointB: {
        identity32: right.publicKey,
        role: TOPOLOGY_ROLE.PRIVATE_ENTRY,
        host: HOST,
        port: rightPort,
        operations: LINK_OPERATION.KNOWN
      },
      epoch: 1n,
      notBefore: 0n,
      expiresAt: 60_000n,
      runId32
    },
    authority.secretKey
  )
  return { authority, grant, left, leftPort, right, rightPort, route, runId32 }
}

function endpoint(host, port, dispatch) {
  return new UdxCellEndpoint({
    host,
    port,
    onBootstrap: (packet, handle) => dispatch.bootstrap(packet, handle),
    onCell: (packet, handle, metadata) => dispatch.cell(packet, handle, metadata),
    onLinkFailure: (handle, direction, reason) => dispatch.failure(handle, direction, reason)
  })
}

test('projected link service opens exact signed UDX adjacency on native loopback', async (t) => {
  const fixture = grantFixture()
  const leftDispatch = {}
  const rightDispatch = {}
  const leftEndpoint = endpoint(HOST, fixture.leftPort, leftDispatch)
  const rightEndpoint = endpoint(HOST, fixture.rightPort, rightDispatch)
  const clock = {
    wallNow: () => 1_000n,
    monotonicNow: () => 1_000n,
    schedule: setTimeout,
    cancelScheduled: clearTimeout
  }
  const left = createProjectedLinkService({
    ...clock,
    endpoint: leftEndpoint,
    authorityPublicKey: fixture.authority.publicKey,
    epoch: 1n,
    localIdentity: fixture.left.publicKey,
    localIdentitySecretKey: fixture.left.secretKey,
    localRouteSecretKey: null,
    runId32: fixture.runId32
  })
  const right = createProjectedLinkService({
    ...clock,
    endpoint: rightEndpoint,
    authorityPublicKey: fixture.authority.publicKey,
    epoch: 1n,
    localIdentity: fixture.right.publicKey,
    localIdentitySecretKey: fixture.right.secretKey,
    localRouteSecretKey: fixture.route.secretKey,
    runId32: fixture.runId32
  })
  leftDispatch.bootstrap = left.receiveBootstrap
  leftDispatch.cell = left.receiveCell
  leftDispatch.failure = left.receiveLinkFailure
  rightDispatch.bootstrap = right.receiveBootstrap
  rightDispatch.cell = right.receiveCell
  rightDispatch.failure = right.receiveLinkFailure

  try {
    await Promise.all([leftEndpoint.bind(), rightEndpoint.bind()])
    const accepted = right.prearmAccept(fixture.grant)
    const opened = await left.initiate(fixture.grant, {
      circuitId: b4a.alloc(16, 0xb1),
      generation: 1n,
      responderStaticKey: fixture.route.publicKey
    })
    const responder = await accepted
    t.ok(opened.established, 'initiator owns authenticated established handle')
    t.ok(responder.established, 'responder owns authenticated established handle')
    t.is(left.snapshot().openLinks, 1)
    t.is(right.snapshot().openLinks, 1)
    const leftSetup = left.openSetupTransport(opened)
    const rightSetup = right.openSetupTransport(responder)
    const offer = b4a.alloc(313, 0xc1)
    const response = b4a.alloc(427, 0xc2)
    await leftSetup.send(offer)
    t.alike(await rightSetup.receive(), offer, 'extension offer crosses authenticated UDX stream')
    await rightSetup.send(response)
    t.alike(
      await leftSetup.receive(),
      response,
      'extension response crosses authenticated UDX stream'
    )
    t.ok(leftSetup.takePhysicalChannel(), 'initiator transfers the exact established link')
    t.ok(rightSetup.takePhysicalChannel(), 'responder transfers the exact established link')
    t.ok(leftSetup.finish(), 'initiator setup transport relinquishes setup ownership')
    t.ok(rightSetup.finish(), 'responder setup transport relinquishes setup ownership')
    await t.exception(
      left.initiate(fixture.grant, {
        circuitId: b4a.alloc(16, 0xb2),
        generation: 2n,
        responderStaticKey: fixture.route.publicKey
      }),
      'signed grant handle is one-shot'
    )
  } finally {
    await Promise.allSettled([left.destroy(), right.destroy()])
    await Promise.allSettled([leftEndpoint.close(), rightEndpoint.close()])
  }
})

function multiGrantFixture() {
  const authority = cryptoSuite.keyPair(b4a.alloc(32, 0xd1))
  const route = cryptoSuite.encryptionKeyPair(b4a.alloc(32, 0xd2))
  const runId32 = b4a.alloc(32, 0xd3)
  const right = identityFor(ROLE.PRIVATE, 0x20)
  const rightPort = nextPort++
  const lefts = [0x10, 0x50, 0x90, 0xd0].map((seed, index) => {
    const identity = identityFor(ROLE.SAFETY, seed)
    const port = nextPort++
    const grant = signTopologyGrant(
      {
        version: PROTOCOL_VERSION,
        format: 0,
        grantId32: b4a.alloc(32, 0xe0 + index),
        endpointA: {
          identity32: identity.publicKey,
          role: TOPOLOGY_ROLE.SAFETY_FINAL,
          host: HOST,
          port,
          operations: LINK_OPERATION.KNOWN
        },
        endpointB: {
          identity32: right.publicKey,
          role: TOPOLOGY_ROLE.PRIVATE_ENTRY,
          host: HOST,
          port: rightPort,
          operations: LINK_OPERATION.KNOWN
        },
        epoch: 1n,
        notBefore: 0n,
        expiresAt: 60_000n,
        runId32
      },
      authority.secretKey
    )
    return { grant, identity, port }
  })
  return { authority, lefts, right, rightPort, route, runId32 }
}

test('multi-grant accept is fail-closed and releases every losing owner exactly once', async (t) => {
  const fixture = multiGrantFixture()
  const clock = {
    wallNow: () => 1_000n,
    monotonicNow: () => 1_000n,
    schedule: setTimeout,
    cancelScheduled: clearTimeout
  }
  const rightDispatch = {}
  const rightEndpoint = endpoint(HOST, fixture.rightPort, rightDispatch)
  const right = createProjectedLinkService({
    ...clock,
    endpoint: rightEndpoint,
    authorityPublicKey: fixture.authority.publicKey,
    epoch: 1n,
    localIdentity: fixture.right.publicKey,
    localIdentitySecretKey: fixture.right.secretKey,
    localRouteSecretKey: fixture.route.secretKey,
    runId32: fixture.runId32
  })
  const leftOwners = fixture.lefts.map((entry) => {
    const dispatch = {}
    const ownerEndpoint = endpoint(HOST, entry.port, dispatch)
    const service = createProjectedLinkService({
      ...clock,
      endpoint: ownerEndpoint,
      authorityPublicKey: fixture.authority.publicKey,
      epoch: 1n,
      localIdentity: entry.identity.publicKey,
      localIdentitySecretKey: entry.identity.secretKey,
      localRouteSecretKey: null,
      runId32: fixture.runId32
    })
    dispatch.bootstrap = service.receiveBootstrap
    dispatch.cell = service.receiveCell
    dispatch.failure = service.receiveLinkFailure
    return { endpoint: ownerEndpoint, service }
  })
  const captured = []
  let captureResolve = null
  const nextCaptured = () => {
    if (captured.length > 0) return Promise.resolve(captured.shift())
    return new Promise((resolve) => {
      captureResolve = resolve
    })
  }
  rightDispatch.bootstrap = (packet, handle) => {
    const value = { handle, packet: b4a.from(packet) }
    if (captureResolve === null) captured.push(value)
    else {
      const resolve = captureResolve
      captureResolve = null
      resolve(value)
    }
    return true
  }
  rightDispatch.cell = right.receiveCell
  rightDispatch.failure = right.receiveLinkFailure

  try {
    await Promise.all([rightEndpoint.bind(), ...leftOwners.map((owner) => owner.endpoint.bind())])
    const grants = fixture.lefts.slice(0, 3).map((entry) => entry.grant)
    const accepted = right.prearmAcceptAny(grants)
    t.alike(right.snapshot(), { openLinks: 0, pending: 1 }, 'three arms have one atomic owner')
    await t.exception(right.prearmAcceptAny(grants), 'a pending grant cannot be replayed')
    t.is(right.snapshot().pending, 1, 'replay does not consume any pending alternative')

    const sourceAWaiting = nextCaptured()
    const sourceAOpening = leftOwners[0].service.initiate(fixture.lefts[0].grant, {
      circuitId: b4a.alloc(16, 0xf1),
      generation: 1n,
      responderStaticKey: fixture.route.publicKey
    })
    const sourceA = await sourceAWaiting
    const sourceBWaiting = nextCaptured()
    const winnerOpening = leftOwners[1].service.initiate(fixture.lefts[1].grant, {
      circuitId: b4a.alloc(16, 0xf2),
      generation: 1n,
      responderStaticKey: fixture.route.publicKey
    })
    const sourceB = await sourceBWaiting
    t.is(
      await right.receiveBootstrap(sourceB.packet, sourceA.handle),
      false,
      'valid B envelope delivered through armed A handle is rejected'
    )
    t.is(right.snapshot().pending, 1, 'cross-arm packet consumes neither grant')
    const delivered = right.receiveBootstrap(sourceB.packet, sourceB.handle)
    const [winner, opened] = await Promise.all([accepted, winnerOpening])
    t.ok(await delivered, 'same B envelope establishes through the B handle')
    t.is(winner.grantIndex, 1, 'the matching middle wins independent of grant order')
    t.ok(winner.link.established)
    t.ok(opened.established)
    await leftOwners[0].service.faultPhysicalLink()
    await t.exception(sourceAOpening, 'losing A source receives no acceptance')
    sourceA.packet.fill(0)
    sourceB.packet.fill(0)
    t.alike(right.snapshot(), { openLinks: 1, pending: 0 })
    await t.exception(
      right.prearmAcceptAny([fixture.lefts[1].grant]),
      'winning grant remains replay-protected while its link is live'
    )

    const pendingAlternatives = right.prearmAcceptAny([
      fixture.lefts[0].grant,
      fixture.lefts[2].grant
    ])
    t.is(
      right.snapshot().pending,
      1,
      'both losing grants were revoked and can be rearmed after winner cleanup'
    )
    t.is(await right.destroy(), true)
    await t.exception(pendingAlternatives, 'destroy rejects the shared pending owner')
    t.alike(right.snapshot(), { openLinks: 0, pending: 0 }, 'destroy releases all arms and winner')
    t.is(await right.destroy(), false, 'destroy cleanup is exactly once')
  } finally {
    await Promise.allSettled(leftOwners.map((owner) => owner.service.destroy()))
    await Promise.allSettled([
      right.destroy(),
      rightEndpoint.close(),
      ...leftOwners.map((owner) => owner.endpoint.close())
    ])
  }
})

for (const teardownKind of ['destroy', 'fault']) {
  test(`${teardownKind} during multi-accept loser close rejects the resolving owner`, async (t) => {
    const fixture = multiGrantFixture()
    const clock = {
      wallNow: () => 1_000n,
      monotonicNow: () => 1_000n,
      schedule: setTimeout,
      cancelScheduled: clearTimeout
    }
    const rightDispatch = {}
    const leftDispatch = {}
    const rightEndpoint = endpoint(HOST, fixture.rightPort, rightDispatch)
    const leftEndpoint = endpoint(HOST, fixture.lefts[1].port, leftDispatch)
    const originalOpenLink = rightEndpoint.openLink.bind(rightEndpoint)
    const closeCalls = []
    let releaseLoser
    const loserReleased = new Promise((resolve) => {
      releaseLoser = resolve
    })
    let markLoserClosing
    const loserClosing = new Promise((resolve) => {
      markLoserClosing = resolve
    })
    rightEndpoint.openLink = (handle, options) => {
      const session = originalOpenLink(handle, options)
      const index = closeCalls.length
      closeCalls.push(0)
      const originalClose = session.close.bind(session)
      let closing = null
      session.close = () => {
        if (closing !== null) return closing
        closeCalls[index]++
        if (index === 0) {
          markLoserClosing()
          closing = loserReleased.then(() => originalClose())
        } else {
          closing = originalClose()
        }
        return closing
      }
      return session
    }
    const createRight = () =>
      createProjectedLinkService({
        ...clock,
        endpoint: rightEndpoint,
        authorityPublicKey: fixture.authority.publicKey,
        epoch: 1n,
        localIdentity: fixture.right.publicKey,
        localIdentitySecretKey: fixture.right.secretKey,
        localRouteSecretKey: fixture.route.secretKey,
        runId32: fixture.runId32
      })
    const right = createRight()
    const left = createProjectedLinkService({
      ...clock,
      endpoint: leftEndpoint,
      authorityPublicKey: fixture.authority.publicKey,
      epoch: 1n,
      localIdentity: fixture.lefts[1].identity.publicKey,
      localIdentitySecretKey: fixture.lefts[1].identity.secretKey,
      localRouteSecretKey: null,
      runId32: fixture.runId32
    })
    rightDispatch.bootstrap = right.receiveBootstrap
    rightDispatch.cell = right.receiveCell
    rightDispatch.failure = right.receiveLinkFailure
    leftDispatch.bootstrap = left.receiveBootstrap
    leftDispatch.cell = left.receiveCell
    leftDispatch.failure = left.receiveLinkFailure

    try {
      await Promise.all([rightEndpoint.bind(), leftEndpoint.bind()])
      const grants = fixture.lefts.slice(0, 2).map((entry) => entry.grant)
      const accepted = right.prearmAcceptAny(grants)
      let acceptedResolved = false
      void accepted.then(
        () => {
          acceptedResolved = true
        },
        () => {}
      )
      const opening = left.initiate(fixture.lefts[1].grant, {
        circuitId: b4a.alloc(16, 0xf3),
        generation: 1n,
        responderStaticKey: fixture.route.publicKey
      })
      await loserClosing
      const ending = teardownKind === 'destroy' ? right.destroy() : right.faultPhysicalLink()
      await t.exception(
        Promise.resolve().then(() => right.prearmAcceptAny(grants)),
        'teardown lock rejects acquisition after the close snapshot'
      )
      let destroyOverlap = null
      let destroySettled = false
      if (teardownKind === 'fault') {
        destroyOverlap = right.destroy()
        void destroyOverlap.then(() => {
          destroySettled = true
        })
      }
      await Promise.resolve()
      t.is(acceptedResolved, false, 'accept owner stays unresolved during loser cleanup')
      if (destroyOverlap !== null)
        t.is(destroySettled, false, 'destroy joins the in-flight fault cleanup')
      releaseLoser()
      t.is(await ending, true)
      if (destroyOverlap !== null) t.is(await destroyOverlap, true)
      await t.exception(accepted, `${teardownKind} wins before accept resolution`)
      await Promise.allSettled([opening])
      t.alike(right.snapshot(), { openLinks: 0, pending: 0 })
      t.alike(closeCalls.slice(0, 2), [1, 1], 'loser and winner sessions close exactly once')

      const replacement = createRight()
      const rearmed = replacement.prearmAcceptAny(grants)
      t.is(replacement.snapshot().pending, 1, 'all grants are released for exact rearm')
      await replacement.faultPhysicalLink()
      await t.exception(rearmed, 'rearmed owner is released on cleanup')
      await replacement.destroy()
    } finally {
      releaseLoser()
      await Promise.allSettled([left.destroy(), right.destroy()])
      await Promise.allSettled([leftEndpoint.close(), rightEndpoint.close()])
    }
  })
}
