const b4a = require('b4a')
const test = require('brittle')

const {
  createExtensionOfferReceiver,
  createExtensionResponseReceiver,
  finishExtensionResponse,
  sendExtensionAccept,
  sendExtensionProof,
  takeExtensionOffer,
  takeExtensionResponse
} = require('../../lib/private/extension-setup-channel')
const { LINK_ACCEPT_SIZE, LINK_OFFER_SIZE } = require('../../lib/private/guard-link')
const { REDACTED_RESPONDER_PROOF_SIZE } = require('../../lib/private/redacted-responder-proof')
const { encodeCanonicalEndpoint } = require('../../lib/private/relay-capability')

function bytes(size, byte) {
  return b4a.alloc(size, byte)
}

function endpoint(last = 1) {
  return encodeCanonicalEndpoint({
    addressFamily: 4,
    addressBytes: b4a.from([192, 0, 2, last]),
    port: 44_000 + last
  })
}

function expectCode(t, operation, code, message) {
  let error = null
  try {
    operation()
  } catch (err) {
    error = err
  }
  t.is(error && error.code, code, message)
}

test('extension offer receiver binds one OFFER, peer endpoint, writer, and physical channel', (t) => {
  const offer = bytes(LINK_OFFER_SIZE, 0x11)
  const accept = bytes(LINK_ACCEPT_SIZE, 0x12)
  const proof = bytes(REDACTED_RESPONDER_PROOF_SIZE, 0x13)
  const inbound = [offer, null]
  const outbound = []
  const physicalChannel = Object.freeze({ destroy() {} })
  let transferred = false
  let finished = 0
  let destroyed = 0
  const receiver = createExtensionOfferReceiver({
    observedPredecessorEndpoint: endpoint(),
    receiveObject: () => inbound.shift(),
    takePhysicalChannel() {
      if (transferred) return null
      transferred = true
      return physicalChannel
    },
    sendObject: (object) => outbound.push(object),
    finish: () => finished++,
    destroy: () => destroyed++
  })

  const received = takeExtensionOffer(receiver)
  t.alike(received.offer, offer)
  t.alike(received.observedPredecessorEndpoint, endpoint())
  t.is(received.physicalChannel, physicalChannel)
  t.ok(Object.isFrozen(received.responseWriter))
  t.alike(Object.keys(received.responseWriter), [])
  expectCode(t, () => sendExtensionProof(received.responseWriter, proof), 'ERR_REPLAY')
  sendExtensionAccept(received.responseWriter, accept)
  expectCode(t, () => finishExtensionResponse(received.responseWriter), 'ERR_REPLAY')
  sendExtensionProof(received.responseWriter, proof)
  finishExtensionResponse(received.responseWriter)
  t.alike(outbound, [accept, proof])
  t.is(finished, 1)
  t.is(destroyed, 0)
  expectCode(t, () => takeExtensionOffer(receiver), 'ERR_REPLAY')
  expectCode(t, () => sendExtensionAccept(received.responseWriter, accept), 'ERR_REPLAY')
})

test('extension offer receiver rejects a second initiator object before channel transfer', (t) => {
  const inbound = [bytes(LINK_OFFER_SIZE, 0x21), bytes(1, 0x22)]
  let transferred = 0
  let destroyed = 0
  const receiver = createExtensionOfferReceiver({
    observedPredecessorEndpoint: endpoint(2),
    receiveObject: () => inbound.shift(),
    takePhysicalChannel() {
      transferred++
      return Object.freeze({ destroy() {} })
    },
    sendObject() {},
    finish() {},
    destroy: () => destroyed++
  })

  expectCode(t, () => takeExtensionOffer(receiver), 'INVALID_ROUTE')
  t.is(transferred, 0)
  t.is(destroyed, 1)
  expectCode(t, () => takeExtensionOffer(receiver), 'ERR_REPLAY')
})

test('extension offer receiver retains ownership when channel transfer returns a truthy malformed candidate', (t) => {
  const observedPredecessorEndpoint = endpoint(3)
  const inbound = [bytes(LINK_OFFER_SIZE, 0x23), null]
  const malformedCandidate = Object.freeze({ destroy: null })
  const originalAlloc = b4a.allocUnsafeSlow
  let ownedPredecessorEndpoint = null
  let destroyed = 0
  let receiver = null

  try {
    b4a.allocUnsafeSlow = (size) => {
      const value = originalAlloc(size)
      if (size === observedPredecessorEndpoint.byteLength) ownedPredecessorEndpoint = value
      return value
    }
    receiver = createExtensionOfferReceiver({
      observedPredecessorEndpoint,
      receiveObject: () => inbound.shift(),
      takePhysicalChannel: () => malformedCandidate,
      sendObject() {},
      finish() {},
      destroy: () => destroyed++
    })
  } finally {
    b4a.allocUnsafeSlow = originalAlloc
  }

  expectCode(t, () => takeExtensionOffer(receiver), 'INVALID_ROUTE')
  t.is(destroyed, 1, 'destroys the setup receiver rather than the malformed candidate')
  t.alike(
    ownedPredecessorEndpoint,
    b4a.alloc(ownedPredecessorEndpoint.byteLength),
    'clears the owned predecessor endpoint'
  )
})

test('extension offer receiver destroys a valid channel on each later non-transfer failure', (t) => {
  for (const failurePosition of [1, 2]) {
    const inbound = [bytes(LINK_OFFER_SIZE, 0x24 + failurePosition), null]
    let channelDestroyed = 0
    let receiverDestroyed = 0
    const physicalChannel = Object.freeze({
      destroy: () => channelDestroyed++
    })
    const receiver = createExtensionOfferReceiver({
      observedPredecessorEndpoint: endpoint(3 + failurePosition),
      receiveObject: () => inbound.shift(),
      takePhysicalChannel: () => physicalChannel,
      sendObject() {},
      finish() {},
      destroy: () => receiverDestroyed++
    })
    const freeze = Object.freeze
    let freezes = 0
    let responseWriter = null

    expectCode(
      t,
      () => {
        try {
          Object.freeze = (value) => {
            if (++freezes === failurePosition) throw new Error('result freeze failed')
            const result = freeze(value)
            if (freezes === 1) responseWriter = result
            return result
          }
          takeExtensionOffer(receiver)
        } finally {
          Object.freeze = freeze
        }
      },
      'INVALID_ROUTE',
      `freeze ${failurePosition}`
    )
    t.is(channelDestroyed, 1, `freeze ${failurePosition} destroys the valid taken channel`)
    t.is(receiverDestroyed, 0, `freeze ${failurePosition} leaves receiver cleanup transferred`)
    if (responseWriter) {
      expectCode(
        t,
        () => sendExtensionAccept(responseWriter, bytes(LINK_ACCEPT_SIZE, 0x27)),
        'ERR_REPLAY',
        'cleans up the untransferred response writer'
      )
    }
  }
})

test('extension offer receiver invokes the accessor-validated channel destructor without redispatch', (t) => {
  const inbound = [bytes(LINK_OFFER_SIZE, 0x28), null]
  const physicalChannel = {}
  let destroyReads = 0
  let channelDestroyed = 0
  let destroyThis = null
  let receiverDestroyed = 0
  Object.defineProperty(physicalChannel, 'destroy', {
    get() {
      destroyReads++
      if (destroyReads !== 1) return null
      return function () {
        channelDestroyed++
        destroyThis = this
      }
    }
  })
  const receiver = createExtensionOfferReceiver({
    observedPredecessorEndpoint: endpoint(6),
    receiveObject: () => inbound.shift(),
    takePhysicalChannel: () => physicalChannel,
    sendObject() {},
    finish() {},
    destroy: () => receiverDestroyed++
  })
  const freeze = Object.freeze

  expectCode(
    t,
    () => {
      try {
        Object.freeze = () => {
          throw new Error('result freeze failed')
        }
        takeExtensionOffer(receiver)
      } finally {
        Object.freeze = freeze
      }
    },
    'INVALID_ROUTE'
  )
  t.is(channelDestroyed, 1, 'invokes the originally validated destructor once')
  t.is(destroyThis, physicalChannel, 'invokes the destructor with the channel as receiver')
  t.is(destroyReads, 1, 'does not redispatch the destroy property')
  t.is(receiverDestroyed, 0, 'does not also destroy the setup receiver')
})

test('extension response receiver invokes the accessor-validated channel destructor without redispatch', (t) => {
  const inbound = [bytes(LINK_ACCEPT_SIZE, 0x37), bytes(REDACTED_RESPONDER_PROOF_SIZE, 0x38), null]
  const physicalChannel = {}
  let destroyReads = 0
  let channelDestroyed = 0
  let destroyThis = null
  let receiverDestroyed = 0
  Object.defineProperty(physicalChannel, 'destroy', {
    get() {
      destroyReads++
      if (destroyReads !== 1) return null
      return function () {
        channelDestroyed++
        destroyThis = this
      }
    }
  })
  const receiver = createExtensionResponseReceiver({
    receiveObject: () => inbound.shift(),
    takePhysicalChannel: () => physicalChannel,
    destroy: () => receiverDestroyed++
  })
  const freeze = Object.freeze

  expectCode(
    t,
    () => {
      try {
        Object.freeze = () => {
          throw new Error('result freeze failed')
        }
        takeExtensionResponse(receiver)
      } finally {
        Object.freeze = freeze
      }
    },
    'INVALID_ROUTE'
  )
  t.is(channelDestroyed, 1, 'invokes the originally validated destructor once')
  t.is(destroyThis, physicalChannel, 'invokes the destructor with the channel as receiver')
  t.is(destroyReads, 1, 'does not redispatch the destroy property')
  t.is(receiverDestroyed, 0, 'does not also destroy the setup receiver')
})

test('extension response receiver transfers only exact ACCEPT then PROOF and no fourth object', (t) => {
  const accept = bytes(LINK_ACCEPT_SIZE, 0x31)
  const proof = bytes(REDACTED_RESPONDER_PROOF_SIZE, 0x32)
  const physicalChannel = Object.freeze({ destroy() {} })
  const inbound = [accept, proof, null]
  let transferred = false
  let destroyed = 0
  const receiver = createExtensionResponseReceiver({
    receiveObject: () => inbound.shift(),
    takePhysicalChannel() {
      if (transferred) return null
      transferred = true
      return physicalChannel
    },
    destroy: () => destroyed++
  })

  const received = takeExtensionResponse(receiver)
  t.alike(received.accept, accept)
  t.alike(received.proof, proof)
  t.is(received.physicalChannel, physicalChannel)
  t.is(destroyed, 0)
  expectCode(t, () => takeExtensionResponse(receiver), 'ERR_REPLAY')
})

test('extension response receiver retains ownership when channel transfer returns a truthy malformed candidate', (t) => {
  const inbound = [bytes(LINK_ACCEPT_SIZE, 0x33), bytes(REDACTED_RESPONDER_PROOF_SIZE, 0x34), null]
  const malformedCandidate = Object.freeze({ destroy: null })
  let destroyed = 0
  const receiver = createExtensionResponseReceiver({
    receiveObject: () => inbound.shift(),
    takePhysicalChannel: () => malformedCandidate,
    destroy: () => destroyed++
  })

  expectCode(t, () => takeExtensionResponse(receiver), 'INVALID_ROUTE')
  t.is(destroyed, 1, 'destroys the setup receiver rather than the malformed candidate')
})

test('extension response receiver destroys a valid channel on a later non-transfer failure', (t) => {
  const inbound = [bytes(LINK_ACCEPT_SIZE, 0x35), bytes(REDACTED_RESPONDER_PROOF_SIZE, 0x36), null]
  let channelDestroyed = 0
  let receiverDestroyed = 0
  const physicalChannel = Object.freeze({
    destroy: () => channelDestroyed++
  })
  const receiver = createExtensionResponseReceiver({
    receiveObject: () => inbound.shift(),
    takePhysicalChannel: () => physicalChannel,
    destroy: () => receiverDestroyed++
  })
  const freeze = Object.freeze

  try {
    Object.freeze = () => {
      throw new Error('result freeze failed')
    }
    expectCode(t, () => takeExtensionResponse(receiver), 'INVALID_ROUTE')
  } finally {
    Object.freeze = freeze
  }

  t.is(channelDestroyed, 1, 'destroys the valid taken channel')
  t.is(receiverDestroyed, 0, 'does not destroy the receiver after channel ownership transfers')
})

test('extension response receiver erases partial state and rejects malformed order or trailing objects', (t) => {
  for (const [name, inbound] of [
    [
      'reordered',
      [bytes(REDACTED_RESPONDER_PROOF_SIZE, 0x41), bytes(LINK_ACCEPT_SIZE, 0x42), null]
    ],
    ['malformed proof', [bytes(LINK_ACCEPT_SIZE, 0x43), bytes(1, 0x44), null]],
    [
      'fourth object',
      [bytes(LINK_ACCEPT_SIZE, 0x45), bytes(REDACTED_RESPONDER_PROOF_SIZE, 0x46), bytes(1, 0x47)]
    ]
  ]) {
    let transferred = 0
    let destroyed = 0
    const receiver = createExtensionResponseReceiver({
      receiveObject: () => inbound.shift(),
      takePhysicalChannel() {
        transferred++
        return Object.freeze({ destroy() {} })
      },
      destroy: () => destroyed++
    })
    expectCode(t, () => takeExtensionResponse(receiver), 'INVALID_ROUTE', name)
    t.is(transferred, 0, `${name} does not transfer the channel`)
    t.is(destroyed, 1, `${name} destroys the setup receiver`)
  }
})
