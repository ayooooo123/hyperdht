'use strict'

const test = require('brittle')
const UDX = require('udx-native')
const dgram = require('node:dgram')
const installDelay = require('./delay')
const { deadline } = require('./protocol')

function event(emitter, name) {
  return new Promise((resolve) => emitter.once(name, resolve))
}

function pair() {
  const udx = new UDX()
  const sockets = [udx.createSocket(), udx.createSocket()]
  for (const socket of sockets) socket.bind(0, '127.0.0.1')
  const streams = [udx.createStream(1), udx.createStream(2)]
  const closed = streams.map((stream) => {
    stream.on('error', () => {})
    return event(stream, 'close')
  })
  streams[0].connect(sockets[0], 2, sockets[1].address().port, '127.0.0.1')
  streams[1].connect(sockets[1], 1, sockets[0].address().port, '127.0.0.1')
  return {
    streams,
    async close() {
      for (const stream of streams) stream.destroy()
      await Promise.all(closed)
      await Promise.all(sockets.map((socket) => socket.close()))
    }
  }
}

test('delay line admits multiple owned batches immediately, preserves flush and FIN order', async (t) => {
  const delay = installDelay(20, { capBytes: 1024, capWrites: 16 })
  const fixture = pair()
  const [sender, receiver] = fixture.streams
  const chunks = []
  receiver.on('data', (data) => chunks.push(Buffer.from(data)))
  sender.resume()
  const ended = event(receiver, 'end')
  let callbacks = 0
  try {
    for (const text of ['alpha', 'beta', 'gamma']) {
      const buffer = Buffer.from(text)
      // Exercise the patched admission boundary directly, independently of
      // streamx batching. These are real connected native UDX streams.
      sender._writev([buffer], (error) => {
        t.absent(error)
        callbacks++
        buffer.fill(0)
      })
    }
    t.is(callbacks, 3, 'every admission completes before any timer can run')
    t.is(delay.stats.queuedWrites, 3, 'more than one batch is in flight')
    t.is(delay.stats.nativeWrites, 0)
    t.ok(await deadline(sender.flush(), 5000, 'injected flush'))
    t.is(delay.stats.outstandingBytes, 0, 'flush includes native buffer completion')
    t.is(Buffer.concat(chunks).toString(), 'alphabetagamma', 'caller reuse did not corrupt payload')
    const finalBuffer = Buffer.from('omega')
    sender._writev([finalBuffer], (error) => {
      t.absent(error)
      callbacks++
      finalBuffer.fill(0)
    })
    sender.end()
    await deadline(ended, 5000, 'ordered EOF')
    t.is(
      Buffer.concat(chunks).toString(),
      'alphabetagammaomega',
      'FIN cannot overtake delayed payload'
    )
    t.is(callbacks, 4, 'native completions never repeat admission callbacks')
  } finally {
    await fixture.close()
    delay.close()
  }
})

test('delay line bounds queued bytes process-wide and rejects only the new admission', async (t) => {
  const delay = installDelay(100, { capBytes: 4, capWrites: 8 })
  const fixture = pair()
  const [sender, receiver] = fixture.streams
  let accepted = 0
  let rejected = 0
  try {
    sender._writev([Buffer.from('full')], (error) => {
      t.absent(error)
      accepted++
    })
    receiver._writev([Buffer.from('x')], (error) => {
      t.ok(error, 'other stream shares the same process byte bound')
      rejected++
    })
    t.is(delay.stats.maxBytes, 4)
    t.is(delay.stats.rejected, 1)
    await fixture.close()
    t.is(accepted, 1)
    t.is(rejected, 1)
    t.is(delay.stats.outstandingBytes, 0)
    t.is(delay.stats.queuedWrites, 0)
  } finally {
    await fixture.close()
    delay.close()
  }
})

test('native drain does not release retained bytes before transport completion', async (t) => {
  const sink = dgram.createSocket('udp4')
  const listening = event(sink, 'listening')
  sink.bind(0, '127.0.0.1')
  await listening
  const packet = event(sink, 'message') // Receives packets but never sends UDX ACKs.
  const delay = installDelay(1, { capBytes: 4, capWrites: 8 })
  const udx = new UDX()
  const socket = udx.createSocket()
  socket.bind(0, '127.0.0.1')
  const stream = udx.createStream(1)
  stream.on('error', () => {})
  const closed = event(stream, 'close')
  stream.connect(socket, 2, sink.address().port, '127.0.0.1')
  let callbacks = 0
  try {
    stream._writev([Buffer.from('data')], (error) => {
      t.absent(error)
      callbacks++
    })
    await deadline(packet, 5000, 'native packet')
    t.is(delay.stats.queuedBytes, 0)
    t.is(delay.stats.nativeBytes, 4, 'native still owns the copied bytes')
    t.is(delay.stats.outstandingBytes, 4)
    stream._writev([Buffer.from('x')], (error) =>
      t.ok(error, 'retained native bytes count against admission')
    )
    await deadline(closed, 5000, 'overflow close')
    t.is(callbacks, 1)
    t.is(delay.stats.outstandingBytes, 0)
  } finally {
    stream.destroy()
    await closed
    await socket.close()
    sink.close()
    delay.close()
  }
})

test('write-count bound covers empty batches and close completes pending final once', async (t) => {
  const delay = installDelay(100, { capBytes: 1024, capWrites: 1 })
  const fixture = pair()
  const [sender, receiver] = fixture.streams
  let accepted = 0
  let finals = 0
  try {
    sender._writev([Buffer.alloc(0)], (error) => {
      t.absent(error)
      accepted++
    })
    sender._final((error) => {
      t.ok(error, 'shutdown fails the unsubmitted final')
      finals++
    })
    receiver._writev([Buffer.alloc(0)], (error) =>
      t.ok(error, 'empty writes cannot bypass the entry bound')
    )
    delay.close()
    delay.close()
    await fixture.close()
    t.is(accepted, 1)
    t.is(finals, 1)
    t.is(delay.stats.outstandingWrites, 0)
    t.is(delay.stats.discarded, 1)
  } finally {
    await fixture.close()
    delay.close()
  }
})
