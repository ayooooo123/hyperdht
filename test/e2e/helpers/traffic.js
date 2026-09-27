'use strict'

const b4a = require('b4a')
const c = require('compact-encoding')
const Protomux = require('protomux')
const { deadline } = require('./network')

function pattern(size, seed) {
  const bytes = b4a.alloc(size)
  for (let offset = 0; offset < size; offset++) {
    const word = (Math.imul(offset >>> 2, 0x9e3779b1) + seed) >>> 0
    bytes[offset] = (word >>> ((offset & 3) * 8)) & 255
  }
  return bytes
}

function event(stream, name) {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      stream.removeListener(name, success)
      stream.removeListener('error', failure)
      stream.removeListener('close', onclose)
    }
    const success = () => {
      cleanup()
      resolve()
    }
    const failure = (error) => {
      cleanup()
      reject(error)
    }
    const onclose = () => failure(new Error('Stream closed before ' + name))
    stream.once(name, success)
    stream.once('error', failure)
    stream.once('close', onclose)
  })
}

function receiver(stream, expected) {
  let offset = 0
  let settle
  const done = new Promise((resolve, reject) => {
    settle = { resolve, reject }
  })
  const fail = (error) => {
    cleanup()
    settle.reject(error)
  }
  const end = () => fail(new Error('Early stream end at ' + offset + '/' + expected.length))
  const data = (chunk) => {
    if (
      offset + chunk.length > expected.length ||
      !b4a.equals(chunk, expected.subarray(offset, offset + chunk.length))
    ) {
      return fail(new Error('Unexpected payload at byte ' + offset))
    }
    offset += chunk.length
    if (offset === expected.length) {
      cleanup()
      settle.resolve(offset)
    }
  }
  function cleanup() {
    stream.removeListener('data', data)
    stream.removeListener('error', fail)
    stream.removeListener('end', end)
    stream.removeListener('close', end)
  }
  stream.on('data', data)
  stream.once('error', fail)
  stream.once('end', end)
  stream.once('close', end)
  return done
}

const frame = {
  preencode(state, value) {
    c.uint.preencode(state, value.sequence)
    c.buffer.preencode(state, value.bytes)
  },
  encode(state, value) {
    c.uint.encode(state, value.sequence)
    c.buffer.encode(state, value.bytes)
  },
  decode(state) {
    return { sequence: c.uint.decode(state), bytes: c.buffer.decode(state) }
  }
}

// Completion requires an explicit final frame, exact sequence and bytes, not
// merely enough received data. Each direction has independent payload contents.
async function exchange(
  client,
  remote,
  { up = 49157, down = 32771, seed = 17, id = 'exchange' } = {}
) {
  if (client.destroyed || client.destroying || remote.destroyed || remote.destroying) {
    throw new Error('Cannot exchange application data on a closed private stream')
  }
  const upload = pattern(up, seed)
  const download = pattern(down, seed + 101)
  function endpoint(stream, expected) {
    let offset = 0
    let sequence = 0
    let resolve
    let reject
    const received = new Promise((yes, no) => {
      resolve = yes
      reject = no
    })
    const fail = (error) => reject(error)
    const onclose = () => fail(new Error('Transfer closed at ' + offset + '/' + expected.length))
    stream.on('error', fail)
    stream.once('close', onclose)
    const channel = Protomux.from(stream).createChannel({
      protocol: 'hyperdht-e2e/bytes',
      id: b4a.from(id)
    })
    const data = channel.addMessage({
      encoding: frame,
      onmessage(value) {
        if (
          value.sequence !== sequence++ ||
          offset + value.bytes.length > expected.length ||
          !b4a.equals(value.bytes, expected.subarray(offset, offset + value.bytes.length))
        ) {
          throw new Error('Payload or sequence mismatch at ' + offset)
        }
        offset += value.bytes.length
      }
    })
    const finish = channel.addMessage({
      encoding: c.uint,
      onmessage(count) {
        if (count !== sequence || offset !== expected.length)
          throw new Error('Incomplete transfer: ' + offset)
        resolve(offset)
      }
    })
    channel.open()
    return {
      received,
      async write(bytes) {
        let sequence = 0
        for (let offset = 0; offset < bytes.length; offset += 32768) {
          if (!data.send({ sequence: sequence++, bytes: bytes.subarray(offset, offset + 32768) })) {
            await event(stream, 'drain')
          }
        }
        finish.send(sequence)
      },
      async close() {
        stream.removeListener('error', fail)
        stream.removeListener('close', onclose)
        channel.close()
        if (!stream.destroying && !stream.destroyed) await stream.flush()
      }
    }
  }
  const left = endpoint(client, download)
  const right = endpoint(remote, upload)
  try {
    const results = await deadline(
      Promise.all([left.received, right.received, left.write(upload), right.write(download)]),
      'verified duplex transfer',
      45000
    )
    return { up: results[1], down: results[0] }
  } finally {
    await Promise.all([left.close(), right.close()])
  }
}

module.exports = { pattern, receiver, event, exchange }
