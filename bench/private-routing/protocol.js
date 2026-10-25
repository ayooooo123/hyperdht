'use strict'

const b4a = require('b4a')
const c = require('compact-encoding')
const sodium = require('sodium-universal')
const process = require('process')

const MIB = 1024 * 1024
const CHUNK = 64 * 1024
const MAX_CONTROL = 4096

function now() {
  return process.hrtime.bigint()
}

function milliseconds(start, end) {
  return Number(BigInt(end) - BigInt(start)) / 1e6
}

function deferred() {
  let resolve
  let reject
  const promise = new Promise((a, b) => {
    resolve = a
    reject = b
  })
  promise.catch(() => {})
  return { promise, resolve, reject }
}

async function deadline(promise, timeout, label) {
  let timer
  try {
    return await Promise.race([
      promise,
      new Promise((resolve, reject) => {
        timer = setTimeout(
          () => reject(new Error(label + ' timed out after ' + timeout + ' ms')),
          timeout
        )
      })
    ])
  } finally {
    clearTimeout(timer)
  }
}

function payload(id, index, size) {
  const seed = b4a.alloc(sodium.randombytes_SEEDBYTES)
  sodium.crypto_generichash(seed, b4a.from('private-routing-benchmark/' + id + '/' + index))
  const data = b4a.allocUnsafe(size)
  sodium.randombytes_buf_deterministic(data, seed)
  return data
}

async function write(stream, data) {
  if (stream.destroying || stream.destroyed) throw new Error('stream closed before write')
  if (stream.write(data)) return
  await new Promise((resolve, reject) => {
    function cleanup() {
      stream.removeListener('drain', ondrain)
      stream.removeListener('error', onerror)
      stream.removeListener('close', onclose)
    }
    function ondrain() {
      cleanup()
      resolve()
    }
    function onerror(error) {
      cleanup()
      reject(error)
    }
    function onclose() {
      onerror(new Error('stream closed while waiting for drain'))
    }
    stream.once('drain', ondrain)
    stream.once('error', onerror)
    stream.once('close', onclose)
  })
}

async function writePayload(stream, data) {
  for (let offset = 0; offset < data.byteLength; offset += CHUNK) {
    await write(stream, data.subarray(offset, offset + CHUNK))
  }
  await writeControl(stream, { finished: data.byteLength })
}

async function writeControl(stream, value) {
  const encoded = c.encode(c.json, value)
  if (encoded.byteLength > MAX_CONTROL) throw new Error('control frame exceeds limit')
  await write(stream, b4a.concat([c.encode(c.uint32, encoded.byteLength), encoded]))
}

// Pull reads preserve transport backpressure. Explicit bounded finish frames
// delimit trials without including transport teardown in application throughput.
class Reader {
  constructor(stream) {
    this.stream = stream
    this.pending = null
    this.waiting = null
    this.ended = false
    this.error = null
    this.bytes = 0
    this.firstNs = null
    this.lastNs = null
    stream.on('readable', () => this.wake())
    stream.once('end', () => {
      this.ended = true
      this.wake()
    })
    stream.on('error', (error) => {
      this.error = error
      this.wake()
    })
    stream.once('close', () => {
      if (!this.ended && !this.error) this.error = new Error('stream closed before EOF')
      this.wake()
    })
  }

  async next() {
    if (this.error) throw this.error
    if (this.pending !== null) {
      const data = this.pending
      this.pending = null
      return data
    }
    if (this.waiting !== null) throw new Error('overlapping benchmark reads')
    this.waiting = deferred()
    const result = this.waiting.promise
    this.wake()
    return result
  }

  wake() {
    if (this.waiting === null) return
    const waiting = this.waiting
    if (this.error) {
      this.waiting = null
      waiting.reject(this.error)
      return
    }
    const data = this.stream.read()
    if (data === null && !this.ended) return
    this.waiting = null
    waiting.resolve(data)
  }

  async exact(size) {
    const out = b4a.allocUnsafe(size)
    let offset = 0
    while (offset < size) {
      const data = await this.next()
      if (data === null) throw new Error('missing control bytes: ' + offset + '/' + size)
      const n = Math.min(data.byteLength, size - offset)
      out.set(data.subarray(0, n), offset)
      offset += n
      if (n < data.byteLength) this.pending = data.subarray(n)
    }
    return out
  }

  async control() {
    const size = c.decode(c.uint32, await this.exact(4))
    if (size === 0 || size > MAX_CONTROL) throw new Error('invalid control frame size')
    const data = await this.exact(size)
    const state = c.state(0, size, data)
    const value = c.json.decode(state)
    if (state.start !== state.end) throw new Error('excess control bytes')
    return value
  }

  async payload(expected, oncomplete = null) {
    while (this.bytes < expected.byteLength) {
      const data = await this.next()
      if (data === null)
        throw new Error('missing payload: ' + this.bytes + '/' + expected.byteLength)
      const at = now().toString()
      if (this.firstNs === null) this.firstNs = at
      const length = Math.min(data.byteLength, expected.byteLength - this.bytes)
      const end = this.bytes + length
      if (!b4a.equals(data.subarray(0, length), expected.subarray(this.bytes, end))) {
        throw new Error('corrupt payload at offset ' + this.bytes)
      }
      this.bytes = end
      this.lastNs = at
      if (length < data.byteLength) this.pending = data.subarray(length)
    }
    const finish = await this.control()
    if (!finish || finish.finished !== expected.byteLength || Object.keys(finish).length !== 1) {
      throw new Error('missing or invalid payload finish frame')
    }
    if (oncomplete !== null) await oncomplete()
    return { bytes: this.bytes, firstNs: this.firstNs, lastNs: this.lastNs }
  }
}

function track(stream) {
  const closed = deferred()
  let error = null
  stream.on('error', (err) => {
    error = err
  })
  stream.once('close', () => {
    if (error) closed.reject(error)
    else closed.resolve()
  })
  return { stream, reader: new Reader(stream), closed: closed.promise }
}

module.exports = {
  MIB,
  CHUNK,
  now,
  milliseconds,
  deferred,
  deadline,
  payload,
  writePayload,
  writeControl,
  track
}
