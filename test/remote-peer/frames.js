'use strict'

// A one-byte op plus a 32-bit length. The mesh needs more than an echo: a member
// must be able to ask another for its report, and one stream carries both. Chunk
// boundaries mean nothing on a stream, so the reader buffers until a whole frame
// is present.

const EventEmitter = require('events')
const b4a = require('b4a')

const OP = Object.freeze({ ECHO: 1, REPORT: 2 })
const HEADER_BYTES = 5
const MAX_FRAME_BYTES = 4 * 1024 * 1024

function writeFrame(op, payload) {
  const body = payload || b4a.alloc(0)
  if (body.byteLength > MAX_FRAME_BYTES) throw new Error('frame too large')
  const frame = b4a.allocUnsafeSlow(HEADER_BYTES + body.byteLength)
  frame[0] = op
  frame.writeUInt32BE(body.byteLength, 1)
  frame.set(body, HEADER_BYTES)
  return frame
}

class FrameReader extends EventEmitter {
  constructor(stream) {
    super()
    this.buffered = b4a.alloc(0)
    this.pending = []
    this.waiting = null
    this.failure = null
    stream.on('data', (data) => this._push(data))
    stream.on('error', (err) => this._fail(err))
    stream.on('close', () => this._fail(new Error('stream closed')))
  }

  _fail(err) {
    if (this.failure !== null) return
    this.failure = err
    if (this.waiting !== null) {
      const waiting = this.waiting
      this.waiting = null
      waiting.reject(err)
    }
  }

  _push(data) {
    this.buffered = this.buffered.byteLength === 0 ? data : b4a.concat([this.buffered, data])
    for (;;) {
      if (this.buffered.byteLength < HEADER_BYTES) return
      const length = this.buffered.readUInt32BE(1)
      if (length > MAX_FRAME_BYTES) return this._fail(new Error('frame too large'))
      if (this.buffered.byteLength < HEADER_BYTES + length) return
      const frame = {
        op: this.buffered[0],
        payload: b4a.from(this.buffered.subarray(HEADER_BYTES, HEADER_BYTES + length))
      }
      this.buffered = b4a.from(this.buffered.subarray(HEADER_BYTES + length))
      if (this.waiting !== null) {
        const waiting = this.waiting
        this.waiting = null
        waiting.resolve(frame)
      } else {
        this.pending.push(frame)
      }
      this.emit('frame', frame)
    }
  }

  // Bounded on purpose: a peer that opens a stream and then says nothing must
  // fail its own measurement rather than stall the run.
  next(timeoutMs) {
    if (this.pending.length > 0) return Promise.resolve(this.pending.shift())
    if (this.failure !== null) return Promise.reject(this.failure)
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiting = null
        reject(new Error(`frame timed out after ${timeoutMs}ms`))
      }, timeoutMs)
      this.waiting = {
        resolve: (frame) => {
          clearTimeout(timer)
          resolve(frame)
        },
        reject: (err) => {
          clearTimeout(timer)
          reject(err)
        }
      }
    })
  }
}

module.exports = { OP, HEADER_BYTES, MAX_FRAME_BYTES, writeFrame, FrameReader }
