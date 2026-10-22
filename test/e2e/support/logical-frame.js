'use strict'

const b4a = require('b4a')

const CONTROL_VERSION = 7
const CIRCUIT_STREAM_ID = 0xffffffff
const TYPES = ['data', 'open', 'fin', 'reset', 'credit', 'demand', 'release']

module.exports = { CONTROL_VERSION, CIRCUIT_STREAM_ID, decodeLogical, decodeControlHeader }

function decodeLogical(frame) {
  if (!b4a.isBuffer(frame)) throw new TypeError('Logical frame must be a Buffer')
  if (frame.byteLength < 5) throw new Error('Logical frame header requires at least 5 bytes')

  const streamId = b4a.readUInt32BE(frame, 0)
  const flags = frame[4]
  const type = TYPES[flags]
  if (type === undefined) throw new Error('Unknown logical frame flag: ' + flags)
  const circuit = streamId === CIRCUIT_STREAM_ID

  const data = frame.subarray(5)
  let count = null
  if (flags >= 4) {
    if (data.byteLength !== 2)
      throw new Error('Logical ' + type + ' count requires exactly 2 bytes')
    if (flags !== 4 && !circuit) throw new Error('Logical ' + type + ' requires circuit scope')
    count = (data[0] << 8) | data[1]
    if (count === 0 && flags !== 5) throw new Error('Logical ' + type + ' count must be nonzero')
    const maximum = circuit ? 2048 : 512
    if (count > maximum) throw new Error('Logical ' + type + ' count exceeds ' + maximum + ' cells')
  } else {
    if (circuit) throw new Error('Logical ' + type + ' requires stream scope')
    if (flags !== 0 && data.byteLength !== 0)
      throw new Error('Logical ' + type + ' body must be empty')
  }

  // The body aliases the input; observers must treat it as read-only.
  return {
    streamId,
    flags,
    type,
    scope: circuit ? 'circuit' : 'stream',
    count,
    data
  }
}

function decodeControlHeader(bytes) {
  if (!b4a.isBuffer(bytes)) throw new TypeError('Control header must be a Buffer')
  if (bytes.byteLength !== 2) throw new Error('Control header requires exactly 2 bytes')

  const version = bytes[0]
  const opcode = bytes[1]
  if (version !== CONTROL_VERSION) throw new Error('Unsupported control version: ' + version)
  if (opcode < 3 || opcode > 7) throw new Error('Unknown outer control opcode: ' + opcode)
  return { version, opcode }
}
