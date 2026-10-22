'use strict'

const test = require('brittle')
const b4a = require('b4a')
const {
  CONTROL_VERSION,
  CIRCUIT_STREAM_ID,
  decodeLogical,
  decodeControlHeader
} = require('../support/logical-frame')

const IDS = [
  ['00000000', 0, 'stream'],
  ['01020304', 0x01020304, 'stream'],
  ['7fffffff', 0x7fffffff, 'stream'],
  ['80000000', 0x80000000, 'stream'],
  ['fffffffe', 0xfffffffe, 'stream'],
  ['ffffffff', CIRCUIT_STREAM_ID, 'circuit']
]
const COUNTS = [
  ['0001', 1],
  ['00ff', 255],
  ['0100', 256],
  ['0102', 258],
  ['01ff', 511],
  ['0200', 512],
  ['0201', 513],
  ['0400', 1024],
  ['07ff', 2047],
  ['0800', 2048]
]

function frame(id, flag, body = '') {
  return b4a.from(id + flag.toString(16).padStart(2, '0') + body, 'hex')
}

test('logical data preserves unsigned stream IDs, scopes and body views', (t) => {
  for (const [id, streamId, scope] of IDS) {
    if (scope !== 'stream') continue
    for (const body of ['', '0080ff0102']) {
      const bytes = frame(id, 0, body)
      const snapshot = b4a.from(bytes)
      const decoded = decodeLogical(bytes)
      t.alike(decoded, {
        streamId,
        flags: 0,
        type: 'data',
        scope,
        count: null,
        data: b4a.from(body, 'hex')
      })
      t.alike(bytes, snapshot, 'decoding does not modify the wire frame')
    }
  }
})

test('logical open, fin and reset require empty bodies in stream scope', (t) => {
  for (const [id, streamId, scope] of IDS) {
    if (scope !== 'stream') continue
    for (const [flags, type] of [
      [1, 'open'],
      [2, 'fin'],
      [3, 'reset']
    ]) {
      t.alike(decodeLogical(frame(id, flags)), {
        streamId,
        flags,
        type,
        scope,
        count: null,
        data: b4a.alloc(0)
      })
      for (const body of ['00', '0001']) {
        t.exception(() => decodeLogical(frame(id, flags, body)), new RegExp(type))
      }
    }
  }
})

test('logical credit, demand and release decode exact unsigned big-endian counts', (t) => {
  for (const [id, streamId, scope] of IDS) {
    for (const [flags, type] of [
      [4, 'credit'],
      [5, 'demand'],
      [6, 'release']
    ]) {
      if (scope !== 'circuit' && flags !== 4) continue
      for (const [body, count] of COUNTS) {
        if (scope === 'stream' && count > 512) continue
        t.alike(decodeLogical(frame(id, flags, body)), {
          streamId,
          flags,
          type,
          scope,
          count,
          data: b4a.from(body, 'hex')
        })
      }
    }
  }
})

test('logical demand zero is valid while credit and release zero are rejected', (t) => {
  t.alike(decodeLogical(frame('ffffffff', 5, '0000')), {
    streamId: CIRCUIT_STREAM_ID,
    flags: 5,
    type: 'demand',
    scope: 'circuit',
    count: 0,
    data: b4a.from('0000', 'hex')
  })
  for (const [id] of IDS) {
    t.exception(() => decodeLogical(frame(id, 4, '0000')), /credit/)
  }
  t.exception(() => decodeLogical(frame('ffffffff', 6, '0000')), /release/)
})

test('logical operations reject wrong scopes and counts above their wire window', (t) => {
  for (const flags of [0, 1, 2, 3]) {
    t.exception(() => decodeLogical(frame('ffffffff', flags)), /stream scope/)
  }
  for (const flags of [5, 6]) {
    t.exception(() => decodeLogical(frame('fffffffe', flags, '0001')), /circuit scope/)
  }
  for (const body of ['0201', '0800', '7fff', '8000', 'ffff']) {
    t.exception(() => decodeLogical(frame('01020304', 4, body)), /512 cells/)
  }
  for (const flags of [4, 5, 6]) {
    for (const body of ['0801', '7fff', '8000', 'ffff']) {
      t.exception(() => decodeLogical(frame('ffffffff', flags, body)), /2048 cells/)
    }
  }
})

test('logical malformed count bodies retain the recognized control type', (t) => {
  for (const id of ['01020304', 'ffffffff']) {
    for (const [flags, type] of [
      [4, 'credit'],
      [5, 'demand'],
      [6, 'release']
    ]) {
      for (const body of ['', '01', '000100', '00010001']) {
        t.exception(() => decodeLogical(frame(id, flags, body)), new RegExp(type))
      }
    }
  }
})

test('logical decoding rejects unknown flags, short headers and nonbuffers', (t) => {
  for (const flags of [7, 8, 127, 255]) {
    for (const body of ['', '0001']) {
      t.exception(() => decodeLogical(frame('01020304', flags, body)), /flag/i)
    }
  }
  for (let length = 0; length < 5; length++) {
    t.exception(() => decodeLogical(b4a.alloc(length)), /header/i)
  }
  for (const value of [undefined, null, false, 5, '0000000000', [], {}, new ArrayBuffer(5)]) {
    t.exception.all(() => decodeLogical(value), /Buffer/)
  }
})

test('outer control header accepts version seven and opcodes three through seven', (t) => {
  for (const opcode of [3, 4, 5, 6, 7]) {
    t.alike(decodeControlHeader(b4a.from([7, opcode])), { version: CONTROL_VERSION, opcode })
  }
})

test('outer control header rejects other versions, inner opcodes and combined writes', (t) => {
  for (const version of [0, 6, 8, 255]) {
    t.exception(() => decodeControlHeader(b4a.from([version, 3])), /version/i)
  }
  for (const opcode of [0, 1, 2, 8, 255]) {
    t.exception(() => decodeControlHeader(b4a.from([7, opcode])), /opcode/i)
  }
  for (const bytes of [[], [7], [7, 3, 0], [7, 3, 7, 4]]) {
    t.exception(() => decodeControlHeader(b4a.from(bytes)), /2 bytes/)
  }
  for (const value of [undefined, null, false, 2, '0703', [7, 3], {}, new ArrayBuffer(2)]) {
    t.exception.all(() => decodeControlHeader(value), /Buffer/)
  }
})
