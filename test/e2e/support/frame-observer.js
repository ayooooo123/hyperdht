'use strict'

const b4a = require('b4a')
const { decodeLogical, decodeControlHeader } = require('./logical-frame')

const INNER = new Set(['source-resolve', 'source-resolved', 'source-extend'])

module.exports = function frameObserver() {
  const controls = new Set()
  const lengths = new Set()
  const errors = new Set()

  function observe(event) {
    if (event.type === 'control-read' || event.type === 'control-write') {
      if (INNER.has(event.label)) {
        lengths.add(event.bytes.byteLength)
        controls.add(b4a.toString(event.bytes, 'hex'))
      }
      if (event.type === 'control-read' && event.label === 'header') {
        try {
          decodeControlHeader(event.bytes)
        } catch (error) {
          errors.add(error.message)
        }
      }
      return null
    }
    if (event.type !== 'route-cell-opened' && event.type !== 'route-cell-sealed') return null
    // Source control writes are observed before their cells are sealed. Their
    // opcode namespace is not the logical frame namespace, even on the same link.
    if (
      lengths.has(event.plaintext.byteLength) &&
      controls.has(b4a.toString(event.plaintext, 'hex'))
    ) {
      return { type: 'source-control', scope: null, count: null, data: event.plaintext }
    }
    try {
      return decodeLogical(event.plaintext)
    } catch (error) {
      // Production intentionally ignores observer exceptions; retain failures
      // so a malformed frame cannot silently disappear from the test evidence.
      errors.add(event.label + ': ' + error.message)
      return { type: 'invalid', scope: null, count: null, data: event.plaintext }
    }
  }

  return { observe, errors }
}
