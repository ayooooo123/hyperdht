'use strict'

const fs = require('fs')
const process = require('process')
const { analyze } = require('./analyzer')

const args = process.argv.slice(2)
if (args.length !== 1) {
  console.error('Usage: node test/e2e/c2/capture/cli.js normalized-evidence.json')
  process.exitCode = 64
} else {
  try {
    const input = JSON.parse(fs.readFileSync(args[0], 'utf8'))
    console.log(JSON.stringify(analyze(input), null, 2))
  } catch (error) {
    console.error(JSON.stringify({ error: error.code || 'INVALID_INPUT', message: error.message }))
    process.exitCode = 1
  }
}
