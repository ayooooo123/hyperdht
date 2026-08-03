'use strict'

const registerLiveProcessSuite = require('./live-process-suite')

registerLiveProcessSuite({
  nodePath: process.execPath,
  runtime: 'node',
  runtimeVersion: process.version
})
