const fs = require('fs')
const sodium = require('sodium-universal')
const { VECTORS, buildSurb, processSurbHop, createReplayGuard } = require('./lib/private/surb.js')

const vec = {}
for (const line of fs.readFileSync('/tmp/surb_vectors.txt', 'utf8').trim().split('\n')) {
  const [k, ...rest] = line.split(' ')
  vec[k] = rest.join(' ')
}

const nodeKeys = [
  { id: 'ff2182654d0000000000000000000000', pub: 'd7314c8d2ba771dbe2982fa6299844f1b92736881e78ae7644f4bccbf8817a69' },
  { id: 'ff0f9a62780000000000000000000000', pub: '5ce56657b8af66bd47df2469b10065206a2fd777a0cd17b104160256810bc976' },
  { id: 'ffc74d10550000000000000000000000', pub: '47ade5905376604cde0b57e732936b4298281c8a67b6a62c6107482eb69e2941' },
  { id: 'ffbb0407380000000000000000000000', pub: '4704aff4bc2aaaa3fd187d52913a203aba4e19f6e7b491bda8c8e67daa8daa67' },
  { id: 'ff81855a360000000000000000000000', pub: '73514173ee741afacdd4733e84f629b5cb9e34d28d072d749a8171fc6d64a930' }
]
const route = nodeKeys.map((n) => ({ id: Buffer.from(n.id, 'hex'), key: Buffer.from(n.pub, 'hex') }))

// Reader sequence: ComposeReplyBlock -> create_header reads x(32) then padding(15); then kTilde(32).
// Go ChachaEntropyReader.Read XORs zeros with the running cipher (one continuous stream).
const seed = Buffer.from('47ade5905376604cde0b57e732936b4298281c8a67b6a62c6107482eb69e2941', 'hex')
const full = Buffer.alloc(96)
for (let b = 0; b < 2; b++) {
  const len = Math.min(64, 96 - b * 64)
  sodium.crypto_stream_chacha20_xor_ic(full.subarray(b * 64, b * 64 + len), Buffer.alloc(len), Buffer.alloc(8), b, seed)
}
const xSeed = full.subarray(0, 32)
const padSeed = full.subarray(32, 32 + 15)
const kTildeSeed = full.subarray(47, 47 + 32)

const clientID = Buffer.from('0f436c69656e74206665656463383061', 'hex')
const destination = Buffer.concat([Buffer.from([clientID.length]), clientID])
const messageId = Buffer.from(vec.messageID || 'ff81855a360000000000000000000000', 'hex')
const { surb } = buildSurb(VECTORS, route, destination, messageId, { xSeed, paddingSeed: padSeed, kTildeSeed })

let ok = 0, total = 0
function check(name, got, expectedHex) {
  total++
  const pass = Buffer.compare(got, Buffer.from(expectedHex, 'hex')) === 0
  if (pass) ok++
  else console.log('FAIL', name, 'got', got.toString('hex').slice(0, 32), 'want', expectedHex.slice(0, 32))
}
check('alpha', surb.header.alpha, vec.alpha)
check('beta', surb.header.beta, vec.beta)
check('gamma', surb.header.gamma, vec.gamma)

// Per-hop processing: hop forward packets must match hop1..hop4 vectors
const guard = createReplayGuard()
let m = { header: surb.header, delta: Buffer.alloc(VECTORS.deltaBytes) }
for (let i = 1; i <= 4; i++) {
  const r = processSurbHop(VECTORS, m, Buffer.from(nodeKeys[i - 1].sec, 'hex'), guard)
  check('hop' + i + '_alpha', r.forward.header.alpha, vec['hop' + i + '_alpha'])
  check('hop' + i + '_beta', r.forward.header.beta, vec['hop' + i + '_beta'])
  check('hop' + i + '_gamma', r.forward.header.gamma, vec['hop' + i + '_gamma'])
  m = r.forward
}
console.log(ok + '/' + total + ' vector fields match')
