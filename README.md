# hyperdht

### [See the full API docs at docs.pears.com](https://docs.pears.com/building-blocks/hyperdht)

The DHT powering Hyperswarm

```
npm install hyperdht
```

Built on top of [dht-rpc](https://github.com/mafintosh/dht-rpc).

The Hyperswarm DHT uses a series of holepunching techniques to make sure connectivity works on most networks,
and is mainly used to facilitate finding and connecting to peers using end to end encrypted Noise streams.

> **ALPHA fork API:** An explicitly acknowledged `privateRouting` option adds a separate `dht.privateRouting` peer context. Ordinary `dht.connect()` and `dht.createServer()` remain direct and wire-compatible; only `dht.privateRouting.connect()` and `dht.privateRouting.createServer()` use fail-closed relay circuits with end-to-end Noise. Bootstrap, lookup/announce, immutable and mutable records, plugins, queries, pings, and routing-table maintenance keep their normal direct-overlay behavior and are **not anonymized**. This remains **alpha, not production anonymity**, until Linux privacy evidence and external human cryptographic review are complete; private Hyperswarm integration is not provided. See [ALPHA private peer routing](#alpha-private-peer-routing).

## Usage

To try it out, first instantiate a DHT instance

```js
import DHT from 'hyperdht'

const node = new DHT()
```

Then on one computer listen for connections

```js
// create a server to listen for secure connections
const server = node.createServer()

server.on('connection', function (socket) {
  // socket is E2E encrypted between you and the other peer
  console.log('Remote public key', socket.remotePublicKey)

  // pipe it somewhere like any duplex stream
  process.stdin.pipe(socket).pipe(process.stdout)
})

// make a ed25519 keypair to listen on
const keyPair = DHT.keyPair()

// this makes the server accept connections on this keypair
await server.listen(keyPair)
```

Then on another connect to the computer using the public key of the key-pair it is listening on

```js
// publicKey here is keyPair.publicKey from above
const socket = anotherNode.connect(publicKey)

socket.on('open', function () {
  // socket fully open with the other peer
})

// pipe it somewhere like any duplex stream
process.stdin.pipe(socket).pipe(process.stdout)
```

### ALPHA private peer routing

Private routing is an optional context on an ordinary HyperDHT node. Normal
`bootstrap` and routing-table discovery supply eligible route hops. No private
bootstrap endpoint list, bind address, or advertised address is accepted.

```js
const dht = new DHT({
  privateRouting: {
    release: 'alpha',
    acknowledgeAlpha: true,
    mode: 'optional',
    profile: 'standard',
    relay: false
  }
})

await dht.ready()
await dht.privateRouting.ready()

const server = dht.privateRouting.createServer(function (socket) {
  socket.pipe(socket)
})

await server.listen(keyPair)

const socket = dht.privateRouting.connect(keyPair.publicKey)
socket.write('private peer payload')
```

Relay service is explicit. A node that contributes relay capacity uses the same
five fields with `relay: true`. Relay nodes advertise a separate relay key and
cannot create or connect private application endpoints:

```js
const relay = new DHT({
  privateRouting: {
    release: 'alpha',
    acknowledgeAlpha: true,
    mode: 'optional',
    profile: 'standard',
    relay: true
  }
})
```

Every `privateRouting` field must be an own data property on an ordinary object.
`profile` accepts `'standard'` (directory-sampled alpha) or `'native-v2'` (admitted
native wire v3 relays; relay nodes supply `relayConfig` or load it via
`hyperdht --private-routing-config <file>`). Accessors, inherited fields, unknown
fields, `bootstrapEndpoints`, and endpoint host/port fields are rejected.
A private server selects distinct destination-guard and entry relays, builds a
fixed-cell circuit to the entry, and publishes a signed, expiring descriptor
from its guard. The descriptor is replicated to at least three DHT storage
nodes and accepted only after an exact two-reply readback quorum. Its wire
contains a period-blinded signing key, relay identities, and an opaque route
capability—not the stable destination identity, a destination transport key,
or a dial address.

A client resolves the descriptor through a first source safety relay that
cannot reuse either destination role, then selects a distinct second source
safety relay. The `standard` profile therefore compiles four distinct relay
identities: two source-selected safety relays followed by the
destination-selected entry and guard. Resolution is two-phase: the first
safety relay proves it is not serving as a destination guard or entry, reserves
the resolver role, and only then accepts the destination application key. A
forced destination-role candidate rejects before that key is sent.

Destination admission is also two-phase. The endpoint first authenticates with
a fresh ephemeral Noise key and sends only the build opcode. A relay with an
active resolver rejects at that point, before seeing application-key bytes.
After reserving the destination role, the guard issues a random challenge; the
endpoint signs a domain-separated binding of that challenge, the authenticated
ephemeral peer, the guard identity, and its application key. Only then does the
guard recover the signed previous descriptor and later perform descriptor GET
and PUT operations. Initial publication, restart, and refresh therefore emit no
descriptor-target storage traffic from the endpoint. The entry stages guard-
authenticated registration but does not install it until the guard completes
descriptor quorum publication and sends the commit marker.

The entry multiplexes independent logical streams over the destination circuit.
Every physical relay hop authenticates and opens each 1200-byte route cell,
then reseals the payload with a fresh adjacent circuit key, nonce, circuit ID,
and counter. A relay therefore transforms on-wire bytes rather than forwarding
an unchanged transparent stream. The application Noise/SecretStream handshake
remains end-to-end between the client and server application keys.

Cell sends, receive buffers, deferred transformations, stream counts, frame
counts, and byte totals are bounded. Every link charges independent peer-ledger
budgets. Logical reset and close are stream-scoped and idempotent. The entry and
destination reject reuse of admitted stream IDs and discard late in-flight
DATA, so closing either side of one multiplexed stream cannot reset its siblings
or the destination circuit.

Alpha control version 7 requires both stream and shared-circuit credit before
DATA is sent. The windows are 512 cells per stream and 2,048 cells per circuit,
including unused grants and transmitted cells in the circuit pool. Credits
return when SecretStream consumes raw encrypted bytes, not when a relay merely
receives DATA or an application reads plaintext. These bounds cover additional
private-routing buffering, not ordinary SecretStream atomic records (up to
16,777,215 bytes) or application plaintext buffers. Alpha does not add a
Noise-aware record-fragmentation adapter.

Each link independently reserves 2,048 pending DATA jobs and 256 control slots;
writes contain up to 64 cells with at most two transport batches in flight.
Unused grants are reclaimed on close/reset, after 50 ms of honest writer idle,
or immediately when stream credit is exhausted. The entry also enforces a
five-second unused-grant/no-DATA-progress deadline. Already transmitted cells,
including authenticated late DATA for a retired stream, remain charged until
consumed or discarded. See [the e2e contract and evidence](docs/private-routing-e2e.md#control-version-7-flow-observations)
for bounded demand accounting and the remaining integration gates.

Route-only peer information is not added to the caller's routing table and is
not used for a direct destination ping or dial. Missing, invalid, expired, or
insufficiently diverse routes fail closed; there is no direct peer fallback.

Ordinary `dht.connect()` and `dht.createServer()` always retain normal direct
behavior when the optional context is configured. HyperDHT operations including
bootstrap, lookup/announce, immutable and mutable records, plugins, queries,
pings, and routing-table maintenance also retain direct-overlay behavior and
are **not** anonymized by this option.

`dht.privateRouting` is read-only and frozen:

- `release === 'alpha'`, `mode === 'optional'`, `profile === 'standard'`, and
  `relay` report the selected role.
- `ready()` waits for private subsystem readiness; `dht.ready()` and
  `dht.fullyBootstrapped()` retain normal HyperDHT semantics.
- `connect()` and `createServer()` select private peer routing explicitly.
- `status()` returns `BOOTSTRAPPING`, `READY`, `SUSPENDED`, or `DESTROYED`.
- `exposureReport()` reports the routing model and direct-destination-send trap
  without exposing keys, addresses, or complete paths.
- `createServer({ firewall })` evaluates the authenticated end-to-end Noise
  public key. A refused peer is closed and is never emitted as a server
  connection. Because the policy runs after Noise authentication, the initiator
  can observe handshake completion before the refusal closes its stream.

Suspension stops relay advertisement and closes live circuits; resume restarts
advertisement and republishes listening-server route descriptors. `destroy()`
closes private servers, relay advertisement, and pending route work with the
DHT lifecycle.

This remains an experimental alpha, not a production anonymity claim. Local
Node/Bare behavior tests do not replace Linux packet-capture evidence or
external cryptographic review.

### Native v2 profile (`profile: 'native-v2'`)

Selecting `profile: 'native-v2'` uses the native wire-version-3 controller
(`lib/private/private-native-controller.js`) over admitted native relay
neighbors (`lib/private/peer-native-runtime.js`):

- **Wire version 3:** Every hop applies a 4-round LIONESS wide-block layer over
  the 1,101-byte context envelope (`XChaCha20` + keyed `BLAKE2b-256`), uses
  hop-local circuit/branch identifiers, derives header epochs and counter
  origins per link, and mixes relay ephemerals into tail and purpose secrets
  for forward secrecy. Role and extension indexes remain explicit (position
  hiding is not provided).
- **Relay admission and roles:** Every native relay identity is `ROLE.SAFETY`.
  Two-authority format-1 topology grants orient each edge from upstream
  `SAFETY_GUARD` (1) to downstream `SAFETY_FINAL` (2). A relay's capability
  mask is derived from its grants: mask `9` if it occupies `SAFETY_GUARD` in at
  least one grant, or mask `11` if it occupies `SAFETY_FINAL` in every grant.
  Relay advertisement renewal tears down and reprovisions admission at
  advertisement expiry; active circuits through that relay end at renewal and
  new circuits resume once reprovisioned.
- **Presence and reader policy:** Terminal (mask `11`) relays serve presence
  over onion-layered circuits identified by a reserved terminal-hop parameter
  digest (`PRESENCE_PARAMETERS_DIGEST`) backed by Gate D mutable storage
  quorums. When no `readerSecret` is supplied, both sides derive a public
  reader capability from the destination public key
  (`hyperdht-private-routes/presence/public-reader/v1`), so anyone who knows
  the public key can locate presence while blinding and encryption protect
  against parties who do not. Supplying an explicit 32-byte `readerSecret` on
  `createServer` and `connect` restricts presence lookup to authorized readers.
  Verified presence lookups are cached per destination and reader policy for
  their validity window.
- **Finite budgets and record caps:** Native routes enforce finite per-route
  and per-stream lifetime budgets. Private-to-private legs (purposes 2 and 3)
  fragment application writes into SecretStream records of at most 64 KiB
  (65,536 plaintext / 65,556 raw bytes) and reject oversized inbound records at
  the 3-byte prefix guard before allocating. A source circuit (`purpose 2`,
  `M = 1`, `W = 24`) admits up to `111,852` frames (`109,279,404` raw bytes)
  per direction. A listener registration circuit (`purpose 3`, `M = 17`, `W = 1`
  per application inside a shared 24-frame / 23,448-byte receive pool) admits
  `111,791` aggregate frames per direction with a `1,024`-frame floor per
  remaining application slot (`96,431` frames maximum on the first `OPEN`) and
  refreshes make-before-break when exhausted. When a stream or route budget is
  exhausted, the stream ends cleanly and the application reconnects on a fresh
  route. One pinned guard holds at most 16 concurrent native circuits shared
  across application connections, listener registrations, and presence
  operations; further `connect()` calls wait in a bounded FIFO queue (16
  entries) and fail closed with `ROUTE_UNAVAILABLE` past the bound or deadline.
  Role memory pools are capped at `37,457,344` bytes (source, 16 slots),
  `768,704` bytes (mask-9 forwarding relay, 24 concurrent circuits), and
  `56,848,040` bytes (mask-11 terminal relay, 24 concurrent circuits).
- **Explicit legacy egress:** Calling
  `dht.privateRouting.connect(publicKey, { legacy: true, terminal: { advertisement260 }, keyPair? })`
  connects through a caller-supplied, signature-verified mask-11 terminal relay
  that explicitly opted in via `relayConfig.legacyEgress: true` (default
  `false`, rejected on mask-9 relays). Legacy egress preserves the standard
  16,777,218-byte SecretStream record cap with a finite budget of `M = 1`,
  `W = 24`, `Q = 20,000` frames (`19,540,000` raw bytes) per direction and at
  most one concurrent legacy stream per source and per opted-in terminal. The
  egress terminal learns the destination identity and the destination sees the
  egress terminal's address, not the source's; opt-out terminals refuse
  purpose 1 before contacting the destination, and there is never an automatic
  fallback between private, legacy, or direct modes.

### Local private-routing evidence

Run `npm run test:e2e` and `npm run test:e2e:bare` for the hermetic baseline
scenarios, `npm run test:e2e:b1` and `npm run test:e2e:b1:bare` for the B1
hardening and flow-control suite, `npm run test:e2e:c2:capture` and
`npm run test:e2e:c2:capture:bare` for send-owner capture reconciliation,
`npm run test:e2e:c2:native` and `npm run test:e2e:c2:native:bare` for the
native-v2 end-to-end suite, and `npm run test:e2e:c2:cloudflare` for the live
temporary Cloudflare Worker edge-node e2e suite. `npm run bench:private-routing`
prints a direct/alpha performance comparison. See
[the C1 and C2 evidence guide](docs/private-routing-e2e.md) for topology,
negative controls, benchmark definitions, and capture/diversity gates.

## API

#### `const node = new DHT([options])`

Create a new DHT node.

Options include:

```js
{
  // Optionally overwrite the default bootstrap servers, just need to be an array of any known dht node(s)
  // Defaults to Pear.config.dht.bootstrap in a Pear app or ['88.99.3.86@node1.hyperdht.org:49737', '142.93.90.113@node2.hyperdht.org:49737', '138.68.147.8@node3.hyperdht.org:49737'] elsewhere
  // Supports suggested-IP to avoid DNS calls: [suggested-IP@]<host>:<port>
  bootstrap: ['host:port'],
  keyPair, // set the default key pair to use for server.listen and connect
  connectionKeepAlive, // set a default keep-alive (in ms) on all opened sockets. Defaults to 5000. Set false to turn off (advanced usage).
  randomPunchInterval: 20000 // set a default time for interval between punches (in ms). Defaults to 20000.

}
```

See [dht-rpc](https://github.com/mafintosh/dht-rpc) for more options as HyperDHT inherits from that.

_Note:_ The default bootstrap servers are publicly served on behalf of the commons. To run a fully isolated DHT, start one or more dht nodes with an empty bootstrap array (`new DHT({bootstrap:[]})`) and then use the addresses of those nodes as the `bootstrap` option in all other dht nodes. You'll need at least one persistent node for the network to be completely operational.

#### `keyPair = DHT.keyPair([seed])`

Use this method to generate the required keypair for DHT operations.

Returns an object with `{publicKey, secretKey}`. `publicKey` holds a public key buffer, `secretKey` holds a private key buffer.

If you pass any options they are forwarded to dht-rpc.

#### `await node.destroy([options])`

Fully destroy this DHT node.

This will also unannounce any running servers.
If you want to force close the node without waiting for the servers to unannounce pass `{ force: true }`.

#### `node = DHT.bootstrapper(port, host, [options])`

If you want to run your own Hyperswarm network use this method to easily create a bootstrap node.

## Creating P2P servers

#### `const server = node.createServer([options], [onconnection])`

Create a new server for accepting incoming encrypted P2P connections.

Options include:

```js
{
  firewall (remotePublicKey, remoteHandshakePayload) {
    // validate if you want a connection from remotePublicKey
    // if you do return false, else return true
    // remoteHandshakePayload contains their ip and some more info
    return true
  }
}
```

You can run servers on normal home computers, as the DHT will UDP holepunch connections for you.

#### `await server.listen(keyPair)`

Make the server listen on a keyPair.
To connect to this server use keyPair.publicKey as the connect address.

#### `server.refresh()`

Refresh the server, causing it to reannounce its address. This is automatically called on network changes.

#### `server.on('connection', socket)`

Emitted when a new encrypted connection has passed the firewall check.

`socket` is a [NoiseSecretStream](https://github.com/holepunchto/hyperswarm-secret-stream) instance.

You can check who you are connected to using `socket.remotePublicKey` and `socket.handshakeHash` contains a unique hash representing this crypto session (same on both sides).

#### `server.on('listening')`

Emitted when the server is fully listening on a keyPair.

#### `server.address()`

Returns an object containing the address of the server:

```js
{
  ;(host, // external IP of the server,
    port, // external port of the server if predictable,
    publicKey) // public key of the server
}
```

You can also get this info from `node.remoteAddress()` minus the public key.

#### `await server.close()`

Stop listening.

#### `server.on('close')`

Emitted when the server is fully closed.

## Connecting to P2P servers

#### `const socket = node.connect(remotePublicKey, [options])`

Connect to a remote server. Similar to `createServer` this performs UDP holepunching for P2P connectivity.

The remote public key can be encoded as either a buffer, a hex string or a z-base32 string.

Options include:

```js
{
  nodes: [...], // optional array of close dht nodes to speed up connecting
  keyPair // optional key pair to use when connection (defaults to node.defaultKeyPair)
}
```

#### `socket.on('open')`

Emitted when the encrypted connection has been fully established with the server.

#### `socket.remotePublicKey`

The public key of the remote peer.

#### `socket.publicKey`

The public key of the local socket.

## Additional peer discovery

#### `const stream = node.lookup(topic, [options])`

Look for peers in the DHT on the given topic. Topic should be a 32 byte buffer (normally a hash of something).

The returned stream looks like this

```js
{
  // Who sent the response?
  from: { id, host, port },
  // What address they responded to (i.e. your address)
  to: { host, port },
  // List of peers announcing under this topic
  peers: [ { publicKey, nodes: [{ host, port }, ...] } ]
}
```

To connect to the peers you should afterwards call `connect` with those public keys.

If you pass any options they are forwarded to dht-rpc.

#### `const stream = node.announce(topic, keyPair, [relayAddresses], [options])`

Announce that you are listening on a key-pair to the DHT under a specific topic.

When announcing you'll send a signed proof to peers that you own the key-pair and wish to announce under the specific topic. Optionally you can provide up to 3 nodes, indicating which DHT nodes can relay messages to you - this speeds up connects later on for other users.

An announce does a parallel lookup so the stream returned looks like the lookup stream.

Creating a server using `dht.createServer` automatically announces itself periodically on the key-pair it is listening on. When announcing the server under a specific topic, you can access the nodes it is close to using `server.nodes`.

If you pass any options they are forwarded to dht-rpc.

#### `await node.unannounce(topic, keyPair, [options])`

Unannounce a key-pair.

If you pass any options they are forwarded to dht-rpc.

## Mutable/immutable records

#### `const { hash, closestNodes } = await node.immutablePut(value, [options])`

Store an immutable value in the DHT. When successful, the hash of the value is returned.

If you pass any options they are forwarded to dht-rpc.

#### `const { value, from } = await node.immutableGet(hash, [options])`

Fetch an immutable value from the DHT. When successful, it returns the value corresponding to the hash.

If you pass any options they are forwarded to dht-rpc.

#### `const { publicKey, closestNodes, seq, signature } = await node.mutablePut(keyPair, value, [options])`

Store a mutable value in the DHT.

If you pass any options they are forwarded to dht-rpc.

#### `const { value, from, seq, signature } = await node.mutableGet(publicKey, [options])`

Fetch a mutable value from the DHT.

Options:

- `seq` - OPTIONAL, default `0`, a number which will only return values with corresponding `seq` values that are greater than or equal to the supplied `seq` option.
- `latest` - OPTIONAL - default `false`, a boolean indicating whether the query should try to find the highest seq before returning, or just the first verified value larger than `options.seq` it sees.

Any additional options you pass are forwarded to dht-rpc.

## Additional API

See [dht-rpc](https://github.com/mafintosh/dht-rpc) for the additional APIs the DHT exposes.

## CLI

You can start a DHT node in the command line:

```sh
npm install -g hyperdht
```

Run a DHT node:

```sh
hyperdht # [--port 0] [--host 0.0.0.0] [--bootstrap <comma separated list of ip:port>]
```

Or run multiple nodes:

```sh
hyperdht --nodes 5 # [--host 0.0.0.0] [--bootstrap <list>]
```

Note: by default it uses the [mainnet bootstrap nodes](lib/constants.js).

#### Isolated DHT network

To create your own DHT network is as follows:

1. Run your first bootstrap node:

```sh
hyperdht --bootstrap --host (server-ip) # [--port 49737]
```

Important: it requires the port to be open.

Now your bootstrap node is ready to use at `(server-ip):49737`, for example:

```js
const dht = new DHT({ bootstrap: ['(server-ip):49737'] })
```

Note: You could configure some DNS for the bootstrap IP addresses.

For the network to be fully operational it needs at least one persistent node.

2. Provide the first node by using your own bootstrap values:

```sh
hyperdht --port 49738 --bootstrap (server-ip):49737
```

Important: it requires the port to be open too.

You need to wait ~30 mins for the node to become persistent.

Having persistent nodes in different places makes the network more decentralized and resilient!

For more information: [`examples/isolated-dht.mjs`](examples/isolated-dht.mjs)

## License

MIT
