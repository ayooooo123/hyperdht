# dht-relay-tor

Run the [Hyperswarm DHT](https://github.com/holepunchto/hyperdht) over a **Tor
circuit**, so a client's source IP is never exposed to the swarm. A Tor
transport for [`@hyperswarm/dht-relay`](https://github.com/holepunchto/hyperswarm-dht-relay),
in the same shape as its built-in `/tcp` and `/ws` wrappers.

> :test_tube: Experimental. Same spirit as iroh's `iroh-tor-transport`, but built
> on the existing dht-relay seam rather than a fork of the DHT.

## How it works

dht-relay lets a client speak the full DHT API (`connect`, `lookup`, `announce`,
`createServer`) over a framed `Duplex` to a **relay node** that holds the real
UDP presence on the swarm. Its TCP transport is just `@hyperswarm/secret-stream`
over a socket. So a Tor transport needs no new protocol — you obtain the socket
by dialing the relay's hidden service through Tor's SOCKS5 proxy, then hand it to
the same secret-stream wrapper. The client never opens a UDP socket to the swarm;
the relay does all holepunching on its behalf.

```
 service peer  <-- DHT holepunch (UDP) -->  relay node  <-- secret-stream over Tor -->  masked client
   (on swarm)                                (on swarm)          (no swarm-facing IP)
```

The SOCKS5 client is buffer-free (`b4a` + byte indexing) and the TCP module is
selected per-runtime (`net` on Node, `bare-tcp` on Bare), so it runs on Bare and
Pear as well as Node.

## Install

```sh
npm install dht-relay-tor @hyperswarm/dht-relay hyperdht
```

## Usage

Relayed (client) side — requires a Tor daemon with a SOCKS proxy on `127.0.0.1:9050`:

```js
const DHT = require('@hyperswarm/dht-relay')
const Stream = require('dht-relay-tor')

const dht = new DHT(await Stream.connect({ onion: '<relay>.onion', port: 8080 }))
await dht.ready()

// From here the API matches hyperdht.
const conn = dht.connect(remotePublicKey)
```

Relay side — an ordinary hyperdht node bridged to a TCP endpoint (published as a
hidden service):

```js
const net = require('net')
const HyperDHT = require('hyperdht')
const { relay } = require('@hyperswarm/dht-relay')
const { wrap } = require('dht-relay-tor')

const dht = new HyperDHT()
net.createServer((socket) => relay(dht, wrap(false, socket))).listen(8080, '127.0.0.1')
```

## API

#### `const stream = await Stream.connect(options)`

Dial the relay's onion over Tor and return a Stream ready for `new DHT(stream)`.

- `onion` (required): the relay's `.onion` hidden-service address.
- `port` (default `8080`): the hidden-service port.
- `proxyHost` / `proxyPort` (default `127.0.0.1:9050`): Tor's SOCKS5 proxy.
- `timeout` (default `30000`): SOCKS5 handshake timeout in ms.
- any other options are forwarded to `@hyperswarm/secret-stream`.

#### `const stream = Stream.wrap(isInitiator, socket[, options])`

Wrap an already-connected socket in the transport Stream. `isInitiator` is
`true` on the relayed client, `false` on the relay. Used by the relay server and
by callers who dial the socket themselves.

#### `const Stream = require('dht-relay-tor')`

The default export is `@hyperswarm/secret-stream` — the same Stream class
dht-relay's `/tcp` transport exports — so `new Stream(isInitiator, socket)` works
identically.

## Run it over real Tor

1. Add a hidden service for the relay's port to your `torrc`:

   ```
   HiddenServiceDir /var/lib/tor/hyperdht-relay/
   HiddenServicePort 8080 127.0.0.1:8080
   ```

   Start Tor, then read the address: `cat /var/lib/tor/hyperdht-relay/hostname`.

2. Start the relay: `node example/relay-server.js 8080`
3. Run a masked client: `node example/masked-client.js <relay-onion> 8080 [targetKeyHex]`

## Test

```sh
npm test
```

Covers the SOCKS5 client against a mock proxy and an end-to-end relayed
connection over the transport on a local testnet (no Tor required — it exercises
the same code path, differing only in how the socket is obtained).

## Tradeoffs (read before using)

- **Masking IP means giving up direct connections.** All traffic goes through the
  relay over Tor, so you pay Tor latency and the relay is on the path. You cannot
  have a hidden IP _and_ a direct low-latency holepunch on the same connection —
  masking means routing through an overlay. The productive pattern is a per-peer
  policy (direct for peers you don't mind, masked for the ones you do); that lives
  above this transport, not in it.
- **Trust in the relay.** It proxies your DHT operations and sees your Tor-exit
  connection — not your real IP (Tor handles that) nor your payload (end-to-end
  Noise to the far peer). Run your own, or treat it like a trusted exit.
- **Custodial keys by default.** dht-relay's default lets the relay hold the DHT
  key material. Wire up its non-custodial handshake if the relay should never see
  your keys.

## License

MIT
