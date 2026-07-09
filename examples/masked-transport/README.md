# Masked transport for HyperDHT (Tor, via dht-relay)

A working prototype that runs the **Hyperswarm DHT over a Tor circuit**, so a
client's source IP is never exposed to the swarm — the same idea iroh ships as
`iroh-tor-transport`, but built on Holepunch's existing
[`@hyperswarm/dht-relay`](https://github.com/holepunchto/hyperswarm-dht-relay)
instead of a new fork of the DHT.

> Status: experimental prototype / proof of concept.

## The idea in one paragraph

dht-relay already lets a client speak the full DHT API (`connect`, `lookup`,
`announce`, `createServer`) over an arbitrary **framed `Duplex` stream** to a
*relay node*, which holds the real UDP presence on the swarm. Its built-in TCP
transport is literally `@hyperswarm/secret-stream` over a `net.Socket`. So a
"Tor transport" needs **no new protocol** — you obtain the socket by dialing the
relay's Tor hidden service through Tor's SOCKS5 proxy, then hand it to the same
secret-stream wrapper. Your machine never opens a UDP socket to the swarm and
never reveals its IP; the relay node does all holepunching on your behalf.

```
 service peer  <-- DHT holepunch (UDP) -->  relay node  <-- secret-stream over Tor -->  masked client
   (on swarm)                                (on swarm)          (no swarm-facing IP)
```

## What's here

| File | Role |
| --- | --- |
| `lib/socks5.js` | Minimal SOCKS5 CONNECT client (RFC 1928, no-auth). The only Tor-specific code. |
| `lib/tor-transport.js` | `connect()` dials the relay onion through Tor and wraps it in secret-stream; `wrap()` is the shared wrapper. |
| `relay-server.js` | The relay node: a hyperdht node + a local TCP endpoint bridged into it via `relay()`. |
| `masked-client.js` | A real client that reaches the relay over Tor and drives the DHT. |
| `demo-local.js` | End-to-end verification with **no Tor required** (localhost TCP stands in for the circuit). |

## Verify it locally (no Tor needed)

```sh
npm install
npm run demo
```

Expected output ends with:

```
[demo] masked client ready — it has a DHT handle but no UDP socket of its own
[demo] round-trip reply from service peer: "echo:hello-over-masked-transport"
[demo] PASS ✅  connection established over the relayed transport
```

This exercises the exact code path a Tor client uses — the relay protocol over a
secret-stream `Duplex` — differing only in how the socket is obtained. Swapping
`net.connect` for the SOCKS5 dialer in `lib/tor-transport.js#connect` is the
whole difference.

## Run it for real over Tor

1. **Run a Tor daemon** with a hidden service in front of the relay's TCP port.
   Add to your `torrc`:

   ```
   HiddenServiceDir /var/lib/tor/hyperdht-relay/
   HiddenServicePort 8080 127.0.0.1:8080
   ```

   Start Tor, then read the generated onion address:
   `cat /var/lib/tor/hyperdht-relay/hostname`.

2. **Start the relay** (this machine has a normal UDP presence on the swarm):

   ```sh
   node relay-server.js 8080
   ```

3. **Run a masked client** on any machine with Tor's SOCKS proxy on
   `127.0.0.1:9050`:

   ```sh
   node masked-client.js <relay-onion>.onion 8080 [targetPeerPublicKeyHex]
   ```

   The client's DHT traffic and its peer connections all ride the Tor circuit to
   the relay; its IP never touches the swarm.

## Honest tradeoffs

- **This masks IP by giving up direct connections.** All traffic goes through
  the relay node over Tor, so you pay Tor latency and the relay is on the path.
  You cannot get *both* a hidden IP *and* a direct low-latency holepunch on the
  same connection — masking means routing through an overlay. The productive
  pattern is a **per-peer policy**: direct holepunch for peers you don't mind
  exposing your IP to, masked-relay for the ones you do. That policy layer is
  the natural next step and is not included here.
- **Trust in the relay.** The relay node sees your (Tor-exit) connection and
  proxies your DHT operations. Run your own, or treat it like a VPN/exit you
  trust. It does *not* see your real IP (Tor handles that) or your connection
  contents (end-to-end Noise via secret-stream to the far peer).
- **Custodial keys.** By default the relayed node lets the relay hold the DHT
  key material (`custodial` mode in dht-relay). dht-relay also supports a
  non-custodial handshake; wire that up if the relay should never see your keys.

## Where this could go next

- A `socks5`-style wrapper for **other overlays** (I2P SAM, a Nym SOCKS proxy,
  a WireGuard endpoint) — each is "get a `Duplex` a different way," same seam.
- The **per-peer transport policy** in the swarm layer so a single app can mix
  direct and masked peers.
- **Offline links** (BLE/LoRa/serial): the `Duplex` seam ports over, but they
  need their own discovery instead of the DHT and are a separate effort.
