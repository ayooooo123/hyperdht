# dht-transport-policy

Per-peer transport policy for [hyperdht](https://github.com/holepunchto/hyperdht):
a **trusted-peer whitelist** that routes each connection over the **direct**
transport (fast, holepunched, exposes your IP) or a **masked** transport (Tor /
relay — hides your IP, slower). This is the piece that reconciles "mask my IP"
with "don't kill direct low-latency connections": you don't get both on one
connection, so you choose per peer.

Pairs with [dht-relay-tor](../dht-relay-tor) for the masked transport, but the
router is transport-agnostic — any object with `.connect(publicKey)` works, so
Nym/I2P/WireGuard drop in unchanged.

## Idea

```
                         ┌─ trusted (whitelist) ─→  direct  →  holepunch  (fast, IP exposed)
 router.connect(key) ──┤
                         └─ everyone else       ─→  masked  →  Tor/relay  (private, slower)
```

Default posture is **private-by-default**: unknown peers are masked, and you
_opt in_ to direct connections by adding a peer to the trust list — e.g. from a
UI where the user imports keys of devices/people they trust. Flip it with
`defaultMode`/`trustedMode` if you'd rather be direct-by-default and mask only
specific peers.

## Usage

```js
const DHT = require('hyperdht')
const RelayedDHT = require('@hyperswarm/dht-relay')
const TorStream = require('dht-relay-tor')
const { TrustList, TransportRouter } = require('dht-transport-policy')

const trust = new TrustList()
trust.add('yhdoqba8…') // hex, z-base-32, or a 32-byte buffer

const direct = new DHT()
const masked = new RelayedDHT(await TorStream.connect({ onion: '<relay>.onion' }))

const router = new TransportRouter({ direct, masked, trust })

const conn = router.connect(peerPublicKey) // direct if trusted, else over Tor
```

## Wiring a UI to import trusted peers

`TrustList` is an `EventEmitter` built for a front-end:

```js
trust.on('update', () => render(trust.list())) // live re-render on any change

// user pastes / scans keys to trust:
trust.import([{ id: 'yhdoqba8…', alias: 'my-laptop' }])

// persist however the UI likes (localStorage, a file, a Hyperbee):
localStorage.setItem('trust', JSON.stringify(trust.toJSON()))

// restore next launch:
const trust = TrustList.fromJSON(JSON.parse(localStorage.getItem('trust') || '[]'))
```

Keys are accepted as hex, z-base-32
([hypercore-id-encoding](https://github.com/holepunchto/hypercore-id-encoding)),
or raw buffers and normalised to one id, so the same peer added in different
forms is a single entry. `example/policy-swarm.js` shows the whole stack wired to
a JSON file that stands in for the UI's persistence.

## API

### `TrustList`

- `new TrustList(entries?)` — seed from keys or `{ id|publicKey|key, alias, note }`.
- `add(key, { alias, note })` / `remove(key)` / `has(key)` / `get(key)` / `clear()`.
- `import(entries)` — bulk add; emits one `update`.
- `list()` — array of `{ publicKey, id, alias, note }`.
- `toJSON()` / `TrustList.fromJSON(json)` — persist and restore.
- emits `update` with `{ type, entry|entries }` on every change.

### `TransportRouter`

- `new TransportRouter({ direct, masked?, trust?, defaultMode?, trustedMode?, strict? })`
  - `direct` (required): any `{ connect(publicKey, opts) }` — normally a `HyperDHT`.
  - `masked`: a ready `{ connect() }`, an async factory `() => Promise<{connect()}>` (lazy), or `null`.
  - `defaultMode` (`'masked'`) / `trustedMode` (`'direct'`): the policy.
  - `strict` (`true`): if a peer routes masked but no masked transport exists, throw rather than silently connect direct and leak your IP.
- `mode(key)` → `'direct' | 'masked'` — the decision, no connection made.
- `describe(key)` → `{ id, mode, trusted, entry }` — for a UI.
- `connect(key, opts)` — route and return the encrypted stream. Also `connectDirect` / `connectMasked` to force a mode.
- `ready()` — resolve a lazy masked factory up front.
- emits `connection` with `{ id, mode, publicKey, connection }`.

## Test

```sh
npm test
```

Unit tests for the trust list and router plus an end-to-end integration test on a
local testnet: a trusted peer is reached over the direct transport and an
untrusted peer over the relayed transport, chosen purely by the list.

## Scope / not yet

- **Outbound only.** This routes _your_ connections (do I expose my IP to this
  peer?). Inbound/server-side masking is a separate concern.
- **No auto-fallback across modes.** A masked peer does not silently fall back to
  direct (that would leak your IP); in `strict` mode it errors instead.

## License

MIT
