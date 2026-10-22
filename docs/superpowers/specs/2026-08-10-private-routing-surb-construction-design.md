# Private Routing: SURB Construction (Gate C)

**Status:** implemented with owner-approved experimental wire and live DHT
integration; external cryptographic review and wire stabilization remain open.
The original construction sketch and primitive inventory below are historical:
the [ownership amendment](#ownership-amendment--2026-09-06) supersedes its
buffer-based APIs and manual replay reset. See
[current implementation and open gates](../../private-routing-migration.md#current-implementation).
**Date:** 2026-08-10
**Parent:** [`2026-08-10-private-routing-datagram-surb-design.md`](./2026-08-10-private-routing-datagram-surb-design.md)
**Construction:** onion reply blocks with **per-hop independent X25519 DH** (not Sphinx
scalar-blinding — see Step 0). Layered-header + payload discipline follows Sphinx / Nym
SURBs and Lightning BOLT-04.

## Step 0 — primitive availability (RESOLVED 2026-08-10)

Historical inventory against `sodium-universal@5.0.1` over the original
`sodium-native@5.1.0` baseline, Node 22:

- **Available:** X25519 `crypto_scalarmult` + `crypto_scalarmult_base`; `crypto_box_seal` /
  `crypto_box_seal_open`; `crypto_generichash` (BLAKE2b); XChaCha20-Poly1305 AEAD; ed25519
  point `crypto_scalarmult_ed25519[_base]`, `crypto_core_ed25519_scalar_reduce`,
  `crypto_core_ed25519_add`.
- **NOT available:** ristretto255 (nothing); `crypto_core_ed25519_scalar_mul` (scalar×scalar).

That baseline lacked the scalar×scalar operation needed for the classic Sphinx
blinding chain (`x_{i+1} = b_i · x_i mod L`), so this design selected independent
per-hop X25519 ephemerals. Gate D later introduced a pinned native scalar-multiply
binding; Gate C still uses the independent-X25519 construction. That dependency
change does not authorize a new SURB wire or a JavaScript scalar implementation.

## Keys the initiator already has

Return-path relays are chosen from their signed capability advertisements
(`relay-capability.js`); each carries a route-encryption public key that is **already
X25519** (`caps-responder.js` derives it via `crypto_scalarmult_base` from the relay's route
secret). Use it directly as the relay DH key `Y_i` — no new key type, no advertisement wire
change.

## Per-hop key schedule (per-hop X25519 ephemerals)

Return path `H_1 … H_m` (initiator is the terminal reader). Per hop, one fresh ephemeral +
one X25519 DH:

```
for i in 1..m:
    e_i  = random X25519 scalar
    E_i  = crypto_scalarmult_base(e_i)      # ephemeral pubkey, carried in header layer i
    s_i  = crypto_scalarmult(e_i, Y_i)      # DH secret (relay recomputes s_i = crypto_scalarmult(y_i, E_i))
```

Ephemerals are independent per hop (no blinding chain). Each hop receives its `E_i` **in the
clear**: the SURB head carries `E_1`, and decrypting layer `i` reveals the next hop's clear
`E_{i+1}`. At `m_max = 3` that is 3×32 B of ephemerals — within the cell budget.

From each `s_i` derive, via domain-separated BLAKE2b:

- `k_mac_i` — header MAC key
- `k_hdr_i` — header stream-cipher key (layer of β)
- `k_wrap_i` — payload **wrap** key + nonce prefix (XChaCha20-Poly1305); relay hop `i`
  applies it to **ciphertext only**, never plaintext

Separately, the initiator generates a fresh **one-time reply keypair** `(E_pub, E_priv)`
and embeds **only `E_pub`** (a public encapsulation target) in the SURB. `E_pub` is safe to
place anywhere — a relay or any SURB holder learns nothing exploitable from it. The matching
secret `E_priv` **never travels**; the initiator keeps it in `openKeys`. No symmetric reply
secret is ever put in the SURB.

## SURB structure (fixed size)

- **Per-hop header unit** handed to hop `i`: `{ E_i (clear), β_i (encrypted under
`k_hdr_i`), γ_i }`. The hop computes `s_i = crypto_scalarmult(y_i, E_i)` from the
  **clear** `E_i`, derives `k_mac_i`/`k_hdr_i`/`k_wrap_i`, verifies `γ_i` over `β_i`, then
  decrypts `β_i` to obtain `{ nextHop, E_{i+1} (clear), β_{i+1}, γ_{i+1} }` for the next
  hop. `β` is fixed-length (`m_max = 3`) and PRG-padded so every hop sees a constant size.
  `E_i` **must** be clear — a hop needs it to derive the very key that decrypts its own layer.
- **Per-layer MAC γ_i** over β_i under `k_mac_i` (integrity; a hop rejects a tampered header).
- **Payload slot**: fixed size, holds the responder-sealed **ciphertext** (see Reply
  direction), then relay wrap layers. Sized so `|β| (each layer carries E_i) + |γ_1| + |payload|` ≤ the
  1,200-byte outer cell budget; if it does not fit at `m_max=3`, reduce payload and
  fragment via `fragments.js`.

The initiator retains `openKeys = { E_priv, k_wrap_1 … k_wrap_m }` — `E_priv` never leaves
the initiator.

## Reply direction (why hops _encrypt_)

A SURB is the reply path, so the direction is inverted vs a forward onion — **but no relay
(including the first hop `H_1`) and no SURB holder may ever recover plaintext.** The
responder MUST first **encapsulate its plaintext to the SURB's one-time public key `E_pub`**
— concretely `crypto_box_seal(plaintext, E_pub)` (X25519 sealed box; available in
`sodium-universal`, no exotic group op needed for the reply seal) — producing ciphertext
`P_0`. Only the initiator, holding `E_priv`, can open it; not the responder afterward, and
not any relay. Only `P_0` (never plaintext) is handed to `H_1`. Each return hop `i` then
applies its `k_wrap_i` transform to the **ciphertext** (bitwise unlinkability across links,
so the reply is not correlatable hop-to-hop); the initiator strips every wrap layer with
`k_wrap_1..m` and decapsulates with `E_priv`. A SURB does not hide _that_ a reply exists
from the responder — it authored the plaintext — but it hides the initiator's network
location and the return path (the responder learns only `H_1`).

## API (`lib/private/surb.js`)

Historical buffer-based sketch, superseded by the one-use authorities in the
[ownership amendment](#ownership-amendment--2026-09-06). These are not the current
call signatures.

```
buildSurb({ returnPath: [Y_1..Y_m], epoch, now })
    → { surb: { firstHop: H_1, ephem: E_1, header: β_1, mac: γ_1,
                replyPubKey: E_pub /* public; safe anywhere */ },
        openKeys: { E_priv, k_wrap_1..m } }        // E_priv stays with the initiator

// responder side — MUST run before sending to H_1; encapsulates to E_pub, never exposes plaintext
sealReply(surb, plaintext) → P_0                  // crypto_box_seal to surb.replyPubKey

processSurbHop(surb, hopRouteSecretKey)           // relay side — CIPHERTEXT ONLY
    → { nextHop, surb: { ephem: E_{i+1}, header: β_{i+1}, mac: γ_{i+1} },
        wrapCiphertext(P) }                        // applies k_wrap_i to ciphertext P
    // rejects on: bad MAC, replayed nullifier, expired epoch

openSurbPayload(wrapped, openKeys) → plaintext     // strip k_wrap layers, then crypto_box_seal_open with E_priv
```

- The SURB is carried inside the forward request's **source→destination inner AEAD**
  (existing `crypto-suite` context) so no forward-path hop can read it.
- Responder/exit consumes the SURB via a reply authority alongside
  `createDhtExitCorrelatedReplyAuthorityForIO`; DATAGRAM carriage + reassembly via
  `fragments.js`.

## Single-use / anti-replay

The manual-reset cache described here belongs to the original sketch. Current
replay admission and capability-window ownership follow the amendment below;
there is no production `createNullifierGuard.reset()` contract.

- Each hop derives a **nullifier** `n_i = H("surb/nullifier" ‖ s_i)`. A relay feeds it to a
  per-epoch replay cache (`createNullifierGuard`): a repeat in the epoch is rejected, and the
  cache is **fail-closed** — it never evicts, so a nullifier is never silently re-admitted;
  on overflow with a fresh nullifier it throws (`ERR_QUOTA_EXCEEDED`), forcing epoch rollover
  or more capacity rather than opening a replay window. This is **strict single-use up to
  capacity**, not a best-effort cache. Cleared at rollover (`reset()`); tie to the existing
  `epochExpiresAt` discipline. (The flood-to-refuse DoS is bounded by the relay's circuit
  quotas.)
- The initiator uses each SURB exactly once and issues fresh SURBs per request; batch
  pre-issue is allowed, each single-use.

## Security invariants

1. Header integrity: the routing area `β` is a fixed `RHO`-byte buffer encrypted with a PRG
   keystream (`ρ` = BLAKE2b-CTR keyed by the hop DH secret) and authenticated by a
   keyed-BLAKE2b MAC (`μ`) carried alongside it; a hop that fails the MAC (wrong key or
   tampered `β`/MAC) rejects before doing anything else.
2. Forward-path secrecy: the SURB is unreadable to every forward hop (inner AEAD).
3. Reply secrecy from _all relays and any SURB holder_: the responder encapsulates to the
   SURB's public key `E_pub`; only the initiator, holding `E_priv` (which never travels),
   can decrypt. No return relay — including `H_1` — and no party that merely holds the SURB
   can recover plaintext; relays only wrap ciphertext. (Says nothing about the responder,
   which authored the plaintext — see invariant 4.)
4. Locality: the responder learns only `H_1`; each hop learns only its next hop.
5. Single-use: fresh per-hop DH secret per SURB ⇒ fresh nullifier; the relay's fail-closed
   replay cache rejects any repeat within the epoch (strict up to capacity, no eviction).
   Keys/`openKeys` erased on use, expiry, or teardown.
6. Group hygiene: X25519 DH via `crypto-suite.keyAgreement`, which rejects all-zero /
   low-order shared secrets.
7. Constant size / position-hiding by length: every hop sees exactly `RHO` header bytes
   (decrypt-and-shift with Sphinx filler). A relay cannot infer its index or the remaining
   path length from header size. **Tested** — round-trip for path lengths 1..`MAX_HOPS` plus
   a length-invariance assertion.
8. Additive: absent a SURB, behavior is exactly today's correlated-reply / STREAM reply.

## Implementation gate (do not skip)

1. **Primitives and ownership:** implemented with bounded, one-use capabilities
   and authenticated context/replay binding.
2. **DHT integration:** implemented behind `experimentalSurbReplies: true`,
   including authenticated V2 requests, bounded SURB batches, per-fragment
   authorities, and relay-local live peeling.
3. **Conformance and adversarial coverage:** the current fixture and focused
   suites cover the amended construction. Original fixture/API descriptions in
   the dated reference sections are not a second implementation contract.
4. **External cryptographic review:** still open and not self-certifiable.
   Implementation tests and owner approval for experimentation do not establish
   independent conformance, filler indistinguishability, or production anonymity.

## Open questions

- The old framing and batch questions are resolved: the primitive accepts at
  most 512 plaintext bytes, and the live reply profile uses a 20-byte fragment
  header plus 492 bytes, at most eight fragments / 3,936 reply-message bytes.
- The V2 request allocator covers the existing 4,910-byte generic envelope
  ceiling; the largest legal immutable-put request with eight descriptors is
  4,839 bytes. These are different bounds, not a wire-limit increase.
- Advertised X25519 route keys remain the per-hop DH keys; no advertisement
  format change was needed.
- Independent cryptographic review, conformance, and public-mode approval remain
  open. Independently routed/timed replies or mixing need a separate reviewed
  design; current replies use the existing reverse relays and deadlines.

## Reference implementation (built + tested 2026-08-10)

Historical measurements and APIs from the initial reference, not current suite
totals or an active implementation checklist.

`lib/private/surb.js` + `test/private/surb.js` (brittle). Per-hop X25519 on `crypto-suite`
(`keyAgreement`, `seal`/`open`) + `crypto_box_seal` for the reply; **fixed-size Sphinx
header** (`MAX_HOPS = 4`, `HOP = 81`, `RHO = 324`) with filler, PRG = BLAKE2b-CTR, MAC =
keyed BLAKE2b (16 B), fail-closed per-epoch replay cache (`createNullifierGuard`),
`MAX_REPLY_BYTES = 512` (provisional) budget guard, and an optional deterministic seed seam for vectors.
**16/16 tests, 58/58 asserts pass** on the pinned sodium (Node 22): round-trip for **every
path length 1..4**; constant `RHO`-byte header (length-invariance); first hop never sees
plaintext; a hop learns only its next hop; tampered header/MAC/payload + wrong key rejected;
malformed input fail-closed; fail-closed replay guard (strict single-use up to capacity);
nullifiers deterministic per hop, fresh per SURB; 200-iter property/fuzz; a **byte-for-byte
conformance fixture** over all deterministic wire fields; payload-budget enforcement; and a
(weak) filler non-degeneracy sanity check. At that checkpoint it was not wired
into the DHT or wire-stable. Its then-open deterministic reply-vector, filler,
integration, and review questions must be read with the later amendments below.

## Reference hardening — 2026-09-05

The active reference implementation now rejects noncanonical X25519 public
encodings: the little-endian coordinate must be less than `2^255 - 19`, with
bit 255 clear. This check applies to public keys, not secret scalars. A direct
probe first showed that toggling bit 255 in `message.ephem` still opened the
original reply; the same probe now fails with `INVALID_ROUTE`. Valid generated
keys and the deterministic wire fixture are unchanged.

Temporary DH secrets, derived keys, PRG buffers, and decrypted routing buffers
are erased on success and failure. Returned plaintext and caller-owned
`openKeys` remain intact. An executable fault probe checked temporary-buffer
erasure at all 115 native-hash failure points of a four-hop build, and completed
a four-hop reply at the 512-byte limit.

The relay input is bounded to 608 payload bytes; the initiator input is bounded
to 624. Open-key arrays must contain one through four valid wrap-key pairs.
The suite is now in `test/private-routing.js`. Seeded choices replace
`Math.random`, the tamper loop requires rejection, and the weak filler
non-degeneracy check is removed.

Those hardening changes did not yet implement one-use ownership, authenticated
epoch transition, reply-mode selection, or live DATAGRAM integration. The
2026-09-06 ownership and integration amendments below supersede those gaps;
external cryptographic review remains open.

The initial hardening suite passed **21 tests / 100 assertions** under both
Linux Node and Bare, with a separate internal review. The advisory follow-up
adds low-order reply-public-key rejection: `sealReply` maps only the native
`Error('status: -1')` outcome to `INVALID_ROUTE`. Canonical encoding alone does
not exclude low-order curve points. Unknown native errors still propagate.
Node and Bare smoke checks verify that distinction, failed sealed-output
erasure, and invalid-MAC nullifier erasure. External cryptographic review is
still required.

## Ownership amendment — 2026-09-06

An internal architecture review (not external cryptographic review) found
that the 2026-09-05 reference still had reusable initiator secrets, optional
and late replay admission, and no cryptographic run or epoch binding. The
active reference now implements the reviewed amendment. It remains
experimental, off by default, and not wire-stable.

- **Per-hop context binding.** Each hop derives
  `hopRoot = BLAKE2b-256(key = X25519 shared, input = u16be(len) ||
"hyperdht-private-routes/surb-hop/v1" || u16be(58) || HopContext)` with
  `HopContext = u16be(1) || routeKey[32] || u64be(capabilityEpoch) ||
u64be(issuedAtMs) || u64be(expiresAtMs)` taken from the relay's signed
  capability. `rho`, `mu`, `wrap-key`, `wrap-nonce`, and `nullifier` keys are
  derived from `hopRoot`. The MAC covers `E_i || beta_i`. No context byte is
  on the return wire; the test asserts that for every leg. A header from another
  epoch or another route key derives a different MAC key and fails before any
  replay-store change. The advertised route key is therefore the run boundary:
  a relay must use a fresh route key pair per run and drain old keys only for
  the exact signed capability window. If route keys can be reused across runs,
  this contract is insufficient and a signed key-generation identifier must be
  added to the capability schema under human ratification.
- **Authorities, not buffers.** `buildSurb` returns `{ descriptor,
openAuthority }`; `createSurbCapabilityAuthority` recomputes the public key
  from the secret and rejects mismatch or expiry; `createSurbReplayAuthority`
  has no manual reset. `processSurbHop({ message, capabilityAuthority,
replayAuthority })` verifies the MAC, validates the hop block, admits the
  nullifier atomically, then wraps, and returns a one-use forwarding authority.
  `openSurbReply` consumes the open authority on the first attempt whether it
  succeeds or fails. Every authority is a frozen handle over private WeakMap
  state with erasure on consume, revoke, or expiry.
- **Inner reply.** `crypto_box_seal` is replaced by a fresh X25519 ephemeral
  plus XChaCha20-Poly1305 with associated data `"SURB-REPLY-V1" ||
replyBinding`; the builder and sealer must bind identical bytes. Overhead is
  unchanged at 48 bytes.
- **Sizes.** A 512-byte reply produces relay inputs of 932, 948, 964, and 980
  bytes and a 624-byte terminal payload, all within the 1,073-byte route
  payload. A 513-byte plaintext is rejected before encryption.

`node test/private/surb.js` passes **31 tests / 115 assertions**. The
conformance fixture was regenerated for the new key schedule. Removed exports:
`sealReply`, `openSurbPayload`, `nullifierOf`, `createNullifierGuard`; there
are no other callers. At this point, reply-mode selection, batch framing, the
492-byte fragment profile, and exit/initiator integration were not implemented.
The next section records their subsequent owner-approved experimental integration.

## Integration — 2026-09-06 (experimental, off by default)

Owner-approved wire, external cryptographic review still open. `ROUTED_REQUEST_V2`
(`0x0103`) carries `replyMode`, a batch id and up to eight 436-byte descriptors around
an unchanged V1 request; replies are fragmented under the 492-byte / eight-fragment
`SURB_REPLY_FRAGMENT_PROFILE` (3,936-byte ceiling, `RESPONSE_TOO_LARGE` above), one
independent SURB, reply key pair, open authority and terminal handle per fragment. The
exit's only SURB output is the sealed first-hop cell on its reverse link; relays peel
with `processRelaySurbHop` through the M3 facade's opt-in `surbHopPeel`; the endpoint
admits by terminal handle. `SURB_REQUIRED` never falls back to the correlated path and
is refused unless the controller was created with `experimentalSurbReplies: true`.
Later fixes add link-sealed physical carriage, relay-local replay ownership and
expiry enforcement, and required-mode puts including presence publication and
revocation. The live scenario proves exact maximum-size write readback and
authenticated absence after a period-scoped tombstone at a higher revision,
without correlated replies on the relevant exit. See [current implementation and evidence](../../private-routing-migration.md#current-implementation).
Current return relays and deadlines belong to the existing route; neither
independent return routing nor general timing anonymity is claimed.
