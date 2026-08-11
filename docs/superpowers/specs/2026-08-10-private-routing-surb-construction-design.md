# Private Routing: SURB Construction (Gate C — implementation-ready design)

**Status:** DESIGN — implementation-ready, NOT owner-approved, NOT wire-stable. Hand-rolled
on existing `crypto-suite` primitives; **no new dependency.** Implementation is gated behind
Step 0 (confirm group ops) → fixed test vectors → substitution/property/fuzz → external
cryptographic review, per the repo's standing bar.
**Date:** 2026-08-10
**Parent:** [`2026-08-10-private-routing-datagram-surb-design.md`](./2026-08-10-private-routing-datagram-surb-design.md)
**Construction:** onion reply blocks with **per-hop independent X25519 DH** (not Sphinx
scalar-blinding — see Step 0). Layered-header + payload discipline follows Sphinx / Nym
SURBs and Lightning BOLT-04.

## Step 0 — primitive availability (RESOLVED 2026-08-10)

Verified against the pinned deps (`sodium-universal@5.0.1` over `sodium-native@5.1.0`,
Node 22):

- **Available:** X25519 `crypto_scalarmult` + `crypto_scalarmult_base`; `crypto_box_seal` /
  `crypto_box_seal_open`; `crypto_generichash` (BLAKE2b); XChaCha20-Poly1305 AEAD; ed25519
  point `crypto_scalarmult_ed25519[_base]`, `crypto_core_ed25519_scalar_reduce`,
  `crypto_core_ed25519_add`.
- **NOT available:** ristretto255 (nothing); `crypto_core_ed25519_scalar_mul` (scalar×scalar).

Consequence: the classic Sphinx per-hop **blinding chain** (`x_{i+1} = b_i · x_i mod L`) is
**not implementable** on these deps — it needs scalar×scalar mult. The construction instead
uses **per-hop independent X25519 ephemerals**: only point DH (`crypto_scalarmult`), which
exists and which `crypto-suite` already uses. No new dependency, no scalar arithmetic, no
ristretto/cofactor handling (X25519 clamps/handles cofactor for DH).

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
- `k_mac_i`   — header MAC key
- `k_hdr_i`   — header stream-cipher key (layer of β)
- `k_wrap_i`  — payload **wrap** key + nonce prefix (XChaCha20-Poly1305); relay hop `i`
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

## Reply direction (why hops *encrypt*)

A SURB is the reply path, so the direction is inverted vs a forward onion — **but no relay
(including the first hop `H_1`) and no SURB holder may ever recover plaintext.** The
responder MUST first **encapsulate its plaintext to the SURB's one-time public key `E_pub`**
— concretely `crypto_box_seal(plaintext, E_pub)` (X25519 sealed box; available in
`sodium-universal`, no exotic group op needed for the reply seal) — producing ciphertext
`P_0`. Only the initiator, holding `E_priv`, can open it; not the responder afterward, and
not any relay. Only `P_0` (never plaintext) is handed to `H_1`. Each return hop `i` then
applies its `k_wrap_i` transform to the **ciphertext** (bitwise unlinkability across links,
so the reply is not correlatable hop-to-hop); the initiator strips every wrap layer with
`k_wrap_1..m` and decapsulates with `E_priv`. A SURB does not hide *that* a reply exists
from the responder — it authored the plaintext — but it hides the initiator's network
location and the return path (the responder learns only `H_1`).

## API (`lib/private/surb.js`)

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

- Each hop derives a **nullifier** `n_i = H("surb/nullifier" ‖ s_i)` and records it in a
  per-epoch bounded set; a second SURB presenting the same `n_i` in the epoch is rejected
  (reuse would let a hop link two replies). This reuses the epoch discipline already in
  `crypto-suite`/`fragments.js` (`epochExpiresAt`); the set is cleared at rollover.
- The initiator uses each SURB exactly once and issues fresh SURBs (fresh `x_1`) per request;
  batch pre-issue is allowed, each single-use.

## Security invariants

1. Header integrity: the routing area `β` is a fixed `RHO`-byte buffer encrypted with a PRG
   keystream (`ρ` = BLAKE2b-CTR keyed by the hop DH secret) and authenticated by a
   keyed-BLAKE2b MAC (`μ`) carried alongside it; a hop that fails the MAC (wrong key or
   tampered `β`/MAC) rejects before doing anything else.
2. Forward-path secrecy: the SURB is unreadable to every forward hop (inner AEAD).
3. Reply secrecy from *all relays and any SURB holder*: the responder encapsulates to the
   SURB's public key `E_pub`; only the initiator, holding `E_priv` (which never travels),
   can decrypt. No return relay — including `H_1` — and no party that merely holds the SURB
   can recover plaintext; relays only wrap ciphertext. (Says nothing about the responder,
   which authored the plaintext — see invariant 4.)
4. Locality: the responder learns only `H_1`; each hop learns only its next hop.
5. Single-use: per-hop nullifier rejects replay within the epoch; keys/`openKeys` erased on
   use, expiry, or teardown.
6. Group hygiene: X25519 DH via `crypto-suite.keyAgreement`, which rejects all-zero /
   low-order shared secrets.
7. Constant size / position-hiding by length: every hop sees exactly `RHO` header bytes
   (decrypt-and-shift with Sphinx filler). A relay cannot infer its index or the remaining
   path length from header size. **Tested** — round-trip for path lengths 1..`MAX_HOPS` plus
   a length-invariance assertion.
8. Additive: absent a SURB, behavior is exactly today's correlated-reply / STREAM reply.

## Implementation gate (do not skip)

1. Confirm group ops (Step 0). 2. Implement `surb.js` + integration behind an off-by-default
flag. 3. **Fixed test vectors** (adapt Sphinx/BOLT-04 vectors). 4. Substitution, property,
and fuzz tests (tampered β, wrong key, replayed nullifier, truncated payload, cross-epoch).
5. External cryptographic review. Only then is the wire format stable.

## Open questions

- Exact `m_max` and payload size against the 1,200-byte cell (and stacked with anything the
  request already carries); fragmenting large replies.
- Route-key type: **resolved** — relays already publish X25519 route keys, used directly for
  per-hop DH; no advertisement wire change.
- Whether the responder needs > 1 reply (multi-SURB batch) for `get` responses that exceed
  one payload slot.

## Reference implementation (built + tested 2026-08-10)

`lib/private/surb.js` + `test/private/surb.js` (brittle). Per-hop X25519 on `crypto-suite`
(`keyAgreement`, `seal`/`open`) + `crypto_box_seal` for the reply; **fixed-size Sphinx
header** (`MAX_HOPS = 4`, `HOP = 81`, `RHO = 324`) with filler, PRG = BLAKE2b-CTR, MAC =
keyed BLAKE2b (16 B). **9/9 tests, 18/18 asserts pass** on the pinned sodium (Node 22):
round-trip recovers the reply for **every path length 1..4**; every hop sees a constant
`RHO`-byte header (length-invariance); first hop never sees plaintext; a hop learns only its
next hop; tampered header, tampered MAC, tampered payload, and wrong route key all rejected;
malformed input rejected fail-closed; nullifiers deterministic per hop and fresh per SURB.
Still NOT wired into the DHT and NOT wire-stable — remaining before a format freeze: fixed
cross-impl test vectors, statistical review of filler indistinguishability, payload-size
budget vs the 1,200-byte cell, and external cryptographic review.
