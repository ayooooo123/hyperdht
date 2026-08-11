# Private Routing: SURB Construction (Gate C — implementation-ready design)

**Status:** DESIGN — implementation-ready, NOT owner-approved, NOT wire-stable. Hand-rolled
on existing `crypto-suite` primitives; **no new dependency.** Implementation is gated behind
Step 0 (confirm group ops) → fixed test vectors → substitution/property/fuzz → external
cryptographic review, per the repo's standing bar.
**Date:** 2026-08-10
**Parent:** [`2026-08-10-private-routing-datagram-surb-design.md`](./2026-08-10-private-routing-datagram-surb-design.md)
**Construction:** Sphinx (Danezis–Goldberg) reply blocks. Reference implementations to
follow for vectors/shape: the Sphinx paper, Lightning BOLT-04 onion (forward direction),
Nym SURBs (reply direction).

## Step 0 — primitive availability (blocking)

The construction needs a **prime-order group** with scalar/point ops plus hash-to-scalar.
Confirm the pinned `sodium-universal` exposes, in order of preference:

1. **ristretto255** (preferred — prime order, no cofactor pitfalls): `crypto_scalarmult_ristretto255`,
   `crypto_scalarmult_ristretto255_base`, `crypto_core_ristretto255_scalar_{reduce,mul,add}`,
   `crypto_core_ristretto255_from_hash`.
2. **ed25519 group** (fallback): `crypto_scalarmult_ed25519[_base]`,
   `crypto_core_ed25519_scalar_{reduce,mul}`, `crypto_core_ed25519_from_uniform` — with
   explicit cofactor clearing and identity/low-order-point rejection (the ristretto option
   avoids this class of bug; prefer it).

`crypto-suite` already uses `crypto_scalarmult` (X25519), `crypto_generichash` (BLAKE2b),
and XChaCha20-Poly1305 — reuse those for the KDF and per-layer AEAD. **Do not** attempt the
Sphinx scalar blinding on raw X25519 (Montgomery); it lacks clean scalar arithmetic.

## Keys the initiator already has

Return-path relays are chosen from their **signed capability advertisements**
(`relay-capability.js`), which carry each relay's route-encryption public key. Treat that as
the relay's static group element `Y_i`. (If it is an X25519 key today, add a ristretto/edwards
route-key to the advertisement; note as a wire dependency.)

## Per-hop key schedule (Sphinx blinding)

Return path `H_1 … H_m` (initiator is the terminal reader). `B` = group base point,
`L` = group order, `H_s` = BLAKE2b reduced to a scalar, domain-separated.

```
x_1   = random scalar
α_1   = x_1 · B                       # ephemeral group element for hop 1
for i in 1..m:
    s_i     = x_i · Y_i               # DH shared secret with hop i  (relay computes s_i = y_i · α_i)
    b_i     = H_s("surb/blind" ‖ α_i ‖ s_i)
    α_{i+1} = b_i · α_i
    x_{i+1} = b_i · x_i  (mod L)
```

From each `s_i` derive, via domain-separated BLAKE2b:
- `k_mac_i`   — header MAC key
- `k_hdr_i`   — header stream-cipher key (layer of β)
- `k_pay_i`   — payload AEAD key + nonce prefix (XChaCha20-Poly1305)

## SURB structure (fixed size)

- **Header β**: fixed-length, `m_max` slots (recommend `m_max = 3` to mirror the forward
  3-hop path and fit the cell). Each layer, encrypted under `k_hdr_i`, contains: next-hop id,
  `α`-advance is implicit via blinding (Sphinx carries per-hop routing info + the next MAC).
  Padded with PRG output so every hop sees a constant-size β.
- **Per-layer MAC γ_i** over β_i under `k_mac_i` (integrity; a hop rejects a tampered header).
- **Payload slot**: fixed size, sized so `|β| + |γ| + |α_1| + |payload|` ≤ the 1,200-byte
  outer cell budget (compute against `CAPABILITY_ADVERTISEMENT`/cell constants; if it does
  not fit at `m_max=3`, reduce payload and fragment via `fragments.js`).

The initiator retains `openKeys = {k_pay_1 … k_pay_m}` (the "reply secrets").

## Reply direction (why hops *encrypt*)

A SURB is the reply path, so the direction is inverted vs a forward onion: the responder
puts its plaintext in the payload slot; **each hop adds one AEAD layer** under its `k_pay_i`;
the initiator, holding all `k_pay_i`, peels all layers at the end. No hop can read the reply;
the responder cannot read it after the first hop wraps it.

## API (`lib/private/surb.js`)

```
buildSurb({ returnPath: [Y_1..Y_m], epoch, now })
    → { surb: { firstHop: H_1, alpha: α_1, header: β, mac: γ_1 }, openKeys }

processSurbHop(surb, hopRouteSecretKey)          // relay side, one hop
    → { nextHop, surb: { alpha: α_{i+1}, header: β_{i+1}, mac: γ_{i+1} },
        wrapPayload(payload) }                    // adds this hop's AEAD layer
    // rejects on: bad MAC, replayed nullifier (below), expired epoch

openSurbPayload(wrappedPayload, openKeys)         // initiator side
    → plaintext | throws on AEAD failure
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

1. Header integrity: a hop rejects any β it cannot MAC-verify under `k_mac_i`.
2. Forward-path secrecy: the SURB is unreadable to every forward hop (inner AEAD).
3. Reply secrecy: no return hop and not the responder can read the reply payload; only the
   initiator (holding `openKeys`) can.
4. Locality: the responder learns only `H_1`; each hop learns only its next hop.
5. Single-use: per-hop nullifier rejects replay within the epoch; keys/`openKeys` erased on
   use, expiry, or teardown.
6. Group hygiene: reject identity / low-order elements (moot under ristretto); constant-time
   scalar ops.
7. Fixed size: β and payload are constant-length with PRG padding — no length leak.
8. Additive: absent a SURB, behavior is exactly today's correlated-reply / STREAM reply.

## Implementation gate (do not skip)

1. Confirm group ops (Step 0). 2. Implement `surb.js` + integration behind an off-by-default
flag. 3. **Fixed test vectors** (adapt Sphinx/BOLT-04 vectors). 4. Substitution, property,
and fuzz tests (tampered β, wrong key, replayed nullifier, truncated payload, cross-epoch).
5. External cryptographic review. Only then is the wire format stable.

## Open questions

- Exact `m_max` and payload size against the 1,200-byte cell (and stacked with anything the
  request already carries); fragmenting large replies.
- Route-key type in the capability advertisement (ristretto/edwards vs current X25519) — a
  wire dependency if the current key is X25519-only.
- Whether the responder needs > 1 reply (multi-SURB batch) for `get` responses that exceed
  one payload slot.
