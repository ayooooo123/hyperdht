# Private Routing: Blinded Presence-Record Keys (Candidate Gate D — forward note)

**Status:** FORWARD-LOOKING REQUIREMENT — not a spec for current code. The component it
constrains (address-free private presence records for `lookup`/`announce`) is **not
implemented at Gate 3B1** (route construction). This note exists so the requirement is
captured before that gate is designed; it must be folded into that gate's spec, not
implemented standalone.
**Date:** 2026-08-10
**Relates to:** [`private-routing-v1.md`](../../private-routing-v1.md) (Required-mode
method contract: `lookup`/`announce` "use native address-free private presence records
only"; Security Contract: "DHT storage nodes see stored record keys and bounded
descriptor bytes" and "Route identities and route keys rotate independently from stable
Noise identities") and [`private-routing-logos-lessons.md`](../../private-routing-logos-lessons.md) item **D**.
**Prior art:** Tor v3 onion-service blinded public keys (per-time-period key derivation).

## What exists today (grounding)

- Destination opacity in the live routing path is **hash-based**, not key-blinded:
  `lib/private/opaque-destination.js` derives an opaque id via `sodium.crypto_generichash`
  over `KEY_DOMAIN = "hyperdht-private-routes/routed-dht/opaque-destination-key/v1"`
  (`destination-ref.js` `DESTINATION_REF_SIZE = 172`). This hides the destination from
  intermediaries **in-band**, per request. It is not a public key stored on DHT nodes.
- A `grep` of `lib/private` for `blind` returns zero hits: route/descriptor material
  **rotates by `epoch`** throughout, but there is no key-*blinding* primitive.
- Private presence records themselves — the address-free records `announce`/`lookup`
  would store on DHT nodes in `required` mode — do not exist yet.

## The requirement

When the private-presence gate is designed, the record that gets **stored on and served
by DHT storage nodes** MUST use **blinded, epoch-rotating keys**, not mere rotation:

- Derive a per-time-period **blinded public key** from the destination's stable key plus
  an epoch blinding factor (Tor v3 model), so the storage-key under which a presence
  record is published changes each period and cannot be linked across periods or back to
  the stable identity by the storing node.
- Rotation alone is insufficient: without blinding, a storage node can correlate
  successive records of the same private service (same key → same service over time), and
  can enumerate which services are present. Blinding removes both.
- The blinding scheme must let a legitimate looker-up who knows the destination's stable
  identity compute the current blinded key and locate/verify the record, while a storage
  node holding the record cannot.

## Why not now

The host has no code: there is no presence-record encode/store/lookup path at Gate 3B1.
Writing a full integration spec now would be speculative. This note is the carried
requirement; the actual key-derivation bytes, signature scheme, and storage-node
verification belong in the presence-record gate's own spec, where they can be grounded in
real encode/decode functions and test vectors.

## Acceptance (for the future gate)

- Presence-record storage keys are blinded per epoch; two records of the same service in
  different epochs are unlinkable by the storage node.
- A storage node cannot enumerate the set of private services it holds records for beyond
  what fixed-size padding and query volume reveal.
- A looker-up with the destination's stable identity resolves and verifies the current
  record; a node without it cannot.
- Extends the existing domain-separated `crypto_generichash` derivation discipline; no
  weakening of the Noise-identity/route-key separation.

## Concrete derivation (ready to fold into the presence-record gate)

Tor rend-spec-v3 key blinding, on the **same prime-order group as the Gate C SURB
construction** (ristretto255 preferred; ed25519 with Tor's clamping as fallback) — one
group dependency for both gates, no new library.

Let `(A, a)` be the destination's stable identity keypair (`A = a·B`). For epoch `e` with
public period parameters `P_e` (period number + length), `H_s` = BLAKE2b reduced mod `L`,
domain-separated:

```
h    = H_s("presence/route-blind" ‖ A ‖ P_e)     # blinding scalar
A'   = h · A                                     # blinded public key (published)
a'   = h · a  (mod L)                            # blinded private key (signer)
k_e  = H("presence/addr" ‖ A' ‖ P_e)             # DHT storage key (record address)
```

The record is published at `k_e`, signed with `a'`, its body (the route descriptor)
encrypted to lookers who know `A` (or a shared secret). The storage node stores opaque
bytes at an address it cannot attribute.

**Lookup:** a peer that knows `A` recomputes `h, A', k_e` from public `P_e`, fetches `k_e`,
verifies the signature under `A'`, and decrypts. A storage node holding `{k_e, A', body}`
cannot recover `A`, cannot link `A'` across epochs (different `h` ⇒ different `A'`, `k_e`),
and cannot enumerate which services it stores.

Notes:
- ristretto255 gives a clean `h·A`; the ed25519 fallback must follow Tor's clamping-aware
  blinding (rend-spec-v3 §A.2) — prefer ristretto.
- Rotation is automatic (new epoch ⇒ new key); early revocation uses an identity-signed
  tombstone, consistent with v1's existing capability-store downgrade-tombstone model.
- Still gated: implement inside the future presence-record gate with its own encode/decode,
  fixed test vectors, and review. Not implementable now — no host path exists.
