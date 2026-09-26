# Private Routing: Blinded Presence-Record Keys (Gate D)

**Status:** implemented experimentally over DHT mutable records, including required
SURB publication/resolution/revocation. External cryptographic review and public
required-mode approval remain open. The original derivation sketch below is
historical, not the accepted record transcript.
**Date:** 2026-08-10
**Relates to:** [v1 design](../../private-routing-v1.md),
[current implementation and open gates](../../private-routing-migration.md#current-implementation),
and [Logos lessons, Gate D](../../private-routing-logos-lessons.md).
**Prior art:** Tor v3 onion-service blinded public keys (per-time-period key derivation).

## What exists today (grounding)

- `lib/private/blinded-presence.js` implements period-key derivation, blinded
  signing, fixed-size encrypted records, and authenticated tombstones.
- `lib/private/presence-client.js` implements publication, resolution, revocation,
  period overlap, and rollback protection over mutable DHT records. Its configured
  reply mode applies to both reads and writes.
- The pinned sodium-native fork supplies `crypto_core_ed25519_scalar_mul`;
  no JavaScript scalar multiplication is used.
- Opaque destination references are a separate route-authority boundary, not the
  presence key-blinding mechanism. Gate D supersedes the stable-key, plaintext-topic
  private-storage overlay for presence; the overlay's old IDs remain reserved.

## The requirement

Presence records use **blinded, time-period-derived keys**, not a stable public
identity as the storage identifier:

- Derive a per-time-period blinded public key from the stable key and period
  parameters, so publication does not reuse a stable storage identifier.
- Blinding avoids a stable identifier in stored records; rotation without that
  property would leave straightforward key-based linkage. It does not hide
  timing or volume, and a party that knows the stable identity can derive and
  link its period keys.
- A legitimate resolver derives the expected period key from the stable identity
  and verifies the returned record against that expected key, not an identity
  supplied by the record.
- **Separate concern — body confidentiality.** Blinding avoids publishing the
  stable identity; it does **not** control who may read the descriptor. The public
  stable key `A` is not a confidentiality boundary (it may be widely known). Restricting
  readers requires a separate **reader credential** — a shared secret or the looker's own
  keypair (Tor v3 "client authorization" style) — used to derive the body-encryption key.
  If no reader restriction is intended, say plainly that the body is enumeration-protected
  from the storage node but not access-controlled.

## Implementation boundary

The accepted dependency, signing transcript, period/overlap rules, encrypted
record layout, tombstone semantics, and verification are recorded in the
[Gate D implementation checkpoint](../../private-routing-migration.md#continuation-checkpoint--2026-09-06-gate-d-records-exposure-accounting-live-put-coverage)
and its subsequent review repairs. D10 selects those blinded records over mutable
DHT commands; D12's required-mode writes are complete. Peer-stream consumption
and public required-mode integration remain separate gates.

## Contract and review boundary

- Storage keys change with the derived period key; the stable identity is not
  published in the record.
- Descriptor confidentiality requires the separate reader credential, even when
  the stable identity and period parameters are known.
- Resolution checks the caller-derived key and period, authenticated revision,
  overlap, and tombstone state; an absent response from storage alone is not
  authenticated revocation.
- Timing/volume and known-identity linkage remain visible. Implementation and
  live-gate evidence are not external cryptographic approval.

## Historical derivation sketch — 2026-08-10

The sketch below motivated Gate D but is not its wire specification: its
illustrative domains, storage-key formula, and buffer API must not be used as
replacement codecs or signing transcripts. At the time, the baseline sodium
package lacked scalar×scalar multiplication. The accepted implementation now
uses the pinned native binding; no substitute JavaScript arithmetic is needed.

Let `(A, a)` be the destination's stable identity keypair (`A = a·B`). For epoch `e` with
public period parameters `P_e` (period number + length), `H_s` = BLAKE2b reduced mod `L`,
domain-separated:

```
h    = H_s("presence/route-blind" ‖ A ‖ P_e)     # blinding scalar
A'   = h · A                                     # blinded public key (published)
a'   = h · a  (mod L)                            # blinded private key (signer)
k_e  = H("presence/addr" ‖ A' ‖ P_e)             # DHT storage key (record address)
```

The record is published at `k_e`, signed with `a'`. Its body (the route descriptor) is
encrypted under a key derived from a **separate reader credential** — a shared secret or a
recipient/looker keypair (client-authorization) — **not** from the public `A` (a public key
is not a confidentiality boundary). The storage node stores opaque bytes at an address it
cannot attribute.

**Lookup:** a peer that knows `A` recomputes `h, A', k_e` from public `P_e`, fetches `k_e`,
and verifies the signature under `A'`. It can **read** the body only if it also holds the
reader credential above — knowing `A` alone locates and authenticates the record but does
not decrypt it. This sketch assumes the storing node does not already know `A`.
Knowing `A` permits period-key derivation and linkage; blinding does not prevent
that lookup or eliminate timing and volume correlation.

Notes:

- The original proposal used Tor's clamping-aware derivation as prior art; the
  implemented transcript and domains are recorded in the migration checkpoint.
- Revocation is a blinded-key-signed Gate D tombstone, not the proposed
  identity-signed legacy-capability downgrade object.
- The encode/store/resolve/revoke path and fixed vectors now exist.
  External cryptographic review remains open.
