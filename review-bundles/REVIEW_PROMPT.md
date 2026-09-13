# HyperDHT private routing independent cryptographic review

## Required reviewer and result

This packet is for an independent human cryptographic/protocol reviewer. The
review is not complete until a named reviewer returns a dated disposition tied
to `MANIFEST.json.revisions.hyperdht` and
`MANIFEST.json.revisions.sodium-native`.

Return one of:

- `ACCEPT` — no release-blocking finding in the reviewed claims.
- `ACCEPT WITH CONDITIONS` — enumerate conditions and the exact affected claim.
- `REJECT` — enumerate release-blocking findings.

For every finding include severity, attacker capabilities, reachable entry
point, violated invariant, reproduction or proof sketch, affected files/lines,
and remediation. Separate remote exploitability from defense-in-depth and
review-harness findings. State reviewer name, affiliation or independent status,
date, source revision, native-crypto revision, and whether fixes were
re-reviewed. Sign the report with a verifiable Git commit signature, SSH
signature, age/minisign signature, or an identity-bearing review-platform
account.

## Exact scope

`MANIFEST.json` is authoritative. It contains SHA-256 hashes for every packet
file and the exact revisions below:

- HyperDHT packet source: `MANIFEST.json.revisions.hyperdht`.
- Native `sodium-native` scalar implementation:
  `562d642e1a78a8e124cf97bfbda77f01c02d1a7f`.
- Hyperswarm private-context integration:
  `4bae99e4067f77fa3b378914883b357f87292de4`.
- PearTube desktop/mobile opt-in integration:
  `53896a3be13f1a35b26a00acf58c3aa139c1fc99`.

Review `code/lib/private/**`, its actual public composition in
`code/lib/dht.js`, the native scalar dependency revision, and the protocol and
migration specifications. Tests are evidence and adversarial examples, not the
source of protocol truth.

## Claims under review

### Public alpha peer context

When the exact acknowledged `privateRouting` context is selected:

1. The destination publishes only a signed, expiring, period-blinded route
   descriptor through its guard after a three-node storage quorum and exact
   two-reply readback.
2. A source selects two safety relays independently from the destination's entry
   and guard. Four relay identities are distinct and available IPv4 `/24`
   prefixes are separated.
3. A destination guard does not learn the stable destination application key
   until it has reserved the destination role and authenticated a
   domain-separated key binding. A resolver role is mutually exclusive.
4. Peer application streams use end-to-end Noise/SecretStream. Every physical
   hop authenticates, opens, and reseals a fixed 1,200-byte cell with an
   adjacent circuit key, nonce, circuit ID, and counter.
5. Route streams never fall back to a direct destination dial. Route-only peer
   data does not enter the caller's routing table.
6. A private server firewall receives the authenticated end-to-end Noise public
   key exactly once; refused peers are destroyed and never emitted.
7. Pending bytes, frames, streams, retired IDs, timers, descriptor work, and
   memory ownership are bounded and fail closed.

### Blinded routed DHT v1

Review immutable and mutable get/put derivation, signatures, sequence/CAS rules,
tombstones, replay caches, reply correlation, SURB construction and erasure,
per-hop transformation, deadlines, cancellation, and exact response ownership.

### Dormant native peer-tail/UDX stack

This stack is package-private and is not claimed as a production runtime.
Review its protocol correctness because it is intended for a future cutover:
M3 adjacency, peer capabilities, discovery/extension, final-exit activation,
semantic services, route carrier ownership, quota ledgers, timers, and native
socket lifecycle. The packet includes the resolved activation-material finding
and independent reproduction probe.

## Explicit non-claims

- No resistance to a global passive observer performing timing/volume
  correlation. Fixed-size cells are not constant-rate cover traffic or a
  mixnet.
- No proof that distinct cryptographic relay identities have distinct human
  operators. The implementation enforces identity/address topology diversity,
  not a centralized operator registry.
- Ordinary DHT bootstrap, routing-table maintenance, lookup/findPeer,
  announce/unannounce, raw query, ping, and Hyperswarm topic discovery remain
  direct and are not anonymized.
- The package-private full peer-tail fixture is not deployable production
  discovery/bootstrap.
- Local and container evidence does not substitute for a successful
  geographically distributed real-link run.

## Mandatory review questions

1. Can any endpoint, relay, storage node, or colluding subset recover or link a
   stable destination identity beyond the stated adjacent-hop observations?
2. Are descriptor blinding, signatures, expiry, sequence recovery, storage
   quorum, and restart semantics cryptographically bound to the intended
   identities and period?
3. Can role admission race, reentrancy, retry, or failure expose the destination
   application key before reservation or permit the same relay to occupy an
   excluded role?
4. Does every peer cell have unambiguous key direction, circuit binding, nonce
   uniqueness, replay/order protection, fixed length, and authenticated
   class/stream metadata?
5. Does logical-stream reset/close prevent late data from retiring another
   stream or circuit? Are all stream and byte bounds enforced before allocation
   or publication?
6. Is Noise identity presented to the firewall the actual end-to-end peer, and
   can refusal ever emit or retain an application-visible connection?
7. For routed DHT replies and SURBs, can a malicious relay swap request, reply,
   grant, source, operation class, sequence, or expiry while preserving a valid
   authenticator?
8. Are key derivation domain labels, input ordering, scalar validation, zero
   rejection, low-order handling, and native return/error behavior identical
   across JS and native implementations?
9. Are secrets and ownership-bearing buffers erased only after the final async
   consumer owns or drains them? Check queued Streamx writes, deferred transforms,
   cancellation, throw paths, and destroy races.
10. Does final-exit activation revalidate the exact twelve-property material,
    authoritative owner/clock/deadlines, and generation at both prepare and
    commit? Re-run the included fault-injection probe.
11. Can scheduler, clock, random, logging, getter/proxy, or transport callbacks
    reenter any check-then-publish window and create unbounded or stale
    authority?
12. Are the stated topology, timing, operation-scope, and real-link limitations
    accurate and impossible to mistake for stronger anonymity claims?

## Reproduction gates

From `code/`, using the pinned lockfile and supported Node and Bare runtimes:

```sh
npm ci
node_modules/.bin/brittle-node test/private-routing.js
bare test/private-routing.js
node review-bundles/activation-material-probe.cjs .
```

Linux packet-capture evidence requires privileged Docker:

```sh
bash scripts/linux-gates.sh peer:capture
```

The packet's `evidence/VERIFICATION.json` records observed results,
architectures, revisions, and known failures. Re-run the privileged gate or
inspect retained CI artifacts rather than accepting its summary when evaluating
wire claims.

## Observed evidence at packet preparation

- Node private aggregate: final count recorded in
  `evidence/VERIFICATION.json`; zero failures.
- Bare private aggregate: final count recorded in
  `evidence/VERIFICATION.json`; zero failures.
- Private server firewall public-API regression: Node, Bare, and a fresh Linux
  Node 24 arm64 container each pass 8/8 tests, 93/93 assertions.
- Endpoint invalid-ciphertext/application-error regression: Node and Bare pass
  18/18 tests, 103/103 assertions; fresh Linux arm64 Node 24 passes 25/25
  independent process runs after the regression explicitly enters flowing mode.
- Final-exit mutation regression: Node and Bare 20/20 tests, 156/156 assertions.
- Activation probe: unchanged commit accepted; `localDeadline`, `tailControl`,
  and `clockIdentity` substitutions rejected with `INVALID_ROUTE`.
- Linux arm64 laptop and Linux x86_64 Unraid: peer capture gate 1/1 test,
  23/23 assertions at capture revision
  `32dded3498bec19ed03ac74287b03923f388b576`.
- Hyperswarm focused private integration: Node and Bare 1/1 test, 3/3
  assertions; ordinary topic discovery plus private peer echo and zero direct
  destination sends.
- PearTube backend regression: 29/29; mobile Bare backend bundle and require
  coverage complete.
- Distributed run 34770010983 did not reach LINK_OFFER: only 48/140 directed UDP
  pairs were reachable and role 1 never attached. Treat this as an open evidence
  gate, not negative protocol evidence.
- HyperDHT run 34773603689 passes Linux live plus deterministic macOS/Linux.
- PearTube exact-revision Fast CI, relay build/test, Android debug/release, and
  iOS build pass. Hyperswarm exact-revision lint and git-disabled installs pass;
  its Windows job fails inside upstream `bare-base@v1` because socket-firewall
  cannot locate `npm`, then fail-fast cancels the longer Linux/macOS jobs.

## Release boundary

Do not approve production anonymity, default-on downstream activation, or the
package-private native peer-tail cutover solely from this packet. Those require:

1. a named independent disposition on the exact revisions;
2. remediation and re-review of every release-blocking finding;
3. a successful distributed real-link run that reaches LINK_OFFER and exercises
   responder admission; and
4. for the native cutover, a real decentralized bootstrap/neighbor service in
   place of fixture-provided topology and authorities.
