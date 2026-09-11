# Security review task: HyperDHT private peer v2 ownership and bounded retries

## Objective and authorization

Review and, where justified, repair the included package-private HyperDHT v2 implementation in an isolated copy. This is authorized defensive review of the supplied source, not authorization to probe unrelated systems. Preserve the actual privacy-routing, cryptographic, and native-transport context; do not rename behavior to evade a safety control.

The immediate task is to establish whether final-carrier ownership transfer is correct under delayed packets, early terminal activation, callback reentrancy, loss, and destruction. Return evidence-backed findings and a minimal patch for real defects. Do not assume the candidate fixes are correct because their tests pass.

The ordinary correctness reviewers and source author used different model families. The configured dedicated security-review service was unavailable because of provider credit limits. This external review is still required; no security acceptance is claimed.

## Bundle and exact snapshot

- `code/`: 303 source, test, build-script, and design-document files from the working tree, including uncommitted work. There is no `.git` directory or installed `node_modules`.
- `MANIFEST.json`: snapshot timestamp and SHA256/byte size for each bundled source/evidence file. Review this snapshot, not a guessed upstream commit.
- `evidence/`: captured pre-fix and current test output, verification metadata, and the installed dependency-tree lock metadata.
- The bundled migration document is a historical log and predates the very latest two corrections. This prompt and `evidence/VERIFICATION.json` describe the current snapshot.
- Latest candidate implementation: `peer-tail-control.js` SHA256 `37de0d46df3ecf352575b1ca09aef4ace8e175098026917ae30b655eb8757fec`; `peer-m3-adjacency-runtime.js` SHA256 `fadaca7e4232b8c8a065fb4adc3826d13c196ca3d5f22ad204aa2e812376ac30`.
- Latest focused run: **39/39 tests, 321/321 assertions**, Node24, exit0, 1.82 seconds.
- Latest expanded affected run on this candidate: **505/505 tests, 7982/7982 assertions**, Node24, exit0, 14.83 seconds.
- Native evidence was produced on Darwin arm64 using real `udx-native` sockets. Fake-clock/fake-adapter cases are explicitly identified by their fixtures. Do not treat a fake adapter as native proof.
- The latest duty-transfer edits have not received a final independent security verdict. Their formatting was not rerun after the final edit. Passing behavior is not a format or release claim.

## Scope and reading order

Start with the normative packet:

`code/docs/superpowers/specs/2026-09-09-private-routing-peer-stream-design-packet.md`

Read §§4.2, 4.3, 4.4, 5.1–5.3, 8, and 9, including the TAIL_READY1/TAIL_READY2 attempt budgets. Older v1 behavior is not automatically the v2 contract.

Primary implementation:

1. `lib/private/peer-m3-adjacency-runtime.js`: `pumpRuntimeReceive`, `canTakeFinalCarrierQueue`, `peerM3PayloadContextClass`, `authorizePeerM3FinalCarrierTake`, `issuePeerM3RouteCarrier`, `takePeerM3RouteCarrier`, `releaseFinalReadiness`, `revokeRuntimeTraffic`.
2. `lib/private/peer-tail-control.js`: `createSendTrain`, `startResponderReadiness`, `stopResponderReadiness`, `notifyFinalReady`, `takePeerTailFinalRuntime`, `takePeerFinalCarrierAuthorization`, `destroyPeerTailControl`.
3. `lib/private/peer-ledger.js`: child ledger ownership, memory reservation ancestry, recursive release, and `narrowPeerReservations`.
4. `lib/private/udx-cell-endpoint.js`: actual send/receive ownership, native completion retention, branch/sibling isolation, and physical-channel transfer.
5. `lib/private/m3-adjacency-runtime.js`, `final-exit-handoff.js`, `final-exit-activation.js`: genuine v1/v2 brand dispatch, one-shot activation, carrier bridge, and shared receive-reservation consumption.

Supporting authentication and crypto scope:

- `peer-guard-link.js`, `peer-capability.js`, `peer-direct-bootstrap.js`, `peer-native-neighbors.js`, `guard-lease.js`, `link-bootstrap-session.js`, `peer-crypto.js`, `peer-m3-context.js`, `peer-transport-wire.js`, and `peer-protocol.js`.
- Primary regression files: `test/private/peer-tail-control.js`, `peer-m3-adjacency-runtime.js`, and `peer-native-fixture.js`.

Paths above are relative to `code/` unless explicitly prefixed.

## Findings that triggered this handoff

### A. Early class5 frames were stranded by the shared receive-queue gate

The runtime has one ordinary receive FIFO, not a dedicated tail-only FIFO. The old blanket nonempty-queue rejection made terminal carrier take return `ERR_BUSY` if a legitimate first finalization frame had already arrived. No carrier existed to drain it, so retrying the take did not resolve the problem.

The candidate uses one classifier/predicate at both authorization sites. It refuses outstanding readers and pre-take class6, permits queued class1/class5, and only after genuine final authorization erases class1 and compacts class5 objects in place without copying or reordering. A forged authorization must not alter the queue.

Check both gates, the callback-free span, owner/generation/original-parent comparisons, exact 1101-byte DATAGRAM classification, and preservation of queued finalization bytes.

### B. In-flight class1 could arrive after the synchronous drain

The permanent `physicalChannel.receive()` loop survives the ownership move. An old class1 envelope could arrive after the drain, resolve a carrier waiter, and cause `INVALID_ROUTE`, consuming a legitimate finalization receive reservation.

This was reproduced with an actual Native UDP packet held across transfer and released while a carrier reader was pending. The pre-fix command exited1 with `INVALID_ROUTE` from the carrier receiver.

The candidate sets a write-once runtime `finalCarrierTaken` mode after successful authorization and before draining. The ordinary receive pump erases/discards only valid DATAGRAM/1101/context1 envelopes in that mode, after charging the inbound cell and after branch-closure interception. Other classes/shapes retain the existing validation behavior; incoming class6 never authorizes local promotion.

Inspect both FIFO and waiter paths, in-flight completion after destruction, accounting order, malformed/control payload handling, and buffer erasure. Do not repair this by dropping class5 or by skipping its authentication.

### C. Early terminal take cancelled the residual TAIL_READY2 send duty

`notifyFinalReady` runs after the first local A2 send dispatch settles. That is not proof the source received READY2. The old final-runtime take unconditionally stopped readiness. Losing the first READY2 upstream therefore discarded seven remaining attempts and stranded the source.

The new permanent Native regression immediately claims/takes the terminal carrier on the first dispatch, destroys the old terminal tail owner, and drops the first READY2 upstream. Before the candidate repair:

- the source ended with `ERR_PRIVACY_UNAVAILABLE`, not `FINAL_EXIT_READY`;
- a capacity probe showed the retired tail had freed storage that the residual send duty should still own.

The current candidate chooses ownership transfer, not a healthy-path 1.75-second admission delay:

- the genuine final authorization captures and compares the exact readiness-train identity;
- the already-sealed READY2 envelope, nonce, reservation, remaining attempt count, pending dispatches, existing timer, and original deadline move without resealing or resetting;
- Native installs a send capability restricted to that retained envelope;
- `createSendTrain` can continue under the Native-owned capability after the old tail owner is destroyed;
- the old tail detaches the readiness leaf. If its session storage is destroyed while that duty remains, the existing ancestor pool is retained behind the duty rather than recursively freed or reacquired;
- successful exhaustion of all eight settled dispatches releases the duty. Its failure/expiry or Native retirement releases it and follows the owned failure path;
- there is no unauthenticated class5-based early-discharge shortcut.

This is the most important current review target. Check that the transfer has exactly one owner at every point; that ancestor reservations cannot be freed early, leaked, or released twice; that late/synchronous callbacks cannot revive a train or send after its original bound; and that clearing payloads or closing the old owner cannot damage an unresolved Native send or a surviving sibling. Check failure and destruction order, not just the happy-path retry.

## Non-negotiable invariants

- Keep package-private mode; do not enable public required mode, commit, push, or deploy.
- Keep genuine WeakMap/WeakSet ownership and exact compare-and-swap checks. No fabricated authority or test-only bypass in production.
- Preserve the twelve-field final-material contract and closed v1/v2 dispatch. No exposure of raw identity/route/endpoint keys or a general-purpose sender through a new public field.
- Class1 is ordered tail control; class5 is finalization; class6 is purpose-route traffic. Preserve their distinct key/nonce/counter domains. No counter reset, nonce reuse, incoming-packet-triggered local promotion, or cross-class decryption fallback.
- Retain original canonical READY2 bytes, original eight-attempt allowance, and original stored monotonic deadline. Every dispatched attempt remains charged even if sending fails. No new retry train, budget, or deadline on duplicate/transfer.
- Keep wire Unix expiry separate from host-local monotonic deadline. Preserve clock identity and original parent projection; do not import peer monotonic time or rebase retries.
- Retain early class5 in order. A pending old reader must prevent transfer. Failed/forged authorization must not mutate queued traffic.
- Charge legitimate inbound stale tail cells before discarding; do not bypass authenticated closure processing.
- Preserve sibling ownership. Closing a shared socket to cancel one branch is not an acceptable substitute for per-request ownership.
- Do not free byte reservations merely because a timeout fired while Native still owns a send buffer.
- Tests must use real branded authorities. A fake-clock scheduling test is useful, but cannot satisfy a native-dependency or Linux privacy gate.

## Related unresolved security/dependency boundaries

After the immediate ownership review, separately assess the authenticated setup/admission path and classify any additional concrete defects. Two known open dependency/resource questions must not be silently waived:

1. The pinned `udx-native` 1.20.7 interface has no per-send cancellation API. Native may retain request buffers until completion. A timeout-based release or shared-socket shutdown does not prove safe per-branch cancellation.
2. The fixed 680000-byte responder startup reservation still requires a ratified lifetime bound for retained completion state. Earlier bounded-pending-slot proposals were not accepted. Do not change that bound or claim it solved without evidence and an explicit contract.

Full purpose negotiation, streams, semantic services, controller integration, Linux privacy acceptance, and named human cryptographic/public-release approval remain outside the completion claim. The class6 carrier test uses separate deterministic test-only keys; it does NOT prove OFFER/ACCEPT or sentinel negotiation.

## Reproduction and verification

Work from the extracted `code/` directory. Use an isolated development environment. The original environment used Node **24.18.0**, `udx-native` **1.20.7**, `sodium-universal` **5.0.1**, and the dependency revisions declared in `package.json`.

There is no root lockfile in the source checkout. `evidence/installed-package-lock.json` is the captured installed-tree metadata, not a drop-in root lockfile for `npm ci`. Inspect it and `package.json`, install the declared dependencies as appropriate, and record any resolution/platform differences. GitHub-pinned dependency revisions must remain pinned. `node_modules` and platform-specific binaries are intentionally excluded.

Focused behavior:

```sh
node node_modules/brittle/bin/node.js \
  test/private/peer-tail-control.js \
  test/private/peer-m3-adjacency-runtime.js
```

Expanded affected suite:

```sh
node node_modules/brittle/bin/node.js \
  test/private/peer-*.js \
  test/private/link-bootstrap-session.js \
  test/private/udx-cell-endpoint.js \
  test/private/guard-lease.js \
  test/private/guard-link.js \
  test/private/guard-reconnect-authority.js \
  test/private/endpoint-bootstrap-authority.js \
  test/private/bootstrap-io.js \
  test/private/bootstrap-envelope.js \
  test/private/m3-*.js \
  test/private/final-exit-*.js \
  test/private/tail-control.js
```

Relevant named scenarios:

- `two-extension v2 tail control and one-shot final handoff complete flow over genuine Native carriage`
- `terminal carrier retains its original Native READY2 duty after the tail owner closes`
- `authenticated READY cannot beat an expired operation by preceding its delayed timer callback`
- `Native upstream loss retires the surviving successor without reporting a false physical loss`

Keep reproductions for real failures: fail before your correction, pass after. Add held-send/receive, destruction, exact-deadline and callback-reentrancy cases where they expose a plausible missing transition. Do not weaken assertions merely to restore green tests. Use the targeted formatter after your edits, then run relevant behavior checks.

Do not automatically run production-DHT end-to-end tests or remote credential scripts. The archive includes them as source context, not permission to contact external targets. If real Native execution or dependencies are unavailable, report that limitation explicitly; do not substitute fake authority and label it a native pass.

## Required return package

Return these so JD can bring the results back to the implementation owner:

1. **Findings report**, ordered by severity. For each: exact file and symbol/line, preconditions, demonstrated transition/failure, impact, invariant violated, concrete remedy, and remaining uncertainty. Separate confirmed defects from unverified hypotheses and nonissues.
2. **Minimal unified diff** relative to the bundled `code/` snapshot, including justified regression tests. Keep unrelated refactors and protocol changes out.
3. **Verification transcript**: exact commands, versions/platform, exit statuses, test/assertion counts, pre/post reproduction results, and anything not exercised.
4. **Disposition table for A/B/C**: accepted, corrected, rejected, or still open, with evidence for each. Re-evaluate the candidate; earlier advisory labels are not authority.
5. **Residual-risk list** covering authentication/crypto, memory ancestry, outstanding Native completion, timing, sibling isolation, and unmet external gates.

An AI review is not by itself named external-human cryptographic or public-release approval. Provide findings and evidence; do not claim full-v2 completion or authorize release.
