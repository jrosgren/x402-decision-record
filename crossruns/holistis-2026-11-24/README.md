# Cross-run: holistis attempt-identity vectors vs x402-decision-record v1.0.1


> Published 2026-11-25 by Aron, Polkulab (Payvetted), at the request of Abdellah Ouadoudi (holistis). Cross-run date 2026-11-24. Example data only; this is a test run, not a production record.

Vectors: github.com/holistis/agent-receipt-verify, cross-run 2026-11-24
Credit: Abdellah Ouadoudi (github.com/holistis), Apache-2.0.

- Upstream: `holistis/agent-receipt-verify` @ `0280039f00d8` (main, committed 2026-11-24 09:49 Helsinki time (UTC+2)), folders `vectors/attempt-identity` (72 files, includes the 22 frozen known-answer files) and `vectors/attempt-identity-extra` (8 files). Both match their SHA256SUMS.
- Ours: `jrosgren/x402-decision-record` tag `v1.0.1` (`ee2a6e9`). Our own unit tests: 29/29 OK. (v1.0.2 changed only the published keyset; the `request_sha256` rules are unchanged.)
- Script: [`crossrun_holistis.py`](./crossrun_holistis.py). Full output: [`run-output.txt`](./run-output.txt). Run date: 2026-11-24, no network at run time. To reproduce: put a checkout of `holistis/agent-receipt-verify` @ `0280039f00d8` in `upstream/` and a checkout of this repo @ `v1.0.1` in `ours/` next to the script, install `rfc8785`, then run `python3 crossrun_holistis.py`.

## How the fields map

Our `payment.request_sha256` = sha256(JCS(`{method, url, body_sha256}`)). Here `url` is the absolute URL **as requested** and `body_sha256` is the SHA-256 of the **raw transmitted body bytes** (SPEC §6). Section 5.5 (x402 PR 3776) hashes **canonical members** instead: arrival-order query with percent-decode and re-encode (uppercase hex), and a body that is first content-decoded and charset-decoded, then RFC 8785 for JSON.

| holistis member | ours | mapping |
|---|---|---|
| `method` | `resource_request.method` (upper case) | same |
| `path` + `query` | inside `resource_request.url` (also includes scheme and host) | partial: we do not canonicalise the query, and we bind the origin, which 5.5 does not |
| `body` (canonical body hash) | `resource_request.body_sha256` (hash of raw bytes) | same slot, different bytes hashed |
| payTo/asset/network/amount/scheme in the snapshot | separate record fields (`payee`, `asset`, `network`, `amount_atomic`, `scheme`) plus `payment_requirements_sha256` | bound by the record, but not part of request_sha256 |

## Results

**A. Known-answer vectors, our native rules (30 = 22 frozen + 8 extra).** These are expected to differ by design, because we hash what was sent and do not canonicalise.
- 3 of the 15 right values match: `body-duplicate-keys-hashed-as-bytes`, `query-bare-name-stays-bare` and `query-invalid-utf8-stays-octets`. In all three cases the 5.5 canonical form happens to equal the raw form.
- 12 right values differ: every gzip/deflate/charset/JSON body, plus the query cases with decode-then-encode, plus-sign, lowercase hex and semicolon.
- 4 of our native values are identical to holistis' "wrong" twins: `body-json-rfc8785-wrong`, `query-decode-then-encode-wrong`, `extra/content-encodings-reversed-in-order-wrong` (that one hashes the transmitted bytes) and `extra/plus-json-media-type-is-json-wrong`. Our rules are exactly the "hash what was sent" behaviour these vectors are written to catch. It is a different design choice, not an implementation bug.

**B. Adapter (5.5 rules written in the script, using our verifier's RFC 8785 `canonicalize()`): 30/30 agree.** All 15 right values are reproduced and all 15 wrong values are rejected. So our JCS path and the gzip, deflate, Latin-1 and +json handling reproduce the known answers. The adapter is **not** part of our spec v1.0.1.

**C. canonical_variants (13 vectors), equal/different relation of our native request_sha256:** 6 agree, 7 differ.
- Agree: all 4 repeated-key/order vectors (we keep the order and keep different requests different) and both empty-query vectors. The empty-query agreement holds only because the script writes no `?` for an empty query. Our SPEC does not say whether a trailing `?` counts.
- Differ: gzip vs identity (2 vectors), charset, JSON key order, JSON whitespace, percent-hex case (2 vectors). 5.5 wants the same identity there. Ours gives a different one, because the transmitted bytes differ. The adapter agrees on 13/13.

**D. Verifier path.** v1.0.1 still recomputes our own binding (`VALID`, `BINDING_RECOMPUTED_OK`). If `resource_request` is replaced with an upstream raw request, the result is `BINDING_HASH_MISMATCH:jcs(resource_request)`, as expected. The script prints native request_sha256 values for the 15 distinct upstream raw requests, using the origin placeholder `https://example.invalid` because upstream raw requests carry only a path. No one else has checked these values; they are informational.

## What does not map (not run)

The other ~50 attempt-identity vectors record what an implementation did across paths. They cover `derive-once-at-ingress`, `ingress-snapshot-complete`, `all-paths-same-artifact`, `changed-request-different-artifact`, `countersignature-recompute-or-refuse`, `three-identifiers-not-collapsed`, `name-independent-but-bound`, `outcome-not-folded-into-identity`, `own-identity-from-decoded-fields`, `normalization-applied`, `absent-member-omitted` and `nothing-recorded-not-measured`. Our verifier checks one signed record after the fact. It has no notion of ingress vs settle paths, countersignature comparisons, idempotency keys or an identity snapshot, so there is nothing to feed those vectors into. Conceptually our record keeps the outcome (checks/decision) out of request_sha256, and binds payment fields separately. We did not test that against these vectors.

Informational: 17/26 upstream identity labels in `canonical_variants` equal sha256(sorted compact JSON of the adapter members). Upstream says the labels come from its own function, so we draw no conclusion from that.

## Honest bottom line

Our request_sha256 is a **transmitted-bytes** binding, and section 5.5 defines a **canonical-members** identity. On holistis' vectors the two diverge wherever canonicalisation changes the bytes. Where we differ, our value can match the published "wrong" twin. Our RFC 8785 implementation reproduces all 30 known answers when it is fed 5.5's canonical members. If we want 5.5 compatibility, the candidate for a future minor version is an additional input id (e.g. `x402-5.5-canonical-members`) next to `jcs(resource_request)`. That should not change v1.0.x. It is a decision for later, not part of this cross-run.
