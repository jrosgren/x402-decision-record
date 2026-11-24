# x402 pre-payment decision record: v1.0

**Status: v1.0, final.** Released as **v1.0.0 on 19.11.2026** (JSON Schema, changelog, test vectors and verifiers); current patch release **v1.0.2 (24.11.2026)**, additive only (§12.0.2). The record format is still `schema_version: "1.0"`. This text was v0.3-draft (PR #1) and carries the fixes from the 19.11 reviews. Comments remain welcome in a GitHub issue or the x402 Slack thread; see §12.0 for how they are handled.

**EXAMPLE DATA ONLY, with one exception.** The sample records, test vectors, wallets and demo key `polkulab-demo-2026-11` are made-up illustrations. The demo key signs example records only. The published keyset also lists the Payvetted production public key `payvetted-prod-2026-12`. A production signing endpoint is not live, and Payvetted issues no production records yet.

Author: Aron, Polkulab (Payvetted). Thanks to Miguel Martinez (ReturnCheck), Romeo Reynolds and Abdellah (agent-receipt-verify) for the feedback in the x402 Slack thread that shaped this version.

## 1. Purpose and scope

A decision record is a small, signed statement written **before** an agent pays an x402 resource. It says which checks ran, when they ran, what evidence they saw, what was decided, and exactly which payment the decision was about. It is meant to be verified later by a third party (a platform, an auditor, an insurer) with only the record, the issuer's public keyset, and open algorithms.

The record is deliberately **thin**. It attests to one decision about one payment. Other facts (settlement, content delivered, seller identity) belong in other records and are linked by hash (§7), not copied in.

Keywords MUST, SHOULD and MAY are used as in RFC 2119.

## 2. Record overview

```
{
  "schema_version": "1.0",
  "record_type": "x402-pre-payment-decision",
  "record_id": "...",
  "example_data": true,                       // test vectors only
  "issuer": "https://trypolkulab.com",
  "signing_key": { "key_id", "keyset_uri" },  // §9
  "payment":  { ... binding to one payment ... },          // §4
  "timeline": { ... when things happened ... },            // §5
  "checks":   [ { id, result, ran_at, evidence_ceiling, evidence_sha256, evidence? } ],  // §6
  "decision": { verdict, score, level, reason_codes, policy_id, payer_agent_id },
  "field_evidence_ceilings": { "<JSON Pointer>": "<ceiling>" },                        // §8
  "links":    [ { rel, issuer, scope?, expires_at?, record_sha256, evidence_ceiling } ], // §7
  "not_covered": [ { code, text } ],                                                    // §10
  "signature": { alg, key_id, sig_base64 }                                              // §3
}
```

Full example: [`test-vectors/v1.0/valid.json`](./test-vectors/v1.0/valid.json). Schema: [`schema/decision-record.v1.0.schema.json`](./schema/decision-record.v1.0.schema.json) (JSON Schema 2020-12). The schema is normative: a record that does not validate against it is INVALID (§11 step 0).

## 3. Signature, numbers and timestamps

Signing (unchanged from v0.2):

- Remove the `signature` member from the record.
- Canonicalize the rest with **RFC 8785 (JCS)** and encode as UTF-8. These are the **signed bytes**.
- Sign the signed bytes with **Ed25519** (RFC 8032, pure, no pre-hash).

The `signature` object (changed in v1.0):

- It MUST contain **exactly** three members: `alg` (`"Ed25519"`), `key_id` and `sig_base64`. Any other member, including v0.2's `canonicalization` and `sha256`, → INVALID (`BAD_SIGNATURE_OBJECT`). Those members were not signed, so anyone could change them and with them the `jcs(record)` hash of a still-valid record (§6).
- `sig_base64` MUST be the 64-byte signature in **canonical** standard base64 with padding (RFC 4648 §4: 88 characters, the unused low bits of the last data character are zero). Verifiers MUST decode strictly, re-encode and compare; a mismatch → INVALID (`NONCANONICAL_SIGNATURE`).
- Verifiers MUST reject a signature whose `S` (last 32 bytes, little-endian) is not below the group order `L` (RFC 8032 §5.1.7) → INVALID (`BAD_SIGNATURE`). This applies on every code path, including fallback libraries that skip the check (for example tweetnacl).
- `signature.key_id` MUST equal `signing_key.key_id` (`KEY_ID_MISMATCH`). The copy inside the signed body stops key-id substitution.

Duplicate members: a record or keyset MUST NOT contain the same member name twice in one object (RFC 8259 leaves the result undefined, and parsers differ on which value wins). Verifiers MUST check the text before or while parsing and report INVALID (`DUPLICATE_MEMBER:<pointer>`; in a keyset, `DUPLICATE_MEMBER:keyset#<pointer>`). Text that is not JSON (including `NaN` or `Infinity`) → INVALID (`BAD_JSON`). The same text rules apply to the optional binding inputs and linked records (§11 step 5), with the source in the pointer (`binding_inputs#<pointer>`, `linked[<i>]#<pointer>`). A verifier that is handed an already parsed object cannot apply them; the reference verifiers then add the warning `PARSED_INPUT:<input>`.

Numbers: a record MUST NOT contain a number with a fraction or exponent part (`62.0`, `1e3`) anywhere, including inside `evidence`, and every integer MUST be within ±(2^53−1) (as in I-JSON, RFC 7493). Otherwise → INVALID (`BAD_NUMBER:<pointer>`). Amounts are decimal strings in atomic units; scores are integers. This keeps JCS identical across languages.

Timestamps: every timestamp in a record or keyset MUST match `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{3})?Z$` (UTC, `Z`, whole seconds or exactly three decimals) and be a real calendar time (no leap second). Otherwise → INVALID (`BAD_TIMESTAMP:<pointer>`). Verifiers compare timestamps at millisecond precision.

## 4. Payment binding

`payment` binds the record to exactly one x402 payment. v1.0 binds to **x402 protocol v2** (`x402_version: 2`):

| field | meaning |
|---|---|
| `x402_version` | `2` |
| `scheme`, `network`, `asset` | as in the selected x402 v2 `PaymentRequirements` (one element of `accepts`); `network` is a CAIP-2 id |
| `amount_atomic` | the selected requirements' `amount`, in the asset's smallest unit, decimal string |
| `payer`, `payee` | payer wallet and the requirements' `payTo` |
| `resource` | `resource.url` of the x402 v2 `PaymentRequired` (in v2 the resource sits at the top level, not in the requirements) |
| `authorization.nonce_sha256` | hash of the EIP-3009 authorization nonce (§6) |
| `authorization.valid_after`, `valid_before` | the authorization's validity window, as timestamps (§3) |
| `payment_requirements_sha256` | hash of the selected `PaymentRequirements` object as received |
| `request_sha256` | hash of the resource request (method, URL, body hash) |
| `tx_hash` | `null` when signed before settlement (the normal case) |

**x402 v1.** x402 v1 requirements (`maxAmountRequired`, network names such as `base`, `resource` inside the requirements) MUST be mapped to v2 before a record is issued: `maxAmountRequired` → `amount`, `base` → `eip155:8453`, the resource URL → `PaymentRequired.resource.url`. The hash then covers the v2 object. A verifier given v1-form requirements as binding inputs reports `UNSUPPORTED_X402_V1_REQUIREMENTS`.

**Networks.** v1.0 covers **EVM chains only**, with Base (`eip155:8453`) as the primary target. `network` MUST be a CAIP-2 id of the form `eip155:<chain id>`, where the chain id is a positive decimal integer without leading zeros (pattern `^eip155:[1-9][0-9]*$`; so `eip155:08453` and `eip155:0` are rejected), and verifiers MUST reject any other value (`UNSUPPORTED_NETWORK`). The nonce input id `eip3009-nonce-bytes32` is EVM-specific. Solana and other non-EVM schemes are deferred to v1.1, which will add scheme-specific nonce input ids. *(Resolved, Ella 19.11.)*

**Recomputing the binding.** A verifier that holds the raw inputs (see [`test-vectors/v1.0/binding-inputs.json`](./test-vectors/v1.0/binding-inputs.json): the nonce, the selected `PaymentRequirements`, optionally the `resource` object, and the request) MUST:

- require the nonce to be `0x` plus exactly 64 hex digits (`BAD_NONCE`), and recompute the three hashes (`BINDING_HASH_MISMATCH:<input id>`);
- require `payTo`, `amount`, `network`, `asset` and `scheme` in the requirements (`BINDING_FIELD_MISSING:<field>`) and compare them with `payee`, `amount_atomic`, `network`, `asset` and `scheme` (`BINDING_FIELD_MISMATCH:<record field>`; addresses case-insensitively, the rest exactly);
- if `resource` is supplied, compare `resource.url` with `payment.resource` (`BINDING_FIELD_MISMATCH:resource`).

A verifier MUST NOT report the binding as recomputed (`BINDING_RECOMPUTED_OK`) when any of these failed or was skipped. When no binding inputs are supplied at all, the reference verifiers (v1.0.1 and later) say so with the info code `BINDING_RECOMPUTATION_SKIPPED`, so a VALID result is never read as "binding checked" (§11.2).

Flow: the client builds the payment authorization (including its nonce), presents it to the checker before signing, and the checker issues the record. The nonce is unique per payment, so a record cannot be reused for a second payment. The record carries the **hash** of the nonce, not the nonce itself, so a record leaked before settlement does not reveal the authorization.

Settlement is not in this record. A settlement or outcome record SHOULD link back to this record with `rel: "decision_record"` and a `record_sha256` with input `jcs(record)`, which covers the **whole decision record including `signature`** (§6). See [`test-vectors/v1.0/example-outcome-record.json`](./test-vectors/v1.0/example-outcome-record.json).

## 5. Timeline

`timeline` holds `requirements_received_at`, `authorization_presented_at` and `decision_issued_at`. Each check has its own `ran_at`. A verifier MUST reject the record unless

`requirements_received_at` ≤ `authorization_presented_at` ≤ every check's `ran_at` ≤ `decision_issued_at` < `authorization.valid_before`,

and, if `authorization.valid_after` is present, `valid_after` < `valid_before`. Error codes: `TIMELINE_OUT_OF_ORDER` (requirements received after the authorization was presented, or presented after the decision), `CHECK_OUTSIDE_DECISION_WINDOW:<check id>`, `DECISION_AFTER_AUTHORIZATION_EXPIRY`, `AUTHORIZATION_WINDOW_INVALID`.

Timestamps are the issuer's clock (evidence ceiling `issuer_assertion`). They show order and spacing, not proof of time. A trusted timestamp (RFC 3161 or an on-chain anchor) can be added later as a linked record.

## 6. Hashes: exactly which bytes

Every hash is an object `{"alg": "sha-256", "input": "<input id>", "hex": "<64 lowercase hex>"}`. `input` names exactly which bytes were hashed:

| input id | bytes hashed | used in |
|---|---|---|
| `eip3009-nonce-bytes32` | the 32 raw bytes of the nonce (hex-decoded, without `0x`) | `payment.authorization.nonce_sha256` |
| `jcs(payment_requirements)` | UTF-8 JCS of the selected x402 v2 `PaymentRequirements` object, exactly as received in the 402 response (one element of `accepts`) | `payment.payment_requirements_sha256` |
| `jcs(resource_request)` | UTF-8 JCS of `{"method", "url", "body_sha256"}`: HTTP method in upper case, absolute URL as requested including query, hex SHA-256 of the raw request body (empty body → hash of zero bytes) | `payment.request_sha256` |
| `jcs(evidence)` | UTF-8 JCS of the check's `evidence` object | `checks[].evidence_sha256` |
| `jcs(record)` | UTF-8 JCS of a linked **decision record as a whole, including its `signature` member** | `links[].record_sha256` when the target is a decision record |
| `jcs(linked-record)` | UTF-8 JCS of another linked JSON record (not a decision record) as published | `links[].record_sha256` |
| `raw(linked-record)` | the exact bytes of a linked non-JSON record | `links[].record_sha256` |

Why `jcs(record)` includes the signature: the hash pins the exact signed artefact, not just its content. It is stable because the v1.0 rules leave a third party nothing to change in a valid record: the signed body is fixed by the signature, the `signature` object has no unsigned optional members (§3), `sig_base64` must be canonical base64 (§3), and `S` must be below `L` (§3), which makes Ed25519 non-malleable. Only the key holder could produce a second valid signature over the same body. *(Resolved, Ella 19.11; strict rules added after the 19.11 review.)*

New input ids MUST be defined in this spec before use. In v1.0 the schema only allows the ids above in each place, so an unknown input id makes the record INVALID (`SCHEMA_VIOLATION`).

## 6.1 Checks and evidence

Each element of `checks` MUST have `id`, `result` (`pass|warn|fail|error|skipped`), `ran_at`, `evidence_ceiling` and `evidence_sha256`, and MAY carry the `evidence` object inline.

- If `evidence` is inline, the verifier MUST recompute `jcs(evidence)` and reject on mismatch.
- If it is withheld (for privacy or size), the hash still commits the issuer to it, and it can be disclosed later and checked against the signed hash.
- Evidence SHOULD hold the facts behind the result (block numbers, list snapshot hashes, observed vs listed price), not only a summary.

The score alone is never the evidence.

## 6.2 Check-id registry

v1.0 defines a minimal registry of check ids:

| id | what it checks | typical evidence ceiling |
|---|---|---|
| `endpoint.health` | the resource answers with HTTP 402 and well-formed payment requirements | `recomputable_from_client_view` |
| `terms.price_vs_listing` | the requested amount against the seller's listed price | `recomputable_from_client_view` |
| `payto.change` | whether `payTo` changed since the issuer first saw it | `issuer_assertion` |
| `payee.wallet_risk` | on-chain risk signals for the payee wallet (age, history) | `recomputable_from_chain` |

- Custom checks MUST use the prefix `x-<issuer>.`, for example `x-polkulab.sanctions_list` in the example vectors.
- Verifiers MUST **ignore** check ids they do not know, never reject a record because of one. The reference verifiers report them as info (`CUSTOM_CHECK_ID:` or `UNKNOWN_CHECK_ID:`) and still check their evidence hash and ceiling.
- New registry ids are added by a spec revision. *(Resolved, Ella 19.11.)*

## 7. Links to other records (composability)

`links` points to other records by hash. Each link MUST have a `rel`, the `issuer` of the linked record, a `record_sha256` and an `evidence_ceiling`, and MAY have `uri`, `scope` and `expires_at`. `links` is required; use `[]` when there are none. Defined `rel` values in v1.0:

- `content_time_record`: a record of what content was served when (e.g. by the paid endpoint).
- `seller_attestation`: a statement by an attester about the seller, e.g. that `payTo` belongs to the operator of a domain. It MUST carry `scope` and `expires_at` (the schema enforces this). A verifier SHOULD warn if `expires_at` ≤ `decision_issued_at`.
- `decision_record`: a link **to** a decision record. It MUST use the input `jcs(record)`. Settlement and outcome records use this rel to point back at the decision they follow.

A link proves only that the issuer referred to that exact record. It does not make the linked record's claims true. That is why each link has its own evidence ceiling.

When the verifier is given the linked records, it recomputes their hashes (`LINK_RECOMPUTED_OK:<rel>` as info; `LINK_NOT_SUPPLIED_OR_MISMATCH:<rel>` as a warning). A `raw(linked-record)` link cannot be recomputed from parsed JSON and is reported as not supplied. When no linked records are supplied at all, the reference verifiers (v1.0.1 and later) report each link as info `LINK_RECOMPUTATION_SKIPPED:<rel>` (§11.2).

## 8. Evidence ceilings

Each check, link, and field listed in `field_evidence_ceilings` (keys are JSON Pointers, RFC 6901) has an **evidence ceiling**: the strongest proof a verifier can get for that value.

| ceiling | meaning |
|---|---|
| `recomputable_from_chain` | anyone can recompute it from public chain data (e.g. wallet first-seen block, tx hash) |
| `recomputable_from_client_view` | the paying client can recompute it from what it saw (402 response, its authorization, its request) |
| `issuer_assertion` | only the issuer's word (score, policy, timestamps, private lists) |

The ceiling is a maximum, not a claim that anyone recomputed the value. An underwriter can weight fields by ceiling.

**Fields not listed.** A field of the record that is not a key of `field_evidence_ceilings` (and is not a check or a link, which carry their own ceiling) MUST be treated as `issuer_assertion`, the weakest ceiling. An empty map `{}` is valid against the schema and means every such field is `issuer_assertion`. *(Clarified in v1.0.1, Abdellah 19.11; no change to the format.)*

Every key of `field_evidence_ceilings` MUST resolve to a member of the record (RFC 6901 against the whole record); otherwise → INVALID (`UNRESOLVED_POINTER:<pointer>`). Ceiling values outside the three above are a schema violation.

## 9. Keys: rotation and revocation

- Each signing key has a `key_id`, a validity window `[valid_from, valid_until)` and a `status` (`active`, `retired` or `revoked`). Revoked keys also carry `revoked_at` and `revocation_reason` (`key_compromise` or `superseded`).
- Keys are published in a **keyset** document, `keyset.json` ([`schema/keyset.v1.0.schema.json`](./schema/keyset.v1.0.schema.json)), with `keyset_version: "1.0"` (anything else → `UNSUPPORTED_KEYSET_VERSION`).
- `key_id` MUST be unique within a keyset. A verifier MUST reject a keyset with duplicates (`DUPLICATE_KEY_ID:<key id>`) instead of picking one entry.
- `valid_until` MUST be after `valid_from`, and `revoked_at` MUST NOT be before `valid_from` (`BAD_KEY_WINDOW`). Keyset timestamps follow §3 (`BAD_TIMESTAMP:keyset#<pointer>`).
- Rotation: a new key gets a new `key_id` and an overlapping window. The old key moves to `retired` after its `valid_until` and stays in the keyset forever, so old records keep verifying. Keys are never deleted.

### 9.1 Where the keyset is published (v1.0.0)

1. **Primary:** GitHub Pages, https://jrosgren.github.io/x402-decision-record/.well-known/x402-decision-keyset.json. This is the value of `signing_key.keyset_uri`. The file lives in this repository at [`.well-known/x402-decision-keyset.json`](./.well-known/x402-decision-keyset.json), and `.nojekyll` makes Pages serve the `.well-known` folder.
2. **Secondary:** a release asset `keyset.json` attached to the tag `v1.0.0` (and to each later release that changes the keyset).
3. **Later third copy:** `https://trypolkulab.com/.well-known/x402-decision-keyset.json`. Issuers SHOULD add it, but it is not required.

All copies MUST be byte-identical.

**Exact bytes.** The anchor below is the SHA-256 of the **exact published bytes** of the keyset file (UTF-8, LF line endings, as served by GitHub Pages and attached to the release). It is not a hash of the parsed JSON, so any change of bytes, including line endings, gives a different hash and `KEYSET_SHA256_MISMATCH`. Implementers MUST hash the raw bytes as downloaded (for example `curl -fsS <url> | sha256sum`) and MUST NOT let a tool rewrite them first. In particular, a git checkout with `core.autocrlf=true` used to turn the LF file into CRLF, whose SHA-256 is `ffe2d99a…` instead of the anchor. Since v1.0.1 the repository's [`.gitattributes`](./.gitattributes) disables line-ending conversion for every byte-exact file (`*.json`, `*.pem`, `verifier/verify.html`). With an older clone, fetch the raw file or re-clone with `git -c core.autocrlf=false clone …`. *(Reported by Abdellah, 19.11.)*

**Anchor:** the release notes of each tag that publishes a keyset MUST state the hex SHA-256 of the exact bytes of `keyset.json`. A verifier SHOULD check its copy against that anchor (`verify.py --keyset-sha256 <hex>`, or the anchor field in `verify.html`; mismatch → `KEYSET_SHA256_MISMATCH`) and against a second copy. The anchor of the current published keyset (v1.0.2, demo key plus the production public key) is `725d2ecea67f2ee16908fd93130ab97c44ba9b94b51e7b26201ab6ed7975093a`. The v1.0.0/v1.0.1 demo-only keyset hashed to `958754dbd30cea1c7fa2937b674242d75a5297f5edcb3a5a3d48d0878223f745`. The issuer MUST check the Pages copy against the anchor after the merge and before publishing the release notes ([`RELEASING.md`](./RELEASING.md)).

### 9.2 No root key in v1.0

v1.0 has no long-lived root key. Trust in the keyset comes from the two publication channels and the release-notes anchor. The optional keyset member `keyset_signature` is **reserved** for v1.1, which may sign the keyset with a KMS-held root key without breaking the format. In v1.0, issuers SHOULD omit `keyset_signature` and verifiers MUST ignore it. *(Resolved, Ella 19.11.)*

### 9.3 Verifier rules

These run offline, against a keyset copy the verifier already has:

1. Validate the keyset (schema, `keyset_version`, unique `key_id`, timestamps, windows). Any error → INVALID.
2. Look up `signature.key_id`. If it is unknown → INVALID (`UNKNOWN_KEY`).
3. `decision_issued_at` MUST be within `[valid_from, valid_until)`. Otherwise → INVALID (`KEY_NOT_VALID_AT_ISSUANCE`). This is the "expired key" case.
4. `revoked` with `key_compromise` → INVALID for every record (`KEY_REVOKED`), because a compromised key can backdate.
5. `revoked` with `superseded` → still VALID for records issued before `revoked_at`, with the warning `KEY_SUPERSEDED_AFTER_ISSUANCE`. INVALID (`KEY_REVOKED`) for records issued at or after it.
6. Verifiers SHOULD refresh the keyset before relying on a record for money decisions. An offline verifier can only be as current as its keyset copy.

## 10. Not covered

`not_covered` is a REQUIRED list of `{code, text}` naming what the record does **not** attest. The example uses:

- `SETTLEMENT`
- `RESOURCE_DELIVERY`
- `RESOURCE_QUALITY`
- `PAYEE_LEGAL_IDENTITY`
- `LISTS_NOT_CHECKED`
- `PRINCIPAL_AUTHORIZATION`
- `FUTURE_STATE`

Readers MUST NOT infer coverage of anything listed there.

## 11. Verification procedure

0. **Parse and validate.** Check the text for duplicate members and numbers (§3: `DUPLICATE_MEMBER`, then `BAD_NUMBER`; `BAD_JSON` if it does not parse). Dispatch on the exact `schema_version`: `"1.0"` → these rules; `"0.2-draft"` → the legacy rules of §11.1, only if legacy verification is explicitly enabled (otherwise INVALID, `LEGACY_V02_NOT_ENABLED`); anything else, including `"0.3-draft"` (a review draft that was never issued) and `"1.0.0"`, → INVALID (`UNSUPPORTED_SCHEMA_VERSION`). No prefix matching. Then **validate the record against the JSON Schema for its version** (`SCHEMA_VIOLATION:<pointer>`, or the code the schema names in `x-error-code`, such as `BAD_SIGNATURE_OBJECT`, `NONCANONICAL_SIGNATURE`, `BAD_TIMESTAMP` or `UNSUPPORTED_NETWORK`), and check that every timestamp is a real time (§3). Any error here → INVALID, and the verifier stops.
1. **Key:** validate the keyset (ideally checked against the release anchor) and apply §9.3.
2. **Signature:** check it over the JCS bytes of the record without `signature`, with the strict rules of §3.
3. **Checks:** recompute each inline evidence hash (§6.1); report unknown check ids as info and never reject because of one (§6.2); check that every `field_evidence_ceilings` pointer resolves (§8).
4. **Timeline** (§5).
5. **Optionally** recompute the payment binding from raw inputs (§4) and linked record hashes (§7).
6. VALID only if the signature verifies and no step produced an error. Warnings and info do not make a record invalid.

The keyword `x-error-code` in the schemas is an annotation: generic JSON Schema validators ignore it, and the reference verifiers use it to name the error. Both reference verifiers implement the same small validator for the keywords the schemas use, so they report identical error lists for every vector.

Reference verifiers:

- [`verifier/verify.py`](./verifier/verify.py): CLI, offline. Requires `rfc8785`.
- [`verifier/verify.html`](./verifier/verify.html): single file, no network calls, schemas embedded. Hosted copy: https://jrosgren.github.io/x402-decision-record/verifier/verify.html

### 11.2 Info codes

Info codes describe what the verifier did. They never make a record INVALID and never turn an INVALID record VALID (§11 step 6). Errors (INVALID) and warnings are named in the sections above and in `expected.json`.

| info code | when | since |
|---|---|---|
| `BINDING_RECOMPUTED_OK` | binding inputs supplied and every check of §4 passed | v1.0.0 |
| `BINDING_RECOMPUTATION_SKIPPED` | no binding inputs supplied, so the payment binding was not recomputed | v1.0.1 |
| `LINK_RECOMPUTED_OK:<rel>` | linked records supplied and this link's hash matched one of them | v1.0.0 |
| `LINK_RECOMPUTATION_SKIPPED:<rel>` | no linked records supplied, so this link's hash was not recomputed (one entry per link) | v1.0.1 |
| `CUSTOM_CHECK_ID:<id>` | a check id with the `x-<issuer>.` prefix (§6.2) | v1.0.0 |
| `UNKNOWN_CHECK_ID:<id>` | a check id that is neither registered nor prefixed (§6.2) | v1.0.0 |
| `EVIDENCE_WITHHELD:<id>` | a check's evidence is not inline; only its hash is signed (§6.1) | v1.0.0 |

When linked records are supplied but a link's hash matches none of them, the result is the warning `LINK_NOT_SUPPLIED_OR_MISMATCH:<rel>` as in v1.0.0, not the skip code. Third-party verifiers MAY use other info codes; `expected.json` checks info with `info_includes` (must be present) and, since v1.0.1, `info_excludes` (must be absent).

### 11.1 Legacy 0.2-draft records

v0.2 records carry no payment binding, timeline or evidence hashes, so a VALID v0.2 result only says "this issuer key signed these bytes". Verifiers MUST NOT apply these rules unless the caller opts in (`verify.py --allow-legacy-v02`, `allowLegacyV02: true` in `verify.html`'s API, the "Also accept legacy 0.2-draft records" box on the page). When enabled:

1. **Closed v0.2 schema.** Validate against [`schema/decision-record.v0.2.schema.json`](./schema/decision-record.v0.2.schema.json) (`additionalProperties: false`, `checkedAt` required and a real timestamp). Any v1.0 member (`record_type`, `issuer`, `signing_key`, `payment`, `timeline`, `checks`, `decision`, `field_evidence_ceilings`, `links`, `not_covered`) → INVALID (`LEGACY_V02_WITH_V1_FIELDS:<pointer>`). This stops v1.0 content from being relabelled `0.2-draft` to skip the v1.0 checks.
2. **Key, with a keyset** (the normal case): validate the keyset as in §9.3; an unknown `key_id` → INVALID (`UNKNOWN_KEY`), **never** a fallback to the demo key; `checkedAt` outside `[valid_from, valid_until)` → INVALID (`KEY_NOT_VALID_AT_ISSUANCE`); a revoked key → INVALID (`KEY_REVOKED`) whatever `revocation_reason` says, because `checkedAt` is not bound to a payment and cannot be trusted as an issuance time.
3. **Key, without a keyset:** a public key given explicitly is used as is, with the warning `NO_KEYSET_VALIDITY_NOT_CHECKED`. With neither a keyset nor a key, the verifiers use the demo key and add the warning `DEMO_KEY_ASSUMED`.
4. **Signature** over the JCS bytes without `signature`, with the strict rules of §3. A v0.2 `signature.sha256` that does not match is a warning (`EMBEDDED_SHA256_MISMATCH`).
5. Every VALID legacy result carries the warning `LEGACY_V02_SIGNATURE_ONLY`.

[`test-vectors/v1.0/expected.json`](./test-vectors/v1.0/expected.json) lists every vector with its expected status, errors and warnings, positive and negative. Third-party verifiers SHOULD pass the same list.

## 12. Changelog

### 12.0 v1.0.0 (19.11.2026) and what comes next

v1.0.0 is final: the record format, schemas, error codes and test vectors of this release do not change. Comments received before 23.11.2026 from the x402 Slack reviewers or from underwriters will go into **v1.0.1 or v1.1**, as **additive** changes only (new optional fields, new check ids, new info or warning codes, more test vectors). A record that is VALID under v1.0.0 stays VALID. Anything that would break that needs a v2.0.

### 12.0.2 v1.0.2 (24.11.2026)

Additive only (§12.0): the record format, schemas, verifiers and all 75 v1.0.1 test-vector files are unchanged. A record that is VALID under v1.0.1 stays VALID.

- **Published keyset:** the primary copy at [`.well-known/x402-decision-keyset.json`](./.well-known/x402-decision-keyset.json) keeps the still-active demo key and adds the Payvetted production public key `payvetted-prod-2026-12`. The demo key still signs example records only. A production signing endpoint is not live yet. The new keyset anchor is `725d2ecea67f2ee16908fd93130ab97c44ba9b94b51e7b26201ab6ed7975093a` (§9.1).
- **Generator:** `tools/make_vectors.py` no longer overwrites the published well-known file with the demo-only keyset.

### 12.0.1 v1.0.1 (20.11.2026)

Additive only (§12.0): the format, schemas and every v1.0.0 error and warning are unchanged, and the 70 v1.0.0 cases in `expected.json` are unchanged. Thanks to Abdellah (holistis, agent-receipt-verify), who built an independent verifier from the v1.0 text and reported these in the x402 Slack thread on 19.11.

- **Line endings (bug fix):** new `.gitattributes` with `*.json -text`, `*.pem -text` and `verifier/verify.html -text` (and `* text=auto eol=lf` for the rest), so a checkout with `core.autocrlf=true` no longer turns the keyset into CRLF and breaks the anchor (`ffe2d99a…` instead of `958754db…`). The committed bytes were and are LF. §9.1 now says the anchor is over the exact published bytes.
- **Fields not listed in `field_evidence_ceilings`** are `issuer_assertion`; `{}` is valid (§8). A clarification, not a format change.
- **Info codes for skipped recomputation:** `BINDING_RECOMPUTATION_SKIPPED` and `LINK_RECOMPUTATION_SKIPPED:<rel>` in `verify.py` and `verify.html` (§4, §7, new table §11.2). Info only, so no VALID/INVALID outcome changes.
- **Test vectors:** 5 new cases in `expected.json` (75 in total), and the optional `info_excludes` field. New tests for LF bytes, the `.gitattributes` rules and the CRLF anchor mismatch.
- **Verifier version:** `verify.py --version` and `AgentTrustVerifier.VERIFIER_VERSION` report `1.0.1`; the page byline names release v1.0.1.

### 12.1 Changes from the v0.3-draft review (19.11)

- **Strict signature object** (review M1): exactly `alg`, `key_id`, `sig_base64`; `canonicalization` and `sha256` removed; canonical base64 and `S < L` required on every path. Without this, a third party could change `jcs(record)` of a valid record in five ways.
- **Exact versions** (M2): `schema_version` and `keyset_version` are `"1.0"` and matched exactly, otherwise `UNSUPPORTED_SCHEMA_VERSION` / `UNSUPPORTED_KEYSET_VERSION`. No silent fallback to v0.2 rules.
- **Unique key ids** (M3): `DUPLICATE_KEY_ID` instead of last-entry-wins.
- **Timestamps** (M4): whole seconds or exactly milliseconds, with `Z`, the same regex in schema and verifiers (`BAD_TIMESTAMP`); keyset timestamps too.
- **x402 v2 binding** (M5): `x402_version: 2`, `amount` instead of v1 `maxAmountRequired`, `resource` from `PaymentRequired.resource`; missing binding fields are errors.
- **Schema validation as step 0** (M6) in both verifiers; `links[].evidence_ceiling` is now required and seller attestations must carry `scope` and `expires_at`.
- **Negative vectors as files** (M7) in `test-vectors/v1.0/negative/`, all listed in `expected.json` and run by both test suites.
- **Numbers** (B1): integers within ±(2^53−1), no fraction or exponent part anywhere (`BAD_NUMBER`); `verify.py` requires `rfc8785`.
- **Timeline rule** (B2) written as one chain, plus `valid_after < valid_before`.
- **Nonce length** (B3): exactly 32 bytes (`BAD_NONCE`).
- **Verifier parity** (B4): `verify.html` has the anchor check and linked-record recomputation.
- **Field pointers** (review K1): `field_evidence_ceilings` keys must resolve (`UNRESOLVED_POINTER`). Keyset top level is closed and windows are checked (`BAD_KEY_WINDOW`).
- Test vectors moved from `test-vectors/v0.3/` to `test-vectors/v1.0/`, schemas renamed to `*.v1.0.schema.json`.

Follow-up review of `dcedfb5` (19.11):

- **Legacy path closed** (MUST): 0.2-draft is opt-in (`LEGACY_V02_NOT_ENABLED`), validated against a closed v0.2 schema (`LEGACY_V02_WITH_V1_FIELDS`), uses the keyset rules without any demo-key fallback (`UNKNOWN_KEY`), treats every revocation as `KEY_REVOKED`, checks `checkedAt` against the key window, and marks every VALID result `LEGACY_V02_SIGNATURE_ONLY` (§11.1). Negative vectors for the three reported cases are in `expected.json`.
- **Duplicate members** (SHOULD): `DUPLICATE_MEMBER:<pointer>` for records and keysets (§3).
- **Browser number check fails closed** (SHOULD): `verify.html` scans the JSON text itself instead of relying on `JSON.parse` source-text access, so `62.0` is rejected in every browser.
- **CAIP-2 chain id** (SHOULD): `^eip155:[1-9][0-9]*$` (§4).

Optional items from the approval of `96ecab0` (19.11): binding inputs and linked records go through the same strict text parser (`DUPLICATE_MEMBER`, `BAD_NUMBER`, `BAD_JSON`, labelled `binding_inputs#` / `linked[<i>]#`), and a parsed object passed instead of text gives the warning `PARSED_INPUT:<input>` (§3).

### 12.2 Changes vs v0.2-draft

- **Payment binding (new `payment`)**: binds the record to one payment through the hash of the authorization nonce, plus payer, payee, `amount_atomic`, asset, network, scheme, resource and the authorization window. Adds `payment_requirements_sha256`, `request_sha256` and `tx_hash` (null before settlement). Replaces v0.2 `input`, `payer_wallet`, `asset` and `amount`.
- **Timeline (new)**: `timeline` and a `ran_at` on each check, with ordering rules relative to the authorization.
- **Exact hashing (new)**: every hash is `{alg, input, hex}`, with the input ids defined in §6.
- **Evidence (changed)**: v0.2 `evidence` (a map of free-text details) becomes `checks[]`, each with structured `evidence`, `evidence_sha256` and `evidence_ceiling`.
- **Evidence ceilings (new)**: `field_evidence_ceilings`.
- **Links (new)**: `links[]` for content-time records and seller attestations (issuer, scope, expiry).
- **Not covered (new)**: required `not_covered[]`.
- **Keys (new)**: `signing_key` inside the signed body, a keyset document with validity windows and revocation, and the verifier rules in §9.
- **Decision (moved)**: `verdict`, `score`, `level`, `reason_codes`, `policy_id` and `payer_agent_id` move under `decision`. Free-text `reasons` are dropped; use `reason_codes` and the evidence.
- **Outcome (removed)**: `outcome` is removed from the decision record. It belongs in a separate linked outcome record, because a signed record cannot be updated later.
- **Networks**: EVM only (`eip155:<chain id>`). Non-EVM is deferred to v1.1.
- **Check ids**: a minimal registry plus an `x-<issuer>.` prefix for custom checks. Verifiers ignore unknown ids.
- **Linked decision records**: hashed with `jcs(record)`, which includes the signature.
- **Keyset**: primary copy on GitHub Pages, secondary copy as a release asset, with a SHA-256 anchor in the release notes. `keyset_signature` is reserved for v1.1.
- **No floats**: numbers with a fraction or exponent part are not allowed, and integers stay within ±(2^53−1), which keeps JCS simple.
- **Signature object (changed)**: exactly `alg`, `key_id`, `sig_base64`; v0.2's unsigned `canonicalization` and `sha256` members are gone.
- **Unchanged**: the signature method (Ed25519 over the JCS of the record without `signature`) and the demo key id `polkulab-demo-2026-11`.

## 13. Questions resolved for v1.0

- **Q1. Should the keyset be signed by a root key?** Resolved (Ella 19.11): no root key in v1.0. The keyset is published in two places, with a SHA-256 anchor in the release notes. `keyset_signature` is reserved for a v1.1 KMS root key. See §9.2.
- **Q2. Should links hash a decision record with or without its signature?** Resolved (Ella 19.11): with. The input id is `jcs(record)`. The strict signature rules in §3 keep the hash stable. See §6.
- **Q3. Should non-EVM schemes be covered now?** Resolved (Ella 19.11): v1.0 covers EVM/Base only, with CAIP-2 `eip155:<chain id>`. Solana and other non-EVM schemes come in v1.1. See §4.
- **Q4. Should there be a check-id registry?** Resolved (Ella 19.11): a minimal registry plus an `x-<issuer>.` prefix for custom checks, and verifiers ignore unknown ids. See §6.2.
- **Q5. Which fields do underwriters need that are still missing?** **Open, after v1.0.** Underwriter input received before 23.11.2026 goes into v1.0.1 or v1.1 as additive fields (§12.0).
