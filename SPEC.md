# x402 pre-payment decision record: v0.3-draft

**Status: DRAFT, open for review.** v0.3 is planned to be frozen as **v1.0 on 24.11.2026**, with a tagged release **v1.0.0 by 25.11.2026** (JSON Schema, changelog, test vectors and verifier). Comments before then are welcome in the PR or the x402 Slack thread.

**EXAMPLE DATA ONLY.** All records, keys, wallets and URLs in this repository are made-up illustrations. The demo key `polkulab-demo-2026-11` signs example records only. Payvetted is pre-launch and issues no production records yet.

Author: Aron, Polkulab (Payvetted). Thanks to Miguel Martinez (ReturnCheck), Romeo Reynolds and Abdellah (agent-receipt-verify) for the feedback in the x402 Slack thread that shaped v0.3.

## 1. Purpose and scope

A decision record is a small, signed statement written **before** an agent pays an x402 resource. It says which checks ran, when they ran, what evidence they saw, what was decided, and exactly which payment the decision was about. It is meant to be verified later by a third party (a platform, an auditor, an insurer) with only the record, the issuer's public keyset, and open algorithms.

The record is deliberately **thin**. It attests to one decision about one payment. Other facts (settlement, content delivered, seller identity) belong in other records and are linked by hash (§7), not copied in.

Keywords MUST, SHOULD and MAY are used as in RFC 2119.

## 2. Record overview

```
{
  "schema_version": "0.3-draft",
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
  "signature": { alg, key_id, canonicalization, sha256, sig_base64 }                    // §3
}
```

Full example: [`test-vectors/v0.3/valid.json`](./test-vectors/v0.3/valid.json). Schema: [`schema/decision-record.v0.3.schema.json`](./schema/decision-record.v0.3.schema.json) (JSON Schema 2020-12).

## 3. Signature (unchanged from v0.2)

- Remove the `signature` member from the record.
- Canonicalize the rest with **RFC 8785 (JCS)** and encode as UTF-8. These are the **signed bytes**.
- Sign the signed bytes with **Ed25519** (RFC 8032, pure, no pre-hash).
- `signature.sig_base64` is the 64-byte signature in standard base64 with padding.
- `signature.sha256` is the hex SHA-256 of the signed bytes. It is informative only, to help debugging; verifiers MUST check the signature, not this value.
- `signature.key_id` MUST equal `signing_key.key_id`. The copy inside the signed body stops key-id substitution.

To keep JCS trivial to implement, v0.3 records MUST NOT contain floating-point numbers. Amounts are decimal strings in atomic units; scores are integers. Timestamps are RFC 3339 strings in UTC with a `Z` suffix.

## 4. Payment binding

`payment` binds the record to exactly one x402 payment:

| field | meaning |
|---|---|
| `x402_version`, `scheme`, `network` (CAIP-2), `asset` | as in the selected x402 `PaymentRequirements` |
| `amount_atomic` | amount in the asset's smallest unit, decimal string |
| `payer`, `payee` | payer wallet and `payTo` |
| `resource` | resource URL from the requirements |
| `authorization.nonce_sha256` | hash of the EIP-3009 authorization nonce (§6.1) |
| `authorization.valid_after`, `valid_before` | the authorization's validity window, as RFC 3339 |
| `payment_requirements_sha256` | hash of the selected `PaymentRequirements` object as received |
| `request_sha256` | hash of the resource request (method, URL, body hash) |
| `tx_hash` | `null` when signed before settlement (the normal case) |

Flow: the client builds the payment authorization (including its nonce), presents it to the checker before signing, and the checker issues the record. The nonce is unique per payment, so a record cannot be reused for a second payment. The record carries the **hash** of the nonce, not the nonce itself, so a record leaked before settlement does not reveal the authorization.

Settlement is not in this record. A settlement or outcome record SHOULD link back to this record by its hash (`jcs(linked-record)` over this record minus `signature`, or over the full signed record; see open question Q2).

## 5. Timeline

`timeline` holds `requirements_received_at`, `authorization_presented_at` and `decision_issued_at`. Each check has its own `ran_at`. A verifier MUST reject a record where:

- a check's `ran_at` is before `authorization_presented_at` or after `decision_issued_at`;
- `requirements_received_at` > `authorization_presented_at` > `decision_issued_at` (out of order);
- `decision_issued_at` ≥ `authorization.valid_before`.

Timestamps are the issuer's clock (evidence ceiling `issuer_assertion`). They show order and spacing, not proof of time. A trusted timestamp (RFC 3161 or an on-chain anchor) can be added later as a linked record.

## 6. Hashes: exactly which bytes

Every hash is an object `{"alg": "sha-256", "input": "<input id>", "hex": "<64 lowercase hex>"}`. `input` names exactly which bytes were hashed:

| input id | bytes hashed | used in |
|---|---|---|
| `eip3009-nonce-bytes32` | the 32 raw bytes of the nonce (hex-decoded, without `0x`) | `payment.authorization.nonce_sha256` |
| `jcs(payment_requirements)` | UTF-8 JCS of the selected `PaymentRequirements` object, exactly as received in the 402 response (one element of `accepts`) | `payment.payment_requirements_sha256` |
| `jcs(resource_request)` | UTF-8 JCS of `{"method", "url", "body_sha256"}`: HTTP method in upper case, absolute URL as requested including query, hex SHA-256 of the raw request body (empty body → hash of zero bytes) | `payment.request_sha256` |
| `jcs(evidence)` | UTF-8 JCS of the check's `evidence` object | `checks[].evidence_sha256` |
| `jcs(linked-record)` | UTF-8 JCS of the linked JSON record as published | `links[].record_sha256` |
| `raw(linked-record)` | the exact bytes of a linked non-JSON record | `links[].record_sha256` |

New input ids MUST be defined in this spec before use. Verifiers MUST treat an unknown input id as unverifiable.

[`test-vectors/v0.3/binding-inputs.json`](./test-vectors/v0.3/binding-inputs.json) holds the raw example inputs, so a client can recompute the binding hashes (`verify.py --binding-inputs`).

## 6.1 Checks and evidence

Each element of `checks` has `id`, `result` (`pass|warn|fail|error|skipped`), `ran_at`, `evidence_ceiling` and `evidence_sha256`, and MAY carry the `evidence` object inline.

- If `evidence` is inline, the verifier MUST recompute `jcs(evidence)` and reject on mismatch.
- If it is withheld (for privacy or size), the hash still commits the issuer to it, and it can be disclosed later and checked against the signed hash.
- Evidence SHOULD hold the facts behind the result (block numbers, list snapshot hashes, observed vs listed price), not only a summary.

The score alone is never the evidence.

## 7. Links to other records (composability)

`links` points to other records by hash. Each link has a `rel`, the `issuer` of the linked record, a `record_sha256`, an `evidence_ceiling`, and optionally `uri`, `scope` and `expires_at`. Defined `rel` values in v0.3:

- `content_time_record`: a record of what content was served when (e.g. by the paid endpoint).
- `seller_attestation`: a statement by an attester about the seller, e.g. that `payTo` belongs to the operator of a domain. It MUST carry `scope` and `expires_at`. A verifier SHOULD warn if `expires_at` ≤ `decision_issued_at`.
- `settlement_record`, `outcome_record`: reserved for later records that link **to** a decision record.

A link proves only that the issuer referred to that exact record. It does not make the linked record's claims true. That is why each link has its own evidence ceiling.

## 8. Evidence ceilings

Each check, link, and field listed in `field_evidence_ceilings` (keys are JSON Pointers, RFC 6901) has an **evidence ceiling**: the strongest proof a verifier can get for that value.

| ceiling | meaning |
|---|---|
| `recomputable_from_chain` | anyone can recompute it from public chain data (e.g. wallet first-seen block, tx hash) |
| `recomputable_from_client_view` | the paying client can recompute it from what it saw (402 response, its authorization, its request) |
| `issuer_assertion` | only the issuer's word (score, policy, timestamps, private lists) |

The ceiling is a maximum, not a claim that anyone recomputed the value. An underwriter can weight fields by ceiling.

## 9. Keys: rotation and revocation

- Each signing key has a `key_id`, a validity window `[valid_from, valid_until)` and a `status` (`active`, `retired` or `revoked`). Revoked keys also carry `revoked_at` and `revocation_reason` (`key_compromise` or `superseded`).
- Keys are published in a **keyset** document ([`schema/keyset.v0.3.schema.json`](./schema/keyset.v0.3.schema.json)) in two independent places:
  1. `https://trypolkulab.com/.well-known/x402-decision-keyset.json` (`signing_key.keyset_uri`);
  2. a tagged release of this repository (`keys/keyset.json` from v1.0.0 on).

  A verifier SHOULD check that both copies match. The demo keyset is [`verifier/demo-keyset.json`](./verifier/demo-keyset.json).
- Rotation: a new key gets a new `key_id` and an overlapping window. The old key moves to `retired` after its `valid_until` and stays in the keyset forever, so old records keep verifying. Keys are never deleted.

Verifier rules (offline, against a keyset the verifier already has):

1. Look up `signature.key_id`. If it is unknown → INVALID (`UNKNOWN_KEY`).
2. `decision_issued_at` MUST be within `[valid_from, valid_until)`. Otherwise → INVALID (`KEY_NOT_VALID_AT_ISSUANCE`). This is the "expired key" case.
3. `revoked` with `key_compromise` → INVALID for every record (`KEY_REVOKED`), because a compromised key can backdate.
4. `revoked` with `superseded` → still VALID for records issued before `revoked_at`, with the warning `KEY_SUPERSEDED_AFTER_ISSUANCE`. INVALID for records issued after it.
5. Verifiers SHOULD refresh the keyset before relying on a record for money decisions; an offline verifier can only be as current as its keyset copy.

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

## 11. Verification procedure (summary)

1. Parse; dispatch on `schema_version` (`0.2-draft` → v0.2 rules, `0.3-draft` → these rules).
2. Key: find it in the keyset and apply §9.
3. Signature: check it over the JCS bytes of the record without `signature` (§3).
4. Recompute each inline evidence hash (§6.1) and check every ceiling value is one of the three in §8.
5. Check the timeline (§5).
6. Optionally recompute the payment binding hashes from raw inputs (§4, §6) and linked record hashes (§7).
7. VALID only if the signature verifies and no step produced an error.

Reference verifiers:

- [`verifier/verify.py`](./verifier/verify.py): CLI, offline.
- [`verifier/verify.html`](./verifier/verify.html): single file, no network calls. Hosted copy: https://jrosgren.github.io/x402-decision-record/verifier/verify.html

Both verifiers still verify v0.2 records.

## 12. Changelog vs v0.2-draft

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
- **No floats**: floating-point numbers are not allowed, which keeps JCS simple.
- **Unchanged**: the signature method (Ed25519 over the JCS of the record without `signature`) and the demo key id `polkulab-demo-2026-11`.

## 13. Open questions (to settle before the v1.0 freeze on 24.11)

- **Q1.** Should the keyset itself be signed by a long-lived root key, or are two publication channels (domain + tagged release) enough?
- **Q2.** Should links to a decision record hash it with or without its `signature` member? The draft leans to "with", because it pins the exact signed artefact.
- **Q3.** Should the record also cover non-EVM schemes (e.g. Solana) now, with a scheme-specific nonce input id, or should that wait for v1.1?
- **Q4.** Should v1.0 add a minimum set of check ids (a registry) so scores from different issuers can be compared?
- **Q5.** Which fields do underwriters need that are still missing? Input from reviewers is welcome before 23.11.
