# Changelog

All releases of x402-decision-record. The record format is `schema_version: "1.0"` in every 1.0.x release. Patch releases are additive only (SPEC §12.0): a record that is VALID under v1.0.0 stays VALID.

## v1.0.2 (24.11.2026)

Additive only (SPEC §12.0): the record format, schemas, verifiers and all 75 v1.0.1 test-vector files are unchanged. A record that is VALID under v1.0.1 stays VALID.

- **Published keyset:** [`.well-known/x402-decision-keyset.json`](./.well-known/x402-decision-keyset.json) keeps the still-active demo key `polkulab-demo-2026-11` and adds the Payvetted production public key `payvetted-prod-2026-12` (valid from 2026-11-24T00:00:00Z to 2027-11-24T00:00:00Z). `example_data` is removed from the published file. The production private key is held in AWS KMS and is not in this repository. A production signing endpoint is not live yet, and no production records have been issued.
- **Anchor:** SHA-256 of the published keyset bytes is `725d2ecea67f2ee16908fd93130ab97c44ba9b94b51e7b26201ab6ed7975093a`. The v1.0.0/v1.0.1 demo-only keyset hashed to `958754dbd30cea1c7fa2937b674242d75a5297f5edcb3a5a3d48d0878223f745`.
- **`tools/make_vectors.py`** no longer overwrites the published well-known keyset with the demo-only keyset. It still writes `test-vectors/v1.0/keyset-demo.json` and `verifier/demo-keyset.json`, and it copies the published file to `test-vectors/v1.0/keyset-published.json` so the release-anchor test stays in sync.
- **Verifier version** remains `1.0.1` (no change to verification behaviour).

## v1.0.1 (20.11.2026)

Thanks to **Abdellah (holistis, agent-receipt-verify)**, who built an independent verifier from the v1.0 spec, passed all 70 cases, and reported the items below in the x402 Slack thread on 19.11.

- **Fixed:** with git `core.autocrlf=true` the keyset JSON was checked out with CRLF line endings, so its SHA-256 (`ffe2d99a…`) no longer matched the anchor `958754dbd30cea1c7fa2937b674242d75a5297f5edcb3a5a3d48d0878223f745` and one vector failed. New `.gitattributes` turns off line-ending conversion for `*.json`, `*.pem` and `verifier/verify.html`. The committed bytes are LF, unchanged, and the anchor is unchanged. SPEC §9.1 now says the anchor is over the exact published bytes, and how to fetch them.
- **Clarified (SPEC §8):** a field not listed in `field_evidence_ceilings` is treated as `issuer_assertion`; an empty map is valid.
- **Added:** info codes `BINDING_RECOMPUTATION_SKIPPED` and `LINK_RECOMPUTATION_SKIPPED:<rel>` when binding inputs or linked records are not supplied, in `verify.py` and `verify.html`, with an info-code table (SPEC §11.2). Info only: no VALID/INVALID outcome changes.
- **Added:** 5 test cases (75 in `expected.json`; the 70 v1.0.0 cases are unchanged) and the optional `info_excludes` field; tests for LF bytes, `.gitattributes` and the CRLF anchor mismatch.
- **Added:** `verify.py --version` and `AgentTrustVerifier.VERIFIER_VERSION` (`1.0.1`).

## v1.0.0 (19.11.2026)

First release: SPEC v1.0, JSON Schemas, signed positive and negative test vectors (70 cases), Python and browser verifiers, demo keyset on GitHub Pages and as release asset. See SPEC §12.1 and §12.2.
