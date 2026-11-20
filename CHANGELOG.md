# Changelog

All releases of x402-decision-record. The record format is `schema_version: "1.0"` in every 1.0.x release. Patch releases are additive only (SPEC §12.0): a record that is VALID under v1.0.0 stays VALID.

## v1.0.1 (20.11.2026)

Thanks to **Abdellah (holistis, agent-receipt-verify)**, who built an independent verifier from the v1.0 spec, passed all 70 cases, and reported the items below in the x402 Slack thread on 19.11.

- **Fixed:** with git `core.autocrlf=true` the keyset JSON was checked out with CRLF line endings, so its SHA-256 (`ffe2d99a…`) no longer matched the anchor `958754dbd30cea1c7fa2937b674242d75a5297f5edcb3a5a3d48d0878223f745` and one vector failed. New `.gitattributes` turns off line-ending conversion for `*.json`, `*.pem` and `verifier/verify.html`. The committed bytes are LF, unchanged, and the anchor is unchanged. SPEC §9.1 now says the anchor is over the exact published bytes, and how to fetch them.
- **Clarified (SPEC §8):** a field not listed in `field_evidence_ceilings` is treated as `issuer_assertion`; an empty map is valid.
- **Added:** info codes `BINDING_RECOMPUTATION_SKIPPED` and `LINK_RECOMPUTATION_SKIPPED:<rel>` when binding inputs or linked records are not supplied, in `verify.py` and `verify.html`, with an info-code table (SPEC §11.2). Info only: no VALID/INVALID outcome changes.
- **Added:** 5 test cases (75 in `expected.json`; the 70 v1.0.0 cases are unchanged) and the optional `info_excludes` field; tests for LF bytes, `.gitattributes` and the CRLF anchor mismatch.
- **Added:** `verify.py --version` and `AgentTrustVerifier.VERIFIER_VERSION` (`1.0.1`).

## v1.0.0 (19.11.2026)

First release: SPEC v1.0, JSON Schemas, signed positive and negative test vectors (70 cases), Python and browser verifiers, demo keyset on GitHub Pages and as release asset. See SPEC §12.1 and §12.2.
