# x402 decision record (example)

**EXAMPLE DATA ONLY.** This repository is an illustrative example of a signed pre-payment decision record for agent payments on [x402](https://www.x402.org/). Nothing here is a live integration, a finished standard, or production data. All values in the sample are made up.

## The idea

Before an agent pays a 402 endpoint, many teams run some check (is the endpoint live, does the price match the listing, did payTo change, is the payee wallet flagged). Today the result of that check usually disappears. Nobody can later prove what the agent knew when it paid.

This example explores a small, open format for a **signed decision record** written at payment time:

- the request (url, payTo, network, price as observed)
- the checks run and their evidence
- the verdict (allow / warn / deny) and a score
- payer agent and policy ids, outcome, timestamp, signature

The idea is that a platform, an auditor or an insurer could verify the record later without trusting the agent's own logs.

This is a question, not a finished proposal: would a shared format be useful, or is this better left to each facilitator?

## v1.0

[`SPEC.md`](./SPEC.md) describes v1.0, which was v0.3-draft and was shaped by feedback in the x402 Slack and a review on 19.11. The record is bound to one x402 v2 payment through the hash of the authorization nonce, and each check has a timestamp and an evidence hash. Each hash states exactly which bytes it covers, and each field carries an evidence ceiling. Other records can be linked by hash, a not-covered list says what the record does not attest, and the keys have rotation and revocation rules. The signature object is strict (exactly `alg`, `key_id`, `sig_base64`, canonical base64, `S < L`), so the hash of a signed record cannot be changed by a third party. It comes with a JSON Schema in [`schema/`](./schema/), signed positive and negative test vectors in [`test-vectors/v1.0/`](./test-vectors/v1.0/) with one shared [`expected.json`](./test-vectors/v1.0/expected.json), and two verifiers that give identical results on every vector. **Released as v1.0.0 on 19.11.2026; v1.0.1 on 20.11.2026** (line-ending fix, §8 clarification, info codes for skipped recomputation; additive only, see [`CHANGELOG.md`](./CHANGELOG.md)). Comments received before 23.11.2026 go into v1.0.1 or v1.1 as additive changes (SPEC §12.0).

If you clone with `core.autocrlf=true`: the repo's `.gitattributes` keeps the byte-exact files (JSON, PEM, `verify.html`) in LF, so the keyset still hashes to the anchor. Always hash the raw downloaded bytes.

Demo keyset anchor (SHA-256 of [`.well-known/x402-decision-keyset.json`](./.well-known/x402-decision-keyset.json)): `958754dbd30cea1c7fa2937b674242d75a5297f5edcb3a5a3d48d0878223f745`

## What's in this repo

- [`sample-decision-record.json`](./sample-decision-record.json) — an example record (example data only)
- [`sample-decision-record-fields.md`](./sample-decision-record-fields.md) — field guide
- **Try it online:** [jrosgren.github.io/x402-decision-record/verifier/verify.html](https://jrosgren.github.io/x402-decision-record/verifier/verify.html) — loads the valid and tampered examples; all checking happens in your browser.
- [`SPEC.md`](./SPEC.md) — v1.0 spec and changelog
- [`schema/`](./schema/) — JSON Schema 2020-12 for the record and the keyset
- [`test-vectors/v1.0/`](./test-vectors/v1.0/) — signed positive and negative vectors (example data), listed with expected results in `expected.json`
- [`.well-known/x402-decision-keyset.json`](./.well-known/x402-decision-keyset.json): demo keyset at its published location (primary copy, served by GitHub Pages)
- [`RELEASING.md`](./RELEASING.md): release steps and the keyset SHA-256 anchor
- [`CHANGELOG.md`](./CHANGELOG.md): release history
- [`tests/`](./tests/) — `bash tests/run_all.sh` (Python, OpenSSL, Node and headless Chrome; needs `pip install rfc8785 jsonschema cryptography`)
- [`verifier/`](./verifier/) — a standalone third-party check: open [`verifier/verify.html`](./verifier/verify.html) in a browser (no network calls; nothing leaves the device), or use `verifier/verify.py` / OpenSSL. Includes a valid signed example and a tampered copy (score 62→30, original signature kept) so you can see a pass and a fail. Demo key id: `polkulab-demo-2026-11`.

## License

MIT
