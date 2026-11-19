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

## v0.3-draft (in review)

[`SPEC.md`](./SPEC.md) describes v0.3-draft, shaped by feedback in the x402 Slack. The record is bound to one payment through the hash of the authorization nonce, and each check has a timestamp and an evidence hash. Each hash states exactly which bytes it covers, and each field carries an evidence ceiling. Other records can be linked by hash, a not-covered list says what the record does not attest, and the keys have rotation and revocation rules. It comes with a JSON Schema in [`schema/`](./schema/), signed test vectors in [`test-vectors/v0.3/`](./test-vectors/v0.3/), and updated verifiers. **v0.3 is planned to be frozen as v1.0 on 24.11.2026, with release v1.0.0 by 25.11.2026.**

## What's in this repo

- [`sample-decision-record.json`](./sample-decision-record.json) — an example record (example data only)
- [`sample-decision-record-fields.md`](./sample-decision-record-fields.md) — field guide
- **Try it online:** [jrosgren.github.io/x402-decision-record/verifier/verify.html](https://jrosgren.github.io/x402-decision-record/verifier/verify.html) — loads the valid and tampered examples; all checking happens in your browser.
- [`SPEC.md`](./SPEC.md) — v0.3-draft spec and changelog vs v0.2
- [`schema/`](./schema/) — JSON Schema 2020-12 for the record and the keyset
- [`test-vectors/v0.3/`](./test-vectors/v0.3/) — valid, tampered, wrong-key, expired-key and revoked-key cases (example data)
- [`tests/`](./tests/) — `bash tests/run_all.sh`
- [`verifier/`](./verifier/) — a standalone third-party check: open [`verifier/verify.html`](./verifier/verify.html) in a browser (no network calls; nothing leaves the device), or use `verifier/verify.py` / OpenSSL. Includes a valid signed example and a tampered copy (score 62→30, original signature kept) so you can see a pass and a fail. Demo key id: `polkulab-demo-2026-11`.

## License

MIT
