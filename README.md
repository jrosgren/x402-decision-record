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

## What's in this repo

- [`sample-decision-record.json`](./sample-decision-record.json) — an example record (example data only)
- [`sample-decision-record-fields.md`](./sample-decision-record-fields.md) — field guide
- [`verifier/`](./verifier/) — a standalone third-party check: open [`verifier/verify.html`](./verifier/verify.html) in a browser (no network calls; nothing leaves the device), or use `verifier/verify.py` / OpenSSL. Includes a valid signed example and a tampered copy (score 62→30, original signature kept) so you can see a pass and a fail. Demo key id: `polkulab-demo-2026-11`.

## License

MIT
