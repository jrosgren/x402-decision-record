# Sample decision record – field guide

EXAMPLE DATA ONLY. This describes the illustrative record in `sample-decision-record.json`. Values in the sample are made up. Field names are a draft and are not a finished standard.

## Core fields

- **input**: what was checked. `url` (the x402 resource) or `payTo` (the payee address); at least one. `network` as CAIP-2, e.g. `eip155:8453` (Base mainnet).
- **verdict**: `allow` | `warn` | `deny`.
- **score**: 0–100 risk score, and **level**: `low` | `medium` | `high`.
- **reasons**: array of short human-readable strings. **reason_codes** (optional): array of machine-readable codes, same order as `reasons`.
- **evidence**: one entry per check, each with a `result` (pass | warn | fail) and a `detail`:
  - `liveness`: does the resource answer with a valid x402 402 response.
  - `price_vs_listing`: requested amount vs the listed price.
  - `payto_change`: has the payee address changed since first seen.
  - `schema`: do the x402 payment requirements match the expected schema.
  - `payee_wallet_risk`: payee wallet risk signals, including an OFAC sanctions check (`ofac_match`).
- **checkedAt**: time of the check, ISO 8601 (UTC).

## Optional extensions

Grouped under `agenttrust_ext` in the sample. These are extras a platform, auditor or insurer might want on top of the core fields; they are not required for the idea to work.

- `record_id`, `schema_version`: record id and format version.
- `payer_agent_id`, `payer_wallet`: which agent and wallet tried to pay.
- `asset`, `amount`: payment asset and amount (the observed price also appears in `evidence.price_vs_listing`).
- `policy_id`: which rule set produced the verdict.
- `outcome`: added later and linked to the record (settled, refunded, disputed) with source and time. This verdict-to-outcome link is what makes the logs useful as later evidence.
- `signature`: signs the record so a third party (insurer, auditor, platform) can check it wasn't changed after the fact.

Open questions: which extra fields would you require before relying on a record like this (for disputes, refunds, or underwriting)? Examples might include agent operator identity, spending limits, a human-in-the-loop flag, or loss amount.
