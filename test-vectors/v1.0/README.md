# v1.0 test vectors (EXAMPLE DATA ONLY)

All values are made up. The wallets are 0x0…01 to 0x0…03 and the domains end in `.test`. No real people, agents or payments are involved. The vectors are signed with the demo key `polkulab-demo-2026-11`, whose public key is in [`../../verifier/demo-pub.pem`](../../verifier/demo-pub.pem). The private demo key is not published.

**[`expected.json`](./expected.json) is the list to run.** Each case names a record, a keyset (default `keyset-demo.json`), optional binding inputs, linked records and a keyset anchor, and the expected `status`, the exact sorted `errors` and `warnings`, and some `info` entries. Both reference test suites (`tests/test_vectors.py` and `tests/test_verify_html.mjs`) iterate over this one list, so Python and JavaScript are checked against the same cases. Pass records and keysets to a verifier as file text: `negative/number-*.json`, `negative/duplicate-member.json` and `negative/keyset-duplicate-member.json` test rules that a parsed object can hide. Cases with `"allow_legacy_v02": true` run with legacy 0.2-draft verification enabled (SPEC §11.1); without it a 0.2-draft record gives `LEGACY_V02_NOT_ENABLED`.

Main files:

| file | expected | why |
|---|---|---|
| `valid.json` | VALID | correct signature, key valid at `decision_issued_at`, evidence hashes, timeline and x402 v2 binding OK |
| `tampered.json` | INVALID `BAD_SIGNATURE` | `decision.score` changed 62 → 30 after signing |
| `wrong-key.json` | INVALID `BAD_SIGNATURE` | claims `polkulab-demo-2026-11` but was signed with a throwaway key |
| `expired-key.json` | INVALID `KEY_NOT_VALID_AT_ISSUANCE` | issued 2027-01-15, after the demo key's `valid_until` (2027-01-01); the signature itself is fine |
| `unknown-check-id.json` | VALID | an unregistered check id is info only |
| `withheld-evidence.json` | VALID | evidence withheld, hash still signed |
| `valid.json` + `keyset-revoked.json` | INVALID `KEY_REVOKED` | demo key revoked for `key_compromise` |
| `valid.json` + `keyset-superseded-later.json` | VALID, warning | key superseded after issuance |

`negative/` holds one file per defect, each signed with the demo key so that only the named defect is wrong (except where the defect is the signature or a number that cannot be signed): signature object members, non-canonical base64, `S+L`, unsupported versions, timestamp formats, x402 v1 forms, schema violations from the review (ceiling `bogus`, input `md5(x)`, withheld evidence with an unknown input id, score 101), numbers, duplicate members (record, keyset, binding inputs, linked record), a binding-inputs float, a linked record that is not JSON, network ids with a leading zero or chain id 0, unknown key, key-id mismatch, timeline, evidence hash, field pointer, and negative binding inputs. The `keyset-*.json` files in this folder are the keyset cases (duplicate key id, version, timestamp, revocation). `keyset-production-like.json` has no demo key (test public key only), for the legacy no-fallback case.

Legacy 0.2-draft vectors (from the follow-up review): `negative/legacy-v1-fields-relabelled.json` (v1.0 content labelled 0.2-draft, run against the key_compromise keyset), `negative/legacy-v1-fields-relabelled-2030.json` (the same, issued 2030), `negative/legacy-v02-checked-2030.json` (a pure v0.2 record with `checkedAt` after the key window) and `negative/legacy-v02-with-payment.json` (one v1.0 member); `../../verifier/record-valid.json` against `keyset-production-like.json` is the demo-signed record without a demo key in the keyset (`UNKNOWN_KEY`).

Other files:

- `keyset-demo.json`: the demo-only keyset used by the test vectors, byte-identical to `../../verifier/demo-keyset.json`. It is not the published well-known file.
- `keyset-published.json`: a byte-identical copy of `../../.well-known/x402-decision-keyset.json` (demo key plus the production public key). The release-notes anchor is the SHA-256 of these exact bytes.
- `binding-inputs.json`: the raw nonce, x402 v2 payment requirements, resource and request behind the binding hashes.
- `example-outcome-record.json`: an unsigned example of a later record linking to `valid.json` with `jcs(record)`, which hashes the whole record including its signature.
- `linked/`: the example linked records whose hashes appear in `links`.

Regenerate with `python3 tools/make_vectors.py --key <demo private key>`. Ed25519 is deterministic, so every vector except `wrong-key.json` is byte-identical on each run.
