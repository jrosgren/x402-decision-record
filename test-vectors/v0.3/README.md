# v0.3-draft test vectors (EXAMPLE DATA ONLY)

All values are made up. The wallets are 0x0…01 to 0x0…03 and the domains end in `.test`. No real people, agents or payments are involved. The vectors are signed with the demo key `polkulab-demo-2026-11`, whose public key is in [`../../verifier/demo-pub.pem`](../../verifier/demo-pub.pem). The private demo key is not published.

| file | expected | why |
|---|---|---|
| `valid.json` | VALID | correct signature, key valid at `decision_issued_at`, evidence hashes and timeline OK |
| `tampered.json` | INVALID `BAD_SIGNATURE` | `decision.score` changed 62 → 30 after signing |
| `wrong-key.json` | INVALID `BAD_SIGNATURE` | claims `polkulab-demo-2026-11` but was signed with a throwaway key |
| `expired-key.json` | INVALID `KEY_NOT_VALID_AT_ISSUANCE` | issued 2027-01-15, after the demo key's `valid_until` (2027-01-01); the signature itself is fine |
| `valid.json` + `keyset-revoked.json` | INVALID `KEY_REVOKED` | demo key marked revoked for `key_compromise` |

Other files:

- `keyset-demo.json`: the demo keyset.
- `keyset-revoked.json`: the same keyset with the demo key revoked, for tests.
- `binding-inputs.json`: the raw nonce, payment requirements and request behind the binding hashes.
- `linked/`: the example linked records whose hashes appear in `links`.
- `expected.json`: machine-readable expectations.

Regenerate with `python3 tools/make_vectors.py --key <demo private key>`. Ed25519 is deterministic, so every vector except `wrong-key.json` is byte-identical on each run.
