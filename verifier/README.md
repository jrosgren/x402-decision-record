# Third-party verifier for an AgentTrust decision record

**EXAMPLE DATA ONLY.** The records in this folder are signed illustrations with made-up values, not live Payvetted decisions. Payvetted is pre-launch and does not issue production records yet. This folder verifies format v1.0 (release v1.0.0, see [`../SPEC.md`](../SPEC.md)) and, only when you ask for it, legacy v0.2-draft.

A third party can check that a record has not been changed since it was signed, without access to Polkulab systems and without trusting Polkulab's own logs. Verification uses only the record, the public key, and open algorithms.

Made by Aron, Polkulab (Payvetted).

## What is signed

The signature is **Ed25519** over the **RFC 8785 (JCS)** canonical JSON of the record **with the `signature` field removed**. The demo key id is `polkulab-demo-2026-11`.

The SHA-256 of the valid example's canonical bytes is:

`f3a1e3138054d02beac297c4024b82510aceb5507ef4af9b803670f1738435f0`

`record-tampered.json` is the same record with `score` changed from 62 to 30 and the original signature kept, so a check must fail.

## v1.0 records

v1.0 records are first validated against the v1.0 JSON Schema (copies next to this script: `decision-record.v1.0.schema.json`, `keyset.v1.0.schema.json`; `verify.html` embeds them). Both verifiers use the same small validator and report the same error codes, for example `BAD_SIGNATURE_OBJECT:/signature`, `NONCANONICAL_SIGNATURE:/signature/sig_base64`, `BAD_TIMESTAMP:/timeline/decision_issued_at`, `BAD_NUMBER:/decision/score` or `SCHEMA_VIOLATION:<pointer>`. `schema_version` must be exactly `"1.0"`; `"0.2-draft"` is accepted only with the legacy opt-in (below), and anything else is `UNSUPPORTED_SCHEMA_VERSION`. Before parsing, both verifiers scan the JSON text: a member name repeated in one object gives `DUPLICATE_MEMBER:<pointer>`, and a number with a fraction or exponent part or outside ±(2^53−1) gives `BAD_NUMBER:<pointer>`. `verify.html` does this with its own scanner, so it does not depend on browser support for `JSON.parse` source text.

Then the record is checked against a **keyset** (version `"1.0"`, unique key ids, validity window, revocation). By default this is [`demo-keyset.json`](./demo-keyset.json). Signatures must be canonical base64 with `S < L` on every path, including the tweetnacl fallback in `verify.html`.

**Where the keyset is published (from v1.0.0):**

1. **Primary:** https://jrosgren.github.io/x402-decision-record/.well-known/x402-decision-keyset.json (the `keyset_uri` in each record).
2. **Secondary:** the `keyset.json` asset on the GitHub release tag `v1.0.0` (and `v1.0.1`, same bytes).
3. A third copy on trypolkulab.com may follow later. It is optional.

The release notes carry the SHA-256 of `keyset.json` (demo keyset today: `958754dbd30cea1c7fa2937b674242d75a5297f5edcb3a5a3d48d0878223f745`). Check your copy against it with `--keyset-sha256`, or paste it into the anchor field of `verify.html` together with the keyset file text. v1.0 has no root key; the `keyset_signature` field is reserved for v1.1 and is ignored. The verifiers only accept EVM networks (`eip155:<chain id>`, chain id without leading zeros: `^eip155:[1-9][0-9]*$`) and bind to x402 v2 payment requirements (`amount`, not v1 `maxAmountRequired`). Unknown check ids are reported as info and never make a record invalid. Since v1.0.1, a result without binding inputs or linked records carries the info codes `BINDING_RECOMPUTATION_SKIPPED` and `LINK_RECOMPUTATION_SKIPPED:<rel>`, so a VALID result is not mistaken for a checked binding (SPEC §11.2). Clone with the repo's `.gitattributes` (or download raw files): the keyset anchor is over the exact LF bytes (SPEC §9.1).

Run from the repository root (`pip install rfc8785`, and optionally `cryptography`; otherwise OpenSSL 3 is used):

```bash
python3 verifier/verify.py test-vectors/v1.0/valid.json                 # VALID
python3 verifier/verify.py test-vectors/v1.0/expired-key.json           # INVALID KEY_NOT_VALID_AT_ISSUANCE
python3 verifier/verify.py test-vectors/v1.0/valid.json \
    --keyset test-vectors/v1.0/keyset-revoked.json                      # INVALID KEY_REVOKED
python3 verifier/verify.py test-vectors/v1.0/valid.json \
    --binding-inputs test-vectors/v1.0/binding-inputs.json \
    --linked test-vectors/v1.0/linked/*.json --json                     # also recompute binding and link hashes
python3 verifier/verify.py test-vectors/v1.0/valid.json \
    --keyset .well-known/x402-decision-keyset.json --keyset-sha256 958754dbd30cea1c7fa2937b674242d75a5297f5edcb3a5a3d48d0878223f745
```

### Using the verifiers as a library: pass raw text

The duplicate-member and number checks can only run on the JSON **text**. Once a parser has turned the text into an object, `{"score": 30, "score": 62}` has already become `{"score": 62}` and `62.0` has become `62`. So pass every input as the raw file contents:

```python
import verify  # verifier/verify.py
res = verify.verify_record(
    open("record.json", "rb").read(),                        # str or bytes, not json.load(...)
    keyset_bytes=open("keyset.json", "rb").read(),           # also the bytes the anchor is computed over
    keyset_sha256="<anchor from the release notes>",
    binding_inputs=open("binding-inputs.json", "rb").read(), # optional
    linked=[open(p, "rb").read() for p in linked_files],     # optional; or one text holding a JSON array
)
```

```js
const res = await AgentTrustVerifier.verifyRecord(recordText, {
  keysetText, keysetSha256, bindingInputs: bindingText, linked: [linkedText1, linkedText2] // or one array text
});
```

A parsed object is still accepted and verified, but the checks above cannot run on it, so the result then carries the warning `PARSED_INPUT:<record|keyset|binding_inputs|linked[i]>`. Treat a result with that warning as weaker than one from text. Errors in the optional inputs are labelled with where they came from, for example `DUPLICATE_MEMBER:binding_inputs#/payment_requirements/amount`, `BAD_NUMBER:binding_inputs#/payment_requirements/maxTimeoutSeconds`, `DUPLICATE_MEMBER:linked[1]#/scope` or `BAD_JSON:linked[0]#`. The `verify.py` command line always passes file bytes, including for `--binding-inputs` and `--linked`.

`verify.html` has buttons for the v1.0 examples, a keyset field (prefilled with the demo keyset), an anchor field, and optional binding-inputs and linked-records fields. It has the same checks as `verify.py`, including the anchor check and linked-record recomputation, and it still makes no network calls. The page passes every field to the verifier as text, so the same strict checks apply to the record, keyset, binding-inputs and linked-records fields.

All tests: `bash tests/run_all.sh` (Python unittest and Node both run every case in `test-vectors/v1.0/expected.json`, Node through both Web Crypto and tweetnacl; plus OpenSSL by hand and a headless Chrome run of the page itself).

## Legacy v0.2-draft records (opt-in)

v0.2 records have no payment binding, timeline or evidence hashes; a VALID result only means the key signed those bytes. Both verifiers therefore refuse 0.2-draft records (`LEGACY_V02_NOT_ENABLED`) unless you opt in: `--allow-legacy-v02` for `verify.py`, `allowLegacyV02: true` in the `verify.html` API, or the "Also accept legacy 0.2-draft records" box on the page (the two legacy example buttons tick it). With the opt-in (SPEC §11.1):

- the record must match the closed v0.2 schema ([`decision-record.v0.2.schema.json`](./decision-record.v0.2.schema.json)); any v1.0 member gives `LEGACY_V02_WITH_V1_FIELDS:<pointer>`;
- with a keyset, an unknown key id is `UNKNOWN_KEY` (no fallback to the demo key), any revoked key is `KEY_REVOKED`, and `checkedAt` must be inside the key's validity window (`KEY_NOT_VALID_AT_ISSUANCE`);
- with only a public key you get the warning `NO_KEYSET_VALIDITY_NOT_CHECKED`; with neither, the demo key is used and you get `DEMO_KEY_ASSUMED`;
- every VALID result carries the warning `LEGACY_V02_SIGNATURE_ONLY`.

`verify.py` uses the demo keyset by default only for v1.0 records. For a v0.2 record, pass `--keyset` (normal case) or a public key.

## Three ways to verify (v0.2 example)

### 1. In the browser (no install, nothing leaves your device)

Open [`verify.html`](./verify.html) in a browser. It is a single self-contained file: no network requests, no CDN, no data leaves the page. The demo keyset and public key are prefilled. Click "Legacy v0.2 valid" or "Legacy v0.2 tampered" (this ticks the legacy box), or paste a record and tick the box yourself, then click Verify. The page shows **VALID** or **INVALID** and the SHA-256 of the canonical bytes.

### 2. Python

From this directory, with OpenSSL available:

```bash
python3 verify.py record-valid.json --keyset demo-keyset.json --allow-legacy-v02
python3 verify.py record-tampered.json --keyset demo-keyset.json --allow-legacy-v02
python3 verify.py record-valid.json demo-pub.pem --allow-legacy-v02    # key only: NO_KEYSET_VALIDITY_NOT_CHECKED
```

The first prints `VALID`, the sha256 above and the warning `LEGACY_V02_SIGNATURE_ONLY` (exit status 0). The second prints `INVALID` and exits with status 1.

`verify.py` needs the `rfc8785` package (`pip install rfc8785`) for canonicalization. It checks the Ed25519 signature with the `cryptography` package if installed, otherwise with OpenSSL.

### 3. OpenSSL, by hand

These commands were tested with OpenSSL 3. They must be run from this directory.

Write the record without the `signature` field as canonical JSON (UTF-8, sorted keys, no whitespace). For this v0.2 example `json.dumps` with sorted keys equals JCS (ASCII keys, integers only); for other records use an RFC 8785 library:

```bash
python3 -c '
import json, sys
r = json.load(open("record-valid.json"))
r.pop("signature")
sys.stdout.buffer.write(
    json.dumps(r, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
)
' > canon.json
```

Decode the signature and check it with the public key:

```bash
python3 -c '
import json, base64
s = json.load(open("record-valid.json"))["signature"]["sig_base64"]
open("sig.bin", "wb").write(base64.b64decode(s))
'

openssl pkeyutl -verify -pubin -inkey demo-pub.pem -rawin -in canon.json -sigfile sig.bin
```

For `record-valid.json` this prints `Signature Verified Successfully`. Repeat the same steps with `record-tampered.json` in place of `record-valid.json`; OpenSSL then reports that the signature verification failed.

Optional: check the SHA-256 of the canonical bytes:

```bash
sha256sum canon.json
```

## Files

- `verify.html` — standalone in-browser verifier (WebCrypto Ed25519, with an inlined tweetnacl.js 1.0.3 fallback; Unlicense)
- `verify.py` — command-line check
- `record-valid.json` — signed example (example data)
- `record-tampered.json` — same record with `score` 62 → 30 and the original signature kept
- `demo-pub.pem` — demo Ed25519 public key (`polkulab-demo-2026-11`)
- `demo-keyset.json` — demo keyset for v1.0 (validity window 2026-11-01 to 2027-01-01)
- `decision-record.v1.0.schema.json`, `decision-record.v0.2.schema.json` (legacy, closed), `keyset.v1.0.schema.json` — copies of the schemas in `../schema/` (byte-identical), so this folder works on its own

The corresponding private demo key is not in this folder and is not published.
