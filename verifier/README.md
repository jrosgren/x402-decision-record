# Third-party verifier for an AgentTrust decision record

**EXAMPLE DATA ONLY.** The records in this folder are signed illustrations with made-up values, not live Payvetted decisions. Payvetted is pre-launch and does not issue production records yet. The format is unpublished draft v0.2.

A third party can check that a record has not been changed since it was signed, without access to Polkulab systems and without trusting Polkulab's own logs. Verification uses only the record, the public key, and open algorithms.

Made by Aron, Polkulab (Payvetted).

## What is signed

The signature is **Ed25519** over the **RFC 8785 (JCS)** canonical JSON of the record **with the `signature` field removed**. The demo key id is `polkulab-demo-2026-11`.

The SHA-256 of the valid example's canonical bytes is:

`f3a1e3138054d02beac297c4024b82510aceb5507ef4af9b803670f1738435f0`

`record-tampered.json` is the same record with `score` changed from 62 to 30 and the original signature kept, so a check must fail.

## Three ways to verify

### 1. In the browser (no install, nothing leaves your device)

Open [`verify.html`](./verify.html) in a browser. It is a single self-contained file: no network requests, no CDN, no data leaves the page. The demo public key is prefilled. Paste a record, or load the valid or tampered example, and click Verify. The page shows **VALID** or **INVALID** and the SHA-256 of the canonical bytes.

### 2. Python

From this directory, with OpenSSL available:

```bash
python3 verify.py record-valid.json demo-pub.pem
python3 verify.py record-tampered.json demo-pub.pem
```

The first prints `VALID` and the sha256 above (exit status 0). The second prints `INVALID` and exits with status 1.

`verify.py` uses the `rfc8785` package if installed (`pip install rfc8785`). Otherwise it uses `json.dumps(..., sort_keys=True, separators=(',', ':'), ensure_ascii=False)`, which matches JCS for these example records (ASCII keys and integer scores). It then calls OpenSSL to check the Ed25519 signature.

### 3. OpenSSL, by hand

These commands were tested with OpenSSL 3. They must be run from this directory.

Write the record without the `signature` field as canonical JSON (UTF-8, sorted keys, no whitespace):

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

The corresponding private demo key is not in this folder and is not published.
