#!/usr/bin/env bash
# Run all verifier tests (Python + headless Node). Example data only.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
echo "== python unittest ($PY) =="
"$PY" -m unittest discover -s tests -p 'test_*.py' -v
echo "== OpenSSL by hand (v0.3 valid) =="
"$PY" - <<'PYEOF'
import json, base64, sys
sys.path.insert(0, "verifier")
import verify
r = json.load(open("test-vectors/v0.3/valid.json")); s = r.pop("signature")
open("/tmp/x402dr-canon.json", "wb").write(verify.canonicalize(r))
open("/tmp/x402dr-sig.bin", "wb").write(base64.b64decode(s["sig_base64"]))
PYEOF
openssl pkeyutl -verify -pubin -inkey verifier/demo-pub.pem -rawin -in /tmp/x402dr-canon.json -sigfile /tmp/x402dr-sig.bin
echo "== node headless verify.html =="
node tests/test_verify_html.mjs
