#!/usr/bin/env bash
# Run all verifier tests (Python, OpenSSL, headless Node, headless Chrome). Example data only.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
echo "== dependencies =="
"$PY" -c "import rfc8785, jsonschema" || { echo "FAIL: pip install rfc8785 jsonschema (cryptography optional)"; exit 1; }
echo "== python unittest ($PY) =="
"$PY" -m unittest discover -s tests -p 'test_*.py' -v
echo "== OpenSSL by hand (v1.0 valid) =="
"$PY" - <<'PYEOF'
import json, base64, sys
sys.path.insert(0, "verifier")
import verify
r = json.load(open("test-vectors/v1.0/valid.json")); s = r.pop("signature")
open("/tmp/x402dr-canon.json", "wb").write(verify.canonicalize(r))
open("/tmp/x402dr-sig.bin", "wb").write(base64.b64decode(s["sig_base64"]))
PYEOF
openssl pkeyutl -verify -pubin -inkey verifier/demo-pub.pem -rawin -in /tmp/x402dr-canon.json -sigfile /tmp/x402dr-sig.bin
echo "== node headless verify.html =="
node tests/test_verify_html.mjs
echo "== headless Chrome: verify.html in a real browser =="
if [ -n "${CHROME:-}" ] || command -v google-chrome >/dev/null 2>&1 || command -v chromium >/dev/null 2>&1; then
  node tests/test_verify_html_chrome.mjs
else
  echo "SKIP: no Chrome/Chromium found (set CHROME=/path/to/chrome)"
fi
