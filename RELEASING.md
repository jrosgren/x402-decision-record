# Releasing (v1.0.0 and later)

1. Regenerate or update `keyset.json` and copy it byte-for-byte to `.well-known/x402-decision-keyset.json` (served by GitHub Pages; `.nojekyll` must stay in the repo root).
2. Run `bash tests/run_all.sh`; all tests must pass.
3. Compute the anchor: `sha256sum .well-known/x402-decision-keyset.json`.
4. Tag `vX.Y.Z`, create the GitHub release, attach the same file as release asset `keyset.json`, and put this line in the release notes:

   `keyset.json SHA-256: <hex>`

5. Check that the Pages copy, the release asset and the anchor all match:
   `curl -s https://jrosgren.github.io/x402-decision-record/.well-known/x402-decision-keyset.json | sha256sum`
6. Optional (SHOULD, not MUST): publish a third identical copy at `https://trypolkulab.com/.well-known/x402-decision-keyset.json`.

Never commit a private key. The demo private key lives outside this repository.
