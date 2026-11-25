# Releasing (v1.0.0 and later)

1. Update `.well-known/x402-decision-keyset.json` by hand (served by GitHub Pages; `.nojekyll` must stay in the repo root). `tools/make_vectors.py` writes the demo keyset used by the test vectors (`test-vectors/v1.0/keyset-demo.json` and `verifier/demo-keyset.json`); it does **not** overwrite the published well-known file. After you change the published file, run the generator (or copy the file) so `test-vectors/v1.0/keyset-published.json` stays byte-identical, and so the generator prints the new release-notes anchor.
2. Run `bash tests/run_all.sh`; all tests must pass (it fails if `rfc8785` or `jsonschema` is missing, so no test is skipped silently).
3. Compute the anchor: `sha256sum .well-known/x402-decision-keyset.json`. If it changed, update it in `SPEC.md` §9.1 and `README.md` (a test checks this). Current published keyset anchor: `725d2ecea67f2ee16908fd93130ab97c44ba9b94b51e7b26201ab6ed7975093a`.
4. Merge the release PR into `main`.
5. **Post-merge check, before any release notes are published.** Wait for the GitHub Pages deployment, then check that the Pages copy matches the anchor byte for byte and that the hosted verifier is the merged one:

   ```bash
   ANCHOR=725d2ecea67f2ee16908fd93130ab97c44ba9b94b51e7b26201ab6ed7975093a
   curl -fsS https://jrosgren.github.io/x402-decision-record/.well-known/x402-decision-keyset.json | sha256sum   # must print $ANCHOR
   curl -fsS https://jrosgren.github.io/x402-decision-record/verifier/verify.html | cmp - verifier/verify.html  # no output
   curl -fsS -o /tmp/keyset.json https://jrosgren.github.io/x402-decision-record/.well-known/x402-decision-keyset.json
   python3 verifier/verify.py test-vectors/v1.0/valid.json --keyset /tmp/keyset.json --keyset-sha256 "$ANCHOR"     # VALID
   ```

   If any of these fails (404, other hash, other page), stop: fix Pages first, and do not tag or publish.
6. Tag `vX.Y.Z` on the merged commit, create the GitHub release, attach the same file as release asset `keyset.json`, and put this line in the release notes:

   `keyset.json SHA-256: <hex>`

7. Download the release asset and check it against the anchor too: `curl -fsSL https://github.com/jrosgren/x402-decision-record/releases/download/vX.Y.Z/keyset.json | sha256sum`.
8. Optional (SHOULD, not MUST): publish a third identical copy at `https://trypolkulab.com/.well-known/x402-decision-keyset.json` and check it the same way.

Never commit a private key. The demo private key lives outside this repository.
