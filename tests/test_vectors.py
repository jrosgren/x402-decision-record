#!/usr/bin/env python3
"""Tests for the Python verifier against the v1.0 and v0.2 vectors (example data).

Run: python3 -m unittest discover -s tests -v
Needs rfc8785 (verify.py requires it) and jsonschema (pip install rfc8785 jsonschema cryptography).
The vector cases come from test-vectors/v1.0/expected.json, the same list the Node test runs.
"""
import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

import jsonschema  # required: run_all.sh fails if it is missing (no silently skipped schema tests)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "verifier"))
import verify  # noqa: E402

TV = ROOT / "test-vectors" / "v1.0"
EXP = json.loads((TV / "expected.json").read_text(encoding="utf-8"))


def load(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def run_case(c):
    kw = {}
    if c["keyset"]:
        kw["keyset_bytes"] = (TV / c["keyset"]).read_bytes()
    if c.get("keyset_sha256"):
        kw["keyset_sha256"] = c["keyset_sha256"]
    if c.get("binding_inputs"):
        kw["binding_inputs"] = load(TV / c["binding_inputs"])
    if c.get("linked"):
        kw["linked"] = [load(TV / p) for p in c["linked"]]
    return verify.verify_record(load(TV / c["record"]), **kw)


class ExpectedCases(unittest.TestCase):
    def test_cases(self):
        self.assertGreaterEqual(len(EXP["cases"]), 50)
        for c in EXP["cases"]:
            with self.subTest(c["name"]):
                r = run_case(c)
                self.assertEqual(r["status"], c["status"], r)
                self.assertEqual(sorted(r["errors"]), c["errors"], r)
                self.assertEqual(sorted(r["warnings"]), c["warnings"], r)
                for i in c.get("info_includes", []):
                    self.assertIn(i, r["info"], r)
                if c.get("sha256"):
                    self.assertEqual(r["sha256"], c["sha256"])

    def test_every_vector_file_is_used(self):
        used = set()
        for c in EXP["cases"]:
            used |= {c["record"], c["keyset"], c.get("binding_inputs")} | set(c.get("linked") or [])
        files = {str(p.relative_to(TV)) for p in TV.rglob("*.json")} - {"expected.json", "example-outcome-record.json"}
        self.assertEqual(files - used, set())


class Schema(unittest.TestCase):
    """The verifiers' built-in validator must agree with a full JSON Schema implementation."""

    def test_schemas_are_valid_2020_12(self):
        for s in ("decision-record.v1.0.schema.json", "keyset.v1.0.schema.json"):
            jsonschema.Draft202012Validator.check_schema(load(ROOT / "schema" / s))
            self.assertEqual((ROOT / "schema" / s).read_bytes(), (ROOT / "verifier" / s).read_bytes())

    def test_builtin_validator_agrees_with_jsonschema(self):
        rv = jsonschema.Draft202012Validator(verify.RECORD_SCHEMA)
        kv = jsonschema.Draft202012Validator(verify.KEYSET_SCHEMA)
        n = 0
        for p in sorted(TV.rglob("*.json")):
            doc = load(p)
            if not isinstance(doc, dict) or verify.number_errors(doc):
                continue
            if "keyset_version" in doc:
                mine, full = verify.schema_errors(verify.KEYSET_SCHEMA, verify.KEYSET_SCHEMA, doc), kv.is_valid(doc)
            elif doc.get("record_type") == "x402-pre-payment-decision":
                mine, full = verify.schema_errors(verify.RECORD_SCHEMA, verify.RECORD_SCHEMA, doc), rv.is_valid(doc)
            else:
                continue
            self.assertEqual(mine == [], full, (p.name, mine))
            n += 1
        self.assertGreater(n, 35)

    def test_custom_check_ids_schema_valid(self):
        v = jsonschema.Draft202012Validator(verify.RECORD_SCHEMA)
        rec = load(TV / "valid.json"); rec["checks"][0]["id"] = "x-acme.my_check"
        self.assertTrue(v.is_valid(rec))
        rec["checks"][0]["id"] = "Bad Id"
        self.assertFalse(v.is_valid(rec))


class Primitives(unittest.TestCase):
    def test_jcs_sorts_by_utf16(self):
        # B1: U+1F600 (surrogates D83D DE00) sorts before U+E000 in JCS
        self.assertEqual(verify.canonicalize({"\ue000": 1, "\U0001F600": 2}).decode(), '{"\U0001F600":2,"\ue000":1}')

    def test_timestamps(self):
        self.assertEqual(verify.ts_ms("1970-01-01T00:00:00Z"), 0)
        self.assertEqual(verify.ts_ms("2026-11-19T09:00:00.910Z") - verify.ts_ms("2026-11-19T09:00:00Z"), 910)
        for bad in ("2026-11-19T09:00:00.91Z", "2026-11-19T09:00:00.910", "2026-11-19T09:00:00+00:00",
                    "2026-02-29T00:00:00Z", "2026-11-19T24:00:00Z", "2026-11-19T09:00:00Z\n"):
            self.assertIsNone(verify.ts_ms(bad), bad)
        self.assertIsNotNone(verify.ts_ms("2028-02-29T00:00:00Z"))

    def test_strict_base64_and_s_below_l(self):
        s = load(TV / "valid.json")["signature"]["sig_base64"]
        self.assertIsNotNone(verify.decode_sig(s))
        self.assertIsNone(verify.decode_sig(s[:-3] + " " + s[-2:]))
        self.assertIsNone(verify.decode_sig(load(TV / "negative/sig-noncanonical-base64.json")["signature"]["sig_base64"]))
        raw = verify.decode_sig(load(TV / "negative/sig-s-plus-l.json")["signature"]["sig_base64"])
        self.assertGreaterEqual(int.from_bytes(raw[32:], "little"), verify.ED25519_L)

    def test_no_exceptions_on_garbage(self):
        for rec in ([], "x", {"signature": "x"}, {"schema_version": "1.0", "signature": {}}, {"schema_version": None, "signature": {}}):
            self.assertEqual(verify.verify_record(rec)["status"], "INVALID")


class Cli(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(ROOT / "verifier/verify.py"), *map(str, args)], capture_output=True, text=True)

    def test_v02_positional_pubkey(self):
        p = self.run_cli(ROOT / "verifier/record-valid.json", ROOT / "verifier/demo-pub.pem")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertTrue(p.stdout.startswith("VALID"))

    def test_v10_default_keyset(self):
        p = self.run_cli(TV / "valid.json")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_v10_pubkey_only_warns(self):
        p = self.run_cli(TV / "valid.json", ROOT / "verifier/demo-pub.pem", "--json")
        r = json.loads(p.stdout)
        self.assertEqual(r["status"], "VALID")
        self.assertIn("NO_KEYSET_VALIDITY_NOT_CHECKED", r["warnings"])

    def test_v10_full_cli(self):
        p = self.run_cli(TV / "valid.json", "--keyset", ROOT / ".well-known/x402-decision-keyset.json",
                         "--keyset-sha256", EXP["keyset_anchor_sha256"], "--binding-inputs", TV / "binding-inputs.json",
                         "--linked", TV / "linked/content-time-record.json", TV / "linked/seller-attestation.json", "--json")
        r = json.loads(p.stdout)
        self.assertEqual((r["status"], r["errors"], r["warnings"]), ("VALID", [], []), r)
        self.assertIn("BINDING_RECOMPUTED_OK", r["info"])
        p = self.run_cli(TV / "valid.json", "--keyset", ROOT / ".well-known/x402-decision-keyset.json", "--keyset-sha256", "0" * 64)
        self.assertEqual(p.returncode, 1)
        self.assertIn("KEYSET_SHA256_MISMATCH", p.stdout)


class Publication(unittest.TestCase):
    def test_keyset_copies_identical_and_anchor(self):
        a = (ROOT / ".well-known/x402-decision-keyset.json").read_bytes()
        self.assertEqual(a, (ROOT / "verifier/demo-keyset.json").read_bytes())
        self.assertEqual(a, (TV / "keyset-demo.json").read_bytes())
        self.assertTrue((ROOT / ".nojekyll").exists())
        self.assertEqual(verify.sha256_hex(a), EXP["keyset_anchor_sha256"])
        for doc in ("SPEC.md", "RELEASING.md", "README.md"):
            self.assertIn(EXP["keyset_anchor_sha256"], (ROOT / doc).read_text(encoding="utf-8"), doc)

    def test_reserved_keyset_signature_ignored(self):
        ks = load(TV / "keyset-demo.json")
        for v in ({"alg": "reserved-v1.1", "sig_base64": "AAAA"}, None):
            ks["keyset_signature"] = v
            self.assertEqual(verify.verify_record(load(TV / "valid.json"), keyset=ks)["status"], "VALID")

    def test_linked_decision_record_hash_includes_signature(self):
        link = load(TV / "example-outcome-record.json")["links"][0]
        self.assertEqual(link["record_sha256"]["input"], "jcs(record)")
        full = load(TV / "valid.json")
        self.assertEqual(verify.sha256_hex(verify.canonicalize(full)), link["record_sha256"]["hex"])
        body = copy.deepcopy(full); body.pop("signature")
        self.assertNotEqual(verify.sha256_hex(verify.canonicalize(body)), link["record_sha256"]["hex"])

    def test_registry_ids_used(self):
        ids = [c["id"] for c in load(TV / "valid.json")["checks"]]
        for want in sorted(verify.CHECK_REGISTRY):
            self.assertIn(want, ids)

    def test_no_private_key_in_repo(self):
        for p in ROOT.rglob("*"):
            if p.is_file() and not {".git", "__pycache__", "node_modules"} & set(p.parts):
                self.assertNotIn(b"BEGIN " + b"PRIVATE KEY", p.read_bytes(), p)


if __name__ == "__main__":
    unittest.main()
