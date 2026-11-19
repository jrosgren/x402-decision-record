#!/usr/bin/env python3
"""Tests for the Python verifier against v0.2 and v0.3 vectors (example data).

Run: python3 -m unittest discover -s tests -v
Schema tests run when the jsonschema package is installed; otherwise skipped.
"""
import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "verifier"))
import verify  # noqa: E402

TV = ROOT / "test-vectors" / "v0.3"


def load(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


KEYSET = load(TV / "keyset-demo.json")
REVOKED = load(TV / "keyset-revoked.json")
BINDING = load(TV / "binding-inputs.json")
LINKED = [load(p) for p in sorted((TV / "linked").glob("*.json"))]


class V02(unittest.TestCase):
    def test_valid(self):
        r = verify.verify_record(load(ROOT / "verifier/record-valid.json"))
        self.assertEqual(r["status"], "VALID")
        self.assertEqual(r["sha256"], "f3a1e3138054d02beac297c4024b82510aceb5507ef4af9b803670f1738435f0")

    def test_tampered(self):
        self.assertEqual(verify.verify_record(load(ROOT / "verifier/record-tampered.json"))["status"], "INVALID")

    def test_cli_positional_pubkey(self):
        p = subprocess.run([sys.executable, str(ROOT / "verifier/verify.py"), str(ROOT / "verifier/record-valid.json"),
                            str(ROOT / "verifier/demo-pub.pem")], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertTrue(p.stdout.startswith("VALID"))


class V03Vectors(unittest.TestCase):
    def test_expected(self):
        exp = load(TV / "expected.json")
        for name, want in exp.items():
            if name.startswith("_"):
                continue
            rec_name, _, ks_name = name.partition("+")
            ks = load(TV / ks_name) if ks_name else KEYSET
            r = verify.verify_record(load(TV / rec_name), keyset=ks, binding_inputs=BINDING, linked=LINKED)
            self.assertEqual(r["status"], want["status"], (name, r))
            if "reason" in want:
                self.assertIn(want["reason"], r["errors"], (name, r))

    def test_valid_full(self):
        r = verify.verify_record(load(TV / "valid.json"), keyset=KEYSET, binding_inputs=BINDING, linked=LINKED)
        self.assertEqual(r["errors"], [])
        self.assertEqual(r["warnings"], [])
        self.assertIn("BINDING_RECOMPUTED_OK", r["info"])
        self.assertTrue(r["example_data"])

    def test_default_keyset_cli(self):
        p = subprocess.run([sys.executable, str(ROOT / "verifier/verify.py"), str(TV / "valid.json")],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_pubkey_only_warns(self):
        r = verify.verify_record(load(TV / "valid.json"), pub_pem=(ROOT / "verifier/demo-pub.pem").read_text())
        self.assertEqual(r["status"], "VALID")
        self.assertIn("NO_KEYSET_VALIDITY_NOT_CHECKED", r["warnings"])

    def test_unknown_key(self):
        rec = load(TV / "valid.json")
        ks = copy.deepcopy(KEYSET)
        ks["keys"][0]["key_id"] = "other"
        self.assertIn("UNKNOWN_KEY", verify.verify_record(rec, keyset=ks)["errors"])

    def test_superseded_key_still_valid_for_old_records(self):
        ks = copy.deepcopy(KEYSET)
        ks["keys"][0].update({"status": "revoked", "revoked_at": "2026-12-01T00:00:00Z", "revocation_reason": "superseded"})
        r = verify.verify_record(load(TV / "valid.json"), keyset=ks)
        self.assertEqual(r["status"], "VALID")
        self.assertIn("KEY_SUPERSEDED_AFTER_ISSUANCE", r["warnings"])

    def test_wrong_binding_inputs(self):
        bi = copy.deepcopy(BINDING)
        bi["authorization_nonce"] = "0x" + "00" * 32
        bi["payment_requirements"]["payTo"] = "0x0000000000000000000000000000000000000009"
        r = verify.verify_record(load(TV / "valid.json"), keyset=KEYSET, binding_inputs=bi)
        self.assertEqual(r["status"], "INVALID")
        self.assertIn("BINDING_HASH_MISMATCH:eip3009-nonce-bytes32", r["errors"])
        self.assertIn("BINDING_FIELD_MISMATCH:payee", r["errors"])

    def test_evidence_hash_checked_independently(self):
        # Swap inline evidence; even ignoring the signature, the hash check must catch it.
        rec = load(TV / "valid.json")
        rec["checks"][0]["evidence"]["http_status"] = 200
        r = verify.verify_record(rec, keyset=KEYSET)
        self.assertIn("EVIDENCE_HASH_MISMATCH:liveness", r["errors"])

    def test_withheld_evidence_is_info(self):
        rec = load(TV / "valid.json")
        del rec["checks"][0]["evidence"]
        r = verify.verify_record(rec, keyset=KEYSET)
        self.assertIn("EVIDENCE_WITHHELD:liveness", r["info"])
        self.assertIn("BAD_SIGNATURE", r["errors"])  # removing it changes signed bytes

    def test_signature_bytes_match_embedded_sha(self):
        for f in ("valid.json", "wrong-key.json", "expired-key.json"):
            rec = load(TV / f)
            body = copy.deepcopy(rec)
            body.pop("signature")
            self.assertEqual(verify.sha256_hex(verify.canonicalize(body)), rec["signature"]["sha256"], f)


@unittest.skipUnless(__import__("importlib").util.find_spec("jsonschema"), "jsonschema not installed")
class Schema(unittest.TestCase):
    def test_vectors_match_schema(self):
        import jsonschema
        s = load(ROOT / "schema/decision-record.v0.3.schema.json")
        jsonschema.Draft202012Validator.check_schema(s)
        v = jsonschema.Draft202012Validator(s)
        for f in ("valid.json", "tampered.json", "wrong-key.json", "expired-key.json"):
            v.validate(load(TV / f))
        bad = load(TV / "valid.json")
        bad["checks"][0]["evidence_ceiling"] = "trust_me"
        self.assertFalse(v.is_valid(bad))

    def test_keysets_match_schema(self):
        import jsonschema
        s = load(ROOT / "schema/keyset.v0.3.schema.json")
        for f in ("keyset-demo.json", "keyset-revoked.json"):
            jsonschema.Draft202012Validator(s).validate(load(TV / f))


if __name__ == "__main__":
    unittest.main()
