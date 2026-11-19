#!/usr/bin/env python3
"""Verify an x402 pre-payment decision record (v0.2-draft or v0.3-draft).

Usage:
  python3 verify.py RECORD.json [PUBLIC_KEY.pem]                (v0.2 or v0.3)
  python3 verify.py RECORD.json --keyset KEYSET.json            (v0.3)
        [--binding-inputs INPUTS.json] [--linked FILE.json ...] [--json]

Signature: Ed25519 over the RFC 8785 (JCS) canonical JSON of the record with
the "signature" member removed (same rule in v0.2 and v0.3).

v0.3 adds, all checked offline (this script makes no network calls):
  * key lookup in a keyset file (default: demo-keyset.json next to this
    script), validity window and revocation;
  * recomputation of every inline evidence hash;
  * timeline order (checks ran after the authorization was presented and
    before the decision; decision before authorization valid_before);
  * optional recomputation of the payment binding hashes from raw inputs;
  * optional recomputation of linked record hashes.

If the rfc8785 package is installed it is used for canonicalization;
otherwise json.dumps(sort_keys=True, separators=(',', ':'),
ensure_ascii=False), which equals JCS for records that contain only
strings, integers, booleans and null (v0.3 forbids floats for this reason).
Ed25519 uses the cryptography package if installed, else OpenSSL 3.

EXAMPLE DATA: the sample records shipped with this script are illustrations,
not live Payvetted decisions. Made by Aron, Polkulab (Payvetted).
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
CEILINGS = {"recomputable_from_chain", "recomputable_from_client_view", "issuer_assertion"}


# ------------------------------------------------------------ primitives
def canonicalize(obj) -> bytes:
    try:
        import rfc8785  # type: ignore
        return rfc8785.dumps(obj)
    except ImportError:
        _reject_floats(obj)
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8")


def _reject_floats(o) -> None:
    if isinstance(o, float):
        raise ValueError("floats are not allowed in records (install rfc8785 to canonicalize them)")
    if isinstance(o, dict):
        for v in o.values():
            _reject_floats(v)
    elif isinstance(o, list):
        for v in o:
            _reject_floats(v)


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def ed25519_verify(pub_pem: str, message: bytes, sig: bytes) -> bool:
    try:
        from cryptography.exceptions import InvalidSignature  # type: ignore
        from cryptography.hazmat.primitives.serialization import load_pem_public_key  # type: ignore
        try:
            load_pem_public_key(pub_pem.encode()).verify(sig, message)
            return True
        except InvalidSignature:
            return False
    except ImportError:
        pass
    with tempfile.TemporaryDirectory() as td:
        k, m, s = Path(td) / "k.pem", Path(td) / "m.bin", Path(td) / "s.bin"
        k.write_text(pub_pem)
        m.write_bytes(message)
        s.write_bytes(sig)
        p = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(k),
                            "-rawin", "-in", str(m), "-sigfile", str(s)],
                           capture_output=True, text=True)
        return p.returncode == 0


def ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def split_signature(rec: dict):
    body = copy.deepcopy(rec)
    if "signature" not in body:
        raise ValueError("record has no signature member")
    sig = body.pop("signature")
    return body, sig


# ------------------------------------------------------------ v0.2
def verify_v02(rec: dict, pub_pem: str) -> dict:
    body, sig = split_signature(rec)
    canon = canonicalize(body)
    digest = sha256_hex(canon)
    ok = ed25519_verify(pub_pem, canon, base64.b64decode(sig["sig_base64"]))
    errors = [] if ok else ["BAD_SIGNATURE"]
    warnings = []
    if sig.get("sha256") and sig["sha256"] != digest:
        warnings.append("EMBEDDED_SHA256_MISMATCH")
    return {"status": "VALID" if ok else "INVALID", "schema_version": rec.get("schema_version"),
            "sha256": digest, "key_id": sig.get("key_id"), "errors": errors, "warnings": warnings}


# ------------------------------------------------------------ v0.3
HASH_INPUTS = {
    "eip3009-nonce-bytes32": lambda bi: bytes.fromhex(bi["authorization_nonce"].removeprefix("0x")),
    "jcs(payment_requirements)": lambda bi: canonicalize(bi["payment_requirements"]),
    "jcs(resource_request)": lambda bi: canonicalize(bi["resource_request"]),
}


def verify_v03(rec: dict, keyset: dict | None = None, pub_pem: str | None = None,
               binding_inputs: dict | None = None, linked: list[dict] | None = None) -> dict:
    errors: list[str] = []
    warnings: list[str] = []
    info: list[str] = []
    body, sig = split_signature(rec)
    canon = canonicalize(body)
    digest = sha256_hex(canon)
    key_id = sig.get("key_id")
    issued = ts(body["timeline"]["decision_issued_at"])

    if body.get("signing_key", {}).get("key_id") != key_id:
        errors.append("KEY_ID_MISMATCH")  # signed body must name the same key as the signature

    # key lookup
    key_entry = None
    if keyset is not None:
        for k in keyset.get("keys", []):
            if k.get("key_id") == key_id:
                key_entry = k
        if key_entry is None:
            errors.append("UNKNOWN_KEY")
        else:
            pub_pem = key_entry["public_key_pem"]
            if key_entry.get("alg") != "Ed25519" or sig.get("alg") != "Ed25519":
                errors.append("UNSUPPORTED_ALG")
            vf, vu = ts(key_entry["valid_from"]), ts(key_entry["valid_until"])
            if not (vf <= issued < vu):
                errors.append("KEY_NOT_VALID_AT_ISSUANCE")
            if key_entry.get("status") == "revoked":
                reason = key_entry.get("revocation_reason")
                revoked_at = ts(key_entry["revoked_at"])
                if reason == "superseded" and issued < revoked_at:
                    warnings.append("KEY_SUPERSEDED_AFTER_ISSUANCE")
                else:
                    errors.append("KEY_REVOKED")
    elif pub_pem is None:
        errors.append("NO_KEY")
    else:
        warnings.append("NO_KEYSET_VALIDITY_NOT_CHECKED")

    sig_ok = False
    if pub_pem is not None:
        sig_ok = ed25519_verify(pub_pem, canon, base64.b64decode(sig["sig_base64"]))
        if not sig_ok:
            errors.insert(0, "BAD_SIGNATURE")
    if sig.get("sha256") and sig["sha256"] != digest:
        warnings.append("EMBEDDED_SHA256_MISMATCH")

    # evidence hashes and ceilings
    for c in body.get("checks", []):
        if c.get("evidence_ceiling") not in CEILINGS:
            errors.append(f"BAD_EVIDENCE_CEILING:{c.get('id')}")
        eh = c.get("evidence_sha256", {})
        if "evidence" in c:
            if eh.get("input") != "jcs(evidence)" or eh.get("hex") != sha256_hex(canonicalize(c["evidence"])):
                errors.append(f"EVIDENCE_HASH_MISMATCH:{c.get('id')}")
        else:
            info.append(f"EVIDENCE_WITHHELD:{c.get('id')}")
    for ptr, ceil in body.get("field_evidence_ceilings", {}).items():
        if ceil not in CEILINGS:
            errors.append(f"BAD_EVIDENCE_CEILING:{ptr}")

    # timeline
    tl = body["timeline"]
    presented = ts(tl["authorization_presented_at"])
    auth = body["payment"]["authorization"]
    for c in body.get("checks", []):
        ran = ts(c["ran_at"])
        if ran < presented or ran > issued:
            errors.append(f"CHECK_OUTSIDE_DECISION_WINDOW:{c.get('id')}")
    if ts(tl["requirements_received_at"]) > presented or presented > issued:
        errors.append("TIMELINE_OUT_OF_ORDER")
    if issued >= ts(auth["valid_before"]):
        errors.append("DECISION_AFTER_AUTHORIZATION_EXPIRY")

    # payment binding (optional raw inputs)
    if binding_inputs is not None:
        p = body["payment"]
        targets = [p["authorization"]["nonce_sha256"], p["payment_requirements_sha256"], p["request_sha256"]]
        for t in targets:
            fn = HASH_INPUTS.get(t.get("input"))
            if fn is None:
                errors.append(f"UNKNOWN_HASH_INPUT:{t.get('input')}")
            elif sha256_hex(fn(binding_inputs)) != t.get("hex"):
                errors.append(f"BINDING_HASH_MISMATCH:{t.get('input')}")
        pr = binding_inputs.get("payment_requirements", {})
        for field, rk in (("payee", "payTo"), ("amount_atomic", "maxAmountRequired"),
                          ("network", "network"), ("asset", "asset"), ("scheme", "scheme")):
            if rk in pr and str(pr[rk]).lower() != str(p[field]).lower():
                errors.append(f"BINDING_FIELD_MISMATCH:{field}")
        if not any(e.startswith("BINDING") or e.startswith("UNKNOWN_HASH") for e in errors):
            info.append("BINDING_RECOMPUTED_OK")

    # links
    linked_hashes = {sha256_hex(canonicalize(l)) for l in (linked or [])}
    for l in body.get("links", []):
        exp = l.get("expires_at")
        if exp and ts(exp) <= issued:
            warnings.append(f"LINK_EXPIRED_AT_ISSUANCE:{l.get('rel')}")
        if linked:
            if l["record_sha256"]["hex"] in linked_hashes:
                info.append(f"LINK_RECOMPUTED_OK:{l.get('rel')}")
            else:
                warnings.append(f"LINK_NOT_SUPPLIED_OR_MISMATCH:{l.get('rel')}")

    return {"status": "VALID" if sig_ok and not errors else "INVALID",
            "schema_version": body.get("schema_version"), "sha256": digest, "key_id": key_id,
            "errors": errors, "warnings": warnings, "info": info,
            "example_data": body.get("example_data") is True}


def verify_record(rec: dict, **kw) -> dict:
    v = str(rec.get("schema_version", ""))
    if v.startswith("0.2"):
        pem = kw.get("pub_pem")
        if pem is None and kw.get("keyset"):
            kid = rec.get("signature", {}).get("key_id")
            pem = next((k["public_key_pem"] for k in kw["keyset"]["keys"] if k["key_id"] == kid), None)
        if pem is None:
            pem = (HERE / "demo-pub.pem").read_text()
        return verify_v02(rec, pem)
    if v.startswith("0.3"):
        return verify_v03(rec, keyset=kw.get("keyset"), pub_pem=kw.get("pub_pem"),
                          binding_inputs=kw.get("binding_inputs"), linked=kw.get("linked"))
    raise ValueError(f"unsupported schema_version {v!r}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("record")
    ap.add_argument("pubkey", nargs="?", help="PEM public key (skips keyset validity checks for v0.3)")
    ap.add_argument("--keyset")
    ap.add_argument("--binding-inputs")
    ap.add_argument("--linked", nargs="*", default=[])
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    rec = json.loads(Path(a.record).read_text(encoding="utf-8"))
    kw: dict = {}
    if a.pubkey:
        kw["pub_pem"] = Path(a.pubkey).read_text()
    if a.keyset or (not a.pubkey and str(rec.get("schema_version", "")).startswith("0.3")):
        kw["keyset"] = json.loads(Path(a.keyset or HERE / "demo-keyset.json").read_text())
    if a.binding_inputs:
        kw["binding_inputs"] = json.loads(Path(a.binding_inputs).read_text())
    if a.linked:
        kw["linked"] = [json.loads(Path(p).read_text()) for p in a.linked]
    res = verify_record(rec, **kw)
    if a.json:
        print(json.dumps(res, indent=2))
    else:
        print(res["status"])
        print("schema_version:", res["schema_version"])
        print("sha256:", res["sha256"])
        print("key_id:", res["key_id"])
        for k in ("errors", "warnings", "info"):
            if res.get(k):
                print(f"{k}:", ", ".join(res[k]))
    sys.exit(0 if res["status"] == "VALID" else 1)


if __name__ == "__main__":
    main()
