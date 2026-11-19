#!/usr/bin/env python3
"""Verify an x402 pre-payment decision record (v1.0, or legacy v0.2-draft).

Usage:
  python3 verify.py RECORD.json [PUBLIC_KEY.pem]
  python3 verify.py RECORD.json --keyset KEYSET.json
        [--keyset-sha256 HEX] [--binding-inputs INPUTS.json]
        [--linked FILE.json ...] [--allow-legacy-v02] [--json]

Signature: Ed25519 (RFC 8032, strict: canonical base64, S < L) over the
RFC 8785 (JCS) canonical JSON of the record with the "signature" member
removed (same rule in v0.2 and v1.0).

Dispatch is on the exact schema_version: "1.0" -> v1.0 rules; "0.2-draft" ->
legacy v0.2 rules, only with --allow-legacy-v02 (otherwise INVALID
LEGACY_V02_NOT_ENABLED); anything else -> INVALID UNSUPPORTED_SCHEMA_VERSION.
Legacy v0.2 (SPEC §11.1): closed v0.2 schema (no v1.0 members), keyset rules
(no demo-key fallback, any revocation -> KEY_REVOKED, validity window on
checkedAt), signature; a VALID result always carries LEGACY_V02_SIGNATURE_ONLY.

Record and keyset files are scanned as text first: duplicate members
(DUPLICATE_MEMBER) and numbers with a fraction or exponent part or outside
+-(2^53-1) (BAD_NUMBER) are rejected before parsing.

v1.0 steps, all offline (this script makes no network calls), SPEC §11:
  0. numbers (integers within +-(2^53-1), no floats), JSON Schema validation
     of the record (the schema/ files, with this script's own small validator
     so that it gives exactly the same errors as verify.html), timestamps;
  1. keyset: schema, keyset_version "1.0", unique key_id, optional SHA-256
     anchor (--keyset-sha256), key validity window and revocation;
  2. signature;
  3. inline evidence hashes, check ids against the minimal registry (unknown
     ids are info only), field_evidence_ceilings pointers resolve;
  4. timeline order;
  5. optional: payment binding from raw inputs (x402 v2 PaymentRequirements),
     linked record hashes.

Requires the rfc8785 package (pip install rfc8785). Ed25519 uses the
cryptography package if installed, else OpenSSL 3.

EXAMPLE DATA: the sample records shipped with this script are illustrations,
not live Payvetted decisions. Made by Aron, Polkulab (Payvetted).
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import rfc8785  # type: ignore
except ImportError:  # B1: no hand-rolled JCS fallback
    sys.exit("verify.py needs the rfc8785 package for RFC 8785 canonicalization: pip install rfc8785")

HERE = Path(__file__).resolve().parent
SCHEMA_VERSION = "1.0"
KEYSET_VERSION = "1.0"
LEGACY_V02 = "0.2-draft"
# Minimal check-id registry (SPEC §6.2). Custom ids use the prefix "x-<issuer>.".
CHECK_REGISTRY = {"endpoint.health", "terms.price_vs_listing", "payto.change", "payee.wallet_risk"}
MAX_SAFE_INT = 2 ** 53 - 1
ED25519_L = 2 ** 252 + 27742317777372353535851937790883648493
NONCE_RE = re.compile(r"^0x[0-9a-fA-F]{64}\Z")
TS_RE = re.compile(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{3}))?Z\Z")


def _find_schema(name: str) -> Path:
    for p in (HERE.parent / "schema" / name, HERE / name):
        if p.exists():
            return p
    raise FileNotFoundError(name)


RECORD_SCHEMA = json.loads(_find_schema("decision-record.v1.0.schema.json").read_text(encoding="utf-8"))
V02_SCHEMA = json.loads(_find_schema("decision-record.v0.2.schema.json").read_text(encoding="utf-8"))
KEYSET_SCHEMA = json.loads(_find_schema("keyset.v1.0.schema.json").read_text(encoding="utf-8"))


# ------------------------------------------------------------ primitives
def canonicalize(obj) -> bytes:
    return rfc8785.dumps(obj)


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def ptr_join(ptr: str, key) -> str:
    return ptr + "/" + str(key).replace("~", "~0").replace("/", "~1")


def ed25519_verify(pub_pem: str, message: bytes, sig: bytes) -> bool:
    if len(sig) != 64 or int.from_bytes(sig[32:], "little") >= ED25519_L:
        return False  # strict RFC 8032: S must be reduced (no S+L malleability)
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


def decode_sig(s) -> bytes | None:
    """Strict, canonical base64: must decode to 64 bytes and re-encode to the same string."""
    if not isinstance(s, str):
        return None
    try:
        raw = base64.b64decode(s, validate=True)
    except Exception:
        return None
    if len(raw) != 64 or base64.b64encode(raw).decode() != s:
        return None
    return raw


def ts_ms(s) -> int | None:
    """Epoch milliseconds for a v1.0 timestamp, or None if it is not one (BAD_TIMESTAMP)."""
    m = TS_RE.match(s) if isinstance(s, str) else None
    if not m:
        return None
    y, mo, d, h, mi, se = (int(x) for x in m.groups()[:6])
    ms = int(m.group(7) or 0)
    if not (1 <= mo <= 12 and 1 <= d <= _days_in_month(y, mo) and h < 24 and mi < 60 and se < 60):
        return None
    return ((_days_from_civil(y, mo, d) * 24 + h) * 60 + mi) * 60000 + se * 1000 + ms


def _days_in_month(y: int, m: int) -> int:
    if m == 2:
        return 29 if (y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)) else 28
    return 30 if m in (4, 6, 9, 11) else 31


def _days_from_civil(y: int, m: int, d: int) -> int:
    y -= m <= 2
    era = y // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


# ------------------------------------------------------------ step 0: numbers and schema
def number_errors(o, ptr: str = "") -> list[str]:
    """SPEC §3: only integers within +-(2^53-1); no fraction or exponent part anywhere."""
    out: list[str] = []
    if isinstance(o, bool) or o is None or isinstance(o, str):
        return out
    if isinstance(o, float) or (isinstance(o, int) and abs(o) > MAX_SAFE_INT):
        return ["BAD_NUMBER:" + ptr]
    if isinstance(o, dict):
        for k, v in o.items():
            out += number_errors(v, ptr_join(ptr, k))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            out += number_errors(v, ptr_join(ptr, i))
    return out


_NUM_RE = re.compile(r"-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?")


def scan_json(text: str) -> tuple[list[str], list[str]]:
    """Token scan of JSON text (same algorithm as scanJson in verify.html).

    Returns (DUPLICATE_MEMBER errors, BAD_NUMBER errors) with JSON Pointers.
    Raises ValueError for text that is not JSON."""
    i, n = 0, len(text)
    dups: list[str] = []
    bad: list[str] = []

    def ws():
        nonlocal i
        while i < n and text[i] in " \t\n\r":
            i += 1

    def string() -> str:
        nonlocal i
        start = i
        i += 1
        while i < n:
            c = text[i]
            if c == "\\":
                i += 2
            elif c == '"':
                i += 1
                return json.loads(text[start:i])
            else:
                i += 1
        raise ValueError("unterminated string")

    def value(ptr: str, depth: int = 0):
        nonlocal i
        if depth > 200:
            raise ValueError("nesting too deep")
        ws()
        c = text[i] if i < n else ""
        if c == "{":
            i += 1
            seen: set[str] = set()
            ws()
            if i < n and text[i] == "}":
                i += 1
                return
            while True:
                ws()
                if i >= n or text[i] != '"':
                    raise ValueError("expected member name")
                k = string()
                ws()
                if i >= n or text[i] != ":":
                    raise ValueError("expected :")
                i += 1
                if k in seen:
                    dups.append("DUPLICATE_MEMBER:" + ptr_join(ptr, k))
                seen.add(k)
                value(ptr_join(ptr, k), depth + 1)
                ws()
                if i < n and text[i] == ",":
                    i += 1
                    continue
                if i < n and text[i] == "}":
                    i += 1
                    return
                raise ValueError("expected , or }")
        if c == "[":
            i += 1
            ws()
            if i < n and text[i] == "]":
                i += 1
                return
            k = 0
            while True:
                value(ptr_join(ptr, k), depth + 1)
                k += 1
                ws()
                if i < n and text[i] == ",":
                    i += 1
                    continue
                if i < n and text[i] == "]":
                    i += 1
                    return
                raise ValueError("expected , or ]")
        if c == '"':
            string()
            return
        m = _NUM_RE.match(text, i)
        if m and m.group(0):
            i = m.end()
            if m.group(2) or m.group(3) or len(m.group(1)) > 16 or abs(int(m.group(0))) > MAX_SAFE_INT:
                bad.append("BAD_NUMBER:" + ptr)
            return
        for lit in ("true", "false", "null"):
            if text.startswith(lit, i):
                i += len(lit)
                return
        raise ValueError("unexpected character")

    value("")
    ws()
    if i != n:
        raise ValueError("trailing data")
    return _uniq(dups), _uniq(bad)


def _reject_constant(c):
    raise ValueError("NaN/Infinity are not JSON")


def parse_json_text(text) -> tuple[object, list[str]]:
    """Parse record/keyset text. Returns (object or None, errors)."""
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError:
            return None, ["BAD_JSON"]
    try:
        dups, bad = scan_json(text)
        obj = json.loads(text, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        return None, ["BAD_JSON"]
    return obj, (dups or bad)


def _type_ok(t, v) -> bool:
    if isinstance(t, list):
        return any(_type_ok(x, v) for x in t)
    return {
        "object": lambda: isinstance(v, dict),
        "array": lambda: isinstance(v, list),
        "string": lambda: isinstance(v, str),
        "boolean": lambda: isinstance(v, bool),
        "null": lambda: v is None,
        "integer": lambda: isinstance(v, int) and not isinstance(v, bool),
        "number": lambda: isinstance(v, (int, float)) and not isinstance(v, bool),
    }[t]()


def _json_equal(a, b) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_json_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_json_equal(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and a == b


def _pattern_ok(pattern: str, s: str) -> bool:
    # ECMA-262 semantics for the patterns used in the schemas: "$" means end of input.
    p = pattern[:-1] + r"\Z" if pattern.endswith("$") and not pattern.endswith("\\$") else pattern
    return re.search(p, s, flags=re.ASCII) is not None


def schema_errors(root: dict, node: dict, inst, ptr: str = "") -> list[str]:
    """Small JSON Schema 2020-12 validator for the keywords used in schema/*.json.

    The same algorithm is implemented in verify.html, so both verifiers report the
    same errors: "SCHEMA_VIOLATION:<json pointer>", or "<x-error-code>:<pointer>"
    when the failing subschema carries an x-error-code annotation."""
    local: list[str] = []
    sv = "SCHEMA_VIOLATION:"
    if "$ref" in node:
        ref = node["$ref"]
        assert ref.startswith("#/$defs/")
        local += schema_errors(root, root["$defs"][ref[len("#/$defs/"):]], inst, ptr)
    if "type" in node and not _type_ok(node["type"], inst):
        local.append(sv + ptr)
    else:
        if "const" in node and not _json_equal(inst, node["const"]):
            local.append(sv + ptr)
        if "enum" in node and not any(_json_equal(inst, e) for e in node["enum"]):
            local.append(sv + ptr)
        if "not" in node and not schema_errors(root, node["not"], inst, ptr):
            local.append(sv + ptr)
        if isinstance(inst, str):
            if "pattern" in node and not _pattern_ok(node["pattern"], inst):
                local.append(sv + ptr)
            if "minLength" in node and len(inst) < node["minLength"]:
                local.append(sv + ptr)
            if "maxLength" in node and len(inst) > node["maxLength"]:
                local.append(sv + ptr)
        if isinstance(inst, int) and not isinstance(inst, bool):
            if "minimum" in node and inst < node["minimum"]:
                local.append(sv + ptr)
            if "maximum" in node and inst > node["maximum"]:
                local.append(sv + ptr)
        if isinstance(inst, dict):
            for k in node.get("required", []):
                if k not in inst:
                    local.append(sv + ptr_join(ptr, k))
            props = node.get("properties", {})
            for k, v in inst.items():
                if k in props:
                    local += schema_errors(root, props[k], v, ptr_join(ptr, k))
                elif "additionalProperties" in node:
                    ap = node["additionalProperties"]
                    if ap is False:
                        local.append(sv + ptr_join(ptr, k))
                    elif isinstance(ap, dict):
                        local += schema_errors(root, ap, v, ptr_join(ptr, k))
                if "propertyNames" in node:
                    local += schema_errors(root, node["propertyNames"], k, ptr_join(ptr, k))
        if isinstance(inst, list):
            if "minItems" in node and len(inst) < node["minItems"]:
                local.append(sv + ptr)
            if "items" in node:
                for i, v in enumerate(inst):
                    local += schema_errors(root, node["items"], v, ptr_join(ptr, i))
        if "if" in node and not schema_errors(root, node["if"], inst, ptr) and "then" in node:
            local += schema_errors(root, node["then"], inst, ptr)
    code = node.get("x-error-code")
    if code:
        local = [(code + ":" + ptr) if e.startswith(sv) else e for e in local]
    return _uniq(local)


def _uniq(xs: list[str]) -> list[str]:
    seen: set[str] = set()
    return [x for x in xs if not (x in seen or seen.add(x))]


def record_timestamp_errors(body: dict) -> list[str]:
    out = []
    for ptr, v in _record_timestamps(body):
        if ts_ms(v) is None:
            out.append("BAD_TIMESTAMP:" + ptr)
    return out


def _record_timestamps(body: dict):
    tl = body.get("timeline", {})
    for k in ("requirements_received_at", "authorization_presented_at", "decision_issued_at"):
        if k in tl:
            yield "/timeline/" + k, tl[k]
    auth = body.get("payment", {}).get("authorization", {})
    for k in ("valid_after", "valid_before"):
        if k in auth:
            yield "/payment/authorization/" + k, auth[k]
    for i, c in enumerate(body.get("checks", [])):
        if "ran_at" in c:
            yield f"/checks/{i}/ran_at", c["ran_at"]
    for i, l in enumerate(body.get("links", [])):
        if "expires_at" in l:
            yield f"/links/{i}/expires_at", l["expires_at"]


def keyset_errors(keyset) -> list[str]:
    errs = ["SCHEMA_VIOLATION:keyset#" + e.split(":", 1)[1] if e.startswith("SCHEMA_VIOLATION:")
            else e.split(":", 1)[0] + ":keyset#" + e.split(":", 1)[1]
            for e in schema_errors(KEYSET_SCHEMA, KEYSET_SCHEMA, keyset)]
    if errs:
        return errs
    if keyset.get("published_at") is not None and ts_ms(keyset["published_at"]) is None:
        errs.append("BAD_TIMESTAMP:keyset#/published_at")
    seen: set[str] = set()
    for i, k in enumerate(keyset["keys"]):
        for f in ("valid_from", "valid_until", "revoked_at"):
            if f in k and ts_ms(k[f]) is None:
                errs.append(f"BAD_TIMESTAMP:keyset#/keys/{i}/{f}")
        if k["key_id"] in seen:
            errs.append("DUPLICATE_KEY_ID:" + k["key_id"])
        seen.add(k["key_id"])
    if errs:
        return _uniq(errs)
    for i, k in enumerate(keyset["keys"]):
        if ts_ms(k["valid_until"]) <= ts_ms(k["valid_from"]) or \
                ("revoked_at" in k and ts_ms(k["revoked_at"]) < ts_ms(k["valid_from"])):
            errs.append(f"BAD_KEY_WINDOW:keyset#/keys/{i}")
    return errs


def pointer_exists(doc, ptr: str) -> bool:
    cur = doc
    for raw in ptr.split("/")[1:]:
        tok = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, dict) and tok in cur:
            cur = cur[tok]
        elif isinstance(cur, list) and re.fullmatch(r"0|[1-9][0-9]*", tok) and int(tok) < len(cur):
            cur = cur[int(tok)]
        else:
            return False
    return True


def _result(status, version, digest, key_id, errors, warnings=None, info=None, example=False) -> dict:
    return {"status": status, "schema_version": version, "sha256": digest, "key_id": key_id,
            "errors": errors, "warnings": warnings or [], "info": info or [], "example_data": example}


def _invalid(rec, errors) -> dict:
    sig = rec.get("signature") if isinstance(rec, dict) else None
    kid = sig.get("key_id") if isinstance(sig, dict) else None
    v = rec.get("schema_version") if isinstance(rec, dict) else None
    return _result("INVALID", v, None, kid, _uniq(errors))


# ------------------------------------------------------------ v0.2 (legacy, opt-in)
def verify_legacy_v02(rec: dict, keyset: dict | None = None, pub_pem: str | None = None) -> dict:
    """SPEC §11.1. Signature-only legacy rules, but with the v1.0 key rules."""
    errors = number_errors(rec)
    if errors:
        return _invalid(rec, errors)
    errors = schema_errors(V02_SCHEMA, V02_SCHEMA, rec)
    if not errors and ts_ms(rec["checkedAt"]) is None:
        errors = ["BAD_TIMESTAMP:/checkedAt"]
    if errors:
        return _invalid(rec, errors)
    warnings: list[str] = []
    sig = rec["signature"]
    key_id = sig["key_id"]
    issued = ts_ms(rec["checkedAt"])
    pem = None
    if keyset is not None:
        kerr = keyset_errors(keyset)
        if kerr:
            return _invalid(rec, kerr)
        entry = next((k for k in keyset["keys"] if k["key_id"] == key_id), None)
        if entry is None:
            errors.append("UNKNOWN_KEY")  # never fall back to the demo key when a keyset is given
        else:
            pem = entry["public_key_pem"]
            if not (ts_ms(entry["valid_from"]) <= issued < ts_ms(entry["valid_until"])):
                errors.append("KEY_NOT_VALID_AT_ISSUANCE")
            if entry["status"] == "revoked":
                errors.append("KEY_REVOKED")  # any reason: v0.2 has no trustworthy issuance time
    elif pub_pem is not None:
        pem = pub_pem
        warnings.append("NO_KEYSET_VALIDITY_NOT_CHECKED")
    else:
        pem = (HERE / "demo-pub.pem").read_text()
        warnings.append("DEMO_KEY_ASSUMED")
    body = copy.deepcopy(rec)
    body.pop("signature")
    canon = canonicalize(body)
    digest = sha256_hex(canon)
    sig_ok = False
    if pem is not None:
        raw = decode_sig(sig["sig_base64"])
        sig_ok = raw is not None and ed25519_verify(pem, canon, raw)
        if not sig_ok:
            errors.insert(0, "BAD_SIGNATURE")
    if sig.get("sha256") and sig["sha256"] != digest:
        warnings.append("EMBEDDED_SHA256_MISMATCH")
    valid = sig_ok and not errors
    if valid:
        warnings.append("LEGACY_V02_SIGNATURE_ONLY")
    return _result("VALID" if valid else "INVALID", rec["schema_version"], digest, key_id,
                   _uniq(errors), warnings, [], rec.get("example_data") is True)


# ------------------------------------------------------------ v1.0
HASH_INPUTS = {
    "eip3009-nonce-bytes32": lambda bi: bytes.fromhex(bi["authorization_nonce"][2:]),
    "jcs(payment_requirements)": lambda bi: canonicalize(bi["payment_requirements"]),
    "jcs(resource_request)": lambda bi: canonicalize(bi["resource_request"]),
}
# record field -> x402 v2 PaymentRequirements field; all MUST be present (M5)
BINDING_FIELDS = (("payee", "payTo", True), ("amount_atomic", "amount", False), ("network", "network", False),
                  ("asset", "asset", True), ("scheme", "scheme", False))


def verify_v10(rec: dict, keyset: dict | None = None, pub_pem: str | None = None,
               binding_inputs: dict | None = None, linked: list | None = None) -> dict:
    # step 0: numbers, schema, timestamps
    errors = number_errors(rec)
    if errors:
        return _invalid(rec, errors)
    errors = schema_errors(RECORD_SCHEMA, RECORD_SCHEMA, rec) or record_timestamp_errors(rec)
    if errors:
        return _invalid(rec, errors)
    warnings: list[str] = []
    info: list[str] = []
    body = copy.deepcopy(rec)
    sig = body.pop("signature")
    canon = canonicalize(body)
    digest = sha256_hex(canon)
    key_id = sig["key_id"]
    issued = ts_ms(body["timeline"]["decision_issued_at"])

    if body["signing_key"]["key_id"] != key_id:
        errors.append("KEY_ID_MISMATCH")  # signed body must name the same key as the signature

    # step 1: key
    if keyset is not None:
        kerr = keyset_errors(keyset)
        if kerr:
            return _invalid(rec, errors + kerr)
        entry = next((k for k in keyset["keys"] if k["key_id"] == key_id), None)
        pub_pem = None
        if entry is None:
            errors.append("UNKNOWN_KEY")
        else:
            pub_pem = entry["public_key_pem"]
            if not (ts_ms(entry["valid_from"]) <= issued < ts_ms(entry["valid_until"])):
                errors.append("KEY_NOT_VALID_AT_ISSUANCE")
            if entry["status"] == "revoked":
                if entry["revocation_reason"] == "superseded" and issued < ts_ms(entry["revoked_at"]):
                    warnings.append("KEY_SUPERSEDED_AFTER_ISSUANCE")
                else:
                    errors.append("KEY_REVOKED")
    elif pub_pem is None:
        errors.append("NO_KEY")
    else:
        warnings.append("NO_KEYSET_VALIDITY_NOT_CHECKED")

    # step 2: signature
    sig_ok = False
    if pub_pem is not None:
        raw = decode_sig(sig["sig_base64"])
        sig_ok = raw is not None and ed25519_verify(pub_pem, canon, raw)
        if not sig_ok:
            errors.insert(0, "BAD_SIGNATURE")

    # step 3: checks, evidence, ceilings
    for c in body["checks"]:
        cid = c["id"]
        if cid not in CHECK_REGISTRY:
            info.append(f"{'CUSTOM' if cid.startswith('x-') else 'UNKNOWN'}_CHECK_ID:{cid}")
        if "evidence" in c:
            if c["evidence_sha256"]["hex"] != sha256_hex(canonicalize(c["evidence"])):
                errors.append(f"EVIDENCE_HASH_MISMATCH:{cid}")
        else:
            info.append(f"EVIDENCE_WITHHELD:{cid}")
    for ptr in body["field_evidence_ceilings"]:
        if not pointer_exists(rec, ptr):
            errors.append("UNRESOLVED_POINTER:" + ptr)

    # step 4: timeline, SPEC §5
    tl = body["timeline"]
    auth = body["payment"]["authorization"]
    received, presented = ts_ms(tl["requirements_received_at"]), ts_ms(tl["authorization_presented_at"])
    for c in body["checks"]:
        ran = ts_ms(c["ran_at"])
        if ran < presented or ran > issued:
            errors.append(f"CHECK_OUTSIDE_DECISION_WINDOW:{c['id']}")
    if received > presented or presented > issued:
        errors.append("TIMELINE_OUT_OF_ORDER")
    if issued >= ts_ms(auth["valid_before"]):
        errors.append("DECISION_AFTER_AUTHORIZATION_EXPIRY")
    if "valid_after" in auth and ts_ms(auth["valid_after"]) >= ts_ms(auth["valid_before"]):
        errors.append("AUTHORIZATION_WINDOW_INVALID")

    # step 5a: payment binding (optional raw inputs), x402 v2
    if binding_inputs is not None:
        before = len(errors)
        p = body["payment"]
        bi = binding_inputs if isinstance(binding_inputs, dict) else {}
        for t in (p["authorization"]["nonce_sha256"], p["payment_requirements_sha256"], p["request_sha256"]):
            inp = t["input"]
            if inp == "eip3009-nonce-bytes32" and not (isinstance(bi.get("authorization_nonce"), str)
                                                        and NONCE_RE.match(bi["authorization_nonce"])):
                errors.append("BAD_NONCE")
                continue
            src = {"jcs(payment_requirements)": "payment_requirements", "jcs(resource_request)": "resource_request"}.get(inp)
            if src and not isinstance(bi.get(src), dict):
                errors.append("BINDING_FIELD_MISSING:" + src)
                continue
            if sha256_hex(HASH_INPUTS[inp](bi)) != t["hex"]:
                errors.append(f"BINDING_HASH_MISMATCH:{inp}")
        pr = bi.get("payment_requirements")
        if isinstance(pr, dict):
            v1 = "maxAmountRequired" in pr and "amount" not in pr
            if v1:
                errors.append("UNSUPPORTED_X402_V1_REQUIREMENTS")  # map to v2 first, SPEC §4
            for field, rk, ci in BINDING_FIELDS:
                if rk not in pr:
                    if not (v1 and rk == "amount"):
                        errors.append("BINDING_FIELD_MISSING:" + rk)
                    continue
                a, b = pr[rk], p[field]
                if not isinstance(a, str) or (a.lower() != b.lower() if ci else a != b):
                    errors.append("BINDING_FIELD_MISMATCH:" + field)
        res = bi.get("resource")
        if res is not None and (not isinstance(res, dict) or res.get("url") != p["resource"]):
            errors.append("BINDING_FIELD_MISMATCH:resource")
        if len(errors) == before:
            info.append("BINDING_RECOMPUTED_OK")

    # step 5b: links
    linked_hashes = {sha256_hex(canonicalize(l)) for l in (linked or [])}
    for l in body["links"]:
        if "expires_at" in l and ts_ms(l["expires_at"]) <= issued:
            warnings.append(f"LINK_EXPIRED_AT_ISSUANCE:{l['rel']}")
        if linked:
            if l["record_sha256"]["input"] != "raw(linked-record)" and l["record_sha256"]["hex"] in linked_hashes:
                info.append(f"LINK_RECOMPUTED_OK:{l['rel']}")
            else:
                warnings.append(f"LINK_NOT_SUPPLIED_OR_MISMATCH:{l['rel']}")

    errors = _uniq(errors)
    return _result("VALID" if sig_ok and not errors else "INVALID", body["schema_version"], digest, key_id,
                   errors, warnings, info, body.get("example_data") is True)


def _label(errors: list[str], label: str) -> list[str]:
    """Prefix the pointer part of each error with <label>#, e.g. DUPLICATE_MEMBER:keyset#/keys/0/status."""
    out = []
    for e in errors:
        code, _, ptr = e.partition(":")
        out.append(f"{code}:{label}#{ptr}")
    return out


def verify_record(rec, keyset: dict | None = None, keyset_bytes: bytes | None = None,
                  keyset_sha256: str | None = None, pub_pem: str | None = None,
                  binding_inputs=None, linked=None,
                  allow_legacy_v02: bool = False) -> dict:
    """Verify one record.

    Pass the record, keyset (keyset_bytes), binding inputs and linked records as raw
    JSON text (str or bytes): only text can be checked for duplicate members
    (DUPLICATE_MEMBER) and number spelling (BAD_NUMBER). An already parsed object is
    still verified, but those checks cannot run on it, so the result carries the
    warning PARSED_INPUT:<record|keyset|binding_inputs|linked[i]>.
    linked may be a list of texts/objects, or one text holding an array or an object.

    Never raises for bad input; returns status VALID or INVALID."""
    notes: list[str] = []

    def fin(r: dict) -> dict:
        r["warnings"] = list(r["warnings"]) + notes
        return r

    if isinstance(rec, (str, bytes)):
        rec, perr = parse_json_text(rec)
        if perr:
            return fin(_invalid(rec, perr))
    else:
        notes.append("PARSED_INPUT:record")
    if keyset_bytes is not None:
        if keyset_sha256 is not None and sha256_hex(keyset_bytes) != keyset_sha256.lower():
            return fin(_invalid(rec, ["KEYSET_SHA256_MISMATCH"]))
        keyset, kperr = parse_json_text(keyset_bytes)
        if kperr:
            return fin(_invalid(rec, _label(kperr, "keyset")))
    elif keyset_sha256 is not None:
        raise ValueError("keyset_sha256 needs keyset_bytes (the anchor is over the exact file bytes)")
    elif keyset is not None:
        notes.append("PARSED_INPUT:keyset")
    aux_errors: list[str] = []
    if isinstance(binding_inputs, (str, bytes)):
        binding_inputs, berr = parse_json_text(binding_inputs)
        aux_errors += _label(berr, "binding_inputs")
    elif binding_inputs is not None:
        notes.append("PARSED_INPUT:binding_inputs")
    if isinstance(linked, (str, bytes)):
        obj, lerr = parse_json_text(linked)
        aux_errors += _label(lerr, "linked")
        linked = obj if isinstance(obj, list) else [obj]
    elif linked is not None:
        items = []
        for i, item in enumerate(linked):
            if isinstance(item, (str, bytes)):
                item, lerr = parse_json_text(item)
                aux_errors += _label(lerr, f"linked[{i}]")
            else:
                notes.append(f"PARSED_INPUT:linked[{i}]")
            items.append(item)
        linked = items
    if aux_errors:
        return fin(_invalid(rec, aux_errors))
    if not isinstance(rec, dict) or not isinstance(rec.get("signature"), dict):
        return fin(_invalid(rec, ["BAD_SIGNATURE_OBJECT"]))
    v = rec.get("schema_version")
    if v == SCHEMA_VERSION:
        return fin(verify_v10(rec, keyset=keyset, pub_pem=pub_pem, binding_inputs=binding_inputs, linked=linked))
    if v == LEGACY_V02:
        if not allow_legacy_v02:
            return fin(_invalid(rec, ["LEGACY_V02_NOT_ENABLED"]))
        return fin(verify_legacy_v02(rec, keyset=keyset, pub_pem=pub_pem))
    return fin(_invalid(rec, ["UNSUPPORTED_SCHEMA_VERSION"]))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("record")
    ap.add_argument("pubkey", nargs="?", help="PEM public key (skips keyset validity checks)")
    ap.add_argument("--keyset", help="keyset file (default for v1.0: demo-keyset.json next to this script)")
    ap.add_argument("--keyset-sha256", help="expected hex SHA-256 of the keyset file bytes (anchor from the release notes)")
    ap.add_argument("--binding-inputs")
    ap.add_argument("--linked", nargs="*", default=[])
    ap.add_argument("--allow-legacy-v02", action="store_true",
                    help="also accept legacy 0.2-draft records (signature only, SPEC §11.1)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    text = Path(a.record).read_bytes()
    try:
        rec = json.loads(text)
    except ValueError:
        rec = None
    kw: dict = {}
    if a.pubkey:
        kw["pub_pem"] = Path(a.pubkey).read_text()
    if a.keyset or (not a.pubkey and isinstance(rec, dict) and rec.get("schema_version") == SCHEMA_VERSION):
        kw["keyset_bytes"] = Path(a.keyset or HERE / "demo-keyset.json").read_bytes()
        kw["keyset_sha256"] = a.keyset_sha256
    # all inputs go to verify_record as raw bytes, so the strict text checks apply to each file
    if a.binding_inputs:
        kw["binding_inputs"] = Path(a.binding_inputs).read_bytes()
    if a.linked:
        kw["linked"] = [Path(p).read_bytes() for p in a.linked]
    res = verify_record(text, allow_legacy_v02=a.allow_legacy_v02, **kw)
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
