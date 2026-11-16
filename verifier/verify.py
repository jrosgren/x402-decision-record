#!/usr/bin/env python3
"""Verify an AgentTrust signed decision record (Ed25519 over RFC 8785 / JCS).

Usage: python3 verify.py RECORD.json [PUBLIC_KEY.pem]

The signature covers the record with the "signature" field removed,
canonicalized as RFC 8785 (JCS). If the rfc8785 package is installed it
is used; otherwise json.dumps(..., sort_keys=True, separators=(',', ':'))
is used, which matches JCS for the example records (ASCII keys, integers).

EXAMPLE DATA: the sample records shipped with this script are illustrations,
not live Payvetted decisions. Made by Aron, Polkulab (Payvetted).
"""
from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def canonicalize(obj: dict) -> bytes:
    try:
        import rfc8785  # type: ignore
        return rfc8785.dumps(obj)
    except ImportError:
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")


def verify(record_path: Path, pubkey_path: Path) -> tuple[bool, str, str]:
    rec = json.loads(record_path.read_text(encoding="utf-8"))
    if "signature" not in rec:
        raise SystemExit("record has no signature field")
    sig = rec.pop("signature")
    canon = canonicalize(rec)
    digest = hashlib.sha256(canon).hexdigest()
    sig_bytes = base64.b64decode(sig["sig_base64"])
    with tempfile.TemporaryDirectory() as td:
        cpath = Path(td) / "canon.json"
        spath = Path(td) / "sig.bin"
        cpath.write_bytes(canon)
        spath.write_bytes(sig_bytes)
        proc = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(pubkey_path),
                "-rawin",
                "-in",
                str(cpath),
                "-sigfile",
                str(spath),
            ],
            capture_output=True,
            text=True,
        )
    ok = proc.returncode == 0
    return ok, digest, (sig.get("sha256") or "")


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__.strip(), file=sys.stderr)
        sys.exit(2)
    record_path = Path(sys.argv[1])
    pubkey_path = Path(
        sys.argv[2]
        if len(sys.argv) > 2
        else Path(__file__).resolve().parent / "demo-pub.pem"
    )
    ok, digest, embedded = verify(record_path, pubkey_path)
    print("VALID" if ok else "INVALID")
    print("sha256:", digest)
    if embedded and embedded != digest:
        print("embedded sha256 does not match canonical bytes:", embedded)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
