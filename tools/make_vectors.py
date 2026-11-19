#!/usr/bin/env python3
"""Generate the v0.3 test vectors (EXAMPLE DATA ONLY).

Usage: python3 tools/make_vectors.py --key /path/to/demo-key.pem

The demo private key is NOT in this repository and must never be committed.
Requires: cryptography, rfc8785 (pip install cryptography rfc8785).
Writes test-vectors/v0.3/* and injects the vectors into verifier/verify.html.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import re
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
TV = ROOT / "test-vectors" / "v0.3"
KEY_ID = "polkulab-demo-2026-11"
DEMO_PUB_PEM = (ROOT / "verifier" / "demo-pub.pem").read_text().strip() + "\n"


def jcs(obj) -> bytes:
    return rfc8785.dumps(obj)


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def h(inp: str, data: bytes) -> dict:
    return {"alg": "sha-256", "input": inp, "hex": sha256_hex(data)}


def dump(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def sign(record: dict, key: Ed25519PrivateKey, key_id: str = KEY_ID) -> dict:
    body = copy.deepcopy(record)
    body.pop("signature", None)
    canon = jcs(body)
    sig = key.sign(canon)
    out = copy.deepcopy(body)
    out["signature"] = {
        "alg": "Ed25519",
        "key_id": key_id,
        "canonicalization": "RFC 8785 (JCS) of the record without the signature member",
        "sha256": sha256_hex(canon),
        "sig_base64": base64.b64encode(sig).decode(),
    }
    return out


# ---------------------------------------------------------------- inputs
NONCE_HEX = "0x" + "e1" * 4 + "0" * 48 + "00000001"  # example bytes32 nonce
PAYMENT_REQUIREMENTS = {
    "scheme": "exact",
    "network": "eip155:8453",
    "maxAmountRequired": "4500000",
    "resource": "https://api.example-seller.test/v1/report",
    "description": "EXAMPLE resource (example data)",
    "mimeType": "application/json",
    "payTo": "0x0000000000000000000000000000000000000002",
    "maxTimeoutSeconds": 300,
    "asset": "0x0000000000000000000000000000000000000003",
    "extra": {"name": "USD Coin (example)", "version": "2"},
}
RESOURCE_REQUEST = {
    "method": "GET",
    "url": "https://api.example-seller.test/v1/report?id=example-123",
    "body_sha256": sha256_hex(b""),
}
BINDING_INPUTS = {
    "_note": "EXAMPLE DATA ONLY. Raw inputs a client would hold, so a verifier can recompute the binding hashes.",
    "authorization_nonce": NONCE_HEX,
    "payment_requirements": PAYMENT_REQUIREMENTS,
    "resource_request": RESOURCE_REQUEST,
}

CONTENT_TIME_RECORD = {
    "_note": "EXAMPLE DATA ONLY. Stand-in for a separately issued content-time record.",
    "record_type": "example-content-time-record",
    "issuer": "https://content-time.example.test",
    "resource": "https://api.example-seller.test/v1/report?id=example-123",
    "content_sha256": sha256_hex(b"example response body"),
    "observed_at": "2026-11-19T09:00:02Z",
}
SELLER_ATTESTATION = {
    "_note": "EXAMPLE DATA ONLY. Stand-in for a seller attestation.",
    "record_type": "example-seller-attestation",
    "issuer": "https://attest.example-registry.test",
    "subject": "https://api.example-seller.test",
    "scope": "payTo 0x0000000000000000000000000000000000000002 is controlled by the operator of api.example-seller.test",
    "issued_at": "2026-11-10T00:00:00Z",
    "expires_at": "2026-12-10T00:00:00Z",
}


def check(cid, result, ran_at, ceiling, evidence):
    return {
        "id": cid,
        "result": result,
        "ran_at": ran_at,
        "evidence_ceiling": ceiling,
        "evidence_sha256": h("jcs(evidence)", jcs(evidence)),
        "evidence": evidence,
    }


def base_record(issued_at="2026-11-19T09:00:00.910Z", valid_after="2026-11-19T08:59:00Z",
                valid_before="2026-11-19T09:05:00Z", presented="2026-11-19T09:00:00.150Z",
                received="2026-11-19T09:00:00.000Z", record_id="at_dr_example_v03_000001"):
    nonce_bytes = bytes.fromhex(NONCE_HEX[2:])
    d = issued_at[:10]
    checks = [
        check("liveness", "pass", f"{d}T09:00:00.210Z", "recomputable_from_client_view",
              {"http_status": 402, "payment_requirements_sha256": sha256_hex(jcs(PAYMENT_REQUIREMENTS))}),
        check("price_vs_listing", "warn", f"{d}T09:00:00.260Z", "recomputable_from_client_view",
              {"requested_atomic": "4500000", "listed_atomic": "3000000",
               "listing_source": "https://api.example-seller.test/.well-known/x402-listing (example)",
               "listing_sha256": sha256_hex(b"example listing document")}),
        check("payto_change", "pass", f"{d}T09:00:00.300Z", "issuer_assertion",
              {"payto_first_seen_at": "2026-11-13T10:00:00Z", "changes_since_first_seen": 0}),
        check("payee_wallet_age", "warn", f"{d}T09:00:00.640Z", "recomputable_from_chain",
              {"network": "eip155:8453", "first_tx_block": 22000000, "first_tx_hash": "0x" + "ab" * 32,
               "age_days_at_check": 6}),
        check("sanctions_list", "pass", f"{d}T09:00:00.700Z", "issuer_assertion",
              {"list": "OFAC SDN (digital currency addresses)", "list_snapshot_date": "2026-11-18",
               "list_snapshot_sha256": sha256_hex(b"example list snapshot"), "match": False}),
    ]
    return {
        "schema_version": "0.3-draft",
        "record_type": "x402-pre-payment-decision",
        "record_id": record_id,
        "example_data": True,
        "issuer": "https://trypolkulab.com",
        "signing_key": {
            "key_id": KEY_ID,
            "keyset_uri": "https://trypolkulab.com/.well-known/x402-decision-keyset.json",
        },
        "payment": {
            "x402_version": 1,
            "scheme": "exact",
            "network": "eip155:8453",
            "asset": "0x0000000000000000000000000000000000000003",
            "asset_symbol": "USDC",
            "asset_decimals": 6,
            "amount_atomic": "4500000",
            "payer": "0x0000000000000000000000000000000000000001",
            "payee": "0x0000000000000000000000000000000000000002",
            "resource": "https://api.example-seller.test/v1/report",
            "authorization": {
                "nonce_sha256": h("eip3009-nonce-bytes32", nonce_bytes),
                "valid_after": valid_after,
                "valid_before": valid_before,
            },
            "payment_requirements_sha256": h("jcs(payment_requirements)", jcs(PAYMENT_REQUIREMENTS)),
            "request_sha256": h("jcs(resource_request)", jcs(RESOURCE_REQUEST)),
            "tx_hash": None,
        },
        "timeline": {
            "requirements_received_at": received,
            "authorization_presented_at": presented,
            "decision_issued_at": issued_at,
        },
        "checks": checks,
        "decision": {
            "verdict": "warn",
            "score": 62,
            "level": "medium",
            "reason_codes": ["PAYEE_NEW", "PRICE_ABOVE_LISTING"],
            "policy_id": "policy:default-v1",
            "payer_agent_id": "agent:example-buyer-01",
        },
        "field_evidence_ceilings": {
            "/payment/network": "recomputable_from_client_view",
            "/payment/asset": "recomputable_from_client_view",
            "/payment/amount_atomic": "recomputable_from_client_view",
            "/payment/payer": "recomputable_from_client_view",
            "/payment/payee": "recomputable_from_client_view",
            "/payment/resource": "recomputable_from_client_view",
            "/payment/authorization": "recomputable_from_client_view",
            "/payment/payment_requirements_sha256": "recomputable_from_client_view",
            "/payment/request_sha256": "recomputable_from_client_view",
            "/payment/tx_hash": "recomputable_from_chain",
            "/timeline": "issuer_assertion",
            "/decision": "issuer_assertion",
        },
        "links": [
            {"rel": "content_time_record", "issuer": CONTENT_TIME_RECORD["issuer"],
             "record_sha256": h("jcs(linked-record)", jcs(CONTENT_TIME_RECORD)),
             "evidence_ceiling": "issuer_assertion"},
            {"rel": "seller_attestation", "issuer": SELLER_ATTESTATION["issuer"],
             "scope": SELLER_ATTESTATION["scope"], "expires_at": SELLER_ATTESTATION["expires_at"],
             "record_sha256": h("jcs(linked-record)", jcs(SELLER_ATTESTATION)),
             "evidence_ceiling": "issuer_assertion"},
        ],
        "not_covered": [
            {"code": "SETTLEMENT", "text": "Whether or when the payment settled. The record is signed before settlement; tx_hash is null and settlement is attested by a separate linked record."},
            {"code": "RESOURCE_DELIVERY", "text": "Whether the seller delivered the resource after payment."},
            {"code": "RESOURCE_QUALITY", "text": "Whether the delivered content was correct, fresh or fit for purpose."},
            {"code": "PAYEE_LEGAL_IDENTITY", "text": "Who legally owns the payee wallet. No KYC/KYB was performed."},
            {"code": "LISTS_NOT_CHECKED", "text": "Sanctions or risk lists other than the one named in the sanctions_list check, and list changes after its snapshot date."},
            {"code": "PRINCIPAL_AUTHORIZATION", "text": "Whether the human or organisation behind the payer agent approved this payment."},
            {"code": "FUTURE_STATE", "text": "Anything that happened after decision_issued_at."},
        ],
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", required=True, help="path to the demo Ed25519 private key PEM (never commit it)")
    args = ap.parse_args()
    key = serialization.load_pem_private_key(Path(args.key).read_bytes(), password=None)
    pub = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    if pub.strip() != DEMO_PUB_PEM.strip():
        raise SystemExit("private key does not match verifier/demo-pub.pem")

    keyset = {
        "_note": "EXAMPLE / DEMO keyset. The demo key signs example records only, never production decisions.",
        "keyset_version": "0.3-draft",
        "example_data": True,
        "issuer": "https://trypolkulab.com",
        "published_at": "2026-11-19T00:00:00Z",
        "keys": [{
            "key_id": KEY_ID,
            "alg": "Ed25519",
            "public_key_pem": DEMO_PUB_PEM,
            "valid_from": "2026-11-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
            "status": "active",
            "purpose": "demo signing of example records only",
        }],
    }
    revoked = copy.deepcopy(keyset)
    revoked["_note"] = "EXAMPLE keyset for tests: the demo key marked revoked for key_compromise."
    revoked["published_at"] = "2026-11-20T00:00:00Z"
    revoked["keys"][0].update({"status": "revoked", "revoked_at": "2026-11-20T00:00:00Z",
                               "revocation_reason": "key_compromise"})

    valid = sign(base_record(), key)
    tampered = copy.deepcopy(valid)
    tampered["decision"]["score"] = 30
    other = Ed25519PrivateKey.generate()  # throwaway key, discarded after this run
    wrong = sign(base_record(record_id="at_dr_example_v03_000002"), other)
    expired = sign(base_record(issued_at="2027-01-15T09:00:00.910Z", valid_after="2027-01-15T08:59:00Z",
                               valid_before="2027-01-15T09:05:00Z", presented="2027-01-15T09:00:00.150Z",
                               received="2027-01-15T09:00:00.000Z", record_id="at_dr_example_v03_000003"), key)

    TV.mkdir(parents=True, exist_ok=True)
    (TV / "linked").mkdir(exist_ok=True)
    dump(TV / "valid.json", valid)
    dump(TV / "tampered.json", tampered)
    dump(TV / "wrong-key.json", wrong)
    dump(TV / "expired-key.json", expired)
    dump(TV / "keyset-demo.json", keyset)
    dump(TV / "keyset-revoked.json", revoked)
    dump(TV / "binding-inputs.json", BINDING_INPUTS)
    dump(TV / "linked" / "content-time-record.json", CONTENT_TIME_RECORD)
    dump(TV / "linked" / "seller-attestation.json", SELLER_ATTESTATION)
    dump(ROOT / "verifier" / "demo-keyset.json", keyset)
    dump(TV / "expected.json", {
        "_note": "Expected verifier results (keyset-demo.json unless stated).",
        "valid.json": {"status": "VALID"},
        "tampered.json": {"status": "INVALID", "reason": "BAD_SIGNATURE"},
        "wrong-key.json": {"status": "INVALID", "reason": "BAD_SIGNATURE"},
        "expired-key.json": {"status": "INVALID", "reason": "KEY_NOT_VALID_AT_ISSUANCE"},
        "valid.json+keyset-revoked.json": {"status": "INVALID", "reason": "KEY_REVOKED"},
    })

    # inject into verify.html
    html_path = ROOT / "verifier" / "verify.html"
    html = html_path.read_text(encoding="utf-8")
    block = ("/* BEGIN V03 VECTORS (generated by tools/make_vectors.py) */\n"
             f"  const DEMO_KEYSET = {json.dumps(keyset, indent=2)};\n"
             f"  const DEMO_V03 = {json.dumps({'valid': valid, 'tampered': tampered, 'wrong_key': wrong, 'expired_key': expired}, indent=2)};\n"
             f"  const DEMO_BINDING_INPUTS = {json.dumps(BINDING_INPUTS, indent=2)};\n"
             "  /* END V03 VECTORS */")
    new, n = re.subn(r"/\* BEGIN V03 VECTORS.*?/\* END V03 VECTORS \*/", lambda m: block, html, flags=re.S)
    if n == 1:
        html_path.write_text(new, encoding="utf-8")
        print("injected vectors into verify.html")
    else:
        print("WARNING: markers not found in verify.html; not injected")
    print("wrote", ", ".join(sorted(p.name for p in TV.iterdir())))


if __name__ == "__main__":
    main()
