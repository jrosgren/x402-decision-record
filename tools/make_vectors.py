#!/usr/bin/env python3
"""Generate the v1.0 test vectors (EXAMPLE DATA ONLY).

Usage: python3 tools/make_vectors.py --key /path/to/demo-key.pem

The demo private key is NOT in this repository and must never be committed.
Requires: cryptography, rfc8785 (pip install cryptography rfc8785).
Writes test-vectors/v1.0/* (positive and negative vectors plus expected.json),
the keyset copies, the schema copies in verifier/, and injects the vectors and
schemas into verifier/verify.html.
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
TV = ROOT / "test-vectors" / "v1.0"
NEG = TV / "negative"
L = 2 ** 252 + 27742317777372353535851937790883648493
KEY_ID = "polkulab-demo-2026-11"
KEYSET_URI = "https://jrosgren.github.io/x402-decision-record/.well-known/x402-decision-keyset.json"
DEMO_PUB_PEM = (ROOT / "verifier" / "demo-pub.pem").read_text().strip() + "\n"


def jcs(obj) -> bytes:
    return rfc8785.dumps(obj)


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def h(inp: str, data: bytes) -> dict:
    return {"alg": "sha-256", "input": inp, "hex": sha256_hex(data)}


def dump(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def sign_v02(record: dict, key: Ed25519PrivateKey, key_id: str = KEY_ID) -> dict:
    """Legacy 0.2-draft signature object (with canonicalization and sha256 members)."""
    body = copy.deepcopy(record)
    body.pop("signature", None)
    msg = jcs(body)
    out = copy.deepcopy(body)
    out["signature"] = {"alg": "Ed25519", "key_id": key_id,
                        "canonicalization": "RFC 8785 (JCS) of the record without the signature field",
                        "sha256": sha256_hex(msg), "sig_base64": base64.b64encode(key.sign(msg)).decode()}
    return out


def sign(record: dict, key: Ed25519PrivateKey, key_id: str = KEY_ID) -> dict:
    """v1.0 signature object: exactly alg, key_id, sig_base64 (SPEC §3)."""
    body = copy.deepcopy(record)
    body.pop("signature", None)
    sig = key.sign(jcs(body))
    out = copy.deepcopy(body)
    out["signature"] = {"alg": "Ed25519", "key_id": key_id, "sig_base64": base64.b64encode(sig).decode()}
    return out


# ---------------------------------------------------------------- inputs
NONCE_HEX = "0x" + "e1" * 4 + "0" * 48 + "00000001"  # example bytes32 nonce
# x402 v2: one element of PaymentRequired.accepts (amount, not v1 maxAmountRequired; no resource)
PAYMENT_REQUIREMENTS = {
    "scheme": "exact",
    "network": "eip155:8453",
    "amount": "4500000",
    "asset": "0x0000000000000000000000000000000000000003",
    "payTo": "0x0000000000000000000000000000000000000002",
    "maxTimeoutSeconds": 300,
    "extra": {"name": "USD Coin (example)", "version": "2"},
}
# x402 v2: PaymentRequired.resource (ResourceInfo)
RESOURCE_INFO = {
    "url": "https://api.example-seller.test/v1/report",
    "description": "EXAMPLE resource (example data)",
    "mimeType": "application/json",
}
RESOURCE_REQUEST = {
    "method": "GET",
    "url": "https://api.example-seller.test/v1/report?id=example-123",
    "body_sha256": sha256_hex(b""),
}
BINDING_INPUTS = {
    "_note": "EXAMPLE DATA ONLY. Raw inputs a client would hold, so a verifier can recompute the binding hashes.",
    "authorization_nonce": NONCE_HEX,
    "x402_version": 2,
    "payment_requirements": PAYMENT_REQUIREMENTS,
    "resource": RESOURCE_INFO,
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
                received="2026-11-19T09:00:00.000Z", record_id="at_dr_example_v10_000001"):
    nonce_bytes = bytes.fromhex(NONCE_HEX[2:])
    d = issued_at[:10]
    checks = [
        check("endpoint.health", "pass", f"{d}T09:00:00.210Z", "recomputable_from_client_view",
              {"http_status": 402, "payment_requirements_sha256": sha256_hex(jcs(PAYMENT_REQUIREMENTS))}),
        check("terms.price_vs_listing", "warn", f"{d}T09:00:00.260Z", "recomputable_from_client_view",
              {"requested_atomic": "4500000", "listed_atomic": "3000000",
               "listing_source": "https://api.example-seller.test/.well-known/x402-listing (example)",
               "listing_sha256": sha256_hex(b"example listing document")}),
        check("payto.change", "pass", f"{d}T09:00:00.300Z", "issuer_assertion",
              {"payto_first_seen_at": "2026-11-13T10:00:00Z", "changes_since_first_seen": 0}),
        check("payee.wallet_risk", "warn", f"{d}T09:00:00.640Z", "recomputable_from_chain",
              {"network": "eip155:8453", "first_tx_block": 22000000, "first_tx_hash": "0x" + "ab" * 32,
               "age_days_at_check": 6}),
        check("x-polkulab.sanctions_list", "pass", f"{d}T09:00:00.700Z", "issuer_assertion",
              {"list": "OFAC SDN (digital currency addresses)", "list_snapshot_date": "2026-11-18",
               "list_snapshot_sha256": sha256_hex(b"example list snapshot"), "match": False}),
    ]
    return {
        "schema_version": "1.0",
        "record_type": "x402-pre-payment-decision",
        "record_id": record_id,
        "example_data": True,
        "issuer": "https://trypolkulab.com",
        "signing_key": {
            "key_id": KEY_ID,
            "keyset_uri": KEYSET_URI,
        },
        "payment": {
            "x402_version": 2,
            "scheme": "exact",
            "network": "eip155:8453",
            "asset": "0x0000000000000000000000000000000000000003",
            "asset_symbol": "USDC",
            "asset_decimals": 6,
            "amount_atomic": "4500000",
            "payer": "0x0000000000000000000000000000000000000001",
            "payee": "0x0000000000000000000000000000000000000002",
            "resource": RESOURCE_INFO["url"],
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
            {"code": "LISTS_NOT_CHECKED", "text": "Sanctions or risk lists other than the one named in the x-polkulab.sanctions_list check, and list changes after its snapshot date."},
            {"code": "PRINCIPAL_AUTHORIZATION", "text": "Whether the human or organisation behind the payer agent approved this payment."},
            {"code": "FUTURE_STATE", "text": "Anything that happened after decision_issued_at."},
        ],
    }


def mutated(key, fn, record_id, **kw) -> dict:
    """Build the base record, apply fn, then sign: the only defect is the one fn introduces."""
    r = base_record(record_id=record_id, **kw)
    fn(r)
    return sign(r, key, key_id=r["signing_key"]["key_id"])


def set_path(obj, path, value):
    for k in path[:-1]:
        obj = obj[k]
    obj[path[-1]] = value


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", required=True, help="path to the demo Ed25519 private key PEM (never commit it)")
    args = ap.parse_args()
    key = serialization.load_pem_private_key(Path(args.key).read_bytes(), password=None)
    pub = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    if pub.strip() != DEMO_PUB_PEM.strip():
        raise SystemExit("private key does not match verifier/demo-pub.pem")

    for old in list(TV.glob("*.json")) + list(NEG.glob("*.json")):
        old.unlink()  # regenerate from scratch
    TV.mkdir(parents=True, exist_ok=True)
    (TV / "linked").mkdir(exist_ok=True)
    NEG.mkdir(exist_ok=True)

    # ------------------------------------------------------------ keysets
    keyset = {
        "_note": "EXAMPLE / DEMO keyset. The demo key signs example records only, never production decisions.",
        "keyset_version": "1.0",
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

    def keyset_variant(note, fn):
        k = copy.deepcopy(keyset)
        k["_note"] = "EXAMPLE keyset for tests: " + note
        fn(k)
        return k

    keysets = {
        "keyset-revoked.json": keyset_variant("the demo key revoked for key_compromise.", lambda k: (
            k.update({"published_at": "2026-11-20T00:00:00Z"}),
            k["keys"][0].update({"status": "revoked", "revoked_at": "2026-11-20T00:00:00Z", "revocation_reason": "key_compromise"}))),
        "keyset-superseded-later.json": keyset_variant("the demo key superseded on 2026-12-01, after valid.json was issued.", lambda k:
            k["keys"][0].update({"status": "revoked", "revoked_at": "2026-12-01T00:00:00Z", "revocation_reason": "superseded"})),
        "keyset-superseded-earlier.json": keyset_variant("the demo key superseded at 2026-11-19T09:00:00Z, before valid.json was issued.", lambda k:
            k["keys"][0].update({"status": "revoked", "revoked_at": "2026-11-19T09:00:00Z", "revocation_reason": "superseded"})),
        "keyset-duplicate-key-id.json": keyset_variant("the same key_id twice, first revoked then active (must be rejected, not last-wins).", lambda k:
            k["keys"].insert(0, dict(k["keys"][0], status="revoked", revoked_at="2026-11-02T00:00:00Z", revocation_reason="key_compromise"))),
        "keyset-version-0.3.json": keyset_variant("unsupported keyset_version.", lambda k: k.update({"keyset_version": "0.3-draft"})),
        "keyset-bad-timestamp.json": keyset_variant("valid_from without a Z zone.", lambda k: k["keys"][0].update({"valid_from": "2026-11-01T00:00:00"})),
    }
    # A production-like keyset that does not contain the demo key. The public key is derived from a
    # fixed public test seed, so the file is stable; it is a test key, never used to sign anything real.
    prod_pub = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"x402-decision-record test: production-like keyset").digest()) \
        .public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    keysets["keyset-production-like.json"] = {
        "_note": "EXAMPLE keyset for tests: production-like, WITHOUT the demo key. Test public key only.",
        "keyset_version": "1.0",
        "issuer": "https://trypolkulab.com",
        "published_at": "2026-11-19T00:00:00Z",
        "keys": [{"key_id": "polkulab-prod-2026-12", "alg": "Ed25519", "public_key_pem": prod_pub,
                  "valid_from": "2026-12-01T00:00:00Z", "valid_until": "2027-12-01T00:00:00Z", "status": "active",
                  "purpose": "test stand-in for a production key"}],
    }

    # ------------------------------------------------------------ records
    valid = sign(base_record(), key)
    tampered = copy.deepcopy(valid)
    tampered["decision"]["score"] = 30
    other = Ed25519PrivateKey.generate()  # throwaway key, discarded after this run
    wrong = sign(base_record(record_id="at_dr_example_v10_000002"), other)
    expired = sign(base_record(issued_at="2027-01-15T09:00:00.910Z", valid_after="2027-01-15T08:59:00Z",
                               valid_before="2027-01-15T09:05:00Z", presented="2027-01-15T09:00:00.150Z",
                               received="2027-01-15T09:00:00.000Z", record_id="at_dr_example_v10_000003"), key)

    dump(TV / "valid.json", valid)
    dump(TV / "tampered.json", tampered)
    dump(TV / "wrong-key.json", wrong)
    dump(TV / "expired-key.json", expired)
    dump(TV / "keyset-demo.json", keyset)
    for name, ks in keysets.items():
        dump(TV / name, ks)
    dump(TV / "linked" / "content-time-record.json", CONTENT_TIME_RECORD)
    dump(TV / "linked" / "seller-attestation.json", SELLER_ATTESTATION)
    dump(ROOT / "verifier" / "demo-keyset.json", keyset)
    (ROOT / ".well-known").mkdir(exist_ok=True)
    dump(ROOT / ".well-known" / "x402-decision-keyset.json", keyset)

    # binding inputs: x402 v2 plus variants
    dump(TV / "binding-inputs.json", BINDING_INPUTS)

    def bi_variant(note, fn):
        b = copy.deepcopy(BINDING_INPUTS)
        b["_note"] = "EXAMPLE DATA ONLY. Negative binding inputs: " + note
        fn(b)
        return b

    v1_pr = {"scheme": "exact", "network": "base", "maxAmountRequired": "4500000",
             "resource": RESOURCE_INFO["url"], "description": RESOURCE_INFO["description"],
             "mimeType": RESOURCE_INFO["mimeType"], "payTo": PAYMENT_REQUIREMENTS["payTo"],
             "maxTimeoutSeconds": 300, "asset": PAYMENT_REQUIREMENTS["asset"], "extra": PAYMENT_REQUIREMENTS["extra"]}
    bindings = {
        "binding-inputs-x402-v1.json": bi_variant("x402 v1 requirements (maxAmountRequired, network 'base'); must be mapped to v2 first.",
                                                  lambda b: b.update({"x402_version": 1, "payment_requirements": v1_pr})),
        "binding-inputs-no-amount.json": bi_variant("amount missing.", lambda b: b["payment_requirements"].pop("amount")),
        "binding-inputs-wrong-amount.json": bi_variant("amount differs from amount_atomic.", lambda b: b["payment_requirements"].update({"amount": "9900000"})),
        "binding-inputs-wrong-payto.json": bi_variant("payTo differs from payee.", lambda b: b["payment_requirements"].update({"payTo": "0x0000000000000000000000000000000000000009"})),
        "binding-inputs-wrong-resource.json": bi_variant("resource.url differs from payment.resource.", lambda b: b["resource"].update({"url": "https://other.example-seller.test/v1/report"})),
        "binding-inputs-wrong-nonce.json": bi_variant("a different 32-byte nonce.", lambda b: b.update({"authorization_nonce": "0x" + "00" * 32})),
        "binding-inputs-bad-nonce.json": bi_variant("nonce is 31 bytes, not 32.", lambda b: b.update({"authorization_nonce": "0x" + "e1" * 31})),
    }
    for name, b in bindings.items():
        dump(NEG / name, b)
    altered_ct = dict(CONTENT_TIME_RECORD, observed_at="2026-11-19T09:00:03Z")
    dump(NEG / "linked-content-time-record-altered.json", altered_ct)

    # negative records (each signed with the demo key, so only the named defect is wrong)
    def sig_variant(fn):
        r = copy.deepcopy(valid)
        fn(r["signature"])
        return r

    raw_sig = base64.b64decode(valid["signature"]["sig_base64"])
    s_plus_l = raw_sig[:32] + (int.from_bytes(raw_sig[32:], "little") + L).to_bytes(32, "little")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    b64 = valid["signature"]["sig_base64"]
    noncanon = b64[:85] + alphabet[(alphabet.index(b64[85]) & 0b110000) | 0b0101] + "=="
    assert base64.b64decode(noncanon) == raw_sig and noncanon != b64

    def drop_evidence(i, inp=None):
        def f(r):
            del r["checks"][i]["evidence"]
            if inp:
                r["checks"][i]["evidence_sha256"]["input"] = inp
        return f

    def bad_evidence(r):
        r["checks"][0]["evidence"]["http_status"] = 200  # hash no longer matches, but signed

    neg = {
        "sig-extra-member.json": sig_variant(lambda s: s.update({"extra": "x"})),
        "sig-canonicalization-member.json": sig_variant(lambda s: s.update({"canonicalization": "RFC8785"})),
        "sig-sha256-member.json": sig_variant(lambda s: s.update({"sha256": "00" * 32})),
        "sig-noncanonical-base64.json": sig_variant(lambda s: s.update({"sig_base64": noncanon})),
        "sig-s-plus-l.json": sig_variant(lambda s: s.update({"sig_base64": base64.b64encode(s_plus_l).decode()})),
        "version-0.3-draft.json": mutated(key, lambda r: r.update({"schema_version": "0.3-draft"}), "at_dr_neg_version_03"),
        "version-1.0.0.json": mutated(key, lambda r: r.update({"schema_version": "1.0.0"}), "at_dr_neg_version_100"),
        "ts-microseconds.json": mutated(key, lambda r: set_path(r, ["timeline", "authorization_presented_at"], "2026-11-19T09:00:00.150900Z"), "at_dr_neg_ts_us"),
        "ts-no-zone.json": mutated(key, lambda r: set_path(r, ["timeline", "decision_issued_at"], "2026-11-19T09:00:00.910"), "at_dr_neg_ts_nozone"),
        "ts-offset.json": mutated(key, lambda r: set_path(r, ["timeline", "requirements_received_at"], "2026-11-19T11:00:00.000+02:00"), "at_dr_neg_ts_offset"),
        "ts-not-a-date.json": mutated(key, lambda r: set_path(r, ["checks", 0, "ran_at"], "2026-02-30T09:00:00.210Z"), "at_dr_neg_ts_feb30"),
        "x402-v1-record.json": mutated(key, lambda r: set_path(r, ["payment", "x402_version"], 1), "at_dr_neg_x402v1"),
        "link-ceiling-bogus.json": mutated(key, lambda r: set_path(r, ["links", 0, "evidence_ceiling"], "bogus"), "at_dr_neg_link_ceiling"),
        "link-input-md5.json": mutated(key, lambda r: set_path(r, ["links", 0, "record_sha256", "input"], "md5(x)"), "at_dr_neg_link_input"),
        "seller-attestation-no-expiry.json": mutated(key, lambda r: r["links"][1].pop("expires_at"), "at_dr_neg_attest_noexp"),
        "withheld-evidence-unknown-input.json": mutated(key, drop_evidence(2, "sha3(foo)"), "at_dr_neg_withheld_input"),
        "score-101.json": mutated(key, lambda r: set_path(r, ["decision", "score"], 101), "at_dr_neg_score101"),
        "non-evm-network.json": mutated(key, lambda r: set_path(r, ["payment", "network"], "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"), "at_dr_neg_solana"),
        "unknown-key-id.json": mutated(key, lambda r: set_path(r, ["signing_key", "key_id"], "polkulab-unknown-key"), "at_dr_neg_unknown_key"),
        "key-id-mismatch.json": sign(dict(base_record(record_id="at_dr_neg_kid_mismatch"), signing_key={"key_id": "polkulab-other-key", "keyset_uri": KEYSET_URI}), key),
        "timeline-out-of-order.json": mutated(key, lambda r: None, "at_dr_neg_timeline", received="2026-11-19T09:00:00.200Z"),
        "check-outside-window.json": mutated(key, lambda r: set_path(r, ["checks", 0, "ran_at"], "2026-11-19T09:00:00.100Z"), "at_dr_neg_check_window"),
        "decision-after-expiry.json": mutated(key, lambda r: None, "at_dr_neg_expiry", valid_before="2026-11-19T09:00:00.500Z"),
        "authorization-window-inverted.json": mutated(key, lambda r: None, "at_dr_neg_auth_window", valid_after="2026-11-19T09:06:00Z"),
        "evidence-hash-mismatch.json": mutated(key, bad_evidence, "at_dr_neg_evidence"),
        "field-pointer-unresolved.json": mutated(key, lambda r: r["field_evidence_ceilings"].update({"/payment/does_not_exist": "issuer_assertion"}), "at_dr_neg_pointer"),
    }
    pos = {
        "unknown-check-id.json": mutated(key, lambda r: set_path(r, ["checks", 0, "id"], "some.future_check"), "at_dr_pos_unknown_check"),
        "withheld-evidence.json": mutated(key, drop_evidence(2), "at_dr_pos_withheld"),
    }
    for name, r in neg.items():
        dump(NEG / name, r)
    for name, r in pos.items():
        dump(TV / name, r)
    # numbers: written as text, since a float or an out-of-range integer cannot be JCS-signed
    vtext = (TV / "valid.json").read_text(encoding="utf-8")
    for name, old, new in (("number-float.json", '"score": 62,', '"score": 62.0,'),
                           ("number-too-large.json", '"first_tx_block": 22000000,', '"first_tx_block": 9007199254740993,')):
        assert vtext.count(old) == 1
        (NEG / name).write_text(vtext.replace(old, new), encoding="utf-8")

    # duplicate members (DUPLICATE_MEMBER), written as text
    assert vtext.count('"score": 62,') == 1
    (NEG / "duplicate-member.json").write_text(vtext.replace('"score": 62,', '"score": 30,\n    "score": 62,'), encoding="utf-8")
    ktext = (TV / "keyset-demo.json").read_text(encoding="utf-8")
    assert ktext.count('"status": "active",') == 1
    (NEG / "keyset-duplicate-member.json").write_text(ktext.replace('"status": "active",', '"status": "revoked",\n      "status": "active",'), encoding="utf-8")
    for name, net in (("network-leading-zero.json", "eip155:08453"), ("network-zero.json", "eip155:0")):
        dump(NEG / name, mutated(key, lambda r, net=net: set_path(r, ["payment", "network"], net), "at_dr_neg_" + name[:-5].replace("-", "_")))

    # strict text parsing of binding inputs and linked records (written as text)
    btext = (TV / "binding-inputs.json").read_text(encoding="utf-8")
    for name, old, new in (("binding-inputs-duplicate-member.json", '"amount": "4500000",', '"amount": "1",\n    "amount": "4500000",'),
                           ("binding-inputs-float.json", '"maxTimeoutSeconds": 300,', '"maxTimeoutSeconds": 300.0,')):
        assert btext.count(old) == 1
        (NEG / name).write_text(btext.replace(old, new), encoding="utf-8")
    stext = (TV / "linked" / "seller-attestation.json").read_text(encoding="utf-8")
    assert stext.count('"scope": ') == 1
    (NEG / "linked-duplicate-member.json").write_text(stext.replace('"scope": ', '"scope": "anything",\n  "scope": ', 1), encoding="utf-8")
    (NEG / "linked-not-json.json").write_text('{"record_type": "example-seller-attestation",}\n', encoding="utf-8")

    # legacy 0.2-draft (SPEC §11.1)
    v02 = json.loads((ROOT / "verifier" / "record-valid.json").read_text(encoding="utf-8"))
    v02_body = {k: v for k, v in v02.items() if k != "signature"}
    # Ella's case 1: v1.0 content relabelled 0.2-draft, signed with the demo key (revoked for key_compromise
    # in keyset-revoked.json). Must not pass as a "signature-only" legacy record.
    relabel = dict(base_record(record_id="at_dr_neg_legacy_relabel"), schema_version="0.2-draft")
    dump(NEG / "legacy-v1-fields-relabelled.json", sign(relabel, key))
    # Ella's case 2: the same with decision_issued_at in 2030, after the key's valid_until.
    relabel2 = dict(base_record(record_id="at_dr_neg_legacy_relabel_2030", issued_at="2030-01-15T09:00:00.910Z",
                                valid_after="2030-01-15T08:59:00Z", valid_before="2030-01-15T09:05:00Z",
                                presented="2030-01-15T09:00:00.150Z", received="2030-01-15T09:00:00.000Z"),
                    schema_version="0.2-draft")
    dump(NEG / "legacy-v1-fields-relabelled-2030.json", sign(relabel2, key))
    # a pure v0.2 record issued (checkedAt) in 2030, after the key's valid_until
    dump(NEG / "legacy-v02-checked-2030.json", sign_v02(dict(v02_body, record_id="at_dr_neg_legacy_2030", checkedAt="2030-01-15T09:00:00Z"), key))
    # a v0.2 record carrying one v1.0 member
    dump(NEG / "legacy-v02-with-payment.json", sign_v02(dict(v02_body, record_id="at_dr_neg_legacy_payment", payment=base_record()["payment"]), key))

    # Example of a later record linking to a decision record: hash = jcs(record), signature INCLUDED.
    outcome = {
        "_note": "EXAMPLE DATA ONLY. Unsigned stand-in for a later outcome record that links to valid.json.",
        "record_type": "example-outcome-record",
        "issuer": "https://trypolkulab.com",
        "status": "settled",
        "tx_hash": "0x" + "cd" * 32,
        "links": [{"rel": "decision_record", "issuer": "https://trypolkulab.com",
                   "record_sha256": h("jcs(record)", jcs(valid)), "evidence_ceiling": "issuer_assertion"}],
    }
    dump(TV / "example-outcome-record.json", outcome)
    keyset_bytes = (ROOT / ".well-known" / "x402-decision-keyset.json").read_bytes()
    anchor = sha256_hex(keyset_bytes)
    print("keyset.json sha256 (release-notes anchor):", anchor)

    # ------------------------------------------------------------ expected.json
    body = copy.deepcopy(valid); body.pop("signature")
    LINKED = ["linked/content-time-record.json", "linked/seller-attestation.json"]
    BI = "binding-inputs.json"
    cases = []

    def case(name, record, status, errors=(), warnings=(), keyset="keyset-demo.json", **kw):
        c = {"name": name, "record": record, "keyset": keyset}
        c.update(kw)
        c.update({"status": status, "errors": sorted(errors), "warnings": sorted(warnings)})
        cases.append(c)

    case("valid, full (binding inputs and linked records)", "valid.json", "VALID", binding_inputs=BI, linked=LINKED,
         info_includes=["BINDING_RECOMPUTED_OK", "LINK_RECOMPUTED_OK:content_time_record", "LINK_RECOMPUTED_OK:seller_attestation",
                        "CUSTOM_CHECK_ID:x-polkulab.sanctions_list"], sha256=sha256_hex(jcs(body)))
    case("valid, keyset matches the release anchor", "valid.json", "VALID", keyset_sha256=anchor)
    case("keyset does not match the release anchor", "valid.json", "INVALID", ["KEYSET_SHA256_MISMATCH"], keyset_sha256="0" * 64)
    case("tampered after signing (score 62 -> 30)", "tampered.json", "INVALID", ["BAD_SIGNATURE"])
    case("signed with a different key under the demo key_id", "wrong-key.json", "INVALID", ["BAD_SIGNATURE"])
    case("issued after the key's valid_until", "expired-key.json", "INVALID", ["KEY_NOT_VALID_AT_ISSUANCE"],
         ["LINK_EXPIRED_AT_ISSUANCE:seller_attestation"])
    case("key revoked for key_compromise", "valid.json", "INVALID", ["KEY_REVOKED"], keyset="keyset-revoked.json")
    case("key superseded after issuance: still valid", "valid.json", "VALID", [], ["KEY_SUPERSEDED_AFTER_ISSUANCE"], keyset="keyset-superseded-later.json")
    case("key superseded before issuance", "valid.json", "INVALID", ["KEY_REVOKED"], keyset="keyset-superseded-earlier.json")
    case("M3 duplicate key_id in keyset", "valid.json", "INVALID", ["DUPLICATE_KEY_ID:" + KEY_ID], keyset="keyset-duplicate-key-id.json")
    case("M2 keyset_version not 1.0", "valid.json", "INVALID", ["UNSUPPORTED_KEYSET_VERSION:keyset#/keyset_version"], keyset="keyset-version-0.3.json")
    case("M4 keyset timestamp without Z", "valid.json", "INVALID", ["BAD_TIMESTAMP:keyset#/keys/0/valid_from"], keyset="keyset-bad-timestamp.json")
    case("M1 extra member in signature", "negative/sig-extra-member.json", "INVALID", ["BAD_SIGNATURE_OBJECT:/signature"])
    case("M1 canonicalization member in signature", "negative/sig-canonicalization-member.json", "INVALID", ["BAD_SIGNATURE_OBJECT:/signature"])
    case("M1 sha256 member in signature", "negative/sig-sha256-member.json", "INVALID", ["BAD_SIGNATURE_OBJECT:/signature"])
    case("M1 non-canonical base64 (unused bits set)", "negative/sig-noncanonical-base64.json", "INVALID", ["NONCANONICAL_SIGNATURE:/signature/sig_base64"])
    case("M1 malleated signature S+L", "negative/sig-s-plus-l.json", "INVALID", ["BAD_SIGNATURE"])
    case("M2 schema_version 0.3-draft", "negative/version-0.3-draft.json", "INVALID", ["UNSUPPORTED_SCHEMA_VERSION"])
    case("M2 schema_version 1.0.0 (no prefix match)", "negative/version-1.0.0.json", "INVALID", ["UNSUPPORTED_SCHEMA_VERSION"])
    case("M4 timestamp with microseconds", "negative/ts-microseconds.json", "INVALID", ["BAD_TIMESTAMP:/timeline/authorization_presented_at"])
    case("M4 timestamp without zone", "negative/ts-no-zone.json", "INVALID", ["BAD_TIMESTAMP:/timeline/decision_issued_at"])
    case("M4 timestamp with +02:00 offset", "negative/ts-offset.json", "INVALID", ["BAD_TIMESTAMP:/timeline/requirements_received_at"])
    case("M4 timestamp that is not a calendar date", "negative/ts-not-a-date.json", "INVALID", ["BAD_TIMESTAMP:/checks/0/ran_at"])
    case("M5 record claims x402 v1", "negative/x402-v1-record.json", "INVALID", ["SCHEMA_VIOLATION:/payment/x402_version"])
    case("M5 x402 v1 requirements as binding input", "valid.json", "INVALID",
         ["BINDING_FIELD_MISMATCH:network", "BINDING_HASH_MISMATCH:jcs(payment_requirements)", "UNSUPPORTED_X402_V1_REQUIREMENTS"], binding_inputs="negative/binding-inputs-x402-v1.json")
    case("M5 amount missing from requirements", "valid.json", "INVALID",
         ["BINDING_HASH_MISMATCH:jcs(payment_requirements)", "BINDING_FIELD_MISSING:amount"], binding_inputs="negative/binding-inputs-no-amount.json")
    case("M5 amount differs", "valid.json", "INVALID",
         ["BINDING_HASH_MISMATCH:jcs(payment_requirements)", "BINDING_FIELD_MISMATCH:amount_atomic"], binding_inputs="negative/binding-inputs-wrong-amount.json")
    case("payTo differs", "valid.json", "INVALID",
         ["BINDING_HASH_MISMATCH:jcs(payment_requirements)", "BINDING_FIELD_MISMATCH:payee"], binding_inputs="negative/binding-inputs-wrong-payto.json")
    case("resource url differs", "valid.json", "INVALID", ["BINDING_FIELD_MISMATCH:resource"], binding_inputs="negative/binding-inputs-wrong-resource.json")
    case("wrong nonce", "valid.json", "INVALID", ["BINDING_HASH_MISMATCH:eip3009-nonce-bytes32"], binding_inputs="negative/binding-inputs-wrong-nonce.json")
    case("B3 nonce not 32 bytes", "valid.json", "INVALID", ["BAD_NONCE"], binding_inputs="negative/binding-inputs-bad-nonce.json")
    case("M6 link ceiling 'bogus'", "negative/link-ceiling-bogus.json", "INVALID", ["SCHEMA_VIOLATION:/links/0/evidence_ceiling"])
    case("M6 link input md5(x)", "negative/link-input-md5.json", "INVALID", ["SCHEMA_VIOLATION:/links/0/record_sha256/input"])
    case("M6 seller attestation without expires_at", "negative/seller-attestation-no-expiry.json", "INVALID", ["SCHEMA_VIOLATION:/links/1/expires_at"])
    case("M6 withheld evidence with unknown input id", "negative/withheld-evidence-unknown-input.json", "INVALID", ["SCHEMA_VIOLATION:/checks/2/evidence_sha256/input"])
    case("M6 score 101", "negative/score-101.json", "INVALID", ["SCHEMA_VIOLATION:/decision/score"])
    case("B1 float in record", "negative/number-float.json", "INVALID", ["BAD_NUMBER:/decision/score"])
    case("B1 integer above 2^53-1", "negative/number-too-large.json", "INVALID", ["BAD_NUMBER:/checks/3/evidence/first_tx_block"])
    case("non-EVM network", "negative/non-evm-network.json", "INVALID", ["UNSUPPORTED_NETWORK:/payment/network"])
    case("unknown key_id", "negative/unknown-key-id.json", "INVALID", ["UNKNOWN_KEY"])
    case("signing_key.key_id differs from signature.key_id", "negative/key-id-mismatch.json", "INVALID", ["KEY_ID_MISMATCH"])
    case("B2 requirements received after authorization presented", "negative/timeline-out-of-order.json", "INVALID", ["TIMELINE_OUT_OF_ORDER"])
    case("check ran before authorization presented", "negative/check-outside-window.json", "INVALID", ["CHECK_OUTSIDE_DECISION_WINDOW:endpoint.health"])
    case("decision issued after valid_before", "negative/decision-after-expiry.json", "INVALID", ["DECISION_AFTER_AUTHORIZATION_EXPIRY"])
    case("B2 valid_after after valid_before", "negative/authorization-window-inverted.json", "INVALID", ["AUTHORIZATION_WINDOW_INVALID"])
    case("inline evidence does not match its hash", "negative/evidence-hash-mismatch.json", "INVALID", ["EVIDENCE_HASH_MISMATCH:endpoint.health"])
    case("K1 field_evidence_ceilings pointer does not resolve", "negative/field-pointer-unresolved.json", "INVALID", ["UNRESOLVED_POINTER:/payment/does_not_exist"])
    case("unknown check id is info only", "unknown-check-id.json", "VALID", info_includes=["UNKNOWN_CHECK_ID:some.future_check"])
    case("withheld evidence is info only", "withheld-evidence.json", "VALID", info_includes=["EVIDENCE_WITHHELD:payto.change"])
    case("linked record altered: warning only", "valid.json", "VALID", [],
         ["LINK_NOT_SUPPLIED_OR_MISMATCH:content_time_record", "LINK_NOT_SUPPLIED_OR_MISMATCH:seller_attestation"],
         linked=["negative/linked-content-time-record-altered.json"])
    case("S1 duplicate member in record", "negative/duplicate-member.json", "INVALID", ["DUPLICATE_MEMBER:/decision/score"])
    case("S1 duplicate member in keyset", "valid.json", "INVALID", ["DUPLICATE_MEMBER:keyset#/keys/0/status"], keyset="negative/keyset-duplicate-member.json")
    case("S3 network with leading zero", "negative/network-leading-zero.json", "INVALID", ["UNSUPPORTED_NETWORK:/payment/network"])
    case("S3 network eip155:0", "negative/network-zero.json", "INVALID", ["UNSUPPORTED_NETWORK:/payment/network"])
    case("binding inputs with a duplicate member", "valid.json", "INVALID",
         ["DUPLICATE_MEMBER:binding_inputs#/payment_requirements/amount"], binding_inputs="negative/binding-inputs-duplicate-member.json")
    case("binding inputs with a float", "valid.json", "INVALID",
         ["BAD_NUMBER:binding_inputs#/payment_requirements/maxTimeoutSeconds"], binding_inputs="negative/binding-inputs-float.json")
    case("linked record with a duplicate member", "valid.json", "INVALID", ["DUPLICATE_MEMBER:linked[1]#/scope"],
         linked=["linked/content-time-record.json", "negative/linked-duplicate-member.json"])
    case("linked record that is not JSON", "valid.json", "INVALID", ["BAD_JSON:linked[0]#"], linked=["negative/linked-not-json.json"])
    # legacy 0.2-draft: only with allow_legacy_v02
    LV = "../../verifier/record-valid.json"
    V1_MEMBERS = ["record_type", "issuer", "signing_key", "payment", "timeline", "checks", "decision",
                  "field_evidence_ceilings", "links", "not_covered"]
    relabel_errors = ["LEGACY_V02_WITH_V1_FIELDS:/" + m for m in V1_MEMBERS] + ["SCHEMA_VIOLATION:/checkedAt"]
    case("legacy v0.2 not enabled", LV, "INVALID", ["LEGACY_V02_NOT_ENABLED"])
    case("legacy v0.2 valid", LV, "VALID", [], ["LEGACY_V02_SIGNATURE_ONLY"], allow_legacy_v02=True,
         sha256="f3a1e3138054d02beac297c4024b82510aceb5507ef4af9b803670f1738435f0")
    case("legacy v0.2 tampered", "../../verifier/record-tampered.json", "INVALID", ["BAD_SIGNATURE"],
         ["EMBEDDED_SHA256_MISMATCH"], allow_legacy_v02=True)
    case("legacy v0.2, no keyset and no key: demo key assumed", LV, "VALID", [], ["DEMO_KEY_ASSUMED", "LEGACY_V02_SIGNATURE_ONLY"],
         keyset=None, allow_legacy_v02=True)
    case("Ella 1: v1.0 fields labelled 0.2-draft, key revoked (key_compromise)", "negative/legacy-v1-fields-relabelled.json",
         "INVALID", relabel_errors, keyset="keyset-revoked.json", allow_legacy_v02=True)
    case("Ella 2: v1.0 fields labelled 0.2-draft, issued 2030", "negative/legacy-v1-fields-relabelled-2030.json",
         "INVALID", relabel_errors, keyset="keyset-revoked.json", allow_legacy_v02=True)
    case("Ella 3: demo-signed v0.2 against a production-like keyset", LV, "INVALID", ["UNKNOWN_KEY"],
         keyset="keyset-production-like.json", allow_legacy_v02=True)
    case("legacy v0.2, key revoked for key_compromise", LV, "INVALID", ["KEY_REVOKED"], keyset="keyset-revoked.json", allow_legacy_v02=True)
    case("legacy v0.2, key superseded: always revoked on the legacy path", LV, "INVALID", ["KEY_REVOKED"],
         keyset="keyset-superseded-later.json", allow_legacy_v02=True)
    case("legacy v0.2, checkedAt after the key's valid_until", "negative/legacy-v02-checked-2030.json", "INVALID",
         ["KEY_NOT_VALID_AT_ISSUANCE"], allow_legacy_v02=True)
    case("legacy v0.2, checkedAt 2030 and key revoked", "negative/legacy-v02-checked-2030.json", "INVALID",
         ["KEY_NOT_VALID_AT_ISSUANCE", "KEY_REVOKED"], keyset="keyset-revoked.json", allow_legacy_v02=True)
    case("legacy v0.2 with one v1.0 member", "negative/legacy-v02-with-payment.json", "INVALID",
         ["LEGACY_V02_WITH_V1_FIELDS:/payment"], allow_legacy_v02=True)
    # v1.0.1 (additive): skipped recomputations are reported as info, never as warnings or errors
    SKIP_LINKS = ["LINK_RECOMPUTATION_SKIPPED:content_time_record", "LINK_RECOMPUTATION_SKIPPED:seller_attestation"]
    case("v1.0.1 no binding inputs or linked records: both recomputations skipped (info only)", "valid.json", "VALID",
         info_includes=["BINDING_RECOMPUTATION_SKIPPED"] + SKIP_LINKS,
         info_excludes=["BINDING_RECOMPUTED_OK", "LINK_RECOMPUTED_OK:content_time_record", "LINK_RECOMPUTED_OK:seller_attestation"])
    case("v1.0.1 binding inputs only: link recomputation skipped (info only)", "valid.json", "VALID", binding_inputs=BI,
         info_includes=["BINDING_RECOMPUTED_OK"] + SKIP_LINKS, info_excludes=["BINDING_RECOMPUTATION_SKIPPED"])
    case("v1.0.1 linked records only: binding recomputation skipped (info only)", "valid.json", "VALID", linked=LINKED,
         info_includes=["BINDING_RECOMPUTATION_SKIPPED", "LINK_RECOMPUTED_OK:content_time_record", "LINK_RECOMPUTED_OK:seller_attestation"],
         info_excludes=SKIP_LINKS)
    case("v1.0.1 full inputs: nothing skipped", "valid.json", "VALID", binding_inputs=BI, linked=LINKED,
         info_includes=["BINDING_RECOMPUTED_OK"], info_excludes=["BINDING_RECOMPUTATION_SKIPPED"] + SKIP_LINKS)
    case("v1.0.1 skip info does not rescue an invalid record", "tampered.json", "INVALID", ["BAD_SIGNATURE"],
         info_includes=["BINDING_RECOMPUTATION_SKIPPED"] + SKIP_LINKS)
    dump(TV / "expected.json", {
        "_note": ("Expected verifier results. Paths are relative to this folder. Both reference test suites iterate over "
                  "this list and compare status, the sorted errors and the sorted warnings exactly. keyset null means no "
                  "keyset; keyset_sha256 is checked against the exact bytes of the keyset file. allow_legacy_v02 true means "
                  "legacy 0.2-draft verification is enabled (verify.py --allow-legacy-v02, allowLegacyV02 in verify.html). "
                  "Records and keysets are passed to the verifiers as file text. info_includes must all be in the info list; "
                  "info_excludes (v1.0.1) must all be absent. Info entries never change status, errors or warnings."),
        "keyset_anchor_sha256": anchor,
        "cases": cases,
    })

    # schema copies next to the standalone verifier
    for s in ("decision-record.v1.0.schema.json", "decision-record.v0.2.schema.json", "keyset.v1.0.schema.json"):
        (ROOT / "verifier" / s).write_bytes((ROOT / "schema" / s).read_bytes())

    # inject into verify.html
    html_path = ROOT / "verifier" / "verify.html"
    html = html_path.read_text(encoding="utf-8")
    rs = json.loads((ROOT / "schema" / "decision-record.v1.0.schema.json").read_text(encoding="utf-8"))
    ks = json.loads((ROOT / "schema" / "keyset.v1.0.schema.json").read_text(encoding="utf-8"))
    block = ("/* BEGIN GENERATED (tools/make_vectors.py) */\n"
             f"  const RECORD_SCHEMA = {json.dumps(rs)};\n"
             f"  const KEYSET_SCHEMA = {json.dumps(ks)};\n"
             f"  const LEGACY_V02_SCHEMA = {json.dumps(json.loads((ROOT / 'schema' / 'decision-record.v0.2.schema.json').read_text(encoding='utf-8')))};\n"
             f"  const DEMO_KEYSET = {json.dumps(keyset, indent=2)};\n"
             f"  const DEMO_V10 = {json.dumps({'valid': valid, 'tampered': tampered, 'wrong_key': wrong, 'expired_key': expired}, indent=2)};\n"
             f"  const DEMO_BINDING_INPUTS = {json.dumps(BINDING_INPUTS, indent=2)};\n"
             f"  const DEMO_LINKED = {json.dumps([CONTENT_TIME_RECORD, SELLER_ATTESTATION], indent=2)};\n"
             "  /* END GENERATED */")
    new, n = re.subn(r"/\* BEGIN (?:V03 VECTORS|GENERATED).*?/\* END (?:V03 VECTORS|GENERATED) \*/", lambda m: block, html, flags=re.S)
    if n == 1:
        html_path.write_text(new, encoding="utf-8")
        print("injected vectors and schemas into verify.html")
    else:
        raise SystemExit("markers not found in verify.html")
    print("wrote", len(cases), "expected cases;", len(neg), "negative records")


if __name__ == "__main__":
    main()
