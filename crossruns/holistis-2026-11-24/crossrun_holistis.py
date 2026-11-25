#!/usr/bin/env python3
"""
Vectors: github.com/holistis/agent-receipt-verify, cross-run 2026-11-24
Credit:  Abdellah Ouadoudi (github.com/holistis), attempt-identity vectors for x402 section 5.5
         (Apache-2.0). Upstream commit pinned in RESULTS.md / printed at runtime.
Against: github.com/jrosgren/x402-decision-record v1.0.1 (verifier/verify.py, SPEC section 6,
         input id `jcs(resource_request)` -> payment.request_sha256).

What this does (read-only; no network; example data only):
  0. Checks the fetched upstream vector folders against their SHA256SUMS.
  A. NATIVE: our request_sha256 rules as written in SPEC v1.0.1 section 6:
       request_sha256 = sha256(JCS({"method": UPPER, "url": absolute URL as requested incl. query,
                                    "body_sha256": hex sha256 of the RAW request body bytes}))
     For each known-answer vector we compute the value our rules put in body_sha256 / the query
     part of `url`, and compare it with holistis' right value and wrong value.
  B. ADAPTER (NOT part of our spec): section 5.5 canonical members, written here from the
     upstream README rules, using OUR verifier's RFC 8785 canonicalize() for JSON bodies.
     Shows whether our JCS implementation reproduces the known answers.
  C. canonical_variants vectors: does our NATIVE request_sha256 give the same
     equal/different relation that section 5.5 requires?
  D. Verifier sanity: our v1.0.1 verifier still recomputes the binding of our own vector,
     and request_sha256 values computed via verify.HASH_INPUTS for the upstream raw requests.
Exit code 0 if the script ran; findings (including expected differences) are reported, not asserted.
"""
import base64, glob, gzip, hashlib, json, os, re, subprocess, sys, zlib

HERE = os.path.dirname(os.path.abspath(__file__))
UP = os.path.join(HERE, "upstream", "vectors")
OURS = os.path.join(HERE, "ours")
sys.path.insert(0, os.path.join(OURS, "verifier"))
import verify  # our v1.0.1 verifier (uses rfc8785)

ORIGIN = "https://example.invalid"  # upstream raws carry only a path; our url must be absolute
sha = lambda b: hashlib.sha256(b).hexdigest()

def git_head(path):
    try:
        return subprocess.check_output(["git", "-C", path, "log", "-1", "--format=%H %cI"], text=True).strip()
    except Exception:
        return "unknown"

# ---------------------------------------------------------------- 0. integrity
def check_sums(folder):
    p = os.path.join(UP, folder, "SHA256SUMS")
    if not os.path.exists(p):
        return None
    bad = 0; n = 0
    for line in open(p):
        line = line.strip()
        if not line: continue
        h, name = line.split(None, 1); name = name.lstrip("*")
        f = os.path.join(UP, folder, name)
        n += 1
        if not os.path.exists(f) or sha(open(f, "rb").read()) != h: bad += 1
    return n, bad

# ---------------------------------------------------------------- A. native (our spec)
def raw_body(raw):
    return base64.b64decode(raw.get("bodyBase64", ""))

def native_query(raw):
    return raw.get("query", "")  # our spec: URL "as requested"; no canonicalisation

def native_url(raw):
    q = native_query(raw)
    return ORIGIN + raw.get("path", "/") + ("?" + q if q != "" else "")

def native_resource_request(raw):
    return {"method": raw.get("method", "").upper(), "url": native_url(raw),
            "body_sha256": sha(raw_body(raw))}

def native_request_sha256(raw):
    return sha(verify.HASH_INPUTS["jcs(resource_request)"]({"resource_request": native_resource_request(raw)}))

# ---------------------------------------------------------------- B. adapter (section 5.5, not our spec)
UNRES = re.compile(rb"[A-Za-z0-9\-._~]")
def pct_decode(s):
    out = bytearray(); i = 0
    while i < len(s):
        if s[i] == "%" and re.fullmatch(r"[0-9A-Fa-f]{2}", s[i+1:i+3] or ""):
            out.append(int(s[i+1:i+3], 16)); i += 3
        else:
            out += s[i].encode("utf-8"); i += 1
    return bytes(out)
def pct_encode(b):
    return "".join(chr(x) if x < 128 and UNRES.fullmatch(bytes([x])) else "%%%02X" % x for x in b)
def adapter_query(q):
    q = (q or "").lstrip("?")
    if q == "": return ""
    parts = []
    for seg in q.split("&"):          # arrival order kept; ';' is not a separator; '+' stays '+'
        if seg == "": continue         # upstream's documented choice for empty segments
        if "=" in seg:
            n, v = seg.split("=", 1); parts.append(pct_encode(pct_decode(n)) + "=" + pct_encode(pct_decode(v)))
        else:
            parts.append(pct_encode(pct_decode(seg)))  # bare name stays bare
    return "&".join(parts)

def has_duplicate_keys(text):
    dup = [False]
    def hook(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)): dup[0] = True
        return dict(pairs)
    json.loads(text, object_pairs_hook=hook)
    return dup[0]

def adapter_body_sha256(raw):
    b = raw_body(raw)
    for c in reversed([c.strip().lower() for c in raw.get("contentEncoding", "").split(",") if c.strip()]):
        if c in ("gzip", "x-gzip"): b = gzip.decompress(b)
        elif c == "deflate": b = zlib.decompress(b)
        elif c == "identity": pass
        else: raise ValueError("unsupported content-encoding " + c)
    ct = raw.get("contentType", "")
    m = re.search(r'charset\s*=\s*"?([A-Za-z0-9_\-.:]+)"?', ct, re.I)
    label = (m.group(1) if m else "utf-8").lower()
    text = b.decode("latin-1" if label in ("iso-8859-1", "latin1", "l1", "iso_8859-1") else label, errors="strict")
    canon = text
    if re.match(r"^application/(?:[\w.+-]*\+)?json\b", ct.strip(), re.I):
        try:
            if not has_duplicate_keys(text):
                canon = verify.canonicalize(json.loads(text)).decode("utf-8")  # OUR rfc8785 path
        except ValueError:
            canon = text
    return sha(canon.encode("utf-8"))

def adapter_members(raw):
    m = {"method": raw.get("method", "").upper(), "path": raw.get("path", "")}
    q = adapter_query(raw.get("query"))
    if q != "": m["query"] = q
    if raw.get("bodyBase64", "") != "": m["body"] = adapter_body_sha256(raw)
    return m

# ---------------------------------------------------------------- run
def load(folder, pattern="*.json"):
    return [(os.path.basename(f)[:-5], json.load(open(f, encoding="utf-8")))
            for f in sorted(glob.glob(os.path.join(UP, folder, pattern)))]

def main():
    print("Vectors: github.com/holistis/agent-receipt-verify, cross-run 2026-11-24")
    print("upstream commit:", git_head(os.path.join(HERE, "upstream")))
    print("ours (x402-decision-record) commit:", git_head(OURS))
    print()
    print("== 0. upstream SHA256SUMS")
    for f in ("attempt-identity", "attempt-identity-extra"):
        print(f"  {f}: files={check_sums(f)[0]} mismatches={check_sums(f)[1]}")

    ka = load("attempt-identity", "known-answer*.json") + [("extra/" + n, v) for n, v in load("attempt-identity-extra", "known-answer*.json")]
    print(f"\n== A/B. known-answer vectors ({len(ka)})")
    print(f"  {'vector':66s} {'exp':4s} | {'NATIVE (our spec)':22s} | ADAPTER (5.5 via our JCS)")
    tally = {"native_eq_right": 0, "native_eq_wrong": 0, "native_neither": 0, "adapter_ok": 0, "adapter_bad": 0}
    native_rows = []
    for name, v in ka:
        exp = v["expected"]["outcome"]
        for k in v["input"]["known_answers"]:
            raw, obs = k["raw"], k["observed"]
            member = "body_sha256" if "body_sha256" in obs else "query"
            native = sha(raw_body(raw)) if member == "body_sha256" else native_query(raw)
            adapter = adapter_body_sha256(raw) if member == "body_sha256" else adapter_query(raw.get("query"))
            # adapter verdict: PASS vector -> observed must equal adapter; FAIL vector -> must differ
            a_ok = (adapter == obs[member]) == (exp == "PASS")
            tally["adapter_ok" if a_ok else "adapter_bad"] += 1
            if exp == "PASS":
                rel = "== right value" if native == obs[member] else "!= right value"
                if native == obs[member]: tally["native_eq_right"] += 1
                else: tally["native_neither"] += 1
            else:
                rel = "== WRONG value" if native == obs[member] else "!= wrong value"
                if native == obs[member]: tally["native_eq_wrong"] += 1
            native_rows.append((name, member, exp, native == obs[member]))
            print(f"  {name:66s} {exp:4s} | {member[:5]:5s} {rel:16s} | {'agrees' if a_ok else 'DISAGREES'}")
    print("  tally:", tally)

    print("\n== C. canonical_variants: equal/different relation, section 5.5 vs our NATIVE request_sha256")
    agree = disagree = 0
    for name, v in load("attempt-identity"):
        cv = v["input"].get("canonical_variants")
        if not cv: continue
        a, b = cv[0]["raw"], cv[1]["raw"]
        recorded_same = cv[0]["identity"] == cv[1]["identity"]
        required_same = recorded_same if v["expected"]["outcome"] == "PASS" else not recorded_same
        ours_same = native_request_sha256(a) == native_request_sha256(b)
        adapter_same = adapter_members(a) == adapter_members(b)
        ok = ours_same == required_same
        agree += ok; disagree += (not ok)
        print(f"  {name:52s} 5.5 requires {'SAME' if required_same else 'DIFF'} | ours {'SAME' if ours_same else 'DIFF'} "
              f"{'agree' if ok else 'DIFFER'} | adapter {'SAME' if adapter_same else 'DIFF'}")
    print(f"  native agree={agree} differ={disagree}")

    # optional: do upstream identity labels equal sha256(key-sorted compact JSON of canonical members)?
    lab_ok = lab_n = 0
    for name, v in load("attempt-identity"):
        for var in v["input"].get("canonical_variants", []):
            lab_n += 1
            m = adapter_members(var["raw"])
            if sha(json.dumps(m, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()) == var["identity"]:
                lab_ok += 1
    print(f"  identity labels reproduced as sha256(sorted compact JSON of adapter members): {lab_ok}/{lab_n} "
          f"(informational; upstream says labels are produced by their own function)")

    print("\n== D. verifier sanity (ours, v1.0.1)")
    tv = os.path.join(OURS, "test-vectors", "v1.0")
    res = verify.verify_bytes if hasattr(verify, "verify_bytes") else None
    rec = json.load(open(os.path.join(tv, "valid.json"))); ks = json.load(open(os.path.join(tv, "keyset-demo.json")))
    bi = json.load(open(os.path.join(tv, "binding-inputs.json")))
    out = verify.verify_v10(rec, keyset=ks, binding_inputs=bi)
    print("  valid.json + binding-inputs.json:", out.get("status"), [i for i in out.get("info", []) if "BINDING" in i])
    bi2 = json.loads(json.dumps(bi)); first = ka[0][1]["input"]["known_answers"][0]["raw"]
    bi2["resource_request"] = native_resource_request(first)
    out2 = verify.verify_v10(rec, keyset=ks, binding_inputs=bi2)
    print("  same record, resource_request swapped for an upstream raw:", out2.get("status"),
          [e for e in out2.get("errors", []) if "request" in e])
    print("  native request_sha256 for upstream raws (origin placeholder", ORIGIN + "):")
    seen = set()
    for name, v in ka:
        raw = v["input"]["known_answers"][0]["raw"]
        key = json.dumps(raw, sort_keys=True)
        if key in seen: continue
        seen.add(key)
        print(f"    {name.replace('-wrong',''):60s} {native_request_sha256(raw)}")

if __name__ == "__main__":
    main()
