// Headless test of the JavaScript inside verifier/verify.html (example data).
// Run: node tests/test_verify_html.mjs
// Runs every case in test-vectors/v1.0/expected.json (the same list tests/test_vectors.py
// uses) through both the Web Crypto path and the inlined tweetnacl path, and compares
// status, sorted errors and sorted warnings exactly.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const html = readFileSync(join(root, 'verifier/verify.html'), 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
if (scripts.length !== 1) throw new Error('expected exactly one inline script');
if (/fetch\(|XMLHttpRequest|WebSocket|import\(|src=/.test(scripts[0])) throw new Error('verifier must not make network calls');

const ctx = { crypto: globalThis.crypto, TextEncoder, atob, console, Uint8Array, Float64Array, Uint32Array };
ctx.globalThis = ctx;
vm.createContext(ctx);
vm.runInContext(scripts[0] + '\nglobalThis.AgentTrustVerifier = AgentTrustVerifier;', ctx);
const V = ctx.AgentTrustVerifier;

const text = p => readFileSync(join(root, p), 'utf8');
const load = p => JSON.parse(text(p));
const tv = 'test-vectors/v1.0/';
const exp = load(tv + 'expected.json');

let pass = 0, fail = 0;
function check(name, cond, detail) {
  if (cond) { pass++; console.log('ok   ' + name); }
  else { fail++; console.log('FAIL ' + name + ' ' + JSON.stringify(detail)); }
}
const same = (a, b) => JSON.stringify([...a].sort()) === JSON.stringify(b);

for (const mode of [{ forceWebCrypto: true }, { forceTweetnacl: true }]) {
  const tag = mode.forceWebCrypto ? '[webcrypto]' : '[tweetnacl]';
  for (const c of exp.cases) {
    const opts = Object.assign({}, mode);
    if (c.keyset) opts.keysetText = text(tv + c.keyset);
    if (c.keyset_sha256) opts.keysetSha256 = c.keyset_sha256;
    if (c.binding_inputs) opts.bindingInputs = text(tv + c.binding_inputs);
    if (c.linked) opts.linked = c.linked.map(p => text(tv + p));
    if (c.allow_legacy_v02) opts.allowLegacyV02 = true;
    const r = await V.verifyRecord(text(tv + c.record), opts);
    const ok = r.status === c.status && same(r.errors, c.errors) && same(r.warnings, c.warnings) &&
      (c.info_includes || []).every(i => r.info.includes(i)) && (c.info_excludes || []).every(i => !r.info.includes(i)) && (!c.sha256 || r.sha256 === c.sha256);
    check(tag + ' ' + c.name, ok, { status: r.status, errors: r.errors, warnings: r.warnings, info: r.info });
  }
  // the page's embedded demo copies verify too
  const r = await V.verifyRecord(V.DEMO_V10.valid, Object.assign({ keysetText: JSON.stringify(V.DEMO_KEYSET, null, 2) + '\n',
    keysetSha256: exp.keyset_anchor_sha256, bindingInputs: V.DEMO_BINDING_INPUTS, linked: V.DEMO_LINKED }, mode));
  check(tag + ' embedded v1.0 valid, anchor, binding and links', r.status === 'VALID' && r.info.includes('BINDING_RECOMPUTED_OK') &&
    r.info.includes('LINK_RECOMPUTED_OK:seller_attestation'), r);
  // legacy call signature verifyRecord(record, pem, options)
  const r2 = await V.verifyRecord(text('verifier/record-valid.json'), text('verifier/demo-pub.pem'), Object.assign({ allowLegacyV02: true }, mode));
  check(tag + ' v0.2 legacy call signature (pem, no keyset)', r2.status === 'VALID' &&
    same(r2.warnings, ['LEGACY_V02_SIGNATURE_ONLY', 'NO_KEYSET_VALIDITY_NOT_CHECKED']), r2);
}

// S2: number checks do not depend on JSON.parse source-text access (fail closed without ctx.source)
{
  const orig = JSON.parse;
  JSON.parse = function (t, rev) { return orig(t, rev ? function (k, v) { return rev.call(this, k, v); } : undefined); };
  try {
    const r = await V.verifyRecord(text(tv + 'negative/number-float.json'), { keysetText: text(tv + 'keyset-demo.json') });
    check('62.0 rejected without ctx.source', r.status === 'INVALID' && same(r.errors, ['BAD_NUMBER:/decision/score']), r);
  } finally { JSON.parse = orig; }
}
// parsed objects are verified but flagged; text inputs are not
{
  const r = await V.verifyRecord(load(tv + 'valid.json'), { keyset: load(tv + 'keyset-demo.json'),
    bindingInputs: load(tv + 'binding-inputs.json'), linked: [load(tv + 'linked/content-time-record.json')] });
  check('parsed inputs give PARSED_INPUT warnings', r.status === 'VALID' && same(r.warnings.filter(w => w.startsWith('PARSED_INPUT')),
    ['PARSED_INPUT:binding_inputs', 'PARSED_INPUT:keyset', 'PARSED_INPUT:linked[0]', 'PARSED_INPUT:record']), r);
  const r2 = await V.verifyRecord(text(tv + 'valid.json'), { keysetText: text(tv + 'keyset-demo.json'),
    linked: '[' + text(tv + 'linked/content-time-record.json') + ',' + text(tv + 'negative/linked-duplicate-member.json') + ']' });
  check('linked as one text array', r2.status === 'INVALID' && same(r2.errors, ['DUPLICATE_MEMBER:linked#/1/scope']), r2);
}
// scanner unit checks (same results as verify.scan_json)
{
  const s = V.scanJson('{"a":{"b":1,"b":2},"c":[1.5,{"d":1e3}],"e~/f":1,"e~/f":9007199254740992}');
  check('scanJson pointers', JSON.stringify(s) === JSON.stringify({ dups: ['DUPLICATE_MEMBER:/a/b', 'DUPLICATE_MEMBER:/e~0~1f'],
    bad: ['BAD_NUMBER:/c/0', 'BAD_NUMBER:/c/1/d', 'BAD_NUMBER:/e~0~1f'] }), s);
  let threw = 0;
  for (const t of ['{"a":1,}', '{"a":1} x', 'NaN', '{"a":01}', '[1,]']) { try { V.scanJson(t); } catch (e) { threw++; } }
  check('scanJson rejects non-JSON', threw === 5, threw);
}

// jcs(record): link hash over the whole decision record incl. signature
const outcome = load(tv + 'example-outcome-record.json');
check('jcs(record) link hash matches', (await V.sha256Hex(V.canonicalizeBytes(load(tv + 'valid.json')))) === outcome.links[0].record_sha256.hex, null);
check('embedded vectors equal files', JSON.stringify(V.DEMO_V10.valid) === JSON.stringify(load(tv + 'valid.json')) &&
  JSON.stringify(V.DEMO_V10.wrong_key) === JSON.stringify(load(tv + 'wrong-key.json')) &&
  JSON.stringify(V.DEMO_BINDING_INPUTS) === JSON.stringify(load(tv + 'binding-inputs.json')), null);
check('embedded schemas equal files', JSON.stringify(V.RECORD_SCHEMA) === JSON.stringify(load('schema/decision-record.v1.0.schema.json')) &&
  JSON.stringify(V.KEYSET_SCHEMA) === JSON.stringify(load('schema/keyset.v1.0.schema.json')), null);
check('embedded keyset text equals .well-known file (anchor)', JSON.stringify(V.DEMO_KEYSET, null, 2) + '\n' === text('.well-known/x402-decision-keyset.json'), null);

// B1: JCS sorts keys by UTF-16 code units (U+1F600 before U+E000), same as rfc8785 in Python
check('JCS UTF-16 key order', V.canonicalizeToString({ '\ue000': 1, '\u{1F600}': 2 }) === '{"\u{1F600}":2,"\ue000":1}', null);

// v1.0.1: version shown, skipped recomputations are info only
check('verifier version 1.0.1', V.VERIFIER_VERSION === '1.0.1' && html.includes('release v1.0.1'), V.VERIFIER_VERSION);
{
  const r = await V.verifyRecord(text(tv + 'tampered.json'), { keysetText: text(tv + 'keyset-demo.json') });
  check('skip info on an INVALID record stays INVALID', r.status === 'INVALID' && same(r.errors, ['BAD_SIGNATURE']) &&
    r.info.includes('BINDING_RECOMPUTATION_SKIPPED') && r.info.includes('LINK_RECOMPUTATION_SKIPPED:seller_attestation'), r);
  const crlf = text('.well-known/x402-decision-keyset.json').replace(/\n/g, '\r\n');
  const r2 = await V.verifyRecord(text(tv + 'valid.json'), { keysetText: crlf, keysetSha256: exp.keyset_anchor_sha256 });
  check('CRLF keyset text does not match the anchor', r2.status === 'INVALID' && same(r2.errors, ['KEYSET_SHA256_MISMATCH']), r2);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
