// Headless test of the JavaScript inside verifier/verify.html (example data).
// Run: node tests/test_verify_html.mjs
// Runs every vector through both the Web Crypto path and the inlined tweetnacl path.
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

const load = p => JSON.parse(readFileSync(join(root, p), 'utf8'));
const tv = 'test-vectors/v0.3/';
const keyset = load(tv + 'keyset-demo.json');
const revoked = load(tv + 'keyset-revoked.json');
const binding = load(tv + 'binding-inputs.json');
const pem = readFileSync(join(root, 'verifier/demo-pub.pem'), 'utf8');

let pass = 0, fail = 0;
function check(name, cond, detail) {
  if (cond) { pass++; console.log('ok   ' + name); }
  else { fail++; console.log('FAIL ' + name + ' ' + JSON.stringify(detail)); }
}

for (const mode of [{ forceWebCrypto: true }, { forceTweetnacl: true }]) {
  const tag = mode.forceWebCrypto ? '[webcrypto]' : '[tweetnacl]';
  // v0.2 legacy call signature
  let r = await V.verifyRecord(load('verifier/record-valid.json'), pem, mode);
  check(tag + ' v0.2 valid', r.status === 'VALID' && r.sha256 === 'f3a1e3138054d02beac297c4024b82510aceb5507ef4af9b803670f1738435f0', r);
  r = await V.verifyRecord(load('verifier/record-tampered.json'), pem, mode);
  check(tag + ' v0.2 tampered', r.status === 'INVALID', r);

  const exp = load(tv + 'expected.json');
  for (const [name, want] of Object.entries(exp)) {
    if (name.startsWith('_')) continue;
    const [recName, ksName] = name.split('+');
    const ks = ksName ? load(tv + ksName) : keyset;
    r = await V.verifyRecord(load(tv + recName), Object.assign({ keyset: ks, bindingInputs: binding }, mode));
    check(tag + ' v0.3 ' + name, r.status === want.status && (!want.reason || r.errors.includes(want.reason)), r);
  }
  // embedded copies in the page equal the files
  r = await V.verifyRecord(V.DEMO_V03.valid, Object.assign({ keyset: V.DEMO_KEYSET, bindingInputs: V.DEMO_BINDING_INPUTS }, mode));
  check(tag + ' embedded v0.3 valid', r.status === 'VALID' && r.info.includes('BINDING_RECOMPUTED_OK'), r);
  r = await V.verifyRecord(load(tv + 'valid.json'), Object.assign({ keyset: revoked }, mode));
  check(tag + ' revoked keyset', r.status === 'INVALID' && r.errors.includes('KEY_REVOKED'), r);
  const bad = JSON.parse(JSON.stringify(binding)); bad.authorization_nonce = '0x' + '00'.repeat(32);
  r = await V.verifyRecord(load(tv + 'valid.json'), Object.assign({ keyset, bindingInputs: bad }, mode));
  check(tag + ' wrong nonce', r.status === 'INVALID' && r.errors.includes('BINDING_HASH_MISMATCH:eip3009-nonce-bytes32'), r);
  r = await V.verifyRecord(load(tv + 'valid.json'), Object.assign({ keyset }, mode));
  check(tag + ' custom check id is info only', r.status === 'VALID' && r.info.includes('CUSTOM_CHECK_ID:x-polkulab.sanctions_list'), r);
  const sol = load(tv + 'valid.json'); sol.payment.network = 'solana:mainnet';
  r = await V.verifyRecord(sol, Object.assign({ keyset }, mode));
  check(tag + ' non-EVM network rejected', r.errors.includes('UNSUPPORTED_NETWORK:solana:mainnet'), r);
  const unk = load(tv + 'valid.json'); unk.checks[0].id = 'some.future_check';
  r = await V.verifyRecord(unk, Object.assign({ keyset }, mode));
  check(tag + ' unknown check id not an error', r.info.includes('UNKNOWN_CHECK_ID:some.future_check') && !r.errors.some(e => e.includes('CHECK_ID')), r);
}
// jcs(record): link hash over the whole decision record incl. signature
const outcome = load(tv + 'example-outcome-record.json');
check('jcs(record) link hash matches', (await V.sha256Hex(V.canonicalizeBytes(load(tv + 'valid.json')))) === outcome.links[0].record_sha256.hex, null);
check('embedded vectors equal files', JSON.stringify(V.DEMO_V03.valid) === JSON.stringify(load(tv + 'valid.json')) &&
  JSON.stringify(V.DEMO_V03.wrong_key) === JSON.stringify(load(tv + 'wrong-key.json')), null);

// Python and JS must agree on canonical bytes
const valid = load(tv + 'valid.json'); delete valid.signature;
check('JCS sha256 matches embedded', (await V.sha256Hex(V.canonicalizeBytes(valid))) === load(tv + 'valid.json').signature.sha256, null);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
