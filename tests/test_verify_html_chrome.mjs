// Runs verifier/verify.html in headless Chrome (real browser Web Crypto, real DOM).
// Run: node tests/test_verify_html_chrome.mjs   (CHROME=/path/to/chrome to override)
// 1) every case in test-vectors/v1.0/expected.json, default path and forced tweetnacl;
// 2) a UI smoke test: load the v1.0 examples with the buttons, set the anchor, click Verify.
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { execFileSync, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const text = p => readFileSync(join(root, p), 'utf8');
const tv = 'test-vectors/v1.0/';
const exp = JSON.parse(text(tv + 'expected.json'));
const cases = exp.cases.map(c => ({
  c,
  record: text(tv + c.record),
  keysetText: c.keyset ? text(tv + c.keyset) : null,
  binding: c.binding_inputs ? text(tv + c.binding_inputs) : null,
  linked: c.linked ? c.linked.map(p => text(tv + p)) : null,
}));
const data = JSON.stringify({ cases, anchor: exp.keyset_anchor_sha256, publishedKeyset: text(tv + 'keyset-published.json'), noncanon: text(tv + 'negative/sig-noncanonical-base64.json') })
  .replace(/</g, '\\u003c');

const harness = `<script>
(async function () {
  const D = ${data};
  const out = { cases: [], ui: [], webcrypto: null };
  const same = (a, b) => JSON.stringify([...a].sort()) === JSON.stringify(b);
  try {
    for (const mode of [{}, { forceTweetnacl: true }]) {
      for (const x of D.cases) {
        const o = Object.assign({}, mode);
        if (x.keysetText) o.keysetText = x.keysetText;
        if (x.c.keyset_sha256) o.keysetSha256 = x.c.keyset_sha256;
        if (x.binding) o.bindingInputs = x.binding;
        if (x.linked) o.linked = x.linked;
        if (x.c.allow_legacy_v02) o.allowLegacyV02 = true;
        const r = await AgentTrustVerifier.verifyRecord(x.record, o);
        if (!mode.forceTweetnacl && r.method !== 'none') out.webcrypto = out.webcrypto || r.method;
        const ok = r.status === x.c.status && same(r.errors, x.c.errors) && same(r.warnings, x.c.warnings) &&
          (x.c.info_includes || []).every(i => r.info.includes(i)) && (x.c.info_excludes || []).every(i => !r.info.includes(i)) && (!x.c.sha256 || r.sha256 === x.c.sha256);
        out.cases.push({ name: (mode.forceTweetnacl ? '[tweetnacl] ' : '[default] ') + x.c.name, ok, r: ok ? null : r });
      }
    }
    const $ = id => document.getElementById(id);
    async function ui(name, setup, want) {
      setup();
      $('verify').click();
      for (let i = 0; i < 200 && /Checking/.test($('result').textContent); i++) await new Promise(r => setTimeout(r, 10));
      const got = ($('result-status') || {}).textContent;
      out.ui.push({ name, ok: got === want, got, detail: $('result').textContent });
    }
    await ui('page default record (v1.0 valid)', () => {}, 'VALID');
    await ui('v1.0 valid button + published keyset and anchor', () => {
      $('load-v10-valid').click(); $('keyset').value = D.publishedKeyset; $('anchor').value = D.anchor;
    }, 'VALID');
    await ui('v1.0 valid, wrong anchor', () => {
      $('load-v10-valid').click(); $('keyset').value = D.publishedKeyset; $('anchor').value = '00'.repeat(32);
    }, 'INVALID');
    await ui('v1.0 tampered button', () => { $('load-v10-tampered').click(); $('anchor').value = ''; }, 'INVALID');
    await ui('v1.0 wrong-key button', () => { $('load-v10-wrong-key').click(); }, 'INVALID');
    await ui('v1.0 expired-key button', () => { $('load-v10-expired-key').click(); }, 'INVALID');
    await ui('pasted non-canonical signature', () => { $('load-v10-valid').click(); $('record').value = D.noncanon; }, 'INVALID');
    await ui('duplicate member in the binding field', () => { $('load-v10-valid').click();
      $('binding').value = $('binding').value.replace('"amount": "4500000"', '"amount": "1", "amount": "4500000"'); }, 'INVALID');
    out.ui.push({ name: 'binding duplicate reported', ok: (($('result-errors') || {}).textContent || '').includes('DUPLICATE_MEMBER:binding_inputs#/payment_requirements/amount'), got: $('result').textContent });
    await ui('v1.0 valid without binding or linked inputs', () => { $('load-v10-valid').click(); $('binding').value = ''; $('linked').value = ''; }, 'VALID');
    out.ui.push({ name: 'skipped recomputations shown as info', ok: /BINDING_RECOMPUTATION_SKIPPED/.test(($('result-info') || {}).textContent || '') &&
      /LINK_RECOMPUTATION_SKIPPED:seller_attestation/.test(($('result-info') || {}).textContent || '') && !$('result-warnings'), got: $('result').textContent });
    out.ui.push({ name: 'page shows release v1.0.1', ok: /release v1\.0\.1/.test(document.body.textContent) && AgentTrustVerifier.VERIFIER_VERSION === '1.0.1', got: AgentTrustVerifier.VERIFIER_VERSION });
    await ui('v0.2 valid button', () => { $('load-valid').click(); $('binding').value = ''; $('linked').value = ''; }, 'VALID');
    await ui('v0.2 tampered button', () => { $('load-tampered').click(); }, 'INVALID');
    await ui('v0.2 valid without the legacy box', () => { $('load-valid').click(); $('allow-legacy').checked = false; }, 'INVALID');
    await ui('v0.2 legacy result says signature only', () => { $('load-valid').click(); }, 'VALID');
    out.ui.push({ name: 'v0.2 legacy warnings shown', ok: /LEGACY_V02_SIGNATURE_ONLY/.test(($('result-warnings') || {}).textContent || ''), got: $('result').textContent });
  } catch (e) { out.error = String(e && e.stack || e); }
  const pre = document.createElement('pre'); pre.id = 'harness-out';
  pre.textContent = 'HARNESS:' + JSON.stringify(out) + ':END';
  document.body.appendChild(pre);
})();
</script>`;

const html = text('verifier/verify.html');
const dir = mkdtempSync(join(tmpdir(), 'xdr-chrome-'));
const page = join(dir, 'verify-harness.html');
writeFileSync(page, html.replace('</body>', harness + '\n</body>'));
const chrome = process.env.CHROME || ['/opt/google/chrome/chrome', 'google-chrome', 'chromium', 'chromium-browser'].find(b => {
  try { execFileSync('which', [b], { stdio: 'ignore' }); return true; } catch { return false; }
});
// Drive Chrome over the DevTools protocol (more robust than --dump-dom in sandboxes).
const proc = spawn(chrome, ['--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run', '--no-default-browser-check',
  `--user-data-dir=${join(dir, 'profile')}`, '--remote-debugging-port=0', 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
let dom = '';
try {
  const wsUrl = await new Promise((resolve, reject) => {
    let buf = '';
    const t = setTimeout(() => reject(new Error('Chrome did not start')), 30000);
    proc.stderr.on('data', d => { buf += d; const mm = buf.match(/DevTools listening on (ws:\/\/[^\s]+)/); if (mm) { clearTimeout(t); resolve(mm[1]); } });
    proc.on('exit', c => reject(new Error('Chrome exited ' + c)));
  });
  const port = new URL(wsUrl).port;
  const target = await (await fetch(`http://127.0.0.1:${port}/json/new?${encodeURI('file://' + page)}`, { method: 'PUT' })).json();
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  let id = 0; const pending = new Map();
  ws.onmessage = ev => { const msg = JSON.parse(ev.data); if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); } };
  const send = (method, params) => new Promise(res => { const i = ++id; pending.set(i, res); ws.send(JSON.stringify({ id: i, method, params })); });
  const deadline = Date.now() + 120000;
  while (Date.now() < deadline) {
    const r = await send('Runtime.evaluate', { expression: "(document.getElementById('harness-out')||{}).textContent||''", returnByValue: true });
    dom = (r.result && r.result.result && r.result.result.value) || '';
    if (dom) break;
    await new Promise(r => setTimeout(r, 250));
  }
  ws.close();
} finally {
  proc.kill('SIGKILL');
  await new Promise(r => setTimeout(r, 300));
  rmSync(dir, { recursive: true, force: true });
}
const m = dom.match(/HARNESS:([\s\S]*?):END/);
if (!m) { console.log('FAIL harness produced no output'); process.exit(1); }
const out = JSON.parse(m[1]);
let pass = 0, fail = 0;
for (const x of [...out.cases, ...out.ui]) {
  if (x.ok) { pass++; console.log('ok   ' + x.name); }
  else { fail++; console.log('FAIL ' + x.name + ' ' + JSON.stringify(x.r || x.got || '') + ' ' + (x.detail || '')); }
}
if (out.error) { fail++; console.log('FAIL harness error ' + out.error); }
if (out.webcrypto !== 'webcrypto') { fail++; console.log('FAIL default path did not use Web Crypto: ' + out.webcrypto); }
console.log(`\nchrome: ${pass} passed, ${fail} failed (default path: ${out.webcrypto})`);
process.exit(fail ? 1 : 0);
