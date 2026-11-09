import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

// 0.4.1 acceptance B rerun: the provider test read "reachable, 2 RSA key(s)" and "issuer matches, endpoints agree"
// on a Japanese screen. The Edge now sends a code; the screen says it in the reader's language.
const idp = readFileSync(new URL('./idp.js', import.meta.url), 'utf8');
const start = idp.indexOf('const IDP_CHECK_NAMES = {');
const end = idp.indexOf('\n}\n', idp.indexOf('function idpCheckDetail(')) + 3;

function said(lang, check) {
  const ctx = { bl: (m) => m[lang] };
  vm.runInNewContext(idp.slice(start, end) + '\nglobalThis.out = JSON.stringify([idpCheckName(' + JSON.stringify(check) + '), idpCheckDetail(' + JSON.stringify(check) + ')]);', ctx);
  return JSON.parse(ctx.out);
}

test('the checks a working provider passes read in Japanese', () => {
  assert.deepEqual(said('ja', { name: 'jwks', ok: true, code: 'jwks_ok', rsa_keys: 2, detail: 'reachable, 2 RSA key(s)' }),
    ['署名鍵（JWKS）', '届きました。RSA の鍵 2 本']);
  assert.deepEqual(said('ja', { name: 'discovery', ok: true, code: 'issuer_matches', detail: 'issuer matches, endpoints agree' }),
    ['OpenID の設定情報', '発行者もエンドポイントも一致しました']);
});

test('every code the Edge writes has a phrase, and an unknown one keeps the sentence', () => {
  const go = readFileSync(new URL('../cmd/dsse-edge/idp_connection_check.go', import.meta.url), 'utf8');
  // Every outcome code is named for the check it belongs to; the endpoint names in Differ are not outcomes.
  const endpoints = new Set(['jwks_uri', 'token_endpoint', 'authorization_endpoint']);
  const codes = new Set([...go.matchAll(/"((?:jwks|issuer|discovery|ca)_[a-z_]+)"/g)].map((m) => m[1]).filter((c) => !endpoints.has(c)));
  assert.ok(codes.size >= 7, 'found only ' + [...codes].join(', '));
  for (const code of codes) {
    const [, detail] = said('ja', { name: 'jwks', code, rsa_keys: 1, detail: 'SENTENCE' });
    assert.notEqual(detail, 'SENTENCE', code + ' has no phrase');
  }
  assert.equal(said('ja', { name: 'x', code: 'something_new', detail: 'SENTENCE' })[1], 'SENTENCE');
});
