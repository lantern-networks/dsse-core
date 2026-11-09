import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';

// The sign-in page must say "invalid credentials" only when the credential was refused. A 502 from the
// Console's own upstream means the password was never checked (2026-11-04: an administrator retyped a correct
// password because the page said it was wrong).
const loginSource = readFileSync(new URL('./login.js', import.meta.url), 'utf8')
  .replace(/^import .*$/m, '');
const i18nSource = readFileSync(new URL('./i18n.js', import.meta.url), 'utf8');

function load() {
  const context = {
    window: {},
    localStorage: {getItem: () => null, setItem() {}, removeItem() {}},
    document: {addEventListener() {}},
  };
  vm.createContext(context);
  vm.runInContext(i18nSource, context);
  vm.runInContext(loginSource + '\nglobalThis.__login = {signInRefusal, useLang: (l) => { lang = l; }};', context);
  return context.__login;
}

const reply = (status, body) => ({
  ok: false, status,
  json: async () => { if (body === undefined) throw new Error('no body'); return body; },
});

test('a refused credential is reported as invalid credentials', async () => {
  const login = load();
  assert.equal(await login.signInRefusal(reply(401, {error: 'invalid credentials'})), 'Invalid credentials.');
  assert.equal(await login.signInRefusal(reply(400, {error: 'invalid request body'})), 'Invalid credentials.');
});

test('an unreachable upstream is not reported as a wrong password', async () => {
  const login = load();
  for (const status of [500, 502, 503, 504]) {
    const message = await login.signInRefusal(reply(status));
    assert.doesNotMatch(message, /Invalid credentials/);
    assert.match(message, new RegExp(`HTTP ${status}`));
    assert.match(message, /could not be completed/);
    // A 5xx can come after the password was checked (a failed challenge or session issue), so the message
    // does not say which stage failed (2026-11-05).
    assert.doesNotMatch(message, /password/i);
  }
  login.useLang('ja');
  const ja = await login.signInRefusal(reply(502));
  assert.doesNotMatch(ja, /認証情報が正しくありません/);
  assert.match(ja, /HTTP 502/);
  assert.doesNotMatch(ja, /パスワード/);
});

test('a refusal with its own reason shows that reason', async () => {
  const login = load();
  const reason = 'this organization is no longer active — contact your operator';
  assert.equal(await login.signInRefusal(reply(403, {error: reason})), reason);
  assert.match(await login.signInRefusal(reply(429)), /HTTP 429/);
});
