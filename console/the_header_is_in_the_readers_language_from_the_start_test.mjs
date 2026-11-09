import {readFileSync} from 'node:fs';
import test from 'node:test';
import assert from 'node:assert/strict';

// Acceptance C, third walk: the header read "Admin Console · Operating as · Sign out" in English for the length
// of two network reads after sign-in, then turned Japanese. The fixed text is translated before the layout is
// shown and before the session check, neither of which needs the network.
test('the fixed header is translated before the layout appears and before the session check', () => {
  const src = readFileSync(new URL('./app.js', import.meta.url), 'utf8');
  const show = src.indexOf('document.getElementById("console-layout").style.display = ""');
  const session = src.indexOf('const signedIn = await ensureSignedIn();');
  assert.ok(show > 0 && session > 0);
  const beforeShow = src.lastIndexOf('applyStaticI18n();', show);
  const beforeSession = src.lastIndexOf('applyStaticI18n();', session);
  assert.ok(beforeShow > session && beforeShow < show, 'the header is translated after sign-in, before the layout is shown');
  assert.ok(beforeSession > 0 && session - beforeSession < 200, 'the session-check text is translated before the check');
  const entitlements = src.indexOf('apiFetch("GET", "/admin/entitlements")');
  assert.ok(entitlements > show, 'no network read stands between showing the layout and its text');
  const fn = src.slice(src.indexOf('function applyStaticI18n()'), src.indexOf('function applyI18n()'));
  assert.match(fn, /querySelectorAll\("\[data-i18n\]"\)/);
  assert.doesNotMatch(fn, /apiFetch|await/);
});
