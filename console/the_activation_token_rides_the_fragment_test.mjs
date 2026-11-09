import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

// Review R4 (2026-11-07): the API moved to a POST body, but the emailed link still put the token in the query
// string, so the very first page request carried it to every log on the way. The link now uses the fragment,
// which a browser never sends, and the page reads it from there.
const login = readFileSync(new URL('./login.js', import.meta.url), 'utf8');

function extract(src, name) {
  const start = src.indexOf('function ' + name + '(');
  let depth = 0, i = src.indexOf('{', start);
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) break;
  }
  return src.slice(start, i + 1);
}

test('the token is read from the fragment and never from the query string', () => {
  const fn = new Function('URLSearchParams', extract(login, 'activationTokenFromLocation') + '; return activationTokenFromLocation;')(URLSearchParams);
  assert.equal(fn({ hash: '#activate=abc123', search: '' }), 'abc123');
  assert.equal(fn({ hash: '', search: '?activate=abc123' }), '');
  assert.equal(fn({ hash: '#lang=ja', search: '' }), '');
});

test('the page drops the fragment from the address bar once it has the token', () => {
  const body = extract(login, 'initActivationFromURL');
  assert.match(body, /history\.replaceState\(null, "", window\.location\.pathname \+ window\.location\.search\)/);
  assert.doesNotMatch(body, /location\.search\)\.get\("activate"\)/);
});
