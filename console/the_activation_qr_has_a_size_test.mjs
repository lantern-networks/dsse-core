import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {encodeQR} from './vendor/qr.js';

// Found 2026-11-08 on acceptance C: the activation screen said to scan the code with an authenticator app and
// showed no code. The QR encoder's SVG carries only a viewBox; inside the inline-block box that holds it, an SVG
// with no size of its own is drawn zero pixels wide (reproduced in headless Chrome: a white square of padding).
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

test('the encoder gives the code no size of its own, so the page must', () => {
  const svg = encodeQR('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP', 'svg', {ecc: 'medium'});
  const open = svg.slice(0, svg.indexOf('>'));
  assert.doesNotMatch(open, /\swidth=/, 'the encoder now sizes its SVG; this guard can be revisited');
});

test('the activation code is drawn at a size an authenticator app can read', () => {
  const attrs = {};
  const host = {querySelector: (sel) => (sel === 'svg' ? {setAttribute: (k, v) => { attrs[k] = v; }} : null)};
  new Function(extract(login, 'sizeActivationQR') + '; return sizeActivationQR;')()(host);
  assert.equal(attrs.width, '200');
  assert.equal(attrs.height, '200');
});

test('the activation flow sizes the code right after drawing it', () => {
  const at = login.indexOf('encodeQR(j.otpauth_uri');
  assert.ok(at > 0, 'the activation flow no longer draws the code with encodeQR');
  assert.match(login.slice(at, at + 600), /sizeActivationQR\(qrEl\)/);
});
