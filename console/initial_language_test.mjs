import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

// 0.4.1 acceptance B rerun: each region's Console is its own site to the browser, so a reader who chose Japanese
// on one met English on the next. Without a choice, the browser's language preference decides.
const i18n = readFileSync(new URL('./i18n.js', import.meta.url), 'utf8');

function initial(saved, languages) {
  const ctx = { window: {}, localStorage: { getItem: () => saved }, navigator: { languages, language: languages[0] } };
  vm.runInNewContext(i18n, ctx);
  return ctx.window.dsseInitialLang();
}

test('a choice already made on this Console stands', () => {
  assert.equal(initial('en', ['ja-JP']), 'en');
  assert.equal(initial('ja', ['en-US']), 'ja');
});

test("without one, the browser's preference decides, in its order", () => {
  assert.equal(initial(null, ['ja-JP', 'en-US']), 'ja');
  assert.equal(initial(null, ['en-US', 'ja']), 'en');
  assert.equal(initial(null, ['fr-FR', 'ja']), 'ja');
  assert.equal(initial(null, ['fr-FR']), 'en');
});

test('both the sign-in page and the Console start from it', () => {
  for (const name of ['app.js', 'login.js']) {
    const src = readFileSync(new URL('./' + name, import.meta.url), 'utf8');
    assert.match(src, /let lang = \(typeof window !== "undefined" && window\.dsseInitialLang\) \? window\.dsseInitialLang\(\)/, name);
  }
});
