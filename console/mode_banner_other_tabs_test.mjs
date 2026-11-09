import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

// A connector-access mode change made in one tab reaches the other tabs of the same browser, and a tab that
// comes back into view reads the mode again (2026-11-06: another tab still showed "observe" until reloaded).
const app = readFileSync(new URL('./app.js', import.meta.url), 'utf8');

test('a successful change is announced to the other tabs', () => {
  const fn = app.slice(app.indexOf('async function setEastWestMode('), app.indexOf('\n}\n', app.indexOf('async function setEastWestMode(')));
  assert.match(fn, /else \{\s*announceModeChangeToOtherTabs\(\);/);
});

test('the other tabs and a tab coming back into view read the mode again', () => {
  assert.match(app, /window\.addEventListener\("storage", \(e\) => \{ if \(e && e\.key === MODE_CHANGED_KEY\) refreshModeBanner\(\); \}\);/);
  assert.match(app, /document\.addEventListener\("visibilitychange", \(\) => \{ if \(document\.visibilityState === "visible"\) refreshModeBanner\(\); \}\);/);
});
