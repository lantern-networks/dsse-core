import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

// Acceptance C (2026-11-07): the connector was installed on another machine while the Add connector dialog was
// open, and the Sites list behind it did not show it online until a manual reload. Closing reads it again.
const src = readFileSync(new URL('./sites.js', import.meta.url), 'utf8');

test('every way into the Add connector dialog hands it the list to read again', () => {
  const calls = [...src.matchAll(/showEnrollmentCommand\(([^)]*)\)/g)].map((m) => m[1]).filter((a) => !a.startsWith('siteID, listHost'));
  assert.ok(calls.length >= 2, 'expected the list button and the detail button');
  for (const args of calls) assert.match(args, /,\s*host$/, `caller passes no list: showEnrollmentCommand(${args})`);
});

test('closing the dialog reads the list again', () => {
  const start = src.indexOf('async function showEnrollmentCommand(siteID, listHost)');
  assert.ok(start >= 0);
  const head = src.slice(start, start + 1200);
  assert.match(head, /onClose: \(\) => \{ if \(listHost && listHost\.isConnected !== false\) renderSiteList\(listHost\); \}/);
});
