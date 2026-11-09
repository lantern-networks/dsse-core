import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

// 0.4.1 acceptance B rerun: the device configuration's "left uninspected" list and the organization list showed
// English and codes on a Japanese screen.
const read = (name) => readFileSync(new URL(name, import.meta.url), 'utf8');

test('every entry of the built-in catalogue is named in both languages', () => {
  const go = read('../knownbypass/knownbypass.go');
  const names = [...go.matchAll(/\bName:\s*"([a-z0-9_]+)"/g)].map((m) => m[1]);
  assert.ok(names.length >= 15, 'the scan found almost no catalogue entries');
  const src = read('./agentprofile.js');
  const table = src.slice(src.indexOf('const PROFILE_BYPASS_NAMES = {'), src.indexOf('\n};\n', src.indexOf('const PROFILE_BYPASS_NAMES = {')) + 3);
  const ctx = {};
  vm.runInNewContext(table + '\nglobalThis.t = PROFILE_BYPASS_NAMES;', ctx);
  const missing = names.filter((n) => !(ctx.t[n] && ctx.t[n].en && ctx.t[n].ja));
  assert.deepEqual(missing, []);
});

test('the profile names an entry from that table, and one it does not know from its description', () => {
  const src = read('./agentprofile.js');
  const start = src.indexOf('const PROFILE_NOT_SENTENCE_END');
  const end = src.indexOf('\n}\n', src.indexOf('function profileBypassLabel(')) + 3;
  const ctx = { bl: (m) => m.ja };
  vm.runInNewContext(src.slice(start, end) + '\nglobalThis.a = profileBypassLabel({ name: "apple_push", description: "Apple Push (APNs)" });' +
    '\nglobalThis.b = profileBypassLabel({ name: "fed_new", description: "Something new. With detail." });', ctx);
  assert.equal(ctx.a, 'Apple のプッシュ通知（APNs）');
  assert.equal(ctx.b, 'Something new');
});

test('the organization list says the state in the reader\'s language, from the same table as the editor', () => {
  const src = read('./organizations.js');
  assert.match(src, /uiBadge\(orgStatusLabel\(t2\.status\)/);
  assert.match(src, /options: Object\.keys\(ORG_STATUS_LABELS\)\.map/);
  const start = src.indexOf('const ORG_STATUS_LABELS = {');
  const end = src.indexOf('\n', src.indexOf('function orgStatusLabel(')) + 1;
  const ctx = { bl: (m) => m.ja };
  vm.runInNewContext(src.slice(start, end) + '\nglobalThis.a = orgStatusLabel("active"); globalThis.b = orgStatusLabel(""); globalThis.c = orgStatusLabel("new_state");', ctx);
  assert.deepEqual([ctx.a, ctx.b, ctx.c], ['有効', '有効', 'new_state']);
});
