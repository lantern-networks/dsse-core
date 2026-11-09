import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, readdirSync} from 'node:fs';
import vm from 'node:vm';

// Found 2026-11-07 on the three-region acceptance rerun: the connector-access banner read its mode from an Edge
// right after the mode was written to the control plane, so every tab showed the old mode until reloaded. The
// fix of 2026-11-04 had listed its pairs by hand, and this pair was not on the list. So this derives the pairs
// from the screens: every literal GET a screen makes of a path that is also a control-plane write.
const dir = new URL('.', import.meta.url);
const app = readFileSync(new URL('./app.js', dir), 'utf8');
const context = {};
vm.runInNewContext(app.slice(app.indexOf('const CP_AUTHORED_WRITES = ['), app.indexOf('function baseForPlane')) +
  '\nglobalThis.cpAuthoritative = cpAuthoritative; globalThis.writes = CP_AUTHORED_WRITES;', context);

function literalReads() {
  const reads = new Map();
  const note = (path, name) => { if (!reads.has(path)) reads.set(path, new Set()); reads.get(path).add(name); };
  for (const name of readdirSync(dir).filter((f) => f.endsWith('.js'))) {
    const src = readFileSync(new URL('./' + name, dir), 'utf8');
    for (const m of src.matchAll(/apiFetch\(\s*"GET"\s*,\s*"(\/admin\/[^"?]+)(?:\?[^"]*)?"/g)) note(m[1], name);
    // A read of one object by id: "/admin/things/" + encodeURIComponent(id) + "/part". Review of 2026-11-07, R3:
    // the list of applications was moved and its detail was not, and only the literal reads were being checked.
    for (const m of src.matchAll(/apiFetch\(\s*"GET"\s*,\s*"(\/admin\/[^"]*\/)"\s*\+\s*encodeURIComponent\([^)]*\)\s*(?:\+\s*"([^"]*)")?([^)]*)\)/g)) {
      // A call that names the control plane itself is already read there.
      if (/"control"/.test(m[3] || '')) continue;
      note(m[1] + '{id}' + (m[2] || ''), name);
    }
  }
  return reads;
}

// A write entry covers a read of the same object: "POST /admin/things" covers "/admin/things/{id}", and a write
// with its own {id} covers the read with that shape.
function writtenTo(written, path) {
  if (written.has(path)) return true;
  const object = path.replace(/\/\{id\}.*$/, '');
  return object !== path && written.has(object);
}

test('a screen reads back from the control plane what it writes there', () => {
  const written = new Set(context.writes.map((e) => e.slice(e.indexOf(' ') + 1)));
  const reads = literalReads();
  assert.ok(reads.size > 20, 'the scan found almost no reads — it no longer matches how the screens call apiFetch');
  const wrong = [];
  for (const [path, where] of reads) {
    if (writtenTo(written, path) && !context.cpAuthoritative('GET', path.replace(/\{id\}/g, 'x'))) wrong.push(path + ' (' + [...where].join(', ') + ')');
  }
  assert.deepEqual(wrong, [], 'read from an Edge, which has a write to the control plane only after its next pull');
});

test('the detail an edit is built on is read where the save goes', () => {
  assert.equal(context.cpAuthoritative('GET', '/admin/applications/app-1'), true);
  assert.equal(context.cpAuthoritative('GET', '/admin/sites/site-1'), true);
});

test('the connector-access banner reads its mode where the mode is written', () => {
  assert.equal(context.cpAuthoritative('POST', '/admin/east-west'), true);
  assert.equal(context.cpAuthoritative('GET', '/admin/east-west'), true);
});

// Found 2026-11-08 on acceptance C: "Revoke" on an access approval went to an Edge, which refused it, and every
// attempt failed. The approval is revoked where it is held, and the list is read from there too.
test('an access approval is revoked, and listed, on the control plane', () => {
  assert.equal(context.cpAuthoritative('POST', '/admin/grants/g-1/revoke'), true);
  assert.equal(context.cpAuthoritative('GET', '/admin/grants'), true);
});
