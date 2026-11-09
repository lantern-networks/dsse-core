import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, readdirSync} from 'node:fs';
import vm from 'node:vm';

// Every event name the Edge writes by name has a label on the log screen. An unlabelled one is spelled out
// from its code ("Connector connected") — English on a Japanese page, on the row the reader came to read.
const source = readFileSync(new URL('./logsaudit.js', import.meta.url), 'utf8');
const context = vm.createContext({});
vm.runInContext(source + '\n;globalThis.__events = _LA_EVENT;', context);
const labelled = context.__events;

const edgeDir = new URL('../cmd/dsse-edge/', import.meta.url);
const emitted = new Set();
for (const name of readdirSync(edgeDir)) {
  if (!name.endsWith('.go') || name.endsWith('_test.go')) continue;
  const text = readFileSync(new URL(name, edgeDir), 'utf8');
  for (const m of text.matchAll(/\beventType\s*:?=\s*"([a-z_]+)"|\bconnectorAudit\("([a-z_]+)"/g)) {
    const code = m[1] || m[2];
    if (code.endsWith('_')) continue; // a prefix completed at run time, not a name
    emitted.add(code);
  }
}

test('the scan finds the connector rows it exists for', () => {
  for (const code of ['connector_connected', 'connector_reconnect', 'connector_disconnected']) {
    assert.ok(emitted.has(code), code);
  }
});

test('every event name the Edge writes has a label in both languages', () => {
  const missing = [...emitted].filter((code) => !(labelled[code] && labelled[code].en && labelled[code].ja));
  assert.deepEqual(missing, []);
});
