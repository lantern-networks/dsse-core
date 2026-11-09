import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

// Found on a three-region acceptance (2026-11-06): the connector list and detail showed "healthy" and
// "registered" on a Japanese screen. Every state the Edge writes for a connector has a label in both languages.
const ui = readFileSync(new URL('./ui.js', import.meta.url), 'utf8');
const source = readFileSync(new URL('./connectors.js', import.meta.url), 'utf8');
const start = ui.indexOf('const UI_CONNECTOR_STATUS_LABELS = {');
const end = ui.indexOf('\n}\n', ui.indexOf('function uiConnectorStatusLabel(')) + 2;
function label(lang, status) {
  const ctx = vm.createContext({lang});
  vm.runInContext('function bl(o){return (o && (o[lang] || o.en)) || "";}\n' + ui.slice(start, end) +
    '\n;globalThis.__r = uiConnectorStatusLabel(' + JSON.stringify(status) + ');', ctx);
  return ctx.__r;
}

test('the states a connector shows are in the reader language', () => {
  assert.equal(label('ja', 'healthy'), '正常');
  assert.equal(label('ja', 'registered'), '登録済み');
  assert.equal(label('ja', ''), '不明');
  assert.equal(label('en', 'healthy'), 'Healthy');
  assert.equal(label('ja', 'something_new'), 'something_new');
});

test('every connector state the Edge writes has a label', () => {
  const edge = readFileSync(new URL('../cmd/dsse-edge/connector_reachability.go', import.meta.url), 'utf8');
  for (const m of edge.matchAll(/Status:\s*"([a-z_]+)"/g)) {
    assert.match(ui.slice(start, end), new RegExp('\\b' + m[1] + ':'), m[1] + ' has no label');
  }
});

test('the list, the detail and the log all use the label', () => {
  assert.equal((source.match(/uiBadge\(uiConnectorStatusLabel\(/g) || []).length, 2);
  const log = readFileSync(new URL('./logsaudit.js', import.meta.url), 'utf8');
  const cell = log.slice(log.indexOf('function laConnectorStatusCell('), log.indexOf('\n}\n', log.indexOf('function laConnectorStatusCell(')));
  assert.match(cell, /uiConnectorStatusLabel\(status\)/);
});
