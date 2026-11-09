import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

// The time-limited permission dialog names the act in the reader's language. It used to show the Edge list's
// own English argument ("why") inside the Japanese sentence (2026-11-04, acceptance A, third run).
const app = readFileSync(new URL('./app.js', import.meta.url), 'utf8');
const goList = readFileSync(new URL('../cmd/dsse-edge/operator_elevated_acts.go', import.meta.url), 'utf8');

function edgeActs() {
  const start = goList.indexOf('var operatorElevatedActs = []operatorElevatedAct{');
  assert.ok(start >= 0, 'the elevated list moved');
  const body = goList.slice(start, goList.indexOf('\n}\n', start));
  const methods = {MethodPost: 'POST', MethodDelete: 'DELETE', MethodPut: 'PUT', MethodPatch: 'PATCH'};
  return [...body.matchAll(/Method:\s*http\.(Method[A-Za-z]+),\s*Path:\s*"([^"]+)"/g)].map((m) => methods[m[1]] + ' ' + m[2]);
}

function consoleLabels() {
  const start = app.indexOf('const ELEVATED_ACT_LABELS = {');
  assert.ok(start >= 0, 'the label table moved');
  const body = app.slice(start, app.indexOf('\n};\n', start));
  const out = {};
  for (const m of body.matchAll(/^\s*"([A-Z]+ \/[^"]+)":\s*\{\s*en:\s*"([^"]+)",\s*ja:\s*"([^"]+)"\s*\},?$/gm)) out[m[1]] = {en: m[2], ja: m[3]};
  return out;
}

test('every act on the Edge list has a label in both languages, and nothing else does', () => {
  const acts = edgeActs();
  assert.ok(acts.length >= 20, 'the scan found ' + acts.length + ' acts');
  const labels = consoleLabels();
  assert.deepEqual(acts.filter((a) => !labels[a]), [], 'acts without a label');
  assert.deepEqual(Object.keys(labels).filter((k) => !acts.includes(k)), [], 'labels for acts no longer on the list');
  for (const [k, v] of Object.entries(labels)) assert.doesNotMatch(v.ja, /^[ -~]+$/, k + ' has no Japanese');
});

test('the dialog names the act, not the list argument', () => {
  const start = app.indexOf('async function offerOperatorElevation(');
  const dialog = app.slice(start, app.indexOf('confirmLabel:', start));
  assert.match(dialog, /elevatedActText\(need\)/);
  assert.doesNotMatch(dialog, /need\.why/);
});

test('the Edge key is method and path as the list writes them', () => {
  assert.match(goList, /return strings\.ToUpper\(a\.Method\) \+ " " \+ a\.Path/);
});

test('the dialog names the organization by its name, not its tenant ID', async () => {
  const vm = await import('node:vm');
  const start = app.indexOf('function elevationOrganizationName(');
  assert.ok(start >= 0, 'the name helper moved');
  const fn = app.slice(start, app.indexOf('\n}\n', start) + 2);
  const run = (operating, operateTenant, need) => {
    const ctx = vm.createContext({operatingOrganizationName: operating, operateTenant});
    vm.runInContext(fn + '\n;globalThis.__r = elevationOrganizationName(' + JSON.stringify(need) + ');', ctx);
    return ctx.__r;
  };
  assert.equal(run('Acceptance B', 'tenant_x', {tenant_id: 'tenant_x'}), 'Acceptance B');
  assert.equal(run('Acceptance B', 'tenant_x', {}), 'Acceptance B');
  // Another organization than the one on screen: its ID is all the refusal carries, so it is not renamed.
  assert.equal(run('Acceptance B', 'tenant_x', {tenant_id: 'tenant_y'}), 'tenant_y');
  const dialog = app.slice(app.indexOf('async function offerOperatorElevation('), app.indexOf('confirmLabel:', app.indexOf('async function offerOperatorElevation(')));
  assert.match(dialog, /const org = elevationOrganizationName\(need\);/);
});
