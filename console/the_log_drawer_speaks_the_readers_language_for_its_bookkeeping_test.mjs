import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

// Acceptance C (2026-11-07): the drawer's "Other" section showed record keys (tenant_id, edge_region_id, …)
// and the actor type as "human"; organization status and two dates were raw.
const la = readFileSync(new URL('./logsaudit.js', import.meta.url), 'utf8');
for (const key of ['id', 'tenant_id', 'config_generation_id', 'access_decision_id', 'edge_region_id', 'edge_cluster_id', 'connector_id', 'timestamp']) {
  test(`the drawer labels ${key}`, () => assert.match(la, new RegExp(`^\\s*${key}: \\{ en: "[^"]+", ja: "[^"]+" \\}`, 'm')));
}
test('the actor type is said in words, and times go through the shared formatter', () => {
  assert.match(la, /human: \{ en: "Person", ja: "人" \}/);
  assert.match(la, /_LA_TIME_FIELDS\.has\(k\)[^\n]*window\.dsseFormatTime\(v\)/);
});
test('organization status, operator sign-in time and internal CA expiry are not shown raw', () => {
  assert.match(readFileSync(new URL('./operatorhome.js', import.meta.url), 'utf8'), /orgStatusLabel\(t\.status\)/);
  assert.match(readFileSync(new URL('./operators.js', import.meta.url), 'utf8'), /window\.dsseFormatTime\(a\.last_login_at\)/);
  assert.match(readFileSync(new URL('./internalcas.js', import.meta.url), 'utf8'), /window\.dsseFormatTime\(a\.not_after\)/);
});
