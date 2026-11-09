import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

// 0.4.1 acceptance B rerun: an operator inside an organization set to Asia/Tokyo read its logs in UTC, the zone of
// the operator's own organization. This runs the code that adopts the operated organization's clock.
const app = readFileSync(new URL('./app.js', import.meta.url), 'utf8');
const start = app.indexOf('async function adoptOperatedOrganizationClock()');
const fn = app.slice(start, app.indexOf('\n}\n', start) + 3);

async function adopt(operateTenant, answer) {
  const ctx = { operateTenant, window: { dsseTenantTimezone: 'UTC' }, calls: [],
    apiFetch: async (...a) => { ctx.calls.push(a); return answer; } };
  vm.runInNewContext(fn + '\nglobalThis.run = adoptOperatedOrganizationClock;', ctx);
  await ctx.run();
  return ctx;
}

test('inside an organization, times are read in that organization\'s zone', async () => {
  const ctx = await adopt('tenant_b2', { ok: true, body: { tenant_id: 'tenant_b2', timezone: 'Asia/Tokyo' } });
  assert.equal(ctx.window.dsseTenantTimezone, 'Asia/Tokyo');
  assert.deepEqual(ctx.calls, [['GET', '/admin/tenant']]);
});

test('an organization with no zone reads UTC, not the operator\'s clock', async () => {
  const ctx = await adopt('tenant_b2', { ok: true, body: { tenant_id: 'tenant_b2' } });
  assert.equal(ctx.window.dsseTenantTimezone, 'UTC');
});

test('outside any organization nothing is asked and the session\'s zone stands', async () => {
  const ctx = await adopt(null, { ok: true, body: { timezone: 'Europe/Berlin' } });
  assert.equal(ctx.calls.length, 0);
  assert.equal(ctx.window.dsseTenantTimezone, 'UTC');
});

test('it is adopted before anything is drawn', () => {
  const init = app.slice(app.indexOf('async function init()'), app.indexOf('\n}\n', app.indexOf('async function init()')));
  assert.ok(init.indexOf('await adoptOperatedOrganizationClock();') > 0 && init.indexOf('await adoptOperatedOrganizationClock();') < init.indexOf('applyI18n();'));
});

// Review of 2026-11-07: saving the organization's settings re-read the session, which adopts the signed-in
// administrator's own zone again.
test('saving the organization settings adopts the operated organization\'s zone again', () => {
  const src = readFileSync(new URL('./tenantsettings.js', import.meta.url), 'utf8');
  const a = src.indexOf('await ensureSignedIn();'), b = src.indexOf('await adoptOperatedOrganizationClock();');
  assert.ok(a > 0 && b > a, 'the save does not adopt the operated organization\'s zone after re-reading the session');
});
