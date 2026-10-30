import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const app = readFileSync(new URL('./app.js', import.meta.url), 'utf8');

test('every curated screen is registered for missing-script detection', () => {
  const source = app.slice(0, app.indexOf('// State + i18n')) +
    app.slice(app.indexOf('const CUSTOM_VIEWS = {'), app.indexOf('function renderGroup')) +
    '\nGROUPS.filter(group => group.custom && !CUSTOM_VIEWS[group.custom]).map(group => group.id)';
  const missing = vm.runInNewContext(source);
  assert.deepEqual(Array.from(missing), []);
});

function tenantDayRange(now, zone, daysAgo = 0) {
  const RealDate = Date;
  class FixedDate extends RealDate {
    constructor(...args) { super(...(args.length ? args : [now])); }
    static now() { return new RealDate(now).getTime(); }
  }
  const context = {window: {dsseTenantTimezone: zone}, Date: FixedDate, Intl};
  const start = app.indexOf('window.dsseTenantDayRange = function');
  const end = app.indexOf('const DLP_NAV_IDS', start);
  vm.runInNewContext(app.slice(start, end), context);
  return {...context.window.dsseTenantDayRange(daysAgo)};
}

test('tenant day spans the actual spring and autumn DST dates', () => {
  assert.deepEqual(tenantDayRange('2026-03-29T12:00:00Z', 'Europe/Berlin'), {
    from: '2026-03-28T23:00:00.000Z',
    to: '2026-03-29T22:00:00.000Z',
  });
  assert.deepEqual(tenantDayRange('2026-10-25T12:00:00Z', 'Europe/Berlin'), {
    from: '2026-10-24T22:00:00.000Z',
    to: '2026-10-25T23:00:00.000Z',
  });
});

test('daysAgo counts calendar days in the tenant timezone', () => {
  assert.deepEqual(tenantDayRange('2026-03-29T22:30:00Z', 'Europe/Berlin', 1), {
    from: '2026-03-28T23:00:00.000Z',
    to: '2026-03-29T22:00:00.000Z',
  });
});
