import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

// Found 2026-11-04 configuring a new organization from a browser: objects written to the control plane were
// read back from an Edge that had not pulled them yet, and each save said "could not be confirmed".
const app = readFileSync(new URL('./app.js', import.meta.url), 'utf8');
const start = app.indexOf('const CP_AUTHORED_WRITES = [');
const end = app.indexOf('function baseForPlane');
const context = {};
vm.runInNewContext(app.slice(start, end) + '\nglobalThis.cpAuthoritative = cpAuthoritative;', context);

test('each object these screens write is read back from the control plane', () => {
  for (const [write, read] of [
    ['POST /admin/vlan-objects', 'GET /admin/vlan-objects'],
    ['POST /admin/sites/s1/networks', 'GET /admin/sites/s1/networks'],
    ['POST /admin/connectors/c1/routes', 'GET /admin/connectors/c1/routes'],
    ['POST /admin/internal-cas', 'GET /admin/internal-cas'],
    ['POST /admin/rules', 'GET /admin/rules'],
    ['POST /admin/assets/groups', 'GET /admin/assets/groups'],
    ['POST /admin/assets/services', 'GET /admin/assets/services'],
    ['POST /admin/assets/endpoints', 'GET /admin/assets/endpoints'],
  ]) {
    const [wm, wp] = write.split(' '), [rm, rp] = read.split(' ');
    assert.equal(context.cpAuthoritative(wm, wp), true, write + ' is written to the control plane');
    assert.equal(context.cpAuthoritative(rm, rp), true, read + ' must be read where it was written');
  }
});

test('what an Edge observes stays on the Edge', () => {
  assert.equal(context.cpAuthoritative('GET', '/admin/egress-effective-rules'), false);
  assert.equal(context.cpAuthoritative('GET', '/admin/sites/s1/networks/extra'), false);
});

// 2026-11-07, three-region acceptance rerun: one region's Console said "not observed" for a device another
// region's Console showed with 59 days left. The fleet's observations are held by the control plane.
test('what the fleet observed of its devices is read from the control plane', () => {
  assert.equal(context.cpAuthoritative('GET', '/admin/device-certificates'), true);
  assert.equal(context.cpAuthoritative('GET', '/admin/steer-exclusions/observed'), true);
  assert.equal(context.cpAuthoritative('GET', '/admin/steer-exclusions/observed/by-app'), true);
  assert.equal(context.cpAuthoritative('GET', '/admin/agent/device-updates'), true);
  assert.equal(context.cpAuthoritative('GET', '/admin/agent-rollout'), true);
});
