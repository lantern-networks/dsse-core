import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';

const source = readFileSync(new URL('./certs.js', import.meta.url), 'utf8');
const start = source.indexOf('function tenantDeviceCAControl(host) {');
const end = source.indexOf('// prefillPEM', start);
assert.ok(start >= 0 && end > start, 'tenant device CA control must remain reviewable');

test('selected organization shows only its exact tenant CA registrations', () => {
  const el = (tag, props = {}, children = []) => ({
    tag, props, children: Array.isArray(children) ? children : [children],
    appendChild(child) { this.children.push(child); },
    addEventListener() {},
  });
  const context = vm.createContext({
    el, bl: value => value.en, uiBadge: label => ({ label }),
    operateTenant: 'Acme', _pkiDeviceAuthority: null,
    _pkiTenantCAs: [
      { tenant_id: 'Acme', subject: 'own-CA' },
      { tenant_id: 'acme', subject: 'other-tenant-CA' },
      { tenant_id: '', subject: 'unattributed-CA' },
    ],
  });
  vm.runInContext(source.slice(start, end), context);
  const card = vm.runInContext('tenantDeviceCAControl({})', context);
  const rendered = JSON.stringify(card);
  assert.match(rendered, /own-CA/);
  assert.doesNotMatch(rendered, /other-tenant-CA|unattributed-CA/);
});
