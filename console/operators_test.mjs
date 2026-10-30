import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';

const source = readFileSync(new URL('./operators.js', import.meta.url), 'utf8');

test('operator registry outage is an error, not a claim that no operator tenant exists', async () => {
  const states = [];
  let answer = {ok:false, status:503};
  const context = vm.createContext({
    bl: value => value.en,
    apiFetch: async (_, path) => { assert.equal(path, '/admin/tenants'); return answer; },
    uiState: (_, state, message) => states.push({state, message}),
    freshRender: () => () => true,
  });
  vm.runInContext(source, context);
  const host = {};
  await context.renderOperatorList(host, {});
  assert.deepEqual(states.map(item => item.state), ['loading', 'error']);
  assert.match(states.at(-1).message, /could not be read/);
  assert.doesNotMatch(states.at(-1).message, /no operator tenant/);
  let called = false;
  const refused = await context.withOperatorTenant(() => {called = true;});
  assert.equal(refused.lookupUnavailable, true);
  assert.equal(called, false);

  states.length = 0;
  answer = {ok:true, body:{tenants:[]}};
  await context.renderOperatorList(host, {});
  assert.equal(states.at(-1).state, 'empty');
  assert.match(states.at(-1).message, /no operator tenant/);
});
