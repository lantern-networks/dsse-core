import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';
const source = readFileSync(new URL('./eastwestadvanced.js', import.meta.url), 'utf8');
function fixture(response) {
  const calls = [], editors = [], errors = [];
  const c = vm.createContext({
    SUBJECT_ANY: '*', bl: x => x.en,
    apiFetch: async (...args) => { calls.push(args); return response; },
    loadList: async path => { calls.push(['LIST', path]); return path.endsWith('services') ? [
      { id:'udp', ports:[{protocol:'udp',port:22}] }, {id:'tcp',ports:[{protocol:'tcp',port:22}]}] : [{id:'fresh-host',kind:'network',address:'fresh.example'}]; },
    uiPrompt: async () => { throw Error('unexpected endpoint creation'); },
    uiToast: (...args) => errors.push(args),
    openRuleEditor: (...args) => editors.push(args),
  });
  vm.runInContext(source, c);
  return { calls, editors, errors, run: () => vm.runInContext("adoptFlowIntoRule({observation_id:'o',destination:'stale.example',port:53,service_family:'dns'}, {})", c) };
}
for (const [name, response] of [['unavailable',{ok:false,status:503}],['malformed',{ok:true,body:{}}],['removed',{ok:true,body:{observations:[]}}]]) {
  test(`adoption stops before writes/editor when inventory is ${name}`, async () => {
    const f=fixture(response); await f.run(); assert.equal(f.calls.length,1); assert.equal(f.editors.length,0); assert.equal(f.errors.at(-1)[1],'err');
  });
}
test('adoption uses refreshed destination and TCP service rather than stale row or UDP port match', async () => {
  const f=fixture({ok:true,body:{observations:[{observation_id:'o',destination:'fresh.example',port:22,service_family:'ssh',covered:false}]}}); await f.run();
  assert.equal(f.errors.length,0); assert.equal(f.editors.length,1);
  assert.equal(f.editors[0][3].destination[0],'fresh-host'); assert.equal(f.editors[0][3].service_id,'tcp'); assert.equal(f.editors[0][3].name,'Adopted: fresh.example:22');
  assert.ok(f.calls.every(x=>x[0]!=='POST'));
});
