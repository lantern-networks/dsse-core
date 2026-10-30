import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';

const source = readFileSync(new URL('./agentprofile.js', import.meta.url), 'utf8');
const validOptions = tenant_id => ({tenant_id, transport_endpoints:['region-a=https://example.invalid'],
  transport_endpoints_unreachable:[], device_groups:[], bypass_catalog:[]});

function fixture(options, authority = 'Acme') {
  const calls = [], states = [];
  const c = vm.createContext({
    operateTenant: authority, idpSession: {tenant_id:'operator'},
    bl: x => x.en, freshRender: () => () => true,
    uiState: (...args) => states.push(args),
    apiFetch: async (...args) => {
      calls.push(args);
      return args[1] === '/admin/tenant'
        ? {ok:true,body:{tenant_id:authority}}
        : {ok:true,body:options};
    },
  });
  vm.runInContext(source, c);
  let rendered = 0;
  c.renderAgentProfileForm = () => { rendered++; };
  return {c,calls,states,rendered:()=>rendered,run:()=>c.loadAgentProfileForm({})};
}

test('agent profile options reject another exact-case tenant before showing issuance controls', async () => {
  const f = fixture(validOptions('acme'));
  await f.run();
  assert.equal(f.rendered(),0);
  assert.equal(f.states.at(-1)[1],'error');
});

test('agent profile options require complete arrays for selectable endpoint facts', async () => {
  const f = fixture({tenant_id:'Acme',transport_endpoints:null,device_groups:[],bypass_catalog:[]});
  await f.run();
  assert.equal(f.rendered(),0);
  assert.equal(f.states.at(-1)[1],'error');
});

test('matching tenant options allow the form to render', async () => {
  const f = fixture(validOptions('Acme'));
  await f.run();
  assert.equal(f.rendered(),1);
  assert.deepEqual(f.calls.map(x=>x[1]),['/admin/agent-profile/options','/admin/tenant']);
});
