import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';

test('DNS reach includes site bindings without losing connector-specific governance', async () => {
  const calls = [];
  const context = vm.createContext({apiFetch: async (method, path) => {
    calls.push(path);
    if (path === '/admin/connectors') return {ok: true, body: {connectors: [
      {id: 'a', name: 'First', connector_group_id: 'site'},
      {id: 'b', name: 'Second', connector_group_id: 'site'},
      {id: 'c', name: 'Other', connector_group_id: 'other'},
    ]}};
    if (path === '/admin/sites/site/networks') return {ok: true, body: {networks: [
      {routable: true, network_cidrs: ['10.40.0.0/24']},
      {routable: true, cidr: '10.50.0.0/24'},
      {routable: false, cidr: '10.60.0.0/24'},
    ]}};
    if (path === '/admin/connectors/a/routes') return {ok: true, body: {routes: [
      {routable: true, cidr: '10.40.0.0/24'},
      {routable: false, cidr: '10.70.0.0/24'},
    ]}};
    return {ok: true, body: {routes: [], networks: []}};
  }});
  vm.runInContext(readFileSync(new URL('./dns.js', import.meta.url), 'utf8'), context);
  const reach = await context.dnsFetchConnectorReach();
  assert.deepEqual(JSON.parse(JSON.stringify(reach)), [
    {id: 'a', name: 'First', cidrs: ['10.40.0.0/24', '10.50.0.0/24']},
    {id: 'b', name: 'Second', cidrs: ['10.40.0.0/24', '10.50.0.0/24']},
    {id: 'c', name: 'Other', cidrs: []},
  ]);
  assert.equal(calls.filter(p => p === '/admin/sites/site/networks').length, 1);
  assert.equal(context.dnsReachFor('10.40.0.53:53', reach).name, 'First');
  assert.equal(context.dnsReachFor('10.70.0.53:53', reach), null);
});

for(const failed of ['/admin/connectors','/admin/connectors/c/routes','/admin/sites/s/networks'])test('DNS refuses incomplete reachability and recovers: '+failed,async()=>{
 let fail=true,states=[];
 const c=vm.createContext({bl:x=>x.en,freshRender:()=>()=>true,uiState:(host,kind,message,action)=>states.push({kind,message,action}),apiFetch:async(method,path)=>{
  if(path===failed&&fail)return {ok:false,status:503,body:{}};
  return {ok:true,status:200,body:path==='/admin/connectors'?{connectors:[{id:'c',name:'Connector',connector_group_id:'s'}]}:path==='/admin/connectors/c/routes'?{routes:[]} :path==='/admin/dns-policy'?{deny:[],sinkhole:{},forward_zones:[]}:{networks:[{routable:true,cidr:'10.40.0.0/24'}]}};
 }});
 vm.runInContext(readFileSync(new URL('./dns.js',import.meta.url),'utf8'),c);
 await assert.rejects(c.dnsFetchConnectorReach(),/unavailable/);
 await c.loadDns({},{});assert.equal(states.at(-1).kind,'error');assert.match(states.at(-1).message,/could not be verified/);assert.equal(states.at(-1).action.label,'Retry');
 fail=false;const reach=await c.dnsFetchConnectorReach();assert.equal(c.dnsReachFor('10.40.0.53:53',reach).id,'c');
});
test('missing reachability collections are not an empty successful read',async()=>{
 const c=vm.createContext({apiFetch:async()=>({ok:true,status:200,body:{}})});vm.runInContext(readFileSync(new URL('./dns.js',import.meta.url),'utf8'),c);await assert.rejects(c.dnsFetchConnectorReach(),/unavailable/);
});
