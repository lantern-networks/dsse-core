import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';
const source = readFileSync(new URL('./tenant_fleet_settings.js', import.meta.url), 'utf8');
function fixture({accept = true, changeContext, code = 'shared_fleet_residency_confirmation_required'} = {}) {
  const calls = [], prompts = [];
  const ctx = vm.createContext({operateTenant:'tenant-a',idpSession:{tenant_id:'operator',principal_id:'alice'},bl:x=>x.ja,
    apiFetch: async (...args) => {calls.push(args);return calls.length===1?{ok:false,status:409,body:{code}}:{ok:true};},
    uiConfirm:async p=>{prompts.push(p);if(changeContext)ctx.operateTenant='tenant-b';return accept;}});
  vm.runInContext(source,ctx);return {ctx,calls,prompts};
}
test('narrow Region restriction needs an explicit translated confirmation; original body is untouched',async()=>{
  const {ctx,calls,prompts}=fixture();const body={allowed_regions:['region-a']};
  assert.equal((await ctx.saveTenantWithFleetConfirmation('/admin/tenant',body,'control')).ok,true);
  assert.equal(calls.length,2);assert.equal(prompts.length,1);assert.match(prompts[0].body,/拒否/);
  assert.equal(calls[1][2].acknowledge_shared_fleet_residency_impact,true);
  assert.equal(calls[1][2].allowed_regions[0],'region-a');assert.equal(body.acknowledge_shared_fleet_residency_impact,undefined);
});
for(const options of [{accept:false},{changeContext:true},{code:'some_other_conflict'}]) {
  test(`never retries silently: ${JSON.stringify(options)}`,async()=>{
    const {ctx,calls,prompts}=fixture(options);
    const result=await ctx.saveTenantWithFleetConfirmation('/admin/tenants',{allowed_regions:['region-a']},'control');
    assert.equal(result.ok,false);assert.equal(calls.length,1);
    assert.equal(prompts.length,options.code?0:1);
  });
}
test('context switch during first write cannot request or apply confirmation in another organization',async()=>{
  const {ctx,calls,prompts}=fixture();
  ctx.apiFetch=async(...args)=>{calls.push(args);ctx.operateTenant='tenant-b';return {ok:false,body:{code:'shared_fleet_residency_confirmation_required'}};};
  assert.equal((await ctx.saveTenantWithFleetConfirmation('/admin/tenant',{allowed_regions:['region-a']})).cancelled,true);
  assert.equal(calls.length,1);assert.equal(prompts.length,0);
});
test('existing Region conflict is visible in Japanese',()=>{
  const {ctx}=fixture();assert.equal(ctx.sharedFleetTenantWarning({}),'');
  assert.match(ctx.sharedFleetTenantWarning({shared_fleet_warning:'conflict'}),/リージョン制限は維持/);
});
