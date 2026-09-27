import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const app=readFileSync(new URL('./app.js',import.meta.url),'utf8');
for(const lang of ['en','ja'])for(const state of ['pending_approval','active','ended','missing'])test(`only active elevation retries the original write: ${state} (${lang})`,async()=>{
 const calls=[],notices=[];
 const c=vm.createContext({localStorage:{getItem:()=>''},bl:x=>x[lang],uiConfirm:async()=>true,uiToast:(...a)=>notices.push(a),
 fetch:async(url,opts)=>{
  calls.push({url,method:opts.method});
  const elevation=url.endsWith('/operator-elevations');
  const status=elevation?201:calls.length===1?403:200;
  const body=elevation?{state:state==='missing'?undefined:state,elevation:{expires_at:'2099-01-01T00:00:00Z'}}:status===403?{elevation_required:{tenant_id:'customer',why:'block device'}}:{};
  return{ok:status<400,status,text:async()=>JSON.stringify(body)};
 }});
 vm.runInContext(app.slice(app.indexOf('const CP_AUTHORED_WRITES = ['),app.indexOf('// Rendering')),c);
 vm.runInContext('operatingOrganizationName="Customer";',c);
 const r=await c.apiFetch('POST','/admin/test-operation',{});
 assert.equal(calls.length,state==='active'?3:2);assert.equal(r.status,state==='active'?200:403);
 if(state==='pending_approval')assert.match(notices[0][0],lang==='en'?/approval/:/承認/);
 if(state!=='active')assert.ok(!notices.some(n=>/You have time|作業できます/.test(n[0])));
});
