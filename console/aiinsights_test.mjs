import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';

const source=readFileSync(new URL('./aiinsights.js',import.meta.url),'utf8');
const ok=body=>({ok:true,status:200,body});
function report(period='7d') {
  return {schema_version:'admin_ai_usage_report.v2',tenant_id:'own',generated_at:'2026-09-18T00:00:00Z',no_secret_attestation:true,
    window:{requested:period,from:'2026-09-17T00:00:00Z',to:'2026-09-18T00:00:00Z'},
    coverage:{source:'rows',from:'2026-09-17T00:00:00Z',to:'2026-09-18T00:00:00Z',rows:3,row_cap:100000,truncated:false},
    total_ai_accesses:2,total_ai_sessions:1,total_ai_messages:1,total_bytes_sent:100,total_bytes_received:200,
    services:[{saas_application_id:'saas_anthropic_claude',name:'Anthropic Claude',sessions:1,access_count:2,messages:1,bytes_sent:100,bytes_received:200}],
    by_activity:[{identity:'alice',identity_type:'user',corporate_user:'alice',device:'mac',app:'browser',ai_account:'',ai_email:'',ai_name:'',service:'Anthropic Claude',sessions:1,accesses:2,messages:1,bytes_sent:100,bytes_received:200}]};
}
function fixture() {
  const states=[],tables=[],requests=[],versions=new WeakMap();
  const el=(tag,props={},children=[])=>{const n={tag,props,children:[],isConnected:true,appendChild(x){this.children.push(x)}};Object.defineProperty(n,'innerHTML',{set(){this.children=[]}});n.children=Array.isArray(children)?children:[children];return n;};
  const ctx=vm.createContext({el,bl:x=>x.en,operateTenant:'',uiBadge:(text,kind)=>({text,kind}),uiCoverageNote:c=>({coverage:c}),uiPeriodSegment:()=>el('div'),
    uiState:(n,state,message,retry)=>{n.innerHTML='';states.push({state,message,retry})},simpleTable:(headers,rows)=>{tables.push({headers,rows});return{headers,rows}},
    freshRender:n=>{const v=(versions.get(n)||0)+1;versions.set(n,v);return()=>versions.get(n)===v},
    apiFetch:async(method,path,body,plane)=>{requests.push({method,path,plane});if(path==='/admin/tenant')return ok({tenant_id:'own'});if(path==='/admin/human-identities')return ok({tenant_id:'own',identities:[{id:'alice',tenant_id:'own',display_name:'Alice Example',department:'Engineering'}]});return ok(report(new URL('http://fixture'+path).searchParams.get('window')));}});
  vm.runInContext(source,ctx);return {ctx,states,tables,requests,host:el('div')};
}
for(const [name,change] of Object.entries({
  missing:()=>({}),null:()=>null,schema:d=>(d.schema_version='unknown',d),foreign:d=>(d.tenant_id='other',d),tenantMissing:d=>(delete d.tenant_id,d),
  servicesObject:d=>(d.services={},d),servicesNull:d=>(d.services=null,d),activityNull:d=>(d.by_activity=null,d),serviceNull:d=>(d.services=[null],d),activityRow:d=>(d.by_activity=[null],d),
  negative:d=>(d.total_bytes_sent=-1,d),stringCount:d=>(d.total_ai_sessions='1',d),unsafe:d=>(d.total_bytes_received=Number.MAX_SAFE_INTEGER+1,d),
  emptyTotals:d=>(d.services=[],d),activityMismatch:d=>(d.by_activity[0].bytes_sent=50,d),badName:d=>(d.services[0].name={},d),duplicate:d=>(d.services.push({...d.services[0]}),d),
  wrongPeriod:d=>(d.window.requested='30d',d),missingWindow:d=>(delete d.window,d),invalidTime:d=>(d.window.from='invalid',d),missingCoverage:d=>(delete d.coverage,d),
  badCoverage:d=>(d.coverage.truncated='false',d),coverageOutside:d=>(d.coverage.from='2020-01-01T00:00:00Z',d),badActivity:d=>(d.by_activity[0].ai_email={},d),attestation:d=>(d.no_secret_attestation=false,d),
})) test(`rejects ${name} report instead of showing zero or partial usage`,async()=>{
  const f=fixture(),normal=f.ctx.apiFetch;f.ctx.apiFetch=(m,p,b,plane)=>p.startsWith('/admin/ai-usage-report')?ok(change(report())):normal(m,p,b,plane);
  await f.ctx.loadAiUsage(f.host);assert.equal(f.states.at(-1).state,'error');assert.equal(f.states.at(-1).retry.label,'Retry');assert.equal(f.tables.length,0);
});
test('valid results use the control plane, verified tenant and directory; explicit empty succeeds',async()=>{
  const f=fixture();f.ctx.operateTenant='own';await f.ctx.loadAiUsage(f.host);assert.equal(f.tables.length,2);assert.match(JSON.stringify(f.tables),/Alice Example/);
  assert.ok(f.requests.every(r=>r.method==='GET'&&r.plane==='control'));assert.ok(f.requests[0].path.includes('expected_tenant_id=own'));
  const d=report();d.services=[];d.by_activity=[];for(const k of ['total_ai_accesses','total_ai_sessions','total_ai_messages','total_bytes_sent','total_bytes_received'])d[k]=0;
  assert.equal(f.ctx.aiUsageBody(ok(d),'own','7d').services.length,0);
});
test('service bucket union is not the sum of users; aggregate and shortened coverage are accepted',()=>{
  const f=fixture(),d=report();d.by_activity[0].accesses=1;d.by_activity[0].bytes_sent=50;d.by_activity[0].bytes_received=100;
  d.by_activity.push({...d.by_activity[0],identity:'bob',messages:0});
  assert.equal(f.ctx.aiUsageBody(ok(d),'own','7d').total_ai_sessions,1);
  d.coverage.source='aggregate';d.coverage.row_cap=0;d.coverage.truncated=true;assert.equal(f.ctx.aiUsageBody(ok(d),'own','7d').coverage.truncated,true);
  d.coverage.source='rows';d.coverage.row_cap=3;d.coverage.from='2026-09-17T12:00:00Z';assert.equal(f.ctx.aiUsageBody(ok(d),'own','7d').coverage.row_cap,3);
});
for(const fail of ['http','network','tenant'])test(`${fail} failure retries the same selected period`,async()=>{
  const f=fixture(),normal=f.ctx.apiFetch;f.ctx.apiFetch=(m,p,b,plane)=>{
    if(fail==='tenant'&&p==='/admin/tenant')return ok({tenant_id:'other'});
    if(p.startsWith('/admin/ai-usage-report')&&fail!=='tenant'){if(fail==='network')throw Error('reset');return {ok:false,status:503};}
    return normal(m,p,b,plane);
  };
  await f.ctx.loadAiUsage(f.host,'24h');assert.equal(f.states.at(-1).state,'error');f.ctx.apiFetch=normal;await f.states.at(-1).retry.onClick();assert.equal(f.tables.length,2);assert.ok(f.requests.filter(r=>r.path.includes('ai-usage-report')).every(r=>r.path.includes('window=24h')));
});
for(const body of [null,{}, {tenant_id:'other',identities:[{id:'alice',tenant_id:'other',display_name:'Foreign'}]}, {tenant_id:'own',identities:[null,{id:'alice',tenant_id:'other',display_name:'Foreign'}]}, {tenant_id:'own',identities:[{id:'alice',tenant_id:'own',display_name:{bad:true}}]}])test('optional unavailable or foreign directory keeps recorded identity',async()=>{
  const f=fixture(),normal=f.ctx.apiFetch;f.ctx.apiFetch=(m,p,b,plane)=>p==='/admin/human-identities'?ok(body):normal(m,p,b,plane);
  await f.ctx.loadAiUsage(f.host);assert.equal(f.tables.length,2);const text=JSON.stringify(f.tables);assert.match(text,/alice/);assert.doesNotMatch(text,/Foreign|Alice Example/);
});
test('directory exception is optional',async()=>{const f=fixture(),normal=f.ctx.apiFetch;f.ctx.apiFetch=(m,p,b,plane)=>{if(p==='/admin/human-identities')throw Error('offline');return normal(m,p,b,plane)};await f.ctx.loadAiUsage(f.host);assert.equal(f.tables.length,2)});
for(const phase of ['report','directory'])for(const change of ['disconnect','selection','reload'])test(`${change} while awaiting ${phase} discards old response`,async()=>{
  const f=fixture(),normal=f.ctx.apiFetch;let release;const target=phase==='report'?'/admin/ai-usage-report':'/admin/human-identities';
  f.ctx.apiFetch=(m,p,b,plane)=>p.startsWith(target)?new Promise(r=>release=r):normal(m,p,b,plane);
  const pending=f.ctx.loadAiUsage(f.host);await new Promise(setImmediate);
  if(change==='disconnect')f.host.isConnected=false;
  if(change==='selection')f.ctx.operateTenant='other';
  if(change==='reload'){f.ctx.apiFetch=normal;await f.ctx.loadAiUsage(f.host,'24h')}
  const n=f.tables.length;release(phase==='report'?ok(report()):ok({tenant_id:'own',identities:[{id:'alice',tenant_id:'own',display_name:'Stale'}]}));await pending;
  assert.equal(f.tables.length,n);assert.doesNotMatch(JSON.stringify(f.tables),/Stale/);
});
