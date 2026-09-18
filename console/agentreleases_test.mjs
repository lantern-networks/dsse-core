import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';
const source=readFileSync(new URL('./agentreleases.js',import.meta.url),'utf8');
function fixture(){
 const nodes=[],fields={},toasts=[],requests=[],listeners=new Map();let modal,observed;
 const el=(tag,props={},children=[])=>{const n={tag,...props,isConnected:true,children:Array.isArray(children)?children:[children],handlers:{},appendChild(x){this.children.push(x)},remove(){this.isConnected=false},setAttribute(k,v){this[k]=v},focus(){},addEventListener(k,f){this.handlers[k]=f},querySelectorAll(selector){const tags=selector.split(',');return allNodes(this).filter(n=>tags.includes(n.tag))}};Object.defineProperty(n,'innerHTML',{set(){this.children=[]}});nodes.push(n);return n};
 const c=vm.createContext({el,bl:x=>x.en,uiField:opts=>{const f={el:el('input'),value:opts.value,get(){return this.value},setError(error){this.error=error},focus(){}};fields[opts.name]=f;return f},uiModal:opts=>{modal=opts;return{close(){}}},uiToast:(...a)=>toasts.push(a),apiFetch:async(...a)=>{requests.push(a);return{ok:false,status:500}},document:{body:el('body'),createTextNode:s=>s,addEventListener:(k,f)=>listeners.set(k,f),removeEventListener:k=>listeners.delete(k)},MutationObserver:class {constructor(f){observed=f} observe(){} disconnect(){observed=null}}});
 vm.runInContext(readFileSync(new URL('./sites.js',import.meta.url),'utf8'),c);
 c.baseForPlane=()=>'/control';
 vm.runInContext(source,c);
 // Legacy preservation tests open forms directly; production receives this verified
 // context from renderAgentReleaseList. Lifecycle tests below exercise invalidation.
 for(const [name,arity] of [['openAgentWindowForm',3],['openAgentWavesForm',4],['openAgentVersionForm',4]]){const original=c[name];c[name]=(...args)=>{if(args.length<arity)args[arity-1]={tenant:'own',current:()=>true};return original(...args)}}
 return{c,nodes,fields,toasts,requests,listeners,mutation:()=>observed?.(),get modal(){const m=nodes.findLast(n=>n.role==='dialog');return m?{body:m.children[1].children,footer:m.children[2].children}:modal}};
}

const json=x=>JSON.parse(JSON.stringify(x));
const schedule=()=>({waves:[{group:'Pilot',delay_days:0,priority:9},{group:'General',delay_days:5,priority:-1}],default_delay_days:11});
test('editing a wave delay preserves priority and default',async()=>{
 const f=fixture(),before=schedule();f.c.openAgentWavesForm({},before,[]);const inputs=f.nodes.filter(n=>n.tag==='input');inputs[3].value='4';inputs[3].handlers.input();await f.modal.footer[1].handlers.click();assert.deepEqual(json(f.requests[0][2]),{intent:'schedule',waves:{waves:[{group:'Pilot',delay_days:0,priority:9},{group:'General',delay_days:4,priority:-1}],default_delay_days:11}});assert.deepEqual(before,schedule());
});
test('renaming a group preserves that row priority',async()=>{const f=fixture();f.c.openAgentWavesForm({},schedule(),[]);const n=f.nodes.find(n=>n.tag==='input');n.value='Pilot renamed';n.handlers.input();await f.modal.footer[1].handlers.click();assert.equal(f.requests[0][2].waves.waves[0].priority,9);assert.equal(f.requests[0][2].waves.waves[0].group,'Pilot renamed');});
test('removing a group retains remaining row and default',async()=>{const f=fixture();f.c.openAgentWavesForm({},schedule(),[]);f.nodes.find(n=>n.text==='−').onClick();await f.modal.footer[1].handlers.click();assert.deepEqual(json(f.requests[0][2].waves),{waves:[{group:'General',delay_days:5,priority:-1}],default_delay_days:11});});
for(const days of ['1.5','-1','Infinity','9007199254740992'])test('wave rejects '+days,async()=>{const f=fixture();f.c.openAgentWavesForm({},schedule(),[]);const d=f.nodes.filter(n=>n.tag==='input')[1];d.value=days;d.handlers.input();await f.modal.footer[1].handlers.click();assert.equal(f.requests.length,0);assert.equal(f.toasts.length,1);});
for(const [field,value] of [['idle','1.5'],['idle','-1'],['idle','9007199254740992'],['deadline','1.5'],['deadline','366'],['deadline','-1']])test('window rejects '+field+' '+value,async()=>{const f=fixture();f.c.openAgentWindowForm({},{});f.fields[field].value=value;await f.modal.footer[1].handlers.click();assert.equal(f.requests.length,0);assert.ok(f.fields[field].error);});
test('window accepts boundary days and idle integers',async()=>{const f=fixture();f.c.openAgentWindowForm({},{});f.fields.deadline.value='365';f.fields.idle.value='0';await f.modal.footer[1].handlers.click();assert.equal(f.requests[0][2].window.deadline_days,365);assert.equal(f.requests[0][2].window.require_idle_minutes,0);});
test('summary shows configured priority and unmatched default',()=>{const f=fixture();const s=f.c.arWavesSummary(schedule());assert.match(s,/priority 9/);assert.match(s,/priority -1/);assert.match(s,/other groups after 11d/);});
test('an empty wave set still has an explicit default',()=>{const f=fixture();assert.equal(f.c.arWavesSummary({waves:[],default_delay_days:7}),'all groups after 7d');assert.match(f.c.arWavesSummary({waves:[]}),/everything at once/);});
test('version summary exposes a hold and its reason',()=>{const f=fixture();const s=f.c.arRunningSummary({frozen:true,reason:'incident',desired_version:'2.0.0'},{});assert.match(s,/Updates paused: incident/);assert.match(s,/2.0.0/);});

const fullPlan=()=>({desired_version:'0.3.1',release_channel:'stable',frozen:true,intent:'rollout',reason:'incident',updated_at:'2026-09-18T00:00:00Z',window:{local_start:'01:00',local_end:'05:00',require_idle_minutes:15,require_unattended:true,require_ac_power:true,deadline_days:7},waves:schedule()});
const planResponse=p=>({ok:true,status:200,body:{schema_version:'admin_agent_rollout.v1',tenant_id:'own',plan:p}});
const malformedPlans={
 'empty plan':p=>({}), 'null plan':p=>null, 'array plan':p=>[],
 'missing halt':p=>{delete p.frozen;return p},'null halt':p=>({...p,frozen:null}),'string halt':p=>({...p,frozen:'false'}),
 'missing reason':p=>{delete p.reason;return p},'null version':p=>({...p,desired_version:null}),'unknown intent':p=>({...p,intent:'unknown'}),
 'empty window':p=>({...p,window:{}}),'missing power':p=>{delete p.window.require_ac_power;return p},'null idle':p=>{p.window.require_idle_minutes=null;return p},
 'fractional idle':p=>{p.window.require_idle_minutes=1.5;return p},'negative deadline':p=>{p.window.deadline_days=-1;return p},'long deadline':p=>{p.window.deadline_days=366;return p},'bad clock':p=>{p.window.local_start='24:00';return p},
 'missing wave list':p=>({...p,waves:{}}),'wave object':p=>({...p,waves:{waves:{}}}),'null row':p=>({...p,waves:{waves:[null]}}),
 'missing delay':p=>{delete p.waves.waves[0].delay_days;return p},'null priority':p=>{p.waves.waves[0].priority=null;return p},'unsafe priority':p=>{p.waves.waves[0].priority=Number.MAX_SAFE_INTEGER+1;return p},
 'negative default':p=>{p.waves.default_delay_days=-1;return p},'duplicate group':p=>{p.waves.waves[1].group=' PILOT ';return p},
};
for(const [name,change] of Object.entries(malformedPlans))test('rollout read refuses '+name,()=>{const f=fixture();assert.throws(()=>f.c.arRolloutPlanBody(planResponse(change(fullPlan())),'own'),/Could not verify/)});
for(const name of ['foreign','schema','status','body'])test('rollout read refuses envelope '+name,()=>{const f=fixture(),r=planResponse(fullPlan());if(name==='foreign')r.body.tenant_id='other';if(name==='schema')r.body.schema_version='unknown';if(name==='status')r.status=206;if(name==='body')r.body=null;assert.throws(()=>f.c.arRolloutPlanBody(r,'own'),/Could not verify/)});
test('valid holds, explicit defaults and nullable optional schedules remain readable',()=>{const f=fixture();const variants=[fullPlan(),{desired_version:'',release_channel:'',frozen:false,intent:'',reason:'',updated_at:''},{...fullPlan(),window:null,waves:{waves:null,default_delay_days:null}}];for(const p of variants)assert.deepEqual(json(f.c.arRolloutPlanBody(planResponse(p),'own')),p)});
function readFixture(){
 const f=fixture();let api;
 Object.assign(f.c,{window:{},connectorProgramsFetch:async()=>[],operateTenant:'',answeringForTheDeployment:()=>false,uiBadge:(text)=>({text}),uiWhen:x=>x,atob:s=>Buffer.from(s,'base64').toString(),uiState:(host,type,text)=>{host.innerHTML='';host.state={type,text}},freshRender:host=>{const n=host.seq=(host.seq||0)+1;return()=>host.seq===n},apiFetch:(...args)=>{f.requests.push(args);return api(args[0], args[1].replace(/\?expected_tenant_id=.*$/, ""), ...args.slice(2))}});
 const responses=path=>path.startsWith('/admin/agent-rollout')?planResponse(fullPlan()):{ok:true,status:200,body:path==='/admin/tenant'?{tenant_id:'own'}:path==='/admin/agent-updates'?{schema_version:'admin_agent_updates.v1',tenant_id:'own',envelopes:{},pending:{}}:path==='/admin/enrolled-devices'?{devices:[]}:{schema_version:'admin_agent_update_sign_floor.v1',tenant_id:'own',floors:{},signing_public_key:'no'}};
 api=async(method,path)=>responses(path);const host={isConnected:true,children:[],appendChild(n){this.children.push(n)}};Object.defineProperty(host,'innerHTML',{set(){this.children=[]}});
 return{...f,host,responses,setAPI(fn){api=fn}};
}
const allNodes=root=>[root,...(root.children||[]).filter(x=>x&&typeof x==='object').flatMap(allNodes)];
test('incomplete successful plan disables all editors and offers retry',async()=>{const f=readFixture();f.setAPI(async(m,p)=>p.startsWith('/admin/agent-rollout')?planResponse({}):f.responses(p));await f.c.renderAgentReleaseList(f.host);const changes=allNodes(f.host).filter(x=>x.text==='Change');assert.equal(changes.length,3);assert.ok(changes.every(x=>x.disabled));assert.ok(allNodes(f.host).some(x=>x.text==='Retry'));assert.ok(!allNodes(f.host).some(x=>x.text==='not set — devices use their own defaults'));});
test('verified organization pins rollout read and keeps held settings editable',async()=>{const f=readFixture();await f.c.renderAgentReleaseList(f.host);assert.ok(f.requests.some(x=>x[1]==='/admin/agent-rollout?expected_tenant_id=own'));assert.ok(allNodes(f.host).filter(x=>x.text==='Change').every(x=>!x.disabled));assert.ok(allNodes(f.host).some(x=>String(x.text).includes('Updates paused: incident')))});
for(const name of ['missing','foreign-selection','unavailable'])test('organization '+name+' blocks rollout read',async()=>{const f=readFixture();if(name==='foreign-selection')f.c.operateTenant='other';f.setAPI(async(m,p)=>p==='/admin/tenant'?(name==='missing'?{ok:true,status:200,body:{}}:name==='unavailable'?{ok:false,status:503}:f.responses(p)):f.responses(p));await f.c.renderAgentReleaseList(f.host);assert.ok(!f.requests.some(x=>x[1].startsWith('/admin/agent-rollout')));assert.ok(allNodes(f.host).filter(x=>x.text==='Change').every(x=>x.disabled))});
const deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return{promise,resolve}};
test('late old render cannot replace shared publication cache',async()=>{const f=readFixture(),wait=deferred();let n=0,entered;const ready=new Promise(r=>entered=r);f.setAPI(async(m,p)=>{if(p==='/admin/agent-updates'){if(++n===1){entered();return wait.promise}return catalogueResponse('own','0.3.2')}return f.responses(p)});const old=f.c.renderAgentReleaseList(f.host);await ready;await f.c.renderAgentReleaseList(f.host);wait.resolve(catalogueResponse('own','0.3.0'));await old;assert.equal(f.c.arManifestOf(f.c.window._arLastPublished['windows/amd64']).version,'0.3.2')});
for(const name of ['departed','tenant-changed','deployment-changed'])test('late rollout response discarded after '+name,async()=>{const f=readFixture(),wait=deferred();let entered;const started=new Promise(r=>entered=r);f.setAPI(async(m,p)=>{if(p.startsWith('/admin/agent-rollout')){entered();return wait.promise}return f.responses(p)});const render=f.c.renderAgentReleaseList(f.host);await started;if(name==='departed')f.host.isConnected=false;if(name==='tenant-changed')f.c.operateTenant='other';if(name==='deployment-changed')f.c.answeringForTheDeployment=()=>true;wait.resolve(planResponse(fullPlan()));await render;assert.equal(f.c.window._arLastPublished,undefined);assert.equal(f.host.children.length,0)});
test('explicit legacy empty tenant remains bound to its own response',async()=>{const f=readFixture();f.setAPI(async(m,p)=>{const r=f.responses(p);if(p==='/admin/tenant'||p.startsWith('/admin/agent-rollout')||p==='/admin/agent-updates'||p==='/admin/agent-update-sign-floor')r.body.tenant_id='';return r});await f.c.renderAgentReleaseList(f.host);assert.ok(f.requests.some(x=>x[1]==='/admin/agent-rollout?expected_tenant_id='));assert.ok(allNodes(f.host).some(x=>String(x.text).includes('Updates paused: incident')))});


const editorRequests={
 window:()=>({intent:'schedule',window:fullPlan().window}),
 waves:()=>({intent:'schedule',waves:schedule()}),
 version:()=>({intent:'rollout',desired_version:'0.3.1'}),
 follow:()=>({intent:'follow'}),
};
function ack(request){const p=fullPlan();p.intent=request.intent;if(request.intent==='rollout')p.release_channel='';if(request.intent==='follow'){p.desired_version='';p.release_channel=''}return planResponse(p)}
for(const [kind,request] of Object.entries(editorRequests)){
 for(const bad of ['empty','foreign','status','schema','missing halt','wrong intent','wrong value']) test(kind+' save rejects '+bad,()=>{
  const f=fixture(),q=request(),r=ack(q);
  if(bad==='empty')r.body={};if(bad==='foreign')r.body.tenant_id='other';if(bad==='status')r.status=202;if(bad==='schema')r.body.schema_version='unknown';if(bad==='missing halt')delete r.body.plan.frozen;if(bad==='wrong intent')r.body.plan.intent='freeze';
  if(bad==='wrong value'){if(kind==='window')r.body.plan.window.require_ac_power=false;if(kind==='waves')r.body.plan.waves.waves[0].priority=0;if(kind==='version')r.body.plan.desired_version='other';if(kind==='follow')r.body.plan.release_channel='stable'}
  assert.equal(f.c.arRolloutSaveConfirmed(r,'own',q),false);
 });
 test(kind+' save accepts requested fields with concurrent independent changes',()=>{const f=fixture(),q=request(),r=ack(q);r.body.plan.frozen=false;r.body.plan.reason='new incident decision';if(kind==='window')r.body.plan.waves=schedule();if(kind==='waves')r.body.plan.window.local_start='03:00';assert.equal(f.c.arRolloutSaveConfirmed(r,'own',q),true)});
}
test('wave save requires all rows/default but permits omitted zero priority and null default',()=>{
 const f=fixture(),q=editorRequests.waves(),r=ack(q);r.body.plan.waves.waves.pop();assert.equal(f.c.arRolloutSaveConfirmed(r,'own',q),false);
 const r2=ack(q);r2.body.plan.waves.default_delay_days=12;assert.equal(f.c.arRolloutSaveConfirmed(r2,'own',q),false);
 q.waves.waves[0].priority=0;delete q.waves.default_delay_days;const r3=ack(q);r3.body.plan.waves=json(q.waves);delete r3.body.plan.waves.waves[0].priority;r3.body.plan.waves.default_delay_days=null;assert.equal(f.c.arRolloutSaveConfirmed(r3,'own',q),true);
});
function editorFixture(){const f=fixture();let valid=true,rendered=0;f.c.renderAgentReleaseList=()=>rendered++;const context={tenant:'own',current:()=>valid},host={isConnected:true};return{...f,host,context,invalidate(){valid=false;f.mutation()},get rendered(){return rendered}}}
function openDialog(f,request=editorRequests.window){f.c.arRolloutDialog({host:f.host,context:f.context,title:'Edit',body:[f.c.el('input'),f.c.el('button',{text:'Add row'})],request});return{submit:f.nodes.find(n=>n.text==='Save'),cancel:f.nodes.find(n=>n.text==='Cancel'),notice:f.nodes.find(n=>n.role==='status'),backdrop:f.nodes.find(n=>n.class==='ui-modal-backdrop')}}
test('pending save locks all fields, row controls, cancel, Escape, backdrop and reentry',async()=>{
 const f=editorFixture(),wait=deferred(),d=openDialog(f);f.c.apiFetch=async(...args)=>{f.requests.push(args);return wait.promise};const first=d.submit.handlers.click();assert.ok(d.backdrop.querySelectorAll('input,button').every(n=>n.disabled));await d.submit.handlers.click();d.cancel.onClick();f.listeners.get('keydown')({key:'Escape'});d.backdrop.onClick({target:d.backdrop});assert.equal(d.backdrop.isConnected,true);assert.equal(f.requests.length,1);assert.equal(f.requests[0][1],'/admin/agent-rollout?expected_tenant_id=own');wait.resolve(ack(editorRequests.window()));await first;assert.equal(d.backdrop.isConnected,false);assert.equal(f.rendered,1);assert.equal(f.toasts.length,1);
});
for(const failure of ['HTTP','transport','empty ACK'])test(failure+' stays open, displays uncertainty and allows same form retry',async()=>{
 const f=editorFixture(),d=openDialog(f);let calls=0;f.c.apiFetch=async()=>{if(++calls>1)return ack(editorRequests.window());if(failure==='transport')throw Error('offline');return failure==='HTTP'?{ok:false,status:500}:{ok:true,status:200,body:{}}};await d.submit.handlers.click();assert.equal(f.rendered,0);assert.equal(f.toasts.length,0);assert.equal(d.backdrop.isConnected,true);assert.match(d.notice.textContent,/may already be saved/);assert.equal(d.notice.role,'alert');assert.ok(d.backdrop.querySelectorAll('input,button').every(n=>!n.disabled));await d.submit.handlers.click();assert.equal(f.rendered,1);assert.equal(calls,2);
});
for(const pending of [false,true])test('invalidated read context closes editor and drops late success pending='+pending,async()=>{
 const f=editorFixture(),d=openDialog(f),wait=deferred();f.c.apiFetch=async(...args)=>{f.requests.push(args);return wait.promise};const run=pending?d.submit.handlers.click():null;f.invalidate();assert.equal(d.backdrop.isConnected,false);await d.submit.handlers.click();wait.resolve(ack(editorRequests.window()));await run;assert.equal(f.requests.length,pending?1:0);assert.equal(f.rendered,0);assert.equal(f.toasts.length,0);
});
test('failed local validation sends nothing',async()=>{const f=editorFixture(),d=openDialog(f,()=>null);await d.submit.handlers.click();assert.equal(f.requests.length,0);assert.equal(d.backdrop.isConnected,true)});
test('legacy empty verified tenant remains explicitly pinned',async()=>{const f=editorFixture();f.context.tenant='';const d=openDialog(f);f.c.apiFetch=async(...args)=>{f.requests.push(args);const r=ack(editorRequests.window());r.body.tenant_id='';return r};await d.submit.handlers.click();assert.equal(f.requests[0][1],'/admin/agent-rollout?expected_tenant_id=');assert.equal(f.rendered,1)});


function releaseEnvelope(version='0.3.1') {
 const m={schema:'1',version,platform:'windows',arch:'amd64',channel:'stable',delivery:'dsse',artifact_kind:'msi',artifact_url:'https://example.test/agent.msi',artifact_sha256:'a'.repeat(64),artifact_size:32,min_from_version:'',released_at:'2026-09-18T00:00:00Z',not_after:'2026-10-18T00:00:00Z'};
 return {type:'dsse_agent_update_manifest.v1',version:'1',signing_key_id:'test',created_at:m.released_at,payload_b64:Buffer.from(JSON.stringify(m)).toString('base64'),payload_sha256:'b'.repeat(64),signature:'synthetic-not-crypto-verification'};
}
function catalogueResponse(scope='own',version='0.3.1'){return {ok:true,status:200,body:{schema_version:'admin_agent_updates.v1',tenant_id:scope,envelopes:{'windows/amd64':releaseEnvelope(version)},pending:{}}}}
function floorResponse(scope='own'){return {ok:true,status:200,body:{schema_version:'admin_agent_update_sign_floor.v1',tenant_id:scope,floors:{'windows/amd64':'0.3.1'},signing_public_key:'a'.repeat(64)}}}
const catalogueBad={
 'empty body':r=>r.body={},'missing active':r=>delete r.body.envelopes,'missing pending':r=>delete r.body.pending,'null map':r=>r.body.envelopes=null,'array map':r=>r.body.pending=[],
 'foreign scope':r=>r.body.tenant_id='other','missing scope':r=>delete r.body.tenant_id,'wrong schema':r=>r.body.schema_version='wrong','partial status':r=>r.status=206,
 'unknown target':r=>r.body.envelopes.linux=releaseEnvelope(),'null envelope':r=>r.body.envelopes['windows/amd64']=null,
 'wrong envelope type':r=>r.body.envelopes['windows/amd64'].type='steer-policy','missing payload':r=>delete r.body.envelopes['windows/amd64'].payload_b64,
 'broken payload':r=>r.body.envelopes['windows/amd64'].payload_b64='x','missing signature':r=>delete r.body.envelopes['windows/amd64'].signature,
 'bad hash':r=>r.body.envelopes['windows/amd64'].payload_sha256='x',
};
for(const [name,mutate] of Object.entries(catalogueBad))test('catalogue rejects '+name,()=>{const f=readFixture(),r=catalogueResponse();mutate(r);assert.throws(()=>f.c.arCatalogueBody(r,'own'))});
for(const [field,value] of [['version',''],['platform','darwin'],['artifact_size',0],['artifact_size','32'],['artifact_size',1.5],['artifact_sha256','bad'],['not_after','invalid'],['delivery','unknown'],['artifact_url',null],['channel',null]])test('catalogue rejects invalid manifest '+field+'='+value,()=>{const f=readFixture(),r=catalogueResponse(),e=r.body.envelopes['windows/amd64'],m=JSON.parse(Buffer.from(e.payload_b64,'base64'));m[field]=value;e.payload_b64=Buffer.from(JSON.stringify(m)).toString('base64');assert.throws(()=>f.c.arCatalogueBody(r,'own'))});
for(const name of ['missing scope','foreign scope','missing floors','null floors','array floors','foreign target','unknown key','null key','missing key','bad status','missing schema'])test('signing read rejects '+name,()=>{const f=readFixture(),r=floorResponse();if(name==='missing scope')delete r.body.tenant_id;if(name==='foreign scope')r.body.tenant_id='other';if(name==='missing floors')delete r.body.floors;if(name==='null floors')r.body.floors=null;if(name==='array floors')r.body.floors=[];if(name==='foreign target')r.body.floors['other|windows/amd64']='9.0.0';if(name==='unknown key')r.body.signing_public_key='yes';if(name==='null key')r.body.signing_public_key=null;if(name==='missing key')delete r.body.signing_public_key;if(name==='bad status')r.status=206;if(name==='missing schema')delete r.body.schema_version;assert.throws(()=>f.c.arSigningBody(r,'own'))});
test('valid empty catalogue and known no signer remain explicit',()=>{const f=readFixture(),r=catalogueResponse();r.body.envelopes={};assert.deepEqual(json(f.c.arCatalogueBody(r,'own').envelopes),{});for(const key of ['no','a'.repeat(64),'04'+'a'.repeat(128)]){const floor=floorResponse();floor.body.signing_public_key=key;assert.equal(f.c.arSigningBody(floor,'own').signing_public_key,key)}});
for(const status of [404,403,503,200])test('unknown signing information retains verified catalogue without claiming no key: '+status,async()=>{const f=readFixture();f.c.answeringForTheDeployment=()=>true;f.setAPI(async(m,p)=>p==='/admin/agent-updates'?catalogueResponse('deployment'):p==='/admin/agent-update-sign-floor'?{ok:status===200,status,body:{}}:f.responses(p));await f.c.renderAgentReleaseList(f.host);const nodes=allNodes(f.host);assert.ok(nodes.some(n=>String(n.text).includes('Signing information could not be verified')));assert.ok(nodes.some(n=>n.text==='Unknown'));assert.ok(!nodes.some(n=>String(n.text).includes('holds no signing key')));assert.equal(f.c.window._arCanSign,undefined);assert.equal(f.c.arManifestOf(f.c.window._arLastPublished['windows/amd64']).version,'0.3.1');f.c.openAgentReleaseForm(f.host);assert.equal(f.toasts.length,1);assert.equal(f.requests.filter(r=>r[0]!=='GET').length,0)});
test('incomplete catalogue clears caches and does not render empty publication badges',async()=>{const f=readFixture();f.c.window._arLastPublished={old:1};f.c.window._arCanSign=true;f.setAPI(async(m,p)=>p==='/admin/agent-updates'?{ok:true,status:200,body:{}}:f.responses(p));await f.c.renderAgentReleaseList(f.host);assert.equal(f.host.state.type,'error');assert.equal(f.c.window._arLastPublished,undefined);assert.equal(f.c.window._arCanSign,undefined);assert.ok(!allNodes(f.host).some(n=>n.text==='Nothing published'))});
test('deployment catalogue/floor use deployment pin while rollout uses own tenant',async()=>{const f=readFixture();f.c.answeringForTheDeployment=()=>true;f.setAPI(async(m,p)=>p==='/admin/agent-updates'?catalogueResponse('deployment'):p==='/admin/agent-update-sign-floor'?floorResponse('deployment'):f.responses(p));await f.c.renderAgentReleaseList(f.host);for(const route of ['agent-updates','agent-update-sign-floor'])assert.ok(f.requests.some(r=>r[1]==='/admin/'+route+'?expected_tenant_id=deployment'));assert.ok(f.requests.some(r=>r[1]==='/admin/agent-rollout?expected_tenant_id=own'));assert.equal(f.c.window._arCanSign,true)});
test('late signing response cannot restore publication caches after context departure',async()=>{const f=readFixture(),wait=deferred();let entered;const ready=new Promise(r=>entered=r);f.setAPI(async(m,p)=>{if(p==='/admin/agent-update-sign-floor'){entered();return wait.promise}return f.responses(p)});const run=f.c.renderAgentReleaseList(f.host);await ready;f.host.isConnected=false;wait.resolve(floorResponse());await run;assert.equal(f.c.window._arLastPublished,undefined);assert.equal(f.c.window._arCanSign,undefined);assert.equal(f.host.children.length,0)});

// Publishing a signed file must use that file's target/version and the package
// that was checked, regardless of form defaults or input changes during hashing.
function publishFixture(manifestChanges={},canSign=false) {
 const f=fixture(),uploads=[];let closed=0,rendered=0;
 const m={schema:'1',version:'0.3.2',platform:'windows',arch:'arm64',channel:'stable',delivery:'dsse',artifact_kind:'msi',artifact_url:'https://example.test/package.msi',artifact_sha256:'a'.repeat(64),artifact_size:32,released_at:'2026-09-18T00:00:00Z',not_after:'2026-10-18T00:00:00Z',...manifestChanges};
 const env={type:'dsse_agent_update_manifest.v1',version:'1',payload_b64:Buffer.from(JSON.stringify(m)).toString('base64'),payload_sha256:'b'.repeat(64)};
 const file={name:'package.msi',size:32},signedFile={text:async()=>JSON.stringify(env)},host={};
 f.c.atob=s=>Buffer.from(s,'base64').toString('binary');f.c.window={_arCanSign:canSign,_arLastPublished:{},_arReleaseReadContext:{host,scope:'deployment',current:()=>true,signingKnown:true,canSign}};
 f.c.uiField=opts=>{const field={el:f.c.el(opts.type==='select'?'select':'input'),value:opts.value??'',get(){return this.value},set(v){this.value=v},validate(){return Boolean(this.value)},setError(error){this.error=error}};f.fields[opts.name]=field;return field};
 f.c.uiModal=opts=>{f.dialog=opts;return{close(){closed++}}};f.c.renderAgentReleaseList=()=>rendered++;f.c.arHash=async()=>m.artifact_sha256;
 let sent=m;
 f.c.apiFetch=async(...a)=>{f.requests.push(a);sent=a[0]==='PUT'?JSON.parse(Buffer.from(a[2].payload_b64,'base64').toString()):a[2];return{ok:true,status:200,body:{schema_version:'admin_agent_updates.v1',tenant_id:'deployment',manifest_sha256:'b'.repeat(64),published:{platform:sent.platform,arch:sent.arch,version:sent.version,artifact_size:sent.artifact_size,artifact_sha256:sent.artifact_sha256},state:'pending'}}};
 f.c.arUploadArtifact=async(...a)=>{uploads.push(a);return{ok:true,status:200,body:{schema_version:'admin_agent_updates.v1',tenant_id:'deployment',manifest_sha256:'b'.repeat(64),stored:{platform:sent.platform,arch:sent.arch,version:sent.version,bytes:sent.artifact_size,artifact_sha256:sent.artifact_sha256},activated:true,active:true}}};
 f.c.openAgentReleaseForm(host);const inputs=f.nodes.filter(n=>n.type==='file');inputs[0].files=[file];inputs[0].handlers.change();inputs[1].files=[signedFile];inputs[1].handlers.change();
 f.fields.target.set('darwin/arm64');f.fields.version.set('9.9.9');f.fields.url.set('https://wrong.example.test/form.pkg');
 return{...f,m,env,file,signedFile,inputs,uploads,host,submit:(f.modal||f.dialog).footer[1],get closed(){const b=f.nodes.findLast(n=>n.class==='ui-modal-backdrop');return b?Number(!b.isConnected):closed},get rendered(){return rendered}};
}
for(const platform of ['windows','darwin'])for(const arch of ['amd64','arm64'])test('signed publication uses manifest identity for '+platform+'/'+arch,async()=>{
 const f=publishFixture({platform,arch,artifact_kind:platform==='windows'?'msi':'pkg'});await f.submit.handlers.click();assert.equal(f.requests.length,1);assert.equal(f.requests[0][0],'PUT');assert.deepEqual(json(f.requests[0][2]),f.env);assert.deepEqual(f.uploads[0].slice(0,3),[f.file,platform,arch]);assert.equal(f.closed,1);assert.ok(f.toasts.some(x=>x[0]==='0.3.2 is now what these devices are offered.'));assert.ok(f.toasts.every(x=>!x[0].includes('9.9.9')));
});
for(const [name,change] of Object.entries({size:m=>m.artifact_size=31,'string size':m=>m.artifact_size='32','unsafe size':m=>m.artifact_size=Number.MAX_SAFE_INTEGER+1,digest:m=>m.artifact_sha256='b'.repeat(64),platform:m=>m.platform='linux',arch:m=>m.arch='386',version:m=>m.version=''}))test('signed package rejects mismatched '+name+' before publication',async()=>{
 const f=publishFixture();const m={...f.m};change(m);f.signedFile.text=async()=>JSON.stringify({...f.env,payload_b64:Buffer.from(JSON.stringify(m)).toString('base64')});await f.submit.handlers.click();assert.equal(f.requests.length,0);assert.equal(f.uploads.length,0);assert.equal(f.closed,0);assert.equal(f.submit.disabled,false);assert.equal(f.toasts.length,1);
});
test('signed publication reports actual version when upload fails',async()=>{const f=publishFixture();f.c.arUploadArtifact=async()=>({ok:false,status:500,body:{error:'offline'}});await f.submit.handlers.click();assert.equal(f.closed,0);assert.ok(f.nodes.some(n=>String(n.textContent).startsWith('0.3.2 was published, but package delivery could not be confirmed')));assert.ok(f.toasts.every(x=>!x[0].includes('9.9.9')))});
for(const signed of [true,false])test('publication snapshots files and fields before hashing signed='+signed,async()=>{
 const f=publishFixture({},!signed),wait=deferred();if(!signed){f.c.window._arCanSign=true;f.inputs[1].files=[];f.inputs[1].handlers.change();f.fields.target.set('windows/amd64');f.fields.version.set('0.3.3')}
 f.c.arHash=async file=>{assert.equal(file,f.file);return wait.promise};const first=f.submit.handlers.click();f.inputs[0].files=[{name:'other.pkg',size:99}];f.inputs[0].handlers.change();f.inputs[1].files=[{text:async()=>'{broken'}];f.inputs[1].handlers.change();f.fields.target.set('darwin/amd64');f.fields.version.set('8.8.8');f.fields.url.set('https://changed.example.test/other.pkg');wait.resolve('a'.repeat(64));await first;
 assert.equal(f.requests.length,1);assert.equal(f.uploads[0][0],f.file);assert.deepEqual(f.uploads[0].slice(1,3),signed?['windows','arm64']:['windows','amd64']);
 if(!signed){assert.equal(f.requests[0][0],'POST');const m=f.requests[0][2];assert.equal(m.artifact_size,32);assert.equal(m.version,'0.3.3');assert.equal(m.artifact_url,'https://wrong.example.test/form.pkg')}
});
test('signed digest comparison remains case insensitive',async()=>{const f=publishFixture({artifact_sha256:'A'.repeat(64)});f.c.arHash=async()=> 'a'.repeat(64);await f.submit.handlers.click();assert.equal(f.uploads.length,1)});

for(const phase of ['hash','signed-file','publish','upload'])test('publication pins context and discards late completion during '+phase,async()=>{
 const f=publishFixture(),wait=deferred();let valid=true;f.c.window._arReleaseReadContext.current=()=>valid;
 const api=f.c.apiFetch,upload=f.c.arUploadArtifact;if(phase==='hash')f.c.arHash=()=>wait.promise;if(phase==='signed-file')f.signedFile.text=()=>wait.promise;if(phase==='publish')f.c.apiFetch=async(...a)=>{const r=await api(...a);await wait.promise;return r};if(phase==='upload')f.c.arUploadArtifact=async(...a)=>{const r=await upload(...a);await wait.promise;return r};
 const run=f.submit.handlers.click();for(let i=0;i<12;i++)await Promise.resolve();valid=false;f.mutation();wait.resolve(phase==='hash'?'a'.repeat(64):phase==='signed-file'?JSON.stringify(f.env):null);await run;
 assert.equal(f.closed,1);assert.equal(f.toasts.length,0);assert.equal(f.rendered,0);assert.equal(f.requests.length,['publish','upload'].includes(phase)?1:0);assert.equal(f.uploads.length,phase==='upload'?1:0);
});
test('publication locks every control, ignores dismissal and blocks reentry while pending',async()=>{
 const f=publishFixture(),wait=deferred();f.c.arHash=()=>wait.promise;const run=f.submit.handlers.click();const backdrop=f.nodes.findLast(n=>n.class==='ui-modal-backdrop');assert.ok(backdrop);const controls=allNodes(backdrop).filter(n=>['input','select','textarea','button'].includes(n.tag));assert.ok(controls.length>=7&&controls.every(n=>n.disabled));const count=f.nodes.length;f.c.openAgentReleaseForm(f.host);assert.equal(f.nodes.length,count);f.modal.footer[0].onClick();f.listeners.get('keydown')({key:'Escape'});backdrop.onClick({target:backdrop});assert.equal(f.closed,0);await f.submit.handlers.click();wait.resolve('a'.repeat(64));await run;assert.equal(f.requests.length,1);assert.equal(f.closed,1);
});
for(const mode of ['empty','scope','schema','status','target','version','size','digest','manifest','state'])test('publication refuses unconfirmed acknowledgement '+mode,async()=>{
 const f=publishFixture(),api=f.c.apiFetch;f.c.apiFetch=async(...a)=>{const r=await api(...a),b=r.body;if(mode==='empty')r.body={};if(mode==='scope')b.tenant_id='other';if(mode==='schema')b.schema_version='other';if(mode==='status')r.status=206;if(mode==='target')b.published.arch='amd64';if(mode==='version')b.published.version='9.9.9';if(mode==='size')b.published.artifact_size++;if(mode==='digest')b.published.artifact_sha256='c'.repeat(64);if(mode==='manifest')b.manifest_sha256='c'.repeat(64);if(mode==='state')b.state='unknown';return r};await f.submit.handlers.click();assert.equal(f.closed,0);assert.equal(f.uploads.length,0);assert.equal(f.submit.disabled,false);assert.equal(f.toasts.length,0);assert.ok(f.nodes.some(n=>n.role==='alert'&&String(n.textContent).includes('may already be saved')));
});
for(const mode of ['empty','scope','schema','status','target','version','bytes','digest','manifest','active','activated'])test('upload refuses unconfirmed acknowledgement '+mode,async()=>{
 const f=publishFixture(),upload=f.c.arUploadArtifact;f.c.arUploadArtifact=async(...a)=>{const r=await upload(...a),b=r.body;if(mode==='empty')r.body={};if(mode==='scope')b.tenant_id='other';if(mode==='schema')b.schema_version='other';if(mode==='status')r.status=206;if(mode==='target')b.stored.arch='amd64';if(mode==='version')b.stored.version='9.9.9';if(mode==='bytes')b.stored.bytes++;if(mode==='digest')b.stored.artifact_sha256='c'.repeat(64);if(mode==='manifest')b.manifest_sha256='c'.repeat(64);if(mode==='active')b.active=false;if(mode==='activated')delete b.activated;return r};await f.submit.handlers.click();assert.equal(f.closed,0);assert.equal(f.submit.disabled,false);assert.equal(f.toasts.length,0);assert.ok(f.nodes.some(n=>n.role==='alert'&&String(n.textContent).includes('may already be active')));
});
for(const phase of ['publish','upload'])test('network rejection unlocks publication with persistent uncertainty and explicit retry '+phase,async()=>{const f=publishFixture(),method=phase==='publish'?'apiFetch':'arUploadArtifact',original=f.c[method];f.c[method]=async()=>{throw Error('connection lost')};await f.submit.handlers.click();assert.equal(f.closed,0);assert.equal(f.submit.disabled,false);assert.ok(f.nodes.some(n=>n.role==='alert'));f.c[method]=original;await f.submit.handlers.click();assert.equal(f.closed,1);assert.equal(f.toasts.at(-1)[1],'ok')});
test('publication and upload carry the verified scope and acknowledged manifest pin',async()=>{const f=publishFixture();await f.submit.handlers.click();assert.match(f.requests[0][1],/expected_tenant_id=deployment/);assert.deepEqual(json(f.uploads[0][3]),{scope:'deployment',manifestSHA256:'b'.repeat(64)})});
test('upload already active is accepted without claiming this request newly activated it',async()=>{const f=publishFixture(),upload=f.c.arUploadArtifact;f.c.arUploadArtifact=async(...a)=>{const r=await upload(...a);r.body.activated=false;return r};await f.submit.handlers.click();assert.equal(f.closed,1);assert.equal(f.toasts.at(-1)[1],'ok')});

for (const kind of ['agent', 'connector']) test(kind + ' raw upload preserves its own route and authentication contract', async () => {
 const f = fixture(), requests = [], bytes = new Uint8Array([1, 2, 3]);
 Object.assign(f.c, { baseForPlane: () => '/control', localStorage: { getItem: () => 'unused-token' }, idpSession: { auth_method: 'admin_session', csrf_token: 'csrf' }, operateTenant: 'selected', fetch: async (url, opts) => { requests.push({ url, opts }); return { ok: true, status: 200, text: async () => '{"stored":true}' }; } });
 const response = kind === 'agent'
   ? await f.c.arUploadArtifact(bytes, 'windows', 'arm64', { scope: 'selected', manifestSHA256: 'b'.repeat(64) })
   : await f.c.arUploadConnectorProgram(bytes, 'windows', 'arm64', 'c'.repeat(64), '0.3.2');
 assert.equal(response.ok, true); assert.deepEqual(json(response.body), { stored: true }); assert.equal(requests.length, 1);
 const { url, opts } = requests[0], q = new URL(url, 'http://localhost');
 assert.equal(q.pathname, kind === 'agent' ? '/control/admin/agent-update-artifact' : '/control/admin/connector-program');
 assert.equal(q.searchParams.get('platform'), 'windows'); assert.equal(q.searchParams.get('arch'), 'arm64');
 assert.equal(q.searchParams.get('expected_tenant_id'), kind === 'agent' ? 'selected' : null);
 assert.equal(q.searchParams.get('expected_manifest_sha256'), kind === 'agent' ? 'b'.repeat(64) : null);
 assert.equal(opts.method, 'PUT'); assert.equal(opts.body, bytes); assert.equal(opts.credentials, 'include');
 assert.equal(opts.headers['x-csrf-token'], 'csrf'); assert.equal(opts.headers['x-operate-tenant'], 'selected'); assert.equal(opts.headers.authorization, undefined);
 if (kind === 'connector') { assert.equal(opts.headers['x-artifact-sha256'], 'c'.repeat(64)); assert.equal(opts.headers['x-artifact-version'], '0.3.2'); }
});

function resumeFixture(signed=true) {
 const f=publishFixture({},!signed);
 if(!signed){f.inputs[1].files=[];f.inputs[1].handlers.change();f.fields.target.set('windows/amd64');f.fields.version.set('0.3.3')}
 return f;
}
async function failedPackage(f,mode='http') {
 const upload=f.c.arUploadArtifact;
 f.c.arUploadArtifact=async(...args)=>{const r=await upload(...args);if(mode==='network')throw Error('lost response');if(mode==='ack')r.body.active=false;else {r.ok=false;r.status=500}return r};
 await f.submit.handlers.click();f.c.arUploadArtifact=upload;
 assert.equal(f.closed,0);assert.equal(f.requests.length,1);assert.equal(f.uploads.length,1);
}
for(const signed of [true,false])test('confirmed publication retries only its package signed='+signed,async()=>{
 const f=resumeFixture(signed);await failedPackage(f);
 assert.equal(f.submit.textContent,'Retry package');assert.equal(f.submit.disabled,false);assert.equal(f.modal.footer[0].disabled,false);
 assert.ok(f.nodes.filter(n=>['input','select'].includes(n.tag)).every(n=>n.disabled));
 f.c.arHash=async()=>{throw Error('must not hash/sign a second publication')};f.signedFile.text=async()=>{throw Error('must not reopen signed manifest')};
 await f.submit.handlers.click();assert.equal(f.requests.length,1);assert.equal(f.uploads.length,2);assert.equal(f.uploads[1][0],f.file);assert.deepEqual(json(f.uploads[1][3]),json(f.uploads[0][3]));assert.equal(f.closed,1);
});
for(const signed of [true,false])test('upload resume ignores changed form and file references signed='+signed,async()=>{
 const f=resumeFixture(signed);await failedPackage(f);const first=f.uploads[0];
 f.inputs[0].files=[{name:'other.pkg',size:99}];f.inputs[0].handlers.change();f.inputs[1].files=[];f.inputs[1].handlers.change();f.fields.target.set('darwin/amd64');f.fields.version.set('');f.fields.url.set('');
 await f.submit.handlers.click();assert.equal(f.requests.length,1);assert.equal(f.uploads.length,2);assert.equal(f.uploads[1][0],first[0]);assert.deepEqual(json(f.uploads[1].slice(1)),json(first.slice(1)));assert.equal(f.closed,1);
});
for(const mode of ['network','ack','http'])test('unconfirmed package result retains one publication across retries '+mode,async()=>{
 const f=resumeFixture();await failedPackage(f,mode);const upload=f.c.arUploadArtifact;
 f.c.arUploadArtifact=async(...a)=>{const r=await upload(...a);r.ok=false;r.status=409;return r};await f.submit.handlers.click();assert.equal(f.requests.length,1);assert.equal(f.uploads.length,2);assert.equal(f.closed,0);assert.equal(f.toasts.length,0);assert.equal(f.submit.textContent,'Retry package');
 f.c.arUploadArtifact=async(...a)=>{const r=await upload(...a);r.body.activated=false;return r};await f.submit.handlers.click();assert.equal(f.requests.length,1);assert.equal(f.uploads.length,3);assert.equal(f.closed,1);
});
for(const phase of ['before','during'])test('upload resume discards changed context '+phase,async()=>{
 const f=resumeFixture();await failedPackage(f);let valid=true;f.c.window._arReleaseReadContext.current=()=>valid;const wait=deferred(),upload=f.c.arUploadArtifact;
 if(phase==='before')valid=false;else f.c.arUploadArtifact=async(...a)=>{const r=await upload(...a);await wait.promise;return r};
 const run=f.submit.handlers.click();await Promise.resolve();valid=false;f.mutation();wait.resolve();await run;
 assert.equal(f.closed,1);assert.equal(f.requests.length,1);assert.equal(f.uploads.length,phase==='before'?1:2);assert.equal(f.rendered,0);assert.equal(f.toasts.length,0);
});
for(const kind of ['cancel','escape','backdrop'])test('unconfirmed package can be dismissed without another write '+kind,async()=>{
 const f=resumeFixture();await failedPackage(f);assert.equal(f.submit.textContent,'Retry package');
 if(kind==='cancel')f.modal.footer[0].onClick();if(kind==='escape')f.listeners.get('keydown')({key:'Escape'});if(kind==='backdrop'){const b=f.nodes.findLast(n=>n.class==='ui-modal-backdrop');b.onClick({target:b})}
 assert.equal(f.closed,1);assert.equal(f.requests.length,1);assert.equal(f.uploads.length,1);
});
for(const signed of [true,false])test('unconfirmed publication cannot become an upload-only retry signed='+signed,async()=>{
 const f=resumeFixture(signed),api=f.c.apiFetch;f.c.apiFetch=async(...a)=>{const r=await api(...a);r.body={};return r};await f.submit.handlers.click();assert.equal(f.requests.length,1);assert.equal(f.uploads.length,0);assert.equal(f.submit.textContent??f.submit.text,'Publish');assert.ok(f.nodes.filter(n=>['input','select'].includes(n.tag)).every(n=>!n.disabled));
 f.c.apiFetch=api;await f.submit.handlers.click();assert.equal(f.requests.length,2);assert.equal(f.uploads.length,1);assert.equal(f.closed,1);
});
test('package resume locks dismissal and ignores another submit until upload settles',async()=>{
 const f=resumeFixture();await failedPackage(f);const upload=f.c.arUploadArtifact,wait=deferred();
 f.c.arUploadArtifact=async(...a)=>{const r=await upload(...a);await wait.promise;return r};const run=f.submit.handlers.click();await Promise.resolve();
 const b=f.nodes.findLast(n=>n.class==='ui-modal-backdrop');assert.ok(allNodes(b).filter(n=>['input','select','button'].includes(n.tag)).every(n=>n.disabled));f.modal.footer[0].onClick();f.listeners.get('keydown')({key:'Escape'});b.onClick({target:b});await f.submit.handlers.click();assert.equal(f.closed,0);assert.equal(f.requests.length,1);assert.equal(f.uploads.length,2);wait.resolve();await run;assert.equal(f.closed,1);
});

function downloadFixture(platform='windows',arch='amd64') {
 const f=fixture(),downloads=[],raw=[],revoked=[],timers=[];let valid=true;
 const bytes=new Uint8Array([1,2,3]),manifest={platform,arch,version:'0.3.2',artifact_size:3,artifact_sha256:'039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81'};
 const context={scope:'deployment',manifestSHA256:'b'.repeat(64),current:()=>valid};
 const response={ok:true,status:200,headers:new Headers({'X-Dsse-Agent-Update-Scope':'deployment','X-Dsse-Agent-Update-Manifest-SHA256':context.manifestSHA256,'X-Dsse-Agent-Update-Version':manifest.version}),blob:async()=>new Blob([bytes])};
 Object.assign(f.c,{crypto:globalThis.crypto,baseForPlane:()=>'/control',localStorage:{getItem:()=> 'token'},idpSession:{auth_method:'admin_session',csrf_token:'csrf'},operateTenant:'',fetch:async(...a)=>{raw.push(a);return response},URL:{createObjectURL:()=> 'blob:test',revokeObjectURL:u=>revoked.push(u)},setTimeout:fn=>timers.push(fn)});
 f.c.document.createElement=tag=>{const n=f.c.el(tag);n.click=()=>downloads.push({name:n.download,url:n.href});return n};
 return{...f,manifest,context,response,downloads,raw,revoked,timers,invalidate:()=>valid=false,run:()=>f.c.arDownloadArtifact(platform,arch,manifest,context)};
}
for(const platform of ['windows','darwin'])for(const arch of ['amd64','arm64'])test('download verifies and names original bytes '+platform+'/'+arch,async()=>{
 const f=downloadFixture(platform,arch);await f.run();assert.deepEqual(f.downloads,[{name:`dsse-agent-0.3.2-${platform}-${arch}.${platform==='windows'?'msi':'pkg'}`,url:'blob:test'}]);assert.equal(f.toasts.length,0);const [url,opts]=f.raw[0];assert.ok(url.includes('artifact_scope=publication&expected_tenant_id=deployment&expected_manifest_sha256='+'b'.repeat(64)));assert.equal(opts.redirect,'error');assert.equal(opts.cache,'no-store');assert.equal(opts.credentials,'include');assert.equal(opts.headers['x-csrf-token'],'csrf');assert.equal(opts.headers.authorization,undefined);f.timers.forEach(fn=>fn());assert.deepEqual(f.revoked,['blob:test']);
});
for(const mode of ['partial','empty-status','http-error','wrong-scope','missing-scope','wrong-hash','missing-hash','wrong-version','missing-version'])test('download refuses response '+mode,async()=>{
 const f=downloadFixture(),r=f.response;if(mode==='partial')r.status=206;if(mode==='empty-status')r.status=204;if(mode==='http-error'){r.ok=false;r.status=404};for(const [field,key,value] of [['scope','X-Dsse-Agent-Update-Scope','other'],['hash','X-Dsse-Agent-Update-Manifest-SHA256','c'.repeat(64)],['version','X-Dsse-Agent-Update-Version','0.3.3']]){if(mode==='wrong-'+field)r.headers.set(key,value);if(mode==='missing-'+field)r.headers.delete(key)}
 await f.run();assert.equal(f.downloads.length,0);assert.equal(f.toasts.length,1);assert.equal(f.toasts[0][1],'err');
});
for(const mode of ['empty','wrong-size','wrong-digest'])test('download refuses package bytes '+mode,async()=>{const f=downloadFixture();f.response.blob=async()=>new Blob([new Uint8Array(mode==='empty'?[]:mode==='wrong-size'?[1,2]:[1,2,4])]);await f.run();assert.equal(f.downloads.length,0);assert.equal(f.toasts.length,1)});
for(const phase of ['fetch','blob'])test('download catches '+phase+' failure without saving a file',async()=>{const f=downloadFixture();if(phase==='fetch')f.c.fetch=async()=>{throw Error('offline')};else f.response.blob=async()=>{throw Error('connection lost')};await f.run();assert.equal(f.downloads.length,0);assert.equal(f.toasts.length,1)});
for(const phase of ['fetch','blob','hash'])test('download discards late '+phase+' result after leaving context',async()=>{
 const f=downloadFixture(),wait=deferred();let entered;const ready=new Promise(r=>entered=r),fetch=f.c.fetch,blob=f.response.blob;
 if(phase==='fetch')f.c.fetch=async(...a)=>{const r=await fetch(...a);entered();await wait.promise;return r};if(phase==='blob')f.response.blob=async()=>{const r=await blob();entered();await wait.promise;return r};if(phase==='hash')f.c.arHash=async()=>{entered();await wait.promise;return f.manifest.artifact_sha256};
 const run=f.run();await Promise.race([ready,run]);f.invalidate();wait.resolve();await run;assert.equal(f.downloads.length,0);assert.equal(f.toasts.length,0);
});
for(const mode of ['target','size','digest','manifest-hash'])test('download refuses incomplete expected manifest '+mode,async()=>{const f=downloadFixture();if(mode==='target')f.manifest.arch='other';if(mode==='size')f.manifest.artifact_size='3';if(mode==='digest')f.manifest.artifact_sha256='bad';if(mode==='manifest-hash')f.context.manifestSHA256='bad';await f.run();assert.equal(f.raw.length,0);assert.equal(f.downloads.length,0);assert.equal(f.toasts.length,1)});
test('download copies expected manifest and scope before asynchronous work',async()=>{const f=downloadFixture(),wait=deferred(),fetch=f.c.fetch;f.c.fetch=async(...a)=>{await wait.promise;return fetch(...a)};const run=f.run();f.manifest.version='9.9.9';f.manifest.artifact_size=99;f.context.scope='other';f.context.manifestSHA256='c'.repeat(64);wait.resolve();await run;assert.equal(f.downloads[0]?.name,'dsse-agent-0.3.2-windows-amd64.msi');assert.equal(f.toasts.length,0)});
test('download ignores departed context before any request',async()=>{const f=downloadFixture();f.invalidate();await f.run();assert.equal(f.raw.length,0);assert.equal(f.downloads.length,0);assert.equal(f.toasts.length,0)});
for(const present of [true,false])test('download distinguishes an explicit empty legacy scope header present='+present,async()=>{const f=downloadFixture();f.context.scope='';if(present)f.response.headers.set('X-Dsse-Agent-Update-Scope','');else f.response.headers.delete('X-Dsse-Agent-Update-Scope');await f.run();assert.equal(f.downloads.length,present?1:0)});
test('download carries selected tenant and bearer authentication without a session',async()=>{const f=downloadFixture();f.context.scope='other';f.response.headers.set('X-Dsse-Agent-Update-Scope','other');f.c.idpSession=null;f.c.operateTenant='other';await f.run();assert.equal(f.downloads.length,1);const headers=f.raw[0][1].headers;assert.equal(headers.authorization,'Bearer token');assert.equal(headers['x-operate-tenant'],'other');assert.equal(headers['x-csrf-token'],undefined)});
test('catalogue download prevents concurrent clicks and unlocks afterward',async()=>{const f=readFixture(),wait=deferred(),calls=[];f.c.arDownloadArtifact=async(...args)=>{calls.push(args);await wait.promise};f.setAPI(async(m,p)=>p==='/admin/agent-updates'?catalogueResponse('own','0.3.0'):f.responses(p));await f.c.renderAgentReleaseList(f.host);const button=allNodes(f.host).find(n=>n.text==='Download');assert.ok(button);const click=button.handlers.click||button.onClick;const run=click();assert.equal(button.disabled,true);await click();assert.equal(calls.length,1);assert.equal(calls[0][2].version,'0.3.0');assert.equal(calls[0][3].scope,'own');wait.resolve();await run;assert.equal(button.disabled,false)});

for (const language of ['en', 'ja']) {
  for (const kind of ['size', 'digest', 'scope', 'catalogue', 'verification', 'transfer']) {
    test(`download remediation identifies ${kind} in ${language} without saving`, async () => {
      const f = downloadFixture(); f.c.bl = text => text[language];
      if (kind === 'size') f.response.blob = async () => new Blob(['x']);
      if (kind === 'digest') f.response.blob = async () => new Blob(['bad']);
      if (kind === 'scope') f.response.headers.set('X-Dsse-Agent-Update-Scope', 'other');
      if (kind === 'catalogue') f.response.headers.set('X-Dsse-Agent-Update-Version', 'other');
      if (kind === 'verification') f.c.arHash = async () => { throw Error('sensitive browser detail'); };
      if (kind === 'transfer') f.response.blob = async () => { throw Error('sensitive network detail'); };
      await f.run(); assert.equal(f.downloads.length, 0); assert.equal(f.toasts.length, 1);
      const message = f.toasts[0][0]; assert.doesNotMatch(message, /sensitive/);
      const expected = language === 'en'
        ? {size: /size does not match/, digest: /SHA-256 digest does not match/, scope: /selected organization/, catalogue: /Reload the release list/, verification: /check could not be completed/, transfer: /transfer could not be completed/}
        : {size: /サイズが公開済み/, digest: /SHA-256 ハッシュが公開済み/, scope: /選択中の組織/, catalogue: /配布一覧を再読込/, verification: /完全性確認を完了できず/, transfer: /取得できず/};
      assert.match(message, expected[kind]);
      if (kind === 'size' || kind === 'digest') {
        assert.match(message, language === 'en' ? /Do not distribute.*investigate/ : /配布せず.*調査/);
        assert.doesNotMatch(message, /reload|try again|再読込|再試行/i);
      }
    });
  }
}
for (const phase of ['blob', 'hash']) test('late rejected '+phase+' does not warn a different context', async () => {
  const f=downloadFixture(), wait=deferred(); let entered; const ready=new Promise(r=>entered=r);
  const reject=async()=>{entered();await wait.promise;throw Error('late');};
  if(phase==='blob')f.response.blob=reject;else f.c.arHash=reject;
  const run=f.run();await ready;f.invalidate();wait.resolve();await run;
  assert.equal(f.downloads.length,0);assert.equal(f.toasts.length,0);
});

function connectorUploadFixture(){
 const f=fixture(),uploads=[];let valid=true,refreshes=0;
 Object.assign(f.c,{operateTenant:'',idpSession:{auth_method:'admin_session'},localStorage:{getItem:()=>''},crypto:{subtle:{digest:async()=>new Uint8Array(32).buffer}},connectorProgramsLoader:()=>async()=>refreshes++});
 f.c.arUploadConnectorProgram=async(bytes,platform,arch,sha256,version)=>{uploads.push({bytes,platform,arch,sha256,version});return{ok:true,status:200,body:{platform,arch,sha256,version,size:bytes.byteLength,file_name:`dsse-connector-${platform}-${arch}.tar.gz`,published_at:'2026-09-18T00:00:00Z'}}};
 const card=f.c.arConnectorProgramsSection(()=>valid),nodes=allNodes(card),file=nodes.find(n=>n.type==='file'),pair=nodes.find(n=>n.tag==='select'),version=nodes.find(n=>n.type==='text'),submit=nodes.find(n=>n.text==='Add it'),error=nodes.find(n=>n.role==='alert');
 error.style={};file.value='selected';file.files=[{size:3,arrayBuffer:async()=>new Uint8Array([1,2,3]).buffer}];pair.value='linux/amd64';version.value='build-1';
 return{...f,card,file,pair,version,submit,error,uploads,invalidate:()=>valid=false,get refreshes(){return refreshes},run:()=>submit.handlers.click()};
}
test('connector upload confirms exact metadata and clears only confirmed file',async()=>{const f=connectorUploadFixture();await f.run();assert.equal(f.uploads.length,1);assert.equal(f.file.value,'');assert.equal(f.toasts.at(-1)[1],'ok');assert.equal(f.refreshes,2);assert.equal(f.submit.disabled,false)});
for(const mode of ['empty','status','target','version','null-version','size','digest','filename','timestamp','publisher','network'])test('connector upload retains uncertain '+mode,async()=>{
 const f=connectorUploadFixture(),upload=f.c.arUploadConnectorProgram;
 f.c.arUploadConnectorProgram=async(...a)=>{const r=await upload(...a),b=r.body;if(mode==='empty')r.body={};if(mode==='status')r.status=206;if(mode==='target')b.arch='arm64';if(mode==='version')b.version='other';if(mode==='null-version'){f.version.value='';b.version=null}if(mode==='size')b.size++;if(mode==='digest')b.sha256='b'.repeat(64);if(mode==='filename')b.file_name='wrong';if(mode==='timestamp')b.published_at='invalid';if(mode==='publisher')b.published_by={};if(mode==='network')throw Error('private-path');return r};
 await f.run();assert.equal(f.uploads.length,1);assert.equal(f.file.value,'selected');assert.match(f.error.textContent,/may already be saved/);assert.doesNotMatch(f.error.textContent,/private-path/);assert.equal(f.toasts.length,0);assert.equal(f.refreshes,2);assert.ok([f.file,f.pair,f.version,f.submit].every(n=>!n.disabled));
 f.c.arUploadConnectorProgram=upload;await f.run();assert.equal(f.uploads.length,2);assert.equal(f.file.value,'');
});
test('connector upload freezes original fields and prevents overlapping submissions',async()=>{
 const f=connectorUploadFixture(),wait=deferred();f.c.crypto.subtle.digest=()=>wait.promise;const run=f.run();await Promise.resolve();assert.ok([f.file,f.pair,f.version,f.submit].every(n=>n.disabled));await f.run();f.pair.value='linux/arm64';f.version.value='changed';wait.resolve(new Uint8Array(32).buffer);await run;assert.equal(f.uploads.length,1);assert.equal(f.uploads[0].arch,'amd64');assert.equal(f.uploads[0].version,'build-1');
});
for(const key of ['parent','session','selection','authority','token','detached'])for(const phase of ['hash','upload'])test(`connector ignores obsolete ${key} during ${phase}`,async()=>{
 const f=connectorUploadFixture(),wait=deferred();let enter;const entered=new Promise(r=>enter=r);const upload=f.c.arUploadConnectorProgram;
 if(phase==='hash')f.c.crypto.subtle.digest=()=>{enter();return wait.promise};else f.c.arUploadConnectorProgram=async(...a)=>{const r=await upload(...a);enter();await wait.promise;return r};
 const run=f.run();await entered;if(key==='parent')f.invalidate();if(key==='session')f.c.idpSession={};if(key==='selection')f.c.operateTenant='other';if(key==='authority')f.c.baseForPlane=()=>'/new';if(key==='token')f.c.localStorage.getItem=()=> 'new';if(key==='detached')f.card.isConnected=false;
 wait.resolve(new Uint8Array(32).buffer);await run;assert.equal(f.uploads.length,phase==='hash'?0:1);assert.equal(f.toasts.length,0);assert.equal(f.error.textContent,'');assert.equal(f.file.value,'selected');assert.equal(f.refreshes,1);
});
for(const mode of ['oversized','file','hash'])test('connector preparation failure never sends '+mode,async()=>{
 const f=connectorUploadFixture();if(mode==='oversized')f.file.files[0].size=64*1024*1024+1;if(mode==='file')f.file.files[0].arrayBuffer=async()=>{throw Error('private-path')};if(mode==='hash')f.c.crypto.subtle.digest=async()=>{throw Error('private-path')};await f.run();assert.equal(f.uploads.length,0);assert.match(f.error.textContent,/no upload was sent/);assert.equal(f.file.value,'selected');assert.equal(f.submit.disabled,false);
});
test('connector upload Japanese distinguishes unsent and uncertain',()=>{const f=connectorUploadFixture();f.c.bl=x=>x.ja;assert.match(f.c.arConnectorUploadError(true),/保存済み/);assert.match(f.c.arConnectorUploadError(false),/送信していません/)});
test('connector catalogue starts before its card is attached',async()=>{
 const f=fixture(),el=f.c.el;let reads=0;
 Object.assign(f.c,{operateTenant:'',idpSession:{},freshRender:()=>()=>true,uiState(){},apiFetch:async()=>{reads++;return{ok:true,status:200,body:{programs:[],count:0}}},el:(...a)=>{const n=el(...a);if(n.class==='ui-card')n.isConnected=false;return n}});
 const card=f.c.arConnectorProgramsSection();assert.equal(reads,1);card.isConnected=true;for(let i=0;i<6;i++)await Promise.resolve();assert.ok(allNodes(card).some(n=>String(n.text).includes('None yet')));
});
test('connector acknowledgement accepts omitted empty version but rejects null',()=>{const f=fixture(),expected={platform:'linux',arch:'amd64',sha256:'a'.repeat(64),size:0,version:''},body={...expected,file_name:'dsse-connector-linux-amd64.tar.gz',published_at:'2026-09-18T00:00:00Z'};delete body.version;assert.ok(f.c.arConnectorProgramAck({ok:true,status:200,body},expected));body.version=null;assert.throws(()=>f.c.arConnectorProgramAck({ok:true,status:200,body},expected))});
for(const phase of ['hash','upload'])test('connector suppresses obsolete failure '+phase,async()=>{const f=connectorUploadFixture();let reject,enter;const entered=new Promise(r=>enter=r),wait=()=>{enter();return new Promise((_,r)=>reject=r)};if(phase==='hash')f.c.crypto.subtle.digest=wait;else f.c.arUploadConnectorProgram=wait;const run=f.run();await entered;f.invalidate();reject(Error('late private detail'));await run;assert.equal(f.error.textContent,'');assert.equal(f.toasts.length,0)});
