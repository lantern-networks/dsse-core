import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';
const source=readFileSync(new URL('./agentreleases.js',import.meta.url),'utf8');
function fixture(){
 const nodes=[],fields={},toasts=[],requests=[],listeners=new Map();let modal,observed;
 const el=(tag,props={},children=[])=>{const n={tag,...props,isConnected:true,children:Array.isArray(children)?children:[children],handlers:{},appendChild(x){this.children.push(x)},remove(){this.isConnected=false},setAttribute(k,v){this[k]=v},focus(){},addEventListener(k,f){this.handlers[k]=f},querySelectorAll(selector){const tags=selector.split(',');return allNodes(this).filter(n=>tags.includes(n.tag))}};Object.defineProperty(n,'innerHTML',{set(){this.children=[]}});nodes.push(n);return n};
 const c=vm.createContext({el,bl:x=>x.en,uiField:opts=>{const f={el:el('input'),value:opts.value,get(){return this.value},setError(error){this.error=error},focus(){}};fields[opts.name]=f;return f},uiModal:opts=>{modal=opts;return{close(){}}},uiToast:(...a)=>toasts.push(a),apiFetch:async(...a)=>{requests.push(a);return{ok:false,status:500}},document:{body:el('body'),createTextNode:s=>s,addEventListener:(k,f)=>listeners.set(k,f),removeEventListener:k=>listeners.delete(k)},MutationObserver:class {constructor(f){observed=f} observe(){} disconnect(){observed=null}}});
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
 Object.assign(f.c,{window:{},operateTenant:'',answeringForTheDeployment:()=>false,uiBadge:(text)=>({text}),uiWhen:x=>x,atob:s=>Buffer.from(s,'base64').toString(),uiState:(host,type,text)=>{host.innerHTML='';host.state={type,text}},freshRender:host=>{const n=host.seq=(host.seq||0)+1;return()=>host.seq===n},apiFetch:(...args)=>{f.requests.push(args);return api(...args)}});
 const responses=path=>path.startsWith('/admin/agent-rollout')?planResponse(fullPlan()):{ok:true,status:200,body:path==='/admin/tenant'?{tenant_id:'own'}:path==='/admin/agent-updates'?{envelopes:{},pending:{}}:path==='/admin/enrolled-devices'?{devices:[]}:{floors:{},signing_public_key:'no'}};
 api=async(method,path)=>responses(path);const host={isConnected:true,children:[],appendChild(n){this.children.push(n)}};Object.defineProperty(host,'innerHTML',{set(){this.children=[]}});
 return{...f,host,responses,setAPI(fn){api=fn}};
}
const allNodes=root=>[root,...(root.children||[]).filter(x=>x&&typeof x==='object').flatMap(allNodes)];
test('incomplete successful plan disables all editors and offers retry',async()=>{const f=readFixture();f.setAPI(async(m,p)=>p.startsWith('/admin/agent-rollout')?planResponse({}):f.responses(p));await f.c.renderAgentReleaseList(f.host);const changes=allNodes(f.host).filter(x=>x.text==='Change');assert.equal(changes.length,3);assert.ok(changes.every(x=>x.disabled));assert.ok(allNodes(f.host).some(x=>x.text==='Retry'));assert.ok(!allNodes(f.host).some(x=>x.text==='not set — devices use their own defaults'));});
test('verified organization pins rollout read and keeps held settings editable',async()=>{const f=readFixture();await f.c.renderAgentReleaseList(f.host);assert.ok(f.requests.some(x=>x[1]==='/admin/agent-rollout?expected_tenant_id=own'));assert.ok(allNodes(f.host).filter(x=>x.text==='Change').every(x=>!x.disabled));assert.ok(allNodes(f.host).some(x=>String(x.text).includes('Updates paused: incident')))});
for(const name of ['missing','foreign-selection','unavailable'])test('organization '+name+' blocks rollout read',async()=>{const f=readFixture();if(name==='foreign-selection')f.c.operateTenant='other';f.setAPI(async(m,p)=>p==='/admin/tenant'?(name==='missing'?{ok:true,status:200,body:{}}:name==='unavailable'?{ok:false,status:503}:f.responses(p)):f.responses(p));await f.c.renderAgentReleaseList(f.host);assert.ok(!f.requests.some(x=>x[1].startsWith('/admin/agent-rollout')));assert.ok(allNodes(f.host).filter(x=>x.text==='Change').every(x=>x.disabled))});
const deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return{promise,resolve}};
test('late old render cannot replace shared publication cache',async()=>{const f=readFixture(),wait=deferred();let n=0;f.setAPI(async(m,p)=>{if(p==='/admin/agent-updates'){if(++n===1)return wait.promise;return{ok:true,status:200,body:{envelopes:{new:{}},pending:{}}}}return f.responses(p)});const old=f.c.renderAgentReleaseList(f.host);await f.c.renderAgentReleaseList(f.host);wait.resolve({ok:true,status:200,body:{envelopes:{old:{}},pending:{}}});await old;assert.deepEqual(json(f.c.window._arLastPublished),{new:{}})});
for(const name of ['departed','tenant-changed','deployment-changed'])test('late rollout response discarded after '+name,async()=>{const f=readFixture(),wait=deferred();let entered;const started=new Promise(r=>entered=r);f.setAPI(async(m,p)=>{if(p.startsWith('/admin/agent-rollout')){entered();return wait.promise}return f.responses(p)});const render=f.c.renderAgentReleaseList(f.host);await started;if(name==='departed')f.host.isConnected=false;if(name==='tenant-changed')f.c.operateTenant='other';if(name==='deployment-changed')f.c.answeringForTheDeployment=()=>true;wait.resolve(planResponse(fullPlan()));await render;assert.equal(f.c.window._arLastPublished,undefined);assert.equal(f.host.children.length,0)});
test('explicit legacy empty tenant remains bound to its own response',async()=>{const f=readFixture();f.setAPI(async(m,p)=>{const r=f.responses(p);if(p==='/admin/tenant'||p.startsWith('/admin/agent-rollout'))r.body.tenant_id='';return r});await f.c.renderAgentReleaseList(f.host);assert.ok(f.requests.some(x=>x[1]==='/admin/agent-rollout?expected_tenant_id='));assert.ok(allNodes(f.host).some(x=>String(x.text).includes('Updates paused: incident')))});


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
