import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';
const source=readFileSync(new URL('./peopleaccounts.js',import.meta.url),'utf8');
const person={id:'alice',tenant_id:'tenant',subject:'alice',email:'alice@example.test',source:'manual',status:'active',department:'Engineering',metadata:{note:'keep'}};
const paths=['/admin/human-identities/sources/health','/admin/human-identities/sources','/admin/human-identities/import-runs','/admin/human-identities','/admin/risk-signals?entity_type=user'];
const bodyFor=path=>({
 [paths[0]]:{status:'ok',source_count:0,stale_after_seconds:86400,sources:[]},
 [paths[1]]:{sources:[]},[paths[2]]:{runs:[]},[paths[3]]:{identities:[]},[paths[4]]:{entity_type:"user",tenant_id:"tenant",high_risk:{}},
}[path]);
function fixture() {
 const calls=[],states=[],toasts=[],modals=[],fields={},confirms=[],refreshes=[];
 function el(tag,attrs={},children=[]) {
  if(typeof tag!=='string')throw Error('invalid tag');
  let text=attrs.text||'';const listeners={};
  const n={tag,attrs,style:{},children:[],disabled:Object.hasOwn(attrs,"disabled") && attrs.disabled != null,value:attrs.value||'',
   appendChild(child){if(child!=null){if(typeof child!=='object')child=el('text',{text:String(child)});this.children.push(child)};return child},
   addEventListener(event,fn){listeners[event]=fn},
   click(){return (listeners.click||attrs.onClick)?.()}, input(){return listeners.input?.()},
   getAttribute(name){return attrs[name]},
   querySelectorAll(selector){const tags=selector.split(',');return this.children.flatMap(c=>[c,...c.querySelectorAll('*')]).filter(c=>selector==='*'||tags.includes(c.tag)||(selector.startsWith('[')&&Object.hasOwn(c.attrs,selector.slice(1,-1))))},
  };
  Object.defineProperty(n,'textContent',{get(){return text+this.children.map(c=>c.textContent).join('')},set(v){text=String(v);this.children=[]}});
  Object.defineProperty(n,'innerHTML',{set(v){assert.equal(v,'');n.textContent=''}});
  for(const c of [children].flat(Infinity))n.appendChild(c);return n;
 }
 const context=vm.createContext({el,bl:b=>b.en,document:{createTextNode:s=>el('text',{text:s})},window:{dsseFormatTime:s=>s},
  apiFetch:async(method,path,body,plane)=>{calls.push({method,path,body,plane});return {ok:true,status:200,body:method==='GET'?bodyFor(path):{...body,tenant_id:body.tenant_id||'tenant'}}},
  uiState:(host,state,message,retry)=>{host.innerHTML='';states.push({state,message,retry})},
  freshRender:host=>{const n=(host.seq||0)+1;host.seq=n;return()=>host.seq===n},
  uiToast:(message,kind)=>toasts.push({message,kind}),uiBadge:(text)=>el('span',{text}),emptyBox:text=>el('div',{text}),
  uiField:spec=>{const input=el(spec.type==='select'?'select':'input',{value:spec.value||''});let error='';const f={spec,input,el:el('div',{},[input]),get:()=>input.value.trim(),validate:()=>!spec.required||input.value.trim()!=='',focus(){},setError:v=>{error=v},error:()=>error};fields[spec.name]=f;const {input:fixtureInput,...publicField}=f;return publicField},
  uiModal:spec=>{const modal={spec,el:el('div',{},[spec.body,spec.footer]),closed:false,close(){if(this.closed)return;this.closed=true;spec.onClose?.()}};modals.push(modal);return modal},
  uiConfirm:async spec=>{confirms.push(spec);return true},
 });
 vm.runInContext(source,context);const host=el('div');
 return {context,host,calls,states,toasts,modals,fields,confirms,refreshes,el,
  invokeWith:fn=>{context.apiFetch=async(...args)=>{const [method,path,body,plane]=args;calls.push({method,path,body,plane});return fn(...args)}},
  mockRefresh:()=>{context.paPeople=async()=>refreshes.push(true)},
  form:()=>{context.openPersonForm(host);fields.id.input.value='alice';fields.subj.input.value='alice';fields.email.input.value='alice@example.test';return modals.at(-1)},
 };
}
const buttons=n=>n.querySelectorAll('button');
const button=(n,text)=>buttons(n).find(b=>b.textContent===text);
const error=n=>n.querySelectorAll('*').find(b=>b.attrs.role==='alert');
const json=x=>JSON.parse(JSON.stringify(x));
for(const path of paths) test(`${path} failure and invalid body deny editing and offer Retry`,async()=>{
 for(const reply of [{ok:false,status:503},{ok:true,body:{}},{ok:true,body:[]},new Error('offline')]) {
  const f=fixture();f.invokeWith(async(method,p)=>{if(p===path){if(reply instanceof Error)throw reply;return reply}return {ok:true,body:bodyFor(p)}});
  await f.context.paPeople(f.host);assert.equal(f.states.at(-1).state,'error');assert.equal(f.states.at(-1).retry.label,'Retry');assert.equal(buttons(f.host).length,0);assert.equal(f.host.textContent.includes('Normal'),false);
  f.invokeWith(async(method,p)=>({ok:true,body:bodyFor(p)}));await f.states.at(-1).retry.onClick();assert.ok(button(f.host,'Add manually'));
 }
});
test('malformed directory rows, health and risk are rejected',async()=>{
 for(const [path,body] of [[paths[0],{...bodyFor(paths[0]),source_count:1}],[paths[0],{...bodyFor(paths[0]),status:[]}],[paths[1],{sources:[42]}],[paths[2],{runs:[{}]}],[paths[3],{identities:[{...person,status:'disabled'}]}],[paths[3],{identities:[{...person,email:{}}]}],[paths[4],{high_risk:[]}],[paths[4],{high_risk:{alice:'invalid'}}]]){
  const f=fixture();f.invokeWith(async(m,p)=>({ok:true,body:p===path?body:bodyFor(p)}));await f.context.paPeople(f.host);assert.equal(f.states.at(-1).state,'error');assert.equal(buttons(f.host).length,0);
 }
});
test('valid empty arrays/nulls allow manual addition without asserting IdP connectivity',async()=>{
 for(const empty of [[],null]){const f=fixture();f.invokeWith(async(m,p)=>{const b=bodyFor(p);for(const k of ['identities','sources','runs'])if(Object.hasOwn(b,k))b[k]=empty;return {ok:true,body:b}});await f.context.paPeople(f.host);assert.ok(button(f.host,'Add manually'));assert.match(f.host.textContent,/No identity sources recorded/)}
});
test('late read success or failure cannot replace the newest view',async()=>{
 for(const fail of [false,true]){const f=fixture();let finish;f.context.paLoadPeople=()=>new Promise((resolve,reject)=>{finish=()=>fail?reject(Error('obsolete')):resolve({health:bodyFor(paths[0]),sources:[],runs:[],people:[],riskMap:{}})});const old=f.context.paPeople(f.host);f.context.paLoadPeople=async()=>({health:bodyFor(paths[0]),sources:[],runs:[],people:[],riskMap:{}});await f.context.paPeople(f.host);const html=f.host.textContent;finish();await old;assert.equal(f.host.textContent,html);assert.equal(f.states.some(s=>s.state==='error'),false)}
});
test('directory filters removed people, searches and preserves fields on soft removal',async()=>{
 const f=fixture();f.invokeWith(async(m,p,body)=>({ok:true,body:m==='POST'?body:p===paths[3]?{identities:[person,{...person,id:'deleted-person',subject:'deleted-person',status:'deleted'}]}:bodyFor(p)}));await f.context.paPeople(f.host);assert.equal(f.host.textContent.includes('deleted-person'),false);
 const search=f.host.querySelectorAll('input')[0];search.value='missing';search.input();assert.match(f.host.textContent,/No matches/);search.value='Engineering';search.input();assert.match(f.host.textContent,/alice/);
 f.mockRefresh();await button(f.host,'Remove').click();const [write]=f.calls.filter(c=>c.method==='POST');assert.deepEqual(json(write.body),{...person,status:'deleted'});assert.equal(write.plane,'control');assert.equal(f.refreshes.length,1);
});
test('manual form validates and submits supported suspended status',async()=>{
 const f=fixture();f.mockRefresh();f.context.openPersonForm(f.host);const modal=f.modals[0];await button(modal.el,'Add person').click();assert.equal(f.calls.length,0);
 assert.deepEqual(json(f.fields.status.spec.options.map(v=>v.value)),['active','suspended']);f.fields.id.input.value='alice';f.fields.subj.input.value='alice';f.fields.status.input.value='suspended';await button(modal.el,'Add person').click();assert.equal(f.calls[0].body.status,'suspended');assert.equal(f.calls[0].plane,'control');assert.equal(modal.closed,true);assert.equal(f.toasts[0].kind,'ok');assert.equal(f.refreshes.length,1);
});
test('manual form catches HTTP/network/unconfirmed writes, keeps values and can retry',async()=>{
 for(const reply of [{ok:false,status:500,body:{error:'<b>save failed</b>'}},new Error('offline'),{ok:true,body:{}},{ok:true,body:{...person,id:'different'}}]){
  const f=fixture();f.mockRefresh();const m=f.form();const submit=button(m.el,'Add person');f.invokeWith(async()=>{if(reply instanceof Error)throw reply;return reply});await submit.click();assert.equal(m.closed,false);assert.equal(submit.disabled,false);assert.equal(f.fields.id.get(),'alice');assert.ok(error(m.el).textContent);assert.equal(f.toasts.length,0);assert.equal(f.refreshes.length,0);
  f.invokeWith(async(m,p,body)=>({ok:true,body:{...body,tenant_id:'tenant'}}));await submit.click();assert.equal(m.closed,true);assert.equal(f.toasts.at(-1).kind,'ok');
 }
});
test('manual pending snapshots values and suppresses repeated dispatch',async()=>{
 const f=fixture();f.mockRefresh();const m=f.form();let finish;f.invokeWith(async(m,p,body)=>new Promise(resolve=>{finish=()=>resolve({ok:true,body:{...body,tenant_id:'tenant'}})}));const submit=button(m.el,'Add person');const first=submit.click();await submit.click();await submit.click();assert.equal(f.calls.length,1);assert.ok(m.el.querySelectorAll('input,select,button').every(c=>c.disabled));f.fields.id.input.value='different';finish();await first;assert.equal(f.calls[0].body.id,'alice');assert.equal(m.closed,true);
});
test('closing pending modal warns of uncertainty and suppresses late success',async()=>{
 const f=fixture();f.mockRefresh();const m=f.form();let finish;f.invokeWith(async(m,p,body)=>new Promise(resolve=>{finish=()=>resolve({ok:true,body:{...body,tenant_id:'tenant'}})}));const pending=button(m.el,'Add person').click();m.close();finish();await pending;assert.equal(f.toasts.length,1);assert.equal(f.toasts[0].kind,'err');assert.match(f.toasts[0].message,/may already/);assert.equal(f.refreshes.length,0);
});
test('Remove cancellation, failure, bad response and retry preserve actionable row',async()=>{
 for(const reply of [{ok:false,status:500,body:{error:'<b>failed</b>'}},new Error('offline'),{ok:true,body:{}},{ok:true,body:person}]){
  const f=fixture();let writes=0;const row=f.context.paRemoveBtn('remove','body',async()=>{writes++;if(reply instanceof Error)throw reply;return reply},()=>f.refreshes.push(true),r=>f.context.paConfirmPerson(r,{...person,status:'deleted'}));
  f.context.uiConfirm=async()=>false;await button(row,'Remove').click();assert.equal(writes,0);f.context.uiConfirm=async()=>true;await button(row,'Remove').click();assert.equal(writes,1);assert.ok(error(row).textContent);assert.equal(button(row,'Remove').disabled,false);assert.equal(f.toasts.length,0);assert.equal(f.refreshes.length,0);
 }
});
test('Remove suppresses duplicate confirmation and sends only one write',async()=>{
 const f=fixture();let confirm;f.context.uiConfirm=()=>new Promise(resolve=>{confirm=resolve});let writes=0;const row=f.context.paRemoveBtn('remove','body',async()=>{writes++;return {ok:true,body:{...person,status:'deleted'}}},()=>f.refreshes.push(true),r=>f.context.paConfirmPerson(r,{...person,status:'deleted'}));const first=button(row,'Remove').click();await button(row,'Remove').click();confirm(true);await first;assert.equal(writes,1);assert.equal(f.refreshes.length,1);assert.equal(button(row,'Remove').disabled,false);
});

const riskReply=(severity,extra={})=>({ok:true,body:{tenant_id:'tenant',entity_type:'user',entity_id:'alice',severity,applied:true,high_risk:['high','critical'].includes(severity),...extra}});
test('user risk verifies all levels and the selected tenant on the control plane',async()=>{
 for(const severity of ['medium','high','critical','none']){
  const f=fixture();f.mockRefresh();f.invokeWith(async()=>riskReply(severity));await f.context.setUserRisk(person,severity,f.host);
  assert.deepEqual(json(f.calls[0]),{method:'POST',path:'/admin/risk-signals',body:{entity_type:'user',entity_id:'alice',severity},plane:'control'});assert.equal(f.toasts.at(-1).kind,'ok');assert.equal(f.refreshes.length,1);assert.equal(f.host.__paRiskNotices.size,0);
 }
});
test('user risk refuses errors and mismatched success, retaining a retry notice through reload',async()=>{
 for(const response of [{ok:false,status:503},new Error('offline'),{ok:true,body:{}},riskReply('high',{entity_id:'bob'}),riskReply('high',{tenant_id:'other'}),riskReply('high',{severity:'none'}),riskReply('high',{applied:false}),riskReply('high',{high_risk:false}),riskReply('high',{not_stored_durably:true})]){
  const f=fixture();f.invokeWith(async(method,path)=>{if(method==='GET')return {ok:true,body:bodyFor(path)};if(response instanceof Error)throw response;return response});
  await f.context.setUserRisk(person,'high',f.host);assert.equal(f.toasts.length,0);assert.match(error(f.host).textContent,/may already/);assert.ok(button(f.host,'Retry risk change'));
  await f.context.paPeople(f.host);assert.ok(button(f.host,'Retry risk change'));
  f.invokeWith(async(method,path)=>method==='POST'?riskReply('high'):{ok:true,body:bodyFor(path)});await button(f.host,'Retry risk change').click();assert.equal(f.host.__paRiskNotices.size,0);assert.equal(f.toasts.at(-1).kind,'ok');
 }
});
test('user risk weak save remains visible even when reload fails and clears only after retry',async()=>{
 const f=fixture();f.invokeWith(async(method)=>method==='POST'?riskReply('high',{not_stored_durably:'warning'}):{ok:false,status:503});await f.context.setUserRisk(person,'high',f.host);
 assert.equal(f.states.at(-1).state,'error');assert.match(error(f.host).textContent,/durable saving is not confirmed/);assert.equal(f.toasts.length,0);
 f.invokeWith(async(method,path)=>method==='POST'?riskReply('high'):{ok:true,body:bodyFor(path)});await button(f.host,'Retry risk change').click();assert.equal(f.host.__paRiskNotices.size,0);
});
test('pending risk disables its own selector and suppresses duplicate writes',async()=>{
 const f=fixture();f.mockRefresh();const own=f.el('select',{'data-person-risk-id':'alice'}),other=f.el('select',{'data-person-risk-id':'bob'});f.host.appendChild(own);f.host.appendChild(other);let finish;
 f.invokeWith(async()=>new Promise(resolve=>{finish=()=>resolve(riskReply('high'))}));const first=f.context.setUserRisk(person,'high',f.host);await f.context.setUserRisk(person,'critical',f.host);assert.equal(f.calls.length,1);assert.equal(own.disabled,true);assert.equal(other.disabled,false);finish();await first;assert.equal(own.disabled,false);
});
test('a risk snapshot from another tenant never renders clean people',async()=>{
 const f=fixture();f.invokeWith(async(method,path)=>({ok:true,body:path===paths[3]?{identities:[person]}:path===paths[4]?{entity_type:'user',tenant_id:'other',high_risk:{}}:bodyFor(path)}));await f.context.paPeople(f.host);assert.equal(f.states.at(-1).state,'error');assert.equal(buttons(f.host).length,0);
});

const account={id:'account-one',tenant_id:'tenant',name:'Account one',nhi_type:'service_account',owner_user_id:'alice',status:'active'};
const accountPaths=['/admin/non-human-identities','/admin/non-human-identities/risk','/admin/policies?limit=1000'];
const accountBodies=path=>({[accountPaths[0]]:{tenant_id:'tenant',count:1,identities:[account]},[accountPaths[1]]:{tenant_id:'tenant',total:1,identities:[{id:account.id,severity:'high'}]},[accountPaths[2]]:{count:0,policies:[]}}[path]);
const accountForm=f=>{f.host.__paAccountTenant='tenant';f.context.openAccountForm(f.host);f.fields.id.input.value=account.id;f.fields.name.input.value=account.name;f.fields.owner.input.value=account.owner_user_id;f.fields.status.input.value=account.status;return f.modals.at(-1)};
for(const path of accountPaths)test(`accounts require ${path}, including malformed and foreign responses`,async()=>{
 for(const reply of [{ok:false,status:503},{ok:true,body:{}},{ok:true,body:[]},new Error('offline')]){const f=fixture();f.invokeWith(async(m,p)=>{if(p===path){if(reply instanceof Error)throw reply;return reply}return{ok:true,body:accountBodies(p)}});await f.context.paAccounts(f.host);assert.equal(f.states.at(-1).state,'error');assert.equal(buttons(f.host).length,0);assert.equal(f.host.textContent.includes('No account boundary'),false);f.invokeWith(async(m,p)=>({ok:true,body:accountBodies(p)}));await f.states.at(-1).retry.onClick();assert.ok(button(f.host,'+ Add account'));assert.match(f.host.textContent,/High/)}
});
test('account list refuses truncated policies, missing risk, foreign tenant and malformed active boundaries',async()=>{
 for(const [path,body] of [[accountPaths[0],{...accountBodies(accountPaths[0]),identities:[{...account,tenant_id:'other'}]}],[accountPaths[1],{tenant_id:'tenant',total:0,identities:[]}],[accountPaths[2],{count:101,policies:[]}],[accountPaths[2],{count:1,policies:[{id:'pol-agent-account-one',tenant_id:'tenant',status:'active',conditions:{actor_nhi_id:'other'},allowed_tool_ids:['read'],action:{decision:'allow'}}]}]]){const f=fixture();f.invokeWith(async(m,p)=>({ok:true,body:p===path?body:accountBodies(p)}));await f.context.paAccounts(f.host);assert.equal(f.states.at(-1).state,'error')}
});
test('account form validates suspended status and invalid boundary ID before writing',async()=>{
 const f=fixture();f.context.paAccounts=async()=>{};f.context.openAccountForm(f.host);await button(f.modals[0].el,'Add account').click();assert.equal(f.calls.length,0);assert.deepEqual(json(f.fields.status.spec.options.map(o=>o.value)),['active','suspended']);f.fields.id.input.value='bad/id';f.fields.name.input.value='name';f.fields.owner.input.value='alice';f.fields.tools.input.value='read';await button(f.modals[0].el,'Add account').click();assert.equal(f.calls.length,0);assert.match(f.fields.id.error(),/cannot use/);
});
test('account creation handles errors and mismatched replies without attempting the boundary',async()=>{
 for(const reply of [{ok:false,status:500},new Error('offline'),{ok:true,body:{}},{ok:true,body:{...account,tenant_id:'other'}},{ok:true,body:{...account,owner_user_id:'other'}}]){const f=fixture();f.context.paAccounts=async()=>{};const modal=accountForm(f);f.fields.tools.input.value='read';f.invokeWith(async()=>{if(reply instanceof Error)throw reply;return reply});await button(modal.el,'Add account').click();assert.equal(modal.closed,false);assert.equal(f.calls.length,1);assert.ok(error(modal.el).textContent);assert.equal(button(modal.el,'Add account').disabled,false);assert.equal(f.fields.id.get(),account.id);assert.equal(f.toasts.length,0)}
});
test('boundary failure freezes the saved account and retries only the original policy',async()=>{
 for(const reply of [{ok:false,status:500},new Error('offline'),{ok:true,body:{}},{ok:true,body:{id:'wrong'}}]){
  const f=fixture();f.context.paAccounts=async()=>{};const modal=accountForm(f);f.fields.tools.input.value='read, write, read';f.invokeWith(async(m,p,body)=>{if(p===accountPaths[0])return{ok:true,body:{...body}};if(reply instanceof Error)throw reply;return reply});await button(modal.el,'Add account').click();assert.equal(f.calls.length,2);assert.match(error(modal.el).textContent,/Account saved/);assert.equal(f.fields.id.input.disabled,true);assert.equal(f.toasts.length,0);assert.ok(button(modal.el,'Retry boundary'));
  f.fields.id.input.value='changed';f.fields.tools.input.value='danger';f.invokeWith(async(m,p,body)=>({ok:true,body}));await button(modal.el,'Retry boundary').click();assert.equal(f.calls.filter(c=>c.path===accountPaths[0]).length,1);assert.equal(f.calls.at(-1).body.id,'pol-agent-account-one');assert.deepEqual(json(f.calls.at(-1).body.allowed_tool_ids),['read','write']);assert.equal(modal.closed,true);assert.equal(f.toasts.at(-1).kind,'ok');
 }
});
test('account submit snapshots all inputs and suppresses repeated events during its two writes',async()=>{
 const f=fixture();f.context.paAccounts=async()=>{};const modal=accountForm(f);f.fields.tools.input.value='read';let finish;f.invokeWith(async(m,p,body)=>p===accountPaths[0]?new Promise(resolve=>finish=()=>resolve({ok:true,body})):{ok:true,body});const first=button(modal.el,'Add account').click();await button(modal.el,'Add account').click();assert.equal(f.calls.length,1);assert.ok(modal.el.querySelectorAll('input,select,button').every(c=>c.disabled));f.fields.id.input.value='other';f.fields.tools.input.value='other';finish();await first;assert.equal(f.calls.length,2);assert.equal(f.calls[1].body.conditions.actor_nhi_id,'account-one');assert.deepEqual(json(f.calls[1].body.allowed_tool_ids),['read']);assert.equal(modal.closed,true);
});
test('closing a pending account operation retains its result without sending a new boundary',async()=>{
 const f=fixture();f.context.paAccounts=async()=>{f.refreshes.push(true)};const modal=accountForm(f);f.fields.tools.input.value='read';let finish;f.invokeWith(async(m,p,body)=>new Promise(resolve=>finish=()=>resolve({ok:true,body})));const first=button(modal.el,'Add account').click();modal.close();finish();await first;assert.equal(f.calls.length,1);assert.equal(f.toasts.length,0);assert.match(f.host.__paAccountNotices.get(account.id),/Account saved/);
});
test('account boundary falls back to control only on an explicit sourced-node response',async()=>{
 const f=fixture();let n=0;f.invokeWith(async()=>++n===1?{ok:false,status:409,body:{error:'authored on the control plane'}}:{ok:true,body:{}});await f.context.paWriteEnforcement('POST','/admin/policies',{});assert.equal(f.calls.length,2);assert.equal(f.calls[1].plane,'control');
 const g=fixture();g.invokeWith(async()=>({ok:false,status:409,body:{error:'different conflict'}}));await g.context.paWriteEnforcement('POST','/admin/policies',{});assert.equal(g.calls.length,1);
});
