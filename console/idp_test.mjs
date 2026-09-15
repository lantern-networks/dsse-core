import {readFileSync} from 'node:fs';import vm from 'node:vm';import assert from 'node:assert/strict';import test from 'node:test';
const source=readFileSync(new URL('./idp.js',import.meta.url),'utf8');
function fixture() {
 const calls=[],states=[],toasts=[],modals=[],fields={},confirms=[],refreshes=[];
 function el(tag,attrs={},children=[]) {
  if(typeof tag!=='string')throw Error('invalid tag');
  let text=attrs.text||'';const listeners={};
  const n={tag,attrs,style:{},children:[],disabled:Object.hasOwn(attrs,"disabled") && attrs.disabled != null,value:attrs.value||'',
   appendChild(child){if(child!=null){if(typeof child!=='object')child=el('text',{text:String(child)});this.children.push(child)};return child},
   addEventListener(event,fn){listeners[event]=fn},
   click(){return (listeners.click||attrs.onClick)?.()}, input(){return listeners.input?.()},
   getAttribute(name){return attrs[name]}, setAttribute(name,value){attrs[name]=value}, querySelector(selector){return this.querySelectorAll(selector)[0]||null},
   querySelectorAll(selector){const tags=selector.split(',');return this.children.flatMap(c=>[c,...c.querySelectorAll('*')]).filter(c=>selector==='*'||tags.includes(c.tag)||(selector.startsWith('[')&&Object.hasOwn(c.attrs,selector.slice(1,-1))))},
  };
  Object.defineProperty(n,'textContent',{get(){return text+this.children.map(c=>c.textContent).join('')},set(v){text=String(v);this.children=[]}});
  Object.defineProperty(n,'innerHTML',{set(v){assert.equal(v,'');n.textContent=''}});
  for(const c of [children].flat(Infinity))n.appendChild(c);return n;
 }
 const context=vm.createContext({el,bl:b=>b.en,document:{createTextNode:s=>el('text',{text:s})},window:{dsseFormatTime:s=>s},
  apiFetch:async(method,path,body,plane)=>{calls.push({method,path,body,plane});return {ok:true,status:200,body:method==='GET'?(path==='/admin/tenant'?{tenant_id:'tenant'}:{connections:[],default_idp_id:''}):{...body}}},
  uiState:(host,state,message,retry)=>{host.innerHTML='';states.push({state,message,retry})},
  freshRender:host=>{const n=(host.seq||0)+1;host.seq=n;return()=>host.seq===n},
  uiToast:(message,kind)=>toasts.push({message,kind}),uiBadge:(text,kind)=>el('span',{text,'data-kind':kind}),emptyBox:text=>el('div',{text}),
  uiField:spec=>{const input=el(spec.type==='select'?'select':spec.type==='textarea'?'textarea':'input',{value:spec.value??''});let error='';const get=()=>spec.type==='checkbox'?!!input.value:String(input.value).trim();const f={spec,input,el:el('div',{},[input]),get,validate:()=>{error=(!get()&&spec.required?'required':spec.validate?.(get())||'');return !error},focus(){},setError:v=>{error=v},error:()=>error};fields[spec.name]=f;const {input:fixtureInput,...publicField}=f;return publicField},
  uiModal:spec=>{const modal={spec,el:el('div',{},[spec.body,spec.footer]),closed:false,close(){if(this.closed)return;this.closed=true;spec.onClose?.()}};modals.push(modal);return modal},
  uiConfirm:async spec=>{confirms.push(spec);return true},
 });
 vm.runInContext(source,context);const host=el('div');host.__idpAnchor={isConnected:true};host.contains=()=>true;
 return {context,host,calls,states,toasts,modals,fields,confirms,refreshes,el,
  invokeWith:fn=>{context.apiFetch=async(...args)=>{const [method,path,body,plane]=args;calls.push({method,path,body,plane});return fn(...args)}},
  mockRefresh:()=>{context.renderIdPConnectionsView=()=>refreshes.push(true)},
  form:(existing)=>{host.__idpTenant='tenant';context.openIdpForm(host,existing);if(!existing){fields.id.input.value='new';fields.issuer.input.value='https://idp.test';fields.authz.input.value='https://idp.test/auth';fields.client.input.value='client'}return modals.at(-1)},
 };
}
const button=(n,text)=>n.querySelectorAll('button').find(b=>b.textContent===text);
const error=n=>n.querySelectorAll('*').find(b=>b.attrs.role==='alert');
const conn={idp_id:'a',tenant_id:'tenant',type:'oidc',issuer:'https://idp.test',authorization_endpoint:'https://idp.test/auth',client_id:'client',domain_mode:'email_domain'};
const reply=body=>({ok:true,status:200,body});
function list(f){const host=f.el('div');f.host.appendChild(host);host.__idpContent=f.host;host.__idpAdd=f.el('button');return host}
for(const path of ['/admin/idp-connections','/admin/tenant'])test(path+' errors and malformed payloads refuse editing',async()=>{
 for(const failure of [{ok:false,status:503},reply({}),new Error('offline')]){const f=fixture(),h=list(f);f.invokeWith(async(m,p)=>{if(p===path){if(failure instanceof Error)throw failure;return failure}return reply(p==='/admin/tenant'?{tenant_id:'tenant'}:{connections:[conn],default_idp_id:'a'})});await f.context.renderIdPList(h);assert.equal(f.states.at(-1).state,'error');assert.equal(h.__idpAdd.disabled,true);assert.equal(f.states.at(-1).retry.label,'Retry');assert.equal(h.textContent.includes('No sign-in'),false)}
});
test('list validates tenant, duplicate IDs, default pointer and secret redaction',async()=>{
 for(const body of [{connections:[{...conn,tenant_id:'other'}],default_idp_id:'a'},{connections:[conn,conn],default_idp_id:'a'},{connections:[conn],default_idp_id:'missing'},{connections:[{...conn,client_secret:'leaked'}],default_idp_id:'a'}]){const f=fixture(),h=list(f);f.invokeWith(async(m,p)=>reply(p==='/admin/tenant'?{tenant_id:'tenant'}:body));await f.context.renderIdPList(h);assert.equal(f.states.at(-1).state,'error')}
});
test('valid empty registry enables add; loaded records retain default and search',async()=>{
 const f=fixture(),h=list(f);await f.context.renderIdPList(h);assert.equal(h.__idpAdd.disabled,false);assert.equal(f.states.at(-1).state,'empty');f.invokeWith(async(m,p)=>reply(p==='/admin/tenant'?{tenant_id:'tenant'}:{connections:[conn],default_idp_id:'a'}));await f.context.renderIdPList(h);assert.match(h.textContent,/Default/);assert.ok(f.calls.every(c=>c.plane==='control'));
});
test('form validates authorization endpoint and safe ID without posting',async()=>{
 const f=fixture();const m=f.form();f.fields.authz.input.value='';await button(m.el,'Add provider').click();assert.equal(f.calls.length,0);assert.ok(f.fields.authz.error());f.fields.authz.input.value='https://idp.test/auth';f.fields.id.input.value='bad/id';await button(m.el,'Add provider').click();assert.equal(f.calls.length,0)
});
test('form confirms tenant, type and all metadata, normalizing domains and omitting blank secret',async()=>{
 for(const type of ['oidc','google','entra','okta']){const f=fixture();f.mockRefresh();const m=f.form();f.fields.type.input.value=type;f.fields.domains.input.value='Example.test, example.test, OTHER.test';await button(m.el,'Add provider').click();assert.equal(m.closed,true);const c=f.calls[0];assert.equal(c.plane,'control');assert.equal(c.body.tenant_id,'tenant');assert.equal(c.body.type,type);assert.equal(c.body.client_secret,undefined);assert.deepEqual(Array.from(c.body.verified_domains),['example.test','other.test'])}
});
test('form rejects failed, mismatched or leaked-secret replies and restores all controls',async()=>{
 for(const response of [{ok:false,status:500,body:{error:'save failed'}},new Error('offline'),reply({}),reply({...conn,idp_id:'wrong'}),reply({...conn,client_secret:'leaked'})]){const f=fixture();f.mockRefresh();const m=f.form();f.invokeWith(async()=>{if(response instanceof Error)throw response;return response});await button(m.el,'Add provider').click();assert.equal(m.closed,false);assert.ok(error(m.el).textContent);assert.equal(button(m.el,'Add provider').disabled,false);assert.equal(f.toasts.length,0);f.invokeWith(async(m,p,body)=>reply(body));await button(m.el,'Add provider').click();assert.equal(m.closed,true)}
});
test('pending form freezes metadata, refuses duplicate writes and handles closing',async()=>{
 const f=fixture();f.mockRefresh();const m=f.form();let finish;f.invokeWith((m,p,body)=>new Promise(resolve=>finish=()=>resolve(reply(body))));const submit=button(m.el,'Add provider');const pending=submit.click();await submit.click();assert.equal(f.calls.length,1);assert.ok(m.el.querySelectorAll('input,select,textarea,button').every(c=>c.disabled));m.close();assert.match(f.host.__idpNotice,/may already/);finish();await pending;assert.equal(f.toasts.length,0);assert.equal(f.host.__idpPending,false)
});
for(const remove of [false,true])test((remove?'delete':'default')+' confirms result, catches exceptions and supports explicit retry',async()=>{
 for(const failure of [{ok:false,status:500,body:{error:'save failed'}},new Error('offline'),reply({status:remove?'deleted':'default_set',id:'wrong'})]){const f=fixture(),h=list(f);f.context.renderIdPList=async()=>{};f.invokeWith(async()=>{if(failure instanceof Error)throw failure;return failure});await f.context.idpRowChange(conn,h,remove);assert.ok(f.host.__idpNotice);assert.equal(f.host.__idpPending,false);assert.equal(f.toasts.length,0);f.invokeWith(async()=>reply({status:remove?'deleted':'default_set',id:'a'}));await f.context.idpRowChange(conn,h,remove);assert.equal(f.host.__idpNotice,'');assert.equal(f.toasts.at(-1).kind,'ok');assert.ok(f.calls.every(c=>c.plane==='control'))}
});
test('delete cancellation and pending confirmation prevent both opposite and duplicate actions',async()=>{
 const f=fixture(),h=list(f);f.context.renderIdPList=async()=>{};let finish;f.context.uiConfirm=()=>new Promise(resolve=>finish=resolve);const pending=f.context.idpRowChange(conn,h,true);await f.context.idpRowChange(conn,h,false);await f.context.idpRowChange(conn,h,true);assert.equal(f.calls.length,0);finish(false);await pending;assert.equal(f.calls.length,0);assert.equal(f.host.__idpPending,false)
});
test('connectivity test rejects malformed truthy success and preserves valid probe results',async()=>{
 for(const body of [{ok:'false',checks:[]},{ok:true,checks:[{name:'jwks',ok:'false',detail:''}]},{ok:true,checks:[]}]){const f=fixture();f.invokeWith(async()=>reply(body));await f.context.testIdp(conn);assert.equal(f.modals.length,0);assert.equal(f.toasts.at(-1).kind,'err')}
 for(const ok of [true,false]){const f=fixture();f.invokeWith(async()=>reply({ok,checks:[{name:'jwks',ok,detail:'probe result'}]}));await f.context.testIdp(conn);assert.equal(f.modals.length,1);assert.equal(f.toasts.at(-1).kind,ok?'ok':'err');assert.equal(f.calls[0].plane,'control')}
});

test('late closed-form response cannot replace a different page',async()=>{
 const f=fixture();f.mockRefresh();const m=f.form();let finish;f.invokeWith((m,p,body)=>new Promise(resolve=>finish=()=>resolve(reply(body))));const pending=button(m.el,'Add provider').click();m.close();const before=f.refreshes.length;f.host.__idpAnchor.isConnected=false;finish();await pending;assert.equal(f.refreshes.length,before);assert.equal(f.toasts.length,0)
});
