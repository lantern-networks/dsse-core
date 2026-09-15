import {readFileSync} from 'node:fs';import vm from 'node:vm';import assert from 'node:assert/strict';import test from 'node:test';
const source=readFileSync(new URL('./grants.js',import.meta.url),'utf8');
const grant={grant_id:'secret-cookie',tenant_id:'tenant',user_id:'person',user_display_name:'Alice',idp_id:'idp',issued_at:'2026-01-01T00:00:00Z',expires_at:'2099-01-01T00:00:00Z'};
function fixture(){const calls=[],states=[],toasts=[],confirms=[],refreshes=[];
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
 const good=path=>path==='/admin/grants'?{grants:[grant]}:path==='/admin/tenant'?{tenant_id:'tenant'}:path.includes('human-identities')?{identities:[]}:path.includes('idp-connections')?{connections:[]}:{devices:[]};
 const context=vm.createContext({el,bl:b=>b.en,document:{createTextNode:s=>el('text',{text:s})},window:{dsseFormatTime:s=>s},
  apiFetch:async(method,path)=>{calls.push({method,path});return {ok:true,status:200,body:method==='GET'?good(path):{status:'revoked',grant_id:grant.grant_id,tenant_id:grant.tenant_id}}},
  uiState:(host,state,message,retry)=>{host.innerHTML='';states.push({state,message,retry})},freshRender:host=>{const n=(host.seq||0)+1;host.seq=n;return()=>host.seq===n},
  uiToast:(message,kind)=>toasts.push({message,kind}),uiBadge:text=>el('span',{text}),paSearchTable:(placeholder,rows,hay,table)=>table(rows),uiConfirm:async spec=>{confirms.push(spec);return true},
 });vm.runInContext(source,context);const host=el('div');return {context,host,calls,states,toasts,confirms,refreshes,good, mockRefresh:()=>{context.renderGrantsList=async()=>refreshes.push(true)}};
}
test('invalid list/tenant/rows refuse controls; valid retry renders approvals',async()=>{
 for(const [path,bad] of [['/admin/grants',{}],['/admin/grants',{grants:null}],['/admin/grants',{grants:{}}],['/admin/grants',{grants:[null]}],['/admin/grants',{grants:[{...grant,tenant_id:'other'}]}],['/admin/grants',{grants:[grant,grant]}],['/admin/grants',{grants:[{...grant,revoked:'false'}]}],['/admin/grants',{grants:[{...grant,amr:[3]}]}],['/admin/tenant',{}]]){
  const f=fixture();f.context.apiFetch=async(m,p)=>({ok:true,status:200,body:p===path?bad:f.good(p)});await f.context.renderGrantsList(f.host);assert.equal(f.states.at(-1).state,'error');assert.equal(f.host.querySelectorAll('button').length,0);f.context.apiFetch=async(m,p)=>({ok:true,status:200,body:f.good(p)});await f.states.at(-1).retry.onClick();assert.ok(f.host.textContent.includes('Alice'));assert.ok(f.host.querySelectorAll('button').some(x=>x.textContent==='Revoke'));
 }
});
test('valid empty list and read failure stay distinct',async()=>{for(const reply of [{ok:false,status:503},{ok:true,status:200,body:{grants:[]}}]){const f=fixture();f.context.apiFetch=async(m,p)=>p==='/admin/grants'?reply:{ok:true,status:200,body:f.good(p)};await f.context.renderGrantsList(f.host);assert.equal(f.states.at(-1).state,reply.ok?'empty':'error')}});
test('only valid future RFC3339 expiry is active; equality expires',()=>{const f=fixture(),now=Date.parse('2026-09-16T00:00:00Z');for(const exp of ['',undefined,'not-time','2099','2099-02-30T00:00:00Z','2099-13-01T00:00:00Z','2099-01-01T24:00:00Z'])assert.equal(f.context.grantStatus({...grant,expires_at:exp},now).label.en,'Unknown expiry');assert.equal(f.context.grantStatus({...grant,expires_at:'2026-09-16T00:00:00Z'},now).label.en,'Expired');assert.equal(f.context.grantStatus(grant,now).label.en,'Active');assert.equal(f.context.grantStatus({...grant,revoked:true},now).label.en,'Revoked');assert.equal(f.context.grantRemaining({...grant,expires_at:'invalid'},now),'')});
test('revoke success and partial must identify the exact grant and tenant',()=>{const f=fixture();assert.equal(f.context.grantRevokeOutcome({ok:true,status:200,body:{status:'revoked',grant_id:grant.grant_id,tenant_id:'tenant'}},grant).partial,false);assert.equal(f.context.grantRevokeOutcome({ok:false,status:500,body:{status:'partial',applied:true,grant_id:grant.grant_id,tenant_id:'tenant',persistence:'unconfirmed'}},grant).partial,true);for(const body of [{},{status:'revoked',grant_id:'other',tenant_id:'tenant'},{status:'revoked',grant_id:grant.grant_id,tenant_id:'other'}])assert.throws(()=>f.context.grantRevokeOutcome({ok:true,status:200,body},grant),/unconfirmed/)});
test('partial revoke offers retry; retry does not reconfirm and clears only its notice',async()=>{const f=fixture();f.mockRefresh();let partial=true;f.context.apiFetch=async()=>({ok:!partial,status:partial?500:200,body:{grant_id:grant.grant_id,tenant_id:'tenant',status:partial?'partial':'revoked',applied:true,persistence:'unconfirmed'}});await f.context.revokeGrant(grant,f.host,'Alice');assert.equal(f.host.__grantNotices.size,1);assert.match([...f.host.__grantNotices.values()][0].message,/before restarting/);assert.equal(f.toasts.length,0);partial=false;await f.context.revokeGrant(grant,f.host,'Alice',true);assert.equal(f.confirms.length,1);assert.equal(f.host.__grantNotices.size,0);assert.equal(f.toasts.length,1);assert.match(f.toasts[0].message,/Alice/)});
test('pending confirmation/request suppresses duplicate revokes',async()=>{const f=fixture();f.mockRefresh();let release;f.context.uiConfirm=()=>new Promise(r=>{f.confirms.push(true);release=r});const first=f.context.revokeGrant(grant,f.host,'Alice');await f.context.revokeGrant(grant,f.host,'Alice');assert.equal(f.confirms.length,1);release(true);await first;assert.equal(f.calls.filter(c=>c.method==='POST').length,1);assert.equal(f.host.__grantPending.size,0)});
test('cancel makes no request; transport loss or malformed success never announces success',async()=>{for(const mode of ['cancel','offline','bad-success']){const f=fixture();f.mockRefresh();if(mode==='cancel')f.context.uiConfirm=async()=>false;else f.context.apiFetch=async()=>{if(mode==='offline')throw Error('offline');return {ok:true,status:200,body:{}}};await f.context.revokeGrant(grant,f.host,'Alice');assert.equal(f.toasts.length,0);assert.equal(f.host.__grantPending.size,0);assert.equal(f.host.__grantNotices.size,mode==='cancel'?0:1);if(mode==='cancel')assert.equal(f.calls.length,0)}});

test('partial persistence and unknown outcome have distinct recovery labels',async()=>{
 for(const partial of [true,false]) {const f=fixture();f.host.__grantNotices=new Map([['one',{grant,label:'Alice',partial,message:'Review outcome'}]]);f.context.drawGrantNotices(f.host);assert.equal(f.host.querySelectorAll('button')[0].textContent,partial?'Retry saving revocation':'Retry revocation')}
});
