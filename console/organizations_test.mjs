import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';
const source=readFileSync(new URL('./organizations.js',import.meta.url),'utf8'),id='tenant_gone';
function fixture(){
 const calls=[],toasts=[],host={isConnected:true},context=vm.createContext({idpSession:{tenant_id:'operator',principal_id:'admin'},answeringForTheDeployment:()=>true,bl:x=>x.en,uiConfirm:async()=>true,uiToast:(message,kind)=>toasts.push({message,kind})});
 vm.runInContext(source,context);const notices=context.renderOrgErasureNotices;context.renderOrgList=()=>{};context.renderOrgErasureNotices=()=>{};
 const healthy=(method)=>({ok:true,body:method==='DELETE'?{tenant_id:id,deleted:true}:{tenant_id:id,complete:true,remaining:{tenant_id:id,total:0},failures:[]}});
 context.apiFetch=async(...args)=>{calls.push(args);return healthy(args[0])};
 return{context,calls,toasts,host,healthy,notices,send:()=>context.removeOrg({tenant_id:id},host),state:()=>vm.runInContext('_orgErasures.get("tenant_gone")',context),respond:fn=>{context.apiFetch=async(...args)=>{calls.push(args);return fn(...args)}}};
}
test('confirmed deletion and local erasure use the control plane and name the tenant',async()=>{const f=fixture();await f.send();assert.equal(f.calls.length,2);assert.deepEqual(f.calls.map(c=>[c[0],c[1],c[3]]),[['DELETE','/admin/tenants/'+id,'control'],['POST','/admin/tenants/'+id+'/purge','control']]);assert.equal(f.calls[1][2].confirm_tenant_id,id);assert.equal(f.state(),undefined);assert.equal(f.toasts[0].kind,'ok');assert.match(f.toasts[0].message,/Local erasure confirmed: tenant_gone/)});
for(const [name,alter]of [
 ['incomplete',b=>{b.complete=false}],['remaining',b=>{b.remaining.total=1}],['failures',b=>{b.failures=['unavailable']}],['missing_complete',b=>{delete b.complete}],['foreign_tenant',b=>{b.tenant_id='foreign'}],['foreign_footprint',b=>{b.remaining.tenant_id='foreign'}],['invalid_count',b=>{b.remaining.total='0'}],['invalid_failures',b=>{b.failures={}}],
])test('unconfirmed erasure remains retryable: '+name,async()=>{const f=fixture();f.respond(method=>{const r=f.healthy(method);if(method==='POST')alter(r.body);return r});await f.send();assert.ok(f.state());assert.equal(f.state().busy,false);assert.match(f.state().message.en,/not confirmed/);assert.equal(f.toasts.filter(t=>t.kind==='ok').length,0);f.respond(f.healthy);await f.context.eraseOrgRecords(id,f.host,f.state());assert.deepEqual(f.calls.map(c=>c[0]),['DELETE','POST','POST']);assert.equal(f.state(),undefined)});
test('network failure keeps erasure retry separate from deletion',async()=>{const f=fixture();f.respond(method=>{if(method==='POST')throw Error('private backend secret');return f.healthy(method)});await f.send();assert.equal(f.state().message.en.includes('secret'),false);f.respond(f.healthy);await f.context.eraseOrgRecords(id,f.host,f.state());assert.deepEqual(f.calls.map(c=>c[0]),['DELETE','POST','POST'])});
test('invalid deletion acknowledgement never starts erasure',async()=>{const f=fixture();f.respond(()=>({ok:true,body:{deleted:true,tenant_id:'foreign'}}));await f.send();assert.equal(f.calls.length,1);assert.equal(f.state(),undefined);assert.equal(f.toasts[0].kind,'err')});
test('duplicate clicks while deletion or erasure is pending do not duplicate writes',async()=>{const f=fixture();let release;f.respond(method=>new Promise(resolve=>{release=()=>resolve(f.healthy(method))}));const operation=f.send();await new Promise(r=>setImmediate(r));await f.send();assert.equal(f.calls.length,1);release();await new Promise(r=>setImmediate(r));assert.equal(f.calls.length,2);await f.context.eraseOrgRecords(id,f.host,f.state());assert.equal(f.calls.length,2);release();await operation;assert.equal(f.calls.length,2)});
for(const kind of ['detached','tenant_context','principal_changed'])test('stale delete response cannot start erasure: '+kind,async()=>{const f=fixture();let release;f.respond(method=>new Promise(resolve=>{release=()=>resolve(f.healthy(method))}));const operation=f.send();await new Promise(r=>setImmediate(r));if(kind==='detached')f.host.isConnected=false;if(kind==='tenant_context')f.context.answeringForTheDeployment=()=>false;if(kind==='principal_changed')f.context.idpSession.principal_id='different';release();await operation;assert.equal(f.calls.length,1);assert.equal(f.toasts.length,0)});

test('persistent failure notice is translated again when the display language changes',async()=>{
 const f=fixture();f.respond(method=>method==='DELETE'?f.healthy(method):{ok:false});await f.send();const nodes=[];
 f.host.__orgErasureNotices={innerHTML:'',appendChild:n=>nodes.push(n)};
 f.context.el=(tag,attrs={},children=[])=>({tag,attrs,children,appendChild(n){this.children.push(n)}});
 f.context.bl=x=>x.ja;f.notices(f.host);const text=JSON.stringify(nodes);assert.match(text,/このノードでの消去を確認できません/);assert.equal(text.includes('This tenant was deleted'),false);
});

test('manifest removal and unconfirmed artifact cleanup are explained without exposing backend errors',async()=>{
 const f=fixture();f.respond(method=>{const r=f.healthy(method);if(method==='POST'){r.body.complete=false;r.body.failures=['private shelf path'];r.body.artifact_cleanup={manifests:'absence_confirmed',local:'absence_confirmed',shared:'unconfirmed'};}return r});
 await f.send();assert.match(f.state().message.en,/Release manifests were removed/);assert.match(f.state().message.en,/installer file cleanup is not confirmed/);assert.equal(f.state().message.en.includes('private shelf'),false);
 f.respond(f.healthy);await f.context.eraseOrgRecords(id,f.host,f.state());assert.equal(f.state(),undefined);assert.deepEqual(f.calls.map(c=>c[0]),['DELETE','POST','POST']);
});
