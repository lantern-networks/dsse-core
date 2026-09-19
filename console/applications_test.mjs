import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source=readFileSync(new URL('./applications.js',import.meta.url),'utf8');
const fresh={tenant_id:'tenant',saas_provider:'',saas_category:'',saas_risk_tier:'',domain_pattern_count:0,sni_pattern_count:0,updated_at:'2026-09-15T00:00:00Z',application_id:'ssh',application_type:'private_app',name:'Current',published:true,destination:'192.0.2.40',destination_port:22,publish_protocol:'tcp',connector_group_id:'current-site',routing_namespace:'current-scope',service_family:'ssh',protocol:'tcp',destination_role:'ssh_server',route_ref:'route',tags:['critical'],status:'draft',application_sensitivity:'medium'};
function form({existing=fresh,get=async()=>({ok:true,body:fresh}),values={}}={}){
 const fields={},calls=[],errors=[];let handler,button;
 const c=vm.createContext({bl:v=>v.en,uiToast:(m,t)=>{if(t==='err')errors.push(m);},document:{body:{appendChild(){}},getElementById:()=>({})},
  uiField:f=>{fields[f.name]=f;return {el:{querySelector:()=>({setAttribute(){}})},get:()=>values[f.name]??f.value,validate:()=>true,focus(){},setError:m=>errors.push(m)};},
  el:(tag,attrs)=>{const obj={...attrs,remove(){},addEventListener:(event,fn)=>{handler=fn;button=obj;}};return obj;},
  apiFetch:async(method,path,body)=>{calls.push({method,path,body});return method==='GET'?get():{ok:true,body};}});
 vm.runInContext(source,c);vm.runInContext('renderApplicationsView=()=>{}',c);c.openAppForm({},existing);
 return {c,fields,calls,errors,submit:()=>handler(),button:()=>button};
}
test('name edits preserve current routing metadata rather than the stale list entry',async()=>{
 const f=form({existing:{...fresh,destination:'192.0.2.1',connector_group_id:'old-site'},values:{name:'Renamed'}});await f.submit();
 assert.deepEqual(f.calls.map(x=>x.method),['GET','POST']);const saved=JSON.parse(JSON.stringify(f.calls[1].body));assert.deepEqual(saved,{...fresh,name:'Renamed'});assert.equal(f.errors.length,0);
});
test('read failures, missing edited entries and malformed details never write',async()=>{
 for(const get of [async()=>({ok:false,status:503}),async()=>({ok:false,status:404}),async()=>{throw Error('offline');},...([null,[],{}, {application_id:'ssh',application_type:'private_app'}, {...fresh,tags:{}}, {...fresh,domain_pattern_count:undefined}, {...fresh,application_id:'other'}, {...fresh,application_type:'bad'}].map(body=>async()=>({ok:true,body})))]){
  const f=form({get});await f.submit();assert.equal(f.calls.filter(x=>x.method==='POST').length,0);assert.equal(f.button().disabled,false);assert.ok(f.errors.length);
 }
});
test('a new ID accepts only an explicit 404 as a missing base; existing IDs retain SaaS metadata',async()=>{
 const f=form({existing:null,values:{id:'new',name:'New'},get:async()=>({ok:false,status:404})});await f.submit();assert.equal(f.calls[1].body.application_id,'new');
 const metadata={...fresh,application_id:'saas',application_type:'saas',saas_provider:'provider',saas_category:'collaboration',saas_risk_tier:'high',domain_pattern_count:3,sni_pattern_count:2,published:false};
 const g=form({existing:null,values:{id:'saas',name:'Rename',type:'saas'},get:async()=>({ok:true,body:metadata})});await g.submit();for(const k of ['saas_provider','saas_category','saas_risk_tier','domain_pattern_count','sni_pattern_count'])assert.equal(g.calls[1].body[k],metadata[k]);
 const failed=form({existing:null,get:async()=>({ok:false,status:503})});await failed.submit();assert.equal(failed.calls.length,1);
});
test('existing draft and medium values remain selectable instead of changing on an unrelated edit',()=>{
 const f=form();for(const [field,value]of [['status','draft'],['sensitivity','medium']]){assert.equal(f.fields[field].value,value);assert.equal(f.fields[field].options.filter(x=>x.value===value).length,1);}
});
test('a second save activation during the detail read cannot issue another write',async()=>{
 let release;const f=form({get:()=>new Promise(resolve=>{release=resolve;})});const first=f.submit();await f.submit();assert.equal(f.calls.length,1);release({ok:true,body:fresh});await first;assert.equal(f.calls.filter(x=>x.method==='POST').length,1);
});

test('input changes during the detail read cannot copy one application into another ID',async()=>{
 let release;const values={id:'ssh',name:'Submitted'};const f=form({existing:null,values,get:()=>new Promise(resolve=>{release=resolve;})});const pending=f.submit();values.id='other';values.name='Later input';release({ok:true,body:fresh});await pending;assert.equal(f.calls[1].body.application_id,'ssh');assert.equal(f.calls[1].body.name,'Submitted');
});

function publicationFixture(responses) {
 const calls=[],nodes=[],fields={};let modal,closed=0;
 const el=(tag,attrs={},children=[])=>{
  const n={tag,...attrs,style:{},children:Array.isArray(children)?children:[children],listeners:[],appendChild(x){this.children.push(x)},setAttribute(){},addEventListener(event,fn){if(event==='click')this.listeners.push(fn)},querySelector(){return this.input||(this.input=el('input'))},async click(){if(this.disabled)return;for(const fn of this.listeners)await fn();if(this.onclick)await this.onclick()}};nodes.push(n);return n;
 };
 const c=vm.createContext({bl:v=>v.en,el,uiToast(){},document:{getElementById:()=>({})},uiField:f=>{const n=el('div');fields[f.name]={value:f.value||f.placeholder||'',el:n,get(){return this.value},validate:()=>true,focus(){},setError(){}};return fields[f.name]},uiModal:spec=>{modal=spec;return{close(){closed++}}},apiFetch:async(method,path,body)=>{if(method==='GET')return{ok:true,body:{sites:[]}};calls.push({method,path,body});return responses.shift()}});
 vm.runInContext(source,c);vm.runInContext('renderApplicationsView=()=>{}',c);c.openPublishWizard({});
 return{calls,nodes,fields,get button(){return modal.footer[1]},get closed(){return closed}};
}
test('publication Done only closes and never submits a second publish',async()=>{
 const f=publicationFixture([{ok:true,body:{review:{published_route:true}}}]);await f.button.click();assert.equal(f.calls.length,1);assert.equal(f.button.textContent,'Done');await f.button.click();assert.equal(f.calls.length,1);assert.equal(f.closed,1);
});
test('collision step requires explicit approval and sends exactly one override',async()=>{
 const f=publicationFixture([{ok:false,status:409,body:{error:'cidr_route_collision',collisions:[]}},{ok:true,body:{review:{published_route:true}}}]);await f.button.click();assert.equal(f.calls.length,1);await f.button.click();assert.equal(f.calls.length,1);f.nodes.findLast(n=>n.type==='checkbox').checked=true;await f.button.click();await new Promise(resolve=>setImmediate(resolve));assert.equal(f.calls.length,2);assert.equal(f.calls[1].body.override_cidr_collision,true);await f.button.click();assert.equal(f.calls.length,2);assert.equal(f.closed,1);
});
