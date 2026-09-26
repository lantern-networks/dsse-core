import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';
const source=readFileSync(new URL('./incoming.js',import.meta.url),'utf8');
test('saving only an owner change keeps the persisted exception restrictions',async()=>{
 const fields={},buttons=[],writes=[];
 const existing={id:'limited',source_server:'192.0.2.9',device_group:'ops',business_owner:'old',service_family:'custom',protocol:'tcp',port:4444,status:'disabled',mode:'warn',approval_required:true,max_session_seconds:77,expires_at:'2030-01-01T15:12:13Z'};
 const c=vm.createContext({bl:x=>x.en,catalogIndex:async()=>({endpoints:[],groups:[],services:[]}),
  uiField:o=>{let value=o.value;const f={el:{querySelector:()=>({setAttribute(){}})},get:()=>value,set:v=>value=v,validate:()=>true,focus(){}};fields[o.name]=f;return f},
  el:(tag,props)=>{const b={...props,addEventListener:(_event,fn)=>b.click=fn};if(tag==='button')buttons.push(b);return b},
  uiModal:()=>({close(){}}),uiToast(){},apiFetch:async(method,path,body)=>{writes.push({method,path,body});return {ok:true,status:200,body}},
 });
 vm.runInContext(source,c);c.renderIncomingView=()=>{};
 await c.openExceptionForm({},existing);fields.owner.set('new');await buttons.find(b=>b.text==='Save').click();
 assert.equal(writes.length,1);assert.equal(writes[0].body.business_owner,'new');
 for(const key of ['service_family','protocol','port','status','mode','approval_required','max_session_seconds','expires_at'])assert.equal(writes[0].body[key],existing[key],key);
});
