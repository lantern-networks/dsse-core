import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';
const source=readFileSync(new URL('./dlpfingerprints.js',import.meta.url),'utf8');
const tick=()=>new Promise(resolve=>setImmediate(resolve));
async function fixture(specs=[]){
 const fields={},buttons=[],modals=[],toasts=[],writes=[];
 const el=(tag,props={},children=[])=>{
  const node={tag,...props,children:[].concat(children),style:{},querySelectorAll:()=>[],appendChild(c){this.children.push(c)},scrollIntoView(){this.scrolled=true}};
  if(tag==='button')buttons.push(node);return node;
 };
 const context=vm.createContext({el,bl:x=>x.en,uiState(){},freshRender:host=>{const n=host.sequence=(host.sequence||0)+1;return ()=>host.sequence===n},emptyBox:()=>el('div'),simpleTable:()=>el('table'),uiBadge:()=>el('span'),uiConfirm:async()=>true,
  uiToast:(...args)=>toasts.push(args),uiField:opts=>{
   const field={value:opts.value||'',el:{querySelector:()=>({addEventListener(){}})},get(){return this.value},validate:()=>true,focus(){},setError(message){this.error=message}};
   fields[opts.name]=field;return field;
  },uiModal:opts=>{const modal={...opts,closed:false,close(){this.closed=true}};modals.push(modal);return modal},
  apiFetch:async(method,path,body)=>{if(path==='/admin/tenant')return {ok:true,status:200,body:{tenant_id:'tenant'}};if(method==='GET')return {ok:true,status:200,body:{tenant_id:'tenant',datasets:specs}};writes.push(body);return {ok:true,status:200,body:{tenant_id:'tenant',dataset:{name:body.name,count:1},datasets:[{name:body.name,count:1}]}}}
 });
 vm.runInContext(readFileSync(new URL('./dlplibrary.js',import.meta.url),'utf8'),context);vm.runInContext(source,context);await context.renderDLPFingerprintsView(el('div'));await tick();
 return {fields,buttons,modals,toasts,writes,context};
}
test('dataset save suppresses repeated submission and keeps the error in the editor for retry',async()=>{
 const f=await fixture();f.buttons.find(b=>b.text==='+ Add dataset').onClick();f.fields.name.value='project_code';f.fields.values.value='SYNTHETIC-ONLY';
 const modal=f.modals.at(-1),save=modal.footer.find(b=>b.text==='Fingerprint'),alert=modal.body.find(n=>n.role==='alert');
 let resolve;f.context.apiFetch=async(_method,_path,body)=>{if(_method==='GET')return {ok:true,status:200,body:{tenant_id:'tenant'}};f.writes.push(body);return await new Promise(r=>resolve=r)};
 const first=save.onClick();assert.equal(save.disabled,true);await save.onClick();await tick();assert.equal(f.writes.length,1);
 resolve({ok:false,status:500,body:{error:'saving could not be confirmed'}});await first;
 assert.equal(modal.closed,false);assert.equal(save.disabled,false);assert.equal(alert.textContent,'saving could not be confirmed');assert.equal(alert.style.display,'');assert.equal(alert.scrolled,true);assert.equal(f.toasts.length,0);
 f.context.apiFetch=async(_method,_path,body)=>{if(_method==='GET')return {ok:true,status:200,body:{tenant_id:'tenant'}};f.writes.push(body);return {ok:true,status:200,body:{tenant_id:'tenant',dataset:{name:body.name,count:1},datasets:[{name:body.name,count:1}]}}};await save.onClick();
 assert.equal(modal.closed,true);assert.equal(f.writes.length,2);assert.equal(alert.style.display,'none');assert.equal(f.toasts.at(-1)[1],'ok');
});
test('delete save failure preserves the row and uses the supported error notice',async()=>{
 const f=await fixture([{name:'project_code',count:1}]);
 f.context.apiFetch=async(_method,_path,body)=>{if(_method==='GET')return {ok:true,status:200,body:{tenant_id:'tenant'}};f.writes.push(body);return {ok:false,status:500,body:{error:'save failed'}}};
 await f.buttons.find(b=>b.text==='Delete').onClick();assert.equal(f.writes.length,1);assert.equal(f.toasts.at(-1)[1],'err');assert.equal(f.toasts.at(-1)[0],'save failed');
 f.buttons.find(b=>b.text==='Replace…').onClick();assert.equal(f.fields.name.value,'project_code');assert.equal(f.fields.values.value,'');
});

test('Add dataset ignores the click event and opens a creation dialog',async()=>{const f=await fixture();f.buttons.find(b=>b.text==='+ Add dataset').onClick({type:'click'});assert.equal(f.modals.at(-1).title,'Add Exact-Data-Match dataset');assert.equal(f.fields.name.value,'');});
