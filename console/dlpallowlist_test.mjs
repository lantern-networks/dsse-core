import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';
const source=readFileSync(new URL('./dlpallowlist.js',import.meta.url),'utf8');
const tick=()=>new Promise(resolve=>setImmediate(resolve));
async function fixture(specs=[]){
 const fields={},buttons=[],modals=[],toasts=[],writes=[];
 const el=(tag,props={},children=[])=>{
  const node={tag,...props,children:[].concat(children),style:{},appendChild(c){this.children.push(c)},scrollIntoView(){this.scrolled=true}};
  if(tag==='button')buttons.push(node);return node;
 };
 const context=vm.createContext({el,bl:x=>x.en,uiState(){},emptyBox:()=>el('div'),simpleTable:()=>el('table'),uiBadge:()=>el('span'),uiConfirm:async()=>true,
  uiToast:(...args)=>toasts.push(args),uiField:opts=>{
   const field={value:opts.value||'',el:{querySelector:()=>({addEventListener(){}})},get(){return this.value},validate:()=>true,focus(){},setError(message){this.error=message}};
   fields[opts.name]=field;return field;
  },uiModal:opts=>{const modal={...opts,closed:false,close(){this.closed=true}};modals.push(modal);return modal},
  apiFetch:async(method,path,body)=>{if(method==='GET')return {ok:true,body:{values:specs}};writes.push(body);return {ok:true,body:{values:body.values}}}
 });
 vm.runInContext(source,context);await context.renderDLPAllowlistView(el('div'));await tick();
 return {fields,buttons,modals,toasts,writes,context};
}
test('allowlist save keeps input and inline failure for retry and coalesces repeated submits',async()=>{
 const f=await fixture();f.buttons.find(b=>b.text==='+ Add value').onClick();f.fields.value.value='SYNTHETIC-ONLY';
 const modal=f.modals.at(-1),save=modal.footer.find(b=>b.text==='Add'),alert=modal.body.find(n=>n.role==='alert');
 let resolve;f.context.apiFetch=async(_method,_path,body)=>{f.writes.push(body);return await new Promise(r=>resolve=r)};
 const first=save.onClick();assert.equal(save.disabled,true);await save.onClick();assert.equal(f.writes.length,1);
 resolve({ok:false,status:500,body:{error:'saving could not be confirmed'}});await first;
 assert.equal(modal.closed,false);assert.equal(save.disabled,false);assert.equal(f.fields.value.value,'SYNTHETIC-ONLY');assert.equal(alert.textContent,'saving could not be confirmed');assert.equal(alert.style.display,'');assert.equal(alert.scrolled,true);assert.equal(f.toasts.length,0);
 f.context.apiFetch=async(_method,_path,body)=>{f.writes.push(body);return {ok:true,body:{values:body.values}}};await save.onClick();
 assert.equal(modal.closed,true);assert.equal(f.writes.length,2);assert.equal(alert.style.display,'none');assert.equal(f.toasts.at(-1)[1],'ok');
});
test('remove failure retains the old list for the next edit and uses the error notice',async()=>{
 const f=await fixture(['SYNTHETIC-ONLY']);
 f.context.apiFetch=async(_method,_path,body)=>{f.writes.push(body);return {ok:false,status:500,body:{error:'save failed'}}};
 await f.buttons.find(b=>b.text==='Remove').onClick();assert.equal(f.writes.length,1);assert.equal(f.toasts.at(-1)[1],'err');assert.equal(f.toasts.at(-1)[0],'save failed');
 f.buttons.find(b=>b.text==='+ Add value').onClick();f.fields.value.value='NEW';
 await f.modals.at(-1).footer.find(b=>b.text==='Add').onClick();assert.deepEqual(Array.from(f.writes.at(-1).values),['SYNTHETIC-ONLY','NEW']);
});
test('blank or duplicate values do not submit, but literal case variants remain distinct',async()=>{
 const f=await fixture(['BLUEFIN']);f.buttons.find(b=>b.text==='+ Add value').onClick();const save=f.modals.at(-1).footer.find(b=>b.text==='Add');
 f.fields.value.value='  ';await save.onClick();assert.equal(f.writes.length,0);
 f.fields.value.value=' BLUEFIN ';await save.onClick();assert.equal(f.writes.length,0);assert.equal(f.toasts.at(-1)[1],'info');
 f.fields.value.value='bluefin';await save.onClick();assert.equal(f.writes.length,1);assert.deepEqual(Array.from(f.writes[0].values),['BLUEFIN','bluefin']);
});
