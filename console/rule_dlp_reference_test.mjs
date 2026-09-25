import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';

function dlpSelectorFixture(reply, existing='saved-policy') {
  const select={disabled:false,value:'',options:[],replaceChildren(...options){this.options=options;this.value=options[0]?.value||'';}};
  const errors=[];const field={el:{querySelector:()=>select},setError:m=>errors.push(m)};
  const ctx=vm.createContext({bl:b=>b.en,el:(_tag,props)=>props,apiFetch:()=>reply});
  vm.runInContext(readFileSync(new URL('./rules.js',import.meta.url),'utf8'),ctx);
  return {select,errors,start:()=>ctx.loadRuleDLPPolicies(field,existing)};
}
test('rule DLP selection survives loading and a temporarily unavailable list',async()=>{
  let resolve;const f=dlpSelectorFixture(new Promise(r=>resolve=r));const pending=f.start();
  assert.equal(f.select.value,'saved-policy');assert.equal(f.select.disabled,true);
  resolve({ok:false,status:503});await pending;
  assert.equal(f.select.value,'saved-policy');assert.equal(f.select.disabled,true);assert.match(f.errors.at(-1),/unchanged/);
});
test('deleted policy remains selectable until the operator explicitly chooses None',async()=>{
  const f=dlpSelectorFixture(Promise.resolve({ok:true,body:{policies:[]}}));await f.start();
  assert.equal(f.select.value,'saved-policy');assert.equal(f.select.disabled,false);
  assert.deepEqual(f.select.options.map(x=>x.value),['','saved-policy']);assert.match(f.errors.at(-1),/not available/);
  f.select.value='';assert.equal(f.select.value,'');
});
test('available policies replace placeholders without losing the current reference',async()=>{
  const f=dlpSelectorFixture(Promise.resolve({ok:true,body:{policies:[{id:'saved-policy',name:'Protection'},{id:'other',name:'Other'}]}}));await f.start();
  assert.equal(f.select.value,'saved-policy');assert.equal(f.select.disabled,false);assert.equal(f.select.options[1].text,'Protection');assert.equal(f.select.options.length,3);
});
