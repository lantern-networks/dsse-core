import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source=readFileSync(new URL('./operatorhome.js',import.meta.url),'utf8');
function fixture(replies,lang){
 const calls=[];
 function el(tag,attrs={},children=[]){
  const node={tag,...attrs,children:[],textContent:attrs.text||'',appendChild(n){this.children.push(n);return n;},
   replaceChild(n,old){this.children[this.children.indexOf(old)]=n;},get firstChild(){return this.children[0];},
   set innerHTML(_){this.children=[];this.textContent='';},querySelectorAll(selector){return this.children.flatMap(n=>[...(n.tag===selector?[n]:[]),...n.querySelectorAll(selector)]);},
   querySelector(selector){const id=selector.match(/data-op-dist="([^"]+)"/)[1];return this.querySelectorAll('tr').find(n=>n['data-op-dist']===id);}};
  for(const n of [children].flat(Infinity))node.appendChild(n);return node;
 }
 const host=el('div'),c=vm.createContext({el,bl:x=>x[lang],freshRender:()=>()=>true,uiState(){},uiBadge:text=>el('span',{text}),
 apiFetch:async(method,path,body,plane,signal,tenant)=>{calls.push({path,tenant});return path==='/admin/tenants'?{ok:true,body:{tenants:replies.map((_,i)=>({tenant_id:'t'+i}))}}:replies[Number(tenant.slice(1))];}});
 vm.runInContext(source,c);const text=n=>[n.textContent,...n.children.map(text)].join(' ');
 return {c,host,calls,text:()=>text(host)};
}
const empty={ok:true,body:{envelopes:{},pending:{}}};
for(const lang of ['en','ja']){
 for(const status of [403,503])test(`distribution never claims every tenant is empty with an unreadable row ${status} (${lang})`,async()=>{
  const f=fixture([empty,{ok:false,status}],lang);await f.c.renderOperatorDistribution(f.host);
  assert.doesNotMatch(f.text(),/No tenant has a published release|どのテナントにも公開中のリリースがない/);
  assert.match(f.text(),status===403?(lang==='en'?/Not delegated: 1/:/委任なし: 1/):(lang==='en'?/Unreadable: 1/:/読取不能: 1/));
 });
 test(`published and pending platforms remain assigned to their tenant (${lang})`,async()=>{
  const f=fixture([{ok:true,body:{envelopes:{'windows/amd64':{}},pending:{'darwin/arm64':{}}}},empty],lang);
  await f.c.renderOperatorDistribution(f.host);assert.match(f.text(),/windows\/amd64/);assert.match(f.text(),/darwin\/arm64/);
  assert.match(f.text(),lang==='en'?/Published: 1/:/公開中: 1/);assert.deepEqual(f.calls.slice(1).map(x=>x.tenant),['t0','t1']);
 });
 test(`only a completely read empty distribution is called empty (${lang})`,async()=>{
  const f=fixture([empty,empty],lang);await f.c.renderOperatorDistribution(f.host);assert.match(f.text(),lang==='en'?/No tenant has/:/どのテナントにも/);
 });
}
