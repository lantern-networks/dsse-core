import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';
const source = readFileSync(new URL('./connectors.js', import.meta.url), 'utf8');

function routeFixture(routes = [], routeReply) {
 const calls=[],toasts=[];
 function el(tag,props={},children=[]){const node={tag,...props,style:{},value:props.value||'',children:[],appendChild(c){if(c)this.children.push(c)},querySelectorAll(tags){return this.children.flatMap(n=>[n,...n.querySelectorAll(tags)]).filter(n=>tags.split(',').includes(n.tag));}};Object.defineProperty(node,'innerHTML',{set(){this.children=[]}});for(const c of [children].flat(Infinity))node.appendChild(c);return node;}
 const context=vm.createContext({el,bl:x=>x.en,uiBadge:(text)=>el('span',{text}),uiToast:(...args)=>toasts.push(args),uiState:(host,kind,message,action)=>{host.innerHTML='';host.appendChild(el('div',{text:message,kind},action?[el('button',{text:action.label,onClick:action.onClick})]:[]));},apiFetch:async(method,path,payload)=>{calls.push({method,path,payload});return path.endsWith('/routes')?(routeReply?routeReply():{ok:true,body:{routes}}):{ok:true,body:{objects:[{id:'named',name:'Office',cidrs:['10.73.0.0/24']}]}};}});
 vm.runInContext(source,context);const host=el('div');context.connRouteAction=async(id,payload)=>calls.push({method:'POST',id,payload});return{context,host,calls,toasts};
}
test('Reported routes have no unsupported Adopt/Hold/Unhold controls',async()=>{
 const f=routeFixture([{kind:'cidr',source:'connector',cidr:'10.72.0.0/24',pending:true},{kind:'cidr',source:'connector',cidr:'10.74.0.0/24',held:true},{kind:'cidr',source:'connector',cidr:'10.75.0.0/24',routable:true}]);await f.context.renderConnectorRouteGovernance(f.host,'c');
 assert.equal(f.host.querySelectorAll('button').filter(b=>['Adopt','Hold','Unhold'].includes(b.text)).length,0);
 assert.equal(f.host.querySelectorAll('span').filter(n=>n.text==='Routable').length,0);
});
test('Direct CIDR entry retains input and explains Named Networks without a request',async()=>{
 const f=routeFixture();await f.context.renderConnectorRouteGovernance(f.host,'c');const input=f.host.querySelectorAll('input')[0];input.value='10.73.0.0/24';await f.host.querySelectorAll('button').find(b=>b.text==='+ Bind network').onClick();
 assert.equal(f.calls.filter(c=>c.method==='POST').length,0);assert.equal(input.value,'10.73.0.0/24');assert.match(f.toasts.at(-1)[0],/Networks/);assert.doesNotMatch(input.placeholder,/\//);
});
test('Hostname and Named Network bindings and legacy raw removal remain available',async()=>{
 const f=routeFixture([{kind:'cidr',source:'admin',cidr:'10.70.0.0/24',routable:true}]);await f.context.renderConnectorRouteGovernance(f.host,'c');const inputs=f.host.querySelectorAll('input');inputs[0].value=' wiki.routes.test ';inputs[1].value='test description';await f.host.querySelectorAll('button').find(b=>b.text==='+ Bind network').onClick();
 f.host.querySelectorAll('select')[0].value='named';await f.host.querySelectorAll('button').find(b=>b.text==='+ Bind Named Network').onClick();await f.host.querySelectorAll('button').find(b=>b.text==='Remove').onClick();
 assert.deepEqual(JSON.parse(JSON.stringify(f.calls.filter(c=>c.method==='POST').map(c=>c.payload))),[{fqdn:'wiki.routes.test',action:'add',description:'test description'},{action:'add',network_id:'named'},{action:'remove',cidr:'10.70.0.0/24'}]);
});

for (const [name, failure] of [
 ['HTTP failure', () => ({ok:false,status:503})],
 ['transport failure', () => {throw Error('private diagnostic')}],
 ['malformed success', () => ({ok:true,body:{}})],
]) {
 test('Connector route '+name+' requires retry before editing',async()=>{
  let failed=true;
  const f=routeFixture([{kind:'fqdn',source:'admin',fqdn:'existing.example'}],()=>failed?failure():{ok:true,body:{routes:[{kind:'fqdn',source:'admin',fqdn:'existing.example'}]}});
  await f.context.renderConnectorRouteGovernance(f.host,'c');
  assert.equal(f.host.querySelectorAll('button').filter(b=>b.text==='+ Bind network').length,0);
  assert.equal(f.host.querySelectorAll('button').filter(b=>b.text==='Remove').length,0);
  assert.equal(f.host.querySelectorAll('p').filter(p=>/No networks/.test(p.text)).length,0);
  assert.equal(f.calls.filter(c=>c.method==='POST').length,0);
  const retry=f.host.querySelectorAll('button').find(b=>b.text==='Retry');
  assert.ok(retry);
  failed=false;
  await retry.onClick();
  assert.equal(f.host.querySelectorAll('button').filter(b=>b.text==='+ Bind network').length,1);
  assert.equal(f.host.querySelectorAll('button').filter(b=>b.text==='Remove').length,1);
 });
}
