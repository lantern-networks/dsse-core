import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';
const source = readFileSync(new URL('./connectors.js', import.meta.url), 'utf8');
function fixture(response = {ok:true,status:200,body:{connector:{id:'connector-one'},runtime_secret:'test-runtime-secret'}}) {
 const modals=[],toasts=[],requests=[];
 const context=vm.createContext({operateTenant:'tenant-one',idpSession:{id:'session'},baseForPlane:()=>'/control',
  bl:v=>v.en,uiConfirm:async()=>true,uiToast:(...args)=>toasts.push(args),
  el:(tag,attrs={},children=[])=>({tag,...attrs,children}),
  uiModal:spec=>{modals.push(spec);return{close(){}}},
  apiFetch:async(...args)=>{requests.push(args);return typeof response==='function'?response():response}});
 vm.runInContext(source,context);return{context,modals,toasts,requests};
}
test('Connector rotation delivers the returned one-time secret',async()=>{
 const f=fixture();await f.context.rotateConnector('connector-one',null);
 assert.equal(f.modals.length,1);assert.equal(f.modals[0].body.at(-1).text,'test-runtime-secret');
 assert.equal(f.requests.length,1);assert.equal(f.toasts.length,0);
});
for(const [name,response] of [['storage error',{ok:false,status:503,body:{error:'PRIVATE_DIAGNOSTIC'}}],['missing secret',{ok:true,status:200,body:{connector:{id:'connector-one'}}}],['wrong connector',{ok:true,status:200,body:{connector:{id:'other'},runtime_secret:'test-runtime-secret'}}],['transport exception',()=>{throw Error('PRIVATE_DIAGNOSTIC')}]] ) {
 test('Connector rotation does not confirm '+name,async()=>{const f=fixture(response);await f.context.rotateConnector('connector-one',null);assert.equal(f.modals.length,0);assert.equal(f.toasts.length,1);assert.doesNotMatch(JSON.stringify(f.toasts),/PRIVATE_DIAGNOSTIC|test-runtime-secret/);assert.match(f.toasts[0][0],/could not be confirmed/)});
}
test('Connector rotation suppresses duplicate writes and late cross-tenant secret display',async()=>{
 let release;const f=fixture(()=>new Promise(r=>release=r));const first=f.context.rotateConnector('connector-one',null);await new Promise(r=>setImmediate(r));
 await f.context.rotateConnector('connector-one',null);assert.equal(f.requests.length,1);f.context.operateTenant='another';release({ok:true,status:200,body:{connector:{id:'connector-one'},runtime_secret:'late-secret'}});await first;assert.equal(f.modals.length,0);assert.equal(f.toasts.length,0);
});
test('Connector rotation does not write after confirmation changes tenant',async()=>{
 const f=fixture();f.context.uiConfirm=async()=>{f.context.operateTenant='another';return true};await f.context.rotateConnector('connector-one',null);assert.equal(f.requests.length,0);
});
