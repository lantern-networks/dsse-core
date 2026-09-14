import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source=readFileSync(new URL('./enrolmenttokens.js',import.meta.url),'utf8');

test('batch CSV uses CSV quoting and preserves every credential byte',async()=>{
 let blob,download,clicked=false;
 const c=vm.createContext({Blob,URL:{createObjectURL:b=>{blob=b;return 'blob:test';},revokeObjectURL(){}},
  document:{createElement:()=>({set download(v){download=v;},click(){clicked=true;}}),body:{appendChild(){},removeChild(){}}}});
 vm.runInContext(source,c);
 vm.runInContext(`downloadTokenBatch([{token:{label:'Osaka "Sales", desk\\n2',id:'id-1',expires_at:'2026-09-15T00:00:00Z'},secret:'-secret_ABC'},
 {token:{label:'東京\\r\\n部署',id:'id-2',expires_at:'later'},secret:'second'}],2)`,c);
 assert.equal(await blob.text(),'label,token_id,secret,expires_at\n"Osaka ""Sales"", desk\n2","id-1","-secret_ABC","2026-09-15T00:00:00Z"\n"東京\r\n部署","id-2","second","later"\n');
 assert.equal(download,'enrolment-tokens-2.csv');assert.equal(clicked,true);
});

test('revocation reports transport and HTTP failures without announcing success or refreshing',async()=>{
 for(const response of [new Error('offline'),{ok:false,status:503,body:{error:'unavailable'}}]){
  const messages=[];let refreshes=0;
  const c=vm.createContext({bl:v=>v.en,uiConfirm:async()=>true,uiToast:(...args)=>messages.push(args),
   apiFetch:async()=>{if(response instanceof Error)throw response;return response;},refresh:()=>refreshes++});
  vm.runInContext(source,c);vm.runInContext('renderEnrolTokenList=refresh',c);
  await vm.runInContext('revokeEnrolToken({id:"token"},{})',c);
  assert.equal(messages.length,1);assert.equal(messages[0][1],'err');assert.equal(refreshes,0);
 }
});

test('revocation preserves cancellation, control-plane routing and already-used warnings',async()=>{
 for(const confirmed of [false,true])for(const note of ['', 'Already used; revoke the device instead']){
  const calls=[],messages=[];let refreshes=0;
  const c=vm.createContext({bl:v=>v.en,uiConfirm:async()=>confirmed,uiToast:(...args)=>messages.push(args),
   apiFetch:async(...args)=>{calls.push(args);return {ok:true,body:{note}};},refresh:()=>refreshes++});
  vm.runInContext(source,c);vm.runInContext('renderEnrolTokenList=refresh',c);
  await vm.runInContext('revokeEnrolToken({id:"token/id"},{})',c);
  assert.equal(calls.length,confirmed?1:0);assert.equal(refreshes,confirmed?1:0);
  if(confirmed){assert.equal(calls[0][1],'/admin/enrolment-tokens/token%2Fid/revoke');assert.equal(calls[0][3],'control');assert.equal(messages[0][1],note?'err':'ok');}
 }
});
