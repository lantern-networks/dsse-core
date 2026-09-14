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

test('partial batch responses reach one-time disclosure instead of being discarded',async()=>{
 for(const count of [0,1,2]){
  let submit,closed=0,refresh=0;const disclosures=[],errors=[];
  const tokens=Array.from({length:count},(_,i)=>({token:{id:'id-'+i},secret:'secret-'+i}));
  const c=vm.createContext({bl:v=>v.en,uiToast:(...a)=>errors.push(a),
   uiField:f=>({el:{},get:()=>f.name==='count'?'3':f.value||'label',validate:()=>true,focus(){},setError(){}}),
   el:(tag,attrs)=>({...attrs,addEventListener:(event,fn)=>{submit=fn;}}),uiModal:()=>({close:()=>closed++}),
   apiFetch:async()=>({ok:false,status:409,body:{partial:true,tokens,error:'stopped'}}),
   disclose:b=>disclosures.push(b),refresh:()=>refresh++});
  vm.runInContext(source,c);vm.runInContext('showEnrolTokenOnce=disclose;renderEnrolmentTokensView=refresh',c);
  await vm.runInContext('openEnrolTokenForm({})',c);await submit();
  assert.equal(closed,count?1:0);assert.equal(refresh,count?1:0);
  if(count){assert.equal(disclosures[0].tokens.length,count);assert.equal(disclosures[0].requested_count,3);assert.equal(disclosures[0].partial,true);}
  else {assert.equal(disclosures.length,0);assert.equal(errors[0][1],'err');}
 }
});

test('single-token partial batch preserves its secret and shows the partial issuance notice',()=>{
 const modals=[],errors=[];
 const c=vm.createContext({bl:v=>v.en,uiToast:(...a)=>errors.push(a),
  el:(tag,attrs={})=>({tag,...attrs,addEventListener(){}}),uiModal:m=>{modals.push(m);return {close(){}};}});
 vm.runInContext(source,c);
 vm.runInContext('showEnrolTokenOnce({partial:true,requested_count:3,tokens:[{token:{id:"one"},secret:"exact-secret"}]})',c);
 assert.equal(errors.length,0);assert.equal(modals.length,1);
 assert.ok(modals[0].body.some(n=>n.text==='exact-secret'));
 assert.ok(modals[0].body.some(n=>n.text?.includes('1 of 3')));
});

test('missing issuance credentials never announce approval success',()=>{
 for(const body of [{},{tokens:[{token:{id:'bad'}}]},{tokens:'bad'}]){
  const errors=[];const c=vm.createContext({body,uiToast:(...a)=>errors.push(a)});
  vm.runInContext(source,c);vm.runInContext('showEnrolTokenOnce(body)',c);
  assert.equal(errors.length,1);assert.equal(errors[0][1],'err');
 }
});
