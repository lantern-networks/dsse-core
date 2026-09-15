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
  else {assert.equal(disclosures.length,0);assert.equal(errors[0][1],'err');assert.match(errors[0][0],/may already have been created/);assert.match(errors[0][0],/Resolve the failure/);}
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
  const errors=[];const c=vm.createContext({body,bl:v=>v.en,uiToast:(...a)=>errors.push(a)});
  vm.runInContext(source,c);vm.runInContext('showEnrolTokenOnce(body)',c);
  assert.equal(errors.length,1);assert.equal(errors[0][1],'err');
  assert.match(errors[0][0],/may already have been created/);
  assert.match(errors[0][0],/before issuing more/);
 }
});


test('malformed partial issuance warns of saved tokens without disclosure or automatic reissue',async()=>{
 for(const tokens of [[{token:{id:'valid'},secret:'secret-valid'},{token:{id:'missing-secret'}}],'invalid',undefined]){
  let submit,calls=0,closed=0;const errors=[],fieldErrors=[];
  const c=vm.createContext({bl:v=>v.en,uiToast:(...a)=>errors.push(a),
   uiField:f=>({el:{},get:()=>f.name==='count'?'3':f.value||'label',validate:()=>true,focus(){},setError:m=>fieldErrors.push(m)}),
   el:(tag,attrs)=>({...attrs,addEventListener:(event,fn)=>{submit=fn;}}),uiModal:()=>({close:()=>closed++}),
   apiFetch:async()=>{calls++;return {ok:false,status:409,body:{partial:true,tokens,error:'stopped'}};},
   fail:()=>assert.fail('must not disclose a malformed batch')});
  vm.runInContext(source,c);vm.runInContext('showEnrolTokenOnce=fail',c);
  await vm.runInContext('openEnrolTokenForm({})',c);await submit();
  assert.equal(calls,1);assert.equal(closed,0);assert.equal(errors.length,1);
  assert.match(errors[0][0],/may already have been created/);
  assert.match(errors[0][0],/reload the unused-token list/);
  assert.equal(fieldErrors.at(-1),errors[0][0]);assert.equal(errors[0][1],'err');
 }
});


test('issuance counts require decimal whole numbers in the API range', () => {
 const c=vm.createContext({bl:v=>v.en});vm.runInContext(source,c);
 for(const raw of ['', '0', '-1', '1.5', 'abc', '1e2', '501', 'Infinity', '9007199254740992']) {
  const errors=[];assert.equal(c.enrolTokenCount({get:()=>raw,setError:e=>errors.push(e)}),null,raw);assert.ok(errors[0]);
 }
 for(const [raw,want] of [['1',1],['500',500],[' 12 ',12],['002',2]]) {
  assert.equal(c.enrolTokenCount({get:()=>raw,setError:e=>assert.equal(e,'')}),want);
 }
});

test('success requires a complete count of well-formed one-time credentials', () => {
 const c=vm.createContext({});vm.runInContext(source,c);
 const body={tokens:[{token:{id:'one'},secret:'secret'}]};assert.equal(c.enrolTokenCompleteBody(body,1),true);
 for(const value of [undefined,{}, {tokens:[]}, {tokens:[{}]}, {...body,partial:true}])assert.equal(c.enrolTokenCompleteBody(value,1),false);
 assert.equal(c.enrolTokenCompleteBody(body,2),false);
});

function issuanceForm() {
 const fields={},nodes=[],calls=[],disclosures=[];let closed=0;
 const c=vm.createContext({bl:v=>v.en,uiToast(){},
  uiField:spec=>{const field={el:{},value:spec.value||'label',get(){return this.value;},validate:()=>true,focus(){},setError(error){this.error=error;}};fields[spec.name]=field;return field;},
  el:(tag,attrs={})=>{const node={tag,...attrs,addEventListener(event,fn){this[event]=fn;}};nodes.push(node);return node;},
  uiModal:()=>({close:()=>closed++}),apiFetch:async(...args)=>{calls.push(args);return {ok:true,body:{tokens:[]}};}});
 vm.runInContext(source,c);c.showEnrolTokenOnce=body=>disclosures.push(body);c.renderEnrolmentTokensView=()=>{};
 c.openEnrolTokenForm({});const button=nodes.find(n=>n.text==='Approve device');
 return {c,fields,button,calls,disclosures,closed:()=>closed};
}

test('standalone form does not send invalid counts or silently approve one device',async()=>{
 const f=issuanceForm();
 for(const value of ['0','-1','1.5','abc','501','']){f.fields.count.value=value;await f.button.click();assert.equal(f.calls.length,0);assert.equal(f.closed(),0);assert.match(f.fields.count.error,/1 to 500/);}
});

test('standalone uncertain responses keep the form open and require an explicit retry',async()=>{
 for(const response of [new Error('offline'),{ok:false,status:503},{ok:true,body:{}},{ok:true,body:{tokens:[]}}]){
  const f=issuanceForm();f.fields.count.value='2';f.c.apiFetch=async(...args)=>{f.calls.push(args);if(response instanceof Error)throw response;return response;};
  await f.button.click();assert.equal(f.calls.length,1);assert.equal(f.closed(),0);assert.equal(f.disclosures.length,0);assert.equal(f.button.disabled,false);assert.match(f.fields.label.error,/may already have been created/);
  f.c.apiFetch=async(...args)=>{f.calls.push(args);return {ok:true,body:{tokens:[{token:{id:'one'},secret:'a'},{token:{id:'two'},secret:'b'}]}};};
  await f.button.click();assert.equal(f.calls.length,2);assert.equal(f.calls[1][2].count,2);assert.equal(f.closed(),1);assert.equal(f.disclosures.length,1);
 }
});
