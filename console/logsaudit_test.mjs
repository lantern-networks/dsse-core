import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('./logsaudit.js', import.meta.url), 'utf8');
function badge(value) {
  const context = vm.createContext({uiBadge: (label, kind) => ({label, kind})});
  vm.runInContext(source, context);
  context.value = value;
  return vm.runInContext('laResultBadge(value)', context);
}
test('only explicit successful outcomes receive the success color', () => {
  for (const value of ['ok', 'success', 'allow', 'approved', 'done', 'complete', 'completed', ' SUCCESS ']) {
    assert.equal(badge(value).kind, 'ok', value);
  }
});
test('negative and incomplete outcomes cannot be mistaken for success', () => {
  for (const value of ['revoked', 'broken', 'not_ok', 'unsuccessful', 'unapproved', 'incomplete', 'failed', 'denied', 'rejected', 'error', 'failed_to_allow']) {
    assert.notEqual(badge(value).kind, 'ok', value);
  }
  for (const value of ['revoked', 'failed', 'denied', 'rejected', 'error']) {
    assert.equal(badge(value).kind, 'danger', value);
  }
});
test('unrecognized values remain neutral and keep their original text', () => {
  for (const value of ['success_pending', 'allow_requested', 'vendor_result', 'incomplete']) {
    const result = badge(value);
    assert.equal(result.kind, 'off', value);
    assert.equal(result.label, value);
  }
  assert.equal(badge(null).label, '—');
});

test('terminal negative outcomes are distinguishable from pending', () => {
  assert.equal(badge('pending').kind, 'off');
  for (const value of ['expired', 'cancelled', 'canceled', 'withdrawn', 'timeout', 'timed_out']) {
    assert.equal(badge(value).kind, 'danger', value);
  }
});

test('approval outcome does not borrow device trust state', () => {
  const context = vm.createContext({uiBadge: (label, kind) => ({label, kind})});
  vm.runInContext(source, context);
  const columns = vm.runInContext('_LA_COLS.human_approval_events', context);
  const outcome = columns.find(c => c.h.en === 'Outcome');
  const trust = columns.find(c => c.h.en === 'Trust state');
  assert.equal(outcome.c({trust_state: 'trusted'}).label, '—');
  assert.equal(trust.c({trust_state: 'trusted'}), 'trusted');
  assert.equal(outcome.c({outcome: 'denied', trust_state: 'trusted'}).kind, 'danger');
});

test('unavailable legal hold never renders Off or a mutation button', async () => {
  for (const response of [{ok:false,status:503,body:{error:'unavailable'}},{ok:true,body:{}},new Error('offline')]) {
    const states=[],badges=[];
    const host={};
    const context=vm.createContext({host, freshRender:()=>()=>true, bl:v=>v.en,
      apiFetch:async()=>{if(response instanceof Error)throw response;return response;},
      uiState:(...args)=>states.push(args),uiBadge:(...args)=>badges.push(args),
      el:()=>{throw new Error('error state must not render mutation controls');}});
    vm.runInContext(source,context);
    await vm.runInContext('laLegalHold(host)',context);
    assert.equal(states.length,1);
    assert.equal(states[0][1],'error');
    assert.equal(badges.length,0);
    assert.equal(typeof states[0][3].onClick,'function');
  }
});

test('regional coverage distinguishes zero from unavailable', () => {
  const context=vm.createContext({bl:v=>v.en});vm.runInContext(source,context);
  for(const value of [undefined,{status:'unavailable',unknown_region_count:null},{status:'available',unknown_region_count:null},{status:'available',unknown_region_count:-1}]){
    context.coverage=value;
    assert.match(vm.runInContext('laRegionCoverageText(coverage)',context),/could not be determined/);
  }
  for(const count of [0,7]){
    context.coverage={status:'available',unknown_region_count:count};
    assert.match(vm.runInContext('laRegionCoverageText(coverage)',context),new RegExp(': '+count+'$'));
  }
});

test('failed hold mutations reload authoritative state and handle network errors', async () => {
  for (const failure of [{ok:false,status:503,body:{error:'unavailable'}},new Error('offline')]) {
    let click;
    const calls=[],states=[],toasts=[];
    const host={appendChild(){},innerHTML:''};
    const context=vm.createContext({host,freshRender:()=>()=>true,bl:v=>v.en,
      uiConfirm:async()=>true,uiBadge:()=>({}),uiToast:(...args)=>toasts.push(args),
      uiState:(...args)=>states.push(args),
      el:(tag)=>({addEventListener:(event,handler)=>{if(tag==='button')click=handler;}}),
      apiFetch:async(method)=>{
        calls.push(method);
        if(calls.length===1)return {ok:true,body:{tenant_held:true}};
        if(method==='POST'){if(failure instanceof Error)throw failure;return failure;}
        return {ok:false,status:503,body:{error:'unavailable'}};
      }});
    vm.runInContext(source,context);
    await vm.runInContext('laLegalHold(host)',context);
    await click();
    assert.deepEqual(calls,['GET','POST','GET']);
    assert.equal(toasts.length,1);
    assert.equal(toasts[0][1],'err');
    assert.equal(states[0][1],'error');
  }
});

test('export list shows regional exclusions for completed and legacy jobs', async () => {
  for (const coverage of [undefined,{status:'available',unknown_region_count:0}]) {
    const texts=[];
    const context=vm.createContext({section:{appendChild(){},innerHTML:''},freshRender:()=>()=>true,
      uiState(){},bl:v=>v.en,uiBadge:()=>({}),simpleTable:()=>({}),
      el:(tag,props)=>{if(props && props.text)texts.push(props.text);return {};},
      apiFetch:async()=>({ok:true,body:{jobs:[{stream:'access',status:'completed',filters:{edge_region_id:'region-a'},metadata:{region_coverage:coverage}}]}})});
    vm.runInContext(source,context);
    await vm.runInContext('laExports(section)',context);
    assert.ok(texts.some(t=>coverage ? /: 0$/.test(t) : /could not be determined/.test(t)));
  }
});

test('audit writer observations never turn unknown or malformed state into healthy', () => {
 const c=vm.createContext({bl:v=>v.en});vm.runInContext(source,c);
 for(const value of [null,{}, {status:'healthy',primary_failures:null,hook_failures:0}]){
  c.value=value;assert.throws(()=>vm.runInContext('laAuditWriterHealthText(value)',c));
 }
 for(const [status,match] of [['unknown',/No completed writes/],['unavailable',/Unavailable/],['degraded',/Write failures 2/]]){
  c.value={status,primary_failures:status==='degraded'?2:0,hook_failures:0};assert.match(vm.runInContext('laAuditWriterHealthText(value)',c),match);
 }
});

test('audit writer read failure offers retry; forbidden scope shows no statistics', async () => {
 for(const response of [{ok:false,status:503},{ok:false,status:403}]){
  const states=[],texts=[];const c=vm.createContext({host:{innerHTML:'',appendChild(){}},bl:v=>v.en,freshRender:()=>()=>true,
   apiFetch:async()=>response,uiState:(...a)=>states.push(a),el:(tag,p)=>{texts.push(p.text);return {};}});
  vm.runInContext(source,c);await vm.runInContext('laAuditWriterHealth(host)',c);
  if(response.status===503){assert.equal(states[0][1],'error');assert.equal(typeof states[0][3].onClick,'function');}
  else {assert.equal(states.length,0);assert.match(texts[0],/deployment administrators/);}
 }
});
