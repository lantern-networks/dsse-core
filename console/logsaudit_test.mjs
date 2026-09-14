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
