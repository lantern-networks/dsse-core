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

test('export cancellation refreshes authoritative state after success or uncertainty', async () => {
 for(const mode of ['dismiss','success','http','network','wrong-job','wrong-status']) {
  const calls=[],messages=[];let refresh=0;const button={disabled:false};
  const c=vm.createContext({button,bl:v=>v.en,uiConfirm:async()=>mode!=='dismiss',uiToast:(...a)=>messages.push(a),
   apiFetch:async(...a)=>{calls.push(a);if(mode==='network')throw Error('offline');return {ok:mode!=='http',status:403,body:{id:mode==='wrong-job'?'other':'job',status:mode==='wrong-status'?'completed':'cancelled'}};},refresh:async()=>refresh++});
  vm.runInContext(source,c);vm.runInContext('laExports=refresh',c);await vm.runInContext('laCancelExport({id:"job"},button,{})',c);
  assert.equal(button.disabled,false);assert.equal(calls.length,mode==='dismiss'?0:1);assert.equal(refresh,mode==='dismiss'?0:1);
  if(mode!=='dismiss'){assert.equal(calls[0][1],'/admin/export-jobs/job/cancel');assert.equal(calls[0][3],'control');assert.equal(messages[0][1],mode==='success'?'ok':'err');}
 }
});

test('export details refuse a mismatched or failed response rather than showing another job', async () => {
 for(const mode of ['http','wrong-job','network']) {
  const button={disabled:false};let messages=0;
  const c=vm.createContext({button,bl:v=>v.en,uiToast:()=>messages++,uiModal:()=>assert.fail('must not open details'),apiFetch:async()=>{if(mode==='network')throw Error('offline');return {ok:mode!=='http',body:{id:'other',status:'completed'}};}});
  vm.runInContext(source,c);await vm.runInContext('laExportDetails({id:"job"},button)',c);assert.equal(messages,1);assert.equal(button.disabled,false);
 }
});


