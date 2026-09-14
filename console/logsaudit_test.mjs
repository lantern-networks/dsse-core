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

function retentionHarness(api) {
 const calls=[], states=[], toasts=[], buttons=[], fields={};
 const host={innerHTML:'',appendChild(){}};
 const context=vm.createContext({host,bl:v=>v.en,freshRender:()=>()=>true,
  apiFetch:async(...args)=>{calls.push(args);return api(...args);},
  uiState:(...args)=>states.push(args),uiToast:(...args)=>toasts.push(args),
  uiField:spec=>{const f={el:{style:{}},value:spec.value,get(){return this.value;}};fields[spec.name]=f;return f;},
  el:(tag,props)=>{const e={...props,addEventListener:(event,handler)=>{e.click=handler;}};if(tag==='button')buttons.push(e);return e;}});
 vm.runInContext(source,context);
 return {calls,states,toasts,buttons,fields,render:()=>vm.runInContext('laRetentionConfig(host)',context)};
}

test('unavailable retention never masquerades as defaults or offers mutation controls',async()=>{
 for(const response of [{ok:false,status:503},{ok:true,body:{}},{ok:true,body:{overrides_days:null}},{ok:true,body:{overrides_days:{audit:-1}}},new Error('offline')]){
  const h=retentionHarness(async()=>{if(response instanceof Error)throw response;return response;});
  await h.render();assert.equal(h.buttons.length,0);assert.equal(h.states[0][1],'error');assert.equal(typeof h.states[0][3].onClick,'function');
 }
});

test('retention day entry rejects truncation and preserves explicit zero',async()=>{
 for(const value of ['', '0.5', '1.9', '2oops', '-1', '106752', '9007199254740993', '0','365','106751']){
  const h=retentionHarness(async()=>({ok:true,body:{overrides_days:{audit:0}}}));
  await h.render();h.fields.d.value=value;await h.buttons[0].click();
  const posts=h.calls.filter(c=>c[0]==='POST');
  if(['0','365','106751'].includes(value)){assert.equal(posts.length,1);assert.equal(posts[0][2].days,Number(value));}
  else {assert.equal(posts.length,0,value);assert.equal(h.toasts[0][1],'err');}
 }
});

test('retention mutations disable both actions and reload after HTTP or network failure',async()=>{
 for(const reset of [false,true])for(const failure of [{ok:false,status:500},new Error('offline')]){
  let finish;
  const pending=new Promise(resolve=>{finish=resolve;});
  let reads=0;
  const h=retentionHarness(async(method)=>{
   if(method==='GET'){reads++;return reads===1?{ok:true,body:{overrides_days:{audit:0}}}:{ok:false,status:503};}
   await pending;if(failure instanceof Error)throw failure;return failure;
  });
  await h.render();h.fields.d.value='90';
  const clicked=h.buttons[reset?1:0].click();
  assert.ok(h.buttons[0].disabled && h.buttons[1].disabled);
  await h.buttons[reset?0:1].click();
  assert.equal(h.calls.filter(c=>c[0]==='POST').length,1);
  finish();await clicked;
  assert.deepEqual(h.calls.map(c=>c[0]),['GET','POST','GET']);
  assert.equal(h.toasts[0][1],'err');assert.equal(h.states[0][1],'error');
 }
});

test('archive verification distinguishes empty, broken, limited success and malformed results',async()=>{
 for(const body of [
  {ok:false,status:'empty',scope:'listed_segments_only',segments:0},
  {ok:true,status:'links_verified',scope:'listed_segments_only',segments:2},
  {ok:false,status:'broken',scope:'listed_segments_only',segments:1,detail:'invalid header'},
  {},{ok:true,status:'links_verified',scope:'listed_segments_only',segments:0},
  {ok:'true',status:'links_verified',scope:'listed_segments_only',segments:1},
  {ok:true,status:'empty',scope:'listed_segments_only',segments:0},
 ]) {
  let click;const badges=[],toasts=[];
  const context=vm.createContext({host:{innerHTML:'',appendChild(){}},bl:v=>v.en,
   apiFetch:async()=>({ok:true,body}),uiBadge:(...args)=>{badges.push(args);return {};},uiToast:(...args)=>toasts.push(args),
   el:()=>({appendChild(){},addEventListener:(event,fn)=>{click=fn;}})});
  vm.runInContext(source,context);vm.runInContext('laAuditChain(host)',context);await click();
  if(body.status==='empty' && body.ok===false){assert.equal(badges[0][1],'off');assert.match(badges[0][0],/No segments/);}
  else if(body.status==='links_verified' && body.ok===true && body.segments===2){assert.match(badges[0][0],/Listed links/);}
  else if(body.status==='broken'){assert.equal(badges[0][1],'danger');}
  else {assert.equal(badges.length,0);assert.equal(toasts[0][1],'err');}
 }
});

test('audit writer snapshot states retrieval time and avoids missing-record interpretation',async()=>{
 const texts=[];
 const context=vm.createContext({host:{innerHTML:'',appendChild(){}},bl:v=>v.en,freshRender:()=>()=>true,
  apiFetch:async()=>({ok:true,body:{status:'degraded',primary_failures:2,hook_failures:0}}),
  uiBadge:()=>({}),el:(tag,p)=>{texts.push(p.text);return {};}});
 vm.runInContext(source,context);await vm.runInContext('laAuditWriterHealth(host)',context);
 assert.ok(texts.some(t=>/not missing-record counts/.test(t)));
 assert.ok(texts.some(t=>/Retrieved at .*T.*Z.*does not refresh automatically/.test(t)));
});

test('export calendar range includes the whole local end day across time zones and DST',()=>{
 const saved=process.env.TZ;
 try{
  for(const [zone,day,from,to] of [
   ['Asia/Tokyo','2026-09-14','2026-09-13T15:00:00.000Z','2026-09-14T14:59:59.999999999Z'],
   ['UTC','2026-09-14','2026-09-14T00:00:00.000Z','2026-09-14T23:59:59.999999999Z'],
   ['America/New_York','2026-03-08','2026-03-08T05:00:00.000Z','2026-03-09T03:59:59.999999999Z'],
  ]){
   process.env.TZ=zone;
   const c=vm.createContext({bl:v=>v.en,day});vm.runInContext(source,c);
   const range=vm.runInContext('laExportDateRange(day,day)',c);
   assert.equal(range.from,from);assert.equal(range.to,to);
  }
 }finally{if(saved===undefined)delete process.env.TZ;else process.env.TZ=saved;}
});

test('export form rejects incomplete and invalid dates, allows retry and omits unsupported CSV',async()=>{
 for(const [from,to] of [['',''],['2026-02-30','2026-03-01'],['2026-09-15','2026-09-14']]){
  const fields={},buttons=[],toasts=[],calls=[];
  const c=vm.createContext({section:{},bl:v=>v.en,uiToast:(...a)=>toasts.push(a),
   apiFetch:async(...a)=>{calls.push(a);return {ok:false,status:503};},
   uiModal:()=>({close(){}}),uiField:spec=>{const f={el:{},value:spec.value,get(){return this.value;},options:spec.options};fields[spec.name]=f;return f;},
   el:(tag,p)=>{const e={...p,addEventListener:(event,fn)=>{e.click=fn;}};if(tag==='button')buttons.push(e);return e;}});
  vm.runInContext(source,c);vm.runInContext('openExportForm(section)',c);
  assert.deepEqual(Array.from(fields.fmt.options,x=>x.value),['ndjson']);
  fields.from.value=from;fields.to.value=to;
  const submit=buttons.find(b=>b.text==='Create export');await submit.click();
  assert.equal(calls.length,0);assert.equal(submit.disabled,false);assert.equal(toasts[0][1],'err');
  fields.from.value='2026-09-14';fields.to.value='2026-09-14';await submit.click();
  assert.equal(calls.length,1);assert.equal(submit.disabled,false);assert.equal(toasts.at(-1)[1],'err');
 }
});

test('export statuses use exact outcomes rather than substring success',async()=>{
 const badges=[];
 const c=vm.createContext({section:{innerHTML:'',appendChild(){}},bl:v=>v.en,freshRender:()=>()=>true,uiState(){},
  apiFetch:async()=>({ok:true,body:{jobs:['incomplete','failed','completed','queued'].map(status=>({status}))}}),
  uiBadge:(label,kind)=>{badges.push({label,kind});return {};},el:()=>({}),simpleTable:()=>({})});
 vm.runInContext(source,c);await vm.runInContext('laExports(section)',c);
 assert.equal(badges.find(x=>x.label==='incomplete').kind,'off');
 assert.equal(badges.find(x=>x.label==='failed').kind,'danger');
 assert.equal(badges.find(x=>x.label==='completed').kind,'ok');
 assert.equal(badges.find(x=>x.label==='queued').kind,'off');
});
