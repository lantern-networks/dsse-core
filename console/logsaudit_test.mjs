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

function volumeHarness(fetch) {
  const states=[], controls=[], nodes=[];
  const el=(tag,attrs={},children=[])=>{
    const node={tag,...attrs,children:[...children],appendChild(child){this.children.push(child);}};
    nodes.push(node);return node;
  };
  const host=el('section');
  const context=vm.createContext({host,el,bl:v=>v.en,freshRender:()=>()=>true,
    apiFetch:fetch,uiState:(...args)=>states.push(args),controls});
  vm.runInContext(source,context);
  vm.runInContext(`laLegalHold=h=>controls.push(['hold',h]);
    laAuditChain=h=>controls.push(['chain',h]);
    laRetentionConfig=h=>controls.push(['retention',h]);`,context);
  return {host,states,controls,nodes,render:()=>vm.runInContext('laVolume(host)',context)};
}

test('volume request failure or a pending request cannot hide retention and audit controls',async()=>{
  let finish;
  const pending=new Promise(resolve=>{finish=resolve;});
  const h=volumeHarness(async(method,path)=>path.startsWith('/admin/logs/')?pending:{ok:true,body:{identities:[]}});
  const rendering=h.render();
  assert.deepEqual(h.controls.map(c=>c[0]),['hold','chain','retention']);
  assert.equal(h.host.children.length,4);
  finish({ok:false,status:503});await rendering;
  const failure=h.states.find(s=>s[1]==='error');
  assert.equal(failure[0],h.host.children[0]);
  assert.match(failure[2],/503/);
  assert.equal(h.host.children.length,4);
});

test('volume count validates numeric data and retries only the failed estimate',async()=>{
  for(const value of [undefined,null,'12',NaN,Infinity,-1,1.5,Number.MAX_SAFE_INTEGER+1,0,12]){
    let recovery=false;
    const h=volumeHarness(async(method,path)=>path.startsWith('/admin/logs/')?
      {ok:true,body:{total_matches:recovery?20:value}}:{ok:true,body:{identities:[]}});
    await h.render();
    const failure=h.states.find(s=>s[1]==='error');
    if(value===0 || value===12){
      assert.equal(failure,undefined);assert.ok(h.nodes.some(n=>n.text===value.toLocaleString()));
    }else{
      assert.ok(failure,String(value));
      assert.equal(h.nodes.some(n=>n.text==='Access decisions / 24h'),false);
      const controls=[...h.controls];recovery=true;await failure[3].onClick();
      assert.deepEqual(h.controls,controls);
      assert.ok(h.nodes.some(n=>n.text==='20'));
    }
  }
});

test('volume transport failure remains local to the estimate',async()=>{
  const h=volumeHarness(async()=>{throw new Error('offline');});
  await h.render();
  assert.match(h.states.find(s=>s[1]==='error')[2],/offline/);
  assert.equal(h.controls.length,3);
});

test('access decision summary never labels other streams with an allow rate',()=>{
  const nodes=[];
  const host={innerHTML:'stale',appendChild:n=>nodes.push(n)};
  const context=vm.createContext({host,bl:v=>v.en,
    el:(tag,attrs={},children=[])=>({tag,...attrs,children}),uiBadge:()=>({})});
  vm.runInContext(source,context);
  for(const stream of ['audit','inspection','human_approval_events','access']){
    nodes.length=0;context.stream=stream;
    vm.runInContext('laSummary(host,[{decision:"allow"},{decision:"deny"}],stream)',context);
    assert.equal(host.innerHTML,'');assert.equal(nodes.length,stream==='access'?1:0);
    if(stream==='access')assert.match(JSON.stringify(nodes),/50%/);
  }
});

function relatedHarness(fetch) {
  const states=[],nodes=[];
  const host={appendChild:n=>nodes.push(n),set innerHTML(v){nodes.length=0;}};
  const context=vm.createContext({host,bl:v=>v.en,apiFetch:fetch,
    freshRender:h=>{const seq=h.seq=(h.seq||0)+1;return ()=>h.seq===seq;},
    uiState:(h,...args)=>{h.innerHTML='';states.push(args);},uiBadge:(label,kind)=>({label,kind}),
    el:(tag,attrs={},children=[])=>({tag,...attrs,children})});
  vm.runInContext(source,context);
  return {states,nodes,render:id=>{context.id=id;return vm.runInContext('laRelatedRecords(host,id)',context);}};
}

test('missing or malformed related records never claim that no records exist',async()=>{
  for(const body of [{},{access_decision_id:'d'},
    ...[null,[],{audit:null},{audit:'bad'},{audit:[null]},{audit:[[]]}].map(related_logs=>({access_decision_id:'d',related_logs})),
    {access_decision_id:'other',related_logs:{}}]){
    const h=relatedHarness(async()=>({ok:true,body}));await h.render('d');
    assert.equal(h.states.at(-1)[0],'error');assert.equal(h.nodes.length,0);
    assert.equal(typeof h.states.at(-1)[2].onClick,'function');
  }
});

test('related record failures can retry and only valid empty responses claim no links',async()=>{
  for(const response of [{ok:false,status:403},{ok:false,status:503},new Error('offline')]){
    let retry=false;
    const h=relatedHarness(async()=>{
      if(retry)return {ok:true,body:{access_decision_id:'d',related_logs:{audit:[]}}};
      if(response instanceof Error)throw response;return response;
    });
    await h.render('d');assert.equal(h.states.at(-1)[0],'error');
    retry=true;await h.states.at(-1)[2].onClick();
    assert.match(JSON.stringify(h.nodes),/No linked/);
  }
});

test('older related-record responses cannot replace the current decision',async()=>{
  for(const late of [{ok:true,body:{access_decision_id:'old',related_logs:{}}},{ok:false,status:503}]){
    let finish;const pending=new Promise(resolve=>{finish=resolve;});
    const h=relatedHarness(async(method,path)=>path.endsWith('/old')?pending:
      {ok:true,body:{access_decision_id:'new',related_logs:{audit:[{event_type:'new-event'}]}}});
    const old=h.render('old');await h.render('new');
    const rendered=JSON.stringify(h.nodes),stateCount=h.states.length;
    assert.match(rendered,/new-event/);finish(late);await old;
    assert.equal(JSON.stringify(h.nodes),rendered);assert.equal(h.states.length,stateCount);
  }
});

test('related approval summaries do not use trust state as an approval outcome',()=>{
  const c=vm.createContext({});vm.runInContext(source,c);
  assert.doesNotMatch(vm.runInContext('laRelatedSummary("human_approval_events",{trust_state:"trusted"})',c),/trusted/);
  assert.match(vm.runInContext('laRelatedSummary("human_approval_events",{outcome:"denied",trust_state:"trusted"})',c),/denied/);
});

test('stale administrator directory cannot overwrite the newest audit actor mapping',async()=>{
  let finish;const pending=new Promise(resolve=>{finish=resolve;});let reads=0;
  const host={appendChild(){}};
  const c=vm.createContext({host,URLSearchParams,bl:v=>v.en,uiState(){},
    freshRender:h=>{const seq=h.seq=(h.seq||0)+1;return ()=>h.seq===seq;},
    apiFetch:async(method,path)=>path.startsWith('/admin/logs/')?{ok:true,body:{rows:[],total_matches:0}}:
      (++reads===1?pending:{ok:true,body:{admins:[{id:'actor',email:'current@example.test'}]}})});
  vm.runInContext(source,c);vm.runInContext('_laStream="audit"',c);
  const old=vm.runInContext('laLoadStream(host,null,null)',c);
  // Let the first log read reach its optional directory lookup.
  await new Promise(resolve=>setImmediate(resolve));
  await vm.runInContext('laLoadStream(host,null,null)',c);
  assert.equal(vm.runInContext('_laAdminDir.actor.email',c),'current@example.test');
  finish({ok:true,body:{admins:[{id:'actor',email:'stale@example.test'}]}});await old;
  assert.equal(vm.runInContext('_laAdminDir.actor.email',c),'current@example.test');
});

test('starting a new log query clears the preceding allow-rate summary even when it fails',async()=>{
  for(const response of [{ok:false,status:503},new Error('offline')]){
    let finish;const pending=new Promise(resolve=>{finish=resolve;});
    const summary={innerHTML:'Allow rate 100%'};
    const c=vm.createContext({host:{},summary,URLSearchParams,bl:v=>v.en,uiState(){},freshRender:()=>()=>true,
      apiFetch:async()=>{await pending;if(response instanceof Error)throw response;return response;}});
    vm.runInContext(source,c);
    const load=vm.runInContext('laLoadStream(host,null,summary)',c);
    assert.equal(summary.innerHTML,'');finish();await load;assert.equal(summary.innerHTML,'');
  }
});

test('export list treats malformed success responses as unavailable and supports retry',async()=>{
 for(const body of [{},{jobs:null},{jobs:{}},{jobs:'bad'},{jobs:[null]},{jobs:[[]]}]){
  let recover=false;const states=[],empty=[];
  const c=vm.createContext({section:{innerHTML:'',appendChild(){}},bl:v=>v.en,freshRender:()=>()=>true,
   uiState:(...args)=>states.push(args),el:()=>({}),emptyBox:text=>{empty.push(text);return {};},
   apiFetch:async()=>({ok:true,body:recover?{jobs:[]}:body})});
  vm.runInContext(source,c);await vm.runInContext('laExports(section)',c);
  assert.equal(states.at(-1)[1],'error');assert.equal(empty.length,0);
  recover=true;await states.at(-1)[3].onClick();assert.deepEqual(empty,['No exports yet.']);
 }
});

function logSearchHarness(fetch){
 const states=[],calls=[];
 const c=vm.createContext({host:{innerHTML:'',appendChild(){}},URLSearchParams,bl:v=>v.en,
  freshRender:h=>{const seq=h.seq=(h.seq||0)+1;return ()=>h.seq===seq;},
  uiState:(...args)=>states.push(args),el:()=>({appendChild(){}}),
  apiFetch:async(...args)=>{calls.push(args);return fetch(...args);}});
 vm.runInContext(source,c);vm.runInContext('laColsFor=()=>[]',c);
 return {states,calls,render:append=>vm.runInContext(`laLoadStream(host,null,null,${!!append})`,c),
  state:()=>JSON.parse(vm.runInContext('JSON.stringify({rows:_laRows,cursor:_laCursor,total:_laTotal})',c))};
}

test('log search rejects malformed success responses instead of reporting no matches',async()=>{
 for(const body of [{},[],{rows:null,total_matches:0},{rows:[null],total_matches:1},{rows:[[]],total_matches:1},
  ...[null,'0',-1,1.5,Infinity].map(total_matches=>({rows:[],total_matches})),
  {rows:[],total_matches:0,next_cursor:{}}]){
  const h=logSearchHarness(async()=>({ok:true,body}));await h.render(false);
  assert.equal(h.states.at(-1)[1],'error');assert.deepEqual(h.state(),{rows:[],cursor:'',total:0});
 }
 const empty=logSearchHarness(async()=>({ok:true,body:{rows:[],total_matches:0,next_cursor:null}}));
 await empty.render(false);assert.equal(empty.states.at(-1)[1],'empty');
});

test('failed older-page requests retry the same cursor without dropping or duplicating loaded rows',async()=>{
 for(const failure of [{ok:false,status:503},new Error('offline'),{ok:true,body:{rows:[{id:'corrupt'}],total_matches:'bad',next_cursor:'wrong'}}]){
  let request=0;
  const h=logSearchHarness(async()=>{
   request++;
   if(request===1)return {ok:true,body:{rows:[{id:'first'}],total_matches:2,next_cursor:'page-2'}};
   if(request===2){if(failure instanceof Error)throw failure;return failure;}
   return {ok:true,body:{rows:[{id:'second'}],total_matches:2,next_cursor:null}};
  });
  await h.render(false);const before=h.state();await h.render(true);
  assert.equal(h.states.at(-1)[1],'error');assert.deepEqual(h.state(),before);
  await h.states.at(-1)[3].onClick();
  assert.deepEqual(h.state(),{rows:[{id:'first'},{id:'second'}],cursor:'',total:2});
  assert.equal(new URL('https://console.test'+h.calls[1][1]).searchParams.get('cursor'),'page-2');
  assert.equal(h.calls[2][1],h.calls[1][1]);
 }
});

test('export download rejects malformed links and failures without offering a file', async () => {
  for (const mode of ['http', 'missing', 'path', 'scheme', 'query', 'fetch', 'network']) {
    const messages=[]; let fetched=0; const button={disabled:false};
    const links={path:'https://internal.invalid/admin/other/token',scheme:'javascript:alert(1)',query:'https://internal.invalid/admin/export-downloads/token?extra=1'};
    const c=vm.createContext({URL,window:{location:{origin:'https://console.invalid'}},bl:v=>v.en,uiToast:(...a)=>messages.push(a),baseForPlane:()=>'/control',
      apiFetch:async()=>({ok:mode!=='http',status:503,body:mode==='missing'?{}:{download_url:links[mode]||'https://internal.invalid/admin/export-downloads/token'}}),
      fetch:async()=>{fetched++;if(mode==='network')throw new Error('offline');return {ok:false,status:404};},button});
    vm.runInContext(source,c);await vm.runInContext('laDownloadExport({id:"job"},button)',c);
    assert.equal(messages.length,1);assert.equal(messages[0][1],'err');assert.equal(button.disabled,false);
    assert.equal(fetched,['fetch','network'].includes(mode)?1:0);
  }
});

test('export download stays on the control proxy and blocks concurrent clicks', async () => {
  const calls=[];let clicked=0,release; const button={disabled:false};
  const c=vm.createContext({URL:class extends URL {static createObjectURL(){return 'blob:test';}static revokeObjectURL(){}},window:{location:{origin:'https://console.invalid'}},bl:v=>v.en,uiToast:()=>assert.fail('unexpected failure'),baseForPlane:()=>'/control',setTimeout:()=>{},button,
    apiFetch:async(...args)=>{calls.push(args);await new Promise(r=>release=r);return {ok:true,body:{download_url:'https://internal.invalid/admin/export-downloads/token-1'}};},
    fetch:async(path,options)=>{assert.equal(path,'/control/admin/export-downloads/token-1');assert.equal(options.redirect,'error');return {ok:true,blob:async()=>({})};},
    document:{createElement:()=>({click(){clicked++;},remove(){}}),body:{appendChild(){}}}});
  vm.runInContext(source,c);const first=vm.runInContext('laDownloadExport({id:"job/id"},button)',c);
  await vm.runInContext('laDownloadExport({id:"job/id"},button)',c);assert.equal(calls.length,1);release();await first;
  assert.equal(calls[0][1],'/admin/export-jobs/job%2Fid/download-url');assert.equal(calls[0][3],'control');assert.equal(clicked,1);assert.equal(button.disabled,false);
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


test('partial outcomes use a warning color while pending and unknown outcomes stay neutral', () => {
  for (const value of ['partial', ' PARTIAL ']) {
    const result = badge(value);
    assert.equal(result.kind, 'warn');
    assert.equal(result.label, value);
  }
  for (const value of ['pending', 'queued', 'running', 'partial_success', 'partially_failed']) {
    assert.equal(badge(value).kind, 'off', value);
  }
});
