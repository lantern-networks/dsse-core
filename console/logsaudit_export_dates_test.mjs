import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';
const source=readFileSync(new URL('./logsaudit.js',import.meta.url),'utf8');
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



test('export list refreshes and offers downloads only for completed jobs', async () => {
  const nodes=[];
  const c=vm.createContext({
    bl:v=>v.en, window:{dsseFormatTime:v=>v}, uiState(){}, freshRender:()=>()=>true,
    apiFetch:async()=>({ok:true,body:{jobs:['queued','running','failed','incomplete','completed'].map(status=>({id:status,status}))}}),
    el:(_tag,p,children)=>{const n={...p,children};nodes.push(n);return n;},
    uiBadge:(text,kind)=>({text,kind}), simpleTable:(_headers,rows)=>({rows}),
  });
  vm.runInContext(source,c);
  const children=[];
  await c.laExports({appendChild:n=>children.push(n)});
  assert.equal(nodes.filter(n=>n.text==='Refresh').length,1);
  assert.equal(nodes.filter(n=>n.text==='Download').length,1);
  assert.equal(nodes.filter(n=>n.text==='Cancel').length,2);
  assert.equal(nodes.filter(n=>n.text==='Details').length,5);
  assert.deepEqual(Array.from(children[1].rows,r=>r[2].kind),['off','off','danger','off','ok']);
});
