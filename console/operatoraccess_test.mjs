import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';
const source=readFileSync(new URL('./operatoraccess.js',import.meta.url),'utf8');
for(const language of ['en','ja']) test(`pending elevation can be approved and stopped (${language})`,async()=>{
 const calls=[];const el=(tag,props={},children=[])=>({tag,...props,children:[children].flat(Infinity)});
 const c=vm.createContext({el,document:{createTextNode:text=>({text})},bl:x=>x[language],fmtTime:x=>x,uiBadge:text=>({text}),uiToast(){},apiFetch:async(...args)=>{calls.push(args);return{ok:true}}});vm.runInContext(source,c);
 const buttons=n=>[...(n.tag==='button'?[n]:[]),...(n.children||[]).flatMap(buttons)];
 let reloads=0;const row=c.operatorElevationRow({id:'elevation',state:'pending_approval',approval_required:true},()=>reloads++),b=buttons(row);
 assert.equal(b.length,3);assert.equal(b[0].text,language==='en'?'Approve':'承認する');await b[0].onClick();await b[1].onClick();assert.deepEqual(calls.map(x=>x.slice(0,2)),[['POST','/admin/operator-elevations/elevation/approve'],['DELETE','/admin/operator-elevations/elevation']]);assert.equal(reloads,2);
 for(const state of ['ended','expired']) assert.equal(buttons(c.operatorElevationRow({id:'elevation',state},()=>{})).length,1);
});
