import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';
const source=readFileSync(new URL('./agentreleases.js',import.meta.url),'utf8');
function fixture(){
 const nodes=[],fields={},toasts=[],requests=[];let modal;
 const el=(tag,props={},children=[])=>{const n={tag,...props,children:Array.isArray(children)?children:[children],handlers:{},appendChild(x){this.children.push(x)},addEventListener(k,f){this.handlers[k]=f}};Object.defineProperty(n,'innerHTML',{set(){this.children=[]}});nodes.push(n);return n};
 const c=vm.createContext({el,bl:x=>x.en,uiField:opts=>{const f={el:el('input'),value:opts.value,get(){return this.value},setError(error){this.error=error},focus(){}};fields[opts.name]=f;return f},uiModal:opts=>{modal=opts;return{close(){}}},uiToast:(...a)=>toasts.push(a),apiFetch:async(...a)=>{requests.push(a);return{ok:false,status:500}},document:{createTextNode:s=>s}});
 vm.runInContext(source,c);return{c,nodes,fields,toasts,requests,get modal(){return modal}};
}
const json=x=>JSON.parse(JSON.stringify(x));
const schedule=()=>({waves:[{group:'Pilot',delay_days:0,priority:9},{group:'General',delay_days:5,priority:-1}],default_delay_days:11});
test('editing a wave delay preserves priority and default',async()=>{
 const f=fixture(),before=schedule();f.c.openAgentWavesForm({},before,[]);const inputs=f.nodes.filter(n=>n.tag==='input');inputs[3].value='4';inputs[3].handlers.input();await f.modal.footer[1].handlers.click();assert.deepEqual(json(f.requests[0][2]),{intent:'schedule',waves:{waves:[{group:'Pilot',delay_days:0,priority:9},{group:'General',delay_days:4,priority:-1}],default_delay_days:11}});assert.deepEqual(before,schedule());
});
test('renaming a group preserves that row priority',async()=>{const f=fixture();f.c.openAgentWavesForm({},schedule(),[]);const n=f.nodes.find(n=>n.tag==='input');n.value='Pilot renamed';n.handlers.input();await f.modal.footer[1].handlers.click();assert.equal(f.requests[0][2].waves.waves[0].priority,9);assert.equal(f.requests[0][2].waves.waves[0].group,'Pilot renamed');});
test('removing a group retains remaining row and default',async()=>{const f=fixture();f.c.openAgentWavesForm({},schedule(),[]);f.nodes.find(n=>n.text==='−').onClick();await f.modal.footer[1].handlers.click();assert.deepEqual(json(f.requests[0][2].waves),{waves:[{group:'General',delay_days:5,priority:-1}],default_delay_days:11});});
for(const days of ['1.5','-1','Infinity','9007199254740992'])test('wave rejects '+days,async()=>{const f=fixture();f.c.openAgentWavesForm({},schedule(),[]);const d=f.nodes.filter(n=>n.tag==='input')[1];d.value=days;d.handlers.input();await f.modal.footer[1].handlers.click();assert.equal(f.requests.length,0);assert.equal(f.toasts.length,1);});
for(const [field,value] of [['idle','1.5'],['idle','-1'],['idle','9007199254740992'],['deadline','1.5'],['deadline','366'],['deadline','-1']])test('window rejects '+field+' '+value,async()=>{const f=fixture();f.c.openAgentWindowForm({},{});f.fields[field].value=value;await f.modal.footer[1].handlers.click();assert.equal(f.requests.length,0);assert.ok(f.fields[field].error);});
test('window accepts boundary days and idle integers',async()=>{const f=fixture();f.c.openAgentWindowForm({},{});f.fields.deadline.value='365';f.fields.idle.value='0';await f.modal.footer[1].handlers.click();assert.equal(f.requests[0][2].window.deadline_days,365);assert.equal(f.requests[0][2].window.require_idle_minutes,0);});
test('summary shows configured priority and unmatched default',()=>{const f=fixture();const s=f.c.arWavesSummary(schedule());assert.match(s,/priority 9/);assert.match(s,/priority -1/);assert.match(s,/other groups after 11d/);});
test('an empty wave set still has an explicit default',()=>{const f=fixture();assert.equal(f.c.arWavesSummary({waves:[],default_delay_days:7}),'all groups after 7d');assert.match(f.c.arWavesSummary({waves:[]}),/everything at once/);});
test('version summary exposes a hold and its reason',()=>{const f=fixture();const s=f.c.arRunningSummary({frozen:true,reason:'incident',desired_version:'2.0.0'},{});assert.match(s,/Updates paused: incident/);assert.match(s,/2.0.0/);});
