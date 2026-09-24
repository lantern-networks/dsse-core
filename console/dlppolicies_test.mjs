import {readFileSync} from 'node:fs';import vm from 'node:vm';import assert from 'node:assert/strict';import test from 'node:test';
const source=readFileSync(new URL('./dlppolicies.js',import.meta.url),'utf8');
function fixture(overrides={}){
 const states=[],buttons=[],calls=[];const defaults={policies:[],classifiers:[],datasets:[],domains:[]};
 const el=(tag,props={},children=[])=>{if(tag==='button')buttons.push(props.text);return {appendChild(){},innerHTML:'',style:{}}};
 const context=vm.createContext({el,bl:x=>x.en,uiState:(_node,state,_message,retry)=>states.push({state,retry}),freshRender:()=>()=>true,emptyBox:()=>({}),simpleTable:()=>({}),uiBadge:()=>({}),apiFetch:async(_method,path)=>{calls.push(path);const key={'/admin/dlp-policies':'policies','/admin/dlp-classifiers':'classifiers','/admin/dlp-fingerprints':'datasets','/admin/organization-domains':'domains'}[path];return overrides[key]||{ok:true,status:200,body:{[key]:defaults[key]}};}});
 vm.runInContext(source,context);return {context,states,buttons,calls,el};
}
for(const key of ['policies','classifiers','datasets','domains']){
 for(const [name,response] of Object.entries({http:{ok:false,status:503},missing:{ok:true,body:{}},shape:{ok:true,body:{[key]:{}}},entry:{ok:true,body:{[key]:[42]}}})){
 test(`${key} ${name} failure blocks its required operation`,async()=>{const f=fixture({[key]:response});if(key==='policies'){await f.context.renderDLPPoliciesView(f.el('div'));assert.equal(f.states.at(-1).state,'error');assert.equal(f.states.at(-1).retry.label,'Retry');assert.equal(f.buttons.includes('+ Add policy'),false);}else{await assert.rejects(f.context.dlpEditorDependencies());}});
 }
}
test('explicit null empty slices are valid, and successful empty data enables creation',async()=>{const f=fixture(Object.fromEntries(['policies','classifiers','datasets','domains'].map(key=>[key,{ok:true,body:{[key]:null}}])));assert.equal(Object.values(await f.context.dlpEditorDependencies()).every(v=>v.length===0),true);await f.context.renderDLPPoliciesView(f.el('div'));assert.equal(f.buttons.includes('+ Add policy'),true);assert.equal(f.states.some(s=>s.state==='error'),false);});
test('obsolete request failure does not replace a newer render',async()=>{const f=fixture({policies:{ok:false,status:503}});f.context.freshRender=()=>()=>false;await f.context.renderDLPPoliciesView(f.el('div'));assert.deepEqual(f.states.map(s=>s.state),['loading']);});

test('risk counts require nonnegative safe whole numbers',()=>{const f=fixture();for(const value of ['', '12x','1.5','-1','1e3','Infinity','9007199254740992'])assert.equal(f.context.dlpWholeCount(value),null,value);for(const [value,want]of [['0',0],['12',12],[' 12 ',12],['9007199254740991',9007199254740991]])assert.equal(f.context.dlpWholeCount(value),want);});
function saveFixture(raw='12',types='2'){
 const fields={},writes=[],submit={disabled:false},saveError={style:{},scrollIntoView(){}};
 const field=(name,value)=>({get:()=>value,validate:()=>true,focus(){},setError:message=>fields[name]=message});
 const context=vm.createContext({bl:x=>x.en,missingIDs:[],submit,saveError,nameF:field('name','Observe'),idFields:[{id:'email',f:{get:()=>true}}],drEnableF:{get:()=>true},drCountF:field('count',raw),drTypesF:field('types',types),drSameF:{get:()=>true},drWinF:{get:()=> '300'},drClassF:{get:()=> 'any'},actionF:{get:()=> 'observe'},scopeF:{get:()=> 'any'},existing:null,m:{close(){}},render(){},uiToast(){},_policies:[],apiFetch:async(...args)=>{writes.push(args);return {ok:true,body:{policies:[]}}}});
 vm.runInContext(source.slice(source.indexOf('function dlpWholeCount'),source.indexOf('async function renderDLPPoliciesView')),context);
 const start=source.indexOf('    async function onSave()');const end=source.indexOf('\n  }\n\n  async function remove',start);vm.runInContext(source.slice(start,end),context);
 return {context,writes,fields,submit,saveError};
}
test('invalid risk input and all-zero thresholds do not submit',async()=>{for(const [a,b]of [['12x','2'],['12','1.2'],['0','0']]){const f=saveFixture(a,b);await f.context.onSave();assert.equal(f.writes.length,0);assert.ok(Object.values(f.fields).some(Boolean));assert.equal(f.submit.disabled,false);}});
test('in-flight saves coalesce and an error stays in the editor with retry enabled',async()=>{const f=saveFixture();let reject;f.context.apiFetch=(...args)=>{f.writes.push(args);return new Promise((_resolve,r)=>reject=r)};const first=f.context.onSave();assert.equal(f.submit.disabled,true);await f.context.onSave();assert.equal(f.writes.length,1);reject(new Error('save unavailable'));await first;assert.equal(f.saveError.textContent,'save unavailable');assert.equal(f.saveError.style.display,'');assert.equal(f.submit.disabled,false);f.context.apiFetch=async(...args)=>{f.writes.push(args);return {ok:true,body:{policies:[]}}};await f.context.onSave();assert.equal(f.writes.length,2);assert.equal(f.writes[1][2].device_risk[0].min_count,12);});

test('policy readers can list policies without editor-only configuration permission',async()=>{const f=fixture({policies:{ok:true,body:{policies:[{id:'p1',name:'Audit policy',identifiers:['email'],on_match:'observe'}]}},domains:{ok:false,status:403}});await f.context.renderDLPPoliciesView(f.el('div'));assert.equal(f.states.some(s=>s.state==='error'),false);assert.deepEqual(f.calls,['/admin/dlp-policies']);});

function identifierFixture(have,custom=[],edm=[]){
 const fields=[];
 const context=vm.createContext({existing:{identifiers:have},_library:{custom,edm},DLP_BUILTIN_IDENTIFIERS:[{id:'email',label:{en:'Email'}}],bl:x=>x.en,el:()=>({appendChild(){}}),uiField:options=>{const f={...options,get:()=>options.value,el:{}};fields.push(f);return f;}});
 const start=source.indexOf('    const have =');const end=source.indexOf('    // Device-risk condition',start);
 vm.runInContext(source.slice(start,end),context);
 return {fields,missing:vm.runInContext('typeof missingIDs === "undefined" ? [] : missingIDs',context)};
}
test('deleted custom and EDM references remain selected in the identifier picker',()=>{
 const f=identifierFixture(['email','old_custom','old_dataset']);
 assert.deepEqual(f.fields.filter(x=>x.value).map(x=>x.name),['id_email','id_old_custom','id_old_dataset']);
 assert.deepEqual(Array.from(f.missing),['old_custom','old_dataset']);
 const restored=identifierFixture(['old_custom','old_dataset'],[{name:'old_custom'}],[{name:'old_dataset',count:1}]);
 assert.equal(restored.missing.length,0);
});
test('unavailable selected identifiers block saving until explicitly deselected',async()=>{
 const f=saveFixture();f.context.missingIDs=['old_custom'];let selected=true;
 f.context.idFields.push({id:'old_custom',f:{get:()=>selected}});
 await f.context.onSave();assert.equal(f.writes.length,0);assert.match(f.saveError.textContent,/old_custom/);
 selected=false;await f.context.onSave();assert.equal(f.writes.length,1);assert.deepEqual(Array.from(f.writes[0][2].identifiers),['email']);
});
test('ordinary edits retain disabled status, threshold and metadata not exposed by this editor',async()=>{
 const f=saveFixture();f.context.existing={id:'retained',status:'disabled',min_count:5,metadata:{review:'retain'}};
 await f.context.onSave();assert.equal(f.writes.length,1);const saved=f.writes[0][2];
 assert.equal(saved.status,'disabled');assert.equal(saved.min_count,5);assert.equal(saved.metadata.review,'retain');assert.equal(saved.id,'retained');
});

function riskEditorFixture(risks){
 const f=saveFixture();f.context.existing={id:'risk-policy',device_risk:risks};const fields={};
 f.context.el=()=>({style:{}});
 f.context.uiField=options=>{let value=options.value;if(options.type==='select'&&!options.options.some(x=>x.value===value))value=options.options[0].value;const field={get:()=>value,set:v=>value=v,setError(){},focus(){},el:{querySelector:()=>({addEventListener(){}})}};fields[options.name]=field;return field};
 const start=source.indexOf('    const dr =');const end=source.indexOf('    const submit =',start);
 vm.runInContext('(()=>{'+source.slice(start,end)+';Object.assign(globalThis,{drEnableF,drCountF,drTypesF,drSameF,drWinF,drClassF});})()',f.context);
 return {...f,riskFields:fields};
}
const riskConditions=[{min_count:0,min_distinct_types:3,same_destination:false,window_seconds:600,destination_class:'',severity:'medium'},{min_count:12,min_distinct_types:0,same_destination:true,window_seconds:900,destination_class:'personal',severity:'high'}];
test('name-only edits preserve zero thresholds, custom windows, severity and additional risk conditions',async()=>{
 for(const window_seconds of [0,600]){const conditions=structuredClone(riskConditions);conditions[0].window_seconds=window_seconds;const f=riskEditorFixture(conditions);await f.context.onSave();assert.equal(f.writes.length,1);assert.deepEqual(JSON.parse(JSON.stringify(f.writes[0][2].device_risk)),conditions);assert.deepEqual(f.context.existing.device_risk,conditions);}
 const conditions=structuredClone(riskConditions);conditions[0].min_count=12;conditions[0].min_distinct_types=0;const f=riskEditorFixture(conditions);await f.context.onSave();assert.equal(f.writes[0][2].device_risk[0].min_distinct_types,0);
});
test('editing the first risk condition preserves its severity and all other conditions',async()=>{
 const before=structuredClone(riskConditions),f=riskEditorFixture(before);f.riskFields.dr_count.set('5');await f.context.onSave();const saved=JSON.parse(JSON.stringify(f.writes[0][2].device_risk));assert.deepEqual(saved,[{...before[0],min_count:5},before[1]]);assert.deepEqual(before,riskConditions);
});
test('explicitly disabling risk conditions removes them and re-enabling retains the configured conditions',async()=>{
 const f=riskEditorFixture(structuredClone(riskConditions));f.riskFields.dr_on.set(false);await f.context.onSave();assert.deepEqual(Array.from(f.writes[0][2].device_risk),[]);
 const restored=riskEditorFixture(structuredClone(riskConditions));restored.riskFields.dr_on.set(false);restored.riskFields.dr_on.set(true);await restored.context.onSave();assert.deepEqual(JSON.parse(JSON.stringify(restored.writes[0][2].device_risk)),riskConditions);
});
