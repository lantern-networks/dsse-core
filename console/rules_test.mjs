import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';

const context = vm.createContext({bl:b=>b.en,httpErr:r=>r?.body?.error||'request failed'});
vm.runInContext(readFileSync(new URL('./rules.js',import.meta.url),'utf8'),context);
const expected={id:'draft-1',plane:'egress',priority:12,name:'Example',source:['*'],destination:['endpoint-1'],action:{access:'allow',inspection:'bypass',require_workload_attestation:true}};
const saved={...expected,tenant_id:'customer-a',status:'active',stage:'enforce'};
const response=body=>({ok:true,status:200,body});

test('rule save acknowledgment must match identity, tenant and authored fields',()=>{
  context.validateRuleSave(response(saved),expected,'customer-a');
  for(const body of [{},{...saved,id:'another'},{...saved,tenant_id:'customer-b'},{...saved,priority:13},{...saved,source:[]},{...saved,destination:['other']},{...saved,status:'disabled'},{...saved,action:{access:'allow',inspection:'inspect'}},{...saved,action:{access:'allow',inspection:'bypass'}}]) {
    assert.throws(()=>context.validateRuleSave(response(body),expected,'customer-a'));
  }
  assert.throws(()=>context.validateRuleSave({...response(saved),status:202},expected,'customer-a'));
  assert.throws(()=>context.validateRuleSave({ok:false,status:500,body:{error:'save failed'}},expected,'customer-a'),/save failed/);
});
test('DLP acknowledgment must retain the selected policy and identifiers',()=>{
  const want={...expected,action:{access:'allow',inspection:'inspect',dlp:{policy_id:'dlp-1',identifiers:['secret']}}};
  const got={...saved,action:{...want.action,dlp:{...want.action.dlp,action:''}}};
  context.validateRuleSave(response(got),want,'customer-a');
  assert.throws(()=>context.validateRuleSave(response({...got,action:{...got.action,dlp:{policy_id:'dlp-1'}}}),want,'customer-a'));
});
test('missing or malformed catalog cannot become an empty successful list',async()=>{
  for(const body of [null,{},'invalid']) {
    context.apiFetch=async()=>({ok:true,status:200,body});
    await assert.rejects(context.loadList('/admin/assets/endpoints'));
  }
  context.apiFetch=async()=>({ok:false,status:503,body:{error:'unavailable'}});
  await assert.rejects(context.loadList('/admin/assets/endpoints'),/HTTP 503/);
  context.apiFetch=async()=>({ok:true,status:200,body:[]});
  assert.equal((await context.loadList('/admin/assets/endpoints')).length,0);
});
test('tenant verification rejects missing context and propagates transport failure',async()=>{
  for(const body of [{},{tenant_id:''},{tenant_id:7}]) {
    context.apiFetch=async()=>({ok:true,status:200,body});
    await assert.rejects(context.ruleEditorTenant());
  }
  context.apiFetch=async()=>{throw new Error('transport down')};
  await assert.rejects(context.ruleEditorTenant(),/transport down/);
  context.apiFetch=async()=>({ok:true,status:200,body:{tenant_id:'customer-a'}});
  assert.equal(await context.ruleEditorTenant(),'customer-a');
});
test('unsupported inspection sources explain the remaining access and inspection scopes',()=>{assert.match(context.inspectionSourceWarningText('identity_context_unavailable'),/Only device sources/);assert.match(context.inspectionSourceWarningText('identity_context_unavailable'),/access rules still apply/);assert.match(context.inspectionSourceWarningText('no_resolved_device'),/No source device/);assert.match(context.inspectionSourceWarningText('future_reason'),/Check the inspection source/)});


test('cert-pin summary only represents unmodified unrestricted allow/bypass rules',()=>{
 const r={id:'certpin-rule-saved',plane:'egress',source:['*'],destination:['endpoint'],action:{access:'allow',inspection:'bypass'},status:'active'};
 assert.equal(context.isCertPinSummaryRule(r),true);
 assert.equal(context.isCertPinSummaryRule({...r,status:'disabled'}),true);
 for(const changed of [
  {...r,action:{access:'allow',inspection:'inspect'}},
  {...r,action:{access:'deny',inspection:'bypass'}},
  {...r,action:{...r.action,require_workload_attestation:true}},
  {...r,source:['device-a']}, {...r,destination:['a','b']},
  {...r,service_id:'ssh'}, {...r,risk_at_least:'high'}, {...r,allowed_tool_ids:['tool']},
  {...r,id:'ordinary-rule'}, {...r,plane:'eastwest'},
 ]) assert.equal(context.isCertPinSummaryRule(changed),false,JSON.stringify(changed));
});

test('identity directory groups named like Object properties remain selectable',()=>{
 const tree=context.identityTreeFromDirectory([
  {department:'__proto__',subject:'alice',display_name:'Alice'},
  {department:'constructor',subject:'bob',display_name:'Bob'},
  {department:'Finance',subject:'cara',display_name:'Cara'},
 ]);
 assert.deepEqual(JSON.parse(JSON.stringify(tree)),[
  {group:'Finance',people:[{id:'cara',label:'Cara'}]},
  {group:'__proto__',people:[{id:'alice',label:'Alice'}]},
  {group:'constructor',people:[{id:'bob',label:'Bob'}]},
 ]);
 assert.equal(vm.runInContext('({}).alice',context),undefined);
});

test('an IdP group named __proto__ starts collapsed and can be expanded',()=>{
 const make=(tag,attrs={},children=[])=>{
  const node={tag,className:attrs.class||'',style:{},children:[],value:attrs.value||'',checked:false,
   textContent:attrs.text||'',events:{},classList:{add(){},toggle(){}},
   appendChild(child){this.children.push(child);return child},
   addEventListener(name,fn){this.events[name]=fn}};
  for(const child of (Array.isArray(children)?children:[children])) if(child) node.appendChild(child);
  return node;
 };
 const c=vm.createContext({bl:b=>b.en,el:make,uiBadge:(label)=>make('span',{text:label})});
 vm.runInContext(readFileSync(new URL('./rules.js',import.meta.url),'utf8'),c);
 const picker=c.subjectPicker('Source',[],{identityGroups:true,idpTree:[{group:'__proto__',people:[{id:'alice',label:'Alice'}]}]});
 const find=(node,cls)=>{
  if(node.className.split(' ').includes(cls)) return node;
  for(const child of node.children){const found=find(child,cls);if(found)return found}
  return null;
 };
 const person=find(picker.el,'subject-idp-person');
 const expand=find(picker.el,'subject-idp-expand');
 assert.equal(person.style.display,'none');
 expand.events.click();
 assert.equal(person.style.display,'');
});

test('max sign-in age keeps omitted, one-request, and exact positive seconds distinct',()=>{
 assert.equal(context.maxAgeMinutesFromAction({}), '');
 assert.equal(context.maxAgeMinutesFromAction({max_age_seconds:0}), '0');
 assert.equal(context.maxAgeMinutesFromAction({max_age_seconds:90}), '1.5');
 assert.equal(context.parseMaxAgeMinutes(''), null);
 assert.equal(context.parseMaxAgeMinutes('0'), 0);
 assert.equal(context.parseMaxAgeMinutes('1.5'), 90);
 assert.equal(context.parseMaxAgeMinutes(context.maxAgeMinutesFromAction({max_age_seconds:1})), 1);
 assert.equal(context.parseMaxAgeMinutes(context.maxAgeMinutesFromAction({max_age_seconds:Number.MAX_SAFE_INTEGER}), Number.MAX_SAFE_INTEGER), Number.MAX_SAFE_INTEGER);
 for(const bad of ['-1','NaN','Infinity','1e3','0.01','1.01','0.000000000001','9007199254740991']) {
  assert.throws(()=>context.parseMaxAgeMinutes(bad), undefined, bad);
 }
});
// Found 2026-11-04: an Internet Access rule saved to the control plane did not appear in the Edge's list read
// straight afterwards. The list now waits until the Edge shows what was saved, or says it has not arrived.
test('the internet access list waits for the Edge to show a saved rule', async () => {
  const savedRule = {id: 'rule-1', priority: 20, name: 'Deny example.org', status: 'active', stage: 'enforce', source: ['*'], destination: ['g1']};
  const stale = {ok: true, status: 200, body: {rules: [{kind: 'builtin_default', policy_id: 'p', access: 'allow'}]}};
  const fresh = {ok: true, status: 200, body: {rules: [{kind: 'authored', rule: savedRule}, ...stale.body.rules]}};
  assert.equal(context.egressListShows(stale.body.rules, {id: 'rule-1', saved: savedRule}), false);
  assert.equal(context.egressListShows(fresh.body.rules, {id: 'rule-1', saved: savedRule}), true);
  assert.equal(context.egressListShows(fresh.body.rules, {id: 'rule-1', saved: {...savedRule, name: 'renamed'}}), false);
  // A change to what the rule DOES is a change the Edge must show before the wait ends.
  const base = fresh.body.rules.find((e) => e.rule && e.rule.id === 'rule-1').rule;
  for (const changed of [
    {...base, action: {...(base.action || {}), access: 'deny'}},
    {...base, action: {...(base.action || {}), inspection: 'bypass'}},
    {...base, action: {...(base.action || {}), dlp: {profile_ids: ['dlpp_1']}}},
    {...base, risk_at_least: 'high'},
    {...base, allowed_tool_ids: ['tool_1']},
  ]) {
    assert.equal(context.egressListShows(fresh.body.rules, {id: 'rule-1', saved: changed}), false, JSON.stringify(changed));
  }
  // Key order is not a difference.
  const reordered = Object.fromEntries(Object.entries(base).reverse());
  assert.equal(context.egressListShows(fresh.body.rules, {id: 'rule-1', saved: reordered}), true);
  // An empty DLP block and no DLP block are different rules (without its own block the rule
  // takes the organization's DLP). The editor drops an empty block on save; the Edge still holding it is stale.
  const emptyDlp = {...base, action: {access: 'allow', inspection: 'inspect', dlp: {identifiers: null, on_match: ''}}};
  const noDlp = {...base, action: {access: 'allow', inspection: 'inspect'}};
  const withEmpty = {ok: true, status: 200, body: {rules: [{kind: 'authored', rule: emptyDlp}]}};
  const withNone = {ok: true, status: 200, body: {rules: [{kind: 'authored', rule: noDlp}]}};
  assert.equal(context.egressListShows(withEmpty.body.rules, {id: 'rule-1', saved: noDlp}), false);
  assert.equal(context.egressListShows(withNone.body.rules, {id: 'rule-1', saved: emptyDlp}), false);
  assert.equal(context.egressListShows(withNone.body.rules, {id: 'rule-1', saved: noDlp}), true);
  // An emptied list and a false flag are also kept as they are.
  assert.equal(context.egressListShows(fresh.body.rules, {id: 'rule-1', saved: {...base, allowed_tool_ids: []}}), false);
  // The save's answer can carry a warning beside the rule; the Edge's copy never does.
  assert.equal(context.egressListShows(fresh.body.rules, {id: 'rule-1', saved: {...base, warning: 'overlaps rule 10'}}), true);
  assert.match(readFileSync(new URL('../cmd/dsse-edge/rules_admin.go', import.meta.url), 'utf8'), /Warning string `json:"warning,omitempty"`/);
  assert.equal(context.egressListShows(fresh.body.rules, {id: 'rule-1', gone: true}), false);
  assert.equal(context.egressListShows(stale.body.rules, {id: 'rule-1', gone: true}), true);
  assert.equal(context.egressListShows(stale.body.rules, undefined), true);
});
test('server-written rule words are shown in the reader language', () => {
  const ja = vm.createContext({bl: b => b.ja, httpErr: () => ''});
  vm.runInContext(readFileSync(new URL('./rules.js', import.meta.url), 'utf8'), ja);
  assert.equal(ja.ruleFlowText({source_text: 'Any', destination_text: 'Any', service_text: 'Any'}), 'すべて → すべて : すべて');
  assert.equal(ja.ruleDisplayName('Everything, allowed and inspected — the rule to narrow first'), 'すべて許可・検査（最初に絞り込むルール）');
  assert.equal(ja.ruleDisplayName('My rule'), 'My rule');
});
test('a destination says whether it is an application, a network or a device, and where',()=>{
 const make=(tag,attrs={},children=[])=>{
  const node={tag,className:attrs.class||'',textContent:attrs.text||'',children:[],events:{},style:{},classList:{add(){},toggle(){}},
   appendChild(child){this.children.push(child);return child},addEventListener(name,fn){this.events[name]=fn}};
  for(const child of (Array.isArray(children)?children:[children])) if(child) node.appendChild(child);
  return node;
 };
 const c=vm.createContext({bl:b=>b.en,el:make,uiBadge:(label)=>make('span',{text:label})});
 vm.runInContext(readFileSync(new URL('./rules.js',import.meta.url),'utf8'),c);
 const app={id:'app-h1',alias:'H1 internal app',kind:'network',source:'application',address:'h1.c.lab041.test'};
 const net={id:'ep-1',alias:'H1 internal app net',kind:'network',source:'manual',address:'10.47.1.30/32'};
 const dev={id:'dev-1',alias:'DESKTOP-ACC3',kind:'steered_device',source:'enrolled'};
 assert.equal(c.ruleEndpointWhat(app),'application');assert.equal(c.ruleEndpointWhat(net),'network');assert.equal(c.ruleEndpointWhat(dev),'device');
 const subjects=[app,net,dev].map(e=>({id:e.id,label:e.alias,kind:'endpoint',what:c.ruleEndpointWhat(e),address:e.kind==='network'?e.address:''}));
 const picker=c.subjectPicker('Destination',subjects);
 const text=JSON.stringify(picker.el,(k,v)=>k==='events'?undefined:v);
 assert.match(text,/"Application".{0,200}"H1 internal app".{0,200}"h1\.c\.lab041\.test"/s);
 assert.match(text,/"Network".{0,200}"H1 internal app net".{0,200}"10\.47\.1\.30\/32"/s);
 assert.match(text,/"Device".{0,200}"DESKTOP-ACC3"/s);
 assert.doesNotMatch(text,/"Endpoint"/,'every destination here says what it is');
});

// A first rule used to stop at the destination picker: the destination had to be made on the Groups & Services
// page before a rule could name it.
test('a destination that is not in the list yet can be added from the rule editor and comes back selected',async()=>{
 const make=(tag,attrs={},children=[])=>{
  const node={tag,className:attrs.class||'',textContent:attrs.text||'',children:[],events:{},style:{},value:'',checked:false,disabled:false,
   classList:{add(){},toggle(){}},
   appendChild(child){this.children.push(child);return child},addEventListener(name,fn){this.events[name]=fn}};
  for(const child of (Array.isArray(children)?children:[children])) if(child) node.appendChild(child);
  return node;
 };
 const calls=[];
 let answer={ok:true,status:200,body:{id:'ep-new',alias:'prod database',address:'10.0.0.10',kind:'network',source:'manual'}};
 const c=vm.createContext({bl:b=>b.en,el:make,uiBadge:(label)=>make('span',{text:label}),apiFetch:async(...a)=>{calls.push(a);return answer}});
 vm.runInContext(readFileSync(new URL('./rules.js',import.meta.url),'utf8'),c);
 const find=(node,pred)=>{ if(pred(node)) return node; for(const child of node.children){const f=find(child,pred);if(f)return f} return null; };
 const inputs=(node,out=[])=>{ if(node.tag==='input'&&node.className==='ui-input') out.push(node); node.children.forEach(ch=>inputs(ch,out)); return out; };

 const source=c.subjectPicker('Source',[],{});
 assert.equal(find(source.el,n=>/Add server/.test(n.textContent)),null,'only the destination offers it');

 const picker=c.subjectPicker('Destination',[],{addServer:true});
 const toggle=find(picker.el,n=>/Add server/.test(n.textContent));
 const panel=find(picker.el,n=>n.className==='subject-add-panel');
 assert.equal(panel.style.display,'none');
 toggle.events.click();
 assert.equal(panel.style.display,'');
 const [nameIn,addrIn]=inputs(panel);
 const add=find(panel,n=>n.tag==='button'&&n.textContent==='Add');
 const problem=find(panel,n=>n.className.includes('subject-add-problem'));

 await add.events.click();
 assert.equal(calls.length,0,'nothing is sent without a name and an address');
 assert.match(problem.textContent,/name and an address/);

 nameIn.value='prod database'; addrIn.value='10.0.0.10';
 await add.events.click();
 assert.deepEqual(JSON.parse(JSON.stringify(calls[0])),['POST','/admin/assets/endpoints',{alias:'prod database',address:'10.0.0.10',kind:'network',source:'manual',steered:false}]);
 assert.deepEqual([...picker.selected()],['ep-new']);
 assert.equal(nameIn.value,'');

 // What is plainly not an address is said so by the Console, and nothing is sent.
 const sent=calls.length;
 nameIn.value='x'; addrIn.value='not an address';
 await add.events.click();
 assert.equal(calls.length,sent);
 assert.match(problem.textContent,/Give an IP address/);
 // What the Console lets through and the server refuses is answered in the server's words.
 answer={ok:false,status:400,body:{error:'address is not valid'}};
 nameIn.value='x'; addrIn.value='10.0.0.0/33';
 await add.events.click();
 assert.equal(problem.textContent,'address is not valid');
 assert.deepEqual([...picker.selected()],['ep-new'],'a refused server selects nothing new');
});

// Found on a Windows walk (2026-11-14): the Source list of a new rule offered "*.anthropic.com" and every other
// built-in destination.
test('the source list offers devices and the administrator\'s groups, and keeps what a rule already names',()=>{
 const subjects=[
  {id:'dev-1',label:'DESKTOP-ACC3',kind:'endpoint',what:'device'},
  {id:'net-1',label:'prod database',kind:'endpoint',what:'network'},
  {id:'app-1',label:'Wiki',kind:'endpoint',what:'application'},
  {id:'grp-mine',label:'Finance laptops',kind:'group',builtIn:false},
  {id:'grp-builtin',label:'Anthropic',kind:'group',builtIn:true},
 ];
 const ids=(list)=>JSON.stringify(list.map(s=>s.id));
 assert.equal(ids(context.ruleSourceSubjects(subjects)),'["dev-1","grp-mine"]');
 assert.equal(ids(context.ruleSourceSubjects(subjects,['net-1'])),'["dev-1","net-1","grp-mine"]','a rule that already names a network as its source still shows it');
});

// Found on the second Windows walk: a new rule was offered priority 100, the same as the starting
// "everything allowed" rule, and saved as offered it was listed after that rule.
test('a new rule is offered a priority ahead of the rules already written for the same kind of access',()=>{
 const rules=[{plane:'egress',priority:100},{plane:'egress',priority:40},{plane:'east_west',priority:5}];
 assert.equal(context.ruleDefaultPriority(rules,'egress'),30);
 assert.equal(context.ruleDefaultPriority(rules,'east_west'),1);
 assert.equal(context.ruleDefaultPriority([{plane:'egress',priority:100}],'egress'),90);
 assert.equal(context.ruleDefaultPriority([],'egress'),100);
 assert.equal(context.ruleDefaultPriority(null,'egress'),100);
});

test('the Console\'s first look at an address agrees with what a rule can match',()=>{
 for(const ok of ['10.0.0.10','10.0.0.0/24','2001:db8::1','db.example.com','*.example.com','intranet','wiki.10.55.1.30.nip.io']) assert.equal(context.ruleAddressLooksLikeOne(ok),true,ok);
 for(const bad of ['not an address','http://db.example.com','exa mple.com','','-bad.example.com','*']) assert.equal(context.ruleAddressLooksLikeOne(bad),false,bad);
});

// Review finding (2026-11-14): with "Any" selected, a server added from the picker showed as checked and the
// rule would still have been saved for every destination.
test('adding a server while Any is selected selects that server, and what is saved is what is shown',async()=>{
 const make=(tag,attrs={},children=[])=>{
  const node={tag,className:attrs.class||'',textContent:attrs.text||'',children:[],events:{},style:{},value:'',checked:false,disabled:false,
   classList:{add(){},toggle(){}},
   appendChild(child){this.children.push(child);return child},addEventListener(name,fn){this.events[name]=fn}};
  for(const child of (Array.isArray(children)?children:[children])) if(child) node.appendChild(child);
  return node;
 };
 const c=vm.createContext({bl:b=>b.en,el:make,uiBadge:(label)=>make('span',{text:label}),
  apiFetch:async()=>({ok:true,status:200,body:{id:'ep-new',alias:'prod database',address:'10.0.0.10',kind:'network',source:'manual'}})});
 vm.runInContext(readFileSync(new URL('./rules.js',import.meta.url),'utf8'),c);
 const find=(node,pred)=>{ if(pred(node)) return node; for(const child of node.children){const f=find(child,pred);if(f)return f} return null; };
 const inputs=(node,out=[])=>{ if(node.tag==='input'&&node.className==='ui-input') out.push(node); node.children.forEach(ch=>inputs(ch,out)); return out; };
 const picker=c.subjectPicker('Destination',[{id:'ep-old',label:'old server',kind:'endpoint',what:'network'}],{addServer:true});
 picker.setSelected(['*']);
 assert.deepEqual([...picker.selected()],['*']);
 const panel=find(picker.el,n=>n.className==='subject-add-panel');
 const [nameIn,addrIn]=inputs(panel);
 nameIn.value='prod database'; addrIn.value='10.0.0.10';
 await find(panel,n=>n.tag==='button'&&n.textContent==='Add').events.click();
 assert.deepEqual([...picker.selected()],['ep-new'],'the rule is saved for the server that shows as selected');
 const anyRow=find(picker.el,n=>n.className.includes('subject-any'));
 assert.equal(anyRow.children[0].checked,false,'Any is no longer shown as selected');
 const summary=find(picker.el,n=>n.className==='subject-summary');
 assert.match(summary.textContent,/prod database/);
});
