import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';
const context=vm.createContext({bl:o=>o.en,uiBadge:(text,kind)=>({text,kind})});
vm.runInContext(readFileSync(new URL('./effective_policy.js',import.meta.url),'utf8'),context);
vm.runInContext(readFileSync(new URL('./rules.js',import.meta.url),'utf8'),context);
test('device-dependent and absent decisions are not presented as inspected',()=>{
 for(const [decision,text,kind] of [['depends_on_device','Depends on the device','warn'],['bypass','Not inspected','warn'],['inspect','Inspected','ok'],['unknown','Not determined','off'],[undefined,'Not determined','off']]) assert.deepEqual(context.epInspectionBadge({decision}),{text,kind});
});
test('source constraints are explained rather than shown as a working exception',()=>{
 assert.match(context.inspectionSourceWarningText('identity_context_unavailable'),/cannot decide it here/);
 assert.match(context.inspectionSourceWarningText('no_resolved_device'),/No source device/);
 assert.match(context.epInspectionSourceText({source:'device_rule'}),/verify from the source device/);
});
