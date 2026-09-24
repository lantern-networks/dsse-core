import {readFileSync} from 'node:fs';import vm from 'node:vm';import test from 'node:test';import assert from 'node:assert/strict';
const context=vm.createContext({bl:b=>b.en});vm.runInContext(readFileSync(new URL('./internalcas.js',import.meta.url),'utf8'),context);
const cert='-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----';
const authority={id:'one',tenant_id:'tenant',name:'Office',certificate_pem:cert,not_after:'2027-01-01T00:00:00Z'};
test('only a validated tenant and complete list permit certificate actions',()=>{
 assert.equal(context.validatedInternalCAs({internal_cas:[]},{tenant_id:'tenant'}).length,0);
 for(const [body,tenant] of [[{}, {tenant_id:'tenant'}],[{internal_cas:null},{tenant_id:'tenant'}],[{internal_cas:[authority]},{}],[{internal_cas:[{...authority,tenant_id:'other'}]},{tenant_id:'tenant'}],[{internal_cas:[authority,authority]},{tenant_id:'tenant'}],[{internal_cas:[{...authority,expired:'false'}]},{tenant_id:'tenant'}],[{internal_cas:[{...authority,certificate_pem:cert+'\nPRIVATE KEY'}]},{tenant_id:'tenant'}]])assert.throws(()=>context.validatedInternalCAs(body,tenant));
});
test('a 2xx response must confirm the exact tenant, authority and saved material',()=>{
 context.internalCAOutcome({ok:true,status:200,body:authority},'upsert',authority);
 context.internalCAOutcome({ok:true,status:200,body:{id:'one',tenant_id:'tenant',deleted:true}},'delete',authority);
 for(const body of [{},{...authority,id:'other'},{...authority,tenant_id:'other'},{...authority,name:'Wrong'},{...authority,certificate_pem:cert.replace('YWJj','ZGVm')}])assert.throws(()=>context.internalCAOutcome({ok:true,status:200,body},'upsert',authority));
 for(const body of [{deleted:true},{id:'one',tenant_id:'other',deleted:true},{id:'one',tenant_id:'tenant',deleted:false}])assert.throws(()=>context.internalCAOutcome({ok:true,status:200,body},'delete',authority));
 assert.throws(()=>context.internalCAOutcome({ok:true,status:202,body:authority},'upsert',authority),/unconfirmed/);
 assert.throws(()=>context.internalCAOutcome({ok:false,status:500,body:{error:'Storage did not confirm the change'}},'upsert',authority),/Storage/);
});
test('the paste guard refuses extra keys, hidden anchors and text',()=>{
 for(const material of [cert+cert,cert+'\n-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----','secret\n'+cert,cert+'secret',''])assert.equal(context.internalCAPEM(material),false);
 assert.equal(context.internalCAPEM(' \n'+cert+'\n'),true);
});
