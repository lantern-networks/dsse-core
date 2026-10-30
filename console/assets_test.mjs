import {readFileSync} from 'node:fs';import vm from 'node:vm';import test from 'node:test';import assert from 'node:assert/strict';
const context=vm.createContext({});vm.runInContext(readFileSync(new URL('./assets.js',import.meta.url),'utf8'),context);const parse=rows=>JSON.parse(JSON.stringify(context.servicePortsFromRows(rows)));
test('mixed valid and invalid ports reject the complete form',()=>{for(const bad of ['', '0','-1','443.5','443x','65536','1e3','Infinity'])assert.equal(parse([{protocol:'tcp',port:'443'},{protocol:'udp',port:bad}]),null,bad);});
test('service protocols and a nonempty port set are required',()=>{assert.equal(parse([]),null);assert.equal(parse([{protocol:'icmp',port:'1'}]),null);});
test('both port bounds and protocol choices survive unchanged',()=>{assert.deepEqual(parse([{protocol:'tcp',port:'1'},{protocol:'udp',port:'65535'},{protocol:'tcp',port:' 443 '}]),[{protocol:'tcp',port:1},{protocol:'udp',port:65535},{protocol:'tcp',port:443}]);});
test('group member IDs resolve against endpoint metadata, retaining an unresolved ID',()=>{const rows=context.assetGroupMemberRows(['ep-a','missing','ep-b'],[{id:'ep-a',alias:'Renamed A',platform:'macos'},{id:'ep-b',alias:'Server B'}]);assert.deepEqual(JSON.parse(JSON.stringify(rows)),[{id:'ep-a',alias:'Renamed A',platform:'macos'},{id:'missing',alias:'missing'},{id:'ep-b',alias:'Server B'}]);});
test('group members reject object-shaped IDs and invalid endpoint metadata',()=>{assert.throws(()=>context.assetGroupMemberRows([{id:'ep-a'}],[]));assert.throws(()=>context.assetGroupMemberRows(['ep-a'],[null]));assert.throws(()=>context.assetGroupMemberRows([''],[]));assert.deepEqual(JSON.parse(JSON.stringify(context.assetGroupMemberRows([],[]))),[]);});
test('catalog reads distinguish valid empty lists from unavailable or malformed responses',async()=>{for(const body of [[],null]){context.apiFetch=async()=>({ok:true,body});assert.deepEqual(JSON.parse(JSON.stringify(await context.loadAssetsArr('/catalog'))),[]);}for(const body of [{},undefined,'wrong']){context.apiFetch=async()=>({ok:true,body});await assert.rejects(context.loadAssetsArr('/catalog'),/Invalid catalog response/);}context.apiFetch=async()=>({ok:false,status:503});await assert.rejects(context.loadAssetsArr('/catalog'),/HTTP 503/);});
test('a device-dependent inspection decision is not shown as fully inspected',()=>{
 context.bl=labels=>labels.en;
 context.uiBadge=(label,tone)=>({label,tone});
 const device=context.assetInspectionBadge('depends_on_device');
 assert.equal(device.label,'Depends on device');assert.equal(device.tone,'off');
 assert.equal(context.assetInspectionBadge('inspect').label,'Inspected');
 assert.equal(context.assetInspectionBadge('bypass').label,'Bypassed');
 assert.equal(context.assetInspectionBadge('future_decision').label,'Unknown');
});

test('a fresh endpoint inventory reads the current inspection decision',async()=>{
  let decision='bypass';const requests=[];
  const node=(tag,props={},children=[])=>{
    const n={tag,style:{},children:Array.isArray(children)?children:[children],appendChild(child){this.children.push(child)},addEventListener(){},querySelector(){return node('select')},setAttribute(){}};
    Object.assign(n,props);
    Object.defineProperty(n,'innerHTML',{set(){this.children=[]}});
    return n;
  };
  const c=vm.createContext({
    el:node,bl:x=>x.en,uiBadge:text=>node('badge',{text}),
    uiState:()=>{},freshRender:()=>()=>true,
    uiField:()=>({el:node('div'),get:()=> 'all'}),
    document:{createTextNode:nodeText=>nodeText},
    apiFetch:async(_method,path)=>{
      requests.push(path);
      if(path==='/admin/assets/endpoints')return{ok:true,body:[{id:'server',kind:'network',address:'db.example.test',alias:'DB'}]};
      if(path.startsWith('/admin/effective-policy?'))return{ok:true,body:{inspection:{decision}}};
      throw new Error('unexpected path '+path);
    },
  });
  vm.runInContext(readFileSync(new URL('./assets.js',import.meta.url),'utf8'),c);
  const section=node('section');
  await c.renderEndpointsSection(section);
  await new Promise(resolve=>setImmediate(resolve));
  decision='inspect';
  await c.renderEndpointsSection(section);
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(requests.filter(path=>path.startsWith('/admin/effective-policy?')).length,2);
});
