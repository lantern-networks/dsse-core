import {readFileSync} from 'node:fs';import vm from 'node:vm';import test from 'node:test';import assert from 'node:assert/strict';
const context=vm.createContext({});vm.runInContext(readFileSync(new URL('./assets.js',import.meta.url),'utf8'),context);const parse=rows=>JSON.parse(JSON.stringify(context.servicePortsFromRows(rows)));
test('mixed valid and invalid ports reject the complete form',()=>{for(const bad of ['', '0','-1','443.5','443x','65536','1e3','Infinity'])assert.equal(parse([{protocol:'tcp',port:'443'},{protocol:'udp',port:bad}]),null,bad);});
test('service protocols and a nonempty port set are required',()=>{assert.equal(parse([]),null);assert.equal(parse([{protocol:'icmp',port:'1'}]),null);});
test('both port bounds and protocol choices survive unchanged',()=>{assert.deepEqual(parse([{protocol:'tcp',port:'1'},{protocol:'udp',port:'65535'},{protocol:'tcp',port:' 443 '}]),[{protocol:'tcp',port:1},{protocol:'udp',port:65535},{protocol:'tcp',port:443}]);});
