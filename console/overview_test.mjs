import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';

const source = name => readFileSync(new URL(name, import.meta.url), 'utf8');

test('Overview drilldowns use registered navigation groups', () => {
  const destinations = [];
  const context = vm.createContext({renderGroup: id => destinations.push(id)});
  vm.runInContext(source('./overview.js'), context);
  context.ovGoto('devices');
  context.ovGoto('connectors');
  assert.deepEqual(destinations, ['enrolled', 'sites']);
  const navigation = source('./app.js');
  for (const id of destinations) assert.match(navigation, new RegExp('id: "' + id + '"'));
});

function capacityFixture(body) {
  const el = (tag, attrs = {}, children = []) => {
    const node = {children: [], text: attrs.text || '',
      appendChild(child) { if (child) this.children.push(child); return child; },
      set innerHTML(value) { assert.equal(value, ''); this.children = []; this.text = ''; },
      get textContent() { return this.text + this.children.map(c => typeof c === 'string' ? c : c.textContent).join('\n'); }};
    for (const child of [children].flat(Infinity)) node.appendChild(child);
    return node;
  };
  const calls = [], host = el('div');
  const context = vm.createContext({el, bl: value => value.en, freshRender: () => () => true,
    uiState: () => {}, uiBadge: text => el('span', {text}),
    apiFetch: async (...args) => {calls.push(args); return {ok: true, body};}});
  vm.runInContext(source('./operatorhome.js'), context);
  return {host, calls, render: () => context.renderOperatorCapacity(host)};
}

test('operator capacity reads the licence API seat total and tenant usage', async () => {
  const f = capacityFixture({licensed: true, seats: 20, unallocated: 15, allocated: 5,
    tenants: [{tenant_id: 'customer', display_name: 'Customer', allocated: 5, used: 1}]});
  await f.render();
  assert.deepEqual(f.calls, [['GET', '/admin/license', undefined, 'control']]);
  assert.match(f.host.textContent, /Given out: 5/);
  assert.match(f.host.textContent, /Left: 15/);
  assert.match(f.host.textContent, /Customer\n5\n1/);
  assert.doesNotMatch(f.host.textContent, /Pool unknown|No licence/);
});

test('operator capacity keeps a missing licensed pool unknown', async () => {
  const f = capacityFixture({licensed: true, allocated: 5, tenants: []});
  await f.render();
  assert.match(f.host.textContent, /Pool unknown/);
  assert.doesNotMatch(f.host.textContent, /Left:|No licence/);
});

test('Overview treats unavailable required reads as unknown, including transport failures',()=>{
 const c=vm.createContext({});vm.runInContext(source('./overview.js'),c);
 for(const status of [0,401,403,404,500,503])assert.equal(c.ovDenied({ok:false,status,body:{}}),true);
 assert.equal(c.ovDenied({ok:true,status:200,body:null}),true);
 assert.equal(c.ovDenied({ok:true,status:200,body:{devices:[]}}),false);
 assert.equal(c.ovDenied({ok:true,status:200,body:{}},{ok:false,status:503}),true);
});

test('Overview Connector details distinguish an unreported CP tunnel from an Edge observation', () => {
  const c = vm.createContext({bl: value => value.en});
  vm.runInContext(source('./overview.js'), c);
  // The CP can establish online from a fresh heartbeat without holding a tunnel itself.
  const cp = {online: true, status: 'healthy', last_heartbeat_at: '2026-10-21T04:55:37Z'};
  assert.equal(c.ovConnectorTunnelView(cp).text, 'not reported');
  assert.equal(c.ovConnectorTunnelView(cp).tone, 'off');
  assert.equal(c.ovConnectorNetworkRoutes(cp), 'not reported');
  assert.equal(c.ovConnectorTunnelView({tunnel_connected: true}).text, 'up');
  assert.equal(c.ovConnectorTunnelView({tunnel_connected: false}).text, 'down');
  assert.equal(c.ovConnectorNetworkRoutes({reachable_routes: {cidr_count: 0, fqdn_domain_count: 0}}), '0 routes');
  assert.equal(c.ovConnectorNetworkRoutes({reachable_routes: {cidr_count: 2, fqdn_domain_count: 1}}), '3 routes');
  assert.equal(c.ovConnectorNetworkRoutes({reachable_routes: {cidr_count: 2}}), 'not reported');
});

test('an unreadable tenant inventory never falls back to an operator own-tenant list',async()=>{
 const el=(tag,props={})=>({...props,children:[],appendChild(n){this.children.push(n)}}),t=el('div'),r=el('div');let more;
 const c=vm.createContext({el,bl:x=>x.en,answeringForTheDeployment:()=>true,apiFetch:async(m,p)=>p==='/admin/tenants'?{ok:false,status:503}:{ok:true,status:200,body:{tenant_id:'operator'}}});vm.runInContext(source('./overview.js'),c);await c.ovLoadTenantsRegions(t,v=>more=v,r);assert.equal(more,'');assert.equal(t.children[0].text,'not readable here');assert.equal(r.children[0].text,'not readable here');
});

test('Overview does not call devices normal when risk reads fail', async () => {
  const context = vm.createContext({
    byDeviceIdentity: () => ({}), deviceKey: value => value,
    apiFetch: async (_, path) => {
      if (path === '/admin/enrolled-devices') return {ok:true, body:{devices:[
        {identity:'server-known', enabled:true, effective_risk:'high'},
        {identity:'unresolved', enabled:true},
      ]}};
      if (path === '/admin/device-runtime') return {ok:true, body:{devices:{'server-known':{steer_active:true}}}};
      if (path === '/admin/risk-signals' || path === '/admin/device-groups') return {ok:false, status:503};
      return {ok:true, body:{}};
    },
  });
  vm.runInContext(source('./overview.js'), context);
  const aggregate = await context.ovDeviceAggregate();
  assert.equal(aggregate.risk.high, 1);
  assert.equal(aggregate.risk.unknown, 1);
  assert.equal(aggregate.risk.none, 0);
  assert.equal(aggregate.reporting, 1);
});

test('Overview separates unavailable config sync from a verified disabled state', async () => {
  const texts = [];
  const el = (_, attrs = {}, children = []) => ({attrs, children: [children].flat(Infinity), appendChild(child) {this.children.push(child);}});
  const strip = {innerHTML:'', appendChild(node) {texts.push(node.children.at(-1));}};
  let config = {ok:false, status:503};
  const context = vm.createContext({el, document:{createTextNode: value => value}, bl: value => value.en,
    apiFetch: async (_, path) => path === '/admin/config-sync-status' ? config : {ok:false, status:503},
    fleetStripChip: () => null,
  });
  vm.runInContext(source('./overview.js'), context);
  await context.ovLoadStrip(strip, null);
  assert.ok(texts.some(value => typeof value === 'string' && value.includes('unavailable')));
  assert.ok(!texts.some(value => typeof value === 'string' && value.includes(' · off')));
  texts.length = 0;
  config = {ok:true, body:{enabled:false}};
  await context.ovLoadStrip(strip, null);
  assert.ok(texts.some(value => typeof value === 'string' && value.includes(' · off')));
});
