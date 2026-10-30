import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';

const source = readFileSync(new URL('./effective_policy.js', import.meta.url), 'utf8');
const setting = (overrides = {}) => ({tenant_id:'tenant-a',scope:'tenant',mode:'strict',configurable:true,...overrides});

function fixture({language = 'en', selected = null, operator = !!selected, configurable = true, mode = 'strict', request} = {}) {
  class Node {
    constructor(tag, attrs = {}, children = []) {
      this.tag = tag; this.children = []; this.events = {}; this.disabled = false; this.isConnected = true;
      Object.assign(this, attrs); this.textContent = attrs.text || '';
      if (attrs.onClick) this.events.click = attrs.onClick;
      for (const child of [children].flat(Infinity).filter(Boolean)) this.appendChild(child);
    }
    appendChild(child) { this.children.push(child); return child; }
    addEventListener(name, fn) { this.events[name] = fn; }
    setAttribute(name, value) { this[name] = value; }
    set innerHTML(_) { this.children = []; }
    querySelectorAll(selectors) { return this.children.flatMap(walk).filter(node => selectors.split(',').includes(node.tag)); }
  }
  const walk = node => [node,...(node.children || []).flatMap(walk)];
  const el = (tag, attrs = {}, children = []) => new Node(tag, attrs, children);
  const calls = [], fields = [];
  let stored = setting({configurable,mode});
  const context = vm.createContext({
    el, bl: value => value[language], operateTenant:selected,
    signedInAsOperator: () => operator,
    idpSession:{tenant_id:selected ? 'operator' : 'tenant-a',principal_id:'admin-a'},
    freshRender: host => { const generation = host.generation = (host.generation || 0) + 1; return () => host.generation === generation; },
    uiState: (host, state, message) => { host.innerHTML = ''; host.appendChild(el('state', {state,text:message || ''})); },
    uiField: spec => {
      const input = el('select', {value:spec.value}, spec.options.map(option => el('option', {value:option.value,text:option.label})));
      const field = {el:el('field', {text:spec.label}, [input]),input,get:() => input.value};
      fields.push(field); return field;
    },
    apiFetch: async (method, path, body, plane, signal, tenantOverride) => {
      calls.push({method,path,body,plane,tenantOverride});
      if (request) return request(method, path, body, {setting:stored,set:value => stored=value});
      if (path === '/admin/inspection-posture') return {ok:false,status:403,body:{error:'deployment settings unavailable'}};
      if (path === '/admin/tenant') return {ok:true,status:200,body:{tenant_id:'tenant-a',display_name:'Customer A'}};
      if (method === 'POST') stored = {...stored,...body};
      return {ok:true,status:200,body:{...stored}};
    },
  });
  vm.runInContext(source, context);
  const host = el('section');
  const load = () => context.loadTenantUpstreamTLS(host);
  const nodes = () => walk(host);
  const save = () => nodes().find(node => node.tag === 'button' && ['Save','保存'].includes(node.text));
  const choose = value => { fields.at(-1).input.value = value; fields.at(-1).el.events.change(); };
  const notice = () => nodes().find(node => node['aria-live'] === 'polite');
  return {context,host,calls,fields,load,nodes,save,choose,notice,walk};
}

test('tenant TLS settings reject another tenant, deployment scope and malformed capabilities', () => {
  const {context} = fixture();
  assert.equal(context.validatedTenantUpstreamTLS(setting(), 'tenant-a').mode, 'strict');
  for (const body of [null,{},setting({tenant_id:'Tenant-a'}),setting({scope:'deployment'}),
    setting({scope:undefined}),setting({mode:undefined}),setting({mode:'insecure'}),setting({configurable:'true'})]) {
    assert.throws(() => context.validatedTenantUpstreamTLS(body, 'tenant-a'));
  }
});

test('tenant admin changes only the tenant TLS setting and verifies the authoritative readback', async () => {
  const f = fixture(); await f.load();
  assert.equal(f.fields[0].input.value, 'strict');
  assert.equal(f.save().disabled, true);
  f.choose('browser_compatible'); await f.save().events.click();
  const posts = f.calls.filter(call => call.method === 'POST');
  assert.equal(posts.length, 1);
  assert.equal(posts[0].path, '/admin/upstream-tls');
  assert.deepEqual(JSON.parse(JSON.stringify(posts[0].body)), {mode:'browser_compatible'});
  assert.ok(f.calls.every(call => call.plane === 'control'));
  assert.equal(f.calls.at(-1).method, 'GET');
  assert.equal(f.calls.at(-1).path, '/admin/upstream-tls');
  assert.match(f.notice().textContent, /^Saved for this organization/);
  assert.equal(f.save().disabled, true);
  assert.ok(f.nodes().some(node => node.textContent === 'Saved mode: Same as browsers (default)'));
});

test('an organization on the default sees browser-compatible selected and can choose strict', async () => {
  const f = fixture({language:'ja', mode:'browser_compatible'}); await f.load();
  assert.equal(f.fields[0].input.value, 'browser_compatible');
  assert.equal(f.fields[0].input.children[0].value, 'browser_compatible');
  assert.equal(f.fields[0].input.children[0].text, 'ブラウザと同じ（既定）');
  const warning = f.nodes().find(node => /ui-callout-warn/.test(node.class || ''));
  assert.equal(warning.hidden, false);
  f.choose('strict'); await f.save().events.click();
  const posts = f.calls.filter(call => call.method === 'POST');
  assert.deepEqual(JSON.parse(JSON.stringify(posts.at(-1).body)), {mode:'strict'});
});

test('viewer capability disables controls and refuses a dispatched save', async () => {
  const f = fixture({configurable:false}); await f.load();
  assert.equal(f.fields[0].input.disabled, true);
  assert.equal(f.save().disabled, true);
  f.choose('browser_compatible'); await f.save().events.click();
  assert.equal(f.calls.filter(call => call.method === 'POST').length, 0);
  assert.ok(f.nodes().some(node => node.text === 'Read-only in your current session.' && !node.hidden));
});

test('operator calls are pinned to the selected tenant; switching before saving prevents a write', async () => {
  const f = fixture({selected:'tenant-a'}); await f.load();
  assert.ok(f.calls.every(call => call.tenantOverride === 'tenant-a'));
  f.choose('browser_compatible'); f.context.operateTenant = 'tenant-b';
  await f.save().events.click();
  assert.equal(f.calls.filter(call => call.method === 'POST').length, 0);
});

test('operator without a selected organization gets selection guidance, without a deployment-scoped API call', async () => {
  const f = fixture({operator:true}); await f.load();
  assert.equal(f.calls.length, 0);
  assert.equal(f.fields.length, 0);
  assert.ok(f.nodes().some(node => node.state === 'empty' && /Choose an organization/.test(node.text)));
});

test('a tenant switch during save does not read back in the new tenant or show success', async () => {
  let release;
  const f = fixture({selected:'tenant-a',request:async (method, path) => {
    if (path === '/admin/tenant') return {ok:true,status:200,body:{tenant_id:'tenant-a'}};
    if (method === 'POST') return new Promise(resolve => release=resolve);
    return {ok:true,status:200,body:setting()};
  }});
  await f.load(); f.choose('browser_compatible');
  const save = f.save().events.click();
  await f.save().events.click();
  assert.equal(f.calls.filter(call => call.method === 'POST').length, 1);
  f.context.operateTenant = 'tenant-b';
  release({ok:true,status:200,body:setting({mode:'browser_compatible'})}); await save;
  assert.equal(f.calls.length, 3);
  assert.ok(f.calls.every(call => call.tenantOverride === 'tenant-a'));
  assert.doesNotMatch(f.notice().textContent, /^Saved/);
});

test('detached cards and out-of-date reads do not publish settings or submit changes', async () => {
  const f = fixture(); await f.load(); f.choose('browser_compatible'); f.host.isConnected = false;
  await f.save().events.click();
  assert.equal(f.calls.filter(call => call.method === 'POST').length, 0);
  let release;
  const pending = fixture({selected:'tenant-a',request:async (_, path) => path === '/admin/tenant'
    ? {ok:true,status:200,body:{tenant_id:'tenant-a'}} : new Promise(resolve => release=resolve)});
  const load = pending.load(); pending.context.operateTenant = 'tenant-b';
  release({ok:true,status:200,body:setting()}); await load;
  assert.equal(pending.fields.length, 0);
});

test('load failure does not invent a strict setting; tenant card survives unavailable deployment posture', async () => {
  const failed = fixture({request:async () => ({ok:false,status:503,body:{}})});
  await failed.load(); assert.equal(failed.fields.length, 0);
  assert.ok(failed.nodes().some(node => node.state === 'error'));
  const f = fixture(); f.context.renderInspectionPostureView(f.host);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.fields.length, 1);
  assert.equal(f.fields[0].input.disabled, false);
  assert.ok(f.nodes().some(node => node.state === 'error'));
  assert.ok(f.nodes().some(node => node.text === 'Origin TLS compatibility'));
});

test('failed, mismatched and unconfirmed saves never replace the saved setting or report success', async () => {
  for (const failure of ['denied','wrong-tenant','wrong-mode','readback','offline']) {
    let posted = false;
    const f = fixture({request:async (method, path) => {
      if (path === '/admin/tenant') return {ok:true,status:200,body:{tenant_id:'tenant-a'}};
      if (method === 'POST') {
        posted = true;
        if (failure === 'offline') throw new TypeError('offline');
        if (failure === 'denied') return {ok:false,status:403,body:{}};
        return {ok:true,status:200,body:setting({tenant_id:failure==='wrong-tenant'?'tenant-b':'tenant-a',mode:failure==='wrong-mode'?'strict':'browser_compatible'})};
      }
      return {ok:true,status:200,body:setting({mode:posted && failure !== 'readback' ? 'browser_compatible' : 'strict'})};
    }});
    await f.load(); f.choose('browser_compatible'); await f.save().events.click();
    assert.equal(f.notice().role, 'alert', failure);
    assert.match(f.notice().textContent, /^Save not confirmed/, failure);
    assert.ok(f.nodes().some(node => node.textContent === 'Last confirmed mode: Strict'), failure);
    assert.equal(f.save().disabled, true, failure);
    await f.save().events.click();
    assert.equal(f.calls.filter(call => call.method === 'POST').length, 1, failure);
  }
});

test('Japanese controls name the browser-compatible default and warn until a strict save is confirmed', async () => {
  const f = fixture({language:'ja'}); await f.load();
  const text = () => f.nodes().filter(node => !node.hidden).map(node => node.textContent).join('\n');
  const warning = () => f.nodes().find(node => /ui-callout-warn/.test(node.class || ''));
  for (const phrase of ['接続先のTLS互換性','Customer Aだけに適用されます','ブラウザと同じ（既定）','厳格','開けない場合']) assert.ok(text().includes(phrase), phrase);
  assert.ok(!text().includes('厳格（既定）'), 'strict is no longer the default');
  assert.ok(text().includes('DSSE経由では開けない場合があります'));
  // The organization identifier and implementation vocabulary stay off the Japanese screen.
  assert.ok(!text().includes('tenant-a'));
  assert.ok(f.nodes().some(node => node.title === 'tenant-a'));
  for (const jargon of ['static','RSA','AES','GCM','前方秘匿性','傍受']) assert.ok(!text().includes(jargon), jargon);
  assert.equal(warning().hidden, true);
  f.choose('browser_compatible');
  assert.equal(warning().hidden, false);
  for (const phrase of ['古い鍵交換方式','記録された通信を解読','証明書の確認と検査']) assert.ok(text().includes(phrase), phrase);
  await f.save().events.click();
  assert.match(f.notice().textContent, /^この組織の設定を保存しました/);
  assert.equal(warning().hidden, false);
  f.choose('strict');
  assert.equal(warning().hidden, false);
  await f.save().events.click();
  assert.equal(warning().hidden, true);
});

test('failed strict save keeps the saved compatibility warning and requires a fresh read', async () => {
  const f = fixture({request:async (method, path) => {
    if (path === '/admin/tenant') return {ok:true,status:200,body:{tenant_id:'tenant-a'}};
    if (method === 'POST') return {ok:false,status:503,body:{}};
    return {ok:true,status:200,body:setting({mode:'browser_compatible'})};
  }});
  await f.load(); f.choose('strict');
  const warning = () => f.nodes().find(node => /ui-callout-warn/.test(node.class || ''));
  assert.equal(warning().hidden, false);
  await f.save().events.click();
  assert.equal(warning().hidden, false);
  assert.ok(f.nodes().some(node => node.textContent === 'Last confirmed mode: Same as browsers (default)'));
  assert.equal(f.save().disabled, true);
  await f.load();
  assert.equal(f.fields.at(-1).input.value, 'browser_compatible');
  assert.equal(warning().hidden, false);
  f.choose('strict');
  assert.equal(f.save().disabled, false);
});

test('lost compatibility save response cannot hide the risk by selecting strict without saving', async () => {
  for (const currentMode of ['strict', 'browser_compatible']) {
    let posted = false;
    const f = fixture({request:async (method, path) => {
      if (path === '/admin/tenant') return {ok:true,status:200,body:{tenant_id:'tenant-a'}};
      if (method === 'POST') { posted = true; throw new TypeError('connection lost'); }
      return {ok:true,status:200,body:setting({mode:posted ? currentMode : 'strict'})};
    }});
    await f.load(); f.choose('browser_compatible'); await f.save().events.click();
    f.choose('strict');
    const warning = () => f.nodes().find(node => /ui-callout-warn/.test(node.class || ''));
    assert.equal(warning().hidden, false, currentMode);
    assert.equal(f.save().disabled, true, currentMode);
    await f.load();
    assert.equal(f.fields.at(-1).input.value, currentMode);
    assert.equal(warning().hidden, currentMode === 'strict');
  }
});

test('generic API routing sends tenant upstream TLS reads and writes to the control plane', async () => {
  const app = readFileSync(new URL('./app.js', import.meta.url), 'utf8');
  const requests = [];
  const context = vm.createContext({localStorage:{getItem:()=>''},fetch:async (url, options) => {
    requests.push({url,options}); return {status:200,ok:true,text:async ()=>'{}'};
  }});
  vm.runInContext(app.slice(app.indexOf('const CP_AUTHORED_WRITES = ['), app.indexOf('// offerOperatorElevation asks')), context);
  await vm.runInContext("apiFetch('GET','/admin/upstream-tls')", context);
  await vm.runInContext("apiFetch('POST','/admin/upstream-tls',{mode:'strict'})", context);
  assert.deepEqual(requests.map(request => request.url), ['/control/admin/upstream-tls','/control/admin/upstream-tls']);
});
