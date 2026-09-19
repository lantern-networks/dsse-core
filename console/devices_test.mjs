import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';

const source = readFileSync(new URL('./devices.js', import.meta.url), 'utf8');
const identity = 'Device/One.EXAMPLE.TEST';
const device = {identity, enabled: false};
const otherDevice = {identity: 'device-two.example.test', enabled: true};

function responseFor(method, path, body) {
  assert.equal(method, 'POST');
  if (path.startsWith('/admin/transport-admission/')) {
    return {ok: true, status: 200, body: {identity: body.identity.toLowerCase(),
      transport_revoked: false, [path.endsWith('/restore') ? 'restored' : 'revoked']: true}};
  }
  const id = decodeURIComponent(path.slice('/admin/enrolled-devices/'.length, path.lastIndexOf('/')));
  return {ok: true, status: 200, body: {device: {identity: id.toLowerCase(), enabled: path.endsWith('/enable')}}};
}

function fixture() {
  const calls = [], confirmations = [], toasts = [], refreshes = [], states = [], rows = new Map();
  let body;
  function el(tag, attrs = {}, children = []) {
    const handlers = {};
    let text = attrs.text || '';
    const node = {tag, style: {}, attributes: {...attrs}, children: [], disabled: attrs.disabled != null,
      appendChild(child) { if (child) { this.children.push(child); child.parentNode = this; } return child; },
      setAttribute(name, value) { this.attributes[name] = value; },
      getAttribute(name) { return this.attributes[name] ?? null; },
      remove() { if (this.parentNode) this.parentNode.children = this.parentNode.children.filter(child => child !== this); this.parentNode = null; },
      querySelector(selector) { return this.querySelectorAll(selector)[0] || null; },
      querySelectorAll(selector) {
        const matches = candidate => selector.startsWith('[')
          ? Object.hasOwn(candidate.attributes, selector.slice(1, -1)) : candidate.tag === selector;
        return this.children.flatMap(child => [child, ...child.querySelectorAll('*')])
          .filter(candidate => selector === '*' || matches(candidate));
      },
      addEventListener(name, fn) { (handlers[name] ||= []).push(fn); },
      click() { return attrs.onClick ? attrs.onClick({target: this}) : Promise.all((handlers.click || []).map(fn => fn({target: this}))); },
    };
    Object.defineProperty(node, 'isConnected', {get() { return this.__connected ?? (this === body || !!this.parentNode?.isConnected); }, set(value) { this.__connected = value; }});
    Object.defineProperty(node, 'textContent', {
      get() { return text + this.children.map(child => child.textContent).join(''); },
      set(value) { text = String(value); this.children = []; },
    });
    Object.defineProperty(node, 'innerHTML', {set(value) { assert.equal(value, '', 'never inject server error markup'); node.textContent = ''; }});
    for (const child of [children].flat(Infinity)) node.appendChild(child);
    return node;
  }
  body = el('body');
  const host = el('div'), messages = el('div'); body.appendChild(host); host.__deviceAdmissionMessages = messages;
  const addRow = id => {
    const row = el('tr', {'data-device-identity': id});
    const primary = el('button', {'data-device-admission-control': '1'});
    const overflow = el('button', {'data-device-admission-control': '1', 'data-device-risk-control': '1'});
    const unrelated = el('button');
    row.appendChild(primary); row.appendChild(overflow); row.appendChild(unrelated); host.appendChild(row);
    rows.set(id, {row, primary, overflow, unrelated}); return row;
  };
  addRow(identity); addRow(otherDevice.identity);
  const context = vm.createContext({el, document: {body}, bl: value => value.en,
    uiState: (host, state, message, retry) => states.push({state,message,retry}),
    freshRender: host => { const seq=host.renderSequence=(host.renderSequence||0)+1; return ()=>host.renderSequence===seq; },
    apiFetch: async (...args) => { calls.push(args); return responseFor(...args); },
    uiConfirm: async spec => { confirmations.push(spec); return true; },
    uiToast: (message, kind) => toasts.push({message, kind}),
  });
  vm.runInContext(source, context);
  const actualRenderList = context.renderList;
  context.renderList = async passedHost => { assert.equal(passedHost, host); refreshes.push(passedHost); };
  const send = (enabled = true, d = device) => context.changeDeviceAdmission(d, host, enabled);
  return {context, body, calls, confirmations, toasts, refreshes, rows, host, messages, send, addRow, states, actualRenderList,
    notice: (id = identity) => host.__deviceAdmissionNotices?.get(id),
    invokeWith: handler => { context.apiFetch = async (...args) => { calls.push(args); return handler(...args); }; },
  };
}

function assertRequests(calls, enabled, id = identity) {
  assert.equal(calls.length, 2);
  assert.equal(calls[0][0], 'POST');
  assert.equal(calls[0][1], '/admin/transport-admission/' + (enabled ? 'restore' : 'revoke'));
  assert.equal(calls[0][2].identity, id); assert.equal(calls[0][3], 'control');
  if (!enabled) assert.equal(calls[0][2].reason, 'blocked from Devices');
  assert.equal(calls[1][0], 'POST');
  assert.equal(calls[1][1], '/admin/enrolled-devices/' + encodeURIComponent(id) + (enabled ? '/enable' : '/disable'));
  assert.equal(calls[1][3], 'control');
}

function assertFailure(f, partial) {
  assert.equal(f.toasts.filter(toast => toast.kind === 'ok').length, 0);
  assert.ok(f.notice()); assert.equal(f.notice().getAttribute('role'), 'alert');
  assert.match(f.notice().textContent, partial ? /may be partly applied/ : /admission update was not sent/);
  assert.ok(f.notice().querySelectorAll('button').some(button => button.textContent === 'Retry'));
  assert.equal(f.rows.get(identity).primary.disabled, false);
  assert.equal(f.rows.get(identity).overflow.disabled, false);
}

test('Allow and Block change transport before admission on control and announce only confirmed success', async () => {
  for (const enabled of [true, false]) {
    const f = fixture(); await f.send(enabled);
    assertRequests(f.calls, enabled);
    assert.equal(f.confirmations.length, enabled ? 0 : 1);
    if (!enabled) assert.equal(f.confirmations[0].danger, true);
    assert.deepEqual(f.toasts, [{message: (enabled ? 'Local admission enabled: ' : 'Device blocked: ') + identity, kind: 'ok'}]);
    assert.equal(f.notice(), undefined); assert.equal(f.refreshes.length, 1);
    assert.equal(f.rows.get(identity).primary.disabled, false); assert.equal(f.rows.get(identity).overflow.disabled, false);
  }
});

test('transport HTTP failure or lost response does not send an admission write or claim success', async () => {
  for (const enabled of [true, false]) for (const failure of [
    {ok: false, status: 403, body: {error: 'denied'}}, {ok: false, status: 503, body: {error: 'unavailable'}}, new Error('response lost'),
  ]) {
    const f = fixture(); f.invokeWith(() => { if (failure instanceof Error) throw failure; return failure; });
    await f.send(enabled);
    assert.equal(f.calls.length, 1); assert.equal(f.calls[0][3], 'control'); assertFailure(f, false);
    assert.equal(f.refreshes.length, 1); assert.match(f.notice().textContent, /transport may already have changed/);
  }
});

test('transport 200 requires the requested device and an explicit true result before admission', async () => {
  for (const enabled of [true, false]) {
    const flag = enabled ? 'restored' : 'revoked';
    for (const body of [undefined, {}, {identity: 'other-device', [flag]: true},
      {identity, [flag]: false}, {identity, [flag]: 'true'}, {identity: 42, [flag]: true},
      {identity, [enabled ? 'revoked' : 'restored']: true},
    ]) {
      const f = fixture(); f.invokeWith(() => ({ok: true, status: 200, body}));
      await f.send(enabled); assert.equal(f.calls.length, 1); assertFailure(f, false);
      assert.match(f.notice().textContent, /transport response did not confirm/);
    }
  }
});

test('admission HTTP failure and lost response retain a partial-operation warning without rollback', async () => {
  for (const enabled of [true, false]) for (const failure of [
    {ok: false, status: 503, body: {message: '<b>storage failed</b>'}}, new Error('inventory reply lost'),
  ]) {
    const f = fixture(); f.invokeWith((...args) => {
      if (args[1].startsWith('/admin/transport-admission/')) return responseFor(...args);
      if (failure instanceof Error) throw failure; return failure;
    });
    await f.send(enabled); assertRequests(f.calls, enabled); assertFailure(f, true);
    assert.equal(f.refreshes.length, 1); assert.equal(f.calls.length, 2, 'no automatic rollback or retry');
  }
});

test('admission 200 requires a matching identity and the exact requested boolean', async () => {
  for (const enabled of [true, false]) for (const body of [undefined, {}, {device: {}},
    {device: {identity: 'other-device', enabled}}, {device: {identity, enabled: !enabled}},
    {device: {identity, enabled: String(enabled)}}, {device: {identity: 42, enabled}},
  ]) {
    const f = fixture(); f.invokeWith((...args) => args[1].startsWith('/admin/transport-admission/')
      ? responseFor(...args) : {ok: true, status: 200, body});
    await f.send(enabled); assertRequests(f.calls, enabled); assertFailure(f, true);
    assert.match(f.notice().textContent, /inventory response did not confirm/);
  }
});

test('failure details remain literal text in a persistent message outside the refreshed list', async () => {
  const f = fixture(), payload = '<img src=x onerror=alert(1)> & <script>bad()</script>';
  f.invokeWith(() => ({ok: false, status: 503, body: {error: payload}}));
  f.context.renderList = async host => { f.refreshes.push(host); host.innerHTML = ''; };
  await f.send();
  assert.ok(f.messages.textContent.includes(payload)); assert.equal(f.messages.querySelectorAll('img').length, 0);
  assert.equal(f.messages.querySelectorAll('script').length, 0); assert.equal(f.messages.children.length, 1);
  await f.context.renderList(f.host);
  assert.ok(f.messages.textContent.includes(payload)); assert.equal(f.refreshes.length, 2);
});

test('an explicit Retry repeats the intended state and clears that device warning on success', async () => {
  for (const enabled of [true, false]) for (const failSecond of [false, true]) {
    const f = fixture(); f.invokeWith((...args) => !failSecond || args[1].startsWith('/admin/enrolled-devices/')
      ? {ok: false, status: 503, body: {error: 'retry me'}} : responseFor(...args));
    await f.send(enabled); assertFailure(f, failSecond);
    const previous = f.calls.length, retry = f.notice().querySelector('button');
    f.invokeWith(responseFor); await retry.click();
    assertRequests(f.calls.slice(previous), enabled); assert.equal(f.notice(), undefined);
    assert.equal(f.messages.children.length, 0);
    assert.equal(f.toasts.filter(toast => toast.kind === 'ok').length, 1);
  }
});

test('same device is locked through confirmation and cancellation performs no requests', async () => {
  const f = fixture(); let finish;
  f.context.uiConfirm = spec => { f.confirmations.push(spec); return new Promise(resolve => { finish = resolve; }); };
  const first = f.context.disableDevice(device, f.host);
  assert.equal(f.rows.get(identity).primary.disabled, true); assert.equal(f.rows.get(identity).overflow.disabled, true);
  await f.context.enableDevice(device, f.host); await f.context.disableDevice(device, f.host);
  assert.equal(f.confirmations.length, 1); assert.equal(f.calls.length, 0);
  finish(false); await first;
  assert.equal(f.calls.length, 0); assert.equal(f.refreshes.length, 0); assert.equal(f.toasts.length, 0);
  assert.equal(f.notice(), undefined); assert.equal(f.rows.get(identity).primary.disabled, false);
  f.context.uiConfirm = async () => true; await f.context.disableDevice(device, f.host);
  assertRequests(f.calls, false);
});

test('same device cannot overlap either transport or admission, even with the opposite requested state', async () => {
  for (const phase of ['transport', 'admission']) {
    const f = fixture(); let finish, reached;
    const started = new Promise(resolve => { reached = resolve; });
    f.invokeWith((...args) => {
      if (args[1].includes(phase === 'transport' ? '/transport-admission/' : '/enrolled-devices/')) {
        reached(); return new Promise(resolve => { finish = () => resolve(responseFor(...args)); });
      }
      return responseFor(...args);
    });
    const pending = f.send(true); await started;
    const count = f.calls.length; await f.send(true); await f.send(false);
    assert.equal(f.calls.length, count); assert.equal(f.confirmations.length, 0);
    finish(); await pending; assertRequests(f.calls, true);
  }
});

test('a different device remains actionable while one device awaits confirmation', async () => {
  const f = fixture(); let finish;
  f.context.uiConfirm = spec => { f.confirmations.push(spec); return new Promise(resolve => { finish = resolve; }); };
  const blocked = f.send(false);
  assert.equal(f.rows.get(otherDevice.identity).primary.disabled, false);
  await f.send(true, otherDevice); assertRequests(f.calls, true, otherDevice.identity);
  assert.equal(f.rows.get(identity).primary.disabled, true);
  finish(false); await blocked; assert.equal(f.rows.get(identity).primary.disabled, false);
  assert.equal(f.toasts.length, 1);
});

test('busy state touches only admission controls of the requested identity', () => {
  const f = fixture(), row = f.rows.get(identity), other = f.rows.get(otherDevice.identity);
  f.context.deviceAdmissionBusy(f.host, identity, true);
  assert.equal(row.primary.disabled, true); assert.equal(row.overflow.disabled, true);
  assert.equal(row.unrelated.disabled, false); assert.equal(other.primary.disabled, false); assert.equal(other.overflow.disabled, false);
  f.context.deviceAdmissionBusy(f.host, identity, false);
  assert.equal(row.primary.disabled, false); assert.equal(row.overflow.disabled, false);
});

test('notices replace only their own device and survive cancellation of a later attempt', async () => {
  const f = fixture();
  f.context.deviceAdmissionNotice(f.host, device, true, 'first');
  const old = f.notice();
  f.context.deviceAdmissionNotice(f.host, otherDevice, false, 'other');
  f.context.deviceAdmissionNotice(f.host, device, true, 'updated');
  assert.equal(old.parentNode, null); assert.equal(f.messages.children.length, 2);
  assert.ok(f.notice().textContent.includes('updated')); assert.ok(f.notice(otherDevice.identity).textContent.includes('other'));
  f.context.uiConfirm = async () => false; await f.send(false);
  assert.ok(f.notice().textContent.includes('updated')); assert.equal(f.calls.length, 0);
  f.context.deviceAdmissionNotice(f.host, device, true, '');
  assert.equal(f.notice(), undefined); assert.equal(f.messages.children.length, 1);
  assert.ok(f.notice(otherDevice.identity).textContent.includes('other'));
});

test('refresh failure after confirmed mutation reports the read failure without claiming the writes failed', async () => {
  for (const enabled of [true, false]) {
    const f = fixture(); f.context.renderList = async () => { throw Error('refresh offline'); };
    await f.send(enabled); assertRequests(f.calls, enabled); assert.equal(f.notice(), undefined);
    assert.deepEqual(f.toasts, [
      {message: (enabled ? 'Local admission enabled: ' : 'Device blocked: ') + identity, kind: 'ok'},
      {message: 'Error: refresh offline', kind: 'err'},
    ]);
    assert.equal(f.rows.get(identity).primary.disabled, false);
  }
});

test('refresh failure after partial mutation does not discard or replace its persistent warning', async () => {
  const f = fixture(); f.invokeWith((...args) => args[1].startsWith('/admin/transport-admission/')
    ? responseFor(...args) : {ok: false, status: 503, body: {error: 'inventory save failed'}});
  f.context.renderList = async () => { throw Error('refresh failed too'); };
  await f.send(); assertFailure(f, true);
  assert.ok(f.notice().textContent.includes('inventory save failed'));
  assert.ok(f.toasts.some(toast => toast.message === 'Error: refresh failed too' && toast.kind === 'err'));
});

test('restore refusal through the existing enable wrapper never falls through to ledger enable success', async () => {
  const f = fixture(); f.invokeWith((...args) => args[1] === '/admin/transport-admission/restore'
    ? {ok: false, status: 503, body: {error: 'restore unavailable'}} : responseFor(...args));
  await f.context.enableDevice(device, f.host);
  assert.equal(f.calls.some(call => call[1].endsWith('/enable')), false);
  assert.equal(f.toasts.some(toast => toast.kind === 'ok'), false);
  assertFailure(f, false);
});

function riskResponse(severity, id = identity, warning) {
  return {ok: true, status: 200, body: {entity_type: 'device', entity_id: id, severity,
    applied: true, high_risk: severity === 'high' || severity === 'critical',
    ...(warning === undefined ? {} : {not_stored_durably: warning})}};
}
const riskSend = (f, severity = 'high', d = device) => f.context.setDeviceRisk(d, severity, f.host);
const riskNotice = (f, id = identity) => f.host.__deviceRiskNotices?.get(id);

test('device risk sends all four UI severities through control and confirms matching outcomes', async () => {
  for (const severity of ['none', 'medium', 'high', 'critical']) {
    const f = fixture(); f.invokeWith(() => riskResponse(severity)); await riskSend(f, severity);
    assert.equal(f.calls.length, 1); const [method,path,body,plane] = f.calls[0];
    assert.equal(method, 'POST'); assert.equal(path, '/admin/risk-signals'); assert.equal(plane, 'control');
    assert.equal(body.entity_type, 'device'); assert.equal(body.entity_id, identity); assert.equal(body.severity, severity);
    assert.equal(f.toasts.filter(t => t.kind === 'ok').length, 1); assert.equal(riskNotice(f), undefined);
  }
});

test('runtime persistence warning stays visible through refresh and explicit retry repairs it', async () => {
  for (const severity of ['none', 'high']) {
    const f = fixture(); f.invokeWith(() => riskResponse(severity, identity, '<b>save failed</b>'));
    await riskSend(f, severity); assert.equal(f.toasts.length, 0);
    assert.match(riskNotice(f).textContent, /Risk applied, but saving was not confirmed/);
    assert.match(riskNotice(f).textContent, /<b>save failed<\/b>/); assert.equal(riskNotice(f).getAttribute('role'), 'alert');
    assert.equal(riskNotice(f).parentNode, f.messages); assert.equal(f.refreshes.length, 1);
    f.invokeWith(() => riskResponse(severity)); await riskNotice(f).querySelector('button').click();
    assert.equal(f.calls.length, 2); assert.equal(riskNotice(f), undefined); assert.equal(f.toasts[0].kind, 'ok');
  }
});

test('risk HTTP, transport and malformed success never announce confirmed success', async () => {
  const good = riskResponse('high').body;
  for (const reply of [
    {ok:false,status:403,body:{error:'denied'}}, {ok:false,status:503,body:{}}, new Error('lost response'),
    ...[null, {}, {...good,entity_id:'someone-else'}, {...good,entity_type:'user'},
      {...good,severity:'none'}, {...good,applied:false}, {...good,applied:'true'},
      {...good,high_risk:false}, {...good,not_stored_durably:{}}, {...good,not_stored_durably:null}]
      .map(body=>({ok:true,status:200,body}))
  ]) {
    const f = fixture(); f.invokeWith(()=>{if(reply instanceof Error)throw reply;return reply;});
    await riskSend(f); assert.equal(f.calls.length,1); assert.equal(f.toasts.filter(t=>t.kind==='ok').length,0);
    assert.match(riskNotice(f).textContent,/may already be applied/); assert.equal(f.rows.get(identity).overflow.disabled,false);
  }
});

test('risk suppresses repeated and opposite risk changes while allowing another device', async () => {
  const f = fixture(); let resolve;
  f.invokeWith((method,path,body)=>body.entity_id===identity?new Promise(r=>resolve=r):riskResponse(body.severity,body.entity_id));
  const first=riskSend(f); assert.equal(f.rows.get(identity).overflow.disabled,true);
  await riskSend(f); await riskSend(f,'none'); assert.equal(f.calls.length,1);
  await riskSend(f,'medium',otherDevice); assert.equal(f.calls.length,2);
  resolve(riskResponse('high')); await first; assert.equal(f.rows.get(identity).overflow.disabled,false);
});

test('overlapping admission and risk keep the More button disabled until both finish', async () => {
  for (const riskFirst of [true,false]) {
    const f = fixture(); let riskResolve,transportResolve;
    f.invokeWith((method,path,body)=>path==='/admin/risk-signals'?new Promise(r=>riskResolve=r)
      :path.includes('transport-admission')?new Promise(r=>transportResolve=r):responseFor(method,path,body));
    const risk=riskSend(f); const admission=f.send(true);
    assert.equal(f.rows.get(identity).overflow.disabled,true);
    if(riskFirst){riskResolve(riskResponse('high'));await risk;assert.equal(f.rows.get(identity).overflow.disabled,true);transportResolve(responseFor('POST','/admin/transport-admission/restore',{identity}));await admission;}
    else{transportResolve(responseFor('POST','/admin/transport-admission/restore',{identity}));await admission;assert.equal(f.rows.get(identity).overflow.disabled,true);riskResolve(riskResponse('high'));await risk;}
    assert.equal(f.rows.get(identity).overflow.disabled,false);
  }
});

test('risk notices are separate from admission notices and from other devices', async () => {
  const f=fixture();f.invokeWith(()=>({ok:false,status:503,body:{error:'unavailable'}}));
  await f.send(); const admissionNotice=f.notice();await riskSend(f); const first=riskNotice(f);
  await riskSend(f,'none',otherDevice); assert.equal(f.notice(),admissionNotice);assert.equal(riskNotice(f),first);
  f.invokeWith(()=>riskResponse('high'));await riskSend(f);assert.equal(riskNotice(f),undefined);
  assert.ok(riskNotice(f,otherDevice.identity));assert.equal(f.notice(),admissionNotice);
});

test('risk refresh failure does not reclassify a confirmed operation or discard persistence warning', async () => {
  for(const warning of [undefined,'runtime save failed']) {
    const f=fixture();f.invokeWith(()=>riskResponse('high',identity,warning));
    f.context.renderList=async()=>{throw new Error('refresh unavailable');};await riskSend(f);
    assert.equal(f.calls.length,1);assert.equal(f.toasts.filter(t=>t.kind==='ok').length,warning?0:1);
    if(warning)assert.match(riskNotice(f).textContent,/saving was not confirmed/);else assert.equal(riskNotice(f),undefined);
  }
});

test('Allow does not enable inventory or announce success while another transport block remains', async () => {
  const f = fixture(); f.invokeWith((...args) => {
    const r = responseFor(...args); r.body.transport_revoked = true; return r;
  });
  await f.send(); assert.equal(f.calls.length, 1); assert.equal(f.toasts.length, 0);
  assert.match(f.notice().textContent, /connection block still applies/);
  assert.match(f.notice().textContent, /inventory admission was not changed/);
  assert.equal(f.refreshes.length, 1);
  f.invokeWith(responseFor); await f.notice().querySelector('button').click();
  assertRequests(f.calls.slice(1), true); assert.equal(f.notice(), undefined);
});

test('Allow requires an explicit effective transport result, not just a local restore acknowledgement', async () => {
  for (const value of [undefined, null, 0, 'false']) {
    const f = fixture(); f.invokeWith((...args) => {
      const r = responseFor(...args); r.body.transport_revoked = value; return r;
    });
    await f.send(); assert.equal(f.calls.length, 1); assertFailure(f, false);
  }
});

const inventoryAnswer = () => ({schema_version: 'admin_enrolled_inventory.v1', tenant_id: 'tenant-a', unassigned: 0,
  devices: [{identity:'LOCAL',enabled:true},{identity:'mesh',enabled:true},{identity:'synced',enabled:true},
    {identity:'inventory-only',enabled:false},{identity:'clear',enabled:true}]});
const transportAnswer = () => ({schema_version:'admin_transport_admission.v1', tenant_id:'tenant-a',
  revoked_identities:['local','mesh','synced'], withheld_unattributable:1});

test('device status derives from both admission gates and takes precedence over steering telemetry', () => {
  const f = fixture(), source = inventoryAnswer();
  const rows = f.context.deviceAdmissionRows(source, transportAnswer(), 'tenant-a');
  assert.equal(rows.filter(d => f.context.deviceIsBlocked(d)).length, 4);
  for (const d of rows.slice(0,4)) {
    const st = f.context.deviceStateOf(d, {steer_active:true}, {steer_active:true}, 'none');
    assert.equal(st.pill.text,'Blocked'); assert.equal(st.steering,false);
    assert.equal(d.admissionContext.tenant,'tenant-a');
  }
  assert.equal(rows[0].enabled,true,'do not rewrite the stored inventory flag');
  assert.equal(source.devices[0].transport_revoked,undefined,'do not mutate API data');
  assert.equal(f.context.deviceIsBlocked(rows[4]),false);
});

test('malformed or wrong-tenant admission reads never become a known unblocked list', () => {
  const f = fixture();
  for (const patch of [{schema_version:'unknown'}, {tenant_id:'tenant-b'}, {revoked_identities:null},
    {revoked_identities:['LOCAL']},{revoked_identities:['']},{revoked_identities:['mesh','mesh']},
    {revoked_identities:[42]},{withheld_unattributable:-1},{withheld_unattributable:'0'}]) {
    assert.throws(() => f.context.deviceAdmissionRows(inventoryAnswer(), {...transportAnswer(),...patch}, ''), /could not be verified/);
  }
  for (const patch of [{schema_version:'unknown'},{tenant_id:''},{devices:null},{unassigned:'0'},{unassigned:null},
    {devices:[{identity:'one',enabled:'true'}]},{devices:[{identity:'one',enabled:true},{identity:'ONE',enabled:true}]}]) {
    assert.throws(() => f.context.deviceAdmissionRows({...inventoryAnswer(),...patch}, transportAnswer(), ''), /could not be verified/);
  }
  assert.throws(() => f.context.deviceAdmissionRows(inventoryAnswer(), transportAnswer(), 'tenant-b'), /could not be verified/);
});

test('verified row context is bound into both writes and both acknowledgements', async () => {
  const d = {...device, admissionContext:{tenant:'tenant-a',selection:'tenant-a'}};
  for (const mismatch of ['', 'transport', 'inventory']) {
    const f = fixture(); f.context.operateTenant = 'tenant-a';
    f.invokeWith((method,path,body) => {
      assert.equal(new URL(path,'https://test').searchParams.get('expected_tenant_id'),'tenant-a');
      const r = responseFor(method,path.split('?')[0],body);
      r.body.tenant_id = path.includes(mismatch==='transport'?'/transport-admission/':'/enrolled-devices/') && mismatch ? 'tenant-b':'tenant-a';
      return r;
    });
    await f.send(true,d);
    assert.equal(f.calls.length,mismatch==='transport'?1:2);
    assert.equal(f.toasts.filter(t=>t.kind==='ok').length,mismatch?0:1);
  }
});

test('navigation or tenant change during a transport write prevents a subsequent inventory write and toast', async () => {
  for (const detached of [false,true]) {
    const f = fixture(); f.context.operateTenant = 'tenant-a'; let finish;
    f.invokeWith((...args)=>new Promise(resolve=>{finish=()=>resolve({...responseFor(...args),body:{identity,restored:true,transport_revoked:false,tenant_id:'tenant-a'}})}));
    const done=f.send(true,{...device,admissionContext:{tenant:'tenant-a',selection:'tenant-a'}});
    if(detached)f.host.isConnected=false;else f.context.operateTenant='tenant-b';
    finish();await done;assert.equal(f.calls.length,1);assert.equal(f.refreshes.length,0);assert.equal(f.toasts.length,0);
  }
});

test('inventory may omit the zero unassigned count as specified by the API', () => {
  const f=fixture(), inventory=inventoryAnswer();delete inventory.unassigned;
  assert.equal(f.context.deviceAdmissionRows(inventory,transportAnswer(),'').length,5);
});


test('required connection reads fail visibly without fetching optional telemetry or sending writes', async () => {
  for (const response of [{ok:false,status:503}, {ok:true,body:{}}, new Error('network lost'), new TypeError('Failed to fetch'), new TypeError('Load failed'), new TypeError('NetworkError when attempting to fetch resource.'), new TypeError('unexpected programming error')]) {
    const f=fixture();f.invokeWith((method,path)=>{
      assert.equal(method,'GET');
      if(path==='/admin/enrolled-devices')return {ok:true,body:inventoryAnswer()};
      assert.equal(path,'/admin/transport-admission?expected_tenant_id=tenant-a');
      if(response instanceof Error)throw response;return response;
    });
    await f.actualRenderList(f.host);assert.equal(f.calls.length,2);
    assert.deepEqual(f.states.map(s=>s.state),['loading','error']);
    if(response instanceof TypeError && response.message !== 'unexpected programming error') {
      assert.equal(f.states[1].message,'Cannot reach the management server. Check your connection, then retry.');
    } else if(response instanceof Error) assert.equal(f.states[1].message,String(response));
  }
});

test('stale inventory and transport replies cannot render after organization change or navigation', async () => {
  for(const stage of ['inventory','transport'])for(const detached of [false,true]){
    const f=fixture();let finish,reached;const waiting=new Promise(resolve=>{reached=resolve});
    f.invokeWith((method,path)=>{
      const r={ok:true,body:path.includes('/transport-admission')?transportAnswer():inventoryAnswer()};
      if(path.includes(stage==='inventory'?'/enrolled-devices':'/transport-admission')){reached();return new Promise(resolve=>{finish=()=>resolve(r)})}
      return r;
    });
    const pending=f.actualRenderList(f.host);await waiting;
    if(detached)f.host.isConnected=false;else f.context.operateTenant='tenant-b';
    finish();await pending;assert.equal(f.calls.length,stage==='inventory'?1:2);
    assert.deepEqual(f.states.map(s=>s.state),['loading']);
  }
});

test('a superseded list request cannot overwrite the latest load error', async () => {
  const f=fixture();let finish;
  f.invokeWith(()=>new Promise(resolve=>{finish=()=>resolve({ok:true,body:inventoryAnswer()})}));
  const old=f.actualRenderList(f.host);
  f.invokeWith(()=>({ok:false,status:503}));await f.actualRenderList(f.host);finish();await old;
  assert.equal(f.calls.length,2);assert.deepEqual(f.states.map(s=>s.state),['loading','loading','error']);
});

const riskReadAnswer = () => ({entity_type:'device',tenant_id:'tenant-a',high_risk:{LOCAL:'high',local:'medium'},withheld_unattributable:0});
test('risk reads require a matching tenant, typed map and explicit withheld count', () => {
 const f=fixture(),good=riskReadAnswer();assert.equal(f.context.deviceRiskSnapshot(good,'tenant-a'),good.high_risk);
 for(const patch of [{entity_type:undefined},{entity_type:'user'},{tenant_id:'tenant-b'},{tenant_id:undefined},
 {high_risk:null},{high_risk:[]},{high_risk:'invalid'},{high_risk:{LOCAL:'none'}},{high_risk:{LOCAL:null}},
 {high_risk:{' LOCAL ':'high'}},{high_risk:{'':'high'}},{withheld_unattributable:undefined},{withheld_unattributable:-1},{withheld_unattributable:'0'},{withheld_unattributable:0.5}]){
 assert.throws(()=>f.context.deviceRiskSnapshot({...good,...patch},'tenant-a'),/Invalid device risk response/);
 }
 const empty={...good,high_risk:{}};assert.equal(f.context.deviceRiskSnapshot(empty,'tenant-a'),empty.high_risk);
});
function answerBeforeRisk(path) {
 if(path.includes('/enrolled-devices'))return {ok:true,body:inventoryAnswer()};
 if(path.includes('/transport-admission'))return {ok:true,body:transportAnswer()};
 return {ok:false,status:503};
}
test('risk HTTP, network and malformed reads stop the list instead of displaying Normal', async()=>{
 for(const reply of [{ok:false,status:403},{ok:false,status:503},{ok:true,body:{}},{ok:true,body:{...riskReadAnswer(),tenant_id:'tenant-b'}},new Error('network')]){
 const f=fixture();f.invokeWith((method,path,body,plane)=>{
 assert.equal(method,'GET');if(!path.includes('/risk-signals'))return answerBeforeRisk(path);
 assert.equal(path,'/admin/risk-signals?expected_tenant_id=tenant-a');assert.equal(plane,'control');if(reply instanceof Error)throw reply;return reply;
 });await f.actualRenderList(f.host);assert.deepEqual(f.states.map(x=>x.state),['loading','error']);assert.match(f.states[1].message,/Risk status could not be read/);assert.equal(f.toasts.length,0);
 assert.ok(!f.calls.some(c=>c[1].includes('/device-groups')));
 }
});
test('stale risk reads cannot render after a tenant switch or navigation',async()=>{
 for(const detached of [false,true]){
 const f=fixture();let finish,reached;const waiting=new Promise(resolve=>reached=resolve);
 f.invokeWith((method,path)=>{if(!path.includes('/risk-signals'))return answerBeforeRisk(path);reached();return new Promise(resolve=>finish=()=>resolve({ok:true,body:riskReadAnswer()}))});
 const pending=f.actualRenderList(f.host);await waiting;if(detached)f.host.isConnected=false;else f.context.operateTenant='tenant-b';finish();await pending;
 assert.deepEqual(f.states.map(x=>x.state),['loading']);assert.ok(!f.calls.some(c=>c[1].includes('/device-groups')));
 }
});
test('risk read errors are translated without displaying backend detail', async()=>{
 const f=fixture();f.context.bl=value=>value.ja;f.invokeWith((method,path)=>path.includes('/risk-signals')?{ok:false,status:503,body:{error:'PRIVATE_PATH'}}:answerBeforeRisk(path));
 await f.actualRenderList(f.host);assert.match(f.states[1].message,/リスク状態を取得できません/);assert.ok(!f.states[1].message.includes('PRIVATE_PATH'));
});


const assignmentDevice = {...device, tenant_id: 'tenant_a', group: 'QA', admissionContext: {tenant: 'tenant_a', selection: ''}};
const groupList = {schema_version: 'admin_device_group_registry.v1', tenant_id: 'tenant_a', groups: [
  {id: 'qa', name: 'QA', tenant_id: 'tenant_a'}, {id: 'pilot', name: 'Pilot', tenant_id: 'tenant_a'},
]};
function assignmentFixture() {
  const f = fixture();
  f.invokeWith((method, path, body) => method === 'GET' ? {ok: true, body: structuredClone(groupList)} :
    {ok: true, body: {schema_version: 'admin_enrolled_inventory.v1', device: {identity, tenant_id: 'tenant_a', group: body.group}}});
  f.dialog = () => f.body.querySelectorAll('div').find(n => n.attributes.role === 'dialog');
  f.button = label => f.dialog().querySelectorAll('button').find(n => n.textContent === label);
  f.open = (d = assignmentDevice) => f.context.openAssignGroupForm(d, f.host);
  return f;
}

test('assignment read failures refuse editing and Retry preserves the existing selection', async () => {
  for (const bad of [{ok: false, status: 503}, {ok: true, body: {}}, {ok: true, body: {...groupList, groups: null}},
    {ok: true, body: {...groupList, groups: {}}}, new Error('offline')]) {
    const f = assignmentFixture(); f.invokeWith(() => { if (bad instanceof Error) throw bad; return bad; });
    await f.open(); assert.equal(f.states.at(-1).state, 'error'); assert.equal(f.states.at(-1).retry.label, 'Retry');
    assert.equal(f.button('Assign').disabled, true); assert.equal(f.button('Unassigned'), undefined); assert.equal(f.button('+ New'), undefined);
    await f.button('Assign').click(); assert.equal(f.calls.filter(c => c[0] === 'POST').length, 0);
    f.invokeWith(() => ({ok: true, body: groupList})); await f.states.at(-1).retry.onClick();
    assert.equal(f.button('Assign').disabled, false); assert.ok(f.button('QA').attributes.class.includes('ui-btn-primary'));
    assert.ok(f.calls.every(c => c[3] === 'control' && c[1].endsWith('?expected_tenant_id=tenant_a')));
  }
});

test('assignment registry rejects wrong context, malformed entries and duplicate choices', () => {
  const f = assignmentFixture();
  for (const body of [{...groupList, schema_version:'wrong'}, {...groupList, tenant_id:'tenant_b'},
    ...[null, [], {}, {id:'g',name:42}, {id:'',name:'QA'}, {id:'g',name:' '}, {id:'g',name:'QA',description:{}},
      {id:'g',name:'QA',tenant_id:'tenant_b'}].map(g => ({...groupList,groups:[g]})),
    {...groupList,groups:[{id:'one',name:'QA'},{id:'two',name:' qa '}]},
    {...groupList,groups:[{id:'one',name:'QA'},{id:'one',name:'Pilot'}]},
  ]) assert.throws(() => f.context.deviceAssignmentGroups({ok:true,body}, 'tenant_a'), /could not be verified/);
});

test('a valid empty registry keeps an older assignment until explicitly cleared', async () => {
  const f = assignmentFixture();f.invokeWith((method, _path, body) => method==='GET' ? {ok:true,body:{...groupList,groups:[]}} :
    {ok:true,body:{schema_version:'admin_enrolled_inventory.v1',device:{identity,tenant_id:'tenant_a',group:body.group}}});
  await f.open();assert.equal(f.button('Assign').disabled,false);assert.ok(f.button('QA'));assert.match(f.dialog().textContent,/not in the group list/);
  await f.button('Assign').click();assert.equal(f.calls.at(-1)[2].group,'QA');assert.equal(f.toasts.at(-1).message,'Group set: QA.');
  await f.open();await f.button('Unassigned').click();await f.button('Assign').click();assert.equal(f.calls.at(-1)[2].group,'');assert.equal(f.toasts.at(-1).message,'Group cleared.');
});

test('assignment loading can be cancelled and a detached or changed tenant cannot open a late editor', async () => {
  for (const action of ['cancel','detach','tenant']) for (const fail of [false,true]) {
    const f = assignmentFixture();let finish;f.invokeWith(()=>new Promise((resolve,reject)=>{finish=()=>fail?reject(Error('late')):resolve({ok:true,body:groupList});}));
    const loading=f.open();assert.ok(f.dialog());assert.equal(f.button('Assign').disabled,true);
    if(action==='cancel')await f.button('Cancel').click();else if(action==='detach')f.host.remove();else f.context.operateTenant='tenant_b';
    finish();await loading;assert.equal(f.dialog(),undefined);assert.equal(f.toasts.length,0);assert.equal(f.calls.filter(c=>c[0]==='POST').length,0);
  }
});

test('assignment saving captures one selection and locks all controls against overlap', async () => {
  const f=assignmentFixture();await f.open();await f.button('Pilot').click();let finish;
  f.invokeWith((_method,_path,body)=>new Promise(resolve=>{finish=()=>resolve({ok:true,body:{schema_version:'admin_enrolled_inventory.v1',device:{identity,tenant_id:'tenant_a',group:body.group}}});}));
  const submit=f.button('Assign');const saving=submit.click();assert.ok(f.dialog().querySelectorAll('button').every(b=>b.disabled));
  await f.button('Unassigned').click();await submit.click();assert.equal(f.calls.filter(c=>c[0]==='POST').length,1);assert.equal(f.calls.at(-1)[2].group,'Pilot');
  finish();await saving;assert.deepEqual(f.toasts,[{message:'Group set: Pilot.',kind:'ok'}]);assert.equal(f.refreshes.length,1);assert.equal(f.dialog(),undefined);
});

test('failed or unconfirmed assignment stays open with a literal persistent error and can retry', async () => {
  for(const bad of [{ok:false,status:500,body:{error:'<b>saving unconfirmed</b>'}},new Error('lost response'),
    {ok:true,body:{}}, {ok:true,body:{schema_version:'admin_enrolled_inventory.v1',device:{identity:'other',tenant_id:'tenant_a',group:'QA'}}},
    {ok:true,body:{schema_version:'admin_enrolled_inventory.v1',device:{identity,tenant_id:'tenant_b',group:'QA'}}},
    {ok:true,body:{schema_version:'admin_enrolled_inventory.v1',device:{identity,tenant_id:'tenant_a',group:'Pilot'}}},
  ]){
    const f=assignmentFixture();await f.open();f.invokeWith(()=>{if(bad instanceof Error)throw bad;return bad});await f.button('Assign').click();
    assert.ok(f.dialog());assert.equal(f.button('Assign').disabled,false);assert.equal(f.toasts.length,0);assert.equal(f.refreshes.length,0);
    const error=f.dialog().querySelectorAll('div').find(n=>n.attributes.role==='alert');assert.ok(error.textContent);assert.equal(error.style.display,'');assert.equal(error.querySelectorAll('b').length,0);
    f.invokeWith((_method,_path,body)=>({ok:true,body:{schema_version:'admin_enrolled_inventory.v1',device:{identity,tenant_id:'tenant_a',group:body.group}}}));await f.button('Assign').click();assert.equal(f.dialog(),undefined);assert.equal(f.toasts.length,1);
  }
});

test('detached assignment saves cannot refresh another page or show a late success or failure', async () => {
  for(const fail of [false,true]){
    const f=assignmentFixture();await f.open();let finish;f.invokeWith(()=>new Promise((resolve,reject)=>{finish=()=>fail?reject(Error('late')):resolve({ok:true,body:{schema_version:'admin_enrolled_inventory.v1',device:{identity,tenant_id:'tenant_a',group:'QA'}}});}));
    const saving=f.button('Assign').click();f.host.remove();finish();await saving;assert.equal(f.dialog(),undefined);assert.equal(f.toasts.length,0);assert.equal(f.refreshes.length,0);
  }
});

test('assignment New hands the confirmed group name back to a freshly loaded editor', async () => {
  const f=assignmentFixture();await f.open();let created;f.context.openCreateGroupForm=fn=>{created=fn};await f.button('+ New').click();assert.equal(f.dialog(),undefined);assert.ok(created);
  await created('Pilot');assert.ok(f.button('Pilot').attributes.class.includes('ui-btn-primary'));assert.equal(f.calls.filter(c=>c[0]==='GET').length,2);
});

test('a late registry retry cannot replace a newer retry failure', async () => {
  const f=assignmentFixture();f.invokeWith(()=>({ok:false,status:503}));await f.open();const retry=f.states.at(-1).retry.onClick;
  let first;let n=0;f.invokeWith(()=>++n===1?new Promise(resolve=>{first=resolve}):{ok:false,status:403});
  const old=retry();await retry();first({ok:true,body:groupList});await old;
  assert.match(f.states.at(-1).message,/HTTP 403/);assert.equal(f.button('Assign').disabled,true);assert.equal(f.button('QA'),undefined);
  assert.equal(f.calls.filter(c=>c[0]==='POST').length,0);
});


test('overview aggregation handles reserved property names for missing and configured groups', async () => {
  const context = vm.createContext({ console });
  vm.runInContext(source, context);
  vm.runInContext(readFileSync(new URL('./overview.js', import.meta.url), 'utf8'), context);
  context.byDeviceIdentity = () => Object.create(null);
  context.deviceKey = x => x;
  context.deviceStateOf = () => ({ offline: true, excluded: 0 });
  for (const groups of [[], [{ name: '__proto__', risk: 'high' }]]) {
    context.apiFetch = async (_, path) => ({ ok: true, status: 200, body:
      path === '/admin/enrolled-devices' ? { devices: [{ identity: '__proto__', group: '__proto__', enabled: true }] } :
      path === '/admin/device-groups' ? { groups } : {} });
    const got = await context.ovDeviceAggregate();
    assert.equal(got.total, 1);
    assert.equal(got.risk[groups.length ? 'high' : 'none'], 1);
  }
});
