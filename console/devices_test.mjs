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
      [path.endsWith('/restore') ? 'restored' : 'revoked']: true}};
  }
  const id = decodeURIComponent(path.slice('/admin/enrolled-devices/'.length, path.lastIndexOf('/')));
  return {ok: true, status: 200, body: {device: {identity: id.toLowerCase(), enabled: path.endsWith('/enable')}}};
}

function fixture() {
  const calls = [], confirmations = [], toasts = [], refreshes = [], rows = new Map();
  function el(tag, attrs = {}, children = []) {
    let text = attrs.text || '';
    const node = {tag, style: {}, attributes: {...attrs}, children: [], disabled: !!attrs.disabled,
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
      click() { return attrs.onClick?.(); },
    };
    Object.defineProperty(node, 'textContent', {
      get() { return text + this.children.map(child => child.textContent).join(''); },
      set(value) { text = String(value); this.children = []; },
    });
    Object.defineProperty(node, 'innerHTML', {set(value) { assert.equal(value, '', 'never inject server error markup'); node.textContent = ''; }});
    for (const child of [children].flat(Infinity)) node.appendChild(child);
    return node;
  }
  const host = el('div'), messages = el('div'); host.__deviceAdmissionMessages = messages;
  const addRow = id => {
    const row = el('tr', {'data-device-identity': id});
    const primary = el('button', {'data-device-admission-control': '1'});
    const overflow = el('button', {'data-device-admission-control': '1'});
    const unrelated = el('button');
    row.appendChild(primary); row.appendChild(overflow); row.appendChild(unrelated); host.appendChild(row);
    rows.set(id, {row, primary, overflow, unrelated}); return row;
  };
  addRow(identity); addRow(otherDevice.identity);
  const context = vm.createContext({el, bl: value => value.en,
    apiFetch: async (...args) => { calls.push(args); return responseFor(...args); },
    uiConfirm: async spec => { confirmations.push(spec); return true; },
    uiToast: (message, kind) => toasts.push({message, kind}),
  });
  vm.runInContext(source, context);
  context.renderList = async passedHost => { assert.equal(passedHost, host); refreshes.push(passedHost); };
  const send = (enabled = true, d = device) => context.changeDeviceAdmission(d, host, enabled);
  return {context, calls, confirmations, toasts, refreshes, rows, host, messages, send, addRow,
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
    assert.deepEqual(f.toasts, [{message: enabled ? 'Device allowed.' : 'Device blocked.', kind: 'ok'}]);
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
      {message: enabled ? 'Device allowed.' : 'Device blocked.', kind: 'ok'},
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
