import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';

const source = readFileSync(new URL('./agentprofile.js', import.meta.url), 'utf8');
function fixture(realResult = false) {
  const fields = {}, nodes = [], calls = [], made = [], notices = [];
  function el(tag, props = {}, children = []) {
    const node = {tag, ...props, style: {}, disabled: false, children: [], listeners: {},
      appendChild(child) { if (child) this.children.push(child); },
      addEventListener(event, handler) { this.listeners[event] = handler; },
    };
    Object.defineProperty(node, 'innerHTML', {set() { this.children = []; }});
    for (const child of children) node.appendChild(child);
    nodes.push(node); return node;
  }
  const context = vm.createContext({el, bl: text => text.en, performance: {now: () => 1},
    uiToast: message => notices.push(message),
    uiField(spec) {
      const field = {el: el('div'), value: spec.value || '',
        get() { return this.value; }, set(value) { this.value = value; },
        setError(message) { this.error = message; },
      };
      fields[spec.name] = field; return field;
    },
    apiFetch: async (...args) => { calls.push(args); return {ok: true, body: {payload_b64: 'signed'}}; },
  });
  vm.runInContext(source, context);
  vm.runInContext('_profileOptions = {device_groups:[{name:"group-a"},{name:"group-b"}]}; _profileEndpoints = [{value:"a=https://a.example.test",on:true},{value:"b=https://b.example.test",on:true}];', context);
  if (!realResult) context.showAgentProfileMade = (body, group) => made.push({body, group});
  context.renderAgentProfileForm(el('div'));
  fields.group.set('group-a');
  const submit = nodes.find(n => n.text === 'Make the configuration');
  return {context, fields, nodes, calls, made, notices, submit, click: () => submit.listeners.click()};
}

test('issued profile and subsequent token dialog retain the submitted group while form changes', async () => {
  for (const group of ['group-a', '']) {
    const f = fixture(); f.fields.group.set(group); let finish;
    f.context.apiFetch = (...args) => { f.calls.push(args); return new Promise(resolve => { finish = resolve; }); };
    const pending = f.click();
    assert.equal(f.calls[0][2].group, group); assert.equal(f.submit.disabled, true);
    f.fields.group.set('group-b');
    const body = {payload_b64: 'signed'}; finish({ok: true, body}); await pending;
    assert.equal(f.made[0].group, group); assert.equal(f.made[0].body, body);
    assert.equal(f.fields.group.get(), 'group-b'); assert.equal(f.submit.disabled, false);
    assert.equal(f.calls[0][3], 'control');
  }
});

test('reentrant issuance makes one request and permits the next request after completion', async () => {
  const f = fixture(); let finish;
  f.context.apiFetch = (...args) => { f.calls.push(args); return new Promise(resolve => { finish = resolve; }); };
  const first = f.click(); const duplicate = f.click(); assert.equal(f.calls.length, 1);
  finish({ok: true, body: {}}); await first; await duplicate; f.fields.group.set('group-b');
  const next = f.click(); assert.equal(f.calls.length, 2); assert.equal(f.calls[1][2].group, 'group-b');
  finish({ok: true, body: {}}); await next;
});

test('HTTP and transport failures do not issue a token dialog and can be retried with a new group', async () => {
  for (const failure of [{ok: false, status: 500, body: {error: 'unavailable'}}, new Error('offline')]) {
    const f = fixture(); f.context.apiFetch = async () => { if (failure instanceof Error) throw failure; return failure; };
    await f.click(); assert.equal(f.submit.disabled, false); assert.equal(f.made.length, 0); assert.equal(f.notices.length, 1);
    f.fields.group.set('group-b'); f.context.apiFetch = async () => ({ok: true, body: {}});
    await f.click(); assert.equal(f.made[0].group, 'group-b');
  }
});

test('no destination or missing explicit acknowledgments refuses issuance', async () => {
  for (const kind of ['endpoints', 'posture', 'virtual-machine']) {
    const f = fixture();
    if (kind === 'endpoints') vm.runInContext('_profileEndpoints.forEach(e => e.on = false)', f.context);
    if (kind === 'posture') f.nodes.find(n => n.value === 'fail-open').checked = true;
    if (kind === 'virtual-machine') f.nodes.find(n => n.value === 'allowed').checked = true;
    await f.click(); assert.equal(f.calls.length, 0); assert.equal(f.made.length, 0); assert.equal(f.submit.disabled, false);
  }
});

test('acknowledged choices and destination order are submitted unchanged', async () => {
  const f = fixture(); f.nodes.find(n => n.value === 'fail-open').checked = true; f.fields.ack.set(true);
  f.nodes.find(n => n.value === 'allowed').checked = true; f.fields.vmack.set(true);
  vm.runInContext('_profileEndpoints.reverse()', f.context); await f.click();
  const body = JSON.parse(JSON.stringify(f.calls[0][2]));
  assert.equal(body.posture, 'fail-open'); assert.equal(body.ack_fail_open, true);
  assert.equal(body.virtual_machine_egress, 'allowed'); assert.equal(body.ack_virtual_machine_egress, true);
  assert.deepEqual(body.transport_endpoints, ['b=https://b.example.test', 'a=https://a.example.test']);
});


function tokenFixture() {
  const f = fixture(true);
  vm.runInContext(readFileSync(new URL('./enrolmenttokens.js', import.meta.url), 'utf8'), f.context);
  f.context.uiModal = () => ({close() {}});
  f.context.navigator = {userAgent: 'test'};
  f.context.showEnrolTokenOnce = body => f.made.push(body);
  f.context.showAgentProfileMade({}, 'group-a');
  f.tokenButton = f.nodes.find(n => n.text === 'Make the tokens');
  f.tokenError = f.nodes.find(n => n.role === 'alert');
  f.send = () => f.tokenButton.listeners.click();
  return f;
}

test('profile token issuance rejects invalid counts before posting', async () => {
  const f = tokenFixture();
  for (const raw of ['0', '-1', '1.5', 'abc', '501', '']) {
    f.fields.count.set(raw); await f.send(); assert.equal(f.calls.length, 0);
    assert.match(f.fields.count.error, /1 to 500/);
  }
});

test('profile partial issuance preserves returned secrets and the requested count without reentry', async () => {
  const f = tokenFixture(); f.fields.count.set('3'); let finish;
  f.context.apiFetch = (...args) => { f.calls.push(args); return new Promise(resolve => { finish = resolve; }); };
  const pending = f.send(); f.fields.count.set('5'); await f.send(); assert.equal(f.calls.length, 1);
  const tokens = [{token: {id: 'one'}, secret: 'exact-secret'}];
  finish({ok: false, status: 409, body: {partial: true, tokens}}); await pending;
  assert.equal(f.made.length, 1); assert.equal(f.made[0].tokens, tokens);
  assert.equal(f.made[0].requested_count, 3); assert.equal(f.made[0].partial, true);
  assert.match(f.tokenError.textContent, /may already have been created/); assert.equal(f.tokenButton.disabled, false);
  assert.equal(f.calls[0][2].group, 'group-a'); assert.equal(f.calls[0][3], 'control');
});

test('profile uncertain and malformed responses stay visible without disclosure or automatic retry', async () => {
  for (const reply of [new Error('offline'), {ok: false, status: 503},
    {ok: false, status: 409, body: {partial: true, tokens: []}},
    {ok: false, status: 409, body: {partial: true, tokens: [{}]}},
    {ok: true, body: {}}, {ok: true, body: {tokens: []}}]) {
    const f = tokenFixture(); f.context.apiFetch = async (...args) => {
      f.calls.push(args); if (reply instanceof Error) throw reply; return reply;
    };
    await f.send(); assert.equal(f.calls.length, 1); assert.equal(f.made.length, 0);
    assert.match(f.tokenError.textContent, /reload the unused-token list/);
    assert.equal(f.tokenError.style.display, ''); assert.equal(f.tokenButton.disabled, false);
  }
});

test('profile definitive refusal can be retried and success clears the previous error', async () => {
  const f = tokenFixture();
  f.context.apiFetch = async () => ({ok: false, status: 400, body: {error: '<b>invalid request</b>'}});
  await f.send(); assert.equal(f.tokenError.textContent, '<b>invalid request</b>'); assert.equal(f.made.length, 0);
  f.context.apiFetch = async () => ({ok: true, body: {tokens: [{token: {id: 'one'}, secret: 'secret'}]}});
  await f.send(); assert.equal(f.made.length, 1); assert.equal(f.tokenError.style.display, 'none');
});
