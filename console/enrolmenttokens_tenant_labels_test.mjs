import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';

const source = readFileSync(new URL('./enrolmenttokens.js', import.meta.url), 'utf8');

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return {promise, resolve};
}

function node(props = {}, children = []) {
  return { ...props, children: Array.isArray(children) ? children : [children],
    appendChild(child) { this.children.push(child); }, innerHTML: '' };
}

test('enrolment approver labels stay with the tenant response during overlapping reads', async () => {
  const firstAdmins = deferred();
  const secondTokens = deferred();
  let tenant = 'first';
  const context = vm.createContext({
    bl: words => words.en,
    uiState() {}, freshRender: () => () => true,
    el: (_tag, props, children) => node(props, children),
    uiBadge: text => node({text}),
    window: {dsseFormatTime: value => value},
    apiFetch: async (_method, path) => {
      const calledFor = tenant;
      if (path === '/admin/admins') {
        if (calledFor === 'first') return firstAdmins.promise;
        return {ok: true, body: {admins: [{principal_id: 'same-id', email: 'second@example.test'}]}};
      }
      if (path === '/admin/enrolment-tokens') {
        if (calledFor === 'second') return secondTokens.promise;
        return {ok: true, body: {tokens: [{id: 'first-token', label: 'first device', issued_by: 'same-id'}]}};
      }
      throw new Error('unexpected API call: ' + path);
    },
  });
  vm.runInContext(source, context);
  const firstHost = node();
  const secondHost = node();
  const firstRender = context.renderEnrolTokenList(firstHost);
  tenant = 'second';
  const secondRender = context.renderEnrolTokenList(secondHost);
  await Promise.resolve();
  firstAdmins.resolve({ok: true, body: {admins: [{principal_id: 'same-id', email: 'first@example.test'}]}});
  await Promise.resolve();
  secondTokens.resolve({ok: true, body: {tokens: [{id: 'second-token', label: 'second device', issued_by: 'same-id'}]}});
  await Promise.all([firstRender, secondRender]);
  const rendered = JSON.stringify(secondHost);
  assert.match(rendered, /second@example\.test/);
  assert.doesNotMatch(rendered, /first@example\.test/);
});
