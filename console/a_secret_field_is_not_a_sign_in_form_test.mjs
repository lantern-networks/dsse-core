import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

// Found 2026-11-08 on acceptance C: registering an identity provider, the browser's password manager filled the
// administrator's own e-mail address into "Client ID" and their own password into "Client secret". A password
// field after a text field reads as a sign-in form. Every password-type field in these forms is a secret that
// belongs to something else, and is marked so.
const ui = readFileSync(new URL('./ui.js', import.meta.url), 'utf8');

function fakeDocument() {
  const make = (tag) => {
    const node = {tag, attrs: {}, children: [], classList: {add() {}, remove() {}}, value: '', checked: false,
      setAttribute(k, v) { this.attrs[k] = String(v); }, getAttribute(k) { return this.attrs[k]; },
      appendChild(c) { this.children.push(c); return c; }, addEventListener() {}, set textContent(v) {}, set className(v) {}};
    return node;
  };
  return {createElement: make, createTextNode: (t) => ({text: t}), querySelector: () => null, body: make('body')};
}

function field(spec) {
  const ctx = vm.createContext({document: fakeDocument(), performance: {now: () => 1}, setTimeout() {}});
  vm.runInContext(ui + '\nglobalThis.__field = uiField;', ctx);
  const f = ctx.__field(spec);
  return f.el.children.find((c) => c && (c.tag === 'input' || c.tag === 'textarea'));
}

test('a secret is never offered the saved sign-in', () => {
  assert.equal(field({name: 'secret', type: 'password'}).attrs.autocomplete, 'new-password');
});

test('the text field before it is not taken for a user name', () => {
  assert.equal(field({name: 'client'}).attrs.autocomplete, 'off');
  assert.equal(field({name: 'notes', type: 'textarea'}).attrs.autocomplete, 'off');
});

test('a field that wants the browser to help can still say so', () => {
  assert.equal(field({name: 'email', type: 'email', autocomplete: 'email'}).attrs.autocomplete, 'email');
});
