import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('./administrators.js', import.meta.url), 'utf8');

function handover(writeText) {
  const messages = [];
  let modal;
  const context = vm.createContext({
    navigator: {clipboard: {writeText}}, bl: value => value.en,
    el: (tag, attrs = {}, children) => ({tag, ...attrs, children}),
    uiToast: (...args) => messages.push(args),
    uiModal: options => { modal = options; return {close() {}}; },
  });
  vm.runInContext(source, context);
  vm.runInContext(`openInvitationHandover({subject:'Synthetic invitation',
    body:'Give this synthetic message to the test recipient.',
    link:'https://example.invalid/synthetic-invitation'})`, context);
  return {messages, buttons: modal.footer};
}

for (const [button, expected] of [
  ['Copy message', 'Subject: Synthetic invitation\n\nGive this synthetic message to the test recipient.'],
  ['Copy link only', 'https://example.invalid/synthetic-invitation'],
]) {
  test(`${button} reports success only after the clipboard write succeeds`, async () => {
    let finish;
    const written = [];
    const fixture = handover(text => {
      written.push(text);
      return new Promise(resolve => { finish = resolve; });
    });
    const pending = fixture.buttons.find(b => b.text === button).onClick();
    assert.deepEqual(written, [expected]);
    assert.deepEqual(fixture.messages, []);
    finish();
    await pending;
    assert.deepEqual(fixture.messages, [['Copied.', 'ok']]);
  });

  test(`${button} handles clipboard rejection without claiming success`, async () => {
    const rejection = Promise.reject(new Error('synthetic permission denial'));
    rejection.catch(() => {}); // Keep old-code reproduction focused on its incorrect feedback.
    const fixture = handover(() => rejection);
    await fixture.buttons.find(b => b.text === button).onClick();
    assert.equal(fixture.messages.length, 1);
    assert.equal(fixture.messages[0][1], 'err');
    assert.match(fixture.messages[0][0], /copy.*message/i);
  });
}
