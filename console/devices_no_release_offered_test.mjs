import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';

// Found on a Windows acceptance (2026-11-12): a deployment that publishes no agent release showed
// "no update report 1" for as long as it ran. A device can only be silent about something it was offered.
const source = readFileSync(new URL('./devices.js', import.meta.url), 'utf8');
const start = source.indexOf('function applyUpdateState');
const end = source.indexOf('\n}\n', start) + 3;
const context = vm.createContext({});
vm.runInContext('function bl(o){return o.en;}\n' + source.slice(start, end) + '\nglobalThis.__apply = applyUpdateState;', context);
const apply = (state, offered) => { const st = {signals: []}; context.__apply(st, {state}, offered); return st; };

test('a silent device is counted while a release is being offered', () => {
  assert.equal(apply('never_reported', true).updateChip, 'never_reported');
});

test('a silent device is not counted when nothing is offered', () => {
  assert.equal(apply('never_reported', false).updateChip, undefined);
});

test('a device that failed or refused is shown whether or not anything is offered now', () => {
  assert.equal(apply('failed', false).updateChip, 'failed');
  assert.equal(apply('refused', false).updateChip, 'refused');
});

test('the screen tells the function whether anything is offered', () => {
  assert.match(source, /applyUpdateState\(st, updates\[d\.identity\], Object\.keys\(updateOffering\)\.length > 0 \|\| !!updateFrozen\)/);
});
