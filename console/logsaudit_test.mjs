import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('./logsaudit.js', import.meta.url), 'utf8');
function badge(value) {
  const context = vm.createContext({uiBadge: (label, kind) => ({label, kind})});
  vm.runInContext(source, context);
  context.value = value;
  return vm.runInContext('laResultBadge(value)', context);
}
test('only explicit successful outcomes receive the success color', () => {
  for (const value of ['ok', 'success', 'allow', 'approved', 'done', 'complete', 'completed', ' SUCCESS ']) {
    assert.equal(badge(value).kind, 'ok', value);
  }
});
test('negative and incomplete outcomes cannot be mistaken for success', () => {
  for (const value of ['revoked', 'broken', 'not_ok', 'unsuccessful', 'unapproved', 'incomplete', 'failed', 'denied', 'rejected', 'error', 'failed_to_allow']) {
    assert.notEqual(badge(value).kind, 'ok', value);
  }
  for (const value of ['revoked', 'failed', 'denied', 'rejected', 'error']) {
    assert.equal(badge(value).kind, 'danger', value);
  }
});
test('unrecognized values remain neutral and keep their original text', () => {
  for (const value of ['success_pending', 'allow_requested', 'vendor_result', 'incomplete']) {
    const result = badge(value);
    assert.equal(result.kind, 'off', value);
    assert.equal(result.label, value);
  }
  assert.equal(badge(null).label, '—');
});

test('terminal negative outcomes are distinguishable from pending', () => {
  assert.equal(badge('pending').kind, 'off');
  for (const value of ['expired', 'cancelled', 'canceled', 'withdrawn', 'timeout', 'timed_out']) {
    assert.equal(badge(value).kind, 'danger', value);
  }
});

test('approval outcome does not borrow device trust state', () => {
  const context = vm.createContext({uiBadge: (label, kind) => ({label, kind})});
  vm.runInContext(source, context);
  const columns = vm.runInContext('_LA_COLS.human_approval_events', context);
  const outcome = columns.find(c => c.h.en === 'Outcome');
  const trust = columns.find(c => c.h.en === 'Trust state');
  assert.equal(outcome.c({trust_state: 'trusted'}).label, '—');
  assert.equal(trust.c({trust_state: 'trusted'}), 'trusted');
  assert.equal(outcome.c({outcome: 'denied', trust_state: 'trusted'}).kind, 'danger');
});
