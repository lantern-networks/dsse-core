import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

// Found 2026-11-07 on the three-region acceptance rerun: a rule saved in one tab left another tab's list reading
// "no rules yet" until it was reloaded. This runs the code that announces a write and the code that catches up.
const app = readFileSync(new URL('./app.js', import.meta.url), 'utf8');

test('every successful write is announced, with the organization it was made in', () => {
  const fn = app.slice(app.indexOf('async function apiFetch('), app.indexOf('\n}\n', app.indexOf('async function apiFetch(')));
  assert.match(fn, /const answer = \{ status: res\.status, ok: res\.ok, body: parsed \};\n  if \(method !== "GET" && res\.ok\) announceWriteToOtherTabs\(actingTenant\);/);
});

function scene({ tenantHere, visible, modalOpen }) {
  const start = app.indexOf('// What another tab wrote reaches this one');
  const end = app.indexOf('\n}\n', app.indexOf('function catchUpWithOtherTabs()')) + 3;
  assert.ok(start > 0 && end > start, 'the cross-tab code is not where this test looks for it');
  const listeners = { window: {}, document: {} };
  const rendered = [];
  const inserted = [];
  const content = { contains: (t) => !!(t && t.inContent), parentNode: { insertBefore: (bar) => inserted.push(bar) } };
  const document = {
    visibilityState: visible ? 'visible' : 'hidden',
    addEventListener: (type, fn) => { listeners.document[type] = fn; },
    getElementById: (id) => (id === 'content' ? content : null),
    querySelector: (sel) => (sel === '.ui-modal-backdrop' ? (modalOpen ? {} : null) : { dataset: { group: 'rules' } }),
  };
  const ctx = {
    document, operateTenant: tenantHere, otherTabWrotePending: false, editedSinceDrawn: false, banner: 0,
    WRITE_ANNOUNCED_KEY: 'dsse.consoleWriteAnnounced',
    window: { addEventListener: (type, fn) => { listeners.window[type] = fn; } },
    localStorage: { setItem: () => {} },
    refreshModeBanner: () => { ctx.banner++; },
    renderGroup: (g) => rendered.push(g),
    el: (tag, attrs) => ({ tag, attrs }),
    bl: (m) => m.en,
  };
  vm.runInNewContext(app.slice(start, end), ctx);
  const wrote = (tenant) => listeners.window.storage({ key: 'dsse.consoleWriteAnnounced', newValue: JSON.stringify({ tenant, at: 1 }) });
  // An element as the listeners see it: where it is, and what it is inside.
  const node = ({ inContent = false, inModal = false, isButton = false } = {}) => ({
    inContent,
    closest: (sel) => (sel === '.ui-modal-backdrop' ? (inModal ? {} : null) : sel === 'button' ? (isButton ? {} : null) : null),
  });
  return { ctx, listeners, rendered, inserted, document, wrote, node };
}

test('a visible tab in the same organization, with nothing typed, draws its screen again', () => {
  const s = scene({ tenantHere: 'tenant_b2', visible: true });
  s.wrote('tenant_b2');
  assert.deepEqual(s.rendered, ['rules']);
  assert.equal(s.ctx.banner, 1);
});

test('a hidden tab waits until it is looked at', () => {
  const s = scene({ tenantHere: 'tenant_b2', visible: false });
  s.wrote('tenant_b2');
  assert.deepEqual(s.rendered, []);
  s.document.visibilityState = 'visible';
  s.listeners.document.visibilitychange();
  assert.deepEqual(s.rendered, ['rules']);
});

test('a screen with something typed into it is offered the redraw instead of losing it', () => {
  const s = scene({ tenantHere: 'tenant_b2', visible: true });
  s.listeners.document.input({ target: s.node({ inContent: true }) });
  s.wrote('tenant_b2');
  assert.deepEqual(s.rendered, []);
  assert.equal(s.inserted.length, 1);
});

// Review of 2026-11-07, R4: a form in a modal is not inside #content, and a form changed by buttons fires no
// input event. Both are work in progress.
test('typing into a modal, pressing a button in the screen, or an open modal all hold the redraw', () => {
  const typedInModal = scene({ tenantHere: 'tenant_b2', visible: true });
  typedInModal.listeners.document.input({ target: typedInModal.node({ inModal: true }) });
  typedInModal.wrote('tenant_b2');
  assert.deepEqual(typedInModal.rendered, [], 'a name being typed into "Edit site" was thrown away');

  const reordered = scene({ tenantHere: 'tenant_b2', visible: true });
  reordered.listeners.document.click({ target: reordered.node({ inContent: true, isButton: true }) });
  reordered.wrote('tenant_b2');
  assert.deepEqual(reordered.rendered, [], 'an entrance order changed with ↑↓ was thrown away');

  const modalOpen = scene({ tenantHere: 'tenant_b2', visible: true, modalOpen: true });
  modalOpen.wrote('tenant_b2');
  assert.deepEqual(modalOpen.rendered, [], 'a screen with a modal open was redrawn under it');
  assert.equal(modalOpen.inserted.length, 1);

  // A click that is not a button, outside the screen, is not work.
  const idle = scene({ tenantHere: 'tenant_b2', visible: true });
  idle.listeners.document.click({ target: idle.node() });
  idle.wrote('tenant_b2');
  assert.deepEqual(idle.rendered, ['rules']);
});

test('a write in another organization leaves this tab alone', () => {
  const s = scene({ tenantHere: 'tenant_b2', visible: true });
  s.wrote('tenant_other');
  assert.deepEqual(s.rendered, []);
  assert.equal(s.ctx.banner, 0);
});
