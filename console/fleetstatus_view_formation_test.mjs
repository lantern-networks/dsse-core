import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';

const source = readFileSync(new URL('./fleetstatus.js', import.meta.url), 'utf8');

function fixture() {
  function el(tag, attrs = {}, children = []) {
    const node = { tag, ...attrs, children: [], appendChild(child) {
      if (child) this.children.push(child);
      return child;
    } };
    Object.defineProperty(node, 'textContent', {
      get() { return String(this.text ?? '') + this.children.map(child => child.textContent ?? child.text ?? '').join(''); },
      set(value) { node.text = value; node.children = []; },
    });
    Object.defineProperty(node, 'innerHTML', { set(value) { assert.equal(value, ''); node.children = []; } });
    for (const child of Array.isArray(children) ? children : [children]) node.appendChild(child);
    return node;
  }
  const c = vm.createContext({
    el, bl: text => text.en, ovEmpty: text => el('div', { text }),
    uiBadge: (text, tone) => el('span', { text, tone }),
    document: { createTextNode: text => ({ textContent: text }) },
  });
  vm.runInContext(source, c);
  return { c, el };
}

const fleet = formed => ({ ok: true, status: 200, body: {
  fleet_view_formed: formed, in_sync: formed,
  edges: [{ region_id: 'region-a', status: 'current', rule_count: 3 }],
} });

test('forming fleet does not claim every Edge or a green complete view', async () => {
  const { c, el } = fixture(), host = el('div');
  let more = '';
  await c.ovLoadFleetConfig(host, value => { more = value; }, Promise.resolve(fleet(false)));
  assert.match(more, /forming|not yet complete/i);
  assert.doesNotMatch(more, /all 1 in effect|0 of 1 behind/i);
  assert.match(host.textContent, /forming|not yet complete/i);
  const chip = c.fleetStripChip(fleet(false));
  assert.match(chip.textContent, /forming|not yet complete/i);
  assert.ok(chip.children.some(child => /ov-dot-warn/.test(child.class ?? '')));
});

test('formed fleet still reports all current Edges normally', async () => {
  const { c, el } = fixture(), host = el('div');
  let more = '';
  await c.ovLoadFleetConfig(host, value => { more = value; }, Promise.resolve(fleet(true)));
  assert.equal(more, 'all 1 in effect');
  const chip = c.fleetStripChip(fleet(true));
  assert.ok(chip.children.some(child => /ov-dot-ok/.test(child.class ?? '')));
});

test('fleet grouping handles region and status names that are JavaScript object keys', () => {
  const { c } = fixture();
  const rows = [
    { region_id: '__proto__', status: 'current', rule_count: 1 },
    { region_id: 'constructor', status: 'constructor', rule_count: 1 },
  ];
  const rollup = c.fleetRollup({ edges: rows });
  assert.equal(rollup.regions.length, 2);
  assert.equal(rollup.regions.reduce((count, region) => count + region.all.length, 0), 2);
  assert.equal(c.fleetByState(rows).length, 2);
});
