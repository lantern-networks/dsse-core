import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

// 0.4.1 acceptance B: turning the mouse wheel over a site's expected connector count changed it from 1 to 0.
// The answer is one listener for every number field in the Console; this runs that listener.
const app = readFileSync(new URL('./app.js', import.meta.url), 'utf8');
const start = app.indexOf('document.addEventListener("wheel", ');
const end = app.indexOf('}, { passive: true });', start);

function runWheel(target, active) {
  assert.ok(start >= 0 && end > start, 'the wheel listener is not in app.js');
  let handler = null;
  let options = null;
  const document = {
    activeElement: active,
    addEventListener: (type, fn, opts) => { if (type === 'wheel') { handler = fn; options = opts; } },
  };
  vm.runInNewContext(app.slice(start, end + '}, { passive: true });'.length), { document });
  assert.ok(handler, 'no wheel listener was registered');
  assert.equal(options && options.passive, true, 'the listener must not hold up scrolling');
  handler({ target });
}

test('a focused number field lets go under the wheel instead of changing', () => {
  let blurred = false;
  const field = { tagName: 'INPUT', type: 'number', blur: () => { blurred = true; } };
  runWheel(field, field);
  assert.equal(blurred, true);
});

test('other fields, and a number field without focus, are left alone', () => {
  let blurred = false;
  const text = { tagName: 'INPUT', type: 'text', blur: () => { blurred = true; } };
  runWheel(text, text);
  const number = { tagName: 'INPUT', type: 'number', blur: () => { blurred = true; } };
  runWheel(number, null);
  assert.equal(blurred, false);
});
