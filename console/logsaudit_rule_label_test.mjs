import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';

const script = readFileSync(new URL('./logsaudit.js', import.meta.url), 'utf8');

for (const [language, expected] of [['en', 'Changed Access rule'], ['ja', '変更 アクセスルール']]) {
  test(`admin rule audit label is accurate for both rule planes (${language})`, () => {
    const context = vm.createContext({
      bl: value => value[language],
      el: (_tag, props, children) => ({props, children}),
    });
    vm.runInContext(script, context);
    const cell = context.laAuditActionCell({
      event_type: 'admin_config_change',
      action: 'POST',
      target_id: '/admin/rules',
      metadata: {method: 'POST', path: '/admin/rules'},
    });
    assert.equal(cell.children[0].props.text, expected);
    assert.equal(cell.props.title, 'POST /admin/rules');
  });
}

test('the DLP policy audit label remains specific', () => {
  const context = vm.createContext({bl: value => value.en, el: (_tag, props, children) => ({props, children})});
  vm.runInContext(script, context);
  const cell = context.laAuditActionCell({
    event_type: 'admin_config_change',
    metadata: {method: 'POST', path: '/admin/dlp-policies'},
  });
  assert.equal(cell.children[0].props.text, 'Changed DLP policy');
});
