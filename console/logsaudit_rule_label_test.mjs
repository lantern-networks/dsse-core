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

function ruleNameContext(rules) {
  const context = vm.createContext({
    bl: value => value.en,
    el: (_tag, props, children) => ({props, children}),
    apiFetch: async (method, path) => {
      assert.equal(method + ' ' + path, 'GET /admin/rules');
      return {ok: true, body: rules};
    },
  });
  vm.runInContext(script, context);
  return context;
}

test('a log row names the deciding rule the way the administrator named it', async () => {
  const context = ruleNameContext([
    {id: 'rule-4', name: 'Short'},
    {id: 'rule-45', name: 'Block example.org'},
    {id: 'rule-9'},
  ]);
  // Before the rules are read, and for anything they do not name, the recorded id stays.
  assert.equal(context.laRuleLabel('rule-egress-rule-45-any'), 'rule-egress-rule-45-any');
  await vm.runInContext('laLoadRuleNames().then((n) => { _laRuleNames = n; })', context);
  assert.equal(context.laRuleLabel('rule-egress-rule-45-any'), 'Block example.org');
  assert.equal(context.laRuleLabel('rule-egress-rule-45-0-fqdn-s1-tcp'), 'Block example.org');
  assert.equal(context.laRuleLabel('rule-egress-rule-4-nomatch-udp'), 'Short');
  assert.equal(context.laRuleLabel('rule-45'), 'Block example.org');
  assert.equal(context.laRuleLabel('rule-egress-rule-9-any'), 'rule-9');
  assert.equal(context.laRuleLabel('rule-egress-rule-77-any'), 'rule-egress-rule-77-any');
  // Not something the compiler writes after a rule id: no name is guessed.
  assert.equal(context.laRuleLabel('rule-egress-rule-45'), 'rule-egress-rule-45');
  assert.equal(context.laRuleLabel('rule-egress-rule-45-other'), 'rule-egress-rule-45-other');
  assert.equal(context.laRuleLabel('east_west_policy'), 'Connector-access rules');
});

test('a rule id that ends like a compiled suffix does not take another rule\'s row', async () => {
  // "rule-4" compiles its first FQDN destination to rule-egress-rule-4-0-fqdn. "rule-4-0" never compiles to that.
  const context = ruleNameContext([
    {id: 'rule-4', name: 'Deny the site'},
    {id: 'rule-4-0', name: 'Allow everything'},
  ]);
  await vm.runInContext('laLoadRuleNames().then((n) => { _laRuleNames = n; })', context);
  assert.equal(context.laRuleLabel('rule-egress-rule-4-0-fqdn'), 'Deny the site');
  assert.equal(context.laRuleLabel('rule-egress-rule-4-0-any'), 'Allow everything');
  assert.equal(context.laRuleLabel('rule-egress-rule-4-any'), 'Deny the site');
});

test('an id two rules could both have produced names neither', async () => {
  // rule-4's first FQDN destination over the transport "any", or rule-4-0-fqdn's catch-all: the id cannot say.
  const context = ruleNameContext([
    {id: 'rule-4', name: 'Deny the site'},
    {id: 'rule-4-0-fqdn', name: 'Allow everything'},
  ]);
  await vm.runInContext('laLoadRuleNames().then((n) => { _laRuleNames = n; })', context);
  assert.equal(context.laRuleLabel('rule-egress-rule-4-0-fqdn-any'), 'rule-egress-rule-4-0-fqdn-any');
});
