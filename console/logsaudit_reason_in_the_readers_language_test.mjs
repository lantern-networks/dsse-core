import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, readdirSync} from 'node:fs';
import vm from 'node:vm';

// Found on a three-region acceptance (2026-11-06): an allowed row's reason read "Request matched the active lab
// policy." on a Japanese screen — English, and a word from the product's lab days. The server keeps an English
// sentence for logs; the screen says it with the row's reason codes, in the reader's language.
const source = readFileSync(new URL('./logsaudit.js', import.meta.url), 'utf8');
function load(lang) {
  const context = vm.createContext({lang});
  vm.runInContext('function bl(o){return (o && (o[lang] || o.en)) || "";}\n' + source +
    '\n;globalThis.__sentence = laReasonSentence; globalThis.__reason = _LA_REASON;', context);
  return context;
}

test('an allowed row reads in Japanese on a Japanese screen', () => {
  const {__sentence} = load('ja');
  const row = {reason_codes: ['policy_matched', 'application_allowed']};
  assert.equal(__sentence(row, 'Request matched an active allow policy.'), 'ポリシーで許可');
});

test('a row allowed by a completed sign-in reads in Japanese', () => {
  const {__sentence} = load('ja');
  const row = {reason_codes: ['policy_matched', 'authenticate_required', 'authentication_satisfied']};
  assert.equal(__sentence(row, 'Allowed: the interactive authentication this rule requires was completed.'),
    '本人確認が必要・本人確認済み');
});

test('the English screen keeps the server sentence', () => {
  const {__sentence} = load('en');
  const row = {reason_codes: ['policy_matched', 'application_allowed']};
  assert.equal(__sentence(row, 'Request matched an active allow policy.'), 'Request matched an active allow policy.');
});

test('a code without a phrase keeps the server sentence rather than mixing languages', () => {
  const {__sentence} = load('ja');
  assert.equal(__sentence({reason_codes: ['something_new']}, 'Server sentence.'), 'Server sentence.');
});

test('every code the policy decision and the sign-in path write has a phrase in both languages', () => {
  const {__reason} = load('ja');
  const evaluator = readFileSync(new URL('../decision/evaluator.go', import.meta.url), 'utf8');
  const fn = evaluator.slice(evaluator.indexOf('func reasonCodesForPolicyDecision'), evaluator.indexOf('func reasonForPolicyDecision'));
  const codes = new Set([...fn.matchAll(/"([a-z_]+)"/g)].map((m) => m[1]).filter((c) => !['deny', 'require_reauthentication', 'require_workload_attestation', 'delegated_agent', 'nhi'].includes(c)));
  codes.add('authentication_satisfied');
  codes.add('authenticate_required');
  const missing = [...codes].filter((c) => !(__reason[c] && __reason[c].en && __reason[c].ja));
  assert.deepEqual(missing, []);
});

// 2026-11-07, three-region acceptance rerun: the test above reads one function, so the connector-access and
// server-initiated decisions — which return their codes from their own files — were never asked, and a sign-in
// row read in English. This derives every code a decision in the package returns.
test('every code any decision in the decision package returns has a phrase in both languages', () => {
  const {__reason} = load('ja');
  const dir = new URL('../decision/', import.meta.url);
  const codes = new Set();
  for (const name of readdirSync(dir).filter((f) => f.endsWith('.go') && !f.endsWith('_test.go'))) {
    const src = readFileSync(new URL(name, dir), 'utf8');
    for (const m of src.matchAll(/return "[a-z_]+", "[^"]*", \[\]string\{([^}]*)\}/g)) {
      for (const c of m[1].matchAll(/"([a-z_]+)"/g)) codes.add(c[1]);
    }
  }
  assert.ok(codes.size >= 10, 'the scan found almost no codes — it no longer matches how decisions return them');
  const missing = [...codes].filter((c) => !(__reason[c] && __reason[c].en && __reason[c].ja));
  assert.deepEqual(missing, []);
});

test('a connector-access row allowed by a completed sign-in reads in Japanese', () => {
  const {__sentence} = load('ja');
  const row = {reason_codes: ['east_west_authentication_required', 'authentication_satisfied']};
  assert.equal(__sentence(row, 'Allowed: the interactive authentication this rule requires was completed.'),
    'このルールは本人確認を求める・本人確認済み');
});

test('no reason sentence the product writes calls a deployment a lab', () => {
  const evaluator = readFileSync(new URL('../decision/evaluator.go', import.meta.url), 'utf8');
  assert.doesNotMatch(evaluator, /return "[^"]*\blab\b[^"]*"/);
});

// Found 2026-11-08 on acceptance C: the drawer translated the reason and the list row beside it printed the
// server's English sentence.
test('the list row says the reason the way the drawer does', () => {
  const ctx = vm.createContext({lang: 'ja', el: (tag, props, children) => ({tag, ...props, children}), laReasonChip: (c) => c});
  vm.runInContext('function bl(o){return (o && (o[lang] || o.en)) || "";}\n' + source + '\n;globalThis.__cell = laReasonCell;', ctx);
  const row = {reason: 'Allowed: the interactive authentication this rule requires was completed.',
    reason_codes: ['east_west_authentication_required', 'authentication_satisfied']};
  const cell = ctx.__cell(row);
  const text = JSON.stringify(cell);
  assert.match(text, /このルールは本人確認を求める・本人確認済み/);
  assert.doesNotMatch(text, /"text":"Allowed: the interactive/);
});

// Found 2026-11-08 on acceptance C: a related record's summary read "actor_type=human".
test('a related record is summarised in the drawer\'s words', () => {
  const ctx = vm.createContext({lang: 'ja', window: {}});
  vm.runInContext('function bl(o){return (o && (o[lang] || o.en)) || "";}\n' + source + '\n;globalThis.__sum = laRelatedSummary;', ctx);
  const text = ctx.__sum('decision_traces', {actor_type: 'human', decision: 'allow'});
  assert.doesNotMatch(text, /actor_type|=human/);
  assert.match(text, /人/);
});

// Found 2026-11-08 on acceptance C, fourth walk: an allowed row's reason cell was empty while a denied row said
// "ポリシーで拒否" and the allowed row's own drawer said "ポリシーで許可".
test('an allowed row says why, as a denied row does', () => {
  const ctx = vm.createContext({lang: 'ja', el: (tag, props, children) => ({tag, ...props, children}), laReasonChip: (c) => c});
  vm.runInContext('function bl(o){return (o && (o[lang] || o.en)) || "";}\n' + source + '\n;globalThis.__cell = laReasonCell;', ctx);
  const allowed = ctx.__cell({reason: 'Request matched an active allow policy.', reason_codes: ['policy_matched', 'application_allowed']});
  assert.match(JSON.stringify(allowed), /ポリシーで許可/);
  const denied = ctx.__cell({reason: 'Request matched an active deny policy.', reason_codes: ['policy_matched', 'application_denied']});
  assert.match(JSON.stringify(denied), /ポリシーで拒否/);
  assert.doesNotMatch(JSON.stringify(denied), /ポリシーで許可/);
});

test('an allowed row that names its rule still says the generic reason (acceptance D, 2026-11-09)', () => {
  const ctx = vm.createContext({lang: 'ja', el: (tag, props, children) => ({tag, ...props, children}), laReasonChip: (c) => c});
  vm.runInContext('function bl(o){return (o && (o[lang] || o.en)) || "";}\n' + source + '\n;globalThis.__cell = laReasonCell;', ctx);
  const allowed = ctx.__cell({reason: 'Request matched an active allow policy.', policy_id: 'pol_allow_7', reason_codes: ['policy_matched', 'application_allowed']});
  const text = JSON.stringify(allowed);
  assert.ok(text.includes('pol_allow_7'), 'the rule id stays: ' + text);
  assert.ok(text.includes('ポリシーで許可') || text.includes('application_allowed'), 'the row still says why it was allowed: ' + text);
});
