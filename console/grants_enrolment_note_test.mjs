import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

// The access-approval screen reads the enrolment record in the reader's language, for every sentence the
// Edge writes into the ledger; a note an administrator typed is shown as typed.
const source = readFileSync(new URL('./grants.js', import.meta.url), 'utf8');
function noteIn(lang, note) {
  const context = vm.createContext({bl: (b) => b[lang], el: () => ({}), document: {}, window: {}});
  vm.runInContext(source, context);
  context.note = note;
  return vm.runInContext('enrolmentNoteText(note)', context);
}

test('the four sentences the Edge writes read in Japanese', () => {
  assert.equal(noteIn('ja', 'enrolled with a token issued by admin@example.test'), 'admin@example.test が発行したトークンで登録');
  assert.equal(noteIn('ja', 'enrolled via IdP login by user@example.test (issuer https://idp.example.test/realms/x)'),
    'user@example.test のサインインで登録（https://idp.example.test/realms/x）');
  assert.equal(noteIn('ja', 'enrolled as a connector for site hq'), 'サイト hq のコネクタとして登録');
  assert.equal(noteIn('ja', 'enrolled via POST /enroll'), '登録（承認した人の記録なし）');
  for (const ja of [noteIn('ja', 'enrolled with a token issued by a'), noteIn('ja', 'enrolled via POST /enroll')]) {
    assert.doesNotMatch(ja, /enrolled|POST/);
  }
});

test('a typed note is shown as typed', () => {
  assert.equal(noteIn('ja', '経理のノート PC'), '経理のノート PC');
  assert.equal(noteIn('en', 'Finance laptop'), 'Finance laptop');
});

// The shapes are read from the Edge's own source, so a reworded sentence there fails here instead of falling
// back to English on the screen.
test('the Edge still writes the sentences this screen reads', () => {
  const edge = (f) => readFileSync(new URL('../cmd/dsse-edge/' + f, import.meta.url), 'utf8');
  assert.match(edge('enroll_endpoint.go'), /"enrolled with a token issued by "\+enrolmentIssuerText\(tok\)/);
  assert.match(edge('enroll_endpoint.go'), /note := "enrolled via POST \/enroll"/);
  assert.match(edge('enroll_eligibility_idp.go'), /"enrolled via IdP login by %s \(issuer %s\)"/);
  assert.match(edge('connector_enrolment_identity.go'), /"enrolled as a connector for site " \+ strings\.TrimSpace\(site\)/);
});

test('the screen uses it where the note is shown', () => {
  assert.match(source, /text: enrolmentNoteText\(humanNote\)/);
});

test('the issuer is named, not its account id (2026-11-06)', () => {
  assert.equal(noteIn('ja', 'enrolled with a token issued by admin@example.test (adm_7f154644e80ef44f4ef65fb296ebda8e)'),
    'admin@example.test が発行したトークンで登録');
  assert.equal(noteIn('en', 'enrolled with a token issued by admin@example.test (adm_7f15)'),
    'Enrolled with a token issued by admin@example.test');
  // A record written before the label was used still reads.
  assert.equal(noteIn('ja', 'enrolled with a token issued by adm_7f15'), 'adm_7f15 が発行したトークンで登録');
});
