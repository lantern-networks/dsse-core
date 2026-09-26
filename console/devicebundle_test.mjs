import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';

const bundleSource = readFileSync(new URL('./devicebundle.js', import.meta.url), 'utf8');
const tokenSource = readFileSync(new URL('./enrolmenttokens.js', import.meta.url), 'utf8');
const secret = 'synthetic-one-time-secret';
const tokenID = 'token/one';
const envelope = {type: 'install_profile', payload_b64: 'synthetic-payload'};
const installerBytes = Uint8Array.of(0, 1, 128, 255, 10);
const completeReply = () => ({ok: true, status: 200,
  body: {tokens: [{token: {id: tokenID}, secret}]}});
const revokedReply = (note = '') => ({ok: true, status: 200, body: {note,
  token: {id: tokenID, revoked_at: '2026-09-15T05:00:00Z', used_at: note ? '2026-09-15T04:00:00Z' : ''}}});
const response = (status = 200, bytes = installerBytes) => ({
  ok: status >= 200 && status < 300, status,
  arrayBuffer: async () => bytes.slice().buffer,
});

function fixture() {
  const calls = [], notices = [], blobs = [], downloads = [], timers = [], revokedURLs = [], disclosures = [];
  function el(tag, attrs = {}, children = []) {
    let text = attrs.text || '';
    const node = {tag, ...attrs, style: {}, children: [], listeners: {}, attributes: {}, disabled: false,
      appendChild(child) { if (child) { this.children.push(child); child.parentNode = this; } return child; },
      addEventListener(name, handler) { this.listeners[name] = handler; },
      setAttribute(name, value) { this.attributes[name] = value; },
      querySelector(selector) { return this.querySelectorAll(selector)[0] || null; },
      querySelectorAll(selector) {
        const match = candidate => selector.startsWith('[')
          ? Object.hasOwn(candidate.attributes, selector.slice(1, -1)) : candidate.tag === selector;
        return this.children.flatMap(child => [child, ...child.querySelectorAll('*')])
          .filter(candidate => selector === '*' || match(candidate));
      },
      remove() {
        if (this.parentNode) this.parentNode.children = this.parentNode.children.filter(child => child !== this);
        this.parentNode = null;
      },
      click() { if (tag === 'a') downloads.push({name: this.download, url: this.href}); return this.listeners.click?.(); },
    };
    Object.defineProperty(node, 'textContent', {
      get() { return text + this.children.map(child => child.textContent).join(''); },
      set(value) { text = String(value); this.children = []; },
    });
    Object.defineProperty(node, 'innerHTML', {set(value) { assert.equal(value, ''); node.textContent = ''; }});
    for (const child of children) node.appendChild(child);
    return node;
  }
  const body = el('body'), host = el('div'), button = el('button', {text: 'Download everything for one device'});
  host.appendChild(button);
  const context = vm.createContext({Blob, TextEncoder, Uint8Array, el, bl: value => value.en,
    profileSigningKeyOf: () => 'fixture-signing-key',
    uiToast: (message, kind) => notices.push({message, kind}),
    baseForPlane: plane => { assert.equal(plane, 'control'); return '/control'; },
    idpSession: {auth_method: 'admin_session', csrf_token: 'fixture-csrf'}, operateTenant: 'fixture-tenant',
    localStorage: {getItem: () => 'fixture-bearer'},
    fetch: async (...args) => { calls.push(['GET', ...args]); return response(); },
    apiFetch: async (...args) => { calls.push(args); return completeReply(); },
    document: {body, createElement: tag => el(tag)},
    URL: {createObjectURL: blob => { blobs.push(blob); return 'blob:bundle-' + blobs.length; },
      revokeObjectURL: url => revokedURLs.push(url)},
    setTimeout: (handler, ms) => { timers.push({handler, ms}); },
  });
  vm.runInContext('const _PROFILE_PLANE = "control";', context);
  vm.runInContext(tokenSource, context);
  vm.runInContext(bundleSource, context);
  context.showEnrolTokenOnce = body => disclosures.push(body);
  const send = (platform = 'darwin', arch = 'arm64') => context.downloadDeviceBundle(envelope, 'fixture-group', platform, arch, button);
  return {context, calls, notices, blobs, downloads, timers, revokedURLs, disclosures, host, button, send,
    fallback: () => host.querySelector('[data-bundle-approval]')};
}

// Independent bit-at-a-time CRC oracle; ZIP parser also cross-checks central records and local offsets.
function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}
async function unzipStored(blob) {
  const bytes = Buffer.from(await blob.arrayBuffer());
  const entries = new Map(), locations = new Map();
  let pos = 0;
  while (bytes.readUInt32LE(pos) === 0x04034b50) {
    const start = pos, size = bytes.readUInt32LE(pos + 18), nameLength = bytes.readUInt16LE(pos + 26);
    assert.equal(bytes.readUInt16LE(pos + 8), 0, 'stored method');
    assert.equal(bytes.readUInt32LE(pos + 22), size);
    const name = bytes.subarray(pos + 30, pos + 30 + nameLength).toString('utf8');
    pos += 30 + nameLength + bytes.readUInt16LE(pos + 28);
    const content = bytes.subarray(pos, pos + size);
    assert.equal(bytes.readUInt32LE(start + 14), crc32(content), 'entry CRC');
    assert.equal(entries.has(name), false, 'duplicate entry');
    entries.set(name, content); locations.set(name, start); pos += size;
  }
  const directoryStart = pos; let count = 0;
  while (bytes.readUInt32LE(pos) === 0x02014b50) {
    const nameLength = bytes.readUInt16LE(pos + 28);
    const name = bytes.subarray(pos + 46, pos + 46 + nameLength).toString('utf8');
    assert.equal(bytes.readUInt32LE(pos + 42), locations.get(name));
    assert.equal(bytes.readUInt32LE(pos + 16), crc32(entries.get(name)));
    assert.equal(bytes.readUInt32LE(pos + 20), entries.get(name).length);
    pos += 46 + nameLength + bytes.readUInt16LE(pos + 30) + bytes.readUInt16LE(pos + 32); count++;
  }
  assert.equal(bytes.readUInt32LE(pos), 0x06054b50);
  assert.equal(bytes.readUInt16LE(pos + 10), count); assert.equal(count, entries.size);
  assert.equal(bytes.readUInt32LE(pos + 16), directoryStart);
  assert.equal(bytes.readUInt32LE(pos + 12), pos - directoryStart);
  assert.equal(pos + 22, bytes.length);
  return entries;
}

function controlRevoke(call) {
  assert.equal(call[0], 'POST');
  assert.equal(call[1], '/admin/enrolment-tokens/token%2Fone/revoke');
  assert.equal(call[3], 'control');
}

function fallbackButton(f, label) {
  return f.fallback().querySelectorAll('button').find(button => button.textContent === label);
}

test('installer retrieval preserves credentials and tenant, refuses redirects, and returns exact bytes', async () => {
  const f = fixture();
  assert.deepEqual(Array.from(await f.context.dbFetchInstaller('darwin', 'arm64')), Array.from(installerBytes));
  const [, url, options] = f.calls[0];
  assert.equal(url, '/control/admin/agent-update-artifact?platform=darwin&arch=arm64');
  assert.equal(options.credentials, 'include'); assert.equal(options.redirect, 'error');
  assert.equal(options.headers['x-operate-tenant'], 'fixture-tenant');
  assert.equal(options.headers.authorization, undefined);
  f.context.idpSession = null; await f.context.dbFetchInstaller('windows', 'amd64');
  assert.equal(f.calls[1][2].headers.authorization, 'Bearer fixture-bearer');
});

test('only a 404 is an absent installer; other HTTP and transport failures reject', async () => {
  const f = fixture(); f.context.fetch = async () => response(404);
  assert.equal(await f.context.dbFetchInstaller('darwin', 'arm64'), null);
  for (const status of [401, 403, 429, 500, 503]) {
    f.context.fetch = async () => response(status);
    await assert.rejects(f.context.dbFetchInstaller('darwin', 'arm64'));
  }
  for (const failure of [new Error('offline'), new Error('redirect refused')]) {
    f.context.fetch = async () => { throw failure; };
    await assert.rejects(f.context.dbFetchInstaller('darwin', 'arm64'));
  }
  f.context.fetch = async () => response(200, new Uint8Array());
  await assert.rejects(f.context.dbFetchInstaller('darwin', 'arm64'));
  f.context.fetch = async () => ({...response(), arrayBuffer: async () => { throw Error('body interrupted'); }});
  await assert.rejects(f.context.dbFetchInstaller('darwin', 'arm64'));
});

test('missing profile signing key refuses bundle preparation before any network request', async () => {
  const f = fixture(); f.context.profileSigningKeyOf = () => '';
  await f.send(); assert.equal(f.calls.length, 0); assert.equal(f.blobs.length, 0);
  assert.equal(f.fallback(), null); assert.equal(f.button.disabled, false);
  assert.ok(f.notices.some(notice => notice.kind === 'err'));
});

test('installer failure happens before issuance, leaves no approval, and can be retried', async () => {
  for (const failure of [401, 403, 500, new Error('offline')]) {
    const f = fixture(); f.context.fetch = async (...args) => {
      f.calls.push(['GET', ...args]); if (failure instanceof Error) throw failure; return response(failure);
    };
    await f.send();
    assert.equal(f.calls.length, 1); assert.equal(f.calls[0][0], 'GET');
    assert.equal(f.blobs.length, 0); assert.equal(f.fallback(), null); assert.equal(f.button.disabled, false);
    assert.ok(f.notices.some(notice => notice.kind === 'err'));
    f.context.fetch = async (...args) => { f.calls.push(['GET', ...args]); return response(); };
    await f.send(); assert.equal(f.calls.filter(call => call[0] === 'POST').length, 1);
    assert.equal(f.downloads.length, 1);
  }
});

test('pending guard survives an externally reenabled button without duplicate issuance', async () => {
  const f = fixture(); let finish;
  f.context.fetch = (...args) => { f.calls.push(['GET', ...args]); return new Promise(resolve => { finish = resolve; }); };
  const pending = f.send(); assert.equal(f.button.disabled, true);
  f.button.disabled = false;
  await f.send('windows', 'amd64'); assert.equal(f.calls.length, 1);
  finish(response()); await pending;
  assert.equal(f.calls.length, 2); assert.equal(f.calls[1][0], 'POST');
  assert.equal(f.downloads[0].name, 'dsse-device-setup-darwin-arm64.zip');
  assert.equal(f.button.disabled, false);
  f.context.fetch = async (...args) => { f.calls.push(['GET', ...args]); return response(); };
  await f.send('windows', 'amd64'); assert.equal(f.calls.filter(call => call[0] === 'POST').length, 2);
  assert.equal(f.downloads[1].name, 'dsse-device-setup-windows-amd64.zip');
});

test('all supported platforms produce exact ZIP contents and fetch the installer before one token', async () => {
  for (const platform of ['darwin', 'windows']) for (const arch of ['arm64', 'amd64']) {
    const f = fixture(); await f.send(platform, arch);
    assert.deepEqual(f.calls.map(call => call[0]), ['GET', 'POST']);
    assert.equal(f.calls[1][1], '/admin/enrolment-tokens'); assert.equal(f.calls[1][3], 'control');
    assert.equal(f.calls[1][2].count, 1); assert.equal(f.calls[1][2].group, 'fixture-group');
    assert.equal(f.calls[1][2].expires_in_hours, 168);
    const entries = await unzipStored(f.blobs[0]);
    const installerName = `dsse-agent-${platform}-${arch}.${platform === 'windows' ? 'msi' : 'pkg'}`;
    assert.equal(entries.size, 5); assert.deepEqual(entries.get(installerName), Buffer.from(installerBytes));
    assert.equal(entries.get('install_profile.json').toString(), JSON.stringify(envelope, null, 2) + '\n');
    assert.equal(entries.get('profile_signing_key.txt').toString(), 'fixture-signing-key\n');
    assert.equal(entries.get('enrolment_token.txt').toString(), secret + '\n');
    assert.ok(entries.get('README.txt').toString().includes(installerName));
    assert.equal(f.downloads[0].name, `dsse-device-setup-${platform}-${arch}.zip`);
    assert.ok(f.fallback());
    f.timers.forEach(timer => timer.handler()); assert.deepEqual(f.revokedURLs, ['blob:bundle-1']);
  }
});

test('404 preserves the separate-files bundle with an explicit missing-installer warning', async () => {
  const f = fixture(); f.context.fetch = async (...args) => { f.calls.push(['GET', ...args]); return response(404); };
  await f.send('windows', 'amd64'); const entries = await unzipStored(f.blobs[0]);
  assert.equal(entries.size, 4); assert.equal([...entries.keys()].some(name => /\.(pkg|msi)$/.test(name)), false);
  assert.equal(entries.get('enrolment_token.txt').toString(), secret + '\n');
  assert.ok(f.notices.some(notice => notice.kind === 'warn'));
  assert.match(entries.get('README.txt').toString(), /installer.*not|no installer|not.*installer/i);
  assert.deepEqual(f.calls.map(call => call[0]), ['GET', 'POST']);
});

test('unconfirmed issuance never produces an archive or retries the token request automatically', async () => {
  const complete = completeReply().body;
  const replies = [new Error('response lost'), {ok: false, status: 503},
    {ok: false, status: 409, body: {partial: true, tokens: []}},
    {ok: true, body: {}}, {ok: true, body: {secret, token: {id: tokenID}}},
    {ok: true, body: {tokens: [{}]}}, {ok: true, body: {tokens: [{token: {id: tokenID}, secret: 42}]}},
    {ok: true, body: {tokens: [complete.tokens[0], complete.tokens[0]]}},
  ];
  for (const reply of replies) {
    const f = fixture(); f.context.apiFetch = async (...args) => {
      f.calls.push(args); if (reply instanceof Error) throw reply; return reply;
    };
    await f.send(); assert.equal(f.calls.filter(call => call[0] === 'POST').length, 1);
    assert.equal(f.blobs.length, 0); assert.equal(f.fallback(), null); assert.equal(f.button.disabled, false);
    assert.ok(f.notices.some(notice => /may already have been created/.test(notice.message)));
  }
});

test('nonempty partial issuance preserves its returned credential without creating a ZIP or retrying', async () => {
  const f = fixture(), rows = completeReply().body.tokens;
  f.context.apiFetch = async (...args) => {
    f.calls.push(args); return {ok: false, status: 409, body: {partial: true, tokens: rows, error: 'issuance stopped'}};
  };
  await f.send();
  assert.equal(f.calls.filter(call => call[0] === 'POST').length, 1);
  assert.equal(f.disclosures.length, 1); assert.equal(f.disclosures[0].tokens, rows);
  assert.equal(f.disclosures[0].requested_count, 1); assert.equal(f.disclosures[0].partial, true);
  assert.equal(f.blobs.length, 0); assert.equal(f.fallback(), null); assert.equal(f.button.disabled, false);
  assert.ok(f.notices.some(notice => /may already have been created/.test(notice.message)));
});

test('malformed partial issuance does not disclose a mixed set or fabricate a usable bundle', async () => {
  for (const rows of ['invalid', [{token: {id: tokenID}, secret}, {token: {id: 'missing-secret'}}]]) {
    const f = fixture(); f.context.apiFetch = async (...args) => {
      f.calls.push(args); return {ok: false, status: 409, body: {partial: true, tokens: rows}};
    };
    await f.send(); assert.equal(f.disclosures.length, 0); assert.equal(f.blobs.length, 0);
    assert.equal(f.calls.filter(call => call[0] === 'POST').length, 1);
    assert.ok(f.notices.some(notice => /may already have been created/.test(notice.message)));
  }
});

test('definitive token refusal reports the error and no credential is fabricated', async () => {
  const f = fixture(); f.context.apiFetch = async (...args) => {
    f.calls.push(args); return {ok: false, status: 400, body: {error: '<b>approval refused</b>'}};
  };
  await f.send(); assert.equal(f.blobs.length, 0); assert.equal(f.fallback(), null);
  assert.ok(f.notices.some(notice => notice.message === '<b>approval refused</b>'));
  assert.equal(f.button.disabled, false);
});

test('ZIP or download allocation failure keeps the issued secret and its revoke control reachable', async () => {
  for (const stage of ['zip', 'url', 'click']) {
    const f = fixture();
    if (stage === 'zip') f.context.zipStored = () => { throw Error('zip allocation failed'); };
    else if (stage === 'url') f.context.URL.createObjectURL = () => { throw Error('url allocation failed'); };
    else {
      const create = f.context.document.createElement;
      f.context.document.createElement = tag => { const node = create(tag); node.click = () => { throw Error('download refused'); }; return node; };
    }
    await f.send(); assert.equal(f.calls.filter(call => call[0] === 'POST').length, 1);
    assert.equal(f.downloads.length, 0); assert.ok(f.fallback());
    if (stage === 'click') {
      assert.equal(f.context.document.body.children.length, 0);
      f.timers.forEach(timer => timer.handler()); assert.deepEqual(f.revokedURLs, ['blob:bundle-1']);
    }
    await fallbackButton(f, 'Show the approval').click(); assert.ok(f.fallback().textContent.includes(secret));
    f.context.apiFetch = async (...args) => { f.calls.push(args); return revokedReply(); };
    await fallbackButton(f, 'Take it back').click(); controlRevoke(f.calls.at(-1));
    assert.equal(f.fallback().textContent.includes(secret), false);
  }
});

test('fallback revocation suppresses reentry and reports success only after the control response', async () => {
  const f = fixture(); f.context.bundleApprovalFallback(f.button, secret, tokenID);
  let finish; f.context.apiFetch = (...args) => { f.calls.push(args); return new Promise(resolve => { finish = resolve; }); };
  const revoke = fallbackButton(f, 'Take it back');
  const pending = revoke.click(); await revoke.click();
  assert.equal(f.calls.length, 1); controlRevoke(f.calls[0]); assert.equal(revoke.disabled, true);
  assert.doesNotMatch(f.fallback().textContent, /Taken back\./);
  finish(revokedReply()); await pending;
  assert.match(f.fallback().textContent, /Taken back\./); assert.equal(f.fallback().querySelectorAll('button').length, 0);
});

test('revocation failure leaves controls usable and secret available for an explicit retry', async () => {
  for (const failure of [new Error('offline'), {ok: false, status: 503, body: {error: '<b>save refused</b>'}}]) {
    const f = fixture(); f.context.bundleApprovalFallback(f.button, secret, tokenID);
    f.context.apiFetch = async (...args) => { f.calls.push(args); if (failure instanceof Error) throw failure; return failure; };
    const revoke = fallbackButton(f, 'Take it back'); await revoke.click();
    assert.equal(revoke.disabled, false); assert.doesNotMatch(f.fallback().textContent, /Taken back\./);
    assert.ok(f.notices.some(notice => notice.kind === 'err'));
    await fallbackButton(f, 'Show the approval').click(); assert.ok(f.fallback().textContent.includes(secret));
    f.context.apiFetch = async (...args) => { f.calls.push(args); return revokedReply(); };
    await revoke.click(); assert.equal(f.calls.length, 2); controlRevoke(f.calls[1]);
    assert.match(f.fallback().textContent, /Taken back\./);
  }
});

test('malformed revocation 200 keeps fallback controls and requests a state check instead of announcing success', async () => {
  const valid = revokedReply().body.token;
  const bodies = [undefined, {}, {token: null}, {token: {...valid, id: 'different-token'}},
    {token: {...valid, revoked_at: ''}}, {token: {...valid, revoked_at: 42}},
    {token: {...valid, used_at: '2026-09-15T04:00:00Z'}},
    {token: {...valid, used_at: '2026-09-15T04:00:00Z'}, note: ''},
    {token: {...valid, used_at: '2026-09-15T04:00:00Z'}, note: 42},
  ];
  for (const body of bodies) {
    const f = fixture(); f.context.bundleApprovalFallback(f.button, secret, tokenID);
    f.context.apiFetch = async (...args) => { f.calls.push(args); return {ok: true, status: 200, body}; };
    const revoke = fallbackButton(f, 'Take it back'); await revoke.click();
    assert.equal(f.calls.length, 1); assert.equal(revoke.disabled, false);
    assert.doesNotMatch(f.fallback().textContent, /Taken back\./);
    assert.ok(f.notices.some(notice => /Revocation could not be confirmed/.test(notice.message)));
    await fallbackButton(f, 'Show the approval').click(); assert.ok(f.fallback().textContent.includes(secret));
    f.context.apiFetch = async (...args) => { f.calls.push(args); return revokedReply(); };
    await revoke.click(); assert.equal(f.calls.length, 2); assert.match(f.fallback().textContent, /Taken back\./);
  }
});

test('used-token revocation keeps the device-access warning visible instead of claiming access was removed', async () => {
  const f = fixture(); f.context.bundleApprovalFallback(f.button, secret, tokenID);
  const note = 'This token was used: revoking it does NOT remove device access; disable the device instead.';
  f.context.apiFetch = async (...args) => { f.calls.push(args); return revokedReply(note); };
  await fallbackButton(f, 'Take it back').click(); controlRevoke(f.calls[0]);
  assert.ok(f.fallback().textContent.includes(note));
  assert.doesNotMatch(f.fallback().textContent, /Nothing can enrol.*nothing is left outstanding/);
});

test('CRC agrees with the standard check value and empty and binary entries retain valid ZIP records', async () => {
  const f = fixture();
  assert.equal(f.context.zipCRC32(new TextEncoder().encode('123456789')), 0xcbf43926);
  const entries = await unzipStored(f.context.zipStored([
    {name: 'empty.txt', bytes: new Uint8Array()}, {name: 'binary.bin', bytes: installerBytes},
  ]));
  assert.equal(entries.get('empty.txt').length, 0); assert.deepEqual(entries.get('binary.bin'), Buffer.from(installerBytes));
});

test('confirmed unused and used revocations remove the old waiting label', async () => {
  for (const note of ['', 'Already used; disable the device to remove its access.']) {
    const f = fixture(); await f.send();
    assert.match(f.button.textContent, /one approval is now waiting/);
    f.context.apiFetch = async (...args) => { f.calls.push(args); return revokedReply(note); };
    await fallbackButton(f, 'Take it back').click();
    assert.equal(f.button.textContent, 'Download everything for one device');
    assert.doesNotMatch(f.button.textContent, /waiting/);
    if (note) assert.ok(f.fallback().textContent.includes(note));
  }
});

test('revoking the previous approval leaves a pending bundle label intact and never revives the revoked waiting state', async () => {
  for (const artifactStatus of [200, 503]) {
    const f = fixture(); await f.send();
    let finishRevoke, finishArtifact;
    f.context.apiFetch = (...args) => {
      f.calls.push(args);
      if (args[1].endsWith('/revoke')) return new Promise(resolve => { finishRevoke = resolve; });
      return Promise.resolve({ok: true, status: 200, body: {tokens: [{token: {id: 'new-token'}, secret: 'new-secret'}]}});
    };
    const revoking = fallbackButton(f, 'Take it back').click();
    f.context.fetch = (...args) => { f.calls.push(['GET', ...args]); return new Promise(resolve => { finishArtifact = resolve; }); };
    const preparing = f.send('windows', 'amd64');
    const preparingLabel = f.button.textContent;
    finishRevoke(revokedReply()); await revoking;
    assert.equal(f.button.textContent, preparingLabel); assert.equal(f.button.disabled, true);
    finishArtifact(response(artifactStatus)); await preparing;
    if (artifactStatus === 200) assert.match(f.button.textContent, /one approval is now waiting/);
    else assert.doesNotMatch(f.button.textContent, /waiting/, 'failed next bundle must not revive the revoked approval');
  }
});

test('a delayed revocation from a replaced fallback cannot overwrite the latest bundle or approval', async () => {
  const f = fixture(); await f.send();
  const previousFallback = f.fallback(); let finishRevoke;
  f.context.apiFetch = (...args) => {
    f.calls.push(args);
    if (args[1].endsWith('/revoke')) return new Promise(resolve => { finishRevoke = resolve; });
    return Promise.resolve({ok: true, status: 200, body: {tokens: [{token: {id: 'new-token'}, secret: 'new-secret'}]}});
  };
  const revoking = fallbackButton(f, 'Take it back').click();
  await f.send('windows', 'amd64'); const latestFallback = f.fallback(), latestLabel = f.button.textContent;
  assert.notEqual(latestFallback, previousFallback); assert.match(latestLabel, /one approval is now waiting/);
  finishRevoke(revokedReply()); await revoking;
  assert.equal(f.fallback(), latestFallback); assert.equal(f.button.textContent, latestLabel);
  await fallbackButton(f, 'Show the approval').click(); assert.ok(latestFallback.textContent.includes('new-secret'));
  assert.equal(latestFallback.textContent.includes(secret), false);
});
