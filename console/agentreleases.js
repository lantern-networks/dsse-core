"use strict";

// agentreleases.js — "Agent Releases": put a new agent version in front of a fleet, from here and nowhere else.
//
// ★ WHY THIS SCREEN EXISTS (2026-08-13). Publishing a release was a command-line act: hash the package by
// hand, hand-write a manifest, sign it with a file-based key on somebody's laptop, curl it in, curl the bytes
// in after it. The most consequential operation in the product — it decides what code runs, as root,
// unattended, on every machine — was the one with no screen and the least protection around it.
//
// The browser hashes the package it is holding, so the digest describes the bytes actually uploaded rather
// than something typed in beside them. The control plane signs, with a key in a token that never enters a
// process. Nobody handles a signing key and nobody copies a hash.
//
// ★ TWO STEPS, AND THE SECOND ONE IS WHAT REACHES DEVICES. Publishing stores a signed manifest; devices are
// still offered the PREVIOUS release until its bytes arrive. That is deliberate in the API and it is shown
// here rather than smoothed over — a release waiting for its package is a normal state, and hiding it would
// leave an operator believing a rollout started when nothing has moved.
//
// Backend (control plane): GET/POST /admin/agent-updates, PUT /admin/agent-update-artifact,
// GET /admin/agent-update-sign-floor.

// Everything here is the control plane's. An Edge that pulls its published set refuses the write, and answers
// the read with a copy that is one poll behind.
const _AR_PLANE = "control";

// The targets in the words an operator uses. "darwin/arm64" is our vocabulary; nobody administering a fleet of
// laptops thinks in it, and learning it should not be a precondition for shipping an update.
const _AR_TARGETS = [
  { platform: "darwin", arch: "arm64", t: { en: "Mac (Apple silicon)", ja: "Mac(Apple シリコン)" } },
  { platform: "darwin", arch: "amd64", t: { en: "Mac (Intel)", ja: "Mac(Intel)" } },
  { platform: "windows", arch: "amd64", t: { en: "Windows (64-bit)", ja: "Windows(64bit)" } },
  { platform: "windows", arch: "arm64", t: { en: "Windows (Arm)", ja: "Windows(Arm)" } },
];

function arTargetKey(p, a) { return p + "/" + a; }

function arTargetLabel(p, a) {
  const t = _AR_TARGETS.find((x) => x.platform === p && x.arch === a);
  return t ? bl(t.t) : p + "/" + a;
}

// What an envelope says, without asking the reader to open one. The payload is base64 of the manifest JSON;
// this reads it only to SHOW it. Nothing here is a check — the signature was verified by the control plane
// before it stored this, and a check written in the browser would be one an attacker simply does not run.
function arManifestOf(env) {
  if (!env) return null;
  try {
    return JSON.parse(atob(String(env.payload_b64 || env.payload || "")));
  } catch (e) {
    return null;
  }
}

// The package the browser is holding, hashed in the browser.
//
// ★ THE DIGEST MUST DESCRIBE THE BYTES THAT ARE UPLOADED, and this is the only arrangement in which it does:
// anything typed alongside the file describes what somebody believed about a different copy. A mismatch would
// not surface until every device in the fleet refused the download.
async function arHash(file) {
  const buf = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// A version out of the file name when it is there. Convenience only, and the field stays editable: a guess
// that silently becomes the published version is worse than no guess.
function arGuessVersion(name) {
  const m = String(name).match(/(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)/);
  return m ? m[1] : "";
}

function arGuessTarget(name) {
  const n = String(name).toLowerCase();
  if (n.endsWith(".msi")) return { platform: "windows", arch: "amd64" };
  if (n.indexOf("amd64") >= 0 || n.indexOf("x86_64") >= 0 || n.indexOf("intel") >= 0) {
    return { platform: "darwin", arch: "amd64" };
  }
  if (n.endsWith(".pkg")) return { platform: "darwin", arch: "arm64" };
  return null;
}

function arErrorText(r) {
  if (r && r.body && (r.body.error || r.body.message)) return String(r.body.error || r.body.message);
  if (r && r.status) return "HTTP " + r.status;
  return bl({ en: "unknown error", ja: "不明なエラー" });
}

function arReleaseReadError() { return bl({ en: "Could not verify release information. Retry before publishing or choosing a version.", ja: "配布情報を確認できません。公開やバージョンの選択前に再試行してください。" }); }
function arSigningReadError() { return bl({ en: "Signing information could not be verified. Retry before publishing; the signing key and minimum versions are unknown.", ja: "署名情報を確認できません。署名鍵と最低バージョンは不明です。公開前に再試行してください。" }); }
function arKnownTarget(key) { return _AR_TARGETS.some(t => arTargetKey(t.platform, t.arch) === key); }
function arReleaseResponse(response, schema, scope) {
  const d = response?.body;
  if (!response?.ok || response.status !== 200 || !arReadObject(d) || d.schema_version !== schema || d.tenant_id !== scope) throw new Error(arReleaseReadError());
  return d;
}
// This checks the display contract, not cryptographic trust or installer bytes.
// Signature verification remains the authority's and the endpoint's responsibility.
function arCatalogueBody(response, scope) {
  const d = arReleaseResponse(response, "admin_agent_updates.v1", scope);
  const text = v => typeof v === "string" && v.trim() !== "";
  const date = v => typeof v === "string" && Number.isFinite(Date.parse(v));
  for (const map of [d.envelopes, d.pending]) {
    if (!arReadObject(map)) throw new Error(arReleaseReadError());
    for (const [key, envelope] of Object.entries(map)) {
      if (!arKnownTarget(key) || !arReadObject(envelope) || envelope.type !== "dsse_agent_update_manifest.v1" || envelope.version !== "1" ||
          !text(envelope.signing_key_id) || !date(envelope.created_at) || !text(envelope.signature) ||
          !/^[a-f0-9]{64}$/.test(envelope.payload_sha256) || typeof envelope.payload_b64 !== "string" || !envelope.payload_b64) throw new Error(arReleaseReadError());
      const m = arManifestOf(envelope);
      if (!arReadObject(m) || m.schema !== "1" || arTargetKey(m.platform, m.arch) !== key || !text(m.version) ||
          !text(m.channel) || !["dsse", "mdm"].includes(m.delivery) || !["pkg", "msi"].includes(m.artifact_kind) ||
          typeof m.artifact_url !== "string" || (m.delivery === "dsse" && !text(m.artifact_url)) ||
          !/^[a-f0-9]{64}$/.test(m.artifact_sha256) || !Number.isSafeInteger(m.artifact_size) || m.artifact_size <= 0 ||
          !date(m.released_at) || !date(m.not_after)) throw new Error(arReleaseReadError());
    }
  }
  return d;
}
function arSigningBody(response, scope) {
  const d = arReleaseResponse(response, "admin_agent_update_sign_floor.v1", scope), key = d.signing_public_key;
  if (!arReadObject(d.floors) || typeof key !== "string" || !(key === "no" || /^[a-f0-9]{64}$/.test(key) || /^04[a-f0-9]{128}$/.test(key)) ||
      Object.entries(d.floors).some(([target, version]) => !arKnownTarget(target) || typeof version !== "string" || !version.trim())) throw new Error(arSigningReadError());
  return d;
}

function arRolloutSelection() { return typeof operateTenant === "string" ? operateTenant : ""; }
function arRolloutReadError() { return bl({ en: "Could not verify rollout settings. Retry before making changes.", ja: "配布設定を確認できません。変更する前に再試行してください。" }); }
function arReadObject(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }
function arRolloutPlanBody(response, tenant) {
  const d = response?.body, p = d?.plan;
  const invalid = () => { throw new Error(arRolloutReadError()); };
  if (!response?.ok || response.status !== 200 || !arReadObject(d) || d.schema_version !== "admin_agent_rollout.v1" ||
      d.tenant_id !== tenant || !arReadObject(p) || typeof p.frozen !== "boolean" ||
      ["desired_version", "release_channel", "intent", "reason", "updated_at"].some(k => typeof p[k] !== "string") ||
      !["", "rollout", "rollback", "freeze", "follow", "schedule"].includes(p.intent)) invalid();
  const whole = n => Number.isSafeInteger(n) && n >= 0;
  if (p.window !== undefined && p.window !== null) {
    const w = p.window, clock = v => typeof v === "string" && /^([01]\d|2[0-3]):[0-5]\d$/.test(v.trim());
    if (!arReadObject(w) || !clock(w.local_start) || !clock(w.local_end) ||
        typeof w.require_ac_power !== "boolean" || typeof w.require_unattended !== "boolean" ||
        !whole(w.require_idle_minutes) || !whole(w.deadline_days) || w.deadline_days > 365) invalid();
  }
  if (p.waves !== undefined && p.waves !== null) {
    const w = p.waves, groups = new Set();
    if (!arReadObject(w) || (w.waves !== null && !Array.isArray(w.waves)) ||
        (w.default_delay_days !== undefined && w.default_delay_days !== null && !whole(w.default_delay_days))) invalid();
    for (const row of w.waves || []) {
      if (!arReadObject(row) || typeof row.group !== "string" || !row.group.trim() || !whole(row.delay_days) ||
          (row.priority !== undefined && !Number.isSafeInteger(row.priority))) invalid();
      const key = row.group.trim().toLowerCase();
      if (groups.has(key)) invalid();
      groups.add(key);
    }
  }
  return p;
}

// Check the fields this editor requested. The authority merges unrelated settings
// under its lock; comparing them with the old form would falsely imply a CAS.
function arRolloutSaveConfirmed(response, tenant, request) {
  let p;
  try { p = arRolloutPlanBody(response, tenant); } catch (_) { return false; }
  if (p.intent !== request.intent) return false;
  if (request.intent === "rollout") return p.desired_version === request.desired_version && p.release_channel === (request.release_channel || "");
  if (request.intent === "follow") return p.desired_version === "" && p.release_channel === "";
  if (request.intent !== "schedule") return false;
  if (request.window && (!p.window || Object.keys(request.window).some(k => p.window[k] !== request.window[k]))) return false;
  if (request.waves) {
    const expected = request.waves, actual = p.waves;
    if (!actual || (expected.default_delay_days ?? null) !== (actual.default_delay_days ?? null) ||
        (expected.waves || []).length !== (actual.waves || []).length) return false;
    if ((expected.waves || []).some((w, i) => {
      const a = actual.waves[i];
      return a.group !== w.group || a.delay_days !== w.delay_days || (a.priority ?? 0) !== (w.priority ?? 0);
    })) return false;
  }
  return !!(request.window || request.waves);
}

// The verified read owns this dialog's tenant and render context. Leaving it
// suppresses late UI completion, but cannot cancel a write already on the server.
function arRolloutDialog(opts) {
  let closed = false, pending = false, observer;
  const notice = el("div", { role: "status" });
  const close = () => { if (closed) return; closed = true; observer?.disconnect(); backdrop.remove(); document.removeEventListener("keydown", onKey); };
  const active = () => {
    if (closed) return false;
    if (opts.host.isConnected === false || typeof opts.context?.tenant !== "string" || !opts.context.current()) { close(); return false; }
    return true;
  };
  const cancel = el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => { if (!pending) close(); } });
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Save", ja: "保存" }) });
  const onKey = e => { if (e.key === "Escape" && !pending) close(); };
  const backdrop = el("div", { class: "ui-modal-backdrop", onClick: e => { if (e.target === backdrop && !pending) close(); } }, [
    el("div", { class: "ui-modal", role: "dialog" }, [
      el("div", { class: "ui-modal-head", text: opts.title }),
      el("div", { class: "ui-modal-body" }, [...opts.body, notice]),
      el("div", { class: "ui-modal-foot" }, [cancel, submit]),
    ]),
  ]);
  const lock = () => backdrop.querySelectorAll("input,select,textarea,button").forEach(n => { n.disabled = pending; });
  document.body.appendChild(backdrop);
  document.addEventListener("keydown", onKey);
  submit.addEventListener("click", async () => {
    if (!active() || pending) return;
    const request = opts.request();
    if (!request) return;
    pending = true; lock(); notice.textContent = ""; notice.setAttribute("role", "status");
    try {
      const r = await apiFetch("PUT", "/admin/agent-rollout?expected_tenant_id=" + encodeURIComponent(opts.context.tenant), request, _AR_PLANE);
      if (!active()) return;
      if (!arRolloutSaveConfirmed(r, opts.context.tenant, request)) throw new Error();
      close();
      uiToast(bl({ en: "Saved. Devices pick it up on their next check.", ja: "保存しました。端末は次の確認時に反映します。" }), "ok");
      renderAgentReleaseList(opts.host);
    } catch (_) {
      if (active()) {
        notice.setAttribute("role", "alert");
        notice.textContent = bl({ en: "The save could not be confirmed. The change may already be saved. Retry with Save, or cancel and reload the settings before making another change.",
          ja: "保存結果を確認できません。変更は保存済みの可能性があります。保存ボタンで再試行するか、キャンセルして設定を再読込してから次の変更を行ってください。" });
      }
    } finally { pending = false; if (active()) lock(); }
  });
  observer = new MutationObserver(() => { active(); });
  observer.observe(document.body, { childList: true, subtree: true });
  active();
}

// The artifact upload is raw bytes, so it cannot go through apiFetch (which sends JSON). The session and the
// headers are built from the same globals rather than copied, so a change to how the Console authenticates
// does not leave this one call behind.
async function arUploadArtifact(file, platform, arch, context) {
  const base = baseForPlane(_AR_PLANE);
  const token = localStorage.getItem("adminToken") || "";
  const signedIn = idpSession && idpSession.auth_method === "admin_session";
  const headers = { "content-type": "application/octet-stream" };
  if (!signedIn && token) headers["authorization"] = "Bearer " + token;
  if (signedIn && idpSession.csrf_token) headers["x-csrf-token"] = idpSession.csrf_token;
  if (operateTenant) headers["x-operate-tenant"] = operateTenant;
  const path = "/admin/agent-update-artifact?platform=" + encodeURIComponent(platform) +
    "&arch=" + encodeURIComponent(arch) + "&expected_tenant_id=" + encodeURIComponent(context.scope) +
    "&expected_manifest_sha256=" + encodeURIComponent(context.manifestSHA256);
  try {
    const res = await fetch(base + path, { method: "PUT", headers, credentials: "include", body: file });
    const text = await res.text();
    let parsed;
    try { parsed = JSON.parse(text); } catch (e) { parsed = text; }
    return { ok: res.ok, status: res.status, body: parsed };
  } catch (e) {
    return { ok: false, status: 0, body: { error: String(e) } };
  }
}

// Keep remediation tied to the failed check. A byte mismatch is not evidence
// that refreshing the catalogue will repair the stored package.
function arArtifactDownloadError(reason) {
  if (reason === "scope") return bl({
    en: "Download blocked: the package response does not match the selected organization. Check the organization selection and reload the release list.",
    ja: "ダウンロードを停止しました。応答の組織が選択中の組織と一致しません。組織の選択を確認し、配布一覧を再読込してください。" });
  if (reason === "size" || reason === "digest") return bl({
    en: "Download blocked: the package " + (reason === "size" ? "size" : "SHA-256 digest") + " does not match the published release. Do not distribute this package. Ask the deployment operator to investigate the stored artifact and delivery path.",
    ja: "ダウンロードを停止しました。パッケージの" + (reason === "size" ? "サイズ" : "SHA-256 ハッシュ") + "が公開済みリリースと一致しません。このパッケージは配布せず、配備の運用者に保存されたファイルと配信経路の調査を依頼してください。" });
  if (reason === "verification") return bl({
    en: "The package integrity check could not be completed. No package was saved. Check browser support and try again; this does not establish that the package is corrupt.",
    ja: "パッケージの完全性確認を完了できず、保存していません。ブラウザの対応状況を確認して再試行してください。パッケージの破損を確認したわけではありません。" });
  if (reason === "transfer") return bl({
    en: "The package transfer could not be completed. No package was saved. Check your connection and access, then reload the release list and try again.",
    ja: "パッケージを取得できず、保存していません。接続とアクセス権を確認し、配布一覧を再読込してから再試行してください。" });
  return bl({ en: "The package could not be verified. Reload the release list and try again.",
    ja: "パッケージを確認できません。配布一覧を再読込してから、もう一度ダウンロードしてください。" });
}

// Download the active package described by this verified catalogue snapshot.
// Header checks bind the response context; the selected manifest's digest and
// size decide which bytes may be handed to the browser as a download.
async function arDownloadArtifact(platform, arch, manifest, context) {
  const current = context?.current;
  if (typeof current !== "function" || !current()) return;
  const scope = context.scope, manifestSHA256 = context.manifestSHA256, expected = { ...manifest };
  let failure = "catalogue";
  try {
    if (typeof scope !== "string" || !/^[a-f0-9]{64}$/.test(manifestSHA256) ||
        expected.platform !== platform || expected.arch !== arch || !arKnownTarget(arTargetKey(platform, arch)) ||
        typeof expected.version !== "string" || !expected.version ||
        !Number.isSafeInteger(expected.artifact_size) || expected.artifact_size <= 0 ||
        !/^[a-fA-F0-9]{64}$/.test(expected.artifact_sha256)) throw new Error();
    const headers = {}, token = localStorage.getItem("adminToken") || "";
    const signedIn = idpSession && idpSession.auth_method === "admin_session";
    if (!signedIn && token) headers["authorization"] = "Bearer " + token;
    if (signedIn && idpSession.csrf_token) headers["x-csrf-token"] = idpSession.csrf_token;
    if (operateTenant) headers["x-operate-tenant"] = operateTenant;
    const path = "/admin/agent-update-artifact?platform=" + encodeURIComponent(platform) +
      "&arch=" + encodeURIComponent(arch) + "&artifact_scope=publication&expected_tenant_id=" + encodeURIComponent(scope) +
      "&expected_manifest_sha256=" + encodeURIComponent(manifestSHA256);
    failure = "transfer";
    const res = await fetch(baseForPlane(_AR_PLANE) + path, { headers, credentials: "include", redirect: "error", cache: "no-store" });
    if (!current()) return;
    if (!res.ok || res.status !== 200) throw new Error();
    failure = "scope";
    if (!res.headers.has("X-Dsse-Agent-Update-Scope") || res.headers.get("X-Dsse-Agent-Update-Scope") !== scope) throw new Error();
    failure = "catalogue";
    if (res.headers.get("X-Dsse-Agent-Update-Manifest-SHA256") !== manifestSHA256 ||
        res.headers.get("X-Dsse-Agent-Update-Version") !== expected.version) throw new Error();
    failure = "transfer";
    const blob = await res.blob();
    if (!current()) return;
    failure = "size";
    if (blob.size !== expected.artifact_size) throw new Error();
    failure = "verification";
    const digest = await arHash(blob);
    if (!current()) return;
    failure = "digest";
    if (digest !== expected.artifact_sha256.toLowerCase()) throw new Error();
    failure = "catalogue";
    const ext = platform === "windows" ? "msi" : "pkg", url = URL.createObjectURL(blob), a = document.createElement("a");
    a.href = url; a.download = "dsse-agent-" + expected.version + "-" + platform + "-" + arch + "." + ext;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  } catch (_) {
    if (current()) uiToast(arArtifactDownloadError(failure), "err");
  }
}

// ★ THE WINDOW IS A RULE AN OPERATOR OWNS, AND IT HAD NO SCREEN (2026-08-13, raised by the operator). The plan
// has carried a maintenance window since the rollout lane was built — devices honour it, the Edge signs it, the
// admin API accepts it under intent=schedule — and the only way to set one was a hand-written PUT. A setting
// that exists in the product and nowhere in the product's interface is a setting nobody has.
//
// ★★ AND IT CANNOT LOOSEN WHAT A DEVICE ALREADY REQUIRES. agentupdate.RaiseWindow takes the STRICTER of the
// two: unchecking "only when nobody is using it" does not permit installs while somebody is typing if that
// device's own floor demands otherwise. Saying so on the screen is the difference between a rule an operator
// can reason about and one that appears not to work.
function arWindowSummary(w) {
  if (!w) return bl({ en: "not set — devices use their own defaults", ja: "未設定 — 端末の既定に従います" });
  const parts = [];
  const start = (w.local_start || "").trim();
  const end = (w.local_end || "").trim();
  if (start && end && !(start === "00:00" && end === "23:59")) {
    parts.push(bl({ en: start + "–" + end + " device local time", ja: "端末のローカル時刻で " + start + "〜" + end }));
  } else {
    parts.push(bl({ en: "any time of day", ja: "時間帯の制限なし" }));
  }
  if (w.require_ac_power) parts.push(bl({ en: "on mains power", ja: "電源に接続中" }));
  if (w.require_unattended) parts.push(bl({ en: "nobody using it", ja: "誰も使っていない" }));
  if (w.require_idle_minutes > 0) {
    parts.push(bl({ en: "idle " + w.require_idle_minutes + " min", ja: "操作なし " + w.require_idle_minutes + " 分" }));
  }
  if (w.deadline_days > 0) {
    parts.push(bl({ en: "installed within " + w.deadline_days + " days regardless", ja: "遅くとも " + w.deadline_days + " 日以内には実施" }));
  }
  return parts.join(bl({ en: " · ", ja: " · " }));
}

// openAgentWindowForm edits the window and nothing else: intent=schedule leaves the halt and the wave schedule
// exactly as they were, which is why this form cannot accidentally release a frozen fleet.
function openAgentWindowForm(host, current, context) {
  const w = current || {};
  const startF = uiField({ name: "start", label: bl({ en: "From", ja: "開始" }), value: w.local_start || "00:00",
    placeholder: "01:00", hint: bl({ en: "The device's own local time, not yours.", ja: "端末のローカル時刻です(管理者の時刻ではありません)。" }) });
  const endF = uiField({ name: "end", label: bl({ en: "Until", ja: "終了" }), value: w.local_end || "23:59", placeholder: "05:00" });
  const acF = uiField({ name: "ac", label: bl({ en: "Only on mains power", ja: "電源に接続中のときだけ" }),
    type: "checkbox", value: !!w.require_ac_power,
    hint: bl({ en: "A laptop on battery waits.", ja: "バッテリー駆動中の端末は待ちます。" }) });
  const unattendedF = uiField({ name: "unattended", label: bl({ en: "Only when nobody is using it", ja: "誰も使っていないときだけ" }),
    type: "checkbox", value: !!w.require_unattended });
  const idleF = uiField({ name: "idle", label: bl({ en: "Minutes with no activity first", ja: "操作がないまま何分待つか" }),
    value: String(w.require_idle_minutes || 0),
    hint: bl({ en: "0 means do not wait for idleness.", ja: "0 なら操作の有無を待ちません。" }) });
  const deadlineF = uiField({ name: "deadline", label: bl({ en: "Install anyway after (days)", ja: "この日数を過ぎたら条件を待たずに実施" }),
    value: String(w.deadline_days || 0),
    hint: bl({ en: "Stops a device that is never idle from never updating. 0 means no deadline.", ja: "ずっと使われている端末が永久に更新されないのを防ぎます。0 なら期限なし。" }) });

  const note = el("div", { class: "ui-field-hint", text: bl({
    en: "A device applies whichever is STRICTER — this rule or its own. Unchecking something here does not " +
        "permit an install the device itself refuses.",
    ja: "端末は「この設定」と「端末自身の設定」の厳しい方を使います。ここでチェックを外しても、端末側が" +
        "禁じているインストールが許可されるわけではありません。" }) });

  arRolloutDialog({ host, context,
    title: bl({ en: "When updates may install", ja: "更新してよいとき" }),
    body: [startF.el, endF.el, acF.el, unattendedF.el, idleF.el, deadlineF.el, note],
    request: () => {
      const hhmm = /^([01]\d|2[0-3]):[0-5]\d$/;
      if (!hhmm.test(startF.get())) { startF.setError(bl({ en: "Use HH:MM, e.g. 01:00", ja: "HH:MM 形式で入力してください(例 01:00)" })); return; }
      if (!hhmm.test(endF.get())) { endF.setError(bl({ en: "Use HH:MM, e.g. 05:00", ja: "HH:MM 形式で入力してください(例 05:00)" })); return; }
      const idle = Number(idleF.get());
      const deadline = Number(deadlineF.get());
      if (!Number.isSafeInteger(idle) || idle < 0) { idleF.setError(bl({ en: "A whole number of minutes.", ja: "分を整数で入力してください。" })); return; }
      if (!Number.isSafeInteger(deadline) || deadline < 0 || deadline > 365) { deadlineF.setError(bl({ en: "A whole number of days from 0 to 365.", ja: "日数は0から365の整数で入力してください。" })); return; }

      return { intent: "schedule", window: {
        local_start: startF.get(), local_end: endF.get(), require_idle_minutes: idle,
        require_unattended: unattendedF.get(), require_ac_power: acF.get(), deadline_days: deadline,
      } };
    },
  });
}

// ★ THE ROLLOUT ORDER HAD NO SCREEN EITHER (2026-08-13). Same gap as the window, one object over: the plan
// carries a wave schedule, the Edge signs it, devices compute their own start from it — and the only way to
// author one was a hand-written PUT. Review 30 called it "the schedule an operator authored" while no operator
// could author one.
function arWavesSummary(waves) {
  const list = (waves && waves.waves) || [];
  if (!list.length) {
    if (waves?.default_delay_days !== undefined && waves.default_delay_days !== null) return bl({
      en: "all groups after " + waves.default_delay_days + "d", ja: "全グループは " + waves.default_delay_days + "日後" });
    return bl({ en: "everything at once, as soon as a release is published",
                ja: "公開と同時に全端末へ(段階分けなし)" });
  }
  const ordered = list.slice().sort((a, b) => (a.delay_days || 0) - (b.delay_days || 0));
  const summary = ordered.map((w) => {
    const d = w.delay_days || 0;
    const when = d === 0
      ? bl({ en: w.group + " immediately", ja: w.group + " はすぐ" })
      : bl({ en: w.group + " after " + d + "d", ja: w.group + " は " + d + "日後" });
    return when + (w.priority ? bl({ en: " (priority " + w.priority + ")", ja: "（優先度 " + w.priority + "）" }) : "");
  }).join(" → ");
  return summary + (waves.default_delay_days !== undefined && waves.default_delay_days !== null
    ? bl({ en: "; other groups after " + waves.default_delay_days + "d", ja: "、その他のグループは " + waves.default_delay_days + "日後" }) : "");
}

// openAgentWavesForm edits the rollout order and nothing else — intent=schedule again, so the halt and the
// window are untouched.
function openAgentWavesForm(host, current, groupsInUse, context) {
  const rows = ((current && current.waves) || []).map((w) => ({ group: w.group || "", days: String(w.delay_days || 0), priority: w.priority }));
  if (!rows.length) rows.push({ group: "", days: "0" });

  const list = el("div", {});
  const draw = () => {
    list.innerHTML = "";
    rows.forEach((row, i) => {
      const g = el("input", { class: "ui-input", value: row.group, placeholder: bl({ en: "group name", ja: "グループ名" }) });
      g.addEventListener("input", () => { row.group = g.value; });
      const d = el("input", { class: "ui-input", value: row.days, style: "max-width:7em" });
      d.addEventListener("input", () => { row.days = d.value; });
      list.appendChild(el("div", { class: "ui-form-row" }, [
        g, el("span", { class: "ui-muted", text: bl({ en: "starts after", ja: "の開始は" }) }), d,
        el("span", { class: "ui-muted", text: bl({ en: "days", ja: "日後" }) }),
        el("button", { class: "ui-btn ui-btn-sm", text: "−", onClick: () => { rows.splice(i, 1); if (!rows.length) rows.push({ group: "", days: "0" }); draw(); } }),
      ]));
    });
    list.appendChild(el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "+ Add a group", ja: "+ グループを追加" }),
      onClick: () => { rows.push({ group: "", days: "0" }); draw(); } }));
  };
  draw();

  // ★ THE TWO RULES AN OPERATOR HAS TO KNOW, because both are silent when they bite.
  const rules = el("div", { class: "ui-field-hint", text: bl({
    en: "The highest configured group priority wins; ties take the slowest wave. Unlisted groups use the configured default, or the slowest wave if no default is set. Existing priorities and the default stay unchanged here.",
    ja: "設定済みの優先度が高いグループを使い、同じ優先度では遅い方を使います。未指定のグループは既定の日数を使い、既定がなければ最も遅い日数を使います。この画面では既存の優先度と既定の日数を維持します。" }) });

  const reality = el("div", { class: "ui-field-hint", text: groupsInUse.length
    ? bl({ en: "Groups your devices currently carry: " + groupsInUse.join(", "),
           ja: "いま端末が持っているグループ: " + groupsInUse.join("、") })
    : bl({ en: "No device group memberships were available here. Unlisted devices still use the default delay.",
           ja: "この画面では端末のグループ所属情報がありません。未指定の端末にも既定の待機日数は適用されます。" }) });

  arRolloutDialog({ host, context,
    title: bl({ en: "Rollout order", ja: "配布の順番" }),
    body: [list, rules, reality],
    request: () => {
      const waves = [];
      for (const row of rows) {
        const group = (row.group || "").trim();
        if (!group) continue;
        const days = Number(row.days);
        if (!Number.isSafeInteger(days) || days < 0) {
          uiToast(bl({ en: "Days must be a whole number, 0 or more.", ja: "日数は 0 以上の整数で入力してください。" }), "err");
          return;
        }
        waves.push({ group: group, delay_days: days, ...(row.priority !== undefined ? { priority: row.priority } : {}) });
      }
      if (!waves.length) {
        uiToast(bl({ en: "Name at least one group, or cancel to leave the order as it is.",
                     ja: "グループを1つ以上入力してください(変更しない場合はキャンセル)。" }), "err");
        return;
      }
      return { intent: "schedule", waves: { ...(current || {}), waves } };
    },
  });
}

function renderAgentReleasesView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "Agent Releases", ja: "エージェント配布" }) }),
    ]),
    // ★ PUBLISHING IS THE OPERATOR'S (2026-08-17, measured signed in as a customer administrator: POST
    // /admin/agent-updates answers 403). What an organization needs from this screen is WHICH version its
    // devices are being offered; deciding what the deployment distributes is not theirs, and a button that
    // cannot work is worse than no button — it reads as a permission problem with their account.
    //
    // ★★★ AND THE OPERATOR MUST BE ABLE TO OFFER IT TO AN ORGANIZATION (2026-08-28, measured by publishing a
    // real signed, notarised package and then asking a device for it: 404, "no agent updates are published by
    // this edge"). The published set is per organization — GET /admin/agent-updates answered `darwin/arm64`
    // for the operator's own and `[]` for all three customers — and this button was hidden the moment the
    // operator ENTERED one. So the only organization on the deployment that could ever be offered a release
    // was the operator's, and no customer's devices could be updated at all.
    //
    // The predicate was "standing outside every organization". The question it should ask is "may this caller
    // act for the deployment", which is true of an operator inside an organization through the envelope — the
    // same rule every other cross-organization act on this Console follows, elevation and all. A customer
    // administrator still sees nothing, which is the part that was right.
    ...(signedInAsOperator()
      ? [el("button", {
          class: "ui-btn ui-btn-primary",
          text: bl({ en: "+ Publish a version", ja: "+ バージョンを公開" }),
          onClick: () => openAgentReleaseForm(host),
        })]
      : []),
  ]));
  const host = el("div", {});
  content.appendChild(el("div", { class: "ui-toolbar" }, [
    el("span", { class: "ui-spacer" }),
    el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Reload", ja: "再読込" }),
      onClick: () => renderAgentReleaseList(host) }),
  ]));
  content.appendChild(host);
  renderAgentReleaseList(host);
}

async function renderAgentReleaseList(host) {
  if (host.isConnected === false) return;
  uiState(host, "loading");
  const fresh = freshRender(host), selection = arRolloutSelection(), deployment = answeringForTheDeployment();
  const current = () => fresh() && host.isConnected !== false && selection === arRolloutSelection() && deployment === answeringForTheDeployment();
  // Publication caches belong to this verified page/context. An unavailable new
  // read must not leave a previous tenant's data available to the publish form.
  delete window._arLastPublished;
  delete window._arCanSign;
  window._arReleaseReadContext = null;
  let catalogue, signing = null, rolloutTenant;
  try {
    const organization = await apiFetch("GET", "/admin/tenant", undefined, _AR_PLANE);
    if (!current()) return;
    const tenant = organization?.body?.tenant_id;
    if (!organization?.ok || organization.status !== 200 || !arReadObject(organization.body) ||
        typeof tenant !== "string" || tenant.trim() !== tenant || (selection && selection !== tenant)) throw new Error();
    rolloutTenant = tenant;
    const scope = deployment ? "deployment" : tenant;
    const updates = await apiFetch("GET", "/admin/agent-updates?expected_tenant_id=" + encodeURIComponent(scope), undefined, _AR_PLANE);
    if (!current()) return;
    catalogue = arCatalogueBody(updates, scope);
    try {
      const floor = await apiFetch("GET", "/admin/agent-update-sign-floor?expected_tenant_id=" + encodeURIComponent(scope), undefined, _AR_PLANE);
      if (!current()) return;
      signing = arSigningBody(floor, scope);
    } catch (_) { signing = null; }
  } catch (_) {
    if (!current()) return;
    uiState(host, "error", arReleaseReadError(), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderAgentReleaseList(host) });
    return;
  }
  if (!current()) return;

  let plan = null, planUnread = false;
  try {
    const r = await apiFetch("GET", "/admin/agent-rollout?expected_tenant_id=" + encodeURIComponent(rolloutTenant), undefined, _AR_PLANE);
    if (!current()) return;
    plan = arRolloutPlanBody(r, rolloutTenant);
  } catch (_) { planUnread = true; }
  if (!current()) return;

  // Which groups devices ACTUALLY carry. A rollout order naming groups nothing is in is a schedule that
  // applies to nobody, and that is invisible from the schedule itself.
  let groupsInUse = [];
  try {
    const g = await apiFetch("GET", "/admin/enrolled-devices", undefined, _AR_PLANE);
    const seen = {};
    ((g.body && (g.body.devices || g.body.entries)) || []).forEach((d) => {
      const name = ((d && d.group) || "").trim();
      if (name) seen[name] = true;
    });
    groupsInUse = Object.keys(seen).sort();
  } catch (e) {
    groupsInUse = [];
  }

  const published = catalogue.envelopes, pending = catalogue.pending;
  const floors = signing?.floors || {};
  const signingKey = signing?.signing_public_key;
  if (!current()) return;
  window._arLastPublished = published; // so the form can reuse the address this target used last time
  host.innerHTML = "";

  if (planUnread) host.appendChild(el("div", { class: "ui-state ui-state-error" }, [
    el("p", { text: arRolloutReadError() }),
    el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Retry", ja: "再試行" }), onClick: () => { if (current()) renderAgentReleaseList(host); } }),
  ]));

  // ★ SAID BEFORE THE TABLE, NOT AFTER A FAILED ATTEMPT. A control plane with no signing key cannot publish
  // from this screen at all, and finding that out by filling in a form and pressing the button is the version
  // of this that wastes an operator's afternoon.
  window._arCanSign = signing ? signingKey !== "no" : undefined;
  window._arReleaseReadContext = { host, current, scope: catalogue.tenant_id, signingKnown: signing !== null, canSign: window._arCanSign };
  if (!signing) host.appendChild(el("div", { class: "ui-state ui-state-warn" }, [
    el("p", { text: arSigningReadError() }),
    el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Retry", ja: "再試行" }), onClick: () => { if (current()) renderAgentReleaseList(host); } }),
  ]));
  // ★★ AND IT IS SAID ONLY TO WHOEVER CAN ACT ON IT (2026-08-28, caught the same day it was written). The
  // sentence below tells the reader to sign a manifest with the deployment's key and choose the file "below" —
  // and the form it names is rendered only for the operator, because publishing is the operator's. A customer
  // administrator was being given an instruction with no control anywhere on their screen, which is the exact
  // shape this file's own comment above the Publish button warns about.
  //
  // What an organization needs from this screen is which version its devices are being offered. That the
  // deployment cannot sign is the operator's problem to fix and nobody else's to read.
  if (signing && !window._arCanSign && answeringForTheDeployment()) {
    // ★★★ IT SAID "NOTHING CAN BE PUBLISHED FROM HERE" AND THAT WAS NOT TRUE (2026-08-28, measured on a
    // deployment this product's own installer built). The signing key has NO on-disk fallback by design — it
    // belongs in a token — so a control plane without one cannot SIGN. Publishing an envelope signed elsewhere
    // is the route the product was designed around and this screen accepts it. The old sentence sent every
    // operator of a file-key deployment to a terminal to find out, which is the risk this lane removed.
    host.appendChild(el("div", { class: "ui-state ui-state-warn" }, [
      el("strong", { text: bl({
        en: "This control plane holds no signing key, so it cannot sign a release here.",
        ja: "この管理サーバーは署名鍵を持たないため、ここで署名はできません。" }) }),
      el("p", { class: "ui-view-desc", text: bl({
        en: "Publish a release that was signed elsewhere instead: sign the manifest with this deployment's " +
            "update-signing key — the one kept out of every node, in the deployment's authority directory — " +
            "and choose the signed file below alongside the package. Everything after that is the same.",
        ja: "他所で署名したリリースを公開してください。この配備の更新署名鍵（どのノードにも置かず、" +
            "配備を運用する側だけが持つ鍵）でマニフェストに署名し、下の画面でパッケージと一緒に" +
            "署名済みファイルを選びます。その先は同じです。" }) }),
    ]));
  }

  const rows = _AR_TARGETS.map((target) => {
    const key = arTargetKey(target.platform, target.arch);
    const active = arManifestOf(published[key]);
    const waiting = arManifestOf(pending[key]);

    let badge, version, second = null;
    if (waiting) {
      version = waiting.version || "—";
      badge = uiBadge(bl({ en: "Waiting for the package", ja: "パッケージ待ち" }), "warn");
      // What devices are getting RIGHT NOW, which is the previous release — the single most misread thing on
      // a screen like this.
      second = el("div", { class: "ui-muted", text: active
        ? bl({ en: "devices still get " + (active.version || "—"), ja: "端末は現在 " + (active.version || "—") + " を取得中" })
        : bl({ en: "devices are getting nothing yet", ja: "端末にはまだ何も配布されていません" }) });
    } else if (active) {
      version = active.version || "—";
      badge = uiBadge(bl({ en: "Being distributed", ja: "配布中" }), "ok");
    } else {
      version = "—";
      badge = uiBadge(bl({ en: "Nothing published", ja: "未公開" }), "off");
    }

    const floorFor = floors[key];
    let downloading = false;
    const download = active ? el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Download", ja: "ダウンロード" }) }) : null;
    if (download) download.addEventListener("click", async () => {
      if (downloading || !current()) return;
      downloading = true; download.disabled = true;
      try { await arDownloadArtifact(target.platform, target.arch, active, { current, scope: catalogue.tenant_id, manifestSHA256: published[key].payload_sha256 }); }
      finally { downloading = false; if (current()) download.disabled = false; }
    });
    return el("tr", {}, [
      el("td", {}, [el("div", { text: arTargetLabel(target.platform, target.arch) })]),
      el("td", {}, [el("div", { text: version }), second].filter(Boolean)),
      el("td", {}, badge),
      el("td", { class: "ui-muted", text: active && active.not_after ? uiWhen(active.not_after) : "—" }),
      el("td", { class: "ui-muted", text: !signing ? bl({ en: "Unknown", ja: "不明" }) : floorFor
        ? bl({ en: "no older than " + floorFor, ja: floorFor + " より古いものは不可" })
        : "—" }),
      // ★ THE FIRST INSTALL HAS NO OTHER SOURCE. A device with no agent cannot use the device-facing route —
      // it has no transport identity yet — so without this the operator is told to install something the
      // product never hands them. Only an ACTIVE release: a manifest whose package has not arrived would
      // download nothing and look like a broken button.
      el("td", {}, download || el("span", { class: "ui-muted", text: "—" })),
    ]);
  });

  // ★ THE TIMING RULE IS SHOWN ABOVE THE VERSIONS, because "why has this device not updated" is answered here
  // at least as often as by the version table: a fleet on mains-power-only with nothing plugged in is not
  // behind, it is waiting.
  const w = plan && plan.window;
  host.appendChild(el("div", { class: "ui-toolbar" }, [
    el("div", {}, [
      el("div", { class: "ui-muted", text: bl({ en: "When updates may install", ja: "更新してよいとき" }) }),
      el("div", { text: plan === null
        ? bl({ en: "could not be read", ja: "読み取れませんでした" })
        : arWindowSummary(w) }),
    ]),
    el("span", { class: "ui-spacer" }),
    el("button", {
      class: "ui-btn ui-btn-sm",
      disabled: plan === null ? "disabled" : undefined,
      text: bl({ en: "Change", ja: "変更" }),
      onClick: () => { if (current() && plan !== null) openAgentWindowForm(host, w, { tenant: rolloutTenant, current }); },
    }),
  ]));

  // ★★★ WHICH VERSION THIS TENANT RUNS, WHICH IS THEIRS AND HAD NO SCREEN (2026-08-28). The operator decides
  // which versions EXIST — a tenant holds neither the vendor's signing identity nor this deployment's
  // update-signing key, so it cannot mint one. Choosing among the versions offered to it is the other half,
  // and it is the tenant's: their plan has carried the field for months, the device-facing manifest route now
  // reads it, and until this row there was nowhere to set it but a hand-written PUT.
  host.appendChild(el("div", { class: "ui-toolbar" }, [
    el("div", {}, [
      el("div", { class: "ui-muted", text: bl({ en: "The version this tenant runs", ja: "このテナントが動かすバージョン" }) }),
      el("div", { text: plan === null
        ? bl({ en: "could not be read", ja: "読み取れませんでした" })
        : arRunningSummary(plan, published) }),
    ]),
    el("span", { class: "ui-spacer" }),
    el("button", {
      class: "ui-btn ui-btn-sm",
      disabled: plan === null ? "disabled" : undefined,
      text: bl({ en: "Change", ja: "変更" }),
      onClick: () => { if (current() && plan !== null) openAgentVersionForm(host, plan, published, { tenant: rolloutTenant, current }); },
    }),
  ]));

  host.appendChild(el("div", { class: "ui-toolbar" }, [
    el("div", {}, [
      el("div", { class: "ui-muted", text: bl({ en: "Rollout order", ja: "配布の順番" }) }),
      el("div", { text: plan === null
        ? bl({ en: "could not be read", ja: "読み取れませんでした" })
        : arWavesSummary(plan.waves) }),
    ]),
    el("span", { class: "ui-spacer" }),
    el("button", {
      class: "ui-btn ui-btn-sm",
      disabled: plan === null ? "disabled" : undefined,
      text: bl({ en: "Change", ja: "変更" }),
      onClick: () => { if (current() && plan !== null) openAgentWavesForm(host, plan.waves, groupsInUse, { tenant: rolloutTenant, current }); },
    }),
  ]));

  host.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [
      el("th", { text: bl({ en: "Devices", ja: "端末" }) }),
      el("th", { text: bl({ en: "Version", ja: "バージョン" }) }),
      el("th", { text: bl({ en: "State", ja: "状態" }) }),
      el("th", { text: bl({ en: "Stops being offered", ja: "配布終了" }) }),
      el("th", { text: bl({ en: "Minimum version to sign", ja: "署名できる最低バージョン" }) }),
      el("th", { text: bl({ en: "The installer", ja: "インストーラ" }) }),
    ])),
    el("tbody", {}, rows),
  ]));

  // ★★★ AND THE CONNECTOR PROGRAM HAD NO SCREEN AT ALL (2026-09-06, found by walking a connector onto a
  // machine in a customer's own network). Add connector lists only what this deployment holds, and when it
  // holds nothing for that machine's platform it says so plainly and ends with "ask whoever runs this
  // deployment to add one". The person asked is the operator — and the operator, on their own screens, had
  // nowhere to add one either. The API's refusal names the remedy as an HTTP call:
  //
  //	404 this deployment holds no connector program for linux-amd64: an operator publishes one
  //	    with PUT /admin/connector-program
  //
  // A deployment seeds ONE program from its own image, its own architecture and no other, so a branch office
  // on a different architecture is the ordinary case and not an edge one. This is the same chain that pointed
  // at itself on the device lane this morning, one screen along.
  if (answeringForTheDeployment()) {
    host.appendChild(arConnectorProgramsSection());
  }
}

// arConnectorProgramsSection lists what this deployment can put on a connector machine, and lets the operator
// add one. The bytes live with the authority, like agent artifacts, so both calls are control-plane.
function arConnectorProgramsSection() {
  const card = el("div", { class: "ui-card", style: "margin-top:18px" });
  card.appendChild(el("strong", { text: bl({ en: "Connector programs", ja: "コネクタのプログラム" }) }));
  card.appendChild(el("div", { class: "ui-view-desc", text: bl({
    en: "What an administrator can put on a machine in a customer's own network, from Sites → Add connector. "
      + "This deployment seeded one from its own image — its own architecture, and no other — so a location "
      + "on a different one has nothing to install until it is added here.",
    ja: "顧客側のネットワークにあるマシンへ、管理者が「サイト → コネクタを追加」から置けるものです。この配備は"
      + "自身のイメージから1つだけ用意しています（自身のアーキテクチャのみ）。異なるものを使う拠点は、ここで"
      + "追加するまで導入するものがありません。" }) }));
  const list = el("div", { style: "margin-top:8px" });
  card.appendChild(list);

  const refresh = async () => {
    list.innerHTML = "";
    const programs = await connectorProgramsFetch();
    if (!programs.length) {
      list.appendChild(el("div", { class: "ui-view-desc", text: bl({
        en: "None yet — no location can install a connector until one is added.",
        ja: "まだありません。1つ追加するまで、どの拠点もコネクタを導入できません。" }) }));
    }
    for (const p of programs) {
      list.appendChild(el("div", { style: "margin-top:4px" }, [
        el("code", { text: p.platform + " / " + p.arch }),
        el("span", { style: "margin-left:10px", class: "ui-view-desc", text: connectorProgramSize(p.size) }),
        el("span", { style: "margin-left:10px", class: "ui-view-desc",
          text: p.version ? bl({ en: "build " + p.version, ja: "ビルド " + p.version })
                          : bl({ en: "build not stated", ja: "ビルド不明" }) }),
      ]));
    }
  };
  refresh();

  const fileF = el("input", { class: "ui-input", type: "file", style: "max-width:340px" });
  const pairF = el("select", { class: "ui-input", style: "max-width:200px" });
  for (const t of ["linux/amd64", "linux/arm64"]) pairF.appendChild(el("option", { value: t, text: t }));
  const verF = el("input", { class: "ui-input", type: "text", style: "max-width:200px", placeholder: "0.3.0+9d0ccdb" });
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Add it", ja: "追加する" }) });
  submit.addEventListener("click", async () => {
    const file = fileF.files && fileF.files[0];
    if (!file) { uiToast(bl({ en: "Choose the program first.", ja: "先にプログラムを選んでください。" }), "err"); return; }
    submit.disabled = true;
    try {
      // ★ THE DIGEST IS COMPUTED HERE AND DECLARED, because the route refuses an upload without one: without
      // something to check against it is a place to stage anything and call it published. A truncated upload
      // is then refused at the deployment rather than carried to a machine and run.
      const bytes = await file.arrayBuffer();
      const sum = await crypto.subtle.digest("SHA-256", bytes);
      const digest = [...new Uint8Array(sum)].map((b) => b.toString(16).padStart(2, "0")).join("");
      const [platform, arch] = String(pairF.value).split("/");
      const r = await arUploadConnectorProgram(bytes, platform, arch, digest, String(verF.value || "").trim());
      if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
      uiToast(bl({ en: "Added. A location on " + platform + "/" + arch + " can install a connector now.",
                   ja: "追加しました。" + platform + "/" + arch + " の拠点はコネクタを導入できます。" }), "ok");
      fileF.value = "";
      refresh();
    } catch (e) {
      uiToast(String(e && e.message || e), "err");
    } finally {
      submit.disabled = false;
    }
  });
  card.appendChild(el("div", { style: "display:flex;align-items:center;gap:10px;margin-top:12px;flex-wrap:wrap" },
    [fileF, pairF, verF, submit]));
  card.appendChild(el("div", { class: "ui-field-hint", style: "margin-top:4px", text: bl({
    en: "The build is optional and worth stating: -verify asks whether every node runs the same build, and a "
      + "connector installed from a program nobody could name is outside that question.",
    ja: "ビルドの記入は任意ですが、書く価値があります。-verify は全ノードが同じビルドかを問うので、名前の無い"
      + "プログラムから入れたコネクタはその問いの外に出ます。" }) }));
  return card;
}

// arUploadConnectorProgram publishes the bytes. Raw, like the agent artifact beside it, and for the same
// reason: apiFetch sends JSON and this is a file.
async function arUploadConnectorProgram(bytes, platform, arch, digest, version) {
  const base = baseForPlane(_AR_PLANE);
  const token = localStorage.getItem("adminToken") || "";
  const signedIn = idpSession && idpSession.auth_method === "admin_session";
  const headers = { "content-type": "application/octet-stream", "x-artifact-sha256": digest };
  if (version) headers["x-artifact-version"] = version;
  if (!signedIn && token) headers["authorization"] = "Bearer " + token;
  if (signedIn && idpSession.csrf_token) headers["x-csrf-token"] = idpSession.csrf_token;
  if (operateTenant) headers["x-operate-tenant"] = operateTenant;
  const path = "/admin/connector-program?platform=" + encodeURIComponent(platform) +
    "&arch=" + encodeURIComponent(arch);
  try {
    const res = await fetch(base + path, { method: "PUT", headers, credentials: "include", body: bytes });
    const text = await res.text();
    let parsed;
    try { parsed = JSON.parse(text); } catch (e) { parsed = text; }
    return { ok: res.ok, status: res.status, body: parsed };
  } catch (e) {
    return { ok: false, status: 0, body: { error: String(e) } };
  }
}

// arRunningSummary says, in one line, what this tenant's devices are being offered and why.
//
// ★ THE TWO STATES ARE NOT "SET" AND "UNSET". Following what the deployment offers is a choice with a
// consequence — this tenant moves when the operator publishes — and naming a version is a different one. A
// summary that said "not set" for the first would describe the ordinary state as a gap.
function arRunningSummary(plan, published) {
  if (plan?.frozen) return bl({ en: "Updates paused", ja: "更新を停止中" }) +
    (plan.reason ? ": " + plan.reason : "") + " · " + arRunningSummary({ ...plan, frozen: false }, published);
  const want = plan && String(plan.desired_version || "").trim();
  const offered = Object.keys(published || {}).map((k) => {
    const m = arManifestOf(published[k]);
    return m && m.version;
  }).filter(Boolean);
  if (!want) {
    return offered.length
      ? bl({ en: "whatever this deployment offers — now " + offered.join(", "),
             ja: "この配備が提供するもの — 現在 " + offered.join(", ") })
      : bl({ en: "whatever this deployment offers", ja: "この配備が提供するもの" });
  }
  // ★ AND A NAMED VERSION NOTHING PUBLISHES IS A HOLD, said as one. It is a legitimate thing to do — it keeps
  // a fleet where it is — and it is not the same as being up to date, so it must not read like it.
  if (offered.length && !offered.some((v) => v.toLowerCase() === want.toLowerCase())) {
    return bl({ en: want + " — held here; this deployment offers " + offered.join(", ") + ", and these devices are not moved onto it",
                ja: want + " — ここで留めています。この配備が提供しているのは " + offered.join(", ") + " ですが、端末はそこへ移されません" });
  }
  return bl({ en: want + " — named by this tenant", ja: want + " — このテナントが指定" });
}

// openAgentVersionForm lets a tenant say which version its own fleet runs.
//
// ★ IT OFFERS WHAT IS PUBLISHED AND ACCEPTS ANY VERSION. Choosing from the list is the ordinary act; typing
// one that is not offered is how a fleet is HELD where it is, deliberately, and refusing that would take away
// the one control a tenant has when a release is going badly.
function openAgentVersionForm(host, plan, published, context) {
  const offered = Object.keys(published || {}).map((k) => {
    const m = arManifestOf(published[k]);
    return m && m.version;
  }).filter(Boolean);
  const current = (plan && String(plan.desired_version || "").trim()) || "";
  const followF = el("input", { type: "radio", name: "ar-version" });
  const nameF = el("input", { type: "radio", name: "ar-version" });
  followF.checked = current === "";
  nameF.checked = current !== "";
  const versionF = uiField({
    name: "version", label: bl({ en: "Version", ja: "バージョン" }), value: current,
    placeholder: offered[0] || "0.3.0",
    hint: offered.length
      ? bl({ en: "Offered now: " + offered.join(", "), ja: "現在提供中: " + offered.join(", ") })
      : bl({ en: "Nothing is published yet.", ja: "まだ何も公開されていません。" }),
  });
  arRolloutDialog({ host, context,
    title: bl({ en: "The version this tenant runs", ja: "このテナントが動かすバージョン" }),
    body: [
      el("div", { class: "ui-field" }, [
        el("label", { class: "ui-check" }, [followF, document.createTextNode(" " + bl({
          en: "Follow what this deployment offers", ja: "この配備が提供するものに従う" }))]),
        el("div", { class: "ui-field-hint", text: bl({
          en: "These devices move when a new version is published for them.",
          ja: "新しいバージョンが公開されると、端末はそこへ移ります。" }) }),
        el("label", { class: "ui-check" }, [nameF, document.createTextNode(" " + bl({
          en: "Run a version we name", ja: "指定したバージョンを動かす" }))]),
        el("div", { class: "ui-field-hint", text: bl({
          en: "These devices stay on it. Naming one this deployment does not publish holds them where they are — " +
              "which is what to do while a release is going badly.",
          ja: "端末はそのバージョンに留まります。この配備が公開していないバージョンを指定すると、端末はいまの場所に" +
              "留まります — リリースの調子が悪いときはこれを使います。" }) }),
      ]),
      versionF.el,
    ],
    request: () => {
      const want = nameF.checked ? versionF.get().trim() : "";
      if (nameF.checked && !want) {
        versionF.setError(bl({ en: "Name the version, or follow what is offered.",
                               ja: "バージョンを入力するか、提供されるものに従ってください。" }));
        return;
      }
      return want ? { intent: "rollout", desired_version: want } : { intent: "follow" };
    },
  });
  (nameF.checked ? versionF : { focus: () => followF.focus() }).focus();
}

// The external manifest names the upload target and version. Match its declared
// bytes against the selected package before asking the authority to verify and
// publish its signature. This is not browser-side signature verification.
function arSignedPackage(env, file, digest) {
  const m = arManifestOf(env);
  if (!arReadObject(m) || !arKnownTarget(arTargetKey(m.platform, m.arch)) ||
      typeof m.version !== "string" || !m.version.trim() || !Number.isSafeInteger(m.artifact_size) ||
      m.artifact_size <= 0 || m.artifact_size !== file.size || typeof m.artifact_sha256 !== "string" ||
      m.artifact_sha256.toLowerCase() !== digest.toLowerCase()) {
    throw new Error(bl({
      en: "The signed file must name a supported target and version, and its package size and digest must match the selected file.",
      ja: "署名済みファイルの対象端末・バージョンを確認してください。パッケージのサイズとハッシュ値は、選んだファイルとの一致が必要です。" }));
  }
  return m;
}

// Match the acknowledged scope and package before continuing the two-step
// publication. HTTP success alone is not confirmation of the requested release.
function arPublicationAck(response, scope, manifest, expectedHash) {
  const b = arReleaseResponse(response, "admin_agent_updates.v1", scope), p = b.published;
  if (!arReadObject(p) || p.platform !== manifest.platform || p.arch !== manifest.arch || p.version !== manifest.version ||
      p.artifact_size !== manifest.artifact_size || typeof p.artifact_sha256 !== "string" ||
      p.artifact_sha256.toLowerCase() !== manifest.artifact_sha256.toLowerCase() ||
      !/^[a-f0-9]{64}$/.test(b.manifest_sha256) || !["pending", "active"].includes(b.state) ||
      (expectedHash !== undefined && (typeof expectedHash !== "string" || b.manifest_sha256 !== expectedHash.toLowerCase()))) throw new Error();
  return b.manifest_sha256;
}
function arArtifactAck(response, scope, manifest, manifestSHA256) {
  const b = arReleaseResponse(response, "admin_agent_updates.v1", scope), p = b.stored;
  if (!arReadObject(p) || p.platform !== manifest.platform || p.arch !== manifest.arch || p.version !== manifest.version ||
      p.bytes !== manifest.artifact_size || typeof p.artifact_sha256 !== "string" ||
      p.artifact_sha256.toLowerCase() !== manifest.artifact_sha256.toLowerCase() ||
      b.manifest_sha256 !== manifestSHA256 || b.active !== true || typeof b.activated !== "boolean") throw new Error();
}

// ★ THE FORM IS THE SCREEN'S REASON TO EXIST. A page that shows what is published and cannot publish sends the
// reader back to a terminal — which is exactly where the risk this lane was built to remove lives.
function openAgentReleaseForm(host) {
  if (window._arReleaseDialog?.active()) return;
  const read = window._arReleaseReadContext;
  if (!read || read.host !== host || !read.current() || !read.signingKnown || typeof read.scope !== "string") {
    uiToast(arReleaseReadError(), "err");
    return;
  }
  let chosen = null;
  const canSign = read.canSign === true;

  const fileInput = el("input", { class: "ui-input", type: "file", accept: ".pkg,.msi" });
  const fileField = el("div", { class: "ui-field" }, [
    el("label", { class: "ui-field-label" }, [bl({ en: "Package file", ja: "パッケージファイル" }),
      el("span", { class: "ui-field-req", text: "*" })]),
    fileInput,
    el("span", { class: "ui-field-hint", text: bl({
      en: "The file is checked here and sent as it is. Nothing is typed about it.",
      ja: "ファイルはこの画面で確認され、そのまま送信されます。内容を手入力する項目はありません。" }) }),
  ]);

  // The release signed somewhere this control plane's key is not. Required when it holds no signer, and
  // available even when it does: a deployment moving its key into a token should not have to change screens.
  let chosenEnvelope = null;
  const envInput = el("input", { class: "ui-input", type: "file", accept: ".json" });
  const envField = el("div", { class: "ui-field" }, [
    el("label", { class: "ui-field-label" }, [
      bl({ en: "Signed release file", ja: "署名済みリリースファイル" }),
      canSign ? el("span", { class: "ui-field-hint", text: bl({ en: " (optional)", ja: "（任意）" }) })
                        : el("span", { class: "ui-field-req", text: "*" })]),
    envInput,
    el("span", { class: "ui-field-hint", text: bl({
      en: "Signed away from this control plane, with the key no node holds. What it says about the package is " +
          "checked against the package you chose before anything is published.",
      ja: "どのノードも持たない鍵で、この管理サーバーの外で署名したものです。その内容が選んだパッケージと一致するかを、" +
          "公開の前にこの画面で確認します。" }) }),
  ]);
  envInput.addEventListener("change", () => {
    chosenEnvelope = envInput.files && envInput.files[0];
  });

  const targetF = uiField({
    name: "target", label: bl({ en: "Which devices", ja: "対象の端末" }), type: "select",
    value: arTargetKey("darwin", "arm64"),
    options: _AR_TARGETS.map((t) => ({ value: arTargetKey(t.platform, t.arch), label: bl(t.t) })),
  });

  const versionF = uiField({
    name: "version", label: bl({ en: "Version", ja: "バージョン" }), required: true, placeholder: "0.3.0",
    hint: bl({ en: "What the agent will report once it has updated.", ja: "更新後にエージェントが報告するバージョンです。" }),
  });

  const urlF = uiField({
    name: "url", label: bl({ en: "Where devices download it", ja: "端末のダウンロード先" }), required: true,
    placeholder: "https://…/steer/agent-update-artifact?platform=darwin&arch=arm64",
    hint: bl({
      en: "Typed once per kind of device; it is filled in from last time after that.",
      ja: "端末の種類ごとに一度だけ入力すれば、次回からは前回の値が入ります。" }),
  });

  // Filling in from the file is the point of choosing it first: the version and the target are in its name,
  // and the address was used last time for that target.
  fileInput.addEventListener("change", () => {
    chosen = fileInput.files && fileInput.files[0];
    if (!chosen) return;
    const v = arGuessVersion(chosen.name);
    if (v && !versionF.get()) versionF.set(v);
    const t = arGuessTarget(chosen.name);
    if (t) targetF.set(arTargetKey(t.platform, t.arch));
    const prev = arManifestOf((window._arLastPublished || {})[targetF.get()]);
    if (prev && prev.artifact_url && !urlF.get()) urlF.set(prev.artifact_url);
  });

  targetF.el.addEventListener("change", () => {
    const prev = arManifestOf((window._arLastPublished || {})[targetF.get()]);
    if (prev && prev.artifact_url) urlF.set(prev.artifact_url);
  });

  let pending = false, closed = false, staged = null, observer;
  const progress = el("div", { class: "ui-muted", role: "status" });
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Publish", ja: "公開" }) });
  const close = () => {
    if (closed) return;
    closed = true; observer?.disconnect(); backdrop.remove(); document.removeEventListener("keydown", onKey);
    if (window._arReleaseDialog === controller) delete window._arReleaseDialog;
  };
  const active = () => {
    if (closed) return false;
    if (host.isConnected === false || !read.current()) { close(); return false; }
    return true;
  };
  const cancel = el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => { if (!pending) close(); } });
  const onKey = e => { if (e.key === "Escape" && !pending) close(); };
  const backdrop = el("div", { class: "ui-modal-backdrop", onClick: e => { if (e.target === backdrop && !pending) close(); } }, [
    el("div", { class: "ui-modal", role: "dialog" }, [
      el("div", { class: "ui-modal-head", text: bl({ en: "Publish a version", ja: "バージョンを公開" }) }),
      el("div", { class: "ui-modal-body" }, [fileField, envField, targetF.el, versionF.el, urlF.el, progress]),
      el("div", { class: "ui-modal-foot" }, [cancel, submit]),
    ]),
  ]);
  const controller = { active };
  window._arReleaseDialog = controller;
  const lock = () => {
    backdrop.querySelectorAll("input,select,textarea").forEach(n => { n.disabled = pending || staged !== null; });
    cancel.disabled = submit.disabled = pending;
    submit.textContent = staged
      ? bl({ en: "Retry package", ja: "パッケージ送信を再試行" })
      : bl({ en: "Publish", ja: "公開" });
  };
  document.body.appendChild(backdrop); document.addEventListener("keydown", onKey);
  submit.addEventListener("click", async () => {
    if (!active() || pending) return;
    // Capture this attempt before the first await; programmatic input changes
    // must not substitute another file even while the controls are disabled.
    const file = staged ? staged.file : chosen, signedFile = chosenEnvelope;
    let version = staged ? staged.manifest.version : versionF.get();
    const artifactURL = urlF.get(), parts = String(targetF.get()).split("/");
    if (!file) { uiToast(bl({ en: "Choose the package file.", ja: "パッケージファイルを選んでください。" }), "err"); return; }
    if (!staged && !canSign && !signedFile) {
      uiToast(bl({ en: "Choose the signed release file — this control plane cannot sign one.", ja: "署名済みリリースファイルを選んでください。この管理サーバーは署名できません。" }), "err"); return;
    }
    if (!staged && !signedFile && (!versionF.validate() || !urlF.validate())) return;
    pending = true; lock(); progress.setAttribute("role", "status");
    let sent = staged !== null, published = staged !== null;
    try {
      if (!staged) {
        progress.textContent = bl({ en: "Checking the package…", ja: "パッケージを確認中…" });
        const digest = await arHash(file);
        if (!active()) return;
        const now = new Date(), iso = d => d.toISOString().replace(/\.\d+Z$/, "Z");
        let envelope, manifest = { version, platform: parts[0], arch: parts[1], channel: "stable", delivery: "dsse",
          artifact_kind: parts[0] === "windows" ? "msi" : "pkg", artifact_url: artifactURL,
          artifact_sha256: digest, artifact_size: file.size, released_at: iso(now), not_after: iso(new Date(now.getTime() + 180 * 24 * 3600 * 1000)) };
        if (signedFile) {
          progress.textContent = bl({ en: "Checking the signed file…", ja: "署名済みファイルを確認中…" });
          try { envelope = JSON.parse(await signedFile.text()); }
          catch (_) { throw new Error(bl({ en: "That is not a signed release file.", ja: "署名済みリリースファイルではありません。" })); }
          if (!active()) return;
          manifest = arSignedPackage(envelope, file, digest); version = manifest.version;
        }
        if (!active()) return;
        progress.textContent = bl({ en: "Publishing…", ja: "公開中…" }); sent = true;
        const signed = await apiFetch(signedFile ? "PUT" : "POST", "/admin/agent-updates?expected_tenant_id=" + encodeURIComponent(read.scope), signedFile ? envelope : manifest, _AR_PLANE);
        if (!active()) return;
        const manifestSHA256 = arPublicationAck(signed, read.scope, manifest, signedFile ? envelope.payload_sha256 : undefined);
        published = true;
        // Keep the acknowledged file and manifest for this dialog. An upload retry
        // must not sign or publish again, or replace another writer's newer release.
        staged = { file, manifest, manifestSHA256 };
      }
      const { manifest, manifestSHA256 } = staged;
      progress.textContent = bl({ en: "Sending the package…", ja: "パッケージを送信中…" });
      const upload = await arUploadArtifact(file, manifest.platform, manifest.arch, { scope: read.scope, manifestSHA256 });
      if (!active()) return;
      arArtifactAck(upload, read.scope, manifest, manifestSHA256);
      close();
      uiToast(bl({ en: version + " is now what these devices are offered.", ja: version + " をこれらの端末に配布します。" }), "ok");
      renderAgentReleaseList(host);
    } catch (e) {
      if (!active()) return;
      if (!sent) { progress.textContent = ""; uiToast(e.message || String(e), "err"); }
      else {
        progress.setAttribute("role", "alert");
        progress.textContent = published
          ? bl({ en: version + " was published, but package delivery could not be confirmed. It may already be active. Retry package sends the same file without publishing again. If the release changed, cancel and reload before continuing.",
                 ja: version + " の公開後、パッケージ送信の結果を確認できません。すでに有効な可能性があります。「パッケージ送信を再試行」で同じファイルを送信します。再公開はしません。公開内容が変わった場合はキャンセルして再読込してください。" })
          : bl({ en: "Publication could not be confirmed. The release may already be saved. Retry with Publish, or cancel and reload before making another change.",
                 ja: "公開結果を確認できません。すでに保存済みの可能性があります。公開ボタンで再試行するか、キャンセルして再読込してから次の変更を行ってください。" });
      }
    } finally { pending = false; if (active()) lock(); }
  });
  observer = new MutationObserver(() => { active(); });
  observer.observe(document.body, { childList: true, subtree: true });
  active();
}
