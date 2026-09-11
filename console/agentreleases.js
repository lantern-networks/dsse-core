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

// The artifact upload is raw bytes, so it cannot go through apiFetch (which sends JSON). The session and the
// headers are built from the same globals rather than copied, so a change to how the Console authenticates
// does not leave this one call behind.
async function arUploadArtifact(file, platform, arch) {
  const base = baseForPlane(_AR_PLANE);
  const token = localStorage.getItem("adminToken") || "";
  const signedIn = idpSession && idpSession.auth_method === "admin_session";
  const headers = { "content-type": "application/octet-stream" };
  if (!signedIn && token) headers["authorization"] = "Bearer " + token;
  if (signedIn && idpSession.csrf_token) headers["x-csrf-token"] = idpSession.csrf_token;
  if (operateTenant) headers["x-operate-tenant"] = operateTenant;
  const path = "/admin/agent-update-artifact?platform=" + encodeURIComponent(platform) +
    "&arch=" + encodeURIComponent(arch);
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

// arDownloadArtifact hands the operator the package this deployment published.
//
// ★★★ A DEPLOYMENT COULD PUBLISH A RELEASE AND HAD NO WAY TO HAND ANYONE THE INSTALLER (2026-08-29, found by
// trying to put an agent on a Mac using only this Console). The device-facing route needs a verified device
// transport identity — which a machine that has no agent yet does not have — so the update path serves
// devices that are ALREADY enrolled and says nothing about the first install. The Device configuration screen
// hands out the profile and the tokens and tells the operator to "install this on the devices it is for",
// without ever giving them the thing to install. Every first install had to come from outside the product.
//
// The bytes were always reachable at GET /admin/agent-update-artifact, authenticated as the operator. What was
// missing was the button.
async function arDownloadArtifact(platform, arch, version) {
  const base = baseForPlane(_AR_PLANE);
  const token = localStorage.getItem("adminToken") || "";
  const signedIn = idpSession && idpSession.auth_method === "admin_session";
  const headers = {};
  if (!signedIn && token) headers["authorization"] = "Bearer " + token;
  if (signedIn && idpSession.csrf_token) headers["x-csrf-token"] = idpSession.csrf_token;
  if (operateTenant) headers["x-operate-tenant"] = operateTenant;
  const path = "/admin/agent-update-artifact?platform=" + encodeURIComponent(platform) +
    "&arch=" + encodeURIComponent(arch);
  const res = await fetch(base + path, { headers, credentials: "include" });
  if (!res.ok) {
    let why = "";
    try { why = (await res.text()).slice(0, 300); } catch (e) { why = ""; }
    uiToast(bl({ en: "Could not download it: " + (why || res.status),
                 ja: "取得できませんでした: " + (why || res.status) }), "err");
    return;
  }
  const blob = await res.blob();
  // The name says what it is and which deployment it came from, because an installer in a downloads folder
  // with a generic name is the one an operator installs on the wrong fleet.
  const ext = platform === "windows" ? "msi" : "pkg";
  const name = "dsse-agent-" + (version || "release") + "-" + platform + "-" + arch + "." + ext;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
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
function openAgentWindowForm(host, current) {
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

  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Save", ja: "保存" }) });
  const m = uiModal({
    title: bl({ en: "When updates may install", ja: "更新してよいとき" }),
    body: [startF.el, endF.el, acF.el, unattendedF.el, idleF.el, deadlineF.el, note],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit],
  });

  submit.addEventListener("click", async () => {
    const hhmm = /^([01]\d|2[0-3]):[0-5]\d$/;
    if (!hhmm.test(startF.get())) { startF.setError(bl({ en: "Use HH:MM, e.g. 01:00", ja: "HH:MM 形式で入力してください(例 01:00)" })); return; }
    if (!hhmm.test(endF.get())) { endF.setError(bl({ en: "Use HH:MM, e.g. 05:00", ja: "HH:MM 形式で入力してください(例 05:00)" })); return; }
    const idle = Number(idleF.get());
    const deadline = Number(deadlineF.get());
    if (!Number.isFinite(idle) || idle < 0) { idleF.setError(bl({ en: "A whole number of minutes.", ja: "分を整数で入力してください。" })); return; }
    if (!Number.isFinite(deadline) || deadline < 0) { deadlineF.setError(bl({ en: "A whole number of days.", ja: "日数を整数で入力してください。" })); return; }

    submit.disabled = true;
    // ★ intent=schedule, so the halt and the wave schedule are left exactly as they are. A form about timing
    // must not be able to release a fleet somebody stopped.
    const r = await apiFetch("PUT", "/admin/agent-rollout", {
      intent: "schedule",
      window: {
        local_start: startF.get(), local_end: endF.get(),
        require_idle_minutes: idle, require_unattended: unattendedF.get(),
        require_ac_power: acF.get(), deadline_days: deadline,
      },
    }, _AR_PLANE);
    if (!r.ok) {
      submit.disabled = false;
      startF.setError(arErrorText(r));
      uiToast(arErrorText(r), "err");
      return;
    }
    m.close();
    uiToast(bl({ en: "Saved. Devices pick it up on their next check.", ja: "保存しました。端末は次の確認時に反映します。" }), "ok");
    renderAgentReleaseList(host);
  });
}

// ★ THE ROLLOUT ORDER HAD NO SCREEN EITHER (2026-08-13). Same gap as the window, one object over: the plan
// carries a wave schedule, the Edge signs it, devices compute their own start from it — and the only way to
// author one was a hand-written PUT. Review 30 called it "the schedule an operator authored" while no operator
// could author one.
function arWavesSummary(waves) {
  const list = (waves && waves.waves) || [];
  if (!list.length) {
    return bl({ en: "everything at once, as soon as a release is published",
                ja: "公開と同時に全端末へ(段階分けなし)" });
  }
  const ordered = list.slice().sort((a, b) => (a.delay_days || 0) - (b.delay_days || 0));
  return ordered.map((w) => {
    const d = w.delay_days || 0;
    return d === 0
      ? bl({ en: w.group + " immediately", ja: w.group + " はすぐ" })
      : bl({ en: w.group + " after " + d + "d", ja: w.group + " は " + d + "日後" });
  }).join(" → ");
}

// openAgentWavesForm edits the rollout order and nothing else — intent=schedule again, so the halt and the
// window are untouched.
function openAgentWavesForm(host, current, groupsInUse) {
  const rows = ((current && current.waves) || []).map((w) => ({ group: w.group || "", days: String(w.delay_days || 0) }));
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
    en: "A device in several groups takes the SLOWEST of them. A group not listed here also takes the slowest " +
        "wave — so forgetting one delays it, it never causes a same-day rollout to everybody.",
    ja: "複数のグループに属する端末は、いちばん遅い方が適用されます。ここに無いグループも最も遅い波になります — " +
        "書き忘れは「遅れる」方に倒れ、全端末への即日展開にはなりません。" }) });

  const reality = el("div", { class: "ui-field-hint", text: groupsInUse.length
    ? bl({ en: "Groups your devices currently carry: " + groupsInUse.join(", "),
           ja: "いま端末が持っているグループ: " + groupsInUse.join("、") })
    : bl({ en: "★ No device carries a group yet, so a schedule here applies to nobody until devices are grouped.",
           ja: "★ いまグループを持つ端末がありません。端末にグループを付けるまで、この設定は誰にも当たりません。" }) });

  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Save", ja: "保存" }) });
  const m = uiModal({
    title: bl({ en: "Rollout order", ja: "配布の順番" }),
    body: [list, rules, reality],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit],
  });

  submit.addEventListener("click", async () => {
    const waves = [];
    for (const row of rows) {
      const group = (row.group || "").trim();
      if (!group) continue;
      const days = Number(row.days);
      if (!Number.isFinite(days) || days < 0) {
        uiToast(bl({ en: "Days must be a whole number, 0 or more.", ja: "日数は 0 以上の整数で入力してください。" }), "err");
        return;
      }
      waves.push({ group: group, delay_days: days });
    }
    if (!waves.length) {
      uiToast(bl({ en: "Name at least one group, or cancel to leave the order as it is.",
                   ja: "グループを1つ以上入力してください(変更しない場合はキャンセル)。" }), "err");
      return;
    }
    submit.disabled = true;
    const r = await apiFetch("PUT", "/admin/agent-rollout", { intent: "schedule", waves: { waves: waves } }, _AR_PLANE);
    if (!r.ok) {
      submit.disabled = false;
      uiToast(arErrorText(r), "err");
      return;
    }
    m.close();
    uiToast(bl({ en: "Saved. Devices pick it up on their next check.", ja: "保存しました。端末は次の確認時に反映します。" }), "ok");
    renderAgentReleaseList(host);
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
  uiState(host, "loading");
  const current = freshRender(host);
  let updates, floor;
  try {
    updates = await apiFetch("GET", "/admin/agent-updates", undefined, _AR_PLANE);
  } catch (e) {
    if (!current()) return;
    uiState(host, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderAgentReleaseList(host) });
    return;
  }
  if (!updates.ok) {
    if (!current()) return;
    uiState(host, "error", arErrorText(updates), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderAgentReleaseList(host) });
    return;
  }
  // The floor is a newer endpoint than the published set. A control plane without it must not blank this page
  // — but it must not be shown a floor it never reported either, so the column simply stays empty.
  try {
    floor = await apiFetch("GET", "/admin/agent-update-sign-floor", undefined, _AR_PLANE);
  } catch (e) {
    floor = { ok: false };
  }

  // The timing rule, read from the same control plane. Best-effort: a page about releases must not go blank
  // because the schedule could not be read, but it must not pretend there is no rule either.
  let plan = null;
  try {
    const r = await apiFetch("GET", "/admin/agent-rollout", undefined, _AR_PLANE);
    if (r.ok && r.body && r.body.plan) plan = r.body.plan;
  } catch (e) {
    plan = null;
  }

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

  const published = (updates.body && updates.body.envelopes) || {};
  const pending = (updates.body && updates.body.pending) || {};
  const floors = (floor && floor.ok && floor.body && floor.body.floors) || {};
  const signingKey = (floor && floor.ok && floor.body && floor.body.signing_public_key) || "";
  window._arLastPublished = published; // so the form can reuse the address this target used last time

  if (!current()) return;
  host.innerHTML = "";

  // ★ SAID BEFORE THE TABLE, NOT AFTER A FAILED ATTEMPT. A control plane with no signing key cannot publish
  // from this screen at all, and finding that out by filling in a form and pressing the button is the version
  // of this that wastes an operator's afternoon.
  window._arCanSign = !(!signingKey || signingKey === "no");
  // ★★ AND IT IS SAID ONLY TO WHOEVER CAN ACT ON IT (2026-08-28, caught the same day it was written). The
  // sentence below tells the reader to sign a manifest with the deployment's key and choose the file "below" —
  // and the form it names is rendered only for the operator, because publishing is the operator's. A customer
  // administrator was being given an instruction with no control anywhere on their screen, which is the exact
  // shape this file's own comment above the Publish button warns about.
  //
  // What an organization needs from this screen is which version its devices are being offered. That the
  // deployment cannot sign is the operator's problem to fix and nobody else's to read.
  if (!window._arCanSign && answeringForTheDeployment()) {
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

    const floorFor = floors[key] || floors["|" + key];
    return el("tr", {}, [
      el("td", {}, [el("div", { text: arTargetLabel(target.platform, target.arch) })]),
      el("td", {}, [el("div", { text: version }), second].filter(Boolean)),
      el("td", {}, badge),
      el("td", { class: "ui-muted", text: active && active.not_after ? uiWhen(active.not_after) : "—" }),
      el("td", { class: "ui-muted", text: floorFor
        ? bl({ en: "no older than " + floorFor, ja: floorFor + " より古いものは不可" })
        : "—" }),
      // ★ THE FIRST INSTALL HAS NO OTHER SOURCE. A device with no agent cannot use the device-facing route —
      // it has no transport identity yet — so without this the operator is told to install something the
      // product never hands them. Only an ACTIVE release: a manifest whose package has not arrived would
      // download nothing and look like a broken button.
      el("td", {}, active
        ? el("button", {
            class: "ui-btn ui-btn-sm",
            text: bl({ en: "Download", ja: "ダウンロード" }),
            onClick: () => arDownloadArtifact(target.platform, target.arch, active.version),
          })
        : el("span", { class: "ui-muted", text: "—" })),
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
      onClick: () => openAgentWindowForm(host, w),
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
      onClick: () => openAgentVersionForm(host, plan, published),
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
      onClick: () => openAgentWavesForm(host, plan && plan.waves, groupsInUse),
    }),
  ]));

  host.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [
      el("th", { text: bl({ en: "Devices", ja: "端末" }) }),
      el("th", { text: bl({ en: "Version", ja: "バージョン" }) }),
      el("th", { text: bl({ en: "State", ja: "状態" }) }),
      el("th", { text: bl({ en: "Stops being offered", ja: "配布終了" }) }),
      el("th", { text: bl({ en: "Can go back to", ja: "戻せる範囲" }) }),
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
function openAgentVersionForm(host, plan, published) {
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
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Save", ja: "保存" }) });
  const m = uiModal({
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
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit],
  });
  submit.addEventListener("click", async () => {
    const want = nameF.checked ? versionF.get().trim() : "";
    if (nameF.checked && !want) {
      versionF.setError(bl({ en: "Name the version, or follow what is offered.",
                             ja: "バージョンを入力するか、提供されるものに従ってください。" }));
      return;
    }
    submit.disabled = true;
    // intent=rollout carries the version and leaves the halt and the schedule alone — a form about WHICH
    // version must not release a fleet somebody stopped, for the same reason the window form says so.
    // ★ FOLLOWING IS ITS OWN ACT, not "rollout to nothing": rollout requires a version, so sending an empty one
    // was refused and the control was one-way — an organization could hold its fleet and never release it.
    const r = want
      ? await apiFetch("PUT", "/admin/agent-rollout", { intent: "rollout", desired_version: want }, _AR_PLANE)
      : await apiFetch("PUT", "/admin/agent-rollout", { intent: "follow" }, _AR_PLANE);
    if (!r.ok) {
      submit.disabled = false;
      versionF.setError(arErrorText(r));
      uiToast(arErrorText(r), "err");
      return;
    }
    m.close();
    uiToast(want
      ? bl({ en: "These devices run " + want + ".", ja: "端末は " + want + " を動かします。" })
      : bl({ en: "These devices follow what this deployment offers.", ja: "端末は配備が提供するものに従います。" }), "ok");
    renderAgentReleaseList(host);
  });
  (nameF.checked ? versionF : { focus: () => followF.focus() }).focus();
}

// ★ THE FORM IS THE SCREEN'S REASON TO EXIST. A page that shows what is published and cannot publish sends the
// reader back to a terminal — which is exactly where the risk this lane was built to remove lives.
function openAgentReleaseForm(host) {
  let chosen = null;

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
      window._arCanSign ? el("span", { class: "ui-field-hint", text: bl({ en: " (optional)", ja: "（任意）" }) })
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

  const progress = el("div", { class: "ui-muted" });
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Publish", ja: "公開" }) });
  const m = uiModal({
    title: bl({ en: "Publish a version", ja: "バージョンを公開" }),
    body: [fileField, envField, targetF.el, versionF.el, urlF.el, progress],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit],
  });

  submit.addEventListener("click", async () => {
    if (!chosen) {
      uiToast(bl({ en: "Choose the package file.", ja: "パッケージファイルを選んでください。" }), "err");
      return;
    }
    if (!window._arCanSign && !chosenEnvelope) {
      uiToast(bl({ en: "Choose the signed release file — this control plane cannot sign one.",
                   ja: "署名済みリリースファイルを選んでください。この管理サーバーは署名できません。" }), "err");
      return;
    }
    if (!chosenEnvelope && (!versionF.validate() || !urlF.validate())) return;
    const parts = String(targetF.get()).split("/");
    const platform = parts[0];
    const arch = parts[1];

    submit.disabled = true;
    progress.textContent = bl({ en: "Checking the package…", ja: "パッケージを確認中…" });
    let digest;
    try {
      digest = await arHash(chosen);
    } catch (e) {
      submit.disabled = false;
      progress.textContent = "";
      uiToast(String(e), "err");
      return;
    }

    const now = new Date();
    const iso = (d) => d.toISOString().replace(/\.\d+Z$/, "Z");
    const manifest = {
      // No schema field: the control plane stamps it when it signs, and a constant restated here is one more
      // place to be wrong. It was wrong — the first version of this file sent "schema_version" where the
      // document says "schema", and the endpoint refused it rather than signing a manifest with a field the
      // operator never meant to set. That refusal is the strict decode doing its job.
      version: versionF.get(),
      platform: platform,
      arch: arch,
      channel: "stable",
      delivery: "dsse",
      artifact_kind: platform === "windows" ? "msi" : "pkg",
      artifact_url: urlF.get(),
      artifact_sha256: digest,
      artifact_size: chosen.size,
      released_at: iso(now),
      // How long the DOCUMENT may be acted on — a bound on a stolen copy, not a support window. Set here
      // rather than asked: a field whose right answer is always "a few months" is a question that only
      // produces mistakes.
      not_after: iso(new Date(now.getTime() + 180 * 24 * 3600 * 1000)),
    };

    let signed;
    if (chosenEnvelope) {
      // ★★★ THE ENVELOPE MUST DESCRIBE THE BYTES BEING UPLOADED, AND THIS IS THE ONLY MOMENT BOTH ARE HERE.
      // A manifest signed for a different copy of the package publishes cleanly and is refused by every device
      // in the fleet at download time — days later, as "the update is broken", with the cause in no screen.
      // The signature itself is checked by the control plane, which is the only check that means anything; this
      // one is about which FILE, and only this screen is holding both.
      progress.textContent = bl({ en: "Checking the signed file…", ja: "署名済みファイルを確認中…" });
      let envelope;
      try {
        envelope = JSON.parse(await chosenEnvelope.text());
      } catch (e) {
        submit.disabled = false;
        progress.textContent = "";
        uiToast(bl({ en: "That is not a signed release file.", ja: "署名済みリリースファイルではありません。" }), "err");
        return;
      }
      const said = arManifestOf(envelope);
      if (!said) {
        submit.disabled = false;
        progress.textContent = "";
        uiToast(bl({ en: "That file carries no release manifest.",
                     ja: "そのファイルにリリースマニフェストが入っていません。" }), "err");
        return;
      }
      if (String(said.artifact_sha256 || "").toLowerCase() !== String(digest).toLowerCase()) {
        submit.disabled = false;
        progress.textContent = "";
        uiToast(bl({
          en: "The signed file describes a different package (" + String(said.artifact_sha256 || "—").slice(0, 12) +
              "…) than the one chosen. Publishing it would give every device a download it refuses.",
          ja: "署名済みファイルが指しているのは、選んだパッケージとは別のもの（" +
              String(said.artifact_sha256 || "—").slice(0, 12) + "…）です。このまま公開すると、" +
              "全端末がダウンロードを拒否します。" }), "err");
        return;
      }
      // The envelope names its own target and version; the form's are not consulted, so the two cannot disagree.
      progress.textContent = bl({ en: "Publishing…", ja: "公開中…" });
      signed = await apiFetch("PUT", "/admin/agent-updates", envelope, _AR_PLANE);
    } else {
      progress.textContent = bl({ en: "Signing…", ja: "署名中…" });
      signed = await apiFetch("POST", "/admin/agent-updates", manifest, _AR_PLANE);
    }
    if (!signed.ok) {
      submit.disabled = false;
      progress.textContent = "";
      const msg = arErrorText(signed);
      versionF.setError(msg);
      uiToast(msg, "err");
      return;
    }

    progress.textContent = bl({ en: "Sending the package…", ja: "パッケージを送信中…" });
    const up = await arUploadArtifact(chosen, platform, arch);
    if (!up.ok) {
      // ★ THE HALF-DONE STATE, NAMED. The manifest is stored and devices are still on the previous release.
      // The fix is to send the file again — NOT to publish again — and saying so is the difference between a
      // five-second retry and an operator inventing a version number to get unstuck.
      submit.disabled = false;
      progress.textContent = "";
      uiToast(bl({
        en: versionF.get() + " is published and waiting for its package — sending it failed (" + arErrorText(up) +
            "). Press Publish again with the same file; the version does not change.",
        ja: versionF.get() + " は公開済みでパッケージ待ちです。送信に失敗しました(" + arErrorText(up) +
            ")。同じファイルで再度「公開」してください。バージョンは変わりません。" }), "err");
      renderAgentReleaseList(host);
      return;
    }

    m.close();
    uiToast(bl({
      en: versionF.get() + " is now what these devices are offered.",
      ja: versionF.get() + " をこれらの端末に配布します。" }), "ok");
    renderAgentReleaseList(host);
  });
}
