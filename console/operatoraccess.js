"use strict";

// operatoraccess.js — what the operator may do inside THIS organization, seen and decided by the organization.
//
// ★★★ THE WHOLE ENVELOPE EXISTED WITH NO CUSTOMER-FACING SCREEN (2026-08-16, found by signing in as a customer
// administrator and looking for it). The multi-tenant design rests on the customer being able to see
// that the operator may run their organization, turn it off, and read every elevation over them. The API gave
// them all of it — measured as Northwind's administrator: GET /admin/operator-access 200 with fourteen
// elevation records, PUT /admin/operator-delegation 200 turning the delegation off and on again — and the only
// places it could be set were the operator's own checklist and the creation wizard. A control that only the
// party being controlled cannot reach is not a control.
//
// ★ SETTINGS, NOT DESCRIPTION. Each block states what the setting ENABLES in one line and carries the control
// that changes it. No prose paragraphs, no ids, no raw JSON.
//
// Backend (control plane):
//   GET /admin/operator-access                        -> {managed, elevation_requires_approval, elevations:[…]}
//   PUT /admin/operator-delegation                    {managed, elevation_requires_approval}
//   POST   /admin/operator-elevations/{id}/approve    (this organization approving)
//   DELETE /admin/operator-elevations/{id}            (this organization cutting one short)

const OPERATOR_ELEVATION_STATE = {
  active: { tone: "warn", t: { en: "In progress", ja: "実行中" } },
  awaiting_approval: { tone: "warn", t: { en: "Waiting for you", ja: "承認待ち" } },
  ended: { tone: "off", t: { en: "Ended", ja: "終了" } },
  expired: { tone: "off", t: { en: "Time ran out", ja: "時間切れ" } },
};

function renderOperatorAccessView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "Operator access", ja: "運営のアクセス" }) }),
      el("p", { class: "ui-view-desc", text: bl({
        en: "What the company that runs this service may do inside your tenant. You decide it here, and every time they use it is listed below.",
        ja: "このサービスを運用する会社が、あなたのテナントの中で何をできるか。ここで決めます。使われた記録は下に残ります。" }) }),
    ]),
    el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Reload", ja: "再読込" }), onClick: () => renderOperatorAccessView(content) }),
  ]));
  const host = el("div", {});
  content.appendChild(host);
  loadOperatorAccess(host, content);
}

async function loadOperatorAccess(host, content) {
  uiState(host, "loading");
  const current = freshRender(host);
  let data;
  try {
    const r = await apiFetch("GET", "/admin/operator-access", undefined, "control");
    if (!current()) return;
    if (!r.ok) {
      uiState(host, "error", "HTTP " + r.status, { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => loadOperatorAccess(host, content) });
      return;
    }
    data = r.body || {};
  } catch (e) {
    if (!current()) return;
    uiState(host, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => loadOperatorAccess(host, content) });
    return;
  }
  if (!current()) return;
  host.innerHTML = "";

  const reload = () => loadOperatorAccess(host, content);
  host.appendChild(operatorAccessSetting({
    on: !!data.managed,
    title: bl({ en: "Let them run this tenant", ja: "このテナントの運用を任せる" }),
    enables: bl({
      en: "They can change this tenant's settings as part of ordinary work. Anything irreversible still needs the separate, time-limited permission below.",
      ja: "日常の作業として、このテナントの設定を変更できます。取り消せない操作には、下の時間制限つきの許可が別に必要です。" }),
    // ★★ THIS SENTENCE WAS NOT TRUE (2026-08-18). It read "Nobody outside your tenant can change your
    // settings." — an absolute promise, on the one screen built to give a tenant control over exactly this.
    // The server's own comment on PUT /admin/operator-delegation says either side may write it and that the
    // operator sets it at onboarding, so a tenant that withdraws the delegation can have it re-granted.
    //
    // The replacement is not a softer sentence maintained by hand: `operator_may_enable` is computed on the
    // server by running the real guard, so if the grant is ever restricted to the tenant, the promise here
    // becomes true again on its own. Same lesson as the response key this file once invented — a screen that
    // states a rule the code does not enforce is worse than a screen that states nothing.
    whenOff: data.operator_may_enable === false
      ? bl({ en: "Nobody outside your tenant can change your settings.",
             ja: "テナントの外の人が、あなたの設定を変更することはありません。" })
      : bl({
        en: "Nobody outside your tenant is changing your settings right now. The company that runs this service can switch this back on — if they do, it shows here with who did it, and it is in the record below.",
        ja: "いまは、テナントの外の人があなたの設定を変更することはありません。このサービスを運用する会社は、これを入れ直すことができます。入れ直された場合は、実行者とともにここに表示され、下の記録にも残ります。" }),
    onLabel: bl({ en: "Allowed", ja: "任せている" }),
    offLabel: bl({ en: "Not allowed", ja: "任せていない" }),
    turnOn: bl({ en: "Let them run it", ja: "任せる" }),
    turnOff: bl({ en: "Stop letting them", ja: "任せるのをやめる" }),
    apply: (next) => apiFetch("PUT", "/admin/operator-delegation", { managed: next }, "control"),
    onDone: reload,
    footnote: operatorDelegationFootnote(data),
  }));

  host.appendChild(operatorAccessSetting({
    on: !!data.elevation_requires_approval,
    title: bl({ en: "Ask you before anything irreversible", ja: "取り消せない操作の前に、あなたに確認する" }),
    enables: bl({
      en: "They must wait for someone in your tenant to approve, every time, before an irreversible or tenant-wide action.",
      ja: "取り消せない操作やテナント全体に及ぶ操作の前に、毎回あなたのテナントの誰かが承認するまで待ちます。" }),
    whenOff: bl({
      en: "They can take those actions without waiting. You still see every one of them below, as it happens.",
      ja: "待たずに実行できます。実行された記録は、その都度そのまま下に残ります。" }),
    onLabel: bl({ en: "Asked first", ja: "確認する" }),
    offLabel: bl({ en: "Not asked", ja: "確認しない" }),
    turnOn: bl({ en: "Ask me first", ja: "確認するようにする" }),
    turnOff: bl({ en: "Do not ask", ja: "確認しないようにする" }),
    apply: (next) => apiFetch("PUT", "/admin/operator-delegation", { elevation_requires_approval: next }, "control"),
    onDone: reload,
  }));

  host.appendChild(el("h3", { class: "ui-view-title", style: "font-size:15px;margin-top:24px", text: bl({ en: "When they used it", ja: "使われた記録" }) }));
  const elevations = Array.isArray(data.elevations) ? data.elevations : [];
  if (!elevations.length) {
    const empty = el("div", {});
    host.appendChild(empty);
    uiState(empty, "empty", bl({ en: "They have never taken an irreversible action here.", ja: "取り消せない操作は、まだ一度も行われていません。" }));
    return;
  }
  host.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [
      bl({ en: "Started", ja: "開始" }), bl({ en: "Until", ja: "期限" }), bl({ en: "State", ja: "状態" }),
      bl({ en: "Approved", ja: "承認" }), "",
    ].map((x) => el("th", { text: x })))),
    el("tbody", {}, elevations.map((e) => operatorElevationRow(e, reload))),
  ]));
}

// operatorAccessSetting is one setting: what it is, what turning it on ENABLES, and the control that changes
// it. The state is a badge rather than a sentence, so the answer to "how is it now" is one glance.
function operatorAccessSetting(spec) {
  const button = el("button", {
    class: "ui-btn ui-btn-sm" + (spec.on ? "" : " ui-btn-primary"),
    text: spec.on ? spec.turnOff : spec.turnOn,
  });
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      const r = await spec.apply(!spec.on);
      if (!r.ok) { button.disabled = false; uiToast((r.body && r.body.error) || ("HTTP " + r.status), "err"); return; }
      uiToast(bl({ en: "Saved.", ja: "保存しました。" }), "ok");
      if (spec.onDone) spec.onDone();
    } catch (e) { button.disabled = false; uiToast(String(e), "err"); }
  });
  return el("div", { class: "ui-card", style: "padding:14px 16px;margin-bottom:12px" }, [
    el("div", { style: "display:flex;align-items:center;gap:10px" }, [
      el("strong", { text: spec.title }),
      uiBadge(spec.on ? spec.onLabel : spec.offLabel, spec.on ? "ok" : "off"),
      el("span", { style: "flex:1 1 auto" }),
      button,
    ]),
    el("div", { class: "ui-view-desc", style: "margin-top:6px", text: spec.on ? spec.enables : spec.whenOff }),
    ...(spec.footnote ? [spec.footnote] : []),
  ]);
}

// ★★ WHO LAST MOVED THIS, AND WHEN (2026-08-17, measured). Either side may write the standing delegation: the
// operator sets it at onboarding — necessary, since a brand-new organization has no administrator to grant it
// — and this organization can withdraw it. Which means the operator can also set it BACK, and measured live
// they can, in one call. This screen listed ELEVATIONS only, so a re-grant left no trace where the customer
// looks. A control you are told you hold, whose removal the other party can undo invisibly, is a control in
// name. The audit trail always had the event; the screen presenting the control now says it too.
function operatorDelegationFootnote(data) {
  const at = String(data.managed_changed_at || "").trim();
  if (!at) return null;
  // The person, not the id. The Edge resolves it across organizations because the one who moved this is
  // usually the operator, in another organization — an id the customer cannot resolve names nobody.
  const by = String(data.managed_changed_by_label || data.managed_changed_by || "").trim();
  const line = el("div", { class: "ui-view-desc", style: "margin-top:6px" }, [
    document.createTextNode(bl({ en: "Last changed ", ja: "最後の変更: " })
      + (typeof dsseFormatTime === "function" ? dsseFormatTime(at) : at)
      + (by ? bl({ en: " by ", ja: " / 実行者 " }) + by : "") + " "),
  ]);
  const open = el("button", { class: "ui-btn ui-btn-sm", style: "margin-left:8px",
    text: bl({ en: "See the record", ja: "記録を見る" }) });
  open.addEventListener("click", () => {
    // The audit log, narrowed to the delegation's own event — the same move the elevation rows make.
    try {
      if (typeof _laFilters === "object" && _laFilters) {
        _laFilters.q = "operator_delegation";
        _laFilters.from = ""; _laFilters.to = "";
      }
      // ★ "admin_audit" IS NOT A STREAM (2026-08-17, measured against the running server, which answers
      // `unknown admin log stream "admin_audit"`). The id is "audit" — which the elevation rows fifty lines
      // below already used, so this file named one thing two ways and only one of them worked. The button an
      // organization presses to see who moved its delegation landed on a stream the server refuses, and a
      // refused fetch renders as an empty screen: "nothing to see", on the screen opened to see it.
      if (typeof _laStream !== "undefined") _laStream = "audit";
    } catch (e) { /* the link is a convenience; the line above is the fact */ }
    renderGroup("audit");
  });
  line.appendChild(open);
  return line;
}

function operatorElevationRow(e, reload) {
  const state = e.state === "active" && e.approval_required && !e.approved_at ? "awaiting_approval" : e.state;
  const meta = OPERATOR_ELEVATION_STATE[state] || { tone: "off", t: { en: state || "—", ja: state || "—" } };
  const actions = [];
  if (state === "awaiting_approval") {
    actions.push(el("button", { class: "ui-btn ui-btn-sm ui-btn-primary", text: bl({ en: "Approve", ja: "承認する" }),
      onClick: () => operatorElevationAct("POST", "/admin/operator-elevations/" + encodeURIComponent(e.id) + "/approve", {}, reload) }));
  }
  if (state === "active" || state === "awaiting_approval") {
    actions.push(document.createTextNode(" "));
    // Ending one is the organization taking its permission back before the clock does. Only offered while
    // there is something to end: a finished elevation is a record, and a record is not editable.
    actions.push(el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Stop it now", ja: "今すぐ終了" }),
      onClick: () => operatorElevationAct("DELETE", "/admin/operator-elevations/" + encodeURIComponent(e.id), undefined, reload) }));
  }
  // ★ THE RECORD SAYS THEY WERE HERE; THE AUDIT LOG SAYS WHAT THEY DID. The elevation carries no stated
  // reason — deliberately, a typed justification is a box people fill in, not a control — so the answer to
  // "what did they change" is the audit trail, and this is the way to it rather than a sentence telling the
  // reader to go and find it.
  actions.push(document.createTextNode(" "));
  actions.push(el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "What they did", ja: "何をしたか" }),
    onClick: () => operatorAccessOpenAudit(e) }));

  return el("tr", {}, [
    el("td", { class: "ui-view-desc", text: fmtTime(e.started_at) }),
    el("td", { class: "ui-view-desc", text: fmtTime(e.ended_at || e.expires_at) }),
    el("td", {}, uiBadge(bl(meta.t), meta.tone)),
    el("td", { class: "ui-view-desc", text: e.approved_at ? fmtTime(e.approved_at)
      : e.approval_required ? bl({ en: "not yet", ja: "未承認" }) : bl({ en: "not needed", ja: "不要" }) }),
    el("td", { class: "ui-row-actions" }, actions),
  ]);
}

async function operatorElevationAct(method, path, body, reload) {
  const r = await apiFetch(method, path, body, "control");
  if (!r.ok) { uiToast((r.body && r.body.error) || ("HTTP " + r.status), "err"); return; }
  uiToast(bl({ en: "Done.", ja: "実行しました。" }), "ok");
  if (reload) reload();
}

// operatorAccessOpenAudit opens the audit log narrowed to the days this elevation spanned.
function operatorAccessOpenAudit(e) {
  const day = (t) => String(t || "").slice(0, 10);
  const from = day(e.started_at);
  const to = day(e.ended_at || e.expires_at) || from;
  try {
    _laTab = "logs";
    _laStream = "audit";
    _laFilters = from
      ? { _from: from, from: new Date(from + "T00:00:00").toISOString(), _to: to, to: new Date(to + "T23:59:59.999").toISOString() }
      : {};
  } catch (err) { /* the audit screen has not been loaded yet; it opens unfiltered */ }
  renderGroup("audit");
}
