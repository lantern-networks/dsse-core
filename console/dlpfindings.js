"use strict";

// dlpfindings.js — "DLP Findings" (Web & Traffic): the operator-facing visibility view of what Data-Loss
// Prevention has detected in inspected uploads. NON-SECRET throughout — identifier type + count + action + who/
// where + time, never the raw matched value. Backend: GET /admin/dlp-findings (dlp_match findings only —
// inspection events + an aggregated summary). See docs/dlp_vision_and_roadmap.md.

// dlpInstanceBadge shows the destination instance class (instance-aware action): corporate = the sanctioned
// org account, personal = an outside-the-organization account. Blank when not classified.
function dlpInstanceBadge(cls) {
  if (cls === "corporate") return uiBadge(bl({ en: "Corporate", ja: "自社" }), "ok");
  if (cls === "personal") return uiBadge(bl({ en: "Personal / outside", ja: "個人/社外" }), "err");
  return null;
}

// Source is split into three INDEPENDENT columns — Application, User, Device — each showing the field the flow
// carried, or "—". Device-only steered flows have no corporate session, so User falls back to the OS/signed-in
// identity, Device to the source IP.
function dlpAppCell(f) { return f.source_app ? el("code", { text: f.source_app }) : el("span", { class: "ui-view-desc", text: "—" }); }
function dlpUserCell(f) { const u = f.corporate_user || f.user_id || f.account; return u ? el("span", { text: u }) : el("span", { class: "ui-view-desc", text: "—" }); }
function dlpDeviceCell(f) { const dvc = f.device_id || f.source_ip; return dvc ? el("span", { text: dvc }) : el("span", { class: "ui-view-desc", text: "—" }); }

function dlpActionBadge(action) {
  if (action === "block") return uiBadge(bl({ en: "Blocked", ja: "遮断" }), "err");
  if (action === "authenticate") return uiBadge(bl({ en: "Verify", ja: "認証要求" }), "warn");
  if (action === "warn") return uiBadge(bl({ en: "Warned", ja: "警告" }), "warn");
  if (action === "observe") return uiBadge(bl({ en: "Observed", ja: "監視" }), "off");
  return uiBadge(action || "—", "off");
}

function dlpFindingsObject(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }
function dlpFindingsInvalid() { return bl({en:"Could not load DLP findings correctly. Retry to confirm the results.",ja:"DLP検出を正しく読み込めません。再試行して結果を確認してください。"}); }
function dlpFindingsSelection() { return typeof operateTenant === "undefined" ? "" : (operateTenant || ""); }
function dlpFindingsTenant(response) {
  if (!response?.ok || response.status !== 200 || !dlpFindingsObject(response.body) ||
      typeof response.body.tenant_id !== "string" || !response.body.tenant_id.trim()) throw new Error(dlpFindingsInvalid());
  return response.body.tenant_id;
}
function dlpFindingsBody(response, tenant) {
  const body = response?.body, count = v => Number.isSafeInteger(v) && v >= 0;
  if (dlpFindingsTenant(response) !== tenant || body.schema_version !== "admin_dlp_findings.v1" ||
      body.no_secret_attestation !== true || !Array.isArray(body.findings) || !dlpFindingsObject(body.summary)) throw new Error(dlpFindingsInvalid());
  const sum = body.summary;
  if (!count(sum.total) || !count(sum.returned) || !count(sum.blocked) || sum.returned !== body.findings.length ||
      sum.returned > sum.total || sum.blocked > sum.total) throw new Error(dlpFindingsInvalid());
  for (const key of ["by_identifier", "by_action", "by_destination"]) {
    if (!dlpFindingsObject(sum[key]) || Object.values(sum[key]).some(v => !count(v) || v > sum.total)) throw new Error(dlpFindingsInvalid());
  }
  const seen = new Set();
  for (const row of body.findings) {
    if (!dlpFindingsObject(row) || typeof row.id !== "string" || !row.id || seen.has(row.id) ||
        typeof row.timestamp !== "string" || !Number.isFinite(Date.parse(row.timestamp)) || typeof row.action !== "string" ||
        (row.identifier_types !== null && (!Array.isArray(row.identifier_types) || row.identifier_types.some(id => typeof id !== "string" || !id)))) throw new Error(dlpFindingsInvalid());
    seen.add(row.id);
    for (const key of ["destination", "source_app", "user_id", "device_id", "corporate_user", "account", "source_ip", "instance_class", "rule_id"]) {
      if (row[key] !== undefined && typeof row[key] !== "string") throw new Error(dlpFindingsInvalid());
    }
  }
  return body;
}

async function renderDLPFindingsView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, el("div", {}, [
    el("h2", { class: "ui-view-title", text: bl({ en: "DLP Findings", ja: "DLP 検出" }) }),
    el("p", { class: "ui-view-desc", text: bl({
      en: "What Data-Loss Prevention detected in inspected uploads — identifier type, count, and the action taken. The raw value is never shown or stored.",
      ja: "傍受したアップロードで DLP が検出した内容 — 識別子の種類・件数・実行アクション。生の値は表示も保存もされません。",
    }) }),
  ])));
  const section = el("div", {});
  content.appendChild(section);
  let _filter = "";
  const fresh = freshRender(content);
  const current = () => fresh() && content.isConnected !== false && section.isConnected !== false;

  // A missing/deleted policy name may fall back to its recorded ID. Findings
  // themselves must be valid even when this optional name lookup is unavailable.
  async function policyNames(tenant) {
    const names = Object.create(null);
    try {
      const r = await apiFetch("GET", "/admin/dlp-policies");
      if (r.ok && Array.isArray(r.body?.policies)) {
        for (const p of r.body.policies) {
          if (p && p.tenant_id === tenant && typeof p.id === "string" && typeof p.name === "string") names[p.id] = p.name || p.id;
        }
      }
    } catch (_) { /* The recorded policy ID remains available. */ }
    return names;
  }

  async function load() {
    if (!current()) return;
    const latest = freshRender(section), selected = dlpFindingsSelection();
    const active = () => current() && latest();
    uiState(section, "loading");
    const suffix = _filter ? "?identifier=" + encodeURIComponent(_filter) : "";
    let body, names;
    try {
      const [response, organization] = await Promise.all([
        apiFetch("GET", "/admin/dlp-findings" + suffix, undefined, "control"), apiFetch("GET", "/admin/tenant"),
      ]);
      if (!active()) return;
      const tenant = dlpFindingsTenant(organization);
      if (selected !== dlpFindingsSelection() || (selected && selected !== tenant)) throw new Error(dlpFindingsInvalid());
      body = dlpFindingsBody(response, tenant);
      names = body.findings.length ? await policyNames(tenant) : Object.create(null);
      if (!active()) return;
      if (selected !== dlpFindingsSelection()) throw new Error(dlpFindingsInvalid());
    } catch (e) {
      if (active()) uiState(section, "error", dlpFindingsInvalid(), {label:bl({en:"Retry",ja:"再試行"}),onClick:load});
      return;
    }
    section.innerHTML = "";
    const sum = body.summary, findings = body.findings, byId = sum.by_identifier;

    // Counts are events, not occurrences or the sum of overlapping identifier types.
    const chips = [el("span", { class: "ui-view-desc", text: bl({
      en: sum.total + " events · " + sum.blocked + " blocked · Showing " + sum.returned + " · ",
      ja: "検出イベント " + sum.total + " 件 · 遮断 " + sum.blocked + " 件 · 表示 " + sum.returned + " 件 · ",
    }) })];
    const allChip = el("button", { class: "ui-btn ui-btn-sm" + (_filter ? "" : " ui-btn-primary"), text: bl({ en: "All", ja: "すべて" }), onClick: () => { _filter = ""; load(); } });
    chips.push(allChip);
    Object.keys(byId).sort().forEach((id) => {
      chips.push(el("button", { class: "ui-btn ui-btn-sm" + (_filter === id ? " ui-btn-primary" : ""), text: id + " (" + byId[id] + ")", onClick: () => { _filter = (_filter === id ? "" : id); load(); } }));
    });
    section.appendChild(el("div", { class: "ui-toolbar" }, chips));

    if (!findings.length) {
      section.appendChild(emptyBox(_filter
        ? bl({ en: "No findings for this identifier.", ja: "この識別子の検出はありません。" })
        : bl({ en: "No DLP detections yet. Enable DLP on an Internet Access rule (observe or block) to start detecting sensitive data in uploads.", ja: "まだ DLP 検出はありません。「インターネットアクセス」のルールで DLP(監視/遮断)を有効化すると、アップロード内の機密データの検出が始まります。" })));
      return;
    }

    section.appendChild(simpleTable(
      [bl({ en: "Time", ja: "時刻" }), bl({ en: "Identifiers", ja: "識別子" }), bl({ en: "Action", ja: "アクション" }), bl({ en: "Application", ja: "アプリ" }), bl({ en: "User", ja: "ユーザー" }), bl({ en: "Device", ja: "デバイス" }), bl({ en: "Destination", ja: "宛先" })],
      findings.map((f) => {
        const idents = (f.identifier_types || []);
        const identCell = idents.length
          ? el("span", {}, idents.map((id) => uiBadge(id, "warn")))
          : el("span", { class: "ui-view-desc", text: "—" });
        // Destination cell = host + (corporate/personal badge when the account instance was classified).
        const instBadge = dlpInstanceBadge(f.instance_class);
        const destCell = el("div", {}, [
          f.destination ? el("div", {}, el("code", { text: f.destination })) : el("div", { class: "ui-view-desc", text: "—" }),
          instBadge ? el("div", {}, instBadge) : null,
        ]);
        // Action + the catching DLP policy, shown by NAME (rule_id holds the policy id; hover reveals the id).
        const actionCell = el("div", {}, [
          el("div", {}, dlpActionBadge(f.action)),
          f.rule_id ? el("div", { class: "ui-view-desc", style: "font-size:0.85em", title: f.rule_id, text: bl({ en: "policy: ", ja: "ポリシー: " }) + (names[f.rule_id] || f.rule_id) }) : null,
        ]);
        return [
          el("span", { class: "ui-view-desc", text: f.timestamp ? window.dsseFormatTime(f.timestamp) : "—" }),
          identCell,
          actionCell,
          dlpAppCell(f),
          dlpUserCell(f),
          dlpDeviceCell(f),
          destCell,
        ];
      })
    ));
  }
  return load();
}
