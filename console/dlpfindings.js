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
  let _filter = "";       // identifier filter
  let _policyNames = null; // DLP policy id -> human name (the finding stores the policy id in rule_id)

  // ensurePolicyNames resolves a finding's rule_id (a DLP policy object id) to the operator-facing policy
  // NAME. Cached for the view lifetime; falls back to the raw id when the policy was since deleted or the
  // lookup fails (the id is non-secret, so a fallback leaks nothing).
  async function ensurePolicyNames() {
    if (_policyNames) return _policyNames;
    const map = {};
    try {
      const r = await apiFetch("GET", "/admin/dlp-policies");
      if (r.ok && r.body && Array.isArray(r.body.policies)) {
        r.body.policies.forEach((p) => { if (p && p.id) map[p.id] = p.name || p.id; });
      }
    } catch (e) { /* fall back to the raw id */ }
    _policyNames = map;
    return map;
  }

  async function load() {
    uiState(section, "loading");
    let body;
    const qs = [];
    if (_filter) qs.push("identifier=" + encodeURIComponent(_filter));
    // Read findings from the CONTROL plane (the aggregated, fleet-wide, restart-safe hot store) — not a single
    // Edge's in-memory cache (event_log_design.md, S2). Policy names are still resolved on the Edge, where
    // policies are configured.
    try { const r = await apiFetch("GET", "/admin/dlp-findings" + (qs.length ? "?" + qs.join("&") : ""), undefined, "control"); if (!r.ok) throw new Error("HTTP " + r.status); body = r.body || {}; }
    catch (e) { uiState(section, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: load }); return; }
    section.innerHTML = "";
    const sum = body.summary || {};
    const findings = body.findings || [];
    const byId = sum.by_identifier || {};
    const matchTotal = Object.values(byId).reduce((a, b) => a + b, 0);

    // Summary line: matches + blocked + per-identifier chips (clickable to filter).
    const chips = [el("span", { class: "ui-view-desc", text: bl({
      en: (matchTotal) + " matches · " + (sum.blocked || 0) + " blocked · ",
      ja: "検出 " + (matchTotal) + " 件 · 遮断 " + (sum.blocked || 0) + " 件 · ",
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

    const policyNames = await ensurePolicyNames();
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
          f.rule_id ? el("div", { class: "ui-view-desc", style: "font-size:0.85em", title: f.rule_id, text: bl({ en: "policy: ", ja: "ポリシー: " }) + (policyNames[f.rule_id] || f.rule_id) }) : null,
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
  load();
}
