"use strict";

// aiinsights.js — two distinct surfaces that used to be merged under one confusing "AI Insights" view:
//
//   1. renderAiServiceUsageView  — AI-service *visibility/governance*: which AI SaaS your users
//      reached THROUGH the SSE, and how it was governed. Backend: GET /admin/ai-usage-report.
//      (This is about monitoring others' AI usage. No LLM involved.)

const _AI_PLANE = "control";

// ---- 1. AI service usage (visibility / governance) -----------------------------------------

// The period the AI usage view is showing. Module-level so switching periods does not reset on re-render, and
// so it is the ONE place the view's window is decided — the report used to be a fixed 7 days that no screen
// printed, which meant a report cut short by the row cap looked exactly like a quiet week.
let _aiUsagePeriod = "7d";

function renderAiServiceUsageView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "AI service usage", ja: "AI サービス利用" }) }),
      el("p", { class: "ui-view-desc", text: bl({ en: "Which AI services your users reached through the SSE, and WHO used them.", ja: "利用者が SSE 経由で到達した AI サービスと、誰が使ったか。" }) }),
    ]),
    el("div", { style: "display:flex;gap:8px;align-items:center" }, [
      uiPeriodSegment(_aiUsagePeriod, (v) => { _aiUsagePeriod = v; renderAiServiceUsageView(content); }),
      el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Reload", ja: "再読込" }), onClick: () => renderAiServiceUsageView(content) }),
    ]),
  ]));
  const host = el("div", {});
  content.appendChild(host);
  loadAiUsage(host);
}

async function loadAiUsage(host) {
  uiState(host, "loading");
  const current = freshRender(host);
  let d;
  // apiFetch routes this report to the control plane so usage in other regions
  // remains visible when an agent fails over or this Console is opened elsewhere.
  try { const r = await apiFetch("GET", "/admin/ai-usage-report?window=" + encodeURIComponent(_aiUsagePeriod)); if (!r.ok) throw new Error("HTTP " + r.status); d = r.body || {}; }
  catch (e) { if (!current()) return; uiState(host, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => loadAiUsage(host) }); return; }
  // Attribution enrichment (P2): join the corporate_user against the People directory so the report shows a
  // display name + department, not a raw id/subject. The directory lives on the control plane (durable, synced);
  // best-effort — a miss falls back to the raw id, so the report never breaks if the directory is empty.
  const dir = {};
  try {
    const hr = await apiFetch("GET", "/admin/human-identities", undefined, "control");
    if (hr.ok && hr.body && Array.isArray(hr.body.identities)) {
      hr.body.identities.forEach((u) => {
        const info = { name: u.display_name || u.subject || u.id, dept: u.department || "" };
        [u.id, u.subject, u.email].forEach((k) => { if (k) dir[String(k).toLowerCase()] = info; });
      });
    }
  } catch (e) { /* directory optional */ }
  if (!current()) return;
  host.innerHTML = "";
  const stat = (label, val) => el("div", { style: "display:inline-block;margin-right:28px" }, [el("div", { class: "ui-view-desc", text: label }), el("div", { style: "font-size:22px;font-weight:650", text: String(val) })]);
  const tiles = [stat(bl({ en: "AI sessions", ja: "AI セッション" }), d.total_ai_sessions || 0), stat(bl({ en: "Sent to AI", ja: "AI へ送信" }), fmtBytes(d.total_bytes_sent)), stat(bl({ en: "Received", ja: "受信" }), fmtBytes(d.total_bytes_received))];
  host.appendChild(el("div", { style: "margin:6px 0 16px" }, tiles));
  // What range these numbers actually cover — which is not always the period selected above.
  const cov = uiCoverageNote(d.coverage);
  if (cov) host.appendChild(el("div", { style: "margin:-8px 0 16px" }, [cov]));

  const services = d.services || [];
  if (services.length) {
    host.appendChild(el("h3", { class: "ui-field-label", text: bl({ en: "AI services", ja: "AI サービス" }) }));
    // The unit belongs in the column, not in a paragraph above it. "Sessions" alone is ambiguous — the number
    // is distinct 30-minute activity windows, not requests — so the header carries that and nothing else does.
    host.appendChild(simpleTable([bl({ en: "Service", ja: "サービス" }), bl({ en: "Sessions · 30 min", ja: "セッション · 30分" }), bl({ en: "Sent", ja: "送信" }), bl({ en: "Received", ja: "受信" })], services.map((s) => [
      el("strong", { text: s.name || "—" }), el("span", { text: String(s.sessions ?? 0) }), el("span", { text: fmtBytes(s.bytes_sent) }), el("span", { class: "ui-view-desc", text: fmtBytes(s.bytes_received) }),
    ])));
  } else {
    host.appendChild(el("p", { class: "ui-view-desc", text: bl({ en: "No AI service accesses recorded yet.", ja: "AI サービスのアクセス記録はまだありません。" }) }));
  }

  const acts = d.by_activity || [];
  if (acts.length) {
    host.appendChild(el("h3", { class: "ui-field-label", style: "margin-top:20px", text: bl({ en: "Who is using which AI", ja: "誰がどの AI を使っているか" }) }));
    let prevWho = null;
    host.appendChild(simpleTable(
      [bl({ en: "Logged-in user", ja: "ログインユーザー" }), bl({ en: "Device", ja: "デバイス" }), bl({ en: "App", ja: "アプリ" }), bl({ en: "AI name", ja: "AI 名前" }), bl({ en: "AI email", ja: "AI メール" }), bl({ en: "AI service", ja: "AI サービス" }), bl({ en: "Sessions", ja: "セッション" }), bl({ en: "Sent", ja: "送信" }), bl({ en: "Received", ja: "受信" })],
      acts.map((a) => {
        const who = a.corporate_user || a.identity || "—";
        const showWho = who !== prevWho; prevWho = who;
        // P2: show the directory display name (+ department) for the corporate_user; keep the raw id as a tooltip.
        const hit = dir[String(who).toLowerCase()];
        const whoCell = !showWho ? el("span", {})
          : hit ? el("span", { title: who }, [el("strong", { text: hit.name })].concat(hit.dept ? [el("span", { class: "ui-view-desc", style: "margin-left:6px", text: hit.dept })] : []))
          : el("strong", { text: who });
        // Name + Email as their own columns; blank when this AI service does not expose that field.
        const aiName = a.ai_name || (a.ai_account && !/@/.test(a.ai_account) ? a.ai_account : "");
        const aiEmail = a.ai_email || (/@/.test(a.ai_account || "") ? a.ai_account : "");
        // A personal account on a corporate assistant is the governance signal on this table, and it used to be
        // conveyed by a paragraph telling the reader to look for an "@gmail"-shaped address. Mark the row instead.
        const emailCell = el("span", { class: "ui-mono", text: aiEmail });
        const accountCell = a.identity_type === "user_personal"
          ? el("span", {}, [emailCell, el("span", { style: "margin-left:8px" }, [uiBadge(bl({ en: "Shadow AI", ja: "シャドーAI" }), "warn")])])
          : emailCell;
        return [
          whoCell,
          el("span", { class: "ui-view-desc", text: a.device || "—" }),
          el("span", { class: "ui-view-desc", text: a.app || "—" }),
          el("span", { text: aiName }),
          accountCell,
          el("span", { text: a.service || "—" }),
          el("span", { class: "ui-view-desc", text: String(a.sessions ?? 0) }),
          el("span", { class: "ui-view-desc", text: fmtBytes(a.bytes_sent) }),
          el("span", { class: "ui-view-desc", text: fmtBytes(a.bytes_received) }),
        ];
      })
    ));
  }
}

function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  if (n < 1073741824) return (n / 1048576).toFixed(1) + " MB";
  return (n / 1073741824).toFixed(2) + " GB";
}

function aiIdentityTypeLabel(t) {
  return ({
    user: bl({ en: "user", ja: "ユーザー" }),
    user_personal: bl({ en: "personal (shadow AI)", ja: "個人（シャドーAI）" }),
    user_opaque: bl({ en: "unresolved id", ja: "未解決ID" }),
    ai_agent: bl({ en: "AI agent", ja: "AIエージェント" }),
    device: bl({ en: "device", ja: "デバイス" }),
    source_ip: bl({ en: "source IP", ja: "送信元IP" }),
    unattributed: bl({ en: "unattributed", ja: "不明" }),
  })[t] || t || "—";
}

// ---- 2. Operations assistant (explains YOUR access decisions) ------------------------------
