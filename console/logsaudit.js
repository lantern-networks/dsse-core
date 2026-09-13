"use strict";

// logsaudit.js — "Logs & Audit": a decision-centric, typed log console (control plane).
// Tabs: Logs (per-stream typed viewer with faceted filters + a structured detail drawer) / Exports.
// Backend (control): GET /admin/logs/{stream}?decision=&user_id=&application_id=&device_id=&policy_id=
//   &service_family=&actor_type=&q=&from=&to=&limit=&cursor= ; /admin/export-jobs {jobs} + POST create.
// See docs/logs_audit_ui_and_volume_design.md — no raw JSON in the row; raw is behind a "View raw" toggle.

const _LA_PLANE = "control";
// Only SOME streams are shipped to the control plane for cross-edge aggregation. The rest are EDGE-LOCAL —
// written by the enforcing edge and never shipped — so reading them from the control plane returns an empty
// list and the tab is silently blank (no error, just nothing).
//
// This set MIRRORS the backend's `defaultAuditShipStreams` (cmd/edge/audit_ship.go). Keep them in
// sync: a stream added there must be added here, or its tab reads the wrong plane. Anything not listed is
// read from the edge — the safe default, since an edge always has its own records.
const _LA_SHIPPED_STREAMS = new Set(["audit", "access", "device_state", "inspection_events", "config_generations"]);
function laPlaneFor(stream) { return _LA_SHIPPED_STREAMS.has(stream) ? _LA_PLANE : "edge"; }
let _laTab = "logs";
let _laStream = "access";
let _laFilters = {}; // active facet filters (field -> value) + q/from/to

// Stream ids MUST match the backend aliases (adminLogStreamFilenameMap): the old ids
// tool_call / human_approval / delegated_grants 404'd. Access is the flagship, listed first.
const _LA_STREAMS = [
  { id: "access", label: { en: "Access decisions", ja: "アクセス判断" } },
  { id: "audit", label: { en: "Admin audit", ja: "管理監査" } },
  // (The "decision_trace" stream was retired — the access decision record now carries the trace's fields,
  //  incl. cache_status, so it is no longer a separate stream. See logging_what_to_log_design.md.)
  { id: "inspection_events", label: { en: "Inspection / DLP", ja: "検査・DLP" } },
  { id: "tool_call_events", label: { en: "AI tool calls", ja: "AIツール実行" } },
  { id: "human_approval_events", label: { en: "Human approvals", ja: "人手承認" } },
  { id: "delegated_access_grants", label: { en: "Delegated grants", ja: "委譲グラント" } },
  { id: "connector", label: { en: "Connector", ja: "コネクタ" } },
  { id: "device_state", label: { en: "Device state", ja: "デバイス状態" } },
];

// ---- small field helpers -------------------------------------------------
function laVal(row) { for (let i = 1; i < arguments.length; i++) { const v = row[arguments[i]]; if (v !== undefined && v !== null && String(v) !== "") return String(v); } return ""; }
// Rendered in the TENANT's zone, not the browser's. An engineer reviewing another region's tenant would
// otherwise read every timestamp shifted by their own location, and the zone is shown so nobody has to guess
// which clock a plausible-looking time belongs to.
function laWhen(row) {
  const w = laVal(row, "ts", "time", "timestamp", "created_at");
  if (!w) return "—";
  if (String(w).length <= 4) return w;
  return window.dsseFormatTime ? window.dsseFormatTime(w) : new Date(w).toLocaleString();
}
function laDash(s) { return (s === "" || s == null) ? "—" : s; }

// Decision → colour. allow=green, deny=red, any challenge/step-up=amber, bypass=grey.
function laDecisionBadge(dec) {
  const d = String(dec || "").toLowerCase();
  let kind = "off", label = dec || "—";
  if (d === "allow") { kind = "ok"; label = bl({ en: "Allow", ja: "許可" }); }
  else if (d === "deny") { kind = "danger"; label = bl({ en: "Deny", ja: "拒否" }); }
  else if (/reauth|authenticate|challenge|require|step_up|workload_attestation/.test(d)) { kind = "warn"; label = bl({ en: "Challenge", ja: "要認証" }); }
  else if (d === "bypass") { kind = "off"; label = bl({ en: "Bypass", ja: "バイパス" }); }
  return uiBadge(label, kind);
}
function laResultBadge(res) {
  const r = String(res || "").trim().toLowerCase();
  // Match whole outcomes: "revoked" contains "ok", and "incomplete" contains "complete".
  // Unknown outcomes retain their text and remain neutral rather than implying success.
  const kind = /^(ok|success|allow|allowed|approved|done|complete|completed)$/.test(r) ? "ok"
    : /^(fail|failed|failure|deny|denied|error|reject|rejected|revoked)$/.test(r) ? "danger" : "off";
  return uiBadge(laDash(res), kind);
}

// reason_codes → human phrases (mirrors oss/aiops/explainer.go; fallback prettifies the code).
const _LA_REASON = {
  policy_matched: { en: "Policy matched", ja: "ポリシー合致" },
  application_allowed: { en: "Allowed by policy", ja: "ポリシーで許可" },
  no_policy_match: { en: "No policy matched (default deny)", ja: "合致ポリシーなし(既定拒否)" },
  risk_signal_manual_high_risk: { en: "Marked high-risk", ja: "高リスク指定" },
  risk_signal_idp_high_risk: { en: "IdP high risk", ja: "IdP高リスク" },
  risk_signal_agent_tamper: { en: "Agent tampering", ja: "エージェント改ざん" },
  risk_signal_authentication_anomaly: { en: "Authentication anomaly", ja: "認証異常" },
  risk_state_recommended_emergency_block: { en: "Risk state: emergency block", ja: "リスク状態:緊急遮断" },
  ransomware_protection_mode_active: { en: "Risk overlay active", ja: "リスクオーバーレイ作動" },
  high_sensitivity_application: { en: "High-sensitivity app", ja: "機密アプリ" },
  authentication_max_age_exceeded: { en: "Stale authentication", ja: "認証鮮度切れ" },
  east_west_authenticate_required: { en: "East-West step-up required", ja: "コネクタ経由アクセスの認証が必要" },
  east_west_default_deny: { en: "East-West default deny", ja: "コネクタ経由アクセス 既定拒否" },
  east_west_warn: { en: "East-West warn (dry-run)", ja: "コネクタ経由アクセス 警告(ドライラン)" },
  device_attested_auto: { en: "Device-attested (silent)", ja: "デバイス認証(無言許可)" },
  // Built-in default inspection posture (NOT operator policies — hardcoded decrypt-all + SaaS tenant enforcement).
  // These appear on every intercepted flow; the "(built-in)" marker tells the operator they are not a hidden rule.
  tls_inspection_readiness_policy_layer: { en: "TLS interception", ja: "TLS傍受" },
  swg_saas_tenant_enforcement_preflight: { en: "SaaS tenant-restriction check", ja: "SaaSテナント制限チェック" },
  swg_default_tls_decryption_required: { en: "Default decrypt-all", ja: "既定の全復号" },
  swg_tenant_restriction_header_injection_planned: { en: "Tenant-restriction header inject", ja: "テナント制限ヘッダ注入" },
  swg_tls_bypass_applied: { en: "TLS bypass applied", ja: "TLSバイパス適用" },
};
// event_type / finding_type / action codes → human phrases. Unknown codes are prettified (snake_case →
// "Title case", trailing _recorded/_by_admin/_updated noise trimmed) so no raw token ever shows in a cell.
const _LA_EVENT = {
  // The operator envelope — what the company running this service did inside a customer's organization, and
  // when. These are the rows the customer's own "Operator access" screen links into, so they are written for
  // that reader rather than as event names.
  admin_tenant_model_operator_delegation_changed: { en: "Management delegation changed", ja: "運営への委任を変更" },
  admin_tenant_model_operator_elevation_granted: { en: "Time-boxed permission started", ja: "時間制限つきの許可を開始" },
  admin_tenant_model_operator_elevation_approved: { en: "Time-boxed permission approved", ja: "時間制限つきの許可を承認" },
  admin_tenant_model_operator_elevation_ended: { en: "Time-boxed permission ended", ja: "時間制限つきの許可が終了" },
  // admin actions
  admin_policy_upserted: { en: "Policy saved", ja: "ポリシー保存" },
  admin_application_upserted: { en: "Application saved", ja: "アプリ保存" },
  admin_application_deleted: { en: "Application deleted", ja: "アプリ削除" },
  admin_endpoint_inventory_upserted: { en: "Endpoint saved", ja: "エンドポイント保存" },
  enrolled_inventory_updated: { en: "Enrolled inventory updated", ja: "登録インベントリ更新" },
  admin_tenant_model_updated: { en: "Tenant settings changed", ja: "テナント設定変更" },
  admin_rbac_denied: { en: "Admin action denied (RBAC)", ja: "管理操作を拒否(RBAC)" },
  // ★ Read from the organization being operated IN, which is where this row actually matters: "cross-tenant
  // operate" is the deployment's word for it, and the customer's question is "somebody outside my organization
  // was working in it".
  admin_operate_within_tenant: { en: "The operator worked in this tenant", ja: "運営がこのテナントで作業しました" },
  // These were reaching the screen unmapped, so laPretty spelled the code out in English on a Japanese page.
  admin_account_deleted: { en: "Administrator removed", ja: "管理者を削除" },
  admin_account_created: { en: "Administrator added", ja: "管理者を追加" },
  admin_account_suspended: { en: "Administrator suspended", ja: "管理者を停止" },
  admin_account_reactivated: { en: "Administrator reactivated", ja: "管理者を再開" },
  admin_config_change: { en: "Setting changed", ja: "設定を変更" },
  admin_login: { en: "Signed in", ja: "サインイン" },
  admin_logout: { en: "Signed out", ja: "サインアウト" },
  operator_elevation_granted: { en: "The operator took a time-limited permission", ja: "運営が時間制限つきの許可を取得" },
  operator_elevation_approved: { en: "You approved that permission", ja: "その許可をあなたが承認" },
  operator_elevation_ended: { en: "That permission ended", ja: "その許可が終了" },
  operator_delegation_changed: { en: "Who runs this tenant changed", ja: "このテナントの運用担当が変更" },
  // The one act that does not need this organization's delegation, because before it there was nobody here who
  // could have granted one. Named plainly: an unlabelled event type renders as its raw identifier, which is an
  // English internal string on a Japanese screen, on the row that most needs to be understood.
  // ★ THE REST OF WHAT THE ADMIN PLANE EMITS (2026-08-17). Twenty-two event types had no entry here, so each
  // rendered as its own identifier — an English internal string in the What column of the log an organization
  // reads to find out what happened to it. Named in the words the reader uses: what happened, not which
  // function wrote it. The gate's budget goes to zero with this.
  admin_break_glass_used: { en: "Emergency master key used", ja: "緊急用マスターキーが使われました" },
  pki_material_changed: { en: "Certificate authority material changed", ja: "証明書の発行元が変更されました" },
  authentication_event_failed: { en: "A sign-in was refused", ja: "サインインが拒否されました" },
  authentication_event_recorded: { en: "Sign-in recorded", ja: "サインインを記録" },
  admin_agent_tool_upserted: { en: "AI tool definition changed", ja: "AIツールの定義を変更" },
  admin_tool_call_event_upserted: { en: "AI tool run recorded", ja: "AIツールの実行を記録" },
  tool_call_event_recorded: { en: "AI tool run recorded", ja: "AIツールの実行を記録" },
  inspection_event_recorded: { en: "Inspection result recorded", ja: "検査結果を記録" },
  human_approval_event_recorded: { en: "Approval decision recorded", ja: "承認の判断を記録" },
  human_identity_source_policy_upserted: { en: "Directory import rules changed", ja: "ディレクトリ取り込み規則を変更" },
  admin_audit_outbox_replayed: { en: "Undelivered audit records resent", ja: "未送達の監査記録を再送" },
  admin_domain_event_outbox_replayed: { en: "Undelivered events resent", ja: "未送達のイベントを再送" },
  admin_export_task_enqueued: { en: "Export started", ja: "エクスポートを開始" },
  admin_export_dead_letter_bridge_failed: { en: "Export delivery failed", ja: "エクスポートの配信に失敗" },
  agent_status_reported: { en: "A device reported its state", ja: "端末が状態を報告" },
  agent_rollout_plan_attempted: { en: "Agent rollout attempted", ja: "エージェント配信を試行" },
  agent_rollout_plan_applied: { en: "Agent rollout applied", ja: "エージェント配信を適用" },
  agent_update_publish_attempted: { en: "Agent release publish attempted", ja: "エージェント版の公開を試行" },
  agent_update_published: { en: "Agent release published", ja: "エージェント版を公開" },
  agent_update_activate_attempted: { en: "Agent release activation attempted", ja: "エージェント版の有効化を試行" },
  agent_update_activated: { en: "Agent release activated", ja: "エージェント版を有効化" },
  agent_update_event_recorded: { en: "A device reported an update outcome", ja: "端末が更新結果を報告" },
  operator_seated_first_administrator: {
    en: "The operator set up this tenant's first administrator",
    ja: "運営がこのテナントの最初の管理者を設定",
  },
  break_glass_exported: { en: "Break-glass export", ja: "緊急エクスポート" },
  human_identity_upserted: { en: "Identity saved", ja: "ID保存" },
  human_identities_imported: { en: "Directory imported", ja: "ディレクトリ取込" },
  non_human_identity_upserted: { en: "NHI saved", ja: "NHI保存" },
  agent_rollout_plan_updated: { en: "Agent rollout updated", ja: "エージェント配信更新" },
  swg_http_egress_rewrite_recorded: { en: "Tenant-restriction rewrite", ja: "テナント制限リライト" },
  // device / connector
  device_registered: { en: "Device registered", ja: "デバイス登録" },
  device_heartbeat: { en: "Heartbeat", ja: "ハートビート" },
  device_state_changed: { en: "Posture changed", ja: "ポスチャ変化" },
  connector_registered: { en: "Connector registered", ja: "コネクタ登録" },
  connector_heartbeat: { en: "Heartbeat", ja: "ハートビート" },
  connector_disconnected: { en: "Disconnected", ja: "切断" },
  connector_status_changed: { en: "Status changed", ja: "状態変化" },
  connector_runtime_secret_rotated: { en: "Secret rotated", ja: "シークレット更新" },
  connector_route_allowed: { en: "Route allowed", ja: "経路許可" },
  connector_route_denied: { en: "Route denied", ja: "経路拒否" },
  connector_route_held_pending_authentication: { en: "Held for step-up", ja: "認証待ちで保留" },
  private_app_tcp_session_started: { en: "Private session started", ja: "プライベートセッション開始" },
  private_app_web_session_started: { en: "Web session started", ja: "Webセッション開始" },
  // inspection findings
  saas_tenant_restriction_rewrite: { en: "Tenant-restriction rewrite", ja: "テナント制限リライト" },
  dlp_match: { en: "DLP match", ja: "DLP一致" },
};
function laPretty(code) {
  const c = String(code || "").trim();
  if (!c) return "";
  if (_LA_EVENT[c]) return bl(_LA_EVENT[c]);
  return c.replace(/_recorded$|_by_admin$/g, "").replace(/_/g, " ").replace(/^\w/, (m) => m.toUpperCase());
}
// laEvent renders a prettified event/finding label; the raw code stays available on hover for power users.
function laEventLabel(row, ...fields) { const code = laVal(row, ...fields); return code ? el("span", { title: code, text: laPretty(code) }) : el("span", { text: "—" }); }

// _laAdminDir resolves an admin principal id (adm_…) → { email, name }, fetched once per audit-stream load so
// the Admin column shows WHO acted, not an opaque id. Populated in laLoadStream for the audit stream.
let _laAdminDir = {};
// auth-method → readable badge: how the caller authenticated (Console session vs a service API token vs the
// shared legacy owner bearer). The legacy token is flagged because it is an unattributed shared credential.
function laAuthMethodBadge(m) {
  const v = String(m || "").toLowerCase();
  if (v === "admin_session") return el("span", { class: "ui-badge ui-badge-off", style: "font-size:10px", title: bl({ en: "Admin Console session", ja: "管理コンソールのセッション" }), text: bl({ en: "Console", ja: "コンソール" }) });
  if (v === "api_token") return el("span", { class: "ui-badge ui-badge-off", style: "font-size:10px", title: bl({ en: "Named API token (service identity)", ja: "名前付きAPIトークン(サービスID)" }), text: bl({ en: "API token", ja: "APIトークン" }) });
  if (v === "legacy_admin_token" || v === "lab_bypass") return el("span", { class: "ui-badge ui-badge-warn", style: "font-size:10px", title: bl({ en: "Shared legacy owner bearer — unattributed credential", ja: "共有レガシーオーナートークン(無帰属)" }), text: bl({ en: "Legacy token", ja: "レガシートークン" }) });
  return v ? el("span", { class: "ui-badge ui-badge-off", style: "font-size:10px", text: v }) : null;
}
// audit actor: resolve to a real person (email/name) — from the row's own metadata (the new admin_config_change
// and admin_login rows carry it), else the admins directory, else the raw id. SYSTEM events (rewrite/ingest with
// no actor) read "System", not a blank. An auth-method badge shows HOW they authenticated.
function laAuditActor(row) {
  const meta = row.metadata || {};
  const id = laVal(row, "actor_user_id", "actor_nhi_id");
  const dir = id && _laAdminDir[id];
  const name = (meta.display_name || (dir && dir.name) || "").trim();
  const email = (meta.email || (dir && dir.email) || "").trim();
  const primary = name || email;
  const authBadge = laAuthMethodBadge(meta.auth_method);
  if (!primary && !id) return el("span", { class: "ui-view-desc", text: bl({ en: "System", ja: "システム" }) });
  // ★ AN ORGANIZATION CANNOT LOOK UP THE OPERATOR'S PEOPLE (2026-08-17, read in Northwind's own audit trail).
  // The directory this resolves against is the caller's OWN administrators, so an act performed by the
  // operator inside a customer rendered as a bare adm_1e9a9d5698… — on the very screen that exists to answer
  // "who did this". The record already says it was the operator (it carries the operator's organization), so
  // the screen says so, and keeps the identifier where somebody with the standing to resolve it can find it.
  // ★ AND KNOWING THE NAME MUST NOT HIDE THAT THEY ARE AN OUTSIDER (2026-08-17). This was gated on the name
  // being ABSENT, so the better a row identified the operator the less it said about them: the row that
  // carried a named operator account rendered exactly like a row about the organization's own administrator,
  // on the screen whose whole job is to show that somebody outside the organization was working inside it.
  // The badge is about WHOSE act it was, which is a different question from what to call them, so the name is
  // shown when it is known and the badge either way.
  const operatorActed = !!String(meta.operator_principal_id || "").trim();
  if (operatorActed) {
    return el("span", { title: id || "", style: "display:inline-flex;gap:6px;align-items:center;flex-wrap:wrap" }, [
      el("span", { text: primary || bl({ en: "The operator", ja: "運営" }) }),
      uiBadge(bl({ en: "on your behalf", ja: "あなたのテナントで" }), "warn"),
    ]);
  }
  const kids = [el("span", { text: primary || id })];
  if (email && email !== primary) kids.push(el("div", { class: "ui-view-desc", text: email }));
  if (authBadge) kids.push(authBadge);
  return el("span", { style: "display:inline-flex;gap:6px;align-items:center;flex-wrap:wrap" }, kids);
}
// audit action: admin_config_change rows carry the real mutation as method + path — render that (readable),
// with a small tooltip mapping common paths to friendly names. Other event types use the prettified label.
const _LA_PATH_NAME = {
  "/admin/rules": { en: "Connector-access rule", ja: "コネクタアクセスルール" },
  "/admin/policies": { en: "Access policy", ja: "アクセスポリシー" },
  "/admin/dlp-rules": { en: "DLP rule", ja: "DLPルール" },
  "/admin/dlp-policies": { en: "DLP policy", ja: "DLPポリシー" },
  "/admin/connectors": { en: "Connector", ja: "コネクタ" },
  "/admin/east-west": { en: "East-West posture", ja: "East-Westポスチャ" },
  "/admin/vlan-objects": { en: "Network object", ja: "ネットワークオブジェクト" },
  "/admin/idp-connections": { en: "Identity provider", ja: "IDプロバイダ" },
  "/admin/grants": { en: "Access approval", ja: "アクセス承認" },
  "/admin/admins": { en: "Administrator", ja: "管理者" },
  "/admin/api-tokens": { en: "API token", ja: "APIトークン" },
};
function laAuditActionCell(row) {
  if (row.event_type !== "admin_config_change") return laEventLabel(row, "event_type", "action");
  const meta = row.metadata || {};
  const method = laVal(meta, "method") || laVal(row, "action");
  const path = laVal(meta, "path") || laVal(row, "target_id");
  // Friendly noun for a known base path (/admin/rules/{id} → "Connector-access rule").
  const base = "/" + String(path).split("/").slice(1, 3).join("/");
  const noun = _LA_PATH_NAME[base] ? bl(_LA_PATH_NAME[base]) : "";
  const verb = { POST: bl({ en: "Changed", ja: "変更" }), PUT: bl({ en: "Changed", ja: "変更" }), PATCH: bl({ en: "Changed", ja: "変更" }), DELETE: bl({ en: "Deleted", ja: "削除" }) }[method] || method;
  const label = noun ? (verb + " " + noun) : (method + " " + path);
  return el("span", { title: method + " " + path }, [el("span", { text: label })]);
}
// device posture: compose the real signals (encryption / firewall / OS / logged-in user) the record carries
// into readable badges instead of reading a non-existent "state" field.
function laDevicePostureCell(row) {
  const kids = [];
  const enc = row.disk_encryption_enabled, fw = row.firewall_enabled;
  if (enc === true) kids.push(el("span", { class: "ui-badge ui-badge-ok", style: "font-size:10px", title: bl({ en: "Disk encrypted", ja: "ディスク暗号化" }), text: "🔒 enc" }));
  else if (enc === false) kids.push(el("span", { class: "ui-badge ui-badge-danger", style: "font-size:10px", title: bl({ en: "Disk NOT encrypted", ja: "ディスク未暗号化" }), text: "🔓 enc" }));
  if (fw === true) kids.push(el("span", { class: "ui-badge ui-badge-ok", style: "font-size:10px", title: bl({ en: "Firewall on", ja: "FW有効" }), text: "🛡 fw" }));
  else if (fw === false) kids.push(el("span", { class: "ui-badge ui-badge-danger", style: "font-size:10px", title: bl({ en: "Firewall off", ja: "FW無効" }), text: "⚠ fw" }));
  return kids.length ? el("span", { style: "display:inline-flex;gap:4px;flex-wrap:wrap" }, kids) : el("span", { class: "ui-view-desc", text: "—" });
}
function laDeviceUserCell(row) {
  const u = row.logged_in_users;
  const val = Array.isArray(u) ? u.join(", ") : laVal(row, "logged_in_users", "os_user", "user_id");
  return laDash(val);
}
// connector heartbeat freshness: green if seen in the last ~2 min, else amber/grey.
function laConnectorStatusCell(row) {
  const status = laVal(row, "status", "result");
  const hb = laVal(row, "last_heartbeat_at", "timestamp");
  const kids = [uiBadge(laDash(status) || "—", /healthy|ok|connected|active/i.test(status) ? "ok" : "off")];
  if (hb) { const ageMs = Date.now() - Date.parse(hb); if (!isNaN(ageMs) && ageMs > 150000) kids.push(el("span", { class: "ui-view-desc", style: "font-size:10px", text: bl({ en: "stale", ja: "古い" }) })); }
  return el("span", { style: "display:inline-flex;gap:5px;align-items:center" }, kids);
}
// Human names for DLP identifier types (WHAT sensitive data matched) — the most important fact on a DLP finding.
const _LA_DLP_ID = {
  my_number: { en: "My Number", ja: "マイナンバー" },
  corporate_number: { en: "Corporate Number", ja: "法人番号" },
  credit_card: { en: "Credit card", ja: "クレジットカード" },
  api_key: { en: "API key / secret", ja: "APIキー/秘密" },
  email: { en: "Email address", ja: "メールアドレス" },
  phone: { en: "Phone number", ja: "電話番号" },
};
function laDlpIdName(t) { return _LA_DLP_ID[t] ? bl(_LA_DLP_ID[t]) : String(t).replace(/_/g, " "); }
// inspection finding + severity chip + (for a DLP match) WHAT was detected. The mode is a separate column.
function laInspectionFindingCell(row) {
  const kids = [laEventLabel(row, "finding_type", "event_type")];
  const sev = laVal(row, "severity");
  if (sev && sev !== "info" && sev !== "none") kids.push(uiBadge(sev, /high|critical/i.test(sev) ? "danger" : "warn"));
  // DLP: show the detected identifier types (My Number, credit card, …) — the finding's whole point.
  const ids = (row.metadata && row.metadata.dlp_identifier_types) || [];
  if (Array.isArray(ids) && ids.length) kids.push(el("span", { class: "ui-view-desc", text: ids.map(laDlpIdName).join(", ") }));
  // DLP action (observe / block / authenticate) tells the operator whether it was enforced or just recorded.
  const act = row.metadata && row.metadata.dlp_action;
  if (act && act !== "observe") kids.push(uiBadge(act, /block/i.test(act) ? "danger" : "warn"));
  return el("span", { style: "display:inline-flex;gap:6px;align-items:center;flex-wrap:wrap" }, kids);
}

// Reason codes from the built-in inspection posture (decrypt-all / SaaS tenant enforcement / inspection layers),
// as opposed to operator-authored policy. Marked visually so the log never looks like it matched a phantom rule.
function laReasonIsBuiltin(code) { return /^swg_|^tls_inspection_/.test(String(code)); }
function laReasonPhrase(code) { const m = _LA_REASON[code]; return m ? bl(m) : String(code).replace(/_/g, " "); }
function laReasonChip(c) {
  const builtin = laReasonIsBuiltin(c);
  return el("span", {
    class: "ui-badge ui-badge-off", style: "font-size:11px" + (builtin ? ";opacity:.7;border:1px dashed var(--ui-border,#ccc)" : ""),
    title: builtin ? bl({ en: "Built-in inspection posture — not an operator policy", ja: "組込の検査ポスチャ(運営のポリシーではない)" }) : "",
    text: (builtin ? "⚙ " : "") + laReasonPhrase(c),
  });
}
// Generic filler that just restates "a policy allowed this" — already conveyed by the green Allow badge + the
// deciding policy_id (drawer). Suppress it so the Why column carries only a MEANINGFUL reason (deny/exception).
const _LA_GENERIC_CODE = { policy_matched: 1, application_allowed: 1 };
// Codes hidden from the row Why (kept in the drawer): the MISLEADING "SaaS tenant-restriction check" (fires even
// with no restriction configured) and the REDUNDANT "default decrypt-all" (already conveyed by the TLS傍受 chip).
// Meaningful interception status (tls_inspection_readiness → "TLS interception", swg_tls_bypass_applied) is KEPT.
const _LA_ROW_HIDE_CODE = { swg_saas_tenant_enforcement_preflight: 1, swg_default_tls_decryption_required: 1 };
function laReasonIsGenericSentence(reason) { return /^request matched\b.*\bpolic/i.test(String(reason || "")); }
function laReasonCell(row) {
  const reason = laVal(row, "reason", "message");
  const codes = (Array.isArray(row.reason_codes) ? row.reason_codes : []).filter((c) => !_LA_GENERIC_CODE[c] && !_LA_ROW_HIDE_CODE[c]);
  // Top line: a meaningful reason (deny/exception) if any, plus WHICH policy decided (the "why allowed").
  const line = [];
  if (reason && !laReasonIsGenericSentence(reason)) line.push(el("span", { text: reason }));
  const pid = laVal(row, "policy_id");
  if (pid) line.push(el("span", { class: "ui-view-desc", title: bl({ en: "Matched policy", ja: "合致ポリシー" }), text: "▸ " + pid }));
  const kids = [];
  if (line.length) kids.push(el("span", { style: "display:inline-flex;gap:8px;align-items:center;flex-wrap:wrap" }, line));
  if (codes.length) kids.push(el("span", { class: "ui-chip-row", style: "margin-top:3px;display:flex;gap:4px;flex-wrap:wrap" }, codes.slice(0, 4).map(laReasonChip)));
  return kids.length ? el("div", {}, kids) : el("span", { class: "ui-view-desc", text: "—" });
}

// source_ip is the mTLS tunnel's OBSERVED peer address (a trust-boundary fact the edge records) — the real
// network origin, not the agent's self-reported value. Only the residual synthetic fallback placeholder
// (when the tunnel peer was unavailable) is hidden as "—".
function laSrcIp(row) { const v = laVal(row, "source_ip"); return (!v || v.indexOf("network-extension-runtime-copy") >= 0) ? "—" : v; }

function laIdentityCell(row) {
  const who = laVal(row, "user_id", "subject_user_id", "actor_user_id", "actor_nhi_id");
  const at = laVal(row, "actor_type");
  const kids = [el("span", { text: laDash(who) })];
  if (at && at !== "human") kids.push(uiBadge(at, "off"));
  // Authorization signal at a glance: this access was gated by a delegated grant / human approval (not just allow).
  if (laVal(row, "delegated_access_grant_id")) kids.push(el("span", { class: "ui-badge ui-badge-off", style: "font-size:10px", title: bl({ en: "Authorized by a delegated grant", ja: "委譲grantで認可" }), text: "🔑 grant" }));
  if (laVal(row, "human_approval_event_id")) kids.push(el("span", { class: "ui-badge ui-badge-off", style: "font-size:10px", title: bl({ en: "Gated by a human approval", ja: "人手承認あり" }), text: "✋ approval" }));
  return el("span", { style: "display:inline-flex;gap:6px;align-items:center;flex-wrap:wrap" }, kids);
}
// app_swg_egress (and other app_swg_* placeholders) are synthetic internal ids, not a resource an operator
// recognizes — the real resource is the destination. Prefer destination; show a real named app only as context.
function laIsSyntheticApp(app) { return !app || /^app_swg/.test(app); }
function laResourceCell(row) {
  const app = laVal(row, "application_id");
  // Inspection events carry the destination in metadata (the model has no top-level field); read it too —
  // a DLP finding puts it in dlp_destination, a tenant-restriction rewrite in destination/saas_application_id.
  const dst = laVal(row, "destination", "fqdn", "sni", "destination_ip") || laVal(row.metadata || {}, "dlp_destination", "destination", "saas_application_id");
  const port = laVal(row, "destination_port");
  const fam = laVal(row, "service_family");
  const method = laVal(row, "request_method");
  const path = laVal(row, "request_path");
  const stdPort = port === "443" || port === "80"; // don't clutter the host with the default port
  const host = dst ? (dst + (port && !stdPort ? ":" + port : "")) : (laIsSyntheticApp(app) ? "" : app);
  // Keep the list column on the DESTINATION (host) — it's the information the operator scans by. The request path
  // is recorded (rows stay distinct) but shown in the detail drawer, not the row: a full path per row narrows the
  // column and crowds out the fields that matter at a glance.
  const main = host || "—";
  void path; // request_path lives in the detail drawer (see _LA_GROUPS Destination), intentionally not in the row
  const chips = [];
  if (method && method !== "GET") chips.push(uiBadge(method, "warn")); // a mutating request (POST/PUT/DELETE) stands out from routine GETs
  if (fam) chips.push(uiBadge(fam, "off"));
  if (dst && !laIsSyntheticApp(app)) chips.push(uiBadge(app, "off")); // a real named SaaS app, as extra context
  return el("span", { style: "display:inline-flex;gap:6px;align-items:center" }, [el("span", { text: main })].concat(chips));
}

// ---- per-stream typed columns -------------------------------------------
// Each column: { h: header, c: (row) -> node|string }. Access is the flagship.
const _LA_COLS = {
  access: [
    { h: { en: "Time", ja: "時刻" }, c: laWhen },
    { h: { en: "Identity", ja: "ユーザー" }, c: laIdentityCell },
    { h: { en: "Decision", ja: "判断" }, c: (r) => laDecisionBadge(r.decision) },
    { h: { en: "Resource", ja: "宛先" }, c: laResourceCell },
    { h: { en: "Why", ja: "理由" }, c: laReasonCell },
    { h: { en: "Device", ja: "デバイス" }, c: (r) => laDash(laVal(r, "device_id")) },
    // Src IP is the mTLS tunnel's OBSERVED peer address (a trust-boundary audit fact, set by the edge) — not the
    // agent's self-reported value. laSrcIp still hides any residual synthetic placeholder.
    { h: { en: "Src IP", ja: "送信元IP" }, c: (r) => laSrcIp(r) },
  ],
  audit: [
    { h: { en: "Time", ja: "時刻" }, c: laWhen },
    { h: { en: "Admin", ja: "実行者" }, c: laAuditActor },
    { h: { en: "Action", ja: "操作" }, c: laAuditActionCell },
    { h: { en: "Object", ja: "対象" }, c: (r) => { const t = laVal(r, "target_type"), id = laVal(r, "target_id"); return laDash([t, id].filter(Boolean).join(": ")); } },
    { h: { en: "Result", ja: "結果" }, c: (r) => laResultBadge(laVal(r, "result")) },
    { h: { en: "Src IP", ja: "送信元IP" }, c: (r) => laSrcIp(r) },
  ],
  inspection_events: [
    { h: { en: "Time", ja: "時刻" }, c: laWhen },
    { h: { en: "Identity", ja: "ユーザー" }, c: laIdentityCell },
    { h: { en: "Resource", ja: "宛先" }, c: laResourceCell },
    { h: { en: "Finding", ja: "検出" }, c: laInspectionFindingCell },
    { h: { en: "Mode", ja: "モード" }, c: (r) => laEventLabel(r, "inspection_mode") },
    { h: { en: "Device", ja: "デバイス" }, c: (r) => laDash(laVal(r, "device_id")) },
  ],
  tool_call_events: [
    { h: { en: "Time", ja: "時刻" }, c: laWhen },
    { h: { en: "Agent", ja: "エージェント" }, c: (r) => laDash(laVal(r, "actor_nhi_id", "user_id")) },
    { h: { en: "Tool", ja: "ツール" }, c: (r) => laDash(laVal(r, "tool_id")) },
    { h: { en: "Action", ja: "アクション" }, c: (r) => laEventLabel(r, "tool_action_type", "action", "event_type") },
    { h: { en: "Boundary", ja: "境界" }, c: (r) => laDash(laVal(r, "context_boundary_id", "agent_task_session_id")) },
    { h: { en: "Decision", ja: "判断" }, c: (r) => laDecisionBadge(r.decision) },
  ],
  human_approval_events: [
    { h: { en: "Time", ja: "時刻" }, c: laWhen },
    { h: { en: "Requester", ja: "申請者" }, c: (r) => laDash(laVal(r, "requester_user_id", "subject_user_id", "user_id")) },
    { h: { en: "Approver", ja: "承認者" }, c: (r) => laDash(laVal(r, "approver_user_id", "approver_id")) },
    { h: { en: "Object", ja: "対象" }, c: (r) => laDash(laVal(r, "target_id", "application_id")) },
    { h: { en: "Event", ja: "イベント" }, c: (r) => laEventLabel(r, "event_type", "action") },
    { h: { en: "Outcome", ja: "結果" }, c: (r) => laResultBadge(laVal(r, "outcome", "result", "trust_state")) },
  ],
  delegated_access_grants: [
    { h: { en: "Time", ja: "時刻" }, c: laWhen },
    { h: { en: "Grantee", ja: "付与先" }, c: (r) => laDash(laVal(r, "grantee_id", "actor_nhi_id", "user_id")) },
    { h: { en: "Scope", ja: "スコープ" }, c: (r) => laDash(laVal(r, "scope", "application_id", "tool_id")) },
    { h: { en: "Event", ja: "イベント" }, c: (r) => laEventLabel(r, "event_type", "action", "status") },
  ],
  connector: [
    { h: { en: "Time", ja: "時刻" }, c: laWhen },
    { h: { en: "Connector", ja: "コネクタ" }, c: (r) => laDash(laVal(r, "connector_id")) },
    { h: { en: "Site", ja: "サイト" }, c: (r) => laDash(laVal(r, "connector_group_id", "site_id", "network_id")) },
    { h: { en: "Event", ja: "イベント" }, c: (r) => laEventLabel(r, "event_type", "action") },
    { h: { en: "Status", ja: "状態" }, c: laConnectorStatusCell },
  ],
  device_state: [
    { h: { en: "Time", ja: "時刻" }, c: laWhen },
    { h: { en: "Device", ja: "デバイス" }, c: (r) => laDash(laVal(r, "device_id")) },
    { h: { en: "User", ja: "ユーザー" }, c: laDeviceUserCell },
    { h: { en: "OS", ja: "OS" }, c: (r) => laDash(laVal(r, "os")) },
    { h: { en: "Posture", ja: "ポスチャ" }, c: laDevicePostureCell },
    { h: { en: "Event", ja: "イベント" }, c: (r) => laEventLabel(r, "event", "event_type", "action") },
  ],
};
function laColsFor(stream) { return _LA_COLS[stream] || [{ h: { en: "Time", ja: "時刻" }, c: laWhen }, { h: { en: "Event", ja: "イベント" }, c: (r) => laDash(laVal(r, "event_type", "type", "action", "decision")) }]; }

// ---- render --------------------------------------------------------------
function renderLogsAuditView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "Logs & Audit", ja: "ログ・監査" }) }),
      el("p", { class: "ui-view-desc", text: bl({ en: "Access decisions and activity, and scheduled exports.", ja: "アクセス判断・アクティビティと、エクスポート。" }) }),
    ]),
  ]));
  content.appendChild(uiTabs([
    { id: "logs", label: bl({ en: "Logs", ja: "ログ" }) },
    { id: "volume", label: bl({ en: "Volume", ja: "ログ量" }) },
    { id: "exports", label: bl({ en: "Exports", ja: "エクスポート" }) },
  ], _laTab, (id) => { _laTab = id; renderLogsAuditView(content); }));
  const section = el("div", {});
  content.appendChild(section);
  if (_laTab === "exports") laExports(section);
  else if (_laTab === "volume") laVolume(section);
  else laLogs(section);
}

// Volume: MEASURE the log rate from real data (access decisions in the last 24h via the search total_matches)
// and project storage — grounding the sizing model in this environment's numbers, not a guess. See
// docs/logs_audit_ui_and_volume_design.md.
function laHumanBytes(b) {
  const u = ["B", "KB", "MB", "GB", "TB", "PB"];
  let i = 0; while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return (b >= 100 || i === 0 ? Math.round(b) : b.toFixed(1)) + " " + u[i];
}
async function laVolume(section) {
  uiState(section, "loading");
  const current = freshRender(section);
  const from = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
  let flows24 = null, users = null, errMsg = null;
  try {
    const r = await apiFetch("GET", "/admin/logs/access?from=" + encodeURIComponent(from) + "&limit=1", undefined, _LA_PLANE);
    if (r.ok && r.body && r.body.total_matches != null) flows24 = Number(r.body.total_matches);
    else errMsg = "HTTP " + (r && r.status);
  } catch (e) { errMsg = String(e); }
  try {
    const dr = await apiFetch("GET", "/admin/human-identities", null, "control");
    const items = (dr && dr.ok && dr.body) ? (dr.body.identities || dr.body.items || []) : [];
    if (items.length) users = items.length;
  } catch (e) { /* optional */ }
  if (flows24 == null) { if (!current()) return; uiState(section, "error", errMsg || bl({ en: "no data", ja: "データなし" }), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => laVolume(section) }); return; }

  const RAW = 1024, COMP = 4; // planning constants: ~1 KB/access record raw, ~4x compression (design doc)
  const storedDay = (flows24 * RAW) / COMP;
  if (!current()) return;
  section.innerHTML = "";
  section.appendChild(el("p", { class: "ui-view-desc", style: "margin:4px 0", text: bl({ en: "Measured from access decisions in the last 24h in THIS environment, projected at ~1 KB/record and ~4x compression. Calibrate against your fleet.", ja: "この環境の直近24hのアクセス判断からの実測値を、1レコード約1KB・圧縮約4倍で投影。実フリートで較正してください。" }) }));
  const card = (label, value, sub) => el("div", { class: "subject-add-panel", style: "min-width:150px;flex:1" }, [
    el("div", { class: "ui-view-desc", text: label }),
    el("div", { style: "font-size:22px;font-weight:700;margin-top:2px", text: value }),
    sub ? el("div", { class: "ui-view-desc", style: "margin-top:2px", text: sub }) : null,
  ].filter(Boolean));
  section.appendChild(el("div", { style: "display:flex;gap:12px;flex-wrap:wrap;margin:8px 0" }, [
    card(bl({ en: "Access decisions / 24h", ja: "アクセス判断 / 24h" }), flows24.toLocaleString(), bl({ en: "measured", ja: "実測" })),
    users ? card(bl({ en: "Flows / user / day", ja: "通信 / 利用者 / 日" }), Math.round(flows24 / users).toLocaleString(), users + bl({ en: " users", ja: " ユーザー" })) : null,
    card(bl({ en: "Stored / day (est.)", ja: "保存 / 日 (推定)" }), laHumanBytes(storedDay)),
    card(bl({ en: "Stored / 30 days", ja: "保存 / 30日" }), laHumanBytes(storedDay * 30)),
    card(bl({ en: "Stored / year", ja: "保存 / 年" }), laHumanBytes(storedDay * 365)),
  ].filter(Boolean)));
  if (users) {
    const perUser = Math.round(flows24 / users);
    section.appendChild(el("p", { class: "ui-view-desc", style: "margin-top:6px", text: bl({ en: "Design-model assumption was 3,000 flows/user/day — your measured " + perUser.toLocaleString() + " calibrates it (per user ≈ " + laHumanBytes((perUser * RAW) / COMP) + "/day stored).", ja: "設計モデルの仮定は 3,000 flows/user/日 ── 実測 " + perUser.toLocaleString() + " で較正できます（1ユーザー ≈ 保存 " + laHumanBytes((perUser * RAW) / COMP) + "/日）。" }) }));
  }
  const lhHost = el("div", { style: "margin-top:18px" });
  section.appendChild(lhHost);
  laLegalHold(lhHost);
  const acHost = el("div", { style: "margin-top:18px" });
  section.appendChild(acHost);
  laAuditChain(acHost);
  const rcHost = el("div", { style: "margin-top:18px" });
  section.appendChild(rcHost);
  laRetentionConfig(rcHost);
}

// Admin-configurable per-stream retention (days) — overrides the built-in defaults at runtime, no redeploy.
async function laRetentionConfig(host) {
  let ov = {};
  try { const r = await apiFetch("GET", "/admin/retention-config", undefined, _LA_PLANE); if (r.ok && r.body) ov = r.body.overrides_days || {}; } catch (e) { /* optional */ }
  host.innerHTML = "";
  host.appendChild(el("h3", { class: "ui-field-label", text: bl({ en: "Retention (per stream)", ja: "保持（ストリーム別）" }) }));
  host.appendChild(el("p", { class: "ui-view-desc", text: bl({ en: "Override how long each stream is kept in hot storage (days) — no redeploy. 0 = keep forever; unset = the built-in default (audit/approvals/grants 365d, others 30d).", ja: "各ストリームの短期保持日数を上書き（再デプロイ不要）。0=無期限、未設定=組込既定（audit/承認/grant は365日、他は30日）。" }) }));
  const keys = Object.keys(ov).sort();
  if (keys.length) host.appendChild(el("div", { style: "display:flex;gap:4px;flex-wrap:wrap;margin:4px 0" }, keys.map((s) => el("span", { class: "ui-badge ui-badge-off", style: "font-size:11px", text: s + " = " + (ov[s] === 0 ? bl({ en: "forever", ja: "無期限" }) : ov[s] + "d") }))));
  const streamF = uiField({ name: "s", label: bl({ en: "Stream", ja: "ストリーム" }), type: "select", value: "access", options: _LA_STREAMS.map((s) => ({ value: s.id, label: bl(s.label) })) });
  const daysF = uiField({ name: "d", label: bl({ en: "Days (0 = forever)", ja: "日数 (0=無期限)" }), type: "number", value: "" });
  streamF.el.style.marginBottom = "0"; daysF.el.style.marginBottom = "0";
  const save = el("button", { class: "ui-btn ui-btn-primary ui-btn-sm", text: bl({ en: "Save", ja: "保存" }) });
  const clr = el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Reset to default", ja: "既定に戻す" }) });
  host.appendChild(el("div", { style: "display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;margin-top:4px" }, [streamF.el, daysF.el, save, clr]));
  save.addEventListener("click", async () => {
    const days = parseInt(daysF.get(), 10);
    if (isNaN(days) || days < 0) { uiToast(bl({ en: "Enter a day count (0 = forever).", ja: "日数を入力（0=無期限）。" }), "err"); return; }
    const r = await apiFetch("POST", "/admin/retention-config", { stream: streamF.get(), days: days }, _LA_PLANE);
    if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
    uiToast(bl({ en: "Retention saved.", ja: "保持を保存しました。" }), "ok"); laRetentionConfig(host);
  });
  clr.addEventListener("click", async () => {
    const r = await apiFetch("POST", "/admin/retention-config", { stream: streamF.get(), clear: true }, _LA_PLANE);
    if (!r.ok) { uiToast("HTTP " + r.status, "err"); return; }
    uiToast(bl({ en: "Reset to default.", ja: "既定に戻しました。" }), "ok"); laRetentionConfig(host);
  });
}

// Audit integrity: verify the tamper-evident hash chain of archived audit segments.
function laAuditChain(host) {
  host.innerHTML = "";
  host.appendChild(el("h3", { class: "ui-field-label", text: bl({ en: "Audit integrity", ja: "監査の完全性" }) }));
  host.appendChild(el("p", { class: "ui-view-desc", text: bl({ en: "Verify the tamper-evident hash chain of the archived audit segments — detects any deleted, altered, or reordered segment.", ja: "アーカイブ済み監査セグメントの改ざん検知ハッシュチェーンを検証 ── 削除・改ざん・並べ替えを検出。" }) }));
  const out = el("span", { class: "ui-view-desc" });
  const btn = el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Verify chain", ja: "チェーン検証" }) });
  host.appendChild(el("div", { class: "ui-toolbar", style: "align-items:center" }, [btn, el("span", { class: "ui-spacer" }), out]));
  btn.addEventListener("click", async () => {
    btn.disabled = true; out.textContent = bl({ en: "Verifying…", ja: "検証中…" });
    let r; try { r = await apiFetch("GET", "/admin/audit-chain/verify", undefined, _LA_PLANE); } catch (e) { btn.disabled = false; out.textContent = ""; uiToast(String(e), "err"); return; }
    btn.disabled = false;
    if (!r.ok) { out.textContent = ""; uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
    const b = r.body || {}; out.innerHTML = "";
    out.appendChild(uiBadge(b.ok ? bl({ en: "Intact", ja: "整合" }) : bl({ en: "BROKEN", ja: "破損" }), b.ok ? "ok" : "danger"));
    out.appendChild(el("span", { style: "margin-left:8px", text: (b.segments || 0) + bl({ en: " segment(s)", ja: " セグメント" }) + (b.ok ? "" : " — " + (b.detail || b.broken_at || "")) }));
  });
}

// Legal hold: freeze retention for THIS tenant (litigation / e-discovery). While held, no log is deleted/tiered.
async function laLegalHold(host) {
  let held = false;
  try { const r = await apiFetch("GET", "/admin/legal-hold", undefined, _LA_PLANE); if (r.ok && r.body) held = !!r.body.tenant_held; } catch (e) { /* optional */ }
  host.innerHTML = "";
  host.appendChild(el("h3", { class: "ui-field-label", text: bl({ en: "Legal hold", ja: "リーガルホールド" }) }));
  host.appendChild(el("p", { class: "ui-view-desc", text: bl({ en: "While ON, ALL logs for this tenant are preserved (retention frozen) for litigation / e-discovery, until released. Survives a restart.", ja: "オンの間、このテナントの全ログを保持（保持凍結）── 訴訟・e-discovery 用、解除まで削除されません。再起動しても維持。" }) }));
  const btn = el("button", { class: "ui-btn ui-btn-sm " + (held ? "ui-btn-danger" : "") });
  btn.textContent = held ? bl({ en: "Release hold", ja: "ホールド解除" }) : bl({ en: "Place legal hold", ja: "リーガルホールドを設定" });
  host.appendChild(el("div", { class: "ui-toolbar", style: "align-items:center" }, [el("span", { style: "font-weight:600" }, [bl({ en: "Status: ", ja: "状態: " }), uiBadge(held ? bl({ en: "Held", ja: "保持中" }) : bl({ en: "Off", ja: "オフ" }), held ? "danger" : "off")]), el("span", { class: "ui-spacer" }), btn]));
  btn.addEventListener("click", async () => {
    const ok = await uiConfirm({ title: held ? bl({ en: "Release the legal hold?", ja: "リーガルホールドを解除?" }) : bl({ en: "Place a legal hold?", ja: "リーガルホールドを設定?" }), body: held ? bl({ en: "Retention resumes — aged logs expire / tier to cold again per policy.", ja: "保持が再開し、古いログはポリシーに従い失効/cold 階層化されます。" }) : bl({ en: "ALL logs for this tenant will be preserved (no deletion, no tiering) until released.", ja: "このテナントの全ログが解除まで保持（削除も階層化もしない）されます。" }), confirmLabel: held ? bl({ en: "Release", ja: "解除" }) : bl({ en: "Place hold", ja: "設定" }), danger: !held });
    if (!ok) return;
    const r = await apiFetch("POST", "/admin/legal-hold", { active: !held }, _LA_PLANE);
    if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
    uiToast(held ? bl({ en: "Legal hold released.", ja: "リーガルホールドを解除しました。" }) : bl({ en: "Legal hold placed.", ja: "リーガルホールドを設定しました。" }), "ok");
    laLegalHold(host);
  });
}

function laLogs(section) {
  section.innerHTML = "";
  const sel = uiField({ name: "stream", type: "select", value: _laStream, options: _LA_STREAMS.map((s) => ({ value: s.id, label: bl(s.label) })) });
  sel.el.style.marginBottom = "0";
  sel.el.querySelector("select").addEventListener("change", () => { _laStream = sel.get(); _laFilters = {}; laLoadStream(host, filterHost, summaryHost); });
  section.appendChild(el("div", { class: "ui-toolbar" }, [
    el("span", { class: "ui-view-desc", text: bl({ en: "Stream:", ja: "ストリーム:" }) }), sel.el,
    el("span", { class: "ui-spacer" }),
    el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Reload", ja: "再読込" }), onClick: () => laLoadStream(host, filterHost, summaryHost) }),
  ]));
  const filterHost = el("div", {});
  const summaryHost = el("div", {});
  const host = el("div", {});
  section.appendChild(filterHost);
  section.appendChild(summaryHost);
  section.appendChild(host);
  laFilterBar(filterHost, host, summaryHost);
  laLoadStream(host, filterHost, summaryHost);
}

// Faceted filter bar. All fields map to existing backend query params (adminLogFilters + q/from/to).
function laFilterBar(filterHost, host, summaryHost) {
  filterHost.innerHTML = "";
  const isDecisionStream = _laStream === "access" || _laStream === "tool_call_events";
  const fields = [];
  const q = uiField({ name: "q", label: bl({ en: "Search", ja: "検索" }), type: "text", value: _laFilters.q || "" }); fields.push(["q", q]);
  if (isDecisionStream) {
    const dec = uiField({ name: "decision", label: bl({ en: "Decision", ja: "判断" }), type: "select", value: _laFilters.decision || "", options: [{ value: "", label: bl({ en: "Any", ja: "すべて" }) }, { value: "allow", label: bl({ en: "Allow", ja: "許可" }) }, { value: "deny", label: bl({ en: "Deny", ja: "拒否" }) }] });
    fields.push(["decision", dec]);
  }
  const user = uiField({ name: "user_id", label: bl({ en: "User", ja: "ユーザー" }), type: "text", value: _laFilters.user_id || "" }); fields.push(["user_id", user]);
  // Filter by DESTINATION (host), not application_id: for egress flows application_id is the synthetic
  // "app_swg_egress" placeholder, so an app-name filter never matched. The host is what operators filter by.
  if (isDecisionStream) { const dst = uiField({ name: "destination", label: bl({ en: "Destination", ja: "宛先" }), type: "text", value: _laFilters.destination || "" }); fields.push(["destination", dst]); }
  const dev = uiField({ name: "device_id", label: bl({ en: "Device", ja: "デバイス" }), type: "text", value: _laFilters.device_id || "" }); fields.push(["device_id", dev]);
  const from = uiField({ name: "from", label: bl({ en: "From", ja: "開始" }), type: "date", value: _laFilters._from || "" }); fields.push(["from", from]);
  const to = uiField({ name: "to", label: bl({ en: "To", ja: "終了" }), type: "date", value: _laFilters._to || "" }); fields.push(["to", to]);

  const apply = () => {
    const f = {};
    // Date fields are day-granular. Interpret the picked day in the operator's LOCAL time and span the WHOLE day:
    // from = local start-of-day, to = local END-of-day. Previously "to" became that day's 00:00Z, so selecting a
    // "to" date excluded the entire day (occurred_at <= midnight) and date filtering returned nothing.
    fields.forEach(([k, fld]) => { const v = String(fld.get() || "").trim(); if (!v) return; if (k === "from") { f._from = v; f.from = new Date(v + "T00:00:00").toISOString(); } else if (k === "to") { f._to = v; f.to = new Date(v + "T23:59:59.999").toISOString(); } else f[k] = v; });
    _laFilters = f;
    laLoadStream(host, filterHost, summaryHost);
  };
  fields.forEach(([, fld]) => { const inp = fld.el.querySelector("input,select"); if (inp) inp.addEventListener("keydown", (e) => { if (e.key === "Enter") apply(); }); });
  const applyBtn = el("button", { class: "ui-btn ui-btn-primary ui-btn-sm", text: bl({ en: "Apply", ja: "適用" }), onClick: apply });
  const clearBtn = el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Clear", ja: "クリア" }), onClick: () => { _laFilters = {}; laFilterBar(filterHost, host, summaryHost); laLoadStream(host, filterHost, summaryHost); } });
  const bar = el("div", { style: "display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;margin:8px 0 4px" }, fields.map(([, f]) => { f.el.style.marginBottom = "0"; return f.el; }).concat([applyBtn, clearBtn]));
  filterHost.appendChild(bar);
}

const _LA_PAGE = 100; // page size (backend max 200). Older data is reached by paging via next_cursor, not by one big pull.
let _laRows = [];     // rows accumulated across pages for the active query
let _laCursor = "";   // next_cursor from the last page ("" = no more / not loaded)
let _laTotal = 0;     // total_matches for the active query (across the whole hot store, not just this page)
function laQueryString(cursor) {
  const p = new URLSearchParams();
  Object.keys(_laFilters).forEach((k) => { if (k.charAt(0) === "_") return; const v = _laFilters[k]; if (v) p.set(k, v); });
  p.set("limit", String(_LA_PAGE));
  if (cursor) p.set("cursor", cursor); // page forward to OLDER rows (server orders newest-first)
  return p.toString();
}

// Client-side summary over the loaded window (no extra endpoint): decision mix + allow rate.
function laSummary(summaryHost, rows, stream) {
  summaryHost.innerHTML = "";
  if (!stream === "access" || !rows.length) return;
  const counts = {}; let allow = 0, total = 0;
  rows.forEach((r) => { const d = String(r.decision || "").toLowerCase(); if (!d) return; counts[d] = (counts[d] || 0) + 1; total++; if (d === "allow") allow++; });
  if (!total) return;
  const rate = Math.round((allow / total) * 100);
  const chips = Object.keys(counts).sort().map((d) => el("span", { style: "display:inline-flex;align-items:center;gap:5px" }, [laDecisionBadge(d), el("span", { class: "ui-view-desc", text: String(counts[d]) })]));
  summaryHost.appendChild(el("div", { class: "subject-add-panel", style: "display:flex;gap:16px;align-items:center;flex-wrap:wrap;margin:6px 0" }, [
    el("strong", { text: bl({ en: "Over the latest ", ja: "直近 " }) + total + bl({ en: " decisions", ja: " 件" }) }),
    el("span", { style: "display:inline-flex;gap:12px" }, chips),
    el("span", { class: "ui-spacer" }),
    el("span", { text: bl({ en: "Allow rate ", ja: "許可率 " }) }), el("strong", { text: rate + "%" }),
  ]));
}

// Load the active query. append=false starts a fresh query (page 1, resets accumulation); append=true pulls the
// NEXT page (older rows) via next_cursor and appends. The filters (q/from/to/user/decision) are applied server-side
// across the whole hot store — paging is how older matches are reached, not a client-side slice of one page.
async function laLoadStream(host, filterHost, summaryHost, append) {
  // The guard is taken for EVERY call, not only the fresh ones: "Load older" appends to the same host, and an
  // append that lands after a newer query started would concatenate two different result sets.
  const current = freshRender(host);
  if (!append) { _laRows = []; _laCursor = ""; _laTotal = 0; uiState(host, "loading"); }
  try {
    const qs = laQueryString(append ? _laCursor : "");
    const r = await apiFetch("GET", "/admin/logs/" + encodeURIComponent(_laStream) + (qs ? "?" + qs : ""), undefined, laPlaneFor(_laStream));
    if (!r.ok) { if (!current()) return; uiState(host, "error", "HTTP " + r.status, { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => laLoadStream(host, filterHost, summaryHost) }); return; }
    const body = r.body || {};
    const rows = Array.isArray(body) ? body : (body.rows || body.entries || body.events || []);
    _laRows = append ? _laRows.concat(rows) : rows;
    _laCursor = (body && body.next_cursor) || "";
    if (body && body.total_matches != null) _laTotal = Number(body.total_matches);
  } catch (e) { if (!current()) return; uiState(host, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => laLoadStream(host, filterHost, summaryHost) }); return; }
  // For the audit stream, resolve admin principal ids → email/name once so the Admin column shows WHO acted.
  if (_laStream === "audit" && !append) {
    _laAdminDir = {};
    try {
      const ar = await apiFetch("GET", "/admin/admins", undefined, _LA_PLANE);
      const admins = (ar && ar.ok && ar.body && (ar.body.admins || ar.body.principals || ar.body.items)) || [];
      admins.forEach((a) => { const id = a && (a.id || a.principal_id); if (id) _laAdminDir[id] = { email: (a.email || "").trim(), name: ((a.display_name || a.name) || "").trim() }; });
    } catch (e) { /* directory optional — metadata email still shows */ }
  }
  if (summaryHost) laSummary(summaryHost, _laRows, _laStream);
  if (!_laRows.length) { if (!current()) return; uiState(host, "empty", bl({ en: "No matching entries.", ja: "該当エントリはありません。" })); return; }
  const cols = laColsFor(_laStream);
  const trs = _laRows.map((row) => {
    const tds = cols.map((col) => { const v = col.c(row); return el("td", typeof v === "string" ? { text: v } : {}, typeof v === "string" ? null : v); });
    tds.push(el("td", { class: "ui-row-actions" }, el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Details", ja: "詳細" }), onClick: () => laDetail(row) })));
    return el("tr", { style: "cursor:pointer" }, tds);
  });
  if (!current()) return;
  host.innerHTML = "";
  host.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, cols.map((col) => el("th", { text: bl(col.h) })).concat([el("th", { text: "" })]))),
    el("tbody", {}, trs),
  ]));
  // Footer: how many of the total matched are loaded, + a way to reach OLDER rows. Without this the view showed
  // only the most-recent page and search looked like it "only saw the current screen".
  const countTxt = _laTotal
    ? bl({ en: "Showing ", ja: "表示 " }) + _laRows.length + bl({ en: " of ", ja: " / " }) + _laTotal + bl({ en: " matches", ja: " 件（一致）" })
    : bl({ en: "Showing ", ja: "表示 " }) + _laRows.length;
  const footer = el("div", { style: "display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin:8px 0 2px" }, [el("span", { class: "ui-view-desc", text: countTxt })]);
  if (_laCursor) footer.appendChild(el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Load older", ja: "さらに古いものを読み込む" }), onClick: () => laLoadStream(host, filterHost, summaryHost, true) }));
  else footer.appendChild(el("span", { class: "ui-view-desc", text: bl({ en: "— end of matches (older data past retention is in cold archive; use Exports)", ja: "— 一致の末尾（保持期間を過ぎた古いデータはコールドアーカイブ。エクスポートを利用）" }) }));
  host.appendChild(footer);
}

// Structured detail drawer: grouped, labelled fields; raw JSON only behind "View raw".
const _LA_GROUPS = [
  { title: { en: "Identity", ja: "ユーザー" }, keys: ["user_id", "subject_user_id", "actor_user_id", "actor_type", "actor_nhi_id"] },
  { title: { en: "Authentication & authorization", ja: "認証・認可" }, keys: ["session_id", "auth_time", "authentication_event_id", "delegated_access_grant_id", "human_approval_event_id", "agent_task_session_id", "reauthentication_reason", "authentication_max_age_seconds"] },
  { title: { en: "Device", ja: "デバイス" }, keys: ["device_id", "source_ip", "source_port", "posture", "trust_state"] },
  { title: { en: "Destination", ja: "宛先" }, keys: ["application_id", "destination", "request_method", "request_path", "destination_ip", "destination_port", "fqdn", "sni", "protocol", "service_family"] },
  { title: { en: "Decision & policy", ja: "判断・ポリシー" }, keys: ["decision", "reason", "reason_codes", "policy_id", "policy_bundle_id", "policy_bundle_version", "matched_conditions", "cache_status", "bypass", "action", "result", "event_type", "target_type", "target_id"] },
  { title: { en: "Risk", ja: "リスク" }, keys: ["risk_state_id", "risk_state_severity", "risk_recommended_action"] },
  { title: { en: "Inspection", ja: "検査" }, keys: ["inspection_profile_id", "inspection_mode", "inspection_route_category", "data_classification"] },
  { title: { en: "Agent / tool", ja: "エージェント・ツール" }, keys: ["tool_id", "tool_action_type", "context_boundary_id", "mcp_server_id", "runtime_environment_id"] },
];
function laFieldRow(k, v) {
  let node;
  if (k === "decision") node = laDecisionBadge(v);
  else if (k === "reason_codes" && Array.isArray(v)) node = el("span", { style: "display:flex;gap:4px;flex-wrap:wrap" }, v.map(laReasonChip));
  else if (k === "source_ip") node = el("span", { text: laSrcIp({ source_ip: v }) });
  else node = el("span", { text: Array.isArray(v) ? v.join(", ") : String(v) });
  return el("div", { style: "display:flex;gap:10px;padding:3px 0;border-bottom:1px solid var(--ui-border,#eee)" }, [
    el("span", { class: "ui-view-desc", style: "min-width:180px;flex:none", text: k.replace(/_/g, " ") }), node,
  ]);
}
// One-line summary of a related record (grant / approval / inspection / decision-trace) linked to a decision.
function laRelatedSummary(s, r) {
  if (s === "delegated_access_grants") return [laVal(r, "grantee_id", "actor_nhi_id", "user_id"), laVal(r, "scope", "application_id", "tool_id"), laVal(r, "event_type", "action", "status")].filter(Boolean).join(" · ") || "—";
  if (s === "human_approval_events") return [laVal(r, "requester_user_id", "user_id", "subject_user_id"), "→", laVal(r, "approver_user_id", "approver_id"), laVal(r, "outcome", "result", "trust_state")].filter(Boolean).join(" ") || "—";
  if (s === "inspection_events") return [laPretty(laVal(r, "finding_type", "event_type")), laVal(r, "inspection_mode"), laVal(r, "severity")].filter(Boolean).join(" · ") || "—";
  return Object.keys(r).slice(0, 3).map((k) => k + "=" + laVal(r, k)).join(" ") || "—";
}
// Fetch the records LINKED to an access decision (its grant, approval, inspection, decision trace) and show
// them — so a grant/approval is visible right from the access-log entry it authorized.
async function laRelatedRecords(host, decisionId) {
  host.innerHTML = "";
  host.appendChild(el("div", { class: "ui-field-label", text: bl({ en: "Related records", ja: "関連レコード" }) }));
  const status = el("div", { class: "ui-view-desc", text: bl({ en: "Loading…", ja: "読込中…" }) });
  host.appendChild(status);
  let body;
  try { const r = await apiFetch("GET", "/admin/access-decisions/" + encodeURIComponent(decisionId), undefined, _LA_PLANE); if (!r.ok) { status.textContent = "HTTP " + r.status; return; } body = r.body; }
  catch (e) { status.textContent = String(e); return; }
  const rel = (body && body.related_logs) || {};
  const streams = Object.keys(rel).filter((s) => (rel[s] || []).length);
  status.remove();
  if (!streams.length) { host.appendChild(el("div", { class: "ui-view-desc", text: bl({ en: "No linked grant / approval / inspection for this decision.", ja: "この判断に紐づく grant/承認/検査はありません。" }) })); return; }
  streams.forEach((s) => {
    const label = (_LA_STREAMS.find((x) => x.id === s) || { label: { en: s, ja: s } }).label;
    host.appendChild(el("div", { style: "margin:6px 0" }, [
      el("div", { style: "font-weight:600;font-size:12px;display:inline-flex;gap:6px;align-items:center" }, [el("span", { text: bl(label) }), uiBadge(String(rel[s].length), "off")]),
      el("div", {}, rel[s].slice(0, 5).map((rr) => el("div", { class: "ui-view-desc", style: "padding:2px 0", text: "▸ " + laRelatedSummary(s, rr) }))),
    ]));
  });
}
function laDetail(row) {
  const present = new Set();
  const body = [];
  _LA_GROUPS.forEach((g) => {
    const rows = g.keys.filter((k) => { const v = row[k]; return v !== undefined && v !== null && String(v) !== "" && !(Array.isArray(v) && !v.length); });
    rows.forEach((k) => present.add(k));
    if (rows.length) body.push(el("div", { style: "margin:6px 0" }, [el("div", { class: "ui-field-label", text: bl(g.title) })].concat(rows.map((k) => laFieldRow(k, row[k])))));
  });
  const other = Object.keys(row).filter((k) => !present.has(k) && k !== "metadata" && row[k] !== undefined && row[k] !== null && String(row[k]) !== "");
  if (other.length) body.push(el("div", { style: "margin:6px 0" }, [el("div", { class: "ui-field-label", text: bl({ en: "Other", ja: "その他" }) })].concat(other.map((k) => laFieldRow(k, row[k])))));
  // Link the grant / approval / inspection / decision-trace records to THIS access decision.
  const decId = laVal(row, "access_decision_id");
  if (decId) { const relHost = el("div", { style: "margin:10px 0" }); body.push(relHost); laRelatedRecords(relHost, decId); }
  const raw = el("div", { class: "ui-preview", style: "display:none;white-space:pre-wrap;margin-top:8px", text: JSON.stringify(row, null, 2) });
  const rawBtn = el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "View raw", ja: "Raw表示" }), onClick: () => { const on = raw.style.display === "none"; raw.style.display = on ? "block" : "none"; rawBtn.textContent = on ? bl({ en: "Hide raw", ja: "Raw非表示" }) : bl({ en: "View raw", ja: "Raw表示" }); } });
  body.push(el("div", { style: "margin-top:10px" }, [rawBtn, raw]));
  const m = uiModal({ title: bl({ en: "Log entry", ja: "ログエントリ" }), body: body, footer: [el("button", { class: "ui-btn", text: bl({ en: "Close", ja: "閉じる" }), onClick: () => m.close() })] });
}

// ---- Exports (unchanged behaviour) --------------------------------------
async function laExports(section) {
  uiState(section, "loading");
  const current = freshRender(section);
  let jobs;
  try { const r = await apiFetch("GET", "/admin/export-jobs", undefined, _LA_PLANE); if (!r.ok) throw new Error("HTTP " + r.status); jobs = (r.body && r.body.jobs) || []; }
  catch (e) { if (!current()) return; uiState(section, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => laExports(section) }); return; }
  if (!current()) return;
  section.innerHTML = "";
  section.appendChild(el("div", { class: "ui-toolbar" }, [el("span", { class: "ui-spacer" }), el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "+ New export", ja: "+ エクスポート作成" }), onClick: () => openExportForm(section) })]));
  if (!jobs.length) { section.appendChild(emptyBox(bl({ en: "No exports yet.", ja: "エクスポートがありません。" }))); return; }
  section.appendChild(simpleTable([bl({ en: "Stream", ja: "ストリーム" }), bl({ en: "Format", ja: "形式" }), bl({ en: "Status", ja: "状態" }), bl({ en: "Created", ja: "作成" })], jobs.map((j) => [
    el("span", { text: j.stream || "—" }), el("span", { text: j.format || "—" }), uiBadge(j.status || "—", /done|complete|ready/i.test(j.status || "") ? "ok" : "off"), el("span", { class: "ui-view-desc", text: j.created_at ? window.dsseFormatTime(j.created_at) : "—" }),
  ])));
}

function openExportForm(section) {
  const streamF = uiField({ name: "stream", label: bl({ en: "Log", ja: "ログ" }), type: "select", value: "access", options: _LA_STREAMS.map((s) => ({ value: s.id, label: bl(s.label) })) });
  const fmtF = uiField({ name: "fmt", label: bl({ en: "Format", ja: "形式" }), type: "select", value: "ndjson", options: [{ value: "ndjson", label: "NDJSON" }, { value: "csv", label: "CSV" }] });
  const fromF = uiField({ name: "from", label: bl({ en: "From", ja: "開始" }), type: "date" });
  const toF = uiField({ name: "to", label: bl({ en: "To", ja: "終了" }), type: "date" });
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Create export", ja: "エクスポート作成" }) });
  const m = uiModal({ title: bl({ en: "New export", ja: "エクスポート作成" }), body: [streamF.el, fmtF.el, fromF.el, toF.el], footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit] });
  submit.addEventListener("click", async () => {
    submit.disabled = true;
    const payload = { stream: streamF.get(), format: fmtF.get() };
    if (fromF.get()) payload.from = new Date(fromF.get()).toISOString();
    if (toF.get()) payload.to = new Date(toF.get()).toISOString();
    try {
      const r = await apiFetch("POST", "/admin/export-jobs", payload, _LA_PLANE);
      if (!r.ok) { submit.disabled = false; uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
      m.close(); uiToast(bl({ en: "Export started.", ja: "エクスポートを開始しました。" }), "ok"); laExports(section);
    } catch (e) { submit.disabled = false; uiToast(String(e), "err"); }
  });
}
