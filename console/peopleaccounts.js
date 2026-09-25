"use strict";

// peopleaccounts.js — "People & Service Accounts" (control plane). Two jobs, per
// docs/people_service_accounts_direction.md:
//   • People    = a read-centric IDENTITY DIRECTORY, normally SYNCED from an IdP/HR source (sources / health /
//                 staleness / import runs surfaced). Manual add is a labeled fallback and grants NO access.
//   • Service accounts / Delegations / Activity = NHI / AGENT governance that actually feeds enforcement
//                 (NHI risk, delegated-grant validity, tool-action boundary).
// Access is NOT granted here — end-user access = sign-in + Internet/Connector Access (idgroup) rules.
// Backend (control): /admin/human-identities (+ /sources, /sources/health, /import-runs),
//   /admin/non-human-identities (+ /risk), /admin/delegated-grants (+ /{id}/revoke),
//   /admin/tool-call-events, /admin/human-approval-events.

// People = the synced identity DIRECTORY (control plane). Service accounts / Delegations / Activity = the
// ENFORCEMENT plane (the Edge, where the decision engine reads NHI / grants / policies) — the SAME plane the
// Internet/Connector Access rules write to. Writing agent config to the Edge (not just the control plane) is what
// makes agent governance actually enforce; see docs/agentic_governance_configuration_design.md (S1).
const _PA_DIR = "control";
const _PA_ENF = undefined; // undefined = the default (Edge) plane
let _paTab = "people";

function renderPeopleView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "People & Service Accounts", ja: "ユーザー・サービスアカウント" }) }),
      el("p", { class: "ui-view-desc", text: bl({
        en: "The identities the system knows: people (synced from your IdP/HR directory) and the automated accounts it governs (service accounts, AI agents). This is inventory + agent governance — access is NOT granted here. End-user access is decided by sign-in and Internet/Connector Access rules.",
        ja: "システムが把握する人と自動アカウント ── 人(IdP/HR ディレクトリから同期)と、統治する自動アカウント(サービスアカウント・AI エージェント)。ここは台帳とエージェントの統治であり、アクセスは付与しません。エンドユーザーのアクセスは、サインインと「インターネットアクセス」「コネクタ経由アクセス」のルールで決まります。",
      }) }),
    ]),
  ]));
  content.appendChild(uiTabs([
    { id: "people", label: bl({ en: "People", ja: "ユーザー" }) },
    { id: "accounts", label: bl({ en: "Service accounts", ja: "サービスアカウント" }) },
    { id: "delegations", label: bl({ en: "Delegations", ja: "委譲" }) },
    { id: "activity", label: bl({ en: "Activity", ja: "活動" }) },
  ], _paTab, (id) => { _paTab = id; renderPeopleView(content); }));
  const section = el("div", {});
  content.appendChild(section);
  if (_paTab === "accounts") paAccounts(section);
  else if (_paTab === "delegations") paDelegations(section);
  else if (_paTab === "activity") paActivity(section);
  else paPeople(section);
}

async function paGet(path, plane) { const r = await apiFetch("GET", path, undefined, plane); if (!r.ok) throw new Error("HTTP " + r.status); return r.body || {}; }
async function paList(path, key, plane) { const b = await paGet(path, plane); return (b && b[key]) || []; }
async function paLoadRiskMarks() {
  try {
    const r = await apiFetch("GET", "/admin/risk-signals", null, _PA_ENF);
    const marks = r && r.ok && r.body && r.body.high_risk;
    if (marks && typeof marks === "object" && !Array.isArray(marks) &&
        Object.values(marks).every((severity) => ["medium", "high", "critical"].includes(severity))) return marks;
  } catch (e) { /* Directory readers may not have risk.read. */ }
  return null;
}

// paWriteEnforcement writes an enforcement-config resource (delegated grant, service account / NHI, agent policy).
// It goes to the ENFORCEMENT Edge by default — where this single-edge lab decides, so a grant lands exactly where
// the decision engine reads it. If the Edge is a config-PULLER (a fleet: -config-source-url set) it rejects the
// write with 409 "authored on the control plane"; we then transparently retry on the CONTROL PLANE, the fleet
// authority that fans the change out via the config-bundle. One console, correct in both deployment models — see
// docs/delegated_grant_consistency.md (the Edge/CP grant-store consistency note).
async function paWriteEnforcement(method, path, body) {
  let r = await apiFetch(method, path, body, _PA_ENF); // Edge (single-edge authority; where enforcement reads)
  if (r && r.status === 409 && /control plane/i.test((r.body && (r.body.error || r.body.message)) || "")) {
    r = await apiFetch(method, path, body, _PA_DIR); // fleet: the control plane is authoritative + distributes
  }
  return r;
}

// setUserRisk marks / clears a person's risk from their own row (no free-text id) — replaces the Device Risk
// page's user option. "high" makes a risk-gated policy bite (e.g. force re-authentication) for that user on ANY
// device; "none" clears it. Keyed by the person's id (the IdP subject the decision request carries).
async function setUserRisk(u, severity, section) {
  const r = await apiFetch("POST", "/admin/risk-signals", { entity_type: "user", entity_id: u.id, severity: severity, evidence_ref: "console" }, _PA_ENF);
  if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); paPeople(section); return; }
  uiToast(severity === "none" ? bl({ en: "Risk cleared.", ja: "リスクを解除しました。" }) : bl({ en: "Risk set: " + severity + ".", ja: "リスクを設定: " + severity + "。" }), "ok");
  paPeople(section);
}

// ---- People: a synced directory (health + sources + import runs + identities), manual add demoted ----
async function paPeople(section) {
  uiState(section, "loading");
  const current = freshRender(section);
  let health, sources, runs, people;
  try {
    [health, sources, runs, people] = await Promise.all([
      paGet("/admin/human-identities/sources/health", _PA_DIR).catch(() => ({})),
      paList("/admin/human-identities/sources", "sources", _PA_DIR).catch(() => []),
      paList("/admin/human-identities/import-runs", "runs", _PA_DIR).catch(() => []),
      paList("/admin/human-identities", "identities", _PA_DIR),
    ]);
  } catch (e) { if (!current()) return; uiState(section, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => paPeople(section) }); return; }
  // Removed identities (the sync's soft-delete terminal state) are not part of the live directory — hide them.
  people = (people || []).filter((u) => (u.status || "").toLowerCase() !== "deleted");
  // Current high-risk marks (the shared overlay lives on the enforcement Edge), keyed by person id.
  // A denied or unavailable read must not render an unverified Normal value or an edit control.
  const riskMap = await paLoadRiskMarks();
  if (!current()) return;
  section.innerHTML = "";
  if (riskMap === null) section.appendChild(el("div", { class: "ui-view-desc", role: "status", text: bl({
    en: "Risk settings are unavailable. People remain visible, but risk is Unknown and cannot be edited.",
    ja: "リスク設定を取得できません。ユーザー一覧は表示できますが、リスクは不明となり編集できません。",
  }) }));

  // Directory-sync health banner: this is a SYNCED directory; the operator should see freshness, not a raw list.
  const synced = (health.source_count || 0) > 0;
  const staleDays = health.stale_after_seconds ? Math.round(health.stale_after_seconds / 86400) : null;
  const hb = el("div", { class: "pa-health " + (health.status === "ok" ? "pa-health-ok" : health.status ? "pa-health-warn" : "") });
  hb.appendChild(el("strong", { text: synced
    ? bl({ en: (health.source_count) + " identity source(s) · ", ja: "identity ソース " + (health.source_count) + " 件 · " }) + (health.status === "ok" ? bl({ en: "healthy", ja: "健全" }) : (health.status || "—"))
    : bl({ en: "No identity source connected", ja: "identity ソース未接続" }) }));
  hb.appendChild(el("div", { class: "ui-view-desc", text: synced
    ? bl({ en: "People are synced from your IdP/HR directory" + (staleDays ? "; a source is stale after " + staleDays + " day(s)." : "."), ja: "ユーザーは IdP/HR ディレクトリから同期されます" + (staleDays ? "; " + staleDays + " 日で stale 扱い。" : "。") })
    : bl({ en: "People are normally synced from an IdP/HR directory. None is connected yet — the list below is manual entries only.", ja: "ユーザーは通常 IdP/HR ディレクトリから同期します。未接続のため、下の一覧は手動エントリのみです。" }) }));
  section.appendChild(hb);

  // Sources (per-source counts + freshness) — the value that was previously hidden.
  if (sources.length) {
    section.appendChild(el("h3", { class: "ui-field-label", text: bl({ en: "Sources", ja: "ソース" }) }));
    section.appendChild(simpleTable(
      [bl({ en: "Source", ja: "ソース" }), bl({ en: "Total", ja: "総数" }), bl({ en: "Active", ja: "有効" }), bl({ en: "Expired", ja: "期限切れ" }), bl({ en: "Last import", ja: "最終取込" })],
      sources.map((s) => [el("strong", { text: s.source || "—" }), el("span", { text: String(s.total || 0) }), el("span", { text: String(s.active || 0) }), el("span", { text: String(s.expired || 0) }), el("span", { class: "ui-view-desc", text: s.observed_at ? window.dsseFormatTime(s.observed_at) : "—" })])
    ));
    if (runs.length) {
      section.appendChild(el("div", { class: "ui-view-desc", style: "margin-top:6px", text: bl({ en: "Recent import: ", ja: "最近の取込: " }) + runs.slice(0, 3).map((r) => (r.source || "?") + " +" + (r.upserted || 0) + "/-" + (r.deactivated || 0)).join("  ·  ") }));
    }
  }

  // Identities directory (read) — richer columns from the sync (source / dept / last seen / expires).
  section.appendChild(el("h3", { class: "ui-field-label", style: "margin-top:18px", text: bl({ en: "Identities", ja: "identity 一覧" }) }));
  section.appendChild(paSearchTable(
    bl({ en: "Search people by name, email, dept, source…", ja: "名前・メール・部門・出所で検索…" }),
    people,
    (u) => [u.display_name, u.subject, u.email, u.department, u.source, u.id].filter(Boolean).join(" "),
    (rows) => simpleTable(
      [bl({ en: "Person", ja: "ユーザー" }), bl({ en: "Email", ja: "メール" }), bl({ en: "Dept", ja: "部門" }), bl({ en: "Source", ja: "出所" }), bl({ en: "Last seen", ja: "最終確認" }), bl({ en: "Status", ja: "状態" }), bl({ en: "Risk", ja: "リスク" }), bl({ en: "", ja: "" })],
      rows.map((u) => {
        const sev = riskMap && riskMap[u.id];
        const riskSel = riskMap === null ? null : el("select", { class: "ui-input", style: "width:auto;padding:2px 4px" }, [
          el("option", { value: "none", text: bl({ en: "Normal", ja: "通常" }) }),
          el("option", { value: "medium", text: bl({ en: "Medium", ja: "中" }) }),
          el("option", { value: "high", text: bl({ en: "High", ja: "高" }) }),
          el("option", { value: "critical", text: bl({ en: "Critical", ja: "重大" }) }),
        ]);
        if (riskSel) {
          riskSel.value = sev || "none";
          riskSel.addEventListener("change", () => setUserRisk(u, riskSel.value, section));
        }
        return [
          el("strong", { text: u.display_name || u.subject || u.id }), el("span", { text: u.email || "—" }), el("span", { text: u.department || "—" }),
          el("span", { text: u.source || "—" }), el("span", { class: "ui-view-desc", text: u.last_seen_at ? window.dsseFormatTime(u.last_seen_at) : "—" }),
          uiBadge(u.status === "active" ? bl({ en: "Active", ja: "有効" }) : (u.status || "—"), u.status === "active" ? "ok" : "off"),
          uiBadge(riskMap === null ? bl({ en: "Unknown", ja: "不明" }) : sev === "critical" ? bl({ en: "Critical", ja: "重大" }) : sev === "high" ? bl({ en: "High", ja: "高" }) : sev === "medium" ? bl({ en: "Medium", ja: "中" }) : bl({ en: "Normal", ja: "通常" }), (sev === "high" || sev === "critical") ? "danger" : (sev === "medium" ? "warn" : "off")),
          el("span", { class: "ui-row-actions" }, [
            ...(riskSel ? [riskSel, document.createTextNode(" ")] : []),
            paRemoveBtn(
              bl({ en: "Remove this identity from the directory?", ja: "この identity をディレクトリから除去?" }),
              bl({ en: "It leaves the live directory (soft-remove). Access is decided by sign-in + rules, so this does not change access.", ja: "ライブディレクトリから外れます(ソフト除去)。アクセスはサインイン+ルールで決まるため変わりません。" }),
              () => apiFetch("POST", "/admin/human-identities", { id: u.id, subject: u.subject, email: u.email, source: u.source || "manual", status: "deleted" }, _PA_DIR),
              () => paPeople(section)),
          ]),
        ];
      })
    ),
    synced ? bl({ en: "No identities in the directory yet.", ja: "ディレクトリに identity がありません。" }) : bl({ en: "No people yet. Connect an IdP/HR source, or add one manually below.", ja: "ユーザーがいません。IdP/HR ソースを接続するか、下で手動追加してください。" })
  ));

  // Manual add — DEMOTED to a labeled fallback with a "no access granted" note.
  section.appendChild(el("div", { class: "pa-fallback" }, [
    el("span", { class: "ui-view-desc", text: bl({ en: "Not in a synced source? Add manually — this records an identity but does NOT grant access.", ja: "同期ソースに無い? 手動追加 ── identity を記録するだけで、アクセスは付与しません。" }) }),
    el("span", { class: "ui-spacer" }),
    el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Add manually", ja: "手動追加" }), onClick: () => openPersonForm(section) }),
  ]));
}
function openPersonForm(section) {
  const idF = uiField({ name: "id", label: bl({ en: "ID", ja: "ID" }), required: true, placeholder: "u1" });
  const subjF = uiField({ name: "subj", label: bl({ en: "Username / subject", ja: "ユーザー名 / subject" }), required: true, placeholder: "alice" });
  const emailF = uiField({ name: "email", label: bl({ en: "Email", ja: "メール" }), placeholder: "alice@example.com" });
  const statusF = uiField({ name: "status", label: bl({ en: "Status", ja: "状態" }), type: "select", value: "active", options: [{ value: "active", label: bl({ en: "Active", ja: "有効" }) }, { value: "disabled", label: bl({ en: "Disabled", ja: "無効" }) }] });
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Add person", ja: "ユーザー追加" }) });
  const m = uiModal({ title: bl({ en: "Add a person (manual fallback)", ja: "ユーザーを追加(手動フォールバック)" }), body: [el("p", { class: "ui-field-hint", text: bl({ en: "Recording an identity here does not grant any access — access is decided by sign-in + rules.", ja: "ここで identity を記録してもアクセスは付与されません ── アクセスはサインイン + ルールで決まります。" }) }), idF.el, subjF.el, emailF.el, statusF.el], footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit] });
  submit.addEventListener("click", async () => {
    if (!idF.validate() || !subjF.validate()) return; submit.disabled = true;
    const r = await apiFetch("POST", "/admin/human-identities", { id: idF.get(), subject: subjF.get(), email: emailF.get(), source: "manual", status: statusF.get() }, _PA_DIR);
    if (!r.ok) { submit.disabled = false; uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
    m.close(); uiToast(bl({ en: "Person added.", ja: "ユーザーを追加しました。" }), "ok"); paPeople(section);
  });
  idF.focus();
}

// ---- Service accounts (NHI): actors in agentic decisions; show risk. ----
async function paAccounts(section) {
  uiState(section, "loading");
  const current = freshRender(section);
  let accts, risk, policies;
  try {
    [accts, risk, policies] = await Promise.all([
      paList("/admin/non-human-identities", "identities", _PA_ENF),
      paGet("/admin/non-human-identities/risk", _PA_ENF).catch(() => ({ identities: [] })),
      paList("/admin/policies", "policies", _PA_ENF).catch(() => []),
    ]);
  } catch (e) { if (!current()) return; uiState(section, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => paAccounts(section) }); return; }
  const sevById = {}; (risk.identities || []).forEach((r) => (sevById[r.id] = r.severity));
  // Tool-boundary (ceiling) per agent — the policy pol-agent-<id> authored alongside the NHI (S3). Enforcement
  // reads this policy's AllowedToolIDs; showing it here makes the boundary visible where the agent lives.
  const boundaryById = {}; (policies || []).forEach((p) => { const t = agentBoundaryTools(p); if (t) boundaryById[t.nhi] = t.tools; });
  if (!current()) return;
  section.innerHTML = "";
  section.appendChild(el("div", { class: "ui-toolbar" }, [
    el("span", { class: "ui-view-desc", text: bl({ en: "The automated actors in agentic decisions — risk gates access, and out-of-boundary tool calls are denied.", ja: "エージェントとして判断する主体 ── リスクがアクセスを絞り、境界外のツール呼び出しは拒否されます。" }) }),
    el("span", { class: "ui-spacer" }), el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "+ Add account", ja: "+ アカウント追加" }), onClick: () => openAccountForm(section) }),
  ]));
  section.appendChild(paSearchTable(
    bl({ en: "Search accounts by name, owner, type…", ja: "名前・所有者・種別で検索…" }),
    accts,
    (a) => [a.name, a.id, a.owner_user_id, a.nhi_type].filter(Boolean).join(" "),
    (rows) => simpleTable(
      [bl({ en: "Account", ja: "アカウント" }), bl({ en: "Type", ja: "種別" }), bl({ en: "Owner", ja: "所有者" }), bl({ en: "Allowed tools", ja: "許可ツール" }), bl({ en: "Risk", ja: "リスク" }), bl({ en: "Status", ja: "状態" })],
      rows.map((a) => [
        el("strong", { text: a.name || a.id }), el("span", { text: a.nhi_type || "—" }), el("span", { text: a.owner_user_id || "—" }),
        boundaryById[a.id] ? el("code", { text: boundaryById[a.id].join(", ") }) : el("span", { class: "ui-view-desc", text: bl({ en: "any (no boundary)", ja: "制限なし" }) }),
        severityBadge(sevById[a.id]),
        uiBadge(a.status === "active" ? bl({ en: "Active", ja: "有効" }) : (a.status || "—"), a.status === "active" ? "ok" : "off"),
      ])
    ),
    bl({ en: "No service accounts yet.", ja: "サービスアカウントがありません。" })
  ));
}
// The agent tool-boundary is authored as a policy pol-agent-<nhi> keyed on actor_nhi_id, carrying AllowedToolIDs.
const AGENT_POLICY_PREFIX = "pol-agent-";
function agentBoundaryTools(p) {
  if (!p || !p.id || p.id.indexOf(AGENT_POLICY_PREFIX) !== 0) return null;
  const nhi = (p.conditions && p.conditions.actor_nhi_id) || p.id.slice(AGENT_POLICY_PREFIX.length);
  const tools = p.allowed_tool_ids || [];
  return { nhi, tools };
}
function severityBadge(sev) {
  sev = (sev || "none").toLowerCase();
  const kind = (sev === "high" || sev === "critical") ? "danger" : sev === "medium" ? "warn" : "off";
  const label = { none: bl({ en: "None", ja: "なし" }), low: bl({ en: "Low", ja: "低" }), medium: bl({ en: "Medium", ja: "中" }), high: bl({ en: "High", ja: "高" }), critical: bl({ en: "Critical", ja: "重大" }) }[sev] || sev;
  return uiBadge(label, kind);
}
function openAccountForm(section) {
  const idF = uiField({ name: "id", label: bl({ en: "ID", ja: "ID" }), required: true, placeholder: "nhi-1" });
  const nameF = uiField({ name: "name", label: bl({ en: "Name", ja: "名前" }), required: true, placeholder: "ci-bot" });
  const typeF = uiField({ name: "type", label: bl({ en: "Type", ja: "種別" }), type: "select", value: "service_account", options: [{ value: "service_account", label: bl({ en: "Service account", ja: "サービスアカウント" }) }, { value: "ai_agent", label: bl({ en: "AI agent", ja: "AI エージェント" }) }, { value: "workload", label: bl({ en: "Workload", ja: "ワークロード" }) }] });
  const ownerF = uiField({ name: "owner", label: bl({ en: "Owner (person ID)", ja: "所有者(ユーザー ID)" }), required: true, placeholder: "u1", hint: bl({ en: "Every automated account is owned by a person — accountability for its actions.", ja: "自動アカウントは必ず人が所有 ── 行動の説明責任。" }) });
  const toolsF = uiField({ name: "tools", label: bl({ en: "Allowed tools (boundary)", ja: "許可ツール(境界)" }), placeholder: "read_repo, open_pr", hint: bl({ en: "The tools this agent may ever call. Any tool outside this list is denied before it runs (leave empty for no boundary).", ja: "このエージェントが呼べるツールの上限。ここに無いツールは実行前に拒否(空なら境界なし)。" }) });
  const statusF = uiField({ name: "status", label: bl({ en: "Status", ja: "状態" }), type: "select", value: "active", options: [{ value: "active", label: bl({ en: "Active", ja: "有効" }) }, { value: "disabled", label: bl({ en: "Disabled", ja: "無効" }) }] });
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Add account", ja: "アカウント追加" }) });
  const m = uiModal({ title: bl({ en: "Add a service account", ja: "サービスアカウントを追加" }), body: [idF.el, nameF.el, typeF.el, ownerF.el, toolsF.el, statusF.el], footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit] });
  submit.addEventListener("click", async () => {
    if (!idF.validate() || !nameF.validate() || !ownerF.validate()) return; submit.disabled = true;
    const r = await paWriteEnforcement("POST", "/admin/non-human-identities", { id: idF.get(), name: nameF.get(), nhi_type: typeF.get(), owner_user_id: ownerF.get(), status: statusF.get() });
    if (!r.ok) { submit.disabled = false; uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
    // Author the agent's tool boundary as a policy (S3): pol-agent-<id> keyed on actor_nhi_id, allow with an
    // AllowedToolIDs allowlist. The evaluator denies any tool outside it before execution.
    const tools = toolsF.get().split(",").map((s) => s.trim()).filter(Boolean);
    if (tools.length) {
      const pr = await paWriteEnforcement("POST", "/admin/policies", { id: AGENT_POLICY_PREFIX + idF.get(), name: "Agent tool boundary: " + nameF.get(), priority: 50, conditions: { actor_nhi_id: idF.get() }, action: { decision: "allow" }, allowed_tool_ids: tools, status: "active" });
      if (!pr.ok) { submit.disabled = false; uiToast(bl({ en: "Account saved but boundary failed: ", ja: "アカウントは保存、境界は失敗: " }) + ((pr.body && (pr.body.error || pr.body.message)) || ("HTTP " + pr.status)), "err"); return; }
    }
    m.close(); uiToast(bl({ en: "Account added.", ja: "アカウントを追加しました。" }), "ok"); paAccounts(section);
  });
  idF.focus();
}

// ---- Delegations: NHI acts on behalf of a person; the decision checks validity/scope/expiry. ----
async function paDelegations(section) {
  uiState(section, "loading");
  const current = freshRender(section);
  let grants;
  try { grants = await paList("/admin/delegated-grants", "grants", _PA_ENF); }
  catch (e) { if (!current()) return; uiState(section, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => paDelegations(section) }); return; }
  if (!current()) return;
  section.innerHTML = "";
  section.appendChild(el("div", { class: "ui-toolbar" }, [el("span", { class: "ui-view-desc", text: bl({ en: "Lets a service account act on behalf of a person; the decision checks the grant is valid, in scope, and unexpired.", ja: "サービスアカウントが人の代理で動作することを許可。判定では、その許可が有効で・範囲内で・失効していないかを確認します。" }) }), el("span", { class: "ui-spacer" }), el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "+ Add delegation", ja: "+ 委譲を追加" }), onClick: () => openDelegationForm(section) })]));
  const scopeText = (g) => {
    const parts = [];
    if (g.tool_ids && g.tool_ids.length) parts.push((g.tool_ids.length) + bl({ en: " tool(s)", ja: " ツール" }));
    if (g.scopes && g.scopes.length) parts.push((g.scopes.length) + bl({ en: " scope(s)", ja: " スコープ" }));
    if (g.application_id) parts.push("app:" + g.application_id);
    return parts.length ? parts.join(", ") : bl({ en: "any", ja: "制限なし" });
  };
  const delRow = (g) => el("tr", {}, [
    el("td", { text: g.actor_nhi_id || "—" }),
    el("td", { text: g.subject_user_id || "—" }),
    el("td", {}, el("span", { class: "ui-view-desc", text: scopeText(g) })),
    el("td", {}, el("span", { class: "ui-view-desc", text: g.expires_at ? window.dsseFormatTime(g.expires_at) : "—" })),
    el("td", {}, uiBadge(g.status === "active" ? bl({ en: "Active", ja: "有効" }) : (g.status || "—"), g.status === "active" ? "ok" : "off")),
    el("td", { class: "ui-row-actions" }, g.status === "active" ? el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Revoke", ja: "失効" }), onClick: async () => {
      const ok = await uiConfirm({ title: bl({ en: "Revoke this delegation?", ja: "この委譲を失効?" }), confirmLabel: bl({ en: "Revoke", ja: "失効" }), danger: true });
      if (!ok) return; const r = await paWriteEnforcement("POST", "/admin/delegated-grants/" + encodeURIComponent(g.id) + "/revoke", {});
      if (!r.ok) { uiToast("HTTP " + r.status, "err"); return; } uiToast(bl({ en: "Revoked.", ja: "失効しました。" }), "ok"); paDelegations(section);
    } }) : el("span", { class: "ui-view-desc", text: "—" })),
  ]);
  section.appendChild(paSearchTable(
    bl({ en: "Search delegations by account or person…", ja: "アカウント・代理対象で検索…" }),
    grants,
    (g) => [g.actor_nhi_id, g.subject_user_id, g.application_id].filter(Boolean).join(" "),
    (gs) => el("table", { class: "ui-table" }, [el("thead", {}, el("tr", {}, [bl({ en: "Account", ja: "アカウント" }), bl({ en: "Acts as", ja: "代理対象" }), bl({ en: "Scope", ja: "スコープ" }), bl({ en: "Expires", ja: "失効" }), bl({ en: "Status", ja: "状態" }), bl({ en: "Actions", ja: "操作" })].map((x) => el("th", { text: x })))), el("tbody", {}, gs.map(delRow))]),
    bl({ en: "No delegations yet.", ja: "委譲がありません。" })
  ));
}
function openDelegationForm(section) {
  const idF = uiField({ name: "id", label: bl({ en: "ID", ja: "ID" }), required: true, placeholder: "grant-1" });
  const nhiF = uiField({ name: "nhi", label: bl({ en: "Service account", ja: "サービスアカウント" }), required: true, placeholder: "nhi-1" });
  const subjF = uiField({ name: "subj", label: bl({ en: "Acts as (person ID)", ja: "代理対象(ユーザー ID)" }), required: true, placeholder: "u1" });
  const toolsF = uiField({ name: "tools", label: bl({ en: "Tool scope", ja: "ツールスコープ" }), placeholder: "read_repo, open_pr", hint: bl({ en: "The tools this delegation permits (within the agent's boundary). Leave empty for the agent's full boundary.", ja: "この委譲が許すツール(エージェント境界内)。空ならエージェント境界の全て。" }) });
  const expF = uiField({ name: "exp", label: bl({ en: "Expires (optional)", ja: "失効(任意)" }), type: "datetime-local", hint: bl({ en: "After this the delegation is denied. Leave empty for no expiry.", ja: "これ以降この委譲は拒否。空なら無期限。" }) });
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Add delegation", ja: "委譲を追加" }) });
  const m = uiModal({ title: bl({ en: "Add a delegation", ja: "委譲を追加" }), body: [idF.el, nhiF.el, subjF.el, toolsF.el, expF.el], footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit] });
  submit.addEventListener("click", async () => {
    if (!idF.validate() || !nhiF.validate() || !subjF.validate()) return; submit.disabled = true;
    const tools = toolsF.get().split(",").map((s) => s.trim()).filter(Boolean);
    const body = { id: idF.get(), actor_nhi_id: nhiF.get(), subject_user_id: subjF.get(), tool_ids: tools, status: "active" };
    if (expF.get()) body.expires_at = new Date(expF.get()).toISOString();
    const r = await paWriteEnforcement("POST", "/admin/delegated-grants", body);
    if (!r.ok) { submit.disabled = false; uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
    m.close(); uiToast(bl({ en: "Delegation added.", ja: "委譲を追加しました。" }), "ok"); paDelegations(section);
  });
  idF.focus();
}

// ---- Activity: tool calls the agentic boundary evaluated + step-up approvals. ----
async function paActivity(section) {
  uiState(section, "loading");
  const current = freshRender(section);
  let events, approvals;
  try { [events, approvals] = await Promise.all([paList("/admin/tool-call-events", "events", _PA_ENF).catch(() => []), paList("/admin/human-approval-events", "approvals", _PA_ENF).catch(() => [])]); }
  catch (e) { if (!current()) return; uiState(section, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => paActivity(section) }); return; }
  if (!current()) return;
  section.innerHTML = "";
  section.appendChild(el("p", { class: "ui-view-desc", text: bl({ en: "Tool calls the agentic boundary evaluated, and step-up approvals — the audit trail behind the decisions above.", ja: "AIエージェントの境界が評価したツール呼び出しと、ステップアップ承認 ── 上の判定の監査証跡。" }) }));
  section.appendChild(el("h3", { class: "ui-field-label", text: bl({ en: "Recent tool calls", ja: "最近のツール呼び出し" }) }));
  if (!events.length) section.appendChild(emptyBox(bl({ en: "No tool activity.", ja: "ツール活動なし。" })));
  else section.appendChild(simpleTable([bl({ en: "When", ja: "日時" }), bl({ en: "Account", ja: "アカウント" }), bl({ en: "Tool", ja: "ツール" }), bl({ en: "Result", ja: "結果" })], events.slice(0, 100).map((e2) => [
    el("span", { class: "ui-view-desc", text: (e2.created_at || e2.timestamp) ? window.dsseFormatTime(e2.created_at || e2.timestamp) : "—" }), el("span", { text: e2.actor_nhi_id || e2.actor || "—" }), el("code", { text: e2.tool_id || e2.tool || "—" }), uiBadge(e2.decision || e2.result || "—", /allow|ok|success/i.test(e2.decision || e2.result || "") ? "ok" : "off"),
  ])));
  section.appendChild(el("h3", { class: "ui-field-label", style: "margin-top:20px", text: bl({ en: "Recent approvals", ja: "最近の承認" }) }));
  if (!approvals.length) section.appendChild(emptyBox(bl({ en: "No approvals.", ja: "承認なし。" })));
  else section.appendChild(simpleTable([bl({ en: "When", ja: "日時" }), bl({ en: "Who", ja: "対象" }), bl({ en: "Decision", ja: "判定" })], approvals.slice(0, 100).map((a) => [
    el("span", { class: "ui-view-desc", text: a.created_at ? window.dsseFormatTime(a.created_at) : "—" }), el("span", { text: a.subject_user_id || a.subject || "—" }), uiBadge(a.decision || "—", /approve|allow/i.test(a.decision || "") ? "ok" : "off"),
  ])));
}

// paRemoveBtn — a "Remove" action that soft-removes a record (the model has no hard delete; removal is a status
// change) after a confirm. doAction returns the apiFetch promise; onDone re-renders.
function paRemoveBtn(confirmTitle, bodyMsg, doAction, onDone) {
  return el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Remove", ja: "除去" }), onClick: async () => {
    const ok = await uiConfirm({ title: confirmTitle, body: bodyMsg, confirmLabel: bl({ en: "Remove", ja: "除去" }), danger: true });
    if (!ok) return;
    const r = await doAction();
    if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
    uiToast(bl({ en: "Removed.", ja: "除去しました。" }), "ok"); onDone();
  } });
}

// searchTable — a search box over a list that filters client-side on a per-item haystack, then re-renders via
// render(filteredItems). No search box when the list is empty (just the empty message).
function paSearchTable(placeholder, items, hay, render, emptyMsg) {
  if (!items.length) return emptyBox(emptyMsg);
  const wrap = el("div", {});
  const host = el("div", {});
  const search = el("input", { class: "ui-input ui-search", type: "search", placeholder });
  const draw = (q) => {
    q = (q || "").trim().toLowerCase();
    const rows = q ? items.filter((it) => hay(it).toLowerCase().includes(q)) : items;
    host.innerHTML = "";
    host.appendChild(rows.length ? render(rows) : emptyBox(bl({ en: "No matches.", ja: "一致なし。" })));
  };
  search.addEventListener("input", () => draw(search.value));
  wrap.appendChild(search); wrap.appendChild(host); draw("");
  return wrap;
}

// simpleTable(headers, rowsOfCells) — small helper for read tables (cells are nodes).
function simpleTable(headers, rows) {
  return el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, headers.map((h) => el("th", { text: h })))),
    el("tbody", {}, rows.map((cells) => el("tr", {}, cells.map((c) => el("td", {}, c))))),
  ]);
}
