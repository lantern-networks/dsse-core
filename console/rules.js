"use strict";

// ---------------------------------------------------------------------------
// rules.js — "Internal Access" (East-West) and "Internet Access / Egress" views on the shared ui.js component
// layer (toasts, modals, typed fields, data tables, empty/loading/error states — see
// docs/console_ux_design_direction.md). Replaces the legacy_ui.js card paradigm (badge / sectionNote /
// mkInput / mkSelect / fieldLabel / loadAssets are no longer used here).
//
// A rule reads `source → destination : service ⇒ action`. Internal Access (the centerpiece) is edited per
// direction (Outbound / Inbound) because the threat model and enforcement differ — inbound enforces on
// Windows WFP only, so the Inbound tab carries a standing notice and the edge rejects macOS-only receivers.
// The action is two orthogonal axes: access (allow/authenticate/deny) × inspection (inspect/bypass).
//
// app.js dispatches here for the GROUPS entries custom:'eastwest' (renderEastWestView) and custom:'egress'
// (renderEgressView). Those two names + dispatch keys are the stable public contract and must not change.
// All API calls use the default (edge) plane.
// ---------------------------------------------------------------------------

let ewDirection = "outbound"; // Internal Access rule sub-tab: "outbound" | "inbound"
let _ewTop = "rules"; // Internal Access top tab: "rules" | "approvals" | "verifications" (runtime state folded in)
const SUBJECT_ANY = "*"; // explicit wildcard token (matches the backend's policyrule.SubjectAny)

// ---- views -----------------------------------------------------------------

function renderEastWestView(content) {
  content.innerHTML = "";
  const section = el("div", {});
  const head = [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "Connector Access", ja: "コネクタ経由アクセス" }) }),
      el("p", { class: "ui-view-desc", text: bl({
        en: "Which devices may reach which internal systems, connection by connection. Observations lists the traffic already seen inside your network, ready to turn into rules. (Traffic that starts OUTSIDE and comes in is on the Incoming Connections page.)",
        ja: "どの端末が、社内のどのシステムに到達してよいか。接続ごとに決めます。「観測」には社内で実際に見えた通信が並び、そのままルールにできます。(外から入ってくる通信は「受信接続」のページです。)",
      }) }),
    ]),
  ];
  // "+ Add rule" belongs to the Rules tab only. Connector Access is OUTBOUND (client → server) only — inbound
  // (server → client) is authored + enforced on the separate Incoming Connections page (Windows WFP).
  if (_ewTop === "rules") {
    head.push(el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "+ Add rule", ja: "+ ルールを追加" }),
      onClick: () => openRuleEditor("east_west", "outbound", () => renderRuleList(section, "east_west", "outbound")) }));
  }
  content.appendChild(el("div", { class: "ui-view-head" }, head));

  // Top tabs: RULES (authoring) + OBSERVATIONS (the learning inventory). The OBSERVE / ENFORCING posture is the
  // always-visible banner (app.js). The old Approvals / Verifications runtime tabs were removed — standing grants
  // and in-progress step-ups are transient runtime state, not something the operator authors here.
  content.appendChild(uiTabs([
    { id: "rules", label: bl({ en: "Rules", ja: "ルール" }) },
    { id: "observations", label: bl({ en: "Observations", ja: "観測" }) },
  ], _ewTop, (id) => { _ewTop = id; renderEastWestView(content); }));

  content.appendChild(section);
  if (_ewTop === "observations") ewObservations(section);
  else renderRuleList(section, "east_west", "outbound");
}

function renderEgressView(content) {
  content.innerHTML = "";
  const section = el("div", {});
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "Internet Access", ja: "インターネットアクセス" }) }),
      el("p", { class: "ui-view-desc", text: bl({
        // ★ WRITTEN FOR THE PERSON WHO HAS TO USE IT (2026-08-17, read as a customer administrator). It said
        // "north-south access", "there is no observe mode here" and "source → destination : service" — three
        // pieces of our own vocabulary in two sentences, on the screen a customer reaches for first.
        en: "Manage access and inspection rules for internet destinations. Actual inspection also depends on Inspection Settings, device configuration and other exclusions.",
        ja: "インターネットの宛先へのアクセスと検査ルールを管理します。実際の検査範囲は傍受設定・端末設定・他の除外にも従います。",
      }) }),
    ]),
    el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "+ Add rule", ja: "+ ルールを追加" }),
      onClick: () => openRuleEditor("egress", "", () => renderRuleList(section, "egress", "")) }),
  ]));
  content.appendChild(section);
  renderRuleList(section, "egress", "");
}

// ---- shared list rendering -------------------------------------------------

// loadList fetches an admin endpoint that returns a bare JSON array (the asset/rule catalogs).
async function loadList(path) {
  const r = await apiFetch("GET", path);
  if (!r.ok) throw new Error("HTTP " + r.status + (typeof r.body === "string" && r.body ? " " + r.body : ""));
  if (!Array.isArray(r.body)) throw new Error("Invalid catalog response");
  return r.body;
}

// catalogIndex loads the asset catalog once and returns lookups for display + editor pickers.
async function catalogIndex() {
  const [endpoints, groups, services] = await Promise.all([
    loadList("/admin/assets/endpoints"),
    loadList("/admin/assets/groups"),
    loadList("/admin/assets/services"),
  ]);
  const aliasByID = {};
  endpoints.forEach((e) => (aliasByID[e.id] = e.alias));
  groups.forEach((g) => (aliasByID[g.id] = g.alias));
  services.forEach((s) => (aliasByID[s.id] = s.alias));
  return { endpoints, groups, services, aliasByID };
}

async function renderRuleList(section, plane, direction) {
  uiState(section, "loading");
  const current = freshRender(section);

  let idx;
  try { idx = await catalogIndex(); }
  catch (e) { if (!current()) return; uiState(section, "error", String(e.message || e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderRuleList(section, plane, direction) }); return; }

  // EGRESS: render the unified effective-egress list — authored rules + built-in default + the bypass scattered
  // across the inspection posture (known-bypass floor, legacy Optimize) + approved cert-pin bypass — all in one
  // place, since an operator expects the Internet Access view to reflect every egress decision, not just authored
  // rules.
  if (plane === "egress") {
    let resp;
    try { resp = await apiFetch("GET", "/admin/egress-effective-rules"); }
    catch (e) { if (!current()) return; uiState(section, "error", String(e.message || e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderRuleList(section, plane, direction) }); return; }
    if (!resp || !resp.ok || !resp.body || !Array.isArray(resp.body.rules)) {
      if (!current()) return;
      uiState(section, "error", bl({ en: "Could not load internet-access rules.", ja: "インターネットアクセスのルールを読み込めません。" }), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderRuleList(section, plane, direction) });
      return;
    }
    const entries = resp.body.rules;
    const builtinDefaults = entries.filter((e) => e.kind === "builtin_default").map((e) => ({ policy_id: e.policy_id, decision: e.access, status: e.status }));
    if (!current()) return;
    section.innerHTML = "";
    if (!entries.length) { section.appendChild(emptyBox(bl({ en: "No rules yet. Add one with “+ Add rule”.", ja: "まだルールがありません。「+ ルールを追加」から作成してください。" }))); return; }
    // Collapse the many per-host cert-pin bypass rules into a single summary row (Details opens the full list).
    // Cert-pin bypasses arrive as ordinary authored egress rules whose id starts with "certpin-rule-"; every
    // other authored rule (e.g. a development bypass rule) keeps its own row + Edit/Disable/Delete.
    const rows = [];
    const certPins = [];
    entries.forEach((entry) => {
      if (entry.kind === "authored" && entry.rule) {
        if (isCertPinSummaryRule(entry.rule) && !entry.destination_unresolved && !entry.service_unresolved && !entry.inspection_source_warning) { certPins.push(entry.rule); return; }
        rows.push(authoredRow(Object.assign({}, entry.rule, { destination_unresolved: entry.destination_unresolved, service_unresolved: entry.service_unresolved, inspection_source_warning: entry.inspection_source_warning }), idx, section, plane, direction));
        return;
      }
      if (entry.kind === "builtin_default") { rows.push(builtinRow({ policy_id: entry.policy_id, name: entry.name, priority: entry.priority, decision: entry.access, status: entry.status, service_text: entry.service_text, inspection: entry.inspection }, section, plane, direction, builtinDefaults)); return; }
      rows.push(derivedRow(entry, section, plane, direction));
    });
    if (certPins.length) rows.push(certPinSummaryRow(certPins, idx, section, plane, direction));
    section.appendChild(ruleTable(rows));
    return;
  }

  // INTERNAL ACCESS: authored rules only (no built-in default / bypass surfaces on the lateral plane).
  let rules;
  try { rules = await loadList("/admin/rules?plane=" + encodeURIComponent(plane)); }
  catch (e) { if (!current()) return; uiState(section, "error", String(e.message || e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderRuleList(section, plane, direction) }); return; }
  rules = rules.filter((r) => (r.direction || "outbound") === direction);

  if (!current()) return;
  section.innerHTML = "";

  if (!rules.length) { section.appendChild(emptyBox(bl({ en: "No rules yet. Add one with “+ Add rule”.", ja: "まだルールがありません。「+ ルールを追加」から作成してください。" }))); return; }
  section.appendChild(ruleTable(rules.map((r) => authoredRow(r, idx, section, plane, direction))));
}

function ruleTable(rows) {
  return el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [
      bl({ en: "Rule", ja: "ルール" }),
      bl({ en: "Flow", ja: "フロー" }),
      bl({ en: "Access", ja: "アクセス" }),
      bl({ en: "Contents", ja: "中身" }),
      bl({ en: "Status", ja: "状態" }),
      bl({ en: "Actions", ja: "操作" }),
      // ★ The short headings wrapped mid-word — "アクセス" broke across two lines as "アクセ / ス" — because the
      // flow column takes whatever width it likes. A heading a reader has to reassemble is a heading that
      // costs a glance.
    ].map((x) => el("th", { text: x, style: "white-space:nowrap" })))),
    el("tbody", {}, rows),
  ]);
}

// ---- badges / vocabulary ---------------------------------------------------

const ACCESS_LABEL = {
  allow: { en: "Allow", ja: "許可" },
  authenticate: { en: "Verify", ja: "本人確認" },
  deny: { en: "Deny", ja: "拒否" },
};

function accessBadge(access) {
  const kind = access === "deny" ? "danger" : access === "authenticate" ? "warn" : "ok";
  return uiBadge(bl(ACCESS_LABEL[access] || { en: access, ja: access }), kind);
}

function inspectionBadge(inspection) {
  return inspection === "bypass"
    ? uiBadge(bl({ en: "Not inspected", ja: "検査しない" }), "warn")
    : uiBadge(bl({ en: "Inspected", ja: "検査する" }), "off");
}

function statusBadge(active) {
  return uiBadge(active ? bl({ en: "Active", ja: "有効" }) : bl({ en: "Disabled", ja: "無効" }), active ? "ok" : "off");
}

// ★★ "ACTIVE" AND ENFORCING NOTHING (2026-08-17, measured as a customer administrator). An egress rule whose
// destination resolves to no endpoint compiles to a match-nothing sentinel — deliberately, so it stays visible
// rather than vanishing — and the compiler logs "a DENY here is NOT enforcing". Only the container log said
// so: this list showed the rule as 有効 / 拒否 against the hostname it names, while asking the policy checker
// about that exact hostname answered ALLOW. An administrator would believe the site was blocked.
//
// The route now answers the compiler's own question per rule, and the status column says both halves.
function statusCellFor(rule, active) {
  const cell = el("td", {}, statusBadge(active));
  if (rule && rule.destination_unresolved) {
    cell.appendChild(document.createTextNode(" "));
    cell.appendChild(uiBadge(bl({ en: "matches nothing", ja: "一致なし" }), "danger"));
    cell.appendChild(el("div", { class: "ui-view-desc", text: bl({
      en: "This destination is not in the endpoint catalog, so the rule enforces nothing.",
      ja: "この宛先はエンドポイントに登録されていないため、このルールは何も強制していません。" }) }));
  }
  if (rule && rule.service_unresolved) {
    cell.appendChild(uiBadge(bl({en:"service unavailable",ja:"サービス未解決"}), "danger"));
    cell.appendChild(el("div", {class:"ui-view-desc", text:bl({en:"This service is unavailable or invalid. The rule matches no traffic, including deny and authentication rules.",ja:"サービスが存在しないか定義が不正です。このルールは通信に一致せず、拒否・認証要求も適用されません。"})}));
  }
  return cell;
}

function names(ids, idx) {
  return (ids || []).map((id) => {
    if (id === SUBJECT_ANY) return bl({ en: "Any", ja: "すべて" });
    if (typeof id === "string" && id.indexOf(IDGROUP_PREFIX) === 0) return id.slice(IDGROUP_PREFIX.length); // IdP person/group by name
    if (typeof id === "string" && id.indexOf(AGENT_PREFIX) === 0) return "🤖 " + id.slice(AGENT_PREFIX.length); // agent / service account
    return idx.aliasByID[id] || id;
  }).join(", ");
}

// ruleAllowsAgentless reports whether a rule's "who" is an IdP identity group AND it grants (allow/authenticate)
// — i.e. it lets an unmanaged browser reach the destination after an IdP login (clientless). A deny rule, or a
// device-source rule, does not. (The backend still refuses agentless reach to a high-sensitivity destination
// regardless — a hard invariant — so the chip means "eligible", not "unconditionally reachable".)
function ruleAllowsAgentless(r) {
  const access = (r.action && r.action.access) || "";
  if (access === "deny") return false;
  return (r.source || []).some((s) => typeof s === "string" && s.indexOf(IDGROUP_PREFIX) === 0);
}

function browserChip() {
  return el("span", { class: "rule-browser-chip", title: bl({
    en: "An unmanaged browser can reach this after an IdP login (published, non-high-sensitivity apps only).",
    ja: "IdP ログイン後、未管理ブラウザが到達可能(公開済みで、高機微でないアプリのみ)。",
  }), text: "🌐 " + bl({ en: "browser", ja: "ブラウザ" }) });
}

function ruleExpr(r, idx) {
  const svc = " : " + (r.service_id ? (idx.aliasByID[r.service_id] || r.service_id) : bl({ en: "Any", ja: "すべて" }));
  return names(r.source, idx) + " → " + names(r.destination, idx) + svc;
}

function httpErr(resp) {
  return (resp.body && (resp.body.error || resp.body.message)) || ("HTTP " + resp.status + (typeof resp.body === "string" && resp.body ? ": " + resp.body : ""));
}

// ---- rows ------------------------------------------------------------------

// authoredRow renders an operator-authored rule. The human-readable name is primary; the stable rule id +
// priority are shown only as a small <code> (they used to be the heading). Edit re-opens the rule in the editor
// (keeping its id); Toggle keeps a rule but makes it inert; Delete removes it.
function authoredRow(r, idx, section, plane, direction) {
  const active = r.status !== "disabled";

  const accessCell = el("td", {}, [accessBadge(r.action.access)]);
  if (r.action.require_workload_attestation) {
    accessCell.appendChild(document.createTextNode(" "));
    accessCell.appendChild(uiBadge(bl({ en: "Workload-attested", ja: "ワークロード認証" }), "off"));
  }
  // Warn-stage (learning-lifecycle dry-run): the rule ALLOWS + notifies instead of biting yet.
  if (r.stage === "warn") {
    accessCell.appendChild(document.createTextNode(" "));
    accessCell.appendChild(uiBadge(bl({ en: "Warn (dry-run)", ja: "警告のみ" }), "warn"));
  }

  const edit = el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Edit", ja: "編集" }),
    onClick: () => openRuleEditor(plane, direction, () => renderRuleList(section, plane, direction), r) });

  let pending = false;
  const run = async operation => {
    if (pending || section.isConnected === false) return;
    pending = true;
    const controls = [edit,toggle,del]; controls.forEach(e => e.disabled = true);
    try {
      if (await ruleEditorTenant() !== r.tenant_id) throw new Error(ruleUnknownOutcome());
      if (section.isConnected === false) return;
      if (await operation() === true) await renderRuleList(section,plane,direction);
    } catch(e) { uiToast((e.message || String(e))+" "+ruleUnknownOutcome(),"err"); }
    finally { pending = false; controls.forEach(e => e.disabled = false); }
  };
  const toggle = el("button", { class:"ui-btn ui-btn-sm", text:active ? bl({en:"Disable",ja:"無効化"}) : bl({en:"Enable",ja:"有効化"}), onClick:()=>run(async()=>{
    const body = Object.assign({},r,{status:active ? "disabled" : "active"});
    const resp = await apiFetch("POST","/admin/rules",body);
    validateRuleSave(resp,body,r.tenant_id);
    uiToast(bl({en:"Rule status saved.",ja:"ルールの状態を保存しました。"}),"ok");
    return true;
  })});
  const del = el("button", {class:"ui-btn ui-btn-sm ui-btn-danger",text:bl({en:"Delete",ja:"削除"}),onClick:()=>run(async()=>{
    if (!await uiConfirm({title:bl({en:"Delete this rule?",ja:"このルールを削除しますか?"}),body:r.name || r.id,confirmLabel:bl({en:"Delete",ja:"削除"}),danger:true})) return false;
    if (section.isConnected === false || await ruleEditorTenant() !== r.tenant_id) throw new Error(ruleUnknownOutcome());
    const resp = await apiFetch("DELETE","/admin/rules/"+encodeURIComponent(r.id));
    if (!resp?.ok) throw new Error(httpErr(resp));
    if (resp.status!==200 || resp.body?.status!=="deleted" || resp.body?.id!==r.id) throw new Error(ruleUnknownOutcome());
    uiToast(bl({en:"Rule deleted.",ja:"ルールを削除しました。"}),"ok");return true;
  })});

  return el("tr", {}, [
    el("td", {}, [
      el("strong", { text: r.name || bl({ en: "(unnamed rule)", ja: "(名称なしルール)" }) }),
      el("div", { class: "ui-view-desc" }, el("code", { text: "#" + r.priority + " · " + r.id })),
    ]),
    el("td", {}, ruleAllowsAgentless(r)
      ? [el("span", { class: "rule-expr", text: ruleExpr(r, idx) }), document.createTextNode(" "), browserChip()]
      : [el("span", { class: "rule-expr", text: ruleExpr(r, idx) })]),
    accessCell,
    el("td", {}, [inspectionBadge(r.action.inspection), r.inspection_source_warning ? el("div", {class:"ui-view-desc", text:inspectionSourceWarningText(r.inspection_source_warning)}) : null]),
    statusCellFor(r, active),
    el("td", { class: "ui-row-actions" }, [edit, document.createTextNode(" "), toggle, document.createTextNode(" "), del]),
  ]);
}

function inspectionSourceWarningText(reason) {
  if (reason === "identity_context_unavailable") return bl({en:"Only device sources can select TLS inspection. Person, identity-group and agent sources cannot decide it here; access rules still apply.",ja:"TLS検査の範囲は端末の送信元で指定します。人・IDグループ・エージェントの指定はここでは検査範囲に反映されません。アクセス条件は引き続き適用されます。"});
  if (reason === "no_resolved_device") return bl({en:"No source device resolves for inspection. Check the selected device or group.",ja:"検査対象の送信元端末が見つかりません。選択した端末・グループを確認してください。"});
  return bl({en:"Check the inspection source before relying on this rule.",ja:"このルールの検査範囲を確認してください。"});
}

// hasImplJargon flags a backend-supplied name that leaks internal codenames / implementation language (a programme codename,
// "decrypt-all", "LOWEST precedence", etc.) so it is never shown verbatim as a user-facing heading.
function hasImplJargon(name) {
  if (!name) return true; // no human name → fall back to the plain heading
  return /\bTrack\s+[A-Z]\b/.test(name) || /decrypt-all|lowest precedence|default fallback|catch-all/i.test(name);
}

// builtinHeading returns a plain, user-facing heading for a built-in default rule. The catch-all internet
// default (and any built-in whose name carries implementation jargon) gets a fixed friendly label instead of
// the raw backend name; the raw id stays as the small <code> handle below.
function builtinHeading(p) {
  if (hasImplJargon(p.name)) return bl({ en: "Default: all internet access", ja: "既定: すべてのインターネットアクセス" });
  return p.name;
}

// builtinRow renders a built-in policy (shipped via -policy / the bundle) as a rule row in the Internet Access
// view, so the default that decides every flow is visible and toggleable — not hidden behind "All policies".
// No Delete (its source of truth is the config) and no inline edit. The catch-all default allow is the
// precedence floor; disabling the last active allow makes egress default-deny, so it confirms with a lockout
// warning. Toggling goes through POST /admin/policies/{id}/status (durable override).
function builtinRow(p, section, plane, direction, builtIns) {
  const active = p.status !== "disabled";
  const access = p.decision === "deny" ? "deny" : p.decision === "authenticate" ? "authenticate" : "allow";

  const toggle = el("button", { class: "ui-btn ui-btn-sm", text: active ? bl({ en: "Disable", ja: "無効化" }) : bl({ en: "Enable", ja: "有効化" }),
    onClick: async () => {
      // Lockout guard: disabling the last active allow default leaves egress with no fallback allow → default-deny
      // for every flow no authored rule covers. Confirm before doing it.
      if (active && p.decision === "allow") {
        const otherAllow = builtIns.some((q) => q.policy_id !== p.policy_id && q.decision === "allow" && q.status !== "disabled");
        if (!otherAllow) {
          const ok = await uiConfirm({
            title: bl({ en: "Disable the default internet allow?", ja: "既定のインターネット許可を無効化しますか?" }),
            body: bl({ en: "This is the catch-all every flow falls through to. With it off, any destination not matched by a specific Allow rule is denied (default-deny). You can re-enable it here at any time.", ja: "これは、どのルールにも一致しなかった通信が最後に行き着くルールです。off にすると、特定の許可ルールに一致しない宛先はすべて拒否されます(既定拒否)。ここからいつでも再有効化できます。" }),
            confirmLabel: bl({ en: "Disable", ja: "無効化" }), danger: true,
          });
          if (!ok) return;
        }
      }
      toggle.disabled = true;
      const resp = await apiFetch("POST", "/admin/policies/" + encodeURIComponent(p.policy_id) + "/status", { status: active ? "disabled" : "active" });
      if (!resp.ok) { toggle.disabled = false; uiToast(httpErr(resp), "err"); return; }
      uiToast(bl({ en: "Default updated.", ja: "既定を更新しました。" }), "ok");
      renderRuleList(section, plane, direction);
    } });

  const idDesc = el("div", { class: "ui-view-desc" }, [uiBadge(bl({ en: "Built-in (default)", ja: "組み込み(既定)" }), "off")]);
  // ★ NOT THE RAW ID (2026-08-17, read as a customer). This printed "#1000000 · pol_northwind_baseline" on the
  // screen a customer reaches for first. The number is the precedence, which does matter — a customer needs to
  // know this rule is the last one consulted — and the internal identifier is ours, not theirs. It stays
  // available where identifiers belong: the title attribute, for anyone who is debugging.
  if (p.policy_id) {
    idDesc.appendChild(document.createTextNode(" "));
    idDesc.appendChild(el("span", { class: "ui-view-desc", title: p.policy_id,
      text: bl({ en: "consulted last", ja: "最後に参照されます" }) }));
  }

  return el("tr", {}, [
    el("td", {}, [
      el("strong", { text: builtinHeading(p) }),
      idDesc,
      el("div", { class: "ui-view-desc", text: bl({ en: "The baseline used when no rule above matches. You can turn it on or off here.", ja: "上のどのルールにも一致しないときに使われる土台です。ここでオン/オフできます。" }) }),
    ]),
    el("td", {}, el("span", { class: "rule-expr", text: bl({ en: "Any → Any : ", ja: "すべて → すべて : " }) + (p.service_text || bl({ en: "Any", ja: "すべて" })) })),
    el("td", {}, accessBadge(access)),
    el("td", {}, inspectionBadge(p.inspection === "inspect" ? "inspect" : "bypass")),
    el("td", {}, statusBadge(active)),
    el("td", { class: "ui-row-actions" }, toggle),
  ]);
}

// derivedRow renders a bypass that lives on another surface — the known-bypass OS/cert floor, a legacy SaaS
// Optimize selection, or an approved cert-pin bypass — as a read-only Internet Access row so the view reflects
// EVERY egress decision in one place. The host/name is primary; the kind is a small badge. known_bypass entries
// toggle the whole OS/cert floor (all-or-nothing); cert-pin entries can be revoked (re-intercept the host);
// the rest are info-only (managed in their own view).
function derivedRow(entry, section, plane, direction) {
  const active = entry.status === "active";
  const kindLabel = {
    known_bypass: { en: "Not inspected (system)", ja: "検査しない(システム)" },
    optimize_bypass: { en: "Optimize bypass (legacy)", ja: "Optimize による検査除外(旧)" },
    cert_pin_bypass: { en: "Cert-pin bypass", ja: "ピンニングによる検査除外" },
  }[entry.kind];
  const kindText = kindLabel ? bl(kindLabel) : entry.kind;
  const title = entry.name || (entry.kind === "known_bypass"
    ? bl({ en: "Operating-system and certificate traffic", ja: "OS と証明書のための通信" })
    : kindText);

  const nameChildren = [
    el("strong", { text: title }),
    el("div", { class: "ui-view-desc" }, uiBadge(kindText, "off")),
  ];
  // ★ THE WORDING IS THE SCREEN'S (2026-08-17, read as a customer). The API's detail is English prose, and it
  // rendered untranslated in a Japanese console — the same defect the setup checklist had. The API text stays
  // as the fallback for a kind this screen does not know, so a row is never left blank.
  const KIND_DETAIL = {
    known_bypass: { en: "These hosts check their own certificate, so inspecting them stops the operating system working. On or off as one set.",
                    ja: "これらは自分の証明書を自分で確かめるため、検査すると OS が動かなくなります。まとめてオン/オフします。" },
    optimize_bypass: { en: "Left over from an older setting. It still lets this traffic through uninspected.",
                       ja: "以前の設定の名残です。この通信は今も検査せずに通ります。" },
    cert_pin_bypass: { en: "An application that refuses inspection, allowed through after being reviewed.",
                       ja: "検査を受け付けないアプリを、確認のうえ通しています。" },
  };
  const detailText = KIND_DETAIL[entry.kind] ? bl(KIND_DETAIL[entry.kind]) : entry.detail;
  if (detailText) {
    const d = detailText + (entry.patterns && entry.patterns.length ? "  ·  " + entry.patterns.slice(0, 6).join(", ") + (entry.patterns.length > 6 ? " …" : "") : "");
    nameChildren.push(el("div", { class: "ui-view-desc", text: d }));
  }

  let actions;
  if (entry.toggle_kind === "known_bypass_master") {
    const tog = el("button", { class: "ui-btn ui-btn-sm", text: active ? bl({ en: "Disable", ja: "無効化" }) : bl({ en: "Enable", ja: "有効化" }),
      title: bl({ en: "Toggles the whole known-bypass set (the entire OS/cert floor)", ja: "既知のバイパス群(OS・証明書インフラ全体)をまとめて切り替えます" }),
      onClick: async () => {
        const ok = await uiConfirm({
          title: active ? bl({ en: "Disable the entire OS / cert bypass set?", ja: "OS・証明書のための検査除外すべてを無効化しますか?" }) : bl({ en: "Enable the OS / cert bypass set?", ja: "OS・証明書のための検査除外を有効化しますか?" }),
          body: bl({ en: "These hosts pin their certificates (Apple push, OS updates, OCSP, …). Decrypting them breaks the OS. Change this only if you know what you're doing.", ja: "これらは自身の証明書を固定しています(Apple push・OS 更新・OCSP …)。復号すると OS が壊れます。理解した上でのみ変更してください。" }),
          confirmLabel: active ? bl({ en: "Disable", ja: "無効化" }) : bl({ en: "Enable", ja: "有効化" }), danger: active,
        });
        if (!ok) return;
        tog.disabled = true;
        const resp = await apiFetch("POST", "/admin/inspection-posture", { known_bypass_enabled: !active });
        if (!resp.ok) { tog.disabled = false; uiToast(httpErr(resp), "err"); return; }
        uiToast(bl({ en: "Updated.", ja: "更新しました。" }), "ok");
        renderRuleList(section, plane, direction);
      } });
    actions = tog;
  } else if (entry.toggle_kind === "cert_pin_revoke" && entry.candidate_id) {
    const rev = el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Revoke", ja: "失効" }),
      title: bl({ en: "Inspect this site again", ja: "このサイトをもう一度検査する" }),
      onClick: async () => {
        const ok = await uiConfirm({
          title: bl({ en: "Revoke this cert-pin bypass?", ja: "この ピンニングによる検査除外を失効しますか?" }),
          body: bl({ en: "This site will be inspected again. If it is built to refuse inspection, the connection may fail until you allow it through once more.", ja: "このサイトを再び検査します。検査を受け付けない作りだった場合、もう一度通すまで接続できなくなることがあります。" }),
          confirmLabel: bl({ en: "Revoke", ja: "失効" }), danger: true,
        });
        if (!ok) return;
        rev.disabled = true;
        const resp = await apiFetch("POST", "/admin/policy-candidates/" + encodeURIComponent(entry.candidate_id) + "/review", { decision: "suppressed", review_reason_code: "revoked_via_egress_view" });
        if (!resp.ok) { rev.disabled = false; uiToast(httpErr(resp), "err"); return; }
        uiToast(bl({ en: "Revoked.", ja: "失効しました。" }), "ok");
        renderRuleList(section, plane, direction);
      } });
    actions = rev;
  } else {
    actions = el("span", { class: "ui-view-desc", text: bl({ en: "Managed elsewhere", ja: "別画面で管理" }) });
  }

  return el("tr", {}, [
    el("td", {}, nameChildren),
    // ★ NOT A WALL OF OUR IDENTIFIERS (2026-08-17, read as a customer). The system-bypass row printed fifteen
    // catalogue ids in a monospace blob — apple_push, apple_software_update, apple_notarization_gatekeeper …
    // — which is the internal name of each group, not anything a customer reads. The count is the fact; the
    // names of the groups are already spelled out in the description underneath.
    el("td", {}, el("span", { class: "rule-expr", text: ruleFlowText(entry) })),
    el("td", {}, accessBadge(entry.access)),
    el("td", {}, inspectionBadge(entry.inspection)),
    el("td", {}, statusBadge(active)),
    el("td", { class: "ui-row-actions" }, actions),
  ]);
}

// Only the original unrestricted allow/bypass shape fits the compact presentation.
// Edited rules must retain their ordinary row and editor instead of hiding intent.
function isCertPinSummaryRule(rule) {
  return !!rule && typeof rule.id === "string" && rule.id.startsWith("certpin-rule-") &&
    rule.plane === "egress" && rule.action?.access === "allow" && rule.action?.inspection === "bypass" &&
    Object.keys(rule.action).every(key => key === "access" || key === "inspection") &&
    Array.isArray(rule.source) && rule.source.length === 1 && rule.source[0] === "*" &&
    Array.isArray(rule.destination) && rule.destination.length === 1 &&
    !rule.service_id && !rule.risk_at_least && !rule.allowed_tool_ids?.length;
}

// certPinSummaryRow collapses the per-host cert-pin bypass rules (authored egress rules whose id starts with
// "certpin-rule-") into a single row. The per-host list + controls live in the Details modal so the Internet
// Access view isn't flooded with one row per site. Access/Inspection are fixed (Allow + Bypass).
function certPinSummaryRow(rules, idx, section, plane, direction) {
  const n = rules.length;
  const allActive = rules.every((r) => r.status !== "disabled");
  const someActive = rules.some((r) => r.status !== "disabled");
  const statusCell = allActive ? statusBadge(true) : someActive ? uiBadge(bl({ en: "Mixed", ja: "混在" }), "warn") : statusBadge(false);

  const details = el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Details", ja: "詳細" }),
    onClick: () => openCertPinDetails(rules.slice(), idx, section, plane, direction) });

  return el("tr", {}, [
    el("td", {}, [
      el("strong", { text: bl({ en: "Cert-pin bypass", ja: "ピンニングによる検査除外" }) }),
      el("div", { class: "ui-view-desc" }, uiBadge(bl({ en: n + " sites", ja: n + " 件のサイト" }), "off")),
    ]),
    el("td", {}, el("span", { class: "rule-expr", text: bl({ en: n + " saved bypass rules", ja: "保存済みの検査除外ルール " + n + " 件" }) })),
    el("td", {}, accessBadge("allow")),
    el("td", {}, inspectionBadge("bypass")),
    el("td", {}, statusCell),
    el("td", { class: "ui-row-actions" }, details),
  ]);
}

// openCertPinDetails shows the per-host cert-pin bypass list in a modal table (Host / Status / Action). Each is
// an authored egress rule, so Re-intercept removes it (DELETE /admin/rules/{id} — the host goes back to being
// TLS-inspected) and Enable/Disable toggles it (POST /admin/rules). A success updates the in-modal list and the
// rule list behind it. `rules` is a local working copy of the cert-pin authored rules.
function openCertPinDetails(rules, idx, section, plane, direction) {
  const listHost = el("div", {});

  function rebuild() {
    listHost.innerHTML = "";
    if (!rules.length) { listHost.appendChild(emptyBox(bl({ en: "No cert-pin bypasses remain.", ja: "ピンニングによる検査除外はありません。" }))); return; }
    const rows = rules.map((r) => {
      const active = r.status !== "disabled";
      const host = names(r.destination, idx) || r.name || r.id;

      const rev = el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Re-intercept", ja: "再傍受" }),
        title: bl({ en: "Remove this bypass — the host is TLS-inspected again", ja: "この検査除外を削除 — ホストを再び TLS 傍受の対象に戻します" }),
        onClick: async () => {
          const ok = await uiConfirm({
            title: bl({ en: "Re-intercept this host?", ja: "このホストを再傍受しますか?" }),
            body: bl({ en: "This puts the site back under TLS inspection (the cert-pin bypass is deleted). If it really pins its certificate, the connection may break until you re-approve it.", ja: "このサイトを再び検査の対象に戻します。このサイトが検査を受け付けない作りだった場合、もう一度許可するまで接続できなくなることがあります。" }),
            confirmLabel: bl({ en: "Re-intercept", ja: "再傍受" }), danger: true,
          });
          if (!ok) return;
          rev.disabled = true;
          const resp = await apiFetch("DELETE", "/admin/rules/" + encodeURIComponent(r.id));
          if (!resp.ok) { rev.disabled = false; uiToast(httpErr(resp), "err"); return; }
          uiToast(bl({ en: "Re-intercepting.", ja: "再傍受します。" }), "ok");
          const i = rules.indexOf(r); if (i >= 0) rules.splice(i, 1);
          rebuild();
          renderRuleList(section, plane, direction);
        } });

      const tog = el("button", { class: "ui-btn ui-btn-sm", text: active ? bl({ en: "Disable", ja: "無効化" }) : bl({ en: "Enable", ja: "有効化" }),
        onClick: async () => {
          tog.disabled = true;
          const resp = await apiFetch("POST", "/admin/rules", Object.assign({}, r, { status: active ? "disabled" : "active" }));
          if (!resp.ok) { tog.disabled = false; uiToast(httpErr(resp), "err"); return; }
          uiToast(active ? bl({ en: "Disabled.", ja: "無効化しました。" }) : bl({ en: "Enabled.", ja: "有効化しました。" }), "ok");
          r.status = active ? "disabled" : "active";
          rebuild();
          renderRuleList(section, plane, direction);
        } });

      return el("tr", {}, [
        el("td", {}, el("strong", { text: host })),
        el("td", {}, statusBadge(active)),
        el("td", { class: "ui-row-actions" }, [tog, document.createTextNode(" "), rev]),
      ]);
    });
    listHost.appendChild(el("table", { class: "ui-table" }, [
      el("thead", {}, el("tr", {}, [bl({ en: "Host", ja: "ホスト" }), bl({ en: "Status", ja: "状態" }), bl({ en: "Action", ja: "操作" })].map((x) => el("th", { text: x })))),
      el("tbody", {}, rows),
    ]));
  }

  rebuild();
  const m = uiModal({ title: bl({ en: "Cert-pin bypass — " + rules.length + " sites", ja: "ピンニングによる検査除外 — " + rules.length + " 件のサイト" }), body: [listHost],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Close", ja: "閉じる" }), onClick: () => m.close() })] });
}

// ---- editor ----------------------------------------------------------------

// openRuleEditor builds the two-axis rule editor in a modal. plane/direction fix the rule's plane + direction.
// Authenticate (with provider-aware step-up assurance) is available on both planes. onSaved re-renders the list.
// When `existing` (a rule object) is passed, the editor prefills every field and saves back to the same rule id
// (upsert) — i.e. Edit; otherwise it creates a new rule.
async function openRuleEditor(plane, direction, onSaved, existing, onCancelled) {
  existing = existing || null;
  let savePending = false, writeAttempted = false;
  let savedOk = false; // set true on a successful save so onCancelled (below) does NOT fire on close
  let idx, editorTenant;
  try { [idx, editorTenant] = await Promise.all([catalogIndex(), ruleEditorTenant()]); }
  catch (e) { uiToast(bl({ en: "Could not load the catalog: ", ja: "カタログを読み込めません: " }) + (e.message || e), "err"); return; }

  const eAction = (existing && existing.action) || {};
  // existing WITH an id = Edit; existing WITHOUT an id = a PRE-FILLED new rule (e.g. adopting an observed flow) —
  // review + Save creates it. No existing = a blank new rule.
  const isEdit = !!(existing && existing.id);
  const draftRuleID = isEdit ? existing.id : "rule-" + crypto.randomUUID();
  const title = isEdit
    ? bl({ en: "Edit rule", ja: "ルールを編集" })
    : existing
      ? bl({ en: "Adopt observed flow into a rule", ja: "観測フローをルール化" })
      : (plane === "east_west"
        ? bl({ en: "New Connector Access rule", ja: "新しいコネクタ経由アクセスルール" })
        : bl({ en: "New internet access rule", ja: "新しいインターネットアクセスルール" }));

  const prioF = uiField({ name: "prio", label: bl({ en: "Priority (lower wins)", ja: "優先度(小さいほど優先)" }), type: "number", value: existing && existing.priority != null ? existing.priority : 100 });
  const nameF = uiField({ name: "name", label: bl({ en: "Name (optional)", ja: "名前(任意)" }), value: existing ? (existing.name || "") : "", placeholder: bl({ en: "e.g. Allow Finance → ERP", ja: "例: 経理 → ERP を許可" }) });

  // Source / Destination subject pickers — every group AND every endpoint (operator + built-in catalog) is
  // individually selectable, sorted alphabetically so a just-added endpoint lands where expected. Type-to-filter.
  const subjects = idx.groups.map((g) => ({ id: g.id, label: g.alias, kind: "group", tier0: g.tier0, builtIn: !!g.built_in }))
    .concat(idx.endpoints.map((e) => ({ id: e.id, label: e.alias, kind: "endpoint", platform: e.platform, builtIn: !!e.built_in })));
  subjects.sort((a, b) => (a.label || "").localeCompare(b.label || ""));
  // Source "who" can be a device/group OR — via the identity-group add — an IdP person/group (idgroup:<name>).
  // An identity source applies to the user from any device, browser included, which is how one rule covers
  // agentless (clientless) published-app access. Destination stays device/endpoint only.
  // Populate the identity-group picker with the REAL IdP groups the directory has seen (the synced Keycloak
  // department/group set) so the operator can SELECT a configured group instead of guessing its exact name.
  // Free-text still works for a group not yet represented in the directory.
  // IdP identity tree for the Source drill-down: the configured IdP's groups, each with its members, built from
  // the synced directory (department = the Keycloak group; a person's stable id is the subject). This lets the
  // operator pick a WHOLE group (idgroup:) OR drill in and pick INDIVIDUAL people (iduser:) — multi-select at
  // either level. Source-only — the Destination stays device/endpoint.
  const src = subjectPicker(bl({ en: "Source (who — people, devices, or agents)", ja: "送信元(誰 — 人・デバイス・エージェント)" }), subjects, { identityGroups: true, agents: plane === "egress", onAgentChange: () => syncAgent() });
  const dst = subjectPicker(bl({ en: "Destination (where)", ja: "宛先(どこ)" }), subjects);
  if (existing) { src.setSelected(existing.source); dst.setSelected(existing.destination); }
  // Load the IdP identity drill-down (groups→members) LAZILY. The editor must open IMMEDIATELY, so a slow or
  // unreachable directory (control plane) can NEVER block it — blocking here made "add a Source" appear
  // unresponsive. When the directory resolves, inject the tree into the Source picker; on any failure the
  // free-text "+ Add" identity-group entry, the device/group list, and the agent add all still work.
  (async () => {
    try {
      const dr = await apiFetch("GET", "/admin/human-identities", null, "control");
      if (!(dr && dr.ok && dr.body)) return;
      const items = dr.body.identities || dr.body.items || (Array.isArray(dr.body) ? dr.body : []);
      const byGroup = {}; // group -> { id -> {id,label} }  (dedup people by id: the directory can hold duplicates)
      items.forEach((i) => {
        const g = ((i && i.department) || "").trim();
        const pid = ((i && (i.subject || i.id || i.email)) || "").trim();
        if (!g || !pid) return;
        (byGroup[g] = byGroup[g] || {})[pid] = { id: pid, label: (i.display_name || i.email || pid) };
      });
      src.setIdpTree(Object.keys(byGroup).sort().map((g) => ({ group: g, people: Object.values(byGroup[g]).sort((a, b) => (a.label || "").localeCompare(b.label || "")) })));
    } catch (e) { /* directory optional — the free-text identity-group input still works */ }
  })();
  // Same lazily, for the agent (NHI) source: populate the "+ Add agent" list with the registered service
  // accounts / AI agents so the operator picks one instead of typing an id. Egress-only; failure is non-fatal
  // (the free-text agent add still works). NHIs live on the enforcement (Edge) plane, like the rules.
  if (plane === "egress") {
    (async () => {
      try {
        const nr = await apiFetch("GET", "/admin/non-human-identities", null);
        if (!(nr && nr.ok && nr.body)) return;
        const nhis = nr.body.identities || nr.body.items || (Array.isArray(nr.body) ? nr.body : []);
        src.setAgentList(nhis.map((n) => ({ id: (n && n.id) || "", name: (n && n.name) || "" })).filter((n) => n.id));
      } catch (e) { /* agent list optional — the free-text agent add still works */ }
    })();
  }

  // Agent tool boundary (S4): when the "who" is an agent (nhi:), the rule's target is a TOOL allowlist, not a
  // network destination — it compiles to the policy's allowed_tool_ids, so a tool outside it is denied
  // before it runs. Shown only for an agent source; the network Destination can then be Any.
  const toolsF = uiField({ name: "tools", label: bl({ en: "Allowed tools (agent boundary)", ja: "許可ツール(エージェント境界)" }), value: (existing && (existing.allowed_tool_ids || []).join(", ")) || "", placeholder: "read_repo, open_pr", hint: bl({ en: "The tools this agent may call. Leave empty for no tool boundary. The network Destination can be Any for an agent rule.", ja: "このエージェントが呼べるツール。空なら制限しません。エージェントのルールでは宛先を「すべて」にできます。" }) });
  const agentWrap = el("div", { class: "asset-dyn" }, [toolsF.el]);
  const hasAgentSource = () => (src.selected() || []).some((s) => typeof s === "string" && s.indexOf(AGENT_PREFIX) === 0);
  function syncAgent() { agentWrap.style.display = hasAgentSource() ? "" : "none"; }

  // Service.
  // Empty service_id compiles to no service scope on BOTH planes (east-west: any protocol; egress: any
  // destination port — compile_egress.go keeps a no-service rule port-agnostic). Label it Any, same as the
  // Source/Destination wildcard; a 443-only rule picks the explicit HTTPS service.
  const svcOptions = [{ value: "", label: bl({ en: "Any", ja: "すべて" }) }]
    .concat(idx.services.map((s) => ({ value: s.id, label: s.alias + " (" + (s.ports || []).map((p) => p.protocol + "/" + p.port).join(",") + ")" })));
  const svcF = uiField({ name: "svc", label: bl({ en: "Service (what)", ja: "Service(何を)" }), type: "select", value: existing ? (existing.service_id || "") : "", options: svcOptions });

  // Access axis.
  const accessF = uiField({ name: "access", label: bl({ en: "Access", ja: "アクセス" }), type: "select", value: eAction.access || "allow", options: [
    { value: "allow", label: bl({ en: "Allow", ja: "許可" }) },
    { value: "authenticate", label: bl({ en: "Authenticate (verify identity)", ja: "本人確認を要求" }) },
    { value: "deny", label: bl({ en: "Deny", ja: "拒否" }) },
  ] });

  // Inspection axis.
  const inspF = uiField({ name: "insp", label: bl({ en: "Contents", ja: "中身" }), type: "select", value: eAction.inspection || "inspect", options: [
    { value: "inspect", label: bl({ en: "Inspect (decrypt)", ja: "傍受(復号)" }) },
    { value: "bypass", label: bl({ en: "Do not inspect it", ja: "検査しない" }) },
  ] });

  // Step-up assurance for access=authenticate — provider-aware (the chosen IdP's type decides which acr/amr it
  // can satisfy). Shown only when Authenticate is chosen.
  const idpF = uiField({ name: "idp", label: bl({ en: "Identity provider", ja: "ID プロバイダ" }), type: "select", value: "", options: [{ value: "", label: bl({ en: "(tenant default IdP)", ja: "(テナント既定 IdP)" }) }] });
  const asrF = uiField({ name: "asr", label: bl({ en: "Required sign-in strength", ja: "要求するサインイン強度" }), type: "select", value: "none", options: [{ value: "none", label: bl({ en: "No extra sign-in", ja: "追加サインインなし" }) }] });
  const maxAgeF = uiField({ name: "maxage", label: bl({ en: "Require a sign-in within (minutes)", ja: "この分数以内のサインインを要求" }), type: "number", value: eAction.max_age_seconds ? Math.round(eAction.max_age_seconds / 60) : (plane === "east_west" ? 15 : "") });
  const customAcrF = uiField({ name: "acr", label: bl({ en: "Custom acr (advanced)", ja: "カスタム acr(上級)" }), placeholder: "acr" });
  const customAmrF = uiField({ name: "amr", label: bl({ en: "Custom amr (comma-separated)", ja: "カスタム amr(カンマ区切り)" }), placeholder: "fido, mfa" });
  customAcrF.el.style.display = "none"; customAmrF.el.style.display = "none";

  // Machine / no-logged-in-user path. When ON, a connection from an ENROLLED device with nobody signed in (a
  // service or automated job that cannot do a browser sign-in) is allowed automatically instead of held forever;
  // a high-risk device is still denied. OFF (default) = even an enrolled machine needs a person to sign in. Only
  // meaningful for Authenticate rules. (No posture gate — device attestation = a verified enrolled device.)
  const deviceAttestedF = uiField({ name: "device_attested_auto", label: bl({ en: "Allow machines with no signed-in user (no browser prompt)", ja: "サインインユーザーのいないマシンを許可(ブラウザ確認なし)" }), type: "checkbox", value: !!eAction.device_attested_auto, hint: bl({
    en: "Some traffic comes from a machine with nobody logged in — a background service or scheduled job that can't complete a browser sign-in. Turn this ON to let those connections through automatically, but only from an ENROLLED, known device. A device flagged high-risk is still blocked. Leave it OFF for your most sensitive destinations, so even an enrolled machine needs a person to sign in first.",
    ja: "ログインユーザーのいないマシン — バックグラウンドのサービスやスケジュール実行など、ブラウザでのサインインができない接続があります。ONにすると、そうした接続を自動的に通します(対象は「登録済みの既知デバイス」からのものだけ)。高リスクと判定されたデバイスは引き続き拒否します。最も機密な宛先ではOFFのままにし、登録済みマシンでも人によるサインインを必須にしてください。",
  }) });

  const note = el("p", { class: "ui-field-hint", text: bl({
    en: "For access to internal resources, require a phishing-resistant sign-in (a passkey or security key) done recently. Not every identity provider can do this — the choices below are limited to what the selected provider supports.",
    ja: "内部リソースへのアクセスには、フィッシング耐性のあるサインイン(パスキーまたはセキュリティキー)を、しかも最近行われたものとして要求します。すべての ID プロバイダが対応しているわけではなく、下の選択肢は選んだプロバイダが対応できるものに限られます。",
  }) });
  note.style.color = "var(--warn)";
  const googleWarn = el("p", { class: "ui-field-hint", text: bl({
    en: "⚠ The selected identity provider can't enforce a phishing-resistant sign-in. Choose “no step-up”, or pick a provider that supports one.",
    ja: "⚠ 選択中の ID プロバイダはフィッシング耐性のあるサインインを強制できません。「step-upなし」を選ぶか、対応するプロバイダを選んでください。",
  }) });
  googleWarn.style.color = "#c0392b"; googleWarn.style.display = "none";

  const idpSelect = idpF.el.querySelector("select");
  const asrSelect = asrF.el.querySelector("select");
  const idpTypes = {};
  let defaultType = "";

  // Presets map a menu choice to the assurance the broker checks: acr-based (Okta) sets min_acr; amr-based
  // (Entra) sets required_amr via the "amr:" prefix; "custom" reveals free-text acr/amr for generic OIDC.
  function presetsForType(type) {
    const none = ["none", bl({ en: "No extra sign-in", ja: "追加サインインなし" })];
    const custom = ["custom", bl({ en: "Custom (advanced)", ja: "カスタム(上級)" })];
    switch ((type || "").toLowerCase()) {
      case "okta": return [none,
        ["phr", bl({ en: "Phishing-resistant passkey", ja: "フィッシング耐性パスキー" })],
        ["phrh", bl({ en: "Phishing-resistant hardware key", ja: "フィッシング耐性ハードウェアキー" })],
        ["urn:okta:loa:2fa:any", bl({ en: "Any two factors", ja: "任意の2要素" })], custom];
      case "entra": return [none,
        ["amr:fido", bl({ en: "Phishing-resistant passkey (FIDO2)", ja: "フィッシング耐性パスキー(FIDO2)" })],
        ["amr:mfa", bl({ en: "Multi-factor (MFA)", ja: "多要素(MFA)" })], custom];
      case "google": return [none];
      default: return [none, custom];
    }
  }
  function applyPreset(val) {
    if (!val || val === "none") return {};
    if (val === "custom") {
      const out = {};
      if (customAcrF.get()) out.min_acr = customAcrF.get();
      const amr = customAmrF.get().split(",").map((s) => s.trim()).filter(Boolean);
      if (amr.length) out.required_amr = amr;
      return out;
    }
    if (val.indexOf("amr:") === 0) return { required_amr: [val.slice(4)] };
    return { min_acr: val };
  }
  function typeForSelectedIdP() { return idpF.get() ? (idpTypes[idpF.get()] || "") : defaultType; }
  function toggleCustom() {
    const isCustom = asrF.get() === "custom";
    customAcrF.el.style.display = isCustom ? "" : "none";
    customAmrF.el.style.display = isCustom ? "" : "none";
  }
  function rebuildAssurance() {
    const ty = typeForSelectedIdP();
    const presets = presetsForType(ty);
    asrSelect.innerHTML = "";
    presets.forEach(([v, l]) => asrSelect.appendChild(el("option", { value: v, text: l })));
    // security-forward default for internal access: prefer a phishing-resistant preset when supported.
    if (plane === "east_west") { const phr = presets.find(([v]) => v === "phr" || v === "amr:fido"); if (phr) asrSelect.value = phr[0]; }
    googleWarn.style.display = ty.toLowerCase() === "google" ? "" : "none";
    toggleCustom();
  }
  // applyExistingAssurance reverse-maps a saved authenticate action onto the assurance controls: it picks the
  // matching preset if one exists (e.g. acr=phr, amr:fido), else falls back to the Custom acr/amr free-text.
  function applyExistingAssurance() {
    const a = eAction;
    let want = "none";
    if (a.min_acr) want = a.min_acr;
    else if (a.required_amr && a.required_amr.length) want = "amr:" + a.required_amr[0];
    const opt = want !== "none" && Array.from(asrSelect.options).some((o) => o.value === want);
    if (want === "none") asrSelect.value = "none";
    else if (opt) asrSelect.value = want;
    else {
      asrSelect.value = "custom";
      if (a.min_acr) customAcrF.set(a.min_acr);
      if (a.required_amr && a.required_amr.length) customAmrF.set(a.required_amr.join(", "));
    }
    toggleCustom();
  }

  asrSelect.addEventListener("change", toggleCustom);
  idpSelect.addEventListener("change", rebuildAssurance);

  apiFetch("GET", "/admin/idp-connections").then((r) => {
    if (r && r.ok && r.body && Array.isArray(r.body.connections)) {
      r.body.connections.forEach((c) => {
        idpTypes[c.idp_id] = c.type || "";
        if (c.idp_id === r.body.default_idp_id) defaultType = c.type || "";
        idpSelect.appendChild(el("option", { value: c.idp_id, text: c.idp_id + " (" + (c.type || "oidc") + ")" }));
      });
    }
    if (existing && eAction.required_idp_id) idpF.set(eAction.required_idp_id);
    rebuildAssurance();
    if (existing && eAction.access === "authenticate") applyExistingAssurance();
  }).catch(() => { rebuildAssurance(); if (existing && eAction.access === "authenticate") applyExistingAssurance(); });

  const assuranceWrap = el("div", { class: "asset-dyn" }, [
    el("div", { class: "ui-field-label", text: bl({ en: "Sign-in requirements (for Authenticate)", ja: "サインイン要件(本人確認を要求する場合)" }) }),
    note, idpF.el, asrF.el, maxAgeF.el, customAcrF.el, customAmrF.el, deviceAttestedF.el, googleWarn,
  ]);
  assuranceWrap.style.display = "none";

  // Coherence: deny cannot bypass inspection; assurance only for authenticate.
  const inspSelect = inspF.el.querySelector("select");
  function syncAccess() {
    const v = accessF.get();
    const bypassOpt = inspSelect.querySelector('option[value="bypass"]');
    if (v === "deny") { if (bypassOpt) bypassOpt.disabled = true; inspF.set("inspect"); }
    else if (bypassOpt) bypassOpt.disabled = false;
    assuranceWrap.style.display = v === "authenticate" ? "" : "none";
  }
  accessF.el.querySelector("select").addEventListener("change", syncAccess);
  syncAccess(); // reflect the initial / prefilled access value

  // DLP axis (egress only): scan the decrypted upload for identifiers and act on a match. Requires
  // Interception = Inspect (a bypassed flow has no plaintext). Third axis of the action: Access × Inspection × DLP.
  const dlpExisting = (existing && existing.action && existing.action.dlp) || null;
  // DLP is configured ONLY via a reusable named DLP Policy (docs/dlp_policy_ux_integration.md) — there is no
  // inline per-rule DLP config, so DLP settings live in exactly one place (the DLP Policies page) and a rule only
  // SELECTS one here. Options are loaded async from /admin/dlp-policies.
  const dlpPolicyF = uiField({ name: "dlppolicy", label: bl({ en: "DLP policy", ja: "DLP ポリシー" }), type: "select", value: (dlpExisting && dlpExisting.policy_id) || "", hint: bl({ en: "Apply a reusable DLP policy to this traffic. Create and edit policies (what to detect + action + account + device risk) on the DLP Policies page.", ja: "この通信に適用する DLP ポリシーを選択。ポリシー(検出対象+アクション+アカウント+デバイスリスク)は「DLP ポリシー」ページで作成・編集します。" }), options: [{ value: "", label: bl({ en: "None", ja: "なし" }) }] });
  // Load the tenant's named DLP policies into the selector.
  (async () => {
    try {
      const pr = await apiFetch("GET", "/admin/dlp-policies");
      const policies = (pr && pr.ok && pr.body && pr.body.policies) || [];
      const sel = dlpPolicyF.el.querySelector("select");
      policies.forEach((p) => sel.appendChild(el("option", { value: p.id, text: p.name })));
      if (dlpExisting && dlpExisting.policy_id) sel.value = dlpExisting.policy_id;
    } catch (e) { /* policies optional */ }
  })();
  // Paid-feature gate: only show the DLP option on a rule when the tenant is licensed for DLP.
  const dlpLicensed = !(window.dsseEntitlements && window.dsseEntitlements.dlp === false);
  const dlpWrap = dlpLicensed ? el("div", { class: "asset-dyn" }, [dlpPolicyF.el]) : el("div", {});

  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Save rule", ja: "ルールを保存" }) });
  // Risk gate (optional): the rule bites only when the subject's CURRENT risk is at least this level (a device or
  // person marked high-risk from its row). Pair "High or higher" with Access = Require verification for the
  // canonical "high-risk → re-authenticate".
  const riskF = uiField({ name: "risk", label: bl({ en: "Apply only when risk is at least", ja: "適用するリスク下限" }), type: "select", value: (existing && existing.risk_at_least) || "", hint: bl({ en: "Gate this rule on the subject's live risk (set from a device's or person's own row). Any = no gate.", ja: "対象のいまのリスク(デバイス/ユーザーの行から設定)でこのルールを絞り込みます。「すべて」なら絞り込みません。" }), options: [
    { value: "", label: bl({ en: "Any (no risk gate)", ja: "すべて(ゲートなし)" }) },
    { value: "medium", label: bl({ en: "Medium or higher", ja: "中以上" }) },
    { value: "high", label: bl({ en: "High or higher", ja: "高以上" }) },
    { value: "critical", label: bl({ en: "Critical", ja: "重大" }) } ] });
  // Enforcement stage (East-West learning lifecycle): Warn = dry-run — an Authenticate/Deny rule ALLOWS the
  // connection but the user is notified it's monitored and will soon require auth; flip to Enforce when ready.
  // No effect on Allow rules (nothing to soften). See docs/east_west_policy_learning_lifecycle_gap.md.
  const stageF = uiField({ name: "stage", label: bl({ en: "Enforcement stage", ja: "適用ステージ" }), type: "select", value: (existing && existing.stage) || "enforce", hint: bl({
    en: "Warn = dry-run: an Authenticate/Deny rule still ALLOWS the connection, but the user is notified it's monitored and will soon require authentication. Flip to Enforce when you trust the rule. (No effect on Allow rules.)",
    ja: "「警告のみ」では、本人確認を要求・拒否のルールでも接続は許可したうえで、監視中であり間もなく認証が必要になることを利用者に通知します。ルールを信頼できたら「即時適用」に切り替えてください。(「許可」のルールには影響しません。)",
  }), options: [
    { value: "enforce", label: bl({ en: "Enforce (rule bites)", ja: "即時適用" }) },
    { value: "warn", label: bl({ en: "Warn (monitor + notify, don't block yet)", ja: "警告のみ(監視して通知、まだ遮断しない)" }) },
  ] });
  const m = uiModal({ title, body: [prioF.el, nameF.el, src.el, agentWrap, dst.el, svcF.el, accessF.el, assuranceWrap, inspF.el, riskF.el].concat(plane === "east_west" ? [stageF.el] : []).concat(plane === "egress" ? [dlpWrap] : []),
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit],
    // Clean up a pre-created dependency only if no write was attempted. An unconfirmed response
    // may follow a committed rule that still references that dependency.
    onClose: () => { if (!savedOk && !writeAttempted && typeof onCancelled === "function") onCancelled(); } });

  submit.addEventListener("click", async () => {
    if (savePending || !m.el.isConnected || !prioF.validate()) return;
    const priority = Number(prioF.get());
    if (!/^-?\d+$/.test(prioF.get().trim()) || !Number.isSafeInteger(priority)) { uiToast(bl({en:"Priority must be a whole number.",ja:"優先度は整数で入力してください。"}),"err"); return; }
    const source = src.selected();
    let destination = dst.selected();
    const agentRule = source.some((s) => typeof s === "string" && s.indexOf(AGENT_PREFIX) === 0);
    // An agent rule's target is its TOOL boundary, not a network destination — default the destination to Any.
    if (agentRule && !destination.length) destination = [SUBJECT_ANY];
    if (!source.length || !destination.length) { uiToast(bl({ en: "Pick a source and a destination.", ja: "送信元と宛先を選択してください。" }), "err"); return; }

    const action = Object.assign({}, eAction, { access: accessF.get(), inspection: inspF.get() });
    for (const key of ["required_idp_id","min_acr","required_amr","max_age_seconds","device_attested_auto","dlp"]) delete action[key];
    if (plane === "egress" && dlpPolicyF.get()) {
      // DLP is applied by referencing a named DLP policy (the only model) — it supplies detectors + action + scope.
      action.dlp = { policy_id: dlpPolicyF.get() };
    }
    if (accessF.get() === "authenticate") {
      if (idpF.get()) action.required_idp_id = idpF.get();
      const a = applyPreset(asrF.get());
      if (a.min_acr) action.min_acr = a.min_acr;
      if (a.required_amr) action.required_amr = a.required_amr;
      const mins = parseInt(maxAgeF.get(), 10);
      if (mins > 0) action.max_age_seconds = mins * 60;
      if (deviceAttestedF.get()) action.device_attested_auto = true; // machine/non-interactive: device attestation in lieu of a human ceremony
    }

    const body = { plane, priority, name: nameF.get(), source, destination, service_id: svcF.get() || undefined, action };
    if (riskF.get()) body.risk_at_least = riskF.get(); // risk gate → compiles to a risk_state_severity condition
    // Agent rule: carry the tool boundary → compiles to the policy's allowed_tool_ids.
    if (agentRule) { const tools = toolsF.get().split(",").map((s) => s.trim()).filter(Boolean); if (tools.length) body.allowed_tool_ids = tools; }
    if (plane === "east_west") body.direction = (existing && existing.direction) || direction;
    if (plane === "east_west") body.stage = stageF.get(); // learning-lifecycle stage (enforce|warn)
    // Preserve the rule ID on edits and retries, including a new draft with an unconfirmed response.
    body.id = draftRuleID;
    if (existing && existing.id) body.status = existing.status;

    savePending = true;
    const controls = [...m.el.querySelectorAll("button,input,select,textarea")].map(e => [e,e.disabled]);
    controls.forEach(([e]) => e.disabled = true);
    m.el.querySelectorAll(".rule-save-error").forEach(e => e.remove());
    try {
      if (await ruleEditorTenant() !== editorTenant) throw new Error(ruleUnknownOutcome());
      if (!m.el.isConnected) return;
      writeAttempted = true;
      const resp = await apiFetch("POST", "/admin/rules", body);
      validateRuleSave(resp, body, editorTenant);
      savedOk = true;
      m.close();
      const warning = resp.body && resp.body.warning;
      if (warning) uiToast(bl({ en: "Saved with a warning: ", ja: "警告付きで保存: " }) + warning, "info");
      else uiToast(bl({ en: "Rule saved.", ja: "ルールを保存しました。" }), "ok");
      onSaved();
    } catch(e) {
      if (m.el.isConnected) {
        const message = e.message || String(e), guidance = ruleUnknownOutcome();
        const notice = el("p",{class:"rule-save-error ui-callout ui-callout-warn",role:"alert",text:message.includes(guidance) ? message : message+" "+guidance});
        m.el.querySelector(".ui-modal-body").prepend(notice);
        notice.scrollIntoView({block:"nearest"});
      }
    } finally {
      savePending = false;
      controls.forEach(([e,disabled]) => e.disabled = disabled);
    }
  });

  syncAgent(); // reflect an agent source (show the tool-boundary field) on open, incl. Edit of an existing agent rule
  prioF.focus();
}

// subjectPicker is a searchable, scrollable multi-select over groups + endpoints — it scales to a large catalog
// (type to filter; checked items stay visible; a summary line shows the selection). Groups are listed mixed in,
// sorted alphabetically by label. Returns { el, setSelected, selected() }.
//
// opts.identityGroups (source only): also let the operator add an IdP identity GROUP (a person/group from the
// sign-in provider) as a subject. IdP groups aren't in the asset catalog (they come from the IdP token and are
// not synced), so they're referenced by name — added here and stored as `idgroup:<name>`. A rule whose "who" is
// an identity group applies to that user from ANY device, INCLUDING an agentless browser (clientless access) —
// the one addition that lets one access rule cover published-app access. See
// docs/published_app_access_egress_unification_design.md.
const IDGROUP_PREFIX = "idgroup:"; // matches policyrule.IdentityGroupPrefix
const IDUSER_PREFIX = "iduser:"; // matches policyrule.IdentityUserPrefix — a rule "who" that is one individual IdP user
const AGENT_PREFIX = "nhi:"; // matches policyrule.AgentPrefix — a rule "who" that is an agent / service account

function subjectPicker(labelText, subjects, opts) {
  opts = opts || {};
  const wrap = el("div", { class: "ui-field" }, el("div", { class: "ui-field-label", text: labelText }));
  const picker = el("div", { class: "subject-picker" });

  const anyCb = el("input", { type: "checkbox" });
  const anyRow = el("label", { class: "asset-check subject-row subject-any" }, [anyCb, uiBadge(bl({ en: "Any (wildcard)", ja: "すべて(ワイルドカード)" }), "warn")]);
  const search = el("input", { class: "ui-input subject-search", type: "search", placeholder: bl({ en: "filter by name / platform…", ja: "名前 / プラットフォームで絞り込み…" }) });
  const list = el("div", { class: "subject-list" });
  const summary = el("div", { class: "subject-summary" });
  const checks = {};
  const rows = [];
  let idInput = null;
  // Disclosure hosts: "+ Add person / group" and "+ Add agent" each reveal a focused, checkable LIST (rendered
  // into these) so the operator SELECTS from a list rather than having to know + type an id — the +↦list↦
  // multi-select the source picker was missing. Populated by setIdpTree() / setAgentList() when their (lazy)
  // fetches resolve.
  let idpTreeHost = null;
  let agentListHost = null;

  const updateSummary = () => {
    if (anyCb.checked) { summary.textContent = bl({ en: "Selected: Any (wildcard)", ja: "選択中: すべて(ワイルドカード)" }); return; }
    const sel = rows.filter((r) => r.cb.checked).map((r) => r.label);
    summary.textContent = sel.length ? bl({ en: "Selected: ", ja: "選択中: " }) + sel.join(", ") : bl({ en: "Nothing selected", ja: "未選択" });
  };
  const expandedGroups = {}; // IdP-group drill-down: group name -> expanded?
  const applyFilter = () => {
    const q = search.value.trim().toLowerCase();
    rows.forEach((r) => {
      let show;
      if (r.groupName) { // a drill-down PERSON row: shown when a search matches it, or its group is expanded, or it's checked
        show = q ? r.hay.includes(q) : (expandedGroups[r.groupName] || r.cb.checked);
      } else {
        show = !q || r.hay.includes(q) || r.cb.checked;
      }
      r.row.style.display = show ? "" : "none";
    });
  };

  anyCb.addEventListener("change", () => {
    const on = anyCb.checked;
    search.disabled = on;
    rows.forEach((r) => { r.cb.disabled = on; });
    if (idInput) idInput.disabled = on;
    picker.classList.toggle("any-on", on);
    updateSummary();
  });

  // addSubjectRow renders one selectable subject — a catalog device/group, or an added identity group.
  const addSubjectRow = (s) => {
    const cb = el("input", { type: "checkbox" });
    cb.addEventListener("change", updateSummary);
    checks[s.id] = cb;
    let chipEls;
    if (s.kind === "identity") {
      chipEls = [uiBadge(bl({ en: "Person / group", ja: "人 / グループ" }), "ok"), el("span", { class: "subject-chip-label", text: s.label })];
    } else if (s.kind === "agent") {
      chipEls = [uiBadge(bl({ en: "Agent", ja: "エージェント" }), "warn"), el("span", { class: "subject-chip-label", text: s.label })];
    } else {
      chipEls = [
        uiBadge(s.kind === "group" ? bl({ en: "Group", ja: "グループ" }) : bl({ en: "Endpoint", ja: "エンドポイント" }), s.kind === "group" ? "ok" : "off"),
        el("span", { class: "subject-chip-label", text: s.label }),
      ];
      if (s.builtIn) chipEls.push(uiBadge(bl({ en: "built-in", ja: "組み込み" }), "off"));
      if (s.tier0) chipEls.push(uiBadge("Tier-0", "danger"));
      if (s.platform === "macos") chipEls.push(uiBadge("macOS", "off"));
      if (s.platform === "windows") chipEls.push(uiBadge("Windows", "off"));
    }
    const row = el("label", { class: "asset-check subject-row" }, [cb, el("span", { class: "subject-chip" }, chipEls)]);
    list.appendChild(row);
    rows.push({ row, cb, label: s.label, hay: (s.label + " " + (s.kind || "") + " " + (s.platform || "")).toLowerCase() });
    return cb;
  };
  subjects.forEach(addSubjectRow);

  // IdP identity DRILL-DOWN (source only): the configured IdP's groups, each expandable to its members, so the
  // operator can pick a WHOLE group (idgroup:<name>) OR INDIVIDUAL people (iduser:<id>) — multi-select at either
  // level. Groups + members come from the synced directory. Every checkbox registers in `checks`, so selection +
  // save use the same path as any other subject.
  const ensureIdentityUser = (id, label) => {
    id = (id || "").trim();
    if (!id) return null;
    const sid = IDUSER_PREFIX + id;
    if (checks[sid]) return checks[sid];
    return addSubjectRow({ id: sid, label: label || id, kind: "identity" });
  };
  // buildIdpTree renders the group→member drill-down. It is called LAZILY (setIdpTree) once the directory fetch
  // resolves — the editor must never block on that fetch, so a slow/unreachable directory cannot stop the Source
  // picker (or the whole editor) from opening. A group already represented as a flat row (e.g. materialized by
  // setSelected on Edit) is skipped to avoid a duplicate/checkbox race. Safe to call more than once.
  let _idpTreeBuilt = false;
  const buildIdpTree = (idpTree) => {
    if (_idpTreeBuilt || !idpTree || !idpTree.length) return;
    _idpTreeBuilt = true;
    const tree = el("div", { class: "subject-idp-tree" });
    idpTree.forEach(({ group, people }) => {
      const gid = IDGROUP_PREFIX + group;
      if (checks[gid]) return; // already present as a flat row — don't duplicate it in the tree
      const gcb = el("input", { type: "checkbox" });
      gcb.addEventListener("change", () => { updateSummary(); applyFilter(); });
      checks[gid] = gcb;
      const expand = el("button", { class: "ui-btn ui-btn-sm subject-idp-expand", type: "button", text: "▸" });
      const grow = el("label", { class: "asset-check subject-row subject-idp-group" }, [gcb, el("span", { class: "subject-chip" }, [uiBadge(bl({ en: "IdP group", ja: "IdP グループ" }), "ok"), el("span", { class: "subject-chip-label", text: group }), el("span", { class: "subject-idp-count", text: " (" + ((people && people.length) || 0) + ")" })])]);
      const grouprow = el("div", { class: "subject-idp-grouprow" }, [expand, grow]);
      tree.appendChild(grouprow);
      rows.push({ row: grouprow, cb: gcb, label: group, hay: (group + " idp group").toLowerCase() });
      expand.addEventListener("click", () => { expandedGroups[group] = !expandedGroups[group]; expand.textContent = expandedGroups[group] ? "▾" : "▸"; applyFilter(); });
      (people || []).forEach((pp) => {
        const uid = IDUSER_PREFIX + pp.id;
        if (checks[uid]) return;
        const pcb = el("input", { type: "checkbox" });
        pcb.addEventListener("change", () => { updateSummary(); applyFilter(); });
        checks[uid] = pcb;
        const prow = el("label", { class: "asset-check subject-row subject-idp-person" }, [pcb, el("span", { class: "subject-chip" }, [uiBadge(bl({ en: "Person", ja: "人" }), "off"), el("span", { class: "subject-chip-label", text: pp.label })])]);
        prow.style.display = "none";
        tree.appendChild(prow);
        rows.push({ row: prow, cb: pcb, label: pp.label, hay: (pp.label + " " + group + " person").toLowerCase(), groupName: group });
      });
    });
    (idpTreeHost || list).appendChild(tree); // into the "+ Add person / group" disclosure panel (falls back to the list)
    applyFilter();
  };
  buildIdpTree(opts.idpTree);

  // buildAgentList renders the existing service accounts / AI agents (NHIs) as a checkable list into the
  // "+ Add agent" disclosure panel, so the operator picks an agent instead of having to know + type its id.
  let _agentListBuilt = false;
  const buildAgentList = (nhis) => {
    if (_agentListBuilt || !agentListHost || !nhis || !nhis.length) return;
    _agentListBuilt = true;
    nhis.forEach((n) => {
      const nid = ((n && (n.id || n.name)) || "").trim();
      if (!nid) return;
      const sid = AGENT_PREFIX + nid;
      if (checks[sid]) return;
      const cb = el("input", { type: "checkbox" });
      cb.addEventListener("change", () => { updateSummary(); applyFilter(); if (opts.onAgentChange) opts.onAgentChange(); });
      checks[sid] = cb;
      const lbl = (n.name && n.name !== nid) ? (n.name + " (" + nid + ")") : nid;
      const row = el("label", { class: "asset-check subject-row" }, [cb, el("span", { class: "subject-chip" }, [uiBadge(bl({ en: "Agent", ja: "エージェント" }), "warn"), el("span", { class: "subject-chip-label", text: lbl })])]);
      agentListHost.appendChild(row);
      rows.push({ row, cb, label: lbl, hay: (lbl + " " + nid + " agent").toLowerCase() });
    });
    applyFilter();
  };

  // Identity-group add (source only): reference an IdP group by name → an `idgroup:<name>` subject.
  const ensureIdentityGroup = (name) => {
    name = (name || "").trim();
    if (!name) return null;
    const id = IDGROUP_PREFIX + name;
    if (checks[id]) return checks[id]; // already present
    return addSubjectRow({ id, label: name, kind: "identity" });
  };
  if (opts.identityGroups) {
    // "+ Add person / group" DISCLOSURE: clicking it reveals a focused list of the configured IdP groups (each
    // expandable to its members) to multi-select — plus a free-text field for a group not in the directory.
    const toggle = el("button", { class: "ui-btn ui-btn-sm subject-add-toggle", type: "button", text: bl({ en: "＋ Add person / group ▾", ja: "＋ 人 / グループを追加 ▾" }) });
    idpTreeHost = el("div", { class: "subject-idp-tree-host" });
    idInput = el("input", { class: "ui-input", type: "text", placeholder: bl({ en: "…or a group name not listed", ja: "…一覧にないグループ名" }) });
    const addBtn = el("button", { class: "ui-btn ui-btn-sm", type: "button", text: bl({ en: "Add", ja: "追加" }) });
    const addNow = () => { const cb = ensureIdentityGroup(idInput.value); if (cb) { cb.checked = true; idInput.value = ""; updateSummary(); applyFilter(); } };
    addBtn.addEventListener("click", addNow);
    idInput.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); addNow(); } });
    const panel = el("div", { class: "subject-add-panel" }, [idpTreeHost, el("div", { class: "subject-idadd" }, [idInput, addBtn])]);
    panel.style.display = "none";
    toggle.addEventListener("click", () => { const open = panel.style.display === "none"; panel.style.display = open ? "" : "none"; toggle.textContent = bl({ en: "＋ Add person / group " + (open ? "▴" : "▾"), ja: "＋ 人 / グループを追加 " + (open ? "▴" : "▾") }); if (open) applyFilter(); });
    picker.appendChild(toggle);
    picker.appendChild(panel);
  }

  // Agent add (source only): reference a service account / AI agent by its NHI id → an `nhi:<id>` subject. A rule
  // whose "who" is an agent governs that automated actor (actor_nhi_id), and can carry a tool boundary.
  const ensureAgent = (id) => {
    id = (id || "").trim();
    if (!id) return null;
    const sid = AGENT_PREFIX + id;
    if (checks[sid]) return checks[sid];
    return addSubjectRow({ id: sid, label: id, kind: "agent" });
  };
  if (opts.agents) {
    // "+ Add agent" DISCLOSURE: reveals a list of the existing service accounts / AI agents (NHIs) to
    // multi-select — plus a free-text field for an agent id not in the registry.
    const toggle = el("button", { class: "ui-btn ui-btn-sm subject-add-toggle", type: "button", text: bl({ en: "＋ Add agent ▾", ja: "＋ エージェントを追加 ▾" }) });
    agentListHost = el("div", { class: "subject-agent-host" });
    const agInput = el("input", { class: "ui-input", type: "text", placeholder: bl({ en: "…or an agent id not listed, e.g. ci-bot", ja: "…一覧にないエージェント id (例: ci-bot)" }) });
    const agBtn = el("button", { class: "ui-btn ui-btn-sm", type: "button", text: bl({ en: "Add", ja: "追加" }) });
    const addAg = () => { const cb = ensureAgent(agInput.value); if (cb) { cb.checked = true; agInput.value = ""; updateSummary(); applyFilter(); if (opts.onAgentChange) opts.onAgentChange(); } };
    agBtn.addEventListener("click", addAg);
    agInput.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); addAg(); } });
    const panel = el("div", { class: "subject-add-panel" }, [agentListHost, el("div", { class: "subject-idadd" }, [agInput, agBtn])]);
    panel.style.display = "none";
    toggle.addEventListener("click", () => { const open = panel.style.display === "none"; panel.style.display = open ? "" : "none"; toggle.textContent = bl({ en: "＋ Add agent " + (open ? "▴" : "▾"), ja: "＋ エージェントを追加 " + (open ? "▴" : "▾") }); if (open) applyFilter(); });
    picker.appendChild(toggle);
    picker.appendChild(panel);
  }

  search.addEventListener("input", applyFilter);
  updateSummary();
  picker.appendChild(anyRow);
  picker.appendChild(search);
  picker.appendChild(list);
  picker.appendChild(summary);
  wrap.appendChild(picker);

  // setSelected prefills the picker (used by Edit). ["*"] turns on the Any wildcard; otherwise the matching
  // endpoint/group checkboxes are checked — and any `idgroup:<name>` id is materialized as an identity row.
  const setSelected = (ids) => {
    ids = ids || [];
    if (ids.indexOf(SUBJECT_ANY) >= 0) {
      anyCb.checked = true;
      search.disabled = true;
      rows.forEach((r) => { r.cb.disabled = true; });
      if (idInput) idInput.disabled = true;
      picker.classList.add("any-on");
    } else {
      ids.forEach((id) => {
        if (!checks[id] && id.indexOf(IDGROUP_PREFIX) === 0) ensureIdentityGroup(id.slice(IDGROUP_PREFIX.length));
        if (!checks[id] && id.indexOf(IDUSER_PREFIX) === 0) ensureIdentityUser(id.slice(IDUSER_PREFIX.length));
        if (!checks[id] && id.indexOf(AGENT_PREFIX) === 0) ensureAgent(id.slice(AGENT_PREFIX.length));
        if (checks[id]) checks[id].checked = true;
      });
    }
    updateSummary();
    applyFilter();
  };

  return { el: wrap, setSelected, selected: () => (anyCb.checked ? [SUBJECT_ANY] : Object.keys(checks).filter((id) => checks[id].checked)), setIdpTree: buildIdpTree, setAgentList: buildAgentList };
}


// ruleFlowText is the one-line "who reaches what" for a row. A set with many destinations is stated as a
// count rather than as its members: fifteen internal group identifiers in a monospace run is not a sentence
// anybody reads, and the members are named in the row's own description.
function ruleFlowText(entry) {
  const dest = String(entry.destination_text || "");
  const parts = dest.split(",").map((x) => x.trim()).filter(Boolean);
  const shown = parts.length > 3
    ? bl({ en: parts.length + " destination groups", ja: "宛先 " + parts.length + " グループ" })
    : dest;
  return entry.source_text + " → " + shown + " : " + entry.service_text;
}

function ruleUnknownOutcome() {
  return bl({en:"The outcome is unconfirmed. Reload the rule list and check it before creating or retrying a rule.",ja:"結果を確認できません。作成や再試行の前にルール一覧を再読込して確認してください。"});
}
async function ruleEditorTenant() {
  const r = await apiFetch("GET","/admin/tenant");
  if (!r?.ok || typeof r.body?.tenant_id !== "string" || !r.body.tenant_id) throw new Error(ruleUnknownOutcome());
  return r.body.tenant_id;
}
function validateRuleSave(response, expected, tenant) {
  if (!response?.ok) throw new Error(httpErr(response));
  const saved = response.body;
  if (response.status!==200 || !saved || typeof saved.id!=="string" || !saved.id || saved.tenant_id!==tenant || (expected.id && saved.id!==expected.id)) throw new Error(ruleUnknownOutcome());
  for (const key of ["plane","direction","priority","name","service_id","status","stage","risk_at_least"]) {
    let value = expected[key];
    if (key==="status" && !value) value="active";
    if (key==="stage" && !value) value="enforce";
    if (key==="direction" && expected.plane==="east_west" && !value) value="outbound";
    if ((saved[key] ?? "") !== (value ?? "")) throw new Error(ruleUnknownOutcome());
  }
  for (const key of ["source","destination","allowed_tool_ids"]) {
    const want = expected[key] || [];
    if (JSON.stringify(saved[key] || []) !== JSON.stringify(want)) throw new Error(ruleUnknownOutcome());
  }
  const action = Object.assign({},expected.action,{inspection:expected.action?.inspection || "inspect"});
  for (const [key,value] of Object.entries(action)) {
    if (value===false || value===0 || value==="" || value==null) { if (saved.action?.[key] && saved.action[key]!==value) throw new Error(ruleUnknownOutcome()); }
    else if (!ruleExpectedValue(saved.action?.[key],value)) throw new Error(ruleUnknownOutcome());
  }
  return saved;
}

function ruleExpectedValue(actual, expected) {
  if (Array.isArray(expected)) return JSON.stringify(actual) === JSON.stringify(expected);
  if (expected && typeof expected === "object") return actual && Object.entries(expected).every(([key,value]) => ruleExpectedValue(actual[key],value));
  return actual === expected;
}
