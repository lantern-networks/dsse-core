"use strict";

// effective_policy.js — two views on the shared ui.js primitives (product-quality pattern, see
// docs/console_ux_design_direction.md):
//   • renderEffectivePolicyView   — "Policy decision check" Explains, for a destination, the full precedence-
//     ordered decision basis: every rule that competes (your rules AND built-in policies you never authored),
//     with the winner and overridden matches marked, plus whether the connection is decrypted or passed
//     through and why. Backed by GET /admin/effective-policies and GET /admin/effective-policy.
//   • renderInspectionPostureView — "Inspection Settings" Surfaces the otherwise-invisible default: does the
//     Edge decrypt every steered HTTPS flow or only an allowlist, the trusted never-decrypt list, and the
//     SaaS bypass groups. Read + configurable. Backed by GET/POST /admin/inspection-posture (+ egress
//     rules for the SaaS bypass toggles).
//
// Loaded after app.js / ui.js (el, uiState, uiBadge, uiToast, uiConfirm, uiField, simpleTable, bl, apiFetch,
// escapeHtml in scope). app.js dispatches here for custom: "effective" and custom: "posture".

// --- shared label / badge helpers --------------------------------------------------------------------------

function epDecisionLabel(d) {
  return ({
    allow: bl({ en: "Allow", ja: "許可" }),
    deny: bl({ en: "Deny", ja: "拒否" }),
    authenticate: bl({ en: "Verify", ja: "認証要求" }),
    require_reauthentication: bl({ en: "Re-verify", ja: "再認証" }),
  })[d] || d || "—";
}

function epDecisionKind(d) {
  if (d === "allow") return "ok";
  if (d === "deny") return "danger";
  if (d === "require_reauthentication" || d === "authenticate") return "warn";
  return "off";
}

function epDecisionBadge(d) { return uiBadge(epDecisionLabel(d), epDecisionKind(d)); }

function epSourceBadge(source) {
  // authored = your intent (visible in the rule editor); built_in = loaded with the system bundle.
  return source === "authored"
    ? uiBadge(bl({ en: "Your rule", ja: "作成済ルール" }), "ok")
    : uiBadge(bl({ en: "Built-in", ja: "組込" }), "off");
}

function epStatusBadge(status) {
  const disabled = status === "disabled";
  return uiBadge(disabled ? bl({ en: "Disabled", ja: "無効" }) : bl({ en: "Active", ja: "有効" }), disabled ? "off" : "ok");
}

function epMatchBadge(e) {
  if (e.winner) return uiBadge(bl({ en: "Winner", ja: "勝者" }), "ok");
  if (e.shadowed) return uiBadge(bl({ en: "Overridden", ja: "上書きされ" }), "warn");
  if (e.matched) return uiBadge(bl({ en: "Matched", ja: "一致" }), "off");
  return el("span", { class: "ui-view-desc", text: "—" });
}

// epIsImplName flags a backend-supplied name that leaks internal codenames / implementation language (a programme codename,
// "decrypt-all", "LOWEST precedence", …) or the compiler's "Authored egress rule <id>" placeholder, so it is
// never shown verbatim as a user-facing heading. Mirrors rules.js hasImplJargon.
function epIsImplName(name) {
  if (!name) return true;
  return /\bTrack\s+[A-Z]\b/.test(name)
    || /decrypt-all|lowest precedence|default fallback|catch-all/i.test(name)
    || /^Authored\s+(?:egress|east[\s-]?west)\s+rule\b/i.test(name);
}

// epAuthoredID recovers the operator's original rule id (e.g. rule-45, certpin-rule-…) from the compiler's
// "Authored egress rule <id>" name, so the recognizable id — not the internal compiled policy id — is shown as
// the small <code> handle.
function epAuthoredID(name) {
  const m = name && name.match(/^Authored\s+(?:egress|east[\s-]?west)\s+rule\s+(.+)$/i);
  return m ? m[1].trim() : "";
}

// epRuleHost pulls a human destination host from a row if the backend carries one (defensive: today's
// effective-policy rows do not, so this normally yields "").
function epRuleHost(entry) {
  const d = entry.host || entry.destination;
  if (Array.isArray(d)) { const h = d.find((x) => x && x !== "*"); return h || ""; }
  return d && d !== "*" ? d : "";
}

// epRuleHeading derives a human-readable heading for a policy / trace row, in order: (1) the backend name when it
// carries no implementation jargon; (2) "Rule for <host>" when a destination host is available; (3) the fixed
// "Default: all internet access" for built-in defaults whose name was jargon; (4) "(unnamed rule)". The raw id is
// never used as the heading — it stays as a small <code> via epPolicyCell.
function epRuleHeading(entry) {
  if (entry.name && !epIsImplName(entry.name)) return entry.name;
  const host = epRuleHost(entry);
  if (host) return bl({ en: "Rule for " + host, ja: host + " のルール" });
  if (entry.source === "built_in") return bl({ en: "Default: all internet access", ja: "既定: すべてのインターネットアクセス" });
  // A rule with a recognizable authored id but no human name (e.g. an auto-generated cert-pin bypass) should
  // be titled by that id — NOT "(unnamed rule)" while the same id also appears below it (that read as a
  // contradiction). The redundant <code> under the heading is then suppressed in epPolicyCell.
  const authored = epAuthoredID(entry.name);
  if (authored) return bl({ en: "Rule " + authored, ja: "ルール " + authored });
  return bl({ en: "(unnamed rule)", ja: "(無題のルール)" });
}

// epPolicyCell — human heading primary, raw rule id secondary in a small <code>.
function epPolicyCell(entry) {
  const codeId = epAuthoredID(entry.name) || entry.policy_id;
  const heading = epRuleHeading(entry);
  // Show the raw id under the heading only when it ADDS information — i.e. the heading is a human name. When the
  // heading already IS the id ("Rule rule-46"), a second "rule-46" line is just noise, so suppress it.
  const showCode = codeId && !String(heading).includes(codeId);
  return el("td", {}, [
    el("strong", { text: heading }),
    showCode ? el("div", { class: "ui-view-desc" }, el("code", { text: codeId })) : null,
  ]);
}

const EP_INSPECTION_SOURCES = {
  default_decrypt_all: bl({ en: "decrypt-everything default", ja: "全復号の既定" }),
  known_bypass: bl({ en: "the list of traffic we do not inspect", ja: "検査しない通信の一覧" }),
  authored_bypass: bl({ en: "a rule you wrote", ja: "自分で作ったルール" }),
  cert_pin_materialized: bl({ en: "an app that refuses inspection", ja: "検査を受け付けないアプリ" }),
  static_bypass: bl({ en: "set on this node", ja: "このノードでの設定" }),
};

function epInspectionSourceText(ins) {
  if (!ins) return "";
  if (ins.source === "device_rule") return bl({ en: "a device-specific rule; verify from the source device", ja: "端末別ルールがあります。対象端末から確認してください" });
  let s = EP_INSPECTION_SOURCES[ins.source] || ins.source || "";
  if (ins.detail) s += " (" + ins.detail + ")";
  return s;
}

function epInspectionBadge(ins) {
  if (ins?.decision === "depends_on_device") return uiBadge(bl({en:"Depends on the device",ja:"端末によって異なる"}), "warn");
  if (ins?.decision === "bypass") return uiBadge(bl({en:"Not inspected",ja:"検査しない"}), "warn");
  if (ins?.decision === "inspect") return uiBadge(bl({en:"Inspected",ja:"検査する"}), "ok");
  return uiBadge(bl({en:"Not determined",ja:"未判定"}), "off");
}

// --- "Policy decision check" --------------------------------------------------------------------------------

function renderEffectivePolicyView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "Policy decision check", ja: "ポリシー判定確認" }) }),
      el("p", { class: "ui-view-desc", text: bl({
        en: "Preview TCP/443 for a destination: every rule that competes — your rules and the built-in policies you never authored — in precedence order, with the winner and any rules it overrode, plus whether the connection is decrypted or bypassed, and why.",
        ja: "宛先へのTCP/443通信の判定を確認します。関係するルールを優先度の順に並べ、どれが効いたかを示し、その通信を検査するかどうかと、その理由まで表示します。",
      }) }),
    ]),
  ]));

  // Standing list of every policy the engine evaluates, source-tagged (built-in policies are visible here too).
  const allWrap = el("div", { style: "margin-bottom:18px" });
  content.appendChild(allWrap);
  renderAllPolicies(allWrap);

  // Destination lookup.
  const search = el("input", { class: "ui-input ui-search", type: "search",
    placeholder: bl({ en: "Destination, e.g. accounts.google.com", ja: "宛先(例: accounts.google.com)" }) });
  const explainBtn = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Explain", ja: "説明" }) });
  const result = el("div", {});
  const run = async () => {
    const dest = (search.value || "").trim();
    if (!dest) { search.focus(); return; }
    uiState(result, "loading", bl({ en: "Explaining…", ja: "説明中…" }));
    let r;
    try { r = await apiFetch("GET", "/admin/effective-policy?destination=" + encodeURIComponent(dest)); }
    catch (e) { uiState(result, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: run }); return; }
    if (!r.ok) { uiState(result, "error", "HTTP " + r.status, { label: bl({ en: "Retry", ja: "再試行" }), onClick: run }); return; }
    renderEffectivePolicyResult(result, r.body || {});
  };
  explainBtn.addEventListener("click", run);
  search.addEventListener("keydown", (e) => { if (e.key === "Enter") run(); });
  content.appendChild(el("div", { class: "ui-toolbar" }, [search, explainBtn]));
  content.appendChild(result);
}

function renderEffectivePolicyResult(result, data) {
  result.innerHTML = "";
  const ins = data.inspection || {};

  // Summary: destination + final decision + connection handling.
  const winnerLine = data.winner_policy_id
    ? el("code", { text: data.winner_policy_id, style: "margin-left:8px" })
    : el("span", { class: "ui-view-desc", text: bl({ en: " no rule matched — default deny", ja: " 一致するルールなし — 既定は拒否" }) });
  result.appendChild(el("div", { class: "ui-preview", style: "font-family:inherit;font-size:14px" }, [
    el("div", { class: "ui-view-title", style: "font-size:15px;margin-bottom:8px", text: data.destination || "" }),
    el("div", {}, [el("strong", { text: bl({ en: "Decision: ", ja: "判定: " }) }), epDecisionBadge(data.final_decision), winnerLine]),
    el("div", { style: "margin-top:6px" }, [
      el("strong", { text: bl({ en: "Connection: ", ja: "接続: " }) }),
      epInspectionBadge(ins),
      el("span", { class: "ui-view-desc", style: "margin-left:8px", text: epInspectionSourceText(ins) }),
    ]),
  ]));

  // ★ THE API'S NOTE IS FOR AN API CONSUMER (2026-08-17, read as a customer administrator). It explains the
  // two modes by their internal names — "decrypt_all decrypts every steered HTTPS flow EXCEPT the bypass set;
  // bypass_default decrypts ONLY the allowlist…" — in English, on a Japanese screen. The screen says the same
  // thing in the reader's language and keeps the API's own wording for anything it does not recognise.
  if (data.note) result.appendChild(el("p", { class: "ui-view-desc", text: posturePlainNote(data) }));

  // Precedence-ordered trace.
  const rows = (data.trace || []).map((e) => {
    const tr = el("tr", {}, [
      el("td", {}, epSourceBadge(e.source)),
      el("td", {}, el("code", { text: String(e.priority) })),
      el("td", {}, epDecisionBadge(e.decision)),
      epPolicyCell(e),
      el("td", {}, epStatusBadge(e.status)),
      el("td", {}, epMatchBadge(e)),
    ]);
    if (e.winner) tr.style.background = "var(--panel2)";
    return tr;
  });
  result.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [
      bl({ en: "Source", ja: "出所" }), bl({ en: "Priority", ja: "優先度" }), bl({ en: "Decision", ja: "判定" }),
      bl({ en: "Rule", ja: "ルール" }), bl({ en: "Status", ja: "状態" }), bl({ en: "Match", ja: "一致" }),
    ].map((x) => el("th", { text: x })))),
    el("tbody", {}, rows),
  ]));
}

async function renderAllPolicies(wrap) {
  wrap.innerHTML = "";
  // Reference list only — COLLAPSED by default so the destination verdict above is the focus (the raw
  // precedence dump is not the answer, just the basis). Expanding shows every policy the engine evaluates;
  // multi-pattern rules are grouped to ONE row (a rule with 10 patterns was showing as 10 identical rows).
  const details = el("details", { style: "margin-top:10px" });
  details.appendChild(el("summary", { style: "cursor:pointer;font-weight:600;color:var(--muted,#9ca3af)",
    text: bl({ en: "All policies (reference — precedence order, first match wins)", ja: "全ポリシー(参照用・優先度順、最初の一致が勝つ)" }) }));
  const host = el("div", { style: "margin-top:8px" });
  details.appendChild(host);
  wrap.appendChild(details);
  uiState(host, "loading");
  let data;
  try {
    const r = await apiFetch("GET", "/admin/effective-policies");
    if (!r.ok) { uiState(host, "error", "HTTP " + r.status, { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderAllPolicies(wrap) }); return; }
    data = r.body || {};
  } catch (e) { uiState(host, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderAllPolicies(wrap) }); return; }

  const policies = data.policies || [];
  if (!policies.length) { uiState(host, "empty", bl({ en: "No policies loaded.", ja: "ポリシーがありません。" })); return; }

  // Group per-pattern duplicates: one authored rule with N destination patterns compiles to N engine policies
  // that display identically (same id/priority/decision) — that is why rule-46 showed up ~10 times. Collapse
  // each into ONE row with a pattern count.
  const groups = [], byKey = new Map();
  for (const p of policies) {
    const key = [p.source, p.priority, p.decision, epAuthoredID(p.name) || p.name || p.policy_id].join("|");
    let g = byKey.get(key);
    if (!g) { g = { rep: p, count: 0 }; byKey.set(key, g); groups.push(g); }
    g.count++;
  }
  const rows = groups.map(({ rep: p, count }) => {
    // Status cell: badge + (built-in only) enable/disable. Your rules compile from the rule editor — toggle
    // those in the Access Rules view instead.
    const stCell = el("td", { class: "ui-row-actions" }, epStatusBadge(p.status));
    if (p.source === "built_in") {
      const disabled = p.status === "disabled";
      const tg = el("button", { class: "ui-btn ui-btn-sm", style: "margin-left:8px",
        text: disabled ? bl({ en: "Enable", ja: "有効化" }) : bl({ en: "Disable", ja: "無効化" }) });
      tg.addEventListener("click", async () => {
        tg.disabled = true;
        const resp = await apiFetch("POST", "/admin/policies/" + encodeURIComponent(p.policy_id) + "/status", { status: disabled ? "active" : "disabled" });
        if (!resp.ok) { tg.disabled = false; uiToast((resp.body && (resp.body.error || resp.body.message)) || ("HTTP " + resp.status), "err"); return; }
        uiToast(disabled ? bl({ en: "Policy enabled.", ja: "ポリシーを有効化しました。" }) : bl({ en: "Policy disabled.", ja: "ポリシーを無効化しました。" }), "ok");
        renderAllPolicies(wrap);
      });
      stCell.appendChild(tg);
    } else {
      stCell.appendChild(el("span", { class: "ui-view-desc", style: "margin-left:8px",
        text: bl({ en: "(toggle in Access Rules)", ja: "(アクセスルールで切替)" }) }));
    }
    const polCell = epPolicyCell(p);
    if (count > 1) polCell.appendChild(el("span", { class: "ui-view-desc", style: "margin-left:6px",
      text: bl({ en: "(" + count + " patterns)", ja: "(" + count + " パターン)" }) }));
    return el("tr", {}, [
      el("td", {}, epSourceBadge(p.source)),
      el("td", {}, el("code", { text: String(p.priority) })),
      el("td", {}, epDecisionBadge(p.decision)),
      polCell,
      stCell,
    ]);
  });
  host.innerHTML = "";
  host.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [
      bl({ en: "Source", ja: "出所" }), bl({ en: "Priority", ja: "優先度" }), bl({ en: "Decision", ja: "判定" }),
      bl({ en: "Policy", ja: "ポリシー" }), bl({ en: "Status", ja: "状態" }),
    ].map((x) => el("th", { text: x })))),
    el("tbody", {}, rows),
  ]));
  if (data.note) host.appendChild(el("p", { class: "ui-view-desc", text: data.note }));
}

// --- "Inspection Settings" ---------------------------------------------------------------------------------

function renderInspectionPostureView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "Inspection Settings", ja: "傍受設定" }) }),
      el("p", { class: "ui-view-desc", text: bl({
        // ★ Written for the reader, not from the model. It said "every steered HTTPS connection except the
        // trusted bypass list" and "still steered and policy-checked" — steer, bypass list and policy-check
        // are all our words, on the screen that decides whether a customer's traffic is read.
        en: "Whether the contents of your people's traffic are looked at. Anything listed as not inspected still goes through this service and is still allowed or blocked by your rules — only its contents are left unread.",
        ja: "社内の人の通信の中身を見るかどうかの設定です。「検査しない」としたものも、この経路は通り、ルールによる許可・遮断も受けます。読まれないのは中身だけです。",
      }) }),
    ]),
  ]));
  const result = el("div", {});
  content.appendChild(el("button",{class:"ui-btn",text:bl({en:"Reload",ja:"再読込"}),onClick:()=>loadInspectionPosture(result)}));
  content.appendChild(result);
  loadInspectionPosture(result);
}

async function loadInspectionPosture(result) {
  if(result.__posturePending)return;
  uiState(result, "loading");
  const current = freshRender(result);
  let data;
  try {
    const [r,tenant] = await Promise.all([apiFetch("GET", "/admin/inspection-posture"),apiFetch("GET","/admin/tenant")]);
 if(!tenant?.ok)throw new Error("Organization unavailable");
    if (!r.ok) { if (!current()) return; uiState(result, "error", "HTTP " + r.status, { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => loadInspectionPosture(result) }); return; }
    data = validatedInspectionPosture(r.body,tenant.body);
  } catch (e) { if (!current()) return; uiState(result, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => loadInspectionPosture(result) }); return; }
  if (!current()) return;
  result.innerHTML = "";
  result.__postureData=data;
  result.appendChild(el("p",{class:"ui-callout",text:bl({en:"These defaults apply to the whole deployment. Only the deployment operator can change them outside a customer context.",ja:"この既定値は配備全体に適用されます。顧客の操作画面を離れた運営管理者だけが変更できます。"})}));
  if(!data.runtime_available)result.appendChild(el("p",{class:"ui-callout ui-callout-warn",text:bl({en:"This server has no interception engine. The saved defaults are shown; live traffic coverage is unavailable here.",ja:"このサーバーには傍受エンジンがありません。保存された既定値を表示しています。実通信の検査範囲はここでは確認できません。"})}));


  // Safety warnings (e.g. allowlist-only with no sign-in decrypted -> tenant restriction at risk).
  (data.warnings || []).forEach((w) => result.appendChild(el("div", { style: "margin:6px 0;display:flex;gap:8px;align-items:flex-start" }, [
    uiBadge(bl({ en: "Warning", ja: "警告" }), "warn"), el("span", { text: w }),
  ])));

  const modeLabel = {
    decrypt_all: bl({ en: "Inspect everything (default)", ja: "すべて検査(既定)" }),
    bypass_default: bl({ en: "Inspect only what I list", ja: "挙げたものだけ検査" }),
  }[data.default_mode] || data.default_mode || "—";
  const bypassDefault = data.default_mode === "bypass_default";

  // Current mode summary.
  const decryptedHosts = data.intercept_hosts || [];
  result.appendChild(el("div", { class: "ui-preview", style: "font-family:inherit;font-size:14px" }, [
    el("div", { class: "ui-field-label", style: "margin-bottom:6px", text: data.runtime_available ? bl({ en: "What is inspected right now", ja: "いま検査しているもの" }) : bl({en:"Configured inspection default",ja:"保存された検査の既定値"}) }),
    el("div", {}, uiBadge(modeLabel, data.default_mode === "decrypt_all" ? "warn" : "ok")),
    bypassDefault ? el("div", { class: "ui-view-desc", style: "margin-top:8px" }, [
      el("span", { text: bl({ en: "Decrypted hosts: ", ja: "復号するホスト: " }) }),
      decryptedHosts.length ? el("code", { text: decryptedHosts.join(", ") }) : el("span", { text: bl({ en: "none", ja: "なし" }) }),
    ]) : null,
    el("div", { class: "ui-view-desc", style: "margin-top:6px",
      text: bl({ en: "Explicit bypass patterns: ", ja: "明示的な検査除外パターン数: " }) + (data.effective_bypass || []).length }),
    data.device_scoped ? el("div", { class: "ui-view-desc", text: bl({en:"Device-specific inspection rules also apply. The host lists above show settings shared by all source devices.",ja:"端末別の検査ルールも適用されます。上のホスト一覧は全送信元端末に共通する設定です。"}) }) : null,
  ]));

  // Mode switch.
  const mkModeBtn = (mode, label) => {
    const b = el("button", { class: "ui-btn", style: "margin-right:8px", text: label });
    b.disabled = !data.configurable || data.default_mode === mode;
    b.addEventListener("click", () => inspectionPostureMutation(result, async () => {
      // Footgun guard: switching to allowlist-only with an EMPTY allowlist decrypts nothing — all interception,
      // tenant restriction and DLP turn off until hosts / sign-in groups are added.
      if (mode === "bypass_default") {
        const emptyAllowlist = !((data.decrypt_allowlist_groups || []).length) && !((data.decrypt_allowlist_hosts || []).length);
        if (emptyAllowlist) {
          const ok = await uiConfirm({
            title: bl({ en: "Switch with nothing listed?", ja: "何も挙げないまま切り替えますか?" }),
            body: bl({
              en: "Nothing will be decrypted — all interception, tenant restriction and data-loss prevention turn OFF until you add hosts or sign-in presets below. Tip: pick the sign-in (and AI) presets first, then switch.",
              ja: "何も復号されず、下で サインイン(と AI)の定型セットやホストを追加するまで、全傍受・テナント制限・情報漏えい対策が OFF になります。ヒント: 先に サインイン/AI の定型セットを選んでから切り替えてください。",
            }),
            confirmLabel: bl({ en: "Switch anyway", ja: "それでも切替" }), danger: true,
          });
          if (!ok) return;
        }
      }
      return await saveInspectionPatch(result,data,{mode},bl({en:"Inspection mode changed.",ja:"傍受モードを変更しました。"}));
    }));
    return b;
  };
  result.appendChild(el("div", { class: "ui-toolbar" }, [
    mkModeBtn("decrypt_all", bl({ en: "Inspect everything", ja: "すべて検査" })),
    mkModeBtn("bypass_default", bl({ en: "Inspect only what I list", ja: "挙げたものだけ検査" })),
  ]));

  // Decrypt allowlist editor — always editable (saved even under decrypt-everything; takes effect once you
  // switch to allowlist-only).
  result.appendChild(buildDecryptAllowlistEditor(data, bypassDefault, result));

  // Trusted bypass list on/off.
  const enabled = !!data.known_bypass_enabled;
  const tbtn = el("button", { class: "ui-btn",
    text: enabled ? bl({ en: "Inspect the operating-system traffic too", ja: "OS の通信も検査する" })
                  : bl({ en: "Stop inspecting the operating-system traffic", ja: "OS の通信は検査しない" }) });
  tbtn.disabled=!data.configurable;
  tbtn.addEventListener("click",()=>inspectionPostureMutation(result,()=>saveInspectionPatch(result,data,{known_bypass_enabled:!enabled},bl({en:"Updated.",ja:"更新しました。"}))));
  result.appendChild(el("div", { class: "ui-toolbar" }, [
    tbtn,
    uiBadge(enabled ? bl({ en: "OS bypass enabled", ja: "OS の検査除外: 有効" }) : bl({ en: "OS bypass disabled", ja: "OS の検査除外: 無効" }), enabled ? "ok" : "warn"),
  ]));

  // SaaS bypass groups (authored as egress rules).
  if ((data.saas_bypass_groups || []).length) {
    try { const section=await buildSaasBypassSection(data,result);if(!current() || result.isConnected===false)return;result.appendChild(section); }
    catch(e){if(!current() || result.isConnected===false)return;const failure=el("div",{});uiState(failure,"error",bl({en:"Could not load service inspection rules. Their inspection state is unknown.",ja:"サービスの検査ルールを読み込めません。検査状態は不明です。"}),{label:bl({en:"Retry",ja:"再試行"}),onClick:()=>loadInspectionPosture(result)});result.appendChild(failure);}

  }

  // ★ THE API'S NOTE IS FOR AN API CONSUMER (2026-08-17, read as a customer administrator). It explains the
  // two modes by their internal names — "decrypt_all decrypts every steered HTTPS flow EXCEPT the bypass set;
  // bypass_default decrypts ONLY the allowlist…" — in English, on a Japanese screen. The screen says the same
  // thing in the reader's language and keeps the API's own wording for anything it does not recognise.
  if (data.note) result.appendChild(el("p", { class: "ui-view-desc", text: posturePlainNote(data) }));

  // The built-in "trusted bypass groups" listing lives on its own page (Built-in Bypass List /
  // 組込バイパスリスト); it is NOT duplicated here — this page only sets the decrypt posture + the on/off toggle.
}

function buildDecryptAllowlistEditor(data, bypassDefault, result) {
  const body = [];
  body.push(el("div", { class: "ui-field-label", text: bl({ en: "What to inspect when 'inspect only what I list' is on", ja: "「挙げたものだけ検査」のときに検査するもの" }) }));
  if (!bypassDefault) {
    body.push(el("p", { class: "ui-view-desc", text: bl({
      en: "While everything is inspected this list does nothing, but it is saved and takes effect the moment you switch.",
      ja: "すべて検査している間はこの一覧は効きませんが、保存されており、切り替えた時点で効きはじめます。",
    }) }));
  }

  // SaaS decrypt presets grouped by category. Selecting keeps these decrypted even under allowlist-only
  // (sign-in preserves tenant restriction; AI/collaboration preserve data-loss prevention).
  body.push(el("p", { class: "ui-view-desc", text: bl({
    en: "Keep-decrypted presets (sign-in = tenant restriction; AI = data-loss prevention / agent governance):",
    ja: "検査を続けるもの(サインイン: 会社アカウントの制限のため / AI: 送信内容の確認のため):",
  }) }));
  const catLabels = { sign_in: bl({ en: "Sign-in", ja: "サインイン" }), ai: bl({ en: "AI", ja: "AI" }), collaboration: bl({ en: "Collaboration", ja: "コラボ" }) };
  const groupBoxes = [];
  const checklist = el("div", { class: "ui-checklist" });
  let anyGroups = false;
  ["sign_in", "ai", "collaboration"].forEach((cat) => {
    const groups = (data.auth_decrypt_groups || []).filter((g) => (g.category || "sign_in") === cat);
    if (!groups.length) return;
    anyGroups = true;
    checklist.appendChild(el("div", { class: "ui-field-label", style: "margin:6px 0 2px;font-size:12px", text: catLabels[cat] || cat }));
    groups.forEach((g) => {
      const cb = el("input", { type: "checkbox" });
      cb.checked = !!g.selected;cb.disabled=!data.configurable;
      cb.dataset.group = g.name;
      groupBoxes.push(cb);
      // Same words as the list below it — the two are the same groups, and reading one name here and another
      // there is how a reader concludes they are different things.
      const words = bypassGroupWords(g.name);
      checklist.appendChild(el("label", { class: "ui-checkrow" }, [
        cb,
        el("strong", { text: words ? bl(words.label) : g.name }),
        el("span", { class: "ui-view-desc", title: g.name, text: words ? bl(words.what) : (g.description || "") }),
      ]));
    });
  });
  if (anyGroups) body.push(checklist);

  // Explicit hosts.
  const hostsF = uiField({ name: "decrypt_hosts", type: "textarea",
    label: bl({ en: "Other destinations to inspect (one per line; *.example.com covers everything under it)", ja: "ほかに検査する宛先(1行に1つ。*.example.com のように書くと配下すべて)" }),
    value: (data.decrypt_allowlist_hosts || []).join("\n") });
  body.push(hostsF.el);

  const apply = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Save this list", ja: "この一覧を保存" }) });
  apply.disabled=!data.configurable;
  hostsF.el.querySelectorAll("input,textarea").forEach(e=>e.disabled=!data.configurable);
  apply.addEventListener("click",()=>inspectionPostureMutation(result,async()=>{
    const hosts=hostsF.get().split("\n").map(s=>s.trim()).filter(Boolean),groups=groupBoxes.filter(c=>c.checked).map(c=>c.dataset.group);
    return await saveInspectionPatch(result,data,{decrypt_allowlist_hosts:hosts,decrypt_allowlist_groups:groups},bl({en:"Saved.",ja:"保存しました。"}));
  }));
  body.push(el("div", { class: "ui-toolbar" }, apply));

  return el("div", { class: "ui-preview", style: "font-family:inherit;font-size:14px;margin-top:12px" }, body);
}

async function buildSaasBypassSection(data, result) {
  // Toggling a group AUTHORS a real Egress bypass rule (Any → group ⇒ allow, not decrypted), visible and
  // editable in the Access Rules / Egress view — the rule is the single source of truth. A legacy posture
  // selection remains cleanup-only and never grants tenant bypass.
  const er = await apiFetch("GET", "/admin/rules?plane=egress");
  if(!er?.ok || !Array.isArray(er.body) || er.body.some(r=>!r || typeof r.id!=="string" || !Array.isArray(r.destination) || r.destination.some(d=>typeof d!=="string") || !r.action || (r.tenant_id && r.tenant_id!==data.tenant_id)))throw new Error("Invalid service rules");
 const egressRules=er.body;
  const bypassRuleFor = (name) => egressRules.filter((r) =>
    (r.destination || []).indexOf("bi-grp-" + name) !== -1 && r.action && r.action.inspection === "bypass" && r.status === "active");
  const postureSelected = (data.saas_bypass_groups || []).filter((g) => g.selected).map((g) => g.name);

  const body = [];
  body.push(el("div", { class: "ui-field-label", text: bl({ en: "Services you can leave uninspected", ja: "検査しないでおけるサービス" }) }));
  body.push(el("p", { class: "ui-view-desc", text: bl({
    en: "Marking one as not inspected writes a rule for that service. Removing its bypass does not guarantee inspection: the default, allowlist and other exclusions still apply. You can also edit the rule on the Internet Access screen.",
    ja: "「検査しない」にすると、そのサービスの検査除外ルールができます。除外を消した後も、既定値・検査対象の一覧・他の除外設定に従います。ルールはインターネットアクセス画面でも編集できます。",
  }) }));

  (data.saas_bypass_groups || []).forEach((g) => {
    const rules = bypassRuleFor(g.name);
    const on = rules.length > 0;
    const tog = el("button", { class: "ui-btn ui-btn-sm",
      text: on ? bl({ en: "Inspect it", ja: "検査する" }) : bl({ en: "Do not inspect it", ja: "検査しない" }) });
    const state = on
      ? uiBadge(bl({ en: "Bypass rule saved", ja: "検査除外ルールあり" }), "warn")
      : uiBadge(bl({ en: "No service bypass", ja: "サービスの検査除外なし" }), "ok");
    tog.disabled=!data.can_manage_rules;
    tog.addEventListener("click",()=>inspectionPostureMutation(result,async()=>{
      if(on){
        const confirmed=await uiConfirm({title:bl({en:"Inspect this service again?",ja:"このサービスを再び検査しますか？"}),body:bl({en:"The matching bypass rules will be removed. Review the Internet Access page if a rule also covers other destinations.",ja:"該当する検査除外ルールを削除します。他の宛先も含む場合はインターネットアクセス画面で確認してください。"}),confirmLabel:bl({en:"Inspect it",ja:"検査する"})});if(!confirmed || result.isConnected===false)return;
        if(rules.some(r=>r.destination.length!==1))throw new Error(bl({en:"A bypass rule also covers other destinations. Edit it on the Internet Access page.",ja:"他の宛先も含む検査除外ルールがあります。インターネットアクセス画面で編集してください。"}));
        for(const rule of rules){const response=await apiFetch("DELETE","/admin/rules/"+encodeURIComponent(rule.id));if(!response?.ok)throw new Error(postureHTTPError(response));}
      }else{
        const response=await apiFetch("POST","/admin/rules",{plane:"egress",priority:60,name:"Bypass: "+g.name,source:["*"],destination:["bi-grp-"+g.name],action:{access:"allow",inspection:"bypass"},status:"active"});if(!response?.ok)throw new Error(postureHTTPError(response));
      }
      // Re-read the authored rules: a 2xx or partial multi-write result is not proof of the desired state.
      const verify=await apiFetch("GET","/admin/rules?plane=egress");if(!verify?.ok || !Array.isArray(verify.body))throw new Error(postureUnknown());
      const bypass=verify.body.some(r=>r && r.status==="active" && r.action?.inspection==="bypass" && r.destination?.includes("bi-grp-"+g.name));if(bypass===on)throw new Error(postureUnknown());
      uiToast(bl({en:"Updated.",ja:"更新しました。"}),"ok");return true;
    }));
    let legacy = null;
    if (g.selected) {
      const clear = el("button", {class:"ui-btn ui-btn-sm", text:bl({en:"Clear older selection",ja:"以前の選択を削除"})});
      clear.disabled = !data.configurable;
      clear.addEventListener("click",()=>inspectionPostureMutation(result,()=>saveInspectionPatch(result,data,
        {bypass_groups:postureSelected.filter(n=>n!==g.name)},bl({en:"Older selection cleared. Saved rules were kept.",ja:"以前の選択を削除しました。保存済みルールは維持されています。"}))));
      legacy = el("div", {class:"ui-callout ui-callout-warn"},[
        el("span",{text:bl({en:"An older deployment selection is retained for review. It does not grant a bypass. Save a rule for this organization if needed. Clearing it leaves saved rules unchanged.",ja:"配備全体の以前の選択が残っています。この選択だけでは検査を除外しません。必要ならこの組織のルールを保存してください。以前の選択を削除しても保存済みルールは変わりません。"})}), clear]);
    }
    // ★ THE NAME A CUSTOMER READS, NOT OUR IDENTIFIER, AND NOT ENGLISH PROSE IN A JAPANESE CONSOLE
    // (2026-08-17, read as a customer administrator). This printed the group key in monospace —
    // google_auth, okta_auth, salesforce_auth — beside an English sentence from the API. The API text
    // stays as the fallback for a group this screen does not know, so a row is never blank.
    const words = bypassGroupWords(g.name);
    body.push(el("div", {class:"saas-bypass-group"}, [el("div", { style: "display:flex;align-items:center;gap:8px;margin:6px 0" }, [
      tog, state,
      el("strong", { text: words ? bl(words.label) : g.name }),
      el("span", { class: "ui-view-desc", title: g.name, text: words ? bl(words.what) : (g.description || "") }),
    ]), legacy]));
  });

  return el("div", { class: "ui-preview", style: "font-family:inherit;font-size:14px;margin-top:12px" }, body);
}


// The bypass groups in the customer's own words. Each says WHAT IT IS and, where it matters, what turning the
// bypass on costs — because "bypass" means "we stop looking", and the reason to look is different per group.
const BYPASS_GROUP_WORDS = {
  m365_auth: { label: { en: "Microsoft 365 sign-in", ja: "Microsoft 365 のサインイン" },
               what: { en: "Inspect it to keep people signing in to your company's Microsoft 365 only.", ja: "検査すると、自社の Microsoft 365 以外にはサインインできないようにできます。" } },
  google_auth: { label: { en: "Google Workspace sign-in", ja: "Google Workspace のサインイン" },
                 what: { en: "Inspect it to keep people signing in to your company's Google accounts only.", ja: "検査すると、自社の Google アカウント以外にはサインインできないようにできます。" } },
  okta_auth: { label: { en: "Okta sign-in", ja: "Okta のサインイン" },
               what: { en: "Inspect it to apply your session and account controls.", ja: "検査すると、セッションやアカウントの制御を効かせられます。" } },
  salesforce_auth: { label: { en: "Salesforce sign-in", ja: "Salesforce のサインイン" },
                     what: { en: "Inspect it to apply your login and session controls.", ja: "検査すると、ログインとセッションの制御を効かせられます。" } },
  onelogin_auth: { label: { en: "OneLogin sign-in", ja: "OneLogin のサインイン" }, what: { en: "", ja: "" } },
  ping_auth: { label: { en: "Ping Identity sign-in", ja: "Ping Identity のサインイン" }, what: { en: "", ja: "" } },
  github_auth: { label: { en: "GitHub sign-in", ja: "GitHub のサインイン" }, what: { en: "", ja: "" } },
  openai: { label: { en: "ChatGPT", ja: "ChatGPT" },
            what: { en: "Inspect it to see what leaves your tenant in a prompt.", ja: "検査すると、プロンプトで社外に出ていく内容を確認できます。" } },
  anthropic: { label: { en: "Claude", ja: "Claude" },
               what: { en: "Inspect it to see what leaves your tenant in a prompt.", ja: "検査すると、プロンプトで社外に出ていく内容を確認できます。" } },
  google_gemini: { label: { en: "Gemini", ja: "Gemini" }, what: { en: "", ja: "" } },
  microsoft_copilot: { label: { en: "Microsoft Copilot", ja: "Microsoft Copilot" }, what: { en: "", ja: "" } },
  github_copilot: { label: { en: "GitHub Copilot", ja: "GitHub Copilot" }, what: { en: "", ja: "" } },
  slack: { label: { en: "Slack", ja: "Slack" },
           what: { en: "Inspect it to see files and messages leaving your tenant.", ja: "検査すると、社外に出ていくファイルやメッセージを確認できます。" } },
  zoom: { label: { en: "Zoom", ja: "Zoom" }, what: { en: "", ja: "" } },
  atlassian: { label: { en: "Atlassian (Jira / Confluence)", ja: "Atlassian (Jira / Confluence)" }, what: { en: "", ja: "" } },
  box: { label: { en: "Box", ja: "Box" }, what: { en: "", ja: "" } },
  dropbox: { label: { en: "Dropbox", ja: "Dropbox" }, what: { en: "", ja: "" } },
  notion: { label: { en: "Notion", ja: "Notion" }, what: { en: "", ja: "" } },
  m365_optimize: { label: { en: "Microsoft 365 media and sync", ja: "Microsoft 365 の通話・同期" },
                   what: { en: "Heavy traffic that gains little from inspection.", ja: "検査してもほとんど得るものがない、重い通信です。" } },
  google_optimize: { label: { en: "Google media and sync", ja: "Google の通話・同期" },
                     what: { en: "Heavy traffic that gains little from inspection.", ja: "検査してもほとんど得るものがない、重い通信です。" } },
  slack_media: { label: { en: "Slack calls", ja: "Slack の通話" }, what: { en: "", ja: "" } },
  zoom_media: { label: { en: "Zoom calls", ja: "Zoom の通話" }, what: { en: "", ja: "" } },
  // The rest are product names, which are the same in both languages. They are listed rather than left to
  // fall through so that no row shows an identifier: a reader who sees "huggingface" in monospace has been
  // handed our catalogue key, and one who sees it beside "Hugging Face" has been handed it twice.
  perplexity: { label: { en: "Perplexity", ja: "Perplexity" }, what: { en: "", ja: "" } },
  mistral: { label: { en: "Mistral", ja: "Mistral" }, what: { en: "", ja: "" } },
  cohere: { label: { en: "Cohere", ja: "Cohere" }, what: { en: "", ja: "" } },
  huggingface: { label: { en: "Hugging Face", ja: "Hugging Face" }, what: { en: "", ja: "" } },
  deepseek: { label: { en: "DeepSeek", ja: "DeepSeek" }, what: { en: "", ja: "" } },
  xai_grok: { label: { en: "Grok (xAI)", ja: "Grok (xAI)" }, what: { en: "", ja: "" } },
  poe: { label: { en: "Poe", ja: "Poe" }, what: { en: "", ja: "" } },
  meta_ai: { label: { en: "Meta AI", ja: "Meta AI" }, what: { en: "", ja: "" } },
  alibaba_qwen: { label: { en: "Qwen (Alibaba)", ja: "Qwen (Alibaba)" }, what: { en: "", ja: "" } },
  moonshot_kimi: { label: { en: "Kimi (Moonshot)", ja: "Kimi (Moonshot)" }, what: { en: "", ja: "" } },
  bytedance_doubao: { label: { en: "Doubao (ByteDance)", ja: "Doubao (ByteDance)" }, what: { en: "", ja: "" } },
  felo: { label: { en: "Felo", ja: "Felo" }, what: { en: "", ja: "" } },
};

function bypassGroupWords(name) {
  const words = BYPASS_GROUP_WORDS[String(name || "").trim()];
  if (!words) return null;
  // A group we know by name but have nothing extra to say about still gets its readable name.
  return { label: words.label, what: bl(words.what) ? words.what : { en: "", ja: "" } };
}


// posturePlainNote states the current posture in the reader's own words. Falls back to the API's note when the
// mode is one this screen does not know — an unexplained screen is worse than an awkward sentence.
function posturePlainNote(data) {
  const mode = String((data && (data.default_mode || data.mode)) || "").trim();
  if (mode === "decrypt_all") {
    return bl({
      en: "Everything your people reach is inspected, except what is listed below as not inspected.",
      ja: "社内の人が開くものはすべて検査します。下で「検査しない」としたものだけが例外です。" });
  }
  if (mode === "bypass_default") {
    return bl({
      en: "Only what is listed below is inspected; everything else passes without being looked at. Keep the sign-in services inspected, or the limit on which company accounts people may use stops working.",
      ja: "下に挙げたものだけを検査し、それ以外は中身を見ずに通します。サインインのサービスは検査したままにしてください。外すと、どの会社アカウントを使えるかの制限が効かなくなります。" });
  }
  return (data && data.note) || "";
}

function postureUnknown(){return bl({en:"The outcome is unconfirmed. Reload to check the current settings before retrying.",ja:"結果を確認できません。再読込して現在の設定を確認してから再試行してください。"})}
function postureHTTPError(r){return typeof r?.body?.error==="string"?r.body.error:postureUnknown()}
function validatedInspectionPosture(body,tenant){
 if(!body || typeof body!=="object" || !tenant || typeof tenant.tenant_id!=="string" || !tenant.tenant_id || body.tenant_id!==tenant.tenant_id || body.scope!=="deployment" || !["decrypt_all","bypass_default"].includes(body.default_mode))throw new Error("Invalid inspection settings or organization response");
 const data={...body};for(const key of ["configurable","runtime_available","can_manage_rules","known_bypass_enabled"]){if(typeof data[key]!=="boolean")throw new Error("Invalid inspection capability")}
 if(data.device_scoped!==undefined && typeof data.device_scoped!=="boolean")throw new Error("Invalid device inspection scope");
 for(const key of ["decrypt_allowlist_hosts","decrypt_allowlist_groups","bypass_groups","intercept_hosts","effective_bypass","warnings"]){if(key!=="warnings" && !Object.hasOwn(data,key))throw new Error("Incomplete inspection list");if(data[key]==null)data[key]=[];if(!Array.isArray(data[key]) || data[key].some(v=>typeof v!=="string"))throw new Error("Invalid inspection list")}
 for(const key of ["auth_decrypt_groups","saas_bypass_groups"]){if(!Array.isArray(data[key]) || data[key].some(g=>!g || typeof g.name!=="string" || !g.name || typeof g.selected!=="boolean" || !Array.isArray(g.patterns) || g.patterns.some(p=>typeof p!=="string")))throw new Error("Invalid inspection presets")}
 return data;
}
function validatedInspectionMutation(r,before,patch){
 if(!r?.ok)throw new Error(postureHTTPError(r));if(r.status!==200)throw new Error(postureUnknown());
 const saved=validatedInspectionPosture(r.body,{tenant_id:before.tenant_id});
 for(const [key,value]of Object.entries(patch)){
  const actual=saved[key==="mode"?"default_mode":key];
  if(Array.isArray(value)){const expected=[...new Set(value.map(v=>key==="decrypt_allowlist_hosts"?v.trim().toLowerCase():v.trim()).filter(Boolean))];if(JSON.stringify(expected)!==JSON.stringify(actual))throw new Error(postureUnknown())}
  else if(value!==actual)throw new Error(postureUnknown());
 }
 return saved;
}
async function saveInspectionPatch(result,data,patch,message){
 if(result.isConnected===false)return false;
 const r=await apiFetch("POST","/admin/inspection-posture",patch);validatedInspectionMutation(r,data,patch);if(result.isConnected!==false)uiToast(message,"ok");return true;
}
async function inspectionPostureMutation(result,operation){
 if(result.__posturePending || result.isConnected===false)return;result.__posturePending=true;
 const controls=[...result.querySelectorAll("button,input,textarea")].map(e=>[e,e.disabled]);controls.forEach(([e])=>e.disabled=true);
 result.querySelectorAll(".posture-error").forEach(e=>e.remove());let reload=false;
 try{reload=await operation()===true}catch(e){if(result.isConnected!==false)result.prepend(el("p",{class:"posture-error ui-callout ui-callout-warn",role:"alert",text:(e.message||String(e))+" "+postureUnknown()}))}
 finally{result.__posturePending=false;controls.forEach(([e,disabled])=>e.disabled=disabled)}
 if(reload && result.isConnected!==false)await loadInspectionPosture(result);
}
