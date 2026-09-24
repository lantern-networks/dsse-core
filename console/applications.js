"use strict";

// applications.js — "Applications" view on the shared ui.js primitives (product-quality pattern, see
// docs/console_ux_design_direction.md): list with search + filters + badges + states, and a typed "Add
// application" form (no JSON). Replaces the raw-JSON applications card.
// Backend: GET /admin/applications -> {applications:[…]}, POST /admin/applications {application_id,name,
// application_type,status,application_sensitivity}.

let _appsState = { search: "", type: "all" };

function renderApplicationsView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "Applications", ja: "アプリケーション" }) }),
      el("p", { class: "ui-view-desc", text: bl({ en: "Your internal apps and SaaS apps — the things your access rules point at.", ja: "社内アプリと SaaS アプリ — アクセスルールが指す対象です。" }) }),
    ]),
    el("div", { class: "ui-row-actions" }, [
      el("button", { class: "ui-btn", text: bl({ en: "+ Publish private app", ja: "+ 社内アプリを公開" }), onClick: () => openPublishWizard(content) }),
      el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "+ Add application", ja: "+ アプリを追加" }), onClick: () => openAppForm(content) }),
    ]),
  ]));
  const search = el("input", { class: "ui-input ui-search", type: "search", placeholder: bl({ en: "Search applications…", ja: "アプリを検索…" }) });
  search.value = _appsState.search;
  search.addEventListener("input", () => { _appsState.search = search.value; renderAppList(host); });
  const typeF = uiField({ name: "type", type: "select", value: _appsState.type, options: [
    { value: "all", label: bl({ en: "All types", ja: "全種別" }) },
    { value: "private_app", label: bl({ en: "Internal app", ja: "社内アプリ" }) },
    { value: "saas", label: bl({ en: "SaaS app", ja: "SaaS アプリ" }) },
  ] });
  typeF.el.style.marginBottom = "0";
  typeF.el.querySelector("select").addEventListener("change", () => { _appsState.type = typeF.get(); renderAppList(host); });
  content.appendChild(el("div", { class: "ui-toolbar" }, [search, typeF.el, el("span", { class: "ui-spacer" }),
    el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Reload", ja: "再読込" }), onClick: () => renderAppList(host) })]));
  const host = el("div", {});
  content.appendChild(host);
  renderAppList(host);
}

function appTypeLabel(t) {
  return t === "saas" ? bl({ en: "SaaS app", ja: "SaaS アプリ" }) : t === "private_app" ? bl({ en: "Internal app", ja: "社内アプリ" }) : (t || "—");
}

async function renderAppList(host) {
  uiState(host, "loading");
  const current = freshRender(host);
  let apps;
  try {
    const r = await apiFetch("GET", "/admin/applications");
    if (!r.ok) { if (!current()) return; uiState(host, "error", "HTTP " + r.status, { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderAppList(host) }); return; }
    apps = (r.body && r.body.applications) || [];
  } catch (e) { if (!current()) return; uiState(host, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderAppList(host) }); return; }
  const q = _appsState.search.trim().toLowerCase();
  const filtered = apps.filter((a) => {
    if (_appsState.type !== "all" && a.application_type !== _appsState.type) return false;
    if (q && !((a.name || "").toLowerCase().includes(q) || (a.application_id || "").toLowerCase().includes(q))) return false;
    return true;
  });
  if (apps.length === 0) { if (!current()) return; uiState(host, "empty", bl({ en: "No applications yet. Add one so your rules can refer to it.", ja: "アプリがありません。ルールから参照できるよう追加してください。" })); return; }
  if (filtered.length === 0) { if (!current()) return; uiState(host, "empty", bl({ en: "No applications match your search.", ja: "検索に一致するアプリがありません。" })); return; }
  const rows = filtered.sort((a, b) => (a.name || "").localeCompare(b.name || "")).map((a) => {
    const isPrivate = a.application_type === "private_app";
    const publishedBadge = a.published
      ? uiBadge(bl({ en: "Published", ja: "公開中" }), "ok")
      : (isPrivate ? uiBadge(bl({ en: "Not published", ja: "未公開" }), "off") : el("span", { text: "—" }));
    const actions = [el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Edit", ja: "編集" }), onClick: () => openAppForm(document.getElementById("content"), a) })];
    if (isPrivate) {
      actions.push(el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Test reachability", ja: "到達性テスト" }), onClick: () => testReachability(a) }));
      if (a.published) {
        actions.push(el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Unpublish", ja: "公開停止" }), onClick: () => unpublishApp(a) }));
      } else {
        actions.push(el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Publish", ja: "公開" }), onClick: () => openPublishWizard(document.getElementById("content"), a) }));
      }
    }
    actions.push(el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Delete", ja: "削除" }), onClick: () => deleteApp(a) }));
    return el("tr", {}, [
      el("td", {}, [el("strong", { text: a.name || a.application_id }), el("div", { class: "ui-view-desc" }, el("code", { text: a.application_id }))]),
      el("td", { text: appTypeLabel(a.application_type) }),
      el("td", {}, uiBadge(a.application_sensitivity || "normal", a.application_sensitivity === "high" ? "warn" : "off")),
      el("td", {}, publishedBadge),
      el("td", {}, uiBadge(a.status === "active" ? bl({ en: "Active", ja: "有効" }) : (a.status || "—"), a.status === "active" ? "ok" : "off")),
      el("td", { class: "ui-row-actions" }, actions),
    ]);
  });
  if (!current()) return;
  host.innerHTML = "";
  host.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [
      el("th", { text: bl({ en: "Application", ja: "アプリ" }) }),
      el("th", { text: bl({ en: "Type", ja: "種別" }) }),
      el("th", { text: bl({ en: "Sensitivity", ja: "重要度" }) }),
      el("th", { text: bl({ en: "Published", ja: "公開" }) }),
      el("th", { text: bl({ en: "Status", ja: "状態" }) }),
      el("th", { class: "ui-row-actions", text: bl({ en: "Actions", ja: "操作" }) }),
    ])),
    el("tbody", {}, rows),
  ]));
  host.appendChild(el("p", { class: "ui-view-desc", text: bl({ en: "Showing ", ja: "表示 " }) + filtered.length + " / " + apps.length }));
}

// The catalog POST replaces an entry. Preserve fields outside this form from a
// fresh detail read instead of resetting routing, classification and SaaS metadata.
async function appSaveBase(id, editing) {
  const r = await apiFetch("GET", "/admin/applications/" + encodeURIComponent(id));
  if (r.status === 404 && !editing) return {};
  if (!r.ok) throw new Error("HTTP " + r.status);
  const entry = r.body;
  if (!entry || typeof entry !== "object" || Array.isArray(entry) || entry.application_id !== id ||
      !["private_app", "saas"].includes(entry.application_type)) {
    throw new Error("Invalid application response");
  }
  const strings = ["tenant_id", "name", "service_family", "protocol", "destination_role",
    "application_sensitivity", "route_ref", "saas_provider", "saas_category", "saas_risk_tier", "status"];
  if (strings.some(key => typeof entry[key] !== "string") ||
      ["domain_pattern_count", "sni_pattern_count"].some(key => !Number.isSafeInteger(entry[key]) || entry[key] < 0) ||
      !Object.hasOwn(entry, "tags") || (entry.tags !== null && (!Array.isArray(entry.tags) || entry.tags.some(tag => typeof tag !== "string"))) ||
      !Object.hasOwn(entry, "updated_at") || (entry.updated_at !== null && typeof entry.updated_at !== "string")) {
    throw new Error("Invalid application response");
  }
  return entry;
}

function appOptionsWithCurrent(options, value) {
  return value && !options.some(o => o.value === value)
    ? options.concat([{ value, label: value }]) : options;
}

function openAppForm(content, existing) {
  existing = existing || null;
  const idF = uiField({ name: "id", label: bl({ en: "Application ID", ja: "アプリ ID" }), required: true, value: existing ? existing.application_id : "",
    placeholder: "wiki", hint: bl({ en: "A short unique key. Editing an existing ID updates that application.", ja: "短い一意キー。既存 ID を入れると更新になります。" }),
    validate: (v) => (/\s/.test(v) ? bl({ en: "No spaces allowed.", ja: "空白は使えません。" }) : "") });
  if (existing) idF.el.querySelector("input").setAttribute("readonly", "true");
  const nameF = uiField({ name: "name", label: bl({ en: "Display name", ja: "表示名" }), required: true, value: existing ? existing.name : "", placeholder: bl({ en: "Wiki", ja: "社内 Wiki" }) });
  const typeF = uiField({ name: "type", label: bl({ en: "Type", ja: "種別" }), type: "select", value: existing ? existing.application_type : "private_app", options: [
    { value: "private_app", label: bl({ en: "Internal app", ja: "社内アプリ" }) },
    { value: "saas", label: bl({ en: "SaaS app", ja: "SaaS アプリ" }) },
  ] });
  const sensF = uiField({ name: "sensitivity", label: bl({ en: "Sensitivity", ja: "重要度" }), type: "select", value: existing ? existing.application_sensitivity : "normal", options: appOptionsWithCurrent([
    { value: "low", label: bl({ en: "Low", ja: "低" }) },
    { value: "normal", label: bl({ en: "Normal", ja: "標準" }) },
    { value: "high", label: bl({ en: "High", ja: "高" }) },
  ], existing && existing.application_sensitivity) });
  const statusF = uiField({ name: "status", label: bl({ en: "Status", ja: "状態" }), type: "select", value: existing ? existing.status : "active", options: appOptionsWithCurrent([
    { value: "active", label: bl({ en: "Active", ja: "有効" }) },
    { value: "disabled", label: bl({ en: "Disabled", ja: "無効" }) },
  ], existing && existing.status) });
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: existing ? bl({ en: "Save changes", ja: "変更を保存" }) : bl({ en: "Add application", ja: "アプリを追加" }) });
  const backdrop = el("div", { class: "ui-modal-backdrop", onClick: (e) => { if (e.target === backdrop) backdrop.remove(); } }, [
    el("div", { class: "ui-modal", role: "dialog" }, [
      el("div", { class: "ui-modal-head", text: existing ? bl({ en: "Edit application", ja: "アプリを編集" }) : bl({ en: "Add an application", ja: "アプリを追加" }) }),
      el("div", { class: "ui-modal-body" }, [idF.el, nameF.el, typeF.el, sensF.el, statusF.el]),
      el("div", { class: "ui-modal-foot" }, [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => backdrop.remove() }), submit]),
    ]),
  ]);
  submit.addEventListener("click", async () => {
    if (submit.disabled || !idF.validate() || !nameF.validate()) return;
    submit.disabled = true;
    try {
      const edited = { application_id: idF.get(), name: nameF.get(), application_type: typeF.get(), application_sensitivity: sensF.get(), status: statusF.get() };
      const base = await appSaveBase(edited.application_id, Boolean(existing));
      const r = await apiFetch("POST", "/admin/applications", { ...base, ...edited });
      if (!r.ok) { submit.disabled = false; const m = (r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status); idF.setError(m); uiToast(m, "err"); return; }
      backdrop.remove();
      uiToast(existing ? bl({ en: "Application saved.", ja: "アプリを保存しました。" }) : bl({ en: "Application added.", ja: "アプリを追加しました。" }), "ok");
      renderApplicationsView(document.getElementById("content"));
    } catch (e) { submit.disabled = false; idF.setError(String(e)); uiToast(String(e), "err"); }
  });
  document.body.appendChild(backdrop);
  (existing ? nameF : idF).focus();
}

// openPublishWizard — Connector UX Slice 2. Publish a Private App: name -> type -> destination -> Site
// (from GET /admin/sites) -> Review & Publish. The review makes "Published != Allow" explicit: the server
// returns published_route / policy_assigned / users_allowed_now, surfaced to the operator so a freshly
// published app is clearly reachable-but-unauthorized until a policy is bound.
function openPublishWizard(content, existing) {
  existing = existing || null;
  const idF = uiField({ name: "pub_id", label: bl({ en: "Application ID", ja: "アプリ ID" }), required: true, value: existing ? existing.application_id : "",
    placeholder: "jira", hint: bl({ en: "Short unique key. Publishing an existing private app re-uses its ID.", ja: "短い一意キー。既存の社内アプリを公開すると ID を再利用します。" }),
    validate: (v) => (/\s/.test(v) ? bl({ en: "No spaces allowed.", ja: "空白は使えません。" }) : "") });
  if (existing) idF.el.querySelector("input").setAttribute("readonly", "true");
  const nameF = uiField({ name: "pub_name", label: bl({ en: "App name", ja: "アプリ名" }), required: true, value: existing ? (existing.name || "") : "", placeholder: bl({ en: "Internal Jira", ja: "社内 Jira" }) });
  const typeF = uiField({ name: "pub_type", label: bl({ en: "App type", ja: "アプリ種別" }), type: "select", value: existing ? (existing.publish_protocol || "web") : "web", options: [
    { value: "web", label: bl({ en: "Web app", ja: "Web アプリ" }) },
    { value: "tcp", label: bl({ en: "TCP app", ja: "TCP アプリ" }) },
    { value: "network", label: bl({ en: "Network route", ja: "ネットワークルート" }) },
  ] });
  const destF = uiField({ name: "pub_dest", label: bl({ en: "Private destination", ja: "プライベート宛先" }), required: true, value: existing ? (existing.destination || "") : "",
    placeholder: "jira.internal.example.com", hint: bl({ en: "Host the connector reaches on your private network.", ja: "コネクタがプライベートネットワークで到達するホスト。" }) });
  const portF = uiField({ name: "pub_port", label: bl({ en: "Port", ja: "ポート" }), type: "text", value: existing && existing.destination_port ? String(existing.destination_port) : "",
    placeholder: "443", validate: (v) => (v && !/^\d{1,5}$/.test(v) ? bl({ en: "Port must be a number.", ja: "ポートは数値です。" }) : "") });
  const siteF = uiField({ name: "pub_site", label: bl({ en: "Connector Group / Site", ja: "コネクタグループ / サイト" }), type: "select", value: existing ? (existing.connector_group_id || "") : "", options: [
    { value: "", label: bl({ en: "Loading sites…", ja: "サイトを読込中…" }) },
  ] });
  // Slice 5: routing namespace scopes a CIDR (network) route so overlapping private ranges can coexist across
  // sites. Shown for all types but only consulted for Network routes; a network route with no namespace is
  // "ambiguous" and blocked by default on a CIDR collision.
  const nsF = uiField({ name: "pub_namespace", label: bl({ en: "Routing namespace (CIDR routes)", ja: "ルーティング名前空間 (CIDR ルート)" }), value: existing ? (existing.routing_namespace || "") : "",
    placeholder: "site-tokyo", hint: bl({ en: "Scopes a network/CIDR route so overlapping ranges can coexist across sites. Optional for FQDN/host apps.", ja: "ネットワーク/CIDR ルートをスコープし、重複レンジをサイト間で共存させます。FQDN/ホストアプリでは任意。" }),
    validate: (v) => (v && !/^[A-Za-z0-9_-]+$/.test(v) ? bl({ en: "Letters, digits, _ and - only.", ja: "英数字と _ - のみ。" }) : "") });
  // raw-IP guidance: when the destination is a raw IP/CIDR (no DNS name), nudge toward an FQDN and surface any
  // reverse-lookup / recent DNS evidence the server returns (none available here -> show the address only).
  const ipEvidence = el("div", { class: "ui-field-hint", style: "display:none" });
  const refreshIPEvidence = () => {
    const v = (destF.get() || "").trim();
    const isIPLiteral = /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(v) || /^[0-9a-fA-F:]+(\/\d{1,3})?$/.test(v) && v.indexOf(":") >= 0;
    if (isIPLiteral) {
      ipEvidence.style.display = "block";
      ipEvidence.textContent = bl({ en: "Raw IP/CIDR — prefer an FQDN route. No DNS name resolved for ", ja: "生 IP/CIDR — FQDN ルートを推奨。DNS 名は解決されていません: " }) + v;
    } else {
      ipEvidence.style.display = "none";
    }
  };
  // Populate the Site selector from the live Sites list (objects).
  apiFetch("GET", "/admin/sites").then((r) => {
    const sites = (r && r.ok && r.body && r.body.sites) || [];
    const sel = siteF.el.querySelector("select");
    sel.innerHTML = "";
    const opts = [{ value: "", label: bl({ en: "— Select a Site —", ja: "— サイトを選択 —" }) }].concat(sites.map((s) => ({ value: s.site_id || "", label: (s.name || s.site_id || "") + (s.site_id ? " (" + s.site_id + ")" : "") })));
    opts.forEach((o) => { const opt = el("option", { value: o.value, text: o.label }); if (o.value === (existing ? existing.connector_group_id : "")) opt.selected = true; sel.appendChild(opt); });
    if (sites.length === 0) sel.appendChild(el("option", { value: "", text: bl({ en: "No sites yet — enroll a connector first.", ja: "サイトがありません — 先にコネクタを登録してください。" }) }));
  }).catch(() => {});

  const reviewBox = el("div", { class: "ui-preview" });
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Review & Publish", ja: "確認して公開" }) });
  const modal = uiModal({
    title: bl({ en: "Publish a Private App", ja: "社内アプリを公開" }),
    body: [idF.el, nameF.el, typeF.el, destF.el, ipEvidence, portF.el, siteF.el, nsF.el, reviewBox],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => modal.close() }), submit],
  });
  const destInput = destF.el.querySelector("input");
  if (destInput) destInput.addEventListener("input", refreshIPEvidence);
  refreshIPEvidence();
  // CIDR collision panel: render the detected collisions + the recommended choices, with an explicit
  // high-risk override checkbox that re-submits with override_cidr_collision=true.
  const renderCollision = (resp) => {
    reviewBox.innerHTML = "";
    const box = el("div", { class: "ui-field-error-msg", style: "display:block" });
    box.appendChild(el("div", { text: "⚠ " + bl({ en: "CIDR route collision — this network route overlaps an existing route in the same scope.", ja: "CIDR ルート競合 — このネットワークルートは同一スコープの既存ルートと重複します。" }) }));
    if (resp.ambiguous) box.appendChild(el("div", { class: "ui-field-hint", text: bl({ en: "No namespace assigned — ambiguous CIDR is blocked by default.", ja: "名前空間が未割当 — あいまいな CIDR は既定でブロックされます。" }) }));
    (resp.collisions || []).forEach((c) => {
      box.appendChild(el("div", { class: "ui-view-desc", text: (c.cidr || "") + " ↔ " + (c.with_cidr || "") + " (" + (c.relation || "overlap") + ")" + (c.site ? " — " + bl({ en: "Site ", ja: "サイト " }) + c.site : "") + (c.namespace ? " [" + c.namespace + "]" : "") + (c.source ? " — " + c.source : "") }));
    });
    reviewBox.appendChild(box);
    // recommended choices.
    const choices = resp.choices || [];
    if (choices.length) {
      reviewBox.appendChild(el("h4", { text: bl({ en: "How to resolve", ja: "解決方法" }), style: "margin:10px 0 4px;" }));
      const ul = el("ul", { style: "margin:0 0 8px 18px;" });
      choices.forEach((ch) => {
        ul.appendChild(el("li", { text: (ch.label || ch.id) + (ch.recommended ? " " + bl({ en: "(recommended)", ja: "(推奨)" }) : "") + (ch.requires_permission ? " — " + bl({ en: "needs ", ja: "要 " }) + ch.requires_permission : "") }));
      });
      reviewBox.appendChild(ul);
    }
    // Explicit high-risk override.
    const overrideChk = el("input", { type: "checkbox" });
    const overrideLabel = el("label", { class: "ui-field-hint", style: "display:flex;gap:6px;align-items:center;" }, [overrideChk, el("span", { text: bl({ en: "Override with explicit high-risk approval (requires admin.connectors.write).", ja: "明示的な高リスク承認で上書き (admin.connectors.write が必要)。" }) })]);
    reviewBox.appendChild(overrideLabel);
    submit.textContent = bl({ en: "Publish anyway (high-risk)", ja: "それでも公開 (高リスク)" });
    submit.disabled = false;
    submit.onclick = () => {
      if (!overrideChk.checked) { uiToast(bl({ en: "Check the override box to publish despite the collision.", ja: "競合を無視して公開するには上書きにチェックしてください。" }), "err"); return; }
      doPublish(true);
    };
  };
  async function doPublish(override) {
    if (submit.disabled) return;
    if (!idF.validate() || !nameF.validate() || !destF.validate() || !portF.validate() || !nsF.validate()) return;
    submit.disabled = true;
    const body = { name: nameF.get(), destination: destF.get(), publish_protocol: typeF.get(), connector_group_id: siteF.get(), routing_namespace: nsF.get() };
    if (portF.get()) body.destination_port = parseInt(portF.get(), 10);
    if (override) body.override_cidr_collision = true;
    try {
      const r = await apiFetch("POST", "/admin/applications/" + encodeURIComponent(idF.get()) + "/publish", body);
      if (r.status === 409 && r.body && r.body.error === "cidr_route_collision") { renderCollision(r.body); return; }
      if (!r.ok) { submit.disabled = false; const m = (r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status); destF.setError(m); uiToast(m, "err"); return; }
      const review = (r.body && r.body.review) || {};
      // review: Published route / Policy assigned / Users allowed now. Make Published != Allow explicit.
      reviewBox.innerHTML = "";
      reviewBox.appendChild(el("div", { text: bl({ en: "Published route: ", ja: "公開ルート: " }) + (review.published_route ? bl({ en: "yes", ja: "はい" }) : bl({ en: "no", ja: "いいえ" })) }));
      reviewBox.appendChild(el("div", { text: bl({ en: "Policy assigned: ", ja: "ポリシー割当: " }) + (review.policy_assigned ? bl({ en: "yes", ja: "はい" }) : bl({ en: "no", ja: "いいえ" })) }));
      reviewBox.appendChild(el("div", { text: bl({ en: "Users allowed now: ", ja: "現在許可ユーザー数: " }) + (review.users_allowed_now || 0) }));
      if (!review.policy_assigned) {
        reviewBox.appendChild(el("div", { class: "ui-field-hint", text: bl({ en: "Publishing is complete, but no user is authorized yet. Bind a policy to allow access.", ja: "公開は完了しましたが、まだ誰も認可されていません。アクセスを許可するにはポリシーを割り当ててください。" }) }));
      }
      submit.textContent = bl({ en: "Done", ja: "完了" });
      submit.disabled = false;
      submit.onclick = () => { modal.close(); renderApplicationsView(document.getElementById("content")); };
      uiToast(bl({ en: "Private app published.", ja: "社内アプリを公開しました。" }), "ok");
    } catch (e) { submit.disabled = false; uiToast(String(e), "err"); }
  }
  // One handler owns the current step. Keeping the original listener alongside
  // the override/Done handlers would publish again when the user only closes.
  submit.onclick = () => doPublish(false);
  (existing ? destF : idF).focus();
}

// testReachability — Connector UX Slice 3. Probe the app's destination through the connector that fronts
// it (DNS/TCP/TLS/HTTP, scoped to reachable_routes on the connector side) and show the result by layer plus the
// policy simulation. No real user traffic is flowed (bounded probe + a pure policy dry-run). Secret-safe: the
// server never returns key material; resolved IPs / cert fields shown here are visible only to an authorized
// admin and are NOT recorded in the audit trail.
async function testReachability(a) {
  const appID = a.application_id;
  const bodyBox = el("div", {}, [el("div", { class: "ui-view-desc", text: bl({ en: "Probing…", ja: "プロービング中…" }) })]);
  const closeBtn = el("button", { class: "ui-btn", text: bl({ en: "Close", ja: "閉じる" }) });
  const retryBtn = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Re-test", ja: "再テスト" }) });
  const modal = uiModal({
    title: bl({ en: "Reachability — ", ja: "到達性 — " }) + (a.name || appID),
    body: [bodyBox],
    footer: [closeBtn, retryBtn],
  });
  closeBtn.addEventListener("click", () => modal.close());

  // add() is a fail-safe append: it only appends real DOM Nodes. The reachability response is partial by design
  // (route_error / policy_simulation / probe / connector are each optional and may be absent for a given verdict),
  // so a section builder can legitimately yield null/undefined; routing every append through add() keeps a missing
  // section from throwing "appendChild: parameter 1 is not of type 'Node'" and aborting the whole modal render.
  const add = (node) => { if (node instanceof Node) bodyBox.appendChild(node); };

  const kvRow = (label, valueNode) => {
    const node = typeof valueNode === "string" || valueNode == null ? el("span", { text: valueNode && String(valueNode).length ? String(valueNode) : "—" }) : valueNode;
    return el("div", { class: "ui-kv-row" }, [el("div", { class: "ui-kv-key", text: label }), el("div", { class: "ui-kv-val" }, node)]);
  };
  const layerRow = (label, layer) => {
    if (!layer || !layer.attempted) return kvRow(label, "—");
    const ok = !!layer.ok;
    const detail = ok ? (layer.latency_ms != null ? layer.latency_ms + " ms" : "") : (layer.error || bl({ en: "failed", ja: "失敗" }));
    return kvRow(label, el("span", {}, [uiBadge(ok ? bl({ en: "OK", ja: "OK" }) : bl({ en: "Failed", ja: "失敗" }), ok ? "ok" : "warn"), el("span", { class: "ui-view-desc", text: detail ? " " + detail : "" })]));
  };
  const errLine = (text) => { bodyBox.innerHTML = ""; bodyBox.appendChild(el("div", { class: "ui-field-error-msg", style: "display:block", text: "⚠ " + text })); };

  const run = async () => {
    retryBtn.disabled = true;
    bodyBox.innerHTML = "";
    bodyBox.appendChild(el("div", { class: "ui-view-desc", text: bl({ en: "Probing…", ja: "プロービング中…" }) }));
    let res;
    try {
      const r = await apiFetch("POST", "/admin/applications/" + encodeURIComponent(appID) + "/reachability", {});
      retryBtn.disabled = false;
      if (!r.ok) { errLine((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status)); return; }
      res = r.body || {};
    } catch (e) { retryBtn.disabled = false; errLine(String(e)); return; }

    bodyBox.innerHTML = "";
    // Overall verdict.
    const reachable = !!res.reachable;
    const verdict = res.status === "ok"
      ? (reachable ? uiBadge(bl({ en: "Reachable", ja: "到達可能" }), "ok") : uiBadge(bl({ en: "Failure layer: ", ja: "失敗レイヤ: " }) + (res.failure_layer || "?"), "warn"))
      : uiBadge(res.status === "no_connector" ? bl({ en: "No reachable connector", ja: "到達できるコネクタなし" })
        : res.status === "no_tunnel" ? bl({ en: "Connector tunnel not connected", ja: "コネクタトンネル未接続" })
        : bl({ en: "Probe failed", ja: "プローブ失敗" }), "warn");
    add(kvRow(bl({ en: "Reachability", ja: "到達性" }), verdict));

    // Selected connector.
    if (res.connector) {
      add(kvRow(bl({ en: "Connector", ja: "コネクタ" }), (res.connector.name || res.connector.connector_id || "—") + (res.connector.connector_group_id ? " (" + res.connector.connector_group_id + ")" : "")));
    }
    if (res.destination && res.destination.host) {
      add(kvRow(bl({ en: "Destination", ja: "宛先" }), el("code", { text: res.destination.host + (res.destination.port ? ":" + res.destination.port : "") })));
    }

    // Per-layer results.
    const probe = res.probe;
    if (probe) {
      add(el("h4", { text: bl({ en: "Layers", ja: "レイヤ" }), style: "margin:10px 0 4px;" }));
      add(layerRow("DNS", probe.dns));
      if (probe.resolved_ips && probe.resolved_ips.length) {
        add(kvRow(bl({ en: "Resolved IPs", ja: "解決 IP" }), el("code", { text: probe.resolved_ips.join(", ") })));
      }
      add(layerRow("TCP", probe.tcp));
      add(layerRow("TLS", probe.tls));
      if (probe.tls_cert) {
        const c = probe.tls_cert;
        add(el("div", { class: "ui-view-desc", text: bl({ en: "Cert: ", ja: "証明書: " }) + (c.subject || "?") + (c.issuer ? " / " + bl({ en: "issued by ", ja: "発行元 " }) + c.issuer : "") + (c.not_after ? " / " + bl({ en: "expires ", ja: "有効期限 " }) + c.not_after : "") + (c.expired ? " " + bl({ en: "(EXPIRED)", ja: "(期限切れ)" }) : "") }));
      }
      add(layerRow("HTTP", probe.http));
      if (probe.http_status) {
        add(kvRow(bl({ en: "HTTP status", ja: "HTTP ステータス" }), String(probe.http_status)));
      }
    }

    if (res.suggested_action) {
      add(el("div", { class: "ui-field-hint", text: bl({ en: "Suggested action: ", ja: "推奨対応: " }) + res.suggested_action, style: "margin-top:8px;" }));
    }

    // Route-level residency error (Connector UX Slice 6) — shown SEPARATELY from the policy simulation. The
    // route is unavailable because the fronting connector's region is outside the tenant's residency boundary; this
    // is distinct from a policy denial below.
    if (res.route_error && res.route_error.kind === "residency") {
      add(el("h4", { text: bl({ en: "Route error (residency)", ja: "ルートエラー (レジデンシー)" }), style: "margin:10px 0 4px;" }));
      add(kvRow(bl({ en: "Status", ja: "状態" }), uiBadge(bl({ en: "Unavailable — residency boundary", ja: "利用不可 — レジデンシー境界" }), "danger")));
      if (res.route_error.connector_region) {
        add(kvRow(bl({ en: "Connector region", ja: "コネクタリージョン" }), res.route_error.connector_region));
      }
      add(el("div", { class: "ui-field-hint", text: res.route_error.message || bl({ en: "This route is unavailable for residency reasons — separate from any policy decision.", ja: "このルートはレジデンシー上の理由で利用できません。ポリシー判定とは別です。" }) }));
    }

    // Policy simulation (dry-run — no traffic flowed).
    const sim = res.policy_simulation;
    if (sim) {
      add(el("h4", { text: bl({ en: "Policy simulation (dry-run)", ja: "ポリシーシミュレーション (ドライラン)" }), style: "margin:10px 0 4px;" }));
      add(kvRow(bl({ en: "Decision", ja: "判定" }), uiBadge(String(sim.decision || "?"), sim.permitted ? "ok" : "warn")));
      add(kvRow(bl({ en: "Policy assigned", ja: "ポリシー割当" }), sim.policy_assigned ? bl({ en: "yes", ja: "はい" }) : bl({ en: "no", ja: "いいえ" })));
      add(kvRow(bl({ en: "Users allowed now", ja: "現在許可ユーザー数" }), String(sim.users_allowed_now || 0)));
      if (!sim.policy_assigned) {
        add(el("div", { class: "ui-field-hint", text: bl({ en: "Reachable does not mean allowed — bind a policy to authorize users.", ja: "到達可能でも許可済とは限りません — ユーザーを認可するにはポリシーを割り当ててください。" }) }));
      }
    }
  };
  retryBtn.addEventListener("click", run);
  run();
}

// unpublishApp — withdraw a Private App's published route (reachability). Authorization (policy) is untouched.
async function unpublishApp(a) {
  const ok = await uiConfirm({
    title: bl({ en: "Unpublish private app?", ja: "社内アプリを公開停止しますか?" }),
    body: bl({ en: "This withdraws the published route. Users will no longer be able to reach this app through the connector.", ja: "公開ルートを取り下げます。ユーザーはコネクタ経由でこのアプリに到達できなくなります。" }),
    confirmLabel: bl({ en: "Unpublish", ja: "公開停止" }),
    danger: true,
  });
  if (!ok) return;
  try {
    const r = await apiFetch("POST", "/admin/applications/" + encodeURIComponent(a.application_id) + "/unpublish", {});
    if (!r.ok) { const m = (r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status); uiToast(m, "err"); return; }
    uiToast(bl({ en: "Private app unpublished.", ja: "社内アプリを公開停止しました。" }), "ok");
    renderApplicationsView(document.getElementById("content"));
  } catch (e) { uiToast(String(e), "err"); }
}

// deleteApp — permanently remove an operator-authored application. Deleting a PUBLISHED app also withdraws its
// route (it becomes unreachable), so the confirm dialog warns about that explicitly. Policies that reference the
// app are left in place; the dialog reminds the operator to tidy them up. Config-seed apps (derived from
// configuration) are not deletable and the server responds 404 — surfaced as a toast.
async function deleteApp(a) {
  const lines = [bl({ en: "This permanently removes the application from the catalog.", ja: "このアプリをカタログから完全に削除します。" })];
  if (a.published) {
    lines.push(bl({ en: "It is currently PUBLISHED — deleting it withdraws its route, so users will no longer be able to reach it through the connector.", ja: "現在公開中です — 削除するとルートが取り下げられ、ユーザーはコネクタ経由で到達できなくなります。" }));
  }
  lines.push(bl({ en: "Any policies that reference this application are left in place (they will match no application). Tidy them up manually.", ja: "このアプリを参照するポリシーはそのまま残ります(参照先が無くなります)。手動で整理してください。" }));
  const ok = await uiConfirm({
    title: bl({ en: "Delete application?", ja: "アプリを削除しますか?" }),
    body: lines.join(" "),
    confirmLabel: bl({ en: "Delete", ja: "削除" }),
    danger: true,
  });
  if (!ok) return;
  try {
    const r = await apiFetch("DELETE", "/admin/applications/" + encodeURIComponent(a.application_id));
    if (!r.ok) { const m = (r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status); uiToast(m, "err"); return; }
    uiToast(bl({ en: "Application deleted.", ja: "アプリを削除しました。" }), "ok");
    renderApplicationsView(document.getElementById("content"));
  } catch (e) { uiToast(String(e), "err"); }
}
