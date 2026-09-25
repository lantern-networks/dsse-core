"use strict";

// sites.js — "Sites" view (Connector UX Slice 1 + 1b, docs/connector_ux_design.md). A Site /
// Connector Group is the primary product object; an individual connector is infrastructure behind a Site. The
// list MERGES the persistent Site metadata with the read-only connector projection (aggregated by
// connector_group_id). Slice 1b adds Create Site, an enrollment-command (Install connector), and Delete site.
// Backend: GET/POST /admin/sites, GET/DELETE /admin/sites/{site_id}, POST /admin/sites/{site_id}/enrollment-command.
// Secret-safe: built from the admin-safe DTO; private base URLs / hashes are never shown. The bootstrap secret is
// shown ONCE in the enrollment-command modal (only its hash is stored server-side).

function renderSitesView(content) {
  content.innerHTML = "";
  const host = el("div", {});
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "Sites", ja: "サイト" }) }),
      el("p", { class: "ui-view-desc", text: bl({ en: "Your locations and the connectors in each.", ja: "拠点と、各拠点のコネクタ。" }) }),
    ]),
    el("div", { style: "display:flex; gap:8px; flex-wrap:wrap;" }, [
      el("button", { class: "ui-btn ui-btn-primary ui-btn-sm", text: bl({ en: "+ Create Site", ja: "+ サイト作成" }), onClick: () => openSiteForm(host) }),
      el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Reload", ja: "再読込" }), onClick: () => renderSiteList(host) }),
    ]),
  ]));
  content.appendChild(host);
  renderSiteList(host);
}

// openSiteForm opens the Create Site modal (Connector UX): name, region, expected connector count, routing
// namespace, deployment type. The site_id (= connector_group_id) is required and binds enrolled connectors.
// Pass `existing` (a site row) to EDIT it — the Site ID is fixed (it is the connector group id); the rest is
// pre-filled and saved via upsert. Hidden routing namespace and HA policy are preserved on edit.
function siteExpectedConnectorCount(value) {
  if (value === "") return 0;
  if (!/^[0-9]+$/.test(value)) return null;
  const count = Number(value);
  return Number.isSafeInteger(count) ? count : null;
}

function openSiteForm(host, existing) {
  const editing = !!existing;
  const s = { ...(existing || {}) };
  // Do not turn an unreadable hidden setting into an empty setting during a visible-field edit.
  if ([s.routing_namespace, s.ha_policy].some(value => value != null && typeof value !== "string")) {
    uiToast(bl({ en: "Site settings could not be read. Reload before editing.", ja: "サイト設定を読み取れませんでした。再読込してから編集してください。" }), "err");
    return;
  }
  const idF = uiField({ name: "site_id", label: bl({ en: "Site ID", ja: "サイト ID" }), required: true, value: s.site_id || "", placeholder: "tokyo-dc", hint: editing ? bl({ en: "Fixed — this is the connector group id.", ja: "変更不可 — コネクタグループ ID です。" }) : bl({ en: "Stable id; also the connector group id. Connectors enrolled with this id join this site.", ja: "安定した ID(コネクタグループ ID を兼ねる)。この ID で登録したコネクタがこのサイトに入ります。" }) });
  if (editing) { const inp = idF.el.querySelector("input,select,textarea"); if (inp) inp.disabled = true; }
  const nameF = uiField({ name: "name", label: bl({ en: "Display name", ja: "表示名" }), value: s.name || "", placeholder: bl({ en: "Tokyo DC", ja: "東京 DC" }) });
  const regionF = uiField({ name: "region", label: bl({ en: "Region / location", ja: "リージョン / 拠点" }), value: s.region || "", placeholder: "ap-northeast-1 / Tokyo office" });
  const expectedF = uiField({ name: "expected", label: bl({ en: "Expected connectors (HA target)", ja: "想定コネクタ数 (HA 目標)" }), type: "number", value: String(s.expected_connector_count ?? (editing ? 0 : "")), placeholder: "2", hint: bl({ en: "The site shows Degraded when fewer than this are online. Blank or 0 means no target.", ja: "オンラインがこれ未満のときサイトは「一部障害」になります。空欄または 0 は目標なしです。" }), validate: value => {
    const input = expectedF.el.querySelector("input");
    return (input && input.validity && input.validity.badInput) || siteExpectedConnectorCount(value) === null
      ? bl({ en: "Enter a non-negative whole number in decimal digits, up to 9007199254740991, or leave blank.", ja: "0 以上 9007199254740991 以下の整数を数字だけで入力するか、空欄にしてください。" }) : "";
  } });
  const deployF = uiField({ name: "deployment_type", label: bl({ en: "Deployment type", ja: "デプロイ種別" }), value: s.deployment_type || "", placeholder: "vm / container / appliance" });
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: editing ? bl({ en: "Save", ja: "保存" }) : bl({ en: "Create", ja: "作成" }) });
  const m = uiModal({
    title: editing ? bl({ en: "Edit site", ja: "サイトを編集" }) : bl({ en: "Create a site", ja: "サイトを作成" }),
    body: [idF.el, nameF.el, regionF.el, expectedF.el, deployF.el],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit],
  });
  submit.onclick = async () => {
    if (!editing && !idF.validate()) return;
    if (!expectedF.validate()) return;
    submit.disabled = true;
    const body = { site_id: editing ? s.site_id : idF.get(), name: nameF.get(), region: regionF.get(), deployment_type: deployF.get() };
    if (s.routing_namespace) body.routing_namespace = s.routing_namespace; // preserve (not shown; out of scope)
    if (s.ha_policy) body.ha_policy = s.ha_policy;
    body.expected_connector_count = siteExpectedConnectorCount(expectedF.get());
    try {
      const r = await apiFetch("POST", "/admin/sites", body);
      if (!r.ok) { submit.disabled = false; uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
      m.close(); uiToast(editing ? bl({ en: "Site saved.", ja: "サイトを保存しました。" }) : bl({ en: "Site created.", ja: "サイトを作成しました。" }), "ok"); renderSiteList(host);
    } catch (e) { submit.disabled = false; uiToast(String(e), "err"); }
  };
  if (editing) nameF.focus(); else idF.focus();
}

// showSiteNetworks opens the site's Networks — bound once to the site and served by all its connectors. Subnets
// are SELECTED from the catalog (defined on the Networks page); a single hostname is bound directly here.
async function showSiteNetworks(siteID, host) {
  let bodyHost;
  const modal = uiModal({ title: bl({ en: "Networks — " + siteID, ja: siteID + " のネットワーク" }), body: [], footer: [], onClose: () => { if (bodyHost) freshRender(bodyHost); } });
  const box = modal.el.querySelector(".ui-modal"); if (box) box.style.width = "min(720px, 94vw)";
  bodyHost = modal.el.querySelector(".ui-modal-body");
  const foot = modal.el.querySelector(".ui-modal-foot"); foot.innerHTML = "";
  foot.appendChild(el("button", { class: "ui-btn", text: bl({ en: "Done", ja: "完了" }), onClick: () => { modal.close(); renderSiteList(host); } }));
  await renderSiteNetworks(bodyHost, siteID, host);
}

function siteNetworkRows(response, key) {
  if (!response || !response.ok) throw new Error("HTTP " + (response && response.status));
  if (!response.body || !Object.hasOwn(response.body, key)) throw new Error("Invalid site network response");
  const rows = response.body[key];
  if (rows === null) return [];
  if (!Array.isArray(rows) || rows.some(row => !row || typeof row !== "object" || Array.isArray(row))) throw new Error("Invalid site network response");
  return rows;
}

async function loadSiteNetworkData(siteID) {
  const [bindings, networks, connectors] = await Promise.all([
    apiFetch("GET", "/admin/sites/" + encodeURIComponent(siteID) + "/networks"),
    apiFetch("GET", "/admin/vlan-objects"),
    apiFetch("GET", "/admin/connectors"),
  ]);
  const rows = siteNetworkRows(bindings, "networks");
  const catalog = siteNetworkRows(networks, "objects");
  const conns = siteNetworkRows(connectors, "connectors");
  const text = value => typeof value === "string" && value.length > 0;
  const optionalText = value => value == null || typeof value === "string";
  const optionalTexts = value => value == null || (Array.isArray(value) && value.every(v => typeof v === "string"));
  if (rows.some(r => !["network", "fqdn", "cidr"].includes(r.kind) ||
      (r.kind === "network" && !text(r.network_id)) || (r.kind === "fqdn" && !text(r.fqdn)) || (r.kind === "cidr" && !text(r.cidr)) ||
      ![r.network_id, r.fqdn, r.cidr].every(optionalText) || [r.network_id, r.fqdn, r.cidr].filter(Boolean).length !== 1 ||
      !optionalText(r.network_name) || !optionalTexts(r.network_cidrs))) throw new Error("Invalid site network binding");
  if (catalog.some(n => !text(n.id) || !optionalText(n.name) || !optionalTexts(n.cidrs))) throw new Error("Invalid network catalog");
  if (conns.some(c => !text(c.id) || ![c.name, c.connector_group_id, c.edge_region_id, c.attached_region_id].every(optionalText))) throw new Error("Invalid connector catalog");
  return { rows, catalog, conns: conns.filter(c => (c.connector_group_id || "") === siteID) };
}

async function renderSiteNetworks(bodyHost, siteID, listHost) {
  const current = freshRender(bodyHost);
  bodyHost.__siteNetworkEditor = null;
  uiState(bodyHost, "loading");
  let data;
  try { data = await loadSiteNetworkData(siteID); }
  catch (e) { if (current()) uiState(bodyHost, "error", String(e.message || e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderSiteNetworks(bodyHost, siteID, listHost) }); return; }
  if (!current()) return;
  const { rows, catalog, conns } = data;
  bodyHost.innerHTML = "";
  bodyHost.appendChild(el("p", { class: "ui-view-desc", text: bl({ en: "The networks this site serves — all its connectors serve them.", ja: "この拠点が担うネットワーク。配下の全コネクタが担います。" }) }));
  const dest = (rt) => rt.kind === "network" ? ((rt.network_name || rt.network_id) + ((rt.network_cidrs && rt.network_cidrs.length) ? " (" + rt.network_cidrs.join(", ") + ")" : "")) : (rt.cidr || rt.fqdn || "");
  const payloadFor = (rt) => rt.kind === "network" ? { network_id: rt.network_id } : (rt.fqdn ? { fqdn: rt.fqdn } : { cidr: rt.cidr });
  const kindLabel = (rt) => rt.kind === "network" ? bl({ en: "Named network", ja: "定義済みNW" }) : (rt.fqdn ? bl({ en: "Name", ja: "名前" }) : bl({ en: "Subnet", ja: "サブネット" }));
  if (rows.length) {
    const trows = rows.map((rt) => el("tr", {}, [
      el("td", {}, el("code", { text: dest(rt) })),
      el("td", {}, uiBadge(kindLabel(rt), "off")),
      el("td", { class: "ui-row-actions" }, el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Remove", ja: "削除" }), onClick: () => siteNetworkAction(siteID, Object.assign({ action: "remove" }, payloadFor(rt)), bodyHost, listHost) })),
    ]));
    bodyHost.appendChild(el("table", { class: "ui-table" }, [
      el("thead", {}, el("tr", {}, [bl({ en: "Network", ja: "ネットワーク" }), bl({ en: "Type", ja: "種別" }), bl({ en: "Manage", ja: "操作" })].map((x) => el("th", { text: x })))),
      el("tbody", {}, trows),
    ]));
  } else {
    bodyHost.appendChild(el("p", { class: "ui-view-desc", text: bl({ en: "No networks yet.", ja: "ネットワーク未設定。" }) }));
  }
  // Add by SELECTING from the catalog (define once, select everywhere).
  if (catalog.length) {
    const sel = el("select", { class: "ui-input" }); sel.style.maxWidth = "300px";
    sel.appendChild(el("option", { value: "", text: bl({ en: "Select a network from the catalog…", ja: "カタログからネットワークを選択…" }) }));
    catalog.forEach((n) => { const c = (n.cidrs || []).join(", "); sel.appendChild(el("option", { value: n.id, text: (n.name || n.id) + (c ? " (" + c + ")" : "") })); });
    bodyHost.appendChild(el("div", { class: "ui-toolbar", style: "margin-top:10px" }, [sel, el("button", { class: "ui-btn ui-btn-sm ui-btn-primary", text: bl({ en: "Add network", ja: "ネットワークを追加" }), onClick: () => { if (sel.value) siteNetworkAction(siteID, { action: "add", network_id: sel.value }, bodyHost, listHost); } })]));
  }
  // Subnets come from the catalog (select above — defined on the Networks page). A single hostname is bound here.
  const inp = el("input", { class: "ui-input", placeholder: bl({ en: "or a hostname — wiki.corp", ja: "またはホスト名 — wiki.corp" }) }); inp.style.maxWidth = "240px";
  bodyHost.appendChild(el("div", { class: "ui-toolbar", style: "margin-top:6px" }, [inp, el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Add", ja: "追加" }), onClick: () => { const v = inp.value.trim(); if (!v) return; siteNetworkAction(siteID, { action: "add", fqdn: v }, bodyHost, listHost); } })]));
  const saveError = el("div", { class: "ui-state ui-state-error", role: "alert", style: "display:none" });
  bodyHost.appendChild(saveError);
  bodyHost.__siteNetworkEditor = { current, busy: false, error: saveError, controls: Array.from(bodyHost.querySelectorAll("button,input,select")) };

  // (connector_network_route_advertisement_design.md): the route-governance surface lives HERE — the
  // site-first IA has no separate Connectors page, so each of the site's connectors gets its governance panel
  // (configured bindings and informational connector-reported routes) in this
  // modal. Configured bindings can be removed; reported subnets are informational.
  for (const c of conns) {
    const panel = el("div", { style: "margin-top:16px;border-top:1px solid rgba(128,128,128,.25);padding-top:10px" });
    bodyHost.appendChild(panel);
    // ★ THE ID IS ALWAYS SHOWN, NOT ONLY THE NAME (2026-08-25). Connectors registered themselves with one
    // hardcoded name, so a site with several showed several identical panels and an operator binding a network
    // could not tell which connector it was going to. A name is a convenience; the id is what the act is
    // performed on, so it is on screen either way.
    if (conns.length > 1) {
      panel.appendChild(el("div", { class: "ui-kv-sub" }, [
        el("span", { text: c.name || c.id }),
        c.name ? el("code", { class: "ui-view-desc", style: "margin-left:8px", text: c.id }) : null,
      ]));
    }
    // ★ A CONNECTOR THAT IS NOT WHERE IT WAS SET UP IS SAID ON THE SCREEN (2026-08-26). A connector with more
    // than one door moves region when its own goes away, and the deployment then sends everything behind it to
    // the new one. That is the system working — but an operator looking at a site sees a connector filed under
    // a region it is no longer in, and nothing explains why traffic is going somewhere else. Shown only when
    // the two differ: a line that appears on every row is a line people stop reading.
    const setUpIn = (c.edge_region_id || "").trim();
    const connectedThrough = (c.attached_region_id || "").trim();
    if (setUpIn && connectedThrough && setUpIn.toLowerCase() !== connectedThrough.toLowerCase()) {
      panel.appendChild(el("div", { class: "ui-callout ui-callout-warn", text: bl({
        en: "Set up in " + setUpIn + ", but currently connected through " + connectedThrough +
            ". Traffic to everything behind this connector is being sent to " + connectedThrough + ".",
        ja: setUpIn + " で設定されていますが、いま繋がっているのは " + connectedThrough +
            " です。このコネクタの背後にあるものへの通信は " + connectedThrough + " へ送られています。",
      }) }));
    }
    // renderConnectorRouteGovernance clears its host on (re)render, so give it a nested host of its own.
    const inner = el("div", {});
    panel.appendChild(inner);
    renderConnectorRouteGovernance(inner, c.id);
  }
}

async function siteNetworkAction(siteID, payload, bodyHost, listHost) {
  const editor = bodyHost.__siteNetworkEditor;
  if (!editor || !editor.current() || editor.busy) return;
  editor.busy = true;
  editor.error.style.display = "none";
  const controls = editor.controls.map(control => ({ control, disabled: control.disabled }));
  controls.forEach(({ control }) => { control.disabled = true; });
  try {
    const r = await apiFetch("POST", "/admin/sites/" + encodeURIComponent(siteID) + "/networks", payload);
    if (!r.ok) throw new Error((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status));
    if (!editor.current()) return;
    uiToast(bl({ en: "Network updated.", ja: "ネットワークを更新しました。" }), "ok");
    await renderSiteNetworks(bodyHost, siteID, listHost);
  } catch (e) {
    if (!editor.current()) return;
    editor.error.textContent = String(e.message || e);
    editor.error.style.display = "";
    editor.error.scrollIntoView({ block: "nearest" });
  } finally {
    editor.busy = false;
    if (editor.current()) controls.forEach(({ control, disabled }) => { control.disabled = disabled; });
  }
}

// renameConnector opens a small modal to set an operator display name for a connector (survives reconnection).
async function renameConnector(id, current, host) {
  const f = uiField({ name: "name", label: bl({ en: "Connector name", ja: "コネクタ名" }), value: current || "", placeholder: bl({ en: "Tokyo DC connector", ja: "東京DC コネクタ" }), hint: bl({ en: "A friendly name shown in the console. Leave empty to clear.", ja: "コンソール表示用の分かりやすい名前。空で解除。" }) });
  const save = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Save", ja: "保存" }) });
  const m = uiModal({ title: bl({ en: "Rename connector", ja: "コネクタの名前変更" }), body: [f.el], footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), save] });
  save.onclick = async () => {
    save.disabled = true;
    try {
      const r = await apiFetch("POST", "/admin/connectors/" + encodeURIComponent(id) + "/name", { name: f.get() });
      if (!r.ok) { save.disabled = false; uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
      m.close(); uiToast(bl({ en: "Renamed.", ja: "名前を変更しました。" }), "ok"); renderSiteList(host);
    } catch (e) { save.disabled = false; uiToast(String(e), "err"); }
  };
  f.focus();
}

// removeConnector decommissions a connector (deletes it from the registry). A live connector re-registers, so
// this is for offline / retired ones.
async function removeConnector(id, name, host) {
  const ok = await uiConfirm({ title: bl({ en: "Remove this connector?", ja: "このコネクタを削除?" }), body: bl({ en: "\"" + name + "\" is removed from this site. A connector that is still running will re-appear when it next checks in.", ja: "「" + name + "」をこの拠点から削除します。稼働中のコネクタは次回チェックインで再登場します。" }), confirmLabel: bl({ en: "Remove", ja: "削除" }), danger: true });
  if (!ok) return;
  const r = await apiFetch("DELETE", "/admin/connectors/" + encodeURIComponent(id));
  if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
  uiToast(bl({ en: "Connector removed.", ja: "コネクタを削除しました。" }), "ok"); renderSiteList(host);
}

// siteHealthBadge maps a Site health label to a coloured badge. healthy -> ok, degraded -> warn,
// down -> danger, unknown / other -> off.
function siteHealthBadge(health) {
  const h = String(health || "unknown");
  const kind = h === "healthy" ? "ok" : h === "degraded" ? "warn" : h === "down" ? "danger" : "off";
  const label = {
    healthy: bl({ en: "Healthy", ja: "正常" }),
    degraded: bl({ en: "Degraded", ja: "一部障害" }),
    down: bl({ en: "Down", ja: "停止" }),
    unknown: bl({ en: "Unknown", ja: "不明" }),
  }[h] || h;
  return uiBadge(label, kind);
}

// siteRouteCount renders a compact "F fqdn / C cidr" route summary from route_summary.
function siteRouteCount(routeSummary) {
  const rs = routeSummary || {};
  const f = rs.fqdn_domain_count || 0;
  const c = rs.cidr_count || 0;
  return bl({ en: f + " fqdn / " + c + " cidr", ja: "FQDN " + f + " / CIDR " + c });
}

// renderSiteList shows every site as a CARD with its connectors + live status INLINE, so opening the page shows
// the connector situation at a glance (no drill-in needed). Connectors are grouped by connector_group_id; per
// connector you can rename it, see its Connected/Offline status + last heartbeat, and open its Networks.
async function renderSiteList(host) {
  uiState(host, "loading");
  const current = freshRender(host);
  let sites = [], conns = [];
  try {
    const [rs, rc] = await Promise.all([apiFetch("GET", "/admin/sites"), apiFetch("GET", "/admin/connectors")]);
    if (!rs.ok) { if (!current()) return; uiState(host, "error", "HTTP " + rs.status, { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderSiteList(host) }); return; }
    sites = (rs.body && rs.body.sites) || [];
    conns = (rc.ok && rc.body && rc.body.connectors) || [];
  } catch (e) { if (!current()) return; uiState(host, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderSiteList(host) }); return; }

  const bySite = {};
  conns.forEach((c) => { const g = c.connector_group_id || ""; (bySite[g] = bySite[g] || []).push(c); });

  if (!current()) return;
  host.innerHTML = "";
  if (!sites.length && !conns.length) {
    if (!current()) return;
    uiState(host, "empty", bl({ en: "No sites yet. Create a site, then install a connector into it.", ja: "サイトがありません。サイトを作成し、コネクタを導入してください。" }));
    return;
  }

  const cid = (c) => c.id || c.connector_id || "";
  // connTable lists a site's connectors. In HA mode it shows the active-standby role: exactly one online
  // connector is ACTIVE (the one routing sends traffic to — the stable pick among the online ones); the other
  // online connectors are STANDBY (ready to take over); offline ones are OFFLINE. Non-HA (unassigned) shows plain
  // connected/offline.
  const connTable = (list, ha) => {
    if (!list.length) return el("p", { class: "ui-view-desc", style: "margin:6px 0 2px", text: bl({ en: "No connectors yet — use “Add connector”.", ja: "コネクタ未導入 —「コネクタを追加」から。" }) });
    // ★ THE SERVER'S ANSWER, NOT ITS INGREDIENTS (2026-09-01). This read tunnel_connected as a boolean, and
    // that field has three states: held here, unknown, and — never — false. A control plane holds no connector
    // tunnel at all, so it answers unknown for every connector, and this screen showed "Healthy … 0 / 2
    // connectors online" with a heartbeat eight seconds old beside each Offline row, while the API it had just
    // called said online=2. `online` is that same answer, decided once, on the server.
    const activeId = list.filter((c) => c.online).map(cid).sort()[0] || null;
    const roleBadge = (c) => {
      if (!c.online) return uiBadge(bl({ en: "Offline", ja: "オフライン" }), "danger");
      if (!ha) return uiBadge(bl({ en: "Connected", ja: "接続中" }), "ok");
      return cid(c) === activeId ? uiBadge(bl({ en: "Active", ja: "アクティブ" }), "ok") : uiBadge(bl({ en: "Standby", ja: "スタンバイ" }), "off");
    };
    const rows = list.map((c) => {
      const id = cid(c);
      return el("tr", {}, [
        el("td", {}, [el("div", { style: "font-weight:600", text: c.name || id }), el("code", { class: "ui-view-desc", text: id })]),
        el("td", {}, roleBadge(c)),
        el("td", { text: c.last_heartbeat_at || bl({ en: "never", ja: "なし" }) }),
        el("td", { class: "ui-row-actions" }, [
          el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Rename", ja: "名前変更" }), onClick: () => renameConnector(id, c.name, host) }),
          el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Remove", ja: "削除" }), onClick: () => removeConnector(id, c.name || id, host) }),
        ]),
      ]);
    });
    return el("table", { class: "ui-table", style: "margin-top:6px" }, [
      el("thead", {}, el("tr", {}, [bl({ en: "Connector", ja: "コネクタ" }), bl({ en: "Role", ja: "役割" }), bl({ en: "Last heartbeat", ja: "最終ハートビート" }), bl({ en: "Manage", ja: "操作" })].map((x) => el("th", { text: x })))),
      el("tbody", {}, rows),
    ]);
  };

  const card = (s, opts) => {
    opts = opts || {};
    const sid = s.site_id || s.id || "";
    const list = opts.list || bySite[sid] || [];
    const online = list.filter((c) => c.online).length;
    const total = list.length || s.connector_count || 0;
    const wrap = el("div", { style: "border:1px solid var(--ui-line);border-radius:10px;padding:14px 16px;margin-bottom:14px;background:var(--panel)" });
    const actions = opts.orphan ? [] : [
      el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Networks", ja: "ネットワーク" }), onClick: () => showSiteNetworks(sid, host) }),
      el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Edit", ja: "編集" }), onClick: () => openSiteForm(host, s) }),
      el("button", { class: "ui-btn ui-btn-sm ui-btn-primary", text: bl({ en: "Add connector", ja: "コネクタを追加" }), onClick: () => showEnrollmentCommand(sid) }),
      s.managed ? el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Delete", ja: "削除" }), onClick: () => deleteSite(sid, s.name, null, host) }) : null,
    ].filter(Boolean);
    wrap.appendChild(el("div", { style: "display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap" }, [
      el("div", { style: "display:flex;align-items:center;gap:10px;flex-wrap:wrap" }, [
        el("span", { style: "font-size:15px;font-weight:650", text: opts.title || s.name || sid }),
        opts.orphan ? null : siteHealthBadge(s.health),
        el("span", { class: "ui-view-desc", text: online + " / " + total + bl({ en: " connectors online", ja: " コネクタ オンライン" }) }),
        (s.regions && s.regions.length) ? el("span", { class: "ui-view-desc", text: s.regions.join(", ") }) : null,
      ].filter(Boolean)),
      el("div", { class: "ui-row-actions" }, actions),
    ]));
    wrap.appendChild(connTable(list, !opts.orphan));
    return wrap;
  };

  sites.forEach((s) => host.appendChild(card(s)));

  // Connectors whose group id matches no site — surface them so they are never hidden.
  const siteIds = new Set(sites.map((s) => s.site_id || s.id));
  const orphanIds = Object.keys(bySite).filter((g) => g && !siteIds.has(g));
  const orphans = (bySite[""] || []).concat(...orphanIds.map((g) => bySite[g]));
  if (orphans.length) {
    host.appendChild(card({ site_id: "", regions: [] }, { orphan: true, list: orphans, title: bl({ en: "Connectors not assigned to a site", ja: "サイト未割り当てのコネクタ" }) }));
  }
}

// siteKVRow builds a label/value line for the Site detail modal. value may be a string or a node.
function siteKVRow(label, value) {
  // A real DOM node is used as-is; anything else (string, number, or an unexpected object) is coerced to text so
  // we never appendChild a non-Node (a plain object here crashed the whole Site detail — "not of type Node").
  const isNode = value && typeof value === "object" && typeof value.nodeType === "number";
  const valueNode = isNode
    ? value
    : el("span", { text: (value != null && typeof value !== "object" && String(value).length) ? String(value) : "—" });
  return el("div", { class: "ui-kv-row" }, [
    el("div", { class: "ui-kv-key", text: label }),
    el("div", { class: "ui-kv-val" }, valueNode),
  ]);
}

// showSiteDetail opens a read-only drill-down for a Site: its aggregate plus the member connector list. It
// fetches the detail DTO for fresh state, falling back to the list row if the fetch fails. Only non-secret
// fields are shown (private base URLs / secrets are never here).
async function showSiteDetail(siteID, fallback, host) {
  const modal = uiModal({
    title: bl({ en: "Site detail", ja: "サイト詳細" }),
    body: [el("div", {}, uiBadge(bl({ en: "Loading…", ja: "読込中…" }), "off"))],
    footer: [],
  });
  const bodyHost = modal.el.querySelector(".ui-modal-body");
  let s = fallback || {};
  let connectors = [];
  try {
    const r = await apiFetch("GET", "/admin/sites/" + encodeURIComponent(siteID));
    if (r.ok && r.body) { s = r.body; connectors = r.body.connectors || []; }
  } catch (e) { /* keep fallback row */ }

  const rs = s.route_summary || {};
  const namespaces = (rs.namespaces || []).join(", ");
  const expectedText = s.expected_connector_count
    ? (s.online_count || 0) + " / " + s.expected_connector_count + bl({ en: " expected online", ja: " 想定中オンライン" })
    : (s.online_count || 0) + " / " + (s.connector_count || 0) + bl({ en: " online", ja: " オンライン" });
  const overviewRows = [
    siteKVRow(bl({ en: "Site ID", ja: "サイト ID" }), el("code", { text: s.site_id || siteID })),
    s.name ? siteKVRow(bl({ en: "Name", ja: "名前" }), s.name) : null,
    siteKVRow(bl({ en: "Health", ja: "健全性" }), siteHealthBadge(s.health)),
    siteKVRow(bl({ en: "Connectors", ja: "コネクタ" }), expectedText),
    typeof s.region === "string" ? siteKVRow(bl({ en: "Region", ja: "リージョン" }), s.region) : null,
    s.deployment_type ? siteKVRow(bl({ en: "Deployment type", ja: "デプロイ種別" }), s.deployment_type) : null,
    s.ha_policy ? siteKVRow(bl({ en: "HA policy", ja: "HA ポリシー" }), s.ha_policy) : null,
    siteKVRow(bl({ en: "Regions", ja: "リージョン" }), (s.regions || []).join(", ") || "—"),
    siteKVRow(bl({ en: "Routes", ja: "ルート" }), siteRouteCount(rs)),
    siteKVRow(bl({ en: "Namespaces", ja: "ネームスペース" }), namespaces || s.routing_namespace || bl({ en: "None", ja: "なし" })),
    siteKVRow(bl({ en: "Last heartbeat", ja: "最終ハートビート" }), s.last_heartbeat_at || bl({ en: "never", ja: "なし" })),
  ];
  const overview = el("div", { class: "ui-kv" }, overviewRows.filter(Boolean));

  bodyHost.innerHTML = "";
  bodyHost.appendChild(overview);

  // Slice 6: HA failover readiness + multi-region / residency. Both are additive detail-only blocks.
  if (s.failover) bodyHost.appendChild(siteFailoverSection(s.failover));
  if (s.region) bodyHost.appendChild(siteRegionSection(s.region));

  bodyHost.appendChild(el("h3", { class: "ui-kv-sub", text: bl({ en: "Connectors", ja: "コネクタ" }) }));
  bodyHost.appendChild(el("p", { class: "ui-view-desc", text: bl({ en: "Click a connector to manage its Networks (bind subnets/hostnames it serves) and rotate its secret.", ja: "コネクタをクリックすると、担うネットワーク(サブネット/ホスト名)の紐付けとシークレット更新ができます。" }) }));
  if (connectors.length === 0) {
    bodyHost.appendChild(el("p", { class: "ui-view-desc", text: bl({ en: "No connectors in this site.", ja: "このサイトにコネクタはありません。" }) }));
  } else {
    const openConn = (c) => { if (typeof showConnectorDetail === "function") showConnectorDetail(c.id, c); };
    const rows = connectors.map((c) => el("tr", { class: "ui-row-clickable", onClick: () => openConn(c) }, [
      el("td", {}, el("code", { text: c.id || "" })),
      el("td", { text: c.name || "—" }),
      // The server's own answer, for the same reason as the badge above: tunnel_connected is unknown for every
      // connector when this list is read at a control plane, and unknown is not offline.
      el("td", {}, uiBadge(c.online ? bl({ en: "Connected", ja: "接続中" }) : bl({ en: "Offline", ja: "オフライン" }), c.online ? "ok" : "danger")),
      el("td", { text: [c.edge_region_id, c.edge_cluster_id].filter(Boolean).join(" / ") || "—" }),
      el("td", { text: c.last_heartbeat_at || bl({ en: "never", ja: "なし" }) }),
    ]));
    bodyHost.appendChild(el("table", { class: "ui-table" }, [
      el("thead", {}, el("tr", {}, [
        el("th", { text: bl({ en: "Connector", ja: "コネクタ" }) }),
        el("th", { text: bl({ en: "Name", ja: "名前" }) }),
        el("th", { text: bl({ en: "Tunnel", ja: "トンネル" }) }),
        el("th", { text: bl({ en: "Region / Cluster", ja: "リージョン / クラスター" }) }),
        el("th", { text: bl({ en: "Last heartbeat", ja: "最終ハートビート" }) }),
      ])),
      el("tbody", {}, rows),
    ]));
  }
  const foot = modal.el.querySelector(".ui-modal-foot");
  foot.innerHTML = "";
  const managed = !!s.managed;
  foot.appendChild(el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Install connector", ja: "コネクタを導入" }), onClick: () => showEnrollmentCommand(s.site_id || siteID) }));
  if (managed) {
    foot.appendChild(el("button", { class: "ui-btn ui-btn-danger", text: bl({ en: "Delete site", ja: "サイトを削除" }), onClick: () => deleteSite(s.site_id || siteID, s.name, modal, host) }));
  }
  foot.appendChild(el("button", { class: "ui-btn", text: bl({ en: "Close", ja: "閉じる" }), onClick: () => modal.close() }));
}

// siteFailoverSection renders the HA failover-readiness block: expected vs online, a capacity warning when
// online is below target, the impacted apps/routes, and the health-aware selection note (no fixed active/standby).
function siteFailoverSection(f) {
  const wrap = el("div", {});
  wrap.appendChild(el("h3", { class: "ui-kv-sub", text: bl({ en: "Failover readiness (HA)", ja: "フェイルオーバー準備状況 (HA)" }) }));
  const readyBadge = f.failover_ready
    ? uiBadge(bl({ en: "Ready", ja: "準備完了" }), "ok")
    : uiBadge(f.capacity_warning ? bl({ en: "Capacity below target", ja: "容量が目標未満" }) : bl({ en: "No redundancy", ja: "冗長性なし" }), "warn");
  const online = f.online_count || 0;
  const expected = f.expected_connector_count || 0;
  const connectorsText = expected
    ? online + " / " + expected + bl({ en: " online (expected)", ja: " オンライン (想定)" })
    : online + bl({ en: " online", ja: " オンライン" });
  const rows = [
    siteKVRow(bl({ en: "Failover", ja: "フェイルオーバー" }), readyBadge),
    siteKVRow(bl({ en: "Connectors", ja: "コネクタ" }), connectorsText),
  ];
  if (f.degraded_reason) rows.push(siteKVRow(bl({ en: "Reason", ja: "理由" }), f.degraded_reason));
  rows.push(siteKVRow(bl({ en: "Affected apps", ja: "影響を受けるアプリ" }), String(f.affected_app_count || 0)));
  rows.push(siteKVRow(bl({ en: "Affected routes", ja: "影響を受けるルート" }), String(f.affected_route_count || 0)));
  rows.push(siteKVRow(bl({ en: "Connector selection", ja: "コネクタ選択" }), bl({ en: "Health-aware (no fixed active/standby)", ja: "ヘルス連動 (固定のアクティブ/スタンバイなし)" })));
  wrap.appendChild(el("div", { class: "ui-kv" }, rows));
  return wrap;
}

// siteRegionSection renders the multi-region block: connector home region(s), the serving edge region,
// advertised regions, and the residency boundary. A residency error (a connector region outside the boundary) is
// shown as a ROUTE-LEVEL residency problem, kept distinct from any policy decision.
function siteRegionSection(r) {
  const wrap = el("div", {});
  wrap.appendChild(el("h3", { class: "ui-kv-sub", text: bl({ en: "Region & residency", ja: "リージョンとレジデンシー" }) }));
  const rows = [
    siteKVRow(bl({ en: "Connector home regions", ja: "コネクタのホームリージョン" }), (r.home_regions || []).join(", ") || "—"),
    siteKVRow(bl({ en: "Serving edge region", ja: "処理エッジリージョン" }), r.serving_edge_region || "—"),
  ];
  if (r.advertised_regions && r.advertised_regions.length) {
    rows.push(siteKVRow(bl({ en: "Advertised regions", ja: "広告リージョン" }), r.advertised_regions.join(", ")));
  }
  rows.push(siteKVRow(bl({ en: "Residency boundary", ja: "レジデンシー境界" }),
    r.residency_restricted ? ((r.residency_boundary || []).join(", ") || "—") : bl({ en: "Unrestricted", ja: "制限なし" })));
  if (r.residency_error) {
    rows.push(siteKVRow(bl({ en: "Residency", ja: "レジデンシー" }), uiBadge(bl({ en: "Route unavailable (residency)", ja: "ルート利用不可 (レジデンシー)" }), "danger")));
    rows.push(siteKVRow(bl({ en: "Out of boundary", ja: "境界外" }), (r.out_of_boundary_regions || []).join(", ")));
  }
  wrap.appendChild(el("div", { class: "ui-kv" }, rows));
  if (r.residency_error) {
    wrap.appendChild(el("div", { class: "ui-field-hint", text: bl({ en: "A connector region is outside the residency boundary, so its route is unavailable for residency reasons — this is separate from a policy denial.", ja: "コネクタのリージョンがレジデンシー境界外のため、そのルートはレジデンシー上の理由で利用できません。これはポリシーによる拒否とは別物です。" }) }));
  }
  return wrap;
}

// showEnrollmentCommand requests a fresh enrollment command and shows it ONCE — the bootstrap secret embedded in
// the command is shown only this once (only its hash is stored server-side), so the modal warns to copy it now.
// enrollmentCommandFetch POSTs for the enrollment command, retrying with a short back-off. The endpoint is fast,
// but this POST fired from the "Add connector" click can race the Sites page's own in-flight GETs and fail at the
// front door with "Failed to fetch" (the "Add connector does nothing" report). A delayed retry runs once those
// have settled, so it goes through on its own. Purely a transport recovery — no duplicate work server-side.
async function enrollmentCommandFetch(siteID) {
  const path = "/admin/sites/" + encodeURIComponent(siteID) + "/enrollment-command";
  let lastErr;
  for (let attempt = 0; attempt < 6; attempt++) {
    if (attempt > 0) await new Promise((r) => setTimeout(r, 400));
    // Bound each try: this POST can either fast-fail ("Failed to fetch") OR stall on a contended front-door
    // connection. AbortController turns a stall into a quick failure so the delayed retry — which runs once the
    // page's own requests have settled — reaches the (fast) endpoint on its own.
    const ctl = typeof AbortController === "function" ? new AbortController() : null;
    const timer = ctl ? setTimeout(() => ctl.abort(), 1200) : null;
    try {
      const r = await apiFetch("POST", path, {}, undefined, ctl ? ctl.signal : undefined);
      if (timer) clearTimeout(timer);
      return r;
    } catch (e) { if (timer) clearTimeout(timer); lastErr = e; }
  }
  throw lastErr;
}

// connectorProgramsFetch asks the control plane what programs this deployment holds. The bytes live with the
// authority, the same way agent release artifacts do, so this read is explicitly control-plane.
async function connectorProgramsFetch() {
  try {
    const r = await apiFetch("GET", "/admin/connector-programs", undefined, "control");
    if (!r || !r.ok || !r.body) return [];
    return Array.isArray(r.body.programs) ? r.body.programs : [];
  } catch (e) { return []; }
}

// downloadConnectorProgram takes the bytes away. A raw fetch rather than apiFetch, for the same reason the
// agent release screen uses one: apiFetch reads every answer as text, and a program is not text.
async function downloadConnectorProgram(program) {
  const base = baseForPlane("control");
  const token = localStorage.getItem("adminToken") || "";
  const signedIn = idpSession && idpSession.auth_method === "admin_session";
  const headers = {};
  if (!signedIn && token) headers["authorization"] = "Bearer " + token;
  if (operateTenant) headers["x-operate-tenant"] = operateTenant;
  const path = "/admin/connector-program?platform=" + encodeURIComponent(program.platform) +
    "&arch=" + encodeURIComponent(program.arch);
  const res = await fetch(base + path, { method: "GET", headers, credentials: "include" });
  if (!res.ok) throw new Error("HTTP " + res.status);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = program.file_name || ("dsse-connector-" + program.platform + "-" + program.arch);
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function connectorProgramSize(n) {
  const b = Number(n) || 0;
  if (b >= 1048576) return (b / 1048576).toFixed(1) + " MB";
  if (b >= 1024) return Math.round(b / 1024) + " KB";
  return b + " B";
}

// downloadConnectorProfile hands the file over. Same shape as downloadAgentProfile in agentprofile.js —
// one way of doing this across the Console.
//
// ★ IT DIFFERS FROM THE DEVICE PROFILE IN ONE WAY THAT MATTERS. The device configuration deliberately carries
// no identity, because it is the same file for every device in a group; the tokens are made separately, one
// per machine. A connector is one machine and one issue, so its one-time key is INSIDE this file — which is
// why the screen calls the file a key and the device screen does not.
function downloadConnectorProfile(profile, fileName) {
  const text = JSON.stringify(profile, null, 2) + "\n";
  const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

async function showEnrollmentCommand(siteID) {
  // Open the modal immediately with a loading state so the click always has visible feedback, then fetch.
  const host = el("div", {}, el("span", { class: "ui-view-desc", text: bl({ en: "Generating…", ja: "生成中…" }) }));
  const m = uiModal({
    title: bl({ en: "Add a connector to " + siteID, ja: siteID + " にコネクタを追加" }),
    body: [host],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Done", ja: "完了" }), onClick: () => m.close() })],
  });
  let body;
  try {
    const r = await enrollmentCommandFetch(siteID);
    if (!r || !r.ok) { host.innerHTML = ""; host.appendChild(el("p", { class: "ui-view-desc", text: (r && r.body && (r.body.error || r.body.message)) || ("HTTP " + (r ? r.status : "error")) })); return; }
    body = r.body || {};
  } catch (e) { host.innerHTML = ""; host.appendChild(el("p", { class: "ui-view-desc", text: String(e && e.message || e) })); return; }
  const command = body.command || "";
  const verifyCommand = body.verify_command || "";
  // One vocabulary for "take this away with you", used by both steps below.
  // text may be a string or a function, so a block whose content depends on a choice made later still copies
  // what is on the screen rather than what was on it when the button was made.
  const copyButton = (text, primary) => el("button", { class: primary ? "ui-btn ui-btn-primary" : "ui-btn", text: bl({ en: "Copy", ja: "コピー" }), onClick: () => {
    try { navigator.clipboard.writeText(typeof text === "function" ? text() : text); uiToast(bl({ en: "Copied.", ja: "コピーしました。" }), "ok"); }
    catch (e) { uiToast(String(e), "err"); }
  } });
  host.innerHTML = "";
  // ★★★ WHAT THIS CONFIGURES, BEFORE THE COMMAND (2026-08-26). The device configuration screen beside this
  // one states the rule it works to: nothing is typed, every value is one the deployment already knows — and
  // it SHOWS them, because the person deciding whether this is right has to be able to see it. This modal
  // printed one opaque token. Whether the connector it produces could survive losing a region was invisible,
  // and it could not, which is exactly how that went unnoticed.
  const doors = Array.isArray(body.doors) ? body.doors : [];
  const summary = el("div", { style: "margin-bottom:12px" });
  summary.appendChild(el("div", { class: "ui-field-label", text: bl({ en: "This connector will be able to reach", ja: "このコネクタが到達できる先" }) }));
  if (doors.length === 0) {
    summary.appendChild(el("div", { class: "ui-callout ui-callout-warn", text: bl({
      en: "Nothing. This deployment has not been told an address a connector can reach it on.",
      ja: "ありません。この配備は、コネクタが到達できるアドレスを一度も教えられていません。" }) }));
  } else {
    const list = el("ol", { class: "ui-view-desc", style: "margin:4px 0 6px 18px" });
    for (const d of doors) {
      const eq = d.indexOf("=");
      const region = eq > 0 ? d.slice(0, eq) : "";
      const addr = eq > 0 ? d.slice(eq + 1) : d;
      list.appendChild(el("li", {}, [
        el("code", { text: addr }),
        region ? el("span", { class: "ui-field-hint", style: "margin-left:8px", text: region }) : null,
      ]));
    }
    summary.appendChild(list);
    summary.appendChild(el("div", { class: doors.length > 1 ? "ui-field-hint" : "ui-callout ui-callout-warn", text: doors.length > 1
      ? bl({ en: "Tried in this order. Losing one does not take this location off the network.",
             ja: "この順に試します。1つ失っても、この拠点は網から落ちません。" })
      : bl({ en: "One address. If it stops answering, everything behind this connector is unreachable until it comes back.",
             ja: "アドレスは1つです。応答しなくなると、このコネクタの背後にあるものは復帰まで届きません。" }) }));
  }
  summary.appendChild(el("div", { class: body.ca_pinned ? "ui-field-hint" : "ui-callout ui-callout-warn", text: body.ca_pinned
    ? bl({ en: "Its first connection verifies what it is talking to.", ja: "最初の接続で、相手が本物かを確かめます。" })
    : bl({ en: "Its first connection — the one that carries its request for an identity — would trust anything.",
           ja: "最初の接続（身元の要求を運ぶ接続）が、相手を確かめません。" }) }));
  host.appendChild(summary);

  // ★★★ A FILE TO CARRY, THEN A COMMAND, THEN A CHECK (operator's instruction, 2026-08-26). This screen used
  // to hand over one thing: a wall of base64 to select out of a browser and paste into a terminal on another
  // machine. A connector gets what an agent gets — a token AND a profile — and the profile is a FILE, which
  // is copied whole or not at all. A hand-carried token that arrives short one door produces a connector that
  // enrols, works, and silently has one region instead of two; nothing downstream reports that.
  //
  // ★ AND THE THIRD STEP IS THE ONE NOBODY HAD. The Console shows Connected the moment a tunnel arrives, so a
  // connector holding one of its two doors looks exactly like one holding both — until the day the door it
  // holds is the one that goes. That question is answered on the machine, so the screen hands over the way to
  // ask it, in the same breath as the thing to ask about.
  const profile = body.profile || null;
  const fileName = "dsse-connector-" + String(siteID).replace(/[^A-Za-z0-9._-]+/g, "-") + ".json";
  let setRunCommand = () => {};

  if (profile) {
    host.appendChild(el("div", { class: "ui-field-label", style: "margin-top:4px", text: bl({ en: "1. Put these on the machine at this location", ja: "1. この拠点のマシンに置く" }) }));

    // ★★★ THE PROGRAM TRAVELS WITH THE PROFILE (operator's instruction, 2026-08-26). This screen told the
    // customer to run dsse-connector-install and nothing in the product put that program on their machine.
    // The endpoint agent's signed artifact lane cannot serve it — that route lives inside the tunnel under
    // mandatory mTLS, and a connector has no identity until the program it does not have has enrolled it. So
    // it is carried by the same person, in the same act, from this screen.
    // Assigned once the run block below exists. The program list arrives asynchronously, so the choice can
    // land before or after that block is built; a holder declared here is true in both orders, and keeps this
    // wiring inside the one modal rather than on window.
    const programHost = el("div", { style: "margin:6px 0 10px 0" });
    host.appendChild(programHost);
    connectorProgramsFetch().then((programs) => {
      programHost.innerHTML = "";
      if (!programs.length) {
        // ★ A ZERO THE READER CAN ACT ON. Not "0 programs" — what the zero means for the person about to walk
        // to a machine, and who fixes it.
        programHost.appendChild(el("div", { class: "ui-callout ui-callout-warn", text: bl({
          en: "This deployment holds no connector program, so there is nothing to put on the machine. Ask whoever runs this deployment to add one for that machine's operating system.",
          ja: "この配備はコネクタのプログラムを持っていないため、マシンに置くものがありません。この配備の運用者に、そのマシンの OS 向けのものを追加してもらってください。" }) }));
        return;
      }
      const pick = el("select", { class: "ui-input", style: "max-width:220px" });
      for (const p of programs) {
        pick.appendChild(el("option", { value: p.platform + "/" + p.arch, text: p.platform + " / " + p.arch }));
      }
      const detail = el("div", { class: "ui-field-hint", style: "margin-top:4px" });
      const chosen = () => programs.find((p) => p.platform + "/" + p.arch === pick.value) || programs[0];
      const describe = () => {
        const p = chosen();
        detail.innerHTML = "";
        detail.appendChild(el("code", { text: p.file_name || "" }));
        detail.appendChild(el("span", { style: "margin-left:8px", text: connectorProgramSize(p.size) }));
        // The digest, so the person who carries the file can check what arrived on the far machine.
        detail.appendChild(el("div", { style: "margin-top:2px" }, el("code", { text: "sha256 " + String(p.sha256 || "").slice(0, 16) + "…" })));
        // ★★★ WHICH BUILD THIS IS, BECAUSE THE DEPLOYMENT ASKS THAT QUESTION ABOUT EVERY OTHER NODE
        // (2026-09-04, found by publishing a second architecture and looking at what the screen then offered).
        // This screen hands over the program a connector will run for months. `-verify` asks whether every
        // node runs the same build and reports a disagreement by name; a connector installed from a program
        // nobody could identify is outside that question entirely. The deployment stamps what it seeds from
        // its own image, and an operator publishing another architecture declares it with x-artifact-version.
        // A program with neither says so — "not stated" is a fact about the program, and blank was being read
        // as agreement.
        detail.appendChild(el("div", { style: "margin-top:2px", class: "ui-view-desc", text: p.version
          ? bl({ en: "build " + p.version, ja: "ビルド " + p.version })
          : bl({ en: "build not stated — whoever published this did not say which one it is",
                 ja: "ビルド不明 — 公開した人がどのビルドかを申告していません" }) }));
        // The command below opens what this particular download actually is.
        setRunCommand(p);
      };
      pick.addEventListener("change", describe);
      const dlProgram = el("button", { class: "ui-btn", text: bl({ en: "Download the program", ja: "プログラムをダウンロード" }), onClick: async () => {
        try {
          await downloadConnectorProgram(chosen());
          dlProgram.textContent = bl({ en: "Downloaded — download again", ja: "ダウンロード済み — 再ダウンロード" });
        } catch (e) { uiToast(String(e && e.message || e), "err"); }
      } });
      programHost.appendChild(el("div", { style: "display:flex;align-items:center;gap:10px" }, [dlProgram, pick]));
      programHost.appendChild(detail);
      describe();
    });

    const dl = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Download the settings", ja: "設定をダウンロード" }), onClick: () => {
      try {
        downloadConnectorProfile(profile, fileName);
        // The same acknowledgement the device configuration screen gives, for the same reason: a download is
        // the one action in this modal with no visible result, and pressing it twice is a normal thing to do.
        dl.textContent = bl({ en: "Downloaded — download again", ja: "ダウンロード済み — 再ダウンロード" });
      } catch (e) { uiToast(String(e && e.message || e), "err"); }
    } });
    host.appendChild(el("div", { style: "display:flex;align-items:center;gap:10px;margin:6px 0" }, [dl,
      el("code", { class: "ui-field-hint", text: fileName })]));
    host.appendChild(el("div", { class: "ui-callout ui-callout-warn", text: bl({
      en: "Download it now — the one-time key inside is not shown again. Until this connector has run once, the file is a key: keep it as you would a password.",
      ja: "今ダウンロードを。中のワンタイムキーは再表示されません。このコネクタが一度動くまで、このファイルは鍵です。パスワードと同じに扱ってください。" }) }));
  }

  // ★ THE COMMAND IS BUILT FROM WHAT WAS ACTUALLY PUBLISHED, not from a guess. An archive has to be opened
  // before anything in it can run, and a screen that omits that line sends somebody to a machine to be told
  // "command not found" — while a screen that always prints it is wrong for a deployment that published a
  // plain binary. The published file name is the only thing here that knows which it is.
  const runCommandFor = (program) => {
    const lines = [];
    const name = program && program.file_name ? String(program.file_name) : "";
    if (/\.(tar\.gz|tgz)$/i.test(name)) lines.push("tar xzf " + name);
    else if (/\.zip$/i.test(name)) lines.push("unzip " + name);
    lines.push((profile ? "./dsse-connector-install --profile " + fileName : command));
    return lines.join("\n");
  };
  host.appendChild(el("div", { class: "ui-field-label", style: "margin-top:14px", text: bl({ en: "2. Run this on that machine", ja: "2. そのマシンで実行" }) }));
  let runCommand = runCommandFor(null);
  const runPre = el("div", { class: "ui-preview", style: "margin:6px 0", text: runCommand });
  setRunCommand = (program) => { runCommand = runCommandFor(program); runPre.textContent = runCommand; };
  const runCopy = copyButton(() => runCommand, !profile);
  host.appendChild(runPre);
  host.appendChild(el("div", { style: "display:flex;align-items:center;gap:10px" }, [runCopy,
    el("span", { class: "ui-field-hint", text: bl({
      en: "It starts on its own and starts again after a restart. It appears above as Connected.",
      ja: "自動で起動し、マシンを再起動しても起動し直します。上に「接続中」で表示されます。" }) })]));

  if (verifyCommand) {
    host.appendChild(el("div", { class: "ui-field-label", style: "margin-top:14px", text: bl({ en: (profile ? "3." : "2.") + " Then check it on the same machine", ja: (profile ? "3." : "2.") + " 同じマシンで確かめる" }) }));
    host.appendChild(el("div", { class: "ui-preview", style: "margin:6px 0", text: verifyCommand }));
    host.appendChild(el("div", { style: "display:flex;align-items:center;gap:10px" }, [copyButton(verifyCommand, false), el("span", { class: "ui-field-hint", text: bl({
      en: "Says whether it got in, whether its certificate came from here, and whether every address above answers it.",
      ja: "入れたか、証明書がここから出たものか、上のアドレスすべてが応答するかを答えます。" }) })]));
  }

  // For a machine a file cannot be carried to. Same single issue as the profile above — not a second one.
  if (profile && command) {
    const alt = el("details", { style: "margin-top:14px" });
    alt.appendChild(el("summary", { class: "ui-field-hint", style: "cursor:pointer", text: bl({ en: "Cannot put a file on that machine", ja: "そのマシンにファイルを置けない場合" }) }));
    alt.appendChild(el("div", { class: "ui-preview", style: "margin:6px 0", text: command }));
    alt.appendChild(el("div", { style: "display:flex;align-items:center;gap:10px" }, [copyButton(command, false), el("span", { class: "ui-field-hint", text: bl({
      en: "The same one-time key, typed instead of carried.", ja: "同じワンタイムキーを、運ぶ代わりに打ち込む形です。" }) })]));
    host.appendChild(alt);
  }
}

// deleteSite removes the persistent Site record (its connectors are not deleted) after a danger confirm.
async function deleteSite(siteID, name, detailModal, host) {
  const ok = await uiConfirm({
    title: bl({ en: "Delete this site?", ja: "このサイトを削除?" }),
    body: bl({ en: "\"" + (name || siteID) + "\" is removed. Connectors are not deleted, but the Site's name, region, and HA settings are lost.", ja: "「" + (name || siteID) + "」を削除します。コネクタは削除されませんが、サイトの名前・リージョン・HA 設定は失われます。" }),
    confirmLabel: bl({ en: "Delete", ja: "削除" }), danger: true,
  });
  if (!ok) return;
  const r = await apiFetch("DELETE", "/admin/sites/" + encodeURIComponent(siteID));
  if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
  uiToast(bl({ en: "Site deleted.", ja: "サイトを削除しました。" }), "ok");
  if (detailModal) detailModal.close();
  if (host) renderSiteList(host);
}
