"use strict";

// ---------------------------------------------------------------------------
// "Groups & Services" view — the named things your rules refer to: devices/servers (endpoints), groups, and
// services (port sets). Rewritten on the shared ui.js primitives (tables, modal forms, uiConfirm/uiToast/uiState)
// so it is consistent with the rest of the product UX (no inline forms / window.prompt / window.confirm).
// Backend: /admin/assets/{endpoints,groups,services}, /admin/assets/groups/{id}/members, /admin/catalog-groups,
// /admin/effective-policy. app.js dispatches here for custom:"assets".
// ---------------------------------------------------------------------------

let assetsTab = "endpoints"; // "endpoints" | "groups" | "services"
const _assetsFilter = { ep: "", epType: "all", grp: "", svc: "" }; // per-tab search/filter, kept across re-renders
const _inspCache = {}; // address -> "inspect"|"bypass" so search-filtering does not re-query effective-policy

function renderAssetsView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "Groups & Services", ja: "グループ・サービス" }) }),
      el("p", { class: "ui-view-desc", text: bl({
        en: "The named things your rules point at. Devices that connect appear here automatically; add servers and other destinations, group them, and name the port sets (services) your rules allow.",
        ja: "ルールが指す名前付きの対象。接続するデバイスは自動表示されます。サーバ等の宛先を追加し、グループ化し、ルールが許可するポートの集合(サービス)に名前を付けます。",
      }) }),
    ]),
  ]));
  const tabs = uiTabs([
    { id: "endpoints", label: bl({ en: "Devices & Servers", ja: "デバイス・サーバ" }) },
    { id: "groups", label: bl({ en: "Groups", ja: "グループ" }) },
    { id: "services", label: bl({ en: "Services", ja: "サービス" }) },
  ], assetsTab, (id) => { assetsTab = id; renderAssetsView(content); });
  content.appendChild(tabs);
  const section = el("div", {});
  content.appendChild(section);
  if (assetsTab === "groups") renderGroupsSection(section);
  else if (assetsTab === "services") renderServicesSection(section);
  else renderEndpointsSection(section);
}

async function loadAssetsArr(path) {
  const r = await apiFetch("GET", path);
  if (!r.ok) throw new Error("HTTP " + r.status);
  if (r.body === null) return [];
  if (!Array.isArray(r.body)) throw new Error("Invalid catalog response");
  return r.body;
}
function platLabel(p) { return p === "macos" ? "macOS" : p === "windows" ? "Windows" : "—"; }

// ---- Devices & Servers (endpoints) ----------------------------------------

async function renderEndpointsSection(section) {
  uiState(section, "loading");
  const current = freshRender(section);
  let eps;
  try { eps = await loadAssetsArr("/admin/assets/endpoints"); }
  catch (e) { if (!current()) return; uiState(section, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderEndpointsSection(section) }); return; }
  eps = eps.filter((ep) => !ep.built_in);

  if (!current()) return;
  section.innerHTML = "";
  const search = el("input", { class: "ui-input ui-search", type: "search", placeholder: bl({ en: "Search by name or address…", ja: "名前・アドレスで検索…" }) });
  search.value = _assetsFilter.ep;
  const typeF = uiField({ name: "type", type: "select", value: _assetsFilter.epType, options: [
    { value: "all", label: bl({ en: "All types", ja: "全種別" }) },
    { value: "device", label: bl({ en: "Devices", ja: "デバイス" }) },
    { value: "server", label: bl({ en: "Servers", ja: "サーバ" }) },
  ] });
  typeF.el.style.marginBottom = "0";
  const tableHost = el("div", {});
  const draw = () => {
    const q = _assetsFilter.ep.trim().toLowerCase();
    const filtered = eps.filter((ep) => {
      const isDevice = ep.kind === "steered_device";
      if (_assetsFilter.epType === "device" && !isDevice) return false;
      if (_assetsFilter.epType === "server" && isDevice) return false;
      if (q && !((ep.alias || "").toLowerCase().includes(q) || (ep.address || "").toLowerCase().includes(q) || (ep.identity || "").toLowerCase().includes(q))) return false;
      return true;
    });
    if (!eps.length) { uiState(tableHost, "empty", bl({ en: "No devices or servers yet. Devices appear when they connect; add a server with “Add server”.", ja: "デバイス・サーバがありません。デバイスは接続時に表示されます。「サーバを追加」で追加してください。" })); return; }
    if (!filtered.length) { uiState(tableHost, "empty", bl({ en: "No matches.", ja: "一致なし。" })); return; }
    const rows = filtered.map((ep) => {
      const actions = el("div", { class: "ui-row-actions" });
      if (ep.source === "application") {
        actions.appendChild(el("span", { text: bl({ en: "Managed in Applications", ja: "アプリケーションで管理" }) }));
      } else actions.appendChild(el("button", { class: "ui-btn ui-btn-sm", text: ep.kind === "network" ? bl({ en: "Edit", ja: "編集" }) : bl({ en: "Rename", ja: "名前変更" }), onClick: () => openEndpointForm(section, ep) }));
      if (ep.source !== "enrolled" && ep.source !== "application") {
        actions.appendChild(document.createTextNode(" "));
        actions.appendChild(el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Remove", ja: "削除" }), onClick: () => removeEndpoint(ep, section) }));
      }
      const insCell = el("td", { text: "" });
      if (ep.kind === "network" && ep.address) {
        const cached = _inspCache[ep.address];
        const setBadge = (dec) => { insCell.innerHTML = ""; insCell.appendChild(uiBadge(dec === "bypass" ? bl({ en: "Bypassed", ja: "バイパス" }) : bl({ en: "Inspected", ja: "傍受" }), dec === "bypass" ? "warn" : "ok")); };
        if (cached) setBadge(cached);
        else {
          insCell.textContent = "…";
          apiFetch("GET", "/admin/effective-policy?destination=" + encodeURIComponent(ep.address)).then((r) => {
            const ins = r && r.ok && r.body && r.body.inspection;
            if (!ins) { insCell.textContent = "—"; return; }
            _inspCache[ep.address] = ins.decision; setBadge(ins.decision);
          }).catch(() => { insCell.textContent = "—"; });
        }
      } else { insCell.textContent = "—"; }
      return el("tr", {}, [
        el("td", {}, [el("strong", { text: ep.alias || "(unnamed)" })]),
        el("td", {}, uiBadge(ep.kind === "steered_device" ? bl({ en: "Device", ja: "デバイス" }) : bl({ en: "Server", ja: "サーバ" }), ep.kind === "steered_device" ? "ok" : "off")),
        el("td", { text: ep.kind === "steered_device" ? platLabel(ep.platform) : "—" }),
        el("td", {}, uiBadge(ep.source === "application" ? bl({ en: "Application", ja: "アプリケーション" }) : ep.source === "enrolled" ? bl({ en: "Automatic", ja: "自動" }) : bl({ en: "Added by you", ja: "手動追加" }), "off")),
        el("td", {}, el("code", { text: ep.identity || ep.address || "—" })),
        insCell,
        el("td", { class: "ui-row-actions" }, actions),
      ]);
    });
    tableHost.innerHTML = "";
    tableHost.appendChild(el("table", { class: "ui-table" }, [
      el("thead", {}, el("tr", {}, ["Name", bl({ en: "Type", ja: "種別" }), bl({ en: "Platform", ja: "OS" }), bl({ en: "Source", ja: "出所" }), bl({ en: "Address", ja: "アドレス" }), bl({ en: "Interception", ja: "傍受" }), bl({ en: "Actions", ja: "操作" })].map((x) => el("th", { text: x })))),
      el("tbody", {}, rows),
    ]));
    tableHost.appendChild(el("p", { class: "ui-view-desc", text: bl({ en: "Showing ", ja: "表示 " }) + filtered.length + " / " + eps.length }));
  };
  search.addEventListener("input", () => { _assetsFilter.ep = search.value; draw(); });
  typeF.el.querySelector("select").addEventListener("change", () => { _assetsFilter.epType = typeF.get(); draw(); });
  section.appendChild(el("div", { class: "ui-toolbar" }, [search, typeF.el, el("span", { class: "ui-spacer" }),
    el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "+ Add server", ja: "+ サーバを追加" }), onClick: () => openEndpointForm(section) })]));
  section.appendChild(tableHost);
  draw();
}

function openEndpointForm(section, ep) {
  ep = ep || null;
  const network = !ep || ep.kind === "network";
  const aliasF = uiField({ name: "alias", label: bl({ en: "Name", ja: "名前" }), required: true, value: ep ? ep.alias : "", placeholder: bl({ en: "e.g. prod database", ja: "例: 本番DB" }) });
  const addrF = uiField({ name: "address", label: bl({ en: "Address", ja: "アドレス" }), required: true, value: ep ? ep.address : "", placeholder: bl({ en: "IP, network range, or domain", ja: "IP・ネットワーク範囲・ドメイン" }), hint: bl({ en: "e.g. 10.0.0.10, 10.0.0.0/24, or db.example.com", ja: "例: 10.0.0.10 / 10.0.0.0/24 / db.example.com" }) });
  const body = network ? [aliasF.el, addrF.el] : [aliasF.el, el("p", { class: "ui-field-hint", text: bl({ en: "This device connected automatically; you can rename it here.", ja: "このデバイスは自動で接続されました。名前のみ変更できます。" }) })];
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: ep ? bl({ en: "Save", ja: "保存" }) : bl({ en: "Add server", ja: "サーバを追加" }) });
  const m = uiModal({ title: ep ? bl({ en: "Edit", ja: "編集" }) : bl({ en: "Add a server", ja: "サーバを追加" }), body,
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit] });
  submit.addEventListener("click", async () => {
    if (!aliasF.validate()) return;
    if (network && !addrF.validate()) return;
    submit.disabled = true;
    const payload = ep ? Object.assign({}, ep, { alias: aliasF.get() }) : { alias: aliasF.get(), kind: "network", source: "manual", steered: false };
    if (network) payload.address = addrF.get();
    try {
      const r = await apiFetch("POST", "/admin/assets/endpoints", payload);
      if (!r.ok) { submit.disabled = false; const msg = (r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status); addrF.setError(msg); uiToast(msg, "err"); return; }
      m.close(); uiToast(ep ? bl({ en: "Saved.", ja: "保存しました。" }) : bl({ en: "Server added.", ja: "サーバを追加しました。" }), "ok");
      renderEndpointsSection(section);
    } catch (e) { submit.disabled = false; uiToast(String(e), "err"); }
  });
  aliasF.focus();
}

async function removeEndpoint(ep, section) {
  const ok = await uiConfirm({ title: bl({ en: "Remove this?", ja: "削除しますか?" }), body: bl({ en: "Removes \"" + (ep.alias || ep.id) + "\". Rules that referenced it will no longer match it.", ja: "「" + (ep.alias || ep.id) + "」を削除します。これを参照していたルールは一致しなくなります。" }), confirmLabel: bl({ en: "Remove", ja: "削除" }), danger: true });
  if (!ok) return;
  const r = await apiFetch("DELETE", "/admin/assets/endpoints/" + encodeURIComponent(ep.id));
  if (!r.ok) { uiToast("HTTP " + r.status, "err"); return; }
  uiToast(bl({ en: "Removed.", ja: "削除しました。" }), "ok");
  renderEndpointsSection(section);
}

// ---- Groups ---------------------------------------------------------------

function dynamicSummary(rule) {
  const parts = [];
  if (rule.platform) parts.push(platLabel(rule.platform));
  if (rule.steered === true) parts.push(bl({ en: "connected", ja: "接続中" }));
  if (rule.tag) parts.push("#" + rule.tag);
  if (rule.subnet) parts.push(rule.subnet);
  return bl({ en: "Auto: ", ja: "自動: " }) + (parts.join(", ") || bl({ en: "any", ja: "すべて" }));
}

async function renderGroupsSection(section) {
  uiState(section, "loading");
  const current = freshRender(section);
  let groups, eps;
  try { [groups, eps] = await Promise.all([loadAssetsArr("/admin/assets/groups"), loadAssetsArr("/admin/assets/endpoints")]); }
  catch (e) { if (!current()) return; uiState(section, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderGroupsSection(section) }); return; }
  groups = groups.filter((g) => !g.built_in);

  if (!current()) return;
  section.innerHTML = "";
  const search = el("input", { class: "ui-input ui-search", type: "search", placeholder: bl({ en: "Search groups…", ja: "グループを検索…" }) });
  search.value = _assetsFilter.grp;
  const groupsHost = el("div", {});
  const draw = () => {
    const q = _assetsFilter.grp.trim().toLowerCase();
    const filtered = groups.filter((g) => !q || (g.alias || "").toLowerCase().includes(q));
    if (!groups.length) { uiState(groupsHost, "empty", bl({ en: "No groups yet. Create one to bundle members, or auto-include devices by a rule.", ja: "グループがありません。メンバーをまとめる、または条件で自動追加するグループを作成してください。" })); return; }
    if (!filtered.length) { uiState(groupsHost, "empty", bl({ en: "No matches.", ja: "一致なし。" })); return; }
    const rows = filtered.map((g) => {
      const tags = el("td", {});
      if (g.tier0) { tags.appendChild(uiBadge(bl({ en: "Sensitive", ja: "機密" }), "warn")); tags.appendChild(document.createTextNode(" ")); }
      if (g.dynamic) { tags.appendChild(uiBadge(dynamicSummary(g.dynamic), "off")); }
      if (g.static_members && g.static_members.length) { tags.appendChild(document.createTextNode(" ")); tags.appendChild(uiBadge(g.static_members.length + bl({ en: " chosen", ja: " 件選択" }), "off")); }
      return el("tr", {}, [
        el("td", {}, el("strong", { text: g.alias })),
        tags,
        el("td", { class: "ui-row-actions" }, [
          el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Members", ja: "メンバー" }), onClick: () => showGroupMembers(g) }),
          document.createTextNode(" "),
          el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Delete", ja: "削除" }), onClick: () => removeGroup(g, section) }),
        ]),
      ]);
    });
    groupsHost.innerHTML = "";
    groupsHost.appendChild(el("table", { class: "ui-table" }, [
      el("thead", {}, el("tr", {}, [bl({ en: "Group", ja: "グループ" }), bl({ en: "Members", ja: "メンバー" }), bl({ en: "Actions", ja: "操作" })].map((x) => el("th", { text: x })))),
      el("tbody", {}, rows),
    ]));
  };
  search.addEventListener("input", () => { _assetsFilter.grp = search.value; draw(); });
  section.appendChild(el("div", { class: "ui-toolbar" }, [search, el("span", { class: "ui-spacer" }),
    el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "+ Create group", ja: "+ グループ作成" }), onClick: () => openGroupForm(section, eps) })]));
  section.appendChild(groupsHost);
  draw();
  renderCatalogGroups(section);
}

function assetGroupMemberRows(ids, endpoints) {
  if (!Array.isArray(ids) || !ids.every((id) => typeof id === "string" && id)) throw new Error("Invalid group member list");
  if (!Array.isArray(endpoints) || !endpoints.every((ep) => ep && typeof ep.id === "string" && ep.id)) throw new Error("Invalid endpoint list");
  const byID = new Map(endpoints.map((ep) => [ep.id, ep]));
  return ids.map((id) => byID.get(id) || { id, alias: id });
}

async function showGroupMembers(g) {
  const bodyHost = el("div", {}, el("span", { class: "ui-spinner" }));
  const m = uiModal({ title: bl({ en: "Members of ", ja: "メンバー: " }) + g.alias, body: [bodyHost], footer: [el("button", { class: "ui-btn", text: bl({ en: "Close", ja: "閉じる" }), onClick: () => m.close() })] });
  try {
    const [ids, endpoints] = await Promise.all([
      loadAssetsArr("/admin/assets/groups/" + encodeURIComponent(g.id) + "/members"),
      loadAssetsArr("/admin/assets/endpoints"),
    ]);
    const list = assetGroupMemberRows(ids, endpoints);
    bodyHost.innerHTML = "";
    if (!list.length) { bodyHost.appendChild(el("p", { class: "ui-view-desc", text: bl({ en: "No members match right now.", ja: "現在一致するメンバーはありません。" }) })); return; }
    list.forEach((mem) => bodyHost.appendChild(el("div", { class: "ui-checkrow" }, [uiBadge(platLabel(mem.platform), "off"), el("span", { text: mem.alias || mem.id })])));
  } catch (e) { bodyHost.textContent = String(e); }
}

function openGroupForm(section, eps) {
  const aliasF = uiField({ name: "alias", label: bl({ en: "Group name", ja: "グループ名" }), required: true, placeholder: bl({ en: "e.g. Windows servers", ja: "例: Windows サーバ" }) });
  const tier0F = uiField({ name: "tier0", type: "checkbox", label: bl({ en: "Mark as sensitive (extra protection)", ja: "機密としてマーク(追加保護)" }) });
  const platF = uiField({ name: "plat", label: bl({ en: "Auto-include by platform", ja: "OS で自動追加" }), type: "select", value: "", options: [
    { value: "", label: bl({ en: "Any / off", ja: "指定なし" }) }, { value: "macos", label: "macOS" }, { value: "windows", label: "Windows" } ] });
  const subnetF = uiField({ name: "subnet", label: bl({ en: "Auto-include by network range", ja: "ネットワーク範囲で自動追加" }), placeholder: "10.0.0.0/24" });
  // static members checklist
  const checks = {};
  const checklist = el("div", { class: "ui-checklist" });
  eps.filter((ep) => !ep.built_in).forEach((ep) => {
    const cb = el("input", { type: "checkbox" }); checks[ep.id] = cb;
    checklist.appendChild(el("label", { class: "ui-checkrow" }, [cb, el("span", { text: ep.alias })]));
  });
  if (!Object.keys(checks).length) checklist.appendChild(el("span", { class: "ui-view-desc", text: bl({ en: "Nothing to choose yet.", ja: "選べる対象がありません。" }) }));
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Create group", ja: "グループ作成" }) });
  const m = uiModal({ title: bl({ en: "Create a group", ja: "グループを作成" }), body: [
    aliasF.el, tier0F.el,
    el("div", { class: "ui-field-label", text: bl({ en: "Choose members", ja: "メンバーを選択" }) }), checklist,
    el("div", { style: "height:12px" }), platF.el, subnetF.el,
  ], footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit] });
  submit.addEventListener("click", async () => {
    if (!aliasF.validate()) return;
    const staticMembers = Object.keys(checks).filter((id) => checks[id].checked);
    const payload = { alias: aliasF.get(), tier0: tier0F.get() };
    if (staticMembers.length) payload.static_members = staticMembers;
    const rule = {};
    if (platF.get()) rule.platform = platF.get();
    if (subnetF.get()) rule.subnet = subnetF.get();
    if (Object.keys(rule).length) payload.dynamic = rule;
    submit.disabled = true;
    try {
      const r = await apiFetch("POST", "/admin/assets/groups", payload);
      if (!r.ok) { submit.disabled = false; const msg = (r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status); aliasF.setError(msg); uiToast(msg, "err"); return; }
      m.close(); uiToast(bl({ en: "Group created.", ja: "グループを作成しました。" }), "ok");
      renderGroupsSection(section);
    } catch (e) { submit.disabled = false; uiToast(String(e), "err"); }
  });
  aliasF.focus();
}

async function removeGroup(g, section) {
  const ok = await uiConfirm({ title: bl({ en: "Delete this group?", ja: "このグループを削除?" }), body: bl({ en: "Deletes \"" + g.alias + "\". Rules that referenced the group will no longer match its members.", ja: "「" + g.alias + "」を削除します。このグループを参照していたルールはメンバーに一致しなくなります。" }), confirmLabel: bl({ en: "Delete", ja: "削除" }), danger: true });
  if (!ok) return;
  const r = await apiFetch("DELETE", "/admin/assets/groups/" + encodeURIComponent(g.id));
  if (!r.ok) { uiToast("HTTP " + r.status, "err"); return; }
  uiToast(bl({ en: "Group deleted.", ja: "グループを削除しました。" }), "ok");
  renderGroupsSection(section);
}

async function renderCatalogGroups(section) {
  let groups;
  try { const r = await apiFetch("GET", "/admin/catalog-groups"); groups = (r.ok && r.body && r.body.groups) || []; } catch (e) { return; }
  if (!groups.length) return;
  section.appendChild(el("h3", { class: "ui-field-label", style: "margin-top:22px", text: bl({ en: "Built-in groups (read-only)", ja: "組込グループ(読み取り専用)" }) }));
  const catLabel = { sign_in: "Sign-in", ai: "AI", collaboration: "Collaboration", optimize: bl({ en: "Bypassed", ja: "バイパス" }) };
  const rows = groups.map((g) => el("tr", {}, [
    el("td", {}, el("strong", { text: g.name })),
    el("td", {}, uiBadge(g.axis === "bypass" ? bl({ en: "Bypassed", ja: "バイパス" }) : bl({ en: "Inspected", ja: "傍受" }), g.axis === "bypass" ? "warn" : "ok")),
    el("td", { text: catLabel[g.category] || g.category }),
    el("td", { class: "ui-view-desc", text: (g.patterns || []).join(", ") }),
  ]));
  section.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [bl({ en: "Group", ja: "グループ" }), bl({ en: "Interception", ja: "傍受" }), bl({ en: "Category", ja: "分類" }), bl({ en: "Includes", ja: "対象" })].map((x) => el("th", { text: x })))),
    el("tbody", {}, rows),
  ]));
}

// ---- Services -------------------------------------------------------------

async function renderServicesSection(section) {
  uiState(section, "loading");
  const current = freshRender(section);
  let svcs;
  try { svcs = await loadAssetsArr("/admin/assets/services"); }
  catch (e) { if (!current()) return; uiState(section, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderServicesSection(section) }); return; }

  if (!current()) return;
  section.innerHTML = "";
  const search = el("input", { class: "ui-input ui-search", type: "search", placeholder: bl({ en: "Search services…", ja: "サービスを検索…" }) });
  search.value = _assetsFilter.svc;
  const tableHost = el("div", {});
  const draw = () => {
    const q = _assetsFilter.svc.trim().toLowerCase();
    const filtered = svcs.filter((s) => {
      if (!q) return true;
      if ((s.alias || "").toLowerCase().includes(q)) return true;
      return (s.ports || []).some((pp) => (pp.protocol + "/" + pp.port).includes(q));
    });
    if (!svcs.length) { uiState(tableHost, "empty", bl({ en: "No services yet. Add one to name a port set your rules can allow.", ja: "サービスがありません。ルールが許可するポート集合に名前を付けて追加してください。" })); return; }
    if (!filtered.length) { uiState(tableHost, "empty", bl({ en: "No matches.", ja: "一致なし。" })); return; }
    const rows = filtered.map((svc) => {
      const ports = el("td", {});
      (svc.ports || []).forEach((pp) => { ports.appendChild(uiBadge(pp.protocol + "/" + pp.port, "off")); ports.appendChild(document.createTextNode(" ")); });
      return el("tr", {}, [
        el("td", {}, el("strong", { text: svc.alias })),
        ports,
        el("td", { class: "ui-row-actions" }, el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Delete", ja: "削除" }), onClick: () => removeService(svc, section) })),
      ]);
    });
    tableHost.innerHTML = "";
    tableHost.appendChild(el("table", { class: "ui-table" }, [
      el("thead", {}, el("tr", {}, [bl({ en: "Service", ja: "サービス" }), bl({ en: "Ports", ja: "ポート" }), bl({ en: "Actions", ja: "操作" })].map((x) => el("th", { text: x })))),
      el("tbody", {}, rows),
    ]));
  };
  search.addEventListener("input", () => { _assetsFilter.svc = search.value; draw(); });
  section.appendChild(el("div", { class: "ui-toolbar" }, [search, el("span", { class: "ui-spacer" }),
    el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "+ Add service", ja: "+ サービス追加" }), onClick: () => openServiceForm(section) })]));
  section.appendChild(tableHost);
  draw();
}

function servicePortsFromRows(rows) {
  if (!Array.isArray(rows) || !rows.length) return null;
  const ports = [];
  for (const row of rows) {
    const text = String(row.port).trim();
    if (!/^\d+$/.test(text) || !["tcp", "udp"].includes(row.protocol)) return null;
    const port = Number(text);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
    ports.push({ protocol: row.protocol, port });
  }
  return ports;
}

function openServiceForm(section) {
  const aliasF = uiField({ name: "alias", label: bl({ en: "Service name", ja: "サービス名" }), required: true, placeholder: bl({ en: "e.g. PostgreSQL", ja: "例: PostgreSQL" }) });
  const portRows = [];
  const portsHost = el("div", {});
  const renderPorts = () => {
    portsHost.innerHTML = "";
    portRows.forEach((pr, i) => {
      const proto = el("select", { class: "ui-select" }, [el("option", { value: "tcp", text: "TCP" }), el("option", { value: "udp", text: "UDP" })]);
      proto.value = pr.protocol;
      const port = el("input", { class: "ui-input", type: "number", value: pr.port || "", placeholder: bl({ en: "port", ja: "ポート" }) });
      proto.addEventListener("change", () => { pr.protocol = proto.value; });
      port.addEventListener("input", () => { pr.port = port.value; });
      proto.style.maxWidth = "110px"; port.style.maxWidth = "140px";
      portsHost.appendChild(el("div", { class: "ui-toolbar" }, [proto, port, el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Remove", ja: "削除" }), onClick: () => { portRows.splice(i, 1); renderPorts(); } })]));
    });
  };
  portRows.push({ protocol: "tcp", port: "" });
  renderPorts();
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Add service", ja: "サービス追加" }) });
  const m = uiModal({ title: bl({ en: "Add a service", ja: "サービスを追加" }), body: [
    aliasF.el,
    el("div", { class: "ui-field-label", text: bl({ en: "Ports", ja: "ポート" }) }), portsHost,
    el("div", { style: "margin-top:6px" }, el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "+ Add port", ja: "+ ポート追加" }), onClick: () => { portRows.push({ protocol: "tcp", port: "" }); renderPorts(); } })),
  ], footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit] });
  submit.addEventListener("click", async () => {
    if (submit.disabled || !aliasF.validate()) return;
    const ports = servicePortsFromRows(portRows);
    if (!ports) { uiToast(bl({ en: "Enter a whole port number from 1 to 65535 in every row.", ja: "各行のポートに1から65535の整数を入力してください。" }), "err"); return; }
    submit.disabled = true;
    try {
      const r = await apiFetch("POST", "/admin/assets/services", { alias: aliasF.get(), ports });
      if (!r.ok) { submit.disabled = false; uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
      m.close(); uiToast(bl({ en: "Service added.", ja: "サービスを追加しました。" }), "ok");
      renderServicesSection(section);
    } catch (e) { submit.disabled = false; uiToast(String(e), "err"); }
  });
  aliasF.focus();
}

async function removeService(svc, section) {
  const ok = await uiConfirm({ title: bl({ en: "Delete this service?", ja: "このサービスを削除?" }), body: bl({ en: "Deletes \"" + svc.alias + "\".", ja: "「" + svc.alias + "」を削除します。" }), confirmLabel: bl({ en: "Delete", ja: "削除" }), danger: true });
  if (!ok) return;
  const r = await apiFetch("DELETE", "/admin/assets/services/" + encodeURIComponent(svc.id));
  if (!r.ok) { uiToast("HTTP " + r.status, "err"); return; }
  uiToast(bl({ en: "Service deleted.", ja: "サービスを削除しました。" }), "ok");
  renderServicesSection(section);
}

// ---- shared tiny helper ----
function emptyBox(msg) { const h = el("div", {}); uiState(h, "empty", msg); return h; }
