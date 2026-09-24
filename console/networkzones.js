"use strict";

// networkzones.js — the "Networks" catalog: define a network once, see which sites use it. Backend:
// /admin/vlan-objects {objects}. (The old zone-to-zone "Rules" tab was a firewall-rule EXPORT for an external
// firewall, not in-product enforcement — removed from the UI; the export capability stays in the backend.)

function renderNetworkZonesView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "Networks", ja: "ネットワーク" }) }),
      el("p", { class: "ui-view-desc", text: bl({ en: "Define a network once here; sites and everything else select it.", ja: "ネットワークをここで一度定義。サイト等はここから選択します。" }) }),
    ]),
  ]));
  const section = el("div", {});
  content.appendChild(section);
  renderZones(section);
}

function nzCatalogRows(response, key) {
  if (!response.ok) throw new Error("HTTP " + response.status);
  if (!response.body || !Object.hasOwn(response.body, key)) throw new Error("Invalid network catalog response");
  const rows = response.body[key];
  if (rows === null) return [];
  if (!Array.isArray(rows) || rows.some(row => !row || typeof row !== "object" || Array.isArray(row))) {
    throw new Error("Invalid network catalog response");
  }
  return rows;
}

// All site bindings must be available before declaring a network unused.
async function nzSiteMembership() {
  const map = Object.create(null);
  const sites = nzCatalogRows(await apiFetch("GET", "/admin/sites"), "sites");
  await Promise.all(sites.map(async s => {
    const sid = s.site_id || s.id;
    if (typeof sid !== "string" || !sid || (s.name != null && typeof s.name !== "string")) throw new Error("Invalid site response");
    const networks = nzCatalogRows(await apiFetch("GET", "/admin/sites/" + encodeURIComponent(sid) + "/networks"), "networks");
    networks.forEach(n => {
      if (!["network", "fqdn", "cidr"].includes(n.kind) ||
          (n.kind === "fqdn" && (typeof n.fqdn !== "string" || !n.fqdn)) ||
          (n.kind === "cidr" && (typeof n.cidr !== "string" || !n.cidr))) throw new Error("Invalid network binding response");
      if (n.kind === "network" && (typeof n.network_id !== "string" || !n.network_id)) throw new Error("Invalid network binding response");
      if (n.network_id != null && typeof n.network_id !== "string") throw new Error("Invalid network binding response");
      if (n.network_id) (map[n.network_id] = map[n.network_id] || []).push(s.name || sid);
    });
  }));
  return map;
}

async function renderZones(section) {
  uiState(section, "loading");
  const current = freshRender(section);
  let objs, membership;
  try {
    objs = nzCatalogRows(await apiFetch("GET", "/admin/vlan-objects"), "objects");
    if (objs.some(o => typeof o.id !== "string" || !o.id || (o.name != null && typeof o.name !== "string") ||
        (o.cidrs != null && (!Array.isArray(o.cidrs) || o.cidrs.some(cidr => typeof cidr !== "string"))))) throw new Error("Invalid network response");
    membership = await nzSiteMembership();
  }
  catch (e) { if (!current()) return; uiState(section, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderZones(section) }); return; }
  if (!current()) return;
  section.innerHTML = "";
  section.appendChild(el("div", { class: "ui-toolbar" }, [el("span", { class: "ui-spacer" }), el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "+ Add network", ja: "+ ネットワークを追加" }), onClick: () => openNetworkForm(section) })]));
  if (!objs.length) { section.appendChild(emptyBox(bl({ en: "No networks yet.", ja: "ネットワークがありません。" }))); return; }
  const rows = objs.map((o) => {
    const sites = membership[o.id] || [];
    return el("tr", {}, [
      el("td", {}, el("strong", { text: o.name || o.id })),
      el("td", { class: "ui-view-desc", text: (o.cidrs || []).join(", ") }),
      el("td", {}, sites.length ? el("span", {}, sites.map((s) => el("code", { class: "ui-chip", text: s }))) : el("span", { class: "ui-view-desc", text: bl({ en: "— not used", ja: "— 未使用" }) })),
      el("td", { class: "ui-row-actions" }, el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Delete", ja: "削除" }), onClick: () => nzDeleteNetwork(o, section) })),
    ]);
  });
  section.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [bl({ en: "Network", ja: "ネットワーク" }), bl({ en: "Ranges", ja: "範囲" }), bl({ en: "Used by sites", ja: "利用サイト" }), bl({ en: "Manage", ja: "操作" })].map((x) => el("th", { text: x })))),
    el("tbody", {}, rows),
  ]));
}

// openNetworkForm defines a network in the catalog: a name + one or more subnets. No internal id or "kind" is
// shown — the id is derived from the name; the class is a fixed default (this catalog is about the ranges).
function openNetworkForm(section) {
  const nameF = uiField({ name: "name", label: bl({ en: "Name", ja: "名前" }), required: true, placeholder: bl({ en: "Tokyo servers", ja: "東京サーバ" }) });
  const cidrsF = uiField({ name: "cidrs", label: bl({ en: "Subnets", ja: "サブネット" }), required: true, placeholder: "10.20.0.0/16, 10.30.0.0/16", hint: bl({ en: "Comma-separated.", ja: "カンマ区切り。" }) });
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Add network", ja: "ネットワーク追加" }) });
  const m = uiModal({ title: bl({ en: "Add a network", ja: "ネットワークを追加" }), body: [nameF.el, cidrsF.el], footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit] });
  submit.addEventListener("click", async () => {
    if (!nameF.validate() || !cidrsF.validate()) return;
    const cidrs = cidrsF.get().split(",").map((s) => s.trim()).filter(Boolean);
    // A UNIQUE id — never derived from the name, so a new network can't collide with (and silently overwrite) an
    // existing one that a site already references, which would make it show as "used" the moment it's created.
    const id = "net-" + ((self.crypto && crypto.randomUUID) ? crypto.randomUUID().slice(0, 8) : String(Date.now()));
    submit.disabled = true;
    try {
      const r = await apiFetch("POST", "/admin/vlan-objects", { id: id, name: nameF.get(), class: "server", cidrs: cidrs });
      if (!r.ok) { submit.disabled = false; uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
      m.close(); uiToast(bl({ en: "Network added.", ja: "ネットワークを追加しました。" }), "ok"); renderZones(section);
    } catch (e) { submit.disabled = false; uiToast(String(e), "err"); }
  });
  nameF.focus();
}

async function nzDeleteNetwork(o, section) {
  const ok = await uiConfirm({ title: bl({ en: "Delete this network?", ja: "このネットワークを削除?" }), body: bl({ en: "\"" + (o.name || o.id) + "\" is removed from the catalog. Sites that referenced it lose the binding.", ja: "「" + (o.name || o.id) + "」をカタログから削除します。参照していたサイトの紐付けは外れます。" }), confirmLabel: bl({ en: "Delete", ja: "削除" }), danger: true });
  if (!ok) return;
  const r = await apiFetch("DELETE", "/admin/vlan-objects/" + encodeURIComponent(o.id));
  if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
  uiToast(bl({ en: "Network deleted.", ja: "ネットワークを削除しました。" }), "ok"); renderZones(section);
}


