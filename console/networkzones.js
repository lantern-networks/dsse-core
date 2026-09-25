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

function networkZonesCanWrite() {
  const permissions = typeof idpSession === "undefined" ? null : idpSession?.permissions;
  return Array.isArray(permissions) && (permissions.includes("admin.vlan.write") || permissions.includes("*"));
}

function nzObjectMatches(row, expected) {
  return !!row && typeof row === "object" && !Array.isArray(row) && row.id === expected.id &&
    row.name === expected.name && row.class === expected.class && Array.isArray(row.cidrs) &&
    row.cidrs.length === expected.cidrs.length && row.cidrs.every((cidr, i) => cidr === expected.cidrs[i]);
}

function nzSavedObject(response, expected) {
  return !!response && response.ok && response.status === 200 && nzObjectMatches(response.body, expected);
}

function nzObjectReadback(response, expected) {
  const rows = nzCatalogRows(response, "objects");
  if (rows.some(row => typeof row.id !== "string" || !row.id)) return false;
  const matches = rows.filter(row => row.id === expected.id);
  return matches.length === 1 && nzObjectMatches(matches[0], expected);
}

function nzDeletionReadback(response, id) {
  const rows = nzCatalogRows(response, "objects");
  return rows.every(row => typeof row.id === "string" && row.id && row.id !== id);
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
  const canWrite = networkZonesCanWrite();
  section.innerHTML = "";
  section.appendChild(el("div", { class: "ui-toolbar" }, [el("span", { class: "ui-spacer" }), ...(canWrite ? [el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "+ Add network", ja: "+ ネットワークを追加" }), onClick: () => openNetworkForm(section) })] : [])]));
  if (!objs.length) { section.appendChild(emptyBox(bl({ en: "No networks yet.", ja: "ネットワークがありません。" }))); return; }
  const rows = objs.map((o) => {
    const sites = membership[o.id] || [];
    return el("tr", {}, [
      el("td", {}, el("strong", { text: o.name || o.id })),
      el("td", { class: "ui-view-desc", text: (o.cidrs || []).join(", ") }),
      el("td", {}, sites.length ? el("span", {}, sites.map((s) => el("code", { class: "ui-chip", text: s }))) : el("span", { class: "ui-view-desc", text: bl({ en: "— not used", ja: "— 未使用" }) })),
      ...(canWrite ? [el("td", { class: "ui-row-actions" }, el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Delete", ja: "削除" }), onClick: () => nzDeleteNetwork(o, section) }))] : []),
    ]);
  });
  section.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [bl({ en: "Network", ja: "ネットワーク" }), bl({ en: "Ranges", ja: "範囲" }), bl({ en: "Used by sites", ja: "利用サイト" }), ...(canWrite ? [bl({ en: "Manage", ja: "操作" })] : [])].map((x) => el("th", { text: x })))),
    el("tbody", {}, rows),
  ]));
}

// openNetworkForm defines a network in the catalog: a name + one or more subnets. No internal id or "kind" is
// shown — the id is derived from the name; the class is a fixed default (this catalog is about the ranges).
function openNetworkForm(section) {
  const nameF = uiField({ name: "name", label: bl({ en: "Name", ja: "名前" }), required: true, placeholder: bl({ en: "Tokyo servers", ja: "東京サーバ" }) });
  const cidrsF = uiField({ name: "cidrs", label: bl({ en: "Subnets", ja: "サブネット" }), required: true, placeholder: "10.20.0.0/16, 10.30.0.0/16", hint: bl({ en: "Comma-separated.", ja: "カンマ区切り。" }) });
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Add network", ja: "ネットワーク追加" }) });
  const notice = el("div", { role: "alert", class: "ui-state ui-state-error", style: "display:none" });
  let closed = false, busy = false, attempted = false;
  const initial = { session: typeof idpSession === "undefined" ? null : idpSession,
    tenant: typeof operateTenant === "string" ? operateTenant : "", seq: section.__renderSeq,
    authority: baseForPlane("control"), token: typeof localStorage === "undefined" ? "" : localStorage.getItem("adminToken") || "" };
  const current = () => !closed && section.isConnected !== false && section.__renderSeq === initial.seq &&
    (typeof idpSession === "undefined" ? null : idpSession) === initial.session &&
    (typeof operateTenant === "string" ? operateTenant : "") === initial.tenant &&
    baseForPlane("control") === initial.authority &&
    (typeof localStorage === "undefined" ? "" : localStorage.getItem("adminToken") || "") === initial.token;
  const m = uiModal({ title: bl({ en: "Add a network", ja: "ネットワークを追加" }), body: [nameF.el, cidrsF.el, notice], footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit], onClose: () => { closed = true; } });
  submit.addEventListener("click", async () => {
    if (busy || attempted || !current()) return;
    if (!nameF.validate() || !cidrsF.validate()) return;
    const cidrs = cidrsF.get().split(",").map((s) => s.trim()).filter(Boolean);
    // A UNIQUE id — never derived from the name, so a new network can't collide with (and silently overwrite) an
    // existing one that a site already references, which would make it show as "used" the moment it's created.
    const id = "net-" + ((self.crypto && crypto.randomUUID) ? crypto.randomUUID().slice(0, 8) : String(Date.now()));
    const request = { id, name: nameF.get(), class: "server", cidrs };
    attempted = true; busy = true; submit.disabled = true;
    try {
      const r = await apiFetch("POST", "/admin/vlan-objects", request);
      if (!current()) return;
      if (r && !r.ok && r.status === 400) {
        attempted = false; submit.disabled = false;
        notice.textContent = (r.body && (r.body.error || r.body.message)) || bl({ en: "Check the network name and subnets.", ja: "ネットワーク名とサブネットを確認してください。" });
        notice.style.display = "";
        return;
      }
      if (!nzSavedObject(r, request)) throw new Error("Unconfirmed network save");
      const read = await apiFetch("GET", "/admin/vlan-objects");
      if (!current()) return;
      if (!nzObjectReadback(read, request)) throw new Error("Unconfirmed network readback");
      m.close(); uiToast(bl({ en: "Network added.", ja: "ネットワークを追加しました。" }), "ok"); renderZones(section);
    } catch (_) {
      if (!current()) return;
      notice.textContent = bl({ en: "The network save could not be confirmed. It may already have been applied. Cancel and reload to check the catalog before trying again.", ja: "ネットワークの保存を確認できませんでした。すでに反映されている可能性があります。キャンセルして再読込し、一覧を確認してから再試行してください。" });
      notice.style.display = "";
    } finally { busy = false; }
  });
  nameF.focus();
}

async function nzDeleteNetwork(o, section) {
  const pending = section.__networkDeletions || (section.__networkDeletions = new Set());
  if (pending.has(o.id)) return;
  pending.add(o.id);
  let closed = false, busy = false, attempted = false;
  const initial = { session: typeof idpSession === "undefined" ? null : idpSession,
    tenant: typeof operateTenant === "string" ? operateTenant : "", seq: section.__renderSeq,
    authority: baseForPlane("control"), token: typeof localStorage === "undefined" ? "" : localStorage.getItem("adminToken") || "" };
  const current = () => !closed && section.isConnected !== false && section.__renderSeq === initial.seq &&
    (typeof idpSession === "undefined" ? null : idpSession) === initial.session &&
    (typeof operateTenant === "string" ? operateTenant : "") === initial.tenant &&
    baseForPlane("control") === initial.authority &&
    (typeof localStorage === "undefined" ? "" : localStorage.getItem("adminToken") || "") === initial.token;
  const notice = el("div", { role: "alert", class: "ui-state ui-state-error", style: "display:none" });
  const confirm = el("button", { class: "ui-btn ui-btn-danger", text: bl({ en: "Delete", ja: "削除" }) });
  const modal = uiModal({ title: bl({ en: "Delete this network?", ja: "このネットワークを削除?" }),
    body: [el("p", { text: bl({ en: "\"" + (o.name || o.id) + "\" is removed from the catalog. Sites that referenced it lose the binding.", ja: "「" + (o.name || o.id) + "」をカタログから削除します。参照していたサイトの紐付けは外れます。" }) }), notice],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => modal.close() }), confirm],
    onClose: () => { closed = true; if (!busy) pending.delete(o.id); } });
  confirm.onclick = async () => {
    if (busy || attempted || !current()) return;
    attempted = true; busy = true; confirm.disabled = true;
    try {
      const r = await apiFetch("DELETE", "/admin/vlan-objects/" + encodeURIComponent(o.id));
      if (!current()) return;
      if (!r || !r.ok || r.status !== 200 || !r.body || Array.isArray(r.body) || r.body.deleted !== o.id) throw new Error("Unconfirmed network deletion");
      const read = await apiFetch("GET", "/admin/vlan-objects");
      if (!current()) return;
      if (!nzDeletionReadback(read, o.id)) throw new Error("Network still listed");
      modal.close(); uiToast(bl({ en: "Network deleted.", ja: "ネットワークを削除しました。" }), "ok"); renderZones(section);
    } catch (_) {
      if (!current()) return;
      notice.textContent = bl({ en: "The deletion could not be confirmed. It may already have been applied. Cancel and reload to check the catalog before trying again.", ja: "削除を確認できませんでした。すでに反映されている可能性があります。キャンセルして再読込し、一覧を確認してから再試行してください。" });
      notice.style.display = "";
    } finally { busy = false; if (closed) pending.delete(o.id); }
  };
}
