"use strict";

// connectors.js — "Connectors" view on the shared ui.js primitives. List + per-row "Rotate secret" with
// confirmation + states. Replaces the raw-JSON connectors card.
// Backend: GET /admin/connectors -> {connectors:[…]}, POST /admin/connectors/{id}/runtime-secret/rotate.

function renderConnectorsView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "Connectors", ja: "コネクタ" }) }),
      el("p", { class: "ui-view-desc", text: bl({ en: "Outbound connectors that reach your private networks, and their secrets.", ja: "プライベートネットワークに到達するアウトバウンドコネクタとそのシークレット。" }) }),
    ]),
    el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Reload", ja: "再読込" }), onClick: () => renderConnList(host) }),
  ]));
  const host = el("div", {});
  content.appendChild(host);
  renderConnList(host);
}

async function renderConnList(host) {
  uiState(host, "loading");
  const current = freshRender(host);
  let conns;
  try {
    const r = await apiFetch("GET", "/admin/connectors");
    if (!r.ok) { if (!current()) return; uiState(host, "error", "HTTP " + r.status, { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderConnList(host) }); return; }
    conns = (r.body && r.body.connectors) || [];
  } catch (e) { if (!current()) return; uiState(host, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderConnList(host) }); return; }
  if (conns.length === 0) { if (!current()) return; uiState(host, "empty", bl({ en: "No connectors registered. Connectors are added when you deploy one into a private network.", ja: "登録済みコネクタがありません。プライベートネットワークにコネクタを配備すると追加されます。" })); return; }
  const rows = conns.map((c) => {
    const id = c.connector_id || c.id || "";
    const status = c.status || (c.connected ? "connected" : "unknown");
    return el("tr", { class: "ui-row-clickable", onClick: () => showConnectorDetail(id, c) }, [
      el("td", {}, el("code", { text: id })),
      el("td", { text: c.name || "—" }),
      el("td", {}, uiBadge(status, /connect|online|active|healthy/i.test(status) ? "ok" : "off")),
      el("td", {}, connTunnelBadge(c.tunnel_connected)),
      el("td", { class: "ui-row-actions" }, [
        el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Details", ja: "詳細" }), onClick: (e) => { e.stopPropagation(); showConnectorDetail(id, c); } }),
        el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Rotate secret", ja: "シークレット更新" }), onClick: (e) => { e.stopPropagation(); rotateConnector(id, host); } }),
      ]),
    ]);
  });
  if (!current()) return;
  host.innerHTML = "";
  host.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [
      el("th", { text: bl({ en: "Connector", ja: "コネクタ" }) }),
      el("th", { text: bl({ en: "Name", ja: "名前" }) }),
      el("th", { text: bl({ en: "Status", ja: "状態" }) }),
      el("th", { text: bl({ en: "Tunnel", ja: "トンネル" }) }),
      el("th", { class: "ui-row-actions", text: bl({ en: "Actions", ja: "操作" }) }),
    ])),
    el("tbody", {}, rows),
  ]));
}

// connTunnelBadge renders the live tunnel-connection state. true -> connected, false -> disconnected,
// null/undefined -> unknown (older Edge / no tunnel manager). Never asserts "disconnected" when unknown.
function connTunnelBadge(tunnelConnected) {
  if (tunnelConnected === true) return uiBadge(bl({ en: "Connected", ja: "接続中" }), "ok");
  if (tunnelConnected === false) return uiBadge(bl({ en: "Disconnected", ja: "切断" }), "off");
  return uiBadge(bl({ en: "Unknown", ja: "不明" }), "warn");
}

// connDetailRow builds a label/value line for the detail modal. value may be a string or a node.
function connDetailRow(label, value) {
  const valueNode = typeof value === "string" || value == null
    ? el("span", { text: value && String(value).length ? String(value) : "—" })
    : value;
  return el("div", { class: "ui-kv-row" }, [
    el("div", { class: "ui-kv-key", text: label }),
    el("div", { class: "ui-kv-val" }, valueNode),
  ]);
}

// showConnectorDetail opens a read-only drill-down modal for a single connector instance (Connector UX
// the design). It fetches the admin-safe detail DTO for fresh tunnel/heartbeat state, falling back to the
// list row if the fetch fails. Only non-secret fields are shown (private base URLs / secrets are never here).
async function showConnectorDetail(id, fallback) {
  const modal = uiModal({
    title: bl({ en: "Connector detail", ja: "コネクタ詳細" }),
    body: [el("div", {}, uiBadge(bl({ en: "Loading…", ja: "読込中…" }), "off"))],
    footer: [],
  });
  // Widen this modal: the Networks table (network / type / source / state / manage) needs more than the default
  // 520px so the Manage actions aren't clipped.
  const modalBox = modal.el.querySelector(".ui-modal");
  if (modalBox) modalBox.style.width = "min(820px, 94vw)";
  const bodyHost = modal.el.querySelector(".ui-modal-body");
  let c = fallback || {};
  try {
    const r = await apiFetch("GET", "/admin/connectors/" + encodeURIComponent(id));
    if (r.ok && r.body) c = r.body;
  } catch (e) { /* keep fallback row */ }

  const rotatedAt = c.runtime_secret_rotated_at || "";
  const secretLine = c.runtime_secret_configured
    ? (rotatedAt ? bl({ en: "Configured (rotated " + rotatedAt + ")", ja: "設定済み(更新: " + rotatedAt + ")" }) : bl({ en: "Configured", ja: "設定済み" }))
    : bl({ en: "Not configured", ja: "未設定" });
  const uptime = (c.uptime_seconds != null) ? connFormatUptime(c.uptime_seconds) : "";

  const sections = [
    connDetailRow(bl({ en: "Connector ID", ja: "コネクタ ID" }), el("code", { text: c.id || id })),
    connDetailRow(bl({ en: "Name", ja: "名前" }), c.name || ""),
    connDetailRow(bl({ en: "Status", ja: "状態" }), uiBadge(c.status || bl({ en: "unknown", ja: "不明" }), /connect|online|active|healthy/i.test(c.status || "") ? "ok" : "off")),
    connDetailRow(bl({ en: "Tunnel", ja: "トンネル" }), connTunnelBadge(c.tunnel_connected)),
    connDetailRow(bl({ en: "Version", ja: "バージョン" }), c.version || bl({ en: "unknown", ja: "不明" })),
    connDetailRow(bl({ en: "Uptime", ja: "稼働時間" }), uptime || bl({ en: "unknown", ja: "不明" })),
    connDetailRow(bl({ en: "Last heartbeat", ja: "最終ハートビート" }), c.last_heartbeat_at || bl({ en: "never", ja: "なし" })),
    connDetailRow(bl({ en: "Registered", ja: "登録日時" }), c.registered_at || ""),
    connDetailRow(bl({ en: "Region / Cluster", ja: "リージョン / クラスター" }), [c.edge_region_id, c.edge_cluster_id].filter(Boolean).join(" / ") || "—"),
    connDetailRow(bl({ en: "Connector group", ja: "コネクタグループ" }), c.connector_group_id || "—"),
    connDetailRow(bl({ en: "Runtime secret", ja: "ランタイムシークレット" }), secretLine),
    connDetailRow(bl({ en: "Reachable routes", ja: "到達可能ルート" }), connRoutesNode(c.reachable_routes)),
  ];

  bodyHost.innerHTML = "";
  bodyHost.appendChild(el("div", { class: "ui-kv" }, sections));
  const govHost = el("div", { style: "margin-top:16px" });
  bodyHost.appendChild(govHost);
  renderConnectorRouteGovernance(govHost, c.id || id);
  const foot = modal.el.querySelector(".ui-modal-foot");
  foot.innerHTML = "";
  // Rotate secret lives here too, so the Connector detail (reached from a Site) is fully self-sufficient now that
  // the standalone Connectors page is folded into Sites (Site ⊃ Connector ⊃ Networks).
  foot.appendChild(el("button", { class: "ui-btn ui-btn-danger", text: bl({ en: "Rotate secret", ja: "シークレット更新" }), onClick: () => rotateConnector(c.id || id, null) }));
  foot.appendChild(el("button", { class: "ui-btn", text: bl({ en: "Close", ja: "閉じる" }), onClick: () => modal.close() }));
}

// renderConnectorRouteGovernance is the CP-configured "Networks" surface (the design doc): the operator BINDS a
// network (CIDR or FQDN) to the connector — the control plane, not the connector, is the source of routes. A
// connector's self-reported subnets are non-authoritative DISCOVERY the operator ADOPTS to make routable. A
// saved binding propagates at once (route layer instantly; the connector within one effective-routes poll).
// Backend: GET/POST /admin/connectors/{id}/routes ({action, cidr|fqdn, description}).
async function renderConnectorRouteGovernance(host, id) {
  host.innerHTML = "";
  host.appendChild(el("h3", { class: "ui-field-label", text: bl({ en: "Connector routes (declared / adopted)", ja: "コネクタ経路（宣言 / 採用）" }) }));
  host.appendChild(el("p", { class: "ui-field-hint", text: bl({ en: "Bind the networks (subnets or hostnames) this connector serves. Configured bindings are the source of routing; a subnet the connector reports is DISCOVERED — adopt it to make it routable. Changes take effect immediately.", ja: "このコネクタが担うネットワーク(サブネット/ホスト名)を紐付けます。設定した紐付けがルーティングの源です。コネクタが報告するサブネットは「発見」状態で、採用するとルーティング可能になります。変更は即時に反映されます。" }) }));
  let routes = [];
  try { const r = await apiFetch("GET", "/admin/connectors/" + encodeURIComponent(id) + "/routes"); if (r.ok && r.body) routes = r.body.routes || []; } catch (e) { /* leave empty */ }
  // Named Networks (VLAN objects) are ranges defined ONCE and referenced here, so a subnet is not re-typed.
  let networks = [];
  try { const r = await apiFetch("GET", "/admin/vlan-objects"); if (r.ok && r.body) networks = r.body.objects || []; } catch (e) { /* leave empty */ }
  const dest = (rt) => {
    if (rt.kind === "network") return (rt.network_name || rt.network_id) + ((rt.network_cidrs && rt.network_cidrs.length) ? " (" + rt.network_cidrs.join(", ") + ")" : "");
    return rt.cidr || rt.fqdn || "";
  };
  const payloadFor = (rt) => rt.kind === "network" ? { network_id: rt.network_id }
    : (rt.kind === "fqdn" || (!rt.cidr && rt.fqdn)) ? { fqdn: rt.fqdn } : { cidr: rt.cidr };
  if (!routes.length) {
    host.appendChild(el("p", { class: "ui-view-desc", text: bl({ en: "No networks bound and none discovered yet.", ja: "紐付け済み・発見済みのネットワークはまだありません。" }) }));
  } else {
    const stateBadge = (rt) => rt.held
      ? uiBadge(bl({ en: "Held", ja: "保留" }), "danger")
      : rt.pending
        ? uiBadge(bl({ en: "Discovered", ja: "発見" }), "warn")
        : uiBadge(bl({ en: "Routable", ja: "ルーティング可" }), "ok");
    const connActions = (rt) => {
      // hold/adopt govern self-reported SUBNETS only (the backend rejects an fqdn hold); a discovered name
      // route is informational today — no dead button that can only 400.
      if (rt.kind !== "cidr" && !rt.cidr) return null;
      if (rt.held) return [el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Unhold", ja: "保留解除" }), onClick: () => connRouteAction(id, Object.assign({ action: "unhold" }, payloadFor(rt)), host) })];
      if (rt.pending) return [
        el("button", { class: "ui-btn ui-btn-sm ui-btn-primary", text: bl({ en: "Adopt", ja: "採用" }), onClick: () => connRouteAction(id, Object.assign({ action: "approve" }, payloadFor(rt)), host) }),
        el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Hold", ja: "保留" }), onClick: () => connRouteAction(id, Object.assign({ action: "hold" }, payloadFor(rt)), host) }),
      ];
      return [el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Hold", ja: "保留" }), onClick: () => connRouteAction(id, Object.assign({ action: "hold" }, payloadFor(rt)), host) })];
    };
    const kindBadge = (rt) => uiBadge(
      rt.kind === "network" ? bl({ en: "Named network", ja: "定義済みNW" })
        : (rt.kind === "fqdn" || (!rt.cidr && rt.fqdn)) ? bl({ en: "Name", ja: "名前" })
          : bl({ en: "Subnet", ja: "サブネット" }), "off");
    const rows = routes.map((rt) => el("tr", {}, [
      el("td", {}, el("code", { text: dest(rt) })),
      el("td", {}, kindBadge(rt)),
      el("td", {}, uiBadge(rt.source === "admin" ? bl({ en: "Configured", ja: "設定済み" }) : bl({ en: "Discovered", ja: "発見" }), rt.source === "admin" ? "ok" : "off")),
      el("td", {}, stateBadge(rt)),
      el("td", { class: "ui-row-actions" }, rt.source === "admin"
        ? [el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Remove", ja: "削除" }), onClick: () => connRouteAction(id, Object.assign({ action: "remove" }, payloadFor(rt)), host) })]
        : connActions(rt)),
    ]));
    host.appendChild(el("table", { class: "ui-table" }, [
      el("thead", {}, el("tr", {}, [bl({ en: "Network", ja: "ネットワーク" }), bl({ en: "Type", ja: "種別" }), bl({ en: "Source", ja: "由来" }), bl({ en: "State", ja: "状態" }), bl({ en: "Manage", ja: "操作" })].map((x) => el("th", { text: x })))),
      el("tbody", {}, rows),
    ]));
  }
  // Bind a network: a CIDR (e.g. 10.20.0.0/16) or an FQDN/hostname (e.g. wiki.corp) + optional description.
  // Type is auto-detected — a value with "/" is a subnet, otherwise a name binding.
  const inp = el("input", { class: "ui-input", placeholder: bl({ en: "10.20.0.0/16 or wiki.corp", ja: "10.20.0.0/16 または wiki.corp" }) });
  inp.style.maxWidth = "220px";
  const desc = el("input", { class: "ui-input", placeholder: bl({ en: "description (optional)", ja: "説明(任意)" }) });
  desc.style.maxWidth = "200px";
  const submit = () => {
    const v = inp.value.trim();
    if (!v) return;
    const payload = v.indexOf("/") >= 0 ? { cidr: v } : { fqdn: v };
    payload.action = "add";
    if (desc.value.trim()) payload.description = desc.value.trim();
    connRouteAction(id, payload, host);
  };
  host.appendChild(el("div", { class: "ui-toolbar", style: "margin-top:6px" }, [inp, desc, el("button", { class: "ui-btn ui-btn-sm ui-btn-primary", text: bl({ en: "+ Bind network", ja: "+ ネットワークを紐付け" }), onClick: submit })]));

  // Or reference a Named Network (a range defined once in Network Zones), so the subnet is not re-typed here.
  if (networks.length) {
    const sel = el("select", { class: "ui-input" });
    sel.style.maxWidth = "260px";
    sel.appendChild(el("option", { value: "", text: bl({ en: "Reference a Named Network…", ja: "定義済みネットワークを参照…" }) }));
    networks.forEach((n) => {
      const cidrs = (n.cidrs || []).join(", ");
      sel.appendChild(el("option", { value: n.id, text: (n.name || n.id) + (cidrs ? " (" + cidrs + ")" : "") }));
    });
    const bindNet = () => { if (sel.value) connRouteAction(id, { action: "add", network_id: sel.value }, host); };
    host.appendChild(el("div", { class: "ui-toolbar", style: "margin-top:6px" }, [sel, el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "+ Bind Named Network", ja: "+ 定義済みNWを紐付け" }), onClick: bindNet })]));
  }
  host.appendChild(el("p", { class: "ui-field-hint", text: bl({ en: "A saved binding applies to the route layer immediately and reaches the connector within one poll (~15s) — no restart. Referencing a Named Network keeps the subnet defined in one place.", ja: "保存した紐付けは経路層に即時反映され、約15秒以内に コネクタへ届きます(再起動不要)。定義済みネットワークを参照すると、サブネットの定義を一箇所に保てます。" }) }));
}

// connRouteAction posts a route mutation (payload = {action, cidr|fqdn, description?}) and re-renders. On an
// error it surfaces the collision report / validation message from the backend.
async function connRouteAction(id, payload, host) {
  const r = await apiFetch("POST", "/admin/connectors/" + encodeURIComponent(id) + "/routes", payload);
  if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
  uiToast(bl({ en: "Network updated.", ja: "ネットワークを更新しました。" }), "ok");
  renderConnectorRouteGovernance(host, id);
}

// connRoutesNode renders the route layer (FQDN domains, CIDRs, namespace). These destinations are not
// secrets. Empty -> a plain "none" line.
function connRoutesNode(routes) {
  if (!routes || ((routes.fqdn_domains || []).length === 0 && (routes.cidrs || []).length === 0 && !routes.namespace)) {
    return el("span", { text: bl({ en: "None declared", ja: "宣言なし" }) });
  }
  const parts = [];
  const fqdn = routes.fqdn_domains || [];
  const cidrs = routes.cidrs || [];
  if (fqdn.length) {
    parts.push(el("div", { class: "ui-kv-sub", text: bl({ en: "FQDN domains (" + fqdn.length + ")", ja: "FQDN ドメイン (" + fqdn.length + ")" }) }));
    parts.push(el("div", {}, fqdn.map((d) => el("code", { class: "ui-chip", text: d }))));
  }
  if (cidrs.length) {
    parts.push(el("div", { class: "ui-kv-sub", text: bl({ en: "CIDRs (" + cidrs.length + ")", ja: "CIDR (" + cidrs.length + ")" }) }));
    parts.push(el("div", {}, cidrs.map((d) => el("code", { class: "ui-chip", text: d }))));
  }
  if (routes.namespace) {
    parts.push(el("div", { class: "ui-kv-sub", text: bl({ en: "Namespace", ja: "ネームスペース" }) }));
    parts.push(el("div", {}, el("code", { class: "ui-chip", text: routes.namespace })));
  }
  return el("div", {}, parts);
}

// connFormatUptime turns a seconds count into a compact human string (e.g. "2d 3h 4m").
function connFormatUptime(seconds) {
  seconds = Math.max(0, Math.floor(Number(seconds) || 0));
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const parts = [];
  if (d) parts.push(d + "d");
  if (h) parts.push(h + "h");
  if (m || (!d && !h)) parts.push(m + "m");
  return parts.join(" ");
}

async function rotateConnector(id, host) {
  const ok = await uiConfirm({
    title: bl({ en: "Rotate this connector's secret?", ja: "このコネクタのシークレットを更新しますか?" }),
    body: bl({ en: "Issues a new secret for \"" + id + "\". The connector must pick up the new secret to keep connecting.", ja: "「" + id + "」に新しいシークレットを発行します。接続を維持するにはコネクタ側で新しいシークレットを取り込む必要があります。" }),
    confirmLabel: bl({ en: "Rotate", ja: "更新" }), danger: true,
  });
  if (!ok) return;
  try {
    const r = await apiFetch("POST", "/admin/connectors/" + encodeURIComponent(id) + "/runtime-secret/rotate", {});
    if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
    uiToast(bl({ en: "Secret rotated.", ja: "シークレットを更新しました。" }), "ok");
    if (host && typeof renderConnList === "function") renderConnList(host); // no list to refresh when called from the detail modal
  } catch (e) { uiToast(String(e), "err"); }
}
