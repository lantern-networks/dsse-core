"use strict";

// dns.js — "DNS Filtering" view on ui.js (the settings-form variant of the product pattern). Replaces the
// raw-JSON dns-policy card with structured editors: a blocked-domains list, redirect (domain→address) rows, and
// a plain-language toggle, with a review-before-apply confirmation. Fields it does not surface (fixed addresses)
// are preserved untouched on save.
// Backend: GET /admin/dns-policy -> {deny:[],sinkhole:{},stub_ipv4:{},ech_strip}, PUT /admin/dns-policy.

// --- connector reachability helpers (for conditional forwarding) -----------------------------------------
// An internal-zone DNS query is forwarded to the internal DNS server (upstream). The Edge can't reach internal
// DNS directly — it routes the query through whichever connector's Networks cover the upstream IP. These helpers
// show the operator WHICH connector will carry it (or warn that none does), tying DNS forwarding to the
// connector Networks bindings. See docs/connector_network_route_advertisement_design.md.
function dnsIpToInt(ip) {
  const p = String(ip || "").split(".");
  if (p.length !== 4) return null;
  let n = 0;
  for (const o of p) { const v = parseInt(o, 10); if (isNaN(v) || v < 0 || v > 255 || !/^\d+$/.test(o)) return null; n = (n * 256) + v; }
  return n >>> 0;
}
function dnsIpInCidr(ip, cidr) {
  const parts = String(cidr || "").split("/");
  if (parts.length !== 2) return false;
  const bits = parseInt(parts[1], 10);
  const ipN = dnsIpToInt(ip), netN = dnsIpToInt(parts[0]);
  if (ipN == null || netN == null || isNaN(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipN & mask) === (netN & mask);
}
function dnsUpstreamHost(upstream) {
  // "10.10.0.10:53" -> "10.10.0.10"; leave a bare host/hostname as-is.
  const s = String(upstream || "").trim();
  const i = s.lastIndexOf(":");
  return i > 0 ? s.slice(0, i) : s;
}
// dnsFetchConnectorReach returns [{id,name,cidrs:[]}] of ROUTABLE CIDRs per connector (raw CIDR bindings + the
// CIDRs a Named-Network reference expands to), so we can tell which connector reaches a forward zone's upstream.
async function dnsFetchConnectorReach() {
  let conns = [];
  try { const r = await apiFetch("GET", "/admin/connectors"); if (r.ok && r.body) conns = r.body.connectors || []; } catch (e) { return []; }
  return Promise.all(conns.map(async (c) => {
    const id = c.id || c.connector_id || "";
    const cidrs = [];
    try {
      const rr = await apiFetch("GET", "/admin/connectors/" + encodeURIComponent(id) + "/routes");
      const routes = (rr.ok && rr.body && rr.body.routes) || [];
      routes.forEach((rt) => { if (!rt.routable) return; if (rt.cidr) cidrs.push(rt.cidr); (rt.network_cidrs || []).forEach((x) => cidrs.push(x)); });
    } catch (e) { /* leave empty */ }
    return { id, name: c.name || id, cidrs };
  }));
}
// dnsReachFor: undefined = upstream isn't an IPv4 literal (can't check); a connector object = it reaches it;
// null = an IPv4 that NO connector's Networks cover (the query can't get to that DNS server).
function dnsReachFor(upstream, connectorReach) {
  const host = dnsUpstreamHost(upstream);
  if (dnsIpToInt(host) == null) return undefined;
  for (const c of connectorReach) { for (const cd of c.cidrs) { if (dnsIpInCidr(host, cd)) return c; } }
  return null;
}

function renderDnsView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "DNS Filtering", ja: "DNS フィルタ" }) }),
      // ★ ONE NODE'S RESOLVER, SO ONE PARTY DECIDES IT (2026-08-17). The DNS policy — deny, redirect, forward —
      // is a single set for the whole node: there is no tenant in it, and a customer changing it would change
      // it for every organization on this Edge. The scope moved to the operator the same day; this screen was
      // still offering the editor to everyone, which turns a boundary into a button that answers 403.
      //
      // A customer keeps the READ, because what their own devices resolve through is something they are
      // entitled to see.
      el("p", { class: "ui-view-desc", text: answeringForTheDeployment()
        ? bl({ en: "Block domains, or redirect them to an address you choose. Changes apply immediately.",
               ja: "ドメインをブロック、または指定アドレスへリダイレクトします。変更は即時反映されます。" })
        : bl({ en: "What this node's resolver blocks and redirects. It is one set for the whole deployment, so the company that runs this service maintains it.",
               ja: "このノードの名前解決でブロック・リダイレクトされるものです。配備全体で1つの設定なので、このサービスを運用する会社が管理します。" }) }),
    ]),
    el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Reload", ja: "再読込" }), onClick: () => renderDnsView(content) }),
  ]));
  const host = el("div", {});
  content.appendChild(host);
  loadDns(host, content);
}

async function loadDns(host, content) {
  uiState(host, "loading");
  const current = freshRender(host);
  let pol;
  try {
    const r = await apiFetch("GET", "/admin/dns-policy");
    if (!r.ok) { if (!current()) return; uiState(host, "error", "HTTP " + r.status, { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => loadDns(host, content) }); return; }
    pol = r.body || {};
  } catch (e) { if (!current()) return; uiState(host, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => loadDns(host, content) }); return; }

  const blocked = Array.isArray(pol.deny) ? pol.deny.slice() : [];
  const redirects = Object.keys(pol.sinkhole || {}).map((k) => ({ name: k, addr: pol.sinkhole[k] }));
  const stub = pol.stub_ipv4 || {}; // preserved untouched
  let ech = !!pol.ech_strip;
  const forwardZones = Array.isArray(pol.forward_zones) ? pol.forward_zones.map((z) => ({ zone: z.zone || "", upstream: z.upstream || "" })) : [];
  // Which connector reaches each internal DNS server (upstream)? Fetched once so the forward-zone rows can show it.
  const connectorReach = await dnsFetchConnectorReach();

  if (!current()) return;
  host.innerHTML = "";

  // --- Blocked domains ---
  host.appendChild(el("h3", { class: "ui-field-label", text: bl({ en: "Blocked domains", ja: "ブロックするドメイン" }) }));
  host.appendChild(el("p", { class: "ui-field-hint", text: bl({ en: "Lookups for these names fail.", ja: "これらの名前の解決は失敗します。" }) }));
  const blockedHost = el("div", {});
  host.appendChild(blockedHost);
  const renderBlocked = () => {
    blockedHost.innerHTML = "";
    if (!blocked.length) blockedHost.appendChild(el("p", { class: "ui-view-desc", text: bl({ en: "None.", ja: "なし。" }) }));
    blocked.forEach((name, i) => {
      const inp = el("input", { class: "ui-input", value: name, placeholder: "evil.example" });
      inp.style.maxWidth = "360px";
      inp.addEventListener("input", () => { blocked[i] = inp.value.trim(); });
      blockedHost.appendChild(el("div", { class: "ui-toolbar" }, [inp, el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Remove", ja: "削除" }), onClick: () => { blocked.splice(i, 1); renderBlocked(); } })]));
    });
  };
  renderBlocked();
  host.appendChild(el("div", { style: "margin:6px 0 18px" }, el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "+ Add domain", ja: "+ ドメインを追加" }), onClick: () => { blocked.push(""); renderBlocked(); } })));

  // --- Redirects ---
  host.appendChild(el("h3", { class: "ui-field-label", text: bl({ en: "Redirects", ja: "リダイレクト" }) }));
  host.appendChild(el("p", { class: "ui-field-hint", text: bl({ en: "Send a domain to an address you choose (e.g. a safe landing page).", ja: "ドメインを指定アドレス(例: 安全な案内ページ)へ向けます。" }) }));
  const redirHost = el("div", {});
  host.appendChild(redirHost);
  const renderRedir = () => {
    redirHost.innerHTML = "";
    if (!redirects.length) redirHost.appendChild(el("p", { class: "ui-view-desc", text: bl({ en: "None.", ja: "なし。" }) }));
    redirects.forEach((row, i) => {
      const n = el("input", { class: "ui-input", value: row.name, placeholder: "ads.example" });
      const a = el("input", { class: "ui-input", value: row.addr, placeholder: "100.64.0.250" });
      n.style.maxWidth = "260px"; a.style.maxWidth = "180px";
      n.addEventListener("input", () => { row.name = n.value.trim(); });
      a.addEventListener("input", () => { row.addr = a.value.trim(); });
      redirHost.appendChild(el("div", { class: "ui-toolbar" }, [n, el("span", { text: "→" }), a, el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Remove", ja: "削除" }), onClick: () => { redirects.splice(i, 1); renderRedir(); } })]));
    });
  };
  renderRedir();
  host.appendChild(el("div", { style: "margin:6px 0 18px" }, el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "+ Add redirect", ja: "+ リダイレクトを追加" }), onClick: () => { redirects.push({ name: "", addr: "" }); renderRedir(); } })));

  // --- Conditional forwarding (internal zones) ---
  host.appendChild(el("h3", { class: "ui-field-label", text: bl({ en: "Conditional forwarding (internal zones)", ja: "条件付きフォワード(内部ゾーン)" }) }));
  host.appendChild(el("p", { class: "ui-field-hint", text: bl({ en: "Resolve an internal DNS zone (e.g. an Active Directory domain) against your internal DNS server. This is a TENANT setting — the Edge can't reach internal DNS directly, so it routes the query through whichever connector's Networks cover the DNS server's IP. Make sure that IP is bound in a connector's Networks (each row shows which connector will carry it). A zone rule also covers its subdomains (incl. _msdcs for AD DC location).", ja: "内部 DNS ゾーン(例: Active Directory ドメイン)を社内の内部 DNS サーバで解決します。これはテナント設定 — Edge は内部 DNS に直接到達できないため、その DNS サーバの IP を含むネットワークのコネクタ経由で問い合わせます。その IP がいずれかのコネクタのネットワークに紐付いていることを確認してください(各行に、どのコネクタが担うかを表示します)。ゾーン指定はサブドメイン(AD の DC 検出用 _msdcs 含む)も対象。" }) }));
  const fwdHost = el("div", {});
  host.appendChild(fwdHost);
  const reachBadge = (upstream) => {
    const c = dnsReachFor(upstream, connectorReach);
    if (c === undefined) return null; // not an IPv4 literal — nothing to assert
    return c
      ? uiBadge(bl({ en: "via " + c.name, ja: c.name + " 経由" }), "ok")
      : uiBadge(bl({ en: "no connector reaches this IP", ja: "到達するコネクタなし" }), "warn");
  };
  const renderFwd = () => {
    fwdHost.innerHTML = "";
    if (!forwardZones.length) fwdHost.appendChild(el("p", { class: "ui-view-desc", text: bl({ en: "None.", ja: "なし。" }) }));
    forwardZones.forEach((row, i) => {
      const z = el("input", { class: "ui-input", value: row.zone, placeholder: "corp.example.com" });
      z.style.maxWidth = "260px";
      z.addEventListener("input", () => { row.zone = z.value.trim(); });
      const up = el("input", { class: "ui-input", value: row.upstream, placeholder: bl({ en: "internal DNS 10.10.0.10:53", ja: "内部DNS 10.10.0.10:53" }) });
      up.style.maxWidth = "220px";
      const badgeSlot = el("span", {}, reachBadge(row.upstream));
      up.addEventListener("input", () => { row.upstream = up.value.trim(); badgeSlot.innerHTML = ""; const b = reachBadge(row.upstream); if (b) badgeSlot.appendChild(b); });
      fwdHost.appendChild(el("div", { class: "ui-toolbar" }, [z, el("span", { text: "→" }), up, badgeSlot, el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Remove", ja: "削除" }), onClick: () => { forwardZones.splice(i, 1); renderFwd(); } })]));
    });
  };
  renderFwd();
  host.appendChild(el("div", { style: "margin:6px 0 18px" }, el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "+ Add zone", ja: "+ ゾーンを追加" }), onClick: () => { forwardZones.push({ zone: "", upstream: "" }); renderFwd(); } })));

  // --- ECH toggle ---
  const echField = uiField({ name: "ech", type: "checkbox", value: ech, label: bl({ en: "Unmask encrypted site names (ECH)", ja: "暗号化されたサイト名を解除 (ECH)" }), hint: bl({ en: "Some browsers hide the site name in an encrypted field. Turn this on so blocking and inspection still see it.", ja: "一部ブラウザはサイト名を暗号化フィールドに隠します。オンにするとブロックや傍受がサイト名を認識できます。" }) });
  host.appendChild(echField.el);

  // --- preserved note + save ---
  if (Object.keys(stub).length) host.appendChild(el("p", { class: "ui-view-desc", text: bl({ en: "Fixed addresses kept as-is: ", ja: "固定アドレスは保持: " }) + Object.keys(stub).length }));
  const save = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Review & apply", ja: "確認して適用" }) });
  // The editor above is read-only for a customer: the controls render so they can SEE what is in force, and
  // the one button that would write it is the operator's.
  if (answeringForTheDeployment()) host.appendChild(el("div", { style: "margin-top:14px" }, save));
  save.addEventListener("click", async () => {
    // An incomplete edit must not silently delete an existing rule. Deletion
    // is the explicit Remove action, including for newly added blank rows.
    if (redirects.some(r => !r.name.trim() || !r.addr.trim())) {
      uiToast(bl({ en: "Complete each redirect domain and address, or remove the row explicitly.", ja: "各リダイレクトのドメインとアドレスを入力してください。削除する場合は行の削除ボタンを使ってください。" }), "err");
      return;
    }
    if (forwardZones.some(z => !z.zone.trim() || !z.upstream.trim())) {
      uiToast(bl({ en: "Complete each forward zone and DNS server, or remove the row explicitly.", ja: "各転送ゾーンとDNSサーバを入力してください。削除する場合は行の削除ボタンを使ってください。" }), "err");
      return;
    }
    const deny = blocked.map((s) => s.trim()).filter(Boolean);
    const sinkhole = {};
    for (const r of redirects) { if (r.name && r.addr) sinkhole[r.name] = r.addr; }
    const forward_zones = forwardZones.filter((z) => z.zone && z.upstream).map((z) => ({ zone: z.zone.trim(), upstream: z.upstream.trim() }));
    const next = { deny, sinkhole, stub_ipv4: stub, ech_strip: echField.get(), forward_zones };
    const preview = bl({ en: "Blocked: ", ja: "ブロック: " }) + deny.length + " · " + bl({ en: "Redirects: ", ja: "リダイレクト: " }) + Object.keys(sinkhole).length + " · " + bl({ en: "Forward zones: ", ja: "フォワードゾーン: " }) + forward_zones.length + " · " + bl({ en: "Unmask ECH: ", ja: "ECH 解除: " }) + (next.ech_strip ? bl({ en: "on", ja: "オン" }) : bl({ en: "off", ja: "オフ" }));
    const ok = await uiConfirm({ title: bl({ en: "Apply DNS filtering?", ja: "DNS フィルタを適用しますか?" }), body: bl({ en: "This takes effect immediately.", ja: "即時に反映されます。" }), preview, confirmLabel: bl({ en: "Apply", ja: "適用" }) });
    if (!ok) return;
    try {
      const r = await apiFetch("PUT", "/admin/dns-policy", next);
      if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
      uiToast(bl({ en: "DNS filtering applied.", ja: "DNS フィルタを適用しました。" }), "ok");
      renderDnsView(content);
    } catch (e) { uiToast(String(e), "err"); }
  });
}
