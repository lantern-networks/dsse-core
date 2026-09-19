"use strict";

// overview.js — the Overview dashboard (docs/overview_dashboard_redesign.md). An at-a-glance operational surface:
// subsystem health + edge identity, a fleet stat strip, an AGGREGATE device panel (no per-device rows — the
// Devices page owns those), decision analytics + activity-over-time charts, and tenants / regions / edge-connector
// / usage panels. Every panel loads independently and degrades to its own empty/error state; charts are inline SVG
// (no dependency), coloured with the console's ok/warn/danger/off tokens. Reuses deviceStateOf() from devices.js.

let _ovPeriod = "7d"; // 24h | 7d | 30d — drives access-trends + events/trends windows

// ---- inline-SVG chart primitives -------------------------------------------------------------------------
const OV_SVGNS = "http://www.w3.org/2000/svg";
function svgEl(tag, attrs, kids) {
  const n = document.createElementNS(OV_SVGNS, tag);
  if (attrs) for (const k in attrs) if (attrs[k] != null) n.setAttribute(k, attrs[k]);
  (Array.isArray(kids) ? kids : kids ? [kids] : []).forEach((c) => n.appendChild(typeof c === "string" ? document.createTextNode(c) : c));
  return n;
}
const OV_TONE = { ok: "var(--ok)", warn: "var(--warn)", danger: "var(--err)", danger2: "var(--err)", off: "#a9b2bf", accent: "var(--accent)", muted: "var(--muted)" };

// ovDonut — segments [{value,color}], with a centre label. r=15.9 gives circumference≈100 so dasharray is a %.
function ovDonut(segments, size, centerTop, centerBot) {
  const total = segments.reduce((s, x) => s + (x.value || 0), 0) || 1;
  let off = 25; // start at 12 o'clock
  const rings = segments.filter((s) => s.value > 0).map((s) => {
    const pct = (s.value / total) * 100;
    const c = svgEl("circle", { cx: 21, cy: 21, r: 15.9, fill: "none", stroke: s.color, "stroke-width": 6,
      "stroke-dasharray": pct.toFixed(2) + " " + (100 - pct).toFixed(2), "stroke-dashoffset": off.toFixed(2), transform: "rotate(-90 21 21)" });
    off -= pct;
    return c;
  });
  const kids = [svgEl("circle", { cx: 21, cy: 21, r: 15.9, fill: "none", stroke: "var(--panel2)", "stroke-width": 6 }), ...rings];
  if (centerTop) kids.push(svgEl("text", { x: 21, y: centerBot ? 20 : 22.5, "text-anchor": "middle", "font-size": 6, "font-weight": 700, style: "fill:var(--ui-text,#e6e9ef)" }, centerTop));
  if (centerBot) kids.push(svgEl("text", { x: 21, y: 26, "text-anchor": "middle", "font-size": 3.4, fill: OV_TONE.muted }, centerBot));
  return svgEl("svg", { width: size || 108, height: size || 108, viewBox: "0 0 42 42" }, kids);
}

// ovSegbar — a horizontal stacked bar. segments [{value,color,title}].
function ovSegbar(segments, height) {
  const bar = el("div", { class: "ov-segbar", style: height ? "height:" + height + "px" : "" });
  const total = segments.reduce((s, x) => s + (x.value || 0), 0) || 1;
  segments.forEach((s) => { if (s.value > 0) bar.appendChild(el("span", { style: "width:" + ((s.value / total) * 100).toFixed(2) + "%;background:" + s.color, title: s.title || "" })); });
  return bar;
}

// ovHbar — labelled horizontal bars. rows [{k,v,color}].
function ovHbar(rows, fmt) {
  const max = Math.max(1, ...rows.map((r) => r.v));
  return el("div", { class: "ov-hbar" }, rows.map((r) => el("div", { class: "ov-row" }, [
    el("span", { class: "ov-k", text: r.k, title: r.k }),
    el("div", { class: "ov-track" }, el("div", { class: "ov-fill", style: "width:" + Math.round((r.v / max) * 100) + "%;background:" + (r.color || OV_TONE.accent) })),
    el("span", { class: "ov-v", text: fmt ? fmt(r.v) : String(r.v) }),
  ])));
}

// ovSparkline — small line with an area fill.
function ovSparkline(values, w, h, color) {
  const max = Math.max(1, ...values), min = Math.min(...values, 0), rng = (max - min) || 1;
  const pts = values.map((v, i) => [(i / (values.length - 1)) * w, h - ((v - min) / rng) * (h - 3) - 1.5]);
  const line = pts.map((p) => p[0].toFixed(1) + "," + p[1].toFixed(1)).join(" ");
  return svgEl("svg", { width: "100%", height: h, viewBox: "0 0 " + w + " " + h, preserveAspectRatio: "none" }, [
    svgEl("polyline", { points: line + " " + w + "," + h + " 0," + h, fill: color, "fill-opacity": ".14", stroke: "none" }),
    svgEl("polyline", { points: line, fill: "none", stroke: color, "stroke-width": 1.5 }),
    svgEl("circle", { cx: pts[pts.length - 1][0].toFixed(1), cy: pts[pts.length - 1][1].toFixed(1), r: 2.2, fill: color }),
  ]);
}

// ovArea — multi-series area/line over buckets. series [{values,color,fill?}]; faint grid.
function ovArea(series, w, h) {
  const max = Math.max(1, ...series.flatMap((s) => s.values));
  const n = Math.max(2, (series[0] && series[0].values.length) || 2);
  const x = (i) => (i / (n - 1)) * w, y = (v) => h - (v / max) * (h - 6) - 3;
  const grid = [0.25, 0.5, 0.75].map((f) => svgEl("line", { x1: 0, y1: (h * f).toFixed(0), x2: w, y2: (h * f).toFixed(0), stroke: "#1f2530", "stroke-width": 1 }));
  const layers = [];
  series.forEach((s) => {
    const pts = s.values.map((v, i) => x(i).toFixed(1) + "," + y(v).toFixed(1)).join(" ");
    if (s.fill) layers.push(svgEl("polyline", { points: pts + " " + w + "," + h + " 0," + h, fill: s.color, "fill-opacity": ".16", stroke: "none" }));
    layers.push(svgEl("polyline", { points: pts, fill: "none", stroke: s.color, "stroke-width": s.fill ? 2 : 1.5 }));
  });
  return svgEl("svg", { width: "100%", height: h, viewBox: "0 0 " + w + " " + h, preserveAspectRatio: "none" }, [...grid, ...layers]);
}

// ---- small helpers ---------------------------------------------------------------------------------------
function ovNum(n) { n = Number(n) || 0; if (n >= 1e6) return (n / 1e6).toFixed(1) + "M"; if (n >= 1e3) return (n / 1e3).toFixed(1) + "k"; return String(n); }
function ovBytes(n) { n = Number(n) || 0; const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; } return n.toFixed(i ? 1 : 0) + " " + u[i]; }
function ovAgo(iso) { if (!iso) return "—"; const t = Date.parse(iso); if (isNaN(t)) return "—"; const m = Math.floor((Date.now() - t) / 60000); if (m < 1) return "just now"; if (m < 60) return m + "m ago"; const h = Math.floor(m / 60); return h < 48 ? h + "h ago" : Math.floor(h / 24) + "d ago"; }
function ovHealthTone(s) { s = (s || "").toLowerCase(); if (s === "ok" || s === "healthy") return "ok"; if (s === "unconfigured" || s === "disabled" || s === "memory" || s === "") return "off"; if (s === "degraded" || s === "warn") return "warn"; return "danger"; }
function ovWindow() { const now = new Date(); const from = new Date(now.getTime() - ({ "24h": 24, "7d": 168, "30d": 720 }[_ovPeriod] || 168) * 3600 * 1000); return { from: from.toISOString(), to: now.toISOString(), gran: _ovPeriod === "24h" ? "1h" : "1d" }; }
async function ovGet(path, plane) { try { return await apiFetch("GET", path, undefined, plane); } catch (e) { return { ok: false, status: 0, body: null, error: String(e) }; } }
function ovPanel(title, more) {
  const head = el("div", { class: "ov-panel-h" }, [el("h3", { text: title })]);
  if (more) head.appendChild(el("span", { class: "ov-more", text: more }));
  const body = el("div", {});
  const panel = el("div", { class: "ov-panel" }, [head, body]);
  return { panel, body, setMore: (t) => { const m = head.querySelector(".ov-more"); if (m) m.textContent = t; else head.appendChild(el("span", { class: "ov-more", text: t })); } };
}
function ovEmpty(msg) { return el("div", { class: "ov-empty", text: msg }); }
function ovGoto(view) { renderGroup(view === "devices" ? "enrolled" : view === "connectors" ? "sites" : view); }
function ovLeg(color, label, val, valColor) { return el("span", { class: "ov-metric" }, [el("i", { style: "display:inline-block;width:9px;height:9px;border-radius:2px;background:" + color + ";margin-right:7px" }), document.createTextNode(label), el("b", { style: "float:right;font-variant-numeric:tabular-nums;" + (valColor ? "color:" + valColor : ""), text: String(val) })]); }
function ovLegSmall(color, text) { return el("span", {}, [el("i", { style: "display:inline-block;width:9px;height:9px;border-radius:2px;background:" + color + ";margin-right:5px;vertical-align:-1px" }), document.createTextNode(text)]); }

// ---- view entry ------------------------------------------------------------------------------------------
function renderOverviewView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "Overview", ja: "概要" }) }),
      // ★ Written for whoever opens it. "fleet・テナント・リージョン・Edge" is four of our words in a row, on the
      // first screen of the product.
      el("p", { class: "ui-view-desc", text: bl({ en: "Devices, traffic and where things stand — anything wrong comes first, anything healthy stays quiet.", ja: "端末・通信・いまの状態を一目で。おかしいところが先に出て、正常なものは静かにしています。" }) }),
    ]),
    (function () {
      const seg = el("div", { style: "display:flex;border:1px solid var(--ui-line,#242a35);border-radius:8px;overflow:hidden" });
      ["24h", "7d", "30d"].forEach((v) => seg.appendChild(el("button", {
        class: "ui-btn ui-btn-sm" + (_ovPeriod === v ? " ui-btn-primary" : ""), text: v,
        onClick: () => { if (_ovPeriod !== v) { _ovPeriod = v; renderOverviewView(content); } },
      })));
      return seg;
    })(),
  ]));

  // ONE fleet request for this render, shared by the strip and the two panels that need it — so nothing on
  // screen can disagree with anything else on screen about how many Edges there are.
  const fleetP = fleetStatus();
  const strip = el("div", { class: "ov-strip" }); content.appendChild(strip); ovLoadStrip(strip, fleetP);

  const tiles = el("div", { class: "ov-grid ov-tiles" }); content.appendChild(tiles); ovLoadTiles(tiles);

  const devices = ovPanel(bl({ en: "Devices · endpoint fleet", ja: "デバイス · 端末の全体" }), bl({ en: "aggregate · view all →", ja: "集計 · 全件 →" }));
  devices.panel.style.marginTop = "14px";
  devices.panel.querySelector(".ov-more").style.cursor = "pointer";
  devices.panel.querySelector(".ov-more").addEventListener("click", () => ovGoto("devices"));
  content.appendChild(devices.panel); ovLoadDevices(devices.body, devices.setMore);

  const dRow = el("div", { class: "ov-grid", style: "grid-template-columns:1fr 1fr;margin-top:14px" });
  const mix = ovPanel(bl({ en: "Decision mix · " + _ovPeriod, ja: "判定内訳 · " + _ovPeriod }));
  const deny = ovPanel(bl({ en: "Top deny reasons · " + _ovPeriod, ja: "拒否の理由 上位 · " + _ovPeriod }));
  dRow.appendChild(mix.panel); dRow.appendChild(deny.panel); content.appendChild(dRow);
  ovLoadDecisions(mix.body, mix.setMore, deny.body);

  const activity = ovPanel(bl({ en: "Activity · " + _ovPeriod, ja: "アクティビティ · " + _ovPeriod }));
  activity.panel.style.marginTop = "14px"; content.appendChild(activity.panel); ovLoadActivity(activity.body);

  // Configuration reach — above Tenants/Regions because it answers a question about THIS console's own
  // truthfulness: whether what an operator authored is in effect everywhere, or only where the console asked.
  const reach = ovPanel(bl({ en: "Configuration reach", ja: "設定の反映状況" }));
  reach.panel.style.marginTop = "14px"; content.appendChild(reach.panel); ovLoadFleetConfig(reach.body, reach.setMore, fleetP);

  const tRow = el("div", { class: "ov-grid", style: "grid-template-columns:1.25fr .75fr;margin-top:14px" });
  // A customer has exactly one organization — their own — so the panel is named for what they will see in it.
  const tenants = ovPanel(answeringForTheDeployment() ? bl({ en: "Tenants", ja: "テナント" }) : bl({ en: "Your tenant", ja: "あなたのテナント" }));
  const regions = ovPanel(bl({ en: "Regions", ja: "リージョン" }), bl({ en: "config-driven", ja: "設定由来" }));
  tRow.appendChild(tenants.panel); tRow.appendChild(regions.panel); content.appendChild(tRow);
  ovLoadTenantsRegions(tenants.body, tenants.setMore, regions.body);

  // Split from the panel below, which called itself "Edge & connector fleet" and listed no Edges at all.
  const edges = ovPanel(bl({ en: "Edges by region", ja: "リージョン別の Edge" }));
  edges.panel.style.marginTop = "14px"; content.appendChild(edges.panel); ovLoadEdgesByRegion(edges.body, edges.setMore, fleetP);

  const edge = ovPanel(bl({ en: "Connectors", ja: "コネクタ" }));
  edge.panel.style.marginTop = "14px"; content.appendChild(edge.panel); ovLoadEdge(edge.body, edge.setMore);

  const usage = ovPanel(bl({ en: "Usage & quota · this period", ja: "利用 & クォータ · 今期" }));
  usage.panel.style.marginTop = "14px"; content.appendChild(usage.panel); ovLoadUsage(usage.body);
}

// ---- (A) status strip ------------------------------------------------------------------------------------
async function ovLoadStrip(strip, fleetP) {
  const sys = [
    { p: "/admin/usage/health", l: bl({ en: "Usage metering", ja: "利用メータリング" }) },
    { p: "/admin/auth/health", l: bl({ en: "Admin sign-in", ja: "管理者サインイン" }) },
    { p: "/admin/hot-store/health", l: bl({ en: "Activity store", ja: "アクティビティストア" }) },
  ];
  const [uh, ah, hh, cs, st] = await Promise.all([...sys.map((s) => ovGet(s.p)), ovGet("/admin/config-sync-status"), ovGet("/admin/state")]);
  strip.innerHTML = "";
  [[uh, sys[0].l], [ah, sys[1].l], [hh, sys[2].l]].forEach(([r, l]) => {
    const tone = r.ok ? ovHealthTone(r.body && r.body.status) : "danger";
    strip.appendChild(el("span", { class: "ov-sys" }, [el("span", { class: "ov-dot ov-dot-" + tone }), document.createTextNode(l)]));
  });
  // ★ Config sync, asked of the FLEET rather than of this node. /admin/config-sync-status answers for the one
  // Edge the console front door proxies to, so a green dot here meant "the Edge I happen to be talking to is
  // in sync" while a sibling could be days behind. Falls back to the local answer only when the fleet view is
  // unavailable, and says which one it is showing.
  const fleet = fleetP ? await fleetP : null;
  const fleetOK = fleet && fleet.ok && fleet.body && Array.isArray(fleet.body.edges);
  if (fleetOK) {
    const roll = fleetRollup(fleet.body);
    const tone = !roll.edges.length ? "off" : roll.behind.length ? "warn" : "ok";
    strip.appendChild(el("span", { class: "ov-sys" }, [el("span", { class: "ov-dot ov-dot-" + tone }),
      document.createTextNode(bl({ en: "Config in effect", ja: "設定の反映" }) + (roll.behind.length ? bl({ en: " · " + roll.behind.length + " behind", ja: " · " + roll.behind.length + " 台未反映" }) : ""))]));
  } else {
    const csEnabled = cs.ok && cs.body && cs.body.enabled;
    strip.appendChild(el("span", { class: "ov-sys" }, [el("span", { class: "ov-dot ov-dot-" + (csEnabled ? (cs.body.healthy === false ? "warn" : "ok") : "off") }),
      document.createTextNode(bl({ en: "Config sync (this node)", ja: "設定の同期(このノード)" }) + (csEnabled ? "" : bl({ en: " · off", ja: " · 無効" })))]));
  }
  // ★ The identity chip named whichever Edge the front door proxies to — one node's cluster id, region and
  // bundle version, presented as the system's. On a dashboard for the whole of DSSE a fleet has no single
  // answer to any of those, so the chip is a COUNT. Falls back to naming the node only when the fleet view is
  // unavailable, where "this node" is at least labelled as such.
  const chip = fleetStripChip(fleet);
  if (chip) strip.appendChild(chip);
  else if (st.ok && st.body && st.body.edge) {
    strip.appendChild(el("span", { class: "ov-id" }, [
      document.createTextNode(bl({ en: "this node ", ja: "このノード " })), el("b", { text: st.body.edge.edge_region_id || "—" }),
    ]));
  }
}

// ---- (B) fleet tiles -------------------------------------------------------------------------------------
// ★★ A REFUSED READ WAS DRAWN AS A ZERO (2026-08-17, measured as the operator inside a customer that had not
// delegated its management). /admin/state, /admin/connectors, /admin/enrolled-devices and the rest ALL
// answered 403, and every `(r.ok && r.body && r.body.x) || []` above turned that into an empty list — so this
// screen reported "0 devices, 0 connectors, 0 policies, 0% posture" about an organization it was not allowed
// to see. An operator reads that as a customer with nothing deployed.
//
// "Nothing" and "you may not know" are different answers and must not share a character. A refused read gets
// an em dash and a reason; only a read that ANSWERED gets a number.
function ovDenied() {
  for (const r of arguments) {
    if (r && (r.status === 403 || r.status === 401)) return true;
  }
  return false;
}
const OV_UNREADABLE = { en: "not readable here", ja: "取得できていません" };

async function ovLoadTiles(host) {
  host.innerHTML = "";
  for (let i = 0; i < 5; i++) host.appendChild(el("div", { class: "ov-tile" }, el("div", { class: "ov-foot", text: "…" })));
  // two-planes-deliberate: five separate figures, each read from the plane that owns it — decisions and
  // policies exist only where enforcement happens, connector liveness only at the authority. See
  // ops/checks/a_site_card_reads_one_plane.sh; what that gate forbids is ONE statement assembled out of two
  // moments, which is what the Sites card was doing when a healthy fleet read "0 connectors online".
  const [st, conn, at, d] = await Promise.all([ovGet("/admin/state"), ovGet("/admin/connectors"), ovGet("/admin/ai-ops/access-trends?window=" + _ovPeriod), ovDeviceAggregate()]);
  const counts = (st.ok && st.body && st.body.counts) || {};
  host.innerHTML = "";
  if (d.denied || ovDenied(st, conn, at)) {
    // One statement instead of five confident zeros. Which reads were refused is not the operator's problem;
    // that the figures are absent rather than nil is.
    for (const label of [bl({ en: "Devices", ja: "デバイス" }), bl({ en: "Connectors", ja: "コネクタ" }),
                         bl({ en: "Policies", ja: "ポリシー" }), bl({ en: "Decisions · " + _ovPeriod, ja: "判定 · " + _ovPeriod }),
                         bl({ en: "Deny rate · " + _ovPeriod, ja: "拒否率 · " + _ovPeriod })]) {
      host.appendChild(ovTile(label, "—", null, [el("div", { class: "ov-foot", text: bl(OV_UNREADABLE) })]));
    }
    return;
  }
  host.appendChild(ovTile(bl({ en: "Devices", ja: "デバイス" }), String(d.total), null,
    [ovSegbar([{ value: d.steering, color: OV_TONE.ok }, { value: d.failopen, color: OV_TONE.danger }, { value: d.offline, color: OV_TONE.off }, { value: d.blocked, color: OV_TONE.danger2 }], 6),
     el("div", { class: "ov-foot" }, [document.createTextNode(d.steering + bl({ en: " steering · ", ja: " ステア中 · " })), el("span", { style: "color:" + OV_TONE.danger2, text: d.failopen + bl({ en: " fail-open", ja: " fail-open" }) })])], () => ovGoto("devices")));
  const connectors = (conn.ok && conn.body && conn.body.connectors) || [];
  // ★★★ ONLINE IS THE ANSWER, AND THIS TILE WAS STILL WORKING IT OUT ITSELF. tunnel_connected is absent when
  // nothing reported one — which is what a control plane answers about every connector, and what a node
  // answers about a connector it does not hold — so `=== true` read "unknown" as "down". This tile showed
  // "0 / 2 up · 2 tunnel down" beside a connector whose heartbeat was thirty seconds old, whose record said
  // online: true and status: healthy, and whose own --verify on the machine said every door answers it.
  //
  // The server already decides this once and sends the conclusion (see adminConnectorOnline). The connectors
  // screen was moved onto it; this tile kept the old rule, which is how a rule kept in two places behaves.
  const up = connectors.filter((c) => c.online === true).length;
  const down = Math.max(0, connectors.length - up);
  host.appendChild(ovTile(bl({ en: "Connectors", ja: "コネクタ" }), String(up), " / " + connectors.length + bl({ en: " up", ja: " up" }),
    [ovSegbar([{ value: up, color: OV_TONE.ok }, { value: down, color: OV_TONE.danger }], 6),
     // "All connectors online" beside a count of zero is a reassurance about nothing. A deployment with no
     // connectors has not achieved anything to report; it says so.
     el("div", { class: "ov-foot", text: connectors.length === 0 ? bl({ en: "none registered", ja: "未登録" })
       : down > 0 ? bl({ en: down + " offline", ja: down + " 断" }) : bl({ en: "all connectors online", ja: "全コネクタ接続中" }) })], () => ovGoto("connectors")));
  host.appendChild(ovTile(bl({ en: "Policies", ja: "ポリシー" }), String(counts.policies != null ? counts.policies : "—"), null,
    [el("div", { class: "ov-foot", text: (counts.applications != null ? counts.applications : 0) + bl({ en: " apps", ja: " アプリ" }) })]));
  const wd = ovDecisionsInWindow(at, counts);
  const wdSpark = wd || 0;
  host.appendChild(ovTile(bl({ en: "Decisions · " + _ovPeriod, ja: "判定 · " + _ovPeriod }), ovDecisionsText(at, counts), null,
    [el("div", { style: "margin-top:6px" }, ovSparkline([wdSpark * 0.6, wdSpark * 0.65, wdSpark * 0.7, wdSpark * 0.78, wdSpark * 0.86, wdSpark * 0.93, wdSpark], 120, 24, OV_TONE.accent))]));
  const dr = at.ok && at.body ? at.body.deny_rate_percent : null;
  const drTone = dr == null ? OV_TONE.muted : dr >= 15 ? OV_TONE.danger : dr >= 5 ? OV_TONE.warn : OV_TONE.ok;
  host.appendChild(ovTile(bl({ en: "Deny rate · " + _ovPeriod, ja: "拒否率 · " + _ovPeriod }), dr == null ? "—" : dr.toFixed(1), dr == null ? "" : "%",
    [el("div", { class: "ov-foot", text: at.ok && at.body ? (at.body.deny_count || 0) + bl({ en: " denied", ja: " 拒否" }) : "" }),
     ovSegbar([{ value: dr || 0, color: drTone }, { value: Math.max(0, 100 - (dr || 0)), color: "var(--panel2)" }], 6)], null, drTone));
}
// ovDecisionsInWindow is how many access decisions the deployment made in the selected period. access-trends is
// the answer when it is readable; counts.access_decisions is one node's total and is only a fallback. Either may
// be null — a node that decides nothing now says so instead of sending a zero — and null renders as "—",
// because "we do not know" and "none happened" are different things to tell an operator. Returns the number
// or null; ovDecisionsText renders it, so the two places that show it cannot disagree about the dash.
function ovDecisionsInWindow(at, counts) {
  const w = at && at.ok && at.body ? at.body.window_decisions : null;
  const n = w != null ? w : (counts ? counts.access_decisions : null);
  return n == null ? null : n;
}
function ovDecisionsText(at, counts) {
  const n = ovDecisionsInWindow(at, counts);
  return n == null ? "\u2014" : ovNum(n);
}
function ovTile(lbl, big, small, extra, onClick, bigColor) {
  const t = el("div", { class: "ov-tile" + (onClick ? " ov-clickable" : "") }, [
    el("div", { class: "ov-lbl", text: lbl }),
    el("div", { class: "ov-big", style: bigColor ? "color:" + bigColor : "" }, [document.createTextNode(big), ...(small ? [el("small", { text: small })] : [])]),
    ...(extra || []),
  ]);
  if (onClick) t.addEventListener("click", onClick);
  return t;
}

// ---- device aggregate (reuses deviceStateOf from devices.js) ---------------------------------------------
async function ovDeviceAggregate() {
  const out = { total: 0, steering: 0, failopen: 0, offline: 0, blocked: 0, excluded: 0, encOn: 0, encTot: 0, fwOn: 0, fwTot: 0, platform: {}, risk: { none: 0, medium: 0, high: 0, critical: 0 }, reporting: 0 };
  // two-planes-deliberate: the two that decide the answer — who is enrolled, and whether they are steering —
  // both come from the authority, which is the only place that knows the whole fleet. The other three add
  // DETAIL about the devices this node happens to serve: exclusions, risk and groups. Their absence downgrades
  // a row from "Steering · 2 exclusions" to "Steering · via tokyo-west", which is still true; it can never
  // turn a steering device into a stopped one. That is the difference between a join that degrades and a join
  // that lies, and it is why this one is declared rather than fixed.
  const [de, rt, ob, rk, gr] = await Promise.all([ovGet("/admin/enrolled-devices"), ovGet("/admin/device-runtime"), ovGet("/admin/steer-exclusions/observed?limit=500"), ovGet("/admin/risk-signals"), ovGet("/admin/device-groups")]);
  // The device list is what every figure in here is computed from, so a refusal on it makes the whole
  // aggregate absent rather than empty. Carried out so the callers can tell the two apart.
  out.denied = ovDenied(de);
  const devices = (de.ok && de.body && de.body.devices) || [];
  const runtime = (rt.ok && rt.body && rt.body.devices) || {};
  const steer = byDeviceIdentity((ob.ok && ob.body && ob.body.observed) || []);
  const riskMap = (rk.ok && rk.body && rk.body.high_risk) || {};
  const groupRisk = Object.create(null); ((gr.ok && gr.body && gr.body.groups) || []).forEach((g) => { groupRisk[(g.name || "").trim().toLowerCase()] = g.risk || ""; });
  out.total = devices.length;
  devices.forEach((d) => {
    const r = runtime[d.identity] || runtime[deviceKey(d.identity)] || {}; const obs = steer[deviceKey(d.identity)];
    const sev = Object.hasOwn(riskMap, d.identity) ? riskMap[d.identity] : undefined; const grp = groupRisk[(d.group || "").trim().toLowerCase()] || "";
    const eff = (d.effective_risk && d.effective_risk.trim()) || (typeof riskMax === "function" ? riskMax(sev || "none", grp || "none") : (sev || "none"));
    out.risk[eff] = (out.risk[eff] || 0) + 1;
    const st = (typeof deviceStateOf === "function") ? deviceStateOf(d, obs, r, eff) : { steering: r.steer_active === true, offline: !obs, blocked: !d.enabled, failOpen: false, excluded: 0 };
    if (!d.enabled) out.blocked++; else if (st.failOpen) out.failopen++; else if (st.steering) out.steering++; else out.offline++;
    if (st.excluded > 0) out.excluded++;
    if (obs) out.reporting++;
    const p = r.posture || {};
    if (p.disk_encryption_enabled != null) { out.encTot++; if (p.disk_encryption_enabled) out.encOn++; }
    if (p.firewall_enabled != null) { out.fwTot++; if (p.firewall_enabled) out.fwOn++; }
    const os = (r.os || "").toLowerCase();
    const fam = os.includes("mac") ? "macOS" : os.includes("win") ? "Windows" : (os.includes("linux") || os.includes("ubuntu")) ? "Linux" : os.includes("android") ? "Android" : os ? "Other" : "Unknown";
    out.platform[fam] = (out.platform[fam] || 0) + 1;
  });
  return out;
}

// ---- (C) devices panel (aggregate only) ------------------------------------------------------------------
async function ovLoadDevices(host, setMore) {
  host.innerHTML = ""; host.appendChild(el("div", { class: "ov-foot", text: "…" }));
  const d = await ovDeviceAggregate();
  if (d.denied) {
    // Every donut and bar below is computed from the device list. With that list refused they would each draw
    // a confident 0 or 0% — see ovDenied.
    host.innerHTML = "";
    setMore("");
    host.appendChild(ovEmpty(bl({ en: "The device list is not readable here, so none of these figures could be computed. They are missing, not zero.",
                                  ja: "端末の一覧をここでは取得できないため、以下の数値は計算できていません。「0」ではなく「不明」です。" })));
    return;
  }
  setMore(d.total + bl({ en: " enrolled · aggregate · view all →", ja: " 台 · 集計 · 全件 →" }));
  const grid = el("div", { class: "ov-grid", style: "grid-template-columns:1fr 1fr 1fr" });
  const c1 = el("div", {}, [
    el("div", { class: "ov-metric", style: "margin-bottom:8px", text: bl({ en: "Steering state", ja: "ステアリングの状態" }) }),
    ovSegbar([{ value: d.steering, color: OV_TONE.ok, title: "steering" }, { value: d.failopen, color: OV_TONE.danger, title: "fail-open" }, { value: d.offline, color: OV_TONE.off, title: "offline" }, { value: d.blocked, color: OV_TONE.danger2, title: "blocked" }], 12),
    el("div", { style: "margin-top:14px;display:flex;flex-direction:column;gap:9px" }, [
      ovLeg(OV_TONE.ok, bl({ en: "Steering", ja: "ステア中" }), d.steering),
      ovLeg(OV_TONE.danger, bl({ en: "Fail-open engaged", ja: "fail-open 発動" }), d.failopen, d.failopen > 0 ? OV_TONE.danger2 : null),
      ovLeg(OV_TONE.off, bl({ en: "Not reporting", ja: "報告なし" }), d.offline),
      ovLeg(OV_TONE.danger2, bl({ en: "Blocked", ja: "ブロック" }), d.blocked),
    ]),
    // Honesty note: fail-open is SELF-reported, and a device only reports when it can still reach the edge. A
    // device cut off from the edge (which is exactly when it fails open) can't report that, so it shows under
    // "Not reporting", not "Fail-open engaged". "Not reporting" is therefore state-UNKNOWN (shut down, offline,
    // or fail-open-and-unreachable) — not a claim that the device is down.
    el("div", { class: "ov-note", style: "margin-top:12px", text: bl({ en: "\"Fail-open engaged\" is self-reported; a device cut off from the edge appears under \"Not reporting\" (state unknown), not fail-open.", ja: "「fail-open 発動」は自己申告 ―― edge から切れた端末は fail-open でも「報告なし（状態不明）」に出ます。" }) }),
  ]);
  if (d.excluded > 0) c1.appendChild(el("div", { style: "margin-top:12px" }, el("span", { class: "ui-badge", text: d.excluded + bl({ en: " with excluded apps", ja: " 台 除外アプリあり" }) })));
  const encPct = d.encTot ? Math.round((d.encOn / d.encTot) * 100) : 0, fwPct = d.fwTot ? Math.round((d.fwOn / d.fwTot) * 100) : 0;
  const c2 = el("div", {}, [
    el("div", { class: "ov-metric", style: "margin-bottom:10px", text: bl({ en: "Device posture", ja: "デバイスの状態" }) }),
    el("div", { style: "display:flex;gap:12px;justify-content:space-around" }, [
      el("div", { class: "ov-donutwrap" }, [ovDonut([{ value: d.encOn, color: OV_TONE.ok }, { value: d.encTot - d.encOn, color: OV_TONE.danger }], 84, encPct + "%", bl({ en: "encrypted", ja: "暗号化" })), el("div", { class: "ov-note", text: d.encOn + " / " + d.encTot })]),
      el("div", { class: "ov-donutwrap" }, [ovDonut([{ value: d.fwOn, color: (d.fwTot - d.fwOn) > 0 ? OV_TONE.warn : OV_TONE.ok }, { value: d.fwTot - d.fwOn, color: OV_TONE.warn }], 84, fwPct + "%", bl({ en: "firewall", ja: "FW" })), el("div", { class: "ov-note", text: d.fwOn + " / " + d.fwTot + (d.fwTot - d.fwOn > 0 ? " · " + (d.fwTot - d.fwOn) + " off" : "") })]),
    ]),
    el("div", { class: "ov-metric", style: "margin:16px 0 8px", text: bl({ en: "Risk", ja: "リスク" }) }),
    ovSegbar([{ value: d.risk.none, color: OV_TONE.off }, { value: d.risk.medium, color: OV_TONE.warn }, { value: d.risk.high, color: OV_TONE.danger }, { value: d.risk.critical, color: OV_TONE.danger2 }], 8),
    el("div", { class: "ov-legend", style: "margin-top:8px" }, [ovLegSmall(OV_TONE.off, d.risk.none + " normal"), ovLegSmall(OV_TONE.warn, d.risk.medium + " med"), ovLegSmall(OV_TONE.danger, d.risk.high + " high"), ovLegSmall(OV_TONE.danger2, d.risk.critical + " crit")]),
  ]);
  const platRows = Object.entries(d.platform).sort((a, b) => b[1] - a[1]).map(([k, v]) => ({ k, v, color: OV_TONE.accent }));
  const c3 = el("div", {}, [
    el("div", { class: "ov-metric", style: "margin-bottom:10px", text: bl({ en: "Platform", ja: "プラットフォーム" }) }),
    platRows.length ? ovHbar(platRows) : ovEmpty(bl({ en: "no runtime reports", ja: "稼働の報告なし" })),
    el("div", { class: "ov-metric", style: "margin:18px 0 8px", text: bl({ en: "Reporting", ja: "報告状況" }) }),
    el("div", { style: "display:flex;gap:8px;flex-wrap:wrap" }, [
      el("span", { class: "ui-badge ui-badge-ok", text: d.reporting + bl({ en: " reporting", ja: " 報告中" }) }),
      ...(d.total - d.reporting > 0 ? [el("span", { class: "ui-badge ui-badge-off", text: (d.total - d.reporting) + bl({ en: " no report", ja: " 報告なし" }) })] : []),
    ]),
    el("div", { class: "ov-note", style: "margin-top:14px", text: bl({ en: "Aggregated from the Devices state model — no extra backend.", ja: "Devices 状態モデルの集計 ―― 追加バックエンド不要。" }) }),
  ]);
  grid.appendChild(c1); grid.appendChild(c2); grid.appendChild(c3);
  host.innerHTML = ""; host.appendChild(grid);
}

// ---- (D) decision analytics ------------------------------------------------------------------------------
async function ovLoadDecisions(mixHost, setMore, denyHost) {
  mixHost.innerHTML = ""; denyHost.innerHTML = ""; mixHost.appendChild(el("div", { class: "ov-foot", text: "…" }));
  const at = await ovGet("/admin/ai-ops/access-trends?window=" + _ovPeriod);
  if (!at.ok || !at.body) { mixHost.innerHTML = ""; mixHost.appendChild(ovEmpty(bl({ en: "Decision analytics unavailable.", ja: "判定分析を取得できません。" }))); denyHost.appendChild(ovEmpty("—")); return; }
  const b = at.body, byd = b.by_decision || {};
  const allow = byd.allow || byd.allowed || 0, denyN = b.deny_count || byd.deny || 0, step = b.step_up_count || byd.require_reauth || byd.step_up || 0;
  setMore(ovNum(b.window_decisions || 0) + bl({ en: " decisions", ja: " 判定" }));
  const total = (b.window_decisions || (allow + denyN + step)) || 1;
  mixHost.innerHTML = "";
  // These decisions are held in memory and evicted under pressure, so the period asked for is not always the
  // period answered. Say so on the panel when it happens — the tiles above print the period as a fact.
  if (b.coverage && b.coverage.truncated) {
    const note = uiCoverageNote(b.coverage);
    if (note) mixHost.appendChild(el("div", { style: "margin-bottom:10px" }, [note]));
  }
  mixHost.appendChild(el("div", { style: "display:flex;align-items:center;gap:22px" }, [
    ovDonut([{ value: allow, color: OV_TONE.ok }, { value: denyN, color: OV_TONE.warn }, { value: step, color: OV_TONE.accent }], 120, Math.round((allow / total) * 100) + "%", bl({ en: "allow", ja: "許可" })),
    el("div", { style: "display:flex;flex-direction:column;gap:9px;min-width:150px" }, [
      ovLeg(OV_TONE.ok, bl({ en: "Allow", ja: "許可" }), ovNum(allow)),
      ovLeg(OV_TONE.warn, bl({ en: "Deny", ja: "拒否" }), ovNum(denyN)),
      ovLeg(OV_TONE.accent, bl({ en: "Step-up", ja: "追加認証" }), ovNum(step)),
    ]),
  ]));
  const splitRows = (m, color) => Object.entries(m || {}).sort((a, b) => b[1] - a[1]).slice(0, 4).map(([k, v]) => ({ k, v, color }));
  const actor = splitRows(b.by_actor_type, OV_TONE.accent), svc = splitRows(b.by_service_family, OV_TONE.muted);
  mixHost.appendChild(el("div", { class: "ov-grid", style: "grid-template-columns:1fr 1fr;margin-top:16px" }, [
    el("div", {}, [el("div", { class: "ov-metric", style: "margin-bottom:8px", text: bl({ en: "By actor", ja: "実行者別" }) }), actor.length ? ovHbar(actor, ovNum) : ovEmpty("—")]),
    el("div", {}, [el("div", { class: "ov-metric", style: "margin-bottom:8px", text: bl({ en: "By service", ja: "service 別" }) }), svc.length ? ovHbar(svc, ovNum) : ovEmpty("—")]),
  ]));
  const dr = (b.top_deny_reason_codes || []).slice(0, 6).map((x, i) => ({ k: x.key || x.code || "—", v: x.count || 0, color: i < 2 ? OV_TONE.danger : OV_TONE.warn }));
  denyHost.appendChild(dr.length ? ovHbar(dr, ovNum) : ovEmpty(bl({ en: "No denies in window.", ja: "窓内に拒否なし。" })));
  const tp = (b.top_denied_policies || []).slice(0, 4);
  if (tp.length) { denyHost.appendChild(el("div", { class: "ov-metric", style: "margin:16px 0 8px", text: bl({ en: "Top denied policies", ja: "拒否の多いポリシー" }) })); denyHost.appendChild(el("div", { style: "display:flex;gap:8px;flex-wrap:wrap" }, tp.map((x) => el("span", { class: "ui-badge ui-badge-off", text: (x.key || "—") + " · " + ovNum(x.count || 0) })))); }
}

// ---- (E) activity over time ------------------------------------------------------------------------------
async function ovLoadActivity(host) {
  host.innerHTML = ""; host.appendChild(el("div", { class: "ov-foot", text: "…" }));
  const w = ovWindow();
  // ★★ THE ANALYTICS STORE IS ON THE CONTROL PLANE, AND THIS PANEL ASKED THE EDGE (2026-08-19). The Edge
  // answers 501 — correctly, it keeps no ingest-time rollup — and this screen turned that into "not enabled on
  // this backend", which an operator reads as "this deployment has no analytics". Measured on the lab in the
  // same second: the Edge 501s and the control plane returns 200 with real buckets. The panel had reported the
  // feature missing for as long as it has existed, including every day ClickHouse was perfectly healthy, and
  // separately from the weeks it was genuinely down for a credential mismatch.
  //
  // Audit and reporting belong to the control plane in this topology — the console-server proxies them there —
  // so the plane is stated rather than left to the default.
  const r = await ovGet("/admin/events/trends?from=" + encodeURIComponent(w.from) + "&to=" + encodeURIComponent(w.to) + "&granularity=" + w.gran, "control");
  host.innerHTML = "";
  // A 501 from the control plane means the deployment really has no analytics store. The wording says which
  // plane was asked, because "not enabled" without a subject is what made this unactionable for months.
  if (r.status === 501) { host.appendChild(ovEmpty(bl({ en: "Activity trends need the analytics (ClickHouse) store, and the control plane reports none configured.", ja: "アクティビティ時系列には分析(ClickHouse)ストアが必要で、コントロールプレーンは未設定と答えています。" }))); return; }
  // A refused read is not a quiet window. "No activity" about an organization this console was not allowed to
  // read is the same lie the tiles used to tell with a zero.
  if (ovDenied(r)) { host.appendChild(ovEmpty(bl({ en: "Activity is not readable here — this is not a quiet window.", ja: "このテナントのアクティビティはここでは取得できません。「活動がない」ではありません。" }))); return; }
  if (!r.ok || !r.body || !Array.isArray(r.body.buckets) || r.body.buckets.length === 0) { host.appendChild(ovEmpty(bl({ en: "No activity in this window.", ja: "この期間の動きはありません。" }))); return; }
  const byTime = {};
  r.body.buckets.forEach((b) => { const e = byTime[b.bucket] || (byTime[b.bucket] = { events: 0, users: 0, destinations: 0 }); e.events += b.events || 0; e.users = Math.max(e.users, b.users || 0); e.destinations = Math.max(e.destinations, b.destinations || 0); });
  const keys = Object.keys(byTime).sort();
  const series = [
    { values: keys.map((k) => byTime[k].events), color: OV_TONE.accent, fill: true },
    { values: keys.map((k) => byTime[k].users), color: OV_TONE.ok },
    { values: keys.map((k) => byTime[k].destinations), color: OV_TONE.warn },
  ];
  host.appendChild(el("div", { class: "ov-legend", style: "justify-content:flex-end;margin-bottom:8px" }, [ovLegSmall(OV_TONE.accent, "events"), ovLegSmall(OV_TONE.ok, "users"), ovLegSmall(OV_TONE.warn, "destinations")]));
  host.appendChild(ovArea(series, 900, 150));
  host.appendChild(el("div", { class: "ov-note", text: "/admin/events/trends · " + keys.length + bl({ en: " buckets · " + w.gran, ja: " 区間 · " + w.gran }) }));
}

// ---- (F) tenants + (G) regions ---------------------------------------------------------------------------
async function ovLoadTenantsRegions(tHost, setMore, rHost) {
  tHost.innerHTML = ""; rHost.innerHTML = "";
  // ★ DO NOT ASK A QUESTION THIS CALLER MAY NOT ASK (2026-08-17). A customer administrator holds no
  // cross-tenant permission, so /admin/tenants answered 403 on EVERY dashboard load — a permanent refusal in
  // their logs and ours, for an answer the page then discards in favour of their own organization anyway.
  //
  // ★ AND NOT WHILE OPERATING INSIDE ONE (2026-08-17). An operator who has entered a customer is looking at
  // that customer's screen, under a banner that says so — and this panel listed EVERY organization on the
  // deployment, with their plans and configuration versions, on it. Same shape as the certificates screen that
  // told an operator inside a new organization which CA a DIFFERENT customer's devices verify with: entering
  // is a mode, and the answer follows the organization the request names.
  const asksForTheList = answeringForTheDeployment();
  const [tn, cs, me] = await Promise.all([
    asksForTheList ? ovGet("/admin/tenants") : Promise.resolve({ ok: false, body: null }),
    ovGet("/admin/config-sync-status"),
    ovGet("/admin/tenant"),
  ]);
  let tenants = (tn.ok && tn.body && tn.body.tenants) || null;
  if (!tenants && me.ok && me.body) tenants = [me.body];
  if (!tenants || !tenants.length) {
    // "Unavailable" reads as a fault. For a customer there is nothing wrong: this panel is about the
    // deployment's organizations, and they have one — their own — which the line above already found.
    tHost.appendChild(ovEmpty(asksForTheList
      ? bl({ en: "The tenant list could not be read.", ja: "テナントの一覧を取得できませんでした。" })
      : operateTenant
        // "Your organization" is the customer's sentence. An operator inside a customer is not looking at
        // theirs, and this panel is deliberately not the deployment-wide list while they are in here.
        ? bl({ en: "This screen is about the tenant you have entered.", ja: "この画面は、いま入っているテナントについてのものです。" })
        : bl({ en: "Your tenant is shown above.", ja: "あなたのテナントは上に表示されています。" })));
  }
  else {
    setMore(answeringForTheDeployment() ? tenants.length + bl({ en: " tenants", ja: " テナント" }) : "");
    const rows = tenants.map((t) => el("tr", {}, [
      el("td", {}, [el("strong", { text: t.display_name || t.tenant_id || "—" }), ...(t.is_operator ? [el("span", { class: "ui-badge ui-badge-off", style: "margin-left:6px", text: bl({ en: "operator", ja: "運営" }) })] : [])]),
      el("td", { class: "ui-view-desc", text: t.plan || "—" }),
      el("td", {}, el("code", { text: t.home_region || t.region || "—" })),
      el("td", {}, uiBadge(t.status || "—", t.status === "active" ? "ok" : t.status === "suspended" ? "warn" : "off")),
      el("td", { style: "text-align:right" }, el("code", { text: t.policy_bundle_version ? "v" + t.policy_bundle_version : "—" })),
    ]));
    tHost.appendChild(el("div", { style: "overflow-x:auto" }, el("table", { class: "ui-table" }, [
      el("thead", {}, el("tr", {}, [[bl({ en: "Tenant", ja: "テナント" }), 0], [bl({ en: "Plan", ja: "プラン" }), 0], [bl({ en: "Home region", ja: "ホーム" }), 0], [bl({ en: "Status", ja: "状態" }), 0], [bl({ en: "Configuration", ja: "設定の版" }), 1]].map(([h, r]) => el("th", { style: r ? "text-align:right" : "", text: h })))),
      el("tbody", {}, rows),
    ])));
  }
  const regionSet = {};
  (tenants || []).forEach((t) => { const home = t.home_region || t.region; if (home) (regionSet[home] = regionSet[home] || { name: home, tenants: 0, home: 0 }); (t.allowed_regions || []).forEach((a) => { regionSet[a] = regionSet[a] || { name: a, tenants: 0, home: 0 }; }); if (home) { regionSet[home].tenants++; regionSet[home].home++; } });
  if (me.ok && me.body && me.body.region) { const rr = me.body.region; regionSet[rr] = regionSet[rr] || { name: rr, tenants: 0, home: 0 }; }
  const regions = Object.values(regionSet);
  if (!regions.length) rHost.appendChild(ovEmpty(bl({ en: "No region config surfaced.", ja: "リージョン構成なし。" })));
  else regions.sort((a, b) => b.home - a.home).forEach((rg, i) => {
    rHost.appendChild(el("div", { class: "ov-region", style: i > 0 ? "margin-top:10px" : "" }, [
      el("span", { class: "ov-dot ov-dot-" + (rg.home > 0 ? "ok" : "off") }),
      el("div", {}, [el("div", { style: "font-weight:600", text: rg.name }), el("div", { class: "ov-note", style: "margin-top:2px", text: answeringForTheDeployment() ? rg.tenants + bl({ en: " tenants", ja: " テナント" }) : bl({ en: "serves this tenant", ja: "このテナントを提供しています" }) })]),
      el("span", { class: "ui-badge ui-badge-" + (rg.home > 0 ? "ok" : "off"), style: "margin-left:auto", text: rg.home > 0 ? bl({ en: "primary", ja: "主" }) : bl({ en: "allowed", ja: "許可" }) }),
    ]));
  });
  const csTxt = (cs.ok && cs.body && cs.body.enabled) ? (cs.body.healthy === false ? bl({ en: "degraded", ja: "低下" }) : bl({ en: "healthy", ja: "正常" })) : bl({ en: "off", ja: "無効" });
  rHost.appendChild(el("div", { class: "ov-empty", style: "margin-top:10px" }, [document.createTextNode(bl({ en: "Live per-region reachability not yet reported. Config-sync: ", ja: "リージョンごとの到達性はまだ報告されていません。設定の同期: " })), el("b", { text: csTxt })]));
}

// ---- (H) edge & connectors -------------------------------------------------------------------------------
async function ovLoadEdge(host, setMore) {
  host.innerHTML = ""; host.appendChild(el("div", { class: "ov-foot", text: "…" }));
  // The AI figure follows the page's period control like everything else here. It used to be fetched with no
  // window and labelled "7d" from a string literal, so the control moved every number on the page except this one.
  // Decisions come from access-trends, the same source as the tile at the top of the page: it is windowed, and
  // it reads the deployment's whole access stream rather than the ring of the node that happens to serve this
  // Console. This block used to print counts.access_decisions under the label "Decisions (window)" — a total
  // that ignored the period control, and on a control plane a zero about a deployment that was deciding.
  // two-planes-deliberate: separate figures again — connector liveness is the authority's, decisions and AI
  // traffic are the enforcement stream's. Nothing here combines the two into one number.
  const [st, conn, ai, at] = await Promise.all([ovGet("/admin/state"), ovGet("/admin/connectors"), ovGet("/admin/ai-usage-report?window=" + encodeURIComponent(_ovPeriod)), ovGet("/admin/ai-ops/access-trends?window=" + encodeURIComponent(_ovPeriod))]);
  // Refused reads are absent, not empty — see ovDenied. "No connectors registered" and "0 decisions" about an
  // organization this console may not read are the same claim the tiles used to make with a zero.
  if (ovDenied(st, conn, ai)) {
    host.innerHTML = ""; setMore("");
    host.appendChild(ovEmpty(bl({ en: "Connectors, decisions and AI traffic are not readable here — absent, not zero.",
                                  ja: "コネクタ・判定・AI 通信はここでは取得できません。「0」ではなく「不明」です。" })));
    return;
  }
  const connectors = (conn.ok && conn.body && conn.body.connectors) || [];
  setMore(connectors.length + bl({ en: " registered", ja: " 登録済み" }));
  const grid = el("div", { class: "ov-grid", style: "grid-template-columns:1.4fr 1fr" });
  const rows = connectors.map((c) => el("tr", {}, [
    el("td", {}, [el("code", { text: c.id || "—" }), ...(c.name ? [el("span", { class: "ui-view-desc", style: "margin-left:6px", text: c.name })] : [])]),
    el("td", {}, el("code", { text: c.edge_region_id || "—" })),
    el("td", {}, uiBadge(c.tunnel_connected === true ? bl({ en: "up", ja: "up" }) : bl({ en: "down", ja: "断" }), c.tunnel_connected === true ? "ok" : "danger")),
    el("td", { class: "ui-view-desc", text: ovAgo(c.last_heartbeat_at) }),
    el("td", { class: "ui-view-desc", style: "text-align:right", text: (((c.reachable_routes && (c.reachable_routes.cidr_count || 0) + (c.reachable_routes.fqdn_domain_count || 0)) || 0)) + bl({ en: " routes", ja: " 経路" }) }),
  ]));
  const left = connectors.length ? el("div", { style: "overflow-x:auto" }, el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [[bl({ en: "Connector", ja: "コネクタ" }), 0], [bl({ en: "Region", ja: "リージョン" }), 0], [bl({ en: "Tunnel", ja: "トンネル" }), 0], [bl({ en: "Heartbeat", ja: "最終応答" }), 0], [bl({ en: "Routes", ja: "経路" }), 1]].map(([h, r]) => el("th", { style: r ? "text-align:right" : "", text: h })))),
    el("tbody", {}, rows),
  ])) : ovEmpty(bl({ en: "No connectors registered.", ja: "コネクタ未登録。" }));
  const counts = (st.ok && st.body && st.body.counts) || {};
  const aiBody = (ai.ok && ai.body) || {}; const aiUp = aiBody.total_bytes_sent || 0, aiDown = aiBody.total_bytes_received || 0;
  const right = el("div", {}, [
    el("div", { style: "display:flex;gap:22px;flex-wrap:wrap" }, [
      el("div", {}, [el("div", { class: "ov-metric", text: bl({ en: "Decisions · " + _ovPeriod, ja: "判定 · " + _ovPeriod }) }), el("div", { class: "ov-big", style: "font-size:22px", text: ovDecisionsText(at, counts) })]),
      el("div", {}, [el("div", { class: "ov-metric", text: bl({ en: "AI traffic · ", ja: "AI 通信 · " }) + ((aiBody.window && aiBody.window.requested) || _ovPeriod) }), el("div", { class: "ov-big", style: "font-size:22px", text: ovBytes(aiUp + aiDown) }), el("div", { class: "ov-note", text: ovBytes(aiUp) + " ↑ · " + ovBytes(aiDown) + " ↓" })]),
    ]),
    el("div", { class: "ov-metric", style: "margin:16px 0 6px" }, [document.createTextNode(bl({ en: "Total bandwidth ", ja: "総帯域 " })), el("span", { class: "ui-badge ui-badge-off", text: bl({ en: "pending metric", ja: "計測はこれから" }) })]),
    el("div", { class: "ov-note", text: bl({ en: "Total edge bytes up/down — instrumentation pending (dsse_edge_bytes_total).", ja: "エッジの総送受信量は、まだ計測していません。" }) }),
  ]);
  grid.appendChild(left); grid.appendChild(right);
  host.innerHTML = ""; host.appendChild(grid);
}

// ---- (I) usage & quota -----------------------------------------------------------------------------------
async function ovLoadUsage(host) {
  host.innerHTML = ""; host.appendChild(el("div", { class: "ov-foot", text: "…" }));
  const r = await ovGet("/admin/usage/summary");
  host.innerHTML = "";
  if (!r.ok || !r.body || !r.body.meters) { host.appendChild(ovEmpty(bl({ en: "Usage data unavailable.", ja: "利用データを取得できません。" }))); return; }
  const meters = Object.values(r.body.meters);
  if (!meters.length) { host.appendChild(ovEmpty(bl({ en: "No metered usage this period.", ja: "今期の計測なし。" }))); return; }
  const grid = el("div", { class: "ov-grid", style: "grid-template-columns:repeat(3,1fr)" });
  meters.slice(0, 6).forEach((m) => {
    const q = m.quota || {}, inc = q.included_quantity || 0, used = m.quantity || 0;
    const pct = inc ? Math.min(100, Math.round((used / inc) * 100)) : 0;
    const tone = q.hard_cap_exceeded ? OV_TONE.danger : (q.soft_cap_exceeded || pct >= 85) ? OV_TONE.warn : OV_TONE.ok;
    grid.appendChild(el("div", {}, [
      el("div", { class: "ov-metric", style: "display:flex;justify-content:space-between" }, [el("span", { text: (m.meter_type || "").replace(/_/g, " ") }), el("span", { style: "color:" + tone + ";font-variant-numeric:tabular-nums", text: ovNum(used) + (inc ? " / " + ovNum(inc) : "") + (m.unit ? " " + m.unit : "") })]),
      el("div", { style: "margin-top:8px" }, ovSegbar([{ value: pct, color: tone }, { value: 100 - pct, color: "var(--panel2)" }], 9)),
      el("div", { class: "ov-note", text: inc ? (pct >= 85 ? bl({ en: "approaching cap", ja: "上限接近" }) : bl({ en: pct + "% of plan", ja: "プランの " + pct + "%" })) : bl({ en: "no cap", ja: "上限なし" }) }),
    ]));
  });
  host.appendChild(grid);
}
