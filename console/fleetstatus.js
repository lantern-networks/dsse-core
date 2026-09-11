"use strict";

// ---------------------------------------------------------------------------
// "Configuration reach" — the Overview panel answering: is what an operator authored actually in effect at
// every Edge?
//
// ★ Why this exists (2026-08-10). An operator adopted a bypass, this Console confirmed it, and the endpoint
// whose only purpose is to show what is really NOT being decrypted listed the host. The device kept being
// intercepted, because it was served by the OTHER Edge — one that had never heard of the change. Every surface
// agreed with the operator. "Applied" meant "applied on whichever Edge the front door proxies to", and nothing
// on screen could have revealed it. See docs/authored_policy_reaches_one_edge_not_the_serving_one.md.
//
// ★ ON THE DASHBOARD, not beside the settings. This carries no control — there is nothing here to configure —
// and a screen that only describes does not belong among the ones that configure. It is fleet state, so it
// lives where fleet state lives, and it is visible without anyone deciding to go looking.
//
// ★ AND IT MUST NEVER READ AS AGREEMENT WHEN IT DOES NOT KNOW. The endpoint is served by the control plane; a
// single-node deployment, or an older control plane, returns 404. Rendering that as "everywhere" would repeat
// the original defect inside the component built to end it, so an unavailable answer says so and an empty
// fleet is not "all in sync" — the API decides that, and this file does not second-guess it.
//
// Backend: GET /admin/fleet/config-status (control plane). Loaded before overview.js; uses that page's
// idioms (el / ovPanel / ovEmpty / uiBadge).
// ---------------------------------------------------------------------------

// Plain words. "generation", "epoch" and "in_sync" are our vocabulary, not the reader's, and none of them
// change what an operator does next.
// ★ ABOUT CONFIGURATION ONLY. There is no "missing" or "not responding" state, because the fleet is whatever
// is reporting NOW: instances are created and destroyed continuously, so one that stops reporting has almost
// always been removed. A first version kept them and counted them as behind, which turned a routine scale-in
// into "4 Edges, 2 not responding" — an alarm manufactured from normal operation, and an assertion about an
// EXPECTED count that nothing here knows.
const FLEET_STATE = {
  current: { tone: "ok", t: { en: "In effect", ja: "反映済み" } },
  lagging: { tone: "warn", t: { en: "Catching up", ja: "反映中" } },
  never_applied: { tone: "warn", t: { en: "Nothing applied", ja: "未反映" } },
  error: { tone: "danger", t: { en: "Error", ja: "エラー" } },
};

// ONE fetch per dashboard render, shared as a promise by the three places that need it. A time-based cache was
// tried and removed: it made the module hold state between renders, which is invisible to a caller and was
// immediately wrong in tests. Passing the promise keeps "one request" true without anything remembering.
//
// Consumers that are handed nothing fetch for themselves, so each panel still works alone.
async function fleetStatus() {
  try {
    return await apiFetch("GET", "/admin/fleet/config-status", undefined, "control");
  } catch (e) {
    return { ok: false, status: 0, body: null };
  }
}

// fleetRollup reduces the API's per-instance rows to what the dashboard renders: totals, and a per-region
// grouping. Kept in ONE place so the strip, the reach panel and the Edge list cannot count differently.
function fleetRollup(body) {
  const edges = (body && Array.isArray(body.edges) ? body.edges : []);
  const byRegion = {};
  edges.forEach((e) => {
    const k = String(e.region_id || "").trim() || "—";
    (byRegion[k] = byRegion[k] || { name: k, all: [] }).all.push(e);
  });
  const regions = Object.values(byRegion).sort((a, b) => a.name.localeCompare(b.name));
  regions.forEach((g) => {
    g.ok = g.all.filter((e) => e.status === "current").length;
    g.worst = g.all.reduce((w, e) => (FLEET_RANK[e.status] || 0) > (FLEET_RANK[w.status] || 0) ? e : w, g.all[0]);
  });
  return { edges, regions, behind: edges.filter((e) => e.status !== "current") };
}

const FLEET_RANK = { error: 3, never_applied: 2, lagging: 1, current: 0 };

async function ovLoadFleetConfig(host, setMore, shared) {
  host.innerHTML = "";
  const res = await (shared || fleetStatus());

  // No control plane serving this (single-node), or one that predates the route. Neither is a fault and
  // neither is agreement.
  if (res.status === 404 || res.status === 501) {
    setMore("");
    host.appendChild(ovEmpty(bl({
      en: "Not available on this deployment.",
      ja: "この構成では取得できません。",
    })));
    return;
  }
  if (!res.ok || !res.body || !Array.isArray(res.body.edges)) {
    setMore("");
    host.appendChild(ovEmpty(bl({
      en: "Cannot tell where configuration is in effect.",
      ja: "設定がどこまで反映されているか確認できません。",
    })));
    return;
  }

  const { edges, regions, behind } = fleetRollup(res.body);

  // ★ Counted in INSTANCES, not regions. A region is not one Edge — production fronts several behind a load
  // balancer, and "region-a is fine" is exactly the summary that hid a lagging sibling.
  if (res.body.in_sync) {
    setMore(bl({ en: "all " + edges.length + " in effect", ja: edges.length + " 台すべて反映済み" }));
  } else if (!edges.length) {
    setMore(bl({ en: "none reporting", ja: "報告なし" }));
  } else {
    setMore(bl({ en: behind.length + " of " + edges.length + " behind", ja: edges.length + " 台中 " + behind.length + " 台が未反映" }));
  }

  if (!edges.length) {
    host.appendChild(ovEmpty(bl({
      en: "No Edge has reported. Nothing authored here is confirmed to be in effect anywhere.",
      ja: "反映を報告した Edge がありません。ここで設定した内容が、どこかで有効になっている確証はありません。",
    })));
    return;
  }

  // Grouped by region for DISPLAY, per instance for TRUTH. The node id is a container hash — plumbing, and not
  // something an operator acts on — so the row names the region and says how many of its instances are in
  // effect. The badge takes the WORST state in the region: a region with one lagging Edge is not "in effect",
  // and a summary that rounded it up would be the same lie in a smaller box.
  regions.forEach((g, i) => {
    const worst = g.worst;
    const st = FLEET_STATE[worst.status] || { tone: "off", t: { en: worst.status || "—", ja: worst.status || "—" } };
    const ok = g.ok;
    // Stated only when the region has more than one Edge: "region-a (1 of 1)" is noise. No "last heard" —
    // everything in this list reported within the freshness window, so recency is not a fact worth a column.
    const note = g.all.length > 1
      ? bl({ en: ok + " of " + g.all.length + " in effect", ja: g.all.length + " 台中 " + ok + " 台が反映済み" })
      : "";
    host.appendChild(el("div", { class: "ov-region", style: i > 0 ? "margin-top:10px" : "" }, [
      el("span", { class: "ov-dot ov-dot-" + st.tone }),
      el("div", {}, [
        el("div", { style: "font-weight:600", text: g.name }),
        el("div", { class: "ov-note", style: "margin-top:2px", text: note }),
      ]),
      el("span", { class: "ui-badge ui-badge-" + st.tone, style: "margin-left:auto", text: bl(st.t) }),
    ]));
  });
}

// ---------------------------------------------------------------------------
// The two dashboard surfaces that assumed a single Edge.
// ---------------------------------------------------------------------------

// fleetStripChip replaces the top strip's `edge <cluster> · region <region> · bundle vN`.
//
// ★ That chip named whichever Edge the console front door happens to proxy to, and presented it as the
// system's identity. On a dashboard for the whole of DSSE that is not a detail — it is the same claim the
// incident was made of: one node answering for the fleet, with nothing on screen saying so. A fleet has no
// single cluster id, region or bundle version, so the honest chip is a COUNT.
function fleetStripChip(res) {
  if (!res || !res.ok || !res.body || !Array.isArray(res.body.edges)) return null;
  const { edges, regions, behind } = fleetRollup(res.body);
  if (!edges.length) {
    return el("span", { class: "ov-id" }, [el("b", { text: bl({ en: "no Edges reporting", ja: "報告中の Edge なし" }) })]);
  }
  const tone = behind.length ? (behind.some((e) => e.status === "error") ? "danger" : "warn") : "ok";
  return el("span", { class: "ov-id" }, [
    el("span", { class: "ov-dot ov-dot-" + tone, style: "margin-right:6px" }),
    el("b", { text: String(edges.length) }),
    // The published shapes include one Edge in one region, so the plural is not a safe default: this line
    // read "1 Edges · 1 regions" on the deployment it was written for. Japanese has no plural to get wrong.
    document.createTextNode(bl({ en: (edges.length === 1 ? " Edge · " : " Edges · "), ja: " 台の Edge · " })),
    el("b", { text: String(regions.length) }),
    document.createTextNode(bl({ en: (regions.length === 1 ? " region" : " regions"), ja: " リージョン" })),
    ...(behind.length ? [document.createTextNode(bl({ en: " · " + behind.length + " behind", ja: " · " + behind.length + " 台が未反映" }))] : []),
  ]);
}

// ovLoadEdgesByRegion lists every Edge, grouped by region.
//
// ★ COUNTED AND NAMED IN EDGES, not "sites" or "enforcement points". Several Edges sit behind one load
// balancer in one place, so a count of Edges is not a count of locations and must not be worded as though it
// were. "Edge" is this product's own noun for the component and is already what the rest of the Console says.
//
// ★ The panel this replaces was titled "Edge & connector fleet" and listed NO EDGES — it showed connectors and
// labelled itself "this edge · region-a", from /admin/state on the one node the Console talks to. A region is
// not one Edge either: production fronts several behind a load balancer, and the instance that is BEHIND is
// the one an operator needs to find.
//
// ★ INSTANCES ARE NOT NAMED HERE. A first version listed each one by its hostname, on the argument that it
// answers "which one do I go and look at". In a fleet where instances are created and destroyed continuously
// that identifier is an ephemeral container hash: it is not a name, it will not exist by the time anyone looks
// it up, and the orchestrator — not this console — is where a specific process is found. What the operator can
// act on is the region and how much of it holds the current configuration.
// fleetByState collapses a region's instances into one row per configuration state, worst first.
function fleetByState(all) {
  const by = {};
  all.forEach((e) => {
    const k = e.status || "—";
    (by[k] = by[k] || { status: k, count: 0, rules: e.rule_count });
    by[k].count++;
    // Instances in the same state should agree on the rule count; if they do not, say nothing rather than pick.
    if (by[k].rules !== e.rule_count) by[k].rules = null;
  });
  return Object.values(by).sort((a, b) => (FLEET_RANK[b.status] || 0) - (FLEET_RANK[a.status] || 0));
}

async function ovLoadEdgesByRegion(host, setMore, shared) {
  host.innerHTML = "";
  const res = await (shared || fleetStatus());
  if (res.status === 404 || res.status === 501) {
    setMore("");
    host.appendChild(ovEmpty(bl({ en: "Not available on this deployment.", ja: "この構成では取得できません。" })));
    return;
  }
  if (!res.ok || !res.body || !Array.isArray(res.body.edges)) {
    setMore("");
    host.appendChild(ovEmpty(bl({ en: "Cannot list the Edges.", ja: "Edge の一覧を取得できません。" })));
    return;
  }
  const { edges, regions } = fleetRollup(res.body);
  if (!edges.length) {
    setMore("");
    host.appendChild(ovEmpty(bl({
      en: "No Edge has reported.",
      ja: "報告した Edge がありません。",
    })));
    return;
  }
  setMore(bl({ en: edges.length + " across " + regions.length + " regions", ja: regions.length + " リージョン · " + edges.length + " 台" }));

  regions.forEach((g, gi) => {
    host.appendChild(el("div", { style: (gi ? "margin-top:14px;" : "") + "font-weight:600", text: g.name }));
    host.appendChild(el("div", { style: "overflow-x:auto;margin-top:6px" }, el("table", { class: "ui-table" }, [
      el("thead", {}, el("tr", {}, [
        el("th", { text: bl({ en: "Configuration", ja: "設定" }) }),
        el("th", { text: bl({ en: "Edges", ja: "Edge" }) }),
        el("th", { style: "text-align:right", text: bl({ en: "Rules in effect", ja: "有効なルール" }) }),
      ])),
      // Grouped by the state itself: "2 Edges in effect, 1 catching up" is the shape of the fleet right now,
      // which is what a dashboard shows. A row per ephemeral process is a list that is already out of date.
      el("tbody", {}, fleetByState(g.all).map((row) => {
        const st = FLEET_STATE[row.status] || { tone: "off", t: { en: row.status || "—", ja: row.status || "—" } };
        return el("tr", {}, [
          el("td", {}, uiBadge(bl(st.t), st.tone)),
          el("td", { class: "ui-view-desc", text: String(row.count) }),
          el("td", { class: "ui-view-desc", style: "text-align:right", text: row.rules == null ? "—" : String(row.rules) }),
        ]);
      })),
    ])));
  });
}
