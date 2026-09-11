"use strict";

// operatormachines.js — the machines this deployment runs on, on the operator's own screen.
//
// ★★★ THE OPERATOR COULD NOT SEE THE DEPLOYMENT (2026-09-03, found by adding a fourth machine to a running
// region and then looking for it). The operator's home showed three blocks — the organizations they run, the
// capacity they can allocate, what they are distributing — and nothing about the deployment itself. The
// customer Overview has a fleet panel, but an operator does not land there, and it groups by STATE ("2 in
// effect, 1 catching up") rather than naming anything, deliberately, from a time when Edges were assumed to
// be interchangeable instances behind a load balancer.
//
// This product's Edges are not that. They are machines an operator DECLARED, in a plan, with names — and when
// one of them is behind, the only useful thing a screen can say is WHICH ONE.
//
// ★ SO EVERY ROW NAMES A MACHINE. Not a container id: those change every time a container is recreated, and
// three of them in a region is not an answer to anything. The installer carries each machine's declared name
// onto it and the node reports it back; a deployment that predates that shows the id it has, labelled as such,
// rather than pretending.
//
// ★ AND IT SAYS WHAT IT CANNOT SEE. A machine that has not reported recently is not "gone" — this view is
// built from what nodes SAY, so silence means silence. It is listed as not reporting, with when it last did.
//
// Backend: GET /admin/fleet/config-status (control plane).

// The words the control plane uses, in the words a reader uses. "generation", "epoch" and "lagging" are our
// vocabulary; none of them change what an operator does next.
const OP_MACHINE_STATE = {
  current:       { tone: "ok",   t: { en: "In effect",      ja: "反映済み" } },
  lagging:       { tone: "warn", t: { en: "Catching up",    ja: "追いついている途中" } },
  never_applied: { tone: "warn", t: { en: "Nothing applied yet", ja: "まだ何も反映していない" } },
  error:         { tone: "err",  t: { en: "Reported a problem", ja: "問題を報告している" } },
  silent:        { tone: "warn", t: { en: "Not reporting",  ja: "報告なし" } },
};

function opMachineRows(body) {
  const edges = (body && Array.isArray(body.edges)) ? body.edges : [];
  return edges.map((e) => {
    const machine = String(e.machine || "").trim();
    return {
      // The name if the deployment carries one; otherwise say plainly that this is the container's id, so
      // nobody reads a hex string as a machine name.
      name: machine || String(e.node_id || "").trim(),
      named: !!machine,
      address: String(e.machine_address || "").trim(),
      region: String(e.region_id || "").trim(),
      rules: e.rule_count == null ? null : Number(e.rule_count),
      reportedAt: String(e.reported_at || "").trim(),
      // ★★★ THE AUTHORITY'S VERDICT, NOT A SECOND ONE COMPUTED HERE (2026-09-03, caught the first time this
      // was rendered against a live fleet). The first version compared this node's generation with the
      // control plane's and decided for itself — and showed three of four machines "catching up" while the
      // API that produced both numbers said all four were current. The comparison is not the screen's to
      // make: the control plane knows what an epoch change means and when a number may not be compared at
      // all, and it publishes the answer. A view that recomputes it is a second opinion that will differ.
      status: String(e.status || "").trim(),
    };
  });
}

// How long ago, in words. A timestamp is a thing to subtract; "4 minutes ago" is a thing to read.
function opMachineWhen(iso) {
  const t = Date.parse(iso);
  if (!isFinite(t)) return "—";
  const secs = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (secs < 60) return bl({ en: "just now", ja: "たった今" });
  const mins = Math.round(secs / 60);
  if (mins < 60) return bl({ en: mins + " min ago", ja: mins + " 分前" });
  const hrs = Math.round(mins / 60);
  return bl({ en: hrs + " h ago", ja: hrs + " 時間前" });
}

async function renderOperatorMachines(host) {
  uiState(host, "loading");
  const current = freshRender(host);
  let r;
  try {
    r = await apiFetch("GET", "/admin/fleet/config-status", undefined, "control");
  } catch (e) {
    if (!current()) return;
    uiState(host, "error", String(e));
    return;
  }
  if (!current()) return;
  if (r.status === 404 || r.status === 501) {
    uiState(host, "empty", bl({
      en: "This deployment does not report its machines.",
      ja: "この配備は機械の状況を報告しません。" }));
    return;
  }
  if (!r.ok) { uiState(host, "error", "HTTP " + r.status); return; }

  const rows = opMachineRows(r.body);
  if (!rows.length) {
    // ★ NOT "everything is fine". Nothing has reported, and that is a different sentence.
    uiState(host, "empty", bl({
      en: "No machine has reported yet.",
      ja: "まだどの機械からも報告がありません。" }));
    return;
  }

  // ★★★ ONE ROW PER MACHINE, NOT PER CONTAINER (2026-09-03, seen the moment a fifth machine was added: the
  // osaka machine appeared twice). The control plane keys its fleet by (region, cluster, NODE id) — rightly,
  // because a node id is what distinguishes two Edges — and a node id is the container's hostname, so
  // recreating a container leaves the machine reporting under a new one while the old entry is still inside
  // the freshness window. Grouping by STATE hid this; naming machines shows it.
  //
  // Two entries naming the same machine are the same machine: the older one is a container that no longer
  // exists. The newest report wins. A machine with no name of its own is left alone — those rows are node
  // ids, and two of them really are two things.
  const newest = {};
  const collapsed = [];
  rows.forEach((row) => {
    if (!row.named) { collapsed.push(row); return; }
    const key = row.region + "|" + row.name;
    const seen = newest[key];
    if (!seen) { newest[key] = row; collapsed.push(row); return; }
    if (Date.parse(row.reportedAt) > Date.parse(seen.reportedAt)) {
      collapsed[collapsed.indexOf(seen)] = row;
      newest[key] = row;
    }
  });

  // Grouped by region, because that is how an operator was asked to declare them, and ordered by name inside
  // it so the same machine is in the same place every time this is opened.
  const byRegion = {};
  collapsed.forEach((row) => { (byRegion[row.region] = byRegion[row.region] || []).push(row); });
  const regions = Object.keys(byRegion).sort();
  regions.forEach((k) => byRegion[k].sort((a, b) => a.name.localeCompare(b.name)));

  host.innerHTML = "";
  regions.forEach((region, i) => {
    host.appendChild(el("div", {
      style: (i ? "margin-top:16px;" : "") + "font-weight:600",
      text: region || bl({ en: "(no region)", ja: "(リージョン不明)" }),
    }));
    host.appendChild(el("div", { style: "overflow-x:auto;margin-top:6px" }, el("table", { class: "ui-table" }, [
      el("thead", {}, el("tr", {}, [
        bl({ en: "Machine", ja: "機械" }),
        bl({ en: "Settings", ja: "設定" }),
        bl({ en: "Rules in effect", ja: "有効なルール" }),
        bl({ en: "Last heard from", ja: "最後の報告" }),
      ].map((x) => el("th", { text: x })))),
      el("tbody", {}, byRegion[region].map((row) => {
        const name = el("td", {}, [
          el("strong", { text: row.name || "—" }),
          row.address ? el("div", { class: "ui-view-desc", text: row.address }) : null,
          row.named ? null : el("div", { class: "ui-view-desc", text: bl({
            en: "reported as a container id — this deployment does not carry machine names",
            ja: "コンテナ ID で報告されています — この配備は機械の名前を持っていません" }) }),
        ].filter(Boolean));
        const st = OP_MACHINE_STATE[row.status] || {
          tone: "off", t: { en: row.status || "—", ja: row.status || "—" } };
        const state = uiBadge(bl(st.t), st.tone);
        return el("tr", {}, [
          name,
          el("td", {}, state),
          el("td", { class: "ui-view-desc", text: row.rules == null ? "—" : String(row.rules) }),
          el("td", { class: "ui-view-desc", text: opMachineWhen(row.reportedAt) }),
        ]);
      })),
    ])));
  });
}
