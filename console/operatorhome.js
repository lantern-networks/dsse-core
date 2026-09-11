"use strict";

// operatorhome.js — where an operator lands, instead of a customer's dashboard.
//
// ★ AN OPERATOR'S SCREEN CANNOT BE A SUBSET OF A CUSTOMER'S. super_admin holds none of the customer-side
// write permissions — that is the design, not a limitation — so the customer Overview shows an operator a
// deployment full of things they cannot touch, and hides the three they actually work on. Three blocks:
// the organizations they run, the capacity they have to allocate, and what they are distributing.
//
// ★ IT COUNTS ONLY WHAT IT CAN SEE, AND SAYS SO. The setup state of each organization comes from both planes
// (see organizationsetup.js); a block that cannot be answered says so rather than showing a zero, because a
// zero here reads as "nothing to do".

function renderOperatorHomeView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "Overview", ja: "概要" }) }),
      el("p", { class: "ui-view-desc", text: bl({
        en: "The tenants you run, the capacity you have left to give them, and what you are distributing.",
        ja: "運用しているテナント、まだ配分できる容量、配布しているもの。" }) }),
    ]),
  ]));
  const orgs = el("div", {});
  const licence = el("div", {});
  const distribution = el("div", {});
  content.appendChild(el("div", { class: "ui-panel" }, [
    el("h3", { class: "ui-panel-title", text: bl({ en: "Tenants", ja: "テナント" }) }), orgs]));
  content.appendChild(el("div", { class: "ui-panel" }, [
    el("h3", { class: "ui-panel-title", text: bl({ en: "Capacity", ja: "容量" }) }), licence]));
  content.appendChild(el("div", { class: "ui-panel" }, [
    el("h3", { class: "ui-panel-title", text: bl({ en: "What you are distributing", ja: "配布しているもの" }) }), distribution]));
  // ★ AND THE DEPLOYMENT ITSELF. Three blocks about what an operator hands out, and none about what hands it
  // out — see operatormachines.js for the machine that could not be found on any screen.
  const machines = el("div", {});
  content.appendChild(el("div", { class: "ui-panel" }, [
    el("h3", { class: "ui-panel-title", text: bl({ en: "Your machines", ja: "運用している機械" }) }), machines]));
  renderOperatorOrganizations(orgs);
  renderOperatorCapacity(licence);
  renderOperatorDistribution(distribution);
  renderOperatorMachines(machines);
}

// Block 1 — the organizations, each with how far its setup got. The point of the block is the ones that are
// NOT working: an operator's queue is the organizations that were created and then left half-done.
async function renderOperatorOrganizations(host) {
  uiState(host, "loading");
  const current = freshRender(host);
  let tenants = [];
  try {
    const r = await apiFetch("GET", "/admin/tenants", undefined, "control");
    if (!current()) return;
    if (!r.ok) { uiState(host, "error", "HTTP " + r.status); return; }
    tenants = ((r.body && r.body.tenants) || []).filter((t) => !t.is_operator);
  } catch (e) { if (!current()) return; uiState(host, "error", String(e)); return; }
  if (!tenants.length) { uiState(host, "empty", bl({ en: "No tenants yet.", ja: "テナントがありません。" })); return; }

  const rows = tenants.map((t) => el("tr", { "data-op-setup": t.tenant_id }, [
    el("td", {}, [el("strong", { text: t.display_name || t.tenant_id })]),
    el("td", {}, uiBadge(t.status || "active", t.status === "active" ? "ok" : "warn")),
    el("td", { class: "ui-view-desc", text: "…" }),
    el("td", { class: "ui-row-actions" }, [
      el("button", { class: "ui-btn ui-btn-sm ui-btn-primary", text: bl({ en: "Enter", ja: "入る" }), onClick: () => enterTenant(t.tenant_id) }),
    ]),
  ]));
  if (!current()) return;
  host.innerHTML = "";
  host.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [bl({ en: "Tenant", ja: "テナント" }), bl({ en: "Status", ja: "状態" }),
      bl({ en: "Setup", ja: "セットアップ" }), bl({ en: "", ja: "" })].map((x) => el("th", { text: x })))),
    el("tbody", {}, rows),
  ]));

  // One at a time, after the table is up: a slow plane costs that row and not the block. The organization is
  // named per call rather than by assigning the console's selection — see fillOrgSetupColumn.
  for (const t of tenants) {
    const cell = host.querySelector('[data-op-setup="' + String(t.tenant_id).replace(/"/g, '\\"') + '"] td:nth-child(3)');
    if (!cell) continue;
    let summary = null;
    try { summary = await organizationSetupMerged(t.tenant_id); } catch (e) { summary = null; }
    // The table this cell belongs to may have been replaced while that read was in flight; stop rather than
    // fill a row nobody is looking at.
    if (!current()) return;
    cell.innerHTML = "";
    const badge = organizationSetupBadge(summary);
    badge.style.cursor = "pointer";
    badge.addEventListener("click", () => openOrgSetup(t, summary));
    cell.appendChild(badge);
  }
}

// Block 2 — capacity. What the licence grants against what has been given out, so "how many can I still
// promise" is a number on screen rather than a subtraction somebody does in their head.
async function renderOperatorCapacity(host) {
  uiState(host, "loading");
  const current = freshRender(host);
  try {
    // ★ SEAT ALLOCATIONS ARE WRITE-ONLY (405 in the browser, first run). POST allocates and DELETE removes;
    // the READ is the licence, which is also the only place the pool total and per-organization USE exist.
    // Reading the write route returned "HTTP 405" into the panel — an error message where a number belongs.
    const r = await apiFetch("GET", "/admin/license", undefined, "control");
    if (!r.ok) {
      if (!current()) return;
      // A bare status code is the thing this block exists to avoid — see the note above about reading the
      // write route and printing "HTTP 405" where a number belongs. Every outcome gets a sentence.
      uiState(host, "empty", r.status === 404
        ? bl({ en: "This deployment has no licence pool.", ja: "この配備にはライセンスプールがありません。" })
        : r.status === 403
          ? bl({ en: "The licence pool is not readable from inside an tenant. Leave the tenant to see it.",
                 ja: "ライセンスの総量はテナントの中からは読めません。テナントを出ると表示されます。" })
          : bl({ en: "The licence pool could not be read.", ja: "ライセンスの総量を読み取れませんでした。" }));
      return;
    }
    const body = r.body || {};
    const allocations = (body.tenants || []).map((t) => ({ tenant_id: t.display_name || t.tenant_id, seats: t.allocated || 0, used: t.used || 0 }));
    const allocated = typeof body.allocated === "number" ? body.allocated : allocations.reduce((n, a) => n + a.seats, 0);
    const pool = typeof body.pool_seats === "number" ? body.pool_seats : (body.licensed ? null : 0);
    if (!current()) return;
    host.innerHTML = "";
    host.appendChild(el("div", { class: "ui-toolbar" }, [
      uiBadge(bl({ en: "Given out: ", ja: "配分済み: " }) + allocated, "ok"),
      pool === null ? uiBadge(bl({ en: "Pool unknown", ja: "総量不明" }), "off")
                    : (pool === 0 ? uiBadge(bl({ en: "No licence", ja: "ライセンスなし" }), "off")
                                  : uiBadge(bl({ en: "Left: ", ja: "残り: " }) + Math.max(0, pool - allocated), pool - allocated > 0 ? "ok" : "warn")),
      el("span", { class: "ui-spacer" }),
      el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Open licensing", ja: "ライセンスを開く" }), onClick: () => renderGroup("licensing") }),
    ]));
    if (!body.licensed) {
      host.appendChild(el("p", { class: "ui-view-desc", text: bl({
        en: "No licence is installed, so nothing limits how many devices any tenant enrols.",
        ja: "ライセンスが入っていないため、どのテナントも端末登録に上限がありません。" }) }));
    }
    if (!allocations.length) {
      host.appendChild(el("p", { class: "ui-view-desc", text: bl({
        en: "No tenant has an allowance yet.", ja: "割当のあるテナントがありません。" }) }));
      return;
    }
    // USE beside allowance: "allocated 0, using 1" is the row that explains a complaint, and a table with
    // only the allowance cannot show it.
    host.appendChild(el("table", { class: "ui-table" }, [
      el("thead", {}, el("tr", {}, [bl({ en: "Tenant", ja: "テナント" }), bl({ en: "Allowance", ja: "割当" }),
        bl({ en: "In use", ja: "使用中" })].map((x) => el("th", { text: x })))),
      el("tbody", {}, allocations.map((a) => el("tr", {}, [
        el("td", { text: a.tenant_id }),
        el("td", { text: a.seats ? String(a.seats) : bl({ en: "none", ja: "なし" }) }),
        el("td", { text: String(a.used) })]))),
    ]));
  } catch (e) { if (!current()) return; uiState(host, "error", String(e)); }
}

// Block 3 — what is being distributed. The releases an operator has published, which is the other thing they
// own on behalf of every organization at once.
//
// ★ TWO DEFECTS, AND EITHER ONE ALONE MADE THIS BLOCK PERMANENTLY EMPTY (2026-08-17).
//
//  1. IT READ KEYS THE ROUTE DOES NOT HAVE. GET /admin/agent-updates answers {envelopes, pending} — maps keyed
//     by "platform/arch" — and this block asked for `offerings || releases`, so it resolved to [] whatever was
//     published and printed "No agent release is published, so no endpoint can update itself." A false
//     statement, on the landing screen, about the thing the operator is responsible for. agentreleases.js has
//     read the right keys all along, which is what makes a hand-written second reader of the same route a
//     liability: nothing fails when the shape and the reader disagree.
//  2. IT ASKED THE WRONG ORGANIZATION. Publishing is per organization — the route scopes to the caller, so an
//     operator publishing inside Northwind publishes to Northwind's devices. Read with no organization named
//     it answers for the OPERATOR'S OWN tenant, where nothing is ever published and nothing ever will be.
//
// So the block asks each organization, by name, one at a time — the same shape as block 1. An organization
// that has not delegated management answers 403 (the envelope working as designed), and that is reported as
// "not delegated" rather than as an error: the operator genuinely cannot see it, and the standing delegation
// is the customer's to give.
async function renderOperatorDistribution(host) {
  uiState(host, "loading");
  const current = freshRender(host);
  let tenants = [];
  try {
    const r = await apiFetch("GET", "/admin/tenants", undefined, "control");
    if (!current()) return;
    if (!r.ok) { uiState(host, "error", "HTTP " + r.status); return; }
    tenants = ((r.body && r.body.tenants) || []).filter((t) => !t.is_operator);
  } catch (e) { if (!current()) return; uiState(host, "error", String(e)); return; }
  if (!tenants.length) { uiState(host, "empty", bl({ en: "No tenants yet.", ja: "テナントがありません。" })); return; }

  const rows = tenants.map((t) => el("tr", { "data-op-dist": t.tenant_id }, [
    el("td", {}, [el("strong", { text: t.display_name || t.tenant_id })]),
    el("td", { class: "ui-view-desc", text: "…" }),
    el("td", { class: "ui-view-desc", text: "…" }),
  ]));
  if (!current()) return;
  host.innerHTML = "";
  const summary = el("div", { class: "ui-toolbar" }, [
    el("span", { class: "ui-view-desc", text: bl({ en: "Reading…", ja: "読取中…" }) }),
    el("span", { class: "ui-spacer" }),
    el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Open agent distribution", ja: "エージェント配布を開く" }), onClick: () => renderGroup("agents") }),
  ]);
  host.appendChild(summary);
  host.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [bl({ en: "Tenant", ja: "テナント" }),
      bl({ en: "Devices can update to", ja: "端末が更新できる版" }),
      bl({ en: "Waiting for its file", ja: "ファイル待ち" })].map((x) => el("th", { text: x })))),
    el("tbody", {}, rows),
  ]));

  let published = 0, withSomething = 0, undelegated = 0;
  for (const t of tenants) {
    const row = host.querySelector('[data-op-dist="' + String(t.tenant_id).replace(/"/g, '\\"') + '"]');
    if (!row) continue;
    let live = null, waiting = null, note = null;
    try {
      const r = await apiFetch("GET", "/admin/agent-updates", undefined, "control", undefined, t.tenant_id);
      if (r.ok) {
        live = Object.keys((r.body && r.body.envelopes) || {});
        waiting = Object.keys((r.body && r.body.pending) || {});
      } else if (r.status === 403) {
        note = bl({ en: "not delegated", ja: "委任なし" });
        undelegated += 1;
      } else {
        note = "HTTP " + r.status;
      }
    } catch (e) { note = bl({ en: "unreadable", ja: "読めません" }); }
    if (!current()) return;
    const cells = row.querySelectorAll("td");
    cells[1].innerHTML = ""; cells[2].innerHTML = "";
    if (note !== null) {
      cells[1].appendChild(uiBadge(note, "off"));
      cells[2].textContent = "—";
      continue;
    }
    published += live.length;
    if (live.length) withSomething += 1;
    cells[1].textContent = live.length ? live.join(", ") : bl({ en: "nothing", ja: "なし" });
    if (!live.length) cells[1].className = "ui-view-desc";
    cells[2].textContent = waiting.length ? waiting.join(", ") : "—";
  }
  if (!current()) return;
  // ★ The summary counts what it could read and says what it could not — a "0" that silently included
  // organizations the operator was refused would read as "nothing to do".
  summary.replaceChild(el("span", {}, [
    uiBadge(bl({ en: "Published: ", ja: "公開中: " }) + published, published ? "ok" : "off"),
    undelegated ? uiBadge(bl({ en: "Not delegated: ", ja: "委任なし: " }) + undelegated, "off") : el("span", {}),
  ]), summary.firstChild);
  if (!published && withSomething === 0 && undelegated < tenants.length) {
    host.appendChild(el("p", { class: "ui-view-desc", text: bl({
      en: "No tenant has a published release, so no endpoint can update itself.",
      ja: "どのテナントにも公開中のリリースがないため、端末は自分を更新できません。" }) }));
  }
}
