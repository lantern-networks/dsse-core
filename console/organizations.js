"use strict";

// organizations.js — "Organizations" (tenants) on the shared ui.js pattern: list + search, create/edit modal,
// delete with confirmation, toasts/states. Replaces the raw-JSON tenants card.
// Backend: GET /admin/tenants -> {tenants:[…]}, POST /admin/tenants {tenant_id,display_name,status,plan,
// home_region,allowed_regions}, DELETE /admin/tenants/{tenant_id}. (Super-admin.)

let _orgSearch = "";

function renderOrganizationsView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "Tenants", ja: "テナント" }) }),
      // Says what the screen is FOR, in the words the rest of the console uses. "The organizations (tenants)
      // this system serves, their regions, and status" named a row's columns back to whoever was reading them,
      // and used our word for a customer in brackets on the screen that lists customers.
      el("p", { class: "ui-view-desc", text: bl({ en: "Your tenants: how far each one's setup has got, and whether they have delegated their management to you.", ja: "あなたのテナント。どこまで設定が進んでいるか、運営に管理を委任しているか。" }) }),
    ]),
    // The wizard, not the form. A one-page form produces a registry row and says nothing about what that
    // leaves undone, which is how "created it, and nothing happens" survived this long. openOrgForm stays for
    // EDITING an organization that already exists, where the sequence has already happened.
    el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "+ Add tenant", ja: "+ テナントを追加" }), onClick: () => openOrganizationWizard(content) }),
  ]));
  const search = el("input", { class: "ui-input ui-search", type: "search", placeholder: bl({ en: "Search tenants…", ja: "テナントを検索…" }) });
  search.value = _orgSearch;
  const host = el("div", {});
  search.addEventListener("input", () => { _orgSearch = search.value; renderOrgList(host); });
  content.appendChild(el("div", { class: "ui-toolbar" }, [search, el("span", { class: "ui-spacer" }),
    el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Reload", ja: "再読込" }), onClick: () => renderOrgList(host) })]));
  content.appendChild(host);
  renderOrgList(host);
}

function orgStatusKind(s) { return s === "active" ? "ok" : s === "suspended" ? "warn" : "off"; }

async function renderOrgList(host) {
  uiState(host, "loading");
  const current = freshRender(host);
  let tenants;
  try {
    const r = await apiFetch("GET", "/admin/tenants");
    if (!r.ok) { if (!current()) return; uiState(host, "error", r.status === 403 ? bl({ en: "You don't have permission to manage tenants.", ja: "テナントを管理する権限がありません。" }) : "HTTP " + r.status, { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderOrgList(host) }); return; }
    // The operator tenant (is_operator) is the SSE operator's own tenant, not a customer — exclude it from the
    // customer list and counts entirely (multi-tenant Admin Console Q5). When the operator-tenant feature is off,
    // no tenant carries is_operator and this is a no-op.
    tenants = ((r.body && r.body.tenants) || []).filter((t2) => !t2.is_operator);
  } catch (e) { if (!current()) return; uiState(host, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderOrgList(host) }); return; }
  const q = _orgSearch.trim().toLowerCase();
  const filtered = tenants.filter((t2) => !q || (t2.display_name || "").toLowerCase().includes(q) || (t2.tenant_id || "").toLowerCase().includes(q));
  if (!tenants.length) { if (!current()) return; uiState(host, "empty", bl({ en: "No tenants yet.", ja: "テナントがありません。" })); return; }
  if (!filtered.length) { if (!current()) return; uiState(host, "empty", bl({ en: "No matches.", ja: "一致なし。" })); return; }
  const rows = filtered.map((t2) => el("tr", {}, [
    el("td", {}, [el("strong", { text: t2.display_name || t2.tenant_id }), el("div", { class: "ui-view-desc" }, el("code", { text: t2.tenant_id }))]),
    el("td", {}, uiBadge(t2.status || "active", orgStatusKind(t2.status))),
    el("td", { text: t2.plan || "—" }),
    el("td", { text: t2.home_region || "—" }),
    el("td", { class: "ui-view-desc", text: (t2.allowed_regions || []).join(", ") || "—" }),
    // ★ THE COLUMN THAT ANSWERS "DOES IT ACTUALLY WORK". A registry row is the entrance, not the finish, and
    // this list used to show only the row: name, status, plan, regions — every one of which is true of an
    // organization that enforces nothing. Filled in per row after the table is drawn, because it asks both
    // planes and the list must not wait on that.
    el("td", { "data-setup-for": t2.tenant_id }, el("span", { class: "ui-view-desc", text: "…" })),
    el("td", { class: "ui-row-actions" }, [
      el("button", { class: "ui-btn ui-btn-sm ui-btn-primary", text: bl({ en: "Manage", ja: "管理" }), title: bl({ en: "Operate within this tenant", ja: "このテナントに入って操作" }), onClick: () => enterTenant(t2.tenant_id) }),
      document.createTextNode(" "),
      el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Edit", ja: "編集" }), onClick: () => openOrgForm(document.getElementById("content"), t2) }),
      document.createTextNode(" "),
      el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Delete", ja: "削除" }), onClick: () => removeOrg(t2, host) }),
    ]),
  ]));
  if (!current()) return;
  host.innerHTML = "";
  host.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [bl({ en: "Tenant", ja: "テナント" }), bl({ en: "Status", ja: "状態" }), bl({ en: "Plan", ja: "プラン" }), bl({ en: "Home region", ja: "ホームリージョン" }), bl({ en: "Allowed regions", ja: "許可リージョン" }), bl({ en: "Setup", ja: "セットアップ" }), bl({ en: "Actions", ja: "操作" })].map((x) => el("th", { text: x })))),
    el("tbody", {}, rows),
  ]));
  host.appendChild(el("p", { class: "ui-view-desc", text: bl({ en: "Showing ", ja: "表示 " }) + filtered.length + " / " + tenants.length }));
  fillOrgSetupColumn(host, filtered);
}

function openOrgForm(content, existing) {
  existing = existing || null;
  const idF = uiField({ name: "id", label: bl({ en: "Tenant ID", ja: "テナント ID" }), required: true, value: existing ? existing.tenant_id : "", placeholder: "tenant_acme", validate: (v) => (/\s/.test(v) ? bl({ en: "No spaces allowed.", ja: "空白は使えません。" }) : "") });
  if (existing) idF.el.querySelector("input").setAttribute("readonly", "true");
  const nameF = uiField({ name: "name", label: bl({ en: "Display name", ja: "表示名" }), required: true, value: existing ? existing.display_name : "", placeholder: "Acme Corp" });
  const statusF = uiField({ name: "status", label: bl({ en: "Status", ja: "状態" }), type: "select", value: existing ? existing.status : "active", options: [
    { value: "active", label: bl({ en: "Active", ja: "有効" }) },
    { value: "suspended", label: bl({ en: "Suspended", ja: "停止" }) },
    { value: "archived", label: bl({ en: "Archived", ja: "アーカイブ" }) },
  ] });
  const planF = uiField({ name: "plan", label: bl({ en: "Plan (optional)", ja: "プラン(任意)" }), value: existing ? existing.plan : "", placeholder: "enterprise" });
  const homeF = uiField({ name: "home", label: bl({ en: "Home region (optional)", ja: "ホームリージョン(任意)" }), value: existing ? existing.home_region : "", placeholder: "region-a" });
  const regionsF = uiField({ name: "regions", label: bl({ en: "Allowed regions (optional)", ja: "許可リージョン(任意)" }), value: existing ? (existing.allowed_regions || []).join(", ") : "", placeholder: "region-a, region-b", hint: bl({ en: "Comma-separated.", ja: "カンマ区切り。" }) });
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: existing ? bl({ en: "Save changes", ja: "保存" }) : bl({ en: "Add tenant", ja: "テナントを追加" }) });
  const m = uiModal({ title: existing ? bl({ en: "Edit tenant", ja: "テナントを編集" }) : bl({ en: "Add a tenant", ja: "テナントを追加" }),
    body: [idF.el, nameF.el, statusF.el, planF.el, homeF.el, regionsF.el],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit] });
  submit.addEventListener("click", async () => {
    if (!idF.validate() || !nameF.validate()) return;
    submit.disabled = true;
    const regions = regionsF.get().split(",").map((s) => s.trim()).filter(Boolean);
    try {
      const r = await apiFetch("POST", "/admin/tenants", { tenant_id: idF.get(), display_name: nameF.get(), status: statusF.get(), plan: planF.get(), home_region: homeF.get(), allowed_regions: regions });
      if (!r.ok) { submit.disabled = false; const msg = (r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status); idF.setError(msg); uiToast(msg, "err"); return; }
      m.close(); uiToast(existing ? bl({ en: "Tenant saved.", ja: "テナントを保存しました。" }) : bl({ en: "Tenant added.", ja: "テナントを追加しました。" }), "ok");
      renderOrganizationsView(content);
    } catch (e) { submit.disabled = false; uiToast(String(e), "err"); }
  });
  (existing ? nameF : idF).focus();
}

async function removeOrg(t2, host) {
  const ok = await uiConfirm({ title: bl({ en: "Delete this tenant?", ja: "このテナントを削除?" }), body: bl({ en: "Permanently deletes \"" + (t2.display_name || t2.tenant_id) + "\". This is destructive.", ja: "「" + (t2.display_name || t2.tenant_id) + "」を完全に削除します。破壊的操作です。" }), confirmLabel: bl({ en: "Delete permanently", ja: "完全に削除" }), danger: true });
  if (!ok) return;
  const r = await apiFetch("DELETE", "/admin/tenants/" + encodeURIComponent(t2.tenant_id));
  if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }

  // ★ "DELETE PERMANENTLY" HAS TO MEAN IT (2026-08-17, measured). This called the registry delete and stopped:
  // the organization vanished from the list while the access rules it had authored were still on BOTH planes,
  // carrying its id. The button said "permanently deletes … this is destructive", and what it did was remove
  // the row. The erasure is a separate route that reports a FOOTPRINT — what it erased, and what is left — so
  // the delete runs it and says what it found rather than claiming success on the strength of one 200.
  // Named to the CONTROL PLANE: the erasure order is recorded there and carried to every node, and purging
  // only the Edge the front door happens to proxy to is the per-node blindness this product has paid for
  // before.
  const purge = await apiFetch("POST", "/admin/tenants/" + encodeURIComponent(t2.tenant_id) + "/purge",
    // The route refuses without the organization named back to it, which is right: this cannot be undone. The
    // operator has already named it in the confirmation above, so the console does not ask twice.
    { confirm_tenant_id: t2.tenant_id }, "control");
  const remaining = (purge.ok && purge.body && purge.body.remaining && purge.body.remaining.total) || 0;
  const failures = (purge.ok && purge.body && purge.body.failures) || [];
  if (!purge.ok) {
    uiToast(bl({
      en: "Removed from the list, but erasing what it left behind failed — its data is still on this deployment.",
      ja: "一覧からは消えましたが、残ったデータの消去に失敗しました。この配備にまだ残っています。" }), "err");
  } else if (remaining > 0 || failures.length) {
    uiToast(bl({
      en: "Deleted, and " + remaining + " record(s) could not be erased — see the tenant's footprint.",
      ja: "削除しましたが、" + remaining + " 件を消去できませんでした。" }), "err");
  } else {
    uiToast(bl({ en: "Tenant deleted, and everything it held is erased.", ja: "テナントを削除し、保持していたものも消去しました。" }), "ok");
  }
  // ★ AND STOP OPERATING WITHIN IT. Deleting the organization you are inside left the console carrying its
  // id on every request, with the banner still saying you were working in it — an organization that no
  // longer exists. Measured after a wizard run: "tenant_half_built_ltd を運営として操作中", for a tenant that
  // had just been removed.
  if (operateTenant && String(operateTenant).toLowerCase() === String(t2.tenant_id).toLowerCase()) {
    exitTenant(); // reloads, which is what clears every screen drawn in that organization's context
    return;
  }
  renderOrgList(host);
}

// fillOrgSetupColumn asks each organization's setup state after the table is on screen.
//
// ★ ONE ORGANIZATION AT A TIME, AND THE ANSWER IS NEVER GUESSED. Each cell asks both planes for that
// organization (X-Operate-Tenant selects it), so a slow or missing plane costs that row and not the list. A
// cell that cannot be answered says so rather than defaulting to a tick — showing something absent as
// complete is exactly the failure this column exists to make visible.
async function fillOrgSetupColumn(host, tenants) {
  for (const t2 of tenants) {
    const cell = host.querySelector('[data-setup-for="' + String(t2.tenant_id).replace(/"/g, '\\"') + '"]');
    if (!cell) continue;
    let summary = null;
    // ★ NO LONGER BY ASSIGNING THE SELECTION. Doing that made every row a moment in which the console was
    // "operating within" that organization, and anything capturing the selection to restore it later — a
    // modal, the wizard — captured a row instead of the operator's own context.
    try { summary = await organizationSetupMerged(t2.tenant_id); } catch (e) { summary = null; }
    cell.innerHTML = "";
    const badge = organizationSetupBadge(summary);
    badge.style.cursor = "pointer";
    badge.title = bl({ en: "Open this tenant's setup", ja: "このテナントのセットアップを開く" });
    badge.addEventListener("click", () => openOrgSetup(t2, summary));
    cell.appendChild(badge);
    // ★ AND WHETHER "MANAGE" WILL ACTUALLY DO ANYTHING (2026-08-17). The standing delegation is the customer's
    // to give; without it every admin read inside that organization is refused, so pressing Manage opened a
    // screen of dashes. The button looked identical either way. Asked per row, after the table is up, from the
    // one route that answers for an organization that refuses everything else.
    try {
      const acc = await apiFetch("GET", "/admin/operator-access", undefined, "control", undefined, t2.tenant_id);
      if (acc.ok && acc.body && acc.body.managed === false) {
        cell.appendChild(document.createTextNode(" "));
        cell.appendChild(uiBadge(bl({ en: "not delegated", ja: "委任なし" }), "off"));
        const row = cell.closest("tr");
        const manage = row && row.querySelector(".ui-btn-primary");
        if (manage) {
          manage.classList.remove("ui-btn-primary");
          manage.title = bl({ en: "This tenant has not delegated its management, so these screens will be empty",
                              ja: "このテナントは運営に管理を委任していないため、入っても各画面は空になります" });
        }
      }
    } catch (e) { /* the delegation state is an annotation; its absence must not cost the row */ }
  }
}

// openOrgSetup shows the checklist for one organization, with every row settable.
//
// ★ IT DOES NOT BORROW THE SELECTION AT ALL ANY MORE (2026-08-16). Two earlier versions borrowed it while the
// modal was open: the first never handed it back (m.onClose was assigned AFTER uiModal returned, and the modal
// reads it from its options at construction), so the next WRITE anywhere in the console landed in the customer
// whose checklist had just been LOOKED at. The second handed it back correctly and was still wrong in kind —
// while borrowed, that selection is what everything else running at the same moment reads and later restores.
//
// Every read here names its organization on the call, and every action that needs a context ENTERS the
// organization for real, with a banner. The modal title is what says whose checklist this is.
function openOrgSetup(t2, summary) {
  const body = el("div", {});
  const note = el("div", {});
  const m = uiModal({
    title: (t2.display_name || t2.tenant_id) + " — " + bl({ en: "setup", ja: "セットアップ" }),
    body: [note, body],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Close", ja: "閉じる" }), onClick: () => m.close() })],
  });
  renderOrganizationSetup(body, t2.tenant_id, () => {});
  // ★★ THE LIST OFFERS ACTIONS THAT BOUNCE (2026-08-17, walked from a half-built organization). Every "open X"
  // here enters the organization and lands on a screen — and if that organization has not delegated its
  // management, every one of those screens is refused. Measured: "Device identity — not set … Open
  // certificates" landed on a page whose entire content was "HTTP 403 / HTTP 403". The delegation item is on
  // this very list, at the BOTTOM, after ten rows of things that depend on it. Say it first.
  (async () => {
    try {
      const r = await apiFetch("GET", "/admin/operator-access", undefined, "control", undefined, t2.tenant_id);
      if (!r.ok || !r.body || r.body.managed !== false || !note.isConnected) return;
      note.appendChild(el("div", { class: "ui-callout ui-callout-warn" }, [
        el("strong", { text: bl({ en: "This tenant runs itself.", ja: "このテナントは自ら運用しています。" }) }),
        el("p", { class: "ui-view-desc", text: bl({
          en: "It has not delegated its management, so the screens below can be opened but not read or changed. "
            + "Ask it to delegate — the last item on this list — or leave the setup to its own administrators.",
          ja: "運営に管理を委任していないため、以下の画面は開けても表示・変更ができません。委任を依頼する(この一覧の最後の項目)か、"
            + "そのテナントの管理者にセットアップを任せてください。" }) }),
      ]));
    } catch (e) { /* an annotation; its absence must not cost the list */ }
  })();
}
