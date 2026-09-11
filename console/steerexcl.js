"use strict";

// steerexcl.js — "Steering Exclusions" view on the shared ui.js primitives. Replaces the last
// raw-JSON admin card. Implements G1 (typed CRUD for the admin policy layer) and G2 (effective-set visibility)
// from docs/steer_exclusions_purpose_and_gaps_analysis.md.
//
// A device's EFFECTIVE exclusion set is the additive merge of three layers (doc):
//   1. loop-prevention floor (self-image)  — hardcoded safety invariant, never admin-removable
//   2. development scaffold             — hardcoded dev-only posture
//   3. admin-managed policy                 — the product feature, authored here
// Higher layers never remove a lower layer's entries. The console historically rendered ONLY layer 3, so the
// device's real (merged) exclusions — including the scaffold's — were invisible (the "invisible effective configuration"
// anti-pattern). This view exposes all three: authored CRUD, observed-on-device reverse telemetry, and a
// resolved-for-device preview.
//
// Backend:
//   GET    /admin/steer-exclusions               -> {steer_exclusions:[{id,tenant_id,scope_type,scope_id,
//                                                     excluded_app_signing_ids[],note,status,created_at,updated_at}]}
//   POST   /admin/steer-exclusions               (upsert by id)
//   DELETE /admin/steer-exclusions/{id}
//   GET    /admin/steer-exclusions/observed       -> {observed:[{device_identity,device_group,platform,
//                                                     effective_app_signing_ids[],server_app_signing_id_count,reported_at}]}
//   GET    /admin/steer-exclusions/resolved?device=<id> -> {device_identity,device_group,resolved_app_signing_ids[]}

let _steerExclTab = "authored";

function renderSteerExclusionsView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "Steering Exclusions", ja: "ステアリング除外" }) }),
      el("p", { class: "ui-view-desc", text: bl({ en: "Apps excluded from steering to the secure gateway, set per tenant, group, or device. Centrally enforced — users cannot change it.", ja: "セキュアゲートウェイへのステアリングから除外するアプリをテナント/グループ/デバイス単位で設定。中央で強制されユーザーは変更不可。" }) }),
    ]),
  ]));
  const tabs = uiTabs([
    { id: "authored", label: bl({ en: "Authored exclusions", ja: "管理者設定の除外" }) },
    { id: "observed", label: bl({ en: "Observed on devices", ja: "デバイス上の実態" }) },
    { id: "resolved", label: bl({ en: "Resolved for a device", ja: "デバイス向け解決結果" }) },
  ], _steerExclTab, (id) => { _steerExclTab = id; renderSteerExclusionsView(content); });
  content.appendChild(tabs);
  const host = el("div", {});
  content.appendChild(host);
  if (_steerExclTab === "observed") renderSteerExclObserved(host);
  else if (_steerExclTab === "resolved") renderSteerExclResolved(host);
  else renderSteerExclAuthored(host);
}

// ---------------------------------------------------------------------------
// Section 1 — Authored exclusions (admin policy, layer 3): full CRUD.
// ---------------------------------------------------------------------------

function steerExclScopeLabel(t) {
  return t === "tenant" ? bl({ en: "Tenant", ja: "テナント" })
    : t === "device_group" ? bl({ en: "Device group", ja: "デバイスグループ" })
    : t === "device" ? bl({ en: "Device", ja: "デバイス" })
    : (t || "—");
}

function renderSteerExclAuthored(host) {
  host.innerHTML = "";
  host.appendChild(el("div", { class: "ui-toolbar" }, [
    el("span", { class: "ui-spacer" }),
    el("button", { class: "ui-btn ui-btn-primary ui-btn-sm", text: bl({ en: "+ Add exclusion", ja: "+ ステアリング除外を追加" }), onClick: () => openSteerExclForm(host) }),
    el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Reload", ja: "再読込" }), onClick: () => renderSteerExclList(listHost) }),
  ]));
  // The paragraph that used to sit here explained the AppID forms and told the reader to check another tab for
  // what devices actually exclude. The Applied column answers the second half in place, and the form rules
  // belong in the add form's hint, next to the field where they are needed.
  host.appendChild(el("p", { class: "ui-view-desc", text: bl({ en: "Admin-authored only. Each device also has its loop-prevention floor and any dev scaffold.", ja: "管理者設定分のみ。各デバイスにはループ防止フロアと開発用スキャフォールドも別途あります。" }) }));
  const listHost = el("div", {});
  host.appendChild(listHost);
  renderSteerExclList(listHost);
}

async function renderSteerExclList(listHost) {
  uiState(listHost, "loading");
  const current = freshRender(listHost);
  let items;
  let devices = [];
  try {
    // Read from the AUTHORITY, not from an enforcing Edge's copy. Writes land on the control plane (the Edge
    // refuses them and the console routes them there), and the Edge refreshes its cache on a poll — so reading
    // the Edge showed a rule the operator had just created as missing for up to fifteen seconds.
    const r = await apiFetch("GET", "/admin/steer-exclusions", undefined, "control");
    if (!r.ok) { if (!current()) return; uiState(listHost, "error", "HTTP " + r.status, { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderSteerExclList(listHost) }); return; }
    items = (r.body && r.body.steer_exclusions) || [];
  } catch (e) { if (!current()) return; uiState(listHost, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderSteerExclList(listHost) }); return; }
  // Device reality, best-effort: an authored rule that no device applies is invisible otherwise, and silence is
  // exactly what this screen must not have. A failure here costs the column, not the list.
  // ★ AND A REFUSED READ IS NOT AN EMPTY ONE (2026-08-17). Whichever way this failed, `devices` became [] and
  // the applied column printed an em dash — which on this screen means "no device this rule covers is applying
  // it", the loudest statement the column can make. The comment above says silence is exactly what this screen
  // must not have; an unread observation set said something worse than silence.
  let devicesUnread = false;
  try {
    const o = await apiFetch("GET", "/admin/steer-exclusions/observed?limit=200");
    devicesUnread = !o.ok;
    devices = (o.ok && o.body && o.body.observed) || [];
  } catch (e) { devices = []; devicesUnread = true; }
  if (!items.length) {
    if (!current()) return;
    uiState(listHost, "empty", bl({ en: "No admin-authored steering exclusions yet. Add one to exclude an app from steering to the secure gateway for an tenant, group, or device.", ja: "管理者設定のステアリング除外はまだありません。テナント/グループ/デバイス単位でアプリをセキュアゲートウェイへのステアリングから外すには追加してください。" }));
    return;
  }
  const rows = items.map((x) => {
    const ids = x.excluded_app_signing_ids || [];
    const idCell = el("td", {});
    if (!ids.length) idCell.appendChild(el("span", { class: "ui-view-desc", text: "—" }));
    else ids.forEach((id) => idCell.appendChild(el("div", {}, el("code", { text: id }))));
    const applied = devicesUnread
      ? el("td", {}, uiBadge(bl({ en: "not known", ja: "不明" }), "off"))
      : steerExclAppliedCell(x, devices);
    return el("tr", {}, [
      el("td", {}, [uiBadge(steerExclScopeLabel(x.scope_type), "off"), x.scope_id ? el("div", { class: "ui-view-desc" }, el("code", { text: x.scope_id })) : null]),
      idCell,
      applied,
      el("td", { class: "ui-view-desc", text: x.note || "—" }),
      el("td", {}, uiBadge(x.status === "active" || !x.status ? bl({ en: "Active", ja: "有効" }) : (x.status), x.status === "active" || !x.status ? "ok" : "off")),
      el("td", { class: "ui-row-actions" }, [
        el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Edit", ja: "編集" }), onClick: () => openSteerExclForm(listHost.parentNode, x) }),
        el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Delete", ja: "削除" }), onClick: () => deleteSteerExcl(x, listHost) }),
      ]),
    ]);
  });
  if (!current()) return;
  listHost.innerHTML = "";
  listHost.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [
      el("th", { text: bl({ en: "Scope", ja: "対象範囲" }) }),
      el("th", { text: bl({ en: "Excluded apps", ja: "除外アプリ" }) }),
      el("th", { text: bl({ en: "Applied", ja: "適用" }) }),
      el("th", { text: bl({ en: "Note", ja: "メモ" }) }),
      el("th", { text: bl({ en: "Status", ja: "状態" }) }),
      el("th", { class: "ui-row-actions", text: bl({ en: "Actions", ja: "操作" }) }),
    ])),
    el("tbody", {}, rows),
  ]));
  if (devicesUnread) {
    // One sentence for the whole column, so "not known" in every row is explained once rather than read as a
    // per-rule fact.
    listHost.appendChild(el("p", { class: "ui-view-desc", text: bl({
      en: "What devices are actually applying could not be read, so the Applied column says \"not known\" rather than showing nothing applied.",
      ja: "端末が実際に適用しているかを取得できなかったため、「適用」列は「不明」と表示しています(「どこにも適用されていない」ではありません)。" }) }));
  }
}

function openSteerExclForm(host, existing) {
  existing = existing || null;
  const scopeF = uiField({ name: "scope_type", label: bl({ en: "Scope", ja: "対象範囲" }), type: "select",
    value: existing ? (existing.scope_type || "device") : "device", options: [
      { value: "tenant", label: bl({ en: "Tenant (whole tenant)", ja: "テナント(テナント全体)" }) },
      { value: "device_group", label: bl({ en: "Device group", ja: "デバイスグループ" }) },
      { value: "device", label: bl({ en: "Device", ja: "デバイス" }) },
    ] });
  const scopeIDF = uiField({ name: "scope_id", label: bl({ en: "Device identity", ja: "デバイス識別子" }), value: existing ? (existing.scope_id || "") : "",
    placeholder: "mac-dev-1", hint: bl({ en: "The id of the device group or device this applies to.", ja: "適用先のデバイスグループ ID またはデバイス ID。" }) });
  const idsF = uiField({ name: "ids", label: bl({ en: "Excluded AppIDs", ja: "除外するアプリ識別子" }), type: "textarea",
    value: existing ? ((existing.excluded_app_signing_ids || []).join("\n")) : "",
    placeholder: "subject:Example Corp\nthumbprint:1941ce62…\ncom.example.app",
    hint: bl({ en: "One AppID per line. Cross-platform (recommended): subject:<org> (vendor) or thumbprint:<sha256> (exact pin) — one entry matches on both macOS and Windows. OS-specific: macOS signing-id:<bundle id> / team-id:<TEAMID>; Windows publisher:<name> / signed:<exe>. Bare = macOS signing-id / Windows image-path. Each device applies only the forms its OS understands.", ja: "1行に1つアプリ識別子。クロス OS(推奨): subject:<テナント>(ベンダー)または thumbprint:<sha256>(厳密ピン)— 1エントリで macOS と Windows 両方に一致。OS 固有: macOS signing-id:<bundle id> / team-id:<TEAMID>、Windows publisher:<名前> / signed:<exe>。素 = macOS は signing-id / Windows はイメージパス。各デバイスは自 OS が理解する形式のみ適用。" }) });
  const noteF = uiField({ name: "note", label: bl({ en: "Note", ja: "メモ" }), value: existing ? (existing.note || "") : "",
    placeholder: bl({ en: "Why this app is excluded (optional).", ja: "このアプリを除外する理由(任意)。" }) });

  // The scope_id field is irrelevant for a tenant-wide scope; hide it and relabel it for group vs device.
  const syncScopeID = () => {
    const t = scopeF.get();
    if (t === "tenant") { scopeIDF.el.style.display = "none"; scopeIDF.set(""); return; }
    scopeIDF.el.style.display = "";
    const labelEl = scopeIDF.el.querySelector(".ui-field-label");
    if (labelEl) labelEl.firstChild.textContent = t === "device_group"
      ? bl({ en: "Device group ID", ja: "デバイスグループ ID" })
      : bl({ en: "Device identity", ja: "デバイス識別子" });
  };
  const scopeSelect = scopeF.el.querySelector("select");
  if (scopeSelect) scopeSelect.addEventListener("change", syncScopeID);
  syncScopeID();

  const submit = el("button", { class: "ui-btn ui-btn-primary", text: existing ? bl({ en: "Save changes", ja: "変更を保存" }) : bl({ en: "Add exclusion", ja: "ステアリング除外を追加" }) });
  const m = uiModal({
    title: existing ? bl({ en: "Edit steering exclusion", ja: "ステアリング除外を編集" }) : bl({ en: "Add a steering exclusion", ja: "ステアリング除外を追加" }),
    body: [scopeF.el, scopeIDF.el, idsF.el, noteF.el],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit],
  });
  submit.addEventListener("click", async () => {
    const scopeType = scopeF.get();
    const ids = (idsF.get() || "").split("\n").map((s) => s.trim()).filter(Boolean);
    if (!ids.length) { idsF.setError(bl({ en: "List at least one app identifier.", ja: "アプリ識別子を1つ以上入力してください。" })); return; }
    if (scopeType !== "tenant" && !scopeIDF.get()) { scopeIDF.setError(bl({ en: "Required for a group or device scope.", ja: "グループ/デバイス範囲では必須です。" })); return; }
    submit.disabled = true;
    const body = { scope_type: scopeType, excluded_app_signing_ids: ids, note: noteF.get() };
    if (scopeType !== "tenant") body.scope_id = scopeIDF.get();
    if (existing && existing.id) body.id = existing.id;
    try {
      const r = await apiFetch("POST", "/admin/steer-exclusions", body);
      if (!r.ok) { submit.disabled = false; const msg = (r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status); uiToast(msg, "err"); return; }
      m.close();
      uiToast(existing ? bl({ en: "Exception saved.", ja: "除外を保存しました。" }) : bl({ en: "Exception added.", ja: "除外を追加しました。" }), "ok");
      renderSteerExclAuthored(host);
    } catch (e) { submit.disabled = false; uiToast(String(e), "err"); }
  });
  scopeF.focus();
}

async function deleteSteerExcl(x, listHost) {
  const ok = await uiConfirm({
    title: bl({ en: "Delete this steering exclusion?", ja: "このステアリング除外を削除しますか?" }),
    body: bl({ en: "The excluded apps will be steered through the secure gateway again on the affected devices (subject to the loop-prevention floor and any dev scaffold).", ja: "除外していたアプリは、対象デバイスで再びセキュアゲートウェイ経由になります(ループ防止フロアや開発用スキャフォールドは別途残ります)。" }),
    confirmLabel: bl({ en: "Delete", ja: "削除" }), danger: true,
  });
  if (!ok) return;
  try {
    const r = await apiFetch("DELETE", "/admin/steer-exclusions/" + encodeURIComponent(x.id || ""));
    if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
    uiToast(bl({ en: "Exception deleted.", ja: "除外を削除しました。" }), "ok");
    renderSteerExclList(listHost);
  } catch (e) { uiToast(String(e), "err"); }
}

// ---------------------------------------------------------------------------
// Section 2 — Observed on devices (reverse telemetry; read-only). Shows what a device ACTUALLY excludes —
// floor + scaffold + admin policy as applied — so silent exclusions become accountable.
//
// SCALE REDESIGN (docs/steer_exclusions_observed_telemetry_scale_design.md): the old design rendered one
// card per device (observed.forEach(dev => card)) and broke at fleet scale. This is now a SEARCH-FIRST,
// SUMMARY-ANCHORED surface — never "fetch everything":
//   • a summary bar (devices reporting + an anomalous shortcut),
//   • a "Devices" view: server-filtered + cursor-paginated dense table, row → detail drawer,
//   • a "By AppID" view: the fleet-wide drift aggregate, click an AppID → drills into the device table.
// All filtering/pagination is server-side via the fixed API contract; classification is authoritative per-entry
// (admin / floor / unmanaged by membership in the device's admin_/unmanaged_app_signing_ids).
// ---------------------------------------------------------------------------

// Observed-pane state, persisted across re-renders so a "By AppID" drill keeps its app= filter.
let _steerExclObservedView = "devices"; // "devices" | "by-app"
let _steerExclObservedFilters = { device: "", group: "", app: "", anomalous: false };

function steerExclRelTime(ts) {
  if (!ts) return bl({ en: "never", ja: "なし" });
  const d = new Date(ts);
  if (isNaN(d.getTime())) return String(ts);
  return window.dsseFormatTime(d);
}

function steerExclDebounce(fn, ms) {
  let t;
  return function () { clearTimeout(t); t = setTimeout(fn, ms); };
}

// steerExclClassifyEntry returns the authoritative class of one effective AppID for a device:
// "admin" (admin-authored), "unmanaged" (neither admin nor known floor — the accountability signal), or
// "floor" (everything else: loop-prevention self-image / known dev scaffold). Per the API contract this is by
// list membership, NOT the old "first N = baseline" position heuristic.
function steerExclClassifyEntry(id, dev) {
  const sid = String(id);
  if ((dev.admin_app_signing_ids || []).indexOf(sid) >= 0) return "admin";
  if ((dev.unmanaged_app_signing_ids || []).indexOf(sid) >= 0) return "unmanaged";
  return "floor";
}

function steerExclClassBadge(cls) {
  if (cls === "unmanaged") return uiBadge(bl({ en: "unmanaged", ja: "管理者設定外" }), "warn");
  if (cls === "admin") return uiBadge(bl({ en: "admin", ja: "管理者" }), "ok");
  return uiBadge(bl({ en: "floor", ja: "デバイス標準" }), "off");
}

// renderSteerExclObserved is the observed-pane shell: description, a summary bar, a Devices/By-AppID switch, and
// the active inner view. It never lists the whole fleet — each inner view queries the server with filters+paging.
function renderSteerExclObserved(host) {
  host.innerHTML = "";
  host.appendChild(el("p", { class: "ui-view-desc", text: bl({ en: "What devices actually exclude — the loop-prevention floor and any dev scaffold appear here even though they aren't admin-authored. Read-only telemetry reported by the endpoint agent. Search and filter the fleet rather than browsing every device.", ja: "各デバイスが実際に除外している内容です。ループ防止フロアや開発用スキャフォールドは管理者が設定していなくてもここに表示されます。エンドポイントエージェントが報告する読み取り専用テレメトリです。全デバイスを閲覧するのではなく、検索・絞り込みで探します。" }) }));

  const summaryHost = el("div", { class: "ui-kv", style: "margin:6px 0 12px; display:flex; gap:18px; flex-wrap:wrap; align-items:center;" });
  host.appendChild(summaryHost);
  renderSteerExclObservedSummary(summaryHost, host);

  host.appendChild(uiTabs([
    { id: "devices", label: bl({ en: "Devices", ja: "デバイス" }) },
    { id: "by-app", label: bl({ en: "By AppID", ja: "アプリ識別子別" }) },
  ], _steerExclObservedView, (id) => { _steerExclObservedView = id; renderSteerExclObserved(host); }));

  const pane = el("div", {});
  host.appendChild(pane);
  if (_steerExclObservedView === "by-app") renderSteerExclByApp(pane, host);
  else renderSteerExclDevices(pane, host);
}

// renderSteerExclObservedSummary fills the always-on fleet-health bar: total reporters + a prominent anomalous
// shortcut. Both are cheap total_estimate reads (limit=1) — no list. The anomalous chip jumps to the filter.
async function renderSteerExclObservedSummary(summaryHost, host) {
  summaryHost.innerHTML = "";
  summaryHost.appendChild(el("span", { class: "ui-view-desc", text: bl({ en: "Loading fleet summary…", ja: "フリート概要を読込中…" }) }));
  let total = null, anomalous = null;
  try {
    const [rAll, rAnom] = await Promise.all([
      apiFetch("GET", "/admin/steer-exclusions/observed?limit=1"),
      apiFetch("GET", "/admin/steer-exclusions/observed?anomalous=true&limit=1"),
    ]);
    if (rAll.ok && rAll.body) total = rAll.body.total_estimate || 0;
    if (rAnom.ok && rAnom.body) anomalous = rAnom.body.total_estimate || 0;
  } catch (e) { /* leave summary best-effort */ }
  summaryHost.innerHTML = "";
  if (total == null) {
    summaryHost.appendChild(el("span", { class: "ui-view-desc", text: bl({ en: "Fleet summary unavailable.", ja: "フリート概要を取得できません。" }) }));
    return;
  }
  summaryHost.appendChild(el("span", {}, [
    el("strong", { text: String(total) }),
    document.createTextNode(" "),
    el("span", { class: "ui-view-desc", text: bl({ en: "devices reporting", ja: "デバイスが報告中" }) }),
  ]));
  if (anomalous != null) {
    if (anomalous > 0) {
      summaryHost.appendChild(el("button", {
        class: "ui-btn ui-btn-sm ui-btn-danger",
        title: bl({ en: "Show only devices with unmanaged exclusions", ja: "管理者設定外の除外があるデバイスのみ表示" }),
        text: "⚠ " + anomalous + " " + bl({ en: "devices with unmanaged exclusions", ja: "件: 管理者設定外の除外あり" }),
        onClick: () => {
          _steerExclObservedView = "devices";
          _steerExclObservedFilters = { device: "", group: "", app: "", anomalous: true };
          renderSteerExclObserved(host);
        },
      }));
    } else {
      summaryHost.appendChild(uiBadge(bl({ en: "0 anomalous", ja: "管理者設定外の除外なし" }), "ok"));
    }
  }
}

// renderSteerExclDevices is the server-paginated device table. Text inputs debounce → requery from page 1; a
// "Load more" button appends the next cursor page. A generation token discards stale in-flight responses.
function renderSteerExclDevices(pane, host) {
  pane.innerHTML = "";
  const f = _steerExclObservedFilters;

  const deviceF = uiField({ name: "device", label: bl({ en: "Device", ja: "デバイス" }), value: f.device, placeholder: "mac-dev-1 " + bl({ en: "or", ja: "または" }) + " mac-*", hint: bl({ en: "Exact, or a prefix ending in *.", ja: "完全一致、または * で終わる前方一致。" }) });
  const groupF = uiField({ name: "group", label: bl({ en: "Group", ja: "グループ" }), value: f.group, placeholder: "engineering" });
  const appF = uiField({ name: "app", label: bl({ en: "AppID", ja: "アプリ識別子" }), value: f.app, placeholder: "team-id:Q6L2SF6YDW" });
  const anomF = uiField({ name: "anomalous", label: bl({ en: "Anomalous only", ja: "管理者設定外のみ" }), type: "checkbox", value: f.anomalous });
  [deviceF, groupF, appF].forEach((x) => { x.el.style.marginBottom = "0"; x.el.style.minWidth = "180px"; });
  anomF.el.style.marginBottom = "0";

  pane.appendChild(el("div", { class: "ui-toolbar", style: "gap:12px; flex-wrap:wrap; align-items:flex-end;" }, [deviceF.el, groupF.el, appF.el, anomF.el]));

  const countHost = el("div", { class: "ui-view-desc", style: "margin:6px 0;" });
  pane.appendChild(countHost);
  const tableHost = el("div", {});
  pane.appendChild(tableHost);
  const moreHost = el("div", { style: "margin-top:10px;" });
  pane.appendChild(moreHost);

  let gen = 0;          // request generation; stale responses are ignored
  let cursor = "";      // next_cursor for "Load more"
  let loaded = 0;       // rows shown so far
  let total = 0;        // total_estimate
  let tbody = null;     // table body to append into

  const syncFilters = () => {
    f.device = deviceF.get(); f.group = groupF.get(); f.app = appF.get(); f.anomalous = anomF.get();
  };

  const updateCount = (capped) => {
    countHost.innerHTML = "";
    countHost.appendChild(document.createTextNode(bl({ en: "Showing ", ja: "表示 " }) + loaded + bl({ en: " of ~", ja: " / 約" }) + total));
    if (capped) countHost.appendChild(el("span", { class: "ui-view-desc", text: "  · " + bl({ en: "showing most recent reporters (cache bound)", ja: "直近の報告デバイスを表示(キャッシュ上限)" }) }));
  };

  const load = async (reset) => {
    syncFilters();
    const myGen = ++gen;
    if (reset) { cursor = ""; loaded = 0; total = 0; tbody = null; }
    if (reset) uiState(tableHost, "loading");
    moreHost.innerHTML = "";
    const params = [];
    if (f.device) params.push("device=" + encodeURIComponent(f.device));
    if (f.group) params.push("group=" + encodeURIComponent(f.group));
    if (f.app) params.push("app=" + encodeURIComponent(f.app));
    if (f.anomalous) params.push("anomalous=true");
    params.push("limit=50");
    if (cursor) params.push("cursor=" + encodeURIComponent(cursor));
    let body;
    try {
      const r = await apiFetch("GET", "/admin/steer-exclusions/observed?" + params.join("&"));
      if (myGen !== gen) return; // superseded
      if (!r.ok) { uiState(tableHost, "error", "HTTP " + r.status, { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => load(true) }); return; }
      body = r.body || {};
    } catch (e) {
      if (myGen !== gen) return;
      uiState(tableHost, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => load(true) });
      return;
    }
    const page = body.observed || [];
    total = typeof body.total_estimate === "number" ? body.total_estimate : (loaded + page.length);
    const next = body.next_cursor || "";
    cursor = (next && next !== "|") ? next : "";

    if (reset && !page.length) {
      uiState(tableHost, "empty", bl({ en: "No device matches — or no device has reported yet.", ja: "一致するデバイスがありません。またはまだ報告がありません。" }));
      updateCount(false);
      return;
    }
    if (reset) {
      tbody = el("tbody", {});
      tableHost.innerHTML = "";
      tableHost.appendChild(el("table", { class: "ui-table" }, [
        el("thead", {}, el("tr", {}, [
          el("th", { text: bl({ en: "Device", ja: "デバイス" }) }),
          el("th", { text: bl({ en: "Group", ja: "グループ" }) }),
          el("th", { text: bl({ en: "Platform", ja: "プラットフォーム" }) }),
          el("th", { text: bl({ en: "#Effective", ja: "実効数" }) }),
          el("th", { text: bl({ en: "#Unmanaged", ja: "管理者設定外" }) }),
          el("th", { text: bl({ en: "Reported", ja: "報告時刻" }) }),
        ])),
        tbody,
      ]));
    }
    page.forEach((dev) => {
      const eff = dev.effective_app_signing_ids || [];
      const unmanaged = (dev.unmanaged_app_signing_ids || []).length;
      tbody.appendChild(el("tr", { class: "ui-row-clickable", onClick: () => showSteerExclDeviceDetail(dev) }, [
        el("td", {}, el("code", { text: dev.device_identity || "—" })),
        el("td", { text: dev.device_group || "—" }),
        el("td", {}, dev.platform ? uiBadge(dev.platform, "off") : document.createTextNode("—")),
        el("td", { text: String(eff.length) }),
        el("td", {}, unmanaged > 0 ? uiBadge(String(unmanaged), "warn") : document.createTextNode("0")),
        el("td", { text: steerExclRelTime(dev.reported_at) }),
      ]));
    });
    loaded += page.length;
    // Cache-bound note: when we've drained the cursor but shown fewer than the estimate, the store is bounded.
    updateCount(!cursor && loaded < total);
    moreHost.innerHTML = "";
    if (cursor) {
      moreHost.appendChild(el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Load more", ja: "さらに読込" }), onClick: () => load(false) }));
    }
  };

  const debounced = steerExclDebounce(() => load(true), 250);
  [deviceF, groupF, appF].forEach((x) => {
    const inp = x.el.querySelector("input");
    if (inp) inp.addEventListener("input", debounced);
  });
  const anomInp = anomF.el.querySelector("input");
  if (anomInp) anomInp.addEventListener("change", () => load(true));

  load(true);
}

// showSteerExclDeviceDetail is the single-device rich view (the one place a card-density layout is right): the
// full effective set, each entry badged admin / floor / unmanaged by authoritative list membership.
function showSteerExclDeviceDetail(dev) {
  const eff = dev.effective_app_signing_ids || [];
  const idEls = eff.map((id) => el("div", { class: "ui-kv-row" }, [
    el("div", { class: "ui-kv-val" }, el("code", { text: String(id) })),
    el("div", { class: "ui-kv-key" }, steerExclClassBadge(steerExclClassifyEntry(id, dev))),
  ]));
  const overview = el("div", { class: "ui-kv" }, [
    el("div", { class: "ui-kv-row" }, [
      el("div", { class: "ui-kv-key", text: bl({ en: "Device", ja: "デバイス" }) }),
      el("div", { class: "ui-kv-val" }, [el("code", { text: dev.device_identity || "—" }),
        dev.platform ? document.createTextNode(" ") : null,
        dev.platform ? uiBadge(dev.platform, "off") : null]),
    ]),
    el("div", { class: "ui-kv-row" }, [
      el("div", { class: "ui-kv-key", text: bl({ en: "Group", ja: "グループ" }) }),
      el("div", { class: "ui-kv-val", text: dev.device_group || "—" }),
    ]),
    el("div", { class: "ui-kv-row" }, [
      el("div", { class: "ui-kv-key", text: bl({ en: "Reported", ja: "報告時刻" }) }),
      el("div", { class: "ui-kv-val", text: steerExclRelTime(dev.reported_at) }),
    ]),
  ]);
  const m = uiModal({
    title: bl({ en: "Device exclusions", ja: "デバイスの除外" }),
    body: [
      overview,
      el("h4", { style: "margin:12px 0 4px;", text: bl({ en: "Effective exclusions", ja: "実効除外" }) + " (" + eff.length + ")" }),
      eff.length ? el("div", { class: "ui-kv" }, idEls) : el("p", { class: "ui-view-desc", text: bl({ en: "None reported.", ja: "報告なし。" }) }),
    ],
    footer: [el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Close", ja: "閉じる" }), onClick: () => m.close() })],
  });
}

// renderSteerExclByApp is the fleet-wide drift aggregate: which AppIDs are excluded and on how many devices,
// unmanaged-first (already sorted by the API). Clicking an AppID drills into the device table filtered to it.
async function renderSteerExclByApp(pane, host) {
  pane.innerHTML = "";
  pane.appendChild(el("p", { class: "ui-view-desc", text: bl({ en: "Which AppIDs are excluded across the fleet — unmanaged (neither admin-authored nor known floor) first. Click an AppID to see which devices apply it.", ja: "フリート全体で除外されているアプリ識別子の一覧 — 管理者設定外(管理者設定でも既知フロアでもない)を先頭に表示。アプリ識別子をクリックすると適用デバイスを確認できます。" }) }));
  const listHost = el("div", {});
  pane.appendChild(listHost);
  uiState(listHost, "loading");
  let body;
  try {
    const r = await apiFetch("GET", "/admin/steer-exclusions/observed/by-app?limit=100");
    if (!r.ok) { uiState(listHost, "error", "HTTP " + r.status, { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderSteerExclByApp(pane, host) }); return; }
    body = r.body || {};
  } catch (e) { uiState(listHost, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderSteerExclByApp(pane, host) }); return; }
  const apps = body.apps || [];
  if (!apps.length) {
    uiState(listHost, "empty", bl({ en: "No exclusions reported across the fleet yet.", ja: "フリート全体でまだ除外の報告がありません。" }));
    return;
  }
  const drill = (appID) => {
    _steerExclObservedView = "devices";
    _steerExclObservedFilters = { device: "", group: "", app: appID, anomalous: false };
    renderSteerExclObserved(host);
  };
  const rows = apps.map((a) => el("tr", { class: "ui-row-clickable", onClick: () => drill(a.app_id) }, [
    el("td", {}, el("code", { text: a.app_id || "—" })),
    el("td", { text: String(a.device_count || 0) }),
    el("td", {}, steerExclClassBadge(a.class)),
  ]));
  listHost.innerHTML = "";
  listHost.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [
      el("th", { text: bl({ en: "AppID", ja: "アプリ識別子" }) }),
      el("th", { text: bl({ en: "Devices", ja: "デバイス数" }) }),
      el("th", { text: bl({ en: "Class", ja: "区分" }) }),
    ])),
    el("tbody", {}, rows),
  ]));
}

// ---------------------------------------------------------------------------
// Section 3 — Resolved for a device (forward, layer 3 only): the admin set the Edge would serve a given device.
// ---------------------------------------------------------------------------

function renderSteerExclResolved(host) {
  host.innerHTML = "";
  host.appendChild(el("p", { class: "ui-view-desc", text: bl({ en: "Preview the admin-authored exclusion set the Edge would serve a specific device (the resolved layer 3 — not the device's local floor or scaffold).", ja: "特定デバイスに対して Edge が配信する管理者設定の除外セット(解決後のレイヤ3 — デバイス側のフロアやスキャフォールドは含みません)をプレビューします。" }) }));
  const deviceF = uiField({ name: "device", label: bl({ en: "Device identity", ja: "デバイス識別子" }), placeholder: "mac-dev-1" });
  deviceF.el.style.marginBottom = "0";
  const goBtn = el("button", { class: "ui-btn ui-btn-primary ui-btn-sm", text: bl({ en: "Resolve", ja: "解決" }) });
  host.appendChild(el("div", { class: "ui-toolbar" }, [deviceF.el, goBtn]));
  const resultHost = el("div", {});
  host.appendChild(resultHost);

  const run = async () => {
    const device = deviceF.get();
    if (!device) { deviceF.setError(bl({ en: "Enter a device identity.", ja: "デバイス識別子を入力してください。" })); return; }
    uiState(resultHost, "loading");
    let res;
    try {
      const r = await apiFetch("GET", "/admin/steer-exclusions/resolved?device=" + encodeURIComponent(device));
      if (!r.ok) { uiState(resultHost, "error", "HTTP " + r.status, { label: bl({ en: "Retry", ja: "再試行" }), onClick: run }); return; }
      res = r.body || {};
    } catch (e) { uiState(resultHost, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: run }); return; }
    const ids = (res && res.resolved_app_signing_ids) || [];
    resultHost.innerHTML = "";
    const rows = [
      el("div", { class: "ui-kv-row" }, [
        el("div", { class: "ui-kv-key", text: bl({ en: "Device", ja: "デバイス" }) }),
        el("div", { class: "ui-kv-val" }, el("code", { text: (res && res.device_identity) || device })),
      ]),
      el("div", { class: "ui-kv-row" }, [
        el("div", { class: "ui-kv-key", text: bl({ en: "Group", ja: "グループ" }) }),
        el("div", { class: "ui-kv-val", text: (res && res.device_group) || "—" }),
      ]),
    ];
    resultHost.appendChild(el("div", { class: "ui-kv" }, rows));
    if (!ids.length) {
      resultHost.appendChild(el("p", { class: "ui-view-desc", text: bl({ en: "No admin-authored exclusions resolve for this device.", ja: "このデバイスに解決される管理者設定の除外はありません。" }) }));
      return;
    }
    resultHost.appendChild(el("h4", { style: "margin:10px 0 4px;", text: bl({ en: "Resolved admin exclusions", ja: "解決された管理者除外" }) + " (" + ids.length + ")" }));
    resultHost.appendChild(el("div", { class: "ui-kv" }, ids.map((id) => el("div", { class: "ui-kv-row" }, [
      el("div", { class: "ui-kv-val" }, el("code", { text: String(id) })),
      el("div", { class: "ui-kv-key" }, uiBadge(bl({ en: "admin", ja: "管理者" }), "ok")),
    ]))));
  };
  goBtn.addEventListener("click", run);
  const inp = deviceF.el.querySelector("input");
  if (inp) inp.addEventListener("keydown", (e) => { if (e.key === "Enter") run(); });
}

// ── Which devices actually apply an authored rule ────────────────────────────────────────────────────────
// An authored rule that no device applies used to be invisible: the authored tab listed it, the observed tab
// listed device reality, and nothing joined the two. Silence is the accepted behaviour for a form a device's OS
// cannot use — but silence the operator cannot see is how an authoring mistake looks exactly like correct
// inapplicability.
//
// steerExclAppIDApplies is a DISPLAY HINT and must track docs/steering_exclusion_appid_format.md. It decides
// nothing; the agents do. A drift here shows a wrong explanation, never wrong behaviour.
function steerExclAppIDApplies(appID, platform) {
  const id = String(appID || "").trim();
  const os = String(platform || "").toLowerCase();
  const typed = id.match(/^([a-z-]+):/i);
  if (typed) {
    const kind = typed[1].toLowerCase();
    if (kind === "subject" || kind === "thumbprint") return true;          // shared forms
    if (kind === "team-id" || kind === "signing-id") return os === "macos";
    if (kind === "publisher" || kind === "signed") return os === "windows";
    return false;                                                          // unknown prefix: ignored everywhere
  }
  // Bare: macOS reads it as a code-signing identifier, Windows as an image-path substring. A macOS signing
  // identifier cannot contain a backslash, a space or brackets, so a Windows install path is inert there.
  if (os === "macos") return /^[A-Za-z0-9._-]+$/.test(id);
  return true;
}

function steerExclDevicesInScope(rule, devices) {
  return (devices || []).filter((d) => {
    if (rule.scope_type === "tenant") return true;
    // Compared through deviceKey: a rule is scoped from one list and matched against another, and the two
    // spell the same machine differently (see ui.js). An exact compare read as "not applied".
    if (rule.scope_type === "device") return deviceKey(d.device_identity) === deviceKey(rule.scope_id);
    if (rule.scope_type === "device_group") return rule.scope_id && d.device_group === rule.scope_id;
    return false;
  });
}

function steerExclAppliedCell(rule, devices) {
  const inScope = steerExclDevicesInScope(rule, devices);
  if (!inScope.length) return el("td", { class: "ui-view-desc", text: "—" });
  const ids = (rule.excluded_app_signing_ids || []).map((i) => String(i).toLowerCase());
  const notes = [];
  let applying = 0;
  inScope.forEach((d) => {
    const have = new Set((d.admin_app_signing_ids || []).map((i) => String(i).toLowerCase()));
    const missing = ids.filter((i) => !have.has(i));
    if (!missing.length) { applying++; return; }
    // Split the missing ones: a form this OS cannot use is expected; anything else is not explained.
    const expected = missing.filter((i) => !steerExclAppIDApplies(i, d.platform));
    const unexplained = missing.filter((i) => steerExclAppIDApplies(i, d.platform));
    // The DEVICE's own answer wins over our inference. An agent that reports what it ignored has already
    // decided; inferring from the AppID's shape is only for agents that do not say (older ones, and Windows,
    // which reports its merged set without splitting it).
    const said = (d.ignored_app_signing_ids || []).map((i) => String(i).toLowerCase());
    if (said.length) {
      const unaccounted = missing.filter((i) => said.indexOf(i) < 0);
      if (unaccounted.length) {
        notes.push({ warn: true, text: d.device_identity + ": " + bl({ en: "not applied", ja: "未適用" }) });
      } else {
        notes.push({ warn: false, text: d.device_identity + ": " + bl({ en: "ignored by the device", ja: "デバイスが適用対象外と判断" }) });
      }
      return;
    }
    if (unexplained.length) {
      notes.push({ warn: true, text: d.device_identity + ": " + bl({ en: "not applied", ja: "未適用" }) });
    } else if (expected.length) {
      const osName = { macos: "macOS", windows: "Windows" }[String(d.platform || "").toLowerCase()] || d.platform || bl({ en: "this OS", ja: "この OS" });
      notes.push({ warn: false, text: d.device_identity + ": " + bl({ en: "form " + osName + " cannot use", ja: osName + " が使えない形式" }) });
    }
  });
  const cell = el("td", {}, [el("div", { text: applying + "/" + inScope.length })]);
  notes.forEach((n) => cell.appendChild(el("div", {
    class: "ui-view-desc", style: n.warn ? "color:var(--ui-warn,#d98b24)" : "", text: n.text,
  })));
  return cell;
}
