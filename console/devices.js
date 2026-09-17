"use strict";

// ---------------------------------------------------------------------------
// devices.js — "Enrolled Devices" view: the VERTICAL SLICE reference implementation of the product-quality UX
// (docs/console_ux_design_direction.md). It replaces the raw-JSON "enrolled" card with the full object
// lifecycle on the shared ui.js primitives: list (search + status filter + badges + empty/loading/error),
// a typed+validated enroll form (no JSON), and per-row lifecycle actions (enable / disable=revoke / remove)
// with proportional confirmation and toast feedback that refreshes the list in place.
//
// Backend (edge): GET /admin/enrolled-devices -> {devices:[{identity,enabled,note,group,enrolled_at,updated_at}]},
// POST /admin/enrolled-devices {identity,note,group}, POST /admin/enrolled-devices/{id}/{enable|disable},
// POST /admin/enrolled-devices/{id}/group {group} (M7: CP-authoritative device-group assignment — the
// union-model scope the agent-policy/agent-tuning resolution reads), DELETE /admin/enrolled-devices/{id}.
// app.js dispatches here for the GROUPS entry custom:"devices".
// ---------------------------------------------------------------------------

let _devicesState = { search: "", filter: "all", tab: "devices" };
let _devicesRoot = null;

// renderDevicesView — the view entry (app.js custom:"devices"). Renders the page-level tab bar
// [Devices | Device groups] and dispatches to the selected tab's body. Device groups are a TAB of this page
// (not a separate left-nav item), per docs/admin_console_device_group_registry_and_tab_select_design.ja.md.
function renderDevicesView(content) {
  _devicesRoot = content;
  content.innerHTML = "";
  const tab = _devicesState.tab || "devices";
  const mkTab = (key, label) => el("button", {
    class: "ui-btn ui-btn-sm" + (tab === key ? " ui-btn-primary" : ""),
    text: label,
    onClick: () => { if (_devicesState.tab !== key) { _devicesState.tab = key; renderDevicesView(content); } },
  });
  content.appendChild(el("div", { class: "ui-tabbar", style: "display:flex;gap:8px;margin-bottom:16px" }, [
    mkTab("devices", bl({ en: "Devices", ja: "デバイス" })),
    mkTab("groups", bl({ en: "Device groups", ja: "デバイスグループ" })),
  ]));
  const body = el("div", {});
  content.appendChild(body);
  if (tab === "groups") renderGroupsTab(body);
  else renderDevicesTab(body);
}

function renderDevicesTab(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "Devices", ja: "デバイス" }) }),
      el("p", { class: "ui-view-desc", text: bl({
        en: "Devices registered with the secure gateway. Admission requires enabled enrollment and no connection block. Steering shows reported activity. Block status reflects the latest control-plane read; it does not confirm that every region has applied a change.",
        ja: "セキュアゲートウェイに登録したデバイス。接続には登録が有効で、接続の遮断がないことが必要です。ステア中は報告された稼働状態を表します。遮断状態は管理サーバーの最新の取得結果であり、全リージョンへの反映完了を示すものではありません。",
      }) }),
    ]),
    el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "+ Add device", ja: "+ デバイスを追加" }), onClick: () => openEnrollForm(content) }),
  ]));

  const search = el("input", { class: "ui-input ui-search", type: "search", placeholder: bl({ en: "Search devices…", ja: "デバイスを検索…" }) });
  search.value = _devicesState.search;
  search.addEventListener("input", () => { _devicesState.search = search.value; renderList(listHost); });
  const filter = uiField({ name: "status", type: "select", value: _devicesState.filter, options: [
    { value: "all", label: bl({ en: "All", ja: "全て" }) },
    { value: "enabled", label: bl({ en: "Allowed", ja: "許可" }) },
    { value: "disabled", label: bl({ en: "Blocked", ja: "ブロック" }) },
  ] });
  filter.el.style.marginBottom = "0";
  filter.el.querySelector("select").addEventListener("change", () => { _devicesState.filter = filter.get(); renderList(listHost); });

  content.appendChild(el("div", { class: "ui-toolbar" }, [
    search,
    filter.el,
    el("span", { class: "ui-spacer" }),
    el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Reload", ja: "再読込" }), onClick: () => renderList(listHost) }),
  ]));

  const messages = el("div", {});
  content.appendChild(messages);
  const listHost = el("div", {});
  listHost.__deviceAdmissionMessages = messages;
  content.appendChild(listHost);
  renderList(listHost);
}

// ---- device state model (redesign: one primary pill + severity + quiet signals) --------------------------
// docs/2026-07-25_trip_wrapup_and_aws_shutdown.ja.md + the "Devices — redesign proposal" mockup. deviceStateOf
// folds the enrolled-device record (d), the reverse-telemetry observed entry (obs), and the runtime posture (rt)
// into one runtime STATE: a single primary steering pill + a quiet config subline, a severity for the row stripe,
// and a signal list where only ANOMALIES get colour (a healthy device shows just "✓ managed"). No backend change
// — every field already comes from the existing /admin/steer-exclusions/observed + /admin/device-runtime calls.
// The device's certificate as one table cell: how long it has left, and when it renews itself. The expiry is
// the fact with a deadline; the renewal date is what says the deadline will never arrive. A device with no
// observed certificate says so — "not observed" is a state, not an empty cell that reads as fine.
function deviceCertCell(cert) {
  if (!cert) {
    return el("span", { class: "dev-risk-ok", text: bl({ en: "not observed", ja: "未観測" }),
      title: bl({ en: "This device has not presented a certificate since this node started.",
                  ja: "このノードの起動以降、この端末は証明書を提示していません。" }) });
  }
  const days = cert.days_left;
  const tone = cert.expired ? "danger" : (days != null && days <= 30 ? "warn" : "ok");
  const badge = uiBadge(cert.expired ? bl({ en: "EXPIRED", ja: "期限切れ" })
    : bl({ en: days + "d left", ja: "残り" + days + "日" }), tone === "danger" ? "off" : tone);
  const renews = cert.renews_in_days != null
    ? bl({ en: "renews in " + cert.renews_in_days + "d", ja: "更新まで" + cert.renews_in_days + "日" })
    : "";
  return el("div", {
    title: (cert.issuer_common_name ? bl({ en: "Issued by ", ja: "発行: " }) + cert.issuer_common_name : "") +
           (cert.not_after ? "\n" + bl({ en: "Expires ", ja: "期限: " }) + cert.not_after : ""),
  }, [badge, renews ? el("div", { class: "dev-sub", text: renews }) : null].filter(Boolean));
}

function fmtAgo(ts) {
  const m = Math.max(0, Math.floor((Date.now() - ts) / 60000));
  if (m < 60) return m + bl({ en: "m ago", ja: "分前" });
  return Math.floor(m / 60) + bl({ en: "h ago", ja: "時間前" });
}
function shortApp(a) { a = String(a || ""); const parts = a.split(/[.\/\\:]/); return parts[parts.length - 1] || a; }
function riskLabel(sev) { return sev === "critical" ? bl({ en: "Critical", ja: "重大" }) : sev === "high" ? bl({ en: "High", ja: "高" }) : sev === "medium" ? bl({ en: "Medium", ja: "中" }) : bl({ en: "Normal", ja: "通常" }); }
function riskTone(sev) { return (sev === "high" || sev === "critical") ? "danger" : (sev === "medium" ? "warn" : "off"); }

// applyUpdateState folds what a device did with the release it was offered into the row it already has.
//
// ★ CHIPS ONLY WHEN THERE IS SOMETHING TO SAY. A device that took the release looks exactly as it does today;
// the ones worth walking over to are the ones that gained a chip. A screen that marks every row marks none.
//
// ★ AND "NEVER REPORTED" IS ITS OWN STATE, not "up to date". The inventory carries an agent_version from the
// heartbeat, so a device that has never completed an update still LOOKS current — on a fleet where the
// reporting lane is broken, every machine would read as fine.
function applyUpdateState(st, u) {
  st.update = u || null;
  if (!u) return;
  if (u.state === "refused") {
    st.updateChip = "refused";
    st.signals.push({
      text: bl({ en: "refusing the update", ja: "更新を拒否" }), tone: "danger",
      // The device's own sentence, unedited. It wrote it knowing why; a summary here would replace what
      // happened with what this file guessed it meant.
      title: u.reason || "",
    });
    if (u.rejected_manifest_sha256) {
      st.signals.push({
        text: bl({ en: "unverified release document", ja: "検証できない配布文書" }), tone: "danger",
        title: bl({ en: "digest of the document this device refused: ", ja: "この端末が拒否した文書のダイジェスト: " }) + u.rejected_manifest_sha256,
      });
    }
  } else if (u.state === "failed") {
    st.updateChip = "failed";
    st.signals.push({ text: bl({ en: "update failed", ja: "更新に失敗" }), tone: "danger", title: u.reason || "" });
  } else if (u.state === "pending") {
    st.updateChip = "pending";
    st.signals.push({
      text: bl({ en: "update pending", ja: "更新待ち" }), tone: "warn",
      title: (u.reported_version || "?") + " → " + (u.target_version || "?"),
    });
  } else if (u.state === "no_release") {
    // Not a hazard on the device — a gap in what the fleet publishes, or in what it knows about the device.
    st.updateChip = "no_release";
    st.signals.push({ text: bl({ en: "no release for this device", ja: "配布対象なし" }), tone: "", title: u.reason || "" });
  } else if (u.state === "never_reported") {
    // Quiet, and counted: this is not a hazard on one device, it is a hole in what the fleet number covers.
    st.updateChip = "never_reported";
  }
  // `unknown` deliberately sets NOTHING. It is what the endpoint says when it could not read the outcome
  // store, and the whole point is that this device's update state is not being asserted — so it must not
  // acquire a chip, and must not be counted under "never reported", which is a claim about the DEVICE.
}

// Inventory and transport admission are independent gates. Keep the stored
// inventory flag intact, and derive the display from both verified read results.
function deviceIsBlocked(d) { return !d.enabled || d.transport_revoked === true; }
function deviceTenantSelection() { return typeof operateTenant === "string" ? operateTenant : ""; }
function deviceContextPath(path, tenant) {
  return tenant ? path + "?expected_tenant_id=" + encodeURIComponent(tenant) : path;
}
function deviceAdmissionRows(inventory, transport, selection) {
  const validID = value => typeof value === "string" && value.trim() !== "";
  if (!inventory || inventory.schema_version !== "admin_enrolled_inventory.v1" ||
      !validID(inventory.tenant_id) || (selection && inventory.tenant_id !== selection) ||
      !Array.isArray(inventory.devices) ||
      (inventory.unassigned !== undefined && (!Number.isInteger(inventory.unassigned) || inventory.unassigned < 0)) ||
      inventory.devices.some(d => !d || !validID(d.identity) || typeof d.enabled !== "boolean") ||
      new Set(inventory.devices.map(d => d.identity.trim().toLowerCase())).size !== inventory.devices.length) {
    throw new Error(bl({en: "The device inventory response could not be verified.", ja: "デバイス一覧の応答を確認できません。"}));
  }
  if (!transport || transport.schema_version !== "admin_transport_admission.v1" ||
      transport.tenant_id !== inventory.tenant_id || !Array.isArray(transport.revoked_identities) ||
      !Number.isInteger(transport.withheld_unattributable) || transport.withheld_unattributable < 0 ||
      transport.revoked_identities.some(id => !validID(id) || id !== id.trim().toLowerCase()) ||
      new Set(transport.revoked_identities).size !== transport.revoked_identities.length) {
    throw new Error(bl({en: "The connection block status could not be verified. Reload before changing devices.",
      ja: "接続の遮断状態を確認できません。デバイスを変更する前に再読込してください。"}));
  }
  const revoked = new Set(transport.revoked_identities);
  return inventory.devices.map(d => ({...d, transport_revoked: revoked.has(d.identity.trim().toLowerCase()),
    admissionContext: {tenant: inventory.tenant_id, selection}}));
}

function deviceStateOf(d, obs, rt, effSev) {
  const st = { severity: "", signals: [], steering: false, failOpen: false, offline: false, excluded: 0, sub: "" };
  const p = (rt && rt.posture) || {};
  if (deviceIsBlocked(d)) {
    st.severity = "danger"; st.pill = { text: bl({ en: "Blocked", ja: "ブロック" }), tone: "danger" };
    st.sub = bl({ en: "connection blocked", ja: "接続を遮断" });
  } else if (!obs) {
    if (rt && rt.steer_active === true) {
      // steering per device-runtime, but no reverse-telemetry entry yet (e.g. an agent that reports runtime but
      // not the observed steer-state). Still steering — just without the exclusion/posture detail.
      st.steering = true; st.pill = { text: bl({ en: "Steering", ja: "ステア中" }), tone: "ok" };
      // ★ WHERE it is steering, when that is somewhere other than the node we asked (2026-08-14). A device that
      // failed over used to read as not steering at all; naming the Edge turns "missing" into "over there",
      // which is the difference between an incident and a fact.
      st.sub = (rt.edge && String(rt.edge).trim())
        ? bl({ en: "via " + rt.edge, ja: rt.edge + " 経由" })
        : bl({ en: "state not reported", ja: "詳細未報告" });
    } else {
      st.offline = true; st.severity = "off"; st.pill = { text: bl({ en: "No report", ja: "報告なし" }), tone: "off" };
      st.sub = bl({ en: "not steering yet", ja: "未ステア" });
    }
  } else {
    const prot = (obs.posture || "").toLowerCase();
    const ts = obs.reported_at ? Date.parse(obs.reported_at) : NaN;
    const stale = !isNaN(ts) && (Date.now() - ts) > 5 * 60 * 1000;
    const foLabel = obs.fail_open_configured ? "fail-open" : "fail-close";
    // region_failover_enabled means multi-region is WIRED — NOT that the device is currently failing over. The
    // report does not carry the device's HOME region, so a name comparison cannot tell "failed over" from "on
    // home" — and the macOS NE reports the synthetic seed "bootstrap" until its first signed region list, which
    // a hard-coded home ("region-a") misread as a live failover. Show the active region as fact, verdict-free.
    const region = !obs.region_failover_enabled
      ? bl({ en: "single edge", ja: "単一Edge" })
      : bl({ en: "multi-region", ja: "マルチリージョン" }) + (obs.active_region ? " · " + obs.active_region : "");
    if (stale) {
      // "Not reporting" (state unknown), NOT "Offline" (shut down): the edge only knows the device stopped
      // reporting — it can't tell a powered-off device from one that failed open and can no longer reach the edge
      // to report it. The "last report" age is the honest signal.
      st.offline = true; st.severity = "off"; st.pill = { text: bl({ en: "Not reporting", ja: "報告なし" }), tone: "off" };
      st.sub = bl({ en: "last report ", ja: "最終報告 " }) + fmtAgo(ts);
    } else if (prot === "disarmed") {
      st.failOpen = true; st.severity = "danger"; st.pill = { text: bl({ en: "Fail-open engaged", ja: "fail-open 発動" }), tone: "danger" };
      st.sub = bl({ en: "unmediated native egress", ja: "何も介さず直接そのまま外へ出る通信" });
      st.signals.push({ text: bl({ en: "edge outage", ja: "edge 障害" }), tone: "danger" });
    } else if (prot === "dark") {
      st.severity = "danger"; st.pill = { text: bl({ en: "Blocked (dark)", ja: "遮断" }), tone: "danger" }; st.sub = foLabel;
    } else if (prot === "stopped") {
      st.severity = "off"; st.pill = { text: bl({ en: "Stopped", ja: "停止" }), tone: "off" }; st.sub = foLabel;
    } else if (prot === "captive_onboarding") {
      st.severity = "warn"; st.pill = { text: bl({ en: "Captive onboarding", ja: "キャプティブ" }), tone: "warn" }; st.sub = foLabel;
    } else if (prot === "steering") {
      st.steering = true; st.pill = { text: bl({ en: "Steering", ja: "ステア中" }), tone: "ok" }; st.sub = foLabel + " · " + region;
    } else if (!prot && rt && rt.steer_active === true) {
      // The agent's device-runtime reports it is actively steering, but its reverse-telemetry hasn't populated the
      // newer steer-state posture field — the macOS NE doesn't yet report posture/fail-open/region the way the
      // Windows agent (Phase 1a) does. Trust steer_active: it IS steering; the config detail is just unreported.
      st.steering = true; st.pill = { text: bl({ en: "Steering", ja: "ステア中" }), tone: "ok" };
      st.sub = (obs.fail_open_configured != null) ? (foLabel + " · " + region) : bl({ en: "state not reported", ja: "詳細未報告" });
    } else {
      st.pill = { text: obs.posture || bl({ en: "Unknown", ja: "不明" }), tone: "off" }; st.sub = foLabel;
    }
    // Excluded apps are an operational fact, not a hazard — a fleet with zero exclusions is the exception — so
    // they must not colour the row or its severity. The admin/unmanaged accountability split stays on the Steer
    // Exclusions page, which exists for exactly that question.
    const excl = (obs.admin_app_signing_ids || []).concat(obs.unmanaged_app_signing_ids || []);
    st.excluded = excl.length;
    if (excl.length > 0) {
      // Count chip carries the FULL list as a tooltip; show the first few app names inline, then "+N more" so the
      // count and the visible chips never disagree (6 excluded must not read as only 3).
      const show = 3;
      st.signals.unshift({ text: excl.length + bl({ en: " excluded apps", ja: " 除外アプリ" }), tone: "", title: excl.join(", ") });
      excl.slice(0, show).forEach((a) => st.signals.push({ text: shortApp(a), tone: "", title: a }));
      if (excl.length > show) st.signals.push({ text: "+" + (excl.length - show) + bl({ en: " more", ja: " 件" }), tone: "", title: excl.slice(show).join(", ") });
    }
    if (p.firewall_enabled === false) { st.signals.push({ text: bl({ en: "firewall off", ja: "FW オフ" }), tone: "warn" }); if (st.severity === "") st.severity = "warn"; }
    if (p.disk_encryption_enabled === false) { st.signals.push({ text: bl({ en: "disk enc off", ja: "暗号化オフ" }), tone: "warn" }); if (st.severity === "") st.severity = "warn"; }
  }
  // What the device REPORTS about itself, shown as fact rather than as a verdict.
  //
  // Only a FALSE reading used to appear (the two chips above), so "on" and "never measured" both rendered as
  // nothing at all — and an axis nobody measures is precisely what quietly failed this fleet: the Edge
  // required screen lock, no agent reads it, and every device sat noncompliant with no screen anywhere
  // saying why. Absence of a signal is information; it must not look like a clean bill of health.
  st.posture = postureFacts(p);
  if (effSev === "critical") st.severity = "danger";
  else if ((effSev === "high" || effSev === "medium") && st.severity !== "danger" && st.severity !== "off") st.severity = "warn";
  if (st.steering && st.signals.length === 0) st.signals.push({ text: bl({ en: "✓ managed", ja: "✓ 管理下" }), tone: "ok" });
  return st;
}

// overflowMenu — the row's "⋯": Block/Allow stays a first-class button; Group / Risk / Remove fold in here so the
// row isn't a wall of buttons. Risk levels below the device's group floor are disabled (they wouldn't take effect).
function overflowMenu(d, host, sev, grpSev) {
  const wrap = el("span", { class: "dev-ov" });
  const btn = el("button", { class: "ui-btn ui-btn-sm", text: "⋯", title: bl({ en: "More", ja: "その他" }) });
  btn.setAttribute("data-device-admission-control", "1");
  btn.setAttribute("data-device-risk-control", "1");
  btn.disabled = !!((host.__deviceAdmissionPending && host.__deviceAdmissionPending.has(d.identity)) ||
    (host.__deviceRiskPending && host.__deviceRiskPending.has(d.identity)));
  let menu = null;
  const onDoc = (e) => { if (!wrap.contains(e.target)) close(); };
  function close() { if (menu) { menu.remove(); menu = null; document.removeEventListener("click", onDoc, true); } }
  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    if (menu) { close(); return; }
    const floorRank = riskRank(grpSev);
    const items = [
      el("button", { class: "dev-ov-item", text: bl({ en: "Assign group…", ja: "グループを割当…" }), onClick: () => { close(); openAssignGroupForm(d, host); } }),
      el("div", { class: "dev-ov-sep" }),
    ];
    [["none", "Normal", "通常"], ["medium", "Medium", "中"], ["high", "High", "高"], ["critical", "Critical", "重大"]].forEach(([val, en, ja]) => {
      const below = riskRank(val) < floorRank;
      const cur = (sev || "none") === val;
      items.push(el("button", {
        class: "dev-ov-item", disabled: below || undefined,
        text: (cur ? "✓ " : "") + bl({ en: "Risk: " + en, ja: "リスク: " + ja }) + (below ? bl({ en: " (below floor)", ja: "(フロア未満)" }) : ""),
        onClick: () => { if (below) return; close(); setDeviceRisk(d, val, host); },
      }));
    });
    items.push(el("div", { class: "dev-ov-sep" }));
    // ★★★ THE RE-IMAGED MACHINE HAD NO DOOR EITHER (2026-08-29). Enrolment is once per device: the Edge
    // refuses a second one with "this identity is already enrolled — a renewal proves possession of the one
    // being replaced". A machine that was wiped, or whose agent was reinstalled, no longer holds the key that
    // would prove possession, so it can neither enrol nor renew. It is listed here, looking healthy, and
    // cannot come back. The grant that fixes it existed on the server with no caller anywhere in this Console.
    items.push(el("button", {
      class: "dev-ov-item",
      text: bl({ en: "Allow re-enrolment", ja: "再登録を許可" }),
      onClick: () => { close(); offerReEnrolment(d.identity, null, () => renderDevicesView(_devicesRoot)); },
    }));
    items.push(el("button", { class: "dev-ov-item dev-ov-danger", text: bl({ en: "Remove device", ja: "デバイスを削除" }), onClick: () => { close(); removeDevice(d, host); } }));
    menu = el("div", { class: "dev-ov-menu" }, items);
    wrap.appendChild(menu);
    setTimeout(() => document.addEventListener("click", onDoc, true), 0);
  });
  wrap.appendChild(btn);
  return wrap;
}

function deviceRiskSnapshot(body, tenant) {
  const map = body && body.high_risk;
  if (!body || body.entity_type !== "device" || body.tenant_id !== tenant || !tenant ||
      !map || typeof map !== "object" || Array.isArray(map) ||
      !Number.isSafeInteger(body.withheld_unattributable) || body.withheld_unattributable < 0 ||
      Object.entries(map).some(([id, severity]) => !id || id !== id.trim() || !["medium", "high", "critical"].includes(severity))) {
    throw new Error("Invalid device risk response");
  }
  return map;
}

async function renderList(host) {
  uiState(host, "loading");
  const selection = deviceTenantSelection(), renderCurrent = freshRender(host);
  const current = () => renderCurrent() && host.isConnected !== false && selection === deviceTenantSelection();
  let devices, tenant;
  // ★ unassigned IS PART OF THE ANSWER (2026-08-12, seventeenth review). The endpoint withholds devices that
  // belong to no tenant — they are nobody's to see or act on — and reports how many. Reading only `devices`
  // threw that number away, so the guarantee that made withholding safe ("nothing vanishes, it becomes a
  // count") stopped at the API and never reached anyone. On a fleet where every device is unassigned the
  // screen said "No devices yet", which is the fleet vanishing, in the exact words that invite an operator to
  // enrol them a second time.
  let unassigned = 0, withheldBlocks = 0;
  try {
    const r = await apiFetch("GET", deviceContextPath("/admin/enrolled-devices", selection), undefined, "control");
    if (!current()) return;
    if (!r.ok) throw new Error("HTTP " + r.status);
    tenant = r.body && r.body.tenant_id;
    if (typeof tenant !== "string" || !tenant.trim() || (selection && selection !== tenant)) {
      throw new Error(bl({en: "The device organization could not be verified. Reload before continuing.",
        ja: "デバイスの所属組織を確認できません。再読込してください。"}));
    }
    const transport = await apiFetch("GET", deviceContextPath("/admin/transport-admission", tenant), undefined, "control");
    if (!current()) return;
    if (!transport.ok) throw new Error(bl({en: "Connection block status unavailable", ja: "接続の遮断状態を取得できません"}) + " (HTTP " + transport.status + ")");
    devices = deviceAdmissionRows(r.body, transport.body, selection);
    unassigned = r.body.unassigned === undefined ? 0 : r.body.unassigned;
    withheldBlocks = transport.body.withheld_unattributable;
  } catch (e) {
    if (!current()) return;
    uiState(host, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderList(host) });
    return;
  }
  // Runtime facts the endpoint agent reports over the steer transport (OS, logged-in user, steer state, posture),
  // keyed by device identity. Best-effort — the list still renders if it is unavailable.
  // ★★ THE FLEET SPANS EDGES, SO THIS ASKS THE CONTROL PLANE (2026-08-14, from an operator whose Mac was
  // steering through region-b and read here as not steering at all, with no user). The Console's front door
  // proxies ONE Edge; a device that fails over — which is designed behaviour — disappears from it. The control
  // plane holds every Edge's shipped device-state history and answers for the whole fleet.
  //
  // The Edge is the fallback, not the preference: a deployment with no control plane still has one node's
  // truthful view of its own devices, and that is better than an empty page.
  let runtime = {}, runtimeFleetWide = false;
  try {
    const rr = await apiFetch("GET", "/admin/device-runtime", undefined, "control");
    if (rr.ok && rr.body && rr.body.devices) {
      runtime = rr.body.devices;
      runtimeFleetWide = !!rr.body.fleet_wide;
    }
  } catch (e) { /* fall through to the local Edge */ }
  if (!Object.keys(runtime).length) {
    try {
      const rr = await apiFetch("GET", "/admin/device-runtime");
      if (rr.ok && rr.body && rr.body.devices) runtime = rr.body.devices;
    } catch (e) { /* best-effort */ }
  }
  // What each device did with the release it was offered. Best-effort like every other overlay here: a fleet
  // that cannot be asked about updates is still a fleet whose steering state is worth seeing.
  //
  // ★ THIS LANE HAS BEEN INVISIBLE. Updates, rollbacks, refusals and the halt have all worked and been
  // reachable by curl and nothing else — so a release going out, or a device refusing one, showed up on no
  // screen an operator looks at.
  let updates = {}, updateOffering = {}, updateCoverage = null, updateFrozen = null, updateDegraded = "";
  try {
    const ru = await apiFetch("GET", "/admin/agent/device-updates");
    if (ru.ok && ru.body) {
      (ru.body.devices || []).forEach((u) => { updates[u.device_id] = u; });
      updateOffering = ru.body.offering || {};
      // ★ AN EMPTY COVERAGE IS NOT A COVERAGE OF ZERO. The endpoint withholds the numbers when it could not
      // read the telemetry, so "0/12 reported" is a sentence this screen must never assemble out of nothing —
      // it is the exact reading an operator would act on, and it would be describing a database, not a fleet.
      updateDegraded = ru.body.degraded || "";
      // ★ AND THE ROWS ARE NOT CONSUMED WHEN THE ANSWER IS DEGRADED (2026-08-12, fifteenth review).
      // Withholding the coverage was not enough on its own: the counts, the filter chips and the per-device
      // badges are all computed from the ROWS, so a telemetry outage still rendered as a fleet that had gone
      // quiet, one layer below the fix. The endpoint now says `unknown` rather than `never_reported`, and
      // this drops the overlay entirely so nothing here has to remember that.
      if (updateDegraded) { updates = {}; }
      updateCoverage = (ru.body.coverage && Object.keys(ru.body.coverage).length) ? ru.body.coverage : null;
      if (ru.body.frozen) updateFrozen = ru.body.frozen_reason || bl({ en: "rollout halted", ja: "配布停止中" });
    }
  } catch (e) { /* best-effort */ }
  // Risk is required for both the badge and the current value in the action menu.
  // A failed/foreign/malformed read must not turn into "Normal" or a clear selection.
  let riskMap;
  try {
    const rk = await apiFetch("GET", deviceContextPath("/admin/risk-signals", tenant), undefined, "control");
    if (!current()) return;
    if (!rk.ok) throw new Error("HTTP " + rk.status);
    riskMap = deviceRiskSnapshot(rk.body, tenant);
  } catch (e) {
    if (!current()) return;
    uiState(host, "error", bl({ en: "Risk status could not be read. Reload before changing device risk.",
      ja: "リスク状態を取得できません。変更する前に再読込してください。" }),
      { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderList(host) });
    return;
  }
  // Device-group RISK FLOOR: a group can carry a risk floor, and a member device's EFFECTIVE risk is
  // max(its own overlay risk, its group's floor). Fetch the registry so this list REFLECTS the group floor.
  // NOTE: this is the display (R3). Enforcement — the decision engine acting on the floor — is the separate R1
  // step, see docs/device_group_risk_floor_union_resolution_design.ja.md.
  let groupRisk = {};
  try {
    const rg = await apiFetch("GET", "/admin/device-groups");
    if (rg.ok && rg.body && rg.body.groups) rg.body.groups.forEach((g) => { groupRisk[(g.name || "").trim().toLowerCase()] = g.risk || ""; });
  } catch (e) { /* best-effort */ }
  // Device steering-state (reverse telemetry): each device's live posture (fail-open/close), effective steer-
  // excluded apps, region-failover, and server-initiated rule count, keyed by identity.
  // Best-effort — the list still renders if telemetry is unavailable. Ask for the fleet page (max 500).
  let steerState = {};
  try {
    const rs = await apiFetch("GET", "/admin/steer-exclusions/observed?limit=500");
    if (rs.ok && rs.body && rs.body.observed) steerState = byDeviceIdentity(rs.body.observed);
  } catch (e) { /* best-effort */ }
  // The certificate each device is actually presenting at the (T) handshake — expiry, issuer, and when it
  // renews next. Lives HERE because a device's certificate is a fact about the device, not a separate page
  // (operator decision 2026-07-31; the standalone Device-certificates screen is retired). Observed, so a
  // device that has not connected since this node started simply has no certificate fact — shown as such,
  // never as healthy.
  let certMap = {};
  try {
    const rc = await apiFetch("GET", "/admin/device-certificates");
    if (rc.ok && rc.body && rc.body.certificates) certMap = byDeviceIdentity(rc.body.certificates, "identity");
  } catch (e) { /* best-effort */ }
  if (devices.length === 0) {
    // ★ AND IT SAYS WHO CAN FIX IT AND HOW (2026-08-12, eighteenth review). The first version told the reader
    // an operator had to assign these devices, and no call could do it — a tenant-scoped admin was refused and
    // an unscoped one re-saved the empty tenant. Naming an action the product does not have is worse than
    // saying nothing: the reader goes looking, and the likeliest thing they find is "enrol it again".
    if (!current()) return;
    uiState(host, "empty", unassigned
      ? bl({ en: unassigned + " device(s) are enrolled here but belong to no tenant, so they are not listed. " +
                 "Switch to the tenant they should join (Operate within tenant) and add them by identity — " +
                 "that assigns them. Do not enrol them again; they are already here.",
             ja: unassigned + " 台がテナント未割当のため表示されていません。所属させたいテナントに切り替え（テナント内で操作）、" +
                 "端末IDを指定して追加すると割り当てられます。再登録は不要です（すでに登録されています）。" })
      : bl({ en: "No devices yet. Add one to allow it to connect.", ja: "デバイスがありません。追加すると接続が許可されます。" }));
    return;
  }

  // Fold each device into its runtime STATE once, so the fleet summary and the rows read from the same model.
  const enrich = devices.map((d) => {
    const rt = runtime[d.identity] || runtime[deviceKey(d.identity)] || {};
    // Every join on a device name goes through deviceKey — see ui.js for the two spellings that made this necessary.
    const obs = steerState[deviceKey(d.identity)];
    const sev = riskMap[d.identity]; // the device's OWN overlay mark
    const grpSev = groupRisk[(d.group || "").trim().toLowerCase()] || "";
    // Effective risk is resolved SERVER-SIDE (effective_risk) with the decision path's helper (folds in device-store
    // metadata the Console can't see; never reads LOWER than enforcement). Fall back to max(overlay, floor) if omitted.
    const effSev = (d.effective_risk && d.effective_risk.trim()) || riskMax(sev || "none", grpSev || "none");
    const st = deviceStateOf(d, obs, rt, effSev);
    applyUpdateState(st, updates[d.identity]);
    return { d, rt, obs, sev, grpSev, effSev, st };
  });

  // Fleet summary — the counts an admin actually asks, before the table (and clickable as filters).
  const counts = {
    total: enrich.length,
    steering: enrich.filter((x) => x.st.steering).length,
    failopen: enrich.filter((x) => x.st.failOpen).length,
    excluded: enrich.filter((x) => x.st.excluded > 0).length,
    offline: enrich.filter((x) => x.st.offline).length,
    blocked: enrich.filter((x) => deviceIsBlocked(x.d)).length,
    updPending: enrich.filter((x) => x.st.updateChip === "pending").length,
    updFailed: enrich.filter((x) => x.st.updateChip === "failed" || x.st.updateChip === "refused").length,
    updSilent: enrich.filter((x) => x.st.updateChip === "never_reported").length,
    updNone: enrich.filter((x) => x.st.updateChip === "no_release").length,
  };
  const ff = _devicesState.fleet || "all";
  const q = _devicesState.search.trim().toLowerCase();
  const filtered = enrich.filter(({ d, st }) => {
    if (_devicesState.filter === "enabled" && deviceIsBlocked(d)) return false;
    if (_devicesState.filter === "disabled" && !deviceIsBlocked(d)) return false;
    if (ff === "steering" && !st.steering) return false;
    if (ff === "failopen" && !st.failOpen) return false;
    if (ff === "excluded" && !(st.excluded > 0)) return false;
    if (ff === "offline" && !st.offline) return false;
    if (ff === "blocked" && !deviceIsBlocked(d)) return false;
    if (ff === "updPending" && st.updateChip !== "pending") return false;
    if (ff === "updFailed" && !(st.updateChip === "failed" || st.updateChip === "refused")) return false;
    if (ff === "updSilent" && st.updateChip !== "never_reported") return false;
    if (ff === "updNone" && st.updateChip !== "no_release") return false;
    // agent_version is searchable because "which devices are still on 0.1.0" is the question this column
    // creates, and during a rollout it is the only one anyone asks.
    if (q && !((d.identity || "").toLowerCase().includes(q) || (d.note || "").toLowerCase().includes(q) || (d.group || "").toLowerCase().includes(q) || (d.agent_version || "").toLowerCase().includes(q))) return false;
    return true;
  });

  if (!current()) return;
  host.innerHTML = "";
  const stat = (key, dot, n, label) => el("div", {
    class: "dev-stat" + (ff === key ? " is-active" : ""),
    onClick: () => { _devicesState.fleet = (ff === key ? "all" : key); renderList(host); },
  }, [
    el("span", { class: "dev-dot dev-dot-" + dot }),
    el("div", {}, [el("div", { class: "dev-n", text: String(n) }), el("div", { class: "dev-lbl", text: label })]),
  ]);
  host.appendChild(el("div", { class: "dev-fleet" }, [
    stat("all", "accent", counts.total, bl({ en: "devices", ja: "台" })),
    stat("steering", "ok", counts.steering, bl({ en: "steering", ja: "ステア中" })),
    stat("failopen", "danger", counts.failopen, bl({ en: "fail-open engaged", ja: "fail-open 発動" })),
    stat("excluded", "off", counts.excluded, bl({ en: "excluded apps", ja: "除外アプリ" })),
    stat("offline", "off", counts.offline, bl({ en: "not reporting", ja: "報告なし" })),
    stat("blocked", "danger", counts.blocked, bl({ en: "blocked", ja: "ブロック" })),
  ]));

  // The devices this answer WITHHELD. They belong to no tenant, so they are not in the rows above and no
  // action here reaches them — but they are enrolled, they are consuming a seat, and nobody is looking after
  // them. A count is what makes "withheld" different from "gone".
  if (unassigned > 0) {
    host.appendChild(el("div", { class: "ui-view-desc", style: "margin:4px 0 8px", text:
      bl({ en: "+ " + unassigned + " enrolled device(s) belong to no tenant and are not listed. An operator can assign one by adding it by identity while operating within this tenant.",
           ja: "ほかに " + unassigned + " 台がテナント未割当のため一覧に出ていません。このテナント内で操作中に端末IDを指定して追加すると、割り当てられます。" }) }));
  }

  if (withheldBlocks > 0) {
    host.appendChild(el("div", {class: "ui-view-desc", text: bl({
      en: withheldBlocks + " blocked identity/identities cannot be assigned to an organization and are not included in this list or its counts.",
      ja: "所属組織を確認できない遮断対象が " + withheldBlocks + " 件あります。この一覧と集計には含まれません。"})}));
  }

  // ── The release band. Only when there IS one: a deployment that has published nothing should look like one.
  if (Object.keys(updateOffering).length > 0 || updateFrozen) {
    const offering = Object.keys(updateOffering).sort().map((k) => updateOffering[k]);
    const uniq = offering.filter((v, i) => offering.indexOf(v) === i);
    const band = el("div", { class: "dev-fleet", style: "align-items:center" }, [
      el("div", {}, [
        el("div", { class: "dev-n", text: uniq.join(" / ") || "—" }),
        el("div", { class: "dev-lbl", text: updateFrozen ? bl({ en: "halted", ja: "配布停止中" }) : bl({ en: "being offered", ja: "配布中" }) }),
      ]),
      // ★ COVERAGE BESIDE THE NUMBERS, not in a tooltip. "12 pending" over a fleet where 3 machines have never
      // reported is a different sentence from "12 pending" over one where all of them have.
      updateCoverage ? el("div", { class: "dev-lbl", style: "margin-left:auto;text-align:right" , text:
        bl({ en: "", ja: "" }) + updateCoverage.reported + "/" + updateCoverage.devices +
        bl({ en: " devices have reported an outcome", ja: " 台が更新結果を報告済み" }) +
        (updateCoverage.never_reported ? bl({ en: " · " + updateCoverage.never_reported + " never have", ja: " ・" + updateCoverage.never_reported + " 台は未報告" }) : "") +
        (updateCoverage.unassigned ? bl({ en: " · " + updateCoverage.unassigned + " in no tenant", ja: " ・" + updateCoverage.unassigned + " 台はテナント未割当" }) : "") }) : null,
      // When the telemetry could not be read, say THAT rather than showing a fleet that has gone quiet.
      updateDegraded ? el("div", { class: "dev-lbl", style: "margin-left:auto;text-align:right;color:var(--danger)", text:
        bl({ en: "Update reporting could not be read — the states below are the inventory's, and no coverage is shown",
             ja: "更新結果を読み出せませんでした。以下は在庫情報の値で、カバー率は表示していません" }) }) : null,
    ].filter(Boolean));
    if (updateFrozen) {
      band.appendChild(el("div", { class: "dev-lbl", style: "flex-basis:100%;color:var(--danger)", text:
        bl({ en: "Halted: ", ja: "停止中: " }) + updateFrozen }));
    }
    host.appendChild(band);
  }

  // Update chips, shown only when they have something to say — a quiet fleet keeps the row it has today.
  if (counts.updPending || counts.updFailed || counts.updSilent || counts.updNone) {
    host.appendChild(el("div", { class: "dev-fleet" }, [
      counts.updPending ? stat("updPending", "warn", counts.updPending, bl({ en: "update pending", ja: "更新待ち" })) : null,
      counts.updFailed ? stat("updFailed", "danger", counts.updFailed, bl({ en: "update failed or refused", ja: "失敗・拒否" })) : null,
      counts.updSilent ? stat("updSilent", "off", counts.updSilent, bl({ en: "no update report", ja: "更新の報告なし" })) : null,
      counts.updNone ? stat("updNone", "off", counts.updNone, bl({ en: "no release offered", ja: "配布対象なし" })) : null,
    ].filter(Boolean)));
  }

  if (filtered.length === 0) {
    host.appendChild(el("div", { class: "ui-state ui-state-warn" }, [
      el("span", { text: bl({
        en: "No devices match this filter — " + enrich.length + " are hidden by it, not missing.",
        ja: "この条件に一致するデバイスがありません — " + enrich.length + " 台が絞り込みで非表示です(存在しないわけではありません)。" }) }),
      el("div", { class: "ui-state-actions" },
        el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Show all", ja: "すべて表示" }),
          onClick: () => { _devicesState.fleet = "all"; _devicesState.filter = "all"; renderList(host); } })),
    ]));
    return;
  }

  const rows = filtered.sort((a, b) => (a.d.identity || "").localeCompare(b.d.identity || "")).map(({ d, rt, sev, grpSev, effSev, st }) => {
    const user = (rt.logged_in_users && rt.logged_in_users.length) ? rt.logged_in_users.join(", ") : bl({ en: "no user", ja: "ユーザーなし" });
    // The RUNNING agent version (server-joined as agent_version, from the agent's own heartbeat — the process
    // that reports it is the process that is executing, which is the distinction that matters on a box holding
    // new bytes and running old ones).
    //
    // A version with no recency is a trap: a device that stopped reporting keeps showing its last known
    // version forever, so "it is on 0.1.0" quietly becomes "it said 0.1.0 once" — a different claim that reads
    // identically. When the device is not reporting, the text says so rather than leaving the reader to
    // notice the offline chip elsewhere in the row and connect it themselves.
    const agentVer = (d.agent_version || "").trim();
    // ★ WHERE IT IS GOING, beside where it is. During a rollout "0.2.4" is only half the sentence an operator
    // is reading the row for; the other half is whether this machine is still expected to move.
    const upd = st.update;
    const movingTo = (upd && upd.state === "pending" && upd.target_version && upd.target_version !== agentVer)
      ? " → " + upd.target_version + bl({ en: " pending", ja: " 待ち" }) : "";
    const verText = agentVer
      ? agentVer + movingTo + (st.offline ? bl({ en: " (last reported)", ja: "（最終報告時）" }) : "")
      : bl({ en: "agent version unknown", ja: "エージェント版 不明" });
    const verTitle = d.last_seen_at
      ? bl({ en: "reported " + d.last_seen_at, ja: d.last_seen_at + " に報告" })
      : bl({ en: "this device has never reported a version", ja: "このデバイスはバージョンを報告したことがありません" });
    const meta = el("div", { class: "dev-meta" }, [
      el("span", { text: user }),
      el("span", { style: "color:#6b7382", text: "·" }),
      el("span", { text: rt.os || bl({ en: "unknown OS", ja: "OS 不明" }) }),
      el("span", { style: "color:#6b7382", text: "·" }),
      el("span", { text: verText, title: verTitle }),
      el("span", { class: "dev-grp", text: (d.group || "").trim() || bl({ en: "no group", ja: "グループなし" }) }),
    ]);
    // Where this machine is reaching us from. Shown only when we have it: a device restored from another
    // node's shipped history has no address here, and "—" would read as "it has no address" rather than as
    // "this node has not seen it connect".
    const from = (rt.source_ip || "").trim();
    if (from) {
      meta.appendChild(el("span", { style: "color:#6b7382", text: "·" }));
      meta.appendChild(el("span", { text: bl({ en: "from " + from, ja: from + " から" }) }));
    }
    const primary = !deviceIsBlocked(d)
      ? el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Block", ja: "ブロック" }), onClick: () => disableDevice(d, host) })
      : el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Allow", ja: "許可" }), onClick: () => enableDevice(d, host) });
    primary.setAttribute("data-device-admission-control", "1");
    primary.disabled = !!(host.__deviceAdmissionPending && host.__deviceAdmissionPending.has(d.identity));
    const signals = st.signals.length
      ? st.signals.map((s) => el("span", { class: "dev-chip" + (s.tone ? " dev-chip-" + s.tone : ""), text: s.text, title: s.title || undefined }))
      : [el("span", { class: "dev-risk-ok", text: "—" })];
    return el("tr", { class: st.severity ? "dev-sev-" + st.severity : "", "data-device-identity": d.identity }, [
      el("td", { class: "dev-lead" }, [el("div", { class: "dev-id", text: d.identity || "" }), meta]),
      el("td", {}, [uiBadge(st.pill.text, st.pill.tone), el("div", { class: "dev-sub", text: st.sub })]),
      el("td", {}, deviceCertCell(certMap[deviceKey(d.identity)])),
      el("td", {}, postureFactsCell(st.posture)),
      el("td", {}, el("div", { class: "dev-signals" }, signals)),
      el("td", {}, (!effSev || effSev === "none") ? el("span", { class: "dev-risk-ok", text: bl({ en: "Normal", ja: "通常" }) }) : uiBadge(riskLabel(effSev), riskTone(effSev))),
      el("td", { class: "ui-row-actions", style: "text-align:right" }, el("div", { style: "display:flex;gap:7px;justify-content:flex-end;align-items:center" }, [primary, overflowMenu(d, host, sev, grpSev)])),
    ]);
  });
  host.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [
      el("th", { text: bl({ en: "Device", ja: "デバイス" }) }),
      el("th", { text: bl({ en: "Steering", ja: "ステア状態" }) }),
      el("th", { text: bl({ en: "Certificate", ja: "証明書" }) }),
      el("th", { text: bl({ en: "Reported by device", ja: "端末の報告" }) }),
      el("th", { text: bl({ en: "Signals", ja: "シグナル" }) }),
      el("th", { text: bl({ en: "Risk", ja: "リスク" }) }),
      el("th", { class: "ui-row-actions", text: bl({ en: "Actions", ja: "操作" }) }),
    ])),
    el("tbody", {}, rows),
  ]));
  // ★★ A HIDDEN DEVICE MUST SAY IT IS HIDDEN, AND WHERE THE HIDING CAME FROM (2026-08-13, from an operator who
  // could not find a device that was in the list all along). The fleet chip is kept in memory for the session,
  // so one click three screens ago goes on filtering — and "Showing 1 / 2" at the BOTTOM of the table is not
  // where somebody looking for a missing device is reading. A device that is absent and a device that is
  // filtered are the same picture, which is this product's most expensive shape.
  if (filtered.length < enrich.length) {
    const clear = el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Show all", ja: "すべて表示" }),
      onClick: () => { _devicesState.fleet = "all"; _devicesState.filter = "all"; renderList(host); } });
    host.appendChild(el("div", { class: "ui-state ui-state-warn" }, [
      el("span", { text: bl({
        en: (enrich.length - filtered.length) + " device(s) are hidden by the filter in force, not missing.",
        ja: (enrich.length - filtered.length) + " 台が絞り込みで非表示です(存在しないわけではありません)。" }) }),
      el("div", { class: "ui-state-actions" }, clear),
    ]));
  }
  host.appendChild(el("p", { class: "ui-view-desc", text: bl({ en: "Showing ", ja: "表示 " }) + filtered.length + " / " + devices.length }));
}


// isRemovedByAdministrator recognises the one refusal that has a specific remedy. Matched on the server's own
// wording rather than a status code, because the same 4xx covers "name in use by another tenant" and
// "unassigned", which this must NOT offer to lift.
function isRemovedByAdministrator(msg) {
  const m = String(msg || "").toLowerCase();
  return m.includes("removed by an administrator") || m.includes("allow re-enrolment");
}

// offerReEnrolment asks for the decision by name and, if it is given, makes it — then adds the device.
//
// It is a SEPARATE, NAMED decision on the server (its own route, its own audit action, its own grant number),
// because it is what lets a machine obtain a certificate in a removed device's name. This dialog says that in
// the words an operator can check, and does not bundle it into "add".
async function offerReEnrolment(deviceID, backdrop, done) {
  const ok = await uiConfirm({
    title: bl({ en: "Let this device enrol again?", ja: "この端末の再登録を許可しますか?" }),
    body: bl({
      en: "Enrolment happens once per device. \"" + deviceID + "\" has already enrolled, or was removed, and " +
          "either way an Edge refuses a second enrolment under that name — replacing a certificate is a " +
          "renewal, which proves possession of the one being replaced. Allow this when the machine can no " +
          "longer prove possession: it was re-imaged, or its agent was reinstalled. It lets ANY machine enrol " +
          "under this name with a fresh token, not only the one you have in mind, and it is recorded as its " +
          "own decision.",
      ja: "登録は1端末につき1度です。「" + deviceID + "」は既に登録済みか、削除されています。どちらの場合も " +
          "Edge は同じ名前での2度目の登録を拒みます — 証明書の差し替えは更新であり、差し替える証明書の所持を" +
          "証明する必要があるからです。機械を作り直した、エージェントを入れ直したなど、所持を証明できなく" +
          "なった場合に許可してください。新しいトークンがあれば「どの機械でも」この名前で登録できるようになり、" +
          "この判断は独立した記録として残ります。",
    }),
    confirmLabel: bl({ en: "Allow re-enrolment", ja: "再登録を許可" }), danger: true,
  });
  if (!ok) return;
  const r = await apiFetch("POST", "/admin/enrolled-devices/" + encodeURIComponent(deviceID) + "/allow-reenrolment", {});
  if (!r.ok) {
    uiToast(bl({ en: "Could not allow re-enrolment: ", ja: "再登録の許可に失敗: " }) +
            ((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status)), "err");
    return;
  }
  // Only the removal path needs the device put back; a device that is already listed just needed the grant.
  if (backdrop) {
    const add = await apiFetch("POST", "/admin/enrolled-devices", { identity: deviceID });
    if (!add.ok) {
      uiToast(bl({ en: "Re-enrolment allowed, but the device could not be added: ", ja: "再登録は許可しましたが追加に失敗: " }) +
              ((add.body && (add.body.error || add.body.message)) || ("HTTP " + add.status)), "err");
      return;
    }
    backdrop.remove();
  }
  uiToast(bl({ en: "Re-enrolment allowed. The device can enrol again with a fresh token.",
               ja: "再登録を許可しました。新しいトークンで登録できます。" }), "ok");
  if (done) done();
}

function openEnrollForm(content) {
  const identity = uiField({ name: "identity", label: bl({ en: "Device ID", ja: "デバイス ID" }), required: true,
    placeholder: "finance-laptop-01", hint: bl({ en: "The name on the device's certificate, checked when it connects.", ja: "接続時に照合される、デバイス証明書上の名前。" }),
    validate: (v) => (/\s/.test(v) ? bl({ en: "No spaces allowed.", ja: "空白は使えません。" }) : "") });
  const group = uiField({ name: "group", label: bl({ en: "Device group (optional)", ja: "デバイスグループ(任意)" }),
    placeholder: "finance", hint: bl({ en: "Scope for group-targeted steer-exclusion / captive-tuning policies. Can be changed later.", ja: "グループ対象のステアリング除外・キャプティブ調整ポリシーのスコープ。後から変更できます。" }),
    validate: (v) => (/\s/.test(v) ? bl({ en: "No spaces allowed.", ja: "空白は使えません。" }) : "") });
  const note = uiField({ name: "note", label: bl({ en: "Note (optional)", ja: "メモ(任意)" }), type: "textarea", placeholder: bl({ en: "e.g. Finance laptop, owner …", ja: "例: 経理ノート PC、所有者 …" }) });
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Add device", ja: "デバイスを追加" }) });
  const backdrop = el("div", { class: "ui-modal-backdrop", onClick: (e) => { if (e.target === backdrop) backdrop.remove(); } }, [
    el("div", { class: "ui-modal", role: "dialog" }, [
      el("div", { class: "ui-modal-head", text: bl({ en: "Add a device", ja: "デバイスを追加" }) }),
      el("div", { class: "ui-modal-body" }, [identity.el, group.el, note.el]),
      el("div", { class: "ui-modal-foot" }, [
        el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => backdrop.remove() }),
        submit,
      ]),
    ]),
  ]);
  submit.addEventListener("click", async () => {
    if (!identity.validate() || !group.validate() || !note.validate()) return;
    submit.disabled = true;
    try {
      const r = await apiFetch("POST", "/admin/enrolled-devices", { identity: identity.get(), note: note.get(), group: group.get() });
      if (!r.ok) {
        submit.disabled = false;
        const msg = (r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status);
        // ★★★ THE REMEDY THE SERVER NAMES MUST HAVE A DOOR (2026-08-29, found by walking the install lane on a
        // real Mac). Removing a device writes a tombstone that survives 90 days, deliberately: a removal has to
        // stop a machine that still holds a certificate this deployment issued. The Edge then refuses enrolment
        // with "identity is disabled by an administrator", adding the device back is refused with "allow
        // re-enrolment to lift it" — and NOTHING in this Console could do that. The route existed and had no
        // caller. The name is what is spent, not the token: a token is not bound to a device name (the machine
        // names itself at /enroll), so the approval screen cannot warn, and six freshly approved tokens were
        // spent one after another on a Mac that could never be admitted under its own name again. The only
        // screen that CAN say this is the one an operator reaches by trying to add the device back — here.
        if (isRemovedByAdministrator(msg)) {
          identity.setError(msg);
          offerReEnrolment(identity.get(), backdrop, () => {
            renderDevicesView(_devicesRoot);
          });
          return;
        }
        identity.setError(msg);
        uiToast(bl({ en: "Could not add device: ", ja: "追加に失敗: " }) + msg, "err");
        return;
      }
      backdrop.remove();
      uiToast(bl({ en: "Device added.", ja: "デバイスを追加しました。" }), "ok");
      renderDevicesView(_devicesRoot);
    } catch (e) { submit.disabled = false; uiToast(String(e), "err"); }
  });
  document.body.appendChild(backdrop);
  identity.focus();
}

// openAssignGroupForm — assign/change/clear a device's CP-authoritative group via TAB-SELECT: the admin picks
// from the created groups (the registry) instead of free-typing a name. Tabs = Unassigned + each registry group
// + "+ New" (create then reselect). Empty selection clears the assignment (device → tenant scope). The Edge
// still reads the group from the enrolled ledger (NOT device-reported metadata) to resolve per-group policies.
async function openAssignGroupForm(d, host, preselect) {
  let groups = [];
  try {
    const r = await apiFetch("GET", "/admin/device-groups");
    if (r.ok && r.body && r.body.groups) groups = r.body.groups;
  } catch (e) { /* fall back to just the current assignment */ }
  // preselect (a group NAME) is passed after the inline "+ New" flow so the just-created group is selected.
  let selected = (typeof preselect === "string" ? preselect : (d.group || "")).trim();
  const tabsHost = el("div", { style: "display:flex;flex-wrap:wrap;gap:6px;margin:10px 0" });
  const info = el("p", { class: "ui-view-desc" });
  const renderTabs = () => {
    tabsHost.innerHTML = "";
    const mk = (label, value) => el("button", {
      class: "ui-btn ui-btn-sm" + (selected === value ? " ui-btn-primary" : ""),
      text: label,
      onClick: () => { selected = value; renderTabs(); },
    });
    tabsHost.appendChild(mk(bl({ en: "Unassigned", ja: "未割当" }), ""));
    groups.forEach((g) => tabsHost.appendChild(mk(g.name, g.name)));
    tabsHost.appendChild(el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "+ New", ja: "+ 新規作成" }), onClick: () => {
      backdrop.remove();
      // create, then reopen the assign modal with the new group already selected.
      openCreateGroupForm((createdName) => openAssignGroupForm(d, host, createdName));
    } }));
    const cur = groups.find((g) => g.name === selected);
    info.textContent = selected
      ? (bl({ en: "Selected: ", ja: "選択中: " }) + selected + (cur && cur.description ? " — " + cur.description : ""))
      : bl({ en: "No group (tenant scope).", ja: "グループなし(テナントスコープ)。" });
  };
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Assign", ja: "割当" }) });
  const backdrop = el("div", { class: "ui-modal-backdrop", onClick: (e) => { if (e.target === backdrop) backdrop.remove(); } }, [
    el("div", { class: "ui-modal", role: "dialog" }, [
      el("div", { class: "ui-modal-head", text: bl({ en: "Device group", ja: "デバイスグループ" }) }),
      el("div", { class: "ui-modal-body" }, [
        el("p", { class: "ui-view-desc", text: bl({
          en: "Assign \"" + d.identity + "\" to a group. Pick a created group (or Unassigned to remove it). Group-scoped steer-exclusion / captive-tuning policies then apply to the device.",
          ja: "「" + d.identity + "」をグループに割当てます。作成済みグループを選択(未割当で解除)。このグループ対象の steer 除外・キャプティブ調整ポリシーがデバイスに適用されます。",
        }) }),
        tabsHost, info,
      ]),
      el("div", { class: "ui-modal-foot" }, [
        el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => backdrop.remove() }),
        submit,
      ]),
    ]),
  ]);
  submit.addEventListener("click", async () => {
    submit.disabled = true;
    try {
      const r = await apiFetch("POST", "/admin/enrolled-devices/" + encodeURIComponent(d.identity) + "/group", { group: selected });
      if (!r.ok) {
        submit.disabled = false;
        uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err");
        return;
      }
      backdrop.remove();
      uiToast(selected ? bl({ en: "Group set: " + selected + ".", ja: "グループを設定: " + selected + "。" }) : bl({ en: "Group cleared.", ja: "グループを解除しました。" }), "ok");
      renderList(host);
    } catch (e) { submit.disabled = false; uiToast(String(e), "err"); }
  });
  document.body.appendChild(backdrop);
  renderTabs();
}

// ---- Device groups TAB (registry: list + create + delete) ----------------------------------------------

function renderGroupsTab(content) {
  content.innerHTML = "";
  const listHost = el("div", {});
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "Device groups", ja: "デバイスグループ" }) }),
      el("p", { class: "ui-view-desc", text: bl({
        en: "Named groups you create here become the scope you assign devices and group-targeted policies to. Create a group, then assign devices to it from the Devices tab.",
        ja: "ここで作成した名前付きグループが、デバイスやグループ対象ポリシーの割当先(スコープ)になります。作成後、デバイスタブから割り当てます。",
      }) }),
    ]),
    el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "+ Create group", ja: "+ グループを作成" }), onClick: () => openCreateGroupForm(() => renderGroupsList(listHost)) }),
  ]));
  content.appendChild(el("div", { class: "ui-toolbar" }, [
    el("span", { class: "ui-spacer" }),
    el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Reload", ja: "再読込" }), onClick: () => renderGroupsList(listHost) }),
  ]));
  content.appendChild(listHost);
  renderGroupsList(listHost);
}

async function renderGroupsList(host) {
  uiState(host, "loading");
  const current = freshRender(host);
  let groups;
  try {
    const r = await apiFetch("GET", "/admin/device-groups");
    if (!r.ok) { if (!current()) return; uiState(host, "error", "HTTP " + r.status, { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderGroupsList(host) }); return; }
    groups = (r.body && r.body.groups) || [];
  } catch (e) {
    if (!current()) return;
    uiState(host, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderGroupsList(host) });
    return;
  }
  if (groups.length === 0) { if (!current()) return; uiState(host, "empty", bl({ en: "No groups yet. Create one, then assign devices to it from the Devices tab.", ja: "グループがありません。作成し、デバイスタブから割り当ててください。" })); return; }
  const rows = groups.map((g) => {
    const riskLabel = g.risk === "critical" ? bl({ en: "Critical", ja: "重大" }) : g.risk === "high" ? bl({ en: "High", ja: "高" }) : g.risk === "medium" ? bl({ en: "Medium", ja: "中" }) : bl({ en: "Normal", ja: "通常" });
    const riskTone = (g.risk === "high" || g.risk === "critical") ? "danger" : (g.risk === "medium" ? "warn" : "off");
    return el("tr", {}, [
      el("td", {}, el("code", { text: g.name || "" })),
      el("td", { class: "ui-view-desc", text: g.description || "—" }),
      el("td", {}, uiBadge(riskLabel, riskTone)),
      el("td", { text: String(g.device_count != null ? g.device_count : 0) }),
      el("td", { class: "ui-row-actions" }, el("div", { class: "ui-row-actions" }, [
        el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Edit", ja: "編集" }), onClick: () => openEditGroupForm(g, () => renderGroupsList(host)) }),
        el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Delete", ja: "削除" }), onClick: () => deleteGroup(g, host) }),
      ])),
    ]);
  });
  if (!current()) return;
  host.innerHTML = "";
  host.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [
      el("th", { text: bl({ en: "Group", ja: "グループ名" }) }),
      el("th", { text: bl({ en: "Description", ja: "説明" }) }),
      el("th", { text: bl({ en: "Risk", ja: "リスク" }) }),
      el("th", { text: bl({ en: "Devices", ja: "デバイス数" }) }),
      el("th", { class: "ui-row-actions", text: bl({ en: "Actions", ja: "操作" }) }),
    ])),
    el("tbody", {}, rows),
  ]));
  host.appendChild(el("p", { class: "ui-view-desc", text: bl({ en: "Showing ", ja: "表示 " }) + groups.length + " / " + groups.length }));
}

// openCreateGroupForm — create a first-class group in the registry. onDone() runs after a successful create
// (the caller re-renders its list, or reopens the assign modal for the tab-select flow).
function openCreateGroupForm(onDone) {
  const name = uiField({ name: "name", label: bl({ en: "Group name", ja: "グループ名" }), required: true,
    placeholder: "finance", hint: bl({ en: "Shown as the group's tab when you assign a device.", ja: "デバイス割当時にタブとして表示されます。" }),
    validate: (v) => (/\s/.test(v) ? bl({ en: "No spaces allowed.", ja: "空白は使えません。" }) : "") });
  const desc = uiField({ name: "description", label: bl({ en: "Description (optional)", ja: "説明(任意)" }), type: "textarea", placeholder: bl({ en: "e.g. Finance laptops", ja: "例: 経理ノート PC" }) });
  const risk = uiField({ name: "risk", type: "select", label: bl({ en: "Risk (optional)", ja: "リスク(任意)" }), value: "none", options: [
    { value: "none", label: bl({ en: "Normal", ja: "通常" }) },
    { value: "medium", label: bl({ en: "Medium", ja: "中" }) },
    { value: "high", label: bl({ en: "High", ja: "高" }) },
    { value: "critical", label: bl({ en: "Critical", ja: "重大" }) },
  ] });
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Create group", ja: "グループを作成" }) });
  const backdrop = el("div", { class: "ui-modal-backdrop", onClick: (e) => { if (e.target === backdrop) backdrop.remove(); } }, [
    el("div", { class: "ui-modal", role: "dialog" }, [
      el("div", { class: "ui-modal-head", text: bl({ en: "Create a device group", ja: "デバイスグループを作成" }) }),
      el("div", { class: "ui-modal-body" }, [name.el, desc.el, risk.el]),
      el("div", { class: "ui-modal-foot" }, [
        el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => backdrop.remove() }),
        submit,
      ]),
    ]),
  ]);
  submit.addEventListener("click", async () => {
    if (!name.validate()) return;
    submit.disabled = true;
    try {
      const r = await apiFetch("POST", "/admin/device-groups", { name: name.get(), description: desc.get(), risk: risk.get() === "none" ? "" : risk.get() });
      if (!r.ok) {
        submit.disabled = false;
        const msg = (r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status);
        name.setError(msg);
        uiToast(bl({ en: "Could not create group: ", ja: "作成に失敗: " }) + msg, "err");
        return;
      }
      backdrop.remove();
      uiToast(bl({ en: "Group created.", ja: "グループを作成しました。" }), "ok");
      const createdName = (r.body && r.body.group && r.body.group.name) || name.get();
      if (typeof onDone === "function") onDone(createdName);
    } catch (e) { submit.disabled = false; uiToast(String(e), "err"); }
  });
  document.body.appendChild(backdrop);
  name.focus();
}

// openEditGroupForm — PATCH an existing registry group (rename / description / risk). The id is immutable; a
// rename cascades to member device assignments server-side (the response reports how many). onDone() re-renders
// the list.
function openEditGroupForm(g, onDone) {
  const name = uiField({ name: "name", label: bl({ en: "Group name", ja: "グループ名" }), required: true, value: g.name || "",
    placeholder: "finance", hint: bl({ en: "Renaming re-points every assigned device to the new name.", ja: "名前を変更すると割当済みデバイスも新しい名前に付け替えます。" }),
    validate: (v) => (/\s/.test(v) ? bl({ en: "No spaces allowed.", ja: "空白は使えません。" }) : "") });
  const desc = uiField({ name: "description", label: bl({ en: "Description (optional)", ja: "説明(任意)" }), type: "textarea", value: g.description || "", placeholder: bl({ en: "e.g. Finance laptops", ja: "例: 経理ノート PC" }) });
  const risk = uiField({ name: "risk", type: "select", label: bl({ en: "Risk (optional)", ja: "リスク(任意)" }), value: g.risk || "none", options: [
    { value: "none", label: bl({ en: "Normal", ja: "通常" }) },
    { value: "medium", label: bl({ en: "Medium", ja: "中" }) },
    { value: "high", label: bl({ en: "High", ja: "高" }) },
    { value: "critical", label: bl({ en: "Critical", ja: "重大" }) },
  ] });
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Save changes", ja: "変更を保存" }) });
  const backdrop = el("div", { class: "ui-modal-backdrop", onClick: (e) => { if (e.target === backdrop) backdrop.remove(); } }, [
    el("div", { class: "ui-modal", role: "dialog" }, [
      el("div", { class: "ui-modal-head", text: bl({ en: "Edit device group", ja: "デバイスグループを編集" }) }),
      el("div", { class: "ui-modal-body" }, [name.el, desc.el, risk.el]),
      el("div", { class: "ui-modal-foot" }, [
        el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => backdrop.remove() }),
        submit,
      ]),
    ]),
  ]);
  submit.addEventListener("click", async () => {
    if (!name.validate()) return;
    submit.disabled = true;
    try {
      const r = await apiFetch("PATCH", "/admin/device-groups/" + encodeURIComponent(g.id), { name: name.get(), description: desc.get(), risk: risk.get() === "none" ? "" : risk.get() });
      if (!r.ok) {
        submit.disabled = false;
        const msg = (r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status);
        name.setError(msg);
        uiToast(bl({ en: "Could not save group: ", ja: "保存に失敗: " }) + msg, "err");
        return;
      }
      backdrop.remove();
      const moved = (r.body && r.body.reassigned_devices) || 0;
      uiToast(moved > 0
        ? bl({ en: "Group saved; " + moved + " device(s) re-pointed.", ja: "グループを保存し、" + moved + "台を付け替えました。" })
        : bl({ en: "Group saved.", ja: "グループを保存しました。" }), "ok");
      if (typeof onDone === "function") onDone();
    } catch (e) { submit.disabled = false; uiToast(String(e), "err"); }
  });
  document.body.appendChild(backdrop);
  name.focus();
}

async function deleteGroup(g, host) {
  const ok = await uiConfirm({
    title: bl({ en: "Delete this group?", ja: "このグループを削除しますか?" }),
    body: bl({ en: "Deletes the group \"" + g.name + "\". If devices are still assigned to it, the delete is refused — reassign them from the Devices tab first.", ja: "グループ「" + g.name + "」を削除します。デバイスが割り当たっている場合は削除は拒否されます ―― 先にデバイスタブで再割当してください。" }),
    confirmLabel: bl({ en: "Delete", ja: "削除" }), danger: true,
  });
  if (!ok) return;
  try {
    const r = await apiFetch("DELETE", "/admin/device-groups/" + encodeURIComponent(g.id));
    if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
    uiToast(bl({ en: "Group deleted.", ja: "グループを削除しました。" }), "ok");
    renderGroupsList(host);
  } catch (e) { uiToast(String(e), "err"); }
}

function deviceAdmissionBusy(host, identity, busy) {
  for (const row of host.querySelectorAll("[data-device-identity]")) {
    if (row.getAttribute("data-device-identity") !== identity) continue;
    for (const button of row.querySelectorAll("[data-device-admission-control]")) {
      button.disabled = busy || !!(button.getAttribute("data-device-risk-control") &&
        host.__deviceRiskPending && host.__deviceRiskPending.has(identity));
    }
  }
}

function deviceAdmissionNotice(host, d, enabled, message) {
  const notices = host.__deviceAdmissionNotices || (host.__deviceAdmissionNotices = new Map());
  const previous = notices.get(d.identity);
  if (previous) { previous.remove(); notices.delete(d.identity); }
  if (!message) return;
  const box = el("div", { class: "ui-callout ui-callout-warn", role: "alert", style: "margin-bottom:12px" }, [
    el("strong", { text: d.identity }),
    el("div", { text: message, style: "white-space:pre-wrap" }),
    el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Retry", ja: "再試行" }),
      onClick: () => changeDeviceAdmission(d, host, enabled) }),
  ]);
  (host.__deviceAdmissionMessages || host).appendChild(box);
  notices.set(d.identity, box);
}

async function changeDeviceAdmission(d, host, enabled) {
  const context = d.admissionContext;
  const active = () => host.isConnected !== false && (!context || context.selection === deviceTenantSelection());
  if (!active()) return;
  const path = value => deviceContextPath(value, context && context.tenant);
  const matchesTenant = body => !context || (body && body.tenant_id === context.tenant);
  const pending = host.__deviceAdmissionPending || (host.__deviceAdmissionPending = new Set());
  if (pending.has(d.identity)) return;
  pending.add(d.identity);
  deviceAdmissionBusy(host, d.identity, true);
  let transportDone = false, failure = "", remainingBlock = false;
  try {
    if (!enabled) {
      const ok = await uiConfirm({
        title: bl({ en: "Turn off this device?", ja: "このデバイスをオフにしますか?" }),
        body: bl({ en: "\"" + d.identity + "\" will be blocked from connecting right away, and any active sessions end shortly after. You can turn it back on at any time.", ja: "「" + d.identity + "」はすぐに接続できなくなり、進行中のセッションも間もなく終了します。いつでも再びオンにできます。" }),
        confirmLabel: bl({ en: "Turn off", ja: "オフにする" }), danger: true,
      });
      if (!ok || !active()) return;
    }
    deviceAdmissionNotice(host, d, enabled, "");
    const replyError = r => new Error((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status));
    const identityMatches = value => typeof value === "string" && value.trim().toLowerCase() === d.identity.trim().toLowerCase();
    // Do not change admission after an unconfirmed transport operation. A retry is explicit and repeats
    // the same intended state; it never reverses a possibly applied operation as an automatic rollback.
    const transport = await apiFetch("POST", path("/admin/transport-admission/" + (enabled ? "restore" : "revoke")),
      enabled ? { identity: d.identity } : { identity: d.identity, reason: "blocked from Devices" }, "control");
    if (!active()) return;
    if (!transport.ok) throw replyError(transport);
    if (!transport.body || !matchesTenant(transport.body) || !identityMatches(transport.body.identity) ||
        transport.body[enabled ? "restored" : "revoked"] !== true ||
        (enabled && typeof transport.body.transport_revoked !== "boolean")) {
      throw new Error(bl({ en: "The transport response did not confirm the requested device state.",
        ja: "接続制御の応答から、指定した端末の変更を確認できません。" }));
    }
    transportDone = true;
    if (enabled && transport.body.transport_revoked) {
      remainingBlock = true;
      throw new Error(bl({en: "A connection block still applies to this device. Its inventory admission was not changed. Resolve the remaining block, then reload or retry.",
        ja: "このデバイスには接続の遮断が残っています。一覧の接続許可は変更していません。残る遮断を解消してから、再読込または再試行してください。"}));
    }
    const inventory = await apiFetch("POST", path("/admin/enrolled-devices/" + encodeURIComponent(d.identity) +
      (enabled ? "/enable" : "/disable")), undefined, "control");
    if (!active()) return;
    if (!inventory.ok) throw replyError(inventory);
    const device = inventory.body && inventory.body.device;
    if (!device || !matchesTenant(inventory.body) || !identityMatches(device.identity) || device.enabled !== enabled) {
      throw new Error(bl({ en: "The inventory response did not confirm the requested device state.",
        ja: "デバイス一覧の応答から、指定した端末の変更を確認できません。" }));
    }
  } catch (e) {
    failure = remainingBlock ? String(e.message || e) : (transportDone
      ? bl({ en: "The transport change was acknowledged, but the device admission update could not be confirmed. The operation may be partly applied. Reload the state and retry when the error is resolved.",
          ja: "接続制御の変更は受け付けられましたが、デバイスの接続許可の更新を確認できません。一部だけ反映された可能性があります。状態を再読込し、エラー解消後に再試行してください。" })
      : bl({ en: "The transport change could not be confirmed, so the device admission update was not sent. The transport may already have changed. Reload the state and retry when the error is resolved.",
          ja: "接続制御の変更を確認できないため、デバイスの接続許可の更新は送信していません。接続制御だけ変更済みの可能性があります。状態を再読込し、エラー解消後に再試行してください。" })) + "\n" + String(e);
  } finally {
    pending.delete(d.identity);
    deviceAdmissionBusy(host, d.identity, false);
  }
  if (!active()) return;
  if (failure) deviceAdmissionNotice(host, d, enabled, failure);
  else uiToast((enabled ? bl({ en: "Device allowed: ", ja: "デバイスを許可しました: " })
    : bl({ en: "Device blocked: ", ja: "デバイスを遮断しました: " })) + d.identity, "ok");
  // A refresh failure must not turn an acknowledged write into a failed mutation or discard its warning.
  try { await renderList(host); } catch (e) { uiToast(String(e), "err"); }
}

async function disableDevice(d, host) { return changeDeviceAdmission(d, host, false); }
async function enableDevice(d, host) { return changeDeviceAdmission(d, host, true); }

// setDeviceRisk marks / clears a device's risk from its own row (no free-text id) — replaces the Device Risk
// page. "high" marks high-risk (a risk-gated policy then bites, e.g. re-auth); "none" clears it.
function deviceRiskBusy(host, identity, busy) {
  for (const row of host.querySelectorAll("[data-device-identity]")) {
    if (row.getAttribute("data-device-identity") !== identity) continue;
    for (const button of row.querySelectorAll("[data-device-risk-control]")) {
      button.disabled = busy || !!(host.__deviceAdmissionPending && host.__deviceAdmissionPending.has(identity));
    }
  }
}

function deviceRiskNotice(host, d, severity, message) {
  const notices = host.__deviceRiskNotices || (host.__deviceRiskNotices = new Map());
  const previous = notices.get(d.identity);
  if (previous) { previous.remove(); notices.delete(d.identity); }
  if (!message) return;
  const box = el("div", { class: "ui-callout ui-callout-warn", role: "alert", style: "margin-bottom:12px" }, [
    el("strong", { text: d.identity }),
    el("div", { text: message, style: "white-space:pre-wrap" }),
    el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Retry", ja: "再試行" }),
      onClick: () => setDeviceRisk(d, severity, host) }),
  ]);
  (host.__deviceAdmissionMessages || host).appendChild(box);
  notices.set(d.identity, box);
}

async function setDeviceRisk(d, severity, host) {
  const pending = host.__deviceRiskPending || (host.__deviceRiskPending = new Set());
  if (pending.has(d.identity)) return;
  pending.add(d.identity);
  deviceRiskBusy(host, d.identity, true);
  deviceRiskNotice(host, d, severity, "");
  let notice = "";
  try {
    const r = await apiFetch("POST", "/admin/risk-signals", {
      entity_type: "device", entity_id: d.identity, severity, evidence_ref: "console",
    }, "control");
    if (!r.ok) throw new Error((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status));
    const b = r.body;
    if (!b || b.entity_type !== "device" || typeof b.entity_id !== "string" ||
        b.entity_id.trim().toLowerCase() !== d.identity.trim().toLowerCase() || b.severity !== severity ||
        b.applied !== true || b.high_risk !== (severity === "high" || severity === "critical") ||
        (b.not_stored_durably !== undefined && typeof b.not_stored_durably !== "string")) {
      throw new Error(bl({ en: "The response did not confirm the requested device risk.",
        ja: "応答から、指定した端末のリスク変更を確認できません。" }));
    }
    if (b.not_stored_durably && b.not_stored_durably.trim()) {
      notice = bl({ en: "Risk applied, but saving was not confirmed. Retry once the store is healthy.",
        ja: "リスクは反映されましたが、保存を確認できません。保存先の復旧後に再試行してください。" }) + "\n" + b.not_stored_durably;
    }
  } catch (e) {
    notice = bl({ en: "The risk change could not be confirmed. It may already be applied. Reload the state and retry when the error is resolved.",
      ja: "リスク変更を確認できません。反映済みの可能性があります。状態を再読込し、エラー解消後に再試行してください。" }) + "\n" + String(e);
  } finally {
    pending.delete(d.identity);
    deviceRiskBusy(host, d.identity, false);
  }
  if (notice) deviceRiskNotice(host, d, severity, notice);
  else uiToast(severity === "none" ? bl({ en: "Risk cleared.", ja: "リスクを解除しました。" })
    : bl({ en: "Risk set: " + severity + ".", ja: "リスクを設定: " + severity + "。" }), "ok");
  try { await renderList(host); } catch (e) { uiToast(String(e), "err"); }
}

async function removeDevice(d, host) {
  const ok = await uiConfirm({
    title: bl({ en: "Remove this device?", ja: "この端末を削除しますか?" }),
    // ★ IT USED TO SAY "you would have to add the device again", AND THAT DOES NOT WORK. The removal leaves a
    // tombstone that adding is refused against; only an explicit re-enrolment grant lifts it. A dialog that
    // names the wrong remedy is worse than one that names none — it sends the operator down a path the server
    // will refuse, which is how six unusable enrolment tokens got minted for one Mac.
    body: bl({
      en: "Removes \"" + d.identity + "\" and keeps the removal in force on every Edge, so a machine still " +
          "holding this deployment's certificate for that name cannot come back. Adding the device again will " +
          "be refused until an administrator explicitly allows re-enrolment.",
      ja: "「" + d.identity + "」を削除し、その削除を全 Edge で有効なまま保ちます(その名前の証明書をまだ持つ" +
          "機械が戻れないようにするため)。管理者が明示的に再登録を許可するまで、再追加は拒否されます。",
    }),
    confirmLabel: bl({ en: "Remove permanently", ja: "完全に削除" }), danger: true,
  });
  if (!ok) return;
  await act("DELETE", "/admin/enrolled-devices/" + encodeURIComponent(d.identity), host, bl({ en: "Device removed.", ja: "端末を削除しました。" }));
}

async function act(method, path, host, successMsg) {
  try {
    // Plane is not passed: apiFetch routes CP-authored writes to the control plane from one table (app.js).
    const r = await apiFetch(method, path);
    if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
    uiToast(successMsg, "ok");
    renderList(host);
  } catch (e) { uiToast(String(e), "err"); }
}

function fmtTime(s) {
  if (!s) return "—";
  try { return window.dsseFormatTime(s); } catch (e) { return s; }
}

function postureMark(v) { return v === true ? "✓" : (v === false ? "✗" : "—"); }

// Risk severity ordering for the union-model group floor: none < medium < high < critical.
function riskRank(sev) { return ({ medium: 1, high: 2, critical: 3 })[(sev || "").trim().toLowerCase()] || 0; }
function riskMax(a, b) { return riskRank(a) >= riskRank(b) ? (a || "none") : (b || "none"); }


// postureFacts turns a device's reported posture into a fixed list of rows — one per axis, ALWAYS present.
// A missing reading reads "not reported", never blank, because "we did not measure this" and "this is fine"
// must not look the same.
function postureFacts(p) {
  p = p || {};
  const yes = bl({ en: "on", ja: "オン" });
  const no = bl({ en: "off", ja: "オフ" });
  const unknown = bl({ en: "not reported", ja: "未報告" });
  const row = (label, v) => ({
    label,
    text: v === true ? yes : v === false ? no : unknown,
    tone: v === true ? "ok" : v === false ? "warn" : "off",
  });
  // Only the axes THIS channel carries. enforcement_agent_healthy is deliberately absent: the Windows agent
  // does report it, but on the heartbeat, not in the device-runtime posture this view reads — printing "not
  // reported" for a signal the device is in fact sending would be exactly the wrong-signal problem this
  // column exists to end. The Steering column already answers "is the agent working".
  return [
    row(bl({ en: "Disk encryption", ja: "ディスク暗号化" }), p.disk_encryption_enabled),
    row(bl({ en: "Firewall", ja: "ファイアウォール" }), p.firewall_enabled),
  ];
}

// postureFactsCell renders those rows compactly for the device row.
function postureFactsCell(facts) {
  return el("div", { class: "dev-posture" }, (facts || []).map((f) =>
    el("span", { class: "dev-posture-item", title: f.label }, [
      el("span", { class: "ui-view-desc", text: f.label + ": " }),
      uiBadge(f.text, f.tone),
    ])));
}
