"use strict";

// incoming.js — "Incoming Connections" on the shared ui.js pattern: block servers from starting connections to
// devices by default, with reviewed exceptions. Replaces the raw-JSON serverinit card.
// Backend: POST /admin/server-initiated {enabled}; GET /admin/legacy-exceptions {exceptions};
// POST /admin/legacy-exceptions {…}; GET /admin/legacy-exceptions/export.

async function renderIncomingView(content) {
  uiState(content, "loading");
  const current = freshRender(content);
  let blocked;
  try {
    blocked = incomingDefaultBody(await apiFetch("GET", "/admin/server-initiated"));
  } catch (e) {
    if (!current()) return;
    uiState(content, "error", bl({ en: "The incoming default could not be verified. Retry before changing this policy.", ja: "受信接続の既定動作を確認できません。設定を変更する前に再試行してください。" }),
      { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderIncomingView(content) });
    return;
  }
  if (!current()) return;
  content.innerHTML = "";
  const canWrite = incomingCanWrite();
  const addButton = canWrite ? el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "+ Add exception", ja: "+ 例外を追加" }), onClick: () => openExceptionForm(content) }) : null;
  if (addButton) addButton.disabled = true;
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("div", { style: "display:flex;align-items:center;gap:8px" }, [
        el("h2", { class: "ui-view-title", text: bl({ en: "Incoming Connections (server-initiated)", ja: "受信接続(サーバ発)" }) }),
        uiBadge(bl({ en: "Windows Defender Firewall", ja: "Windows Defender ファイアウォール" }), "warn"),
      ]),
      el("p", { class: "ui-view-desc", text: bl({ en: "Controls connections a SERVER starts INTO a device — the reverse of normal client-initiated traffic, which the client-side steering never sees. Blocks them by default, except reviewed exceptions. Enforced on WINDOWS ONLY, as standard Windows Defender Firewall inbound rules (visible and auditable in wf.msc); macOS receivers are out of scope. Distinct from Connector Access, which authorizes the connections a device makes OUT to internal resources.", ja: "サーバが起点でデバイスに張ってくる接続を制御します(通常のクライアント発とは逆向きで、クライアント側のステアリングでは見えない経路)。既定でブロック、レビュー済み例外は許可。強制は Windows のみで、標準の Windows Defender ファイアウォールの受信ルールとして適用されます(wf.msc で確認・監査可能)。macOS 受信側は対象外。デバイスが内部リソースへ出ていく接続を認可する「コネクタ経由アクセス」とは別物です。" }) }),
    ]),
    ...(addButton ? [addButton] : []),
  ]));
  // Show the LIVE default (readable via GET) so it is unambiguous which is in effect, then offer to switch.
  content.appendChild(el("div", { class: "ui-toolbar" }, [
    el("span", { class: "ui-view-desc", text: bl({ en: "Default for incoming connections:", ja: "受信接続の既定:" }) }),
    uiBadge(blocked ? bl({ en: "Currently: Block by default", ja: "現在: 既定でブロック" }) : bl({ en: "Currently: Allow by default", ja: "現在: 既定で許可" }), blocked ? "ok" : "warn"),
    ...(canWrite ? [el("button", { class: "ui-btn ui-btn-sm", text: blocked ? bl({ en: "Switch to allow by default", ja: "既定で許可に切替" }) : bl({ en: "Switch to block by default", ja: "既定でブロックに切替" }), onClick: () => { if (current()) setIncoming(!blocked, content); } })] : []),
  ]));
  // Applied automatically — no manual export step. The Windows agent on each endpoint fetches this policy and
  // reconciles it into standard Windows Defender Firewall inbound rules (group "DSSE Server-Initiated",
  // visible in wf.msc). macOS inbound is out of scope.
  content.appendChild(el("p", { class: "ui-field-hint", text: bl({
    en: "This policy is applied automatically: each Windows endpoint's agent fetches it and reconciles it into standard Windows Defender Firewall inbound rules (group \"DSSE Server-Initiated\", visible in wf.msc). Windows already denies unsolicited inbound by default; the exceptions below open or close on top of that. No manual export/apply. (macOS inbound is out of scope.)",
    ja: "このポリシーは自動適用されます: 各 Windows 端末のエージェントがこれを取得し、標準の Windows Defender ファイアウォールの受信ルール(グループ「DSSE Server-Initiated」、wf.msc で確認可能)として反映します。Windows は元々未承諾の受信を既定拒否するため、下記の例外がその上で開閉します。手動の書き出し/適用は不要。(macOS の受信は対象外)",
  }) }));
  const host = el("div", {});
  content.appendChild(host);
  loadExceptions(host, content, addButton);
}

function incomingCanWrite() {
  const permissions = typeof idpSession === "undefined" ? null : idpSession?.permissions;
  return Array.isArray(permissions) && (permissions.includes("admin.serverinitiated.write") || permissions.includes("*"));
}

function incomingDefaultBody(response) {
  if (!response?.ok || response.status !== 200 || typeof response.body?.server_initiated_enabled !== "boolean") {
    throw new Error("Incoming default unavailable");
  }
  return response.body.server_initiated_enabled;
}

async function setIncoming(enabled, content) {
  const ok = await uiConfirm({
    title: enabled ? bl({ en: "Block incoming by default?", ja: "受信を既定でブロック?" }) : bl({ en: "Allow incoming by default?", ja: "受信を既定で許可?" }),
    body: enabled ? bl({ en: "Servers will not be able to start connections to devices unless an exception allows it.", ja: "例外で許可しない限り、サーバはデバイスへ接続を開始できなくなります。" }) : bl({ en: "Servers will be able to start connections to devices (enforcement off).", ja: "サーバはデバイスへ接続を開始できます(強制オフ)。" }),
    confirmLabel: enabled ? bl({ en: "Block by default", ja: "既定でブロック" }) : bl({ en: "Allow by default", ja: "既定で許可" }), danger: enabled,
  });
  if (!ok) return;
  const r = await apiFetch("POST", "/admin/server-initiated", { enabled });
  if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
  uiToast(enabled ? bl({ en: "Incoming blocked by default.", ja: "受信を既定でブロックにしました。" }) : bl({ en: "Incoming allowed by default.", ja: "受信を既定で許可にしました。" }), "ok");
  if (content) renderIncomingView(content);
}

function incomingExceptionListBody(response) {
  const body = response?.body;
  if (!response?.ok || response.status !== 200 || body?.schema_version !== "admin_legacy_exceptions.v1" || !Array.isArray(body.exceptions)) {
    throw new Error("Incoming exceptions unavailable");
  }
  const textFields = ["id", "tenant_id", "business_owner", "expires_at", "source_server", "device_group", "service_family", "protocol", "mode", "status"];
  if (!body.exceptions.every((x) => x && typeof x === "object" && !Array.isArray(x) &&
      textFields.every((key) => typeof x[key] === "string") && x.id.trim() &&
      Number.isInteger(x.port) && x.port >= 0 && x.port <= 65535 &&
      Number.isInteger(x.max_session_seconds) && x.max_session_seconds >= 0 && Number.isFinite(Date.parse(x.expires_at)) &&
      typeof x.approval_required === "boolean" &&
      ["active", "disabled"].includes(x.status) && ["", "allow", "deny", "warn", "observe"].includes(x.mode))) {
    throw new Error("Incoming exceptions unavailable");
  }
  return body.exceptions;
}

async function loadExceptions(host, content, addButton) {
  const canWrite = !!addButton;
  if (addButton) addButton.disabled = true;
  uiState(host, "loading");
  const current = freshRender(host);
  let exc;
  try { exc = incomingExceptionListBody(await apiFetch("GET", "/admin/legacy-exceptions")); }
  catch (e) { if (!current()) return; uiState(host, "error", bl({ en: "The exceptions could not be verified. Retry before adding or changing one.", ja: "例外を確認できません。追加・変更する前に再試行してください。" }), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => loadExceptions(host, content, addButton) }); return; }
  if (!current()) return;
  if (!exc.length) { if (addButton) addButton.disabled = false; uiState(host, "empty", bl({ en: "No exceptions. With \"block by default\" on, no server can start a connection to a device.", ja: "例外なし。「既定でブロック」時、どのサーバもデバイスへ接続を開始できません。" })); return; }
  const rows = exc.map((x) => el("tr", {}, [
    el("td", {}, el("code", { text: x.source_server || x.id || "" })),
    el("td", { text: x.device_group || "—" }),
    el("td", {}, uiBadge([x.service_family, x.protocol, x.port || ""].filter(Boolean).join(" / ") || bl({ en: "Any service", ja: "全サービス" }), "off")),
    el("td", { text: x.business_owner || "—" }),
    el("td", { class: "ui-view-desc", text: x.expires_at ? window.dsseFormatTime(x.expires_at, { hour: undefined, minute: undefined, second: undefined, timeZoneName: undefined }) : "—" }),
    el("td", {}, [uiBadge(x.mode === "deny" ? bl({ en: "Block", ja: "ブロック" }) : (x.mode === "warn" || x.mode === "observe" ? x.mode : bl({ en: "Allow", ja: "許可" })), x.mode === "deny" ? "danger" : "ok"), x.status === "disabled" ? uiBadge(bl({ en: "Disabled", ja: "無効" }), "off") : null]),
    ...(canWrite ? [el("td", { class: "ui-row-actions" }, [
      el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Edit", ja: "編集" }), onClick: () => openExceptionForm(content, x) }),
      el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Delete", ja: "削除" }), onClick: () => deleteException(x.id, content) }),
    ])] : []),
  ]));
  if (!current()) return;
  host.innerHTML = "";
  host.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [bl({ en: "Server", ja: "サーバ" }), bl({ en: "To device group", ja: "対象グループ" }), bl({ en: "Service", ja: "サービス" }), bl({ en: "Owner", ja: "責任者" }), bl({ en: "Expires", ja: "期限" }), bl({ en: "Action", ja: "動作" }), ...(canWrite ? [bl({ en: "Manage", ja: "操作" })] : [])].map((x) => el("th", { text: x })))),
    el("tbody", {}, rows),
  ]));
  if (addButton) addButton.disabled = false;
}

async function deleteException(id, content) {
  const ok = await uiConfirm({ title: bl({ en: "Delete this exception?", ja: "この例外を削除しますか?" }), body: id, confirmLabel: bl({ en: "Delete", ja: "削除" }), danger: true });
  if (!ok) return;
  const r = await apiFetch("DELETE", "/admin/legacy-exceptions/" + encodeURIComponent(id));
  if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
  uiToast(bl({ en: "Exception deleted.", ja: "例外を削除しました。" }), "ok");
  renderIncomingView(content);
}

async function openExceptionForm(content, existing) {
  existing = existing || null;
  // Reuse the SAME asset catalog as the Egress / Connector Access rule editors so Source / Destination / Service
  // are SELECTED, not hand-typed. Values map to the Legacy-Exception fields (source_server = endpoint address,
  // device_group = group alias, protocol + port = selected catalog TCP port).
  let idx;
  try { idx = await catalogIndex(); } catch (e) {
    uiToast(bl({ en: "The asset catalog could not be read. Retry opening the editor after it recovers.", ja: "資産カタログを取得できません。復旧後に編集を開き直してください。" }), "err");
    return;
  }
  const curTag = bl({ en: " (current)", ja: "(現在値)" });

  const idF = uiField({ name: "id", label: bl({ en: "Exception ID", ja: "例外 ID" }), required: true, value: existing ? (existing.id || "") : "", placeholder: "ex-1" });
  if (existing) idF.el.querySelector("input").setAttribute("readonly", "true");

  // Source (server): catalog endpoints that have a network address. Value = the address (what enforcement matches).
  const srcOpts = [{ value: "", label: bl({ en: "Select a server…", ja: "サーバを選択…" }) }]
    .concat((idx.endpoints || []).filter((e) => e.address).map((e) => ({ value: e.address, label: e.alias + " (" + e.address + ")" })));
  if (existing && existing.source_server && !srcOpts.some((o) => o.value === existing.source_server)) {
    srcOpts.push({ value: existing.source_server, label: existing.source_server + curTag });
  }
  const srcF = uiField({ name: "src", label: bl({ en: "Source (server)", ja: "送信元(サーバ)" }), type: "select", value: existing ? (existing.source_server || "") : "", options: srcOpts, hint: bl({ en: "The server allowed to start the connection (from the asset catalog).", ja: "接続を開始してよいサーバ(資産カタログから)。" }) });

  // Destination (device group): catalog groups. Value = the group alias (what device_group matches).
  const grpOpts = [{ value: "", label: bl({ en: "Any device group", ja: "全デバイスグループ" }) }]
    .concat((idx.groups || []).map((g) => ({ value: g.alias, label: g.alias })));
  if (existing && existing.device_group && !grpOpts.some((o) => o.value === existing.device_group)) {
    grpOpts.push({ value: existing.device_group, label: existing.device_group + curTag });
  }
  const grpF = uiField({ name: "grp", label: bl({ en: "Destination (device group)", ja: "宛先(デバイスグループ)" }), type: "select", value: existing ? (existing.device_group || "") : "", options: grpOpts });

  // The current Windows export supports TCP. One exception represents one port;
  // never silently take ports[0] or turn a display name into a protocol family.
  const serviceChoices = incomingServiceChoices(idx.services || []);
  const svcOpts = [{ value: "", label: bl({ en: "Any service", ja: "全サービス" }) }]
    .concat(serviceChoices.map((x) => ({ value: x.value, label: x.label })));
  const hasCurrent = existing && (existing.service_family || existing.protocol || existing.port);
  if (hasCurrent) svcOpts.push({ value: "__raw__", label: bl({ en: "Keep current condition: ", ja: "現在の条件を保持: " }) + [existing.service_family, existing.protocol, existing.port || ""].filter(Boolean).join(" / ") });
  const svcF = uiField({ name: "svc", label: bl({ en: "Service", ja: "Service" }), type: "select", value: hasCurrent ? "__raw__" : "", options: svcOpts,
    hint: bl({ en: "Each selection is one TCP port. UDP services are not supported by the current Windows export. Choose Any only to remove the service restriction.", ja: "1つの選択はTCPの1ポートです。現行のWindows配布はUDPサービスに対応していません。サービス制限を外す場合だけ「全サービス」を選んでください。" }) });

  const ownerF = uiField({ name: "owner", label: bl({ en: "Business owner", ja: "業務責任者" }), value: existing ? (existing.business_owner || "") : "", placeholder: "secops" });
  const expF = uiField({ name: "exp", label: bl({ en: "Expires", ja: "期限" }), type: "date", value: existing && existing.expires_at ? String(existing.expires_at).slice(0, 10) : "" });
  const modeF = uiField({ name: "mode", label: bl({ en: "Action", ja: "動作" }), type: "select", value: existing ? (existing.mode || "allow") : "allow", options: [{ value: "allow", label: bl({ en: "Allow", ja: "許可" }) }, { value: "deny", label: bl({ en: "Block", ja: "ブロック" }) }].concat(existing && ["warn", "observe"].includes(existing.mode) ? [{ value: existing.mode, label: existing.mode + curTag }] : []) });
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: existing ? bl({ en: "Save", ja: "保存" }) : bl({ en: "Add exception", ja: "例外を追加" }) });
  const m = uiModal({ title: existing ? bl({ en: "Edit an incoming-connection exception", ja: "受信接続の例外を編集" }) : bl({ en: "Add an incoming-connection exception", ja: "受信接続の例外を追加" }), body: [idF.el, srcF.el, grpF.el, svcF.el, ownerF.el, expF.el, modeF.el], footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit] });
  submit.addEventListener("click", async () => {
    if (!idF.validate()) return;
    if (!srcF.get()) { uiToast(bl({ en: "Pick a source server.", ja: "送信元のサーバを選択してください。" }), "err"); return; }
    let payload;
    try {
      payload = incomingExceptionPayload(existing, { id: idF.get(), source_server: srcF.get(), device_group: grpF.get(), business_owner: ownerF.get(), mode: modeF.get() }, svcF.get(), serviceChoices, expF.get());
    } catch (e) { uiToast(String(e), "err"); return; }

    submit.disabled = true;
    try {
      const r = await apiFetch("POST", "/admin/legacy-exceptions", payload);
      if (!r.ok) { submit.disabled = false; uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
      m.close(); uiToast(existing ? bl({ en: "Exception saved.", ja: "例外を保存しました。" }) : bl({ en: "Exception added.", ja: "例外を追加しました。" }), "ok"); renderIncomingView(content);
    } catch (e) { submit.disabled = false; uiToast(String(e), "err"); }
  });
  idF.focus();
}

// Keep non-editor fields and exact expiry instants when an unrelated field changes.
function incomingServiceChoices(services) {
  return services.flatMap((s) => (s.ports || []).filter((p) => String(p.protocol).toLowerCase() === "tcp" && Number.isInteger(p.port) && p.port > 0 && p.port <= 65535)
    .map((p, i, pairs) => ({ value: pairs.length === 1 ? s.id : JSON.stringify([s.id, "tcp", p.port]), label: s.alias + " (tcp/" + p.port + ")", protocol: "tcp", port: p.port })));
}
function incomingExceptionPayload(existing, fields, service, choices, expiryDate) {
  const payload = { ...fields };
  for (const key of ["status", "max_session_seconds", "approval_required"]) {
    if (existing && Object.hasOwn(existing, key)) payload[key] = existing[key];
  }
  if (service === "__raw__" && existing) {
    payload.service_family = existing.service_family || "";
    payload.protocol = existing.protocol || "";
    payload.port = existing.port || 0;
  } else if (service) {
    const choice = choices.find((x) => x.value === service);
    if (!choice) throw new Error(bl({ en: "Service is unavailable. Reload before saving.", ja: "サービスを取得できません。再読込してから保存してください。" }));
    payload.service_family = "";
    payload.protocol = choice.protocol;
    payload.port = choice.port;
  } else {
    payload.service_family = ""; payload.protocol = ""; payload.port = 0;
  }
  if (expiryDate) payload.expires_at = existing && expiryDate === String(existing.expires_at || "").slice(0, 10) ? existing.expires_at : new Date(expiryDate).toISOString();
  return payload;
}
