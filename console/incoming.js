"use strict";

// incoming.js — "Incoming Connections" on the shared ui.js pattern: block servers from starting connections to
// devices by default, with reviewed exceptions. Replaces the raw-JSON serverinit card.
// Backend: POST /admin/server-initiated {enabled}; GET /admin/legacy-exceptions {exceptions};
// POST /admin/legacy-exceptions {…}; GET /admin/legacy-exceptions/export.

async function renderIncomingView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("div", { style: "display:flex;align-items:center;gap:8px" }, [
        el("h2", { class: "ui-view-title", text: bl({ en: "Incoming Connections (server-initiated)", ja: "受信接続(サーバ発)" }) }),
        uiBadge(bl({ en: "Windows Defender Firewall", ja: "Windows Defender ファイアウォール" }), "warn"),
      ]),
      el("p", { class: "ui-view-desc", text: bl({ en: "Controls connections a SERVER starts INTO a device — the reverse of normal client-initiated traffic, which the client-side steering never sees. Blocks them by default, except reviewed exceptions. Enforced on WINDOWS ONLY, as standard Windows Defender Firewall inbound rules (visible and auditable in wf.msc); macOS receivers are out of scope. Distinct from Connector Access, which authorizes the connections a device makes OUT to internal resources.", ja: "サーバが起点でデバイスに張ってくる接続を制御します(通常のクライアント発とは逆向きで、クライアント側のステアリングでは見えない経路)。既定でブロック、レビュー済み例外は許可。強制は Windows のみで、標準の Windows Defender ファイアウォールの受信ルールとして適用されます(wf.msc で確認・監査可能)。macOS 受信側は対象外。デバイスが内部リソースへ出ていく接続を認可する「コネクタ経由アクセス」とは別物です。" }) }),
    ]),
    el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "+ Add exception", ja: "+ 例外を追加" }), onClick: () => openExceptionForm(content) }),
  ]));
  // Show the LIVE default (readable via GET) so it is unambiguous which is in effect, then offer to switch.
  let blocked = false;
  try { const r = await apiFetch("GET", "/admin/server-initiated"); if (r.ok && r.body) blocked = !!r.body.server_initiated_enabled; } catch (e) { /* fall back to unknown=allow */ }
  content.appendChild(el("div", { class: "ui-toolbar" }, [
    el("span", { class: "ui-view-desc", text: bl({ en: "Default for incoming connections:", ja: "受信接続の既定:" }) }),
    uiBadge(blocked ? bl({ en: "Currently: Block by default", ja: "現在: 既定でブロック" }) : bl({ en: "Currently: Allow by default", ja: "現在: 既定で許可" }), blocked ? "ok" : "warn"),
    el("button", { class: "ui-btn ui-btn-sm", text: blocked ? bl({ en: "Switch to allow by default", ja: "既定で許可に切替" }) : bl({ en: "Switch to block by default", ja: "既定でブロックに切替" }), onClick: () => setIncoming(!blocked, content) }),
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
  loadExceptions(host, content);
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

async function loadExceptions(host, content) {
  uiState(host, "loading");
  const current = freshRender(host);
  let exc;
  try { const r = await apiFetch("GET", "/admin/legacy-exceptions"); if (!r.ok) throw new Error("HTTP " + r.status); exc = (r.body && r.body.exceptions) || []; }
  catch (e) { if (!current()) return; uiState(host, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => loadExceptions(host, content) }); return; }
  if (!exc.length) { if (!current()) return; uiState(host, "empty", bl({ en: "No exceptions. With \"block by default\" on, no server can start a connection to a device.", ja: "例外なし。「既定でブロック」時、どのサーバもデバイスへ接続を開始できません。" })); return; }
  const rows = exc.map((x) => el("tr", {}, [
    el("td", {}, el("code", { text: x.source_server || x.id || "" })),
    el("td", { text: x.device_group || "—" }),
    el("td", {}, uiBadge(x.service_family || "—", "off")),
    el("td", { text: x.business_owner || "—" }),
    el("td", { class: "ui-view-desc", text: x.expires_at ? window.dsseFormatTime(x.expires_at, { hour: undefined, minute: undefined, second: undefined, timeZoneName: undefined }) : "—" }),
    el("td", {}, uiBadge(x.mode === "deny" ? bl({ en: "Block", ja: "ブロック" }) : bl({ en: "Allow", ja: "許可" }), x.mode === "deny" ? "danger" : "ok")),
    el("td", { class: "ui-row-actions" }, [
      el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Edit", ja: "編集" }), onClick: () => openExceptionForm(content, x) }),
      el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Delete", ja: "削除" }), onClick: () => deleteException(x.id, content) }),
    ]),
  ]));
  if (!current()) return;
  host.innerHTML = "";
  host.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [bl({ en: "Server", ja: "サーバ" }), bl({ en: "To device group", ja: "対象グループ" }), bl({ en: "Service", ja: "サービス" }), bl({ en: "Owner", ja: "責任者" }), bl({ en: "Expires", ja: "期限" }), bl({ en: "Action", ja: "動作" }), bl({ en: "Manage", ja: "操作" })].map((x) => el("th", { text: x })))),
    el("tbody", {}, rows),
  ]));
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
  // device_group = group alias, service_family + port = catalog service) — backend unchanged.
  let idx;
  try { idx = await catalogIndex(); } catch (e) { idx = { endpoints: [], groups: [], services: [] }; }
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

  // Service: catalog services. Value = service id (resolved to service_family + port on save).
  let svcInitial = "";
  const svcMatch = existing && existing.service_family ? (idx.services || []).find((s) => (s.alias || "").toLowerCase() === String(existing.service_family).toLowerCase()) : null;
  if (svcMatch) svcInitial = svcMatch.id;
  const svcOpts = [{ value: "", label: bl({ en: "Any / select a service…", ja: "指定なし / サービスを選択…" }) }]
    .concat((idx.services || []).map((s) => ({ value: s.id, label: s.alias + " (" + (s.ports || []).map((p) => p.protocol + "/" + p.port).join(",") + ")" })));
  if (existing && existing.service_family && !svcMatch) {
    svcOpts.push({ value: "__raw__", label: existing.service_family + curTag });
    svcInitial = "__raw__";
  }
  const svcF = uiField({ name: "svc", label: bl({ en: "Service", ja: "Service" }), type: "select", value: svcInitial, options: svcOpts });

  const ownerF = uiField({ name: "owner", label: bl({ en: "Business owner", ja: "業務責任者" }), value: existing ? (existing.business_owner || "") : "", placeholder: "secops" });
  const expF = uiField({ name: "exp", label: bl({ en: "Expires", ja: "期限" }), type: "date", value: existing && existing.expires_at ? String(existing.expires_at).slice(0, 10) : "" });
  const modeF = uiField({ name: "mode", label: bl({ en: "Action", ja: "動作" }), type: "select", value: existing ? (existing.mode || "allow") : "allow", options: [{ value: "allow", label: bl({ en: "Allow", ja: "許可" }) }, { value: "deny", label: bl({ en: "Block", ja: "ブロック" }) }] });
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: existing ? bl({ en: "Save", ja: "保存" }) : bl({ en: "Add exception", ja: "例外を追加" }) });
  const m = uiModal({ title: existing ? bl({ en: "Edit an incoming-connection exception", ja: "受信接続の例外を編集" }) : bl({ en: "Add an incoming-connection exception", ja: "受信接続の例外を追加" }), body: [idF.el, srcF.el, grpF.el, svcF.el, ownerF.el, expF.el, modeF.el], footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit] });
  submit.addEventListener("click", async () => {
    if (!idF.validate()) return;
    if (!srcF.get()) { uiToast(bl({ en: "Pick a source server.", ja: "送信元のサーバを選択してください。" }), "err"); return; }
    const payload = { id: idF.get(), source_server: srcF.get(), device_group: grpF.get(), business_owner: ownerF.get(), mode: modeF.get() };
    const sid = svcF.get();
    if (sid === "__raw__" && existing) {
      payload.service_family = existing.service_family;
    } else if (sid) {
      const svc = (idx.services || []).find((s) => s.id === sid);
      if (svc) { payload.service_family = svc.alias; if (svc.ports && svc.ports[0]) payload.port = svc.ports[0].port; }
    }
    if (expF.get()) payload.expires_at = new Date(expF.get()).toISOString();
    submit.disabled = true;
    try {
      const r = await apiFetch("POST", "/admin/legacy-exceptions", payload);
      if (!r.ok) { submit.disabled = false; uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
      m.close(); uiToast(existing ? bl({ en: "Exception saved.", ja: "例外を保存しました。" }) : bl({ en: "Exception added.", ja: "例外を追加しました。" }), "ok"); renderIncomingView(content);
    } catch (e) { submit.disabled = false; uiToast(String(e), "err"); }
  });
  idF.focus();
}
