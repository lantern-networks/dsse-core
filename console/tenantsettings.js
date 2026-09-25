"use strict";

// tenantsettings.js — the tenant's own settings. Today that is the display name and the timezone.
//
// The timezone has been settable through the API for a while and there was nowhere to set it, so in practice
// every tenant read every timestamp in UTC. A capability with no way to reach it is a capability nobody has.
//
// The preview is the point of this screen rather than decoration. A zone name is an abstraction — "Asia/Tokyo"
// tells an operator nothing about whether the log line they are looking at will now read the way they expect —
// so the same instant is shown in the chosen zone as it is chosen. Picking from a list and seeing the clock move
// is the difference between configuring something and hoping.
//
// Backend: GET/POST /admin/tenant on the CONTROL PLANE, which is not an arbitrary choice.
//
// The Console reads the tenant clock from GET /admin/session, and the front door routes the auth surface to the
// control plane while routing /admin/* to the Edge. Both planes keep their own tenant model. So a timezone
// written through the ordinary Edge route is stored, reported back correctly by that same route, and NEVER
// reaches the session — the setting looks applied and does nothing. Verified live: writing to the Edge left the
// session on UTC; writing here made it read Asia/Tokyo immediately.
//
// Write where the value is read. Anything else is a setting that silently fails.
const _TENANT_PLANE = "control";

// Zones an operator is realistically choosing between, with UTC first because it is the default and a deliberate
// answer rather than an absence. The field also accepts anything the IANA database knows — the Edge validates
// against the real zone database, so a typo is refused where it can still be seen rather than surfacing weeks
// later as a report covering the wrong day.
const _TZ_COMMON = [
  "UTC",
  "Asia/Tokyo", "Asia/Seoul", "Asia/Shanghai", "Asia/Singapore", "Asia/Kolkata", "Asia/Dubai",
  "Europe/London", "Europe/Berlin", "Europe/Paris", "Europe/Madrid",
  "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles", "America/Sao_Paulo",
  "Australia/Sydney", "Pacific/Auckland",
];

function renderTenantSettingsView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "Tenant settings", ja: "テナント設定" }) }),
      el("p", { class: "ui-view-desc", text: bl({
        en: "How this tenant is named, and the timezone its operators read times in.",
        ja: "このテナントの名称と、運用者が時刻を読むタイムゾーン。" }) }),
    ]),
  ]));
  const host = el("div", {});
  content.appendChild(host);
  loadTenantSettings(host, content);
}

async function loadTenantSettings(host, content) {
  uiState(host, "loading");
  const current = freshRender(host);
  let tenant;
  try {
    const r = await apiFetch("GET", "/admin/tenant", undefined, _TENANT_PLANE);
    if (!r.ok) {
      if (!current()) return;
      uiState(host, "error", "HTTP " + r.status, { label: bl({ en: "Retry", ja: "再試行" }),
        onClick: () => loadTenantSettings(host, content) });
      return;
    }
    tenant = r.body || {};
  } catch (e) {
    if (!current()) return;
    uiState(host, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }),
      onClick: () => loadTenantSettings(host, content) });
    return;
  }

  if (!current()) return;
  host.innerHTML = "";
  const card = el("div", { class: "ui-card" });

  const nameF = uiField({ name: "display_name", label: bl({ en: "Display name", ja: "表示名" }),
    value: tenant.display_name || "" });

  const currentZone = tenant.timezone || "UTC";
  const options = _TZ_COMMON.slice();
  if (!options.includes(currentZone)) options.unshift(currentZone); // keep a zone somebody set by hand
  const tzF = uiField({
    name: "timezone", label: bl({ en: "Timezone", ja: "タイムゾーン" }), type: "select", value: currentZone,
    options: options.map((z) => ({ value: z, label: z })),
    hint: bl({
      en: "Times are STORED in UTC and always will be. This changes how they are displayed and where a day begins — which is what makes “yesterday” mean your yesterday in a report.",
      ja: "時刻の保存は常に UTC のままです。これが変えるのは表示と「1日の境目」で、レポートの「昨日」が、このテナントにとっての昨日になるかを決めます。" }),
  });

  // The preview: the same instant, in the zone being chosen. A zone name means little until the clock moves.
  const preview = el("div", { class: "ui-preview", style: "margin-top:8px" });
  const paint = (zone) => {
    const now = new Date();
    let inZone, offset;
    try {
      inZone = new Intl.DateTimeFormat("en-GB", {
        timeZone: zone, dateStyle: "full", timeStyle: "long",
      }).format(now);
      offset = new Intl.DateTimeFormat("en-GB", { timeZone: zone, timeZoneName: "shortOffset" })
        .formatToParts(now).find((p) => p.type === "timeZoneName");
    } catch (e) {
      preview.innerHTML = "";
      preview.appendChild(el("div", { text: bl({
        en: "This browser does not recognise that zone — the Edge will still check it against the IANA database when you save.",
        ja: "このブラウザはそのゾーンを認識しませんでした — 保存時に Edge が IANA データベースで検証します。" }) }));
      return;
    }
    preview.innerHTML = "";
    preview.appendChild(el("div", { text: bl({ en: "Right now, in " + zone + ":", ja: zone + " での現在時刻:" }) }));
    preview.appendChild(el("div", { text: inZone + (offset ? " (" + offset.value + ")" : "") }));
    preview.appendChild(el("div", { text: bl({
      en: "The same instant in UTC: " + now.toISOString().replace("T", " ").slice(0, 19) + " UTC",
      ja: "同じ瞬間の UTC: " + now.toISOString().replace("T", " ").slice(0, 19) + " UTC" }) }));
  };
  paint(currentZone);
  tzF.el.addEventListener("change", () => paint(tzF.get()));
  tzF.el.addEventListener("input", () => paint(tzF.get()));

  const save = el("button", { class: "ui-btn ui-btn-primary", style: "margin-top:12px",
    text: bl({ en: "Save", ja: "保存" }) });
  save.addEventListener("click", async () => {
    save.disabled = true;
    // Send the tenant back whole: the self-scoped update takes the model, and posting only the changed fields
    // would clear the rest.
    const body = Object.assign({}, tenant, { display_name: nameF.get(), timezone: tzF.get() });
    let r;
    try {
      r = await apiFetch("POST", "/admin/tenant", body, _TENANT_PLANE);
    } catch (e) {
      // The request may have reached the authority even when its reply was lost.
      // Keep the edit and let the operator verify the saved value before retrying.
      uiToast(bl({
        en: "Could not confirm the save. Reload to verify the setting before retrying.",
        ja: "保存結果を確認できませんでした。再試行前に再読込して設定を確認してください。" }), "err");
      return;
    } finally {
      save.disabled = false;
    }
    if (!r.ok) {
      const msg = (r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status);
      tzF.setError(msg);
      uiToast(msg, "err");
      return;
    }
    uiToast(bl({
      en: "Saved. Times across the Console now read in " + tzF.get() + ".",
      ja: "保存しました。Console 全体の時刻が " + tzF.get() + " で表示されます。" }), "ok");
    // Reload so every view picks up the new zone rather than showing a mix until the next navigation.
    // Re-read the session so every other view adopts the new zone immediately. Without this the Console
    // would show a mix — this page in the new zone, everything else in the old one — until a reload, which
    // reads as the setting not having worked.
    if (typeof ensureSignedIn === "function") { await ensureSignedIn(); }
    renderTenantSettingsView(content);
  });

  card.appendChild(nameF.el);
  card.appendChild(tzF.el);
  card.appendChild(preview);
  card.appendChild(save);
  host.appendChild(card);

  host.appendChild(el("p", { class: "ui-view-desc", text: bl({
    en: "Timestamps in logs and exports stay UTC — mixing zones into stored values is how audit trails stop being comparable. Only presentation and day boundaries follow this setting.",
    ja: "ログやエクスポートに記録される時刻は UTC のままです — 保存値にゾーンを混ぜると監査証跡が比較できなくなります。この設定が及ぶのは表示と日付境界だけです。" }) }));
}
