"use strict";

// grants.js — "Access Approvals" on the shared ui.js pattern (product-quality, see
// docs/console_ux_design_direction.md). These are the access approvals minted after a user signs in
// through your identity provider: access is permitted only while an approval is live, and Revoke is
// checked by the receiving server; other servers need the configuration update.
//
// Loaded after app.js (apiFetch / bl / escapeHtml / el / ui* in scope). app.js dispatches here for
// custom: "grants". Backend: GET /admin/grants -> {grants:[…]} + POST /admin/grants/{id}/revoke.

// _grantsShowAll: list filter state — false (default) shows only live approvals; true includes history.
let _grantsShowAll = false;

function grantExpiryTime(g) {
  const m = typeof g.expires_at === "string" && /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.exec(g.expires_at);
  if (!m) return NaN;
  const [year,month,day,hour,minute,second] = m.slice(1).map(Number);
  const days = new Date(Date.UTC(2000 + year % 400,month,0)).getUTCDate();
  if (month < 1 || month > 12 || day < 1 || day > days || hour > 23 || minute > 59 || second > 59) return NaN;
  return Date.parse(g.expires_at);
}

function grantStatus(g, nowMs) {
  if (g.revoked) return { label: { en: "Revoked", ja: "失効" }, kind: "off" };
  const exp = grantExpiryTime(g);
  if (!Number.isFinite(exp)) return { label: { en: "Unknown expiry", ja: "期限不明" }, kind: "warn" };
  if (exp <= nowMs) return { label: { en: "Expired", ja: "期限切れ" }, kind: "warn" };
  return { label: { en: "Active", ja: "有効" }, kind: "ok" };
}

function grantTime(s) {
  if (!s) return "—";
  const t = Date.parse(s);
  if (isNaN(t)) return s;
  // Compact: approvals are short-lived — minute precision, no seconds, so ten columns stay readable.
  return window.dsseFormatTime(t, { year: "2-digit", month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit", second: undefined });
}

// grantRemaining renders how long an ACTIVE approval has left ("in 14 min"), so Expires answers the
// operator's real question — "is this still letting someone in, and for how much longer?"
function grantRemaining(g, nowMs) {
  if (g.revoked) return "";
  const exp = grantExpiryTime(g);
  if (isNaN(exp) || exp <= nowMs) return "";
  const min = Math.round((exp - nowMs) / 60000);
  if (min < 60) return bl({ en: "in " + min + " min", ja: "あと" + min + "分" });
  const h = Math.floor(min / 60), m = min % 60;
  return bl({ en: "in " + h + " h " + m + " min", ja: "あと" + h + "時間" + m + "分" });
}

// acrMeaning translates the raw assurance code (acr) the IdP asserted into what it MEANS for the
// operator. Unknown codes fall through to the raw value — an operator-configured acr is meaningful as-is.
function acrMeaning(acr) {
  const a = (acr || "").trim();
  if (a === "phishing_resistant") return { label: { en: "Phishing-resistant passkey", ja: "フィッシング耐性パスキー" }, kind: "ok" };
  if (a === "" || a === "0" || a === "1") return { label: { en: "Password (single factor)", ja: "パスワード（単要素）" }, kind: "warn" };
  return null;
}

// AMR_LABELS translates RFC 8176 authentication-method values (amr) to readable methods.
const AMR_LABELS = {
  pwd: { en: "Password", ja: "パスワード" },
  password: { en: "Password", ja: "パスワード" },
  otp: { en: "One-time code", ja: "ワンタイムコード" },
  totp: { en: "One-time code (app)", ja: "ワンタイムコード（アプリ）" },
  sms: { en: "One-time code (SMS)", ja: "ワンタイムコード（SMS）" },
  webauthn: { en: "Passkey (WebAuthn)", ja: "パスキー（WebAuthn）" },
  hwk: { en: "Hardware key", ja: "ハードウェアキー" },
  swk: { en: "Software key", ja: "ソフトウェアキー" },
  fpt: { en: "Biometric", ja: "生体認証" },
  face: { en: "Biometric (face)", ja: "生体認証（顔）" },
  pin: { en: "PIN", ja: "PIN" },
  mfa: { en: "Multi-factor", ja: "多要素" },
  user: { en: "User presence", ja: "ユーザー実在確認" },
};

// signInMethod: the amr claim when the IdP sent one; otherwise the method is implied by the assurance
// level the ceremony enforced (a phishing_resistant grant WAS a passkey sign-in; acr=1 was a password).
function signInMethod(g) {
  const amr = (g.amr || []).filter(Boolean);
  if (amr.length) return amr.map((m) => bl(AMR_LABELS[String(m).toLowerCase()] || { en: m, ja: m })).join(" + ");
  if ((g.acr || "").trim() === "phishing_resistant") return bl({ en: "Passkey (WebAuthn)", ja: "パスキー（WebAuthn）" });
  return bl({ en: "Password", ja: "パスワード" });
}

function renderGrantsView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "Access Approvals", ja: "アクセス承認" }) }),
      el("p", { class: "ui-view-desc", text: bl({
        en: "Access granted to people after they sign in through your identity provider. Revocation takes effect on this server; other servers must receive the configuration update.",
        ja: "ユーザーが ID プロバイダでサインインした後に付与されるアクセスです。失効はこのサーバーで反映されます。他のサーバーには設定の配布が必要です。",
      }) }),
    ]),
    el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Reload", ja: "再読込" }), onClick: () => renderGrantsList(host) }),
  ]));
  const host = el("div", {});
  content.appendChild(host);
  renderGrantsList(host);
}

async function renderGrantsList(host) {
  uiState(host, "loading");
  const current = freshRender(host);
  let grants;
  try {
    const [r, tenant] = await Promise.all([apiFetch("GET", "/admin/grants"), apiFetch("GET", "/admin/tenant")]);
    if (!r?.ok || !tenant?.ok) throw new Error("HTTP " + (!r?.ok ? r?.status : tenant?.status));
    grants = validatedAccessGrants(r.body, tenant.body);
  } catch (e) {
    if (!current()) return;
    uiState(host, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderGrantsList(host) });
    drawGrantNotices(host); return;
  }

  if (!grants.length) {
    if (!current()) return;
    uiState(host, "empty", bl({ en: "No access approvals yet. One appears here after a person signs in through your identity provider.", ja: "アクセス承認はまだありません。ユーザーが ID プロバイダでサインインすると表示されます。" }));
    drawGrantNotices(host); return;
  }

  // Resolve the opaque IdP subject (g.user_id — a sub/UUID) to a readable person via the synced directory. The
  // raw sub is unreadable, so the User column shows the person's name + email; it falls back to the raw id only
  // if the directory is unavailable or the user isn't in it.
  // The grant itself carries the person (email / username / display name captured from the verified ID
  // token at mint time). The synced directory is only a FALLBACK for grants minted before that existed.
  const dir = {};
  try {
    const dr = await apiFetch("GET", "/admin/human-identities", null, "control");
    const items = (dr && dr.ok && dr.body) ? (dr.body.identities || dr.body.items || (Array.isArray(dr.body) ? dr.body : [])) : [];
    items.forEach((i) => {
      const rec = { name: ((i && i.display_name) || "").trim(), email: ((i && i.email) || "").trim(), subject: ((i && i.subject) || "").trim() };
      [i && i.id, i && i.subject, i && i.email].forEach((k) => { if (k) dir[k] = rec; });
    });
  } catch (e) { /* directory optional — fall back to the raw id */ }
  const resolveUser = (uid) => dir[uid] || null;

  // IdP display names (so the column says "Keycloak Lab", not "keycloak-lab") — best-effort.
  const idpNames = {};
  try {
    const ir = await apiFetch("GET", "/admin/idp-connections");
    ((ir && ir.ok && ir.body && (ir.body.connections || ir.body.idp_connections)) || []).forEach((c) => {
      if (c && c.idp_id) idpNames[c.idp_id] = (c.display_name || "").trim();
    });
  } catch (e) { /* best-effort */ }

  // Device notes (the operator's own label for mac-dev-1 etc.) — best-effort.
  const deviceNotes = {};
  try {
    const er = await apiFetch("GET", "/admin/enrolled-devices");
    ((er && er.ok && er.body && er.body.devices) || []).forEach((d) => {
      if (d && d.identity) deviceNotes[d.identity] = (d.note || "").trim();
    });
  } catch (e) { /* best-effort */ }

  const now = Date.now();
  const buildRow = (g) => {
    const st = grantStatus(g, now);

    // WHO: prefer the identity the grant itself recorded; directory fallback. When neither knows the
    // person (grants minted before identity capture, against a since-reset IdP), SAY it is unknown —
    // an unexplained raw subject id is exactly the kind of display this page must not have.
    const person = resolveUser(g.user_id);
    const displayName = g.user_display_name || (person && person.name) || g.username || "";
    const email = g.user_email || (person && person.email) || "";
    const primary = displayName || email || "";
    const userKids = primary
      ? [el("strong", { text: primary })]
      : [el("span", { text: bl({ en: "Unknown user", ja: "不明なユーザー" }) }),
         el("div", { class: "ui-view-desc" }, el("code", { text: g.user_id || "—" }))];
    if (email && email !== primary) userKids.push(el("div", { class: "ui-view-desc", text: email }));
    if (g.username && g.username !== primary) userKids.push(el("div", { class: "ui-view-desc", text: g.username }));

    // DEVICE the approval is bound to (the East-West gate only honors it from this device). The operator
    // note is shown only when it reads like a human label — machine seed markers are not information.
    const note = (g.device_id && deviceNotes[g.device_id]) || "";
    const humanNote = note && !/^[a-z0-9_]+$/.test(note) ? note : "";
    const deviceKids = g.device_id
      ? [el("span", { text: g.device_id })]
      : [el("span", { class: "ui-view-desc", text: bl({ en: "Not device-bound", ja: "デバイス束縛なし" }) })];
    if (humanNote) deviceKids.push(el("div", { class: "ui-view-desc", text: humanNote }));

    // WHAT the ceremony was run for (recorded at approval; older approvals predate the field).
    const destCell = g.scope ? el("code", { text: g.scope }) : el("span", { class: "ui-view-desc", text: "—" });

    // Assurance: what the level MEANS, with the raw code kept underneath for auditability.
    const meaning = acrMeaning(g.acr);
    const acrKids = meaning ? [uiBadge(bl(meaning.label), meaning.kind)] : [el("code", { text: g.acr || "—" })];
    if (meaning && g.acr) acrKids.push(el("div", { class: "ui-view-desc" }, el("code", { text: "acr=" + g.acr })));

    // One validity cell: when it expires (the operator's live question, with time left) over when it
    // was granted — two related times don't need two columns.
    const expireKids = [document.createTextNode(grantTime(g.expires_at))];
    const remain = grantRemaining(g, now);
    if (remain) expireKids.push(el("div", { class: "ui-view-desc", text: remain }));
    expireKids.push(el("div", { class: "ui-view-desc", text: bl({ en: "granted ", ja: "付与 " }) + grantTime(g.issued_at) }));

    return el("tr", {}, [
      el("td", {}, userKids),
      el("td", {}, deviceKids),
      el("td", {}, destCell),
      el("td", { text: idpNames[g.idp_id] || g.idp_id || "—" }),
      el("td", {}, acrKids),
      el("td", { text: signInMethod(g) }),
      el("td", {}, expireKids),
      el("td", {}, uiBadge(bl(st.label), st.kind)),
      el("td", { class: "ui-row-actions" }, g.revoked ? null : grantRevokeButton(g, host, primary || email || g.user_id)),
    ]);
  };
  // Searchable: person (name / email / username), device, destination, IdP, or status.
  const hay = (g) => {
    const person = resolveUser(g.user_id);
    return [g.user_display_name, g.user_email, g.username, person && person.name, person && person.email,
      person && person.subject, g.user_id, g.device_id, g.scope, idpNames[g.idp_id], g.idp_id,
      bl(grantStatus(g, now).label)].filter(Boolean).join(" ");
  };
  const table = (list) => el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [
      bl({ en: "User", ja: "ユーザー" }), bl({ en: "Device", ja: "デバイス" }), bl({ en: "Approved for", ja: "承認対象" }),
      bl({ en: "Identity provider", ja: "ID プロバイダ" }), bl({ en: "Assurance", ja: "保証レベル" }),
      bl({ en: "Sign-in method", ja: "サインイン方法" }), bl({ en: "Expires", ja: "期限" }),
      bl({ en: "Status", ja: "状態" }), bl({ en: "Actions", ja: "操作" }),
    ].map((t) => el("th", { text: t })))),
    el("tbody", {}, list.map(buildRow)),
  ]);

  // Default to LIVE approvals — the operator's working set. Revoked/expired history is one click away
  // (and still searchable there), instead of burying the few active grants under weeks of dead rows.
  const active = grants.filter((g) => grantStatus(g, now).kind === "ok");
  const showAll = _grantsShowAll || active.length === 0; // nothing active -> show history rather than an empty page
  const shown = showAll ? grants : active;
  const filterBar = el("div", { class: "ui-row-actions", style: "margin-bottom:8px" }, [
    el("button", {
      class: "ui-btn ui-btn-sm" + (showAll ? "" : " ui-btn-primary"),
      text: bl({ en: "Active", ja: "有効" }) + " (" + active.length + ")",
      onClick: () => { _grantsShowAll = false; renderGrantsList(host); },
    }),
    el("button", {
      class: "ui-btn ui-btn-sm" + (showAll ? " ui-btn-primary" : ""),
      text: bl({ en: "All (incl. revoked/expired)", ja: "すべて（失効・期限切れ含む）" }) + " (" + grants.length + ")",
      onClick: () => { _grantsShowAll = true; renderGrantsList(host); },
    }),
  ]);

  if (!current()) return;
  host.innerHTML = "";
  drawGrantNotices(host);
  host.appendChild(filterBar);
  host.appendChild(paSearchTable(bl({ en: "Search by user, email, device, destination, or identity provider…", ja: "ユーザー・email・デバイス・宛先・ID プロバイダで検索…" }), shown, hay, table, bl({ en: "No matches.", ja: "一致なし。" })));
}

function accessGrantObject(v) { return v && typeof v === "object" && !Array.isArray(v); }
function accessGrantText(v) { return typeof v === "string" && v.trim() !== ""; }
function validatedAccessGrants(body, tenant) {
  if (!accessGrantObject(tenant) || !accessGrantText(tenant.tenant_id) || !accessGrantObject(body) || !Array.isArray(body.grants)) throw new Error("Invalid access approval response");
  const ids = new Set();
  for (const g of body.grants) {
    if (!accessGrantObject(g) || !accessGrantText(g.grant_id) || g.tenant_id !== tenant.tenant_id || ids.has(g.grant_id) ||
        (g.revoked !== undefined && typeof g.revoked !== "boolean") ||
        ["user_id","user_email","username","user_display_name","device_id","idp_id","acr","scope","issued_at","expires_at"].some(k => g[k] !== undefined && typeof g[k] !== "string") ||
        (g.amr !== undefined && (!Array.isArray(g.amr) || g.amr.some(v => typeof v !== "string")))) throw new Error("Invalid access approval record");
    ids.add(g.grant_id);
  }
  return body.grants;
}
function grantUnconfirmed() { return bl({en:"The revocation outcome is unconfirmed. Check the approval and retry revocation.",ja:"失効の結果を確認できません。承認の状態を確認し、失効を再試行してください。"}); }
function grantRevokeOutcome(r, g) {
  const b = r?.body;
  const same = accessGrantObject(b) && b.grant_id === g.grant_id && b.tenant_id === g.tenant_id;
  if (r?.ok && r.status === 200 && same && b.status === "revoked" && (b.persistence === undefined || b.persistence === "saved_non_atomic")) return {partial:false,nonAtomic:b.persistence === "saved_non_atomic"};
  if (!r?.ok && r?.status === 500 && same && b.status === "partial" && b.applied === true && b.persistence === "unconfirmed") return {partial:true};
  if (r?.ok || (accessGrantObject(b) && b.status === "partial")) throw new Error(grantUnconfirmed());
  throw new Error(accessGrantText(b?.error) ? b.error : grantUnconfirmed());
}
function grantRevokeButton(g, host, label, retry = false, partial = false) {
  const button = el("button", {class:"ui-btn ui-btn-sm ui-btn-danger", text: retry ? (partial ? bl({en:"Retry saving revocation",ja:"失効の保存を再試行"}) : bl({en:"Retry revocation",ja:"失効を再試行"})) : bl({en:"Revoke",ja:"失効"}), onClick: async () => {
    if (button.disabled) return; button.disabled = true;
    try { await revokeGrant(g, host, label, retry); } finally { button.disabled = false; }
  }});
  return button;
}
function drawGrantNotices(host) {
  for (const notice of (host.__grantNotices || new Map()).values()) {
    host.appendChild(el("div", {class:"ui-callout ui-callout-warn",role:"alert"}, [
      el("p",{text:(notice.label || bl({en:"Access approval",ja:"アクセス承認"})) + ": " + notice.message}),
      notice.retry === false ? null : grantRevokeButton(notice.grant,host,notice.label,true,notice.partial),
    ]));
  }
}
async function revokeGrant(g, host, label, retry = false) {
  const pending = host.__grantPending || (host.__grantPending = new Set());
  const notices = host.__grantNotices || (host.__grantNotices = new Map());
  const key = g.tenant_id + "\0" + g.grant_id;
  if (pending.has(key)) return; pending.add(key);
  try {
    if (!retry && !await uiConfirm({
      title:bl({en:"Revoke this access?",ja:"このアクセスを失効?"}),
      body:bl({en:"Revoke this approval on this server. Other servers must receive the update. This cannot be undone.",ja:"このサーバーで承認を失効します。他のサーバーには更新の配布が必要です。この操作は取り消せません。"}),
      confirmLabel:bl({en:"Revoke",ja:"失効"}),danger:true,
    })) return;
    let r;
    try { r = await apiFetch("POST", "/admin/grants/" + encodeURIComponent(g.grant_id) + "/revoke"); }
    catch (_) { throw new Error(grantUnconfirmed()); }
    const outcome = grantRevokeOutcome(r,g);
    if (outcome.partial) {
      notices.set(key,{grant:g,label,partial:true,message:bl({en:"Revoked on this server, but persistence is unconfirmed. Restore storage and retry saving this revocation before restarting.",ja:"このサーバーでは失効済みですが、保存を確認できません。保存先を復旧し、再起動前に失効の保存を再試行してください。"})});
    } else if (outcome.nonAtomic) {
      notices.set(key,{grant:g,label,retry:false,message:bl({en:"Revoked and saved without atomic replacement. This save completed, but interrupted future writes could damage the snapshot. Use storage that supports atomic replacement.",ja:"失効を保存しましたが、原子的な置き換えはできませんでした。今回の保存は完了しています。今後の書き込み中断による破損を避けるため、原子的な置き換えが可能な保存先を使用してください。"})});
    } else { notices.delete(key); if (host.isConnected !== false) uiToast((label || bl({en:"Access approval",ja:"アクセス承認"})) + ": " + bl({en:"Revocation accepted.",ja:"失効を受け付けました。"}),"ok"); }
  } catch (e) { notices.set(key,{grant:g,label,message:e.message || String(e)}); }
  finally { pending.delete(key); }
  if (host.isConnected !== false) await renderGrantsList(host);
}
