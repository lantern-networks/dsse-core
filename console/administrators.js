"use strict";

// administrators.js — "Administrators" view: the administrators of the CURRENT tenant (the backend scopes every
// call to the caller's tenant). List / invite / suspend / reactivate / change roles / remove, on the shared
// ui.js pattern. Part of the multi-tenant Admin Console (Phase 1).
// Backend: GET /admin/admins -> {admins:[{principal_id,email,roles,status,created_at,last_login_at}]},
// POST /admin/admins/invite {email,roles}, POST /admin/admins/{id}/suspend|reactivate,
// POST /admin/admins/{id}/roles {roles}, DELETE /admin/admins/{id}. Assignable roles from /admin/rbac/catalog.

let _adminRolesCache = null;

function roleLabelBL(role) {
  const m = {
    super_admin: { en: "Operator (cross-tenant)", ja: "運営(横断)" },
    owner: { en: "Owner", ja: "オーナー" },
    tenant_admin: { en: "Administrator", ja: "管理者" },
    admin: { en: "Administrator (legacy name)", ja: "管理者(旧称)" },
    analyst: { en: "Analyst", ja: "アナリスト" },
    approver: { en: "Approver", ja: "承認者" },
    auditor: { en: "Auditor", ja: "監査者" },
  };
  return m[role] ? bl(m[role]) : role;
}

async function loadAssignableRoles() {
  if (_adminRolesCache) return _adminRolesCache;
  const fallback = ["tenant_admin", "admin", "analyst", "approver", "auditor"];
  try {
    const r = await apiFetch("GET", "/admin/rbac/catalog");
    // One key, the one the route sends. The `|| r.body.APITokenRoles` that used to sit here was the Go FIELD
    // name, which never appears on the wire — a guess that reads as defensiveness. See
    // ops/checks/console_body_keys_exist.sh for the one it hid.
    const list = (r.ok && r.body && r.body.api_token_roles) || [];
    const roles = list.map((x) => x.role || x.Role).filter(Boolean);
    _adminRolesCache = roles.length ? roles : fallback;
  } catch (e) { _adminRolesCache = fallback; }
  return _adminRolesCache;
}

// What each role ENABLES, in one line, so the choice is a decision rather than a guess.
function roleHintBL(role) {
  const m = {
    tenant_admin: { en: "Everything in this tenant: rules, devices, people, certificates.", ja: "このテナントのすべて: ルール・端末・人・証明書。" },
    admin: { en: "The same as Administrator. An older name kept for accounts that already have it.", ja: "「管理者」と同じです。既にこの名前が付いている人のために残しています。" },
    analyst: { en: "Can read everything and change nothing.", ja: "すべてを見られますが、何も変更できません。" },
    approver: { en: "Can approve access requests, and nothing else.", ja: "アクセスの承認だけができます。" },
    auditor: { en: "Can read the logs and the audit trail.", ja: "ログと監査記録を読めます。" },
    super_admin: { en: "Runs the whole deployment, across every tenant.", ja: "配備全体を、すべてのテナントにまたがって運用します。" },
    owner: { en: "Runs the whole deployment, across every tenant.", ja: "配備全体を、すべてのテナントにまたがって運用します。" },
  };
  return m[role] ? bl(m[role]) : "";
}

function privilegedRole(r) { return r === "super_admin" || r === "owner"; }

// assignableForCaller: tenant-internal roles are always assignable; the cross-tenant operator roles
// (super_admin / owner) are offered ONLY to an operator who already holds cross-tenant admin. A tenant_admin
// never sees them. The backend independently refuses any escalation (403), so this is the UX layer, not the
// security gate.
function assignableForCaller(catalogRoles) {
  const allowed = catalogRoles.filter((r) => !privilegedRole(r) || hasCrossTenantAdmin());
  // ★ "admin" is the older name for the same authority as "tenant_admin", and offering both put the deprecated
  // one FIRST in the list. A new invitation should not present a choice between a role and its own former
  // name; the label map keeps it so accounts that already hold it still render correctly.
  const withoutLegacy = allowed.filter((r) => r !== "admin");
  return (allowed.includes("tenant_admin") && withoutLegacy.length) ? withoutLegacy : allowed;
}

function adminStatusKind(s) { return s === "active" ? "ok" : s === "suspended" ? "warn" : "off"; }
function adminStatusLabel(s) {
  return s === "active" ? bl({ en: "Active", ja: "有効" })
    : s === "suspended" ? bl({ en: "Suspended", ja: "停止中" })
    // ★ The API's own word reached the screen untranslated: a row read "pending_activation", in English, in a
    // Japanese console. Both spellings are mapped, and an unknown status still shows rather than blanking.
    : (s === "pending" || s === "pending_activation") ? bl({ en: "Invited — has not signed in yet", ja: "招待済み — まだサインインしていません" })
    : (s || "—");
}

function renderAdministratorsView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "Administrators", ja: "管理者" }) }),
      el("p", { class: "ui-view-desc", text: bl({ en: "The people who can administer this tenant. Only this tenant — nobody here can see or change another one.", ja: "このテナントを管理できる人。このテナントだけです — ここにいる人が他のテナントを見たり変えたりすることはありません。" }) }),
    ]),
    el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "+ Invite admin", ja: "+ 管理者を招待" }), onClick: () => openInviteForm(content) }),
  ]));
  const host = el("div", {});
  content.appendChild(host);
  renderAdminList(host);
}

async function renderAdminList(host) {
  uiState(host, "loading");
  const current = freshRender(host);
  let admins;
  try {
    const r = await apiFetch("GET", "/admin/admins");
    if (!r.ok) {
      const msg = r.status === 403 ? bl({ en: "You don't have permission to view administrators.", ja: "管理者を閲覧する権限がありません。" }) : "HTTP " + r.status;
      if (!current()) return;
      uiState(host, "error", msg, { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderAdminList(host) });
      return;
    }
    admins = (r.body && r.body.admins) || [];
  } catch (e) { if (!current()) return; uiState(host, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderAdminList(host) }); return; }
  if (!admins.length) { if (!current()) return; uiState(host, "empty", bl({ en: "No administrators yet. Invite one to get started.", ja: "管理者がいません。招待して開始してください。" })); return; }
  const rows = admins.slice().sort((a, b) => (a.email || "").localeCompare(b.email || "")).map((a) => {
    const status = a.status || "active";
    const roleCell = el("td", {});
    const rolesArr = a.roles || [];
    if (!rolesArr.length) roleCell.appendChild(el("span", { class: "ui-view-desc", text: "—" }));
    rolesArr.forEach((rr, i) => { if (i) roleCell.appendChild(document.createTextNode(" ")); roleCell.appendChild(uiBadge(roleLabelBL(rr), rr === "super_admin" || rr === "owner" ? "warn" : "off")); });
    const actCell = el("td", { class: "ui-row-actions" });
    const acts = [];
    if (status === "active") acts.push(el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Suspend", ja: "停止" }), onClick: () => adminStatusChange(a, "suspend", host) }));
    if (status === "suspended") acts.push(el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Reactivate", ja: "再開" }), onClick: () => adminStatusChange(a, "reactivate", host) }));
    acts.push(el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Roles", ja: "ロール" }), onClick: () => openRolesForm(a, host) }));
    acts.push(el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Remove", ja: "削除" }), onClick: () => adminDelete(a, host) }));
    acts.forEach((b, i) => { if (i) actCell.appendChild(document.createTextNode(" ")); actCell.appendChild(b); });
    return el("tr", {}, [
      // ★ NOT THE PRINCIPAL ID (2026-08-17, read as a customer). Every row carried adm_8bafc649958320c8… in
      // monospace under the email. The email identifies the person; the identifier is ours, and it stays where
      // somebody debugging can still reach it.
      el("td", { title: a.principal_id || "" }, [el("strong", { text: a.email || bl({ en: "(no email)", ja: "(メールなし)" }) })]),
      roleCell,
      el("td", {}, uiBadge(adminStatusLabel(status), adminStatusKind(status))),
      el("td", { class: "ui-view-desc", text: a.last_login_at ? window.dsseFormatTime(a.last_login_at) : bl({ en: "Never", ja: "なし" }) }),
      actCell,
    ]);
  });
  if (!current()) return;
  host.innerHTML = "";
  host.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [bl({ en: "Administrator", ja: "管理者" }), bl({ en: "Roles", ja: "ロール" }), bl({ en: "Status", ja: "状態" }), bl({ en: "Last sign-in", ja: "最終サインイン" }), bl({ en: "Actions", ja: "操作" })].map((x) => el("th", { text: x })))),
    el("tbody", {}, rows),
  ]));
}

// openInvitationHandover shows the invitation the backend assembled, for the operator to deliver.
//
// ★ THIS REPLACED A LIE (2026-08-15). The old flow threw the response away and toasted "Invitation sent."
// Nothing was sent — this product has no SMTP, by decision — so every administrator invited from the screen
// was unreachable, and the failure was invisible: twenty-three dead accounts accumulated in the lab before
// anyone noticed. What was missing was never a way to send. It was a way to HAND OVER.
//
// Shared deliberately: the same panel serves the Administrators view (a tenant admin inviting a colleague,
// which is the common case) and, later, the organization-creation wizard's first administrator. One panel
// means the words a person receives cannot drift between the two places that produce them.
// NOT exported: this Console loads its files as CLASSIC scripts (console.html has no type="module"), so an
// `export` here is a syntax error that stops the WHOLE file being evaluated — the Administrators view
// would simply not exist. Sharing happens through the global scope, the way every other view here shares.
function openInvitationHandover(invitation, opts) {
  const inv = invitation || {};
  const onReissue = opts && opts.onReissue;
  const text = [inv.subject ? bl({ en: "Subject: ", ja: "件名: " }) + inv.subject : "", inv.body || ""]
    .filter(Boolean).join("\n\n");
  const copyAll = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Copy message", ja: "本文をコピー" }), onClick: () => {
    try { navigator.clipboard.writeText(text); uiToast(bl({ en: "Copied.", ja: "コピーしました。" }), "ok"); }
    catch (e) { uiToast(String(e), "err"); }
  } });
  const copyLink = el("button", { class: "ui-btn", text: bl({ en: "Copy link only", ja: "リンクのみコピー" }), onClick: () => {
    try { navigator.clipboard.writeText(inv.link || ""); uiToast(bl({ en: "Copied.", ja: "コピーしました。" }), "ok"); }
    catch (e) { uiToast(String(e), "err"); }
  } });
  // onClosed lets a caller continue AFTER the operator has taken the link. The creation wizard needs it:
  // opening its checklist alongside put a modal on top of the one thing in the flow that cannot be recovered
  // by looking again.
  const onClosed = opts && opts.onClosed;
  const footer = [el("button", { class: "ui-btn", text: bl({ en: "Done", ja: "閉じる" }), onClick: () => { m.close(); if (onClosed) onClosed(); } })];
  if (onReissue) {
    footer.unshift(el("button", { class: "ui-btn", text: bl({ en: "Issue a new link", ja: "リンクを再発行" }), onClick: async () => {
      const next = await onReissue();
      if (next) { m.close(); openInvitationHandover(next, opts); }
    } }));
  }
  const m = uiModal({
    // NOT "sent". The operator is about to do the sending, and the heading is where that has to be honest.
    title: bl({ en: "Invitation created", ja: "招待を作成しました" }),
    body: [
      el("p", { class: "ui-view-desc", text: bl({
        en: "Nothing has been emailed. Give this to " + (inv.to || "them") + " however you normally reach them.",
        ja: (inv.to || "本人") + " に、いつもの連絡手段で以下を渡してください。メールは送信されていません。" }) }),
      el("div", { class: "ui-preview", style: "margin:8px 0;white-space:pre-wrap" , text: text }),
      el("p", { class: "ui-field-hint", text: bl({
        en: "The link works once and expires " + (inv.expires_at || "") + ". Issue a new one if it is lost.",
        ja: "リンクは1回限りで、" + (inv.expires_at || "") + " に失効します。紛失した場合は再発行してください。" }) }),
    ],
    footer: [copyAll, copyLink, ...footer],
  });
}

async function openInviteForm(content) {
  const roles = assignableForCaller(await loadAssignableRoles());
  const emailF = uiField({ name: "email", label: bl({ en: "Email", ja: "メールアドレス" }), required: true, placeholder: "admin@example.com",
    validate: (v) => (/.+@.+\..+/.test(v) ? "" : bl({ en: "Enter a valid email address.", ja: "正しいメールアドレスを入力してください。" })) });
  // ★ SAY WHAT EACH ROLE LETS THEM DO (2026-08-17). The list offered "管理者" and "テナント管理者" side by side
  // with nothing to choose between them — they are the same authority, one of them an older name — plus three
  // more whose difference is the whole decision being made. The hint states it for whichever is selected.
  const roleF = uiField({ name: "role", label: bl({ en: "What they may do", ja: "この人ができること" }), type: "select",
    value: roles.includes("tenant_admin") ? "tenant_admin" : roles[0],
    hint: roleHintBL(roles.includes("tenant_admin") ? "tenant_admin" : roles[0]),
    options: roles.map((r) => ({ value: r, label: roleLabelBL(r) })) });
  {
    const sel = roleF.el.querySelector("select");
    const hint = roleF.el.querySelector(".ui-field-hint") || roleF.el.querySelector("small");
    if (sel && hint) sel.addEventListener("change", () => { hint.textContent = roleHintBL(sel.value); });
  }
  // "Create", not "Send": this product does not send mail, and the button is the first place that has to
  // stop implying otherwise.
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Create invitation", ja: "招待を作成" }) });
  const m = uiModal({ title: bl({ en: "Invite an administrator", ja: "管理者を招待" }),
    // ★ IT SAID THE LINK WOULD BE SENT, AND NOTHING SENDS IT (2026-08-17, read as a customer). No mail leaves
    // this product — the very next screen says so and hands you the link to pass on yourself. A sentence
    // before the action that the screen after it contradicts is the kind of thing people act on.
    body: [emailF.el, roleF.el, el("p", { class: "ui-view-desc", text: bl({
      en: "You get a one-time link to pass to them yourself — no email is sent. They use it to set a password and register an authenticator app.",
      ja: "一度だけ使えるリンクが表示されます。ご自身で本人に渡してください(メールは送られません)。本人はそのリンクでパスワードを決め、認証アプリを登録します。" }) })],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit] });
  submit.addEventListener("click", async () => {
    if (!emailF.validate()) return;
    submit.disabled = true;
    try {
      const invite = async () => {
        const rr = await apiFetch("POST", "/admin/admins/invite", { email: emailF.get(), roles: [roleF.get()] });
        if (!rr.ok) {
          const msg = (rr.body && (rr.body.error || rr.body.message)) || ("HTTP " + rr.status);
          emailF.setError(msg); uiToast(msg, "err");
          return null;
        }
        return (rr.body && rr.body.invitation) || null;
      };
      const invitation = await invite();
      if (!invitation) { submit.disabled = false; return; }
      m.close();
      renderAdministratorsView(content);
      // The link is shown, not announced. "Issue a new link" re-invites the same address in the same tenant,
      // which the backend allows precisely so a lost link can be replaced.
      openInvitationHandover(invitation, { onReissue: invite });
    } catch (e) { submit.disabled = false; uiToast(String(e), "err"); }
  });
  emailF.focus();
}

async function openRolesForm(a, host) {
  const catalog = await loadAssignableRoles();
  const assignable = new Set(assignableForCaller(catalog));
  const current = new Set(a.roles || []);
  // Tenant-internal roles + any role this admin already holds, so an existing operator/owner role stays visible
  // and is never silently dropped. Roles the caller cannot assign are shown disabled and kept as-is on save.
  const display = [...new Set([...catalog.filter((r) => assignable.has(r)), ...(a.roles || [])])];
  const boxes = display.map((r) => { const cb = el("input", { type: "checkbox" }); cb.checked = current.has(r); cb.value = r; cb.disabled = !assignable.has(r); return { r, cb }; });
  const list = el("div", { class: "ui-checklist" }, boxes.map(({ r, cb }) => el("label", { class: "ui-checkrow" }, [cb, el("span", { text: roleLabelBL(r) + (cb.disabled ? bl({ en: " (operator only)", ja: "(運営のみ)" }) : "") })])));
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Save roles", ja: "ロールを保存" }) });
  const m = uiModal({ title: bl({ en: "Change roles", ja: "ロールを変更" }),
    body: [el("p", { class: "ui-view-desc", text: a.email || a.principal_id || "" }), list],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit] });
  submit.addEventListener("click", async () => {
    const sel = boxes.filter(({ cb }) => cb.checked).map(({ r }) => r);
    if (!sel.length) { uiToast(bl({ en: "Pick at least one role.", ja: "ロールを1つ以上選択してください。" }), "err"); return; }
    submit.disabled = true;
    try {
      const r = await apiFetch("POST", "/admin/admins/" + encodeURIComponent(a.principal_id) + "/roles", { roles: sel });
      if (!r.ok) { submit.disabled = false; uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
      m.close(); uiToast(bl({ en: "Roles updated.", ja: "ロールを更新しました。" }), "ok"); renderAdminList(host);
    } catch (e) { submit.disabled = false; uiToast(String(e), "err"); }
  });
}

async function adminStatusChange(a, action, host) {
  if (action === "suspend") {
    const ok = await uiConfirm({ title: bl({ en: "Suspend this administrator?", ja: "この管理者を停止しますか?" }),
      body: (a.email || a.principal_id) + " " + bl({ en: "will not be able to sign in until reactivated.", ja: "は再開するまでサインインできなくなります。" }),
      confirmLabel: bl({ en: "Suspend", ja: "停止" }), danger: true });
    if (!ok) return;
  }
  const r = await apiFetch("POST", "/admin/admins/" + encodeURIComponent(a.principal_id) + "/" + action, {});
  if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
  uiToast(action === "suspend" ? bl({ en: "Suspended.", ja: "停止しました。" }) : bl({ en: "Reactivated.", ja: "再開しました。" }), "ok");
  renderAdminList(host);
}

async function adminDelete(a, host) {
  const ok = await uiConfirm({ title: bl({ en: "Remove this administrator?", ja: "この管理者を削除しますか?" }),
    body: bl({ en: "Permanently removes ", ja: "完全に削除します: " }) + (a.email || a.principal_id) + ".",
    confirmLabel: bl({ en: "Remove", ja: "削除" }), danger: true });
  if (!ok) return;
  const r = await apiFetch("DELETE", "/admin/admins/" + encodeURIComponent(a.principal_id));
  if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
  uiToast(bl({ en: "Administrator removed.", ja: "管理者を削除しました。" }), "ok");
  renderAdminList(host);
}
