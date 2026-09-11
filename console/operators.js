"use strict";

// operators.js — the people who run this deployment.
//
// ★ THE SCREEN THAT DID NOT EXIST IS WHY THE LAB HAD NO HUMAN OPERATOR AT ALL. Two things are genuinely
// super-admin-only: creating a new organization's first administrator, and adding another super-admin. The
// first now lives in the creation wizard. The second had nowhere to live, so it was never done — and the
// deployment ran on a shared break-glass token that names nobody, for months.
//
// ★ THE LOCKOUT GUARD IS THE SERVER'S. Suspending or deleting the last account able to manage admins is
// refused with a 409 by the API, for the operator tenant like any other. This screen shows why the button is
// refused; it does not invent the rule, because a rule enforced only by a screen is not enforced.
//
// Backend: GET /admin/tenants (to find the operator's own organization), then GET /admin/admins,
// POST /admin/admins/invite, /suspend, /reactivate, DELETE — all with X-Operate-Tenant set to it.

let _operatorTenantId = null;

// operatorTenantIdentity finds the operator's own organization. It is marked in the registry (is_operator)
// rather than named in a setting here, so a Console pointed at a different deployment cannot be wrong about
// which organization is the operator's.
async function operatorTenantIdentity() {
  if (_operatorTenantId) return _operatorTenantId;
  const r = await apiFetch("GET", "/admin/tenants", undefined, "control");
  const tenants = (r.ok && r.body && r.body.tenants) || [];
  const operator = tenants.find((t) => t.is_operator);
  _operatorTenantId = operator ? operator.tenant_id : "";
  return _operatorTenantId;
}

// withOperatorTenant runs one call inside the operator's own organization. It names the organization on the
// call itself rather than moving the Console's selection there and back: a selection that moves, even briefly,
// is the selection anything running at the same moment will read and later restore.
// A deployment with no operator organization gets a refusal, not a call: without a name to send, the request
// would be answered by whichever organization the caller is signed in to, which is never what was asked for.
async function withOperatorTenant(fn) {
  const tenant = await operatorTenantIdentity();
  if (!tenant) return { ok: false, status: 0, noOperatorTenant: true, body: {} };
  return fn(tenant);
}

function renderOperatorsView(content) {
  content.innerHTML = "";
  const add = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "+ Add operator", ja: "+ オペレータを追加" }),
    onClick: () => openOperatorInvite(content) });
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "Operators", ja: "オペレータ" }) }),
      // ★★ THE SAME PROMISE THE TENANT-FACING SCREEN MADE, AND IT IS NOT KEPT HERE EITHER (2026-08-18).
      // "they cannot change a tenant's settings unless that tenant has asked them to" reads as a lock. An
      // operator can set the delegation on any tenant themselves — PUT /admin/operator-delegation is
      // deliberately writable by either side, so that a tenant with no administrator can be stood up at all.
      // Saying so here matters more than on the tenant's screen, because this is the page that tells an
      // operator what their own role is allowed to do, and an operator who believes the door is locked will
      // not think to say they opened it.
      el("p", { class: "ui-view-desc", text: bl({
        en: "The people who run this deployment. They can create tenants and add other operators. Changing a tenant's settings needs that tenant's delegation — which an operator can also switch on themselves, for a tenant being set up; either way it is recorded, and the tenant can withdraw it.",
        ja: "この配備を運用する人。テナントの作成と、オペレータの追加ができます。テナントの設定を変更するには、そのテナントの委任が要ります — その委任はオペレータ自身が入れることもできます（立ち上げ中のテナントのため）。いずれの場合も記録され、テナントは撤回できます。" }) }),
    ]),
    add,
  ]));
  const host = el("div", {});
  content.appendChild(host);
  renderOperatorList(host, content);
  // ★ AN ENABLED BUTTON THAT CANNOT DO WHAT IT SAYS IS WORSE THAN A MISSING ONE. With no operator organization
  // there is no name to send the invitation to, and the invitation lands in whichever organization the caller
  // is signed in to — a customer's, silently. The button says so instead of doing that.
  operatorTenantIdentity().then((t) => {
    if (t) return;
    add.disabled = true;
    add.title = bl({ en: "This deployment has no operator tenant to add an operator to.",
                     ja: "この配備にはオペレータテナントがないため、追加先がありません。" });
  });
}

async function renderOperatorList(host, content) {
  uiState(host, "loading");
  const current = freshRender(host);
  let admins = [];
  let tenantId = "";
  try {
    const r = await withOperatorTenant(async (t) => { tenantId = t; return apiFetch("GET", "/admin/admins", undefined, "control", undefined, t); });
    if (!tenantId) {
      if (!current()) return;
      uiState(host, "empty", bl({
        en: "This deployment has no operator tenant, so there is nobody to list. Start the control plane with -operator-tenant-id.",
        ja: "この配備にはオペレータテナントがありません。コントロールプレーンを -operator-tenant-id 付きで起動してください。" }));
      return;
    }
    if (!r.ok) { if (!current()) return; uiState(host, "error", "HTTP " + r.status, { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderOperatorList(host, content) }); return; }
    admins = (r.body && r.body.admins) || [];
  } catch (e) { if (!current()) return; uiState(host, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderOperatorList(host, content) }); return; }

  if (!admins.length) { if (!current()) return; uiState(host, "empty", bl({ en: "No operators yet.", ja: "オペレータがいません。" })); return; }

  // The last one standing is shown as such. The API refuses to remove it; saying so before the click is the
  // difference between a screen that explains and one that lets somebody discover a 409.
  const active = admins.filter((a) => (a.status || "") === "active");
  const rows = admins.map((a) => {
    const id = a.principal_id || a.admin_principal_id || a.id;
    const isActive = (a.status || "") === "active";
    const lastOne = isActive && active.length === 1;
    const actions = [];
    if (isActive) {
      actions.push(el("button", { class: "ui-btn ui-btn-sm", disabled: lastOne || undefined,
        title: lastOne ? bl({ en: "The last operator cannot be suspended — the deployment would lock itself out.", ja: "最後のオペレータは停止できません。配備が自分を締め出します。" }) : "",
        text: bl({ en: "Suspend", ja: "停止" }), onClick: () => operatorAction(host, content, id, "suspend") }));
    } else {
      actions.push(el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Reactivate", ja: "再開" }), onClick: () => operatorAction(host, content, id, "reactivate") }));
    }
    actions.push(document.createTextNode(" "));
    actions.push(el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", disabled: lastOne || undefined,
      title: lastOne ? bl({ en: "The last operator cannot be removed.", ja: "最後のオペレータは削除できません。" }) : "",
      text: bl({ en: "Remove", ja: "削除" }), onClick: () => removeOperator(host, content, a, id) }));
    return el("tr", {}, [
      el("td", {}, [el("strong", { text: a.email || id }),
        lastOne ? el("div", { class: "ui-view-desc", text: bl({ en: "the only operator — cannot be suspended or removed", ja: "唯一のオペレータ — 停止・削除できません" }) }) : document.createTextNode("")]),
      el("td", {}, uiBadge(a.status === "active" ? bl({ en: "Active", ja: "有効" })
                          : a.status === "pending_activation" ? bl({ en: "Not activated", ja: "未有効化" })
                          : bl({ en: "Suspended", ja: "停止中" }),
                          a.status === "active" ? "ok" : a.status === "pending_activation" ? "warn" : "off")),
      el("td", { class: "ui-view-desc", text: a.last_login_at || bl({ en: "never signed in", ja: "サインインなし" }) }),
      el("td", { class: "ui-row-actions" }, actions),
    ]);
  });
  if (!current()) return;
  host.innerHTML = "";
  host.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [bl({ en: "Operator", ja: "オペレータ" }), bl({ en: "Status", ja: "状態" }),
      bl({ en: "Last signed in", ja: "最終サインイン" }), bl({ en: "Actions", ja: "操作" })].map((x) => el("th", { text: x })))),
    el("tbody", {}, rows),
  ]));
}

async function operatorAction(host, content, id, action) {
  const r = await withOperatorTenant((t) => apiFetch("POST", "/admin/admins/" + encodeURIComponent(id) + "/" + action, {}, "control", undefined, t));
  if (!r.ok) { uiToast((r.body && r.body.error) || ("HTTP " + r.status), "err"); return; }
  uiToast(bl({ en: "Done.", ja: "実行しました。" }), "ok");
  renderOperatorList(host, content);
}

async function removeOperator(host, content, a, id) {
  const ok = await uiConfirm({
    title: bl({ en: "Remove this operator?", ja: "このオペレータを削除?" }),
    body: bl({ en: "\"" + (a.email || id) + "\" will no longer be able to sign in.", ja: "「" + (a.email || id) + "」はサインインできなくなります。" }),
    confirmLabel: bl({ en: "Remove", ja: "削除" }), danger: true });
  if (!ok) return;
  const r = await withOperatorTenant((t) => apiFetch("DELETE", "/admin/admins/" + encodeURIComponent(id), undefined, "control", undefined, t));
  if (!r.ok) { uiToast((r.body && r.body.error) || ("HTTP " + r.status), "err"); return; }
  uiToast(bl({ en: "Removed.", ja: "削除しました。" }), "ok");
  renderOperatorList(host, content);
}

// openOperatorInvite adds another operator. The role is not offered as a choice because there is only one
// correct answer: the operator organization uses the scoped super_admin role, and `owner` is refused there by
// the server anyway — a select with one valid option is a question with no answer.
function openOperatorInvite(content) {
  const emailF = uiField({ name: "email", label: bl({ en: "Work email", ja: "会社メール" }), required: true, placeholder: "ops@your-company.example" });
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Create invitation", ja: "招待を作成" }) });
  const m = uiModal({
    title: bl({ en: "Add an operator", ja: "オペレータを追加" }),
    body: [emailF.el, el("p", { class: "ui-view-desc", text: bl({
      en: "They will be able to create tenants and add other operators. Nothing is emailed — you will be given a link to hand over.",
      ja: "テナントの作成と、オペレータの追加ができるようになります。メールは送信されません。手渡し用のリンクが出ます。" }) })],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit],
  });
  submit.addEventListener("click", async () => {
    if (!emailF.validate()) return;
    submit.disabled = true;
    const invite = async () => {
      // ★ BOTH ROLES, AND THE SECOND ONE IS NOT A CONVENIENCE. super_admin holds five permissions — none of
      // them tenant-side — so an operator created with it ALONE cannot read this very screen: listing the
      // operators needs admin.accounts.read. Measured here, signed in as a freshly created operator: HTTP 403
      // on the page that had just created them.
      //
      // `admin` gives them ordinary administration OF THEIR OWN organization and nothing toward a customer's:
      // what an operator may do inside a customer is decided by that customer's delegation, not by this role.
      const r = await withOperatorTenant((t) => apiFetch("POST", "/admin/admins/invite", { email: emailF.get(), roles: ["super_admin", "admin"] }, "control", undefined, t));
      if (!r.ok) {
        submit.disabled = false;
        const msg = r.noOperatorTenant
          ? bl({ en: "This deployment has no operator tenant. Start the control plane with -operator-tenant-id; until then an invitation has nowhere to go.",
                 ja: "この配備にはオペレータテナントがありません。コントロールプレーンを -operator-tenant-id 付きで起動してください。それまで招待の宛先がありません。" })
          : (r.body && r.body.error) || ("HTTP " + r.status);
        emailF.setError(msg); uiToast(msg, "err"); return null;
      }
      return r.body && r.body.invitation;
    };
    const invitation = await invite();
    if (!invitation) return;
    m.close();
    openInvitationHandover(invitation, { onReissue: invite, onClosed: () => renderOperatorsView(content) });
  });
  emailF.focus();
}
