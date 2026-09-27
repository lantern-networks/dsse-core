"use strict";

// apitokens.js — "API Tokens & Roles" on the shared ui.js pattern (control plane). List + create (name + role)
// + rotate + revoke, with the secret shown ONCE in a copy-now modal. Replaces the raw-JSON tokens card.
// Backend (control plane): GET /admin/api-tokens -> {tokens:[…]}, POST /admin/api-tokens {name,roles},
// POST /admin/api-tokens/{id}/rotate, POST /admin/api-tokens/{id}/revoke.

const _TOK_PLANE = "control";
let _tokSearch = "";

function renderApiTokensView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "API Tokens & Roles", ja: "API トークン・ロール" }) }),
      el("p", { class: "ui-view-desc", text: bl({ en: "Tokens for programmatic access, each limited to a role. A token's secret is shown only once when created or rotated.", ja: "プログラムからのアクセス用トークン(各ロールに制限)。シークレットは作成/更新時に一度だけ表示されます。" }) }),
    ]),
    el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "+ Create token", ja: "+ トークン作成" }), onClick: () => openTokenForm(content) }),
  ]));
  const search = el("input", { class: "ui-input ui-search", type: "search", placeholder: bl({ en: "Search tokens…", ja: "トークンを検索…" }) });
  search.value = _tokSearch;
  const host = el("div", {});
  search.addEventListener("input", () => { _tokSearch = search.value; renderTokList(host); });
  content.appendChild(el("div", { class: "ui-toolbar" }, [search, el("span", { class: "ui-spacer" }),
    el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Reload", ja: "再読込" }), onClick: () => renderTokList(host) })]));
  content.appendChild(host);
  renderTokList(host);
}

async function renderTokList(host) {
  uiState(host, "loading");
  const current = freshRender(host);
  let tokens;
  try {
    const r = await apiFetch("GET", "/admin/api-tokens", undefined, _TOK_PLANE);
    if (!r.ok) { if (!current()) return; uiState(host, "error", "HTTP " + r.status, { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderTokList(host) }); return; }
    tokens = (r.body && r.body.tokens) || [];
  } catch (e) { if (!current()) return; uiState(host, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderTokList(host) }); return; }
  const q = _tokSearch.trim().toLowerCase();
  const filtered = tokens.filter((t2) => !q || (t2.name || "").toLowerCase().includes(q) || (Array.isArray(t2.roles) ? t2.roles.join(" ") : "").toLowerCase().includes(q));
  if (!tokens.length) { if (!current()) return; uiState(host, "empty", bl({ en: "No API tokens yet. Create one for a script or integration.", ja: "API トークンがありません。スクリプトや連携用に作成してください。" })); return; }
  if (!filtered.length) { if (!current()) return; uiState(host, "empty", bl({ en: "No matches.", ja: "一致なし。" })); return; }
  const rows = filtered.map((t2) => {
    const id = t2.id || t2.token_id || "";
    const revoked = t2.status === "revoked" || t2.revoked === true;
    const actions = el("div", { class: "ui-row-actions" });
    if (!revoked) {
      actions.appendChild(el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Rotate", ja: "更新" }), onClick: () => rotateToken(id, host) }));
      actions.appendChild(document.createTextNode(" "));
      actions.appendChild(el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Revoke", ja: "失効" }), onClick: () => revokeToken(id, t2.name, host) }));
    }
    return el("tr", {}, [
      el("td", {}, [el("strong", { text: t2.name || id }), el("div", { class: "ui-view-desc" }, el("code", { text: id }))]),
      el("td", {}, uiBadge(Array.isArray(t2.roles) ? t2.roles.join(", ") : "—", "off")),
      el("td", {}, uiBadge(revoked ? bl({ en: "Revoked", ja: "失効" }) : bl({ en: "Active", ja: "有効" }), revoked ? "danger" : "ok")),
      el("td", { class: "ui-view-desc", text: t2.created_at ? window.dsseFormatTime(t2.created_at) : "—" }),
      el("td", { class: "ui-row-actions" }, actions),
    ]);
  });
  if (!current()) return;
  host.innerHTML = "";
  host.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [bl({ en: "Token", ja: "トークン" }), bl({ en: "Role", ja: "ロール" }), bl({ en: "Status", ja: "状態" }), bl({ en: "Created", ja: "作成" }), bl({ en: "Actions", ja: "操作" })].map((x) => el("th", { text: x })))),
    el("tbody", {}, rows),
  ]));
}

async function loadRoleOptions() {
  const r = await apiFetch("GET", "/admin/rbac/catalog", undefined, _TOK_PLANE);
  const roles = r.body && r.body.api_token_roles;
  if (!r.ok || !Array.isArray(roles) || !roles.length || roles.some(x=>!x || typeof x.role !== "string" || !x.role)) throw new Error("Role catalog is unavailable");
  const preferred = r.body.api_token_default_role;
  const ordered = [...roles.filter(x=>x.role === preferred), ...roles.filter(x=>x.role !== preferred)];
  return ordered.map(x=>({value:x.role,label:x.role}));
}

async function openTokenForm(content) {
  let options;
  try { options = await loadRoleOptions(); }
  catch (e) { uiToast(bl({en:"Could not load token roles. Try again.",ja:"トークンのロールを取得できませんでした。再試行してください。"}),"err"); return; }
  const nameF = uiField({ name: "name", label: bl({ en: "Token name", ja: "トークン名" }), required: true, placeholder: bl({ en: "e.g. ci-pipeline", ja: "例: ci-pipeline" }) });
  const roleF = uiField({ name: "role", label: bl({ en: "Role", ja: "ロール" }), type: "select", value: options[0].value, options, hint: bl({ en: "What this token is allowed to do.", ja: "このトークンに許可する操作の範囲。" }) });
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Create token", ja: "トークン作成" }) });
  const m = uiModal({ title: bl({ en: "Create an API token", ja: "API トークンを作成" }), body: [nameF.el, roleF.el], footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit] });
  submit.addEventListener("click", async () => {
    if (submit.disabled || !nameF.validate()) return;
    submit.disabled = true;
    try {
      const r = await apiFetch("POST", "/admin/api-tokens", { name: nameF.get(), roles: [roleF.get()] }, _TOK_PLANE);
      if (!r.ok) { submit.disabled = false; const msg = (r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status); nameF.setError(msg); uiToast(msg, "err"); return; }
      m.close();
      showSecretOnce(r.body, bl({ en: "Token created", ja: "トークンを作成しました" }));
      renderApiTokensView(content);
    } catch (e) { submit.disabled = false; uiToast(String(e), "err"); }
  });
  nameF.focus();
}

// showSecretOnce surfaces a freshly-issued secret in a copy-now modal (it cannot be retrieved again).
function showSecretOnce(body, title) {
  const secret = body && body.raw_token;
  if (typeof secret !== "string" || !secret) { uiToast(bl({en:"The token secret could not be retrieved. Check the token list before creating or rotating again.",ja:"トークンの秘密値を取得できませんでした。追加の作成や更新の前に一覧を確認してください。"}), "err"); return; }
  const m = uiModal({ title: title,
    body: [el("p", { class: "ui-view-desc", text: bl({ en: "Copy this secret now — it will not be shown again.", ja: "このシークレットを今コピーしてください。再表示はできません。" }) }), el("div", { class: "ui-preview", text: String(secret) })],
    footer: [el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Done", ja: "完了" }), onClick: () => m.close() })] });
}

async function rotateToken(id, host) {
  const ok = await uiConfirm({ title: bl({ en: "Rotate this token?", ja: "このトークンを更新?" }), body: bl({ en: "Issues a new secret and invalidates the old one. Anything using the old secret stops working until updated.", ja: "新しいシークレットを発行し旧シークレットを無効化します。旧シークレットを使う処理は更新まで動かなくなります。" }), confirmLabel: bl({ en: "Rotate", ja: "更新" }), danger: true });
  if (!ok) return;
  let r; try { r = await apiFetch("POST", "/admin/api-tokens/" + encodeURIComponent(id) + "/rotate", {}, _TOK_PLANE); } catch (e) { uiToast(bl({en:"Rotation could not be confirmed. Reload the list before retrying.",ja:"更新結果を確認できませんでした。一覧を再読込してから再操作してください。"}),"err"); return; }
  if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
  showSecretOnce(r.body, bl({ en: "Token rotated", ja: "トークンを更新しました" }));
  renderTokList(host);
}

async function revokeToken(id, name, host) {
  const ok = await uiConfirm({ title: bl({ en: "Revoke this token?", ja: "このトークンを失効?" }), body: bl({ en: "\"" + (name || id) + "\" stops working immediately and cannot be restored.", ja: "「" + (name || id) + "」は即座に使えなくなり、復元できません。" }), confirmLabel: bl({ en: "Revoke", ja: "失効" }), danger: true });
  if (!ok) return;
  let r; try { r = await apiFetch("POST", "/admin/api-tokens/" + encodeURIComponent(id) + "/revoke", {}, _TOK_PLANE); } catch (e) { uiToast(bl({en:"Revocation could not be confirmed. Reload the list before retrying.",ja:"失効結果を確認できませんでした。一覧を再読込してから再操作してください。"}),"err"); return; }
  if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
  uiToast(bl({ en: "Token revoked.", ja: "トークンを失効しました。" }), "ok");
  renderTokList(host);
}
