"use strict";

// idp.js — "IdP integration" on the shared ui.js pattern: a list of the trusted end-user sign-in providers
// (OIDC / SAML-style connections) this organization authenticates against, with one marked as the default,
// plus an add/edit modal, a connectivity test, set-default, and delete-with-confirmation. Replaces the raw
// input/JSON card. Backend (edge plane):
//   GET    /admin/idp-connections -> {connections:[…], default_idp_id}
//   POST   /admin/idp-connections {idp_id,display_name,type,issuer,authorization_endpoint,token_endpoint,
//          jwks_uri,client_id,client_secret(write-only),domain_mode,verified_domains[],use_pkce,acr_claim,
//          amr_claim,groups_claim,hosted_domain_claim}
//   POST   /admin/idp-connections/{id}/default
//   GET    /admin/idp-connections/{id}/test -> {ok, checks:[{name,ok,detail}]}
//   DELETE /admin/idp-connections/{id}

let _idpSearch = "";

function idpObject(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }
function idpText(v) { return typeof v === "string" && v.trim() !== ""; }
function idpConnection(c) {
  return idpObject(c) && ["idp_id", "tenant_id", "issuer", "authorization_endpoint", "client_id"].every(k => idpText(c[k])) &&
    /^[A-Za-z0-9_-]+$/.test(c.idp_id) && ["oidc","entra","google","okta"].includes(c.type) &&
    ["email_domain","google_hd"].includes(c.domain_mode) && !c.client_secret &&
    ["display_name","jwks_uri","token_endpoint","groups_claim","acr_claim","amr_claim","hosted_domain_claim","ca_pem"].every(k => c[k] == null || typeof c[k] === "string") &&
    (c.use_pkce == null || typeof c.use_pkce === "boolean") && (c.verified_domains == null || (Array.isArray(c.verified_domains) && c.verified_domains.every(idpText)));
}
function idpError(r) { return r?.body?.error || r?.body?.message || ("HTTP " + (r?.status || "unknown")); }
function idpUncertain() { return bl({en:"The provider change could not be confirmed and may already be applied. Reload before retrying.",ja:"プロバイダの変更結果を確認できません。反映済みの可能性があるため、再読込してから再試行してください。"}); }
function idpRefresh(content) {
  if (content.__idpAnchor?.isConnected && content.contains(content.__idpAnchor)) renderIdPConnectionsView(content);
}
function idpNotice(content, message) { content.__idpNotice = message; }
function idpShowNotice(content, host) {
  if (content.__idpNotice) host.appendChild(el("div", {class:"ui-callout ui-callout-warn",role:"alert",text:content.__idpNotice}));
}
async function idpGet(path) {
  const r = await apiFetch("GET", path, undefined, "control");
  if (!r.ok) throw new Error(idpError(r));
  return r.body;
}
function idpConfirmConnection(r, expected) {
  if (!r?.ok) throw new Error(idpError(r));
  const c = r.body;
  const keys = ["idp_id","tenant_id","type","display_name","issuer","authorization_endpoint","token_endpoint","jwks_uri","client_id","domain_mode","acr_claim","amr_claim","groups_claim","hosted_domain_claim","ca_pem"];
  if (!idpConnection(c) || keys.some(k => (c[k] || "") !== (expected[k] || "")) || !!c.use_pkce !== !!expected.use_pkce ||
      JSON.stringify(c.verified_domains || []) !== JSON.stringify(expected.verified_domains || [])) throw new Error(idpUncertain());
}

function idpTypeLabel(t) {
  switch (t) {
    case "oidc": return bl({ en: "OpenID Connect", ja: "OpenID Connect" });
    case "entra": return bl({ en: "Microsoft Entra ID", ja: "Microsoft Entra ID" });
    case "google": return bl({ en: "Google Workspace", ja: "Google Workspace" });
    case "okta": return bl({ en: "Okta", ja: "Okta" });
    default: return t || "—";
  }
}

function idpDomainModeLabel(m) {
  return m === "google_hd"
    ? bl({ en: "Google hosted domain", ja: "Google ホストドメイン" })
    : bl({ en: "Email domain", ja: "メールドメイン" });
}

function renderIdPConnectionsView(content) {
  content.innerHTML = "";
  const add = el("button", {class:"ui-btn ui-btn-primary",text:bl({en:"+ Add provider",ja:"+ プロバイダを追加"}),onClick:()=>openIdpForm(content)});
  add.disabled = true; content.__idpAnchor = add;
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "IdP integration", ja: "IdP 連携" }) }),
      el("p", { class: "ui-view-desc", text: bl({
        en: "The trusted sign-in providers this tenant authenticates users against. One is the default; an access rule's Authenticate action can require a specific provider. The client secret is write-only and never shown again.",
        ja: "このテナントがユーザー認証に使う信頼済みサインインプロバイダ。1つが既定です。アクセスルールの「本人確認を要求」で、使うプロバイダを指定できます。クライアントシークレットは書き込み専用で、再表示されません。",
      }) }),
    ]),
    add,
  ]));
  const search = el("input", { class: "ui-input ui-search", type: "search", placeholder: bl({ en: "Search providers…", ja: "プロバイダを検索…" }) });
  search.value = _idpSearch;
  const host = el("div", {});
  host.__idpContent = content; host.__idpAdd = add;
  search.addEventListener("input", () => { _idpSearch = search.value; renderIdPList(host); });
  content.appendChild(el("div", { class: "ui-toolbar" }, [search, el("span", { class: "ui-spacer" }),
    el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Reload", ja: "再読込" }), onClick: () => renderIdPList(host) })]));
  content.appendChild(host);
  renderIdPList(host);
}

async function renderIdPList(host) {
  uiState(host, "loading");
  const current = freshRender(host);
  let connections, defaultID;
  const content = host.__idpContent;
  host.__idpAdd.disabled = true;
  try {
    const [body, tenant] = await Promise.all([idpGet("/admin/idp-connections"), idpGet("/admin/tenant")]);
    if (!idpObject(tenant) || !idpText(tenant.tenant_id) || !idpObject(body) || !Array.isArray(body.connections) || typeof body.default_idp_id !== "string" ||
        !body.connections.every(c => idpConnection(c) && c.tenant_id === tenant.tenant_id) || new Set(body.connections.map(c => c.idp_id)).size !== body.connections.length ||
        (body.connections.length ? !body.connections.some(c => c.idp_id === body.default_idp_id) : body.default_idp_id !== "")) throw new Error("Invalid provider response");
    if (!current()) return;
    connections = body.connections; defaultID = body.default_idp_id; content.__idpTenant = tenant.tenant_id;
    host.__idpAdd.disabled = !!content.__idpPending;
  } catch (e) {
    if (!current()) return;
    uiState(host, "error", String(e), {label:bl({en:"Retry",ja:"再試行"}),onClick:()=>renderIdPList(host)});
    idpShowNotice(content, host); return;
  }

  const q = _idpSearch.trim().toLowerCase();
  const filtered = connections.filter((c) => !q ||
    (c.display_name || "").toLowerCase().includes(q) ||
    (c.idp_id || "").toLowerCase().includes(q) ||
    (c.issuer || "").toLowerCase().includes(q));
  if (!connections.length) { if (!current()) return; uiState(host, "empty", bl({ en: "No sign-in providers yet. Add one so your access rules can require it.", ja: "サインインプロバイダがありません。アクセスルールから要求できるよう追加してください。" })); idpShowNotice(content, host); return; }
  if (!filtered.length) { if (!current()) return; uiState(host, "empty", bl({ en: "No providers match your search.", ja: "検索に一致するプロバイダがありません。" })); idpShowNotice(content, host); return; }

  const rows = filtered.map((c) => {
    const isDefault = c.idp_id === defaultID;
    const nameCell = [el("strong", { text: c.display_name || c.idp_id }), el("div", { class: "ui-view-desc" }, el("code", { text: c.idp_id }))];
    if (isDefault) nameCell.splice(1, 0, document.createTextNode(" "), uiBadge(bl({ en: "Default", ja: "既定" }), "ok"));
    const actions = [];
    if (!isDefault) actions.push(el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Set default", ja: "既定にする" }), disabled:content.__idpPending ? true : null, onClick: () => setIdpDefault(c, host) }), document.createTextNode(" "));
    actions.push(
      el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Test", ja: "テスト" }), onClick: () => testIdp(c) }), document.createTextNode(" "),
      el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Edit", ja: "編集" }), disabled:content.__idpPending ? true : null, onClick: () => openIdpForm(content, c) }), document.createTextNode(" "),
      el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Delete", ja: "削除" }), disabled:content.__idpPending ? true : null, onClick: () => removeIdp(c, host) }),
    );
    return el("tr", {}, [
      el("td", {}, nameCell),
      el("td", { text: idpTypeLabel(c.type) }),
      el("td", { class: "ui-view-desc", text: c.issuer || "—" }),
      el("td", { class: "ui-view-desc", text: (c.verified_domains && c.verified_domains.length) ? c.verified_domains.join(", ") : "—" }),
      el("td", { class: "ui-row-actions" }, actions),
    ]);
  });
  if (!current()) return;
  host.innerHTML = "";
  idpShowNotice(content, host);
  host.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [
      bl({ en: "Provider", ja: "プロバイダ" }),
      bl({ en: "Type", ja: "種別" }),
      bl({ en: "Issuer", ja: "発行者" }),
      bl({ en: "Verified domains", ja: "検証済みドメイン" }),
      bl({ en: "Actions", ja: "操作" }),
    ].map((x, i) => el("th", i === 4 ? { class: "ui-row-actions", text: x } : { text: x })))),
    el("tbody", {}, rows),
  ]));
  host.appendChild(el("p", { class: "ui-view-desc", text: bl({ en: "Showing ", ja: "表示 " }) + filtered.length + " / " + connections.length }));
}

async function idpRowChange(c, host, remove) {
  const content = host.__idpContent;
  if (content.__idpPending) return;
  content.__idpPending = true;
  const controls = content.querySelectorAll("button"); controls.forEach(b => { b.disabled = true; });
  try {
    if (remove && !await uiConfirm({title:bl({en:"Delete this provider?",ja:"このプロバイダを削除?"}),body:bl({en:"Access rules that require this provider will no longer be able to authenticate users through it.",ja:"このプロバイダを要求するアクセスルールは、これを使ってユーザーを認証できなくなります。"}),confirmLabel:bl({en:"Delete permanently",ja:"完全に削除"}),danger:true})) return;
    let r;
    try { r = await apiFetch(remove ? "DELETE" : "POST", "/admin/idp-connections/" + encodeURIComponent(c.idp_id) + (remove ? "" : "/default"), undefined, "control"); }
    catch (_) { throw new Error(idpUncertain()); }
    if (!r?.ok) throw new Error(idpError(r));
    if (!idpObject(r.body) || r.body.id !== c.idp_id || r.body.status !== (remove ? "deleted" : "default_set")) throw new Error(idpUncertain());
    idpNotice(content, "");
    uiToast(remove ? bl({en:"Provider deleted.",ja:"プロバイダを削除しました。"}) : bl({en:"Default provider updated.",ja:"既定プロバイダを更新しました。"}), "ok");
  } catch (e) { idpNotice(content, e.message || String(e)); }
  finally { content.__idpPending = false; controls.forEach(b => { b.disabled = false; }); await renderIdPList(host); }
}
async function setIdpDefault(c, host) { return idpRowChange(c, host, false); }
async function removeIdp(c, host) { return idpRowChange(c, host, true); }

// Non-interactive connectivity probe (discovery + JWKS reachable/parseable, issuer match) — no end-user login.
async function testIdp(c) {
  uiToast(bl({ en: "Testing…", ja: "テスト中…" }), "info");
  let res;
  try {
    const r = await apiFetch("GET", "/admin/idp-connections/" + encodeURIComponent(c.idp_id) + "/test", undefined, "control");
    if (!r.ok) { uiToast((typeof r.body === "string" ? r.body : (r.body && (r.body.error || r.body.message))) || ("HTTP " + r.status), "err"); return; }
    res = r.body;
    if (!idpObject(res) || typeof res.ok !== "boolean" || !Array.isArray(res.checks) || !res.checks.length ||
        !res.checks.every(k => idpObject(k) && idpText(k.name) && typeof k.ok === "boolean" && typeof k.detail === "string")) throw new Error("Invalid provider test response");
  } catch (e) { uiToast(String(e), "err"); return; }
  const checks = res.checks || [];
  const body = checks.length
    ? [el("table", { class: "ui-table" }, [
        el("thead", {}, el("tr", {}, [bl({ en: "Check", ja: "チェック" }), bl({ en: "Result", ja: "結果" })].map((x) => el("th", { text: x })))),
        el("tbody", {}, checks.map((k) => el("tr", {}, [
          el("td", {}, [el("div", { text: k.name }), k.detail ? el("div", { class: "ui-view-desc", text: k.detail }) : null]),
          el("td", {}, uiBadge(k.ok ? bl({ en: "OK", ja: "OK" }) : bl({ en: "Failed", ja: "NG" }), k.ok ? "ok" : "danger")),
        ]))),
      ])]
    : [el("p", { class: "ui-view-desc", text: res.ok ? bl({ en: "All checks passed.", ja: "すべてのチェックに合格しました。" }) : bl({ en: "The provider did not pass its checks.", ja: "プロバイダはチェックに合格しませんでした。" }) })];
  const m = uiModal({
    title: bl({ en: "Test: ", ja: "テスト: " }) + (c.display_name || c.idp_id),
    body: [el("p", { class: "ui-view-desc" }, uiBadge(res.ok ? bl({ en: "Reachable", ja: "到達可能" }) : bl({ en: "Not reachable", ja: "到達不可" }), res.ok ? "ok" : "danger"))].concat(body),
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Close", ja: "閉じる" }), onClick: () => m.close() })],
  });
  uiToast(res.ok ? bl({ en: "Provider reachable.", ja: "プロバイダは到達可能です。" }) : bl({ en: "Provider not reachable.", ja: "プロバイダに到達できません。" }), res.ok ? "ok" : "err");
}

function openIdpForm(content, existing) {
  if (content.__idpPending || !content.__idpTenant) return;
  existing = existing || null;
  const idF = uiField({ name: "id", label: bl({ en: "Provider ID", ja: "プロバイダ ID" }), required: true, value: existing ? existing.idp_id : "",
    placeholder: "idp_corp", hint: bl({ en: "A short unique key. Editing an existing provider keeps this fixed.", ja: "短い一意キー。既存プロバイダの編集では固定されます。" }),
    validate: (v) => (!/^[A-Za-z0-9_-]+$/.test(v) ? bl({ en: "Use letters, numbers, underscore or hyphen.", ja: "英数字・アンダースコア・ハイフンを使用してください。" }) : "") });
  if (existing) idF.el.querySelector("input").setAttribute("readonly", "true");
  const nameF = uiField({ name: "name", label: bl({ en: "Display name", ja: "表示名" }), value: existing ? existing.display_name : "", placeholder: bl({ en: "Corporate sign-in", ja: "社内サインイン" }) });
  const typeF = uiField({ name: "type", label: bl({ en: "Type", ja: "種別" }), type: "select", value: existing ? existing.type : "oidc", options: [
    { value: "oidc", label: idpTypeLabel("oidc") },
    { value: "entra", label: idpTypeLabel("entra") },
    { value: "google", label: idpTypeLabel("google") },
    { value: "okta", label: idpTypeLabel("okta") },
  ] });
  const issuerF = uiField({ name: "issuer", label: bl({ en: "Issuer URL", ja: "発行者 URL" }), required: true, value: existing ? existing.issuer : "", placeholder: "https://login.example.com" });
  // ★ REQUIRED BY THE SERVER, OPTIONAL ON THIS FORM (2026-08-17, walked as a customer administrator). The form
  // marked three fields with an asterisk; filling exactly those and pressing Add produced a toast reading
  // "authorization_endpoint is required" — the server's wire field name, in English, detached from any field,
  // on the last step of a customer finishing their own setup. The neighbouring token endpoint says it is
  // discovered automatically, which makes the omission read as deliberate.
  //
  // Marking it required is the honest half: the form now refuses before the request, in this console's words,
  // against the field. (Discovering it from the issuer is the better answer and belongs on the server, which
  // already fetches /.well-known/openid-configuration to VERIFY a connection — see idp_connection_check.go.)
  const authzF = uiField({ name: "authz", label: bl({ en: "Authorization endpoint", ja: "認可エンドポイント" }), required: true, value: existing ? existing.authorization_endpoint : "", placeholder: "https://login.example.com/authorize", hint: bl({ en: "Your provider's sign-in URL. Usually the issuer with /authorize or /protocol/openid-connect/auth on the end.", ja: "サインインさせる先の URL。多くの場合、発行者 URL の末尾に /authorize や /protocol/openid-connect/auth が付いたものです。" }) });
  const tokenF = uiField({ name: "token", label: bl({ en: "Token endpoint (optional)", ja: "トークンエンドポイント(任意)" }), value: existing ? existing.token_endpoint : "", placeholder: "https://login.example.com/token", hint: bl({ en: "Left blank, it is discovered automatically.", ja: "空欄なら自動検出します。" }) });
  const jwksF = uiField({ name: "jwks", label: bl({ en: "JWKS URI (optional)", ja: "JWKS URI(任意)" }), value: existing ? existing.jwks_uri : "", placeholder: "https://login.example.com/keys" });
  const clientF = uiField({ name: "client", label: bl({ en: "Client ID", ja: "クライアント ID" }), required: true, value: existing ? existing.client_id : "" });
  const secretF = uiField({ name: "secret", label: bl({ en: "Client secret", ja: "クライアントシークレット" }), type: "password", value: "",
    placeholder: existing ? bl({ en: "Leave blank to keep current secret", ja: "空欄なら現在のシークレットを維持" }) : "",
    hint: bl({ en: "Write-only — it is never shown again.", ja: "書き込み専用 — 再表示されません。" }) });
  const domainsF = uiField({ name: "domains", label: bl({ en: "Verified domains (optional)", ja: "検証済みドメイン(任意)" }), value: existing ? (existing.verified_domains || []).join(", ") : "", placeholder: "example.com, corp.example.com", hint: bl({ en: "Comma-separated.", ja: "カンマ区切り。" }) });
  const domainModeF = uiField({ name: "domainmode", label: bl({ en: "Domain match", ja: "ドメイン照合" }), type: "select", value: existing ? existing.domain_mode : "email_domain", options: [
    { value: "email_domain", label: idpDomainModeLabel("email_domain") },
    { value: "google_hd", label: idpDomainModeLabel("google_hd") },
  ] });
  const pkceF = uiField({ name: "pkce", label: bl({ en: "Use PKCE", ja: "PKCE を使う" }), type: "checkbox", value: existing ? !!existing.use_pkce : false });
  // Advanced: custom assurance/identity claim names — for a provider that carries them under non-standard names
  // (e.g. Microsoft Entra Conditional Access uses "acrs"). Blank = the standard acr / amr / groups / hd.
  const acrF = uiField({ name: "acr", label: bl({ en: "Assurance claim (optional)", ja: "保証レベルクレーム(任意)" }), value: existing ? existing.acr_claim : "", placeholder: "acr", hint: bl({ en: "e.g. acrs for Microsoft Entra. Blank = standard acr.", ja: "例: Entra は acrs。空欄=標準 acr。" }) });
  const amrF = uiField({ name: "amr", label: bl({ en: "Methods claim (optional)", ja: "認証方式クレーム(任意)" }), value: existing ? existing.amr_claim : "", placeholder: "amr" });
  const groupsF = uiField({ name: "groups", label: bl({ en: "Groups claim (optional)", ja: "グループクレーム(任意)" }), value: existing ? existing.groups_claim : "", placeholder: "groups" });
  const hdF = uiField({ name: "hd", label: bl({ en: "Hosted-domain claim (optional)", ja: "ホストドメインクレーム(任意)" }), value: existing ? existing.hosted_domain_claim : "", placeholder: "hd" });
  // ★★★ A PROVIDER THE PUBLIC WEB DOES NOT VOUCH FOR (2026-09-03). This deployment does not only send a
  // browser to the provider: it calls it itself, for the token exchange and for the signing keys. Those calls
  // verify the provider's certificate, and until this field existed they could only verify it against the
  // public web's authorities — so a provider inside the organization's own network could be described here in
  // full and never complete a sign-in.
  const caF = uiField({ name: "ca", label: bl({ en: "Certificate authority (optional)", ja: "証明書の発行元(任意)" }),
    type: "textarea", value: existing ? (existing.ca_pem || "") : "",
    placeholder: "-----BEGIN CERTIFICATE-----",
    hint: bl({ en: "Only for a provider inside your own network. Paste the certificate of whoever issues its TLS certificate. Blank means it is one the public internet already trusts, which is the case for Entra, Okta and Google.",
               ja: "社内にあるプロバイダのときだけ。その TLS 証明書を発行している側の証明書を貼ってください。空欄なら、インターネットが既に信頼している発行元だという意味です(Entra・Okta・Google はこちら)。" }) });

  const submit = el("button", { class: "ui-btn ui-btn-primary", text: existing ? bl({ en: "Save changes", ja: "変更を保存" }) : bl({ en: "Add provider", ja: "プロバイダを追加" }) });
  const error = el("div", {class:"ui-field-error-msg",role:"alert",style:"display:block;white-space:pre-wrap"});
  let pending = false, closed = false, completed = false;
  const tenant = content.__idpTenant;
  const m = uiModal({
    onClose:()=>{ closed = true; if (pending && !completed) { idpNotice(content, idpUncertain()); idpRefresh(content); } },
    title: existing ? bl({ en: "Edit sign-in provider", ja: "サインインプロバイダを編集" }) : bl({ en: "Add a sign-in provider", ja: "サインインプロバイダを追加" }),
    body: [
      idF.el, nameF.el, typeF.el, issuerF.el, authzF.el, tokenF.el, jwksF.el, clientF.el, secretF.el, domainsF.el, domainModeF.el, pkceF.el,
      el("p", { class: "ui-view-desc", text: bl({ en: "Advanced claim mapping", ja: "詳細: クレームマッピング" }) }),
      acrF.el, amrF.el, groupsF.el, hdF.el, caF.el, error,
    ],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit],
  });
  submit.addEventListener("click", async () => {
    if (pending || closed || content.__idpPending) return;
    if (![idF,issuerF,authzF,clientF].map(f => f.validate()).every(Boolean)) return;
    error.textContent = "";
    const body = {
      tenant_id: tenant,
      idp_id: idF.get(),
      display_name: nameF.get(),
      type: typeF.get(),
      issuer: issuerF.get(),
      authorization_endpoint: authzF.get(),
      token_endpoint: tokenF.get(),
      jwks_uri: jwksF.get(),
      client_id: clientF.get(),
      domain_mode: domainModeF.get(),
      verified_domains: [...new Set(domainsF.get().split(",").map(s => s.trim().toLowerCase()).filter(Boolean))],
      use_pkce: pkceF.get(),
      acr_claim: acrF.get(),
      amr_claim: amrF.get(),
      groups_claim: groupsF.get(),
      hosted_domain_claim: hdF.get(),
      ca_pem: caF.get(),
    };
    if (secretF.get()) body.client_secret = secretF.get();
    const controls = m.el.querySelectorAll("input,select,textarea,button");
    pending = true; content.__idpPending = true; controls.forEach(c => { c.disabled = true; });
    try {
      let r;
      try { r = await apiFetch("POST", "/admin/idp-connections", body, "control"); }
      catch (_) { throw new Error(idpUncertain()); }
      idpConfirmConnection(r, body);
      completed = true; idpNotice(content, "");
      if (!closed) { m.close(); uiToast(existing ? bl({en:"Provider saved.",ja:"プロバイダを保存しました。"}) : bl({en:"Provider added.",ja:"プロバイダを追加しました。"}), "ok"); }
    } catch (e) { const message = e.message || String(e); idpNotice(content, message); if (!closed) error.textContent = message; }
    finally {
      pending = false; content.__idpPending = false; controls.forEach(c => { c.disabled = false; });
      if (closed) idpRefresh(content);
    }
  });
  (existing ? nameF : idF).focus();
}
