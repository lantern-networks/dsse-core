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
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "IdP integration", ja: "IdP 連携" }) }),
      el("p", { class: "ui-view-desc", text: bl({
        en: "The trusted sign-in providers this tenant authenticates users against. One is the default; an access rule's Authenticate action can require a specific provider. The client secret is write-only and never shown again.",
        ja: "このテナントがユーザー認証に使う信頼済みサインインプロバイダ。1つが既定です。アクセスルールの「本人確認を要求」で、使うプロバイダを指定できます。クライアントシークレットは書き込み専用で、再表示されません。",
      }) }),
    ]),
    el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "+ Add provider", ja: "+ プロバイダを追加" }), onClick: () => openIdpForm(content) }),
  ]));
  const search = el("input", { class: "ui-input ui-search", type: "search", placeholder: bl({ en: "Search providers…", ja: "プロバイダを検索…" }) });
  search.value = _idpSearch;
  const host = el("div", {});
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
  try {
    const r = await apiFetch("GET", "/admin/idp-connections");
    if (!r.ok) { if (!current()) return; uiState(host, "error", "HTTP " + r.status, { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderIdPList(host) }); return; }
    connections = (r.body && r.body.connections) || [];
    defaultID = (r.body && r.body.default_idp_id) || "";
  } catch (e) { if (!current()) return; uiState(host, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderIdPList(host) }); return; }

  const q = _idpSearch.trim().toLowerCase();
  const filtered = connections.filter((c) => !q ||
    (c.display_name || "").toLowerCase().includes(q) ||
    (c.idp_id || "").toLowerCase().includes(q) ||
    (c.issuer || "").toLowerCase().includes(q));
  if (!connections.length) { if (!current()) return; uiState(host, "empty", bl({ en: "No sign-in providers yet. Add one so your access rules can require it.", ja: "サインインプロバイダがありません。アクセスルールから要求できるよう追加してください。" })); return; }
  if (!filtered.length) { if (!current()) return; uiState(host, "empty", bl({ en: "No providers match your search.", ja: "検索に一致するプロバイダがありません。" })); return; }

  const rows = filtered.map((c) => {
    const isDefault = c.idp_id === defaultID;
    const nameCell = [el("strong", { text: c.display_name || c.idp_id }), el("div", { class: "ui-view-desc" }, el("code", { text: c.idp_id }))];
    if (isDefault) nameCell.splice(1, 0, document.createTextNode(" "), uiBadge(bl({ en: "Default", ja: "既定" }), "ok"));
    const actions = [];
    if (!isDefault) actions.push(el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Set default", ja: "既定にする" }), onClick: () => setIdpDefault(c, host) }), document.createTextNode(" "));
    actions.push(
      el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Test", ja: "テスト" }), onClick: () => testIdp(c) }), document.createTextNode(" "),
      el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Edit", ja: "編集" }), onClick: () => openIdpForm(document.getElementById("content"), c) }), document.createTextNode(" "),
      el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Delete", ja: "削除" }), onClick: () => removeIdp(c, host) }),
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

async function setIdpDefault(c, host) {
  const r = await apiFetch("POST", "/admin/idp-connections/" + encodeURIComponent(c.idp_id) + "/default");
  if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
  uiToast(bl({ en: "Default provider updated.", ja: "既定プロバイダを更新しました。" }), "ok");
  renderIdPList(host);
}

// Non-interactive connectivity probe (discovery + JWKS reachable/parseable, issuer match) — no end-user login.
async function testIdp(c) {
  uiToast(bl({ en: "Testing…", ja: "テスト中…" }), "info");
  let res;
  try {
    const r = await apiFetch("GET", "/admin/idp-connections/" + encodeURIComponent(c.idp_id) + "/test");
    if (!r.ok) { uiToast((typeof r.body === "string" ? r.body : (r.body && (r.body.error || r.body.message))) || ("HTTP " + r.status), "err"); return; }
    res = r.body || {};
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

async function removeIdp(c, host) {
  const label = c.display_name || c.idp_id;
  const ok = await uiConfirm({
    title: bl({ en: "Delete this provider?", ja: "このプロバイダを削除?" }),
    body: bl({ en: "Permanently removes the sign-in provider \"" + label + "\". Access rules that require it will no longer be able to authenticate users through it.", ja: "サインインプロバイダ「" + label + "」を完全に削除します。これを要求するアクセスルールはこのプロバイダで認証できなくなります。" }),
    confirmLabel: bl({ en: "Delete permanently", ja: "完全に削除" }), danger: true,
  });
  if (!ok) return;
  const r = await apiFetch("DELETE", "/admin/idp-connections/" + encodeURIComponent(c.idp_id));
  if (!r.ok) { uiToast((typeof r.body === "string" ? r.body : (r.body && (r.body.error || r.body.message))) || ("HTTP " + r.status), "err"); return; }
  uiToast(bl({ en: "Provider deleted.", ja: "プロバイダを削除しました。" }), "ok");
  renderIdPList(host);
}

function openIdpForm(content, existing) {
  existing = existing || null;
  const idF = uiField({ name: "id", label: bl({ en: "Provider ID", ja: "プロバイダ ID" }), required: true, value: existing ? existing.idp_id : "",
    placeholder: "idp_corp", hint: bl({ en: "A short unique key. Editing an existing provider keeps this fixed.", ja: "短い一意キー。既存プロバイダの編集では固定されます。" }),
    validate: (v) => (/\s/.test(v) ? bl({ en: "No spaces allowed.", ja: "空白は使えません。" }) : "") });
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
  const m = uiModal({
    title: existing ? bl({ en: "Edit sign-in provider", ja: "サインインプロバイダを編集" }) : bl({ en: "Add a sign-in provider", ja: "サインインプロバイダを追加" }),
    body: [
      idF.el, nameF.el, typeF.el, issuerF.el, authzF.el, tokenF.el, jwksF.el, clientF.el, secretF.el, domainsF.el, domainModeF.el, pkceF.el,
      el("p", { class: "ui-view-desc", text: bl({ en: "Advanced claim mapping", ja: "詳細: クレームマッピング" }) }),
      acrF.el, amrF.el, groupsF.el, hdF.el, caF.el,
    ],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit],
  });
  submit.addEventListener("click", async () => {
    if (!idF.validate() || !issuerF.validate() || !clientF.validate()) return;
    submit.disabled = true;
    const body = {
      idp_id: idF.get(),
      display_name: nameF.get(),
      type: typeF.get(),
      issuer: issuerF.get(),
      authorization_endpoint: authzF.get(),
      token_endpoint: tokenF.get(),
      jwks_uri: jwksF.get(),
      client_id: clientF.get(),
      domain_mode: domainModeF.get(),
      verified_domains: domainsF.get().split(",").map((s) => s.trim()).filter(Boolean),
      use_pkce: pkceF.get(),
      acr_claim: acrF.get(),
      amr_claim: amrF.get(),
      groups_claim: groupsF.get(),
      hosted_domain_claim: hdF.get(),
      ca_pem: caF.get(),
    };
    if (secretF.get()) body.client_secret = secretF.get();
    try {
      const r = await apiFetch("POST", "/admin/idp-connections", body);
      if (!r.ok) { submit.disabled = false; const msg = (typeof r.body === "string" ? r.body : (r.body && (r.body.error || r.body.message))) || ("HTTP " + r.status); idF.setError(msg); uiToast(msg, "err"); return; }
      m.close();
      uiToast(existing ? bl({ en: "Provider saved.", ja: "プロバイダを保存しました。" }) : bl({ en: "Provider added.", ja: "プロバイダを追加しました。" }), "ok");
      renderIdPConnectionsView(content);
    } catch (e) { submit.disabled = false; uiToast(String(e), "err"); }
  });
  (existing ? nameF : idF).focus();
}
