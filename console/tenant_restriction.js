"use strict";

// tenant_restriction.js — "Company Account Control" view on the shared ui.js primitives (product-quality
// pattern, see docs/console_ux_design_direction.md). Restrict each SaaS sign-in (Google Workspace, Microsoft
// 365, ChatGPT, Claude) to your company's tenant: the Edge injects the provider's restriction header on the
// decrypted sign-in flow, so a user cannot sign in to a personal or another company's account. Each provider is
// a row; "Configure" opens a typed form (allowed value + enforcement toggle). Saved values are write-only (never
// returned by GET), so the input starts blank and a saved value stays hidden. A history section lists prior
// Replaces the per-provider raw-JSON cards. Change history lives with configuration versioning as a whole,
// not bolted onto each settings screen — this page shows the CURRENT setting and how to change it.
//
// Built-in providers are configured durably on the control plane and distributed to Edges.
// Legacy startup-file rows retain their original update contract.
// Backend:
//   GET  /admin/swg/tenant-restriction            -> {rules:[{provider,saas_application_id,header_name,
//                                                     header_value_ref,active,…}], tenant_restriction_resolver_configured}
//   POST /admin/swg/tenant-restriction            {saas_enablement:{<saas_application_id>:bool},
//                                                  header_value_updates:{<header_value_ref>:value}}
//
// Loaded after app.js; app.js dispatches here for the custom:"swg" group. bl / apiFetch / el / ui* are in scope.

// Per-provider presentation: human-readable name + what the operator types for the allowed value.
const TR_PROVIDER_META = {
  google_workspace: {
    name: "Google Workspace",
    valueLabel: { en: "Allowed domains", ja: "許可ドメイン" },
    placeholder: "example.com, acme.com",
    help: { en: "Comma-separated company domains. Users can only sign in to Google with these domains.", ja: "カンマ区切りの会社ドメイン。ユーザーはこれらのドメインでのみ Google にサインインできます。" },
  },
  microsoft_365: {
    name: "Microsoft 365",
    valueLabel: { en: "Allowed tenant IDs", ja: "許可テナント ID" },
    placeholder: "00000000-0000-0000-0000-000000000000",
    help: { en: "Comma-separated Entra tenant GUIDs. Users can only sign in to these Microsoft 365 tenants.", ja: "カンマ区切りの Entra テナント GUID。ユーザーはこれらの Microsoft 365 テナントにのみサインインできます。" },
  },
  openai_chatgpt: {
    name: "OpenAI ChatGPT",
    valueLabel: { en: "Allowed workspace ID", ja: "許可ワークスペース ID" },
    placeholder: "wsp_xxxxxxxx",
    help: { en: "Your ChatGPT Enterprise/Team workspace ID — restricts ChatGPT to it.", ja: "ChatGPT Enterprise/Team のワークスペース ID — ChatGPT をそのワークスペースに限定します。" },
  },
  anthropic_claude: {
    name: "Anthropic Claude",
    valueLabel: { en: "Allowed org IDs", ja: "許可テナント ID" },
    placeholder: "00000000-0000-0000-0000-000000000000",
    help: { en: "Comma-separated Claude tenant IDs.", ja: "カンマ区切りの Claude テナント ID。" },
  },
};

function trProviderMeta(provider) {
  return TR_PROVIDER_META[provider] || {
    name: provider,
    valueLabel: { en: "Allowed value", ja: "許可値" },
    placeholder: "",
    help: { en: "", ja: "" },
  };
}

function renderTenantRestrictionView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "SaaS Tenant Restriction", ja: "SaaS テナント制限" }) }),
      el("p", { class: "ui-view-desc", text: bl({
        en: "Restrict each SaaS to your company's tenant: the Edge injects the provider's restriction header on the decrypted sign-in flow, so a user cannot sign in to a personal or another company's account.",
        ja: "各 SaaS を自社テナントに限定します。Edge が復号したサインインの通信に、そのサービス指定のヘッダを注入し、個人や他社アカウントへのサインインを防ぎます。",
      }) }),
    ]),
    el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Reload", ja: "再読込" }), onClick: () => renderTenantRestrictionView(content) }),
  ]));

  // Tenant restriction only bites when the sign-in host is decrypted (inspected).
  content.appendChild(el("p", { class: "ui-view-desc", text: bl({
    en: "Requires the SaaS sign-in host to be decrypted (inspected). If Inspection Posture bypasses it, header injection cannot happen.",
    ja: "SaaS のサインインホストが復号(傍受)されている必要があります。傍受の設定で検査から除外していると、ヘッダ注入はできません。",
  }) }));

  const host = el("div", {});
  content.appendChild(host);
  loadTenantRestriction(host, content);

}

async function loadTenantRestriction(host, content) {
  uiState(host, "loading");
  const current = freshRender(host);
  let data;
  try {
    const r = await apiFetch("GET", "/admin/swg/tenant-restriction");
    if (!r.ok) { if (!current()) return; uiState(host, "error", "HTTP " + r.status, { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => loadTenantRestriction(host, content) }); return; }
    data = r.body || {};
  } catch (e) { if (!current()) return; uiState(host, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => loadTenantRestriction(host, content) }); return; }

  if (!current()) return;
  host.innerHTML = "";

  // The restriction header only takes effect when the resolver is configured; warn loudly otherwise.
  if (data.tenant_restriction_resolver_configured === false) {
    host.appendChild(el("div", { class: "ui-state ui-state-error", style: "text-align:left;padding:12px 16px;margin-bottom:16px" },
      el("span", { text: bl({
        en: "The tenant-restriction resolver is not configured on this Edge — enforcement will not take effect.",
        ja: "この Edge ではテナント制限リゾルバが未設定です — 強制は有効になりません。",
      }) })));
  }

  const rules = Array.isArray(data.rules) ? data.rules : [];
  if (!rules.length) { if (!current()) return; uiState(host, "empty", bl({ en: "No SaaS providers are available for tenant restriction.", ja: "テナント制限の対象 SaaS がありません。" })); return; }

  const rows = rules.map((rule) => {
    const meta = trProviderMeta(rule.provider);
    const active = !!rule.active;
    return el("tr", {}, [
      el("td", {}, [
        el("strong", { text: meta.name }),
        el("div", { class: "ui-view-desc" }, el("code", { text: rule.saas_application_id || rule.provider || "" })),
      ]),
      el("td", {}, uiBadge(active ? bl({ en: "Enabled", ja: "有効" }) : (rule.managed && !rule.value_configured ? bl({ en: "Not configured", ja: "未設定" }) : bl({ en: "Off", ja: "オフ" })), active ? "ok" : "off")),
      el("td", { class: "ui-view-desc" }, rule.header_name ? el("code", { text: rule.header_name }) : document.createTextNode("—")),
      el("td", { class: "ui-row-actions" }, el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Configure", ja: "設定" }), onClick: () => openTrForm(content, rule) })),
    ]);
  });
  host.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [
      el("th", { text: bl({ en: "Provider", ja: "プロバイダ" }) }),
      el("th", { text: bl({ en: "Enforcement", ja: "強制" }) }),
      el("th", { text: bl({ en: "Restriction header", ja: "制限ヘッダ" }) }),
      el("th", { class: "ui-row-actions", text: bl({ en: "Actions", ja: "操作" }) }),
    ])),
    el("tbody", {}, rows),
  ]));
}

function openTrForm(content, rule) {
  const meta = trProviderMeta(rule.provider);
  const active = !!rule.active;

  const valueF = uiField({
    name: "value",
    label: bl(meta.valueLabel),
    value: "",
    placeholder: meta.placeholder,
    hint: bl(meta.help) + " " + bl({ en: "Saved values are hidden — leave blank to keep the current one.", ja: "保存済みの値は非表示です — 空欄なら現在の値を維持します。" }),
  });
  const contextF = rule.managed && rule.provider === "microsoft_365" ? uiField({
    name: "context_tenant_id",
    label: bl({ en: "Your Entra directory ID", ja: "管理元の Entra テナント ID" }),
    value: "", placeholder: "00000000-0000-0000-0000-000000000000",
    hint: bl({ en: "The directory that owns this restriction policy. Leave blank to keep the saved ID.", ja: "この制限を管理するテナントのディレクトリ ID。空欄なら保存済み ID を維持します。" }),
  }) : null;
  const enforceF = uiField({
    name: "enforce",
    type: "checkbox",
    value: active,
    label: bl({ en: "Enforce tenant restriction", ja: "テナント制限を強制" }),
    hint: bl({ en: "Enabling requires an allowed value to be configured.", ja: "有効化するには許可値の設定が必要です。" }),
  });

  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Save", ja: "保存" }) });
  const m = uiModal({
    title: bl({ en: "Configure ", ja: "設定: " }) + meta.name,
    body: [valueF.el, ...(contextF ? [contextF.el] : []), enforceF.el],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit],
  });

  submit.addEventListener("click", async () => {
    const value = valueF.get().trim();
    const body = rule.managed ? { provider: rule.provider, enabled: enforceF.get() } : { saas_enablement: {}, header_value_updates: {} };
    if (rule.managed) {
      if (value) body.allowed_value = value;
      if (contextF && contextF.get().trim()) body.context_tenant_id = contextF.get().trim();
    } else {
      if (rule.saas_application_id) body.saas_enablement[rule.saas_application_id] = enforceF.get();
      if (value && rule.header_value_ref) body.header_value_updates[rule.header_value_ref] = value;
    }
    submit.disabled = true;
    try {
      const r = await apiFetch("POST", "/admin/swg/tenant-restriction", body);
      if (!r.ok) {
        submit.disabled = false;
        const msg = (r.body && (r.body.error || r.body.message)) || (typeof r.body === "string" ? r.body : "HTTP " + r.status);
        valueF.setError(msg);
        uiToast(msg, "err");
        return;
      }
      m.close();
      uiToast(bl({ en: "Tenant restriction saved.", ja: "テナント制限を保存しました。" }), "ok");
      renderTenantRestrictionView(content);
    } catch (e) { submit.disabled = false; uiToast(String(e), "err"); }
  });
  valueF.focus();
}


function trWhen(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : window.dsseFormatTime(d);
}

async function rollbackTr(v, content) {
  const ok = await uiConfirm({
    title: bl({ en: "Roll back to this version?", ja: "この版にロールバックしますか?" }),
    body: bl({ en: "Re-applies the configuration from version ", ja: "次の版の設定を再適用します: 版 " }) + (v.version_no != null ? v.version_no : "?") + bl({ en: ". This takes effect immediately.", ja: "。即時に反映されます。" }),
    confirmLabel: bl({ en: "Roll back", ja: "ロールバック" }),
    danger: true,
  });
  if (!ok) return;
  try {
    const r = await apiFetch("POST", "/admin/swg/tenant-restriction/rollback", { version_no: v.version_no });
    if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
    uiToast(bl({ en: "Rolled back.", ja: "ロールバックしました。" }), "ok");
    renderTenantRestrictionView(content);
  } catch (e) { uiToast(String(e), "err"); }
}
