"use strict";

// dlppolicies.js — "DLP Policies" (Web & Traffic): the reusable named DLP Policy objects (S5,
// docs/dlp_policy_ux_integration.md). A DLP Policy bundles WHAT to detect (identifiers from the Sensitive-Data
// library) + the ACTION + instance scope (+ device-risk conditions, S4). An Internet Access rule SELECTS a policy
// by name instead of repeating inline config. Backend: GET/POST/DELETE /admin/dlp-policies.

function dlpActionLabel(a) {
  return { observe: bl({ en: "Observe", ja: "監視" }), warn: bl({ en: "Warn", ja: "警告" }), block: bl({ en: "Block", ja: "遮断" }), authenticate: bl({ en: "Require verification", ja: "認証要求" }) }[a] || a || "—";
}
function dlpInstanceScopeLabel(s) {
  return { corporate: bl({ en: "Corporate only", ja: "自社のみ" }), personal: bl({ en: "Personal / outside only", ja: "個人/社外のみ" }) }[s] || bl({ en: "Any account", ja: "すべて" });
}

// Every dependency is required for a safe edit: an unavailable detector library
// must not turn an existing selection into an empty one on the next save.
function dlpEditorList(response, key, validItem) {
  if (!response || !response.ok) throw new Error(key + ": HTTP " + (response && response.status || "unavailable"));
  const body = response.body;
  if (!body || !Object.hasOwn(body, key) ||
      (body[key] !== null && !Array.isArray(body[key]))) throw new Error(key + ": invalid response");
  const list = body[key] || []; // These APIs may encode an empty slice as null.
  if (!list.every(validItem)) throw new Error(key + ": invalid entry");
  return list;
}

async function renderDLPPoliciesView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, el("div", {}, [
    el("h2", { class: "ui-view-title", text: bl({ en: "DLP Policies", ja: "DLP ポリシー" }) }),
    el("p", { class: "ui-view-desc", text: bl({
      en: "Reusable DLP policies — what to detect (from the Sensitive Data library) + the action + which account. Select a policy on an Internet Access rule to apply it to that traffic. Define once, use on many rules.",
      ja: "再利用可能な DLP ポリシー — 何を検出するか(機密データライブラリから)+ アクション + 対象アカウント。「インターネットアクセス」のルールでポリシーを選択して適用します。一度定義して多数のルールで利用。",
    }) }),
  ])));
  const section = el("div", {});
  content.appendChild(section);
  let _policies = [];
  let _library = { custom: [], edm: [] };
  let _orgDomains = []; // the "our company" domains that decide corporate vs personal (S6)

  async function load() {
    const current = freshRender(section);
    uiState(section, "loading");
    try {
      const [pr, cr, fr, od] = await Promise.all([apiFetch("GET", "/admin/dlp-policies"), apiFetch("GET", "/admin/dlp-classifiers"), apiFetch("GET", "/admin/dlp-fingerprints"), apiFetch("GET", "/admin/organization-domains")]);
      const named = (x) => x && typeof x.name === "string" && x.name.trim() !== "";
      const policies = dlpEditorList(pr, "policies", (x) => named(x) && typeof x.id === "string" && x.id && Array.isArray(x.identifiers) && x.identifiers.every((id) => typeof id === "string" && id));
      const custom = dlpEditorList(cr, "classifiers", named);
      const edm = dlpEditorList(fr, "datasets", named);
      const domains = dlpEditorList(od, "domains", (x) => typeof x === "string" && x.trim() !== "");
      if (!current()) return;
      _policies = policies;
      _library = { custom, edm };
      _orgDomains = domains;
    } catch (e) { if (!current()) return; uiState(section, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: load }); return; }
    render();
  }

  function render() {
    section.innerHTML = "";
    section.appendChild(el("div", { class: "ui-toolbar" }, [
      el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "+ Add policy", ja: "+ ポリシーを追加" }), onClick: () => openEditor(null) }),
      el("span", { class: "ui-view-desc", text: _policies.length + " " + bl({ en: "policies", ja: "ポリシー" }) }),
    ]));
    if (!_policies.length) {
      section.appendChild(emptyBox(bl({ en: "No DLP policies yet. Add one, then select it on an Internet Access rule.", ja: "DLP ポリシーはまだありません。追加して 「インターネットアクセス」のルールで選択します。" })));
      return;
    }
    section.appendChild(simpleTable(
      [bl({ en: "Name", ja: "名前" }), bl({ en: "Detects", ja: "検出" }), bl({ en: "Action", ja: "アクション" }), bl({ en: "Account", ja: "アカウント" }), bl({ en: "Device risk", ja: "デバイスリスク" }), ""],
      _policies.map((p) => [
        el("span", { text: p.name }),
        el("span", {}, (p.identifiers || []).map((id) => uiBadge(id, "warn"))),
        uiBadge(dlpActionLabel(p.on_match), p.on_match === "block" ? "err" : p.on_match === "observe" ? "off" : "warn"),
        el("span", { class: "ui-view-desc", text: dlpInstanceScopeLabel(p.instance_scope) }),
        el("span", { class: "ui-view-desc", text: (p.device_risk && p.device_risk.length) ? (p.device_risk.length + " " + bl({ en: "condition(s)", ja: "条件" })) : "—" }),
        el("div", { class: "ui-row-actions" }, [
          el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Edit", ja: "編集" }), onClick: () => openEditor(p) }),
          el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Delete", ja: "削除" }), onClick: () => remove(p) }),
        ]),
      ])
    ));
  }

  function openEditor(existing) {
    const nameF = uiField({ name: "name", label: bl({ en: "Policy name", ja: "ポリシー名" }), required: true, value: existing ? existing.name : "", placeholder: bl({ en: "Block PII to personal accounts", ja: "個人アカウントへの個人情報の送信を遮断" }) });
    const actionF = uiField({ name: "action", label: bl({ en: "Action on match", ja: "一致時のアクション" }), type: "select", value: existing ? existing.on_match : "observe", options: [
      { value: "observe", label: dlpActionLabel("observe") }, { value: "warn", label: dlpActionLabel("warn") }, { value: "block", label: dlpActionLabel("block") }, { value: "authenticate", label: dlpActionLabel("authenticate") },
    ] });
    const scopeF = uiField({ name: "scope", label: bl({ en: "Apply to which account?", ja: "どのアカウントに適用?" }), type: "select", value: (existing && existing.instance_scope) || "any", options: [
      { value: "any", label: dlpInstanceScopeLabel("any") }, { value: "corporate", label: dlpInstanceScopeLabel("corporate") }, { value: "personal", label: dlpInstanceScopeLabel("personal") },
    ] });
    // Corporate/Personal depends on the ORGANIZATION DOMAINS (S6). Show what "our company" is, warn when unset
    // (scoped rules would never fire), and offer to edit — the discoverable home DLP references.
    const orgBox = el("div", { style: "margin:0 0 0.4rem 1rem" });
    const syncOrg = () => {
      orgBox.innerHTML = "";
      if (scopeF.get() === "any") return;
      if (_orgDomains.length) {
        orgBox.appendChild(el("span", { class: "ui-view-desc", text: bl({ en: "Our company = ", ja: "自社 = " }) + _orgDomains.join(", ") + "  " }));
      } else {
        orgBox.appendChild(el("span", { class: "ui-view-desc", style: "color:var(--ui-warn,#c60)", text: bl({ en: "⚠ No tenant domains set — Corporate/Personal can't be determined, so this rule never fires. ", ja: "⚠ 自社ドメイン未設定 — 自社/個人を判定できず、このルールは発火しません。 " }) }));
      }
      orgBox.appendChild(el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Edit tenant domains…", ja: "自社ドメインを編集…" }), onClick: editOrgDomains }));
    };
    scopeF.el.querySelector("select").addEventListener("change", syncOrg);
    // Identifier picker from the library.
    const have = (existing && existing.identifiers) || [];
    const idFields = [];
    const idBox = el("div", { style: "margin-left:1rem" });
    const group = (title, items) => {
      if (!items.length) return;
      idBox.appendChild(el("div", { class: "ui-view-desc", style: "margin:0.3rem 0 0.15rem", text: title }));
      items.forEach((it) => { const f = uiField({ name: "id_" + it.id, label: it.label, type: "checkbox", value: have.indexOf(it.id) >= 0 }); idFields.push({ id: it.id, f }); idBox.appendChild(f.el); });
    };
    group(bl({ en: "Built-in identifiers", ja: "組み込み識別子" }), DLP_BUILTIN_IDENTIFIERS.map((b) => ({ id: b.id, label: bl(b.label) })));
    group(bl({ en: "Custom identifiers", ja: "カスタム識別子" }), _library.custom.map((c) => ({ id: c.name, label: c.name })));
    group(bl({ en: "Exact-Data-Match datasets", ja: "完全一致データ" }), _library.edm.map((d) => ({ id: d.name, label: d.name + " (" + d.count + ")" })));

    // Device-risk condition (S4,): a COMPOSITE condition (not a raw count) that raises the device's risk so
    // risk-based rules act. Defaults chosen to catch real exfil while excluding FP noise (≥2 distinct types, same
    // destination, short burst).
    const dr = (existing && existing.device_risk && existing.device_risk[0]) || null;
    const drEnableF = uiField({ name: "dr_on", label: bl({ en: "Raise device risk on an abnormal burst", ja: "異常なバースト時にデバイスリスクを上げる" }), type: "checkbox", value: !!dr });
    const drCountF = uiField({ name: "dr_count", label: bl({ en: "Detections (min)", ja: "検出数(最小)" }), type: "text", value: String((dr && dr.min_count) || 10) });
    const drTypesF = uiField({ name: "dr_types", label: bl({ en: "Distinct confidential types (min)", ja: "異なる機密データ種類(最小)" }), type: "text", value: String((dr && dr.min_distinct_types) || 2), hint: bl({ en: "≥2 excludes single-type false positives (e.g. telemetry ids).", ja: "≥2 で単一型の誤検知(テレメトリ ID 等)を除外。" }) });
    const drSameF = uiField({ name: "dr_same", label: bl({ en: "All to the same destination", ja: "すべて同一宛先へ" }), type: "checkbox", value: dr ? !!dr.same_destination : true });
    const drWinF = uiField({ name: "dr_win", label: bl({ en: "Within", ja: "計測期間" }), type: "select", value: String((dr && dr.window_seconds) || 300), options: [
      { value: "300", label: bl({ en: "5 minutes", ja: "5 分" }) }, { value: "900", label: bl({ en: "15 minutes", ja: "15 分" }) }, { value: "3600", label: bl({ en: "1 hour", ja: "1 時間" }) },
    ] });
    const drClassF = uiField({ name: "dr_class", label: bl({ en: "Only to", ja: "対象宛先" }), type: "select", value: (dr && dr.destination_class) || "any", options: [
      { value: "any", label: bl({ en: "Any destination", ja: "すべての宛先" }) }, { value: "personal", label: bl({ en: "Personal / outside-org only", ja: "個人/社外のみ" }) },
    ] });
    const drBox = el("div", { style: "margin-left:1rem" }, [drCountF.el, drTypesF.el, drSameF.el, drWinF.el, drClassF.el]);
    const syncDr = () => { drBox.style.display = drEnableF.get() ? "" : "none"; };
    drEnableF.el.querySelector("input").addEventListener("change", syncDr);

    const m = uiModal({
      title: existing ? bl({ en: "Edit DLP policy", ja: "DLP ポリシーを編集" }) : bl({ en: "Add DLP policy", ja: "DLP ポリシーを追加" }),
      body: [nameF.el, actionF.el, scopeF.el, orgBox, el("div", { class: "ui-view-desc", style: "margin:0.4rem 0 0.15rem", text: bl({ en: "Detect", ja: "検出対象" }) }), idBox,
        el("div", { class: "ui-view-desc", style: "margin:0.6rem 0 0.15rem", text: bl({ en: "Device risk (optional)", ja: "デバイスリスク(任意)" }) }), drEnableF.el, drBox],
      footer: [
        el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }),
        el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Save", ja: "保存" }), onClick: onSave }),
      ],
    });
    nameF.focus();
    syncDr();
    syncOrg();

    // editOrgDomains opens a small editor for the organization ("our company") domains (S6), then refreshes the note.
    function editOrgDomains() {
      const df = uiField({ name: "orgd", label: bl({ en: "Tenant domains (one per line)", ja: "自社ドメイン(1 行に 1 件)" }), type: "textarea", value: _orgDomains.join("\n"), placeholder: "acme.com\nacme.co.jp", hint: bl({ en: "The domains that count as your company. An account whose email domain matches is 'Corporate'; any other confirmed domain is 'Personal'.", ja: "自社とみなすドメイン。メールドメインが一致するアカウントは「自社」、それ以外の確定ドメインは「個人/社外」。" }) });
      const dm = uiModal({
        title: bl({ en: "Tenant domains", ja: "自社ドメイン" }),
        body: [df.el],
        footer: [
          el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => dm.close() }),
          el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Save", ja: "保存" }), onClick: async () => {
            const domains = df.get().split("\n").map((s) => s.trim()).filter(Boolean);
            try {
              const r = await apiFetch("PUT", "/admin/organization-domains", { domains });
              if (!r.ok) throw new Error((r.body && r.body.error) || ("HTTP " + r.status));
              _orgDomains = (r.body && r.body.domains) || domains;
              uiToast(bl({ en: "Tenant domains saved", ja: "自社ドメインを保存しました" }), "ok");
              dm.close();
              syncOrg();
            } catch (e) { uiToast(String(e.message || e), "danger"); }
          } }),
        ],
      });
      df.focus();
    }

    async function onSave() {
      if (!nameF.validate()) { nameF.focus(); return; }
      const ids = idFields.filter((x) => x.f.get()).map((x) => x.id);
      if (!ids.length) { uiToast(bl({ en: "Pick at least one identifier to detect.", ja: "検出する識別子を 1 つ以上選んでください。" }), "err"); return; }
      const obj = { name: nameF.get(), identifiers: ids, on_match: actionF.get(), instance_scope: scopeF.get() === "any" ? "" : scopeF.get() };
      if (existing) obj.id = existing.id;
      obj.device_risk = drEnableF.get() ? [{
        min_count: parseInt(drCountF.get(), 10) || 0,
        min_distinct_types: parseInt(drTypesF.get(), 10) || 0,
        same_destination: drSameF.get(),
        window_seconds: parseInt(drWinF.get(), 10) || 300,
        destination_class: drClassF.get() === "any" ? "" : drClassF.get(),
        severity: "high",
      }] : [];
      try {
        const r = await apiFetch("POST", "/admin/dlp-policies", obj);
        if (!r.ok) throw new Error((r.body && r.body.error) || ("HTTP " + r.status));
        _policies = (r.body && r.body.policies) || _policies;
        uiToast(bl({ en: "Policy saved", ja: "ポリシーを保存しました" }), "ok");
        m.close();
        render();
      } catch (e) { uiToast(String(e.message || e), "danger"); }
    }
  }

  async function remove(p) {
    const ok = await uiConfirm({ title: bl({ en: "Delete policy?", ja: "ポリシーを削除?" }), body: bl({ en: 'Rules that select "' + p.name + '" will no longer apply DLP.', ja: '「' + p.name + '」を選択しているルールは DLP を適用しなくなります。' }), confirmLabel: bl({ en: "Delete", ja: "削除" }), danger: true });
    if (!ok) return;
    try {
      const r = await apiFetch("DELETE", "/admin/dlp-policies?id=" + encodeURIComponent(p.id));
      if (!r.ok) throw new Error("HTTP " + r.status);
      _policies = (r.body && r.body.policies) || _policies.filter((x) => x.id !== p.id);
      uiToast(bl({ en: "Policy deleted", ja: "ポリシーを削除しました" }), "ok");
      render();
    } catch (e) { uiToast(String(e.message || e), "danger"); }
  }

  await load();
}
