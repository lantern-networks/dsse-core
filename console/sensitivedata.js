"use strict";

// sensitivedata.js — "Sensitive Data" (Web & Traffic): the DLP LIBRARY, one page with tabs. It DEFINES what
// sensitive data is (Identifiers = built-in + custom; Exact-Data-Match datasets) and the Allowlist tuning. It has
// no "enforce" control — detectors here are inert until an Internet Access rule references them. This consolidates
// the former three standalone pages (S3, docs/dlp_policy_ux_integration.md). Each tab reuses its existing render
// function in embedded mode (no duplicate page header).

// dlpBuiltinIdentifiers is the read-only reference list shown at the top of the Identifiers tab — the detectors
// every rule can select without any setup.
const DLP_BUILTIN_IDENTIFIERS = [
  { id: "my_number", label: { en: "My Number", ja: "マイナンバー" } },
  { id: "corporate_number", label: { en: "Corporate Number", ja: "法人番号" } },
  { id: "credit_card", label: { en: "Credit card", ja: "クレジットカード" } },
  { id: "api_key", label: { en: "API keys / secrets", ja: "API鍵 / シークレット" } },
  { id: "email", label: { en: "Email address", ja: "メールアドレス" } },
  { id: "phone", label: { en: "Phone number (JP mobile)", ja: "電話番号(携帯)" } },
];

async function renderSensitiveDataView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, el("div", {}, [
    el("h2", { class: "ui-view-title", text: bl({ en: "Sensitive Data", ja: "機密データ" }) }),
    el("p", { class: "ui-view-desc", text: bl({
      en: "Define what sensitive data looks like — built-in and custom identifiers, and exact-data-match datasets — plus the allowlist that trims false positives. These are a library: they do nothing until you reference them on an Internet Access rule (Detect + Action).",
      ja: "機密データの定義 — 組み込み/カスタム識別子、完全一致データセット、そして誤検知を減らす許可リスト。これらはライブラリで、「インターネットアクセス」のルール(検出と処理)で参照するまで何も起きません。",
    }) }),
  ])));

  const body = el("div", {});
  const tabs = [
    { id: "identifiers", label: bl({ en: "Identifiers", ja: "識別子" }) },
    { id: "edm", label: bl({ en: "Exact-Data-Match", ja: "完全一致データ" }) },
    { id: "allowlist", label: bl({ en: "Allowlist", ja: "許可リスト" }) },
  ];
  let _current = "identifiers";
  const bar = uiTabs(tabs, _current, (id) => { _current = id; renderTab(); paint(); });
  content.appendChild(bar);
  content.appendChild(body);

  function paint() {
    [...bar.querySelectorAll(".ui-tab")].forEach((b, i) => b.classList.toggle("active", tabs[i].id === _current));
  }

  function renderTab() {
    if (_current === "identifiers") {
      body.innerHTML = "";
      // Built-in reference (read-only) — the always-available detectors.
      body.appendChild(el("div", { class: "ui-view-desc", style: "margin:0.5rem 0 0.25rem", text: bl({ en: "Built-in identifiers (always available)", ja: "組み込み識別子(常に利用可)" }) }));
      body.appendChild(el("div", { class: "ui-toolbar" }, DLP_BUILTIN_IDENTIFIERS.map((b) => uiBadge(bl(b.label), "off"))));
      // Custom identifiers editor (embedded — no duplicate header).
      const customBox = el("div", { style: "margin-top:0.75rem" });
      body.appendChild(el("div", { class: "ui-view-desc", style: "margin:0.5rem 0 0.25rem", text: bl({ en: "Custom identifiers", ja: "カスタム識別子" }) }));
      body.appendChild(customBox);
      renderDLPClassifiersView(customBox, { embedded: true });
    } else if (_current === "edm") {
      renderDLPFingerprintsView(body, { embedded: true });
    } else {
      renderDLPAllowlistView(body, { embedded: true });
    }
  }
  renderTab();
}
