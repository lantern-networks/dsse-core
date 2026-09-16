"use strict";

// dlpallowlist.js — "DLP Allowlist" (Web & Traffic): the operator list of KNOWN-SAFE values DLP should ignore, to
// cut false positives (a test card 4111 1111 1111 1111, a sample My Number used in a template, a benign shared
// mailbox). Numeric grouping and email case normalize; other values compare exactly. An allowed value raises no
// finding and never trips a block. Backend: GET/POST /admin/dlp-allowlist (the whole list POSTed atomically). The
// scanner keeps only salted hashes; values are stored and distributed for management — so the UI warns
// against entering real secrets.

async function renderDLPAllowlistView(content, opts) {
  content.innerHTML = "";
  if (!(opts && opts.embedded)) content.appendChild(el("div", { class: "ui-view-head" }, el("div", {}, [
    el("h2", { class: "ui-view-title", text: bl({ en: "DLP Allowlist", ja: "DLP 許可リスト" }) }),
  ])));
  content.appendChild(el("p", { class: "ui-view-desc", text: bl({
    en: "Values DLP should treat as known-safe and ignore — a test card, a sample My Number in a template, a benign shared mailbox. Numeric identifiers ignore grouping, and email addresses ignore case. Other values, including custom identifiers and secrets, must match exactly. Other matches remain detectable.",
    ja: "DLP が既知の安全な値として無視する値 — テストカード、テンプレート内のサンプルのマイナンバー、無害な共有メールなど。数値の識別子は区切り、メールアドレスは大文字小文字を無視します。カスタム識別子や秘密情報を含む他の値は完全一致で照合し、別の値の検出は維持します。",
  }) }));
  // Safety note: these are stored to let you manage them — do not paste real secrets.
  content.appendChild(el("div", { class: "ui-view-desc", style: "border-left:3px solid var(--ui-warn,#c60);padding:0.4rem 0.75rem;margin:0.25rem 0 0.75rem", text: bl({
    en: "⚠ Only add values you have confirmed are NOT sensitive. Do not paste real tenant data or live secrets here.",
    ja: "⚠ 機密でないと確認済みの値のみ追加してください。実際のテナントデータや本番の秘密情報は貼り付けないでください。",
  }) }));
  const section = el("div", {});
  content.appendChild(section);
  let _values = [];

  async function load() {
    uiState(section, "loading");
    try { const r = await apiFetch("GET", "/admin/dlp-allowlist"); if (!r.ok) throw new Error("HTTP " + r.status); _values = (r.body && r.body.values) || []; }
    catch (e) { uiState(section, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: load }); return; }
    render();
  }

  async function save(next, okMsg) {
    const r = await apiFetch("POST", "/admin/dlp-allowlist", { values: next });
    if (!r.ok) throw new Error((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status));
    _values = (r.body && r.body.values) || next;
    uiToast(okMsg || bl({ en: "Saved", ja: "保存しました" }), "ok");
    render();
  }

  function render() {
    section.innerHTML = "";
    section.appendChild(el("div", { class: "ui-toolbar" }, [
      el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "+ Add value", ja: "+ 値を追加" }), onClick: addValue }),
      el("span", { class: "ui-view-desc", text: _values.length + " " + bl({ en: "allowlisted", ja: "件" }) }),
    ]));
    if (!_values.length) {
      section.appendChild(emptyBox(bl({ en: "No allowlisted values. Add a test card or sample identifier that keeps triggering false positives.", ja: "許可リストは空です。誤検知を繰り返すテストカードやサンプル識別子を追加できます。" })));
      return;
    }
    section.appendChild(simpleTable(
      [bl({ en: "Known-safe value", ja: "既知の安全な値" }), ""],
      _values.map((v, i) => [
        el("code", { text: v }),
        el("div", { class: "ui-row-actions" }, el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Remove", ja: "削除" }), onClick: () => remove(i) })),
      ])
    ));
  }

  function addValue() {
    const valueF = uiField({ name: "value", label: bl({ en: "Value DLP should ignore (e.g. a test card)", ja: "DLP が無視する値(例: テストカード)" }), placeholder: "4111 1111 1111 1111" });
    const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Add", ja: "追加" }), onClick: onSave });
    const saveError = el("div", { class: "ui-state ui-state-error", role: "alert", style: "display:none" });
    const modal = uiModal({ title: bl({ en: "Add a known-safe value", ja: "既知の安全な値を追加" }), body: [valueF.el, saveError], footer: [
      el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => modal.close() }), submit,
    ] });
    valueF.focus();
    async function onSave() {
      if (submit.disabled) return;
      saveError.style.display = "none";
      const val = String(valueF.get()).trim();
      if (!val) { valueF.focus(); return; }
      if (_values.some((x) => x === val)) { uiToast(bl({ en: "Already on the list.", ja: "既に登録済みです。" }), "info"); return; }
      submit.disabled = true;
      try { await save(_values.concat([val]), bl({ en: "Value allowlisted", ja: "値を許可リストに追加しました" })); modal.close(); }
      catch (e) { saveError.textContent = String(e.message || e); saveError.style.display = ""; saveError.scrollIntoView({ block: "nearest" }); }
      finally { submit.disabled = false; }
    }
  }

  async function remove(i) {
    const ok = await uiConfirm({
      title: bl({ en: "Remove from allowlist?", ja: "許可リストから削除?" }),
      body: bl({ en: 'DLP will resume flagging "' + _values[i] + '".', ja: '「' + _values[i] + '」を DLP が再び検出するようになります。' }),
      confirmLabel: bl({ en: "Remove", ja: "削除" }), danger: true,
    });
    if (!ok) return;
    try { await save(_values.filter((_, idx) => idx !== i), bl({ en: "Removed", ja: "削除しました" })); }
    catch (e) { uiToast(String(e.message || e), "err"); }
  }

  load();
}
