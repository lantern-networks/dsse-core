"use strict";

// dlpfingerprints.js — "DLP Exact-Data-Match" (Web & Traffic): the operator fingerprints a SENSITIVE dataset (a
// list of exact values — customer record ids, employee numbers, account keys) under a named identifier, and DLP
// then detects any of those exact values in egress and reports them under that name. NON-SECRET storage: the
// values are fingerprinted (salted-hashed) at upload and NEVER stored or shown back — the list shows only each
// dataset's name + value count. Backend: GET/POST/DELETE /admin/dlp-fingerprints. See docs/dlp_vision_and_roadmap.md.

async function renderDLPFingerprintsView(content, opts) {
  content.innerHTML = "";
  if (!(opts && opts.embedded)) content.appendChild(el("div", { class: "ui-view-head" }, el("div", {}, [
    el("h2", { class: "ui-view-title", text: bl({ en: "DLP Exact-Data-Match", ja: "DLP 完全一致データ" }) }),
    el("p", { class: "ui-view-desc", text: bl({
      en: "Fingerprint your own sensitive data — a column of tenant record ids, employee numbers, account keys — so DLP flags those exact values wherever they appear in uploads. The values are hashed on upload and never stored or shown back; only the dataset name and count are kept.",
      ja: "自社の機密データ(テナントレコード ID、社員番号、口座キーなどの一覧)をフィンガープリント化し、その完全一致をアップロード内で検出します。値はアップロード時にハッシュ化され、保存も再表示もされません(保持されるのはデータセット名と件数のみ)。",
    }) }),
  ])));
  const section = el("div", {});
  content.appendChild(section);
  let _datasets = [];

  async function load() {
    uiState(section, "loading");
    try { const r = await apiFetch("GET", "/admin/dlp-fingerprints"); if (!r.ok) throw new Error("HTTP " + r.status); _datasets = (r.body && r.body.datasets) || []; }
    catch (e) { uiState(section, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: load }); return; }
    render();
  }

  function render() {
    section.innerHTML = "";
    section.appendChild(el("div", { class: "ui-toolbar" }, [
      el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "+ Add dataset", ja: "+ データセットを追加" }), onClick: () => addDataset() }),
      el("span", { class: "ui-view-desc", text: _datasets.length + " " + bl({ en: "datasets", ja: "データセット" }) }),
    ]));
    if (!_datasets.length) {
      section.appendChild(emptyBox(bl({
        en: "No datasets yet. Add one — paste the exact values (one per line) you want DLP to catch precisely, like a list of tenant ids.",
        ja: "データセットはまだありません。DLP に正確に検出させたい値(テナント ID の一覧など)を 1 行に 1 件で貼り付けて追加します。",
      })));
      return;
    }
    section.appendChild(simpleTable(
      [bl({ en: "Dataset (identifier)", ja: "データセット(識別子)" }), bl({ en: "Values fingerprinted", ja: "登録件数" }), ""],
      _datasets.map((d) => [
        el("code", { text: d.name }),
        el("span", { text: String(d.count) }),
        el("div", { class: "ui-row-actions" }, [
          el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Replace…", ja: "再登録…" }), onClick: () => addDataset(d.name) }),
          el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Delete", ja: "削除" }), onClick: () => remove(d.name) }),
        ]),
      ])
    ));
  }

  // addDataset(existingName?): open an editor for a new or replacement dataset. Values are POSTed (hashed server-
  // side); on success only the count comes back.
  function addDataset(existingName) {
    const nameF = uiField({
      name: "name", label: bl({ en: "Dataset name (identifier)", ja: "データセット名(識別子)" }), required: true,
      value: typeof existingName === "string" ? existingName : "",
      placeholder: "customer_record",
      hint: bl({ en: "Lowercase letters, digits, underscores (e.g. customer_record). Detections are reported under this name.", ja: "英小文字・数字・アンダースコア(例: customer_record)。検出はこの名前で報告されます。" }),
      validate: (v) => (/^[a-z][a-z0-9_]{1,39}$/.test(v) ? "" : bl({ en: "2–40 chars, lowercase snake_case.", ja: "2〜40 文字の英小文字スネークケース。" })),
    });
    const valuesF = uiField({
      name: "values", label: bl({ en: "Exact values (one per line)", ja: "完全一致の値(1 行に 1 件)" }), type: "textarea",
      placeholder: "CUST-100482\nCUST-100915\nEMP-556677",
      hint: bl({ en: "Use single ASCII tokens (letters, digits, - _ . @ +), up to 128 characters. Case, - and _ are normalized; values shorter than 5 normalized characters are ignored. At least one supported value is required. Only hashes are stored.", ja: "半角英数字と - _ . @ + の単一語句を128文字以内で入力します。大文字小文字と - _ を正規化し、正規化後5文字未満の値は無視します。有効な値が1件以上必要です。保存されるのはハッシュのみです。" }),
    });
    const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Fingerprint", ja: "登録" }), onClick: onSave });
    const saveError = el("div", { class: "ui-state ui-state-error", role: "alert", style: "display:none" });
    const modal = uiModal({
      title: existingName ? bl({ en: "Replace dataset", ja: "データセットを再登録" }) : bl({ en: "Add Exact-Data-Match dataset", ja: "完全一致データセットを追加" }),
      body: [nameF.el, valuesF.el, saveError],
      footer: [
        el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => modal.close() }),
        submit,
      ],
    });
    nameF.focus();

    async function onSave() {
      if (submit.disabled) return;
      saveError.style.display = "none";
      if (!nameF.validate()) { nameF.focus(); return; }
      const values = valuesF.get().split("\n").map((s) => s.trim()).filter(Boolean);
      if (!values.length) { valuesF.setError(bl({ en: "Add at least one value.", ja: "値を 1 件以上入力してください。" })); return; }
      submit.disabled = true;
      try {
        const r = await apiFetch("POST", "/admin/dlp-fingerprints", { name: nameF.get(), values });
        if (!r.ok) throw new Error((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status));
        const cnt = (r.body && r.body.dataset && r.body.dataset.count) || 0;
        _datasets = (r.body && r.body.datasets) || _datasets;
        uiToast(bl({ en: cnt + " values fingerprinted", ja: cnt + " 件を登録しました" }), "ok");
        modal.close();
        render();
      } catch (e) {
        saveError.textContent = String(e.message || e);
        saveError.style.display = "";
        saveError.scrollIntoView({ block: "nearest" });
      } finally { submit.disabled = false; }
    }
  }

  async function remove(name) {
    const ok = await uiConfirm({
      title: bl({ en: "Delete dataset?", ja: "データセットを削除?" }),
      body: bl({ en: 'DLP will stop detecting the values in "' + name + '".', ja: '「' + name + '」の値の検出を停止します。' }),
      confirmLabel: bl({ en: "Delete", ja: "削除" }), danger: true,
    });
    if (!ok) return;
    try {
      const r = await apiFetch("DELETE", "/admin/dlp-fingerprints?name=" + encodeURIComponent(name));
      if (!r.ok) throw new Error((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status));
      _datasets = (r.body && r.body.datasets) || _datasets.filter((d) => d.name !== name);
      uiToast(bl({ en: "Dataset deleted", ja: "データセットを削除しました" }), "ok");
      render();
    } catch (e) { uiToast(String(e.message || e), "err"); }
  }

  load();
}
