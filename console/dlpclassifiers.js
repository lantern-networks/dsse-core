"use strict";

// dlpclassifiers.js — "DLP Custom Identifiers" (Web & Traffic): the operator editor for tenant-specific DLP
// identifiers. Two kinds, in plain language: a *pattern* (regex — e.g. an employee-ID format EMP-123456) or a
// *keyword list* (flag any of a set of exact words/phrases, e.g. internal project codenames). These are detected
// by the DLP scan alongside the built-in identifiers (My Number, credit card, …). NON-SECRET throughout — a
// custom identifier only ever reports its name + a count, never the matched text. Backend:
// GET/POST /admin/dlp-classifiers. The whole set is authored client-side and POSTed atomically. See
// docs/dlp_vision_and_roadmap.md slice C.

// dlpClassifierKindLabel returns the friendly label for a classifier kind.
function dlpClassifierKindLabel(kind) {
  if (kind === "regex") return bl({ en: "Pattern", ja: "パターン" });
  if (kind === "keyword") return bl({ en: "Keyword list", ja: "キーワード" });
  return kind || "—";
}

// dlpClassifierDefinitionSummary describes a classifier's definition without dumping raw internals.
function dlpClassifierDefinitionSummary(c) {
  if (c.kind === "regex") return c.pattern + (c.case_insensitive ? "  (" + bl({ en: "case-insensitive", ja: "大文字小文字を区別しない" }) + ")" : "");
  if (c.kind === "keyword") { const kws = c.keywords || []; return kws.length + " " + bl({ en: "keywords", ja: "語" }) + ": " + kws.slice(0, 6).join(", ") + (kws.length > 6 ? " …" : ""); }
  return "—";
}

async function renderDLPClassifiersView(content, opts) {
  content.innerHTML = "";
  if (!(opts && opts.embedded)) content.appendChild(el("div", { class: "ui-view-head" }, el("div", {}, [
    el("h2", { class: "ui-view-title", text: bl({ en: "DLP Custom Identifiers", ja: "DLP カスタム識別子" }) }),
    el("p", { class: "ui-view-desc", text: bl({
      en: "Teach DLP to recognize your own sensitive data — an ID format, a contract-number shape, or a list of internal codenames. These are detected alongside the built-in identifiers, and only ever reported by name and count (never the matched text).",
      ja: "自社固有の機密データ(ID の書式、契約番号の形、社内コードネームの一覧など)を DLP に登録します。組み込み識別子と併せて検出され、報告されるのは名前と件数のみ(一致した本文は非表示)です。",
    }) }),
  ])));
  const section = el("div", {});
  content.appendChild(section);

  let _specs = []; // the current authored set (source of truth for the atomic POST)

  async function load() {
    uiState(section, "loading");
    try { const r = await apiFetch("GET", "/admin/dlp-classifiers"); if (!r.ok) throw new Error("HTTP " + r.status); _specs = (r.body && r.body.classifiers) || []; }
    catch (e) { uiState(section, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: load }); return; }
    render();
  }

  // save POSTs the whole set atomically; on a 400 (a bad classifier) it surfaces the server message and keeps the
  // editor open so nothing is half-applied.
  async function save(nextSpecs, okMsg) {
    const r = await apiFetch("POST", "/admin/dlp-classifiers", { classifiers: nextSpecs });
    if (!r.ok) { throw new Error((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status)); }
    _specs = (r.body && r.body.classifiers) || nextSpecs;
    uiToast(okMsg || bl({ en: "Saved", ja: "保存しました" }), "ok");
    render();
  }

  function render() {
    section.innerHTML = "";
    section.appendChild(el("div", { class: "ui-toolbar" }, [
      el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "+ Add identifier", ja: "+ 識別子を追加" }), onClick: () => openEditor(null) }),
      el("span", { class: "ui-view-desc", text: _specs.length + " / 64 " + bl({ en: "defined", ja: "件" }) }),
    ]));
    if (!_specs.length) {
      section.appendChild(emptyBox(bl({
        en: "No custom identifiers yet. Add one to detect a pattern (like an employee-ID format) or a keyword list specific to your tenant.",
        ja: "カスタム識別子はまだありません。自社固有のパターン(社員 ID の書式など)やキーワード一覧を追加して検出できます。",
      })));
      return;
    }
    section.appendChild(simpleTable(
      [bl({ en: "Name", ja: "名前" }), bl({ en: "Kind", ja: "種類" }), bl({ en: "Definition", ja: "定義" }), bl({ en: "Description", ja: "説明" }), ""],
      _specs.map((c, i) => [
        el("code", { text: c.name }),
        uiBadge(dlpClassifierKindLabel(c.kind), c.kind === "regex" ? "warn" : "off"),
        el("span", { class: "ui-view-desc", text: dlpClassifierDefinitionSummary(c) }),
        el("span", { class: "ui-view-desc", text: c.description || "—" }),
        el("div", { class: "ui-row-actions" }, [
          el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Edit", ja: "編集" }), onClick: () => openEditor(i) }),
          el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Delete", ja: "削除" }), onClick: () => remove(i) }),
        ]),
      ])
    ));
  }

  async function remove(i) {
    const c = _specs[i];
    const ok = await uiConfirm({
      title: bl({ en: "Delete identifier?", ja: "識別子を削除?" }),
      body: bl({ en: 'Stop detecting "' + c.name + '". Any DLP rule that governs it will no longer match it.', ja: '「' + c.name + '」の検出を停止します。これを対象とする DLP ルールは一致しなくなります。' }),
      confirmLabel: bl({ en: "Delete", ja: "削除" }), danger: true,
    });
    if (!ok) return;
    const next = _specs.filter((_, idx) => idx !== i);
    try { await save(next, bl({ en: "Identifier deleted", ja: "識別子を削除しました" })); }
    catch (e) { uiToast(String(e.message || e), "danger"); }
  }

  // openEditor(index|null): add (null) or edit an existing classifier. Builds the whole next-set on save and POSTs.
  function openEditor(index) {
    const editing = index != null ? _specs[index] : null;
    const nameF = uiField({
      name: "name", label: bl({ en: "Name", ja: "名前" }), required: true, value: editing ? editing.name : "",
      placeholder: "employee_id",
      hint: bl({ en: "Lowercase letters, digits and underscores (e.g. employee_id). This is the label shown in findings — never a secret.", ja: "英小文字・数字・アンダースコア(例: employee_id)。検出結果に表示される名前です(秘密情報ではありません)。" }),
      validate: (v) => (/^[a-z][a-z0-9_]{1,39}$/.test(v) ? "" : bl({ en: "2–40 chars, lowercase snake_case.", ja: "2〜40 文字の英小文字スネークケース。" })),
    });
    const descF = uiField({ name: "description", label: bl({ en: "Description (optional)", ja: "説明(任意)" }), value: editing ? (editing.description || "") : "", placeholder: bl({ en: "What this detects and why", ja: "何を・なぜ検出するか" }) });
    const kindF = uiField({
      name: "kind", label: bl({ en: "How should it match?", ja: "どう一致させる?" }), type: "select",
      value: editing ? editing.kind : "regex",
      options: [
        { value: "regex", label: bl({ en: "A pattern (e.g. EMP-123456)", ja: "パターン(例: EMP-123456)" }) },
        { value: "keyword", label: bl({ en: "A keyword list (exact words/phrases)", ja: "キーワード一覧(完全一致の語句)" }) },
      ],
    });
    // Regex fields.
    const patternF = uiField({
      name: "pattern", label: bl({ en: "Pattern", ja: "パターン" }), type: "textarea", value: editing && editing.kind === "regex" ? editing.pattern : "",
      placeholder: "EMP-[0-9]{6}",
      hint: bl({ en: "A regular expression (RE2). Example: EMP-[0-9]{6} matches EMP- followed by six digits.", ja: "正規表現(RE2)。例: EMP-[0-9]{6} は EMP- のあとに数字 6 桁。" }),
    });
    const ciF = uiField({ name: "ci", label: bl({ en: "Ignore upper/lowercase", ja: "大文字小文字を無視" }), type: "checkbox", value: editing ? !!editing.case_insensitive : false });
    // Keyword fields.
    const keywordsF = uiField({
      name: "keywords", label: bl({ en: "Keywords (one per line)", ja: "キーワード(1 行に 1 語)" }), type: "textarea",
      value: editing && editing.kind === "keyword" ? (editing.keywords || []).join("\n") : "",
      placeholder: "BLUEFIN\nREDCEDAR\nProject Falcon",
      hint: bl({ en: "Each line is flagged wherever it appears (case-sensitive substring). Up to 256 entries.", ja: "各行はどこに現れても検出されます(大文字小文字を区別する部分一致)。最大 256 件。" }),
    });
    // Live preview: count matches against a sample. Best-effort (browser regex ≈ RE2), labeled approximate.
    const sampleF = uiField({ name: "sample", label: bl({ en: "Try it (paste sample text)", ja: "試す(サンプルを貼り付け)" }), type: "textarea", placeholder: bl({ en: "Paste text here to see how many matches it finds…", ja: "ここにテキストを貼ると一致数が表示されます…" }) });
    const previewOut = el("div", { class: "ui-field-hint", text: "" });

    const regexWrap = el("div", {}, [patternF.el, ciF.el]);
    const keywordWrap = el("div", {}, [keywordsF.el]);
    const syncKind = () => { const k = kindF.get(); regexWrap.style.display = k === "regex" ? "" : "none"; keywordWrap.style.display = k === "keyword" ? "" : "none"; runPreview(); };
    kindF.el.querySelector("select").addEventListener("change", syncKind);
    [patternF, keywordsF, sampleF].forEach((f) => { const inp = f.el.querySelector("textarea"); if (inp) inp.addEventListener("input", runPreview); });
    ciF.el.querySelector("input").addEventListener("change", runPreview);

    function runPreview() {
      const sample = sampleF.get();
      if (!sample) { previewOut.textContent = ""; return; }
      try {
        let n = 0;
        if (kindF.get() === "regex") {
          const pat = patternF.get();
          if (!pat) { previewOut.textContent = ""; return; }
          const re = new RegExp(pat, "g" + (ciF.get() ? "i" : ""));
          n = (sample.match(re) || []).length;
        } else {
          const kws = keywordsF.get().split("\n").map((s) => s.trim()).filter(Boolean);
          kws.forEach((kw) => { let idx = 0; while ((idx = sample.indexOf(kw, idx)) >= 0) { n++; idx += kw.length; } });
        }
        previewOut.textContent = bl({ en: n + " match(es) in the sample (approximate preview).", ja: "サンプル内で " + n + " 件一致(概算プレビュー)。" });
        previewOut.style.color = n > 0 ? "" : "var(--ui-muted, #888)";
      } catch (e) { previewOut.textContent = bl({ en: "Pattern not valid yet: " + e.message, ja: "パターンが未完成: " + e.message }); }
    }

    const modal = uiModal({
      title: editing ? bl({ en: "Edit identifier", ja: "識別子を編集" }) : bl({ en: "Add custom identifier", ja: "カスタム識別子を追加" }),
      body: [nameF.el, descF.el, kindF.el, regexWrap, keywordWrap, sampleF.el, previewOut],
      footer: [
        el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => modal.close() }),
        el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Save", ja: "保存" }), onClick: onSave }),
      ],
    });
    syncKind();
    nameF.focus();

    async function onSave() {
      if (!nameF.validate()) { nameF.focus(); return; }
      const kind = kindF.get();
      const spec = { name: nameF.get(), description: descF.get(), kind };
      if (kind === "regex") {
        if (!patternF.validate() || !patternF.get()) { patternF.setError(bl({ en: "A pattern is required.", ja: "パターンは必須です。" })); return; }
        try { new RegExp(patternF.get()); } catch (e) { patternF.setError(bl({ en: "Not a valid pattern: " + e.message, ja: "無効なパターン: " + e.message })); return; }
        spec.pattern = patternF.get();
        if (ciF.get()) spec.case_insensitive = true;
      } else {
        const kws = keywordsF.get().split("\n").map((s) => s.trim()).filter(Boolean);
        if (!kws.length) { keywordsF.setError(bl({ en: "Add at least one keyword.", ja: "キーワードを 1 つ以上入力してください。" })); return; }
        spec.keywords = kws;
      }
      // Duplicate-name guard (client-side; the backend also rejects).
      const dupe = _specs.some((c, i) => c.name === spec.name && i !== index);
      if (dupe) { nameF.setError(bl({ en: "An identifier with this name already exists.", ja: "同じ名前の識別子が既に存在します。" })); return; }
      const next = _specs.slice();
      if (index != null) next[index] = spec; else next.push(spec);
      try { await save(next, editing ? bl({ en: "Identifier updated", ja: "識別子を更新しました" }) : bl({ en: "Identifier added", ja: "識別子を追加しました" })); modal.close(); }
      catch (e) { uiToast(String(e.message || e), "danger"); }
    }
  }

  load();
}
