"use strict";

// ---------------------------------------------------------------------------
// "Predefined Catalog" view — the curated set of well-known un-interceptable services (Apple push/iCloud,
// OS updates, OCSP…) that the edge no-decrypt-bypasses by DEFAULT, so they work out of the box and do not
// generate cert-pinning detection noise. Each entry carries vendor / category / risk metadata and a version.
//
// A tenant admin can OVERRIDE an individual entry — finer-grained than the all-or-nothing known-bypass toggle
// on the inspection posture:
//   - Force-inspect: decrypt this entry's traffic despite the pin (it MAY break the app — warned).
//   - Disable: stop applying this curated bypass (also re-inspects).
//   - Restore default: clear the override (the entry is bypassed again).
//
// Backend (edge): GET /admin/predefined-catalog, POST /admin/predefined-catalog/overrides {entry_id, mode,
// reason}, POST /admin/predefined-catalog/overrides/{id}/clear. Loaded after app.js (apiFetch / bl / escapeHtml
// in scope); app.js dispatches here for the GROUPS entry flagged custom:"catalog".
// ---------------------------------------------------------------------------

function catalogModeBadge(mode) {
  const m = String(mode || "").trim();
  if (m === "force_inspect") {
    return `<span style="padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600;background:#fee2e2;color:#991b1b">${escapeHtml(bl({ en: "force-inspect", ja: "強制傍受" }))}</span>`;
  }
  if (m === "disabled") {
    return `<span style="padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600;background:#f3f4f6;color:#4b5563">${escapeHtml(bl({ en: "disabled", ja: "無効" }))}</span>`;
  }
  return `<span style="padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600;background:#dcfce7;color:#166534">${escapeHtml(bl({ en: "bypassed (default)", ja: "バイパス(既定)" }))}</span>`;
}

function catalogRiskBadge(risk) {
  const r = String(risk || "").trim();
  const style = r === "high" ? "background:#fee2e2;color:#991b1b"
    : r === "medium" ? "background:#fef3c7;color:#92400e"
    : "background:#e5e7eb;color:#374151";
  return `<span style="padding:1px 6px;border-radius:4px;${style}">${escapeHtml(r || "—")}</span>`;
}

function renderPredefinedCatalogView(content) {
  content.innerHTML = "";
  const h = document.createElement("h2");
  h.className = "group-title";
  h.textContent = bl({ en: "Predefined Catalog", ja: "定義済みカタログ" });
  content.appendChild(h);
  const d = document.createElement("p");
  d.className = "group-desc";
  d.textContent = bl({
    en: "The curated set of well-known un-interceptable services (Apple push/iCloud, OS updates, OCSP) that the " +
      "edge no-decrypt-bypasses by default — so they work out of the box and don't flood the cert-pinning queue. " +
      "Override an entry to Force-inspect (decrypt despite the pin — may break the app) or Disable it; Restore " +
      "default to bypass it again.",
    ja: "Edge が既定で復号バイパスする、傍受できない著名サービス群(Apple push/iCloud・OS更新・OCSP)。箱出しで動き、" +
      "証明書ピンニング検出を溢れさせません。各エントリを「強制傍受」(ピンを無視して復号・アプリが壊れる可能性)や" +
      "「無効」に上書きできます。「既定に戻す」で再びバイパスします。",
  });
  content.appendChild(d);

  const bar = document.createElement("div");
  bar.style.cssText = "margin:8px 0;display:flex;gap:8px;align-items:center";
  const reloadBtn = document.createElement("button");
  reloadBtn.textContent = bl({ en: "Reload", ja: "再読込" });
  bar.appendChild(reloadBtn);
  const ver = document.createElement("span");
  ver.className = "group-desc";
  ver.style.marginLeft = "8px";
  bar.appendChild(ver);
  content.appendChild(bar);

  const container = document.createElement("div");
  content.appendChild(container);

  // Signed feed section (proprietary): status + apply a vendor-signed catalog + rollback.
  const feedHeader = document.createElement("h3");
  feedHeader.textContent = bl({ en: "Signed catalog feed", ja: "署名付きカタログフィード" });
  feedHeader.style.cssText = "margin-top:24px";
  content.appendChild(feedHeader);
  const feedDesc = document.createElement("p");
  feedDesc.className = "group-desc";
  feedDesc.textContent = bl({
    en: "The vendor ships the catalog as a signed feed (ed25519). Applying a newer signed feed replaces the " +
      "built-in default; an invalid/expired/older feed is rejected and the current catalog is kept. Roll back " +
      "to a prior version from the history.",
    ja: "ベンダーはカタログを署名付きフィード(ed25519)として配布します。より新しい署名フィードを適用すると組込既定を" +
      "置き換えます。不正/期限切れ/古いフィードは拒否され現行カタログを維持します。履歴から以前の版へ戻せます。",
  });
  content.appendChild(feedDesc);
  const feedContainer = document.createElement("div");
  content.appendChild(feedContainer);

  const reload = () => { reloadCatalog(container, ver); reloadFeed(feedContainer); };
  feedContainer._refreshAll = reload; // applying/rolling back a feed changes the catalog entries too
  reloadBtn.addEventListener("click", reload);
  reload();
}

async function reloadFeed(container) {
  container.innerHTML = `<p class="group-desc">${escapeHtml(bl({ en: "Loading…", ja: "読込中…" }))}</p>`;
  let st;
  try {
    const r = await apiFetch("GET", "/admin/predefined-catalog/feed");
    if (r.status === 503) { container.innerHTML = `<p class="group-desc">${escapeHtml(bl({ en: "Feed not configured on this edge (built-in default in use).", ja: "この Edge でフィード未設定(組込既定を使用)。" }))}</p>`; return; }
    if (!r.ok) { container.innerHTML = `<p class="group-desc">HTTP ${r.status}</p>`; return; }
    st = r.body || {};
  } catch (e) {
    container.innerHTML = `<p class="group-desc">${escapeHtml(String(e))}</p>`;
    return;
  }
  const source = String(st.source || "builtin");
  const staleBadge = st.stale ? ` <span style="padding:1px 6px;border-radius:4px;background:#fef3c7;color:#92400e">${escapeHtml(bl({ en: "stale (last-known-good)", ja: "期限切れ(最終正常)" }))}</span>` : "";
  const hist = Array.isArray(st.history) ? st.history : [];
  // Deduplicate history by catalog_version (newest applied_at wins) for the rollback list.
  const byVer = {};
  hist.forEach((h) => { byVer[h.catalog_version] = h; });
  const versions = Object.values(byVer).sort((a, b) => b.catalog_version - a.catalog_version);
  const curVer = st.current ? st.current.catalog_version : null;
  const histRows = versions.map((h) => {
    const isCur = h.catalog_version === curVer;
    const action = isCur
      ? `<span class="group-desc">${escapeHtml(bl({ en: "current", ja: "現行" }))}</span>`
      : `<button data-rollback="${escapeHtml(String(h.catalog_version))}">${escapeHtml(bl({ en: "Roll back", ja: "戻す" }))}</button>`;
    return `<tr><td>v${escapeHtml(String(h.catalog_version))}</td><td>${escapeHtml(h.signing_key_id || "")}</td><td>${escapeHtml(h.applied_at || "")}</td><td>${action}</td></tr>`;
  }).join("");

  container.innerHTML =
    `<p><strong>${escapeHtml(bl({ en: "Source", ja: "ソース" }))}:</strong> ${escapeHtml(source)} · ` +
    `<strong>${escapeHtml(bl({ en: "version", ja: "版" }))}:</strong> v${escapeHtml(String(st.catalog_version != null ? st.catalog_version : "?"))}${staleBadge}</p>` +
    `<p class="group-desc">${escapeHtml(bl({ en: "Paste a vendor-signed feed envelope (JSON) and apply:", ja: "ベンダー署名済フィード(JSON)を貼り付けて適用:" }))}</p>` +
    `<textarea id="feed-envelope" rows="5" style="width:100%;font-family:monospace;font-size:12px" placeholder='{"type":"predefined_catalog_feed", ...}'></textarea>` +
    `<div style="margin:6px 0"><button id="feed-apply"><strong>${escapeHtml(bl({ en: "Apply signed feed", ja: "署名フィードを適用" }))}</strong></button></div>` +
    (versions.length ? `<table class="data-table"><thead><tr>` +
      `<th>${escapeHtml(bl({ en: "Version", ja: "版" }))}</th><th>${escapeHtml(bl({ en: "Signer", ja: "署名者" }))}</th><th>${escapeHtml(bl({ en: "Applied", ja: "適用日時" }))}</th><th>${escapeHtml(bl({ en: "Action", ja: "操作" }))}</th>` +
      `</tr></thead><tbody>${histRows}</tbody></table>` : "");

  const applyBtn = container.querySelector("#feed-apply");
  if (applyBtn) applyBtn.addEventListener("click", () => applyFeed(container));
  container.querySelectorAll("button[data-rollback]").forEach((b) => {
    b.addEventListener("click", () => rollbackFeed(parseInt(b.dataset.rollback, 10), container));
  });
}

async function applyFeed(container) {
  const ta = container.querySelector("#feed-envelope");
  const txt = (ta && ta.value || "").trim();
  if (!txt) { window.alert(bl({ en: "Paste a signed feed envelope first.", ja: "署名済フィードを貼り付けてください。" })); return; }
  let env;
  try { env = JSON.parse(txt); } catch (e) { window.alert(bl({ en: "Not valid JSON: ", ja: "JSON が不正: " }) + String(e)); return; }
  const r = await apiFetch("POST", "/admin/predefined-catalog/feed", env);
  if (!r.ok) { window.alert("HTTP " + r.status + "\n" + JSON.stringify(r.body)); return; }
  window.alert(bl({ en: "Feed applied: catalog v", ja: "フィード適用: カタログ v" }) + (r.body && r.body.catalog_version));
  if (container._refreshAll) container._refreshAll(); else reloadFeed(container);
}

async function rollbackFeed(version, container) {
  if (!window.confirm(bl({ en: "Roll back the catalog to v" + version + "?", ja: "カタログを v" + version + " に戻しますか?" }))) return;
  const r = await apiFetch("POST", "/admin/predefined-catalog/feed/rollback", { catalog_version: version });
  if (!r.ok) { window.alert("HTTP " + r.status + "\n" + JSON.stringify(r.body)); return; }
  if (container._refreshAll) container._refreshAll(); else reloadFeed(container);
}

async function reloadCatalog(container, ver) {
  container.innerHTML = `<p class="group-desc">${escapeHtml(bl({ en: "Loading…", ja: "読込中…" }))}</p>`;
  let doc;
  try {
    const r = await apiFetch("GET", "/admin/predefined-catalog");
    if (!r.ok) { container.innerHTML = `<p class="group-desc">HTTP ${r.status}</p>`; return; }
    doc = r.body || {};
  } catch (e) {
    container.innerHTML = `<p class="group-desc">${escapeHtml(String(e))}</p>`;
    return;
  }
  if (ver) ver.textContent = bl({ en: "catalog version ", ja: "カタログ版 " }) + String(doc.version != null ? doc.version : "?");
  const entries = Array.isArray(doc.entries) ? doc.entries : [];
  const overrides = {};
  (Array.isArray(doc.overrides) ? doc.overrides : []).forEach((o) => { overrides[String(o.entry_id)] = String(o.mode || ""); });

  if (entries.length === 0) {
    container.innerHTML = `<p class="group-desc">${escapeHtml(bl({ en: "(empty catalog)", ja: "(カタログ空)" }))}</p>`;
    return;
  }

  const rows = entries.map((e) => {
    const id = String(e.id || "");
    const mode = overrides[id] || "";
    const patterns = Array.isArray(e.patterns) ? e.patterns : [];
    const patternList = patterns.map((p) => `<code>${escapeHtml(p)}</code>`).join("<br>");
    let actions = "";
    if (mode === "") {
      actions =
        `<button data-act="force_inspect" data-id="${encodeURIComponent(id)}">${escapeHtml(bl({ en: "Force-inspect", ja: "強制傍受" }))}</button> ` +
        `<button data-act="disabled" data-id="${encodeURIComponent(id)}">${escapeHtml(bl({ en: "Disable", ja: "無効化" }))}</button>`;
    } else {
      actions = `<button data-act="clear" data-id="${encodeURIComponent(id)}">${escapeHtml(bl({ en: "Restore default", ja: "既定に戻す" }))}</button>`;
    }
    return `<tr>
      <td><strong>${escapeHtml(e.name || id)}</strong><br><span class="group-desc">${escapeHtml(e.description || "")}</span></td>
      <td>${escapeHtml(e.vendor || "—")}<br><span class="group-desc">${escapeHtml(e.category || "")}</span></td>
      <td style="font-size:12px">${patternList}</td>
      <td class="nowrap">${catalogModeBadge(mode)}</td>
      <td class="nowrap">${actions}</td>
    </tr>`;
  }).join("");

  container.innerHTML = `<table class="data-table">
    <colgroup><col class="c-entry"><col class="c-vendor"><col class="c-patterns"><col class="c-state"><col class="c-actions"></colgroup>
    <thead><tr>
      <th>${escapeHtml(bl({ en: "Entry", ja: "エントリ" }))}</th>
      <th>${escapeHtml(bl({ en: "Vendor / Category", ja: "ベンダー / 分類" }))}</th>
      <th>${escapeHtml(bl({ en: "Patterns", ja: "パターン" }))}</th>
      <th>${escapeHtml(bl({ en: "State", ja: "状態" }))}</th>
      <th>${escapeHtml(bl({ en: "Actions", ja: "操作" }))}</th>
    </tr></thead>
    <tbody>${rows}</tbody></table>`;

  container.querySelectorAll("button[data-act]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const act = btn.dataset.act;
      const id = decodeURIComponent(btn.dataset.id);
      if (act === "clear") {
        clearCatalogOverride(id, container, ver);
      } else {
        setCatalogOverride(id, act, container, ver);
      }
    });
  });
}

async function setCatalogOverride(id, mode, container, ver) {
  if (mode === "force_inspect") {
    if (!window.confirm(bl({
      en: "Force-inspect this entry? The edge will DECRYPT this pinned service despite the pin — the app may break (it pins precisely to refuse interception). Proceed?",
      ja: "このエントリを強制傍受しますか? このサービスは自身の証明書を固定しており、強制的に復号するとアプリが壊れる可能性があります。続けますか?",
    }))) return;
  }
  const r = await apiFetch("POST", "/admin/predefined-catalog/overrides", { entry_id: id, mode: mode });
  if (!r.ok) { window.alert("HTTP " + r.status + "\n" + JSON.stringify(r.body)); return; }
  reloadCatalog(container, ver);
}

async function clearCatalogOverride(id, container, ver) {
  const r = await apiFetch("POST", "/admin/predefined-catalog/overrides/" + encodeURIComponent(id) + "/clear", {});
  if (!r.ok) { window.alert("HTTP " + r.status + "\n" + JSON.stringify(r.body)); return; }
  reloadCatalog(container, ver);
}
