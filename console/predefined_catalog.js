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

  // Signed feed section: status + apply a vendor-signed catalog + rollback.
  const feedHeader = document.createElement("h3");
  feedHeader.textContent = bl({ en: "Signed catalog feed", ja: "署名付きカタログフィード" });
  feedHeader.style.cssText = "margin-top:24px";
  content.appendChild(feedHeader);
  const feedDesc = document.createElement("p");
  feedDesc.className = "group-desc";
  feedDesc.textContent = bl({
    en: "The vendor ships the catalog as a signed feed (ed25519). Applying a newer signed feed replaces the " +
      "built-in default; an invalid/expired/older feed is rejected and the current catalog is kept. Roll back " +
      "to a prior version from the history. Feed changes affect the whole deployment and require an operator; entry overrides affect only the selected organization.",
    ja: "ベンダーはカタログを署名付きフィード(ed25519)として配布します。より新しい署名フィードを適用すると組込既定を" +
      "置き換えます。不正/期限切れ/古いフィードは拒否され現行カタログを維持します。履歴から以前の版へ戻せます。フィード変更は配備全体に影響し、運用者権限が必要です。エントリの上書きは選択中の組織だけに適用します。",
  });
  content.appendChild(feedDesc);
  const feedContainer = document.createElement("div");
  content.appendChild(feedContainer);

  const message = document.createElement("p");
  message.className = "group-desc";
  bar.after(message);
  const view = catalogView(content, container, ver, feedContainer, reloadBtn, message);
  container._catalogView = feedContainer._catalogView = view;
  reloadBtn.addEventListener("click", view.load);
  view.load();
}

function paintCatalogFeed(container, st) {
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
  try { env = JSON.parse(txt); } catch (e) { window.alert(bl({ en: "Not valid JSON.", ja: "JSON が不正です。" })); return; }
  if (!catalogEnvelope(env)) { window.alert(bl({ en: "A valid signed catalog envelope is required.", ja: "有効な署名付きカタログが必要です。" })); return; }
  const view = container._catalogView;
  if (await view.write("/admin/predefined-catalog/feed", env, "deployment", a => catalogApplied(a) && catalogSameEnvelope(a.envelope, env))) {
    ta.value = "";
    await view.load();
  }
}

async function rollbackFeed(version, container) {
  if (!window.confirm(bl({ en: "Roll back the catalog to v" + version + "?", ja: "カタログを v" + version + " に戻しますか?" }))) return;
  const view = container._catalogView;
  const target = view.feed()?.history?.filter(h => h.catalog_version === version).at(-1);
  if (!target) return;
  if (await view.write("/admin/predefined-catalog/feed/rollback", { catalog_version: version }, "deployment",
      a => catalogApplied(a) && a.catalog_version === version && catalogSameEnvelope(a.envelope, target.envelope))) await view.load();
}

function paintCatalog(container, ver, doc) {
  if (ver) ver.textContent = bl({ en: "catalog version ", ja: "カタログ版 " }) + String(doc.version != null ? doc.version : "?");
  const entries = Array.isArray(doc.entries) ? doc.entries : [];
  const overrides = Object.create(null);
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
  const view = container._catalogView;
  if (await view.write("/admin/predefined-catalog/overrides", { entry_id: id, mode }, "tenant",
      o => catalogOverride(o) && o.entry_id === id && o.mode === mode)) await view.load();
}

async function clearCatalogOverride(id, container, ver) {
  const view = container._catalogView;
  if (await view.write("/admin/predefined-catalog/overrides/" + encodeURIComponent(id) + "/clear", {}, "tenant",
      o => catalogObject(o) && o.entry_id === id && typeof o.cleared === "boolean")) await view.load();
}

// Verify API shape and context before making an editable view. This is response
// validation, not a replacement for the server's signature or permission checks.
function catalogObject(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }
function catalogText(v) { return typeof v === "string" && v.trim() !== ""; }
function catalogVersion(v) { return Number.isSafeInteger(v) && v > 0; }
function catalogSame(a, b) {
  if (a === b) return true;
  if (Array.isArray(a) && Array.isArray(b)) return a.length === b.length && a.every((v, i) => catalogSame(v, b[i]));
  if (!catalogObject(a) || !catalogObject(b)) return false;
  const keys = Object.keys(a);
  return keys.length === Object.keys(b).length && keys.every(k => Object.hasOwn(b, k) && catalogSame(a[k], b[k]));
}
function catalogEntries(rows) {
  if (!Array.isArray(rows) || !rows.length) return false;
  const ids = new Set();
  return rows.every(e => {
    if (!catalogObject(e) || !catalogText(e.id) || e.id.trim() !== e.id || ids.has(e.id)) return false;
    ids.add(e.id);
    return ["name", "vendor", "category", "risk", "description"].every(k => e[k] === undefined || typeof e[k] === "string") &&
      (e.patterns === undefined || e.patterns === null || Array.isArray(e.patterns) && e.patterns.every(p => typeof p === "string"));
  });
}
function catalogOverride(o) {
  return catalogObject(o) && catalogText(o.entry_id) && ["force_inspect", "disabled"].includes(o.mode) &&
    (o.reason === undefined || typeof o.reason === "string") && catalogText(o.updated_at) && Number.isFinite(Date.parse(o.updated_at));
}
function catalogDocument(d) {
  if (!catalogObject(d) || !catalogVersion(d.version) || !["builtin", "feed"].includes(d.source) || !catalogEntries(d.entries) || !Array.isArray(d.overrides)) return false;
  const ids = new Set();
  // Overrides for entries absent from the currently selected feed are legitimate.
  return d.overrides.every(o => { if (!catalogOverride(o) || ids.has(o.entry_id)) return false; ids.add(o.entry_id); return true; });
}
function catalogEnvelope(e) {
  return catalogObject(e) && e.type === "predefined_catalog_feed" && e.status === "active" &&
    ["version", "signing_key_id", "checksum", "signature"].every(k => catalogText(e[k])) &&
    ["created_at", "expires_at"].every(k => e[k] === undefined || e[k] === "" || typeof e[k] === "string" && Number.isFinite(Date.parse(e[k]))) &&
    (e.metadata === undefined || e.metadata === null || catalogObject(e.metadata)) &&
    catalogObject(e.payload) && catalogVersion(e.payload.version) && catalogEntries(e.payload.entries);
}
function catalogApplied(a) {
  return catalogObject(a) && catalogEnvelope(a.envelope) && catalogVersion(a.catalog_version) &&
    a.catalog_version === a.envelope.payload.version && catalogSame(a.entries, catalogMaterializedEntries(a.envelope.payload.entries)) &&
    a.envelope_version === a.envelope.version && a.signing_key_id === a.envelope.signing_key_id &&
    a.created_at === (a.envelope.created_at || "") && a.expires_at === (a.envelope.expires_at || "") &&
    catalogText(a.applied_at) && Number.isFinite(Date.parse(a.applied_at));
}
function catalogFeedStatus(s) {
  if (!catalogObject(s) || !catalogVersion(s.catalog_version) || typeof s.stale !== "boolean" ||
      !(s.history === null || Array.isArray(s.history))) return false;
  const history = s.history || [];
  if (s.source === "builtin") return s.current === null && !s.stale && history.length === 0;
  return s.source === "feed" && catalogApplied(s.current) && s.catalog_version === s.current.catalog_version &&
    history.length > 0 && history.every(catalogApplied) && catalogSame(s.current, history[history.length - 1]);
}
function catalogContext(r, tenant, scope) {
  const b = r && r.body;
  if (!r || !r.ok || r.status !== 200 || !catalogObject(b) || b.tenant_id !== tenant || b.scope !== scope) throw new Error("invalid context");
  return b.data;
}
function catalogMessage(kind) {
  if (kind === "changed") return bl({ en: "The organization changed. Reload before continuing.", ja: "組織が変わりました。再読込してから操作してください。" });
  if (kind === "unknown") return bl({ en: "Could not confirm the result. Your input is retained. Reload and check the saved state before trying again.", ja: "結果を確認できません。入力は保持しています。再読込して保存状態を確認してから再試行してください。" });
  return bl({ en: "Could not verify the catalog response. Reload to try again.", ja: "カタログの応答を確認できません。再読込してください。" });
}
function catalogView(content, container, ver, feedContainer, reloadButton, message) {
  const fresh = freshRender(content);
  const current = () => fresh() && content.isConnected !== false && container.isConnected !== false && feedContainer.isConnected !== false;
  const selection = () => typeof operateTenant === "string" ? operateTenant : "";
  let loaded = false, pending = false, tenant = "", selected = "", revision = 0, feed = null;
  const active = n => loaded && current() && revision === n && selection() === selected;
  const lock = () => {
    reloadButton.disabled = pending;
    for (const host of [container, feedContainer]) host.querySelectorAll("button,textarea").forEach(b => { b.disabled = pending || !loaded; });
  };
  const fail = kind => { loaded = false; if (current()) { message.textContent = catalogMessage(kind); message.setAttribute("role", "alert"); lock(); } };
  const owner = r => r && r.ok && r.status === 200 && catalogObject(r.body) && catalogText(r.body.tenant_id) ? r.body.tenant_id : "";
  const path = p => p + "?scoped=1&expected_tenant_id=" + encodeURIComponent(tenant);
  const load = async () => {
    if (pending || !current()) return;
    loaded = false; feed = null; const stamp = ++revision, chosen = selection();
    const draft = feedContainer.querySelector("#feed-envelope")?.value || "";
    message.textContent = bl({ en: "Loading…", ja: "読込中…" });
    container.innerHTML = ""; feedContainer.innerHTML = ""; ver.textContent = ""; lock();
    try {
      const who = owner(await apiFetch("GET", "/admin/tenant"));
      if (!current() || revision !== stamp) return;
      if (selection() !== chosen || chosen && chosen !== who) { fail("changed"); return; }
      if (!who) throw new Error("missing owner");
      const suffix = "?scoped=1&expected_tenant_id=" + encodeURIComponent(who);
      const [cr, fr] = await Promise.all([apiFetch("GET", "/admin/predefined-catalog" + suffix), apiFetch("GET", "/admin/predefined-catalog/feed" + suffix)]);
      if (!current() || revision !== stamp) return;
      if (selection() !== chosen) { fail("changed"); return; }
      const doc = catalogContext(cr, who, "tenant");
      if (!catalogDocument(doc)) throw new Error("invalid catalog");
      // Feed support is optional. An unavailable feed must not be described as
      // an active builtin catalog; the independently verified catalog still works.
      const unavailable = fr && !fr.ok && fr.status === 503;
      const status = unavailable ? null : catalogContext(fr, who, "deployment");
      if (!unavailable && (!catalogFeedStatus(status) || status.source !== doc.source || status.catalog_version !== doc.version ||
          status.current && !catalogSame(status.current.entries, doc.entries))) throw new Error("inconsistent feed");
      tenant = who; selected = chosen; feed = status; loaded = true;
      paintCatalog(container, ver, doc);
      if (status) { paintCatalogFeed(feedContainer, status); feedContainer.querySelector("#feed-envelope").value = draft; }
      else feedContainer.textContent = bl({ en: "Feed status unavailable on this edge. Catalog entries above were verified separately.", ja: "この Edge のフィード状態は取得できません。上のカタログは別途確認済みです。" });
      message.textContent = ""; lock();
    } catch (_) { if (current() && revision === stamp) fail("invalid"); }
  };
  const write = async (url, body, scope, matches) => {
    const stamp = revision;
    if (pending || !active(stamp)) { if (!pending) fail("changed"); return false; }
    pending = true; lock();
    try {
      const who = owner(await apiFetch("GET", "/admin/tenant"));
      if (!who) { fail("invalid"); return false; }
      if (who !== tenant || !active(stamp)) { fail("changed"); return false; }
      const r = await apiFetch("POST", path(url), body);
      if (!active(stamp)) { fail("unknown"); return false; }
      const data = catalogContext(r, tenant, scope);
      if (!matches(data)) { fail("unknown"); return false; }
      loaded = false; return true;
    } catch (_) { fail("unknown"); return false; }
    finally { pending = false; if (current()) lock(); }
  };
  return { load, write, feed: () => feed };
}

function catalogMaterializedEntries(rows) {
  return rows.map(e => ({ id: e.id, name: e.name || "", vendor: e.vendor || "", category: e.category || "", risk: e.risk || "", description: e.description || "", patterns: e.patterns || null }));
}
function catalogSameEnvelope(a, b) {
  const normalized = e => ({ ...e, created_at: e.created_at || "", expires_at: e.expires_at || "", metadata: e.metadata || null });
  return catalogSame(normalized(a), normalized(b));
}
