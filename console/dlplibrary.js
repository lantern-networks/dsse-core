"use strict";

// Shared read/write contract for the three Sensitive Data editors. A bad read is
// never an empty library, and an unconfirmed write must be reconciled by reloading.
function dlpLibraryObject(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }
function dlpLibraryName(v) { return typeof v === "string" && /^[a-z][a-z0-9_]{1,39}$/.test(v); }
function dlpLibraryInvalid() { return bl({en:"Could not load this list correctly. Reload before editing.",ja:"一覧を正しく読み込めません。編集前に再読込してください。"}); }
function dlpLibraryOrganizationChanged() { return bl({en:"The organization changed or is unavailable. Reload before editing.",ja:"組織が変わったか、確認できません。編集前に一覧を再読込してください。"}); }
function dlpLibraryListChanged() { return bl({en:"The list or organization changed. Close the editor and reload before editing.",ja:"一覧または組織が変わりました。編集画面を閉じて一覧を再読込してください。"}); }
function dlpLibraryTenant(response) {
  if (!response?.ok || response.status !== 200 || !dlpLibraryObject(response.body) ||
      typeof response.body.tenant_id !== "string" || !response.body.tenant_id.trim()) throw new Error(dlpLibraryOrganizationChanged());
  return response.body.tenant_id;
}
function dlpLibraryList(response, key, tenant) {
  if (!response?.ok || response.status !== 200) throw new Error(dlpLibraryInvalid());
  if (dlpLibraryTenant(response) !== tenant || !Object.hasOwn(response.body, key) ||
      (response.body[key] !== null && !Array.isArray(response.body[key]))) throw new Error(dlpLibraryInvalid());
  const rows = response.body[key] || []; // The APIs encode empty slices as null.
  const names = new Set();
  for (const row of rows) {
    if (key === "values") {
      if (typeof row !== "string" || !row.trim() || names.has(row)) throw new Error(dlpLibraryInvalid());
      names.add(row); continue;
    }
    if (!dlpLibraryObject(row) || !dlpLibraryName(row.name) || names.has(row.name)) throw new Error(dlpLibraryInvalid());
    names.add(row.name);
    if (key === "datasets") {
      if (!Number.isSafeInteger(row.count) || row.count < 0) throw new Error(dlpLibraryInvalid());
    } else if (key === "classifiers") {
      if ((row.description !== undefined && typeof row.description !== "string") ||
          (row.case_insensitive !== undefined && typeof row.case_insensitive !== "boolean") ||
          !["regex", "keyword"].includes(row.kind) ||
          (row.kind === "regex" && (typeof row.pattern !== "string" || !row.pattern.trim())) ||
          (row.kind === "keyword" && (!Array.isArray(row.keywords) || !row.keywords.length || row.keywords.some(k => typeof k !== "string" || !k.trim())))) throw new Error(dlpLibraryInvalid());
    }
  }
  return rows;
}
function dlpLibrarySameClassifiers(actual, expected) {
  const canonical = rows => rows.map(r => ({name:r.name,kind:r.kind,description:r.description || "",case_insensitive:!!r.case_insensitive,
    pattern:r.pattern || "",keywords:r.keywords || []}));
  return JSON.stringify(canonical(actual)) === JSON.stringify(canonical(expected));
}
function dlpLibraryUnconfirmed() {
  return bl({en:"The result could not be confirmed. Your input is kept. Close the editor and reload the list before making another change.",ja:"結果を確認できません。入力は保持しています。編集画面を閉じて一覧を再読込してから、次の変更を行ってください。"});
}
function dlpLibrarySelection() {
  return typeof operateTenant === "undefined" ? "" : (operateTenant || "");
}

function dlpLibraryView(content, section, key, endpoint, onLoaded) {
  const fresh = freshRender(content);
  const current = () => fresh() && content.isConnected !== false && section.isConnected !== false;
  let loaded = false, pending = false, tenant = "", selection = "", revision = 0;
  function lock() { section.querySelectorAll("button").forEach(b => { b.disabled = pending; }); }
  function error(message) {
    if (current()) uiState(section, "error", message, {label:bl({en:"Reload list",ja:"一覧を再読込"}),onClick:load});
  }
  async function load() {
    if (pending || !current()) return;
    loaded = false; revision++;
    const latest = freshRender(section), selected = dlpLibrarySelection();
    uiState(section, "loading");
    try {
      const [response, organization] = await Promise.all([apiFetch("GET", endpoint), apiFetch("GET", "/admin/tenant")]);
      if (!current() || !latest()) return;
      if (selected !== dlpLibrarySelection()) throw new Error(dlpLibraryOrganizationChanged());
      const owner = dlpLibraryTenant(organization), rows = dlpLibraryList(response, key, owner);
      if (selected && selected !== owner) throw new Error(dlpLibraryOrganizationChanged());
      tenant = owner; selection = selected; loaded = true; onLoaded(rows);
    } catch (e) { if (current() && latest()) { loaded = false; error(String(e.message || e)); } }
  }
  function active(stamp) {
    return loaded && current() && selection === dlpLibrarySelection() && revision === stamp;
  }
  async function write(method, path, body, stamp, matches) {
    if (pending || !active(stamp)) throw new Error(dlpLibraryListChanged());
    pending = true; lock();
    try {
      const organization = await apiFetch("GET", "/admin/tenant");
      if (!active(stamp) || dlpLibraryTenant(organization) !== tenant) throw new Error(dlpLibraryOrganizationChanged());
      // Bind the request at the server as well: credentials/context may change
      // after this preflight, including while apiFetch offers an elevation retry.
      if (method === "DELETE") path += (path.includes("?") ? "&" : "?") + "expected_tenant_id=" + encodeURIComponent(tenant);
      else body = {...body, expected_tenant_id:tenant};
      let response;
      try { response = await apiFetch(method, path, body); }
      catch (_) { loaded = false; error(dlpLibraryUnconfirmed()); throw new Error(dlpLibraryUnconfirmed()); }
      if (!response?.ok) throw new Error(response?.body?.error || "HTTP " + response?.status);
      let rows;
      try {
        if (!active(stamp)) throw new Error("obsolete response");
        rows = dlpLibraryList(response, key, tenant);
        if (!matches(rows, response.body)) throw new Error("unmatched acknowledgement");
      } catch (_) { loaded = false; error(dlpLibraryUnconfirmed()); throw new Error(dlpLibraryUnconfirmed()); }
      revision++;
      return rows;
    } finally { pending = false; if (current()) lock(); }
  }
  return {load,write,current,stamp:()=>revision};
}
